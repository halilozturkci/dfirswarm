#!/usr/bin/env python3
"""Turn identified cloud log exports into canonical rows, offline, and keep everything the adapters cannot read.

Input: CSV, JSON (an array, a single object, an envelope such as `{"entries": [...]}`, `{"items": [...]}` or `{"value": [...]}`), JSON Lines
and gzip of those, and the two text formats below; the format is read from the content and not from the name. Seven adapters read seven documented shapes:

  - `gcp_audit`: a Cloud Logging `LogEntry` whose `protoPayload` is a `google.cloud.audit.AuditLog` (Admin Activity, Data Access, System
    Event and Policy Denied logs): the principal and its delegation chain, service, method, resource, status, caller address and user agent,
    `insertId`, `timestamp` against `receiveTimestamp`, the log's type from `logName`, and the monitored resource.
  - `kubernetes_audit`: an `audit.k8s.io/v1` `Event` (alone, in JSON Lines, or in an `EventList`): audit id, stage, level, verb, request URI,
    user, groups, impersonation, source addresses, object reference, response status, both timestamps and the annotations. A record is one
    stage and is one row: the stages of one audit id are never merged into one action. A request or response body that is a Secret object
    is replaced whole before the record is cleaned.
  - `entra_directory_audit`: a Microsoft Graph `directoryAudit`: id, category, correlation id, result and its reason, activity, logging
    service, operation type, the initiator (user or application, kept apart from the target resources) and the modified properties of each
    target. The values of modified properties are sensitive: a property named like a secret has its old and new values withheld, and every
    other value goes through the credential rules.
  - `azure_activity_log`: an Azure Activity log record (JSON, or a CSV whose header carries the same field names): a start and its completion
    are separate rows of one correlation id; the scope and resource ids are kept as written; claims, authorization, properties and the HTTP
    request are kept whole and go through the credential rules. The Azure documentation was not read: the names are the work card's.
  - `workspace_activities`: Google Workspace Reports API activities, one row per event, the parameter bag kept whole; the Google documentation was
    not read, so the shape and every name are the work card's and unchecked against vendor documentation.
  - `aws_s3_access_log`: the S3 server access log, a space-separated text file, one request per line (27 fields, the AWS page of 2026-11-04).
    `-` is null; fields beyond the last the page lists are counted and kept.
  - `aws_vpc_flow`: VPC Flow Logs as delivered text: the fields are named by the header line (versions 2 to 11 on the AWS page of 2026-11-04);
    start and end are Unix seconds; a NODATA or SKIPDATA record is a row of kind no_flow_record, never a flow of zero traffic.

Every row has: provider, adapter, tenant (the project, organisation or folder for gcp; the audit event and the directory audit record name
none, and say so), principal, action, resource, outcome (success, failure, or unknown when the record says nothing) with its basis, the raw time and the
UTC time (a time with no zone is never read as UTC: time_utc is null), a locator (file, record, line, offset in characters of the decoded text),
duplicate annotation, the parser's name, and the whole record, cleaned. A record that parsed and that no adapter reads, a malformed line and a
record over max_record_bytes go to rejected.jsonl with the reason and the locator, and are counted: nothing is dropped. coverage.json says, per source
file, the format, the counts read, rejected and unsupported, the observed time range, pagination markers and the first failures.

Time is one clock: `time_limit_seconds` (default 420, at most 480, the manifest allows 600) covers the walk of directories, the reading, the
withholding and the writing of the rows; a run that reaches it is partial and names the files it did not read. A signal ends the run with a
partial coverage file and one line of JSON.

SECRET-SAFE OUTPUT (docs/packs.md, "Secrets and sensitive output"). A field whose name says it is a secret, and any text shaped like one, is
withheld in every channel; the original goes to `cloud-normalise-values.jsonl` under $OUT (mode 0600, created first) only when
`write_values: true` is asked, in a job run as secret output (the manifest makes a job with write_values one; otherwise it is refused and
nothing is written). Names, addresses and user agents are personal data, not secrets: they are in the rows.
"""
# ---- BEGIN SHARED BLOCK ----------------------------------------------------------------------------------------------
# Identical in cloudtrail_parse, signin_analyse and ual_parse. A tool is standalone, so what the three share is copied,
# as LosslessPage is in every pack tool, and tests/pack-cloud-shared.test.ts holds the three copies equal. Edit it in all
# three, never in one. It holds: the answer's error form, typed arguments, where an output may be written and published
# without replacing another, the lossless page, the secret-safe values file (the SecretValues of recovery_key_scan), the
# withholding of anything shaped like a credential, timestamps, and a bounded streaming reader for JSON and JSON Lines.
import atexit
import calendar
import codecs
import csv
import datetime
import errno
import itertools
import json
import os
import re
import secrets
import signal
import sqlite3
import stat
import struct
import sys
import tempfile
import time
import zlib
from pathlib import Path

DEFAULT_LIMIT = 500
FIRST_PROBLEMS = 25               # how many failures an answer names inline; every one is in the file the page names
MAX_RECORD_BYTES = 16 << 20       # one record (a JSON Lines line, an array element, a CSV field) larger than this is rejected, named
MAX_DOCUMENT_BYTES = 64 << 20     # what may sit in front of a document's array of records, or a document with none, larger than this is refused, named
MAX_EXPANDED_BYTES = 4 << 30      # per file, after decompression
MAX_SCAN_CHARS = 1 << 20          # a string longer than this is withheld whole, not scanned
MAX_DEPTH = 200                   # a value nested deeper than this is withheld whole
INLINE_BUDGET = 4 << 20           # bytes of rows an answer carries inline; the rest of a page is in its file
MAX_DISTINCT = 1000000            # distinct values a summary table counts; beyond it they are counted as uncounted
MAX_FIELD_BYTES = 16 << 20        # one CSV line (a field may span lines) longer than this stops the file, named
MAX_SPANS_PER_TEXT = 2000         # a text with more credential-shaped stretches than this has the rest of it withheld as one stretch, counted
MAX_INT_DIGITS = 4000             # an integer written with more digits is kept as the text it was written as (Python cannot print one past 4300)
DEFAULT_SECONDS = 420             # the time a read may take unless the call says otherwise
MAX_SECONDS = 480                 # the most it may be given: the manifest's 600 seconds must hold for the work that follows the deadline
FIRST_REJECTS = 1000              # a file whose first records are all rejected is not an export this tool reads: it stops after this many
LIST_REJECTS = 100000             # rejected records one file lists; the rest are counted
MAX_FILTER_CHARS = 1024           # a caller's regular expression is matched against at most this many characters of a value
CHUNK = 1 << 20
DEADLINE = [None]


def in_job():
    return bool(os.environ.get("JOB_ID") and os.environ.get("OUT"))


def describe(exc):
    code = errno.errorcode.get(exc.errno, "") if getattr(exc, "errno", None) else ""
    return scrub_text("%s%s: %s" % (type(exc).__name__, " " + code if code else "", getattr(exc, "strerror", None) or str(exc)))


def scrub_all(value):
    if isinstance(value, str):
        return scrub_text(value)
    if isinstance(value, dict):
        return {k: scrub_all(v) for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        return [scrub_all(v) for v in value]
    return value


def fail(message, **extra):
    """An error answer: JSON, exit 1, the same `status` every answer of this pack carries. A name in it that is shaped
    like a credential is withheld like any other output."""
    if hasattr(signal, "pthread_sigmask"):
        signal.pthread_sigmask(signal.SIG_BLOCK, {signal.SIGTERM, signal.SIGINT, signal.SIGHUP})     # one document: the stop handlers may not be in yet (a refusal can come before main() installs them), and one that is in would write a second, false, document after this one; a stop that arrives while this is written waits, and the tool leaves with it
    print(json.dumps({"error": scrub_text(str(message)), "status": "failed",
                      "status_basis": "the tool stopped with an error (see error)", **scrub_all(extra)}, default=str))
    raise SystemExit(1)


def read_args():
    try:
        args = loads_strict(sys.stdin.read())
    except (ValueError, RecursionError) as exc:
        fail("arguments are not valid JSON", reason=type(exc).__name__)
    if not isinstance(args, dict):
        fail("arguments must be a JSON object")
    return args


def want_str(args, key, required=None):
    value = args.get(key)
    if value is None:
        if required:
            fail(required)
        return None
    if not isinstance(value, str) or not value or "\0" in value:
        fail("%s must be a non-empty string" % key)
    return value


def want_bool(args, key, default=False):
    value = args.get(key, default)
    if not isinstance(value, bool):
        fail("%s must be true or false" % key)
    return value


def want_int(args, key, default, minimum=1, maximum=None):
    value = args.get(key, default)
    if isinstance(value, bool) or not isinstance(value, int) or value < minimum or (maximum is not None and value > maximum):
        fail("%s must be an integer of at least %d%s" % (key, minimum, "" if maximum is None else " and at most %d" % maximum))
    return value


def want_str_list(args, key):
    value = args.get(key)
    if value is None:
        return []
    if isinstance(value, str):
        value = [value]
    if not isinstance(value, list) or not all(isinstance(v, (str, int)) and not isinstance(v, bool) for v in value):
        fail("%s must be a list of strings" % key)
    return [str(v) for v in value]


def unsafe_regex(pattern):
    """Why a caller's pattern is refused, or None: a group that repeats without a bound and itself repeats or branches, or a back
    reference, takes time that grows exponentially with the text, so it is not started. This is a first filter for the shapes
    that are known, not the guard: every test of every pattern is timed (Filter), whatever its shape."""
    stack, i, n, repeats, in_class = [], 0, len(pattern), 0, False
    quant = re.compile(r"[*+?]|\{\d*,?\d*\}")

    def repeating(q):
        """A quantifier that can repeat without a bound: *, + and {n,}; ? and {n,m} cannot."""
        return q in ("*", "+") or (q.startswith("{") and q.endswith(",}")) or q == "{}"

    while i < n:
        c = pattern[i]
        if c == "\\":
            if i + 1 < n and pattern[i + 1] in "123456789":
                return "a back reference"
            i += 2
            continue
        if in_class:
            in_class = c != "]"
            i += 1
            continue
        if c == "[":
            in_class = True
            i += 1
            if pattern[i:i + 1] == "^":
                i += 1
            if pattern[i:i + 1] == "]":
                i += 1
            continue
        if c == "(":
            stack.append(False)
            i += 1
            if pattern[i:i + 1] == "?":
                i += 1
            continue
        if c == "|":
            if stack:
                stack[-1] = True
            i += 1
            continue
        if c == ")":
            inner = stack.pop() if stack else False
            i += 1
            m = quant.match(pattern, i)
            if m and repeating(m.group(0)):
                if inner:
                    return "a repeated group that itself repeats or branches"
                repeats += 1
                if stack:
                    stack[-1] = True
            elif stack and inner:
                stack[-1] = True
            i = m.end() if m else i
            continue
        m = quant.match(pattern, i)
        if m:
            if repeating(m.group(0)):
                repeats += 1
                if stack:
                    stack[-1] = True
            i = m.end()
        else:
            i += 1
    return "more than six repeats" if repeats > 6 else None


FILTER_SECONDS = 0.25             # one test of a caller's pattern against one value may take this long; past it the call fails, named


class FilterTooSlow(Exception):
    pass


_ARMED = [False]


def _filter_alarm(_signum, _frame):
    if _ARMED[0]:                 # a timer that fires after its test has ended is not a slow test
        _ARMED[0] = False
        raise FilterTooSlow()


class Filter:
    """A caller's regular expression. Its text is limited, a pattern of a known exponential shape is refused before it is
    compiled, and EVERY test of ANY pattern against a value is timed, whatever the pattern's shape (a bounded repeat such as
    `(a?){30}a{30}` or `(\\w{1,20}){1,10}@` is as slow as an unbounded one): the re module checks for signals while it matches, so
    a test that takes more than FILTER_SECONDS is stopped and the call fails, named, instead of hanging."""

    def __init__(self, rx, key):
        self.rx, self.key = rx, key

    def __bool__(self):
        return True

    def test(self, text):
        try:
            _ARMED[0] = True
            signal.setitimer(signal.ITIMER_REAL, FILTER_SECONDS)
            found = self.rx.search(text) is not None
        except FilterTooSlow:
            fail("the %s pattern took longer than %s seconds to test one value (%d characters); use a simpler pattern" % (self.key, FILTER_SECONDS, len(text)))
        finally:
            _ARMED[0] = False
            signal.setitimer(signal.ITIMER_REAL, 0)
        return found


def want_regex(args, key):
    text = want_str(args, key)
    if text is None:
        return None
    if not hasattr(signal, "setitimer"):
        fail("%s needs interval timers to bound a pattern's time, which this platform does not have" % key)
    if len(text) > 200:
        fail("%s is longer than 200 characters" % key)
    why = unsafe_regex(text)
    if why:
        fail("%s is refused (%s): a pattern of that shape takes exponential time. Use a simpler one." % (key, why))
    try:
        return Filter(re.compile(text, re.I), key)
    except re.error as exc:
        fail("%s is not a valid regex" % key, reason=str(exc))


def hits(rx, text):
    """Whether a caller's pattern matches the text AS IT IS PRINTED, and only its first MAX_FILTER_CHARS characters: a count of
    matches against a withheld original would tell the caller one bit of it per call."""
    return rx.test(text[:MAX_FILTER_CHARS])


def refuse_unknown(args, allowed):
    """An argument the tool does not have is a typo that would return an unfiltered answer that looks filtered."""
    extra = sorted(str(k) for k in args if k not in allowed)
    if extra:
        fail("unknown argument(s): %s. This tool takes: %s" % (", ".join(extra), ", ".join(sorted(allowed))))


def start_clock(args, default=DEFAULT_SECONDS, maximum=MAX_SECONDS):
    seconds = args.get("time_limit_seconds", default)
    if isinstance(seconds, bool) or not isinstance(seconds, (int, float)) or seconds < 1 or seconds > maximum:
        fail("time_limit_seconds must be a number from 1 to %d" % maximum)
    DEADLINE[0] = time.monotonic() + seconds
    return seconds


def out_of_time():
    return DEADLINE[0] is not None and time.monotonic() > DEADLINE[0]


class TimeUp(Exception):
    """The time limit passed inside a record (a long string, a row of many cells): the record is abandoned, counted and listed as
    cut by the limit, and the read ends. A record's work is checked against the deadline, not only the gaps between records."""


_TICKS = [0]


def check_deadline(weight=1):
    """Raise TimeUp when the deadline has passed. The clock is read once per 2048 units of work (a unit is about 256 characters of text
    or one withheld stretch), so the check costs nothing against the work it guards."""
    _TICKS[0] += weight
    if _TICKS[0] >= 2048:
        _TICKS[0] = 0
        if out_of_time():
            raise TimeUp()


def dumps_deep(value, **kwargs):
    """json.dumps for a value that may be nested very deeply. The decoder admits a document nested nearly as deep as the interpreter's
    recursion limit, and the encoder then needs more than the frames left (Python 3.11 counts the C encoder's levels against the same
    limit): the limit is raised for this one call, by more than any document the decoder admits."""
    try:
        return json.dumps(value, **kwargs)
    except RecursionError:
        old = sys.getrecursionlimit()
        sys.setrecursionlimit(old + 5000)
        try:
            return json.dumps(value, **kwargs)
        finally:
            sys.setrecursionlimit(old)


def shown_text(value):
    """A value as the one line of text a table key, a filter or a reason carries. A string is scrubbed. A number or a boolean is its
    own text. A list or an object is what it is (its kind and size) and never its content: it reaches the answer, field by field and
    cleaned, in the record, and str() of it would print a name and its value side by side."""
    if isinstance(value, str):
        return scrub_text(value)
    if isinstance(value, (bool, int, float)):
        return str(value)
    if isinstance(value, dict):
        return "(object with %d keys)" % len(value)
    if isinstance(value, (list, tuple)):
        return "(list of %d items)" % len(value)
    return "(%s)" % type(value).__name__


def failed_record(exc):
    """The reason listed for a record that could not be processed: the kind of failure, and the message when it is short. One
    malformed record never ends the run: it is counted, located and listed, and the next is read."""
    if isinstance(exc, TimeUp):
        return "the time limit ended the read inside this record: it was not processed"
    message = scrub_text(str(exc))
    return "the record could not be processed (%s%s); it is counted and listed here and the read went on" % (
        type(exc).__name__, ": " + message if message and len(message) <= 200 else "")


_PAGINATION = re.compile(r"(?i)next.?(page.?)?(token|link|uri|url)|continuation")


def pagination_key(name):
    """A key of an API response that names the next page: the export is one page of more (the key's value is a token, and is
    never printed)."""
    return bool(_PAGINATION.search(str(name)))


def compact(row, keep=("success", "time_utc")):
    """A row without its empty fields; an unknown that means something (a null success, a time that could not be decoded) stays."""
    return {k: v for k, v in row.items() if k in keep or v not in (None, "", {}, [])}


def status_of(failed, complete, basis_complete, basis_partial, basis_failed):
    """`status`, with the reason: complete (every record of the supplied files was read, nothing was left out), partial
    (some were, and the answer names what was not) or failed. Complete says nothing about the export's own coverage."""
    if failed:
        return {"status": "failed", "status_basis": basis_failed}
    if complete:
        return {"status": "complete", "status_basis": basis_complete}
    return {"status": "partial", "status_basis": basis_partial}


# ---- where an output may be written ------------------------------------------------------------------------------


def resolve_output(out, what="output"):
    """Where `out` really lands, as a path under the run directory; a place outside it, the run directory itself, or
    anything under inputs/ is refused. A string check is not enough: `work/../inputs/x`, an absolute path and a symlink
    that points out all name a place the tool must not write, so the path is resolved first and directories compared.
    In a job the run directory is read-only and only $OUT is written, so a place outside $OUT is refused with the way
    to name one (work/<your agent id>/..., which the harness maps to $OUT), not left to fail on a read-only file system."""
    root = Path.cwd().resolve()
    dest = (root / out).resolve() if not Path(out).is_absolute() else Path(out).resolve()
    if dest == root or root not in dest.parents:
        fail("%s must stay inside the run directory" % what, **{what: str(out)})
    inputs = root / "inputs"
    if dest == inputs or inputs in dest.parents:
        fail("%s cannot be under inputs/" % what, **{what: str(out)})
    if in_job():
        base = Path(os.environ["OUT"]).resolve()
        if dest == base or base not in dest.parents:
            fail("%s is not under this job's output directory: a job writes only $OUT, and the run directory is read-only. "
                 "Name a place under work/<your agent id>/ and the harness maps it there, or leave %s out." % (what, what),
                 **{what: str(out)})
    return str(dest.relative_to(root))


def shown_output(path):
    """How an output is named in an answer: a job's $OUT is sealed as store/jobs/<job>/out, so a place under it is
    shown as it will be cited."""
    try:
        rel = Path(path).resolve().relative_to(Path(os.environ["OUT"]).resolve())
        return "store/jobs/%s/out/%s" % (re.sub(r"[^A-Za-z0-9_.-]", "_", os.environ["JOB_ID"]), rel.as_posix())
    except (KeyError, ValueError, OSError):
        return str(path)


def same_bytes(a, b, deadline=None):
    """Whether two files hold the same bytes (read in blocks, never whole). Each is opened without waiting and without following a link
    (O_NONBLOCK, O_NOFOLLOW) and looked at with fstat first: only two regular files of one size are read, so a FIFO, a device, a
    directory or a link at either name is never read (a FIFO would hold the tool for ever). Past `deadline` (a monotonic time) the
    answer is False."""
    flags = os.O_RDONLY | getattr(os, "O_NONBLOCK", 0) | getattr(os, "O_NOFOLLOW", 0)
    fa = fb = None
    try:
        fa = os.fdopen(os.open(str(a), flags), "rb")
        fb = os.fdopen(os.open(str(b), flags), "rb")
        sa, sb = os.fstat(fa.fileno()), os.fstat(fb.fileno())
        if (sa.st_mode & 0o170000) != 0o100000 or (sb.st_mode & 0o170000) != 0o100000 or sa.st_size != sb.st_size:
            return False
        while True:
            if deadline is not None and time.monotonic() > deadline:
                return False
            x, y = fa.read(CHUNK), fb.read(CHUNK)
            if x != y:
                return False
            if not x:
                return True
    except OSError:
        return False
    finally:
        for fh in (fa, fb):
            if fh is not None:
                fh.close()


def publish(tmp, path):
    """Move a finished file to `path` without replacing what is there: a file at the name is an earlier answer (a
    complete one, perhaps, where this run was cut short by a lower limit) and stays; this one is kept beside it as
    name.2.ext, unless it holds the same bytes, when the file already there is it. Returns the path it has."""
    stem, ext = os.path.splitext(str(path))
    k = 1
    while True:
        candidate = Path(stem + ("" if k == 1 else ".%d" % k) + ext)
        try:
            os.link(tmp, candidate)
        except FileExistsError:
            if same_bytes(tmp, candidate):
                os.unlink(tmp)
                return candidate
            k += 1
            continue
        except OSError:                                   # a file system with no hard links: a look, then a rename
            if os.path.lexists(candidate):
                if same_bytes(tmp, candidate):
                    os.unlink(tmp)
                    return candidate
                k += 1
                continue
            os.rename(tmp, candidate)
            return candidate
        os.unlink(tmp)
        return candidate


_TEMPS = set()
CLEANUP = []        # what to undo when the run ends early: a temporary index, above all


def _drop_unpublished():
    """A refused, failed or signalled run leaves no half-written result and no temporary index behind: only a finished file is
    published. (A SIGKILL cannot be caught: what it leaves is hidden, named .<tool>-..., and holds no unwithheld value.)"""
    while CLEANUP:
        try:
            CLEANUP.pop()()
        except Exception:  # noqa: BLE001 - best effort, and never a second failure over the first
            pass
    for path in list(_TEMPS):
        try:
            os.unlink(path)
        except OSError:
            pass
        _TEMPS.discard(path)


def _on_signal(signum, _frame):
    if hasattr(signal, "setitimer"):
        signal.setitimer(signal.ITIMER_REAL, 0)       # a pattern timer must not fire inside the cleanup
    _drop_unpublished()
    os._exit(128 + signum)


def install_signal_handlers():
    for signum in (signal.SIGTERM, signal.SIGINT, signal.SIGHUP):
        signal.signal(signum, _on_signal)
    if hasattr(signal, "setitimer"):
        signal.signal(signal.SIGALRM, _filter_alarm)


class signals_held:
    """The termination signals wait, pending, while a temporary file or directory is made and registered for removal: a signal that
    arrives between the two would run the cleanup before it knew of the file, and the process would exit with the file behind. Where
    the platform cannot hold signals the registration comes first, so only the file's own creation is unprotected."""

    def __enter__(self):
        self.before = None
        if hasattr(signal, "pthread_sigmask"):
            self.before = signal.pthread_sigmask(signal.SIG_BLOCK, {signal.SIGTERM, signal.SIGINT, signal.SIGHUP})
        return self

    def __exit__(self, *_exc):
        if self.before is not None:
            signal.pthread_sigmask(signal.SIG_SETMASK, self.before)
        return False


atexit.register(_drop_unpublished)


class LosslessPage:
    """The page an answer carries, and the whole in a file it names. Rows past `limit` (or past the inline byte budget)
    go to a JSON Lines file, so nothing is cut: under $OUT/tool-output in a job, work/<agent>/tool-output otherwise, with a
    random name (never a digest of the request). With `dest` the whole is always written there (never over a file that is
    already there: it is kept and this one named beside it). Rows are written with ASCII escapes, so a lone surrogate
    from a non-UTF-8 name survives and no row can raise."""

    def __init__(self, tool, limit, dest=None, budget=INLINE_BUDGET):
        if isinstance(limit, bool) or not isinstance(limit, int) or limit < 1:
            raise ValueError("limit must be a positive integer")
        self.tool = re.sub(r"[^A-Za-z0-9_.-]", "_", tool)
        self.limit, self.budget, self.dest = limit, budget, dest
        self.page, self.total, self.bytes = [], 0, 0
        self._out = self._tmp = None
        if dest:
            self.path = Path(dest)
            self._open_tmp(self.path.parent)
        else:
            name = "%s-%s.jsonl" % (self.tool, secrets.token_hex(8))
            job, out = os.environ.get("JOB_ID"), os.environ.get("OUT")
            if job and out:
                self.path = Path(out) / "tool-output" / name
            else:
                agent = re.sub(r"[^A-Za-z0-9_.-]", "_", os.environ.get("AGENT_ID") or "tool")
                self.path = Path("work") / agent / "tool-output" / name

    def _open_tmp(self, directory):
        try:
            directory.mkdir(parents=True, exist_ok=True)
            with signals_held():
                fd, name = tempfile.mkstemp(dir=directory, prefix=".%s-" % self.tool)
                self._tmp = Path(name)
                _TEMPS.add(name)
            self._out = os.fdopen(fd, "w", encoding="utf-8", errors="backslashreplace")
        except OSError as exc:
            fail("the whole result could not be written: %s cannot be created (%s)" % (shown_output(directory), describe(exc)))

    def _write(self, text):
        try:
            self._out.write(text)
            self._out.write("\n")
        except OSError as exc:
            fail("the whole result could not be written to %s: %s" % (shown_output(self.path), describe(exc)))

    def add(self, row):
        text = dumps_deep(row, default=str, allow_nan=False)      # a number JSON cannot hold raises here, before the row is counted
        self.total += 1
        if self._out is None and (len(self.page) >= self.limit or self.bytes + len(text) > self.budget):
            self._open_tmp(self.path.parent)
            for kept in self.page:
                self._write(dumps_deep(kept, default=str, allow_nan=False))
        if self._out is not None:
            self._write(text)
        if len(self.page) < self.limit and self.bytes + len(text) <= self.budget:
            self.page.append(row)
            self.bytes += len(text)

    def finish(self, partial=False):
        """Close the page. With `dest` and `partial`, the file is published as <name>.partial<ext>: the requested name only ever
        holds a result that read everything it was given."""
        result = {"matched": self.total, "returned": len(self.page), "truncated": self.total > len(self.page)}
        if self._out is not None:
            try:
                self._out.flush()
                os.fsync(self._out.fileno())
                self._out.close()
                if partial and self.dest:
                    stem, ext = os.path.splitext(str(self.path))
                    self.path = Path(stem + ".partial" + ext)
                    result["all_results_partial"] = True
                final = publish(self._tmp, self.path)
                _TEMPS.discard(str(self._tmp))
            except OSError as exc:
                fail("the whole result could not be written to %s: %s" % (shown_output(self.path), describe(exc)))
            result["all_results"] = shown_output(final)
            result["all_results_format"] = "JSON Lines, one complete result per line"
            if str(final) != str(self.path):
                result["all_results_note"] = "a different file was already at %s and was kept; this result is beside it" % shown_output(self.path)
        return result


class SecretValuesRefused(Exception):
    pass


class SecretValues:
    """Where a value goes when, and only when, the caller asked for it.

    The secret-safe output pattern of recovery_key_scan (docs/packs.md, "Secrets and sensitive output"), copied
    unchanged but for the file's name and the tool named in the refusal. With `enabled` false it writes nothing and
    `summary()` says so. Enabled, it is refused outside a job and in a job that was not run as secret output
    (SECRET_OUTPUT is not "1"; the manifest's `secret_output` makes a job with write_values one); inside a secret job
    the file is created at once, before anything is read (mode 0600, O_EXCL and O_NOFOLLOW: a file or a link already at that name is refused by name, a dangling link
    included), so with nothing withheld it stays an empty file and the answer says written: 0.
    """

    def __init__(self, enabled, name, tool):
        self.enabled = enabled
        self.written = 0
        self._fh = None
        self.job = os.environ.get("JOB_ID") or ""
        self.out = os.environ.get("OUT") or ""
        self.path = None
        self.shown = None
        if not enabled:
            return
        if not (self.job and self.out):
            raise SecretValuesRefused(
                "write_values is refused outside a job: a value written here would be an ordinary "
                "file, not a sealed secret output. Run this as job_run tool=%s with "
                "secret_output: true, and ask again there. Nothing was written." % tool
            )
        if os.environ.get("SECRET_OUTPUT") != "1":
            raise SecretValuesRefused(
                "write_values is refused in a job that was not run as secret output: its files would "
                "be sealed as ordinary output. The harness sets SECRET_OUTPUT=1 for a secret job's "
                "process and it is not set here. Run this as job_run tool=%s (its manifest makes a "
                "job with write_values secret output), or give a command job secret_output: true; "
                "if that is refused the same way, this run's harness does not set the variable and "
                "the values mode is not available in it. Nothing was written." % tool
            )
        self.path = Path(self.out) / name
        self.shown = "store/jobs/%s/out/%s" % (re.sub(r"[^A-Za-z0-9_.-]", "_", self.job), name)
        try:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            fd = os.open(str(self.path), os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o600)
        except FileExistsError:
            raise SecretValuesRefused("the values file already exists: %s" % self.shown)
        except OSError as exc:
            raise SecretValuesRefused("the values file could not be created: %s (%s)" % (self.shown, describe(exc)))
        self._fh = os.fdopen(fd, "w", encoding="utf-8", errors="backslashreplace")
        CLEANUP.append(self.close)          # a signal flushes what was written, so the originals the answer never named are not lost unannounced

    def add(self, finding_id, locator, value):
        if not self.enabled:
            return
        self._fh.write(dumps_deep({"finding_id": finding_id, **locator, "value": value}, default=str))
        self._fh.write("\n")
        self.written += 1

    def close(self):
        if self._fh is not None:
            self._fh.flush()
            os.fsync(self._fh.fileno())
            self._fh.close()
            self._fh = None

    def summary(self):
        return {
            "requested": self.enabled,
            "written": self.written,
            "values_file": self.shown if self.enabled else None,
            "contains_secret_values": self.written > 0,
            "format": "JSON Lines, mode 0600: finding_id, file (the real path), record, line, pointer, why, value" if self.enabled else None,
        }


# ---- withholding: where each slot goes --------------------------------------------------------------------------
# The rules are the shared WITHHOLDING block's (below this one, the same text in every tool of the repository that carries it): the name
# layer (`name_is_sensitive`), the structure rule (`clean_value`) and the text rules (`credential_spans`). What is this block's is
# the routing: which slot goes to which rule, and what is printed in its place. Every slot a tool prints has one of three treatments.
#   - A designed-visible identifier is printed as it is and judged by nothing: an event id, a request id, an access key id (the
#     `session_origin` link is made by it), an Entra object id, a record Id, a correlation id, an ARN, an account id, a hash a record
#     names. The tools key on these, and the shared `scrub` withholds identifier-shaped runs (a hex digest, a GUID-shaped id, an AKIA
#     key id), so no slot that can hold one goes through it.
#   - Free text (every string of a record, a path, a file name, a JSON pointer, a table key, a reason, an error message) goes through
#     `scrub_text`: the credential rules only, never the rules for identifier-shaped runs. A string longer than WITHHOLD_LIMIT is withheld
#     whole (the shared block's other carriers keep 64 KiB; these tools keep 1 MiB).
#   - A named field (a key that says it holds a secret, or the `Value` of a pair whose `Name` does) goes through the name layer, at any
#     depth, whatever its value looks like, a number included.
# The values the rules find are withheld in every channel (rows, paths, error messages, the files the answer names), the same strings
# in all three tools. A filter a caller gives (identity, user, events, operations) is matched against the text as it is printed,
# never against a withheld original: a count of matches would tell the caller one bit of it per call.

WITHHOLD_LIMIT = MAX_SCAN_CHARS   # read by the shared block below: a text longer than this is withheld whole
WITHHOLD_TICK = check_deadline    # called by the shared block below during a long scan: it raises TimeUp at the deadline
WITHHELD_TEXT = "[withheld: %s, %d characters]"
LOCAL = {"paths": 0, "text": 0}


def scrub_text(text):
    """`text` with each credential in it replaced by a marker that holds only its length."""
    if not isinstance(text, str) or len(text) < 5:
        return text
    if len(text) > MAX_SCAN_CHARS:
        LOCAL["text"] += 1
        return WITHHELD_TEXT % ("text longer than 1 MiB", len(text))
    try:
        spans = credential_spans(text)
    except TimeUp:
        LOCAL["text"] += 1
        return WITHHELD_TEXT % ("text not scanned: the time limit ended the scan", len(text))      # fail closed
    if not spans:
        return text
    out, at = [], 0
    for start, end, why in spans:
        out.append(text[at:start])
        out.append(WITHHELD_TEXT % (why, end - start))
        LOCAL["text"] += 1
        at = end
    out.append(text[at:])
    return "".join(out)


_SEGMENTS = {}


def shown_pointer(pointer):
    """A JSON pointer as it may be printed. A key in it is text the record chose, and can be shaped like a credential (a URL with a
    password in it, a name of 40 base64 characters): each key is withheld like any other text, before the pointer is joined. (The
    values file holds the real pointer; the "~" and "/" escapes of a key would otherwise break the shape a rule looks for.)"""
    if not pointer:
        return pointer
    tail = ""
    m = re.search(r"@\d+$", pointer)
    if m:
        pointer, tail = pointer[:m.start()], m.group(0)
    parts = []
    for part in pointer.split("/"):
        hit = _SEGMENTS.get(part)
        if hit is None:
            key = part.replace("~1", "/").replace("~0", "~")
            safe = scrub_text(key)
            hit = part if safe == key else safe.replace("~", "~0").replace("/", "~1")
            if len(_SEGMENTS) < 20000:
                _SEGMENTS[part] = hit
        parts.append(hit)
    return "/".join(parts) + tail


def shown_path(path):
    """A path as it may be printed: a component shaped like a credential (a file named after a token) is withheld."""
    if not isinstance(path, str):
        return path
    parts = path.split("/")
    for i, part in enumerate(parts):
        clean = scrub_text(part)
        if clean != part:
            parts[i] = clean
            LOCAL["paths"] += 1
    return "/".join(parts)


class Withheld:
    """Cleans values on their way into an answer, counts what was withheld, lists where, and hands the originals to the
    values file when the caller asked for it (write_values, in a job). A row's `locator` says which record it came from.
    `quiet` cleans without recording (for a value that is stored on the way, such as an index entry). The walk over a value is the
    shared block's `clean_value`; this class records what it finds."""

    def __init__(self, vault, limit, quiet=False):
        self.vault = vault
        self.quiet = quiet
        self.count = 0
        self.reasons = {}
        self.page = None if quiet else LosslessPage("withheld", limit)

    def note(self, locator, pointer, why, length, original, shown_ptr=None):
        if self.quiet:
            return
        check_deadline()
        self.count += 1
        self.reasons[why] = self.reasons.get(why, 0) + 1
        fid = "W%06d" % self.count
        shown = {k: (shown_path(v) if k == "file" else v) for k, v in locator.items()}
        self.page.add({"finding_id": fid, **shown, "pointer": shown_ptr if shown_ptr is not None else shown_pointer(pointer), "why": why, "length": length})
        if self.vault is not None:
            self.vault.add(fid, {**locator, "pointer": pointer, "why": why}, original)

    @staticmethod
    def size_of(value):
        if isinstance(value, str):
            return "%d characters" % len(value)
        if isinstance(value, dict):
            return "object with %d keys" % len(value)
        if isinstance(value, list):
            return "list of %d items" % len(value)
        return "a number"

    def field(self, locator, pointer, why, original):
        """What is printed for a field the name layer withheld (or a value nested too deep), after noting it."""
        self.note(locator, pointer, why, len(original) if isinstance(original, str) else len(dumps_deep(original, default=str)), original)
        return "[withheld: %s, %s]" % (why, self.size_of(original))

    def clean(self, value, locator, pointer="", depth=0, shapes=True):
        return clean_value(value, lambda text, point, shaped: self.clean_text(text, locator, point, shaped),
                           lambda point, why, original: self.field(locator, point, why, original),
                           scrub_text, pointer, depth, shapes, MAX_DEPTH)

    def clean_text(self, text, locator, pointer, shapes=True):
        if len(text) < 5:
            return text
        if len(text) > MAX_SCAN_CHARS:
            self.note(locator, pointer, "text longer than 1 MiB", len(text), text)
            return WITHHELD_TEXT % ("text longer than 1 MiB", len(text))
        check_deadline(1 + len(text) // 256)
        spans = credential_spans(text, shapes)          # at the deadline this raises TimeUp: a record is being read
        if not spans:
            return text
        if len(spans) > MAX_SPANS_PER_TEXT:
            # a text with thousands of stretches would write a note, and a line of the values file, for each: past the cap the rest
            # of the text is withheld as one stretch (counted as one, and the values file holds all of it)
            first = spans[MAX_SPANS_PER_TEXT - 1][0]
            spans = spans[:MAX_SPANS_PER_TEXT - 1] + [(first, len(text), "the rest of a text that holds more than %d credential-shaped stretches" % MAX_SPANS_PER_TEXT)]
        out, at = [], 0
        base = shown_pointer(pointer) if not self.quiet else pointer
        for start, end, why in spans:
            out.append(text[at:start])
            out.append(WITHHELD_TEXT % (why, end - start))
            self.note(locator, "%s@%d" % (pointer, start), why, end - start, text[start:end], "%s@%d" % (base, start))
            at = end
        out.append(text[at:])
        return "".join(out)

    def summary(self):
        page = self.page.finish()
        return {"count": self.count, "by_reason": self.reasons, "locators": self.page.page, "page": page,
                "text_withheld_from_paths_and_messages": LOCAL["paths"] + LOCAL["text"]}



# ---- timestamps -------------------------------------------------------------------------------------------------

_EPOCH = datetime.datetime(1970, 1, 1)
ISO_STAMP = re.compile(r"^\s*(\d{4})-(\d{2})-(\d{2})[T ](\d{2}):(\d{2})(?::(\d{2})(?:[.,](\d{1,9}))?)?\s*(Z|z|[+-]\d{2}(?::?\d{2})?)?\s*$")
SLASH_STAMP = re.compile(r"^\s*(\d{1,2})/(\d{1,2})/(\d{4})[ ,T]+(\d{1,2}):(\d{2})(?::(\d{2})(?:[.,](\d{1,9}))?)?\s*([AaPp][Mm])?\s*(Z|z|[+-]\d{2}(?::?\d{2})?)?\s*$")


def _clock_ok(y, mo, d, h, mi, s):
    return 1 <= mo <= 12 and 1 <= d <= calendar.monthrange(y, mo)[1] and 0 <= h <= 23 and 0 <= mi <= 59 and 0 <= s <= 59


def slash_order(raw):
    """'mdy', 'dmy', 'either' (the two fields are equal) or 'ambiguous' for a day/month/year string; None if it is not one."""
    m = SLASH_STAMP.match(raw) if isinstance(raw, str) else None
    if not m:
        return None
    a, b = int(m.group(1)), int(m.group(2))
    if a == b:
        return "either"
    if a > 12 >= b:
        return "dmy"
    if b > 12 >= a:
        return "mdy"
    return "ambiguous" if a <= 12 and b <= 12 else None


def proven_order(raw):
    """'dmy' or 'mdy' when the day/month/year string can be read only that way and read that way it is a real date; else None."""
    got = slash_order(raw)
    if got in ("dmy", "mdy") and parse_stamp(raw, got, True)["ns"] is not None:
        return got
    return None


def parse_stamp(raw, order=None, assume_utc=False):
    """A time as the export wrote it, decoded without a guess.

    Returns {utc, ns, status, basis}. `utc` is ISO 8601 UTC with the fractions as written; `ns` is nanoseconds from the
    1970 epoch (for sorting and differences). `status` is zoned (the string carried an offset or Z), assumed_utc (it carried
    none and the caller said to read it as UTC), no_zone (it carried none and nothing was assumed), ambiguous_date_order
    (a day/month/year string with both fields up to 12 and no declared order), unparseable or missing. Nothing is
    assumed unless asked: a clock with no zone is not UTC because it is convenient, and 03/04/2026 is not March because
    a program was written in one country."""
    if raw is None or raw == "":
        return {"utc": None, "ns": None, "status": "missing", "basis": "no time in the record"}
    if not isinstance(raw, str):
        return {"utc": None, "ns": None, "status": "unparseable", "basis": "the time is not a string (%s)" % type(raw).__name__}
    m = ISO_STAMP.match(raw)
    if m:
        y, mo, d, h, mi = (int(m.group(i)) for i in (1, 2, 3, 4, 5))
        s, frac, zone = int(m.group(6) or 0), m.group(7) or "", m.group(8)
        am = None
    else:
        m = SLASH_STAMP.match(raw)
        if not m:
            return {"utc": None, "ns": None, "status": "unparseable", "basis": "not an ISO 8601 or day/month/year time"}
        got = slash_order(raw)
        use = order if order in ("mdy", "dmy") else ("mdy" if got == "mdy" else "dmy" if got == "dmy" else "mdy" if got == "either" else None)
        if use is None:
            return {"utc": None, "ns": None, "status": "ambiguous_date_order",
                    "basis": "both leading fields are 12 or less and no date_order was declared or proved by other rows"}
        if got in ("mdy", "dmy") and got != use:
            return {"utc": None, "ns": None, "status": "unparseable", "basis": "the field order contradicts date_order %s" % use}
        a, b, y = int(m.group(1)), int(m.group(2)), int(m.group(3))
        mo, d = (a, b) if use == "mdy" else (b, a)
        h, mi, s, frac, am, zone = int(m.group(4)), int(m.group(5)), int(m.group(6) or 0), m.group(7) or "", m.group(8), m.group(9)
        if am:
            if not 1 <= h <= 12:
                return {"utc": None, "ns": None, "status": "unparseable", "basis": "an hour outside 1-12 beside AM or PM"}
            h = h % 12 + (12 if am.lower() == "pm" else 0)
    if not _clock_ok(y, mo, d, h, mi, s):
        return {"utc": None, "ns": None, "status": "unparseable", "basis": "a date or clock value out of range"}
    offset = 0
    if zone and zone not in ("Z", "z"):
        digits = zone[1:].replace(":", "")
        offset = (int(digits[:2]) * 3600 + int(digits[2:4] or 0) * 60) * (1 if zone[0] == "+" else -1)
        status, basis = "zoned", "the string carries the offset %s" % zone
    elif zone:
        status, basis = "zoned", "the string carries Z"
    elif assume_utc:
        status, basis = "assumed_utc", "the string carries no zone; read as UTC because assume_utc was set"
    else:
        return {"utc": None, "ns": None, "status": "no_zone", "basis": "the string carries no zone and assume_utc was not set"}
    try:
        secs = calendar.timegm((y, mo, d, h, mi, s, 0, 0, 0)) - offset
        base = (_EPOCH + datetime.timedelta(seconds=secs)).strftime("%Y-%m-%dT%H:%M:%S")
    except (ValueError, OverflowError):
        return {"utc": None, "ns": None, "status": "unparseable", "basis": "a date outside the years 1 to 9999"}
    ns = secs * 1000000000 + (int(frac.ljust(9, "0")) if frac else 0)
    if not -(1 << 63) < ns < (1 << 63):
        return {"utc": None, "ns": None, "status": "unparseable", "basis": "a date outside 1678-2261, the range of nanoseconds a 64-bit integer holds"}
    return {"utc": base + ("." + frac if frac else "") + "Z", "ns": ns, "status": status, "basis": basis}


def ns_to_utc(ns):
    if ns is None:
        return None
    secs, rest = divmod(ns, 1000000000)
    try:
        base = (_EPOCH + datetime.timedelta(seconds=secs)).strftime("%Y-%m-%dT%H:%M:%S")
    except (ValueError, OverflowError):
        return None
    return base + ("." + ("%09d" % rest).rstrip("0") if rest else "") + "Z"


class Tally:
    """A count of each distinct value, bounded: past MAX_DISTINCT a new value is counted in `uncounted`, never lost
    silently (the records themselves are in the whole-result file)."""

    def __init__(self):
        self.counts = {}
        self.uncounted = 0

    def add(self, key):
        try:
            hash(key)
        except TypeError:                 # a list or an object is counted as what it is, never as a table key
            key = shown_text(key)
        if key in self.counts:
            self.counts[key] += 1
        elif len(self.counts) < MAX_DISTINCT:
            self.counts[key] = 1
        else:
            self.uncounted += 1

    def rows(self):
        return [{"value": k, "count": v} for k, v in sorted(self.counts.items(), key=lambda kv: (-kv[1], str(kv[0])))]

class RejectLog:
    """The rejected records of a read, listed in a file (a LosslessPage) with at most LIST_REJECTS per file (the rest are counted, and
    the answer says so), and a file whose first FIRST_REJECTS records were all rejected is stopped: it is not an export this tool
    reads, and listing five million rows of it would fill the output."""

    def __init__(self, page):
        self.page = page
        self.listed = self.unlisted = self.accepted = self.run = 0
        self.total_unlisted = 0

    def start_file(self):
        self.listed = self.accepted = self.run = 0

    def accept(self):
        self.accepted += 1
        self.run = 0

    def note(self, row):
        """List a row (up to the cap) that is not a rejected record: a record read whose payload is not."""
        if self.listed < LIST_REJECTS:
            self.page.add(row)
            self.listed += 1
        else:
            self.total_unlisted += 1

    def reject(self, row):
        """List the row; True when the file should be stopped."""
        self.run += 1
        self.note(row)
        return self.accepted == 0 and self.run >= FIRST_REJECTS


def dbtext(value):
    """A string for SQLite: a lone surrogate (a JSON escape such as \\ud800, or a name that is not UTF-8) cannot be stored as text, so
    it is kept as its escape; every other character is unchanged."""
    return value.encode("utf-8", "backslashreplace").decode("utf-8") if isinstance(value, str) else value


class Skips:
    """What a directory walk did not read: the first rows are kept for the answer, every one is counted."""

    def __init__(self, keep=100):
        self.items, self.total, self.by_name, self.keep = [], 0, 0, keep

    def append(self, row):
        self.total += 1
        if row["reason"].startswith("its name"):
            self.by_name += 1
        if len(self.items) < self.keep:
            self.items.append(row)

    @property
    def unreadable(self):
        return self.total - self.by_name


def named(items, limit=FIRST_PROBLEMS):
    """The first `limit` of a list, for an answer that also gives the count."""
    return list(items[:limit])


def open_temp_db(prefix):
    """A SQLite database on disk (in $OUT in a job, where only $OUT is writable; the temporary directory otherwise), so a
    large export does not have to fit in memory. Returns (db, directory, where); in memory only if no directory can be made.
    The directory is registered for removal before the file in it exists, with the termination signals held meanwhile, so a
    SIGTERM at any point of this function leaves neither the directory nor the file."""
    directory, opened = None, []
    try:
        with signals_held():
            directory = tempfile.mkdtemp(prefix=prefix, dir=os.environ["OUT"] if in_job() else None)
            where = directory
            CLEANUP.append(lambda: remove_temp_db(opened[0] if opened else None, where))
            opened.append(sqlite3.connect(os.path.join(directory, "work.sqlite")))
        os.chmod(os.path.join(directory, "work.sqlite"), 0o600)
        return opened[0], directory, "a temporary file"
    except (OSError, sqlite3.Error):
        if directory:
            remove_temp_db(opened[0] if opened else None, directory)
        return sqlite3.connect(":memory:"), None, "memory (no temporary directory could be created)"


def remove_temp_db(db, directory):
    try:
        if db is not None:
            db.close()
    except sqlite3.Error:
        pass
    if directory:
        try:
            names = os.listdir(directory)
        except OSError:
            return
        for name in names:
            try:
                os.unlink(os.path.join(directory, name))
            except OSError:
                pass
        try:
            os.rmdir(directory)
        except OSError:
            pass


# ---- reading files: a bounded stream of JSON values -------------------------------------------------------------

BOM = "\ufeff"
REPLACEMENT = "\ufffd"
_SPACE = re.compile(r"\s*")
ARCHIVE_EXT = (".zip", ".7z", ".rar", ".tar", ".tgz", ".bz2", ".xz", ".zst", ".lz4")
ARCHIVE_MAGIC = ((b"PK\x03\x04", "a ZIP archive"), (b"PK\x05\x06", "a ZIP archive"), (b"PK\x07\x08", "a ZIP archive"),
                 (b"BZh", "a bzip2 file"), (b"\xfd7zXZ\x00", "an xz file"), (b"\x28\xb5\x2f\xfd", "a Zstandard file"),
                 (b"7z\xbc\xaf\x27\x1c", "a 7-Zip archive"), (b"Rar!", "a RAR archive"), (b"\x04\x22\x4d\x18", "an LZ4 file"))


def _no_constant(name):
    raise json.JSONDecodeError("%s is not JSON" % name, "", 0)


def _number(text):
    """A number written with a decimal point or an exponent. One that does not fit a float (1e999) is kept as the text it was written as,
    not turned into an infinity that no JSON answer can hold."""
    value = float(text)
    return text if value in (_INF, -_INF) else value


def _integer(text):
    """An integer. One of more than MAX_INT_DIGITS digits is kept as its text: Python refuses to print one past 4300 digits."""
    return int(text) if len(text) <= MAX_INT_DIGITS else text


_INF = float("inf")
_DEC = json.JSONDecoder(parse_constant=_no_constant, parse_float=_number, parse_int=_integer)
DECODE_ERRORS = [0]


def _count_replace(exc):
    DECODE_ERRORS[0] += exc.end - exc.start
    return (REPLACEMENT * (exc.end - exc.start), exc.end)


codecs.register_error("cloud_replace", _count_replace)


def loads_strict(text):
    """json.loads that refuses NaN, Infinity and -Infinity (an answer holding one is not JSON to the next reader)."""
    return _DEC.decode(text)


def archive_kind(head):
    for magic, name in ARCHIVE_MAGIC:
        if head.startswith(magic):
            return name
    if head[257:262] == b"ustar":
        return "a tar archive"
    return None


def walk_inputs(top, wanted, skipped):
    """The regular files under `top`: the files of a directory in name order, then its subdirectories in name order. A link,
    a special file (a pipe is never opened), an unlistable directory and an archive are named in `skipped`, and so is a file
    whose name `wanted` refuses."""
    stack = [top]
    found = []
    while stack:
        if out_of_time():
            skipped.append({"path": shown_path(stack[-1]), "reason": "the time limit ended the listing of directories: this one and the rest were not listed"})
            return found
        directory = stack.pop()
        try:
            with os.scandir(directory) as it:
                entries = sorted(it, key=lambda e: e.name)
        except OSError as exc:
            skipped.append({"path": shown_path(directory), "reason": "the directory could not be listed", "error": describe(exc)})
            continue
        subdirs = []
        for n, entry in enumerate(entries):
            if n % 4096 == 4095 and out_of_time():
                skipped.append({"path": shown_path(directory), "reason": "the time limit ended the listing of this directory: its entries from %s on were not examined" % shown_path(entry.name)})
                return found
            try:
                if entry.is_symlink():
                    skipped.append({"path": shown_path(entry.path), "reason": "a symbolic link: links are not followed"})
                elif entry.is_dir(follow_symlinks=False):
                    subdirs.append(entry.path)
                elif not stat.S_ISREG(entry.stat(follow_symlinks=False).st_mode):
                    skipped.append({"path": shown_path(entry.path), "reason": "not a regular file: it is not opened"})
                elif wanted(entry.name):
                    found.append(entry.path)
                elif entry.name.lower().endswith(ARCHIVE_EXT):
                    skipped.append({"path": shown_path(entry.path), "reason": "an archive: extract it first; it was not read"})
                else:
                    skipped.append({"path": shown_path(entry.path), "reason": "its name is not one this tool reads"})
            except OSError as exc:
                skipped.append({"path": shown_path(entry.path), "reason": "the entry could not be examined", "error": describe(exc)})
        stack.extend(reversed(subdirs))
    return found


def gzip_header_length(buf):
    """The length of the gzip member header at the start of `buf`, None if `buf` ends inside it; ValueError if it is not one."""
    if len(buf) < 2:
        if buf[:1] and buf[:1] != b"\x1f":
            raise ValueError("not gzip")
        return None
    if buf[:2] != b"\x1f\x8b":
        raise ValueError("not gzip")
    if len(buf) < 10:
        return None
    if buf[2] != 8:
        raise ValueError("not deflate")
    flags, pos = buf[3], 10
    if flags & 4:
        if len(buf) < pos + 2:
            return None
        pos += 2 + int.from_bytes(buf[pos:pos + 2], "little")
    for bit in (8, 16):
        if flags & bit:
            end = buf.find(b"\x00", pos)
            if end < 0:
                return None
            pos = end + 1
    if flags & 2:
        pos += 2
    return pos if len(buf) >= pos else None


class Source:
    """One file as a stream of text. Gzip is recognised by its magic bytes (not its name) and expanded as it is read, at most
    `cap` bytes of expansion, every byte up to a break kept (a gzip that ends early, or fails its check, gives what came before
    it and says so in `error`); an archive (ZIP, tar, bzip2, xz, 7-Zip...) is named and not read. UTF-8 is assumed, UTF-16
    where a byte order mark says so; each byte that does not decode becomes U+FFFD and is counted in `replaced`. The read
    ends at the deadline (`timed_out`). Zero bytes after the last gzip member, to the end of the file, are padding (GNU gzip
    ignores them): they are counted in `trailing_zero_bytes` and are not a problem. Every problem of a file is kept in
    `problems` (the first FIRST_PROBLEMS), the rest counted, and `error` is the first."""

    def __init__(self, path, cap):
        self.path, self.cap = path, cap
        self.buf, self.pos = "", 0
        self.eof = False
        self.bytes_read = 0
        self.compressed = False
        self.error = None          # the first problem of the file; `problems` holds them in order, `problem_lines()` is what the answer lists
        self.problems = []
        self.problems_total = 0
        self.trailing_zero_bytes = 0
        self._zero_run = 0
        self._member = 0
        self.archive = None
        self.capped = False
        self.timed_out = False
        self.replaced = 0
        self.line = 1
        self.chars_before = 0
        self.encoding = "utf-8"
        self._dec = codecs.getincrementaldecoder("utf-8")("cloud_replace")
        self._first = True
        self._pending = b""
        self._ended = False
        self._state, self._hdr, self._tr, self._d, self._crc, self._isize = "header", b"", b"", None, 0, 0
        self.fh = self._raw = None
        try:
            if not stat.S_ISREG(os.stat(path).st_mode):
                raise OSError(errno.EINVAL, "not a regular file")
            self._raw = open(path, "rb")
            head = self._raw.read(512)
            self._raw.seek(0)
            kind = archive_kind(head)
            if kind:
                self.archive = kind
                self._problem("%s: extract it first; it was not read" % kind)
                self.eof = True
            elif head[:2] == b"\x1f\x8b":
                self.compressed = True
            self.fh = self._raw
        except OSError as exc:
            self._problem(describe(exc))
            self.eof = True

    def _problem(self, text):
        """Keep a problem of this file. The first stays in `error`; the first FIRST_PROBLEMS are listed, the rest are counted."""
        self.problems_total += 1
        if len(self.problems) < FIRST_PROBLEMS:
            self.problems.append(text)
        if self.error is None:
            self.error = text

    def problem_lines(self):
        """Every problem of the file in the order it happened (the first FIRST_PROBLEMS), and a line counting the rest."""
        lines = list(self.problems)
        if self.problems_total > len(self.problems):
            lines.append("%d more problem(s) of this file were counted and are not listed" % (self.problems_total - len(self.problems)))
        return lines

    def close(self):
        for h in (self.fh, self._raw):
            try:
                if h is not None:
                    h.close()
            except OSError:
                pass

    def _expand(self, want):
        """Up to `want` bytes of expansion of a gzip file (members one after another), bounded in memory by `want`. The members are
        read here, header, deflate data and trailer, so that a break or a failed check costs only the step it happened in: every
        byte before it is returned."""
        out = []
        got = 0
        while got < want and not self._ended:
            if out_of_time():                 # millions of empty members are many steps and no output: the deadline is checked here too
                self.timed_out = True
                self._ended = True
                break
            if not self._pending:
                raw = self._raw.read(1 << 18)
                if not raw:
                    if self._state != "header" or self._hdr:
                        self._problem("the compressed stream ends early, after %d bytes of expansion: what came before it was read" % (self.bytes_read + got))
                    else:
                        self.trailing_zero_bytes = self._zero_run         # zero padding after the last member, to the end of the file: counted, not damage
                    self._ended = True
                    break
                self._pending = raw
            if self._state == "header":
                buf = self._hdr + self._pending
                if self._zero_run or buf[:1] == b"\x00":
                    stripped = buf.lstrip(b"\x00")                 # zeros cannot begin a member; GNU gzip ignores such padding at the end of a file
                    self._zero_run += len(buf) - len(stripped)
                    buf = stripped
                    if not buf:
                        self._hdr = self._pending = b""
                        continue
                try:
                    if self._zero_run:
                        raise ValueError("zeros, then something that is not the end of the file")
                    n = gzip_header_length(buf)
                except ValueError:
                    self._problem("%d bytes follow the end of the compressed stream and are not another member: they were not read" % (self._zero_run + len(buf)))
                    self._ended = True
                    self._pending = b""
                    break
                if n is None:
                    self._hdr, self._pending = buf, b""
                    continue
                self._pending, self._hdr = buf[n:], b""
                self._d, self._crc, self._isize, self._state = zlib.decompressobj(-15), 0, 0, "body"
            elif self._state == "body":
                try:
                    piece = self._d.decompress(self._pending, min(want - got, 32768))
                except zlib.error as exc:
                    self._problem("the compressed stream is damaged after %d bytes of expansion (%s): what came before it was read" % (self.bytes_read + got, exc))
                    self._ended = True
                    self._pending = b""
                    break
                self._pending = self._d.unconsumed_tail
                if self._d.eof:
                    self._pending = self._d.unused_data      # at the end of the stream the tail repeats what is already here
                if piece:
                    out.append(piece)
                    got += len(piece)
                    self._crc = zlib.crc32(piece, self._crc)
                    self._isize += len(piece)
                if self._d.eof:
                    self._state = "trailer"
            else:
                take = self._pending[:8 - len(self._tr)]
                self._tr += take
                self._pending = self._pending[len(take):]
                if len(self._tr) == 8:
                    crc, size = struct.unpack("<II", self._tr)
                    self._tr = b""
                    self._member += 1
                    failed = (["CRC-32"] if crc != self._crc & 0xFFFFFFFF else []) + (["length"] if size != self._isize & 0xFFFFFFFF else [])
                    if failed:
                        self._problem("member %d of the compressed stream fails its %s check: its bytes were read and may be wrong" % (self._member, " and ".join(failed)))
                    self._state = "header"
        return b"".join(out)


    def fill(self):
        """Read one more chunk into the buffer; False at the end."""
        if self.eof:
            return False
        if out_of_time():
            self.timed_out = True
            self.eof = True
            return False
        room = self.cap - self.bytes_read
        want = min(CHUNK, room + 1)
        try:
            data = self._expand(want) if self.compressed else self.fh.read(want)
        except OSError as exc:
            self._problem(describe(exc))
            self.eof = True
            data = b""
        if self._first and self.compressed and data[257:262] == b"ustar":
            self.archive = "a tar archive"
            self._problem("a tar archive (gzip-compressed): extract it first; it was not read")
            self.eof = True
            data = b""
        if self._ended:
            self.eof = True
        if len(data) > room:
            data = data[:room]
            self.capped = True
            self.eof = True
        elif not data:
            self.eof = True
        if self._first and data[:2] in (b"\xff\xfe", b"\xfe\xff"):
            # A byte order mark: the export is UTF-16 (PowerShell's Export-Csv -Encoding Unicode writes it), not UTF-8.
            self._dec = codecs.getincrementaldecoder("utf-16")("cloud_replace")
            self.encoding = "utf-16"
        self.bytes_read += len(data)
        before = DECODE_ERRORS[0]
        text = self._dec.decode(data, final=self.eof)
        self.replaced += DECODE_ERRORS[0] - before
        if self._first and text:
            self._first = False
            if text[0] == BOM:
                text = text[1:]
        self.buf += text
        return bool(data)

    def advance(self, new_pos):
        self.line += self.buf.count("\n", self.pos, new_pos)
        self.pos = new_pos
        if self.pos > 4 * CHUNK:
            self.chars_before += self.pos
            self.buf = self.buf[self.pos:]
            self.pos = 0

    def ensure(self, n):
        while len(self.buf) - self.pos < n and self.fill():
            pass

    def skip_ws(self):
        while True:
            end = _SPACE.match(self.buf, self.pos).end()
            self.advance(end)
            if self.pos < len(self.buf) or not self.fill():
                return

    def offset(self):
        return self.chars_before + self.pos


class TooLong(Exception):
    pass


def _decode_at(src, limit, lead=""):
    """One JSON value at the read position (with `lead` put in front of the text, to read the rest of an object whose
    first key was already consumed), reading more while it is incomplete; `limit` bounds the text held while waiting for it
    to end. Returns the value and the buffer index after it. The position is not moved."""
    while True:
        text = lead + src.buf[src.pos:] if lead else src.buf
        at = 0 if lead else src.pos
        try:
            value, end = _DEC.raw_decode(text, at)
            if not isinstance(value, (dict, list)) and end >= len(text) and not src.eof:
                raise json.JSONDecodeError("a value that may continue", text, end)
            return value, (src.pos + end - len(lead)) if lead else end
        except json.JSONDecodeError as exc:
            if src.eof:
                raise
            # An error well inside the text is a real one; at its end, or in an unterminated string, the record may only be
            # incomplete, and more is read (within `limit`).
            if exc.pos < len(text) - 16 and not exc.msg.startswith("Unterminated string"):
                raise
            if len(src.buf) - src.pos > limit:
                raise TooLong()
            src.fill()
        except RecursionError:
            raise json.JSONDecodeError("nested too deeply", text, at)


_STRING = re.compile(r'"(?:[^"\\]|\\.)*"', re.S)
_TOKEN = re.compile(r'["{}\[\]]')
_BARE = re.compile(r'[^\s,}\]"\[{:]+')


def _more(src, i, limit):
    """Make buffer index `i` exist, reading as needed; False when the file ends first. Raises TooLong past `limit`."""
    while i >= len(src.buf):
        if len(src.buf) - src.pos > limit:
            raise TooLong()
        if not src.fill():
            return False
    return True


def _skip_ws_at(src, i, limit):
    while True:
        if not _more(src, i, limit):
            return i
        i = _SPACE.match(src.buf, i).end()
        if i < len(src.buf) or not _more(src, i, limit):
            return i


def _skip_value(src, i, limit):
    """The buffer index after the JSON value that starts at `i` (a scalar, a string, or a balanced object or array), found without
    parsing it; None if the file ends or the text is not JSON."""
    i = _skip_ws_at(src, i, limit)
    if not _more(src, i, limit):
        return None
    c = src.buf[i]
    if c == '"':
        while True:
            m = _STRING.match(src.buf, i)
            if m:
                return m.end()
            if not _more(src, len(src.buf), limit):
                return None
    if c in "{[":
        depth, j = 0, i
        while True:
            m = _TOKEN.search(src.buf, j)
            if not m:
                j = len(src.buf)
                if not _more(src, j, limit):
                    return None
                continue
            ch = m.group(0)
            if ch == '"':
                s = _STRING.match(src.buf, m.start())
                if not s:
                    if not _more(src, len(src.buf), limit):
                        return None
                    j = m.start()
                    continue
                j = s.end()
                continue
            depth += 1 if ch in "{[" else -1
            j = m.end()
            if depth == 0:
                return j
            if depth < 0:
                return None
    m = _BARE.match(src.buf, i)
    while m and m.end() >= len(src.buf) and not src.eof:
        if not _more(src, len(src.buf), limit):
            break
        m = _BARE.match(src.buf, i)
    return m.end() if m else None


_STR_RUN = re.compile(r'[^"\\]*+(?:\\.[^"\\]*+)*+', re.S)  # a string's body up to its closing quote, or to a lone backslash at the buffer's end (possessive, Python 3.11 and later: the plain form keeps state for every escape)
_JSON_RUN = re.compile(r'(?:[^"{}\[\]]++|"[^"\\]*+(?:\\.[^"\\]*+)*+")*+', re.S)   # plain text and whole strings, up to the next bracket or a string the buffer ends inside
_BRACKET = re.compile(r'[{}\[\]]')
_NOT_BRACKET = re.compile(r'[^{}\[\]]+')
_DEPTH_STEP = [0] * 256
_DEPTH_STEP[ord("{")] = _DEPTH_STEP[ord("[")] = 1
_DEPTH_STEP[ord("}")] = _DEPTH_STEP[ord("]")] = -1


def _skip_stream(src):
    """Move the read position past the JSON value that starts at it, holding none of it: the scan takes what the buffer has, moves
    the position on and reads the next chunk, so memory stays at one chunk whatever the size of the value (a record over
    max_record_bytes is skipped this way). It steps over strings and counts brackets and looks at nothing else, so it needs no
    valid JSON inside the value. The clock is read every 4096 steps, and `fill` reads it too. Returns "ok" (the position is after
    the value), "bad" (what stands there is not a value) or "end" (the file, the clock or the expansion cap ended it first:
    `src.timed_out` and `src.capped` say which)."""
    src.ensure(1)
    if src.pos >= len(src.buf):
        return "end"
    first = src.buf[src.pos]
    depth, in_string, steps = 0, False, 0
    if first in "{[":
        depth = 1
        src.advance(src.pos + 1)
    elif first == '"':
        in_string = True
        src.advance(src.pos + 1)
    else:
        m = _BARE.match(src.buf, src.pos)
        if not m:
            return "bad"
        while True:
            src.advance(m.end())
            if src.pos < len(src.buf) or not src.fill():
                return "ok"
            m = _BARE.match(src.buf, src.pos)
            if not m:
                return "ok"
    while True:
        buf, j, n = src.buf, src.pos, len(src.buf)
        while j < n:
            steps += 1
            if not steps & 4095 and out_of_time():
                src.advance(j)
                src.timed_out = True
                src.eof = True
                return "end"
            if in_string:
                e = _STR_RUN.match(buf, j).end()
                if e < n and buf[e] == '"':
                    j = e + 1
                    in_string = False
                    if depth == 0:
                        src.advance(j)
                        return "ok"
                    continue
                j = e                       # the buffer ends inside the string, or on a backslash whose next character is still to come
                break
            j = _JSON_RUN.match(buf, j).end()    # plain text and whole strings, at C speed, up to a bracket
            if j >= n:
                break
            if buf[j] == '"':               # a string the buffer ends inside
                in_string = True
                j += 1
                continue
            q = buf.find('"', j)            # a bracket: the stretch up to the next string
            end = q if q >= 0 else n
            closers = buf.count("}", j, end) + buf.count("]", j, end)
            if closers and depth - closers <= 0:
                # The value may end in this stretch. The lowest depth it reaches is found at C speed (the brackets alone, summed as they come);
                # only a stretch that does reach zero is walked bracket by bracket, to find where.
                lowest = min(itertools.accumulate(map(_DEPTH_STEP.__getitem__, _NOT_BRACKET.sub("", buf[j:end]).encode())))
                if depth + lowest <= 0:
                    for m in _BRACKET.finditer(buf, j, end):
                        depth += 1 if m.group() in "{[" else -1
                        if depth <= 0:
                            src.advance(m.end())
                            return "ok"
            depth += buf.count("{", j, end) + buf.count("[", j, end) - closers
            j = end
        src.advance(j)
        if not src.fill():
            return "end"


def envelope_scan(src, envelope_keys, limit):
    """For an object that starts at the read position: ("envelope", key, index after its `[`, names of the members before it)
    if a member named in `envelope_keys` holds an array, with the members in front of it skipped whatever they hold;
    ("plain", None, None, names) if the object ends without one; ("bad", reason, None, names) if it is not JSON. Nothing
    is consumed: the buffer only grows."""
    i = src.pos + 1
    names = []
    while True:
        i = _skip_ws_at(src, i, limit)
        if not _more(src, i, limit):
            return "bad", "the object is not closed", None, names
        c = src.buf[i]
        if c == "}":
            return "plain", None, i + 1, names
        if c == ",":
            i += 1
            continue
        if c != '"':
            return "bad", "a member name was expected", None, names
        while True:
            m = _STRING.match(src.buf, i)
            if m or not _more(src, len(src.buf), limit):
                break
        if not m:
            return "bad", "a member name is not closed", None, names
        key = m.group(0)[1:-1]
        i = _skip_ws_at(src, m.end(), limit)
        if not _more(src, i, limit) or src.buf[i] != ":":
            return "bad", "a colon was expected after a member name", None, names
        i = _skip_ws_at(src, i + 1, limit)
        if key in envelope_keys and _more(src, i, limit) and src.buf[i] == "[":
            return "envelope", key, i + 1, names
        names.append(key)
        j = _skip_value(src, i, limit)
        if j is None:
            return "bad", "the value of a member is not JSON or is not closed", None, names
        i = j


def read_units(src, envelope_keys, record_cap=MAX_RECORD_BYTES, document_cap=MAX_DOCUMENT_BYTES):
    """Yield the records of a JSON file as ("item", info, value) or ("reject", info, reason), one by one, whatever the
    shape: an array, an object with a named array of records (streamed, however much sits in front of it, and the object's
    other keys read after it), JSON Lines (a bad line is rejected and the next is read), or one pretty-printed document
    (read whole, within `document_cap`, and parsed once); several arrays or envelopes one after another are read in turn.
    `info` is {record, line, offset, chars, envelope}. After the last unit (or when the reader is closed early)
    `src.mode` names the shape, `src.extra_keys` the other top-level keys of the envelopes (names only) and `src.stopped`
    says why reading ended before the end of the file, if it did."""
    src.mode, src.extra_keys, src.stopped, src.envelope = "empty", [], None, None
    count, modes, extra = [0], [], set()

    def info(line, offset, chars, envelope):
        count[0] += 1
        return {"record": count[0], "line": line, "offset": offset, "chars": chars, "envelope": envelope}

    def skip_oversize(start_line, start_off, key):
        """A record over the cap, which the read position stands at: scan to its end without holding it (clocked, one chunk of
        memory). Returns the reject to yield, and whether the read must stop. A skipped record is rejected with where it was
        and how long; the records after it are read."""
        outcome = _skip_stream(src)
        if outcome == "ok":
            return ("reject", info(start_line, start_off, src.offset() - start_off, key),
                    "a record larger than max_record_bytes (%d): skipped, and the records after it are read" % record_cap), False
        if outcome == "bad":
            src.stopped = "what stands at line %d, where a record larger than max_record_bytes should be, is not a JSON value: the rest of the array was not read" % start_line
            return ("reject", info(start_line, start_off, None, key), "a record larger than max_record_bytes (%d), and not a JSON value" % record_cap), True
        src.stopped = ("the time limit ended the read" if src.timed_out else
                       "the expansion reached max_expanded_bytes inside a record larger than max_record_bytes at line %d" % start_line if src.capped else
                       "the array was not closed: the file ends inside a record larger than max_record_bytes at line %d" % start_line)
        return ("reject", info(start_line, start_off, None, key), "a record larger than max_record_bytes (%d), and the read ended inside it" % record_cap), True

    def finish():
        src.extra_keys = sorted(extra)
        src.mode = modes[0] if len(set(modes)) == 1 else ("mixed" if modes else "empty")
        if src.timed_out and not src.stopped:
            src.stopped = "the time limit ended the read"

    try:
        while True:
            src.ensure(4096)
            src.skip_ws()
            src.ensure(65536)
            if src.pos >= len(src.buf):
                break
            first = src.buf[src.pos]
            key, names, bracket, one_line = None, [], None, ""
            if first == "{":
                line_end = src.buf.find("\n", src.pos)
                one_line = src.buf[src.pos: line_end if line_end >= 0 else len(src.buf)].strip()
                if one_line == "{" or line_end < 0 or line_end - src.pos > 65536:
                    # a pretty-printed object, or one too long to be a JSON Lines record: look for the array of records in it
                    try:
                        kind, key, bracket, names = envelope_scan(src, envelope_keys, document_cap)
                    except TooLong:
                        src.stopped = ("the object around the records is larger than %d characters before its array of records: it was not read" % document_cap)
                        yield "reject", info(src.line, src.offset(), None, None), src.stopped
                        return
                    if kind != "envelope":
                        key, bracket = None, None
            if first == "[" or bracket is not None:
                modes.append("envelope" if bracket is not None else "array")
                if key:
                    src.envelope = src.envelope or key
                    extra.update(names)
                src.advance(bracket if bracket is not None else src.pos + 1)
                src.skip_ws()
                expecting_item = True
                while True:
                    while src.pos >= len(src.buf):
                        if not src.fill():
                            src.stopped = src.stopped or ("the time limit ended the read" if src.timed_out else "the array was not closed: the file ends inside it")
                            return
                    here = src.buf[src.pos]
                    if here == "]":
                        src.advance(src.pos + 1)
                        break
                    if here == ",":
                        if expecting_item:
                            src.stopped = "an unexpected comma at line %d: the rest of the array was not read" % src.line
                            yield "reject", info(src.line, src.offset(), None, key), "malformed JSON: an unexpected comma"
                            return
                        src.advance(src.pos + 1)
                        src.skip_ws()
                        expecting_item = True
                        continue
                    if not expecting_item:
                        src.stopped = "no comma between records at line %d: the rest of the array was not read" % src.line
                        yield "reject", info(src.line, src.offset(), None, key), "malformed JSON: no comma between records"
                        return
                    start_line, start_off, start_pos = src.line, src.offset(), src.pos
                    try:
                        value, end = _decode_at(src, record_cap)
                    except TooLong:
                        reject, stop = skip_oversize(start_line, start_off, key)
                        yield reject
                        if stop:
                            return
                        expecting_item = False
                        src.skip_ws()
                        if src.timed_out:
                            return
                        continue
                    except json.JSONDecodeError as exc:
                        if src.timed_out:       # the deadline cut the record, the JSON is not damaged
                            src.stopped = "the time limit ended the read"
                            yield "reject", info(start_line, start_off, None, key), "the last record is cut off where the read ended (the time limit)"
                            return
                        if exc.msg == "nested too deeply":
                            # a record the decoder cannot hold is valid JSON as far as can be told: it is skipped without parsing it (by counting
                            # its brackets), rejected, and the records after it are read
                            try:
                                skip_end = _skip_value(src, start_pos, record_cap)
                            except TooLong:             # over the cap as well: the scan that holds nothing skips it
                                reject, stop = skip_oversize(start_line, start_off, key)
                                yield reject
                                if stop:
                                    return
                                expecting_item = False
                                src.skip_ws()
                                if src.timed_out:
                                    return
                                continue
                            if skip_end is not None:
                                src.advance(skip_end)
                                yield "reject", info(start_line, start_off, skip_end - start_pos, key), "a record nested too deeply to be read (deeper than the JSON decoder holds)"
                                expecting_item = False
                                src.skip_ws()
                                continue
                        src.stopped = "the JSON stopped being valid at line %d (%s): the rest was not read" % (start_line, exc.msg)
                        yield "reject", info(start_line, start_off, None, key), "malformed JSON: %s" % exc.msg
                        return
                    src.advance(end)
                    yield "item", info(start_line, start_off, end - start_pos, key), value
                    expecting_item = False
                    src.skip_ws()
                    if src.timed_out:
                        return
                if key:
                    # the rest of the envelope object: its other keys, names only (a next-page token is a token)
                    src.skip_ws()
                    if src.pos < len(src.buf) and src.buf[src.pos] == ",":
                        src.advance(src.pos + 1)
                    try:
                        obj, end = _decode_at(src, record_cap, lead="{")
                    except (TooLong, json.JSONDecodeError):
                        src.stopped = "the time limit ended the read" if src.timed_out else "the object around the records does not end validly: its other keys were not read"
                        return
                    src.advance(end)
                    extra.update(str(k) for k in obj)
                continue
            # not an array, not an envelope: one pretty-printed document, or JSON Lines to the end of the file
            if first == "{" and one_line == "{":
                modes.append("document")
                start_line, start_off = src.line, src.offset()
                try:
                    value, end = _DEC.raw_decode(src.buf, src.pos)
                except (json.JSONDecodeError, RecursionError) as exc:
                    if src.timed_out:
                        src.stopped = "the time limit ended the read"
                        return
                    src.stopped = "the JSON stopped being valid near line %d (%s): the rest was not read" % (start_line, getattr(exc, "msg", "nested too deeply"))
                    yield "reject", info(start_line, start_off, None, None), "malformed JSON: %s" % getattr(exc, "msg", "nested too deeply")
                    return
                src.advance(end)
                yield from _expand(value, envelope_keys, info, start_line, start_off, src, extra)
                continue
            modes.append("lines")
            while True:
                src.skip_ws()
                if src.pos >= len(src.buf):
                    break
                i = src.buf.find("\n", src.pos)
                while i < 0 and not src.eof and len(src.buf) - src.pos <= record_cap:
                    src.fill()
                    i = src.buf.find("\n", src.pos)
                start_line, start_off = src.line, src.offset()
                if (i if i >= 0 else len(src.buf)) - src.pos > record_cap:
                    size = 0
                    while True:
                        i = src.buf.find("\n", src.pos)
                        if i >= 0:
                            size += i - src.pos
                            src.advance(i + 1)
                            break
                        size += len(src.buf) - src.pos
                        src.advance(len(src.buf))
                        if not src.fill():
                            break
                    yield "reject", info(start_line, start_off, size, None), "a line larger than max_record_bytes (%d)" % record_cap
                    continue
                text = src.buf[src.pos: i if i >= 0 else len(src.buf)]
                src.advance(i + 1 if i >= 0 else len(src.buf))
                stripped = text.strip()
                if not stripped:
                    continue
                try:
                    value = loads_strict(stripped)
                except (ValueError, RecursionError) as exc:
                    reason = "malformed JSON: %s" % getattr(exc, "msg", type(exc).__name__)
                    if i < 0 and src.eof and (src.error or src.capped or src.timed_out):
                        reason = "the last record is cut off where the read ended (%s)" % (src.error or "the expansion cap" if not src.timed_out else "the time limit")
                    yield "reject", info(start_line, start_off, len(text), None), reason
                    continue
                yield from _expand(value, envelope_keys, info, start_line, start_off, src, extra)
                if src.timed_out:
                    return
            break
    finally:
        finish()


def _expand(value, envelope_keys, info, line, offset, src, extra):
    """A parsed top-level value of a lines or document file: an envelope object yields its records, a list its elements."""
    if isinstance(value, dict):
        for key in envelope_keys:
            if isinstance(value.get(key), list):
                src.envelope = src.envelope or key
                extra.update(str(k) for k in value if k != key)
                for element in value[key]:
                    yield "item", info(line, offset, None, key), element
                return
        yield "item", info(line, offset, None, None), value
    elif isinstance(value, list):
        for element in value:
            yield "item", info(line, offset, None, None), element
    else:
        yield "reject", info(line, offset, None, None), "a JSON %s, not a record" % type(value).__name__


# ---- CSV and what both CSV and JSON rows need ------------------------------------------------------------------------


def csv_lines(src, cap=MAX_FIELD_BYTES):
    """The lines of a CSV file, newline kept, one at a time (a quoted field may span several). A line longer than `cap` (the call's
    max_record_bytes, 16 MiB unless it is raised, as for a JSON record) stops the file, named."""
    while True:
        i = src.buf.find("\n", src.pos)
        while i < 0 and not src.eof and len(src.buf) - src.pos <= cap:
            src.fill()
            i = src.buf.find("\n", src.pos)
        if i < 0 and src.pos >= len(src.buf):
            return
        end = i + 1 if i >= 0 else len(src.buf)
        if end - src.pos > cap:
            raise TooLong()
        line = src.buf[src.pos:end]
        src.advance(end)
        yield line


def csv_rows(src, delimiter, field_limit, record_cap=MAX_FIELD_BYTES):
    """Yield ("row", info, dict) / ("reject", info, reason) for a CSV file; a bad row is rejected and the next is read; a failure
    of the reader itself stops the file, says where, and keeps what was read. A header name that repeats keeps every column
    (the second is `name#2`)."""
    src.mode, src.stopped, src.extra_keys, src.envelope, src.header = "csv", None, [], None, None
    csv.field_size_limit(field_limit)
    line_cap = record_cap
    reader = csv.reader(csv_lines(src, line_cap), delimiter=delimiter)
    header, count = None, 0
    while True:
        before = reader.line_num
        try:
            row = next(reader)
        except StopIteration:
            break
        except TooLong:
            src.stopped = "a line longer than %d characters at line %d: the rest of the file was not read" % (line_cap, before + 1)
            yield "reject", {"record": count + 1, "line": before + 1, "offset": src.offset(), "chars": None, "envelope": None}, src.stopped
            return
        except csv.Error as exc:
            src.stopped = "the CSV reader stopped at line %d (%s): the rest of the file was not read" % (before + 1, exc)
            yield "reject", {"record": count + 1, "line": before + 1, "offset": src.offset(), "chars": None, "envelope": None}, "CSV error: %s" % exc
            return
        if not row:
            continue
        if header is None:
            seen = {}
            header = []
            for name in row:
                seen[name] = seen.get(name, 0) + 1
                header.append(name if seen[name] == 1 else "%s#%d" % (name, seen[name]))
            src.header = header
            if len(header) == 1 and re.search(r"[;\t|]", header[0]):
                src.stopped = "the header is one column that contains ';', a tab or '|': the file may use another delimiter (pass delimiter)"
                yield "reject", {"record": 0, "line": before + 1, "offset": 0, "chars": None, "envelope": None}, src.stopped
                return
            continue
        count += 1
        info = {"record": count, "line": before + 1, "offset": None, "chars": None, "envelope": None}
        if len(row) != len(header):
            yield "reject", info, "the row has %d fields and the header %d" % (len(row), len(header))
            continue
        yield "row", info, dict(zip(header, row))
        if src.timed_out:
            return
    if src.timed_out and not src.stopped:
        src.stopped = "the time limit ended the read"


def sniff(path):
    """'json' or 'csv', from the first characters of the file's own content (decompressed if it is gzip), never its name."""
    src = Source(path, MAX_EXPANDED_BYTES)
    try:
        src.ensure(4096)
        head = src.buf[src.pos:].lstrip()
    finally:
        src.close()
    return "json" if head[:1] in ("{", "[") else "csv"


def key_map(item):
    return {k.strip().lower(): k for k in item if isinstance(k, str)}


def first_of(item, keys, *names):
    for n in names:
        k = keys.get(n.lower())
        if k is not None and item.get(k) not in (None, ""):
            return item[k]
    return None


# ---- END SHARED BLOCK -------------------------------------------------------------------------------------------

# BEGIN SHARED WITHHOLDING
# The same text is in every tool that withholds identifier-shaped strings and credentials (the network, base, encrypted-containers,
# memory, virtualization, ransomware and reverse-engineering packs, and the three tools of the cloud pack), so that they withhold the
# same strings; the tests that hold the copies equal are tests/shared-blocks-census.test.ts (how many carry it),
# tests/pack-re-delta10.test.ts (every copy equal, found by the marker), tests/pack-network-withholding.test.ts,
# tests/pack-base-shared.test.ts, tests/pack-virtualization-shared.test.ts, tests/pack-re-process.test.ts and
# tests/pack-cloud-shared.test.ts. An identifier-shaped string is withheld wherever the tool would print one: a name, a path
# component, a URL, a message that quotes either; and a credential (a value given to a password, a token, a cookie, a pair, a
# switch) by the name it is given under. A carrier may set two names above this block: WITHHOLD_LIMIT, the length past which a text is
# withheld whole (65536 when it sets none), and WITHHOLD_TICK, a hook that long scans call and that may raise to end them at the
# carrier's deadline (none when it sets none). Nothing else in the block is a carrier's to change.
COUNTS = {"names": 0, "urls": 0, "text": 0}
# A run of name characters long enough to be a token. `=` is only a padding at the end (so a key= prefix stays);
# `/` joins pieces of a base64 token and is handled apart, below.
_RUN = re.compile(r"[A-Za-z0-9_+%-]{20,}={0,2}|[A-Za-z0-9_+%-]{14,}={2}")
_SLASHED = re.compile(r"[A-Za-z0-9_+/%-]{30,}={0,2}")
_HEX = re.compile(r"[0-9a-fA-F]{32,}")
# The prefixed secrets that one expression finds. A JWT is not among them: `eyJ` + 8 name characters + `.` + 8 + `.` + the rest, tried at
# every `eyJ`, runs to the end of the run of name characters and fails again at each next `eyJ` of a text made of them, which costs the
# square of the length. `_prefixed_spans` reads a JWT in one pass instead, and puts it in order with these.
_PREFIX_RULES = re.compile(r"(?:AKIA|ASIA)[0-9A-Z]{16}|gh[pousr]_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{20,}"
                           r"|xox[abeprs]-[A-Za-z0-9-]{10,}|sk-[A-Za-z0-9_-]{20,}"
                           r"|(?i:basic|bearer)\s+[A-Za-z0-9+/=._~-]{8,}")
_JWT_RUN = re.compile(r"[A-Za-z0-9_-]+")
# User-info: after `//` (a URL, or a scheme-relative one), or bare as name:password@host. A mailto: address is not one.
_USERINFO = re.compile(r"(?<=//)[^/?#\s@]+(?=@)")
_BARE_USERINFO = re.compile(r"(?<![\w.%+:/-])(?!mailto:)[\w.%+-]{1,64}:[^\s/@:]{1,128}(?=@[\w\[])")


def _withheld(what, length, kind):
    COUNTS[kind] = COUNTS.get(kind, 0) + 1
    return ("<%s withheld %d characters>" % (what, length)) if what else ("<withheld %d characters>" % length)


def _token_run(run):
    """Is this run of name characters shaped like a token, and not like words, dates or versions?"""
    if _HEX.search(run):
        return True
    chunks = [(m.group()[0].isdigit(), m.start(), m.end()) for m in re.finditer(r"[A-Za-z]+|[0-9]+", run)]
    # digits packed between letters ("a9b2c7"), which words, dates and versions do not do
    packed = 0
    for i, (is_digit, start, end) in enumerate(chunks):
        if not is_digit or end - start > 3:
            continue
        before = i > 0 and not chunks[i - 1][0] and chunks[i - 1][2] == start
        after = i + 1 < len(chunks) and not chunks[i + 1][0] and chunks[i + 1][1] == end
        packed += 1 if before or after else 0
    if packed >= 3:
        return True
    letters = [c for c in run if c.isalpha()]
    case_flips = sum(1 for a, b in zip(letters, letters[1:]) if a.islower() != b.islower())
    if len(letters) >= 20 and case_flips >= max(8, 0.4 * len(letters)):
        return True
    if run.endswith("==") and len(run) >= 16:
        return True
    if run.endswith("=") and len(run) >= 24:
        return True
    return len(run) >= 40 and run.isalnum() and any(c.isdigit() for c in run) and any(c.isalpha() for c in run)


def _randomish(piece):
    """A piece of a path that is not a plain word: digits among letters, or capitals inside a word."""
    if len(piece) < 4 or "." in piece or re.fullmatch(r"[A-Z][a-z]+", piece):
        return False
    letters = [c for c in piece if c.isalpha()]
    mixed = any(c.islower() for c in letters) and any(c.isupper() for c in letters)
    return (any(c.isdigit() for c in piece) and bool(letters)) or mixed


_SPAN_PIECE = re.compile(r"[A-Za-z0-9_+%-]+")
# A text longer than this is withheld whole, by its length, and not examined: no name, path or URL is tens of thousands of characters
# long, and the answer says how long the text was. Every rule below reads a text of this length in well under a second whatever its
# characters are, so that no call of `scrub` or `token_spans` can run for long on a text a file chose; the limit is the backstop for
# a shape of text that no rule was tried on, and the rules themselves are linear.
TEXT_LIMIT = globals().get("WITHHOLD_LIMIT", 65536)


def _prefixed_spans(text, tail=None):
    """The spans of the prefixed secrets in the text (a vendor prefix, a JWT, `Basic`/`Bearer` and its value), left to right and apart,
    as one expression holding all of them would find them (the first match at each offset, the next search where the last ended), in
    time linear in the text. With `tail`, an expression matched where each span ends, the span takes what it matches.

    A JWT is read from the runs of name characters (`[A-Za-z0-9_-]+`), cut once: its head is the first `eyJ` of a run that is followed
    by 8 or more characters of that run, and it ends where the third part of the JWT does; every later `eyJ` of the run reads the same
    rest, so the first one is the one that matches and a run that does not hold a JWT is not read again for each `eyJ` in it."""
    from bisect import bisect_right
    size = len(text)
    starts, ends, rest = [], [], {}
    if "eyJ" in text:
        for m in _JWT_RUN.finditer(text):
            starts.append(m.start())
            ends.append(m.end())

    def jwt_end(r):      # where a JWT whose head is in run r ends, or -1: `.`, a run of 8 or more, `.`, then the rest of the next run
        if r not in rest:
            end, last = -1, ends[r] + 1
            if (last < size and text[last - 1] == "." and r + 1 < len(starts) and starts[r + 1] == last
                    and ends[r + 1] - last >= 8 and ends[r + 1] < size and text[ends[r + 1]] == "."):
                end = ends[r + 1] + 1
                if r + 2 < len(starts) and starts[r + 2] == end:
                    end = ends[r + 2]
            rest[r] = end
        return rest[r]

    def next_jwt(at):    # (start, end) of the first JWT that starts at or after `at`, or None
        while True:
            p = text.find("eyJ", at)
            if p < 0:
                return None
            r = bisect_right(starts, p) - 1
            if p + 11 <= ends[r] and jwt_end(r) >= 0:
                return p, jwt_end(r)
            at = ends[r]  # no `eyJ` further in this run can be a head either

    spans, at = [], 0
    other = _PREFIX_RULES.search(text)
    jwt = next_jwt(0) if starts else None
    while other is not None or jwt is not None:
        if other is not None and other.start() < at:      # it began inside the span just taken: look again from its end
            other = _PREFIX_RULES.search(text, at)
        elif jwt is not None and jwt[0] < at:
            jwt = next_jwt(at)
        else:
            start, end = other.span() if jwt is None or (other is not None and other.start() < jwt[0]) else jwt
            if tail is not None:
                end = tail.match(text, end).end()
            spans.append((start, end))
            at = end
    return spans


def _grow_spans(text, spans):
    """Each flagged span takes the random-looking pieces next to it across a `/`: the head of a token is not printed.

    One pass cuts the text into pieces (runs of name characters) and keeps where each starts and ends. A span then walks
    that array by index; a piece is judged once, and a walk that reaches a piece an earlier walk has settled stops there, so
    the work is linear in the text and no range is sliced or searched again. (Looking back with a search over everything
    before a piece costs the cube of the length for a name of many `/`-joined pieces.)"""
    from bisect import bisect_left
    starts, ends = [], []
    for m in _SPAN_PIECE.finditer(text):
        starts.append(m.start())
        ends.append(m.end())
    count, size = len(starts), len(text)
    judged_left, judged_right, settled_left, settled_right = {}, {}, {}, {}

    def padded(k):       # where piece k ends with the up to two `=` of padding after it
        e = ends[k]
        if e < size and text[e] == "=":
            e += 2 if e + 1 < size and text[e + 1] == "=" else 1
        return e

    def left_ok(j):
        if j not in judged_left:
            judged_left[j] = _randomish(text[starts[j]:ends[j]])
        return judged_left[j]

    def right_ok(k):
        if k not in judged_right:
            judged_right[k] = _randomish(text[starts[k]:padded(k)])
        return judged_right[k]

    def before(at):      # the piece that growing left from offset `at` takes, or -1. `$` also ends a match before a final line break.
        if at < 2 or text[at - 1] != "/":
            return -1
        for stop in ((at - 1, at - 2) if text[at - 2] == "\n" else (at - 1,)):
            j = bisect_left(ends, stop)
            if j < count and ends[j] == stop:
                return j if left_ok(j) else -1
        return -1

    def after(k):        # the piece that growing right from the end of piece k takes, or -1
        e = padded(k)
        if k + 1 >= count or e >= size - 1 or text[e] != "/" or starts[k + 1] != e + 1:
            return -1
        return k + 1 if right_ok(k + 1) else -1

    def settle(i, step, memo):
        trail = []
        while i not in memo:
            trail.append(i)
            j = step(i)
            if j < 0:
                memo[i] = i
                break
            i = j
        final = memo[i]
        for t in trail:
            memo[t] = final
        return final

    grown = []
    for start, end in spans:
        j = before(start)
        if j >= 0:
            start = starts[settle(j, lambda i: before(starts[i]), settled_left)]
        if end < size - 1 and text[end] == "/":
            k = bisect_left(starts, end + 1)
            if k < count and starts[k] == end + 1 and right_ok(k):
                end = padded(settle(k, after, settled_right))
        grown.append((start, end))
    return grown


def token_spans(text):
    if len(text) > TEXT_LIMIT:
        return [(0, len(text))]
    spans = _prefixed_spans(text)
    for m in _RUN.finditer(text):
        if _token_run(m.group()):
            spans.append(m.span())
    # A base64 token holds `/`: pieces too short to be one alone (an AWS-style secret has two) are caught as a whole.
    for m in _SLASHED.finditer(text):
        run = m.group()
        if "/" in run and sum(1 for p in run.split("/") if _randomish(p)) >= 3 and re.search(r"[0-9+]", run):
            spans.append(m.span())
    grown = _grow_spans(text, spans) if spans else []
    grown.sort()
    merged = []
    for start, end in grown:
        if merged and start <= merged[-1][1]:
            merged[-1] = (merged[-1][0], max(merged[-1][1], end))
        else:
            merged.append((start, end))
    return merged


def token_shaped(text):
    return bool(token_spans(text))


# ---- credentials: a value is withheld by the name it is given under and by the text around it ----------------------------------
# The rules above find strings that are shaped like an identifier. These find a secret that has no shape, because of what it is
# assigned to (`password=`, a `Name`/`Value` pair, a `-Password` switch, `curl -u user:pass`, `mysql -pSECRET`), and the common
# token families, private key blocks and hashes of an account database. A name decides whether a value is a secret, a value
# decides nothing. Every rule runs in time linear in the text (a bounded stretch after each anchor, no nested repeat), and a
# carrier whose texts are long (a cloud log: a megabyte) sets WITHHOLD_TICK to a hook that ends the work at its deadline.
_CRED_CHECKSUM_NAME = re.compile(r"(?i)checksum|digest|sha[0-9]|md5|etag|crc[0-9]")
_CRED_REDACTED = re.compile(r"^\W*(?:hidden_due_to_security_reasons|redacted|masked|removed|\*+|x{3,}|\[\])\W*$", re.I)
_CRED_NOT_A_VALUE = frozenset(("true", "false", "null", "none", "nil", "undefined", "required", "optional", "enabled", "disabled"))
_CRED_EXACT = {
    "password", "newpassword", "oldpassword", "currentpassword", "passwd", "pwd", "passphrase", "passcode", "pin", "otp",
    "pass", "dbpass", "userpass", "adminpass", "rootpass", "plaintext",
    "secret", "clientsecret", "secretkey", "secretaccesskey", "awssecretaccesskey", "awssecretkey", "secretstring",
    "secretbinary", "secrettext", "secretvalue", "accesskeysecret",
    "sessiontoken", "securitytoken", "accesstoken", "refreshtoken", "idtoken", "bearertoken", "authtoken", "token",
    "tokencode", "mfacode", "verificationcode", "authorizationcode",
    "authorization", "proxyauthorization", "cookie", "setcookie", "apikey", "privatekey", "privatekeypem",
    "sharedaccesskey", "sharedaccesssignature", "accountkey", "primarykey", "secondarykey", "keyvalue", "masterkey",
    "storagekey", "subscriptionkey", "ocpapimsubscriptionkey",
    "connectionstring", "credential", "credentials", "assertion", "samlresponse", "mfasecret",
    "sastoken", "sassignature", "signature", "sig",
    "passwordhash", "nthash", "ntlmhash", "lmhash",
}
_CRED_SUFFIX = ("password", "passwd", "passphrase", "secret", "apikey", "privatekey", "sessiontoken", "securitytoken",
                "accesstoken", "refreshtoken", "clientsecret", "token", "secrettext", "secretkey", "secretaccesskey",
                "primarykey", "secondarykey", "accountkey", "sharedaccesskey", "subscriptionkey", "passwordhash",
                "ntlmhash", "nthash", "passcode", "signature", "cookie")
# a position or an idempotency key under a name that ends in `token`
_CRED_NOT_SECRET = ("nexttoken", "pagetoken", "continuationtoken", "paginationtoken", "nextpagetoken", "pagingtoken",
                    "startingtoken", "nextmarkertoken", "clienttoken", "clientrequesttoken", "idempotencytoken",
                    "nextforwardtoken", "nextbackwardtoken", "requesttoken")
_CRED_CONTAINERS = ("credential", "credentials")
_CRED_NAME_CACHE = {}
_CRED_NAME_KEYS = ("Name", "name", "Key", "key")
_CRED_VALUE_KEYS = ("Value", "NewValue", "OldValue", "value", "newValue", "oldValue")


def is_container_name(name):
    """`credentials` names a group of fields (an access key id, an expiry, a token): each is judged by its own name."""
    return re.sub(r"[^a-z0-9]", "", str(name).lower()) in _CRED_CONTAINERS


def name_is_sensitive(name):
    """Does a field or a parameter of this name hold a secret? (`Password`, `client_secret`, `x-api-key`; not `nextToken`.)"""
    hit = _CRED_NAME_CACHE.get(name)
    if hit is None:
        flat = re.sub(r"[^a-z0-9]", "", str(name).lower())
        hit = flat in _CRED_EXACT or (len(flat) > 6 and flat.endswith(_CRED_SUFFIX) and not flat.endswith(_CRED_NOT_SECRET))
        if len(_CRED_NAME_CACHE) < 20000:
            _CRED_NAME_CACHE[name] = hit
    return hit


_CRED_B64 = "A-Za-z0-9+/_-"
_CRED_B64_RUN = re.compile(r"(?<![%s])[%s]{128,}={0,2}(?![%s])" % (_CRED_B64, _CRED_B64, _CRED_B64))
_CRED_B64_EDGE = "(?<![A-Za-z0-9+/=_-])"
_CRED_B64_END = "(?![A-Za-z0-9+/=_-])"
# The names an assignment is recognised by. A long compound name may carry any prefix (dbPassword=, apiToken=, adminSecret:);
# a short one needs the edge of a word (sig= is not design=).
_CRED_STRONG = (r"password|passwd|passphrase|secret|api[_-]?key|access[_-]?token|refresh[_-]?token|id[_-]?token|session[_-]?token|"
                r"security[_-]?token|auth[_-]?token|bearer[_-]?token|account[_-]?key|shared[_-]?access[_-]?key|primary[_-]?key|"
                r"secondary[_-]?key|private[_-]?key|subscription[_-]?key|sas[_-]?token|password[_-]?hash|nt[_-]?hash|ntlm[_-]?hash|"
                r"lm[_-]?hash|client[_-]?secret|secret[_-]?access[_-]?key|secret[_-]?key|secret[_-]?text|secret[_-]?value|token|signature|plaintext")
_CRED_SHORT = r"(?<![A-Za-z0-9])(?:pwd|pass|sig|pin|otp|sas)"
_CRED_SEP = r"""(?:\\*["']|["'])?\s*(?:[:=]|%3[dD]|%3[aA])\s*"""
# a short name is a name only as `pwd=value` or `pass:value`: "pass: 3 attempts" is prose
_CRED_SEPS = r"""(?:\\*["']|["'])?(?:\s*(?:=|%3[dD])\s*|:(?=\S))"""
_CRED_NAME = r"(?:(?:%s)%s|%s%s)" % (_CRED_STRONG, _CRED_SEP, _CRED_SHORT, _CRED_SEPS)
_CRED_ARN_TAIL = re.compile(r"arn:[A-Za-z0-9-]+:[A-Za-z0-9-]+:[A-Za-z0-9-]*:[0-9]*:$")
_CRED_PAIR_WHY = "a value paired with a credential name"
_CRED_RULES = [
    # anchored at the start of a run and possessive, so that a megabyte of `eyJ` is read once, not once per `eyJ`
    ("a JSON Web Token", re.compile(r"(?<![A-Za-z0-9_-])eyJ[A-Za-z0-9_-]{6,}+\.[A-Za-z0-9_-]{2,}+(?:\.[A-Za-z0-9_-]*+)?"), 0),
    ("a JSON Web Encryption token", re.compile(r"(?<![A-Za-z0-9_-])eyJ[A-Za-z0-9_-]{6,}+(?:\.[A-Za-z0-9_-]*+){4}"), 0),
    ("a password in a URL", re.compile(r"(?i)(?<![A-Za-z0-9+.-])[a-z][a-z0-9+.-]{1,20}://[^\s:/@\"'<>\\]{0,256}:([^\s/\"'<>\\]{1,1024})@(?=[^\s/@\"'<>]{1,255})"), 1),
    ("an Azure Functions key", re.compile(r"""(?i)(?:x-functions-key["']?\s*[:=]\s*(?:\\*["'])?|[?&;]code=)([A-Za-z0-9_/+=-]{16,512})"""), 1),
    ("a private key block", re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----(?:[\s\S]*?-----END [A-Z ]*PRIVATE KEY-----|[\s\S]*)"), 0),
    ("a base64 block of key lines", re.compile(r"(?:[A-Za-z0-9+/]{60,80}={0,2}\r?\n){2,}[A-Za-z0-9+/]{2,80}={0,2}"), 0),
    ("an authorization header value", re.compile(
        r"""(?i)authorization["']?\s*[:=]\s*(?:\\*["'])?(?:(?:bearer|basic|digest|negotiate|ntlm|token)\s+)?([^\s"'&,;\\]{1,4096})"""), 1),
    ("a cookie header value", re.compile(r"""(?i)cookie["']?\s*[:=]\s*(?:\\*["'])?([^\r\n"'\\]{1,4096})"""), 1),
    ("a scheme and its credential", re.compile(r"(?i)\b(?:bearer|basic)\s+([A-Za-z0-9._~+/=-]{3,4096})|\b(?:negotiate|ntlm|digest)\s+([A-Za-z0-9._~+/=-]{24,4096})"), -2),
    ("a value assigned to a credential name (quoted)", re.compile(
        r"""(?i)%s\\*(["'])(.{1,4096}?)(?=\\*\1)""" % _CRED_NAME), 2),
    ("a value assigned to a credential name", re.compile(
        r"""(?i)%s((?:(?!%%26)[^\s"'&<>\\]){1,4096})""" % _CRED_NAME), 1),
    ("a value given to a credential switch", re.compile(
        r"""(?i)(?<![A-Za-z0-9_])-(?:password|pass|pwd|passphrase|secret|clientsecret|apikey|accesstoken|token)\s+(?:\\*(["'])(.{1,4096}?)(?=\\*\1)|([^\s"'-][^\s"']{0,4095}))"""), -1),
    ("a secret given to ConvertTo-SecureString", re.compile(
        r"""(?i)ConvertTo-SecureString\s+(?:\\*(["'])(.{1,4096}?)(?=\\*\1)|([^\s"'-][^\s"']{0,4095}))"""), -1),
    # `mysql -u<user> -p<password>`: with `-p` glued to its value, and only as an option of a MySQL or MariaDB client (`ssh -p 22`,
    # `nc -p 80` and `mysql -p` alone, which asks for the password, name a port or nothing). The options are read up to the next
    # command of the kind, so that a text of many of them is read once, not once for each
    ("a password given to a MySQL client", re.compile(
        r"""(?i:(?<![\w.-])(?:mysql|mysqldump|mysqladmin|mysqlcheck|mysqlimport|mysqlshow|mariadb|mariadb-dump|mariadb-admin)(?:\.exe)?(?=\s))(?:(?!(?i:mysql|mariadb)\b)[^\n]){0,512}?(?<=\s)-p(?=[^\s`,;)])(?:"([^"\n]{1,256})"|'([^'\n]{1,256})'|([^\s"']{1,256}))"""), -3),
    # `curl -u user:password`: the part after the colon, and only when there is one (`curl -u user` asks for it)
    ("a password given to curl", re.compile(
        r"""(?i:(?<![\w.-])curl(?:\.exe)?(?=\s))(?:(?!(?i:curl)\b)[^\n]){0,512}?(?<=\s)(?:-u|-U|--user|--proxy-user)(?:\s+|=)(?:"[^":\n]*:([^"\n]{1,256})"|'[^':\n]*:([^'\n]{1,256})'|[^\s:"']*:([^\s"']{1,256}))"""), -3),
    ("a hash pair of an account database", re.compile(r"(?<![0-9a-fA-F])[0-9a-fA-F]{32}:([0-9a-fA-F]{32})(?![0-9a-fA-F])"), 1),
    ("a bcrypt hash", re.compile(r"(?<![A-Za-z0-9$])\$2[abxy]?\$[0-9]{2}\$[./A-Za-z0-9]{53}(?![./A-Za-z0-9])"), 0),
    ("a token of a known family", re.compile(
        r"(?:GOCSPX-[A-Za-z0-9_-]{20,}|gh[pousr]_[A-Za-z0-9]{36,}|github_pat_[A-Za-z0-9_]{50,}|xox[abprs]-[A-Za-z0-9-]{10,}|AIza[0-9A-Za-z_-]{35}(?![0-9A-Za-z_-])|"
        r"ya29\.[0-9A-Za-z_-]{20,}|1//0[0-9A-Za-z_-]{30,}|(?:IQoJb3JpZ2lu|FQoGZXIvYXdz|FwoGZXIvYXdz)[A-Za-z0-9+/=]{40,}|"
        r"[A-Za-z0-9_.~-]{3}[0-9]Q~[A-Za-z0-9_.~-]{30,}|[01]\.A[A-Za-z0-9_-]{50,}|[sr]k_(?:live|test)_[A-Za-z0-9]{16,})"), 0),
]
_CRED_GROUPS = {-1: (1, 2, 3), -2: (1, 2), -3: (1, 2, 3)}
# A random-looking run of an exact length that keys have: 32, 40 (an AWS secret access key), 43 + "=" and 86 + "==" (a base64 key).
_CRED_SHAPES = [
    ("a key-length base64 string", re.compile(_CRED_B64_EDGE + r"(?:[A-Za-z0-9+/]{32}|[A-Za-z0-9+/]{40}|[A-Za-z0-9+/]{43}=|[A-Za-z0-9+/]{86}==)" + _CRED_B64_END), True),
]
# A Name/Value pair written as JSON text inside a string (an AuditData in a column of another name, a parameter list in a cell): the
# structure rule (clean_value) cannot see it, so the text rule reads the head of the pair, and the name decides as it does there. The
# value is read by hand, not by an expression: a string up to its first quote (the backslashes before the quote are not part of it), a
# number, a flat array of up to 4,096 characters, or a literal; and the next value of the same pair (`OldValue`, then `NewValue`).
_CRED_PAIR_HEAD = re.compile(r"""(?i)\b(?:name|key)\\*"\s*:\s*\\*"([^"\\]{1,64})\\*"\s*,\s*\\*"(?:new|old)?value\\*"\s*:\s*""")
_CRED_NEXT_VALUE = re.compile(r"""(?i)\s*,\s*\\*"(?:new|old)?value\\*"\s*:\s*""")
_CRED_QUOTE = re.compile(r'\\*"')
# a format directive (`%s`, `%d`), a template field (`{0}`, `{name}`) or a `%VAR%` is where a value goes, not a value
_CRED_PLACEHOLDER = re.compile(r"%[-+ #0-9.]*[sdiuxXfeEgGcr](?![A-Za-z0-9])|\{\w*\}|%\w+%$|\.{2,}|\u2026")
_CRED_BARE = re.compile(r"-?[0-9][0-9.eE+-]{0,39}|\[[^\[\]]{0,4096}\]|(?:null|true|false)\b")
# What a text must hold for a rule to match it: a literal (lower case) of which one must be in the text, checked before the rule runs, so
# that a text with none of them (most names, addresses and ids) costs a few substring tests and no expression. An assignment rule also
# needs a separator in the text. Each is a necessary condition of its rule.
_CRED_ASSIGN = ("pass", "pwd", "secret", "key", "token", "signature", "plaintext", "sig", "pin", "otp", "sas", "hash")
_CRED_NEEDLES = {
    "a JSON Web Token": ("eyj",), "a JSON Web Encryption token": ("eyj",), "a password in a URL": ("://",),
    "an Azure Functions key": ("x-functions-key", "code="), "a private key block": ("-----begin",), "a base64 block of key lines": ("\n",),
    "an authorization header value": ("authorization",), "a cookie header value": ("cookie",),
    "a scheme and its credential": ("bearer", "basic", "negotiate", "ntlm", "digest"),
    "a value assigned to a credential name (quoted)": _CRED_ASSIGN, "a value assigned to a credential name": _CRED_ASSIGN,
    "a value given to a credential switch": ("password", "pass", "pwd", "secret", "apikey", "accesstoken", "token"),
    "a secret given to ConvertTo-SecureString": ("securestring",), "a password given to a MySQL client": ("mysql", "mariadb"),
    "a password given to curl": ("curl",), "a hash pair of an account database": (":",), "a bcrypt hash": ("$2",),
    "a token of a known family": ("gocspx-", "ghp_", "gho_", "ghu_", "ghs_", "ghr_", "github_pat_", "xoxa-", "xoxb-", "xoxp-", "xoxr-", "xoxs-",
                                  "aiza", "ya29.", "1//0", "iqojb3", "fqogzx", "fwogzx", "q~", "0.a", "1.a", "sk_", "rk_"),
}
_CRED_CLEAN = set()               # short texts already judged to hold nothing (names, addresses and ids repeat)
_CRED_GATE = 4096                 # a text longer than this is scanned with the carrier's hook in view, rule by rule
# The carrier's hook for long scans: called with the work done so far (1 per stretch found, 4096 between rules over a long text); it may
# raise to end the scan at the carrier's deadline. Most carriers set none and the calls do nothing.
_tick = globals().get("WITHHOLD_TICK") or (lambda units=1: None)


def _cred_json_value(text, at):
    """(start, end, after) of the JSON value whose text starts at `at`: `end` is where what is withheld ends, `after` where the next
    token of the pair begins. None when no value starts there."""
    q = _CRED_QUOTE.match(text, at)
    if q:
        start = q.end()
        close = text.find('"', start)
        if close < 0:
            return start, len(text), len(text)      # a value that is cut off: the rest of the text is the value
        return start, start + len(text[start:close].rstrip("\\")), close + 1
    m = _CRED_BARE.match(text, at)
    if m is None:
        return None
    if m.group()[0] in "nft":
        return at, at, m.end()                     # null, true and false are not secrets
    return m.start(), m.end(), m.end()


def _cred_pair_spans(text, spans):
    for head in _CRED_PAIR_HEAD.finditer(text):
        if not name_is_sensitive(head.group(1)):
            continue
        at = head.end()
        for _ in range(3):
            got = _cred_json_value(text, at)
            if got is None:
                break
            start, end, after = got
            if end > start:
                value = text[start:end]
                if not (_CRED_REDACTED.match(value) or value.lower() in _CRED_NOT_A_VALUE or value.startswith(("${", "{{")) or _CRED_PLACEHOLDER.match(value)):
                    spans.append((start, end, _CRED_PAIR_WHY))
            more = _CRED_NEXT_VALUE.match(text, after)
            if more is None:
                break
            at = more.end()


def _cred_random_like(run):
    """A run that looks like random base64 and not like a path, a name or a hash: mixed case and digits in the proportions
    random text has (a long path is mostly lower case with few capitals; a hex digest has no case to mix)."""
    n = len(run)
    upper = sum(1 for ch in run if "A" <= ch <= "Z")
    lower = sum(1 for ch in run if "a" <= ch <= "z")
    digit = sum(1 for ch in run if "0" <= ch <= "9")
    return upper * 100 >= 15 * n and lower * 100 >= 15 * n and digit * 100 >= 5 * n


def _cred_name_before(text, at):
    """The letters and digits of the name an assigned value follows (`nextToken=` gives `nexttoken`)."""
    return re.sub(r"[^a-z0-9]", "", text[max(0, at - 64):at].lower())


def _cred_spans(text, shapes, skip=()):
    spans = []
    big = len(text) > _CRED_GATE
    low = text.lower()
    sep = "=" in text or ":" in text or "%3" in low
    if "value" in low:
        _cred_pair_spans(text, spans)
    for why, rx, group in _CRED_RULES:
        if why in skip:
            continue
        need = _CRED_NEEDLES[why]
        if need is _CRED_ASSIGN and not sep:
            continue
        for n in need:
            if n in low:
                break
        else:
            continue
        if big:
            _tick(4096)
        for m in rx.finditer(text):
            if big:
                _tick(1)
            if "assigned to a credential name" in why:
                if _CRED_ARN_TAIL.search(text[max(0, m.start() - 120):m.start()]):
                    continue                              # arn:aws:secretsmanager:...:secret:NAME is a name, not a value
                if _cred_name_before(text, m.start(m.lastindex or 0)).endswith(_CRED_NOT_SECRET):
                    continue                              # nextToken=, pageToken=, clientToken=: a position or an idempotency key
            for g in _CRED_GROUPS.get(group, (group,)):
                if g and m.group(g) is None:
                    continue
                start, end = m.span(g)
                value = text[start:end]
                if g and (_CRED_REDACTED.match(value) or value.lower() in _CRED_NOT_A_VALUE or value.startswith(("${", "{{")) or _CRED_PLACEHOLDER.match(value)):
                    continue
                if why == "a scheme and its credential" and g == 1 and not (re.search(r"[0-9+/=_.~-]", value) or len(value) >= 16):
                    continue                              # "basic authentication" is prose, "Basic dXNlcjpwYXNz" is not
                if g == 1 and group == -1 and len(m.groups()) >= 2 and m.group(1) in ("'", '"'):
                    continue                              # group 1 of the switch rules is the quote
                spans.append((start, end, why))
    if big:
        _tick(4096)
    for m in (_CRED_B64_RUN.finditer(text) if len(text) >= 128 and "a long unbroken base64-like run" not in skip else ()):
        if _cred_random_like(m.group(0)):
            spans.append((m.start(), m.end(), "a long unbroken base64-like run"))
    if shapes and len(text) >= 32 and "a key-length base64 string" not in skip:
        for why, rx, check in _CRED_SHAPES:
            for m in rx.finditer(text):
                if not check or _cred_random_like(m.group(0)):
                    spans.append((m.start(), m.end(), why))
    spans.sort()
    merged = []
    for s in spans:
        if merged and s[0] < merged[-1][1]:
            if s[1] > merged[-1][1]:
                merged[-1] = (merged[-1][0], s[1], merged[-1][2])
            continue
        merged.append(s)
    return merged


def credential_spans(text, shapes=True, skip=()):
    """(start, end, why) of each stretch of `text` that is a credential by the name it is given under or by its text, in order and
    not overlapping. `shapes` False leaves out the rules that recognise a key by its length alone (a value that is named a checksum or
    a digest is not scanned for them). This is not `token_spans`: an identifier (a GUID, a hex digest, an access key id, an ARN) is
    not a credential here, and a tool that prints identifiers on purpose asks only for these."""
    if len(text) > TEXT_LIMIT:
        return [(0, len(text), "text longer than %d characters" % TEXT_LIMIT)]
    if shapes and not skip and text in _CRED_CLEAN:
        return []
    spans = _cred_spans(text, shapes, skip)
    if shapes and not skip and not spans and len(text) <= 256 and len(_CRED_CLEAN) < 100000:
        _CRED_CLEAN.add(text)
    return spans


def clean_value(value, leaf, note, key=None, pointer="", depth=0, shapes=True, max_depth=200):
    """The structure rule: `value` (what a JSON document decoded to) with every credential in it replaced. A string goes to
    `leaf(text, pointer, shapes)`, which returns what is printed for it. A field whose name says it holds a secret (or a `Value` whose
    `Name` does), at any depth, is not read at all: `note(pointer, why, original)` returns what is printed for it (a number under such
    a name is withheld too: 0 and 1 are not nothing). A key goes through `key(text)` when one is given. A value nested deeper than
    `max_depth` is replaced the same way."""
    if isinstance(value, str):
        return leaf(value, pointer, shapes)
    _tick(1)
    if depth > max_depth and isinstance(value, (dict, list)):
        return note(pointer, "nested deeper than %d levels" % max_depth, value)
    if isinstance(value, dict):
        named = None
        for k in _CRED_NAME_KEYS:
            if isinstance(value.get(k), str):
                named = value[k]
                break
        pair_secret = named is not None and name_is_sensitive(named)
        out = {}
        for k, v in value.items():
            ks = str(k)
            point = "%s/%s" % (pointer, ks.replace("~", "~0").replace("/", "~1"))
            safe_key = key(ks) if key is not None else ks
            if safe_key in out:
                safe_key = "%s#%d" % (safe_key, len(out))
            sensitive = name_is_sensitive(ks) or (pair_secret and ks in _CRED_VALUE_KEYS)
            if sensitive and is_container_name(ks) and isinstance(v, (dict, list)):
                sensitive = False
            if sensitive and not (v is None or isinstance(v, bool) or v == "") and not (isinstance(v, str) and (_CRED_REDACTED.match(v) or v.lower() in _CRED_NOT_A_VALUE)):
                out[safe_key] = note(point, "credential-named field", v)
            else:
                out[safe_key] = clean_value(v, leaf, note, key, point, depth + 1, shapes and not _CRED_CHECKSUM_NAME.search(ks), max_depth)
        return out
    if isinstance(value, list):
        return [clean_value(v, leaf, note, key, "%s/%d" % (pointer, i), depth + 1, shapes, max_depth) for i, v in enumerate(value)]
    return value


# what the rules of the block above already withhold whole, with their own markers: the first pass leaves these to them
_CRED_OLD_COVERS = frozenset(("a JSON Web Token", "a password in a URL", "an authorization header value", "a scheme and its credential",
                              "a long unbroken base64-like run", "a key-length base64 string"))


def _credentials_withheld(text, kind, skip=()):
    """`text` with each credential in it withheld. It runs after the rules above, on text that may hold their markers: a stretch that
    begins at a marker is theirs already."""
    out, last = [], 0
    for start, end, why in credential_spans(text, True, skip):
        if text.startswith("<", start):
            continue
        out.append(text[last:start])
        out.append(_withheld(why, end - start, kind))
        last = end
    if not out:
        return text
    out.append(text[last:])
    return "".join(out)


def scrub(text, kind="text"):
    """The text with every token-shaped run, every user-info and every credential withheld."""
    if len(text) > TEXT_LIMIT:
        return _withheld("over-long text", len(text), kind)
    text = _credentials_withheld(text, kind, _CRED_OLD_COVERS)     # first: the rules above cut a secret into pieces that no rule for a whole one can match
    text = _USERINFO.sub(lambda m: _withheld("userinfo", len(m.group()), kind), text)
    text = _BARE_USERINFO.sub(lambda m: _withheld("userinfo", len(m.group()), kind), text)
    out, last = [], 0
    for start, end in token_spans(text):
        out.append(text[last:start])
        out.append(_withheld("token-shaped text", end - start, kind))
        last = end
    out.append(text[last:])
    return _credentials_withheld("".join(out), kind)


def redact_url(url):
    """A URL or request target without its user-info, its token-shaped path text, its query values or its fragment."""
    rest, fragment = (url.split("#", 1) + [None])[:2]
    rest, query = (rest.split("?", 1) + [None])[:2]
    scheme = authority = ""
    m = re.match(r"^((?:[A-Za-z][A-Za-z0-9+.-]*:)?//)([^/]*)(.*)$", rest, re.S)
    if m:
        scheme, authority, rest = m.group(1), m.group(2), m.group(3)
        if "@" in authority:
            userinfo, authority = authority.rsplit("@", 1)
            authority = _withheld("userinfo", len(userinfo), "urls") + "@" + authority
    out = scheme + authority + scrub(rest, "urls")
    if query is not None:
        pairs = []
        for pair in query.split("&"):
            name, eq, value = pair.partition("=")
            pairs.append(scrub(name, "urls") + (eq + _withheld("", len(value), "urls") if eq else ""))
        out += "?" + "&".join(pairs)
    if fragment is not None:
        out += "#" + _withheld("", len(fragment), "urls")
    return out


def cell(value):
    """Text for one tab-separated cell or one printed path: no tab or line break, and a byte that was not UTF-8
    (a lone surrogate) written as \\xNN, so that no writer raises on it."""
    text = value if isinstance(value, str) else str(value)
    out = []
    for ch in text:
        o = ord(ch)
        if ch == "\\":
            out.append("\\\\")
        elif ch == "\t":
            out.append("\\t")
        elif ch == "\r":
            out.append("\\r")
        elif ch == "\n":
            out.append("\\n")
        elif 0xDC80 <= o <= 0xDCFF:
            out.append("\\x%02x" % (o - 0xDC00))
        elif 0xD800 <= o <= 0xDFFF:
            out.append("\\u%04x" % o)
        elif o < 0x20 or o == 0x7F:
            out.append("\\x%02x" % o)
        else:
            out.append(ch)
    return "".join(out)
# END SHARED WITHHOLDING


TOOL = "cloud_normalise"
# The label moves when what a row says changes (docs/packs.md, 'A tool's version and its PARSER label').
# 1: the core and the adapters gcp_audit, kubernetes_audit and entra_directory_audit.
# 2: the adapters azure_activity_log, aws_s3_access_log and aws_vpc_flow, and the text reader behind the last two.
# 3: the adapter workspace_activities, and the change topics of the Entra directory audit rows.
PARSER = "cloud_normalise/3"
VALUES_NAME = "cloud-normalise-values.jsonl"
ENVELOPE_KEYS = ("entries", "items", "value", "records", "Records")
ARGS = frozenset(("path", "paths", "provider", "format", "delimiter", "out_dir", "principal", "limit", "time_limit_seconds", "max_expanded_bytes",
                  "max_record_bytes", "write_values", "vpc_flow_fields"))
PROVIDERS = ("gcp", "kubernetes", "entra", "azure", "workspace", "aws_s3", "aws_vpc")
MAX_IDS = 500000                  # distinct record keys held to annotate duplicates; past it duplicates are no longer annotated, and the coverage says so
OUT_NAMES = {"rows": "normalised.jsonl", "rejected": "rejected.jsonl", "coverage": "coverage.json"}
ENTRA_SECRET_NAME = re.compile(r"(?i)password|passwd|passphrase|secret|credential|token")   # a modified property named so has both its values withheld, whatever they look like
READ_NAMES = (".json", ".jsonl", ".ndjson", ".csv", ".log", ".txt", ".gz")

import hashlib
import urllib.parse


class Unsupported(Exception):
    """A record that parsed as JSON and that no adapter of the requested provider reads: it is rejected with this reason, never dropped."""


def is_dict(v):
    return isinstance(v, dict)


def text_of(v):
    """A scalar slot as the text it is printed as; an object or a list is never turned into text here."""
    if isinstance(v, str):
        return v
    if isinstance(v, bool) or v is None:
        return None
    if isinstance(v, (int, float)):
        return str(v)
    return None


def ident(v):
    """An identifier slot (a record id, an audit id, a correlation id, a project or tenant id): printed as it is and judged by nothing."""
    return text_of(v)


def free(v):
    """A free-text slot (a principal, an action, a resource name, an address, a message): printed through the credential rules only."""
    t = text_of(v)
    return scrub_text(t) if t is not None else None


def pick(d, *names):
    if not isinstance(d, dict):
        return None
    for n in names:
        if d.get(n) not in (None, ""):
            return d[n]
    return None


def maybe_json(value):
    """A CSV cell that holds a JSON object or list is that structure; anything else is the cell."""
    if isinstance(value, str) and value[:1] in ("{", "[") and len(value) <= MAX_RECORD_BYTES:
        try:
            return loads_strict(value)
        except (ValueError, RecursionError):
            return value
    return value


def stamp(raw):
    return parse_stamp(raw, None, False)


# ---- the adapters --------------------------------------------------------------------------------------------------------------------------
# Each adapter has `recognise(item)` (a cheap test of the record's own fields) and `adapt(item, ctx)`, which returns the canonical rows of one
# record (Kubernetes: one record is one stage, and so one row). `ctx.protect(item, pointer, ...)` is how a value that must not be printed is
# replaced before the record is cleaned; a record is never changed in place.

GCP_LOG_TYPES = {"activity": "admin_activity", "data_access": "data_access", "system_event": "system_event", "policy": "policy_denied"}


def gcp_recognise(item):
    pp = item.get("protoPayload")
    if not is_dict(pp):
        return False
    kind = pp.get("@type")
    return (isinstance(kind, str) and kind.endswith("google.cloud.audit.AuditLog")) or "cloudaudit.googleapis.com" in str(item.get("logName") or "") or (
        "methodName" in pp and "serviceName" in pp)


def gcp_tenant(item):
    labels = pick(item.get("resource"), "labels") if is_dict(item.get("resource")) else None
    if is_dict(labels) and labels.get("project_id") not in (None, ""):
        return "project", ident(labels["project_id"])
    name = item.get("logName")
    if isinstance(name, str):
        m = re.match(r"^(projects|organizations|folders|billingAccounts)/([^/]+)/logs/", name)
        if m:
            return {"projects": "project", "organizations": "organization", "folders": "folder", "billingAccounts": "billing account"}[m.group(1)], m.group(2)
    return "project", None


def gcp_adapt(item, ctx):
    pp = item["protoPayload"]
    auth = pp.get("authenticationInfo") if is_dict(pp.get("authenticationInfo")) else {}
    meta = pp.get("requestMetadata") if is_dict(pp.get("requestMetadata")) else {}
    status = pp.get("status") if is_dict(pp.get("status")) else None
    principal = pick(auth, "principalEmail", "principalSubject")
    code = status.get("code") if status is not None else None
    sev = item.get("severity")
    if status is None:
        outcome, basis = "unknown", "the record has no status%s" % ((" (the entry's severity is %s)" % free(sev)) if isinstance(sev, str) else "")
    elif code in (None, 0) and isinstance(code, (int, type(None))) and not isinstance(code, bool):
        outcome, basis = "success", "status.code is %s" % ("0" if code == 0 else "absent, which is 0 in the proto's JSON form")
    elif isinstance(code, int) and not isinstance(code, bool):
        outcome, basis = "failure", "status.code is %d" % code
    else:
        outcome, basis = "unknown", "status.code is not an integer"
    log_name = item.get("logName") if isinstance(item.get("logName"), str) else ""
    m = re.search(r"/logs/cloudaudit\.googleapis\.com(?:%2[Ff]|/)([A-Za-z_]+)$", log_name)
    log_type = GCP_LOG_TYPES.get(m.group(1), m.group(1)) if m else None
    kind, tenant = gcp_tenant(item)
    res = item.get("resource") if is_dict(item.get("resource")) else {}
    delegation = auth.get("serviceAccountDelegationInfo")
    if not isinstance(delegation, list):
        delegation = pp.get("serviceAccountDelegationInfo")      # where the card put it; the proto holds it in authenticationInfo
    row = {
        "provider": "gcp", "adapter": "gcp_audit", "tenant_kind": kind, "tenant": tenant,
        "principal": free(principal), "principal_kind": "principalEmail" if auth.get("principalEmail") else ("principalSubject" if auth.get("principalSubject") else None),
        "action": free(pp.get("methodName")), "service": free(pp.get("serviceName")), "resource": free(pp.get("resourceName")),
        "outcome": outcome, "outcome_basis": basis, "outcome_detail": {"status": status} if status else None,
        "time_raw": item.get("timestamp"), "receive_time_raw": item.get("receiveTimestamp"),
        "event_id": ident(item.get("insertId")), "log_type": log_type, "log_name": free(log_name) if log_name else None,
        "resource_type": free(res.get("type")), "resource_labels": res.get("labels") if is_dict(res.get("labels")) else None,
        "source_ip": ident(meta.get("callerIp")), "user_agent": free(meta.get("callerSuppliedUserAgent")),
        "delegation_chain": delegation if isinstance(delegation, list) else None,
        "authentication": {k: v for k, v in auth.items() if k not in ("principalEmail", "principalSubject", "serviceAccountDelegationInfo")} or None,
        "authorization": pp.get("authorizationInfo") if isinstance(pp.get("authorizationInfo"), list) else None,
        "operation": item.get("operation") if is_dict(item.get("operation")) else None,
        "severity": item.get("severity") if isinstance(item.get("severity"), str) else None,
    }
    ctx.second_time(row, "receive_time_raw", "receive_time_utc")
    return [row], item


K8S_STAGES = ("RequestReceived", "ResponseStarted", "ResponseComplete", "Panic")


def k8s_recognise(item):
    api = item.get("apiVersion")
    if isinstance(api, str) and api.startswith("audit.k8s.io/") and item.get("kind") in (None, "Event"):
        return True
    return item.get("auditID") not in (None, "") and "stage" in item and ("verb" in item or "requestURI" in item)


def k8s_is_secret(item, body):
    ref = item.get("objectRef") if is_dict(item.get("objectRef")) else {}
    if ref.get("resource") == "secrets" and ref.get("apiGroup") in (None, ""):
        return True
    if is_dict(body):
        kind = body.get("kind")
        if kind in ("Secret", "SecretList"):
            return True
        if is_dict(body.get("metadata")) and body.get("data") is not None and kind in (None, ""):
            return True
    return False


def k8s_adapt(item, ctx):
    ref = item.get("objectRef") if is_dict(item.get("objectRef")) else {}
    user = item.get("user") if is_dict(item.get("user")) else {}
    imp = item.get("impersonatedUser") if is_dict(item.get("impersonatedUser")) else None
    status = item.get("responseStatus") if is_dict(item.get("responseStatus")) else None
    ann = item.get("annotations") if is_dict(item.get("annotations")) else {}
    decision = ann.get("authorization.k8s.io/decision")
    code = status.get("code") if status is not None else None
    if isinstance(code, int) and not isinstance(code, bool):
        outcome, basis = ("failure" if code >= 400 else "success"), "responseStatus.code is %d" % code
    elif decision == "forbid":
        outcome, basis = "failure", "the authorization decision annotation says forbid"
    else:
        outcome, basis = "unknown", "no responseStatus.code in this stage's record (stage %s)" % free(item.get("stage"))
    parts = [p for p in (ref.get("namespace"), ref.get("resource"), ref.get("subresource"), ref.get("name")) if isinstance(p, str) and p]
    resource = "/".join(parts) if parts else None
    uri = item.get("requestURI")
    ips = item.get("sourceIPs")
    stage = item.get("stage")
    # a request or response body can hold a Secret object: it is replaced whole before the record is cleaned, and its original goes to the values
    # file only when the caller asked for it
    protected = dict(item)
    for key in ("requestObject", "responseObject"):
        body = item.get(key)
        if body is not None and k8s_is_secret(item, body):
            protected[key] = ctx.withhold_field("/" + key, "a Kubernetes Secret body", body)
    row = {
        "provider": "kubernetes", "adapter": "kubernetes_audit", "tenant_kind": "cluster (the audit event does not name one)", "tenant": None,
        "principal": free(user.get("username")), "principal_kind": "user.username", "principal_id": ident(user.get("uid")),
        "groups": user.get("groups") if isinstance(user.get("groups"), list) else None,
        "user_extra": user.get("extra") if is_dict(user.get("extra")) else None,
        "impersonated_principal": free(imp.get("username")) if imp else None,
        "impersonated_user": imp,
        "action": free(item.get("verb")), "resource": free(resource) if resource else (free(uri) if isinstance(uri, str) else None),
        "request_uri": free(uri) if isinstance(uri, str) else None, "object_ref": ref or None,
        "outcome": outcome, "outcome_basis": basis, "outcome_detail": {"responseStatus": status, "decision": decision} if (status or decision) else None,
        "time_raw": item.get("stageTimestamp"), "request_received_raw": item.get("requestReceivedTimestamp"),
        "event_id": ident(item.get("auditID")), "stage": stage if isinstance(stage, str) else None,
        "stage_known": stage in K8S_STAGES, "level": item.get("level") if isinstance(item.get("level"), str) else None,
        "source_ip": [ident(i) for i in ips] if isinstance(ips, list) else None, "user_agent": free(item.get("userAgent")),
        "annotations": ann or None,
    }
    ctx.second_time(row, "request_received_raw", "request_received_utc")
    return [row], protected


def entra_recognise(item):
    keys = key_map(item)
    return "activitydisplayname" in keys and "activitydatetime" in keys


def entra_adapt(item, ctx):
    keys = key_map(item)

    def got(name):
        k = keys.get(name.lower())
        return maybe_json(item.get(k)) if k is not None else None

    by = got("initiatedBy")
    user = by.get("user") if is_dict(by) and is_dict(by.get("user")) else None
    app = by.get("app") if is_dict(by) and is_dict(by.get("app")) else None
    if user:
        principal = pick(user, "userPrincipalName", "displayName", "id")
        kind, pid = "user", user.get("id")
        ip = user.get("ipAddress")
    elif app:
        principal = pick(app, "displayName", "servicePrincipalName", "appId", "servicePrincipalId")
        kind, pid = "application", pick(app, "servicePrincipalId", "appId")
        ip = app.get("ipAddress") if isinstance(app.get("ipAddress"), str) else None
    else:
        principal, kind, pid, ip = None, None, None, None
    targets_raw = got("targetResources")
    protected = dict(item)
    targets, props = [], []
    if isinstance(targets_raw, list):
        new_targets = []
        for ti, t in enumerate(targets_raw):
            if not is_dict(t):
                new_targets.append(t)
                continue
            t2 = dict(t)
            mps = t.get("modifiedProperties")
            if isinstance(mps, list):
                new_mps = []
                for mi, mp in enumerate(mps):
                    if not is_dict(mp):
                        new_mps.append(mp)
                        continue
                    mp2 = dict(mp)
                    name = mp.get("displayName")
                    for vk in ("oldValue", "newValue"):
                        if vk in mp and mp[vk] not in (None, "") and isinstance(name, str) and (name_is_sensitive(name) or ENTRA_SECRET_NAME.search(name)):
                            mp2[vk] = ctx.withhold_field("/targetResources/%d/modifiedProperties/%d/%s" % (ti, mi, vk), "a modified property named like a secret", mp[vk])
                    new_mps.append(mp2)
                    props.append({"target_index": ti, "name": free(name), "old_value": mp2.get("oldValue"), "new_value": mp2.get("newValue")})
                t2["modifiedProperties"] = new_mps
            new_targets.append(t2)
            targets.append({"index": ti, "id": ident(t.get("id")), "type": free(t.get("type")), "display_name": free(t.get("displayName")),
                            "user_principal_name": free(t.get("userPrincipalName")), "group_type": free(t.get("groupType")),
                            "modified_properties_count": len(mps) if isinstance(mps, list) else 0})
        key = keys.get("targetresources")
        if key is not None:
            protected[key] = new_targets
    elif keys.get("targetresources") is not None:
        protected[keys["targetresources"]] = targets_raw
    result = got("result")
    reason = got("resultReason")
    word = result.lower() if isinstance(result, str) else None
    if word == "success":
        outcome, basis = "success", "result is success"
    elif word in ("failure", "timeout"):
        outcome, basis = "failure", "result is %s" % word
    else:
        outcome, basis = "unknown", "result is %s" % ("absent" if result in (None, "") else "not success, failure or timeout")
    first = targets[0] if targets else None
    resource = None
    if first:
        resource = first["user_principal_name"] or first["display_name"] or first["id"]
    row = {
        "provider": "entra", "adapter": "entra_directory_audit", "tenant_kind": "tenant (the record does not name one)", "tenant": None,
        "principal": free(principal), "principal_kind": kind, "principal_id": ident(pid), "source_ip": ident(ip),
        "action": free(got("activityDisplayName")), "category": free(got("category")), "operation_type": free(got("operationType")),
        "logged_by_service": free(got("loggedByService")), "resource": resource,
        "targets": targets or None, "modified_properties": props or None, "values_of_modified_properties_are_sensitive": True if props else None,
        "outcome": outcome, "outcome_basis": basis, "outcome_detail": {"result": result, "result_reason": free(reason) if isinstance(reason, str) else reason},
        "time_raw": got("activityDateTime"), "event_id": ident(got("id")), "correlation_id": ident(got("correlationId")),
        "additional_details": got("additionalDetails"),
    }
    hints = topic_hints(row["action"], row["category"], row["operation_type"])
    row["change_topics"] = hints or None
    row["change_topics_basis"] = "words in the activity, category and operation names, from this tool's own list; a hint for where to look, not a classification Microsoft documents" if hints else None
    return [row], protected


# ---- Azure Activity log ------------------------------------------------------------------------------------------------------------------
# The field names are the work card's (eventTimestamp, submissionTimestamp, operationName, status, subStatus, caller, claims,
# authorization{action,scope}, resourceId, correlationId, level, category, properties, httpRequest, eventDataId). The Azure documentation
# was not read for this version, so the layout of the objects (a name with a value and a localizedValue) and the words a status can take
# are NOT checked against a vendor page; the row says what it read and the manifest says so.

AZURE_DONE = {"succeeded": "success", "success": "success"}
AZURE_FAILED = {"failed": "failure", "failure": "failure"}
_AZURE_SUB = re.compile(r"(?i)^/subscriptions/([^/]+)")


def az_recognise(item):
    keys = key_map(item)
    return "eventtimestamp" in keys and "operationname" in keys


def az_value(v):
    """A field the REST form writes as {value, localizedValue} and an export may write as plain text."""
    if isinstance(v, dict):
        return text_of(v.get("value"))
    return text_of(v)


def az_adapt(item, ctx):
    keys = key_map(item)

    def got(name):
        k = keys.get(name.lower())
        return maybe_json(item.get(k)) if k is not None else None

    op, status, sub, cat = got("operationName"), got("status"), got("subStatus"), got("category")
    auth, claims, props, http = got("authorization"), got("claims"), got("properties"), got("httpRequest")
    rid = got("resourceId")
    state = az_value(status)
    word = state.strip().lower() if state else None
    if word in AZURE_DONE:
        outcome, basis = AZURE_DONE[word], "status is %s" % free(state)
    elif word in AZURE_FAILED:
        outcome, basis = AZURE_FAILED[word], "status is %s" % free(state)
    elif word is None:
        outcome, basis = "unknown", "the record has no status"
    else:
        outcome, basis = "unknown", "status is %s: a start or an intermediate state is not an outcome; the operation's completion is another record of the same correlation id" % free(state)
    m = _AZURE_SUB.match(rid) if isinstance(rid, str) else None
    scope = auth.get("scope") if is_dict(auth) else None
    row = {
        "provider": "azure", "adapter": "azure_activity_log",
        "tenant_kind": "subscription (read from the resource id)" if m else "subscription (the record does not name one)", "tenant": ident(m.group(1)) if m else None,
        "principal": free(got("caller")), "principal_kind": "caller",
        "action": free(az_value(op)), "operation_localized": free(op.get("localizedValue")) if is_dict(op) else None,
        "resource": ident(rid) if isinstance(rid, str) else None,
        "outcome": outcome, "outcome_basis": basis, "lifecycle": free(state),
        "status": status if is_dict(status) else None, "sub_status": sub if is_dict(sub) else free(az_value(sub)),
        "time_raw": got("eventTimestamp"), "submission_time_raw": got("submissionTimestamp"),
        "event_id": ident(got("eventDataId")), "correlation_id": ident(got("correlationId")),
        "category": free(az_value(cat)), "level": free(got("level")),
        "authorization_action": free(auth.get("action")) if is_dict(auth) else None, "authorization_scope": ident(scope),
        "authorization_detail": auth if is_dict(auth) else None,      # not named `authorization`: the name layer withholds a field of that name whole
        "claims": claims if is_dict(claims) else (free(claims) if isinstance(claims, str) else None),
        "claims_are_sensitive": True if claims else None,
        "properties": props if props not in (None, "") else None,
        "http_request": http if is_dict(http) else None,
        "source_ip": ident(http.get("clientIpAddress")) if is_dict(http) else None,
        "_dedupe_part": state,
    }
    ctx.second_time(row, "submission_time_raw", "submission_time_utc")
    # the whole record, with the one key the name layer would withhold whole (authorization: it is an object of an action and a scope) renamed
    protected = {("authorization_object" if isinstance(k, str) and k.strip().lower() == "authorization" else k): v for k, v in item.items()}
    return [row], protected


# ---- text formats: the S3 server access log and the VPC Flow Log ----------------------------------------------------------------------------
# Both are read from the delivered text file line by line (the lines are the records); a line is never guessed at: it is a row or a located
# reject. Field lists: the AWS pages named in tests/fixtures/cloud-normalise/SOURCES.json, read on 2026-11-04.

S3_FIELDS = ("bucket_owner", "bucket", "time", "remote_ip", "requester", "request_id", "operation", "key", "request_uri", "http_status", "error_code",
             "bytes_sent", "object_size", "total_time_ms", "turn_around_time_ms", "referer", "user_agent", "version_id", "host_id", "signature_version",
             "cipher_suite", "authentication_type", "host_header", "tls_version", "access_point_arn", "acl_required", "source_region")
S3_QUOTED = {8: "request_uri", 15: "referer", 16: "user_agent"}
S3_MIN_FIELDS = 10                # through the HTTP status; an older or shorter record has the fields it has, the rest are absent
MAX_TRAILING_SHOWN = 20
_S3_URI_END = re.compile(r'" (?:[0-9]{3}|-)(?: |$)')
_S3_TIME = re.compile(r"^\[([0-9]{1,2})/([A-Za-z]{3,9})/([0-9]{4}):([0-9]{2}):([0-9]{2}):([0-9]{2}) ([+-][0-9]{4})\]$")
_S3_HEAD = re.compile(r"^[^ ]* [^ ]* \[[0-9]{1,2}/[A-Za-z]{3,9}/[0-9]{4}:[0-9]{2}:[0-9]{2}:[0-9]{2} [+-][0-9]{4}\] ")
MONTHS = ("january", "february", "march", "april", "may", "june", "july", "august", "september", "october", "november", "december")

VPC_VERSIONS = {}
for _ver, _names in (
        (2, "version account-id interface-id srcaddr dstaddr srcport dstport protocol packets bytes start end action log-status"),
        (3, "vpc-id subnet-id instance-id tcp-flags type pkt-srcaddr pkt-dstaddr"),
        (4, "region az-id sublocation-type sublocation-id"),
        (5, "pkt-src-aws-service pkt-dst-aws-service flow-direction traffic-path"),
        (7, "ecs-cluster-arn ecs-cluster-name ecs-container-instance-arn ecs-container-instance-id ecs-container-id ecs-second-container-id "
            "ecs-service-name ecs-task-definition-arn ecs-task-arn ecs-task-id"),
        (8, "reject-reason"), (9, "resource-id"), (10, "encryption-status"),
        (11, "instance-tag instance-tag-2 interface-tag interface-tag-2 asg-tag asg-tag-2 interface-type next-hop-interface-id next-hop-subnet-id "
            "next-hop-az-id next-hop-vpc-id next-hop-interface-type")):
    for _n in _names.split():
        VPC_VERSIONS[_n] = _ver
VPC_DEFAULT = tuple(n for n in VPC_VERSIONS if VPC_VERSIONS[n] == 2)
VPC_NUMBERS = frozenset(("version", "srcport", "dstport", "protocol", "packets", "bytes", "start", "end", "tcp-flags", "traffic-path", "encryption-status"))
VPC_FREE = frozenset(("instance-tag", "instance-tag-2", "interface-tag", "interface-tag-2", "asg-tag", "asg-tag-2", "ecs-cluster-name", "ecs-service-name"))
VPC_STATUSES = ("OK", "NODATA", "SKIPDATA")
_VPC_NAME = re.compile(r"^[a-z][a-z0-9-]*$")
MAX_VPC_FIELDS = 200


def num(text):
    """A documented number as an integer; anything else is left as the text it was written as (and counted by the caller)."""
    if isinstance(text, str) and re.fullmatch(r"[0-9]{1,18}", text):
        return int(text)
    return text


def epoch_stamp(raw):
    """Unix seconds (the unit the VPC page documents for start and end) as the same dict parse_stamp gives."""
    if raw in (None, ""):
        return {"utc": None, "ns": None, "status": "missing", "basis": "no time in the record"}
    if not isinstance(raw, str) or not re.fullmatch(r"[0-9]{1,12}", raw) or int(raw) >= 253402300800:
        return {"utc": None, "ns": None, "status": "unparseable", "basis": "not Unix seconds (a whole number of at most 12 digits, before the year 10000)"}
    ns = int(raw) * 1000000000
    return {"utc": ns_to_utc(ns), "ns": ns, "status": "zoned", "basis": "Unix seconds, which count from the UTC epoch (the VPC documentation gives the unit)"}


def s3_stamp(raw):
    m = _S3_TIME.match(raw) if isinstance(raw, str) else None
    if not m:
        return {"utc": None, "ns": None, "status": "unparseable", "basis": "not the [day/month/year:hour:minute:second zone] form the S3 page documents"}
    word = m.group(2).lower()
    month = [i for i, name in enumerate(MONTHS) if name == word or name[:3] == word]
    if not month:
        return {"utc": None, "ns": None, "status": "unparseable", "basis": "an unknown month name"}
    iso = "%s-%02d-%02dT%s:%s:%s%s" % (m.group(3), month[0] + 1, int(m.group(1)), m.group(4), m.group(5), m.group(6), m.group(7))
    st = parse_stamp(iso, None, False)
    if st["status"] == "zoned":
        st["basis"] = "the bracketed time carries its offset %s (the S3 page says these times are UTC)" % m.group(7)
    return st


def s3_tokens(line):
    """The fields of one S3 server access log record and how many quoted fields held a quote of their own. The request URI, the referer and
    the user agent are quoted and may hold unescaped quotes (the page says so): the URI ends at the first quote that is followed by a
    space and the status, the referer at the first quote-space-quote, the user agent at the last quote of the line. A record built to
    imitate those closings can move a field; the field count and the time field are the checks, and they are reported."""
    out, inner, i, n = [], 0, 0, len(line)
    while True:
        idx = len(out)
        if idx == 2 and line.startswith("[", i):
            end = line.find("]", i + 1)          # the bracketed time holds a space of its own
            if end < 0:
                raise ValueError("the bracketed time is not closed")
            out.append((line[i:end + 1], False))
            i = end + 1
            if i < n and line[i] != " ":
                raise ValueError("the bracketed time is followed by text, not by a space")
        elif line.startswith('"', i) and idx in S3_QUOTED:
            if idx == 8:
                m = _S3_URI_END.search(line, i + 1)
                end = m.start() if m else -1
            elif idx == 15:
                end = line.find('" "', i + 1)
            else:
                end = line.rfind('"')
            if end <= i:
                raise ValueError("a quoted field is not closed")
            body = line[i + 1:end]
            inner += 1 if '"' in body else 0
            out.append((body, True))
            i = end + 1
            if i < n and line[i] != " ":
                raise ValueError("a quoted field is followed by text, not by a space")
        else:
            j = line.find(" ", i)
            j = n if j < 0 else j
            out.append((line[i:j], False))
            i = j
        if i >= n:
            break
        i += 1
        if i == n:
            out.append(("", False))
            break
        check_deadline(1 + n // 262144)
    return out, inner


def s3_rows(src, record_cap):
    """Yield ("row", info, item) / ("reject", info, reason) for an S3 server access log; item holds the fields by name."""
    src.mode, src.stopped, src.extra_keys, src.envelope, src.header = "text", None, [], None, None
    lines = csv_lines(src, record_cap)
    count = 0
    while True:
        line_no = src.line
        try:
            raw = next(lines)
        except StopIteration:
            break
        except TooLong:
            src.stopped = "a line longer than %d characters at line %d: the rest of the file was not read" % (record_cap, line_no)
            yield "reject", {"record": count + 1, "line": line_no, "offset": src.offset(), "chars": None, "envelope": None}, src.stopped
            return
        text = raw[:-1] if raw.endswith("\n") else raw
        text = text[:-1] if text.endswith("\r") else text
        if not text.strip():
            continue
        count += 1
        info = {"record": count, "line": line_no, "offset": None, "chars": None, "envelope": None}
        try:
            toks, inner = s3_tokens(text)
        except ValueError as exc:
            yield "reject", info, "not an S3 server access log record: %s" % exc
            continue
        if len(toks) < S3_MIN_FIELDS or not _S3_TIME.match(toks[2][0]):
            yield "reject", info, "not an S3 server access log record: %d field(s), and the third is %s a bracketed time" % (len(toks), "not" if len(toks) >= 3 else "missing, so not")
            continue
        loose = [S3_QUOTED[i] for i in S3_QUOTED if i < len(toks) and not toks[i][1]]
        if loose:
            yield "reject", info, "not an S3 server access log record: the field %s is not quoted where the format quotes it (a quote of the record's own may have closed an earlier field)" % loose[0]
            continue
        names = S3_FIELDS[:len(toks)]
        yield "row", info, {"fields": {name: tok for name, (tok, _q) in zip(names, toks)}, "trailing": [t for t, _q in toks[len(S3_FIELDS):]],
                            "present": len(toks), "inner_quotes": inner, "line": text}
        if src.timed_out:
            return
    if src.timed_out and not src.stopped:
        src.stopped = "the time limit ended the read"


def s3_adapt(item, ctx):
    f = item["fields"]

    def dash(name):
        v = f.get(name)
        return None if v in (None, "", "-") else v

    ctx.count("fields_missing_from_a_short_record", len(S3_FIELDS) - item["present"] if item["present"] < len(S3_FIELDS) else 0)
    ctx.count("unknown_trailing_fields", len(item["trailing"]))
    ctx.count("quoted_fields_with_inner_quotes", item["inner_quotes"])
    status = dash("http_status")
    code = num(status) if status is not None else None
    if isinstance(code, int) and 200 <= code < 300:
        outcome, basis = "success", "the HTTP status is %d" % code
    elif isinstance(code, int) and code >= 400:
        outcome, basis = "failure", "the HTTP status is %d" % code
    elif isinstance(code, int):
        outcome, basis = "unknown", "the HTTP status is %d: neither a success nor a failure answer" % code
    else:
        outcome, basis = "unknown", "the record has no usable HTTP status"
    key, bucket, requester = dash("key"), dash("bucket"), dash("requester")
    resource = None
    if bucket is not None:
        resource = free(bucket + ("/" + key.lstrip("/") if key is not None else ""))
    sent = dash("bytes_sent")
    st = s3_stamp(f.get("time"))
    row = {
        "provider": "aws", "adapter": "aws_s3_access_log", "tenant_kind": "bucket owner (canonical user id)", "tenant": ident(dash("bucket_owner")),
        "principal": free(requester), "principal_kind": "requester" if requester is not None else None,
        "action": free(dash("operation")), "service": "s3", "resource": resource, "bucket": ident(bucket), "key": free(key),
        "request_uri": free(dash("request_uri")), "http_status": code, "error_code": free(dash("error_code")),
        "bytes_sent": num(sent) if sent is not None else None, "bytes_sent_note": "the record has - here: the page says - also means zero bytes sent for this field, and any field can be - when the data is unknown" if f.get("bytes_sent") == "-" else None,
        "object_size": num(dash("object_size")) if dash("object_size") is not None else None,
        "total_time_ms": num(dash("total_time_ms")) if dash("total_time_ms") is not None else None,
        "turn_around_time_ms": num(dash("turn_around_time_ms")) if dash("turn_around_time_ms") is not None else None,
        "referer": free(dash("referer")), "user_agent": free(dash("user_agent")), "version_id": free(dash("version_id")), "host_id": ident(dash("host_id")),
        "signature_version": free(dash("signature_version")), "cipher_suite": free(dash("cipher_suite")), "authentication_type": free(dash("authentication_type")),
        "host_header": free(dash("host_header")), "tls_version": free(dash("tls_version")), "access_point_arn": ident(dash("access_point_arn")),
        "acl_required": free(dash("acl_required")), "source_region": free(dash("source_region")),
        "source_ip": ident(dash("remote_ip")), "event_id": ident(dash("request_id")),
        "outcome": outcome, "outcome_basis": basis,
        "time_raw": f.get("time")[1:-1] if isinstance(f.get("time"), str) else None, "_stamp": st,
        "fields_present": item["present"], "fields_documented": len(S3_FIELDS),
        "unknown_trailing_field_count": len(item["trailing"]) or None,
        "unknown_trailing_fields": [free(t) for t in item["trailing"][:MAX_TRAILING_SHOWN]] or None,
        "unknown_trailing_fields_note": ("the first %d of %d are shown; the whole record is in raw_record" % (MAX_TRAILING_SHOWN, len(item["trailing"]))) if len(item["trailing"]) > MAX_TRAILING_SHOWN else None,
        "_dedupe_part": dash("operation"),
    }
    return [row], {"line": item["line"]}


def is_vpc_header(toks):
    return len(toks) >= 2 and len(toks) <= MAX_VPC_FIELDS and all(_VPC_NAME.match(t) for t in toks) and sum(1 for t in toks if t in VPC_VERSIONS) * 2 >= len(toks) \
        and len(set(toks)) == len(toks)


def vpc_rows(src, record_cap, given):
    """Yield ("row", info, item) / ("reject", info, reason) for a VPC Flow Log file. The field names are those of the header line the file
    carries (a delivered file starts with one; a later header line, as in files put end to end, replaces it); without one, a 14-field
    record that begins with the version 2 is read in the default order, and anything else is rejected unless the caller named the
    fields (vpc_flow_fields)."""
    src.mode, src.stopped, src.extra_keys, src.envelope, src.header = "text", None, [], None, None
    src.header_lines = 0
    fields, origin = (list(given), "the vpc_flow_fields argument") if given else (None, None)
    lines = csv_lines(src, record_cap)
    count = 0
    while True:
        line_no = src.line
        try:
            raw = next(lines)
        except StopIteration:
            break
        except TooLong:
            src.stopped = "a line longer than %d characters at line %d: the rest of the file was not read" % (record_cap, line_no)
            yield "reject", {"record": count + 1, "line": line_no, "offset": src.offset(), "chars": None, "envelope": None}, src.stopped
            return
        text = raw[:-1] if raw.endswith("\n") else raw
        text = text[:-1] if text.endswith("\r") else text
        if not text.strip():
            continue
        toks = text.split(" ")
        if is_vpc_header(toks):
            fields, origin = toks, "the header line of the file (line %d)" % line_no
            src.header_lines += 1
            continue
        count += 1
        info = {"record": count, "line": line_no, "offset": None, "chars": None, "envelope": None}
        if "" in toks:
            yield "reject", info, "a flow log record with an empty field (two spaces in a row, or a space at either end)"
            continue
        use, why = fields, origin
        if use is None:
            if len(toks) == len(VPC_DEFAULT) and toks[0] == "2":
                use, why = list(VPC_DEFAULT), "the default version 2 order (the file has no header line before this record)"
            else:
                yield "reject", info, "a flow log record with %d fields and no header line: the field order is not known (pass vpc_flow_fields, the format's field names in order)" % len(toks)
                continue
        if len(toks) != len(use):
            yield "reject", info, "the record has %d fields and the field list (%s) has %d" % (len(toks), why, len(use))
            continue
        yield "row", info, {"names": use, "values": toks, "origin": why, "line": text}
        if src.timed_out:
            return
    if src.timed_out and not src.stopped:
        src.stopped = "the time limit ended the read"


def vpc_adapt(item, ctx):
    names, values = item["names"], item["values"]
    f = {}
    for n, v in zip(names, values):
        f[n] = None if v == "-" else v
    status = f.get("log-status")
    declared = num(f["version"]) if f.get("version") is not None else None
    known = [VPC_VERSIONS[n] for n in names if n in VPC_VERSIONS]
    highest = max(known) if known else None
    unknown = [n for n in names if n not in VPC_VERSIONS]
    ctx.count("fields_not_in_the_documented_list", len(unknown))
    if status is None and "log-status" in names:
        kind, why = "unknown_status", "log-status is - in this record"
    elif status in ("NODATA", "SKIPDATA"):
        kind = "no_flow_record"
        why = ("log-status is NODATA: the interface had no traffic during the aggregation interval (the documentation); this is a record of no traffic, not a flow of zero packets"
               if status == "NODATA" else
               "log-status is SKIPDATA: some flow log records were skipped in the interval (the documentation); this is not a flow, and it does not say how much traffic there was")
        ctx.count("log_status_" + status, 1)
    elif status in (None, "OK"):
        kind, why = "flow", ("log-status is OK" if status else "log-status is not in this log's format")
        if status:
            ctx.count("log_status_OK", 1)
    else:
        kind, why = "unknown_status", "log-status is %s, a value the documentation does not list" % free(status)
        ctx.count("log_status_other", 1)
    flow = kind == "flow"
    act = f.get("action")
    if kind == "no_flow_record":
        outcome, basis = "unknown", why
    elif act == "ACCEPT":
        outcome, basis = "success", "action is ACCEPT: the traffic was accepted (the documentation); this does not show a connection was established"
    elif act == "REJECT":
        outcome, basis = "failure", "action is REJECT: the traffic was rejected (the documentation)"
    else:
        outcome, basis = "unknown", "action is %s" % ("absent" if act is None else "not ACCEPT or REJECT")
    shown = {}
    for n in names:
        v = f[n]
        if v is None:
            shown[n if n in VPC_VERSIONS else free(n)] = None
        elif n in VPC_NUMBERS:
            shown[n] = num(v)
        elif n in VPC_FREE or n not in VPC_VERSIONS:
            shown[n if n in VPC_VERSIONS else free(n)] = free(v)
        else:
            shown[n] = ident(v)
    st = epoch_stamp(f.get("start")) if "start" in names else {"utc": None, "ns": None, "status": "missing", "basis": "start is not a field of this log's format"}
    end = epoch_stamp(f.get("end")) if "end" in names else None
    row = {
        "provider": "aws", "adapter": "aws_vpc_flow", "tenant_kind": "account (the owner of the source network interface)", "tenant": ident(f.get("account-id")),
        "principal": None, "principal_kind": None,
        "action": free(act) if flow else free(status), "service": "vpc-flow-logs", "resource": ident(f.get("interface-id")),
        "row_kind": kind, "row_kind_basis": why, "log_status": free(status),
        "outcome": outcome, "outcome_basis": basis,
        "flow_log_version": declared, "flow_log_version_from_fields": highest,
        "fields_from": item["origin"], "fields": shown,
        "time_raw": f.get("start"), "_stamp": st, "end_time_raw": f.get("end"), "end_time_utc": end["utc"] if end else None,
        "source_ip": ident(f.get("srcaddr")) if flow else None, "destination_ip": ident(f.get("dstaddr")) if flow else None,
        "source_port": num(f["srcport"]) if flow and f.get("srcport") is not None else None,
        "destination_port": num(f["dstport"]) if flow and f.get("dstport") is not None else None,
        "protocol_number": num(f["protocol"]) if flow and f.get("protocol") is not None else None,
        "packets": num(f["packets"]) if flow and f.get("packets") is not None else None,
        "bytes": num(f["bytes"]) if flow and f.get("bytes") is not None else None,
        "traffic": None if flow else "none reported: this row is a log-status record, and its counts (if any) are in fields as written",
        "unknown_field_names": [free(n) for n in unknown[:MAX_TRAILING_SHOWN]] or None,
    }
    if declared is not None and highest is not None and declared != highest:
        row["flow_log_version_note"] = "the version field says %s and the highest version among this log's field names is %s" % (declared, highest)
    return [row], {"line": item["line"]}


def text_kind(path):
    """'s3log' or 'vpcflow' when the first non-blank line of the file (decompressed if it is gzip) is the form of one of the two text formats,
    else None. Read from the content; the name is never used."""
    src = Source(path, MAX_EXPANDED_BYTES)
    try:
        src.ensure(8192)
        head = src.buf[src.pos:src.pos + 8192]
    finally:
        src.close()
    for line in head.split("\n"):
        line = line.rstrip("\r")
        if not line.strip():
            continue
        if _S3_HEAD.match(line[:4096]):
            return "s3log"
        toks = line.split(" ")
        if is_vpc_header(toks):
            return "vpcflow"
        if re.fullmatch(r"[0-9]{1,2}", toks[0]) and 2 <= int(toks[0]) <= 99 and len(toks) >= 14 and "" not in toks:
            return "vpcflow"
        return None
    return None


# ---- Google Workspace Reports API activities ----------------------------------------------------------------------------------------------------
# The shape is the work card's: id{time, uniqueQualifier, applicationName, customerId}, actor, ipAddress, events[{type, name, parameters[{name, value,
# multiValue, boolValue...}]}]. The Google documentation was not read for this version (only the AWS pages were permitted), so the shape, the application
# names, the event names and the parameter names are NOT checked against a vendor page; the adapter takes every name from the record and invents none.

WS_VALUE_KEYS = ("value", "multiValue", "intValue", "multiIntValue", "boolValue", "messageValue")
WS_SECRET_NAME = ENTRA_SECRET_NAME
MAX_TOPIC_CHARS = 2000
TOPIC_RULES = (
    ("grant", re.compile(r"grant|authori[sz]e|consent|permission")),
    ("revocation", re.compile(r"revoke|remov|delet|disabl|deactivat")),
    ("delegation", re.compile(r"delegat")),
    ("forwarding", re.compile(r"forward")),
    ("sharing", re.compile(r"visibility|shar(?:e|ing)|\bacl\b|user_access|access_change")),
    ("role", re.compile(r"role|privilege")),
    ("credential", re.compile(r"password|credential|secret|certificate|2sv|two.step|recovery|\bkeys?\b")),
)


def topic_hints(*texts):
    """Words of an event name that point at consent, grant, revocation, delegation, forwarding, sharing, a role or a credential: this tool's own list, a hint
    for where to look and never a classification any vendor documents."""
    words = " ".join(t for t in texts if isinstance(t, str))[:MAX_TOPIC_CHARS].lower()
    return [name for name, rx in TOPIC_RULES if rx.search(words)]


def ws_recognise(item):
    keys = key_map(item)
    idd = item.get(keys["id"]) if "id" in keys else None
    return is_dict(idd) and "applicationname" in key_map(idd) and isinstance(item.get(keys.get("events")), list)


def ws_param_value(p):
    for k in WS_VALUE_KEYS:
        if k in p and p[k] is not None:
            return p[k]
    return None


def ws_adapt(item, ctx):
    keys = key_map(item)

    def top(name):
        k = keys.get(name.lower())
        return item.get(k) if k is not None else None

    idd = top("id") if is_dict(top("id")) else {}
    ik = key_map(idd)

    def idv(name):
        k = ik.get(name.lower())
        return idd.get(k) if k is not None else None

    actor = top("actor") if is_dict(top("actor")) else {}
    ak = key_map(actor)

    def av(name):
        k = ak.get(name.lower())
        return actor.get(k) if k is not None else None

    ekey = keys["events"]
    events = item[ekey]
    app = idv("applicationName")
    principal = av("email") if av("email") not in (None, "") else av("profileId")
    protected = dict(item)
    new_events = []
    rows = []
    for ei, ev in enumerate(events):
        if not is_dict(ev):
            new_events.append(ev)
            continue
        ev2 = dict(ev)
        evk = key_map(ev)
        pkey = evk.get("parameters")
        params = ev.get(pkey) if pkey is not None else None
        bag, by_name = None, {}
        if isinstance(params, list):
            bag = []
            for pi, p in enumerate(params):
                if not is_dict(p):
                    bag.append(p)
                    continue
                p2 = dict(p)
                name = p.get("name")
                if isinstance(name, str) and (name_is_sensitive(name) or WS_SECRET_NAME.search(name)):
                    for vk in WS_VALUE_KEYS:
                        if vk in p and p[vk] not in (None, "", [], {}):
                            p2[vk] = ctx.withhold_field("/%s/%d/%s/%d/%s" % (ekey, ei, pkey, pi, vk), "a parameter named like a secret", p[vk])
                bag.append(p2)
                if isinstance(name, str):
                    label = scrub_text(name)
                    value = ws_param_value(p2)
                    if label not in by_name:
                        by_name[label] = value
                    elif isinstance(by_name[label], dict) and "repeated" in by_name[label] and len(by_name[label]) == 1:
                        by_name[label]["repeated"].append(value)
                    else:
                        by_name[label] = {"repeated": [by_name[label], value]}
            ev2[pkey] = bag
        new_events.append(ev2)
        name_l = {k.lower(): k for k in by_name if isinstance(k, str)}
        pairs = []
        for low, label in name_l.items():
            if low.startswith("old_") and ("new_" + low[4:]) in name_l:
                pairs.append({"name": low[4:], "before": by_name[label], "after": by_name[name_l["new_" + low[4:]]]})
        ename, etype = ev.get(evk.get("name")), ev.get(evk.get("type"))
        row = {
            "provider": "google_workspace", "adapter": "workspace_activities",
            "tenant_kind": "customer (id.customerId)" if idv("customerId") not in (None, "") else "customer (the record does not name one)", "tenant": ident(idv("customerId")),
            "principal": free(principal), "principal_kind": "actor.email" if av("email") not in (None, "") else ("actor.profileId" if av("profileId") not in (None, "") else None),
            "principal_id": ident(av("profileId")), "actor_caller_type": free(av("callerType")), "actor_key": ident(av("key")),
            "action": free(ename), "event_type": free(etype), "application": free(app), "resource": None,
            "outcome": "unknown", "outcome_basis": "the activity record is read as it was written: this adapter reads no result field from it, so no success or failure is stated",
            "source_ip": ident(top("ipAddress")), "owner_domain": ident(top("ownerDomain")),
            "time_raw": idv("time"), "event_id": ident(idv("uniqueQualifier")), "event_index": ei, "events_in_activity": len(events),
            "parameters": bag, "parameters_by_name": by_name or None, "before_after": pairs or None,
            "topic_hints": topic_hints(ename if isinstance(ename, str) else "", app if isinstance(app, str) else "") or None,
            "topic_hints_basis": "words in the application and event names, from this tool's own list; a hint for where to look, not a classification the vendor documents",
            "values_are_sensitive": True if bag else None,
            "_dedupe_part": "%d:%s" % (ei, ename if isinstance(ename, str) else ""),
        }
        rows.append(row)
    protected[ekey] = new_events
    if not rows:
        rows.append({
            "provider": "google_workspace", "adapter": "workspace_activities", "tenant_kind": "customer (id.customerId)", "tenant": ident(idv("customerId")),
            "principal": free(principal), "action": None, "application": free(app), "outcome": "unknown", "outcome_basis": "the activity has no event",
            "source_ip": ident(top("ipAddress")), "time_raw": idv("time"), "event_id": ident(idv("uniqueQualifier")), "events_in_activity": 0, "_dedupe_part": "none",
        })
    return rows, protected


ADAPTERS = {
    "gcp": ("gcp_audit", gcp_recognise, gcp_adapt),
    "kubernetes": ("kubernetes_audit", k8s_recognise, k8s_adapt),
    "entra": ("entra_directory_audit", entra_recognise, entra_adapt),
    "azure": ("azure_activity_log", az_recognise, az_adapt),
    "workspace": ("workspace_activities", ws_recognise, ws_adapt),
}
TEXT_ADAPTERS = {"s3log": ("aws_s3", "aws_s3_access_log", s3_adapt), "vpcflow": ("aws_vpc", "aws_vpc_flow", vpc_adapt)}


def foreign_hint(item):
    """What another tool of this pack reads, when the record is its shape (a hint in the reject reason, nothing more)."""
    if "eventVersion" in item and "eventSource" in item:
        return "; it looks like a CloudTrail record: cloudtrail_parse reads it"
    keys = key_map(item)
    if "recordtype" in keys and "operation" in keys:
        return "; it looks like a unified audit log row: ual_parse reads it"
    if "userprincipalname" in keys and ("appdisplayname" in keys or "conditionalaccessstatus" in keys):
        return "; it looks like a sign-in record: signin_analyse reads it"
    return ""


def choose(item, provider):
    """(provider key, adapter) for a record, or raise Unsupported with the reason."""
    if provider != "auto":
        name, recognise, adapt = ADAPTERS[provider]
        if recognise(item):
            return provider, adapt
        raise Unsupported("not a %s record (the %s adapter did not recognise it)%s" % (provider, name, foreign_hint(item)))
    for key, (name, recognise, adapt) in ADAPTERS.items():
        if recognise(item):
            return key, adapt
    raise Unsupported("no adapter of this tool reads this record (adapters: gcp_audit, kubernetes_audit, entra_directory_audit, azure_activity_log, workspace_activities; the S3 server access log and the VPC Flow Log are text files and are read as such)%s" % foreign_hint(item))


# ---- one file ---------------------------------------------------------------------------------------------------------------------------------

class Ctx:
    """What an adapter may do: decode a second time, and replace a value it must not print (noting where, and writing the original to the values
    file when the caller asked for it)."""

    def __init__(self, withheld, locator):
        self.withheld, self.locator = withheld, locator
        self.notes = {}

    def second_time(self, row, raw_key, utc_key):
        st = stamp(row.get(raw_key))
        row[utc_key] = st["utc"]

    def withhold_field(self, pointer, why, original):
        return self.withheld.field(self.locator, pointer, why, original)

    def count(self, name, n=1):
        """A count an adapter keeps for the file's coverage (unknown trailing fields, log-status words...); a zero is not noted."""
        if n:
            self.notes[name] = self.notes.get(name, 0) + n


class Run:
    """Everything the run counts, in one place, so that a signal can write what there is."""

    def __init__(self):
        self.files = []
        self.totals = {"records_read": 0, "rows": 0, "records_rejected": 0, "records_unsupported": 0, "records_malformed": 0, "records_filtered_out": 0,
                       "duplicates": 0, "files_found": 0, "files_read": 0}
        self.first_ns = self.last_ns = None
        self.ids = set()
        self.ids_full = False
        self.stopped_by_time = False
        self.status = "running"
        self.dir = None
        self.paths = {}

    def note_time(self, ns):
        if ns is None:
            return
        self.first_ns = ns if self.first_ns is None else min(self.first_ns, ns)
        self.last_ns = ns if self.last_ns is None else max(self.last_ns, ns)

    def live_totals(self):
        """The counts now: the files' own counters (updated as each record is read), so that a signal reports what was read."""
        sums = dict(self.totals)
        for key in ("records_read", "rows", "records_rejected", "records_unsupported", "records_malformed", "records_filtered_out", "duplicates"):
            sums[key] = sum(f.get(key, 0) for f in self.files)
        return sums

    def snapshot(self, status, basis=None):
        return {"tool": TOOL, "parser": PARSER, "status": status, "status_basis": basis, "totals": self.live_totals(),
                "observed_time_range": {"first_utc": ns_to_utc(self.first_ns), "last_utc": ns_to_utc(self.last_ns)},
                "sources": self.files}


RUN = Run()


def write_partial_coverage():
    """Called when the run ends before its answer is written (a signal, an error): a partial coverage file beside the outputs, and one line of
    JSON on stdout, so that what was counted is not lost. It never replaces a file."""
    if RUN.status != "running" or RUN.dir is None:
        return
    RUN.status = "interrupted"
    try:
        doc = RUN.snapshot("partial", "the run ended before its answer was written (a signal or an error); the counts are those at that moment; the rows and rejected files may or may not have been published, and the answer was not written")
        doc["interrupted"] = True
        data = dumps_deep(doc, default=str, allow_nan=False, indent=2)
        directory = Path(RUN.dir)
        directory.mkdir(parents=True, exist_ok=True)
        fd, name = tempfile.mkstemp(dir=directory, prefix=".%s-coverage-" % TOOL)
        with os.fdopen(fd, "w", encoding="utf-8", errors="backslashreplace") as fh:
            fh.write(data)
            fh.write("\n")
        final = publish(name, directory / "coverage.partial.json")
        print(dumps_deep({"tool": TOOL, "parser": PARSER, "status": "partial", "interrupted": True,
                          "status_basis": "the run was stopped by a signal or ended in an error before its answer was written; the counts are those at that moment",
                          "partial_coverage": shown_output(final), "totals": RUN.live_totals()}, default=str, allow_nan=False))
        sys.stdout.flush()
    except Exception:  # noqa: BLE001 - best effort inside a signal handler
        pass


class FileRow:
    def __init__(self, shown):
        self.d = {"file": shown, "status": "read", "format": None, "format_basis": None, "compressed": False, "provider_requested": None,
                  "records_read": 0, "rows": 0, "records_rejected": 0, "records_unsupported": 0, "records_malformed": 0, "records_filtered_out": 0,
                  "duplicates": 0, "bytes_read": 0, "adapters": {}, "time_statuses": {}, "observed_time_range": {"first_utc": None, "last_utc": None},
                  "pagination_markers": [], "first_failures": []}
        self.first_ns = self.last_ns = None

    def fail(self, reason, record, line):
        if len(self.d["first_failures"]) < FIRST_PROBLEMS:
            self.d["first_failures"].append({"record": record, "line": line, "reason": reason})


def open_rows(path, fmt_arg, delimiter, max_expanded, record_cap, provider="auto", vpc_fields=None):
    kind = text_kind(path)
    seen = kind or sniff(path)
    if kind is None and fmt_arg in ("s3log", "vpcflow") and seen == "csv":
        seen = fmt_arg                # a text file the first line does not identify (a custom flow log with no header line), named by the caller
    shown_kind = {"s3log": "an S3 server access log", "vpcflow": "a VPC Flow Log"}.get(seen, seen)
    wanted = {"auto": seen, "csv": "csv", "json": "json", "jsonl": "json", "s3log": "s3log", "vpcflow": "vpcflow"}[fmt_arg]
    if wanted != seen:
        raise ValueError("format %s was asked for, and the content of this file reads as %s" % (fmt_arg, shown_kind))
    if seen in TEXT_ADAPTERS and provider not in ("auto", TEXT_ADAPTERS[seen][0]):
        raise ValueError("provider %s was asked for, and the content of this file reads as %s (provider %s)" % (provider, shown_kind, TEXT_ADAPTERS[seen][0]))
    src = Source(path, max_expanded)
    basis = "the content" if fmt_arg == "auto" else "the format argument, and the content agrees"
    if seen == "s3log":
        return src, s3_rows(src, record_cap), seen, basis
    if seen == "vpcflow":
        return src, vpc_rows(src, record_cap, vpc_fields), seen, basis
    if seen == "json":
        return src, read_units(src, ENVELOPE_KEYS, record_cap, MAX_DOCUMENT_BYTES), seen, basis
    return src, csv_rows(src, delimiter, record_cap, record_cap), seen, basis


def dedupe_key(adapter, row, part=None):
    ident_ = row.get("event_id")
    if ident_ is None:
        return None
    raw = "%s\x00%s\x00%s" % (adapter, ident_, row.get("stage") or part or "")
    return int.from_bytes(hashlib.blake2b(raw.encode("utf-8", "backslashreplace"), digest_size=8).digest(), "big")


def process_file(path, opts, sinks, withheld, fr):
    """Read one file into the rows page and the rejects page. Returns the Source (for its problems) and whether the file's read was cut."""
    d = fr.d
    shown = d["file"]
    src, units, fmt, basis = open_rows(path, opts["format"], opts["delimiter"], opts["max_expanded"], opts["record_cap"], opts["provider"], opts["vpc_fields"])
    d["format"], d["format_basis"] = fmt, basis
    sinks["rejected"].start_file()
    stopped_all = False
    size_rejects = 0
    first_reject = None
    try:
        for kind, info, item in units:
            if out_of_time():
                src.timed_out = True
                break
            check_deadline()
            loc = {"file": path, "record": info["record"], "line": info["line"]}
            where = {"file": shown, "record": info["record"], "line": info["line"], "offset": info.get("offset")}
            if kind == "reject" or not isinstance(item, dict):
                reason = item if kind == "reject" else "a JSON %s, not a record" % type(item).__name__
                d["records_rejected"] += 1
                d["records_malformed"] += 1
                first_reject = first_reject or (info["record"], info["line"], reason)
                fr.fail(scrub_text(reason), info["record"], info["line"])
                if kind == "reject" and ("larger than max_record_bytes" in str(reason) or "a line longer than" in str(reason)):
                    size_rejects += 1
                if sinks["rejected"].reject({**where, "kind": "malformed", "reason": scrub_text(reason)}):
                    stopped_all = True
                    break
                continue
            d["records_read"] += 1
            try:
                if fmt == "csv":
                    item = {k: maybe_json(v) for k, v in item.items()}
                if fmt in TEXT_ADAPTERS:
                    key, adapt = TEXT_ADAPTERS[fmt][0], TEXT_ADAPTERS[fmt][2]
                else:
                    key, adapt = choose(item, opts["provider"])
                ctx = Ctx(withheld, loc)
                rows, protected = adapt(item, ctx)
                for note, n in ctx.notes.items():
                    counts = d.setdefault("adapter_counts", {})
                    counts[note] = counts.get(note, 0) + n
                pending = []
                for row in rows:
                    st = row.pop("_stamp", None) or stamp(row.get("time_raw"))
                    part = row.pop("_dedupe_part", None)
                    row["time_utc"], row["time_status"], row["time_basis"] = st["utc"], st["status"], st["basis"]
                    d["time_statuses"][st["status"]] = d["time_statuses"].get(st["status"], 0) + 1
                    shown_principal = row.get("principal")
                    if opts["principal"] and not (shown_principal and hits(opts["principal"], shown_principal)):
                        d["records_filtered_out"] += 1
                        continue
                    dk = dedupe_key(row["adapter"], row, part)
                    dup = None
                    if dk is not None:
                        if dk in RUN.ids:
                            dup = True
                        elif len(RUN.ids) < MAX_IDS:
                            RUN.ids.add(dk)
                        else:
                            RUN.ids_full = True
                    row["duplicate_of_an_earlier_record"] = True if dup else None
                    row["locator"] = {"file": shown, "record": info["record"], "line": info["line"], "offset": info.get("offset"),
                                      "offset_unit": "characters of the decoded text"}
                    row["parser"] = PARSER
                    out = withheld.clean(compact(row, keep=("outcome", "time_utc", "time_status")), loc, "")
                    out["raw_record"] = withheld.clean(protected, loc, "/raw_record")
                    pending.append((out, st, key, dup))
                for out, st, key, dup in pending:
                    sinks["rows"].add(out)
                    d["rows"] += 1
                    d["adapters"][out["adapter"]] = d["adapters"].get(out["adapter"], 0) + 1
                    if dup:
                        d["duplicates"] += 1
                    if st["ns"] is not None:
                        fr.first_ns = st["ns"] if fr.first_ns is None else min(fr.first_ns, st["ns"])
                        fr.last_ns = st["ns"] if fr.last_ns is None else max(fr.last_ns, st["ns"])
                        RUN.note_time(st["ns"])
            except Unsupported as exc:
                d["records_read"] -= 1
                d["records_rejected"] += 1
                d["records_unsupported"] += 1
                reason = scrub_text(str(exc))
                first_reject = first_reject or (info["record"], info["line"], reason)
                fr.fail(reason, info["record"], info["line"])
                if sinks["rejected"].reject({**where, "kind": "unsupported", "reason": reason, "raw_record": withheld.clean(item, loc, "/raw_record")}):
                    stopped_all = True
                    break
                continue
            except Exception as exc:       # one record never ends the run: it is counted, located and listed, and the next is read
                d["records_read"] -= 1
                d["records_rejected"] += 1
                reason = failed_record(exc)
                first_reject = first_reject or (info["record"], info["line"], reason)
                fr.fail(reason, info["record"], info["line"])
                sinks["rejected"].note({**where, "kind": "adapter_error", "reason": reason})
                if isinstance(exc, TimeUp):
                    src.timed_out = True
                    break
                continue
            sinks["rejected"].accept()
    finally:
        src.close()
    d["observed_time_range"] = {"first_utc": ns_to_utc(fr.first_ns), "last_utc": ns_to_utc(fr.last_ns)}
    return src, stopped_all, size_rejects, first_reject


def main():
    install_signal_handlers()
    args = read_args()
    refuse_unknown(args, ARGS)
    one = want_str(args, "path")
    many = want_str_list(args, "paths")
    inputs = ([one] if one is not None else []) + many
    if not inputs:
        fail("path or paths is required: an export file or a directory of them")
    provider = want_str(args, "provider") or "auto"
    if provider not in ("auto",) + PROVIDERS:
        fail("provider must be auto, " + ", ".join(PROVIDERS))
    fmt_arg = want_str(args, "format") or "auto"
    if fmt_arg not in ("auto", "csv", "json", "jsonl", "s3log", "vpcflow"):
        fail("format must be auto, csv, json, jsonl, s3log or vpcflow")
    vpc_text = want_str(args, "vpc_flow_fields")
    vpc_fields = None
    if vpc_text is not None:
        vpc_fields = vpc_text.replace(",", " ").split()
        if not vpc_fields or len(vpc_fields) > MAX_VPC_FIELDS or len(set(vpc_fields)) != len(vpc_fields) or not all(_VPC_NAME.match(x) for x in vpc_fields):
            fail("vpc_flow_fields must be 1 to %d distinct field names (lower case letters, digits and hyphens), separated by spaces or commas" % MAX_VPC_FIELDS)
    delimiter = want_str(args, "delimiter") or ","
    if len(delimiter) != 1:
        fail("delimiter must be one character")
    limit = want_int(args, "limit", DEFAULT_LIMIT)
    pattern = want_regex(args, "principal")
    max_expanded = want_int(args, "max_expanded_bytes", MAX_EXPANDED_BYTES, 1024)
    record_cap = want_int(args, "max_record_bytes", MAX_RECORD_BYTES, 1024, 1 << 30)
    write_values = want_bool(args, "write_values")
    seconds = start_clock(args)
    for p in inputs:
        if os.path.islink(p) and not os.path.exists(p):
            fail("the path is a link that does not lead to a file (a loop or a missing target)", path=shown_path(p))
        if not os.path.exists(p):
            fail("no such file or directory", path=shown_path(p))
    out_dir = want_str(args, "out_dir")
    if out_dir is not None:
        directory = Path(resolve_output(out_dir, "out_dir"))
    elif in_job():
        directory = Path(os.environ["OUT"]) / "cloud-normalise"
    else:
        directory = Path("work") / re.sub(r"[^A-Za-z0-9_.-]", "_", os.environ.get("AGENT_ID") or "tool") / "cloud-normalise"
    try:
        vault = SecretValues(write_values, VALUES_NAME, TOOL)
    except SecretValuesRefused as exc:
        fail(str(exc), write_values="refused", written=False)

    skipped = Skips()
    targets, seen_real = [], set()
    for p in inputs:
        found = []
        if os.path.isdir(p):
            found = walk_inputs(p, lambda n: n.lower().endswith(READ_NAMES), skipped)
        elif os.path.isfile(p):
            found = [p]
        else:
            fail("the path is neither a regular file nor a directory: it is not opened", path=shown_path(p))
        for f in found:
            real = os.path.realpath(f)
            if real in seen_real:
                skipped.append({"path": shown_path(f), "reason": "the same file was already listed"})
                continue
            seen_real.add(real)
            targets.append(f)
    if not targets:
        fail("no export file found there", path=shown_path(inputs[0]), skipped=named(skipped.items))

    RUN.totals["files_found"] = len(targets)
    RUN.dir = str(directory)
    CLEANUP.append(write_partial_coverage)
    withheld = Withheld(vault, limit)
    sinks = {"rows": LosslessPage(TOOL, limit, dest=str(directory / OUT_NAMES["rows"])),
             "rejected": RejectLog(LosslessPage("rejected_records", limit, dest=str(directory / OUT_NAMES["rejected"])))}
    opts = {"provider": provider, "format": fmt_arg, "delimiter": delimiter, "principal": pattern, "max_expanded": max_expanded, "record_cap": record_cap, "vpc_fields": vpc_fields}
    problems, pagination = [], []
    any_cut = False
    replaced_total = 0
    try:
        for n, path in enumerate(targets):
            if out_of_time():
                RUN.stopped_by_time = True
                problems.append("the time limit ended the run before %d file(s) were opened: %s" % (len(targets) - n, ", ".join(shown_path(t) for t in targets[n:n + 5])))
                for t in targets[n:]:
                    fr = FileRow(shown_path(t))
                    fr.d["status"] = "not_read"
                    fr.d["problems"] = ["the time limit ended the run before this file was opened"]
                    RUN.files.append(fr.d)
                any_cut = True
                break
            fr = FileRow(shown_path(path))
            fr.d["provider_requested"] = provider
            RUN.files.append(fr.d)
            try:
                src, stopped_all, size_rejects, first_reject = process_file(path, opts, sinks, withheld, fr)
            except ValueError as exc:
                fr.d["status"] = "unsupported"
                fr.d["problems"] = [scrub_text(str(exc))]
                problems.extend(fr.d["problems"])
                any_cut = True
                continue
            d = fr.d
            fp = []
            if src.error:
                fp.extend(src.problem_lines())
            if src.capped:
                fp.append("the expansion reached max_expanded_bytes (%d): the rest of the file was not read" % max_expanded)
            if getattr(src, "stopped", None):
                fp.append(src.stopped)
            if stopped_all and size_rejects == d["records_rejected"]:
                fp.append("the first %d records were each larger than max_record_bytes (%d), so none was read: raise it; the rest of the file was not examined" % (FIRST_REJECTS, record_cap))
            elif stopped_all:
                fp.append("the first %d records were all rejected: this is not an export this tool reads, and the rest of the file was not examined" % FIRST_REJECTS)
            if d["records_rejected"]:
                fp.append("%d record(s) were not turned into rows (%d malformed, %d that no adapter read; the first, record %s at line %s: %s); %s" % (
                    d["records_rejected"], d["records_malformed"], d["records_unsupported"], first_reject[0], first_reject[1], first_reject[2],
                    "every one is in rejected.jsonl" if not sinks["rejected"].total_unlisted else "the first %d are in rejected.jsonl" % LIST_REJECTS))
            if src.replaced:
                fp.append("%d byte(s) were not valid %s and were replaced; the records they sit in are not exact" % (src.replaced, src.encoding.upper()))
                d["replacement_characters"] = src.replaced
                replaced_total += src.replaced
            markers = [scrub_text(k) for k in getattr(src, "extra_keys", []) if pagination_key(k)]
            if markers:
                d["pagination_markers"] = markers
                pagination.append({"file": d["file"], "keys": markers})
            d.update({"compressed": src.compressed, "encoding": src.encoding, "bytes_read": src.bytes_read, "shape": getattr(src, "mode", None)})
            if src.trailing_zero_bytes:
                d["trailing_zero_bytes"] = src.trailing_zero_bytes
            if getattr(src, "header_lines", 0):
                d["header_lines"] = src.header_lines
            cut = bool(src.error or src.capped or getattr(src, "stopped", None) or src.timed_out or stopped_all)
            if src.timed_out:
                d["status"] = "partial"
                RUN.stopped_by_time = True
            elif src.archive:
                d["status"] = "unsupported"
                d["archive"] = src.archive
            elif src.bytes_read == 0 and not src.error:
                d["status"] = "empty"
            elif d["rows"] == 0 and d["records_filtered_out"] == 0 and (src.error or d["records_rejected"] or fp):
                d["status"] = "failed" if src.error and not d["records_rejected"] else "unsupported"
            elif fp:
                d["status"] = "partial"
            if d["status"] == "read":
                RUN.totals["files_read"] += 1
            if fp:
                d["problems"] = [scrub_text(p) for p in fp]
                problems.extend(d["problems"])
            any_cut = any_cut or cut or d["status"] != "read"
            if src.timed_out:
                for t in targets[n + 1:]:
                    f2 = FileRow(shown_path(t))
                    f2.d["status"] = "not_read"
                    f2.d["problems"] = ["the time limit ended the run before this file was opened"]
                    RUN.files.append(f2.d)
                problems.append("the time limit ended the read inside %s; %d file(s) after it were not opened" % (d["file"], len(targets) - n - 1))
                break
    except TimeUp:
        RUN.stopped_by_time = True
        any_cut = True
        problems.append("the time limit ended the run inside a record")
    finally:
        vault.close()

    if skipped.total:
        problems.append("%d entr%s of the supplied directories were not read (links, special files, archives, names this tool does not read)" % (skipped.total, "y" if skipped.total == 1 else "ies"))
    rows_page = sinks["rows"].finish(partial=any_cut or bool(pagination))
    rej_page = sinks["rejected"].page.finish()
    withheld_summary = withheld.summary()
    all_read = bool(RUN.files) and all(f["status"] == "read" for f in RUN.files)
    complete = all_read and not pagination and replaced_total == 0 and not skipped.total
    totals = RUN.live_totals()
    adapter_counts = {}
    for f in RUN.files:
        for k, v in (f.get("adapter_counts") or {}).items():
            adapter_counts[k] = adapter_counts.get(k, 0) + v
    failed = totals["rows"] == 0 and not totals["records_filtered_out"] and not complete
    status = status_of(
        failed, complete,
        "every record of the supplied files was read and turned into a row, nothing was rejected, and no file names a next page; that says nothing about whether the export holds everything the "
        "provider logged, or whether logging was complete (export completeness is not logging completeness)",
        ("the time limit (%s s) ended the run; what was read is kept and the files not read are named (see sources and problems)" % seconds) if RUN.stopped_by_time else
        "part of the input was not turned into rows, a file names a next page that was not supplied, a file was not read, or bytes were replaced (see sources, problems, rejected.jsonl and pagination_markers)",
        "no record could be turned into a row (see problems and rejected.jsonl)")
    coverage = RUN.snapshot(status["status"], status["status_basis"])
    coverage.update({
        "providers_requested": provider, "adapters": {**{k: v[0] for k, v in ADAPTERS.items()}, **{v[0]: v[1] for v in TEXT_ADAPTERS.values()}},
        "adapter_counts": adapter_counts, "time_limit_seconds": seconds,
        "stopped_by_time_limit": RUN.stopped_by_time, "max_expanded_bytes": max_expanded, "max_record_bytes": record_cap,
        "pagination_markers": pagination, "problems": [scrub_text(p) for p in problems], "skipped_entries": skipped.total, "skipped_first": named(skipped.items),
        "duplicate_annotation": ("complete" if not RUN.ids_full else "stopped after %d distinct record keys: duplicates after that are not annotated" % MAX_IDS),
        "rejected_records_not_listed": sinks["rejected"].total_unlisted,
        "values_withheld": withheld_summary["count"], "export_vs_logging": "this file describes the export that was supplied; it says nothing about the provider's logging, retention or what was never exported",
    })
    cov_data = dumps_deep(coverage, default=str, allow_nan=False, indent=2) + "\n"
    directory.mkdir(parents=True, exist_ok=True)
    with signals_held():
        fd, tmp = tempfile.mkstemp(dir=directory, prefix=".%s-coverage-" % TOOL)
        _TEMPS.add(tmp)
    with os.fdopen(fd, "w", encoding="utf-8", errors="backslashreplace") as fh:
        fh.write(cov_data)
        fh.flush()
        os.fsync(fh.fileno())
    cov_name = "coverage.json" if status["status"] == "complete" else "coverage.partial.json" if status["status"] == "partial" else "coverage.failed.json"
    cov_final = publish(tmp, directory / cov_name)
    _TEMPS.discard(tmp)
    RUN.status = status["status"]
    if write_partial_coverage in CLEANUP:
        CLEANUP.remove(write_partial_coverage)
    sources_page = LosslessPage("sources", limit)
    for f in RUN.files:
        sources_page.add(f)
    sources_done = sources_page.finish()
    answer = {
        "parser": PARSER, **status, "provider": provider,
        "outputs": {"normalised": rows_page.get("all_results"), "rejected": rej_page.get("all_results"), "coverage": shown_output(cov_final)},
        "output_names_note": "an output whose name was already taken (an earlier run in the same directory) is kept beside the earlier one, as name.2.ext; a read that ended early publishes the rows as normalised.partial.jsonl",
        "coverage": {**RUN.live_totals(), "observed_time_range": coverage["observed_time_range"], "time_limit_seconds": seconds, "stopped_by_time_limit": RUN.stopped_by_time,
                     "max_expanded_bytes": max_expanded, "max_record_bytes": record_cap, "duplicate_annotation": coverage["duplicate_annotation"],
                     "rejected_records_not_listed": coverage["rejected_records_not_listed"], "skipped_entries": skipped.total, "adapter_counts": adapter_counts},
        "sources": sources_page.page, "problems": coverage["problems"], "pagination_markers": pagination,
        "rows": [], "rows_inline": 0, "row_count": RUN.live_totals()["rows"],
        "values_withheld": {"count": withheld_summary["count"], "by_reason": withheld_summary["by_reason"], "locators": withheld_summary["locators"],
                            "page": withheld_summary["page"], "text_withheld_from_paths_and_messages": withheld_summary["text_withheld_from_paths_and_messages"]},
        "secret_values": vault.summary(),
        "sensitive_output": {"payloads_inline": True, "personal_data": "principal names, addresses and user agents are in the rows",
                             "withholding": "credential-named fields, Kubernetes Secret bodies and credential-shaped text are withheld; other secrets are not recognised",
                             "advice": "run this tool as a job with secret_output: true when the case treats the export as sensitive"},
        "pages": {"normalised": rows_page, "rejected_records": rej_page, "sources": sources_done},
        "truncated": rows_page["truncated"] or rej_page["truncated"] or sources_done["truncated"],
        "note": "Export completeness is not logging completeness: nothing here says the provider logged everything, kept it, or that the export holds all of it. A row's outcome is the "
                "record's own (success, failure, or unknown when it says nothing); a Kubernetes audit event is one stage of a request, and the stages of one audit id are separate rows. "
                "A time with no zone is never read as UTC: time_utc is null and time_raw is kept. A duplicate is annotated and kept; nothing is deduplicated.",
    }
    answer["rows"] = sinks["rows"].page
    answer["rows_inline"] = len(sinks["rows"].page)
    if status["status"] == "failed":
        answer["error"] = "no record could be turned into a row"
    print(dumps_deep(answer, indent=2, default=str, allow_nan=False))
    if status["status"] == "failed":
        raise SystemExit(1)


# BEGIN SHARED LEAVE
# The same text is in every pack tool and recipe and in their tool-library twins (tests/shared-blocks-census.test.ts holds the copies equal):
# how a call ends once its answer has begun. The interpreter's own teardown resets the signal handlers to their defaults before it frees what
# the call held, and a stop signal that landed there killed a process that had printed its whole answer; a handler that raises or writes a
# last word, run after the answer was out, wrote a second document or a traceback after a whole one. So, when the file runs as a program:
# * Standard output is wrapped, and its first write is the first byte of the answer: from there the stop signals are held for good (blocked
#   in this thread, and given a handler that does nothing for any other), so no handler runs into the answer or after it, and an error Python
#   can only report (a file the call left open whose last write the file system refuses, closed when the frame that held it is freed) is
#   not printed (Python 3.11 and 3.12 say nothing of it; 3.14 prints a traceback). A handler that was already due runs on the way in, before
#   any byte is written, and its own answer is then the one.
# * _code(stop) is a SystemExit's exit code, and _leave(code) ends the call: both hold the signals first; _leave then flushes standard output
#   and standard error, runs the atexit hooks (a hook that removes a temporary file), each step on its own and none able to raise, and ends
#   the process with os._exit, never through the teardown. A stop signal after the hold is not answered: the exit code is the call's own.
# The modules are imported here, as the file is loaded, never inside the ending (an import there ran a due handler inside the import system).
import atexit
import os
import signal
import sys

_ENDING = {"held": False}
_ENDING_SIGNALS = (signal.SIGTERM, signal.SIGINT, signal.SIGHUP)


def _ending_nothing(*_ignored):
    """The stop signals' handler, and sys.unraisablehook, once the answer has begun: nothing."""


def hold_stop_signals():
    """Hold the stop signals for good. A handler that was due runs first, in the first call that can run it, and may raise: that is before
    any byte of the answer is written. Called by a thread that is not the main one, it blocks the signals there and leaves the rest to the
    main thread's next write."""
    if _ENDING["held"]:
        return
    try:
        signal.pthread_sigmask(signal.SIG_BLOCK, _ENDING_SIGNALS)
    except (AttributeError, ValueError, OSError):
        pass                          # no pthread_sigmask here: the handler below holds them
    main_thread = True
    for signum in _ENDING_SIGNALS:
        try:
            signal.signal(signum, _ending_nothing)
        except (ValueError, OSError):
            main_thread = False
    sys.unraisablehook = _ending_nothing
    _ENDING["held"] = main_thread


def _hold_at_the_end():
    for _attempt in range(len(_ENDING_SIGNALS) + 2):
        try:
            hold_stop_signals()
            return
        except BaseException:  # noqa: BLE001 - a handler that was due ran on the way in; the hold is made again
            continue


class _AnswerStream:
    """Standard output of a call: the first write holds the stop signals (above); everything else is the stream's own."""

    def __init__(self, stream):
        self._stream = stream

    def write(self, text):
        if not _ENDING["held"]:
            hold_stop_signals()
        return self._stream.write(text)

    def writelines(self, lines):
        if not _ENDING["held"]:
            hold_stop_signals()
        return self._stream.writelines(lines)

    def __getattr__(self, name):
        if name == "_stream":
            raise AttributeError(name)
        return getattr(self._stream, name)


def _code(stop):
    _hold_at_the_end()
    code = getattr(stop, "code", 1)
    return code if isinstance(code, int) else (0 if code is None else 1)


def _leave(code):
    _hold_at_the_end()
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.flush()
        except BaseException:  # noqa: BLE001 - a reader that is gone, a stream that is closed: the exit code is the call's own
            pass
    try:
        atexit._run_exitfuncs()
    except BaseException:  # noqa: BLE001 - a hook that fails is not a failure of the answer
        pass
    code = code if isinstance(code, int) else 1
    os._exit(code)


if __name__ == "__main__" and sys.stdout is not None and not isinstance(sys.stdout, _AnswerStream):
    sys.stdout = _AnswerStream(sys.stdout)
# END SHARED LEAVE


if __name__ == "__main__":
    exit_code = 0
    try:
        try:
            main()
        except SystemExit:
            raise
        except Exception as exc:  # never an empty or clean answer for a failure
            fail("unexpected failure: %s: %s" % (type(exc).__name__, scrub_text(str(exc))))
    except SystemExit as stop:
        exit_code = _code(stop)
    _leave(exit_code)
