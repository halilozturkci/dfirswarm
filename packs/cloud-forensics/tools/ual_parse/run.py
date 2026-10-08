#!/usr/bin/env python3
"""Read a Microsoft 365 unified audit log export offline, open the payload that matters, and say what was and was not read.

The export is CSV (or JSON) in which one column, AuditData, is a JSON document holding almost everything: the client
address, the application, the parameters of the operation, the affected items. This reads it as a stream, one record at a
time, and keeps the whole payload beside the fields it lifts out of it.

Shapes it reads, and says so when it meets one it does not:
  - a wrapper row (CSV or JSON): outer columns and an `AuditData` column that is JSON text or an object;
  - a native audit event (JSON array, JSON Lines, or `{"value": [...]}`): an object that is itself the audit record, with
    `Operation`, `UserId`, `Id`, `CreationTime` at the top;
  - a Graph audit log record: outer fields and an `auditData` object.
Anything else is a rejected record or an unsupported file, counted and located; nothing is passed over quietly.

What it keeps. `audit_data` is the whole payload as the export wrote it (Name/Value, NewValue/OldValue and duplicate
parameter names stay as they are), with a value that is named or shaped like a credential withheld; beside it the fields
lifted out of it (operation, user, address, workload, record type, result, record id, object, client, MailAccessType,
OperationCount, the number of items listed) and, for every record, its file, record number and line.

Time. The time of a record is AuditData's CreationTime where it has one, else the outer column. A time with no zone is not
UTC unless `assume_utc` says so; a day/month/year string whose two leading fields are both 12 or less is read only with a
declared `date_order`, or when the file's own unambiguous rows prove one (reported, never silent). Raw and decoded times
are both kept.

What it does not do. The flagged operations are the names this tool lists for a second look, not detections: each is also
what an administrator does on an ordinary day. A record is not a human act, and a MailItemsAccessed record is not a
statement that anyone read the content. The summary tables describe the records that matched the filters; the operation
census of every row read is separate. A filter on a record whose time could not be read excludes it, and says how many.

SECRET-SAFE OUTPUT (docs/packs.md, "Secrets and sensitive output"). Parameters and properties of an audit record can hold a
secret. A field whose name says it is one, and any text shaped like one, is withheld in every channel (rows, paths, error
messages, the files the answer names); the row says how many characters, and the original goes to
`ual-values.jsonl` under $OUT (mode 0600, created first) only when `write_values: true` is asked, in a job, which the
skill says to run with `secret_output: true`. A name and a shape recognise some secrets and never all.
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
MAX_FIELD_BYTES = 64 << 20        # one CSV line (a field may span lines) longer than this stops the file, named
FIRST_REJECTS = 1000              # a file whose first records are all rejected is not an export this tool reads: it stops after this many
LIST_REJECTS = 100000             # rejected records one file lists; the rest are counted
MAX_FILTER_CHARS = 1024           # a caller's regular expression is matched against at most this many characters of a value
CHUNK = 1 << 20
DEADLINE = [None]


def in_job():
    return bool(os.environ.get("JOB_ID") and os.environ.get("OUT"))


def describe(exc):
    code = errno.errorcode.get(exc.errno, "") if getattr(exc, "errno", None) else ""
    return scrub("%s%s: %s" % (type(exc).__name__, " " + code if code else "", getattr(exc, "strerror", None) or str(exc)))


def scrub_all(value):
    if isinstance(value, str):
        return scrub(value)
    if isinstance(value, dict):
        return {k: scrub_all(v) for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        return [scrub_all(v) for v in value]
    return value


def fail(message, **extra):
    """An error answer: JSON, exit 1, the same `status` every answer of this pack carries. A name in it that is shaped
    like a credential is withheld like any other output."""
    print(json.dumps({"error": scrub(str(message)), "status": "failed",
                      "status_basis": "the tool stopped with an error (see error)", **scrub_all(extra)}, default=str))
    raise SystemExit(1)


def read_args():
    try:
        args = json.load(sys.stdin)
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
    """Why a caller's pattern is refused, or None: a group that repeats and itself repeats or branches, or a back reference,
    can take time that grows exponentially with the text; the tool cannot interrupt a match, so it does not start one."""
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


def _filter_alarm(_signum, _frame):
    raise FilterTooSlow()


class Filter:
    """A caller's regular expression. Its text is limited, a pattern that can take exponential time is refused before it is
    compiled, and every test of it against a value is timed: the re module checks for signals while it matches, so a pattern that
    takes polynomial time on a long value (`.*.*.*.*x`) is stopped at FILTER_SECONDS and the call fails, named, instead of hanging."""

    def __init__(self, rx, key):
        self.rx, self.key = rx, key
        self.timed = hasattr(signal, "setitimer") and len(re.findall(r"(?<!\\)(?:[*+]|\{\d*,\})", rx.pattern)) > 1

    def __bool__(self):
        return True

    def test(self, text):
        if not self.timed:
            return self.rx.search(text) is not None
        try:
            signal.setitimer(signal.ITIMER_REAL, FILTER_SECONDS)
            found = self.rx.search(text) is not None
            signal.setitimer(signal.ITIMER_REAL, 0)
            return found
        except FilterTooSlow:
            fail("the %s pattern took longer than %s seconds to test one value (%d characters); use a simpler pattern" % (self.key, FILTER_SECONDS, len(text)))
        finally:
            signal.setitimer(signal.ITIMER_REAL, 0)


def want_regex(args, key):
    text = want_str(args, key)
    if text is None:
        return None
    if len(text) > 200:
        fail("%s is longer than 200 characters" % key)
    why = unsafe_regex(text)
    if why:
        fail("%s is refused (%s): a pattern that can take exponential time cannot be interrupted. Use a simpler one." % (key, why))
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


def start_clock(args, default=540, maximum=580):
    seconds = args.get("time_limit_seconds", default)
    if isinstance(seconds, bool) or not isinstance(seconds, (int, float)) or seconds < 1 or seconds > maximum:
        fail("time_limit_seconds must be a number from 1 to %d" % maximum)
    DEADLINE[0] = time.monotonic() + seconds
    return seconds


def out_of_time():
    return DEADLINE[0] is not None and time.monotonic() > DEADLINE[0]


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


def same_bytes(a, b):
    try:
        if os.path.getsize(a) != os.path.getsize(b):
            return False
        with open(a, "rb") as fa, open(b, "rb") as fb:
            while True:
                x, y = fa.read(CHUNK), fb.read(CHUNK)
                if x != y:
                    return False
                if not x:
                    return True
    except OSError:
        return False


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
        text = json.dumps(row, default=str)
        self.total += 1
        if self._out is None and (len(self.page) >= self.limit or self.bytes + len(text) > self.budget):
            self._open_tmp(self.path.parent)
            for kept in self.page:
                self._write(json.dumps(kept, default=str))
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
    `summary()` says so. Enabled, it is refused outside a job; inside one the file is created at once, before anything
    is read (mode 0600, O_EXCL and O_NOFOLLOW: a file or a link already at that name is refused by name, a dangling link
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
        self._fh.write(json.dumps({"finding_id": finding_id, **locator, "value": value}, default=str))
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


# ---- withholding: nothing named or shaped like a credential is printed -------------------------------------------
# The values a cloud log can carry that are secrets are named, or they are shaped, or neither. A name or a shape is a
# way to recognise some of them and never all, so the skill says to run the tool as a job with secret_output: true
# whenever the export may hold request parameters or properties; what the rules below catch is withheld regardless, in
# every channel (rows, paths, error messages, the files the answer names), the same strings in all three tools.
# A filter a caller gives (identity, user, events, operations) is matched against the text as it is printed, never
# against a withheld original: a count of matches would tell the caller one bit of it per call.

# a value under such a name is a digest of something, not a key: the length rules do not apply to it (x-amz-checksum-sha256)
CHECKSUM_NAME = re.compile(r"(?i)checksum|digest|sha[0-9]|md5|etag|crc[0-9]")
REDACTED = re.compile(r"^\W*(?:hidden_due_to_security_reasons|redacted|masked|removed|\*+|x{3,}|\[\])\W*$", re.I)
NOT_A_VALUE = frozenset(("true", "false", "null", "none", "nil", "undefined", "required", "optional", "enabled", "disabled"))
SENSITIVE_EXACT = {
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
SENSITIVE_SUFFIX = ("password", "passwd", "passphrase", "secret", "apikey", "privatekey", "sessiontoken", "securitytoken",
                    "accesstoken", "refreshtoken", "clientsecret", "token", "secrettext", "secretkey", "secretaccesskey",
                    "primarykey", "secondarykey", "accountkey", "sharedaccesskey", "subscriptionkey", "passwordhash",
                    "ntlmhash", "nthash", "passcode", "signature", "cookie")
NOT_SECRET_TOKEN = ("nexttoken", "pagetoken", "continuationtoken", "paginationtoken", "nextpagetoken", "pagingtoken",
                    "startingtoken", "nextmarkertoken", "clienttoken", "clientrequesttoken", "idempotencytoken",
                    "nextforwardtoken", "nextbackwardtoken", "requesttoken")
CONTAINERS = ("credential", "credentials")
_NAME_CACHE = {}


def is_container_name(name):
    """`credentials` names a group of fields (an access key id, an expiry, a token): each is judged by its own name."""
    return re.sub(r"[^a-z0-9]", "", str(name).lower()) in CONTAINERS


def name_is_sensitive(name):
    hit = _NAME_CACHE.get(name)
    if hit is None:
        flat = re.sub(r"[^a-z0-9]", "", str(name).lower())
        hit = flat in SENSITIVE_EXACT or (len(flat) > 6 and flat.endswith(SENSITIVE_SUFFIX) and not flat.endswith(NOT_SECRET_TOKEN))
        if len(_NAME_CACHE) < 20000:
            _NAME_CACHE[name] = hit
    return hit


_B64 = "A-Za-z0-9+/_-"
_B64_RUN = re.compile(r"(?<![%s])[%s]{128,}={0,2}(?![%s])" % (_B64, _B64, _B64))
_B64_EDGE = "(?<![A-Za-z0-9+/=_-])"
_B64_END = "(?![A-Za-z0-9+/=_-])"
# The names an assignment is recognised by. A long compound name may carry any prefix (dbPassword=, apiToken=, adminSecret:);
# a short one needs the edge of a word (sig= is not design=).
_STRONG = (r"password|passwd|passphrase|secret|api[_-]?key|access[_-]?token|refresh[_-]?token|id[_-]?token|session[_-]?token|"
           r"security[_-]?token|auth[_-]?token|bearer[_-]?token|account[_-]?key|shared[_-]?access[_-]?key|primary[_-]?key|"
           r"secondary[_-]?key|private[_-]?key|subscription[_-]?key|sas[_-]?token|password[_-]?hash|nt[_-]?hash|ntlm[_-]?hash|"
           r"lm[_-]?hash|client[_-]?secret|secret[_-]?access[_-]?key|secret[_-]?key|secret[_-]?text|secret[_-]?value|token|signature|plaintext")
_SHORT = r"(?<![A-Za-z0-9])(?:pwd|pass|sig|pin|otp|sas)"
_SEP = r"""(?:\\*["']|["'])?\s*(?:[:=]|%3[dD]|%3[aA])\s*"""
# a short name is a name only as `pwd=value` or `pass:value`: "pass: 3 attempts" is prose
_SEPS = r"""(?:\\*["']|["'])?(?:\s*(?:=|%3[dD])\s*|:(?=\S))"""
_NAME = r"(?:(?:%s)%s|%s%s)" % (_STRONG, _SEP, _SHORT, _SEPS)
ARN_TAIL = re.compile(r"arn:[A-Za-z0-9-]+:[A-Za-z0-9-]+:[A-Za-z0-9-]*:[0-9]*:$")
SCHEMES = ("bearer", "basic", "digest", "negotiate", "ntlm")
TOKEN_RULES = [
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
        r"""(?i)%s\\*(["'])(.{1,4096}?)(?=\\*\1)""" % _NAME), 2),
    ("a value assigned to a credential name", re.compile(
        r"""(?i)%s((?:(?!%%26)[^\s"'&<>\\]){1,4096})""" % _NAME), 1),
    ("a value given to a credential switch", re.compile(
        r"""(?i)(?<![A-Za-z0-9_])-(?:password|pass|pwd|passphrase|secret|clientsecret|apikey|accesstoken|token)\s+(?:\\*(["'])(.{1,4096}?)(?=\\*\1)|([^\s"'-][^\s"']{0,4095}))"""), -1),
    ("a secret given to ConvertTo-SecureString", re.compile(
        r"""(?i)ConvertTo-SecureString\s+(?:\\*(["'])(.{1,4096}?)(?=\\*\1)|([^\s"'-][^\s"']{0,4095}))"""), -1),
    ("a hash pair of an account database", re.compile(r"(?<![0-9a-fA-F])[0-9a-fA-F]{32}:([0-9a-fA-F]{32})(?![0-9a-fA-F])"), 1),
    ("a token of a known family", re.compile(
        r"(?:GOCSPX-[A-Za-z0-9_-]{20,}|gh[pousr]_[A-Za-z0-9]{36,}|github_pat_[A-Za-z0-9_]{50,}|xox[abprs]-[A-Za-z0-9-]{10,}|AIza[0-9A-Za-z_-]{35}(?![0-9A-Za-z_-])|"
        r"ya29\.[0-9A-Za-z_-]{20,}|1//0[0-9A-Za-z_-]{30,}|(?:IQoJb3JpZ2lu|FQoGZXIvYXdz|FwoGZXIvYXdz)[A-Za-z0-9+/=]{40,}|"
        r"[A-Za-z0-9_.~-]{3}[0-9]Q~[A-Za-z0-9_.~-]{30,}|[01]\.A[A-Za-z0-9_-]{50,}|[sr]k_(?:live|test)_[A-Za-z0-9]{16,})"), 0),
]
# A random-looking run of an exact length that keys have: 32, 40 (an AWS secret access key), 43 + "=" and 86 + "==" (a base64 key).
SHAPES = [
    ("a key-length base64 string", re.compile(_B64_EDGE + r"(?:[A-Za-z0-9+/]{32}|[A-Za-z0-9+/]{40}|[A-Za-z0-9+/]{43}=|[A-Za-z0-9+/]{86}==)" + _B64_END), True),
]
WITHHELD_TEXT = "[withheld: %s, %d characters]"
LOCAL = {"paths": 0, "text": 0}


def _random_like(run):
    """A run that looks like random base64 and not like a path, a name or a hash: mixed case and digits in the proportions
    random text has (a long path is mostly lower case with few capitals; a hex digest has no case to mix)."""
    n = len(run)
    upper = sum(1 for ch in run if "A" <= ch <= "Z")
    lower = sum(1 for ch in run if "a" <= ch <= "z")
    digit = sum(1 for ch in run if "0" <= ch <= "9")
    return upper * 100 >= 15 * n and lower * 100 >= 15 * n and digit * 100 >= 5 * n


# What a text must hold for any rule below to match it: a literal one of them looks for, or a run long enough for a shape. A text
# with none of these is judged clean without running the rules (most values of a log: names, ids, times, addresses). Each
# alternative is a necessary condition of at least one rule; tests/pack-cloud-shared.test.ts holds the two paths equal.
_QUICK = re.compile(r"eyJ|-----BEGIN|\n|authorization|cookie|bearer|basic|digest|negotiate|ntlm|pass|pwd|secret|token|key|signature|sig|"
                    r"plaintext|hash|pin|otp|sas|securestring|gh[pousr]_|github_pat_|xox|AIza|ya29\.|1//0|IQoJb|FQoG|FwoG|Q~|[01]\.A|[sr]k_|"
                    r"://|gocspx|functions|code=|"
                    r"[A-Za-z0-9+/]{32}|[A-Za-z0-9+/_-]{128}", re.I)


_CLEAN = set()                    # short texts already judged to hold nothing (names, addresses and ids repeat across a log)
LONG_TEXT = 1 << 16               # a text this long is scanned with the deadline in view


def token_spans(text, shapes=True):
    """(start, end, why) of each stretch of `text` shaped like a credential, in order and not overlapping. `shapes` False leaves
    out the rules that recognise a key by its length alone (a value that is named a checksum or a digest is not scanned for them)."""
    if shapes and text in _CLEAN:
        return []
    spans = _spans(text, shapes) if _QUICK.search(text) else []
    if shapes and not spans and len(text) <= 256 and len(_CLEAN) < 100000:
        _CLEAN.add(text)
    return spans


def _name_before(text, start, at):
    """The letters and digits of the name an assigned value follows (`nextToken=` gives `nexttoken`)."""
    return re.sub(r"[^a-z0-9]", "", text[max(0, at - 64):at].lower())


def _spans(text, shapes=True):
    spans = []
    big = len(text) > LONG_TEXT
    for why, rx, group in TOKEN_RULES:
        if big and out_of_time():
            return [(0, len(text), "text not scanned: the time limit ended the scan")]      # fail closed
        for m in rx.finditer(text):
            if "assigned to a credential name" in why:
                if ARN_TAIL.search(text[max(0, m.start() - 120):m.start()]):
                    continue                              # arn:aws:secretsmanager:...:secret:NAME is a name, not a value
                if _name_before(text, m.start(), m.start(m.lastindex or 0)).endswith(NOT_SECRET_TOKEN):
                    continue                              # nextToken=, pageToken=, clientToken=: a position or an idempotency key
            groups = (1, 2, 3) if group == -1 else ((1, 2) if group == -2 else (group,))
            for g in groups:
                if g and m.group(g) is None:
                    continue
                start, end = m.span(g)
                value = text[start:end]
                if g and (REDACTED.match(value) or value.lower() in NOT_A_VALUE or value.startswith(("${", "{{"))):
                    continue
                if why == "a scheme and its credential" and g == 1 and not (re.search(r"[0-9+/=_.~-]", value) or len(value) >= 16):
                    continue                              # "basic authentication" is prose, "Basic dXNlcjpwYXNz" is not
                if g == 1 and group == -1 and len(m.groups()) >= 2 and m.group(1) in ("'", '"'):
                    continue                              # group 1 of the switch rules is the quote
                spans.append((start, end, why))
    for m in _B64_RUN.finditer(text):
        if _random_like(m.group(0)):
            spans.append((m.start(), m.end(), "a long unbroken base64-like run"))
    if shapes:
        for why, rx, check in SHAPES:
            for m in rx.finditer(text):
                if not check or _random_like(m.group(0)):
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


def scrub(text):
    """`text` with each stretch shaped like a credential replaced by a marker that holds only its length."""
    if not isinstance(text, str) or len(text) < 5:
        return text
    if len(text) > MAX_SCAN_CHARS:
        LOCAL["text"] += 1
        return WITHHELD_TEXT % ("text longer than 1 MiB", len(text))
    spans = token_spans(text)
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


def shown_path(path):
    """A path as it may be printed: a component shaped like a credential (a file named after a token) is withheld."""
    if not isinstance(path, str):
        return path
    parts = path.split("/")
    for i, part in enumerate(parts):
        clean = scrub(part)
        if clean != part:
            parts[i] = clean
            LOCAL["paths"] += 1
    return "/".join(parts)


class Withheld:
    """Cleans values on their way into an answer, counts what was withheld, lists where, and hands the originals to the
    values file when the caller asked for it (write_values, in a job). A row's `locator` says which record it came from.
    `quiet` cleans without recording (for a value that is stored on the way, such as an index entry)."""

    VALUE_KEYS = ("Value", "NewValue", "OldValue", "value", "newValue", "oldValue")
    NAME_KEYS = ("Name", "name", "Key", "key")

    def __init__(self, vault, limit, quiet=False):
        self.vault = vault
        self.quiet = quiet
        self.count = 0
        self.reasons = {}
        self.page = None if quiet else LosslessPage("withheld", limit)

    def note(self, locator, pointer, why, length, original):
        if self.quiet:
            return
        self.count += 1
        self.reasons[why] = self.reasons.get(why, 0) + 1
        fid = "W%06d" % self.count
        shown = {k: (shown_path(v) if k == "file" else v) for k, v in locator.items()}
        self.page.add({"finding_id": fid, **shown, "pointer": scrub(pointer), "why": why, "length": length})
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

    def clean(self, value, locator, pointer="", depth=0, shapes=True):
        if isinstance(value, str):
            return self.clean_text(value, locator, pointer, shapes)
        if depth > MAX_DEPTH and isinstance(value, (dict, list)):
            self.note(locator, pointer, "nested deeper than %d levels" % MAX_DEPTH, len(json.dumps(value, default=str)), value)
            return "[withheld: nested deeper than %d levels, %s]" % (MAX_DEPTH, self.size_of(value))
        if isinstance(value, dict):
            named = None
            for key in self.NAME_KEYS:
                if isinstance(value.get(key), str):
                    named = value[key]
                    break
            pair_secret = named is not None and name_is_sensitive(named)
            out = {}
            for k, v in value.items():
                ks = str(k)
                point = "%s/%s" % (pointer, ks.replace("~", "~0").replace("/", "~1"))
                safe_key = scrub(ks)
                if safe_key in out:
                    safe_key = "%s#%d" % (safe_key, len(out))
                sensitive = name_is_sensitive(ks) or (pair_secret and ks in self.VALUE_KEYS)
                if sensitive and is_container_name(ks) and isinstance(v, (dict, list)):
                    sensitive = False
                if sensitive and v not in (None, "", True, False) and not (isinstance(v, str) and (REDACTED.match(v) or v.lower() in NOT_A_VALUE)):
                    self.note(locator, point, "credential-named field", len(v) if isinstance(v, str) else len(json.dumps(v, default=str)), v)
                    out[safe_key] = "[withheld: credential-named field, %s]" % self.size_of(v)
                else:
                    out[safe_key] = self.clean(v, locator, point, depth + 1, shapes and not CHECKSUM_NAME.search(ks))
            return out
        if isinstance(value, list):
            return [self.clean(v, locator, "%s/%d" % (pointer, i), depth + 1, shapes) for i, v in enumerate(value)]
        return value

    def clean_text(self, text, locator, pointer, shapes=True):
        if len(text) < 5:
            return text
        if len(text) > MAX_SCAN_CHARS:
            self.note(locator, pointer, "text longer than 1 MiB", len(text), text)
            return WITHHELD_TEXT % ("text longer than 1 MiB", len(text))
        spans = token_spans(text, shapes)
        if not spans:
            return text
        out, at = [], 0
        for start, end, why in spans:
            out.append(text[at:start])
            out.append(WITHHELD_TEXT % (why, end - start))
            self.note(locator, "%s@%d" % (pointer, start), why, end - start, text[start:end])
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
    large export does not have to fit in memory. Returns (db, directory, where); in memory only if no directory can be made."""
    try:
        directory = tempfile.mkdtemp(prefix=prefix, dir=os.environ["OUT"] if in_job() else None)
        db = sqlite3.connect(os.path.join(directory, "work.sqlite"))
        os.chmod(os.path.join(directory, "work.sqlite"), 0o600)
        CLEANUP.append(lambda: remove_temp_db(db, directory))
        return db, directory, "a temporary file"
    except (OSError, sqlite3.Error):
        return sqlite3.connect(":memory:"), None, "memory (no temporary directory could be created)"


def remove_temp_db(db, directory):
    try:
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


_DEC = json.JSONDecoder(parse_constant=_no_constant)
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
        directory = stack.pop()
        try:
            with os.scandir(directory) as it:
                entries = sorted(it, key=lambda e: e.name)
        except OSError as exc:
            skipped.append({"path": shown_path(directory), "reason": "the directory could not be listed", "error": describe(exc)})
            continue
        subdirs = []
        for entry in entries:
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
    ends at the deadline (`timed_out`)."""

    def __init__(self, path, cap):
        self.path, self.cap = path, cap
        self.buf, self.pos = "", 0
        self.eof = False
        self.bytes_read = 0
        self.compressed = False
        self.error = None
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
                self.error = "%s: extract it first; it was not read" % kind
                self.eof = True
            elif head[:2] == b"\x1f\x8b":
                self.compressed = True
            self.fh = self._raw
        except OSError as exc:
            self.error = describe(exc)
            self.eof = True

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
                        self.error = "the compressed stream ends early, after %d bytes of expansion: what came before it was read" % (self.bytes_read + got)
                    self._ended = True
                    break
                self._pending = raw
            if self._state == "header":
                buf = self._hdr + self._pending
                try:
                    n = gzip_header_length(buf)
                except ValueError:
                    self.error = "%d bytes follow the end of the compressed stream and are not another member: they were not read" % len(buf)
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
                    self.error = "the compressed stream is damaged after %d bytes of expansion (%s): what came before it was read" % (self.bytes_read + got, exc)
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
                    if crc != self._crc & 0xFFFFFFFF or size != self._isize & 0xFFFFFFFF:
                        self.error = "a member of the compressed stream fails its own check (CRC-32 or length): its bytes were read and may be wrong"
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
            self.error = describe(exc)
            self.eof = True
            data = b""
        if self._first and self.compressed and data[257:262] == b"ustar":
            self.archive = "a tar archive"
            self.error = "a tar archive (gzip-compressed): extract it first; it was not read"
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
                        src.stopped = "a record larger than max_record_bytes at line %d: the rest of the array was not read" % start_line
                        yield "reject", info(start_line, start_off, None, key), "a record larger than max_record_bytes (%d)" % record_cap
                        return
                    except json.JSONDecodeError as exc:
                        if src.timed_out:       # the deadline cut the record, the JSON is not damaged
                            src.stopped = "the time limit ended the read"
                            yield "reject", info(start_line, start_off, None, key), "the last record is cut off where the read ended (the time limit)"
                            return
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


def csv_lines(src):
    """The lines of a CSV file, newline kept, one at a time (a quoted field may span several)."""
    while True:
        i = src.buf.find("\n", src.pos)
        while i < 0 and not src.eof and len(src.buf) - src.pos <= MAX_FIELD_BYTES:
            src.fill()
            i = src.buf.find("\n", src.pos)
        if i < 0 and src.pos >= len(src.buf):
            return
        end = i + 1 if i >= 0 else len(src.buf)
        if end - src.pos > MAX_FIELD_BYTES:
            raise TooLong()
        line = src.buf[src.pos:end]
        src.advance(end)
        yield line


def csv_rows(src, delimiter, field_limit):
    """Yield ("row", info, dict) / ("reject", info, reason) for a CSV file; a bad row is rejected and the next is read; a failure
    of the reader itself stops the file, says where, and keeps what was read. A header name that repeats keeps every column
    (the second is `name#2`)."""
    src.mode, src.stopped, src.extra_keys, src.envelope, src.header = "csv", None, [], None, None
    csv.field_size_limit(field_limit)
    reader = csv.reader(csv_lines(src), delimiter=delimiter)
    header, count = None, 0
    while True:
        before = reader.line_num
        try:
            row = next(reader)
        except StopIteration:
            break
        except TooLong:
            src.stopped = "a line longer than %d characters at line %d: the rest of the file was not read" % (MAX_FIELD_BYTES, before + 1)
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

TOOL = "ual_parse"
PARSER = "ual_parse/4"
VALUES_NAME = "ual-values.jsonl"
ENVELOPE_KEYS = ("value", "Records", "items")
AUDIT_KEYS = ("AuditData", "auditData")
OUTER_TIME = ("CreationDate", "CreationTime", "createdDateTime")
NATIVE_KEYS = ("Operation", "Workload", "RecordType", "CreationTime", "UserId", "Id")

# What the tool lists for a second look: the operation name only. A record is not a human act and not a proof of an effect.
NOTABLE = {
    "New-InboxRule": "an inbox rule creation record",
    "Set-InboxRule": "an inbox rule change record",
    "UpdateInboxRules": "an inbox rules change record from a client",
    "Set-Mailbox": "a mailbox settings change record (the changed properties say which: forwarding settings are among them)",
    "Add-MailboxPermission": "a mailbox permission grant record",
    "Add-RecipientPermission": "a recipient permission (send-as) grant record",
    "MailItemsAccessed": "a mailbox item access record (what it means is in MailAccessType, OperationCount and Folders; it is not a statement that content was read)",
    "Send": "a mail send record",
    "SendAs": "a mail send-as record",
    "Consent to application": "an application consent record (the grant's scope is in the properties)",
    "Add service principal.": "a service principal creation record (not by itself a consent or a permission)",
    "Add app role assignment grant to user.": "an app role assignment record",
    "Add member to role.": "a role membership change record",
    "AnonymousLinkCreated": "an anonymous link creation record",
    "SharingSet": "a sharing change record (who or what it shared with is in the properties)",
    "AddedToSecureLink": "a record that someone was added to a sharing link",
    "FileSyncDownloadedFull": "a full library sync download record",
    "FileDownloaded": "a file download record",
    "UserLoggedIn": "a sign-in record",
    "UserLoginFailed": "a failed sign-in record",
    "Update user.": "an account change record",
    "Reset user password.": "a password reset record",
    "Disable Strong Authentication.": "a record that strong authentication was disabled for an account",
}
ARGS = frozenset(("path", "operations", "user", "since", "until", "record_type", "notable_only", "assume_utc", "date_order", "format", "delimiter",
                  "max_field_bytes", "out_file", "limit", "max_expanded_bytes", "max_record_bytes", "time_limit_seconds", "write_values"))


def interpret(item):
    """(audit dict or None, outer dict, payload status, detail) for one record, or (None, None, None, reason) when it has no
    audit payload and is not itself an audit event."""
    if not isinstance(item, dict):
        return None, None, None, "a JSON %s, not a record" % type(item).__name__
    keys = key_map(item)
    audit_key = keys.get("auditdata")
    if audit_key is not None:
        outer = {k: v for k, v in item.items() if k != audit_key}
        value = item[audit_key]
        if isinstance(value, dict):
            return value, outer, "object", None
        if isinstance(value, str) and value.strip():
            try:
                parsed = loads_strict(value)
            except (ValueError, RecursionError) as exc:
                return None, outer, "invalid_json", "AuditData is not valid JSON (%s)" % getattr(exc, "msg", type(exc).__name__)
            if isinstance(parsed, dict):
                return parsed, outer, "json_text", None
            return None, outer, "not_an_object", "AuditData is JSON %s, not an object" % type(parsed).__name__
        if value in (None, ""):
            return None, outer, "absent", "AuditData is empty"
        return None, outer, "not_an_object", "AuditData is a %s, not JSON text or an object" % type(value).__name__
    if "operation" in keys or ("creationtime" in keys and ("workload" in keys or "userid" in keys)):
        return item, {}, "native", None
    return None, None, None, "neither an AuditData payload nor a native audit event (no Operation, or CreationTime with Workload or UserId)"


def lifted(audit, outer, o_keys):
    """The fields lifted out of the payload, the outer columns filling what the payload lacks. The record type is kept as the
    payload writes it (a number) and as the outer column writes it (a name), beside each other: an export carries one, the
    other or both, and a filter matches either."""
    a = audit or {}

    def pick(audit_names, *outer_names):
        for n in audit_names:
            if a.get(n) not in (None, ""):
                return a[n]
        return first_of(outer, o_keys, *outer_names)

    payload_type = a.get("RecordType") if a.get("RecordType") not in (None, "") else None
    outer_type = first_of(outer, o_keys, "RecordType", "auditLogRecordType")
    out = {
        "operation": pick(("Operation",), "Operation", "Operations"),
        "user": pick(("UserId",), "UserId", "UserIds", "userPrincipalName"),
        "address": pick(("ClientIP", "ClientIPAddress", "ActorIpAddress"), "ClientIP", "clientIp"),
        "workload": pick(("Workload",), "Workload", "service"),
        "record_type": payload_type if payload_type is not None else outer_type,
        "record_type_outer": outer_type if payload_type is not None and outer_type is not None else None,
        "result": pick(("ResultStatus",), "ResultStatus"),
        "record_id": pick(("Id",), "Id", "RecordId"),
        "object": a.get("ObjectId"), "user_agent": a.get("UserAgent"), "client": a.get("ClientInfoString"),
        "site": a.get("SiteUrl"), "file": a.get("SourceFileName"), "user_type": a.get("UserType"),
        "organization_id": a.get("OrganizationId"),
    }
    differs = {}
    for field, audit_names, outer_names in (("operation", ("Operation",), ("Operation", "Operations")), ("user", ("UserId",), ("UserId", "UserIds")),
                                            ("record_id", ("Id",), ("Id", "RecordId"))):
        mine = next((a[n] for n in audit_names if a.get(n) not in (None, "")), None)
        theirs = first_of(outer, o_keys, *outer_names)
        if mine is not None and theirs is not None and str(mine) != str(theirs):
            differs[field] = {"payload": mine, "outer_column": theirs}
    if differs:
        out["outer_differs"] = differs
    access = []
    for group in ("OperationProperties", "ExtendedProperties", "Parameters", "ModifiedProperties"):
        items = a.get(group)
        if isinstance(items, list):
            access.extend(i.get("Value", i.get("NewValue")) for i in items if isinstance(i, dict) and i.get("Name") == "MailAccessType")
    if access:
        out["mail_access_type"] = access
    folders = a.get("Folders")
    if isinstance(folders, list):
        out["items_accessed"] = sum(len(f.get("FolderItems") or []) for f in folders if isinstance(f, dict) and isinstance(f.get("FolderItems") or [], list))
    if a.get("OperationCount") not in (None, ""):
        out["operation_count"] = a["OperationCount"]
    return out


def norm_type(value):
    """A record type as compared: without white space or case, and a number without leading zeros ("015" and " 15" are 15)."""
    text = str(value).strip().lower()
    return str(int(text)) if text.isdigit() else text


def type_forms(fields):
    """The forms a record's type can be asked for by: the payload's value and the outer column's, as text, lower case."""
    return {norm_type(v) for v in (fields.get("record_type"), fields.get("record_type_outer")) if v is not None}


def time_candidates(audit, outer, o_keys):
    """(raw, source) pairs: the payload's CreationTime first, then the outer column."""
    found = []
    if audit and isinstance(audit.get("CreationTime"), str):
        found.append((audit["CreationTime"], "AuditData.CreationTime"))
    raw = first_of(outer, o_keys, *OUTER_TIME)
    if raw is not None:
        found.append((raw, "outer column"))
    return found


def choose_time(cands, order, assume_utc):
    """The first candidate that carries its own zone, else the first read as UTC on the caller's say-so, else the first."""
    parsed = [(raw, source, parse_stamp(raw, order, assume_utc)) for raw, source in cands]
    for wanted in ("zoned", "assumed_utc"):
        for raw, source, st in parsed:
            if st["status"] == wanted:
                return raw, source, st
    return parsed[0] if parsed else (None, None, parse_stamp(None))


class Census:
    def __init__(self, limit):
        self.files = LosslessPage("file_census", limit)
        self.rejected = RejectLog(LosslessPage("rejected_records", limit))
        self.problems = []
        self.conventions = []
        self.pagination = []
        self.cut = False
        self.counts = {"files_found": 0, "files_read": 0, "files_partial": 0, "files_failed": 0, "files_unsupported": 0,
                       "files_empty": 0, "files_skipped": 0, "files_not_attempted": 0, "rows_read": 0, "rows_rejected": 0,
                       "payloads_rejected": 0, "replacement_characters": 0, "bytes_read": 0}

    def problem(self, text):
        if len(self.problems) < FIRST_PROBLEMS:
            self.problems.append(scrub(text))


def open_rows(path, fmt_arg, delimiter, max_expanded, field_limit, record_cap=MAX_RECORD_BYTES):
    """(source, row iterator, format, basis) for one file; the format comes from its content, and one the caller names that the
    content contradicts is refused."""
    seen = sniff(path)
    if fmt_arg != "auto" and fmt_arg != seen:
        fail("format %s was asked for, and the content of %s reads as %s" % (fmt_arg, shown_path(path), seen), path=shown_path(path))
    src = Source(path, max_expanded)
    if seen == "json":
        return src, read_units(src, ENVELOPE_KEYS, record_cap, MAX_DOCUMENT_BYTES), seen, "the content" if fmt_arg == "auto" else "the format argument, and the content agrees"
    return src, csv_rows(src, delimiter, field_limit), seen, "the content" if fmt_arg == "auto" else "the format argument, and the content agrees"


def detect_order(path, fmt_arg, delimiter, max_expanded, field_limit, record_cap):
    """What a file's own unambiguous day/month/year strings prove about its date order, from the outer time columns only:
    'dmy', 'mdy', 'contradictory' or None (no unambiguous row). A string counts only if read that way it is a real date.
    One pass, with no payload opened."""
    seen = {"dmy": 0, "mdy": 0}
    src, rows, fmt, _ = open_rows(path, fmt_arg, delimiter, max_expanded, field_limit, record_cap)
    try:
        for kind, info, row in rows:
            if out_of_time():
                break
            if kind != "row" and kind != "item" or not isinstance(row, dict):
                continue
            keys = key_map(row)
            raw = first_of(row, keys, *OUTER_TIME)
            got = proven_order(raw) if isinstance(raw, str) else None
            if got in seen:
                seen[got] += 1
    finally:
        src.close()
    if seen["dmy"] and seen["mdy"]:
        return "contradictory", seen
    if seen["dmy"] or seen["mdy"]:
        return ("dmy" if seen["dmy"] else "mdy"), seen
    return None, seen


def main():
    install_signal_handlers()
    args = read_args()
    refuse_unknown(args, ARGS)
    path = want_str(args, "path", "path is required: a unified audit log export, or a directory of them")
    if os.path.islink(path) and not os.path.exists(path):
        fail("the path is a link that does not lead to a file (a loop or a missing target)", path=shown_path(path))
    if not os.path.exists(path):
        fail("no such file or directory", path=shown_path(path))
    limit = want_int(args, "limit", DEFAULT_LIMIT)
    out_file = want_str(args, "out_file")
    wanted_ops = {o.strip().lower(): o for o in want_str_list(args, "operations")}          # compared without case, reported as given
    record_types = {norm_type(t): t for t in want_str_list(args, "record_type")}
    pattern = want_regex(args, "user")
    notable_only = want_bool(args, "notable_only")
    assume_utc = want_bool(args, "assume_utc")
    date_order = want_str(args, "date_order")
    if date_order is not None and date_order not in ("mdy", "dmy"):
        fail("date_order must be mdy or dmy")
    fmt_arg = want_str(args, "format") or "auto"
    if fmt_arg not in ("auto", "csv", "json"):
        fail("format must be auto, csv or json")
    delimiter = want_str(args, "delimiter") or ","
    if len(delimiter) != 1:
        fail("delimiter must be one character")
    max_expanded = want_int(args, "max_expanded_bytes", MAX_EXPANDED_BYTES, 1024)
    record_cap = want_int(args, "max_record_bytes", MAX_RECORD_BYTES, 1024, 1 << 30)
    field_limit = want_int(args, "max_field_bytes", MAX_FIELD_BYTES, 1024, MAX_FIELD_BYTES)
    write_values = want_bool(args, "write_values")
    seconds = start_clock(args)
    since = until = None
    for key in ("since", "until"):
        if args.get(key) is not None:
            text = want_str(args, key)
            st = parse_stamp(text, None, True)
            if st["ns"] is None:
                fail("%s must be ISO 8601, e.g. 2026-02-14T00:00:00Z" % key, value=text)
            if key == "since":
                since = st["ns"]
            else:
                until = st["ns"]
    if out_file is not None:
        out_file = resolve_output(out_file, "out_file")
    try:
        vault = SecretValues(write_values, VALUES_NAME, TOOL)
    except SecretValuesRefused as exc:
        fail(str(exc), write_values="refused", written=False)

    skipped = Skips()
    if os.path.isdir(path):
        targets = walk_inputs(path, lambda n: n.lower().endswith((".csv", ".json", ".jsonl", ".ndjson", ".csv.gz", ".json.gz", ".jsonl.gz", ".ndjson.gz")), skipped)
        if not targets:
            fail("no CSV or JSON export there", path=shown_path(path), skipped=named(skipped.items))
    elif os.path.isfile(path):
        targets = [path]
    else:
        fail("the path is neither a regular file nor a directory: it is not opened", path=shown_path(path))

    census = Census(limit)
    census.counts["files_found"] = len(targets)
    census.counts["files_skipped"] = skipped.total
    withheld = Withheld(vault, limit)
    complete_target = LosslessPage(TOOL, limit, dest=out_file or None)
    by_operation_all, by_operation, by_user, by_address, by_types = Tally(), Tally(), Tally(), Tally(), Tally()
    matched = excluded_unknown_time = 0
    first_ns = last_ns = None
    time_statuses = {}
    ops_hit, types_hit = set(), set()
    not_attempted = []
    stop_all = False

    try:
        for n, target in enumerate(targets):
            if out_of_time():
                stop_all = True
                not_attempted = targets[n:]
                break
            shown = shown_path(target)
            row = {"file": shown, "status": "read", "format": None, "compressed": False, "records": 0, "rejected": 0, "payloads_rejected": 0, "bytes_read": 0}
            try:
                src, rows, fmt, basis = open_rows(target, fmt_arg, delimiter, max_expanded, field_limit, record_cap)
            except OSError as exc:
                row.update({"status": "failed", "problems": [describe(exc)]})
                census.counts["files_failed"] += 1
                census.problem("%s: %s" % (shown, describe(exc)))
                census.files.add(row)
                continue
            census.rejected.start_file()
            order = {"value": date_order, "basis": "declared" if date_order else None, "tried": False, "seen": None, "contradicted": 0}
            result_count = max_index = None
            records = rejected = payload_bad = 0
            first_reject = None
            stopped_all_rejected = False
            try:
                for kind, info, item in rows:
                    if out_of_time():
                        src.timed_out = True
                        break
                    locator = {"file": target, "record": info["record"], "line": info["line"]}
                    if kind == "reject" or (kind != "reject" and not isinstance(item, dict)):
                        reason = item if kind == "reject" else "a JSON %s, not a record" % type(item).__name__
                        rejected += 1
                        first_reject = first_reject or (info["record"], info["line"], reason)
                        if census.rejected.reject({"file": shown, "record": info["record"], "line": info["line"], "reason": scrub(reason)}):
                            stopped_all_rejected = True
                            break
                        continue
                    audit, outer, payload_status, detail = interpret(item)
                    if payload_status is None:
                        rejected += 1
                        first_reject = first_reject or (info["record"], info["line"], detail)
                        if census.rejected.reject({"file": shown, "record": info["record"], "line": info["line"], "reason": detail}):
                            stopped_all_rejected = True
                            break
                        continue
                    records += 1
                    census.rejected.accept()
                    census.counts["rows_read"] += 1
                    o_keys = key_map(outer)
                    if payload_status in ("invalid_json", "not_an_object", "absent"):
                        payload_bad += 1
                        census.counts["payloads_rejected"] += 1
                        census.rejected.note({"file": shown, "record": info["record"], "line": info["line"], "reason": detail, "kind": "payload"})
                    rc, ri = first_of(outer, o_keys, "ResultCount"), first_of(outer, o_keys, "ResultIndex")
                    try:
                        result_count = max(result_count or 0, int(rc)) if rc is not None else result_count
                        max_index = max(max_index or 0, int(ri)) if ri is not None else max_index
                    except (TypeError, ValueError):
                        pass
                    cands = time_candidates(audit, outer, o_keys)
                    raw, source, st = choose_time(cands, order["value"], assume_utc)
                    if st["status"] == "ambiguous_date_order" and not order["tried"]:
                        order["tried"] = True
                        found, seen = detect_order(target, fmt_arg, delimiter, max_expanded, field_limit, record_cap)
                        order["seen"] = seen
                        if found in ("dmy", "mdy"):
                            order["value"], order["basis"] = found, "detected from %d unambiguous rows and none that contradict it" % seen[found]
                        elif found == "contradictory":
                            order["basis"] = "contradictory: %d rows are only day/month and %d only month/day" % (seen["dmy"], seen["mdy"])
                        else:
                            order["basis"] = "no unambiguous row in this file"
                        raw, source, st = choose_time(cands, order["value"], assume_utc)
                    if order["value"] and st["status"] == "unparseable" and "contradicts date_order" in st["basis"]:
                        order["contradicted"] += 1
                    time_statuses[st["status"]] = time_statuses.get(st["status"], 0) + 1
                    if st["ns"] is not None:
                        first_ns = st["ns"] if first_ns is None else min(first_ns, st["ns"])
                        last_ns = st["ns"] if last_ns is None else max(last_ns, st["ns"])
                    fields = lifted(audit, outer, o_keys)
                    operation = fields.get("operation")
                    operation = scrub(operation) if isinstance(operation, str) else (scrub(str(operation)) if operation is not None else "?")
                    by_operation_all.add(operation)
                    forms = type_forms(fields)
                    by_types.add((scrub(str(fields.get("record_type"))) if fields.get("record_type") is not None else None,
                                  scrub(str(fields.get("record_type_outer"))) if fields.get("record_type_outer") is not None else None))
                    note = NOTABLE.get(operation)
                    # every filter looks at the text as it will be printed, never at a value that is withheld
                    shown_user = scrub(str(fields.get("user") or ""))
                    if wanted_ops and operation.strip().lower() in wanted_ops:
                        ops_hit.add(operation.strip().lower())
                    types_hit.update(record_types.keys() & forms)
                    if wanted_ops and operation.strip().lower() not in wanted_ops:
                        continue
                    if notable_only and not note:
                        continue
                    if record_types and not (record_types.keys() & forms):
                        continue
                    if pattern and not hits(pattern, shown_user):
                        continue
                    if since is not None or until is not None:
                        if st["ns"] is None:
                            excluded_unknown_time += 1
                            continue
                        if (since is not None and st["ns"] < since) or (until is not None and st["ns"] > until):
                            continue
                    entry = {
                        "time": raw, "time_utc": st["utc"], "time_status": st["status"], "time_source": source,
                        **fields,
                        "payload_status": payload_status,
                    }
                    if outer:
                        entry["outer_columns"] = outer
                    if audit is not None:
                        entry["audit_data"] = audit
                    if note:
                        entry["notable"] = note
                    entry = withheld.clean(entry, locator, "")
                    entry.update({"source_file": shown, "record": info["record"], "line": info["line"], "parser": PARSER})
                    matched += 1
                    by_operation.add(operation)
                    if fields.get("user"):
                        by_user.add(shown_user)
                    if fields.get("address"):
                        by_address.add(scrub(str(fields["address"])))
                    complete_target.add(compact(entry))
            finally:
                src.close()
            stopped_early = src.timed_out
            if order["value"] or order["tried"]:
                census.conventions.append({"file": shown, "date_order": order["value"], "basis": order["basis"]})
            problems = []
            markers = [k for k in getattr(src, "extra_keys", []) if pagination_key(k)]
            if markers:
                census.pagination.append({"file": shown, "keys": markers})
                row["pagination_marker_keys"] = markers
            if result_count is not None and (records < result_count or (max_index is not None and max_index < result_count)):
                census.pagination.append({"file": shown, "keys": ["ResultCount"], "result_count": result_count, "rows": records, "highest_result_index": max_index})
                problems.append("the export's own ResultCount says %d records matched the search; this file holds %d (the highest ResultIndex is %s): the search was not exported whole" % (
                    result_count, records, max_index))
            if src.error:
                problems.append(src.error)
            if src.capped:
                problems.append("the expansion reached max_expanded_bytes (%d): the rest of the file was not read" % max_expanded)
            if getattr(src, "stopped", None):
                problems.append(src.stopped)
            if stopped_all_rejected:
                problems.append("the first %d records were all rejected: this is not an export this tool reads, and the rest of the file was not examined" % FIRST_REJECTS)
            if rejected:
                problems.append("%d record(s) were not read as audit records (the first, record %d at line %s: %s); %s" % (
                    rejected, first_reject[0], first_reject[1], first_reject[2],
                    "every one is in rejected_records" if not census.rejected.total_unlisted else "the first %d of this file are in rejected_records" % LIST_REJECTS))
            if payload_bad:
                problems.append("%d record(s) have no readable AuditData payload (kept with their outer columns; listed in rejected_records)" % payload_bad)
            if order["contradicted"]:
                problems.append("date_order %s was declared and %d row(s) of this file can only be read the other way round: they were not decoded" % (order["value"], order["contradicted"]))
            if src.replaced:
                problems.append("%d byte(s) were not valid %s and were replaced; the records they sit in are not exact" % (src.replaced, src.encoding.upper()))
            census.cut = census.cut or bool(src.error or src.capped or getattr(src, "stopped", None) or stopped_early or stopped_all_rejected)
            row.update({"format": fmt, "format_basis": basis, "compressed": src.compressed, "encoding": src.encoding, "records": records, "rejected": rejected,
                        "payloads_rejected": payload_bad, "bytes_read": src.bytes_read, "shape": getattr(src, "mode", None)})
            if stopped_early:
                row["status"] = "partial"
            elif src.archive:
                row["status"] = "unsupported"
                row["archive"] = src.archive
            elif src.bytes_read == 0 and not src.error:
                row["status"] = "empty"
            elif records == 0 and src.error:
                row["status"] = "failed"
            elif records == 0 and (rejected or problems):
                row["status"] = "unsupported"
            elif records == 0 and getattr(src, "mode", "empty") in ("empty",):
                row["status"] = "empty"
            elif records == 0 and not rejected and getattr(src, "header", True) is None:
                row["status"] = "empty"       # a file of nothing but white space has no header and no rows
            elif problems:
                row["status"] = "partial"
            if problems:
                row["problems"] = [scrub(p) for p in problems]
            if src.replaced:
                row["replacement_characters"] = src.replaced
            if order["value"] or order["tried"]:
                row["date_order"] = order["value"]
                row["date_order_basis"] = order["basis"]
            census.counts["replacement_characters"] += src.replaced
            census.counts["bytes_read"] += src.bytes_read
            census.counts["rows_rejected"] += rejected
            census.counts[{"read": "files_read", "partial": "files_partial", "failed": "files_failed", "unsupported": "files_unsupported", "empty": "files_empty"}[row["status"]]] += 1
            if row["status"] != "read":
                census.problem("%s: %s" % (shown, "; ".join(row.get("problems", [])) or row["status"]))
            census.files.add(row)
            if stopped_early:
                stop_all = True
                not_attempted = targets[n + 1:]
                break
    finally:
        vault.close()

    census.counts["files_not_attempted"] = len(not_attempted)
    records_cut = bool(stop_all or census.cut or not_attempted)
    pages = {"records": complete_target.finish(partial=records_cut), "file_census": census.files.finish(), "rejected_records": census.rejected.page.finish()}
    withheld_summary = withheld.summary()
    tables = {}
    for name, tally in (("by_operation", by_operation), ("by_user", by_user), ("by_address", by_address), ("operations_all_rows", by_operation_all)):
        page = LosslessPage(TOOL + "-" + name, limit)
        for r in tally.rows():
            page.add(r)
        pages[name] = page.finish()
        tables[name] = page.page
    type_page = LosslessPage(TOOL + "-record_types", limit)
    for (payload_value, outer_value), count in sorted(by_types.counts.items(), key=lambda kv: (-kv[1], str(kv[0]))):
        type_page.add({"audit_data": payload_value, "outer_column": outer_value, "count": count})
    pages["record_types_all_rows"] = type_page.finish()
    c = census.counts
    ambiguous = time_statuses.get("ambiguous_date_order", 0)
    no_zone = time_statuses.get("no_zone", 0)
    unmatched = {"operations": sorted(v for k, v in wanted_ops.items() if k not in ops_hit), "record_type": sorted(v for k, v in record_types.items() if k not in types_hit)}
    complete = (not stop_all and c["files_partial"] == c["files_failed"] == c["files_unsupported"] == c["files_empty"] == 0
                and c["rows_rejected"] == 0 and c["payloads_rejected"] == 0 and not skipped.unreadable and c["files_not_attempted"] == 0
                and c["replacement_characters"] == 0 and not census.pagination and not excluded_unknown_time)
    nothing_read = c["rows_read"] == 0
    status = status_of(nothing_read and (c["files_failed"] or c["files_unsupported"] or c["files_empty"] or c["files_not_attempted"]), complete,
                       "every row of every supplied file was read and nothing was left out; that says nothing about whether the export holds everything the tenant logged",
                       "some of what was supplied was not read as audit records or not read at all, an export names a next page or says it holds fewer records than matched, or a time filter excluded "
                       "rows whose time could not be read (see coverage, file_census, rejected_records, file_problems, skipped, pagination_markers)",
                       "no audit record could be read from what was supplied (see file_problems)")
    answer = {
        "parser": PARSER, **status, "path": shown_path(path),
        "coverage": {**c, "time_limit_seconds": seconds, "stopped_by_time_limit": stop_all, "max_expanded_bytes": max_expanded,
                     "records_matched": matched, "excluded_for_unreadable_time": excluded_unknown_time, "time_statuses": time_statuses,
                     "rejected_records_not_listed": census.rejected.total_unlisted},
        "files": len(targets), "rows_read": c["rows_read"], "unreadable_audit_data": c["payloads_rejected"],
        "file_census": census.files.page, "rejected_records": census.rejected.page.page,
        "file_problems": census.problems,
        "files_not_attempted_named": [shown_path(p) for p in not_attempted[:FIRST_PROBLEMS]],
        "skipped": named(skipped.items), "skipped_count": skipped.total, "skipped_by_name_count": skipped.by_name,
        "pagination_markers": named(census.pagination), "pagination_marker_count": len(census.pagination),
        "date_conventions": named(census.conventions), "date_convention_count": len(census.conventions),
        "date_convention": ("ambiguous: %d rows could not be dated (day/month or month/day) and no date_order was declared or proved" % ambiguous) if ambiguous else
                           ("declared: %s" % date_order if date_order else
                            ("proved by the files' own unambiguous rows: see date_conventions" if census.conventions else "not needed: no day/month/year string was met")),
        "time_zone": ({"rows_without_a_zone": no_zone, "note": "These rows carry a time with no zone and were not decoded. If the schema or the collection record you hold documents "
                                                                "these times as UTC, run again with assume_utc: true; a since or until filter excludes them until then."} if no_zone else None),
        "filter_values_that_matched_no_row": {k: v for k, v in unmatched.items() if v} or None,
        "records": complete_target.page, "record_count": matched, "records_inline": len(complete_target.page),
        ("partial_records" if records_cut else "complete_records"): pages["records"].get("all_results"),
        "records_file_status": ("partial: the read ended early or part of an input was not read (see status)" if records_cut else "holds every matched record that was read"),
        "first_record": ns_to_utc(first_ns), "last_record": ns_to_utc(last_ns),
        "table_scope": "by_operation, by_user and by_address describe the records that matched the filters; operations_all_rows and record_types_all_rows are every row read; first_record and last_record cover every row read whose time could be read",
        "by_operation": tables["by_operation"], "by_user": tables["by_user"], "by_address": tables["by_address"],
        "operations_all_rows": tables["operations_all_rows"], "record_types_all_rows": type_page.page,
        "inline_limited": pages["records"]["truncated"],
        "tables_uncounted": {"by_operation": by_operation.uncounted, "by_user": by_user.uncounted, "by_address": by_address.uncounted, "operations_all_rows": by_operation_all.uncounted,
                             "note": "distinct values past %d are counted here and not in the tables; every record is in the whole-result file" % MAX_DISTINCT},
        "values_withheld": {"count": withheld_summary["count"], "by_reason": withheld_summary["by_reason"], "locators": withheld_summary["locators"],
                            "page": withheld_summary["page"], "text_withheld_from_paths_and_messages": withheld_summary["text_withheld_from_paths_and_messages"]},
        "secret_values": vault.summary(),
        "sensitive_output": {"payloads_inline": True, "withholding": "by field name and by shape only; other secrets are not recognised",
                             "advice": "run this tool as a job with secret_output: true when the export may hold parameters or properties"},
        "pages": pages,
        "truncated": any(p["truncated"] for p in pages.values()),
        "note": "The flagged operations are names this tool lists for a second look, not detections: each is also what an administrator does on an ordinary day. "
                "A record is not a human act; MailItemsAccessed is not a statement that anyone read the content (audit_data keeps MailAccessType, "
                "OperationCount and Folders as the export wrote them). The record Id is what lets someone find the row again; a record without one has no record_id field and is cited by its file, record and line. "
                "Overlapping searches repeat records and this tool keeps every copy: count distinct record Id. "
                "Aggregation and duplicate suppression can apply to some operations: check the documentation for the schema the export carries before treating a quiet "
                "period as absence. A filter looks at the text as it is printed; a record_type is matched against the payload's value and the outer column's.",
    }
    if answer["time_zone"] is None:
        del answer["time_zone"]
    if answer["filter_values_that_matched_no_row"] is None:
        del answer["filter_values_that_matched_no_row"]
    if status["status"] == "failed":
        answer["error"] = "no audit record could be read from what was supplied"
    print(json.dumps(answer, indent=2, default=str, allow_nan=False))
    if status["status"] == "failed":
        raise SystemExit(1)


if __name__ == "__main__":
    try:
        main()
    except SystemExit:
        raise
    except Exception as exc:  # never an empty or clean answer for a failure
        fail("unexpected failure: %s: %s" % (type(exc).__name__, scrub(str(exc))))
