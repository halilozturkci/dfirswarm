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
`ual-values.jsonl` under $OUT (mode 0600, created first) only when `write_values: true` is asked, in a job run as
secret output (the manifest makes a job with write_values one; otherwise it is refused and nothing is written). A name and a shape recognise some secrets and never all.
"""

# BEGIN SHARED ENDS
# The same text is in every pack tool and recipe and in their tool-library twins, before the file's own imports (tests/shared-blocks-census.test.ts
# holds the copies equal): the two ends of a call, where a stop signal (SIGTERM, SIGINT, SIGHUP) found no handler, or one that did harm.
# * The start. From here a stop is answered by ONE JSON document and exit 128 + the signal, until the tool installs its own handlers (which then
#   answer it), and for good for a signal the tool never takes. Only the start of the interpreter and the compiling of the file come before
#   it: a stop there ends the process with no answer, before anything was read. answer_a_stop() is that document: a handler whose own last word
#   wrote nothing on standard output calls it before it ends the process, so that a stop is never answered by silence.
# * The end. The interpreter's own teardown resets the handlers to their defaults before it frees what the call held, and a stop that landed
#   there killed a process that had printed its whole answer; a handler that raises, writes a last word or ends the process, run once the
#   answer was decided, wrote a second document, a traceback, or nothing at all. Python runs a handler on the main thread whichever thread the
#   signal reached, so a mask of the main thread alone holds nothing while another thread runs. hold_stop_signals() holds the stop signals for
#   good: blocked in this thread and given a handler that does nothing, which is the hold whatever thread the signal reaches; an error Python
#   can only report from then on (a file left open whose last write the file system refuses, closed when the frame that held it is freed) is
#   not printed (3.11 and 3.12 say nothing of it, 3.14 a traceback). A handler that was due runs on the way in, and never raises out of it.
#   Every writer of a final answer calls it before it commits to writing, every error branch at the end calls it, and, when the file runs as
#   a program, standard output is wrapped so that its first write calls it too. _code(stop) is a SystemExit's exit code (its text, if it has
#   one, goes to standard error as the interpreter puts it), and _leave(code) ends the call: both hold the signals first; _leave flushes
#   standard output (a write that fails there makes a 0 an exit 120, as the interpreter does) and standard error, runs the atexit hooks (a hook
#   that removes a temporary file), each step on its own and none able to raise, and ends the process with os._exit, never through the teardown.
# The modules are imported here, as the file is loaded, never inside the ending (an import there ran a due handler inside the import system).
import atexit
import json
import os
import signal
import sys

_ENDING = {"held": False}
_ENDING_SIGNALS = (signal.SIGTERM, signal.SIGINT, signal.SIGHUP)


def answer_a_stop(signum, when="before it had answered"):
    """The one document of a stop that ends the call before any answer was begun (nothing once one has): status failed, interrupted, and
    no claim about what was read or written. A handler whose own last word printed nothing calls it before it ends the process."""
    if _ENDING["held"]:
        return
    _ENDING["held"] = True
    name = {signal.SIGTERM: "SIGTERM", signal.SIGINT: "SIGINT", signal.SIGHUP: "SIGHUP"}.get(signum, "signal %d" % signum)
    text = json.dumps({"error": "the tool was stopped by %s %s" % (name, when), "status": "failed", "interrupted": name,
                       "status_basis": "stopped by %s %s: no answer was made, and what it had read or written by then is not described" % (name, when)})
    try:
        os.write(1, (text + "\n").encode("ascii"))
    except OSError:
        pass


def _stopped_without_handler(signum, _frame):
    for other in _ENDING_SIGNALS:
        try:
            signal.signal(other, signal.SIG_IGN)
        except (ValueError, OSError):
            pass
    answer_a_stop(signum, "while it was being loaded, or at a point where it has no stop handling of its own")
    os._exit(128 + signum)


def _ending_nothing(*_ignored):
    """The stop signals' handler, and sys.unraisablehook, once the answer has begun: nothing."""


def hold_stop_signals():
    """Hold the stop signals for good. Never raises. Called by a thread that is not the main one, it blocks them there and leaves the rest to
    the main thread's next call."""
    for _attempt in range(len(_ENDING_SIGNALS) + 2):
        if _ENDING["held"]:
            return
        try:
            try:
                signal.pthread_sigmask(signal.SIG_BLOCK, _ENDING_SIGNALS)
            except (AttributeError, ValueError, OSError):
                pass                  # no pthread_sigmask here: the handler below is the hold
            main_thread = True
            for signum in _ENDING_SIGNALS:
                try:
                    signal.signal(signum, _ending_nothing)
                except (ValueError, OSError):
                    main_thread = False
            sys.unraisablehook = _ending_nothing
            _ENDING["held"] = main_thread
            return
        except BaseException:  # noqa: BLE001 - a handler that was due ran on the way in (and raised): the hold is made again
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
    hold_stop_signals()
    code = getattr(stop, "code", 1)
    if isinstance(code, int):
        return code
    if code is not None:
        try:
            sys.stderr.write("%s\n" % (code,))
        except BaseException:  # noqa: BLE001
            pass
    return 0 if code is None else 1


def _leave(code):
    hold_stop_signals()
    code = code if isinstance(code, int) else 1
    try:
        sys.stdout.flush()
    except BaseException:  # noqa: BLE001 - a reader that is gone: the answer did not reach it
        code = code or 120
    try:
        sys.stderr.flush()
    except BaseException:  # noqa: BLE001
        pass
    try:
        atexit._run_exitfuncs()
    except BaseException:  # noqa: BLE001 - a hook that fails is not a failure of the answer
        pass
    os._exit(code)


if __name__ == "__main__":
    for _signum in _ENDING_SIGNALS:
        signal.signal(_signum, _stopped_without_handler)
    if sys.stdout is not None and not isinstance(sys.stdout, _AnswerStream):
        sys.stdout = _AnswerStream(sys.stdout)
# END SHARED ENDS


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
    hold_stop_signals()
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
    answer_a_stop(signum)
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

TOOL = "ual_parse"
# The label moves when what a record says changes (docs/packs.md, 'A tool's version and its PARSER label'). 4: until the
# foreign-record, long-integer and per-record-isolation changes; 5: those; 6: a record over max_record_bytes is skipped and the
# records after it are read (they were never read before); 7: the credential
# rules are the shared block's (a number or an array under a credential's name, mysql -p, curl -u and a bcrypt hash are withheld now).
PARSER = "ual_parse/7"
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
    if isinstance(item.get(keys.get("operation")), str) or ("creationtime" in keys and ("workload" in keys or "userid" in keys)):     # a GCP log entry's `operation` is an object
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
    text = shown_text(value).strip().lower()
    return str(int(text)) if text.isascii() and text.isdigit() and len(text) <= 40 else text


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


_NOT_FULL_BYTE = re.compile(rb"[^\xff]")


class ResultIndexes:
    """The ResultIndex values of one file, held against the ResultCount beside them. The rows of one search carry the same count and
    the indices 1 to that count, each once, in any order; rows with another count belong to another search, so each count is its own
    group. A group is a bitmap of one bit per index (a count of 5,000,000 is 625 KB), so a repeat is found when it is read and a gap
    when the file ends, whatever the order. Memory is bounded: all bitmaps together hold at most TRACK_BITS bits and there are at most
    MAX_COUNTS groups; rows of a count beyond that are counted, not checked, and the answer says so (a read is never whole on what it did
    not check). The first FIRST_PROBLEMS repeated, missing and out-of-range indices of a group are named, the rest counted."""
    TRACK_BITS = 1 << 28
    MAX_COUNTS = 64

    def __init__(self):
        self.groups = {}
        self.used = 0
        self.with_index = self.without_index = self.no_count = self.not_checked = 0
        self.not_checked_counts = set()

    def add(self, count, index):
        if index is None:
            self.without_index += 1
            return
        self.with_index += 1
        if count is None:
            self.no_count += 1
            return
        g = self.groups.get(count)
        if g is None:
            if count < 1 or len(self.groups) >= self.MAX_COUNTS or self.used + count > self.TRACK_BITS:
                self.not_checked += 1
                if len(self.not_checked_counts) < FIRST_PROBLEMS:
                    self.not_checked_counts.add(count)
                return
            self.used += count
            g = self.groups[count] = {"bits": bytearray((count + 7) >> 3), "rows": 0, "repeated": 0, "first_repeated": [], "out_of_range": 0, "first_out": []}
        g["rows"] += 1
        if 1 <= index <= count:
            at, mask = (index - 1) >> 3, 1 << ((index - 1) & 7)
            if g["bits"][at] & mask:
                g["repeated"] += 1
                if len(g["first_repeated"]) < FIRST_PROBLEMS:
                    g["first_repeated"].append(index)
            else:
                g["bits"][at] |= mask
        else:
            g["out_of_range"] += 1
            if len(g["first_out"]) < FIRST_PROBLEMS:
                g["first_out"].append(index)

    @staticmethod
    def first_missing(bits, count, n):
        out = []
        for m in _NOT_FULL_BYTE.finditer(bits):
            for bit in range(8):
                index = m.start() * 8 + bit + 1
                if index <= count and not bits[m.start()] >> bit & 1:
                    out.append(index)
                    if len(out) >= n:
                        return out
        return out

    def findings(self, shown, said_for=None):
        """(entry for the answer's pagination_markers, sentence for the file's problems) for each thing wrong with the indices. `said_for` is
        the count whose missing indices the ResultCount sentence of the file already says (rows fewer than the count): not said twice."""
        found = []
        if self.with_index and self.without_index:
            found.append(({"file": shown, "keys": ["ResultIndex"], "rows_with_result_index": self.with_index, "rows_without_result_index": self.without_index},
                          "%d row(s) carry a ResultIndex and %d carry none or one that is not a number: the indices cannot show the search was exported whole" % (self.with_index, self.without_index)))
        if self.not_checked:
            found.append(({"file": shown, "keys": ["ResultIndex"], "rows_not_checked": self.not_checked, "counts_not_checked": sorted(self.not_checked_counts)},
                          "%d row(s) carry a ResultCount this tool does not check the indices of (more than %d distinct counts, or more indices than it holds): their ResultIndex values were not checked" % (
                              self.not_checked, self.MAX_COUNTS)))
        named = 0
        for count in sorted(self.groups):
            g = self.groups[count]
            distinct = int.from_bytes(g["bits"], "little").bit_count()
            missing = count - distinct
            if not (g["repeated"] or g["out_of_range"] or (missing and count != said_for)):
                continue
            named += 1
            if named > FIRST_PROBLEMS:
                continue
            first_missing = self.first_missing(g["bits"], count, FIRST_PROBLEMS) if missing else []
            found.append(({"file": shown, "keys": ["ResultIndex"], "result_count": count, "rows": g["rows"], "distinct_indices": distinct,
                           "repeated_indices": g["repeated"], "first_repeated": g["first_repeated"], "missing_indices": missing, "first_missing": first_missing,
                           "out_of_range_indices": g["out_of_range"], "first_out_of_range": g["first_out"]},
                          "the %d row(s) of ResultCount %d hold %d distinct ResultIndex value(s) of the %d expected: %d repeated (first: %s), %d missing (first: %s), %d outside 1 to %d (first: %s)" % (
                              g["rows"], count, distinct, count, g["repeated"], g["first_repeated"][:5], missing, first_missing[:5], g["out_of_range"], count, g["first_out"][:5])))
        if named > FIRST_PROBLEMS:
            found.append(({"file": shown, "keys": ["ResultIndex"], "more_counts_with_problems": named - FIRST_PROBLEMS},
                          "%d more ResultCount group(s) have repeated, missing or out-of-range indices and are counted, not listed" % (named - FIRST_PROBLEMS)))
        return found


class Census:
    def __init__(self, limit):
        self.files = LosslessPage("file_census", limit)
        self.rejected = RejectLog(LosslessPage("rejected_records", limit))
        self.problems = []
        self.conventions = []
        self.pagination = []
        self.limit_stops = []      # a limit of the tool's own (max_expanded_bytes, max_record_bytes) ended a file before a record was read
        self.cut = False
        self.counts = {"files_found": 0, "files_read": 0, "files_partial": 0, "files_failed": 0, "files_unsupported": 0,
                       "files_empty": 0, "files_skipped": 0, "files_not_attempted": 0, "rows_read": 0, "rows_rejected": 0,
                       "payloads_rejected": 0, "rows_not_audit_records": 0, "replacement_characters": 0, "bytes_read": 0}

    def problem(self, text):
        if len(self.problems) < FIRST_PROBLEMS:
            self.problems.append(scrub_text(text))


def open_rows(path, fmt_arg, delimiter, max_expanded, field_limit, record_cap=MAX_RECORD_BYTES):
    """(source, row iterator, format, basis) for one file; the format comes from its content, and one the caller names that the
    content contradicts is refused."""
    seen = sniff(path)
    if fmt_arg != "auto" and fmt_arg != seen:
        fail("format %s was asked for, and the content of %s reads as %s" % (fmt_arg, shown_path(path), seen), path=shown_path(path))
    src = Source(path, max_expanded)
    if seen == "json":
        return src, read_units(src, ENVELOPE_KEYS, record_cap, MAX_DOCUMENT_BYTES), seen, "the content" if fmt_arg == "auto" else "the format argument, and the content agrees"
    return src, csv_rows(src, delimiter, field_limit, record_cap), seen, "the content" if fmt_arg == "auto" else "the format argument, and the content agrees"


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
    field_limit = want_int(args, "max_field_bytes", MAX_FIELD_BYTES, 1024, 1 << 30)
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
            if out_of_time() or any("the time limit ended the listing" in str(s.get("reason", "")) for s in skipped.items):
                fail("the time limit ended the listing of the directory before any CSV or JSON export was found; nothing was read or judged (see skipped)", path=shown_path(path), skipped=named(skipped.items))
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
            indexes = ResultIndexes()
            records = rejected = payload_bad = size_rejects = 0
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
                        if kind == "reject" and ("larger than max_record_bytes" in str(reason) or "a line longer than" in str(reason)):
                            size_rejects += 1
                        if census.rejected.reject({"file": shown, "record": info["record"], "line": info["line"], "reason": scrub_text(reason)}):
                            stopped_all_rejected = True
                            break
                        continue
                    counted = payload_flagged = False
                    try:
                        audit, outer, payload_status, detail = interpret(item)
                        if payload_status is None:
                            rejected += 1
                            census.counts["rows_not_audit_records"] += 1
                            first_reject = first_reject or (info["record"], info["line"], detail)
                            if census.rejected.reject({"file": shown, "record": info["record"], "line": info["line"], "reason": detail}):
                                stopped_all_rejected = True
                                break
                            continue
                        records += 1
                        census.rejected.accept()
                        census.counts["rows_read"] += 1
                        counted = True
                        o_keys = key_map(outer)
                        if payload_status in ("invalid_json", "not_an_object", "absent"):
                            payload_bad += 1
                            census.counts["payloads_rejected"] += 1
                            payload_flagged = True
                            census.rejected.note({"file": shown, "record": info["record"], "line": info["line"], "reason": detail, "kind": "payload"})
                        rc, ri = first_of(outer, o_keys, "ResultCount"), first_of(outer, o_keys, "ResultIndex")
                        count_now = index_now = None
                        try:
                            count_now = int(rc) if rc is not None else None
                        except (TypeError, ValueError, OverflowError):
                            pass
                        try:
                            index_now = int(ri) if ri is not None else None
                        except (TypeError, ValueError, OverflowError):
                            pass
                        if count_now is not None:
                            result_count = max(result_count or 0, count_now)
                        if index_now is not None:
                            max_index = max(max_index or 0, index_now)
                        indexes.add(count_now, index_now)
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
                        operation = shown_text(operation) if operation is not None else "?"
                        forms = type_forms(fields)
                        type_key = (shown_text(fields.get("record_type")) if fields.get("record_type") is not None else None,
                                    shown_text(fields.get("record_type_outer")) if fields.get("record_type_outer") is not None else None)
                        # every filter looks at the text as it will be printed, never at a value that is withheld
                        shown_user = shown_text(fields.get("user") or "")
                        by_operation_all.add(operation)
                        by_types.add(type_key)
                        note = NOTABLE.get(operation)
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
                        row_out = compact(entry)
                        address_key = shown_text(fields["address"]) if fields.get("address") else None
                        complete_target.add(row_out)
                        matched += 1
                        by_operation.add(operation)
                        if fields.get("user"):
                            by_user.add(shown_user)
                        if address_key is not None:
                            by_address.add(address_key)

                    except Exception as exc:               # one record never ends the run: it is counted, located and listed, and the next is read
                        if counted:
                            records -= 1
                            census.counts["rows_read"] -= 1
                        if payload_flagged:
                            payload_bad -= 1
                            census.counts["payloads_rejected"] -= 1
                        rejected += 1
                        reason = failed_record(exc)
                        first_reject = first_reject or (info["record"], info["line"], reason)
                        census.rejected.note({"file": shown, "record": info["record"], "line": info["line"], "reason": reason})
                        if isinstance(exc, TimeUp):
                            src.timed_out = True
                            break
                        continue
            finally:
                src.close()
            stopped_early = src.timed_out
            if order["value"] or order["tried"]:
                census.conventions.append({"file": shown, "date_order": order["value"], "basis": order["basis"]})
            problems = []
            markers = [scrub_text(k) for k in getattr(src, "extra_keys", []) if pagination_key(k)]
            if markers:
                census.pagination.append({"file": shown, "keys": markers})
                row["pagination_marker_keys"] = markers
            if result_count is not None and (records < result_count or (max_index is not None and max_index < result_count)):
                census.pagination.append({"file": shown, "keys": ["ResultCount"], "result_count": result_count, "rows": records, "highest_result_index": max_index})
                problems.append("the export's own ResultCount says %d records matched the search; this file holds %d (the highest ResultIndex is %s): the search was not exported whole" % (
                    result_count, records, max_index))
            count_says = result_count is not None and (records < result_count or (max_index is not None and max_index < result_count))
            for entry, sentence in indexes.findings(shown, result_count if count_says else None):
                census.pagination.append(entry)
                problems.append(sentence)
            if src.error:
                problems.extend(src.problem_lines())
            if src.capped:
                problems.append("the expansion reached max_expanded_bytes (%d): the rest of the file was not read" % max_expanded)
            if getattr(src, "stopped", None):
                problems.append(src.stopped)
            # A limit of the tool's own that ended the file before any record was read is the limit's doing, never a verdict on the input.
            limit_stop = None
            if records == 0 and src.capped:
                limit_stop = "max_expanded_bytes (%d) stopped the read of %s before any record" % (max_expanded, shown)
            elif records == 0 and size_rejects and size_rejects == rejected:
                limit_stop = "max_record_bytes (%d) rejected every record of %s (%d of them), so no record was read" % (record_cap, shown, size_rejects)
            if limit_stop:
                census.limit_stops.append(limit_stop)
            if stopped_all_rejected and size_rejects == rejected:
                problems.append("the first %d records were each larger than max_record_bytes (%d), so none was read: raise it; the rest of the file was not examined" % (FIRST_REJECTS, record_cap))
            elif stopped_all_rejected:
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
                row["problems"] = [scrub_text(p) for p in problems]
            if src.replaced:
                row["replacement_characters"] = src.replaced
            if src.trailing_zero_bytes:
                row["trailing_zero_bytes"] = src.trailing_zero_bytes
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
                and c["rows_rejected"] == 0 and c["payloads_rejected"] == 0 and not skipped.total and c["files_not_attempted"] == 0
                and c["replacement_characters"] == 0 and not census.pagination and not excluded_unknown_time)
    nothing_read = c["rows_read"] == 0
    # The tool's own clock ended the read: a stop by the tool, never a verdict on the input (see cloudtrail_parse).
    clock_basis = None
    if stop_all:
        files_read = len(targets) - c["files_not_attempted"]
        clock_basis = ("the time limit (%s s) ended the read after %d of the %d supplied files, with %d not attempted and %d audit rows read; "
                       "what was read is kept and nothing in the files not read was judged (see coverage.stopped_by_time_limit and files_not_attempted_named)"
                       % (seconds, files_read, len(targets), c["files_not_attempted"], c["rows_read"]))
        if c["files_failed"] or c["files_unsupported"] or c["files_empty"]:
            clock_basis += "; before the stop %d file(s) could not be read, %d were unsupported and %d were empty (see file_problems)" % (
                c["files_failed"], c["files_unsupported"], c["files_empty"])
    # The same rule for the tool's other limits: when max_expanded_bytes or max_record_bytes ended every file before a record was read,
    # the answer is partial and names the limit and its value; it does not say that nothing could be read from what was supplied.
    limit_basis = None
    if census.limit_stops and nothing_read and not stop_all:
        limit_basis = ("a limit of this tool's own stopped the read before any record: %s; raise it (max_expanded_bytes, max_record_bytes) and run again; "
                       "nothing in the supplied files was judged (see coverage.limit_stops and file_problems)" % "; ".join(census.limit_stops[:3]))
    status = status_of((not stop_all) and not limit_basis and nothing_read and (c["files_failed"] or c["files_unsupported"] or c["files_empty"] or c["files_not_attempted"]), complete,
                       "every row of every supplied file was read and nothing was left out; that says nothing about whether the export holds everything the tenant logged",
                       clock_basis or limit_basis or "some of what was supplied was not read as audit records or not read at all (a file skipped for its name too: see skipped), an export names a next page or says it holds fewer records than matched, or a time filter excluded "
                       "rows whose time could not be read (see coverage, file_census, rejected_records, file_problems, skipped, pagination_markers)",
                       "no audit record could be read from what was supplied (see file_problems)")
    answer = {
        "parser": PARSER, **status, "path": shown_path(path),
        "coverage": {**c, "time_limit_seconds": seconds, "stopped_by_time_limit": stop_all, "max_expanded_bytes": max_expanded, "max_record_bytes": record_cap, "limit_stops": census.limit_stops[:20],
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
    exit_code = 0
    try:
        try:
            main()
        except SystemExit:
            raise
        except Exception as exc:  # never an empty or clean answer for a failure
            hold_stop_signals()
            fail("unexpected failure: %s: %s" % (type(exc).__name__, scrub_text(str(exc))))
    except SystemExit as stop:
        exit_code = _code(stop)
    _leave(exit_code)
