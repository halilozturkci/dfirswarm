#!/usr/bin/env python3
"""Lay out an iOS backup as a derivative: every file under the domain and path the phone knew it by, tied to its Manifest.db row.

A backup is a set of blobs named by a 40-digit hexadecimal id, and `Manifest.db` is the map from an id to a domain and a
relative path. This reads that map (with the row reader of `manifest_db`, copied: tools do not import each other) and, for a
selection, writes a derivative layout under the output directory:

    derivative/derivative.json                       the banner: this is a derivative, not the phone
    derivative/files/<domain>/<relativePath>          the blobs, one per Manifest row, under the names the phone used
    tool-output/backup_materialise-<digest>.jsonl     one line per row: the whole account, whatever the answer shows inline

For every row the result keeps the original file id, the domain, the relative path (and both as base64 of their bytes beside
the displayed text, so a name that is not UTF-8 survives), the Manifest row number, the state of the blob (present, missing, a
directory, a link never followed, refused, special), the SHA-256 of the blob when it was copied, and the name it was written
under when that is not the name it had (a collision, a case-folding one included, is resolved and listed).

What it does not do. It does not decrypt: a backup whose Manifest.plist says IsEncrypted is refused, and one whose flag is
missing is said to be of unknown state and the answer is partial. It does not rebuild the phone's file system and it is not an
acquisition of the phone: the derivative is a copy of what a backup kept, in the layout of the backup's map, and a file the backup
does not hold (missing) is not in it. It never follows a link in the backup, it writes only under the output directory, and it
treats every domain and relative path as hostile text: a path with `..` or `.` or an empty component, an absolute path, a NUL, a
component of more than 255 bytes, a path of more than 4096 bytes or of more than 64 components is rejected and listed, never
written.

THE SECRET-SAFE OUTPUT PATTERN. Copying content writes what the backup holds, and that can be secret. `copy_content` is false by
default and is a `secret_output` mode of the manifest: it is accepted only in a job run as secret output (SECRET_OUTPUT=1) and is
otherwise refused as JSON before anything is made. With it false the run is a plan: it reads the map and looks at each blob
(opens it, never reads it), writes the result file and nothing else, and no digest of a blob is computed. A path component shaped
like a recovery password is withheld from every channel: the answer, the result file and the names under derivative/ carry the
placeholder `withheld-component` where it stood; its real name is written only to the 0600 values file of a `copy_content` job.
Selection (`domains`, `paths`) is matched against the names as they are printed, so no selection can ask whether withheld text
matches.
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
#   not printed (3.11 and 3.12 say nothing of it, 3.14 a traceback). A handler that was due runs on the way in: what it raises reaches the
#   writer that asked (the tool's own handling then answers the stop, before any byte of the answer), or, quietly, is dropped (the end of a
#   call, an error branch). Every writer of a final answer calls it before it commits to writing, every error branch at the end calls it
#   quietly, and, when the file runs as a program, standard output is wrapped so that its first write calls it too. _code(stop) is a
#   SystemExit's exit code (its text, if it has one, goes to standard error as the interpreter puts it), and _leave(code) ends the call: both
#   hold the signals first, quietly; _leave flushes
#   standard output (a write that fails there makes a 0 an exit 120, as the interpreter does) and standard error, runs the atexit hooks (a hook
#   that removes a temporary file), each step on its own and none able to raise, and ends the process with os._exit, never through the teardown.
# The modules are imported here, as the file is loaded, never inside the ending (an import there ran a due handler inside the import system).
import atexit
import json
import os
import signal
import sys

_ENDING = {"held": False, "program": __name__ == "__main__"}      # imported (a test that loads the file as a module), the block holds nothing
_ENDING_SIGNALS = (signal.SIGTERM, signal.SIGINT, signal.SIGHUP)


def answer_a_stop(signum, when="before it had answered"):
    """The one document of a stop that ends the call before any answer was begun (nothing once one has): status failed, interrupted, and
    no claim about what was read or written. A handler whose own last word printed nothing calls it before it ends the process. It writes
    only when the file runs as a program: its wrapped standard output is what knows whether an answer was begun."""
    if _ENDING["held"] or not isinstance(sys.stdout, _AnswerStream):
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


def hold_stop_signals(quietly=False):
    """Hold the stop signals for good. A handler that was due runs on the way in, before the hold and before any byte of the answer, and what
    it raises is raised here, so that the tool's own handling of a stop answers it; quietly (the end of a call, an error branch, where nothing
    may escape) it is dropped and the hold is made all the same. Called by a thread that is not the main one, it blocks the signals there and
    leaves the rest to the main thread's next call."""
    for _attempt in range(len(_ENDING_SIGNALS) + 2):
        if _ENDING["held"] or not _ENDING["program"]:
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
        except BaseException:  # noqa: BLE001 - a handler that was due ran on the way in, and raised
            if not quietly:
                raise



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
    hold_stop_signals(quietly=True)
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
    hold_stop_signals(quietly=True)
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
    if sys.stdout is not None and not isinstance(sys.stdout, _AnswerStream):
        sys.stdout = _AnswerStream(sys.stdout)
    for _signum in _ENDING_SIGNALS:
        signal.signal(_signum, _stopped_without_handler)
# END SHARED ENDS


import base64
import datetime
import errno
import hashlib
import json
import math
import os
import plistlib
import re
import select
import shutil
import signal
import sqlite3
import stat
import struct
import sys
import tempfile
import time
import unicodedata
from pathlib import Path

PARSER = "backup_materialise/3"
TOOL = "backup_materialise"
VALUES_NAME = "backup-materialise-values.jsonl"       # the first free name of this and -2, -3 ... is used (see choose_values_name)
VALUES_FORMAT = "JSON Lines: the file id, the real domain and the real relative path of each row whose name is withheld"


# --- shared with the pack's other tools: begin ---------------------------------------------
# The three tools of this pack carry this block byte for byte (a test holds the copies equal),
# so that they withhold the same strings, write the same files the same way and refuse in the
# same words. Standalone tools do not import each other: the block is copied.
#
# THE SECRET-SAFE OUTPUT PATTERN (docs/packs.md, "Secrets and sensitive output"), as the
# encrypted-containers pack's recovery_key_scan introduced it and the macOS pack's plist_read
# copied it:
#   1. The answer carries presence, kind, location (file and offset or path), length and counts.
#      It carries no value, no characters of one, no masked shape and no digest of one.
#   2. A value is written only on `write_values: true`, only when the tool runs as a job
#      (JOB_ID and OUT are set) that the harness ran as secret output (SECRET_OUTPUT=1, which the
#      manifest's `secret_output` declaration makes the job service set), and only to a file under
#      $OUT: JSON Lines, mode 0600, created exclusively before anything is read. Outside such a job
#      the request is refused as JSON and nothing is written.
#   3. A secret is never on a command line: these tools take a path and flags only.
#   4. A printed path component shaped like a recovery password is withheld on every output
#      channel (the answer, the files it names, an error message); the values file keeps the
#      real path.
#   5. The harness shows the requester a sealed file's size and digest, so neither may answer a
#      question about text nobody can see: a filter marks rows and never drops them, a window or an
#      expression that is not accepted writes a file of the same size as one that is, and every row
#      carries a random per-run `run`, so that no two runs share a digest.
#   6. One document is written, whole: from the moment the answer is being written a stop signal is
#      ignored, so a reader that is slow never gets a truncated answer followed by a failure. A reader that
#      takes nothing for WRITE_STALL_SECONDS is given up on: the tool exits (141) instead of waiting for ever.

# A stop that arrives while the rest of this module is still being read (the definitions below, the tool's own code after
# the block) is answered here, by one JSON document and exit 128 + the signal, as run_main answers it later. The handlers are
# installed as the module reaches this point, not when main() starts, so the window left is the interpreter's own start-up and
# the imports above the block, which no code in this file can close and which this tool does not claim: a stop there ends the
# process with no answer, before anything was read or written. run_main replaces these handlers.
EARLY_SIGNALS = [getattr(signal, name) for name in ("SIGTERM", "SIGINT", "SIGHUP") if hasattr(signal, name)]


def early_stop(signum, frame):
    for number in EARLY_SIGNALS:
        signal.signal(number, signal.SIG_IGN)
    name = signal.Signals(signum).name
    text = json.dumps({"error": "the tool was stopped by %s before it finished: this is not an answer to the question" % name,
                       "status": "failed", "status_basis": "stopped by %s before the tool had started to read anything" % name,
                       "interrupted": name}) + "\n"
    try:
        os.write(1, text.encode("utf-8"))
    except OSError:
        pass
    os._exit(128 + signum)


for early_number in EARLY_SIGNALS:
    signal.signal(early_number, early_stop)

WITHHELD = "<recovery-password-shaped name withheld>"
WITHHELD_LONG = "<name too long to judge withheld>"
PATHS_WITHHELD = [0]
# A BitLocker recovery password is eight groups of six digits: 48 digits. People save a key under its own name, and not
# only in the dashed form: with spaces, underscores or dots between the groups, with no separator at all, with another
# dash, comma, colon, bracket or quote mark, in full-width or Arabic-Indic digits, with a zero-width character or an accent
# inside, and a name can carry part of it or be split across two path components. A text is shaped like one when it holds
# RECOVERY_DIGITS (seven groups of six) or more decimal digits in a run that allows at most three characters that are neither
# a letter nor a digit between two digits (a run of white space counts as one, and `/` is such a character), after NFKC
# folding (which turns full-width digits, superscripts and circled digits into ASCII ones). Fewer digits are a timestamp, a
# phone number or an id.
# The judgment is linear in the text: the maximal runs of digits and separators are found in one pass, and only a run long
# enough to hold RECOVERY_DIGITS digits is looked at again, at its start (a pattern tried from every digit costs 41 steps per
# character on "41 digits and a letter", repeated). A path is judged only up to JUDGE_CHARS characters: nothing a file system
# holds is longer, and a longer text is withheld whole instead of being read, so that the cost of one hostile cell stays small.
RECOVERY_DIGITS = 42
JUDGE_CHARS = 8192
SEPARATOR = r"[\W_]"
DIGIT_RUN = re.compile(r"\d(?:%s{0,3}\d)*" % SEPARATOR)
KEY_START = re.compile(r"\d(?:%s{0,3}\d){%d}" % (SEPARATOR, RECOVERY_DIGITS - 1))
SPACES = re.compile(r"\s+")


def folded(text):
    """NFKC, with every run of white space as one space."""
    return SPACES.sub(" ", unicodedata.normalize("NFKC", text))


def key_spans(text):
    """(start, end) of every run of `text` (already folded) that holds RECOVERY_DIGITS or more digits."""
    return [run.span() for run in DIGIT_RUN.finditer(text)
            if run.end() - run.start() >= RECOVERY_DIGITS and KEY_START.match(text, run.start())]


def key_shaped(text):
    return bool(key_spans(folded(text)))


def shown(path, count=True):
    """A path as it may be printed: a component that holds digits of a text shaped like a recovery password (a key split
    across components included) is withheld, and a path too long to judge is withheld whole."""
    if not isinstance(path, str):
        return path
    if len(path) > JUDGE_CHARS:
        if count:
            PATHS_WITHHELD[0] += 1
        return WITHHELD_LONG
    parts = path.split("/")
    texts = [folded(part) for part in parts]
    spans = key_spans("/".join(texts))
    if not spans:
        return path
    at, hidden = 0, []
    for i, text in enumerate(texts):
        if any(start < at + len(text) and end > at for start, end in spans):
            hidden.append(i)
        at += len(text) + 1
    for i in hidden:
        parts[i] = WITHHELD
        if count:
            PATHS_WITHHELD[0] += 1
    return "/".join(parts)


def scrub(text):
    """Text that may quote a path, with anything shaped like a recovery password withheld."""
    text = DIGIT_RUN.sub(lambda run: WITHHELD if run.end() - run.start() >= RECOVERY_DIGITS and KEY_START.match(run.string, run.start())
                         else run.group(), text)
    if key_shaped(text):      # digits only NFKC folds (superscripts, circled digits): the text is not printed at all
        return WITHHELD
    return text


def describe(exc):
    code = errno.errorcode.get(exc.errno, "") if getattr(exc, "errno", None) else ""
    return scrub("%s%s: %s" % (type(exc).__name__, " " + code if code else "", getattr(exc, "strerror", None) or str(exc)))


def clean(value):
    """The value as strict JSON: a float that is not finite (JSON has no NaN or Infinity) is its text."""
    if isinstance(value, float) and not math.isfinite(value):
        return {"_float": repr(value)}
    if isinstance(value, dict):
        return {k: clean(v) for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        return [clean(v) for v in value]
    return value


def dumps(value, **kwargs):
    return json.dumps(clean(value), allow_nan=False, default=str, **kwargs)


# What is open when a run fails: the pages and the values file are closed and named in the error, so a
# result read before the failure is kept, whole, and never left as a hidden temporary file.
OPEN_PAGES = []
OPEN_VALUES = []
NONCE = "%d-%d" % (os.getpid(), time.time_ns())


# Things the run made that a failure or a stop must not leave behind (a working copy of an evidence file). Each is a
# callable that removes what the tool itself created; it is run once, by fail() and by a stop signal.
CLEANUP = []


def run_cleanup():
    while CLEANUP:
        step = CLEANUP.pop()
        try:
            step()
        except Exception:
            pass


def wrap_up(answer):
    """What an answer that ends the run early carries: the pages already written are closed and named, the values
    file is closed and counted, and what the tool made as scratch is removed."""
    kept = []
    for page in OPEN_PAGES:
        if page._out is not None:
            try:
                kept.append(page.finish().get("all_results"))
            except Exception:
                pass
    if kept:
        answer["rows_read_before_the_failure_kept_in"] = kept
    for values in OPEN_VALUES:
        values.close()
        if values.written:
            answer["values_written_before_the_failure"] = {"file": values.shown, "rows": values.written}
    run_cleanup()
    return answer


WRITE_STALL_SECONDS = 30
WRITE_CHUNK = 4096


def write_stalled(signum, frame):
    sys.stderr.write("the reader took nothing for %d seconds: the answer is not delivered\n" % WRITE_STALL_SECONDS)
    raise SystemExit(141)


def emit(text):
    """Write one document to standard output, whole. From here a stop signal is ignored: the answer is written in one piece
    (a reader that is slow, or has not started, sees all of it) and never as a truncated document followed by a failure.
    A reader that takes nothing for WRITE_STALL_SECONDS is given up on (exit 141): without that, a pipe nobody reads could
    be ended only by SIGKILL."""
    for number in STOP_SIGNALS:
        signal.signal(number, signal.SIG_IGN)
    data = memoryview((text + "\n").encode("utf-8"))
    # One os.write on a blocking pipe returns only when everything it was given has gone in, however slowly the reader takes it,
    # so a single call for the whole document would restart the clock once. A write of at most WRITE_CHUNK bytes (a pipe takes
    # up to PIPE_BUF bytes in one piece) returns when that much has been taken, so the clock restarts on every chunk the reader
    # takes and only a reader that takes nothing for WRITE_STALL_SECONDS is given up on.
    timed = hasattr(signal, "setitimer")
    if timed:
        try:
            signal.signal(signal.SIGALRM, write_stalled)
        except ValueError:      # not the main thread: no deadline
            timed = False
    try:
        sys.stdout.flush()
        descriptor = sys.stdout.fileno()
        while len(data):
            if timed:
                signal.setitimer(signal.ITIMER_REAL, WRITE_STALL_SECONDS)       # progress restarts the wait
            try:
                data = data[os.write(descriptor, data[:WRITE_CHUNK]):]
            except BlockingIOError:      # a pipe set non-blocking by its owner and full: wait until it can take more
                select.select([], [descriptor], [], 1.0)
    except OSError:       # the reader went away: there is nobody to answer
        raise SystemExit(1)
    finally:
        if timed:
            signal.setitimer(signal.ITIMER_REAL, 0)


def fail(message, **extra):
    answer = {"error": scrub(str(message)), "status": "failed", "status_basis": "the tool stopped with an error: %s" % scrub(str(message)),
              **{k: (scrub(v) if isinstance(v, str) else v) for k, v in extra.items()}}
    emit(dumps(wrap_up(answer)))
    raise SystemExit(1)


class Interrupted(BaseException):
    """A stop signal (SIGTERM, SIGINT or SIGHUP) arrived. A BaseException, so that no `except Exception` of a tool
    swallows it; run_main answers for it once, at the top."""

    def __init__(self, signum):
        BaseException.__init__(self, signum)
        self.signum = signum


STOP_SIGNALS = [getattr(signal, name) for name in ("SIGTERM", "SIGINT", "SIGHUP") if hasattr(signal, name)]


def stop_handler(signum, frame):
    # The answer to the first signal is written once: a second signal while it is written changes nothing.
    for number in STOP_SIGNALS:
        signal.signal(number, signal.SIG_IGN)
    raise Interrupted(signum)


def stopped(signum):
    """One JSON answer for a run a signal ended, then exit 128 + the signal. The pages and the values file are closed
    and named, the scratch the tool made is removed, and nothing is said about what the tool had read."""
    name = signal.Signals(signum).name
    answer = wrap_up({"error": "the tool was stopped by %s before it finished: this is not an answer to the question" % name,
                      "status": "failed", "status_basis": "stopped by %s before the answer was complete" % name,
                      "interrupted": name})
    emit(dumps(answer))
    raise SystemExit(128 + signum)


class Timeout(Exception):
    pass


def alarm_handler(signum, frame):
    raise Timeout()


def timed_search(pattern, text, seconds):
    """pattern.search(text), stopped after `seconds` where the platform can: a pattern the caller
    wrote can backtrack without end."""
    if not hasattr(signal, "setitimer"):
        return pattern.search(text)
    old = signal.signal(signal.SIGALRM, alarm_handler)
    signal.setitimer(signal.ITIMER_REAL, seconds)
    try:
        return pattern.search(text)
    finally:
        signal.setitimer(signal.ITIMER_REAL, 0)
        signal.signal(signal.SIGALRM, old)


def safe_name(text):
    return re.sub(r"[^A-Za-z0-9_.-]", "_", text)


class LosslessPage:
    """A page an agent reads, and the whole result in a file the answer names.

    The page stays small (rows, and bytes when a byte limit is given); when there are more rows
    the whole result is written as JSON Lines under work/<agent>/tool-output (in a job,
    $OUT/tool-output) and named: nothing is cut. The file name is a digest of the page's key (a
    path), never of a value. Rows are written with ensure_ascii on: a path the filesystem gave as
    bytes that are not UTF-8 reaches Python as lone surrogates, which a UTF-8 file cannot hold
    and an escape can. A rerun that would replace a larger earlier file of the same name writes a
    new name and says which earlier file it kept.
    """

    def __init__(self, tool, key, limit, byte_limit=None):
        if isinstance(limit, bool) or not isinstance(limit, int) or limit < 1:
            raise ValueError("limit must be a positive integer")
        self.tool = safe_name(tool)
        self.limit = limit
        self.byte_limit = byte_limit
        self.page = []
        self.page_bytes = 0
        self.full = False
        self.bytes_bound_hit = False
        self.total = 0
        self._out = None
        self._tmp = None
        OPEN_PAGES.append(self)
        # The key is the question (a path as it may be printed, a filter), plus this call's own nonce: two
        # questions that print alike (two files in directories whose names are withheld, two messages passed
        # in the call) never share a file, and a rerun never replaces an earlier result.
        digest = hashlib.sha256(dumps([key, NONCE], sort_keys=True).encode("utf-8")).hexdigest()[:16]
        name = "%s-%s.jsonl" % (self.tool, digest)
        job, out = os.environ.get("JOB_ID"), os.environ.get("OUT")
        if job and out:
            # In a job only $OUT is written, and it is sealed as the job's output: the whole
            # result is cited from there.
            self.path = Path(out) / "tool-output" / name
            self.shown = "store/jobs/%s/out/tool-output/%s" % (safe_name(job), name)
        else:
            agent = safe_name(os.environ.get("AGENT_ID") or "tool")
            self.path = Path("work") / agent / "tool-output" / name
            self.shown = str(self.path)

    def _write(self, row):
        self._out.write(dumps(row))
        self._out.write("\n")

    def add(self, row):
        self.total += 1
        if not self.full and len(self.page) < self.limit:
            size = len(dumps(row)) if self.byte_limit is not None else 0
            if self.byte_limit is None or self.page_bytes + size <= self.byte_limit:
                self.page.append(row)
                self.page_bytes += size
                return
            self.bytes_bound_hit = True
        # From the first row that does not fit, every later row goes to the file only: the page
        # is a prefix.
        self.full = True
        if self._out is None:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            fd, name = tempfile.mkstemp(dir=self.path.parent, prefix=".%s-" % self.path.name)
            self._tmp = Path(name)
            self._out = os.fdopen(fd, "w", encoding="utf-8")
            for kept in self.page:
                self._write(kept)
        self._write(row)

    def finish(self):
        result = {"matched": self.total, "returned": len(self.page), "truncated": self.total > len(self.page)}
        if self.byte_limit is not None:
            result["inline_byte_limit"] = self.byte_limit
            if self.bytes_bound_hit:
                result["inline_bounded_by_bytes"] = True
        if self._out is not None:
            self._out.flush()
            os.fsync(self._out.fileno())
            self._out.close()
            target, shown_as = self.path, self.shown
            if target.exists() and target.stat().st_size > os.path.getsize(self._tmp):
                n = 2
                while target.with_name("%s-%d%s" % (target.stem, n, target.suffix)).exists():
                    n += 1
                target = target.with_name("%s-%d%s" % (target.stem, n, target.suffix))
                shown_as = self.shown.rsplit("/", 1)[0] + "/" + target.name
                result["kept_earlier_larger_result"] = self.shown
            os.replace(self._tmp, target)
            result["all_results"] = shown_as
            result["all_results_format"] = "JSON Lines, one complete result per line"
        return result


class SecretValuesRefused(Exception):
    pass


class SecretValues:
    """Where a value goes when, and only when, the caller asked for it.

    The pattern of recovery_key_scan (encrypted-containers), copied: call `add` once per finding
    with its id, its locator and the value. With `enabled` false it writes nothing and
    `summary()` says so.
    """

    def __init__(self, enabled):
        self.enabled = enabled
        self.written = 0
        self._fh = None
        self.job = os.environ.get("JOB_ID") or ""
        self.out = os.environ.get("OUT") or ""
        self.path = None
        self.shown = None
        self.run = os.urandom(8).hex()      # in every row: the file's digest is different in every run, whatever it holds
        if not enabled:
            return
        if not (self.job and self.out):
            raise SecretValuesRefused(
                "write_values is refused outside a job: a value written here would be an ordinary "
                "file, not a sealed secret output. Run this as job_run tool=%s with "
                "secret_output: true, and ask again there. Nothing was written." % TOOL
            )
        if os.environ.get("SECRET_OUTPUT") != "1":
            raise SecretValuesRefused(
                "write_values is refused in a job that is not run as secret output (SECRET_OUTPUT is not 1): the values file would "
                "be sealed as ordinary output. The harness sets SECRET_OUTPUT=1 for a secret job's process and it is not set here. "
                "Run this as job_run tool=%s with secret_output: true, and ask again there. Nothing was written." % TOOL
            )
        self.path = Path(self.out) / VALUES_NAME
        self.shown = "store/jobs/%s/out/%s" % (safe_name(self.job), VALUES_NAME)
        # Created now, before anything is read: a file or a link already at that name is refused
        # by name at once (O_EXCL does not follow a link, a dangling one included), instead of
        # failing, or writing through it, after the scan. With nothing found it stays an empty
        # file, mode 0600, and the answer says written: 0.
        try:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            fd = os.open(str(self.path), os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o600)
        except FileExistsError:
            raise SecretValuesRefused("the values file already exists: %s" % self.path)
        except OSError as exc:
            raise SecretValuesRefused("the values file could not be created: %s (%s)" % (self.path, describe(exc)))
        self._fh = os.fdopen(fd, "w", encoding="utf-8")
        OPEN_VALUES.append(self)

    def add(self, finding_id, locator, value):
        if not self.enabled:
            return
        # ensure_ascii: a file name that is not UTF-8 is a lone surrogate to Python; an escape
        # reads back, a raw write cannot.
        self._fh.write(dumps({"finding_id": finding_id, **locator, "run": self.run, "value": value}))
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
            "format": VALUES_FORMAT if self.enabled else None,
        }


def open_values(args):
    """The values file, or a refusal as JSON: write_values must be true or false."""
    wanted = args.get("write_values", False)
    if not isinstance(wanted, bool):
        fail("write_values must be true or false")
    try:
        return SecretValues(wanted)
    except SecretValuesRefused as exc:
        fail(str(exc), write_values="refused", written=False)


def positive(args, name, default, maximum=None):
    value = args.get(name, default)
    if not isinstance(value, int) or isinstance(value, bool) or value < 1:
        fail("%s must be a positive integer" % name, **{name: value})
    if maximum is not None and value > maximum:
        fail("%s is at most %d" % (name, maximum), **{name: value})
    return value


def seconds(args, name, default, cap):
    """A time limit: finite, positive and at most `cap` (the tool's own limit less a margin, so that the
    answer is written before the harness stops the tool; NaN and Infinity would switch the clock off)."""
    value = args.get(name, default)
    if isinstance(value, bool) or not isinstance(value, (int, float)) or not math.isfinite(value) or value <= 0:
        fail("%s must be a positive finite number of seconds" % name, **{name: str(value)})
    if value > cap:
        fail("%s is at most %s seconds (the tool's own limit less the margin it needs to write its answer)" % (name, cap), **{name: value})
    return float(value)


def read_args():
    try:
        args = json.load(sys.stdin)
    except ValueError as exc:
        fail("arguments are not valid JSON", reason=str(exc))
    if not isinstance(args, dict):
        fail("arguments must be a JSON object")
    return args


def send(result):
    emit(dumps(result, indent=2))


def run_main(main):
    for number in STOP_SIGNALS:
        signal.signal(number, stop_handler)
    try:
        try:
            main()
        except SystemExit:
            raise
        except Exception as exc:  # never an empty or clean answer for a failure, and never a traceback
            fail("unexpected failure: " + (describe(exc) if isinstance(exc, OSError) else "%s: %s" % (type(exc).__name__, exc)))
    except Interrupted as stop:
        stopped(stop.signum)
# --- shared with the pack's other tools: end -----------------------------------------------

# BEGIN SHARED PLACE
# The same text is in every windows-forensics tool that keeps a result file (a windows-forensics test holds the copies equal).
# A result file that is there is never replaced by another result: a file of the same bytes is named again, any other result takes the next free
# <stem>-<n><suffix>. A result written at the same moment cannot be replaced either: taking a name fails when it is there.
# Only regular files are ever compared: both names are opened with O_NONBLOCK and O_NOFOLLOW and looked at with fstat before a byte is
# read, so a FIFO, a device, a directory or a link at a name (the caller's own results_to, say) is another result's and cannot hold the
# tool. The comparing of one call has PLACE_COMPARE_SECONDS in all; past it an earlier result is taken as different and this one takes
# the next free name (nothing is replaced, but an identical rerun may then be named anew).
# The name is taken with a hard link of the finished file, so it never holds an empty file, whatever stops the tool and when (SIGKILL
# included). Where the file system refuses the link, the name is taken with an exclusive create and the file is moved over it: a stop
# that unwinds (an exception) takes the empty name back while it is still the empty file this call made; a stop that ends the process
# without unwinding (SIGKILL, the handlers of the STOP block) between the create and the move leaves the empty name, and the next run takes -2.
PLACE_COMPARE_SECONDS = 5   # all the comparing one call to place_without_replacing does; past it an earlier result is taken as different


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
            x, y = fa.read(1 << 20), fb.read(1 << 20)
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


def _take_name(tmp, candidate):
    """Give the finished `tmp` the name `candidate` if it is free, and say whether it now has it (False: the name is taken, by a file, a
    link, a FIFO or a directory). The name is taken with a hard link, so it never holds an empty file; where the file system refuses the
    link it is taken with an exclusive create and the file is moved over it, and a stop that unwinds in between takes the empty name back."""
    try:
        os.link(tmp, candidate)
    except FileExistsError:
        return False
    except OSError:
        pass                                   # no hard links here: the older way, below
    else:
        try:
            os.unlink(tmp)
        except OSError:
            pass                               # the hidden name stays beside the placed file; the stop path of the page removes it
        return True
    fd = made = None
    try:
        fd = os.open(str(candidate), os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o600)
        made = os.fstat(fd)
        closing, fd = fd, None
        os.close(closing)
        os.replace(tmp, candidate)             # only replaces the empty file this call just made
        return True
    except FileExistsError:
        return False
    except BaseException:
        try:
            if made is None and fd is not None:
                made = os.fstat(fd)
        except OSError:
            pass
        try:
            if fd is not None:
                os.close(fd)
        except OSError:
            pass
        try:
            now = os.lstat(candidate)
            if made is not None and (now.st_mode & 0o170000) == 0o100000 and now.st_size == 0 and (now.st_dev, now.st_ino) == (made.st_dev, made.st_ino):
                os.unlink(candidate)           # the empty name this call took is not left behind
        except OSError:
            pass
        raise


def place_without_replacing(tmp, path):
    """Move the finished `tmp` to `path` and never replace what is there. A name that is taken (by a file, a link, a FIFO or a directory) is
    left as it is: a regular file of the same bytes is named again, any other result takes the next free <stem>-<n><suffix>. Returns the
    path that holds it. The comparing with earlier results has PLACE_COMPARE_SECONDS in all: past it an earlier result is taken as
    different and this one takes the next free name."""
    deadline = time.monotonic() + PLACE_COMPARE_SECONDS
    for n in range(1, 1000):
        candidate = path if n == 1 else path.with_name("%s-%d%s" % (path.stem, n, path.suffix))
        if _take_name(tmp, candidate):
            return candidate
        if not os.path.islink(candidate) and same_bytes(tmp, candidate, deadline):
            os.unlink(tmp)
            return candidate
    raise OSError("no free name beside %s" % path)
# END SHARED PLACE


# --- backup_materialise ---------------------------------------------------------------------------------------------------

SQLITE_MAGIC = b"SQLite format 3\x00"
FILE_ID = re.compile(r"[0-9a-fA-F]{40}")
DEFAULT_LIMIT = 200
INLINE_BYTES = 1 << 20
DEFAULT_MAX_SECONDS = 240
MAX_SECONDS_CAP = 255       # manifest.json timeout_seconds (300) less the work after the loops and the time to write the answer
READ_SHARE = 0.35           # the Manifest.db read ends at this share of max_seconds; the copying has the rest, up to COPY_SHARE
COPY_SHARE = 0.93
LOOK_EVERY = 1000
COUNT_SHARE = 0.1
CELL_CHARS = JUDGE_CHARS + 1
DEFAULT_MAX_FILES = 100000
MAX_FILES_CAP = 500000
DEFAULT_MAX_BYTES = 4 << 30
MAX_BYTES_CAP = 1 << 42
COMPONENT_BYTES = 255       # the longest name a file system holds
PATH_BYTES = 4096
MAX_COMPONENTS = 64
MAX_CLAIMS = 2000000        # names the layout may hold in all; past it a row is rejected, so the memory of one run is bounded
MAX_LIST = 1000             # entries of domains and paths
MAX_ARCHIVE_BYTES = 1 << 20
MAX_PLIST_BYTES = 4 << 20
MAX_REF_DEPTH = 12
COPY_CHUNK = 1 << 20
KINDS = {1: "file", 2: "directory", 4: "symlink"}
COMPANION_SUFFIXES = ("-wal", "-shm", "-journal")
PLACEHOLDER = "withheld-component"
ARGUMENTS = ("path", "copy_content", "all", "domains", "paths", "max_files", "max_bytes", "max_seconds", "limit")
# A row in one of these states is a file the selection named that the derivative does not hold (or, in a plan, would not hold).
NOT_HELD = ("missing", "directory", "symlink", "special", "unreadable", "refused_id", "rejected_path", "not_copied_max_bytes",
            "not_attempted_max_seconds", "not_attempted_write_stopped", "write_failed", "layout_full", "shard_not_a_directory")
BANNER = {"kind": "ios-backup-derivative", "tool": TOOL, "parser": PARSER,
          "layout": "files/<domain>/<relativePath>, each file under the name the backup's Manifest.db gave it; the one-line-per-row "
                    "account is the result file the tool's answer names",
          "is_not": "the phone's file system, an acquisition of the phone, or a copy of anything the backup does not hold"}


class OutOfTime(Exception):
    pass


class Budget(Exception):
    """A file was not copied because of a limit; `which` names it."""

    def __init__(self, which):
        Exception.__init__(self, which)
        self.which = which


class NotRegular(Exception):
    pass


class TreeFull(Exception):
    pass


def fd_flags(extra=0):
    return os.O_RDONLY | extra | getattr(os, "O_NONBLOCK", 0) | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0)


def open_regular(path, dir_fd=None):
    """(fd, fstat) of a regular file, opened without waiting and without following a link: a FIFO, a device or a link at the name
    is never read (a FIFO would hold the tool for ever)."""
    fd = os.open(path, fd_flags(), dir_fd=dir_fd)
    try:
        info = os.fstat(fd)
    except OSError:
        os.close(fd)
        raise
    if not stat.S_ISREG(info.st_mode):
        os.close(fd)
        raise NotRegular(stat.S_IFMT(info.st_mode))
    return fd, info


def read_plist(path):
    """(status, tree, reason): a backup's plain plist, read without following a link."""
    try:
        fd, info = open_regular(path)
    except FileNotFoundError:
        return "missing", None, None
    except NotRegular:
        return "unreadable", None, "not a regular file"
    except OSError as exc:
        if exc.errno == errno.ELOOP:
            return "link", None, "a symbolic link: not followed"
        return "unreadable", None, describe(exc)
    with os.fdopen(fd, "rb") as fh:
        if info.st_size > MAX_PLIST_BYTES:
            return "too_large", None, "%d bytes, over %d" % (info.st_size, MAX_PLIST_BYTES)
        try:
            data = fh.read(MAX_PLIST_BYTES + 1)
            if len(data) > MAX_PLIST_BYTES:
                return "too_large", None, "over %d bytes" % MAX_PLIST_BYTES
            return "ok", plistlib.loads(data), None
        except Exception as exc:  # a parser fault on hostile input is that file's status, not a crash
            return "unreadable", None, describe(exc)


class Archive:
    """An NSKeyedArchiver graph: the root object, and values followed through UID references with a depth bound and a cycle check
    (manifest_db's reader, copied)."""

    def __init__(self, tree):
        self.objects = None
        self.root = None
        self.reason = None
        self.status = "ok"
        if not isinstance(tree, dict) or tree.get("$archiver") != "NSKeyedArchiver":
            self.status, self.reason = "not_keyed_archive", "no $archiver of NSKeyedArchiver at the top"
            return
        objects, top = tree.get("$objects"), tree.get("$top")
        if not isinstance(objects, list) or not isinstance(top, dict):
            self.status, self.reason = "malformed", "$objects is not a list or $top is not a dictionary"
            return
        self.objects = objects
        ref = top.get("root")
        if ref is None:
            if len(top) != 1:
                self.status, self.reason = "malformed", "$top has no root and more or fewer than one entry"
                return
            ref = next(iter(top.values()))
        try:
            root = self.deref(ref)
        except ValueError as exc:
            self.status, self.reason = "malformed", str(exc)
            return
        if not isinstance(root, dict):
            self.status, self.reason = "malformed", "the root object is a %s, not a dictionary" % type(root).__name__
            return
        self.root = root

    def deref(self, value):
        seen = set()
        while isinstance(value, plistlib.UID):
            index = value.data
            if index in seen:
                raise ValueError("a reference cycle at object %d" % index)
            if len(seen) >= MAX_REF_DEPTH:
                raise ValueError("references deeper than %d" % MAX_REF_DEPTH)
            if not 0 <= index < len(self.objects):
                raise ValueError("a reference to object %d, and the archive has %d" % (index, len(self.objects)))
            seen.add(index)
            value = self.objects[index]
        return value

    def get(self, key):
        if key not in self.root:
            return None, False
        return self.deref(self.root[key]), True


def manifest_size_mode(blob):
    """(status, size, mode) from the keyed archive of a `file` cell: what the Manifest says the file was."""
    if not isinstance(blob, (bytes, bytearray)):
        return "absent", None, None
    try:
        archive = Archive(plistlib.loads(bytes(blob)))
    except Exception:
        return "unreadable", None, None
    if archive.root is None:
        return archive.status, None, None
    try:
        size, found_size = archive.get("Size")
        mode, found_mode = archive.get("Mode")
    except ValueError:
        return "malformed", None, None
    size = size if found_size and isinstance(size, int) and not isinstance(size, bool) else None
    mode = mode if found_mode and isinstance(mode, int) and not isinstance(mode, bool) else None
    return "ok", size, mode


def b64(text):
    return base64.b64encode(text.encode("utf-8", "surrogateescape")).decode("ascii")


def nbytes(text):
    return len(text.encode("utf-8", "surrogateescape"))


# --- where the output goes ---------------------------------------------------------------------------------------------------

def output_base():
    """(Path, shown prefix): $OUT in a job, work/<agent> outside one (as the pack's other tools)."""
    job, out = os.environ.get("JOB_ID"), os.environ.get("OUT")
    if job and out:
        return Path(out), "store/jobs/%s/out" % safe_name(job)
    base = Path("work") / safe_name(os.environ.get("AGENT_ID") or "tool")
    return base, str(base)


class ResultFile:
    """One line per row, written as the row is known and flushed at once, so that the count the answer gives is the lines the file
    holds, whatever ends the run. The inline page is a prefix. The file takes its name without replacing an earlier one (PLACE); the
    hidden temporary is registered for removal before it exists and is removed by a failure and by a stop."""

    def __init__(self, base, shown_base, key, limit, byte_limit):
        self.limit, self.byte_limit = limit, byte_limit
        self.page, self.page_bytes, self.rows, self.bytes_bound_hit = [], 0, 0, False
        digest = hashlib.sha256(dumps([key, NONCE], sort_keys=True).encode("utf-8")).hexdigest()[:16]
        name = "%s-%s.jsonl" % (TOOL, digest)
        self.dir = base / "tool-output"
        self.target = self.dir / name
        self.shown_dir = shown_base + "/tool-output/"
        self.shown = self.shown_dir + name
        self._out = None
        self._tmp = None
        self._cleanup = None
        OPEN_PAGES.append(self)

    def open(self):
        if self._out is not None:
            return
        self.dir.mkdir(parents=True, exist_ok=True)
        fd, name = tempfile.mkstemp(dir=str(self.dir), prefix=".%s-" % TOOL)
        self._tmp = Path(name)
        tmp = self._tmp
        self._cleanup = lambda: tmp.unlink() if tmp.exists() or tmp.is_symlink() else None
        CLEANUP.append(self._cleanup)
        self._out = os.fdopen(fd, "w", encoding="utf-8")

    def add(self, row):
        self.open()
        text = dumps(row)
        self._out.write(text)
        self._out.write("\n")
        self._out.flush()
        self.rows += 1
        if len(self.page) < self.limit and self.page_bytes + len(text) <= self.byte_limit:
            self.page.append(row)
            self.page_bytes += len(text)
        elif len(self.page) < self.limit:
            self.bytes_bound_hit = True

    def finish(self):
        self.open()
        out, self._out = self._out, None
        out.flush()
        os.fsync(out.fileno())
        out.close()
        placed = place_without_replacing(self._tmp, self.target)
        if self._cleanup in CLEANUP:
            CLEANUP.remove(self._cleanup)
        result = {"rows": self.rows, "returned": len(self.page), "truncated": self.rows > len(self.page),
                  "inline_byte_limit": self.byte_limit, "all_results": self.shown_dir + placed.name,
                  "all_results_format": "JSON Lines, one row of the backup's map per line"}
        if self.bytes_bound_hit:
            result["inline_bounded_by_bytes"] = True
        if placed != self.target:
            result["earlier_result_kept"] = self.shown
        return result


def refuse_linked_dir(path, what):
    """A directory this tool writes into is never reached through a link planted in the output directory: lstat, not stat."""
    try:
        info = os.lstat(path)
    except FileNotFoundError:
        return
    except OSError as exc:
        fail("%s could not be examined: %s" % (what, describe(exc)))
    if stat.S_ISLNK(info.st_mode) or not stat.S_ISDIR(info.st_mode):
        fail("%s in the output directory is a symbolic link or not a directory: the tool does not write through it" % what, written=False)


def make_dirs_nofollow(path):
    """mkdir -p, then refuse a link at any component of what was made (the tool's own output directory)."""
    os.makedirs(path, mode=0o700, exist_ok=True)
    walk = Path(path)
    while walk != walk.parent and str(walk) not in (".", ""):
        if walk.is_symlink():
            raise OSError(errno.ELOOP, "a symbolic link in the output path", str(walk))
        walk = walk.parent


def choose_values_name(out):
    global VALUES_NAME
    stem = "backup-materialise-values"
    for n in range(1, 1000):
        name = "%s%s.jsonl" % (stem, "" if n == 1 else "-%d" % n)
        if not os.path.lexists(os.path.join(out, name)):
            VALUES_NAME = name
            return
    fail("no free name for the values file in the output directory")


# --- the layout: names, collisions ------------------------------------------------------------------------------------------

def fold(text):
    return unicodedata.normalize("NFC", text).casefold()


def vary(name, n, is_file):
    """name-<n>.ext (or name-<n> for a directory), cut so the component stays within COMPONENT_BYTES."""
    stem, suffix = os.path.splitext(name) if is_file else (name, "")
    extra = "-%d%s" % (n, suffix)
    room = COMPONENT_BYTES - nbytes(extra)
    raw = stem.encode("utf-8", "surrogateescape")
    if len(raw) > room:
        stem = raw[:max(room, 1)].decode("utf-8", "surrogateescape")
    return stem + extra


class Tree:
    """The names the layout holds, so that two rows never meet on one name, case-folding ones included (a file system that folds case
    would merge them). Keyed by a digest chain of the folded components, so memory is linear in the names and not in their depth.
    A directory met again in another spelling is the first spelling (said in the row). A file whose name is taken, as a file or as a
    directory, takes name-2, name-3 ...; the next number to try is remembered per name, so a hostile run of one name is linear."""

    def __init__(self):
        self.claimed = {}

    def resolve(self, parts):
        """(final components, notes)"""
        final, notes, key = [], [], b""
        for i, part in enumerate(parts):
            last = i == len(parts) - 1
            name = part
            origin = None
            while True:
                k = hashlib.blake2b(key + b"\0" + fold(name).encode("utf-8", "surrogatepass"), digest_size=16).digest()
                have = self.claimed.get(k)
                if have is None:
                    if len(self.claimed) >= MAX_CLAIMS:
                        raise TreeFull()
                    self.claimed[k] = ["file" if last else "dir", name, 2]
                    break
                if not last and have[0] == "dir":
                    if have[1] != part:
                        notes.append({"kind": "case_fold", "component": i, "note": "the directory was met in another spelling and is the first one"})
                    name = have[1]
                    break
                # taken: a file by a file, or a file and a directory
                if origin is None:
                    origin = have
                    notes.append({"kind": ("duplicate_path" if have[1] == part else "case_fold") if (last and have[0] == "file")
                                  else "file_vs_directory", "component": i})
                name = vary(part, origin[2], last)
                origin[2] += 1
            final.append(name)
            key = k
        return final, notes


def check_names(domain, relative, kind):
    """None if a domain and a relative path may be written under the layout, else the reason they may not."""
    if len(domain) > JUDGE_CHARS or len(relative) > JUDGE_CHARS:
        return "a name too long to be a path (over %d characters)" % JUDGE_CHARS
    if not domain:
        return "an empty domain"
    if domain in (".", "..") or "/" in domain or "\0" in domain:
        return "the domain is not one safe component (a dot name, a slash or a NUL)"
    if nbytes(domain) > COMPONENT_BYTES:
        return "the domain is over %d bytes" % COMPONENT_BYTES
    if not relative:
        return "an empty relative path"
    if "\0" in relative:
        return "the relative path holds a NUL"
    if relative.startswith("/"):
        return "the relative path is absolute"
    parts = relative.split("/")
    if len(parts) > MAX_COMPONENTS:
        return "more than %d components" % MAX_COMPONENTS
    for part in parts:
        if part in ("", ".", ".."):
            return "a component that is empty, '.' or '..'"
        if nbytes(part) > COMPONENT_BYTES:
            return "a component of over %d bytes" % COMPONENT_BYTES
    if nbytes(relative) > PATH_BYTES:
        return "a path of over %d bytes" % PATH_BYTES
    return None


# --- the blobs ------------------------------------------------------------------------------------------------------------------

def classify(dir_fd, name, layout):
    """(state, layout, fd, size) for `name` in the directory `dir_fd`; never through a link."""
    try:
        info = os.stat(name, dir_fd=dir_fd, follow_symlinks=False)
    except FileNotFoundError:
        return None
    except OSError:
        return "unreadable", layout, None, None
    if stat.S_ISLNK(info.st_mode):
        return "symlink", layout, None, None
    if stat.S_ISDIR(info.st_mode):
        return "directory", layout, None, None
    if not stat.S_ISREG(info.st_mode):
        return "special", layout, None, None
    try:
        fd, opened = open_regular(name, dir_fd=dir_fd)
    except FileNotFoundError:
        return None
    except (NotRegular, OSError):
        return "special", layout, None, None
    return "present", layout, fd, opened.st_size


def open_blob(root_fd, file_id):
    """The blob a file id names, looked for in the sharded and then the flat layout, through directory descriptors and without following
    a link: (state, layout, fd or None, size or None)."""
    try:
        shard = os.open(file_id[:2], fd_flags(os.O_DIRECTORY), dir_fd=root_fd)
    except FileNotFoundError:
        shard = None
    except OSError:
        return "shard_not_a_directory", "sharded", None, None
    if shard is not None:
        try:
            got = classify(shard, file_id, "sharded")
        finally:
            os.close(shard)
        if got is not None:
            return got
    got = classify(root_fd, file_id, "flat")
    return got if got is not None else ("missing", None, None, None)


def ensure_dir(root_fd, parts):
    """The descriptor of the directory root/parts, made one component at a time without following a link (mode 0700)."""
    fd = os.dup(root_fd)
    try:
        for part in parts:
            try:
                os.mkdir(part, 0o700, dir_fd=fd)
            except FileExistsError:
                pass
            nxt = os.open(part, fd_flags(os.O_DIRECTORY), dir_fd=fd)
            os.close(fd)
            fd = nxt
        return fd
    except BaseException:
        os.close(fd)
        raise


TEMP_COUNTER = [0]


def copy_blob(src_fd, files_fd, files_path, parts, budget_left, deadline):
    """Copy the blob open at src_fd to files/<parts> without replacing anything: written to a hidden temporary beside it (registered for
    removal before it is made), then given its name by PLACE. Returns (path it holds, bytes, sha256). Raises Budget when the bytes would
    pass `budget_left` or the clock `deadline` passes; the temporary is removed in every case."""
    dir_fd = ensure_dir(files_fd, parts[:-1])
    TEMP_COUNTER[0] += 1
    tmp_name = ".bm-%s-%d.tmp" % (NONCE, TEMP_COUNTER[0])
    directory = os.path.join(files_path, *parts[:-1]) if len(parts) > 1 else files_path
    tmp_path = os.path.join(directory, tmp_name)

    def remove():
        try:
            os.unlink(tmp_path)
        except FileNotFoundError:
            pass
    CLEANUP.append(remove)
    out_fd = None
    try:
        out_fd = os.open(tmp_name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0), 0o600, dir_fd=dir_fd)
        digest, total = hashlib.sha256(), 0
        while True:
            chunk = os.read(src_fd, COPY_CHUNK)
            if not chunk:
                break
            total += len(chunk)
            if total > budget_left:
                raise Budget("max_bytes")
            if time.monotonic() > deadline:
                raise Budget("max_seconds")
            digest.update(chunk)
            view = memoryview(chunk)
            while len(view):
                view = view[os.write(out_fd, view):]
        os.close(out_fd)
        out_fd = None
        placed = place_without_replacing(Path(tmp_path), Path(directory) / parts[-1])
        return placed, total, digest.hexdigest()
    finally:
        if out_fd is not None:
            os.close(out_fd)
        os.close(dir_fd)
        remove()
        if remove in CLEANUP:
            CLEANUP.remove(remove)


def write_banner(derivative_path):
    """derivative/derivative.json, with the same banner every run: an identical one is named again, never replaced."""
    text = (json.dumps(BANNER, sort_keys=True, indent=2) + "\n").encode("utf-8")
    fd, name = tempfile.mkstemp(dir=derivative_path, prefix=".bm-banner-")
    tmp = Path(name)
    CLEANUP.append(lambda: tmp.unlink() if tmp.exists() else None)
    with os.fdopen(fd, "wb") as fh:
        fh.write(text)
    return place_without_replacing(tmp, Path(derivative_path) / "derivative.json")


# --- Manifest.db, as manifest_db reads it ---------------------------------------------------------------------------------------

def stage(db, companions, base, deadline):
    """Copy the database and its -wal or -journal to a working directory of their own under tool-output, and return the copy's path. The
    copy is read-write for SQLite's recovery; the original is never opened for writing."""
    parent = base / "tool-output"
    parent.mkdir(parents=True, exist_ok=True)
    scratch = tempfile.mkdtemp(prefix="backup_materialise-working-copy-", dir=str(parent))
    CLEANUP.append(lambda: shutil.rmtree(scratch, ignore_errors=True))
    for suffix in ("",) + tuple(companions):
        fd, info = open_regular(db + suffix)
        with os.fdopen(fd, "rb") as source, open(os.path.join(scratch, "Manifest.db" + suffix), "wb") as target:
            while True:
                chunk = source.read(1 << 20)
                if not chunk:
                    break
                if time.monotonic() > deadline:
                    raise OutOfTime()
                target.write(chunk)
    return os.path.join(scratch, "Manifest.db"), scratch


class Guard:
    """Ends a long SQLite statement at the deadline or at a stop signal (manifest_db's Guard, copied): SQLite calls `look` every
    LOOK_EVERY steps and a true answer ends the statement. A stop signal that arrives while SQLite runs is taken as a flag and ends the
    statement; one that arrives anywhere else raises Interrupted at once."""

    def __init__(self):
        self.until = None
        self.expired = False
        self.signum = None
        self.inside = False
        self.before = {}

    def run(self, call, *args):
        self.inside = True
        try:
            return call(*args)
        finally:
            self.inside = False

    def look(self):
        if self.signum is not None:
            return 1
        if self.until is not None and time.monotonic() > self.until:
            self.expired = True
            return 1
        return 0

    def caught(self, signum, frame):
        for number in STOP_SIGNALS:
            signal.signal(number, signal.SIG_IGN)
        self.signum = signum
        if not self.inside:
            raise Interrupted(signum)

    def start(self):
        for number in STOP_SIGNALS:
            self.before[number] = signal.signal(number, self.caught)

    def finish(self):
        if self.signum is not None:
            raise Interrupted(self.signum)
        for number, handler in self.before.items():
            signal.signal(number, handler)
        self.before = {}

    def check(self):
        if self.signum is not None:
            raise Interrupted(self.signum)


CELL_BYTES = 4 * CELL_CHARS     # a character is at most four bytes, so this many bytes hold CELL_CHARS characters


def capped(column):
    """The first CELL_BYTES bytes of a text or blob cell, taken as BYTES: SQLite's substr on TEXT stops at a NUL, and a path with a NUL in
    it would come back cut at the NUL, as a different name from the one the Manifest holds. A longer cell is not read into Python."""
    return "CASE WHEN typeof(%s) IN ('text', 'blob') THEN substr(CAST(%s AS BLOB), 1, %d) ELSE %s END" % (column, column, CELL_BYTES, column)


def text_of(value):
    """A cell as text: bytes are decoded with surrogateescape (so a name that is not UTF-8 is kept exactly) and cut to CELL_CHARS."""
    if isinstance(value, (bytes, bytearray)):
        return bytes(value).decode("utf-8", "surrogateescape")[:CELL_CHARS]
    return value[:CELL_CHARS] if isinstance(value, str) else ("" if value is None else str(value))


def string_list(args, name):
    value = args.get(name)
    if value is None:
        return []
    if not isinstance(value, list) or len(value) > MAX_LIST or not all(isinstance(v, str) and 0 < len(v) <= PATH_BYTES for v in value):
        fail("%s must be a list of at most %d non-empty strings of at most %d characters" % (name, MAX_LIST, PATH_BYTES))
    return value


def main():
    started = time.monotonic()
    args = read_args()
    unknown = sorted(str(k) for k in args if k not in ARGUMENTS)
    if unknown:
        fail("the tool has no such argument: %s" % ", ".join(scrub(k) for k in unknown[:10]), arguments=list(ARGUMENTS))
    path = args.get("path")
    if not isinstance(path, str) or not path:
        fail("path is required: a backup directory or its Manifest.db")
    copy_content = args.get("copy_content", False)
    select_all = args.get("all", False)
    if not isinstance(copy_content, bool) or not isinstance(select_all, bool):
        fail("copy_content and all must be true or false")
    domains = string_list(args, "domains")
    paths = string_list(args, "paths")
    if select_all and (domains or paths):
        fail("all selects the whole map: do not give domains or paths with it")
    if not select_all and not domains and not paths:
        fail("name what to lay out: domains, paths, or all: true for the whole map (the tool never defaults to the whole map)")
    max_files = positive(args, "max_files", DEFAULT_MAX_FILES, MAX_FILES_CAP)
    max_bytes = positive(args, "max_bytes", DEFAULT_MAX_BYTES, MAX_BYTES_CAP)
    limit = positive(args, "limit", DEFAULT_LIMIT, 1 << 20)
    max_seconds = seconds(args, "max_seconds", DEFAULT_MAX_SECONDS, MAX_SECONDS_CAP)
    read_deadline = started + max_seconds * READ_SHARE
    copy_deadline = started + max_seconds * COPY_SHARE
    if copy_content:
        # Refused before anything is made: content is written only by a job that is run as secret output.
        if not (os.environ.get("JOB_ID") and os.environ.get("OUT")):
            fail("copy_content is refused outside a job: the content of a backup written here would be an ordinary file, not a sealed secret output. "
                 "Run this as job_run tool=%s with secret_output: true, and ask again there. Nothing was written." % TOOL, copy_content="refused", written=False)
        if os.environ.get("SECRET_OUTPUT") != "1":
            fail("copy_content is refused in a job that is not run as secret output (SECRET_OUTPUT is not 1). Run this as job_run tool=%s with "
                 "secret_output: true, and ask again there. Nothing was written." % TOOL, copy_content="refused", written=False)

    if not os.path.exists(path):
        fail("no such file or directory", path=shown(path, False))
    if os.path.isdir(path):
        root, db = path, os.path.join(path, "Manifest.db")
    elif os.path.basename(path) in ("Manifest.plist", "Info.plist", "Status.plist"):
        root = os.path.dirname(os.path.abspath(path))
        db = os.path.join(root, "Manifest.db")
    else:
        root, db = os.path.dirname(os.path.abspath(path)), path
    try:
        db_fd, db_info = open_regular(db)
    except FileNotFoundError:
        fail("no Manifest.db there", looked_at=shown(db, False),
             note="A backup made by iOS 9 or earlier keeps Manifest.mbdb instead, which this tool does not read; otherwise this is not a backup directory.")
    except NotRegular:
        fail("Manifest.db is not a regular file", looked_at=shown(db, False))
    except OSError as exc:
        if exc.errno == errno.ELOOP:
            fail("Manifest.db is a symbolic link: it is not followed", looked_at=shown(db, False))
        fail("Manifest.db could not be opened: %s" % describe(exc), looked_at=shown(db, False))
    with os.fdopen(db_fd, "rb") as fh:
        sample = fh.read(4096)
    db_bytes = db_info.st_size
    if sample[:16] != SQLITE_MAGIC:
        fail("Manifest.db is not a plaintext SQLite database: nothing can be laid out. The file is %d bytes. This tool does not decrypt." % db_bytes,
             db=shown(db, False))
    try:
        root_fd = os.open(root, fd_flags(os.O_DIRECTORY))      # the backup directory itself may be a link the caller named; what is in it is not followed
    except OSError as exc:
        fail("the backup directory could not be opened: %s" % describe(exc), path=shown(root, False))

    # --- the backup's plain files: encryption and completion ---------------------------------------------------------------
    status_m, manifest, why_m = read_plist(os.path.join(root, "Manifest.plist"))
    status_s, snapshot, why_s = read_plist(os.path.join(root, "Status.plist"))
    flag = manifest.get("IsEncrypted", "absent") if status_m == "ok" and isinstance(manifest, dict) else "unreadable"
    if flag is True:
        fail("Manifest.plist says the backup is encrypted (IsEncrypted is true): its blobs are ciphertext, and a derivative of them would be "
             "ciphertext under plain names. This tool does not decrypt.", encryption="encrypted",
             note="Give a decrypted backup, whose Manifest.plist does not say it is encrypted.")
    if flag is False:
        enc_state, enc_basis = "not_encrypted", "Manifest.plist IsEncrypted is false"
    else:
        enc_state = "unknown"
        enc_basis = ("Manifest.plist is %s%s" % (status_m, ": " + why_m if why_m else "")) if status_m != "ok" else (
            "Manifest.plist has no IsEncrypted key" if flag == "absent" else "Manifest.plist IsEncrypted is not a boolean")
    if status_s == "ok" and isinstance(snapshot, dict) and isinstance(snapshot.get("SnapshotState"), str):
        completion = {"state": "finished" if snapshot["SnapshotState"] == "finished" else "not_finished",
                      "basis": "Status.plist SnapshotState is %s" % json.dumps(scrub(snapshot["SnapshotState"]))}
    else:
        completion = {"state": "unknown", "basis": "Status.plist is %s%s" % (status_s, ": " + why_s if why_s else "") if status_s != "ok" else "Status.plist has no SnapshotState string"}
    observations = []
    if completion["state"] != "finished":
        observations.append("the backup's completion state is %s (%s): the derivative is of a backup that may not be whole" % (completion["state"].replace("_", " "), completion["basis"]))
    if enc_state == "unknown":
        observations.append("the encryption state is unknown (%s): if the backup is encrypted, the blobs laid out are ciphertext" % enc_basis)

    # A file cut short: SQLite reads the missing part of the last page as zeros, and a row there comes back as nothing.
    cut = False
    if len(sample) >= 100:
        page_size = struct.unpack_from(">H", sample, 16)[0] or 65536
        if page_size == 1:
            page_size = 65536
        declared = struct.unpack_from(">I", sample, 28)[0]
        valid_header = declared != 0 and struct.unpack_from(">I", sample, 24)[0] == struct.unpack_from(">I", sample, 92)[0]
        if page_size >= 512 and not page_size & (page_size - 1):
            if db_bytes % page_size:
                cut = True
                observations.append("Manifest.db ends %d bytes into a page of %d: the last page is cut short, and a row on it may read as nothing" % (db_bytes % page_size, page_size))
            if valid_header and db_bytes < declared * page_size:
                cut = True
                observations.append("Manifest.db holds %d pages and its header declares %d: it is cut short" % (db_bytes // page_size, declared))
    skipped_companions = 0
    manifest_companions = []
    for suffix in ("-wal", "-journal"):
        try:
            info = os.lstat(db + suffix)
        except OSError:
            continue
        if stat.S_ISLNK(info.st_mode):
            observations.append("Manifest.db%s is a symbolic link: not followed, not copied, and not applied" % suffix)
            skipped_companions += 1
        elif not stat.S_ISREG(info.st_mode):
            observations.append("Manifest.db%s is not a regular file: not opened, not copied, and not applied" % suffix)
            skipped_companions += 1
        elif info.st_size > 0:
            manifest_companions.append(suffix)

    base, shown_base = output_base()
    refuse_linked_dir(str(base / "tool-output"), "tool-output")
    result = ResultFile(base, shown_base, [shown(os.path.realpath(db), False), sorted(domains), sorted(paths), select_all, copy_content], limit, INLINE_BYTES)
    values = None
    if copy_content:
        try:
            base.mkdir(parents=True, exist_ok=True)
            choose_values_name(str(base))
            values = SecretValues(True)
        except SecretValuesRefused as exc:
            fail(str(exc), copy_content="refused", written=False)
        except OSError as exc:
            fail("the output directory could not be made: %s" % describe(exc))

    # --- read the map: the selected rows, and the rows that could be a selected file's companions ------------------------------
    guard = Guard()
    work_dir = None
    counts = {"files_in_manifest": None, "rows_read": 0, "rows_selected": 0, "selected_not_kept_max_files": 0, "companions_found": 0,
              "companions_not_considered": 0, "states": {}, "copied_files": 0, "copied_bytes": 0, "size_differs_from_manifest": 0,
              "rejected_paths": 0, "name_collisions": 0, "names_withheld": 0}
    read_error = None
    stopped_at_row = None
    selected_rows, companion_index = [], {}
    wanted_domains = set(domains)
    path_exact = set(p for p in paths if not p.endswith("/"))
    path_prefix = tuple(p for p in paths if p.endswith("/"))
    snapshot_kind = "the main file only (no -wal or -journal beside it)"
    try:
        opened = db
        if manifest_companions:
            opened, work_dir = stage(db, manifest_companions, base, read_deadline)
            snapshot_kind = "the main file and %s, copied to a working directory and opened there" % " and ".join(manifest_companions)
        uri = "file:%s?%s" % (opened.replace("%", "%25").replace("?", "%3f").replace("#", "%23"), "mode=rw" if manifest_companions else "mode=ro&immutable=1")
        connection = sqlite3.connect(uri, uri=True)
        guard.until = read_deadline
        guard.start()
        connection.set_progress_handler(guard.look, LOOK_EVERY)
        connection.text_factory = lambda raw: raw.decode("utf-8", "surrogateescape")
        tables = [r[0] for r in guard.run(lambda: list(connection.execute("SELECT name FROM sqlite_master WHERE type = 'table'")))]
    except OutOfTime:
        fail("max_seconds passed while Manifest.db was being copied to a working directory: nothing is laid out.")
    except (sqlite3.Error, OSError) as exc:
        guard.check()
        if guard.expired:
            fail("max_seconds passed while Manifest.db was being opened: nothing is laid out.", db=shown(db))
        fail("Manifest.db would not open as SQLite", db=shown(db), reason=describe(exc) if isinstance(exc, OSError) else scrub(str(exc)), note="Nothing is laid out.")
    if "Files" not in tables:
        fail("Manifest.db has no Files table", tables=[scrub(t) for t in tables[:50]])
    guard.until = min(read_deadline, time.monotonic() + max_seconds * COUNT_SHARE)
    try:
        counts["files_in_manifest"] = guard.run(lambda: connection.execute("SELECT coalesce(sum(1), 0) FROM Files NOT INDEXED").fetchone()[0])
    except sqlite3.Error:
        guard.check()
        observations.append("the rows of the Files table were not all counted in the time given to the count: files_in_manifest is unknown, and the read goes on")
    guard.expired = False
    guard.until = read_deadline
    file_cell = ("typeof(file), CASE WHEN typeof(file) = 'blob' AND length(file) <= %d THEN file END" % MAX_ARCHIVE_BYTES)
    names = "%s, %s, %s, flags, %s FROM Files NOT INDEXED" % (capped("fileID"), capped("domain"), capped("relativePath"), file_cell)
    rows = iter(())
    with_rowid = True
    try:
        try:
            rows = iter(guard.run(connection.execute, "SELECT rowid, " + names))
        except sqlite3.OperationalError:
            guard.check()
            if guard.expired:
                raise
            with_rowid = False
            rows = iter(guard.run(connection.execute, "SELECT " + names))
    except sqlite3.Error:
        guard.check()
        if not guard.expired:
            raise
        stopped_at_row = 0
    while stopped_at_row is None:
        try:
            row = guard.run(next, rows)
        except StopIteration:
            break
        except sqlite3.Error as exc:
            guard.check()
            if guard.expired:
                stopped_at_row = counts["rows_read"]
                break
            read_error = "%s%s after %d rows" % (type(exc).__name__, " (" + exc.sqlite_errorname + ")" if getattr(exc, "sqlite_errorname", None) else "", counts["rows_read"])
            break
        guard.check()
        if time.monotonic() > read_deadline:
            stopped_at_row = counts["rows_read"]
            break
        counts["rows_read"] += 1
        rowid = row[0] if with_rowid else None
        file_id, domain, relative, flags, file_type, blob = (row[1:] if with_rowid else row)
        file_id, domain, relative = text_of(file_id), text_of(domain), text_of(relative)
        # Selection looks at the names as they are printed, so a withheld component cannot be asked about.
        domain_s, relative_s = shown(domain, False), shown(relative, False)
        chosen = select_all or (
            (not wanted_domains or domain_s in wanted_domains)
            and (not paths or relative_s in path_exact or (path_prefix and relative_s.startswith(path_prefix))))
        if chosen:
            counts["rows_selected"] += 1
            if len(selected_rows) >= max_files:
                counts["selected_not_kept_max_files"] += 1
                continue
            mstatus, msize, mmode = manifest_size_mode(blob) if file_type == "blob" else ("absent", None, None)
            selected_rows.append((rowid, file_id, domain, relative, flags, msize, mmode))
        elif relative.endswith(COMPANION_SUFFIXES) and len(relative) <= JUDGE_CHARS:
            if len(companion_index) >= max_files:
                counts["companions_not_considered"] += 1
                continue
            mstatus, msize, mmode = manifest_size_mode(blob) if file_type == "blob" else ("absent", None, None)
            companion_index.setdefault((domain, relative), (rowid, file_id, domain, relative, flags, msize, mmode))
    connection.close()
    guard.finish()
    if work_dir:
        run_cleanup()      # the working copy of Manifest.db is not needed any more
        work_dir = None

    # The companions of the selected files, resolved through the Manifest: same domain, relativePath plus the suffix.
    plan = []
    seen_ids = set()
    for item in selected_rows:
        if item[1] not in seen_ids:
            seen_ids.add(item[1])
            plan.append((item, "selected", None))
    for item, _how, _parent in list(plan):
        for suffix in COMPANION_SUFFIXES:
            if len(plan) >= max_files:
                break
            found = companion_index.get((item[2], item[3] + suffix))
            if found is not None and found[1] not in seen_ids:
                seen_ids.add(found[1])
                plan.append((found, "companion", item[1]))
                counts["companions_found"] += 1

    # --- lay out -----------------------------------------------------------------------------------------------------------
    files_fd = None
    files_path = None
    if copy_content:
        try:
            derivative_path = str(base / "derivative")
            files_path = str(base / "derivative" / "files")
            make_dirs_nofollow(files_path)
            files_fd = os.open(files_path, fd_flags(os.O_DIRECTORY))
            write_banner(derivative_path)
        except OSError as exc:
            fail("the derivative directory could not be made: %s" % describe(exc))
    tree = Tree()
    state_counts = counts["states"]
    collisions = []
    write_stopped = False
    out_of_budget = False
    clock_stopped = False
    bytes_left = max_bytes
    for position, (item, how, parent) in enumerate(plan):
        rowid, file_id, domain, relative, flags, msize, mmode = item
        valid = bool(FILE_ID.fullmatch(file_id))
        kind = KINDS.get(flags, flags)
        domain_s, relative_s = shown(domain), shown(relative)
        withheld = domain_s != domain or relative_s != relative
        if withheld:
            counts["names_withheld"] += 1
        record = {"file_id": scrub(file_id) if len(file_id) <= JUDGE_CHARS else WITHHELD_LONG, "file_id_valid": valid, "domain": domain_s,
                  "relative_path": relative_s,
                  "domain_b64": None if withheld or len(domain) > JUDGE_CHARS else b64(domain),
                  "path_b64": None if withheld or len(relative) > JUDGE_CHARS else b64(relative),
                  "name_withheld": withheld, "selected_by": "all" if select_all else ("companion_of:" + parent if how == "companion" else "selection"),
                  "flags": flags if isinstance(flags, (int, str)) or flags is None else str(flags), "kind": kind if isinstance(kind, (int, str)) else str(kind),
                  "manifest_rowid": rowid, "manifest_size": msize, "manifest_mode": mmode, "source": "Manifest.db", "parser": PARSER}
        state = None
        if time.monotonic() > copy_deadline:
            clock_stopped = True
        why = check_names(domain, relative, kind) if state is None else None
        if kind in ("directory", "symlink"):
            state = "not_applicable"       # the manifest says the entry is a directory or a link: there is no blob to lay out
            record["reason"] = "the Manifest entry is a %s, not a file" % kind
        elif clock_stopped:
            state = "not_attempted_max_seconds"
        elif write_stopped:
            state = "not_attempted_write_stopped"
        elif not valid:
            state = "refused_id"
            record["reason"] = "a file id that is not 40 hexadecimal digits is never joined to a path"
        elif why:
            state = "rejected_path"
            record["reason"] = why
            counts["rejected_paths"] += 1
        if state is None:
            # the name in the layout: withheld components are the placeholder
            real_parts = [domain] + relative.split("/")
            shown_parts = [shown(domain, False)] + shown(relative, False).split("/")
            parts = [PLACEHOLDER if s != r else r for r, s in zip(real_parts, shown_parts)]
            try:
                final, notes = tree.resolve(parts)
            except TreeFull:
                state = "layout_full"
                record["reason"] = "the layout holds %d names, the most one run keeps" % MAX_CLAIMS
            else:
                record["derivative_path"] = "files/" + "/".join(final)
                if notes:
                    record["name_collision"] = notes
                    counts["name_collisions"] += 1
        if state is None:
            blob_state, layout, src_fd, size = open_blob(root_fd, file_id)
            record["blob"] = blob_state
            if layout:
                record["blob_layout"] = layout
            if blob_state != "present":
                state = blob_state
            else:
                record["blob_bytes"] = size
                if msize is not None:
                    record["size_matches_manifest"] = msize == size
                try:
                    if not copy_content:
                        state = "planned"
                    elif size > bytes_left:
                        state = "not_copied_max_bytes"
                        out_of_budget = True
                    else:
                        try:
                            placed, total, digest = copy_blob(src_fd, files_fd, files_path, final, bytes_left, copy_deadline)
                        except Budget as stop:
                            if stop.which == "max_bytes":
                                state, out_of_budget = "not_copied_max_bytes", True
                            else:
                                state, clock_stopped = "not_attempted_max_seconds", True
                            record["reason"] = "stopped by %s while the file was being copied: no part of it is in the layout" % stop.which
                        except OSError as exc:
                            state = "write_failed"
                            record["reason"] = describe(exc)
                            if getattr(exc, "errno", None) in (errno.ENOSPC, errno.EDQUOT, errno.EFBIG):
                                write_stopped = True
                        else:
                            state = "copied"
                            bytes_left -= total
                            counts["copied_files"] += 1
                            counts["copied_bytes"] += total
                            record["sha256"] = digest
                            record["derivative_bytes"] = total
                            if placed.name != final[-1]:
                                record["derivative_path"] = "files/" + "/".join(final[:-1] + [placed.name])
                                record.setdefault("name_collision", []).append({"kind": "name_taken_on_disk", "component": len(final) - 1})
                                counts["name_collisions"] += 1
                            if total != size:
                                state = "changed_during_read"
                                record["reason"] = "read %d bytes, and the blob was %d when it was opened" % (total, size)
                            if msize is not None and msize != total:
                                counts["size_differs_from_manifest"] += 1
                finally:
                    os.close(src_fd)
        record["state"] = state
        state_counts[state] = state_counts.get(state, 0) + 1
        if record.get("name_collision"):
            collisions.append({"file_id": record["file_id"], "derivative_path": record.get("derivative_path"), "notes": record["name_collision"]})
        if withheld and values is not None:
            values.add(file_id, {"manifest_rowid": rowid}, {"domain": domain, "relative_path": relative})
        result.add(record)
    if files_fd is not None:
        os.close(files_fd)
    os.close(root_fd)
    if values is not None:
        values.close()

    # --- the answer --------------------------------------------------------------------------------------------------------
    paging = result.finish()
    held = counts["copied_files"] if copy_content else state_counts.get("planned", 0)
    not_held = {k: n for k, n in state_counts.items() if k in NOT_HELD or k == "changed_during_read"}
    if counts["size_differs_from_manifest"]:
        observations.append("%d copied blob(s) differ in size from the Size the Manifest's keyed archive records (size_matches_manifest on the row)" % counts["size_differs_from_manifest"])
    if counts["name_collisions"]:
        observations.append("%d row(s) share a name in the layout with another row (a duplicate path, a name that differs only in case, or a file and a directory): each was given its own name and says so in name_collision" % counts["name_collisions"])
    if counts["selected_not_kept_max_files"]:
        observations.append("%d selected row(s) past max_files (%d) were counted and not laid out" % (counts["selected_not_kept_max_files"], max_files))
    if stopped_at_row is not None:
        observations.append("max_seconds passed after %d rows of Manifest.db: the rest of the map is not read, so rows after it are in no selection" % stopped_at_row)
    reasons = []
    if stopped_at_row is not None:
        reasons.append("the time limit stopped the read of Manifest.db")
    if read_error is not None:
        reasons.append("a damaged page ended the read (%s)" % read_error)
    if cut:
        reasons.append("Manifest.db is cut short")
    if skipped_companions:
        reasons.append("a Manifest.db companion that is a link was not applied")
    if counts["selected_not_kept_max_files"]:
        reasons.append("max_files was reached")
    if counts["companions_not_considered"]:
        reasons.append("%d possible companion row(s) were not considered (max_files)" % counts["companions_not_considered"])
    if not_held:
        reasons.append("%d selected row(s) are not in the layout (%s)" % (sum(not_held.values()), ", ".join("%s %d" % kv for kv in sorted(not_held.items()))))
    if clock_stopped:
        reasons.append("the time limit stopped the copying")
    if out_of_budget:
        reasons.append("max_bytes was reached")
    if enc_state == "unknown":
        reasons.append("the encryption state is unknown")
    if completion["state"] == "not_finished":
        reasons.append("the backup did not finish")
    if status_m == "too_large" or status_s == "too_large":
        reasons.append("a plain plist is over %d bytes and was not read" % MAX_PLIST_BYTES)
    if not plan and not reasons:
        reasons.append("the selection matched no row of Manifest.db")
    complete = not reasons
    status = "complete" if complete else "partial"
    if complete:
        status_basis = ("Manifest.db was read to its end; all %d selected row(s) %s; %s" % (
            len(plan), "were copied to the layout" if copy_content else "are present in the backup (this is a plan: copy_content was false and nothing was copied)",
            "the backup finished" if completion["state"] == "finished" else "the backup's completion is unknown"))
    else:
        status_basis = "partial because " + "; ".join(reasons) + " (see observations and counts)"
    answer = {
        "path": shown(path), "backup_root": shown(root), "manifest_db": shown(db), "parser": PARSER,
        "status": status, "status_basis": status_basis,
        "copy_content": copy_content,
        "encryption": {"state": enc_state, "basis": enc_basis,
                       "decryption": "not provided: this tool carries no decryption backend and reads no password"},
        "completion": completion,
        "selection": {"all": select_all, "domains": [scrub(d) for d in domains], "paths": [scrub(p) for p in paths],
                      "matched_on": "the names as they are printed (a withheld component is its placeholder)",
                      "companions": "for each selected file its -wal, -shm and -journal, found through the Manifest (same domain, relativePath plus the suffix)"},
        "limits": {"max_files": max_files, "max_bytes": max_bytes, "max_seconds": max_seconds},
        "manifest_db_file": {"bytes": db_bytes, "snapshot": snapshot_kind},
        "derivative": ({"root": shown_base + "/derivative", "files": shown_base + "/derivative/files", "banner": shown_base + "/derivative/derivative.json",
                        "values_file": values.shown, "values_written": values.written} if copy_content else
                       {"written": False, "note": "copy_content was false: nothing was copied and no derivative was made; the result file is the plan"}),
        "counts": counts, "rows_in_plan": len(plan), "held_in_layout": held,
        "observations": observations, "stopped_at_row": stopped_at_row, "read_error": read_error,
        "entries": result.page, "entry_count": result.rows,
        "collisions": collisions[:limit], "collision_count": len(collisions), "collisions_in": paging["all_results"] if collisions else None,
        "pages": {"entries": paging}, "truncated": paging["truncated"] or len(collisions) > limit,
        "paths_withheld": PATHS_WITHHELD[0],
        "note": "This is a derivative of what a backup holds, laid out by the backup's own map; it is not the phone's file system and not an acquisition of the phone. "
                "Cite the file id, the domain and the relative path (as the phone named the file) and the Manifest row, with the backup it came from. "
                "path_b64 and domain_b64 are the names' bytes in base64, null for a name that is withheld. A path component shaped like a recovery password "
                "is withheld from every channel; with copy_content its real name is only in the 0600 values file.",
    }
    CLEANUP.clear()
    send(answer)


if __name__ == "__main__":
    exit_code = 0
    try:
        run_main(main)
    except SystemExit as stop:
        exit_code = _code(stop)
    _leave(exit_code)
