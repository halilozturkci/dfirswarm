#!/usr/bin/env python3
"""Stream a binary for ASCII and UTF-16LE needles and say where each one is.

The answer is a list of locators: for every occurrence, an id, the offset it starts at,
the needle and encoding that matched and how many bytes of context lie around it.
No context bytes come back by default. Context around a hit in a memory image, a
pagefile or unallocated space is where a password, a token or a card number sits, so
the bytes are written only when the caller asks (`write_values: true`), only in a job,
and only to a file under $OUT (JSON Lines, mode 0600, created new), which the skill
says to run with `secret_output: true`. The answer then says where that file is and
that it holds secret values, not what they are. Never put a secret in `needles`: the
arguments of a call are recorded in the trace.

What it finds, exactly: every occurrence of each needle, by the offset it starts at,
overlapping occurrences included, so the count does not depend on `chunk`. Matching is
case-sensitive and on the needle's bytes: ASCII/UTF-8 as given, and the same text as
UTF-16LE. Each read keeps back the bytes a needle or its context could still need, so a
match or its context cut by a read boundary is found once, whole. `scanned_*` and
`bytes_scanned` are the bytes actually read, not the range asked for.

The scan has a clock (`max_seconds`, default 100, at most 110, inside the manifest's 120): a scan that reaches it answers for the
range it decided, says `complete: false` and `status: partial`, and gives `next_start`, the offset to go on from (`start`). The clock is read between reads and every CLOCK_EVERY matches. Every
occurrence that starts before `next_start` is reported once; one that starts at or after it is the next scan's, found there once.
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


import errno
import hashlib
import json
import os
import re
import sys
import tempfile
import time
from collections import defaultdict
from pathlib import Path


# BEGIN SHARED STOP
# The same text is in every tool that carries this block (tests/pack-shared-stop.test.ts holds the copies equal). SIGTERM, SIGINT and SIGHUP end the tool with JSON
# (status failed with interrupted true: a stop is not a status, the statuses are complete, partial and failed; exit 128 + the signal) and remove the temporary file a page was writing; the tool's own clock (set_deadline) is below the manifest's.
# The handlers are in as soon as the module has run as far as this block, with a minimal last word until main() installs the tool's own (only
# the start of the interpreter and the compiling of the file come before it). The first signal counts: a second one does nothing while the
# first is answered. print_answer holds the stop signals back while the answer is printed, so exactly one complete document is written
# (the ransomware tools print through it; the windows tools hold the signals in the emit of their boundary block, and carry this text unused).
import signal
import time

STOP = {"last_word": None, "deadline": None}


def set_deadline(seconds):
    STOP["deadline"] = time.monotonic() + seconds


def out_of_time():
    return STOP["deadline"] is not None and time.monotonic() > STOP["deadline"]


def _on_signal(signum, _frame):
    for other in (signal.SIGTERM, signal.SIGINT, signal.SIGHUP):
        signal.signal(other, signal.SIG_IGN)
    for page in list(globals().get("PAGES", ())):
        tmp = getattr(page, "_tmp", None)
        if tmp is not None:
            try:
                os.unlink(tmp)
            except OSError:
                pass
    last_word = STOP["last_word"]
    if last_word:
        try:
            last_word(signum)
        except Exception:  # noqa: BLE001 - a last word is best effort
            pass
    answer_a_stop(signum)
    os._exit(128 + signum)


def install_signal_handlers(last_word=None):
    STOP["last_word"] = last_word
    for signum in (signal.SIGTERM, signal.SIGINT, signal.SIGHUP):
        signal.signal(signum, _on_signal)


def interrupted_answer(signum, **extra):
    print(json.dumps({"error": "stopped by signal %d before the answer was complete" % signum, "status": "failed", "interrupted": True,
                      "status_basis": "the tool was stopped by signal %d; nothing it had read is an answer" % signum,
                      "signal": signum, **extra}), flush=True)


def print_answer(answer, **dumps_kwargs):
    """Print the answer with the stop signals held back: a signal that came in the middle of the write would end the process there, with the
    answer cut. The tool ends by itself right after, so a signal that is held is not lost for good."""
    try:
        signal.pthread_sigmask(signal.SIG_BLOCK, {signal.SIGTERM, signal.SIGINT, signal.SIGHUP})
    except (AttributeError, ValueError, OSError):
        pass
    hold_stop_signals()
    STOP["last_word"] = None
    print(json.dumps(answer, **dumps_kwargs))


install_signal_handlers(lambda signum: interrupted_answer(signum))
# END SHARED STOP

import os as _os
import sys as _sys
import threading as _threading

# ---- the one protected printer of an answer (outside the shared block) ------------------------------------------------------------
# The stop signals are held while the answer is written, so that a signal cannot cut the document. A reader that stops taking it (a full
# pipe) would make that tool unkillable by SIGTERM: the held write is therefore bounded. If a stop signal is waiting when
# HELD_WRITE_SECONDS have passed, the tool says so on stderr and ends with 128 plus that signal; nothing is claimed about the answer.
HELD_WRITE_SECONDS = int(_os.environ.get("TOOL_HELD_WRITE_SECONDS") or 30)       # the environment variable is for the tests
_STOPS = (signal.SIGTERM, signal.SIGINT, signal.SIGHUP)


def _unstick():
    try:
        waiting = signal.sigpending()
    except (AttributeError, OSError):
        waiting = set()
    held = [s for s in _STOPS if s in waiting]
    if held:
        try:
            _os.write(2, ("the answer could not be written in %d seconds (the reader is not taking it); ended by the stop signal that was held\n" % HELD_WRITE_SECONDS).encode())
        except OSError:
            pass
        _os._exit(128 + int(held[0]))
    again = _threading.Timer(1.0, _unstick)
    again.daemon = True
    again.start()


ERROR_FLAGS = ("all_results_error", "all_matches_error", "receipt_error", "receipts_error", "rows_file_error", "rows_error", "invalid_lines_file_error",
               "write_error", "values_error")


def _flagged(node, depth=0):
    """The first error flag found in an answer (top level, and two levels of dicts below it), or None."""
    if not isinstance(node, dict) or depth > 2:
        return None
    for key in ERROR_FLAGS:
        if node.get(key):
            return key
    for value in node.values():
        found = _flagged(value, depth + 1)
        if found:
            return found
    return None


def _reconcile(answer):
    """status, complete and ok are one fact: an error flag in the answer (a file that should hold the rest could not be written) is not a
    complete answer, and a complete or ok that survives a partial or failed status is a wrong claim. Said once, here, for every answer."""
    if not isinstance(answer, dict):
        return
    flag = _flagged(answer)
    if flag and answer.get("status") == "complete":
        answer["status"] = "partial"
        basis = answer.get("status_basis")
        answer["status_basis"] = ("%s; but %s says part of what was asked for could not be kept" % (basis, flag)) if basis else "%s says part of what was asked for could not be kept" % flag
    if answer.get("status") in ("partial", "failed") or flag:
        if answer.get("complete") is True:
            answer["complete"] = False
    if answer.get("status") == "failed" and answer.get("ok") is True:
        answer["ok"] = False


# BEGIN SHARED TEMPS
# One lifecycle for the hidden temporary files of a run. A file is made by temp_create (or its name is registered with temp_hold before it is
# made), it is registered before anything else is done with it, and it stays registered until temp_done says it was renamed into place. What is
# still registered when the run ends is removed: by atexit on a normal end or any exception, by drop_temporaries in the last-resort handler, and
# by the stop signal's own cleanup, which removes the _tmp of every object in PAGES (a registered name is one such object).
import atexit
import tempfile

if "PAGES" not in globals():
    PAGES = []                 # objects with a hidden temporary file (_tmp) that a stop removes


class _HeldTemp:
    def __init__(self, name):
        self._tmp = name


def temp_hold(name):
    """Register a temporary file that is about to be made (or has been): it is removed on every way out unless temp_done is called."""
    held = _HeldTemp(os.fspath(name))
    PAGES.append(held)
    return held._tmp


def temp_create(directory, prefix, suffix=""):
    """tempfile.mkstemp with the new name registered at once: (fd, name)."""
    fd, name = tempfile.mkstemp(dir=os.fspath(directory), prefix=prefix, suffix=suffix)
    temp_hold(name)
    return fd, name


def temp_done(name):
    """The file was renamed into place (or is kept on purpose): it is no longer a temporary."""
    name = os.fspath(name)
    PAGES[:] = [p for p in PAGES if not (isinstance(p, _HeldTemp) and p._tmp == name)]


def temp_drop(name):
    """Remove one temporary now; False when it could not be removed (it stays registered, and the end of the run tries again)."""
    try:
        os.unlink(name)
    except FileNotFoundError:
        pass
    except OSError:
        return False
    temp_done(name)
    return True


def temp_replace(tmp, dest):
    os.replace(tmp, dest)
    temp_done(tmp)


def drop_temporaries():
    """Remove every temporary still registered (the pages being written and the held names); the names that could not be removed come back."""
    left = []
    for page in list(PAGES):
        tmp = None
        try:
            tmp = getattr(page, "_tmp", None)
            if tmp is not None:
                os.unlink(tmp)
        except FileNotFoundError:
            pass
        except Exception:   # noqa: BLE001 - every one is tried
            left.append(str(tmp))
    return left


atexit.register(drop_temporaries)
# END SHARED TEMPS


def _guarded_write(write):
    try:
        before = signal.pthread_sigmask(signal.SIG_BLOCK, set(_STOPS))      # before the timer thread exists, so that the thread holds them too
    except (AttributeError, ValueError, OSError):
        before = None
    watch = _threading.Timer(HELD_WRITE_SECONDS, _unstick)
    watch.daemon = True
    watch.start()
    try:
        write()
        _sys.stdout.flush()
    except BrokenPipeError:                       # the reader is gone: there is nobody to tell
        _os._exit(1)
    watch.cancel()
    if before is not None:
        # The document is whole. A stop that came while it was written is delivered now; the last word was cleared, so it ends the tool
        # (128 plus the signal) with nothing more on stdout. The mask is also what an in-process caller (a test) had before.
        signal.pthread_sigmask(signal.SIG_SETMASK, before)


_shared_print_answer = print_answer


def print_answer(answer, **dumps_kwargs):
    _reconcile(answer)
    _guarded_write(lambda: _shared_print_answer(answer, **dumps_kwargs))


def _unexpected_tool(kind, value, _tb):
    """Last resort: an error nobody foresaw is an answer too. The hidden temporaries are removed first (a name that cannot be removed is said in the
    answer), then one JSON document with the class and, for a file-system error, its reason (a message can quote a name from the evidence), and
    exit 1; what was written before it is not claimed. A stop signal that arrives while this runs is held with the answer's write and is answered by
    this document and exit 1, not by 128 + the signal."""
    try:
        left = drop_temporaries()
        reason = getattr(value, "strerror", None) if issubclass(kind, OSError) else None
        said = ("a path or file could not be used: %s" % (reason or kind.__name__)) if issubclass(kind, (OSError, ValueError)) else "internal error: %s" % kind.__name__
        answer = {"tool": globals().get("TOOL"), "status": "failed", "error": said,
                  "status_basis": "the tool stopped on an error it did not foresee (%s); what it had written before is not claimed" % kind.__name__}
        if left:
            answer["temporaries_left"] = left[:10]
            answer["status_basis"] += "; hidden temporary files that could not be removed are listed in temporaries_left"
        print_answer(answer)
    except BaseException:       # noqa: BLE001 - nothing may stop the exit
        pass
    os._exit(1)


sys.excepthook = _unexpected_tool


def open_regular(path):
    """open(path, "rb") for a caller's path that was checked as a regular file a moment ago: opened without waiting (O_NONBLOCK) and looked at with
    fstat on the descriptor, so a FIFO or a device put in its place is refused and never waited on (a FIFO would hold the tool for ever)."""
    fd = os.open(path, os.O_RDONLY | getattr(os, "O_NONBLOCK", 0))
    try:
        if os.fstat(fd).st_mode & 0o170000 != 0o100000:
            raise OSError(22, "is not a regular file (it changed after it was checked)")
    except BaseException:
        os.close(fd)
        raise
    return open(fd, "rb")

PAGES = []                 # objects with a hidden temporary file (_tmp) that a stop removes

TOOL = {"name": "ioc_scan", "version": 18}
CHUNK_DEFAULT = 8 * 1024 * 1024
CHUNK_MIN, CHUNK_MAX = 16, 256 * 1024 * 1024
CONTEXT_MAX = 65536
BEFORE = 16                        # bytes of context before a match
HITS_MAX = 1_000_000
NEEDLES_MAX = 1000
NEEDLE_BYTES_MAX = 4096
SEEN_CAP = 100_000                 # distinct contexts remembered for the inline view
ROW_CAP = 20_000_000               # rows in the whole-result file; counting goes on past it
VALUES_ROWS_MAX = 20_000_000       # rows in the values file (write_values); the scan and its locators go on past it
LOCATORS_BYTES_MAX = int(os.environ.get("IOC_SCAN_LOCATORS_BYTES") or 1 << 30)  # bytes in the whole-result file (a smaller cap can be asked for)
VALUES_BYTES_MAX = int(os.environ.get("IOC_SCAN_VALUES_BYTES") or 1 << 30)    # bytes in the values file (a smaller cap can be asked for)
SECONDS_DEFAULT, SECONDS_MAX = 100, 110   # the scan's own clock, inside the manifest's 120
FEED = 256 * 1024                  # bytes handed to the engine at a time: the clock is looked at between feeds
CLOCK_EVERY = 256                  # and between this many matches of one feed: a feed of dense matches times many needles is millions of them


# BEGIN SHARED SCAN
# The same text is in ioc_scan, chunk_needles and sig_carve (tests/test_scan_core.py holds the copies equal and holds the
# engine to a brute-force search over every way of cutting a stream into reads). One engine finds literal byte strings in a
# stream read in blocks: every occurrence once, at its true offset, overlapping ones included, in (offset, needle) order,
# whatever the block size. A match is held back until `after` bytes of context follow it (or the stream has ended), and
# `before` bytes of context are kept behind the searched position, so a match, or its context, cut by a read boundary is
# neither lost nor counted twice. Each tool keeps its own answer: what it reports for a match, its pages and its budgets.
import heapq

SCAN_SLICE = 256 * 1024            # positions searched and handed out together


def _positions(buf, needle, index, lo, stop):
    """(position, index) wherever `needle` starts in buf[lo:stop], one at a time: nothing is collected, so a stream that is one repeated
    byte searched for many nested needles holds one position per needle, not every match of a slice."""
    j = buf.find(needle, lo, stop)
    while j >= 0:
        yield j, index
        j = buf.find(needle, j + 1, stop)


class StreamScan:
    """feed() each block as it is read; every call returns (offset, needle index, buffer, buffer's offset) for the matches that can
    be decided now, in (offset, needle index) order. The buffer holds the match and its context. Exhaust the generator before the
    next feed: the buffer is trimmed when it ends. A caller may instead stop taking matches between two of them (a clock): every
    match it took came in order, none after it was handed out, and the scan is over (this object is not fed again).

    needles   the byte strings (a needle's index is its position in this list)
    before    bytes of context behind a match that stay in the buffer
    after     bytes of context after a match a match waits for
    start     the stream offset of the first byte fed
    prefix    the bytes that precede `start` in the stream, when a match may begin in them and end after `start` (a resumed scan)
    final     the last block (it may be empty): everything fully inside the buffer is handed out. Also what a scan stopped before its end
              calls: the matches that end inside what was read are all reported, and one that crosses the end is the next scan's.
    """

    def __init__(self, needles, before=0, after=0, start=0, prefix=b""):
        self.needles = list(needles)
        self.longest = max(len(n) for n in self.needles)
        self.before, self.after = before, after
        self.buf = prefix
        self.base = start - len(prefix)
        self.done = self.base
        # a match is this scan's when it ends after `start`: the first start position of a needle is start - len + 1
        self.first = [start - len(n) + 1 if prefix else start for n in self.needles]

    def feed(self, data, final=False):
        self.buf += data
        have = self.base + len(self.buf)
        process_end = have if final else have - (self.longest + self.after)
        if process_end > self.done:
            lo, hi = self.done - self.base, process_end - self.base
            a = lo
            while a < hi:
                b = min(hi, a + SCAN_SLICE)
                # One lazy stream per needle, merged by (offset, needle index): the same order for any block size, and the caller
                # can stop between any two matches (a clock looked at per match) without a slice's matches having been collected.
                streams = [_positions(self.buf, nb, vi, max(a, self.first[vi] - self.base), min(len(self.buf), b + len(nb) - 1))
                           for vi, nb in enumerate(self.needles)]
                for j, vi in heapq.merge(*streams):
                    yield self.base + j, vi, self.buf, self.base
                a = b
            self.done = process_end
        if not final:
            keep_from = max(0, (self.done - self.before) - self.base)
            self.buf, self.base = self.buf[keep_from:], self.base + keep_from
# END SHARED SCAN


def describe(exc):
    code = errno.errorcode.get(exc.errno, "") if getattr(exc, "errno", None) else ""
    return "%s%s: %s" % (type(exc).__name__, " " + code if code else "", getattr(exc, "strerror", None) or str(exc))


class SecretValuesRefused(Exception):
    pass


class SecretValues:
    """Where a value goes when, and only when, the caller asked for it.

    The reference implementation of the secret-safe output pattern: copy this
    class unchanged into a tool that has to produce a secret, and call `add`
    once per finding with the finding's id, its locator and the value. With
    `enabled` false it writes nothing and `summary()` says so.
    """

    NAME = "ioc-scan-values.jsonl"

    def __init__(self, enabled: bool):
        self.enabled = enabled
        self.written = 0
        self.bytes = 0
        self.stopped_at = None
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
                "file, not a sealed secret output. Run this as job_run tool=ioc_scan with "
                "secret_output: true, and ask again there. Nothing was written."
            )
        if os.environ.get("SECRET_OUTPUT") != "1":
            raise SecretValuesRefused(
                "write_values is refused in a job that was not run as secret output: its files would be sealed as ordinary "
                "output. The harness sets SECRET_OUTPUT=1 for a secret job's process and it is not set here. Run it as "
                "job_run(tool: \"ioc_scan\", args: {...}), whose manifest makes a job that sets write_values secret output, or give "
                "a command job secret_output: true. Nothing was written."
            )
        self.path = Path(self.out) / self.NAME
        self.shown = "store/jobs/%s/out/%s" % (re.sub(r"[^A-Za-z0-9_.-]", "_", self.job), self.NAME)
        # Created now, before anything is scanned: a file or a link already at that name is
        # refused by name at once (O_EXCL does not follow a link, a dangling one included),
        # instead of failing, or writing through it, after the scan. With nothing found it
        # stays as an empty file, mode 0600, and the answer says written: 0.
        try:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            fd = os.open(str(self.path), os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o600)
        except FileExistsError:
            raise SecretValuesRefused("the values file already exists: %s" % self.path)
        except OSError as exc:
            raise SecretValuesRefused("the values file could not be created: %s (%s)" % (self.path, describe(exc)))
        self._fh = os.fdopen(fd, "w", encoding="utf-8")

    def add(self, finding_id: str, locator: dict, value: str) -> None:
        if not self.enabled:
            return
        # ensure_ascii: a path that is not UTF-8 (its bytes arrive as lone surrogates) is written as an escape, never an encoding error.
        line = json.dumps({"finding_id": finding_id, **locator, "value": value}, ensure_ascii=True) + "\n"
        if self.stopped_at is not None or self.written >= VALUES_ROWS_MAX or self.bytes + len(line) > VALUES_BYTES_MAX:
            if self.stopped_at is None:
                self.stopped_at = locator.get("offset")
            return      # from the first occurrence that did not fit on, none is written: the file is a prefix
        self._fh.write(line)
        self.written += 1
        self.bytes += len(line)

    def close(self) -> None:
        if self._fh is not None:
            self._fh.flush()
            os.fsync(self._fh.fileno())
            self._fh.close()
            self._fh = None

    def summary(self) -> dict:
        return {
            "requested": self.enabled,
            "written": self.written,
            "values_file": self.shown if self.enabled else None,
            "contains_secret_values": self.written > 0,
            **({"complete": self.stopped_at is None} if self.enabled else {}),
            **({"stopped_at_offset": self.stopped_at, "cap_rows": VALUES_ROWS_MAX, "cap_bytes": VALUES_BYTES_MAX,
                "resume": "the file holds every occurrence that starts before stopped_at_offset; to get the rest, scan again from start=stopped_at_offset in a new job"}
               if self.stopped_at is not None else {}),
            "format": "JSON Lines, mode 0600: finding_id, file, offset, needle, encoding, value (the printable context around the match)" if self.enabled else None,
        }


def earlier_answers(path):
    """How many other files answer this same question in the folder (name.ext, name.2.ext, ...): one more for every different
    answer, and none is deleted, so the count is said."""
    stem, ext = os.path.splitext(os.path.basename(str(path)))
    base = re.sub(r"\.\d+$", "", stem)
    rx = re.compile(r"^%s(\.\d+)?%s$" % (re.escape(base), re.escape(ext)))
    try:
        return max(0, sum(1 for n in os.listdir(os.path.dirname(str(path)) or ".") if rx.match(n)) - 1)
    except OSError:
        return 0


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


def publish(tmp, path, shown):
    result = _publish(tmp, path, shown)
    temp_done(tmp)                                        # it is in place (a link, a rename) or gone: no longer a temporary
    return result


def _publish(tmp, path, shown):
    """Move a finished file to `path` without replacing what is there: a file at the name is an earlier answer (a complete
    one, perhaps, where this run was cut short) and stays; this one is kept beside it as name.2.ext, unless it is the
    same bytes, when the file already there is it. Returns the path it has
    and the name to show for it."""
    stem, ext = os.path.splitext(str(path))
    shown_stem, _ = os.path.splitext(shown)
    k = 1
    while True:
        suffix = "" if k == 1 else ".%d" % k
        candidate = Path(stem + suffix + ext)
        try:
            os.link(tmp, candidate)
        except FileExistsError:
            if same_bytes(tmp, candidate):                # the same answer again (a page of the same search): the file is already there
                os.unlink(tmp)
                return candidate, shown_stem + suffix + ext
            k += 1
            continue
        except OSError:                                   # a file system with no hard links: a look, then a rename
            if os.path.lexists(candidate):
                if same_bytes(tmp, candidate):
                    os.unlink(tmp)
                    return candidate, shown_stem + suffix + ext
                k += 1
                continue
            os.rename(tmp, candidate)
            return candidate, shown_stem + suffix + ext
        os.unlink(tmp)
        return candidate, shown_stem + suffix + ext


class Locators:
    """Every locator goes to a file as it is found; the inline page is the view of them the caller asked for.
    The file is published when the page is not the whole (more rows than the page, or repeats hidden from it)."""

    def __init__(self, key, page_limit):
        self.limit, self.page, self.total, self.hidden = page_limit, [], 0, 0
        digest = hashlib.sha256(json.dumps(key, sort_keys=True, default=str).encode("utf-8")).hexdigest()[:16]
        name = "ioc_scan-%s.jsonl" % digest
        job, out = os.environ.get("JOB_ID"), os.environ.get("OUT")
        if job and out:
            self.path = Path(out) / "tool-output" / name
            self.shown = "store/jobs/%s/out/tool-output/%s" % (re.sub(r"[^A-Za-z0-9_.-]", "_", job), name)
        else:
            agent = re.sub(r"[^A-Za-z0-9_.-]", "_", os.environ.get("AGENT_ID") or "tool")
            self.path = Path("work") / agent / "tool-output" / name
            self.shown = str(self.path)
        self.tmp = self.fh = self.error = None
        self.written = 0
        self.bytes = 0
        self.stopped_at = None
        PAGES.append(self)
        try:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            fd, tmp = temp_create(self.path.parent, ".ioc_scan-")
            self.tmp = Path(tmp)
            try:
                self.fh = os.fdopen(fd, "w", encoding="utf-8")
            except BaseException:
                os.close(fd)
                raise
        except OSError as exc:
            self.error = "the whole result could not be kept (%s: %s)" % (self.path.parent, exc.strerror or exc)

    def _give_up(self, exc):
        """The file of every locator cannot be written (a full disk, a file-size limit): it is closed and removed, the counts and the page stay
        whole, and the answer says so (all_results_error)."""
        self.error = "the whole result could not be kept (%s: %s)" % (self.path.parent, getattr(exc, "strerror", None) or exc.__class__.__name__)
        try:
            if self.fh:
                self.fh.close()
        except OSError:
            pass
        try:
            if self.tmp is not None:
                os.unlink(self.tmp)
        except OSError:
            pass
        self.fh = self.tmp = None

    def add(self, row, show):
        self.total += 1
        if self.fh:
            line = json.dumps(row, ensure_ascii=True) + "\n"
            if self.stopped_at is None and self.written < ROW_CAP and self.bytes + len(line) <= LOCATORS_BYTES_MAX:
                try:
                    self.fh.write(line)
                except OSError as exc:
                    self._give_up(exc)
                else:
                    self.written += 1
                    self.bytes += len(line)
            elif self.stopped_at is None:
                self.stopped_at = row["offset"]       # from the first row that did not fit on, none is written: the file is a prefix
        if show and len(self.page) < self.limit:
            self.page.append(row)
        elif show is False:
            self.hidden += 1

    @property
    def _tmp(self):
        return self.tmp

    def discard(self):
        """Close and remove the file being written, if it is still there: the whole result is not kept when the run did not finish."""
        try:
            if self.fh and not self.fh.closed:
                self.fh.close()
        except OSError:
            pass
        if self.tmp is not None:
            try:
                os.unlink(self.tmp)
            except OSError:
                pass

    def finish(self):
        info = {"matched": self.total, "returned": len(self.page), "truncated": self.total > len(self.page)}
        try:
            self._store(info)
        except OSError as exc:              # the last bytes or the publishing failed: the file is dropped, the page and counts stay whole
            self._give_up(exc)
            for k in [k for k in info if k.startswith("all_results") or k == "earlier_answers"]:
                del info[k]
        if self.error:
            info["all_results_error"] = self.error
        return info

    def _store(self, info):
        if self.fh:
            self.fh.flush()
            os.fsync(self.fh.fileno())
            self.fh.close()
            if self.total > len(self.page):
                self.path, self.shown = publish(self.tmp, self.path, self.shown)
                self.tmp = None
                info["all_results"] = self.shown
                info["earlier_answers"] = earlier_answers(self.path)
                info["all_results_format"] = "JSON Lines, one locator per occurrence: finding_id, offset, needle, enc, context_length"
                if self.stopped_at is not None:
                    info["all_results_complete"] = False
                    info["all_results_stopped_at_offset"] = self.stopped_at
                    info["all_results_cap_rows"] = ROW_CAP
                    info["all_results_cap_bytes"] = LOCATORS_BYTES_MAX
                    info["all_results_note"] = ("the file holds every occurrence that starts before all_results_stopped_at_offset, and is whole as far as it goes; "
                                                "the counts and the inline page are of the whole scan. To list the rest, scan again from start=all_results_stopped_at_offset")
            else:
                os.unlink(self.tmp)


def fail(message, **extra):
    print_answer({"error": message, "status": "failed", "status_basis": "the tool stopped with an error: %s" % message, "tool": TOOL, **extra})
    sys.exit(1)


def whole(args, key, default, low, high):
    value = args.get(key)
    if value is None:
        return default
    if not isinstance(value, int) or isinstance(value, bool) or not low <= value <= high:
        fail("%s is a whole number from %d to %d" % (key, low, high), **{key: value})
    return value


DEFAULT_NEEDLES = [
    "http://", "https://", "ftp://",
    "powershell", "cmd.exe", "rundll32", "mshta", "wscript", "cscript",
    "schtasks", "bitsadmin", "certutil", "regsvr32",
    "Invoke-", "IEX(", "-enc ", "FromBase64",
    "HKEY_", "CurrentVersion\\Run", "UserInit",
    "mimikatz", "meterpreter", "cobalt", "beacon",
    ".onion", "bitcoin", "ransom", "wallet",
    "psexec", "procexp", "sysinternals", "tcpview", "autoruns",
    "IEUser", "@gmail", "@yahoo", "@hotmail",
    "password", "Password", "C2", "user-agent", "User-Agent",
    ".exe", ".ps1", ".bat", ".vbs", ".js",
    "AppData\\", "\\Temp\\", "Downloads\\",
    "From:", "Subject:", "mailto:",
    "192.168.", "10.0.", "172.16.",
]


def main():
    started = time.monotonic()
    try:
        args = json.load(sys.stdin)
    except (ValueError, RecursionError) as exc:
        fail("arguments are not valid JSON", reason=str(exc))
    if not isinstance(args, dict):
        fail("arguments are a JSON object")
    path = args.get("path") or "inputs/[UNALLOCATED]"
    if not isinstance(path, str) or "\0" in path:
        fail("path is a string without a NUL byte: a file or a directory to scan")
    needles = args.get("needles")  # a list of strings, or a pipe-separated string
    if isinstance(needles, str):
        needles = [n for n in needles.split("|") if n]
    if needles is not None and (not isinstance(needles, list) or not all(isinstance(n, str) for n in needles)):
        fail("needles is a pipe-separated string or a list of strings")
    if "needles" in args and args["needles"] is not None and not needles:
        fail("needles is empty: give at least one needle, or leave needles out for the default set (the answer lists which ran)")
    needles_source = "given" if needles else "the default set: no needles were given"
    if not needles:
        needles = DEFAULT_NEEDLES
    needles = list(dict.fromkeys(needles))          # a needle given twice is one needle
    if len(needles) > NEEDLES_MAX:
        fail("at most %d needles" % NEEDLES_MAX, given=len(needles))
    max_hits = whole(args, "max_hits", 80, 1, HITS_MAX)
    context = whole(args, "context", 96, 0, CONTEXT_MAX)
    start = whole(args, "start", 0, 0, 1 << 62)
    length = args.get("length")
    if length is not None:
        length = whole(args, "length", None, 0, 1 << 62)
    chunk = whole(args, "chunk", CHUNK_DEFAULT, CHUNK_MIN, CHUNK_MAX)
    max_seconds = whole(args, "max_seconds", SECONDS_DEFAULT, 1, SECONDS_MAX)
    if args.get("skip_zeros", False):
        fail("skip_zeros would make the scan lossy and is not supported", hint="omit skip_zeros or pass false")
    unique_only = bool(args.get("unique_only", True))
    write_values = args.get("write_values", False)
    if not isinstance(write_values, bool):
        fail("write_values is true or false")

    variants = []
    for n in needles:
        try:
            raw = n.encode("utf-8")
            wide = n.encode("utf-16le")
        except UnicodeEncodeError:
            fail("a needle is not text that can be encoded", needle_index=needles.index(n))
        if not raw:
            continue
        if len(raw) > NEEDLE_BYTES_MAX:
            fail("a needle is longer than %d bytes" % NEEDLE_BYTES_MAX, needle_index=needles.index(n))
        variants.append(("ascii", n, raw))
        variants.append(("utf16", n, wide))
    if not variants:
        fail("no needle to look for")
    longest = max(len(v[2]) for v in variants)

    if os.path.isdir(path):
        fail("a directory, not a file: scan one file at a time", path=path)
    if not os.path.isfile(path):
        fail("no such file", path=path)
    size = os.path.getsize(path)
    if start > size:
        fail("start is past the end of the file", start=start, size=size)
    end = size if length is None else min(size, start + length)

    try:
        secret = SecretValues(write_values)
    except SecretValuesRefused as exc:
        fail(str(exc), write_values="refused")
    progress = {"scanned": start}

    def _stopped(signum):
        try:
            secret.close()
        except Exception:  # noqa: BLE001
            pass
        print(json.dumps({"tool": TOOL, "status": "partial", "interrupted": True, "signal": signum, "path": path, "scanned_end": progress["scanned"], "secret_values": secret.summary(),
                          "status_basis": "the tool was stopped by signal %d: the counts and locators so far were not kept (the half-written locators file was removed), and a values "
                                          "file already begun holds the rows written before the stop; scan again from start=%d" % (signum, start)}), flush=True)
    install_signal_handlers(_stopped)
    locators = Locators([path, needles, start, end, context, unique_only, size], max_hits)
    counts = defaultdict(int)
    seen = set()

    def emit(at, kind, name, nb, buf, base, vi):
        i = at - base
        s = max(0, i - BEFORE)
        e = min(len(buf), i + len(nb) + context)
        raw = buf[s:e]
        # Named by where the occurrence starts and which needle variant it is, so a scan that goes on from next_start (or from where the
        # values file stopped) never gives an id an earlier call gave to another occurrence, and one that finds the same occurrence again
        # gives it the same id.
        fid = "F%d-%d" % (at, vi)
        counts[name] += 1
        row = {"finding_id": fid, "offset": at, "needle": name, "enc": kind, "context_length": len(raw)}
        show = True
        if unique_only:
            key = (name, kind, raw[:80])
            if key in seen:
                show = False
            elif len(seen) < SEEN_CAP:
                seen.add(key)
        locators.add(row, show)
        if write_values:
            text = "".join(chr(c) if 32 <= c < 127 else "." for c in raw)
            secret.add(fid, {"file": path, "offset": at, "needle": name, "encoding": kind}, text)

    # The shared engine finds every occurrence once, in (offset, needle) order, whatever chunk is (see StreamScan above). The bytes of a
    # read go to it FEED at a time. The clock is looked at between feeds and every CLOCK_EVERY matches: a scan that has used its seconds
    # stops there. Between feeds the matches that start before scanner.done are its answer; inside a feed they are the ones that start at
    # or before the offset of the match it stopped at (those at that offset are all taken first), so next_start is that offset + 1. The
    # rest are the next scan's, from next_start.
    scanner = StreamScan([v[2] for v in variants], before=BEFORE, after=context, start=start)
    deadline = started + max_seconds
    scanned = start
    stopped = None
    next_start = None
    taken, cut = [0], [None]

    def drain(matches):
        """Emit the matches a feed hands out; False when the clock stopped them, after the last one of the offset it stopped at."""
        for at, vi, buf, base in matches:
            if cut[0] is not None and at != cut[0]:
                return False
            kind, name, nb = variants[vi]
            emit(at, kind, name, nb, buf, base, vi)
            taken[0] += 1
            if cut[0] is None and taken[0] % CLOCK_EVERY == 0 and time.monotonic() > deadline:
                cut[0] = at
        return True

    def stop_inside_a_feed():
        return ("the %d-second time budget was used inside a read, after the occurrences that start at or before offset %d: the counts and hits are for the "
                "occurrences that start in [%d, %d); run again with start=%d to go on" % (max_seconds, cut[0], start, cut[0] + 1, cut[0] + 1))
    try:
        with open_regular(path) as fh:
            fh.seek(start)
            while scanned < end and stopped is None:
                data = fh.read(min(chunk, end - scanned))
                if not data:
                    break
                for off in range(0, len(data), FEED):
                    block = data[off:off + FEED] if len(data) > FEED else data
                    inside = not drain(scanner.feed(block))
                    scanned += len(block)
                    progress["scanned"] = scanned
                    if inside:
                        stopped, next_start = stop_inside_a_feed(), cut[0] + 1
                        break
                    if scanned < end and time.monotonic() > deadline:
                        next_start = scanner.done
                        stopped = ("the %d-second time budget was used after %d bytes: the counts and hits are for the occurrences that start in [%d, %d); "
                                   "run again with start=%d to go on" % (max_seconds, scanned - start, start, scanner.done, scanner.done))
                        break
        if stopped is None and scanned < end:
            stopped_short = "the file ended after %d bytes, before the requested end at %d (it changed while it was read, or its size was wrong)" % (scanned, end)
        else:
            stopped_short = None
        if stopped is None and not drain(scanner.feed(b"", final=True)):
            stopped, next_start = stop_inside_a_feed(), cut[0] + 1
        secret.close()
        page = locators.finish()
    except OSError as exc:
        secret.close()
        locators.discard()
        fail("the file could not be read all the way: %s" % (exc.strerror or exc), path=path, scanned_end=scanned,
             note="what was found before the read failed is not a result; the values file, when one was asked for, holds those rows only",
             secret_values=secret.summary())
    finally:
        locators.discard()                 # a half-written locators file is never left behind (a no-op once it is published or dropped)
    result = {
        "tool": TOOL,
        "path": path,
        "source": {"path": path, "bytes": size, "address_space": "the bytes of this file as given; a container (E01, VMDK) is not decoded"},
        "scanned_start": start,
        "scanned_end": scanned,
        "bytes_scanned": scanned - start,
        "requested": {"start": start, "length": length, "end": end},
        "complete": scanned >= end and stopped is None and secret.stopped_at is None,
        "status": "complete" if scanned >= end and stopped is None else "partial",
        "status_basis": ("every byte of the requested range was read and every occurrence that starts in it is reported" if scanned >= end and stopped is None
                         else "the scan did not read the whole requested range (see stopped): only the occurrences it reports are known"),
        "size": size,
        "case_sensitive": True,
        "match_policy": "every occurrence by its start offset, overlapping ones included; a needle is searched as given (UTF-8) and as UTF-16LE",
        "context": {"after_bytes": context, "before_bytes": BEFORE, "returned_inline": False,
                    "note": "context bytes are not returned: they are where a secret sits. write_values: true, in a job run with secret_output: true, writes them to a file under $OUT."},
        "hit_count_returned": page["returned"],
        "needles_that_ran": needles,
        "needles_source": needles_source,
        "counts": dict(sorted(counts.items(), key=lambda kv: -kv[1])),
        "hits": locators.page,
        **page,
        "secret_values": secret.summary(),
    }
    if stopped or stopped_short:
        result["stopped"] = stopped or stopped_short
    if stopped:
        result["next_start"] = next_start
    if locators.error and result["truncated"]:
        result["status"] = "partial"
        result["complete"] = False
        result["status_basis"] += "; the file that should hold every locator could not be written (all_results_error), so the occurrences past the page are counted, not listed"
    if secret.stopped_at is not None:
        result["status"] = "partial"
        result["complete"] = False
        result["status_basis"] += "; the values file stopped at its cap (secret_values.stopped_at_offset), the locators did not"
    if unique_only and locators.hidden:
        result["repeats_hidden_inline"] = locators.hidden
        result["repeats_note"] = "occurrences whose context repeats one already listed are not in the inline page; every one is in all_results"
    print_answer(result, indent=2)


if __name__ == "__main__":
    exit_code = 0
    try:
        main()
    except SystemExit as stop:
        exit_code = _code(stop)
    _leave(exit_code)
