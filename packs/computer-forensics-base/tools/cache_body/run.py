#!/usr/bin/env python3
"""Write the body of one browser HTTP cache entry out as a file, decoded, with its detected type.

Three sources. A Chromium simple-cache entry file (<16 hex>_0: a header, the key, the body, an end record, the response headers and a
second end record). A Chromium block-file cache directory (index, data_0 to data_3, f_NNNNNN): listed first, one row an entry, then
one entry taken by its row number or address. A plain file (an external f_ file, a carved body). The response's Content-Encoding
header, when the entry has one, says how the body is stored: gzip and deflate are decoded with the standard library, brotli and zstd
with a Python module when one imports; when none does the stored bytes are written as they are and the answer is partial and says
"brotli: not decodable here". Decoding is bounded (max_bytes, a ratio, the tool's clock).

The body, the key (the URL) and the header block are files under the output directory; the answer carries sizes, offsets, the
body file's sha256, the status code, the media type and the coding, never the key or a header value beyond those two tokens.
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
            sys.stderr.flush()
            os.write(2, ("%s\n" % (code,)).encode("utf-8", "backslashreplace"))
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


import errno
import hashlib
import itertools
import re
import stat
import struct
import time
import zlib


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
    if "answer_a_stop" in globals():     # (a block run on its own, by a test, has no ENDS block)
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
    answer cut. A signal that is held is not answered once the answer is out (the shared ENDS block): the answer stands, and the call ends
    with its own exit code."""
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
        # The document is whole. A stop that came while it was written is let go now: run as a program, the shared ENDS block has given it a
        # handler that does nothing (the answer stands, and the call ends with its own code); loaded as a module, the tool's own handler ends it
        # (128 plus the signal; the last word was cleared) with nothing more on stdout. The mask is also what an in-process caller (a test) had before.
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


TOOL = {"name": "cache_body", "version": 4}
PARSER = "cache_body/4"
DEFAULT_SECONDS, MAX_SECONDS = 100, 110         # under the manifest's 120
DEFAULT_BYTES, MAX_BYTES = 256 << 20, 2 << 30   # the most one body may be when decoded
MAX_RATIO = 2000                                # decoded bytes for one stored byte, past the first MiB
MAX_ENTRIES = 500000
KNOWN_PARAMS = {"path", "kind", "encoding", "list", "entry", "address", "max_bytes", "max_seconds"}
KINDS = ("auto", "simple", "blockfile", "plain")
ENCODINGS = ("auto", "identity", "gzip", "deflate", "br", "zstd")
RULES = [
    "A cache entry shows that these bytes were stored under this key (a URL) by this browser profile; it does not show that a person "
    "opened the page, when it was shown, or that the server still serves it. Cite the entry file (or the cache directory and the "
    "entry's address), the body file and its sha256.",
    "Read status: `partial` with `brotli: not decodable here` (or zstd) means the stored bytes were written out as they are and NOT "
    "decoded: the body is still compressed, and nothing found or not found in it is a statement about the page.",
    "A block-file cache is listed first ({\"path\": \"<cache directory>\", \"list\": true}: one row an entry in entries.tsv, the key "
    "in the file, never in the answer), then one entry is taken by its row number (entry) or its address; a simple-cache entry file "
    "(<16 hex>_0) and a plain file are read directly. A plain file whose encoding is brotli needs encoding: \"br\" (brotli has no signature).",
    "The key (the URL) and the response headers can carry a session token: they are written to files beside the body, never into the "
    "answer. When the case turns on them, run the job with secret_output: true and cite the file.",
]


# ---- what every answer and every file of this tool goes through ---------------------------------------------------------------------
MAX_ARGUMENT_BYTES = 4 << 20


class Refused(Exception):
    """A parameter or an input the tool refuses: the text is the whole message."""


def fail(message, **extra):
    print_answer({"tool": TOOL, "status": "failed", "error": message,
                  "status_basis": "the tool stopped with an error (see error): it read nothing it answers for, and that is not a negative",
                  "rules": RULES, **extra})
    raise SystemExit(1)


def describe(exc):
    """An error without the path it names: its class, the errno's name and the system's own words."""
    code = errno.errorcode.get(exc.errno, "") if getattr(exc, "errno", None) else ""
    words = getattr(exc, "strerror", None) or "no system message"
    return "%s%s: %s" % (type(exc).__name__, " " + code if code else "", words)


def where_it_failed(exc):
    tb, line = exc.__traceback__, None
    while tb is not None:
        if tb.tb_frame.f_code.co_filename == __file__:
            line = tb.tb_lineno
        tb = tb.tb_next
    return "line %s of the tool" % line if line else "an unknown line"


def printable(text, most=300):
    """A caller's string as the answer repeats it: one line, bounded, with nothing a terminal or a JSON reader would trip on."""
    text = text if isinstance(text, str) else repr(text)
    text = "".join(ch if " " <= ch < "\x7f" or (ch > "\xa0" and ch.isprintable() and not 0xD800 <= ord(ch) <= 0xDFFF) else "?" for ch in text)
    return text if len(text) <= most else text[:most] + "...(%d characters)" % len(text)


def read_args(known):
    """The arguments, a JSON object on standard input: (args, the names it does not know)."""
    raw = sys.stdin.buffer.read(MAX_ARGUMENT_BYTES + 1)
    if len(raw) > MAX_ARGUMENT_BYTES:
        fail("the arguments are over %d bytes" % MAX_ARGUMENT_BYTES)
    try:
        args = json.loads(raw.decode("utf-8"))
    except (ValueError, RecursionError) as exc:
        fail("the arguments are not valid JSON (%s): send one JSON object on standard input" % type(exc).__name__)
    if not isinstance(args, dict):
        fail("the arguments must be a JSON object")
    return args, sorted(printable(k, 60) for k in args if k not in known)


def int_param(args, key, default, low, high):
    value = args.get(key)
    if value is None:
        return default
    if isinstance(value, bool) or not isinstance(value, int) or not low <= value <= high:
        raise Refused("%s must be a whole number from %d to %d" % (key, low, high))
    return value


def number_param(args, key, default, low, high):
    value = args.get(key)
    if value is None:
        return default
    if isinstance(value, bool) or not isinstance(value, (int, float)) or value != value or not low <= value <= high:
        raise Refused("%s must be a number from %s to %s" % (key, low, high))
    return float(value)


def bool_param(args, key, default=False):
    value = args.get(key)
    if value is None:
        return default
    if not isinstance(value, bool):
        raise Refused("%s must be true or false" % key)
    return value


def choice_param(args, key, default, choices):
    value = args.get(key)
    if value is None:
        return default
    if not isinstance(value, str) or value not in choices:
        raise Refused("%s must be one of: %s" % (key, ", ".join(choices)))
    return value


def path_param(value, what):
    if not isinstance(value, str) or not value or "\x00" in value or len(value) > 4096:
        raise Refused("%s must be a path: a string of 1 to 4096 characters without a NUL" % what)
    try:
        value.encode("utf-8")
    except UnicodeError:
        raise Refused("%s is not a path this tool can open: it does not encode as UTF-8" % what)
    return value


def read_file(path, most, what):
    """The bytes of a regular file, opened without waiting on a FIFO or a device, at most `most` bytes: Refused says why not."""
    try:
        fd = os.open(path, os.O_RDONLY | getattr(os, "O_NONBLOCK", 0))
    except OSError as exc:
        raise Refused("%s cannot be opened (%s)" % (what, describe(exc)))
    try:
        st = os.fstat(fd)
        if not stat.S_ISREG(st.st_mode):
            raise Refused("%s is not a regular file (a directory, a FIFO or a device is not read)" % what)
        if st.st_size > most:
            raise Refused("%s is %d bytes; this tool reads a file of up to %d" % (what, st.st_size, most))
        parts, got = [], 0
        while got <= most:
            if out_of_time():
                raise Refused("the tool's clock ran out while %s was being read" % what)
            block = os.read(fd, min(1 << 22, most + 1 - got))
            if not block:
                break
            parts.append(block)
            got += len(block)
        if got > most:
            raise Refused("%s grew past %d bytes while it was read" % (what, most))
        return b"".join(parts)
    except OSError as exc:
        raise Refused("%s cannot be read (%s)" % (what, describe(exc)))
    finally:
        os.close(fd)


class Place:
    """Where this call writes: a directory of its own, made new, under $OUT in a job and under work/<agent>/tool-output outside one. No
    link is followed on the way: every directory is opened with O_NOFOLLOW and the next one made and opened below it, and a file is
    created exclusively (never over a name that is there, never through a link). A file that was begun and not finished is removed on
    every way out (the shared TEMPS block holds its name until it is whole)."""

    def __init__(self, stem):
        job, out = os.environ.get("JOB_ID"), os.environ.get("OUT")
        self.in_job = bool(job and out)
        nofollow = getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_DIRECTORY", 0) | os.O_RDONLY
        try:
            if self.in_job:
                self.shown = "store/jobs/%s/out" % re.sub(r"[^A-Za-z0-9_.-]", "_", job)
                self.path = out
                os.makedirs(out, exist_ok=True)
                fd = os.open(out, nofollow)
            else:
                agent = os.environ.get("AGENT_ID") or "tool"
                if not re.fullmatch(r"[A-Za-z0-9_-][A-Za-z0-9_.-]{0,127}", agent):
                    raise Refused("AGENT_ID is not a plain name (letters, digits, '_', '-' and '.', and no '.' first): outside a job the files go under "
                                  "work/<AGENT_ID>/tool-output, and this one would not name a directory there. Nothing was written")
                self.shown = "work/%s/tool-output" % agent
                self.path = os.path.join("work", agent, "tool-output")
                fd = os.open(".", nofollow)
                for part in ("work", agent, "tool-output"):
                    try:
                        os.mkdir(part, 0o755, dir_fd=fd)
                    except FileExistsError:
                        pass
                    below = os.open(part, nofollow, dir_fd=fd)
                    os.close(fd)
                    fd = below
            for n in range(1, 10000):
                name = stem if n == 1 else "%s-%d" % (stem, n)
                try:
                    os.mkdir(name, 0o755, dir_fd=fd)
                except FileExistsError:
                    continue
                self.fd = os.open(name, nofollow, dir_fd=fd)
                os.close(fd)
                self.shown += "/" + name
                self.path = os.path.join(self.path, name)
                return
            os.close(fd)
            raise Refused("no free name for this call's output directory under %s" % self.shown)
        except OSError as exc:
            raise Refused("the output directory cannot be made or is reached through a link (%s): nothing was written" % describe(exc))

    def write(self, name, chunks, mode=0o644):
        """Create `name` here and write the chunks (bytes, or an iterable of bytes); the name the answer cites. OSError when it cannot."""
        full = os.path.join(self.path, name)
        fd = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), mode, dir_fd=self.fd)
        temp_hold(full)
        try:
            for chunk in ((chunks,) if isinstance(chunks, (bytes, bytearray)) else chunks):
                view = memoryview(chunk)
                while len(view):
                    view = view[os.write(fd, view[:1 << 20]):]
        finally:
            os.close(fd)
        temp_done(full)
        return "%s/%s" % (self.shown, name)

    def remove(self, name):
        """Remove a file this call wrote here (a result that turned out to hold nothing); False when it could not be."""
        try:
            os.unlink(name, dir_fd=self.fd)
            return True
        except OSError:
            return False

    def note(self):
        return None if self.in_job else ("written where you called it, not sealed: run it as a job (job_run tool=%s) to have the files sealed into the store and citable as job:<id>/<path>" % TOOL["name"])


def answered(main):
    """main(), with every way it can fail turned into one JSON answer."""
    try:
        main()
    except SystemExit:
        raise
    except Refused as exc:
        hold_stop_signals(quietly=True)
        left = drop_temporaries()
        fail(str(exc), **({"temporaries_left": left[:10]} if left else {}))
    except (MemoryError, RecursionError) as exc:
        hold_stop_signals(quietly=True)
        drop_temporaries()
        fail("the input needs more memory or nesting than this tool has (%s)" % type(exc).__name__)
    except Exception as exc:  # noqa: BLE001 - never an empty or clean answer for a failure
        hold_stop_signals(quietly=True)
        drop_temporaries()
        fail("unexpected failure: %s" % (describe(exc) if isinstance(exc, OSError) else "%s at %s" % (type(exc).__name__, where_it_failed(exc))))


SIMPLE_INITIAL, SIMPLE_FINAL = 0xFCFB6D1BA7725C30, 0xF4FA6F45970D41D8      # net/disk_cache/simple/simple_entry_format.h
SIMPLE_HEADER, SIMPLE_EOF = 24, 24                                         # both structures are 20 bytes of fields, padded to 24
INDEX_MAGIC, BLOCK_MAGIC = 0xC103CAC3, 0xC104CAC3                          # net/disk_cache/blockfile/disk_format.h, disk_format_base.h
INDEX_HEADER, BLOCK_HEADER, ENTRY_STORE, KEY_IN_ENTRY = 368, 8192, 256, 160
BLOCK_SIZES = {1: 36, 2: 256, 3: 1024, 4: 4096}
KEY_MAX = 1 << 20
HEADERS_MAX = 4 << 20
TOKEN = re.compile(r"[A-Za-z0-9!#$&^_.+-]{1,60}\Z")
MEDIA = re.compile(r"\s*([A-Za-z0-9!#$&^_.+-]{1,60}/[A-Za-z0-9!#$&^_.+-]{1,60})")
TYPES = (
    (0, b"\x89PNG\r\n\x1a\n", "PNG image", "png"), (0, b"\xff\xd8\xff", "JPEG image", "jpg"), (0, b"GIF87a", "GIF image", "gif"), (0, b"GIF89a", "GIF image", "gif"),
    (0, b"%PDF-", "PDF document", "pdf"), (0, b"PK\x03\x04", "ZIP archive (or an Office or Java file)", "zip"), (0, b"\x1f\x8b\x08", "gzip stream", "gz"),
    (0, b"\x00asm", "WebAssembly module", "wasm"), (0, b"SQLite format 3\x00", "SQLite database", "sqlite"), (0, b"MZ", "DOS or PE executable", "bin"),
    (0, b"\x7fELF", "ELF executable", "bin"), (0, b"wOFF", "WOFF font", "woff"), (0, b"wOF2", "WOFF2 font", "woff2"), (4, b"ftyp", "ISO media file (MP4 family)", "mp4"),
    (0, b"\x1a\x45\xdf\xa3", "Matroska or WebM", "webm"), (0, b"OggS", "Ogg", "ogg"), (0, b"ID3", "MP3 audio", "mp3"), (0, b"\x28\xb5\x2f\xfd", "Zstandard stream", "zst"),
    (0, b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1", "OLE compound file", "ole"), (0, b"\x00\x00\x01\x00", "ICO image", "ico"), (0, b"BM", "BMP image", "bmp"),
)


class Clock(Exception):
    """The tool's own clock ran out inside a loop."""


def tick():
    if out_of_time():
        raise Clock()


class Unread:
    """The one list of what this call did not read or did not judge: every place that leaves something unread or unjudged counts it here,
    under a name declared up front, with the sentence that says it. The status is derived from this list alone (a failed call aside): a
    count above zero makes the answer partial. The answer prints every counter, zeros included (`not_read_or_judged`)."""

    def __init__(self, *names):
        self.counts = {name: 0 for name in names}
        self.said = {}

    def add(self, name, count=1, sentence=None):
        if name not in self.counts:
            raise KeyError(name)
        if count:
            self.counts[name] += count
            if sentence and name not in self.said:
                self.said[name] = sentence

    def __bool__(self):
        return any(self.counts.values())

    def reasons(self):
        return [self.said.get(name, name.replace("_", " ")) for name, count in self.counts.items() if count]


class Unreadable(Exception):
    """A cache structure that is not what the format says: the text names the structure and the offset, never a value from the file."""


def detect_type(head):
    """(what the first bytes are, a suffix for the file's name): a reading of the first bytes, not a validation."""
    for offset, magic, what, suffix in TYPES:
        if head[offset:offset + len(magic)] == magic:
            return what, suffix
    if head[:4] == b"RIFF" and head[8:12] == b"WEBP":
        return "WebP image", "webp"
    if head[:4] == b"RIFF":
        return "RIFF container", "riff"
    text = head.lstrip(b"\xef\xbb\xbf \t\r\n")[:64].lower()
    if text.startswith((b"<!doctype html", b"<html", b"<head", b"<body")):
        return "HTML text", "html"
    if text.startswith(b"<?xml") or text.startswith(b"<svg"):
        return "XML text", "xml"
    if text[:1] in (b"{", b"["):
        return "text that begins like JSON", "json"
    sample = head[:512]
    if sample and all(b in b"\t\r\n" or 32 <= b < 127 or b >= 128 for b in sample):
        try:
            sample.decode("utf-8")
            return "text", "txt"
        except UnicodeDecodeError:
            if len(sample) == 512:
                try:
                    sample[:508].decode("utf-8")
                    return "text", "txt"
                except UnicodeDecodeError:
                    pass
    return "unrecognised bytes", "bin"


def pread(fd, length, offset, what):
    parts, got = [], 0
    while got < length:
        tick()
        block = os.pread(fd, min(1 << 22, length - got), offset + got)
        if not block:
            break
        parts.append(block)
        got += len(block)
    data = b"".join(parts)
    if len(data) != length:
        raise Unreadable("%s ends after %d of %d bytes at offset %d" % (what, len(data), length, offset))
    return data


def open_file(path, what, follow=True):
    """A regular file opened without waiting on a FIFO or a device; follow=False refuses a link (the files inside a cache directory)."""
    try:
        fd = os.open(path, os.O_RDONLY | getattr(os, "O_NONBLOCK", 0) | (0 if follow else getattr(os, "O_NOFOLLOW", 0)))
    except OSError as exc:
        if not follow and exc.errno in (errno.ELOOP, getattr(errno, "EMLINK", -1)) and os.path.islink(path):
            raise Refused("%s is a link, and a link inside the cache is not followed" % what)
        raise Refused("%s cannot be opened (%s)" % (what, describe(exc)))
    st = os.fstat(fd)
    if not stat.S_ISREG(st.st_mode):
        os.close(fd)
        raise Refused("%s is not a regular file" % what)
    return fd, st.st_size


def chunks_of(fd, offset, length):
    """The bytes of a range of a file, a mebibyte at a time."""
    end = offset + length
    while offset < end:
        tick()
        block = os.pread(fd, min(1 << 20, end - offset), offset)
        if not block:
            raise Unreadable("the body ends at offset %d, before its recorded end %d" % (offset, end))
        offset += len(block)
        yield block


def brotli_module():
    """(module, its name, why none is used): a brotli module whose decoder bounds the output of a call (output_buffer_limit, brotli 1.2
    and later). An older one is not used: its process() returns all that a stored byte decodes to, which can be hundreds of MiB."""
    older = None
    for name in ("brotli", "brotlicffi"):
        try:
            module = __import__(name)
        except Exception:  # noqa: BLE001 - not installed, or a broken build
            continue
        try:
            engine = module.Decompressor()
            engine.process(b"", output_buffer_limit=OUT_PIECE)
            if hasattr(engine, "can_accept_more_data"):
                return module, name, None
        except Exception:  # noqa: BLE001 - no output_buffer_limit (TypeError), or a module that dislikes an empty input
            pass
        older = older or name
    return None, None, ("the %s module of this image is older than 1.2: its decoder cannot bound what one call returns, so it is not used" % older
                        if older else "no brotli or brotlicffi module imports in this image")


def zstd_module():
    """The standard library's zstd (Python 3.14 and later: its output is bounded a call), else the zstandard module."""
    try:
        from compression import zstd as module           # noqa: PLC0415 - optional, by the interpreter's version
        return module, "compression.zstd"
    except Exception:  # noqa: BLE001
        pass
    try:
        return __import__("zstandard"), "zstandard"
    except Exception:  # noqa: BLE001
        return None, None


OUT_PIECE = 1 << 20          # the most one call of a decoder returns, where the decoder can be told so


class Damaged(Exception):
    """The decoder refused the bytes it was given: the stream is damaged there (or its own check failed)."""


class _Zlib:
    """gzip and deflate: output bounded a call (max_length), the stream's end and what followed it said by the engine."""
    piece = 8192

    def __init__(self, wbits):
        self.engine = zlib.decompressobj(wbits)

    def feed(self, data):
        while data and not self.engine.eof:
            try:
                out = self.engine.decompress(data, OUT_PIECE)
            except zlib.error:
                raise Damaged()
            data = self.engine.unconsumed_tail
            yield out

    def finished(self):
        return self.engine.eof

    def left_over(self):
        return len(self.engine.unused_data) + len(self.engine.unconsumed_tail)


class _Brotli:
    """brotli 1.2 and later (brotli_module() takes no other): with output_buffer_limit a call returns at most about OUT_PIECE and the rest
    is drained with empty input (can_accept_more_data() can say True while output is still held, so the drain runs until a call returns
    nothing). A brotli decoder refuses bytes after the end of its stream: that shows as Damaged, and the replay (below) finds where the end was."""
    piece = 16384

    def __init__(self, module):
        self.engine = module.Decompressor()

    def feed(self, data):
        try:
            yield self.engine.process(data, output_buffer_limit=OUT_PIECE)
            while True:               # what the piece holds past the limit comes with empty input, until a call returns nothing
                out = self.engine.process(b"", output_buffer_limit=OUT_PIECE)
                if not out:
                    break
                yield out
        except Exception:  # noqa: BLE001 - the module's own error class; its message is not repeated
            raise Damaged()

    def finished(self):
        return bool(self.engine.is_finished()) if hasattr(self.engine, "is_finished") else False

    def left_over(self):
        return 0


class _ZstdStd:
    """The standard library's zstd (compression.zstd): output bounded a call, the stream's end and what followed it said by the engine."""
    piece = 8192

    def __init__(self, module):
        self.engine = module.ZstdDecompressor()

    def feed(self, data):
        try:
            out = self.engine.decompress(data, OUT_PIECE)
            yield out
            while not self.engine.eof and not self.engine.needs_input:
                out = self.engine.decompress(b"", OUT_PIECE)
                if not out:
                    break
                yield out
        except Exception:  # noqa: BLE001
            raise Damaged()

    def finished(self):
        return self.engine.eof

    def left_over(self):
        return len(self.engine.unused_data)


class _Zstandard:
    """The zstandard module: a call's output is not bounded, so the input goes in 256 bytes at a time. A zstd block decodes to at most
    128 KiB and takes at least 4 stored bytes, so one call returns at most about 8 MiB."""
    piece = 256

    def __init__(self, module):
        self.engine = module.ZstdDecompressor().decompressobj()

    def feed(self, data):
        try:
            yield self.engine.decompress(data)
        except Exception:  # noqa: BLE001
            raise Damaged()

    def finished(self):
        return bool(getattr(self.engine, "eof", False))

    def left_over(self):
        return len(getattr(self.engine, "unused_data", b"") or b"")


def decoded(stored, encoding, most, state, again):
    """The stored chunks decoded: gzip and deflate with zlib, brotli and zstd with a module when one imports; every decoder's output is
    bounded a call, and what is yielded stops exactly at max_bytes or at MAX_RATIO decoded bytes for one stored byte past the first MiB.
    again(n) reads the first n stored bytes once more: when a decoder refuses a piece, what that piece held before the damage is found by
    decoding again up to it and then feeding it a byte at a time (a gzip whose own CRC fails keeps its last output that way).
    state gets decoded (bytes yielded, which is what the body file holds), stored (stored bytes taken), ended (the stream reached its
    end marker), stream_end (the stored bytes the stream took, when it ended), error (why it stopped early) and cut (the cap that cut it)."""
    state.update({"decoded": 0, "stored": 0, "ended": encoding == "identity", "error": None, "stream_end": None, "cut": None})
    name = {"gzip": "gzip", "deflate": "deflate", "br": "brotli", "zstd": "zstd"}.get(encoding, encoding)

    def take(out):
        """The part of out that may be written: a cap cuts it exactly, and says which cap."""
        by_bytes = most - state["decoded"]
        by_ratio = max(1 << 20, MAX_RATIO * max(1, state["stored"])) - state["decoded"]
        left = min(by_bytes, by_ratio)
        if len(out) > left:
            out = out[:max(0, left)]
            state["cut"] = "max_bytes (%d)" % most if by_bytes <= by_ratio else "%d times its stored size" % MAX_RATIO
            state["error"] = "the decoded body reached %s: it was cut there, after %d bytes" % (state["cut"], state["decoded"] + len(out))
        state["decoded"] += len(out)
        return out

    if encoding == "identity":
        for block in stored:
            state["stored"] += len(block)
            part = take(block)
            if part:
                yield part
            if state["cut"]:
                return
        return
    if encoding in ("gzip", "deflate"):
        wbits = [31 if encoding == "gzip" else 15]

        def make():
            return _Zlib(wbits[0])
    elif encoding == "br":
        module = brotli_module()[0]

        def make():
            return _Brotli(module)
    else:
        module, module_name = zstd_module()

        def make():
            return _ZstdStd(module) if module_name == "compression.zstd" else _Zstandard(module)
    engine = None
    position = 0                       # the stored offset of the next piece fed
    for block in stored:
        state["stored"] += len(block)
        if engine is None:
            if encoding == "deflate" and (len(block) < 2 or (block[0] & 0x0F) != 8 or ((block[0] << 8) | block[1]) % 31):
                wbits[0] = -15         # a server that sends raw deflate under the name: no zlib header
                state["raw_deflate"] = True
            engine = make()
        for at in range(0, len(block), engine.piece):
            piece = block[at:at + engine.piece]
            given = 0                  # what this piece decoded to and was yielded before a refusal: the replay does not give it again
            try:
                for out in engine.feed(piece):
                    tick()
                    part = take(out)
                    given += len(part)
                    if part:
                        yield part
                    if state["cut"]:
                        return
            except Damaged:
                yield from _replay(make, again, position, piece, state, take, name, given)
                return
            if engine.finished():
                state["ended"] = True
                state["stream_end"] = position + len(piece) - engine.left_over()
                return
            position += len(piece)
    if engine is not None and engine.finished():
        state["ended"] = True
        state["stream_end"] = position
        return
    state["error"] = "the %s stream has no end marker: the stored body is cut after %d stored bytes" % (name, state["stored"])


def _replay(make, again, position, piece, state, take, name, given=0):
    """A decoder refused the piece at `position`. Decode the stored bytes before it again (their output was written already, and is
    dropped here), then the piece a byte at a time: what decodes before the refused byte is yielded, except its first `given` bytes,
    which the piece had yielded before the refusal (a decoder is deterministic: the replay decodes the same bytes again, and the body
    holds each decoded byte once), and a stream that ends inside the piece ends there (the bytes after it are what the decoder refused)."""
    engine = make()
    skip = [given]

    def fresh(out):
        """The part of out the body does not hold yet."""
        if skip[0]:
            dropped = min(skip[0], len(out))
            skip[0] -= dropped
            out = out[dropped:]
        return out
    done = 0
    for chunk in again(position):
        for at in range(0, len(chunk), engine.piece):
            tick()
            try:
                for _out in engine.feed(chunk[at:at + engine.piece]):
                    tick()
            except Damaged:
                state["error"] = "the %s stream is damaged after %d decoded bytes (at about stored byte %d)" % (name, state["decoded"], position)
                return
    for k in range(len(piece)):
        if engine.finished():
            state["ended"] = True
            state["stream_end"] = position + k
            return
        try:
            for out in engine.feed(piece[k:k + 1]):
                tick()
                part = take(fresh(out))
                if part:
                    yield part
                if state["cut"]:
                    return
        except Damaged:
            state["error"] = "the %s stream is damaged after %d decoded bytes (at stored byte %d)" % (name, state["decoded"], position + k)
            return
    if engine.finished():
        state["ended"] = True
        state["stream_end"] = position + len(piece) - engine.left_over()
        return
    state["error"] = "the %s stream is damaged after %d decoded bytes (in the stored bytes from %d)" % (name, state["decoded"], position)


def response_headers(stream0):
    """What the stored response says about its body, from the header block inside the entry's first stream (lines separated by NUL,
    as Chromium keeps them): {status_code, content_type, content_encoding, content_length, header_lines, block} or None when no block
    is found. The codings are those of every Content-Encoding line, in order, each line's comma list taken apart (HTTP joins repeated
    lines into one list): two lines are two codings, never the last one alone. Every Content-Length line is read; lines that disagree,
    or a value that is no number, are said (content_length_said) and no length is taken."""
    start = stream0.find(b"HTTP/")
    if start < 0:
        return None
    end = stream0.find(b"\x00\x00", start)
    block = stream0[start:end if end >= 0 else len(stream0)]
    lines = [line for line in block.split(b"\x00") if line]
    info = {"header_lines": len(lines), "block": block}
    first = lines[0].decode("latin-1").split() if lines else []
    if len(first) >= 2 and first[1].isdigit() and len(first[1]) == 3:
        info["status_code"] = int(first[1])
    codings, coding_lines, lengths = [], 0, []
    for line in lines[1:]:
        name, _, value = line.partition(b":")
        name, value = name.strip().lower(), value.strip().decode("latin-1")
        if name == b"content-encoding":
            coding_lines += 1
            codings += [v.strip().lower() for v in value.split(",") if v.strip()]
        elif name == b"content-length":
            lengths.append(value.strip())
        elif name == b"content-type":
            media = MEDIA.match(value)
            info["content_type"] = media.group(1).lower() if media else "(not a media type: see the headers file)"
    if coding_lines:
        info["content_encoding"] = codings if all(TOKEN.match(c) for c in codings) and len(codings) <= 4 else ["(not a token, or more than four codings: see the headers file)"]
        if coding_lines > 1:
            info["content_encoding_lines"] = coding_lines
    if lengths:
        if all(re.fullmatch(r"[0-9]{1,15}", v) for v in lengths) and len({int(v) for v in lengths}) == 1:
            info["content_length"] = int(lengths[0])
        else:
            info["content_length_said"] = "%d Content-Length line(s) that are not one number: see the headers file" % len(lengths)
    return info


RESPONSE_INFO_TRUNCATED = 1 << 12           # net/http/http_response_info.cc: the response was not finished when it was stored


def response_flags(stream0):
    """The flags of the HttpResponseInfo pickle the entry's first stream holds (a 4-byte payload size, then the flags), or None when the
    stream does not read as one (a payload size that does not fit, or a version outside 1 to 3, RESPONSE_INFO_VERSION_MASK's byte)."""
    if len(stream0) < 8:
        return None
    payload, flags = struct.unpack("<Ii", stream0[:8])
    if payload + 4 > len(stream0) or payload < 4 or not 1 <= (flags & 0xFF) <= 3:
        return None
    return flags


def webkit_time(raw):
    """Microseconds since 1601-01-01 UTC as ISO 8601, or None outside 1970 to 2100."""
    seconds = raw / 1000000.0 - 11644473600
    if not 0 <= seconds < 4102444800:
        return None
    whole = int(seconds)
    return time.strftime("%Y-%m-%dT%H:%M:%S", time.gmtime(whole)) + ".%06dZ" % (raw % 1000000)


def esc(raw):
    """A key for a file a reader opens: one line, one field."""
    out = []
    for ch in raw.decode("utf-8", "surrogateescape"):
        o = ord(ch)
        if 0xDC80 <= o <= 0xDCFF:
            out.append("\\x%02x" % (o - 0xDC00))
        elif ch == "\\":
            out.append("\\\\")
        elif o < 0x20 or o == 0x7F:
            out.append("\\x%02x" % o)
        else:
            out.append(ch)
    return "".join(out)


def read_simple(fd, size):
    """A simple-cache entry file (<hash>_0): the header, the key, stream 1 (the body), its end record, stream 0 (the response headers),
    the key's SHA-256 when the flag says so, and stream 0's end record, which alone carries a stream size."""
    if size < SIMPLE_HEADER + 2 * SIMPLE_EOF:
        raise Unreadable("the file is %d bytes, shorter than a header and two end records" % size)
    magic, version, key_length, _key_hash = struct.unpack("<QIII", pread(fd, 20, 0, "the entry header"))
    if magic != SIMPLE_INITIAL:
        raise Unreadable("the file does not begin with the simple-cache entry magic")
    if not 5 <= version <= 9:
        raise Unreadable("simple-cache entry version %d: this tool reads versions 5 to 9 (the layout with 24-byte end records)" % version)
    if key_length == 0 or key_length > KEY_MAX or SIMPLE_HEADER + key_length + 2 * SIMPLE_EOF > size:
        raise Unreadable("the header's key length (%d) does not fit the file" % key_length)
    final, flags0, _crc0, stream0_size = struct.unpack("<QIII", pread(fd, 20, size - SIMPLE_EOF, "stream 0's end record"))
    if final != SIMPLE_FINAL:
        raise Unreadable("the file does not end with a simple-cache end record (it is cut, or it is the entry's other file)")
    stream0_end = size - SIMPLE_EOF - (32 if flags0 & 2 else 0)
    stream0_start = stream0_end - stream0_size
    eof1 = stream0_start - SIMPLE_EOF
    body_start = SIMPLE_HEADER + key_length
    if stream0_size > HEADERS_MAX or eof1 < body_start:
        raise Unreadable("stream 0's recorded size (%d) does not fit between the key and the end of the file" % stream0_size)
    final1, flags1, crc1, _unused = struct.unpack("<QIII", pread(fd, 20, eof1, "stream 1's end record"))
    if final1 != SIMPLE_FINAL:
        raise Unreadable("no end record where stream 1 should end (offset %d)" % eof1)
    key = pread(fd, key_length, SIMPLE_HEADER, "the key")
    entry = {"kind": "Chromium simple cache entry", "format_version": version, "key": key, "body_offset": body_start, "body_stored_bytes": eof1 - body_start,
             "stream0": pread(fd, stream0_size, stream0_start, "stream 0"), "body_crc32": crc1 if flags1 & 1 else None}
    if flags0 & 2:
        entry["key_sha256_matches"] = hashlib.sha256(key).digest() == pread(fd, 32, stream0_end, "the key's SHA-256")
    return entry


class BlockCache:
    """A block-file cache directory: index (a header and a hash table of entry addresses), data_N block files and f_NNNNNN external files."""

    def __init__(self, directory):
        self.directory = directory
        self.files = {}
        fd, size = open_file(os.path.join(directory, "index"), "the cache's index file", follow=False)
        self.files["index"] = (fd, size)
        if size < INDEX_HEADER:
            raise Unreadable("the index is %d bytes, shorter than its header" % size)
        head = pread(fd, 40, 0, "the index header")
        magic, version, self.entries_said, _b, _last, _id, _stats, self.table_len = struct.unpack("<IIiiIiIi", head[:32])
        if magic != INDEX_MAGIC:
            raise Unreadable("the index does not begin with the block-file index magic")
        if version not in (0x20000, 0x20001):
            raise Unreadable("block-file index version 0x%x: this tool reads 2.0 and 2.1" % version)
        self.version = "2.%d" % (version & 0xFFFF)
        if not 0 < self.table_len <= 0x1000000 or INDEX_HEADER + 4 * self.table_len > size:
            self.table_len = max(0, min(0x1000000, (size - INDEX_HEADER) // 4))
            self.table_cut = True

    def close(self):
        for fd, _size in self.files.values():
            os.close(fd)

    def _file(self, name):
        if name not in self.files:
            if len(self.files) > 300:
                raise Unreadable("more than 300 files of the cache would be open")
            try:
                self.files[name] = open_file(os.path.join(self.directory, name), "the cache file %s" % name, follow=False)
            except Refused as exc:      # a file that is missing, a link or not a regular file: what points into it does not read
                raise Unreadable(str(exc))
        return self.files[name]

    def locate(self, address):
        """(file name, offset, the most bytes the address spans) of an initialised address, or Unreadable."""
        if not address & 0x80000000:
            raise Unreadable("an address that is not initialised")
        kind = (address >> 28) & 7
        if kind == 0:
            return "f_%06x" % (address & 0x0FFFFFFF), 0, None
        if kind not in BLOCK_SIZES:
            raise Unreadable("an address of file type %d, which is no data file" % kind)
        blocks, number, start = ((address >> 24) & 3) + 1, (address >> 16) & 0xFF, address & 0xFFFF
        return "data_%d" % number, BLOCK_HEADER + start * BLOCK_SIZES[kind], blocks * BLOCK_SIZES[kind]

    def read(self, address, length, what):
        name, offset, span = self.locate(address)
        fd, size = self._file(name)
        if span is not None and length > span:
            raise Unreadable("%s is %d bytes at an address that spans %d" % (what, length, span))
        if offset + length > size:
            raise Unreadable("%s lies past the end of %s" % (what, name))
        return pread(fd, length, offset, what)

    def entry(self, address):
        raw = self.read(address, ENTRY_STORE, "an entry record")
        _hash, nxt, _rank, _reuse, _refetch, state, created, key_len, long_key = struct.unpack("<IIIiiiQiI", raw[:40])
        sizes, addresses = struct.unpack("<4i", raw[40:56]), struct.unpack("<4I", raw[56:72])
        flags = struct.unpack("<I", raw[72:76])[0]
        if not 0 < key_len <= KEY_MAX or state not in (0, 1, 2) or any(s < 0 for s in sizes):
            raise Unreadable("an entry record whose key length, state or sizes are not an entry's")
        if long_key:
            key = self.read(long_key, key_len, "an entry's long key")
        else:
            _name, _offset, span = self.locate(address)
            if key_len > span - (ENTRY_STORE - KEY_IN_ENTRY):
                raise Unreadable("an entry whose key (%d bytes) does not fit its blocks" % key_len)
            key = self.read(address, (ENTRY_STORE - KEY_IN_ENTRY) + key_len, "an entry and its key")[ENTRY_STORE - KEY_IN_ENTRY:]
        return {"address": address, "next": nxt, "state": state, "created_raw": created, "key": key, "sizes": sizes, "addresses": addresses, "flags": flags}

    def walk(self, problems):
        """Every entry the hash table reaches, in table order then chain order: (row number from 1, entry)."""
        fd, _size = self.files["index"]
        seen, number = set(), 0
        for start in range(0, self.table_len, 4096):
            tick()
            table = pread(fd, 4 * min(4096, self.table_len - start), INDEX_HEADER + 4 * start, "the index table")
            for slot in struct.unpack("<%dI" % (len(table) // 4), table):
                address, hops = slot, 0
                while address:
                    tick()
                    if address in seen or hops > 10000:
                        problems["chains_cut"] += 1
                        break
                    seen.add(address)
                    hops += 1
                    try:
                        entry = self.entry(address)
                    except Unreadable as exc:
                        problems["entries_unreadable"] += 1
                        problems.setdefault("first_unreadable", "an entry at address 0x%08x: %s" % (address, exc))
                        break
                    number += 1
                    yield number, entry
                    if number >= MAX_ENTRIES:
                        problems["stopped_at_limit"] = True
                        return
                    address = entry["next"]

    def stream_problem(self, entry, index):
        """Why one of the entry's data streams cannot be read where its address points (None when it can, or when it has none), opening
        no f_ file: a data file is opened (there are four), an external file is looked at (a link or a file that is not regular is no stream)."""
        size, address = entry["sizes"][index], entry["addresses"][index]
        if size == 0 or not address:
            return None
        try:
            name, offset, span = self.locate(address)
            if span is None:
                st = os.lstat(os.path.join(self.directory, name))
                if not stat.S_ISREG(st.st_mode):
                    return "stream %d is in %s, which is a link or not a regular file" % (index, name)
                file_size = st.st_size
            else:
                file_size = self._file(name)[1]
                if size > span:
                    return "stream %d is %d bytes at an address that spans %d" % (index, size, span)
            if offset + size > file_size:
                return "stream %d lies past the end of %s" % (index, name)
        except Unreadable as exc:
            return "stream %d: %s" % (index, exc)
        except OSError as exc:
            return "stream %d: its file cannot be looked at (%s)" % (index, describe(exc))
        return None

    def stream(self, entry, index):
        """(file descriptor, offset, length) of one of the entry's data streams, or None when it has none."""
        size, address = entry["sizes"][index], entry["addresses"][index]
        if size == 0 or not address:
            return None
        name, offset, span = self.locate(address)
        fd, file_size = self._file(name)
        if span is not None and size > span:
            raise Unreadable("stream %d is %d bytes at an address that spans %d" % (index, size, span))
        if offset + size > file_size:
            raise Unreadable("stream %d lies past the end of %s" % (index, name))
        return fd, offset, size, name


def main():
    args, unknown = read_args(KNOWN_PARAMS)
    seconds = int_param(args, "max_seconds", DEFAULT_SECONDS, 5, MAX_SECONDS)
    most = int_param(args, "max_bytes", DEFAULT_BYTES, 1, MAX_BYTES)
    kind = choice_param(args, "kind", "auto", KINDS)
    encoding = choice_param(args, "encoding", "auto", ENCODINGS)
    listing = bool_param(args, "list")
    number = int_param(args, "entry", None, 1, MAX_ENTRIES)
    address = args.get("address")
    if address is not None:
        if isinstance(address, str) and re.fullmatch(r"(0x)?[0-9a-fA-F]{8}", address):
            address = int(address, 16)
        if isinstance(address, bool) or not isinstance(address, int) or not 0x80000000 <= address <= 0xFFFFFFFF:
            raise Refused("address must be an entry's address as entries.tsv prints it (0x followed by 8 hex digits)")
    if args.get("path") is None:
        raise Refused("path is required: a simple-cache entry file (<16 hex>_0), a block-file cache directory (the one that holds index and data_1), or a plain file. " + RULES[2])
    path = path_param(args.get("path"), "path")
    set_deadline(seconds)
    started = time.monotonic()
    common = {"tool": TOOL, "parser": PARSER, "path": printable(path), "rules": RULES, **({"unrecognised_parameters": unknown} if unknown else {})}
    is_dir = os.path.isdir(path)
    if kind == "auto":
        if is_dir:
            kind = "blockfile"
        else:
            fd, size = open_file(path, "path")
            try:
                head = os.pread(fd, 8, 0)
            finally:
                os.close(fd)
            kind = "simple" if len(head) == 8 and struct.unpack("<Q", head)[0] == SIMPLE_INITIAL else "plain"
            if len(head) >= 4 and struct.unpack("<I", head[:4])[0] in (INDEX_MAGIC, BLOCK_MAGIC):
                raise Refused("path is a file of a block-file cache: give the cache directory that holds it (index, data_0 to data_3 and the f_ files are read together). " + RULES[2])
    if kind == "blockfile" and not is_dir:
        raise Refused("kind blockfile takes the cache directory (the one that holds index and data_1). " + RULES[2])
    if kind != "blockfile" and is_dir:
        raise Refused("path is a directory: only a block-file cache is read as one (kind blockfile). A simple cache is read an entry file at a time")
    if kind != "blockfile" and (listing or number is not None or address is not None):
        raise Refused("list, entry and address go with a block-file cache directory")
    if kind == "blockfile" and not listing and number is None and address is None:
        raise Refused("a block-file cache holds many entries: " + RULES[2])
    if kind == "blockfile" and listing and (number is not None or address is not None):
        raise Refused("list writes the list; entry or address takes one entry: one of them a call")
    common["kind"] = {"simple": "Chromium simple cache entry", "blockfile": "Chromium block-file cache", "plain": "plain file"}[kind]
    place = Place("cache_body")
    cache = None
    opened = []
    unread = Unread("list_stopped_by_the_clock", "chains_cut", "entries_unreadable", "entries_past_the_limit", "index_table_cut",
                    "entries_the_index_count_disagrees_by", "list_streams_unreadable", "structure_unreadable", "sparse_entry",
                    "key_sha256_mismatch", "key_or_headers_not_written", "entry_without_a_check", "response_truncated",
                    "content_length_disagrees", "content_length_not_one_number", "codings_not_decoded", "decoded_by_signature_only",
                    "coding_not_decodable_here", "body_decode_error", "body_not_written_by_the_clock", "body_unreadable", "body_not_written",
                    "body_rest_not_read_by_the_clock", "body_rest_unreadable", "bytes_after_the_stream_end", "crc32_mismatch")

    def finish(answer, status, basis):
        reasons = unread.reasons()
        answer.update({"status": status, "complete": status == "complete", "status_basis": basis, "not_read_or_judged": dict(unread.counts),
                       "output_directory": place.shown, "seconds": round(time.monotonic() - started, 2)})
        if reasons:
            answer["partial_reasons"] = reasons
        if place.note():
            answer["note"] = place.note()
        print_answer(answer, indent=1)
        if status == "failed":
            raise SystemExit(1)

    try:
        if kind == "blockfile":
            cache = BlockCache(path)
            common["format_version"] = cache.version
            problems = {"chains_cut": 0, "entries_unreadable": 0}
            if listing:
                count = [0]

                def lines():
                    yield b"n\taddress\tstate\tcreated_utc\tcreated_raw\tkey_bytes\theaders_bytes\tbody_bytes\tbody_in\tsparse\tkey\n"
                    for n, entry in cache.walk(problems):
                        count[0] = n
                        for index in (0, 1):
                            problem = cache.stream_problem(entry, index)
                            if problem:
                                problems["streams_unreadable"] = problems.get("streams_unreadable", 0) + 1
                                problems.setdefault("first_stream_unreadable", "entry %d (0x%08x): %s" % (n, entry["address"], problem))
                        try:
                            where = cache.locate(entry["addresses"][1])[0] if entry["sizes"][1] and entry["addresses"][1] & 0x80000000 else ""
                        except Unreadable:
                            where = ""         # an address of no data file: counted above, as a stream that does not read
                        yield ("%d\t0x%08x\t%s\t%s\t%d\t%d\t%d\t%d\t%s\t%s\t%s\n" % (
                            n, entry["address"], ("normal", "evicted", "doomed")[entry["state"]], webkit_time(entry["created_raw"]) or "", entry["created_raw"], len(entry["key"]),
                            entry["sizes"][0], entry["sizes"][1], where, "parent" if entry["flags"] & 1 else "child" if entry["flags"] & 2 else "", esc(entry["key"]))).encode("utf-8")

                stopped = None
                try:
                    listed = place.write("entries.tsv", lines(), 0o600)
                except Clock:
                    listed, stopped = None, "the clock ran out after %d entries; the list was not kept" % count[0]
                if stopped:
                    unread.add("list_stopped_by_the_clock", 1, stopped)
                unread.add("chains_cut", problems["chains_cut"], "%d chain(s) of the index's hash table were cut at a loop or at 10000 hops: what they led to is not in the list" % problems["chains_cut"])
                unread.add("entries_unreadable", problems["entries_unreadable"], "%d entry record(s) did not read as entries (the first: %s): what they led to is not in the list" % (
                    problems["entries_unreadable"], problems.get("first_unreadable")))
                unread.add("entries_past_the_limit", 1 if problems.get("stopped_at_limit") else 0, "the list stopped at %d entries: the entries past them are not in the list" % MAX_ENTRIES)
                unread.add("index_table_cut", 1 if getattr(cache, "table_cut", False) else 0, "the index is shorter than its table (or its table length is not one): the slots past it were not read")
                if not stopped and not problems.get("stopped_at_limit") and cache.entries_said != count[0]:
                    unread.add("entries_the_index_count_disagrees_by", abs(cache.entries_said - count[0]),
                               "the index's own count says %d entries and its hash table reaches %d: %s" % (
                                   cache.entries_said, count[0], "entries the count holds are not reached by the table (unlinked, or in a chain that is damaged)"
                                   if cache.entries_said > count[0] else "the count is behind the table (a cache not closed cleanly): which of them the browser held is not settled here"))
                unread.add("list_streams_unreadable", problems.get("streams_unreadable", 0),
                           "%d stream(s) of listed entries point where the cache holds no readable bytes (the first: %s): those entries are listed, "
                           "and their headers or body cannot be taken" % (problems.get("streams_unreadable", 0), problems.get("first_stream_unreadable")))
                answer = {**common, "mode": "list", "entries": count[0], "entries_the_index_says": cache.entries_said, **({"entries_file": listed} if listed else {}),
                          "columns": ["n", "address", "state", "created_utc", "created_raw", "key_bytes", "headers_bytes", "body_bytes", "body_in", "sparse", "key"],
                          "created": "created_raw is microseconds since 1601-01-01 UTC, as the cache keeps it; created_utc is that value as ISO 8601",
                          "key_in_answer": False, "problems": problems}
                finish(answer, "failed" if stopped else "partial" if unread else "complete",
                       ("every entry the index's hash table reaches was read and listed: %d, the index's own count" % count[0]) if not unread else
                       "the list is not whole: %s" % "; ".join(unread.reasons()))
                return
            entry = None
            if address is not None:
                try:
                    entry = cache.entry(address)
                except Unreadable as exc:
                    raise Refused("no entry reads at address 0x%08x (%s): take the address from the list. %s" % (address, exc, RULES[2]))
            else:
                for n, candidate in cache.walk(problems):
                    if n == number:
                        entry = candidate
                        break
                if entry is None:
                    raise Refused("the cache's table reaches fewer than %d entries: take the row number from the list. %s" % (number, RULES[2]))
            source = {"address": "0x%08x" % entry["address"], "state": ("normal", "evicted", "doomed")[entry["state"]], "created_raw": entry["created_raw"],
                      "created_utc": webkit_time(entry["created_raw"]), "created_clock": "microseconds since 1601-01-01 UTC, the browser's clock"}
            key = entry["key"]
            stream0 = b""
            located = cache.stream(entry, 0)
            if located:
                if located[2] > HEADERS_MAX:
                    raise Unreadable("the entry's header stream is %d bytes" % located[2])
                stream0 = pread(located[0], located[2], located[1], "the entry's header stream")
            body = cache.stream(entry, 1)
            if entry["flags"] & 3:
                source["sparse"] = "parent" if entry["flags"] & 1 else "child"
                unread.add("sparse_entry", 1, "the entry is a sparse %s: a sparse body is kept in child entries and is not put together here" % source["sparse"])
            body_fd, body_offset, body_length = (body[0], body[1], body[2]) if body else (None, 0, 0)
            if body:
                source["body_in"] = body[3]
                source["body_offset"] = body_offset
            expected_crc = None
        elif kind == "simple":
            fd, size = open_file(path, "path")
            opened.append(fd)
            entry = read_simple(fd, size)
            common["format_version"] = entry["format_version"]
            source = {"body_offset": entry["body_offset"]}
            if "key_sha256_matches" in entry:
                source["key_sha256_matches"] = entry["key_sha256_matches"]
                if not entry["key_sha256_matches"]:
                    unread.add("key_sha256_mismatch", 1, "the entry's key does not match the SHA-256 the entry records: the key or its length in the header is damaged, so where "
                                   "the body begins is not certain and the body file may not be the stored body")
            key, stream0 = entry["key"], entry["stream0"]
            body_fd, body_offset, body_length, expected_crc = fd, entry["body_offset"], entry["body_stored_bytes"], entry["body_crc32"]
        else:
            fd, size = open_file(path, "path")
            opened.append(fd)
            key, stream0, source = None, b"", {}
            body_fd, body_offset, body_length, expected_crc = fd, 0, size, None
    except Unreadable as exc:
        unread.add("structure_unreadable", 1, str(exc))
        finish({**common, "error": "the cache structure did not read: %s" % exc}, "failed", "the structure did not read as the format says (%s): no body was written, and that is not an empty entry" % exc)
        return
    except Clock:
        finish({**common, "error": "the tool's clock ran out before the entry was located"}, "failed", "the clock (max_seconds %d) ran out before the entry was located: nothing was written" % seconds)
        return

    answer = {**common, **source}
    files = {}
    headers = response_headers(stream0) if stream0 else None
    try:
        if key is not None:
            answer["key_bytes"] = len(key)
            files["key"] = place.write("key.txt", esc(key).encode("utf-8") + b"\n", 0o600)
        if headers:
            files["headers"] = place.write("headers.txt", b"\n".join(headers["block"].split(b"\x00")) + b"\n", 0o600)
            answer["response"] = {k: headers[k] for k in ("status_code", "content_type", "content_encoding", "content_encoding_lines", "content_length",
                                                          "content_length_said", "header_lines") if k in headers}
        elif kind != "plain":
            answer["response"] = {"said": "no HTTP header block was found in the entry's first stream (%d bytes)" % len(stream0)}
    except OSError as exc:
        files["write_error"] = "the key or the headers could not be written (%s)" % describe(exc)
        unread.add("key_or_headers_not_written", 1, "the key or the headers file could not be written")
    answer["key_in_answer"] = False
    if kind == "simple" and "key_sha256_matches" not in source and expected_crc is None:
        answer["checks"] = "none: the entry records neither its key's SHA-256 nor its body's CRC-32"
        unread.add("entry_without_a_check", 1, "the entry records neither its key's SHA-256 nor its body's CRC-32: where the body begins rests on the key length in the header alone, "
                       "and nothing checks that the body file holds the stored body")
    flags = response_flags(stream0) if stream0 else None
    if flags is not None and flags & RESPONSE_INFO_TRUNCATED:
        answer.setdefault("response", {})["truncated"] = True
        unread.add("response_truncated", 1, "the entry marks its own response truncated (the browser stored it before the response had ended): the body is not the whole response")
    if headers and "content_length" in headers and headers["content_length"] != body_length:
        unread.add("content_length_disagrees", 1, "the response's Content-Length says %d bytes and the entry stores %d: the stored body is %s" % (
            headers["content_length"], body_length, "cut" if body_length < headers["content_length"] else "not the length the response said"))
    if headers and "content_length_said" in headers:
        unread.add("content_length_not_one_number", 1, "the response's Content-Length lines are not one number: the stored body's length is not checked against them")
    # Which encoding: the caller's word, else the stored response's header, else a signature (gzip and zstd have one; deflate and brotli do not).
    said_by = "the caller"
    head = b""
    if body_length:
        head = os.pread(body_fd, 64, body_offset)
    if encoding == "auto":
        codings = (headers or {}).get("content_encoding")
        if codings:
            said_by = "the stored response's Content-Encoding header"
            if len(codings) == 1 and codings[0] in ("gzip", "x-gzip", "deflate", "br", "zstd", "identity"):
                encoding = "gzip" if codings[0] == "x-gzip" else codings[0]
            else:
                encoding = "identity"
                if len(codings) > 1:
                    answer["not_decoded"] = ("the response names %d content codings at once (%s, in the order they were applied, from every Content-Encoding "
                                             "line): several codings are not decoded, and the stored bytes were written as they are" % (len(codings), ", ".join(codings)))
                    unread.add("codings_not_decoded", 1, "the response names %d content codings at once (%s): several are not decoded, and the body file holds the stored bytes, "
                                   "still coded" % (len(codings), ", ".join(codings)))
                else:
                    answer["not_decoded"] = "the header names a coding this tool does not decode: the stored bytes were written as they are"
                    unread.add("codings_not_decoded", 1, "the body's content coding is not one this tool decodes")
        elif head[:3] == b"\x1f\x8b\x08" or head[:4] == b"\x28\xb5\x2f\xfd":
            encoding, said_by = "gzip" if head[:1] == b"\x1f" else "zstd", "the stored bytes' own signature (no header said)"
            if headers:
                answer["signature_note"] = ("the stored response names no Content-Encoding, and its body begins with a %s signature: it was decoded by that "
                                            "signature, so the body file holds what the %s file decodes to, while the response's own body is the %s file as "
                                            "stored (encoding: identity writes that)" % ((encoding,) * 3))
                unread.add("decoded_by_signature_only", 1, "decoded as %s by the bytes' own signature although the stored response names no Content-Encoding: the body may be a %s "
                               "file the server sent as it is (encoding: identity writes the stored bytes)" % (encoding, encoding))
        else:
            encoding, said_by = "identity", "nothing: no header named a coding and the bytes begin with no gzip or zstd signature (deflate and brotli have none)"
    undecodable, why_not = None, None
    if encoding == "br" and brotli_module()[0] is None:
        undecodable, why_not = "brotli: not decodable here", brotli_module()[2]
    if encoding == "zstd" and zstd_module()[0] is None:
        undecodable, why_not = "zstd: not decodable here", "no compression.zstd or zstandard module imports in this image"
    answer["encoding"] = {"coding": encoding, "said_by": said_by}
    if encoding in ("br", "zstd") and not undecodable:
        answer["encoding"]["decoder"] = (brotli_module() if encoding == "br" else zstd_module())[1] + " (a Python module of this image)"
    if undecodable:
        answer["encoding"]["decoded"] = False
        answer["encoding"]["said"] = "%s (%s): the stored bytes were written as they are, still compressed" % (undecodable, why_not)
        unread.add("coding_not_decodable_here", 1, undecodable)
    state = {}
    body_info = {"stored_bytes": body_length}
    if body_length == 0:
        body_info["said"] = "the entry has no body bytes (a redirect, a 304, or headers only)"
    else:
        digest = hashlib.sha256()
        crc = [0, 0]                    # the CRC-32 of the stored bytes read, and how many were read

        def stored():
            for block in chunks_of(body_fd, body_offset, body_length):
                crc[0] = zlib.crc32(block, crc[0])
                crc[1] += len(block)
                yield block

        def kept(source_chunks):
            for block in source_chunks:
                digest.update(block)
                yield block

        source_chunks = stored()
        stream = decoded(source_chunks, "identity" if undecodable else encoding, most, state, lambda n: chunks_of(body_fd, body_offset, n))
        try:
            first = next(stream, b"")
            what, suffix = detect_type(first) if not undecodable else ("%s-compressed bytes, not decoded" % ("brotli" if encoding == "br" else "zstd"), "br" if encoding == "br" else "zst")
            files["body"] = place.write("body.%s" % suffix, kept(itertools.chain([first], stream)), 0o600)
            body_info.update({"decoded_bytes": state["decoded"], "sha256": digest.hexdigest(), "sha256_of": "the body file as written",
                              "decoded_bytes_are": "the bytes the body file holds", "detected_type": what,
                              "detected_by": "the first bytes of the body (a reading, not a validation)"})
            if state.get("raw_deflate"):
                body_info["deflate_form"] = "raw (no zlib header)"
            if state["cut"]:
                body_info.update({"truncated": True, "cap": state["cut"],
                                  "whole_kept_in": "the stored entry itself: its %d stored bytes from offset %d of the source (the body file holds the first %d decoded bytes)" % (body_length, body_offset, state["decoded"])})
            if state["error"]:
                body_info["decode_error"] = state["error"]
                unread.add("body_decode_error", 1, state["error"])
                if state["decoded"] == 0 and place.remove("body.%s" % suffix):
                    del files["body"]                 # nothing decoded: an empty file would read as an empty body
                    body_info["said"] = "not written: not one byte of the body decoded"
                    for key in ("sha256", "sha256_of", "decoded_bytes_are", "detected_type", "detected_by"):
                        body_info.pop(key, None)
        except Clock:
            unread.add("body_not_written_by_the_clock", 1, "the clock (max_seconds %d) ran out while the body was written: the body file was removed" % seconds)
            body_info["said"] = "not written: the clock ran out"
            files.pop("body", None)
        except Unreadable as exc:
            unread.add("body_unreadable", 1, str(exc))
            body_info["said"] = "not written whole: %s" % exc
        except OSError as exc:
            files["write_error"] = "the body file could not be written (%s)" % describe(exc)
            unread.add("body_not_written", 1, "the body file could not be written")
        # The rest of the stored body is read whatever stopped the decoder (its end marker, a cap, damage): what follows the end of a
        # stream is counted from it, and the entry's own CRC-32 covers every stored byte.
        if "body" in files or state.get("error"):
            try:
                for _block in source_chunks:
                    pass
            except Clock:
                unread.add("body_rest_not_read_by_the_clock", 1, "the clock (max_seconds %d) ran out before the rest of the stored body was read: what follows the stream and the entry's CRC-32 were not checked" % seconds)
            except Unreadable as exc:
                unread.add("body_rest_unreadable", 1, str(exc))
        if state.get("ended") and state.get("stream_end") is not None and encoding != "identity" and not undecodable and crc[1] == body_length:
            after = body_length - state["stream_end"]
            if after > 0:
                body_info.update({"stream_ends_at": state["stream_end"], "bytes_after_the_stream_end": after})
                unread.add("bytes_after_the_stream_end", after, "the %s stream ends at stored byte %d and %d stored byte(s) follow it, not decoded" % (
                    {"br": "brotli"}.get(encoding, encoding), state["stream_end"], after))
        if expected_crc is not None and crc[1] == body_length:
            body_info["stored_crc32_matches"] = (crc[0] & 0xFFFFFFFF) == expected_crc
            if not body_info["stored_crc32_matches"]:
                unread.add("crc32_mismatch", 1, "the stored body does not match the CRC-32 its entry records")
        elif expected_crc is not None:
            body_info["stored_crc32_matches"] = None
            body_info["stored_crc32_said"] = "not checked: the stored body was not read to its end"
    answer["body"] = body_info
    answer["files"] = files
    for fd in opened:
        os.close(fd)
    if cache is not None:
        cache.close()
    wrote = "body" in files
    status = "partial" if unread else "complete"
    if body_length and not wrote:
        status = "failed"
    basis = ("the entry was read whole: its %d stored body bytes were %s and written (%d bytes), with the key and the headers beside it" % (
        body_length, "decoded as %s" % encoding if encoding != "identity" else "written as they are (no coding to lift)", state.get("decoded", 0))
        if status == "complete" and kind != "plain" else
        "the file was read whole: its %d bytes were %s and written (%d bytes)" % (body_length, "decoded as %s" % encoding if encoding != "identity" else "written as they are", state.get("decoded", 0))
        if status == "complete" else "not everything asked for was done: %s" % "; ".join(unread.reasons()))
    finish(answer, status, basis)


if __name__ == "__main__":
    exit_code = 0
    try:
        answered(main)
    except SystemExit as stop:
        exit_code = _code(stop)
    _leave(exit_code)
