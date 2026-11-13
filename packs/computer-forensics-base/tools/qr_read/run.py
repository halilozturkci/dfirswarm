#!/usr/bin/env python3
"""Read QR symbols from pictures with the standard library alone, and say what was looked for when none is read.

A picture (a PNG by a reader of its own; any format Pillow reads when Pillow imports) is thresholded, its finder patterns are found
by their 1:1:3:1:1 runs, the module grid is sampled through the three finders (and the alignment pattern, from version 2), the format
word is read against all 32 valid words (BCH 15,5, up to three wrong bits), the mask is lifted, the codewords are corrected with
Reed-Solomon and the numeric, alphanumeric and byte segments are read. Versions 1 to 10, the four levels, the eight masks.

Two readings need less than three finders. `repaint`: the grid is taken from the two finders that are left (as neighbouring or as
opposite corners) or from the box of the dark pixels, every fixed module is taken as the standard's instead of being read, and the
format word and Reed-Solomon decide; a repainted copy of the symbol is written. `fragments`: several pictures that are rectangular
pieces of one symbol are each cut into modules, every place of every piece is ranked on the fixed modules it would cover, and whole
placements are scored on the format word and the Reed-Solomon syndromes.

Before any picture is read a control is run: a symbol made here, with modules flipped, is read back by the same code. One row per
input: decoded (version, level, mask, errors corrected, the payload's length and the file it was written to, never the payload) or
"not a symbol" with what was looked for. One JSON answer always; the tool's own clock (max_seconds) ends a search as partial.
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


import collections
import errno
import hashlib
import math
import re
import stat
import struct
import time
import warnings
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


TOOL = {"name": "qr_read", "version": 1}
PARSER = "qr_read/1"
DEFAULT_SECONDS, MAX_SECONDS = 90, 100          # under the manifest's 120
MAX_INPUTS = 64
KNOWN_PARAMS = {"image", "images", "mode", "box", "version", "module_pixels", "reader", "max_seconds", "self_test"}
MODES = ("auto", "finders", "repaint", "fragments")
RULES = [
    "A decoded payload is a reading of a picture: it says what the symbol encodes, not who made it, when, or that a link in it was opened. "
    "Cite the picture, the payload file and version, level and mask; errors_corrected says how much of the symbol was repaired.",
    "The payload is in a file, never in the answer: it can be a credential (an otpauth secret, a Wi-Fi passphrase, a login link). When "
    "payload_shape says so, or the case suggests it, run the job with secret_output: true and cite the file, not the text.",
    "A symbol with a finder erased or overdrawn is read by mode repaint (auto tries it too): the grid is taken from the two finders "
    "left or from the box of the dark pixels, the fixed patterns are taken as the standard's, and the format word and Reed-Solomon "
    "decide. Pieces of one symbol go to mode fragments together, as images: [..], never one call a piece.",
    "\"not a symbol\" is a statement about these methods on this picture (looked_for lists them) and holds only because the planted "
    "control was read first: a symbol under perspective, torn along a ragged line, of version 11 or above, or of another kind (Data "
    "Matrix, Aztec, a bar code) is not read here, and that is not its absence.",
]
NOT_READ = ("versions 11 to 40; Micro QR, rMQR and every other symbology; a symbol photographed at a strong angle or on a curved surface "
            "(one alignment pattern is used, from version 2); pieces that are turned against each other, scaled differently or not "
            "rectangular; a piece set with a hole is read only while Reed-Solomon can still correct what is missing (missing modules "
            "count as light, there is no erasure decoding)")


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
                agent = re.sub(r"[^A-Za-z0-9_.-]", "_", os.environ.get("AGENT_ID") or "tool")
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


# ---- pictures: a small PNG reader and writer of its own, and Pillow when it imports ---------------------------------------------------
PNG_MAGIC = b"\x89PNG\r\n\x1a\n"
MAX_PIXELS = 36_000_000            # a picture larger than this is refused (its rows would not fit the tool's memory and clock)
MAX_IMAGE_BYTES = 256 << 20
MAX_PNG_ROWS = 256 << 20           # the inflated rows of a PNG the built-in reader holds


class NotAPicture(Exception):
    """The file is not a picture this tool can read; the text says what was found and what would read it."""


class Picture:
    """A picture as rows of bytes: `gray` (one byte a pixel, 0 black to 255 white) always, `rgb` (three bytes a pixel) when it was asked for."""

    def __init__(self, width, height, gray, rgb=None, reader=""):
        self.width, self.height, self.gray, self.rgb, self.reader = width, height, gray, rgb, reader


def _unfilter(kind, line, previous, bpp):
    if kind == 0:
        return line
    out = bytearray(line)
    if kind == 1:
        for i in range(bpp, len(out)):
            out[i] = (out[i] + out[i - bpp]) & 255
    elif kind == 2:
        if previous is not None:
            out = bytearray((a + b) & 255 for a, b in zip(out, previous))
    elif kind == 3:
        for i in range(len(out)):
            left = out[i - bpp] if i >= bpp else 0
            up = previous[i] if previous is not None else 0
            out[i] = (out[i] + ((left + up) >> 1)) & 255
    elif kind == 4:
        for i in range(len(out)):
            a = out[i - bpp] if i >= bpp else 0
            b = previous[i] if previous is not None else 0
            c = previous[i - bpp] if previous is not None and i >= bpp else 0
            p = a + b - c
            pa, pb, pc = abs(p - a), abs(p - b), abs(p - c)
            out[i] = (out[i] + (a if pa <= pb and pa <= pc else b if pb <= pc else c)) & 255
    else:
        raise NotAPicture("a PNG row with the unknown filter %d" % kind)
    return bytes(out)


def read_png(data, want_rgb=False, tick=None):
    """A PNG read with the standard library alone: 8 and 16-bit grey, RGB, palette and alpha forms and the 1, 2 and 4-bit grey and palette
    forms, not interlaced. Transparency is put on white. NotAPicture for anything else; tick() is called once a row (the clock)."""
    if data[:8] != PNG_MAGIC:
        raise NotAPicture("not a PNG (no PNG signature)")
    at, header, palette, alpha, parts = 8, None, None, None, []
    while at + 12 <= len(data):
        length = int.from_bytes(data[at:at + 4], "big")
        kind = data[at + 4:at + 8]
        body = data[at + 8:at + 8 + length]
        if len(body) != length:
            raise NotAPicture("a PNG cut inside its %s chunk" % kind.decode("ascii", "replace"))
        if zlib.crc32(kind + body) != int.from_bytes(data[at + 8 + length:at + 12 + length], "big"):
            raise NotAPicture("a PNG whose %s chunk fails its CRC" % "".join(ch if ch.isalpha() else "?" for ch in kind.decode("latin-1")))
        at += 12 + length
        if kind == b"IHDR":
            if length != 13:
                raise NotAPicture("a PNG with a header of the wrong length")
            header = struct.unpack(">IIBBBBB", body)
        elif kind == b"PLTE":
            palette = body
        elif kind == b"tRNS":
            alpha = body
        elif kind == b"IDAT":
            parts.append(body)
        elif kind == b"IEND":
            break
    if header is None or not parts:
        raise NotAPicture("a PNG with no header or no image data")
    width, height, depth, colour, _compression, _filter, interlace = header
    if width == 0 or height == 0 or width * height > MAX_PIXELS:
        raise NotAPicture("a PNG of %d x %d pixels (this tool reads up to %d pixels)" % (width, height, MAX_PIXELS))
    channels = {0: 1, 2: 3, 3: 1, 4: 2, 6: 4}.get(colour)
    if channels is None or depth not in (1, 2, 4, 8, 16) or (depth < 8 and colour not in (0, 3)) or (depth == 16 and colour == 3):
        raise NotAPicture("a PNG of colour type %d at %d bits, which the format does not define" % (colour, depth))
    if interlace:
        raise NotAPicture("an interlaced PNG: the built-in reader does not read Adam7 (Pillow does, when it is installed)")
    if colour == 3 and palette is None:
        raise NotAPicture("a palette PNG with no palette")
    stride = (width * channels * depth + 7) // 8
    bpp = max(1, channels * depth // 8)
    if height * (stride + 1) > MAX_PNG_ROWS:
        raise NotAPicture("a PNG whose rows are %d bytes when inflated (the built-in reader takes up to %d; Pillow, when it is installed, reads it)" % (height * (stride + 1), MAX_PNG_ROWS))
    inflater = zlib.decompressobj()
    raw = bytearray()
    want = height * (stride + 1)
    for part in parts:
        raw += inflater.decompress(part, want - len(raw) + 1)
        if len(raw) > want:
            break
        if tick:
            tick()
    if len(raw) < want:
        raise NotAPicture("a PNG whose image data ends after %d of %d bytes" % (len(raw), want))
    if palette is not None:
        entries = len(palette) // 3
        pal_gray = bytearray(256)
        pal_rgb = [b"\xff\xff\xff"] * 256
        for i in range(min(256, entries)):
            r, g, b = palette[3 * i:3 * i + 3]
            a = alpha[i] if alpha is not None and i < len(alpha) else 255
            r, g, b = ((v * a + 255 * (255 - a)) // 255 for v in (r, g, b))
            pal_gray[i] = (r * 299 + g * 587 + b * 114) // 1000
            pal_rgb[i] = bytes((r, g, b))
    gray, rgb, previous = [], [] if want_rgb else None, None
    for y in range(height):
        if tick:
            tick()
        start = y * (stride + 1)
        line = _unfilter(raw[start], bytes(raw[start + 1:start + 1 + stride]), previous, bpp)
        previous = line
        if depth == 16:
            line = line[0::2]
        elif depth < 8:
            mask, scale = (1 << depth) - 1, 255 // ((1 << depth) - 1) if colour == 0 else 1
            line = bytes(((line[(x * depth) >> 3] >> (8 - depth - (x * depth) % 8)) & mask) * scale for x in range(width))
        if colour == 0:
            g = line
        elif colour == 3:
            g = line.translate(bytes(pal_gray))
        elif colour == 2:
            g = bytes((line[i] * 299 + line[i + 1] * 587 + line[i + 2] * 114) // 1000 for i in range(0, 3 * width, 3))
        elif colour == 4:
            g = bytes((line[i] * line[i + 1] + 255 * (255 - line[i + 1])) // 255 for i in range(0, 2 * width, 2))
        else:
            g = bytes(((line[i] * 299 + line[i + 1] * 587 + line[i + 2] * 114) // 1000 * line[i + 3] + 255 * (255 - line[i + 3])) // 255 for i in range(0, 4 * width, 4))
        gray.append(g)
        if want_rgb:
            if colour == 2:
                rgb.append(line)
            elif colour == 3:
                rgb.append(b"".join(pal_rgb[v] for v in line))
            elif colour == 6:
                rgb.append(bytes((line[i + k] * line[i + 3] + 255 * (255 - line[i + 3])) // 255 for i in range(0, 4 * width, 4) for k in range(3)))
            else:
                rgb.append(bytes(v for v in g for _ in range(3)))
    return Picture(width, height, gray, rgb, "the built-in PNG reader")


def pillow():
    """The Pillow module, or None when it does not import here."""
    if "module" not in _PILLOW:
        try:
            from PIL import Image
            Image.MAX_IMAGE_PIXELS = MAX_PIXELS
            _PILLOW["module"] = Image
            _PILLOW["version"] = getattr(__import__("PIL"), "__version__", "?")
        except Exception:  # noqa: BLE001 - not installed, or broken: the built-in reader is what there is
            _PILLOW["module"] = None
    return _PILLOW["module"]


_PILLOW = {}


def read_picture(data, want_rgb=False, reader="auto", tick=None):
    """The picture in `data`: a PNG by the built-in reader when it reads it (or when reader is "builtin"), anything else, and a PNG the
    built-in reader refuses, by Pillow when it imports. NotAPicture says which reader said what."""
    first = None
    if data[:8] == PNG_MAGIC or reader == "builtin":
        try:
            return read_png(data, want_rgb, tick)
        except NotAPicture as exc:
            first = str(exc)
            if reader == "builtin":
                raise
    image_module = pillow() if reader != "builtin" else None
    if image_module is None:
        raise NotAPicture(first or "not a PNG, and Pillow, which reads the other picture formats, does not import here")
    import io
    try:
        with warnings.catch_warnings():
            warnings.simplefilter("error")
            image = image_module.open(io.BytesIO(data))
            if image.width * image.height > MAX_PIXELS:
                raise NotAPicture("a picture of %d x %d pixels (this tool reads up to %d pixels)" % (image.width, image.height, MAX_PIXELS))
            image.load()
            if image.mode in ("RGBA", "LA", "PA") or "transparency" in image.info:
                image = image.convert("RGBA")
                flat = image_module.new("RGB", image.size, (255, 255, 255))
                flat.paste(image, mask=image.split()[3])
                image = flat
            grey = image.convert("L")
            width, height = grey.size
            flat_gray = grey.tobytes()
            gray = [flat_gray[y * width:(y + 1) * width] for y in range(height)]
            rgb = None
            if want_rgb:
                flat_rgb = image.convert("RGB").tobytes()
                rgb = [flat_rgb[y * width * 3:(y + 1) * width * 3] for y in range(height)]
    except NotAPicture:
        raise
    except Exception as exc:  # noqa: BLE001 - Pillow's own errors, a decompression-bomb warning included: the class is said, never the message
        raise NotAPicture("%sPillow does not read it as a picture (%s)" % ("the built-in reader: %s; " % first if first else "", type(exc).__name__))
    return Picture(width, height, gray, rgb, "Pillow %s" % _PILLOW.get("version", "?"))


def png_bytes(width, height, rows, channels=1):
    """A PNG (8-bit grey, or RGB with channels 3) from rows of bytes."""
    raw = b"".join(b"\x00" + bytes(row) for row in rows)

    def chunk(kind, body):
        return struct.pack(">I", len(body)) + kind + body + struct.pack(">I", zlib.crc32(kind + body))

    return (PNG_MAGIC + chunk(b"IHDR", struct.pack(">IIBBBBB", width, height, 8, 0 if channels == 1 else 2, 0, 0, 0))
            + chunk(b"IDAT", zlib.compress(raw, 6)) + chunk(b"IEND", b""))


def otsu(gray_rows, tick=None):
    """The threshold that best splits the grey values in two (Otsu): a pixel below it is dark."""
    histogram = [0] * 256
    step = max(1, len(gray_rows) // 400)
    for row in gray_rows[::step]:
        if tick:
            tick()
        for value, count in collections.Counter(row).items():
            histogram[value] += count
    total = sum(histogram)
    if total == 0:
        return 128
    sum_all = sum(i * h for i, h in enumerate(histogram))
    best, threshold, weight, running = -1.0, 128, 0, 0
    for i in range(256):
        weight += histogram[i]
        if weight == 0:
            continue
        if weight == total:
            break
        running += i * histogram[i]
        mean_low, mean_high = running / weight, (sum_all - running) / (total - weight)
        between = weight * (total - weight) * (mean_low - mean_high) ** 2
        if between > best:
            best, threshold = between, i + 1
    return threshold


def binarise(gray_rows, threshold=None, tick=None):
    """Rows of 0 (light) and 1 (dark)."""
    threshold = otsu(gray_rows, tick) if threshold is None else threshold
    table = bytes(1 if v < threshold else 0 for v in range(256))
    return [row.translate(table) for row in gray_rows], threshold


# ---- the symbol: tables, Reed-Solomon, the encoder of the control and the decoder ---------------------------------------------------
# ISO/IEC 18004 versions 1 to 10. EC_TABLE[version][level] = (error-correction codewords per block, blocks); the data codewords of a
# block follow from the version's total (the short blocks first). The totals are checked against the count of data modules in self_check().
LEVELS = "LMQH"
LEVEL_BITS = {"L": 1, "M": 0, "Q": 3, "H": 2}
LEVEL_OF_BITS = {v: k for k, v in LEVEL_BITS.items()}
TOTAL_CODEWORDS = {1: 26, 2: 44, 3: 70, 4: 100, 5: 134, 6: 172, 7: 196, 8: 242, 9: 292, 10: 346}
EC_TABLE = {
    1: {"L": (7, 1), "M": (10, 1), "Q": (13, 1), "H": (17, 1)},
    2: {"L": (10, 1), "M": (16, 1), "Q": (22, 1), "H": (28, 1)},
    3: {"L": (15, 1), "M": (26, 1), "Q": (18, 2), "H": (22, 2)},
    4: {"L": (20, 1), "M": (18, 2), "Q": (26, 2), "H": (16, 4)},
    5: {"L": (26, 1), "M": (24, 2), "Q": (18, 4), "H": (22, 4)},
    6: {"L": (18, 2), "M": (16, 4), "Q": (24, 4), "H": (28, 4)},
    7: {"L": (20, 2), "M": (18, 4), "Q": (18, 6), "H": (26, 5)},
    8: {"L": (24, 2), "M": (22, 4), "Q": (22, 6), "H": (26, 6)},
    9: {"L": (30, 2), "M": (22, 5), "Q": (20, 8), "H": (24, 8)},
    10: {"L": (18, 4), "M": (26, 5), "Q": (24, 8), "H": (28, 8)},
}
ALIGNMENT = {1: [], 2: [6, 18], 3: [6, 22], 4: [6, 26], 5: [6, 30], 6: [6, 34], 7: [6, 22, 38], 8: [6, 24, 42], 9: [6, 26, 46], 10: [6, 28, 50]}
MAX_VERSION = 10
ALPHANUMERIC = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ $%*+-./:"
MASKS = (
    lambda r, c: (r + c) % 2 == 0, lambda r, c: r % 2 == 0, lambda r, c: c % 3 == 0, lambda r, c: (r + c) % 3 == 0,
    lambda r, c: (r // 2 + c // 3) % 2 == 0, lambda r, c: (r * c) % 2 + (r * c) % 3 == 0,
    lambda r, c: ((r * c) % 2 + (r * c) % 3) % 2 == 0, lambda r, c: ((r + c) % 2 + (r * c) % 3) % 2 == 0,
)

GF_EXP = [0] * 512
GF_LOG = [0] * 256
_x = 1
for _i in range(255):
    GF_EXP[_i] = _x
    GF_LOG[_x] = _i
    _x <<= 1
    if _x & 0x100:
        _x ^= 0x11D
for _i in range(255, 512):
    GF_EXP[_i] = GF_EXP[_i - 255]


def gf_mul(a, b):
    return 0 if a == 0 or b == 0 else GF_EXP[GF_LOG[a] + GF_LOG[b]]


def gf_div(a, b):
    return 0 if a == 0 else GF_EXP[(GF_LOG[a] - GF_LOG[b]) % 255]


def poly_eval(poly, x):
    """poly[0] is the highest power."""
    y = 0
    for coefficient in poly:
        y = gf_mul(y, x) ^ coefficient
    return y


def rs_generator(degree):
    gen = [1]
    for i in range(degree):
        nxt = [0] * (len(gen) + 1)
        for j, g in enumerate(gen):
            nxt[j] ^= g
            nxt[j + 1] ^= gf_mul(g, GF_EXP[i])
        gen = nxt
    return gen


def rs_encode(data, degree):
    gen = rs_generator(degree)
    rem = [0] * degree
    for byte in data:
        factor = byte ^ rem[0]
        rem = rem[1:] + [0]
        if factor:
            for i in range(degree):
                rem[i] ^= gf_mul(gen[i + 1], factor)
    return rem


def rs_syndromes(block, degree):
    return [poly_eval(block, GF_EXP[i]) for i in range(degree)]


def rs_correct(block, degree):
    """The block corrected in place of a copy: (block, errors corrected), or (None, 0) when it has more errors than degree // 2 or the
    locator is not consistent. Berlekamp-Massey, a Chien search and Forney's formula, with the generator's roots alpha^0 .. alpha^(degree-1)."""
    synd = rs_syndromes(block, degree)
    if not any(synd):
        return list(block), 0
    locator, previous, shift, last = [1], [1], 1, 1          # lowest power first
    for i in range(degree):
        delta = synd[i]
        for j in range(1, len(locator)):
            delta ^= gf_mul(locator[j], synd[i - j])
        if delta == 0:
            shift += 1
            continue
        scale = gf_div(delta, last)
        candidate = list(locator) + [0] * max(0, len(previous) + shift - len(locator))
        for j, p in enumerate(previous):
            candidate[j + shift] ^= gf_mul(scale, p)
        if 2 * (len(locator) - 1) <= i:
            previous, last, shift = locator, delta, 1
        else:
            shift += 1
        locator = candidate
    while len(locator) > 1 and locator[-1] == 0:
        locator.pop()
    errors = len(locator) - 1
    if errors == 0 or errors * 2 > degree:
        return None, 0
    n = len(block)
    positions = []
    for i in range(n):                      # the coefficient of x^i is block[n - 1 - i]; an error there has the locator X = alpha^i
        x_inverse = GF_EXP[(255 - i) % 255]
        value = 0
        for j in range(len(locator) - 1, -1, -1):
            value = gf_mul(value, x_inverse) ^ locator[j]
        if value == 0:
            positions.append(i)
    if len(positions) != errors:
        return None, 0
    omega = [0] * degree                    # the evaluator: S(x) * locator(x) mod x^degree, lowest power first
    for i in range(degree):
        value = 0
        for j in range(min(i, len(locator) - 1) + 1):
            value ^= gf_mul(locator[j], synd[i - j])
        omega[i] = value
    fixed = list(block)
    for i in positions:
        x = GF_EXP[i]
        x_inverse = GF_EXP[(255 - i) % 255]
        numerator = 0
        for j in range(degree - 1, -1, -1):
            numerator = gf_mul(numerator, x_inverse) ^ omega[j]
        denominator = 0
        for j in range(1, len(locator), 2):                 # the formal derivative keeps the odd powers
            denominator ^= gf_mul(locator[j], GF_EXP[(GF_LOG[x_inverse] * (j - 1)) % 255] if j > 1 else 1)
        if denominator == 0:
            return None, 0
        fixed[n - 1 - i] ^= gf_mul(x, gf_div(numerator, denominator))
    if any(rs_syndromes(fixed, degree)):
        return None, 0
    return fixed, errors


def bch_format(data5):
    value = data5 << 10
    for shift in range(4, -1, -1):
        if value & (1 << (shift + 10)):
            value ^= 0x537 << shift
    return ((data5 << 10) | value) ^ 0x5412


FORMAT_WORDS = [bch_format(i) for i in range(32)]            # all 32: level bits (2) and mask (3), with the BCH(15,5) check bits and the mask 0x5412


def bch_version(version):
    value = version << 12
    for shift in range(5, -1, -1):
        if value & (1 << (shift + 12)):
            value ^= 0x1F25 << shift
    return (version << 12) | value


def nearest_format(word):
    """(distance, data5) of the nearest of the 32 format words; BCH(15,5) corrects up to three wrong bits."""
    best = (16, 0)
    for data5, valid in enumerate(FORMAT_WORDS):
        distance = bin(word ^ valid).count("1")
        if distance < best[0]:
            best = (distance, data5)
    return best


def format_cells(n):
    """The two copies of the 15 format bits: lists of (row, col), index = bit number (bit 14 is the most significant)."""
    first = [(i, 8) for i in range(6)] + [(7, 8), (8, 8), (8, 7)] + [(8, 14 - i) for i in range(9, 15)]
    second = [(8, n - 1 - i) for i in range(8)] + [(n - 15 + i, 8) for i in range(8, 15)]
    return first, second


def version_cells(n):
    """The two copies of the 18 version bits (version 7 and above): lists of (row, col), index = bit number."""
    top_right = [(i // 3, n - 11 + i % 3) for i in range(18)]
    return top_right, [(c, r) for r, c in top_right]


_FUNCTION_CACHE = {}


def function_modules(version):
    """(known, reserved) for a version: known maps (row, col) to the module's fixed value (finder, separator, timing and alignment
    patterns, the dark module); reserved is the set of every module that is not data (the known ones, the format and the version bits)."""
    if version in _FUNCTION_CACHE:
        return _FUNCTION_CACHE[version]
    n = 17 + 4 * version
    known = {}
    for top, left in ((0, 0), (0, n - 7), (n - 7, 0)):
        for r in range(-1, 8):
            for c in range(-1, 8):
                rr, cc = top + r, left + c
                if 0 <= rr < n and 0 <= cc < n:
                    ring = max(abs(r - 3), abs(c - 3))
                    known[(rr, cc)] = 1 if ring in (0, 1, 3) else 0
    for i in range(8, n - 8):
        known[(6, i)] = known[(i, 6)] = 1 - i % 2
    centres = ALIGNMENT[version]
    for r in centres:
        for c in centres:
            if (r, c) in ((6, 6), (6, n - 7), (n - 7, 6)):
                continue
            for dr in range(-2, 3):
                for dc in range(-2, 3):
                    known[(r + dr, c + dc)] = 1 if max(abs(dr), abs(dc)) != 1 else 0
    known[(n - 8, 8)] = 1
    reserved = set(known)
    for cells in format_cells(n):
        reserved.update(cells)
    if version >= 7:
        for cells in version_cells(n):
            reserved.update(cells)
    _FUNCTION_CACHE[version] = (known, reserved)
    return known, reserved


_ORDER_CACHE = {}


def data_order(version):
    """The data modules in the order the codeword bits are placed: two columns at a time from the right, upward then downward, column 6 skipped."""
    if version in _ORDER_CACHE:
        return _ORDER_CACHE[version]
    n = 17 + 4 * version
    reserved = function_modules(version)[1]
    order, col, upward = [], n - 1, True
    while col > 0:
        if col == 6:
            col -= 1
        for step in range(n):
            row = n - 1 - step if upward else step
            for c in (col, col - 1):
                if (row, c) not in reserved:
                    order.append((row, c))
        upward = not upward
        col -= 2
    _ORDER_CACHE[version] = order
    return order


def block_layout(version, level):
    """[(data codewords, error-correction codewords)] per block, the short blocks first."""
    ec, blocks = EC_TABLE[version][level]
    data = TOTAL_CODEWORDS[version] - ec * blocks
    short, long_blocks = data // blocks, data % blocks
    return [(short, ec)] * (blocks - long_blocks) + [(short + 1, ec)] * long_blocks


def count_bits(mode, version):
    if version <= 9:
        return {"numeric": 10, "alphanumeric": 9, "byte": 8, "kanji": 8}[mode]
    return {"numeric": 12, "alphanumeric": 11, "byte": 16, "kanji": 10}[mode]


def self_check():
    """The tables agree with the geometry: for every version the data modules hold exactly the version's codewords (and 0 or 7 remainder bits)."""
    for version in range(1, MAX_VERSION + 1):
        bits = len(data_order(version))
        if bits // 8 != TOTAL_CODEWORDS[version] or bits % 8 not in (0, 7):
            return "version %d: %d data modules for %d codewords" % (version, bits, TOTAL_CODEWORDS[version])
        for level in LEVELS:
            if sum(d + e for d, e in block_layout(version, level)) != TOTAL_CODEWORDS[version]:
                return "version %d level %s: the blocks do not add up" % (version, level)
    return None


def encode_symbol(payload, version, level, mask):
    """The modules (rows of 0 and 1) of a byte-mode symbol: the control's generator. Raises ValueError when the payload does not fit."""
    n = 17 + 4 * version
    layout = block_layout(version, level)
    capacity = sum(d for d, _e in layout)
    bits = [0, 1, 0, 0]
    width = count_bits("byte", version)
    bits += [(len(payload) >> (width - 1 - i)) & 1 for i in range(width)]
    for byte in payload:
        bits += [(byte >> (7 - i)) & 1 for i in range(8)]
    if len(bits) > capacity * 8:
        raise ValueError("the payload does not fit")
    bits += [0] * min(4, capacity * 8 - len(bits))
    bits += [0] * (-len(bits) % 8)
    data = [int("".join(map(str, bits[i:i + 8])), 2) for i in range(0, len(bits), 8)]
    pad = 0
    while len(data) < capacity:
        data.append((0xEC, 0x11)[pad % 2])
        pad += 1
    blocks, at = [], 0
    for d, e in layout:
        blocks.append((data[at:at + d], rs_encode(data[at:at + d], e)))
        at += d
    stream = []
    for i in range(max(d for d, _e in layout)):
        stream += [b[0][i] for b in blocks if i < len(b[0])]
    for i in range(layout[0][1]):
        stream += [b[1][i] for b in blocks]
    known, _reserved = function_modules(version)
    grid = [[0] * n for _ in range(n)]
    for (r, c), value in known.items():
        grid[r][c] = value
    order = data_order(version)
    test = MASKS[mask]
    for index, (r, c) in enumerate(order):
        bit = (stream[index >> 3] >> (7 - (index & 7))) & 1 if index >> 3 < len(stream) else 0
        grid[r][c] = bit ^ (1 if test(r, c) else 0)
    word = FORMAT_WORDS[(LEVEL_BITS[level] << 3) | mask]
    for cells in format_cells(n):
        for bit, (r, c) in enumerate(cells):
            grid[r][c] = (word >> bit) & 1
    if version >= 7:
        word = bch_version(version)
        for cells in version_cells(n):
            for bit, (r, c) in enumerate(cells):
                grid[r][c] = (word >> bit) & 1
    return grid


class BitReader:
    def __init__(self, data):
        self.data, self.at, self.end = data, 0, len(data) * 8

    def left(self):
        return self.end - self.at

    def take(self, count):
        if count > self.left():
            raise ValueError("the bit stream ends inside a field")
        value = 0
        for _ in range(count):
            value = (value << 1) | ((self.data[self.at >> 3] >> (7 - (self.at & 7))) & 1)
            self.at += 1
        return value


def read_segments(data, version):
    """(payload bytes, segments, notes) from the data codewords: numeric, alphanumeric and byte segments; an ECI designator and the FNC1
    and structured-append headers are read and noted; a kanji segment's two-byte values are kept as they decode (Shift JIS). ValueError
    for a stream that is not one (an unknown mode, a count past the end)."""
    reader, payload, segments, notes = BitReader(data), bytearray(), [], []
    while reader.left() >= 4:
        mode = reader.take(4)
        if mode == 0:
            break
        if mode == 7:
            first = reader.take(8)
            if first & 0x80 == 0:
                designator = first
            elif first & 0xC0 == 0x80:
                designator = ((first & 0x3F) << 8) | reader.take(8)
            elif first & 0xE0 == 0xC0:
                designator = ((first & 0x1F) << 16) | reader.take(16)
            else:
                raise ValueError("an ECI designator of an unknown form")
            notes.append("ECI designator %d: the bytes after it are in that character set, kept as they are" % designator)
            continue
        if mode in (5, 9):
            if mode == 9:
                reader.take(8)
            notes.append("FNC1 in %s position: a GS1 or an application-identifier symbol" % ("first" if mode == 5 else "second"))
            continue
        if mode == 3:
            position, parity = reader.take(8), reader.take(8)
            notes.append("structured append: symbol %d of %d (parity %d): the message goes on in other symbols" % ((position >> 4) + 1, (position & 15) + 1, parity))
            continue
        if mode == 1:
            count = reader.take(count_bits("numeric", version))
            text = ""
            remaining = count
            while remaining >= 3:
                value = reader.take(10)
                if value > 999:
                    raise ValueError("a numeric group over 999")
                text += "%03d" % value
                remaining -= 3
            if remaining == 2:
                value = reader.take(7)
                if value > 99:
                    raise ValueError("a numeric group over 99")
                text += "%02d" % value
            elif remaining == 1:
                value = reader.take(4)
                if value > 9:
                    raise ValueError("a numeric digit over 9")
                text += "%d" % value
            payload += text.encode("ascii")
            segments.append({"mode": "numeric", "characters": count})
        elif mode == 2:
            count = reader.take(count_bits("alphanumeric", version))
            text = ""
            remaining = count
            while remaining >= 2:
                value = reader.take(11)
                if value >= 45 * 45:
                    raise ValueError("an alphanumeric pair out of range")
                text += ALPHANUMERIC[value // 45] + ALPHANUMERIC[value % 45]
                remaining -= 2
            if remaining:
                value = reader.take(6)
                if value >= 45:
                    raise ValueError("an alphanumeric character out of range")
                text += ALPHANUMERIC[value]
            payload += text.encode("ascii")
            segments.append({"mode": "alphanumeric", "characters": count})
        elif mode == 4:
            count = reader.take(count_bits("byte", version))
            if count * 8 > reader.left():
                raise ValueError("a byte count past the end of the data")
            payload += bytes(reader.take(8) for _ in range(count))
            segments.append({"mode": "byte", "characters": count})
        elif mode == 8:
            count = reader.take(count_bits("kanji", version))
            for _ in range(count):
                value = reader.take(13)
                value = ((value // 0xC0) << 8) | (value % 0xC0)
                value += 0x8140 if value < 0x1F00 else 0xC140
                payload += bytes((value >> 8, value & 0xFF))
            segments.append({"mode": "kanji", "characters": count})
            notes.append("a kanji segment: its characters are written as Shift JIS byte pairs")
        else:
            raise ValueError("an unknown mode indicator")
    if not segments:
        raise ValueError("no data segment")
    return bytes(payload), segments, notes


def decode_modules(grid, version, level, mask):
    """The payload of a module matrix read with one format: {payload, segments, notes, errors_corrected, blocks, blocks_clean}, or
    (None, why) as a pair. Every block must pass Reed-Solomon and the bit stream must parse."""
    order = data_order(version)
    test = MASKS[mask]
    total = TOTAL_CODEWORDS[version]
    stream = [0] * total
    for index in range(total * 8):
        r, c = order[index]
        if grid[r][c] ^ (1 if test(r, c) else 0):
            stream[index >> 3] |= 0x80 >> (index & 7)
    layout = block_layout(version, level)
    blocks = [[] for _ in layout]
    at = 0
    for i in range(max(d for d, _e in layout)):
        for b, (d, _e) in enumerate(layout):
            if i < d:
                blocks[b].append(stream[at])
                at += 1
    for i in range(layout[0][1]):
        for b in range(len(layout)):
            blocks[b].append(stream[at])
            at += 1
    data, corrected, clean = [], 0, 0
    for b, (d, e) in enumerate(layout):
        fixed, errors = rs_correct(blocks[b], e)
        if fixed is None:
            return None, "Reed-Solomon block %d of %d has more errors than its %d check codewords correct" % (b + 1, len(layout), e)
        corrected += errors
        clean += 1 if errors == 0 else 0
        data += fixed[:d]
    try:
        payload, segments, notes = read_segments(data, version)
    except ValueError as exc:
        return None, "the corrected codewords are not a data stream (%s)" % exc
    return {"payload": payload, "segments": segments, "notes": notes, "errors_corrected": corrected, "blocks": len(layout), "blocks_clean": clean}, None


def clean_blocks(grid, version, level, mask):
    """How many Reed-Solomon blocks of the matrix have all-zero syndromes under this format (no correction tried): the cheap score of a placement."""
    order = data_order(version)
    test = MASKS[mask]
    total = TOTAL_CODEWORDS[version]
    stream = [0] * total
    for index in range(total * 8):
        r, c = order[index]
        if grid[r][c] ^ (1 if test(r, c) else 0):
            stream[index >> 3] |= 0x80 >> (index & 7)
    layout = block_layout(version, level)
    blocks = [[] for _ in layout]
    at = 0
    for i in range(max(d for d, _e in layout)):
        for b, (d, _e) in enumerate(layout):
            if i < d:
                blocks[b].append(stream[at])
                at += 1
    for i in range(layout[0][1]):
        for b in range(len(layout)):
            blocks[b].append(stream[at])
            at += 1
    return sum(1 for b, (_d, e) in enumerate(layout) if not any(rs_syndromes(blocks[b], e))), len(layout)


def read_format(grid, n):
    """Both copies of the format word, each against all 32 valid words: [(distance, level, mask, "copy 1" | "copy 2")], the nearer first."""
    found = []
    for name, cells in zip(("copy 1 (beside the top-left finder)", "copy 2 (split between the other two finders)"), format_cells(n)):
        word = 0
        for bit, (r, c) in enumerate(cells):
            word |= grid[r][c] << bit
        distance, data5 = nearest_format(word)
        found.append((distance, LEVEL_OF_BITS[data5 >> 3], data5 & 7, name))
    found.sort(key=lambda f: f[0])
    return found


def orientations(grid, which):
    """The matrix turned: which is a list of names out of r0, r90, r180, r270 and their mirrored forms m0, m90, m180, m270."""
    n = len(grid)
    out = []
    for name in which:
        g = grid
        if name.startswith("m"):
            g = [list(row) for row in zip(*g)]
        for _ in range(int(name[1:]) // 90):
            g = [list(row) for row in zip(*g[::-1])]
        out.append((name, g if g is not grid else [list(row) for row in grid]))
    return out


def function_agreement(grid, version):
    known = function_modules(version)[0]
    agree = sum(1 for (r, c), value in known.items() if grid[r][c] == value)
    return agree, len(known)


def decode_matrix(grid, tries, all_formats=False, stats=None):
    """Read a sampled n x n matrix: for each orientation in `tries` the format word (both copies, BCH distance up to 3), then the
    codewords. With all_formats, an orientation whose format copies are both unreadable is tried with each of the 32 format words, and
    Reed-Solomon decides. Returns the result (with version, level, mask, orientation, format) or None; stats counts what was tried."""
    n = len(grid)
    version = (n - 17) // 4
    stats = stats if stats is not None else {}
    for name, turned in orientations(grid, tries):
        formats = read_format(turned, n)
        stats["format_words_read"] = stats.get("format_words_read", 0) + 2
        candidates = [(d, level, mask, where) for d, level, mask, where in formats if d <= 3]
        seen = set()
        for distance, level, mask, where in candidates:
            if (level, mask) in seen:
                continue
            seen.add((level, mask))
            stats["reed_solomon_attempts"] = stats.get("reed_solomon_attempts", 0) + 1
            result, _why = decode_modules(turned, version, level, mask)
            if result is not None:
                agree, known = function_agreement(turned, version)
                result.update({"version": version, "level": level, "mask": mask, "orientation": name, "modules": turned,
                               "format": {"read_from": where, "bits_corrected": distance, "by": "nearest of the 32 format words (BCH 15,5)"},
                               "function_modules_agreeing": agree, "function_modules": known})
                return result
        if all_formats:
            for data5 in range(32):
                level, mask = LEVEL_OF_BITS[data5 >> 3], data5 & 7
                if (level, mask) in seen:
                    continue
                if clean_blocks(turned, version, level, mask)[0] == 0 and EC_TABLE[version][level][1] > 1:
                    continue
                stats["reed_solomon_attempts"] = stats.get("reed_solomon_attempts", 0) + 1
                result, _why = decode_modules(turned, version, level, mask)
                if result is not None and (result["errors_corrected"] * 4 <= sum(e for _d, e in block_layout(version, level))):
                    agree, known = function_agreement(turned, version)
                    result.update({"version": version, "level": level, "mask": mask, "orientation": name, "modules": turned,
                                   "format": {"read_from": "neither copy (both were more than 3 bits from every format word)", "bits_corrected": None,
                                              "by": "each of the 32 format words tried, Reed-Solomon deciding"},
                                   "function_modules_agreeing": agree, "function_modules": known})
                    return result
    return None


# ---- finding the symbol in a picture ------------------------------------------------------------------------------------------------
RUNS = re.compile(rb"\x01+|\x00+")
ALL_TURNS = ["r0", "r90", "r180", "r270", "m0", "m90", "m180", "m270"]


class Clock(Exception):
    """The tool's own clock ran out inside a search."""


def tick():
    if out_of_time():
        raise Clock()


def _ratio(lengths):
    """Whether five runs (dark, light, dark, light, dark) are a finder's 1:1:3:1:1, and the module size they give."""
    total = sum(lengths)
    if total < 7:
        return None
    unit = total / 7.0
    slack = unit * 0.7 + 0.5
    if abs(lengths[0] - unit) > slack or abs(lengths[1] - unit) > slack or abs(lengths[3] - unit) > slack or abs(lengths[4] - unit) > slack:
        return None
    if abs(lengths[2] - 3 * unit) > 1.5 * slack:
        return None
    return unit


def _cross_check(line, centre):
    """Along one line of 0 and 1 (a row, or a column as bytes), the finder pattern through `centre`: (middle, total length) or None."""
    n = len(line)
    centre = int(centre)
    if not 0 <= centre < n or line[centre] != 1:
        return None
    lengths = [0] * 5
    i = centre
    while i >= 0 and line[i] == 1:
        i -= 1
    lengths[2] = centre - i
    start_core = i + 1
    for k, want in ((1, 0), (0, 1)):
        j = i
        while j >= 0 and line[j] == want:
            j -= 1
        lengths[k] = i - j
        i = j
    left = i + 1
    i = centre + 1
    while i < n and line[i] == 1:
        i += 1
    lengths[2] += i - centre - 1
    end_core = i
    for k, want in ((3, 0), (4, 1)):
        j = i
        while j < n and line[j] == want:
            j += 1
        lengths[k] = j - i
        i = j
    if min(lengths) == 0 or _ratio(lengths) is None:
        return None
    return (start_core + end_core) / 2.0, i - left


def find_finders(binary, width, height):
    """Finder-pattern candidates: [(x, y, module size, rows that saw it)], the most seen first. A row is scanned for five runs in the
    ratio 1:1:3:1:1, the column through its middle must show the same, and the row through that column's middle again."""
    flat = b"".join(binary)
    found = []
    step = max(1, height // 1500)
    for y in range(0, height, step):
        if y % 64 == 0:
            tick()
        row = binary[y]
        if 1 not in row:
            continue
        runs = [(m.start(), m.end() - m.start()) for m in RUNS.finditer(row)]
        first_dark = 0 if row[0] == 1 else 1
        for i in range(first_dark, len(runs) - 4, 2):
            lengths = [runs[i + k][1] for k in range(5)]
            if _ratio(lengths) is None:
                continue
            cx = runs[i + 2][0] + runs[i + 2][1] / 2.0
            vertical = _cross_check(flat[int(cx)::width], y)
            if vertical is None:
                continue
            cy, vertical_total = vertical
            horizontal = _cross_check(binary[int(cy)], cx)
            if horizontal is None:
                continue
            cx, horizontal_total = horizontal
            if not 0.6 <= horizontal_total / float(vertical_total) <= 1.67:
                continue
            unit = (horizontal_total + vertical_total) / 14.0
            for item in found:
                if abs(item[0] - cx) <= item[2] * 2.5 and abs(item[1] - cy) <= item[2] * 2.5:
                    seen = item[3]
                    item[0], item[1], item[2], item[3] = (item[0] * seen + cx) / (seen + 1), (item[1] * seen + cy) / (seen + 1), (item[2] * seen + unit) / (seen + 1), seen + 1
                    break
            else:
                found.append([cx, cy, unit, 1])
    found.sort(key=lambda item: -item[3])
    strongest = found[0][3] if found else 0
    return [tuple(item) for item in found if item[3] * 6 >= strongest or item[3] >= 3][:12]


def _solve(matrix, vector):
    """Gaussian elimination with pivoting; None for a singular system."""
    n = len(vector)
    a = [list(row) + [vector[i]] for i, row in enumerate(matrix)]
    for col in range(n):
        pivot = max(range(col, n), key=lambda r: abs(a[r][col]))
        if abs(a[pivot][col]) < 1e-12:
            return None
        a[col], a[pivot] = a[pivot], a[col]
        for r in range(n):
            if r != col:
                factor = a[r][col] / a[col][col]
                if factor:
                    for k in range(col, n + 1):
                        a[r][k] -= factor * a[col][k]
    return [a[i][n] / a[i][i] for i in range(n)]


def affine_from(top_left, top_right, bottom_left, n):
    """Module coordinates (u across, v down, in modules from the symbol's corner) to pixels, from the three finder centres at (3.5, 3.5),
    (n - 3.5, 3.5) and (3.5, n - 3.5)."""
    span = float(n - 7)
    ux, uy = (top_right[0] - top_left[0]) / span, (top_right[1] - top_left[1]) / span
    vx, vy = (bottom_left[0] - top_left[0]) / span, (bottom_left[1] - top_left[1]) / span
    ox, oy = top_left[0] - 3.5 * ux - 3.5 * vx, top_left[1] - 3.5 * uy - 3.5 * vy
    return lambda u, v: (ox + u * ux + v * vx, oy + u * uy + v * vy)


def projective_from(module_points, pixel_points):
    """The same mapping through four points (the three finders and an alignment pattern): a perspective transform, or None."""
    rows, rhs = [], []
    for (u, v), (x, y) in zip(module_points, pixel_points):
        rows.append([u, v, 1, 0, 0, 0, -u * x, -v * x])
        rhs.append(x)
        rows.append([0, 0, 0, u, v, 1, -u * y, -v * y])
        rhs.append(y)
    h = _solve(rows, rhs)
    if h is None:
        return None

    def point(u, v):
        w = h[6] * u + h[7] * v + 1.0
        if abs(w) < 1e-9:
            return (-1.0, -1.0)
        return ((h[0] * u + h[1] * v + h[2]) / w, (h[3] * u + h[4] * v + h[5]) / w)
    return point


def sample(binary, width, height, mapping, n, unit):
    """The n x n modules under a mapping: each is the majority of five points around its centre (outside the picture counts as light)."""
    d = max(0.0, unit * 0.22)
    offsets = ((0.0, 0.0), (-d, -d), (d, -d), (-d, d), (d, d)) if d >= 0.75 else ((0.0, 0.0),)
    need = len(offsets) // 2 + 1
    grid = []
    for r in range(n):
        row = []
        for c in range(n):
            x, y = mapping(c + 0.5, r + 0.5)
            dark = 0
            for dx, dy in offsets:
                px, py = int(x + dx), int(y + dy)
                if 0 <= px < width and 0 <= py < height and binary[py][px]:
                    dark += 1
            row.append(1 if dark >= need else 0)
        grid.append(row)
    return grid


def find_alignment(binary, width, height, mapping, n, unit):
    """The pixel centre of the bottom-right alignment pattern near where the mapping puts it, or None: the place within two modules
    whose 5 x 5 neighbourhood agrees best with the pattern (at least 23 of 25)."""
    centre = n - 6.5
    best = (22, None)
    steps = [i * 0.25 for i in range(-8, 9)]
    ax, ay = mapping(centre, centre)
    for dy in steps:
        for dx in steps:
            x0, y0 = ax + dx * unit, ay + dy * unit
            agree = 0
            for r in range(-2, 3):
                for c in range(-2, 3):
                    px, py = int(x0 + c * unit), int(y0 + r * unit)
                    want = 1 if max(abs(r), abs(c)) != 1 else 0
                    if 0 <= px < width and 0 <= py < height and binary[py][px] == want:
                        agree += 1
            if agree > best[0]:
                best = (agree, (x0, y0))
    return best[1]


def _sizes(distance_modules):
    """Versions to try for a measured side, the nearest first: the estimate and its neighbours, within 1 to MAX_VERSION."""
    estimate = (distance_modules + 7 - 17) / 4.0
    order = sorted(range(1, MAX_VERSION + 1), key=lambda v: abs(v - estimate))
    return [v for v in order if abs(v - estimate) <= 1.6][:3]


def _distance(a, b):
    return math.hypot(a[0] - b[0], a[1] - b[1])


def triples(finders):
    """Three finders as (top-left, top-right, bottom-left), the best right-angled triples first: the corner is opposite the longest side."""
    out = []
    pool = finders[:8]
    for i in range(len(pool)):
        for j in range(i + 1, len(pool)):
            for k in range(j + 1, len(pool)):
                a, b, c = pool[i], pool[j], pool[k]
                units = [a[2], b[2], c[2]]
                if max(units) > 1.6 * min(units):
                    continue
                sides = sorted(((_distance(b, c), a, b, c), (_distance(a, c), b, a, c), (_distance(a, b), c, a, b)), key=lambda s: -s[0])
                hypotenuse, corner, p, q = sides[0]
                leg1, leg2 = _distance(corner, p), _distance(corner, q)
                if min(leg1, leg2) < 10 * min(units):
                    continue
                error = abs(leg1 - leg2) / max(leg1, leg2) + abs(hypotenuse - math.sqrt(leg1 * leg1 + leg2 * leg2)) / hypotenuse
                if error > 0.35:
                    continue
                cross = (p[0] - corner[0]) * (q[1] - corner[1]) - (p[1] - corner[1]) * (q[0] - corner[0])
                top_right, bottom_left = (p, q) if cross > 0 else (q, p)
                out.append((error - 0.01 * (a[3] + b[3] + c[3]), corner, top_right, bottom_left))
    out.sort(key=lambda t: t[0])
    return [(t[1], t[2], t[3]) for t in out[:6]]


def read_by_finders(binary, width, height, finders, stats):
    """The standard reading: three finders give the grid (and, from version 2, the alignment pattern a perspective correction)."""
    for top_left, top_right, bottom_left in triples(finders):
        unit = (top_left[2] + top_right[2] + bottom_left[2]) / 3.0
        side = (_distance(top_left, top_right) + _distance(top_left, bottom_left)) / 2.0 / unit
        for version in _sizes(side):
            tick()
            n = 17 + 4 * version
            mapping = affine_from(top_left, top_right, bottom_left, n)
            module = _distance(top_left, top_right) / (n - 7)
            mappings = []
            if version >= 2:
                centre = find_alignment(binary, width, height, mapping, n, module)
                if centre is not None:
                    projective = projective_from([(3.5, 3.5), (n - 3.5, 3.5), (3.5, n - 3.5), (n - 6.5, n - 6.5)], [top_left[:2], top_right[:2], bottom_left[:2], centre])
                    if projective is not None:
                        mappings.append(("three finder patterns and the alignment pattern (a perspective mapping)", projective))
            mappings.append(("three finder patterns (an affine mapping)", mapping))
            for how, m in mappings:
                stats["grids_sampled"] = stats.get("grids_sampled", 0) + 1
                result = decode_matrix(sample(binary, width, height, m, n, module), ["r0", "m0"], stats=stats)
                if result is not None:
                    result["located_by"] = how
                    result["module_pixels"] = round(module, 2)
                    return result
    return None


def dark_box(binary, width, height):
    """(left, top, right, bottom) of the dark pixels, right and bottom exclusive, or None for a picture with none."""
    top = bottom = None
    left, right = width, 0
    for y, row in enumerate(binary):
        first = row.find(b"\x01")
        if first < 0:
            continue
        if top is None:
            top = y
        bottom = y + 1
        left = min(left, first)
        right = max(right, row.rfind(b"\x01") + 1)
    return None if top is None else (left, top, right, bottom)


def module_size(binary, width, box):
    """The module size of an axis-aligned symbol (or a piece of one) from its runs: the largest size of which nine runs in ten, along
    rows and columns inside the box, are whole multiples. None when no size fits (a picture that is not made of square modules)."""
    left, top, right, bottom = box
    runs = []
    rows = range(top, bottom, max(1, (bottom - top) // 60))
    for y in rows:
        runs += [m.end() - m.start() for m in RUNS.finditer(binary[y][left:right])]
    flat = b"".join(binary)
    for x in range(left, right, max(1, (right - left) // 60)):
        runs += [m.end() - m.start() for m in RUNS.finditer(flat[x::width][top:bottom])]
    if len(runs) < 8:
        return None
    tick()
    counts = collections.Counter(runs)
    largest = min(max(counts), min(right - left, bottom - top))
    size = float(largest)
    total = len(runs)
    while size >= 1.0:
        slack = max(1.0, size * 0.2)
        fit = sum(count for length, count in counts.items() if round(length / size) >= 1 and abs(length - size * round(length / size)) <= slack)
        if fit >= 0.9 * total:
            multiples = sum(round(length / size) * count for length, count in counts.items() if round(length / size) >= 1)
            return sum(length * count for length, count in counts.items() if round(length / size) >= 1) / float(multiples)
        size -= 0.5
    return None


def read_by_two_finders(binary, width, height, finders, stats):
    """Two finders left: they are two corners of a square of square modules, next to each other or across the diagonal, and the third
    corner is on one side or the other. Each such grid is sampled, turned every way, and the format word and Reed-Solomon decide."""
    pool = finders[:4]
    for i in range(len(pool)):
        for j in range(i + 1, len(pool)):
            a, b = pool[i], pool[j]
            unit = (a[2] + b[2]) / 2.0
            dx, dy = b[0] - a[0], b[1] - a[1]
            apart = math.hypot(dx, dy)
            if apart < 10 * unit:
                continue
            hypotheses = []
            for side in (1, -1):                              # next to each other: the third corner is a quarter turn from a
                third = (a[0] - side * dy, a[1] + side * dx)
                hypotheses.append((apart / unit, a, b, third, "two finder patterns taken as neighbouring corners"))
                mid = ((a[0] + b[0]) / 2.0, (a[1] + b[1]) / 2.0)   # across the diagonal: the corner is the midpoint moved half the diagonal sideways
                corner = (mid[0] - side * dy / 2.0, mid[1] + side * dx / 2.0)
                hypotheses.append((apart / math.sqrt(2) / unit, corner, a, b, "two finder patterns taken as opposite corners"))
            for side_modules, top_left, top_right, bottom_left, how in hypotheses:
                for version in _sizes(side_modules):
                    tick()
                    n = 17 + 4 * version
                    mapping = affine_from(top_left, top_right, bottom_left, n)
                    module = _distance(top_left, top_right) / (n - 7)
                    stats["grids_sampled"] = stats.get("grids_sampled", 0) + 1
                    result = decode_matrix(sample(binary, width, height, mapping, n, module), ALL_TURNS, stats=stats)
                    if result is not None:
                        result["located_by"] = how
                        result["module_pixels"] = round(module, 2)
                        return result
    return None


def read_by_box(binary, width, height, finders, stats, box=None, version=None, last_resort=False):
    """No finder to go by: an upright symbol fills the box of the picture's dark pixels (or the box given), so the grid is the box cut
    into n x n; n comes from the module size the runs give, and its neighbours are tried. The format word and Reed-Solomon decide; as a
    last resort a grid whose format copies are both unreadable is tried with each of the 32 format words."""
    given = box is not None
    box = box or dark_box(binary, width, height)
    if box is None:
        return None
    left, top, right, bottom = box
    if right - left < 21 or bottom - top < 21:
        return None
    unit = module_size(binary, width, box) or (sum(f[2] for f in finders) / len(finders) if finders else None)
    versions = [version] if version else sorted(range(1, MAX_VERSION + 1), key=lambda v: abs((right - left) / float(17 + 4 * v) - unit) if unit else v)
    for candidate in versions[:4] if unit and not version else versions:
        n = 17 + 4 * candidate
        mx, my = (right - left) / float(n), (bottom - top) / float(n)
        if mx < 1 or my < 1 or not 0.8 <= mx / my <= 1.25:
            continue
        tick()
        mapping = (lambda mx, my: lambda u, v: (left + u * mx, top + v * my))(mx, my)
        stats["grids_sampled"] = stats.get("grids_sampled", 0) + 1
        result = decode_matrix(sample(binary, width, height, mapping, n, min(mx, my)), ALL_TURNS, all_formats=last_resort, stats=stats)
        if result is not None:
            result["located_by"] = ("the box given cut into %d x %d modules" if given else "the box of the dark pixels cut into %d x %d modules") % (n, n)
            result["module_pixels"] = round((mx + my) / 2.0, 2)
            return result
    return None


def repainted(result):
    """The modules as read, with every fixed module (finder, separator, timing and alignment patterns, the dark module) set to its
    standard value and the format word written again in both places: (grid, how many fixed modules were changed)."""
    version, grid = result["version"], [list(row) for row in result["modules"]]
    n = len(grid)
    changed = 0
    for (r, c), value in function_modules(version)[0].items():
        if grid[r][c] != value:
            grid[r][c] = value
            changed += 1
    word = FORMAT_WORDS[(LEVEL_BITS[result["level"]] << 3) | result["mask"]]
    for cells in format_cells(n):
        for bit, (r, c) in enumerate(cells):
            if grid[r][c] != (word >> bit) & 1:
                grid[r][c] = (word >> bit) & 1
                changed += 1
    return grid, changed


def render(grid, scale=8, quiet=4):
    """A module matrix as rows of grey bytes."""
    n = len(grid)
    side = (n + 2 * quiet) * scale
    white = b"\xff" * side
    rows = [white] * (quiet * scale)
    for line in grid:
        row = b"\xff" * (quiet * scale) + b"".join((b"\x00" if m else b"\xff") * scale for m in line) + b"\xff" * (quiet * scale)
        rows += [row] * scale
    rows += [white] * (quiet * scale)
    return side, rows


def read_symbol(binary, width, height, mode, stats, box=None, version=None):
    """One picture: the standard reading, then (mode auto or repaint) the readings that do not need all three finders."""
    finders = find_finders(binary, width, height)
    stats["finder_patterns_found"] = len(finders)
    result = None
    if mode in ("auto", "finders") and len(finders) >= 3 and box is None:
        result = read_by_finders(binary, width, height, finders, stats)
    if result is None and mode in ("auto", "repaint"):
        if len(finders) >= 2 and box is None:
            result = read_by_two_finders(binary, width, height, finders, stats)
        if result is None:
            result = read_by_box(binary, width, height, finders, stats, box=box, version=version)
        if result is None:
            result = read_by_box(binary, width, height, finders, stats, box=box, version=version, last_resort=True)
        if result is not None:
            result["function_patterns"] = "not read: taken as the standard's (repainted)"
    return result


# ---- pieces of one symbol -----------------------------------------------------------------------------------------------------------
MAX_PIECES = 16
MAX_LEAVES = 4000                  # whole placements whose format word and syndromes are computed


def piece_modules(binary, width, height, unit_given=None):
    """A piece as a matrix of modules: the box of its dark pixels cut at the module size its runs give. (grid, module size) or (None, why)."""
    box = dark_box(binary, width, height)
    if box is None:
        return None, "it has no dark pixel"
    unit = unit_given or module_size(binary, width, box)
    if unit is None:
        return None, "no module size fits its runs (it is not made of square modules, or it is turned)"
    left, top, right, bottom = box
    columns, rows = int(round((right - left) / unit)), int(round((bottom - top) / unit))
    if columns < 1 or rows < 1 or columns > 17 + 4 * MAX_VERSION or rows > 17 + 4 * MAX_VERSION:
        return None, "its dark pixels span %d x %d modules of %.1f pixels, which is no piece of a version 1 to %d symbol" % (columns, rows, unit, MAX_VERSION)
    mx, my = (right - left) / float(columns), (bottom - top) / float(rows)
    d = unit * 0.22
    offsets = ((0.0, 0.0), (-d, -d), (d, -d), (-d, d), (d, d)) if d >= 0.75 else ((0.0, 0.0),)
    grid = []
    for r in range(rows):
        line = []
        for c in range(columns):
            x, y = left + (c + 0.5) * mx, top + (r + 0.5) * my
            dark = sum(1 for dx, dy in offsets if 0 <= int(x + dx) < width and 0 <= int(y + dy) < height and binary[int(y + dy)][int(x + dx)])
            line.append(1 if dark * 2 > len(offsets) else 0)
        grid.append(line)
    return grid, unit


def _turn(grid, quarter_turns):
    for _ in range(quarter_turns):
        grid = [list(row) for row in zip(*grid[::-1])]
    return grid


def _placements(piece, version):
    """Where a piece can lie in a version's grid, the likeliest first: [(score, row, col, agree, disagree)]. The score is the count of
    fixed modules (finder, separator, timing, alignment, dark module) the piece agrees with there, less four for each it contradicts;
    a place where it contradicts more than one in twelve of them is dropped."""
    n = 17 + 4 * version
    known = function_modules(version)[0]
    rows, columns = len(piece), len(piece[0])
    out = []
    for r0 in range(n - rows + 1):
        for c0 in range(n - columns + 1):
            agree = disagree = 0
            for r in range(rows):
                line = piece[r]
                for c in range(columns):
                    value = known.get((r0 + r, c0 + c))
                    if value is not None:
                        if value == line[c]:
                            agree += 1
                        else:
                            disagree += 1
            if disagree * 12 > agree + disagree:
                continue
            out.append((agree - 4 * disagree, r0, c0, agree, disagree))
    out.sort(key=lambda p: -p[0])
    return out


def assemble(pieces, stats, version_given=None):
    """Place the pieces of one symbol. For each turn of the set and each version they could fill, every piece's candidate places are
    ranked on the fixed modules; whole placements are then walked (the most constrained piece first, a piece never contradicting one
    already placed), and each is scored on the format word (BCH distance) and on how many Reed-Solomon blocks have zero syndromes; the
    first that decodes is the answer. Returns (result, tried) with tried the best placements that did not decode."""
    area = sum(len(p) * len(p[0]) for p in pieces)
    tried = []
    leaves = [0]
    for turn in range(4):
        turned = [_turn(p, turn) for p in pieces]
        tallest, widest = max(len(p) for p in turned), max(len(p[0]) for p in turned)
        versions = [version_given] if version_given else sorted(
            (v for v in range(1, MAX_VERSION + 1) if 17 + 4 * v >= max(tallest, widest) and area >= 0.6 * (17 + 4 * v) ** 2 and area <= 1.6 * (17 + 4 * v) ** 2),
            key=lambda v: abs((17 + 4 * v) ** 2 - area))
        for version in versions:
            tick()
            n = 17 + 4 * version
            if tallest > n or widest > n:
                continue
            options = []
            for index, piece in enumerate(turned):
                tick()
                options.append((index, _placements(piece, version)))
            if any(not places for _index, places in options):
                continue
            # the most constrained piece first: the one whose best place stands furthest above its second
            options.sort(key=lambda o: -(o[1][0][0] - (o[1][1][0] if len(o[1]) > 1 else -99)))
            grid = [[-1] * n for _ in range(n)]
            chosen = {}

            def walk(depth):
                if leaves[0] >= MAX_LEAVES:
                    return None
                if depth == len(options):
                    leaves[0] += 1
                    stats["placements_scored"] = leaves[0]
                    tick()
                    full = [[1 if v == 1 else 0 for v in row] for row in grid]
                    missing = sum(1 for row in grid for v in row if v < 0)
                    formats = read_format(full, n)
                    if formats[0][0] > 3:
                        return None
                    _distance_bits, level, mask, _where = formats[0]
                    clean, blocks = clean_blocks(full, version, level, mask)
                    result = decode_matrix(full, ["r0"], stats=stats)
                    if result is None:
                        tried.append({"version": version, "format_bits_wrong": formats[0][0], "blocks_with_zero_syndromes": clean, "blocks": blocks, "modules_not_covered": missing})
                        return None
                    result.update({"placements": [{"piece": i, "row": chosen[i][0], "column": chosen[i][1], "fixed_modules_agreeing": chosen[i][2],
                                                   "fixed_modules_contradicted": chosen[i][3]} for i in sorted(chosen)],
                                   "pieces_turned_quarter_turns": turn, "modules_not_covered": missing, "blocks_with_zero_syndromes": clean})
                    return result
                index, places = options[depth]
                piece = turned[index]
                rows, columns = len(piece), len(piece[0])
                ranked = []
                for score, r0, c0, agree, disagree in places[:400]:
                    fresh = clash = 0
                    for r in range(rows):
                        target, line = grid[r0 + r], piece[r]
                        for c in range(columns):
                            held = target[c0 + c]
                            if held < 0:
                                fresh += 1
                            elif held != line[c]:
                                clash += 1
                    if clash * 20 > rows * columns - fresh:
                        continue
                    ranked.append((score * 1000 + fresh - 50 * clash, r0, c0, agree, disagree))
                ranked.sort(key=lambda p: -p[0])
                for _rank, r0, c0, agree, disagree in ranked[:60]:
                    written = []
                    for r in range(rows):
                        target, line = grid[r0 + r], piece[r]
                        for c in range(columns):
                            if target[c0 + c] < 0:
                                target[c0 + c] = line[c]
                                written.append((r0 + r, c0 + c))
                    chosen[index] = (r0, c0, agree, disagree)
                    result = walk(depth + 1)
                    if result is not None:
                        return result
                    del chosen[index]
                    for r, c in written:
                        grid[r][c] = -1
                return None

            result = walk(0)
            if result is not None:
                result["located_by"] = "placement of %d pieces by fixed modules, format word and Reed-Solomon syndromes" % len(pieces)
                return result, tried
    tried.sort(key=lambda t: (t["format_bits_wrong"], -t["blocks_with_zero_syndromes"], t["modules_not_covered"]))
    return None, tried[:5]


def payload_shape(payload):
    """What kind of text the payload is, by its first characters alone (a kind, never the content)."""
    try:
        text = payload.decode("utf-8")
    except UnicodeDecodeError:
        return "bytes that are not UTF-8 text", False
    lowered = text[:16].lower()
    if lowered.startswith("otpauth://") or lowered.startswith("otpauth-migration://"):
        return "an otpauth URI (a one-time-password secret)", True
    if lowered.startswith("wifi:"):
        return "a Wi-Fi configuration (it can carry the passphrase)", True
    if re.match(r"[a-z][a-z0-9+.-]{1,15}:", lowered):
        return "a URI", False
    return "text", False


def control(mode):
    """The planted control: a symbol made here (version 3, level Q: two Reed-Solomon blocks) with three modules flipped, drawn at three
    pixels a module and read back by the code that reads the evidence: whole, with a finder erased when the repaint reading is in play,
    and cut into four pieces for the fragments mode. {passed, checks}."""
    problem = self_check()
    checks = [{"check": "the tables agree with the geometry for versions 1 to %d" % MAX_VERSION, "passed": problem is None, **({"problem": problem} if problem else {})}]
    planted = ("control-" + os.urandom(6).hex()).encode("ascii")
    grid = encode_symbol(planted, 3, "Q", os.urandom(1)[0] % 8)
    reserved = function_modules(3)[1]
    flipped = 0
    for r, c in ((9, 12), (15, 20), (22, 11)):
        if (r, c) not in reserved:
            grid[r][c] ^= 1
            flipped += 1
    side, rows = render(grid, 3, 4)

    def read_back(rows, mode):
        binary, _threshold = binarise(rows)
        return read_symbol(binary, side, side, mode, {})

    if mode in ("auto", "finders", "all"):
        result = read_back(rows, "finders")
        checks.append({"check": "a planted symbol with %d modules flipped is read by its three finders" % flipped,
                       "passed": result is not None and result["payload"] == planted and result["errors_corrected"] >= 1})
    if mode in ("auto", "repaint", "all"):
        erased = [bytearray(row) for row in rows]
        for y in range(10, 35):
            erased[y][10:35] = b"\xff" * 25
        result = read_back([bytes(row) for row in erased], "repaint")
        checks.append({"check": "the same symbol with its top-left finder erased is read by the repaint reading", "passed": result is not None and result["payload"] == planted})
    if mode in ("fragments", "all"):
        n, half = len(grid), len(grid) // 2 + 1
        pieces = [[row[:half] for row in grid[:half]], [row[half:] for row in grid[:half]], [row[:half] for row in grid[half:]], [row[half:] for row in grid[half:]]]
        result, _tried = assemble([pieces[2], pieces[0], pieces[3], pieces[1]], {})
        checks.append({"check": "the same symbol cut into four pieces, given out of order, is placed and read", "passed": result is not None and result["payload"] == planted})
    return {"passed": all(c["passed"] for c in checks), "checks": checks}


def describe_result(result):
    row = {"result": "decoded", "version": result["version"], "modules": "%d x %d" % (len(result["modules"]), len(result["modules"])), "level": result["level"],
           "mask": result["mask"], "format": result["format"], "errors_corrected": result["errors_corrected"], "blocks": result["blocks"],
           "blocks_without_error": result["blocks_clean"], "segments": result["segments"], "payload_bytes": len(result["payload"]),
           "located_by": result["located_by"], "orientation": result["orientation"],
           "fixed_modules_agreeing": "%d of %d" % (result["function_modules_agreeing"], result["function_modules"]), "parser": PARSER}
    for key in ("module_pixels", "function_patterns", "placements", "pieces_turned_quarter_turns", "modules_not_covered", "blocks_with_zero_syndromes", "polarity"):
        if key in result:
            row[key] = result[key]
    if result["notes"]:
        row["notes"] = result["notes"]
    shape, secret = payload_shape(result["payload"])
    row["payload_shape"] = shape
    if secret:
        row["payload_holds_a_secret_shape"] = True
    return row


def keep(place, row, result, number, want_repaint):
    """Write the payload (and the repainted symbol) of one result; the row says where, or why not."""
    try:
        row["payload_file"] = place.write("qr-%02d.payload.bin" % number, result["payload"], 0o600)
        row["payload_in_answer"] = False
        if want_repaint:
            grid, changed = repainted(result)
            side, rows = render(grid, 8, 4)
            row["repainted_file"] = place.write("qr-%02d.repainted.png" % number, png_bytes(side, side, rows))
            row["fixed_modules_repainted"] = changed
    except OSError as exc:
        row["write_error"] = "the payload could not be written under the output directory (%s)" % describe(exc)


def load(path, reader, what):
    data = read_file(path, MAX_IMAGE_BYTES, what)
    picture = read_picture(data, False, reader, tick)
    return picture, hashlib.sha256(data).hexdigest(), len(data)


def looked_for(stats, mode):
    methods = []
    if mode in ("auto", "finders"):
        methods.append("finder patterns (1:1:3:1:1 along rows and columns), three of them at the corners of a right angle, the grid sampled through them and the alignment pattern")
    if mode in ("auto", "repaint"):
        methods += ["two finder patterns as neighbouring or opposite corners of a square grid", "the box of the dark pixels cut into the module grid of each version the module size allows",
                    "the same grids with each of the 32 format words when neither format copy could be read"]
    return {"methods": methods, "polarities": ["dark on light", "light on dark"], "versions": "1 to %d" % MAX_VERSION, **stats}


def main():
    args, unknown = read_args(KNOWN_PARAMS)
    self_test = bool_param(args, "self_test")
    mode = choice_param(args, "mode", "auto", MODES)
    reader = choice_param(args, "reader", "auto", ("auto", "builtin"))
    seconds = int_param(args, "max_seconds", DEFAULT_SECONDS, 5, MAX_SECONDS)
    version = int_param(args, "version", None, 1, MAX_VERSION)
    module_pixels = number_param(args, "module_pixels", None, 1, 512)
    box = args.get("box")
    if box is not None:
        if not isinstance(box, list) or len(box) != 4 or any(isinstance(v, bool) or not isinstance(v, int) or not 0 <= v <= 100000 for v in box) or box[2] - box[0] < 21 or box[3] - box[1] < 21:
            raise Refused("box must be [left, top, right, bottom] in pixels, whole numbers, at least 21 wide and high: the symbol's own extent without its quiet zone")
    paths = []
    if args.get("image") is not None:
        paths.append(path_param(args.get("image"), "image"))
    if args.get("images") is not None:
        images = args.get("images")
        if not isinstance(images, list) or not images or len(images) > MAX_INPUTS:
            raise Refused("images must be a list of 1 to %d paths" % MAX_INPUTS)
        paths += [path_param(p, "each of images") for p in images]
    if len(paths) > MAX_INPUTS:
        raise Refused("at most %d pictures a call" % MAX_INPUTS)
    common = {"tool": TOOL, "mode": mode, "rules": RULES, "not_read": NOT_READ, **({"unrecognised_parameters": unknown} if unknown else {})}
    set_deadline(seconds)
    started = time.monotonic()
    check = control("all" if self_test else mode)
    if not check["passed"]:
        print_answer({**common, "status": "failed", "control": check, "error": "the planted control was not read",
                      "status_basis": "the planted control was not read by this build on this interpreter, so no picture was read: a symbol it missed would prove nothing"})
        raise SystemExit(1)
    if self_test:
        print_answer({**common, "status": "complete", "control": check, "self_test": True,
                      "status_basis": "the planted control alone was run and every check passed; no evidence was read"})
        return
    if not paths:
        raise Refused("image is required: the path of a picture (PNG by the built-in reader; other formats when Pillow imports), or images: a list of them. " + RULES[2])
    if mode == "fragments" and len(paths) < 2:
        raise Refused("mode fragments takes the pieces of one symbol together: images is a list of at least two pictures. " + RULES[2])
    if box is not None and (len(paths) != 1 or mode == "fragments"):
        raise Refused("box goes with one picture and a mode other than fragments")
    place = Place("qr_read")
    rows, reasons = [], []

    def one(path, number):
        row = {"input": printable(path)}
        try:
            picture, digest, size = load(path, reader, "the picture")
        except (Refused, NotAPicture) as exc:
            row.update({"result": "not read", "why": str(exc)})
            reasons.append("%s was not read as a picture" % row["input"])
            return row
        row.update({"sha256": digest, "bytes": size, "pixels": "%d x %d" % (picture.width, picture.height), "picture_reader": picture.reader})
        stats = {}
        result = None
        for polarity, threshold_rows in (("dark on light", picture.gray), ("light on dark", None)):
            if threshold_rows is None:
                threshold_rows = [r.translate(INVERT) for r in picture.gray]
            binary, threshold = binarise(threshold_rows, None, tick)
            result = read_symbol(binary, picture.width, picture.height, mode, stats, box=box, version=version)
            if result is not None:
                result["polarity"] = polarity
                break
        row["threshold"] = threshold
        if result is None:
            row.update({"result": "not a symbol", "looked_for": looked_for(stats, mode),
                        "meaning": "no QR symbol of version 1 to %d was read from this picture by these methods; see not_read for what they do not reach" % MAX_VERSION})
            return row
        row.update(describe_result(result))
        keep(place, row, result, number, mode == "repaint" or "function_patterns" in result)
        return row

    stopped = None
    if mode == "fragments":
        pieces, piece_rows, unread = [], [], 0
        for index, path in enumerate(paths):
            row = {"piece": index, "input": printable(path)}
            try:
                picture, digest, size = load(path, reader, "the picture")
                binary, _threshold = binarise(picture.gray, None, tick)
                grid, unit = piece_modules(binary, picture.width, picture.height, module_pixels)
                row.update({"sha256": digest, "bytes": size, "pixels": "%d x %d" % (picture.width, picture.height), "picture_reader": picture.reader})
                if grid is None:
                    row.update({"result": "not a piece", "why": unit})
                    unread += 1
                else:
                    row.update({"modules": "%d x %d" % (len(grid[0]), len(grid)), "module_pixels": round(unit, 2)})
                    pieces.append(grid)
            except (Refused, NotAPicture) as exc:
                row.update({"result": "not read", "why": str(exc)})
                unread += 1
            except Clock:
                stopped = "the clock ran out while piece %d was being read" % index
                break
            piece_rows.append(row)
        row = {"input": "the set of %d pieces" % len(paths), "pieces": piece_rows}
        if stopped is None and unread:
            row.update({"result": "not read", "why": "%d of the %d pictures gave no piece (see pieces): the set was not placed" % (unread, len(paths))})
            reasons.append("%d of the pieces could not be read" % unread)
        elif stopped is None:
            if len(pieces) > MAX_PIECES:
                raise Refused("at most %d pieces are placed" % MAX_PIECES)
            stats = {}
            try:
                result, tried = assemble(pieces, stats, version)
            except Clock:
                result, tried, stopped = None, [], "the clock ran out while the pieces were being placed (%d placements scored)" % stats.get("placements_scored", 0)
            if result is not None:
                row.update(describe_result(result))
                keep(place, row, result, 1, True)
            elif stopped is None:
                row.update({"result": "not a symbol", "looked_for": {"methods": ["each piece cut into modules at the module size its runs give", "every place of each piece in the grids of the versions the pieces could fill, in all four turns of the set, ranked on the fixed modules",
                                                                                 "whole placements scored on the format word (BCH distance) and the Reed-Solomon syndromes, the most constrained piece first"],
                                                                     "best_placements_that_did_not_decode": tried, **stats},
                            "meaning": "these pieces were not put together into a QR symbol of version 1 to %d by these methods; see not_read" % MAX_VERSION})
        rows.append(row)
    else:
        for number, path in enumerate(paths, 1):
            try:
                rows.append(one(path, number))
            except Clock:
                stopped = "the clock ran out while picture %d of %d was being read" % (number, len(paths))
                rows.append({"input": printable(path), "result": "not finished", "why": "the tool's clock (max_seconds %d) ran out in this picture" % seconds})
                break
    if stopped:
        reasons.append(stopped)
    if len(rows) < len(paths) and mode != "fragments":
        reasons.append("%d picture(s) were not reached" % (len(paths) - len(rows)))
    if any("write_error" in r for r in rows):
        reasons.append("a payload could not be written")
    counts = collections.Counter(r.get("result", "not finished") for r in rows)
    readable = counts["decoded"] + counts["not a symbol"]
    status = "failed" if readable == 0 and reasons else "partial" if reasons else "complete"
    basis = ("every picture given was read whole and searched by the methods named; %d decoded, %d not a symbol (a statement about these methods, the control having been read first)"
             % (counts["decoded"], counts["not a symbol"]) if status == "complete" else
             "not everything asked for was read: %s. %d decoded, %d not a symbol" % ("; ".join(reasons), counts["decoded"], counts["not a symbol"]))
    answer = {**common, "status": status, "status_basis": basis, "complete": status == "complete", "control": check,
              "counts": {"inputs": len(paths), "decoded": counts["decoded"], "not_a_symbol": counts["not a symbol"], "not_read": counts["not read"] + counts["not a piece"], "not_finished": counts["not finished"] + (len(paths) - len(rows) if mode != "fragments" else 0)},
              "rows": rows, "output_directory": place.shown, "seconds": round(time.monotonic() - started, 2),
              "payloads": "each decoded payload is a file (payload_file, mode 0600), never in this answer: read it there, and cite the file"}
    if reasons:
        answer["partial_reasons"] = reasons
    if place.note():
        answer["note"] = place.note()
    print_answer(answer, indent=1)
    if status == "failed":
        raise SystemExit(1)


INVERT = bytes(255 - v for v in range(256))

if __name__ == "__main__":
    exit_code = 0
    try:
        answered(main)
    except SystemExit as stop:
        exit_code = _code(stop)
    _leave(exit_code)
