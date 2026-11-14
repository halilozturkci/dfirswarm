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


import array
import collections
import errno
import hashlib
import itertools
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
        if "kill_decoder" in globals():
            kill_decoder()
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
# A stop ends the child that decodes a picture with Pillow (below) before the tool's own last word.
install_signal_handlers(lambda signum: (kill_decoder(), interrupted_answer(signum)))


TOOL = {"name": "qr_read", "version": 11}
PARSER = "qr_read/5"
DEFAULT_SECONDS, MAX_SECONDS = 90, 100          # under the manifest's 120
MAX_INPUTS = 64
MAX_SYMBOLS = 8                                 # symbols read from one frame: a frame with more is searched no further, and the answer is partial
# What a call can leave unread or unjudged, each a counter of the one list (Unread) the status is derived from.
UNREAD = ("pictures_not_read", "pictures_damaged", "jpeg_data_not_walked", "pictures_with_frames_not_searched", "finder_patterns_not_read",
          "frames_past_the_symbol_bound", "pieces_not_read", "pieces_contradicting_the_symbol", "placement_search_stopped", "clock_stops",
          "pictures_not_reached", "payloads_not_written")
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
            "count as light, there is no erasure decoding); frames past the %dth of a picture, and by the built-in reader (reader builtin, or "
            "no Pillow) the frames of an animated PNG other than its default image (frames_not_read names them, and the answer is partial); "
            "a picture of a format other than PNG, JPEG, BMP, GIF, WebP and TIFF (an icon, for one), which is not read; a JPEG, or a TIFF "
            "strip or tile of JPEG data, whose coded data the tool's own walk does not take (arithmetic, lossless or hierarchical coding, a "
            "height given by a DNL marker, more than one frame header, a walk past its share of the clock; old-style JPEG in a TIFF, a TIFF "
            "directory the walk cannot follow) or a frame past the first of a multi-picture JPEG, which Pillow decodes and "
            "which is then not told from one cut short and given its end marker back (jpeg_data_not_walked names it, and the answer is "
            "partial); more than %d symbols in one frame (the search of a frame stops there, and the answer is partial)" % (64, 8))


# ---- what every answer and every file of this tool goes through ---------------------------------------------------------------------
MAX_ARGUMENT_BYTES = 4 << 20


class Refused(Exception):
    """A parameter or an input the tool refuses: the text is the whole message."""


class Unread:
    """The one list of what this call did not read or did not judge: every place that leaves something unread or unjudged counts it here,
    under a name declared up front, with the sentence that says it. The status is derived from this list alone (a failed call aside): a
    count above zero makes the answer partial. The answer prints every counter, zeros included (`not_read_or_judged`)."""

    def __init__(self, *names):
        self.counts = {name: 0 for name in names}
        self.said = {}

    def add(self, name, count=1, sentence=None):
        if name not in self.counts:
            raise KeyError("an undeclared counter: %s" % name)
        if count > 0:
            self.counts[name] += count
            if sentence:
                self.said.setdefault(name, []).append(sentence)

    def __bool__(self):
        return any(self.counts.values())

    def reasons(self):
        """The sentences of the counters above zero, in the order they were declared."""
        out = []
        for name, count in self.counts.items():
            if count:
                out += self.said.get(name) or ["%s: %d" % (name, count)]
        return out


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
MAX_FRAMES = 64                    # frames or pages of one picture that are searched


class NotAPicture(Exception):
    """The file is not a picture this tool can read; the text says what was found and what would read it. `damaged` is True when the
    file is a picture of its kind that is cut or corrupt (not one of a form the reader does not take)."""

    def __init__(self, text, damaged=False):
        super().__init__(text)
        self.damaged = damaged


class Picture:
    """A picture as rows of bytes: `gray` (one byte a pixel, 0 black to 255 white) always, `rgb` (three bytes a pixel) when it was asked for.
    `frames` is how many frames or pages the built-in reader knows the file holds (this is the first), and `frames_why` why it does not
    read the others. `stream` is Pillow's (a PillowFrames, the child that decodes the picture): its next_frame() gives the frames after
    this one as they are decoded, and how many there are is known only when it has given the last. `damage` is what the built-in reader
    found wrong with a PNG that Pillow then read, or what the tool's own walk of a JPEG's coded data or of a TIFF's strips and tiles
    found cut or corrupt (Pillow fills what is missing), or None; `damage_by` says which found it. `unchecked` is why that walk did not
    reach the picture (a coding it does not take, its share of the clock), or None."""

    def __init__(self, width, height, gray, rgb=None, reader=""):
        self.width, self.height, self.gray, self.rgb, self.reader = width, height, gray, rgb, reader
        self.frames, self.stream, self.frames_why, self.damage, self.notes = 1, None, None, None, []
        self.damage_by, self.unchecked, self.jpeg = "the built-in reader", None, False
        self.later_damage = None        # what the built-in reader found cut in an animated PNG's frames after its image data


SPAN = 1 << 16                     # the bytes (or pixels) of a row worked between two readings of the clock: a row can be 144 MB wide


def _spans(start, stop, tick, step=1):
    """range(start, stop) in pieces of SPAN steps, the clock read before each: (first, end) pairs."""
    for first in range(start, stop, SPAN * step):
        if tick:
            tick()
        yield first, min(stop, first + SPAN * step)


def _unfilter(kind, out, previous, bpp, tick=None):
    """Undo a row's filter in place (`out` is a bytearray of the row's bytes) and return it; the clock is read every SPAN bytes."""
    if kind == 0:
        return out
    if kind == 1:
        for first, end in _spans(bpp, len(out), tick):
            for i in range(first, end):
                out[i] = (out[i] + out[i - bpp]) & 255
    elif kind == 2:
        if previous is not None:
            for first, end in _spans(0, len(out), tick):
                out[first:end] = bytes((a + b) & 255 for a, b in zip(out[first:end], previous[first:end]))
    elif kind == 3:
        for first, end in _spans(0, len(out), tick):
            for i in range(first, end):
                left = out[i - bpp] if i >= bpp else 0
                up = previous[i] if previous is not None else 0
                out[i] = (out[i] + ((left + up) >> 1)) & 255
    elif kind == 4:
        for first, end in _spans(0, len(out), tick):
            for i in range(first, end):
                a = out[i - bpp] if i >= bpp else 0
                b = previous[i] if previous is not None else 0
                c = previous[i - bpp] if previous is not None and i >= bpp else 0
                p = a + b - c
                pa, pb, pc = abs(p - a), abs(p - b), abs(p - c)
                out[i] = (out[i] + (a if pa <= pb and pa <= pc else b if pb <= pc else c)) & 255
    else:
        raise NotAPicture("a PNG row with the unknown filter %d" % kind)
    return out


def read_png(data, want_rgb=False, tick=None):
    """A PNG read with the standard library alone: 8 and 16-bit grey, RGB, palette and alpha forms and the 1, 2 and 4-bit grey and palette
    forms, not interlaced. Transparency is put on white. NotAPicture for anything else; tick() is the clock, read every 1024 chunks, once a
    row and every SPAN bytes inside a row (a row can be 144 MB wide)."""
    if data[:8] != PNG_MAGIC:
        raise NotAPicture("not a PNG (no PNG signature)")
    at, header, palette, alpha, parts, animation, default_in_animation, chunks = 8, None, None, None, [], None, False, 0
    later = []                      # the frames after the image data (fdAT): width, height and their parts, up to MAX_FRAMES
    while at + 12 <= len(data):
        chunks += 1
        if tick and chunks % 1024 == 0:
            tick()
        length = int.from_bytes(data[at:at + 4], "big")
        kind = data[at + 4:at + 8]
        body = data[at + 8:at + 8 + length]
        name = "".join(ch if ch.isalpha() else "?" for ch in kind.decode("latin-1"))
        if len(body) != length or at + 12 + length > len(data):
            raise NotAPicture("a PNG cut inside its %s chunk" % name, damaged=True)
        if zlib.crc32(kind + body) != int.from_bytes(data[at + 8 + length:at + 12 + length], "big"):
            raise NotAPicture("a PNG whose %s chunk fails its CRC" % name, damaged=True)
        at += 12 + length
        if kind == b"acTL" and length == 8:
            animation = int.from_bytes(body[:4], "big")
        elif kind == b"fcTL" and not parts:
            default_in_animation = True
        elif kind == b"fcTL" and animation is not None and length >= 12 and len(later) < MAX_FRAMES:
            later.append((int.from_bytes(body[4:8], "big"), int.from_bytes(body[8:12], "big"), []))
        elif kind == b"fdAT" and later and length > 4:
            later[-1][2].append(body[4:])
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
        raise NotAPicture("a PNG with no header or no image data", damaged=True)
    width, height, depth, colour, _compression, _filter, interlace = header
    if width == 0 or height == 0 or width * height > MAX_PIXELS:
        raise NotAPicture("a PNG of %d x %d pixels (this tool reads up to %d pixels)" % (width, height, MAX_PIXELS))
    if height > MAX_ROWS:
        raise NotAPicture("a PNG of %d x %d pixels (this tool reads up to %d rows)" % (width, height, MAX_ROWS))
    channels = {0: 1, 2: 3, 3: 1, 4: 2, 6: 4}.get(colour)
    if channels is None or depth not in (1, 2, 4, 8, 16) or (depth < 8 and colour not in (0, 3)) or (depth == 16 and colour == 3):
        raise NotAPicture("a PNG of colour type %d at %d bits, which the format does not define" % (colour, depth))
    if colour == 3 and palette is None:
        raise NotAPicture("a palette PNG with no palette", damaged=True)
    # The frames of an animated PNG after its image data are Pillow's to decode, and Pillow fills one whose data ends early as it does
    # the image data (see _inflated_length): each is measured here, and one that is cut makes the picture damaged.
    later_damage = None
    for number, (frame_width, frame_height, frame_parts) in enumerate(later, 1):
        if 0 < frame_width * frame_height <= MAX_PIXELS:
            frame_want = _png_data_length(frame_width, frame_height, channels, depth, interlace)
            got = _inflated_length(frame_parts, frame_want, tick)
            if got < frame_want:
                later_damage = ("an animated PNG whose frame %d after the image data (fdAT) ends after %d of %d bytes" % (number, got, frame_want))
                break
    if interlace:
        # Not read here, but its image data is measured, so that a cut file is not handed to Pillow as a whole one.
        want = _png_data_length(width, height, channels, depth, interlace)
        got = _inflated_length(parts, want, tick)
        if got < want:
            raise NotAPicture("an interlaced PNG whose image data ends after %d of %d bytes" % (got, want), damaged=True)
        if later_damage:
            raise NotAPicture(later_damage, damaged=True)
        raise NotAPicture("an interlaced PNG: the built-in reader does not read Adam7 (Pillow does, when it is installed)")
    stride = (width * channels * depth + 7) // 8
    bpp = max(1, channels * depth // 8)
    want = height * (stride + 1)
    if want > MAX_PNG_ROWS:
        # Not held here, but its image data is measured, so that a cut file is not handed to Pillow as a whole one.
        got = _inflated_length(parts, want, tick)
        if got < want:
            raise NotAPicture("a PNG whose image data ends after %d of %d bytes" % (got, want), damaged=True)
        if later_damage:
            raise NotAPicture(later_damage, damaged=True)
        raise NotAPicture("a PNG whose rows are %d bytes when inflated (the built-in reader takes up to %d; Pillow, when it is installed, reads it)" % (want, MAX_PNG_ROWS))
    raw = _inflate(parts, want, tick)
    if len(raw) < want:
        raise NotAPicture("a PNG whose image data ends after %d of %d bytes" % (len(raw), want), damaged=True)
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
    shift = 8
    if depth == 16:
        # A 16-bit sample is brought to 8 bits by the picture's own largest sample, not by its high byte alone: a picture whose samples
        # run 0 to 255 (a converted 8-bit one) would be all black by its high bytes. One pass over the rows finds the largest.
        high, previous = 0, None
        for y in range(height):
            if tick:
                tick()
            start = y * (stride + 1)
            line = _unfilter(raw[start], raw[start + 1:start + 1 + stride], previous, bpp, tick)
            previous = line
            high = max(high, max(line[0::2]))
        shift = high.bit_length()
    gray, rgb, previous = [], [] if want_rgb else None, None
    for y in range(height):
        if tick:
            tick()
        start = y * (stride + 1)
        line = _unfilter(raw[start], raw[start + 1:start + 1 + stride], previous, bpp, tick)
        previous = line
        if depth == 16:
            line = b"".join(bytes(min(255, ((line[i] << 8) | line[i + 1]) >> shift) for i in range(first, end, 2)) for first, end in _spans(0, len(line), tick, 2))
        elif depth < 8:
            mask, scale = (1 << depth) - 1, 255 // ((1 << depth) - 1) if colour == 0 else 1
            line = b"".join(bytes(((line[(x * depth) >> 3] >> (8 - depth - (x * depth) % 8)) & mask) * scale for x in range(first, end)) for first, end in _spans(0, width, tick))
        if colour == 0:
            g = bytes(line)
        elif colour == 3:
            g = bytes(line.translate(bytes(pal_gray)))
        elif colour == 2:
            g = b"".join(bytes((line[i] * 299 + line[i + 1] * 587 + line[i + 2] * 114) // 1000 for i in range(first, end, 3)) for first, end in _spans(0, 3 * width, tick, 3))
        elif colour == 4:
            g = b"".join(bytes((line[i] * line[i + 1] + 255 * (255 - line[i + 1])) // 255 for i in range(first, end, 2)) for first, end in _spans(0, 2 * width, tick, 2))
        else:
            g = b"".join(bytes(((line[i] * 299 + line[i + 1] * 587 + line[i + 2] * 114) // 1000 * line[i + 3] + 255 * (255 - line[i + 3])) // 255 for i in range(first, end, 4))
                         for first, end in _spans(0, 4 * width, tick, 4))
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
    picture = Picture(width, height, gray, rgb, "the built-in PNG reader")
    if depth == 16:
        picture.notes.append("16-bit samples, brought to 8 bits by the picture's own largest sample (shifted right by %d bits)" % shift)
    if animation is not None and animation + (0 if default_in_animation else 1) > 1:
        picture.frames = animation + (0 if default_in_animation else 1)
        picture.frames_why = "an animated PNG: the built-in reader reads its default image, not its other frames (Pillow does, when it is installed)"
    picture.later_damage = later_damage
    return picture


def _inflate(parts, want, tick=None):
    """The zlib stream of the IDAT chunks, inflated to at most want + 1 bytes. NotAPicture (damaged) for a stream that is not zlib."""
    inflater = zlib.decompressobj()
    raw = bytearray()
    try:
        for part in parts:
            raw += inflater.decompress(part, want - len(raw) + 1)
            if len(raw) > want:
                break
            if tick:
                tick()
    except zlib.error:
        raise NotAPicture("a PNG whose image data is not a zlib stream that inflates (after %d bytes)" % len(raw), damaged=True)
    return raw


INFLATE_PIECE = 1 << 22            # the inflated bytes of a PNG measured between two readings of the clock


def _inflated_length(parts, want, tick=None):
    """How many bytes the zlib stream of the IDAT chunks inflates to, counted up to want + 1 and never held: the stream is inflated
    INFLATE_PIECE bytes at a time and each piece is dropped, the clock read between them. Pillow takes a zlib stream that ends before the
    rows do as the end of the picture and fills the rows it did not get, and says nothing: a PNG the built-in reader does not read (an
    interlaced one, one whose rows pass MAX_PNG_ROWS) is measured here before Pillow is given it. NotAPicture (damaged) for a stream that
    is not zlib."""
    inflater, got = zlib.decompressobj(), 0
    try:
        for part in parts:
            pending = part
            while got <= want:
                asked = min(INFLATE_PIECE, want + 1 - got)
                out = len(inflater.decompress(pending, asked))
                got += out
                pending = inflater.unconsumed_tail
                if tick:
                    tick()
                if not pending and out < asked:
                    break
            if got > want or inflater.eof:
                break
    except zlib.error:
        raise NotAPicture("a PNG whose image data is not a zlib stream that inflates (after %d bytes)" % got, damaged=True)
    return got


def pillow():
    """The Pillow module, or None when it does not import here. The plugins of PILLOW_FORMATS are loaded here, once, before a child is forked."""
    if "module" not in _PILLOW:
        try:
            from PIL import Image
            Image.MAX_IMAGE_PIXELS = MAX_PIXELS
            for plugin in ("BmpImagePlugin", "GifImagePlugin", "JpegImagePlugin", "MpoImagePlugin", "PngImagePlugin", "TiffImagePlugin", "WebPImagePlugin"):
                try:
                    __import__("PIL." + plugin)
                except Exception:  # noqa: BLE001 - a plugin that does not load leaves its format unread
                    pass
            _PILLOW["module"] = Image
            _PILLOW["version"] = getattr(__import__("PIL"), "__version__", "?")
        except Exception:  # noqa: BLE001 - not installed, or broken: the built-in reader is what there is
            _PILLOW["module"] = None
    return _PILLOW["module"]


_PILLOW = {}


def clock_deadline():
    """When the tool's clock runs out (time.monotonic()), or None before it is set."""
    return STOP["deadline"]


# ---- Pillow in a child process that the clock ends (the same code is in qr_read and glyph_strip) --------------------------------------
# Pillow's decoders do not read this tool's clock: a progressive JPEG of a quarter of a million scans, a TIFF of a quarter of a million
# pages (Pillow counts them by walking every page) and a format Pillow decodes in Python each ran for minutes inside one call. So Pillow
# never runs in the tool's own process. A child is forked for one picture; it opens the picture as one of PILLOW_FORMATS only, and sends
# each frame's size and then its grey rows on a pipe, frame after frame (seeking to the next, never asking how many there are), up to the
# frames asked for, and then whether there is another. The tool reads the pipe against its clock and kills the child (SIGKILL) when the
# clock runs out or the picture is done. The child's address space is bounded (DECODE_MEMORY more than it was forked with; Linux, where
# the limit is enforced), its CPU time by the clock, it dies with the tool (Linux), it takes the stop signals' default action, it writes
# nothing on standard output, and it ends with os._exit (no hook of the tool runs in it). A JPEG is counted before it is handed over: one
# with more than MAX_JPEG_SCANS start-of-scan markers is refused (a picture has one, a progressive one about ten).
#
# What the gate does with each format Pillow may open here (PILLOW_FORMATS; nothing else is opened). A decoder that meets data cut short
# or zeroed may raise (the picture is then not read), or fill what it lacks and say nothing (the tool must then find the damage itself).
# Every format, and every TIFF shape, is in one of three groups:
#   walked by the tool:    PNG (every PNG Pillow decodes has its image data, and each animation frame's, inflated and measured against
#                          what its rows need: png_check); JPEG, the first picture of the file (its coded data walked block by block:
#                          jpeg_check); TIFF pages whose shape is on the allowlist in tiff_check: uncompressed (as many pieces as its size needs, byte counts against
#                          the rows, Pillow's own decoder) and JPEG (each strip or tile walked as a JPEG, its frame the strip's or
#                          tile's size).
#   shown to raise:        GIF and BMP (and BMP's RLE) data cut short; WebP cut short; TIFF pages coded with LZW, either Deflate or
#                          PackBits in photometric 0 to 3 with one of strip or tile tags (Pillow reads them strip by strip through
#                          libtiff, which fails the read on a strip that does not decode).
#   counted as not walked: every other TIFF shape (any other codec, YCbCr or another photometric that sends Pillow to libtiff's RGBA
#                          interface, which fills and only prints, a tag named twice, strip and tile tags together, a directory the walk
#                          cannot follow); the pictures of a JPEG past its first (MPO).
# Under all three, a safety net that does not depend on parsing: the child's standard error (where libtiff, and libjpeg and zlib under
# it, print what they could not decode) is read, its first DECODER_SAID_BYTES kept, and any line on it but a note on a tag libtiff does
# not know makes the frame damaged. A known limit: WebP and BMP data whose tail is zeroed, which decodes as zeros without a word.
import resource as _resource
import select as _decode_select

PILLOW_FORMATS = ("PNG", "JPEG", "BMP", "GIF", "WEBP", "TIFF")     # a JPEG of several pictures (MPO) is opened by the JPEG plugin
PILLOW_FORMAT_NAMES = "PNG, JPEG, BMP, GIF, WebP and TIFF"
MAX_ROWS = 100_000                 # a picture higher than this is refused: each row is one object, and a picture one pixel wide would take gigabytes
MAX_JPEG_SCANS = int(os.environ.get("TOOL_MAX_JPEG_SCANS") or 256)        # the environment variable is for the tests
DECODE_MEMORY = 1 << 30            # what the decoding child may add to the address space it was forked with (Linux)
DECODER = {"pid": None}            # the decoding child that is running, which the stop's last word and the exit end
DECODER_SAID_BYTES = 1 << 16       # what is kept of the decoding child's standard error (the rest is read and dropped, and counted)
DECODER_QUIET = (b"Unknown field with tag",)   # libtiff's note on a tag it does not know: about the directory, not the image data
DECODER_SAID_BY = "Pillow's decoder (libtiff, or libjpeg or zlib under it)"


def kill_decoder():
    """End the decoding child that is running, if one is, and reap it."""
    pid, DECODER["pid"] = DECODER["pid"], None
    if pid:
        try:
            os.kill(pid, signal.SIGKILL)
        except OSError:
            pass
        try:
            os.waitpid(pid, 0)
        except OSError:
            pass


atexit.register(kill_decoder)


def jpeg_scans(data):
    """The start-of-scan markers of a JPEG (0 for any other format). Inside entropy-coded data a 0xFF byte is always followed by 0x00 or a
    restart marker, so FF DA is a marker wherever it is; one inside an embedded thumbnail is counted too, which only errs on the side of
    refusing."""
    return data.count(b"\xff\xda") if data[:2] == b"\xff\xd8" else 0


# ---- the tool's own walk of a JPEG's coded data ------------------------------------------------------------------------------------
# libjpeg (and so Pillow) takes a JPEG cut short and given its end-of-image marker back (what a carver makes of a fragmented file) as a
# whole picture: it fills the blocks it did not find with grey and only warns, and Pillow does not pass the warning on. So a JPEG Pillow
# decoded is walked here too, block by block through its Huffman codes, and must code every block its frame's size implies.
JPEG_CHECK_SECONDS = 30            # at most this, and half of what the clock has left, for the walk of one picture

class JpegUnchecked(Exception):
    """The tool's own check of a JPEG's coded data does not reach this picture: the text says why (a coding it does not walk, its share
    of the clock)."""


def _jpeg_huffman(counts, symbols):
    """A lookup of 65,536 entries for one Huffman table: (code length << 8) | symbol, 0 where no code begins with those 16 bits; None
    for a table whose codes do not fit their lengths."""
    table = [0] * 65536
    code, at = 0, 0
    for length in range(1, 17):
        for _ in range(counts[length - 1]):
            if code >= (1 << length):
                return None
            span = 1 << (16 - length)
            start = code << (16 - length)
            table[start:start + span] = [(length << 8) | symbols[at]] * span
            code += 1
            at += 1
        code <<= 1
    return table


def _jpeg_pieces(data, at, most, check):
    """The entropy-coded data of one scan from byte `at`: ([(the piece with its stuffed bytes taken out, the restart marker after it or
    None)], the offset of the marker that ends the scan, or None when the file ends first; -1 past `most` pieces). check() is called
    every 4096 bytes 0xFF met."""
    pieces, start, size, met = [], at, len(data), 0
    while True:
        met += 1
        if met % 4096 == 0:
            check(0)
        i = data.find(b"\xff", at)
        if i < 0 or i + 1 >= size:
            return pieces, None
        following = data[i + 1]
        if following == 0x00:
            at = i + 2
            continue
        if following == 0xFF:
            at = i + 1
            continue
        if 0xD0 <= following <= 0xD7:
            pieces.append((data[start:i].replace(b"\xff\x00", b"\xff"), following - 0xD0))
            if len(pieces) > most:
                return pieces, -1
            start = at = i + 2
            continue
        pieces.append((data[start:i].replace(b"\xff\x00", b"\xff"), None))
        return pieces, i


def _jpeg_scan(data, at, frame, scan, ss, se, ah, al, dc, ac, restart, nonzero, lowest, check):
    """Walk one scan's coded data from byte `at`, block by block: the offset of the marker after it, or a sentence saying where the
    data is cut or corrupt."""
    progressive = frame["progressive"]
    layout = frame["layout"]
    if progressive:
        if (ss == 0) != (se == 0) or se > 63 or ss > se or (ss > 0 and len(scan) != 1) or (ah and al != ah - 1) or al > 13:
            return "a progressive scan whose spectral selection or approximation is not one the standard allows"
        for cid, _d, _a in scan:
            for k in range(ss, se + 1):
                if (lowest[cid][k] is not None) if ah == 0 else (lowest[cid][k] != ah):
                    return "a progressive scan that codes coefficients out of order (a scan missing before it, or one repeated)"
    elif ss != 0 or se != 63 or ah or al:
        return "a sequential scan whose spectral selection is not the whole block"
    tables = []
    for cid, d, a in scan:
        need_dc = ss == 0 and ah == 0
        need_ac = se > 0
        if (need_dc and d not in dc) or (need_ac and a not in ac):
            return "a scan of component %d names a Huffman table not defined before it" % cid
        tables.append((cid, dc.get(d), ac.get(a)))
    if len(scan) == 1:
        cid = scan[0][0]
        units = layout[cid]["bw"] * layout[cid]["bh"]
    else:
        units = frame["mcux"] * frame["mcuy"]
    intervals = -(-units // restart) if restart else 1
    pieces, end = _jpeg_pieces(data, at, intervals, check)
    if end is None:
        return "the file ends inside the scan's coded data, with no marker after it"
    if end == -1:
        return "more restart intervals than the scan has blocks"
    if len(pieces) < intervals:
        return ("the coded data ends after %d of the %d restart intervals the frame's size implies (a cut file given its end back)"
                % (len(pieces), intervals))
    if len(pieces) > intervals or pieces[-1][1] is not None:
        return "more restart intervals than the scan has blocks"
    for index, (_piece, number) in enumerate(pieces[:-1]):
        if number != index % 8:
            return "restart marker RST%d where RST%d was due (interval %d of %d)" % (number, index % 8, index + 1, intervals)
    walked = 0
    for index, (piece, _number) in enumerate(pieces):
        count = min(restart, units - index * restart) if restart else units
        found = _jpeg_interval(piece, frame, scan, tables, ss, se, ah, al, nonzero, walked, count, len(scan) == 1, check)
        if found is not None:
            return found
        walked += count
    if progressive:
        for cid, _d, _a in scan:
            for k in range(ss, se + 1):
                lowest[cid][k] = al
    return end


def _ended_or(pos, bits, said):
    """What a walk that went wrong at bit `pos` of `bits` says: that the data ends there (a code that would reach past the last byte) or
    what it found."""
    if pos + 16 > bits:
        return ("the coded data ends before the last unit the frame's size implies (a cut file given its end back: the decoder fills what "
                "follows, it is not read)")
    return said


def _jpeg_interval(piece, frame, scan, tables, ss, se, ah, al, nonzero, first, count, single, check):
    """Walk `count` units (an MCU, or a block of a scan of one component) from unit `first` through one restart interval's data: None,
    or a sentence saying where it is cut or corrupt."""
    buf = piece + b"\x00\x00\x00\x00"
    bits = len(piece) * 8
    pos = 0
    layout = frame["layout"]
    eobrun = 0
    if single:
        cid, dct, act = tables[0]
        geometry = layout[cid]
        plan = None
    else:
        plan = []
        for cid, dct, act in tables:
            g = layout[cid]
            for v in range(g["v"]):
                for h in range(g["h"]):
                    plan.append((dct, act))
    progressive = frame["progressive"]
    for unit in range(first, first + count):
        if unit % 512 == 0:
            check(unit)
        if single:
            blocks = ((dct, act),)
        else:
            blocks = plan
        for dct, act in blocks:
            if not progressive:
                e = dct[(int.from_bytes(buf[pos >> 3:(pos >> 3) + 3], "big") >> (8 - (pos & 7))) & 0xFFFF]
                if not e:
                    return _ended_or(pos, bits, "a code no Huffman table holds, at bit %d of an interval" % pos)
                pos += (e >> 8) + (e & 255)
                k = 1
                while k < 64:
                    e = act[(int.from_bytes(buf[pos >> 3:(pos >> 3) + 3], "big") >> (8 - (pos & 7))) & 0xFFFF]
                    if not e:
                        return _ended_or(pos, bits, "a code no Huffman table holds, at bit %d of an interval" % pos)
                    pos += e >> 8
                    s = e & 15
                    if s:
                        k += ((e & 255) >> 4) + 1
                        pos += s
                    elif (e & 255) == 0xF0:
                        k += 16
                    else:
                        break
                if k > 64:
                    return _ended_or(pos, bits, "a block whose coefficients run past the 64th")
            elif ss == 0:
                if ah:
                    pos += 1
                else:
                    e = dct[(int.from_bytes(buf[pos >> 3:(pos >> 3) + 3], "big") >> (8 - (pos & 7))) & 0xFFFF]
                    if not e:
                        return _ended_or(pos, bits, "a code no Huffman table holds, at bit %d of an interval" % pos)
                    pos += (e >> 8) + (e & 255)
            else:
                cid = scan[0][0]
                g = layout[cid]
                block = (unit // g["bw"]) * g["pw"] + unit % g["bw"]
                marks = nonzero[cid]
                if ah == 0:
                    if eobrun:
                        eobrun -= 1
                        continue
                    k = ss
                    mask = marks[block]
                    while k <= se:
                        e = act[(int.from_bytes(buf[pos >> 3:(pos >> 3) + 3], "big") >> (8 - (pos & 7))) & 0xFFFF]
                        if not e:
                            return _ended_or(pos, bits, "a code no Huffman table holds, at bit %d of an interval" % pos)
                        pos += e >> 8
                        r, s = (e & 255) >> 4, e & 15
                        if s:
                            k += r
                            if k > se:
                                return _ended_or(pos, bits, "a block whose coefficients run past the scan's last")
                            pos += s
                            mask |= 1 << k
                            k += 1
                        elif r == 15:
                            k += 16
                        else:
                            eobrun = (1 << r) - 1
                            if r:
                                eobrun += (int.from_bytes(buf[pos >> 3:(pos >> 3) + 3], "big") >> (24 - (pos & 7) - r)) & ((1 << r) - 1)
                                pos += r
                            break
                    if k > se + 1:
                        return _ended_or(pos, bits, "a block whose coefficients run past the scan's last")
                    marks[block] = mask
                else:
                    k = ss
                    mask = marks[block]
                    if eobrun == 0:
                        while k <= se:
                            e = act[(int.from_bytes(buf[pos >> 3:(pos >> 3) + 3], "big") >> (8 - (pos & 7))) & 0xFFFF]
                            if not e:
                                return _ended_or(pos, bits, "a code no Huffman table holds, at bit %d of an interval" % pos)
                            pos += e >> 8
                            r, s = (e & 255) >> 4, e & 15
                            if s:
                                if s != 1:
                                    return _ended_or(pos, bits, "a refinement code of a size other than one")
                                pos += 1
                            elif r != 15:
                                eobrun = 1 << r
                                if r:
                                    eobrun += (int.from_bytes(buf[pos >> 3:(pos >> 3) + 3], "big") >> (24 - (pos & 7) - r)) & ((1 << r) - 1)
                                    pos += r
                                break
                            while k <= se:
                                if mask >> k & 1:
                                    pos += 1
                                else:
                                    if r == 0:
                                        break
                                    r -= 1
                                k += 1
                            if s:
                                if k > se:
                                    return _ended_or(pos, bits, "a refinement that places a coefficient past the scan's last")
                                mask |= 1 << k
                            k += 1
                    if eobrun > 0:
                        while k <= se:
                            if mask >> k & 1:
                                pos += 1
                            k += 1
                        eobrun -= 1
                    marks[block] = mask
            if pos > bits:
                return ("the coded data ends inside unit %d, before the last the frame's size implies (a cut file given its end back: the "
                        "decoder fills what follows, it is not read)" % (unit + 1))
    if pos > bits:
        return "the coded data ends before the interval's last unit"
    if bits - pos >= 8:
        return "%d bytes of coded data follow the last unit the frame's size implies" % ((bits - pos) // 8)
    return None


def jpeg_check(data, tick, budget):
    """The tool's own walk of a JPEG's entropy-coded data (Huffman-coded, sequential or progressive; ISO/IEC 10918-1 Annexes F and G),
    without decoding a pixel: every scan is walked block by block through its Huffman codes, its restart markers are checked in order,
    and the walk must code every block the frame's size implies before the scan's data ends; the scans must code every component (a
    progressive set: every coefficient of every component to its last bit). Returns None when the data is whole, or a sentence saying
    where it is cut or corrupt (libjpeg, and so Pillow, fills what is missing with grey and goes on). JpegUnchecked for what it does not
    walk, and when `budget()` (seconds the walk may still take) runs out; tick() reads the tool's clock."""
    size = len(data)
    if data[:2] != b"\xff\xd8":
        raise JpegUnchecked("not a JPEG")
    at, dc, ac, frame, restart, scans = 2, {}, {}, None, 0, 0
    nonzero, lowest, sequential = {}, {}, {}

    def check(unit):
        tick()
        if budget() <= 0:
            raise JpegUnchecked("the check's share of the clock ran out in scan %d" % scans)

    while True:
        check(0)
        if at + 2 > size:
            return "the data ends at byte %d without an end-of-image marker" % at
        if data[at] != 0xFF:
            return "at byte %d a marker was expected" % at
        marker = data[at + 1]
        if marker == 0xFF:
            at += 1
            continue
        if marker == 0xD9:
            break
        if 0xD0 <= marker <= 0xD8 or marker == 0x01:
            at += 2
            continue
        if at + 4 > size:
            return "the data ends inside the marker at byte %d" % at
        length = int.from_bytes(data[at + 2:at + 4], "big")
        if length < 2 or at + 2 + length > size:
            return "the segment of marker FF%02X at byte %d runs past the end of the file" % (marker, at)
        body = data[at + 4:at + 2 + length]
        segment_end = at + 2 + length
        if marker in (0xC0, 0xC1, 0xC2):
            if frame is not None:
                raise JpegUnchecked("a JPEG with more than one frame header")
            if len(body) < 6:
                return "a frame header too short"
            height, width, count = int.from_bytes(body[1:3], "big"), int.from_bytes(body[3:5], "big"), body[5]
            if height == 0:
                raise JpegUnchecked("a JPEG whose height is given after its first scan (a DNL marker)")
            if width * height > MAX_PIXELS:
                raise JpegUnchecked("a JPEG whose frame header says %d x %d pixels, more than the %d this tool reads" % (width, height, MAX_PIXELS))
            if width == 0 or count == 0 or len(body) < 6 + 3 * count:
                return "a frame header that names no size or no component"
            sampling = {}
            for i in range(count):
                cid, factors = body[6 + 3 * i], body[7 + 3 * i]
                if not 1 <= factors >> 4 <= 4 or not 1 <= factors & 15 <= 4:
                    return "a component with a sampling factor out of range"
                sampling[cid] = (factors >> 4, factors & 15)
            hmax = max(h for h, _v in sampling.values())
            vmax = max(v for _h, v in sampling.values())
            mcux, mcuy = -(-width // (8 * hmax)), -(-height // (8 * vmax))
            layout = {}
            for cid, (h, v) in sampling.items():
                cw, ch = -(-width * h // hmax), -(-height * v // vmax)
                layout[cid] = {"h": h, "v": v, "bw": -(-cw // 8), "bh": -(-ch // 8), "pw": mcux * h, "ph": mcuy * v}
            frame = {"progressive": marker == 0xC2, "layout": layout, "mcux": mcux, "mcuy": mcuy}
            for cid in sampling:
                sequential[cid] = 0
                lowest[cid] = [None] * 64
                if frame["progressive"]:
                    nonzero[cid] = array.array("Q", bytes(8 * layout[cid]["pw"] * layout[cid]["ph"]))
        elif 0xC3 <= marker <= 0xCF and marker not in (0xC4, 0xC8):
            raise JpegUnchecked("a JPEG coded in a way the check does not walk (marker FF%02X: lossless, hierarchical or arithmetic coding)" % marker)
        elif marker == 0xC4:
            p = 0
            while p < len(body):
                if p + 17 > len(body):
                    return "a Huffman table segment cut short"
                kind, index = body[p] >> 4, body[p] & 15
                counts = list(body[p + 1:p + 17])
                total = sum(counts)
                if p + 17 + total > len(body) or kind > 1 or index > 3:
                    return "a Huffman table segment that does not hold its table"
                table = _jpeg_huffman(counts, body[p + 17:p + 17 + total])
                if table is None:
                    return "a Huffman table whose codes do not fit their lengths"
                (dc if kind == 0 else ac)[index] = table
                p += 17 + total
        elif marker == 0xDD:
            if len(body) < 2:
                return "a restart interval segment too short"
            restart = int.from_bytes(body[:2], "big")
        elif marker == 0xDA:
            if frame is None:
                return "a scan before the frame header"
            ns = body[0] if body else 0
            if ns < 1 or ns > 4 or len(body) < 1 + 2 * ns + 3:
                return "a scan header that does not hold its components"
            scan = []
            for i in range(ns):
                cid, chosen = body[1 + 2 * i], body[2 + 2 * i]
                if cid not in frame["layout"]:
                    return "a scan of a component the frame does not have"
                scan.append((cid, chosen >> 4, chosen & 15))
            ss, se, ah, al = body[1 + 2 * ns], body[2 + 2 * ns], body[3 + 2 * ns] >> 4, body[3 + 2 * ns] & 15
            scans += 1
            found = _jpeg_scan(data, segment_end, frame, scan, ss, se, ah, al, dc, ac, restart, nonzero, lowest, check)
            if isinstance(found, str):
                return "scan %d: %s" % (scans, found)
            for cid, _d, _a in scan:
                sequential[cid] += 1
            at = found
            continue
        at = segment_end
    if frame is None:
        return "no frame header before the end-of-image marker"
    if scans == 0:
        return "no scan before the end-of-image marker"
    for cid in frame["layout"]:
        if frame["progressive"]:
            missing = sum(1 for k in range(64) if lowest[cid][k] != 0)
            if missing:
                return ("the scans end before every coefficient of component %d is coded to its last bit (%d of 64 are not): the data "
                        "that follows was not there to read" % (cid, missing))
        elif sequential[cid] == 0:
            return "component %d is in no scan before the end-of-image marker" % cid
        elif sequential[cid] > 1:
            return "component %d is in more than one sequential scan" % cid
    return None

# ---- the tool's own walk of a TIFF's strips and tiles ------------------------------------------------------------------------------
# libtiff hands a strip or tile of JPEG data (TIFF compression 7, and the old style, 6) to libjpeg, which takes one cut short and given its
# end marker back as whole, fills what is missing with grey and only warns; a JPEG strip whose frame is smaller than the strip leaves the
# rows it lacks unwritten. Pillow reads an uncompressed strip or tile itself, at its offset, for the bytes its rows need, whatever its
# byte count says (one of byte count 0, a strip the file does not hold, is read from wherever its offset points). libtiff's RGBA
# interface, which Pillow uses for YCbCr pages (but JPEG-coded ones of one plane), fills a strip that does not decode and only prints.
# So a TIFF Pillow decoded is walked here too, page by page, as many pages as are searched, and a page passes only when its shape is
# one the walk sees as libtiff and Pillow do (an allowlist): no tag named twice in its directory (Pillow keeps the last copy, libtiff
# the first), the tags of a size or a coding given once, strip tags or tile tags but not both (Pillow's own decoder takes the strips,
# the walk would take the tiles), and one of: uncompressed (1) in photometric 0, 1, 2, 3 or 5, whose strips or tiles must hold the bytes
# their rows need; JPEG (7) in photometric 0, 1, 2 or 6, of one plane, each strip or tile walked as a JPEG (the page's JPEGTables put
# before its own data) whose frame is the strip's or tile's size with a component for each sample; or LZW or
# PackBits in photometric 0 to 3, which Pillow reads strip by strip through libtiff and which fail the read on data that does not
# decode. Every other page is counted as not walked.
TIFF_MAGICS = (b"II*\x00", b"MM\x00*", b"II+\x00", b"MM\x00+")
TIFF_NUMBER_TYPES = (3, 4, 16)    # SHORT, LONG, LONG8: the types the walk reads the tags it uses as
TIFF_TYPE_SIZES = {1: 1, 2: 1, 3: 2, 4: 4, 5: 8, 6: 1, 7: 1, 8: 2, 9: 4, 10: 8, 11: 4, 12: 8, 13: 4, 16: 8, 17: 8, 18: 8}
TIFF_TAGS = (256, 257, 258, 259, 262, 273, 277, 278, 279, 284, 322, 323, 324, 325, 339, 347)
TIFF_SINGLE_TAGS = (256, 257, 259, 262, 277, 278, 284, 322, 323)    # tags of one value: a page that gives more is not walked
MAX_TIFF_PIECES = 1 << 20          # the strips or tiles of one page that are walked; a page with more is not walked


def _tiff_pages(data, most, tick):
    """The directories of a TIFF (classic or BigTIFF) in the order of their chain, up to `most`, the clock read as they are read: each a
    pair (a dict of the TIFF_TAGS it holds, tag -> list of numbers (JPEGTables -> its bytes); the tags, of any number, its directory
    names more than once). JpegUnchecked when the chain cannot be followed."""
    order = "little" if data[:2] == b"II" else "big"
    big = data[2:4] in (b"+\x00", b"\x00+")
    size = len(data)

    def number(at, width):
        if at < 0 or at + width > size:
            raise JpegUnchecked("the TIFF's directory points past the end of the file (byte %d)" % at)
        return int.from_bytes(data[at:at + width], order)

    word, entry, head = (8, 20, 8) if big else (4, 12, 2)
    offset = number(8, 8) if big else number(4, 4)
    pages, seen = [], set()
    while offset and len(pages) < most:
        if offset in seen:
            break                           # a chain that comes back to a directory ends there (Pillow stops there too)
        seen.add(offset)
        count = number(offset, head)
        if offset + head + count * entry + word > size:
            raise JpegUnchecked("the TIFF's directory %d runs past the end of the file" % (len(pages) + 1))
        tags, named, twice = {}, set(), set()
        for i in range(count):
            if i % 1024 == 0:
                tick()
            at = offset + head + i * entry
            tag, kind, n = number(at, 2), number(at + 2, 2), number(at + 4, word)
            if tag in named:
                twice.add(tag)
            named.add(tag)
            if tag not in TIFF_TAGS or tag in twice:
                continue
            width = TIFF_TYPE_SIZES.get(kind)
            if width is None:
                raise JpegUnchecked("tag %d of page %d is of the type %d, which the walk does not take" % (tag, len(pages) + 1, kind))
            if tag != 347 and kind not in TIFF_NUMBER_TYPES:
                # Pillow keeps a tag of another type as bytes, a float or a rational, and so reads the page differently from a walk that
                # reads every type as a whole number (a PlanarConfiguration of type BYTE reads as "contiguous" there, as 2 here).
                raise JpegUnchecked("tag %d of page %d is of the type %d; the walk takes the tags it reads only as SHORT, LONG or LONG8" % (tag, len(pages) + 1, kind))
            if n > MAX_TIFF_PIECES and tag != 347:
                raise JpegUnchecked("tag %d of page %d holds %d values, more than the %d the walk takes" % (tag, len(pages) + 1, n, MAX_TIFF_PIECES))
            where = at + 4 + word if n * width <= word else number(at + 4 + word, word)
            if where + n * width > size:
                raise JpegUnchecked("tag %d of page %d runs past the end of the file" % (tag, len(pages) + 1))
            if tag == 347:
                tags[tag] = data[where:where + n * width]
            else:
                values = []
                for k in range(n):
                    if k % 65536 == 0:
                        tick()
                    values.append(number(where + k * width, width))
                tags[tag] = values
        pages.append((tags, sorted(twice)))
        offset = number(offset + head + count * entry, word)
    return pages


def _tiff_needs(tags, tiled, pieces):
    """For an uncompressed page: the bytes Pillow reads for each of its strips or tiles (a function of the piece's index), and the pieces
    it reads at all (a page of one strip that covers it is read from its last offset alone, as Pillow does)."""
    width, height = (tags.get(256) or [0])[0], (tags.get(257) or [0])[0]
    samples = (tags.get(277) or [1])[0]
    depths = tags.get(258) or [1]
    planar = (tags.get(284) or [1])[0] == 2
    if planar and any(depth != 8 for depth in depths):
        # Pillow's raw path takes each plane's mode from one character of the page's ("RGB;16B" gives "R", "G", "B"): a plane of 16-bit
        # (or 4-bit) samples is decoded as 8-bit, with no error and nothing on stderr.
        raise JpegUnchecked("an uncompressed page in separate planes whose samples are not all 8 bits; Pillow decodes each plane as 8-bit")
    bits = depths[0] if planar else (sum(depths) if len(depths) == samples else depths[0] * samples)
    if tiled:
        across, down = (tags.get(322) or [0])[0], (tags.get(323) or [0])[0]
    else:
        across, down = width, (tags.get(278) or [height])[0]
    if not width or not height or not across or not down or not bits:
        raise JpegUnchecked("an uncompressed page whose size, strips or tiles are not given")
    if tiled and (across * bits) % 8:
        # Pillow's raw decoder takes the row stride of an edge tile rounded down (int(width * bits / 8)); libtiff and this walk round it up:
        # the TIFF specification asks a tile width of a multiple of 16, and a page that is not so is decoded with its right edge misread.
        raise JpegUnchecked("an uncompressed page whose tile rows (%d pixels of %d bits) do not end on a byte; the walk does not take it" % (across, bits))
    per_row = -(-width // across)
    per_plane = per_row * -(-height // down)
    stride = -(-across * bits // 8)
    expected = per_plane * (samples if planar else 1)
    if pieces != expected:
        # Pillow's decoder sets up one tile for each offset the directory names and writes nothing for the rest: the rows no piece holds stay
        # black, with no error and nothing on stderr.
        raise JpegUnchecked("an uncompressed page holds %d %s%s where its size needs %d; the walk does not take it" % (
            pieces, "tile" if tiled else "strip", "" if pieces == 1 else "s", expected))

    def need(k):
        k %= per_plane
        x, y = (k % per_row) * across, (k // per_row) * down
        rows = max(0, min(down, height - y))
        return 0 if rows == 0 else (rows - 1) * stride + -(-min(across, width - x) * bits // 8)

    read = range(pieces - 1, pieces) if across == width and down == height and not planar else range(pieces)
    return need, read


def _jpeg_frame(data):
    """The frame header of a JPEG stream: (height, width, components), or None when no frame header comes before its first scan."""
    at, size = 2, len(data)
    while at + 4 <= size:
        if data[at] != 0xFF:
            return None
        marker = data[at + 1]
        if marker == 0xFF:
            at += 1
            continue
        if marker in (0xD8, 0xD9, 0xDA):
            return None
        if 0xD0 <= marker <= 0xD7 or marker == 0x01:
            at += 2
            continue
        length = int.from_bytes(data[at + 2:at + 4], "big")
        if 0xC0 <= marker <= 0xCF and marker not in (0xC4, 0xC8, 0xCC):
            body = data[at + 4:at + 2 + length]
            if length < 8 or len(body) < 6:
                return None
            return int.from_bytes(body[1:3], "big"), int.from_bytes(body[3:5], "big"), body[5]
        at += 2 + length
    return None


# The TIFF codecs whose decoder in Pillow's libtiff was shown to raise on a cut or damaged strip when Pillow reads the page strip by
# strip (LZW, PackBits): their pages need no walk of their own, in the photometric interpretations that keep
# Pillow off libtiff's RGBA interface. Every other codec but none (1) and JPEG (7), which the walk takes, is counted as not walked:
# CCITT (2, 3, 4) fills a damaged strip and says nothing.
TIFF_CODECS_THAT_RAISE = (5, 32773)
# Deflate (8, 32946) is not on the list: libtiff stops when its output buffer is full, and the zero bits of a zeroed tail decode as symbols of a
# dynamic Huffman block, so a page whose tail was overwritten is decoded as noise with nothing on stderr. It is counted as not walked.
TIFF_SAMPLES_OF = {0: 1, 1: 1, 2: 3, 3: 1, 5: 4, 6: 3}      # the samples a photometric interpretation needs: no extra sample is walked
TIFF_PHOTOMETRIC_STRIP_BY_STRIP = (0, 1, 2, 3)      # grey (either way), RGB, palette: not YCbCr (6), which Pillow reads through RGBA
TIFF_PHOTOMETRIC_UNCOMPRESSED = (0, 1, 2, 3, 5)     # Pillow's own decoder, the bytes of whose rows the walk counts (5: CMYK)
TIFF_PHOTOMETRIC_JPEG = (0, 1, 2, 6)                # libjpeg's frame of one plane, YCbCr given back as RGB by libjpeg itself
TIFF_STRIP_TAGS, TIFF_TILE_TAGS = (273, 278, 279), (322, 323, 324, 325)


def tiff_check(data, pages, tick, budget):
    """The tool's own walk of the strips and tiles of a TIFF's first `pages` pages (see above). Returns None when every page is of a
    shape the walk takes and every strip and tile Pillow reads holds what its rows need, or a sentence saying where one does not.
    JpegUnchecked for every page of a shape the allowlist does not hold (old-style JPEG, another codec, a photometric interpretation
    that sends Pillow to libtiff's RGBA interface, a tag named twice, strip and tile tags together, a directory it cannot follow, a
    JPEG coding the JPEG walk does not take) and when `budget()` (seconds the walk may still take) runs out; tick() reads the clock."""
    for page, (tags, twice) in enumerate(_tiff_pages(data, pages, tick), 1):
        if twice:
            raise JpegUnchecked("page %d names tag%s %s more than once in its directory (Pillow reads the last copy, libtiff the first); "
                                "the walk does not take it" % (page, "s" if len(twice) > 1 else "", ", ".join(str(t) for t in twice[:8])))
        for tag in TIFF_SINGLE_TAGS:
            if tag in tags and len(tags[tag]) != 1:
                raise JpegUnchecked("page %d gives tag %d %d values where it takes one; the walk does not take it" % (page, tag, len(tags[tag])))
        compression = (tags.get(259) or [1])[0]
        photometric = (tags.get(262) or [0])[0]
        planar = (tags.get(284) or [1])[0]
        if planar != 1:
            # Pillow takes each separate plane's mode from one character of the page's mode ("RGB;16B" gives "R", "G", "B"; "L;I" gives "L";
            # a bit-reversed "L;R" gives "L"): a plane loses its width, its inversion or its bit order, with no error and nothing on stderr.
            raise JpegUnchecked("page %d is in separate planes (PlanarConfiguration %d); Pillow reads each plane without the page's "
                                "inversion, bit order or sample width; the walk does not take it" % (page, planar))
        depths, samples = tags.get(258) or [1], (tags.get(277) or [1])[0]
        if len(depths) != samples or any(depth != depths[0] for depth in depths) or depths[0] not in (1, 2, 4, 8):
            # Pillow's converters clip a 16-, 12- or 32-bit grey sample above 255 to 255 (a page of scanner values reads as white), take 16-bit
            # WhiteIsZero without inverting it, and treat a count of depths that is not the count of samples in its own way.
            raise JpegUnchecked("page %d has %d sample(s) of depths %s; the walk takes pages whose samples are all 1, 2, 4 or 8 bits" % (
                page, samples, "/".join(str(depth) for depth in depths[:8])))
        if samples != TIFF_SAMPLES_OF.get(photometric):
            # More samples than the interpretation needs are extra samples: Pillow takes a fourth sample of an RGB page for alpha when ExtraSamples is
            # missing (and flattens the picture on white), libtiff takes it as undefined and the picture as opaque.
            raise JpegUnchecked("page %d has %d sample(s) in photometric interpretation %d, which needs %s; the walk does not take it" % (
                page, samples, photometric, TIFF_SAMPLES_OF.get(photometric, "no number it takes")))
        if any(value != 1 for value in tags.get(339, [1])):
            # SampleFormat 2 (signed), 3 (floating point) or 4 (undefined): Pillow's mode table reads the bytes as unsigned integers.
            raise JpegUnchecked("page %d has a SampleFormat other than unsigned integer; Pillow reads those bytes as unsigned integers; the "
                                "walk does not take it" % page)
        stripped, tiled = any(t in tags for t in TIFF_STRIP_TAGS), any(t in tags for t in TIFF_TILE_TAGS)
        if stripped and tiled:
            raise JpegUnchecked("page %d holds both strip and tile tags (Pillow's decoder and libtiff may read different ones); the walk "
                                "does not take it" % page)
        if compression == 6:
            raise JpegUnchecked("page %d is coded as old-style JPEG (TIFF compression 6), whose data the walk does not take" % page)
        if compression in TIFF_CODECS_THAT_RAISE:
            if photometric not in TIFF_PHOTOMETRIC_STRIP_BY_STRIP:
                raise JpegUnchecked("page %d is coded with TIFF compression %d in photometric interpretation %d, which Pillow reads through "
                                    "libtiff's RGBA interface; that fills a strip that does not decode and only prints; the walk does not "
                                    "take it" % (page, compression, photometric))
            continue
        if compression not in (1, 7):
            raise JpegUnchecked("page %d is coded with TIFF compression %d, whose decoder may fill a cut strip and only warn; the walk does "
                                "not take it" % (page, compression))
        if photometric not in (TIFF_PHOTOMETRIC_UNCOMPRESSED if compression == 1 else TIFF_PHOTOMETRIC_JPEG) or (compression == 7 and planar != 1):
            raise JpegUnchecked("page %d is coded with TIFF compression %d in photometric interpretation %d%s, which the walk does not "
                                "take" % (page, compression, photometric, "" if planar == 1 else " in separate planes"))
        what = "tile" if tiled else "strip"
        offsets, counts = tags.get(324 if tiled else 273), tags.get(325 if tiled else 279)
        if not offsets or counts is None or len(offsets) != len(counts):
            raise JpegUnchecked("page %d: its %s offsets and byte counts do not pair" % (page, what))
        if compression == 1:
            need, read = _tiff_needs(tags, tiled, len(offsets))
            for k in read:
                if k % 1024 == 0:
                    tick()
                if counts[k] < need(k):
                    return ("page %d, %s %d of uncompressed data: its byte count is %d and its rows need %d (Pillow reads them from the "
                            "file at its offset all the same)" % (page, what, k + 1, counts[k], need(k)))
            continue
        width, height, samples = (tags.get(256) or [0])[0], (tags.get(257) or [0])[0], (tags.get(277) or [1])[0]
        if tiled:
            across, down = (tags.get(322) or [0])[0], (tags.get(323) or [0])[0]
        else:
            across, down = width, min(height, (tags.get(278) or [height])[0])
        if not width or not height or not across or not down:
            raise JpegUnchecked("page %d: a JPEG page whose size, strips or tiles are not given" % page)
        per_row = -(-width // across)
        expected = per_row * -(-height // down)
        if len(offsets) != expected:
            raise JpegUnchecked("page %d holds %d %ss of JPEG data where its size needs %d; the walk does not take it" % (page, len(offsets), what, expected))
        tables = tags.get(347)
        if tables is not None and (tables[:2] != b"\xff\xd8" or tables[-2:] != b"\xff\xd9"):
            raise JpegUnchecked("page %d: its JPEGTables are not a JPEG of tables (start and end markers)" % page)
        for k, (start, length) in enumerate(zip(offsets, counts)):
            tick()
            if budget() <= 0:
                raise JpegUnchecked("the walk's share of the clock ran out at page %d, %s %d" % (page, what, k + 1))
            if length == 0 or start + length > len(data):
                return "page %d, %s %d of JPEG data: it is not in the file (byte count %d at byte %d)" % (page, what, k + 1, length, start)
            piece = data[start:start + length]
            if piece[:2] != b"\xff\xd8":
                raise JpegUnchecked("page %d, %s %d of JPEG data does not begin with a start-of-image marker" % (page, what, k + 1))
            stream = tables[:-2] + piece[2:] if tables else piece
            frame = _jpeg_frame(stream)
            if frame is None:
                raise JpegUnchecked("page %d, %s %d of JPEG data: no frame header before its first scan" % (page, what, k + 1))
            rows = down if tiled else min(down, height - (k // per_row) * down)
            if frame != (rows, across, samples):
                if frame[1:] == (across, samples) and 0 < frame[0] < rows:
                    return ("page %d, %s %d of JPEG data: its frame is %d rows high where the %s is %d (libtiff leaves the rows it lacks "
                            "unwritten)" % (page, what, k + 1, frame[0], what, rows))
                raise JpegUnchecked("page %d, %s %d of JPEG data: its frame is %d x %d pixels of %d component(s) where the %s is %d x %d of "
                                    "%d sample(s); the walk does not take it" % (page, what, k + 1, frame[1], frame[0], frame[2], what, across, rows, samples))
            try:
                found = jpeg_check(stream, tick, budget)
            except JpegUnchecked as exc:
                raise JpegUnchecked("page %d, %s %d of JPEG data: %s" % (page, what, k + 1, exc))
            if found is not None:
                return "page %d, %s %d of JPEG data: %s" % (page, what, k + 1, found)
    return None


# ---- the tool's own measure of a PNG's image data ----------------------------------------------------------------------------------
# Pillow takes a zlib stream that ends before the rows do as the end of the picture and fills the rows it did not get, and says nothing.
# So every PNG handed to Pillow, whatever the built-in reader said of it, has its image data measured here, as Pillow reads it: the
# header's first 13 bytes (Pillow takes a longer header chunk), the run of IDAT chunks that begins at the first one (Pillow reads no
# IDAT after another chunk), and each animation frame's run of fdAT chunks after its fcTL. The data is inflated a piece at a time and
# dropped, never held.
PNG_CHANNELS = {0: 1, 2: 3, 3: 1, 4: 2, 6: 4}
PNG_DEPTHS = {0: (1, 2, 4, 8, 16), 2: (8, 16), 3: (1, 2, 4, 8), 4: (8, 16), 6: (8, 16)}


def _png_data_length(width, height, channels, depth, interlace):
    """The bytes a PNG image of this size and form inflates to: its rows, each with its filter byte, or the rows of its seven passes."""
    if not interlace:
        return height * (1 + (width * channels * depth + 7) // 8)
    want = 0
    for x0, y0, dx, dy in ((0, 0, 8, 8), (4, 0, 8, 8), (0, 4, 4, 8), (2, 0, 4, 4), (0, 2, 2, 4), (1, 0, 2, 2), (0, 1, 1, 2)):
        pass_width, pass_height = (width - x0 + dx - 1) // dx, (height - y0 + dy - 1) // dy
        if pass_width > 0 and pass_height > 0:
            want += pass_height * (1 + (pass_width * channels * depth + 7) // 8)
    return want


def png_check(data, pages, tick, budget):
    """The tool's own measure of a PNG's image data (see above), and of the data of up to `pages` animation frames after it. Returns None
    when each inflates to every byte its rows need, or a sentence saying which does not. JpegUnchecked for chunks that cannot be walked
    as Pillow reads them, and when `budget()` runs out; tick() reads the tool's clock."""
    def check():
        tick()
        if budget() <= 0:
            raise JpegUnchecked("the measure's share of the clock ran out")

    at, size, header, image, closed, frames, previous, chunks = 8, len(data), None, None, False, [], None, 0
    while at + 8 <= size:
        chunks += 1
        if chunks % 1024 == 0:
            check()
        length = int.from_bytes(data[at:at + 4], "big")
        kind = data[at + 4:at + 8]
        body = data[at + 8:min(size, at + 8 + length)]
        if kind == b"IHDR":
            if header is not None:
                raise JpegUnchecked("a PNG with a second header chunk")
            if length < 13 or len(body) < 13:
                raise JpegUnchecked("a PNG whose header chunk is %d bytes (it takes 13)" % length)
            header = struct.unpack(">IIBBBBB", body[:13])
        elif kind == b"IDAT":
            if image is None:
                image = [body]
            elif not closed:
                image.append(body)
        elif kind == b"fcTL" and image is not None and len(frames) < pages:
            if len(body) < 12:
                raise JpegUnchecked("a PNG whose frame control chunk is cut")
            frames.append((int.from_bytes(body[4:8], "big"), int.from_bytes(body[8:12], "big"), []))
        elif kind == b"fdAT" and frames and previous in (b"fcTL", b"fdAT") and len(body) > 4:
            frames[-1][2].append(body[4:])
        elif kind == b"IEND":
            break
        if image is not None and kind != b"IDAT":
            closed = True
        previous = kind
        at += 12 + length
    if header is None or image is None:
        raise JpegUnchecked("a PNG with no header or no image data before its end")
    width, height, depth, colour, _compression, _filter, interlace = header
    channels = PNG_CHANNELS.get(colour)
    if channels is None or depth not in PNG_DEPTHS[colour] or not 0 < width * height <= MAX_PIXELS:
        raise JpegUnchecked("a PNG of %d x %d pixels, colour type %d at %d bits, which the measure does not take" % (width, height, colour, depth))
    try:
        want = _png_data_length(width, height, channels, depth, interlace)
        got = _inflated_length(image, want, check)
        if got < want:
            return "its image data (IDAT) inflates to %d of the %d bytes its rows need" % (got, want)
        for number, (frame_width, frame_height, parts) in enumerate(frames, 1):
            if not 0 < frame_width * frame_height <= MAX_PIXELS:
                raise JpegUnchecked("animation frame %d after the image data is %d x %d pixels, which the measure does not take" % (number, frame_width, frame_height))
            want = _png_data_length(frame_width, frame_height, channels, depth, interlace)
            got = _inflated_length(parts, want, check)
            if got < want:
                return "animation frame %d after the image data (fdAT) inflates to %d of the %d bytes its rows need" % (number, got, want)
    except NotAPicture as exc:
        return str(exc)
    return None


def walk_coded_data(data, picture, tick, pages):
    """The tool's own walk of a picture Pillow decoded, for the formats whose decoder fills a cut picture and says nothing: a JPEG's coded
    data (its first picture), a TIFF's strips and tiles (its first `pages` pages) and a PNG's image data (and its first `pages` animation
    frames'). It sets picture.damage and picture.damage_by when the walk finds the data cut or corrupt, picture.unchecked when the walk
    does not reach it; a picture of another format (GIF, BMP, WebP: their decoders raise on data cut short) is left as it is. The walk
    takes at most JPEG_CHECK_SECONDS and half of what the clock has left."""
    if data[:2] == b"\xff\xd8":
        walk, by = jpeg_check, "the tool's own walk of the JPEG's coded data"
    elif data[:4] in TIFF_MAGICS:
        walk, by = (lambda whole, read_clock, left: tiff_check(whole, pages, read_clock, left)), "the tool's own walk of the TIFF's strips and tiles"
    elif data[:8] == PNG_MAGIC:
        walk, by = (lambda whole, read_clock, left: png_check(whole, pages, read_clock, left)), "the tool's own measure of the PNG's image data"
    else:
        return
    until = time.monotonic() + min(JPEG_CHECK_SECONDS, max(0.5, (clock_deadline() - time.monotonic()) / 2.0 if clock_deadline() is not None else JPEG_CHECK_SECONDS))
    try:
        found = walk(data, tick or (lambda: None), lambda: until - time.monotonic())
    except JpegUnchecked as exc:
        picture.unchecked = str(exc)
    else:
        if found is not None:
            picture.damage, picture.damage_by = found, by


def _send(fd, kind, body=b""):
    for part in (kind + len(body).to_bytes(4, "big"), body):
        view = memoryview(part)
        while len(view):
            view = view[os.write(fd, view[:1 << 20]):]


def _bound_decoder(parent):
    deadline = clock_deadline()
    if deadline is not None:
        cpu = int(max(1.0, deadline - time.monotonic())) + 2
        try:
            _resource.setrlimit(_resource.RLIMIT_CPU, (cpu, cpu + 1))
        except (ValueError, OSError, AttributeError):
            pass
    if sys.platform.startswith("linux"):
        try:
            with open("/proc/self/status", "rb") as status:
                size = next(int(line.split()[1]) for line in status if line.startswith(b"VmSize:")) * 1024
            _hard = _resource.getrlimit(_resource.RLIMIT_AS)[1]
            limit = size + DECODE_MEMORY
            _resource.setrlimit(_resource.RLIMIT_AS, (limit if _hard == _resource.RLIM_INFINITY else min(limit, _hard), _hard))
        except Exception:  # noqa: BLE001 - the clock still bounds the child
            pass
        try:
            import ctypes
            ctypes.CDLL(None).prctl(1, signal.SIGKILL)       # PR_SET_PDEATHSIG: the child dies with the tool
            if os.getppid() != parent:                       # the tool was gone before the request was made (the tool can be pid 1)
                os._exit(1)
        except Exception:  # noqa: BLE001
            pass


def _decode_frames(data, image_module, fd, frames):
    import io
    k = 0
    with warnings.catch_warnings():
        warnings.simplefilter("error")         # a decompression-bomb warning is an error, as in the tool
        try:
            image = image_module.open(io.BytesIO(data), formats=PILLOW_FORMATS)
        except Exception as exc:  # noqa: BLE001 - the class is sent, never the message
            _send(fd, b"U" if type(exc).__name__ == "UnidentifiedImageError" else b"X", json.dumps({"frame": 0, "class": type(exc).__name__}).encode("ascii"))
            return
        try:
            while True:
                width, height = image.size
                _send(fd, b"H", struct.pack(">II", width, height))
                if width * height > MAX_PIXELS or height > MAX_ROWS:
                    return                     # the tool refuses it by the size it was sent
                image.load()
                frame = image
                if frame.mode in ("RGBA", "LA", "PA") or "transparency" in frame.info:
                    frame = frame.convert("RGBA")
                    flat = image_module.new("RGB", frame.size, (255, 255, 255))
                    flat.paste(frame, mask=frame.split()[3])
                    frame = flat
                _send(fd, b"F", frame.convert("L").tobytes())
                k += 1
                try:
                    image.seek(k)
                except EOFError:
                    _send(fd, b"E", struct.pack(">I", k))
                    return
                if k >= frames:
                    _send(fd, b"M", struct.pack(">I", k))
                    return
        except Exception as exc:  # noqa: BLE001 - the class is sent, never the message
            _send(fd, b"X", json.dumps({"frame": k, "class": type(exc).__name__}).encode("ascii"))


def _decoder_child(data, image_module, fd, frames, parent, said_fd):
    """The forked child: it never returns. Its standard error is `said_fd`, the pipe on which the tool reads what libtiff, libjpeg and
    zlib print there; its standard input and output are /dev/null."""
    code = 0
    try:
        for signum in (signal.SIGTERM, signal.SIGINT, signal.SIGHUP):
            signal.signal(signum, signal.SIG_DFL)
        try:
            signal.pthread_sigmask(signal.SIG_SETMASK, set())
        except (AttributeError, ValueError, OSError):
            pass
        null = os.open(os.devnull, os.O_RDWR)
        for target in (0, 1):
            os.dup2(null, target)
        os.dup2(said_fd, 2)
        _bound_decoder(parent)
        _decode_frames(data, image_module, fd, frames)
    except BaseException as exc:  # noqa: BLE001 - nothing may return into the tool's own code
        try:
            _send(fd, b"X", json.dumps({"frame": None, "class": type(exc).__name__}).encode("ascii"))
        except BaseException:  # noqa: BLE001
            code = 1
    finally:
        os._exit(code)


class PillowFrames:
    """The frames of one picture as Pillow decodes them in a child. next_frame() is the next frame as a Picture, or None when there is no
    other: then `total` is how many frames the picture has, or `more` is True when it has more than were asked for. NotAPicture when
    Pillow does not read it (or a frame of it), Clock when the clock runs out first; either way the child is ended. `check(width, height)`
    may refuse a frame by its size before its rows are taken. close() ends the child. The child's standard error is read as its frames
    are: a frame before whose rows the child printed a line there (a decoder's warning or error) comes with that line in its `damage`."""

    def __init__(self, data, image_module, frames, check=None):
        self.total, self.more, self.check, self.k, self.buf, self.pid, self.fd = None, False, check, 0, bytearray(), None, None
        self.said, self.said_fd, self.said_dropped, self.said_seen, self.said_dropped_seen = bytearray(), None, 0, 0, 0
        said_read, said_write = os.pipe()
        try:
            read_fd, write_fd = os.pipe()
        except OSError:
            os.close(said_read)
            os.close(said_write)
            raise
        stops = (signal.SIGTERM, signal.SIGINT, signal.SIGHUP)
        try:
            before = signal.pthread_sigmask(signal.SIG_BLOCK, stops)   # a stop between the fork and the child's own handlers waits
        except (AttributeError, ValueError, OSError):
            before = None
        parent = os.getpid()
        try:
            pid = os.fork()
        except OSError as exc:
            for end in (read_fd, write_fd, said_read, said_write):
                os.close(end)
            if before is not None:
                signal.pthread_sigmask(signal.SIG_SETMASK, before)
            raise NotAPicture("Pillow decodes in a child process here, and none could be started (%s)" % describe(exc))
        if pid == 0:
            os.close(read_fd)
            os.close(said_read)
            _decoder_child(data, image_module, write_fd, frames, parent, said_write)
        DECODER["pid"] = self.pid = pid
        os.close(write_fd)
        os.close(said_write)
        self.fd, self.said_fd = read_fd, said_read
        if before is not None:
            signal.pthread_sigmask(signal.SIG_SETMASK, before)

    def close(self, kill=True):
        """End the child (kill, or wait up to a second for one that has said its last) and reap it: its wait status, or None."""
        status, pid, self.pid = None, self.pid, None
        if pid:
            if DECODER["pid"] == pid:
                DECODER["pid"] = None
            try:
                if not kill:
                    for _wait in range(100):
                        done, status = os.waitpid(pid, os.WNOHANG)
                        if done:
                            break
                        time.sleep(0.01)
                    else:
                        kill = True
                if kill:
                    try:
                        os.kill(pid, signal.SIGKILL)
                    except OSError:
                        pass
                    _done, status = os.waitpid(pid, 0)
            except OSError:
                pass
        if self.fd is not None:
            os.close(self.fd)
            self.fd = None
        if self.said_fd is not None:
            os.close(self.said_fd)
            self.said_fd = None
        return status

    def _read_said(self):
        """Read once from the child's standard error: the first DECODER_SAID_BYTES are kept, the rest counted and dropped."""
        block = os.read(self.said_fd, 1 << 16)
        if not block:
            os.close(self.said_fd)
            self.said_fd = None
            return
        room = max(0, DECODER_SAID_BYTES - len(self.said))
        self.said += block[:room]
        self.said_dropped += len(block) - min(room, len(block))

    def _decoder_said(self):
        """What the child printed on its standard error since the last call, read to what is there now: (lines, first line), or None
        when it printed nothing but notes on tags libtiff does not know. The child writes there before it sends the frame's rows, so
        what it printed while it decoded a frame is there when the rows have come."""
        for _read in range(256):
            if self.said_fd is None or not _decode_select.select([self.said_fd], [], [], 0)[0]:
                break
            self._read_said()
        text, self.said_seen = bytes(self.said[self.said_seen:]), len(self.said)
        dropped, self.said_dropped_seen = self.said_dropped - self.said_dropped_seen, self.said_dropped
        lines = [line.strip() for line in text.splitlines() if line.strip() and not any(quiet in line for quiet in DECODER_QUIET)]
        if dropped:
            lines.append(b"(%d more bytes past the %d kept)" % (dropped, DECODER_SAID_BYTES))
        if not lines:
            return None
        return len(lines), printable(lines[0].decode("utf-8", "replace"))

    def _fill(self, need):
        while len(self.buf) < need:
            deadline = clock_deadline()
            wait = 1.0 if deadline is None else deadline - time.monotonic()
            if wait <= 0:
                raise Clock()
            watched = [self.fd] if self.said_fd is None else [self.fd, self.said_fd]
            ready = _decode_select.select(watched, [], [], min(wait, 1.0))[0]
            if self.said_fd is not None and self.said_fd in ready:
                self._read_said()
            if self.fd not in ready:
                continue
            block = os.read(self.fd, max(1 << 16, min(need - len(self.buf), 1 << 22)))
            if not block:
                return False
            self.buf += block
        return True

    def _ended(self):
        status = self.close(kill=False)
        if status is not None and os.WIFSIGNALED(status):
            return ("Pillow's decoding process was ended by signal %d before it answered (past its bound of memory or of CPU time, or a "
                    "fault in a decoder)" % os.WTERMSIG(status))
        return "Pillow's decoding process ended without an answer (exit code %s)" % (os.WEXITSTATUS(status) if status is not None and os.WIFEXITED(status) else "unknown")

    def _message(self):
        if not self._fill(5):
            raise NotAPicture(self._ended())
        kind, length = bytes(self.buf[:1]), int.from_bytes(self.buf[1:5], "big")
        if length > MAX_PIXELS + 4096 or not self._fill(5 + length):
            raise NotAPicture(self._ended())
        body = bytes(self.buf[5:5 + length])
        del self.buf[:5 + length]
        return kind, body

    def _refusal(self, kind, body):
        try:
            said = json.loads(body.decode("ascii"))
            frame, name = said.get("frame"), str(said.get("class"))[:80]
        except (ValueError, UnicodeDecodeError, AttributeError):
            frame, name = None, "an unreadable report"
        if kind == b"U":
            return "Pillow does not read it as a picture of the formats this tool hands it (%s: %s)" % (PILLOW_FORMAT_NAMES, name)
        if frame:
            return "Pillow does not read frame %d (%s)" % (frame + 1, name)
        return "Pillow does not read it as a picture (%s)" % name

    def next_frame(self):
        if self.total is not None or self.more or self.pid is None:
            return None
        try:
            kind, body = self._message()
            if kind in (b"E", b"M"):
                if kind == b"E":
                    self.total = int.from_bytes(body, "big")
                else:
                    self.more = True
                self.close(kill=False)
                return None
            if kind != b"H" or len(body) != 8:
                raise NotAPicture(self._refusal(kind, body) if kind in (b"U", b"X") else "Pillow's decoding process sent what it should not")
            width, height = struct.unpack(">II", body)
            what = "frame %d is" % (self.k + 1) if self.k else "a picture of"
            if width * height > MAX_PIXELS or width == 0 or height == 0:
                raise NotAPicture("%s %d x %d pixels (this tool reads up to %d pixels)" % (what, width, height, MAX_PIXELS))
            if height > MAX_ROWS:
                raise NotAPicture("%s %d x %d pixels (this tool reads up to %d rows)" % (what, width, height, MAX_ROWS))
            if self.check is not None:
                self.check(width, height)
            kind, body = self._message()
            if kind != b"F" or len(body) != width * height:
                raise NotAPicture(self._refusal(kind, body) if kind in (b"U", b"X") else "Pillow's decoding process sent what it should not")
            self.k += 1
            gray = [body[y * width:(y + 1) * width] for y in range(height)]
            picture = Picture(width, height, gray, None, "Pillow %s" % _PILLOW.get("version", "?"))
            said = self._decoder_said()
            if said is not None:
                picture.damage = "frame %d: it printed %d line(s) on its standard error while it decoded, the first: %s" % (self.k, said[0], said[1])
                picture.damage_by = DECODER_SAID_BY
            return picture
        except BaseException:
            self.close()
            raise


def read_picture(data, want_rgb=False, reader="auto", tick=None, frames=MAX_FRAMES):
    """The picture in `data`: a PNG by the built-in reader when it reads it (or when reader is "builtin"), anything else, a PNG the
    built-in reader refuses and an animated PNG, by Pillow in a child when it imports. NotAPicture says which reader said what; Clock
    when the clock runs out first. A PNG the built-in reader found cut or corrupt and Pillow read all the same carries that finding in
    `damage`: Pillow fills what is missing; so does what walk_coded_data finds, and what Pillow's decoder printed on its standard error
    while it decoded the first frame. A picture Pillow read carries `stream`, which gives up to `frames` frames in all (each with what
    the decoder printed while it decoded it in its `damage`), and which the caller closes. Pillow's frames are grey only (want_rgb is for the built-in reader)."""
    first = damage = builtin = None
    if data[:8] == PNG_MAGIC or reader == "builtin":
        try:
            builtin = read_png(data, want_rgb, tick)
            if builtin.frames == 1 or reader == "builtin" or pillow() is None:
                return builtin
            damage = builtin.later_damage
        except NotAPicture as exc:
            first = str(exc)
            damage = first if exc.damaged else None
            if reader == "builtin":
                raise
    image_module = pillow() if reader != "builtin" else None
    if image_module is None:
        raise NotAPicture(first or "not a PNG, and Pillow, which reads the other picture formats, does not import here")
    said = "the built-in reader: %s; " % first if first else ""
    scans = jpeg_scans(data)
    if scans > MAX_JPEG_SCANS:
        raise NotAPicture("%sa JPEG of %d scans (start-of-scan markers): this tool hands Pillow a JPEG of up to %d (a picture has one, a "
                          "progressive one about ten)" % (said, scans, MAX_JPEG_SCANS), damaged=damage is not None)
    stream = PillowFrames(data, image_module, frames)
    try:
        picture = stream.next_frame()
        if picture is None:
            raise NotAPicture("Pillow found no frame in it")
    except NotAPicture as exc:
        stream.close()
        if builtin is not None:
            return builtin                  # an animated PNG Pillow does not read: its default image, and frames_why says the rest
        raise NotAPicture("%s%s" % (said, exc), damaged=damage is not None)
    except BaseException:
        stream.close()
        raise
    if damage is not None:
        picture.damage, picture.damage_by = damage, "the built-in reader"
    picture.stream = stream
    picture.jpeg = data[:2] == b"\xff\xd8"
    if picture.damage is None:
        try:
            walk_coded_data(data, picture, tick, frames)
        except BaseException:
            stream.close()
            raise
    return picture


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
    counts = collections.Counter()
    for row in gray_rows[::step]:
        for first in range(0, len(row), SPAN * 16):       # a wide row is counted a megabyte at a time, the clock read before each
            if tick:
                tick()
            counts.update(row[first:first + SPAN * 16])
    for value, count in counts.items():
        histogram[value] = count
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
    return place_symbol(stream, version, level, mask)


def place_symbol(stream, version, level, mask, remainder=0):
    """The modules of a symbol from its interleaved codewords: the fixed patterns, the codewords masked in their order, the format word
    and (version 7 and above) the version word. The remainder bits after the last codeword take `remainder` (None: not known)."""
    n = 17 + 4 * version
    known, _reserved = function_modules(version)
    grid = [[0] * n for _ in range(n)]
    for (r, c), value in known.items():
        grid[r][c] = value
    order = data_order(version)
    test = MASKS[mask]
    for index, (r, c) in enumerate(order):
        if index >> 3 < len(stream):
            grid[r][c] = ((stream[index >> 3] >> (7 - (index & 7))) & 1) ^ (1 if test(r, c) else 0)
        else:
            grid[r][c] = None if remainder is None else remainder ^ (1 if test(r, c) else 0)
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
            position, _parity = reader.take(8), reader.take(8)
            notes.append("structured append: symbol %d of %d: the message goes on in other symbols (its parity byte, a digest of the whole "
                         "message, is not printed)" % ((position >> 4) + 1, (position & 15) + 1))
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
    data, corrected, clean, whole = [], 0, 0, []
    for b, (d, e) in enumerate(layout):
        fixed, errors = rs_correct(blocks[b], e)
        if fixed is None:
            return None, "Reed-Solomon block %d of %d has more errors than its %d check codewords correct" % (b + 1, len(layout), e)
        corrected += errors
        clean += 1 if errors == 0 else 0
        data += fixed[:d]
        whole.append(fixed)
    try:
        payload, segments, notes = read_segments(data, version)
    except ValueError as exc:
        return None, "the corrected codewords are not a data stream (%s)" % exc
    stream = []                                   # the corrected codewords, interleaved again as they are placed
    for i in range(max(d for d, _e in layout)):
        stream += [whole[b][i] for b, (d, _e) in enumerate(layout) if i < d]
    for i in range(layout[0][1]):
        stream += [whole[b][d + i] for b, (d, _e) in enumerate(layout)]
    return {"payload": payload, "segments": segments, "notes": notes, "errors_corrected": corrected, "blocks": len(layout), "blocks_clean": clean,
            "codewords": stream}, None


def expected_modules(result):
    """The modules the decoded symbol has: its corrected codewords placed again under its format (remainder bits None: not known)."""
    return place_symbol(result["codewords"], result["version"], result["level"], result["mask"], remainder=None)


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
            # Every one of the 32 is tried, and the strongest level that decodes is taken: where two levels of a version have blocks of the
            # same lengths (version 1 at every level, version 6 at M, Q and H, ...), a codeword of the stronger level is a codeword of the
            # weaker one too, which then decodes with no error and the wrong split between data and check codewords.
            decoded = []
            for data5 in range(32):
                level, mask = LEVEL_OF_BITS[data5 >> 3], data5 & 7
                if (level, mask) in seen:
                    continue
                tick()
                stats["reed_solomon_attempts"] = stats.get("reed_solomon_attempts", 0) + 1
                result, _why = decode_modules(turned, version, level, mask)
                check = sum(e for _d, e in block_layout(version, level))
                if result is not None and result["errors_corrected"] * 4 <= check:
                    decoded.append((check, -result["errors_corrected"], -data5, level, mask, result))
            if decoded:
                _check, _errors, _order, level, mask, result = max(decoded, key=lambda d: d[:3])
                agree, known = function_agreement(turned, version)
                result.update({"version": version, "level": level, "mask": mask, "orientation": name, "modules": turned,
                               "format": {"read_from": "neither copy (both were more than 3 bits from every format word)", "bits_corrected": None,
                                          "by": "each of the 32 format words tried, Reed-Solomon deciding (the strongest level that decodes)",
                                          "formats_that_decoded": len(decoded)},
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
    """Along one line of 0 and 1 (a row, or a column as bytes), the finder pattern through `centre`: (middle, total length) or None. The
    runs are walked by find and rfind, so a run of millions of pixels costs no Python loop."""
    n = len(line)
    centre = int(centre)
    if not 0 <= centre < n or line[centre] != 1:
        return None
    lengths = [0] * 5
    i = line.rfind(b"\x00", 0, centre + 1)           # the first light pixel left of the dark core (or -1)
    lengths[2] = centre - i
    start_core = i + 1
    for k, other in ((1, b"\x01"), (0, b"\x00")):
        j = line.rfind(other, 0, i + 1) if i >= 0 else -1
        lengths[k] = i - j
        i = j
    left = i + 1
    i = line.find(b"\x00", centre + 1)
    i = n if i < 0 else i
    lengths[2] += i - centre - 1
    end_core = i
    for k, other in ((3, b"\x01"), (4, b"\x00")):
        j = line.find(other, i) if i < n else -1
        j = n if j < 0 else j
        lengths[k] = j - i
        i = j
    if min(lengths) == 0 or _ratio(lengths) is None:
        return None
    return (start_core + end_core) / 2.0, i - left


def find_finders(binary, width, height):
    """Finder-pattern candidates: [(x, y, module size, rows that saw it)], the most seen first. A row is scanned for five runs in the
    ratio 1:1:3:1:1, the column through its middle must show the same, and the row through that column's middle again. A row's runs are
    walked through a window of five (never a list of them all: a row can be 36,000,000 runs), the clock read every 4096 runs."""
    flat = b"".join(binary)
    found = []
    step = max(1, height // 1500)
    for y in range(0, height, step):
        if y % 64 == 0:
            tick()
        row = binary[y]
        if 1 not in row:
            continue
        window = collections.deque(maxlen=5)
        for seen, m in enumerate(RUNS.finditer(row), 1):
            if seen % 4096 == 0:
                tick()
            window.append((m.start(), m.end() - m.start()))
            if len(window) < 5 or row[window[0][0]] != 1:
                continue
            lengths = [w[1] for w in window]
            if _ratio(lengths) is None:
                continue
            tick()
            cx = window[2][0] + window[2][1] / 2.0
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
    whose 5 x 5 neighbourhood agrees best with the pattern (at least 23 of 25). On a clean picture every offset within half a module
    of the true centre agrees fully, so the centre is the middle of the offsets that agree best, not the first of them (which lies
    half a module off and turns a clean symbol into one that needs correcting)."""
    centre = n - 6.5
    steps = [i * 0.25 for i in range(-8, 9)]
    ax, ay = mapping(centre, centre)

    def agreement(x0, y0):
        agree = 0
        for r in range(-2, 3):
            for c in range(-2, 3):
                px, py = int(x0 + c * unit), int(y0 + r * unit)
                want = 1 if max(abs(r), abs(c)) != 1 else 0
                if 0 <= px < width and 0 <= py < height and binary[py][px] == want:
                    agree += 1
        return agree

    scored = [(agreement(ax + dx * unit, ay + dy * unit), ax + dx * unit, ay + dy * unit) for dy in steps for dx in steps]
    best = max(s[0] for s in scored)
    if best < 23:
        return None
    plateau = [(x, y) for agree, x, y in scored if agree == best]
    mx, my = sum(p[0] for p in plateau) / len(plateau), sum(p[1] for p in plateau) / len(plateau)
    if agreement(mx, my) != best:
        return plateau[0]           # two separate plateaus (something like the pattern nearby): the middle is neither, keep the first
    # The plateau is sampled in quarter modules, so its middle can still be a fraction of a module off; the pattern's dark centre module
    # gives the centre to the pixel, as the finders' centres are taken (the middle of the run, its end exclusive).

    def run_middle(line, at):
        if not 0 <= at < len(line) or line[at] != 1:
            return None
        start, end = at, at + 1
        while start > 0 and line[start - 1] == 1:
            start -= 1
        while end < len(line) and line[end] == 1:
            end += 1
        return (start + end) / 2.0 if 0.5 * unit <= end - start <= 1.6 * unit else None

    reach = 3 * int(unit + 1)
    for _round in range(2):
        x, y = int(mx), int(my)
        if not (0 <= x < width and 0 <= y < height):
            break
        across = run_middle(binary[y], x)
        nx = across if across is not None else mx
        top = max(0, y - reach)
        column = bytes(binary[yy][int(nx)] for yy in range(top, min(height, y + reach))) if 0 <= int(nx) < width else b""
        down = run_middle(column, y - top) if column else None
        ny = down + top if down is not None else my
        if agreement(nx, ny) != best:
            break
        mx, my = nx, ny
    return (mx, my)


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
                    result["region"] = region_of(m, n)
                    return result
    return None


def bounds_of(corners):
    """[left, top, right, bottom] in whole pixels round the corners of a symbol read."""
    xs, ys = [c[0] for c in corners], [c[1] for c in corners]
    return [max(0, int(math.floor(min(xs)))), max(0, int(math.floor(min(ys)))), int(math.ceil(max(xs))), int(math.ceil(max(ys)))]


def region_of(mapping, n):
    """The four pixel corners of a symbol of n x n modules under its mapping, half a module out from its edge: what is masked once it
    is read."""
    return [mapping(-0.5, -0.5), mapping(n + 0.5, -0.5), mapping(n + 0.5, n + 0.5), mapping(-0.5, n + 0.5)]


def inside(corners, x, y):
    """Whether the point is inside the convex quadrilateral `corners`."""
    signs = set()
    for (x0, y0), (x1, y1) in zip(corners, corners[1:] + corners[:1]):
        cross = (x1 - x0) * (y - y0) - (y1 - y0) * (x - x0)
        if cross:
            signs.add(cross > 0)
    return len(signs) <= 1


def mask_region(binary, width, height, corners):
    """Set light every pixel of `binary` inside the quadrilateral `corners` (a symbol read, and half a module round it), row by row."""
    ys = [c[1] for c in corners]
    top, bottom = max(0, int(math.floor(min(ys)))), min(height - 1, int(math.ceil(max(ys))))
    edges = list(zip(corners, corners[1:] + corners[:1]))
    for y in range(top, bottom + 1):
        if y % 1024 == 0:
            tick()
        xs = []
        for (x0, y0), (x1, y1) in edges:
            if min(y0, y1) <= y + 0.5 <= max(y0, y1):
                xs.append(x0 if y1 == y0 else x0 + (y + 0.5 - y0) * (x1 - x0) / (y1 - y0))
                if y1 == y0:
                    xs.append(x1)
        if not xs:
            continue
        left, right = max(0, int(math.floor(min(xs)))), min(width, int(math.ceil(max(xs))) + 1)
        if right > left:
            row = binary[y]
            binary[y] = row[:left] + bytes(right - left) + row[right:]


def dark_box(binary, width, height):
    """(left, top, right, bottom) of the dark pixels, right and bottom exclusive, or None for a picture with none."""
    top = bottom = None
    left, right = width, 0
    for y, row in enumerate(binary):
        if y % 4096 == 0:
            tick()
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
    counts = collections.Counter()           # the lengths are counted as they come (a row can hold 36,000,000 runs), the clock read between
    flat = b"".join(binary)
    rows = (binary[y][left:right] for y in range(top, bottom, max(1, (bottom - top) // 60)))
    columns = (flat[x::width][top:bottom] for x in range(left, right, max(1, (right - left) // 60)))
    for line in itertools.chain(rows, columns):
        runs = RUNS.finditer(line)
        while True:
            tick()
            piece = [m.end() - m.start() for m in itertools.islice(runs, 1 << 16)]
            if not piece:
                break
            counts.update(piece)
    total = sum(counts.values())
    if total < 8:
        return None
    tick()
    largest = min(max(counts), min(right - left, bottom - top))
    size = float(largest)
    while size >= 1.0:
        tick()
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
                        result["region"] = region_of(mapping, n)
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
            result["region"] = region_of(mapping, n)
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


def read_symbol(binary, width, height, mode, stats, box=None, version=None, seen=None):
    """One picture: the standard reading, then (mode auto or repaint) the readings that do not need all three finders. `seen`, a list,
    is given the finder patterns found."""
    finders = find_finders(binary, width, height)
    stats["finder_patterns_found"] = len(finders)
    if seen is not None:
        seen[:] = finders
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
MAX_NODES = 20000                  # steps of the placement search (a piece put in a place, or a whole placement scored)


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
        tick()
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
    first that decodes is the answer. The walk reads the clock at every step and stops at MAX_NODES steps or MAX_LEAVES whole placements.
    Returns (result, tried, cut): tried the best placements that did not decode, cut None or why the search stopped before its end."""
    area = sum(len(p) * len(p[0]) for p in pieces)
    tried = []
    budget = {"leaves": 0, "nodes": 0, "cut": None}
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
                if budget["cut"] is not None:
                    return None
                budget["nodes"] += 1
                stats["search_steps"] = budget["nodes"]
                if budget["nodes"] > MAX_NODES:
                    budget["cut"] = "the placement search stopped at its bound of %d steps (%d whole placements scored)" % (MAX_NODES, budget["leaves"])
                    return None
                tick()
                if depth == len(options):
                    if budget["leaves"] >= MAX_LEAVES:
                        budget["cut"] = "the placement search stopped at its bound of %d whole placements scored" % MAX_LEAVES
                        return None
                    budget["leaves"] += 1
                    stats["placements_scored"] = budget["leaves"]
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
                    check_pieces(result, turned)
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
                    if budget["cut"] is not None:
                        return None
                return None

            result = walk(0)
            if result is not None:
                result["located_by"] = "placement of %d pieces by fixed modules, format word and Reed-Solomon syndromes" % len(pieces)
                return result, tried, None
            if budget["cut"] is not None:
                break
        if budget["cut"] is not None:
            break
    tried.sort(key=lambda t: (t["format_bits_wrong"], -t["blocks_with_zero_syndromes"], t["modules_not_covered"]))
    return None, tried[:5], budget["cut"]


def check_pieces(result, turned):
    """Each placed piece held against the symbol that was decoded (its corrected codewords placed again, with the fixed modules and the
    format word): the modules where the piece says otherwise. A piece of another symbol of the same version and mask agrees on the fixed
    modules and is outvoted by Reed-Solomon in the data, so it is told only here: a piece that contradicts any module is named in
    pieces_contradicting_the_symbol (it is damaged there, or it is not a piece of this symbol), and the answer is partial."""
    expected = expected_modules(result)
    foreign = []
    for placement in result["placements"]:
        piece = turned[placement["piece"]]
        r0, c0 = placement["row"], placement["column"]
        compared = contradicted = 0
        for r, line in enumerate(piece):
            for c, value in enumerate(line):
                want = expected[r0 + r][c0 + c]
                if want is None:
                    continue
                compared += 1
                if want != value:
                    contradicted += 1
        placement["modules_contradicting_the_decoded_symbol"] = contradicted
        placement["modules_compared"] = compared
        if contradicted:
            foreign.append(placement["piece"])
    result["pieces_contradicting_the_symbol"] = foreign


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
        result, _tried, _cut = assemble([pieces[2], pieces[0], pieces[3], pieces[1]], {})
        checks.append({"check": "the same symbol cut into four pieces, given out of order, is placed and read, and the pieces contradict the symbol read in "
                                "exactly the %d flipped modules" % flipped,
                       "passed": result is not None and result["payload"] == planted
                       and sum(p["modules_contradicting_the_decoded_symbol"] for p in result["placements"]) == flipped})
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


def keep(place, row, result, stem, want_repaint):
    """Write the payload (and the repainted symbol) of one result, both mode 0600; the row says where, or why not."""
    try:
        row["payload_file"] = place.write("%s.payload.bin" % stem, result["payload"], 0o600)
        row["payload_in_answer"] = False
        if want_repaint:
            grid, changed = repainted(result)
            side, rows = render(grid, 8, 4)
            row["repainted_file"] = place.write("%s.repainted.png" % stem, png_bytes(side, side, rows), 0o600)
            row["fixed_modules_repainted"] = changed
    except OSError as exc:
        row["write_error"] = "the payload could not be written under the output directory (%s)" % describe(exc)


def load(path, reader, what, frames=MAX_FRAMES):
    data = read_file(path, MAX_IMAGE_BYTES, what)
    picture = read_picture(data, False, reader, tick, frames)
    return picture, hashlib.sha256(data).hexdigest(), len(data)


def looked_for(stats, mode, box=None):
    methods = []
    if box is not None:
        return {"methods": ["the box given cut into the module grid of each version the module size allows (the readings by finder patterns take no box)",
                            "the same grids with each of the 32 format words when neither format copy could be read"],
                "polarities": ["dark on light", "light on dark"], "versions": "1 to %d" % MAX_VERSION, **stats}
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
        if mode in ("finders", "fragments"):
            raise Refused("box goes with mode auto or repaint: the box is read by the repaint reading, and the three-finder reading and the placement of pieces take none")
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
    rows = []
    unread = Unread(*UNREAD)

    def search(picture, stats):
        """One frame, both polarities, every symbol in it: (results, the threshold of the last polarity tried, finder patterns that no
        symbol read explains, whether the bound of MAX_SYMBOLS was reached). A symbol read is masked out (its modules and half a module
        round them set light) and the frame is searched again, until a search reads nothing; then the other polarity, with every symbol
        read masked. With a box, the box's one symbol is read and the search ends."""
        if box is not None and (box[2] > picture.width or box[3] > picture.height):
            raise Refused("box %s reaches past the picture's %d x %d pixels: give the symbol's extent inside it" % (box, picture.width, picture.height))
        results, regions, threshold, capped, left = [], [], None, False, []
        for polarity, threshold_rows in (("dark on light", picture.gray), ("light on dark", None)):
            if threshold_rows is None:
                threshold_rows = [r.translate(INVERT) for r in picture.gray]
            binary, threshold = binarise(threshold_rows, None, tick)
            for region in regions:
                mask_region(binary, picture.width, picture.height, region)
            while True:
                seen = []
                result = read_symbol(binary, picture.width, picture.height, mode, stats, box=box, version=version, seen=seen)
                if result is None:
                    left += seen
                    break
                if len(results) >= MAX_SYMBOLS:
                    capped = True
                    break
                result["polarity"] = polarity
                results.append(result)
                if box is not None:
                    return results, threshold, 0, False
                regions.append(result["region"])
                mask_region(binary, picture.width, picture.height, result["region"])
            if capped:
                break
        # A finder pattern a pass saw and no reading explained counts when it lies outside every symbol read in either polarity.
        unexplained = []
        for f in (left if results else []):
            if not any(inside(r, f[0], f[1]) for r in regions) and not any(abs(f[0] - g[0]) <= 2.5 * g[2] and abs(f[1] - g[1]) <= 2.5 * g[2] for g in unexplained):
                unexplained.append(f)
        return results, threshold, len(unexplained), capped

    def one(path, number):
        row = {"input": printable(path)}
        try:
            picture, digest, size = load(path, reader, "the picture")
        except (Refused, NotAPicture) as exc:
            row.update({"result": "not read", "why": str(exc)})
            unread.add("pictures_not_read", 1, "%s was not read as a picture" % row["input"])
            return row
        row.update({"sha256": digest, "bytes": size, "pixels": "%d x %d" % (picture.width, picture.height), "picture_reader": picture.reader})
        if picture.notes:
            row["picture_notes"] = picture.notes
        if picture.damage:
            row["picture_damaged"] = ("%s found it cut or corrupt (%s); Pillow read it all the same, and what it filled in for "
                                      "the missing part is not the picture's" % (picture.damage_by, picture.damage))
            unread.add("pictures_damaged", 1, "%s is a damaged picture, read only in part (see picture_damaged)" % row["input"])
        jpeg = picture.jpeg
        if picture.unchecked:
            row["jpeg_data_not_walked"] = ("%s: Pillow decoded it, and coded data cut short (a JPEG's given its end marker back, a TIFF "
                                           "strip's or tile's, a PNG's image data) is not told from whole data by Pillow, so a negative here "
                                           "is not one of a whole picture" % picture.unchecked)
            unread.add("jpeg_data_not_walked", 1, "%s: the tool's own walk of the picture's coded data did not reach it (jpeg_data_not_walked)" % row["input"])
        stats, found, searched, frames_not_read, total = {}, [], 0, None, None
        left_frames, capped_frames, later_damage = {}, [], None
        frame = picture
        try:
            while True:
                if searched == 0:
                    try:
                        results, row["threshold"], left, capped = search(picture, stats)
                    except Refused as exc:
                        row.update({"result": "not read", "why": str(exc)})
                        unread.add("pictures_not_read", 1, "%s was not read: %s" % (row["input"], exc))
                        return row
                else:
                    try:
                        results, _threshold, left, capped = search(frame, stats)
                    except Refused as exc:
                        frames_not_read = "frame %d and any after it: %s" % (searched + 1, exc)
                        break
                    except Clock:
                        frames_not_read = "frame %d and any after it: the tool's clock (max_seconds %d) ran out while it was searched" % (searched + 1, seconds)
                        break
                searched += 1
                for index, result in enumerate(results):
                    found.append((searched, index, result))
                if left:
                    left_frames[searched] = left
                if capped:
                    capped_frames.append(searched)
                if picture.stream is None:
                    total = picture.frames
                    if total > 1:
                        frames_not_read = "frames 2 to %d: %s" % (total, picture.frames_why)
                    break
                try:
                    frame = picture.stream.next_frame()
                except NotAPicture as exc:
                    frames_not_read = "frame %d and any after it: %s" % (searched + 1, exc)
                    break
                except Clock:
                    frames_not_read = ("frame %d and any after it (whether the picture has more frames is not known): the tool's clock (max_seconds %d) ran "
                                       "out while it was decoded" % (searched + 1, seconds))
                    break
                if frame is not None and frame.damage and later_damage is None:
                    later_damage = (frame.damage_by, frame.damage)
                if frame is None:
                    if picture.stream.more:
                        frames_not_read = ("frames past the %dth: the picture has more than %d frames, and they were neither counted nor searched (the bound of %d "
                                           "frames a picture)" % (MAX_FRAMES, MAX_FRAMES, MAX_FRAMES))
                    else:
                        total = picture.stream.total
                    break
        finally:
            if picture.stream is not None:
                picture.stream.close()
        if later_damage and not picture.damage:
            row["picture_damaged"] = ("%s found it cut or corrupt (%s); Pillow read it all the same, and what it filled in for "
                                      "the missing part is not the picture's" % later_damage)
            unread.add("pictures_damaged", 1, "%s is a damaged picture, read only in part (see picture_damaged)" % row["input"])
        if total is None:
            row.update({"frames_at_least": searched + (1 if picture.stream is not None and picture.stream.more else 0), "frames_searched": searched})
        elif total > 1:
            row.update({"frames": total, "frames_searched": searched})
        if frames_not_read:
            row["frames_not_read"] = frames_not_read
            unread.add("pictures_with_frames_not_searched", 1, "%s: %s" % (row["input"], frames_not_read))
        if jpeg and searched > 1:
            row["jpeg_frames_not_walked"] = ("frames 2 to %d: the tool's own walk of a JPEG's coded data reads the first picture of the file only, and a "
                                             "later one Pillow decoded (a multi-picture file) may be cut and given its end back unseen" % searched)
            unread.add("jpeg_data_not_walked", searched - 1, "%s: %d frame(s) past the first of a JPEG were searched without the tool's walk of their coded data (jpeg_frames_not_walked)" % (row["input"], searched - 1))
        if left_frames:
            row["finder_patterns_not_read"] = {"count": sum(left_frames.values()), "frames": sorted(left_frames)[:MAX_FRAMES],
                                               "what": "finder patterns (1:1:3:1:1) in a frame from which a symbol was read, outside every symbol read, that no reading made a symbol of: another symbol may be there that these methods do not read"}
            unread.add("finder_patterns_not_read", sum(left_frames.values()), "%s: %d finder pattern(s) outside the symbols read were not read as a symbol (finder_patterns_not_read)" % (row["input"], sum(left_frames.values())))
        if capped_frames:
            row["symbols_past_the_bound"] = {"frames": capped_frames, "what": "a frame held more than %d symbols: the search of it stopped there, and the others were not read" % MAX_SYMBOLS}
            unread.add("frames_past_the_symbol_bound", len(capped_frames), "%s: the search stopped at %d symbols in %d frame(s) (symbols_past_the_bound)" % (row["input"], MAX_SYMBOLS, len(capped_frames)))
        if not found:
            row.update({"result": "not a symbol", "looked_for": looked_for(stats, mode, box),
                        "meaning": "no QR symbol of version 1 to %d was read from this picture%s by these methods; see not_read for what they do not reach"
                        % (MAX_VERSION, "" if total == 1 else " (in the %d frames searched; frames_not_read names any that were not)" % searched)})
            return row
        frame_number, _index, result = found[0]
        row.update(describe_result(result))
        if total != 1:
            row["frame"] = frame_number
        keep(place, row, result, "qr-%02d" % number, mode == "repaint" or "function_patterns" in result)
        row["symbols_decoded"] = len(found)
        others, same, listed_symbols = [], [], []
        for k, index, other in found[1:]:
            if index == 0 and other["payload"] == result["payload"]:
                same.append(k)
                continue
            same_as = None
            if other["payload"] == result["payload"]:
                same_as = (frame_number, 0)
            else:
                same_as = next(((kk, ii) for kk, ii, o, _first in others if o["payload"] == other["payload"]), None)
            others.append((k, index, other, same_as))
        if same:
            row["frames_with_the_same_payload"] = same
        listed_frames = []
        for k, index, other, same_as in others:
            entry = {"frame": k, "version": other["version"], "level": other["level"], "mask": other["mask"], "errors_corrected": other["errors_corrected"],
                     "payload_bytes": len(other["payload"]), "located_by": other["located_by"], "polarity": other.get("polarity"),
                     "region_pixels": bounds_of(other["region"])}
            if index:
                entry["symbol"] = index + 1
            entry["payload_shape"], secret = payload_shape(other["payload"])
            if secret:
                entry["payload_holds_a_secret_shape"] = True
            if same_as is None:
                keep(place, entry, other, "qr-%02d-frame%d" % (number, k) + ("-symbol%d" % (index + 1) if index else ""), False)
            elif same_as[1] == 0:
                entry["same_payload_as_frame"] = same_as[0]
            else:
                entry["same_payload_as_frame"], entry["same_payload_as_symbol"] = same_as[0], same_as[1] + 1
            (listed_symbols if index else listed_frames).append(entry)
        row["region_pixels"] = bounds_of(result["region"])
        if listed_frames:
            row["other_frames_decoded"] = listed_frames
        if listed_symbols:
            row["other_symbols_decoded"] = listed_symbols
        if any("write_error" in e for e in listed_frames + listed_symbols):
            row["write_error"] = "the payload of another symbol could not be written (see other_frames_decoded, other_symbols_decoded)"
        return row

    stopped = None
    if mode == "fragments":
        pieces, piece_rows, pieces_unread = [], [], 0
        for index, path in enumerate(paths):
            row = {"piece": index, "input": printable(path)}
            picture = None
            try:
                picture, digest, size = load(path, reader, "the picture", 1)
                more = picture.frames > 1
                if picture.stream is not None:
                    try:
                        more = picture.stream.next_frame() is None and picture.stream.more
                    except NotAPicture:
                        more = None         # Pillow could not say whether a second frame is there (it does not read past the first)
                    finally:
                        picture.stream.close()
                binary, _threshold = binarise(picture.gray, None, tick)
                grid, unit = piece_modules(binary, picture.width, picture.height, module_pixels)
                row.update({"sha256": digest, "bytes": size, "pixels": "%d x %d" % (picture.width, picture.height), "picture_reader": picture.reader})
                if picture.notes:
                    row["picture_notes"] = picture.notes
                if picture.damage:
                    row["picture_damaged"] = ("%s found it cut or corrupt (%s); Pillow read it all the same, and what it filled in "
                                              "for the missing part is not the picture's" % (picture.damage_by, picture.damage))
                    unread.add("pictures_damaged", 1, "piece %d is a damaged picture, read only in part (see picture_damaged)" % index)
                if picture.unchecked:
                    row["jpeg_data_not_walked"] = picture.unchecked
                    unread.add("jpeg_data_not_walked", 1, "piece %d: the tool's own walk of the JPEG's coded data did not reach it (jpeg_data_not_walked)" % index)
                if more or more is None:
                    row["frames_not_read"] = "frames past the first%s: a piece is read from its first frame" % ("" if more else ", if it has any (Pillow did not say)")
                    unread.add("pictures_with_frames_not_searched", 1, "piece %d: %s" % (index, row["frames_not_read"]))
                if grid is None:
                    row.update({"result": "not a piece", "why": unit})
                    pieces_unread += 1
                else:
                    row.update({"modules": "%d x %d" % (len(grid[0]), len(grid)), "module_pixels": round(unit, 2)})
                    pieces.append(grid)
            except (Refused, NotAPicture) as exc:
                row.update({"result": "not read", "why": str(exc)})
                pieces_unread += 1
            except Clock:
                stopped = "the clock ran out while piece %d was being read" % index
                break
            finally:
                if picture is not None and picture.stream is not None:
                    picture.stream.close()
            piece_rows.append(row)
        row = {"input": "the set of %d pieces" % len(paths), "pieces": piece_rows}
        if stopped is None and pieces_unread:
            row.update({"result": "not read", "why": "%d of the %d pictures gave no piece (see pieces): the set was not placed" % (pieces_unread, len(paths))})
            unread.add("pieces_not_read", pieces_unread, "%d of the pieces could not be read" % pieces_unread)
        elif stopped is None:
            if len(pieces) > MAX_PIECES:
                raise Refused("at most %d pieces are placed" % MAX_PIECES)
            stats = {}
            try:
                result, tried, cut = assemble(pieces, stats, version)
            except Clock:
                result, tried, cut = None, [], None
                stopped = "the clock ran out while the pieces were being placed (%d steps, %d placements scored)" % (stats.get("search_steps", 0), stats.get("placements_scored", 0))
                row.update({"result": "not finished", "why": stopped + ": no placement decoded before it, and that is not a negative", "search": stats})
            if result is not None:
                row.update(describe_result(result))
                keep(place, row, result, "qr-01", True)
                if result["pieces_contradicting_the_symbol"]:
                    row["pieces_contradicting_the_symbol"] = result["pieces_contradicting_the_symbol"]
                    unread.add("pieces_contradicting_the_symbol", len(result["pieces_contradicting_the_symbol"]),
                               "piece(s) %s contradict the decoded symbol (modules_contradicting_the_decoded_symbol in placements): each is damaged "
                               "there or is a piece of another symbol whose modules Reed-Solomon outvoted, so the payload is not shown to be the whole set's"
                               % ", ".join(str(i) for i in result["pieces_contradicting_the_symbol"]))
            elif cut is not None:
                why = cut + ": no placement decoded before it, and that is not a negative"
                unread.add("placement_search_stopped", 1, why)
                row.update({"result": "not finished", "why": why, "best_placements_that_did_not_decode": tried, "search": stats})
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
            if out_of_time() and number < len(paths):
                stopped = "the clock ran out after picture %d of %d" % (number, len(paths))
                break
    if stopped:
        unread.add("clock_stops", 1, stopped)
    if len(rows) < len(paths) and mode != "fragments":
        unread.add("pictures_not_reached", len(paths) - len(rows), "%d picture(s) were not reached" % (len(paths) - len(rows)))
    written_not = sum(1 for r in rows if "write_error" in r)
    if written_not:
        unread.add("payloads_not_written", written_not, "a payload could not be written")
    counts = collections.Counter(r.get("result", "not finished") for r in rows)
    readable = counts["decoded"] + counts["not a symbol"]
    reasons = unread.reasons()
    # The status is derived from the one list of what was not read or not judged, and from nothing else.
    status = "failed" if readable == 0 and unread else "partial" if unread else "complete"
    basis = ("every picture given was read whole and searched by the methods named; %d decoded, %d not a symbol (a statement about these methods, the control having been read first)"
             % (counts["decoded"], counts["not a symbol"]) if status == "complete" else
             "not everything asked for was read: %s. %d decoded, %d not a symbol" % ("; ".join(reasons), counts["decoded"], counts["not a symbol"]))
    answer = {**common, "status": status, "status_basis": basis, "complete": status == "complete", "control": check,
              "counts": {"inputs": len(paths), "decoded": counts["decoded"], "not_a_symbol": counts["not a symbol"], "not_read": counts["not read"] + counts["not a piece"], "not_finished": counts["not finished"] + (len(paths) - len(rows) if mode != "fragments" else 0)},
              "rows": rows, "output_directory": place.shown, "seconds": round(time.monotonic() - started, 2),
              "not_read_or_judged": dict(unread.counts),
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
