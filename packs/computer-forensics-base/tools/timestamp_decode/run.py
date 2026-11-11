#!/usr/bin/env python3
"""Say what a number could be as a date, under every epoch that matters.

A field in an artefact holds a number and the documentation does not say which
clock wrote it. Guess wrong and the answer is off by decades, or by 66 years,
or by a factor of a thousand, and the report reads as though it were
established. This tool lists the candidates. The artefact's schema decides
which one is right, not this tool, and a plausible date is not a determination.

The epochs, and where each one shows up:

    Unix seconds            1970-01-01  syslog, sqlite, most Linux
    Unix milliseconds       1970-01-01  Java, Android, many app databases
    Unix microseconds       1970-01-01  Chromium's older tables, systemd
    Unix nanoseconds        1970-01-01  APFS, many log formats
    FILETIME                1601-01-01  everything Windows, in 100 ns ticks
    WebKit / Chrome         1601-01-01  Chromium history, in microseconds
    Apple absolute (Cocoa)  2001-01-01  macOS and iOS plists, seconds
    Apple, nanoseconds      2001-01-01  KnowledgeC and biome, sometimes
    HFS+                    1904-01-01  older Mac file systems, seconds
    OLE automation          1899-12-30  Office metadata, days as a float
    DOS date and time       1980-01-01  FAT, ZIP, shell items; packed, LOCAL time

The arithmetic is exact: the value is read as a decimal (or a hexadecimal
integer), never through a float, and a fraction of a second or of a day is kept
to the nanosecond; whatever lies beyond the ninth digit is returned as
`remainder_s`, not dropped. A DOS value and an OLE automation date carry no
zone: they are returned without a `Z`, as the writing machine's own local time.
Every other reading is UTC, which is what its epoch defines. Nothing here reads
the wall clock: plausibility is judged against an explicit range, so the same
input gives the same answer on any day.
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


import datetime
import decimal
import json
import os
import re
import sys


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

TOOL = {"name": "timestamp_decode", "version": 12}

UTC = datetime.timezone.utc
CTX = decimal.Context(prec=120, traps=[decimal.InvalidOperation, decimal.Overflow, decimal.DivisionByZero])
D = decimal.Decimal

# Epoch bases, as naive components: whether a reading is UTC is said per clock.
UNIX = datetime.datetime(1970, 1, 1)
FILETIME = datetime.datetime(1601, 1, 1)
APPLE = datetime.datetime(2001, 1, 1)
HFS = datetime.datetime(1904, 1, 1)
OLE = datetime.datetime(1899, 12, 30)

DEFAULT_FROM = "1990-01-01"
DEFAULT_TO = "2040-01-01"
MAX_DIGITS = 40
MAX_SIGNIFICANT = 60
TEXT_MAX = 80                    # characters of the value as written (an exponent or a hexadecimal run included)
SHOWN_DIGITS = 9


def fail(message, **extra):
    print_answer({"error": message, "status": "failed", "status_basis": "the tool stopped with an error: %s" % message, "tool": TOOL, **extra})
    raise SystemExit(1)


# Each clock: its epoch, the length of one unit in seconds (exact), the digits of
# fraction its own resolution has, whether the epoch defines UTC, and its use.
CLOCKS = [
    ("Unix seconds", UNIX, D(1), 0, True, "1 s", "syslog, sqlite, most Linux"),
    ("Unix milliseconds", UNIX, D("0.001"), 3, True, "1 ms", "Java, Android, app databases"),
    ("Unix microseconds", UNIX, D("0.000001"), 6, True, "1 µs", "systemd, some Chromium tables"),
    ("Unix nanoseconds", UNIX, D("0.000000001"), 9, True, "1 ns", "APFS, many log formats"),
    ("FILETIME (100 ns)", FILETIME, D("0.0000001"), 7, True, "100 ns", "Windows, everywhere"),
    ("WebKit / Chrome (µs)", FILETIME, D("0.000001"), 6, True, "1 µs", "Chromium history and cookies"),
    ("Apple absolute (s)", APPLE, D(1), 0, True, "1 s", "macOS and iOS plists"),
    ("Apple absolute (ns)", APPLE, D("0.000000001"), 9, True, "1 ns", "KnowledgeC, biome"),
    ("HFS+ (s)", HFS, D(1), 0, True, "1 s", "older Mac file systems"),
]


def parse_value(raw, as_hex):
    """The value as an exact decimal. Booleans and anything that is not a number are refused."""
    if isinstance(raw, bool) or raw is None:
        fail("value is required: the number to read as a date", value=raw)
    text = str(raw).strip().replace("_", "")
    if not text:
        fail("value is empty")
    if len(text) > TEXT_MAX:
        fail("value is longer than %d characters: no clock here is written with more" % TEXT_MAX, length=len(text))
    if "," in text:
        fail("a comma is ambiguous (a thousands separator or a decimal comma): write the number without one", value=raw)
    try:
        if re.fullmatch(r"[+-]?0[xX][0-9a-fA-F]+", text) or (as_hex and re.fullmatch(r"[+-]?[0-9a-fA-F]+", text)):
            number = D(int(text, 16))
        elif as_hex:
            raise ValueError(text)
        elif re.fullmatch(r"[+-]?([0-9]+(\.[0-9]*)?|\.[0-9]+)", text):
            number = CTX.create_decimal(text)
        elif re.fullmatch(r"[+-]?([0-9]+(\.[0-9]*)?|\.[0-9]+)[eE][+-]?[0-9]{1,3}", text):
            number = CTX.create_decimal(text)
        else:
            raise ValueError(text)
    except (ValueError, decimal.DecimalException):
        fail("value is not a number: a decimal, a decimal with a fraction, or hexadecimal", value=raw)
    if number != 0 and (number.adjusted() > MAX_DIGITS or number.adjusted() < -MAX_DIGITS):
        fail("value is outside what this tool reads (more than %d digits)" % MAX_DIGITS, value=raw)
    if len(number.as_tuple().digits) > MAX_SIGNIFICANT:
        fail("value has more than %d significant digits: the arithmetic here is exact up to that and no further" % MAX_SIGNIFICANT, value=raw)
    return text, number


def fraction_digits(frac):
    """The digits of a fraction in [0, 1), exactly: ('123456789', 'beyond') split at the ninth."""
    text = format(frac, "f")
    digits = text.split(".", 1)[1].rstrip("0") if "." in text else ""
    return digits[:SHOWN_DIGITS], digits[SHOWN_DIGITS:]


def stamp(base, seconds, utc, min_digits):
    """(when, remainder_s) for `seconds` after `base`, or (None, reason)."""
    whole = int(seconds.to_integral_value(rounding=decimal.ROUND_FLOOR))
    frac = CTX.subtract(seconds, D(whole))
    try:
        moment = base + datetime.timedelta(seconds=whole)
    except OverflowError:
        return None, "outside the years 1 to 9999 that a date can hold"
    shown, beyond = fraction_digits(frac)
    when = moment.replace(microsecond=0).isoformat() + ("." + shown if shown else "") + ("Z" if utc else "")
    # What lies beyond the ninth digit, as the decimal number of seconds it is.
    return when, ("0." + "0" * SHOWN_DIGITS + beyond if beyond else "0")


def dos_readings(number):
    """Packed FAT date and time. Both word orders are tried and each valid one is
    its own reading: date in the high word and time in the low (ZIP's and the
    directory entry's order), or the reverse. A reading is made through a real
    date, so month 13 or 30 February is refused, and the refusal is said."""
    if number != number.to_integral_value() or number < 0 or number > 0xFFFFFFFF:
        return [], ["DOS date and time: not a 32-bit unsigned integer"]
    value = int(number)
    high, low = (value >> 16) & 0xFFFF, value & 0xFFFF
    readings, refused = [], []
    for label, d, t in (("date in the high word", high, low), ("date in the low word", low, high)):
        year, month, day = ((d >> 9) & 0x7F) + 1980, (d >> 5) & 0x0F, d & 0x1F
        hour, minute, second = (t >> 11) & 0x1F, (t >> 5) & 0x3F, (t & 0x1F) * 2
        try:
            moment = datetime.datetime(year, month, day, hour, minute, second)
        except ValueError as exc:
            refused.append("DOS date and time (%s): %04d-%02d-%02d %02d:%02d:%02d is not a calendar date and time (%s)"
                           % (label, year, month, day, hour, minute, second, exc))
            continue
        readings.append({
            "epoch": "DOS date and time (%s)" % label, "when": moment.isoformat(), "zone": "none stated: the local time of the machine that wrote it",
            "precision": "2 s", "remainder_s": "0", "used_by": "FAT, ZIP, shell items", "_moment": moment, "_base": datetime.datetime(1980, 1, 1)})
    return readings, refused


def ole_reading(number):
    """OLE automation date: days from 1899-12-30. For a negative value the
    integer part is the day and the fraction is the time of day counted
    forwards, so -1.25 is 29 December 1899 06:00, not 18:00."""
    whole = number.to_integral_value(rounding=decimal.ROUND_DOWN)
    frac = abs(CTX.subtract(number, whole))
    try:
        day = OLE + datetime.timedelta(days=int(whole))
    except OverflowError:
        return None, "OLE automation date: outside the years 1 to 9999 that a date can hold"
    seconds = CTX.multiply(frac, D(86400))
    when, remainder = stamp(day, seconds, False, 0)
    if when is None:
        return None, "OLE automation date: " + remainder
    return {"epoch": "OLE automation (days)", "when": when, "zone": "none stated: the local time of the writing application",
            "precision": "1 day, with a fraction of a day", "remainder_s": remainder, "used_by": "Office document metadata",
            "_moment": datetime.datetime.fromisoformat(when[:19]), "_base": OLE}, None


def parse_day(text, name):
    try:
        return datetime.datetime.strptime(text, "%Y-%m-%d")
    except (TypeError, ValueError):
        fail("%s is a date as YYYY-MM-DD" % name, **{name: text})


def main():
    try:
        # A JSON number is kept as the text it was written in, never read through a float.
        args = json.load(sys.stdin, parse_float=str, parse_int=int)
    except (ValueError, RecursionError) as exc:
        fail("arguments are not valid JSON", reason=str(exc))
    if not isinstance(args, dict):
        fail("arguments are a JSON object")
    as_hex = args.get("hex", False)
    if not isinstance(as_hex, bool):
        fail("hex is true or false")

    text, number = parse_value(args.get("value"), as_hex)
    low = parse_day(args.get("plausible_from", DEFAULT_FROM), "plausible_from")
    high_day = parse_day(args.get("plausible_to", DEFAULT_TO), "plausible_to")
    if low >= high_day:
        fail("plausible_from must be before plausible_to", plausible_from=args.get("plausible_from"), plausible_to=args.get("plausible_to"))
    try:
        high = high_day + datetime.timedelta(days=1)      # plausible_to is a day, and the whole day is inside
    except OverflowError:
        high = datetime.datetime.max                      # the last day a date can hold: nothing lies after it
    explicit_range = "plausible_from" in args or "plausible_to" in args
    plausible_only = args.get("plausible_only", False)
    if not isinstance(plausible_only, bool):
        fail("plausible_only is true or false")

    readings, refused, out_of_range = [], [], []
    for epoch, base, unit, digits, utc, precision, used in CLOCKS:
        seconds = CTX.multiply(number, unit)
        when, remainder = stamp(base, seconds, utc, digits)
        if when is None:
            out_of_range.append(epoch)
            continue
        readings.append({"epoch": epoch, "when": when, "zone": "UTC, as the epoch defines it", "precision": precision,
                         "remainder_s": remainder, "used_by": used,
                         "_moment": datetime.datetime.fromisoformat(when[:19]), "_base": base})
    ole, why = ole_reading(number)
    if ole:
        readings.append(ole)
    else:
        out_of_range.append("OLE automation (days)")
    if out_of_range:
        refused.append("outside the years 1 to 9999 that a date can hold, under: " + ", ".join(out_of_range))
    dos, dos_refused = dos_readings(number)
    readings += dos
    refused += dos_refused

    for r in readings:
        moment, base = r.pop("_moment"), r.pop("_base")
        # A reading that lands within a year of its own epoch means the value was far
        # too small for that clock: it is arithmetic, not a date, and it drowns the real answer.
        # (Only with the default range: a caller who names a range decides what is plausible.)
        near = (not explicit_range) and not r["epoch"].startswith("DOS") and abs((moment - base).total_seconds()) < 86400 * 366
        r["plausible"] = bool(low <= moment <= high and not near)
        if near:
            r["why_not_plausible"] = "within a year of its own epoch: the value is too small for this clock"
        elif not r["plausible"]:
            r["why_not_plausible"] = "outside the reference range"
    ranked = sorted(readings, key=lambda r: not r["plausible"])
    kept = [r for r in ranked if r["plausible"]] if plausible_only else ranked
    print_answer({
        "tool": TOOL,
        "status": "complete",
        "status_basis": "every epoch this tool knows was applied to the value; which reading the artefact uses is not decided here",
        "value": text,
        "hex": hex(int(number)) if number == number.to_integral_value() else None,
        "reference_range": {"from": low.date().isoformat(), "to": high_day.date().isoformat(),
                            "meaning": "a ranking aid supplied by the caller or defaulted, not evidence: a date outside it can still be right"},
        "readings": kept,
        "reading_count": len(kept),
        "dropped_as_implausible": len(ranked) - len(kept),
        "refused": refused,
        "note": "More than one reading can be plausible; the artefact decides which, not this tool. "
                "Say in the report which epoch you applied and why the artefact uses it. A DOS "
                "value or an OLE date has no zone: it is the local time of the machine or application that "
                "wrote it, and needs that machine's timezone (with its daylight-saving history for that date) "
                "before it can join a UTC timeline. Keep the raw value beside any converted time.",
    }, indent=2)


if __name__ == "__main__":
    exit_code = 0
    try:
        main()
    except SystemExit as stop:
        exit_code = _code(stop)
    _leave(exit_code)
