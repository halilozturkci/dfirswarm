#!/usr/bin/env python3
"""first-stage-candidates: which document may have started it on one machine, ranked, from the whole member list.

    run.py detect --target TARGET          exit 0 applies, 1 does not, 2 cannot tell
    run.py run --target TARGET --out DIR   candidates.tsv + coverage.json in DIR

TARGET is JSON (inline or a file path): {"paths": [...]}; paths[0] is a directory tree (a profile, a volume, an extracted
collection) or a member list (a TSV with a `path` column, such as a catalogue's members.tsv, or a path a line).

Every file name is read, wherever it lies: a macro-capable Office document is a candidate by its name, in any folder of a profile
or outside one, not only under Documents, Desktop and Downloads. Each candidate gets a score from signals that are named one by
one in its row: the kind of name; in a tree, whether a VBA project is inside (the ZIP directory or an OLE directory name: no
member is opened and no macro is read or run); the folder (a temporary, cache, attachment or unpack folder, a downloads folder, or
simply outside the usual document folders); a Recent shortcut of the same name; in a tree, the name in the bytes of the profile's
NTUSER.DAT (where an Office MRU keeps it) and of the antivirus logs and detection files; and a Prefetch file of the document's
application. The registry key, the event record and the Prefetch list are not parsed here: a name found in the bytes is a lead to
the record, which the Windows pack's readers read.

coverage.json says whether the whole list was read (whole_list_read) and carries the rule the ranking exists for: to answer
"cannot be determined" to a "which file" question the whole member list must have been searched.

Two rules hold every loop. Each one reads the clock often enough that no single step of it can carry the run past its seconds (a
hive or an antivirus file is not opened past it), and what it keeps is bounded by a limit named below (a directory's entries are held
DIRECTORY_BATCH at a time, as names; a member list keeps no hive's path). Every limit met (seconds, members, documents, hives,
antivirus files, Recent names, directories waiting, a list's line, a file's size, a ZIP directory's records) is a line of limits_hit.
The status is derived from one list, Unread: every place that leaves something unread or unjudged (a limit, an error, a link, a row
with no path, a line outside the declared forms, a document whose VBA check could not be told, a name that is not text) counts it
there, any count above zero makes the run partial, and coverage.json prints every counter (not_read_or_judged). candidates.tsv has
every scored document.
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
import json
import os
import re
import stat
import struct
import sys
import time


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


def _probe_out(directory):
    """The output directory is written to once, up front: a directory that cannot be written (not owned, mounted read-only, a full disk) is a refusal
    before anything is run, not a PermissionError in the middle of the coverage file."""
    probe = _os.path.join(directory, ".write-probe-%d" % _os.getpid())
    temp_hold(probe)                 # registered before it is made: whatever stops this, it is removed
    try:
        fd = _os.open(probe, _os.O_WRONLY | _os.O_CREAT | _os.O_EXCL, 0o600)
        _os.close(fd)
        if not temp_drop(probe):
            raise OSError(0, "the probe file could not be removed")
    except (OSError, ValueError) as exc:
        temp_drop(probe)
        print_answer({"ok": False, "status": "failed", "error": "--out cannot be written: %s" % (getattr(exc, "strerror", None) or exc.__class__.__name__),
                      "status_basis": "the output directory cannot be written, so nothing was run"})
        _sys.exit(2)


def _unexpected_recipe(kind, value, _tb):
    """What nobody foresaw (a file that cannot be written half way, a target of an odd type) is an answer too: its class only, exit 2."""
    try:
        drop_temporaries()
    except BaseException:   # noqa: BLE001
        pass
    why = "a path, a file or the target could not be used: %s" % kind.__name__
    if len(_sys.argv) > 1 and _sys.argv[1] == "detect":
        doc = {"applies": "unknown", "why": why, "ok": False, "error": why}
    else:
        doc = {"ok": False, "status": "failed", "error": why, "status_basis": "the recipe stopped on %s, so what it had written is not a complete result" % kind.__name__}
    try:
        _sys.stdout.write(json.dumps(doc) + "\n")
        _sys.stdout.flush()
    except (OSError, ValueError):
        pass
    _os._exit(2)


_sys.excepthook = _unexpected_recipe


def _write_json_whole(path, doc, **dumps_kwargs):
    """A JSON file whole or not at all: written beside, then renamed over the name. A write that fails (a full disk, a file-size limit) removes
    the part and raises, so the recipe answers (the excepthook) and the earlier file, if any, stands; a cut coverage.json is never left."""
    tmp = path + ".tmp"
    temp_hold(tmp)
    try:
        with os.fdopen(_create_new(tmp), "w") as fh:
            json.dump(doc, fh, **dumps_kwargs)
        temp_replace(tmp, path)
    except BaseException:
        temp_drop(tmp)
        raise


def _create_new(path):
    """A descriptor of a file made new at path, never written through a link: a name already there (a file or a link left in the output
    directory) is removed first, and the file is then created exclusively, without following a link."""
    try:
        os.unlink(path)
    except FileNotFoundError:
        pass
    return os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o644)


def _write_text_whole(path, text):
    """A text file whole or not at all, never through a link: written beside, then renamed over the name (a link at the name is replaced,
    not followed)."""
    tmp = path + ".tmp"
    temp_hold(tmp)
    try:
        with os.fdopen(_create_new(tmp), "w", encoding="utf-8", newline="\n") as fh:
            fh.write(text)
        temp_replace(tmp, path)
    except BaseException:
        temp_drop(tmp)
        raise


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


RECIPE = "first-stage-candidates"
VERSION = "1.3.0"
HERE = os.path.dirname(os.path.abspath(__file__))
COLUMNS = ["rank", "score", "path", "kind", "size", "profile", "signals"]
MACRO_NAMES = {".docm": "word", ".dotm": "word", ".xlsm": "excel", ".xltm": "excel", ".xlam": "excel", ".xlsb": "excel", ".pptm": "powerpoint", ".potm": "powerpoint",
               ".ppsm": "powerpoint", ".ppam": "powerpoint", ".sldm": "powerpoint"}
LEGACY_NAMES = {".doc": "word", ".dot": "word", ".xls": "excel", ".xlt": "excel", ".xla": "excel", ".ppt": "powerpoint", ".pot": "powerpoint", ".pps": "powerpoint"}
PLAIN_OOXML = {".docx": "word", ".dotx": "word", ".xlsx": "excel", ".xltx": "excel", ".pptx": "powerpoint", ".potx": "powerpoint", ".ppsx": "powerpoint"}
APPLICATION = {"word": "WINWORD.EXE", "excel": "EXCEL.EXE", "powerpoint": "POWERPNT.EXE"}
USUAL = ("/documents/", "/desktop/", "/my documents/", "/onedrive/documents/", "/onedrive/desktop/")
DELIVERY = (("/appdata/local/temp/", "a temporary folder of the profile"), ("/local settings/temp/", "a temporary folder of the profile"),
            ("/inetcache/", "a browser or mail cache folder"), ("/temporary internet files/", "a browser or mail cache folder"), ("/content.outlook/", "Outlook's attachment folder"),
            ("/appdata/roaming/", "the profile's roaming application data"), ("/appdata/locallow/", "the profile's low-integrity application data"))
DOWNLOADS = ("/downloads/",)
ARCHIVE_TEMP = re.compile(r"/(7z[a-z0-9]{6,}|rar\$[a-z0-9.]+|temp\d+_[^/]+\.zip|[^/]+\.zip\.[a-z0-9]{3,})/", re.I)
PROFILE = re.compile(r"(?:^|/)(?:users|documents and settings)/([^/]+)/", re.I)
LISTED_PROFILE = re.compile(r"(?:^|[/\t])(?:users|documents and settings)/([^/\t\n]+)/", re.I | re.M)     # a line or a cell of a list
ANTIVIRUS = re.compile(r"(microsoft-windows-windows defender%4(operational|whc)\.evtx|/mplog-[^/]*\.log|/detectionhistory/|/windows defender/support/|/quarantine/)", re.I)
VBA_OLE = "_VBA_PROJECT".encode("utf-16-le")
MAX_MEMBERS = 5_000_000
MAX_DOCUMENTS = 100_000           # the most documents scored; every one of them is a row of candidates.tsv
MAX_ANTIVIRUS = 400               # the most antivirus logs and detection files searched for names
MAX_RECENT = 200_000              # the most Recent shortcut names (of documents) kept, and the most (name, profile) pairs of them
MAX_HIVES = 20_000                # the most profiles' NTUSER.DAT kept (in a tree) to search for the names
DIRECTORY_BATCH = 100_000         # a directory's entries are held this many at a time (names and kinds, never the scandir objects)
MAX_PENDING_DIRECTORIES = 1_000_000  # the most directories waiting to be entered (each its own name and its parent's, shared); one past it is not entered
SCAN_BYTES = 512 << 20            # the most of one hive or log file that is searched for names
OLE_BYTES = 64 << 20
ZIP_RECORDS = 20_000              # the most ZIP central-directory records walked for a VBA project
LINE_MAX = 1 << 20                # the longest line of a member list that is read
COVERAGE_MAX_BYTES = 4 << 20      # the list's own coverage record, read up to this size
LIST_NAME = "members.tsv"         # the name every lister of the house gives the member list its coverage record stands for
DETECT_LIST_BYTES = 256 << 20     # detect reads at most this much of a member list ...
DETECT_SECONDS = 60               # ... and for at most this long; past either, it cannot tell
CLOCK_EVERY = 256                 # a loop reads the clock at least once per this many steps of its own
WHY_MAX, WHY_CHARS = 5, 400


class Unread:
    """The one list of what this run did not read or did not judge: every place that leaves something unread or unjudged counts it here,
    under a name declared up front, with the sentence that says it. The status is derived from this list alone (a failed run aside): a
    count above zero makes the answer partial. The answer prints every counter, zeros included (`not_read_or_judged`)."""

    def __init__(self, *names):
        self.counts = {n: 0 for n in names}
        self.said = {}

    def add(self, name, count=1, sentence=None):
        if name not in self.counts:
            raise KeyError("an undeclared counter: %s" % name)
        if count <= 0:
            return
        self.counts[name] += count
        if sentence and name not in self.said:
            self.said[name] = sentence

    def __bool__(self):
        return any(self.counts.values())

    def reasons(self):
        return ["%s (%s: %d)" % (self.said.get(n, "not read or not judged"), n, c) for n, c in self.counts.items() if c]


# The counters of a run. The first group is of the names themselves: a count above zero there means the tree or the list was not read
# to its end (whole_list_read false). The second is of what the names were scored on.
NAME_COUNTERS = ("walk_stopped_by_the_clock", "members_past_the_limit", "directories_not_entered", "walk_errors", "links_to_directories_outside",
                 "list_lines_over_the_line_limit", "list_rows_without_a_path", "list_lines_of_another_form", "documents_past_the_cap",
                 "member_list_not_known_whole")
SIGNAL_COUNTERS = ("links_not_followed", "documents_not_looked_into", "documents_vba_not_told_by_a_limit", "documents_vba_not_told",
                   "names_not_searched_in_bytes", "hives_past_the_cap", "antivirus_files_not_searched", "files_not_searched_past_the_clock",
                   "files_searched_only_in_part", "files_not_read_to_their_end", "recent_shortcuts_past_the_cap")


def limits():
    try:
        with open(os.path.join(HERE, "recipe.json"), encoding="utf-8") as fh:
            lim = json.load(fh).get("limits", {})
    except Exception:  # noqa: BLE001 - the defaults below
        lim = {}
    try:
        return int(os.environ.get("RECIPE_SECONDS") or lim.get("seconds") or 900), int(os.environ.get("RECIPE_MEMBERS") or lim.get("members") or MAX_MEMBERS)
    except ValueError:
        return 900, MAX_MEMBERS


def refuse(message):
    if sys.argv[1:2] == ["detect"]:      # a call detect could not use is no answer about the object: it cannot tell
        print_answer({"ok": False, "applies": "unknown", "why": message, "error": message})
    else:
        print_answer({"ok": False, "status": "failed", "error": message, "status_basis": "the target could not be used, so nothing was run"})
    sys.exit(2)


def target_of(arg):
    text = arg
    if os.path.isfile(arg):
        try:
            with open(arg, encoding="utf-8") as fh:
                text = fh.read(1 << 20)
        except (OSError, ValueError) as exc:
            refuse("the target file cannot be read as UTF-8 text: %s" % (getattr(exc, "strerror", None) or exc.__class__.__name__))
    try:
        t = json.loads(text)
    except (ValueError, RecursionError) as exc:
        refuse("the target is not valid JSON (%s)" % exc.__class__.__name__)
    if not isinstance(t, dict) or not isinstance(t.get("paths"), list) or not t["paths"] or not isinstance(t["paths"][0], str) or not t["paths"][0] or "\x00" in t["paths"][0]:
        refuse("the target is a JSON object with a paths list: the first path is a directory tree (a profile, a volume, an extracted collection) or a member list (a TSV with a path column, or a path a line)")
    return t, t["paths"][0]


def esc(text):
    out = []
    for ch in text:
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


def esc_listed(text):
    """A member list's path as the list has it: a backslash stays one backslash (a Windows path matches the list's text); only an
    undecodable byte or a control character is written as \\xNN."""
    out = []
    for ch in text:
        o = ord(ch)
        if 0xDC80 <= o <= 0xDCFF:
            out.append("\\x%02x" % (o - 0xDC00))
        elif o < 0x20 or o == 0x7F:
            out.append("\\x%02x" % o)
        else:
            out.append(ch)
    return "".join(out)


def listing_rows(path, deadline, max_members, cov, unread):
    """The paths of a member list: a TSV whose header has a `path` column (any case; and maybe `type` and `size`), or a path a line.
    Backslashes are read as separators. Yields (path, size or None, False). A line is read LINE_MAX bytes at a time at most: a longer one
    is skipped (it is in limits_hit, and the run is partial), so memory is bounded whatever the list holds. A line outside the declared
    forms is counted in list_lines_of_another_form, which makes the run partial: one holding a NUL byte (a UTF-16 list) or a carriage
    return inside (lines ended by CR alone) is not read; a line of a path-a-line list that holds a tab (a TSV with no path column) is
    read whole as a path and counted. The members limit is met only by a member past it, never by the last one of a list."""
    with open_regular(path) as raw:
        column = size_column = type_column = None
        first = True
        number = 0
        while True:
            if number % 4096 == 0 and time.monotonic() > deadline:
                cov["limits_hit"].append("seconds: the clock ran out after %d lines of the list" % number)
                unread.add("walk_stopped_by_the_clock", 1, "the clock ran out before the list was read to its end")
                return
            line = raw.readline(LINE_MAX + 1)
            if not line:
                return
            number += 1
            if len(line) > LINE_MAX:
                skipped = 0
                while line and not line.endswith(b"\n"):
                    skipped += 1
                    if skipped % 16 == 0 and time.monotonic() > deadline:
                        cov["limits_hit"].append("seconds: the clock ran out inside line %d of the list, which is longer than %d bytes" % (number, LINE_MAX))
                        unread.add("walk_stopped_by_the_clock", 1, "the clock ran out before the list was read to its end")
                        return
                    line = raw.readline(LINE_MAX + 1)
                cov["long_lines"] = cov.get("long_lines", 0) + 1
                if cov["long_lines"] == 1:
                    cov["limits_hit"].append("lines: line %d of the list (and any other line longer than %d bytes) was not read" % (number, LINE_MAX))
                unread.add("list_lines_over_the_line_limit", 1, "a line of the list longer than %d bytes was not read" % LINE_MAX)
                first = False
                continue
            body = line.rstrip(b"\r\n")
            if first and body.startswith(b"\xef\xbb\xbf"):
                body = body[3:]                                  # a UTF-8 byte-order mark before the header
            if b"\x00" in body or b"\r" in body:
                if first:
                    first = False
                    cov["list_form"] = ("not UTF-8 text a line at a time (NUL bytes: a UTF-16 list?)" if b"\x00" in body else
                                        "lines ended by a carriage return alone") + ": not a form this recipe reads"
                cov["lines_of_another_form"] = cov.get("lines_of_another_form", 0) + 1
                unread.add("list_lines_of_another_form", 1, "a line of the list holding a NUL byte (a UTF-16 list?) or a carriage return inside "
                           "(lines ended by CR alone) was not read: the list is not in a form this recipe reads")
                continue
            text = body.decode("utf-8", "surrogateescape")
            if first:
                first = False
                cells = [c.strip().lower() for c in text.split("\t")]
                if "path" in cells:
                    column = cells.index("path")
                    size_column = cells.index("size") if "size" in cells else None
                    type_column = cells.index("type") if "type" in cells else None
                    cov["list_form"] = "a TSV with a path column (column %d)" % (column + 1)
                    if cells.count("path") > 1:
                        cov["list_form"] += ", the first of %d columns named path" % cells.count("path")
                        unread.add("list_lines_of_another_form", 1, "the list's header names more than one path column: the first was read, the others not")
                    continue
                cov["list_form"] = "a path a line"
            if not text:
                continue
            if column is None:
                if "\t" in text:
                    cov["lines_of_another_form"] = cov.get("lines_of_another_form", 0) + 1
                    unread.add("list_lines_of_another_form", 1, "a line of a path-a-line list holds a tab (a TSV with no path column?): it was read whole as one path")
                if cov["members"] >= max_members:
                    cov["limits_hit"].append("members: the list has more than %d rows" % max_members)
                    unread.add("members_past_the_limit", 1, "the list has more than %d rows: the rest were not read" % max_members)
                    return
                yield text, None, False
                continue
            cells = text.split("\t")
            if column >= len(cells):
                cov["rows_without_a_path"] = cov.get("rows_without_a_path", 0) + 1
                unread.add("list_rows_without_a_path", 1, "a row of the list has no cell in its path column: its name was not read")
                continue
            if cov["members"] >= max_members:
                cov["limits_hit"].append("members: the list has more than %d rows" % max_members)
                unread.add("members_past_the_limit", 1, "the list has more than %d rows: the rest were not read" % max_members)
                return
            if type_column is not None and type_column < len(cells) and cells[type_column] in ("folder", "dir", "directory", "d"):
                cov["members"] += 1
                continue
            size = None
            if size_column is not None and size_column < len(cells) and cells[size_column].isdigit():
                size = int(cells[size_column])
            yield cells[column], size, False


def list_coverage(path):
    """What the member list's own coverage record says of the list: {status, read_from, why, recipe}. The record is the coverage.json in
    the directory where the list really lies (a link to a list is resolved, so a record beside the link is not taken for the list's own),
    and it stands for one list: the one named members.tsv (LIST_NAME), the name every lister of the house gives its member list
    (ad1-items, archive-members and android-backup write it beside their record; ad1-items' attributes.tsv lies beside the same record and
    is not a member list). status is the record's (complete, partial, failed); "unknown" when the record gives none or cannot be read;
    "not recorded" when there is no record; "not named" when the record does not stand for this list. A record that says complete and
    lists a limit, an error or a missing segment contradicts itself and counts as partial. Only "complete" says the list is the whole of
    its object. The record is opened without waiting and without following a link, and read only when it is a regular file of at most
    COVERAGE_MAX_BYTES."""
    real = os.path.realpath(path)
    where = os.path.join(os.path.dirname(real), "coverage.json")
    out = {"status": "not recorded", "read_from": esc(os.path.relpath(where))}
    if real != os.path.abspath(path):
        out["list_is_a_link_to"] = esc(os.path.relpath(real))
    if not os.path.lexists(where):
        out["why"] = ["no coverage.json beside the list (where it really lies): nothing records whether the list is the whole of its object"]
        return out
    fd = None
    try:
        fd = os.open(where, os.O_RDONLY | getattr(os, "O_NONBLOCK", 0) | getattr(os, "O_NOFOLLOW", 0))
        st = os.fstat(fd)
        if not stat.S_ISREG(st.st_mode):
            raise ValueError("it is not a regular file")
        if st.st_size > COVERAGE_MAX_BYTES:
            raise ValueError("it is %d bytes, more than the %d this recipe reads" % (st.st_size, COVERAGE_MAX_BYTES))
        with os.fdopen(fd, "rb") as fh:
            fd = None
            record = json.loads(fh.read(COVERAGE_MAX_BYTES + 1).decode("utf-8", "replace"))
        if not isinstance(record, dict):
            raise ValueError("it is not a JSON object")
    except (OSError, ValueError, RecursionError) as exc:
        out.update({"status": "unknown", "why": ["the list's coverage record could not be read (%s)" % (getattr(exc, "strerror", None) or str(exc) or exc.__class__.__name__)]})
        return out
    finally:
        if fd is not None:
            os.close(fd)
    status = record.get("status")
    out["status"] = status if status in ("complete", "partial", "failed") else "unknown"
    if isinstance(record.get("recipe"), str):
        out["recipe"] = esc(record["recipe"])[:100]
    why = []
    if os.path.basename(real) != LIST_NAME:
        out["record_status"] = out["status"]
        out["status"] = "not named"
        why.append("the coverage record beside the list stands for the member list named %s, and this list is %s: the record says nothing of it"
                   % (LIST_NAME, esc(os.path.basename(real))[:200]))
    elif out["status"] == "complete":
        said = [key for key in ("limits_hit", "errors", "segments_missing") if isinstance(record.get(key), list) and record[key]]
        if said:
            out["status"] = "partial"
            why.append("the record says complete and lists %s: it contradicts itself, and is read as partial" % " and ".join(said))
    if out["status"] != "complete":
        for key in ("limits_hit", "errors", "segments_missing"):
            if isinstance(record.get(key), list):
                why += ["%s: %s" % (key, v) if key != "errors" else str(v) for v in record[key]]
        if isinstance(record.get("status_basis"), str) and record["status_basis"]:
            why.append(record["status_basis"])
        if out["status"] == "unknown":
            why.append("the record gives no status that can be read")
        if not why:
            why.append("the record's status is %s, and it says no more" % out["status"])
        seen = []
        for text in why:
            text = esc(text)
            text = text if len(text) <= WHY_CHARS else text[:WHY_CHARS] + "..."
            if text not in seen:
                seen.append(text)
        out["why"] = seen[:WHY_MAX]
        if len(seen) > WHY_MAX:
            out["why_total"] = len(seen)
    return out


def note_error(cov, text, unread=None):
    """An error of the walk: every one is counted (errors_total, and walk_errors), the first 200 are kept with their words, so memory stays bounded."""
    cov["errors_total"] = cov.get("errors_total", 0) + 1
    if unread is not None:
        unread.add("walk_errors", 1, "a directory or an entry of the tree could not be read: the names below it were not read")
    if len(cov["errors"]) < 200:
        cov["errors"].append(text)


def _inside(real, top):
    return real == top or real.startswith(top.rstrip(os.sep) + os.sep)


def _kind(entry):
    """What a directory entry is, from what the listing gave (no stat): link, dir, file or other (a FIFO, a socket, a device)."""
    if entry.is_symlink():
        return "link"
    if entry.is_dir(follow_symlinks=False):
        return "dir"
    return "file" if entry.is_file(follow_symlinks=False) else "other"


def tree_rows(root, deadline, max_members, cov, unread):
    """Every file below a directory, links never followed: (path relative to it, size, False), and a link by its own name: (path, None, True);
    an entry that is neither a file, a directory nor a link (a FIFO, a socket, a device) is a name too, with no size. The clock is read at
    least once per 4096 entries. A directory's entries are held DIRECTORY_BATCH at a time, as names and kinds (never the listing's own
    objects), each batch in name order: a directory of millions of entries is read whole in bounded memory. At most MAX_PENDING_DIRECTORIES
    directories wait to be entered; one found past that is not entered and is counted (directories_not_entered). A link whose target is a
    directory outside the tree is counted in links_to_directories_outside: what lies below it is not read (only a stat of the target tells
    it is a directory; nothing in it is listed)."""
    stack = [("", "")]                # (the parent's path, shared by its subdirectories, and the directory's own name)
    top = os.path.realpath(root)
    stop = []

    def stopped_by_clock(rel, where):
        cov["limits_hit"].append("seconds: the clock ran out %s %s; %d directories were not entered" % (where, esc(rel) or "the tree's root", len(stack) + 1))
        unread.add("walk_stopped_by_the_clock", 1, "the clock ran out before the tree was walked to its end")
        unread.add("directories_not_entered", len(stack) + 1, "directories of the tree were not entered: the names below them were not read")
        stop.append(True)

    def batch_rows(rel, batch):
        batch.sort()
        for number, (entry_name, kind) in enumerate(batch, 1):
            if number % 4096 == 0 and time.monotonic() > deadline:
                stopped_by_clock(rel, "inside")
                return
            name = os.path.join(rel, entry_name) if rel else entry_name
            full = os.path.join(root, name)
            if kind == "dir":
                if len(stack) >= MAX_PENDING_DIRECTORIES:
                    if not cov.get("pending_cut"):
                        cov["pending_cut"] = True
                        cov["limits_hit"].append("directories: more than %d directories were waiting to be entered at once; those found past that were not entered" % MAX_PENDING_DIRECTORIES)
                    unread.add("directories_not_entered", 1, "directories of the tree were not entered: the names below them were not read")
                else:
                    stack.append((rel, entry_name))
                continue
            if cov["members"] >= max_members:
                cov["limits_hit"].append("members: the tree has more than %d files" % max_members)
                unread.add("members_past_the_limit", 1, "the tree has more than %d files: the rest were not read" % max_members)
                stop.append(True)
                return
            try:
                if kind == "link":
                    cov["links_not_followed"] = cov.get("links_not_followed", 0) + 1
                    try:
                        if os.path.isdir(full) and not _inside(os.path.realpath(full), top):
                            cov["links_to_directories_outside"] = cov.get("links_to_directories_outside", 0) + 1
                            unread.add("links_to_directories_outside", 1, "a link in the tree leads to a directory outside it, which was not entered: the names below it were not read")
                    except (OSError, ValueError):
                        pass
                    yield name, None, True
                elif kind == "file":
                    yield name, os.lstat(full).st_size, False
                else:
                    yield name, None, False
            except OSError:
                note_error(cov, "an entry could not be read: %s" % esc(name)[:200], unread)

    while stack:
        parent, own = stack.pop()
        rel = os.path.join(parent, own) if parent else own
        if time.monotonic() > deadline:
            stopped_by_clock(rel, "before")
            return
        try:
            with os.scandir(os.path.join(root, rel) if rel else root) as entries:
                batch, number, batched = [], 0, False
                for entry in entries:
                    number += 1
                    if number % 4096 == 0 and time.monotonic() > deadline:
                        stopped_by_clock(rel, "while listing")
                        return
                    try:
                        batch.append((entry.name, _kind(entry)))
                    except OSError:
                        note_error(cov, "an entry could not be read: %s" % esc(os.path.join(rel, entry.name))[:200], unread)
                    if len(batch) >= DIRECTORY_BATCH:
                        if not batched:
                            batched = True
                            cov["directories_read_in_batches"] = cov.get("directories_read_in_batches", 0) + 1
                        yield from batch_rows(rel, batch)
                        batch = []
                        if stop:
                            return
                yield from batch_rows(rel, batch)
                if stop:
                    return
        except OSError as exc:
            note_error(cov, "a directory could not be listed (%s): %s" % (getattr(exc, "strerror", None) or exc.__class__.__name__, esc(rel)[:200]), unread)
            continue


def zip_vba(fh, size, deadline):
    """A VBA project in a ZIP's central directory, walked here record by record (no member is opened, and no more than ZIP_RECORDS
    records are walked, so memory is the same whatever the directory declares): (True | False | None, how, limit or None)."""
    tail_len = min(size, 22 + 0xFFFF)
    fh.seek(size - tail_len)
    tail = fh.read(tail_len)
    at, eocd = tail.rfind(b"PK\x05\x06"), None
    while at >= 0:                          # the record whose comment ends the file, else the last one that fits
        if at + 22 <= len(tail):
            if at + 22 + struct.unpack_from("<H", tail, at + 20)[0] == len(tail):
                eocd = at
                break
            eocd = at if eocd is None else eocd
        at = tail.rfind(b"PK\x05\x06", 0, at)
    if eocd is None:
        return None, "it begins like a ZIP and has no end-of-central-directory record: its directory cannot be found", None
    _sig, _disk, _cd_disk, _n_disk, entries, cd_size, _cd_offset, _comment = struct.unpack_from("<IHHHHIIH", tail, eocd)
    cd_end = size - tail_len + eocd
    locator = b""
    if cd_end >= 20 + 56:
        fh.seek(cd_end - 20)
        locator = fh.read(20)
    if locator[:4] == b"PK\x06\x07":            # a ZIP64 end record before the end record: its counts are the ones that hold
        fh.seek(cd_end - 20 - 56)
        record = fh.read(56)
        if len(record) < 56 or record[:4] != b"PK\x06\x06":
            return None, "its ZIP64 end record does not read: its directory does not read", None
        entries, cd_size = struct.unpack_from("<QQ", record, 32)
        cd_end -= 20 + 56
    start = cd_end - cd_size
    if start < 0:
        return None, "its end record puts the directory before the file's start: its directory does not read", None
    fh.seek(start)
    walked, at = 0, start
    while walked < entries and at < cd_end:
        if walked >= ZIP_RECORDS:
            return None, "its ZIP directory has more than %d members: the first %d were walked and hold no VBA project" % (ZIP_RECORDS, ZIP_RECORDS), \
                "vba: a ZIP directory of more than %d members was walked only that far" % ZIP_RECORDS
        if walked % CLOCK_EVERY == 0 and time.monotonic() > deadline:
            return None, "the clock ran out while its ZIP directory was walked", "seconds: the clock ran out while a ZIP directory was walked"
        head = fh.read(46)
        if len(head) < 46 or head[:4] != b"PK\x01\x02":
            return None, "its ZIP directory does not read (record %d is not a directory record)" % (walked + 1), None
        name_len, extra_len, comment_len = struct.unpack_from("<HHH", head, 28)
        name = fh.read(name_len)
        if name.lower().endswith(b"vbaproject.bin"):
            return True, "the member list of its ZIP directory (no member was opened)", None
        if extra_len or comment_len:
            fh.seek(extra_len + comment_len, 1)
        at += 46 + name_len + extra_len + comment_len
        walked += 1
    if walked < entries:
        return None, "its ZIP directory ends after %d of the %d members its end record declares" % (walked, entries), None
    return False, "the member list of its ZIP directory (no member was opened)", None


def vba_in_file(path, kind, deadline):
    """What the file's own bytes say about a VBA project: (True | False | None when it could not be told, how, limit or None). limit is
    a line for limits_hit when a limit of the recipe (size, records, clock) is why it could not be told."""
    try:
        size = os.path.getsize(path)
        if size > SCAN_BYTES:
            return None, "it is over %d bytes: not looked into" % SCAN_BYTES, "vba: a document over %d bytes was not looked into" % SCAN_BYTES
        if size == 0:
            return False, "it is empty (0 bytes)", None
        with open_regular(path) as fh:
            head = fh.read(8)
            if head[:4] == b"PK\x03\x04":
                try:
                    return zip_vba(fh, os.fstat(fh.fileno()).st_size, deadline)
                except (OSError, ValueError, struct.error):
                    return None, "it begins like a ZIP and its directory does not read", None
            if head == b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1":
                fh.seek(0)
                read, tail = 0, b""
                while read < OLE_BYTES:
                    if time.monotonic() > deadline:
                        return None, "the clock ran out while it was read", "seconds: the clock ran out while a document was read"
                    block = fh.read(1 << 20)
                    if not block:
                        return False, "a search of its bytes for the directory name _VBA_PROJECT (UTF-16LE)", None
                    if VBA_OLE in tail + block:
                        return True, "a search of its bytes for the directory name _VBA_PROJECT (UTF-16LE)", None
                    read += len(block)
                    tail = block[-len(VBA_OLE):]
                return None, "it is over %d bytes: only that much was searched" % OLE_BYTES, "vba: an OLE document over %d bytes was searched only that far" % OLE_BYTES
            return None, "it is neither a ZIP nor an OLE compound file by its first bytes (its name says %s)" % kind, None
    except (OSError, ValueError):
        return None, "it could not be opened", None


def name_index(names):
    """The names (lower-case file names, each ending in its suffix) as byte patterns, by the bytes of their suffix: {suffix bytes: (the
    pattern lengths, {pattern: name})}, UTF-16LE and UTF-8; and the longest pattern. A name occurs in a text exactly when, at some place
    where its suffix ends, the bytes of the name's length that end there are the name: so a search costs a find of each suffix and a few
    look-ups per place, whatever the number of names. The third value counts the names that are not text (a name of bytes that are not
    UTF-8, kept as surrogates): they cannot be searched for as UTF-16LE or UTF-8, and the caller counts them as not searched."""
    index, longest = {}, 0
    unencodable = 0                   # names that are not text (bytes no encoding names): not searched for, and counted
    for name in names:
        dot = name.rfind(".")
        if dot <= 0:
            continue
        for encoding in ("utf-16-le", "utf-8"):
            try:
                pattern, suffix = name.encode(encoding), name[dot:].encode(encoding)
            except UnicodeError:
                unencodable += encoding == "utf-8"
                continue
            lengths, patterns = index.setdefault(suffix, (set(), {}))
            lengths.add(len(pattern))
            patterns[pattern] = name
            longest = max(longest, len(pattern))
    return {suffix: (sorted(lengths), patterns) for suffix, (lengths, patterns) in index.items()}, longest, unencodable


def names_in_file(path, index, deadline):
    """Which of the names of a name_index occur in a file's bytes as UTF-16LE or UTF-8, case folded for ASCII: a set, and why the whole
    file was not searched (None when it was; "seconds", "size" past SCAN_BYTES, or "error"). The clock is read once per CLOCK_EVERY places a suffix occurs, so no block can hold the run past it."""
    found = set()
    by_suffix, longest = index[0], index[1]
    steps = 0
    try:
        with open_regular(path) as fh:
            read, tail = 0, b""
            while read < SCAN_BYTES:
                if time.monotonic() > deadline:
                    return found, "seconds"
                block = fh.read(4 << 20)
                if not block:
                    return found, None
                window = (tail + block).lower()
                for suffix, (lengths, patterns) in by_suffix.items():
                    at = window.find(suffix)
                    while at >= 0:
                        steps += 1
                        if steps % CLOCK_EVERY == 0 and time.monotonic() > deadline:
                            return found, "seconds"
                        end = at + len(suffix)
                        for length in lengths:
                            if length > end:
                                break
                            name = patterns.get(window[end - length:end])
                            if name is not None:
                                found.add(name)
                        at = window.find(suffix, at + 1)
                read += len(block)
                tail = block[-longest:] if longest else b""
            return found, "size" if fh.read(1) else None
    except (OSError, ValueError):
        return found, "error"


def detect(path):
    """(True | False | "unknown", why). A directory applies when a profile folder is within three levels of it; a list when a line of it
    names a profile path. A directory that could not be listed, or a list read only in part (DETECT_LIST_BYTES, DETECT_SECONDS), with
    no profile found in what was read, cannot be told: "unknown", never False."""
    began = time.monotonic()
    try:
        st = os.stat(path)
    except (OSError, ValueError) as exc:
        return "unknown", "the target cannot be read: %s" % (getattr(exc, "strerror", None) or exc.__class__.__name__)
    if stat.S_ISDIR(st.st_mode):
        level, seen, unlisted = [path], 0, 0
        for _depth in range(4):
            below = []
            for directory in level:
                try:
                    with os.scandir(directory) as entries:
                        for entry in entries:
                            seen += 1
                            if seen > 20000:
                                return "unknown", "more than 20,000 entries in the first levels of the tree: not told"
                            if seen % 4096 == 0 and time.monotonic() - began > DETECT_SECONDS:
                                return "unknown", "the first levels of the tree were not walked in %d seconds: not told" % DETECT_SECONDS
                            try:
                                if entry.is_dir(follow_symlinks=False):
                                    if entry.name.lower() in ("users", "documents and settings"):
                                        return True, "a profile folder (%s) is in the tree" % entry.name
                                    below.append(entry.path)
                                elif entry.name.lower() == "ntuser.dat":
                                    return True, "a user's registry hive is in the tree: it is a profile"
                            except OSError:
                                unlisted += 1
                except OSError:
                    unlisted += 1
            level = below
        if unlisted:
            return "unknown", "%d director%s within three levels of the directory could not be listed or read, and no profile folder was found in the rest: not told" % (
                unlisted, "y" if unlisted == 1 else "ies")
        return False, "no Users or Documents and Settings folder and no NTUSER.DAT within three levels of the directory"
    if not stat.S_ISREG(st.st_mode):
        # a pipe, a device or a socket is not opened (a read could wait for ever): a file it cannot read is a file it cannot tell about
        return "unknown", "neither a directory nor a regular file (a pipe, a device or a socket): not opened, so not told"
    try:
        with open_regular(path) as fh:
            read, tail = 0, ""
            while True:
                if read >= DETECT_LIST_BYTES:
                    return "unknown", "no path of a user profile in the first %d bytes of the list, and the rest was not read: not told" % read
                if time.monotonic() - began > DETECT_SECONDS:
                    return "unknown", "no path of a user profile in the first %d bytes of the list, read in %d seconds; the rest was not read: not told" % (read, DETECT_SECONDS)
                block = fh.read(4 << 20)
                if not block:
                    break
                if read == 0 and b"\x00" in block[:4096]:
                    return False, "not a text list (it holds NUL bytes)"
                read += len(block)
                text = tail + block.decode("utf-8", "replace").replace("\\", "/")
                if LISTED_PROFILE.search(text):
                    return True, "the list names paths inside a user profile"
                tail = text[-1024:]
    except (OSError, ValueError) as exc:
        return "unknown", "the list cannot be read: %s" % (getattr(exc, "strerror", None) or exc.__class__.__name__)
    return False, "no path of a user profile in the whole list (%d bytes)" % read


def run(path, out_dir):
    seconds, max_members = limits()
    started = time.monotonic()
    deadline = started + seconds * 0.9
    try:
        os.makedirs(out_dir, exist_ok=True)
    except (OSError, ValueError) as exc:
        print_answer({"ok": False, "status": "failed", "error": "--out cannot be used: %s" % (getattr(exc, "strerror", None) or exc.__class__.__name__),
                      "status_basis": "the output directory could not be made, so nothing was run"})
        sys.exit(2)
    if os.path.islink(out_dir):
        print_answer({"ok": False, "status": "failed", "error": "--out is a link: the recipe writes into a directory, never through a link", "status_basis": "the output directory is a link, so nothing was run"})
        sys.exit(2)
    _probe_out(out_dir)
    is_tree = os.path.isdir(path)
    cov = {"recipe": RECIPE, "recipe_version": VERSION, "target": path, "mode": "tree" if is_tree else "member list", "members": 0, "candidates": 0,
           "covered": "", "not_covered": "", "limits_hit": [], "errors": [],
           "rule": "To answer \"cannot be determined\" to a \"which file\" question the whole member list must have been searched: whole_list_read says whether it was "
                   "(the recipe read the whole tree or list, and a member list's own coverage record says the list is complete). "
                   "A ranking is a list of candidates with the signals each one has, not a finding: the first row is where to look first."}
    _write_json_whole(os.path.join(out_dir, "coverage.json"), dict(cov, status="partial", whole_list_read=False, status_basis="the run had started and had read nothing yet"), indent=2)

    def _stopped(signum):
        _write_json_whole(os.path.join(out_dir, "coverage.json"), dict(cov, status="partial", whole_list_read=False, interrupted=True, signal=signum,
                          status_basis="the recipe was stopped by signal %d after %d members: no ranking was written, and nothing is claimed about the list" % (signum, cov["members"])), indent=2)
        print(json.dumps({"ok": False, "status": "partial", "interrupted": True, "signal": signum, "members": cov["members"]}), flush=True)
    install_signal_handlers(_stopped)

    unread = Unread(*NAME_COUNTERS, *SIGNAL_COUNTERS)
    documents, recent, hives, antivirus, prefetch, linked = [], collections.defaultdict(set), {}, [], set(), set()
    hives_seen, recent_pairs = 0, 0
    applications = {a.lower() for a in APPLICATION.values()}
    document_suffixes = set(MACRO_NAMES) | set(LEGACY_NAMES) | (set(PLAIN_OOXML) if is_tree else set())
    antivirus_seen, source_limits = 0, []      # a cut of a signal's source: in limits_hit, but the names were still all read
    rows = tree_rows(path, deadline, max_members, cov, unread) if is_tree else listing_rows(path, deadline, max_members, cov, unread)
    try:
        for raw, size, link in rows:
            cov["members"] += 1
            plain = raw.replace("\\", "/")
            lower = "/" + plain.lower().lstrip("/")
            base = lower.rsplit("/", 1)[1]
            dot = base.rfind(".")
            suffix = base[dot:] if dot > 0 else ""
            profile = PROFILE.search(lower)
            owner = profile.group(1) if profile else ""
            if suffix in document_suffixes:
                if base.startswith("~$"):
                    cov["owner_files_skipped"] = cov.get("owner_files_skipped", 0) + 1
                elif len(documents) < MAX_DOCUMENTS:
                    documents.append((raw, lower, base, suffix, size, owner))
                    if link:
                        linked.add(raw)
                else:
                    cov["limits_hit"].append("documents: more than %d macro-capable documents; the list was not read further and the rest were not scored" % MAX_DOCUMENTS)
                    unread.add("documents_past_the_cap", 1, "more than %d macro-capable documents: the list was not read further" % MAX_DOCUMENTS)
                    break
            elif suffix == ".lnk" and ("/microsoft/windows/recent/" in lower or "/microsoft/office/recent/" in lower):
                shortcut = base[:-4]
                dot = shortcut.rfind(".")
                if dot > 0 and shortcut[dot:] in document_suffixes:      # only a shortcut of a document can be a signal
                    if owner in recent.get(shortcut, ()):
                        pass
                    elif recent_pairs < MAX_RECENT:
                        recent[shortcut].add(owner)
                        recent_pairs += 1
                    else:
                        if not cov.get("recent_cut"):
                            cov["recent_cut"] = True
                            source_limits.append("recent: more than %d Recent shortcuts of documents; the names of the rest were not kept" % MAX_RECENT)
                        unread.add("recent_shortcuts_past_the_cap", 1, "more than %d Recent shortcuts of documents: the names of the rest were not kept as a signal" % MAX_RECENT)
            elif base == "ntuser.dat" and owner and lower.endswith("/%s/ntuser.dat" % owner) and not link:
                # Only a tree's hives are searched (a member list has names only): a list keeps none of them, and counts them.
                hives_seen += 1
                if is_tree:
                    if owner in hives or len(hives) < MAX_HIVES:
                        hives[owner] = raw
                    else:
                        if not cov.get("hives_cut"):
                            cov["hives_cut"] = True
                            source_limits.append("hives: more than %d profiles' NTUSER.DAT; the names were searched for in the first %d only" % (MAX_HIVES, MAX_HIVES))
                        unread.add("hives_past_the_cap", 1, "more than %d profiles' NTUSER.DAT: the rest were not searched for the names" % MAX_HIVES)
            elif suffix == ".pf" and "/prefetch/" in lower and base.split("-")[0] in applications:
                prefetch.add(base.split("-")[0])
            if ANTIVIRUS.search(lower) and not link:
                antivirus_seen += 1
                if len(antivirus) < MAX_ANTIVIRUS:
                    antivirus.append(raw)
                elif antivirus_seen == MAX_ANTIVIRUS + 1 and is_tree:
                    source_limits.append("antivirus: more than %d antivirus logs and detection files; the names were searched for in the first %d only" % (MAX_ANTIVIRUS, MAX_ANTIVIRUS))
    except (OSError, ValueError) as exc:
        cov["errors"].append("the %s could not be read to its end: %s" % ("tree" if is_tree else "list", getattr(exc, "strerror", None) or exc.__class__.__name__))
        unread.add("walk_errors", 1, "the %s could not be read to its end" % ("tree" if is_tree else "list"))
    if antivirus_seen > MAX_ANTIVIRUS and is_tree:
        cov["antivirus_files_not_searched"] = antivirus_seen - MAX_ANTIVIRUS
        unread.add("antivirus_files_not_searched", antivirus_seen - MAX_ANTIVIRUS, "more than %d antivirus logs and detection files: the rest were not searched for the names" % MAX_ANTIVIRUS)
    if cov.get("links_not_followed"):
        unread.add("links_not_followed", cov["links_not_followed"], "%d link(s) in the tree were not followed: each is ranked by its own name only, and what it points at was not read" % cov["links_not_followed"])
    outside = cov.get("links_to_directories_outside", 0)
    # A member list is the whole of its object only when its own coverage record says so: a list cut by the recipe that wrote it (a
    # missing segment, a limit) is read to its end here and is still not the whole member list.
    list_cov = None if is_tree else list_coverage(path)
    read_to_the_end = not any(unread.counts[n] for n in NAME_COUNTERS)
    if list_cov is not None and list_cov["status"] != "complete":
        unread.add("member_list_not_known_whole", 1, "the member list itself is not known to be whole: its coverage record (%s) says %s%s" % (
            esc(os.path.basename(list_cov["read_from"])), list_cov["status"], ": %s" % list_cov["why"][0] if list_cov.get("why") else ""))
    whole = not any(unread.counts[n] for n in NAME_COUNTERS)
    cov["limits_hit"] += source_limits

    # What the files themselves say, in a tree: a VBA project inside, the name in the profile's hive, the name in an antivirus log.
    vba = {}
    hive_names, antivirus_names, read_notes = {}, set(), []
    if is_tree:
        vba_limits, not_told, first_not_told = collections.Counter(), 0, None
        for number, (raw, _lower, _base, suffix, _size, _owner) in enumerate(documents):
            if time.monotonic() > deadline:
                cov["limits_hit"].append("seconds: the clock ran out before %d of the %d documents were looked into for a VBA project" % (len(documents) - number, len(documents)))
                unread.add("documents_not_looked_into", len(documents) - number, "the clock ran out before every document was looked into for a VBA project")
                break
            if raw in linked:
                vba[raw] = (None, "it is a link, which is not followed: only its name was read")
                continue
            has, how, limit = vba_in_file(os.path.join(path, raw), MACRO_NAMES.get(suffix) or LEGACY_NAMES.get(suffix) or PLAIN_OOXML.get(suffix), deadline)
            vba[raw] = (has, how)
            if has is None:
                if limit:
                    vba_limits[limit] += 1
                    unread.add("documents_vba_not_told_by_a_limit", 1, "whether a VBA project is inside was not told for a document a limit of the recipe stopped (a size, a ZIP directory's records, the clock)")
                else:
                    not_told += 1
                    first_not_told = first_not_told or "%s (%s)" % (esc(raw)[:200], how)
                    unread.add("documents_vba_not_told", 1, "whether a VBA project is inside could not be told for a document, ranked with that said in its row")
        for limit, count in sorted(vba_limits.items()):
            cov["limits_hit"].append("%s (%d document%s: ranked, with whether a VBA project is inside not told)" % (limit, count, "" if count == 1 else "s"))
        if not_told:
            read_notes.append("whether a VBA project is inside could not be told for %d document(s), each ranked with that said in its row; the first: %s" % (not_told, first_not_told))
        # A document under a plain name is a candidate unless its own directory says it holds no VBA project: one that could not be told
        # (or was not looked into) is ranked, and says so.
        documents = [d for d in documents if d[3] not in PLAIN_OOXML or vba.get(d[0], (None,))[0] is not False]
        index = name_index(sorted({d[2] for d in documents}))
        if index[2] and (hives or antivirus):
            cov["names_not_searched_in_bytes"] = index[2]
            read_notes.append("%d document name(s) are not text (bytes that are not UTF-8): they were not searched for in the hives and the antivirus files" % index[2])
            unread.add("names_not_searched_in_bytes", index[2], "document names that are not text (bytes that are not UTF-8) were not searched for in the hives and the antivirus files")
        searched = collections.Counter()
        # Every file searched reads the clock before it is opened: a run of many hives or logs ends at its seconds, and the files it did not
        # reach are counted, never passed over in silence.
        sources = [("hive", owner, hive) for owner, hive in sorted(hives.items())] + [("antivirus", None, log) for log in antivirus]
        for number, (what, owner, rel) in enumerate(sources):
            if time.monotonic() > deadline:
                searched["seconds"] += len(sources) - number
                unread.add("files_not_searched_past_the_clock", len(sources) - number, "the clock ran out before every registry hive and antivirus file was searched for the names")
                break
            full = os.path.join(path, rel)
            if what == "antivirus" and (not os.path.isfile(full) or os.path.islink(full)):
                read_notes.append("an antivirus file is no longer a regular file and was not searched: %s" % esc(rel)[:200])
                unread.add("files_not_read_to_their_end", 1, "a registry hive or an antivirus file could not be read to its end")
                continue
            found, cut = names_in_file(full, index, deadline)
            if what == "hive":
                hive_names[owner] = found
            else:
                antivirus_names |= found
            if cut == "error":
                read_notes.append("the registry hive of %s could not be read to its end" % esc(owner) if what == "hive" else "an antivirus file could not be read to its end: %s" % esc(rel)[:200])
                unread.add("files_not_read_to_their_end", 1, "a registry hive or an antivirus file could not be read to its end")
            elif cut == "seconds":
                searched["seconds"] += 1
                unread.add("files_not_searched_past_the_clock", 1, "the clock ran out before every registry hive and antivirus file was searched for the names")
            elif cut == "size":
                searched["size"] += 1
                unread.add("files_searched_only_in_part", 1, "a registry hive or an antivirus file over %d bytes was searched only that far for the names" % SCAN_BYTES)
        if searched["seconds"]:
            cov["limits_hit"].append("seconds: the clock ran out before %d registry hive(s) or antivirus file(s) were searched to their end for the names" % searched["seconds"])
        if searched["size"]:
            cov["limits_hit"].append("scan: %d registry hive(s) or antivirus file(s) are over %d bytes and were searched only that far for the names" % (searched["size"], SCAN_BYTES))

    scored = []
    for raw, lower, base, suffix, size, owner in documents:
        kind = MACRO_NAMES.get(suffix) or LEGACY_NAMES.get(suffix) or PLAIN_OOXML.get(suffix)
        score, signals = 0, []
        if suffix in MACRO_NAMES:
            score += 3
            signals.append("+3 a macro-enabled name (%s)" % suffix)
        elif suffix in LEGACY_NAMES:
            score += 1
            signals.append("+1 a legacy Office name (%s), a format that can hold macros" % suffix)
        if is_tree and raw not in vba:
            signals.append("+0 not looked into for a VBA project: the clock ran out first")
        if raw in vba:
            has, how = vba[raw]
            if has:
                score += 4
                signals.append("+4 a VBA project inside, by %s" % how)
                if suffix in PLAIN_OOXML:
                    score += 3
                    signals.append("+3 its name (%s) is not a macro-enabled one: the name does not say what the file holds" % suffix)
            elif has is False and suffix in MACRO_NAMES:
                score -= 1
                signals.append("-1 no VBA project inside, by %s" % how)
            elif has is None:
                signals.append("+0 not told whether it holds a VBA project: %s" % how)
        if raw in linked:
            signals.append("+0 a link in the tree: not followed, so only its own name was read")
        if any(mark in lower for mark in USUAL):
            signals.append("+0 in a usual document folder")
        else:
            where = next((what for mark, what in DELIVERY if mark in lower), None)
            if ARCHIVE_TEMP.search(lower):
                score += 3
                signals.append("+3 inside a folder an archive program unpacks to")
            elif where:
                score += 3
                signals.append("+3 in %s" % where)
            elif any(mark in lower for mark in DOWNLOADS):
                score += 2
                signals.append("+2 in a downloads folder")
            elif owner:
                score += 2
                signals.append("+2 inside the profile but outside its usual document folders")
            else:
                score += 2
                signals.append("+2 outside every user profile")
        if base in recent:
            same = owner in recent[base] or not owner
            score += 3 if same else 1
            signals.append("+%d a Recent shortcut carries its name (%s)" % (3 if same else 1, "the same profile" if same else "another profile"))
        if owner in hive_names and base in hive_names[owner]:
            score += 2
            signals.append("+2 its name occurs in the bytes of the profile's NTUSER.DAT (where an Office MRU keeps names; the key was not read)")
        if base in antivirus_names:
            score += 4
            signals.append("+4 its name occurs in the bytes of an antivirus log or detection file (the event was not read)")
        if APPLICATION[kind].lower() in prefetch:
            score += 1
            signals.append("+1 a Prefetch file of %s exists (the application ran; which files it loaded was not read)" % APPLICATION[kind])
        scored.append((score, raw, kind, size, owner, signals))
    scored.sort(key=lambda s: (-s[0], s[1].lower()))
    # Every scored document is a row (at most MAX_DOCUMENTS, a limit that is in limits_hit when it is met): the ranking is never cut here.
    shown = esc if is_tree else esc_listed
    _write_text_whole(os.path.join(out_dir, "candidates.tsv"), "".join(
        ["\t".join(COLUMNS) + "\n"] + ["%d\t%d\t%s\t%s\t%s\t%s\t%s\n" % (rank, score, shown(raw), kind, "" if size is None else size, esc(owner), "; ".join(signals))
                                       for rank, (score, raw, kind, size, owner, signals) in enumerate(scored, 1)]))
    cov["candidates"] = len(scored)
    cov["whole_list_read"] = whole
    cov["list_read_to_its_end"] = read_to_the_end
    if list_cov is not None:
        cov["list_coverage"] = list_cov
        if list_cov["status"] != "complete":
            read_notes.insert(0, "the member list itself is not known to be whole: its coverage record (%s) says %s%s" % (
                esc(os.path.basename(list_cov["read_from"])), list_cov["status"], ": %s" % list_cov["why"][0] if list_cov.get("why") else ""))
    if cov.get("links_not_followed"):
        read_notes.append("%d link(s) in the tree were not followed: each is ranked by its own name only, and what it points at was not read" % cov["links_not_followed"])
    if outside:
        read_notes.insert(0, "%d link(s) in the tree lead to a directory outside it, which was not entered: the file names below them were not read" % outside)
    if cov.get("rows_without_a_path"):
        read_notes.append("%d row(s) of the list have no cell in its path column: their names were not read" % cov["rows_without_a_path"])
    if cov.get("lines_of_another_form"):
        read_notes.append("%d line(s) of the list are outside the forms this recipe reads (%s)" % (cov["lines_of_another_form"], cov.get("list_form", "a TSV with a path column, or a path a line")))
    cov["sources"] = {"recent_shortcuts": recent_pairs, "registry_hives": len(hives) if is_tree else hives_seen, "antivirus_files": len(antivirus), "prefetch_applications": sorted(prefetch & {a.lower() for a in APPLICATION.values()})}
    if read_notes:
        cov["not_read_to_the_end"] = read_notes[:20]
    cov["covered"] = ("%s file name%s of the %s (%d), ranked for macro-capable Office documents by their name%s, their folder, a Recent shortcut of the same name and the document application's Prefetch file%s"
                      % ("every" if read_to_the_end else "the first", "" if read_to_the_end else "s read", "tree" if is_tree else "member list", cov["members"], ", a VBA project inside (the ZIP directory, or the OLE directory name)" if is_tree else "",
                         ", and their name in the bytes of the profile's NTUSER.DAT and of the antivirus files" if is_tree else ""))
    cov["not_covered"] = ("no macro was read or run and no document was opened as a document; the registry key, the event record and the Prefetch file's list were not parsed (regkv, evtx_query and prefetch_mam of the Windows pack read them); "
                          + ("a member list has names only: nothing inside a file was read, so a macro in a file named .docx, the registry and the antivirus logs are not in the ranking; " if not is_tree else "")
                          + "other first stages (a shortcut, a script, an installer, a disc image, a OneNote file) are not ranked; a name that occurs in a hive or a log is a lead to the record, not the record")
    # The status is derived from the one list of what was not read or not judged, and from nothing else.
    status = "partial" if unread else "complete"
    cov["status"] = status
    cov["not_read_or_judged"] = dict(unread.counts)
    cov["status_basis"] = ("the whole %s was read (%d members)%s and every macro-capable document in it is ranked (%d)" % (
                               "tree" if is_tree else "member list", cov["members"], "" if is_tree else ", its own coverage record says the list is complete,", len(scored))
                           if status == "complete" else
                           "the ranking is of part of what was asked: %s" % "; ".join(unread.reasons()[:5]))
    cov["seconds"] = round(time.monotonic() - started, 2)
    _write_json_whole(os.path.join(out_dir, "coverage.json"), cov, indent=2)
    _write_text_whole(os.path.join(out_dir, "index.tsv"),
                      "candidates.tsv\tfirst-stage candidates (%d), ranked: rank, score, path, kind, size, profile, signals; each signal says what it adds and what was not read\n" % len(scored))
    print_answer({"ok": True, "status": status, "members": cov["members"], "candidates": len(scored), "whole_list_read": whole,
                  "not_read_or_judged": dict(unread.counts),
                  **({"list_coverage": list_cov["status"]} if list_cov is not None else {}), "rule": cov["rule"],
                  "first": [{"rank": i + 1, "score": s[0], "path": shown(s[1])[:300], "signals": len(s[5])} for i, s in enumerate(scored[:5])], "status_basis": cov["status_basis"]})
    return 0


def main(argv):
    if len(argv) < 2 or argv[1] not in ("detect", "run"):
        print_answer({"ok": False, "applies": "unknown", "error": "usage: run.py detect --target T | run --target T --out DIR"})
        return 2
    args = dict(zip(argv[2::2], argv[3::2]))
    if "--target" not in args:
        print_answer({"ok": False, "applies": "unknown", "error": "--target is required"})
        return 2
    _t, path = target_of(args["--target"])
    if argv[1] == "detect":
        applies, why = detect(path)
        print_answer({"applies": applies, "why": why})
        return 0 if applies is True else 2 if applies == "unknown" else 1
    if "--out" not in args:
        print_answer({"ok": False, "status": "failed", "error": "run needs --out DIR", "status_basis": "no output directory was given, so nothing was run"})
        return 2
    if not os.path.isdir(path) and not os.path.isfile(path):
        print_answer({"ok": False, "status": "failed", "status_basis": "the target is neither a directory nor a regular file, so nothing was run", "error": "not a directory or a regular file"})
        return 2
    return run(path, args["--out"])


if __name__ == "__main__":
    exit_code = 0
    try:
        sys.exit(main(sys.argv))
    except SystemExit as stop:
        exit_code = _code(stop)
    _leave(exit_code)
