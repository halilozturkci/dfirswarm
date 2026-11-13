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
import sys
import time
import zipfile


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
        with open(tmp, "w") as fh:
            json.dump(doc, fh, **dumps_kwargs)
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
VERSION = "1.0.0"
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
ANTIVIRUS = re.compile(r"(microsoft-windows-windows defender%4(operational|whc)\.evtx|/mplog-[^/]*\.log|/detectionhistory/|/windows defender/support/|/quarantine/)", re.I)
VBA_OLE = "_VBA_PROJECT".encode("utf-16-le")
MAX_MEMBERS = 5_000_000
MAX_CANDIDATES = 20000
SCAN_BYTES = 512 << 20            # the most of one hive or log file that is searched for names
OLE_BYTES = 64 << 20


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


def listing_rows(path, deadline, max_members, cov):
    """The paths of a member list: a TSV whose header has a `path` column (and maybe `type` and `size`), or a path a line. Backslashes are
    read as separators. Yields (path, size or None)."""
    with open_regular(path) as raw:
        column = size_column = type_column = None
        first = True
        for number, line in enumerate(raw):
            if number % 4096 == 0 and time.monotonic() > deadline:
                cov["limits_hit"].append("seconds: the clock ran out after %d lines of the list" % number)
                return
            if cov["members"] >= max_members:
                cov["limits_hit"].append("members: the list has more than %d rows" % max_members)
                return
            text = line.rstrip(b"\r\n").decode("utf-8", "surrogateescape")
            if first:
                first = False
                cells = text.split("\t")
                if "path" in cells:
                    column = cells.index("path")
                    size_column = cells.index("size") if "size" in cells else None
                    type_column = cells.index("type") if "type" in cells else None
                    cov["list_form"] = "a TSV with a path column (column %d)" % (column + 1)
                    continue
                cov["list_form"] = "a path a line"
            if not text:
                continue
            if column is None:
                yield text, None
                continue
            cells = text.split("\t")
            if column >= len(cells):
                cov["rows_without_a_path"] = cov.get("rows_without_a_path", 0) + 1
                continue
            if type_column is not None and type_column < len(cells) and cells[type_column] in ("folder", "dir", "directory", "d"):
                cov["members"] += 1
                continue
            size = None
            if size_column is not None and size_column < len(cells) and cells[size_column].isdigit():
                size = int(cells[size_column])
            yield cells[column], size


def tree_rows(root, deadline, max_members, cov):
    """Every file below a directory, links never followed: (path relative to it, size)."""
    stack = [""]
    while stack:
        rel = stack.pop()
        if time.monotonic() > deadline:
            cov["limits_hit"].append("seconds: the clock ran out inside %s; %d directories were not entered" % (esc(rel) or "the tree's root", len(stack) + 1))
            return
        try:
            with os.scandir(os.path.join(root, rel) if rel else root) as entries:
                listed = sorted(entries, key=lambda e: e.name)
        except OSError as exc:
            cov["errors"].append("a directory could not be listed (%s): %s" % (getattr(exc, "strerror", None) or exc.__class__.__name__, esc(rel)[:200]))
            continue
        for entry in listed:
            name = os.path.join(rel, entry.name) if rel else entry.name
            try:
                if entry.is_symlink():
                    cov["links_not_followed"] = cov.get("links_not_followed", 0) + 1
                elif entry.is_dir(follow_symlinks=False):
                    stack.append(name)
                elif entry.is_file(follow_symlinks=False):
                    if cov["members"] >= max_members:
                        cov["limits_hit"].append("members: the tree has more than %d files" % max_members)
                        return
                    yield name, entry.stat(follow_symlinks=False).st_size
            except OSError:
                cov["errors"].append("an entry could not be read: %s" % esc(name)[:200])


def vba_in_file(path, kind, deadline):
    """What the file's own bytes say about a VBA project: (True | False | None when it could not be told, how)."""
    try:
        if os.path.getsize(path) > SCAN_BYTES:
            return None, "it is over %d bytes: not looked into" % SCAN_BYTES
        with open_regular(path) as fh:
            head = fh.read(8)
            if head[:4] == b"PK\x03\x04":
                try:
                    with zipfile.ZipFile(fh) as archive:
                        names = []
                        for info in archive.infolist():
                            names.append(info.filename.lower())
                            if len(names) > 20000:
                                return None, "its ZIP directory has more than 20,000 members: not read"
                        return any(n.endswith("vbaproject.bin") for n in names), "the member list of its ZIP directory (no member was opened)"
                except (zipfile.BadZipFile, OSError, ValueError, NotImplementedError, RuntimeError):
                    return None, "it begins like a ZIP and its directory does not read"
            if head == b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1":
                fh.seek(0)
                read, tail = 0, b""
                while read < OLE_BYTES:
                    if time.monotonic() > deadline:
                        return None, "the clock ran out while it was read"
                    block = fh.read(1 << 20)
                    if not block:
                        return False, "a search of its bytes for the directory name _VBA_PROJECT (UTF-16LE)"
                    if VBA_OLE in tail + block:
                        return True, "a search of its bytes for the directory name _VBA_PROJECT (UTF-16LE)"
                    read += len(block)
                    tail = block[-len(VBA_OLE):]
                return None, "it is over %d bytes: only that much was searched" % OLE_BYTES
            return None, "it is neither a ZIP nor an OLE compound file by its first bytes (its name says %s)" % kind
    except (OSError, ValueError):
        return None, "it could not be opened"


def names_in_file(path, names, deadline):
    """Which of the names (lower-case strings) occur in a file's bytes as UTF-16LE or UTF-8, case folded for ASCII: a set, and whether
    the whole file was read."""
    found = set()
    patterns = {}
    for name in names:
        try:
            patterns[name] = (name.encode("utf-16-le"), name.encode("utf-8"))
        except UnicodeError:
            continue
    longest = max((len(p[0]) for p in patterns.values()), default=0)
    try:
        with open_regular(path) as fh:
            read, tail = 0, b""
            while read < SCAN_BYTES:
                if time.monotonic() > deadline:
                    return found, False
                block = fh.read(4 << 20)
                if not block:
                    return found, True
                window = (tail + block).lower()
                for name, (wide, narrow) in patterns.items():
                    if name not in found and (wide in window or narrow in window):
                        found.add(name)
                read += len(block)
                tail = block[-longest:] if longest else b""
            return found, False
    except (OSError, ValueError):
        return found, False


def detect(path):
    """(True | False | "unknown", why). A directory applies when a profile folder is within three levels of it; a list when one of its
    first lines names a profile path."""
    try:
        st = os.stat(path)
    except (OSError, ValueError) as exc:
        return "unknown", "the target cannot be read: %s" % (getattr(exc, "strerror", None) or exc.__class__.__name__)
    if stat.S_ISDIR(st.st_mode):
        level, seen = [path], 0
        for _depth in range(4):
            below = []
            for directory in level:
                try:
                    with os.scandir(directory) as entries:
                        for entry in entries:
                            seen += 1
                            if seen > 20000:
                                return "unknown", "more than 20,000 entries in the first levels of the tree: not told"
                            if entry.is_dir(follow_symlinks=False):
                                if entry.name.lower() in ("users", "documents and settings"):
                                    return True, "a profile folder (%s) is in the tree" % entry.name
                                below.append(entry.path)
                            elif entry.name.lower() == "ntuser.dat":
                                return True, "a user's registry hive is in the tree: it is a profile"
                except OSError:
                    continue
            level = below
        return False, "no Users or Documents and Settings folder and no NTUSER.DAT within three levels of the directory"
    if not stat.S_ISREG(st.st_mode):
        return False, "neither a directory nor a regular file"
    try:
        with open_regular(path) as fh:
            head = fh.read(4 << 20)
    except (OSError, ValueError) as exc:
        return "unknown", "the list cannot be read: %s" % (getattr(exc, "strerror", None) or exc.__class__.__name__)
    if b"\x00" in head[:4096]:
        return False, "not a text list (it holds NUL bytes)"
    if PROFILE.search(head.decode("utf-8", "replace").replace("\\", "/")):
        return True, "the list names paths inside a user profile"
    return False, "no path of a user profile in the first %d bytes of the list" % len(head)


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
           "rule": "To answer \"cannot be determined\" to a \"which file\" question the whole member list must have been searched: whole_list_read says whether it was. "
                   "A ranking is a list of candidates with the signals each one has, not a finding: the first row is where to look first."}
    _write_json_whole(os.path.join(out_dir, "coverage.json"), dict(cov, status="partial", whole_list_read=False, status_basis="the run had started and had read nothing yet"), indent=2)

    def _stopped(signum):
        _write_json_whole(os.path.join(out_dir, "coverage.json"), dict(cov, status="partial", whole_list_read=False, interrupted=True, signal=signum,
                          status_basis="the recipe was stopped by signal %d after %d members: no ranking was written, and nothing is claimed about the list" % (signum, cov["members"])), indent=2)
        print(json.dumps({"ok": False, "status": "partial", "interrupted": True, "signal": signum, "members": cov["members"]}), flush=True)
    install_signal_handlers(_stopped)

    documents, recent, hives, antivirus, prefetch = [], collections.defaultdict(set), {}, [], set()
    rows = tree_rows(path, deadline, max_members, cov) if is_tree else listing_rows(path, deadline, max_members, cov)
    try:
        for raw, size in rows:
            cov["members"] += 1
            plain = raw.replace("\\", "/")
            lower = "/" + plain.lower().lstrip("/")
            base = lower.rsplit("/", 1)[1]
            dot = base.rfind(".")
            suffix = base[dot:] if dot > 0 else ""
            profile = PROFILE.search(lower)
            owner = profile.group(1) if profile else ""
            if suffix in MACRO_NAMES or suffix in LEGACY_NAMES or (is_tree and suffix in PLAIN_OOXML):
                if base.startswith("~$"):
                    cov["owner_files_skipped"] = cov.get("owner_files_skipped", 0) + 1
                elif len(documents) < MAX_CANDIDATES * 5:
                    documents.append((raw, lower, base, suffix, size, owner))
                else:
                    cov["limits_hit"].append("candidates: more than %d documents; the rest were not scored" % (MAX_CANDIDATES * 5))
                    break
            elif suffix == ".lnk" and ("/microsoft/windows/recent/" in lower or "/microsoft/office/recent/" in lower):
                recent[base[:-4]].add(owner)
            elif base == "ntuser.dat" and owner and lower.endswith("/%s/ntuser.dat" % owner):
                hives[owner] = raw
            elif suffix == ".pf" and "/prefetch/" in lower:
                prefetch.add(base.split("-")[0])
            if ANTIVIRUS.search(lower) and len(antivirus) < 400:
                antivirus.append(raw)
    except (OSError, ValueError) as exc:
        cov["errors"].append("the %s could not be read to its end: %s" % ("tree" if is_tree else "list", getattr(exc, "strerror", None) or exc.__class__.__name__))
    whole = not cov["limits_hit"] and not cov["errors"]

    # What the files themselves say, in a tree: a VBA project inside, the name in the profile's hive, the name in an antivirus log.
    vba = {}
    hive_names, antivirus_names, read_notes = {}, set(), []
    names = sorted({d[2] for d in documents})
    if is_tree:
        for raw, _lower, _base, suffix, _size, _owner in documents:
            if time.monotonic() > deadline:
                cov["limits_hit"].append("seconds: the clock ran out before every document was looked into for a VBA project")
                break
            vba[raw] = vba_in_file(os.path.join(path, raw), MACRO_NAMES.get(suffix) or LEGACY_NAMES.get(suffix) or PLAIN_OOXML.get(suffix), deadline)
        documents = [d for d in documents if d[3] not in PLAIN_OOXML or vba.get(d[0], (None,))[0]]
        names = sorted({d[2] for d in documents})
        for owner, hive in sorted(hives.items()):
            found, all_read = names_in_file(os.path.join(path, hive), names, deadline)
            hive_names[owner] = found
            if not all_read:
                read_notes.append("the registry hive of %s was not searched to its end" % esc(owner))
        for log in antivirus:
            if os.path.isfile(os.path.join(path, log)):
                found, all_read = names_in_file(os.path.join(path, log), names, deadline)
                antivirus_names |= found
                if not all_read:
                    read_notes.append("an antivirus file was not searched to its end: %s" % esc(log)[:200])

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
    kept = scored[:MAX_CANDIDATES]
    tmp = os.path.join(out_dir, "candidates.tsv.tmp")
    temp_hold(tmp)
    with open(tmp, "w", encoding="utf-8", newline="\n") as fh:
        fh.write("\t".join(COLUMNS) + "\n")
        for rank, (score, raw, kind, size, owner, signals) in enumerate(kept, 1):
            fh.write("%d\t%d\t%s\t%s\t%s\t%s\t%s\n" % (rank, score, esc(raw), kind, "" if size is None else size, esc(owner), "; ".join(signals)))
    temp_replace(tmp, os.path.join(out_dir, "candidates.tsv"))
    cov["candidates"] = len(scored)
    cov["whole_list_read"] = whole
    cov["sources"] = {"recent_shortcuts": sum(len(v) for v in recent.values()), "registry_hives": len(hives), "antivirus_files": len(antivirus), "prefetch_applications": sorted(prefetch & {a.lower() for a in APPLICATION.values()})}
    if read_notes:
        cov["not_read_to_the_end"] = read_notes[:20]
    cov["covered"] = ("every file name of the %s (%d), ranked for macro-capable Office documents by their name%s, their folder, a Recent shortcut of the same name and the document application's Prefetch file%s"
                      % ("tree" if is_tree else "member list", cov["members"], ", a VBA project inside (the ZIP directory, or the OLE directory name)" if is_tree else "",
                         ", and their name in the bytes of the profile's NTUSER.DAT and of the antivirus files" if is_tree else ""))
    cov["not_covered"] = ("no macro was read or run and no document was opened as a document; the registry key, the event record and the Prefetch file's list were not parsed (regkv, evtx_query and prefetch_mam of the Windows pack read them); "
                          + ("a member list has names only: nothing inside a file was read, so a macro in a file named .docx, the registry and the antivirus logs are not in the ranking; " if not is_tree else "")
                          + "other first stages (a shortcut, a script, an installer, a disc image, a OneNote file) are not ranked; a name that occurs in a hive or a log is a lead to the record, not the record")
    status = "complete" if whole and not read_notes else "partial"
    cov["status"] = status
    cov["status_basis"] = ("the whole %s was read (%d members) and every macro-capable document in it is ranked (%d)" % ("tree" if is_tree else "member list", cov["members"], len(scored)) if status == "complete" else
                           "the ranking is of part of what was asked: %s" % "; ".join((cov["limits_hit"] + cov["errors"] + read_notes)[:5]))
    cov["seconds"] = round(time.monotonic() - started, 2)
    _write_json_whole(os.path.join(out_dir, "coverage.json"), cov, indent=2)
    with open(os.path.join(out_dir, "index.tsv"), "w", encoding="utf-8") as fh:
        fh.write("candidates.tsv\tfirst-stage candidates (%d), ranked: rank, score, path, kind, size, profile, signals; each signal says what it adds and what was not read\n" % len(kept))
    print_answer({"ok": True, "status": status, "members": cov["members"], "candidates": len(scored), "whole_list_read": whole, "rule": cov["rule"],
                  "first": [{"rank": i + 1, "score": s[0], "path": esc(s[1])[:300], "signals": len(s[5])} for i, s in enumerate(kept[:5])], "status_basis": cov["status_basis"]})
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
