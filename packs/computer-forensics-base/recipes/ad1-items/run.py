#!/usr/bin/env python3
"""ad1-items: the item list of an AccessData AD1 logical image, each file's
content inflated to check the digests the image records; nothing extracted.

    run.py detect --target TARGET [--probe-out DIR]   exit 0 applies, 1 does not, 2 error
    run.py run --target TARGET --out DIR              members.tsv, attributes.tsv, image.json,
                                                      index.tsv and coverage.json in DIR

TARGET is JSON (inline or a file path): {"paths": [...], "ref": ..., "name": ...};
the image is paths[0], its first segment; paths[1:] are its further segments
when given, else they are looked for beside it (x.ad2, x.ad3, ...). Every
item is one row of members.tsv:

    n  type  path  path_b64  size  packed  mtime  tz  mode  uid  gid  link  locator  flags
    atime  btime  md5  sha1  sha256  check  class

The first fourteen columns are archive-members' own, so catalog_search
which=members and a member:<generation>#<n> reference read it the same way.
`n` counts from 0 in the image's own order (an item, its children, then its
next sibling) and is what ad1_extract takes; a folder's n takes its subtree.
When the listing is partial (a segment missing, an item that cannot be
read), the items after a break are numbered without it, so a whole read
numbers them otherwise: `locator` (ad1:item=<address>) names an item the
same way in both, and ad1_extract takes it too. `path` is the item's names
joined by "/" under the image's data source name (image.json), escaped as
archive-members escapes them, and `path_b64` its exact bytes. `type` is
file, dir or other:<n>; an item the image marks as a file of unknown kind or
as deleted is a file, flagged so. `size` is the content's size, `packed` the
bytes of its zlib chunks. The times are the image's own text, as dissect
reads them: mtime the modified time (key 0x9), atime the accessed (0x7),
btime the created (0x8), with no zone the image records (`tz` is unknown).
`md5` and `sha1` are the digests the image records for the item; `sha256`
is of the content as this recipe inflated it; `check` says whether that
content matches the recorded digests: ok, mismatch, no-stored-hash, or
not-read (why is in coverage.json). `class` is the file class the image
records (regular file, folder, reparse point, ...). `flags` names what an
examiner should know first: escapes-root (a name that is empty, "." or
"..", or holds a "/"), name-not-utf8, hash-mismatch, unknown-file, deleted,
and encrypted (the source file system's encryption flag: the content may be
ciphertext). attributes.tsv holds every metadata entry of every item (n,
category, key, label, text), so nothing the image records is left out; an item
that has the same metadata chain as an earlier item (the chain starts at one
address) gets one row, label same-chain, naming that item, so a chain the
image shares is written once. The entries written cannot add up to more than
the bytes the image holds (entries sit at their own addresses): past that,
chains overlap, attributes.tsv stops at the item named in limits_hit, and the
items after it are still listed. image.json holds the segment and logical
image headers and the image's own metadata (its data source name).

The listing has a clock of its own, later than the one that stops a file's
content being inflated: it stops at 97% of the recipe's seconds
(RECIPE_LISTING_SECONDS sets the seconds), says where, and the items after
that point are not listed. The walk cannot count items (the format has none),
so it keeps the byte ranges it reached and counts the data no item, name,
metadata entry, chunk table or chunk led to (zero bytes are padding):
non-zero bytes there make the coverage partial and integrity_status
unverified (unreferenced_nonzero_bytes).
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
import hashlib
import json
import os
import re
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

HERE = os.path.dirname(os.path.abspath(__file__))
MAX_ITEMS = 5_000_000
COLUMNS = ["n", "type", "path", "path_b64", "size", "packed", "mtime", "tz", "mode", "uid", "gid", "link", "locator", "flags",
           "atime", "btime", "md5", "sha1", "sha256", "check", "class"]
# The metadata keys as dissect.evidence names them (its MetaType); a key
# not here keeps its number, and attributes.tsv has every one.
LABELS = {
    0x01: "content hashes", 0x02: "file class", 0x03: "file size", 0x04: "physical size", 0x05: "timestamps",
    0x06: "start cluster", 0x07: "accessed", 0x08: "created", 0x09: "modified", 0x0D: "encrypted", 0x0E: "compressed",
    0x1E: "actual file", 0x1F: "start sector", 0x24: "alternate data streams",
    0x1001: "short name", 0x1002: "hidden", 0x1003: "system", 0x1004: "read-only", 0x1005: "archive",
    0x2001: "POSIX permissions", 0x5001: "md5", 0x5002: "sha1",
    0x9001: "cluster size", 0x9002: "cluster count", 0x9003: "free clusters", 0x9006: "volume serial number",
    0xA001: "MFT record number", 0xA002: "MFT record changed", 0xA003: "MFT resident", 0xA004: "MFT offline",
    0xA005: "MFT sparse", 0xA006: "MFT temporary", 0xA007: "owner SID", 0xA008: "owner name", 0xA009: "group SID",
    0xA00A: "group name", 0xA01C: "$FILE_NAME created", 0xA01D: "$FILE_NAME modified", 0xA01E: "$FILE_NAME accessed",
    0xA01F: "$FILE_NAME changed", 0xA020: "$FILE_NAME size", 0xA021: "$FILE_NAME physical size", 0xA028: "$I30 name",
    0xA029: "$I30 size", 0xA02A: "$I30 physical size", 0xA02B: "$I30 created", 0xA02C: "$I30 modified",
    0xA02D: "$I30 accessed", 0xA02E: "$I30 changed", 0x10002: "data source name",
}
CLASSES = {b"1": "regular file", b"2": "placeholder", b"3": "folder", b"4": "file system metadata", b"6": "file slack",
           b"9": "symbolic link", b"11": "reparse point"}


# --- AD1 reader ---------------------------------------------------------------
# The same block in recipes/ad1-items/run.py and tools/ad1_extract/run.py;
# tests/ad1-pack.test.ts holds the two equal. An AccessData AD1 logical image
# (FTK Imager's "custom content image") as the public descriptions of the
# format lay it out (dissect.evidence's ad1, AD1-tools' libad1, pyad1):
#
#   every segment file   a header: "ADSEGMENTEDFILE", at 0x18 its number
#                        (from 1), at 0x1c the number of segments, at 0x20
#                        its size in bytes with the header, at 0x28 the
#                        header's own size (512); then its share of the data
#   the image's data     one address space running on from segment to
#                        segment; at address 0 the logical image header:
#                        "ADLOGICALIMAGE", +16 version (4), +24 zlib chunk
#                        size, +28 the image's own metadata, +36 the first
#                        item, +44 the data source name's length, +52 its
#                        address
#   an item              +0 next sibling, +8 first child, +16 first metadata
#                        entry, +24 chunk table, +32 size, +40 type (0 a
#                        file, 1 a file of unknown kind, 2 deleted, 5 a
#                        folder), +44 name length, +48 the name (UTF-8)
#   a metadata entry     +0 next, +8 category, +12 key, +16 length, +20 text
#   a chunk table        +0 count, +8 count + 1 addresses: chunk i is the
#                        zlib stream from address i to address i + 1
#
# Every address is held to the data the segments hold, every chain to one
# visit per address, the tree to a depth, every count to what the image can
# hold and to a ceiling, every chunk to the chunk size and every file to its
# size: a damaged or hostile image is named, never followed. The format has no
# item count, so a walk cannot know it reached every item: it keeps the byte
# ranges it reached (items, names, metadata, chunk tables and chunks) and
# ad1_unaccounted() says how much of the image's data nothing led to.
import array as _array
import bisect as _bisect
import heapq as _heapq
import os as _os
import struct as _struct
import time as _time
import zlib as _zlib

AD1_SEGMENT_MAGIC = b"ADSEGMENTEDFILE\x00"
AD1_LOGICAL_MAGIC = b"ADLOGICALIMAGE"
AD1_ENCRYPTED_MAGIC = b"ADCRYPT"
AD1_VERSION = 4
AD1_FILE, AD1_UNKNOWN_FILE, AD1_DELETED, AD1_FOLDER = 0, 1, 2, 5
AD1_SEGMENTS_MAX = 4096           # 6 TB at FTK Imager's default 1500 MB a segment
AD1_CHUNK_MIN, AD1_CHUNK_MAX = 512, 1 << 24   # FTK Imager writes 65536
AD1_NAME_MAX = 1 << 16
AD1_TEXT_MAX = 1 << 20
AD1_META_MAX = 1 << 16            # entries in one metadata chain
AD1_META_BYTES_MAX = 64 << 20     # bytes of text in one metadata chain
AD1_DEPTH_MAX = 1024
AD1_OPEN_MAX = 64                 # segment files held open at once
AD1_TABLE_BATCH = 4096            # chunk addresses read at a time
AD1_CHUNKS_MAX = 1 << 26          # one file's chunks: 4 TiB at FTK Imager's 64 KiB
AD1_CACHE_MAX = 32 << 20          # bytes (estimated) of the last metadata chains kept, for an item that shares one with an earlier item
AD1_CACHE_CHAINS = 8              # and how many of them
AD1_FOLD_AT = 1 << 16             # reached-range entries held before they are merged
AD1_SLACK = 0                     # non-zero bytes of the data nothing may lead to before the walk is not called whole
AD1_GAP_BLOCK = 1 << 20            # bytes of unreached data read at a time: the clock is looked at before each block
AD1_GAPS_LISTED = 20              # gaps named one by one in the report: those with non-zero bytes, or not read to their end
AD1_GUID_TABLES = (b"ATTRGUID", b"LOCSGUID")   # the two tables FTK Imager leaves after the items; the header points at them


class AD1Error(Exception):
    pass


def ad1_segment_header(head):
    """The segment header's fields from a file's first bytes, or an AD1Error."""
    if head.startswith(AD1_ENCRYPTED_MAGIC):
        raise AD1Error("an encrypted AD1 image (ADCRYPT header): it is read only once decrypted with its key")
    if len(head) < 0x2C or not head.startswith(AD1_SEGMENT_MAGIC):
        raise AD1Error("no ADSEGMENTEDFILE header")
    number, count, size = _struct.unpack_from("<IIQ", head, 0x18)
    header = _struct.unpack_from("<I", head, 0x28)[0]
    if not 0x30 <= header <= 0x10000:
        raise AD1Error("the segment header says it is %d bytes long" % header)
    if not 1 <= count <= AD1_SEGMENTS_MAX:
        raise AD1Error("the segment header says the image has %d segments (this reader takes 1 to %d)" % (count, AD1_SEGMENTS_MAX))
    if not 1 <= number <= count:
        raise AD1Error("the segment header says segment %d of %d" % (number, count))
    if size <= header:
        raise AD1Error("the segment header says a segment is %d bytes, header included" % size)
    return {"index": number, "count": count, "bytes": size, "header": header}


def ad1_where(parent):
    return parent.decode("utf-8", "replace") if parent else "the root"


def open_regular(path):
    """open(path, "rb") for an image path: opened without waiting (O_NONBLOCK) and looked at with fstat on the descriptor, so a FIFO or a device
    (named, or put in the place of the file after it was checked) is refused and never waited on."""
    fd = _os.open(path, _os.O_RDONLY | getattr(_os, "O_NONBLOCK", 0))
    try:
        if _os.fstat(fd).st_mode & 0o170000 != 0o100000:
            raise OSError(22, "is not a regular file")
    except BaseException:
        _os.close(fd)
        raise
    return open(fd, "rb")


class AD1:
    """An AD1 image opened read-only from its first segment (and the paths of
    the rest, when given; else beside it, x.ad2, x.ad3, ...). `missing` names
    the segments that are not there; an address in one of them is an
    AD1Error where it is read. `errors` names what the headers said that
    could not be taken."""

    def __init__(self, first, more=()):
        with open_regular(first) as fh:
            self.segment = ad1_segment_header(fh.read(0x30))
        if self.segment["index"] != 1:
            raise AD1Error("segment %d of %d of an AD1 image: the image is read from its first segment" % (self.segment["index"], self.segment["count"]))
        count = self.segment["count"]
        given = [first] + list(more)
        stem, ext = _os.path.splitext(first)
        beside = ext[1:3].lower() == "ad" and ext[3:] == "1"
        self.paths, self.names, self.missing, self.errors, self.walk_errors = [], [], [], [], []
        self.margins, self.starts, self.actual = [], [0], []
        for k in range(1, count + 1):
            p = given[k - 1] if k <= len(given) else (stem + ext[:-1] + str(k) if beside else None)
            margin, span, present = self.segment["header"], self.segment["bytes"] - self.segment["header"], 0
            if p and _os.path.isfile(p):
                with open_regular(p) as fh:
                    h = ad1_segment_header(fh.read(0x30))
                    size = _os.fstat(fh.fileno()).st_size
                if h["index"] != k or h["count"] != count:
                    raise AD1Error("%s says it is segment %d of %d, where segment %d of %d belongs" % (_os.path.basename(p), h["index"], h["count"], k, count))
                margin, span = h["header"], h["bytes"] - h["header"]
                if size - margin > span:
                    raise AD1Error("%s holds more than the %d bytes of data its header says" % (_os.path.basename(p), span))
                present = size - margin   # the last segment is usually shorter than the size its header declares
            else:
                self.missing.append(_os.path.basename(p) if p else "segment %d (the first is not named .ad1)" % k)
                p = None
            self.names.append(_os.path.basename(p) if p else self.missing[-1])
            self.paths.append(p)
            self.margins.append(margin)
            self.actual.append(present)
            self.starts.append(self.starts[-1] + span)
        self.end = self.starts[-1]
        self._open = {}
        self._reached, self._lo, self._hi = _array.array("Q"), _array.array("Q"), _array.array("Q")
        self._chains, self._chains_held = {}, 0
        self.packed_read = 0          # compressed bytes of content read so far, for a ratio against what is written
        self.gap_report = None
        if self.read(0, 14) != AD1_LOGICAL_MAGIC:
            raise AD1Error("no ADLOGICALIMAGE header at the start of the image's data")
        (self.version,) = _struct.unpack("<I", self.read(16, 4))
        if self.version != AD1_VERSION:
            raise AD1Error("an AD1 logical image of version %d: this reader reads version %d" % (self.version, AD1_VERSION))
        (self.chunk_size,) = _struct.unpack("<I", self.read(24, 4))
        if not AD1_CHUNK_MIN <= self.chunk_size <= AD1_CHUNK_MAX:
            raise AD1Error("the logical image header says its chunks are %d bytes (this reader takes %d to %d)" % (self.chunk_size, AD1_CHUNK_MIN, AD1_CHUNK_MAX))
        self.meta_addr, self.first_item, name_len = _struct.unpack("<QQI", self.read(28, 20))
        (name_addr,) = _struct.unpack("<Q", self.read(52, 8))
        self.source_name = b""
        after = [a for a in (self.meta_addr, self.first_item, name_addr) if a >= 60]
        self._reach(0, min(after) if after else 60)       # the header runs on to the first thing it points at
        self._reach_guid_tables()
        if name_len > AD1_TEXT_MAX:
            self.errors.append("the data source name says it is %d bytes long: not read" % name_len)
        elif name_addr:
            try:
                self.source_name = self.read(name_addr, name_len)
                self._reach(name_addr, name_len)
            except AD1Error as e:
                self.errors.append("the data source name cannot be read: %s" % e)

    def close(self):
        for fh in self._open.values():
            fh.close()
        self._open = {}

    def _fh(self, k):
        fh = self._open.pop(k, None)
        if fh is None:
            if len(self._open) >= AD1_OPEN_MAX:
                self._open.pop(next(iter(self._open))).close()
            fh = open_regular(self.paths[k])
        self._open[k] = fh
        return fh

    def read(self, addr, n):
        """n bytes of the image's data from addr, across segments."""
        if addr < 0 or n < 0 or addr + n > self.end:
            raise AD1Error("address %d (+%d) is outside the image's data" % (addr, n))
        out = bytearray()
        while len(out) < n:
            at = addr + len(out)
            k = _bisect.bisect_right(self.starts, at) - 1
            if self.paths[k] is None:
                raise AD1Error("address %d is in segment %d, which is not there (%s)" % (at, k + 1, self.names[k]))
            off = at - self.starts[k]
            want = min(n - len(out), self.starts[k + 1] - at)
            got = _os.pread(self._fh(k).fileno(), want, self.margins[k] + off)
            if len(got) < want:
                raise AD1Error("address %d (+%d) runs past the end of segment %d: the image is truncated" % (addr, n, k + 1))
            out += got
        return bytes(out)

    def _reach(self, addr, n):
        """The walk reached n bytes from addr (a structure it read, or one that it was led to)."""
        if n > 0:
            r = self._reached
            if r and r[-1] == addr:
                r[-1] = addr + n          # laid out one after the other, as a writer does: one range
                return
            r.append(addr)
            r.append(addr + n)
            if len(r) >= max(AD1_FOLD_AT, min(2 * len(self._lo), 1 << 20)):   # a fold costs the ranges held: wait for as many new ones
                self._fold()

    def _fold(self):
        """Merge the ranges reached since the last fold into the sorted, disjoint ones already held (two arrays, 16 bytes a range)."""
        fresh = sorted(zip(self._reached[0::2], self._reached[1::2]))
        self._reached = _array.array("Q")
        lo, hi = _array.array("Q"), _array.array("Q")
        for a, b in _heapq.merge(zip(self._lo, self._hi), fresh):
            if hi and a <= hi[-1]:
                if b > hi[-1]:
                    hi[-1] = b
            else:
                lo.append(a)
                hi.append(b)
        self._lo, self._hi = lo, hi

    def _reach_guid_tables(self):
        """The tables of GUIDs the logical image header points to (FTK Imager writes the pointers at +60 and +76, with room for
        two more): an 8-byte tag, a count at +12, then 20 bytes an entry."""
        for at in (60, 68, 76, 84):
            try:
                (addr,) = _struct.unpack("<Q", self.read(at, 8))
                if addr >= 76 and self.read(addr, 8) in AD1_GUID_TABLES:
                    (count,) = _struct.unpack("<I", self.read(addr + 12, 4))
                    if count < 1 << 16:
                        self._reach(addr, 16 + 20 * count)
            except AD1Error:
                pass

    def _reach_table(self, table, size):
        """A file's chunk table and the chunks it lists, as far as the table reads sanely (chunks() names the rest)."""
        try:
            (count,) = _struct.unpack("<Q", self.read(table, 8))
            most = (size + self.chunk_size - 1) // self.chunk_size
            if count > max(most, 1) or count > (self.end - table - 8) // 8 - 1 or count > AD1_CHUNKS_MAX:
                return
            (first,) = _struct.unpack("<Q", self.read(table + 8, 8))
            (last,) = _struct.unpack("<Q", self.read(table + 8 + 8 * count, 8))
        except AD1Error:
            return
        self._reach(table, 16 + 8 * count)
        if first <= last <= self.end:
            self._reach(first, last - first)

    def _gaps(self):
        """(from, to) of every stretch of the data present that no reached range covers, in address order."""
        for k, extent in enumerate(self.actual):
            at, end = self.starts[k], self.starts[k] + extent
            for i in range(_bisect.bisect_right(self._hi, at), len(self._lo)):
                lo, hi = self._lo[i], self._hi[i]
                if lo >= end:
                    break
                if lo > at:
                    yield at, lo
                at = max(at, hi)
            if at < end:
                yield at, end

    def unreferenced(self, deadline=None, sink=None):
        """(bytes, non-zero bytes, whole) of the image's data that no structure the walk read or was led to covers, or None while a
        segment is not there. Every such stretch is read to its end, in blocks of AD1_GAP_BLOCK, and the clock (`deadline`, a
        time.monotonic() value) is looked at before each block: zero bytes between structures are padding, the non-zero ones are
        content nothing led to. `whole` is False when the clock stopped the read before the end of the unreached data; `gap_report`
        then says where (stopped_at, an address) and how much was read, and counts the gaps that hold non-zero bytes or were not
        read to their end, naming the first AD1_GAPS_LISTED of them; `sink`, when given, is called with every such gap (from, to,
        read, nonzero_bytes), so the caller can keep them all. The image's own metadata chain counts as reached, so it is read here
        if the caller has not."""
        if self.missing:
            return None
        if self.meta_addr:
            try:
                self.metadata(self.meta_addr)
            except AD1Error:
                pass
        self._fold()
        total, nonzero, read, stopped = 0, 0, 0, False
        rep = {"gaps": 0, "gaps_with_nonzero_bytes": 0, "gaps_not_read_to_the_end": 0, "stopped_at": None, "listed": []}
        for lo, hi in self._gaps():
            total += hi - lo
            rep["gaps"] += 1
            start, nz, got = lo, 0, 0
            while lo < hi and not stopped:
                if deadline is not None and _time.monotonic() > deadline:
                    stopped = True
                    rep["stopped_at"] = lo
                    break
                block = self.read(lo, min(hi - lo, AD1_GAP_BLOCK))
                nz += len(block) - block.count(0)
                got += len(block)
                lo += len(block)
            nonzero += nz
            read += got
            rep["gaps_with_nonzero_bytes"] += 1 if nz else 0
            rep["gaps_not_read_to_the_end"] += 1 if got < hi - start else 0
            if nz or got < hi - start:
                gap = {"from": start, "to": hi, "read": got, "nonzero_bytes": nz}
                if len(rep["listed"]) < AD1_GAPS_LISTED:
                    rep["listed"].append(gap)
                if sink is not None:
                    sink(gap)
        rep.update({"bytes": total, "read": read, "nonzero_bytes": nonzero})
        self.gap_report = rep
        return total, nonzero, read >= total

    def metadata(self, addr):
        """[(category, key, text bytes, address)] of a metadata chain. An item that shares its chain with an earlier one gets the same
        list back (it is read once), so a caller does not change it."""
        if addr in self._chains:
            return self._chains[addr][0]
        out, seen, held, head = [], set(), 0, addr
        while addr:
            if addr in seen:
                raise AD1Error("the metadata chain loops back to address %d" % addr)
            seen.add(addr)
            nxt, cat, key, length = _struct.unpack("<QIII", self.read(addr, 20))
            if length > AD1_TEXT_MAX:
                raise AD1Error("a metadata entry at address %d says it is %d bytes" % (addr, length))
            held += length
            if len(out) >= AD1_META_MAX or held > AD1_META_BYTES_MAX:
                raise AD1Error("a metadata chain holds more than %d entries or %d bytes of text: not read further" % (AD1_META_MAX, AD1_META_BYTES_MAX))
            out.append((cat, key, self.read(addr + 20, length), addr))
            self._reach(addr, 20 + length)
            addr = nxt
        cost = held + 200 * len(out)
        if head and cost <= AD1_CACHE_MAX:
            self._chains[head] = (out, cost)
            self._chains_held += cost
            while len(self._chains) > AD1_CACHE_CHAINS or self._chains_held > AD1_CACHE_MAX:
                self._chains_held -= self._chains.pop(next(iter(self._chains)))[1]
        return out

    def walk(self):
        """Every item, depth first in the image's own order (an item, its
        children, then its next sibling), numbered from 0, with its path
        (names joined by "/"). A node that cannot be read ends its chain,
        and is named in walk_errors: a numbering after it is not the
        numbering of a whole read, and an item's address (locator) is."""
        seen, n = set(), 0
        stack = [(self.first_item, b"", None, 0)] if self.first_item else []
        while stack:
            addr, parent, parent_n, depth = stack.pop()
            if addr in seen:
                self.walk_errors.append("the tree loops back to item address %d under %s: not followed" % (addr, ad1_where(parent)))
                continue
            seen.add(addr)
            if depth >= AD1_DEPTH_MAX:
                self.walk_errors.append("item at address %d under %s is nested deeper than %d levels: it and the siblings after it are not listed" % (addr, ad1_where(parent), AD1_DEPTH_MAX))
                continue
            try:
                nxt, child, meta, table, size, kind, name_len = _struct.unpack("<QQQQQII", self.read(addr, 48))
                if name_len > AD1_NAME_MAX:
                    raise AD1Error("its name is %d bytes long" % name_len)
                name = self.read(addr + 48, name_len)
                meta = self.metadata(meta)
                self._reach(addr, 48 + name_len)
                if table:
                    self._reach_table(table, size)
            except AD1Error as e:
                self.walk_errors.append("item at address %d under %s cannot be read: %s; it and the siblings after it are not listed" % (addr, ad1_where(parent), e))
                continue
            path = parent + b"/" + name if parent_n is not None else name
            item = {"n": n, "addr": addr, "parent": parent_n, "path": path, "name": name, "type": kind,
                    "size": size, "table": table, "meta": meta}
            n += 1
            if nxt:
                stack.append((nxt, parent, parent_n, depth))
            if child:
                stack.append((child, path, item["n"], depth + 1))
            yield item

    def chunks(self, item):
        """The compressed byte ranges of an item's content, its chunk table
        read a batch at a time; an AD1Error at the first range out of order,
        outside the data or larger than a chunk's zlib stream can be."""
        table = item["table"]
        if not table:
            if item["size"]:
                raise AD1Error("it has no chunk table for its %d bytes" % item["size"])
            return
        (count,) = _struct.unpack("<Q", self.read(table, 8))
        most = (item["size"] + self.chunk_size - 1) // self.chunk_size
        room = (self.end - table - 8) // 8 - 1
        if count > max(most, 1) or count > room or count > AD1_CHUNKS_MAX:
            raise AD1Error("its chunk table lists %d chunks for %d bytes" % (count, item["size"]))
        packed_max = 2 * self.chunk_size + 1024
        prev, i, at, left = None, 0, table + 8, count + 1
        while left:
            take = min(left, AD1_TABLE_BATCH)
            for a in _struct.unpack("<%dQ" % take, self.read(at, 8 * take)):
                if prev is not None:
                    if a < prev or a > self.end or a - prev > packed_max:
                        raise AD1Error("its chunk %d runs from address %d to %d" % (i, prev, a))
                    yield prev, a
                    i += 1
                prev = a
            at += 8 * take
            left -= take

    def content(self, item):
        """An item's content, chunk by chunk, each inflated within the chunk
        size; an AD1Error when a chunk does not inflate whole or the content
        is not the item's size."""
        bound = self.chunk_size
        total = 0
        for i, (start, end) in enumerate(self.chunks(item)):
            z = _zlib.decompressobj()
            try:
                packed = self.read(start, end - start)
                self.packed_read += len(packed)
                block = z.decompress(packed, bound + 1)
            except _zlib.error as e:
                raise AD1Error("its chunk %d does not inflate: %s" % (i, e))
            if len(block) > bound or z.unconsumed_tail:
                raise AD1Error("its chunk %d inflates past the chunk size of %d" % (i, bound))
            if not z.eof or z.unused_data:
                raise AD1Error("its chunk %d is not one whole zlib stream" % i)
            total += len(block)
            if total > item["size"]:
                raise AD1Error("its content runs past its size of %d bytes" % item["size"])
            yield block
        if total != item["size"]:
            raise AD1Error("its content is %d bytes, not its size of %d" % (total, item["size"]))


def ad1_unaccounted(img, deadline=None, sink=None):
    """None, or words, once a walk has reached the end of the tree: the image's data holds bytes that no item, name, metadata entry,
    chunk table or chunk led to. A zeroed or damaged next or child pointer ends a chain early with no error, and the format has no item
    count, so the walk cannot tell a tree that ended from a tree that was cut: it says what it could not account for. The unreached data
    is read to its end unless the clock (`deadline`) stops it, and then the words say where."""
    left = img.unreferenced(deadline, sink)
    if left is None:
        return None
    rep = img.gap_report
    stopped = "" if left[2] else "; the read of the unreached data stopped at its time budget at address %d, %d of its %d bytes in" % (rep["stopped_at"], rep["read"], left[0])
    if left[1] <= AD1_SLACK:
        if left[2]:
            return None
        # The clock stopped the read, and what was read held nothing: that says nothing of the rest, where a zeroed pointer's lost items
        # can sit behind a long run of zeros.
        return ("%d of the %d bytes of the image's data that no item, name, metadata entry, chunk table or chunk of the tree leads to were read for non-zero bytes "
                "(up to address %d) and held none; the read stopped at its time budget, so the rest was not read, the tree is not shown to account for the "
                "image's data and the list is not shown to be whole" % (rep["read"], left[0], rep["stopped_at"]))
    return ("%s%d bytes of the image's data that are not zero are reached by no item, name, metadata entry, chunk table or chunk of the tree: a zeroed or damaged "
            "next or child pointer would leave exactly such bytes, and the format has no item count, so the list is not shown to be whole%s" % ("" if left[2] else "at least ", left[1], stopped))


def ad1_text(meta, key):
    """The text of the first metadata entry with this key, or None."""
    for _c, k, v, _a in meta:
        if k == key:
            return v
    return None
# --- end of the AD1 reader ----------------------------------------------------


GAPS_FILE_MAX = 100_000           # rows in the file of gaps; the counts in the report go on past it


class GapFile:
    """The gaps of the image's data that no structure led to and that hold non-zero bytes or were not read to their end, one JSON line
    each, in a file made new on the first one and cut at GAPS_FILE_MAX rows (`cut` says so)."""

    def __init__(self, path):
        self.path, self.fh, self.written, self.cut, self.error = path, None, 0, False, None

    def add(self, gap):
        if self.error or self.cut:
            return
        if self.written >= GAPS_FILE_MAX:
            self.cut = True
            return
        try:
            if self.fh is None:
                fd = os.open(self.path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o644)
                self.fh = os.fdopen(fd, "w", encoding="ascii")
            self.fh.write(json.dumps(gap) + "\n")
            self.written += 1
        except OSError as exc:
            self.error = "the gaps could not be written (%s)" % (exc.strerror or exc)

    def close(self):
        if self.fh is not None:
            try:
                self.fh.close()
            except OSError as exc:
                self.error = self.error or "the gaps were not all written (%s)" % (exc.strerror or exc)
            self.fh = None


def limits():
    try:
        lim = json.load(open(os.path.join(HERE, "recipe.json"))).get("limits", {})
    except Exception:
        lim = {}
    return int(os.environ.get("RECIPE_SECONDS") or lim.get("seconds") or 3600)


def refuse(message):
    """A target that cannot be read is an answer on stdout, as every other refusal here is, not a traceback."""
    print_answer({"ok": False, "error": message})
    sys.exit(2)


def target_of(arg):
    text = arg
    if os.path.isfile(arg):
        try:
            with open(arg, encoding="utf-8") as fh:
                text = fh.read(1 << 20)
        except (OSError, ValueError) as exc:               # ValueError: bytes that are not UTF-8
            refuse("the target file cannot be read as UTF-8 text: %s" % (getattr(exc, "strerror", None) or exc.__class__.__name__))
    try:
        t = json.loads(text)
    except (ValueError, RecursionError) as exc:
        refuse("the target is not valid JSON: %s" % exc)
    if not isinstance(t, dict):
        refuse("the target is a JSON object with a paths list")
    paths = t.get("paths") or []
    if not isinstance(paths, list):
        refuse("the target is a JSON object with a paths list")
    if not paths or not all(isinstance(p, str) for p in paths):
        refuse("the target names no path")
    return t, paths


def esc(raw):
    """A name or a text for a reader: one line, one field, nothing hidden."""
    out = []
    for ch in raw.decode("utf-8", "surrogateescape"):
        o = ord(ch)
        if 0xDC80 <= o <= 0xDCFF:
            out.append("\\x%02x" % (o - 0xDC00))
        elif ch == "\\":
            out.append("\\\\")
        elif ch == "\t":
            out.append("\\t")
        elif ch == "\n":
            out.append("\\n")
        elif ch == "\r":
            out.append("\\r")
        elif o < 0x20 or o == 0x7F:
            out.append("\\x%02x" % o)
        else:
            out.append(ch)
    return "".join(out)


STAMP = re.compile(rb"^(\d{4})(\d{2})(\d{2})T(\d{2})(\d{2})(\d{2})(\.\d+)?$")


def stamp(raw):
    """The image's time text (20231004T101112.123456) as ISO 8601 with no zone; any other text as it is."""
    if raw is None:
        return ""
    m = STAMP.match(raw.strip())
    if not m:
        return esc(raw)
    g = [x.decode() for x in m.groups(b"")]
    return "%s-%s-%sT%s:%s:%s%s" % tuple(g)


def _open_regular(path):
    """The target opened for reading without waiting for it (an open of a FIFO named here would block until a writer came): the type is read from the
    descriptor, and anything but a regular file is refused as an OSError, which detect reads as "cannot tell"."""
    import errno
    import stat
    fd = os.open(path, os.O_RDONLY | os.O_NONBLOCK | getattr(os, "O_CLOEXEC", 0))
    try:
        if not stat.S_ISREG(os.fstat(fd).st_mode):
            raise OSError(errno.EINVAL, "not a regular file")
        os.set_blocking(fd, True)
        return os.fdopen(fd, "rb")
    except BaseException:
        os.close(fd)
        raise


def _is_regular(path):
    import stat
    try:
        return stat.S_ISREG(os.stat(path).st_mode)
    except (OSError, ValueError):
        return False


def detect(path):
    """(format, why) or (None, why), from the headers alone."""
    try:
        with _open_regular(path) as fh:
            head = fh.read(0x30)
            seg = ad1_segment_header(head)
            if seg["index"] != 1:
                return None, "segment %d of %d of an AD1 image: the image is read, and catalogued, from its first segment (.ad1)" % (seg["index"], seg["count"])
            fh.seek(seg["header"])
            logical = fh.read(20)
    except (OSError, ValueError) as e:        # ValueError: a NUL or a lone surrogate in the path
        return "unknown", "unreadable, so it cannot be told whether it is an AD1 image: %s" % (getattr(e, "strerror", None) or e.__class__.__name__)
    except AD1Error as e:
        return None, str(e)
    if not logical.startswith(AD1_LOGICAL_MAGIC):
        return None, "an ADSEGMENTEDFILE header with no ADLOGICALIMAGE header after it"
    version = int.from_bytes(logical[16:20], "little")
    if version != AD1_VERSION:
        return None, "an AD1 logical image of version %d: this recipe reads version %d" % (version, AD1_VERSION)
    return "AD1", "an AD1 logical image (version 4, segment 1 of %d)" % seg["count"]


def row_of(img, item, w, deadline, cov, escapes):
    meta = item["meta"]
    raw_path = item["path"]
    flags = []
    try:
        item["name"].decode("utf-8")
    except UnicodeDecodeError:
        flags.append("name-not-utf8")
    # A name that climbs, or one under it: the parent's mark is carried down.
    if item["name"] in (b"", b".", b"..") or b"/" in item["name"] or item["parent"] in escapes:
        flags.append("escapes-root")
        escapes.add(item["n"])
    if item["type"] == AD1_UNKNOWN_FILE:
        flags.append("unknown-file")
    if item["type"] == AD1_DELETED:
        flags.append("deleted")
    if (ad1_text(meta, 0x0D) or b"").strip().lower() == b"true":
        flags.append("encrypted")
    is_file = item["type"] in (AD1_FILE, AD1_UNKNOWN_FILE, AD1_DELETED)
    kind = "dir" if item["type"] == AD1_FOLDER else "file" if is_file else "other:%d" % item["type"]
    # As recorded, escaped as any text is: a field never breaks the row.
    md5 = esc((ad1_text(meta, 0x5001) or b"").strip()).lower()
    sha1 = esc((ad1_text(meta, 0x5002) or b"").strip()).lower()
    packed, sha256, check = "", "", ""
    ranges = True
    try:
        packed = ""
        if item["table"]:
            packed = 0
            for k, (c_start, c_end) in enumerate(img.chunks(item)):
                packed += c_end - c_start
                if k and k % 4096 == 0 and time.monotonic() > deadline:
                    packed = ""        # cut by the clock: not known, and the file is not inflated either
                    break
    except AD1Error as e:
        ranges = None
        cov["errors"].append("item %d (%s, %s): %s" % (item["n"], esc(raw_path), "ad1:item=%d" % item["addr"], e))
    if item["type"] != AD1_FOLDER:
        if ranges is None:
            check = "not-read"
        elif time.monotonic() > deadline:
            check = "not-read"
            cov["unread_at_limit"] += 1
        else:
            hs = [hashlib.md5(), hashlib.sha1(), hashlib.sha256()]
            try:
                cut = False
                for block in img.content(item):
                    for h in hs:
                        h.update(block)
                    if time.monotonic() > deadline:
                        cut = True     # past the limit part way through one file: it is not a checked file, and says so
                        break
                if cut:
                    check = "not-read"
                    cov["unread_at_limit"] += 1
                else:
                    sha256 = hs[2].hexdigest()
                    if not md5 and not sha1:
                        check = "no-stored-hash"
                        cov["no_stored_hash"] += 1
                    elif (md5 and md5 != hs[0].hexdigest()) or (sha1 and sha1 != hs[1].hexdigest()):
                        check = "mismatch"
                        flags.append("hash-mismatch")
                        cov["mismatches"].append(item["n"])
                    else:
                        check = "ok"
                    cov["checked"] += 1
            except AD1Error as e:
                check = "not-read"
                cov["errors"].append("item %d (%s, %s): %s" % (item["n"], esc(raw_path), "ad1:item=%d" % item["addr"], e))
    klass = ad1_text(meta, 0x02)
    w.write("\t".join(str(v) for v in (
        item["n"], kind, esc(raw_path), base64.b64encode(raw_path).decode("ascii"), item["size"], packed,
        stamp(ad1_text(meta, 0x09)), "unknown", "", "", "", "", "ad1:item=%d" % item["addr"], ",".join(flags),
        stamp(ad1_text(meta, 0x07)), stamp(ad1_text(meta, 0x08)), md5, sha1, sha256, check,
        CLASSES.get((klass or b"").strip(), esc(klass or b"")))) + "\n")
    cov["folders" if item["type"] == AD1_FOLDER else "files"] += 1


def missing_words(img):
    """The segments not there, in words: on the host they are not beside the
    first; in a job they may also be outside its view, which holds only what
    the job declared. coverage.json's segments_missing has every name."""
    names = img.missing if len(img.missing) <= 5 else img.missing[:2] + ["...", img.missing[-1]]
    return ("the image has %d segments and %d of them (%s) %s not there, beside the first or in this job's view (a job is given "
            "only the segments it declares): what lies in them is not read"
            % (img.segment["count"], len(img.missing), ", ".join(names), "is" if len(img.missing) == 1 else "are"))


def label(key):
    return LABELS.get(key, "")


def run(target, paths, out_dir):
    seconds = limits()
    deadline = time.monotonic() + seconds * 0.9       # past this, no further file's content is inflated
    list_deadline = time.monotonic() + float(os.environ.get("RECIPE_LISTING_SECONDS") or seconds * 0.97)  # past this, no further item is listed
    try:
        os.makedirs(out_dir, exist_ok=True)
    except (OSError, ValueError) as exc:        # a name too long, a loop, a file in the way, a directory that cannot be entered
        print_answer({"ok": False, "status": "failed", "error": "--out cannot be used: %s" % (getattr(exc, "strerror", None) or exc.__class__.__name__),
                      "status_basis": "the output directory could not be made, so nothing was run"})
        sys.exit(2)
    _probe_out(out_dir)
    cov = {"recipe": "ad1-items", "target": paths[0], "format": "AD1", "items": 0, "files": 0, "folders": 0, "checked": 0,
           "mismatches": [], "no_stored_hash": 0, "unread_at_limit": 0, "segments_missing": [],
           "covered": "every item of the image's tree, with its metadata, and each file's content inflated and checked against the digests the image records",
           "not_covered": "anything the imager did not put in the image (a logical image holds no unallocated space, and slack only where it was taken as an item); files inside the files; an encrypted (ADCRYPT) image",
           "limits_hit": [], "errors": []}

    def write_cov():
        _write_json_whole(os.path.join(out_dir, "coverage.json"), cov, indent=2)

    def finish(status, code):
        cov["status"] = status
        cov["status_basis"] = {"complete": "every item of the tree was listed, its metadata written, and the data the tree leads to accounts for the image's",
                               "partial": "a limit was hit, a segment is missing, an item broke, or the tree does not account for all of the image's data (see limits_hit and errors)",
                               "failed": "no item could be listed (see errors)",
                               "unsupported": "this is not an AD1 image this recipe reads (see why)"}.get(status, status)
        if "integrity_status" not in cov:
            cov["integrity_status"] = "mismatch" if cov["mismatches"] else "unverified" if cov["files"] > cov["checked"] or cov["no_stored_hash"] or cov.get("unaccounted") else "verified" if cov["files"] else "not_applicable"
        write_cov()
        print_answer({"ok": code == 0, "status": status, "format": "AD1", "items": cov["items"]})
        return code

    # Said before the first read: a run cut short leaves a coverage file that says it was, never none.
    cov["status"] = "partial"
    cov["status_basis"] = "the run had started and had listed nothing yet"
    cov["why"] = "started; the run did not reach its end"
    write_cov()
    del cov["why"]

    def _stopped(signum):
        cov["status"] = "partial"
        cov["interrupted"] = True
        cov["signal"] = signum
        cov["status_basis"] = "the recipe was stopped by signal %d: the items listed before the stop are in members.tsv, and nothing is claimed about the rest" % signum
        cov["integrity_status"] = "unverified"
        try:
            write_cov()
        except OSError:
            pass
        print(json.dumps({"ok": False, "status": "partial", "interrupted": True, "signal": signum, "format": "AD1", "items": cov["items"]}), flush=True)
    install_signal_handlers(_stopped)
    img_source = b""
    try:
        img = AD1(paths[0], paths[1:])
    except AD1Error as e:
        cov["why"] = str(e)
        return finish("unsupported", 2)
    except OSError as e:
        cov["errors"].append("%s: %s" % (paths[0], e.strerror or e))
        return finish("failed", 2)
    cov["segments_missing"] = img.missing
    if img.missing:
        cov["errors"].append(missing_words(img))
    cov["errors"] += img.errors
    try:
        with open(os.path.join(out_dir, "members.tsv"), "w", encoding="utf-8", newline="\n") as w, \
                open(os.path.join(out_dir, "attributes.tsv"), "w", encoding="utf-8", newline="\n") as a:
            w.write("\t".join(COLUMNS) + "\n")
            a.write("n\tcategory\tkey\tlabel\ttext\n")
            escapes = set()
            # Past the content deadline an item is still listed (its digests are then not checked); the listing has a later
            # clock of its own, and an item budget, because a hostile image can make one item cost a metadata chain's worth.
            written_chains, attr_cost, attr_stopped = {}, 0, None
            holds = sum(img.actual)      # the bytes of data the image has (its last segment is shorter than its header says)
            walked_all = False
            for item in img.walk():
                if cov["items"] >= MAX_ITEMS:
                    cov["limits_hit"].append("items: the listing stopped after %d items; every item after it in the image's order is not listed" % cov["items"])
                    break
                if cov["items"] and time.monotonic() > list_deadline:
                    cov["limits_hit"].append("seconds: the listing stopped after %d items; every item after it in the image's order is not listed" % cov["items"])
                    break
                row_of(img, item, w, deadline, cov, escapes)
                # attributes.tsv: a metadata chain is written once, for the first item that has it; an item sharing the whole
                # chain gets one row naming that item. The text written is held to the bytes the image holds: entries that
                # sit at their own addresses cannot add up to more, so a total above it means chains that overlap.
                head = item["meta"][0][3] if item["meta"] else None
                if attr_stopped is not None:
                    pass
                elif head is not None and head in written_chains:
                    a.write("%d\t\t\tsame-chain\tthe metadata entries of item %d, which has this chain (entry address %d)\n" % (item["n"], written_chains[head], head))
                else:
                    if head is not None:
                        written_chains[head] = item["n"]
                    for cat, key, text, _addr in item["meta"]:
                        attr_cost += 20 + len(text)
                        if attr_cost > holds:
                            attr_stopped = item["n"]
                            cov["limits_hit"].append("attributes: attributes.tsv stops inside item %d (ad1:item=%d): the entries of the chains written would be more than the %d bytes the image's data holds, "
                                                     "so chains overlap; item %d and the items after it have no complete attribute rows there (their metadata is read from the image at the locator)"
                                                     % (item["n"], item["addr"], holds, item["n"]))
                            break
                        a.write("%d\t%d\t0x%x\t%s\t%s\n" % (item["n"], cat, key, label(key), esc(text)))
                cov["items"] += 1
            else:
                walked_all = not img.walk_errors
        cov["errors"] += img.walk_errors
        if walked_all and not cov["limits_hit"]:
            # The data nothing led to is read to its end under the listing's clock; the gaps that hold non-zero bytes or were not read
            # to their end are all in unreferenced-gaps.jsonl (at most GAPS_FILE_MAX of them), the first AD1_GAPS_LISTED in the coverage.
            gaps = GapFile(os.path.join(out_dir, "unreferenced-gaps.jsonl"))
            try:
                lost = ad1_unaccounted(img, list_deadline, gaps.add)
            finally:
                gaps.close()
            rep = img.gap_report
            if rep is not None:
                cov["unreferenced_bytes"], cov["unreferenced_nonzero_bytes"] = rep["bytes"], rep["nonzero_bytes"]
                cov["unreferenced_bytes_read"] = rep["read"]
                cov["unreferenced_gaps"] = {k: rep[k] for k in ("gaps", "gaps_with_nonzero_bytes", "gaps_not_read_to_the_end", "stopped_at", "listed")}
                if gaps.written or gaps.error:
                    cov["unreferenced_gaps"]["file"] = "unreferenced-gaps.jsonl" if gaps.written else None
                    cov["unreferenced_gaps"]["file_rows"] = gaps.written
                    if gaps.cut:
                        cov["unreferenced_gaps"]["file_cut_at_rows"] = GAPS_FILE_MAX
                    if gaps.error:
                        cov["unreferenced_gaps"]["file_error"] = gaps.error
            if lost:
                cov["errors"].append(lost)
                cov["unaccounted"] = True
                if rep is not None and rep["stopped_at"] is not None:
                    cov["limits_hit"].append("seconds: the read of the data nothing led to stopped at address %d, %d of its %d bytes in" % (rep["stopped_at"], rep["read"], rep["bytes"]))
        try:
            own = [{"category": c, "key": "0x%x" % k, "label": label(k), "text": esc(t)} for c, k, t, _a in img.metadata(img.meta_addr)]
        except AD1Error as e:
            own = []
            cov["errors"].append("the image's own metadata: %s" % e)
        segs = []
        for k, p in enumerate(img.paths, 1):
            segs.append({"segment": k, "name": img.names[k - 1], "present": p is not None, **({"bytes": os.path.getsize(p)} if p else {})})
        _write_json_whole(os.path.join(out_dir, "image.json"), {"format": "AD1", "segment_header": img.segment, "segments": segs,
                   "logical_image": {"version": img.version, "chunk_size": img.chunk_size, "first_item": img.first_item, "metadata": img.meta_addr},
                   "data_source_name": esc(img.source_name), "metadata": own,
                   "items": cov["items"], "files": cov["files"], "folders": cov["folders"]}, indent=2, ensure_ascii=False)
    finally:
        img_source = img.source_name
        img.close()
    if cov["unread_at_limit"]:
        cov["limits_hit"].append("seconds: past the limit, the content of %d file(s) was not inflated, so their digests were not checked (check not-read); every item is still listed" % cov["unread_at_limit"])
    with open(os.path.join(out_dir, "index.tsv"), "w", encoding="utf-8") as fh:
        mism = len(cov["mismatches"])
        fh.write("members.tsv\tAD1 item list (%d items: %d files, %d folders), paths under the data source name %s: n, type, path, path_b64, size, packed, mtime, tz, mode, uid, gid, link, locator, flags, atime, btime, md5, sha1, sha256, check, class; ad1_extract takes n or the locator%s\n"
                 % (cov["items"], cov["files"], cov["folders"], esc(img_source) or "(none recorded)", "; %d file(s) whose content does not match the digests the image records (check mismatch)" % mism if mism else ""))
        fh.write("attributes.tsv\tevery metadata entry of every item (a chain several items share is written once, then a same-chain row names the item): n, category, key, label, text\n")
        fh.write("image.json\tthe AD1 segment and logical image headers, its segments, its data source name and its own metadata\n")
    status = "complete" if not cov["limits_hit"] and not cov["errors"] else ("partial" if cov["items"] else "failed")
    return finish(status, 0 if status in ("complete", "partial") else 2)


def main(argv):
    if len(argv) < 2 or argv[1] not in ("detect", "run"):
        print_answer({"ok": False, "error": "usage: run.py detect --target T [--probe-out DIR] | run --target T --out DIR"})
        return 2
    args = dict(zip(argv[2::2], argv[3::2]))
    if "--target" not in args:
        print_answer({"ok": False, "error": "--target is required"})
        return 2
    target, paths = target_of(args["--target"])
    if argv[1] == "detect":
        fmt, why = detect(paths[0])
        if fmt == "unknown":
            print_answer({"applies": "unknown", "format": None, "why": why})
            return 2
        print_answer({"applies": fmt is not None, "format": fmt, "why": why})
        return 0 if fmt else 1
    if "--out" not in args:
        print_answer({"ok": False, "error": "run needs --out DIR"})
        return 2
    if not _is_regular(paths[0]):
        print_answer({"ok": False, "status": "failed", "status_basis": "the target is not a regular file, so nothing was run", "error": "not a regular file"})
        return 2
    return run(target, paths, args["--out"])


if __name__ == "__main__":
    exit_code = 0
    try:
        sys.exit(main(sys.argv))
    except SystemExit as stop:
        exit_code = _code(stop)
    _leave(exit_code)
