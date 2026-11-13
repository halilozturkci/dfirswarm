#!/usr/bin/env python3
"""ad1_extract: write the files and folders of an AccessData AD1 logical image
out as a tree, each file inflated, hashed and checked against the digests the
image records, with a manifest of what went where.

Args, JSON on stdin:
  image     the image's first segment (.ad1); its further segments are
            looked for beside it (x.ad2, x.ad3, ...)
  members   items from the catalogue's members.tsv for this image (the
            ad1-items recipe): their numbers (n), or their locators
            (ad1:item=<address>); a folder takes its subtree. Default: every
            item. A listing that was partial (a segment missing, an item it
            could not read) numbers the items after a break otherwise than a
            whole read does; a locator names the same item in both
  out_dir   where the tree goes, a new or empty directory. Default: in a job
            ($OUT set) $OUT/<image name less .ad1>, and in a job it must be
            inside $OUT; called directly, work/<AGENT_ID>/ad1/<image name
            less .ad1>
  max_items, max_walk, max_bytes, max_seconds
            budgets for the whole call (items taken, items looked at, bytes
            written, wall clock): defaults 5,000,000, 5,000,000, 256 GiB and
            1500 s. A call that reaches one stops, keeps what it wrote, and
            says it was partial. What is held while it walks is the depth of
            the tree, not the number of items. One over its ceiling is held
            to the ceiling; in a job max_bytes is held to the room free where
            $OUT is (less 64 MiB) and a relative out_dir is taken under $OUT:
            each is said in the answer's adjusted

Run it as a job (job_run tool=ad1_extract): what it writes is then sealed
into the store, citable as job:<id>/<path>, and the derived catalogue offers
each file to the recipes, so an archive, a disk image or an executable inside
the AD1 image is catalogued in turn.

Each item lands at out_dir/<its path in the image>. A name this file system
cannot hold as it is (empty, "." or "..", holding "/" or a NUL, not UTF-8,
past 255 bytes, or one a sibling already took, letter case and Unicode
normalisation aside) is written renamed, and the manifest,
out_dir/ad1_extract.tsv, names both (an item at the top named like the
manifest is renamed too):

    n  type  path  path_b64  locator  written  size  sha256  check  note

`path`, `path_b64` and `locator` are as ad1-items lists them; `written` is
under out_dir; `check` is ok, mismatch, no-stored-hash or not-read, as
ad1-items says it, or not-written (this file system refused it). A file
whose content breaks part way, or whose write fails (a full disk), is kept
as <name>.partial, holding what was written, and says so: no truncated file
keeps its own name, and the name it is kept under is one no other item
of that directory holds, partial or whole. Nothing is written outside
out_dir, under inputs/, or outside the run directory (in a job, its $OUT).

Two statuses, kept apart. `processing_status` says whether every item asked
for was written (complete), some were not (partial: a budget, an item that
broke) or nothing was (failed). `integrity_status` says whether what was
written matches the digests the image records: verified (every file had a
stored digest and matched), mismatch (at least one did not), or unverified
(some had no stored digest or were not read); `ok` is true only for a complete
processing with no mismatch. The exit code is 0 when the tool ran and what it
examined is whole or said not to be: processing complete (a mismatch included: the
files were written, and the mismatch is a finding about the image's content, not a
failure of this tool), or partial only because a budget stopped it between items
(`stopped_by_budget` says which). An item that broke or could not be written, a
segment that is not there or a manifest that could not be written is exit 1.
ad1_extract.coverage.json
is written as incomplete before the first item and again at the end.
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


import base64
import contextlib
import hashlib
import json
import os
import sys
import shutil
import time
import unicodedata
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

NAME_MAX = 255
SHOWN_ERRORS = 20
MANIFEST = "ad1_extract.tsv"
ERRORS = "ad1_extract.errors.txt"
COVERAGE = "ad1_extract.coverage.json"
GAPS = "ad1_extract.gaps.jsonl"
ITEMS_DEFAULT, ITEMS_CEILING = 5_000_000, 100_000_000
WALK_DEFAULT, WALK_CEILING = 5_000_000, 100_000_000       # items looked at, taken or not
BYTES_DEFAULT, BYTES_CEILING = 256 * 1024 ** 3, 1024 ** 4
SECONDS_DEFAULT, SECONDS_CEILING = 1500, 1700          # the ceiling is inside the manifest's own 1800-second limit
DISK_MARGIN = 64 * 1024 ** 2                           # left free where $OUT is, in a job
RATIO_DEFAULT, RATIO_CEILING = 1000, 1_000_000         # bytes written per byte of the image's content read (the max_ratio archive_extract has)
RATIO_SLACK = 1 << 20                                  # a file may expand this much past the ratio before it counts (a tiny image)


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
        numbering of a whole read, and an item's address (locator) is.
        FTK Imager writes the address of the item's parent folder (0 for a
        top-level item) as 8 bytes after its name: those count as reached
        when they hold that address, and are left to the unreferenced-data
        check (non-zero bytes nothing accounts for) when they do not."""
        seen, n = set(), 0
        stack = [(self.first_item, b"", None, 0, 0)] if self.first_item else []
        while stack:
            addr, parent, parent_n, depth, parent_addr = stack.pop()
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
                if addr + 56 + name_len <= self.end and _struct.unpack("<Q", self.read(addr + 48 + name_len, 8))[0] == parent_addr:
                    self._reach(addr + 48 + name_len, 8)
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
                stack.append((nxt, parent, parent_n, depth, parent_addr))
            if child:
                stack.append((child, path, item["n"], depth + 1, addr))
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


def fail(message, **extra):
    print_answer({"ok": False, "status": "failed", "status_basis": "the tool stopped with an error: %s" % message, "error": message, **extra})
    raise SystemExit(1)


def esc(raw):
    """A name for a reader: one line, one field, nothing hidden (as ad1-items writes it)."""
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


def resolve_output(out):
    """Where `out` really lands, links resolved first: in a job, inside its
    $OUT (the one place a job writes); called directly, inside the run
    directory (not the run directory itself); never under inputs/."""
    root = Path.cwd().resolve()
    try:
        dest = Path(out).resolve() if Path(out).is_absolute() else (root / out).resolve()
    except (OSError, RuntimeError, ValueError) as exc:     # a symlink loop, a name too long, a lone surrogate
        fail("out_dir cannot be resolved: %s" % (exc.__class__.__name__ if not getattr(exc, "strerror", None) else exc.strerror), out_dir=str(out))
    if os.environ.get("OUT") and os.environ.get("JOB_ID"):
        job_out = Path(os.environ["OUT"]).resolve()
        if dest != job_out and job_out not in dest.parents:
            fail("in a job out_dir must be inside $OUT, the one place a job writes ({OUT}/<name>)", out_dir=str(out))
    elif dest == root or root not in dest.parents:
        fail("out_dir must be inside the run directory, not the run directory itself", out_dir=str(out))
    inputs = root / "inputs"
    if dest == inputs or inputs in dest.parents:
        fail("out_dir cannot be under inputs/", out_dir=str(out))
    return dest


def fold(name):
    return unicodedata.normalize("NFC", name).casefold()


def safe_name(raw):
    """A name this file system holds, and whether it had to change."""
    try:
        text = raw.decode("utf-8")
        changed = False
    except UnicodeDecodeError:
        text = "".join(ch if not 0xDC80 <= ord(ch) <= 0xDCFF else "%%%02X" % (ord(ch) - 0xDC00) for ch in raw.decode("utf-8", "surrogateescape"))
        changed = True
    if "/" in text or "\x00" in text:
        text = text.replace("%", "%25").replace("/", "%2F").replace("\x00", "%00")
        changed = True
    if text in ("", ".", ".."):
        text = "%2E" * len(text) if text else "%"
        changed = True
    if len(text.encode("utf-8")) > NAME_MAX - 40:
        digest = hashlib.sha256(raw).hexdigest()[:16]
        keep = text.encode("utf-8")[:NAME_MAX - 58].decode("utf-8", "ignore")
        text = "%s~%s" % (keep, digest)
        changed = True
    return text, changed


def unique(used, name, n):
    """`name`, or a variant no sibling holds (letter case and Unicode
    normalisation aside, as APFS compares names), reserved in `used`."""
    cand, k = name, 0
    while fold(cand) in used:
        k += 1
        cand = "%s~n%d" % (name, n) if k == 1 else "%s~n%d.%d" % (name, n, k)
    used.add(fold(cand))
    return cand


def parse_members(members):
    """The item numbers and the item addresses a members list names."""
    if members is None:
        return None, None
    if not isinstance(members, list) or not members:
        fail("members is a non-empty list of item numbers (n) or locators (ad1:item=<address>) from the catalogue's members.tsv; leave it out to take every item")
    ns, addrs = set(), set()
    for m in members:
        if isinstance(m, int) and not isinstance(m, bool) and m >= 0:
            ns.add(m)
        elif isinstance(m, str) and m.startswith("ad1:item=") and m[9:].isascii() and m[9:].isdecimal() and len(m) <= 40:
            addrs.add(int(m[9:]))
        else:
            fail("members holds %s: an item number (n) or a locator (ad1:item=<address>) from members.tsv" % json.dumps(m))
    return ns, addrs


class Budget(Exception):
    pass


def write_file(img, item, dest, notes, used, stop):
    """Write one item's content to dest: (size, hashes, check, why, the name
    it is kept under). A content that breaks, a budget that is reached, or a
    write that fails, leaves what was written as <name>.partial (or nothing),
    and says so; the partial's name is one no other item of its directory
    holds, and its size and sha256 (the sixth value) are those of the bytes kept."""
    hs = [hashlib.md5(), hashlib.sha1(), hashlib.sha256()]
    size, broke, kept_hash = 0, None, ""
    try:
        fh = open(dest, "xb")
    except OSError as e:
        return 0, None, "not-written", "cannot be written: %s" % (e.strerror or e), "", ""
    try:
        with fh:
            for block in img.content(item):
                reason = stop(len(block))
                if reason:
                    raise Budget(reason)
                fh.write(block)
                size += len(block)
                for h in hs:
                    h.update(block)
    except Budget as e:
        broke = ("not-read", str(e))
    except AD1Error as e:
        broke = ("not-read", str(e))
    except OSError as e:
        broke = ("not-written", "the write failed: %s" % (e.strerror or e))
    if broke is None:
        return size, hs, "", "", dest.name, ""
    # One allocator for every name in the directory, whole or partial; and a name that is on disk is taken.
    k, kept_name = 0, unique(used, dest.name + ".partial", item["n"])
    part = dest.with_name(kept_name)
    while part.exists() or part.is_symlink():
        k += 1
        kept_name = unique(used, dest.name + ".partial", item["n"] + k)
        part = dest.with_name(kept_name)
    kept = part.name
    try:
        try:
            os.link(dest, part)        # fails where the name is taken: never over another file
            os.unlink(dest)
        except FileExistsError:
            raise
        except OSError:
            # A file system with no hard links (exFAT, a mounted share): a rename, once the name is seen to be free.
            if part.exists() or part.is_symlink():
                raise
            os.rename(dest, part)
        try:
            kept_size = os.path.getsize(part)
        except OSError:
            kept_size = size
        h = hashlib.sha256()
        with open(part, "rb") as rf:
            for chunk in iter(lambda: rf.read(1 << 20), b""):
                h.update(chunk)
        notes.append("partial: %d of %d bytes kept" % (kept_size, item["size"]))
        size, kept_hash = kept_size, h.hexdigest()
    except OSError:
        try:
            os.unlink(dest)
            kept = ""
            notes.append("partial: nothing kept (it could not be renamed)")
        except OSError:
            kept = dest.name
            notes.append("partial: %d of %d bytes left under its own name (it could be neither renamed nor removed)" % (size, item["size"]))
    return size, None, broke[0], broke[1], kept, kept_hash


def main():
    try:
        args = json.load(sys.stdin)
    except (ValueError, RecursionError) as e:
        fail("arguments are JSON on stdin: %s" % str(e)[:200])
    if not isinstance(args, dict):
        fail("arguments are a JSON object")
    image = args.get("image")
    if not isinstance(image, str) or not image or "\0" in image:
        fail("image is required: the AD1 image's first segment (.ad1)")
    want_n, want_addr = parse_members(args.get("members"))
    budgets = {}
    # What the call took otherwise than it was asked, and why: said in the answer (adjusted), never silent.
    adjusted = []
    for key, default, ceiling in (("max_items", ITEMS_DEFAULT, ITEMS_CEILING), ("max_walk", WALK_DEFAULT, WALK_CEILING), ("max_bytes", BYTES_DEFAULT, BYTES_CEILING), ("max_ratio", RATIO_DEFAULT, RATIO_CEILING), ("max_seconds", SECONDS_DEFAULT, SECONDS_CEILING)):
        v = args.get(key, default)
        # Over the ceiling is held to it and said: a seat that asked for 3000 seconds was refused and sent the call again (the run s571aaa).
        if isinstance(v, int) and not isinstance(v, bool) and v > ceiling:
            adjusted.append("%s %d is over this tool's ceiling of %d: held to %d" % (key, v, ceiling, ceiling))
            v = ceiling
        if not isinstance(v, int) or isinstance(v, bool) or not 1 <= v <= ceiling:
            fail("%s is a whole number from 1 to %d" % (key, ceiling), **{key: v})
        budgets[key] = v
    started = time.monotonic()
    deadline = started + budgets["max_seconds"]
    stem = os.path.basename(image)
    if stem.lower().endswith(".ad1"):
        stem = stem[:-4]
    in_job = bool(os.environ.get("OUT") and os.environ.get("JOB_ID"))
    out_arg = args.get("out_dir") or (os.path.join(os.environ["OUT"], stem) if in_job else os.path.join("work", os.environ.get("AGENT_ID") or "ad1", "ad1", stem))
    if not isinstance(out_arg, str) or "\0" in out_arg:
        fail("out_dir is a string without a NUL byte: a new or empty directory", out_dir=str(out_arg)[:200])
    # In a job a relative out_dir ("tree") is taken under $OUT, the one place a job writes, and said (it was refused, on the run s571aaa).
    if in_job and not os.path.isabs(out_arg):
        adjusted.append("out_dir %r is relative: in a job it is taken under $OUT, as %s" % (out_arg, os.path.join(os.environ["OUT"], out_arg)))
        out_arg = os.path.join(os.environ["OUT"], out_arg)
    # In a job the bytes written are held to the room where $OUT is, less a margin: a whole-image call that ran into a full disk
    # stopped part way through a file with an error (three jobs of the Batman III runs); held here it stops by its budget, between
    # items, keeping what it wrote, and says so.
    if in_job:
        try:
            room = shutil.disk_usage(os.environ["OUT"]).free - DISK_MARGIN
        except OSError:
            room = None
        if room is not None and budgets["max_bytes"] > max(room, 1):
            adjusted.append("max_bytes %d is more than the %d bytes free where $OUT is, less a margin of %d: held to %d, so the call stops by its budget instead of filling the disk; name fewer members to take the rest in another job"
                            % (budgets["max_bytes"], room + DISK_MARGIN, DISK_MARGIN, max(room, 1)))
            budgets["max_bytes"] = max(room, 1)
    try:
        out = resolve_output(out_arg)
        holds_something = out.exists() and (not out.is_dir() or any(out.iterdir()))
    except OSError as e:
        fail("out_dir cannot be used: %s" % (e.strerror or e), out_dir=out_arg[:200])
    if holds_something:
        fail("out_dir already holds something: name a new or empty directory", out_dir=str(out_arg))
    try:
        img = AD1(image)
    except AD1Error as e:
        fail("not an AD1 image this tool reads: %s" % e, image=image)
    except OSError as e:
        fail("cannot read %s: %s" % (image, e.strerror or e))
    errors = list(img.errors)
    soft = [0]         # errors that are only a budget's stop: the answer is valid for what was examined, and says where it stopped
    if img.missing:
        names = img.missing if len(img.missing) <= 5 else img.missing[:2] + ["...", img.missing[-1]]
        errors.append("the image has %d segments and %d of them (%s) %s not there, beside the first or in this job's view (declare every segment in inputs): what lies in them is not read"
                      % (img.segment["count"], len(img.missing), ", ".join(names), "is" if len(img.missing) == 1 else "are"))
    # The names and places of the directories the walk is inside, and nothing else: the walk is depth first, so when it leaves a
    # subtree that subtree's state is dropped, and what is held is the depth of the tree, not the number of items.
    chain = []         # [{n, selected, placed_rel, dir_of, children_dir, is_dir}], the ancestors of the item being looked at
    # The manifest's own names, at the top of out_dir, are not an item's.
    taken = {"": {fold(MANIFEST), fold(ERRORS), fold(COVERAGE), fold(GAPS)}}  # directory (relative) -> folded names already used there
    walked = 0
    seen_n, seen_addr = set(), set()       # the wanted numbers and addresses that were met, not every item's
    near_of = {a: [None, None] for a in sorted(want_addr)[:16]} if want_addr else {}
    counts = {"items": 0, "files": 0, "folders": 0, "bytes": 0, "renamed": 0, "mismatches": 0, "checked": 0}
    tally = {"no_stored_hash": 0, "not_read": 0}
    reached = [None]                      # the budget that stopped the call, if one did
    this_file = [0]

    def stop(nbytes):
        """Why the call must stop, or None: the time budget, or the bytes budget with this block counted."""
        this_file[0] += nbytes
        if time.monotonic() > deadline:
            reached[0] = reached[0] or "the time budget of %d seconds was reached" % budgets["max_seconds"]
        elif counts["bytes"] + this_file[0] > budgets["max_bytes"]:
            reached[0] = reached[0] or "the output budget of %d bytes was reached" % budgets["max_bytes"]
        elif counts["bytes"] + this_file[0] > budgets["max_ratio"] * max(img.packed_read, 1) + RATIO_SLACK:
            reached[0] = reached[0] or ("the expansion limit max_ratio of %d was reached: %d bytes written from %d bytes of the image's content read (more than %d times)"
                                        % (budgets["max_ratio"], counts["bytes"] + this_file[0], img.packed_read, budgets["max_ratio"]))
        return reached[0]

    def coverage(status, extra=None):
        doc = {"tool": "ad1_extract", "image": image, "processing_status": status, "budgets": budgets, **counts, **tally,
               "elapsed_seconds": round(time.monotonic() - started, 1), **(extra or {})}
        tmp = out / (COVERAGE + ".tmp")
        temp_hold(tmp)
        try:                                     # whole or not at all: beside, then renamed over the name
            with open(tmp, "w", encoding="utf-8") as cf:
                json.dump(doc, cf, indent=2)
                cf.write("\n")
            temp_replace(tmp, out / COVERAGE)
            return True
        except OSError:
            temp_drop(tmp)
            return False
        except BaseException:
            temp_drop(tmp)
            raise
    try:
        out.mkdir(parents=True, exist_ok=True)
        man = open(out / MANIFEST, "x", encoding="utf-8", newline="\n")
    except OSError as e:
        img.close()
        fail("cannot write in out_dir: %s" % (e.strerror or e), out_dir=str(out_arg))
    stopped = None

    writing = [None]                      # the file being written, so that a stop can keep it under a name that says it is not whole

    held_gaps = [None]                    # the gaps file, so that a stop closes it with every row it was given (gaps.jsonl is whole lines up to the stop)

    def _stopped(signum):
        try:
            man.flush()
        except (OSError, ValueError):
            pass
        if held_gaps[0] is not None:
            held_gaps[0].close()
        kept = None
        if writing[0] is not None and os.path.lexists(writing[0]):
            k, kept = 0, str(writing[0]) + ".partial"
            while os.path.lexists(kept):
                k += 1
                kept = "%s.partial.%d" % (writing[0], k)
            try:
                os.rename(writing[0], kept)
            except OSError:
                kept = None
        coverage("partial", {"integrity_status": "unverified", "interrupted": True, "signal": signum})
        print(json.dumps({"ok": False, "status": "partial", "processing_status": "partial", "integrity_status": "unverified", "interrupted": True, "signal": signum,
                          "image": image, "out_dir": str(out_arg), "manifest": os.path.join(str(out_arg), MANIFEST), "coverage": os.path.join(str(out_arg), COVERAGE),
                          **counts, "partial_file": os.path.relpath(kept, str(out_arg)) if kept else None,
                          "status_basis": "the tool was stopped by signal %d: what was written is in out_dir (the file being written is kept under a .partial name, and is not the item), "
                                          "the manifest lists the items before the stop, and nothing is claimed about the rest" % signum}), flush=True)
    install_signal_handlers(_stopped)
    coverage("incomplete")                # said before the first item, so a run cut short leaves this file
    close_error = []

    @contextlib.contextmanager
    def closing_manifest(fh):
        """The manifest is closed whatever happens, and a close that fails (the last bytes could not be written) is said, not raised."""
        try:
            yield fh
        finally:
            try:
                fh.close()
            except OSError as exc:
                close_error.append("stopped: %s; the manifest does not hold everything that was written" % (exc.strerror or exc))

    with closing_manifest(man):
        try:
            man.write("n\ttype\tpath\tpath_b64\tlocator\twritten\tsize\tsha256\tcheck\tnote\n")
            for item in img.walk():
                n = item["n"]
                if time.monotonic() > deadline and not reached[0]:
                    reached[0] = "the time budget of %d seconds was reached" % budgets["max_seconds"]
                if reached[0]:
                    # Checked for every item, wanted or not: a long walk past the last wanted item is not free either.
                    errors.append("stopped: %s; item %d (%s) and every item after it in the image's order were not examined" % (reached[0], n, esc(item["path"])))
                    soft[0] += 1
                    break
                walked += 1
                if walked > budgets["max_walk"]:
                    reached[0] = "the walk budget of %d items was reached" % budgets["max_walk"]
                    errors.append("stopped: %s; item %d (%s) and every item after it in the image's order were not examined" % (reached[0], n, esc(item["path"])))
                    soft[0] += 1
                    break
                if want_n is not None and n in want_n:
                    seen_n.add(n)
                if want_addr is not None and item["addr"] in want_addr:
                    seen_addr.add(item["addr"])
                # The addresses either side of each locator asked for, for one the image does not hold (16 at most: two numbers each).
                for a, v in near_of.items():
                    x = item["addr"]
                    if x < a and (v[0] is None or x > v[0]):
                        v[0] = x
                    elif x > a and (v[1] is None or x < v[1]):
                        v[1] = x
                # Leaving a subtree: the chain is cut back to this item's parent, and the state of what was left goes with it.
                while chain and chain[-1]["n"] != item["parent"]:
                    left = chain.pop()
                    if left["children_dir"] is not None and left["children_dir"] != "":
                        taken.pop(left["children_dir"], None)
                if item["parent"] is None:
                    parent_dir, parent_selected = "", False
                else:
                    owner = chain[-1]
                    if owner["children_dir"] is None:
                        # A file's children (a stream, say) go beside it, in a directory of their own, named when the first one arrives.
                        owner["children_dir"] = os.path.join(owner["dir_of"], unique(taken[owner["dir_of"]], owner["placed"] + ".ad1-children", owner["n"]))
                    parent_dir, parent_selected = owner["children_dir"], owner["selected"]
                used = taken.setdefault(parent_dir, set())
                name, changed = safe_name(item["name"])
                placed = unique(used, name, n)
                changed = changed or placed != name
                rel = os.path.join(parent_dir, placed) if parent_dir else placed
                is_dir = item["type"] == AD1_FOLDER
                take = (want_n is None or n in want_n or item["addr"] in want_addr or (item["parent"] is not None and parent_selected))
                chain.append({"n": n, "selected": take, "placed": placed, "dir_of": parent_dir, "children_dir": rel if is_dir else None})
                if not take:
                    continue
                if counts["items"] >= budgets["max_items"]:
                    reached[0] = "the item budget of %d items was reached" % budgets["max_items"]
                elif time.monotonic() > deadline:
                    reached[0] = reached[0] or "the time budget of %d seconds was reached" % budgets["max_seconds"]
                if reached[0]:
                    errors.append("stopped: %s; item %d (%s) and every item after it in the image's order were not written or listed" % (reached[0], n, esc(item["path"])))
                    soft[0] += 1
                    break
                raw_path = item["path"]
                locator = "ad1:item=%d" % item["addr"]
                notes = ["renamed"] if changed else []
                if item["type"] == AD1_UNKNOWN_FILE:
                    notes.append("a file of unknown kind")
                if item["type"] == AD1_DELETED:
                    notes.append("deleted")
                counts["items"] += 1
                counts["renamed"] += changed
                dest = out / rel
                head = "%d\t%s\t%s\t%s\t%s\t" % (n, "dir" if is_dir else "file" if item["type"] in (AD1_FILE, AD1_UNKNOWN_FILE, AD1_DELETED) else "other:%d" % item["type"],
                                               esc(raw_path), base64.b64encode(raw_path).decode(), locator)
                try:
                    dest.parent.mkdir(parents=True, exist_ok=True)
                    if is_dir:
                        dest.mkdir(exist_ok=True)
                except OSError as e:
                    errors.append("item %d (%s, %s): cannot be written at %s: %s" % (n, esc(raw_path), locator, esc(rel.encode()), e.strerror or e))
                    man.write(head + "\t\t\tnot-written\t%s\n" % ",".join(notes + ["cannot be written"]))
                    continue
                if is_dir:
                    counts["folders"] += 1
                    man.write(head + "%s\t\t\t\t%s\n" % (esc(rel.encode()), ",".join(notes)))
                    continue
                md5 = (ad1_text(item["meta"], 0x5001) or b"").strip().decode("ascii", "replace").lower()
                sha1 = (ad1_text(item["meta"], 0x5002) or b"").strip().decode("ascii", "replace").lower()
                this_file[0] = 0
                writing[0] = dest
                size, hs, check, why, kept, kept_hash = write_file(img, item, dest, notes, used, stop)
                writing[0] = None
                if hs is None:
                    errors.append("item %d (%s, %s): %s" % (n, esc(raw_path), locator, why))
                    if reached[0] and why == reached[0]:
                        soft[0] += 1                          # the item was cut by the budget: the budget's stop is said once more below
                    written = esc(os.path.join(os.path.dirname(rel), kept).encode()) if kept else ""
                    # The sha256 of a partial row is of the bytes kept, not of the item.
                    man.write(head + "%s\t%d\t%s\t%s\t%s\n" % (written, size, kept_hash, check, ",".join(notes)))
                    counts["files"] += 1
                    counts["bytes"] += size
                    tally["not_read"] += 1
                    if reached[0]:
                        errors.append("stopped: %s; item %d is kept as a partial, and every item after it in the image's order was not written or listed" % (reached[0], n))
                        soft[0] += 1
                        break
                    continue
                if not md5 and not sha1:
                    check = "no-stored-hash"
                    tally["no_stored_hash"] += 1
                elif (md5 and md5 != hs[0].hexdigest()) or (sha1 and sha1 != hs[1].hexdigest()):
                    check = "mismatch"
                    counts["mismatches"] += 1
                else:
                    check = "ok"
                counts["checked"] += 1
                counts["files"] += 1
                counts["bytes"] += size
                man.write(head + "%s\t%d\t%s\t%s\t%s\n" % (esc(rel.encode()), size, hs[2].hexdigest(), check, ",".join(notes)))
        except OSError as e:
            # The manifest itself could not be written (a full disk): stop, say so.
            stopped = "stopped: %s; the manifest lists what was written before" % (e.strerror or e)
        finally:
            img.close()
    if close_error:
        stopped = stopped or close_error[0]
    errors += img.walk_errors
    absent = sorted(want_n - seen_n) if want_n is not None else []
    gone = sorted(want_addr - seen_addr) if want_addr is not None else []
    # After a stop (a budget, a manifest that could not be written) the walk did not reach the end of the image: an item not
    # seen is not an item that is not there, and is not claimed to be absent.
    walked_all = not (reached[0] or stopped)
    if absent:
        soft[0] += 0 if walked_all else 1
        errors.append(("no item %s in this read of the image (it listed %d items)" if walked_all else
                       "item %s was not reached before the call stopped (it had looked at %d items): it is not claimed absent") % (", ".join(map(str, absent)), walked))
    if gone:
        soft[0] += 0 if walked_all else 1
        # A locator is an item's address as the catalogue's members.tsv lists it, not an offset in a segment file: a seat of the run
        # s68ce47 worked one out from a raw offset. The nearest addresses the walk met are named, and where the right ones are.
        near = ""
        picks = sorted({x for a in gone if a in near_of for x in near_of[a] if x is not None})
        if walked_all:
            near = ("; the nearest items this read holds are at %s" % ", ".join("ad1:item=%d" % x for x in picks) if picks else "") + \
                ". A locator is an item's address as the ad1-items generation's members.tsv lists it (catalog_search which=members), not an offset in a segment file"
        errors.append(("no item at %s in this read of the image" + near if walked_all else
                       "the item at %s was not reached before the call stopped: it is not claimed absent") % ", ".join("ad1:item=%d" % a for a in gone))
    if stopped:
        errors.insert(0, stopped)
    # A walk that reached the end of the tree says what of the image's data nothing led to (a zeroed next pointer ends a chain
    # with no error): it cannot call the list whole, nor the digests it checked the image's.
    unaccounted = None
    gaps = None
    if walked_all and not img.walk_errors:
        # Read to its end under the call's clock; the gaps with non-zero bytes, or not read to their end, are all in ad1_extract.gaps.jsonl
        # (at most GAPS_FILE_MAX of them), the first AD1_GAPS_LISTED in the answer.
        gaps = GapFile(str(out / GAPS))
        held_gaps[0] = gaps
        try:
            unaccounted = ad1_unaccounted(img, deadline, gaps.add)
        finally:
            gaps.close()
        if unaccounted:
            errors.append(unaccounted)
            if img.gap_report["stopped_at"] is not None:
                reached[0] = reached[0] or "the time budget of %d seconds was reached while the data nothing led to was being read" % budgets["max_seconds"]
    processing = "complete" if not errors else ("partial" if counts["files"] or counts["folders"] else "failed")
    if counts["mismatches"]:
        integrity = "mismatch"
    elif counts["files"] == 0:
        integrity = "not_applicable"
    elif tally["no_stored_hash"] or tally["not_read"] or unaccounted:
        integrity = "unverified"
    else:
        integrity = "verified"
    unreferenced = None
    if gaps is not None and img.gap_report is not None:
        r = img.gap_report
        unreferenced = {"bytes": r["bytes"], "bytes_read": r["read"], "nonzero_bytes": r["nonzero_bytes"], "gaps": r["gaps"],
                        "gaps_with_nonzero_bytes": r["gaps_with_nonzero_bytes"], "gaps_not_read_to_the_end": r["gaps_not_read_to_the_end"],
                        "stopped_at": r["stopped_at"], "listed": r["listed"]}
        if gaps.written or gaps.error:
            unreferenced["file"] = os.path.join(str(out_arg), GAPS) if gaps.written else None
            unreferenced["file_rows"] = gaps.written
            unreferenced["file_note"] = "every gap with non-zero bytes or not read to its end, one JSON line each (listed has the first %d)%s" % (
                AD1_GAPS_LISTED, "; cut at %d rows" % GAPS_FILE_MAX if gaps.cut else "")
            if gaps.error:
                unreferenced["file_error"] = gaps.error
    if not coverage(processing, {"integrity_status": integrity, **({"unreferenced_data": unreferenced} if unreferenced else {})}):
        errors.append("%s could not be written whole (the earlier one, which says incomplete, stands)" % COVERAGE)
        if processing == "complete":
            processing = "partial"
    result = {"ok": processing == "complete" and integrity != "mismatch", "processing_status": processing, "integrity_status": integrity,
              "status": processing,
              "status_basis": {"complete": "the tree was walked to its end, every item selected was written, and the data the tree leads to accounts for the image's",
                               "partial": "a budget stopped the walk, an item broke or could not be written, a segment is not there, or the tree does not account for all of the image's data (see errors)",
                               "failed": "no item could be written (see errors)"}[processing],
              "image": image, "out_dir": str(out_arg), "manifest": os.path.join(str(out_arg), MANIFEST), "coverage": os.path.join(str(out_arg), COVERAGE),
              **counts, **tally, "segments_missing": img.missing, "budgets": budgets}
    if adjusted:
        result["adjusted"] = adjusted
    if unreferenced:
        result["unreferenced_data"] = unreferenced
    if integrity == "mismatch":
        result["integrity_note"] = ("%d file(s) were written whose content does not match the digests the image records (check mismatch in the manifest). "
                                    "The files were written; the exit status is 0 for a complete extraction, so read integrity_status" % counts["mismatches"])
    elif integrity == "unverified":
        result["integrity_note"] = ("%d file(s) have no stored digest and %d were not read: their content is not checked against the image" % (tally["no_stored_hash"], tally["not_read"])
                                    + ("; and the tree does not account for all of the image's data, so items may be missing from the list" if unaccounted else ""))
    if reached[0]:
        result["stopped_by_budget"] = reached[0]
    if errors:
        result["errors"] = errors[:SHOWN_ERRORS]
        result["errors_total"] = len(errors)
        if len(errors) > SHOWN_ERRORS:
            try:
                with open(out / ERRORS, "x", encoding="utf-8") as fh:
                    fh.write("\n".join(errors) + "\n")
                result["errors_file"] = os.path.join(str(out_arg), ERRORS)
            except OSError as e:
                result["errors_file_error"] = "the whole list could not be written: %s" % (e.strerror or e)
    if not in_job:
        result["note"] = "written where you called it, not sealed: run it as a job (job_run tool=ad1_extract) to have the files sealed into the store, citable as job:<id>/<path>, and catalogued by the derived catalogue"
    print_answer(result)
    # Exit 0 means the tool ran and what it examined is whole or said not to be: complete, or partial only because a budget stopped it
    # between items (processing_status says partial and stopped_by_budget says which). An item that broke or could not be written, a
    # manifest that could not be written, a segment that is not there: 1.
    return 0 if len(errors) == soft[0] else 1


if __name__ == "__main__":
    exit_code = 0
    try:
        sys.exit(main())
    except SystemExit as stop:
        exit_code = _code(stop)
    _leave(exit_code)
