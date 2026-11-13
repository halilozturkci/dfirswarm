#!/usr/bin/env python3
"""Read a Windows thumbnail or icon cache (thumbcache_*.db, iconcache_*.db; Vista and later) and write the images it stores.

Explorer keeps the thumbnails and icons it has rendered in %LOCALAPPDATA%\\Microsoft\\Windows\\Explorer, one file per size class. A file is a
24- or 28-byte header and then entries, each a header of its own, an identifier, padding and one stored image (a BMP, a JPEG or a PNG):

  file header   0  4  'CMMM'
                4  4  format version (0x14 Vista, 0x15 Windows 7, 0x1A/0x1C/0x1E Windows 8, 0x1F Windows 8.1, 0x20 Windows 10 and later)
                8  4  cache type (the size class, by a table that differs by version)
               12  .  offset of the first entry and of the first free byte (at 12 and 16, or behind one unknown field at 16 and 20)
  entry header  0  4  'CMMM'
                4  4  size of the whole entry
                8  8  entry hash
                .  .  Vista only: a four-character extension (UTF-16LE)
                .  4  identifier length in bytes, 4 padding length, 4 data length
                .  .  Windows 8 and later: 4 width, 4 height
                .  4  unknown, 8 data checksum, 8 header checksum

The read begins at the end of the file header, whatever the header gives as the offset of its first entry: an entry that lies before that
offset is read as an entry and marked, and bytes there that are neither an entry nor zero are counted like any others. Every length is checked
against the entry and the entry against the file: an entry whose parts do not fit it is a problem line and the next 'CMMM' is looked for; a
file that ends inside an entry gives a truncated row and a partial answer, and its image is written only when every byte of the image is in the
file. A version that is not in the table is refused, not guessed. The index (thumbcache_idx.db, 'IMMM') and the older IconCache.db are other
formats and are answered as such. The checksums are copied and not verified.

An image is copied out under a name this tool makes (the number of the cache file in this call, the entry's number and its hash in hexadecimal),
never one the evidence gives, and a file that is there is never replaced. The images directory is the tool's own: one that is a link, or a $OUT
that is not there, is refused before anything is read. Only regular files are opened, without blocking and without following a link.
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


import json
import os
import re
import stat
import struct
import sys
from pathlib import Path

# Lossless paging (the same in every library tool that pages): the page an
# agent reads stays small, and when there are more rows the whole result is
# written as JSON Lines under work/<agent>/tool-output and named.
import hashlib
import json
import os
import re
import tempfile
from pathlib import Path


class LosslessPage:
    def __init__(self, tool: str, key: object, limit: int):
        if isinstance(limit, bool) or not isinstance(limit, int) or limit < 1:
            raise ValueError("limit must be a positive integer")
        self.tool = re.sub(r"[^A-Za-z0-9_.-]", "_", tool)
        self.limit = limit
        self.page: list[object] = []
        self.total = 0
        self._out = None
        self._tmp: Path | None = None
        digest = hashlib.sha256(
            json.dumps(key, sort_keys=True, default=str).encode("utf-8")
        ).hexdigest()[:16]
        name = f"{self.tool}-{digest}.jsonl"
        job, out = os.environ.get("JOB_ID"), os.environ.get("OUT")
        if job and out:
            # In a job only $OUT is written, and it is sealed as the job's
            # output: the whole result is cited from there.
            self.path = Path(out) / "tool-output" / name
            self.shown = "store/jobs/%s/out/tool-output/%s" % (re.sub(r"[^A-Za-z0-9_.-]", "_", job), name)
        else:
            agent = re.sub(
                r"[^A-Za-z0-9_.-]", "_", os.environ.get("AGENT_ID") or "tool"
            )
            self.path = Path("work") / agent / "tool-output" / name
            self.shown = str(self.path)

    def _cannot_write(self, exc: BaseException) -> None:
        """The whole result cannot be kept: say so as JSON and stop, never a traceback."""
        import sys as _sys
        # The hidden temp file goes first: a page that cannot be written leaves nothing behind (a full disk, a quota).
        out, self._out = self._out, None
        try:
            if out is not None:
                out.close()
        except BaseException:
            pass
        try:
            if self._tmp is not None:
                os.unlink(self._tmp)
        except OSError:
            pass
        _sys.stdout.write(json.dumps({
            "error": "the whole result (%d rows so far) cannot be written to %s: %s. Outside a job the place is your own "
                     "work/<your id>/ directory; in a job it is $OUT." % (self.total, self.shown, exc),
            "status": "failed",
        }) + "\n")
        _sys.exit(1)

    def _write(self, row: object) -> None:
        assert self._out is not None
        text = json.dumps(row, ensure_ascii=False, default=str)
        try:
            text.encode("utf-8")
        except UnicodeEncodeError:
            # A lone surrogate (a file name that is not UTF-8): escape it, lose nothing.
            text = json.dumps(row, ensure_ascii=True, default=str)
        try:
            self._out.write(text)
            self._out.write("\n")
        except OSError as exc:
            self._cannot_write(exc)

    def add(self, row: object) -> None:
        self.total += 1
        if len(self.page) < self.limit:
            self.page.append(row)
            return
        if self._out is None:
            try:
                self.path.parent.mkdir(parents=True, exist_ok=True)
                fd, name = tempfile.mkstemp(
                    dir=self.path.parent, prefix=f".{self.path.name}-"
                )
                self._tmp = Path(name)
                self._out = os.fdopen(fd, "w", encoding="utf-8")
            except OSError as exc:
                self._cannot_write(exc)
            for kept in self.page:
                self._write(kept)
        self._write(row)

    def finish(self) -> dict:
        result = {
            "matched": self.total,
            "returned": len(self.page),
            "truncated": self.total > len(self.page),
        }
        if self._out is not None:
            try:
                self._out.flush()
                os.fsync(self._out.fileno())
                self._out.close()
                assert self._tmp is not None
                os.replace(self._tmp, self.path)
            except OSError as exc:
                self._cannot_write(exc)
            result["all_results"] = self.shown
            result["all_results_format"] = "JSON Lines, one complete result per line"
        return result

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


# BEGIN SHARED PAGE
# The same text is in every windows-forensics tool that pages through LosslessPage (held equal by a windows-forensics test): LosslessPage replaces a file of the
# same name; this one places its finished file with place_without_replacing, and registers itself so that a stop can remove its temporary file.
PAGES = []


class NoReplacePage(LosslessPage):
    """LosslessPage whose finished file is placed without replacing an earlier file of the same name (a rerun with other limits, or one
    the time limit stopped, must not leave a smaller file where a larger one was)."""

    def __init__(self, tool, key, limit):
        super().__init__(tool, key, limit)
        PAGES.append(self)

    def add(self, row: object, *rest) -> object:
        """The hidden temporary file is made, and registered in `_tmp`, with the stop signals held: a stop that landed between mkstemp and the
        registration found no file to remove and left a hidden one behind (the SIGTERM case of tests/pack-windows-forensics-fs-contract.test.ts, 1 run
        in many on a loaded Mac). A signal that comes in meanwhile waits and is answered, by the handler that removes the file, as soon as the
        registration is in."""
        if self._out is not None or len(self.page) < self.limit:
            return super().add(row, *rest)
        before = None
        try:
            before = signal.pthread_sigmask(signal.SIG_BLOCK, {signal.SIGTERM, signal.SIGINT, signal.SIGHUP})
        except (AttributeError, ValueError, OSError):
            pass
        try:
            return super().add(row, *rest)
        finally:
            if before is not None:
                signal.pthread_sigmask(signal.SIG_SETMASK, before)

    def finish(self) -> dict:
        result = {"matched": self.total, "returned": len(self.page), "truncated": self.total > len(self.page)}
        if self._out is not None:
            try:
                self._out.flush()
                os.fsync(self._out.fileno())
                self._out.close()
                assert self._tmp is not None
                placed = place_without_replacing(self._tmp, self.path)
            except OSError as exc:
                self._cannot_write(exc)
            self._tmp = None
            self.path = placed
            self.shown = self.shown[: len(self.shown) - len(Path(self.shown).name)] + placed.name
            result["all_results"] = self.shown
            result["all_results_format"] = "JSON Lines, one complete result per line"
        return result
# END SHARED PAGE


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


PARSER = "thumbcache_read/3"
MAGIC = b"CMMM"
INDEX_MAGIC = b"IMMM"
DEADLINE_SECONDS = 100            # the manifest allows 120: the reads and the writes stop here, so that the page is placed and the answer printed before the harness ends it
MAX_LIMIT = 1000                  # the largest inline page (a row is a few hundred bytes); the whole result is in the file the answer names
DEFAULT_LIMIT = 100
DEFAULT_MAX_ENTRIES = 200_000
MAX_MAX_ENTRIES = 2_000_000
DEFAULT_IMAGE_BYTES = 64 << 20    # an entry whose stored image is larger is listed and not written
DEFAULT_OUTPUT_BYTES = 1 << 30    # the images written in one call
MAX_OUTPUT_BYTES = 8 << 30
MAX_FILES = 200                   # cache files read from one directory
MAX_PROBLEMS = 50
IDENTIFIER_SHOWN = 128
BLOCK = 1 << 20
PROGRESS = {"files": 0, "entries": 0, "written": 0}
TEMPS = []                        # image files being written: removed on every way out unless they were placed

# The header's version, as Windows wrote it, and the layout each one has (the entry header's size; whether the entry carries a width and a height;
# where in the 24 or 28 bytes of the file header the offset of the first entry and of the first free byte are). The table is the one the
# published readers of the format use (thumbcache_viewer's structures); what this tool was run against is in the manifest.
#   version: (label, entry header bytes, layout, offset of "first entry", offset of "first free byte", file header bytes)
VERSIONS = {
    0x14: ("Windows Vista", 56, "vista", 12, 16, 24),
    0x15: ("Windows 7", 48, "seven", 12, 16, 24),
    0x1A: ("Windows 8", 56, "eight", 12, 16, 24),
    0x1C: ("Windows 8 (v2)", 56, "eight", 16, 20, 28),
    0x1E: ("Windows 8 (v3)", 56, "eight", 16, 20, 24),
    0x1F: ("Windows 8.1", 56, "eight", 16, 20, 24),
    0x20: ("Windows 10 and later", 56, "eight", 16, 20, 24),
}
# What the header's cache type number means, by version: the size class or the kind of the cache.
TYPES_OLD = ("32", "96", "256", "1024", "sr")
TYPES_8 = ("16", "32", "48", "96", "256", "1024", "sr", "wide", "exif")
TYPES_81 = ("16", "32", "48", "96", "256", "1024", "1600", "sr", "wide", "exif", "wide_alternate")
TYPES_10 = ("16", "32", "48", "96", "256", "768", "1280", "1920", "2560", "sr", "wide", "exif", "wide_alternate", "custom_stream")
TYPES = {0x14: TYPES_OLD, 0x15: TYPES_OLD, 0x1A: TYPES_8, 0x1C: TYPES_8, 0x1E: TYPES_8, 0x1F: TYPES_81, 0x20: TYPES_10}
CACHE_NAME = re.compile(r"(thumbcache|iconcache)_([A-Za-z0-9_]+)\.db$", re.I)
IMAGE_MAGIC = ((b"BM", "bmp"), (b"\xff\xd8\xff", "jpeg"), (b"\x89PNG\r\n\x1a\n", "png"))
EXTENSION = {"bmp": "bmp", "jpeg": "jpg", "png": "png", "unknown": "bin"}


def drop_pages():
    """Remove the temporary files of the pages and of the images that were being written (the STOP block removes the pages' on a signal)."""
    for page in list(PAGES):
        tmp = getattr(page, "_tmp", None)
        if tmp is not None:
            try:
                os.unlink(tmp)
            except OSError:
                pass
            page._tmp = None
    for name in list(TEMPS):
        try:
            os.unlink(name)
        except OSError:
            pass
        if name in TEMPS:
            TEMPS.remove(name)


def fail(message, **extra):
    drop_pages()
    print_answer({"error": message, "status": "failed", "status_basis": "the tool stopped with an error and read no cache (see error)", **extra})
    raise SystemExit(1)


def last_word(signum):
    for name in list(TEMPS):
        try:
            os.unlink(name)
        except OSError:
            pass
    interrupted_answer(signum, files_started=PROGRESS["files"], entries_read=PROGRESS["entries"], images_written=PROGRESS["written"],
                       note="the images placed before the stop are whole files; no list of them was written")


def describe(exc):
    return "%s%s" % (type(exc).__name__, (": " + exc.strerror) if getattr(exc, "strerror", None) else "")


def pread(fd, length, offset):
    """Up to `length` bytes at `offset`, read in pieces (a short read is not the end of the file)."""
    parts, got = [], 0
    while got < length:
        piece = os.pread(fd, min(length - got, BLOCK), offset + got)
        if not piece:
            break
        parts.append(piece)
        got += len(piece)
    return b"".join(parts)


def shown_text(raw):
    """An entry's identifier (UTF-16LE in the file) as text that can be printed: at most IDENTIFIER_SHOWN characters, a character that is not
    printable replaced by '?'. Windows writes the entry hash in hexadecimal there; the text is the evidence's and is shown as a name, not judged."""
    text = raw[:len(raw) - (len(raw) % 2)].decode("utf-16-le", "replace").split("\x00", 1)[0]
    shown = "".join(c if c.isprintable() and c != "�" else "?" for c in text[:IDENTIFIER_SHOWN])
    return shown, len(text)


def image_kind(head):
    for magic, kind in IMAGE_MAGIC:
        if head.startswith(magic):
            return kind
    return "unknown"


def image_size(kind, head):
    """The width and height the stored image's own header declares (BMP and PNG; a JPEG's is not at a fixed place and is not looked for)."""
    try:
        if kind == "bmp" and len(head) >= 26:
            width, height = struct.unpack_from("<ii", head, 18)
            return width, abs(height)
        if kind == "png" and len(head) >= 24 and head[12:16] == b"IHDR":
            return struct.unpack_from(">II", head, 16)
    except struct.error:
        pass
    return None, None


def name_class(name):
    found = CACHE_NAME.search(name)
    return (found.group(1).lower(), found.group(2).lower()) if found else (None, None)


def output_directory(identity):
    job, out = os.environ.get("JOB_ID"), os.environ.get("OUT")
    name = "thumbcache_read-" + identity
    if job and out:
        return Path(out) / name, "store/jobs/%s/out/%s" % (re.sub(r"[^A-Za-z0-9_.-]", "_", job), name)
    agent = re.sub(r"[^A-Za-z0-9_.-]", "_", os.environ.get("AGENT_ID") or "tool")
    return Path("work") / agent / name, str(Path("work") / agent / name)


def refuse_output_place(directory, shown_dir, extract):
    """Why nothing may be written to the images directory, or None. In a job $OUT must be there (it is the harness's to make, never this
    tool's), and the images directory, if something is at its name, must be a directory of its own and not a link: a link planted there
    would send every image somewhere else."""
    job, out = os.environ.get("JOB_ID"), os.environ.get("OUT")
    if job and out and not os.path.isdir(out):
        return "$OUT is not an existing directory: it is not created by this tool, and nothing was read or written"
    if not extract:
        return None                   # no image is written: the directory is not touched
    try:
        mode = os.lstat(directory).st_mode
    except OSError:
        return None
    if stat.S_ISLNK(mode):
        return "%s is a symbolic link: nothing is written through it, and nothing was read (remove the link, or name another output place)" % shown_dir
    if not stat.S_ISDIR(mode):
        return "%s is there and is not a directory: nothing was written or read" % shown_dir
    return None


def make_output_directory(directory):
    """Make the images directory (in a job only the directory itself, under a $OUT that is there; outside a job its parents under work/ too)
    and hold that it is a directory of its own, not a link."""
    import errno
    job, out = os.environ.get("JOB_ID"), os.environ.get("OUT")
    if not (job and out):
        os.makedirs(directory.parent, exist_ok=True)
    try:
        os.mkdir(directory)
    except FileExistsError:
        pass
    if not stat.S_ISDIR(os.lstat(directory).st_mode):
        raise OSError(errno.ENOTDIR, "the images directory is a link or not a directory, and nothing is written through it")


class Budget:
    def __init__(self, entries, image_bytes, output_bytes):
        self.entries_left = entries
        self.image_bytes = image_bytes
        self.output_left = output_bytes
        self.stopped = None           # why no further entry is read (the clock, the entry bound)
        self.output_full = False


def write_image(fd, offset, length, directory, shown_dir, name):
    """Copy `length` bytes of the cache at `offset` to a new file in `directory`, hashing them on the way, and place it without replacing what is
    there (the same bytes are named again; other bytes take the next free name). Returns (shown path, sha256, bytes written)."""
    import hashlib
    import tempfile
    make_output_directory(directory)
    digest = hashlib.sha256()
    before = None
    try:
        before = signal.pthread_sigmask(signal.SIG_BLOCK, {signal.SIGTERM, signal.SIGINT, signal.SIGHUP})
    except (AttributeError, ValueError, OSError):
        pass
    try:
        out_fd, tmp = tempfile.mkstemp(dir=directory, prefix=".%s-" % name)
        TEMPS.append(tmp)
    finally:
        if before is not None:
            signal.pthread_sigmask(signal.SIG_SETMASK, before)
    done = 0
    with os.fdopen(out_fd, "wb") as out:
        while done < length and not out_of_time():
            piece = os.pread(fd, min(length - done, BLOCK), offset + done)
            if not piece:
                break
            digest.update(piece)
            out.write(piece)
            done += len(piece)
    if done < length:
        # The clock ran out (or the file shrank) inside the image: a part of an image is not a result, so nothing is placed.
        try:
            os.unlink(tmp)
        except OSError:
            pass
        if tmp in TEMPS:
            TEMPS.remove(tmp)
        return None, None, done
    os.chmod(tmp, 0o644)
    placed = place_without_replacing(tmp, directory / name)
    if tmp in TEMPS:
        TEMPS.remove(tmp)
    return "%s/%s" % (shown_dir, placed.name), digest.hexdigest(), done


def digest_at(fd, offset, length):
    """(the SHA-256 of `length` bytes at `offset`, the bytes read); the digest is None when the clock ran out before the last byte."""
    import hashlib
    digest, done = hashlib.sha256(), 0
    while done < length and not out_of_time():
        piece = os.pread(fd, min(length - done, BLOCK), offset + done)
        if not piece:
            break
        digest.update(piece)
        done += len(piece)
    return (digest.hexdigest() if done == length else None), done


def next_magic(fd, start, size):
    """The offset of the next 'CMMM' that lies whole between `start` and `size`, or `size` when there is none; and whether a byte that is not
    zero lies before it. Nothing at or past `size` is read. Read in blocks, the clock looked at between them (None, None when it ran out)."""
    pos, nonzero, carry = start, False, b""
    while pos < size:
        if out_of_time():
            return None, None
        chunk = os.pread(fd, min(BLOCK, size - pos), pos)
        if not chunk:
            break
        data = carry + chunk
        at = data.find(MAGIC)
        if at >= 0:
            if data[:at].strip(b"\x00"):
                nonzero = True
            return pos - len(carry) + at, nonzero
        if chunk.strip(b"\x00"):
            nonzero = True
        carry = data[-3:]
        pos += len(chunk)
    return size, nonzero


def read_cache(path, rows, budget, extract, include_free, directory, shown_dir, prefix):
    """Read one cache file: its header, then every entry from the end of the header to the end of the file (the header's own offset of its
    first entry decides nothing about what is read). `prefix` is this tool's own name for the file, which the images are named by. Returns
    what the answer says of the file."""
    said = {"file": path, "output_prefix": prefix, "status": "complete", "entries": 0, "entries_with_image": 0, "images_written": 0, "image_bytes_written": 0, "problems": []}
    reasons = []

    def problem(text):
        if len(said["problems"]) < MAX_PROBLEMS:
            said["problems"].append(text)
        said["problem_count"] = said.get("problem_count", 0) + 1

    def ended(status, why):
        said["status"] = status
        said["status_basis"] = why
        return said

    base = os.path.basename(path)
    family, by_name = name_class(base)
    said["cache_family_from_name"], said["size_class_from_name"] = family, by_name
    try:
        mode = os.lstat(path).st_mode
        if stat.S_ISLNK(mode):
            return ended("failed", "a link, not followed: the file was not opened")
        if not stat.S_ISREG(mode):
            return ended("failed", "not a regular file: it was not opened")
        fd = os.open(path, os.O_RDONLY | getattr(os, "O_NONBLOCK", 0) | getattr(os, "O_NOFOLLOW", 0))
    except OSError as exc:
        return ended("failed", "the file could not be opened (%s)" % describe(exc))
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode):
            return ended("failed", "not a regular file: it was not read")
        size = info.st_size
        said["bytes"] = size
        head = pread(fd, 28, 0)
        if head[:4] == INDEX_MAGIC:
            said["format"] = "index (IMMM)"
            return ended("failed", "this is the cache's index (it begins 'IMMM'): it holds no image and its layout is not read by this tool; the images are in the "
                                   "thumbcache_<size>.db files beside it")
        if head[:4] != MAGIC:
            said["format"] = "not a thumbnail cache"
            return ended("failed", "the file does not begin with 'CMMM' (%d bytes): it is not a thumbcache_*.db or iconcache_*.db of Windows Vista or later, and nothing was "
                                   "read from it (IconCache.db, without a size in its name, is another format this tool does not read)" % size)
        if len(head) < 24:
            return ended("partial", "the file is %d bytes, shorter than the 24 bytes of a cache header: no entry was read" % size)
        version, cache_type = struct.unpack_from("<II", head, 4)
        said["format_version"] = "0x%02X" % version
        said["cache_type"] = cache_type
        if version not in VERSIONS:
            return ended("failed", "the header's version is 0x%X, which is not one this tool has a layout for (0x14, 0x15, 0x1A, 0x1C, 0x1E, 0x1F, 0x20): no entry was "
                                   "read, and the layout is not guessed" % version)
        label, entry_header, layout, first_at, free_at, header_bytes = VERSIONS[version]
        said["windows"] = label
        kinds = TYPES[version]
        said["size_class_from_header"] = kinds[cache_type] if cache_type < len(kinds) else None
        if said["size_class_from_header"] is None:
            problem("the header's cache type %d has no meaning in the table for version 0x%X" % (cache_type, version))
        elif by_name is not None and by_name != said["size_class_from_header"]:
            problem("the file's name says '%s' and its header says '%s'" % (by_name, said["size_class_from_header"]))
        if len(head) < header_bytes:
            return ended("partial", "the file is %d bytes, shorter than the %d bytes of this version's header: no entry was read" % (size, header_bytes))
        first, free = struct.unpack_from("<I", head, first_at)[0], struct.unpack_from("<I", head, free_at)[0]
        said["first_entry_offset"], said["first_free_offset"] = first, free
        said["first_entry_offset_from"] = "header"
        first_usable = not (first < header_bytes or first > size or (first < size and pread(fd, 4, first) != MAGIC and first != free))
        if not first_usable:
            said["first_entry_offset_from"] = "search"
            problem("the header's first entry offset (%d) is not where an entry begins: the first 'CMMM' after the header was looked for instead" % first)
        if free > size:
            problem("the header's first free offset (%d) is past the end of the file (%d bytes): the file is shorter than its header says" % (free, size))
            reasons.append("the file ends before the offset its header gives for its first free byte (%d of %d bytes are there)" % (size, free))
        # The read begins at the end of the header, never at the header's own offset: what lies between the two is read like the rest of the
        # file (an entry there is an entry, bytes there that are no entry and not zero are counted), so an offset that points past real
        # entries hides none of them.
        pos = header_bytes
        said["read_from_offset"] = pos
        gaps = {"zero_bytes": 0, "other_bytes": 0, "other": 0}
        end = size if include_free or not header_bytes <= free <= size else free
        said["read_to_offset"] = end
        # An entry's declared size can be larger than its parts (header, identifier, padding, data). The read goes on from the end of its parts,
        # never from its declared end: what lies in the rest of its declared size (its slack) is read like any other stretch of the file. An entry
        # that begins there is read as an entry and marked inside_entry_at; bytes there that are neither an entry nor zero are counted in
        # bytes_not_in_an_entry; zeros there are the entry's own and are not counted.
        slacks = []                                            # (offset of the entry, its declared end) of the entries whose slack is being read
        while pos < end:
            slacks = [s for s in slacks if s[1] > pos]
            if out_of_time():
                budget.stopped = "the tool's own clock (%d s) ran out" % DEADLINE_SECONDS
            if budget.stopped is None and budget.entries_left <= 0:
                budget.stopped = "max_entries was reached"
            if budget.stopped:
                reasons.append("%s at offset %d of %d: the entries from there on were not read" % (budget.stopped, pos, size))
                break
            head = pread(fd, entry_header, pos)
            if head[:4] != MAGIC and slacks:
                owner = slacks[-1][0]
                at, nonzero = next_magic(fd, pos, min(min(s[1] for s in slacks), end))
                if at is None:
                    continue                                   # the clock ran out inside the search: said at the top of the loop
                if nonzero:
                    gaps["other"] += 1
                    gaps["other_bytes"] += at - pos
                    said["slack_stretches_not_zero"] = said.get("slack_stretches_not_zero", 0) + 1
                    problem("%d byte(s) at offset %d lie inside the declared size of the entry at offset %d, after its parts, and are neither an entry nor "
                            "zero: they were not read as one" % (at - pos, pos, owner))
                pos = at
                continue
            if head[:4] != MAGIC:
                at, nonzero = next_magic(fd, pos, size)
                if at is None:
                    continue                                   # the clock ran out inside the search: said at the top of the loop
                if nonzero:
                    gaps["other"] += 1
                    gaps["other_bytes"] += at - pos
                    problem("%d byte(s) at offset %d are not an entry (no 'CMMM' there) and are not all zero: they were not read as one" % (at - pos, pos))
                else:
                    gaps["zero_bytes"] += at - pos
                pos = at
                continue
            row = {"file": path, "entry": said["entries"] + 1, "offset": pos, "in_free_space": pos >= free}
            if first_usable and pos < first:
                row["before_first_entry_offset"] = True
                said["entries_before_first_entry_offset"] = said.get("entries_before_first_entry_offset", 0) + 1
            if slacks:
                row["inside_entry_at"] = slacks[-1][0]
                said["entries_inside_another_entry"] = said.get("entries_inside_another_entry", 0) + 1
            said["entries"] += 1
            budget.entries_left -= 1
            PROGRESS["entries"] += 1
            if len(head) < entry_header:
                row.update(truncated=True, error="the file ends %d bytes into this entry's header of %d" % (len(head), entry_header))
                rows.add(row)
                reasons.append("the file ends inside the header of the entry at offset %d" % pos)
                said["entries_truncated"] = said.get("entries_truncated", 0) + 1
                break
            entry_size, entry_hash = struct.unpack_from("<IQ", head, 4)
            at = 16
            if layout == "vista":
                row["extension"] = shown_text(head[16:24])[0]
                at = 24
            if layout == "eight":
                name_bytes, padding, data_size, width, height, _unknown, data_sum, header_sum = struct.unpack_from("<IIIIIIQQ", head, at)
                row["declared_width"], row["declared_height"] = width, height
            else:
                name_bytes, padding, data_size, _unknown, data_sum, header_sum = struct.unpack_from("<IIIIQQ", head, at)
            row.update(entry_size=entry_size, entry_hash="%016x" % entry_hash, identifier_bytes=name_bytes, padding_bytes=padding, data_size=data_size,
                       data_checksum="%016x" % data_sum, header_checksum="%016x" % header_sum, checksums_verified=False)
            inside = entry_header + name_bytes + padding + data_size
            if entry_size < entry_header or inside > entry_size:
                # The entry's own lengths do not fit it: nothing in it is believed, and the next entry is looked for byte by byte.
                row["error"] = ("the entry declares %d bytes and its parts need %d (header %d, identifier %d, padding %d, data %d): its image was not read"
                                % (entry_size, inside, entry_header, name_bytes, padding, data_size))
                rows.add(row)
                problem("the entry at offset %d has lengths that do not fit it" % pos)
                said["entries_malformed"] = said.get("entries_malformed", 0) + 1
                pos += 4
                continue
            identifier, identifier_chars = shown_text(pread(fd, min(name_bytes, 2 * IDENTIFIER_SHOWN + 2), pos + entry_header))
            row["identifier"] = identifier
            if identifier_chars > IDENTIFIER_SHOWN or name_bytes > 2 * IDENTIFIER_SHOWN + 2:
                row["identifier_cut"] = True
            data_at = pos + entry_header + name_bytes + padding
            row["data_offset"] = data_at
            present = max(0, min(data_size, size - data_at))
            cut = pos + entry_size > size
            if cut:
                row["truncated"] = True
                row["data_bytes_present"] = present
                reasons.append("the file ends inside the entry at offset %d (%d of its %d bytes are there)" % (pos, size - pos, entry_size))
                said["entries_truncated"] = said.get("entries_truncated", 0) + 1
            if data_size:
                said["entries_with_image"] += 1
                start = pread(fd, 32, data_at) if present else b""
                kind = image_kind(start)
                row["image_type"] = kind
                row["image_width"], row["image_height"] = image_size(kind, start)
                if present < data_size:
                    row["not_written"] = "the file ends inside the image (%d of %d bytes): a cut image is not written" % (present, data_size)
                    row["sha256"] = None
                elif not extract:
                    row["sha256"], _n = digest_at(fd, data_at, data_size)
                    row["not_written"] = "extract is false"
                elif data_size > budget.image_bytes:
                    row["sha256"], _n = digest_at(fd, data_at, data_size)
                    row["not_written"] = "the image is %d bytes, over max_image_bytes (%d)" % (data_size, budget.image_bytes)
                    said["images_not_written_for_size"] = said.get("images_not_written_for_size", 0) + 1
                elif data_size > budget.output_left:
                    row["sha256"], _n = digest_at(fd, data_at, data_size)
                    row["not_written"] = "max_output_bytes was reached"
                    budget.output_full = True
                    said["images_not_written_for_output"] = said.get("images_not_written_for_output", 0) + 1
                else:
                    name = "%s-%06d-%016x.%s" % (prefix, row["entry"], entry_hash, EXTENSION[kind])
                    try:
                        row["written"], row["sha256"], wrote = write_image(fd, data_at, data_size, directory, shown_dir, name)
                    except OSError as exc:
                        drop_pages()
                        fail("an image could not be written to %s: %s. Outside a job the place is your own work/<your id>/ directory; in a job it is $OUT." % (shown_dir, describe(exc)),
                             images_written=PROGRESS["written"])
                    if row["written"] is None:
                        del row["written"]
                        row["not_written"] = "the read stopped %d bytes into this image (the tool's own clock ran out, or the file ended): a part of an image is not written" % wrote
                    else:
                        budget.output_left -= wrote
                        said["images_written"] += 1
                        said["image_bytes_written"] += wrote
                        PROGRESS["written"] += 1
                if row.get("sha256") is None and present >= data_size:
                    # Hashing or copying stopped at the clock: the entry is listed, and the read ends here with the reason.
                    row.setdefault("not_written", "the tool's own clock ran out while this image was read")
                    budget.stopped = "the tool's own clock (%d s) ran out" % DEADLINE_SECONDS
                    reasons.append("%s inside the image of the entry at offset %d: that image was not hashed or written, and the entries after it were not read" % (budget.stopped, pos))
                    rows.add(row)
                    break
            else:
                row["image_type"] = None
            if entry_size > inside:
                row["slack_bytes"] = entry_size - inside
            rows.add(row)
            if cut and pos + inside > size:
                break                                          # the file ends inside the entry's parts: there is nothing after them
            if entry_size > inside:
                slacks.append((pos, pos + entry_size))
            pos += inside
        said["bytes_not_in_an_entry"] = gaps
        skipped_by_header = said.get("entries_before_first_entry_offset", 0)
        if skipped_by_header:
            problem("the header's first entry offset (%d) lies past %d entr(ies) that begin before it: a reader that starts at that offset skips them; they were "
                    "read here as entries and are marked before_first_entry_offset" % (first, skipped_by_header))
        swallowed = said.get("entries_inside_another_entry", 0)
        if swallowed:
            problem("%d entr(ies) begin inside the declared size of another entry, after its parts: a reader that steps from entry to entry by the declared "
                    "size skips them; they were read here as entries and are marked inside_entry_at (the offset of the entry whose size covers them)" % swallowed)
        if gaps["other"]:
            reasons.append("%d stretch(es) of the file (%d bytes) are neither an entry nor zero" % (gaps["other"], gaps["other_bytes"]))
        if said.get("entries_malformed"):
            reasons.append("%d entr(ies) have lengths that do not fit them" % said["entries_malformed"])
        if said.get("images_not_written_for_size"):
            reasons.append("%d image(s) are over max_image_bytes and were hashed, not written" % said["images_not_written_for_size"])
        if said.get("images_not_written_for_output"):
            reasons.append("%d image(s) were hashed and not written because max_output_bytes was reached" % said["images_not_written_for_output"])
        if said["first_entry_offset_from"] == "search":
            reasons.append("the header's first entry offset was not usable, so the entries were found by search")
        if reasons:
            return ended("partial", "; ".join(reasons))
        return ended("complete", "every entry from the end of the header to %s was read (%d, %d with an image)%s%s%s" % (
            "the end of the file" if end == size else "the header's first free offset (include_free is false: what lies past it was not read)",
            said["entries"], said["entries_with_image"],
            "" if not extract else "; every image was written" if said["entries_with_image"] else "",
            "" if not skipped_by_header else "; %d of them begin before the header's first entry offset (%d), which skips them: they are marked "
                                             "before_first_entry_offset" % (skipped_by_header, first),
            "" if not swallowed else "; %d of them begin inside the declared size of another entry, which covers them: they are marked inside_entry_at"
                                     % swallowed))
    finally:
        os.close(fd)


def whole(value, name, default, low, high):
    if value is None:
        return default
    if isinstance(value, bool) or not isinstance(value, int) or not low <= value <= high:
        fail("%s must be a whole number from %d to %d" % (name, low, high))
    return value


def flag(value, name, default):
    if value is None:
        return default
    if not isinstance(value, bool):
        fail("%s must be true or false" % name)
    return value


def main():
    set_deadline(DEADLINE_SECONDS)
    install_signal_handlers(last_word)
    try:
        args = json.load(sys.stdin)
    except ValueError as exc:
        fail("arguments are not valid JSON", reason=str(exc))
    if not isinstance(args, dict):
        fail("arguments must be a JSON object")
    unknown = sorted(set(args) - {"path", "limit", "extract", "include_free", "max_entries", "max_image_bytes", "max_output_bytes"})
    if unknown:
        fail("unknown argument(s): %s" % ", ".join(re.sub(r"[^A-Za-z0-9_]", "?", str(k))[:40] for k in unknown[:10]))
    path = args.get("path")
    if not isinstance(path, str) or not path or "\x00" in path:
        fail("path is required: a thumbcache_*.db or iconcache_*.db file, or a directory holding them")
    limit = whole(args.get("limit"), "limit", DEFAULT_LIMIT, 1, MAX_LIMIT)
    extract = flag(args.get("extract"), "extract", True)
    include_free = flag(args.get("include_free"), "include_free", True)
    budget = Budget(whole(args.get("max_entries"), "max_entries", DEFAULT_MAX_ENTRIES, 1, MAX_MAX_ENTRIES),
                    whole(args.get("max_image_bytes"), "max_image_bytes", DEFAULT_IMAGE_BYTES, 1, MAX_OUTPUT_BYTES),
                    whole(args.get("max_output_bytes"), "max_output_bytes", DEFAULT_OUTPUT_BYTES, 0, MAX_OUTPUT_BYTES))

    targets, skipped, walk_stopped = [], [], None
    if os.path.islink(path):
        fail("the path is a symbolic link: it is not followed (name what it resolves to)", path=path)
    if os.path.isdir(path):
        def unreadable(exc):
            skipped.append({"file": getattr(exc, "filename", None) or path, "why": "the directory could not be listed: %s" % exc.strerror})
        for root, dirs, names in os.walk(path, onerror=unreadable):
            if out_of_time():
                walk_stopped = "the tool's own clock (%d s) ran out while the directory was walked" % DEADLINE_SECONDS
                break
            dirs.sort()
            for name in sorted(names):
                if CACHE_NAME.search(name):
                    targets.append(os.path.join(root, name))
        if not targets and not skipped and not walk_stopped:
            fail("no thumbcache_*.db or iconcache_*.db file under that directory", path=path)
        if len(targets) > MAX_FILES:
            skipped.extend({"file": t, "why": "more than %d cache files under the directory: this one was not read (name it in a call of its own)" % MAX_FILES} for t in targets[MAX_FILES:])
            targets = targets[:MAX_FILES]
    elif os.path.isfile(path):
        targets = [path]
    elif os.path.lexists(path):
        fail("not a regular file or a directory: it is not opened", path=path)
    else:
        fail("no such file or directory", path=path)

    import hashlib
    identity = hashlib.sha256(json.dumps([os.path.abspath(path), extract, include_free]).encode("utf-8", "surrogatepass")).hexdigest()[:12]
    directory, shown_dir = output_directory(identity)
    refused = refuse_output_place(directory, shown_dir, extract)
    if refused:
        fail(refused, path=path)
    rows = NoReplacePage("thumbcache_read", [os.path.abspath(path), extract, include_free, budget.entries_left, budget.image_bytes, budget.output_left], limit)
    files, indexes = [], []
    for number, target in enumerate(targets, 1):
        if budget.stopped or out_of_time():
            skipped.append({"file": target, "why": "%s before this file was started" % (budget.stopped or "the tool's own clock (%d s) ran out" % DEADLINE_SECONDS)})
            continue
        PROGRESS["files"] += 1
        said = read_cache(target, rows, budget, extract, include_free, directory, shown_dir, "c%03d" % number)
        if said.get("format") == "index (IMMM)" and os.path.isdir(path):
            # The index Explorer keeps beside its caches is in every real directory: it is named as what it is, and it is not a cache that
            # failed to read, so it does not make the answer for the directory partial. Named by itself, it is answered as failed (below).
            indexes.append({"file": target, "bytes": said.get("bytes"),
                            "why": "the cache's index (it begins 'IMMM'): not a cache this tool reads; it holds no image, and its layout (which ties an entry "
                                   "hash to a slot in each cache) is not read"})
            continue
        files.append(said)

    page = rows.finish()
    reasons = []
    not_complete = [f for f in files if f["status"] != "complete"]
    if walk_stopped:
        reasons.append(walk_stopped)
    if not_complete:
        reasons.append("%d of the %d cache file(s) read are partial or failed (files[].status_basis says why for each)" % (len(not_complete), len(files)))
    if skipped:
        reasons.append("%d file(s) or director(ies) were not read (not_read)" % len(skipped))
    if files and all(f["status"] == "failed" for f in files) and not page["matched"]:
        status, basis = "failed", "no cache file named was read: " + "; ".join("%s" % f.get("status_basis") for f in files[:3])
    elif not files and indexes and not skipped and not walk_stopped:
        status, basis = "failed", "the directory holds %d cache index file(s) ('IMMM') and no cache this tool reads: nothing was read" % len(indexes)
    else:
        status = "partial" if reasons else "complete"
        to_free = sum(1 for f in files if f.get("read_to_offset") != f.get("bytes"))
        skipped_by_header = sum(f.get("entries_before_first_entry_offset", 0) for f in files)
        swallowed = sum(f.get("entries_inside_another_entry", 0) for f in files)
        basis = "; ".join(reasons) if reasons else "every cache file found (%d) was read from the end of its header to %s; %d entr(ies), %d with an image%s%s%s%s" % (
            len(files),
            "its end" if not to_free else "the header's first free offset in %d of them and to its end in the others (include_free is false: what lies past that "
                                          "offset was not read, and complete says nothing of it)" % to_free,
            sum(f["entries"] for f in files), sum(f["entries_with_image"] for f in files),
            ", every image written" if extract else ", none written (extract is false)",
            "" if not skipped_by_header else "; %d entr(ies) begin before their header's first entry offset, which skips them (marked before_first_entry_offset)" % skipped_by_header,
            "" if not swallowed else "; %d entr(ies) begin inside the declared size of another entry, which covers them (marked inside_entry_at)" % swallowed,
            "" if not indexes else "; %d cache index file(s) beside them are named in not_caches and are not caches this tool reads" % len(indexes))
    answer = {
        "parser": PARSER,
        "status": status,
        "status_basis": basis,
        "files": files[:MAX_PROBLEMS],
        "file_count": len(files),
        "files_not_listed": max(0, len(files) - MAX_PROBLEMS),
        "not_read": skipped[:MAX_PROBLEMS],
        "not_read_count": len(skipped),
        "not_caches": indexes[:MAX_PROBLEMS],
        "not_caches_count": len(indexes),
        "entries": rows.page,
        "entry_count": page["matched"],
        "images_written": sum(f["images_written"] for f in files),
        "image_bytes_written": sum(f["image_bytes_written"] for f in files),
        "images_directory": shown_dir if any(f["images_written"] for f in files) else None,
        "stopped_by_time_limit": bool(budget.stopped and "clock" in budget.stopped) or bool(walk_stopped) or any("clock" in s["why"] for s in skipped),
        "limits": {"max_entries": whole(args.get("max_entries"), "max_entries", DEFAULT_MAX_ENTRIES, 1, MAX_MAX_ENTRIES), "max_image_bytes": budget.image_bytes,
                   "max_output_bytes": whole(args.get("max_output_bytes"), "max_output_bytes", DEFAULT_OUTPUT_BYTES, 0, MAX_OUTPUT_BYTES)},
        "note": "An entry is a rendering Explorer stored: a thumbnail or an icon, under a hash of the item it was made for. The cache does not hold the item's path "
                "(Windows Search's index and the cache's own index tie a hash to a file, and neither is read here), and it gives no time. in_free_space marks an entry "
                "past the offset the header gives for its first free byte: bytes of an earlier state of the cache, a candidate. before_first_entry_offset marks an "
                "entry that begins before the offset the header gives for its first entry: the header skips it, and it was read all the same. inside_entry_at marks an "
                "entry that begins inside the declared size of another entry (the one at that offset), after its parts: a reader that steps by the declared "
                "size skips it, and it was read all the same; slack_bytes is how much an entry's declared size exceeds its parts. An image's file is "
                "named by this tool (files[].output_prefix, the entry's number, its hash), never by the cache file's name. The two checksums are copied, not verified.",
        **page,
    }
    if status == "failed":
        answer["error"] = "no thumbnail cache was read"
    print_answer(answer, indent=2)
    if status == "failed":
        raise SystemExit(1)


if __name__ == "__main__":
    exit_code = 0
    try:
        try:
            main()
        except SystemExit:
            raise
        except Exception as exc:                                  # whatever hostile input does, the answer is JSON
            hold_stop_signals(quietly=True)
            drop_pages()
            print_answer({"error": "the read failed", "status": "failed", "status_basis": "the tool stopped with an unexpected error",
                          "reason": "%s" % type(exc).__name__})
            sys.exit(1)
    except SystemExit as stop:
        exit_code = _code(stop)
    _leave(exit_code)
