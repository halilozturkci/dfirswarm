#!/usr/bin/env python3
"""Recover the names a directory used to hold.

When a file is deleted its entry is removed from the parent directory's index,
but NTFS does not clear what it removed: the index node's live entries shrink
and the bytes past the end stay where they were. That slack holds whole
$FILE_NAME structures — the name, the parent, the four times, the sizes — for
files whose $MFT record may long since have been reused. It is the artefact
that proves what was in a folder before somebody emptied it.

INDX block layout, little-endian:

  0x00  "INDX", update sequence array offset at 0x04 and count at 0x06,
        $LogFile sequence number at 0x08, the node's VCN at 0x10.
  0x18  the node header: offset to the first entry (relative to 0x18),
        total size of the live entries, allocated size, flags.
  entry MFT reference (8), entry length (2), key length (2), flags (2),
        then the $FILE_NAME attribute itself at offset 0x10 of the entry.

Live entries run from the first-entry offset to total-size. From total-size to
allocated-size is the slack, and that is where this tool does its real work: it
walks the region looking for a structure whose parent reference, name length
and namespace are all sane and whose name decodes, and reports each hit with
the byte offset it came from.

The update sequence fixup is applied first. Without it the last two bytes of
every sector are a checksum, and a name that straddles a sector boundary comes
back with two bytes of rubbish in the middle of it.

Every block is read. The page returned inline is `limit` long, and when more
entries match the whole list is written to a file the output names; the same
holds for the problems.

Integrity travels with every entry. A block is `fixup_ok` when every 512-byte unit
carries its update sequence number and the array covers the whole block, and `node_ok`
when the node header and each live entry's length, alignment and key length fit inside
the live region. An entry carries its `block_offset` and `salvaged` (true when either
check failed). A salvaged block's entries are left out of the answer unless
`include_unreliable` is true, and the answer counts the blocks and entries it left out.
A name that parses is structurally plausible (a sane parent, a decodable name, a known
namespace, a valid time), not verified.
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
import json
import mmap
import os
import re
import struct
import sys

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


FILETIME_EPOCH = datetime.datetime(1601, 1, 1, tzinfo=datetime.timezone.utc)
MAGIC = b"INDX"
NAMESPACE = {0: "POSIX", 1: "Win32", 2: "DOS", 3: "Win32 and DOS"}
FN_FIXED = 0x42          # the $FILE_NAME header, before the name itself


PARSER = "indx_carve/5"
DEADLINE_SECONDS = 285            # the manifest allows 300: the sweep stops here, so that the pages are placed and the answer printed before the harness ends it
MAX_BLOCK = 65536                 # the largest block_size (NTFS index blocks are 4096, rarely 512 to 65536)
MAX_LIMIT = 10000                 # the largest inline page; the whole result is in the file the answer names
MAX_NAME = 500                    # the longest name filter
PATTERN_SECONDS = 0.5             # one name is tested against the caller's expression for at most this long
PROGRESS = {"blocks": 0, "offset": 0}


class PatternTooSlow(Exception):
    pass


def _pattern_alarm(_signum, _frame):
    raise PatternTooSlow()


def matches(pattern, text):
    """Whether the caller's expression matches `text`, for at most PATTERN_SECONDS (the re module looks at signals while it matches, so an
    expression that takes exponential time on a name is stopped instead of outrunning the tool's clock)."""
    signal.signal(signal.SIGALRM, _pattern_alarm)
    signal.setitimer(signal.ITIMER_REAL, PATTERN_SECONDS)
    try:
        return pattern.search(text) is not None
    finally:
        signal.setitimer(signal.ITIMER_REAL, 0)


def drop_pages():
    """Remove the temporary files of the pages that were being written (the STOP block does the same on a signal)."""
    for page in list(PAGES):
        tmp = getattr(page, "_tmp", None)
        if tmp is not None:
            try:
                os.unlink(tmp)
            except OSError:
                pass
            page._tmp = None


def fail(message, **extra):
    drop_pages()
    print_answer({"error": message, "status": "failed", "status_basis": "the tool stopped with an error and read no result (see error)", **extra})
    raise SystemExit(1)


def last_word(signum):
    interrupted_answer(signum, blocks_read=PROGRESS["blocks"], offset_reached=PROGRESS["offset"])


def filetime(value):
    """ISO 8601 UTC with seven fractional digits, by integer arithmetic; None for 0 or a date past 9999."""
    if not value:
        return None
    try:
        whole, ticks = divmod(value, 10_000_000)
        return (FILETIME_EPOCH + datetime.timedelta(seconds=whole)).strftime("%Y-%m-%dT%H:%M:%S") + ".%07dZ" % ticks
    except (OverflowError, ValueError, OSError):
        return None


def apply_fixup(block):
    """Undo the update sequence fixup of a 512-byte-unit record: the last two bytes of each unit hold the
    sequence number, and the real bytes are in the array. Returns the fixed block and a problem or None.
    The array must cover the whole block."""
    usa_offset, usa_count = struct.unpack_from("<HH", block, 0x04)
    if usa_count == 0 or usa_offset + usa_count * 2 > len(block):
        return block, "the update sequence array is outside the block"
    units = len(block) // 512
    if usa_count - 1 != units:
        return block, "the update sequence array holds %d fixup value(s) and the block has %d 512-byte unit(s)" % (usa_count - 1, units)
    signature = block[usa_offset:usa_offset + 2]
    out = bytearray(block)
    for i in range(1, usa_count):
        end = i * 512 - 2
        if end + 2 > len(out):
            return bytes(out), "the block is shorter than its sector count claims"
        if bytes(out[end:end + 2]) != signature:
            return bytes(out), "sector %d does not carry the update sequence number" % i
        out[end:end + 2] = block[usa_offset + i * 2:usa_offset + i * 2 + 2]
    return bytes(out), None


def read_filename(buf, at, key_end=None, strict=True):
    """The $FILE_NAME attribute content at `at`, as (found, why). `found` is None when it is not plausibly one, and
    `why` says what failed. `key_end` bounds the name to the index entry's own key; `strict` adds the plausibility rules
    a search of slack needs (a parent that is a real entry, a believable time) and a live entry, which the node walk
    has already placed, does not: its odd values are kept and flagged `unreliable` with the reasons."""
    limit = len(buf) if key_end is None else min(key_end, len(buf))
    if at + FN_FIXED > limit:
        return None, "the key holds %d bytes, fewer than the %d a $FILE_NAME header needs" % (max(limit - at, 0), FN_FIXED)
    parent, = struct.unpack_from("<Q", buf, at)
    parent_entry = parent & 0xFFFFFFFFFFFF
    created, modified, mft_modified, accessed = struct.unpack_from("<QQQQ", buf, at + 8)
    alloc, real = struct.unpack_from("<QQ", buf, at + 0x28)
    flags, = struct.unpack_from("<I", buf, at + 0x38)
    name_chars = buf[at + 0x40]
    namespace = buf[at + 0x41]
    if not 1 <= name_chars <= 255:
        return None, "the name length is %d characters" % name_chars
    if namespace not in NAMESPACE:
        return None, "the namespace byte is %d" % namespace
    end = at + FN_FIXED + name_chars * 2
    if end > limit:
        return None, "the name is %d characters (%d bytes from the start of the key) and the key holds %d" % (
            name_chars, FN_FIXED + name_chars * 2, max(limit - at, 0))
    raw = buf[at + FN_FIXED:end]
    try:
        name = raw.decode("utf-16-le")
    except UnicodeDecodeError:
        return None, "the name is not valid UTF-16"
    if not name or any(ord(c) < 0x20 for c in name):
        return None, "the name holds a control character"
    reasons = []
    if parent_entry == 0 or parent_entry > 0xFFFFFFFF:
        reasons.append("the parent reference (entry %d) is not a believable directory" % parent_entry)
    if not any(filetime(v) for v in (created, modified)):
        reasons.append("the created and modified times are both 0, all ones or past the year 9999")
    if strict and reasons:
        return None, "; ".join(reasons)
    found = {
        "name": name,
        "namespace": NAMESPACE[namespace],
        "parent_entry": parent_entry,
        "parent_sequence": parent >> 48,
        "created": filetime(created),
        "modified": filetime(modified),
        "mft_modified": filetime(mft_modified),
        "accessed": filetime(accessed),
        "created_filetime": str(created),
        "modified_filetime": str(modified),
        "mft_modified_filetime": str(mft_modified),
        "accessed_filetime": str(accessed),
        "allocated_size": alloc,
        "real_size": real,
        "is_directory": bool(flags & 0x10000000),
        "length": FN_FIXED + name_chars * 2,
    }
    if reasons:
        found["unreliable"] = True
        found["unreliable_reasons"] = reasons
    return found, None


def node_problems(block):
    """The node header's own consistency: the first entry, the live total and the allocated size must
    be ordered, 8-byte aligned and inside the block. Returns a problem or None."""
    if len(block) < 0x28:
        return "the block is shorter than a node header"
    first, total, allocated = struct.unpack_from("<III", block, 0x18)
    if first < 0x10 or first % 8 or total < first or allocated < total or 0x18 + allocated > len(block) or total % 8:
        return ("the node header is inconsistent (first entry %d, live size %d, allocated size %d, block %d bytes)"
                % (first, total, allocated, len(block)))
    return None


def live_entries(block, base_offset):
    """Walk the node's live entries, the ones the directory still lists. Every length is checked against
    the live region and the key length against the entry: the first entry that does not fit is a problem,
    named, and the walk of this node's live entries ends there."""
    out, problems, unreadable = [], [], []
    if len(block) < 0x28:
        return out, 0, 0, problems, unreadable
    first, total, allocated = struct.unpack_from("<III", block, 0x18)
    start = 0x18 + first
    end = min(0x18 + total, len(block))
    at = start
    while at + 0x10 <= end:
        reference, length, key_length = struct.unpack_from("<QHH", block, at)
        entry_flags, = struct.unpack_from("<H", block, at + 0x0C)
        if length < 0x10 or length % 8 or at + length > end or key_length > length - 0x10:
            problems.append("the live entry at block offset %d has a length (%d) or key length (%d) that does not fit the live region"
                            % (at, length, key_length))
            break
        if entry_flags & 0x02:                     # the end-of-node marker
            break
        if key_length:
            found, why = read_filename(block, at + 0x10, key_end=at + 0x10 + key_length, strict=False)
        else:
            found, why = None, "the entry has no key"
        if found:
            found.update({"source": "live", "mft_entry": reference & 0xFFFFFFFFFFFF,
                          "mft_sequence": reference >> 48, "offset": base_offset + at})
            out.append(found)
        else:
            unreadable.append({"offset": base_offset + at, "mft_entry": reference & 0xFFFFFFFFFFFF,
                               "mft_sequence": reference >> 48, "why": why})
        at += length
    return out, 0x18 + total, 0x18 + allocated, problems, unreadable


def carve_slack(block, slack_start, slack_end, base_offset):
    """Past the live entries, look for a $FILE_NAME that still parses.

    Entries sit on 8-byte boundaries, so after a hit the walk goes on from the
    next boundary. Stepping by the name's own length left the walk misaligned
    for every name whose length is not a multiple of 8, and every entry after
    it in the slack was then missed.
    """
    out = []
    at = max(0x18, slack_start)
    at += (-at) % 8
    limit = min(slack_end, len(block))
    while at + FN_FIXED <= limit:
        found, _ = read_filename(block, at)
        if found:
            found.update({"source": "slack", "offset": base_offset + at})
            out.append(found)
            at += found["length"]
            at += (-at) % 8
            continue
        at += 8                                    # entries are 8-byte aligned
    return out


def run(args):
    path = args.get("path")
    if not isinstance(path, str) or not path:
        fail("path is required: an extracted $I30 stream or a blob to sweep")
    block_size = args.get("block_size", 4096)
    if isinstance(block_size, bool) or not isinstance(block_size, int) or block_size % 512 or not 512 <= block_size <= MAX_BLOCK:
        fail("block_size must be a multiple of 512 from 512 to %d" % MAX_BLOCK)
    limit = args.get("limit", 500)
    if isinstance(limit, bool) or not isinstance(limit, int) or not 1 <= limit <= MAX_LIMIT:
        fail("limit must be a whole number from 1 to %d (the inline page; the whole result is in the file the answer names)" % MAX_LIMIT)
    name = args.get("name")
    if name is not None and (not isinstance(name, str) or len(name) > MAX_NAME):
        fail("name must be a string of at most %d characters: a case-insensitive regular expression over the names" % MAX_NAME)
    include_unreliable = args.get("include_unreliable", False)
    if not isinstance(include_unreliable, bool):
        fail("include_unreliable must be true or false")
    slack_only = args.get("slack_only", False)
    if not isinstance(slack_only, bool):
        fail("slack_only must be true or false")
    pattern = None
    if name:
        try:
            pattern = re.compile(name, re.I)
        except re.error as exc:
            fail("name is not a valid regex", reason=str(exc))
    if not os.path.isfile(path):
        if os.path.exists(path):
            fail("not a regular file: it is not opened", path=path, not_attempted=1)
        fail("no such file", path=path)

    key = [path, block_size, slack_only, name, include_unreliable]
    entries = NoReplacePage("indx_carve", key, limit)
    problems = NoReplacePage("indx_carve-problems", key, 40)
    blocks, from_slack = 0, 0
    blocks_fixup_failed = blocks_salvaged = excluded = 0
    live_unreadable_count = live_flagged = 0
    stopped = None

    try:
        fh = open(path, "rb")
        size = os.fstat(fh.fileno()).st_size
        # Mapped rather than read: a raw blob to sweep can be larger than memory.
        data = mmap.mmap(fh.fileno(), 0, access=mmap.ACCESS_READ) if size else b""
    except (OSError, ValueError) as exc:
        fail("could not read the file", path=path, reason=str(exc))
    with fh:
        try:
            at = 0
            while stopped is None:
                if out_of_time():
                    stopped = "the tool's own clock (%d s) ran out" % DEADLINE_SECONDS
                    break
                PROGRESS["blocks"], PROGRESS["offset"] = blocks, at
                at = data.find(MAGIC, at)
                if at < 0:
                    at = size
                    break
                block = data[at:at + block_size]
                start_of_block = at
                at += 4
                if len(block) < 0x28:
                    problems.add({"offset": start_of_block, "why": "the block runs past the end of the file"})
                    continue
                fixed, problem = apply_fixup(block)
                if problem:
                    problems.add({"offset": start_of_block, "why": problem})
                    blocks_fixup_failed += 1
                blocks += 1
                node_problem = node_problems(fixed) if not problem else None
                if node_problem:
                    problems.add({"offset": start_of_block, "why": node_problem})
                live, slack_start, slack_end, live_problems, live_unreadable = live_entries(fixed, start_of_block)
                for why in live_problems:
                    problems.add({"offset": start_of_block, "why": why})
                for lost in live_unreadable:
                    live_unreadable_count += 1
                    problems.add({"offset": lost["offset"], "block_offset": start_of_block,
                                  "why": "a live entry (MFT entry %d, sequence %d) was not read as a name: %s"
                                         % (lost["mft_entry"], lost["mft_sequence"], lost["why"])})
                live_flagged += sum(1 for e in live if e.get("unreliable"))
                salvaged = bool(problem or node_problem or live_problems)
                if salvaged:
                    blocks_salvaged += 1
                found = live + carve_slack(fixed, slack_start, slack_end, start_of_block)
                for entry in found:
                    if slack_only and entry["source"] != "slack":
                        continue
                    if pattern:
                        try:
                            if not matches(pattern, entry["name"]):
                                continue
                        except PatternTooSlow:
                            stopped = ("the name expression took more than %s s on a name in the block at byte %d, so the sweep stopped there; use a simpler expression"
                                       % (PATTERN_SECONDS, start_of_block))
                            break
                    entry.update({"block_offset": start_of_block, "fixup_ok": problem is None,
                                  "node_ok": not (node_problem or live_problems), "salvaged": salvaged})
                    if salvaged and not include_unreliable:
                        excluded += 1
                        continue
                    entries.add(entry)
                    if entry["source"] == "slack":
                        from_slack += 1
                if stopped is not None:
                    break
                if not problem:
                    # A block whose fixup holds is a block: the next one starts
                    # after it, not at the next magic. One whose fixup fails may
                    # be a false positive, so the search goes on inside it.
                    at = start_of_block + block_size
        finally:
            if size:
                data.close()

    if not blocks and not stopped:
        problems.add({"offset": 0, "why": "no INDX block was found in the %d bytes of the file: nothing was read as a directory index (is this an $I30 stream, or a blob that holds one?)" % size})
    page = entries.finish()
    problem_page = problems.finish()
    reasons = []
    if stopped:
        reasons.append("%s at byte %d of %d, after %d blocks: the rest of the file was not searched" % (stopped, PROGRESS["offset"], size, blocks))
    if problem_page["matched"]:
        reasons.append("%d problem(s) are named under problems" % problem_page["matched"])
    out = {
        "parser": PARSER,
        "status": "partial" if reasons else "complete",
        "status_basis": "; ".join(reasons) if reasons else "every INDX signature of the %d-byte file was read as a block (%d blocks) and no problem is named" % (size, blocks),
        "path": path,
        "block_size": block_size,
        "blocks": blocks,
        "blocks_fixup_failed": blocks_fixup_failed,
        "blocks_salvaged": blocks_salvaged,
        "include_unreliable": include_unreliable,
        "entries_excluded_unreliable": excluded,
        "live_entries_unreadable": live_unreadable_count,
        "live_entries_flagged_unreliable": live_flagged,
        "stopped_by_time_limit": bool(stopped),
        "entries": entries.page,
        "entry_count": page["matched"],
        "from_slack": from_slack,
        "from_live": page["matched"] - from_slack,
        **page,
        "problems": problems.page,
        "problem_count": problem_page["matched"],
        "note": "A slack entry is stale index material: a $FILE_NAME as the directory's index held it when the entry "
                "was removed or the node rewritten. Its times are that structure's historical metadata, not the file's "
                "current times and not evidence that they were left unaltered, and a name that parses is structurally "
                "plausible, not verified. It does not say the file was deleted: a rename or a move out of the directory "
                "leaves the same trace; the USN journal and the $MFT record, where one survives, can corroborate. "
                + ("%d block(s) failed an integrity check (see problems): their entries are %s. " % (
                    blocks_salvaged, "included and marked salvaged" if include_unreliable else
                    "left out (%d), unless include_unreliable is true" % excluded) if blocks_salvaged else "")
                + ("%d live entry(ies) were walked but could not be read as a name (see problems: each says why, with its MFT "
                   "reference), and none is dropped silently. " % live_unreadable_count if live_unreadable_count else "")
                + ("%d live entry(ies) carry values that are odd (a parent that is not a believable directory, no believable time): "
                   "they are returned, flagged unreliable with the reasons. " % live_flagged if live_flagged else "")
                + "See filesystem/journals.",
    }
    if problem_page.get("all_results"):
        out["all_problems"] = problem_page["all_results"]
    print_answer(out, indent=2)


def main():
    set_deadline(DEADLINE_SECONDS)
    install_signal_handlers(last_word)
    try:
        args = json.load(sys.stdin)
    except ValueError as exc:
        fail("arguments are not valid JSON", reason=str(exc))
    if not isinstance(args, dict):
        fail("arguments must be a JSON object")
    try:
        run(args)
    except OSError as exc:
        fail("the file could not be read", reason=str(exc))


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
                          "reason": "%s: %s" % (type(exc).__name__, exc)})
            sys.exit(1)
    except SystemExit as stop:
        exit_code = _code(stop)
    _leave(exit_code)
