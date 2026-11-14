#!/usr/bin/env python3
r"""UserAssist, BAM, DAM and ShimCache (AppCompatCache) records of a registry hive, decoded, each with its raw bytes beside what was decoded.

What this is: a reader that turns three execution-related registry sources into records. Presence of a record is not execution, and the sources differ in what
they note:

  UserAssist   NTUSER.DAT   Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist\{GUID}\Count; the value names are ROT13-encoded (the raw
                            name and the decoded one are both in the record; only ASCII letters are rotated); the data is 72 bytes (session, run count,
                            focus count, focus time in ms, last-run FILETIME at 60) or 16 bytes (session, run count, last-run FILETIME at 8).
  BAM and DAM  SYSTEM       ControlSet00n\Services\bam (and dam)\State\UserSettings\<SID> (or ...\UserSettings\<SID>); the value name is an NT device
                            path, the data is 24 bytes whose first 8 are a FILETIME. The SID is the name of the key.
  ShimCache    SYSTEM       ControlSet00n\Control\Session Manager\AppCompatCache (value AppCompatCache), in the Windows 7 (32 and 64-bit), 8.0, 8.1
                            and 10 and later layouts. Its time is the file's last-modified time, not an execution time.

Every record names its layout and the basis for choosing it. The offsets are those the published notes give; none has been checked against a real hive by
the tool's author, and a value or an entry that does not fit a layout is returned as `unsupported` with its bytes, never guessed. A UserAssist hive does not
name its owner, so the record carries no SID unless the caller gave owner_sid. The regipy plugins for these sources are not used: the decoding here is this
tool's own, from the published layouts. No second reader cross-checks the records, and the answer says so.

The hive is read as it is on disk: a hive whose sequence numbers differ is reported dirty, and its transaction logs are not replayed. The filters
`contains` (in the path or the name) and `sid` look only in the text the answer prints, never in what the boundary withholds.
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


import datetime
import json
import os
import re
import stat
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


# BEGIN SHARED HIVE BOUNDS
# The same text is in regkv, shellbags, amcache_apps, userassist_bam_shimcache, persistence_normalise and registry_recover, and in the
# tool-library twins of regkv and amcache_apps (tests/shared-blocks-census.test.ts holds the copies equal).
# A hive of N bytes holds at most N // 76 key cells (an nk cell is at least 76 bytes) and N // 20 value cells (a vk cell is at least 20), however
# many elements an index claims: regipy follows a subkey index (ri) element by element, so one list repeated by an index is read as many times as
# it is repeated (a 61 KB hive listed a million keys and took 1.2 GB). Every list of subkeys and values is read through these bounds, and what is
# past one is said, never followed. The bounds are also of memory: a list keeps only the distinct keys it names, counted by what each takes (its
# record and its name, as stored and as decoded: a name can be 65,535 bytes), and the names of the keys a walk keeps add up to at most twice the
# hive's bytes (key cells that overlap, an element pointing into another key's name, are each read as a key of their own); a value's data is read
# up to VALUE_DATA_BYTES, data that is not wholly inside the file or inside the cell that holds it is said and not read, every value's bytes are
# found the same way whatever its type and then taken by its type as the table at VALUE_TYPES says, and a key's values are handed out one at a
# time, at most LIST_DATA_BYTES of their names and data. A hive is opened through open_hive, which checks the base block and the root cell before
# regipy reads the file.
import datetime
import hashlib
import itertools
import logging
import re
import struct
import sys
import time
import warnings

KEY_CELL_BYTES = 76
VALUE_CELL_BYTES = 20
REPEAT_RUN = 4096                         # elements in a row naming keys a list already named: the list repeats, and is read no further
HELD_KEY_BYTES = 1400                     # what one of regipy's key records holds in memory besides its name (measured: 1.47 KB, a 64 KiB name counted apart)
HELD_KEYS_BYTES = 256 << 20               # the memory the distinct keys of one list may hold: each its record, and its name as stored and as decoded
HELD_NAMES_PER_BYTE = 2                   # the names of the keys a walk keeps add up to at most this many times the hive's bytes (each name is inside its own cell)
IDENTITY_NAME = 64                        # a longer name is known among a list's identities by its length and a digest, not by a copy of it
VALUE_DATA_BYTES = 16 << 20               # the data of one value read at most: a value that declares more is said with its length, its data not read
LIST_DATA_BYTES = 64 << 20                # the data of one key's values handed out at most (a caller may hold them all)
LATE_ELEMENTS = 16384                     # the elements read of a subkey list begun after the deadline
LATE_VALUES = 4096                        # the values read of a value list begun after the deadline
ROOT_SCAN_BYTES = 0x10000                 # how far into the first bin regipy may look for its root key (it reads 4 bytes at a time, with no clock)
# regipy decodes a name the hive stores one byte a character (Windows stores a name so whenever every character of it is below U+0100: "M\u00fcller",
# "Caf\u00e9") as ASCII, with errors replaced, and a broken UTF-16 name the same way: each character it could not decode is U+FFFD, and the name it
# gives is not the hive's. Such a name is counted here and said, so an answer that shows one is not complete.
LOST_CHARACTER = "\ufffd"


def _lost_names(items):
    return sum(1 for item in items if LOST_CHARACTER in str(getattr(item, "name", "") or ""))


def _lost_names_problem(where, what, count):
    return {"where": where, "what": what,
            "error": "%d %s name(s) here hold U+FFFD where regipy could not decode a character (a name stored one byte a character, as Windows stores "
                     "one whose every character is below U+0100, is decoded as ASCII): each such name is shown as regipy gives it, which is not the "
                     "hive's, and a filter or a path made from it may not match the hive" % (count, "key" if what == "subkeys" else "value")}


class LibraryLog(logging.Handler):
    """regipy reports what it cannot parse through the logging module, and its text carries bytes of the value or the name it failed on
    (for a text value that is neither UTF-16 nor UTF-8: the byte and its position). The text is not printed anywhere: it is counted."""
    messages = 0
    errors = 0

    def emit(self, record):
        LibraryLog.messages += 1
        if record.levelno >= logging.ERROR:
            LibraryLog.errors += 1


def withhold_library_output():
    logging.root.handlers[:] = [LibraryLog()]
    warnings.simplefilter("ignore")


INLINE_DATA = 0x80000000                  # a value record whose data size has this bit set holds its data (four bytes at most) in the offset field
HBIN_START = 0x1000                       # a cell offset counts from the end of the hive's 4096-byte base block
SEGMENT_DATA = 0x3FD8                     # the data one big-data segment holds: a value with more is kept in segments that a "db" record lists

# The bytes of a value are found first, the same way for every type: held in its record (a size with the top bit set: four bytes at most), in
# the data cell its record names (the size it declares must fit inside that cell, whose size is in the cell's header, and inside the file), or,
# when it declares more than one segment holds and that cell starts "db", put together from the segments a big data record lists (each
# segment inside a cell that holds it, the record and its list too). Windows keeps every value of more than 16,344 bytes so, whatever its type.
# Only then is the value taken by its type, here and nowhere else:
#
#   type (number)                         bytes it requires                given as                                  otherwise
#   REG_NONE (0), REG_BINARY (3)          any                              the bytes (hex where printed)             -
#   REG_SZ (1), REG_EXPAND_SZ (2),        valid UTF-16LE (a last odd       text; the NULs that end it are not in     the bytes, and a problem line naming the
#     REG_LINK (6)                        NUL byte is padding)             it, a NUL inside it is                    first byte that does not decode
#   REG_DWORD (4)                         exactly 4                        a number, little-endian                   not given: a problem line
#   REG_DWORD_BIG_ENDIAN (5)              exactly 4                        a number, big-endian                      not given: a problem line
#   REG_QWORD (11)                        exactly 8                        a number, little-endian                   not given: a problem line
#   REG_FILETIME (16)                     exactly 8, a time up to the end  ISO 8601 UTC with seven fractional        wrong size: not given; a time past 9999:
#                                         of the year 9999                 digits, exact (the number in .filetime)   the bytes, and a problem line
#   REG_MULTI_SZ (7)                      UTF-16LE strings between NULs    the strings, empty ones left out          bytes no NUL ends, or a string that is not
#                                                                                                                    UTF-16 and all after it: not given, counted
#                                                                                                                    in a problem line; strings after the empty
#                                                                                                                    one that ends the list: given, and said
#   REG_RESOURCE_LIST (8), REG_FULL_RESOURCE_DESCRIPTOR (9), REG_RESOURCE_REQUIREMENTS_LIST (10): the bytes, whole
#   every other type (one Windows does not define, a device property 0xFFFF0000 + n, 0x00200000): the bytes, whole, the type named by its
#   number in decimal (regipy's own name for it maps a device property onto a registry type it is not)
#
# "The bytes" is a bytes object, which each tool prints as hex through its boundary; nothing is decoded through regipy's try_decode_binary,
# which falls back to UTF-8 and strips NULs from binary data, and nothing is cut to a length (a value is given whole or not at all).
VALUE_TYPES = {0: "REG_NONE", 1: "REG_SZ", 2: "REG_EXPAND_SZ", 3: "REG_BINARY", 4: "REG_DWORD", 5: "REG_DWORD_BIG_ENDIAN", 6: "REG_LINK",
               7: "REG_MULTI_SZ", 8: "REG_RESOURCE_LIST", 9: "REG_FULL_RESOURCE_DESCRIPTOR", 10: "REG_RESOURCE_REQUIREMENTS_LIST", 11: "REG_QWORD",
               16: "REG_FILETIME"}
FIXED_VALUE_BYTES = {"REG_DWORD": 4, "REG_DWORD_BIG_ENDIAN": 4, "REG_QWORD": 8, "REG_FILETIME": 8}   # one that declares another size is not its type's value
TEXT_TYPES = ("REG_SZ", "REG_EXPAND_SZ", "REG_LINK")
FILETIME_LAST = 265046774400 * 10 ** 7 - 1        # 9999-12-31T23:59:59.9999999Z: a later FILETIME has no ISO 8601 form (regipy gave 1601-01-01)


def filetime_text(n):
    """A FILETIME as ISO 8601 UTC with seven fractional digits, by integer arithmetic (exact), or None past FILETIME_LAST."""
    if not 0 <= n <= FILETIME_LAST:
        return None
    seconds, ticks = divmod(n, 10 ** 7)
    when = datetime.datetime(1601, 1, 1) + datetime.timedelta(seconds=seconds)
    return "%04d-%02d-%02dT%02d:%02d:%02d.%07dZ" % (when.year, when.month, when.day, when.hour, when.minute, when.second, ticks)


def typed_value(data_type, data):
    """(the value, its FILETIME number or None, a problem sentence or None) for `data`, the whole bytes of a value of `data_type` (a name of
    VALUE_TYPES or a number in decimal), by the table above. The sizes of the fixed-size types are checked by the caller before this."""
    if data_type in TEXT_TYPES:
        body = data[:-1] if len(data) % 2 and data[-1:] == b"\x00" else data
        try:
            return body.decode("utf-16-le").rstrip("\x00"), None, None
        except UnicodeDecodeError as exc:
            return data, None, ("is not valid UTF-16 text from byte %d of its %d: its bytes are given, not text" % (exc.start, len(data)))
    if data_type == "REG_DWORD":
        return struct.unpack("<I", data)[0], None, None
    if data_type == "REG_DWORD_BIG_ENDIAN":
        return struct.unpack(">I", data)[0], None, None
    if data_type == "REG_QWORD":
        return struct.unpack("<Q", data)[0], None, None
    if data_type == "REG_FILETIME":
        n = struct.unpack("<Q", data)[0]
        text = filetime_text(n)
        if text is None:
            return data, None, "holds a FILETIME past the end of the year 9999, which has no date: its 8 bytes are given, not a time"
        return text, n, None
    if data_type == "REG_MULTI_SZ":
        strings, dropped, undecodable, after = multi_strings(data)
        said = []
        if dropped:
            said.append(("holds a string that is not valid UTF-16: it and the rest of the data, %d byte(s), are not in the answer (regipy drops them "
                         "too), the strings before it are" if undecodable else
                         "ends in %d byte(s) that no NUL ends: they are not in the answer (regipy drops them too), the strings before them are") % dropped)
        if after:
            said.append("holds %d string(s) after the empty string that ends its list: they are given, after the others, as the hive holds them" % after)
        return strings, None, "; and ".join(said) or None
    return data, None, None


def bound_value_reads():
    """regipy reads the data of every value with stream.read(data_size) at the record's data offset, before it looks at the type. For a value
    whose data is inside the record (the size has its top bit set) that is a read of up to 2 GiB at a place the four data bytes name: the rest
    of the hive file. regipy then drops what it read for the types it knows to be inline (REG_SZ, REG_BINARY, REG_DWORD, REG_QWORD,
    REG_MULTI_SZ) and RETURNS it for every other type: a device property (a type above 0xFFFF0000, which Windows writes under
    the Properties keys of Control/Class and Enum by the thousand), REG_LINK, REG_FILETIME or a type it does not know came back as
    megabytes of the hive, and the data budget below then stopped the walk (a 12 MB SYSTEM hive: 184 of 70,010 values read). The reader is
    replaced once: a record with inline data gives its own bytes, and every other record is read as before. Returns whether the reader is in
    place (False where the library is a stand-in without it)."""
    try:
        import regipy.registry as reg
        record, made = reg.NKRecord, reg.VKRecord
        real = record.read_value
    except Exception:  # noqa: BLE001 - no library, or one without this reader: nothing to replace
        return False
    if getattr(real, "bounded_inline", False):
        return True

    def read_value(vk, stream):
        size = vk.data_size
        if isinstance(size, int) and size >= INLINE_DATA:
            data = struct.pack("<I", int(vk.data_offset) & 0xFFFFFFFF)[:min(size - INLINE_DATA, 4)]
            return made(value_type=vk.data_type, value_type_str=str(vk.data_type), value=data, size=size)
        return real(vk, stream)

    read_value.bounded_inline = True
    record.read_value = staticmethod(read_value)
    return True


def multi_strings(data):
    """REG_MULTI_SZ data as regipy 6.3 gives it, read in one pass: the UTF-16LE strings between NULs that start on an even byte, empty ones left
    out, up to the bytes after the last NUL (dropped) or up to a string that is not valid UTF-16 (dropped, and every string after it). regipy
    parses it with construct's GreedyRange(CString), which grows each string a code unit at a time: a string with no NUL after it took 4.3 s for
    1 MiB and 50 s for 2 MiB, and no clock of the tool could stop it. Returns (strings, the bytes dropped that are not NUL padding, whether a
    string that is not valid UTF-16 began them, how many of the strings come after an empty one, the end of a REG_MULTI_SZ's list), so that
    what is dropped, and what lies past the end of the list, is said."""
    strings, at, ended, after = [], 0, False, 0
    while True:
        end = data.find(b"\x00\x00", at)
        while end != -1 and (end - at) % 2:
            end = data.find(b"\x00\x00", end + 1)
        if end == -1:
            break
        if end > at:
            try:
                strings.append(data[at:end].decode("utf-16-le"))
            except UnicodeDecodeError:
                return strings, len(data) - at, True, after
            after += ended
        else:
            ended = True
        at = end + 2
    tail = data[at:]
    return strings, (len(tail) if tail.strip(b"\x00") else 0), False, after


class HiveRefused(Exception):
    """A hive that open_hive does not hand to regipy; the text says what was found."""


def open_hive(path):
    """regipy's RegistryHive(path), called only when the file is what regipy's open assumes. RegistryHive takes for the root key the first
    allocated cell of the first bin, reading the bin 4 bytes at a time with no clock: a free cell (a size of zero or more) does not move it on,
    so a hive whose first bin is free space was read word by word to the end of the file (a 40 MB hive: 57.6 s; 150 MB ran past every tool's
    limit). The file is checked first, without regipy: the base block's signature, the root cell offset it names inside the hive bins it
    declares and inside the file, the first bin's signature and size, the root cell allocated (a negative size), big enough for a key and an
    "nk", and the first allocated cell of the first bin (what regipy takes) that same cell, at most ROOT_SCAN_BYTES in. A hive that fails one
    of these raises HiveRefused with what was found, and regipy does not read it. A stand-in library (one without the regf layout) is called
    as it is."""
    import regipy.registry as reg
    if not all(hasattr(reg, name) for name in ("HBin", "REGF_HEADER", "CM_KEY_NODE")):
        return reg.RegistryHive(path)
    size = os.path.getsize(path)
    with open(path, "rb") as fh:
        base = fh.read(HBIN_START + 0x20)
        if len(base) < HBIN_START + 0x20 or base[:4] != b"regf":
            raise HiveRefused("the file is not a registry hive: it does not start with a regf base block and a first hive bin (%d bytes)" % size)
        root, bins = struct.unpack_from("<II", base, 0x24)
        if base[HBIN_START:HBIN_START + 4] != b"hbin":
            raise HiveRefused("the hive has no hive bin at offset 4096 (the bytes there are not \"hbin\"): regipy would look for the root key in them")
        first = struct.unpack_from("<I", base, HBIN_START + 8)[0]
        if first < 0x1000 or first % 0x1000:
            raise HiveRefused("the first hive bin declares a size of %d bytes, which is not a positive multiple of 4096: the bins are not read" % first)
        if bins % 0x1000 or root < 0x20 or root % 8 or root + 4 + 0x4C > bins or HBIN_START + root + 4 + 0x4C > size:
            raise HiveRefused("the base block names the root key's cell at offset %d of hive bins it declares as %d bytes, in a file of %d bytes: "
                              "that is not a cell inside the bins" % (root, bins, size))
        fh.seek(HBIN_START + root)
        cell = fh.read(6)
        cell_size = struct.unpack_from("<i", cell)[0]
        if cell_size >= 0:
            raise HiveRefused("the root key's cell (offset %d) is free (its size, %d, is not negative): the hive's root is not there" % (root, cell_size))
        if -cell_size < 4 + 0x4C or cell[4:6] != b"nk":
            raise HiveRefused("the root key's cell (offset %d) is not a key: %d bytes, signature %r" % (root, -cell_size, bytes(cell[4:6])))
        # The first word with its sign bit set, from the first cell of the first bin on: the cell regipy takes for the root.
        fh.seek(HBIN_START + 0x20)
        words = fh.read(min(root - 0x20, ROOT_SCAN_BYTES) + 4)
        hit = re.search(b"[\x80-\xff]", words[3::4])
        if hit is None or 0x20 + 4 * hit.start() != root:
            raise HiveRefused("regipy takes for the root key the first allocated cell of the first bin, %s, and the base block names the cell at offset "
                              "%d: the root regipy would read is not the hive's" % (
                                  "at offset %d" % (0x20 + 4 * hit.start()) if hit is not None else "which is more than %d bytes in" % ROOT_SCAN_BYTES, root))
    return reg.RegistryHive(path)


class HiveBounds:
    def __init__(self, hive_path, size=None):
        self.inline_values_bounded = bound_value_reads()
        size = os.path.getsize(hive_path) if size is None else size
        self.hive_bytes = size
        self.key_cells = max(size // KEY_CELL_BYTES, 1)
        self.value_cells = max(size // VALUE_CELL_BYTES, 1)
        self.keys_read = 0                      # subkey elements read over the whole walk
        self.names_held = 0                     # bytes of the stored names of the distinct keys the lists of the walk handed out
        self.data_read = 0                      # bytes of value data read over the whole walk
        self.repeats = 0                        # elements that named a key already named in the same list
        self.not_read = 0                       # values a key lists that this block did not read (refused, or past a bound or the clock)
        self.deadline = None                    # a monotonic time the caller sets for its walk; else the tool's own deadline is read

    def subkeys(self, node, where, problems):
        """The distinct subkeys of `node`, at most the keys the hive can still hold; what is past that, or repeated, is a problem line. A key is
        kept the first time the list names it, and only then: an index that names one list again and again (65,535 lists of 65,535 elements)
        costs the elements read, not a record kept for each (one of regipy's key records is about 1.4 KB besides its name, and such a list held
        them all past 2 GB). What a kept key takes is counted by its own size: the record, its name as stored (up to 65,535 bytes) and as decoded
        (up to twice that); regipy does not check that an element points at a key, so elements a byte apart in a run of random bytes are each a
        key with a name of up to 64 KiB (65,000 of them held 11.8 GB). The list is read no further after REPEAT_RUN elements in a row that name
        keys it already named, after the distinct keys reach HELD_KEYS_BYTES of memory, after the names the walk kept reach HELD_NAMES_PER_BYTE
        times the hive's bytes, at the deadline, and, for a list begun after the deadline (a tool that finishes what it needs), after
        LATE_ELEMENTS elements; each such stop is a problem line."""
        room = max(self.key_cells - self.keys_read, 0)
        late = self.past_deadline()
        most_names = HELD_NAMES_PER_BYTE * self.hive_bytes
        seen, distinct = set(), []
        read = repeated = run = held = 0
        source = node.iter_subkeys() or iter(())
        try:
            for sub in source:
                if read >= room:
                    problems.append({"where": where, "what": "subkeys",
                                     "error": "its subkey list yields more keys than a %d-byte hive can hold (%d keys at most, %d already read in this walk): "
                                              "an index that repeats a list; the elements past that are not read" % (self.hive_bytes, self.key_cells, self.keys_read)})
                    break
                if late and read >= LATE_ELEMENTS:
                    problems.append({"where": where, "what": "subkeys",
                                     "error": "its subkey list was begun after the time limit and %d of its elements were read: the elements past that are not read" % read})
                    break
                header = getattr(sub, "header", None)
                name = str(getattr(sub, "name", "") or "")
                said = name.lower()
                if len(said) > IDENTITY_NAME:
                    said = (len(said), hashlib.blake2b(said.encode("utf-8", "surrogatepass"), digest_size=16).digest())
                identity = (said, getattr(header, "last_modified", None),
                            getattr(header, "subkeys_list_offset", None), getattr(header, "values_list_offset", None))
                if identity in seen:
                    read += 1
                    repeated += 1
                    run += 1
                    if run >= REPEAT_RUN:
                        problems.append({"where": where, "what": "subkeys",
                                         "error": "its subkey list named keys it had already named %d times in a row, after %d elements: an index that repeats "
                                                  "a list; the elements past that are not read" % (run, read)})
                        break
                else:
                    stored = getattr(header, "key_name_string", None)
                    stored = len(stored) if isinstance(stored, (bytes, bytearray)) else len(name)
                    cost = HELD_KEY_BYTES + stored + sys.getsizeof(name) + sys.getsizeof(said)
                    if held + cost > HELD_KEYS_BYTES:
                        problems.append({"where": where, "what": "subkeys",
                                         "error": "its subkey list names more distinct keys than this tool holds for one list (%d MiB of memory, their names "
                                                  "counted; %d were kept): the elements past that are not read" % (HELD_KEYS_BYTES >> 20, len(distinct))})
                        break
                    if self.names_held + stored > most_names:
                        problems.append({"where": where, "what": "subkeys",
                                         "error": "the names of the keys this walk kept add up to more than %d times the %d bytes of the hive, and each name is "
                                                  "inside a cell of its own: key cells that overlap, elements that point into other keys; the elements past that "
                                                  "are not read" % (HELD_NAMES_PER_BYTE, self.hive_bytes)})
                        break
                    held += cost
                    self.names_held += stored
                    read += 1
                    run = 0
                    seen.add(identity)
                    distinct.append(sub)
                if not late and read % 256 == 0 and self.past_deadline():
                    # The library reads a key record for every element: an index that repeats lists in a large hive is a million of them.
                    problems.append({"where": where, "what": "subkeys",
                                     "error": "the time limit was reached after %d elements of its subkey list: the elements past that are not read" % read})
                    break
        finally:
            close = getattr(source, "close", None)
            if callable(close):
                close()
        self.keys_read += read
        if repeated:
            self.repeats += repeated
            problems.append({"where": where, "what": "subkeys",
                             "error": "its subkey list names %d key(s) more than once; each is listed once" % repeated})
        lost = _lost_names(distinct)
        if lost:
            problems.append(_lost_names_problem(where, "subkeys", lost))
        return distinct

    def key(self, root, path, problems):
        """The key at `path` below `root` (parts split at backslashes, matched without regard to case), each subkey list on the way read through
        subkeys(); None when a part is not there. regipy's get_key reads the elements of each list on the way until one has the name, and an
        index that names one list again and again is read as many times as it says (65,535 lists of 65,535 keys), past any clock of the tool.
        Each list is read to what the hive can hold (and, after the deadline, to LATE_ELEMENTS); a lookup is not counted against the walk's own
        count of keys read (a tool looks a few paths up, and may look one list up again for each)."""
        parts = [p for p in str(path).replace("/", "\\").split("\\") if p]
        node = root
        for i, part in enumerate(parts):
            said, walked, names = [], self.keys_read, self.names_held
            self.keys_read = self.names_held = 0
            try:
                kids = self.subkeys(node, "\\" + "\\".join(parts[:i]), said)
            finally:
                self.keys_read, self.names_held = walked, names
            # What a list on the way was cut or de-duplicated for is the caller's; names of keys that are not on the path are not.
            lost = _lost_names_problem("", "subkeys", 0)["error"].split(" ", 1)[1]
            for item in said:
                if not str(item.get("error", "")).endswith(lost):
                    problems.append(item)
            node = next((kid for kid in kids if str(getattr(kid, "name", "")).lower() == part.lower()), None)
            if node is None:
                return None
        return node

    def past_deadline(self):
        """Whether the walk's deadline has passed: the one the caller set (self.deadline), else the tool's own (the "deadline" that set_deadline
        writes into STOP or CLOCK). The deadline is read here, not through the tool's out_of_time(), so that a tool's count of its own clock
        readings is not moved by this block."""
        deadline = self.deadline
        if deadline is None:
            for box in (globals().get("STOP"), globals().get("CLOCK")):
                at = box.get("deadline") if isinstance(box, dict) else None
                if isinstance(at, (int, float)) and not isinstance(at, bool):
                    deadline = at
                    break
        return deadline is not None and time.monotonic() > deadline

    def values(self, node, where, problems, **kwargs):
        """The values of `node`, handed out one at a time: at most the values the hive can hold, at most the data it can hold over the whole walk
        (a value list that names one big record again and again reads that record every time), at most LIST_DATA_BYTES of names and data for
        the key (a caller may keep every value of it, and a name can be 65,535 bytes: a list naming one such record 50,000 times is 3 GB of names),
        and, for a list begun after the deadline, at most LATE_VALUES; a key that lists more is a problem
        line. The deadline is read before every value of a list begun before it: a key whose values are not all read in time is a problem line.
        With the real library the values are read here (read_values), every value's size checked before its data is read; with a stand-in that
        has no stream, through its iter_values. What the list declares and was not handed out, other than what regipy itself leaves out, is
        counted in not_read when the list ends (or the caller stops reading it)."""
        declared = getattr(node, "values_count", None)
        declared = declared if isinstance(declared, int) and not isinstance(declared, bool) else None
        reg = _library_for(node)
        own = reg is not None
        tally = {"skipped": 0, "data": 0}       # values regipy itself leaves out; data of this key handed out
        source = self.read_values(node, reg, where, problems, tally, **kwargs) if own else iter(node.iter_values(**kwargs) or ())
        given, lost, cut = 0, 0, False
        late = self.past_deadline()
        try:
            while True:
                if not late and self.past_deadline():
                    if declared is None or given + tally["skipped"] < declared:
                        problems.append({"where": where, "what": "values",
                                         "error": "the time limit was reached after %d of the %s value(s) its list holds: the values past that are not read"
                                                  % (given, declared if declared is not None else "unknown number of")})
                        cut = True
                    break
                if late and given >= LATE_VALUES:
                    if declared is None or given + tally["skipped"] < declared:
                        problems.append({"where": where, "what": "values",
                                         "error": "its value list was begun after the time limit and %d of its values were read: the values past that are not read" % given})
                        cut = True
                    break
                try:
                    v = next(source)
                except StopIteration:
                    break
                if given >= self.value_cells:
                    problems.append({"where": where, "what": "values",
                                     "error": "its value list yields more values than a %d-byte hive can hold (%d at most): the elements past that are not read"
                                              % (self.hive_bytes, self.value_cells)})
                    cut = True
                    break
                if not own:
                    data = getattr(v, "value", None)
                    cost = len(data) if isinstance(data, (bytes, bytearray, str)) else sum(len(x) for x in data if isinstance(x, (str, bytes))) if isinstance(data, list) else 0
                    self.data_read += cost
                    tally["data"] += cost
                    if self.data_read > 4 * self.hive_bytes:
                        problems.append({"where": where, "what": "values",
                                         "error": "the values read in this walk hold more data than a %d-byte hive can: records that a value list names again and again; "
                                                  "the values past that are not read" % self.hive_bytes})
                        cut = True
                        break
                    if tally["data"] > LIST_DATA_BYTES:
                        problems.append({"where": where, "what": "values",
                                         "error": "the values of this key hold more than %d MiB of data, the most this tool holds for one key: the values past "
                                                  "that are not read" % (LIST_DATA_BYTES >> 20)})
                        cut = True
                        break
                given += 1
                if LOST_CHARACTER in str(getattr(v, "name", "") or ""):
                    lost += 1
                yield v
        finally:
            close = getattr(source, "close", None)
            if callable(close):
                close()
            if declared is not None and (own or cut):
                # What the list holds and was not handed out: regipy's own skips (a type it leaves out, the rest of a list after a record it
                # cannot parse) are the library's; every other one this block refused or did not reach.
                self.not_read += max(declared - given - tally["skipped"], 0)
            if lost:
                problems.append(_lost_names_problem(where, "values", lost))

    def read_values(self, node, reg, where, problems, tally, as_json=False, max_len=None, trim_values=True):
        """regipy 6.3's NKRecord.iter_values, read from the library's copy of the hive with the same records and names, except where its own
        reading costs without bound or gives what the hive does not hold. A big data value (a "db" record and its list of segments) is checked
        before its data is put together, for every type, and refused when it declares more data than the file holds past its base block, when
        its list holds fewer segments than its size needs, runs past the file or names a segment twice, or when a segment lies outside the file or
        its cell (regipy put together whatever the list named: one 16 KB segment named 160 times was a 2.5 MiB value, and a 548 KB hive declared a
        value of 2 GiB; and it put together only six types, giving the "db" record and the bytes after it as the value of every other). Every
        value's data and name are counted against the walk's budget and the key's (`tally`, which also counts values not read) before its data is
        read, and a value that declares more than VALUE_DATA_BYTES is said with its length and not read (a value list naming one 250 MB string
        four times held a gigabyte of text at once); a value whose data is not wholly inside the file (it runs past the end or starts past it) or
        inside the cell that holds it (the bytes past the cell are the next cells', another value's among them), or that declares more than the
        four bytes a record holds, is not read. The bytes found are taken by typed_value, by the table at VALUE_TYPES. A refused value is a
        problem line and is not in the list; a value given as its bytes because its type's decoding does not hold for them is in the list, and a
        problem line says so. as_json, max_len and trim_values are taken for the library's signature and not applied: a value is given whole."""
        count = node.values_count
        if not count:
            return
        library_log = logging.getLogger("regipy.registry")
        stream = node._stream
        with stream.getbuffer() as buf:
            end = len(buf)
            room = max(end - HBIN_START, 0)
            listed_at = HBIN_START + 4 + node.header.values_list_offset
            for i in range(min(count, self.value_cells + 1)):
                at = listed_at + 4 * i
                if at + 4 > end:
                    raise reg.RegistryParsingException("Bad registry VK at %d" % at)
                vk_at = HBIN_START + 4 + struct.unpack_from("<I", buf, at)[0]
                here = stream.tell()
                try:
                    stream.seek(vk_at)
                    vk = reg.VALUE_KEY.parse_stream(stream)     # the layout as the library holds it (a tool may have put a checking one in its place)
                except (reg.ConstError, reg.StreamError):
                    # regipy ends the list without an error at a value record it cannot parse; so does this
                    library_log.error("Could not parse VK at %d, registry hive is probably corrupted." % vk_at)
                    tally["skipped"] += count - i
                    return
                finally:
                    stream.seek(here)
                kind = int(vk.data_type) & 0xFFFFFFFF
                data_type = VALUE_TYPES.get(kind, str(kind))
                where_value = "its value %d of the %d its list holds (%s)" % (i + 1, count, data_type)
                if vk.name_size == 0:
                    name = "(default)"
                elif vk.flags.VALUE_COMP_NAME:
                    name = vk.name.decode("ascii", errors="replace")
                else:
                    name = vk.name.decode("utf-16-le", errors="replace")
                size, offset = vk.data_size, vk.data_offset
                inline = size >= INLINE_DATA
                big = False
                if inline:
                    if size - INLINE_DATA > 4:
                        # the record holds four bytes of data at most: what it declares past them is nowhere, and four bytes of it are not its value
                        problems.append({"where": where, "what": "values",
                                         "error": "%s is not read: it declares %d bytes of data held in its record, which holds 4 at most" % (where_value, size - INLINE_DATA)})
                        continue
                    cost = 0
                else:
                    start = HBIN_START + 4 + offset
                    big = size > SEGMENT_DATA and bytes(buf[start:start + 2]) == b"db"
                    if big:
                        segments, why = big_data_segments(buf, start, size, room)
                    elif size and start + size > end:
                        # data that runs past the end of the file, or starts past it, is not the value: the part inside (or nothing) is not printed as it
                        why = "it declares %d bytes of data at offset %d of a hive file of %d bytes, %s" % (
                            size, start, end, "which starts past its end" if start >= end else "and %d of them are past its end" % (start + size - end))
                    else:
                        why = cell_short(buf, start, size, "its data cell") if size else None
                    if why:
                        problems.append({"where": where, "what": "values", "error": "%s is not read: %s" % (where_value, why)})
                        continue
                    cost = size
                    if cost > VALUE_DATA_BYTES:
                        problems.append({"where": where, "what": "values",
                                         "error": "%s is not read: it declares %d bytes of data, more than the %d MiB this tool reads of one value; its length "
                                                  "is all that is read" % (where_value, size, VALUE_DATA_BYTES >> 20)})
                        continue
                cost += len(vk.name)                # the name is held too, as stored and as decoded: a list that names one long-named record again and again
                if tally["data"] + cost > LIST_DATA_BYTES:
                    problems.append({"where": where, "what": "values",
                                     "error": "the values of this key hold more than %d MiB of names and data, the most this tool holds for one key: the values past "
                                              "that are not read" % (LIST_DATA_BYTES >> 20)})
                    return
                if self.data_read + cost > 4 * self.hive_bytes:
                    problems.append({"where": where, "what": "values",
                                     "error": "the values read in this walk hold more names and data than a %d-byte hive can: records that a value list names "
                                              "again and again; the values past that are not read" % self.hive_bytes})
                    return
                self.data_read += cost
                tally["data"] += cost
                if inline:
                    data = struct.pack("<I", offset & 0xFFFFFFFF)[:size - INLINE_DATA]
                else:
                    data = b"".join(bytes(buf[s:s + n]) for s, n in segments) if big else bytes(buf[start:start + size])
                fixed = FIXED_VALUE_BYTES.get(data_type)
                if fixed is not None and len(data) != fixed:
                    # the first bytes of a longer value, or bytes the record does not declare, are not its value: neither is printed as it
                    problems.append({"where": where, "what": "values",
                                     "error": "%s is not read: a %s is %d bytes and this one declares %d; its data is not given as the value" % (
                                         where_value, data_type, fixed, len(data))})
                    continue
                value, filetime, said = typed_value(data_type, data)
                if said:
                    problems.append({"where": where, "what": "values", "error": "%s %s" % (where_value, said)})
                item = reg.Value(name=name, value_type=data_type, value=value, is_corrupted=False)
                item.filetime = filetime
                yield item


def _library_for(node):
    """regipy's registry module when `node` is its key record over a copy of the hive in memory (what read_values reads), else None (a stand-in)."""
    if not hasattr(getattr(node, "_stream", None), "getbuffer") or not isinstance(getattr(getattr(node, "header", None), "values_list_offset", None), int):
        return None
    try:
        import regipy.registry as reg
        for name in ("VALUE_KEY", "Value", "RegistryParsingException", "ConstError", "StreamError"):
            getattr(reg, name)
    except Exception:  # noqa: BLE001 - another library under the name: its own iter_values is read
        return None
    return reg if isinstance(node, reg.NKRecord) else None


def cell_short(buf, start, length, what):
    """None when the allocated cell whose data starts at `start` holds `length` bytes (its size, in the 4-byte header before it, counts the
    header), else why not. A value's bytes are read only from inside their own cell: what is past it is the next cells' (another value's data, a
    name). A cell whose size is zero or more is free: its bytes are what a deleted record left or nothing, not this value's data."""
    if start - 4 < HBIN_START or start > len(buf):
        return "%s at offset %d is not inside the hive bins" % (what, start)
    size = struct.unpack_from("<i", buf, start - 4)[0]
    if size >= 0:
        return "%s (offset %d) is a free cell (its size, %d, is not negative): its bytes are not allocated data" % (what, start - 4, size)
    held = -size - 4
    if length > held:
        return ("it declares %d bytes of data and %s (offset %d) holds %d: the bytes past the cell are not its data"
                % (length, what, start - 4, max(held, 0)))
    return None


def big_data_segments(buf, start, size, room):
    """The (place, length) of each segment of the big data value whose "db" record starts at `start`, or a reason to refuse it. Nothing is read
    but the record and its list: the value is put together by the caller only when every segment is a distinct place inside the file and
    inside a cell that holds it, and the record and its list are inside theirs."""
    if size > room:
        return None, "it declares %d bytes of data, more than the %d bytes the hive file holds past its base block" % (size, room)
    end = len(buf)
    if start + 8 > end:
        return None, "its big data record runs past the end of the hive file"
    why = cell_short(buf, start, 8, "the cell of its big data record")
    if why:
        return None, why
    listed, list_offset = struct.unpack_from("<HI", buf, start + 2)
    needed = -(-size // SEGMENT_DATA)
    if listed < needed:
        return None, "its big data record lists %d segment(s) and %d are needed for the %d bytes it declares" % (listed, needed, size)
    at = HBIN_START + 4 + list_offset
    if at + 4 * needed > end:
        return None, "its list of segments runs past the end of the hive file"
    why = cell_short(buf, at, 4 * needed, "the cell of its list of segments")
    if why:
        return None, why
    offsets = struct.unpack_from("<%dI" % needed, buf, at)
    if len(set(offsets)) < needed:
        return None, ("its list of segments names one segment more than once (%d distinct of %d): a list made to read one segment again and again"
                      % (len(set(offsets)), needed))
    segments = []
    for n, offset in enumerate(offsets):
        place, length = HBIN_START + 4 + offset, min(SEGMENT_DATA, size - n * SEGMENT_DATA)
        if place + length > end:
            return None, "its segment %d of %d lies past the end of the hive file" % (n + 1, needed)
        why = cell_short(buf, place, length, "the cell of its segment %d of %d" % (n + 1, needed))
        if why:
            return None, why
        segments.append((place, length))
    return segments, None
# END SHARED HIVE BOUNDS


# BEGIN SHARED BOUNDARY
# BOUNDARY v2, the one text: the same text is in every tool that prints names, paths, event data, registry data, identifiers or table
# cells from evidence (tests/pack-boundary-shared.test.ts finds every copy under packs/ and tool-library/ and holds them equal: one variant, 16 carriers).
# It is the owner-approved HYBRID design: an allow-list for
# identifier-shaped fields, a deny-list for free text, and an independent backstop on the way out.
#
# Names defined here start with _b_ or _B_ where another shared block of a tool could define the same name (the WITHHOLDING block has _withheld and _USERINFO).
# THE CALLS A TOOL MAKES, and what the virtualization block called each (the three virtualization tools moved onto this text; the table is what they map to):
#   FIELDS, KEY_KINDS, bind_fields(table, key_kinds)           the table of field kinds, which the CALLER passes in (this text holds no tool's table);
#                                                              it was _FIELDS, _INHERIT and field_kind(); a digit run in a field name stands for any number
#                                                              (`ethernet#.address`), and a field the table does not list has the kind of the field above it
#   T(kind, text), show(s, kind, field)                        one string judged by its kind                         (the Shower, boundary_text, seal_text, seal_head)
#   sealed_text(text, kind, field), print_order(items, ...)    what an answer prints for a string; nothing counted    (seal_text without the count)
#   bind_values(enabled, tool), close_values(), values_summary()  the values file of a secret_output job            (bind_run(values, seconds))
#   seal_stop_after(seconds)                                   the clock: nothing is judged after it                  (bind_run's seconds, RUN["deadline"])
#   row_object(row)                                            one row of a paging file                               (row_text(row, where))
#   answer_object(doc), emit(doc)                              an answer, sealed and read back                        (answer_text(doc), backstop(value, where))
#   boundary_summary()                                         the "boundary" object; stopped_by is in it when judging stopped
#   OWN_NAMES                                                  the exact strings the run made and shows as they are   (OWN_NAMES)
# The kinds of a field: text (the default), name, path, key, url, host, hex, id (one of several forms of identifier: a GUID, a VMFS volume id, a device id, a VMware uuid, a MAC, a content id of 32 hexadecimal digits or a number; else a name), and the typed ones guid, digest, sid, mac, ip, time, number, version
# and, for virtualized storage and machines, vmfs (a VMFS volume id), device (naa., eui., wwn-0x, vml. and t10. ids), iqn, vmuuid (the VMware
# uuid of a machine), cid (a disk's content id), winhost (the name Windows gives a machine nobody named).
#
# LAYER 1, an allow-list per field type. A string the evidence supplied is shown as it is only when it fits the plain grammar of the
# type of the field it fills: a name (registry key and value names, event field names, provider and channel names, table and column
# names), a path (file names and paths, a registry path, a URL path), a key, a URL, or a typed id (GUID, SID, MAC, IP address, digest,
# time, number, version). The grammar is: letters of any script, digits, space and `_ - . $ @ ? : ~ + , # ( ) [ ] { } ' < > *`, at
# most 128 characters a component, no user-info shape (a `:` before an `@`), and no chain of 16 or more characters made of
# random-looking pieces (pieces that break into one- and two-character parts, flip between letters and digits, or are letters with
# no pronounceable word in them; a 16-hex id, a GUID or a number up to 18 digits is plain). Below 16 characters a chain is shown
# whatever it looks like: a short random password in a name is not recognised. A path is judged component by component and only the
# offending span is replaced; a string with a format, control or combining character is withheld whole.
#
# LAYER 2, for every kind, and it reads the string FIRST, as the evidence wrote it (the deny-list and the grammar cut spans out of a string
# and take with them the context these rules need: the user of `user:password@host`, the characters glued before `glpat-`): user-info up
# to the last `@` before the host (the password may hold a `/`, not a port); the value after a secret's name (password, secret, token,
# api/access/account/private key, credential, auth) found anywhere, up to a space or quote, and past a `& ; ,` that no `name=` follows;
# a PEM private key; a vendor token with its own prefix (AKIA, gh?_, github_pat_, xox?-, glpat-, sk_live_, SG., AIza, npm_, dop_v1_,
# ya29., sk-, JWT) in any case; a base64 key with its padding; and the same rules on a copy with invisible characters taken out and NFKC
# applied (a hit withholds the whole string). FREE TEXT (event data, messages, command lines, registry data strings, table cells) is on
# the deny-list: the same chain test applied to the text with its typed ids (GUID, SID, IP address, time, labelled digest, number) left
# alone, plus layer 2, and no character grammar.
#
# LAYER 3, the backstop, written apart from the layers above: every key and value of what is about to be written is read once more
# by its own normaliser and patterns (a PEM marker, a named secret, a run of 19 or more digits, a token prefix in any case, user-info, a
# run of 40 or more hex digits outside a typed field, a base64 run, a run that changes class as random text does; a typed field must hold
# the characters of its type; data written as hexadecimal is decoded and its printable text is read as text). It reads the shown string
# AND the original: a window of 12 characters of anything it calls secret in the original that is still in the shown string means the
# layers above left a piece of a secret between two cuts. A string it finds suspect is replaced by <withheld N bytes: backstop: why>,
# counted, its place named in boundary.replaced_at (built from the keys on the way as they are SHOWN, or their positions), and the
# answer is partial. A placeholder is only a placeholder when its reason is one of the fixed list. The names of the components of the Windows
# component store (WinSxS: lower case, a public key token, a language or `none`, a hash) are not judged by the backstop in a name or key slot:
# a real SOFTWARE hive lists them by the thousand and their hash looked random to it; layer 1 judges them as it does every name.
#
# ONE WAY OUT: emit() writes an answer, row_object() makes a row of a paging file, and both seal every key and value first (a value that is not
# a string, a number or a container is sealed as the text str() makes of it). Binary data written as hex (a REG_BINARY value, an ESE
# binary column) is decoded and its printable views (Latin-1, UTF-16LE and UTF-16BE, and runs holding full-width characters read as UTF-8 and UTF-16LE with
# the width folded) are judged by the free-text rules, by both layers and the
# backstop; hex that holds a secret-shaped text is withheld, and any other hex is shown (random bytes with no text in them are printed).
# What is withheld is a placeholder with its length and the reason; its original goes to the values file only when write_values was
# asked for in a job run as secret output. A list of names is printed in the order of the text shown for each, the placeholders of
# withheld names in a random order that is new every run (print_order); a `contains` filter is applied to the text the answer PRINTS (the
# string after the layers and the backstop, sealed_text), never to what is withheld or replaced, and contains_check says when the needle
# could have been in what is hidden. Every string is judged in linear time (a string is read to 256 KiB, the pieces the backstop compares
# are at most 64, a PEM body at most 20,000 characters), and an answer or a row that takes longer than SEAL_BUDGET seconds to seal, or that is
# still being sealed at the seal stop of the tool (seal_stop_after: a point in time after which nothing is judged, not a stop of the tool's own
# work, which has its own clock), has the rest of its strings replaced whole (<withheld N bytes: backstop: the judging time ran out>) and is
# partial; what stays readable past that point is the names the tool made itself (OWN_NAMES) and strings of 15 characters or fewer of letters,
# digits, `_` and `.` that do not start like a vendor token (and, in a field of a typed kind, fit the grammar of its type). The seal stop is 3.5 seconds before the
# tool's time limit: the string in progress finishes after it, and one string of 256 KiB takes up to 2.3 seconds to judge on a loaded machine (the worst measured).
# A run has a second bound: past MAX_JUDGED_CHARS characters judged (the final answer is always judged), a string not judged before is withheld by its size in the
# same way. boundary.stopped_by says which bound stopped the judging and boundary.strings_withheld_by_the_stop how many strings it withheld; the answer is partial.
# The judging that only sees what an answer would print (the order of a list, print_order; a filter, sealed_text and contains_check) runs under the same
# clock and counts toward the same cap: past either, the items of a list not judged yet come after the judged ones in a random order, a filter is blind to
# a string it did not judge, each such string is counted (boundary.strings_not_judged_for_order_or_filter), and the answer is partial.
# NOT RECOGNISED, by design: a secret that does not look like one (a plain password, a pronounceable passphrase, a UUID-shaped key,
# anything under 16 characters in a name, a secret hidden in words or in an encoding this block does not read).
import collections
import hashlib
import signal
import time
import unicodedata

LMIN = 16
MAX_ONE_STRING = 1 << 18
MAX_HEX_JUDGED = 1 << 20
MAX_PIECES = 64                 # the pieces of a string the backstop compares with what was shown (it stops collecting at this many)
MAX_PEM_BODY = 20000            # a PEM body is read to this many characters (a 16,384-bit RSA key is about 13,000)
SEAL_BUDGET = 10.0              # seconds one answer, or one row of a paging file, may take to be sealed; a tool may set another
_CLOCK = {"deadline": None, "stop": None}
_BIGRAMS_TEXT = "aaabacadaeafagahaiajakalamanaoapaqarasatauavawaxayazbabbbcbdbebfbhbibjblbmbnbobpbrbsbtbubvbycacbcccdcecfchcickclcncocqcrcsctcucydadbdcdddedfdgdhdidjdldmdndodpdrdsdtdudvdwdyeaebecedeeefegeheiejekelemeneoepeqereseteuevewexeyezfafbfcfdfefffiflfofrftfufygagbgdgegfggghgiglgmgngogrgsgtgugwgyhahbhchdhehfhhhihlhmhnhohphrhshthuhwhyiaibicidieifigihiiijikiliminioipiqirisitiuiviwixizjajejijojukakbkekfkhkikkklkmknkokpkrksktkukwkylalblcldlelflglhlilklllmlnlolplrlsltlulvlwlymambmemfmimlmmmnmompmrmsmumwmynanbncndnenfngnhninjnknlnmnnnonpnqnrnsntnunvnwnxnynzoaobocodoeofogohoiojokolomonooopoqorosotouovowoxoyozpapbpcpepfphpiplpmpnpoppprpsptpupwpyqurarbrcrdrerfrgrhrirjrkrlrmrnrorprqrrrsrtrurvrwryrzsasbscsdsesfsgshsiskslsmsnsospsqsrssstsusvswsytatbtctdtetftgthtitltmtntotptrtstttutvtwtytzuaubucudueufuguhuiukulumunuoupurusutuvuxuyuzvavevivovuvywawbwdwewfwhwiwkwlwmwnwowrwswtwuwyxaxcxexhxixoxpxtxuxxxyyaybycydyeyfygyhyiylymynyoypyrysytyuywyxyyyzzazezizlzozuzyzz"           # the 474 letter pairs that words and identifiers use (the system word list and Python identifiers)
_BIGRAMS = frozenset(_BIGRAMS_TEXT[i:i + 2] for i in range(0, len(_BIGRAMS_TEXT), 2))
BOUNDARY = {"withheld": 0, "by": collections.Counter(), "replaced": 0, "replaced_by": collections.Counter(), "where": [], "not_listed": 0}
OWN_NAMES = set()               # exact strings this run made and shows as they are (file names of its own results)
FIELDS = {}                     # a JSON key -> the kind of what it holds (a tool fills this in, or passes it to bind_fields); a key it does not list has the kind of the key above it (text at the top)
KEY_KINDS = {}                  # a JSON key holding a dict -> the kind of that dict's own keys (registry value names are paths); default: name
MAX_WHERE = 200
MAX_JUDGED_CHARS = 400000000    # characters one run may have judged (every string of its answers and paging files); past it a string not judged before is withheld by its size
FINAL_GRACE_CHARS = 4000000     # the final answer may always be judged: the cap is raised by this much, and is not spent again by the strings already withheld
_STOP = {"cap": MAX_JUDGED_CHARS, "chars": 0, "by": None, "strings": 0, "quiet": 0}   # why judging stopped (None: it did not), how many strings it withheld by
                                                                                        # their size, and how many it left unjudged in an order or a filter


class T(str):
    """A string with its field type, made by the tool where it knows the type (a registry type, an event field, a column)."""
    kind = "text"

    def __new__(cls, kind, text):
        self = super().__new__(cls, text)
        self.kind = kind
        return self


def _mark(n, label, unit="characters"):
    return "<withheld %d %s: %s>" % (n, unit, label)


# the reasons a placeholder can give: a fixed list, so that text which only looks like a placeholder is not taken for one (and not skipped by the rules)
_CHECKS = ("a PEM marker", "a named secret", "a token prefix", "user-info", "not the typed grammar", "a long digit run", "a long hexadecimal run",
           "a base64 run with / and +", "a padded base64 run", "a random-looking run", "a part of a secret-shaped text", "the judging time ran out")
_LABELS = ("not a plain name", "token-shaped text", "user-info", "secret value", "private key", "long number", "rest of a long string",
           "binary data over the judged size", "binary data holding a secret-shaped text", "invisible characters in a name", "not a port", "query value", "fragment",
           "not a guid", "not a digest", "not a sid", "not a mac", "not a ip", "not a time", "not a number", "not a version",
           "not a vmfs", "not a device", "not a iqn", "not a vmuuid", "not a cid", "not a winhost") + \
          tuple("backstop: " + c for c in _CHECKS) + tuple("backstop: in binary data: " + c for c in _CHECKS)
_MARK = re.compile(r"<withheld [0-9]{1,10} (?:characters|bytes)(?:: (?:%s))?>|\[withheld: [0-9]{1,10} (?:characters|bytes)\]"
                   % "|".join(re.escape(x) for x in sorted(_LABELS, key=len, reverse=True)))
_VALUES = {"fh": None, "shown": None, "written": 0, "seen": set(), "count": 0}   # "seen": 16-byte digests of the originals written (at most 200,000)


class ValuesRefused(Exception):
    pass


def bind_values(enabled, tool):
    """The values file: the originals of what the boundary withheld, in a job run as secret output and only when asked for. Decided before
    anything is opened or created (the harness sets SECRET_OUTPUT=1 for a secret job's process)."""
    if not enabled:
        return None
    job, out = os.environ.get("JOB_ID") or "", os.environ.get("OUT") or ""
    if not (job and out) or os.environ.get("SECRET_OUTPUT") != "1":
        raise ValuesRefused("write_values is refused: the originals of what was withheld are written only in a job the harness runs as secret output "
                            "(job_run with secret_output: true), where the file is a sealed secret output. Nothing was written.")
    name = "%s-values.jsonl" % re.sub(r"[^A-Za-z0-9_.-]", "_", tool)
    path = Path(out) / name
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        fd = os.open(str(path), os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o600)
    except FileExistsError:
        raise ValuesRefused("the values file already exists: %s" % path)
    except OSError as exc:
        raise ValuesRefused("the values file could not be created: %s: %s" % (path, exc.strerror or exc))
    _VALUES["fh"] = os.fdopen(fd, "w", encoding="utf-8")
    _VALUES["shown"] = "store/jobs/%s/out/%s" % (re.sub(r"[^A-Za-z0-9_.-]", "_", job), name)
    return _VALUES["shown"]


def close_values():
    fh = _VALUES["fh"]
    if fh is not None:
        fh.flush()
        os.fsync(fh.fileno())
        fh.close()
        _VALUES["fh"] = None


def values_summary():
    return {"requested": _VALUES["shown"] is not None, "values_file": _VALUES["shown"], "written": _VALUES["written"], "contains_secret_values": _VALUES["written"] > 0,
            "format": "JSON Lines, mode 0600: id, field, label, length, value (the original text that was withheld)" if _VALUES["shown"] else None}


_EVENTS = [None]               # while a string is judged only to see what the answer would print (sealed_text): its withholdings, counted when the answer prints it
_QUIET = [False]


def _b_withheld(original, label, field=""):
    n = len(original)
    if _EVENTS[0] is not None:
        _EVENTS[0].append((original, label, field))
        return _mark(n, label)
    BOUNDARY["withheld"] += 1
    BOUNDARY["by"][label] += 1
    fh = _VALUES["fh"]
    digest = hashlib.blake2b(original.encode("utf-8", "surrogatepass"), digest_size=16).digest() if fh is not None else None
    if fh is not None and digest not in _VALUES["seen"]:
        if len(_VALUES["seen"]) < 200000:
            _VALUES["seen"].add(digest)
        _VALUES["count"] += 1
        text = json.dumps({"id": _VALUES["count"], "field": field, "label": label, "length": n, "value": original}, ensure_ascii=False)
        try:
            text.encode("utf-8")
        except UnicodeEncodeError:
            text = json.dumps({"id": _VALUES["count"], "field": field, "label": label, "length": n, "value": original}, ensure_ascii=True)
        fh.write(text + "\n")
        _VALUES["written"] += 1
    return _mark(n, label)


# ---- normalisation ----------------------------------------------------------------------------------------------------------------
_STRIP_CATS = frozenset(("Cf", "Cc", "Mn", "Me", "Cs", "Co", "Cn", "Zl", "Zp"))
_FILLERS = frozenset((0x115F, 0x1160, 0x3164, 0xFFA0, 0x2800))


class _Strip(dict):
    def __missing__(self, o):
        if len(self) > 20000:
            self.clear()
        keep = unicodedata.category(chr(o)) not in _STRIP_CATS and o not in _FILLERS
        self[o] = o if keep else None
        return self[o]


_STRIP = _Strip()
_ESCAPED = re.compile(r"(?<!\\)\\+(?:u([0-9A-Fa-f]{4})|U([0-9A-Fa-f]{8})|x([0-9A-Fa-f]{2})|u\{([0-9A-Fa-f]{1,6})\})")


def _unescape_invisible(m):
    try:
        c = chr(int(m.group(1) or m.group(2) or m.group(3) or m.group(4), 16))
    except (ValueError, OverflowError):
        return m.group(0)
    return "" if (unicodedata.category(c) in _STRIP_CATS or ord(c) in _FILLERS) else m.group(0)


def _flat(text):
    """The text with invisible characters (and the escapes of such characters) taken out, and past ASCII in NFKC form."""
    if "\\u" in text or "\\U" in text or "\\x" in text:          # (the escape pattern needs a backslash and one of these)
        text = _ESCAPED.sub(_unescape_invisible, text)
    if text.isascii():
        return text if text.isprintable() else text.translate(_STRIP)
    out = text.translate(_STRIP)
    return unicodedata.normalize("NFKC", out) if not out.isascii() else out


# ---- layer 1: the allow-list ------------------------------------------------------------------------------------------------------
_PIECE = re.compile(r"[A-Z]{2,}s(?![a-z])|[A-Z]+(?![a-z])|[A-Z]?[a-z]+|[0-9]+")        # (GPOs, an acronym in the plural, is one piece)
_GUID = re.compile(r"\{?[0-9A-Fa-f]{8}-(?:[0-9A-Fa-f]{4}-){3}[0-9A-Fa-f]{12}\}?|[0-9a-f]{8}-[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{12}")
_SID = re.compile(r"S-1-[0-9]{1,2}(?:-[0-9]{1,10}){1,15}")
_IPV4 = re.compile(r"(?<![0-9A-Za-z.])[0-9]{1,3}(?:\.[0-9]{1,3}){3}(?![0-9A-Za-z])")
_HEX_NUMBER = re.compile(r"(?<![0-9A-Za-z])0[xX][0-9A-Fa-f]{1,16}(?![0-9A-Za-z])")
# the publisher ids that follow the name of an AppX package family (the hash of the publisher's name), and the assembly public key tokens of Microsoft
_KNOWN_ID_WORDS = ("0x", "8wekyb", "cw5n1h", "kzf8qx", "31bf38", "b77a5c", "b03f5f")
_KNOWN_ID = re.compile(r"(?<![0-9A-Za-z])(?:8wekyb3d8bbwe|cw5n1h2txyewy|kzf8qxf38zg5c|31bf3856ad364e35|b77a5c561934e089|b03f5f7f11d50a3a|0x[0-9A-Fa-f]{1,16})(?![0-9A-Za-z])")
_NAME_SEPS = " _-.$@?:~+,#()[]{}'`<>*"
_PATH_EXTRA = "&!';=^%\""
_PCT = re.compile(r"%[0-9A-Fa-f]{2}")
_PCT_UNRESERVED = re.compile(r"%((?:4[1-9A-Fa-f]|5[0-9Aa]|6[1-9A-Fa-f]|7[0-9Aa]|3[0-9]|2[DdEe]|5[Ff]|7[Ee]))")
_JOIN_NAME, _JOIN_PATH = "-_+", "-_+/\\"
_CTRL = "\x01\x02\x03\x04\x05\x06\x07\x08\x09"


def _has(words, text):
    """Whether one of `words` is in `text` (a loop: a generator inside any() costs twice as much for the thousands of strings of a hive)."""
    for w in words:
        if w in text:
            return True
    return False


def _pronounceable(piece):
    p = piece.lower()
    bad = sum(1 for a, b in zip(p, p[1:]) if (a + b) not in _BIGRAMS)
    return bad <= 1 + len(p) // 10


_HEX_LOW_OR_UP = re.compile(r"[0-9a-f]+|[0-9A-F]+")
_HEX_ANY = re.compile(r"[0-9A-Fa-f]+")
_SEGMENT_MEMO = {}


def _structure_ok(seg):
    if seg.isdigit() and seg.isascii():
        return len(seg) <= 18
    if len(seg) <= 24 and _HEX_LOW_OR_UP.fullmatch(seg):
        return True                       # a hexadecimal id up to 24 digits (a USB serial, a 16-digit object id, a hash of a few bytes) is plain
    if len(seg) >= 20 and _HEX_ANY.fullmatch(seg):
        return False
    pieces = _PIECE.findall(seg)
    short = sum(1 for p in pieces if len(p) <= 2)
    if short > max(2, 0.4 * len(pieces)):
        return False
    flips = sum(1 for a, b in zip(seg, seg[1:]) if a.isdigit() != b.isdigit())
    if flips > 3 + len(seg) // 16:
        return False
    alpha = [p for p in pieces if p.isalpha()]
    if sum(len(p) for p in alpha) >= 12 and sum(len(p) for p in alpha) < 3.4 * len(alpha):
        return False
    return True


def _plain_segment(seg, lmin=None):
    lmin = LMIN if lmin is None else lmin
    if len(seg) < lmin:
        return True
    memo = (seg, lmin) if len(seg) <= 64 else None          # the same words come again and again in the records of one log
    if memo is not None:
        hit = _SEGMENT_MEMO.get(memo)
        if hit is not None:
            return hit
    if not _structure_ok(seg):
        ok = False
    else:
        ok = all(not (p.isalpha() and len(p) >= 6) or _pronounceable(p) for p in _PIECE.findall(seg))
    if memo is not None:
        if len(_SEGMENT_MEMO) >= 100000:
            _SEGMENT_MEMO.clear()
        _SEGMENT_MEMO[memo] = ok
    return ok


_EMBEDDED_ID = re.compile(r"(?<![A-Za-z0-9])(?:naa\.(?:[0-9a-fA-F]{32}|[0-9a-fA-F]{16})|eui\.[0-9a-fA-F]{16}|wwn-0x[0-9a-fA-F]{16}|vml\.[0-9a-fA-F]{20,40}|vsan:[0-9a-f]{16}-[0-9a-f]{16})(?![A-Za-z0-9])")
_EMBEDDED_T10 = re.compile(r"(?<![A-Za-z0-9])t10\.[A-Za-z0-9_.+-]{8,120}")
_EMBEDDED_WORDS = ("naa.", "eui.", "wwn-0x", "vml.", "vsan:", "t10.")


def _t10_plain(text):
    """Whether a t10. id reads as the id of a drive: every piece between underscores is 19 characters or fewer, and the serial (the last) is not a run of 17 or more hexadecimal digits."""
    pieces = text.split("_")
    return all(len(piece) <= 19 for piece in pieces) and not (len(pieces[-1]) >= 17 and _HEX_ANY.fullmatch(pieces[-1]) is not None)


_ONE_CASE_TAIL = re.compile(r"[A-Za-z]{20,64}")


def _letter_serial_spans(t):
    """The t10. and iqn. ids in `t` whose serial (the last piece of a t10. id) or target (after the last colon of an iqn. name) is 20 or more letters of one case that do not read as a word."""
    if "t10." not in t and "iqn." not in t:
        return []
    spans = []
    for m in _EMBEDDED_T10.finditer(t):
        last = m.group().split("_")[-1]
        if _ONE_CASE_TAIL.fullmatch(last) and (last.islower() or last.isupper()) and not _word_letters(last):
            spans.append((m.start(), m.end()))
    for m in _IQN_NAME.finditer(t):
        last = m.group().rsplit(":", 1)[-1]
        if _ONE_CASE_TAIL.fullmatch(last) and (last.islower() or last.isupper()) and not _word_letters(last):
            spans.append((m.start(), m.end()))
    return spans


_IQN_NAME = re.compile(r"(?<![A-Za-z0-9])iqn[.][0-9]{4}-[0-9]{2}[.][a-z0-9.-]{1,60}(?::[A-Za-z0-9._-]{1,64})?")


def _t10_hex_spans(t):
    """The t10. ids in `t` whose serial is a run of 17 or more hexadecimal digits: a drive's serial is not one (a random one is), and a run of hexadecimal digits is otherwise plain."""
    if "t10." not in t and "iqn." not in t:
        return []
    spans = []
    for m in _EMBEDDED_T10.finditer(t):
        last = m.group().split("_")[-1]
        if len(last) >= 17 and _HEX_ANY.fullmatch(last) is not None:
            spans.append((m.start(), m.end()))
    return spans + _letter_serial_spans(t)


def _mask_embedded(t):
    """`t` with the well-formed ids of devices in it (naa., eui., wwn-0x, vml., vsan: and a t10. id of a drive) replaced by `~`, so that the judging of a name or a path does not take their digits for a random run."""
    if not _has(_EMBEDDED_WORDS, t):
        return t
    t = _EMBEDDED_ID.sub(lambda m: "~" * len(m.group()), t)
    return _EMBEDDED_T10.sub(lambda m: "~" * len(m.group()) if _t10_plain(m.group()) else m.group(), t)


def _prepare(s, typed=True):
    """A same-length copy of `s` in which a GUID, a SID, an IPv4 address and a %XX escape are replaced by `~` and a non-ASCII letter by `e`;
    None when `s` holds a format, control or combining character, a non-NFKC character or a stray space character."""
    if not s.isascii():
        for ch in s:
            cat = unicodedata.category(ch)
            if cat[0] in "CM" or (cat[0] == "Z" and ch != " "):
                return None
        if unicodedata.normalize("NFKC", s) != s:
            return None
        s = "".join(ch if ch.isascii() else "e" for ch in s)
    t = _GUID.sub(lambda m: "~" * len(m.group()), s) if s.count("-") >= 3 else s    # (each pattern is tried only when the text holds what it cannot match without: a GUID has three hyphens or more)
    if typed:
        if "S-1-" in t:
            t = _SID.sub(lambda m: "~" * len(m.group()), t)
        if "." in t:
            t = _IPV4.sub(lambda m: "~" * len(m.group()), t)
        if _has(_KNOWN_ID_WORDS, t):
            t = _KNOWN_ID.sub(lambda m: "~" * len(m.group()), t)
        t = _mask_embedded(t)
    return _PCT.sub("   ", t) if "%" in t else t


def _unpercent(s):
    if "%" not in s:
        return None
    out = _PCT_UNRESERVED.sub(lambda m: chr(int(m.group(1), 16)), s)
    return out if out != s else None


_CHAINS = {}
_SEGMENT = re.compile(r"[A-Za-z0-9]+")


_SEGMENT_PLAIN = {}


def _is_plain_segment(seg):
    """_plain_segment(seg, 0), remembered for the plain ones only (a dict that is asked a hundred thousand times for the same words)."""
    if not _plain_segment(seg, 0):
        return False
    if len(seg) <= 64:
        if len(_SEGMENT_PLAIN) >= 100000:
            _SEGMENT_PLAIN.clear()
        _SEGMENT_PLAIN[seg] = True
    return True


def _bad_runs(t, join):
    """Intervals of `t` that are not plain, judged on CHAINS: maximal sequences of alphanumeric segments joined only by `join` characters. A
    chain is bad when (A) its random-looking segments, adjacent ones taken together, add up to LMIN characters or more, or (B) it is LMIN
    characters or longer, holds 8 or more characters of letter-and-digit-mixed segments, and holds no word of five or more letters."""
    pattern = _CHAINS.get(join)
    if pattern is None:
        pattern = _CHAINS[join] = re.compile(r"[A-Za-z0-9]+(?:[%s]+[A-Za-z0-9]+)*" % "".join(re.escape(c) for c in join))
    plain = _SEGMENT_PLAIN
    if all(plain.get(seg) or _is_plain_segment(seg) for seg in _SEGMENT.findall(t)):
        return []                                       # no chain holds a random-looking segment, so none is bad (the same answer as the loop below, without building the chains)
    bad = []
    for found in pattern.finditer(t):
        if found.end() - found.start() < LMIN:
            continue                                    # a chain shorter than LMIN is neither a run of LMIN random characters nor a long mixed chain
        chain = [(m.start(), m.end()) for m in _SEGMENT.finditer(t, found.start(), found.end())]
        total = sum(b - a for a, b in chain)
        if total < LMIN:
            continue
        rnd = [not _plain_segment(t[a:b], 0) for a, b in chain]
        if not any(rnd):
            continue
        run = None
        for (a, b), r in zip(chain, rnd):
            if r:
                run = [a, b, b - a] if run is None else [run[0], b, run[2] + (b - a)]
            else:
                if run is not None and run[2] >= LMIN:
                    bad.append((run[0], run[1]))
                run = None
        if run is not None and run[2] >= LMIN:
            bad.append((run[0], run[1]))
        mixed = sum(b - a for a, b in chain if not _structure_ok(t[a:b]))
        if total >= LMIN and mixed >= 8 and not any(len(p) >= 5 and p.isalpha() and _pronounceable(p) for a, b in chain for p in _PIECE.findall(t[a:b])):
            bad.append((chain[0][0], chain[-1][1]))
    return bad


_CHARS = {}


def _chars_ok(comp, extra_ok):
    if comp.isascii():
        pattern = _CHARS.get(extra_ok)
        if pattern is None:
            pattern = _CHARS[extra_ok] = re.compile("[A-Za-z0-9%s]*" % re.escape(_NAME_SEPS + extra_ok))
        return pattern.fullmatch(comp) is not None
    return all(ch.isalnum() or ch in _NAME_SEPS or ch in extra_ok for ch in comp)


def _userinfo_shape(t):
    return ":" in t and "@" in t and t.index(":") < t.rindex("@")


def _plain_name(s, extra_ok=""):
    if not s or len(s) > 128:
        return False
    t = _prepare(s)
    if t is None or not _chars_ok(t, extra_ok) or _userinfo_shape(t) or _secret_in_ident(t) or _t10_hex_spans(t):
        return False
    u = _unpercent(s)
    if u is not None:
        pu = _prepare(u)
        if pu is None or _bad_runs(pu, _JOIN_NAME):
            return False
    return not _bad_runs(t, _JOIN_NAME)


def _merge(spans):
    merged = []
    for a, b in sorted(spans):
        if merged and a <= merged[-1][1]:
            merged[-1] = (merged[-1][0], max(merged[-1][1], b))
        else:
            merged.append((a, b))
    return merged


_SPLIT = re.compile(r"([\\/])")
_DRIVE = re.compile(r"[A-Za-z]:|\?|\.")


def _path_spans(s, extra_ok=_PATH_EXTRA):
    t = _prepare(s)
    if t is None:
        return [(0, len(s))]
    bad, pos = [], 0
    if len(t) <= 255 and "@" not in t and t.isascii() and _chars_ok(t, extra_ok + "\\/") and not _secret_in_ident(t):
        parts = ()                       # (every character is allowed, no part is long and none can hold a user-info shape: no part is bad)
    else:
        parts = _SPLIT.split(t)
    for part in parts:
        a, b = pos, pos + len(part)
        pos = b
        judged = part.lstrip(_CTRL)
        if part in ("\\", "/") or part == "" or _DRIVE.fullmatch(part):
            continue
        if len(part) - len(judged) > 1 or len(part) > 255 or not _chars_ok(judged, extra_ok) or _userinfo_shape(judged) or _secret_in_ident(judged):
            bad.append((a, b))
    bad += _bad_runs(t, _JOIN_PATH) + _t10_hex_spans(t)
    u = _unpercent(s)
    if u is not None:
        pu = _prepare(u)
        if pu is None or _bad_runs(pu, _JOIN_PATH):
            bad.append((0, len(s)))
    return _merge(bad)


def _replace_spans(s, spans, label, field):
    out, last = [], 0
    for a, b in spans:
        out.append(s[last:a])
        out.append(_b_withheld(s[a:b], label, field))
        last = b
    out.append(s[last:])
    return "".join(out)


def _show_name(s, field):
    return s if _plain_name(s) else _b_withheld(s, "not a plain name", field)


def _show_path(s, field, extra_ok=_PATH_EXTRA):
    return _replace_spans(s, _path_spans(s, extra_ok), "not a plain name", field)


def _show_key(s, field):
    return _show_path(s, field, _PATH_EXTRA + "*^<>")


_URL = re.compile(r"^((?:[A-Za-z][A-Za-z0-9+.-]*:)?//)(?:([^/?#]*)@)?([^/?#]*)([^?#]*)(?:\?([^#]*))?(?:#(.*))?$", re.S)


def _show_host(s, field):
    """A host name is on the deny-list: a random-looking label of a host is evidence (a C2 name), not a secret. Layer 2 reads it first: the deny-list
    would replace a random user of `user:password@host` and leave the context layer 2 needs."""
    return _deny_text(_layer2(s, field), field)


def _show_value(v):
    return v if re.fullmatch(r"[0-9]{1,12}|true|false|null|yes|no", v) or (v.isalpha() and len(v) <= 24 and _plain_name(v)) else None


def _show_url(s, field):
    m = _URL.match(s)
    if not m:
        return _show_path(s, field)
    scheme, userinfo, host, path, query, frag = m.groups()
    out = scheme
    if userinfo is not None:
        out += (userinfo if _MARK.fullmatch(userinfo) else _b_withheld(userinfo, "user-info", field)) + "@"
    hostname, colon, port = host.partition(":") if not host.startswith("[") else (host, "", "")
    out += _show_host(hostname, field) + (colon + (port if port.isdigit() else _b_withheld(port, "not a port", field)) if colon else "")
    out += _show_path(path, field)
    if query is not None:
        pairs = []
        for pair in query.split("&"):
            k, eq, v = pair.partition("=")
            kk = _show_name(k, field) if k else k
            if eq:
                sv = _show_value(v)
                pairs.append(kk + "=" + (sv if sv is not None else _b_withheld(v, "query value", field)))
            else:
                pairs.append(kk)
        out += "?" + "&".join(pairs)
    if frag is not None:
        sv = _show_value(frag)
        out += "#" + (sv if sv is not None else _b_withheld(frag, "fragment", field))
    return out


_TYPED = {
    "guid": re.compile(_GUID.pattern),
    "digest": re.compile(r"(?:sha256:|sha1:|md5:)?[0-9A-Fa-f]{32,128}|T1[0-9A-Fa-f]{60,72}|[0-9]{1,6}:[A-Za-z0-9+/]{3,}:[A-Za-z0-9+/]{3,}"),
    "sid": re.compile(_SID.pattern),
    "mac": re.compile(r"(?:[0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2}"),
    "ip": re.compile(r"[0-9]{1,3}(?:\.[0-9]{1,3}){3}|[0-9A-Fa-f:.]{2,45}(?:%[0-9A-Za-z_.-]{1,16})?"),
    "time": re.compile(r"[0-9]{4}-[0-9]{2}-[0-9]{2}(?:[T ][0-9:.]+(?:Z|[+-][0-9:]+)?)?|D:[0-9]{8,14}(?:[Zz+-][0-9']*)?|[0-9]{1,18}"),
    "number": re.compile(r"-?[0-9]{1,18}(?:\.[0-9]{1,18})?|0x[0-9A-Fa-f]{1,16}|(?:true|false|null)"),
    "version": re.compile(r"v?[0-9]+(?:\.[0-9A-Za-z]+){1,4}(?:[-+][0-9A-Za-z.]+)?"),
    # the identifiers of virtualized storage and machines: a VMFS volume id (8-8-4-12 hexadecimal digits), a SCSI device id (naa. with 16 or 32 digits, eui. and
    # wwn-0x with 16, vml. with 20 to 40, t10. with a vendor, a model and a serial), an iSCSI name, the VMware uuid of a machine (16 bytes, a `-` after the
    # eighth), the content id of a disk (8 digits) and the name Windows gives a machine nobody named (WIN- and 11 capitals and digits)
    "vmfs": re.compile(r"[0-9a-f]{8}-[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{12}"),
    "device": re.compile(r"naa\.(?:[0-9a-fA-F]{16}|[0-9a-fA-F]{32})|eui\.[0-9a-fA-F]{16}|wwn-0x[0-9a-fA-F]{16}|vml\.[0-9a-fA-F]{20,40}|t10\.[A-Za-z0-9_.+-]{8,120}"),
    "iqn": re.compile(r"iqn\.[0-9]{4}-[0-9]{2}\.[a-z0-9][a-z0-9.-]{0,60}(?::[A-Za-z0-9._-]{1,40})?"),
    "vmuuid": re.compile(r"[0-9a-f]{2}(?: [0-9a-f]{2}){7}-[0-9a-f]{2}(?: [0-9a-f]{2}){7}"),
    "cid": re.compile(r"[0-9a-f]{8}"),
    "winhost": re.compile(r"WIN-[A-Z0-9]{11}"),
}
_ID_FORMS = ("guid", "vmfs", "vmuuid", "device", "mac", "cid", "number")      # the forms a field of kind `id` may hold (the kind of a field that holds one of several forms of identifier), else it is judged as a name
_CONTENT_ID = re.compile(r"[0-9A-Fa-f]{32}")
_NAMING_IDS = frozenset(("device", "iqn"))          # the ids that hold a name a person chose (a t10. vendor, model and serial; an iSCSI name): what they hold must read as a name, not as random text
_KNOWN_KINDS = frozenset(("text", "name", "path", "key", "url", "host", "hex", "label", "id")) | frozenset(_TYPED)
_NUMBER_RUN = re.compile(r"[0-9]+")


def bind_fields(table, key_kinds=None):
    """The field kinds of a tool, passed in by the tool (this text holds none): `table` maps a JSON key to the kind of what it holds, or to a function of
    the key of one item for a dict whose items have kinds of their own; `key_kinds` maps a key holding a dict to the kind of that dict's own keys. A kind
    this text does not know is refused (a misspelt kind would judge the field as free text without a word)."""
    for name, kind in list(table.items()) + list((key_kinds or {}).items()):
        if not isinstance(name, str) or not (callable(kind) or kind in _KNOWN_KINDS):
            raise ValueError("a field kind this text does not know: %r" % (name,))
    FIELDS.update(table)
    KEY_KINDS.update(key_kinds or {})


def _field_entry(name):
    """What FIELDS says of the field `name`; a digit run in a name stands for any number (`ethernet0.address` is `ethernet#.address`)."""
    entry = FIELDS.get(name)
    if entry is None and name and any(c.isdigit() for c in name):
        entry = FIELDS.get(_NUMBER_RUN.sub("#", name))
    return entry


# ---- layer 2: position and prefix rules -------------------------------------------------------------------------------------------
# user-info whose password holds a `/` (RFC 3986 says to encode it; people do not): after `//`, a user, a `:`, then everything up to the last `@` that is
# followed by a host; not `host:8080/...@...` (a port), whose first word after the colon is a number
_URL_USERINFO_SLASH = re.compile(r"(?<=//)(?![^\s/@:<>\"'`]*:[0-9]{1,5}(?:[/?#@]|$))[^\s/@:<>\"'`]{1,64}:[^\s<>\"'`]{1,128}(?=@[^\s/@<>\"'`]*(?:[\s/<>\"'`?#]|$))")
# a user the deny-list already replaced: `<withheld ...>:password@host`
_MARK_USERINFO = re.compile(r"(?P<mark><withheld \d+ (?:characters|bytes)[^<>]{0,70}>|\[withheld: \d+ characters\]):(?P<pw>[^\s/<>\"'`]{1,128})(?=@[^\s/@<>\"'`]*(?:[\s/<>\"'`?#]|$))")
_B_USERINFO = re.compile(r"(?<![A-Za-z0-9._%+-])(?!mailto:)[^\s/@:<>\"'`]{1,64}:[^\s/<>\"'`]{1,128}(?=@[^\s/@<>\"'`]*(?:[\s/<>\"'`?#]|$))")
_URL_USERINFO = re.compile(r"(?<=//)[^/?#\s@]+(?=@)")
_NAMED_HEAD = r"(?i:(?<![Bb]y)(?<![Cc]om)(?<![Oo]ver)(?<![Uu]nder)(?<![Tt]res)(?<![Ee]ncom)(?<![Ss]ur)(?<![Ii]m)pass(?:word|wd|phrase)?|pwd|secret|token|api[_-]?key|access[_-]?key|account[_-]?key|private[_-]?key|client[_-]?secret|credential|auth(?:orization)?|(?<![A-Za-z])(?:pw|sig|sas|otp|psk))" r"s?[0-9]{0,2}[\"']?[ \t]{0,3}[=:][ \t]{0,3}[\"']?"
_NAMED = re.compile(_NAMED_HEAD + r"(?!line[ \t]+[0-9])" + r"(?P<value>(?:(?i:token|bearer|basic|negotiate)[ \t]+(?=[A-Za-z0-9+/._~=-]{8}))?(?:[^\s\"'<>;,&]|[;,&](?![A-Za-z0-9_. -]{1,40}=)){1,512})")
# a placeholder (<redacted>, <password>, <***>) is not a value, but what is glued behind it is
_PLACEHOLDER = r"<(?i:redacted|hidden|masked|removed|omitted|secret|password|passwd|passphrase|pwd|pass|token|key|value|placeholder|empty|none|null|unset|your[ _-]?(?:password|secret|token|key)|\*{1,16})?>"
_PH_END = r"(?=[\s\"';,&\\<>)\]}]|\.(?:\s|$)|$)"
# a value in angle brackets after a secret's name (password=<hJaXeuQz>): withheld unless it reads as a placeholder word
_ANGLE_SPLIT = re.compile(r"[-_.+/=~]")
_NAMED_ANGLE = re.compile(_NAMED_HEAD + r"(?!" + _PLACEHOLDER + r")(?P<value><(?P<inner>[A-Za-z0-9+/_.~=-]{6,128})>)")
_NAMED_PH = re.compile(_NAMED_HEAD + _PLACEHOLDER + r"(?P<value>[^\s\"'<>;,&\\]{1,512})")
# the name of a flag that takes a secret (`-password x`, `--token x`, `--api-key x`, `-auth x`): the words below, any word with `secret` in it or ending in `token`, `key` or
# (after a letter or a digit) Key, Token, Password, Pwd, Pass, Secret, also after up to four words joined by `-` or `_`; `--key-file x` and `--keyboard x` are not (the name ends where the value begins)
_FLAG_NAME = (r"(?:[A-Za-z0-9]{1,20}[-_]){0,4}(?:(?i:passw(?:or)?d|passwd|pass(?:[-_]?phrase)?|pwd|pw|otp|[A-Za-z0-9]{0,20}secret[A-Za-z0-9]{0,20}|[A-Za-z0-9]{0,20}token|api[-_]?key|access[-_]?key|key|keypass|storepass|userpass|auth|authorization|bearer|psk|credentials?|community)"
              r"|[A-Za-z0-9]{1,20}(?-i:Key|Token|Password|Passwd|Pwd|Pass|Passphrase|Secret))")
# a placeholder, a space and a value built like a secret: the placeholder is not the value, the word after it is
_PH_SPACE = re.compile(r"(?:" + _NAMED_HEAD + r"|(?<![\w-])--?" + _FLAG_NAME + r"[ \t]+|(?<![\w-])(?i:set|enable)[ \t]+(?i:passw(?:or)?d|secret|passphrase|token)[ \t]+)"
                       + _PLACEHOLDER + r"[ \t]+(?P<value>[A-Za-z0-9]{8,40})(?![A-Za-z0-9])")
_NAMED_FLAG = re.compile(r"(?<![\w-])--?" + _FLAG_NAME + r"(?:=|[ \t]+)(?!-)(?!" + _PLACEHOLDER + _PH_END + r")(?![\x5ca-zA-Z0-9_./~:-]{1,120}[.](?i:key|pem|pub|crt|p12|pfx|jks)(?![A-Za-z0-9]))(?!(?:~|[.]{1,2})/[A-Za-z0-9_./-]{1,120}|/[A-Za-z0-9_.-]{1,40}(?:/[A-Za-z0-9_.-]{1,40})+)(?P<value>[^\s\"']+)")
_NAMED_SET = re.compile(r"(?<![\w-])(?i:set|enable)[ \t]+(?i:passw(?:or)?d|secret|passphrase|token)[ \t]+(?:[0-9][ \t]+)?(?!" + _PLACEHOLDER + _PH_END + r")(?P<value>[^\s\"']+)")
# in a name or a path component: a secret's name and, glued or after a separator or a space, something that is not a word (password-Zq7kP2mR, Token Zq7kP2mR, pwdZq7kP2mR), or a flag with its value
# (-password x, d--pwd x): a name that holds one is a command line, not a name
_IDENT_FLAG = re.compile(r"(?<![A-Za-z0-9])--?" + _FLAG_NAME + r"[ \t]+(?!-)\S")
_SECRET_THEN = re.compile(r"(?:(?i:passw(?:or)?d|passphrase|pwd|secret|token|credential|api[_-]?key|private[_-]?key|access[_-]?key|account[_-]?key)|(?<=-)(?i:pass|auth|bearer|psk))"
                          r"(?=s?[ \t_.-]*['\"(\[]?([A-Za-z0-9]{1,40}))")
_SECRET_THEN_TEXT = re.compile(r"(?<![A-Za-z0-9])(?i:passw(?:or)?d|passphrase|pwd|secret|token|credential|api[_-]?key|private[_-]?key|access[_-]?key|account[_-]?key)s?[ \t_.-]{1,3}['\"(\[]?(?P<value>[A-Za-z0-9]{7,40})(?![A-Za-z0-9])")
_GLUED_FLAG = re.compile(r"(?<![A-Za-z0-9])--?(?:[A-Za-z0-9]{1,20}[-_]){0,4}(?i:key|token|pass|password|pwd|secret)(?P<value>[A-Za-z0-9]{8,40})(?![A-Za-z0-9])")
_FLAG_THEN = re.compile(r"(?<![A-Za-z0-9])--?" + _FLAG_NAME + r"(?=[ \t_.-]*['\"(\[]?([A-Za-z0-9]{1,40}))")
_ID_SECRET_WORDS = ("pass", "pwd", "secret", "token", "key", "cred", "auth", "bearer", "psk", "otp", "pw", "community")
_WORD_PARTS = re.compile(r"[A-Z]+(?![a-z])|[A-Z]?[a-z]+|[0-9]+")


_FIVE_CONSONANTS = re.compile(r"[^aeiouy]{5}")
_VEEAM_GLUE = re.compile(r"D(?:19|20)[0-9]{2}$")
_DATE8 = re.compile(r"(?:19|20)[0-9]{2}(?:0[1-9]|1[0-2])(?:0[1-9]|[12][0-9]|3[01])(?:[0-2][0-9][0-5][0-9][0-5][0-9])?")


def _value_like(tok):
    """Whether a run of letters and digits after a secret's name is built like a secret and not like words: 7 or more characters with a digit among them (not the one to four
    digits of a counter at the end), or only digits, or a run of capitals of other than two or three, or a word of lower case letters that is not pronounceable."""
    if len(tok) < 7:
        return False
    tok = _VEEAM_GLUE.sub("", tok)                       # (the D2024 that Veeam glues to a job name before its time stamp)
    if len(tok) < 7:
        return False
    if tok.isdigit():
        return _DATE8.fullmatch(tok) is None             # (a date, 20240312, with or without a time of day, is not a value)
    parts = _WORD_PARTS.findall(tok)
    if parts and parts[-1].isdigit():
        if len(parts[-1]) > 4:
            return True
        parts.pop()
    for n, part in enumerate(parts):
        if part.isdigit():
            return True
        if part.isupper():
            if not 2 <= len(part) <= 3:
                return True
        elif len(part) < 3 or (n > 0 and not part[0].isupper()) or not _word_letters(part):
            return True
    return False


_TECH_WORDS = re.compile("vmware|vcenter|vsphere|vsan|proxmox|nextcloud|splunk|openvpn|pfsense|opnsense|switch|postgres(?:ql)?|pgsql|mysql|mssql|sqlserver|rabbitmq|kafka|"
                         "upgrad(?:e|ed|es|ing)|updat(?:e|ed|es|ing)|workstation|helpdesk|cloudhsm|hyperv|xenserver|netapp|nutanix|veeam|commvault|cohesity|wsus|sccm|pgbouncer|mongodb|redis|"
                         "kubernetes|openshift|jumpbox|gitlab|github|jfrog|zabbix|ldaps?|radius|kerberos|tacacs|cifs|ntnx|qemu|esxi|smtp|sftp|dhcp|https?|iscsi|ntfs|sshd|nightly|monthly|fortnightly|midnight|lightweight|scratch|snmp|crowdstrike|etcd|vmfs|btrfs|openbsd")
_NAME_TOKEN = re.compile(r"[A-Za-z0-9]+")
_TAG = re.compile(r"(?:[a-z]{3,5}|[A-Z]{3,5}|[A-Z][a-z]{2,4})[0-9]{1,4}|[A-Z][0-9][A-Z][0-9]")
_DATE_STAMP = re.compile(r"D?(?:19|20)[0-9]{2}[-_.]?(?:0[1-9]|1[0-2])[-_.]?(?:0[1-9]|[12][0-9]|3[01])(?:[-_.T ]?[0-2][0-9][0-5][0-9][0-5][0-9])?(?:_[0-9A-Fa-f]{4}(?![0-9A-Za-z]))?")


def _word_letters(word):
    """Whether a run of letters reads as a word: every pair of letters is one that words hold (the names of products and services are taken out first), and there are no five consonants in a row."""
    low = _TECH_WORDS.sub("", word.lower())
    for k in range(len(low) - 1):
        if low[k:k + 2] not in _BIGRAMS:
            return False
    return _FIVE_CONSONANTS.search(low) is None


_FILE_EXTS = frozenset(("vmdk", "vmx", "vmsd", "vmsn", "vmem", "vmss", "nvram", "log", "qcow2", "qcow", "vhdx", "avhdx", "vhd", "vdi", "ovf", "ova", "json", "jsonl", "yaml", "conf", "cfg", "flat", "delta", "sesparse", "iso", "img", "raw", "bak", "tmp"))


def _groupish(tok):
    """A run of 4 or more letters and digits that is not a tag (srv01, db02 are tags): the part of a value written in groups (ab12-cd34-ef56)."""
    if len(tok) < 4 or _TAG.fullmatch(tok) is not None:
        return False
    if tok.isalpha() and tok.isupper():
        return _TECH_WORDS.fullmatch(tok.lower()) is None            # (capitals of 4 or more letters are not a word: KHIL, not ESXI)
    if tok.isalpha() and not tok[1:].islower():
        return True                                                  # (a word is not written with a capital in the middle: paUn)
    base = tok.rstrip("0123456789")
    return not (base.isalpha() and len(base) >= 4 and len(tok) - len(base) <= 4 and _word_letters(base))


def _words_value(text, start):
    """Whether any word after a secret's name, from `start` on, is a value: built like a secret by itself, or one of two or more groups in a row (ab12-cd34), which are one value written in parts."""
    tokens = _NAME_TOKEN.findall(_DATE_STAMP.sub(" ", text[start:start + 400]))
    group, run, seen = [], [], False
    for tok in tokens[:40]:
        if _value_like(tok):
            return True
        if tok.lower() in _FILE_EXTS:
            run, seen = [], False                                    # (the end of a file name is not a part of a value)
        elif 4 <= len(tok) <= 6:                                     # (a short word between two groups, or next to one, is part of the value: yIgK-paUn)
            run.append(tok)
            seen = seen or (_groupish(tok) and not tok.isdigit())
            if seen and len(run) >= 2 and _value_like("".join(run)):
                return True
        else:
            run, seen = [], False
        if len(tok) == 5 or len(tok) == 6:
            if tok.isdigit() and tok[0] != "0":
                return True              # 5 or 6 digits that do not start like a counter (000001)
        if _groupish(tok):
            group.append(tok)
            if len(group) >= 2 and _value_like("".join(group)):
                return True
        else:
            group = []
    return False


def _secret_in_ident(text):
    """Whether a name or a path component holds a secret's name with a value after it (see above). Linear: each pattern is anchored on a name and reads at most 400 characters after it."""
    if not _has(_ID_SECRET_WORDS, text.lower()):
        return False
    if _IDENT_FLAG.search(text) is not None or _NAMED_SET.search(text) is not None:
        return True
    for pattern in (_SECRET_THEN, _FLAG_THEN):
        m = pattern.search(text)
        if m is not None and _words_value(text, m.start(1)):
            return True
    return False
_PEM = re.compile(r"-----BEGIN [A-Z0-9 ]{0,40}PRIVATE KEY-----.*?(?:-----END [A-Z0-9 ]{0,40}PRIVATE KEY-----|$)", re.S)
_PREFIX = re.compile(r"(?i:(?:AKIA|ASIA)[0-9A-Z]{16}|gh[pousr]_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{20,}|xox[abeprs]-[A-Za-z0-9-]{10,}|glpat-[A-Za-z0-9_-]{20,}"
                     r"|(?:sk|rk|pk)_(?:live|test)_[A-Za-z0-9]{16,}|SG\.[A-Za-z0-9_-]{16,}\.[A-Za-z0-9_-]{16,}|AIza[0-9A-Za-z_-]{30,}|npm_[A-Za-z0-9]{30,}"
                     r"|dop_v1_[0-9a-f]{40,}|ya29\.[0-9A-Za-z_-]{30,})|sk-(?=[A-Za-z0-9_-]{0,39}[0-9])[A-Za-z0-9_-]{20,}|eyJ[A-Za-z0-9_-]{8,300}\.[A-Za-z0-9_-]{8,}(?:\.[A-Za-z0-9_-]*)?")
_BASE64_PADDED = re.compile(r"(?<![A-Za-z0-9+/])[A-Za-z0-9+/]{16,}={1,2}(?![A-Za-z0-9+=])")
_LONG_DIGITS = re.compile(r"(?<![0-9])[0-9]{19,}(?![0-9])")


_BASE64_PADDED_PATH = re.compile(r"[A-Za-z0-9+/]{22,90}={1,2}(?![A-Za-z0-9+=])")           # (bounded: a long run of these characters costs a step for each of the 90 before a start, not the rest of the run)


def _padded_in_path(field):
    """A padded base64 key that stands behind a `/` (a path ends in the key, or the key's own `/` cut it): the last 22 characters before two pads, 27 before one, are withheld."""
    def sub(m):
        body = m.group().rstrip("=")
        pad = len(m.group()) - len(body)
        keep = len(body) - (22 if pad == 2 else 27)
        if keep < 0:
            return m.group()
        tail = body[keep:]
        if "/" not in tail or len({"d" if c.isdigit() else "u" if c.isupper() else "l" for c in tail if c.isalnum()}) < 2 or not _b64_shape(tail + "=" * pad):
            return m.group()
        return body[:keep] + _b_withheld(tail + "=" * pad, "token-shaped text", field)
    return sub


def _b64_shape(run):
    """Whether a padded run can be base64 of random bytes: its length with the padding is a multiple of 4, and it holds a digit, `+` or `/` (a long
    identifier before an `=` in a line of text, RelatedActivityID=, is not one)."""
    return len(run) % 4 == 0 and re.search(r"[0-9+/]", run) is not None


_NAMED_WORDS = ("pass", "pwd", "secret", "token", "key", "credential", "auth")
_PREFIX_HINTS = ("akia", "asia", "ghp_", "gho_", "ghu_", "ghs_", "ghr_", "github_pat_", "xox", "glpat-", "_live_", "_test_", "sg.", "aiza", "npm_", "dop_v1_",
                 "ya29.", "sk-", "eyj")


def _layer2_once(s, field):
    # each rule is tried only when the text holds what it needs (a character or a word it cannot match without): the same result, a lot less reading
    if "withheld" in s:
        s = _MARK_USERINFO.sub(lambda m: m.group("mark") + ":" + _b_withheld(m.group("pw"), "user-info", field), s)
    if "-----" in s:
        s = _outside(s, _MARK, lambda p: _PEM.sub(lambda m: _b_withheld(m.group(), "private key", field), p))
    if "@" in s:
        s = _outside(s, _MARK, lambda p: _URL_USERINFO_SLASH.sub(lambda m: _b_withheld(m.group(), "user-info", field), p))
        s = _outside(s, _MARK, lambda p: _URL_USERINFO.sub(lambda m: _b_withheld(m.group(), "user-info", field), p))
        s = _outside(s, _MARK, lambda p: _B_USERINFO.sub(lambda m: _b_withheld(m.group(), "user-info", field), p))
    low = s.lower()
    if _has(_NAMED_WORDS, low):
        s = _outside(s, _MARK, lambda p: _NAMED.sub(lambda m: m.group()[:m.start("value") - m.start()] + _b_withheld(m.group("value"), "secret value", field), p))
        if "<" in s:
            s = _outside(s, _MARK, lambda p: _PH_SPACE.sub(lambda m: m.group()[:m.start("value") - m.start()] + (_b_withheld(m.group("value"), "secret value", field) if _value_like(m.group("value")) else m.group("value")), p))
            s = _outside(s, _MARK, lambda p: _NAMED_ANGLE.sub(lambda m: m.group()[:m.start("value") - m.start()] + (_b_withheld(m.group("value"), "secret value", field) if any(_value_like(x) for x in _ANGLE_SPLIT.split(m.group("inner"))) else m.group("value")), p))
            s = _outside(s, _MARK, lambda p: _NAMED_PH.sub(lambda m: m.group()[:m.start("value") - m.start()] + _b_withheld(m.group("value"), "secret value", field), p))
    if _has(("pass", "pwd", "secret", "token", "credential", "key"), low):
        s = _outside(s, _MARK, lambda p: _SECRET_THEN_TEXT.sub(lambda m: m.group()[:m.start("value") - m.start()] + (_b_withheld(m.group("value"), "secret value", field) if _value_like(m.group("value")) else m.group("value")), p))
        if "-" in s:
            s = _outside(s, _MARK, lambda p: _GLUED_FLAG.sub(lambda m: m.group()[:m.start("value") - m.start()] + (_b_withheld(m.group("value"), "secret value", field) if _value_like(m.group("value")) else m.group("value")), p))
    if "-" in s or "set" in low or "enable" in low:
        s = _outside(s, _MARK, lambda p: _NAMED_FLAG.sub(lambda m: m.group()[:m.start("value") - m.start()] + _b_withheld(m.group("value"), "secret value", field), p))
        s = _outside(s, _MARK, lambda p: _NAMED_SET.sub(lambda m: m.group()[:m.start("value") - m.start()] + _b_withheld(m.group("value"), "secret value", field), p))
    if "=" in s:
        s = _outside(s, _MARK, lambda p: _BASE64_PADDED.sub(lambda m: _b_withheld(m.group(), "token-shaped text", field) if _b64_shape(m.group()) else m.group(), p))
        if "/" in s:
            s = _outside(s, _MARK, lambda p: _BASE64_PADDED_PATH.sub(_padded_in_path(field), p))
    s = _outside(s, _MARK, lambda p: _LONG_DIGITS.sub(lambda m: _b_withheld(m.group(), "long number", field), p))
    low = s.lower()
    if _has(_PREFIX_HINTS, low):
        s = _outside(s, _MARK, lambda p: _PREFIX.sub(lambda m: _b_withheld(m.group(), "token-shaped text", field), p))
    if "t10." in s or "iqn." in s:
        spans = _t10_hex_spans(s)
        if spans:
            s = _replace_spans(s, _merge(spans), "token-shaped text", field)
    return s


def _outside(text, pattern, fn):
    """`fn` applied to the parts of `text` that `pattern` does not match; the matches are kept as they are."""
    if "withheld" not in text:
        return fn(text)
    out, last = [], 0
    for m in pattern.finditer(text):
        out.append(fn(text[last:m.start()]) if m.start() > last else "")
        out.append(m.group())
        last = m.end()
    out.append(fn(text[last:]) if last < len(text) else "")
    return "".join(out)


def _layer2(s, field):
    out = s
    for _ in range(3):
        nxt = _layer2_once(out, field)
        if nxt == out:
            break
        out = nxt
    return out


# ---- free text: the deny-list ------------------------------------------------------------------------------------------------------
_LABELLED_DIGEST = re.compile(r"(?i)(?:md5|sha-?1|sha-?256|sha-?384|sha-?512|imphash|hashes?|filehash|ssdeep|tlsh)[\"'=:> \t]{1,6}(?:(?:md5|sha-?1|sha-?256|imphash)=)?([0-9a-f]{32,128})")
_TIME = re.compile(r"[0-9]{4}-[0-9]{2}-[0-9]{2}[T ][0-9]{2}:[0-9]{2}:[0-9]{2}(?:[.,][0-9]{1,9})?(?:Z|[+-][0-9]{2}:?[0-9]{2})?")
_HEX_RUN = re.compile(r"(?<![0-9A-Za-z])[0-9A-Fa-f]{32,}(?![0-9A-Za-z])")


def _mask_typed(s):
    """A same-length copy of free text in which what is a typed id (GUID, SID, IPv4, time, labelled digest) is `~`."""
    t = s
    if "-" in s:
        t = _GUID.sub(lambda m: "~" * len(m.group()), t)
        if "S-1-" in s:
            t = _SID.sub(lambda m: "~" * len(m.group()), t)
        if ":" in s:
            t = _TIME.sub(lambda m: "~" * len(m.group()), t)
    if "." in s:
        t = _IPV4.sub(lambda m: "~" * len(m.group()), t)
    low = s.lower()
    if _has(_KNOWN_ID_WORDS, low):
        t = _KNOWN_ID.sub(lambda m: "~" * len(m.group()), t)
    if "ash" in low or "md5" in low or "sha" in low:
        t = _LABELLED_DIGEST.sub(lambda m: m.group().replace(m.group(1), "~" * len(m.group(1))), t)
    return t


def _deny_text(s, field):
    t = _mask_typed(s)
    t = t.replace("\x00", " ")
    spans = _bad_runs(t, _JOIN_PATH)
    spans += [m.span() for m in _HEX_RUN.finditer(t)]
    return _replace_spans(s, _merge(spans), "token-shaped text", field) if spans else s


# ---- the entry point for one string ---------------------------------------------------------------------------------------------------
_MEMO = {}


_WIDE_RUN = re.compile(r"[\x20-\x7e\uff01-\uff5e]{4,}")


def _wide_views(raw):
    """Runs of ASCII and full-width ASCII in `raw` read as UTF-8 and as UTF-16LE (at both byte offsets), when it holds a full-width character at
    all: width is folded afterwards (NFKC), so a full-width token written as hexadecimal is read like a plain one."""
    views = []
    if b"\xef\xbc" in raw or b"\xef\xbd" in raw:
        views += _WIDE_RUN.findall(raw.decode("utf-8", "replace"))
    if b"\xff" in raw:
        for offset in (0, 1):
            views += _WIDE_RUN.findall(raw[offset:len(raw) - (len(raw) - offset) % 2].decode("utf-16-le", "replace"))
    return [unicodedata.normalize("NFKC", v) for v in views]


def _hex_views(s):
    """The printable views of binary data written as hex: Latin-1 runs of 6 or more, UTF-16LE and UTF-16BE runs of 4 or more, and the runs that hold
    full-width characters (UTF-8 and UTF-16LE), width folded."""
    try:
        raw = bytes.fromhex(s[: MAX_HEX_JUDGED])
    except ValueError:
        return None
    views = [m.group().decode("latin-1") for m in re.finditer(rb"[\x20-\x7e]{6,}", raw)]
    views += [m.group().decode("utf-16-le", "replace") for m in re.finditer(rb"(?:[\x20-\x7e]\x00){4,}", raw)]
    views += [m.group().decode("utf-16-be", "replace") for m in re.finditer(rb"(?:\x00[\x20-\x7e]){4,}", raw)]
    return views + _wide_views(raw)


def _show_hex(s, field):
    if not s or not re.fullmatch(r"(?:[0-9A-Fa-f]{2})+", s):
        return s if re.fullmatch(r"[0-9A-Fa-f]*", s) else _show_text(s, field)
    if len(s) > MAX_HEX_JUDGED:
        return _b_withheld(s, "binary data over the judged size", field)
    for v in _hex_views(s) or ():
        if _layer2(v, "") != v or _deny_text(v, "") != v or _suspect(v):
            return _b_withheld(s, "binary data holding a secret-shaped text", field)
    return s


def _show_text(s, field):
    # layer 2 reads the string as the evidence wrote it: the deny-list replaces a span and takes with it the context (`user:` of `user:pw@host`, the
    # characters glued before `glpat-`) the position and prefix rules need; what it leaves is read once more
    out = _layer2(s, field)
    denied = _deny_text(out, field)
    return _layer2(denied, field) if denied != out else out


def _show(s, kind, field):
    if s in OWN_NAMES or _MARK.fullmatch(s):
        return s
    if len(s) > MAX_ONE_STRING:
        return _show(s[:MAX_ONE_STRING], kind, field) + _b_withheld(s[MAX_ONE_STRING:], "rest of a long string", field)
    if kind == "id":
        if len(s) <= 3 or _CONTENT_ID.fullmatch(s):
            return s
        for form in _ID_FORMS:
            if _TYPED[form].fullmatch(s) and not (form in _NAMING_IDS and s[:4] in ("t10.", "iqn.") and _bad_runs(s, _JOIN_NAME)):
                return s
        kind = "name"
    if kind in _TYPED:
        if len(s) <= 3 or (_TYPED[kind].fullmatch(s) and not (kind in _NAMING_IDS and s[:4] in ("t10.", "iqn.") and _bad_runs(s, _JOIN_NAME))):
            return s
        return _b_withheld(s, "not a %s" % kind, field)
    if kind == "hex":
        return _show_hex(s, field)
    flat = _flat(s)
    if flat != s:
        # an invisible character, or the escape of one: identifiers fail closed; free text is judged without it
        if kind in ("name", "path", "key", "url"):
            return _b_withheld(s, "invisible characters in a name", field)
        sealed = _show_text(flat, field)
        return sealed if sealed != flat else s
    if kind not in ("name", "path", "key", "url", "host"):
        return _show_text(s, field)
    pre = _layer2(s, field)
    if kind == "name":
        base = _show_name(pre, field)
    elif kind == "path":
        base = _show_path(pre, field)
    elif kind == "key":
        base = _show_key(pre, field)
    elif kind == "url":
        base = _show_url(pre, field)
    else:
        base = _show_host(pre, field)
    return _layer2(base, field) if base != pre else base


def show(s, kind="text", field=""):
    """The text the answer may show for the string `s` of a field of type `kind` (a T carries its own)."""
    if not isinstance(s, str) or not s:
        return s
    kind = getattr(s, "kind", kind)
    memo = (kind, field, s) if len(s) <= 512 and kind not in _TYPED else None            # (a typed id is judged by one match: it is not worth a place in the memo)
    quiet = _QUIET[0]
    if memo is not None:
        hit = _MEMO.get(memo)
        if hit is not None:
            out, pending = hit
            if pending and not quiet:
                # judged earlier only to see what would be printed: it is withheld, counted and written to the values file now that it is printed (once)
                for original, label, where in pending:
                    _b_withheld(original, label, where)
                _MEMO[memo] = (out, None)
            return out
    events = _EVENTS[0] = [] if quiet and memo is not None else None
    try:
        out = _show(str(s), kind, field)
    finally:
        _EVENTS[0] = None
    if memo is not None:
        if len(_MEMO) > 40000:
            _MEMO.clear()
        _MEMO[memo] = (out, events or None)
    return out


_ORDER_SALT = os.urandom(16)


def _quietly(fn):
    """`fn()` with nothing counted, listed or written: judging a string to see what an answer would show of it is not withholding it."""
    saved = (BOUNDARY["withheld"], BOUNDARY["by"].copy(), BOUNDARY["replaced"], BOUNDARY["replaced_by"].copy(), BOUNDARY["where"][:], BOUNDARY["not_listed"], _VALUES["fh"])
    _VALUES["fh"] = None
    was, _QUIET[0] = _QUIET[0], True
    try:
        return fn()
    finally:
        _QUIET[0] = was
        (BOUNDARY["withheld"], BOUNDARY["by"], BOUNDARY["replaced"], BOUNDARY["replaced_by"], BOUNDARY["where"], BOUNDARY["not_listed"], _VALUES["fh"]) = saved


def sealed_text(text, kind="text", field=""):
    """The exact text an answer prints for the string `text` of a field of type `kind`: the layers, then the backstop (a string it replaces comes
    out as its placeholder). Nothing is counted, listed or written to the values file: this is for what must see what the answer shows (a
    `contains` filter, the order of a list). It runs under the clock of the seal and counts toward the cap of characters (_timed, _late): a string
    it does not judge comes out as its placeholder, and is counted."""
    if not isinstance(text, str) or not text:
        return text
    return _quietly(lambda: _timed(lambda: _seal(text, kind, field, (), True)))


def print_order(items, kind="name", text=str):
    """`items` in the order an answer prints them: by the text the answer PRINTS for each (the layers and the backstop, sealed_text), and the items
    whose text is the same placeholder in a random order that is new for every run. The rank of the withheld texts themselves (the order `sorted`
    would give, the order a directory or a hive lists them in) must never show in what an answer lists. `kind` is the kind of the field the items
    are printed in; `text` gives the string of an item. The judging runs under the clock of the seal (SEAL_BUDGET from the outermost call, never past
    the seal stop) and counts toward the cap of characters, as the judging of an answer does: once either stops it (a list of 13,000 names of 64 KiB
    ran for minutes without a clock), the items not judged come after the judged ones in a random order of their own, each is counted
    (_STOP["quiet"]), and the answer is partial (boundary.stopped_by)."""
    def judge():
        out, rest = [], []
        for n, i in enumerate(items):
            raw = text(i)
            rank = hashlib.blake2b(_ORDER_SALT + str(raw).encode("utf-8", "surrogatepass"), digest_size=8).digest()
            if not rest:
                if not isinstance(raw, str) or not raw:
                    out.append((raw, rank, n, i))
                    continue
                left = _STOP["quiet"]
                shown = _seal(raw, kind, "", (), True)
                if _STOP["quiet"] == left:
                    out.append((shown, rank, n, i))
                    continue
            rest.append((rank, n, i))                 # (the first of them was counted when judging stopped on it; the rest are counted below)
        _STOP["quiet"] += max(len(rest) - 1, 0)
        return out, rest
    items = list(items)
    keyed, rest = _quietly(lambda: _timed(judge))
    keyed.sort(key=lambda k: (k[0], k[1], k[2]))
    rest.sort()
    return [k[3] for k in keyed] + [r[2] for r in rest]


def contains_check(needle_lower, text, kind="text", field=""):
    """(matched, blind) for a `contains` filter: the needle is looked for in the text the answer will PRINT for `text` (sealed_text: after the layers
    AND the backstop), never in what either of them withheld or replaced, so that a count of matches cannot tell a true guess of a hidden piece from
    a wrong one. `blind` is true when it was not found and that text holds a placeholder: the needle may be in what is hidden. It is the same
    whatever the needle, so counting it opens no way to test a guess."""
    sealed = sealed_text(text, kind, field)
    if needle_lower in sealed.lower():
        return True, False
    return False, _MARK.search(sealed) is not None


# ---- layer 3: the backstop, written apart from the layers above ------------------------------------------------------------------------
_S_ESC = re.compile(r"(?<!\\)\\+(?:u([0-9a-fA-F]{4})|U([0-9a-fA-F]{8})|[uU]\{([0-9a-fA-F]{1,8})\}|x([0-9a-fA-F]{2}))")
_S_FILL = "\u115f\u1160\u3164\uffa0\u2800"


def _s_gone(c):
    cat = unicodedata.category(c)
    return cat[0] == "C" or cat in ("Mn", "Me", "Zl", "Zp") or c in _S_FILL


def _s_unesc(m):
    try:
        c = chr(int(m.group(1) or m.group(2) or m.group(3) or m.group(4), 16))
    except (ValueError, OverflowError):
        return m.group(0)
    return "" if _s_gone(c) else m.group(0)


def _s_normal(text):
    if "\\u" in text or "\\U" in text or "\\x" in text:
        text = _S_ESC.sub(_s_unesc, text)
    if text.isascii() and text.isprintable():
        return text
    kept = [c for c in text if not _s_gone(c)]
    return unicodedata.normalize("NFKC", "".join(kept))


_S_PEM = re.compile(r"-----BEGIN [A-Z0-9 ]{0,40}PRIVATE KEY|PRIVATE KEY-----")
_S_DELIM = re.compile(r"[=:]")
_S_NAME_WORDS = ("pass", "pw", "auth", "sig", "sas", "secret", "token", "credential", "key", "psk", "otp", "bearer", "community", "dsn", "pin", "connection_string", "webhook_url")        # a name that ends in a word of _S_STRONG or _S_WEAK holds one of these
_S_FLAGWORD = (r"(?:[a-z0-9]{1,20}[-_]){0,4}(?:passw(?:or)?d|passwd|pass(?:[-_]?phrase)?|pwd|pw|otp|[a-z0-9]{0,20}secret[a-z0-9]{0,20}|[a-z0-9]{0,20}token|api[-_]?key|access[-_]?key|key|keypass|storepass|userpass|auth|authorization|bearer|psk|credentials?|community)")
_S_FLAGCAMEL = r"[A-Za-z0-9]{1,20}(?-i:Key|Token|Password|Passwd|Pwd|Pass|Passphrase|Secret)"
_S_NOVALUE = r"(?!<[^<>\s]{0,40}>(?:[\s;,]|$))(?![A-Za-z0-9_./~:-]{1,120}[.](?i:key|pem|pub|crt|p12|pfx|jks)(?![A-Za-z0-9]))(?!(?:~|[.]{1,2})/[A-Za-z0-9_./-]{1,120}|/[A-Za-z0-9_.-]{1,40}(?:/[A-Za-z0-9_.-]{1,40})+)"
_S_ARGNAME = re.compile(r"(?<![A-Za-z0-9])--?(?i:" + _S_FLAGWORD + r")[= ]" + _S_NOVALUE + r"\S|(?<![A-Za-z0-9])--?" + _S_FLAGCAMEL + r"[= ]" + _S_NOVALUE + r"\S")
_S_PREFIX_WORDS = ("akia", "asia", "agpa", "aida", "aroa", "anpa", "anva", "aipa", "ghp_", "gho_", "ghu_", "ghs_", "ghr_", "github_pat_", "glpat-", "xox", "xapp-",
                   "sk_live_", "rk_live_", "pk_live_", "sk_test_", "npm_", "pypi-", "shpat_", "dop_v1_", "aiza", "ya29.", "sg.", "sk-", "eyj")
_S_LINE = re.compile(r"[ \t]*line[ \t]+[0-9]")
_S_NAME_CHARS = frozenset("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_.-")
_S_STRONG = ("password", "passwd", "passphrase", "passw", "pwd", "secret", "token", "credential", "apikey", "api_key", "api-key", "accesskey", "access_key", "access-key",
             "accountkey", "account_key", "account-key", "privatekey", "private_key", "private-key", "masterkey", "master_key", "sharedkey", "shared_key", "signingkey", "encryptionkey",
             "secretkey", "secret_key", "secret-key")
_S_WEAK = ("pass", "pw", "auth", "sig", "sas")
_S_NOT_PASS = ("bypass", "compass", "overpass", "underpass", "trespass", "encompass", "surpass", "impass")
_S_STRONG_ENDS = tuple(w + p for w in _S_STRONG for p in ("", "s"))       # a name that ends in one of these, or in one of them plural
_S_WEAK_ENDS = tuple(w + p for w in _S_WEAK for p in ("", "s"))
_S_NOT_PASS_ENDS = tuple(w + p for w in _S_NOT_PASS for p in ("", "s"))
_S_VALUEY_ENDS = ("psk", "otp", "bearer", "authorization", "sshkey", "ssh_key", "ssh-key", "snmp_community", "pass_word", "pass-word", "connection_string", "webhook_url", "dsn", "pin")        # names after which only a value built like a secret counts (a log line says `authorization: failed`)
_S_DIGITS = re.compile(r"[0-9]{19}")
_S_HEXRUN = re.compile(r"(?<![0-9A-Za-z])[0-9A-Fa-f]{40,}(?![0-9A-Za-z])")
_S_B64NOPAD = re.compile(r"[A-Za-z0-9+/]{20,}")
_S_B64PADPATH = re.compile(r"[A-Za-z0-9+/]{22,90}={1,2}(?![A-Za-z0-9+=])")
_S_B64PAD = re.compile(r"(?<![A-Za-z0-9+/])[A-Za-z0-9+/]{15,}={1,2}(?![A-Za-z0-9+=])")
# in any case where an upper-case spelling of a lower-case prefix is a likely leak (the vendors' prefixes with a body of 12 or more characters)
_S_PREFIX = re.compile(r"(?:AKIA|ASIA|AGPA|AIDA|AROA|ANPA|ANVA|AIPA)[A-Z0-9]{12}|(?i:(?<![A-Za-z0-9])(?:akia|asia)[a-z0-9]{12}|(?:gh[pousr]_|github_pat_|glpat-|xox[a-z]-|xapp-|sk_live_|rk_live_|pk_live_|sk_test_)[A-Za-z0-9_-]{12})"
                       r"|(?:npm_|pypi-|shpat_|dop_v1_|AIza|ya29\.|SG\.)[A-Za-z0-9_-]{12}|sk-(?=[A-Za-z0-9_-]{0,39}[0-9])[A-Za-z0-9_-]{12}|eyJ[A-Za-z0-9_-]{12}")
_S_TOKEN_CHARS = frozenset("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_.-")
_S_PWHOST = re.compile(r"(?<![A-Za-z0-9._%+-])([A-Za-z0-9]{12,64})@[^\s/@<>\"']")
_S_USERINFO = re.compile(r"[^\s/@:<>\"']{1,64}:(?P<pw>[^\s/<>\"']{1,128})@[^\s/@<>\"']")
_S_USERINFO_MARK = re.compile(r"<>:(?P<pw>[^\s/<>\"']{1,128})@[^\s/@<>\"']")
_S_USERINFO_URL = re.compile(r"(?<=//)(?![^\s/@:<>\"']*:[0-9]{1,5}(?:[/?#@]|$))[^\s/@:<>\"']{1,64}:(?P<pw>[^\s<>\"']{1,128})@[^\s/@<>\"']")
_S_VALUE = re.compile(r"(?:[^\s\"'<>;,&]|[;,&](?![A-Za-z0-9_. -]{1,40}=)){1,512}")
_S_ARGVAL = re.compile(r"(?<![A-Za-z0-9])--?(?:(?i:" + _S_FLAGWORD + r")|" + _S_FLAGCAMEL + r")[= ]" + _S_NOVALUE + r"(\S{1,512})")
# `set password x` and `enable secret x`, and a value glued behind a placeholder (password=<redacted>x, --password <redacted>x, token: <secret>x)
_S_PH_SPACE = re.compile(r"(?:pass|pwd|secret|token|credential|key|auth|psk|otp|pw|sig|sas)[a-z]{0,10}[0-9]{0,2}[\"']?[ \t]{0,2}(?:[=:]|[ \t])[ \t]{0,2}<[^<>\s]{0,40}>[ \t]+([A-Za-z0-9]{8,40})(?![A-Za-z0-9])", re.I)
_S_GLUED = re.compile(r"(?<![A-Za-z0-9])--?(?:[A-Za-z0-9]{1,20}[-_]){0,4}(?:(?i:key|token|pass|password|pwd|secret)|[A-Za-z]{1,20}(?:Key|Token|Pass|Password|Pwd|Secret))([A-Za-z0-9]{8,40})(?![A-Za-z0-9])")
_S_AUTHZ = re.compile(r"(?i:authorization)[\"']?[ \t]{0,2}[=:][ \t]{0,2}[\"']?(?i:token|bearer|basic|negotiate)[ \t]+[A-Za-z0-9+/._~=-]{8,}")
_S_T10TAIL = re.compile(r"t10[.][A-Za-z0-9_.+-]{0,100}?_([A-Za-z]{20,64})(?![A-Za-z0-9])|iqn[.][0-9]{4}-[0-9]{2}[.][a-z0-9.-]{1,60}:([A-Za-z]{20,64})(?![A-Za-z0-9])|iqn[.][0-9]{4}-[0-9]{2}[.]([A-Za-z]{20,64})(?![A-Za-z0-9])")
_S_SET = re.compile(r"(?<![\w-])(?:set|enable)[ \t]+(?:passw(?:or)?d|secret|passphrase|token)[ \t]+(?:[0-9][ \t]+)?[^\s<]", re.I)
_S_ANGLE = re.compile(r"(?:pass|pwd|secret|token|credential|key|auth|psk|otp|pw|sig|sas)[a-z]{0,10}[0-9]{0,2}[\"']?[ \t]{0,2}(?:[=:]|[ \t])[ \t]{0,2}<([A-Za-z0-9+/_.~=-]{6,128})>", re.I)
_S_PH_GLUED = re.compile(r"(?:pass|pwd|secret|token|credential|key|auth|psk|otp|pw|sig|sas)[a-z]{0,10}[0-9]{0,2}[\"']?[ \t]{0,2}(?:[=:]|[ \t])[ \t]{0,2}<[^<>\s]{0,40}>[^\s<>;,&\"']", re.I)
_S_PEMLINE = re.compile(r"[A-Za-z0-9+/=]{12,}")
_S_SHORTRUN = re.compile(r"[A-Za-z0-9]{16,19}")
_S_RUN = re.compile(r"[A-Za-z0-9+/_-]{20,}")
_S_HEX = re.compile(r"[0-9A-Fa-f-]+")
_S_IDS = re.compile(r"\{?[0-9A-Fa-f]{8}-(?:[0-9A-Fa-f]{4}-){3}[0-9A-Fa-f]{12}\}?|[0-9A-Fa-f]{8}-[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12}|S-1-[0-9]{1,2}(?:-[0-9]{1,10}){1,15}|[0-9]{4}-[0-9]{2}-[0-9]{2}[T ][0-9:.]+Z?")
_S_MARK = re.compile(r"<withheld [0-9]{1,10} (?:characters|bytes)(?:: [a-z][a-z ,/+-]{0,60}(?:: [a-z][a-z ,/+-]{0,60})?)?>|\[withheld: [0-9]{1,10} (?:characters|bytes)\]")
_S_DIGEST_LABEL = re.compile(r"(?i)(?:md5|sha-?1|sha-?256|sha-?384|sha-?512|imphash|hashes?|filehash|ssdeep|tlsh)[\"'=:> \t]{1,6}(?:(?:md5|sha-?1|sha-?256|imphash)=)?[0-9a-f]{32,128}")
_TYPED_KINDS = frozenset(("guid", "digest", "sid", "mac", "ip", "time", "number", "version", "hex", "label", "vmfs", "device", "iqn", "vmuuid", "cid", "winhost"))
# what a typed field may hold, by the characters of its type (apart from the grammar the first layer checks, and wider than it)
_S_TYPED = {
    "guid": re.compile(r"[0-9A-Fa-f{}-]{1,64}"), "sid": re.compile(r"[Ss0-9-]{1,400}"), "mac": re.compile(r"[0-9A-Fa-f:-]{1,64}"),
    "ip": re.compile(r"[0-9A-Fa-f:.]{1,64}(?:%[0-9A-Za-z_.-]{1,16})?"), "time": re.compile(r"[0-9TtZzDd:.,+' -]{1,64}"),
    "number": re.compile(r"-?[0-9.]{1,64}|0[xX][0-9A-Fa-f]{1,16}|true|false|null"), "version": re.compile(r"(?=.{1,64}\Z)[vV]?[0-9]+(?:\.[0-9A-Za-z]{1,16}){0,6}(?:[-+][0-9A-Za-z.]{1,32}){0,3}"),
    "digest": re.compile(r"(?:sha256:|sha1:|md5:)?[0-9A-Fa-f]{16,128}|T1[0-9A-Fa-f]{16,80}|[0-9]{1,6}:[A-Za-z0-9+/]+:[A-Za-z0-9+/]+"),
    "vmfs": re.compile(r"[0-9A-Fa-f-]{1,40}"), "cid": re.compile(r"[0-9A-Fa-f]{1,16}"), "vmuuid": re.compile(r"[0-9A-Fa-f -]{1,64}"),
    "winhost": re.compile(r"[Ww][Ii][Nn]-[A-Za-z0-9]{1,16}"), "iqn": re.compile(r"iqn\.[0-9A-Za-z.:_-]{1,120}"),
    "device": re.compile(r"(?:naa|eui|vml|t10)\.[A-Za-z0-9_.+-]{1,130}|wwn-0x[0-9A-Fa-f]{1,32}"),
}
_S_LONG = re.compile(r"[A-Za-z0-9+/_-]{19}")           # the shortest run any check below needs (19 digits); the hexadecimal run needs 40, the others 20
_S_PLAIN_NUM = re.compile(r"[0-9TZ:.+ -]+")
_S_HEXONLY = re.compile(r"(?:[0-9A-Fa-f]{2})+")
_S_PRINT_L1 = re.compile(rb"[\x20-\x7e]{6,}")
_S_PRINT_U16 = re.compile(rb"(?:[\x20-\x7e]\x00){4,}")
_S_PRINT_U16BE = re.compile(rb"(?:\x00[\x20-\x7e]){4,}")


def _class(c):
    return 0 if c.isdigit() else 1 if c.isupper() else 2


def _random_run(run, shortest=20):
    if _S_HEX.fullmatch(run):
        return False
    pieces = [p for p in re.split(r"[/_+-]", run) if p]
    alnum = "".join(pieces)
    if len(alnum) < shortest or max(len(p) for p in pieces) < 12:
        return False
    kinds = {_class(c) for c in alnum}
    if len(kinds) < 2:
        return False
    lower = [len(r) for r in re.findall(r"[a-z]+", alnum)]
    if lower and sum(lower) >= 3 * len(lower) and not re.search(r"[A-Z]{2}", alnum):
        return False
    changes = sum(1 for a, b in zip(alnum, alnum[1:]) if _class(a) != _class(b)) / (len(alnum) - 1)
    digit_runs = len(re.findall(r"[0-9]+", alnum))
    if kinds == {0, 1, 2}:
        return changes >= 0.42 or (changes >= 0.3 and digit_runs >= 4 and len(set(alnum)) >= 0.6 * len(alnum))
    if kinds == {1, 2}:
        return changes >= 0.5 and len(alnum) >= 24
    return changes >= 0.4 and digit_runs >= 5 and len(set(alnum)) >= 0.5 * len(alnum)


def _s_letters_random(word):
    """Letters of one case that no word is made of: some pair of them is one that words do not hold (the second check's own test of the serial of a t10. id and the target of an iqn. name)."""
    if not (word.islower() or word.isupper()):
        return False
    low = word.lower()
    return any(low[k:k + 2] not in _BIGRAMS for k in range(len(low) - 1))


def _s_valuey(tok):
    """Whether a run after a placeholder is built like a secret (the second check's own test): a digit among letters that is not a counter at the end, 8 or more digits, or letters with a pair no word holds."""
    body = tok.rstrip("0123456789")
    if not body:
        return len(tok) >= 8
    if len(tok) - len(body) > 4 or any(c.isdigit() for c in body):
        return True
    low = body.lower()
    return any(low[k:k + 2] not in _BIGRAMS for k in range(len(low) - 1)) or re.search("[^aeiouy]{4}", low) is not None


def _s_named(flat, values=None):
    """Whether `flat` holds a value after a secret's name; with a list, the values themselves are added to it (until it holds MAX_PIECES)."""
    pos, found = 0, False
    while True:
        m = _S_DELIM.search(flat, pos)
        if not m or (values is not None and len(values) >= MAX_PIECES):
            return found
        i = m.start()
        pos = m.end()
        after = flat[i + 1:i + 6].lstrip(" \t\"'\\")
        if not after or after[0] in "<>" or _S_LINE.match(flat, i + 1):
            continue
        j = i
        while j > 0 and flat[j - 1] in " \t\"'\\" and i - j < 5:
            j -= 1
        k = j
        while k > 0 and j - k < 64 and flat[k - 1] in _S_NAME_CHARS:
            k -= 1
        low = flat[k:j].lower()
        if low.endswith(_S_STRONG_ENDS) or (low.endswith(_S_WEAK_ENDS) and not low.endswith(_S_NOT_PASS_ENDS)):
            if values is None:
                return True
            found = True
            v = i + 1
            while v < len(flat) and flat[v] in " \t\"'\\" and v - i <= 6:
                v += 1
            vm = _S_VALUE.match(flat, v)
            if vm:
                values.append(vm.group())
        elif low.rstrip("0123456789").endswith(_S_VALUEY_ENDS) or low.rstrip("0123456789").endswith(_S_STRONG_ENDS):
            v = i + 1
            while v < len(flat) and flat[v] in " \t\"'\\" and v - i <= 6:
                v += 1
            vm = _S_VALUE.match(flat, v)
            if vm and _s_valuey(vm.group()):
                if values is None:
                    return True
                found = True
                values.append(vm.group())


def _s_hex_views(text):
    """The printable text inside data written as hexadecimal (Latin-1 runs of 6 or more, UTF-16LE and UTF-16BE runs of 4 or more), or None when `text` is not such data."""
    if len(text) < 2 or not _S_HEXONLY.fullmatch(text[:MAX_HEX_JUDGED]):
        return None
    try:
        raw = bytes.fromhex(text[:MAX_HEX_JUDGED])
    except ValueError:
        return None
    return ([m.group().decode("latin-1") for m in _S_PRINT_L1.finditer(raw)] + [m.group().decode("utf-16-le", "replace") for m in _S_PRINT_U16.finditer(raw)]
            + [m.group().decode("utf-16-be", "replace") for m in _S_PRINT_U16BE.finditer(raw)] + _wide_views(raw))


def _suspect(text, kind="text"):
    """The name of the check a string fails, or None. A string of a typed kind is not tested for runs of hexadecimal digits or random-looking runs, but
    for the characters of its type; data written as hexadecimal is decoded and its printable text is tested as text."""
    if not text or text in OWN_NAMES:
        return None
    if len(text) > MAX_ONE_STRING:
        text = text[:MAX_ONE_STRING]
    if kind == "hex":
        views = _s_hex_views(text)
        if views is not None:
            for view in views:
                hit = _suspect(view, "text")
                if hit:
                    return "in binary data: " + hit
            return None
        kind = "text"
    if kind in _S_TYPED and len(text) <= 64 and _S_PLAIN_NUM.fullmatch(text):
        # digits, `. : + -`, a space, T and Z: no rule above the typed grammar can fire on these (no name, no prefix, no `@`), so the grammar alone decides
        return None if len(text) <= 3 or _S_TYPED[kind].fullmatch(text) else "not the typed grammar"
    flat = _s_normal(text)
    if "withheld" in flat:
        flat = _S_MARK.sub("<>", flat)
    low = flat.lower()
    if "private key" in low and _S_PEM.search(flat):
        return "a PEM marker"
    bare = _S_IDS.sub(" ", flat) if "-" in flat else flat            # (all three kinds of id hold a `-`)
    bare = _mask_embedded(bare)
    named_words = _has(_S_NAME_WORDS, low)
    if named_words and _S_AUTHZ.search(flat):
        return "a named secret"
    if (named_words and ("=" in bare or ":" in bare) and _s_named(bare)) or ("-" in flat and named_words and _S_ARGNAME.search(flat))             or (named_words and "-" in flat and any(_s_valuey(m.group(1)) for m in _S_GLUED.finditer(flat)))             or (named_words and ("<" in flat and (_S_PH_GLUED.search(flat) or any(_s_valuey(x) for m in _S_ANGLE.finditer(flat) for x in _ANGLE_SPLIT.split(m.group(1))) or any(_s_valuey(m.group(1)) for m in _S_PH_SPACE.finditer(flat))) or ("set" in low or "enable" in low) and _S_SET.search(flat))):
        return "a named secret"
    if _has(_S_PREFIX_WORDS, low) and _S_PREFIX.search(flat):
        return "a token prefix"
    if ("t10." in flat or "iqn." in flat) and any(_s_letters_random(m.group(1) or m.group(2) or m.group(3)) for m in _S_T10TAIL.finditer(flat)):
        return "a random-looking run"
    if "@" in flat:
        flat_user = re.sub("(?i)mailto:", "mailto ", flat)
        if _S_USERINFO.search(flat_user) or _S_USERINFO_URL.search(flat_user) or _S_USERINFO_MARK.search(flat_user):       # (the last: a user that was replaced is still a user)
            return "user-info"
        for m in _S_PWHOST.finditer(flat_user):
            word = m.group(1)
            if len({_class(c) for c in word}) == 3 and sum(1 for a, b2 in zip(word, word[1:]) if _class(a) != _class(b2)) >= 0.3 * len(word):
                return "user-info"            # (the password of a user-info whose user was cut off at a colon: a long run of capitals, small letters and digits before the host)
    if kind in _TYPED_KINDS:
        grammar = _S_TYPED.get(kind)
        return "not the typed grammar" if grammar is not None and len(text) > 3 and not grammar.fullmatch(text) else None
    if 16 <= len(bare) <= 19 and _S_SHORTRUN.fullmatch(bare) and _random_run(bare, 16):
        return "a random-looking run"          # (a whole value of 16 to 19 characters: the length of a generated password, as the first layer takes it too)
    if "=" not in bare and not _S_LONG.search(bare):
        return None                       # no run of 19 characters of these, and no `=` for a padded run: none of the checks below can find anything
    if _S_DIGITS.search(bare):
        return "a long digit run"
    labelled = _S_DIGEST_LABEL.sub(" ", bare) if "ash" in low or "sha" in low or "md5" in low else bare
    if _S_HEXRUN.search(labelled):
        return "a long hexadecimal run"
    for m in _S_B64NOPAD.finditer(labelled):
        if "/" in m.group() and "+" in m.group() and len({_class(c) for c in m.group() if c.isalnum()}) == 3:
            return "a base64 run with / and +"
    for m in _S_B64PAD.finditer(labelled):
        body = m.group().rstrip("=")
        if len(m.group()) % 4 == 0 and re.search(r"[0-9+/]", body) and len({_class(c) for c in body}) >= 2 and (("/" in body or "+" in body) or len(body) >= 20):
            return "a padded base64 run"
    if "=" in labelled:
        for m in _S_B64PADPATH.finditer(labelled):
            # a padded key behind the `/` of a path (inputs/Zk0khEa1Ge/Do3O4Hd43iH==): the key is the last 22 (two pads) or 27 (one pad) characters before the padding
            pad = len(m.group()) - len(m.group().rstrip("="))
            tail = m.group().rstrip("=")[-(22 if pad == 2 else 27):]
            if len(tail) >= 22 and "/" in tail and len({_class(c) for c in tail if c.isalnum()}) >= 2:
                return "a padded base64 run"
    for m in _S_RUN.finditer(labelled):
        if _random_run(m.group()):
            return "a random-looking run"
    return None


def _where_text(where, names=True):
    return "/" + "/".join((w[0][:60] if names else str(w[1])) for w in where)


def _replace(value, where, check, positions=False):
    BOUNDARY["replaced"] += 1
    BOUNDARY["replaced_by"][check] += 1
    if len(BOUNDARY["where"]) < MAX_WHERE:
        # the place is the keys on the way, each of them already sealed; their joining is read once more, and when it is not clean the place is the
        # positions (a key that was replaced or withheld must never come back whole through the report of where something was replaced)
        at = _where_text(where, False) if positions else _where_text(where)
        if not positions and _suspect(at, "label"):
            at = _where_text(where, False)
        BOUNDARY["where"].append({"at": at, "check": check})
    else:
        BOUNDARY["not_listed"] += 1
    return _mark(len(value.encode("utf-8", "replace")), "backstop: %s" % check, "bytes")


_CHECKED = {}
_SHORT_PLAIN = re.compile(r"[A-Za-z0-9_.]{0,15}")      # what the late path may print unjudged: 15 characters or fewer of letters, digits, `_` and `.` (no space, no `-`, so no
                                                          # argument after a flag and no `xox?-` token), and not starting like a vendor token (_unjudged)


def _unjudged(text, kind=None):
    """Whether a string may be printed past the judging time: a name this run made itself (OWN_NAMES: its schema keys, its file names), or a short plain
    string that does not start like one of the vendor tokens the block knows (a prefix and 12 characters are 15) and, in a field of a typed kind (a SID, a
    GUID, a digest ...), fits the grammar of that type as the backstop checks it."""
    if text in OWN_NAMES:
        return True
    if _SHORT_PLAIN.fullmatch(text) is None or text.lower().startswith(_S_PREFIX_WORDS):
        return False
    grammar = _S_TYPED.get(kind)
    return grammar is None or len(text) <= 3 or grammar.fullmatch(text) is not None


def _late(n=0):
    """Whether judging must stop for the string about to be judged, which has `n` characters (counted against the cap of the run, also when the string is
    only being judged to see what an answer would print: an order or a filter costs what an answer does). It says why, once, in _STOP["by"]: the cap of
    characters, or the clock of the seal."""
    if n:
        _STOP["chars"] += n
        if _STOP["chars"] > _STOP["cap"]:
            if _STOP["by"] is None:
                _STOP["by"] = "the cap of %d characters judged in one run" % MAX_JUDGED_CHARS
            return True
    deadline = _CLOCK["deadline"]
    if deadline is not None and time.monotonic() > deadline:
        if _STOP["by"] is None:
            _STOP["by"] = "the judging time (the budget of one answer or row, or the seal stop of the tool)"
        return True
    return False


def _stopped(value, where):
    """A string not judged because judging stopped: withheld whole, by its size, counted (what is let through is only _unjudged). One judged only to see
    what an answer would print (an order, a filter) is counted apart: the answer may still print it, judged then."""
    _STOP["quiet" if _QUIET[0] else "strings"] += 1
    return _replace(value, where, "the judging time ran out", True)


def seal_stop_after(seconds):
    """The seal stop of a tool: no seal runs on past `seconds` from now (its manifest's time limit less 3.5 seconds); what is left is withheld whole,
    except what _unjudged lets through. It stops the judging only, not the tool's own work: that has its own clock, which must run out first."""
    _CLOCK["stop"] = time.monotonic() + seconds


def _timed(fn):
    """`fn()` with the clock of the seal running: SEAL_BUDGET seconds from the outermost call, and never past the seal stop of the tool."""
    first = _CLOCK["deadline"] is None
    if first:
        _CLOCK["deadline"] = time.monotonic() + SEAL_BUDGET
        if _CLOCK["stop"] is not None:
            _CLOCK["deadline"] = min(_CLOCK["deadline"], _CLOCK["stop"])
    try:
        return fn()
    finally:
        if first:
            _CLOCK["deadline"] = None


# the name of a component of the Windows component store (WinSxS), as a whole name or as a component of a key or a path: architecture, words (lower case, letters up
# to 40 or letters and digits up to 16, with `.`, `-` or `_` between them, never a hexadecimal hash), the 16-digit public key token, a four-part version (not always
# there), a language or `none`, and a hash of 8 to 16 hexadecimal digits; a placeholder that layer 1 put in the place of a word, or of the architecture and a word (a
# 32-digit hash), stands for it. A real SOFTWARE hive lists them by the thousand and the backstop took their hash for a random run, so it judges the text with such a
# component taken out; layer 1 judges them as it does every name. Names, keys and paths only, lower case only; every alternative starts with a different character,
# so that a failing match is not retried in a second way.
_WORD = r"(?:[a-z]{1,40}|(?=[a-z0-9]*[0-9])[a-z0-9]{1,16}|<withheld [0-9]{1,10} (?:characters|bytes): not a plain name>)"
_WINSXS = re.compile(r"(?<![^\\/])(?:(?:amd64|x86|wow64|msil|arm64|arm|ia64)_(?![0-9a-f]+_)%s(?:[._-]{1,3}%s){0,12}|<withheld [0-9]{1,10} (?:characters|bytes): not a plain name>)"
                     r"_[0-9a-f]{16}(?:_[0-9]{1,5}(?:\.[0-9]{1,5}){3})?_[a-z0-9-]{2,12}_[0-9a-f]{8,16}(?![^\\/])" % (_WORD, _WORD))


def _without_components(text, kind):
    """`text` as the backstop judges a name, key or path: a component of the component store is one plain word."""
    return _WINSXS.sub("w", text) if kind in ("name", "key", "path") and text.count("_") >= 3 else text


def _verdict(text, kind):
    memo = (kind, text) if len(text) <= 512 and kind not in _S_TYPED else None
    hit = _CHECKED.get(memo, False) if memo else False
    if hit is False:
        hit = None if _MARK.fullmatch(text) else _suspect(_without_components(text, kind), kind)
        if memo:
            if len(_CHECKED) >= 30000:
                _CHECKED.clear()
            _CHECKED[memo] = hit
    return hit


# ---- the backstop reads the original too: what of a secret-shaped text is still in what was shown
def _pem_pieces(flat, found):
    """The base64 lines of the bodies of PEM keys: after each `PRIVATE KEY-----` (found with str.find, at most MAX_PIECES of them) up to the next
    `-----END` or MAX_PEM_BODY characters."""
    pos, bodies = 0, 0
    while bodies < MAX_PIECES and len(found) < MAX_PIECES:
        i = flat.find("PRIVATE KEY-----", pos)
        if i < 0:
            return
        start = i + 16
        end = flat.find("-----END", start, start + MAX_PEM_BODY)
        stop = start + MAX_PEM_BODY if end < 0 else end
        bodies += 1
        for m in _S_PEMLINE.finditer(flat, start, stop):
            found.append(m.group())
            if len(found) >= MAX_PIECES:
                return
        pos = max(stop, start)


def _s_pieces(flat, kind):
    """The parts of `flat` (the original text, normalised) the backstop's own rules call secret: a value after a secret's name, the password of
    user-info, a vendor token, a key's base64, and (outside typed fields) the long random-looking runs. At most MAX_PIECES of them, in this
    order; every walk over the text stops when the list is full."""
    found = []
    bare = _S_IDS.sub(" ", flat)
    _s_named(bare, found)
    for pattern, group in ((_S_ARGVAL, 1), (_S_USERINFO, "pw"), (_S_USERINFO_URL, "pw")):
        for m in pattern.finditer(flat):
            if len(found) >= MAX_PIECES:
                return found
            found.append(m.group(group))
    for m in _S_PREFIX.finditer(flat):
        if len(found) >= MAX_PIECES:
            return found
        end = m.end()
        stop = min(len(flat), end + 512)
        while end < stop and flat[end] in _S_TOKEN_CHARS:
            end += 1
        found.append(flat[m.start():end])
    _pem_pieces(flat, found)
    if kind not in _TYPED_KINDS:
        labelled = _S_DIGEST_LABEL.sub(" ", bare) if "ash" in bare or "sha" in bare.lower() or "md5" in bare.lower() or "ASH" in bare else bare
        for m in _S_B64PAD.finditer(labelled):
            if len(found) >= MAX_PIECES:
                return found
            if _b64_shape(m.group()):
                found.append(m.group())
        for m in _S_HEXRUN.finditer(labelled):
            if len(found) >= MAX_PIECES:
                return found
            found.append(m.group())
        for m in _S_B64NOPAD.finditer(labelled):
            if len(found) >= MAX_PIECES:
                return found
            if "/" in m.group() and "+" in m.group():
                found.append(m.group())
        for m in _S_RUN.finditer(labelled):
            if len(found) >= MAX_PIECES:
                return found
            if _random_run(m.group()):
                found.append(m.group())
    return found


_RESIDUE = {}


def _residue_worthy(win):
    """Whether a window of a piece is a secret's and not the words of a path the piece ran into (a run of base64 characters takes in `/vmfs/volumes/ds1/` before a key): a window with a `/` needs 3 capitals, digits or `+`."""
    return "/" not in win or sum(1 for c in win if c.isupper() or c.isdigit() or c == "+") >= 3


def _residue(original, shown, kind):
    """A window of 12 characters (the whole piece when it is shorter, from 8) of something the backstop calls secret in the ORIGINAL that is still
    in what was shown: the layers above cut spans out of a string and can leave a piece of a secret between two cuts."""
    memo = (kind, original) if len(original) <= 512 else None
    if memo is not None and memo in _RESIDUE:
        return _RESIDUE[memo]
    verdict = None
    flat = _s_normal(original[:MAX_ONE_STRING])
    pieces = _s_pieces(flat, kind)[:MAX_PIECES]
    if pieces:
        kept = _S_MARK.sub("\x00", _s_normal(shown[:MAX_ONE_STRING]))
        rest = flat                                    # the original without those parts: a window that is also here is the text's own words, not the secret
        for piece in sorted(set(pieces), key=len, reverse=True):
            rest = rest.replace(piece, "\x00")
        for piece in pieces:
            n = len(piece)
            if n < 8:
                continue
            w = min(12, n)
            step = 1 if n * len(kept) <= 4000000 else max(1, (n - w + 1) // 64)       # a long piece in a long string: 64 windows, spread over it
            if any(piece[i:i + w] in kept and piece[i:i + w] not in rest and _residue_worthy(piece[i:i + w]) for i in range(0, n - w + 1, step)):
                verdict = "a part of a secret-shaped text"
                break
    if memo is not None:
        if len(_RESIDUE) >= 30000:
            _RESIDUE.clear()
        _RESIDUE[memo] = verdict
    return verdict


# ---- the walker ----------------------------------------------------------------------------------------------------------------------------
_SCALARS = (bool, int, float)
_SCALAR_TYPES = frozenset(_SCALARS)


_KEYS = {}


def _seal(value, kind, field, where, guard, fname=""):
    """`value` with every string sealed by the type of its field, and (guard) read back by the backstop. Keys are names. FIELDS maps a JSON key to the
    kind of what it holds, or to a function of the key of one item for a dict whose items have kinds of their own (event data, registry values).
    `where` is the tuple of (sealed key or position, position) on the way down."""
    if isinstance(value, str):
        k = getattr(value, "kind", kind)
        if _late(len(value)):
            # past the budget the rest is withheld whole, fail closed; what is let through is only a name of this run's own and a short plain string (_unjudged)
            return value if _unjudged(value, k) else _stopped(value, where)
        out = show(value, k, field)
        if guard:
            check = _verdict(out, k)
            if not check and out != value:
                check = _residue(str(value), out, k)
            if check:
                return _replace(out, where, check)
        return out
    if value is None or isinstance(value, _SCALARS):
        return value
    if isinstance(value, dict):
        hook = _field_entry(fname)
        hook = hook if callable(hook) else None
        kk = KEY_KINDS.get(fname, "name")
        out, dupes = {}, {}
        for idx, (key, v) in enumerate(value.items()):
            if isinstance(key, str):
                if _late(len(key)):
                    sk = key if _unjudged(key) else _stopped(key, where + (("(key)", idx),))
                else:
                    sk = _KEYS.get((kk, field, key, guard))
                    if sk is None:
                        sk = show(key, kk, field)
                        if guard:
                            check = _verdict(sk, kk)
                            if check:
                                sk = _replace(sk, where + (("(key)", idx),), check)
                        if sk == key and len(key) <= 128:
                            # a key that comes out as it went in changed nothing (no count, no list): its judging is not repeated for the next row
                            if len(_KEYS) >= 20000:
                                _KEYS.clear()
                            _KEYS[(kk, field, key, guard)] = sk
            elif key is None or isinstance(key, _SCALARS):
                sk = key
            else:
                key = str(key)
                sk = show(key, "name", field)
            if sk in out:
                # many names become one placeholder: the next free " #n" of that placeholder, counted (a probe from the first would be quadratic)
                n = dupes.get(sk, 1)
                while True:
                    n += 1
                    renamed = "%s #%d" % (sk, n)
                    if renamed not in out:
                        break
                dupes[sk] = n
                sk = renamed
            if v is None or type(v) in _SCALAR_TYPES:
                out[sk] = v                               # (a number, a truth value or nothing: there is no string to seal)
                continue
            fk = key if isinstance(key, str) else ""
            sub_kind = (hook(key) if hook else None) or _kind_of(fk, kind)
            label = sk if isinstance(sk, str) else str(sk)
            out[sk] = _seal(v, sub_kind, (field + "." + fk) if field and fk else (fk or field), where + ((label, idx),), guard, fk)
        return out
    if isinstance(value, (list, tuple)):
        return [_seal(v, kind, field, where + ((str(i), i),), guard, fname) for i, v in enumerate(value)]
    return _seal(str(value), "text", field, where, guard, fname)       # anything else the serialiser would have printed with str()


def _kind_of(field, inherited):
    k = _field_entry(field)
    return k if isinstance(k, str) else inherited


def seal(value, kind="text", field=""):
    return _timed(lambda: _seal(value, kind, field, (), True))


_ROW_TYPES = frozenset((str, int, float, bool))
_ROW = [None, None]             # the last row of plain scalars that was sealed without anything being replaced, and what it came out as


def row_object(row):
    """A row of a paging file, sealed and read back: what the file may hold. A tool that writes the same row to two files (every key listed, and
    the nodes of a walk) has it judged once: the second is the first's result, the same judging with nothing to count or list."""
    key = None
    if isinstance(row, dict):
        for k, v in row.items():
            if type(k) is not str or (v is not None and type(v) not in _ROW_TYPES):
                break
        else:
            # (the type is part of the key: 1, True and 1.0 are equal and print differently; a float by its repr, as -0.0 equals 0.0)
            key = tuple((k, type(v), repr(v) if type(v) is float else v) for k, v in row.items())
    if key is not None and _ROW[0] == key:
        return dict(_ROW[1])
    replaced = BOUNDARY["replaced"]
    out = _timed(lambda: _seal(row, "text", "", (), True))
    if key is not None and BOUNDARY["replaced"] == replaced:
        _ROW[0], _ROW[1] = key, dict(out)
    return out


def boundary_summary():
    stopped = {"stopped_by": _STOP["by"], "strings_withheld_by_the_stop": _STOP["strings"],
               "strings_not_judged_for_order_or_filter": _STOP["quiet"]} if _STOP["by"] is not None else {}
    return {"strings_withheld": BOUNDARY["withheld"], "withheld_by_reason": dict(BOUNDARY["by"]),
            "strings_replaced_by_the_backstop": BOUNDARY["replaced"], "replaced_by_check": dict(BOUNDARY["replaced_by"]),
            "replaced_at": list(BOUNDARY["where"]), "replaced_not_listed": BOUNDARY["not_listed"], "values": values_summary(), **stopped,
            "note": "every key and value of this answer and of its paging files was judged by the type of its field: a name, path, key or URL is shown only when it "
                    "fits a plain grammar (a path component by component), free text has token-shaped runs, user-info and the value after a secret's name withheld, "
                    "and a second check written apart from both read it back. A withheld text is <withheld N characters: reason>. Not recognised: a secret that does "
                    "not look like one (a plain password or passphrase, a UUID-shaped key, anything under 16 characters in a name)."}


def _last_look(obj):
    """What this block adds to an answer after the walker (the report of what it did) is read once more by the backstop, keys and values."""
    if isinstance(obj, str):
        return _mark(len(obj), "backstop: a part of a secret-shaped text") if _suspect(obj, "label") else obj
    if isinstance(obj, dict):
        return {_last_look(k): _last_look(v) for k, v in obj.items()}
    if isinstance(obj, list):
        return [_last_look(v) for v in obj]
    return obj


def answer_object(doc):
    """The answer (or an error answer), sealed and read back. A string the backstop had to replace makes a complete answer partial."""
    _STOP["cap"] = max(_STOP["cap"], _STOP["chars"]) + FINAL_GRACE_CHARS            # (the final answer is always judged: the cap of the run does not take it)
    out = _timed(lambda: _seal(doc, "text", "", (), True))
    if isinstance(out, dict):
        out["boundary"] = _last_look(boundary_summary())
        if (BOUNDARY["replaced"] > 0 or _STOP["by"] is not None) and out.get("status") == "complete":
            out["status"] = "partial"
            basis = out.get("status_basis")
            why = []
            # a string withheld unjudged because judging stopped held nothing that was seen: the stop says it, not this count
            shaped = BOUNDARY["replaced"] - BOUNDARY["replaced_by"].get("the judging time ran out", 0)
            if shaped > 0:
                why.append("%d string(s) still held a secret-shaped text when the answer was checked on its way out and were replaced" % shaped)
            if _STOP["by"] is not None:
                why.append("judging the strings stopped at %s: %d string(s) after it were withheld by their size%s" % (
                    _STOP["by"], _STOP["strings"], "" if not _STOP["quiet"] else ", and %d were put in order or filtered without being judged (an order "
                    "of their own, a filter blind to them)" % _STOP["quiet"]))
            out["status_basis"] = "%s%s (see boundary)" % (basis + "; " if isinstance(basis, str) and basis else "", "; ".join(why))
    return out


def emit(doc, **dumps_kwargs):
    """Print an answer through the boundary (the only way an answer leaves a tool that carries this block)."""
    hold_stop_signals()
    obj = answer_object(doc)
    try:
        text = json.dumps(obj, ensure_ascii=False, default=str, **dumps_kwargs)
        text.encode("utf-8")
    except UnicodeEncodeError:
        text = json.dumps(obj, ensure_ascii=True, default=str, **dumps_kwargs)
    try:
        # a signal that arrives while the answer is being written must not start a second one: signals are held from here (the answer is whole)
        signal.pthread_sigmask(signal.SIG_BLOCK, {signal.SIGTERM, signal.SIGINT, signal.SIGHUP})
    except (AttributeError, ValueError, OSError):
        pass
    print(text, flush=True)
# END SHARED BOUNDARY


class SealedPage(NoReplacePage):
    """A page whose rows are written through the boundary."""

    def _write(self, row):
        super()._write(row_object(row))

    def finish(self):
        result = super().finish()
        if result.get("all_results"):
            OWN_NAMES.add(result["all_results"])             # the name of a result file is this tool's own: the answer keeps it readable past the judging time
        return result


try:
    from regipy.registry import RegistryHive
except ImportError:
    emit({
        "error": "regipy is not installed", "status": "failed", "status_basis": "the tool could not start: a library it needs is missing",
        "hint": "python3 -m pip install --user regipy; scripts/toolbox.sh reports it as regipy-dump",
    })
    raise SystemExit(1)


# The keys the answers and the result files of this tool are made of: names the tool wrote itself (regenerate from the literal keys of the answer when a key is added).
# They are shown as they are even past the judging time, so that an answer stays readable; a name from the evidence that is one of them holds no secret.
OWN_NAMES.update((
    "all_problems", "all_results", "all_results_format", "bam", "control_set", "contains_applied", "contains_blind_records", "cross_check", "current_control_set",
    "dam", "data_length", "entry_data_note", "entry_position", "error", "filtered_out", "focus_count", "focus_time_ms", "guid", "hint", "hive", "hive_dirty",
    "hive_sequence_numbers", "hive_type", "insert_flags", "interpretation_limits", "key", "last_execution", "last_execution_filetime", "last_modified",
    "last_modified_filetime", "layout", "layout_basis", "library_messages_withheld", "matched", "metadata_values_not_listed", "name_decoded", "name_raw",
    "not_attempted", "not_run", "parser", "path", "present", "problem_count", "problems", "problems_not_listed", "raw_hex", "raw_length", "raw_not_shown", "reason",
    "record_count", "records", "records_by_source", "result", "returned", "run_count", "session_id", "shim_flags", "shimcache", "sid", "sid_applied",
    "sid_basis", "signal", "source", "sources", "status", "status_basis", "transaction_logs_beside_hive", "transaction_logs_looked_for", "transaction_logs_replayed", "truncated", "unsupported",
    "unsupported_count", "userassist", "value_type", "walk_stopped_by_time_limit", "what", "where", "looked_for"
))


# What the boundary is told about the fields of this tool's answers: the type of what a key holds. A key that is not listed holds free text.
FIELDS.update({
    "hive": "path", "key": "key", "guid": "name", "control_set": "name", "name_raw": "path", "name_decoded": "path", "path": "path", "sid": "sid",
    "all_results": "path", "all_problems": "path", "transaction_logs_beside_hive": "path", "transaction_logs_looked_for": "path", "value_type": "name", "source": "name", "layout": "name",
    "last_execution": "time", "last_execution_filetime": "number", "last_modified": "time", "last_modified_filetime": "number",
    "run_count": "number", "focus_count": "number", "focus_time_ms": "number", "session_id": "number", "data_length": "number", "raw_length": "number",
    "entry_position": "number", "insert_flags": "number", "shim_flags": "number", "hive_type": "name",
})

# What every answer says about how far a record can be read (the words of this tool: the same in every answer, and kept readable past the judging time).
LIMITS = (
    "Presence of a record is not execution: UserAssist, BAM, DAM and ShimCache record that the system noted a program, and each has its own conditions for noting one.",
    "A ShimCache time is the last-modified time of the file as the cache recorded it, not a time the program ran; the order of the entries is the cache's own.",
    "A user whose hive was not collected is not a user with no entry: a record exists only for the hive read, and an absent record is not proof that nothing ran.",
    "The layout of each record is chosen from the length of its value and from tags inside it, as the published notes describe; the offsets are not verified against a real hive, and a layout that does not fit is returned as unsupported with its bytes.",
    "The hive is read as it is on disk: transaction logs are not replayed, so a dirty hive may hold newer state in its logs.",
)
OWN_NAMES.update(LIMITS)

UA_PATH = ("Software", "Microsoft", "Windows", "CurrentVersion", "Explorer", "UserAssist")
BAM_PATHS = (("bam", ("Services", "bam", "State", "UserSettings")), ("bam", ("Services", "bam", "UserSettings")),
             ("dam", ("Services", "dam", "State", "UserSettings")), ("dam", ("Services", "dam", "UserSettings")))
SHIM_PATHS = (("Control", "Session Manager", "AppCompatCache"), ("Control", "Session Manager", "AppCompatibility"))
SOURCES = ("userassist", "bam", "shimcache")
CONTROL_SET = re.compile(r"^ControlSet[0-9]{3}$", re.I)
SID_SHAPE = re.compile(r"^S-1-[0-9]{1,10}(-[0-9]{1,10}){1,15}$", re.I)
MAX_RAW_HEX_BYTES = 1 << 19        # a value longer than this is counted, not written out as hexadecimal (the boundary judges at most 1 MiB of hexadecimal)
FILETIME_EPOCH = datetime.datetime(1601, 1, 1, tzinfo=datetime.timezone.utc)
ROT13 = str.maketrans("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz", "NOPQRSTUVWXYZABCDEFGHIJKLMnopqrstuvwxyzabcdefghijklm")

import random

DEADLINE_SECONDS = 84             # the manifest allows 90; the seal stop (86.5) is 2.5 seconds later
PARSER = "userassist_bam_shimcache/4"


LOG_SUFFIXES = (".LOG1", ".LOG2", ".LOG")


def hive_state(h, hive_path):
    """Whether the hive file is dirty (its two sequence numbers differ: a write was not finished in the file, and the newest state is in the
    transaction logs), the log files the tool looked for beside it and the ones that are there. The logs are never replayed by this tool."""
    header = h.header
    looked = [hive_path + s for s in LOG_SUFFIXES]
    return {"hive_dirty": header.primary_sequence_num != header.secondary_sequence_num,
            "hive_sequence_numbers": [header.primary_sequence_num, header.secondary_sequence_num],
            "transaction_logs_looked_for": looked,
            "transaction_logs_beside_hive": [path for path in looked if os.path.isfile(path)],
            "transaction_logs_replayed": False}


def dirty_caveat(state):
    """Why an answer read from a dirty hive is not complete, in the tool's own words and counts (None for a clean hive). The tool cannot show
    that the key or value asked about is outside the pages the logs would rewrite, so every answer from a dirty hive carries it."""
    if not state.get("hive_dirty"):
        return None
    there = len(state.get("transaction_logs_beside_hive") or [])
    return ("the hive is dirty (its sequence numbers %s and %s differ) and no transaction log was replayed: the tool looked for %s beside the hive "
            "(transaction_logs_looked_for) and %s, and it replays none, so what is read here is the hive file as it is and keys and values may differ from "
            "the live registry (give registry_recover the hive and its logs and read the copy it makes)" % (
                state["hive_sequence_numbers"][0], state["hive_sequence_numbers"][1], ", ".join(LOG_SUFFIXES[:-1]) + " and " + LOG_SUFFIXES[-1],
                "found none (they are not in what this job can read)" if not there else "found %d (transaction_logs_beside_hive)" % there))


INLINE_PROBLEMS = 40
ORDER_CAP = 100000                # most items of one list put in print order (above it: a random order)
ORDER_COST = 0.0003               # seconds one item may take to put in print order (about three times what it takes); a list is ordered only if it fits half of the time left


def fail(message, **extra):
    close_values()
    emit({"error": message, "status": "failed", "status_basis": "the tool stopped with an error (see error); no record was read", **extra})
    raise SystemExit(1)


def filetime(value):
    """ISO 8601 UTC with seven fractional digits, by integer arithmetic; None for 0 or a date past 9999."""
    try:
        value = int(value)
    except (TypeError, ValueError):
        return None
    if value <= 0:
        return None
    try:
        whole, ticks = divmod(value, 10_000_000)
        return (FILETIME_EPOCH + datetime.timedelta(seconds=whole)).strftime("%Y-%m-%dT%H:%M:%S") + ".%07dZ" % ticks
    except (OverflowError, ValueError):
        return None


def u16(b, at):
    return int.from_bytes(b[at:at + 2], "little")


def u32(b, at):
    return int.from_bytes(b[at:at + 4], "little")


def u64(b, at):
    return int.from_bytes(b[at:at + 8], "little")


def raw_fields(row, raw):
    """The bytes of a record, side by side with what was decoded from them: as hexadecimal, or (past MAX_RAW_HEX_BYTES) only their length. False when not written out."""
    row["raw_length"] = str(len(raw))
    if len(raw) <= MAX_RAW_HEX_BYTES:
        row["raw_hex"] = T("hex", bytes(raw).hex())
        return True
    row["raw_not_shown"] = "%d bytes are over the %d bytes this tool writes out as hexadecimal" % (len(raw), MAX_RAW_HEX_BYTES)
    return False


def value_bytes(v):
    """The data of a registry value as bytes (what regipy gives as text or a number is not binary data: None)."""
    data = getattr(v, "value", None)
    if isinstance(data, (bytes, bytearray)):
        return bytes(data)
    return None


# ---- UserAssist ----------------------------------------------------------------------------------------------------------------------

def decode_userassist(raw):
    """(fields, layout, basis, unsupported) of one UserAssist value by its length: 72 bytes (Windows 7 and later) or 16 (the older layout)."""
    if len(raw) == 72:
        return ({"session_id": str(u32(raw, 0)), "run_count": str(u32(raw, 4)), "focus_count": str(u32(raw, 8)), "focus_time_ms": str(u32(raw, 12)),
                 "last_execution_filetime": str(u64(raw, 60)), "last_execution": filetime(u64(raw, 60))},
                "userassist-72", "the value is 72 bytes; offsets (session 0, run count 4, focus count 8, focus time in ms 12, last run FILETIME 60) as the published notes give them, not verified against a real hive", None)
    if len(raw) == 16:
        return ({"session_id": str(u32(raw, 0)), "run_count": str(u32(raw, 4)), "last_execution_filetime": str(u64(raw, 8)), "last_execution": filetime(u64(raw, 8))},
                "userassist-16", "the value is 16 bytes; offsets (session 0, run count 4, last run FILETIME 8) as the published notes give them for the older layout, not verified against a real hive; the run count is as stored (the older layout is described as counting from 5)", None)
    return ({}, "unknown", "the value is %d bytes, which is neither of the two lengths this tool knows (72, 16)" % len(raw), "a UserAssist value of %d bytes: no known layout" % len(raw))


# ---- BAM and DAM -----------------------------------------------------------------------------------------------------------------------

def decode_bam(raw):
    if len(raw) == 24:
        return ({"last_execution_filetime": str(u64(raw, 0)), "last_execution": filetime(u64(raw, 0))},
                "bam-24", "the value is 24 bytes; the FILETIME at 0 as the published notes give it (the 16 bytes after it are kept in raw_hex, not read), not verified against a real hive", None)
    return ({}, "unknown", "the value is %d bytes, not the 24 this tool knows" % len(raw), "a BAM or DAM value of %d bytes: no known layout" % len(raw))


# ---- ShimCache -------------------------------------------------------------------------------------------------------------------------

def utf16(raw):
    return raw.decode("utf-16-le", "replace")


def shim_entries(blob):
    """(layout, basis, entries, declared): the layout chosen from the blob's header and tags, and a generator of entries (an entry that does not fit
    its layout is {"unsupported": why, "position": n, "raw": bytes}). The layout is None when the header is not one this tool knows."""
    n = len(blob)
    if n < 4:
        return None, "the value is shorter than a header", None, None
    first = u32(blob, 0)
    if first == 0xBADC0FEE and n >= 128:
        for size, label in ((48, "shimcache-win7-64"), (32, "shimcache-win7-32")):
            if shim7_fits(blob, 128, size):
                return label, ("the header is 0xBADC0FEE and the first entry fits the %d-byte entry shape (path offset and length inside the value); the entry shape and offsets as the published notes give them for Windows 7, "
                               "not verified against a real hive; the count in the header is compared, not trusted" % size), shim7(blob, size, u32(blob, 4)), u32(blob, 4)
        return None, "the header is 0xBADC0FEE but the first entry fits neither Windows 7 entry shape (the Vista and Server 2003 layout is not decoded)", None, None
    if n >= 0x38 and first in (0x30, 0x34) and blob[first:first + 4] == b"10ts":
        return "shimcache-win10", ("the first u32 is the offset of the first record (%d) and a '10ts' tag is there; record shape as the published notes give it for Windows 10 and later "
                                   "(tag, 4 unknown, body size, path length, path, FILETIME, data size, data), not verified against a real hive; each record's data size is checked against its body" % first), shim8(blob, first, "10"), None
    if n >= 0x84 and first == 0x80 and blob[0x80:0x84] in (b"00ts", b"10ts"):
        kind = "8.0" if blob[0x80:0x84] == b"00ts" else "8.1"
        return "shimcache-win%s" % kind, ("the first u32 is 0x80 and a '%s' tag is at 0x80; record shape as the published notes give it for Windows %s, not verified against a real hive; "
                                           "each record's data size is checked against its body" % (blob[0x80:0x84].decode("ascii"), kind)), shim8(blob, 0x80, kind), None
    if first == 0xDEADBEEF:
        return None, "the header is 0xDEADBEEF, the Windows XP and Server 2003 layout, which this tool does not decode", None, None
    return None, "the header (first u32 0x%08x) is not one of the layouts this tool knows (Windows 7, 8.0, 8.1, 10 and later)" % first, None, None


def shim7_fits(blob, start, size):
    if len(blob) < start + size:
        return False
    if size == 48:
        length, maxlen, pad, off = u16(blob, start), u16(blob, start + 2), u32(blob, start + 4), u64(blob, start + 8)
    else:
        length, maxlen, off = u16(blob, start), u16(blob, start + 2), u32(blob, start + 4)
        pad = 0
    return pad == 0 and length % 2 == 0 and length <= maxlen and off + length <= len(blob) and (length == 0 or off >= start)


def shim7(blob, size, declared):
    count = min(max((len(blob) - 128) // size, 0), declared)       # what the header declares, and no more than fits (the bytes after the entries are the paths)
    for i in range(count):
        at = 128 + i * size
        raw = blob[at:at + size]
        if size == 48:
            length, maxlen, off, ft, ins, shim, dsize = u16(raw, 0), u16(raw, 2), u64(raw, 8), u64(raw, 16), u32(raw, 24), u32(raw, 28), u64(raw, 32)
        else:
            length, maxlen, off, ft, ins, shim, dsize = u16(raw, 0), u16(raw, 2), u32(raw, 4), u64(raw, 8), u32(raw, 16), u32(raw, 20), u32(raw, 24)
        if length % 2 or length > maxlen or off + length > len(blob):
            yield {"unsupported": "the entry's path offset or length does not fit the value", "position": i, "raw": raw}
            continue
        yield {"position": i, "path": utf16(blob[off:off + length]), "ft": ft, "insert_flags": ins, "shim_flags": shim, "data_length": dsize, "raw": raw + blob[off:off + length]}


def shim8(blob, start, kind):
    at, i, n = start, 0, len(blob)
    while at < n:
        if n - at < 12 or blob[at + 2:at + 4] != b"ts" or blob[at:at + 2] not in (b"00", b"10"):
            yield {"unsupported": "no record tag where the previous record ended (%d bytes are left)" % (n - at), "position": i, "raw": blob[at:]}
            return
        body_size = u32(blob, at + 8)
        end = at + 12 + body_size
        if end > n:
            yield {"unsupported": "the record claims %d body bytes and %d are left" % (body_size, n - at - 12), "position": i, "raw": blob[at:]}
            return
        body = blob[at + 12:end]
        entry = shim8_body(body, kind)
        if entry is None:
            yield {"unsupported": "the record body does not fit the Windows %s record shape" % kind, "position": i, "raw": blob[at:end]}
        else:
            # the data blob after the fixed fields is counted (data_length) and not written out
            entry.update({"position": i, "raw": blob[at:at + 12 + entry.pop("_fixed")]})
            yield entry
        at, i = end, i + 1


def shim8_body(body, kind):
    """The record body (after the 12-byte head): path length, path, then by layout. None when it does not fit; the data size must match what is left."""
    if len(body) < 2:
        return None
    plen = u16(body, 0)
    if plen % 2 or 2 + plen > len(body):
        return None
    path = utf16(body[2:2 + plen])
    at = 2 + plen
    ins = shim = None
    if kind == "8.0":
        if at + 2 > len(body):
            return None
        at += 2 + u16(body, at)                  # the package name, not read
        if at + 8 > len(body):
            return None
        ins, shim = u32(body, at), u32(body, at + 4)
        at += 8
    elif kind == "8.1":
        if at + 8 > len(body):
            return None
        ins, shim = u32(body, at), u32(body, at + 4)
        at += 8
    if at + 12 > len(body):
        return None
    ft, dsize = u64(body, at), u32(body, at + 8)
    at += 12
    if dsize != len(body) - at:
        return None
    entry = {"path": path, "ft": ft, "data_length": dsize, "_fixed": at}
    if ins is not None:
        entry["insert_flags"], entry["shim_flags"] = ins, shim
    return entry


# ---- the walk -----------------------------------------------------------------------------------------------------------------------

def main():
    withhold_library_output()
    set_deadline(DEADLINE_SECONDS)
    seal_stop_after(86.5)                 # the manifest allows 90, less 3.5: no seal runs on past that (the rest is withheld whole)
    install_signal_handlers(lambda signum: interrupted_answer(signum))
    try:
        args = json.load(sys.stdin)
    except ValueError as exc:
        fail("arguments are not valid JSON", reason=str(exc))
    if not isinstance(args, dict):
        fail("the arguments are one JSON object")
    hive = args.get("hive")
    if not isinstance(hive, str) or not hive:
        fail("hive is required: the path to NTUSER.DAT (UserAssist) or SYSTEM (BAM, DAM, ShimCache)")
    source = args.get("source", "auto")
    if not isinstance(source, str) or (source != "auto" and source not in SOURCES):
        fail("source must be auto, userassist, bam or shimcache")
    limit = args.get("limit", 500)
    if not isinstance(limit, int) or isinstance(limit, bool) or limit < 1:
        fail("limit must be a positive integer")
    contains = args.get("contains")
    if contains is not None and (not isinstance(contains, str) or not contains):
        fail("contains must be non-empty text")
    contains = contains.lower() if contains else None
    sid_filter = args.get("sid")
    if sid_filter is not None and (not isinstance(sid_filter, str) or not SID_SHAPE.match(sid_filter)):
        fail("sid must be a security identifier such as S-1-5-21-1-2-3-1001")
    owner_sid = args.get("owner_sid")
    if owner_sid is not None and (not isinstance(owner_sid, str) or not SID_SHAPE.match(owner_sid)):
        fail("owner_sid must be a security identifier such as S-1-5-21-1-2-3-1001")
    write_values = args.get("write_values", False)
    if not isinstance(write_values, bool):
        fail("write_values must be true or false")
    try:
        hive_mode = os.stat(hive).st_mode
    except OSError:
        fail("no such hive", hive=hive)
    if not stat.S_ISREG(hive_mode):
        # A named pipe or a device would be opened and waited on: it is not read.
        fail("the hive is not a regular file, so it was not opened", hive=hive, not_attempted=1)
    try:
        bind_values(write_values, "userassist_bam_shimcache")
    except ValuesRefused as exc:
        fail(str(exc))
    OWN_NAMES.add(hive)
    try:
        h = open_hive(hive)
    except Exception as exc:
        fail("could not open the hive", hive=hive, reason=str(exc))
    bounds = HiveBounds(hive)

    # The names of the whole results are made from what was asked about and never from `contains` or `sid`: a needle can be a secret.
    records = SealedPage("userassist_bam_shimcache", [hive, source, bool(contains), bool(sid_filter), owner_sid], limit)
    problem_page = SealedPage("userassist_bam_shimcache-problems", [hive, source], INLINE_PROBLEMS)
    counts = {s: 0 for s in SOURCES}
    counts["dam"] = 0
    present = {}
    n = {"unsupported": 0, "filtered_out": 0, "blind": 0, "unread_for_time": 0, "meta": 0, "failed": 0, "raw_not_shown": 0, "entries_unread": 0, "keys_unstarted": 0,
         "unordered_lists": 0, "unordered_items": 0}
    stopped = [None]

    class Problems:
        def append(self, item):
            problem_page.add("%s: %s" % (item["where"], item["error"]))

    bound_problems = Problems()

    def note(label, exc):
        n["failed"] += 1
        problem_page.add("%s: %s: %s" % (label, type(exc).__name__, exc))

    def time_is_up(label):
        if stopped[0] is None and out_of_time():
            # (fixed words only: the label is one of this tool's own, never a name from the hive)
            stopped[0] = "the tool's own time limit (%d seconds) was reached in %s; what follows was not read" % (DEADLINE_SECONDS, label)
            OWN_NAMES.add(stopped[0])
            problem_page.add(stopped[0])
        return stopped[0] is not None

    def in_print_order(values, kind="name", text=str):
        """print_order, when the list can be put in order in the time left (ORDER_COST an item, within half of it) and is no longer than ORDER_CAP; else the same items in a random order
        (the rank of a name in the hive must not show in the listing, and a list this long is not judged item by item before the clock runs out)."""
        values = list(values)
        left = (STOP["deadline"] - time.monotonic()) if STOP["deadline"] is not None else 1e9
        if len(values) > ORDER_CAP or len(values) * ORDER_COST > left / 2:
            random.SystemRandom().shuffle(values)
            n["unordered_lists"] += 1
            n["unordered_items"] += len(values)
            return values
        return print_order(values, kind, text)

    listings = {}                       # id(node) -> (node, the subkeys read, the same in print order): a list is read once (the bounds count every element read over the whole walk)

    def listing(node, label):
        hit = listings.get(id(node))
        if hit is None:
            try:
                raw = bounds.subkeys(node, label, bound_problems)
            except Exception as exc:
                note(label, exc)
                raw = []
            hit = listings[id(node)] = (node, raw, None)
        return hit

    def kids(node, label):
        node_, raw, ordered = listing(node, label)
        if ordered is None:
            ordered = in_print_order(raw, "name", lambda s: str(getattr(s, "name", "")))
            listings[id(node)] = (node_, raw, ordered)
        return ordered

    def child(node, name, label):
        for sub in listing(node, label)[1]:
            if str(getattr(sub, "name", "")).lower() == name.lower():
                return sub
        return None

    def descend(node, parts, label):
        for part in parts:
            node = child(node, part, label)
            label = label + "\\" + part
            if node is None:
                return None
        return node

    def values_of(node, label):
        try:
            return in_print_order(bounds.values(node, label, bound_problems, trim_values=False), "name", lambda v: str(getattr(v, "name", "")))
        except Exception as exc:
            note(label, exc)
            return []

    def passes(texts, sid):
        """The filters look in the text the answer prints (contains_check, sealed_text), never in what was withheld; a row that does not match and has text withheld is counted."""
        blind = False
        if sid_filter:
            shown = sealed_text(sid, "sid", "sid") if sid else None
            if not shown or shown.lower() != sid_filter.lower():
                if shown and _MARK.search(shown):
                    blind = True
                n["filtered_out"] += 1
                n["blind"] += 1 if blind else 0
                return False
        if contains:
            hit = False
            for text in texts:
                if not text:
                    continue
                found, b = contains_check(contains, text, "path", "path")
                hit = hit or found
                blind = blind or b
            if not hit:
                n["filtered_out"] += 1
                n["blind"] += 1 if blind else 0
                return False
        return True

    def emit_row(row, raw, texts, sid):
        if row.get("unsupported"):
            n["unsupported"] += 1
        if not raw_fields(row, raw):
            n["raw_not_shown"] += 1
        for k in ("layout", "layout_basis", "unsupported", "sid_basis", "raw_not_shown"):     # the tool's own words (numbers and fixed text, never a string of the evidence)
            if isinstance(row.get(k), str):
                OWN_NAMES.add(row[k])
        if passes(texts, sid):
            counts[row["source"]] += 1
            records.add(row)

    def unreadable(row, v, what):
        row.update({"layout": "unknown", "layout_basis": "the value is of type %s, not binary data" % v.value_type, "unsupported": what})

    def read_userassist(root):
        node = descend(root, UA_PATH, "")
        present["userassist"] = node is not None
        if node is None:
            return
        base = "\\".join(UA_PATH)
        guids = kids(node, base)
        for gi, guid in enumerate(guids):
            if time_is_up("UserAssist"):
                n["keys_unstarted"] += len(guids) - gi
                return
            gname = str(getattr(guid, "name", ""))
            count = child(guid, "Count", base + "\\" + gname)
            if count is None:
                continue
            where = base + "\\" + gname + "\\Count"
            listed = values_of(count, where)
            for idx, v in enumerate(listed):
                if time_is_up("UserAssist"):
                    n["unread_for_time"] += len(listed) - idx            # the values of this key still to come
                    n["keys_unstarted"] += len(guids) - gi - 1           # the GUID keys after it: what they hold is not counted
                    return
                try:
                    name = str(v.name)
                    raw = value_bytes(v)
                    row = {"source": "userassist", "key": T("key", where), "guid": gname, "name_raw": name, "name_decoded": name.translate(ROT13),
                           "value_type": str(v.value_type), "sid": owner_sid,
                           "sid_basis": ("given by the caller as owner_sid; not checked against the hive" if owner_sid else
                                         "an NTUSER.DAT does not name its owner: the user is not known from the hive")}
                    if raw is None:
                        unreadable(row, v, "a UserAssist value that is not binary data")
                        raw = b""
                    else:
                        fields, layout, basis, unsupported = decode_userassist(raw)
                        row.update(fields)
                        row["layout"], row["layout_basis"] = layout, basis
                        if unsupported:
                            row["unsupported"] = unsupported
                    emit_row(row, raw, [row["name_decoded"], name], owner_sid)
                except Exception as exc:
                    note(where, exc)

    def control_sets(root):
        current = None
        sel = child(root, "Select", "")
        if sel is not None:
            for v in values_of(sel, "Select"):
                if str(getattr(v, "name", "")).lower() == "current" and isinstance(getattr(v, "value", None), int) and not isinstance(v.value, bool):
                    current = v.value
        return [s for s in kids(root, "") if CONTROL_SET.match(str(getattr(s, "name", "")))], current

    def read_bam(sets, current):
        for cs in sets:
            csn = str(cs.name)
            is_current = None if current is None else csn.lower() == "controlset%03d" % current
            for label, parts in BAM_PATHS:
                node = descend(cs, parts, csn)
                if node is None:
                    continue
                present["bam"] = True
                base = csn + "\\" + "\\".join(parts)
                sids = kids(node, base)
                for si, sidkey in enumerate(sids):
                    if time_is_up(label.upper()):
                        n["keys_unstarted"] += len(sids) - si
                        return
                    sname = str(getattr(sidkey, "name", ""))
                    where = base + "\\" + sname
                    listed = values_of(sidkey, where)
                    for idx, v in enumerate(listed):
                        if time_is_up(label.upper()):
                            n["unread_for_time"] += len(listed) - idx    # the values of this key still to come
                            n["keys_unstarted"] += len(sids) - si - 1    # the SID keys after it: what they hold is not counted
                            return
                        try:
                            name = str(v.name)
                            raw = value_bytes(v)
                            if raw is None and name.lower() in ("version", "sequencenumber") and str(v.value_type) == "REG_DWORD":
                                n["meta"] += 1
                                continue
                            row = {"source": label, "key": T("key", where), "control_set": csn, "current_control_set": is_current, "sid": sname,
                                   "sid_basis": "the name of the key the value is in", "path": name, "value_type": str(v.value_type)}
                            if raw is None:
                                unreadable(row, v, "a value that is not binary data")
                                raw = b""
                            else:
                                fields, layout, basis, unsupported = decode_bam(raw)
                                row.update(fields)
                                row["layout"], row["layout_basis"] = layout, basis
                                if unsupported:
                                    row["unsupported"] = unsupported
                            emit_row(row, raw, [name], sname)
                        except Exception as exc:
                            note(where, exc)

    def read_shim(sets, current):
        for cs in sets:
            csn = str(cs.name)
            is_current = None if current is None else csn.lower() == "controlset%03d" % current
            for parts in SHIM_PATHS:
                node = descend(cs, parts, csn)
                if node is None:
                    continue
                where = csn + "\\" + "\\".join(parts)
                present["shimcache"] = True       # the key is there: a value the HIVE BOUNDS block refused (over its size cap) is a problem line, not an absent source
                for v in values_of(node, where):
                    if str(getattr(v, "name", "")).lower() != "appcompatcache":
                        continue
                    if time_is_up("ShimCache"):
                        n["unread_for_time"] += 1
                        return
                    try:
                        blob = value_bytes(v)
                        base = {"source": "shimcache", "key": T("key", where), "control_set": csn, "current_control_set": is_current, "value_type": str(v.value_type),
                                "sid": None, "sid_basis": "ShimCache is machine-wide: it holds no user"}
                        if blob is None:
                            row = dict(base)
                            unreadable(row, v, "the AppCompatCache value is not binary data")
                            emit_row(row, b"", [], None)
                            continue
                        layout, basis, entries, declared = shim_entries(blob)
                        if layout is None:
                            emit_row(dict(base, layout="unknown", layout_basis=basis, unsupported="the AppCompatCache value (%d bytes) has no known layout" % len(blob)), blob, [], None)
                            continue
                        total = 0
                        # The entries a Windows 7 layout holds are known from its header and size; a record layout (8.0 and later) is known only by
                        # reading it. What is left at the time limit is counted from that, never by running the decoder on to the end (which took
                        # the run past its limit).
                        planned = None
                        if layout.startswith("shimcache-win7") and declared is not None:
                            planned = min(max((len(blob) - 128) // (48 if layout.endswith("64") else 32), 0), declared)
                        for e in entries:
                            if time_is_up("ShimCache entries"):
                                n["entries_unread"] += max(planned - total, 1) if planned is not None else 1
                                break
                            total += 1
                            row = dict(base, layout=layout, layout_basis=basis, entry_position=str(e["position"]))
                            if "unsupported" in e:
                                row["unsupported"] = e["unsupported"]
                                emit_row(row, e["raw"], [], None)
                                continue
                            row.update({"path": e["path"], "last_modified_filetime": str(e["ft"]), "last_modified": filetime(e["ft"]), "data_length": str(e["data_length"])})
                            if "insert_flags" in e:
                                row["insert_flags"], row["shim_flags"] = str(e["insert_flags"]), str(e["shim_flags"])
                            emit_row(row, e["raw"], [e["path"]], None)
                        if declared is not None and declared > total and stopped[0] is None:
                            problem_page.add("%s: the header declares %d entries and %d fit the value" % (where, declared, total))
                    except Exception as exc:
                        note(where, exc)

    root = h.root
    if source in ("auto", "userassist"):
        read_userassist(root)
    if source in ("auto", "bam", "shimcache") and stopped[0] is None:
        sets, current = control_sets(root)
        if source in ("auto", "bam"):
            read_bam(sets, current)
        if source in ("auto", "shimcache") and stopped[0] is None:
            read_shim(sets, current)
    wanted = SOURCES if source == "auto" else (source,)
    if not any(present.get(s) for s in wanted):
        fail("no source key was found in this hive", hive=hive, looked_for=list(wanted), hint="UserAssist is in NTUSER.DAT; BAM, DAM and ShimCache are in SYSTEM",
             problems=problem_page.page)

    if LibraryLog.messages:
        problem_page.add("regipy logged %d message(s) (%d of them errors) while reading; its text can hold bytes of a value or a name and is not shown" % (LibraryLog.messages, LibraryLog.errors))
    state = hive_state(h, hive)
    page = records.finish()
    problem_result = problem_page.finish()
    reasons = []
    if problem_result["matched"]:
        reasons.append("%d problem(s) are named under problems" % problem_result["matched"])
    if n["unsupported"]:
        reasons.append("%d record(s) of the hive have no known layout and are returned undecoded (unsupported; a record a filter removed is counted too)" % n["unsupported"])
    if n["raw_not_shown"]:
        reasons.append("%d record(s) are over %d bytes: their length is given and their bytes are not written out (raw_not_shown)" % (n["raw_not_shown"], MAX_RAW_HEX_BYTES))
    if n["unordered_lists"]:
        reasons.append("%d list(s) (%d item(s) in all) were too long to put in print order in the time left and are listed in a random order" % (n["unordered_lists"], n["unordered_items"]))
    if stopped[0]:
        reasons.append("%s (at least %d value(s) and %d ShimCache entr(ies) were not read; %d key(s) were not started and what they hold is not counted; every source after this point "
                       "was not started and is not counted)" % (stopped[0], n["unread_for_time"], n["entries_unread"], n["keys_unstarted"]))
    if n["blind"]:
        reasons.append("the filters look only in the text the answer prints: %d record(s) were not matched and have text withheld, so the needle may be in what is withheld (contains_blind_records)" % n["blind"])
    if n["failed"]:
        reasons.append("%d key(s) or value(s) could not be read" % n["failed"])
    caveat = dirty_caveat(state)
    if caveat:
        reasons.append(caveat)
    out = {
        "parser": PARSER,
        "status": "partial" if reasons else "complete",
        "status_basis": "; ".join(reasons) if reasons else "every value of the sources found was read to its end and decoded",
        "hive": hive,
        "hive_type": (str(getattr(h, "hive_type", "") or "").lower() or None),
        "sources": {s: {"present": bool(present.get(s))} for s in wanted},
        "records_by_source": counts,
        "records": records.page,
        "record_count": page["matched"],
        "unsupported_count": n["unsupported"],
        "filtered_out": n["filtered_out"],
        "contains_applied": bool(contains),
        "sid_applied": bool(sid_filter),
        "contains_blind_records": n["blind"] if contains or sid_filter else None,
        "metadata_values_not_listed": n["meta"],
        "entry_data_note": "a ShimCache entry's data blob is not decoded or written out: its length is in data_length, and raw_hex holds the entry without it",
        "interpretation_limits": list(LIMITS),
        "cross_check": {"result": "not_run", "reason": "no independent second reader (RECmd, RegRipper) is started by this tool: the records are the decoding of one reader"},
        "problems": problem_page.page,
        "problem_count": problem_result["matched"],
        "problems_not_listed": problem_result["matched"] - len(problem_page.page),
        "walk_stopped_by_time_limit": stopped[0] is not None,
        "library_messages_withheld": LibraryLog.messages,
        **state,
        **page,
    }
    if problem_result.get("all_results"):
        out["all_problems"] = problem_result["all_results"]
    OWN_NAMES.add(out["status_basis"])                       # made of counts and the tool's own words
    for text in (out["cross_check"]["reason"], out["entry_data_note"]):
        OWN_NAMES.add(text)
    emit(out, indent=2)
    close_values()


if __name__ == "__main__":
    exit_code = 0
    try:
        try:
            main()
        except SystemExit:
            raise
        except Exception as exc:                                  # whatever hostile input does, the answer is JSON
            hold_stop_signals(quietly=True)
            emit({"error": "the read failed", "status": "failed", "status_basis": "the tool stopped with an unexpected error", "reason": "%s: %s" % (type(exc).__name__, exc)})
            raise SystemExit(1)
    except SystemExit as stop:
        exit_code = _code(stop)
    _leave(exit_code)
