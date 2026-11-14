#!/usr/bin/env python3
"""Replay a registry hive's transaction logs on a copy, and read the recovered state.

A hive that was in use when it was copied can be dirty: its two sequence numbers differ and its newest
state is in the .LOG1 and .LOG2 files beside it, not in the hive. This tool applies the logs the caller
names (explicitly: nothing is looked for beside the hive) to a COPY of the hive under its own output
directory, writes a receipt of what was done and not done, and writes the key and value records of the
resulting state as JSON Lines. The hive and the logs are only opened for reading.

The replay follows the layout of the two log formats (Suhanov, "Windows registry file format
specification"; libyal's REGF notes):
  new format (HvLE entries, Windows 8.1 and later): an entry is applied only when its signature, the
  Marvin32 hash of its header (hash-2) and of its pages (hash-1) are right, and its sequence number is
  the next one the hive needs. A dirty hive needs the entry whose sequence number is its SECONDARY
  sequence number; after an entry of number n is applied the hive is at n + 1, and entries of the
  following numbers are applied in order, from one log or the other. An entry older than the hive's
  state is not applied (it would put an older page over a newer one), an entry that does not follow is
  not applied, and an entry whose hash is wrong ends the log there. Every entry not applied, and the
  hive ranges its pages would have written, are listed under `unrecovered`.
  old format (a DIRT vector and the dirty 512-byte sectors): applied as a whole when the log's own two
  sequence numbers agree and equal the hive's primary sequence number. It has no hash to check.
regipy's apply_transaction_logs is not used for the replay: it writes the pages of every entry whatever
its sequence number, so an entry older than the hive's state is written over newer data, and it takes
the first dirty sector of an old-format log to be at a fixed place.

The recovered copy differs from the original in the pages of the applied entries and in the fields of its
base block that the receipt names: both sequence numbers (set to the number after the last applied entry), the
hive bins data size (from the last applied entry) and the base block checksum (recomputed) always; for a
new-format log also the root cell offset and the last-written time (from the base block of the log that holds
the last applied entry; a log whose own base block checksum is wrong is not believed) and the flags (those of
that entry), where they differ.

Bounds. An entry that lists no page, declares a hive bins size that is not a positive multiple of 4096 or is
more than the hive file's own bins plus HBS_GROWTH (and MAX_HIVE_BYTES), names a page that is not whole
512-byte sectors or lists more pages than its bins have sectors is not applied, whatever its hashes, and the
reason is under `unrecovered`. At most MAX_LOG_ENTRIES entries of a log are scanned and the rest is named in
the receipt. An entry keeps the number and the place of its page references, never the list, and the clock is
looked at while the log is scanned, while hashes are checked and while pages are written; a replay that runs
out of time leaves no copy. A hive or recovered copy over MAX_READ_BYTES is replayed and not read.
A hive that is clean is not replayed (a clean hive's logs only hold entries it already contains; a log
entry newer than a clean hive is reported, not applied). The key and value records are read with
regipy: `keys.jsonl` is the state read (the recovered copy when something was applied, else the hive),
and when a replay applied something `changes.jsonl` lists the keys and values that differ from the
original.

SENSITIVE OUTPUT. A value that is registry material that can be a secret (the V and SupplementalCredentials
values of each SAM user, the values of the LSA secrets and cached-logon keys of a SECURITY hive, and a
value whose name says password, secret, token or credential, a DWORD or QWORD excepted) is written as a
record with its place, name, type and length, and not its bytes. `write_values: true` in a job run as
secret output writes those values to a file with mode 0600; it is refused anywhere else, before anything
is made. A secret inside a value that does not look like one (a command line with a password in it) is
not recognised and is written with the rest.
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
import datetime
import json
import os
import re
import select
import signal
import stat
import struct
import subprocess
import sys
import tempfile
import time
from pathlib import Path

PARSER = "registry_recover/5"
BASE_BLOCK = 4096
LOG_HEADER = 512
MARVIN_SEED = 0x82EF4D887A4E55C5
FILETIME_EPOCH = datetime.datetime(1601, 1, 1, tzinfo=datetime.timezone.utc)
SENSITIVE_NAME = re.compile(r"passw(or)?d|pwd|secret|token|credential|api_?key|private_?key", re.I)
NUMBER_TYPES = ("REG_DWORD", "REG_DWORD_BIG_ENDIAN", "REG_QWORD")
MAX_HIVE_BYTES = 4 << 30
MAX_LOG_ENTRIES = 50_000            # entries one log is scanned for; the rest of the log is named (the memory is about 1.5 KB for each entry)
HBS_GROWTH = 64 << 20               # how far past the hive file's own hive bins an entry may declare the bins to grow
MAX_READ_BYTES = 512 << 20          # regipy holds the whole hive it reads in memory; a larger hive is replayed and not read
REF_BLOCK = 1 << 17                 # page references read at once (1 MiB of them)
LISTED_RANGES = 20_000              # page references of one entry listed as hive ranges; the rest are named by where they are in the log
RANGE_BUDGET = 200_000              # page references listed as hive ranges over the whole receipt
SECTOR = 512
MAX_DEPTH = 512
DEFAULT_SECONDS = 90
MAX_SECONDS = 110
INLINE_PROBLEMS = 50
# Every inline page is bounded by bytes as well as by rows (a SYSTEM hive gave an answer of 144.8 MB: 182 rows of 96.5 MB): a page holds at most
# INLINE_PAGE_BYTES of rows, a row over INLINE_ROW_BYTES is shown by its small fields and its line in the file, a text of a problem or of a
# list in the answer is cut at INLINE_TEXT, and an answer that is still over MAX_ANSWER_BYTES is printed without its inline pages. Nothing is
# lost by any of it: every row is whole in the file the page names, and `next` says the line to read on from.
INLINE_PAGE_BYTES = 128 << 10
INLINE_ROW_BYTES = 4096
INLINE_FIELD = 512
INLINE_TEXT = 2000
MAX_ANSWER_BYTES = 768 << 10
BLOCK = 1 << 20

# Lossless paging (the same in every library tool that pages): the page an
# agent reads stays small, and when there are more rows the whole result is
# written as JSON Lines under work/<agent>/tool-output and named.
import hashlib


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


# BEGIN SHARED PROCESS
# The same text is in every windows-forensics tool and recipe that starts a program (and in any other pack's tool that copies it);
# tests/pack-windows-forensics-process.test.ts holds the copies equal. A program a tool runs is started in THIS tool's process group, never in a session of its own: the
# harness ends a tool that runs too long, or is aborted, by killing the tool's group (process.kill(-pid, SIGKILL)), and a
# program in a group of its own goes on writing after the tool is gone. On Linux the kernel is also asked to kill it if the
# tool dies. The tool's own deadline kills the program and what it started by walking the process tree, and SIGTERM, SIGINT
# and SIGHUP do the same and then give the tool a last word. Only what is
# below a program this tool started and has not yet waited for is ever signalled: the walk starts at that program's pid
# and nowhere else, and a program that has been waited for (its pid may be another process's by now) is left alone. The
# walk is bounded (MAX_ROUNDS and WALK_SECONDS, below). A stop signal is the one case that reaches further: it also
# ends everything below the tool itself (a program that was forked a moment before it was entered in ACTIVE is among it) and what
# the tool started and lost (reap_orphans): a process that was seen below the tool, in the tool's own group, and whose parent has since
# ended. Nothing else is ever ended: a process the tool never saw in its tree (the next stage of a pipeline the tool heads, a process a
# launcher put in the group) is left alone, whoever leads the group. A program that has ended while something it started still
# holds its pipes does not hold the tool: communicate_bounded gives the pipes PIPE_GRACE seconds (and POST_EXIT_BYTES bytes) and goes on without them. (In the
# windows lineage only the windows-artefacts recipe and lnk_jumplist call it; the lineage is one text, so the others carry it unused.)
# The walk below a program is bounded: MAX_ROUNDS rounds and WALK_SECONDS seconds. Each process is stopped (SIGSTOP) as the walk finds it,
# so one that forks fast cannot outrun the walk; the walk is repeated for what the stopped ones had already forked, and the stopped set is
# then killed. A tree that is still growing at the bound is left, and process_notes() says so.
# Before a pid other than the program itself is signalled, its identity is read again (same_process(pid, ident)): the start time, from
# /proc/<pid>/stat (field 22, counted after the last ")") on Linux, from libproc's PROC_PIDTBSDINFO (pbi_start_tvsec, pbi_start_tvusec;
# written from <sys/proc_info.h>, not run on macOS in this repository's tests) on macOS, and from `ps -o lstart=` (to the second: coarse)
# where neither answers. The parent is no part of it: a child is re-parented when its parent ends, and is still the process that was
# listed. A pid that is gone, or whose start time is not the listed one, is left alone; a pid whose start time could not be read when it
# was listed is signalled only if it can be read now and is in the tool's own group; a ps listing that gave no start time (a minimal ps) is
# checked only for the pid still being there.
# A tree that cannot be listed (ps fails, lists nothing or needs more than PS_WAIT seconds, /proc cannot be read or takes more than
# TABLE_SECONDS) is never taken as an empty one: list_descendants raises TreeNotListed, the program itself is still ended, and a sentence
# in process_notes() says that the tree could not be listed (communicate_bounded also appends it to the stderr bytes it returns when it
# ended the program at its deadline). descendants() is list_descendants for a caller that cannot take an exception (a signal handler): its
# list is empty and has not_listed = True when the tree could not be listed.
# Open: a pid that ends and is reused between the identity check and the signal (two calls) is signalled; the Linux rule that a member of
# the tool's own group that holds the tool's pipe is ended; on macOS a daemon that holds the pipes of a finished program is not found (no
# /proc/<pid>/fd); a tool SIGKILLed between the stop and the kill leaves the program and the stopped set stopped (the harness ends the
# tool's group, and with it the stopped ones that are in it); a carrier's answer carries program_group (process_verdict, process_notes)
# only where that carrier's own code calls process_apply (without the call a program's leftovers are ended but not reported); the start of the interpreter, before any handler is in, is a window a signal can land in.
# What a program leaves behind (settle). A program can exit by itself and leave a process that goes on writing a file the answer then reports:
# one in a session of its own, or one that holds none of the tool's descriptors, which neither the walk nor the pipes reach. On Linux spawn()
# makes the tool a subreaper (become_subreaper, PR_SET_CHILD_SUBREAPER): such a process is adopted by the tool, so it is a direct child of the
# tool, and settle() ends it: when a program leaves ACTIVE after it has ended or been killed (ACTIVE is a list whose remove() does it), and at
# the end of communicate_bounded and inside kill_all. It ends only a child of the tool that is no program's own: not a program spawn() started
# (SPAWNED: Popen reaps those, their returncode is never taken), not one kept (KEEP, process_keep(pid), spawn(argv, leaves=True) for a
# program that leaves a process on purpose) and not a child the tool already had (PRE_KIDS). It stops each one, what it started with it (the
# walk above), kills and reaps them, for at most LEFTOVER_SECONDS, reading the clock for every process. While another program is running in
# ACTIVE nothing is ended and the answer says it is unproven. process_verdict() says what was found; process_apply(answer) puts it into an
# answer as program_group and turns a complete answer partial when a program left something or that could not be ruled out: a carrier
# calls it once where it prints its answer. Where nothing is adopted (not Linux, or the kernel refuses) settle() ends only what the tool saw
# below a program whose parent is gone, and the answer is unproven (NONLINUX_UNPROVEN_DOWNGRADE below is the one line that decides whether
# that alone makes a complete answer partial on a host that is not Linux). Not reached by any of this: a process that is not a descendant of
# a program (started through a service manager, a socket, another PID namespace), and the tool itself being killed (the harness ends its group).
# What a program's pipes deliver after it ended (the byte cap). communicate_bounded reads the pipes itself (a selector, not
# Popen.communicate) and looks at the program after every read. From the moment the program has ended, or been killed at its deadline, it
# takes at most POST_EXIT_BYTES (1 MiB) more bytes from its two pipes together and at most PIPE_GRACE seconds, whichever comes first; a
# program's own last words are in the pipe already (a pipe holds far less than the cap), so only what a process that went on holding the
# pipe wrote can be cut. At the cap the tool stops reading, ends the holder (reap_orphans, settle) and lets the pipes go: PIPE_CUT["cut"]
# counts the calls cut that way, process_notes() says so, and process_apply turns a complete answer partial. The bytes kept are the ones
# read, not a whole stream: a caller that parses the output sees the program's output and at most 1 MiB of what a leftover wrote. While the
# program runs each stream has a running cap too (STDOUT_CAP 64 MiB, STDERR_CAP 8 MiB with its head and last STDERR_TAIL 1 MiB kept, or the
# caller's `caps`): past it the program is ended on the deadline's own path (kill_tree, its tree only), the stream comes back cut
# (Output.cut, output_cut()), OUTPUT_CUT counts the call and process_apply turns a complete answer partial; a caller that parses a cut
# output says so and never takes it for a whole one.
import select as _select
import selectors as _selectors
import time

try:
    import ctypes
except ImportError:  # pragma: no cover
    ctypes = None

STATE = {"last_word": None}    # what to do, with the signal number, when the tool is stopped by a signal
class _Active(list):
    """The programs running now. A program that leaves the list after it has ended or been killed (a carrier removes it when it has waited
    for it) is followed by settle(): what it left behind is ended before the carrier reads what the program wrote. One that is still
    running when it is removed is not looked at."""

    def remove(self, proc):
        list.remove(self, proc)
        if proc.poll() is not None:
            settle()


ACTIVE = _Active()             # the programs running now
SPAWNED = {}                   # the programs spawn() started: pid -> identity (Popen reaps them, settle() never does)
KEEP = {}                      # the processes left on purpose: pid -> identity (settle() leaves them)
PRE_KIDS = {}                  # the children the tool already had when the first program was spawned: pid -> identity
LEAVES = {}                    # the programs started with leaves=True that have not ended yet: pid -> Popen
LEFT = {"left_behind": 0, "unproven": []}   # how many live processes settle() ended, and why nothing-left-behind cannot be proven
SUB = {"tried": False, "on": False, "note": None}        # whether the subreaper was asked for, and is on
SETTLING = [False]             # settle() is running (the stop signal's own call goes through)
LEFTOVER_SECONDS = 3              # the most one settle() works, in seconds; the clock is read for every process it ends, not once per pass
SETTLE_LOOK = 0.05             # the pause before the look that follows an ending: a fork that was under way when the first process died
# The one line the owner decides: on a host that cannot adopt orphaned processes (not Linux) a program may have left a process nobody can find.
# True: that alone is `unproven`, and process_apply turns a complete answer partial. False: the answer only carries a note.
NONLINUX_UNPROVEN_DOWNGRADE = True
SEEN = set()                   # the pids seen below a program this tool started: the only ones reap_orphans may end once their parent is gone
SEEN_IDENT = {}                # what each pid in SEEN was (its start time) when it was seen below the tool: a pid that ended and was reused does not match
NOTES = []                     # what this block could not do, as sentences for an answer (process_notes())
MAX_ROUNDS, WALK_SECONDS = 8, 15   # the bound of the walk below a program: rounds, and seconds
TABLE_SECONDS = 10             # the longest reading of /proc (or of a process table) is given
SEEN_MAX = 1 << 16             # the most pids SEEN holds


def _die_with_parent():  # runs in the child between fork and exec
    try:
        ctypes.CDLL(None).prctl(1, signal.SIGKILL)   # PR_SET_PDEATHSIG
    except Exception:  # noqa: BLE001
        pass


def spawn(argv, leaves=False, **kwargs):
    kwargs.setdefault("stdin", subprocess.DEVNULL)
    become_subreaper()
    if sys.platform.startswith("linux") and ctypes is not None:
        kwargs["preexec_fn"] = _die_with_parent
    proc = subprocess.Popen(argv, **kwargs)
    SEEN.add(proc.pid)
    started = _read_ident(proc.pid, "proc" if os.path.isdir("/proc/self") else "libproc")
    if started is not None:
        SEEN_IDENT[proc.pid] = started
    SPAWNED[proc.pid] = started
    if leaves:
        LEAVES[proc.pid] = proc     # what this program leaves behind stays (settle() keeps it)
    return proc


class TreeNotListed(Exception):
    """The processes could not be listed: ps failed, listed nothing or needed more than PS_WAIT seconds, /proc could not be read, or reading
    it took more than TABLE_SECONDS. It is never to be read as a tree with nothing below it."""


class _Listing(list):
    """The pids below a process, as a list; .ident holds each pid's identity from the same reading, .not_listed says the tree could not be listed."""
    ident = None
    not_listed = False


class _Table(dict):
    """{pid: (parent pid, process group)}; .ident holds each pid's identity from the same reading."""
    ident = None


def _note(text):
    """Record a sentence about what this block could not do (once, at most 20) and return it."""
    if text not in NOTES and len(NOTES) < 20:
        NOTES.append(text)
    return text


def process_notes():
    """What this block could not do so far, as sentences (a tree that could not be listed, a walk that was cut), for an answer."""
    return list(NOTES)


def _libproc_start(pid):
    """(seconds, microseconds) of the start of `pid` from libproc's PROC_PIDTBSDINFO (macOS), or None. Written from <sys/proc_info.h>
    (struct proc_bsdinfo, 136 bytes, flavor 3); not run on macOS in this repository's tests."""
    try:
        import ctypes.util

        class BsdInfo(ctypes.Structure):
            _fields_ = [("pbi_flags", ctypes.c_uint32), ("pbi_status", ctypes.c_uint32), ("pbi_xstatus", ctypes.c_uint32),
                        ("pbi_pid", ctypes.c_uint32), ("pbi_ppid", ctypes.c_uint32), ("pbi_uid", ctypes.c_uint32),
                        ("pbi_gid", ctypes.c_uint32), ("pbi_ruid", ctypes.c_uint32), ("pbi_rgid", ctypes.c_uint32),
                        ("pbi_svuid", ctypes.c_uint32), ("pbi_svgid", ctypes.c_uint32), ("rfu_1", ctypes.c_uint32),
                        ("pbi_comm", ctypes.c_char * 16), ("pbi_name", ctypes.c_char * 32), ("pbi_nfiles", ctypes.c_uint32),
                        ("pbi_pgid", ctypes.c_uint32), ("pbi_pjobc", ctypes.c_uint32), ("e_tdev", ctypes.c_uint32),
                        ("e_tpgid", ctypes.c_uint32), ("pbi_nice", ctypes.c_int32), ("pbi_start_tvsec", ctypes.c_uint64),
                        ("pbi_start_tvusec", ctypes.c_uint64)]

        lib = ctypes.CDLL(ctypes.util.find_library("proc") or "/usr/lib/libproc.dylib", use_errno=True)
        lib.proc_pidinfo.argtypes = [ctypes.c_int, ctypes.c_int, ctypes.c_uint64, ctypes.c_void_p, ctypes.c_int]
        lib.proc_pidinfo.restype = ctypes.c_int
        info = BsdInfo()
        if lib.proc_pidinfo(pid, 3, 0, ctypes.byref(info), ctypes.sizeof(info)) != ctypes.sizeof(info):
            return None
        return (int(info.pbi_start_tvsec), int(info.pbi_start_tvusec))
    except Exception:  # noqa: BLE001 - no library, no symbol, a sandbox: the caller falls back
        return None


def _ps_start(pid):
    """The start time `ps -o lstart= -p <pid>` prints, to the second (coarse), or None when ps fails, takes more than PS_WAIT seconds or prints none."""
    try:
        done = subprocess.run(["ps", "-o", "lstart=", "-p", str(pid)], capture_output=True, text=True, timeout=PS_WAIT)
    except (OSError, subprocess.SubprocessError):
        return None
    text = " ".join(done.stdout.split())
    return text if done.returncode == 0 and text else None


def _read_ident(pid, kind):
    """The identity of `pid` read the way `kind` ("proc", "libproc" or "ps") says, or None when the process is gone or the way fails."""
    if kind == "proc":
        try:
            with open("/proc/%d/stat" % pid, "rb") as fh:
                data = fh.read()
            return ("proc", int(data[data.rindex(b")") + 2:].split()[19]))   # field 22, counted after the last ")": the name may hold one
        except (OSError, ValueError, IndexError):
            return None
    if kind == "libproc":
        started = _libproc_start(pid)
        return None if started is None else ("libproc", started)
    started = _ps_start(pid)
    return None if started is None else ("ps", started)


def process_ident(pid):
    """What tells the process that has `pid` now from a later one that gets the same pid: its start time. Linux: field 22 of /proc/<pid>/stat;
    macOS: libproc's pbi_start_tvsec and pbi_start_tvusec; where neither answers, the start time ps prints (to the second). The parent is no
    part of it: a child is re-parented when its parent ends, and is still the process that was listed. None where the process is gone or
    cannot be read."""
    if os.path.isdir("/proc/self"):
        return _read_ident(pid, "proc")
    return _read_ident(pid, "libproc") or _read_ident(pid, "ps")


def same_process(pid, ident):
    """Whether `pid` is still the process `ident` was read from (process_ident, or the listing a walk made): a pid that is gone, or that
    another process has taken since (another start time), is not. An `ident` of None (it could not be read when the process was listed) is
    not vouched for either: the pid is signalled only if it can be read now and is in this process's own group. A listing by plain ps that
    gave no start time ("listed") can only be checked for the pid still being there."""
    if ident is None:
        try:
            return process_ident(pid) is not None and os.getpgid(pid) == os.getpgrp()
        except OSError:
            return False
    if ident[0] == "listed":
        try:
            os.kill(pid, 0)
        except PermissionError:
            return True
        except OSError:
            return False
        return True
    return _read_ident(pid, ident[0]) == ident


def _seen_below(pids, ident):
    """Enter pids seen below the tool in SEEN, with the identity the listing that showed them gave."""
    for pid in pids:
        if pid in SEEN or len(SEEN) < SEEN_MAX:
            SEEN.add(pid)
            if ident.get(pid) is not None:
                SEEN_IDENT[pid] = ident[pid]


def _ps_rows(columns):
    """The rows of `ps -A -o <columns>` as lists of fields. Raises TreeNotListed when ps cannot be run, fails, takes more than PS_WAIT seconds
    or lists nothing."""
    try:
        done = subprocess.run(["ps", "-A", "-o", columns], capture_output=True, text=True, timeout=PS_WAIT)
    except subprocess.TimeoutExpired as exc:
        raise TreeNotListed("ps took more than %d seconds" % PS_WAIT) from exc
    except (OSError, subprocess.SubprocessError) as exc:
        raise TreeNotListed("ps could not be run: %s" % type(exc).__name__) from exc
    rows = [line.split() for line in done.stdout.splitlines() if line.split()]
    if done.returncode != 0 or not rows:
        raise TreeNotListed("ps %s" % ("exited %d" % done.returncode if done.returncode != 0 else "listed nothing"))
    return rows


def _children_libproc(pid):
    """The direct children of `pid` on macOS, from libproc (macOS only: proc_listchildpids is not a symbol of the other
    BSDs; a library call, so no program is started and nothing can be slow); None when the library, the symbol or the
    call is not there."""
    try:
        import ctypes.util
        lib = ctypes.CDLL(ctypes.util.find_library("proc") or "/usr/lib/libproc.dylib", use_errno=True)
        lib.proc_listchildpids.argtypes = [ctypes.c_int, ctypes.c_void_p, ctypes.c_int]
        lib.proc_listchildpids.restype = ctypes.c_int
        size = 256
        while size <= 1 << 16:
            buf = (ctypes.c_int * size)()
            if lib.proc_listchildpids(pid, buf, ctypes.sizeof(buf)) < 0:
                return None
            found = []
            for value in buf:
                if value <= 0:
                    break
                found.append(int(value))
            if len(found) < size:
                return found
            size *= 4
        return found
    except Exception:  # noqa: BLE001 - no library, no symbol: the caller falls back
        return None


PS_WAIT = 10    # seconds the ps fallback is given: ps is slow on a heavily loaded host, and a tree that is not found is a program left running


def _below(kids, pid):
    """Every process below `pid` in `kids` ({parent: [children]}), a parent before its children."""
    found, seen, queue = [], {pid}, [pid]
    for parent in queue:
        for child in kids.get(parent, []):
            if child not in seen:
                seen.add(child)
                found.append(child)
                queue.append(child)
    return found


def _libproc_works(pid):
    """Whether an empty libproc answer for `pid` can be believed: libproc has just listed `pid` as this tool's own child, or, when `pid`
    is the tool itself, has just listed the tool as its parent's child. A library that lists nothing for a live process is not working
    (as in a sandbox that denies it)."""
    if pid in (_children_libproc(os.getpid()) or []):
        return True
    return pid == os.getpid() and os.getpid() in (_children_libproc(os.getppid()) or [])


def list_descendants(pid):
    """Every process below `pid` (never one beside it): from /proc where there is one, else from libproc, else from ps (given PS_WAIT
    seconds). libproc is believed when it lists a child; an empty answer is believed only when libproc has just listed this tool's own child
    `pid` (a library that answers nothing for a live child is not working, as in a sandbox that denies it), and otherwise ps is asked. The
    list carries .ident, the identity of each pid from the same reading. Raises TreeNotListed when the processes cannot be listed: that is
    never an empty list."""
    kids, ident = {}, {}
    try:
        if os.path.isdir("/proc/self"):
            started = time.monotonic()
            for entry in os.listdir("/proc"):
                if time.monotonic() - started > TABLE_SECONDS:
                    raise TreeNotListed("reading /proc took more than %d seconds" % TABLE_SECONDS)
                if entry.isdigit():
                    try:
                        with open("/proc/%s/stat" % entry, "rb") as fh:
                            fields = fh.read().rsplit(b")", 1)[1].split()
                        kids.setdefault(int(fields[1]), []).append(int(entry))
                        ident[int(entry)] = ("proc", int(fields[19]))
                    except (OSError, IndexError, ValueError):
                        continue
        else:
            first = _children_libproc(pid)
            if first:
                found, seen, stack = list(first), {pid, *first}, list(first)
                while stack:
                    for child in _children_libproc(stack.pop()) or []:
                        if child not in seen:
                            seen.add(child)
                            found.append(child)
                            stack.append(child)
                listing = _Listing(found)
                listing.ident = {}
                for child in found:
                    started = _libproc_start(child)
                    if started is not None:
                        listing.ident[child] = ("libproc", started)
                return listing
            if first is not None and _libproc_works(pid):
                listing = _Listing()
                listing.ident = {}
                return listing
            for row in _ps_rows("pid=,ppid=,lstart="):
                if len(row) >= 2 and row[0].isdigit() and row[1].isdigit():
                    kids.setdefault(int(row[1]), []).append(int(row[0]))
                    ident[int(row[0])] = ("ps", " ".join(row[2:])) if len(row) >= 6 else ("listed", None)
    except OSError as exc:
        raise TreeNotListed("the processes could not be read: %s" % type(exc).__name__) from exc
    listing = _Listing(_below(kids, pid))
    listing.ident = {child: ident[child] for child in listing if child in ident}
    return listing


def descendants(pid):
    """list_descendants for a caller that cannot take an exception (a signal handler): the same list, but when the tree cannot be listed the
    list is empty, has not_listed = True, and process_notes() says so."""
    try:
        return list_descendants(pid)
    except TreeNotListed as exc:
        _note("the processes below pid %d could not be listed (%s)" % (pid, exc))
        listing = _Listing()
        listing.ident = {}
        listing.not_listed = True
        return listing


def _process_table():
    """{pid: (parent pid, process group)} for every process, from /proc where there is one, else from ps (given PS_WAIT seconds); .ident holds
    each pid's identity from the same reading. Raises TreeNotListed when neither answers."""
    table, ident = _Table(), {}
    try:
        if os.path.isdir("/proc/self"):
            started = time.monotonic()
            for entry in os.listdir("/proc"):
                if time.monotonic() - started > TABLE_SECONDS:
                    raise TreeNotListed("reading /proc took more than %d seconds" % TABLE_SECONDS)
                if entry.isdigit():
                    try:
                        with open("/proc/%s/stat" % entry, "rb") as fh:
                            fields = fh.read().rsplit(b")", 1)[1].split()
                        table[int(entry)] = (int(fields[1]), int(fields[2]))
                        ident[int(entry)] = ("proc", int(fields[19]))
                    except (OSError, IndexError, ValueError):
                        continue
        else:
            for row in _ps_rows("pid=,ppid=,pgid=,lstart="):
                if len(row) >= 3 and all(part.isdigit() for part in row[:3]):
                    table[int(row[0])] = (int(row[1]), int(row[2]))
                    ident[int(row[0])] = ("ps", " ".join(row[3:])) if len(row) >= 8 else ("listed", None)
    except OSError as exc:
        raise TreeNotListed("the processes could not be read: %s" % type(exc).__name__) from exc
    table.ident = ident
    return table


def _sample(pid):
    """Remember what is below `pid` now, by the cheap routes only (/proc, or libproc on macOS; never a program): a process that is seen
    here and later loses its parent is the tool's to end, and one that was never seen is not."""
    try:
        if os.path.isdir("/proc/self"):
            table = _process_table()
            kids = {}
            for child, (parent, _group) in table.items():
                kids.setdefault(parent, []).append(child)
            _seen_below(_below(kids, pid), table.ident)
        else:
            seen, stack = {pid}, [pid]
            while stack:
                for child in _children_libproc(stack.pop()) or []:
                    if child not in seen:
                        seen.add(child)
                        stack.append(child)
            idents = {child: ("libproc", started) for child in seen - {pid} for started in [_libproc_start(child)] if started is not None}
            _seen_below(seen - {pid}, idents)
    except Exception:  # noqa: BLE001 - a sample is best effort
        pass


def _pipe_inodes(proc):
    """The inodes of the pipes the tool holds with `proc` (Linux: /proc names a pipe by it; elsewhere the answer is not used)."""
    found = set()
    for handle in (proc.stdin, proc.stdout, proc.stderr):
        try:
            if handle is not None:
                found.add(os.fstat(handle.fileno()).st_ino)
        except (OSError, ValueError):
            pass
    return found


def _holds_pipe(pid, inodes):
    """Whether `pid` holds one of the pipes (Linux only, from /proc/<pid>/fd): the pipes are private to the tool and what it started."""
    try:
        for name in os.listdir("/proc/%d/fd" % pid):
            try:
                link = os.readlink("/proc/%d/fd/%s" % (pid, name))
            except OSError:
                continue
            if link.startswith("pipe:[") and link.endswith("]") and int(link[6:-1]) in inodes:
                return True
    except (OSError, ValueError):
        pass
    return False


def _same_ident(pid, before, listed):
    """Whether `pid` is still the process `before` was read from. `listed` is the identity the table just read gave it: when it is the same
    kind of identity (a start time from /proc, from libproc or from ps) the two are compared; when it is not (macOS: a process is seen
    through libproc and listed through ps, and the two give different texts for one start time) the pid is read again the way `before` was."""
    if listed is not None and listed[0] == before[0]:
        return listed == before
    return same_process(pid, before)


def reap_orphans(inodes=None):
    """Kill what this tool started and lost: a process of the tool's own group that is no longer below the tool (its parent ended and
    init adopted it, so the walk from a program's pid cannot find it) and that the tool knows to be its own: it was seen below the tool
    (SEEN: the programs it started, the trees it listed, the samples taken while it waited), or, on Linux, it holds one of `inodes`,
    the pipes the tool made. A process the tool never saw in its tree is not touched, whoever leads the group: the next stage of a
    pipeline the tool heads, or a process a launcher put in the group, is not the tool's. A process outside the group is never looked
    at, and a pid is checked against the group, and against the identity it had when it was seen (same_process), at the moment it is
    signalled. Returns the pids signalled; when the processes cannot be listed it signals none and process_notes() says so."""
    me = os.getpid()
    try:
        if os.getpgrp() != me:
            return []
    except OSError:
        return []
    try:
        table = _process_table()
    except TreeNotListed as exc:
        _note("what the tool started and lost could not be looked for: the processes could not be listed (%s)" % exc)
        return []
    kids = {}
    for pid, (parent, _group) in table.items():
        kids.setdefault(parent, []).append(pid)
    below = set(_below(kids, me))
    on_linux = os.path.isdir("/proc/self")
    killed = []
    started = time.monotonic()
    for pid, (_parent, group) in table.items():
        if time.monotonic() - started > TABLE_SECONDS:
            _note("the look for what the tool started and lost was cut after %d seconds" % TABLE_SECONDS)
            break
        if group != me or pid == me or pid in below:
            continue
        listed = table.ident.get(pid)
        holder = False
        if pid in SEEN:
            before = SEEN_IDENT.get(pid)
            if before is not None and not _same_ident(pid, before, listed):
                continue                           # the pid is another process's now: one the tool never saw
        elif inodes and on_linux and _holds_pipe(pid, inodes):
            holder = True
        else:
            continue
        try:
            if os.getpgid(pid) != me:
                continue
            if not same_process(pid, listed) or (holder and not _holds_pipe(pid, inodes)):
                continue
            os.kill(pid, signal.SIGKILL)
            killed.append(pid)
        except OSError:
            pass
    return killed


def _stop_below(root, stopped):
    """Stop (SIGSTOP) every process below `root` as the walk finds it, so one that forks fast cannot outrun the walk, and repeat the walk
    for what the stopped ones had already forked, for at most MAX_ROUNDS rounds and WALK_SECONDS seconds. `stopped` gets {pid: identity}.
    Returns None, or the sentence that says the tree could not be listed or that the walk was cut."""
    began = time.monotonic()
    for _round in range(MAX_ROUNDS):
        try:
            found = list_descendants(root)
        except TreeNotListed as exc:
            return _note("the processes below pid %d could not be listed (%s): the program itself was ended, nothing below it" % (root, exc))
        listed = getattr(found, "ident", None) or {}
        _seen_below(found, listed)
        fresh = [pid for pid in found if pid not in stopped]
        if not fresh:
            return None
        for pid in fresh:
            if not same_process(pid, listed.get(pid)):
                continue
            try:
                os.kill(pid, signal.SIGSTOP)
                stopped[pid] = listed.get(pid)
            except OSError:
                pass
        if time.monotonic() - began > WALK_SECONDS:
            break
    return _note("the walk below pid %d was cut at %d rounds or %d seconds: a process started after it may be running" % (root, MAX_ROUNDS, WALK_SECONDS))


def _end(stopped):
    """Kill the stopped set, each pid only if it is still the process that was stopped."""
    for pid, ident in list(stopped.items()):
        if same_process(pid, ident):
            try:
                os.kill(pid, signal.SIGKILL)
            except OSError:
                pass


def kill_tree(proc):
    """Kill the program and everything it started. The program is stopped first and then each process below it as the walk finds it
    (_stop_below), so the tree does not grow while it is listed; the stopped set is killed after the program. A pid is killed only if it
    is still the process that was listed (same_process). A program already waited for is not touched: its pid is free to be another
    process's, and the walk below it would be that process's children. Returns None, or a sentence when the tree could not be listed or
    the walk was cut."""
    if proc.poll() is not None:
        return None
    try:
        proc.send_signal(signal.SIGSTOP)    # a program that is stopped forks nothing more while its tree is listed
    except OSError:
        pass
    stopped, note = {}, None
    try:
        note = _stop_below(proc.pid, stopped)
    finally:
        try:
            proc.kill()
        except OSError:
            pass
        _end(stopped)
    return note


def wait_for(proc, seconds):
    """(exit code, timed out): wait for the program for at most `seconds`; at the deadline it and what it started are killed."""
    ACTIVE.append(proc)
    try:
        try:
            return proc.wait(timeout=seconds), False
        except subprocess.TimeoutExpired:
            kill_tree(proc)
            return proc.wait(), True
    finally:
        if proc in ACTIVE:
            ACTIVE.remove(proc)


def _stat_row(pid):
    """(state letter, parent pid, identity) of `pid` from /proc/<pid>/stat, or None when it is gone or cannot be read. The identity is the one
    process_ident gives (field 22, counted after the last ")")."""
    try:
        with open("/proc/%d/stat" % pid, "rb") as fh:
            data = fh.read()
        rest = data[data.rindex(b")") + 2:].split()
        return rest[0].decode("ascii", "replace"), int(rest[1]), ("proc", int(rest[19]))
    except (OSError, ValueError, IndexError):
        return None


def _children_of_me():
    """{pid: (state, identity)} of the direct children of this process (Linux). The kernel's own list of each thread's children is read where
    there is one (no scan of every process), and every pid it names is checked against /proc/<pid>/stat; where there is none, /proc is
    scanned. Raises TreeNotListed when /proc cannot be read or takes more than TABLE_SECONDS."""
    me = os.getpid()
    pids = None
    try:
        named = set()
        for tid in os.listdir("/proc/%d/task" % me):
            with open("/proc/%d/task/%s/children" % (me, tid)) as fh:
                named.update(int(part) for part in fh.read().split())
        pids = sorted(named)
    except (OSError, ValueError):
        pids = None
    if pids is None:
        try:
            pids = [int(entry) for entry in os.listdir("/proc") if entry.isdigit()]
        except OSError as exc:
            raise TreeNotListed("the processes could not be read: %s" % type(exc).__name__) from exc
    found, started = {}, time.monotonic()
    for pid in pids:
        if time.monotonic() - started > TABLE_SECONDS:
            raise TreeNotListed("reading /proc took more than %d seconds" % TABLE_SECONDS)
        row = _stat_row(pid)
        if row is not None and row[1] == me:
            found[pid] = (row[0], row[2])
    return found


def _unproven(text):
    """Record why this block cannot say that no program left a process behind (once, at most 20) and return it."""
    if text not in LEFT["unproven"] and len(LEFT["unproven"]) < 20:
        LEFT["unproven"].append(text)
    return text


def become_subreaper():
    """On Linux ask the kernel to make this process the parent of every process a program leaves behind (PR_SET_CHILD_SUBREAPER = 36), so that
    one that left the tool's group or session, or holds none of its descriptors, is a child of the tool and settle() can find it. Called by
    spawn() before the first program; once. PRE_KIDS records the children the tool already had (pid and start time): they are not a program's
    and settle() leaves them. Where the kernel refuses, or the host is not Linux, nothing is adopted: settle() falls back to what the tool
    saw below a program (SEEN), and the answer cannot prove that nothing was left (process_verdict()['unproven']). Returns whether it is on."""
    if SUB["tried"]:
        return SUB["on"]
    SUB["tried"] = True
    if sys.platform.startswith("linux") and ctypes is not None:
        try:
            SUB["on"] = ctypes.CDLL(None, use_errno=True).prctl(36, 1, 0, 0, 0) == 0
        except Exception:  # noqa: BLE001 - no libc symbol, a sandbox: the caller falls back
            SUB["on"] = False
        if SUB["on"]:
            try:
                PRE_KIDS.update({pid: ident for pid, (_state, ident) in _children_of_me().items()})
            except TreeNotListed as exc:
                _unproven(_note("the children the tool already had could not be listed (%s): one of them may be taken for a program's" % exc))
        else:
            _unproven("this host refused PR_SET_CHILD_SUBREAPER: a process a program left behind outside the walk is not adopted and may not be found")
    else:
        reason = "this host cannot adopt orphaned processes (no PR_SET_CHILD_SUBREAPER): a process a program left behind may not be found"
        SUB["note"] = reason              # in process_verdict()["notes"], never in process_notes(): a tool that reads only what a program printed is not made partial by it
        if NONLINUX_UNPROVEN_DOWNGRADE:
            _unproven(reason)
    return SUB["on"]


def process_keep(pid):
    """Let `pid` stay: settle() does not end it. For a process a program leaves on purpose (a daemon the tool stops itself); spawn(argv,
    leaves=True) does it for what that program leaves. A kept process is still ended by a stop signal (kill_all)."""
    ident = process_ident(pid)
    if ident is not None:
        KEEP[pid] = ident


def _exempt(pid, ident, active):
    """Whether the process `pid` (identity `ident`) is the tool's own and not a program's leftover: a program spawn() started (Popen owns it
    and reaps it), one in ACTIVE (`active`, their pids), one kept (KEEP) or one the tool already had (PRE_KIDS). A pid whose identity differs is
    another process that has the number now."""
    if pid in active:
        return True
    for table in (SPAWNED, KEEP, PRE_KIDS):
        if pid in table and (table[pid] is None or (table[pid] == ident if ident is None or table[pid][0] == ident[0] else same_process(pid, table[pid]))):
            return True
    return False


def _victims_children(active):
    """[(pid, state, identity)]: the children of this tool that are no program's own (Linux, with the subreaper on)."""
    return [(pid, state, ident) for pid, (state, ident) in sorted(_children_of_me().items()) if not _exempt(pid, ident, active)]


def _victims_seen(active):
    """[(pid, state, identity)]: where nothing is adopted, the processes that were seen below a program, are still the ones that were seen, and
    have lost their parent (the parent is not the tool and is not a live process the tool saw). Raises TreeNotListed."""
    me = os.getpid()
    candidates = [pid for pid in list(SEEN) if pid != me and SEEN_IDENT.get(pid) is not None and not _exempt(pid, SEEN_IDENT[pid], active)]
    if not candidates:
        return []
    table = _process_table()
    found = []
    for pid in candidates:
        row, listed = table.get(pid), table.ident.get(pid)
        if row is None or not _same_ident(pid, SEEN_IDENT[pid], listed) or row[0] == me:
            continue
        parent = row[0]
        if parent in table and SEEN_IDENT.get(parent) is not None and _same_ident(parent, SEEN_IDENT[parent], table.ident.get(parent)):
            continue                               # its parent is a live process of a program's tree: the program has not ended
        found.append((pid, "S", listed))
    return found


def _stop_under(roots, stopped, deadline):
    """_stop_below for several roots at once with one reading of the processes per round (a program may leave thousands): stop (SIGSTOP)
    every process below any of `roots` as the walk finds it, for at most MAX_ROUNDS rounds, WALK_SECONDS seconds and until `deadline`.
    `stopped` gets {pid: identity}. Returns None, or the sentence that says the tree could not be listed or that the walk was cut."""
    began = time.monotonic()
    for _round in range(MAX_ROUNDS):
        try:
            table = _process_table()
        except TreeNotListed as exc:
            return _unproven(_note("the processes below what a program left behind could not be listed (%s): the leftovers were ended, nothing below them" % exc))
        kids = {}
        for child, (parent, _group) in table.items():
            kids.setdefault(parent, []).append(child)
        fresh = []
        for root in roots:
            fresh.extend(pid for pid in _below(kids, root) if pid not in stopped)
        if not fresh:
            return None
        for pid in fresh:
            ident = table.ident.get(pid)
            if pid not in stopped and same_process(pid, ident):
                try:
                    os.kill(pid, signal.SIGSTOP)
                    stopped[pid] = ident
                except OSError:
                    pass
        if time.monotonic() > min(deadline, began + WALK_SECONDS):
            break
    return _unproven(_note("the walk below what a program left behind was cut at %d rounds or %d seconds: a process started after it may be running" % (MAX_ROUNDS, WALK_SECONDS)))


def _end_counting(stopped):
    """Kill the stopped set, each pid only if it is still the process that was stopped. How many were alive (a zombie was not left running)."""
    alive = 0
    for pid, ident in list(stopped.items()):
        row = _stat_row(pid)
        if not same_process(pid, ident):
            continue
        try:
            os.kill(pid, signal.SIGKILL)
            if row is None or row[0] not in ("Z", "X"):
                alive += 1
        except OSError:
            pass
    return alive


def _end_children(victims, deadline):
    """End the leftovers that are this tool's children: each is stopped (its identity and parent read again first), what it started is stopped
    with it (_stop_under), the set is killed, and the children are reaped (waitpid WNOHANG: the tool is their parent). The clock is read for
    every one, so a program that left thousands is cut at `deadline`, not after a pass. Returns how many live processes were killed."""
    me = os.getpid()
    stopped, reap, cut = {}, [], False
    try:
        for pid, _state, ident in victims:
            if time.monotonic() >= deadline:
                cut = True
                break
            row = _stat_row(pid)
            if row is None or row[1] != me or row[2] != ident:
                continue                           # gone, or not this tool's child any more
            if row[0] in ("Z", "X"):
                reap.append(pid)
                continue
            try:
                os.kill(pid, signal.SIGSTOP)
            except OSError:
                continue
            stopped[pid] = ident
            reap.append(pid)
        _stop_under(list(stopped), stopped, deadline)
    finally:
        alive = _end_counting(stopped)
    pending = set(reap)
    while pending:
        for pid in list(pending):
            try:
                done, _status = os.waitpid(pid, os.WNOHANG)
            except OSError:
                pending.discard(pid)               # not this tool's child (any more): nothing to reap
                continue
            if done:
                pending.discard(pid)
        if not pending:
            break
        if time.monotonic() >= deadline:
            _unproven(_note("%d processes a program left behind did not end within %d seconds" % (len(pending), LEFTOVER_SECONDS)))
            break
        time.sleep(0.005)
    if cut:
        _unproven(_note("a program left more processes than could be ended within %d seconds: some are still running" % LEFTOVER_SECONDS))
    return alive


def _end_seen(victims, deadline):
    """End the leftovers where nothing is adopted: stopped, what they started stopped with them, then killed (each only if it is still the
    process that was seen). Returns how many live processes were killed."""
    stopped = {}
    try:
        for pid, _state, ident in victims:
            if time.monotonic() >= deadline:
                _unproven(_note("a program left more processes than could be ended within %d seconds: some are still running" % LEFTOVER_SECONDS))
                break
            if same_process(pid, ident):
                try:
                    os.kill(pid, signal.SIGSTOP)
                    stopped[pid] = ident
                except OSError:
                    pass
        _stop_under(list(stopped), stopped, deadline)
    finally:
        alive = _end_counting(stopped)
    return alive


def _settle(final):
    active = {proc.pid for proc in list(ACTIVE)}
    if not final and any(proc.poll() is None for proc in list(ACTIVE)):
        _unproven(_note("a program was still running when another one ended: what is left behind cannot be told from what that program started, so nothing was ended"))
        return 0
    deadline = time.monotonic() + LEFTOVER_SECONDS
    victims = _victims_children if SUB["on"] else _victims_seen
    ended, looked = 0, False
    ready = [proc for proc in list(LEAVES.values()) if proc.poll() is not None]
    if ready:
        for proc in ready:                         # a program that leaves a process on purpose: what it left stays
            LEAVES.pop(proc.pid, None)
        for pid, state, ident in victims(active):
            if state not in ("Z", "X"):
                KEEP[pid] = ident
    while True:
        found = victims(active)
        if not found:
            if ended and not looked:
                looked = True                      # one more look after a short pause: a fork that was under way when the first one died
                time.sleep(SETTLE_LOOK)
                continue
            return ended
        if time.monotonic() >= deadline:
            _unproven(_note("%d processes a program left behind were still there after %d seconds: they were not all ended" % (len(found), LEFTOVER_SECONDS)))
            return ended
        ended += (_end_children if SUB["on"] else _end_seen)(found, deadline)
        if not SUB["on"]:
            return ended                           # nothing is adopted: one pass, the processes are not this tool's to reap


def settle(final=False):
    """Look for what the programs this tool ran have left behind, and end it: the processes that are the tool's children and no program's own
    (the subreaper adopted them) are stopped, what they started with them, killed and reaped, for at most LEFTOVER_SECONDS (the clock is read for
    every process, and one more look follows an ending). Never a process of another program: while another program is running in ACTIVE nothing
    is ended and process_verdict() says it is unproven. Never a program spawn() started (Popen owns its exit status: its returncode is never
    taken), nor KEEP, PRE_KIDS or a process outside the tool's own children. final=True is the stop signal's own call (kill_all). Runs on the
    caller's thread, joins none and never raises. Returns how many live processes it ended; process_verdict() holds the totals."""
    if SETTLING[0] and not final:
        return 0
    SETTLING[0] = True
    try:
        ended = _settle(final)
        LEFT["left_behind"] += ended
        return ended
    except Exception as exc:  # noqa: BLE001 - never into the finally of a carrier: say it could not be proven
        _unproven(_note("the look for what a program left behind failed (%s)" % type(exc).__name__))
        return 0
    finally:
        SETTLING[0] = False


def process_verdict():
    """What an answer says about the programs the tool ran: {"subreaper": whether orphans were adopted, "left_behind": how many live processes
    settle() ended, "unproven": why 'nothing was left behind' cannot be claimed (empty when it can), "notes": process_notes()}."""
    return {"subreaper": SUB["on"], "left_behind": LEFT["left_behind"], "unproven": list(LEFT["unproven"]), "notes": process_notes() + ([SUB["note"]] if SUB["note"] else [])}


def process_apply(answer):
    """Put process_verdict() into `answer` as answer["program_group"] and, when a program left a process behind or that cannot be ruled out,
    turn a complete answer into a partial one (status "partial", the ok and complete flags that are there false, a sentence in status_basis;
    a call of communicate_bounded that was cut at POST_EXIT_BYTES counts, PIPE_CUT, and so does one that ended a program whose output passed
    its running cap, OUTPUT_CUT): what a program wrote while the tool read it, or what it printed past a cap, is not a complete result. A
    carrier calls it once where it prints its answer. Returns `answer`."""
    verdict = process_verdict()
    answer["program_group"] = verdict
    if (verdict["left_behind"] > 0 or verdict["unproven"] or PIPE_CUT["cut"] or OUTPUT_CUT["cut"]) and answer.get("status") == "complete":
        answer["status"] = "partial"
        for flag in ("ok", "complete"):
            if flag in answer:
                answer[flag] = False
        if verdict["left_behind"] > 0:
            sentence = "a program left %d process%s running after it ended; the tool ended them, and what they wrote before that is in the files named here" % (
                verdict["left_behind"], "" if verdict["left_behind"] == 1 else "es")
        elif OUTPUT_CUT["cut"]:
            sentence = "a program's output was not read whole: %s" % OUTPUT_CUT["last"]
        elif PIPE_CUT["cut"]:
            sentence = "a process that held a program's pipe after it ended went on writing; the tool read no more than %d bytes of it and let the pipe go" % POST_EXIT_BYTES
        else:
            sentence = "the tool cannot prove that no program left a process behind (see program_group.unproven)"
        basis = answer.get("status_basis")
        answer["status_basis"] = "%s; %s" % (basis, sentence) if isinstance(basis, str) and basis else sentence
    return answer

PIPE_GRACE = 1.0    # seconds the pipes of a program that has ended are given to reach end of file
POST_EXIT_BYTES = 1 << 20    # the most bytes (both pipes together) read from the pipes of a program that has ended
PIPE_CUT = {"cut": 0}        # how many calls stopped reading at POST_EXIT_BYTES because a process still held the pipes and went on writing
STDOUT_CAP = 64 << 20        # the most bytes of standard output one call of communicate_bounded keeps; past it the program is ended and the output is cut
STDERR_CAP = 8 << 20         # the most bytes of standard error one call reads before it ends the program; it keeps the head and the last STDERR_TAIL bytes
STDERR_TAIL = 1 << 20        # the tail of standard error kept once it passes STDERR_CAP (a program's last words are at its end)
OUTPUT_CUT = {"cut": 0, "last": None}    # how many calls cut a stream at its running cap, and the sentence of the last one


class Output(bytes):
    """What communicate_bounded kept of one stream: the bytes, and `cut`, None when the stream was read whole, or a sentence saying it was
    not (the program printed past the stream's cap and was ended there). A caller that parses the output reads `cut` first: a cut output
    is never a whole one."""
    cut = None


def output_cut(*outputs):
    """The sentence of the first of `outputs` (values communicate_bounded or preflight returned) that was cut at its cap; None when each was
    read whole."""
    for out in outputs:
        text = getattr(out, "cut", None)
        if text:
            return text
    return None


def _output(data, cut):
    out = Output(data)
    out.cut = cut
    return out


def communicate_bounded(proc, seconds, input=None, caps=None):
    """(stdout bytes, stderr bytes, timed out) for a program started with pipes, in bytes (Output: bytes with a `cut` sentence or None). At
    `seconds` the program and what it started are killed (timed out). What the tool holds is capped while the program runs: `caps` is
    (stdout cap, stderr cap), STDOUT_CAP and STDERR_CAP when it is None. Standard output is kept to its cap; standard error keeps its head and
    its last STDERR_TAIL bytes (at most half its cap). When either stream passes its cap the program and what it started are ended (kill_tree,
    the deadline's own path: its tree, nothing else), what was kept is returned with `cut` set on that stream, the call is counted in
    OUTPUT_CUT and said in process_notes(), and process_apply turns a complete answer partial. A program that has ended while something it
    started still holds its pipes (a daemon, a helper that inherited them) does not hold the tool: from the moment the program has ended (or
    was killed) the pipes are given PIPE_GRACE seconds and POST_EXIT_BYTES bytes, whichever is used up first; what the program wrote is kept,
    what the tool lost is killed (reap_orphans, settle), and the pipes are let go. A cut at the byte cap is counted in PIPE_CUT and noted
    (process_notes()); the return shape is the same. The pipes are read here and by nothing else (not by Popen.communicate), so letting them
    go is safe. `input` is written while the program runs and is dropped once it has ended."""
    deadline = time.monotonic() + max(0.1, seconds)
    out_cap, err_cap = (STDOUT_CAP, STDERR_CAP) if caps is None else (max(0, int(caps[0])), max(0, int(caps[1])))
    tail_keep = min(STDERR_TAIL, err_cap // 2)
    bufs = (bytearray(), bytearray())       # standard output; the head of standard error
    tail = bytearray()                      # the last tail_keep bytes of standard error read past its head
    seen, over = [0, 0], [False, False]     # bytes read from each stream; the stream passed its cap while the program ran
    late = [False, False]                   # the stream passed its cap after the program had ended (by itself, or at the deadline)
    sel = _selectors.DefaultSelector()
    pending = memoryview(input) if input and proc.stdin is not None else None
    for index, stream in enumerate((proc.stdout, proc.stderr)):
        if stream is not None:
            sel.register(stream, _selectors.EVENT_READ, index)
    if proc.stdin is not None:
        if pending:
            sel.register(proc.stdin, _selectors.EVENT_WRITE, 2)
        else:
            _close_pipe(proc.stdin)
    timed_out, note, ended, extra, cut, sampled, ended_at_cap = False, None, None, 0, False, 0.0, False
    try:
        while True:
            now = time.monotonic()
            if ended is None:
                if proc.poll() is not None:
                    ended = now
                elif over[0] or over[1]:
                    ended_at_cap = True
                    note = kill_tree(proc)
                    ended = time.monotonic()
                elif now >= deadline:
                    timed_out = True
                    note = kill_tree(proc)
                    ended = time.monotonic()
                elif now - sampled >= 0.2:
                    sampled = now
                    _sample(proc.pid)
            if ended is not None:
                if pending is not None:
                    sel.unregister(proc.stdin)
                    _close_pipe(proc.stdin)
                    pending = None
                if not any(key.data != 2 for key in sel.get_map().values()) or extra >= POST_EXIT_BYTES or now - ended >= PIPE_GRACE:
                    cut = extra >= POST_EXIT_BYTES and any(key.data != 2 for key in sel.get_map().values())
                    break
            wait = max(0.01, min(0.2, (deadline if ended is None else ended + PIPE_GRACE) - now))
            if not sel.get_map():
                try:
                    proc.wait(timeout=wait)
                except subprocess.TimeoutExpired:
                    pass
                continue
            for key, _mask in sel.select(wait):
                if key.data == 2:
                    try:
                        pending = pending[os.write(key.fd, pending[:_select.PIPE_BUF]):]
                    except OSError:
                        pending = None
                    if not pending:
                        sel.unregister(proc.stdin)
                        _close_pipe(proc.stdin)
                        pending = None
                    continue
                if ended is not None and extra >= POST_EXIT_BYTES:
                    break
                try:
                    data = os.read(key.fd, 65536 if ended is None else min(65536, POST_EXIT_BYTES - extra))
                except OSError:
                    data = b""
                if not data:
                    sel.unregister(key.fileobj)
                    continue
                index = key.data
                seen[index] += len(data)
                if ended is not None:
                    extra += len(data)
                if index == 0:
                    room = out_cap - len(bufs[0])
                    if room > 0:
                        bufs[0].extend(data[:room])
                    if seen[0] > out_cap:
                        over[0], late[0] = (over[0], True) if ended is not None else (True, late[0])
                else:
                    room = err_cap - tail_keep - len(bufs[1])
                    if room > 0:
                        bufs[1].extend(data[:room])
                        data = data[room:]
                    if data:
                        tail.extend(data)
                        if len(tail) > tail_keep:
                            del tail[:len(tail) - tail_keep]
                    if seen[1] > err_cap:
                        over[1], late[1] = (over[1], True) if ended is not None else (True, late[1])
                if (over[0] or over[1]) and ended is None:
                    break           # the loop's head ends the program at once
        if any(key.data != 2 for key in sel.get_map().values()):
            reap_orphans(_pipe_inodes(proc))
            settle()
    finally:
        sel.close()
        for pipe in (proc.stdin, proc.stdout, proc.stderr):
            _close_pipe(pipe)
    if cut:
        PIPE_CUT["cut"] += 1
        _note("a process that held a program's pipe after the program ended went on writing: the tool read %d bytes more and let the pipe go" % POST_EXIT_BYTES)
    try:
        proc.wait(timeout=PIPE_GRACE)
    except subprocess.TimeoutExpired:
        pass
    settle()
    # A stream that passed its cap only after the program had ended is cut too, unless the pipes were cut at POST_EXIT_BYTES: then what passed
    # it is a process that held the pipe and went on writing, PIPE_CUT says so, and the program's own output was read whole.
    for index in (0, 1):
        over[index] = over[index] or (late[index] and not cut)
    ending = "; the tool ended the program there" if ended_at_cap else ""
    out_cut = ("the program printed more than %d bytes on its standard output; the tool kept the first %d and did not read the rest%s" % (
        out_cap, len(bufs[0]), ending)) if over[0] else None
    err_cut = ("the program printed more than %d bytes on its standard error; the tool kept the first %d and the last %d%s" % (
        err_cap, len(bufs[1]), len(tail), ending)) if over[1] else None
    for sentence in (out_cut, err_cut):
        if sentence:
            OUTPUT_CUT["cut"] += 1
            OUTPUT_CUT["last"] = sentence
            _note(sentence)
    err = bytes(bufs[1])
    if over[1]:
        err += b"\n[... %d bytes of standard error not kept ...]\n" % (seen[1] - len(bufs[1]) - len(tail))
    err += bytes(tail)
    if note:
        err = err + (b"\n" if err else b"") + note.encode("utf-8", "replace")
    return _output(bufs[0], out_cut), _output(err, err_cut), timed_out     # (one copy of standard output, not two)


def _close_pipe(pipe):
    try:
        if pipe is not None:
            pipe.close()
    except (OSError, ValueError):
        pass


def kill_all():
    """End every program the tool has running, with what each started. Then everything below the tool itself, which is the tool's own: a
    program forked a moment before it was entered in ACTIVE is among it. Then what an earlier program started and lost (reap_orphans).
    Returns the sentences for what could not be done (also in process_notes())."""
    notes = []
    for proc in list(ACTIVE):
        note = kill_tree(proc)
        if note:
            notes.append(note)
    stopped = {}
    try:
        note = _stop_below(os.getpid(), stopped)
        if note:
            notes.append(note)
    finally:
        _end(stopped)
    reap_orphans()
    settle(True)     # what the stop ended below the tool is reaped (bounded; settle never raises)
    return notes


def _on_signal(signum, _frame):
    for other in (signal.SIGTERM, signal.SIGINT, signal.SIGHUP):
        signal.signal(other, signal.SIG_IGN)     # the first signal counts: a second one starts no second answer
    kill_all()
    last_word = STATE.get("last_word")
    if last_word:
        try:
            last_word(signum)
        except Exception:  # noqa: BLE001 - a last word is best effort
            pass
    if "answer_a_stop" in globals():     # (a block run on its own, by a test, has no ENDS block)
        answer_a_stop(signum)
    os._exit(128 + signum)


def install_signal_handlers():
    for signum in (signal.SIGTERM, signal.SIGINT, signal.SIGHUP):
        signal.signal(signum, _on_signal)
# END SHARED PROCESS


# BEGIN SHARED HIVE BOUNDS
# The same text is in regkv, shellbags, amcache_apps, userassist_bam_shimcache, persistence_normalise and registry_recover, and in the
# tool-library twins of regkv and amcache_apps (tests/shared-blocks-census.test.ts holds the copies equal).
# A hive of N bytes holds at most N // 76 key cells (an nk cell is at least 76 bytes) and N // 20 value cells (a vk cell is at least 20), however
# many elements an index claims: regipy follows a subkey index (ri) element by element, so one list repeated by an index is read as many times as
# it is repeated (a 61 KB hive listed a million keys and took 1.2 GB). Every list of subkeys and values is read through these bounds, and what is
# past one is said, never followed. The bounds are also of memory: a list keeps only the distinct keys it names, counted by what each takes (its
# record and its name, as stored and as decoded: a name can be 65,535 bytes), and the names of the keys a walk keeps add up to at most twice the
# hive's bytes (key cells that overlap, an element pointing into another key's name, are each read as a key of their own); a value's data is read
# up to VALUE_DATA_BYTES, data that is not wholly inside the file is said and not read, and a key's values are handed out one at a time, at most
# LIST_DATA_BYTES of their names and data. A hive is opened through open_hive, which checks the base block and the root cell before regipy reads
# the file.
import binascii
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
FIXED_VALUE_BYTES = {"REG_DWORD": 4, "REG_QWORD": 8, "REG_FILETIME": 8}   # a value of these types is this many bytes: one that declares more or fewer is not its type's value
HBIN_START = 0x1000                       # a cell offset counts from the end of the hive's 4096-byte base block
SEGMENT_DATA = 0x3FD8                     # the data one big-data segment holds: a value with more is kept in segments that a "db" record lists


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
    string that is not valid UTF-16 began them), so that what is dropped is said."""
    strings, at = [], 0
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
                return strings, len(data) - at, True
        at = end + 2
    tail = data[at:]
    return strings, (len(tail) if tail.strip(b"\x00") else 0), False


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
        """regipy 6.3's NKRecord.iter_values, read from the library's copy of the hive with the same records, names, types and decoding, except
        where its own reading costs without bound: a big data value (a "db" record and its list of segments) is checked before its data is put
        together, and refused when it declares more data than the file holds past its base block, when its list holds fewer segments than its
        size needs, runs past the file or names a segment twice, or when a segment lies outside the file (regipy put together whatever the list
        named: one 16 KB segment named 160 times was a 2.5 MiB value, and a 548 KB hive declared a value of 2 GiB); every value's data and name are
        counted against the walk's budget and the key's (`tally`, which also counts the values regipy itself leaves out) before its data is read,
        and a value that declares more than VALUE_DATA_BYTES is said with its length and not read (a value list naming one 250 MB string four times
        held a gigabyte of text at once); a value whose data is not wholly inside the file (it runs past the end or starts past it), or that
        declares more than the four bytes a record holds, is not read (regipy printed the part inside, or nothing, as the whole value);
        REG_MULTI_SZ is split by multi_strings. A refused value is a problem line and is not in the list."""
        count = node.values_count
        if not count:
            return
        max_len = reg.MAX_LEN if max_len is None else max_len
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
                where_value = "its value %d of the %d its list holds (%s)" % (i + 1, count, vk.data_type)
                kind = int(vk.data_type)
                if kind > 0xFFFF0000:
                    data_type = reg.VALUE_TYPE_ENUM.parse(reg.Int32ul.build(kind & 0xFFFF))
                elif kind == 0x200000:
                    tally["skipped"] += 1        # regipy skips this type without a word
                    continue
                else:
                    data_type = str(vk.data_type)
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
                    big = (size > SEGMENT_DATA and bytes(buf[start:start + 2]) == b"db"
                           and data_type in ("REG_SZ", "REG_EXPAND", "REG_EXPAND_SZ", "REG_BINARY", "REG_NONE", "REG_MULTI_SZ"))
                    if big:
                        segments, why = big_data_segments(buf, start, size, room)
                        if why:
                            problems.append({"where": where, "what": "values", "error": "%s is not read: %s" % (where_value, why)})
                            continue
                    elif size and start + size > end:
                        # data that runs past the end of the file, or starts past it, is not the value: the part inside (or nothing) is not printed as it
                        problems.append({"where": where, "what": "values",
                                         "error": "%s is not read: it declares %d bytes of data at offset %d of a hive file of %d bytes, %s" % (
                                             where_value, size, start, end, "which starts past its end" if start >= end else
                                             "and %d of them are past its end" % (start + size - end))})
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
                if data_type in ("REG_SZ", "REG_EXPAND", "REG_EXPAND_SZ"):
                    value = reg.try_decode_binary(data, as_json=as_json, trim_values=trim_values)
                elif data_type in ("REG_BINARY", "REG_NONE"):
                    if big:
                        value = reg.try_decode_binary(data, as_json=True, trim_values=trim_values) if as_json else data
                    else:
                        value = binascii.b2a_hex(data).decode()[:max_len] if trim_values else data
                elif data_type == "REG_DWORD":
                    value = reg.Int32ul.parse(data)
                elif data_type == "REG_QWORD":
                    value = reg.Int64ul.parse(data)
                elif data_type == "REG_MULTI_SZ":
                    value, dropped, undecodable = multi_strings(data)
                    if dropped:
                        problems.append({"where": where, "what": "values",
                                         "error": ("%s holds a string that is not valid UTF-16: it and the rest of the data, %d byte(s), are not in the answer "
                                                   "(regipy drops them too), the strings before it are" if undecodable else
                                                   "%s ends in %d byte(s) that no NUL ends: they are not in the answer (regipy drops them too), the strings "
                                                   "before them are") % (where_value, dropped)})
                elif data_type in ("REG_RESOURCE_REQUIREMENTS_LIST", "REG_RESOURCE_LIST"):
                    value = binascii.b2a_hex(data).decode()[:max_len] if trim_values else data
                elif data_type == "REG_FILETIME":
                    value = reg.convert_wintime(reg.Int64ul.parse(data), as_json=as_json)
                else:
                    value = reg.try_decode_binary(data, as_json=as_json, trim_values=trim_values)
                yield reg.Value(name=name, value_type=data_type, value=value, is_corrupted=False)


def _library_for(node):
    """regipy's registry module when `node` is its key record over a copy of the hive in memory (what read_values reads), else None (a stand-in)."""
    if not hasattr(getattr(node, "_stream", None), "getbuffer") or not isinstance(getattr(getattr(node, "header", None), "values_list_offset", None), int):
        return None
    try:
        import regipy.registry as reg
        for name in ("VALUE_KEY", "VALUE_TYPE_ENUM", "Int32ul", "Int64ul", "Value", "MAX_LEN", "try_decode_binary", "convert_wintime", "RegistryParsingException",
                     "ConstError", "StreamError"):
            getattr(reg, name)
    except Exception:  # noqa: BLE001 - another library under the name: its own iter_values is read
        return None
    return reg if isinstance(node, reg.NKRecord) else None


def big_data_segments(buf, start, size, room):
    """The (place, length) of each segment of the big data value whose "db" record starts at `start`, or a reason to refuse it. Nothing is read
    but the record and its list: the value is put together by the caller only when every segment is a distinct place inside the file."""
    if size > room:
        return None, "it declares %d bytes of data, more than the %d bytes the hive file holds past its base block" % (size, room)
    end = len(buf)
    if start + 8 > end:
        return None, "its big data record runs past the end of the hive file"
    listed, list_offset = struct.unpack_from("<HI", buf, start + 2)
    needed = -(-size // SEGMENT_DATA)
    if listed < needed:
        return None, "its big data record lists %d segment(s) and %d are needed for the %d bytes it declares" % (listed, needed, size)
    at = HBIN_START + 4 + list_offset
    if at + 4 * needed > end:
        return None, "its list of segments runs past the end of the hive file"
    offsets = struct.unpack_from("<%dI" % needed, buf, at)
    if len(set(offsets)) < needed:
        return None, ("its list of segments names one segment more than once (%d distinct of %d): a list made to read one segment again and again"
                      % (len(set(offsets)), needed))
    segments = []
    for n, offset in enumerate(offsets):
        place, length = HBIN_START + 4 + offset, min(SEGMENT_DATA, size - n * SEGMENT_DATA)
        if place + length > end:
            return None, "its segment %d of %d lies past the end of the hive file" % (n + 1, needed)
        segments.append((place, length))
    return segments, None
# END SHARED HIVE BOUNDS


# ---- small helpers ------------------------------------------------------------------------------------------------------------------

def fail(message, **extra):
    hold_stop_signals()
    if hasattr(signal, "pthread_sigmask"):
        signal.pthread_sigmask(signal.SIG_BLOCK, {signal.SIGTERM, signal.SIGINT, signal.SIGHUP})     # one document: the stop handlers may not be in yet (a refusal can come before main() installs them), and one that is in would write a second, false, document after this one; a stop that arrives while this is written waits, and the tool leaves with it
    forget_temps()
    forget_placed()                      # a refusal is no result: what this run placed before it (pages, a values file, a copy) has no receipt
    print(json.dumps({"ok": False, "error": message, "status": "failed", "status_basis": "the tool stopped with an error (see error); no hive was replayed", **extra}))
    sys.exit(1)


def describe(exc):
    if isinstance(exc, OSError):
        return "%s: %s" % (type(exc).__name__, exc.strerror or exc)
    return "%s: %s" % (type(exc).__name__, exc)


def ft_iso(value):
    """A FILETIME as ISO 8601 UTC with seven fractional digits, by integer arithmetic; None for 0 or a date past year 9999."""
    if not value:
        return None
    try:
        whole, ticks = divmod(int(value), 10_000_000)
        return (FILETIME_EPOCH + datetime.timedelta(seconds=whole)).strftime("%Y-%m-%dT%H:%M:%S") + ".%07dZ" % ticks
    except (OverflowError, ValueError, TypeError):
        return None


CLOCK = {"deadline": None}


def set_deadline(seconds):
    CLOCK["deadline"] = time.monotonic() + seconds


def out_of_time(share=1.0, started=None):
    if CLOCK["deadline"] is None:
        return False
    return time.monotonic() > CLOCK["deadline"]


TEMPS = []                       # temporary files made by this run, removed when it is stopped
PLACED = []                      # files this run has put in their final place that are results only together with the receipt, which is written last


def forget_temps():
    for page in list(PAGES):
        tmp = getattr(page, "_tmp", None)
        if tmp is not None:
            try:
                os.unlink(tmp)
            except OSError:
                pass
    for path in list(TEMPS):
        try:
            os.unlink(path)
        except OSError:
            pass
        TEMPS.remove(path)


def marvin32(chunks, seed=MARVIN_SEED):
    """The 64-bit Marvin32 hash the registry's transaction logs use (the .NET Marvin32 with the 64-bit seed 0x82EF4D887A4E55C5; the
    result is the high state word shifted up 32 beside the low one). `chunks` yields bytes; every piece but the last is a multiple of 4 long."""
    lo, hi = seed & 0xFFFFFFFF, seed >> 32
    pending = b""
    for chunk in chunks:
        data = pending + chunk if pending else chunk
        usable = len(data) - (len(data) % 4)
        pending = data[usable:]
        if not usable:
            continue
        view = memoryview(data)[:usable]
        words = view.cast("I") if sys.byteorder == "little" else (w for (w,) in struct.iter_unpack("<I", view))
        for w in words:
            lo = (lo + w) & 0xFFFFFFFF
            hi ^= lo
            lo = ((lo << 20) | (lo >> 12)) & 0xFFFFFFFF
            lo = (lo + hi) & 0xFFFFFFFF
            hi = ((hi << 9) | (hi >> 23)) & 0xFFFFFFFF
            hi ^= lo
            lo = ((lo << 27) | (lo >> 5)) & 0xFFFFFFFF
            lo = (lo + hi) & 0xFFFFFFFF
            hi = ((hi << 19) | (hi >> 13)) & 0xFFFFFFFF
    tail = 0
    for i, byte in enumerate(pending):
        tail |= byte << (8 * i)
    tail |= 0x80 << (8 * len(pending))
    lo = (lo + tail) & 0xFFFFFFFF
    for _ in range(2):
        hi ^= lo
        lo = ((lo << 20) | (lo >> 12)) & 0xFFFFFFFF
        lo = (lo + hi) & 0xFFFFFFFF
        hi = ((hi << 9) | (hi >> 23)) & 0xFFFFFFFF
        hi ^= lo
        lo = ((lo << 27) | (lo >> 5)) & 0xFFFFFFFF
        lo = (lo + hi) & 0xFFFFFFFF
        hi = ((hi << 19) | (hi >> 13)) & 0xFFFFFFFF
    return (hi << 32) | lo


class TimeLimit(Exception):
    """The tool's own time limit was reached while a long read was in progress."""


def file_chunks(fh, start, length, clock=False):
    fh.seek(start)
    left = length
    while left > 0:
        if clock and out_of_time():
            raise TimeLimit()
        piece = fh.read(min(BLOCK, left))
        if not piece:
            raise OSError("the file ended %d bytes before the range did" % left)
        left -= len(piece)
        yield piece


def base_checksum(block):
    """The base block checksum: the XOR of its first 127 little-endian dwords."""
    total = 0
    for (word,) in struct.iter_unpack("<I", block[:508]):
        total ^= word
    return total & 0xFFFFFFFF


def read_base(fh, size):
    """The fields of a base block (a hive's 4096 bytes, or a log's first 512), and what is wrong with it."""
    fh.seek(0)
    block = fh.read(BASE_BLOCK)
    info = {"bytes_read": len(block), "problems": []}
    if len(block) < LOG_HEADER:
        info["problems"].append("the file is %d bytes, shorter than a 512-byte base block" % size)
        info["signature_ok"] = False
        return info, block
    info["signature_ok"] = block[:4] == b"regf"
    if not info["signature_ok"]:
        info["problems"].append("the file does not start with the 'regf' signature")
        return info, block
    primary, secondary, written, major, minor, ftype, fmt, root, hbs = struct.unpack_from("<IIQIIIIII", block, 4)[0:9]
    info.update({"primary_sequence": primary, "secondary_sequence": secondary, "last_written_filetime": str(written), "last_written": ft_iso(written),
                 "version": "%d.%d" % (major, minor), "file_type": ftype, "format": fmt, "root_cell_offset": root, "hive_bins_data_size": hbs})
    stored = struct.unpack_from("<I", block, 508)[0]
    info["checksum_stored"] = stored
    info["checksum_ok"] = base_checksum(block) == stored
    if not info["checksum_ok"]:
        info["problems"].append("the base block checksum is wrong")
    if len(block) >= 0x94:
        info["flags"] = struct.unpack_from("<I", block, 0x90)[0]
    return info, block


# ---- the logs ---------------------------------------------------------------------------------------------------------------------------

def zero_tail(fh, start, size):
    """Whether the bytes from `start` to `size` are all zero; None when the time limit was reached before they were all read (a sparse log
    of 4 GiB is read block by block, and the clock is looked at between blocks)."""
    fh.seek(start)
    left = size - start
    while left > 0:
        if out_of_time():
            return None
        piece = fh.read(min(BLOCK, left))
        if not piece:
            break
        if piece.count(0) != len(piece):
            return False
        left -= len(piece)
    return True


def iter_refs(fh, e):
    """The page references (hive offset, size) of a well-formed entry, read from the log in blocks: the entry keeps their number and place, never the list."""
    left, at = e["dirty_pages"], e["offset"] + 40
    while left:
        n = min(left, REF_BLOCK)
        fh.seek(at)                                    # the caller reads other parts of the log between two blocks
        raw = fh.read(8 * n)
        if len(raw) != 8 * n:
            raise OSError("the log ended inside the page references of the entry at %d" % e["offset"])
        yield from struct.iter_unpack("<II", raw)
        left -= n
        at += 8 * n


def check_refs(fh, offset, count, hbs, entry_size):
    """Read the page references of the entry at `offset` once, in blocks, and say what is wrong with them (None when nothing is) and the bytes of
    pages they claim. The clock is looked at between blocks."""
    fh.seek(offset + 40)
    left, index, total = count, 0, 0
    while left:
        if out_of_time():
            raise TimeLimit()
        n = min(left, REF_BLOCK)
        raw = fh.read(8 * n)
        if len(raw) != 8 * n:
            return "the log ends inside its page references", total
        for ref_off, ref_size in struct.iter_unpack("<II", raw):
            total += ref_size
            if ref_size == 0 or ref_off + ref_size > hbs:
                return "page reference %d (offset %d, %d bytes) is outside the hive bins data size %d the entry declares" % (index, ref_off, ref_size, hbs), total
            if ref_off % SECTOR or ref_size % SECTOR:
                return "page reference %d (offset %d, %d bytes) does not name whole 512-byte sectors" % (index, ref_off, ref_size), total
            index += 1
        left -= n
    return None, total


def bins_cap(hive_size):
    """The most hive bins data an entry or an old-format log may declare: the bins the hive file really holds plus HBS_GROWTH, and never more than the tool reads."""
    return min(MAX_HIVE_BYTES, max(hive_size - BASE_BLOCK, 0) + HBS_GROWTH)


def entry_flaw(entry_size, count, hbs, cap, off, size):
    """What makes an HvLE entry whose header hash holds unusable, or None. Windows' own readers refuse the same: a size that is not a multiple of 512, no page,
    a hive bins size that is not a positive multiple of 4096. The two bounds are this tool's: it never writes a copy past `cap`, and an entry cannot name more
    pages than the bins it declares have sectors."""
    if entry_size % 512 or entry_size < 512 or entry_size < 40 + 8 * count or off + entry_size > size:
        return "the entry size %d is not a multiple of 512 that holds its %d page references and fits in the file" % (entry_size, count)
    if count == 0:
        return "it lists no page (an entry holds at least one dirty page)"
    if hbs < 4096 or hbs % 4096:
        return "the hive bins data size %d it declares is not a positive multiple of 4096" % hbs
    if hbs > cap:
        return ("it declares %d bytes of hive bins data, more than this tool writes: the hive file's own bins plus %d bytes (%d here), at most %d; "
                "the entry is not applied" % (hbs, HBS_GROWTH, cap, MAX_HIVE_BYTES))
    if count > hbs // SECTOR:
        return "it lists %d page references, more than the %d 512-byte sectors of the %d bytes of bins it declares" % (count, hbs // SECTOR, hbs)
    return None


def scan_hvle(fh, size, cap):
    """The entries of a new-format log, in file order, each with what its header says; the scan stops at the first thing that is not a
    well-formed entry and says what the bytes from there on are. An entry keeps the number of its page references and where they are
    in the log, not the references (they are read again where they are used). The clock is looked at for every entry and every block of references."""
    entries, off, trailing = [], LOG_HEADER, None
    while off + 40 <= size:
        if len(entries) >= MAX_LOG_ENTRIES:
            trailing = {"offset": off, "bytes": size - off, "reason": "more than %d entries: the scan stopped; the entries from here on were not read" % MAX_LOG_ENTRIES, "all_zero": False}
            break
        if out_of_time():
            trailing = {"offset": off, "bytes": size - off, "reason": "the time limit was reached while the log was scanned: the entries from here on were not read", "all_zero": False, "time_limit": True}
            break
        fh.seek(off)
        head = fh.read(40)
        if head[:4] != b"HvLE":
            trailing = {"offset": off, "bytes": size - off, "reason": "no HvLE signature at this offset", "all_zero": zero_tail(fh, off, size)}
            break
        entry_size, flags, seq, hbs, count, hash1, hash2 = struct.unpack_from("<IIIIIQQ", head, 4)
        e = {"index": len(entries), "offset": off, "size": entry_size, "sequence": seq, "flags": flags, "hive_bins_data_size": hbs, "dirty_pages": count,
             "header_hash_ok": marvin32([head[:32]]) == hash2, "pages_hash_ok": None, "valid": False}
        entries.append(e)
        if not e["header_hash_ok"]:
            e["reason"] = "the header hash (hash-2) is wrong"
        else:
            flaw = entry_flaw(entry_size, count, hbs, cap, off, size)
            if flaw:
                e["reason"] = flaw
            else:
                try:
                    bad, total = check_refs(fh, off, count, hbs, entry_size)
                except TimeLimit:
                    trailing = {"offset": off, "bytes": size - off, "reason": "the time limit was reached while the page references of the entry at this offset were read: it and the entries after it were not read",
                                "all_zero": False, "time_limit": True}
                    e["reason"] = "the time limit was reached while its page references were read"
                    break
                if bad is None and 40 + 8 * count + total > entry_size:
                    bad = "its page references claim %d bytes of pages, more than the entry holds" % total
                if bad:
                    e["reason"] = bad
                else:
                    e["valid"] = True
                    e["page_bytes"] = total
                    e["pages_at"] = off + 40 + 8 * count
                    # Hash-1 is checked here, in file order: Windows reads a log's entries up to the first one whose pages hash is wrong and
                    # none after it, so an entry past a bad one is not this log's, whatever its sequence number (an entry after it that the
                    # other log's entries bridged to was applied, and the answer could say complete).
                    try:
                        verify_pages(fh, e)
                    except TimeLimit:
                        e["valid"] = False
                        e["reason"] = "the time limit was reached while its pages hash was checked"
                        trailing = {"offset": off, "bytes": size - off, "reason": "the time limit was reached while the pages hash of the entry at this offset was checked: it and the "
                                    "entries after it were not read", "all_zero": False, "time_limit": True}
                        break
        if not e["valid"]:
            trailing = {"offset": off, "bytes": size - off, "reason": "the entry at this offset cannot be used (%s); nothing after it is read" % e["reason"], "all_zero": False}
            break
        off += entry_size
    if trailing is None and off < size:
        trailing = {"offset": off, "bytes": size - off, "reason": "fewer than 40 bytes follow the last entry", "all_zero": zero_tail(fh, off, size)}
    return entries, trailing


def verify_pages(fh, e):
    """Hash-1 of an entry: the Marvin32 hash of everything after its 40-byte header up to its size."""
    if e["pages_hash_ok"] is None:
        stored = struct.unpack("<Q", read_at(fh, e["offset"] + 24, 8))[0]
        e["pages_hash_ok"] = marvin32(file_chunks(fh, e["offset"] + 40, e["size"] - 40, clock=True)) == stored
        if not e["pages_hash_ok"]:
            e["valid"] = False
            e["reason"] = "the pages hash (hash-1) is wrong"
    return e["pages_hash_ok"]


def read_at(fh, offset, length):
    fh.seek(offset)
    data = fh.read(length)
    if len(data) != length:
        raise OSError("short read at %d" % offset)
    return data


def old_format_layout(fh, size, hbs):
    """Where the dirty sectors of an old-format log start, and which sectors the DIRT vector says are dirty: the vector holds one bit for
    each 512-byte sector of the hive bins and is padded, with its 4-byte signature, to a whole sector."""
    vector_bytes = (hbs // 512 + 7) // 8
    data_start = LOG_HEADER + ((4 + vector_bytes + 511) // 512) * 512
    fh.seek(LOG_HEADER)
    raw = fh.read(4 + vector_bytes)
    if len(raw) < 4 + vector_bytes:
        return None
    marked = sum(bin(byte).count("1") for byte in raw[4:])
    if data_start + marked * SECTOR > size:
        return None                                    # the vector marks more sectors than the log holds: nothing is listed from it
    sectors = [i for i in range(vector_bytes * 8) if raw[4 + i // 8] >> (i % 8) & 1]
    return {"vector_bytes": vector_bytes, "data_start": data_start, "sectors": sectors}


def examine_log(path, role, hive, cap):
    """Everything the replay needs to know about one log, and its receipt entry. `cap` is the most hive bins data a log may declare (bins_cap)."""
    log = {"role": role, "path": path, "problems": []}
    try:
        st = os.stat(path)
    except OSError as exc:
        log["problems"].append("could not be examined: %s" % describe(exc))
        log["usable"] = False
        return log, None
    if not stat.S_ISREG(st.st_mode):
        log["problems"].append("is not a regular file, so it was not opened")
        log["usable"] = False
        return log, None
    log["bytes"] = st.st_size
    if st.st_size > MAX_HIVE_BYTES:
        log["problems"].append("is larger than the %d bytes this tool reads" % MAX_HIVE_BYTES)
        log["usable"] = False
        return log, None
    fh = open(path, "rb")
    try:
        base, block = read_base(fh, st.st_size)
        log["base_block"] = {k: v for k, v in base.items() if k != "problems"}
        log["problems"] += base["problems"]
        if not base["signature_ok"]:
            log["format"] = "not a log"
            log["usable"] = False
            fh.close()
            return log, None
        if base.get("file_type") == 0:
            log["problems"].append("its base block says it is a primary hive (file type 0), not a transaction log: it is not used")
            log["format"] = "not a log"
            log["usable"] = False
            fh.close()
            return log, None
        magic = read_at(fh, LOG_HEADER, 4) if st.st_size >= LOG_HEADER + 4 else b""
        if magic == b"HvLE" and base.get("file_type") == 1:
            log["problems"].append("its base block says it is an old-format log (file type 1) but HvLE entries follow it: the two contradict each other, so it is not used")
            log["format"] = "not a log"
            log["usable"] = False
            fh.close()
            return log, None
        if magic == b"HvLE":
            log["format"] = "new (HvLE entries)"
            entries, trailing = scan_hvle(fh, st.st_size, cap)
            log["entry_count"] = len(entries)
            log["trailing"] = trailing
            log["usable"] = True
            return log, {"fh": fh, "kind": "hvle", "entries": entries, "base": base, "block": bytes(block[:LOG_HEADER])}
        if magic == b"DIRT":
            log["format"] = "old (DIRT vector)"
            hbs = hive.get("hive_bins_data_size") or 0
            if hbs < 4096 or hbs % 4096 or hbs > cap:
                log["problems"].append("an old-format log is read against the hive bins data size the hive declares (%d); it is not a positive multiple of 4096 or is more than this tool "
                                       "handles for a hive file of this size (%d), so the log's DIRT vector is not read" % (hbs, cap))
                log["usable"] = False
                fh.close()
                return log, None
            layout = old_format_layout(fh, st.st_size, hbs)
            if layout is None:
                log["problems"].append("is shorter than the DIRT vector the hive's size needs, or its vector marks more sectors dirty than the log holds")
                log["usable"] = False
                fh.close()
                return log, None
            log["usable"] = True
            log["dirty_sectors"] = len(layout["sectors"])
            return log, {"fh": fh, "kind": "dirt", "layout": layout, "base": base}
        log["format"] = "empty" if st.st_size <= LOG_HEADER or zero_tail(fh, LOG_HEADER, st.st_size) else "unknown"
        log["problems"].append("holds no HvLE entry and no DIRT vector after its base block (%s)" % ("only zeros follow it" if log["format"] == "empty" else "the bytes there are neither"))
        log["usable"] = False
        fh.close()
        return log, None
    except Exception:
        fh.close()
        raise


def entry_view(e):
    return {"index": e["index"], "offset": e["offset"], "size": e["size"], "sequence": e["sequence"], "dirty_pages": e["dirty_pages"],
            "hive_bins_data_size": e["hive_bins_data_size"], "header_hash_ok": e["header_hash_ok"], "pages_hash_ok": e["pages_hash_ok"],
            "state": e.get("state", "not examined"), **({"reason": e["reason"]} if e.get("reason") else {})}


# ---- the replay -------------------------------------------------------------------------------------------------------------------------

def plan_hvle(hive, parsed, receipt_logs):
    """Which entries to apply, in order. Returns (steps, expected_after, notes): steps are (log role, entry)."""
    start = hive["secondary_sequence"]
    expected = start
    steps, notes, timed_out = [], [], []
    by_seq = {}
    for role, p in parsed.items():
        if p["kind"] != "hvle":
            continue
        for e in p["entries"]:
            by_seq.setdefault(e["sequence"], []).append((role, e))
    current = None
    while True:
        choices = sorted(by_seq.get(expected, []), key=lambda c: (c[0] != current, c[0]))
        taken = None
        for role, e in choices:
            if not e["valid"]:
                continue
            try:
                good = verify_pages(parsed[role]["fh"], e)
            except TimeLimit:
                e["state"] = "not applied: the time limit was reached while its pages hash was being checked"
                timed_out.append(e["sequence"])
                return steps, start, expected, notes, timed_out
            if not good:
                e["state"] = "not applied: the pages hash is wrong"
                continue
            taken = (role, e)
            break
        if taken is None:
            for role, e in choices:
                if e["valid"] is False and e.get("state") is None:
                    e["state"] = "not applied: " + e.get("reason", "not valid")
            break
        role, e = taken
        e["state"] = "applied"
        steps.append((role, e))
        others = [c for c in choices if c[1] is not e and c[1]["valid"]]
        if others:
            notes.append("the other log holds an entry of sequence %d too; the one in the log the replay was already in (or the first named) was used" % expected)
        current = role
        expected = (expected + 1) & 0xFFFFFFFF        # a sequence number is 32 bits: the one after 0xFFFFFFFF is 0
    return steps, start, expected, notes, timed_out


def discard_temp(name):
    try:
        os.unlink(name)
    except OSError:
        pass
    if name in TEMPS:
        TEMPS.remove(name)


def fresh_copy(src_path, dest, size):
    """A copy of the hive made in blocks (never read whole), opened for writing. The clock is looked at between blocks; a copy that is not finished is removed."""
    fd, name = tempfile.mkstemp(dir=dest.parent, prefix=".recovered-")
    TEMPS.append(name)
    try:
        with os.fdopen(fd, "wb") as out, open(src_path, "rb") as src:
            for piece in file_chunks(src, 0, size, clock=True):
                out.write(piece)
    except BaseException:
        discard_temp(name)
        raise
    return Path(name)


class Growth:
    """Which 512-byte sectors of the hive bins the copy did not have before the replay (from `lo` up to `hi`) an applied page writes: a bitmap of at most
    HBS_GROWTH / 512 bytes, whatever the log holds. What no page writes is zeros in the copy."""

    def __init__(self, lo, hi):
        self.lo, self.hi = lo, hi
        self.first = lo // SECTOR
        self.marks = bytearray(max((hi + SECTOR - 1) // SECTOR - self.first, 0))

    def add(self, offset, size):
        a = max(offset // SECTOR, self.first)
        b = min((offset + size + SECTOR - 1) // SECTOR, self.first + len(self.marks))
        if a < b:
            self.marks[a - self.first:b - self.first] = b"\x01" * (b - a)

    def gaps(self):
        """[(start, end)] of the uncovered bytes of [lo, hi), in order."""
        out, start = [], None
        for i, mark in enumerate(self.marks):
            if not mark and start is None:
                start = i
            elif mark and start is not None:
                out.append((start, i))
                start = None
        if start is not None:
            out.append((start, len(self.marks)))
        return [(max((self.first + a) * SECTOR, self.lo), min((self.first + b) * SECTOR, self.hi)) for a, b in out]


def write_pages(out_fh, log_fh, e, growth):
    """Copy an entry's pages to their places in the working copy, in blocks; the clock is looked at between references and between blocks."""
    at = e["pages_at"]
    for n, (ref_off, ref_size) in enumerate(iter_refs(log_fh, e)):
        if n % 256 == 255 and out_of_time():
            raise TimeLimit()
        out_fh.seek(BASE_BLOCK + ref_off)
        for piece in file_chunks(log_fh, at, ref_size, clock=True):
            out_fh.write(piece)
        if growth is not None:
            growth.add(ref_off, ref_size)
        at += ref_size


def merge_ranges(ranges):
    merged = []
    for start, length in sorted(ranges):
        if merged and start <= merged[-1][0] + merged[-1][1]:
            merged[-1][1] = max(merged[-1][1], start + length - merged[-1][0])
        else:
            merged.append([start, length])
    return [{"hive_offset": s, "bytes": n} for s, n in merged]


def hive_ranges_of(fh, e, budget):
    """(hive ranges, extra fields) of an entry's pages as the receipt lists them: at most LISTED_RANGES references of one entry and RANGE_BUDGET of the whole
    receipt are listed; the rest are counted and named by where they are in the log (their number, and the offset of the first), so nothing is lost with
    the log in hand."""
    if not e["valid"]:
        return [], {}
    count = e["dirty_pages"]
    wanted = max(min(count, LISTED_RANGES, budget["left"]), 0)
    refs = []
    if wanted:
        for ref in iter_refs(fh, e):
            refs.append(ref)
            if len(refs) >= wanted:
                break
    budget["left"] -= len(refs)
    extra = {}
    if len(refs) < count:
        extra = {"hive_ranges_not_listed": count - len(refs),
                 "page_references": {"log_offset": e["offset"] + 40, "count": count, "bytes_each": 8, "layout": "offset and size, two little-endian 32-bit numbers, from the start of the hive bins data"}}
    return merge_ranges(refs), extra


def unrecovered_entry(role, e, why, fh, budget):
    ranges, extra = hive_ranges_of(fh, e, budget)
    return {"log": role, "entry": e["index"], "sequence": e["sequence"], "why": why, "hive_ranges": ranges, "log_range": {"offset": e["offset"], "bytes": e["size"]}, **extra}


def replay(hive_path, hive_size, hive, logs, out_dir):
    """The whole replay. Returns the receipt part, and the path of the working copy when something was applied."""
    receipt = {"performed": False, "reason": None, "order": [], "entries_applied": 0, "pages_applied": 0, "bytes_applied": 0}
    unrecovered, log_receipts, parsed = [], [], {}
    cap = bins_cap(hive_size)
    receipt["bounds"] = {"hive_bins_data_size_cap": cap, "max_log_entries": MAX_LOG_ENTRIES, "listed_ranges_per_entry": LISTED_RANGES}
    budget = {"left": RANGE_BUDGET}
    time_notes = []
    seen_files = {}
    for role, path in logs:
        same_as = None
        try:
            sx = os.stat(path)
            if stat.S_ISREG(sx.st_mode):
                key = (sx.st_dev, sx.st_ino)
                same_as = seen_files.get(key)
                seen_files.setdefault(key, role)
        except OSError:
            pass
        if same_as is not None:
            # One file named twice is one log: it is read once, under the role it was named first, and said.
            info, handle = {"role": role, "path": path, "format": "same file as %s" % same_as, "usable": False,
                            "problems": ["is the same file as %s (one file was named as both logs): it is read once, as %s, and not again" % (same_as, same_as)]}, None
        else:
            info, handle = examine_log(path, role, hive, cap)
        log_receipts.append(info)
        if handle is not None:
            parsed[role] = handle
        if (info.get("trailing") or {}).get("time_limit"):
            time_notes.append("the time limit was reached while %s was scanned: %s" % (role, info["trailing"]["reason"]))
    dirty = hive.get("signature_ok") and hive["primary_sequence"] != hive["secondary_sequence"]
    receipt["dirty_before"] = bool(dirty)
    receipt["sequence_before"] = [hive.get("primary_sequence"), hive.get("secondary_sequence")]
    steps, working = [], None
    start = expected = None
    try:
        hvle_roles = [r for r, p in parsed.items() if p["kind"] == "hvle"]
        if not hive.get("signature_ok"):
            receipt["reason"] = "the hive has no 'regf' base block, so there is nothing to replay on"
        elif not dirty:
            receipt["reason"] = "the hive is clean (both sequence numbers are %d): nothing is replayed" % hive["primary_sequence"]
            for role in hvle_roles:
                for e in parsed[role]["entries"]:
                    if e["sequence"] >= hive["primary_sequence"]:
                        e["state"] = "not applied: newer than a clean hive (Windows does not replay a clean hive's logs)"
                        unrecovered.append(unrecovered_entry(role, e, e["state"][13:], parsed[role]["fh"], budget))
                    else:
                        e["state"] = "not needed: older than the clean hive's state"
        elif not parsed:
            receipt["reason"] = "the hive is dirty and no log that could be read was named: nothing is replayed"
        else:
            if hvle_roles:
                steps, start, expected, notes, timed_out = plan_hvle(hive, parsed, log_receipts)
                receipt["notes"] = notes
                if timed_out:
                    time_notes.append("the time limit was reached while the pages hash of the entry of sequence %d was checked: nothing after it was examined" % timed_out[0])
            dirt_roles = [r for r, p in parsed.items() if p["kind"] == "dirt"]
            dirt_applied = None
            for role in dirt_roles:
                b = parsed[role]["base"]
                lhbs = b.get("hive_bins_data_size") or 0
                ok = b.get("checksum_ok") and b["primary_sequence"] == b["secondary_sequence"] == hive["primary_sequence"]
                sized = 4096 <= lhbs <= cap and lhbs % 4096 == 0
                parsed[role]["state"] = "applied" if ok and sized and dirt_applied is None and not steps else None
                if not ok:
                    parsed[role]["why"] = ("its own sequence numbers (%s, %s) are not equal to each other and to the hive's primary sequence number (%s), or its base block checksum is wrong"
                                           % (b.get("primary_sequence"), b.get("secondary_sequence"), hive["primary_sequence"]))
                elif not sized:
                    parsed[role]["why"] = ("it declares %d bytes of hive bins data, which is not a positive multiple of 4096 or is more than this tool writes for a hive file of this size (%d)" % (lhbs, cap))
                elif steps:
                    parsed[role]["why"] = "a new-format log was applied; an old-format log is not mixed with it"
                elif dirt_applied is not None:
                    parsed[role]["why"] = "another old-format log was applied"
                else:
                    dirt_applied = role
            if steps or dirt_applied:
                made = None
                try:
                    working = made = fresh_copy(hive_path, out_dir, hive_size)
                    if steps:
                        new_hbs = steps[-1][1]["hive_bins_data_size"]
                    else:
                        new_hbs = parsed[dirt_applied]["base"]["hive_bins_data_size"]
                    with open(working, "r+b") as out_fh:
                        before = os.fstat(out_fh.fileno()).st_size
                        wanted = BASE_BLOCK + new_hbs
                        growth = Growth(max(before - BASE_BLOCK, 0), new_hbs) if before < wanted else None
                        if steps:
                            for role, e in steps:
                                if out_of_time():
                                    raise TimeLimit()
                                write_pages(out_fh, parsed[role]["fh"], e, growth)
                                receipt["order"].append({"log": role, "entry": e["index"], "sequence": e["sequence"], "pages": e["dirty_pages"], "page_bytes": e["page_bytes"]})
                                receipt["entries_applied"] += 1
                                receipt["pages_applied"] += e["dirty_pages"]
                                receipt["bytes_applied"] += e["page_bytes"]
                            final = expected
                        else:
                            p = parsed[dirt_applied]
                            layout = p["layout"]
                            at = layout["data_start"]
                            for n, sector in enumerate(layout["sectors"]):
                                if n % 1024 == 1023 and out_of_time():
                                    raise TimeLimit()
                                out_fh.seek(BASE_BLOCK + sector * SECTOR)
                                out_fh.write(read_at(p["fh"], at, SECTOR))
                                if growth is not None:
                                    growth.add(sector * SECTOR, SECTOR)
                                at += SECTOR
                            final = hive["primary_sequence"]
                            receipt["order"].append({"log": dirt_applied, "dirty_sectors": len(layout["sectors"])})
                            receipt["entries_applied"] = 1
                            receipt["pages_applied"] = len(layout["sectors"])
                            receipt["bytes_applied"] = len(layout["sectors"]) * SECTOR
                        if growth is not None:
                            out_fh.truncate(wanted) if out_fh.seek(0, 2) < wanted else None
                            gaps = growth.gaps()
                            if gaps:
                                shown = [{"hive_offset": a, "bytes": b - a} for a, b in gaps[:LISTED_RANGES]]
                                row = {"log": None, "why": "the working copy had %d bytes of hive bins and the log declares %d; no applied page writes these ranges, which are zeros" % (growth.lo, new_hbs),
                                       "hive_ranges": shown}
                                if len(gaps) > len(shown):
                                    row["hive_ranges_not_listed"] = len(gaps) - len(shown)
                                    row["hive_ranges_note"] = "the ranges past these are the sectors from %d up to %d that no applied page writes" % (growth.lo, new_hbs)
                                unrecovered.append(row)
                        out_fh.seek(0)
                        block = bytearray(out_fh.read(BASE_BLOCK))
                        changed = ["primary_sequence", "secondary_sequence", "hive_bins_data_size", "checksum"]
                        struct.pack_into("<II", block, 4, final, final)
                        struct.pack_into("<I", block, 40, new_hbs)
                        if steps and len(block) >= 0x94:
                            # What the log carries for the base block (Suhanov's recovery of a primary file; yarp does the same): the root cell offset and the last-written time are
                            # the log's, and the flags are those of the last applied entry. A log whose own base block checksum is wrong is not believed.
                            last_role, last_entry = steps[-1]
                            lbase, lblock = parsed[last_role]["base"], parsed[last_role]["block"]
                            if lbase.get("signature_ok") and lbase.get("checksum_ok") and len(lblock) >= 0x28:
                                was = {"root_cell_offset": struct.unpack_from("<I", block, 0x24)[0], "last_written_filetime": struct.unpack_from("<Q", block, 0x0C)[0], "flags": struct.unpack_from("<I", block, 0x90)[0]}
                                now = {"root_cell_offset": struct.unpack_from("<I", lblock, 0x24)[0], "last_written_filetime": struct.unpack_from("<Q", lblock, 0x0C)[0], "flags": last_entry["flags"]}
                                struct.pack_into("<I", block, 0x24, now["root_cell_offset"])
                                struct.pack_into("<Q", block, 0x0C, now["last_written_filetime"])
                                struct.pack_into("<I", block, 0x90, now["flags"])
                                for field, label in (("root_cell_offset", "root_cell_offset"), ("last_written_filetime", "last_written"), ("flags", "flags")):
                                    if was[field] != now[field]:
                                        changed.append(label)
                                receipt["base_block_from_log"] = {
                                    "log": last_role, "taken": True,
                                    "root_cell_offset": {"original": was["root_cell_offset"], "recovered": now["root_cell_offset"]},
                                    "last_written": {"original": ft_iso(was["last_written_filetime"]), "recovered": ft_iso(now["last_written_filetime"])},
                                    "flags": {"original": was["flags"], "recovered": now["flags"]},
                                    "source": "root cell offset and last-written time: the base block of the log that holds the last applied entry; flags: that entry's own flags field"}
                            else:
                                receipt["base_block_from_log"] = {"log": last_role, "taken": False, "why": "the base block of this log has a wrong signature or checksum, so its root cell offset, "
                                                                  "last-written time and the entry's flags were not written into the copy: they are the original's"}
                        struct.pack_into("<I", block, 508, base_checksum(bytes(block)))
                        out_fh.seek(0)
                        out_fh.write(block)
                        out_fh.flush()
                        os.fsync(out_fh.fileno())
                except TimeLimit:
                    if made is not None:
                        discard_temp(str(made))
                    working = None
                    time_notes.append("the time limit was reached while the recovered copy was being made: no copy exists, and the entries that would have been applied are listed as not applied")
                    for role, e in steps:
                        e["state"] = "not applied: the time limit was reached before the recovered copy was complete"
                    if dirt_applied is not None:
                        parsed[dirt_applied]["state"] = None
                        parsed[dirt_applied]["why"] = "the time limit was reached before the recovered copy was complete"
                    receipt.update({"entries_applied": 0, "pages_applied": 0, "bytes_applied": 0, "order": []})
                    unrecovered[:] = [u for u in unrecovered if u.get("log") is not None]
                    receipt["reason"] = time_notes[-1]
                    steps = []
                else:
                    receipt["performed"] = True
                    receipt["sequence_after"] = [final, final]
                    receipt["dirty_after"] = False
                    receipt["hive_bins_data_size"] = {"before": hive["hive_bins_data_size"], "after": new_hbs}
                    receipt["base_block_fields_changed"] = changed
            else:
                receipt["reason"] = ("the hive is dirty (sequence %d / %d) and the time limit was reached while the logs were scanned, before an applicable entry was found"
                                     if time_notes else "the hive is dirty (sequence %d / %d) and no named log holds an applicable entry") % (hive["primary_sequence"], hive["secondary_sequence"])
        if time_notes:
            receipt["time_limit"] = "; ".join(time_notes)
        # What was not applied, with the hive ranges its pages would have written.
        for role in hvle_roles:
            for e in parsed[role]["entries"]:
                if e.get("state") is None:
                    if e["valid"] is False:
                        e["state"] = "not applied: " + e.get("reason", "not valid")
                    elif dirty and start is not None and e["sequence"] < start:
                        e["state"] = "not needed: older than the state the hive was at (sequence %d)" % start
                    elif dirty and start is not None:
                        e["state"] = "not applied: its sequence number %d does not follow the last applied entry (the next needed is %d)" % (e["sequence"], expected)
                    else:
                        e["state"] = "not applied"
                if e["state"].startswith("not applied") and not (not dirty):
                    unrecovered.append(unrecovered_entry(role, e, e["state"][len("not applied: "):], parsed[role]["fh"], budget))
        for info in log_receipts:
            p = parsed.get(info["role"])
            if p is not None and p["kind"] == "hvle":
                info["entries"] = [entry_view(e) for e in p["entries"]]
                info["entries_applied"] = sum(1 for e in p["entries"] if e.get("state") == "applied")
                tr = info.get("trailing")
                if tr and not tr["all_zero"]:
                    unrecovered.append({"log": info["role"], "why": "bytes after the last well-formed entry are not an entry: %s" % tr["reason"], "hive_ranges": [],
                                        "log_range": {"offset": tr["offset"], "bytes": tr["bytes"]}})
            elif p is not None and p["kind"] == "dirt":
                info["state"] = p.get("state") or "not applied"
                if p.get("why"):
                    info["why_not_applied"] = p["why"]
                    if dirty:
                        unrecovered.append({"log": info["role"], "why": p["why"], "hive_ranges": [], "log_range": {"offset": 0, "bytes": info.get("bytes")}})
    finally:
        for p in parsed.values():
            p["fh"].close()
    return receipt, log_receipts, unrecovered, working


# ---- the typed key and value records ----------------------------------------------------------------------------------------------------

SAM_USER_KEY = re.compile(r"\\domains\\account\\users\\[0-9a-f]{8}\\$")
SAM_USER_SECRET_VALUES = ("v", "supplementalcredentials")
CACHED_LOGON = re.compile(r"^NL\$", re.I)
SECRET_PLACES = ("\\policy\\secrets\\", "\\policy\\poleklist\\", "\\policy\\polsecretencryptionkey\\")


class CellGuard:
    """Stands in for one of regipy's record layouts (the key node `nk` and the value key `vk`) and checks what the record declares against the cell it was read
    from. regipy reads a name as long as the record says, whether or not the cell is that long, so a damaged length reads the next cell: the bytes of
    whatever is stored there, a withheld value's data among them, ended up in key paths and names. A name longer than its cell is not believed: the record is
    given a name that says where it is (`[name withheld: ...]`, hive offset and the numbers, none of the bytes), and a value data size longer than its data
    cell is cut at the cell. Each is listed in CELL_DAMAGE for the walk to name."""

    MARK = "[name withheld: "

    def __init__(self, real, kind):
        self.real, self.kind = real, kind

    def parse_stream(self, stream):
        start = stream.tell()
        rec = self.real.parse_stream(stream)
        end = stream.tell()
        try:
            self.check(stream, start, rec)
        finally:
            stream.seek(end)
        return rec

    @staticmethod
    def cell_size(stream, at):
        stream.seek(at)
        raw = stream.read(4)
        return abs(struct.unpack("<i", raw)[0]) if len(raw) == 4 else None

    def check(self, stream, start, rec):
        if self.kind == "nk":
            cell_at, fixed, declared = start - 6, 6 + 74, rec.key_name_size
        else:
            cell_at, fixed, declared = start - 4, 4 + 20, rec.name_size
        if cell_at < 0:
            return
        size = self.cell_size(stream, cell_at)
        if size is None:
            return
        if declared > max(size - fixed, 0):
            mark = ("%s%s at hive offset 0x%x declares %d name bytes in a %d-byte cell]" % (self.MARK, self.kind, cell_at, declared, size)).encode("ascii")
            if self.kind == "nk":
                rec["key_name_string"], rec["key_name_size"] = mark, len(mark)
                rec.flags.KEY_COMP_NAME = True
            else:
                rec["name"], rec["name_size"] = mark, len(mark)
                rec.flags.VALUE_COMP_NAME = True
            CELL_DAMAGE.append("a %s record at hive offset 0x%x declares a name of %d bytes in a cell of %d bytes: its name is withheld, none of the bytes past the cell are read" % (self.kind, cell_at, declared, size))
        if self.kind == "vk" and 0 < rec.data_size < 0x80000000:          # 0x80000000 and up: the data is inside the record itself
            data_cell = 4096 + rec.data_offset
            dsize = self.cell_size(stream, data_cell)
            big = rec.data_size > 0x3FD8 and stream.read(2) == b"db"       # a big-data record: its segments are named by the record, not read from this cell
            if dsize is not None and not big and rec.data_size > max(dsize - 4, 0):
                CELL_DAMAGE.append("the value record at hive offset 0x%x declares %d bytes of data in a cell of %d bytes at hive offset 0x%x: only the cell's bytes are read"
                                   % (cell_at, rec.data_size, dsize, data_cell))
                rec["data_size"] = max(dsize - 4, 0)


CELL_DAMAGE = []


def is_withheld_name(name):
    return isinstance(name, str) and name.startswith(CellGuard.MARK)


def guard_regipy():
    import regipy.registry as reg
    if not isinstance(reg.CM_KEY_NODE, CellGuard):
        reg.CM_KEY_NODE = CellGuard(reg.CM_KEY_NODE, "nk")
        reg.VALUE_KEY = CellGuard(reg.VALUE_KEY, "vk")


def sensitive_value(names, name, vtype):
    """Whether this value is registry material that can be a secret: by its name and by the place the hive itself holds it in, never by its type
    (a DWORD or QWORD under a secret-sounding name is a number and is let through)."""
    name = name or ""
    if is_withheld_name(name) or any(is_withheld_name(n) for n in names):
        return "unreadable name"                       # a name that was withheld cannot be told from a secret's: the value is withheld with it
    if (SENSITIVE_NAME.search(name) or CACHED_LOGON.match(name)) and vtype not in NUMBER_TYPES:
        return "name"
    path = "\\" + "\\".join(names).lower() + "\\"
    if any(place in path for place in SECRET_PLACES):
        return "place"
    if SAM_USER_KEY.search(path) and name.lower() in SAM_USER_SECRET_VALUES:
        return "place"
    return None


class ValuesFile:
    def __init__(self, enabled, directory):
        self.enabled, self.fh, self.written, self.shown = enabled, None, 0, None
        if not enabled:
            return
        job, out = os.environ.get("JOB_ID") or "", os.environ.get("OUT") or ""
        if not (job and out) or os.environ.get("SECRET_OUTPUT") != "1":
            raise ValueError("write_values is refused: the values of what is withheld are written only in a job the harness runs as secret output "
                             "(job_run with secret_output: true), where the file is a sealed secret output. Nothing was written.")
        for n in range(1, 1000):
            name = "values.jsonl" if n == 1 else "values-%d.jsonl" % n
            path = directory / name
            before = None
            try:
                before = signal.pthread_sigmask(signal.SIG_BLOCK, {signal.SIGTERM, signal.SIGINT, signal.SIGHUP})
            except (AttributeError, ValueError, OSError):
                pass
            try:
                fd = os.open(str(path), os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o600)
                PLACED.append(str(path))         # a result only with the receipt: a stop before it removes the file
            except FileExistsError:
                continue
            except OSError as exc:
                raise ValueError("the values file could not be created: %s" % describe(exc))
            finally:
                if before is not None:
                    signal.pthread_sigmask(signal.SIG_SETMASK, before)
            self.fh = os.fdopen(fd, "w", encoding="utf-8")
            self.shown = shown_path(path)
            return
        raise ValueError("no free name for the values file")

    def add(self, row):
        if self.fh is None:
            return
        text = json.dumps(row, ensure_ascii=False)
        try:
            text.encode("utf-8")
        except UnicodeEncodeError:
            text = json.dumps(row, ensure_ascii=True)
        self.fh.write(text + "\n")
        self.written += 1

    def close(self):
        if self.fh is not None:
            self.fh.flush()
            os.fsync(self.fh.fileno())
            self.fh.close()
            self.fh = None


def shown_path(path):
    """A file as the answer names it: in a job as the sealed place, else from the run directory."""
    job, out = os.environ.get("JOB_ID"), os.environ.get("OUT")
    path = Path(path)
    if job and out:
        try:
            return "store/jobs/%s/out/%s" % (re.sub(r"[^A-Za-z0-9_.-]", "_", job), path.resolve().relative_to(Path(out).resolve()))
        except ValueError:
            return str(path)
    try:
        return str(path.resolve().relative_to(Path.cwd().resolve()))
    except ValueError:
        return str(path)


def value_record(v, names, shown_path_, withheld_kind, bounds):
    vtype = str(v.value_type)
    val = v.value
    rec = {"row": "value", "key": shown_path_, "name": v.name, "type": vtype}
    if isinstance(val, (bytes, bytearray)):
        rec["length"], rec["unit"] = len(val), "bytes"
        payload = {"data_hex": bytes(val).hex()}
    elif isinstance(val, str):
        rec["length"], rec["unit"] = len(val), "characters"
        payload = {"data": val}
    elif isinstance(val, list):
        rec["length"], rec["unit"] = len(val), "strings"
        payload = {"data": [x if isinstance(x, str) else str(x) for x in val]}
    elif isinstance(val, int) and not isinstance(val, bool):
        rec["length"], rec["unit"] = None, None
        payload = {"data": val}
    else:
        rec["length"], rec["unit"] = None, None
        payload = {"data": None}
    if getattr(v, "is_corrupted", False):
        rec["corrupted"] = True
    return rec, payload


def digest_of(*parts):
    import hashlib
    h = hashlib.blake2b(digest_size=16)
    for part in parts:
        h.update(repr(part).encode("utf-8", "surrogatepass"))
        h.update(b"\x00")
    return h.digest()


class Walk:
    """One depth-first read of a hive. `sink` receives (kind, path, name, ordinal, digest, record) for every key and value."""

    def __init__(self, path, deadline_at):
        from regipy.registry import RegistryHive
        guard_regipy()
        del CELL_DAMAGE[:]
        self.hive = open_hive(path)
        self.bounds = HiveBounds(path)
        self.bounds.deadline = deadline_at          # the block reads this clock before every value
        self.inline_bounded = self.bounds.inline_values_bounded
        self.deadline_at = deadline_at
        self.keys = self.values = self.withheld = self.problems_count = 0
        self.values_declared = self.values_not_yielded = self.keys_short_of_values = self.values_not_read = 0
        self.stopped_by_time = False
        self.problems = []
        self.type_counts = collections.Counter()

    def release(self):
        """Let go of the library's copy of the hive (it holds the whole file in memory); the counts stay."""
        self.hive = None
        self.bounds = None
        import gc
        gc.collect()

    def problem(self, where, what, error):
        self.problems_count += 1
        if len(self.problems) < 5000:
            self.problems.append({"where": where, "what": what, "error": error})

    def drain(self, where):
        """Name what the guard changed since the last call."""
        while CELL_DAMAGE:
            self.problem(where, "cell", CELL_DAMAGE.pop(0))

    def run(self, on_key, on_value):
        root = self.hive.root
        stack = [(root, [], True)]
        visited = set()
        root_list = getattr(getattr(root, "header", None), "subkeys_list_offset", None)
        if root_list is not None:
            visited.add(root_list)
        while stack:
            if time.monotonic() > self.deadline_at:
                self.stopped_by_time = True
                self.problem("", "walk", "the time limit was reached after %d keys: %d branch(es) were not opened" % (self.keys, len(stack)))
                return
            node, names, descend = stack.pop()
            shown = "\\".join(names)
            self.keys += 1
            header = getattr(node, "header", None)
            lw = getattr(header, "last_modified", None)
            on_key({"row": "key", "path": shown, "name": node.name if names else "", "depth": len(names), "last_written": ft_iso(lw), "last_written_filetime": str(lw) if lw is not None else None,
                    "subkeys": getattr(node, "subkey_count", None), "values": getattr(node, "values_count", None)})
            seen_names = collections.Counter()
            declared = getattr(node, "values_count", None)
            declared = declared if isinstance(declared, int) and not isinstance(declared, bool) and 0 <= declared <= self.bounds.value_cells else None
            yielded, before, left_before = 0, self.problems_count, self.bounds.not_read
            try:
                for v in self.bounds.values(node, shown, _ProblemSink(self), trim_values=False):
                    self.values += 1
                    yielded += 1
                    seen_names[v.name] += 1
                    kind = sensitive_value(names, v.name, str(v.value_type))
                    rec, payload = value_record(v, names, shown, kind, self.bounds)
                    rec["ordinal"] = seen_names[v.name]
                    self.type_counts[rec["type"]] += 1
                    on_value(rec, payload, kind)
            except Exception as exc:
                self.problem(shown, "values", "%s: %s" % (type(exc).__name__, exc))
            # The values the HIVE BOUNDS block refused (a big data value that cannot be what it declares) or did not reach (a bound, the clock)
            # are its own, each said in a problem line; they are not counted as values regipy left out.
            left = self.bounds.not_read - left_before
            self.values_not_read += left
            if declared is not None:
                self.values_declared += declared
                if yielded + left < declared:
                    # regipy gives no sign of a value it leaves out: it skips a value of registry type 0x00200000 by design, and ends a key's list
                    # without an error at a value record it cannot parse. The count the key declares is the only trace, so it is said per key.
                    self.values_not_yielded += declared - yielded - left
                    self.keys_short_of_values += 1
                    if self.problems_count == before:
                        self.problem(shown, "values", "the key declares %d value(s) and regipy gave %d: the %d it left out are not in keys.jsonl (the library skips a value of "
                                                      "registry type 0x00200000 and ends a key's list at a value record it cannot parse, in both cases without an error)"
                                     % (declared, yielded, declared - yielded - left))
            self.drain(shown)
            if not descend:
                continue
            if len(names) >= MAX_DEPTH:
                if getattr(node, "subkey_count", 0):
                    self.problem(shown, "subkeys", "deeper than %d levels: its subkeys are not read" % MAX_DEPTH)
                continue
            try:
                children = self.bounds.subkeys(node, shown, _ProblemSink(self))
            except Exception as exc:
                self.problem(shown, "subkeys", "%s: %s" % (type(exc).__name__, exc))
                continue
            finally:
                self.drain(shown)
            for child in reversed(children):
                header = getattr(child, "header", None)
                lid = getattr(header, "subkeys_list_offset", None)
                enter = True
                if getattr(child, "subkey_count", 0) and lid is not None:
                    if lid in visited:
                        self.problem(shown + "\\" + child.name, "subkeys", "its subkey list (offset %s) was already reached: a cycle, or a list two keys share; it is not entered again" % lid)
                        enter = False
                    else:
                        visited.add(lid)
                stack.append((child, names + [child.name], enter))


class _ProblemSink:
    def __init__(self, walk):
        self.walk = walk

    def append(self, item):
        self.walk.problem(item.get("where", ""), item.get("what", ""), item.get("error", ""))


def read_state(hive_path, deadline_at, key_page, change_db, mode, values_file, changes_page, sensitive_log):
    """Walk a hive. mode 'index': fill the digest table only. mode 'export': write key and value rows to key_page and compare with the table."""
    walk = Walk(hive_path, deadline_at)
    seen_keys = set()

    def on_key(rec):
        if mode == "index":
            change_db.put("k", rec["path"], "", 1, digest_of(rec["last_written_filetime"], rec["subkeys"], rec["values"]))
            return
        key_page.add(rec)
        if change_db is not None:
            old = change_db.get("k", rec["path"], "", 1)
            if old is None:
                changes_page.add({"change": "key_added", "path": rec["path"], "last_written": rec["last_written"]})
            else:
                change_db.mark("k", rec["path"], "", 1)
                if old != digest_of(rec["last_written_filetime"], rec["subkeys"], rec["values"]):
                    changes_page.add({"change": "key_changed", "path": rec["path"], "last_written": rec["last_written"],
                                      "note": "its last-written time, subkey count or value count differs from the original's"})

    def on_value(rec, payload, kind):
        shown_digest = digest_of(rec["type"], sorted(payload.items(), key=lambda kv: kv[0]))
        if mode == "index":
            change_db.put("v", rec["key"], rec["name"], rec["ordinal"], shown_digest)
            return
        out = dict(rec)
        if kind:
            walk.withheld += 1
            out["withheld"] = kind
            out["withheld_why"] = ("a value whose name, or the name of a key above it, could not be read (its length was longer than its cell): it cannot be told from a secret, so its bytes are withheld; write_values in a job run as secret output writes them"
                                   if kind == "unreadable name" else
                                   "a value in a place or under a name that can hold a secret: its place, name, type and length are here, its bytes are not; write_values in a job run as secret output writes them")
            sensitive_log.append({"key": rec["key"], "name": rec["name"], "type": rec["type"], "length": rec["length"], "why": kind})
            values_file.add({**rec, **payload, "why": kind})
        else:
            out.update(payload)
        key_page.add(out)
        if change_db is not None:
            old = change_db.get("v", rec["key"], rec["name"], rec["ordinal"])
            if old is None:
                changes_page.add({"change": "value_added", "key": rec["key"], "name": rec["name"], "type": rec["type"], "length": rec["length"], **({} if kind else payload)})
            else:
                change_db.mark("v", rec["key"], rec["name"], rec["ordinal"])
                if old != shown_digest:
                    changes_page.add({"change": "value_changed", "key": rec["key"], "name": rec["name"], "type": rec["type"], "length": rec["length"], **({} if kind else payload)})

    walk.run(on_key, on_value)
    return walk


class ChangeDb:
    """The original's keys and values by digest, in a temporary SQLite file, so that a hive of millions of records is compared without being held."""

    def __init__(self, directory):
        import sqlite3
        fd, name = tempfile.mkstemp(dir=directory, prefix=".compare-", suffix=".sqlite")
        os.close(fd)
        TEMPS.append(name)
        self.name = name
        self.db = sqlite3.connect(name)
        self.db.execute("PRAGMA journal_mode=OFF")
        self.db.execute("PRAGMA synchronous=OFF")
        self.db.execute("CREATE TABLE t (kind TEXT, path TEXT, name TEXT, ord INTEGER, digest BLOB, seen INTEGER DEFAULT 0, PRIMARY KEY (kind, path, name, ord)) WITHOUT ROWID")
        self.count = 0

    def put(self, kind, path, name, ordinal, digest):
        self.db.execute("INSERT OR REPLACE INTO t (kind, path, name, ord, digest) VALUES (?,?,?,?,?)", (kind, path, name, ordinal, digest))
        self.count += 1
        if self.count % 50000 == 0:
            self.db.commit()

    def get(self, kind, path, name, ordinal):
        row = self.db.execute("SELECT digest FROM t WHERE kind=? AND path=? AND name=? AND ord=?", (kind, path, name, ordinal)).fetchone()
        return row[0] if row else None

    def mark(self, kind, path, name, ordinal):
        self.db.execute("UPDATE t SET seen=1 WHERE kind=? AND path=? AND name=? AND ord=?", (kind, path, name, ordinal))

    def removed(self):
        self.db.commit()
        return self.db.execute("SELECT kind, path, name, ord FROM t WHERE seen=0 ORDER BY kind, path, name, ord")

    def close(self):
        try:
            self.db.close()
        finally:
            try:
                os.unlink(self.name)
                TEMPS.remove(self.name)
            except (OSError, ValueError):
                pass


# ---- the run ---------------------------------------------------------------------------------------------------------------------------

# The independent reader is a program this tool does not control, and a damaged hive can send it into a loop of allocations and output: 8 KB of hive have
# made libregf's regfexport take 5.5 GB of memory and print 5 to 8 GB. It is given room for any hive this tool reads (a gigabyte and four times the hive's
# size of address space; its work on a 300 MiB hive is about a third of that) and a ceiling on what it may print (a hive's honest output is a small multiple
# of its size, 64 times and 64 MiB is far above it), and is stopped, with the reason said, when it passes either.
REGFEXPORT_MEMORY_BASE = 1 << 30
REGFEXPORT_MEMORY_PER_HIVE_BYTE = 4
REGFEXPORT_OUTPUT_PER_HIVE_BYTE = 64
REGFEXPORT_OUTPUT_FLOOR = 64 << 20


def start_with_memory_limit(argv, memory):
    """Start `argv` with at most `memory` bytes of address space. The limit is set on this process for the moment of the start and put back at once: the
    program keeps it through exec, this tool does not. (spawn() is the one place a program is started, and what it passes to the child is the same for
    every tool; the limit is carried by inheritance.) Returns the process and the limit that was applied, or None when it could not be set here."""
    try:
        import resource
        old = resource.getrlimit(resource.RLIMIT_AS)
        new = memory if old[1] == resource.RLIM_INFINITY else min(memory, old[1])
        resource.setrlimit(resource.RLIMIT_AS, (new, old[1]))
    except (ImportError, ValueError, OSError, AttributeError):
        return spawn(argv, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL), None
    try:
        return spawn(argv, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL), new
    except (OSError, MemoryError):
        return None, None
    finally:
        try:
            resource.setrlimit(resource.RLIMIT_AS, old)
        except (ValueError, OSError):
            pass


def regfexport_counts(path, seconds):
    """An independent read of the hive: libregf's regfexport prints one 'Key path:' line per key and one 'Value:' line per value. The two counts, read
    from its output as it streams (nothing of the output is kept), and whether it finished and, if not, why."""
    import shutil
    program = shutil.which("regfexport")
    if not program:
        return {"ran": False, "why": "regfexport (libregf-utils) is not in this image"}
    hive_bytes = os.path.getsize(path)
    memory = REGFEXPORT_MEMORY_BASE + REGFEXPORT_MEMORY_PER_HIVE_BYTE * hive_bytes
    output_ceiling = REGFEXPORT_OUTPUT_FLOOR + REGFEXPORT_OUTPUT_PER_HIVE_BYTE * hive_bytes
    ended_before = process_verdict()["left_behind"]
    try:
        proc, memory_applied = start_with_memory_limit([program, str(path)], memory)
        if proc is None:
            proc, memory_applied = spawn([program, str(path)], stdout=subprocess.PIPE, stderr=subprocess.DEVNULL), None
    except OSError as exc:
        return {"ran": False, "why": "regfexport could not be started: %s" % describe(exc)}
    ACTIVE.append(proc)
    keys = values = printed = 0
    carry = b"\n"          # the first line of the output has a line break before it, as every other has
    end = time.monotonic() + max(seconds, 1.0)
    timed_out = over_output = held = left_running = False
    fd = proc.stdout.fileno()
    gone, settled = None, False        # when regfexport was first seen to have ended while its pipe was still open, and whether what it left was looked for
    try:
        while True:
            left = end - time.monotonic()
            if left <= 0:
                kill_tree(proc)
                timed_out = True
                break
            if proc.poll() is not None:
                # regfexport has ended and something it started still holds its pipe (silent, or writing on): after PIPE_GRACE that is not part of the program. It is ended here (settle() joins and
                # waits for nothing) so that the pipe reaches end of file; a pipe that stays open a second longer is let go and the counts are not trusted.
                gone = gone or time.monotonic()
                if time.monotonic() - gone > PIPE_GRACE and not settled:
                    settled = True
                    settle()
                elif settled and time.monotonic() - gone > PIPE_GRACE + 1.0:
                    held = True
                    break
            # Wait for output for at most the time left: a program that prints nothing must not hold the tool past its clock.
            ready, _w, _x = select.select([fd], [], [], min(left, 0.25 if gone else 1.0))
            if not ready:
                continue
            chunk = os.read(fd, 1 << 16)
            if not chunk:
                break
            printed += len(chunk)
            if printed > output_ceiling:
                kill_tree(proc)
                over_output = True
                break
            data = carry + chunk
            # What lies wholly in the carry was counted with the chunk before it: only the matches that reach into this chunk are new.
            keys += data.count(b"\nKey path: ") - carry.count(b"\nKey path: ")
            values += data.count(b"\nValue: ") - carry.count(b"\nValue: ")
            carry = data[-12:]
        # The output has ended: regfexport has ended or is about to. One that closed its output and went on running is given PIPE_GRACE seconds (never
        # past the clock) and then ended, so that the wait has a bound.
        try:
            code = proc.wait(timeout=max(0.0, min(PIPE_GRACE, end - time.monotonic())))
        except subprocess.TimeoutExpired:
            if not (timed_out or over_output):
                left_running = True
            kill_tree(proc)
            try:
                code = proc.wait(timeout=PIPE_GRACE)
            except subprocess.TimeoutExpired:
                code = None
    finally:
        if proc in ACTIVE:
            ACTIVE.remove(proc)
        try:
            proc.stdout.close()
        except OSError:
            pass
    left_behind = process_verdict()["left_behind"] - ended_before
    finished = not timed_out and not over_output and not left_running and code == 0 and not left_behind and not held
    result = {"ran": True, "exit_code": code, "finished": finished, "keys": keys, "values": values, "output_bytes": printed,
              "limits": {"address_space_bytes": memory_applied, "output_bytes": output_ceiling},
              "counted_by": "the lines of its output that start 'Key path: ' and 'Value: ' (a value whose text holds such a line is counted too)"}
    if not finished:
        if left_behind or held:
            result["why_not_finished"] = ("regfexport left %s running after it ended%s: what they printed cannot be told from what regfexport printed, so its counts are partial and are not compared"
                                          % ("%d process(es)" % left_behind if left_behind else "something holding its output open", "; they were ended" if left_behind else " (it could not be ended)"))
        elif over_output:
            result["why_not_finished"] = ("regfexport printed more than %d bytes (%d bytes were read from a hive of %d) and was stopped: its counts are partial and are not compared"
                                          % (output_ceiling, printed, hive_bytes))
        elif left_running:
            result["why_not_finished"] = ("regfexport closed its output and was still running %.1f s later: it was ended, and its counts are partial and are not compared" % PIPE_GRACE)
        elif timed_out:
            result["why_not_finished"] = "regfexport did not finish within the time left and was stopped: its counts are partial and are not compared"
        elif code is None:
            result["why_not_finished"] = "regfexport could not be ended after it was stopped: its counts are partial and are not compared"
        elif code < 0:
            result["why_not_finished"] = "regfexport was ended by signal %d (%s): its counts are partial and are not compared" % (-code, "the hive may be damaged in a way that breaks the library")
        else:
            result["why_not_finished"] = ("regfexport exited with status %d after %d bytes of output, so it did not read the hive to its end: its counts are partial and are not compared%s"
                                          % (code, printed, " (it ran with at most %d bytes of address space)" % memory_applied if memory_applied else ""))
    return result


def output_directory(identity):
    job, out = os.environ.get("JOB_ID"), os.environ.get("OUT")
    name = "registry_recover-" + identity
    if job and out:
        base = Path(out)
    else:
        agent = re.sub(r"[^A-Za-z0-9_.-]", "_", os.environ.get("AGENT_ID") or "tool")
        base = Path.cwd() / "work" / agent
    return base / name


class FilePage(NoReplacePage):
    """A paging file placed in the tool's own output directory under a fixed name, never replacing an earlier file."""

    def __init__(self, directory, name, key, limit):
        super().__init__("registry_recover", key, limit)
        self.path = directory / name
        self.shown = shown_path(self.path)
        self.inline_bytes = 0
        self.inline_open = True
        self.cut_by = None             # what closed the inline page before the last row: "rows" or "bytes"
        self.shortened = 0             # rows of the inline page shown by their small fields only

    def _open(self):
        """The hidden temporary file, made and registered with the stop signals held (as NoReplacePage.add does)."""
        before = None
        try:
            before = signal.pthread_sigmask(signal.SIG_BLOCK, {signal.SIGTERM, signal.SIGINT, signal.SIGHUP})
        except (AttributeError, ValueError, OSError):
            pass
        try:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            fd, name = tempfile.mkstemp(dir=self.path.parent, prefix=".%s-" % self.path.name)
            self._tmp = Path(name)
            self._out = os.fdopen(fd, "w", encoding="utf-8")
        except OSError as exc:
            self._cannot_write(exc)
        finally:
            if before is not None:
                signal.pthread_sigmask(signal.SIG_SETMASK, before)

    def add(self, row):
        """Every row goes to the file as it comes (the whole result is always a file the answer names, and no row is held in memory for it); the
        inline page takes the first rows while it has room in rows AND in bytes, and is a prefix of the file: row n of the page is line n."""
        if self._out is None:
            self._open()
        self.total += 1
        self._write(row)
        if not self.inline_open:
            return
        if len(self.page) >= self.limit:
            self.inline_open, self.cut_by = False, "rows"
            return
        shown, size = inline_row(row, self.total)
        if self.inline_bytes + size > INLINE_PAGE_BYTES:
            self.inline_open, self.cut_by = False, "bytes"
            return
        if shown is not row:
            self.shortened += 1
        self.inline_bytes += size
        self.page.append(shown)

    def finish(self):
        """The file placed under its name, and entered in PLACED with the stop signals held: it is a result only with the receipt, and a stop
        before the receipt removes it (a run stopped while regfexport counted left keys.jsonl behind, with an answer that said nothing it made
        was a result)."""
        before = None
        try:
            before = signal.pthread_sigmask(signal.SIG_BLOCK, {signal.SIGTERM, signal.SIGINT, signal.SIGHUP})
        except (AttributeError, ValueError, OSError):
            pass
        try:
            result = super().finish()
            if result.get("all_results"):
                PLACED.append(str(self.path))
                result["all_results"] = shown_path(self.path)
        finally:
            if before is not None:
                signal.pthread_sigmask(signal.SIG_SETMASK, before)
        return result

    def said(self, result):
        """What the answer says of this page: how much is inline, what cut it, and where to read on (a line of the file, counted from 1)."""
        out = {"file": result.get("all_results"), "total": self.total, "returned": len(self.page), "inline_bytes": self.inline_bytes,
               "inline_limits": {"rows": self.limit, "page_bytes": INLINE_PAGE_BYTES, "row_bytes": INLINE_ROW_BYTES},
               "cut_by": self.cut_by, "rows_shortened_inline": self.shortened,
               "next": {"file": result.get("all_results"), "line": len(self.page) + 1} if self.total > len(self.page) else None}
        if self.shortened:
            out["rows_shortened_note"] = ("a row longer than %d bytes is shown inline by its small fields, with inline_omitted naming its size and its line in the file, "
                                          "where it is whole" % INLINE_ROW_BYTES)
        return out


def row_bytes(row):
    return len(json.dumps(row, ensure_ascii=True, default=str))


def clip(text, limit=INLINE_TEXT):
    """A text of the answer cut at `limit` characters, the cut said in it."""
    if not isinstance(text, str) or len(text) <= limit:
        return text
    return text[:limit] + " ... [%d more characters; the whole is in the file the answer names]" % (len(text) - limit)


def clip_all(value, limit=INLINE_TEXT):
    """`value` with every text in it cut at `limit` characters (lists and maps are walked; nothing else is changed)."""
    if isinstance(value, str):
        return clip(value, limit)
    if isinstance(value, list):
        return [clip_all(v, limit) for v in value]
    if isinstance(value, dict):
        return {k: clip_all(v, limit) for k, v in value.items()}
    return value


def inline_row(row, line):
    """The row as the inline page shows it, and the bytes it takes there. A row within INLINE_ROW_BYTES is shown as it is (the same object). A longer
    one keeps its numbers and its short texts; a text over INLINE_FIELD characters or a list is replaced by its size, and inline_omitted says how
    long the row is and which line of the file holds it whole. A row still too long after that (a key path of thousands of characters) is its
    line and size alone."""
    size = row_bytes(row)
    if size <= INLINE_ROW_BYTES:
        return row, size
    short = {}
    for k, v in row.items():
        if isinstance(v, str) and len(v) > INLINE_FIELD:
            short[k] = {"omitted_characters": len(v)}
        elif isinstance(v, (list, dict)):
            short[k] = {"omitted_items": len(v)}
        else:
            short[k] = v
    short["inline_omitted"] = {"row_bytes": size, "line": line}
    after = row_bytes(short)
    if after > INLINE_ROW_BYTES:
        short = {"row": row.get("row") or row.get("change"), "inline_omitted": {"row_bytes": size, "line": line}}
        after = row_bytes(short)
    return short, after


def sha256_file(path):
    """The SHA-256 of a file read in blocks with the tool's clock looked at between them: (digest, None), or (None, why) when the time limit was reached
    first. A hive of several GiB on slow storage cannot be read through inside the tool's own limit, so what is not hashed is said, never waited for."""
    import hashlib
    h = hashlib.sha256()
    done = 0
    with open(path, "rb") as fh:
        while True:
            if out_of_time():
                return None, "the time limit was reached after %d bytes of %d were hashed" % (done, os.fstat(fh.fileno()).st_size)
            piece = fh.read(BLOCK)
            if not piece:
                break
            h.update(piece)
            done += len(piece)
    return h.hexdigest(), None


def stand_in(path):
    """What names a file in the run's directory name when its hash could not be made: its path, size and modification time."""
    st = os.stat(path)
    return "unhashed:%s:%d:%d" % (path, st.st_size, st.st_mtime_ns)


def place_json(directory, name, value):
    fd, tmp = tempfile.mkstemp(dir=directory, prefix=".receipt-")
    TEMPS.append(tmp)
    with os.fdopen(fd, "w", encoding="utf-8") as fh:
        json.dump(value, fh, indent=1)
        fh.write("\n")
    placed = place_without_replacing(Path(tmp), directory / name)
    if tmp in TEMPS:
        TEMPS.remove(tmp)
    return placed


def check_args(args):
    if not isinstance(args, dict):
        fail("the arguments are one JSON object")
    hive = args.get("hive")
    if not isinstance(hive, str) or not hive:
        fail("hive is required: the path of the registry hive file (a copy)")
    logs = []
    for role in ("log1", "log2"):
        value = args.get(role)
        if value is not None and (not isinstance(value, str) or not value):
            fail("%s must be the path of a transaction log file" % role)
        if value:
            logs.append((role, value))
    write_values = args.get("write_values", False)
    if not isinstance(write_values, bool):
        fail("write_values must be true or false")
    limit = args.get("limit", 200)
    if isinstance(limit, bool) or not isinstance(limit, int) or limit < 1:
        fail("limit must be a positive whole number", limit=limit)
    seconds = args.get("max_seconds", DEFAULT_SECONDS)
    if isinstance(seconds, bool) or not isinstance(seconds, (int, float)) or not 1 <= seconds <= MAX_SECONDS:
        fail("max_seconds must be a number from 1 to %d" % MAX_SECONDS, max_seconds=seconds)
    export = args.get("export", True)
    if not isinstance(export, bool):
        fail("export must be true or false")
    return hive, logs, write_values, limit, float(seconds), export


def refuse_special(path, what):
    try:
        mode = os.stat(path).st_mode
    except OSError as exc:
        fail("%s could not be examined" % what, path=path, reason=describe(exc))
    if not stat.S_ISREG(mode):
        fail("%s is not a regular file, so it was not opened (a pipe or a device is never opened)" % what, path=path, not_attempted=1)


def main():
    install_signal_handlers()
    STATE["last_word"] = last_word
    try:
        args = json.load(sys.stdin)
    except ValueError as exc:
        fail("arguments are not valid JSON", reason=str(exc))
    hive_path, logs, write_values, limit, seconds, export = check_args(args)
    refuse_special(hive_path, "the hive")
    for role, path in logs:
        if not os.path.exists(path):
            fail("the %s named does not exist" % role, path=path)
    if write_values:
        job, out = os.environ.get("JOB_ID") or "", os.environ.get("OUT") or ""
        if not (job and out) or os.environ.get("SECRET_OUTPUT") != "1":
            fail("write_values is refused: the values of what is withheld are written only in a job the harness runs as secret output (job_run with secret_output: true). Nothing was written.")
    set_deadline(seconds)
    started = time.monotonic()
    hive_size = os.path.getsize(hive_path)
    if hive_size > MAX_HIVE_BYTES:
        fail("the hive is larger than the %d bytes this tool reads" % MAX_HIVE_BYTES, bytes=hive_size)
    with open(hive_path, "rb") as fh:
        hive, _block = read_base(fh, hive_size)
    hive_sha, hive_sha_why = sha256_file(hive_path)
    not_hashed = []        # what the clock stopped the hashing of, said in the receipt and the status
    if hive_sha is None:
        not_hashed.append("the hive: " + hive_sha_why)
    identity_parts = [hive_path, hive_sha or stand_in(hive_path)]
    for role, p in logs:
        if not os.path.isfile(p):
            identity_parts.append(p)
            continue
        log_sha, log_sha_why = sha256_file(p)
        if log_sha is None:
            not_hashed.append("%s: %s" % (role, log_sha_why))
        identity_parts.append(log_sha or stand_in(p))
    import hashlib
    identity = hashlib.sha256(json.dumps(identity_parts).encode("utf-8")).hexdigest()[:12]
    directory = output_directory(identity)
    try:
        directory.mkdir(parents=True, exist_ok=True)
    except OSError as exc:
        fail("the output directory could not be made", reason=describe(exc))
    values_file = ValuesFile(write_values, directory)

    receipt = {"parser": PARSER, "hive_original": {"path": hive_path, "bytes": hive_size, **{k: v for k, v in hive.items() if k not in ("bytes_read", "problems")}, "problems": hive.get("problems", [])}}
    receipt["hive_original"]["sha256"] = hive_sha
    if hive_sha is None:
        receipt["hive_original"]["sha256_not_made"] = hive_sha_why
    if not_hashed:
        receipt["not_hashed"] = not_hashed
    replay_receipt, log_receipts, unrecovered, working = replay(hive_path, hive_size, hive, logs, directory)
    receipt["replay"] = replay_receipt
    receipt["logs"] = log_receipts
    recovered_path = None
    if working is not None:
        recovered_path = place_without_replacing(working, directory / "recovered.hive")
        PLACED.append(recovered_path)
        TEMPS[:] = [t for t in TEMPS if t != str(working)]
        os.chmod(recovered_path, 0o644)
        recovered_sha, recovered_sha_why = sha256_file(recovered_path)
        receipt["recovered"] = {"path": shown_path(recovered_path), "bytes": os.path.getsize(recovered_path), "sha256": recovered_sha}
        if recovered_sha is None:
            receipt["recovered"]["sha256_not_made"] = recovered_sha_why
            not_hashed.append("the recovered copy: " + recovered_sha_why)
            receipt["not_hashed"] = not_hashed
        with open(recovered_path, "rb") as fh:
            after, _b = read_base(fh, os.path.getsize(recovered_path))
        receipt["recovered"]["base_block"] = {k: v for k, v in after.items() if k not in ("bytes_read",)}
    # The records of the state read.
    export_receipt = {"requested": export, "source": None, "status": "not requested" if not export else "not started"}
    sensitive_log = []
    problems = []
    if export and hive.get("signature_ok"):
        read_from = recovered_path or Path(hive_path)
        export_receipt["source"] = "the recovered copy" if recovered_path else "the hive as it is (nothing was applied)"
        read_bytes = os.path.getsize(read_from)
        try:
            import regipy.registry  # noqa: F401
            have_regipy = True
        except ImportError:
            have_regipy = False
            export_receipt.update(status="failed", why="regipy is not installed: python3 -m pip install regipy")
        if have_regipy and read_bytes > MAX_READ_BYTES:
            have_regipy = False
            export_receipt.update(status="skipped", bytes=read_bytes, why="the %s is %d bytes; regipy holds the whole hive in memory, so a hive over %d bytes is not read (the replay above was done, "
                                  "and the recovered copy, if one was made, is the place to read it with a tool that streams)" % (export_receipt["source"], read_bytes, MAX_READ_BYTES))
        if have_regipy:
            withhold_library_output()
            key_page = FilePage(directory, "keys.jsonl", [identity, "keys"], limit)
            changes_page = FilePage(directory, "changes.jsonl", [identity, "changes"], limit)
            change_db = None
            try:
                comparing = recovered_path is not None
                original = None
                compare_failed = None
                if comparing:
                    change_db = ChangeDb(directory)
                    try:
                        original = read_state(hive_path, time.monotonic() + seconds * 0.4, None, change_db, "index", values_file, None, [])
                        export_receipt["original_walk"] = {"keys": original.keys, "values": original.values, "stopped_by_time_limit": original.stopped_by_time,
                                                           "problem_count": original.problems_count}
                        original.release()      # the library holds a hive in memory: the original's is let go before the recovered copy is read
                    except Exception as exc:
                        compare_failed = "the original hive could not be read by regipy (%s), so the recovered state is not compared with it" % type(exc).__name__
                        change_db.close()
                        change_db = None
                walk = read_state(str(read_from), CLOCK["deadline"], key_page, change_db, "export", values_file, changes_page, sensitive_log)
                walk.release()
                removed = 0
                if change_db is not None and not original.stopped_by_time and not walk.stopped_by_time:
                    for kind, path, name, ordinal in change_db.removed():
                        removed += 1
                        changes_page.add({"change": "key_removed" if kind == "k" else "value_removed", "path" if kind == "k" else "key": path, **({} if kind == "k" else {"name": name})})
                keys_result, changes_result = key_page.finish(), changes_page.finish()
                export_receipt.update({
                    "status": "complete" if not walk.stopped_by_time and not walk.problems_count else "partial",
                    "keys": walk.keys, "values": walk.values, "value_types": dict(sorted(walk.type_counts.items())),
                    "values_declared_by_keys": walk.values_declared, "values_not_yielded_by_regipy": walk.values_not_yielded,
                    "values_not_read_by_bounds": walk.values_not_read,
                    "keys_short_of_values": walk.keys_short_of_values, "inline_values_bounded": walk.inline_bounded,
                    "withheld_values": len(sensitive_log), "problem_count": walk.problems_count, "walk_stopped_by_time_limit": walk.stopped_by_time,
                    "keys_file": keys_result.get("all_results"), "keys_inline": key_page.page, "keys_page": key_page.said(keys_result),
                    "library_messages_withheld": LibraryLog.messages,
                })
                if comparing and compare_failed:
                    export_receipt["changes"] = {"compared": False, "why": compare_failed}
                elif comparing:
                    both_whole = not original.stopped_by_time and not walk.stopped_by_time
                    export_receipt["changes"] = {"compared": both_whole, "count": changes_result["matched"], "removed": removed,
                                                 "file": changes_result.get("all_results"), "inline": changes_page.page, "page": changes_page.said(changes_result),
                                                 "note": "keys and values of the recovered copy that are not in the original, are not in the recovered copy, or differ; a withheld value is compared by its bytes and shown by place only"}
                    if not both_whole:
                        export_receipt["status"] = "partial"
                        export_receipt["changes"]["note"] += "; a walk stopped at the time limit, so what is listed is not the whole difference"
                reader = regfexport_counts(read_from, max(5.0, CLOCK["deadline"] - time.monotonic() - 2)) if not walk.stopped_by_time else {"ran": False, "why": "the walk stopped at the time limit, so its counts are not whole"}
                if reader.get("ran") and reader.get("finished"):
                    reader["agrees"] = reader["keys"] == walk.keys and reader["values"] == walk.values
                    reader["regipy"] = {"keys": walk.keys, "values": walk.values, "values_declared_by_keys": walk.values_declared,
                                        "values_not_yielded": walk.values_not_yielded, "values_not_read_by_bounds": walk.values_not_read}
                    # The difference is explained when the values regfexport counted are the ones the keys declare: what is missing is then
                    # exactly what regipy left out and what this tool did not read (each said per key under problems), and nothing else differs
                    # between the two readers.
                    missing = walk.values_not_yielded + walk.values_not_read
                    reader["difference_explained"] = (not reader["agrees"] and reader["keys"] == walk.keys
                                                      and reader["values"] == walk.values + missing and missing > 0)
                export_receipt["independent_reader"] = {"regfexport": reader}
                if reader.get("agrees") is False:
                    export_receipt["status"] = "partial"
                problems = clip_all(walk.problems[:INLINE_PROBLEMS])
                export_receipt["problems"] = problems
                if walk.problems_count > INLINE_PROBLEMS:
                    export_receipt["problems_not_shown"] = walk.problems_count - INLINE_PROBLEMS
            except Exception as exc:
                export_receipt.update(status="failed", why="%s: %s" % (type(exc).__name__, exc))
            finally:
                if change_db is not None:
                    change_db.close()
    elif export:
        export_receipt.update(status="failed", why="the hive has no 'regf' base block: no record was read")
    receipt["records"] = export_receipt
    receipt["sensitive_values_withheld"] = clip_all(sensitive_log[:INLINE_PROBLEMS], INLINE_FIELD)
    receipt["sensitive_values_withheld_count"] = len(sensitive_log)
    values_file.close()
    receipt["values_file"] = values_file.shown
    receipt["unrecovered"] = bounded_list(unrecovered[:INLINE_PROBLEMS])
    receipt["unrecovered_count"] = len(unrecovered)
    if len(unrecovered) > INLINE_PROBLEMS:
        receipt["unrecovered_not_shown"] = len(unrecovered) - INLINE_PROBLEMS
    reasons = []
    dirty_left = bool(hive.get("signature_ok")) and (receipt["replay"]["dirty_before"] and not receipt["replay"]["performed"])
    if not hive.get("signature_ok"):
        status, basis = "failed", "the hive has no 'regf' base block"
    else:
        if dirty_left:
            reasons.append("the hive is dirty and no replay was performed: %s" % receipt["replay"]["reason"])
        if unrecovered:
            reasons.append("%d log entr%s or range%s were not applied (unrecovered)" % (len(unrecovered), "y" if len(unrecovered) == 1 else "ies", "" if len(unrecovered) == 1 else "s"))
        if export and export_receipt.get("status") != "complete":
            said_why = []
            if export_receipt.get("why"):
                said_why.append(clip(str(export_receipt["why"])))
            if export_receipt.get("problem_count"):
                said_why.append("%d problem(s), the first %d under records.problems" % (export_receipt["problem_count"], min(export_receipt["problem_count"], INLINE_PROBLEMS)))
            if export_receipt.get("values_not_yielded_by_regipy"):
                said_why.append("%d of the %d value(s) the keys declare were not given by regipy and are not in keys.jsonl" % (
                    export_receipt["values_not_yielded_by_regipy"], export_receipt.get("values_declared_by_keys", 0)))
            if export_receipt.get("values_not_read_by_bounds"):
                said_why.append("%d of the %d value(s) the keys declare were not read by this tool and are not in keys.jsonl (a big data value refused, "
                                "or a value past a bound or the time limit; each key is named under records.problems)" % (
                    export_receipt["values_not_read_by_bounds"], export_receipt.get("values_declared_by_keys", 0)))
            if export_receipt.get("walk_stopped_by_time_limit"):
                said_why.append("the walk stopped at the time limit")
            reasons.append("the key and value records are %s%s" % (export_receipt.get("status"), (": " + "; ".join(said_why)) if said_why else ""))
        reader_said = (export_receipt.get("independent_reader") or {}).get("regfexport") or {}
        if reader_said.get("ran") and not reader_said.get("finished"):
            reasons.append(reader_said["why_not_finished"])
        if reader_said.get("agrees") is False:
            not_read = reader_said["regipy"].get("values_not_read_by_bounds") or 0
            not_read_said = (" and the %d value(s) this tool did not read (a big data value refused, or a value past a bound or the time limit; each named under "
                             "records.problems)" % not_read) if not_read else ""
            reasons.append("regfexport counted %d keys and %d values where regipy counted %d and %d%s" % (
                reader_said["keys"], reader_said["values"], reader_said["regipy"]["keys"], reader_said["regipy"]["values"],
                (": the difference is the %d value(s) the keys declare and regipy did not give (%d key(s), each named under records.problems; the library skips a value of "
                 "registry type 0x00200000 and ends a list at a value record it cannot parse)%s, and those values are not in keys.jsonl"
                 % (reader_said["regipy"]["values_not_yielded"], export_receipt.get("keys_short_of_values", 0), not_read_said)) if reader_said.get("difference_explained") else
                (" (the keys walked declare %d values, and regipy did not give %d of them%s)" % (reader_said["regipy"]["values_declared_by_keys"], reader_said["regipy"]["values_not_yielded"],
                                                                                                not_read_said))))
        if hive.get("problems"):
            reasons.append("the hive's base block has a problem: " + "; ".join(hive["problems"]))
        if not_hashed:
            reasons.append("not every file was hashed (%s): the digests named in the receipt are those that were made" % "; ".join(not_hashed))
        if receipt["replay"].get("time_limit"):
            reasons.append(receipt["replay"]["time_limit"])
        if (receipt["replay"].get("base_block_from_log") or {}).get("taken") is False:
            reasons.append(receipt["replay"]["base_block_from_log"]["why"])
        status = "partial" if reasons else "complete"
        if reasons:
            basis = "; ".join(reasons)
        else:
            said = []
            if not receipt["replay"]["dirty_before"]:
                said.append("the hive is clean, so nothing was replayed")
            elif receipt["replay"]["performed"]:
                said.append("the replay applied %d entr%s up to sequence %d, and every named log entry that follows was applied or is older than the state the hive was at" % (
                    receipt["replay"]["entries_applied"], "y" if receipt["replay"]["entries_applied"] == 1 else "ies", (receipt["replay"]["sequence_after"][0] - 1) & 0xFFFFFFFF))
            if export:
                said.append("every key and value of the state read was written")
            basis = "; ".join(said)
    receipt["status"], receipt["status_basis"] = status, basis
    placed = place_json(directory, "receipt.json", receipt)
    del PLACED[:]
    answer = {"parser": PARSER, "status": status, "status_basis": basis, "hive": hive_path,
              "dirty_before": receipt["replay"]["dirty_before"], "replayed": receipt["replay"]["performed"],
              "sequence_before": receipt["replay"]["sequence_before"], "sequence_after": receipt["replay"].get("sequence_after"),
              "entries_applied": receipt["replay"]["entries_applied"], "unrecovered_count": len(unrecovered), "unrecovered": receipt["unrecovered"],
              "recovered_copy": receipt.get("recovered", {}).get("path"), "receipt": shown_path(placed),
              "records": {k: v for k, v in export_receipt.items() if k not in ("keys_inline",)},
              "keys_inline": export_receipt.get("keys_inline", []),
              "sensitive_values_withheld_count": len(sensitive_log), "values_file": values_file.shown,
              "contains_secret_values": values_file.written > 0,
              "elapsed_seconds": round(time.monotonic() - started, 2)}
    print(bounded_answer(answer))


def bounded_list(items, budget=INLINE_PAGE_BYTES):
    """The first items that fit in `budget` bytes, texts cut at INLINE_TEXT (the receipt and the answer carry this list; the count beside it is of all)."""
    out, used = [], 0
    for item in items:
        item = clip_all(item)
        size = row_bytes(item)
        if used + size > budget:
            break
        used += size
        out.append(item)
    return out


def bounded_answer(answer):
    """The answer as text, never over MAX_ANSWER_BYTES. Each inline page is bounded where it is made; what a hostile hive or log can still make long
    (a status basis that quotes a reason, a path, a base block's problem list) is cut here, and an answer still too long is printed without its
    inline pages, which says so and names the files and the receipt that hold everything."""
    text = json.dumps(answer, indent=1)
    if len(text) <= MAX_ANSWER_BYTES:
        return text
    answer = clip_all(answer)
    text = json.dumps(answer, indent=1)
    if len(text) <= MAX_ANSWER_BYTES:
        return text
    records = answer.get("records") if isinstance(answer.get("records"), dict) else {}
    dropped = []
    for holder, key in ((answer, "keys_inline"), (records.get("changes") if isinstance(records.get("changes"), dict) else {}, "inline"), (records, "problems"),
                        (answer, "unrecovered")):
        if holder.get(key):
            holder[key] = []
            dropped.append(key)
    for page in (records.get("keys_page"), (records.get("changes") or {}).get("page") if isinstance(records.get("changes"), dict) else None):
        if isinstance(page, dict) and page.get("total"):
            page.update(returned=0, cut_by="answer_bytes", next={"file": page.get("file"), "line": 1})
    answer["inline_dropped"] = {"why": "the answer was over %d bytes with its inline pages, so they are not printed: every row is in the files named, from line 1" % MAX_ANSWER_BYTES,
                                "dropped": dropped}
    text = json.dumps(answer, indent=1)
    if len(text) <= MAX_ANSWER_BYTES:
        return text
    return json.dumps({"parser": answer.get("parser"), "status": answer.get("status"), "status_basis": clip(str(answer.get("status_basis")), INLINE_TEXT),
                       "receipt": clip(str(answer.get("receipt")), INLINE_TEXT), "recovered_copy": clip(str(answer.get("recovered_copy")), INLINE_TEXT) if answer.get("recovered_copy") else None,
                       "inline_dropped": {"why": "the answer was over %d bytes even without its inline pages: only its status and the receipt's name are printed, and the receipt holds the rest" % MAX_ANSWER_BYTES}},
                      indent=1)


def forget_placed():
    """A recovered copy, the keys and changes files and the values file are results with their receipt, which is written last: a file placed by a run
    that did not get to its receipt is removed, not left to be taken for one."""
    removed = 0
    for path in PLACED:
        try:
            os.unlink(path)
            removed += 1
        except OSError:
            pass
    del PLACED[:]
    return removed


def last_word(signum):
    forget_temps()
    copies = forget_placed()
    # A stop is not a status (the statuses are complete, partial and failed): nothing made is a result, so the status is failed, with interrupted true.
    print(json.dumps({"error": "stopped by signal %d before the answer was complete" % signum, "status": "failed", "interrupted": True,
                      "status_basis": "the tool was stopped by signal %d; nothing it had made is a result (the temporary files were removed%s)" % (
                          signum, ", and so were the %d file(s) it had placed (a recovered copy, the keys and changes files, the values file), which had no receipt "
                          "yet" % copies if copies else ""), "signal": signum}), flush=True)


if __name__ == "__main__":
    exit_code = 0
    try:
        try:
            main()
        except SystemExit:
            raise
        except ValueError as exc:
            fail(str(exc))
        except Exception as exc:                                  # whatever hostile input does, the answer is JSON
            hold_stop_signals(quietly=True)
            forget_temps()
            forget_placed()
            print(json.dumps({"ok": False, "error": "the run failed", "status": "failed", "status_basis": "the tool stopped with an unexpected error", "reason": "%s: %s" % (type(exc).__name__, exc)}))
            sys.exit(1)
    except SystemExit as stop:
        exit_code = _code(stop)
    _leave(exit_code)
