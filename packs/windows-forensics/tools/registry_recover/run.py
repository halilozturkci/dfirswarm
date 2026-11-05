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

PARSER = "registry_recover/3"
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
# holds its pipes does not hold the tool: communicate_bounded gives the pipes PIPE_GRACE seconds and goes on without them. (In the
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
            if before is not None and listed is not None and before != listed:
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
        if pid in table and (table[pid] is None or table[pid] == ident):
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
        if row is None or listed != SEEN_IDENT[pid] or row[0] == me:
            continue
        parent = row[0]
        if parent in table and SEEN_IDENT.get(parent) is not None and table.ident.get(parent) == SEEN_IDENT[parent]:
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
    turn a complete answer into a partial one (status "partial", the ok and complete flags that are there false, a sentence in status_basis):
    what a program wrote while the tool read it is not a complete result. A carrier calls it once where it prints its answer. Returns `answer`."""
    verdict = process_verdict()
    answer["program_group"] = verdict
    if (verdict["left_behind"] > 0 or verdict["unproven"]) and answer.get("status") == "complete":
        answer["status"] = "partial"
        for flag in ("ok", "complete"):
            if flag in answer:
                answer[flag] = False
        if verdict["left_behind"] > 0:
            sentence = "a program left %d process%s running after it ended; the tool ended them, and what they wrote before that is in the files named here" % (
                verdict["left_behind"], "" if verdict["left_behind"] == 1 else "es")
        else:
            sentence = "the tool cannot prove that no program left a process behind (see program_group.unproven)"
        basis = answer.get("status_basis")
        answer["status_basis"] = "%s; %s" % (basis, sentence) if isinstance(basis, str) and basis else sentence
    return answer


PIPE_GRACE = 1.0    # seconds the pipes of a program that has ended are given to reach end of file


def communicate_bounded(proc, seconds, input=None):
    """(stdout bytes, stderr bytes, timed out) for a program started with pipes, in bytes. At `seconds` the program and what it started
    are killed (timed out). A program that has ended while something it started still holds its pipes (a daemon, a helper that
    inherited them) does not hold the tool: the pipes are given PIPE_GRACE seconds, what the program wrote is kept, what the tool
    lost is killed (reap_orphans), and the pipes are let go. The pipes are read here and by nothing else, so letting them go is safe."""
    deadline = time.monotonic() + max(0.1, seconds)
    out = err = b""
    started, timed_out, note = False, False, None
    while proc.poll() is None:
        now = time.monotonic()
        if now >= deadline:
            timed_out = True
            note = kill_tree(proc)
            break
        _sample(proc.pid)
        try:
            out, err = proc.communicate(None if started else input, timeout=max(0.01, min(0.2, deadline - now)))
            settle()
            return out or b"", err or b"", False
        except subprocess.TimeoutExpired as exc:
            started = True
            out, err = exc.stdout or b"", exc.stderr or b""
    try:
        out, err = proc.communicate(None if started else input, timeout=PIPE_GRACE)
    except subprocess.TimeoutExpired as exc:
        out, err = exc.stdout or b"", exc.stderr or b""
        reap_orphans(_pipe_inodes(proc))
        settle()
        for pipe in (proc.stdin, proc.stdout, proc.stderr):
            try:
                if pipe is not None:
                    pipe.close()
            except (OSError, ValueError):
                pass
    try:
        proc.wait(timeout=PIPE_GRACE)
    except subprocess.TimeoutExpired:
        pass
    settle()
    err = err or b""
    if note:
        err = err + (b"\n" if err else b"") + note.encode("utf-8", "replace")
    return out or b"", err, timed_out


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
    os._exit(128 + signum)


def install_signal_handlers():
    for signum in (signal.SIGTERM, signal.SIGINT, signal.SIGHUP):
        signal.signal(signum, _on_signal)
# END SHARED PROCESS


# BEGIN SHARED HIVE BOUNDS
# The same text is in regkv, shellbags and amcache_apps (a windows-forensics test holds the copies equal).
# A hive of N bytes holds at most N // 76 key cells (an nk cell is at least 76 bytes) and N // 20 value cells (a vk cell is at least 20), however
# many elements an index claims: regipy follows a subkey index (ri) element by element, so one list repeated by an index is read as many times as
# it is repeated (a 61 KB hive listed a million keys and took 1.2 GB). Every list of subkeys and values is read through these bounds, and what is
# past one is said, never followed.
import itertools
import logging
import warnings

KEY_CELL_BYTES = 76
VALUE_CELL_BYTES = 20


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


class HiveBounds:
    def __init__(self, hive_path, size=None):
        size = os.path.getsize(hive_path) if size is None else size
        self.hive_bytes = size
        self.key_cells = max(size // KEY_CELL_BYTES, 1)
        self.value_cells = max(size // VALUE_CELL_BYTES, 1)
        self.keys_read = 0                      # subkey elements read over the whole walk
        self.data_read = 0                      # bytes of value data read over the whole walk
        self.repeats = 0                        # elements that named a key already named in the same list

    def subkeys(self, node, where, problems):
        """The distinct subkeys of `node`, at most the keys the hive can still hold; what is past that, or repeated, is a problem line."""
        room = max(self.key_cells - self.keys_read, 0)
        raw = list(itertools.islice(node.iter_subkeys() or [], room + 1))
        if len(raw) > room:
            raw = raw[:room]
            problems.append({"where": where, "what": "subkeys",
                             "error": "its subkey list yields more keys than a %d-byte hive can hold (%d keys at most, %d already read in this walk): "
                                      "an index that repeats a list; the elements past that are not read" % (self.hive_bytes, self.key_cells, self.keys_read)})
        self.keys_read += len(raw)
        seen, distinct, repeated = set(), [], 0
        for sub in raw:
            header = getattr(sub, "header", None)
            identity = (str(getattr(sub, "name", "")).lower(), getattr(header, "last_modified", None),
                        getattr(header, "subkeys_list_offset", None), getattr(header, "values_list_offset", None))
            if identity in seen:
                repeated += 1
                continue
            seen.add(identity)
            distinct.append(sub)
        if repeated:
            self.repeats += repeated
            problems.append({"where": where, "what": "subkeys",
                             "error": "its subkey list names %d key(s) more than once; each is listed once" % repeated})
        return distinct

    def values(self, node, where, problems, **kwargs):
        """At most the values the hive can hold, as a list, and at most the data it can hold over the whole walk (a value list that names one big
        record again and again reads that record every time); a key that lists more is a problem line."""
        raw = []
        for v in itertools.islice(node.iter_values(**kwargs), self.value_cells + 1):
            if len(raw) >= self.value_cells:
                problems.append({"where": where, "what": "values",
                                 "error": "its value list yields more values than a %d-byte hive can hold (%d at most): the elements past that are not read"
                                          % (self.hive_bytes, self.value_cells)})
                break
            data = getattr(v, "value", None)
            self.data_read += len(data) if isinstance(data, (bytes, bytearray, str)) else sum(len(x) for x in data if isinstance(x, (str, bytes))) if isinstance(data, list) else 0
            if self.data_read > 4 * self.hive_bytes:
                problems.append({"where": where, "what": "values",
                                 "error": "the values read in this walk hold more data than a %d-byte hive can: records that a value list names again and again; "
                                          "the values past that are not read" % self.hive_bytes})
                break
            raw.append(v)
        return raw
# END SHARED HIVE BOUNDS


# ---- small helpers ------------------------------------------------------------------------------------------------------------------

def fail(message, **extra):
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
    fh.seek(start)
    left = size - start
    while left > 0:
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
        expected += 1
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
            try:
                fd = os.open(str(path), os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o600)
            except FileExistsError:
                continue
            except OSError as exc:
                raise ValueError("the values file could not be created: %s" % describe(exc))
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
        self.hive = RegistryHive(path)
        self.bounds = HiveBounds(path)
        self.deadline_at = deadline_at
        self.keys = self.values = self.withheld = self.problems_count = 0
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
            try:
                for v in self.bounds.values(node, shown, _ProblemSink(self), trim_values=False):
                    self.values += 1
                    seen_names[v.name] += 1
                    kind = sensitive_value(names, v.name, str(v.value_type))
                    rec, payload = value_record(v, names, shown, kind, self.bounds)
                    rec["ordinal"] = seen_names[v.name]
                    self.type_counts[rec["type"]] += 1
                    on_value(rec, payload, kind)
            except Exception as exc:
                self.problem(shown, "values", "%s: %s" % (type(exc).__name__, exc))
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
    timed_out = over_output = False
    fd = proc.stdout.fileno()
    try:
        while True:
            left = end - time.monotonic()
            if left <= 0:
                kill_tree(proc)
                timed_out = True
                break
            # Wait for output for at most the time left: a program that prints nothing must not hold the tool past its clock.
            ready, _w, _x = select.select([fd], [], [], min(left, 1.0))
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
        code = proc.wait()
    finally:
        if proc in ACTIVE:
            ACTIVE.remove(proc)
        try:
            proc.stdout.close()
        except OSError:
            pass
    finished = not timed_out and not over_output and code == 0
    result = {"ran": True, "exit_code": code, "finished": finished, "keys": keys, "values": values, "output_bytes": printed,
              "limits": {"address_space_bytes": memory_applied, "output_bytes": output_ceiling},
              "counted_by": "the lines of its output that start 'Key path: ' and 'Value: ' (a value whose text holds such a line is counted too)"}
    if not finished:
        if over_output:
            result["why_not_finished"] = ("regfexport printed more than %d bytes (%d bytes were read from a hive of %d) and was stopped: its counts are partial and are not compared"
                                          % (output_ceiling, printed, hive_bytes))
        elif timed_out:
            result["why_not_finished"] = "regfexport did not finish within the time left and was stopped: its counts are partial and are not compared"
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

    def finish(self):
        if self._out is None and self.total:
            # the whole result is always a file the answer names, even when it fits in the inline page
            try:
                self.path.parent.mkdir(parents=True, exist_ok=True)
                fd, name = tempfile.mkstemp(dir=self.path.parent, prefix=".%s-" % self.path.name)
                self._tmp = Path(name)
                self._out = os.fdopen(fd, "w", encoding="utf-8")
            except OSError as exc:
                self._cannot_write(exc)
            for kept in self.page:
                self._write(kept)
        result = super().finish()
        if result.get("all_results"):
            result["all_results"] = shown_path(self.path)
        return result


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
                    "withheld_values": len(sensitive_log), "problem_count": walk.problems_count, "walk_stopped_by_time_limit": walk.stopped_by_time,
                    "keys_file": keys_result.get("all_results"), "keys_inline": key_page.page,
                    "library_messages_withheld": LibraryLog.messages,
                })
                if comparing and compare_failed:
                    export_receipt["changes"] = {"compared": False, "why": compare_failed}
                elif comparing:
                    both_whole = not original.stopped_by_time and not walk.stopped_by_time
                    export_receipt["changes"] = {"compared": both_whole, "count": changes_result["matched"], "removed": removed,
                                                 "file": changes_result.get("all_results"), "inline": changes_page.page,
                                                 "note": "keys and values of the recovered copy that are not in the original, are not in the recovered copy, or differ; a withheld value is compared by its bytes and shown by place only"}
                    if not both_whole:
                        export_receipt["status"] = "partial"
                        export_receipt["changes"]["note"] += "; a walk stopped at the time limit, so what is listed is not the whole difference"
                reader = regfexport_counts(read_from, max(5.0, CLOCK["deadline"] - time.monotonic() - 2)) if not walk.stopped_by_time else {"ran": False, "why": "the walk stopped at the time limit, so its counts are not whole"}
                if reader.get("ran") and reader.get("finished"):
                    reader["agrees"] = reader["keys"] == walk.keys and reader["values"] == walk.values
                    reader["regipy"] = {"keys": walk.keys, "values": walk.values}
                export_receipt["independent_reader"] = {"regfexport": reader}
                if reader.get("agrees") is False:
                    export_receipt["status"] = "partial"
                problems = walk.problems[:INLINE_PROBLEMS]
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
    receipt["sensitive_values_withheld"] = sensitive_log[:INLINE_PROBLEMS]
    receipt["sensitive_values_withheld_count"] = len(sensitive_log)
    values_file.close()
    receipt["values_file"] = values_file.shown
    receipt["unrecovered"] = unrecovered[:INLINE_PROBLEMS]
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
            reasons.append("the key and value records are %s%s" % (export_receipt.get("status"), (": " + export_receipt["why"]) if export_receipt.get("why") else ""))
        reader_said = (export_receipt.get("independent_reader") or {}).get("regfexport") or {}
        if reader_said.get("ran") and not reader_said.get("finished"):
            reasons.append(reader_said["why_not_finished"])
        if reader_said.get("agrees") is False:
            reasons.append("regfexport counted %d keys and %d values where regipy counted %d and %d" % (
                reader_said["keys"], reader_said["values"], reader_said["regipy"]["keys"], reader_said["regipy"]["values"]))
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
                    receipt["replay"]["entries_applied"], "y" if receipt["replay"]["entries_applied"] == 1 else "ies", receipt["replay"]["sequence_after"][0] - 1))
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
    print(json.dumps(answer, indent=1))


def forget_placed():
    """A recovered copy is a result with its receipt, which is written last: a copy placed by a run that did not get to its receipt is removed, not left to be taken for one."""
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
    print(json.dumps({"error": "stopped by signal %d before the answer was complete" % signum, "status": "interrupted",
                      "status_basis": "the tool was stopped by signal %d; nothing it had made is a result (the temporary files were removed%s)" % (
                          signum, ", and so was the recovered copy, which had no receipt yet" if copies else ""), "signal": signum}), flush=True)


if __name__ == "__main__":
    try:
        main()
    except SystemExit:
        raise
    except ValueError as exc:
        fail(str(exc))
    except Exception as exc:                                  # whatever hostile input does, the answer is JSON
        forget_temps()
        forget_placed()
        print(json.dumps({"ok": False, "error": "the run failed", "status": "failed", "status_basis": "the tool stopped with an unexpected error", "reason": "%s: %s" % (type(exc).__name__, exc)}))
        sys.exit(1)
