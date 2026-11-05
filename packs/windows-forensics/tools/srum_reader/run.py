#!/usr/bin/env python3
"""Read the System Resource Usage Monitor database (SRUDB.dat) through the backends that read it, and say which backend produced which row.

An adapter and a provenance layer, not a new ESE reader. SRUDB.dat is read by Eric Zimmerman's SrumECmd (through the installed `SrumECmd` wrapper, which runs
the pinned build with dotnet) and by dissect.target (`target-query -f srum`), whichever is installed; the tool runs each, reads what each wrote, and keeps
every row as JSON Lines in a file the answer names, with `backend` on every row. With both present it compares the row count of every table that both name
(`agree` or `disagree`); a backend that is missing, fails, runs out of time, reports an unsupported platform or writes a shape this tool does not know is
`not_run` or `not_compared`, said, and is never `agree`. esedb_query stays the route for the raw tables.

SrumECmd REFUSES TO RUN ON NON-WINDOWS HOSTS: the build pinned here has a message in its strings saying it needs Windows' own ESE libraries and exiting (read from the dll's strings; the build was never run). In a Linux image it therefore
gives no rows, and the answer says `unsupported_platform` for it; its rows come only from a Windows host. Dissect reads a collection directory (a root
with Windows/System32/sru/SRUDB.dat, as the windows-artefacts recipe passes it); for a single file only SrumECmd is tried.

What the tool itself reads (standard library only): the ESE file header of SRUDB.dat (its magic, format version, file type and database state: clean shutdown,
dirty shutdown, ...), and the names and sizes of the log and checkpoint files (.log, .chk, .jrs) beside it. A dirty database with no log beside it is
`partial`. The tool does not replay logs and does not repair anything: SrumECmd copies the database and its logs to a folder of its own (`--temp`) and
reads the copy; the evidence is only opened for reading. SRUM "recovery" belongs on a derivative the examiner records.

Per table the answer gives: the rows, the retained interval (the earliest and the latest row time), the table's counters with the unit the column name
states, how many application, user and profile ids did not resolve (kept, counted, never dropped), and the time semantics. A row's time is its end:
`interval_seconds_since_previous_row_time` is the distance to the previous distinct row time of the same table, NOT a measured length of the interval the
counters cover. Counters are never added, averaged or compared across tables. A profile (network) name needs the SOFTWARE hive (`software`, or the one hive
found under a given directory); without it a profile id is `unresolved` and says why.

What comes from help strings and metadata, not from a real run: the option names (-f, -r, --csv, --temp, --dt), the CSV file and column names, the console
lines parsed for the database state and the log replay, and, as an ASSUMPTION that no SrumECmd dll could hold, the Dissect record shape (JSON lines with `_recorddescriptor` and `ts`). This tool could not run SrumECmd or dissect.target where it was written
(no dotnet, no Windows, no dissect); the stand-in tests hold the adapter to the documented shapes, not to a real output.

SENSITIVE OUTPUT. Application paths, user names and profile names come from the evidence. Every string of the answer and of the rows file goes through
the shared boundary (a secret-shaped text is replaced by a marker with its length). There is no values file: nothing is written under write_values.
"""
import datetime
import hashlib
import json
import os
import re
import shutil
import signal
import stat
import struct
import subprocess
import sys
import tempfile
import time
from pathlib import Path

PARSER = "srum_reader/1"
DEFAULT_SECONDS = 200             # the manifest allows 300: the tool's own clock leaves a minute for ending a backend, closing the files and the answer
MAX_SECONDS = 240
SEAL_STOP = 296.5                 # seconds after the start: no string is judged past it (3.5 before the manifest's limit)
RUN_SHARE = 0.4                   # the most of the tool's own time one backend run is given (a share of the whole)
RESERVE_SHARE = 0.15              # the share kept back from the runs for reading what they wrote and for the answer
OUT_BYTES = 4 << 30               # the most any one file a backend writes may hold (the kernel enforces it); a table that reaches it is partial
LOG_BYTES = 32 << 20              # the most of a backend's console output that is read back
MAX_COLUMNS = 512
MAX_STAMPS = 250_000              # distinct row times kept per table to work out the distance to the previous one
MAX_LINE = 16 << 20               # the longest line of Dissect's output that is read
MAX_WALK = 200_000
MAX_DEPTH = 16
MAX_LOGS = 2000
MAX_LIMIT = 10_000
INLINE_BYTES = 256 << 10          # the most the inline rows may hold together; the rest are in the rows file only
ESE_MAGIC = bytes.fromhex("efcdab89")
ESE_STATES = {1: "just created", 2: "dirty shutdown", 3: "clean shutdown", 4: "being converted", 5: "force detach"}
EPOCH = datetime.datetime(1601, 1, 1, tzinfo=datetime.timezone.utc)

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
_STOP = {"cap": MAX_JUDGED_CHARS, "chars": 0, "by": None, "strings": 0}   # why judging stopped (None: it did not), and how many strings it withheld by their size


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
    `contains` filter, the order of a list)."""
    if not isinstance(text, str) or not text:
        return text
    return _quietly(lambda: _seal(text, kind, field, (), True))


def print_order(items, kind="name", text=str):
    """`items` in the order an answer prints them: by the text the answer PRINTS for each (the layers and the backstop, sealed_text), and the items
    whose text is the same placeholder in a random order that is new for every run. The rank of the withheld texts themselves (the order `sorted`
    would give, the order a directory or a hive lists them in) must never show in what an answer lists. `kind` is the kind of the field the items
    are printed in; `text` gives the string of an item."""
    def judge():
        out = []
        for n, i in enumerate(items):
            raw = text(i)
            shown = _seal(raw, kind, "", (), True) if isinstance(raw, str) and raw else raw
            out.append((shown, hashlib.blake2b(_ORDER_SALT + raw.encode("utf-8", "surrogatepass"), digest_size=8).digest(), n, i))
        return out
    items = list(items)
    keyed = _quietly(judge)
    keyed.sort(key=lambda k: (k[0], k[1], k[2]))
    return [k[3] for k in keyed]


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
    """Whether judging must stop for the string about to be judged, which has `n` characters (counted against the cap of the run, unless the string is
    only being judged to see what an answer would print). It says why, once, in _STOP["by"]: the cap of characters, or the clock of the seal."""
    if n and not _QUIET[0]:
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
    """A string not judged because judging stopped: withheld whole, by its size, counted (what is let through is only _unjudged)."""
    if not _QUIET[0]:
        _STOP["strings"] += 1
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
    stopped = {"stopped_by": _STOP["by"], "strings_withheld_by_the_stop": _STOP["strings"]} if _STOP["by"] is not None else {}
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
            if BOUNDARY["replaced"] > 0:
                why.append("%d string(s) still held a secret-shaped text when the answer was checked on its way out and were replaced" % BOUNDARY["replaced"])
            if _STOP["by"] is not None:
                why.append("judging the strings stopped at %s: %d string(s) after it were withheld by their size" % (_STOP["by"], _STOP["strings"]))
            out["status_basis"] = "%s%s (see boundary)" % (basis + "; " if isinstance(basis, str) and basis else "", "; ".join(why))
    return out


def emit(doc, **dumps_kwargs):
    """Print an answer through the boundary (the only way an answer leaves a tool that carries this block)."""
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



# ---- what the boundary is told about this tool's fields ---------------------------------------------------------------------------
# The keys the answers and the rows file of this tool are made of: names the tool wrote itself. They are shown as they are even past the judging time, so that an answer
# stays readable; a name from the evidence that is one of them holds no secret. (Regenerate from the literal keys when a key is added.)
OWN_NAMES.update((
    '_extra_cells', 'error_lines', 'first_error_line', 'all_results', 'app', 'app_description', 'app_id', 'app_path',
    'app_resolved', 'app_resource_usage', 'app_timeline', 'applicationresourceusage', 'applicationtimeline', 'appresourceusage',
    'appresourceuseinfo', 'apptimeline', 'apptimelineprovider', 'backend', 'backends', 'bytes',
    'canonical_table', 'clean', 'columns', 'comparison', 'console_database_state', 'console_engine_version',
    'console_format_version', 'counter_units', 'counters', 'csv_files', 'cut_files', 'database',
    'deadline', 'directory', 'dirty', 'earliest', 'elapsed_seconds', 'energy_usage',
    'energy_usage_long_term', 'energyusage', 'energyusagelt', 'entries_seen', 'error', 'exit_code',
    'facts', 'file_error', 'file_type', 'files', 'first_time', 'format_version',
    'found', 'found_by', 'found_count', 'hive_unreadable', 'interface_luid', 'interface_type',
    'interval_seconds_since_previous_row_time', 'intervals_note', 'last_time', 'last_word', 'latest', 'logs',
    'logs_beside', 'logs_beside_count', 'logs_beside_note', 'logs_replayed', 'name', 'network_connectivity',
    'network_usage', 'networkconnections', 'networkconnectivity', 'networkconnectivityusage', 'networkdata', 'networkdatausage',
    'networkusage', 'networkusages', 'not_compared', 'not_compared_count', 'note', 'notes',
    'ok', 'other', 'parser', 'path', 'problems', 'profile',
    'profile_id', 'profile_name', 'profile_resolved', 'profile_unresolved_because', 'push_notifications', 'pushnotification',
    'pushnotifications', 'read_problems', 'reason', 'repaired_copy', 'result', 'retained_interval',
    'row', 'rows', 'rows_file', 'rows_inline_truncated', 'rows_total', 'rows_with_a_time_not_read',
    'rows_with_replaced_bytes', 'seconds', 'semantics_note', 'signal', 'software', 'software_hive',
    'source_file', 'source_row', 'state', 'state_code', 'status', 'status_basis',
    'table', 'table_errors', 'tables', 'tables_written', 'time', 'time_column',
    'time_note', 'time_raw', 'time_semantics', 'unit', 'unresolved', 'unresolved_ids',
    'unresolved_ids_total', 'unresolved_note', 'user', 'user_id', 'user_name', 'user_resolved',
    'user_sid', 'value', 'vfuprov', 'why', 'work',
    'program_group', 'subreaper', 'left_behind', 'unproven',
))

FIELDS.update({
    "path": "path", "database": "path", "software": "path", "rows_file": "path", "source_file": "path", "csv_files": "path", "logs": "path", "directory": "path",
    "app_path": "path", "time": "time", "time_raw": "text", "first_time": "time", "last_time": "time", "earliest": "time", "latest": "time",
    "user_sid": "sid", "table": "name", "backend": "name", "state": "name",
})
KEY_KINDS.update({"counters": "name", "other": "name", "tables": "name", "retained_interval": "name", "unresolved": "name", "columns": "name"})


def own(text):
    """A sentence the tool wrote itself: shown as it is even past the judging time (no evidence is in it)."""
    OWN_NAMES.add(text)
    return text


# ---- helpers ------------------------------------------------------------------------------------------------------------------------

def fail(message, **extra):
    close_values()
    emit({"ok": False, "error": message, "status": "failed", "status_basis": own("the tool stopped with an error (see error); no row was produced"), **extra})
    sys.exit(1)


def describe(exc):
    if isinstance(exc, OSError):
        return "%s: %s" % (type(exc).__name__, exc.strerror or exc)
    return "%s: %s" % (type(exc).__name__, exc)


CLOCK = {"deadline": None, "seconds": None}
OUTDIR = {"path": None}           # this run's output directory, once it is made: removed at the end if nothing was placed in it
TEMPS = []
TEMP_DIRS = []                    # the directories a backend writes into; each is removed when its run ends, or by the last word


def out_of_time():
    return CLOCK["deadline"] is not None and time.monotonic() > CLOCK["deadline"]


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
    for path in list(TEMP_DIRS):
        shutil.rmtree(path, ignore_errors=True)
        TEMP_DIRS.remove(path)


def shown_path(path):
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


def output_directory(identity):
    job, out = os.environ.get("JOB_ID"), os.environ.get("OUT")
    name = "srum_reader-" + identity
    if job and out:
        base = Path(out)
    else:
        agent = re.sub(r"[^A-Za-z0-9_.-]", "_", os.environ.get("AGENT_ID") or "tool")
        base = Path.cwd() / "work" / agent
    return base / name


class SealedPage(NoReplacePage):
    """A page whose rows are written through the boundary, placed in the tool's own output directory under a fixed name, never replacing an earlier file."""

    def __init__(self, directory, name, key, limit):
        super().__init__("srum_reader", key, limit)
        self.path = directory / name
        self.shown = shown_path(self.path)

    def _write(self, row):
        super()._write(row_object(row))

    def add(self, row):
        # the inline rows are held to INLINE_BYTES as well as to `limit`: a row past it goes to the file only (rows_inline_truncated says so)
        if len(self.page) < self.limit:
            self.used = getattr(self, "used", 0) + len(json.dumps(row, ensure_ascii=False, default=str))
            if self.used > INLINE_BYTES:
                self.limit = len(self.page)
        super().add(row)

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
            OWN_NAMES.add(result["all_results"])
        return result


# ---- the database and the files beside it ---------------------------------------------------------------------------------------------

class NotEse(Exception):
    pass


def read_header(path):
    """The ESE file header of SRUDB.dat, by the layout libyal documents (checksum 4 bytes, signature EF CD AB 89 at 4, format version at 8, file type at 12,
    database state at 52). Standard library only; nothing is repaired or replayed."""
    with open(path, "rb") as fh:
        head = fh.read(4096)
    if len(head) < 64 or head[4:8] != ESE_MAGIC:
        raise NotEse("the file does not start with the ESE signature (EF CD AB 89 at offset 4)")
    version, file_type = struct.unpack_from("<II", head, 8)
    code = struct.unpack_from("<I", head, 52)[0]
    return {"format_version": "0x%x" % version, "file_type": {0: "database", 1: "streaming file"}.get(file_type, "unknown (%d)" % file_type),
            "state_code": code, "state": ESE_STATES.get(code, "unknown (%d)" % code), "clean": code == 3, "dirty": code == 2}


def list_logs(directory):
    """(logs, more): the ESE log (.log), checkpoint (.chk) and journal (.jrs) files in the database's directory; links, directories and specials are not listed."""
    logs, more = [], 0
    try:
        with os.scandir(directory) as it:
            for entry in it:
                low = entry.name.lower()
                if not low.endswith((".log", ".chk", ".jrs")):
                    continue
                try:
                    if not entry.is_file(follow_symlinks=False):
                        continue
                    size = entry.stat(follow_symlinks=False).st_size
                except OSError:
                    continue
                if len(logs) < MAX_LOGS:
                    logs.append({"name": entry.name, "bytes": size})
                else:
                    more += 1
    except OSError:
        return [], 0
    logs.sort(key=lambda item: item["name"])
    return logs, more


def find_inputs(root):
    """(databases, hives, walked, why_stopped): under a directory, the files named SRUDB.dat and the files named SOFTWARE inside a directory named config. Links are
    not followed. The walk has a clock, a depth and an entry bound."""
    dbs, hives, walked, why = [], [], 0, None
    stack = [(root, 0)]
    while stack and why is None:
        directory, depth = stack.pop()
        try:
            it = os.scandir(directory)
        except OSError:
            continue
        with it:
            for entry in it:
                walked += 1
                if walked > MAX_WALK:
                    why = "more than %d directory entries" % MAX_WALK
                    break
                if out_of_time():
                    why = "the tool's own clock ran out"
                    break
                try:
                    if entry.is_dir(follow_symlinks=False):
                        if depth < MAX_DEPTH:
                            stack.append((entry.path, depth + 1))
                    elif entry.is_file(follow_symlinks=False):
                        low = entry.name.lower()
                        if low == "srudb.dat":
                            dbs.append(entry.path)
                        elif low == "software" and os.path.basename(directory).lower() == "config":
                            hives.append(entry.path)
                except OSError:
                    continue
    return sorted(dbs), sorted(hives), walked, why


# ---- times, tables, units ---------------------------------------------------------------------------------------------------------------

TIME_FORM = re.compile(r"^(\d{4})-(\d\d)-(\d\d)[ T](\d\d):(\d\d):(\d\d)(?:\.(\d{1,7}))?\s*(Z|[+-]\d\d:?\d\d)?$")


def parse_time(text):
    """A datetime (UTC) for a time the backends print, or None. A time with no zone is taken as UTC (what SrumECmd's own text says it prints; not shown by a real run)."""
    if not isinstance(text, str):
        return None
    m = TIME_FORM.match(text.strip())
    if not m:
        return None
    y, mo, d, h, mi, s, frac, zone = m.groups()
    try:
        value = datetime.datetime(int(y), int(mo), int(d), int(h), int(mi), int(s), int((frac or "0").ljust(6, "0")[:6]), tzinfo=datetime.timezone.utc)
        if zone and zone != "Z":
            sign = 1 if zone[0] == "+" else -1
            digits = zone[1:].replace(":", "")
            value = value - sign * datetime.timedelta(hours=int(digits[:2]), minutes=int(digits[2:4]))
    except (ValueError, OverflowError):
        return None
    return value


def iso(value):
    if value is None:
        return None
    text = value.strftime("%Y-%m-%dT%H:%M:%S")
    return text + (".%06d" % value.microsecond if value.microsecond else "") + "Z"


# What is known of each table, from public SRUM research and the backend's own column names; not checked against a real database here. A table the
# backend names differently is kept under its own name and is not compared.
CANON = {
    "networkusages": "network_usage", "networkusage": "network_usage", "networkdata": "network_usage", "networkdatausage": "network_usage",
    "networkconnections": "network_connectivity", "networkconnectivity": "network_connectivity", "networkconnectivityusage": "network_connectivity",
    "appresourceuseinfo": "app_resource_usage", "applicationresourceusage": "app_resource_usage", "appresourceusage": "app_resource_usage",
    "pushnotifications": "push_notifications", "pushnotification": "push_notifications",
    "energyusage": "energy_usage", "energyusagelt": "energy_usage_long_term",
    "apptimelineprovider": "app_timeline", "applicationtimeline": "app_timeline", "apptimeline": "app_timeline",
    "vfuprov": "vfuprov",
}
SEMANTICS = {
    "network_usage": "bytes sent and received by an application and user on an interface; the row time is when the row was written (the end of its interval)",
    "network_connectivity": "connection start time and connected duration of a network profile for an application and user; the row time is when the row was written",
    "app_resource_usage": "CPU cycle, disk byte and operation counters of an application and user accrued up to the row time; the row time is when the row was written",
    "push_notifications": "push notifications by type with their payload size, for an application; the row time is when the row was written",
    "energy_usage": "battery state and energy counters; levels and capacities are states, not accruals; the row time is when the row was written",
    "energy_usage_long_term": "the long-term copy of the energy table; the row time is when the row was written",
    "app_timeline": "an application's foreground and input durations; the row time is when the row was written",
    "vfuprov": "a table whose columns this tool lists but does not interpret; the row time is when the row was written",
}
SEMANTICS_NOTE = own("These readings are from public SRUM research and the backends' column names, not from a run on a real database here. Counters are never added, averaged or compared across tables.")
UNIT_RULES = (
    (re.compile(r"bytes|payloadsize"), "bytes"),
    (re.compile(r"operations|flushes|contextswitches|^count$"), "count"),
    (re.compile(r"cycletime$"), "cpu cycles"),
    (re.compile(r"durationms$|msec$"), "milliseconds"),
)
NO_UNIT = own("not stated by the backend")
NOT_COUNTERS = frozenset(("id", "appid", "userid", "l2profileid", "interfaceluid", "interfacetype", "networktype", "sidtype", "notificationtype", "l2profileflags",
                          "flags", "index", "maptype", "configurationhash", "session", "statetransition", "islt"))
INTEGER = re.compile(r"^-?\d{1,30}$")
TIME_COLUMNS = ("Timestamp", "TimeStamp", "EventTimestamp", "EndTime")
ANSI = re.compile(r"\x1b\[[0-9;?]*[ -/]*[@-~]")
STATE_LINE = re.compile(r"\(State: (?P<state>[^,()]{1,60}), Format Version: (?P<fv>[^,()]{1,30}), Engine Version: (?P<ev>[^()]{1,30})\)")
CSV_NAME = re.compile(r"^(?:.*?_)?SrumECmd_(?P<table>.+)_Output\.csv$")


def canon_of(name):
    return CANON.get(re.sub(r"[^a-z0-9]", "", str(name).lower()))


def unit_of(column):
    low = column.lower()
    for pattern, unit in UNIT_RULES:
        if pattern.search(low):
            return unit
    return NO_UNIT


def stripped(value):
    return (value or "").strip() if isinstance(value, str) else ""


def normalise_srumecmd(table, n, rec, hive_given, hive_failed):
    """One CSV row of SrumECmd as a row of this tool: the columns it names (Id, Timestamp, AppId, ExeInfo, UserId, Sid, UserName, L2ProfileId, ProfileName,
    InterfaceLuid, InterfaceType, and the counters) taken by name; every other column is kept in `other`, as printed. Unresolved ids are kept and flagged."""
    used = set()

    def take(*names):
        for name in names:
            if name in rec:
                used.add(name)
                return rec[name]
        return None

    time_column = next((c for c in TIME_COLUMNS if c in rec and stripped(rec[c])), None)
    raw_time = rec[time_column] if time_column else None
    used.update(c for c in TIME_COLUMNS if c in rec)
    app_id, app_path, app_desc = take("AppId"), take("ExeInfo"), take("ExeInfoDescription")
    user_id, user_sid, user_name = take("UserId"), take("Sid"), take("UserName")
    profile_id, profile_name = take("L2ProfileId"), take("ProfileName")
    luid, itype = take("InterfaceLuid"), take("InterfaceType")
    row = {"row": "srum", "backend": "srumecmd", "table": table, "source_row": n, "time_column": time_column, "time_raw": raw_time}
    row["time"] = iso(parse_time(raw_time)) if raw_time is not None else None
    if app_id is not None or app_path is not None:
        row["app_id"], row["app_path"], row["app_resolved"] = app_id, app_path or None, bool(stripped(app_path))
        if app_desc:
            row["app_description"] = app_desc
    if user_id is not None or user_sid is not None:
        row["user_id"], row["user_sid"], row["user_name"], row["user_resolved"] = user_id, user_sid or None, user_name or None, bool(stripped(user_sid))
    if profile_id is not None and stripped(profile_id) not in ("", "0"):
        resolved = bool(stripped(profile_name))
        row["profile_id"], row["profile_name"], row["profile_resolved"] = profile_id, profile_name or None, resolved
        if not resolved:
            if hive_failed:
                row["profile_unresolved_because"] = own("SrumECmd could not read the SOFTWARE hive")
            elif hive_given:
                row["profile_unresolved_because"] = own("a SOFTWARE hive was given but SrumECmd printed no name for this profile id")
            else:
                row["profile_unresolved_because"] = own("no SOFTWARE hive was given")
    if luid is not None or itype is not None:
        row["interface_luid"], row["interface_type"] = luid, itype
    counters, other = {}, {}
    for column, value in rec.items():
        if column in used or column is None:
            continue
        if INTEGER.match(stripped(value)) and column.lower() not in NOT_COUNTERS:
            counters[column] = {"value": int(value), "unit": unit_of(column)}
        else:
            other[column] = value
    row["counters"], row["other"] = counters, other
    return row


def normalise_dissect(table, n, rec):
    raw_time = rec.get("ts", rec.get("timestamp"))
    other = {}
    for key, value in rec.items():
        if key.startswith("_"):
            continue
        other[key] = value if isinstance(value, (str, int, float, bool)) or value is None else json.dumps(value, ensure_ascii=False, default=str)
    row = {"row": "srum", "backend": "dissect", "table": table, "source_row": n, "time_column": "ts" if "ts" in rec else ("timestamp" if "timestamp" in rec else None),
           "time_raw": raw_time if isinstance(raw_time, str) else None, "counters": {}, "other": other}
    row["time"] = iso(parse_time(raw_time))
    return row


# ---- running a backend -------------------------------------------------------------------------------------------------------------------

def run_program(argv, work, name, seconds):
    """(exit code, timed out, error): the program in this tool's process group, under communicate_bounded with `seconds`, its stdout and stderr in files of `work`
    (never pipes; the kernel stops any one file at OUT_BYTES). Nothing it prints is kept anywhere else."""
    try:
        with open(os.path.join(work, name + ".stdout"), "wb") as out, open(os.path.join(work, name + ".stderr"), "wb") as err:
            saved = None
            try:
                try:
                    import resource
                    soft, hard = resource.getrlimit(resource.RLIMIT_FSIZE)
                    if soft == resource.RLIM_INFINITY or soft > OUT_BYTES:
                        saved = (soft, hard)
                        resource.setrlimit(resource.RLIMIT_FSIZE, (OUT_BYTES, hard))
                except (ImportError, ValueError, OSError):
                    saved = None
                proc = spawn(argv, stdin=subprocess.DEVNULL, stdout=out, stderr=err)
            except OSError as exc:
                return None, False, "could not be started: %s" % describe(exc)
            finally:
                if saved is not None:       # only the child was to have the limit
                    try:
                        resource.setrlimit(resource.RLIMIT_FSIZE, saved)
                    except (ValueError, OSError):
                        pass
            ACTIVE.append(proc)
            try:
                _o, _e, timed_out = communicate_bounded(proc, max(1.0, seconds))
            finally:
                if proc in ACTIVE:
                    ACTIVE.remove(proc)
    except OSError as exc:
        return None, False, "its output files could not be made: %s" % describe(exc)
    return proc.returncode, timed_out, None


STDERR_ERROR = re.compile(r"(?im)^.{0,200}(?:\berror\b|\bexception\b|traceback|\bfatal\b|\bfailed\b|\[(?:ERR|FTL)\]).{0,200}$")


def stderr_errors(work, name, stdout_too=False):
    """(count, first line): the lines of the program's stderr (and, for SrumECmd, its console on stdout) that say error, exception, failed or fatal. A program that exits 0 and
    complains is not trusted to have read everything."""
    text = ""
    for suffix in ((".stderr", ".stdout") if stdout_too else (".stderr",)):
        try:
            with open(os.path.join(work, name + suffix), "rb") as fh:
                text += fh.read(LOG_BYTES).decode("utf-8", "replace") + "\n"
        except OSError:
            pass
    hits = [m.group(0) for m in STDERR_ERROR.finditer(ANSI.sub("", text)) if "Error exporting" not in m.group(0) and "Error processing file" not in m.group(0)]
    first = re.sub(r"[^\x20-\x7e]", "?", hits[0])[:200] if hits else None
    return len(hits), first


def console_text(work, name):
    """What the program printed (stdout, then stderr), read to LOG_BYTES, without terminal colour codes."""
    text = ""
    for suffix in (".stdout", ".stderr"):
        try:
            with open(os.path.join(work, name + suffix), "rb") as fh:
                text += fh.read(LOG_BYTES).decode("utf-8", "replace") + "\n"
        except OSError:
            pass
    return ANSI.sub("", text)


def run_budget():
    """The seconds a backend run is given: a share of the tool's whole time, and never into the part kept back for reading and the answer."""
    total = CLOCK["seconds"]
    left = CLOCK["deadline"] - time.monotonic() - total * RESERVE_SHARE
    return min(total * RUN_SHARE, left)


def backend_record(name):
    return {"name": name, "state": "not_attempted", "why": None, "exit_code": None, "files": [], "facts": {}, "work": None}


def run_srumecmd(db, software, parent):
    """SrumECmd through the installed wrapper (it runs the pinned build with dotnet). The wrapper is given the database, the SOFTWARE hive when there is one, a CSV
    directory and a --temp directory of its own, under a directory of this tool that is removed at the end; the option names are the ones its help strings
    list (-f, -r, --csv, --temp, --dt), not shown by a real run."""
    rec = backend_record("srumecmd")
    program = shutil.which("SrumECmd")
    if not program:
        rec.update(state="not_installed", why=own("SrumECmd is not in this image (it runs through dotnet; requires/host.json pins it, optional)"))
        return rec
    seconds = run_budget()
    if seconds < 2:
        rec.update(state="not_attempted", why=own("the tool's own time was used before SrumECmd could be started"))
        return rec
    try:
        work = tempfile.mkdtemp(dir=parent, prefix=".srumecmd-")
    except OSError as exc:
        rec.update(state="failed", why="SrumECmd's work directory could not be made: %s" % describe(exc))
        return rec
    TEMP_DIRS.append(work)
    rec["work"] = work
    csv_dir, temp_dir = os.path.join(work, "csv"), os.path.join(work, "tmp")
    try:
        os.mkdir(csv_dir)
        os.mkdir(temp_dir)
    except OSError as exc:
        rec.update(state="failed", why="SrumECmd's work directory could not be made: %s" % describe(exc))
        return rec
    argv = [program, "-f", os.path.abspath(db)]
    if software:
        argv += ["-r", os.path.abspath(software)]
    argv += ["--csv", csv_dir, "--temp", temp_dir, "--dt", "yyyy-MM-dd HH:mm:ss"]
    code, timed_out, error = run_program(argv, work, "srumecmd", seconds)
    rec["exit_code"] = code
    text = console_text(work, "srumecmd")
    if "Non-Windows platforms not supported" in text:
        rec.update(state="unsupported_platform", why=own("SrumECmd refuses to run on a non-Windows host (it needs Windows' own ESE libraries and esentutl.exe): it read nothing"))
        return rec
    if error:
        rec.update(state="failed", why=error)
        return rec
    if timed_out:
        rec.update(state="timed_out", why=own("SrumECmd did not finish in %d seconds (it and what it started were ended)" % max(1, int(seconds))))
        return rec
    if code != 0:
        rec.update(state="failed", why=own("SrumECmd exited %d" % code) if code >= 0 else own("SrumECmd was ended by signal %d" % -code))
        return rec
    names = sorted(n for n in os.listdir(csv_dir) if CSV_NAME.match(n))
    for n in names:
        try:
            if os.lstat(os.path.join(csv_dir, n)).st_size >= OUT_BYTES:
                rec["facts"]["cut_files"] = rec["facts"].get("cut_files", 0) + 1
        except OSError:
            pass
    if not names:
        rec.update(state="failed", why=own("SrumECmd exited 0 and wrote no table CSV (a file named like *_SrumECmd_<table>_Output.csv)"))
        return rec
    rec["files"] = [(CSV_NAME.match(n).group("table"), os.path.join(csv_dir, n)) for n in names]
    facts = rec["facts"]
    m = STATE_LINE.search(text)
    if m:
        facts["console_database_state"], facts["console_format_version"], facts["console_engine_version"] = m.group("state"), m.group("fv"), m.group("ev")
    facts["logs_replayed"] = True if "replayed into the copies" in text else (False if "could not be replayed" in text else None)
    facts["hive_unreadable"] = "Unable to read SOFTWARE hive" in text
    facts["table_errors"] = len(re.findall(r"Error exporting '[^']{1,80}' data", text))
    m = re.search(r"([\d,]{1,12}) problem\(s\) found while reading the database", text)
    facts["read_problems"] = int(m.group(1).replace(",", "")) if m else 0
    facts["repaired_copy"] = bool(re.search(r"repaired with esentutl|repairing the copy", text))
    facts["file_error"] = "Error processing file!" in text
    facts["error_lines"], facts["first_error_line"] = stderr_errors(work, "srumecmd", True)
    rec["state"] = "ran"
    return rec


def run_dissect(target, parent):
    """dissect.target's `target-query -f srum --json` over a collection directory, as the windows-artefacts recipe runs it."""
    rec = backend_record("dissect")
    program = shutil.which("target-query")
    if not program:
        rec.update(state="not_installed", why=own("target-query (dissect.target) is not in this image"))
        return rec
    if not os.path.isdir(target):
        rec.update(state="not_applicable", why=own("dissect.target opens a collection directory, and the path given is a single file: only SrumECmd can read it"))
        return rec
    seconds = run_budget()
    if seconds < 2:
        rec.update(state="not_attempted", why=own("the tool's own time was used before target-query could be started"))
        return rec
    try:
        work = tempfile.mkdtemp(dir=parent, prefix=".dissect-")
    except OSError as exc:
        rec.update(state="failed", why="target-query's work directory could not be made: %s" % describe(exc))
        return rec
    TEMP_DIRS.append(work)
    rec["work"] = work
    code, timed_out, error = run_program([program, "--help"], work, "help", min(20.0, seconds))
    if error or timed_out or code != 0 or "--json" not in console_text(work, "help"):
        rec.update(state="unsupported_shape", why=own("this target-query lists no --json (or its --help did not answer): its text output is not read"))
        return rec
    code, timed_out, error = run_program([program, "-f", "srum", "--json", os.path.abspath(target)], work, "srum", run_budget())
    rec["exit_code"] = code
    if error:
        rec.update(state="failed", why=error)
    elif timed_out:
        rec.update(state="timed_out", why=own("target-query did not finish in time (it and what it started were ended)"))
    elif code != 0:
        text = console_text(work, "srum")
        unsupported = re.search(r"unknown (plugin|function)|no (such )?(plugin|function)|PluginNotFound|not a valid (plugin|function)|invalid choice|unrecognized arguments", text, re.I)
        rec.update(state="unsupported" if unsupported else "failed", why=own("this version of target-query has no srum function" if unsupported else "target-query exited %d" % code) if code >= 0 else own(
            "target-query was ended by signal %d" % -code))
    else:
        rec["files"] = [("srum", os.path.join(work, "srum.stdout"))]
        rec["facts"]["error_lines"], rec["facts"]["first_error_line"] = stderr_errors(work, "srum")
        rec["state"] = "ran"
    return rec


# ---- reading what a backend wrote ----------------------------------------------------------------------------------------------------------

class Reading:
    """Rows read from one backend's files, and what went wrong on the way."""

    def __init__(self):
        self.problems = []              # sentences, first ones kept
        self.problem_count = 0
        self.stopped = False            # the tool's own clock ran out before the end of the files

    def problem(self, text):
        self.problem_count += 1
        if len(self.problems) < 20:
            self.problems.append(text)


def walk_csv(path, table, visit, reading):
    import csv
    csv.field_size_limit(MAX_LINE)                 # a cell is read whole up to the line bound; a longer one ends the table with its problem named
    try:
        fh = open(path, "r", encoding="utf-8-sig", errors="replace", newline="")
    except OSError as exc:
        reading.problem("%s: the CSV could not be opened: %s" % (table, describe(exc)))
        return
    with fh:
        try:
            reader = csv.reader(fh)
            header = next(reader, None)
            if header is None:
                reading.problem("%s: the CSV is empty (no header row)" % table)
                return
            if len(set(header)) != len(header):
                reading.problem("%s: the CSV header names a column twice: the later column's cell replaces the earlier one in each row" % table)
            if len(header) > MAX_COLUMNS:
                reading.problem("%s: the CSV header has %d columns (more than %d): it was not read" % (table, len(header), MAX_COLUMNS))
                return
            n = 0
            for cells in reader:
                if out_of_time():
                    reading.stopped = True
                    return
                n += 1
                if not cells:
                    continue
                record = dict(zip(header, cells))
                if len(cells) > len(header):
                    record["_extra_cells"] = ",".join(cells[len(header):])
                    reading.problem("%s: row %d has %d cell(s) more than the header" % (table, n, len(cells) - len(header)))
                elif len(cells) < len(header):
                    reading.problem("%s: row %d has %d cell(s) fewer than the header" % (table, n, len(header) - len(cells)))
                visit(table, n, record)
        except (csv.Error, UnicodeError) as exc:
            reading.problem("%s: the CSV could not be read past row %d: %s" % (table, locals().get("n", 0), describe(exc)))


def walk_jsonl(path, visit, reading):
    try:
        fh = open(path, "rb")
    except OSError as exc:
        reading.problem("the output could not be opened: %s" % describe(exc))
        return
    n = 0
    with fh:
        while True:
            if out_of_time():
                reading.stopped = True
                return
            line = fh.readline(MAX_LINE + 1)
            if not line:
                return
            if len(line) > MAX_LINE and not line.endswith(b"\n"):
                while True:                       # the rest of an over-long line is read and dropped, never held
                    rest = fh.readline(1 << 20)
                    if not rest or rest.endswith(b"\n"):
                        break
                n += 1
                reading.problem("record %d is a line longer than %d bytes: it was not read" % (n, MAX_LINE))
                continue
            if not line.strip():
                continue
            n += 1
            try:
                record = json.loads(line.decode("utf-8", "replace"))
            except ValueError:
                reading.problem("record %d is not JSON" % n)
                continue
            if not isinstance(record, dict):
                reading.problem("record %d is not a JSON object" % n)
                continue
            descriptor = record.get("_recorddescriptor")
            name = descriptor[0] if isinstance(descriptor, list) and descriptor and isinstance(descriptor[0], str) else None
            if name is None:
                reading.problem("record %d has no _recorddescriptor: its table is unknown" % n)
            stamp = record.get("ts", record.get("timestamp"))
            if not isinstance(stamp, str) or parse_time(stamp) is None:
                reading.problem("record %d has no readable ts: the record shape is not the one this tool expects" % n)
            visit(name.rsplit("/", 1)[-1] if name else "srum", n, record)


def walk(backend, visit, reading):
    if backend["name"] == "srumecmd":
        for table, path in backend["files"]:
            walk_csv(path, table, visit, reading)
            if reading.stopped:
                return
    else:
        for _table, path in backend["files"]:
            walk_jsonl(path, visit, reading)


def time_cell(backend_name, record):
    if backend_name == "srumecmd":
        for column in TIME_COLUMNS:
            if column in record and stripped(record[column]):
                return record[column]
        return None
    value = record.get("ts", record.get("timestamp"))
    return value if isinstance(value, str) else None


def micros(value):
    return (value - EPOCH) // datetime.timedelta(microseconds=1)


class TableStats:
    def __init__(self):
        self.rows = 0
        self.first = self.last = None
        self.unresolved = {"app": 0, "user": 0, "profile": 0}
        self.time_unparsed = 0
        self.replaced_bytes = 0
        self.columns = {}
        self.counter_units = {}


def compare(counts):
    """counts = {"srumecmd": {table: rows}, "dissect": {table: rows}} for the backends that ran. Row counts per table that both name, by the table's canonical key."""
    keys = {}
    for backend, tables in counts.items():
        for name, rows in tables.items():
            keys.setdefault(canon_of(name), {}).setdefault(backend, []).append((name, rows))
    per, not_compared, differ = {}, [], False
    for key, backends in keys.items():
        if key is None:
            not_compared.extend({"backend": b, "table": n, "rows": r} for b, items in backends.items() for n, r in items)
            continue
        entry = {b: sum(r for _n, r in items) for b, items in backends.items()}
        both = len(entry) == len(counts)
        entry["result"] = ("agree" if len(set(entry.values())) == 1 else "disagree") if both else "disagree"
        if not both:
            entry["why"] = own("only %s names this table" % "/".join(sorted(b for b in entry if b != "result")))
        if entry["result"] == "disagree":
            differ = True
        per[key] = entry
    state = "disagree" if differ else ("not_compared" if not_compared else "agree")
    return {"state": state, "tables": per, "not_compared": not_compared[:50], "not_compared_count": len(not_compared)}


# ---- the run -------------------------------------------------------------------------------------------------------------------------------

def last_word(signum):
    forget_temps()
    if OUTDIR["path"] is not None:
        try:
            os.rmdir(OUTDIR["path"])          # an interrupted run leaves no empty directory; one that holds a placed rows file is kept
        except OSError:
            pass
    close_values()
    emit({"error": "stopped by signal %d before the answer was complete" % signum, "status": "interrupted",
          "status_basis": own("the tool was stopped by signal %d; nothing it had made is a result (the backends were ended and the temporary files were removed)" % signum),
          "signal": signum})


def check_args(args):
    if not isinstance(args, dict):
        fail("the arguments are one JSON object")
    path = args.get("path")
    if not isinstance(path, str) or not path:
        fail("path is required: SRUDB.dat, or a directory that holds it (a collection root, for dissect.target)")
    software = args.get("software")
    if software is not None and (not isinstance(software, str) or not software):
        fail("software, when given, is the path of the SOFTWARE hive")
    backend = args.get("backend", "all")
    if backend not in ("all", "srumecmd", "dissect"):
        fail("backend is all, srumecmd or dissect", backend=backend if isinstance(backend, str) else None)
    limit = args.get("limit", 100)
    if isinstance(limit, bool) or not isinstance(limit, int) or not 1 <= limit <= MAX_LIMIT:
        fail("limit must be a whole number from 1 to %d" % MAX_LIMIT)
    seconds = args.get("max_seconds", DEFAULT_SECONDS)
    if isinstance(seconds, bool) or not isinstance(seconds, (int, float)) or not 1 <= seconds <= MAX_SECONDS:
        fail("max_seconds must be a number from 1 to %d" % MAX_SECONDS)
    return path, software, backend, limit, float(seconds)


def regular(path, what):
    try:
        mode = os.stat(path).st_mode
    except OSError as exc:
        fail("%s could not be read" % what, path=path, reason=describe(exc))
    if not stat.S_ISREG(mode):
        fail("%s is not a regular file, so it was not opened" % what, path=path)


def main():
    seal_stop_after(SEAL_STOP)
    install_signal_handlers()
    STATE["last_word"] = last_word
    started = time.monotonic()
    try:
        args = json.load(sys.stdin)
    except ValueError as exc:
        fail("arguments are not valid JSON", reason=str(exc))
    path, software_arg, which, limit, seconds = check_args(args)
    CLOCK["deadline"], CLOCK["seconds"] = started + seconds, seconds
    OWN_NAMES.add(path)
    reasons, notes = [], []
    # the inputs: one database, and the SOFTWARE hive when there is one
    try:
        mode = os.stat(path).st_mode
    except OSError as exc:
        fail("path could not be read", path=path, reason=describe(exc))
    target = None
    software, software_from = software_arg, "argument" if software_arg else None
    if stat.S_ISDIR(mode):
        target = path
        dbs, hives, walked, why = find_inputs(path)
        if why:
            fail("the directory could not be searched for SRUDB.dat: " + why, path=path, entries_seen=walked)
        if len(dbs) != 1:
            fail("the directory holds %d file(s) named SRUDB.dat, not one: name the one to read as path" % len(dbs), path=path, found=dbs[:10], found_count=len(dbs))
        db = dbs[0]
        if software is None and len(hives) == 1:
            software, software_from = hives[0], "found under the directory (config/SOFTWARE)"
        elif software is None and len(hives) > 1:
            notes.append(own("%d files named config/SOFTWARE were found under the directory and none was chosen: name one as software" % len(hives)))
    elif stat.S_ISREG(mode):
        db = path
    else:
        fail("path is neither a regular file nor a directory, so it was not opened", path=path)
    if software is not None:
        regular(software, "software")
    OWN_NAMES.update(x for x in (software_arg,) if x)          # (only what the caller typed: a name found under a directory is evidence and is judged)
    try:
        header = read_header(db)
    except NotEse as exc:
        fail("the database is not an ESE file: " + str(exc), path=db)
    except OSError as exc:
        fail("the database could not be read", path=db, reason=describe(exc))
    logs, logs_more = list_logs(os.path.dirname(os.path.abspath(db)))
    database = {"path": db, "bytes": os.stat(db).st_size, **header, "logs_beside": logs, "logs_beside_count": len(logs) + logs_more,
                "logs_beside_note": own("the files ending .log, .chk or .jrs in the database's directory; this tool does not replay them")}
    identity = hashlib.sha256(json.dumps([os.path.abspath(db), software, which, os.stat(db).st_size, os.stat(db).st_mtime_ns]).encode("utf-8")).hexdigest()[:12]
    directory = output_directory(identity)
    try:
        directory.mkdir(parents=True, exist_ok=True)
    except OSError as exc:
        fail("the output directory could not be made", reason=describe(exc))
    OUTDIR["path"] = str(directory)
    OWN_NAMES.add(shown_path(directory))
    backends = []
    try:
        if which in ("all", "srumecmd"):
            backends.append(run_srumecmd(db, software, directory))
        if which in ("all", "dissect") and not out_of_time():
            backends.append(run_dissect(target if target else db, directory))
        ran = [b for b in backends if b["state"] == "ran"]
        # pass 1: the distinct row times of every table, to work out the distance to the previous one
        stamps, full = {}, set()
        reading = {b["name"]: Reading() for b in ran}

        def collect(backend_name):
            def visit(table, _n, record):
                cell = time_cell(backend_name, record)
                value = parse_time(cell) if cell is not None else None
                if value is None:
                    return
                bucket = stamps.setdefault((backend_name, table), set())
                if len(bucket) >= MAX_STAMPS:
                    full.add((backend_name, table))
                else:
                    bucket.add(micros(value))
            return visit

        for b in ran:
            if not out_of_time():
                walk(b, collect(b["name"]), Reading())
        import bisect
        ordered = {key: sorted(values) for key, values in stamps.items()}
        stamps.clear()
        # pass 2: the rows
        page = SealedPage(directory, "rows.jsonl", [identity, which], limit)
        stats = {b["name"]: {} for b in ran}
        hive_given = software is not None

        def write(backend):
            name = backend["name"]
            hive_failed = bool(backend["facts"].get("hive_unreadable"))

            def visit(table, n, record):
                row = normalise_srumecmd(table, n, record, hive_given, hive_failed) if name == "srumecmd" else normalise_dissect(table, n, record)
                s = stats[name].setdefault(table, TableStats())
                s.rows += 1
                if any(isinstance(v, str) and "�" in v for v in record.values()):
                    s.replaced_bytes += 1
                for column in record:
                    if column is not None and len(s.columns) < MAX_COLUMNS:
                        s.columns.setdefault(column, None)
                for column, entry in row.get("counters", {}).items():
                    s.counter_units.setdefault(column, entry["unit"])
                for kind, flag in (("app", "app_resolved"), ("user", "user_resolved"), ("profile", "profile_resolved")):
                    if flag in row and not row[flag]:
                        s.unresolved[kind] += 1
                when = parse_time(row.get("time_raw")) if row.get("time_raw") else None
                if row.get("time_raw") and when is None:
                    s.time_unparsed += 1
                if when is not None:
                    v = micros(when)
                    s.first = v if s.first is None else min(s.first, v)
                    s.last = v if s.last is None else max(s.last, v)
                    key = (name, table)
                    if key in ordered and key not in full:
                        i = bisect.bisect_left(ordered[key], v)
                        row["interval_seconds_since_previous_row_time"] = (v - ordered[key][i - 1]) / 1e6 if i > 0 else None
                page.add(row)
            return visit

        for b in ran:
            if out_of_time():
                reading[b["name"]].stopped = True
                continue
            walk(b, write(b), reading[b["name"]])
        rows_result = page.finish()
        # the answer
        tables = []
        for bname, per in stats.items():
            for table, s in per.items():
                key = canon_of(table)
                entry = {"backend": bname, "table": table, "rows": s.rows, "retained_interval": {"earliest": iso(EPOCH + datetime.timedelta(microseconds=s.first)) if s.first is not None else None,
                                                                                  "latest": iso(EPOCH + datetime.timedelta(microseconds=s.last)) if s.last is not None else None},
                         "unresolved_ids": dict(s.unresolved), "rows_with_a_time_not_read": s.time_unparsed, "rows_with_replaced_bytes": s.replaced_bytes,
                         "columns": list(s.columns), "counter_units": dict(s.counter_units), "canonical_table": key,
                         "time_semantics": SEMANTICS.get(key, own("not known to this tool: the table is kept under the name the backend gave it")) if bname == "srumecmd" else own(
                             "dissect.target's record time (ts) as it printed it; the table is not interpreted by this tool")}
                tables.append(entry)
                if (bname, table) in full:
                    entry["intervals_note"] = own("more than %d distinct row times: interval_seconds_since_previous_row_time is not given for this table" % MAX_STAMPS)
        # what makes the status partial
        for b in ran:
            r = reading[b["name"]]
            if r.stopped:
                reasons.append("the tool's own clock (%d seconds) ran out while %s's output was being read: the rows after that point were not read" % (int(seconds), b["name"]))
            if r.problem_count:
                reasons.append("%d problem(s) reading %s's output (problems names the first)" % (r.problem_count, b["name"]))
            if b["facts"].get("cut_files"):
                reasons.append("%d of %s's output files reached the %d-byte cap and were cut" % (b["facts"]["cut_files"], b["name"], OUT_BYTES))
            if b["facts"].get("table_errors"):
                reasons.append("SrumECmd reported %d table(s) it could not export" % b["facts"]["table_errors"])
            if b["facts"].get("read_problems"):
                reasons.append("SrumECmd reported %d problem(s) while reading the database" % b["facts"]["read_problems"])
            if b["facts"].get("file_error"):
                reasons.append("SrumECmd reported an error processing the file")
            if b["facts"].get("repaired_copy"):
                reasons.append("SrumECmd repaired its copy of the database (esentutl /p): what only the missing logs held is lost")
            if b["facts"].get("hive_unreadable"):
                reasons.append("SrumECmd could not read the SOFTWARE hive: profile and user names are missing")
            if b["facts"].get("error_lines"):
                reasons.append("%s printed %d line(s) that say error, exception or failed although it exited 0 (backends.%s.facts.first_error_line shows the first)" % (b["name"], b["facts"]["error_lines"], b["name"]))
            if not sum(s.rows for s in stats[b["name"]].values()):
                reasons.append("%s ran and exited 0 but produced no row, so it read nothing usable" % b["name"])
        usable = [b for b in ran if sum(s.rows for s in stats[b["name"]].values())]
        for b in backends:
            if b["state"] in ("failed", "timed_out") and usable:
                reasons.append("%s was run and %s (%s): its rows are missing and nothing was compared" % (b["name"], b["state"], b["why"]))
        bad_time = sum(s.time_unparsed for per in stats.values() for s in per.values())
        if bad_time:
            reasons.append("%d row(s) have a time this tool could not read (kept with the raw cell, time null)" % bad_time)
        replaced = sum(s.replaced_bytes for per in stats.values() for s in per.values())
        if replaced:
            reasons.append("%d row(s) held bytes that are not UTF-8: they were read with U+FFFD in their place" % replaced)
        if not header["clean"] and not header["dirty"]:
            reasons.append("the database is in state '%s', which is neither a clean shutdown nor a dirty one the logs can bring up to date: rows may be missing or not whole" % header["state"])
        elif header["dirty"]:
            replayed = any(b["facts"].get("logs_replayed") for b in ran)
            if not logs:
                reasons.append("the database is in state '%s' (not a clean shutdown) and no log or checkpoint file is beside it: rows that only the logs hold are missing" % header["state"])
            elif not replayed:
                reasons.append("the database is in state '%s' (not a clean shutdown); log files are beside it, but no backend said it replayed them" % header["state"])
        # The CSV files, the console and the JSON Lines are what SrumECmd and target-query wrote, and the rows are read from them: a process either left behind may still have written to them.
        # settle() ended such a process when its program ended, before anything was read, so the files are stable but may be short; where one cannot be ruled out (not Linux, or
        # PR_SET_CHILD_SUBREAPER refused) they cannot be shown to be final.
        verdict = process_verdict()
        if backends and (verdict["left_behind"] or verdict["unproven"]):
            if verdict["left_behind"]:
                reasons.append(own("a backend left %d process(es) running after it ended (in the tool's process group or in a session of its own); they were ended before its files were read, so what they "
                                   "would still have written is missing and the rows may be short" % verdict["left_behind"]))
            for why in verdict["unproven"]:
                reasons.append(own(why + ": the backends' files cannot be shown to be final"))
        counts = {b["name"]: {t: s.rows for t, s in stats[b["name"]].items()} for b in ran}
        if len(ran) == 2:
            comparison = compare(counts)
            if comparison["state"] == "disagree":
                reasons.append("srumecmd and dissect disagree on the row count of %d table(s)" % sum(1 for e in comparison["tables"].values() if e["result"] == "disagree"))
            elif comparison["state"] == "not_compared":
                reasons.append("%d table(s) could not be matched between srumecmd and dissect, so those were not compared" % comparison["not_compared_count"])
        else:
            others = [b for b in backends if b["state"] != "ran"]
            comparison = {"state": "not_run", "why": own("a comparison needs both backends to have produced rows") + (": " + "; ".join("%s %s" % (b["name"], b["state"]) for b in others) if others else "")}
        # the status
        if not usable:
            if which == "all" and out_of_time():
                reasons.append("the tool's own clock ran out before a backend was run")
            status = "failed"
            basis = "no backend produced rows: " + ("; ".join("%s %s (%s)" % (b["name"], b["state"], b["why"] or "it exited 0 and gave no row") for b in backends) if backends else "none was started")
            if reasons:
                basis += " (" + "; ".join(reasons) + ")"
        else:
            wanted = [b for b in backends if which != "all" and b["state"] != "ran"]
            if wanted:
                status, basis = "failed", "%s was asked for and %s" % (wanted[0]["name"], wanted[0]["state"])
            else:
                status = "partial" if reasons else "complete"
                basis = "; ".join(reasons) if reasons else "every row of every table the backend(s) wrote was read to its end%s, and the database state is '%s'%s" % (
                    "; the two backends agree on every table's row count" if comparison["state"] == "agree" else "", header["state"],
                    ", with log files beside it that a backend said it replayed" if header["dirty"] else "")
                if not reasons and comparison["state"] == "not_run":
                    basis += "; a second backend did not run, so the rows are one reader's (comparison.why says why)"
        unresolved_total = {kind: sum(s.unresolved[kind] for per in stats.values() for s in per.values()) for kind in ("app", "user", "profile")}
        OWN_NAMES.add(basis)
        backend_view = {}
        for b in backends:
            backend_view[b["name"]] = {"state": b["state"], "why": b["why"], "exit_code": b["exit_code"], "facts": b["facts"],
                                       "problems": reading[b["name"]].problems if b["name"] in reading else [], "tables_written": len(b["files"]) if b["name"] == "srumecmd" else None}
        answer = {"parser": PARSER, "status": status, "status_basis": basis, "path": path, "database": database,
                  "software_hive": {"path": software, "found_by": software_from,
                                    "note": own("without the hive, a profile (network) id is unresolved and the row says why") if software is None else own("given to SrumECmd with -r")},
                  "backends": backend_view, "comparison": comparison, "tables": tables, "unresolved_ids_total": unresolved_total,
                  "unresolved_note": own("an application, user or profile id the backend printed no name for is kept in its row, flagged *_resolved false, and counted here"),
                  "time_note": own("times are UTC as the backend printed them (a time with no zone is taken as UTC; not shown by a real run); time_raw is the cell as printed"),
                  "semantics_note": SEMANTICS_NOTE, "notes": notes, "rows": page.page, "rows_total": rows_result["matched"], "rows_file": rows_result.get("all_results"),
                  "rows_inline_truncated": rows_result["truncated"],
                  "elapsed_seconds": round(time.monotonic() - started, 2),
                  "note": own("SrumECmd's option names, CSV names and columns and console lines were read from the strings of its dll and it was never run; "
                              "the dissect.target record shape is an assumption; "
                              "esedb_query reads the raw tables")}
        process_apply(answer)             # program_group: what settle() ended and why the absence of a leftover is unproven (a complete answer is already partial above)
        for text in [*answer["program_group"]["unproven"], *answer["program_group"]["notes"]]:
            own(text)
        emit(answer, indent=1)
        close_values()
        if status == "failed":
            sys.exit(1)
    finally:
        forget_temps()


if __name__ == "__main__":
    try:
        main()
    except SystemExit:
        raise
    except Exception as exc:                                  # whatever hostile input does, the answer is JSON
        forget_temps()
        emit({"ok": False, "error": "the run failed", "status": "failed", "status_basis": own("the tool stopped with an unexpected error"), "reason": "%s: %s" % (type(exc).__name__, exc)})
        sys.exit(1)
