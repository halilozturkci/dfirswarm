#!/usr/bin/env python3
"""Copy chosen files out of chosen volume shadow copies of a volume, under $OUT, tagged with the snapshot they came from.

vshadowinfo lists the stores of a raw volume or disk image (the identifier, the creation time); vshadowmount (FUSE) exposes each store as
a file `vssN`, a raw copy of the volume as it was; the Sleuth Kit's `fls` finds a path in it (component by component, never through a link:
the volume is read as a volume, not mounted as a file system) and `icat` copies the file. The mount is made under this tool's own
directory (work/<agent id>/, or $OUT in a job), is that VM's alone and is not a sealed output, and it is always unmounted: in a `finally`,
at the tool's own deadline, and on SIGTERM, SIGINT and SIGHUP. Without FUSE (no /dev/fuse that can be opened, no fusermount3 or
fusermount) the answer is `blocked: no FUSE`, as JSON, and nothing is written.

Each selected path is looked up in each selected store; the answer says which store has it, which copy was made, its size and sha256, and
how it stands to the same path in the live volume (same, differs, absent in the live volume). A path that is absent from a store is a fact
about that snapshot, not a failure. SAM, SECURITY and NTDS.dit are credential files: they are copied only on copy_credentials in a job run
as secret output, and no digest of one is printed or written. A copy that could not be written whole is removed and is never named as a copy.

Listing a snapshot is not examining it: a file that is in a store is evidence of that store as vshadowmount presented it, and a copy is
the file as icat read it. This was written against the documented behaviour of libvshadow and the Sleuth Kit and run against stand-ins
for them; a run against a real shadow copy needs FUSE in the worker image and is not verified here.
"""
import hashlib
import json
import os
import re
import select
import shutil
import signal
import stat
import subprocess
import sys
import tempfile
import time
from pathlib import Path

# Lossless paging (the same in every library tool that pages): the page an
# agent reads stays small, and when there are more rows the whole result is
# written as JSON Lines under work/<agent>/tool-output and named.
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
# program is still alive nothing is capped here (a program's own output is its caller's to bound); the timing is unchanged.
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
    turn a complete answer into a partial one (status "partial", the ok and complete flags that are there false, a sentence in status_basis;
    a call of communicate_bounded that was cut at POST_EXIT_BYTES counts, PIPE_CUT):
    what a program wrote while the tool read it is not a complete result. A carrier calls it once where it prints its answer. Returns `answer`."""
    verdict = process_verdict()
    answer["program_group"] = verdict
    if (verdict["left_behind"] > 0 or verdict["unproven"] or PIPE_CUT["cut"]) and answer.get("status") == "complete":
        answer["status"] = "partial"
        for flag in ("ok", "complete"):
            if flag in answer:
                answer[flag] = False
        if verdict["left_behind"] > 0:
            sentence = "a program left %d process%s running after it ended; the tool ended them, and what they wrote before that is in the files named here" % (
                verdict["left_behind"], "" if verdict["left_behind"] == 1 else "es")
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


def communicate_bounded(proc, seconds, input=None):
    """(stdout bytes, stderr bytes, timed out) for a program started with pipes, in bytes. At `seconds` the program and what it started
    are killed (timed out). A program that has ended while something it started still holds its pipes (a daemon, a helper that
    inherited them) does not hold the tool: from the moment the program has ended (or was killed) the pipes are given PIPE_GRACE seconds
    and POST_EXIT_BYTES bytes, whichever is used up first; what the program wrote is kept, what the tool lost is killed (reap_orphans,
    settle), and the pipes are let go. A cut at the byte cap is counted in PIPE_CUT and noted (process_notes()); the return shape is the
    same. The pipes are read here and by nothing else (not by Popen.communicate), so letting them go is safe. `input` is written while
    the program runs and is dropped once it has ended."""
    deadline = time.monotonic() + max(0.1, seconds)
    bufs = (bytearray(), bytearray())
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
    timed_out, note, ended, extra, cut, sampled = False, None, None, 0, False, 0.0
    try:
        while True:
            now = time.monotonic()
            if ended is None:
                if proc.poll() is not None:
                    ended = now
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
                bufs[key.data].extend(data)
                if ended is not None:
                    extra += len(data)
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
    err = bytes(bufs[1])
    if note:
        err = err + (b"\n" if err else b"") + note.encode("utf-8", "replace")
    return bytes(bufs[0]), err, timed_out


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
    os._exit(128 + signum)


def install_signal_handlers():
    for signum in (signal.SIGTERM, signal.SIGINT, signal.SIGHUP):
        signal.signal(signum, _on_signal)
# END SHARED PROCESS


# ---- this tool's own part ------------------------------------------------------------------------------------------------------------

PARSER = "vss_materialise/1"
DEADLINE_SECONDS = 270            # the manifest allows 300; copying stops UNMOUNT_RESERVE seconds before this, so the unmount and the answer come inside it
UNMOUNT_RESERVE = 25
UNMOUNT_TRIES = 3
UNMOUNT_STEP = 8                  # seconds one fusermount call is given
MOUNT_SECONDS = 60
CLOCK = {"deadline": None}
MAX_STORES = 64
MAX_PATHS = 200
MAX_DEPTH = 32
MAX_LISTING = 16 << 20            # bytes of one fls listing that are taken (a larger one stops the program: listing_too_large)
DEFAULT_MAX_COPY = 2 << 30
CREDENTIAL_NAMES = frozenset(("sam", "security", "ntds.dit"))
FLS_LINE = re.compile(r"^(\S+)\s+(\*\s+)?([0-9]+(?:-[0-9]+)*)(?:\([^)]*\))?:\t(.*)$")
GUID = re.compile(r"^[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12}$")
RUN = {"mount": None, "unmounted": None, "temps": [], "answered": False, "copy_rows": None}


def remaining():
    return CLOCK["deadline"] - time.monotonic() if CLOCK["deadline"] is not None else float(DEADLINE_SECONDS)


def copy_time_left():
    return remaining() - UNMOUNT_RESERVE


def print_answer(answer, **dumps_kwargs):
    """The answer, once, with the stop signals held back (a signal in the middle of the write would cut it) and the last word cleared."""
    try:
        signal.pthread_sigmask(signal.SIG_BLOCK, {signal.SIGTERM, signal.SIGINT, signal.SIGHUP})
    except (AttributeError, ValueError, OSError):
        pass
    STATE["last_word"] = None
    RUN["answered"] = True
    print(json.dumps(answer, ensure_ascii=True, default=str, **dumps_kwargs), flush=True)


class SealedPage(NoReplacePage):
    """A page of rows that are always kept whole in a file (LosslessPage writes the file only when there are more rows than the page)."""

    def finish(self) -> dict:
        if self._out is None and self.page:
            try:
                self.path.parent.mkdir(parents=True, exist_ok=True)
                fd, name = tempfile.mkstemp(dir=self.path.parent, prefix=f".{self.path.name}-")
                self._tmp = Path(name)
                self._out = os.fdopen(fd, "w", encoding="utf-8")
            except OSError as exc:
                self._cannot_write(exc)
            for kept in self.page:
                self._write(kept)
        return super().finish()


def remove_temps():
    for page in list(PAGES):
        out, page._out = getattr(page, "_out", None), None
        try:
            if out is not None:
                out.close()
        except BaseException:
            pass
        tmp = getattr(page, "_tmp", None)
        if tmp is not None:
            try:
                os.unlink(tmp)
            except OSError:
                pass
            page._tmp = None
    for name in list(RUN["temps"]):
        try:
            os.unlink(name)
        except OSError:
            pass
    del RUN["temps"][:]


def mounted_at(directory):
    """True/False from /proc/self/mountinfo, None when it cannot be read."""
    try:
        want = os.path.realpath(directory)
        with open("/proc/self/mountinfo", encoding="utf-8", errors="replace") as fh:
            for line in fh:
                parts = line.split(" ")
                if len(parts) > 4 and re.sub(r"\\([0-7]{3})", lambda m: chr(int(m.group(1), 8)), parts[4]) == want:
                    return True
        return False
    except OSError:
        return None


PIPE_CUTS = {"calls": 0}       # calls of run_program, other than the vshadowmount daemon's, whose pipe was cut at its byte cap (PIPE_CUT counts the daemon's too)


def run_program(argv, seconds, leaves=False):
    """(exit code, stdout, stderr, timed out) of a program run in this tool's group, bounded by `seconds` and the tool's clock. `leaves` is for
    the one program that daemonises on purpose (vshadowmount: its FUSE daemon serves the mount until unmount() ends it): the process block's
    settle() then keeps what that program left. Every other program here leaves nothing, and what it leaves is ended."""
    seconds = max(0.5, min(seconds, remaining()))
    proc = spawn(argv, leaves=leaves, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    ACTIVE.append(proc)
    cut_before = PIPE_CUT["cut"]
    try:
        out, err, timed = communicate_bounded(proc, seconds)
    finally:
        if proc in ACTIVE:
            ACTIVE.remove(proc)
    if PIPE_CUT["cut"] > cut_before and not leaves:
        # a program that must leave nothing (vshadowinfo, fusermount) had its pipe held after it ended by a process that went on writing: its output is mixed with that. The daemon of
        # vshadowmount (leaves=True) is left on purpose and is not a leftover: its pipe being cut is not counted here (what the tool reads from that call is its exit and a message)
        PIPE_CUTS["calls"] += 1
    return proc.returncode, out, err, timed


def unmount():
    """Unmount what this run mounted, and remove its directory. Idempotent; used by the finally, the deadline and the last word."""
    if RUN["unmounted"] is not None:
        result = RUN["unmounted"]
        if result.get("mount_made") and not result.get("unmounted") and not result.get("retried"):
            result["retried"] = True                      # a signal cut the unmount short, or it failed: once more, lazily
            program = shutil.which("fusermount3") or shutil.which("fusermount")
            if program:
                try:
                    run_program([program, "-u", "-z", "--", str(RUN["mount"])], UNMOUNT_STEP)
                except Exception:  # noqa: BLE001
                    pass
            if mounted_at(RUN["mount"]) is not True:
                result["unmounted"] = True
                result.pop("note", None)
            try:
                os.rmdir(RUN["mount"])
                result["mount_dir_removed"] = True
            except OSError:
                pass
            result["retried_note"] = "the unmount was cut short or had failed; a lazy unmount (-u -z) was tried once more"
        return result
    directory = RUN["mount"]
    if directory is None:
        return {"mount_made": False}
    result = {"mount_made": True, "unmounted": False, "mount_dir_removed": False}
    RUN["unmounted"] = result
    program = shutil.which("fusermount3") or shutil.which("fusermount")
    if program:
        for attempt in range(UNMOUNT_TRIES):
            flags = ["-u"] if attempt < UNMOUNT_TRIES - 1 else ["-u", "-z"]
            try:
                run_program([program] + flags + ["--", str(directory)], UNMOUNT_STEP)
            except Exception:  # noqa: BLE001
                pass
            if mounted_at(directory) is not True:
                result["unmounted"] = True
                break
            time.sleep(0.2)
    else:
        result["unmounted"] = mounted_at(directory) is False
    try:
        os.rmdir(directory)
        result["mount_dir_removed"] = True
    except OSError:
        pass
    if not result["unmounted"]:
        result["note"] = "the mount at %s could not be shown to be gone: unmount it with `fusermount3 -u` (or `fusermount -u`) before anything else uses that directory" % directory
    return result


def last_word(signum):
    unmounted = unmount()
    remove_temps()
    if not RUN["answered"]:
        print_answer({"error": "stopped by signal %d" % signum, "status": "failed", "interrupted": True, "signal": signum,
                      "status_basis": "the tool was stopped by signal %d; no copy of this run is complete and none is kept as one" % signum,
                      "mount": unmounted})


def fail(message, **extra):
    unmounted = unmount()
    remove_temps()
    print_answer({"error": message, "status": "failed", "status_basis": "the tool stopped with an error (see error)", **({"mount": unmounted} if unmounted.get("mount_made") else {}), **extra})
    raise SystemExit(1)


def whole(args, name, default, low, high=None):
    v = args.get(name)
    if v is None:
        return default
    if isinstance(v, bool) or not isinstance(v, int) or v < low or (high is not None and v > high):
        fail("%s must be a whole number of at least %d%s" % (name, low, " and at most %d" % high if high is not None else ""))
    return v


def split_path(text):
    if not isinstance(text, str) or not text or "\x00" in text or "\n" in text or "\r" in text or text[0] not in "/\\":
        return None
    parts = [p for p in re.split(r"[\\/]+", text) if p]
    if not parts or len(parts) > MAX_DEPTH or any(p in (".", "..") or len(p) > 255 for p in parts):
        return None
    return parts


def fuse_missing():
    device = os.environ.get("DFIRSWARM_FUSE_DEVICE", "/dev/fuse")
    missing = []
    if not os.path.exists(device):
        missing.append("%s is not present" % device)
    elif not os.access(device, os.R_OK | os.W_OK):
        missing.append("%s cannot be opened by this process" % device)
    if not (shutil.which("fusermount3") or shutil.which("fusermount")):
        missing.append("neither fusermount3 nor fusermount is installed")
    return missing


def parse_stores(text):
    """{store number: {"identifier", "created"}} from vshadowinfo's output, in time linear in the text (a line is split once, at its first colon)."""
    stores, current = {}, None
    for line in text.split("\n"):
        stripped = line.strip()
        m = re.match(r"^Store:\s*([0-9]{1,6})$", stripped)
        if m:
            current = stores.setdefault(int(m.group(1)), {"identifier": None, "created": None})
            continue
        if current is None or ":" not in stripped:
            continue
        key, _, value = stripped.partition(":")
        key, value = key.strip().lower(), value.strip()
        if key == "identifier" and GUID.match(value):
            current["identifier"] = value.lower()
        elif key == "creation time" and len(value) <= 80:
            current["created"] = value
    return stores


class Sink:
    """A bounded in-memory sink for one fls listing."""

    def __init__(self):
        self.parts = []

    def write(self, chunk):
        self.parts.append(chunk)


def find_file(volume, sector_offset, parts, seconds):
    """(state, inode): state is found, not_found, not_regular, read_failed or timeout. A path is walked one component at a time with `fls`
    (case-insensitively, as NTFS compares); a deleted entry (`*`) is never taken, and nothing is followed: a reparse point is a name like another."""
    inode = None
    kind = None
    for i, component in enumerate(parts):
        argv = ["fls"] + (["-o", str(sector_offset)] if sector_offset else []) + [volume] + ([inode] if inode else [])
        sink = Sink()
        state, _size, _digest = stream_file(argv, sink, MAX_LISTING, seconds)
        if state == "too_large":
            return "listing_too_large", None
        if state == "timeout":
            return "timeout", None
        if state == "left_behind":
            return "left_behind", None
        if state != "ok":
            return "read_failed", None
        out = b"".join(sink.parts)
        found = None
        want = component.casefold()
        last = i == len(parts) - 1
        for line in out.decode("utf-8", "surrogateescape").split("\n"):
            m = FLS_LINE.match(line)
            if m is None or m.group(2):
                continue
            name = m.group(4)
            if name.casefold() == want and (last or m.group(1).startswith("d")):
                found, kind = m.group(3), m.group(1)
                break
        if found is None:
            return "not_found", None
        inode = found
    return ("found", inode) if kind and kind.startswith("r") else ("not_regular", inode)


def icat_argv(volume, sector_offset, inode):
    return ["icat"] + (["-o", str(sector_offset)] if sector_offset else []) + [volume, inode]


def stream_file(argv, sink, limit, seconds):
    """Run `argv` (icat, or fls) and copy its output into `sink` (a file object, or None to hash only), reading at most `limit` bytes: the program is
    killed with what it started at the limit. Returns (state, bytes, sha256 or None). state is ok, too_large, read_failed, timeout, left_behind or write_failed:<errno>.
    The copy is what the program printed on its pipe: when the program has ended and something it started still holds the pipe, that is ended after PIPE_GRACE (settle())
    so that the read reaches end of file, and the bytes are not taken for the program's: the state is left_behind and the caller keeps nothing of them."""
    ended_before = process_verdict()["left_behind"]
    proc = spawn(argv, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
    ACTIVE.append(proc)
    digest = hashlib.sha256()
    total = 0
    state = "ok"
    stop_at = time.monotonic() + max(0.5, min(seconds, remaining()))
    fd = proc.stdout.fileno()
    gone, settled = None, False        # when the program was first seen to have ended while its pipe was still open, and whether what it left was looked for
    try:
        while True:
            left = stop_at - time.monotonic()
            if left <= 0:
                state = "timeout"
                kill_tree(proc)
                break
            if proc.poll() is not None:
                gone = gone or time.monotonic()
                if time.monotonic() - gone > PIPE_GRACE and not settled:
                    settled = True
                    settle()
                elif settled and time.monotonic() - gone > PIPE_GRACE + 1.0:
                    state = "left_behind"          # the pipe is still held and could not be freed: the bytes are not shown to be the program's
                    break
            ready, _, _ = select.select([fd], [], [], min(0.2, left))
            if not ready:
                continue
            chunk = os.read(fd, 1 << 20)
            if not chunk:
                break
            total += len(chunk)
            if total > limit:
                state = "too_large"
                kill_tree(proc)
                break
            digest.update(chunk)
            if sink is not None:
                try:
                    sink.write(chunk)
                except OSError as exc:
                    state = "write_failed:%s" % (exc.strerror or exc.errno)
                    kill_tree(proc)
                    break
    finally:
        try:
            proc.stdout.close()
        except OSError:
            pass
        code, timed_wait = wait_for(proc, 5)
        if proc in ACTIVE:
            ACTIVE.remove(proc)
    if state == "ok" and process_verdict()["left_behind"] > ended_before:
        state = "left_behind"                      # settle() ended a process the program left: what came through the pipe cannot be told from what the program printed
    if state == "ok" and (code != 0 or timed_wait):
        state = "read_failed"
    return state, total, digest.hexdigest() if state == "ok" else None


def main():
    CLOCK["deadline"] = time.monotonic() + DEADLINE_SECONDS
    STATE["last_word"] = last_word
    install_signal_handlers()
    try:
        args = json.load(sys.stdin)
    except ValueError as exc:
        fail("arguments are not valid JSON", reason=str(exc))
    if not isinstance(args, dict):
        fail("the arguments must be a JSON object")
    image = args.get("image")
    if not isinstance(image, str) or not image or "\x00" in image:
        fail("image is required: a raw volume or disk image, or a device file")
    offset = whole(args, "offset", 0, 0)
    stores_asked = args.get("stores")
    if not isinstance(stores_asked, list) or not stores_asked or len(stores_asked) > MAX_STORES or any(isinstance(s, bool) or not isinstance(s, int) or s < 1 for s in stores_asked):
        fail("stores must be a list of 1 to %d store numbers (whole numbers from 1, as vss_stores lists them)" % MAX_STORES)
    stores_asked = sorted(set(stores_asked))
    paths_asked = args.get("paths")
    if not isinstance(paths_asked, list) or not paths_asked or len(paths_asked) > MAX_PATHS:
        fail("paths must be a list of 1 to %d paths inside the volume, written from its root (/Windows/System32/config/SYSTEM)" % MAX_PATHS)
    parsed = [split_path(p) for p in paths_asked]
    if any(p is None for p in parsed):
        fail("every path must start with / or \\, have at most %d components and no . or .. component" % MAX_DEPTH)
    max_copy = whole(args, "max_copy_bytes", DEFAULT_MAX_COPY, 1)
    limit = whole(args, "limit", 100, 1)
    copy_credentials = args.get("copy_credentials", False)
    if not isinstance(copy_credentials, bool):
        fail("copy_credentials must be true or false")
    secret_job = bool(os.environ.get("JOB_ID") and os.environ.get("OUT") and os.environ.get("SECRET_OUTPUT") == "1")
    if copy_credentials and not secret_job:
        fail("copy_credentials is refused: SAM, SECURITY and NTDS.dit are copied only in a job the harness runs as secret output "
             "(job_run with secret_output: true), where the copy is a sealed secret output. Nothing was made.")

    # Everything that can say no, before anything is made.
    missing_fuse = fuse_missing()
    if missing_fuse:
        print_answer({"status": "failed", "blocked": "no FUSE", "status_basis": "no shadow copy was mounted and nothing was written: this VM has no FUSE",
                      "no_fuse": {"reason": "no_fuse", "blocked_by": missing_fuse,
                                  "what_to_do": "Run this job where /dev/fuse can be opened and fusermount3 or fusermount is installed. Until then say that no FUSE mount was possible here: "
                                                "it is a limit of the VM, not a finding about the evidence."}})
        raise SystemExit(1)
    absent = [p for p in ("vshadowinfo", "vshadowmount", "fls", "icat") if shutil.which(p) is None]
    if absent:
        fail("a program this tool runs is not installed: %s" % ", ".join(absent), missing_programs=absent)
    try:
        fd = os.open(image, os.O_RDONLY | os.O_NONBLOCK | getattr(os, "O_CLOEXEC", 0))
    except OSError as exc:
        fail("the image could not be opened", reason=exc.strerror or type(exc).__name__)
    try:
        mode = os.fstat(fd).st_mode
    finally:
        os.close(fd)
    if not (stat.S_ISREG(mode) or stat.S_ISBLK(mode)):
        fail("the image is not a regular file or a block device, so it was not read", not_attempted=1)

    code, out, err, timed = run_program(["vshadowinfo", "-o", str(offset), image], 120)
    if timed or code != 0:
        fail("vshadowinfo %s" % ("did not finish in time" if timed else "failed with exit status %s" % code), exit_status=code)
    listed = parse_stores(out.decode("utf-8", "replace"))
    selected = [s for s in stores_asked if s in listed]
    not_listed = [s for s in stores_asked if s not in listed]

    in_job = bool(os.environ.get("JOB_ID") and os.environ.get("OUT"))
    key = [image, offset, stores_asked, paths_asked, bool(copy_credentials)]
    rows = SealedPage("vss_materialise", key, limit)
    probs = SealedPage("vss_materialise-problems", key, 40)
    out_dir = rows.path.parent / ("vss_materialise-" + hashlib.sha256(json.dumps(key, sort_keys=True).encode()).hexdigest()[:16])
    agent = re.sub(r"[^A-Za-z0-9_.-]", "_", os.environ.get("AGENT_ID") or "tool")
    base = Path(os.environ["OUT"]) if in_job else Path("work") / agent
    problems = {"count": 0}

    def problem(why, **where):
        problems["count"] += 1
        if problems["count"] <= 2000:
            probs.add({"why": why, **where})

    counts = {"copied": 0, "not_found": 0, "failed": 0, "not_attempted": 0, "credential_not_copied": 0}
    exists = {}
    stopped = {"time": False}
    mount_info = {"mount_made": False}
    mount_waited = {"done": False}
    if selected:
        try:
            base.mkdir(parents=True, exist_ok=True)
            mount_dir = base / (".vss-mount-%d-%s" % (os.getpid(), os.urandom(4).hex()))
            os.mkdir(mount_dir, 0o700)
        except OSError as exc:
            fail("the mount directory could not be made under %s: %s" % (base, exc.strerror or exc))
        RUN["mount"] = mount_dir
        code, _o, err, timed = run_program(["vshadowmount", "-o", str(offset), image, str(mount_dir)], MOUNT_SECONDS, leaves=True)
        if timed or code != 0:
            fail("vshadowmount %s" % ("did not return in time" if timed else "failed with exit status %s" % code), exit_status=code)
        sector_offset = offset // 512 if offset % 512 == 0 else None
        for number in selected:
            info = listed[number]
            volume = mount_dir / ("vss%d" % number)
            tag = {"store": number, "store_guid": info["identifier"], "store_created": info["created"]}
            ready = False
            if mount_waited["done"] is False:
                until = time.monotonic() + 5            # the mount is waited for once, 5 seconds in all, and never past the copy clock
                while time.monotonic() < until and copy_time_left() > 0 and not all(os.path.lexists(mount_dir / ("vss%d" % n)) for n in selected):
                    time.sleep(0.1)
                mount_waited["done"] = True
            try:
                st = os.lstat(volume)
                ready = stat.S_ISREG(st.st_mode) and os.path.dirname(os.path.realpath(volume)) == os.path.realpath(mount_dir)
            except OSError:
                ready = False
            for raw, parts in zip(paths_asked, parsed):
                row = {**tag, "path": raw, "found": None, "copy_status": "not_attempted", "copied_to": None, "bytes": None, "sha256": None, "inode": None,
                       "relation_to_live": "not_compared"}
                exists.setdefault(raw, {})
                if not ready:
                    row["copy_status"] = "store_not_exposed"
                    counts["failed"] += 1
                    problem("the mount has no regular file vss%d" % number, store=number)
                elif stopped["time"] or copy_time_left() <= 0:
                    stopped["time"] = True
                    counts["not_attempted"] += 1
                else:
                    state, inode = find_file(str(volume), None, parts, min(60, copy_time_left()))
                    row["inode"] = inode
                    if state == "not_found":
                        row["found"] = False
                        row["copy_status"] = "not_in_store"
                        counts["not_found"] += 1
                    elif state in ("timeout", "read_failed", "not_regular", "listing_too_large", "left_behind"):
                        row["copy_status"] = state
                        counts["failed"] += 1
                        problem("the path could not be resolved in this store: %s%s" % (state, " (a directory listing over %d bytes was not taken)" % MAX_LISTING if state == "listing_too_large" else ""), store=number)
                    else:
                        row["found"] = True
                        exists[raw][str(number)] = True
                        name = parts[-1]
                        if name.casefold() in CREDENTIAL_NAMES and not copy_credentials:
                            row["copy_status"] = "credential_file_not_copied"
                            counts["credential_not_copied"] += 1
                        else:
                            credential = name.casefold() in CREDENTIAL_NAMES
                            safe = re.sub(r"[^A-Za-z0-9_.-]", "_", name)[:80] or "file"
                            dest_dir = out_dir / ("store-%d" % number)
                            index = paths_asked.index(raw)
                            dest = dest_dir / ("%04d-%s" % (index, safe))
                            tmp = None
                            try:
                                dest_dir.mkdir(parents=True, exist_ok=True)
                                tfd, tname = tempfile.mkstemp(dir=dest_dir, prefix=".copy-")
                                RUN["temps"].append(tname)
                                tmp = tname
                                sink = os.fdopen(tfd, "wb")
                            except OSError as exc:
                                row["copy_status"] = "write_failed"
                                counts["failed"] += 1
                                problem("the copy could not be started: %s" % (exc.strerror or exc), store=number)
                                sink = None
                            if sink is not None:
                                try:
                                    cstate, size, digest = stream_file(icat_argv(str(volume), None, inode), sink, max_copy, min(600, copy_time_left()))
                                    if cstate == "ok":
                                        sink.flush()
                                        os.fsync(sink.fileno())
                                except OSError as exc:
                                    cstate, size, digest = "write_failed:%s" % (exc.strerror or exc.errno), 0, None
                                finally:
                                    try:
                                        sink.close()
                                    except OSError:
                                        cstate = cstate if cstate != "ok" else "write_failed:close"
                                if cstate == "ok":
                                    try:
                                        made = place_without_replacing(Path(tmp), dest)
                                        RUN["temps"].remove(tmp)
                                        row["copy_status"] = "copied"
                                        row["copied_to"] = str(made) if not in_job else "store/jobs/%s/out/%s" % (re.sub(r"[^A-Za-z0-9_.-]", "_", os.environ["JOB_ID"]), os.path.relpath(made, os.environ["OUT"]))
                                        row["bytes"] = size
                                        row["sha256"] = None if credential else digest
                                        counts["copied"] += 1
                                    except OSError as exc:
                                        cstate = "write_failed:%s" % (exc.strerror or exc.errno)
                                if cstate != "ok":
                                    try:
                                        os.unlink(tmp)
                                        RUN["temps"].remove(tmp)
                                    except (OSError, ValueError):
                                        pass
                                    row["copy_status"] = cstate.split(":")[0]
                                    row["reason"] = cstate if ":" in cstate else None
                                    counts["failed"] += 1
                                    problem("the copy was not made (%s) and nothing of it is kept" % cstate, store=number)
                                    if cstate.startswith("write_failed"):
                                        stopped["time"] = True          # a refused write stops the rest: it says nothing about the evidence
                                elif not credential and sector_offset is not None and copy_time_left() > 0:
                                    lstate, linode = find_file(image, sector_offset, parts, min(60, copy_time_left()))
                                    if lstate == "not_found":
                                        row["relation_to_live"] = "absent_in_live"
                                    elif lstate == "found":
                                        ls, lsize, ldigest = stream_file(icat_argv(image, sector_offset, linode), None, max_copy, min(600, copy_time_left()))
                                        if ls == "ok":
                                            row["relation_to_live"] = "same" if ldigest == row["sha256"] else "differs"
                rows.add(row)
    exists_out = {p: {str(s): bool(exists.get(p, {}).get(str(s))) for s in selected} for p in paths_asked}
    page = rows.finish()
    prob_page = probs.finish()
    mount_info = unmount()
    remove_temps()
    reasons = []
    if not_listed:
        reasons.append("store(s) %s are not among the %d vshadowinfo lists" % (", ".join(map(str, not_listed)), len(listed)))
    if counts["failed"]:
        reasons.append("%d copy or lookup(s) failed (copy_status)" % counts["failed"])
    if counts["not_attempted"] or stopped["time"]:
        reasons.append("the clock ran out or a write was refused: %d lookup(s) were not attempted" % counts["not_attempted"])
    if counts["credential_not_copied"]:
        reasons.append("%d credential file(s) were found and not copied (copy_credentials)" % counts["credential_not_copied"])
    if mount_info.get("mount_made") and not mount_info.get("unmounted"):
        reasons.append("the mount could not be shown to be gone")
    # The copies are what icat printed on a pipe and the tool wrote itself, so a host that cannot adopt orphans does not make them less than complete (program_group.unproven says it); a process that
    # fls, icat, vshadowinfo or fusermount left behind was ended by settle(), and what came through the pipe after the program ended is not taken for a copy (copy_status left_behind). The vshadowmount
    # daemon, which is left on purpose and unmounted by this tool, is not counted.
    verdict = process_verdict()
    if verdict["left_behind"]:
        reasons.append("%d process(es) that vshadowinfo, fls, icat or fusermount left running were ended (program_group.left_behind); the copy or the lookup of such a program is not kept as a copy (copy_status left_behind)" % verdict["left_behind"])
    if PIPE_CUTS["calls"]:
        reasons.append("%d call(s) of vshadowinfo or fusermount were cut at %d bytes because a process that held the program's pipe after it ended went on writing: what was read from that pipe "
                       "(the store list, the identifiers and creation times, the unmount messages) may contain bytes the program did not write (process_notes says so; the vshadowmount daemon is left "
                       "on purpose and is not counted)" % (PIPE_CUTS["calls"], POST_EXIT_BYTES))
    if problems["count"]:
        reasons.append("%d problem(s) are named under problems" % problems["count"])
    answer = {
        "parser": PARSER,
        "status": "partial" if reasons else "complete",
        "status_basis": "; ".join(reasons) if reasons else "every selected path was looked up in every selected store, and each one found was copied whole",
        "image": image,
        "offset": offset,
        "stores_listed": {str(n): listed[n] for n in sorted(listed)},
        "stores_selected": selected,
        "stores_not_listed": not_listed,
        "paths_in_stores": exists_out,
        "counts": counts,
        "copies": counts["copied"],
        "row_count": page["matched"],
        "returned": page["returned"],
        "rows": rows.page,
        "mount": mount_info,
        "problem_count": problems["count"],
        "problems": probs.page,
        "process_notes": process_notes(),
        "program_group": verdict,
        "note": "A copy is the file as icat read it from the store as vshadowmount presented it; it is tagged with the store number, the identifier and the creation time "
                "vshadowinfo printed. relation_to_live compares the copy with the same path in the volume as it is now (same, differs, absent_in_live). A path absent from a "
                "store is a fact about that snapshot. Listing a snapshot is not examining it.",
    }
    if page.get("all_results"):
        answer["rows_file"] = page["all_results"]
    if prob_page.get("all_results"):
        answer["all_problems"] = prob_page["all_results"]
    print_answer(answer, indent=2)


if __name__ == "__main__":
    try:
        main()
    except SystemExit:
        unmount()
        remove_temps()
        raise
    except BaseException as exc:                                  # whatever hostile input does, the answer is JSON and the mount is gone
        unmounted = unmount()
        remove_temps()
        if not RUN["answered"]:
            print_answer({"error": "the run failed", "status": "failed", "status_basis": "the tool stopped with an unexpected error", "reason": "%s: %s" % (type(exc).__name__, exc),
                          "mount": unmounted})
        sys.exit(1)
