#!/usr/bin/env python3
"""Recipe protocol for a lossless dissect.target Linux catalogue.

    run.py detect --target T [--probe-out DIR]   exit 0 applies, 1 does not, 2 could not tell
    run.py run --target T --out DIR

detect keeps three answers apart. Exit 0 says dissect.target's `os` function named the target `linux` (its own
identification: nothing here checks it against files in the image). Exit 1 says it named an operating system
this recipe knows is not Linux (windows, osx, esxi, a BSD, android, ios) and so the route is closed. Exit 2 says
it could not tell (the reader is not in this image, it timed out, it failed, it printed nothing, it printed that
it could not identify the system, or it printed a name this recipe does not recognise: `unix`, `debian`, or text
with other words in it) and the route is NOT closed: the census records a detect step that failed, with why,
rather than "does not apply". A reader that is not in the image, or that timed out, is a missing observation
and never a negative. The name is read as one value: the `os` field if the output is a JSON object, the string
if it is a JSON string, the whole line otherwise; a word found among other words is not a name. The prefix by which
dissect.target names the target it read (`<Target /path/disk.E01> linux`) is taken off first when it names this image
exactly: until it was, every image read as could-not-tell and the census never planned this recipe.

Every answer carries `status` (complete, partial or failed) and `status_basis`, the pair coverage.json carries.
For detect, `complete` says the OS was identified (either way) and `failed` says it was not.

run builds the linux_triage artefact files and a coverage receipt that follows what each selected function
produced, read from the wrapper's own durable summary (which the wrapper rewrites after every function), so a
run that is killed or times out still leaves a receipt of what had been done. The receipt is written as
`incomplete` before the wrapper starts, and again if this process is terminated.

Processes. The wrapper, and every program it or detect starts, run in this process's own group, never in a session of
its own: the harness ends a recipe that runs too long, or is aborted, by killing its group, and a program in a group
of its own would go on writing into the output directory after the recipe is gone. SIGTERM, SIGINT and SIGHUP ask the
wrapper to stop (so that it says `terminated` in its summary), kill what is left of its tree, and write the receipt.
detect stops itself at LINUX_TARGET_DETECT_SECONDS (default 240, at most 280 of the harness's 300).
"""

import json
import os
import shutil
import signal
import subprocess
import sys
import time
import traceback
from pathlib import Path

# The harness gives a detect step 300 seconds (`timeout 300`); this one stops itself earlier, whatever the environment says.
MAX_DETECT_SECONDS = 280
try:
    DETECT_SECONDS = min(MAX_DETECT_SECONDS, max(1, int(os.environ.get("LINUX_TARGET_DETECT_SECONDS", "240"))))
except ValueError:
    DETECT_SECONDS = 240
# The wrapper (linux_triage) has deadlines of its own (13800 seconds by default, at most 14100); the recipe gives it this long, under the 14400 of the recipe's limit.
WRAPPER_SECONDS = 14300
# What dissect.target prints for a system it could not identify, rather than for one it identified.
UNIDENTIFIED = {"default", "unknown", "none", "null", "unidentified", "n/a"}
# Operating systems this recipe knows are not what it catalogues. Anything else that is not `linux` is not a no:
# `unix` or a distribution name may be a Linux this reader did not name so.
NOT_LINUX = {"windows", "osx", "macos", "darwin", "esxi", "bsd", "freebsd", "openbsd", "netbsd", "dragonfly", "android", "ios"}
NOT_COVERED = "deleted/unallocated carving, arbitrary application files, memory, encrypted content without a key"
# Where the receipt is read (agents read coverage.json first): the route to a file of this root that no function parses.
FILES_BY_PATH = ("a file of this root that no function parses (a configuration, a script, a binary) comes out by path in a job, through the "
                 "same reader and without mounting: target-fs -q <image> cp <path> -o \"$OUT/root<dir>\". Where The Sleuth Kit reads the file "
                 "system (one linear logical volume at its offset, ext), icat by inode keeps the record's identity, which a copy by path does "
                 "not; the offset is the partition start plus the PV's data start plus the volume's first extent times the extent size, all in "
                 "sectors (skills filesystem/storage-lvm-luks names the command for each); a copy carries the time of extraction as its modification time")


def process_identity(pid):
    """What identifies the process that has this pid right now: its start time (field 22 of /proc/<pid>/stat, in clock ticks since boot) and
    or, where there is no /proc, the start time `ps` reports. The parent is not part of it: when the wrapper ends its children are
    re-parented, and they are still the processes that were listed. A pid that is reused is another process with another start time.
    None where the process is gone or cannot be read."""
    try:
        with open("/proc/%d/stat" % pid, "rb") as fh:
            data = fh.read()
        fields = data[data.rindex(b")") + 2:].split()      # the name (field 2) may hold spaces and brackets: the rest follows the last ")"
        return ("proc", int(fields[19]))
    except (OSError, ValueError, IndexError):
        pass
    code, out, _err, timed_out = preflight(["ps", "-o", "lstart=", "-p", str(pid)], 5)
    text = out.decode("utf-8", "replace").strip()
    return ("ps", text) if code == 0 and not timed_out and text else None


def same_process(pid, listed):
    """Whether `pid` is still the process that was listed with the identity `listed` (process_identity at the time): a pid that has gone, or
    that another process has taken since, is not. A process whose identity could not be read when it was listed (`listed` is None) is not
    vouched for either: it is signalled only if it can be read now and is in this process's own group."""
    now = process_identity(pid)
    if now is None:
        return False
    if listed is None:
        try:
            return os.getpgid(pid) == os.getpgrp()
        except OSError:
            return False
    return now == listed


def answer(value, code=0):
    if value.get("ok") is False and "status" not in value:
        value = {**value, "status": "failed", "status_basis": value.get("error", "the recipe stopped with an error")}
    print(json.dumps(value))
    raise SystemExit(code)


def describe(exc):
    return "%s: %s" % (type(exc).__name__, exc)


# BEGIN SHARED PROCESS
# The same text is in pcap_extract, zeek_run, suricata_run, the network-capture recipe and computer-forensics-base's
# archive_extract; tests/pack-network-withholding.test.ts holds the four network copies equal and tests/pack-base-shared.test.ts
# holds archive_extract's to them. A program an engine tool runs is started in THIS tool's process group, never in a session of
# its own: the harness ends a tool that runs too long, or is aborted, by killing the tool's group (process.kill(-pid,
# SIGKILL)), and an engine in a group of its own goes on writing into the output directory after the tool is gone. On
# Linux the kernel is also asked to kill it if the tool dies. A deadline kills the program and what it started by
# walking the process tree, and SIGTERM, SIGINT and SIGHUP do the same and then give the tool a last word. Only what is
# below a program this tool started and has not yet waited for is ever signalled: the walk starts at that program's pid
# and nowhere else, and a program that has been waited for (its pid may be another process's by now) is left alone. The
# walk is bounded (MAX_ROUNDS and WALK_SECONDS, below). A stop signal is the one case that reaches further: it also
# ends everything below the tool itself (a program that was forked a moment before it was entered in ACTIVE is among it) and what
# the tool started and lost (reap_orphans): a process that was seen below the tool, in the tool's own group, and whose parent has since
# ended. Nothing else is ever ended: a process the tool never saw in its tree (the next stage of a pipeline the tool heads, a process a
# launcher put in the group) is left alone, whoever leads the group. A program that has ended while something it started still
# holds its pipes does not hold the tool: communicate_bounded gives the pipes PIPE_GRACE seconds (and POST_EXIT_BYTES bytes) and goes on without them.
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


def preflight(argv, seconds):
    """Run a short program, bounded; (exit code or None, stdout bytes, stderr bytes, timed out)."""
    try:
        proc = spawn(argv, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    except OSError as exc:
        return None, b"", describe(exc).encode("utf-8", "replace"), False
    ACTIVE.append(proc)
    try:
        out, err, timed_out = communicate_bounded(proc, max(1.0, seconds))
        return (None if timed_out else proc.returncode), out, err, timed_out
    finally:
        ACTIVE.remove(proc)


def run_to_files(argv, stdout_path, stderr_path, seconds, cwd=None):
    """One program with its output in files, killed with what it started at `seconds`. (exit code, timed out)."""
    with open(stdout_path, "wb") as stdout, open(stderr_path, "wb") as stderr:
        proc = spawn(argv, stdout=stdout, stderr=stderr, cwd=cwd)
        ACTIVE.append(proc)
        try:
            return proc.wait(timeout=max(0.1, seconds)), False
        except subprocess.TimeoutExpired:
            kill_tree(proc)
            proc.wait()
            return None, True
        finally:
            ACTIVE.remove(proc)


def install_signal_handlers():
    for signum in (signal.SIGTERM, signal.SIGINT, signal.SIGHUP):
        signal.signal(signum, _on_signal)
# END SHARED PROCESS


def undetermined(why, code=2):
    answer({"applies": "unknown", "status": "failed", "status_basis": "the OS was not identified, so no route is opened or closed", "why": why}, code)


def write_json(path, value):
    try:
        path.write_text(json.dumps(value, indent=2) + "\n")
    except OSError as exc:
        answer({"ok": False, "status": "failed", "status_basis": "the recipe's own output could not be written", "error": f"could not write {path}: {exc.strerror or exc}"}, 2)


def target_value(raw):
    try:
        value = json.load(open(raw, encoding="utf-8")) if os.path.isfile(raw) else json.loads(raw)
    except (OSError, ValueError) as exc:
        answer({"ok": False, "error": f"target is not readable JSON: {exc}"}, 2)
    paths = value.get("paths") if isinstance(value, dict) else None
    if not isinstance(paths, list) or not paths or not isinstance(paths[0], str):
        answer({"ok": False, "error": "target has no paths"}, 2)
    name = value.get("name")
    return paths[0], name if isinstance(name, str) and name else paths[0]


def detect(image):
    """Any failure to read the OS is exit 2 and `applies: unknown`: only an answer naming a system known not to be Linux closes the route.
    Only a reader that cannot run or answer is a failure of the probe; any other error is a defect in this recipe and is not hidden."""
    try:
        detect_os(image)
    except (OSError, subprocess.SubprocessError, UnicodeError) as exc:    # an unreadable reader, an answer that is not text: not a negative
        undetermined(f"the OS probe failed ({type(exc).__name__}: {exc}): the OS was not identified, so this route is not closed")


def target_prefixes(image):
    """How dissect.target names the target it read before a plain value (`<Target /path/disk.E01> linux`): the path as given, as
    normalised (`./disk.E01` is printed `disk.E01`), made absolute, and with its links resolved, longest first."""
    paths = {image, os.path.normpath(image), os.path.abspath(image), os.path.realpath(image)}
    return sorted({f"<Target {p}>" for p in paths if p}, key=len, reverse=True)


def os_name(text, image=None):
    """The one value `os` printed, or None: the `os` field of a JSON object, a JSON string, or the whole line. A word among other
    words is not a name (`{"os":"windows","hostname":"linux"}` names windows, and `a linux box` names nothing). The prefix by which
    dissect.target names the target it read (`<Target /path/disk.E01> linux`, as 3.25 in the linux image prints it) is not a word of the value:
    it is taken off when it names this image exactly, and any other text before the value still makes it no name."""
    text = text.strip()
    for prefix in target_prefixes(image) if image else []:
        if text.startswith(prefix + " ") or text.startswith(prefix + "\t"):
            text = text[len(prefix):].strip()
            break
    if not text:
        return None
    try:
        value = json.loads(text)
    except ValueError:
        value = text
    if isinstance(value, dict):
        value = value.get("os")
    if not isinstance(value, str):
        return None
    value = value.strip().lower()
    return value if value and len(value.split()) == 1 else None


def detect_os(image):
    binary = shutil.which("target-query")
    if not binary:
        undetermined("target-query is not in this image: the OS of the target was not identified, so this route is not closed")
    install_signal_handlers()
    code, raw_out, raw_err, timed_out = preflight([binary, "--no-cache", "-s", "-f", "os", image], DETECT_SECONDS)
    if timed_out:
        undetermined(f"target-query did not identify the OS within {DETECT_SECONDS} seconds: "
                     "not known to be Linux or not, so this route is not closed")
    stdout, stderr = raw_out.decode("utf-8", "replace"), raw_err.decode("utf-8", "replace")
    if code is None:
        undetermined(f"target-query could not be started ({stderr.strip()[-300:]}): the OS was not identified, so this route is not closed")
    text = stdout.strip()
    first = (text.splitlines() or [""])[0][:80]
    name = os_name(text, image) if code == 0 else None
    if name == "linux":
        answer({"applies": True, "status": "complete", "status_basis": "dissect.target's os function named the target; that is its own identification, not checked here against files in the image",
                "why": "dissect.target's os function named the target 'linux' (unverified here against the image's files)"})
    if name in NOT_LINUX:
        answer({"applies": False, "status": "complete", "status_basis": "dissect.target's os function named an operating system this recipe knows is not Linux",
                "why": f"dissect.target's os function named the target {name!r}, not Linux"}, 1)
    why = (stderr or stdout).strip()
    if code == 0 and not why:
        why = "target-query exited 0 and printed nothing: the OS was not identified"
    elif code == 0 and name in UNIDENTIFIED:
        why = f"target-query reported that it could not identify the system ({first!r})"
    elif code == 0:
        why = (f"target-query's os function printed {first!r}, which is not a single name this recipe recognises "
               "(linux, or an operating system it knows is not Linux): it is not read as either")
    elif not why:
        why = f"target-query exited {code} without identifying the OS"
    undetermined(why[-400:] + " (the OS was not identified: this route is not closed)")


def program_group_problems(what, held=True):
    """Sentences for the answer's problems from the shared process block's verdict, for an answer that reports `what`. A process settle() ended means what the program
    wrote (or printed on a pipe it held) was cut where it was ended; where the absence of one cannot be proven (not Linux, PR_SET_CHILD_SUBREAPER refused) files a program
    wrote cannot be shown to be final. held=False is a recipe that reports only what a program printed on a pipe: it is not held to the second rule (program_group still
    says why), but processes that were adopted and could not all be ended are still named."""
    verdict = process_verdict()
    found = []
    if verdict["left_behind"]:
        found.append("a program left %d process(es) running after it ended (in the recipe's process group, in a session of its own, or after a double fork); the shared process block "
                     "stopped, killed and reaped them before %s were read, so what they would still have written is missing from %s" % (verdict["left_behind"], what, what))
    for why in verdict["unproven"]:
        if held or verdict["subreaper"]:
            found.append("%s: %s cannot be shown to be final" % (why, what))
    return found


def combined_group(summary):
    """The verdict of the whole run: the recipe's own (the wrapper it started and anything adopted from it) and the wrapper's, which ran dissect.target (the programs the files come from)
    and reports its own in the summary. A wrapper whose summary carries none (it was stopped, or did not write one) leaves what it ran unproven."""
    own = process_verdict()
    theirs = summary.get("program_group") if isinstance(summary, dict) else None
    if not isinstance(theirs, dict) or not isinstance(theirs.get("left_behind"), int) or not isinstance(theirs.get("unproven"), list):
        return {**own, "wrapper": None, "unproven": own["unproven"] + ["linux_triage's summary carries no program_group: what dissect.target left behind is not known"]}
    return {"subreaper": bool(own["subreaper"] and theirs.get("subreaper")), "left_behind": own["left_behind"] + theirs["left_behind"],
            "unproven": own["unproven"] + ["linux_triage: " + str(why) for why in theirs["unproven"]], "notes": own["notes"], "wrapper": theirs}


def group_problems(group, what):
    found = []
    if group["left_behind"]:
        found.append("a program left %d process(es) running after it ended (dissect.target under linux_triage, or one of this recipe's own); the shared process block stopped, killed and reaped "
                     "them before %s were counted and hashed, so what they would still have written is missing from %s" % (group["left_behind"], what, what))
    for why in group["unproven"]:
        found.append("%s: %s cannot be shown to be final" % (why, what))
    return found


FUNCTION_STATUSES = ("parsed", "empty", "unsupported", "failed", "not_attempted", "unknown")


def coverage_from(summary, proc_code, shown, state):
    """The receipt: what each selected function produced, from the wrapper's own summary."""
    counts = {k: 0 for k in FUNCTION_STATUSES}
    errors, limits = [], []
    for group in (summary or {}).get("groups") or []:
        for fn in group.get("functions") or []:
            status = fn.get("status")
            if status in counts:
                counts[status] += 1
            if status in ("unsupported", "failed", "not_attempted", "unknown"):
                why = {"unsupported": "the stderr says the function is not available for this target",
                       "failed": f"exit {fn.get('exit_code')}, timed_out={fn.get('timed_out')}",
                       "not_attempted": fn.get("reason", "not started"),
                       "unknown": "its output or stderr could not be read as parsed or empty: read the files"}[status]
                errors.append(f"{group.get('group')}: {fn.get('name')} {status}: {why}")
            if fn.get("timed_out"):
                limits.append(f"{fn.get('name')} timed out ({fn.get('deadline', 'function')} deadline)")
            if status in ("running", "pending"):
                counts["not_attempted"] += 1
                errors.append(f"{group.get('group')}: {fn.get('name')} was {status} when the receipt was written")
    wrapper = (summary or {}).get("state", "missing")
    done = wrapper == "finished" and proc_code == 0 and (summary or {}).get("execution_complete") is True
    group = combined_group(summary)
    leftovers = group_problems(group, "the families' files and the receipt")
    errors[0:0] = leftovers
    clean = done and not leftovers and not any(counts[k] for k in ("unsupported", "failed", "not_attempted", "unknown"))
    total = sum(counts.values())
    ran = counts["parsed"] + counts["empty"] + counts["unsupported"] + counts["unknown"]
    if summary is None:
        status, basis = "failed", "the wrapper left no summary of this run, so what ran is not known"
    elif clean:
        status, basis = "complete", f"every one of the {total} selected functions ran to exit 0 and produced records or nothing: this is not coverage of the host"
    elif ran == 0:
        status, basis = "failed", f"no selected function ran to an exit ({counts['failed']} failed, {counts['not_attempted']} not attempted)"
    else:
        short = ", ".join(f"{counts[k]} {k}" for k in ("unsupported", "failed", "not_attempted", "unknown") if counts[k])
        status, basis = "partial", (f"{ran} of {total} selected functions ran" + (f"; {short}" if short else "")
                                    + ("; " + "; ".join(leftovers) if leftovers else "")
                                    + ("" if done else "; the wrapper did not end cleanly") + ": the errors say which")
    return {
        "recipe": "linux-target",
        "status": status,
        "status_basis": basis,
        "covered": "the dissect.target functions selected for this recipe (counted under functions, named in artefacts/summary.json) over "
                   + shown + "; `complete` says every selected function ran and produced records or nothing, not that the artefacts exist or were all read",
        "not_covered": NOT_COVERED,
        "files_by_path": FILES_BY_PATH,
        "functions": counts,
        "limits_hit": limits,
        "errors": errors,
        "wrapper": {"state": wrapper, "exit_code": proc_code, "execution_complete": (summary or {}).get("execution_complete")},
        "program_group": group,
        "receipt_written": state,
    }


def read_summary(out, since):
    """The wrapper's summary, if it is this run's: one that started before this process did is an earlier run's."""
    try:
        summary = json.loads((out / "artefacts" / "summary.json").read_text())
    except (OSError, ValueError):
        return None
    started = summary.get("started") if isinstance(summary, dict) else None
    if not isinstance(started, (int, float)) or started < since:
        return None
    return summary


def write_index(out):
    with (out / "index.tsv").open("w", encoding="utf-8") as index:
        index.write("summary.json\tlinux_triage's answer: per function status, exit code, records, paths, sizes and hashes\n")
        for path in sorted((out / "artefacts").glob("*")) if (out / "artefacts").is_dir() else []:
            if not path.is_file():
                continue
            if path.name == "summary.json":
                kind = "durable summary the wrapper rewrote after every function (state running or finished)"
            elif path.suffix in (".jsonl", ".txt"):
                kind = "complete target-query output of a family's functions, in order"
            else:
                kind = "complete target-query stderr of one function"
            index.write(f"artefacts/{path.name}\t{kind}\n")
        if (out / "runner.stderr").exists():
            index.write("runner.stderr\tcomplete stderr from the linux_triage runner\n")


def run(image, shown, out):
    try:
        out.mkdir(parents=True, exist_ok=True)
    except OSError as exc:
        answer({"ok": False, "error": f"the output directory could not be made: {exc.strerror or exc}", "out": str(out)}, 2)
    # An earlier run's receipt and files are never replaced: the wrapper refuses an out_dir that exists, and the receipt written
    # below would otherwise end as a smaller one saying the wrapper left no summary. Nothing is written here.
    earlier = [name for name in ("coverage.json", "summary.json", "index.tsv", "artefacts") if os.path.lexists(out / name)]
    if earlier:
        answer({"ok": False, "status": "failed",
                "status_basis": "the output directory already holds a result of an earlier run (%s): it was not touched and nothing was run" % ", ".join(earlier),
                "error": f"{out} already holds {', '.join(earlier)} from an earlier run; give --out a directory of its own", "out": str(out)}, 2)
    tool = Path(__file__).resolve().parents[2] / "tools" / "linux_triage" / "run.py"
    # The wrapper runs in the output directory, so that what it makes is under its own working directory whatever this
    # process's was; the image is named by its absolute path for the same reason.
    request = {"source": os.path.abspath(image), "out_dir": "artefacts"}
    state = {"proc": None}
    began = time.time()

    def receipt(proc_code, written):
        summary = read_summary(out, began)
        coverage = coverage_from(summary, proc_code, shown, written)
        write_json(out / "coverage.json", coverage)
        write_index(out)
        return coverage

    # A receipt exists before the wrapper starts, and again if this process is told to stop.
    write_json(out / "coverage.json", {
        "recipe": "linux-target", "status": "partial", "status_basis": "the wrapper had not finished: nothing is established yet",
        "covered": "nothing yet: the wrapper had not finished",
        "not_covered": NOT_COVERED, "errors": ["the wrapper was running when this receipt was written; see artefacts/summary.json"],
        "receipt_written": "before the wrapper started"})

    def terminated(signum, _frame):
        child = state["proc"]
        if child is not None and child.poll() is None:
            # The wrapper is in this process's group, not a session of its own. It is asked to stop first, so that it ends the
            # dissect.target it started and says `terminated` in its summary; whatever is left of its tree is then killed.
            # Each pid is listed with what identifies the process behind it, and killed only if that is still true: the wrapper is given 8
            # seconds to stop, and a process of the list that ended in them may have had its pid taken by another.
            victims = {pid: process_identity(pid) for pid in descendants(child.pid)}
            try:
                child.terminate()
            except OSError:
                pass
            try:
                child.wait(timeout=8)
            except subprocess.TimeoutExpired:
                pass
            kill_tree(child)
            for pid, listed in victims.items():
                if not same_process(pid, listed):
                    continue
                try:
                    os.kill(pid, signal.SIGKILL)
                except OSError:
                    pass
        kill_all()                  # what the wrapper left running (it may have ended already), with anything this recipe started: the stop leaves nothing alive
        receipt(None, "after this process was terminated")
        try:
            sys.stdout.write(json.dumps({"ok": False, "status": "partial", "status_basis": "the recipe was stopped by %s before the wrapper finished: coverage.json says partial" % signal.Signals(signum).name}) + "\n")
            sys.stdout.flush()
        except (OSError, ValueError):
            pass
        os._exit(128 + signum)

    for signum in (signal.SIGTERM, signal.SIGINT, signal.SIGHUP):
        signal.signal(signum, terminated)
    try:
        # In this process's own group, never a session of its own: the harness ends a recipe by killing its group.
        proc = spawn([sys.executable, str(tool)], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, cwd=str(out))
    except OSError as exc:
        answer({"ok": False, "status": "failed", "status_basis": "the wrapper could not be started", "error": f"linux_triage could not be started: {exc.strerror or exc}"}, 2)
    state["proc"] = proc
    ACTIVE.append(proc)
    try:
        # bounded: the wrapper has deadlines of its own (13800 seconds by default), and a process that holds its pipes after it ended is let go after a second and ended
        raw_out, raw_err, wrapper_timed_out = communicate_bounded(proc, WRAPPER_SECONDS, json.dumps(request).encode("utf-8"))
    finally:
        ACTIVE.remove(proc)             # settle(): what the wrapper left behind in its turn is ended before its files are read
    stdout, stderr = raw_out.decode("utf-8", "replace"), raw_err.decode("utf-8", "replace")
    try:
        (out / "summary.json").write_text(stdout or json.dumps({"error": "linux_triage wrote no result"}) + "\n")
        if stderr:
            (out / "runner.stderr").write_text(stderr)
    except OSError as exc:
        answer({"ok": False, "status": "failed", "status_basis": "the recipe's own output could not be written", "error": f"could not write the wrapper's answer: {exc.strerror or exc}"}, 2)
    coverage = receipt(proc.returncode, "after the wrapper finished")
    if proc.returncode != 0:
        coverage["errors"].append(f"linux_triage exited {proc.returncode}" + (f": it did not end within {WRAPPER_SECONDS} seconds and was ended with everything it started" if wrapper_timed_out else ""))
        if coverage["status"] == "complete":
            coverage["status"], coverage["status_basis"] = "partial", f"linux_triage exited {proc.returncode}"
        write_json(out / "coverage.json", coverage)
    answer({"ok": proc.returncode == 0, "status": coverage["status"], "status_basis": coverage["status_basis"], "functions": coverage["functions"], "program_group": coverage["program_group"]},
           0 if proc.returncode == 0 else 2)


def main():
    command = sys.argv[1] if len(sys.argv) > 1 else ""
    target = None
    out = None
    args = iter(sys.argv[2:])
    for arg in args:
        if arg == "--target":
            target = next(args, None)
        elif arg == "--out":
            out = next(args, None)
        elif arg == "--probe-out":
            next(args, None)
        else:
            answer({"ok": False, "error": f"unknown argument: {arg}"}, 2)
    if not target:
        answer({"ok": False, "error": "--target is required"}, 2)
    image, shown = target_value(target)
    if not os.path.exists(image):
        answer({"ok": False, "error": "target path does not exist"}, 2)
    if command == "detect":
        detect(image)
    if command == "run" and out:
        run(image, shown, Path(out))
    answer({"applies": "unknown", "why": "a usage error, so nothing was asked", "ok": False, "error": "usage: run.py detect --target T | run --target T --out DIR"}, 2)


if __name__ == "__main__":
    try:
        main()
    except SystemExit:
        raise
    except Exception:
        # A defect in this recipe is shown, not turned into a negative: the traceback is on stderr, and the answer is
        # "could not tell" (exit 2), never exit 1, which says the route is closed.
        traceback.print_exc()
        undetermined("this recipe failed on an unexpected error (the traceback is on its stderr): the OS was not identified, so no route is closed")
