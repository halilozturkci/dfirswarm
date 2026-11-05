#!/usr/bin/env python3
"""Unpack a UPX-packed executable into a derivative file, and say exactly what was done to it.

UPX only. `upx -t` runs first; a file UPX does not recognise is refused ("unsupported"), and a file that carries the name of another
packer (a section name or a banner such as the ones listed in OTHER_PACKERS) is refused by that name as a hint, never unpacked by guesswork.
The derivative is written by `upx -d` into a directory of its own under the tool-output directory (in a job, under $OUT), never over the
original, under an output budget (UPX can expand about 1000:1): the size UPX lists for the unpacked file is checked against the budget
before anything is written, and the file is watched while UPX writes it, so that a file that grows past the budget ends UPX and is removed.
It is then linked under its final name without replacing anything, with no execute bit. Both SHA-256 values and `upx --version` are recorded.

Nothing from the sample is printed: UPX's own output goes to log files under the tool-output directory, and the answer holds only fixed
words, numbers and the names this tool made. The sample is never executed; UPX reads it and writes the derivative.
"""
import errno
import hashlib
import json
import os
import re
import signal
import stat
import subprocess
import sys
import time
from pathlib import Path

TOOL = {"name": "unpack_safe", "version": 2}
PARSER = "unpack_safe/1"
TOTAL_BUDGET = 150                 # seconds for the whole call; the manifest's own limit is 180
DEFAULT_SECONDS = 120
MAX_INPUT_BYTES = 1 << 30          # the largest sample this tool takes (bytes); a larger one is refused, not cut
DEFAULT_OUTPUT_BYTES = 256 << 20
MIN_OUTPUT_BYTES, MAX_OUTPUT_BYTES = 1 << 20, 1 << 30
POLL = 0.02                        # seconds between looks at the growing derivative
LOG_READ = 1 << 16                 # how much of a log is read back to classify UPX's answer
SCAN_BYTES = 1 << 20               # how much of the head of the sample is looked at for another packer's name
# Names of other packers that leave a plain marker near the head of a file (section names, banners). A hint only: a match is a reason to
# refuse, never a finding about the sample.
OTHER_PACKERS = (
    (b".aspack", "ASPack"), (b".adata", "ASPack"), (b".themida", "Themida"), (b".vmp0", "VMProtect"), (b".vmp1", "VMProtect"),
    (b".MPRESS1", "MPRESS"), (b"PEC2", "PECompact"), (b".petite", "Petite"), (b".nsp0", "NsPack"), (b".enigma1", "Enigma Protector"),
    (b".perplex", "Perplex"), (b"kkrunchy", "kkrunchy"), (b"FSG!", "FSG"), (b".y0da", "Yoda's Protector"), (b"Obsidium", "Obsidium"),
)


def describe(exc):
    code = errno.errorcode.get(exc.errno, "") if getattr(exc, "errno", None) else ""
    return "%s%s: %s" % (type(exc).__name__, " " + code if code else "", getattr(exc, "strerror", None) or str(exc))


def fail(message, **extra):
    print(json.dumps({"error": message, "status": extra.pop("status", "failed"), "status_basis": extra.pop("status_basis", message), "tool": TOOL, **extra}))
    raise SystemExit(1)


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
# holds its pipes does not hold the tool: communicate_bounded gives the pipes PIPE_GRACE seconds and goes on without them.
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

LINKED = []                        # derivatives linked under their final name whose answer is not yet being written: a stop removes them
STAGES = []                        # the directories this call made for the derivative: the last word of a stopped call removes what is left of them


def stopped_answer(signum, **extra):
    print(json.dumps({"error": "stopped by signal %d before the answer was complete" % signum, "status": "failed", "interrupted": True,
                      "status_basis": "the tool was stopped by signal %d; nothing it had done is an answer, and the programs it started were ended" % signum,
                      "tool": TOOL, "stopped_by_signal": signum, **extra}), flush=True)


def _clean_stages():
    for stage in list(STAGES):
        try:
            for name in os.listdir(stage):
                os.unlink(os.path.join(stage, name))
            os.rmdir(stage)
        except OSError:
            pass


def _remove_linked():
    removed = []
    for path in list(LINKED):
        try:
            os.unlink(path)
            removed.append(str(path))
        except OSError:
            pass
        LINKED.remove(path)
    return removed


def _first_word(signum):
    """The last word of a stop signal that comes before main() has set the tool's own: one answer, saying nothing had been done yet."""
    stopped_answer(signum)


STATE["last_word"] = _first_word
install_signal_handlers()
# the stop handlers are installed here, at module level


def print_answer(answer):
    """Print the answer with the stop signals held back, so that exactly one complete document is written."""
    try:
        signal.pthread_sigmask(signal.SIG_BLOCK, {signal.SIGTERM, signal.SIGINT, signal.SIGHUP})
    except (AttributeError, ValueError, OSError):
        pass
    STATE["last_word"] = None
    LINKED.clear()                  # from here the answer is written: the derivative is the answer's
    print(json.dumps(answer, indent=2))
    sys.stdout.flush()


def shutil_which(name):
    for directory in os.environ.get("PATH", "").split(os.pathsep):
        candidate = os.path.join(directory, name)
        if os.path.isfile(candidate) and os.access(candidate, os.X_OK):
            return candidate
    return None


KINDS = ((stat.S_ISDIR, "a directory"), (stat.S_ISFIFO, "a named pipe"), (stat.S_ISSOCK, "a socket"), (stat.S_ISBLK, "a block device"),
         (stat.S_ISCHR, "a character device"))


def open_regular(path):
    """(fd, stat) of a regular file, opened without blocking and without following a link, or (None, why). The kind is read from the open
    descriptor, so a pipe swapped in after a look at the name is still not read."""
    flags = os.O_RDONLY | os.O_NONBLOCK | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0)
    try:
        fd = os.open(path, flags)
    except FileNotFoundError:
        return None, "no such file"
    except OSError as exc:
        if exc.errno == errno.ELOOP:
            return None, "a symbolic link: refused, the file is not followed"
        return None, "the file could not be opened: %s" % describe(exc)
    st = os.fstat(fd)
    if not stat.S_ISREG(st.st_mode):
        os.close(fd)
        return None, "not a regular file (%s)" % next((n for t, n in KINDS if t(st.st_mode)), "a special file")
    return fd, st


def sha256_fd(fd, deadline, limit=None):
    """(digest or None, bytes read, whether the whole file was read): the clock is looked at once per block of 1 MiB."""
    digest = hashlib.sha256()
    size = 0
    os.lseek(fd, 0, os.SEEK_SET)
    while True:
        if time.monotonic() > deadline:
            return None, size, False
        block = os.read(fd, 1 << 20)
        if not block:
            break
        size += len(block)
        if limit is not None and size > limit:
            return None, size, False
        digest.update(block)
    return digest.hexdigest(), size, True


def own_dir(path):
    """Make the tool-output directory; say why it is not used if a symbolic link lies on the way (O_NOFOLLOW guards only the last name). In a
    job only the part under $OUT is checked ($OUT is the job service's)."""
    path = Path(path)
    out = os.environ.get("OUT")
    start = len(Path(out).parts) if out and path.parts[:len(Path(out).parts)] == Path(out).parts else 0
    for i in range(max(start, 1), len(path.parts) + 1):
        step = Path(*path.parts[:i])
        if os.path.islink(step):
            return "%s is a symbolic link: refused, nothing written through it" % step
    path.mkdir(parents=True, exist_ok=True)
    return None


def output_dir():
    out = os.environ.get("OUT")
    if out:
        return Path(out) / "tool-output"
    agent = re.sub(r"[^A-Za-z0-9_.-]", "_", os.environ.get("AGENT_ID") or "tool")
    return Path("work") / agent / "tool-output"


def create_exclusive(directory, name, mode=0o644):
    """A new file named `name` (or `stem-N.ext`) in `directory`, created with O_EXCL and O_NOFOLLOW, never an existing one: (file object, name)."""
    stem, dot, ext = name.rpartition(".")
    flags = os.O_RDWR | os.O_CREAT | os.O_EXCL | os.O_APPEND | getattr(os, "O_NOFOLLOW", 0)
    for n in range(1, 1000):
        candidate = name if n == 1 else "%s-%d.%s" % (stem, n, ext)
        try:
            fd = os.open(str(directory / candidate), flags, mode)
        except FileExistsError:
            continue
        return os.fdopen(fd, "ab", buffering=0), candidate
    raise OSError(errno.EEXIST, "a thousand files of this name already exist")


def printable(text, limit=120):
    return "".join(c if " " <= c <= "~" else "?" for c in text)[:limit]


LEFT_SECONDS = 3.0                 # the longest the tool works at ending what still holds a file of its call
SETTLE_SECONDS = 0.3               # after that, the file is looked at again after this long: a file that still grows is not whole


def _identities(targets):
    """{(device, inode)} of the open files (an int is a descriptor of this tool) and paths (a str) in `targets`; one that cannot be looked at is left out."""
    found = set()
    for target in targets:
        try:
            st = os.fstat(target) if isinstance(target, int) else os.stat(target)
        except OSError:
            continue
        found.add((st.st_dev, st.st_ino))
    return found


def _holds(pid, want):
    """Whether process `pid` has one of the files `want` open (Linux: /proc/<pid>/fd; a process of another user cannot be looked at and holds nothing here)."""
    try:
        for name in os.listdir("/proc/%d/fd" % pid):
            try:
                other = os.stat("/proc/%d/fd/%s" % (pid, name))
            except OSError:
                continue
            if (other.st_dev, other.st_ino) in want:
                return True
    except (OSError, ValueError):
        pass
    return False


def holders_of(targets):
    """The pids, not this tool's, that hold one of `targets` open, or None when they cannot be looked for (no /proc: not Linux). The files are
    private to this call (a stage directory made for it, a log it created), so a process that holds one got it from what the tool started."""
    if not os.path.isdir("/proc/self"):
        return None
    want = _identities(targets)
    if not want:
        return []
    try:
        entries = os.listdir("/proc")
    except OSError:
        return None
    me = os.getpid()
    return [int(entry) for entry in entries if entry.isdigit() and int(entry) != me and _holds(int(entry), want)]


def end_holders(targets):
    """End what still holds one of the call's own files once the program has ended (or been killed): every such process in the tool's own process
    group is killed (SIGKILL, each checked again just before it is signalled), repeated until none is left, for at most LEFT_SECONDS. The group
    is the tool's own, as the harness ends the tool by it; a process outside it that holds a file (one that started a session of its own) is not
    touched. Returns (the pids ended, the pids still holding a file afterwards, or None when they cannot be looked for)."""
    mine = os.getpgrp()
    ended = set()
    end = time.monotonic() + LEFT_SECONDS
    while True:
        holders = holders_of(targets)
        if holders is None:
            return ended, None
        inside = []
        for pid in holders:
            try:
                if os.getpgid(pid) == mine:
                    inside.append(pid)
            except OSError:
                pass
        if not inside:
            return ended, holders
        want = _identities(targets)
        for pid in inside:
            if _holds(pid, want):
                try:
                    os.kill(pid, signal.SIGKILL)
                    ended.add(pid)
                except OSError:
                    pass
        if time.monotonic() >= end:
            return ended, holders_of(targets)
        time.sleep(0.02)


def output_settled(path):
    """(whether the file is still, why not): the size of the file is read, the tool waits SETTLE_SECONDS, and the size is read again; a file that
    grew, that has a second name (a hard link), or that a process still holds open (end_holders ended those in the tool's group, so this is a process outside it), is not whole."""
    try:
        before = os.stat(path).st_size
        time.sleep(SETTLE_SECONDS)
        seen = os.stat(path)
        after = seen.st_size
    except OSError as exc:
        return False, "the file could not be looked at again: %s" % describe(exc)
    held = holders_of([path]) or []
    if after == before and not held and seen.st_nlink == 1:
        return True, None
    reasons = []
    if seen.st_nlink != 1:
        reasons.append("the file has %d names (a hard link made by the program or a process it left): a process that holds no descriptor can still append through the other name" % seen.st_nlink)
    if after != before:
        reasons.append("the file grew from %d to %d bytes after the program had ended" % (before, after))
    if held:
        reasons.append("a process (pid %s) outside the tool's process group still holds the file open" % ", ".join(str(p) for p in held[:5]))
    return False, "; ".join(reasons) + " (a process in a session of its own cannot be ended by this tool, and the file may still be growing)"


class Steps:
    """The programs run for one call: each step's output goes, with a header line, to the one log file under the tool-output directory, and
    only its first 64 KiB is read back, to classify UPX's answer. None of it is printed."""

    def __init__(self, directory, deadline):
        self.dir = directory
        self.deadline = deadline
        self.log = None
        self.log_name = None
        self.records = []

    def open_log(self, key):
        digest = hashlib.sha256(key.encode("utf-8", "surrogatepass")).hexdigest()[:12]
        self.log, self.log_name = create_exclusive(self.dir, "unpack-safe-%s.log" % digest, 0o600)

    def run(self, label, argv, seconds, watch=None, produced=None):
        """Run one program; the record: label, argv, exit_code, timed_out, stopped_by_watch, seconds, text (the first 64 KiB of its output)."""
        remaining = self.deadline - time.monotonic()
        rec = {"label": label, "argv": argv, "exit_code": None, "timed_out": False, "stopped_by_watch": False, "seconds": 0.0, "text": "", "output_bytes": 0,
               "left_behind": 0, "holders_outside": [], "holders_unknown": False}
        if remaining <= 0:
            rec["not_attempted"] = "the call's time budget was spent before this step"
            self.records.append(rec)
            return rec
        seconds = max(0.5, min(seconds, remaining))
        self.log.write(("## %s: %s\n" % (label, " ".join(argv))).encode("utf-8", "replace"))
        start = os.fstat(self.log.fileno()).st_size
        started = time.monotonic()
        try:
            proc = spawn(argv, stdout=self.log, stderr=subprocess.STDOUT)
        except OSError as exc:
            rec["launch_failed"] = "the program could not be started: %s" % describe(exc)
            self.records.append(rec)
            return rec
        ACTIVE.append(proc)
        try:
            while True:
                try:
                    proc.wait(timeout=POLL)
                    break
                except subprocess.TimeoutExpired:
                    pass
                if watch is not None and watch():
                    rec["stopped_by_watch"] = True
                    kill_tree(proc)
                    proc.wait()
                    break
                if time.monotonic() - started > seconds:
                    rec["timed_out"] = True
                    kill_tree(proc)
                    proc.wait()
                    break
        finally:
            before = LEFT["left_behind"]
            ACTIVE.remove(proc)             # the process block's settle() ends what the program left, so the scan below finds none of it: it is counted here
            settled = LEFT["left_behind"] - before
            # a process the program left behind would go on writing into the log, and into the derivative: whatever of the tool's group still holds the log
            # (or the file named in `produced`) is ended, and waited for to be gone, before anything is read
            ended, outside = end_holders([self.log.fileno()] + list(produced or []))
            if not (rec["timed_out"] or rec["stopped_by_watch"]):
                rec["left_behind"] = len(ended) + settled
            rec["holders_outside"] = outside or []
            rec["holders_unknown"] = outside is None
        rec["exit_code"] = proc.returncode
        rec["seconds"] = round(time.monotonic() - started, 3)
        end = os.fstat(self.log.fileno()).st_size
        n = min(end - start, LOG_READ)
        rec["text"] = os.pread(self.log.fileno(), n, start).decode("utf-8", "replace") if n > 0 else ""
        rec["output_bytes"] = max(0, end - start)
        self.records.append(rec)
        return rec

    def shown(self):
        out = []
        for r in self.records:
            row = {k: r[k] for k in ("label", "argv", "exit_code", "timed_out", "stopped_by_watch", "seconds", "output_bytes")}
            for k in ("not_attempted", "launch_failed"):
                if k in r:
                    row[k] = r[k]
            if r["left_behind"]:
                row["left_behind"] = r["left_behind"]
            row["status"] = ("not_attempted" if "not_attempted" in r else "launch_failed" if "launch_failed" in r else "timed_out" if r["timed_out"]
                             else "stopped_by_budget" if r["stopped_by_watch"] else "ok" if r["exit_code"] == 0 else "failed")
            out.append(row)
        return out


def other_packer(fd):
    """The name of another packer whose marker is in the first SCAN_BYTES of the file, or None. A hint only."""
    os.lseek(fd, 0, os.SEEK_SET)
    head = os.read(fd, SCAN_BYTES)
    for marker, name in OTHER_PACKERS:
        if marker in head:
            return name
    return None


LIST_ROW = re.compile(r"^\s*(\d+)\s*(?:->|<-)\s*(\d+)\s+[0-9.]+%\s")


def listed_unpacked_size(text):
    """The unpacked size `upx -l` lists, or None: the larger number of the one row of sizes (the layout of the two numbers differs between
    UPX's list and compress modes, the unpacked one is the larger either way)."""
    sizes = []
    for line in text.splitlines():
        m = LIST_ROW.match(line)
        if m:
            sizes.append(max(int(m.group(1)), int(m.group(2))))
    return sizes[0] if len(sizes) == 1 else None


def parse_args(args):
    if not isinstance(args, dict):
        fail("arguments must be a JSON object")
    path = args.get("path")
    if not isinstance(path, str) or not path or "\0" in path:
        fail("path must be a non-empty string without a NUL")
    try:
        path.encode("utf-8")
    except UnicodeEncodeError:
        fail("path must be text that can be written as UTF-8 (it holds a lone surrogate)")
    budget = args.get("max_output_bytes", DEFAULT_OUTPUT_BYTES)
    if isinstance(budget, bool) or not isinstance(budget, int) or not MIN_OUTPUT_BYTES <= budget <= MAX_OUTPUT_BYTES:
        fail("max_output_bytes must be an integer from %d to %d" % (MIN_OUTPUT_BYTES, MAX_OUTPUT_BYTES))
    seconds = args.get("max_seconds", DEFAULT_SECONDS)
    if isinstance(seconds, bool) or not isinstance(seconds, int) or not 5 <= seconds <= TOTAL_BUDGET:
        fail("max_seconds must be an integer from 5 to %d" % TOTAL_BUDGET)
    for key in args:
        if key not in ("path", "max_output_bytes", "max_seconds"):
            fail("unknown parameter %s" % printable(repr(key), 60))
    return path, budget, seconds


def main():
    try:
        args = json.load(sys.stdin)
    except (ValueError, RecursionError) as exc:
        fail("arguments are not valid JSON", reason=printable(str(exc), 200))
    path, budget, seconds = parse_args(args)
    clock = time.monotonic()
    deadline = clock + seconds
    upx = shutil_which("upx")
    if not upx:
        fail("upx is not installed; this image cannot unpack a UPX-packed file")
    fd, st = open_regular(path)
    if fd is None:
        fail(st, path=path)
    if st.st_size > MAX_INPUT_BYTES:
        os.close(fd)
        fail("the file is %d bytes; this tool takes at most %d" % (st.st_size, MAX_INPUT_BYTES), path=path, bytes=st.st_size, limits_hit=["input_bytes"])
    identity = (st.st_dev, st.st_ino, st.st_size, st.st_mtime_ns)
    sha, read, whole = sha256_fd(fd, deadline)
    if not whole:
        os.close(fd)
        fail("the call's time budget of %d seconds ran out while hashing the sample (%d of %d bytes)" % (seconds, read, st.st_size), path=path, limits_hit=["time"])
    original = {"path": path, "bytes": st.st_size, "sha256": sha}
    directory = output_dir()
    refused = own_dir(directory)
    if refused:
        fail(refused, original=original)
    steps = Steps(directory, deadline)
    try:
        steps.open_log("%s\0%s" % (os.path.realpath(path), sha))
    except OSError as exc:
        fail("the log could not be created in %s: %s" % (directory, describe(exc)), original=original)
    stage = None
    notes = []

    def last_word(signum):
        removed = _remove_linked()
        stopped_answer(signum, original=original, steps=steps.shown(), log=steps.log_name,
                       removed_derivative=removed or None, note=("the derivative linked just before the stop was removed" if removed else None))
        _clean_stages()

    STATE["last_word"] = last_word
    install_signal_handlers()

    def finish(status, basis, derivative=None, **extra):
        version = next((r for r in steps.records if r["label"] == "upx --version"), None)
        line = next((l.strip() for l in (version or {}).get("text", "").splitlines() if l.strip()), "")
        answer = {
            "tool": TOOL, "parser": PARSER, "status": status, "status_basis": basis, "original": original, "derivative": derivative,
            "upx": {"program": upx, "version_command": [upx, "--version"], "version_command_output": printable(line) if line else None},
            "steps": steps.shown(), "log": steps.log_name, "limits": {"max_output_bytes": budget, "max_seconds": seconds, "max_input_bytes": MAX_INPUT_BYTES},
            "notes": notes + process_notes(),
            "note": "The derivative is UPX's decompression of the sample, written to a file of its own with no execute bit; the original was not changed. "
                    "Unpacking does not make the sample safe to run, and a derivative that UPX produced says nothing about whether the sample did anything.",
            **extra,
        }
        print_answer(answer)
        raise SystemExit(0 if status in ("complete", "partial") else 1)

    version = steps.run("upx --version", [upx, "--version"], 10)
    tested = steps.run("upx -t", [upx, "-t", "--", path], max(1, deadline - time.monotonic()))
    if tested["exit_code"] != 0:
        text = tested["text"]
        if "launch_failed" in tested:
            finish("failed", "upx could not be started: nothing was unpacked")
        if tested["timed_out"] or "not_attempted" in tested:
            finish("partial", "upx -t %s within the call's time budget of %d seconds: nothing was unpacked, and nothing is known about whether the file is UPX-packed" % (
                "did not finish" if tested["timed_out"] else "was not run", seconds), limits_hit=["time"])
        if "NotPackedException" in text:
            hint = other_packer(fd)
            if hint:
                finish("unsupported", "upx -t found no UPX packing, and the file carries the marker of another packer (%s, a hint, not a finding); this tool unpacks UPX only" % hint,
                       other_packer_hint=hint)
            finish("unsupported", "upx -t found no UPX packing in the file; this tool unpacks UPX only")
        finish("failed", "upx -t reported a problem with the file (exit %s; UPX's words are in the log): nothing was unpacked and no derivative exists" % tested["exit_code"])
    listing = steps.run("upx -l", [upx, "-l", "--", path], max(1, deadline - time.monotonic()))
    expected = listed_unpacked_size(listing["text"]) if listing["exit_code"] == 0 else None
    if listing["timed_out"] or "not_attempted" in listing:
        finish("partial", "upx -l %s within the call's time budget of %d seconds: upx -d was not attempted, nothing was written" % (
            "did not finish" if listing["timed_out"] else "was not run", seconds), limits_hit=["time"])
    if expected is not None and expected > budget:
        finish("partial", "upx lists an unpacked size of %d bytes, past the output budget of %d: nothing was written" % (expected, budget),
               limits_hit=["max_output_bytes"], expected_unpacked_bytes=expected)
    try:
        stage = Path(directory) / ("stage-%s" % hashlib.sha256(os.urandom(16)).hexdigest()[:16])
        os.mkdir(stage, 0o700)
    except OSError as exc:
        finish("failed", "the directory for the derivative could not be made: %s" % describe(exc))
    STAGES.append(str(stage))
    produced = stage / "out"

    def over_budget():
        try:
            return os.lstat(produced).st_size > budget
        except OSError:
            return False

    unpack = steps.run("upx -d", [upx, "-d", "-o", str(produced), "--", path], max(1, deadline - time.monotonic()), over_budget, produced=[str(produced)])

    def drop():
        try:
            for name in os.listdir(stage):                 # UPX's output and anything else it left in the directory this call made
                os.unlink(os.path.join(stage, name))
        except OSError:
            pass
        try:
            os.rmdir(stage)
            STAGES.remove(str(stage))
        except OSError:
            notes.append("the stage directory %s could not be removed" % stage)

    if "not_attempted" in unpack or "launch_failed" in unpack:
        drop()
        finish("partial" if "not_attempted" in unpack else "failed", "upx -d was %s: no derivative exists" % (
            "not attempted, the call's time budget of %d seconds was spent" % seconds if "not_attempted" in unpack else "not started"),
            limits_hit=["time"] if "not_attempted" in unpack else [])
    if unpack["stopped_by_watch"]:
        drop()
        finish("partial", "the unpacked file grew past the output budget of %d bytes and UPX was ended; the partial file was removed" % budget,
               limits_hit=["max_output_bytes"], expected_unpacked_bytes=expected)
    if unpack["timed_out"]:
        drop()
        finish("partial", "upx -d did not finish within the call's time budget and was ended; the partial file was removed", limits_hit=["time"], expected_unpacked_bytes=expected)
    if unpack["exit_code"] != 0:
        drop()
        finish("failed", "upx -d failed (exit %s; UPX's words are in the log): no derivative exists" % unpack["exit_code"])
    if unpack["holders_outside"]:
        drop()
        finish("partial", "a process (pid %s) outside the tool's process group still holds the log or the derivative: a process in a session of its own cannot be ended by this tool, "
                          "and the derivative may still be growing; it was removed" % ", ".join(str(p) for p in unpack["holders_outside"][:5]),
               limits_hit=["process_left_running"], expected_unpacked_bytes=expected)
    if unpack["holders_unknown"]:
        notes.append("the processes that hold the derivative could not be looked for (no /proc here): a process upx left running is found only if a sample saw it")
    steady, why_not = output_settled(produced)
    if not steady:
        drop()
        finish("partial", "%s: the derivative is not whole and was removed; nothing is claimed about its bytes or its hash" % why_not,
               limits_hit=["process_left_running"], expected_unpacked_bytes=expected)
    if unpack["left_behind"]:
        drop()
        finish("partial", "upx -d exited with status 0 and left %d process(es) running (in the tool's process group, or adopted by the tool: a session of its own is no refuge), which the tool ended before the file was read: "
                          "the derivative may be cut short and was removed. A process that is no descendant of the program cannot be found by this tool" % unpack["left_behind"],
               limits_hit=["process_left_behind"], expected_unpacked_bytes=expected)
    # What UPX made, read through a descriptor opened without following a link.
    out_fd, out_st = open_regular(str(produced))
    if out_fd is None:
        drop()
        finish("failed", "upx -d reported success but its output is not a regular file (%s): no derivative exists" % out_st)
    try:
        if out_st.st_size == 0 or out_st.st_size > budget:
            drop()
            finish("failed" if out_st.st_size == 0 else "partial", "the unpacked file is %d bytes: %s" % (out_st.st_size, "empty" if out_st.st_size == 0 else "past the output budget"),
                   limits_hit=[] if out_st.st_size == 0 else ["max_output_bytes"])
        derived_sha, derived_read, derived_whole = sha256_fd(out_fd, deadline + 5)
        if derived_whole and os.fstat(out_fd).st_size != derived_read:
            drop()
            finish("partial", "the derivative grew while it was hashed: a process in a session of its own may still be writing, and this tool cannot end it; the file was removed",
                   limits_hit=["process_left_running"])
        if not derived_whole:
            drop()
            finish("partial", "the call's time budget ran out while hashing the derivative; it was removed", limits_hit=["time"])
        os.fchmod(out_fd, 0o600)
    finally:
        os.close(out_fd)
    # The sample must be the file that was hashed, still: UPX opened it by name.
    again, now = open_regular(path)
    changed = again is None or (now.st_dev, now.st_ino, now.st_size, now.st_mtime_ns) != identity
    if again is not None:
        os.close(again)
    if changed:
        drop()
        finish("failed", "the sample changed (or was replaced) while UPX read it: the derivative was removed, nothing is claimed about it")
    stem = re.sub(r"[^A-Za-z0-9_.-]", "_", os.path.basename(path))[:80] or "sample"
    final = None
    for n in range(1, 1000):
        candidate = "%s.unpacked" % stem if n == 1 else "%s.unpacked-%d" % (stem, n)
        try:
            os.link(produced, directory / candidate)      # fails when the name exists: nothing is replaced
        except FileExistsError:
            continue
        except OSError as exc:
            notes.append("the derivative could not be linked under its final name (%s): it stays at %s" % (describe(exc), produced))
            break
        final = directory / candidate
        LINKED.append(final)
        break
    if final is not None:
        drop()
        where = str(final)
    else:
        where = str(produced)
        STAGES.remove(str(stage))
    if derived_sha == sha:
        notes.append("the derivative has the sample's own SHA-256: UPX unpacked nothing that differs")
    finish("complete", "upx -t accepted the file, upx -d exited 0, and the derivative is a regular file of %d bytes within the budget of %d" % (derived_read, budget),
           derivative={"path": where, "bytes": derived_read, "sha256": derived_sha, "mode": "0600"}, expected_unpacked_bytes=expected)


if __name__ == "__main__":
    try:
        main()
    except SystemExit:
        raise
    except Exception as exc:  # never a traceback and never a clean answer for a failure
        _clean_stages()
        fail("unexpected failure: %s" % (describe(exc) if isinstance(exc, OSError) else "%s: %s" % (type(exc).__name__, exc)))
