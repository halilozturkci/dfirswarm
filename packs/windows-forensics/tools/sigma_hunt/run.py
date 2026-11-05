#!/usr/bin/env python3
"""Run a Sigma ruleset over event logs, with whichever engine the host carries.

Querying by event id answers a question you already knew to ask. A ruleset
tests patterns you did not think of: each rule is a pattern somebody described,
run over the records the engine reads. How many rules there are, how many the
engine loaded and how many it skipped depend on the ruleset you name and on the
engine, and the tool does not count them: the engine's own output says. A result
shows what these rules, in this engine, found in these records.

Two engines do the same job and neither is shipped here:

    Zircolite   Python; loads the records into SQLite and runs the rules as queries.
    Hayabusa    one Rust binary; it also builds a timeline.

Both are invoked as executables, and either one is enough: this tool needs ONE
of them, not both. A comparison of their speed or memory is not claimed here.

The output is normalised to the same shape whichever ran, because an agent
should not have to learn two formats, and because the thing that goes in the
report is not the detection anyway. A rule firing is a hypothesis with a name.
The evidence is the record it matched, which you then read with evtx_query and
cite by its record id and channel.

out_dir is a place the run can write: work/<your id>/hunt (or work/extracted/<id>/..., work/quarantine/<id>/...,
tool-output/<id>/...) in an agent's VM, $OUT in a job; any other is refused with the places that work named.
Every run gets a directory of its own under out_dir (hunt-<UTC time>-<id>), so a
result left by an earlier invocation can never be taken for this one's. The engine's
exit status is judged: a non-zero status with a result file is a PARTIAL run, not a
clean one. The engine's result is read as a stream and its detections normalised into
detections.jsonl, sorted by level and time with a bounded-memory merge sort. A level
the tool does not know is never ranked as the lowest and dropped: such a detection is
kept, counted under `unknown_levels` and shown first. The engines' own level words are
read (Hayabusa writes `crit`, `med` and `info`). A line of the engine's result that
cannot be read is counted and kept whole in a file, never skipped.

Nothing is cut. Every field of a matched record is kept, every rule that fired
is counted, and the engine's own stdout and stderr are kept whole beside its
result. Past `limit` the detections are a page, and all of them, normalised,
are in detections.jsonl in the run directory; each file is named with its path, size
and sha256. The ruleset the caller names is recorded by digest; where the engine's
own bundled rules are used, that is said, and their content is not recorded here.

Neither engine writes beside the run. Each would put its log in the working
directory, which is the run's, read-only in an agent's VM and in a job's
worker: Zircolite its zircolite.log, which --logfile moves into the run directory
(Zircolite has taken -l/--logfile since 2.x, and 4.0, the images' pin, still
does); Hayabusa its ./logs/errorlog-<time>.log, whose place no option names
(-Q only drops it), so Hayabusa runs in the run directory, given every path
absolute, and its error log is kept there.
"""
import datetime
import hashlib
import heapq
import json
import os
import re
import secrets
import shutil
import signal
import subprocess
import sys
import tempfile
from pathlib import Path

PARSER = "sigma_hunt/7"
DEADLINE_SECONDS = 1170           # the manifest allows 1,200: one clock over the probes, the engine, the parse, the sort, the write and the answer
POST_SECONDS = 120                # kept back for what follows the engine (the parse, the sort, the write, the answer)
PARSE_STOPS_AT = 40               # the read of the engine's result stops when this many seconds are left
WRITE_STOPS_AT = 5                # the write of detections.jsonl stops when this many seconds are left
MAX_LIMIT = 10000                 # the largest inline page; the whole result is in the file the answer names
TEMPS = []                        # the sort's temporary files that are not yet merged
HELD = {"deadline": None, "phase": "starting", "command": None}
MAX_TIMEOUT = 1000


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
DEFAULT_TIMEOUT = 900
LEVELS = ["informational", "low", "medium", "high", "critical"]
# The level words the engines write: Zircolite the full ones, Hayabusa the short ones.
LEVEL_RANK = {"informational": 0, "info": 0, "low": 1, "medium": 2, "med": 2, "high": 3, "critical": 4, "crit": 4}
SORT_RUN_BYTES = 64 * 1024 * 1024
JSON_VALUE_CAP = 256 * 1024 * 1024


# Where the run directory is once it exists, so a failure after the engine ran can name it.
STATE = {"run_dir": None}


def fail(message, **extra):
    if STATE["run_dir"] and "run_dir" not in extra:
        extra["run_dir"] = STATE["run_dir"]
    drop_temps()
    print_answer({"error": message, "status": "failed", "status_basis": "the tool stopped with an error and returned no detection (see error)", **extra})
    raise SystemExit(1)


def writable_place(out_dir):
    """Refuse an out_dir that this run cannot write, naming the places that work. In a job only $OUT is writable; in an
    agent's VM the harness maps the agent's own work/<id>/, work/extracted/<id>/, work/quarantine/<id>/ and
    tool-output/<id>/ and nothing else under them (work/hunt, a bare work/ or another agent's directory fail
    with a permission error after the engine has been looked for). With neither a job nor an agent id there is
    no map to hold the path to."""
    root = Path.cwd().resolve()
    dest = (root / out_dir).resolve()
    if os.environ.get("JOB_ID") and os.environ.get("OUT"):
        base = Path(os.environ["OUT"]).resolve()
        if dest == base or base in dest.parents:
            return
        fail("out_dir must be under $OUT in a job: the run directory is read-only there", out_dir=out_dir,
             writable=[os.path.relpath(base, root) if root in base.parents else str(base)])
    agent = os.environ.get("AGENT_ID")
    if not agent:
        return
    safe = re.sub(r"[^A-Za-z0-9_.-]", "_", agent)
    places = [root / "work" / safe, root / "work" / "extracted" / safe, root / "work" / "quarantine" / safe,
              root / "tool-output" / safe]
    if any(dest == p or p in dest.parents for p in places):
        return
    fail("out_dir is not a place this run can write: use a directory under your own work/%s/" % safe, out_dir=out_dir,
         writable=["work/%s/..." % safe, "work/extracted/%s/..." % safe, "work/quarantine/%s/..." % safe,
                   "tool-output/%s/..." % safe])


def resolve_output(out, what="output"):
    """Where `out` really lands, as a path under the run directory; a place
    outside it, the run directory itself, or anything under inputs/ is refused.

    A string check is not enough: `work/../inputs/x`, an absolute path and a
    symlink that points out all name a place the tool must not write, and none
    of them starts with "inputs/". Resolving first and comparing directories
    is what actually holds, and the read-only inputs are the one place
    extracted bytes must never appear -- a later integrity check would report
    the evidence as modified. In a job $OUT is inside the run directory.
    """
    root = Path.cwd().resolve()
    dest = (root / out).resolve() if not Path(out).is_absolute() else Path(out).resolve()
    if dest == root or root not in dest.parents:
        fail("%s must stay inside the run directory" % what, **{what: str(out)})
    inputs = root / "inputs"
    if dest == inputs or inputs in dest.parents:
        fail("%s cannot be under inputs/" % what, **{what: str(out)})
    return str(dest.relative_to(root))


def file_ref(path, rows=None):
    """Name a file the tool wrote or the engine wrote: path, bytes and sha256, streamed."""
    h = hashlib.sha256()
    n = 0
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
            n += len(chunk)
    named = {"path": path, "bytes": n, "sha256": h.hexdigest()}
    if rows is not None:
        named["rows"] = rows
    return named


def engine_logs(engine, run_dir, zircolite_log):
    """The logs the engine wrote in run_dir: Zircolite's one file, Hayabusa's logs/."""
    if engine == "zircolite":
        return [zircolite_log] if os.path.isfile(zircolite_log) else []
    logs = os.path.join(run_dir, "logs")
    if not os.path.isdir(logs):
        return []
    return sorted(os.path.join(logs, name) for name in os.listdir(logs) if os.path.isfile(os.path.join(logs, name)))


def rank(level):
    """The rank of a level word, or None when it is not one the engines write (or there is none)."""
    if level is None:
        return None
    return LEVEL_RANK.get(str(level).strip().lower())


class Malformed:
    """What of an engine's result could not be read, kept whole in a file."""

    def __init__(self, path):
        self.path = path
        self.count = 0
        self.bytes = 0
        self._fh = None

    def add(self, text, where):
        if self._fh is None:
            self._fh = open(self.path, "w", encoding="utf-8", errors="surrogateescape")
        self.count += 1
        data = "%s\t%s\n" % (where, text.replace("\n", "\\n"))
        self._fh.write(data)
        self.bytes += len(data.encode("utf-8", "surrogateescape"))

    def add_stream(self, first, fh, where):
        """Keep `first` and everything still to be read from `fh` as one unreadable item, copied across in chunks:
        the rest of a document that stopped making sense can be as large as the file."""
        if self._fh is None:
            self._fh = open(self.path, "w", encoding="utf-8", errors="surrogateescape")
        self.count += 1

        def put(text):
            self._fh.write(text)
            self.bytes += len(text.encode("utf-8", "surrogateescape"))

        put("%s\t" % where)
        put(first.replace("\n", "\\n"))
        for chunk in iter(lambda: fh.read(1 << 20), ""):
            put(chunk.replace("\n", "\\n"))
        put("\n")

    def close(self):
        if self._fh is not None:
            self._fh.close()
            self._fh = None


def json_values(path, malformed):
    """Yield the JSON values of an engine's result file, as a stream: the elements of a top-level
    array, objects written one after another (pretty-printed or one to a line). A line of a
    line-delimited file that is not JSON is counted and kept in `malformed`, and the next line is read;
    a document that stops making sense is kept whole from that point, copied to the file in chunks (it is
    never held in memory), and ends the read.

    Which of the two it is comes from the first line alone: a line that begins an object and says more than the
    brace (`{"RuleTitle": ...`) is the first of a line-delimited file whether or not it is whole, so a damaged
    first line costs one line; a lone `{`, a `[` and anything else is a document."""
    decoder = json.JSONDecoder()
    with open(path, "r", encoding="utf-8", errors="replace") as fh:
        first = ""
        pos = fh.tell()
        for line in fh:
            if line.strip():
                first = line.strip()
                break
        fh.seek(pos)
        if first.startswith("{") and first != "{":
            for number, line in enumerate(fh, 1):
                text = line.strip()
                if not text:
                    continue
                try:
                    yield json.loads(text)
                except ValueError:
                    malformed.add(text, "line %d" % number)
            return
        buf, eof = "", False
        while True:
            i = 0
            while True:
                while i < len(buf) and buf[i] in " \t\r\n,[]":
                    i += 1
                if i < len(buf):
                    break
                buf, i = "", 0
                if eof:
                    return
                chunk = fh.read(1 << 20)
                if not chunk:
                    eof = True
                else:
                    buf += chunk
            buf = buf[i:]
            try:
                value, end = decoder.raw_decode(buf)
            except ValueError as exc:
                # More of the file can finish a value only when the error is where the text ends (a cut value,
                # a string not yet closed); an error in the middle of what is held is the document's.
                near_end = isinstance(exc, json.JSONDecodeError) and (
                    exc.pos >= len(buf) - 12 or exc.msg.startswith("Unterminated string"))
                if not eof and near_end and len(buf) < JSON_VALUE_CAP:
                    chunk = fh.read(1 << 20)
                    if chunk:
                        buf += chunk
                        continue
                    eof = True
                    continue
                # What is left does not parse: it is kept whole, streamed to the file, and the read ends here.
                malformed.add_stream(buf, fh, "from the value at the start of this text")
                return
            yield value
            buf = buf[end:]


def zircolite_rows(values, malformed):
    """Zircolite writes a list of rules, each with the events that matched it."""
    for rule in values:
        if not isinstance(rule, dict):
            malformed.add(json.dumps(rule, default=str), "not a rule object")
            continue
        title = rule.get("title") or rule.get("rule_title") or "unnamed rule"
        if not isinstance(title, str):
            malformed.add(json.dumps(rule, default=str), "the rule title is not text")
            continue
        level = rule.get("rule_level") or rule.get("level")
        found = rule.get("matches") or []
        if not isinstance(found, list):
            malformed.add(json.dumps(rule, default=str), "matches is not a list")
            continue
        for match in found:
            if not isinstance(match, dict):
                malformed.add(json.dumps(match, default=str), "a match of rule %s is not an object" % json.dumps(title)[:80])
                continue
            yield {
                "rule": title,
                "level": level,
                "rule_id": rule.get("id"),
                "time": match.get("SystemTime") or match.get("UtcTime") or match.get("timestamp"),
                "event_id": match.get("EventID"),
                "channel": match.get("Channel"),
                "computer": match.get("Computer"),
                "record_id": match.get("EventRecordID"),
                "detail": match,
            }


def hayabusa_rows(values, malformed):
    """Hayabusa's JSON timeline is one detection per object, or one per line."""
    for row in values:
        if not isinstance(row, dict):
            malformed.add(json.dumps(row, default=str), "not a detection object")
            continue
        details = row.get("Details")
        title = row.get("RuleTitle") or row.get("RuleFile") or "unnamed rule"
        if not isinstance(title, str):
            malformed.add(json.dumps(row, default=str), "the rule title is not text")
            continue
        yield {
            "rule": title,
            "level": row.get("Level"),
            "rule_id": row.get("RuleID"),
            "time": row.get("Timestamp") or row.get("timestamp"),
            "event_id": row.get("EventID"),
            "channel": row.get("Channel"),
            "computer": row.get("Computer"),
            "record_id": row.get("RecordID"),
            "detail": details if isinstance(details, dict) else {"details": details},
        }


class Sorted:
    """Normalised detections written to a file in the order the answer gives them (unknown
    levels first, then critical down to informational, then by time), with a merge sort whose
    memory is one run of at most SORT_RUN_BYTES."""

    def __init__(self, directory):
        self.directory = directory
        self.runs = []
        self.buffer = []
        self.size = 0
        self.seq = 0

    def add(self, row, level_rank):
        group = 0 if level_rank is None else 1 + (4 - level_rank)
        key = "%d\t%s\t%012d" % (group, str(row.get("time") or "").replace("\t", " ").replace("\n", " "), self.seq)
        self.seq += 1
        line = key + "\t" + json.dumps(row, default=str)          # ASCII: a lone surrogate in a field (a name that is not UTF-8) is escaped, not an encoding error later
        self.buffer.append(line)
        self.size += len(line)
        if self.size >= SORT_RUN_BYTES:
            self._spill()

    def _spill(self):
        self.buffer.sort()
        fd, name = tempfile.mkstemp(prefix=".sort-", dir=self.directory)
        TEMPS.append(name)
        with os.fdopen(fd, "w", encoding="utf-8", errors="surrogateescape") as fh:
            for line in self.buffer:
                fh.write(line + "\n")
        self.runs.append(name)
        self.buffer, self.size = [], 0

    def write(self, destination, keep, stop=None):
        """Write the sorted rows to destination as JSON Lines; return the first `keep` of them, the count and whether `stop()` cut the write."""
        first, count, cut = [], 0, False
        streams = []
        if self.runs:
            if self.buffer:
                self._spill()
            streams = [open(r, "r", encoding="utf-8", errors="surrogateescape") for r in self.runs]
            merged = heapq.merge(*[(l.rstrip("\n") for l in s) for s in streams])
        else:
            self.buffer.sort()
            merged = iter(self.buffer)
        with open(destination, "w", encoding="utf-8", errors="surrogateescape") as out:
            for line in merged:
                if stop is not None and not (count & 4095) and stop():
                    cut = True
                    break
                row_json = line.split("\t", 3)[3]
                out.write(row_json + "\n")
                if count < keep:
                    first.append(json.loads(row_json))
                count += 1
        for s in streams:
            s.close()
        for r in self.runs:
            os.unlink(r)
            if r in TEMPS:
                TEMPS.remove(r)
        return first, count, cut


def ruleset_record(rules, until=None):
    """The ruleset the caller named, by digest: a file by its sha256, a directory by the digest of its
    sorted relative paths and file digests. Without one, the engine's own bundled rules are in use. `until` is the clock's end; a digest it cuts is none, and says so."""
    if not rules:
        return {"source": "the engine's bundled rules", "digest": None,
                "note": "no ruleset was named, so the rules in use are whatever the engine carries; their content is not recorded here"}

    def hashed(path, h):
        with open(path, "rb") as fh:
            for chunk in iter(lambda: fh.read(1 << 20), b""):
                if until is not None and time.monotonic() > until:
                    return False
                h.update(chunk)
        return True

    p = Path(rules)
    if p.is_file():
        h = hashlib.sha256()
        if not hashed(p, h):
            return {"source": str(rules), "kind": "file", "files": 1, "digest": None, "cut_by_clock": True}
        return {"source": str(rules), "kind": "file", "files": 1, "digest": h.hexdigest()}
    if p.is_dir():
        outer = hashlib.sha256()
        files = 0
        for root, dirs, names in os.walk(p):
            dirs.sort()
            if until is not None and time.monotonic() > until:
                return {"source": str(rules), "kind": "directory", "files": files, "digest": None, "cut_by_clock": True}
            for name in sorted(names):
                full = os.path.join(root, name)
                if os.path.islink(full) or not os.path.isfile(full):
                    continue
                h = hashlib.sha256()
                if not hashed(full, h):
                    return {"source": str(rules), "kind": "directory", "files": files, "digest": None, "cut_by_clock": True}
                outer.update(("%s\t%s\n" % (os.path.relpath(full, p), h.hexdigest())).encode("utf-8", "surrogateescape"))
                files += 1
        return {"source": str(rules), "kind": "directory", "files": files, "digest": outer.hexdigest(),
                "digest_of": "sorted relative paths with each regular file's sha256; links are not followed"}
    return {"source": str(rules), "digest": None, "note": "not a file or directory on this host; the engine may resolve it itself"}


def engine_version(binary, budget):
    """The engine's version line, asking at most twice and never longer than `budget` seconds in all."""
    until = time.monotonic() + budget
    for flag in ("--version", "-V"):
        wait = min(15, until - time.monotonic())
        if wait < 1:
            return None
        try:
            p = subprocess.run([binary, flag], stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=wait, stdin=subprocess.DEVNULL)
        except (OSError, subprocess.TimeoutExpired):
            return None
        text = p.stdout.decode("utf-8", "replace").strip().splitlines()
        if p.returncode == 0 and text:
            return text[0].strip()
    return None


def count_evtx(path, until):
    """How many .evtx files lie under `path` (a file counts as one), looked for until the clock `until`; the second value says the look was cut short."""
    if os.path.isfile(path):
        return 1, False
    n = 0
    for _root, _dirs, names in os.walk(path):
        if time.monotonic() > until:
            return n, True
        n += sum(1 for name in names if name.lower().endswith(".evtx"))
    return n, False


NONE_READ = re.compile(rb"(?i)no\s+evtx\s+files?|evtx\s+files?\s*(?:read|found|loaded)?\s*[:=]\s*0\b|total\s+evtx\s+files?\s*[:=]\s*0\b|0\s+evtx\s+files?")


def engine_says_none_read(*paths):
    """Whether the first 64 KiB of the engine's own words say it read no .evtx file."""
    for p in paths:
        try:
            with open(p, "rb") as fh:
                if NONE_READ.search(fh.read(65536)):
                    return True
        except OSError:
            pass
    return False


def print_answer(answer, **dumps_kwargs):
    """Print the answer with the stop signals held back and the last word cleared: a signal at that point gives no second document."""
    try:
        signal.pthread_sigmask(signal.SIG_BLOCK, {signal.SIGTERM, signal.SIGINT, signal.SIGHUP})
    except (AttributeError, ValueError, OSError):
        pass
    STATE["last_word"] = None
    print(json.dumps(answer, **dumps_kwargs))


def drop_temps():
    """Remove the temporary files of the sort that were not yet merged."""
    for name in list(TEMPS):
        try:
            os.unlink(name)
        except OSError:
            pass
    del TEMPS[:]


def last_word(signum):
    """After the PROCESS handler has ended the engine: remove the sort's temporary files and answer with one document."""
    drop_temps()
    print(json.dumps({"error": "stopped by signal %d before the hunt finished" % signum, "status": "interrupted", "signal": signum,
                      "status_basis": "the tool was stopped by signal %d (the engine and what it started were ended, the sort's temporary files removed); nothing it had read is an answer" % signum,
                      "phase": HELD["phase"], "run_dir": STATE["run_dir"], "command": HELD.get("command"),
                      "note": "No statement about detections follows from an interrupted run."}), flush=True)


# Installed as soon as the module has run as far as here, before main() creates anything.
STATE["last_word"] = last_word
install_signal_handlers()


def left():
    return HELD["deadline"] - time.monotonic()


def main():
    HELD["deadline"] = time.monotonic() + DEADLINE_SECONDS
    try:
        args = json.load(sys.stdin)
    except ValueError as exc:
        fail("arguments are not valid JSON", reason=str(exc))
    if not isinstance(args, dict):
        fail("the arguments must be a JSON object")

    path = args.get("path")
    if not isinstance(path, str) or not path:
        fail("path is required: an .evtx file or a directory of them")
    if not os.path.exists(path):
        fail("no such file or directory", path=path)

    out_dir = args.get("out_dir")
    if not isinstance(out_dir, str) or not out_dir:
        fail("out_dir is required: a directory under work/ for the engine's own output")
    out_dir = resolve_output(out_dir, "out_dir")
    writable_place(out_dir)

    min_level = args.get("min_level") or "medium"
    if not isinstance(min_level, str) or min_level.lower() not in LEVELS:
        fail("min_level must be one of %s" % ", ".join(LEVELS))
    min_level = min_level.lower()
    limit = args.get("limit", 200)
    if not isinstance(limit, int) or isinstance(limit, bool) or not 1 <= limit <= MAX_LIMIT:
        fail("limit must be a whole number from 1 to %d (the inline page; the whole result is in the file the answer names)" % MAX_LIMIT)
    timeout = args.get("timeout_seconds", DEFAULT_TIMEOUT)
    if not isinstance(timeout, int) or isinstance(timeout, bool) or timeout < 10:
        fail("timeout_seconds must be an integer of at least 10")
    timeout = min(timeout, MAX_TIMEOUT)             # the tool's own limit is 1,200 s: the engine stops before it, and its result is read after
    rules_arg = args.get("rules")
    if rules_arg is not None and not isinstance(rules_arg, str):
        fail("rules must be a string: the path of a ruleset (a file or a directory)")

    wanted = args.get("engine") or "auto"
    if not isinstance(wanted, str) or wanted.lower() not in ("auto", "zircolite", "hayabusa"):
        fail("engine must be auto, zircolite or hayabusa")
    wanted = wanted.lower()
    # Every detection row carries the whole matched record, so the files this tool writes are secret output: the manifest makes every job of it one,
    # and a job that was not run as such is refused here, before anything is created.
    if os.environ.get("JOB_ID") and os.environ.get("SECRET_OUTPUT") != "1":
        fail("sigma_hunt is refused in a job that was not run as secret output: its detections carry the whole matched records, and its files would be sealed as ordinary "
             "output. Run it as job_run(tool: \"sigma_hunt\", ...), whose manifest makes every job of this tool secret output. Nothing was created.")

    zircolite = shutil.which("zircolite") or shutil.which("zircolite.py")
    hayabusa = shutil.which("hayabusa")
    engine = None
    if wanted in ("auto", "zircolite") and zircolite:
        engine, binary = "zircolite", zircolite
    elif wanted in ("auto", "hayabusa") and hayabusa:
        engine, binary = "hayabusa", hayabusa
    if engine is None:
        fail("no Sigma engine on PATH",
             looked_for=["zircolite", "hayabusa"],
             install={"zircolite": "https://github.com/wagga40/Zircolite/releases",
                      "hayabusa": "https://github.com/Yamato-Security/hayabusa/releases"},
             note="Either engine is enough. Both are invoked as executables.")

    # A directory of this run's own: whatever an earlier invocation left in out_dir is never read as this one's.
    stamp = datetime.datetime.now(datetime.timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    run_dir = resolve_output(os.path.join(out_dir, "hunt-%s-%s" % (stamp, secrets.token_hex(3))), "out_dir")
    try:
        os.makedirs(out_dir, exist_ok=True)
        os.makedirs(run_dir, exist_ok=False)
    except OSError as exc:
        fail("the run directory cannot be made under out_dir: %s" % exc, out_dir=out_dir, status="failed")
    STATE["run_dir"] = run_dir
    result = resolve_output(os.path.join(run_dir, "%s.json" % engine), "out_dir")
    zircolite_log = resolve_output(os.path.join(run_dir, "zircolite.log"), "out_dir")

    if engine == "zircolite":
        # No --noexternal: Zircolite 3 removed it (it reads EVTX through its
        # Python bindings only) and refuses the flag; 2.x without it uses its
        # own bundled evtx_dump. --logfile: its log in the run directory, not in the
        # working directory (the run's, read-only in a VM and in a job).
        argv = [binary, "--evtx", path, "--outfile", result, "--logfile", zircolite_log]
        if rules_arg:
            argv += ["--ruleset", rules_arg]
        cwd = None
    else:
        # Hayabusa saves its error log under ./logs/ and no option moves it:
        # it runs in the run directory, so every path it is given is absolute, and a
        # link left there as logs is followed to where it lands first.
        resolve_output(os.path.join(run_dir, "logs"), "out_dir")
        argv = [binary, "json-timeline", "-d" if os.path.isdir(path) else "-f", os.path.abspath(path),
                "-o", os.path.abspath(result), "-w", "-q"]
        if rules_arg:
            argv += ["-r", os.path.abspath(rules_arg) if os.path.exists(rules_arg) else rules_arg]
        cwd = os.path.abspath(run_dir)
    HELD["command"] = " ".join(argv)

    # One clock over the whole run: the probes, the count of .evtx files, the digest of the ruleset, the engine, then the parse, the sort and the write,
    # for which POST_SECONDS are kept back. A phase the clock cuts ends the run partial, and says which.
    cut = []
    HELD["phase"] = "asking the engine for its version"
    version = engine_version(binary, max(0.0, min(30.0, left() - POST_SECONDS - 10)))
    HELD["phase"] = "counting the .evtx files"
    evtx_files, evtx_cut = count_evtx(path, time.monotonic() + max(0.0, min(30.0, left() - POST_SECONDS - 10)))
    if evtx_cut:
        cut.append("the count of .evtx files under the path was cut by the clock")
    HELD["phase"] = "recording the ruleset"
    ruleset = ruleset_record(rules_arg, time.monotonic() + max(0.0, min(60.0, left() - POST_SECONDS - 10)))
    if ruleset.get("cut_by_clock"):
        cut.append("the digest of the ruleset was cut by the clock")

    # The engine's own words, whole, beside its result: they used to be
    # dropped when it succeeded and cut to their last few hundred characters
    # when it did not. They are streamed to files, never held in memory.
    stdout_path = resolve_output(os.path.join(run_dir, "%s.stdout" % engine), "out_dir")
    stderr_path = resolve_output(os.path.join(run_dir, "%s.stderr" % engine), "out_dir")
    engine_seconds = min(timeout, int(left() - POST_SECONDS))
    if engine_seconds < 10:
        fail("the tool's own clock (%d s) left the engine no time to run: nothing was hunted" % DEADLINE_SECONDS, run_dir=run_dir, command=" ".join(argv))
    HELD["phase"] = "the engine is running"
    with open(stdout_path, "wb") as so, open(stderr_path, "wb") as se:
        try:
            proc = spawn(argv, stdout=so, stderr=se, cwd=cwd)
        except OSError as exc:
            fail("%s could not be started: %s" % (engine, exc), command=" ".join(argv), status="failed")
        rc, timed_out = wait_for(proc, engine_seconds)
    said = {"stdout": file_ref(stdout_path), "stderr": file_ref(stderr_path)}

    if not os.path.isfile(result):
        if timed_out:
            fail("%s did not finish in time" % engine, after_seconds=engine_seconds, command=" ".join(argv), run_dir=run_dir, **said,
                 engine_logs=engine_logs(engine, run_dir, zircolite_log))
        fail("%s wrote no result file" % engine, exit_code=rc, run_dir=run_dir,
             command=" ".join(argv), **said, engine_logs=engine_logs(engine, run_dir, zircolite_log),
             note="Engine command lines change between versions; the exact invocation is above "
                  "so it can be corrected by hand and re-run. Its whole stdout and stderr are "
                  "the files named here.")

    HELD["phase"] = "reading the engine's result"
    malformed = Malformed(os.path.join(run_dir, "%s-malformed.txt" % engine))
    floor = LEVEL_RANK[min_level]
    ordered = Sorted(run_dir)
    by_rule = {}
    read = below = 0
    unknown_levels = {}
    parse_cut = False
    try:
        values = json_values(result, malformed)
        rows = zircolite_rows(values, malformed) if engine == "zircolite" else hayabusa_rows(values, malformed)
        for row in rows:
            if not (read & 1023) and left() < PARSE_STOPS_AT:
                parse_cut = True
                break
            read += 1
            r = rank(row.get("level"))
            if r is None:
                key = "(no level)" if row.get("level") is None else str(row.get("level"))
                unknown_levels[key] = unknown_levels.get(key, 0) + 1
            elif r < floor:
                below += 1
                continue
            row["level_rank"] = r
            by_rule[row["rule"]] = by_rule.get(row["rule"], 0) + 1
            ordered.add(row, r)
    except OSError as exc:
        malformed.close()
        fail("%s wrote a result this tool could not read" % engine, result=result, reason=str(exc))
    malformed.close()

    HELD["phase"] = "sorting and writing the detections"
    detections_path = resolve_output(os.path.join(run_dir, "detections.jsonl"), "out_dir")
    shown, kept_count, write_cut = ordered.write(detections_path, limit, lambda: left() < WRITE_STOPS_AT)
    all_detections = file_ref(detections_path, rows=kept_count)
    fired = sorted(({"rule": r, "count": c} for r, c in by_rule.items()), key=lambda x: (-x["count"], str(x["rule"])))
    fired_file = None
    if len(fired) > limit:
        fired_path = resolve_output(os.path.join(run_dir, "rules-fired.jsonl"), "out_dir")
        with open(fired_path, "w", encoding="utf-8") as fh:
            for item in fired:
                fh.write(json.dumps(item) + "\n")
        fired_file = file_ref(fired_path, rows=len(fired))
    if parse_cut:
        cut.append("the tool's own clock ran out while the engine's result was read: %d detections were read, the rest were not" % read)
    if write_cut:
        cut.append("the tool's own clock ran out while the detections were sorted and written: detections.jsonl holds %d of them" % kept_count)

    reasons = []
    if timed_out:
        reasons.append("the engine was stopped by its time limit (%d s)" % engine_seconds)
    elif rc != 0:
        reasons.append("the engine exited with status %s" % rc)
    if malformed.count:
        reasons.append("%d line(s) of its result could not be read (malformed_file)" % malformed.count)
    if evtx_files == 0 and not evtx_cut:
        reasons.append("no .evtx file lies under the path, so no record was read")
    elif engine_says_none_read(stdout_path, stderr_path):
        reasons.append("the engine's own output says it read no .evtx file")
    if read == 0 and below == 0 and not malformed.count:
        # Nothing was read. An engine that found nothing writes an empty list; an empty file, a lone object or brackets with nothing in them is not that.
        try:
            with open(result, "rb") as rf:
                head = re.sub(rb"\s+", b"", rf.read(4096))
            size_read = os.path.getsize(result)
        except OSError:
            head, size_read = b"?", -1
        if head != b"[]":
            reasons.append("no detection was read from the engine's result file (%d bytes; it is empty, or not a list of detections): zero detections here is not a statement that no rule matched" % size_read)
    reasons += cut
    # The result file, the engine's own stdout and stderr and its log are what the engine wrote, and the detections are read from the first: a process it left behind may still have written to any of them.
    # settle() ended such a process before they were read, so they are stable but may be short; where one cannot be ruled out (not Linux, or PR_SET_CHILD_SUBREAPER refused) they cannot be shown to be final.
    verdict = process_verdict()
    if verdict["left_behind"]:
        reasons.append("the engine left %d process(es) running after it ended (in the tool's process group or in a session of its own); they were ended before its result file was read, so what they would "
                       "still have written is missing and the result may be short" % verdict["left_behind"])
    for why in verdict["unproven"]:
        reasons.append(why + ": the engine's result file cannot be shown to be final")
    complete = not reasons
    answer = {
        "parser": PARSER,
        "status": "complete" if complete else "partial",
        "status_basis": "; ".join(reasons) if reasons else "the engine exited 0, its whole result was read and sorted, no line of it was unreadable, and %d .evtx file(s) lie under the path" % evtx_files,
        "complete": complete,
        "path": path,
        "evtx_files_under_path": evtx_files,
        "engine": engine,
        "engine_version": version,
        "ruleset": ruleset,
        "exit_code": rc,
        "timed_out": timed_out,
        "run_dir": run_dir,
        "command": " ".join(argv),
        "result_file": result,
        "detections": shown,
        "detection_count": kept_count,
        "returned": len(shown),
        "truncated": kept_count > limit,
        "all_detections": all_detections,
        "engine_detections_read": read,
        "below_min_level": below,
        "min_level": min_level,
        "unknown_levels": unknown_levels,
        "malformed_lines": malformed.count,
        "malformed_file": file_ref(malformed.path) if malformed.count else None,
        "rules_that_fired": fired[:limit],
        "rules_fired": len(by_rule),
        "rules_fired_file": fired_file,
        "engine_stdout": said["stdout"],
        "engine_stderr": said["stderr"],
        "engine_logs": engine_logs(engine, run_dir, zircolite_log),
        "note": "A rule firing is a hypothesis with a name, not a finding. Take its record id and "
                "channel to evtx_query, read the record, and cite the record. Community rulesets "
                "are tuned for live estates and produce false positives on a forensic image: an "
                "administrator doing their job trips a dozen of them. A detection whose level this tool does not "
                "know is kept and counted under unknown_levels, never dropped by min_level. "
                + ("" if complete else "The run is PARTIAL: see status_basis; the detections are what its result file held."),
    }
    process_apply(answer)             # program_group: what settle() ended and why the absence of a leftover is unproven (a complete answer is already partial above)
    print_answer(answer, indent=2)


if __name__ == "__main__":
    try:
        main()
    except SystemExit:
        raise
    except OSError as exc:
        fail("a file could not be read or written: %s" % exc, status="failed")
    except Exception as exc:                                  # whatever hostile input does, the answer is JSON
        drop_temps()
        print_answer({"error": "the hunt failed", "status": "failed", "status_basis": "the tool stopped with an unexpected error",
                      "run_dir": STATE["run_dir"], "reason": "%s: %s" % (type(exc).__name__, exc)})
        sys.exit(1)
