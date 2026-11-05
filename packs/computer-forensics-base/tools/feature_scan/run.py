#!/usr/bin/env python3
"""Run bulk_extractor and say what it wrote, instead of leaving a directory.

bulk_extractor reads the bytes and ignores the file system entirely, which is
why it finds an address in a deleted mail store, a URL in a pagefile and a card
number in unallocated space when nothing in the listing points at any of them.
That is also its weakness: it returns everything, and a directory of feature
files with a million lines is not an answer.

So this returns the shape: every file bulk_extractor wrote, what kind it is
(feature file, histogram, run report, alerts, a pcap, other), how many lines each
feature file holds, how many distinct values (a lower bound when there are more
than the cap), and the offset of the first. It returns NO feature value inline: a
feature file holds addresses, card numbers, account names and passwords the
evidence held. The values are in the feature files bulk_extractor wrote, which
are sealed with the job, so run the job with `secret_output: true`. With
`write_values: true`, in a job, the most frequent values of each feature file are
also written to a 0600 file under $OUT, and the answer names it. That file is not the only
place values are: bulk_extractor's own files in out_dir are unfiltered (alerts.txt can hold a whole
recovery key), so out_dir is made 0700 and its files 0600 once the child ends, and the answer says
`out_dir_contains_secret_values` and which kinds hold them.

A feature file is offset, feature, context, tab-separated; the offset is the
whole provenance, there is no path. A histogram file (`*_histogram.txt`, whose lines
are `n=<count>` and a feature) is another schema and is counted apart. The child's
exit code, stdout and stderr are returned and kept in files: a run that exited
nonzero is partial or failed, not clean.
"""
import collections
import errno
import hashlib
import json
import os
import re
import shutil
import signal
import stat
import subprocess
import sys
import tempfile
import time
from pathlib import Path

TOOL = {"name": "feature_scan", "version": 16}
STARTED = time.monotonic()
DEFAULT_TIMEOUT = 900
TIMEOUT_MAX = 1000                # the tool's own limit is 1200 seconds: the counting of what bulk_extractor wrote needs the rest
DISTINCT_CAP = 200_000            # distinct values remembered per feature file; past it the count is a lower bound
INVENTORY_SHOWN = 200
FEATURES_SHOWN = 200              # feature files and histograms listed in the answer (with their count); out_dir holds them all
DIR_ENTRIES_MAX = 100_000         # entries of one directory of out_dir looked at
LINE_HEAD = 1 << 20               # characters of a line read at a time; a longer line is read past on the clock
COUNT_SECONDS = 1150              # the counting of what bulk_extractor wrote ends here, 50 seconds below the manifest's 1,200
LOCK_SECONDS = 1180               # and restricting the modes of out_dir ends here
# Written by bulk_extractor beside the features; they describe the run, not the evidence.
RUN_FILES = {"report.xml": "run report", "alerts.txt": "alerts the run raised"}
# The scanners bulk_extractor 2.x ships. The ntfs* and win* ones carve records, not
# strings: an $MFT entry, an INDX slack name, a USN record, a prefetch or link file,
# recovered from bytes with no file system around them.
SCANNERS = ["accts", "aes", "base16", "base64", "elf", "email", "evtx", "exif", "facebook",
            "find", "gps", "gzip", "hiberfile", "httplogs", "json", "kml_carved", "msxml",
            "net", "ntfsindx", "ntfslogfile", "ntfsmft", "ntfsusn", "outlook", "pdf", "rar",
            "rtti", "sqlite", "utmp", "vcard_carved", "vin", "windirs", "winlnk", "winpe",
            "winprefetch", "wordlist", "xor", "zip"]
NAME = re.compile(r"^[A-Za-z0-9_]{1,64}$")


def describe(exc):
    code = errno.errorcode.get(exc.errno, "") if getattr(exc, "errno", None) else ""
    return "%s%s: %s" % (type(exc).__name__, " " + code if code else "", getattr(exc, "strerror", None) or str(exc))


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

import os as _os
import sys as _sys
import threading as _threading

# ---- the one protected printer of an answer (outside the shared block) ------------------------------------------------------------
# The stop signals are held while the answer is written, so that a signal cannot cut the document. A reader that stops taking it (a full
# pipe) would make that tool unkillable by SIGTERM: the held write is therefore bounded. If a stop signal is waiting when
# HELD_WRITE_SECONDS have passed, the tool says so on stderr and ends with 128 plus that signal; nothing is claimed about the answer.
HELD_WRITE_SECONDS = int(_os.environ.get("TOOL_HELD_WRITE_SECONDS") or 30)       # the environment variable is for the tests
_STOPS = (signal.SIGTERM, signal.SIGINT, signal.SIGHUP)


def _unstick():
    try:
        waiting = signal.sigpending()
    except (AttributeError, OSError):
        waiting = set()
    held = [s for s in _STOPS if s in waiting]
    if held:
        try:
            _os.write(2, ("the answer could not be written in %d seconds (the reader is not taking it); ended by the stop signal that was held\n" % HELD_WRITE_SECONDS).encode())
        except OSError:
            pass
        _os._exit(128 + int(held[0]))
    again = _threading.Timer(1.0, _unstick)
    again.daemon = True
    again.start()


ERROR_FLAGS = ("all_results_error", "all_matches_error", "receipt_error", "receipts_error", "rows_file_error", "rows_error", "invalid_lines_file_error",
               "write_error", "values_error")


def _flagged(node, depth=0):
    """The first error flag found in an answer (top level, and two levels of dicts below it), or None."""
    if not isinstance(node, dict) or depth > 2:
        return None
    for key in ERROR_FLAGS:
        if node.get(key):
            return key
    for value in node.values():
        found = _flagged(value, depth + 1)
        if found:
            return found
    return None


def _reconcile(answer):
    """status, complete and ok are one fact: an error flag in the answer (a file that should hold the rest could not be written) is not a
    complete answer, and a complete or ok that survives a partial or failed status is a wrong claim. Said once, here, for every answer."""
    if not isinstance(answer, dict):
        return
    flag = _flagged(answer)
    if flag and answer.get("status") == "complete":
        answer["status"] = "partial"
        basis = answer.get("status_basis")
        answer["status_basis"] = ("%s; but %s says part of what was asked for could not be kept" % (basis, flag)) if basis else "%s says part of what was asked for could not be kept" % flag
    if answer.get("status") in ("partial", "failed") or flag:
        if answer.get("complete") is True:
            answer["complete"] = False
    if answer.get("status") == "failed" and answer.get("ok") is True:
        answer["ok"] = False


# BEGIN SHARED TEMPS
# One lifecycle for the hidden temporary files of a run. A file is made by temp_create (or its name is registered with temp_hold before it is
# made), it is registered before anything else is done with it, and it stays registered until temp_done says it was renamed into place. What is
# still registered when the run ends is removed: by atexit on a normal end or any exception, by drop_temporaries in the last-resort handler, and
# by the stop signal's own cleanup, which removes the _tmp of every object in PAGES (a registered name is one such object).
import atexit
import tempfile

if "PAGES" not in globals():
    PAGES = []                 # objects with a hidden temporary file (_tmp) that a stop removes


class _HeldTemp:
    def __init__(self, name):
        self._tmp = name


def temp_hold(name):
    """Register a temporary file that is about to be made (or has been): it is removed on every way out unless temp_done is called."""
    held = _HeldTemp(os.fspath(name))
    PAGES.append(held)
    return held._tmp


def temp_create(directory, prefix, suffix=""):
    """tempfile.mkstemp with the new name registered at once: (fd, name)."""
    fd, name = tempfile.mkstemp(dir=os.fspath(directory), prefix=prefix, suffix=suffix)
    temp_hold(name)
    return fd, name


def temp_done(name):
    """The file was renamed into place (or is kept on purpose): it is no longer a temporary."""
    name = os.fspath(name)
    PAGES[:] = [p for p in PAGES if not (isinstance(p, _HeldTemp) and p._tmp == name)]


def temp_drop(name):
    """Remove one temporary now; False when it could not be removed (it stays registered, and the end of the run tries again)."""
    try:
        os.unlink(name)
    except FileNotFoundError:
        pass
    except OSError:
        return False
    temp_done(name)
    return True


def temp_replace(tmp, dest):
    os.replace(tmp, dest)
    temp_done(tmp)


def drop_temporaries():
    """Remove every temporary still registered (the pages being written and the held names); the names that could not be removed come back."""
    left = []
    for page in list(PAGES):
        tmp = None
        try:
            tmp = getattr(page, "_tmp", None)
            if tmp is not None:
                os.unlink(tmp)
        except FileNotFoundError:
            pass
        except Exception:   # noqa: BLE001 - every one is tried
            left.append(str(tmp))
    return left


atexit.register(drop_temporaries)
# END SHARED TEMPS


def _guarded_write(write):
    try:
        before = signal.pthread_sigmask(signal.SIG_BLOCK, set(_STOPS))      # before the timer thread exists, so that the thread holds them too
    except (AttributeError, ValueError, OSError):
        before = None
    watch = _threading.Timer(HELD_WRITE_SECONDS, _unstick)
    watch.daemon = True
    watch.start()
    try:
        write()
        _sys.stdout.flush()
    except BrokenPipeError:                       # the reader is gone: there is nobody to tell
        _os._exit(1)
    watch.cancel()
    if before is not None:
        # The document is whole. A stop that came while it was written is delivered now; the last word was cleared, so it ends the tool
        # (128 plus the signal) with nothing more on stdout. The mask is also what an in-process caller (a test) had before.
        signal.pthread_sigmask(signal.SIG_SETMASK, before)


def print_answer(answer, **dumps_kwargs):
    """Print the answer with the stop signals held back and the last word cleared (a signal in the middle of the write would cut the
    document, and the last word would add a second one), on the bounded write above."""
    STATE["last_word"] = None
    _reconcile(answer)
    _guarded_write(lambda: print(json.dumps(answer, **dumps_kwargs)))


def _unexpected_tool(kind, value, _tb):
    """Last resort: an error nobody foresaw is an answer too. The hidden temporaries are removed first (a name that cannot be removed is said in the
    answer), then one JSON document with the class and, for a file-system error, its reason (a message can quote a name from the evidence), and
    exit 1; what was written before it is not claimed. A stop signal that arrives while this runs is held with the answer's write and is answered by
    this document and exit 1, not by 128 + the signal."""
    try:
        left = drop_temporaries()
        reason = getattr(value, "strerror", None) if issubclass(kind, OSError) else None
        said = ("a path or file could not be used: %s" % (reason or kind.__name__)) if issubclass(kind, (OSError, ValueError)) else "internal error: %s" % kind.__name__
        answer = {"tool": globals().get("TOOL"), "status": "failed", "error": said,
                  "status_basis": "the tool stopped on an error it did not foresee (%s); what it had written before is not claimed" % kind.__name__}
        if left:
            answer["temporaries_left"] = left[:10]
            answer["status_basis"] += "; hidden temporary files that could not be removed are listed in temporaries_left"
        print_answer(answer)
    except BaseException:       # noqa: BLE001 - nothing may stop the exit
        pass
    os._exit(1)


sys.excepthook = _unexpected_tool


def _early_last_word(signum):
    """Until main() has its own: a stop before the arguments are read gives one document, `failed` and `interrupted`, and depends on nothing
    defined later."""
    sys.stdout.write(json.dumps({"ok": False, "tool": TOOL, "status": "failed", "interrupted": True, "signal": signum,
                                 "status_basis": "the tool was stopped by signal %d before it had started bulk_extractor, so it did nothing" % signum}) + "\n")
    sys.stdout.flush()


STATE["last_word"] = _early_last_word
install_signal_handlers()


class SecretValuesRefused(Exception):
    pass


class SecretValues:
    """Where a value goes when, and only when, the caller asked for it.

    The reference implementation of the secret-safe output pattern: copy this
    class unchanged into a tool that has to produce a secret, and call `add`
    once per finding with the finding's id, its locator and the value. With
    `enabled` false it writes nothing and `summary()` says so.
    """

    NAME = "feature-scan-values.jsonl"

    def __init__(self, enabled: bool):
        self.enabled = enabled
        self.written = 0
        self._fh = None
        self.write_error = None          # why the values file stopped growing (a full disk, a file-size limit)
        self.job = os.environ.get("JOB_ID") or ""
        self.out = os.environ.get("OUT") or ""
        self.path = None
        self.shown = None
        if not enabled:
            return
        if not (self.job and self.out):
            raise SecretValuesRefused(
                "write_values is refused outside a job: a value written here would be an ordinary "
                "file, not a sealed secret output. Run this as job_run tool=feature_scan with "
                "secret_output: true, and ask again there. Nothing was written."
            )
        if os.environ.get("SECRET_OUTPUT") != "1":
            raise SecretValuesRefused(
                "write_values is refused in a job that was not run as secret output: its files would be sealed as ordinary "
                "output. The harness sets SECRET_OUTPUT=1 for a secret job's process and it is not set here. Run it as "
                "job_run(tool: \"feature_scan\", args: {...}), whose manifest makes every job of this tool secret output, or give "
                "a command job secret_output: true. Nothing was written."
            )
        self.path = Path(self.out) / self.NAME
        self.shown = "store/jobs/%s/out/%s" % (re.sub(r"[^A-Za-z0-9_.-]", "_", self.job), self.NAME)
        # Created now, before anything is scanned: a file or a link already at that name is
        # refused by name at once (O_EXCL does not follow a link, a dangling one included),
        # instead of failing, or writing through it, after the scan. With nothing found it
        # stays as an empty file, mode 0600, and the answer says written: 0.
        try:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            fd = os.open(str(self.path), os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o600)
        except FileExistsError:
            raise SecretValuesRefused("the values file already exists: %s" % self.path)
        except OSError as exc:
            raise SecretValuesRefused("the values file could not be created: %s (%s)" % (self.path, describe(exc)))
        self._fh = os.fdopen(fd, "w", encoding="utf-8")

    def add(self, finding_id: str, locator: dict, value: str) -> None:
        if not self.enabled or self.write_error is not None:
            return
        try:
            self._fh.write(json.dumps({"finding_id": finding_id, **locator, "value": value}, ensure_ascii=True) + "\n")   # a path with bytes that are not UTF-8 is an escape, not an encoding error
        except OSError as exc:
            self.write_error = getattr(exc, "strerror", None) or exc.__class__.__name__      # the file is a prefix: what it holds is whole lines up to here
            return
        self.written += 1

    def close(self) -> None:
        if self._fh is not None:
            try:
                self._fh.flush()
                os.fsync(self._fh.fileno())
                self._fh.close()
            except OSError as exc:
                self.write_error = self.write_error or getattr(exc, "strerror", None) or exc.__class__.__name__
            self._fh = None

    def summary(self) -> dict:
        return {
            "requested": self.enabled,
            "written": self.written,
            "values_file": self.shown if self.enabled else None,
            "contains_secret_values": self.written > 0,
            "write_error": self.write_error,
            "format": "JSON Lines, mode 0600: finding_id, feature_file, count (occurrences), value (a feature value as bulk_extractor wrote it)" if self.enabled else None,
        }


def fail(message, **extra):
    forget_temporaries()                      # the hidden files beside out_dir go on every way out
    print_answer({"error": message, "status": "failed", "status_basis": "the tool stopped with an error: %s" % message, "tool": TOOL, **extra})
    raise SystemExit(1)


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


class OutOfTime(Exception):
    pass


def walk_entries(root, deadline, seen):
    """(directory, sorted names of its files, sorted names of its directories) for `root` and everything under it, one directory at a time,
    the clock read for every entry. A directory of more than DIR_ENTRIES_MAX entries gives its first DIR_ENTRIES_MAX (and `seen` says so);
    a directory that cannot be listed is named in seen["unlisted"]. Raises OutOfTime."""
    stack = [root]
    while stack:
        here = stack.pop()
        files, dirs = [], []
        try:
            scan = os.scandir(here)
        except OSError as exc:
            seen.setdefault("unlisted", []).append("%s: %s" % (here, exc.strerror or exc))
            continue
        with scan:
            for entry in scan:
                seen["entries"] = seen.get("entries", 0) + 1
                if time.monotonic() > deadline:
                    raise OutOfTime()
                if len(files) + len(dirs) >= DIR_ENTRIES_MAX:
                    seen["cut"] = seen.get("cut", 0) + 1
                    continue
                try:
                    (dirs if entry.is_dir(follow_symlinks=False) else files).append(entry.name)
                except OSError:
                    files.append(entry.name)
        files.sort()
        dirs.sort()
        yield here, files, dirs
        stack.extend(os.path.join(here, d) for d in reversed(dirs))


def out_dir_full(out_dir, said):
    """A sentence when the disk or quota under out_dir refused a write (bulk_extractor says so on stderr and still exits 0, or a probe write of
    64 KiB beside its files fails), else None. A file system that is full when the run ends is not a proof that a file was cut, and it is not
    proof that none was."""
    low = said.lower()
    for phrase in ("no space left on device", "disk quota exceeded", "file too large"):
        if phrase in low:
            return "its stderr says '%s'" % phrase
    probe = os.path.join(out_dir, ".feature_scan.probe")
    temp_hold(probe)                 # registered before the file is made: whatever stops this, it is removed
    note = None
    try:
        fd = os.open(probe, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        try:
            if os.write(fd, b"\x00" * 65536) != 65536:
                raise OSError(28, "No space left on device")
            os.fsync(fd)
        finally:
            os.close(fd)
    except OSError as exc:
        note = "a probe write of 64 KiB beside its files failed (%s)" % (exc.strerror or exc)
    if not temp_drop(probe):
        note = (note + "; " if note else "") + "the probe file %s could not be removed" % probe
    return note


def lock_down(root, deadline):
    """bulk_extractor writes what it found, unfiltered, with the umask's modes: a feature file, a histogram and
    alerts.txt hold the values themselves (addresses, card numbers, a whole recovery key). Once the child has ended the
    directory is the owner's alone (0700) and its files are 0600. Returns what could not be changed, and what the clock left."""
    failed = []
    seen = {}
    try:
        for dirpath, names, _dirs in walk_entries(root, deadline, seen):
            try:
                os.chmod(dirpath, 0o700)
            except OSError as exc:
                failed.append("%s: %s" % (dirpath, exc.strerror or exc))
            for name in names:
                full = os.path.join(dirpath, name)
                if os.path.islink(full):
                    continue
                try:
                    os.chmod(full, 0o600)
                except OSError as exc:
                    failed.append("%s: %s" % (full, exc.strerror or exc))
    except OutOfTime:
        failed.append("the clock ran out after %d entries: the modes of the rest were not restricted" % seen.get("entries", 0))
    failed.extend("a directory could not be listed (%s)" % u for u in seen.get("unlisted", []))
    if seen.get("cut"):
        failed.append("%d entries beyond the first %d of a directory were not looked at: their modes were not restricted" % (seen["cut"], DIR_ENTRIES_MAX))
    return failed


def classify(name, first_line):
    if name in RUN_FILES:
        return "run report" if name == "report.xml" else "alerts"
    if name.endswith(".pcap") or name.endswith(".pcapng"):
        return "pcap"
    if name.endswith(".txt"):
        if name.endswith("_histogram.txt") or (first_line is not None and re.match(r"n=\d+\t", first_line)):
            return "histogram"
        return "features"
    return "other"


def lines_of(fh, deadline, progress):
    """The head (at most LINE_HEAD characters) of each line of a text file, read in blocks of at most LINE_HEAD with the clock read before
    each, so one very long line cannot hold the run: the rest of a longer line is read past, counted in progress["long_lines"], and not kept.
    progress["bytes"] counts what was read. Raises OutOfTime."""
    while True:
        if time.monotonic() > deadline:
            raise OutOfTime()
        chunk = fh.readline(LINE_HEAD)
        if not chunk:
            return
        progress["bytes"] += len(chunk)
        head = chunk
        if not chunk.endswith("\n") and len(chunk) == LINE_HEAD:
            progress["long_lines"] += 1
            while True:
                if time.monotonic() > deadline:
                    raise OutOfTime()
                chunk = fh.readline(LINE_HEAD)
                if not chunk:
                    break
                progress["bytes"] += len(chunk)
                if chunk.endswith("\n") or len(chunk) < LINE_HEAD:
                    break
        yield head


def open_regular(path):
    """A text file opened without blocking and checked on the descriptor to be a regular file: a pipe put where a file was cannot hold the run."""
    fd = os.open(path, os.O_RDONLY | getattr(os, "O_NONBLOCK", 0) | getattr(os, "O_NOFOLLOW", 0))
    try:
        if not stat.S_ISREG(os.fstat(fd).st_mode):
            raise OSError(errno.ESPIPE, "not a regular file")
        return os.fdopen(fd, "r", encoding="utf-8", errors="replace")
    except BaseException:
        os.close(fd)
        raise


def first_content_line(path, deadline):
    try:
        with open_regular(path) as fh:
            for line in lines_of(fh, deadline, {"bytes": 0, "long_lines": 0}):
                if line.strip() and not line.startswith("#"):
                    return line
    except (OSError, OutOfTime):
        pass
    return None


def summarise(path, deadline=None, cap=DISTINCT_CAP):
    """Feature files are TSV: offset, feature, context. Blank and # lines are headers.
    Returns counts only; the values are tallied to count and rank them and are not returned. When the clock runs out the file is counted as
    far as it was read, and the stats say so (not_counted: the bytes read, of the bytes there are)."""
    deadline = float("inf") if deadline is None else deadline
    counts = collections.Counter()
    lines = uncounted = 0
    first_offset = None
    malformed = 0
    progress = {"bytes": 0, "long_lines": 0}
    out_of_time = False
    with open_regular(path) as fh:
        try:
            for line in lines_of(fh, deadline, progress):
                if not line.strip() or line.startswith("#"):
                    continue
                lines += 1
                parts = line.rstrip("\n").split("\t")
                if len(parts) < 2:
                    malformed += 1
                    continue
                if first_offset is None:
                    first_offset = parts[0]
                key = parts[1]
                if key in counts or len(counts) < cap:
                    counts[key] += 1
                else:
                    uncounted += 1
        except OutOfTime:
            out_of_time = True
    stats = {"lines": lines, "distinct": len(counts), "distinct_capped": uncounted > 0, "occurrences_not_tallied": uncounted,
             "first_offset": first_offset, "malformed_lines": malformed}
    if progress["long_lines"]:
        stats["lines_longer_than_a_block"] = progress["long_lines"]
    if out_of_time:
        stats["not_counted"] = "the clock ran out after %d bytes of this file were read: lines, distinct and first_offset are of that part, and are lower bounds" % progress["bytes"]
    return stats, counts


def count_lines(path, deadline):
    """(content lines, None) of a histogram file, or (the lines counted so far, why it stopped)."""
    n = 0
    progress = {"bytes": 0, "long_lines": 0}
    try:
        with open_regular(path) as fh:
            for line in lines_of(fh, deadline, progress):
                if line.strip() and not line.startswith("#"):
                    n += 1
    except OutOfTime:
        return n, "the clock ran out after %d bytes of this file were read: lines is a lower bound" % progress["bytes"]
    return n, None


class _Named:
    """A hidden file made by temp_create, closed, whose name is all that is kept."""

    def __init__(self, made):
        fd, self.name = made
        os.close(fd)

    def close(self):
        pass


def forget_temporaries():
    drop_temporaries()


def main():
    try:
        args = json.load(sys.stdin)
    except (ValueError, RecursionError) as exc:
        fail("arguments are not valid JSON", reason=str(exc)[:200])
    if not isinstance(args, dict):
        fail("arguments are a JSON object")

    path = args.get("path")
    if not isinstance(path, str) or not path or "\0" in path:
        fail("path is required: an image or any blob")
    if not os.path.isfile(path):
        fail("no such file", path=path)

    out_dir = args.get("out_dir")
    if not isinstance(out_dir, str) or not out_dir or "\0" in out_dir:
        fail("out_dir is required: a directory under work/ that does not exist yet")
    try:
        path.encode("utf-8")
        out_dir.encode("utf-8")
    except UnicodeEncodeError:
        fail("path and out_dir are text that can be written as UTF-8 (a lone surrogate cannot)")
    if "\0" in out_dir:
        fail("out_dir is a string without a NUL byte: a directory under work/ that does not exist yet")
    try:
        out_dir = resolve_output(out_dir, "out_dir")
    except (OSError, RuntimeError, ValueError) as exc:
        fail("out_dir cannot be used: %s" % (getattr(exc, "strerror", None) or exc))
    job_out = os.environ.get("OUT") if os.environ.get("JOB_ID") else None
    if job_out:
        # A job writes in one place, $OUT: a directory elsewhere would fail halfway, or leave bytes outside the sealed output.
        out_root = Path(job_out).resolve()
        if out_root not in (Path.cwd().resolve() / out_dir).resolve().parents:
            fail("in a job out_dir is a directory under $OUT, the one place a job writes", out_dir=out_dir, out=str(out_root))
    if os.path.lexists(out_dir):
        if not os.path.isdir(out_dir):
            fail("out_dir exists and is not a directory", out_dir=out_dir)
        try:
            holds = bool(os.listdir(out_dir))
        except OSError as exc:
            fail("out_dir cannot be listed (%s)" % (exc.strerror or exc), out_dir=out_dir)
        if holds:
            fail("out_dir already holds files; bulk_extractor refuses to write into one", out_dir=out_dir)

    binary = shutil.which("bulk_extractor")
    if not binary:
        fail("bulk_extractor is not on PATH",
             install="brew install bulk_extractor, or apt-get install -y bulk-extractor")

    top = args.get("top", 15)
    if not isinstance(top, int) or isinstance(top, bool) or top < 1:
        fail("top must be a positive integer")
    timeout = args.get("timeout_seconds", DEFAULT_TIMEOUT)
    if not isinstance(timeout, int) or isinstance(timeout, bool) or not 10 <= timeout <= TIMEOUT_MAX:
        fail("timeout_seconds is a whole number from 10 to %d (the tool's own limit is 1200 seconds, and counting what bulk_extractor wrote needs the rest)" % TIMEOUT_MAX)
    write_values = args.get("write_values", False)
    if not isinstance(write_values, bool):
        fail("write_values is true or false")
    try:
        secret = SecretValues(write_values)
    except SecretValuesRefused as exc:
        fail(str(exc), write_values="refused")
    only = args.get("only") or []
    disable = args.get("disable") or []
    for what, names in (("only", only), ("disable", disable)):
        if not isinstance(names, list) or not all(isinstance(n, str) and NAME.match(n) for n in names):
            fail("%s is a list of scanner names (letters, digits and underscores)" % what)

    argv = [binary, "-o", out_dir]
    if len(only) == 1:
        argv += ["-E", only[0]]            # -E is "-x all -E scanner", and only takes one
    elif len(only) > 1:
        argv += ["-x", "all"]
        for name in only:
            argv += ["-e", name]
    for name in disable:
        argv += ["-x", name]
    argv.append(path)

    # The child's words go to files beside out_dir while it runs (bulk_extractor makes out_dir itself and
    # refuses one that has files), and move into it after.
    parent = Path(out_dir).parent
    try:
        parent.mkdir(parents=True, exist_ok=True)
        tmp_out = _Named(temp_create(parent, ".feature_scan-", ".stdout"))
        tmp_err = _Named(temp_create(parent, ".feature_scan-", ".stderr"))
    except OSError as exc:
        fail("the directory out_dir would be made in cannot be written (%s)" % (exc.strerror or exc), out_dir=out_dir, parent=str(parent))
    # An out_dir that exists must be a directory this tool can write in; bulk_extractor would only be run to find that out after it had worked.
    if os.path.lexists(out_dir):
        if not os.path.isdir(out_dir):
            fail("out_dir exists and is not a directory", out_dir=out_dir)
        try:
            probe_fd, probe_name = temp_create(out_dir, ".feature_scan-probe-")
            os.close(probe_fd)
        except OSError as exc:
            fail("out_dir cannot be written (%s)" % (exc.strerror or exc), out_dir=out_dir)
        if not temp_drop(probe_name):
            fail("out_dir cannot be cleaned: the probe file made in it could not be removed", out_dir=out_dir, left=probe_name)

    def last_word(signum):
        """A stop ends bulk_extractor and what it started (the block does that first); what it had written stays in out_dir, not counted, and
        its modes are restricted as they are after a run that ends by itself."""
        locked = lock_down(out_dir, time.monotonic() + 5) if os.path.isdir(out_dir) else []
        forget_temporaries()
        print(json.dumps({"tool": TOOL, "path": path, "out_dir": out_dir, "status": "partial", "interrupted": True, "signal": signum,
                          "status_basis": "the tool was stopped by signal %d: bulk_extractor and what it started were ended, and what it had written is in out_dir, "
                                          "not counted or listed" % signum,
                          "out_dir_mode_problem": locked[:5] or None, "process_notes": process_notes() or None}), flush=True)
    STATE["last_word"] = last_word

    count_deadline = STARTED + COUNT_SECONDS
    timed_out = False
    try:
        code, timed_out = run_to_files(argv, tmp_out.name, tmp_err.name, timeout)
    except OSError as exc:
        forget_temporaries()
        fail("bulk_extractor could not be started: %s" % describe(exc), program=binary, command=" ".join(argv))

    def read_head(p, n=4000):
        try:
            with open(p, "r", encoding="utf-8", errors="replace") as fh:
                return fh.read(n)
        except OSError:
            return ""

    said = read_head(tmp_err.name, 200000) + read_head(tmp_out.name, 200000)
    if "no such scanner" in said:
        named = [l.strip() for l in said.splitlines() if "no such scanner" in l]
        forget_temporaries()
        fail("bulk_extractor does not have a scanner by that name", refused=named, scanners=SCANNERS, command=" ".join(argv))
    if not os.path.isdir(out_dir):
        err = read_head(tmp_err.name)
        forget_temporaries()
        fail("bulk_extractor wrote no output directory", exit_code=code, timed_out=timed_out, stderr=err.strip(), command=" ".join(argv))
    stdout_file, stderr_file = os.path.join(out_dir, "feature_scan.stdout"), os.path.join(out_dir, "feature_scan.stderr")
    try:
        temp_replace(tmp_out.name, stdout_file)
        temp_replace(tmp_err.name, stderr_file)
    except OSError as exc:
        fail("what bulk_extractor said could not be moved into out_dir (%s); what it wrote there is not counted" % (exc.strerror or exc), out_dir=out_dir,
             exit_code=code, timed_out=timed_out)
    locked_failed = lock_down(out_dir, STARTED + LOCK_SECONDS)

    files, features, histograms = [], [], []
    n_files = n_written = hist_total = 0
    kinds = set()
    not_counted = []
    counter = 0
    seen = {}
    try:
        for root_, names, _dirs in walk_entries(out_dir, count_deadline, seen):
            for name in names:
                if time.monotonic() > count_deadline:
                    raise OutOfTime()
                full = os.path.join(root_, name)
                rel = os.path.relpath(full, out_dir)
                if os.path.islink(full) or not os.path.isfile(full):
                    continue
                size = os.path.getsize(full)
                first = first_content_line(full, count_deadline) if name.endswith(".txt") else None
                kind = classify(name, first)
                entry = {"file": os.path.join(out_dir, rel), "bytes": size, "kind": kind}
                n_files += 1
                if entry["file"] not in (stdout_file, stderr_file):
                    n_written += 1
                    if size and kind != "run report":
                        kinds.add(kind)
                if kind == "features" and size:
                    try:
                        stats, counts = summarise(full, count_deadline)
                    except OSError as exc:
                        entry["error"] = exc.strerror or str(exc)
                        stats, counts = None, None
                    if stats and stats["lines"]:
                        entry.update(stats)
                        entry["feature"] = name[:-4]
                        if "not_counted" in stats:
                            not_counted.append("%s: %s" % (entry["file"], stats["not_counted"]))
                        features.append(entry)
                        if len(features) > 4 * FEATURES_SHOWN:
                            features.sort(key=lambda f: -(f.get("lines") or 0))
                            del features[FEATURES_SHOWN:]
                        if write_values:
                            for value, n in counts.most_common(top):
                                counter += 1
                                secret.add("F%06d" % counter, {"feature_file": entry["file"], "count": n}, value)
                    elif stats and "not_counted" in stats:
                        not_counted.append("%s: %s" % (entry["file"], stats["not_counted"]))
                elif kind == "histogram" and size:
                    lines, why = count_lines(full, count_deadline)
                    entry["lines"] = lines
                    if why:
                        entry["not_counted"] = why
                        not_counted.append("%s: %s" % (entry["file"], why))
                    hist_total += 1
                    if len(histograms) < FEATURES_SHOWN:        # the directory holds the rest; histogram_count says how many there are
                        histograms.append(entry)
                if len(files) < INVENTORY_SHOWN:
                    files.append(entry)
    except OutOfTime:
        not_counted.append("the walk of out_dir stopped at the clock after %d entries: files after that were not looked at or counted" % seen.get("entries", 0))
    if seen.get("cut"):
        not_counted.append("%d entries beyond the first %d of a directory of out_dir were not looked at" % (seen["cut"], DIR_ENTRIES_MAX))
    not_counted.extend("a directory of out_dir could not be listed (%s)" % u for u in seen.get("unlisted", []))
    secret.close()
    disk_note = out_dir_full(out_dir, said)
    holding = sorted(kinds)
    features.sort(key=lambda f: -(f.get("lines") or 0))
    feature_total = len(features)
    del features[FEATURES_SHOWN:]
    exit_ok = code == 0 and not timed_out
    # What bulk_extractor left behind (settle() ended it before out_dir was walked): a process that held a file of out_dir, or its stdout or stderr, may have written to it
    # after the program ended, and what it would still have written is missing; where nothing can show that none was left, the files are not shown to be final either.
    verdict = process_verdict()
    left_text = None
    if verdict["left_behind"]:
        left_text = ("bulk_extractor left %d process(es) running after it ended (a child that held a file of out_dir or its stdout or stderr, in the tool's process group or, in a session of its own, "
                     "outside it); settle() killed and reaped them before out_dir was walked and counted, so the files listed are what they held at that moment and what the leftover "
                     "would still have written is missing" % verdict["left_behind"])
    elif verdict["unproven"]:
        left_text = "; ".join(verdict["unproven"]) + ": the files bulk_extractor wrote cannot be shown to be final"
    status = "complete" if exit_ok and not not_counted and secret.write_error is None and not disk_note and not left_text else ("partial" if n_written or exit_ok else "failed")
    result = {
        "tool": TOOL,
        "path": path,
        "out_dir": out_dir,
        "status": status,
        "status_basis": (("bulk_extractor exited 0 and what it wrote is listed (it does not say that every scanner reached every byte). Checked about the disk: bulk_extractor's "
                          "stderr names no full disk or quota, and a 64 KiB write beside its files worked when it ended. Not checked: that each file bulk_extractor wrote "
                          "is whole, since it writes them itself and a disk that had room again by the end would not show a cut") if status == "complete" else
                         "bulk_extractor exited 0, but %s: its files may be cut short, and nothing here can tell which" % disk_note if exit_ok and disk_note else
                         "bulk_extractor exited 0, but %s" % left_text if exit_ok and left_text and not not_counted else
                         "bulk_extractor exited 0, but the clock ran out while what it wrote was being counted: what was not counted is named (not_counted)" if exit_ok else
                         "bulk_extractor did not exit 0 or ran out of time, and what it had written is listed" if status == "partial" else
                         "bulk_extractor did not exit 0 and wrote nothing"),
        "exit_code": code,
        "timed_out": timed_out,
        "command": " ".join(argv),
        "stdout_file": stdout_file,
        "stderr_file": stderr_file,
        "stderr_head": read_head(stderr_file, 600).strip() or None,
        "scanners_only": only or None,
        "features": features,
        "feature_count": feature_total,
        "histograms": histograms,
        "histogram_count": hist_total,
        "values_inline": False,
        "secret_values": secret.summary(),
        "out_dir_contains_secret_values": bool(holding),
        "kinds_holding_values": holding,
        "out_dir_note": "secret_values is about the values file this tool writes. out_dir holds what bulk_extractor wrote, unfiltered: the kinds listed "
                        "in kinds_holding_values (features, histogram and alerts files among them) carry the values themselves. It is mode 0700 with its "
                        "files 0600; in a job it is sealed with the rest of $OUT, so run the job with secret_output: true.",
        "files": files,
        "file_count": n_files,
        "files_written_by_bulk_extractor": n_written,
        "empty_features_omitted": True,
        "note": "No feature value is returned: the feature files hold what the evidence held (addresses, account names, card numbers, "
                "secrets), so read them in a job run with secret_output: true. Each line starts with the byte offset it was found at, and that "
                "offset is the whole provenance: there is no path and no file. A hit is a lead, not a finding, until you have cut the "
                "surrounding bytes and identified what they are. status complete means bulk_extractor exited 0 and every file was counted, not that every "
                "scanner reached every byte (report.xml says what ran).",
    }
    if n_files > INVENTORY_SHOWN:
        result["files_note"] = "the first %d of %d files are listed; the directory holds the rest" % (INVENTORY_SHOWN, n_files)
    if feature_total > FEATURES_SHOWN:
        result["features_note"] = "the %d feature files with the most lines are listed, of %d; the directory holds the rest" % (FEATURES_SHOWN, feature_total)
    if not_counted:
        result["not_counted"] = not_counted[:INVENTORY_SHOWN]
        result["not_counted_total"] = len(not_counted)
    if locked_failed:
        result["out_dir_mode_problem"] = "the modes of %d path(s) could not be restricted, so those may be readable by others: %s" % (len(locked_failed), "; ".join(locked_failed[:5]))
    notes = process_notes()
    if notes:
        result["process_notes"] = notes
    if timed_out:
        result["problem"] = "bulk_extractor did not finish within %d seconds; what it had written is listed and is partial" % timeout
    elif code != 0:
        result["problem"] = "bulk_extractor exited %s; read %s" % (code, stderr_file)
    process_apply(result)         # program_group: what settle() ended and why absence is unproven (a complete answer is already partial above)
    if left_text:
        result["problem"] = left_text if "problem" not in result else "%s; %s" % (result["problem"], left_text)
    print_answer(result, indent=2)
    raise SystemExit(0 if result["status"] == "complete" else 1)


if __name__ == "__main__":
    main()
