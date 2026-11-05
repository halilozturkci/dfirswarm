#!/usr/bin/env python3
"""A broad extraction of a macOS acquisition with the pinned mac_apt, and one status per plugin read from its log.

    run.py detect --target T [--probe-out DIR]   exit 0 applies, 1 does not here, 2 cannot tell
    run.py run --target T --out DIR

The target is {"paths": [<image, volume or folder>], "plugins": [<names>]} (plugins optional; default FAST). The input type is told from the object itself: an Expert
Witness image (EVF), a sparse image, a VMDK, a UDIF image (koly trailer), a raw APFS container or HFS+ volume, a raw disk whose GPT holds a partition of an Apple type, or
a folder whose top holds System/Library/CoreServices/SystemVersion.plist (MOUNTED). Collections (UAC, Velociraptor) and AFF4 are not detected here; the tool macos_triage
takes them with an input type the caller names. mac_apt 1.33.2 is installed in the amd64 image only: on arm64 detect exits 1 ("does not apply here") with the packaging reason.

WHAT WAS READ AND WHAT WAS NEVER SEEN. mac_apt was not installed or run to build this recipe. Its argument shape and the texts of the start, plugin start, plugin end,
plugin exception and finish log lines were read from the source of v1.33.2 (GitHub raw view, 2026-11-04). The prefix of a log line, the wording of an empty or
unsupported plugin and the per-plugin file names were not, and `empty` and `unsupported` rest on an assumed wording. The source sets the log file format
'%(asctime)s|%(name)s|%(levelname)s|%(message)s', read through a page summary and never seen in a real run. So `parsed` rests on a log format never observed: a plugin is
`parsed` when no line of its run holds an error word, and a failure logged below ERROR level or without an error word (permission denied, timed out, no such file,
refused, skipping, errno) can still read as `parsed`, and a run can then be `complete`. The recipe's tests drive it with a stand-in program.

WHAT `complete` MEANS. mac_apt exits 0 after errors it has logged, so the exit code is never the status. The recipe reads mac_apt's own log (Log.<time>.txt in the output
folder; the console output only when that file is missing, and then at best partial) and gives each plugin one status in plugins.tsv: parsed, empty, unsupported or failed.
The run is `complete` only when mac_apt exited 0, the log has its start line (with the pinned version) and its finish line, every plugin the target names is parsed or
empty, and no error line or traceback sits outside a plugin. The default plugin set FAST (and ALL) can never be complete: the plugins they expand to are not listed by anything
read here. coverage.json is written first, as partial, and replaced whole at the end. A run never writes over an earlier run: if the output directory already holds
any of the ten names it writes (mac_apt, coverage.json, coverage.json.tmp, plugins.tsv, index.tsv, mac_apt.stdout, mac_apt.stderr, mac_apt-cwd, mac_apt-tmp,
mac_apt-home), a link included, it refuses (exit 2) and leaves them as they are. Its files and scratch directories are created exclusively (a link at a name is
never followed): if another process creates one of those names after that check, or a file operation fails, the run stops with the same refusal (exit 2, one JSON
answer), touches nothing it did not create, and leaves coverage.json as the partial account it wrote first. No password is passed (a FileVault password is the tool's, from a sealed file). The files hold the
examined system's own content; a recipe cannot declare secret_output, so coverage.json marks every file it wrote under secret_bearing.
"""
import argparse
import errno
import json
import os
import platform
import re
import selectors
import shutil
import signal
import struct
import subprocess
import sys
import time

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

# program-group: settle
# Tool-local (outside the shared blocks); the same text is in macos_triage, the macos-artefacts recipe and unified_log. It looks for what settle() cannot: a writer that is no descendant of the program.
# After the program has ended and what it left in the tool's own process group was ended, the files of the run are looked at again: a file that grew, or a
# process outside the group that still holds one open (Linux, /proc), is a process in a session of its own (setsid), which this tool cannot end.
SETTLE_SECONDS = 1.0       # the files are looked at again after this long


def tree_sizes(roots, limit=200000):
    """{path: size} of the regular files named in `roots` or under the directories named there (links not followed), at most `limit` of them."""
    found = {}
    stack = []
    for root in roots:
        try:
            if os.path.isfile(str(root)) and not os.path.islink(str(root)):
                found[str(root)] = os.stat(str(root)).st_size
            else:
                stack.append(str(root))
        except OSError:
            pass
    while stack and len(found) < limit:
        here = stack.pop()
        try:
            with os.scandir(here) as it:
                for entry in it:
                    try:
                        if entry.is_symlink():
                            continue
                        if entry.is_dir(follow_symlinks=False):
                            stack.append(entry.path)
                        elif entry.is_file(follow_symlinks=False):
                            found[entry.path] = entry.stat(follow_symlinks=False).st_size
                    except OSError:
                        continue
        except OSError:
            continue
    return found


def file_holders(roots):
    """The pids (not this tool's) that hold a file under `roots` open, or None where that cannot be looked for (no /proc: not Linux). The roots are this call's own."""
    if not os.path.isdir("/proc/self"):
        return None
    targets = tuple(os.path.realpath(str(r)).rstrip("/") for r in roots)
    me = os.getpid()
    found = []
    limit = time.monotonic() + 10
    try:
        names = os.listdir("/proc")
    except OSError:
        return None
    for number, name in enumerate(names):
        if not name.isdigit() or int(name) == me:
            continue
        if number % 64 == 0 and time.monotonic() > limit:
            return None
        try:
            for fd in os.listdir("/proc/%s/fd" % name):
                try:
                    link = os.readlink("/proc/%s/fd/%s" % (name, fd))
                    if any(link == t or link.startswith(t + "/") for t in targets):
                        found.append(int(name))
                        break
                except OSError:
                    continue
        except OSError:
            continue
    return found


def settle_check(roots):
    """After the program's group was emptied: the sizes under `roots` are read, SETTLE_SECONDS pass, they are read again. Returns {"grew": the number of
    files that are new or changed in size, "holders": the pids that still hold a file open or None, "settle_seconds": SETTLE_SECONDS}. Any of them
    means something outside the program's group (a process in a session of its own) is still writing, and this tool cannot end it."""
    before = tree_sizes(roots)
    time.sleep(SETTLE_SECONDS)
    after = tree_sizes(roots)
    return {"grew": sum(1 for path, size in after.items() if before.get(path) != size), "holders": file_holders(roots), "settle_seconds": SETTLE_SECONDS}
# program-group: settle end

FILE_CHECK = {"settle": None}   # what the second look at the files of the run found (settle_check)

# macapt-log-reader: start
# The same text is in macos_triage and the macos-artefacts recipe (tests/pack-macos-triage.test.ts holds the copies equal).
# It reads the log of ONE mac_apt run and says, per plugin, what the log shows. What is READ FROM mac_apt v1.33.2's SOURCE (mac_apt.py, GitHub raw view)
# and what is ASSUMED is kept apart, because no run of mac_apt was ever observed here:
#   read from the source: the message texts "Started {program}, version {version}", "Running plugin {name}", "{name} plugin ran for HH:MM:SS",
#     "An exception occurred while running plugin - {name}" (logged with log.exception, so a traceback follows it), "Finished in time = HH:MM:SS",
#     "Could not find OSX/macOS installation!", ":( Could not find a partition having a macOS installation on it", the log file name
#     "Log.<%Y%m%d-%H%M%S>.txt" in the output folder, and that the script ends with exit 0 even after an error it logged (Exit() calls sys.exit()).
#     The source also sets the log format '%(asctime)s|%(name)s|%(levelname)s|%(message)s' (read through a page summary, never seen in a real run).
#   NOT read from the source, never observed: the log file as a real run writes it, the wording of a plugin that finds nothing or does not take an
#     operating-system version, and where the console copy of the log goes. `empty` and `unsupported` rest on wording that is an ASSUMPTION (see the manifest).
# ANCHORING (rests on that format, which was never observed). A line that has the shape time|logger|LEVEL|message is a recognised line only when its MESSAGE
# begins with the text of the line (a start, a plugin start, a plugin end, an exception, the finish, no macOS found): a message that merely ends with that text,
# or quotes it in the middle (evidence the log repeats), is an ordinary line. A line WITHOUT that shape is never recognised as one of those lines, even if it
# holds their text: it is counted (unanchored), the run cannot be complete, and the plugin it would have opened, closed or finished stays not-parsed. So if
# the real format differs from the one read from the source, a run reads as failed or partial, never as a wrong complete. A value of the evidence that holds
# a line break followed by the whole shape could still forge a line (mac_apt's logger was not seen to escape one). The one line exempt from the error
# vocabulary is the finish hint, and only as the whole message of a line of that shape with no error word in its prefix.
# Every line is read whole up to MA_LINE_CAP bytes; a longer line is read to its cap, counted (long_lines) and makes the run partial. The read has a
# deadline and a byte cap; either one ends it (cut) and the run is partial. Nothing a line says is kept except its number: a log line can quote the evidence.
import re
import stat

MA_LINE_CAP = 1 << 20          # a line is scanned whole up to this many bytes; beyond them it is counted in long_lines (unreadable) and the run is partial
MA_READ_MAX = 512 << 20        # the most bytes of log read in one run; beyond them the read is cut and the run is partial
MA_TAIL_BYTES = 1 << 16        # the part of stdout and stderr (their end) that is read for an error word when a log file exists
MA_PREFIX = re.compile(r"[^|\r\n]{1,40}\|[^|\r\n]{1,80}\|(?P<level>[A-Z]{3,10})\|(?P<msg>.*)")
MA_STARTED = re.compile(r"Started (?P<prog>.{1,120}?), version (?P<ver>[0-9A-Za-z][0-9A-Za-z.+_-]{0,40})\s*$")
MA_PLUGIN_RUN = re.compile(r"Running plugin (?P<n>[A-Za-z0-9_]{1,64})\s*$")
MA_PLUGIN_RAN = re.compile(r"(?P<n>[A-Za-z0-9_]{1,64}) plugin ran for (?P<t>[0-9]{2,}:[0-9]{2}:[0-9]{2})\s*$")
MA_EXCEPTION = re.compile(r"An exception occurred while running plugin - (?P<n>[A-Za-z0-9_]{1,64})\s*$")
MA_FINISHED = re.compile(r"Finished in time = (?P<t>[0-9]{2,}:[0-9]{2}:[0-9]{2})\s*$")
MA_NO_MACOS = re.compile(r"Could not find OSX/macOS installation!|Could not find a partition having a macOS installation on it")
MA_EVENTS = (MA_STARTED, MA_PLUGIN_RUN, MA_PLUGIN_RAN, MA_EXCEPTION, MA_FINISHED, MA_NO_MACOS)
MA_ANY_EVENT = re.compile("|".join("(?:%s)" % re.sub(r"\(\?P<\w+>", "(?:", p.pattern) for p in MA_EVENTS))
MA_TRACEBACK = re.compile(r"Traceback \(most recent call last\)")
MA_LEVEL_BAD = re.compile(r"(?<![A-Za-z])(?:ERROR|CRITICAL)(?![A-Za-z])|\b(?:errors?|exceptions?|tracebacks?|fail(?:ed|s|ure|ures)?|cannot|can't|could not|couldn't|unable|corrupt(?:ed)?|malformed|invalid)\b", re.I)
# (the level word of the prefix was never observed, so a line is a failure line when it holds the uppercase level word OR any word of the broader vocabulary above, in any case)
MA_REVIEW = re.compile(r"Review the Log file and report any ERRORs or EXCEPTIONS to the developers\.?\s*")      # the finish-time hint of the source: it names ERRORs and EXCEPTIONS without one having happened
MA_REVIEW_PHRASE = re.compile(r"Review the Log file and report any ERRORs or EXCEPTIONS to the developers")
MA_LEVEL_WARN = re.compile(r"(?<![A-Za-z])WARNING(?![A-Za-z])")
MA_SEPARATOR = re.compile(r"-{20,}\s*$")
MA_UNSUPPORTED = re.compile(r"\b(?:not supported|unsupported)\b", re.I)                                                  # ASSUMED wording
MA_EMPTY = re.compile(r"\bno\b.{0,80}\b(?:found|data|records|entries|items)\b|\b0 (?:records|entries|items)\b", re.I)      # ASSUMED wording
MA_STATUSES = ("parsed", "empty", "unsupported", "failed")


def ma_read_log(paths, deadline=None, max_bytes=MA_READ_MAX, stop=None):
    """Read the given log files in order as one account. Returns a dict: lines, long_lines (lines longer than MA_LINE_CAP, read to the cap), bytes, cut (None, or
    the sentence that says the read ended before the end of the log: its deadline or its byte cap), unanchored (lines that hold the text of a start, plugin or
    finish line without the shape that anchors one), started (bool), program, version, finished (bool), no_macos (bool), run_errors (the lines with an error
    word or a traceback outside any plugin's window), plugins (a list of windows in the order they began: name, line, ran, exception, errors, tracebacks,
    warnings, unsupported, empty, other, closed_by) and unreadable (a log that could not be opened, or is not a regular file). `stop` is a function that
    says a stop signal is waiting."""
    out = {"lines": 0, "long_lines": 0, "bytes": 0, "cut": None, "unanchored": 0, "started": False, "program": None, "version": None, "finished": False,
           "no_macos": False, "run_errors": [], "plugins": [], "unreadable": []}
    current = None

    def cut_now():
        if stop is not None and stop():
            out["cut"] = "a stop signal arrived while the log was read"
        elif deadline is not None and time.monotonic() >= deadline:
            out["cut"] = "the time given to reading the log ran out"
        elif out["bytes"] >= max_bytes:
            out["cut"] = "the log is longer than the %d bytes this tool reads" % max_bytes
        return out["cut"] is not None

    for path in paths:
        if out["cut"] or cut_now():
            break
        try:
            fd = os.open(path, os.O_RDONLY | os.O_NONBLOCK | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0))
        except OSError as exc:
            out["unreadable"].append(exc.strerror or type(exc).__name__)
            continue
        if not stat.S_ISREG(os.fstat(fd).st_mode):
            os.close(fd)                       # a FIFO, a device or a directory at the name of a log is not a log, and is never read (it could block for ever)
            out["unreadable"].append("not a regular file")
            continue
        handle = os.fdopen(fd, "rb")
        with handle:
            while True:
                if out["cut"] or cut_now():
                    break
                raw = handle.readline(MA_LINE_CAP + 1)
                if not raw:
                    break
                out["bytes"] += len(raw)
                if len(raw) > MA_LINE_CAP and not raw.endswith(b"\n"):
                    out["long_lines"] += 1
                    while True:                      # the rest of the line is skipped, in pieces (the clock is looked at between them)
                        rest = handle.readline(MA_LINE_CAP)
                        out["bytes"] += len(rest)
                        if not rest or rest.endswith(b"\n") or cut_now():
                            break
                out["lines"] += 1
                number = out["lines"]
                line = raw.decode("utf-8", "replace").rstrip("\r\n")
                shaped = MA_PREFIX.fullmatch(line)
                message = shaped.group("msg") if shaped else line

                def event(pattern):
                    return pattern.match(message) if shaped else None
                if not shaped and MA_ANY_EVENT.search(line):
                    out["unanchored"] += 1
                m = event(MA_STARTED)
                if m and not out["started"]:
                    out["started"], out["program"], out["version"] = True, m.group("prog"), m.group("ver")
                    continue
                m = event(MA_PLUGIN_RUN)
                if m:
                    current = {"name": m.group("n"), "line": number, "ran": False, "exception": 0, "errors": 0, "tracebacks": 0, "warnings": 0,
                               "unsupported": 0, "empty": 0, "other": 0, "closed_by": None}
                    out["plugins"].append(current)
                    continue
                if event(MA_FINISHED):
                    out["finished"] = True
                    if current is not None:
                        current["closed_by"] = current["closed_by"] or "finish"
                    current = None
                    continue
                if event(MA_NO_MACOS):
                    out["no_macos"] = True
                    continue
                m = event(MA_PLUGIN_RAN)
                if m:
                    if current is not None and current["name"] == m.group("n") and not current["ran"]:
                        current["ran"], current["closed_by"] = True, "ran"
                        current = None
                    else:
                        out["run_errors"].append(number)          # a "ran for" line for a plugin that is not the one in hand: the log is not in the order read
                    continue
                m = event(MA_EXCEPTION)
                if m:
                    target = current if current is not None and current["name"] == m.group("n") else next((w for w in reversed(out["plugins"]) if w["name"] == m.group("n")), None)
                    if target is None:
                        out["run_errors"].append(number)
                    else:
                        target["exception"] += 1
                    continue
                exempt = bool(shaped) and bool(MA_REVIEW.fullmatch(message)) and not MA_LEVEL_BAD.search(line[:shaped.start("msg")])
                bad = bool(MA_LEVEL_BAD.search(line)) and not exempt
                trace = bool(MA_TRACEBACK.search(line))
                if current is None:
                    if bad or trace:
                        out["run_errors"].append(number)
                    continue
                if MA_SEPARATOR.search(line) or not line.strip():
                    continue
                if trace:
                    current["tracebacks"] += 1
                elif bad:
                    current["errors"] += 1
                elif MA_LEVEL_WARN.search(line):
                    current["warnings"] += 1
                elif MA_UNSUPPORTED.search(line):
                    current["unsupported"] += 1
                elif MA_EMPTY.search(line):
                    current["empty"] += 1
                else:
                    current["other"] += 1
    return out


def ma_tail_hits(paths):
    """(the number of lines with an error word or a traceback, the number of files that could not be read) in the last MA_TAIL_BYTES of each file: stdout and
    stderr are read this way when a log file exists, because a traceback printed there is not in the log. The finish hint is taken out of a line first."""
    hits = unreadable = 0
    for path in paths:
        try:
            with open(path, "rb") as handle:
                size = os.fstat(handle.fileno()).st_size
                handle.seek(max(0, size - MA_TAIL_BYTES))
                text = handle.read(MA_TAIL_BYTES).decode("utf-8", "replace")
        except OSError:
            unreadable += 1
            continue
        for line in text.splitlines():
            line = MA_REVIEW_PHRASE.sub("", line)
            if MA_LEVEL_BAD.search(line) or MA_TRACEBACK.search(line):
                hits += 1
    return hits, unreadable


def ma_plugin_status(window):
    """(status, reason) of one plugin window; a fixed sentence, never a line of the log."""
    if window["exception"] or window["errors"] or window["tracebacks"]:
        return "failed", "the log holds an exception, an error line or a traceback inside this plugin's run"
    if not window["ran"]:
        return "failed", "the log shows the plugin started and no line saying it ran to its end (a log cut short, or the run ended inside it)"
    if window["unsupported"]:
        return "unsupported", "a line inside this plugin's run says it does not support something (assumed wording; read it in the kept log)"
    if window["empty"] and not window["other"]:
        return "empty", "the plugin ran to its end and the only lines inside its run say nothing was found (assumed wording; read it in the kept log)"
    return "parsed", "the plugin ran to its end and no line inside its run holds an error word (error, exception, traceback, failed, cannot, could not, unable, corrupt, malformed, invalid); that rests on a log format never observed, and it is not a count of its records"


def ma_plugins(read):
    """One row per plugin name, in the order first started. A name that started more than once is failed (the loop runs each plugin once)."""
    rows, by_name = [], {}
    for w in read["plugins"]:
        status, reason = ma_plugin_status(w)
        row = by_name.get(w["name"])
        if row is None:
            row = {"plugin": w["name"], "status": status, "reason": reason, "log_line": w["line"], "warnings": w["warnings"], "starts": 1}
            by_name[w["name"]] = row
            rows.append(row)
        else:
            row["starts"] += 1
            row["status"], row["reason"] = "failed", "the log shows this plugin started more than once"
            row["warnings"] += w["warnings"]
    return rows
# macapt-log-reader: stop

PINNED_VERSION = "1.33.2"
PROGRAM = "mac_apt.py"
MACAPT_SECONDS = 14100      # recipe.json limits.seconds (14400) less the time to write the account of the run
PIPE_FLOOR = 1.0
LOG_FLOOR_SECONDS = 10.0     # the log is read for what is left of the seconds given to mac_apt, and for at least this long
LOG_END_SECONDS = 14250.0   # and never past this many seconds from the start of the run (recipe.json limits.seconds is 14400)
ARM_REASON = ("mac_apt 1.33.2 is installed in the amd64 worker image only: its statx helper has no syscall number for aarch64 and stops at import on Linux arm64 "
              "(a packaging limit of the pinned copy, which says nothing about the evidence)")
PLUGIN_NAME = re.compile(r"[A-Za-z0-9_]{1,64}-?")
SET_NAMES = ("ALL", "FAST")
LOG_NAME = re.compile(r"Log\.[0-9]{8}-[0-9]{6}\.txt")
APPLE_GUIDS = {  # GPT partition type GUIDs, as the little-endian first three groups and the big-endian rest
    "7c3457ef-0000-11aa-aa11-00306543ecac": "APFS container",
    "48465300-0000-11aa-aa11-00306543ecac": "HFS+ volume",
    "426f6f74-0000-11aa-aa11-00306543ecac": "Apple boot (recovery)",
}
NOT_COVERED = ("what no mac_apt plugin of the pinned release parses (the files stay in the source, unread); deleted records beyond what a plugin reads itself; "
               "an encrypted volume (no password is passed here, and what mac_apt does without one was never observed); input types this recipe does not detect "
               "(UAC, VR, AFF4, AXIOMZIP: they are the tool macos_triage's); a plugin the log does not account for as parsed or empty")
READ_FROM_SOURCE = ("Read from the source of mac_apt v1.33.2 (mac_apt.py, GitHub raw view, 2026-11-04) and never observed from a run: the positional input type, the positional plugin list "
                    "(ALL, FAST, a trailing - excludes), -o, -c, the log file name Log.<time>.txt in the output folder and the texts of the start, plugin start, plugin end, plugin "
                    "exception and finish lines.")
NOT_OBSERVED = ("Never observed and not in what was read: the prefix of a log line, the wording of a plugin that finds nothing or does not take an operating-system version "
                "(`empty` and `unsupported` rest on an assumed wording), the per-plugin file names of the output formats, the console copy of the log, and mac_apt's behaviour on an "
                "encrypted image without a password.")


def target_of(value):
    text = open(value, encoding="utf-8").read() if os.path.isfile(value) else value
    target = json.loads(text)
    paths = target.get("paths") or []
    if not paths or not isinstance(paths[0], str):
        raise ValueError("the target names no path")
    return target, paths[0]


def gpt_apple(handle):
    """(found a partition of an Apple type, why): the GUID partition table of a disk image, read from the header at LBA 1 (512-byte sectors)."""
    handle.seek(512)
    header = handle.read(92)
    if len(header) < 92 or header[:8] != b"EFI PART":
        return None, "no GPT header at sector 1"
    entries_lba = struct.unpack_from("<Q", header, 72)[0]
    count, size = struct.unpack_from("<II", header, 80)
    if size < 128 or size > 4096 or count > 4096 or entries_lba > (1 << 40):
        return None, "the GPT header's entry table is not in a shape this recipe reads"
    handle.seek(entries_lba * 512)
    for _ in range(count):
        entry = handle.read(size)
        if len(entry) < 16:
            break
        guid = "%08x-%04x-%04x-%s-%s" % (struct.unpack_from("<IHH", entry, 0) + (entry[8:10].hex(), entry[10:16].hex()))
        if guid in APPLE_GUIDS:
            return APPLE_GUIDS[guid], "a GPT partition of the type of %s" % APPLE_GUIDS[guid]
    return None, "a GPT with no partition of an Apple type (APFS, HFS+, Apple boot)"


def kind_of(path):
    """(applies, why, input type): applies is True, False or "unknown"."""
    if os.path.islink(path):
        return False, "a symbolic link: name what it resolves to (evidence is not followed through a link)", None
    if os.path.isdir(path):
        if os.path.isfile(os.path.join(path, "System", "Library", "CoreServices", "SystemVersion.plist")):
            return True, "a folder with System/Library/CoreServices/SystemVersion.plist, the root of a macOS volume (input type MOUNTED)", "MOUNTED"
        return False, "a folder without System/Library/CoreServices/SystemVersion.plist at its top", None
    if not os.path.isfile(path):
        return "unknown", "not a readable file or folder, so it cannot be told what it holds", None
    try:
        size = os.path.getsize(path)
        with open(path, "rb") as fh:
            head = fh.read(2048)
            fh.seek(max(0, size - 512))
            tail = fh.read(512)
            if head.startswith(b"EVF\x09\x0d\x0a\xff\x00"):
                return True, "an Expert Witness image (EVF signature); whether it holds macOS is mac_apt's to find (input type E01)", "E01"
            if head.startswith(b"sprs"):
                return True, "a sparse image (signature sprs; input type SPARSE)", "SPARSE"
            if head.startswith(b"KDMV") or head.startswith(b"# Disk Descriptor"):
                return True, "a VMDK (sparse extent or descriptor; input type VMDK)", "VMDK"
            if tail[:4] == b"koly":
                return True, "a UDIF disk image (koly trailer; input type DMG)", "DMG"
            if len(head) >= 36 and head[32:36] == b"NXSB":
                return True, "a raw APFS container (NXSB at offset 32; input type DD)", "DD"
            if len(head) >= 1026 and head[1024:1026] in (b"H+", b"HX"):
                return True, "a raw HFS+ volume (volume header at offset 1024; input type DD)", "DD"
            if size >= 1024:
                found, why = gpt_apple(fh)
                if found:
                    return True, "a raw disk with " + why + " (input type DD)", "DD"
                if why.startswith("a GPT with no"):
                    return False, why, None
    except (OSError, struct.error) as exc:
        return "unknown", "the file could not be read, so it cannot be told what it holds: %s" % (exc.strerror or type(exc).__name__), None
    return False, "no signature of an E01, sparse image, VMDK, DMG, APFS or HFS+ volume, or a GPT with an Apple partition", None


def applies_here(path):
    arch = platform.machine().lower()
    if arch in ("aarch64", "arm64"):
        return False, "does not apply here: " + ARM_REASON, None
    found, why, kind = kind_of(path)
    if found is True and shutil.which(PROGRAM) is None:
        return "unknown", "the input looks like a macOS acquisition (%s), but mac_apt.py is not on PATH in this image, so it cannot be told whether it can be read here" % why, kind
    return found, why, kind


def basis_of(lead, reasons):
    reasons = [str(r).replace("\n", " ") for r in reasons]
    return lead + "; ".join(reasons[:3]) + (" (and %d more in errors)" % (len(reasons) - 3) if len(reasons) > 3 else "")


def tsv_escape(value):
    out = []
    for ch in str(value):
        o = ord(ch)
        if 0xDC80 <= o <= 0xDCFF:
            out.append("\\x%02x" % (o - 0xDC00))
        elif ch == "\\":
            out.append("\\\\")
        elif ch == "\t":
            out.append("\\t")
        elif ch == "\n":
            out.append("\\n")
        elif ch == "\r":
            out.append("\\r")
        elif o < 0x20 or o == 0x7F:
            out.append("\\x%02x" % o)
        else:
            out.append(ch)
    return "".join(out)


def excl(path, mode="w"):
    """A new file of this run's own: created exclusively, a link at the name is never followed, mode 0600."""
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o600)
    return os.fdopen(fd, mode, encoding="utf-8") if "b" not in mode else os.fdopen(fd, mode)


def write_coverage(out, status, covered, errors, basis, limits=(), first=False, **more):
    # written to a temporary name and renamed: a stop never leaves half a file, and the first account (partial) is replaced whole.
    # The first account is put in place with a hard link, which fails when the name exists (a name created after the start check is never replaced).
    final = os.path.join(out, "coverage.json")
    temp = final + ".tmp"
    account = {"recipe": "macos-artefacts", "status": status, "status_basis": basis, "covered": covered, "not_covered": NOT_COVERED,
               "limits_hit": list(limits), "errors": list(errors), **more}
    process_apply(account)          # program_group: what settle() ended and why absence is unproven; a complete account becomes partial
    if FILE_CHECK["settle"]:
        account["program_group"].update({"files_grown_after": FILE_CHECK["settle"]["grew"], "settle_seconds": FILE_CHECK["settle"]["settle_seconds"],
                                         "files_held_open_by_others": None if FILE_CHECK["settle"]["holders"] is None else len(FILE_CHECK["settle"]["holders"])})
    with excl(temp, "w") as handle:
        json.dump(account, handle, indent=2, sort_keys=True)
        handle.write("\n")
    if first:
        try:
            try:
                os.link(temp, final)
            except FileExistsError:
                raise
            except OSError:
                if os.path.lexists(final):
                    raise FileExistsError(errno.EEXIST, "File exists", final)
                os.replace(temp, final)
                return
        finally:
            try:
                os.unlink(temp)
            except OSError:
                pass
        return
    os.replace(temp, final)


def walk(root):
    """Every regular file under root as (relative path, size), links not followed."""
    rows = []
    for dirpath, dirs, files in os.walk(root):
        dirs[:] = sorted(d for d in dirs if not os.path.islink(os.path.join(dirpath, d)))
        for name in sorted(files):
            full = os.path.join(dirpath, name)
            try:
                if os.path.islink(full):
                    continue
                rows.append((os.path.relpath(full, root), os.path.getsize(full)))
            except OSError:
                continue
    return rows


def last_word(signum):
    sys.stdout.write(json.dumps({"ok": False, "status": "partial", "status_basis": "the recipe was stopped by %s before mac_apt finished: coverage.json, written before it started, says partial"
                                 % signal.Signals(signum).name}) + "\n")
    sys.stdout.flush()


def run_program(argv, out_path, err_path, cwd, env, seconds):
    """(exit code, timed out, pipes held) of mac_apt: in this recipe's own process group (the shared PROCESS block), its stdout and stderr written whole to
    two files. What mac_apt left behind is ended and reaped by settle() (the shared block) when mac_apt leaves ACTIVE, before the caller reads a size, a hash or
    the log; process_verdict() says how many."""
    STATE["last_word"] = last_word
    install_signal_handlers()
    fo = excl(out_path, "wb")
    fe = excl(err_path, "wb")
    files = {"stdout": fo, "stderr": fe}
    proc = spawn(argv, stdout=subprocess.PIPE, stderr=subprocess.PIPE, cwd=cwd, env=env)
    ACTIVE.append(proc)
    selector = selectors.DefaultSelector()
    timed_out = held = False
    try:
        for name, pipe in (("stdout", proc.stdout), ("stderr", proc.stderr)):
            os.set_blocking(pipe.fileno(), False)
            selector.register(pipe, selectors.EVENT_READ, name)
        deadline = time.monotonic() + seconds
        ended_at = None
        while selector.get_map():
            if time.monotonic() >= deadline:
                timed_out = True
                kill_tree(proc)
                break
            if proc.poll() is None:
                _sample(proc.pid)
            for key, _events in selector.select(timeout=0.2):
                try:
                    data = os.read(key.fd, 65536)
                except BlockingIOError:
                    continue
                if not data:
                    selector.unregister(key.fileobj)
                    continue
                files[key.data].write(data)
            if proc.poll() is not None:
                if ended_at is None:
                    ended_at = time.monotonic()
                elif time.monotonic() - ended_at > PIPE_GRACE:
                    held = True
                    reap_orphans(_pipe_inodes(proc))
                    break
        try:
            code = proc.wait(timeout=5.0 if timed_out else max(0.1, min(5.0, deadline - time.monotonic())))
        except subprocess.TimeoutExpired:
            timed_out = True
            kill_tree(proc)
            code = proc.wait()
        return code, timed_out, held
    finally:
        if proc.poll() is None:
            kill_tree(proc)
            try:
                proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                pass
        if proc in ACTIVE:
            ACTIVE.remove(proc)
        selector.close()
        for pipe in (proc.stdout, proc.stderr):
            try:
                pipe.close()
            except (OSError, ValueError):
                pass
        for handle in (fo, fe):
            handle.flush()
            handle.close()


def run(path, kind, requested, out, seconds=MACAPT_SECONDS):
    out = os.path.abspath(out)
    report = os.path.join(out, "mac_apt")
    names = ("mac_apt", "coverage.json", "coverage.json.tmp", "plugins.tsv", "index.tsv", "mac_apt.stdout", "mac_apt.stderr", "mac_apt-cwd", "mac_apt-tmp", "mac_apt-home")
    if any(os.path.lexists(os.path.join(out, n)) for n in names):
        # Before anything is written: an earlier run's coverage and output stay as they are, and nothing is replaced.
        print(json.dumps({"ok": False, "status": "failed", "status_basis": "the output directory already holds the files of an earlier run, and this recipe never writes over one: nothing was run",
                          "why": "the output directory already holds one of the names this recipe writes (mac_apt/, coverage.json, plugins.tsv, index.tsv, mac_apt.stdout, mac_apt.stderr, mac_apt-cwd, mac_apt-tmp, mac_apt-home)"}))
        return 2
    try:
        return run_checked(path, kind, requested, out, seconds, report)
    except OSError as exc:
        # A name was created by another process after the check above, or a file operation failed: nothing foreign is touched, coverage.json stays the
        # partial account written first, and the answer is one JSON line with exit 2 (never a traceback).
        ran = " mac_apt had already been started: what it wrote is kept as it is." if STATE.get("started") else ""
        print(json.dumps({"ok": False, "status": "failed",
                          "status_basis": "a file or directory this recipe creates exclusively could not be created, or a file operation failed (%s): another process may have created a name after the start check. "
                                          "Nothing that was not created by this run was touched, and coverage.json, if this run wrote it, is left as the partial account it wrote first.%s" % (errno.errorcode.get(exc.errno, "OSError"), ran),
                          "error": str(exc)}))
        return 2


def run_checked(path, kind, requested, out, seconds, report):
    began = time.monotonic()
    os.makedirs(out, exist_ok=True)
    path = os.path.abspath(path)
    plugins = requested or ["FAST"]
    sets = [p for p in plugins if p in SET_NAMES]
    explicit = [p for p in plugins if p not in SET_NAMES and not p.endswith("-")]
    expected = explicit if not sets else None
    more = {"input": {"type": kind, "route": "mac_apt.py -o <out>/mac_apt -c %s <input> %s" % (kind, " ".join(plugins))}, "plugins_requested": plugins}
    # Said before mac_apt starts: a run stopped at its limit leaves this, and is read as partial.
    write_coverage(out, "partial", "started; mac_apt did not finish (stopped before its end)", ["the run ended before mac_apt did"],
                   "the run started and mac_apt had not finished when this was written: a run that is stopped before its end leaves this account", first=True, **more)
    if platform.machine().lower() in ("aarch64", "arm64") or not shutil.which(PROGRAM):
        reason = ARM_REASON if platform.machine().lower() in ("aarch64", "arm64") else "mac_apt.py (pinned 1.33.2, amd64 worker image) is not on PATH in this image"
        write_coverage(out, "failed", "nothing: mac_apt is not available here", [reason], "mac_apt is not available here, so nothing was parsed: " + reason, **more)
        return 1
    prog = os.path.abspath(shutil.which(PROGRAM))
    for sub in ("mac_apt", "mac_apt-cwd", "mac_apt-tmp", "mac_apt-home"):
        os.mkdir(os.path.join(out, sub))  # no exist_ok: the start check required these names absent, and a link planted since is never entered
    env = {"PATH": os.environ.get("PATH", "/usr/bin:/bin"), "LC_ALL": "C", "LANG": "C", "PYTHONDONTWRITEBYTECODE": "1", "PYTHONNOUSERSITE": "1",
           "TMPDIR": os.path.join(out, "mac_apt-tmp"), "HOME": os.path.join(out, "mac_apt-home")}
    argv = [prog, "-o", report, "-c", kind, path if not path.startswith("-") else "./" + path] + plugins
    STATE["started"] = True
    run_deadline = time.monotonic() + seconds
    code, timed_out, held = run_program(argv, os.path.join(out, "mac_apt.stdout"), os.path.join(out, "mac_apt.stderr"), os.path.join(out, "mac_apt-cwd"), env, seconds)
    # the group is empty: the files of the run are looked at again after a moment; a file that grew, or a process outside the group that holds one open, is a
    # process in a session of its own, which this recipe cannot end
    settle = FILE_CHECK["settle"] = settle_check([report] + [os.path.join(out, n) for n in ("mac_apt-cwd", "mac_apt-tmp", "mac_apt-home")])
    verdict = process_verdict()
    logs = sorted(n for n in os.listdir(report) if LOG_NAME.fullmatch(n) and not os.path.islink(os.path.join(report, n)))
    console = not logs
    now = time.monotonic()
    log_deadline = min(max(run_deadline, now + LOG_FLOOR_SECONDS), began + LOG_END_SECONDS)
    read = ma_read_log([os.path.join(report, n) for n in logs] if logs else [os.path.join(out, "mac_apt.stdout"), os.path.join(out, "mac_apt.stderr")], log_deadline)
    rows = ma_plugins(read)
    missing = []
    if expected is not None:
        seen = {r["plugin"].upper() for r in rows}
        for p in expected:
            if p not in seen:
                missing.append(p)
                rows.append({"plugin": p, "status": "unsupported" if read["no_macos"] else "failed",
                             "reason": ("mac_apt logged that it found no macOS installation, so no plugin ran" if read["no_macos"] else
                                        "requested, and the log shows no start line for it (it did not run, or the log is cut)"), "log_line": "", "warnings": 0, "starts": 0})
    counts = {s: sum(1 for r in rows if r["status"] == s) for s in MA_STATUSES}
    with excl(os.path.join(out, "plugins.tsv")) as fh:
        fh.write("plugin\tstatus\tlog_line\twarnings\treason\n")
        for r in rows:
            fh.write("\t".join(tsv_escape(x) for x in (r["plugin"], r["status"], r["log_line"], r["warnings"], r["reason"])) + "\n")
    files = [(os.path.join("mac_apt", rel), size) for rel, size in walk(report)]
    for sub in ("mac_apt-cwd", "mac_apt-tmp", "mac_apt-home"):
        files += [(os.path.join(sub, rel), size) for rel, size in walk(os.path.join(out, sub))]
    files += [(n, os.path.getsize(os.path.join(out, n))) for n in ("mac_apt.stdout", "mac_apt.stderr")]
    with excl(os.path.join(out, "index.tsv")) as fh:
        fh.write("file\tbytes\twhat\n")
        fh.write("plugins.tsv\t%d\tone row per plugin: status from the log, the log line it started on, the reason\n" % os.path.getsize(os.path.join(out, "plugins.tsv")))
        for rel, size in sorted(files):
            what = "mac_apt's log" if LOG_NAME.fullmatch(os.path.basename(rel)) else "mac_apt's database (every plugin that writes one)" if rel == os.path.join("mac_apt", "mac_apt.db") else \
                "what mac_apt printed" if rel.startswith("mac_apt.std") else "a file mac_apt wrote"
            fh.write("%s\t%d\t%s\n" % (tsv_escape(rel), size, what))
    problems = []
    for reason in verdict["unproven"]:
        problems.append(reason + ": the files of the run cannot be shown to be final")
    if verdict["left_behind"] and not timed_out:
        problems.append("mac_apt left %d process(es) running (in the tool's process group or, after setsid or setpgid, outside it) after it ended; settle() killed and reaped them before any size, hash or log was read, so what they "
                        "would still have written is missing from the files, and the files are what they held at that moment" % verdict["left_behind"])
    if settle["grew"]:
        problems.append("%d file(s) of the run changed after mac_apt's group was empty: a process in a session of its own (setsid) is still writing, this recipe cannot end it, "
                        "and the sizes in index.tsv and the log read here may be short" % settle["grew"])
    if settle["holders"]:
        problems.append("%d process(es) outside mac_apt's group hold a file of the run open (a process in a session of its own): this recipe cannot end it, and the files may still be growing"
                        % len(settle["holders"]))
    if settle["holders"] is None:
        problems.append("which processes hold the run's files open could not be looked for here (no /proc): a process mac_apt left in a session of its own is seen only if a file grew within %g seconds" % settle["settle_seconds"])
    if read["cut"]:
        problems.append("the log was not fully read: %s, so a plugin or the finish line past the cut is not in the account" % read["cut"])
    if read["long_lines"]:
        problems.append("%d log line(s) are longer than %d bytes and were read only to that length" % (read["long_lines"], MA_LINE_CAP))
    if read["unanchored"]:
        problems.append("%d log line(s) hold the text of a start, plugin or finish line without the line shape that anchors one (time|logger|LEVEL|message, read from the source and never observed): "
                        "they were not counted as those lines" % read["unanchored"])
    if logs:
        tail_hits, tail_unreadable = ma_tail_hits([os.path.join(out, "mac_apt.stdout"), os.path.join(out, "mac_apt.stderr")])
        if tail_hits:
            problems.append("the end of mac_apt.stdout or mac_apt.stderr (the last %d bytes of each) holds %d line(s) with an error word or a traceback, which the log does not show" % (MA_TAIL_BYTES, tail_hits))
        if tail_unreadable:
            problems.append("mac_apt.stdout or mac_apt.stderr could not be read for an error word")
    if timed_out:
        problems.append("mac_apt did not finish in the %g seconds this recipe gives it: it was ended with everything it started, and what it wrote is kept whole" % seconds)
    if held:
        problems.append("something mac_apt started held its pipes after it ended; the pipes were let go and what held them (and was ours) was ended")
    if code != 0 and not timed_out:
        problems.append("mac_apt exited %s; its output is kept whole in mac_apt.stdout and mac_apt.stderr" % code)
    if console:
        problems.append("no Log.<time>.txt was found in the output folder: the console output was read instead, and a run read that way is at best partial")
    if not read["started"]:
        problems.append("the log has no start line of mac_apt: the output was not recognised, or the input type did not suit the input (mac_apt exits 0 after many of its own errors)")
    elif read["version"] != PINNED_VERSION:
        problems.append("the log states version %s and the pack pins %s" % (read["version"], PINNED_VERSION))
    if read["started"] and not read["finished"]:
        problems.append("the log does not end with mac_apt's finish line: the run is cut short")
    if read["no_macos"]:
        problems.append("mac_apt logged that it found no macOS installation in the input: no plugin ran")
    if read["run_errors"]:
        problems.append("%d log line(s) outside any plugin speak of an error or a traceback" % len(read["run_errors"]))
    if read["unreadable"]:
        problems.append("a log file could not be read")
    if counts["failed"]:
        problems.append("%d plugin(s) failed by the log; see plugins.tsv" % counts["failed"])
    if counts["unsupported"]:
        problems.append("%d plugin(s) unsupported by the log (the wording is an assumption); see plugins.tsv" % counts["unsupported"])
    if expected is None:
        problems.append("the plugin set is %s: the plugins mac_apt expands it to are not listed by anything read here, so a plugin that never started cannot be told from one that was not meant to; "
                        "a target that names its plugins (\"plugins\": [...]) can be complete" % "/".join(sets))
    secret = {out_rel: "evidence-derived: mac_apt's output of the examined system" for out_rel, _size in sorted(files)}
    secret.update({"plugins.tsv": "the plugin names the log showed and the log lines they started on", "index.tsv": "the names and sizes of the files mac_apt wrote",
                   "coverage.json": "this receipt: plugin names, counts and reasons derived from the examined system's log"})
    receipt = {"log_format_recognised": read["started"], "log_source": "Log.<time>.txt in mac_apt/" if logs else "the console output (mac_apt.stdout, then mac_apt.stderr)",
               "lines": read["lines"], "long_lines": read["long_lines"], "log_bytes_read": read["bytes"], "log_read_cut": read["cut"],
               "unanchored_lines": read["unanchored"],
               "counts": counts, "plugins_not_started": missing, "plugins_listed_in": "plugins.tsv",
               "error_lines_outside_plugins": len(read["run_errors"]), "read_from_source": READ_FROM_SOURCE, "not_observed": NOT_OBSERVED}
    ran_any = bool(read["plugins"])
    extra = dict(more, plugins=receipt, secret_bearing=secret, sensitive_output="the files under mac_apt/ and the kept log hold the examined system's own content; a recipe cannot declare secret_output, so this receipt marks them")
    if read["started"] and ran_any and not problems:
        write_coverage(out, "complete", "mac_apt exited 0 and its log accounts for %d plugin(s): %d parsed, %d empty (by the log; not a count of records)" % (len(rows), counts["parsed"], counts["empty"]),
                       [], "mac_apt exited 0, its log was recognised from the start line to the finish line, and each of the %d requested plugin(s) is parsed or empty by the log (parsed means no line of its run holds an error word, which rests on a log format never observed); the wording behind `empty` was never observed. No process was left running after mac_apt ended (this recipe adopts the orphans of a program it runs and settle() found none; a process that is no descendant of mac_apt is not found, only a file that grew or is held open is) and no file of the run grew after it" % len(rows), **extra)
    elif read["started"] and ran_any:
        write_coverage(out, "partial", "%d plugin(s) in the log: %d parsed, %d empty, %d unsupported, %d failed" % (len(rows), counts["parsed"], counts["empty"], counts["unsupported"], counts["failed"]),
                       problems, basis_of("partial because ", problems), **extra)
    else:
        write_coverage(out, "failed", "nothing parsed", problems or ["mac_apt ran no plugin"], basis_of("nothing was parsed: ", problems or ["mac_apt ran no plugin"]), **extra)
    return 0 if code == 0 and not timed_out else 1


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("command", choices=("detect", "run"))
    parser.add_argument("--target", required=True)
    parser.add_argument("--out")
    parser.add_argument("--probe-out")
    parser.add_argument("--max-seconds", type=float, default=MACAPT_SECONDS)
    args = parser.parse_args()
    try:
        target, path = target_of(args.target)
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        print(json.dumps({"ok": False, "applies": "unknown", "status": "failed", "status_basis": "the target could not be read, so nothing was run", "error": str(exc)}))
        return 2
    applies, why, kind = applies_here(path)
    if args.command == "detect":
        print(json.dumps({"applies": applies, "why": why}))
        return 2 if applies == "unknown" else 0 if applies else 1
    if not args.out:
        print(json.dumps({"ok": False, "status": "failed", "status_basis": "run was given no output directory, so nothing was run", "error": "run needs --out DIR"}))
        return 2
    if applies is not True:
        print(json.dumps({"ok": False, "status": "failed", "status_basis": "the target is not one this recipe reads here, so nothing was run", "why": why}))
        return 2
    requested = target.get("plugins")
    if requested is not None:
        if (not isinstance(requested, list) or not requested or len(requested) > 200 or not all(isinstance(p, str) and PLUGIN_NAME.fullmatch(p) for p in requested)
                or len({p.upper() for p in requested}) != len(requested)):
            print(json.dumps({"ok": False, "status": "failed", "status_basis": "the target's plugins are not a list of distinct plugin names, so nothing was run"}))
            return 2
        requested = [p.upper() for p in requested]
    rc = run(path, kind, requested, args.out, args.max_seconds)
    if rc == 2:
        return rc
    account = json.load(open(os.path.join(os.path.abspath(args.out), "coverage.json"), encoding="utf-8"))
    print(json.dumps({"ok": rc == 0, "status": account.get("status"), "status_basis": account.get("status_basis")}))
    return rc


if __name__ == "__main__":
    sys.exit(main())
