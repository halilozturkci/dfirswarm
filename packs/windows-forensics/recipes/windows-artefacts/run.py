#!/usr/bin/env python3
"""Recipe protocol for the Windows artefacts of an extracted collection (or of artefacts named one by one).

    run.py detect --target T [--probe-out DIR]   exit 0 applies, 1 does not, 2 could not tell
    run.py run --target T --out DIR

TARGET is JSON (inline or a file path): {"paths": [...], "ref": ..., "name": ...}. Every path is a directory (an extracted
collection, walked, links not followed) or a file (a hive, an event log, a prefetch file, a link, a jump list, $MFT, $J, an
ESE database, a browser history database). Nothing here is a parser: each family is read by the tool of this pack that reads
it, once per input, and the whole answer of every call is kept.

detect says whether the target holds an artefact of a family this recipe reads. A directory is walked for at most
WINDOWS_ARTEFACTS_DETECT_SECONDS (default 120, at most 280 of the harness's 300) and the answer says if it was cut short: a
walk that ran out of time and found nothing is `could not tell` (exit 2), never `does not apply`. A file is classified by its
name and its first bytes.

run reads each family in turn and writes, under DIR, one directory per family (`results.jsonl`: one line per tool call with
its arguments, exit code and the whole answer; the files the tools wrote are beside it), an `index.tsv` naming every file, and
`coverage.json`. The status of a family is
  parsed         every input of the family was read and the tool said complete;
  partial        some inputs were read and some were not, or a tool said partial (counts say which);
  empty          the tool ran and found no record in what it read;
  unsupported    the tool refused the input as not what it reads;
  failed         the tool failed on every input (or was killed by its time limit);
  not_attempted  nothing of the family was in the collection, the recipe's time was used, or the tool is not in this pack;
`complete` for the whole run means every family with an input was parsed or empty and no family was cut short: it is not
coverage of the host. Registry hives are handed to registry_recover with the transaction logs found beside them in the
collection, named in the family's results. When the target is one directory and target-query (dissect.target) is installed, a
fixed list of its functions that read what no tool of this pack does is run one call each (stdout and stderr of every call kept
whole in files); a function the installed version does not have is `unsupported`, and a missing target-query is `not_attempted`
with that reason. Plaso is not run (the base pack's disk-timeline recipe runs it over a disk image).

Processes. Every tool runs in this process's own group, never a session of its own, so the harness ending the recipe by killing
its group ends them; SIGTERM, SIGINT and SIGHUP end the running tool, write the receipt as partial and exit 128 + the signal. In that
receipt the family being read is `interrupted` (its counts are the calls that had ended), every family not yet started is
`not_attempted` with its inputs and calls counted, and the status text says only that.

Leftovers. The shared process block's settle() ends, when a program has ended, every process it left behind (in the group, in a session of its own, or with no descriptor of ours), before the
files of the call are sized or counted. A dissect-target call that left one ends `partial` (its row in results.jsonl carries `process`), coverage.json carries `program_group` at its top level, and a
receipt that would be `complete` is `partial` when a leftover was ended or, on a host that is not Linux or where the kernel refuses PR_SET_CHILD_SUBREAPER, when none can be ruled out.

Logs. The files beside a hive named for its logs (.LOG1, .LOG2, and a legacy single .LOG when there is no pair) are looked at with lstat:
a symbolic link (dangling or not), a directory or a pipe is never followed, opened or handed to registry_recover. The hive is read
without it, the row names it under `log_files_not_used`, and the hive's call ends `partial` at best.
"""
import json
import os
import re
import shutil
import signal
import stat
import subprocess
import sys
import time
import traceback
from pathlib import Path

# The harness gives a detect step 300 seconds; this one stops itself earlier, whatever the environment says.
MAX_DETECT_SECONDS = 280
try:
    DETECT_SECONDS = min(MAX_DETECT_SECONDS, max(1, int(os.environ.get("WINDOWS_ARTEFACTS_DETECT_SECONDS", "120"))))
except ValueError:
    DETECT_SECONDS = 120
MAX_WALK_ENTRIES = 2_000_000
RUN_SECONDS = 3300                  # recipe.json allows 3600; no call is started past this
PER_CALL_CAP = 600
NOT_COVERED = ("Plaso (not run by this recipe), PowerShell block reassembly / WMI repository / $LogFile (no reader in this pack), the rows of "
               "SRUM (this recipe lists the tables of SRUDB.dat and reads none; the srum_reader tool reads SRUDB.dat through SrumECmd or dissect.target and this recipe does not run it; dissect.target's own srum output is kept here when it is installed), UserAssist / BAM / ShimCache (read by the userassist_bam_shimcache tool, which this recipe does not run; dissect.target's own output of the same functions is kept beside it as a second reading, when it is installed), "
               "deleted and unallocated data, volume shadow copies, memory")

HIVE_NAMES = {"system", "software", "sam", "security", "default", "ntuser.dat", "usrclass.dat", "amcache.hve", "components", "drivers", "bbi", "elam"}
ESE_NAMES = {"srudb.dat", "webcachev01.dat"}
SQLITE_MAGIC = b"SQLite format 3\x00"
EVTX_MAGIC = b"ElfFile\x00"
REGF_MAGIC = b"regf"
SCCA_MAGICS = (b"SCCA", b"MAM\x04")
ESE_MAGIC_AT_4 = b"\xef\xcd\xab\x89"


def answer(value, code=0):
    if value.get("ok") is False and "status" not in value:
        value = {**value, "status": "failed", "status_basis": value.get("error", "the recipe stopped with an error")}
    print(json.dumps(value))
    raise SystemExit(code)


def describe(exc):
    return "%s: %s" % (type(exc).__name__, exc)


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


# ---- classifying a file -------------------------------------------------------------------------------------------------------

def head_of(path, n=16):
    """The first bytes of a regular file. A pipe, a socket or a device is never read (it is opened without waiting, and only to be refused)."""
    try:
        fd = os.open(path, os.O_RDONLY | getattr(os, "O_NONBLOCK", 0) | getattr(os, "O_CLOEXEC", 0))
    except OSError:
        return b""
    try:
        if not stat.S_ISREG(os.fstat(fd).st_mode):
            return b""
        return os.read(fd, n)
    except OSError:
        return b""
    finally:
        os.close(fd)


USN_NAMES = ("$j", "$usnjrnl$j", "usnjrnl_j", "$usnjrnl_$j")
BROWSER_NAMES = ("history", "places.sqlite")


def in_recycle_bin(path):
    parts = [p.lower() for p in Path(path).parts]
    return any(p.startswith("$recycle.bin") or p == "recycler" for p in parts[:-1])


def classify(path):
    """The family a file belongs to, by its name and then, for the families whose name is not enough, its first bytes; or None.
    The bytes of a file whose name is none of the names below are not read."""
    low = os.path.basename(path).lower()
    if low.endswith(".lnk") or low.endswith("destinations-ms"):
        return "shortcuts-jumplists"
    if low == "$mft":
        return "mft"
    if low in HIVE_NAMES:
        return "registry-hives" if head_of(path)[:4] == REGF_MAGIC else None
    if low.endswith(".pf"):
        head = head_of(path)
        return "prefetch" if (head[:4] in SCCA_MAGICS or head[4:8] == b"SCCA") else None
    if low.endswith(".evtx"):
        return "event-logs" if head_of(path)[:8] == EVTX_MAGIC else None
    if low in ESE_NAMES:
        return "esedb" if head_of(path)[4:8] == ESE_MAGIC_AT_4 else None
    if low in USN_NAMES:
        return "usn-journal" if head_of(path) else None
    if low.startswith("$i") and in_recycle_bin(path):
        return "recycle-bin" if len(head_of(path)) >= 8 else None
    if low in BROWSER_NAMES:
        return "browser-history" if head_of(path)[:16] == SQLITE_MAGIC else None
    return None


def walk(paths, deadline):
    """[(family, absolute path)] for every file under the paths, links not followed; (found, cut short, entries seen)."""
    found, seen, cut = [], 0, False
    for top in paths:
        top = os.path.abspath(top)
        if os.path.isfile(top):
            seen += 1
            family = classify(top)
            if family:
                found.append((family, top))
            continue
        for root, dirs, files in os.walk(top, followlinks=False):
            dirs.sort()
            if time.monotonic() > deadline:
                cut = True
                break
            for name in sorted(files):
                seen += 1
                if seen > MAX_WALK_ENTRIES:
                    cut = True
                    break
                full = os.path.join(root, name)
                try:
                    if not stat.S_ISREG(os.lstat(full).st_mode):
                        continue      # a link is not followed; a pipe, a socket or a device is not read
                except OSError:
                    continue
                family = classify(full)
                if family:
                    found.append((family, full))
            if cut:
                break
        if cut:
            break
    return found, cut, seen


def target_value(raw):
    try:
        value = json.load(open(raw, encoding="utf-8")) if os.path.isfile(raw) else json.loads(raw)
    except (OSError, ValueError) as exc:
        answer({"ok": False, "error": "target is not readable JSON: %s" % describe(exc)}, 2)
    paths = value.get("paths") if isinstance(value, dict) else None
    if not isinstance(paths, list) or not paths or not all(isinstance(p, str) and p for p in paths):
        answer({"ok": False, "error": "target has no paths"}, 2)
    name = value.get("name")
    return paths, name if isinstance(name, str) and name else paths[0]


def detect(paths):
    deadline = time.monotonic() + DETECT_SECONDS
    for p in paths:
        try:
            kind = os.stat(p).st_mode
        except (OSError, ValueError):
            kind = None
        if kind is not None and not (stat.S_ISREG(kind) or stat.S_ISDIR(kind)):
            answer({"applies": "unknown", "status": "failed", "status_basis": "a target path is not a regular file or a directory, so nothing was examined", "why": "a target path is not a regular file or a directory (a FIFO, a device or a socket is not opened)"}, 2)
        if not os.path.exists(p):
            answer({"applies": "unknown", "status": "failed", "status_basis": "a target path does not exist, so nothing was examined", "why": "a target path does not exist"}, 2)
    found, cut, seen = walk(paths, deadline)
    families = sorted({f for f, _ in found})
    if families:
        answer({"applies": True, "status": "complete" if not cut else "partial",
                "status_basis": "found artefact files of %d family(ies) among %d entries%s" % (len(families), seen, "; the walk was cut short, so others may exist" if cut else ""),
                "why": "the target holds Windows artefact files this recipe reads: %s (%d file(s))" % (", ".join(families), len(found))})
    if cut:
        answer({"applies": "unknown", "status": "failed", "status_basis": "the walk of the target ended at its time or entry limit before it found an artefact, so nothing is closed",
                "why": "examined %d entries in %d seconds without finding a Windows artefact; the rest was not examined" % (seen, DETECT_SECONDS)}, 2)
    answer({"applies": False, "status": "complete", "status_basis": "every file of the target was classified by name and first bytes",
            "why": "none of %d entries is a registry hive, event log, prefetch file, link, jump list, $MFT, $J, SRUM or WebCache database, $I file or browser history database" % seen}, 1)


# ---- running the tools --------------------------------------------------------------------------------------------------------

TOOLS_DIR = Path(__file__).resolve().parents[2] / "tools"


def tool_timeout(tool):
    try:
        return int(json.load(open(TOOLS_DIR / tool / "manifest.json")).get("timeout_seconds", 120))
    except (OSError, ValueError):
        return 120


def run_tool(tool, args, cwd, seconds):
    """One call of a tool of this pack. Returns (exit code or None, the answer or None, stdout text, stderr text, timed out, why)."""
    entry = TOOLS_DIR / tool / "run.py"
    if not entry.is_file():
        return None, None, "", "", False, "the tool %s is not in this pack" % tool
    env = dict(os.environ)
    env.setdefault("AGENT_ID", "windows-artefacts")
    try:
        proc = spawn([sys.executable, str(entry)], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, cwd=str(cwd), env=env)
    except OSError as exc:
        return None, None, "", "", False, "the tool could not be started: %s" % describe(exc)
    ACTIVE.append(proc)
    try:
        out, err, timed_out = communicate_bounded(proc, max(1.0, seconds), json.dumps(args).encode("utf-8"))
    finally:
        if proc in ACTIVE:
            ACTIVE.remove(proc)
    text = out.decode("utf-8", "replace")
    parsed = None
    try:
        parsed = json.loads(text)
    except ValueError:
        pass
    return (None if timed_out else proc.returncode), parsed, text, err.decode("utf-8", "replace")[-2000:], timed_out, None


def beside(path, suffixes):
    """({suffix: file}, {suffix: why not}) for the files beside `path` whose name is its name plus one of the suffixes, matched without regard to case. Only a regular
    file is returned: a symbolic link (dangling or not), a directory or a pipe with such a name is never followed or opened, and is named with the reason."""
    directory, name = os.path.split(path)
    try:
        listing = os.listdir(directory)
    except OSError:
        return {}, {}
    wanted = {name.lower() + s.lower(): s for s in suffixes}
    found, refused = {}, {}
    for f in sorted(listing):
        suffix = wanted.get(f.lower())
        if suffix is None:
            continue
        full = os.path.join(directory, f)
        try:
            mode = os.lstat(full).st_mode
        except OSError as exc:
            refused[suffix] = (full, "could not be examined: %s" % describe(exc))
            continue
        if not stat.S_ISREG(mode):
            refused[suffix] = (full, ("a symbolic link" if stat.S_ISLNK(mode) else "not a regular file") + ": not followed and not passed to registry_recover")
        elif suffix not in found:
            found[suffix] = full
    return found, refused


def minimal_directories(files):
    """The fewest directories that hold all the files: a directory whose ancestor is already in the set is left out."""
    dirs = sorted({os.path.dirname(f) for f in files}, key=lambda d: (d.count(os.sep), d))
    kept = []
    for d in dirs:
        if not any(d == k or d.startswith(k + os.sep) for k in kept):
            kept.append(d)
    return kept


LOG_NOTES = {}           # hive -> what was said about the logs beside it (a link not followed, a legacy .LOG)
LOG_REFUSED = {}         # hive -> the log files beside it that were not passed (a symbolic link, a directory): the hive is read without them


def calls_for(family, files):
    """[(label, tool, args)] for a family's files."""
    if family == "registry-hives":
        out = []
        for f in files:
            logs, refused = beside(f, [".LOG1", ".LOG2", ".LOG"])
            args = {"hive": f, "limit": 1}
            notes = ["%s (%s) is %s" % (os.path.basename(full), suffix, why) for suffix, (full, why) in sorted(refused.items())]
            if ".LOG1" in logs:
                args["log1"] = logs[".LOG1"]
            if ".LOG2" in logs:
                args["log2"] = logs[".LOG2"]
            if ".LOG" in logs:
                if ".LOG1" in logs or ".LOG2" in logs:
                    notes.append("%s is a legacy single log beside a .LOG1/.LOG2 pair: it was not passed" % os.path.basename(logs[".LOG"]))
                else:
                    args["log1"] = logs[".LOG"]
                    notes.append("%s is a legacy single log (before Windows 8.1): passed as log1" % os.path.basename(logs[".LOG"]))
            if notes:
                LOG_NOTES[f] = notes
            if refused:
                LOG_REFUSED[f] = [full for full, _why in refused.values()]
            out.append((f, "registry_recover", args))
        return out
    if family == "shortcuts-jumplists":
        return [(d, "lnk_jumplist", {"path": d, "limit": 1}) for d in minimal_directories(files)]
    if family == "prefetch":
        return [(f, "prefetch_mam", {"path": f}) for f in files]
    if family == "event-logs":
        return [(f, "evtx_query", {"path": f, "limit": 1}) for f in files]
    if family == "recycle-bin":
        return [(d, "recyclebin_i", {"path": d, "limit": 1}) for d in minimal_directories(files)]
    if family == "mft":
        return [(f, "mft_records", {"path": f, "limit": 1}) for f in files]
    if family == "usn-journal":
        return [(f, "usn_journal", {"path": f, "limit": 1}) for f in files]
    if family == "esedb":
        return [(f, "esedb_query", {"path": f, "limit": 1}) for f in files]
    if family == "browser-history":
        out = []
        for f in files:
            queries = ("firefox_visits", "firefox_downloads") if os.path.basename(f).lower() == "places.sqlite" else ("chrome_visits", "chrome_downloads")
            out += [(f + " [" + q + "]", "browser_history", {"path": f, "query": q, "limit": 1}) for q in queries]
        return out
    return []


EXTRA_CALLS = {
    "amcache": ("registry-hives", lambda f: os.path.basename(f).lower() == "amcache.hve", "amcache_apps", lambda f: {"hive": f, "limit": 1}),
    "shellbags": ("registry-hives", lambda f: os.path.basename(f).lower() in ("ntuser.dat", "usrclass.dat"), "shellbags", lambda f: {"hive": f, "limit": 1}),
}

FAMILIES = ["registry-hives", "amcache", "shellbags", "prefetch", "shortcuts-jumplists", "event-logs", "recycle-bin", "mft", "usn-journal", "esedb", "browser-history"]
DISSECT_FUNCTIONS = ["userassist", "bam", "shimcache", "srum", "services", "runkeys", "tasks"]   # srum: srum_reader reads SRUDB.dat and this recipe does not run it, so dissect.target's own output is a second reading; services, runkeys and tasks: persistence_normalise reads them, and this recipe does not run it; userassist, bam and shimcache: dissect.target's own output, a second reading beside userassist_bam_shimcache (this recipe does not run that tool)
DISSECT_FUNCTION_SECONDS = 900
NOT_RUN = {
    "plaso": "Plaso is not run by this recipe: the disk-timeline recipe of the base pack runs it over a disk image, and a directory of extracted artefacts is not a source it takes",
}


def probe(argv, seconds):
    """The standard output of a short program (target-query --help or --version), run like every other program of this recipe: in this process's group, ended with what it started
    at its time limit, and settled when it has ended. '' when it could not be started."""
    try:
        proc = spawn(argv, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    except OSError:
        return ""
    ACTIVE.append(proc)
    try:
        out, _err, _timed_out = communicate_bounded(proc, seconds)
    finally:
        if proc in ACTIVE:
            ACTIVE.remove(proc)
    return out.decode("utf-8", "replace")


def dissect_stage(paths, out, deadline, limits):
    """The functions of dissect.target that read what no tool of this pack does, one call each, over a target that is one directory.
    Returns the family's receipt entry. Every call's whole stdout and stderr are kept in files; nothing here reads a record."""
    fam = {"tool": "target-query", "inputs": 0, "calls": 0, "counts": {"parsed": 0, "partial": 0, "empty": 0, "unsupported": 0, "failed": 0, "not_attempted": 0}}
    binary = shutil.which("target-query")
    if not binary:
        fam.update(status="not_attempted", reason="target-query (dissect.target) is not installed in this image, so none of its functions was run")
        return fam
    if len(paths) != 1 or not os.path.isdir(paths[0]):
        fam.update(status="not_attempted", reason="dissect.target opens one target, and this target is not exactly one directory, so none of its functions was run")
        return fam
    help_text = probe([binary, "--help"], 60)
    fam["inputs"] = 1
    fam["version_output"] = probe([binary, "--version"], 60).strip()[:300] or None
    json_flag = ["--json"] if "--json" in help_text else []
    fam["records_format"] = "one JSON object per line" if json_flag else "the program's default text form (this version lists no --json)"
    fdir = out / "dissect-target"
    fdir.mkdir(exist_ok=True)
    with (fdir / "results.jsonl").open("w", encoding="utf-8") as results:
        for name in DISSECT_FUNCTIONS:
            fam["calls"] += 1
            if time.monotonic() > deadline:
                fam["counts"]["not_attempted"] += 1
                limits.append("dissect-target: %s was not started: the recipe's own time was used" % name)
                results.write(json.dumps({"input": paths[0], "tool": "target-query", "function": name, "state": "not_attempted", "why": "the recipe's own time was used"}) + "\n")
                continue
            argv = [binary, "-f", name] + json_flag + [paths[0]]
            out_file, err_file = fdir / (name + ".out"), fdir / (name + ".stderr")
            timed_out, code = False, None
            ended_before = process_verdict()["left_behind"]
            with out_file.open("wb") as o, err_file.open("wb") as e:
                try:
                    proc = spawn(argv, stdout=o, stderr=e)
                except OSError as exc:
                    code, timed_out = None, False
                    e.write(("could not be started: %s\n" % describe(exc)).encode())
                else:
                    ACTIVE.append(proc)
                    try:
                        code = proc.wait(timeout=max(1.0, min(DISSECT_FUNCTION_SECONDS, deadline - time.monotonic())))
                    except subprocess.TimeoutExpired:
                        kill_tree(proc)
                        proc.wait()
                        timed_out = True
                    finally:
                        if proc in ACTIVE:
                            ACTIVE.remove(proc)
            size = out_file.stat().st_size
            try:
                err_text = err_file.read_bytes()[-4000:].decode("utf-8", "replace")
            except OSError:
                err_text = ""
            records = None
            if json_flag and size:
                with out_file.open("rb") as fh:
                    records = sum(1 for line in fh if line.strip())
            if timed_out or code is None:
                state = "failed"
                limits.append("dissect-target: %s was killed at its time limit" % name)
            elif code != 0:
                state = "unsupported" if re.search(r"unknown (plugin|function)|no (such )?(plugin|function)|PluginNotFound|not a valid (plugin|function)|invalid choice|unrecognized arguments", err_text, re.I) else "failed"
            elif size == 0:
                state = "empty"
            else:
                state = "parsed"
            # The .out and .stderr files are what target-query wrote: a process it left behind was ended by settle() before they were sized and counted, so they are stable but may be short; where one
            # cannot be ruled out (not Linux, or PR_SET_CHILD_SUBREAPER refused) they cannot be shown to be final. Either way the call is at best partial.
            verdict = process_verdict()
            left = verdict["left_behind"] - ended_before
            process = None
            if left > 0:
                process = "target-query left %d process(es) running after it ended; they were ended before its files were sized, so the files may be short" % left
            elif verdict["unproven"]:
                process = verdict["unproven"][0] + ": the files of this call cannot be shown to be final"
            if process and state in ("parsed", "empty"):
                state = "partial"
                limits.append("dissect-target: %s: %s" % (name, process))
            fam["counts"][state] += 1
            results.write(json.dumps({"input": paths[0], "tool": "target-query", "function": name, "argv": argv[:-1] + ["<target>"], "exit_code": code, "timed_out": timed_out,
                                      "state": state, "records": records, "stdout_bytes": size, "stdout_file": "dissect-target/" + out_file.name,
                                      "stderr_file": "dissect-target/" + err_file.name, **({"process": process} if process else {})}) + "\n")
    c = fam["counts"]
    total = sum(c.values())
    if c["not_attempted"] == total:
        fam["status"], fam["reason"] = "not_attempted", "no function was started (the recipe's own time was used)"
    elif c["failed"] + c["unsupported"] == total:
        fam["status"], fam["reason"] = ("unsupported" if c["unsupported"] == total else "failed"), "no function produced a result (see results.jsonl and the .stderr files)"
    elif c["parsed"] + c["empty"] == total:
        fam["status"], fam["reason"] = ("empty" if c["empty"] == total else "parsed"), "every function exited 0"
    else:
        fam["status"], fam["reason"] = "partial", "functions ended: " + ", ".join("%d %s" % (v, k) for k, v in c.items() if v)
    return fam


def recovered_path(shown, cwd):
    """The file a registry_recover answer names as its recovered copy, as this process can open it: in a job the answer says
    store/jobs/<job>/out/<rest> and the file is at $OUT/<rest>; outside a job the name is from the tool's working directory."""
    if not isinstance(shown, str) or not shown:
        return None
    out = os.environ.get("OUT")
    m = re.fullmatch(r"store/jobs/[A-Za-z0-9_.-]+/out/(.+)", shown)
    path = Path(out) / m.group(1) if (m and out and os.environ.get("JOB_ID")) else Path(cwd) / shown
    return str(path) if path.is_file() and not path.is_symlink() else None


def judge(answer_json, code, timed_out):
    """(state, records) of one call: parsed, partial, empty, unsupported or failed, from what the tool said."""
    if timed_out or code is None:
        return "failed", None
    if not isinstance(answer_json, dict):
        return "failed", None
    if code != 0:
        error = str(answer_json.get("error", ""))
        if re.search(r"not a (LNK|hive|regf)|not an? .*(file|database|header)|signature|not a registry|is not an|no jump list files|neither", error, re.I):
            return "unsupported", None
        return "failed", None
    status = answer_json.get("status")
    records = None
    for key in ("entry_count", "event_count", "matched", "records_read", "count", "link_count", "nodes_listed", "keys"):
        value = answer_json.get(key)
        if isinstance(value, int) and not isinstance(value, bool):
            records = value
            break
    if isinstance(answer_json.get("records"), dict):
        value = answer_json["records"].get("keys")
        if isinstance(value, int):
            records = value
    if status == "partial":
        return "partial", records
    if records == 0:
        return "empty", 0
    return "parsed", records


def main_run(paths, shown, out):
    try:
        out.mkdir(parents=True, exist_ok=True)
    except OSError as exc:
        answer({"ok": False, "error": "the output directory could not be made: %s" % describe(exc), "out": str(out)}, 2)
    began = time.monotonic()
    deadline = began + RUN_SECONDS
    receipt = {"recipe": "windows-artefacts", "status": "partial", "status_basis": "the recipe had not finished: nothing is established yet", "covered": "nothing yet",
               "not_covered": NOT_COVERED, "families": {}, "errors": [], "receipt_written": "before the first tool ran"}

    def write_receipt(state):
        receipt["receipt_written"] = state
        try:
            (out / "coverage.json").write_text(json.dumps(receipt, indent=2) + "\n")
            write_index()
        except OSError as exc:
            answer({"ok": False, "status": "failed", "status_basis": "the recipe's own output could not be written", "error": "could not write the receipt: %s" % describe(exc)}, 2)

    def write_index():
        with (out / "index.tsv").open("w", encoding="utf-8") as index:
            index.write("coverage.json\tper family: status, why, tool, inputs, counts of parsed/partial/empty/unsupported/failed calls\n")
            for p in sorted(out.rglob("*")):
                if p.is_file() and p.name not in ("index.tsv", "coverage.json") and not p.name.startswith("."):
                    rel = p.relative_to(out).as_posix()
                    index.write("%s\t%s\n" % (rel, "one line per tool call: its arguments, exit code and whole answer" if p.name == "results.jsonl" else "written by the tool of the family"))

    write_receipt("before the first tool ran")

    plan = {}               # family -> (tool, calls, files), set once the walk is done
    current = {"family": None}

    def stopped(signum, _frame):
        kill_all()
        receipt["program_group"] = process_verdict()
        # Every family gets a state: the one in flight is `interrupted` (its counts are the calls that had ended), a family not started is `not_attempted`
        # with its inputs and calls counted, and the ones the recipe does not run keep their reason.
        for fid in FAMILIES:
            fam = receipt["families"].get(fid)
            tool, calls, files = plan.get(fid, (None, [], []))
            if fam is None:
                receipt["families"][fid] = {"tool": tool or {"registry-hives": "registry_recover"}.get(fid), "inputs": len(files), "calls": len(calls) if plan else None,
                                            "status": "not_attempted",
                                            "reason": ("the recipe was terminated by signal %d before this family was started" % signum) if plan else
                                                      "the recipe was terminated by signal %d during the walk of the target: nothing of this family was looked for" % signum,
                                            "counts": {"parsed": 0, "partial": 0, "empty": 0, "unsupported": 0, "failed": 0, "not_attempted": len(calls)}}
            elif "status" not in fam:
                ended = sum(fam["counts"].values())
                fam["status"] = "interrupted"
                fam["reason"] = "the recipe was terminated by signal %d while this family was being read: %d of its %d call(s) had ended (counts), %d had not" % (signum, ended, fam["calls"], fam["calls"] - ended)
                fam["calls_not_ended"] = fam["calls"] - ended
        if "dissect-target" not in receipt["families"]:
            receipt["families"]["dissect-target"] = {"tool": "target-query", "inputs": None, "calls": None,
                                                     "status": "interrupted" if current["family"] == "dissect-target" else "not_attempted",
                                                     "reason": "the recipe was terminated by signal %d %s" % (signum, "while its functions were running" if current["family"] == "dissect-target" else "before this stage was started"),
                                                     "counts": {}}
        for fid, why in NOT_RUN.items():
            receipt["families"].setdefault(fid, {"tool": None, "inputs": 0, "calls": 0, "status": "not_attempted", "reason": why, "counts": {}})
        receipt["status"] = "partial"
        receipt["status_basis"] = ("the recipe was terminated by signal %d before it finished: a family marked parsed, partial, empty, unsupported or failed had ended; the family that was being read is "
                                   "marked interrupted (its counts are the calls that had ended); every family that was not started is marked not_attempted" % signum)
        receipt["errors"].append("the recipe was terminated by signal %d; the receipt is complete as to which families ended, were interrupted or were not started, and says nothing more" % signum)
        write_receipt("after this process was terminated")
        os._exit(128 + signum)

    for signum in (signal.SIGTERM, signal.SIGINT, signal.SIGHUP):
        signal.signal(signum, stopped)

    found, cut, seen = walk(paths, deadline)
    by_family = {}
    for family, full in found:
        by_family.setdefault(family, []).append(full)
    for fam in by_family.values():
        fam.sort()
    receipt["walk"] = {"entries_seen": seen, "files_found": len(found), "cut_short": cut}
    for fid in FAMILIES:
        if fid in EXTRA_CALLS:
            parent, pick, tool, mk = EXTRA_CALLS[fid]
            files = [f for f in by_family.get(parent, []) if pick(f)]
            plan[fid] = (tool, [(f, tool, mk(f)) for f in files], files)
        else:
            files = by_family.get(fid, [])
            calls = calls_for(fid, files)
            plan[fid] = (calls[0][1] if calls else None, calls, files)
    limits = []
    recovered = {}      # hive path -> the recovered copy registry_recover made of it, when it replayed something
    for fid in FAMILIES:
        tool, calls, files = plan[fid]
        fam = {"tool": tool or {"registry-hives": "registry_recover"}.get(fid), "inputs": len(files), "calls": len(calls), "counts": {"parsed": 0, "partial": 0, "empty": 0, "unsupported": 0, "failed": 0, "not_attempted": 0}}
        receipt["families"][fid] = fam
        current["family"] = fid
        if not calls:
            fam["status"] = "not_attempted"
            fam["reason"] = "no file of this family is in the target" + ("; the walk was cut short, so one may exist unseen" if cut else "")
            continue
        fdir = out / fid
        fdir.mkdir(exist_ok=True)
        with (fdir / "results.jsonl").open("w", encoding="utf-8") as results:
            for label, tool_name, args in calls:
                if time.monotonic() > deadline:
                    fam["counts"]["not_attempted"] += 1
                    limits.append("%s: %s was not started: the recipe's own time (%d seconds) was used" % (fid, label, RUN_SECONDS))
                    results.write(json.dumps({"input": label, "tool": tool_name, "state": "not_attempted", "why": "the recipe's own time was used"}) + "\n")
                    continue
                seconds = min(PER_CALL_CAP, tool_timeout(tool_name) + 15, max(1.0, deadline - time.monotonic()))
                note = None
                if fid in EXTRA_CALLS and args.get("hive") in recovered:
                    # The hive was dirty and registry_recover replayed its logs: the other hive tools read that copy, and the row says so.
                    note = "read from the recovered copy of %s made by registry_recover (the original is dirty; this is a derivative)" % args["hive"]
                    args = {**args, "hive": recovered[args["hive"]]}
                code, parsed, text, err, timed_out, why = run_tool(tool_name, args, fdir, seconds)
                if tool_name == "registry_recover" and isinstance(parsed, dict) and parsed.get("replayed") is True:
                    copy = recovered_path(parsed.get("recovered_copy"), fdir)
                    if copy:
                        recovered[args["hive"]] = copy
                if why:
                    state = "not_attempted"
                    fam["counts"]["not_attempted"] += 1
                    results.write(json.dumps({"input": label, "tool": tool_name, "state": state, "why": why}) + "\n")
                    continue
                state, records = judge(parsed, code, timed_out)
                if tool_name == "registry_recover" and label in LOG_REFUSED and state in ("parsed", "empty"):
                    state = "partial"          # a log beside the hive was not used, so what the hive's logs hold is not in this answer
                fam["counts"][state] += 1
                if timed_out:
                    limits.append("%s: %s was killed at %d seconds" % (fid, label, int(seconds)))
                row = {"input": label, "tool": tool_name, "arguments": args, "note": note, "log_notes": LOG_NOTES.get(label), "log_files_not_used": LOG_REFUSED.get(label), "exit_code": code, "timed_out": timed_out, "state": state, "records": records,
                       "answer": parsed if parsed is not None else text, "stderr_tail": err or None}
                results.write(json.dumps(row) + "\n")
        c = fam["counts"]
        total = sum(c.values())
        if c["not_attempted"] == total:
            fam["status"], fam["reason"] = "not_attempted", "no call was made (time used or the tool is not in this pack)"
        elif c["failed"] == total:
            fam["status"], fam["reason"] = "failed", "every call failed (see results.jsonl)"
        elif c["unsupported"] == total:
            fam["status"], fam["reason"] = "unsupported", "the tool refused every input as not what it reads"
        elif c["empty"] == total:
            fam["status"], fam["reason"] = "empty", "the tool ran and found no record in what it read"
        elif c["parsed"] + c["empty"] == total:
            fam["status"], fam["reason"] = "parsed", "every call ended complete"
        else:
            fam["status"], fam["reason"] = "partial", "calls ended: " + ", ".join("%d %s" % (v, k) for k, v in c.items() if v)
        write_receipt("after family %s" % fid)
    current["family"] = "dissect-target"
    receipt["families"]["dissect-target"] = dissect_stage(paths, out, deadline, limits)
    write_receipt("after family dissect-target")
    for fid, why in NOT_RUN.items():
        receipt["families"][fid] = {"tool": None, "inputs": 0, "calls": 0, "status": "not_attempted", "reason": why, "counts": {}}
    statuses = [f["status"] for f in receipt["families"].values() if f["inputs"]]
    bad = [k for k, f in receipt["families"].items() if f["inputs"] and f["status"] not in ("parsed", "empty")]
    receipt["limits_hit"] = limits
    if cut:
        receipt["errors"].append("the walk of the target was cut short: files may exist that were not seen")
    if not statuses and cut:
        receipt["status"], receipt["status_basis"] = "failed", "the walk of the target was cut short before it found an artefact of a family this recipe reads, so nothing is established"
    elif not statuses:
        receipt["status"], receipt["status_basis"] = "failed", "the target held no artefact of a family this recipe reads"
    elif bad or cut or limits:
        receipt["status"] = "partial"
        receipt["status_basis"] = "%d of %d families with an input were parsed or empty%s%s" % (
            len(statuses) - len(bad), len(statuses), ("; not: " + ", ".join("%s (%s)" % (k, receipt["families"][k]["status"]) for k in bad)) if bad else "",
            "; the walk was cut short" if cut else "")
    else:
        receipt["status"] = "complete"
        receipt["status_basis"] = "every family with an input in the target was read by its tool and ended parsed or empty (%d); the families not run are named: this is not coverage of the host" % len(statuses)
    receipt["covered"] = "the files of %s found in %s by name and first bytes, each read by the tool of this pack for it" % (", ".join(sorted(k for k in FAMILIES if receipt["families"][k]["inputs"])) or "no family", shown) + ("; and the dissect.target functions listed in the receipt over the target directory" if receipt["families"]["dissect-target"]["inputs"] else "")
    process_apply(receipt)      # program_group at the top of coverage.json: what settle() ended and why the absence of a leftover is unproven; a complete receipt becomes partial
    write_receipt("after the last family")
    answer({"ok": receipt["status"] != "failed", "status": receipt["status"], "status_basis": receipt["status_basis"],
            "families": {k: v["status"] for k, v in receipt["families"].items()}}, 0 if receipt["status"] != "failed" else 2)


def main():
    command = sys.argv[1] if len(sys.argv) > 1 else ""
    target = out = None
    args = iter(sys.argv[2:])
    for arg in args:
        if arg == "--target":
            target = next(args, None)
        elif arg == "--out":
            out = next(args, None)
        elif arg == "--probe-out":
            next(args, None)
        else:
            answer({"ok": False, "error": "unknown argument: %s" % arg}, 2)
    if not target:
        answer({"ok": False, "error": "--target is required"}, 2)
    paths, shown = target_value(target)
    if command == "detect":
        install_signal_handlers()
        detect(paths)
    if command == "run" and out:
        if not all(os.path.exists(p) for p in paths):
            answer({"ok": False, "error": "a target path does not exist"}, 2)
        main_run(paths, shown, Path(out))
    answer({"ok": False, "error": "usage: run.py detect --target T | run --target T --out DIR"}, 2)


# BEGIN SHARED LEAVE
# The same text is in every pack tool and recipe and in their tool-library twins (tests/shared-blocks-census.test.ts holds the copies equal):
# how a call ends once its answer has begun. The interpreter's own teardown resets the signal handlers to their defaults before it frees what
# the call held, and a stop signal that landed there killed a process that had printed its whole answer; a handler that raises or writes a
# last word, run after the answer was out, wrote a second document or a traceback after a whole one. So, when the file runs as a program:
# * Standard output is wrapped, and its first write is the first byte of the answer: from there the stop signals are held for good (blocked
#   in this thread, and given a handler that does nothing for any other), so no handler runs into the answer or after it, and an error Python
#   can only report (a file the call left open whose last write the file system refuses, closed when the frame that held it is freed) is
#   not printed (Python 3.11 and 3.12 say nothing of it; 3.14 prints a traceback). A handler that was already due runs on the way in, before
#   any byte is written, and its own answer is then the one.
# * _code(stop) is a SystemExit's exit code, and _leave(code) ends the call: both hold the signals first; _leave then flushes standard output
#   and standard error, runs the atexit hooks (a hook that removes a temporary file), each step on its own and none able to raise, and ends
#   the process with os._exit, never through the teardown. A stop signal after the hold is not answered: the exit code is the call's own.
# The modules are imported here, as the file is loaded, never inside the ending (an import there ran a due handler inside the import system).
import atexit
import os
import signal
import sys

_ENDING = {"held": False}
_ENDING_SIGNALS = (signal.SIGTERM, signal.SIGINT, signal.SIGHUP)


def _ending_nothing(*_ignored):
    """The stop signals' handler, and sys.unraisablehook, once the answer has begun: nothing."""


def hold_stop_signals():
    """Hold the stop signals for good. A handler that was due runs first, in the first call that can run it, and may raise: that is before
    any byte of the answer is written. Called by a thread that is not the main one, it blocks the signals there and leaves the rest to the
    main thread's next write."""
    if _ENDING["held"]:
        return
    try:
        signal.pthread_sigmask(signal.SIG_BLOCK, _ENDING_SIGNALS)
    except (AttributeError, ValueError, OSError):
        pass                          # no pthread_sigmask here: the handler below holds them
    main_thread = True
    for signum in _ENDING_SIGNALS:
        try:
            signal.signal(signum, _ending_nothing)
        except (ValueError, OSError):
            main_thread = False
    sys.unraisablehook = _ending_nothing
    _ENDING["held"] = main_thread


def _hold_at_the_end():
    for _attempt in range(len(_ENDING_SIGNALS) + 2):
        try:
            hold_stop_signals()
            return
        except BaseException:  # noqa: BLE001 - a handler that was due ran on the way in; the hold is made again
            continue


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
    _hold_at_the_end()
    code = getattr(stop, "code", 1)
    return code if isinstance(code, int) else (0 if code is None else 1)


def _leave(code):
    _hold_at_the_end()
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.flush()
        except BaseException:  # noqa: BLE001 - a reader that is gone, a stream that is closed: the exit code is the call's own
            pass
    try:
        atexit._run_exitfuncs()
    except BaseException:  # noqa: BLE001 - a hook that fails is not a failure of the answer
        pass
    code = code if isinstance(code, int) else 1
    os._exit(code)


if __name__ == "__main__" and sys.stdout is not None and not isinstance(sys.stdout, _AnswerStream):
    sys.stdout = _AnswerStream(sys.stdout)
# END SHARED LEAVE


if __name__ == "__main__":
    exit_code = 0
    try:
        try:
            main()
        except SystemExit:
            raise
        except Exception:
            traceback.print_exc()
            answer({"applies": "unknown", "status": "failed", "status_basis": "this recipe failed on an unexpected error (the traceback is on its stderr)", "why": "unexpected error"}, 2)
    except SystemExit as stop:
        exit_code = _code(stop)
    _leave(exit_code)
