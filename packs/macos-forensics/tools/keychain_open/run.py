#!/usr/bin/env python3
"""Open a macOS login or System keychain with the password the case supplies, and write every item to a sealed file.

This tool is declared `secret_output: required`: every job of it is a secret job. It opens a keychain only when the case gives the password as a job input
file (`password_file`, mode 0600; never a value in the arguments, in argv or in the environment) or, for `System.keychain`, the SystemKey file (`system_key`,
the file the machine kept under /var/db). It never guesses, recovers or cracks a password.

* The reader is chainbreaker, pinned in this pack's requires/host.json and installed in an environment of its own. It is run as a program in this tool's
  process group (never a session of its own), under the shared PROCESS block, with the password read by the reader's own process from the file and handed
  to the reader as a function argument. This tool itself never reads the password: it checks the file (a regular file, not a link, mode 0600) and names it.
* The keychain's first bytes decide whether it is read at all: 'kych' is the keychain file format of login.keychain-db, login.keychain and System.keychain.
  An SQLite file (the Local Items store, keychain-2.db) is answered `unsupported_format` with its reason, and so is any other file.
* Every item, metadata and value, goes to `keychain-items.jsonl` under $OUT, one JSON object per line, mode 0600, created exclusively, never replacing an
  earlier file (the shared PLACE block). The answer carries the outcome, counts per record class (records, decrypted, not decrypted, value bytes), and the
  file's name, size, line count and sha256; never a name, a value or a hash of one, and it prints no path it was given.
* The outcomes are told apart: opened, partial (opened, some records not decrypted or not read), wrong_secret (the reader could not unlock it with what was
  given), unsupported_format, damaged (truncated or unparseable), unavailable (the reader is not installed or not importable), secret_unreadable,
  reader_failed, storage_refused, timed_out and interrupted. Only `opened` is `complete`.
* SIGTERM, SIGINT and SIGHUP end the reader and what it started, keep the whole lines written, and end with one JSON answer and exit 128 + the signal.
"""
import errno
import hashlib
import json
import os
import re
import shutil
import stat
import struct
import subprocess
import sys
import time
from pathlib import Path
import selectors

# BEGIN SHARED STOP
# The same text is in every macos-forensics tool (a macos-forensics test holds the copies equal). SIGTERM, SIGINT and SIGHUP end a tool the way its
# time limit does: the work in hand is closed, what was done is kept and named, ONE JSON answer says status partial and `interrupted` (the signal's
# name), and the exit code is 128 plus the signal number. The handler raises Interrupted (a BaseException, so no `except Exception` swallows it) from
# wherever the signal lands; a write that must be whole (a row of a result file, the answer) is made under held(), and the signal is delivered when
# it ends, and hold_signals() holds them for good once the answer is being written; a signal that arrives meanwhile is found by pending_stop_signal() before the
# answer is printed, and the answer says so. The first signal counts: later ones do nothing while the tool cleans up. STOP["hooks"] run first (a database connection's
# interrupt, the kill of the reader process this tool started and of its descendants: its own, never a search by name). Until install_stop_handlers
# runs (at the end of the module) _early_stop answers a signal with one document that says nothing was read.
# Two limits are stated, not closed. (1) A signal that arrives before this block has run (the start of the interpreter, the compiling of the file, the
# imports above the block: tens of milliseconds) is not caught, and ends the tool with no JSON at all. (2) hold_signals() trades one whole document for a
# print that cannot be stopped: if whatever reads this tool's stdout stops reading a full pipe, only SIGKILL ends the tool (the harness ends a tool with a
# SIGKILL of its group, so its own path is not affected).
import signal

STOP = {"signal": None, "hooks": []}
STOP_SIGNALS = (signal.SIGTERM, signal.SIGINT, signal.SIGHUP)


class Interrupted(BaseException):
    def __init__(self, signum):
        super().__init__(signum)
        self.signum = signum


def signal_name(signum):
    try:
        return signal.Signals(signum).name
    except ValueError:
        return "signal %d" % signum


def _on_stop_signal(signum, _frame):
    if STOP["signal"] is not None:
        return
    STOP["signal"] = signum
    for hook in list(STOP["hooks"]):
        try:
            hook()
        except Exception:
            pass
    raise Interrupted(signum)


def check_stop():
    """Raise Interrupted again when a stop signal was seen but its exception was lost (a callback that sqlite called swallows exceptions)."""
    if STOP["signal"] is not None:
        raise Interrupted(STOP["signal"])


def install_stop_handlers():
    for signum in STOP_SIGNALS:
        signal.signal(signum, _on_stop_signal)


class held:
    """`with held():` the stop signals wait until the outermost block ends, so a row of a result file is written whole or not at all."""
    depth = 0

    def __enter__(self):
        if held.depth == 0:
            try:
                signal.pthread_sigmask(signal.SIG_BLOCK, set(STOP_SIGNALS))
            except (AttributeError, ValueError, OSError):
                pass
        held.depth += 1
        return self

    def __exit__(self, *exc):
        held.depth -= 1
        if held.depth == 0:
            try:
                signal.pthread_sigmask(signal.SIG_UNBLOCK, set(STOP_SIGNALS))
            except (AttributeError, ValueError, OSError):
                pass
        return False


def pending_stop_signal():
    """The stop signal that arrived while signals were held and was not delivered, or None (how a signal that lands while the answer is sealed is found)."""
    try:
        pending = signal.sigpending()
    except (AttributeError, OSError):
        return None
    for signum in STOP_SIGNALS:
        if signum in pending:
            return signum
    return None


def hold_signals():
    """Hold the stop signals for good: the work is done and the answer is being written, and a signal must not start a second one."""
    held.depth += 1
    try:
        signal.pthread_sigmask(signal.SIG_BLOCK, set(STOP_SIGNALS))
    except (AttributeError, ValueError, OSError):
        pass


def _early_stop(signum, _frame):
    """The handler of the time before install_stop_handlers: this block runs near the top of the module, and the tool's own handlers are
    installed when the module has run to its end. A stop signal in between ends the tool with one answer that says nothing was read."""
    for other in STOP_SIGNALS:
        signal.signal(other, signal.SIG_IGN)
    print(json.dumps({"error": "the tool was stopped by %s before it had read anything" % signal_name(signum), "status": "failed",
                      "status_basis": "stopped by %s during start-up: nothing was read" % signal_name(signum), "interrupted": signal_name(signum)}),
          flush=True)
    os._exit(128 + signum)


for _early in STOP_SIGNALS:
    signal.signal(_early, _early_stop)
# END SHARED STOP

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
SUB = {"tried": False, "on": False}        # whether the subreaper was asked for, and is on
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
            _unproven(_note("this host refused PR_SET_CHILD_SUBREAPER: a process a program left behind outside the walk is not adopted and may not be found"))
    else:
        reason = "this host cannot adopt orphaned processes (no PR_SET_CHILD_SUBREAPER): a process a program left behind may not be found"
        if NONLINUX_UNPROVEN_DOWNGRADE:
            _unproven(_note(reason))
        else:
            _note(reason)
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
        before = LEFT["left_behind"]
        ended += (_end_children if SUB["on"] else _end_seen)(found, deadline)
        LEFT["left_behind"] = before + (ended - (LEFT["left_behind"] - before) if False else 0) + 0
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
    return {"subreaper": SUB["on"], "left_behind": LEFT["left_behind"], "unproven": list(LEFT["unproven"]), "notes": process_notes()}


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

PARSER = "keychain_open/1"
READER = "chainbreaker"
ITEMS_NAME = "keychain-items.jsonl"
DEFAULT_MAX_SECONDS = 60.0            # the manifest allows 120 s: the clean-up and the answer come after this clock
MAX_SECONDS_LIMIT = 90.0
SECRET_FILE_MAX = 4096                # the largest password file or SystemKey file this tool accepts
KEYCHAIN_MAX = 256 << 20              # the largest keychain file named (the reader reads a file whole into memory); a larger one is refused, not cut
SUMMARY_MAX = 65536                   # the reader process's one summary line is read up to here
WRAPPER_MAX = 4096
CLASSES = ("generic_password", "internet_password", "appleshare_password", "x509_certificate", "public_key", "private_key")
STAGES = ("import", "secret", "open", "locked", "write", "read")
NAME_OK = re.compile(r"^[A-Za-z_][A-Za-z0-9_]{0,60}$")
TEMPS = []                            # temporary output files, registered before they are opened: removed on every way out unless they were placed

REFUSED_NOT_SECRET = (
    "keychain_open is refused outside a job run as secret output: every item it opens, metadata and value, is written to a sealed file, "
    "and the password is read from a file of the job. Run it as job_run(tool: \"keychain_open\", args: {...}); the manifest's "
    "secret_output: \"required\" makes every job of this tool one, and the harness then sets SECRET_OUTPUT=1 for the job's process, "
    "which this process does not have. Nothing was read and nothing was written."
)

UNSUPPORTED_SQLITE = (
    "this file is an SQLite database, the shape of the Local Items store (keychain-2.db, the data protection keychain). It is not opened here: "
    "the reader this tool drives reads only the older keychain file format (the file begins with 'kych'), and a password does not by itself "
    "unlock the Local Items store offline. Nothing was read from it and no route to it is provided."
)
UNSUPPORTED_OTHER = ("the file does not begin with 'kych', the signature of the keychain file format the reader reads (a login.keychain-db, a "
                     "login.keychain or a System.keychain), and is not an SQLite database: it is not opened here and nothing was read from it")

# What the reader process runs as, with the interpreter of the reader's own environment: python -I -c SHIM <pythonpath> <keychain>
# <password file> <system key file> <items fd> <summary fd>. It is part of this tool (the reader is imported by it, not run as its command
# line, which takes a password only on argv or from a terminal prompt). The password is read here, from its file, and handed to the reader
# as a function argument: it is never in this process's argument list, environment, standard streams or any file. What it writes: one JSON
# line per item to the items descriptor, and one summary line (counts and the name of an exception class, nothing else) to the summary
# descriptor. Its own standard output and error go nowhere.
SHIM = r'''
import base64, json, logging, math, os, sys
logging.disable(logging.CRITICAL)
pythonpath, keychain, pwfile, keyfile, outfd, sumfd = sys.argv[1], sys.argv[2], sys.argv[3], sys.argv[4], int(sys.argv[5]), int(sys.argv[6])


def finish(obj):
    data = (json.dumps(obj) + "\n").encode("ascii")
    try:
        os.write(sumfd, data)
    finally:
        os._exit(0)


def stop(stage, exc=None, **more):
    finish(dict(stage=stage, error=type(exc).__name__ if exc is not None else None, **more))


sys.path.insert(0, pythonpath)
try:
    from chainbreaker import Chainbreaker
except BaseException as exc:
    stop("import", exc)
password = None
if pwfile:
    try:
        with open(pwfile, "rb") as fh:
            raw = fh.read(4097)
        if raw.endswith(b"\n"):
            raw = raw[:-1]
        password = raw.decode("utf-8")
    except BaseException as exc:
        stop("secret", exc)
    if not password:
        stop("secret", None, empty=True)
try:
    kc = Chainbreaker(keychain, unlock_password=password, unlock_file=keyfile or None)
except BaseException as exc:
    stop("open", exc)
if kc.locked:
    stop("locked")

SKIP = {"SSGP", "DBKey", "Key", "IV", "logger", "locked", "password_b64_encoded", "PrivateKey"}
LOCKED = getattr(Chainbreaker, "KEYCHAIN_LOCKED_SIGNATURE", None)
DUMPS = (("generic_password", "dump_generic_passwords", True), ("internet_password", "dump_internet_passwords", True),
         ("appleshare_password", "dump_appleshare_passwords", True), ("x509_certificate", "dump_x509_certificates", False),
         ("public_key", "dump_public_keys", False), ("private_key", "dump_private_keys", True))


def plain(value):
    if value is None or isinstance(value, (bool, int, str)):
        return value
    if isinstance(value, float):
        return value if math.isfinite(value) else {"float": repr(value)}
    if isinstance(value, (bytes, bytearray)):
        return {"b64": base64.b64encode(bytes(value)).decode("ascii")}
    if isinstance(value, (list, tuple)):
        return [plain(x) for x in value]
    return {"type": type(value).__name__}


def put(row):
    data = (json.dumps(row, ensure_ascii=True) + "\n").encode("ascii")
    view = memoryview(data)
    while view:
        view = view[os.write(outfd, view):]


classes, rows = {}, 0
for name, method, secret in DUMPS:
    stats = {"records": 0, "decrypted": 0, "not_decrypted": 0, "value_bytes": 0}
    classes[name] = stats
    try:
        records = getattr(kc, method)()
    except BaseException as exc:
        stats["error"] = type(exc).__name__
        continue
    for index, record in enumerate(records):
        try:
            row = {"class": name, "index": index, "fields": {k: plain(v) for k, v in vars(record).items() if k not in SKIP and not k.startswith("_")}}
            if secret:
                if name == "private_key":
                    value = getattr(record, "PrivateKey", None)
                    ok = isinstance(value, (bytes, bytearray)) and len(value) > 0
                    encoding = "base64"
                else:
                    value = record.password
                    ok = not record.locked and value is not None
                    encoding = "base64" if getattr(record, "password_b64_encoded", False) else "utf-8"
                if ok:
                    if isinstance(value, (bytes, bytearray)):
                        size = len(value)
                        value = base64.b64encode(bytes(value)).decode("ascii") if name == "private_key" else bytes(value).decode("ascii", "replace")
                    else:
                        size = len(value.encode("utf-8", "replace"))
                    row["value"], row["value_encoding"] = value, encoding
                    stats["decrypted"] += 1
                    stats["value_bytes"] += size
                else:
                    row["value"], row["value_encoding"] = None, None
                    stats["not_decrypted"] += 1
            put(row)
            stats["records"] += 1
            rows += 1
        except BaseException as exc:
            if isinstance(exc, OSError):
                stop("write", exc)
            stats["not_read"] = stats.get("not_read", 0) + 1
            stats["error"] = type(exc).__name__
finish({"stage": "read", "rows": rows, "classes": classes})
'''


def safe_name(text):
    return re.sub(r"[^A-Za-z0-9_.-]", "_", str(text))[:80]


def output_dir():
    out = os.environ.get("OUT")
    job = os.environ.get("JOB_ID")
    shown = "store/jobs/%s/out/" % safe_name(job) if job else ""
    return Path(out), shown


def emit(obj):
    print(json.dumps(obj, indent=2), flush=True)


def fail(message, **extra):
    remove_temporaries()
    emit({"error": message, "status": "failed", "status_basis": "the tool stopped with an error (see error): nothing was opened and nothing was written", **extra})
    raise SystemExit(1)


def remove_temporaries():
    for name in list(TEMPS):
        try:
            os.unlink(name)
        except OSError:
            pass
        if name in TEMPS:
            TEMPS.remove(name)


def refuse_unless_secret_job():
    if os.environ.get("SECRET_OUTPUT") != "1" or not os.environ.get("OUT"):
        emit({"error": REFUSED_NOT_SECRET, "status": "failed", "status_basis": "the call was refused before anything was read or written: not a secret_output job"})
        raise SystemExit(1)


def describe(exc):
    code = errno.errorcode.get(exc.errno, "") if getattr(exc, "errno", None) else ""
    return "%s%s" % (type(exc).__name__, " " + code if code else "")


def regular_file(path, what, secret):
    """lstat a named input file: a regular file, never a link, FIFO, device or directory; a secret file is also mode 0600 (no access for group
    or other) and between 1 and SECRET_FILE_MAX bytes. Returns its size. The path is never printed."""
    try:
        info = os.lstat(path)
    except OSError as exc:
        fail("%s could not be read: %s" % (what, describe(exc)))
    if stat.S_ISLNK(info.st_mode):
        fail("%s is a symbolic link: name the file it resolves to (nothing is followed through a link)" % what)
    if not stat.S_ISREG(info.st_mode):
        fail("%s is not a regular file (a pipe, a device, a socket or a directory is not read)" % what)
    if secret:
        if info.st_mode & 0o077:
            fail("%s must be mode 0600 (no access for group or other): chmod it, or write it as a sealed file in the job" % what)
        if info.st_size < 1:
            fail("%s is empty" % what)
        if info.st_size > SECRET_FILE_MAX:
            fail("%s is larger than %d bytes: not a password or a SystemKey file this tool expects" % (what, SECRET_FILE_MAX))
    return info.st_size


def sniff(path):
    """The first 16 bytes of the keychain, read without following a link or waiting on a pipe."""
    fd = os.open(path, os.O_RDONLY | getattr(os, "O_NONBLOCK", 0) | getattr(os, "O_NOFOLLOW", 0))
    try:
        if not stat.S_ISREG(os.fstat(fd).st_mode):
            return None
        return os.read(fd, 16)
    finally:
        os.close(fd)


def reader_python(program):
    """(interpreter, pythonpath) from the wrapper that images/install.py writes for a pinned source run with python
    (`export PYTHONPATH="<dir>${PYTHONPATH:+:$PYTHONPATH}"` and `exec "<python>" "<entry>" "$@"`), or (None, why)."""
    try:
        fd = os.open(program, os.O_RDONLY | getattr(os, "O_NONBLOCK", 0))
        try:
            data = os.read(fd, WRAPPER_MAX + 1)
        finally:
            os.close(fd)
    except OSError as exc:
        return None, "the reader's launcher could not be read (%s)" % describe(exc)
    if len(data) > WRAPPER_MAX:
        return None, "the reader's launcher is not the small script the image writes"
    text = data.decode("utf-8", "replace")
    path = re.search(r'^export PYTHONPATH="([^"$]+)\$\{PYTHONPATH:\+:\$PYTHONPATH\}"$', text, re.M)
    exe = re.search(r'^exec "([^"]+)" "([^"]+)" "\$@"$', text, re.M)
    if not path or not exe:
        return None, "the reader's launcher is not in the form the image writes (a python entry with PYTHONPATH): it is not run"
    interpreter, pythonpath = exe.group(1), path.group(1)
    if not os.path.isabs(interpreter) or not os.access(interpreter, os.X_OK) or not os.path.isdir(pythonpath):
        return None, "the interpreter or the module directory the reader's launcher names is not there"
    return (interpreter, pythonpath), None


def tidy_tail(fd):
    """Cut a half-written last line (the reader was ended in the middle of a write) so every line of the items file is whole. Returns the size."""
    size = os.fstat(fd).st_size
    if size == 0:
        return 0
    os.lseek(fd, size - 1, os.SEEK_SET)
    if os.read(fd, 1) == b"\n":
        return size
    pos = size
    while pos > 0:
        start = max(0, pos - 65536)
        os.lseek(fd, start, os.SEEK_SET)
        chunk = os.read(fd, pos - start)
        cut = chunk.rfind(b"\n")
        if cut >= 0:
            os.ftruncate(fd, start + cut + 1)
            return start + cut + 1
        pos = start
    os.ftruncate(fd, 0)
    return 0


def describe_file(path):
    """(bytes, sha256, lines) of a placed file, read in blocks."""
    digest, lines, total = hashlib.sha256(), 0, 0
    with open(path, "rb") as fh:
        while True:
            block = fh.read(1 << 20)
            if not block:
                break
            digest.update(block)
            lines += block.count(b"\n")
            total += len(block)
    return total, digest.hexdigest(), lines


def read_summary(fd):
    """The reader process's one summary line as a dict of fixed shape, or None. Only closed vocabularies and counts are taken from it; no text of it
    is ever relayed."""
    try:
        os.set_blocking(fd, False)
        data = os.read(fd, SUMMARY_MAX + 1)
    except (OSError, ValueError):
        return None
    if not data or len(data) > SUMMARY_MAX:
        return None
    try:
        raw = json.loads(data.decode("ascii").splitlines()[0])
    except (ValueError, IndexError):
        return None
    if not isinstance(raw, dict) or raw.get("stage") not in STAGES:
        return None
    out = {"stage": raw["stage"]}
    error = raw.get("error")
    if isinstance(error, str) and NAME_OK.match(error):
        out["error"] = error
    if raw.get("empty") is True:
        out["empty"] = True
    if raw["stage"] == "read":
        classes = raw.get("classes")
        if not isinstance(classes, dict):
            return None
        shaped = {}
        for name in CLASSES:
            c = classes.get(name)
            if not isinstance(c, dict):
                return None
            entry = {}
            for key in ("records", "decrypted", "not_decrypted", "value_bytes", "not_read"):
                v = c.get(key, 0)
                if not isinstance(v, int) or isinstance(v, bool) or v < 0:
                    return None
                entry[key] = v
            err = c.get("error")
            if isinstance(err, str) and NAME_OK.match(err):
                entry["error"] = err
            shaped[name] = entry
        out["classes"] = shaped
        rows = raw.get("rows")
        if not isinstance(rows, int) or isinstance(rows, bool) or rows < 0:
            return None
        out["rows"] = rows
    return out


def run_keychain(args):
    started = time.monotonic()
    if any(key not in ("path", "password_file", "system_key", "max_seconds") for key in args):
        fail("an argument this tool does not take: it takes path, password_file, system_key and max_seconds only (a password is never an argument: give it as a job input file)")
    path = args.get("path")
    if not isinstance(path, str) or not path:
        fail("path is required: a login or System keychain file")
    password_file, system_key = args.get("password_file"), args.get("system_key")
    for name, value in (("password_file", password_file), ("system_key", system_key)):
        if value is not None and (not isinstance(value, str) or not value):
            fail("%s must be a file path (a job input file), never a value given inline" % name)
    if password_file is None and system_key is None:
        fail("password_file or system_key is required: the case must supply the keychain's password (a job input file) or, for System.keychain, the SystemKey file; nothing is guessed or recovered")
    max_seconds = args.get("max_seconds", DEFAULT_MAX_SECONDS)
    if not isinstance(max_seconds, (int, float)) or isinstance(max_seconds, bool) or not 0 < max_seconds <= MAX_SECONDS_LIMIT:
        fail("max_seconds must be a number above 0 and at most %d (the tool's own time limit; the manifest allows 120)" % MAX_SECONDS_LIMIT)
    deadline = started + max_seconds
    size = regular_file(path, "path", False)
    if size > KEYCHAIN_MAX:
        fail("path is larger than %d bytes: a keychain file is far smaller, and the reader reads it whole into memory; this is not a keychain, or not one this tool opens" % KEYCHAIN_MAX)
    if password_file is not None:
        regular_file(password_file, "password_file", True)
    if system_key is not None:
        regular_file(system_key, "system_key", True)
    out_dir, shown_dir = output_dir()
    try:
        if not stat.S_ISDIR(os.stat(out_dir).st_mode):
            fail("the output directory is not a directory")
    except OSError as exc:
        fail("the output directory could not be read: %s" % describe(exc))
    os.umask(0o077)
    try:
        head = sniff(path)
    except OSError as exc:
        fail("path could not be read: %s" % describe(exc))
    if head is None:
        fail("path is not a regular file")

    st = {"interrupted": None, "summary": None, "exit_code": None, "timed_out": False, "ran": False, "bytes": 0, "placed": None, "storage": None, "started": True}
    result = {"parser": PARSER, "reader": {"program": READER, "found": None},
              "keychain": {"bytes": size},
              "secrets_given": {"password": password_file is not None, "system_key": system_key is not None}}
    outcome = reason = None
    status = "failed"
    SWEEP["began"] = True
    if size < 8 or head[:4] == b"kych" and size < 64:
        outcome, reason = "damaged", "the file is shorter than the smallest keychain file (%d bytes): it is truncated or not a keychain, and nothing was read from it" % size
        result["keychain"]["format"] = "kych" if head[:4] == b"kych" else None
    elif head[:4] != b"kych":
        outcome = "unsupported_format"
        if head[:15] == b"SQLite format 3":
            result["keychain"]["format"] = "sqlite (Local Items store)"
            reason = UNSUPPORTED_SQLITE
        else:
            result["keychain"]["format"] = "unknown"
            reason = UNSUPPORTED_OTHER
    else:
        result["keychain"]["format"] = "kych"
    found = interp = None
    if outcome is None:
        found = shutil.which(READER)
        result["reader"]["found"] = found is not None
        if found is None:
            outcome, reason = "unavailable", "the reader (chainbreaker, pinned in this pack's requires/host.json) is not on PATH in this image: nothing was opened"
        else:
            interp, why = reader_python(found)
            if interp is None:
                outcome, reason = "unavailable", why + "; nothing was opened"
    if outcome is None:
        name = "." + ITEMS_NAME + ".%d.%s.tmp" % (os.getpid(), os.urandom(4).hex())
        tmp = str(out_dir / name)
        TEMPS.append(tmp)
        fd = sumr = sumw = None
        try:
            try:
                fd = os.open(tmp, os.O_RDWR | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o600)
                sumr, sumw = os.pipe()
            except OSError as exc:
                st["storage"] = describe(exc)
            if st["storage"] is None:
                argv = [interp[0], "-I", "-c", SHIM, interp[1], path, password_file or "", system_key or "", str(fd), str(sumw)]
                env = {"PATH": os.environ.get("PATH", "/usr/bin:/bin"), "LC_ALL": "C", "LANG": "C"}
                try:
                    try:
                        proc = spawn(argv, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, env=env, pass_fds=(fd, sumw))
                    finally:
                        os.close(sumw)
                        sumw = None
                    st["ran"] = True
                    code, timed_out = wait_for(proc, max(0.1, deadline - time.monotonic()))
                    st["exit_code"], st["timed_out"] = code, timed_out
                    st["summary"] = read_summary(sumr)
                except OSError as exc:
                    st["spawn_failed"] = describe(exc)
                except Interrupted as stop:
                    st["interrupted"] = stop.signum
                    hold_signals()
            hold_signals()
            if fd is not None:
                with held():
                    st["bytes"] = tidy_tail(fd)
                    try:
                        os.fsync(fd)
                    except OSError as exc:
                        st["storage"] = st["storage"] or describe(exc)
        finally:
            hold_signals()
            for d in (fd, sumr, sumw):
                if d is not None:
                    try:
                        os.close(d)
                    except OSError:
                        pass
        if st["bytes"] > 0 and st["storage"] is None:
            placed = place_without_replacing(Path(tmp), out_dir / ITEMS_NAME)
            if tmp in TEMPS:
                TEMPS.remove(tmp)
            total, digest, lines = describe_file(placed)
            st["placed"] = {"file": shown_dir + placed.name, "bytes": total, "sha256": digest, "lines": lines, "mode": "0600"}
            if placed.name != ITEMS_NAME:
                st["placed"]["named_anew"] = "an earlier %s is there and holds other bytes: it was not replaced" % ITEMS_NAME
            try:
                os.chmod(placed, 0o600)
            except OSError:
                pass
        remove_temporaries()
    summary = st["summary"]
    interrupted = st["interrupted"]
    problems = []
    if outcome is None:
        stage = summary["stage"] if summary else None
        if interrupted is not None:
            outcome, reason = "interrupted", "the tool was stopped by %s while the reader ran; the reader and what it started were ended" % signal_name(interrupted)
        elif st.get("spawn_failed"):
            outcome, reason = "reader_failed", "the reader process could not be started (%s): nothing was opened" % st["spawn_failed"]
        elif st["storage"]:
            outcome, reason = "storage_refused", "the output directory refused a write (%s), a fact about that directory and not about the keychain: nothing was kept" % st["storage"]
        elif st["timed_out"]:
            outcome, reason = "timed_out", "the reader did not end within max_seconds (%s) and was ended with what it started" % max_seconds
        elif stage == "import":
            outcome, reason = "unavailable", "the reader could not be imported by its own interpreter (%s): nothing was opened" % summary.get("error", "no detail")
        elif stage == "secret":
            outcome = "secret_unreadable"
            reason = "the password file is empty after its trailing newline was dropped" if summary.get("empty") else "the password file could not be read as UTF-8 text (%s)" % summary.get("error", "no detail")
        elif stage == "open":
            outcome, reason = "damaged", "the reader raised %s while reading the file: it is truncated or damaged, or not a keychain the reader parses; nothing was opened" % summary.get("error", "an error")
        elif stage == "locked":
            outcome = "wrong_secret"
            reason = ("the reader could not unlock the keychain with the secret(s) given: the password is not this keychain's, or the SystemKey file is not the one for it, "
                      "or the file is damaged where the key is held. This is not proof about the password: nothing was opened")
        elif stage == "write":
            outcome, reason = "storage_refused", "the reader could not write the items file (%s): a fact about the output directory, not about the keychain" % summary.get("error", "OSError")
        elif stage == "read":
            classes = summary["classes"]
            bad = sum(c["not_decrypted"] + c.get("not_read", 0) for c in classes.values())
            erred = [n for n, c in classes.items() if c.get("error")]
            if bad or erred:
                outcome = "partial"
                reason = "the keychain was opened, and %d record(s) could not be decrypted or read%s" % (bad, "; the reader failed on class(es) " + ", ".join(erred) if erred else "")
            else:
                outcome = "opened"
                reason = "the keychain was unlocked and every record of every class the reader lists was read; secrets were decrypted where the class holds one"
        else:
            outcome = "reader_failed"
            reason = ("the reader process ended (%s) without a summary: what it wrote before that is in the items file, and nothing is claimed about the keychain beyond it" %
                      ("exit %s" % st["exit_code"] if st["exit_code"] is not None else "no exit code"))
    totals = None
    if summary and summary["stage"] == "read":
        classes = summary["classes"]
        totals = {"records": sum(c["records"] for c in classes.values()), "decrypted": sum(c["decrypted"] for c in classes.values()),
                  "not_decrypted": sum(c["not_decrypted"] for c in classes.values()), "by_class": classes}
        result["records"] = totals
    elif st["placed"]:
        result["records"] = {"records": st["placed"]["lines"], "by_class": None}
        problems.append("the reader did not end with a summary: the record count is the number of lines it wrote, and per-class counts were not reported")
    if st["placed"]:
        result["items_file"] = st["placed"]
    if outcome == "opened":
        status = "complete"
        basis = "the reader unlocked the keychain and ended with a summary; every record it listed was read and every record that holds a secret was decrypted"
        if not st["placed"] and totals and totals["records"] > 0:
            status, outcome = "failed", "reader_failed"
            reason = "the summary counts records but no items file was kept"
        elif totals is not None and st["placed"] and st["placed"]["lines"] != totals["records"]:
            status, outcome = "partial", "partial"
            reason = "the items file holds %d line(s) and the reader counted %d record(s)" % (st["placed"]["lines"], totals["records"])
            basis = "the file and the reader's count differ"
    elif outcome == "partial":
        status = "partial"
        basis = "the keychain was unlocked; the items file holds every record that could be read, and the counts say how many could not be decrypted"
    elif outcome in ("timed_out", "interrupted", "reader_failed") and st["placed"]:
        status = "partial"
        basis = ("the tool was stopped by %s" % signal_name(interrupted) if interrupted is not None else
                 "the reader did not end within max_seconds (%s) and was ended with what it started" % max_seconds if st["timed_out"] else
                 "the reader process ended without a summary") + ": the items file holds the whole lines written before that, and nothing is claimed about the rest of the keychain"
    else:
        status = "failed"
        basis = "the keychain was not opened (see outcome and reason): nothing is claimed about its content"
        if outcome in ("timed_out", "interrupted"):
            basis = ("the tool was stopped by %s" % signal_name(interrupted) if interrupted is not None else "the reader did not end within max_seconds (%s) and was ended" % max_seconds) + " before it had written an item"
    result.update({"status": status, "status_basis": basis, "outcome": outcome})
    if reason:
        result["reason"] = reason
    if problems:
        result["problems"] = problems
    notes = process_notes()
    if notes:
        result["process_notes"] = notes
    if interrupted is not None:
        result["interrupted"] = signal_name(interrupted)
    if st["ran"] and st["exit_code"] is not None:
        result["reader"]["exit_code"] = st["exit_code"]
    result["limits"] = {"max_seconds": max_seconds, "seconds_used": round(time.monotonic() - started, 1)}
    result["sensitive"] = "The items file holds every item's metadata and value, 0600, sealed as secret output; this answer holds counts, sizes and the file's sha256 and no name, value or hash of one."
    hold_signals()
    pending = pending_stop_signal() if interrupted is None else None
    if pending is not None:
        result["interrupted"] = signal_name(pending)
        result["status_basis"] += "; a stop signal (%s) arrived while the answer was being made" % signal_name(pending)
        interrupted = pending
    emit(result)
    if interrupted is not None:
        sys.exit(128 + interrupted)
    if status == "failed":
        sys.exit(1)


SWEEP = {"began": False}


def main():
    STOP["hooks"].append(kill_all)       # a stop signal ends the reader and what it started first (the shared PROCESS block), then the tool answers
    refuse_unless_secret_job()
    try:
        args = json.load(sys.stdin)
    except ValueError:
        fail("arguments are not valid JSON")
    if not isinstance(args, dict):
        fail("the arguments must be a JSON object")
    run_keychain(args)


if __name__ == "__main__":
    install_stop_handlers()
    try:
        main()
    except SystemExit:
        raise
    except Interrupted as stop:
        remove_temporaries()
        emit({"error": "the tool was stopped by %s %s" % (signal_name(stop.signum), "after the reader had been started and before its answer was made" if SWEEP["began"] else "before anything was read"),
              "status": "failed",
              "status_basis": "stopped by %s: nothing is claimed about the keychain; an items file may hold the whole lines written before the stop" % signal_name(stop.signum),
              "interrupted": signal_name(stop.signum)})
        sys.exit(128 + stop.signum)
    except Exception as exc:  # noqa: BLE001
        remove_temporaries()
        emit({"error": "unexpected failure: %s" % type(exc).__name__, "status": "failed", "status_basis": "the tool stopped on an unexpected error: nothing is claimed about the keychain"})
        sys.exit(1)
