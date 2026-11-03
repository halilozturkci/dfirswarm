#!/usr/bin/env python3
"""List the volume shadow copies on an image.

A shadow copy is a second, older state of the same volume, kept by Windows
itself. It holds the registry hives, the event logs and the files as they were
at the moment the snapshot was taken, which is how a file deleted last week is
still readable today and how a Run key that has since been cleaned is still
there to be found.

This tool LISTS stores (through vshadowinfo) and suggests the command that would
mount them; it mounts nothing, and listing a snapshot does not examine it.
vshadowinfo reads a raw volume or disk image: an E01 has to be exposed as raw first.

The unit trap is worth naming once: mmls and the Sleuth Kit's -o work in
**sectors**, and vshadowinfo's -o works in **bytes**. Passing one where the
other belongs is why this returns "unable to open volume" on an image that is
perfectly sound, so this tool takes bytes and says so in its own output.

The answer is judged, never assumed: vshadowinfo's exit status, its whole standard
output and error (kept in files), the number of stores it says it found against the number
this tool could read, and the output's own header. A failed or unrecognised run is `failed`,
never an answer that there are no stores; "no stores" is said only when vshadowinfo ran,
exited 0 and itself reported zero stores.
"""
import hashlib
import json
import os
import re
import shlex
import shutil
import signal
import subprocess
import sys

TIMEOUT = 240
DEADLINE_SECONDS = 285            # the manifest allows 300: one clock over vshadowinfo and the parse, with room left to print the answer
PARSE_RESERVE = 20                # what vshadowinfo leaves of the clock for reading its output
PROGRESS = {"stdout": None, "stderr": None}
CLOCK = {"deadline": None}


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
# tool's group, and with it the stopped ones that are in it); a carrier's answer says what process_notes() holds only where that carrier's
# own code reads it; the start of the interpreter, before any handler is in, is a window a signal can land in.
import time

try:
    import ctypes
except ImportError:  # pragma: no cover
    ctypes = None

STATE = {"last_word": None}    # what to do, with the signal number, when the tool is stopped by a signal
ACTIVE = []                    # the programs running now
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


def spawn(argv, **kwargs):
    kwargs.setdefault("stdin", subprocess.DEVNULL)
    if sys.platform.startswith("linux") and ctypes is not None:
        kwargs["preexec_fn"] = _die_with_parent
    proc = subprocess.Popen(argv, **kwargs)
    SEEN.add(proc.pid)
    started = _read_ident(proc.pid, "proc" if os.path.isdir("/proc/self") else "libproc")
    if started is not None:
        SEEN_IDENT[proc.pid] = started
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
            return out or b"", err or b"", False
        except subprocess.TimeoutExpired as exc:
            started = True
            out, err = exc.stdout or b"", exc.stderr or b""
    try:
        out, err = proc.communicate(None if started else input, timeout=PIPE_GRACE)
    except subprocess.TimeoutExpired as exc:
        out, err = exc.stdout or b"", exc.stderr or b""
        reap_orphans(_pipe_inodes(proc))
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
STORE = re.compile(r"^Store:\s*(\d+)\s*$")


def parse_field(line):
    """(key, value) of a `<whitespace><key> : <value>` line, or None: what `^\\s+(.+?)\\s*:\\s*(.*\\S)\\s*$` matched, found in time linear in the
    line. That expression backtracks over the leading whitespace and the key together, so a line of 4,096 spaces in the output took 37 s (the cube of
    its length), and any text of the image that the reader prints on a line of its own could hold the tool. The key ends at the first point
    from which the next character that is not whitespace is a `:` with something after it; the leading whitespace gives back one character
    at a time only when no key ends after a longer start."""
    n = len(line)
    if n == 0 or not line[0].isspace():
        return None
    after = [n] * (n + 2)                          # after[i]: the first index at or after i that is not whitespace (n when there is none)
    for i in range(n - 1, -1, -1):
        after[i] = after[i + 1] if line[i].isspace() else i
    lead = after[0]
    if lead == n:
        return None
    key_end = [n + 1] * (n + 2)                    # key_end[k]: the smallest k' >= k at which a key can end
    for k in range(n, 0, -1):
        j = after[k]
        key_end[k] = k if j < n and line[j] == ":" and after[j + 1] < n else key_end[k + 1]
    for start in range(lead, 0, -1):
        end = key_end[start + 1]
        if end <= n:
            first = after[after[end] + 1]
            last = n
            while line[last - 1].isspace():
                last -= 1
            return line[start:end], line[first:last]
    return None


def remaining():
    """Seconds left of the tool's one clock."""
    return CLOCK["deadline"] - time.monotonic() if CLOCK["deadline"] is not None else float(DEADLINE_SECONDS)


def out_of_time():
    return remaining() <= 0


def print_answer(answer, **dumps_kwargs):
    """Print the answer with the stop signals held back (a signal in the middle of the write would cut it) and the last word cleared."""
    try:
        signal.pthread_sigmask(signal.SIG_BLOCK, {signal.SIGTERM, signal.SIGINT, signal.SIGHUP})
    except (AttributeError, ValueError, OSError):
        pass
    STATE["last_word"] = None
    print(json.dumps(answer, **dumps_kwargs))


def fail(message, **extra):
    print_answer({"error": message, "status": "failed", "status_basis": "the tool stopped with an error and listed no shadow copy (see error)", **extra})
    raise SystemExit(1)


def last_word(signum):
    said = {"error": "stopped by signal %d before vshadowinfo finished" % signum, "status": "interrupted", "signal": signum,
            "status_basis": "the tool was stopped by signal %d; no statement about shadow copies follows from it" % signum,
            "note": "No statement about shadow copies follows from an interrupted run."}
    if PROGRESS["stdout"]:
        said["stdout_file"], said["stderr_file"] = PROGRESS["stdout"], PROGRESS["stderr"]
    print(json.dumps(said), flush=True)


STATE["last_word"] = last_word       # set before any file is made, and the handlers are in from the moment the module has run this far
install_signal_handlers()


def key_of(label):
    return re.sub(r"[^a-z0-9]+", "_", label.strip().lower()).strip("_")


def tool_output_dir():
    out, job = os.environ.get("OUT"), os.environ.get("JOB_ID")
    if job and out:
        return os.path.join(out, "tool-output"), "store/jobs/%s/out/tool-output" % re.sub(r"[^A-Za-z0-9_.-]", "_", job)
    d = os.path.join("work", re.sub(r"[^A-Za-z0-9_.-]", "_", os.environ.get("AGENT_ID") or "tool"), "tool-output")
    return d, d


def new_pair(outdir, digest):
    """Two new files, stdout and stderr, named by the arguments' digest and, when an earlier run holds that name, by
    the next free number. Exclusive and never through a link. Returns both descriptors, both paths and the earlier
    files of the same digest, which are left as they are."""
    earlier = sorted(n for n in os.listdir(outdir) if n.startswith("vss_stores-%s" % digest))
    for n in range(1, 1000):
        stem = "vss_stores-%s" % digest + ("" if n == 1 else "-%d" % n)
        out_path = os.path.join(outdir, stem + ".stdout.txt")
        err_path = os.path.join(outdir, stem + ".stderr.txt")
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
        try:
            out_fd = os.open(out_path, flags, 0o600)
        except FileExistsError:
            continue
        try:
            err_fd = os.open(err_path, flags, 0o600)
        except FileExistsError:
            os.close(out_fd)
            os.unlink(out_path)
            continue
        return out_fd, err_fd, out_path, err_path, earlier
    raise OSError("no free name for the vshadowinfo output files after 999 tries")


def main():
    CLOCK["deadline"] = time.monotonic() + DEADLINE_SECONDS
    try:
        args = json.load(sys.stdin)
    except ValueError as exc:
        fail("arguments are not valid JSON", reason=str(exc))
    if not isinstance(args, dict):
        fail("the arguments must be a JSON object")

    image = args.get("image")
    if not isinstance(image, str) or not image:
        fail("image is required")
    if not os.path.isfile(image):
        fail("no such image", image=image)

    offset = args.get("offset")
    if offset is not None and (not isinstance(offset, int) or isinstance(offset, bool) or offset < 0):
        fail("offset must be a byte offset, not a sector offset")

    # Where a store would be mounted: the seat's own directory. The rest of
    # work/ is read-only in a VM, and a mount is that VM's alone either way.
    mount_dir = args.get("mount_dir")
    if mount_dir is None:
        mount_dir = "work/%s/vss" % (os.environ.get("AGENT_ID") or "<your id>")
    elif not isinstance(mount_dir, str) or not mount_dir:
        fail("mount_dir must be a directory path")
    mount_dir = mount_dir.rstrip("/")

    if not shutil.which("vshadowinfo"):
        fail("vshadowinfo is not on PATH",
             install="brew install libvshadow, or apt-get install -y libvshadow-utils")

    argv = ["vshadowinfo"]
    if offset is not None:
        argv += ["-o", str(offset)]
    argv.append(image)
    try:
        with open(image, "rb") as fh:
            head = fh.read(8)
    except OSError as exc:
        fail("the image could not be read", image=image, reason=str(exc))
    outdir, shown = tool_output_dir()
    digest = hashlib.sha256(json.dumps(argv).encode("utf-8")).hexdigest()[:16]
    try:
        os.makedirs(outdir, exist_ok=True)
        # Created, never opened over: a run with the same arguments keeps its own pair of files, and an earlier
        # run's stay as they were (the next free number names the new pair).
        out_fd, err_fd, out_path, err_path, earlier = new_pair(outdir, digest)
    except OSError as exc:
        fail("the files for vshadowinfo's output could not be created in %s" % shown, reason=str(exc))
    PROGRESS["stdout"], PROGRESS["stderr"] = out_path, err_path
    with os.fdopen(out_fd, "wb") as so, os.fdopen(err_fd, "wb") as se:
        try:
            proc = spawn(argv, stdout=so, stderr=se)
        except OSError as exc:
            fail("vshadowinfo could not be started: %s" % exc, reason=type(exc).__name__)
        rc, timed_out = wait_for(proc, max(1, min(TIMEOUT, remaining() - PARSE_RESERVE)))

    with open(out_path, "r", encoding="utf-8", errors="replace") as fh:
        text = fh.read()
    with open(err_path, "r", encoding="utf-8", errors="replace") as fh:
        stderr = fh.read().strip()
    stores, current = [], None
    parse_stopped = False
    for line_number, line in enumerate(text.splitlines()):
        if not (line_number & 255) and out_of_time():
            parse_stopped = True
            break
        m = STORE.match(line)
        if m:
            current = {"store": int(m.group(1))}
            stores.append(current)
            continue
        if current is None:
            continue
        field = parse_field(line)
        if field:
            current[key_of(field[0])] = field[1]

    claimed = None
    m = re.search(r"Number of stores:\s*(\d+)", text)
    if m:
        claimed = int(m.group(1))

    mountable = shutil.which("vshadowmount") is not None
    for store in stores:
        mkdir_argv = ["mkdir", "-p", mount_dir]
        mount_argv = ["vshadowmount"] + (["-o", str(offset)] if offset is not None else []) + [image, mount_dir + "/"]
        store["mount_argv"] = [mkdir_argv, mount_argv]
        store["mount_with"] = "%s && %s  # then %s/vss%d" % (shlex.join(mkdir_argv), shlex.join(mount_argv), mount_dir, store["store"])

    problems = []
    if parse_stopped:
        problems.append("the tool's own clock (%d s) ran out while vshadowinfo's output was read: the stores after line %d were not read" % (DEADLINE_SECONDS, line_number))
    if timed_out:
        problems.append("vshadowinfo was stopped by the tool's clock after its share of the %d seconds" % DEADLINE_SECONDS)
    elif rc != 0:
        problems.append("vshadowinfo exited with status %d" % rc)
    if rc == 0 and claimed is None:
        problems.append("vshadowinfo's output has no 'Number of stores' line; this tool does not recognise its format")
    if claimed is not None and claimed != len(stores):
        problems.append("vshadowinfo reports %d store(s) and %d could be read from its output" % (claimed, len(stores)))
    if head == b"EVF\x09\x0d\x0a\xff\x00":
        problems.append("the image starts with the EWF (E01) signature: vshadowinfo reads raw data, so expose the image raw first")

    if problems and (rc != 0 or timed_out or (claimed is None and not parse_stopped)):
        status = "failed"
    elif problems:
        status = "partial"
    else:
        status = "complete"

    out = {
        "parser": "vss_stores/5",
        "status": status,
        "status_basis": ("; ".join(problems) if problems else
                         "vshadowinfo exited 0, its 'Number of stores' line (%s) agrees with the %d store(s) read from its output, and the output was read to its end" % (claimed, len(stores))),
        "stopped_by_time_limit": bool(timed_out or parse_stopped),
        "image": image,
        "offset_bytes": offset,
        "mount_dir": mount_dir,
        "stores": stores,
        "store_count": len(stores),
        "stores_claimed": claimed,
        "problems": problems,
        "vshadowmount_present": mountable,
        "exit_code": rc,
        "timed_out": timed_out,
        "command": shlex.join(argv),
        "stdout_file": "%s/%s" % (shown, os.path.basename(out_path)),
        "stderr_file": "%s/%s" % (shown, os.path.basename(err_path)),
        "earlier_output_files": ["%s/%s" % (shown, n) for n in earlier],
        "vshadowinfo_stderr_lines": len(stderr.splitlines()),
        "vshadowinfo_said": stderr.splitlines()[:5],
    }
    # What a mount of a listed store needs: FUSE. Listing stays complete without it; the answer says, in the form every tool that mounts
    # uses (memory-forensics mem_fs too), that the mount commands will not work here.
    fuse_device = os.environ.get("DFIRSWARM_FUSE_DEVICE", "/dev/fuse")
    fuse_missing = []
    if not os.path.exists(fuse_device):
        fuse_missing.append("%s is not present" % fuse_device)
    elif not os.access(fuse_device, os.R_OK | os.W_OK):
        fuse_missing.append("%s cannot be opened by this process" % fuse_device)
    if not (shutil.which("fusermount3") or shutil.which("fusermount")):
        fuse_missing.append("neither fusermount3 nor fusermount is installed")
    out["fuse_present"] = not fuse_missing
    if fuse_missing and stores:
        out["no_fuse"] = {"reason": "no_fuse", "blocked_by": fuse_missing,
                          "what_to_do": "Run this job where /dev/fuse exists and fusermount3 or fusermount is installed (the image record, /etc/dfirswarm/image.json, says under `fuse` "
                                        "whether the image has fusermount; the VM must also expose /dev/fuse). Until then say that no FUSE mount was possible here, "
                                        "never that the evidence holds nothing."}
    if status == "failed":
        out["error"] = "vshadowinfo did not give a usable answer: " + "; ".join(problems)
        out["note"] = ("This is a failure, not a finding: no statement about shadow copies on this volume follows from it, and "
                       "'no stores' must not be reported. Check the offset (BYTES, not sectors), that this is a raw volume or image, and the "
                       "stderr file; then ask again.")
        print_answer(out, indent=2)
        raise SystemExit(1)
    if not stores:
        out["note"] = ("vshadowinfo, run on this image at offset %s, reported 0 stores. That says no store was found in this volume's metadata "
                       "as this reader parsed it. It does not establish that none was ever made or that one was deleted: correlate the host's "
                       "age and configuration with event logs, command history and free-space evidence before saying why no store is present."
                       % (offset if offset is not None else "0 (none given)"))
    elif status == "partial":
        out["note"] = "The list above is incomplete: " + "; ".join(problems) + ". Do not count the stores from it."
    elif not mountable:
        out["note"] = ("vshadowmount is not installed, so the stores cannot be opened here. "
                       "The list above, with the creation times, still belongs in the timeline.")
    else:
        out["note"] = ("Listing is not mounting, and a listed store is not an examined one. To open one, run the mount_argv commands (a FUSE mount "
                       "may be unavailable in a worker), then run the ordinary toolkit against %s/vssN as if it were a volume. The mount is yours alone: "
                       "copy what you derive from it into your own directory and record it. A hive or a log read there is the state at "
                       "the store's creation time, not at acquisition: cite both times." % mount_dir)
    print_answer(out, indent=2)


if __name__ == "__main__":
    try:
        main()
    except SystemExit:
        raise
    except OSError as exc:
        fail("a file operation failed: %s" % exc, reason=type(exc).__name__)
    except Exception as exc:                                  # whatever hostile input does, the answer is JSON
        print_answer({"error": "the listing failed", "status": "failed", "status_basis": "the tool stopped with an unexpected error",
                      "reason": "%s: %s" % (type(exc).__name__, exc)})
        sys.exit(1)
