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

# macapt-log-reader: start
# The same text is in macos_triage and the macos-artefacts recipe (tests/pack-macos-triage.test.ts holds the copies equal).
# It reads the log of ONE mac_apt run and says, per plugin, what the log shows. What is READ FROM mac_apt v1.33.2's SOURCE (mac_apt.py, GitHub raw view)
# and what is ASSUMED is kept apart, because no run of mac_apt was ever observed here:
#   read from the source: the message texts "Started {program}, version {version}", "Running plugin {name}", "{name} plugin ran for HH:MM:SS",
#     "An exception occurred while running plugin - {name}" (logged with log.exception, so a traceback follows it), "Finished in time = HH:MM:SS",
#     "Could not find OSX/macOS installation!", ":( Could not find a partition having a macOS installation on it", the log file name
#     "Log.<%Y%m%d-%H%M%S>.txt" in the output folder, and that the script ends with exit 0 even after an error it logged (Exit() calls sys.exit()).
#   NOT read from the source, never observed: the prefix each log line carries (level, time, logger), the wording of a plugin that finds nothing or
#     does not take an operating-system version, and where the console copy of the log goes. So every pattern below is searched anywhere in the line,
#     a level word is looked for as a whole word, and `empty` and `unsupported` rest on wording that is an ASSUMPTION (see the manifest).
# Nothing a line says is kept except its number: a log line can quote the evidence.
import re

MA_LINE_BOUND = 4000
MA_STARTED = re.compile(r"Started (?P<prog>.{1,120}?), version (?P<ver>[0-9A-Za-z][0-9A-Za-z.+_-]{0,40})\s*$")
MA_PLUGIN_RUN = re.compile(r"Running plugin (?P<n>[A-Za-z0-9_]{1,64})\s*$")
MA_PLUGIN_RAN = re.compile(r"(?P<n>[A-Za-z0-9_]{1,64}) plugin ran for (?P<t>[0-9]{2,}:[0-9]{2}:[0-9]{2})\s*$")
MA_EXCEPTION = re.compile(r"An exception occurred while running plugin - (?P<n>[A-Za-z0-9_]{1,64})\s*$")
MA_FINISHED = re.compile(r"Finished in time = (?P<t>[0-9]{2,}:[0-9]{2}:[0-9]{2})\s*$")
MA_NO_MACOS = re.compile(r"Could not find OSX/macOS installation!|Could not find a partition having a macOS installation on it")
MA_TRACEBACK = re.compile(r"Traceback \(most recent call last\)")
MA_LEVEL_BAD = re.compile(r"(?<![A-Za-z])(?:ERROR|CRITICAL)(?![A-Za-z])|\b(?:errors?|exceptions?|tracebacks?|fail(?:ed|s|ure|ures)?|cannot|can't|could not|couldn't|unable|corrupt(?:ed)?|malformed|invalid)\b", re.I)
# (the level word of the prefix was never observed, so a line is a failure line when it holds the uppercase level word OR any word of the broader vocabulary above, in any case)
MA_REVIEW = re.compile(r"Review the Log file and report any")                 # the finish-time hint of the source, which names ERRORs and EXCEPTIONS without one having happened
MA_LEVEL_WARN = re.compile(r"(?<![A-Za-z])WARNING(?![A-Za-z])")
MA_SEPARATOR = re.compile(r"-{20,}\s*$")
MA_UNSUPPORTED = re.compile(r"\b(?:not supported|unsupported)\b", re.I)                                                  # ASSUMED wording
MA_EMPTY = re.compile(r"\bno\b.{0,80}\b(?:found|data|records|entries|items)\b|\b0 (?:records|entries|items)\b", re.I)      # ASSUMED wording
MA_STATUSES = ("parsed", "empty", "unsupported", "failed")


def ma_read_log(paths):
    """Read the given log files in order as one account. Returns a dict: lines, long_lines, started (bool), program, version, finished (bool),
    no_macos (bool), run_errors (the lines with an error word or a traceback outside any plugin's window), plugins (a list of windows in the order
    they began: name, line, ran, exception, errors, tracebacks, warnings, unsupported, empty, other, closed_by) and files read."""
    out = {"lines": 0, "long_lines": 0, "started": False, "program": None, "version": None, "finished": False, "no_macos": False,
           "run_errors": [], "plugins": [], "unreadable": []}
    current = None
    for path in paths:
        try:
            handle = open(path, "rb")
        except OSError as exc:
            out["unreadable"].append(exc.strerror or type(exc).__name__)
            continue
        with handle:
            while True:
                raw = handle.readline(MA_LINE_BOUND + 1)
                if not raw:
                    break
                if len(raw) > MA_LINE_BOUND and not raw.endswith(b"\n"):
                    out["long_lines"] += 1
                    while True:                      # the rest of the line is skipped, in pieces
                        rest = handle.readline(MA_LINE_BOUND)
                        if not rest or rest.endswith(b"\n"):
                            break
                out["lines"] += 1
                number = out["lines"]
                line = raw.decode("utf-8", "replace").rstrip("\r\n")
                m = MA_STARTED.search(line)
                if m and not out["started"]:
                    out["started"], out["program"], out["version"] = True, m.group("prog"), m.group("ver")
                    continue
                m = MA_PLUGIN_RUN.search(line)
                if m:
                    current = {"name": m.group("n"), "line": number, "ran": False, "exception": 0, "errors": 0, "tracebacks": 0, "warnings": 0,
                               "unsupported": 0, "empty": 0, "other": 0, "closed_by": None}
                    out["plugins"].append(current)
                    continue
                if MA_FINISHED.search(line):
                    out["finished"] = True
                    if current is not None:
                        current["closed_by"] = current["closed_by"] or "finish"
                    current = None
                    continue
                if MA_NO_MACOS.search(line):
                    out["no_macos"] = True
                    continue
                m = MA_PLUGIN_RAN.search(line)
                if m:
                    if current is not None and current["name"] == m.group("n") and not current["ran"]:
                        current["ran"], current["closed_by"] = True, "ran"
                        current = None
                    else:
                        out["run_errors"].append(number)          # a "ran for" line for a plugin that is not the one in hand: the log is not in the order read
                    continue
                m = MA_EXCEPTION.search(line)
                if m:
                    target = current if current is not None and current["name"] == m.group("n") else next((w for w in reversed(out["plugins"]) if w["name"] == m.group("n")), None)
                    if target is None:
                        out["run_errors"].append(number)
                    else:
                        target["exception"] += 1
                    continue
                bad = bool(MA_LEVEL_BAD.search(line)) and not MA_REVIEW.search(line)
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
    with excl(temp, "w") as handle:
        json.dump({"recipe": "macos-artefacts", "status": status, "status_basis": basis, "covered": covered, "not_covered": NOT_COVERED,
                   "limits_hit": list(limits), "errors": list(errors), **more}, handle, indent=2, sort_keys=True)
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
    """(exit code, timed out, pipes held) of mac_apt: in this recipe's own process group (the shared PROCESS block), its stdout and stderr written whole to two files."""
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
    code, timed_out, held = run_program(argv, os.path.join(out, "mac_apt.stdout"), os.path.join(out, "mac_apt.stderr"), os.path.join(out, "mac_apt-cwd"), env, seconds)
    logs = sorted(n for n in os.listdir(report) if LOG_NAME.fullmatch(n) and not os.path.islink(os.path.join(report, n)))
    console = not logs
    read = ma_read_log([os.path.join(report, n) for n in logs] if logs else [os.path.join(out, "mac_apt.stdout"), os.path.join(out, "mac_apt.stderr")])
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
               "lines": read["lines"], "long_lines": read["long_lines"], "counts": counts, "plugins_not_started": missing, "plugins_listed_in": "plugins.tsv",
               "error_lines_outside_plugins": len(read["run_errors"]), "read_from_source": READ_FROM_SOURCE, "not_observed": NOT_OBSERVED}
    ran_any = bool(read["plugins"])
    extra = dict(more, plugins=receipt, secret_bearing=secret, sensitive_output="the files under mac_apt/ and the kept log hold the examined system's own content; a recipe cannot declare secret_output, so this receipt marks them")
    if read["started"] and ran_any and not problems:
        write_coverage(out, "complete", "mac_apt exited 0 and its log accounts for %d plugin(s): %d parsed, %d empty (by the log; not a count of records)" % (len(rows), counts["parsed"], counts["empty"]),
                       [], "mac_apt exited 0, its log was recognised from the start line to the finish line, and each of the %d requested plugin(s) is parsed or empty by the log (parsed means no line of its run holds an error word, which rests on a log format never observed); the wording behind `empty` was never observed" % len(rows), **extra)
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
