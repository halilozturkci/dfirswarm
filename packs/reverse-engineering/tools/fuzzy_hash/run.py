#!/usr/bin/env python3
"""SHA-256 and fuzzy hashes of one file, or a comparison of two, for static sample clustering.

SHA-256 is computed here, from the bytes, and establishes identity. ssdeep and TLSH are computed by the
installed programs and measure byte similarity only; they are leads, not attribution, and a score between
two files is a statement about their bytes.

Each engine runs on its own, under a time limit, with its whole output kept in a log file under the tool-output
directory (in a job, under $OUT) and none of it held in memory. A digest is accepted only when it has the shape
of that engine's digest: any other text is a diagnostic, never a digest. An engine that times out, fails, or
prints something unrecognised is a structured per-engine result and the answer is partial; the other engine's
result stands. A comparison that cannot be made names the input that prevented it. What each program printed for its
version command is recorded as printed.
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

TOOL = {"name": "fuzzy_hash", "version": 9}
PARSER = "fuzzy_hash/3"
DEFAULT_ENGINE_TIMEOUT = 120
TOTAL_BUDGET = 270                       # seconds for the whole call: the manifest's own limit is 300
VERSION_TIMEOUT = 10
PARSE_BYTES = 1 << 16                    # how much of an engine's stdout is read back for parsing
# TLSH's encodings have fixed lengths: a one- or three-byte checksum, a length byte, a quantile byte and 32 (128 buckets) or 64
# (256 buckets) bytes of body, as 70, 74, 134 or 138 hexadecimal digits, after an optional version prefix.
TLSH_RX = re.compile(r"^(?:T1)?(?:[0-9A-F]{70}|[0-9A-F]{74}|[0-9A-F]{134}|[0-9A-F]{138})$")
SSDEEP_RX = re.compile(r"^[0-9]+:[A-Za-z0-9+/]{1,64}:[A-Za-z0-9+/]{0,64}$")
SSDEEP_EMPTY_RX = re.compile(r"^[0-9]+::$")      # what ssdeep prints for an input too small to hash
DISTANCE_RX = re.compile(r"^[0-9]+$")
TLSH_SHORT = "the file is too short or has too little byte diversity for TLSH"


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

def _first_word(signum):
    """The last word of a stop signal that comes before main() has set the tool's own: one answer that says it was stopped and had produced
    nothing yet. main() replaces it, and installs the handlers again."""
    print(json.dumps({"error": "stopped by signal %d before the tool had begun its work" % signum, "status": "interrupted",
                      "status_basis": "the tool was stopped by signal %d before it had begun its work: nothing it read is an answer" % signum,
                      "tool": TOOL, "stopped_by_signal": signum}))
    sys.stdout.flush()


STATE["last_word"] = _first_word
install_signal_handlers()
# the stop handlers are installed here, at module level


def file_problem(path):
    """Why `path` is not a file this tool can read, in words that fit: a missing file, a directory, a pipe, a loop."""
    try:
        mode = os.stat(path).st_mode
    except FileNotFoundError:
        return "no such file"
    except OSError as exc:
        return "the file could not be examined: %s" % describe(exc)
    if stat.S_ISREG(mode):
        return None
    kinds = ((stat.S_ISDIR, "a directory"), (stat.S_ISFIFO, "a named pipe"), (stat.S_ISSOCK, "a socket"), (stat.S_ISBLK, "a block device"),
             (stat.S_ISCHR, "a character device"))
    return "not a regular file (%s)" % next((n for t, n in kinds if t(mode)), "a special file")


def shutil_which(name):
    for directory in os.environ.get("PATH", "").split(os.pathsep):
        candidate = os.path.join(directory, name)
        if os.path.isfile(candidate) and os.access(candidate, os.X_OK):
            return candidate
    return None


def sha256_of(path, deadline):
    """(the digest or None, bytes hashed, whether the whole file was): the pass ends at the call's own clock, one block of
    1 MiB after it, and then gives no digest at all, only how far it got."""
    digest = hashlib.sha256()
    size = 0
    with open(path, "rb") as fh:
        while True:
            if time.monotonic() > deadline:
                return None, size, False
            block = fh.read(1 << 20)
            if not block:
                break
            size += len(block)
            digest.update(block)
    return digest.hexdigest(), size, True


def own_dir(path):
    """Create the tool-output directory and return None, or say why it is not used: a symbolic link anywhere on the way (the directory itself,
    or work/ or the agent's directory under it) would send the tables and the private names file somewhere else, and O_NOFOLLOW guards only
    the last name of a file. In a job only the part under $OUT is checked ($OUT is the job service's)."""
    path = Path(path)
    out = os.environ.get("OUT")
    start = len(Path(out).parts) if out and path.parts[:len(Path(out).parts)] == Path(out).parts else 0
    for i in range(max(start, 1), len(path.parts) + 1):
        step = Path(*path.parts[:i])
        if os.path.islink(step):
            return "%s is a symbolic link: refused, nothing written through it" % step
    path.mkdir(parents=True, exist_ok=True)
    return None


class Logs:
    """Two files, one for every engine's standard output and one for its standard error, each invocation preceded by
    a header line. The child writes straight into them (appending), so what it prints is never held here."""

    def __init__(self, key):
        out = os.environ.get("OUT")
        if out:
            self.dir = Path(out) / "tool-output"
        else:
            agent = re.sub(r"[^A-Za-z0-9_.-]", "_", os.environ.get("AGENT_ID") or "tool")
            self.dir = Path("work") / agent / "tool-output"
        digest = hashlib.sha256(json.dumps(key).encode("utf-8", "surrogatepass")).hexdigest()[:12]
        self.names = {}
        self.fhs = {}
        self.error = None
        try:
            refused = own_dir(self.dir)
            if refused:
                raise OSError(refused)
            for stream in ("stdout", "stderr"):
                self.fhs[stream], self.names[stream] = self._create("fuzzy-hash-%s.%s.log" % (digest, stream))
        except OSError as exc:
            self.error = "the engines' logs could not be created in %s (%s): their output is not kept" % (self.dir, describe(exc))
            for fh in self.fhs.values():
                fh.close()
            self.fhs, self.names = {}, {}

    def _create(self, name):
        stem, _dot, ext = name.rpartition(".")
        flags = os.O_RDWR | os.O_CREAT | os.O_EXCL | os.O_APPEND | getattr(os, "O_NOFOLLOW", 0)
        for n in range(1, 1000):
            candidate = name if n == 1 else "%s-%d.%s" % (stem, n, ext)
            try:
                fd = os.open(str(self.dir / candidate), flags, 0o644)
            except FileExistsError:
                continue
            return os.fdopen(fd, "ab", buffering=0), candidate
        raise OSError(errno.EEXIST, "a thousand files of this name already exist")

    @property
    def kept(self):
        return bool(self.fhs)


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
    grew, or that a process still holds open (end_holders ended those in the tool's group, so this is a process outside it), is not whole."""
    try:
        before = os.stat(path).st_size
        time.sleep(SETTLE_SECONDS)
        after = os.stat(path).st_size
    except OSError as exc:
        return False, "the file could not be looked at again: %s" % describe(exc)
    held = holders_of([path]) or []
    if after == before and not held:
        return True, None
    reasons = []
    if after != before:
        reasons.append("the file grew from %d to %d bytes after the program had ended" % (before, after))
    if held:
        reasons.append("a process (pid %s) outside the tool's process group still holds the file open" % ", ".join(str(p) for p in held[:5]))
    return False, "; ".join(reasons) + " (a process in a session of its own cannot be ended by this tool, and the file may still be growing)"


def run_engine(logs, argv, label, timeout):
    """Run one invocation. Returns a dict: status (ok, timeout, failed, launch_failed), returncode, stdout (the first
    64 KiB, as text), stderr (the first 2 KiB), bytes written to each stream, seconds."""
    import tempfile
    result = {"argv": argv, "label": label}
    started = time.monotonic()
    temps = []
    if logs.kept:
        handles = {}
        for stream, fh in logs.fhs.items():
            fh.write(("## %s: %s\n" % (label, " ".join(argv))).encode("utf-8", "replace"))
            handles[stream] = (fh, os.fstat(fh.fileno()).st_size)
    else:
        handles = {}
        for stream in ("stdout", "stderr"):
            fh = tempfile.TemporaryFile()
            temps.append(fh)
            handles[stream] = (fh, 0)
    try:
        proc = spawn(argv, stdout=handles["stdout"][0], stderr=handles["stderr"][0])
    except OSError as exc:
        result.update({"status": "launch_failed", "reason": "the program could not be started: %s" % describe(exc), "returncode": None,
                       "stdout": "", "stderr": "", "stdout_bytes": 0, "stderr_bytes": 0, "seconds": round(time.monotonic() - started, 3)})
        for fh in temps:
            fh.close()
        return result
    ACTIVE.append(proc)
    status = "ok"
    left = 0
    try:
        proc.wait(timeout=timeout)
    except subprocess.TimeoutExpired:
        status = "timeout"
        kill_tree(proc)
        proc.wait()
    finally:
        ACTIVE.remove(proc)
        # a process the engine left behind would go on writing into the log that is about to be read: whatever of the tool's group still holds the
        # engine's output files is ended, and waited for to be gone, before they are read
        ended, outside = end_holders([fh.fileno() for fh, _start in handles.values()])
        left = (len(ended) if status == "ok" else 0) + len(outside or [])
    result["returncode"] = proc.returncode
    result["seconds"] = round(time.monotonic() - started, 3)
    text = {}
    for stream, (fh, start) in handles.items():
        end = os.fstat(fh.fileno()).st_size
        n = min(end - start, PARSE_BYTES if stream == "stdout" else 2048)
        text[stream] = os.pread(fh.fileno(), n, start).decode("utf-8", "surrogateescape") if n > 0 else ""
        result[stream + "_bytes"] = max(0, end - start)
    for fh in temps:
        fh.close()
    result["stdout"], result["stderr"] = text["stdout"], text["stderr"]
    if status == "timeout":
        result["status"] = "timeout"
        result["reason"] = "the program was stopped at its time limit of %d second(s)" % timeout
    elif left:
        result["status"] = "failed"
        result["reason"] = ("the program left %d process(es) holding its output, which the tool ended before the output was read where it could (a process in a session of its own "
                            "cannot be ended by this tool): the output is not trusted" % left)
    elif proc.returncode != 0:
        result["status"] = "failed"
        first = next((l.strip() for l in text["stderr"].splitlines() if l.strip()), "")
        result["reason"] = first or "the program exited %d" % proc.returncode
    else:
        result["status"] = "ok"
    return result


def first_line(text):
    return next((line.strip() for line in text.splitlines() if line.strip()), "")


def parse_tlsh(run, path):
    """(digest or None, status, reason or None) for `tlsh -f FILE`: one row, a digest and, when the row names a file, this file."""
    if run["status"] != "ok":
        return None, run["status"], run["reason"]
    if run["stdout_bytes"] > PARSE_BYTES:
        return None, "unrecognised_output", "the program printed %d bytes where a digest line was expected" % run["stdout_bytes"]
    rows = [l.strip() for l in run["stdout"].splitlines() if l.strip()]
    if len(rows) != 1:
        return None, "unrecognised_output", "the program printed %d rows where one was expected" % len(rows)
    token, _tab, name = rows[0].partition("\t")
    token = token.strip()
    if token == "TNULL":
        return None, "insufficient_input", TLSH_SHORT
    if not TLSH_RX.match(token):
        return None, "unrecognised_output", "the program printed %r where a TLSH digest was expected" % rows[0][:200]
    if name.strip() and name.strip() != path:
        return None, "unrecognised_output", "the row names another file than the one asked for (%r)" % name.strip()[:200]
    return token, "ok", None


def parse_ssdeep(run, path):
    """The same for `ssdeep -b -- FILE`: a header line, then one row `blocksize:hash:hash,"name"` whose name, when present, is this file's."""
    if run["status"] != "ok":
        return None, run["status"], run["reason"]
    if run["stdout_bytes"] > PARSE_BYTES:
        return None, "unrecognised_output", "the program printed %d bytes where a digest line was expected" % run["stdout_bytes"]
    rows = [l.strip() for l in run["stdout"].splitlines() if l.strip() and not l.startswith("ssdeep,")]
    if not rows:
        return None, "unrecognised_output", "the program printed no digest line"
    if len(rows) != 1:
        return None, "unrecognised_output", "the program printed %d rows where one was expected" % len(rows)
    token, _comma, name = rows[0].partition(",")
    name = name.strip().strip('"')
    if SSDEEP_EMPTY_RX.match(token):
        return None, "insufficient_input", "the input is too small for ssdeep to hash"
    if not SSDEEP_RX.match(token):
        return None, "unrecognised_output", "the program printed %r where an ssdeep digest was expected" % rows[0][:200]
    if name and name != os.path.basename(path):
        return None, "unrecognised_output", "the row names another file than the one asked for (%r)" % name[:200]
    return token, "ok", None


class Run:
    def __init__(self, logs, engine_timeout):
        self.logs = logs
        self.engine_timeout = engine_timeout
        self.deadline = time.monotonic() + TOTAL_BUDGET
        self.partial = []                # the file entries, filled as the engines answer, for the last word of a stopped call
        self.problems = []

    def call(self, argv, label, cap=None):
        remaining = self.deadline - time.monotonic()
        if remaining <= 0:
            return {"argv": argv, "label": label, "status": "not_attempted", "returncode": None, "stdout": "", "stderr": "", "stdout_bytes": 0,
                    "stderr_bytes": 0, "reason": "the call's time budget of %d seconds was spent before this engine ran" % TOTAL_BUDGET}
        timeout = max(1, min(cap or self.engine_timeout, self.engine_timeout, int(remaining)))
        run = run_engine(self.logs, argv, label, timeout)
        if run["status"] == "timeout":
            run["reason"] = "the program was stopped at its time limit of %d second%s" % (timeout, "" if timeout == 1 else "s")
        return run


def hash_one(runner, path, label):
    sha, hashed, whole = sha256_of(path, runner.deadline)
    entry = {"path": path, "bytes": hashed if whole else os.path.getsize(path), "sha256": sha}
    if not whole:
        entry["sha256_status"] = "not_attempted"
        entry["bytes_hashed"] = hashed
        runner.problems.append("sha256 of %s: the call's time budget of %d seconds ran out after %d of %d bytes: no digest is given, and the engines were not run on it"
                               % (label, TOTAL_BUDGET, hashed, entry["bytes"]))
    runner.partial.append(entry)
    for engine, argv, parse in (("ssdeep", ["ssdeep", "-b", "--", path], parse_ssdeep), ("tlsh", ["tlsh", "-f", path], parse_tlsh)):
        run = runner.call(argv, "%s %s" % (label, engine))
        digest, status, reason = parse(run, path)
        entry[engine] = digest
        entry[engine + "_status"] = status
        entry[engine + "_unavailable"] = reason
        if status not in ("ok", "insufficient_input"):
            runner.problems.append("%s of %s: %s (%s)" % (engine, label, status, reason))
    return entry


def engine_info(runner, name, version_argv, package):
    info = {"program": shutil_which(name), "version_command": version_argv}
    run = runner.call(version_argv, name + " version", VERSION_TIMEOUT)
    line = first_line(run["stdout"]) or first_line(run["stderr"])
    if run["status"] == "ok" and line:
        info["version_command_output"] = line[:200]
    else:
        info["version_command_output"] = None
        info["version_note"] = "the version command %s produced no usable output (%s)" % (" ".join(version_argv), run.get("reason") or "no output")
    if shutil_which("dpkg-query"):
        pkg = runner.call(["dpkg-query", "-W", "-f=${Version}", package], name + " package version", VERSION_TIMEOUT)
        if pkg["status"] == "ok" and first_line(pkg["stdout"]):
            info["package"] = {"name": package, "version": first_line(pkg["stdout"])[:100]}
    return info


def main():
    try:
        args = json.load(sys.stdin)
    except (ValueError, RecursionError) as exc:
        fail("arguments are not valid JSON", reason=str(exc))
    if not isinstance(args, dict):
        fail("arguments must be a JSON object")
    paths = [args.get("path")]
    if args.get("compare_to") is not None:
        paths.append(args.get("compare_to"))
    for path in paths:
        if not isinstance(path, str) or not path:
            fail("path and compare_to must be non-empty strings when supplied")
        why_not = file_problem(path)
        if why_not:
            fail(why_not, path=path)
    timeout = args.get("engine_timeout_seconds", DEFAULT_ENGINE_TIMEOUT)
    if isinstance(timeout, bool) or not isinstance(timeout, int) or not 1 <= timeout <= 600:
        fail("engine_timeout_seconds must be an integer from 1 to 600")
    if not shutil_which("ssdeep"):
        fail("ssdeep is not installed; this image cannot produce the declared fuzzy hash")
    if not shutil_which("tlsh"):
        fail("tlsh is not installed; this image cannot produce the declared TLSH result")

    logs = Logs([os.path.realpath(p) for p in paths])
    runner = Run(logs, timeout)
    install_signal_handlers()

    def last_word(signum):
        # A stop signal ends the engines (the handler did that) and the tool says it was stopped, with what it had.
        print(json.dumps({"error": "stopped by signal %d before the engines finished" % signum, "status": "interrupted",
                          "status_basis": "the tool was stopped by signal %d before the engines finished: the digests already computed are in `files`, and the engines were ended" % signum,
                          "tool": TOOL, "stopped_by_signal": signum, "files": runner.partial, "problems": runner.problems,
                          "logs": logs.names if logs.kept else None}))
        sys.stdout.flush()

    STATE["last_word"] = last_word
    if logs.error:
        runner.problems.append(logs.error)
    try:
        files = [hash_one(runner, path, "path" if i == 0 else "compare_to") for i, path in enumerate(paths)]
    except OSError as exc:
        fail("a file could not be read: %s" % describe(exc))
    comparison = None
    if len(files) == 2:
        distance, unavailable, attempt_failed = None, None, False
        a, b = files[0]["tlsh"], files[1]["tlsh"]
        if a and b:
            run = runner.call(["tlsh", "-c", paths[0], "-f", paths[1]], "tlsh compare")
            line = first_line(run["stdout"])
            token = line.split(None, 1)[0] if line else ""
            if run["status"] != "ok":
                unavailable = {"input": "both", "reason": "tlsh comparison %s: %s" % (run["status"], run.get("reason") or "no reason given")}
                attempt_failed = True
            elif DISTANCE_RX.match(token):
                distance = int(token)
            else:
                unavailable = {"input": "both", "reason": "tlsh returned an unrecognised comparison line: %r" % line[:200]}
                attempt_failed = True
        else:
            missing = [k for k, d in (("path", a), ("compare_to", b)) if not d]
            reasons = {k: files[0 if k == "path" else 1]["tlsh_unavailable"] for k in missing}
            unavailable = {"input": "both" if len(missing) == 2 else missing[0],
                           "reason": "; ".join("%s: %s" % (k, reasons[k]) for k in missing) if len(missing) == 2 else reasons[missing[0]]}
        # A comparison that could not be made because the program was asked and did not answer (or was not asked, the call's budget
        # being spent) is a problem; one that an engine's own "too short" answer rules out is not, and a digest missing for a
        # file has its own problem already.
        if attempt_failed or (unavailable and unavailable["reason"] and re.search(r"unrecognised|timeout|failed|launch_failed|not_attempted", unavailable["reason"])):
            runner.problems.append("tlsh comparison: %s" % unavailable["reason"])
        comparison = {
            "same_sha256": (files[0]["sha256"] == files[1]["sha256"]) if files[0]["sha256"] and files[1]["sha256"] else None,
            "tlsh_distance": distance,
            "unavailable": unavailable,
            "note": "A smaller TLSH distance means more similar bytes; it is a lead, not attribution. A distance of its own proves nothing "
                    "about shared code: shared libraries, packaging and padding produce it too.",
        }
    engines = {
        "ssdeep": {**engine_info(runner, "ssdeep", ["ssdeep", "-V"], "ssdeep"), "argv_per_file": ["ssdeep", "-b", "--", "<file>"]},
        "tlsh": {**engine_info(runner, "tlsh", ["tlsh", "-version"], "tlsh-tools"), "argv_per_file": ["tlsh", "-f", "<file>"],
                 "argv_comparison": ["tlsh", "-c", "<path>", "-f", "<compare_to>"]},
    }
    result = {
        "tool": TOOL,
        "parser": PARSER,
        "files": files,
        "comparison": comparison,
        "engines": engines,
        "status": "partial" if runner.problems else "complete",
        "status_basis": (("%d problem(s), the first of them: %s (each names the engine, its status or the call's %d-second budget; see `problems`)"
                          % (len(runner.problems), runner.problems[0][:300], TOTAL_BUDGET)) if runner.problems else
                         "ssdeep and tlsh each ran on every file within the call's %d-second budget and answered: a digest of the engine's own shape, "
                         "or its own insufficient_input" % TOTAL_BUDGET),
        "problems": runner.problems,
        "engine_timeout_seconds": timeout,
        "logs": {**logs.names, "format": "each invocation is preceded by a '## label: argv' line; the engine's whole output follows"} if logs.kept else None,
        "note": "SHA-256 establishes identity. ssdeep and TLSH measure byte similarity only; explain shared code or structure before assigning "
                "a family. 'insufficient_input' is an engine's own answer for a file that is too short or too uniform, not a failure.",
    }
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    try:
        main()
    except SystemExit:
        raise
    except Exception as exc:  # never a traceback and never a clean answer for a failure
        fail("unexpected failure: %s" % (describe(exc) if isinstance(exc, OSError) else "%s: %s" % (type(exc).__name__, exc)))
