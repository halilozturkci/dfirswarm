#!/usr/bin/env python3
"""A broad extraction of an Android full file-system acquisition with ALEAPP.

The pack's other Android recipe reads an adb backup's header and member list;
nothing parses a full file-system acquisition's artefacts until an agent
does. This one hands the whole acquisition (a tar, plain or compressed, or a
zip, whose members hold an Android userdata root) to ALEAPP, which runs its
artefact modules over it and writes a report per artefact: TSV files, a
timeline database and an HTML report. The TSVs and databases are the
searchable form; they are listed in index.tsv, and every file ALEAPP wrote is
kept under aleapp/.

    run.py detect --target T [--probe-out DIR]   exit 0 applies, 1 does not
    run.py run --target T --out DIR

WHAT `complete` MEANS. ALEAPP exiting 0 with a TSV in its output says the
program ran and wrote something; it does not say that every module ran, and a
module that failed while others wrote their reports leaves the same trace. So
the run reads ALEAPP's own log (the stdout and stderr it keeps whole, read as one
account) for one outcome per module, and writes them to modules.tsv (the text of
a log line is not copied into any of the run's files except as the kept log itself):

    completed      started, completed, and does not say it found nothing
    no_record      started, completed, and said "No file found" or "No data
                   found" and reported no record: it is never read as "the
                   artefact is absent from the phone", only as what that module
                   found in this acquisition
    unsupported    started, completed, reported no record and said "Unsupported
                   version for ..." (the module's own gate on the operating-system
                   version): the module did not read this acquisition's version,
                   which says nothing about whether the artefact is there
    errored        the log says the module failed ("artifact failed after", or
                   "Reading <artefact> artifact had errors!")
    errors_logged  completed, and wrote lines that speak of an error (a module
                   that cannot read a table says so and completes)
    unknown        started, and the log does not say how it ended

The status is `complete` only when the program exited 0, wrote at least one TSV
report (a file under a data/ or media/ folder of the report is a copy of a file the
program read, not a report), the log was recognised (at least one module started),
every module is completed, no_record or unsupported, no line outside a module
speaks of an error, stderr holds no line that is not a log line of the shapes
above, the log says how many modules it
will parse (an "Artifact to parse: N" line, or the [i/N] prefix of a module line)
and that many started, and the log ends with "Processes completed.". The log shape read is the one iLEAPP v2026.4.1 prints; ALEAPP's has not been
checked against a real run here, and a log that differs (one with no count, or no
end line) leaves the run partial, and the receipt says so.

A run that is stopped before its end leaves coverage.json saying partial, so
what it wrote is read as partial and never as complete. A run never writes over
an earlier run's output: if the output directory already holds aleapp/ or a
coverage.json, it refuses and leaves them as they are. The exit status is the
program's own (0 when it exited 0, 1 otherwise); the answer is the `status` in
coverage.json, and `ok` in the printed line says only that the program exited 0.

The input is a tar (plain, gzip, bzip2 or xz) or a zip, told apart by what the file
is and not by what zipfile finds in it: a tar header whose checksum holds, or a
compressed stream, is a tar even when its last member is a zip. A tar is scanned for
the platform's marker header by header, apart from the library that lists it: an
extended header (a GNU long name, a pax header) that declares more than 16 MiB is
not read, since the library would hold it whole in memory.
"""
import argparse
import io
import json
import os
import re
import shutil
import signal
import struct
import subprocess
import sys
import tarfile
import zipfile
import zlib


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

ANDROID_MARKERS = (
    "data/system/packages.xml",
    "data/system/packages.list",
    "data/data/com.android.providers.",
    "data/user_de/0/com.android.",
)
NOT_COVERED = ("artefacts no module of the pinned ALEAPP release parses; deleted records beyond what a module reads "
               "itself (no carving); protected data that needs a key it does not have (file-based encryption without "
               "its keys); archives nested inside the acquisition; a module the log does not account for as completed")

# --- the module receipt: held equal to the one in the iOS recipe by a test ----------------------------
# The log lines a LEAPP program prints for each artefact module, as iLEAPP v2026.4.1 prints them:
#   [12/1139] name [module] artifact started at 09:29:44 UTC
#   Found 3 records for X | No file found | No data found for X     (what the module says it did)
#   Unsupported version for X for iOS 16.3                          (a module's own gate on the OS version)
#   name [module] artifact completed in 0.0s   |   name [module] artifact failed after 0.0s
#   Reading name artifact had errors!          (before a failure, with the module's own error text)
#   Artifact to parse: 1139   ...   Processes completed.
# A count in "Found" has thousands separators ("Found 205,098 records for X"). A release that prints other lines
# leaves its modules unknown, and the run partial.
LOG_START = re.compile(r"^(?:\[\d+/(?P<total>\d+)\] )?(?P<name>.+?) \[(?P<module>[^\[\]]+)\] artifact started(?: at .+)?\s*$")
LOG_DONE = re.compile(r"^(?P<name>.+?) \[(?P<module>[^\[\]]+)\] artifact completed(?: in .+)?\s*$")
LOG_FAILED = re.compile(r"^(?P<name>.+?) \[(?P<module>[^\[\]]+)\] artifact failed(?: after .+)?\s*$")
LOG_ERROR = re.compile(r"^Reading (?P<name>.+?) artifact had errors!\s*$")
LOG_FOUND = re.compile(r"^Found (?P<n>\d{1,3}(?:,\d{3})+|\d+) records? for ")
LOG_NO_FILE = re.compile(r"^No files? found\s*$")
LOG_NO_DATA = re.compile(r"^No data found for ")
LOG_UNSUPPORTED = re.compile(r"^Unsupported version for .+ for \S+ \S+\s*$")
LOG_EXPECTED = re.compile(r"^Artifact to parse: (?P<n>\d+)\s*$")
# Words a module uses when it could not do what it set out to do and went on. A line that holds one, inside a
# module that then completed, makes the module errors_logged, and one outside any module is counted on its own:
# a missed word makes a run complete that is not, a needless one makes it partial, and the second costs a look
# at the log.
LOG_PROBLEM = re.compile(r"\b(\w*(errors?|exceptions?)|traceback|unable|failed|failures?|could not|couldn't|cannot|can't|corrupt(ed)?|"
                         r"malformed|invalid|permission denied|no such (table|column|file)|not a database|unsupported|skipping|skipped|"
                         r"errno|no space left|out of memory|killed|segmentation fault|core dumped|aborted)\b", re.I)
LOG_LINE_BOUND = 4000
FIRST_UNATTRIBUTED = 20
STATUSES = ("completed", "no_record", "unsupported", "errored", "errors_logged", "unknown")


def tsv_escape(value):
    """One line, one field, nothing hidden: backslash, tab, newline, return and other controls escaped."""
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


def read_log(path, source, events, facts):
    """Append (kind, artefact, module, source, line number, extra) for each module line of a kept log, and
    note what the log says about the run itself; count tracebacks and the lines that are not empty and that no
    pattern here recognises (on stderr, each is a line nothing explains). A line is read to LOG_LINE_BOUND
    bytes and the rest of it skipped. The text of a log line is never kept."""
    tracebacks = unread = 0
    try:
        with open(path, "rb") as fh:
            number = 0
            while True:
                raw = fh.readline(LOG_LINE_BOUND + 1)
                if not raw:
                    break
                number += 1
                if len(raw) > LOG_LINE_BOUND and not raw.endswith(b"\n"):
                    while True:
                        rest = fh.readline(1 << 16)
                        if not rest or rest.endswith(b"\n"):
                            break
                line = raw[:LOG_LINE_BOUND].decode("utf-8", "replace").rstrip("\r\n")
                found = LOG_START.match(line)
                if found:
                    events.append(("start", found.group("name"), found.group("module"), source, number, None))
                    if found.group("total"):
                        facts["total"] = int(found.group("total"))
                    continue
                found = LOG_DONE.match(line)
                if found:
                    events.append(("done", found.group("name"), found.group("module"), source, number, None))
                    continue
                found = LOG_FAILED.match(line)
                if found:
                    events.append(("failed", found.group("name"), found.group("module"), source, number, None))
                    continue
                found = LOG_ERROR.match(line)
                if found:
                    events.append(("error", found.group("name"), None, source, number, None))
                    continue
                found = LOG_FOUND.match(line)
                if found:
                    events.append(("found", None, None, source, number, int(found.group("n").replace(",", ""))))
                    continue
                if LOG_NO_FILE.match(line):
                    events.append(("nofile", None, None, source, number, None))
                    continue
                if LOG_NO_DATA.match(line):
                    events.append(("nodata", None, None, source, number, None))
                    continue
                if LOG_UNSUPPORTED.match(line):
                    events.append(("unsupported", None, None, source, number, None))
                    continue
                found = LOG_EXPECTED.match(line)
                if found:
                    facts["expected"] = int(found.group("n"))
                    continue
                if line.startswith("Processes completed."):
                    facts["end"] = True
                    continue
                if line.strip():
                    unread += 1
                if line.startswith("Traceback (most recent call last):"):
                    tracebacks += 1
                if LOG_PROBLEM.search(line):
                    events.append(("problem", None, None, source, number, None))
    except OSError:
        pass
    return tracebacks, unread


def receipt(events):
    """One row per module the log names, in the order they started, and what could not be attributed.

    A module's lines are those between its start and its completed or failed line. errored: the log says
    it failed. errors_logged: it completed, and wrote lines that speak of an error (a module that could
    not read a table says so and completes). unsupported: it completed, reported no record and said its
    version gate does not take this acquisition's operating system. no_record: it completed and said it
    found no file, or no data. completed: it completed and does not say it found nothing. unknown: it
    started and the log does not say how it ended. A line that speaks of an error outside any module
    (between modules, before the first, after the last) is returned on its own, as a locator.
    """
    order, modules, current, unattributed, outside = [], {}, None, [], []
    for kind, name, module, source, line, extra in events:
        if kind == "start":
            key = (module, name)
            if key not in modules:
                modules[key] = {"artefact": name, "module": module, "state": "started", "log": source, "line": line,
                                "records": 0, "nofile": False, "nodata": False, "gated": False, "notes": 0, "errored": False}
                order.append(key)
            elif modules[key]["state"] in ("done", "failed"):
                modules[key]["state"] = "started"        # started again: an error already seen stays
            current = key
        elif kind in ("done", "failed"):
            row = modules.get((module, name))
            if row is None:
                unattributed.append({"what": "a %s line with no start" % ("completed" if kind == "done" else "failed"), "artefact": name, "log": source, "line": line})
                continue
            row["state"] = "done" if kind == "done" else "failed"
            if kind == "failed":
                row["errored"] = True
            current = None
        elif kind == "error":
            key = current if current is not None and modules[current]["artefact"] == name else None
            if key is None:
                for candidate in reversed(order):
                    if modules[candidate]["artefact"] == name:
                        key = candidate
                        break
            if key is None:
                unattributed.append({"what": "an error line for an artefact that never started", "artefact": name, "log": source, "line": line})
            else:
                modules[key]["errored"] = True
                modules[key]["error_log"], modules[key]["error_line"] = source, line
        elif current is not None:
            row = modules[current]
            if kind == "found":
                row["records"] += extra
            elif kind == "nofile":
                row["nofile"] = True
            elif kind == "nodata":
                row["nodata"] = True
            elif kind == "unsupported":
                row["gated"] = True
            elif kind == "problem":
                row["notes"] += 1
        elif kind == "problem":
            outside.append({"log": source, "line": line})
    rows = []
    for key in order:
        row = modules[key]
        if row["errored"]:
            status = "errored"
        elif row["state"] != "done":
            status = "unknown"
        elif row["notes"]:
            status = "errors_logged"
        elif row["records"] == 0 and row["gated"]:
            status = "unsupported"
        elif row["records"] == 0 and (row["nofile"] or row["nodata"]):
            status = "no_record"
        else:
            status = "completed"
        reason = {"no_record": "no source file" if row["nofile"] else "no data", "unsupported": "the module does not take this operating-system version"}.get(status)
        rows.append({**row, "status": status, "reason": reason})
    counts = {name: 0 for name in STATUSES}
    for row in rows:
        counts[row["status"]] += 1
    return rows, counts, unattributed, outside


def write_modules(out, rows):
    with open(os.path.join(out, "modules.tsv"), "w", encoding="utf-8", newline="\n") as handle:
        handle.write("n\tstatus\tartefact\tmodule\trecords\tlogged_error_lines\tlog\tline\n")
        for n, row in enumerate(rows):
            handle.write("%d\t%s\t%s\t%s\t%d\t%d\t%s\t%d\n" % (n, row["status"], tsv_escape(row["artefact"]), tsv_escape(row["module"]),
                                                              row["records"], row["notes"], row["log"], row["line"]))
# --- end of the module receipt -------------------------------------------------------------------------


def target_of(value):
    text = open(value, encoding="utf-8").read() if os.path.isfile(value) else value
    target = json.loads(text)
    paths = target.get("paths") or []
    if not paths or not isinstance(paths[0], str):
        raise ValueError("the target names no path")
    return target, paths[0]


# --- tar watch: begin ----------------------------------------------------------------------------
# Held byte for byte equal in the four recipes that read a tar (a test compares the copies). The watch
# follows a tar header by header, apart from the library that lists it, and says what that library does
# not: whether the end-of-archive blocks came, whether a header would be refused (a checksum that does not
# match, a number that does not parse), how many members there are, and whether an extended header declares
# more than the library should be allowed to hold in memory (it reads a GNU long name or a pax header whole).
# The end of an archive is TWO zero blocks. One zero block with a header after it is not an end: GNU tar and bsdtar
# warn ("lone zero block") and read on, and so does the listing (the library is opened with ignore_zeros); the watch
# counts such blocks, and the run is partial for them.
EXTENDED_HEADER_LIMIT = 16 << 20
ZERO_BLOCK = b"\0" * 512
NO_DATA_TYPES = set(b"123456")        # hard link, symbolic link, character and block device, directory, fifo: the size is not followed by data


def tar_number(field):
    """A tar numeric field as the tar library reads it: octal text, or base-256 when the top bit is set."""
    if field[0] in (0o200, 0o377):
        n = 0
        for i in range(len(field) - 1):
            n = (n << 8) + field[i + 1]
        return -(256 ** (len(field) - 1) - n) if field[0] == 0o377 else n
    return int(bytes(field).split(b"\0")[0].decode("ascii").strip() or "0", 8)


def tar_header(block):
    """The size field of a header the tar library would accept, or None if it would refuse it."""
    try:
        for start, end in ((100, 108), (108, 116), (116, 124), (136, 148), (329, 337), (337, 345)):
            tar_number(block[start:end])
        checksum = tar_number(block[148:156])
        size = tar_number(block[124:136])
    except ValueError:
        return None
    unsigned = 256 + sum(block[:148]) + sum(block[156:])
    signed = 256 + sum(struct.unpack_from("148b", block)) + sum(struct.unpack_from("356b", block, 156))
    return size if checksum in (unsigned, signed) else None


def pax_size(data):
    """The `size` record of a pax header ("<length> <key>=<value>\\n" records), or None; one that is not a number reads as 0, as the library reads it."""
    size, pos = None, 0
    while pos < len(data):
        space = data.find(b" ", pos)
        if space < 0:
            break
        try:
            length = int(data[pos:space])
        except ValueError:
            break
        if length <= 0 or pos + length > len(data):
            break
        key, _, value = data[space + 1:pos + length - 1].partition(b"=")
        if key == b"size":
            try:
                size = int(value)
            except ValueError:
                size = 0
        pos += length
    return size


class TarWatch:
    def __init__(self):
        self.block = bytearray()
        self.skip = 0
        self.collect = 0
        self.collect_padding = 0
        self.collecting = None
        self.acc = bytearray()
        self.position = 0
        self.ended = False
        self.end_at = None           # where the end-of-archive blocks start
        self.zero_at = None          # a zero block just met, the first of the two that end the archive unless a header follows
        self.lone_zeros = 0          # zero blocks that a header followed: not an end
        self.lone_first = None       # where the first of them is
        self.tail_at = None          # the first byte that is not zero after the end-of-archive blocks
        self.zeroed_data = 0         # GNU long-name, long-link and pax headers whose data starts with a zero byte: a name block that was wiped
        self.violation = None        # the size an extended header declares, over the limit
        self.violation_at = None     # where that header starts
        self.bad_at = None           # where a header starts that the tar library would refuse
        self.truncated = False       # a walk reached the end of the file inside a header or its data
        self.members = 0
        self.next_size = None        # a pax `size` for the next member
        self.global_size = None      # one from a global pax header
        self.in_ext = False          # inside the extension blocks of a GNU sparse header
        self.after_ext = 0

    def stopped(self):
        return self.ended or self.violation is not None or self.bad_at is not None

    def stop_at(self):
        """Where the library must see the end of the data: before a header it must not read, or at the end block."""
        for at in (self.violation_at, self.bad_at, self.end_at):
            if at is not None:
                return at
        return None

    def feed(self, data):
        """Follow bytes as they flow past."""
        i, n = 0, len(data)
        while i < n and not self.stopped():
            if self.collect:
                take = min(self.collect, n - i)
                self.acc += data[i:i + take]
                self.collect -= take
                i += take
                self.position += take
                if not self.collect:
                    self.finish_pax()
                continue
            if self.skip:
                step = min(self.skip, n - i)
                self.skip -= step
                i += step
                self.position += step
                continue
            take = min(512 - len(self.block), n - i)
            self.block += data[i:i + take]
            i += take
            self.position += take
            if len(self.block) == 512:
                self.header(bytes(self.block))
                self.block.clear()
        if self.stopped():
            if self.ended and self.tail_at is None and i < n:
                rest = data[i:]
                if rest.count(0) != len(rest):
                    self.tail_at = self.position + len(rest) - len(rest.lstrip(b"\0"))
            self.position += n - i

    def walk(self, fh, size, until=None):
        """Follow a file that can seek, header to header: the data between headers is jumped over, not read."""
        while not self.stopped() and not self.truncated and (until is None or self.position < until):
            if self.collect:
                data = fh.read(self.collect)
                if len(data) < self.collect:
                    self.truncated = True
                    return
                self.acc += data
                self.position += len(data)
                self.collect = 0
                self.finish_pax()
                continue
            if self.skip:
                if self.position + self.skip > size:
                    self.truncated = True
                    return
                fh.seek(self.position + self.skip)
                self.position += self.skip
                self.skip = 0
                continue
            fh.seek(self.position)
            block = fh.read(512)
            if len(block) < 512:
                self.truncated = True
                return
            self.position += 512
            self.header(block)

    def look_past_end(self, fh, size):
        """For a tar on disk whose end blocks came: where the first byte that is not zero lies after them (padding to a record is zeros)."""
        if not self.ended or self.tail_at is not None:
            return
        at = self.end_at + 1024
        while at < size:
            fh.seek(at)
            chunk = fh.read(min(1 << 20, size - at))
            if not chunk:
                return
            data = chunk.lstrip(b"\0")
            if data:
                self.tail_at = at + len(chunk) - len(data)
                return
            at += len(chunk)

    def finish_pax(self):
        if self.acc[:1] == b"\0":
            self.zeroed_data += 1        # a name or a pax record never starts with a zero byte
        if self.collecting in (ord("L"), ord("K")):
            self.acc.clear()             # only its first byte was read: the library reads the name itself
            self.skip = self.collect_padding
            return
        size = pax_size(bytes(self.acc))
        if self.collecting in (ord("x"), ord("X")):
            # The library starts from the global records and lets this header's override them.
            self.next_size = size if size is not None else self.global_size
        else:
            if size is not None:
                self.global_size = size
            self.next_size = self.global_size     # a global header applies to the member that follows it
        self.acc.clear()
        self.skip = self.collect_padding

    def header(self, block):
        start = self.position - 512
        if self.in_ext:
            if not block[504]:
                self.in_ext = False
                self.skip = self.after_ext
            return
        if block == ZERO_BLOCK:
            if self.zero_at is None:
                self.zero_at = start
            else:
                self.ended, self.end_at = True, self.zero_at
            return
        if self.zero_at is not None:
            self.lone_zeros += 1
            if self.lone_first is None:
                self.lone_first = self.zero_at
            self.zero_at = None
        size = tar_header(block)
        if size is None or size < 0:
            self.bad_at = start
            return
        flag = block[156]
        if flag in b"xgX":
            if size > EXTENDED_HEADER_LIMIT:
                self.violation, self.violation_at = size, start
                return
            self.collecting, self.collect, self.collect_padding = flag, size, -size % 512
            if not size:
                self.finish_pax()
            return
        if flag in b"LK":
            if size > EXTENDED_HEADER_LIMIT:
                self.violation, self.violation_at = size, start
                return
            padded = -(-size // 512) * 512
            if size:
                self.collecting, self.collect, self.collect_padding = flag, 1, padded - 1       # its first byte is looked at: a wiped name starts with zero
            else:
                self.skip = padded
            return
        self.members += 1
        if flag in NO_DATA_TYPES:
            self.next_size = None
            return
        if self.next_size is not None:
            # A pax `size` record is the size of the entry it precedes, over the header's own.
            size = self.next_size
        self.next_size = None
        padded = -(-size // 512) * 512
        if flag == ord("S") and block[482]:
            self.in_ext, self.after_ext = True, padded
        else:
            self.skip = padded


def tar_verdict(watch, listed, cut_short=False):
    """What the watch saw, set against the `listed` members the library returned: (tar_end, limits, errors).

    `cut_short`: the bytes were stopped by a budget, so neither the end blocks nor the count is judged.
    """
    limits, errors = [], []
    if watch.violation is not None:
        tar_end = "not_reached"
        limits.append("a tar extended header at offset %d declares %d bytes, over the limit of %d: it is not read, and the listing stopped after %d members"
                      % (watch.violation_at, watch.violation, EXTENDED_HEADER_LIMIT, listed))
    elif watch.bad_at is not None:
        tar_end = "not_reached"
        errors.append("the tar header at offset %d is not one the tar reader accepts (a checksum that does not match, or a number that does not parse): the listing stopped there, after %d members"
                      % (watch.bad_at, listed))
    elif watch.ended:
        tar_end = "reached"
    elif cut_short:
        tar_end = "not_reached"
    else:
        tar_end = "missing"
        if watch.zero_at is not None:
            errors.append("the tar ends after one zero block at offset %d, and an archive ends with two (%d bytes read): it is cut short or damaged, and the listing is what came before"
                          % (watch.zero_at, watch.position))
        else:
            errors.append("the tar ends without its end-of-archive blocks (%d bytes read): the archive is cut short or damaged, and the listing is what came before the cut" % watch.position)
    if watch.lone_zeros:
        errors.append("%d lone zero block(s) inside the tar, the first at offset %d: an archive ends with two zero blocks, and this one goes on after each. GNU tar and bsdtar "
                      "warn and read on, and so does this listing, but the archive was written or damaged in a way a clean one is not"
                      % (watch.lone_zeros, watch.lone_first))
    if watch.zeroed_data:
        errors.append("%d GNU long-name, long-link or pax header(s) whose data starts with a zero byte: the data block was wiped, and the member that follows carries a name "
                      "the archive does not hold" % watch.zeroed_data)
    if watch.tail_at is not None and not cut_short:
        errors.append("data follows the tar's end-of-archive blocks (the first byte that is not zero is at offset %d of the tar): tar stops at the blocks and so does this listing, "
                      "so an archive appended to this one, or anything else after them, is not listed" % watch.tail_at)
    if not cut_short and listed != watch.members:
        errors.append("the tar reader listed %d members and a header-by-header walk counted %d: the two disagree, so the listing may be missing members" % (listed, watch.members))
    return tar_end, limits, errors
# --- tar watch: end ------------------------------------------------------------------------------


# --- tar listing: begin --------------------------------------------------------------------------
CLOCK_BYTES = 16 << 20       # the clock is read at least once for every this many decoded bytes of a compressed tar, so that one huge member cannot outlast max-seconds by more than the time to decode this much
# Held byte for byte equal in the three recipes that open a tar by its path (a test compares the copies).
# A plain tar is read through Guarded and a gzip, bzip2 or xz one through Decoded; both keep the watch
# just ahead of the library and give it an end of data where the watch stops it. The library is opened with
# ignore_zeros, so that a zero block with a header after it is read past, as GNU tar does (the watch has already
# cut the data at the two zero blocks that end the archive, so nothing past the end is read). Decoded has an
# output budget: a compressed tar that expands past it stops the listing, and the run says partial.
def compression_of(head):
    if head[:2] == b"\x1f\x8b":
        return "gz"
    if head[:3] == b"BZh":
        return "bz2"
    if head[:6] == b"\xfd7zXZ\x00":
        return "xz"
    return None


class Guarded(io.RawIOBase):
    """A plain tar on disk as a file for the tar library. A walk of the same file runs just ahead of the library, and
    the library is given an end of file where the walk stops it: before an extended header too large to hold, before a
    header it would refuse, or at the end-of-archive block."""

    def __init__(self, handle, walker, size, watch):
        self.handle, self.walker, self.size, self.watch = handle, walker, size, watch
        self.pos = 0

    def readable(self):
        return True

    def seekable(self):
        return True

    def tell(self):
        return self.pos

    def seek(self, offset, whence=0):
        self.pos = max(0, (offset, self.pos + offset, self.size + offset)[whence])
        return self.pos

    def readinto(self, target):
        self.watch.walk(self.walker, self.size, self.pos + len(target))
        stop = self.watch.stop_at()
        limit = self.size if stop is None else min(stop, self.size)
        count = max(0, min(len(target), limit - self.pos))
        if not count:
            return 0
        self.handle.seek(self.pos)
        data = self.handle.read(count)
        target[:len(data)] = data
        self.pos += len(data)
        return len(data)

    def finish(self):
        """The rest of the headers, so that the watch has its whole answer."""
        self.watch.walk(self.walker, self.size)
        self.watch.look_past_end(self.walker, self.size)


class Decoded(io.RawIOBase):
    """A gzip, bzip2 or xz stream as a plain file for the tar library, read in pieces and followed by the watch; nothing
    is served from the point where the watch stops it."""

    PIECE = 1 << 20

    def __init__(self, source, kind, watch, budget=None, deadline=None):
        self.source, self.kind, self.watch = source, kind, watch
        self.deadline = deadline      # the time (time.monotonic) past which the stream serves no more, or None
        self.looked = 0               # decoded bytes since the clock was last read
        self.timed_out = False        # the stream was ended because the deadline had passed
        self.budget = budget          # at most this many decoded bytes, or None
        self.produced = 0
        self.exceeded = False         # the stream held more than the budget
        self.errors = (zlib.error, ValueError, OSError)
        if kind == "gz":
            self.decoder = zlib.decompressobj(31)
        elif kind == "bz2":
            import bz2
            self.decoder = bz2.BZ2Decompressor()
        else:
            import lzma
            self.decoder = lzma.LZMADecompressor()
            self.errors += (lzma.LZMAError,)
        self.pending = b""
        self.buffer = bytearray()
        self.served = 0
        self.finished = False
        self.trouble = None    # what is wrong with the stream: it ended before its end marker, or its checksum does not hold

    def readable(self):
        return True

    def piece(self):
        """The next decoded piece, or None at the end of the stream or of the budget."""
        if self.exceeded or self.timed_out:
            return None
        out = self._piece()
        if out and self.deadline is not None:
            self.looked += len(out)
            if self.looked >= CLOCK_BYTES:
                self.looked = 0
                if time.monotonic() > self.deadline:
                    self.timed_out = True      # this piece is served; the next call ends the stream, in the middle of a member if need be
        if out is None or self.budget is None:
            return out
        room = self.budget - self.produced
        if len(out) > room:
            self.exceeded = True
            out = out[:max(room, 0)]
        self.produced += len(out)
        return out

    def _piece(self):
        d = self.decoder
        if self.kind == "gz":
            if not self.pending:
                if d.eof:
                    return None
                self.pending = self.source.read(self.PIECE)
                if not self.pending:
                    self.trouble = "the gzip stream ends before its end marker"
                    return None
            out = d.decompress(self.pending, self.PIECE)
            self.pending = d.unconsumed_tail
            return out
        if d.eof:
            return None
        chunk = b""
        if d.needs_input:
            chunk = self.source.read(self.PIECE)
            if not chunk:
                self.trouble = "the %s stream ends before its end marker" % self.kind
                return None
        return d.decompress(chunk, self.PIECE)

    def fill(self):
        while not self.buffer and not self.finished:
            try:
                out = self.piece()
            except self.errors as exc:
                raise OSError("the %s stream is damaged: %s" % (self.kind, exc))
            if out is None:
                self.finished = True
                break
            self.watch.feed(out)
            self.buffer += out
            stop = self.watch.stop_at()
            if stop is not None and self.served + len(self.buffer) > stop:
                del self.buffer[max(0, stop - self.served):]
                self.finished = True

    def readinto(self, target):
        self.fill()
        count = min(len(target), len(self.buffer))
        target[:count] = self.buffer[:count]
        del self.buffer[:count]
        self.served += count
        return count

    def finish(self):
        """The rest of the stream, so that the watch has its whole answer and the stream's own end marker and checksum are
        verified. A tar that stopped at a header the library would not read is not followed further."""
        while self.watch.violation is None and self.watch.bad_at is None:
            try:
                out = self.piece()
            except self.errors as exc:
                self.trouble = "the %s stream is damaged: %s" % (self.kind, exc)
                return
            if out is None:
                return
            self.watch.feed(out)


class NoMembers:
    """The listing of a tar whose very first header the watch would not let the library read."""

    members = []

    def __iter__(self):
        return iter(())

    def close(self):
        pass


class TarList:
    """A tar on disk, listed by the tar library behind a watch: `archive` is the library's TarFile, `watch` the watch.

    The data between members is not read for a plain tar, and a compressed one is read once, decoded in pieces. The
    library is given an end of data before any extended header the watch will not let it hold, and before a header it
    would refuse; `finish()` lets the watch follow the rest, and `watch` then says whether the end block came.
    """

    def __init__(self, path, budget=None, deadline=None):
        self.watch = TarWatch()
        self.handle = open(path, "rb")
        self.walker = None
        head = self.handle.read(6)
        self.handle.seek(0)
        kind = compression_of(head)
        try:
            if kind is None:
                self.walker = open(path, "rb")
                self.source = Guarded(self.handle, self.walker, os.fstat(self.handle.fileno()).st_size, self.watch)
                mode = "r:"
            else:
                self.source = Decoded(self.handle, kind, self.watch, budget, deadline)
                mode = "r|"
                self.source = io.BufferedReader(self.source)
            self.archive = tarfile.open(fileobj=self.source, mode=mode, encoding="utf-8", errors="surrogateescape", ignore_zeros=True)
            if (self.watch.ended and self.watch.end_at == 0) or self.watch.zero_at == 0:
                raise tarfile.ReadError("empty file")        # only zero blocks: the library, which skips them, would list nothing and say nothing
        except tarfile.TarError:
            if self.watch.violation is not None:
                self.archive = NoMembers()
                return
            trouble = getattr(getattr(self.source, "raw", self.source), "trouble", None)
            self.close()
            if trouble:
                raise tarfile.ReadError(trouble)
            if self.watch.bad_at == 0:
                raise tarfile.ReadError("the first header is not a tar header (a checksum that does not match, or a number that does not parse)")
            raise

    def finish(self):
        source = self.source.raw if isinstance(self.source, io.BufferedReader) else self.source
        source.finish()

    def timed_out(self):
        """Whether the clock ended a compressed tar's stream, which can be inside a member."""
        source = self.source.raw if isinstance(self.source, io.BufferedReader) else self.source
        return bool(getattr(source, "timed_out", False))

    def exceeded(self):
        """Whether a compressed tar held more than the budget (the listing stopped there)."""
        source = self.source.raw if isinstance(self.source, io.BufferedReader) else self.source
        return bool(getattr(source, "exceeded", False))

    def trouble(self):
        """For a compressed tar, what is wrong with the stream itself (cut before its end marker, a checksum that does not hold); otherwise None."""
        source = self.source.raw if isinstance(self.source, io.BufferedReader) else self.source
        return getattr(source, "trouble", None)

    def close(self):
        archive = getattr(self, "archive", None)
        if archive is not None:
            archive.close()
        for handle in (self.handle, self.walker):
            if handle is not None:
                handle.close()

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.close()
        return False
# --- tar listing: end ----------------------------------------------------------------------------


def android_name(name):
    low = name.lower()
    return any(marker in low for marker in ANDROID_MARKERS)


def container_kind(path):
    """tar or zip, decided by what the file is: a tar header whose checksum holds, or a gzip, bzip2 or xz stream (a
    compressed tar), is a tar; a file that starts with a zip signature is a zip; a file that is neither is still a zip
    when zipfile finds an end record in it (data before the first header, as in a self-extracting archive). The tar test
    comes first because zipfile finds the end record of a zip that is a MEMBER of a tar, near the tar's end, and would
    take the whole tar for a zip. Not zipfile.is_zipfile alone, whose answer changed between Python 3.11 and 3.14 for an
    archive whose end-of-central-directory record is damaged: dispatch does not depend on a library's verdict."""
    with open(path, "rb") as fh:
        head = fh.read(512)
    if len(head) == 512 and any(head) and tar_header(head) is not None:
        return "tar"
    if compression_of(head) is not None:
        return "tar"
    if head[:4] in (b"PK\x03\x04", b"PK\x05\x06", b"PK\x07\x08"):
        return "zip"
    try:
        with zipfile.ZipFile(path):
            return "zip"
    except (zipfile.BadZipFile, OSError):
        return "tar"


def detect(path):
    """(applies, why, kind): kind is ALEAPP's input type, tar or zip."""
    if not os.path.isfile(path):
        return False, "not a readable file", None
    try:
        kind = container_kind(path)
    except OSError as exc:
        return False, "not a readable file: %s" % (exc.strerror or exc), None
    if kind == "zip":
        try:
            with zipfile.ZipFile(path) as archive:
                for name in archive.namelist():
                    if android_name(name):
                        return True, "zip members have an Android userdata root", "zip"
        except (zipfile.BadZipFile, OSError) as exc:
            return False, "not a readable zip: %s" % exc, None
        return False, "zip has no Android userdata marker", None
    try:
        with TarList(path) as listing:
            for member in listing.archive:
                if android_name(member.name):
                    return True, "tar members have an Android userdata root", "tar"
                listing.archive.members = []
            if listing.watch.violation is not None:
                return False, "tar has no Android userdata marker before a header the scan does not read (an extended header of %d bytes at offset %d)" % (listing.watch.violation, listing.watch.violation_at), None
    except (tarfile.TarError, OSError, EOFError) as exc:
        return False, "not a readable tar or zip: %s" % exc, None
    return False, "tar has no Android userdata marker", None


def basis_of(lead, reasons):
    """The sentence status_basis is: the lead, then the first reasons (all of them are in `errors`)."""
    reasons = [str(r).replace("\n", " ") for r in reasons]
    return lead + "; ".join(reasons[:3]) + (" (and %d more in errors)" % (len(reasons) - 3) if len(reasons) > 3 else "")


def write_coverage(out, status, covered, errors, basis, limits=(), **more):
    with open(os.path.join(out, "coverage.json"), "w", encoding="utf-8") as handle:
        json.dump({"recipe": "android-aleapp", "status": status, "status_basis": basis, "covered": covered, "not_covered": NOT_COVERED,
                   "limits_hit": list(limits), "errors": list(errors), **more}, handle, indent=2, sort_keys=True)
        handle.write("\n")


def program():
    for name in ("aleapp", "aleapp.py"):
        found = shutil.which(name)
        if found:
            return os.path.abspath(found)
    return None


def index(out, report):
    """Every TSV and database ALEAPP wrote, one row each, relative to out/. A file under a data/ or media/ folder is a
    copy of a file of the acquisition that the program read, and is labelled so: it is not a report."""
    rows = []
    for dirpath, dirs, files in os.walk(report):
        dirs.sort()
        for name in sorted(files):
            low = name.lower()
            rel = os.path.relpath(os.path.join(dirpath, name), out)
            copied = any(part in ("data", "media") for part in rel.split(os.sep)[:-1])
            if not low.endswith((".tsv", ".db", ".sqlite", ".kml")):
                continue
            if copied:
                rows.append((rel, "copy of a file of the acquisition that ALEAPP read (%s), not a report" % name, True))
            elif low.endswith(".tsv"):
                rows.append((rel, "ALEAPP artefact report %s (TSV, one row per record)" % name[:-4], False))
            elif low.endswith((".db", ".sqlite")):
                rows.append((rel, "ALEAPP database %s (SQLite: the timeline, or every artefact's rows)" % name, False))
            else:
                rows.append((rel, "ALEAPP locations %s (KML)" % name, False))
    return rows


def write_index(out, rows):
    with open(os.path.join(out, "index.tsv"), "w", encoding="utf-8", newline="\n") as handle:
        for rel, what, _copied in rows:
            handle.write("%s\t%s\n" % (rel.replace("\t", " "), what))
        handle.write("modules.tsv\tone row per module the ALEAPP log names: completed, no_record, unsupported, errored, errors_logged or unknown, with the records it reports and the log line\n")
        handle.write("aleapp.stdout\tALEAPP's standard output, whole: the log that modules.tsv points into\n")
        handle.write("aleapp.stderr\tALEAPP's standard error, whole\n")


def child_files(directory):
    """How many files and links a program left in a directory this recipe gave it: kept, never deleted."""
    count = 0
    for _dirpath, dirs, files in os.walk(directory):
        count += len(files) + sum(1 for d in dirs if os.path.islink(os.path.join(_dirpath, d)))
    return count


LEAPP_SECONDS = 14100      # recipe.json limits.seconds (14400) less the time to write the account of the run
def last_word(signum):
    """The one line a stopped recipe prints (exit 128 plus the signal): the account written before the program started already says partial."""
    sys.stdout.write(json.dumps({"ok": False, "status": "partial", "status_basis": "the recipe was stopped by %s before ALEAPP finished: coverage.json, written before it started, says partial"
                                 % signal.Signals(signum).name}) + "\n")
    sys.stdout.flush()


def run_program(command, stdout, stderr, cwd, env, seconds):
    """(exit code, whether the time ran out) of the program. It runs in this recipe's own process group, never in a session of its own (the shared
    PROCESS block above: the harness ends a recipe by killing its group, and a program outside that group would go on writing into the output after
    the recipe was gone), and on Linux the kernel is asked to end it if the recipe dies. At `seconds` it and everything it started are ended and
    what it wrote stays. A stop signal ends the whole tree, whatever the program does with SIGTERM, before the recipe leaves (exit 128 plus the
    signal): the account written before the program started already says partial."""
    STATE["last_word"] = last_word
    install_signal_handlers()
    proc = spawn(command, stdout=stdout, stderr=stderr, cwd=cwd, env=env)
    ACTIVE.append(proc)
    try:
        try:
            return proc.wait(timeout=seconds), False
        except subprocess.TimeoutExpired:
            kill_tree(proc)
            return proc.wait(), True
    finally:
        ACTIVE.remove(proc)


def run(path, kind, out, seconds=LEAPP_SECONDS):
    out = os.path.abspath(out)       # the program runs from a directory under out: nothing here may be relative
    report = os.path.join(out, "aleapp")
    if os.path.lexists(report) or os.path.lexists(os.path.join(out, "coverage.json")):
        # Before anything is written: an earlier run's coverage and report stay as they are.
        print(json.dumps({"ok": False, "status": "failed", "status_basis": "the output directory already holds the files of an earlier run, and this recipe never writes over one: nothing was run", "why": "the output directory already holds aleapp/ or coverage.json: the recipe does not write over an earlier run"}))
        return 2
    os.makedirs(out, exist_ok=True)
    # Said before ALEAPP starts: a run stopped at its limit leaves this, and is read as partial.
    write_coverage(out, "partial", "started; ALEAPP did not finish (stopped before its end)", ["the run ended before ALEAPP did"],
                   "the run started and ALEAPP had not finished when this was written: a run that is stopped before its end leaves this account")
    prog = program()
    if not prog:
        write_coverage(out, "failed", "nothing: ALEAPP is not in this image", ["aleapp is not on PATH in this job image"],
                       "ALEAPP is not in this image, so nothing was parsed")
        return 1
    path = os.path.abspath(path)
    scratch = os.path.join(out, "aleapp-run")
    # The run directory is read-only in a job: the program's working directory and its temporary files
    # are under the output, and every file it leaves there is kept and counted.
    cwd = os.path.join(out, "aleapp-cwd")
    temp = os.path.join(out, "aleapp-tmp")
    for directory in (scratch, cwd, temp):
        os.makedirs(directory, exist_ok=True)
    env = dict(os.environ, TMPDIR=temp)
    with open(os.path.join(out, "aleapp.stdout"), "wb") as so, open(os.path.join(out, "aleapp.stderr"), "wb") as se:
        rc, timed_out = run_program([prog, "-t", kind, "-i", path, "-o", scratch], so, se, cwd, env, seconds)
    made = [d for d in sorted(os.listdir(scratch)) if os.path.isdir(os.path.join(scratch, d)) and not os.path.islink(os.path.join(scratch, d))]
    layout, siblings = "whole output directory", False
    if len(made) == 1:
        os.rename(os.path.join(scratch, made[0]), report)
        left = sorted(os.listdir(scratch))
        if left:
            # Files the program wrote beside its report folder are kept, whole, in a directory of their own.
            os.rename(scratch, os.path.join(out, "aleapp-run-files"))
            siblings = True
            layout = "one report folder; %d file(s) beside it kept in aleapp-run-files/" % len(left)
        else:
            os.rmdir(scratch)
            layout = "one report folder"
    else:
        os.rename(scratch, report)
    kept = {}
    for name, directory in (("aleapp-cwd", cwd), ("aleapp-tmp", temp)):
        files = child_files(directory)
        if files:
            kept[name] = files
        else:
            for dirpath, _dirs, _files in os.walk(directory, topdown=False):
                try:
                    os.rmdir(dirpath)
                except OSError:
                    pass
    rows = index(out, report)
    reports = [row for row in rows if not row[2]]
    tsvs = sum(1 for rel, _what, _copied in reports if rel.lower().endswith(".tsv"))

    # Both streams are read into one account: a release that logs to stderr (Python's logging does by default)
    # has its module lines, its count and its end line read as well as one that logs to stdout.
    events, facts = [], {}
    read_log(os.path.join(out, "aleapp.stdout"), "aleapp.stdout", events, facts)
    tracebacks, stderr_lines = read_log(os.path.join(out, "aleapp.stderr"), "aleapp.stderr", events, facts)
    modules, counts, unattributed, outside = receipt(events)
    write_modules(out, modules)
    write_index(out, rows)
    recognised = bool(modules)
    expected = facts.get("expected", facts.get("total"))
    receipt_json = {"log_format_recognised": recognised, "counts": counts, "modules_listed_in": "modules.tsv",
                    "records_reported_by_modules": sum(m["records"] for m in modules),
                    "modules_the_log_says_it_will_parse": expected,
                    "log_says_processing_completed": bool(facts.get("end")),
                    "tracebacks_on_stderr": tracebacks, "unexplained_lines_on_stderr": stderr_lines,
                    "error_lines_outside_modules": len(outside), "first_error_lines_outside_modules": outside[:FIRST_UNATTRIBUTED],
                    "unattributed_log_lines": unattributed[:FIRST_UNATTRIBUTED],
                    "report_layout": layout, **({"files_beside_the_report": "aleapp-run-files/"} if siblings else {}),
                    **({"files_left_in_program_directories": kept} if kept else {})}
    errors = [] if rc == 0 else ["ALEAPP exited %d; its output is kept whole in aleapp.stdout and aleapp.stderr" % rc]
    if timed_out:
        errors = ["ALEAPP did not finish in the %g seconds this recipe gives it: it was ended with everything it started, and what it wrote is kept whole in aleapp.stdout, aleapp.stderr and the report folder" % seconds]
    problems = []
    named = lambda status: [m["artefact"] for m in modules if m["status"] == status][:5]
    if counts["errored"]:
        problems.append("%d module(s) errored: %s%s; see modules.tsv and aleapp.stdout" % (counts["errored"], ", ".join(named("errored")), " and others" if counts["errored"] > 5 else ""))
    if counts["errors_logged"]:
        problems.append("%d module(s) completed but logged error lines: %s%s; see modules.tsv and aleapp.stdout" % (counts["errors_logged"], ", ".join(named("errors_logged")), " and others" if counts["errors_logged"] > 5 else ""))
    if counts["unknown"]:
        problems.append("%d module(s) started and the log says nothing more about them" % counts["unknown"])
    if outside:
        where = ", ".join("%s line %d" % (o["log"], o["line"]) for o in outside[:5])
        problems.append("%d log line(s) outside any module speak of an error (%s%s)" % (len(outside), where, " and others" if len(outside) > 5 else ""))
    if stderr_lines:
        problems.append("%d line(s) on stderr that nothing explains%s; see aleapp.stderr" % (stderr_lines, " (%d of them tracebacks)" % tracebacks if tracebacks else ""))
    if unattributed:
        problems.append("%d log line(s) about a module that did not start" % len(unattributed))
    if recognised and expected is None:
        problems.append("the log does not say how many modules it will parse (no 'Artifact to parse' line, no [i/N] prefix): a module that never started cannot be told from one that was not asked for")
    elif recognised and len(modules) != expected:
        problems.append("the log says %d modules would be parsed and %d started" % (expected, len(modules)))
    if recognised and not facts.get("end"):
        problems.append("the log does not end with its processing-completed line")
    if rc == 0 and tsvs and not recognised:
        problems.append("the log has no module lines this recipe reads: per-module outcome is unknown for all of them")
    gated = counts["unsupported"]
    if rc == 0 and tsvs and not problems and not timed_out:
        write_coverage(out, "complete", "ALEAPP exited 0 over the %s and its log accounts for %d module(s): %d completed, %d with no record (no source file or no data)%s; %d TSV report(s)"
                       % (kind, len(modules), counts["completed"], counts["no_record"],
                          ", %d that do not take this operating-system version (see modules.tsv)" % gated if gated else "", tsvs), errors,
                       "ALEAPP exited 0, wrote %d TSV report(s) and its log accounts for every module it started as completed, no_record or unsupported" % tsvs,
                       modules=receipt_json)
    elif reports:
        write_coverage(out, "partial", "ALEAPP wrote %d report file(s); %d module(s) in its log: %d completed, %d no_record, %d unsupported, %d errored, %d errors_logged, %d unknown"
                       % (len(reports), len(modules), counts["completed"], counts["no_record"], gated, counts["errored"], counts["errors_logged"], counts["unknown"]),
                       (errors + problems) or ["ALEAPP wrote no TSV report"],
                       basis_of("partial because ", (errors + problems) or ["ALEAPP wrote no TSV report"]), modules=receipt_json)
    else:
        write_coverage(out, "failed", "nothing parsed", (errors + problems) or ["ALEAPP wrote no report"],
                       basis_of("nothing was parsed: ", (errors + problems) or ["ALEAPP wrote no report"]), modules=receipt_json)
    return 0 if rc == 0 and not timed_out else 1


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("command", choices=("detect", "run"))
    parser.add_argument("--target", required=True)
    parser.add_argument("--out")
    # The census asks every detect step with --probe-out DIR; detect keeps nothing there.
    parser.add_argument("--probe-out")
    parser.add_argument("--max-seconds", type=float, default=LEAPP_SECONDS)
    args = parser.parse_args()
    try:
        _, path = target_of(args.target)
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        print(json.dumps({"ok": False, "status": "failed", "status_basis": "the target could not be read, so nothing was run", "error": str(exc)}))
        return 2
    applies, why, kind = detect(path)
    if args.command == "detect":
        print(json.dumps({"applies": applies, "why": why}))
        return 0 if applies else 1
    if not args.out:
        print(json.dumps({"ok": False, "status": "failed", "status_basis": "run was given no output directory, so nothing was run", "error": "run needs --out DIR"}))
        return 2
    if not applies:
        print(json.dumps({"ok": False, "status": "failed", "status_basis": "the target is not one this recipe reads, so nothing was run", "why": why}))
        return 2
    rc = run(path, kind, args.out, args.max_seconds)
    if rc == 2:
        return rc
    account = json.load(open(os.path.join(os.path.abspath(args.out), "coverage.json"), encoding="utf-8"))
    print(json.dumps({"ok": rc == 0, "status": account.get("status"), "status_basis": account.get("status_basis")}))
    return rc


if __name__ == "__main__":
    sys.exit(main())
