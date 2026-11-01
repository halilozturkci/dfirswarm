#!/usr/bin/env python3
"""Catalogue one PE, ELF or Mach-O file using this pack's static tools.

Two passes, each run as the tool the agent would run, each writing its output straight into a file of this
recipe's directory: `pe_info` (the structure it read) and `entropy_map` (the complete entropy profile). The
recipe's status is the parsers' own statement of what they read, never an exit code and never "the output
file is not empty": a parser that exits 0 with a header problem is `partial` here, and the index says so.

    complete      pe_info read every structure it reads, and the entropy pass finished
    partial       at least one pass produced a usable result and something was not read: coverage.json says
                  which structure, which parser and why (warnings, limits_hit, errors, omissions)
    unsupported   the file is not one this recipe applies to
    failed        neither pass produced a usable result

Applicability (`detect`) is judged from enough structure to tell an executable from a coincident magic prefix:
a PE needs its signature where the DOS header points; an ELF needs a class, a byte order and a whole header
(52 or 64 bytes); a thin Mach-O needs its whole header; a universal binary needs a plausible architecture table
whose first slice starts with a Mach-O magic (a Java class file begins with the same word).

The recipe reads the file; it executes nothing.
"""
import errno
import json
import os
import re
import signal
import struct
import subprocess
import sys
import time
from pathlib import Path

HERE = os.path.dirname(os.path.abspath(__file__))
PACK = os.path.abspath(os.path.join(HERE, "..", ".."))
PE_INFO = os.path.join(PACK, "tools", "pe_info", "run.py")
ENTROPY = os.path.join(PACK, "tools", "entropy_map", "run.py")

BUDGET_SECONDS = 570                      # recipe.json gives this recipe 600
PE_INFO_SECONDS = 110                     # pe_info's and entropy_map's own clocks (max_seconds) are at most this and 280
ENTROPY_SECONDS = 280
GRACE_SECONDS = 10                        # a tool that outlives its own clock by this much is ended
ENTROPY_WINDOW = 65536
ENTROPY_NAME = "entropy-windows.tsv"
EARLIER = re.compile(r"^(binary|entropy)(-\d+)?\.json$|^entropy-windows[^/]*\.tsv$|^(pe_info|entropy_map)(-\d+)?\.stderr$")
MACHO_THIN = {b"\xce\xfa\xed\xfe": 28, b"\xcf\xfa\xed\xfe": 32, b"\xfe\xed\xfa\xce": 28, b"\xfe\xed\xfa\xcf": 32}
FAT = {b"\xca\xfe\xba\xbe": (">", 20), b"\xbe\xba\xfe\xca": ("<", 20), b"\xca\xfe\xba\xbf": (">", 32), b"\xbf\xba\xfe\xca": ("<", 32)}
MAX_JSON = 256 << 20
NOT_COVERED = "execution, unpacking, decompilation, signature verification, or observed behaviour"


def target_of(arg):
    text = open(arg, encoding="utf-8").read() if os.path.isfile(arg) else arg
    target = json.loads(text)
    if not isinstance(target, dict):
        raise ValueError("the target is not a JSON object")
    paths = target.get("paths")
    if not isinstance(paths, list) or not paths or not isinstance(paths[0], str):
        raise ValueError("the target names no path")
    return target, paths[0]


def detect(path):
    """(format or None, why)."""
    try:
        size = os.path.getsize(path)
        with open(path, "rb") as fh:
            head = fh.read(64)
            magic = head[:4]
            if head[:2] == b"MZ":
                if len(head) < 0x40:
                    return None, "MZ header is too short to name a PE signature"
                pe_at = int.from_bytes(head[0x3C:0x40], "little")
                fh.seek(pe_at)
                if fh.read(4) == b"PE\x00\x00":
                    return "PE", "DOS header points to a PE signature"
                return None, "MZ header does not point to a PE signature"
            if magic == b"\x7fELF":
                if len(head) < 6 or head[4] not in (1, 2):
                    return None, "ELF signature with an EI_CLASS that is neither ELFCLASS32 nor ELFCLASS64"
                if head[5] not in (1, 2):
                    return None, "ELF signature with an EI_DATA that is neither little- nor big-endian"
                need = 64 if head[4] == 2 else 52
                if size < need:
                    return None, "ELF signature, and the file is shorter than an ELF%d header (%d bytes)" % (64 if need == 64 else 32, need)
                return "ELF", "ELF signature and a whole ELF header"
            if magic in MACHO_THIN:
                if size < MACHO_THIN[magic]:
                    return None, "Mach-O signature, and the file is shorter than its header (%d bytes)" % MACHO_THIN[magic]
                return "Mach-O", "Mach-O signature and a whole header"
            if magic in FAT:
                e, entry = FAT[magic]
                if size < 8 + entry:
                    return None, "universal-binary signature, and the file is shorter than one architecture entry"
                nfat = struct.unpack(e + "I", head[4:8])[0]
                if not 1 <= nfat <= 256:
                    return None, ("the universal-binary magic with %d slices declared is not a plausible architecture table "
                                  "(0xCAFEBABE is also the first word of a Java class file)" % nfat)
                fh.seek(8)
                row = fh.read(entry)
                if entry == 20:
                    offset, length = struct.unpack(e + "II", row[8:16])
                else:
                    offset, length = struct.unpack(e + "QQ", row[8:24])
                if offset + length > size or length < 4:
                    return None, ("the first slice of this universal-binary header lies outside the file "
                                  "(0xCAFEBABE is also the first word of a Java class file)")
                fh.seek(offset)
                if fh.read(4) not in MACHO_THIN:
                    return None, "the first slice does not begin with a Mach-O magic (0xCAFEBABE is also the first word of a Java class file)"
                return "Mach-O", "universal-binary signature, a plausible architecture table and a Mach-O first slice"
    except OSError as exc:
        return "unknown", "unreadable, so it cannot be told what it is: %s" % (exc.strerror or exc)
    return None, "no PE, ELF or Mach-O signature"


def describe(exc):
    return "%s: %s" % (type(exc).__name__, getattr(exc, "strerror", None) or str(exc))


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
    """The last word of a stop signal that comes before main() has set the recipe's own: one answer that says it was stopped and had produced
    nothing yet. main() replaces it, and installs the handlers again."""
    print(json.dumps({"error": "stopped by signal %d before the recipe had begun its work" % signum, "status": "interrupted",
                      "status_basis": "the recipe was stopped by signal %d before it had begun its work: nothing it read is an answer" % signum,
                      "ok": False, "recipe": "static-binary", "stopped_by_signal": signum}))
    sys.stdout.flush()


STATE["last_word"] = _first_word
install_signal_handlers()
# the stop handlers are installed here, at module level


def run_child(script, args, stdout_path, stderr_path, env, timeout):
    """Run a tool with its arguments on stdin and its output going straight to files, in THIS recipe's process group.
    Returns (returncode or None, timed_out). A deadline ends the tool and what it started."""
    with open(stdout_path, "wb") as out, open(stderr_path, "wb") as err:
        proc = spawn([sys.executable, script], stdin=subprocess.PIPE, stdout=out, stderr=err, env=env)
        ACTIVE.append(proc)
        try:
            try:
                proc.stdin.write(json.dumps(args).encode("utf-8"))
                proc.stdin.close()
            except OSError:
                pass
            try:
                return proc.wait(timeout=max(0.1, timeout)), False
            except subprocess.TimeoutExpired:
                kill_tree(proc)
                proc.wait()
                return None, True
        finally:
            ACTIVE.remove(proc)


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


def make_out_dir(out_dir):
    """Create the recipe's output directory and return None, or say why it was not: a symbolic link anywhere on the way inside the run
    directory (own_dir) or as the directory itself when it is elsewhere. Nothing is written through a link."""
    absolute = os.path.abspath(out_dir)
    cwd = os.getcwd()
    if absolute == cwd or absolute.startswith(cwd + os.sep):
        return own_dir(Path(os.path.relpath(absolute, cwd)))
    if os.path.islink(absolute):
        return "%s is a symbolic link: refused, nothing written through it" % absolute
    os.makedirs(absolute, exist_ok=True)
    return None


def new_name(out_dir, stem, ext):
    """A name in `out_dir` that nothing has: `stem.ext`, or `stem-2.ext`, ... The file is created at once, exclusively, so that a
    result an earlier run left in this directory is never opened for writing, let alone replaced."""
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
    for n in range(1, 1000):
        name = "%s%s" % (stem if n == 1 else "%s-%d" % (stem, n), ext)
        try:
            os.close(os.open(os.path.join(out_dir, name), flags, 0o644))
        except FileExistsError:
            continue
        return name
    raise OSError(errno.EEXIST, "a thousand files of this name already exist in %s" % out_dir)


def read_json(path):
    try:
        if os.path.getsize(path) > MAX_JSON:
            return None, "the output is larger than %d bytes" % MAX_JSON
        with open(path, encoding="utf-8") as fh:
            value = json.load(fh)
    except (OSError, ValueError, RecursionError) as exc:
        return None, "not JSON (%s)" % exc
    return (value, None) if isinstance(value, dict) else (None, "not a JSON object")


def drop_if_empty(path):
    try:
        if os.path.isfile(path) and os.path.getsize(path) == 0:
            os.unlink(path)
            return True
    except OSError:
        pass
    return False


def judge(label, rc, timed_out, doc, why):
    """The parser's own status: (status, reason). A missing or unreadable answer is `failed`."""
    if timed_out:
        return "failed", "%s was stopped at its time limit" % label
    if doc is None:
        return "failed", "%s returned no readable answer: %s (exit %s)" % (label, why, rc)
    status = doc.get("status")
    if status not in ("complete", "partial", "failed", "unsupported"):
        return "failed", "%s's answer carries no status, so what it read cannot be judged (exit %s)" % (label, rc)
    return status, doc.get("status_basis") or doc.get("error") or ""


def pass_state(label):
    return {"label": label, "status": "failed", "reason": "%s has not run" % label, "rc": None, "doc": None}


def assemble(state):
    """The recipe's result from what the passes have said so far: (status, coverage, index lines). A pass that has not
    run counts as failed with that reason, so a recipe that is stopped says exactly this."""
    out_dir, fmt, path = state["out_dir"], state["fmt"], state["path"]
    pe, en = state["pe"], state["en"]
    errors, warnings, limits, omissions = list(state["errors"]), [], [], []
    files = {}
    for st in (pe, en):
        if st["status"] != "complete":
            errors.append("%s status %s: %s" % (st["label"], st["status"], st["reason"]))
    pe_doc, en_doc = pe["doc"], en["doc"]
    if pe_doc:
        warnings += [str(p) for p in (pe_doc.get("problems") or [])]
        limits += [str(x) for x in (pe_doc.get("limits_hit") or [])]
        omissions += [str(x) for x in ((pe_doc.get("coverage") or {}).get("structures_not_read") or [])]
        if pe_doc.get("problems_not_listed"):
            warnings.append("%d further problem(s) were counted and not listed by pe_info" % pe_doc["problems_not_listed"])
        for name, table in (pe_doc.get("tables") or {}).items():
            where = table.get("all_results") if isinstance(table, dict) else None
            if where:
                files[os.path.relpath(where, out_dir) if not where.startswith("store/") else where] = (
                    "the whole %s table, one JSON row per line (the answer holds the first %s)" % (name, table.get("returned")))
    if en["status"] != "complete":
        limits.append("entropy: the pass over the whole file did not finish" if en.get("timed_out") else "entropy: %s" % en["reason"])
    profile = (en_doc or {}).get("profile_file")
    runs = (en_doc or {}).get("runs_file")

    usable = [st["status"] for st in (pe, en) if st["status"] in ("complete", "partial")]
    if pe["status"] == "complete" and en["status"] == "complete" and not state["errors"]:
        status = "complete"
    elif usable:
        status = "partial"
    elif pe["status"] == "unsupported":
        status = "unsupported"
    else:
        status = "failed"

    coverage = {
        "recipe": "static-binary",
        "target": path,
        "format": fmt,
        "status": status,
        "covered": ("the structures pe_info read (see pe_info.status and omissions) and the whole-file entropy profile "
                    "(entropy_map.status): %s" % ("both read in full" if status == "complete" else "not all of it was read: see errors, warnings and limits_hit")),
        "not_covered": NOT_COVERED,
        "pe_info": {"status": pe["status"], "status_basis": pe["reason"], "exit_code": pe["rc"], "problems": len((pe_doc or {}).get("problems") or [])},
        "entropy_map": {"status": en["status"], "status_basis": en["reason"], "exit_code": en["rc"], "windows_measured": (en_doc or {}).get("windows_measured"),
                        "bytes_processed": (en_doc or {}).get("bytes_processed")},
        "limits_hit": limits,
        "warnings": warnings,
        "omissions": omissions,
        "errors": errors,
    }
    lines = []
    names = state["names"]
    binary, entropy_path = os.path.join(out_dir, names.get("binary", "binary.json")), os.path.join(out_dir, names.get("entropy", "entropy.json"))
    if os.path.isfile(binary) and os.path.getsize(binary):
        lines.append("%s\tpe_info/2 inventory for %s: status %s, %d problem(s); the structures it read are listed in the file, and what it did not read in coverage.json"
                     % (names["binary"], fmt, pe["status"], len((pe_doc or {}).get("problems") or [])))
    if os.path.isfile(entropy_path) and os.path.getsize(entropy_path):
        lines.append("%s\tentropy_map inline summary in %d-byte windows: status %s; the profile is the file named next" % (names["entropy"], ENTROPY_WINDOW, en["status"]))
    if profile and os.path.isfile(os.path.join(out_dir, profile)):
        lines.append("%s\t%s entropy profile, %s windows of %d bytes, one row per window" % (
            profile, "complete" if en["status"] == "complete" else "partial (%s)" % en["status"], (en_doc or {}).get("windows_measured"), ENTROPY_WINDOW))
    if runs and os.path.isfile(os.path.join(out_dir, runs)):
        lines.append("%s\tevery high-entropy run, in the order found" % runs)
    for key in ("pe_stderr", "en_stderr"):
        name = names.get(key)
        if name and os.path.isfile(os.path.join(out_dir, name)) and os.path.getsize(os.path.join(out_dir, name)):
            files[name] = "what %s said on stderr" % ("pe_info" if key == "pe_stderr" else "entropy_map")
    for name, what in files.items():
        if not name.startswith("store/") and os.path.isfile(os.path.join(out_dir, name)):
            lines.append("%s\t%s" % (name, what))
    # What an earlier run left in this directory is kept, and named, so that no result is orphaned by this one.
    listed = {l.split("\t", 1)[0] for l in lines}
    try:
        present = sorted(os.listdir(out_dir))
    except OSError:
        present = []
    for name in present:
        if name in listed or not EARLIER.match(name) or not os.path.isfile(os.path.join(out_dir, name)) or os.path.getsize(os.path.join(out_dir, name)) == 0:
            continue
        lines.append("%s\tleft by an earlier run in this directory; kept, and not part of this result" % name)
    coverage["outputs"] = {k: v for k, v in names.items()}
    return status, coverage, lines


def write_results(state):
    status, coverage, lines = assemble(state)
    out_dir = state["out_dir"]
    for name in ("coverage.json", "index.tsv"):
        tmp = os.path.join(out_dir, name + ".new")
        with open(tmp, "w", encoding="utf-8") as fh:
            if name == "coverage.json":
                json.dump(coverage, fh, indent=2)
                fh.write("\n")
            else:
                fh.write("".join(l + "\n" for l in lines))
        os.replace(tmp, os.path.join(out_dir, name))
    return status


def run(path, out_dir, fmt, budget):
    refused = make_out_dir(out_dir)
    if refused:
        raise OSError(errno.EPERM, refused)
    started = time.monotonic()
    env = dict(os.environ)
    # The tools write where $OUT says; a recipe's files belong in its own directory, whatever job called it.
    env["OUT"] = os.path.abspath(out_dir)
    env.pop("JOB_ID", None)
    state = {"out_dir": out_dir, "fmt": fmt, "path": path, "errors": [], "pe": pass_state("pe_info"), "en": pass_state("entropy_map"), "names": {}}
    names = state["names"]
    names["binary"] = new_name(out_dir, "binary", ".json")
    names["entropy"] = new_name(out_dir, "entropy", ".json")
    names["pe_stderr"] = new_name(out_dir, "pe_info", ".stderr")
    names["en_stderr"] = new_name(out_dir, "entropy_map", ".stderr")

    def last_word(signum):
        # Stopped by a signal: the running passes are ended (the handler did that); coverage and the index say where it stopped.
        state["errors"].append("the recipe was stopped by signal %d; the passes that were running were ended" % signum)
        try:
            write_results(state)
        except OSError:
            pass
        print(json.dumps({"ok": False, "status": "interrupted", "status_basis": "the recipe was stopped by signal %d; the passes that were running were ended" % signum,
                          "format": fmt, "coverage": "coverage.json", "index": "index.tsv"}))
        sys.stdout.flush()

    STATE["last_word"] = last_word
    install_signal_handlers()

    def unfinished():
        # A coverage.json that says the recipe has not finished is there from the first moment and after each pass: a recipe
        # ended without a last word (SIGKILL) still leaves one.
        state["errors"].append("the recipe was started and has not finished")
        write_results(state)
        state["errors"].pop()

    unfinished()

    left = budget - (time.monotonic() - started)
    seconds = max(1, min(PE_INFO_SECONDS, int(left)))
    rc, timed_out = run_child(PE_INFO, {"path": path, "max_seconds": seconds}, os.path.join(out_dir, names["binary"]),
                              os.path.join(out_dir, names["pe_stderr"]), env, seconds + GRACE_SECONDS)
    doc, why = read_json(os.path.join(out_dir, names["binary"]))
    status, reason = judge("pe_info", rc, timed_out, doc, why)
    state["pe"] = {"label": "pe_info", "status": status, "reason": reason, "rc": rc, "doc": doc, "timed_out": timed_out}
    unfinished()

    left = budget - (time.monotonic() - started)
    entropy_path = os.path.join(out_dir, names["entropy"])
    if left < 1:
        rc2, timed_out2 = None, True
    else:
        seconds = max(1, min(ENTROPY_SECONDS, int(left)))
        rc2, timed_out2 = run_child(ENTROPY, {"path": path, "window": ENTROPY_WINDOW, "output_name": ENTROPY_NAME, "max_seconds": seconds}, entropy_path,
                                    os.path.join(out_dir, names["en_stderr"]), env, seconds + GRACE_SECONDS)
    doc2, why2 = read_json(entropy_path)
    status2, reason2 = judge("entropy_map", rc2, timed_out2, doc2, why2)
    state["en"] = {"label": "entropy_map", "status": status2, "reason": reason2, "rc": rc2, "doc": doc2, "timed_out": timed_out2}
    # An empty stderr is not a result: it is not left, and not named.
    for key in ("pe_stderr", "en_stderr"):
        if drop_if_empty(os.path.join(out_dir, names[key])):
            names.pop(key)
    final = write_results(state)
    print(json.dumps({"ok": final == "complete", "status": final, "format": fmt}))
    return 0 if final in ("complete", "partial") else 2


def refuse(message):
    """An answer for a call the recipe did not start."""
    print(json.dumps({"ok": False, "status": "failed", "status_basis": message, "error": message}))
    return 2


def main(argv):
    if len(argv) < 2 or argv[1] not in ("detect", "run"):
        return refuse("usage: run.py detect --target T | run --target T --out DIR [--seconds N]")
    args = dict(zip(argv[2::2], argv[3::2]))
    if "--target" not in args:
        return refuse("--target is required")
    try:
        _target, path = target_of(args["--target"])
    except (OSError, ValueError, RecursionError) as exc:
        return refuse(str(exc) if not isinstance(exc, RecursionError) else "the target is nested too deeply")
    if not os.path.isfile(path):
        return refuse("the target is not a readable file")
    fmt, why = detect(path)
    if argv[1] == "detect":
        if fmt == "unknown":
            print(json.dumps({"applies": "unknown", "format": None, "why": why}))
            return 2
        print(json.dumps({"applies": fmt is not None, "format": fmt, "why": why}))
        return 0 if fmt else 1
    if "--out" not in args:
        return refuse("run needs --out DIR")
    if fmt is None or fmt == "unknown":
        refused = make_out_dir(args["--out"])
        if refused:
            return refuse("the output directory cannot be written: %s" % refused)
        with open(os.path.join(args["--out"], "coverage.json"), "w", encoding="utf-8") as fh:
            json.dump({"recipe": "static-binary", "status": "unsupported", "why": why, "limits_hit": [], "errors": []}, fh, indent=2)
        print(json.dumps({"ok": False, "status": "unsupported", "why": why}))
        return 2
    budget = BUDGET_SECONDS
    if "--seconds" in args:
        try:
            budget = int(args["--seconds"])
        except ValueError:
            budget = 0
        if not 1 <= budget <= BUDGET_SECONDS:
            print(json.dumps({"ok": False, "error": "--seconds is a whole number from 1 to %d" % BUDGET_SECONDS}))
            return 2
    try:
        return run(path, args["--out"], fmt, budget)
    except OSError as exc:
        # an --out that cannot be made or written (a symbolic link on the way, a hand run): said as JSON, never a traceback
        return refuse("the output directory cannot be written: %s" % (getattr(exc, "strerror", None) or exc))


if __name__ == "__main__":
    sys.exit(main(sys.argv))
