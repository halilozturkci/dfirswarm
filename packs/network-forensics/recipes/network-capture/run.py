#!/usr/bin/env python3
"""Catalogue a capture: capinfos metadata and complete listings of selected tshark fields.

    run.py detect --target T          exit 0 when the file has a pcap or pcapng signature, 1 when it does not
    run.py run --target T --out DIR

What the catalogue is: a complete listing of the SELECTED FIELDS of every packet (packets.tsv) and of the DNS,
HTTP and TLS packets (dns.tsv, http.tsv, tls.tsv), and of HTTP/2 and QUIC packets (http2.tsv, quic.tsv) when the
installed tshark lists the fields they need. It is a projection the installed tshark made, not the capture: the
capture stays the authority at the byte level, and every listing is one tshark's reading. A table with no rows
does not show that the protocol is absent: packets may be truncated, encrypted, malformed or of a protocol the
build does not decode (coverage.json counts the truncated ones).

The receipt, coverage.json, exists from the first moment and is rewritten after every step, so a run that is cut off
(the outer time limit, a signal, a kill) leaves what was done: status "partial" with finished false until the last
step, then "complete" (every step ran and exited 0 and no listing lacks a field), "partial" (a step failed, timed out or was
not attempted, or a listing was made without a field the installed tshark does not list: the status_basis names it) or
"failed". "complete" is an execution result. It does not say what the capture holds. Every step records its
status, exit code, seconds and rows; the versions of tshark and capinfos are recorded; one deadline
(NETWORK_CAPTURE_SECONDS, default 3300, under the recipe's 3600) covers every step, a step that uses it up is killed
with everything it started and the steps after it are not_attempted.

http2.tsv and quic.tsv are listed only after `tshark -G fields` shows that the installed build has the fields; the
ones it does not have are named in the step (fields_missing) and left out. Nothing is assumed about what a version
supports.

SENSITIVE: http.tsv holds request URIs, hosts and user agents, dns.tsv query and answer names, tls.tsv server names and
certificate strings, http2.tsv the :authority and :path of requests; all of it can carry credentials, tokens and
identifiers. The receipt marks each table (secret_bearing). Every file the recipe writes is private (the directory 0700,
files 0600, and what tshark writes too), but the mark is informational: nothing in the harness reads it, so run the
recipe's job as a sensitive output when the capture can hold any.

Every field a listing asks for is checked against `tshark -G fields` first: a field the installed build does not list is
named in the step (fields_missing) and left out of that listing, so one missing field never makes a whole listing fail.
If the list of fields cannot be read, the fields are asked for unchecked and the step says so.
"""
import json
import os
import signal
import sys


def _before_start(signum, _frame):
    """A stop that arrives while the rest of this file is still loading (the other imports, the compile of what follows): the first signal
    counts, nothing was read, started or written, and the one answer says so. main() installs the tool's own handlers and replaces this one.
    What no script can answer is a stop that arrives before the interpreter has run these first lines (its own start-up)."""
    for other in (signal.SIGTERM, signal.SIGINT, signal.SIGHUP):
        signal.signal(other, signal.SIG_IGN)
    try:
        sys.stdout.write(json.dumps({"recipe": "network-capture", "status": "partial", "ok": False, "stage": "starting",
                                     "status_basis": "stopped by signal %d before any work: nothing was read, started or written" % signum,
                                     "interrupted_by_signal": signum}) + "\n")
        sys.stdout.flush()
    except (OSError, ValueError):
        pass
    os._exit(128 + signum)


for _signum in (signal.SIGTERM, signal.SIGINT, signal.SIGHUP):
    signal.signal(_signum, _before_start)   # replaced by main() once the module is loaded


import errno
import stat
import shutil
import select
import subprocess
import time

MAGICS = {b"\xd4\xc3\xb2\xa1", b"\xa1\xb2\xc3\xd4", b"\x4d\x3c\xb2\xa1",
          b"\xa1\xb2\x3c\x4d", b"\x0a\x0d\x0d\x0a"}
RECIPE_SECONDS = 3600.0        # the recipe's limit
COUNT_MARGIN = 30.0            # counting the rows of a finished listing ends this long before it
DEADLINE = min(float(os.environ.get("NETWORK_CAPTURE_SECONDS", "3300")), 3500.0)   # under the recipe's 3600-second limit, so that it stops its own steps
RECIPE = "network-capture"

# name, display filter, fields, the fields whose existence `tshark -G fields` must show before the listing is made
LISTINGS = [
    ("packets.tsv", None, ["frame.number", "frame.time_epoch", "frame.cap_len", "frame.len", "_ws.col.Protocol", "ip.src", "ipv6.src", "tcp.srcport", "udp.srcport", "ip.dst", "ipv6.dst", "tcp.dstport", "udp.dstport"], []),
    ("dns.tsv", "dns", ["frame.number", "frame.time_epoch", "ip.src", "ipv6.src", "ip.dst", "ipv6.dst", "dns.id", "dns.flags.response", "dns.qry.name", "dns.qry.type", "dns.a", "dns.aaaa", "dns.resp.name", "dns.flags.rcode"], []),
    ("http.tsv", "http", ["frame.number", "frame.time_epoch", "ip.src", "ipv6.src", "ip.dst", "ipv6.dst", "tcp.stream", "http.request.method", "http.host", "http.request.uri", "http.response.code", "http.content_length", "http.user_agent"], []),
    ("tls.tsv", "tls", ["frame.number", "frame.time_epoch", "ip.src", "ipv6.src", "ip.dst", "ipv6.dst", "tcp.stream", "tls.handshake.type", "tls.handshake.extensions_server_name", "tls.handshake.ja3", "x509sat.uTF8String"], []),
    ("http2.tsv", "http2", ["frame.number", "frame.time_epoch", "ip.src", "ipv6.src", "ip.dst", "ipv6.dst", "tcp.stream", "http2.streamid", "http2.type", "http2.headers.method", "http2.headers.authority", "http2.headers.path", "http2.headers.status"],
     ["http2.streamid", "http2.type", "http2.headers.method", "http2.headers.authority", "http2.headers.path", "http2.headers.status"]),
    ("quic.tsv", "quic", ["frame.number", "frame.time_epoch", "ip.src", "ipv6.src", "udp.srcport", "ip.dst", "ipv6.dst", "udp.dstport", "quic.connection.number", "quic.version", "quic.long.packet_type", "quic.dcid", "quic.scid"],
     ["quic.connection.number", "quic.version", "quic.long.packet_type", "quic.dcid", "quic.scid"]),
]
SECRET_BEARING = {
    "http.tsv": "request URIs, hosts and user agents can carry credentials, tokens and session identifiers",
    "dns.tsv": "query and answer names can carry tokens, identifiers and exfiltrated data in a label",
    "tls.tsv": "server names and certificate strings can carry identifiers and tokens",
    "http2.tsv": "the :authority and :path of a request can carry credentials, tokens and session identifiers",
}
# A conditional listing is made only if at least one of these exists in the installed build.
NEEDS_ONE_OF = {"http2.tsv": ["http2.streamid", "http2.type"], "quic.tsv": ["quic.version", "quic.long.packet_type", "quic.dcid", "quic.connection.number"]}


def target_of(arg):
    if os.path.isfile(arg):
        with open_regular(arg) as fh:
            text = fh.read().decode("utf-8")
    else:
        text = arg
    target = json.loads(text)
    paths = target.get("paths") if isinstance(target, dict) else None
    if not isinstance(paths, list) or not paths or not isinstance(paths[0], str):
        raise ValueError("the target names no path")
    return target, paths[0]


def detect(path):
    try:
        with open_regular(path) as fh:
            magic = fh.read(4)
    except OSError as exc:
        return "unknown", "unreadable, so it cannot be told whether it is a capture: %s" % (exc.strerror or exc)
    if magic in MAGICS:
        return True, "pcap or pcapng file signature"
    return False, "no pcap or pcapng file signature"


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


class Receipt:
    """coverage.json and index.tsv, rewritten whole (under a temporary name, then moved into place) after every step."""

    def __init__(self, out_dir, target, path):
        self.out_dir = out_dir
        self.data = {"recipe": RECIPE, "target": target.get("name") or path, "status": "partial", "finished": False,
                     "covered": "capture metadata and complete listings of the selected fields of every packet and of the DNS, HTTP and TLS packets "
                                "(and of HTTP/2 and QUIC packets when the installed tshark lists their fields)",
                     "not_covered": "payload content, encrypted payloads, protocols or fields the installed tshark does not decode, and packets absent from the source; "
                                    "a listing with no rows does not show a protocol is absent",
                     "status_basis": "the recipe has not finished", "errors": [], "files": [], "steps": [], "tools": {}, "deadline_seconds": DEADLINE,
                     "secret_bearing": {}, "limits_on_what_the_listings_show": {}}

    def write(self):
        for name, content in (("coverage.json", json.dumps(self.data, indent=2) + "\n"), ("index.tsv", self._index())):
            final = os.path.join(self.out_dir, name)
            tmp = final + ".tmp"
            with open(os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600), "w", encoding="utf-8", newline="\n") as fh:
                fh.write(content)
                fh.flush()
                os.fsync(fh.fileno())
            os.replace(tmp, final)

    def _index(self):
        lines = ["path\tdescription\trows"]
        for item in self.data["files"]:
            lines.append("%s\t%s\t%s" % (item["path"], item["description"], item["rows"] if item.get("rows") is not None else ""))
        return "\n".join(lines) + "\n"


def count_rows(path, deadline=None):
    """The lines of a listing less its header line; (count, True), or (the lines counted so far, False) when `deadline` ran out first.
    Counted in blocks of a MiB, with the clock looked at after each."""
    lines = 0
    last = b"\n"
    with open(path, "rb") as fh:
        while True:
            if deadline is not None and time.monotonic() > deadline:
                return max(0, lines - 1), False
            block = fh.read(1 << 20)
            if not block:
                break
            lines += block.count(b"\n")
            last = block[-1:]
    if last != b"\n":
        lines += 1
    return max(0, lines - 1), True


def truncated_packets(path, deadline=None):
    """How many packets were captured shorter than they were on the wire, from packets.tsv's cap_len and len columns;
    (count or None when the columns are absent, rows whose lengths could not be read, whether the whole file was read).
    The clock is looked at every 4,096 rows: when `deadline` has run out the count is None, not the number so far."""
    cut = unreadable = seen = 0
    with open(path, "r", encoding="utf-8", errors="replace") as fh:
        header = [c.strip('"') for c in fh.readline().rstrip("\n").split("\t")]
        try:
            i, j = header.index("frame.cap_len"), header.index("frame.len")
        except ValueError:
            return None, 0, True
        for line in fh:
            seen += 1
            if deadline is not None and seen & 4095 == 0 and time.monotonic() > deadline:
                return None, 0, False
            cells = [c.strip('"') for c in line.rstrip("\n").split("\t")]
            try:
                if int(cells[i]) < int(cells[j]):
                    cut += 1
            except (ValueError, IndexError):
                unreadable += 1
    return cut, unreadable, True


def describe(exc):
    return "%s: %s" % (type(exc).__name__, getattr(exc, "strerror", None) or exc)


def open_regular(path, follow=True):
    """A file opened for reading that is never waited on: the open does not block (a name that became a pipe since it was checked would otherwise wait
    for a writer), the type is read from the descriptor, and anything but a regular file is refused. follow=False also refuses a symbolic link (for a
    name the capture or the engine produced). The file object it returns reads in the ordinary, blocking way."""
    flags = os.O_RDONLY | os.O_NONBLOCK | getattr(os, "O_CLOEXEC", 0) | (0 if follow else getattr(os, "O_NOFOLLOW", 0))
    fd = os.open(path, flags)
    try:
        if not stat.S_ISREG(os.fstat(fd).st_mode):
            raise OSError(errno.EINVAL, "not a regular file")
        os.set_blocking(fd, True)
        return os.fdopen(fd, "rb")
    except BaseException:
        os.close(fd)
        raise


def first_line(argv, seconds=30):
    """The first line a program prints, and why it could not be had; (line or None, reason or None)."""
    code, out, err, timed_out = preflight(argv, seconds)
    if timed_out:
        return None, "did not finish in %d seconds" % seconds
    text = (out or err).decode("utf-8", "replace").strip().splitlines()
    if code != 0:
        return None, "exited %s" % code if code is not None else (err.decode("utf-8", "replace").strip() or "could not be run")
    return (text[0].strip() if text else None), None


def field_names(tshark, wanted, seconds):
    """Which of `wanted` the installed tshark lists as fields (`tshark -G fields`, read as a stream, with select so that
    the deadline needs no second thread); (the names found, why the list could not be read or None)."""
    found = set()
    lowered = {w.lower(): w for w in wanted if w.startswith("_ws.col.")}
    try:
        proc = spawn([tshark, "-G", "fields"], stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
    except OSError as exc:
        return found, "tshark -G fields could not be run (%s)" % (exc.strerror or exc)
    ACTIVE.append(proc)
    stop_at = time.monotonic() + max(1.0, seconds)
    killed, buffer = False, b""
    try:
        fd = proc.stdout.fileno()
        while True:
            left = stop_at - time.monotonic()
            if left <= 0:
                killed = True
                kill_tree(proc)
                break
            ready, _, _ = select.select([fd], [], [], min(1.0, left))
            if not ready:
                continue
            chunk = os.read(fd, 1 << 20)
            if not chunk:
                break
            buffer += chunk
            *lines, buffer = buffer.split(b"\n")
            for raw in lines:
                cells = raw.decode("utf-8", "replace").split("\t")
                if len(cells) > 2 and cells[0] == "F":
                    # column pseudo-fields are listed in lower case (_ws.col.protocol) and accepted in either
                    name = cells[2]
                    if name in wanted:
                        found.add(name)
                    elif name.startswith("_ws.col.") and name in lowered:
                        found.add(lowered[name])
    finally:
        try:
            proc.stdout.close()
        except OSError:
            pass
        code = proc.wait()
        ACTIVE.remove(proc)
    if killed:
        return found, "tshark -G fields did not finish in time"
    if code != 0:
        return found, "tshark -G fields exited %d" % code
    return found, None


PROGRESS = {"stage": "checking its arguments"}


def early_word(signum):
    """What a recipe stopped before its receipt's last word exists says on stdout: partial, the stage it was in, and that no listing had been started.
    The last word that writes the receipt takes over once the receipt is ready."""
    print(json.dumps({"ok": False, "status": "partial",
                      "status_basis": "the recipe was stopped by signal %d while it was %s; no program had been started and no listing written%s" %
                                      (signum, PROGRESS["stage"], ", and the output directory may hold the receipt it had begun to write" if PROGRESS["stage"] != "checking its arguments" else ""),
                      "interrupted_by_signal": signum, "stage": PROGRESS["stage"]}), flush=True)


def main():
    STATE["last_word"] = early_word
    install_signal_handlers()
    if len(sys.argv) < 4 or sys.argv[2] != "--target":
        print(json.dumps({"ok": False, "error": "usage: run.py detect --target T | run --target T --out DIR"}))
        return 2
    mode, target_arg = sys.argv[1], sys.argv[3]
    try:
        target, path = target_of(target_arg)
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        print(json.dumps({"ok": False, "error": str(exc)}))
        return 2
    applies, why = detect(path)
    if mode == "detect":
        print(json.dumps({"applies": applies, "why": why}))
        return 2 if applies == "unknown" else 0 if applies else 1
    if mode != "run" or "--out" not in sys.argv[4:] or sys.argv.index("--out") + 1 >= len(sys.argv):
        print(json.dumps({"ok": False, "error": "run needs --out DIR"}))
        return 2
    out_dir = sys.argv[sys.argv.index("--out") + 1]
    PROGRESS["stage"] = "preparing the output directory"
    os.umask(0o077)       # the directory 0700, every file 0600, tshark's and capinfos's own output too
    try:
        os.makedirs(out_dir, mode=0o700, exist_ok=True)
        os.chmod(out_dir, 0o700)
    except OSError as exc:
        print(json.dumps({"ok": False, "error": "the output directory could not be created (%s)" % describe(exc), "out": out_dir}))
        return 2
    receipt = Receipt(out_dir, target, path)
    data = receipt.data
    if applies is not True:
        data.update(status="unsupported", status_basis="the file has no pcap or pcapng signature, so nothing was listed", finished=True, why=why)
        receipt.write()
        return 2
    tshark, capinfos = shutil.which("tshark"), shutil.which("capinfos")
    if not tshark or not capinfos:
        data.update(status="failed", status_basis="a program the recipe needs is not on PATH", finished=True,
                    errors=["missing program(s): " + ", ".join(name for name, value in (("tshark", tshark), ("capinfos", capinfos)) if not value)])
        receipt.write()
        return 2
    started = time.monotonic()
    deadline = started + DEADLINE
    uncounted = []

    def count_deadline():
        """The end of the counting of a finished listing: RECIPE_SECONDS less COUNT_MARGIN from the start, so the answer still prints inside the recipe's limit.
        NETWORK_CAPTURE_COUNT_SECONDS (seconds from the call) exists for the tests."""
        try:
            return time.monotonic() + float(os.environ["NETWORK_CAPTURE_COUNT_SECONDS"])
        except (KeyError, ValueError):
            return started + RECIPE_SECONDS - COUNT_MARGIN
    data["steps"] = ([{"step": "capinfos", "status": "not_attempted", "reason": "planned"}, {"step": "tshark -G fields", "status": "not_attempted", "reason": "planned"}]
                     + [{"step": name, "status": "not_attempted", "reason": "planned"} for name, *_ in LISTINGS])
    receipt.write()

    def step(name):
        return next(s for s in data["steps"] if s["step"] == name)

    def last_word(signum):
        # the running step is killed first (by the handler of the process block), then the receipt says what was done
        for step_entry in data["steps"]:
            if step_entry["status"] == "running":
                step_entry.update(status="interrupted", reason="the recipe was stopped by signal %d while this step ran; its file is partial" % signum)
        data["errors"].append("the recipe was stopped by signal %d before it finished" % signum)
        data["status_basis"] = "the recipe was stopped by signal %d: the listings written so far are whole files, the one running is partial" % signum
        receipt.write()
        print(json.dumps({"ok": False, "status": "partial", "status_basis": data["status_basis"], "interrupted_by_signal": signum}), flush=True)

    STATE["last_word"] = last_word
    for tool_name, binary in (("tshark", tshark), ("capinfos", capinfos)):
        line, why_not = first_line([binary, "--version"], min(30, max(1, deadline - time.monotonic())))
        data["tools"][tool_name] = {"path": binary, "version": line, **({"version_error": why_not} if why_not else {})}
    receipt.write()

    def execute(name, argv, output):
        """One step: its own process group, its output in a file, killed when the shared deadline ends.
        Returns False when the step could not start because the deadline was already used up."""
        entry = step(name)
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            entry.update(status="not_attempted", reason="the shared deadline was used up by an earlier step")
            data["errors"].append("%s was not attempted: the shared deadline was used up" % name)
            return False
        stderr = output + ".stderr"
        began = time.monotonic()
        entry.pop("reason", None)
        entry.update(status="running", command=[os.path.basename(argv[0])] + argv[1:])
        receipt.write()
        code, timed_out = run_to_files(argv, output, stderr, remaining)
        if os.path.getsize(stderr) == 0:
            os.remove(stderr)
        else:
            data["files"].append({"path": os.path.basename(stderr), "description": "complete stderr for " + name})
        entry.update(exit_code=code, seconds=round(time.monotonic() - began, 3))
        if timed_out:
            entry.update(status="timed_out", reason="killed with everything it started when the shared deadline ended; its file is partial")
            data["errors"].append("%s timed out at the shared deadline" % name)
        elif code != 0:
            entry["status"] = "failed"
            data["errors"].append("%s (%s) exited %d" % (name, os.path.basename(argv[0]), code))
        else:
            entry["status"] = "ok"
        return True

    execute("capinfos", [capinfos, "-M", "-c", "-a", "-e", "-u", "-s", "-x", path], os.path.join(out_dir, "capture.txt"))
    data["files"].append({"path": "capture.txt", "description": "capinfos capture metadata"})
    receipt.write()

    needed = {f for _, _, fields, _ in LISTINGS for f in fields}
    entry = step("tshark -G fields")
    entry.pop("reason", None)
    entry.update(status="running", command=[os.path.basename(tshark), "-G", "fields"])
    receipt.write()                       # a kill during this step leaves it running, not planned
    available, field_problem = field_names(tshark, needed, min(300.0, max(1.0, deadline - time.monotonic())))
    entry.update(status="ok" if field_problem is None else "failed", fields_checked=sorted(needed), fields_found=sorted(available))
    if field_problem:
        entry["reason"] = field_problem
        data["errors"].append(field_problem)
    receipt.write()

    base = [tshark, "-n", "-r", path, "-T", "fields", "-E", "header=y", "-E", "separator=/t", "-E", "quote=d", "-E", "occurrence=a"]
    rows = {}
    for name, display_filter, fields, check in LISTINGS:
        entry = step(name)
        if check:
            missing = [f for f in check if f not in available]
            if field_problem or not any(f in available for f in NEEDS_ONE_OF[name]):
                entry.update(status="skipped", fields_missing=missing,
                             reason=("the installed tshark's fields could not be checked, so %s was not listed" % name) if field_problem else
                             "the installed tshark does not list the fields this needs (%s): no listing was made, which says nothing about whether the capture holds the protocol" % ", ".join(missing))
                receipt.write()
                continue
        if not field_problem:
            # Every field is checked, not only the conditional listings': a field the build lacks is named and left out, never a failed listing.
            missing = [f for f in fields if f not in available]
            fields = [f for f in fields if f not in missing]
            if missing:
                entry["fields_missing"] = missing
                if not fields:
                    entry.update(status="skipped", reason="the installed tshark lists none of the fields this needs: no listing was made")
                    receipt.write()
                    continue
        elif check:
            entry["fields_missing"] = []
        argv = list(base)
        if display_filter:
            argv += ["-Y", display_filter]
        for field in fields:
            argv += ["-e", field]
        output = os.path.join(out_dir, name)
        entry["fields"] = fields
        if name in SECRET_BEARING:
            entry["secret_bearing"] = True
            data["secret_bearing"][name] = SECRET_BEARING[name]
        if not execute(name, argv, output):
            try:
                os.remove(output)
            except OSError:
                pass
            receipt.write()
            continue
        complete = entry["status"] == "ok"
        listed = {"path": name, "description": "complete %s listing of the selected fields%s" % (name[:-4], "" if complete else " (PARTIAL: the step did not finish)")}
        counted, counted_all = count_rows(output, count_deadline())
        # A count the recipe's own clock cut short is not a count: the listing is whole on disk, its row count is null and the status says so.
        listed["rows"] = rows[name] = entry["rows"] = counted if counted_all else None
        if not counted_all:
            uncounted.append(name)
        data["files"].append(listed)
        if name == "packets.tsv" and complete:
            cut, unreadable, read_all = truncated_packets(output, count_deadline())
            if not read_all:
                uncounted.append("%s (truncated packets)" % name)
            data["limits_on_what_the_listings_show"] = {
                "packets": rows[name], "truncated_packets": cut, "packets_whose_lengths_could_not_be_read": unreadable,
                "meaning": "a truncated packet was captured shorter than it was on the wire: the fields past the captured bytes are not in any listing"}
        receipt.write()
    data["limits_on_what_the_listings_show"]["rows_by_listing"] = rows
    unfinished = [s["step"] for s in data["steps"] if s["status"] in ("not_attempted", "running", "failed", "timed_out")]
    # A listing made without a field the installed tshark lacks is a listing with a column fewer than asked for: that is not a complete answer.
    narrowed = {s["step"]: s["fields_missing"] for s in data["steps"] if s.get("fields_missing") and s["status"] == "ok"}
    data.update(status="complete" if not data["errors"] and not unfinished and not narrowed and not uncounted else "partial", finished=True, elapsed_seconds=round(time.monotonic() - started, 3))
    reasons = []
    if data["errors"] or unfinished:
        reasons.append("%d error(s) and %d step(s) that did not finish (coverage.json names each)" % (len(data["errors"]), len(unfinished)))
    if uncounted:
        reasons.append("the recipe's own clock ran out while it counted %s: those listings are whole on disk and their counts are null, not zero" % ", ".join(uncounted))
    if narrowed:
        reasons.append("%d listing(s) were made without a field the installed tshark does not list (%s): a column of each is missing"
                       % (len(narrowed), "; ".join("%s: %s" % (name, ", ".join(fields)) for name, fields in sorted(narrowed.items()))))
    data["status_basis"] = "every step ran and exited 0 and every listing was written" if not reasons else "; ".join(reasons)
    if narrowed:
        data["listings_without_fields"] = narrowed
    receipt.write()
    print(json.dumps({"ok": not data["errors"], "status": data["status"], "status_basis": data["status_basis"]}))
    return 0 if not data["errors"] else 2


if __name__ == "__main__":
    raise SystemExit(main())
