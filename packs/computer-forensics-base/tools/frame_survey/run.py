#!/usr/bin/env python3
"""Look at every frame of a video: contact sheets with the frame number and time on each tile, a change score that makes a short
run of differing frames stand out without a scene cut, frames at native size, and a checked repair of a container that will not open.

The decoder is ffmpeg (with ffprobe for the stream's shape), run as a program: this tool has no decoder of its own, and where the
two are not on PATH every mode but the container diagnosis answers `failed` and says so. survey decodes the first video stream to
small frames on a pipe, tiles them on numbered sheets and compares each frame with the one before it in a grid of blocks: a cut
changes most blocks at once, a caption or an overlay changes a few and, when it ends, the same few again, and that pair is reported
as a run. extract writes a range of frames at native size as PNG. repair reads the container's own structure (an MP4's boxes, an
AVI's chunks), says what is missing or cut, has the decoder remux what it can read into a copy, and counts the frames the copy
decodes: that count, not the remux's exit code, is what the answer claims.

One JSON answer always; the tool's clock (max_seconds) is checked for every frame; a sampled or capped survey is partial and says
what it skipped.
"""

# BEGIN SHARED ENDS
# The same text is in every pack tool and recipe and in their tool-library twins, before the file's own imports (tests/shared-blocks-census.test.ts
# holds the copies equal): the two ends of a call, where a stop signal (SIGTERM, SIGINT, SIGHUP) found no handler, or one that did harm.
# * The start. From here a stop is answered by ONE JSON document and exit 128 + the signal, until the tool installs its own handlers (which then
#   answer it), and for good for a signal the tool never takes. Only the start of the interpreter and the compiling of the file come before
#   it: a stop there ends the process with no answer, before anything was read. answer_a_stop() is that document: a handler whose own last word
#   wrote nothing on standard output calls it before it ends the process, so that a stop is never answered by silence.
# * The end. The interpreter's own teardown resets the handlers to their defaults before it frees what the call held, and a stop that landed
#   there killed a process that had printed its whole answer; a handler that raises, writes a last word or ends the process, run once the
#   answer was decided, wrote a second document, a traceback, or nothing at all. Python runs a handler on the main thread whichever thread the
#   signal reached, so a mask of the main thread alone holds nothing while another thread runs. hold_stop_signals() holds the stop signals for
#   good: blocked in this thread and given a handler that does nothing, which is the hold whatever thread the signal reaches; an error Python
#   can only report from then on (a file left open whose last write the file system refuses, closed when the frame that held it is freed) is
#   not printed (3.11 and 3.12 say nothing of it, 3.14 a traceback). A handler that was due runs on the way in: what it raises reaches the
#   writer that asked (the tool's own handling then answers the stop, before any byte of the answer), or, quietly, is dropped (the end of a
#   call, an error branch). Every writer of a final answer calls it before it commits to writing, every error branch at the end calls it
#   quietly, and, when the file runs as a program, standard output is wrapped so that its first write calls it too. _code(stop) is a
#   SystemExit's exit code (its text, if it has one, goes to standard error as the interpreter puts it), and _leave(code) ends the call: both
#   hold the signals first, quietly; _leave flushes
#   standard output (a write that fails there makes a 0 an exit 120, as the interpreter does) and standard error, runs the atexit hooks (a hook
#   that removes a temporary file), each step on its own and none able to raise, and ends the process with os._exit, never through the teardown.
# The modules are imported here, as the file is loaded, never inside the ending (an import there ran a due handler inside the import system).
import atexit
import json
import os
import signal
import sys

_ENDING = {"held": False, "program": __name__ == "__main__"}      # imported (a test that loads the file as a module), the block holds nothing
_ENDING_SIGNALS = (signal.SIGTERM, signal.SIGINT, signal.SIGHUP)


def answer_a_stop(signum, when="before it had answered"):
    """The one document of a stop that ends the call before any answer was begun (nothing once one has): status failed, interrupted, and
    no claim about what was read or written. A handler whose own last word printed nothing calls it before it ends the process. It writes
    only when the file runs as a program: its wrapped standard output is what knows whether an answer was begun."""
    if _ENDING["held"] or not isinstance(sys.stdout, _AnswerStream):
        return
    _ENDING["held"] = True
    name = {signal.SIGTERM: "SIGTERM", signal.SIGINT: "SIGINT", signal.SIGHUP: "SIGHUP"}.get(signum, "signal %d" % signum)
    text = json.dumps({"error": "the tool was stopped by %s %s" % (name, when), "status": "failed", "interrupted": name,
                       "status_basis": "stopped by %s %s: no answer was made, and what it had read or written by then is not described" % (name, when)})
    try:
        os.write(1, (text + "\n").encode("ascii"))
    except OSError:
        pass


def _stopped_without_handler(signum, _frame):
    for other in _ENDING_SIGNALS:
        try:
            signal.signal(other, signal.SIG_IGN)
        except (ValueError, OSError):
            pass
    answer_a_stop(signum, "while it was being loaded, or at a point where it has no stop handling of its own")
    os._exit(128 + signum)


def _ending_nothing(*_ignored):
    """The stop signals' handler, and sys.unraisablehook, once the answer has begun: nothing."""


def hold_stop_signals(quietly=False):
    """Hold the stop signals for good. A handler that was due runs on the way in, before the hold and before any byte of the answer, and what
    it raises is raised here, so that the tool's own handling of a stop answers it; quietly (the end of a call, an error branch, where nothing
    may escape) it is dropped and the hold is made all the same. Called by a thread that is not the main one, it blocks the signals there and
    leaves the rest to the main thread's next call."""
    for _attempt in range(len(_ENDING_SIGNALS) + 2):
        if _ENDING["held"] or not _ENDING["program"]:
            return
        try:
            try:
                signal.pthread_sigmask(signal.SIG_BLOCK, _ENDING_SIGNALS)
            except (AttributeError, ValueError, OSError):
                pass                  # no pthread_sigmask here: the handler below is the hold
            main_thread = True
            for signum in _ENDING_SIGNALS:
                try:
                    signal.signal(signum, _ending_nothing)
                except (ValueError, OSError):
                    main_thread = False
            sys.unraisablehook = _ending_nothing
            _ENDING["held"] = main_thread
            return
        except BaseException:  # noqa: BLE001 - a handler that was due ran on the way in, and raised
            if not quietly:
                raise



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
    hold_stop_signals(quietly=True)
    code = getattr(stop, "code", 1)
    if isinstance(code, int):
        return code
    if code is not None:
        try:
            sys.stderr.flush()
            os.write(2, ("%s\n" % (code,)).encode("utf-8", "backslashreplace"))
        except BaseException:  # noqa: BLE001
            pass
    return 0 if code is None else 1


def _leave(code):
    hold_stop_signals(quietly=True)
    code = code if isinstance(code, int) else 1
    try:
        sys.stdout.flush()
    except BaseException:  # noqa: BLE001 - a reader that is gone: the answer did not reach it
        code = code or 120
    try:
        sys.stderr.flush()
    except BaseException:  # noqa: BLE001
        pass
    try:
        atexit._run_exitfuncs()
    except BaseException:  # noqa: BLE001 - a hook that fails is not a failure of the answer
        pass
    os._exit(code)


if __name__ == "__main__":
    if sys.stdout is not None and not isinstance(sys.stdout, _AnswerStream):
        sys.stdout = _AnswerStream(sys.stdout)
    for _signum in _ENDING_SIGNALS:
        signal.signal(_signum, _stopped_without_handler)
# END SHARED ENDS


import errno
import hashlib
import re
import shutil
import stat
import struct
import subprocess
import time
import zlib


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
# holds its pipes does not hold the tool: communicate_bounded gives the pipes PIPE_GRACE seconds (and POST_EXIT_BYTES bytes) and goes on without them.
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
# program runs each stream has a running cap too (STDOUT_CAP 64 MiB, STDERR_CAP 8 MiB with its head and last STDERR_TAIL 1 MiB kept, or the
# caller's `caps`): past it the program is ended on the deadline's own path (kill_tree, its tree only), the stream comes back cut
# (Output.cut, output_cut()), OUTPUT_CUT counts the call and process_apply turns a complete answer partial; a caller that parses a cut
# output says so and never takes it for a whole one.
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
    a call of communicate_bounded that was cut at POST_EXIT_BYTES counts, PIPE_CUT, and so does one that ended a program whose output passed
    its running cap, OUTPUT_CUT): what a program wrote while the tool read it, or what it printed past a cap, is not a complete result. A
    carrier calls it once where it prints its answer. Returns `answer`."""
    verdict = process_verdict()
    answer["program_group"] = verdict
    if (verdict["left_behind"] > 0 or verdict["unproven"] or PIPE_CUT["cut"] or OUTPUT_CUT["cut"]) and answer.get("status") == "complete":
        answer["status"] = "partial"
        for flag in ("ok", "complete"):
            if flag in answer:
                answer[flag] = False
        if verdict["left_behind"] > 0:
            sentence = "a program left %d process%s running after it ended; the tool ended them, and what they wrote before that is in the files named here" % (
                verdict["left_behind"], "" if verdict["left_behind"] == 1 else "es")
        elif OUTPUT_CUT["cut"]:
            sentence = "a program's output was not read whole: %s" % OUTPUT_CUT["last"]
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
STDOUT_CAP = 64 << 20        # the most bytes of standard output one call of communicate_bounded keeps; past it the program is ended and the output is cut
STDERR_CAP = 8 << 20         # the most bytes of standard error one call reads before it ends the program; it keeps the head and the last STDERR_TAIL bytes
STDERR_TAIL = 1 << 20        # the tail of standard error kept once it passes STDERR_CAP (a program's last words are at its end)
OUTPUT_CUT = {"cut": 0, "last": None}    # how many calls cut a stream at its running cap, and the sentence of the last one


class Output(bytes):
    """What communicate_bounded kept of one stream: the bytes, and `cut`, None when the stream was read whole, or a sentence saying it was
    not (the program printed past the stream's cap and was ended there). A caller that parses the output reads `cut` first: a cut output
    is never a whole one."""
    cut = None


def output_cut(*outputs):
    """The sentence of the first of `outputs` (values communicate_bounded or preflight returned) that was cut at its cap; None when each was
    read whole."""
    for out in outputs:
        text = getattr(out, "cut", None)
        if text:
            return text
    return None


def _output(data, cut):
    out = Output(data)
    out.cut = cut
    return out


def communicate_bounded(proc, seconds, input=None, caps=None):
    """(stdout bytes, stderr bytes, timed out) for a program started with pipes, in bytes (Output: bytes with a `cut` sentence or None). At
    `seconds` the program and what it started are killed (timed out). What the tool holds is capped while the program runs: `caps` is
    (stdout cap, stderr cap), STDOUT_CAP and STDERR_CAP when it is None. Standard output is kept to its cap; standard error keeps its head and
    its last STDERR_TAIL bytes (at most half its cap). When either stream passes its cap the program and what it started are ended (kill_tree,
    the deadline's own path: its tree, nothing else), what was kept is returned with `cut` set on that stream, the call is counted in
    OUTPUT_CUT and said in process_notes(), and process_apply turns a complete answer partial. A program that has ended while something it
    started still holds its pipes (a daemon, a helper that inherited them) does not hold the tool: from the moment the program has ended (or
    was killed) the pipes are given PIPE_GRACE seconds and POST_EXIT_BYTES bytes, whichever is used up first; what the program wrote is kept,
    what the tool lost is killed (reap_orphans, settle), and the pipes are let go. A cut at the byte cap is counted in PIPE_CUT and noted
    (process_notes()); the return shape is the same. The pipes are read here and by nothing else (not by Popen.communicate), so letting them
    go is safe. `input` is written while the program runs and is dropped once it has ended."""
    deadline = time.monotonic() + max(0.1, seconds)
    out_cap, err_cap = (STDOUT_CAP, STDERR_CAP) if caps is None else (max(0, int(caps[0])), max(0, int(caps[1])))
    tail_keep = min(STDERR_TAIL, err_cap // 2)
    bufs = (bytearray(), bytearray())       # standard output; the head of standard error
    tail = bytearray()                      # the last tail_keep bytes of standard error read past its head
    seen, over = [0, 0], [False, False]     # bytes read from each stream; the stream passed its cap while the program ran
    late = [False, False]                   # the stream passed its cap after the program had ended (by itself, or at the deadline)
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
    timed_out, note, ended, extra, cut, sampled, ended_at_cap = False, None, None, 0, False, 0.0, False
    try:
        while True:
            now = time.monotonic()
            if ended is None:
                if proc.poll() is not None:
                    ended = now
                elif over[0] or over[1]:
                    ended_at_cap = True
                    note = kill_tree(proc)
                    ended = time.monotonic()
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
                index = key.data
                seen[index] += len(data)
                if ended is not None:
                    extra += len(data)
                if index == 0:
                    room = out_cap - len(bufs[0])
                    if room > 0:
                        bufs[0].extend(data[:room])
                    if seen[0] > out_cap:
                        over[0], late[0] = (over[0], True) if ended is not None else (True, late[0])
                else:
                    room = err_cap - tail_keep - len(bufs[1])
                    if room > 0:
                        bufs[1].extend(data[:room])
                        data = data[room:]
                    if data:
                        tail.extend(data)
                        if len(tail) > tail_keep:
                            del tail[:len(tail) - tail_keep]
                    if seen[1] > err_cap:
                        over[1], late[1] = (over[1], True) if ended is not None else (True, late[1])
                if (over[0] or over[1]) and ended is None:
                    break           # the loop's head ends the program at once
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
    # A stream that passed its cap only after the program had ended is cut too, unless the pipes were cut at POST_EXIT_BYTES: then what passed
    # it is a process that held the pipe and went on writing, PIPE_CUT says so, and the program's own output was read whole.
    for index in (0, 1):
        over[index] = over[index] or (late[index] and not cut)
    ending = "; the tool ended the program there" if ended_at_cap else ""
    out_cut = ("the program printed more than %d bytes on its standard output; the tool kept the first %d and did not read the rest%s" % (
        out_cap, len(bufs[0]), ending)) if over[0] else None
    err_cut = ("the program printed more than %d bytes on its standard error; the tool kept the first %d and the last %d%s" % (
        err_cap, len(bufs[1]), len(tail), ending)) if over[1] else None
    for sentence in (out_cut, err_cut):
        if sentence:
            OUTPUT_CUT["cut"] += 1
            OUTPUT_CUT["last"] = sentence
            _note(sentence)
    err = bytes(bufs[1])
    if over[1]:
        err += b"\n[... %d bytes of standard error not kept ...]\n" % (seen[1] - len(bufs[1]) - len(tail))
    err += bytes(tail)
    if note:
        err = err + (b"\n" if err else b"") + note.encode("utf-8", "replace")
    return _output(bufs[0], out_cut), _output(err, err_cut), timed_out     # (one copy of standard output, not two)


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
    if "answer_a_stop" in globals():     # (a block run on its own, by a test, has no ENDS block)
        answer_a_stop(signum)
    os._exit(128 + signum)


def preflight(argv, seconds, caps=None):
    """Run a short program, bounded; (exit code or None, stdout bytes, stderr bytes, timed out). The outputs are communicate_bounded's (Output,
    held to `caps`): a program ended because a stream passed its cap has that stream's `cut` set (output_cut()) and its own exit code."""
    try:
        proc = spawn(argv, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    except OSError as exc:
        return None, _output(b"", None), _output(describe(exc).encode("utf-8", "replace"), None), False
    ACTIVE.append(proc)
    try:
        out, err, timed_out = communicate_bounded(proc, max(1.0, seconds), caps=caps)
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
        # The document is whole. A stop that came while it was written is let go now: run as a program, the shared ENDS block has given it a
        # handler that does nothing (the answer stands, and the call ends with its own code); loaded as a module, the tool's own handler ends it
        # (128 plus the signal; the last word was cleared) with nothing more on stdout. The mask is also what an in-process caller (a test) had before.
        signal.pthread_sigmask(signal.SIG_SETMASK, before)


def print_answer(answer, **dumps_kwargs):
    """Print the answer with the stop signals held back and the last word cleared (a signal in the middle of the write would cut the
    document, and the last word would add a second one), on the bounded write above."""
    hold_stop_signals()
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


TOOL = {"name": "frame_survey", "version": 5}
PARSER = "frame_survey/5"
DEFAULT_SECONDS, MAX_SECONDS = 500, 540         # under the manifest's 600, with room for what may follow the clock: FINISH_SECONDS, the pairing's
                                                # own 10 seconds, the decoder's ending and the settling of its group (about 40 seconds at most)
PROBE_SECONDS = 30
DEFAULT_FRAMES, MAX_FRAMES = 20000, 200000      # frames decoded a call
MAX_EXTRACT = 300                               # frames written at native size a call
MAX_EXTRACT_BYTES = 2 << 30
MAX_NATIVE_WIDTH, MAX_NATIVE_HEIGHT = 8192, 4320       # the coded frame, each side (a frame turned by its display matrix is turned after)
TILE_BOX_HEIGHT = 2                             # a tile is at most this many tile widths high: a tall frame is fitted into the box
MAX_SHEET_BYTES = 192 << 20                     # the pixels of one contact sheet held at once (RGB)
FINISH_SECONDS = 20                             # past the clock, the time an encoder that has begun a picture is given (under the manifest's timeout)
# The whole numbers a call takes, each with its own range: the refusal of one says that range.
RANGES = {"every": (1, 100000), "start_frame": (0, 10 ** 9), "max_frames": (1, MAX_FRAMES), "tile_width": (64, 480), "columns": (1, 20),
          "rows": (1, 20), "window": (2, 1000), "first": (0, 10 ** 9), "last": (0, 10 ** 9)}
GRID_COLUMNS, GRID_ROWS = 32, 18                # the blocks a frame is compared in
BLOCK_STEP = 8                                  # a block has changed when its mean moved by more than this (of 255)
KNOWN_PARAMS = {"video", "mode", "every", "start_frame", "max_frames", "tile_width", "columns", "rows", "window", "first", "last", "max_seconds"}
MODES = ("survey", "extract", "repair")
RULES = [
    "Survey first, with the default call ({\"video\": ...}): every frame is decoded, tiled with its frame number and time, and scored. "
    "Read `runs` before the sheets: a run is a stretch of frames in which one region changed and changed back (a caption, an overlay, a "
    "flash) with no scene cut, and it names the sheets that show it.",
    "A sampled or capped survey is `partial` and says what it skipped (every, max_frames, the clock): a run shorter than the sampling "
    "step can fall between two samples, so \"nothing stands out\" is a negative only for a `complete` survey with every: 1.",
    "Take the frames a run names at native size ({\"mode\": \"extract\", \"first\": N, \"last\": M}) before reading text off a tile: a "
    "tile is a reduced copy. Frame numbers count decoded frames of the first video stream from 0; a time is the frame's own "
    "presentation time when the decoder gave one, else frame / rate, and the answer says which.",
    "A file that will not open goes to {\"mode\": \"repair\"}: it says what the container lacks (an MP4's moov, a cut mdat, an AVI's "
    "index), writes a remuxed copy, and counts the frames that copy DECODES. The count decoded is the claim; a missing moov with no "
    "second file from the same recorder is not rebuilt, and the answer says so.",
]


# ---- what every answer and every file of this tool goes through ---------------------------------------------------------------------
MAX_ARGUMENT_BYTES = 4 << 20


class Refused(Exception):
    """A parameter or an input the tool refuses: the text is the whole message."""


def fail(message, **extra):
    print_answer({"tool": TOOL, "status": "failed", "error": message,
                  "status_basis": "the tool stopped with an error (see error): it read nothing it answers for, and that is not a negative",
                  "rules": RULES, **extra})
    raise SystemExit(1)


def describe(exc):
    """An error without the path it names: its class, the errno's name and the system's own words."""
    code = errno.errorcode.get(exc.errno, "") if getattr(exc, "errno", None) else ""
    words = getattr(exc, "strerror", None) or "no system message"
    return "%s%s: %s" % (type(exc).__name__, " " + code if code else "", words)


def where_it_failed(exc):
    tb, line = exc.__traceback__, None
    while tb is not None:
        if tb.tb_frame.f_code.co_filename == __file__:
            line = tb.tb_lineno
        tb = tb.tb_next
    return "line %s of the tool" % line if line else "an unknown line"


def printable(text, most=300):
    """A caller's string as the answer repeats it: one line, bounded, with nothing a terminal or a JSON reader would trip on."""
    text = text if isinstance(text, str) else repr(text)
    text = "".join(ch if " " <= ch < "\x7f" or (ch > "\xa0" and ch.isprintable() and not 0xD800 <= ord(ch) <= 0xDFFF) else "?" for ch in text)
    return text if len(text) <= most else text[:most] + "...(%d characters)" % len(text)


def read_args(known):
    """The arguments, a JSON object on standard input: (args, the names it does not know)."""
    raw = sys.stdin.buffer.read(MAX_ARGUMENT_BYTES + 1)
    if len(raw) > MAX_ARGUMENT_BYTES:
        fail("the arguments are over %d bytes" % MAX_ARGUMENT_BYTES)
    try:
        args = json.loads(raw.decode("utf-8"))
    except (ValueError, RecursionError) as exc:
        fail("the arguments are not valid JSON (%s): send one JSON object on standard input" % type(exc).__name__)
    if not isinstance(args, dict):
        fail("the arguments must be a JSON object")
    return args, sorted(printable(k, 60) for k in args if k not in known)


def int_param(args, key, default, low, high):
    value = args.get(key)
    if value is None:
        return default
    if isinstance(value, bool) or not isinstance(value, int) or not low <= value <= high:
        raise Refused("%s must be a whole number from %d to %d" % (key, low, high))
    return value


def number_param(args, key, default, low, high):
    value = args.get(key)
    if value is None:
        return default
    if isinstance(value, bool) or not isinstance(value, (int, float)) or value != value or not low <= value <= high:
        raise Refused("%s must be a number from %s to %s" % (key, low, high))
    return float(value)


def bool_param(args, key, default=False):
    value = args.get(key)
    if value is None:
        return default
    if not isinstance(value, bool):
        raise Refused("%s must be true or false" % key)
    return value


def choice_param(args, key, default, choices):
    value = args.get(key)
    if value is None:
        return default
    if not isinstance(value, str) or value not in choices:
        raise Refused("%s must be one of: %s" % (key, ", ".join(choices)))
    return value


def path_param(value, what):
    if not isinstance(value, str) or not value or "\x00" in value or len(value) > 4096:
        raise Refused("%s must be a path: a string of 1 to 4096 characters without a NUL" % what)
    try:
        value.encode("utf-8")
    except UnicodeError:
        raise Refused("%s is not a path this tool can open: it does not encode as UTF-8" % what)
    return value


def read_file(path, most, what):
    """The bytes of a regular file, opened without waiting on a FIFO or a device, at most `most` bytes: Refused says why not."""
    try:
        fd = os.open(path, os.O_RDONLY | getattr(os, "O_NONBLOCK", 0))
    except OSError as exc:
        raise Refused("%s cannot be opened (%s)" % (what, describe(exc)))
    try:
        st = os.fstat(fd)
        if not stat.S_ISREG(st.st_mode):
            raise Refused("%s is not a regular file (a directory, a FIFO or a device is not read)" % what)
        if st.st_size > most:
            raise Refused("%s is %d bytes; this tool reads a file of up to %d" % (what, st.st_size, most))
        parts, got = [], 0
        while got <= most:
            if out_of_time():
                raise Refused("the tool's clock ran out while %s was being read" % what)
            block = os.read(fd, min(1 << 22, most + 1 - got))
            if not block:
                break
            parts.append(block)
            got += len(block)
        if got > most:
            raise Refused("%s grew past %d bytes while it was read" % (what, most))
        return b"".join(parts)
    except OSError as exc:
        raise Refused("%s cannot be read (%s)" % (what, describe(exc)))
    finally:
        os.close(fd)


class Place:
    """Where this call writes: a directory of its own, made new, under $OUT in a job and under work/<agent>/tool-output outside one. No
    link is followed on the way: every directory is opened with O_NOFOLLOW and the next one made and opened below it, and a file is
    created exclusively (never over a name that is there, never through a link). A file that was begun and not finished is removed on
    every way out (the shared TEMPS block holds its name until it is whole)."""

    def __init__(self, stem):
        job, out = os.environ.get("JOB_ID"), os.environ.get("OUT")
        self.in_job = bool(job and out)
        nofollow = getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_DIRECTORY", 0) | os.O_RDONLY
        try:
            if self.in_job:
                self.shown = "store/jobs/%s/out" % re.sub(r"[^A-Za-z0-9_.-]", "_", job)
                self.path = out
                os.makedirs(out, exist_ok=True)
                fd = os.open(out, nofollow)
            else:
                agent = os.environ.get("AGENT_ID") or "tool"
                if not re.fullmatch(r"[A-Za-z0-9_-][A-Za-z0-9_.-]{0,127}", agent):
                    raise Refused("AGENT_ID is not a plain name (letters, digits, '_', '-' and '.', and no '.' first): outside a job the files go under "
                                  "work/<AGENT_ID>/tool-output, and this one would not name a directory there. Nothing was written")
                self.shown = "work/%s/tool-output" % agent
                self.path = os.path.join("work", agent, "tool-output")
                fd = os.open(".", nofollow)
                for part in ("work", agent, "tool-output"):
                    try:
                        os.mkdir(part, 0o755, dir_fd=fd)
                    except FileExistsError:
                        pass
                    below = os.open(part, nofollow, dir_fd=fd)
                    os.close(fd)
                    fd = below
            for n in range(1, 10000):
                name = stem if n == 1 else "%s-%d" % (stem, n)
                try:
                    os.mkdir(name, 0o755, dir_fd=fd)
                except FileExistsError:
                    continue
                self.fd = os.open(name, nofollow, dir_fd=fd)
                os.close(fd)
                self.shown += "/" + name
                self.path = os.path.join(self.path, name)
                return
            os.close(fd)
            raise Refused("no free name for this call's output directory under %s" % self.shown)
        except OSError as exc:
            raise Refused("the output directory cannot be made or is reached through a link (%s): nothing was written" % describe(exc))

    def write(self, name, chunks, mode=0o644):
        """Create `name` here and write the chunks (bytes, or an iterable of bytes); the name the answer cites. OSError when it cannot."""
        full = os.path.join(self.path, name)
        fd = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), mode, dir_fd=self.fd)
        temp_hold(full)
        try:
            for chunk in ((chunks,) if isinstance(chunks, (bytes, bytearray)) else chunks):
                view = memoryview(chunk)
                while len(view):
                    view = view[os.write(fd, view[:1 << 20]):]
        finally:
            os.close(fd)
        temp_done(full)
        return "%s/%s" % (self.shown, name)

    def remove(self, name):
        """Remove a file this call wrote here (a result that turned out to hold nothing); False when it could not be."""
        try:
            os.unlink(name, dir_fd=self.fd)
            return True
        except OSError:
            return False

    def note(self):
        return None if self.in_job else ("written where you called it, not sealed: run it as a job (job_run tool=%s) to have the files sealed into the store and citable as job:<id>/<path>" % TOOL["name"])


def answered(main):
    """main(), with every way it can fail turned into one JSON answer."""
    try:
        main()
    except SystemExit:
        raise
    except Refused as exc:
        hold_stop_signals(quietly=True)
        left = drop_temporaries()
        fail(str(exc), **({"temporaries_left": left[:10]} if left else {}))
    except (MemoryError, RecursionError) as exc:
        hold_stop_signals(quietly=True)
        drop_temporaries()
        fail("the input needs more memory or nesting than this tool has (%s)" % type(exc).__name__)
    except Exception as exc:  # noqa: BLE001 - never an empty or clean answer for a failure
        hold_stop_signals(quietly=True)
        drop_temporaries()
        fail("unexpected failure: %s" % (describe(exc) if isinstance(exc, OSError) else "%s at %s" % (type(exc).__name__, where_it_failed(exc))))


def _stopped(signum):
    """The last word of a stop: the temporaries go, then one document (status failed, interrupted)."""
    left = drop_temporaries()
    sys.stdout.write(json.dumps({"tool": TOOL, "status": "failed", "interrupted": True, "signal": signum,
                                 "status_basis": "the tool was stopped by signal %d before its answer: the program it was running was ended, a file it had begun was removed, and nothing is claimed about what it had read" % signum,
                                 **({"temporaries_left": left[:10]} if left else {})}) + "\n")
    sys.stdout.flush()


STATE["last_word"] = _stopped
install_signal_handlers()
STOP_CLOCK = {"deadline": None}


def set_deadline(seconds):
    STOP_CLOCK["deadline"] = time.monotonic() + seconds


def out_of_time():
    return STOP_CLOCK["deadline"] is not None and time.monotonic() > STOP_CLOCK["deadline"]


def seconds_left(most):
    left = (STOP_CLOCK["deadline"] - time.monotonic()) if STOP_CLOCK["deadline"] is not None else most
    return max(0.5, min(most, left))


def past_finish():
    """Past the clock and the FINISH_SECONDS an encoder that has begun a picture is given: the picture is given up."""
    return STOP_CLOCK["deadline"] is not None and time.monotonic() > STOP_CLOCK["deadline"] + FINISH_SECONDS


def find_program(name):
    """The program's path on PATH, or None."""
    return shutil.which(name)


PNG_MAGIC = b"\x89PNG\r\n\x1a\n"


def png_bytes(width, height, rows, channels=1):
    """A PNG (8-bit grey, or RGB with channels 3) from rows of bytes (any iterable), compressed row by row: the rows are never joined into
    one copy. Every 64 rows the clock is read: past the clock and FINISH_SECONDS the picture is given up (Clock)."""
    packer = zlib.compressobj(6)
    parts = []
    for y, row in enumerate(rows):
        if y % 64 == 0 and past_finish():
            raise Clock()
        parts.append(packer.compress(b"\x00"))
        parts.append(packer.compress(row))
    parts.append(packer.flush())
    body = b"".join(parts)

    def chunk(kind, data):
        return struct.pack(">I", len(data)) + kind + data + struct.pack(">I", zlib.crc32(kind + data))

    return (PNG_MAGIC + chunk(b"IHDR", struct.pack(">IIBBBBB", width, height, 8, 0 if channels == 1 else 2, 0, 0, 0))
            + chunk(b"IDAT", body) + chunk(b"IEND", b""))


# ---- index numbers on a picture: a 3 x 5 font of the tool's own (digits and the marks a frame label needs) ----------------------------
FONT_3X5 = {
    "0": "111101101101111", "1": "010110010010111", "2": "111001111100111", "3": "111001111001111", "4": "101101111001001",
    "5": "111100111001111", "6": "111100111101111", "7": "111001001001001", "8": "111101111101111", "9": "111101111001111",
    ":": "000010000010000", ".": "000000000000010", "-": "000000111000000", " ": "000000000000000", "#": "101111101111101",
    "s": "000011110011110", "f": "011100110100100",
}


def label_rows(text, scale=2):
    """A label as rows of 0 (paper) and 1 (ink): (width, rows). A character the font lacks is drawn as a dash."""
    glyphs = [FONT_3X5.get(ch, FONT_3X5["-"]) for ch in text]
    width = max(1, len(glyphs) * 4 - 1) * scale
    rows = []
    for y in range(5):
        line = bytearray()
        for i, glyph in enumerate(glyphs):
            for x in range(3):
                line += (b"\x01" if glyph[y * 3 + x] == "1" else b"\x00") * scale
            if i < len(glyphs) - 1:
                line += b"\x00" * scale
        rows += [bytes(line)] * scale
    return width, rows


class Clock(Exception):
    """The tool's own clock ran out inside a loop."""


def tick():
    if out_of_time():
        raise Clock()


class Unread:
    """The one list of what this call did not read or did not judge: every place that leaves something unread or unjudged counts it here,
    under a name declared up front, with the sentence that says it. The status is derived from this list alone (a failed call aside): a
    count above zero makes the answer partial. The answer prints every counter, zeros included (`not_read_or_judged`)."""

    def __init__(self, *names):
        self.counts = {name: 0 for name in names}
        self.said = {}

    def add(self, name, count=1, sentence=None):
        if name not in self.counts:
            raise KeyError(name)
        if count:
            self.counts[name] += count
            if sentence and name not in self.said:
                self.said[name] = sentence

    def __bool__(self):
        return any(self.counts.values())

    def reasons(self):
        return [self.said.get(name, name.replace("_", " ")) for name, count in self.counts.items() if count]


# showinfo's own line about a frame, at the start of a log line (ffmpeg prints a value of the stream's metadata after an indent and never
# begins a line with it, so a title that holds such text is not read as a frame).
SHOWINFO = re.compile(rb"(?:^|\r)\[Parsed_showinfo[^\]\n]*\] n: *(\d+) +pts: *(-?\d+|N/A) +pts_time: *(-?[0-9.]+|N/A)")
SHOWINFO_LINE = re.compile(rb"(?:^|\r)\[Parsed_showinfo")
LOG_LINE_MOST = 1 << 16                         # a decoder log line is read in pieces of this many bytes
LOG_TAIL = 256                                  # the end of one piece judged again with the next, so a word across two pieces is seen
# A decoder's or a demuxer's line about damage: an error, a cut file ("File ended prematurely", "partial file", "Truncating packet", "end of
# file"), a structure past its parent (Matroska's "exceeds containing master element"), a lost or broken reference ("Frame num gap",
# "non-existing PPS", "no frame!"), a concealed or skipped frame. Plain words a title can hold ("lost", "skipping") are left out.
TROUBLE = re.compile(rb"error|damaged|corrupt|invalid|partial file|missing|conceal|truncat|prematur|end of file|unexpected|incomplete|exceed|overread"
                     rb"|out of (?:range|bounds)|broken|mismatch|desync|resync|fail|num gap|non-existing|no frame", re.I)


def clean(text, most=300):
    text = text.decode("utf-8", "replace") if isinstance(text, bytes) else text
    text = "".join(ch if " " <= ch < "\x7f" else " " for ch in text).strip()
    return text if len(text) <= most else text[:most] + "..."


def programs():
    """The decoder of this image: (ffmpeg path, ffprobe path, what to say when one is missing)."""
    ffmpeg, ffprobe = find_program("ffmpeg"), find_program("ffprobe")
    missing = [name for name, path in (("ffmpeg", ffmpeg), ("ffprobe", ffprobe)) if path is None]
    return ffmpeg, ffprobe, ("no video decoder is in this image: %s %s not on PATH (this tool decodes with ffmpeg and reads the stream's shape with ffprobe; it has no decoder of its own)"
                             % (" and ".join(missing), "is" if len(missing) == 1 else "are")) if missing else None


def target_of(path):
    """A path ffmpeg takes as a file: a relative one is given with ./ in front, so that a name that begins with a dash is no option
    and a name with a colon is no protocol."""
    return path if os.path.isabs(path) else os.path.join(".", path)


def rotation_of(stream):
    """The display rotation a stream carries, in degrees as ffprobe prints it (its display matrix, or an older demuxer's rotate tag), or None."""
    for side in stream.get("side_data_list") or []:
        if isinstance(side, dict) and isinstance(side.get("rotation"), (int, float)) and not isinstance(side.get("rotation"), bool):
            return float(side["rotation"])
    tags = stream.get("tags") if isinstance(stream.get("tags"), dict) else {}
    try:
        return float(tags["rotate"]) if "rotate" in tags else None
    except (TypeError, ValueError):
        return None


def mirror_of(stream):
    """Whether the stream's display matrix mirrors the picture (the determinant of its 2 x 2 part is negative), from the matrix as ffprobe
    prints it; None when it prints none. ffprobe gives a mirror a rotation as well (a horizontal mirror reads as 180 degrees)."""
    for side in stream.get("side_data_list") or []:
        if isinstance(side, dict) and isinstance(side.get("displaymatrix"), str):
            numbers = re.findall(r"^\s*[0-9a-fA-F]{8}:\s*(-?\d+)\s+(-?\d+)\s+(-?\d+)\s*$", side["displaymatrix"], re.M)
            if len(numbers) == 3:
                (a, b, _u), (c, d, _v) = [tuple(int(x) for x in row) for row in numbers[:2]]
                return a * d - b * c < 0
    return None


PROBE_ENTRIES = ("stream=codec_name,width,height,avg_frame_rate,r_frame_rate,nb_frames,duration,start_time:stream_side_data=rotation,displaymatrix"
                 ":stream_tags=rotate:stream_disposition=attached_pic:format=format_name,duration,start_time")
MAX_PIXELS = MAX_NATIVE_WIDTH * MAX_NATIVE_HEIGHT     # the decoder's own bound on a frame's pixels (-max_pixels): every frame, not only the first


def picture_reader(form):
    """Whether ffmpeg reads the file with its picture-sequence demuxer (image2), by the format name ffprobe printed."""
    return "image2" in str(form).split(",")


def input_options(info):
    """The decoder's options for the input: its bound on a frame's pixels, and -pattern_type none where the picture-sequence demuxer reads
    the file (that demuxer alone takes the option; any other refuses it)."""
    return ["-max_pixels", str(MAX_PIXELS), *(["-pattern_type", "none"] if info.get("picture_reader") else [])]


def probe(ffprobe, path):
    """The first video stream as ffprobe reads it: {codec, width, height (of the frame as the decoder gives it), coded, rotation, autorotate,
    rate, frames_said, duration_said, container, video_streams}, or (None, why). A rotation by a quarter or half turn is let through to the
    decoder, which turns each frame without resampling it (width and height are then of the turned frame); any other angle is not applied
    (-noautorotate), because turning by it resamples the frame."""
    given = seconds_left(PROBE_SECONDS)
    # Only the fields read here are asked for: a stream's other tags (of any size a file holds) are not printed. -pattern_type none: a
    # name with a printf pattern and a picture extension is the one file it names, never a numbered sequence of other files.
    code, out, err, timed_out = preflight([ffprobe, "-v", "error", "-pattern_type", "none", "-select_streams", "v", "-show_entries", PROBE_ENTRIES,
                                           "-of", "json", "-i", "file:" + target_of(path)], given, caps=(16 << 20, 1 << 20))
    if timed_out:
        return None, "ffprobe did not finish in the %.0f seconds it was given (at most %d, and no more than the clock had left)" % (given, PROBE_SECONDS)
    if output_cut(out, err):
        return None, "ffprobe's output was not read whole, so it was not parsed: %s" % output_cut(out, err)
    try:
        doc = json.loads(out.decode("utf-8", "replace"))
    except (ValueError, RecursionError):
        doc = {}
    streams = doc.get("streams") if isinstance(doc, dict) else None
    if code != 0 or not isinstance(streams, list) or not streams or not isinstance(streams[0], dict):
        return None, "ffprobe found no video stream it can read (exit %s): %s" % (code, clean(err) or "it said nothing")
    stream = streams[0]
    width, height = stream.get("width"), stream.get("height")
    if (not isinstance(width, int) or not isinstance(height, int) or isinstance(width, bool) or isinstance(height, bool) or width < 2 or height < 2
            or width > MAX_NATIVE_WIDTH or height > MAX_NATIVE_HEIGHT):
        return None, ("the video stream's frame size is not one this tool takes (%s x %s; it takes 2 to %d wide and 2 to %d high, as coded)"
                      % (clean(str(width), 12), clean(str(height), 12), MAX_NATIVE_WIDTH, MAX_NATIVE_HEIGHT))
    turn = rotation_of(stream)
    quarter = turn is not None and abs(turn - round(turn / 90.0) * 90) < 1.0
    autorotate = turn is None or quarter
    coded = (width, height)
    if quarter and int(round(turn / 90.0)) % 2:
        width, height = height, width
    disposition = stream.get("disposition") if isinstance(stream.get("disposition"), dict) else {}

    def rate(text):
        try:
            a, _, b = str(text).partition("/")
            value = float(a) / float(b or 1)
            return value if 0 < value < 1000 else None
        except (ValueError, ZeroDivisionError):
            return None

    def number(text, kind):
        try:
            return kind(text)
        except (TypeError, ValueError):
            return None

    form = doc.get("format") if isinstance(doc.get("format"), dict) else {}
    return {"codec": clean(str(stream.get("codec_name")), 40), "width": width, "height": height, "coded": "%d x %d" % coded,
            "rotation": turn, "mirrored": mirror_of(stream), "autorotate": autorotate, "attached_picture": disposition.get("attached_pic") == 1,
            "rate": rate(stream.get("avg_frame_rate")) or rate(stream.get("r_frame_rate")), "frames_said": number(stream.get("nb_frames"), int),
            "duration_said": number(stream.get("duration"), float) or number(form.get("duration"), float),
            # The decoder shifts every time by the file's start time (it runs without -copyts): the stream's stated end is its own start
            # time less the file's, plus its duration; with only the file's duration, the end is that duration.
            "start_said": ((number(stream.get("start_time"), float) or 0.0) - (number(form.get("start_time"), float) or 0.0)) if number(stream.get("duration"), float) else 0.0,
            "container": clean(str(form.get("format_name")), 60), "picture_reader": picture_reader(form.get("format_name")),
            "video_streams": len(streams)}, None


def turned(info):
    """What the answer says about the stream's display rotation and its other video streams: {field: sentence}, empty when there is nothing."""
    said = {}
    mirror = info.get("mirrored")
    if info["rotation"] is not None and info["autorotate"] and (round(info["rotation"]) % 360 or mirror):
        if mirror:
            said["rotation_note"] = ("the stream's display matrix MIRRORS the picture (ffprobe gives it a rotation of %g degrees, a number that alone does not say how a mirrored picture is shown): "
                                     "the decoder applies the matrix as a player shows it, a mirror%s, moving pixels without resampling them, and every size, "
                                     "frame and region here is of the shown frame, %d x %d (coded %s): text in it reads as the player shows it, which may be "
                                     "mirrored from the scene" % (info["rotation"], " and a turn" if round(info["rotation"]) % 180 else "", info["width"],
                                                                   info["height"], info["coded"]))
        else:
            said["rotation_note"] = ("the stream carries a display rotation of %g degrees: the decoder turns each frame as a player shows it (a quarter or half "
                                     "turn moves pixels without resampling them), and every size, frame and region here is of the turned frame, %d x %d (coded %s)"
                                     % (info["rotation"], info["width"], info["height"], info["coded"]))
    elif info["rotation"] is not None and not info["autorotate"]:
        said["rotation_note"] = ("the stream carries a display rotation of %g degrees%s, which is not a quarter or half turn: it was NOT applied (turning by it "
                                 "resamples the frame), and every size, frame and region here is of the frame as coded, %s" % (
                                     info["rotation"], " and a mirror (not applied either)" if mirror else "", info["coded"]))
    if info["video_streams"] > 1:
        said["streams_note"] = ("the file has %d video streams and this tool reads the first (0:v:0) only: the others were not decoded, and a negative here "
                                "says nothing about them" % info["video_streams"])
    if info["attached_picture"]:
        said["attached_picture_note"] = "the first video stream is an attached picture (cover art), not a recording: it holds one frame"
    return said


def stream_frames(argv, frame_bytes, on_frame, stderr_file):
    """Run a decoder that writes raw frames on its standard output and hand each to on_frame (False from it ends the run). Bounded all
    the way: the tool's clock, read before every frame; and from the moment the decoder has ended, its pipe is given PIPE_GRACE seconds
    and POST_EXIT_BYTES bytes (what it wrote before it ended is at most a pipe's buffer), so a process it left behind that holds the pipe,
    silent or writing, does not hold the tool. Returns {frames, exit, stopped: None | "clock" | "enough" | "pipe held", after_exit (the
    frames whose last byte was read after the decoder had ended), left (bytes of a frame not whole)}."""
    proc = spawn(argv, stdout=subprocess.PIPE, stderr=stderr_file)
    ACTIVE.append(proc)
    state = {"frames": 0, "exit": None, "stopped": None, "left": 0, "after_exit": 0}
    buffer = bytearray()
    fd = proc.stdout.fileno()
    ended, extra = None, 0
    try:
        while True:
            if out_of_time():
                state["stopped"] = "clock"
                break
            if ended is None and proc.poll() is not None:
                ended = time.monotonic()
            if ended is not None and (time.monotonic() - ended >= PIPE_GRACE or extra >= POST_EXIT_BYTES):
                state["stopped"] = "pipe held"
                break
            ready = _select.select([fd], [], [], 0.25)[0]
            if not ready:
                continue
            data = os.read(fd, 1 << 20 if ended is None else min(1 << 20, POST_EXIT_BYTES - extra))
            if not data:
                break
            if ended is not None:
                extra += len(data)
            buffer += data
            at = 0
            while len(buffer) - at >= frame_bytes:
                if out_of_time():
                    state["stopped"] = "clock"
                    break
                frame = bytes(buffer[at:at + frame_bytes])
                at += frame_bytes
                state["frames"] += 1
                if ended is not None:
                    state["after_exit"] += 1
                if on_frame(frame) is False:
                    state["stopped"] = "enough"
                    break
            del buffer[:at]
            if state["stopped"]:
                break
        if state["stopped"]:
            kill_tree(proc)
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            kill_tree(proc)
            proc.wait()
        state["exit"] = proc.returncode
        state["left"] = len(buffer)
    finally:
        _close_pipe(proc.stdout)
        ACTIVE.remove(proc)
    return state


FRAME_SIZE = re.compile(rb" s:(\d+)x(\d+) ")


REBUILT = re.compile(rb"Reconfiguring filter graph")


class LogTimes:
    """The presentation time and the size of each output frame, from the showinfo lines the decoder writes to its log: {output index:
    seconds}, and the indexes whose line was read. An output frame's index is the order of its showinfo line, counted here (the k-th line
    is the k-th frame on the pipe), never showinfo's own n: that counter starts again when the decoder rebuilds its filters. A rebuild
    (its "Reconfiguring filter graph" line, or an n that is not the one after the last) is counted in `restarts`, with the output index it
    came at: the select filter's count started again with it, so a frame number chosen by that filter is not a decoded frame's number past
    it. The log is read on from where the last reading stopped, a line that is not whole yet waits for the next (the last reading takes
    it as it is). A line longer than LOG_LINE_MOST (a metadata value ffmpeg prints on one line) is read in pieces: the first is judged as
    a line, every other for words about an error, each with the end of the piece before it, and the line is counted in long_lines; no
    piece is left unjudged. A line about an error is counted with the input's own name taken out of it first (a file named "missing" is
    no error), and showinfo's own lines are never counted as one. The reading stops at the clock and the FINISH_SECONDS past it: the
    bytes it did not read are counted in bytes_not_read."""

    def __init__(self, path, size, quiet=(), keep=20):
        self.path, self.at, self.times = path, 0, {}
        self.size, self.quiet, self.keep = size, [q for q in quiet if q], keep
        self.seen = set()                          # the output indexes whose showinfo line was read
        self.lines = 0                             # showinfo lines read: the next output index
        self.rebuilt, self.jumps = 0, 0            # the decoder's own lines about a rebuild, and showinfo counters that were not the one after the last
        self.last_n = -1
        self.restart_at = None                     # the output index the first rebuild came at
        self.last_time = None                      # the presentation time of the last frame that had one
        self.other_size, self.other_first = 0, {}  # frames decoded at another size than the stream's: how many, and the first (index: "w x h")
        self.trouble, self.said = 0, []            # the decoder's own lines about errors: how many, and the first three
        self.long_lines = 0                        # lines longer than LOG_LINE_MOST, read in pieces
        self.inside, self.inside_done = None, False    # the end of the last piece of a long line not yet ended, and whether that line is judged
        self.bytes_not_read = 0                    # bytes of the log the clock left unread

    @property
    def restarts(self):
        """How many times the decoder's filters were rebuilt, as far as the log shows it."""
        return max(self.rebuilt, self.jumps)

    def _restart(self):
        if self.restart_at is None:
            self.restart_at = self.lines

    def _troubled(self, text):
        """Count `text` as a line about an error when it is one (the input's names taken out first); True when it was counted."""
        for name in self.quiet:
            text = text.replace(name, b"")
        if TROUBLE.search(text):
            self.trouble += 1
            if len(self.said) < 3:
                self.said.append(clean(text))
            return True
        return False

    def _judge(self, line):
        """Read one line (or the first piece of a long one); True when nothing more of it is to be judged."""
        found = SHOWINFO.search(line)
        if found:
            index = self.lines
            self.lines += 1
            if int(found.group(1)) != self.last_n + 1:
                self.jumps += 1
                self._restart()
            self.last_n = int(found.group(1))
            self.seen.add(index)
            if found.group(3) != b"N/A":
                self.times[index] = self.last_time = float(found.group(3))
            size = FRAME_SIZE.search(line)
            if size and (int(size.group(1)), int(size.group(2))) != self.size:
                self.other_size += 1
                if len(self.other_first) < self.keep:
                    self.other_first[index] = "%s x %s" % (size.group(1).decode(), size.group(2).decode())
            return True
        if SHOWINFO_LINE.search(line):
            return True
        named = line
        for name in self.quiet:
            named = named.replace(name, b"")
        if REBUILT.search(named):
            self.rebuilt += 1
            self._restart()
            return True
        return self._troubled(line)

    def read(self, final=False):
        try:
            with open(self.path, "rb") as fh:
                fh.seek(self.at)
                while True:
                    if past_finish():
                        try:
                            self.bytes_not_read = max(self.bytes_not_read, os.fstat(fh.fileno()).st_size - self.at)
                        except OSError:
                            self.bytes_not_read = max(self.bytes_not_read, 1)
                        break
                    line = fh.readline(LOG_LINE_MOST)
                    if not line:
                        break
                    ends = line.endswith(b"\n")
                    if not ends and len(line) < LOG_LINE_MOST and not final:
                        break                      # a line not whole yet: it waits for the next reading
                    self.at += len(line)
                    if self.inside is not None:    # a later piece of a long line
                        if not self.inside_done:
                            self.inside_done = self._troubled(self.inside + line)
                        self.inside = None if ends else line[-LOG_TAIL:]
                        continue
                    done = self._judge(line)
                    if not ends and len(line) >= LOG_LINE_MOST:
                        self.long_lines += 1
                        self.inside, self.inside_done = line[-LOG_TAIL:], done
        except (OSError, ValueError):
            pass
        return self.times


def quiet_names(video):
    """The input's own names as the decoder prints them: taken out of a log line before it is judged as one about an error."""
    target = target_of(video)
    return [os.fsencode("file:" + target), os.fsencode(target), os.fsencode(video)]


def held_after(state):
    """The words on the frames read after the decoder had ended, while a process it left held its pipe."""
    if not state["after_exit"]:
        return ""
    return (" (%d of the frames counted here were read after the decoder had ended, from a pipe a process it left behind still held: up to a pipe's "
            "buffer of them are the decoder's last frames, the rest may not be the decoder's at all)" % state["after_exit"])


def passthrough(ffmpeg):
    """The option that keeps every decoded frame, none dropped or doubled: -fps_mode from ffmpeg 5.1, -vsync before it."""
    _code_, out, _err, _timed_out = preflight([ffmpeg, "-hide_banner", "-version"], seconds_left(PROBE_SECONDS), caps=(1 << 16, 1 << 16))
    found = re.search(rb"ffmpeg version n?(\d+)\.(\d+)", out)
    old = found is not None and (int(found.group(1)), int(found.group(2))) < (5, 1)
    return (["-vsync", "0"] if old else ["-fps_mode", "passthrough"]), (clean(out.split(b"\n")[0], 80) if out else "ffmpeg, version not printed")


def shortfall(info, last_time):
    """Why a whole-stream survey that ended cleanly did not reach the end the container states, and about how many frames that is ((None, 0)
    when it did, or when there is nothing to compare): its last frame's presentation time plus one frame against the stream's start time
    plus its stated duration, with two frames (0.1 second where the rate is unknown) of slack. A container with no frame count (Matroska,
    WebM, an elementary stream) is held to it."""
    if info["duration_said"] is None or last_time is None or info["duration_said"] <= 0:
        return None, 0
    step = 1.0 / info["rate"] if info["rate"] else 0.05
    end = (info["start_said"] or 0.0) + info["duration_said"]
    reached = last_time + step
    if end - reached <= 2 * step + 0.001:
        return None, 0
    return ("the container states a duration of %.3f s (to %.3f s) and the last frame decoded is at %.3f s: %.3f s, about %d frames, were not decoded "
            "(a cut stream the decoder did not report, or a video stream that ends before the file's other streams)" % (
                info["duration_said"], end, last_time, end - reached, int(round((end - reached) / step)))), max(1, int(round((end - reached) / step)))


def stamp(seconds):
    if seconds is None:
        return "-"
    minutes, rest = divmod(max(0.0, seconds), 60)
    return "%d:%05.2f" % (int(minutes), rest)


def block_means(frame, width, height):
    """The mean of each of GRID_COLUMNS x GRID_ROWS blocks of an RGB frame, all channels together (0 to 255)."""
    stride = width * 3
    means = []
    for by in range(GRID_ROWS):
        y0, y1 = by * height // GRID_ROWS, max(by * height // GRID_ROWS + 1, (by + 1) * height // GRID_ROWS)
        sums = [0] * GRID_COLUMNS
        for y in range(y0, y1):
            row = frame[y * stride:(y + 1) * stride]
            for bx in range(GRID_COLUMNS):
                x0, x1 = bx * width // GRID_COLUMNS, max(bx * width // GRID_COLUMNS + 1, (bx + 1) * width // GRID_COLUMNS)
                sums[bx] += sum(row[x0 * 3:x1 * 3])
        for bx in range(GRID_COLUMNS):
            x0, x1 = bx * width // GRID_COLUMNS, max(bx * width // GRID_COLUMNS + 1, (bx + 1) * width // GRID_COLUMNS)
            means.append(sums[bx] / float((x1 - x0) * 3 * (y1 - y0)))
    return means


def tile_size(width, height, tile_width):
    """The tile of a frame: (tile width, tile height, whether it keeps the frame's shape). It fits a box tile_width wide and TILE_BOX_HEIGHT
    tile widths high, each side even and at least 2 pixels: a frame taller than the box is reduced to the box's height and narrowed with
    it, and a side that would come out under 2 pixels is held at 2 (the tile then does not keep the shape)."""
    box_h = TILE_BOX_HEIGHT * tile_width
    tw, th = tile_width, max(2, int(round(height * tile_width / float(width) / 2.0)) * 2)
    if th > box_h:
        th = box_h
        tw = max(2, int(round(width * box_h / float(height) / 2.0)) * 2)
    exact = height * tw / float(width)            # the tile's height had it kept the shape at its width
    return tw, th, abs(th - exact) <= max(1.0, 0.1 * exact)


class Sheets:
    """Contact sheets: tiles left to right, top to bottom, the frame number and its time under each. A cell is the box a tile fits in
    (box_width wide); a tile narrower than its box sits at the box's left."""

    def __init__(self, place, tile_width, tile_height, box_width, columns, rows):
        self.place, self.tw, self.th, self.box, self.columns, self.rows = place, tile_width, tile_height, box_width, columns, rows
        self.scale = 2 if box_width >= 150 else 1
        self.cell_w, self.cell_h = box_width + 4, tile_height + 5 * self.scale + 8
        self.width, self.height = self.cell_w * columns, self.cell_h * rows
        self.names, self.count, self.first = [], 0, None
        self.canvas = None
        self.error, self.failed = None, 0

    def add(self, frame, number, seconds):
        if self.canvas is None:
            self.canvas = [bytearray(b"\x20" * (self.width * 3)) for _ in range(self.height)]
            self.first = number
        slot = self.count % (self.columns * self.rows)
        x0, y0 = (slot % self.columns) * self.cell_w + 2, (slot // self.columns) * self.cell_h + 2
        stride = self.tw * 3
        for y in range(self.th):
            self.canvas[y0 + y][x0 * 3:(x0 + self.tw) * 3] = frame[y * stride:(y + 1) * stride]
        label_width, label = label_rows(("%06d %s" % (number, stamp(seconds)))[:self.box // (4 * self.scale)], self.scale)
        for i, line in enumerate(label):
            self.canvas[y0 + self.th + 3 + i][x0 * 3:(x0 + label_width) * 3] = b"".join(b"\xff\xff\xff" if p else b"\x20\x20\x20" for p in line)
        self.count += 1
        self.last = number
        if self.count % (self.columns * self.rows) == 0:
            self.flush()

    def flush(self):
        if self.canvas is None:
            return
        name = "sheet-%04d.png" % (len(self.names) + 1)
        try:
            shown = self.place.write(name, png_bytes(self.width, self.height, self.canvas, 3))
            self.names.append({"sheet": shown, "first_frame": self.first, "last_frame": self.last})
        except OSError as exc:
            self.failed += 1
            self.error = self.error or "a contact sheet could not be written (%s)" % describe(exc)
        except Clock:
            self.failed += 1
            self.error = self.error or "%s was not written: the clock and the %d seconds an encoder is given past it ran out while it was encoded" % (name, FINISH_SECONDS)
        self.canvas = None


def survey(args, video, info, ffmpeg, common, started):
    every = int_param(args, "every", 1, *RANGES["every"])
    start = int_param(args, "start_frame", 0, *RANGES["start_frame"])
    most = int_param(args, "max_frames", DEFAULT_FRAMES, *RANGES["max_frames"])
    box_width = int_param(args, "tile_width", 160, *RANGES["tile_width"])
    columns = int_param(args, "columns", 10, *RANGES["columns"])
    rows = int_param(args, "rows", 6, *RANGES["rows"])
    window = int_param(args, "window", 10, *RANGES["window"])
    box_width -= box_width % 2
    tile_width, tile_height, keeps_shape = tile_size(info["width"], info["height"], box_width)
    sheet_bytes = (box_width + 4) * columns * (tile_height + 18) * rows * 3
    if sheet_bytes > MAX_SHEET_BYTES:
        raise Refused("a sheet of %d x %d tiles of %d x %d pixels is %d bytes, over the %d this tool holds at once: ask fewer columns or rows, or a smaller tile_width"
                      % (columns, rows, tile_width, tile_height, sheet_bytes, MAX_SHEET_BYTES))
    place = Place("frame_survey")
    stderr_path = os.path.join(place.path, ".decoder.log")
    temp_hold(stderr_path)
    select = "select='gte(n\\,%d)*not(mod(n-%d\\,%d))'" % (start, start, every)
    keep_every_frame, decoder_version = passthrough(ffmpeg)
    common["decoder"]["version"] = decoder_version
    # -reinit_filter 0: a frame of another size or format goes through the same filters (scale takes it as it comes), so that the select
    # filter's count, which picks the frames, is never started again by a rebuild of the filters; a rebuild that happens anyway is counted.
    argv = [ffmpeg, "-nostdin", "-hide_banner", "-nostats", "-loglevel", "info", *([] if info["autorotate"] else ["-noautorotate"]), "-reinit_filter", "0",
            *input_options(info), "-i", "file:" + target_of(video),
            "-map", "0:v:0", "-an", "-sn", "-vf", "%s,showinfo,scale=%d:%d:flags=area,setsar=1" % (select, tile_width, tile_height), *keep_every_frame,
            "-pix_fmt", "rgb24", "-f", "rawvideo", "pipe:1"]
    sheets = Sheets(place, tile_width, tile_height, box_width, columns, rows)
    blocks = GRID_COLUMNS * GRID_ROWS
    rate = info["rate"]
    pending = []                      # frames waiting for their time (the showinfo line is written a moment before the frame)
    changes = []                      # per decoded frame: (frame number, blocks changed, their box)
    previous = [None]
    kept_frames = [0]

    def on_frame(frame):
        if kept_frames[0] >= most:
            return False              # a frame past max_frames: the cap is reached only when there is one, and it is not kept
        number = start + kept_frames[0] * every
        means = block_means(frame, tile_width, tile_height)
        changed, box = 0, None
        if previous[0] is not None:
            last = previous[0]
            for index in range(blocks):
                if abs(means[index] - last[index]) > BLOCK_STEP:
                    changed += 1
                    bx, by = index % GRID_COLUMNS, index // GRID_COLUMNS
                    box = (bx, by, bx, by) if box is None else (min(box[0], bx), min(box[1], by), max(box[2], bx), max(box[3], by))
        previous[0] = means
        changes.append((number, changed, box))
        pending.append((frame, number, kept_frames[0]))
        kept_frames[0] += 1
        if len(pending) >= 30:
            drain()
        return True

    log_times = LogTimes(stderr_path, (info["width"], info["height"]), quiet_names(video))
    times = log_times.times

    def drain():
        log_times.read()
        for frame, number, index in pending:
            sheets.add(frame, number, times.get(index, number / rate if rate else None))
        del pending[:]

    try:
        with open(stderr_path, "wb") as log:
            state = stream_frames(argv, tile_width * tile_height * 3, on_frame, log)
    except OSError as exc:
        temp_drop(stderr_path)
        raise Refused("the decoder could not be started (%s)" % describe(exc))
    drain()
    sheets.flush()
    log_times.read(final=True)
    errors = log_times.said
    temp_drop(stderr_path)
    decoded = kept_frames[0]
    timed = sum(1 for i in range(decoded) if i in times)
    unread = Unread("frames_before_start_frame", "frames_between_samples", "stream_after_max_frames", "stream_after_the_clock",
                    "pipe_held_after_the_decoder", "decoder_exit_not_zero", "decoder_error_lines", "decoder_log_bytes_not_read",
                    "frames_without_their_log_line", "bytes_after_the_last_whole_frame", "sheets_not_written", "frames_of_another_size",
                    "frames_numbered_after_a_rebuild", "frames_the_container_lists_not_decoded", "frames_short_of_the_stated_duration",
                    "local_changes_not_paired", "score_tables_not_written")
    skipped = []
    if every > 1:
        skipped.append("%d of every %d frames between the samples (every: %d): a run shorter than %d frames can fall between two samples" % (every - 1, every, every, every))
        unread.add("frames_between_samples", max(1, (decoded - 1) * (every - 1)), "not decoded: " + skipped[-1])
    if start:
        skipped.append("the %d frames before start_frame" % start)
        unread.add("frames_before_start_frame", start, "not decoded: " + skipped[-1])
    if state["stopped"] == "enough":
        skipped.append("every frame after frame %d (max_frames %d was reached): go on with start_frame %d" % (start + (decoded - 1) * every, most, start + decoded * every))
        unread.add("stream_after_max_frames", 1, "not decoded: " + skipped[-1])
    if state["stopped"] == "clock":
        skipped.append("every frame after frame %d (the tool's clock ran out): go on with start_frame %d" % (start + (decoded - 1) * every if decoded else start, start + decoded * every))
        unread.add("stream_after_the_clock", 1, "not decoded: " + skipped[-1])
    if state["stopped"] == "pipe held":
        unread.add("pipe_held_after_the_decoder", 1, "the decoder ended but something it started kept its output pipe open: the end of the stream was not seen%s" % held_after(state))
    if state["stopped"] is None and state["exit"] != 0:
        unread.add("decoder_exit_not_zero", 1, "the decoder ended with exit code %s after %d frames: the stream is damaged or cut there, and what follows was not decoded" % (state["exit"], decoded))
    unread.add("decoder_error_lines", log_times.trouble, "the decoder wrote %d line(s) about errors while it decoded (decoder_said has the first): frames near them may be damaged, concealed or missing" % log_times.trouble)
    unread.add("decoder_log_bytes_not_read", log_times.bytes_not_read, "%d bytes of the decoder's log were not read (the clock ran out): a line about an error, a frame's time or its size may be among them" % log_times.bytes_not_read)
    if log_times.lines < decoded:
        unread.add("frames_without_their_log_line", decoded - log_times.lines,
                   "the decoder's own line (showinfo) was read for %d of the %d frames: the time, the size and the order of the other %d were not confirmed, "
                   "and a line about an error may be among what was not read" % (log_times.lines, decoded, decoded - log_times.lines))
    if state["stopped"] is None:
        unread.add("bytes_after_the_last_whole_frame", state["left"], "the decoder's output ended inside a frame (%d bytes over)" % state["left"])
    unread.add("sheets_not_written", sheets.failed, sheets.error)
    unread.add("frames_of_another_size", log_times.other_size,
               "%d frame(s) were decoded at another size than the stream's %d x %d (frames_of_another_size): their tiles are scaled to the same "
               "tile, and a region in native pixels over them is of the stream's size, not theirs" % (log_times.other_size, info["width"], info["height"]))
    if log_times.restarts and (start or every > 1) and log_times.restart_at < decoded:
        unread.add("frames_numbered_after_a_rebuild", decoded - log_times.restart_at,
                   "the decoder rebuilt its filters %d time(s), the first after %d frame(s) given here, and its select filter's count started again "
                   "there: the frame numbers from frame %d on (numbers_unconfirmed_from) are not confirmed to be decoded frames' numbers; survey from "
                   "start_frame 0 with every 1, where every frame is counted here" % (log_times.restarts, log_times.restart_at, start + log_times.restart_at * every))
    whole_call = start == 0 and every == 1 and state["stopped"] is None and state["exit"] == 0
    if whole_call and info["frames_said"] and decoded < info["frames_said"]:
        unread.add("frames_the_container_lists_not_decoded", info["frames_said"] - decoded,
                   "the container lists %d frames and the decoder gave %d with no error: %d were not decoded (dropped by the decoder, or outside an "
                   "edit list), so the frames here are not every frame the file holds" % (info["frames_said"], decoded, info["frames_said"] - decoded))
    short, short_frames = shortfall(info, log_times.last_time) if whole_call and decoded else (None, 0)
    unread.add("frames_short_of_the_stated_duration", short_frames, short)
    # The change scores. A frame's score is the share of blocks that changed from the frame before it. A cut changes most of the picture;
    # a local change (a caption, an overlay) changes a few blocks and, when it ends, changes the same blocks again.
    scores = [c[1] / float(blocks) for c in changes]
    ordered = sorted(scores[1:]) or [0.0]
    median = ordered[len(ordered) // 2]
    spread = sorted(abs(s - median) for s in scores[1:])[len(ordered) // 2] if len(scores) > 1 else 0.0
    floor = max(median + 6 * spread, median * 3, 2.0 / blocks)
    cuts = [changes[i][0] for i in range(1, len(changes)) if scores[i] >= 0.5]
    local = [i for i in range(1, len(changes)) if floor <= scores[i] < 0.5 and scores[i] > 0]
    next_cut, upcoming = [len(changes)] * (len(changes) + 1), len(changes)
    for i in range(len(changes) - 1, -1, -1):
        next_cut[i] = upcoming                      # the first cut after frame i
        if scores[i] >= 0.5:
            upcoming = i
    runs, used = [], set()
    pairing_until = time.monotonic() + 10           # the pairing has a clock of its own, after the decoder's
    for a_pos, a in enumerate(local):
        if a in used:
            continue
        if time.monotonic() > pairing_until:
            unread.add("local_changes_not_paired", len(local) - a_pos, "the local changes after frame %d were not paired into runs (the pairing's own 10 seconds ran out): they are in frames.tsv" % changes[a][0])
            break
        box_a = changes[a][2]
        for b in local[a_pos + 1:a_pos + 1 + 400]:
            if b - a > 2000 or next_cut[a] < b:
                break
            if b in used:
                continue
            box_b = changes[b][2]
            overlap_w = min(box_a[2], box_b[2]) - max(box_a[0], box_b[0]) + 1
            overlap_h = min(box_a[3], box_b[3]) - max(box_a[1], box_b[1]) + 1
            if overlap_w <= 0 or overlap_h <= 0:
                continue
            area_a = (box_a[2] - box_a[0] + 1) * (box_a[3] - box_a[1] + 1)
            area_b = (box_b[2] - box_b[0] + 1) * (box_b[3] - box_b[1] + 1)
            if overlap_w * overlap_h * 2 < max(area_a, area_b):
                continue
            used.update((a, b))
            first, last = changes[a][0], changes[b - 1][0]
            px = lambda bx: bx * info["width"] // GRID_COLUMNS
            py = lambda by: by * info["height"] // GRID_ROWS
            runs.append({"first_frame": first, "last_frame": last, "frames_decoded_in_run": b - a,
                         "first_time": stamp(times.get(a, first / rate if rate else None)), "last_time": stamp(times.get(b - 1, last / rate if rate else None)),
                         "blocks_changed_at_start": changes[a][1], "blocks_changed_at_end": changes[b][1], "of_blocks": blocks,
                         "region_native_pixels": [px(min(box_a[0], box_b[0])), py(min(box_a[1], box_b[1])), px(max(box_a[2], box_b[2]) + 1), py(max(box_a[3], box_b[3]) + 1)],
                         "sheets": [s["sheet"] for s in sheets.names if s["first_frame"] <= last and s["last_frame"] >= first][:6],
                         "what": "one region changed at the first frame and changed again at the frame after the last, with no cut between: a candidate for a caption, an overlay or an inserted stretch"})
            break
    unpaired = [changes[i][0] for i in local if i not in used]
    windows = []
    for at in range(0, len(changes), window):
        part = scores[at:at + window]
        windows.append((changes[at][0], changes[min(len(changes), at + window) - 1][0], max(part), sum(part) / len(part)))
    window_scores = sorted(w[2] for w in windows) or [0.0]
    window_median = window_scores[len(window_scores) // 2]
    files = {}
    try:
        files["windows"] = place.write("windows.tsv", (("first_frame\tlast_frame\tmax_share_of_blocks_changed\tmean_share_of_blocks_changed\n").encode("ascii"),
                                                       *(("%d\t%d\t%.4f\t%.4f\n" % w).encode("ascii") for w in windows)))
        files["frames"] = place.write("frames.tsv", (b"frame\ttime_s\ttime_from\tshare_of_blocks_changed\n",
                                                     *(("%d\t%s\t%s\t%.4f\n" % (changes[i][0], ("%.6f" % times[i]) if i in times else ("%.6f" % (changes[i][0] / rate) if rate else ""),
                                                                               "the frame's presentation time" if i in times else "frame / rate" if rate else "", scores[i])).encode("ascii") for i in range(len(changes)))))
    except OSError as exc:
        files["write_error"] = "a score table could not be written (%s)" % describe(exc)
        unread.add("score_tables_not_written", 1, "a score table could not be written")
    stand_out = sorted((w for w in windows if w[2] >= floor and w[2] > window_median), key=lambda w: -w[2])[:20]
    reasons = unread.reasons()
    status = "failed" if decoded == 0 else "partial" if unread else "complete"
    answer = {**common, "mode": "survey", "status": status, "complete": status == "complete", "not_read_or_judged": dict(unread.counts),
              "frames_decoded": decoded, "frames_the_container_says": info["frames_said"], "first_frame": start, "last_frame": start + (decoded - 1) * every if decoded else None,
              "every": every, "tile": "%d x %d" % (tile_width, tile_height), "tile_keeps_shape": keeps_shape, "sheets": len(sheets.names), "sheet_files": sheets.names[:40], "tiles_a_sheet": columns * rows,
              "times": {"from_the_frames_own_presentation_time": timed, "from_frame_over_rate": decoded - timed, "rate": rate},
              "decoder_log": {"frame_lines_read": log_times.lines, "lines_over_%d_bytes" % LOG_LINE_MOST: log_times.long_lines,
                              "what": "the decoder's own line a frame (showinfo) gives its time and size; a line longer than %d bytes is judged in pieces, all of it" % LOG_LINE_MOST},
              "scores": {"what": "a frame's score is the share of %d x %d blocks whose mean moved by more than %d of 255 from the frame decoded before it" % (GRID_COLUMNS, GRID_ROWS, BLOCK_STEP),
                         "median": round(median, 4), "stands_out_from": round(floor, 4), "window_frames": window, "windows": len(windows)},
              "scene_cuts": {"count": len(cuts), "frames": cuts[:50], "what": "half of the blocks or more changed at once"},
              "runs": runs[:50], "runs_total": len(runs),
              "local_changes_without_a_partner": {"count": len(unpaired), "frames": unpaired[:50], "what": "a local change with no matching change among the next 400 local changes, within 2000 decoded frames and before the next cut"},
              "windows_that_stand_out": [{"first_frame": w[0], "last_frame": w[1], "max_share_of_blocks_changed": round(w[2], 4)} for w in stand_out],
              "files": files, "output_directory": place.shown, **({"decoder_said": errors} if errors else {}), **turned(info)}
    if not keeps_shape:
        answer["tile_note"] = ("a frame of %d x %d does not fit a tile %d wide and at most %d high with its shape: its tile is %d x %d, stretched, and a "
                               "region read off it is of that stretched copy (region_native_pixels is of the frame)" % (info["width"], info["height"], box_width,
                                                                                                                       TILE_BOX_HEIGHT * box_width, tile_width, tile_height))
    if log_times.restarts and (start or every > 1) and log_times.restart_at < decoded:
        answer["numbers_unconfirmed_from"] = start + log_times.restart_at * every
    if log_times.other_size:
        answer["frames_of_another_size"] = {"count": log_times.other_size, "first": [{"frame": start + i * every, "size": v} for i, v in sorted(log_times.other_first.items())],
                                            "what": "frames the decoder gave at another size than the stream's %d x %d (the stream changes size there): their tiles are scaled to the same tile, and a region in native pixels is of the stream's size" % (info["width"], info["height"])}
    if len(sheets.names) > 40:
        answer["sheet_files_more"] = "%d sheets in all, sheet-0001.png to sheet-%04d.png, %d tiles each in frame order" % (len(sheets.names), len(sheets.names), columns * rows)
    if skipped:
        answer["skipped"] = skipped
    if reasons:
        answer["partial_reasons"] = reasons
    answer["status_basis"] = ("no frame was decoded: %s" % ("; ".join(reasons) or "the decoder wrote none") if decoded == 0 else
                              "every frame the decoder gave of the first video stream was tiled and scored: %d frames on %d sheets, the decoder ended cleanly at the end of the stream" % (decoded, len(sheets.names))
                              if status == "complete" else
                              "%d frames were tiled and scored, but not the whole stream: %s" % (decoded, "; ".join(reasons)))
    if status == "complete" and info["frames_said"] and info["frames_said"] != decoded:
        answer["status_basis"] += " (the container's own count is %d: the decoder's count is what was read)" % info["frames_said"]
    return answer, place


def extract(args, video, info, ffmpeg, common):
    first = int_param(args, "first", None, *RANGES["first"])
    last = int_param(args, "last", None, *RANGES["last"])
    if first is None:
        raise Refused("mode extract takes first (and last): frame numbers as the survey prints them. " + RULES[2])
    last = first if last is None else last
    if last < first or last - first + 1 > MAX_EXTRACT:
        raise Refused("last must be from first to first + %d: at most %d frames a call at native size" % (MAX_EXTRACT - 1, MAX_EXTRACT))
    width, height = info["width"], info["height"]
    place = Place("frame_survey")
    stderr_path = os.path.join(place.path, ".decoder.log")
    temp_hold(stderr_path)
    keep_every_frame, decoder_version = passthrough(ffmpeg)
    common["decoder"]["version"] = decoder_version
    # The frame's own size is read from showinfo, before the scale: a frame of the stream's size passes the scale untouched (the same bytes
    # as without it), and one of another size (a stream that changes size, a turn the probe did not foresee) comes out at the size the
    # frames are cut at, never misaligned, and is named. setsar only sets the aspect the raw output does not carry, so that the encoder
    # writes no line about it.
    # -reinit_filter 0 keeps one set of filters for the whole stream (see survey): select's count is the decoded frame's number.
    argv = [ffmpeg, "-nostdin", "-hide_banner", "-nostats", "-loglevel", "info", *([] if info["autorotate"] else ["-noautorotate"]), "-reinit_filter", "0",
            *input_options(info), "-i", "file:" + target_of(video),
            "-map", "0:v:0", "-an", "-sn", "-vf", "select='between(n\\,%d\\,%d)',showinfo,scale=%d:%d,setsar=1" % (first, last, width, height), *keep_every_frame,
            "-pix_fmt", "rgb24", "-f", "rawvideo", "pipe:1"]
    written, total, problem = [], [0], [None]
    stride = width * 3

    def on_frame(frame):
        number = first + len(written)
        try:
            data = png_bytes(width, height, (frame[y * stride:(y + 1) * stride] for y in range(height)), 3)
            written.append({"frame": number, "file": place.write("frame-%06d.png" % number, data), "bytes": len(data), "sha256": hashlib.sha256(data).hexdigest()})
            total[0] += len(data)
        except OSError as exc:
            problem[0] = "a frame could not be written (%s)" % describe(exc)
            return False
        except Clock:
            problem[0] = "frame %d was not written: the clock and the %d seconds an encoder is given past it ran out while it was encoded" % (number, FINISH_SECONDS)
            return False
        if total[0] > MAX_EXTRACT_BYTES:
            problem[0] = "the frames written passed %d bytes" % MAX_EXTRACT_BYTES
            return False
        return len(written) < last - first + 1

    try:
        with open(stderr_path, "wb") as log:
            state = stream_frames(argv, width * height * 3, on_frame, log)
    except OSError as exc:
        temp_drop(stderr_path)
        raise Refused("the decoder could not be started (%s)" % describe(exc))
    log_times = LogTimes(stderr_path, (width, height), quiet_names(video), MAX_EXTRACT)
    times = log_times.read(final=True)
    temp_drop(stderr_path)
    dropped, rebuilt = 0, None
    if log_times.restarts and log_times.restart_at < len(written):
        # The select filter's count started again with a rebuild: a frame it gave after the rebuild is not known to be the decoded frame its
        # number names, so none of those is kept under a number that may not be its own (the frames before the rebuild were counted whole).
        doubtful = written[log_times.restart_at:]
        for row in doubtful:
            dropped += place.remove(os.path.basename(row["file"]))
        rebuilt = ("the decoder rebuilt its filters %d time(s) (the stream changes size or format) and the count that picks frames started again "
                   "with it: the %d frame(s) it gave after that cannot be numbered, and %d were removed%s" % (
                       log_times.restarts, len(doubtful), dropped, "" if dropped == len(doubtful) else " (the others could not be: do not cite them)"))
        written = written[:log_times.restart_at]
    unconfirmed = []
    for index, row in enumerate(written):
        seconds = times.get(index, row["frame"] / info["rate"] if info["rate"] else None)
        row["time"] = stamp(seconds)
        row["time_from"] = "the frame's presentation time" if index in times else "frame / rate" if info["rate"] else "unknown"
        if index in log_times.other_first:
            row["native"] = False
            row["decoded_size"] = log_times.other_first[index]
        elif index not in log_times.seen:
            unconfirmed.append(row["frame"])
    wanted = last - first + 1
    unread = Unread("frames_dropped_after_a_rebuild", "frames_not_written", "frames_after_the_clock", "pipe_held_after_the_decoder",
                    "decoder_exit_not_zero", "decoder_error_lines", "decoder_log_bytes_not_read", "frames_of_another_size",
                    "frames_size_not_confirmed", "bytes_after_the_last_whole_frame", "frames_the_stream_did_not_give")
    if rebuilt:
        unread.add("frames_dropped_after_a_rebuild", max(1, len(doubtful)), rebuilt)
    if problem[0]:
        unread.add("frames_not_written", max(1, wanted - len(written)), problem[0])
    if state["stopped"] == "clock":
        unread.add("frames_after_the_clock", max(1, wanted - len(written)), "the tool's clock ran out after %d of %d frames" % (len(written), wanted))
    if state["stopped"] == "pipe held":
        unread.add("pipe_held_after_the_decoder", 1, "the decoder ended but something it started kept its output pipe open%s" % held_after(state))
    if state["stopped"] is None and state["exit"] != 0:
        unread.add("decoder_exit_not_zero", 1, "the decoder ended with exit code %s after %d of the frames asked for: the stream is damaged or cut there" % (state["exit"], len(written)))
    unread.add("decoder_error_lines", log_times.trouble, "the decoder wrote %d line(s) about errors while it decoded: a frame written here may be damaged or concealed" % log_times.trouble)
    unread.add("decoder_log_bytes_not_read", log_times.bytes_not_read, "%d bytes of the decoder's log were not read (the clock ran out): a line about an error or a frame's size may be among them" % log_times.bytes_not_read)
    unread.add("frames_of_another_size", log_times.other_size,
               "%d frame(s) were decoded at another size than the stream's %d x %d and were scaled to it, so they are not at native size (native: false, "
               "decoded_size on each)" % (log_times.other_size, width, height))
    if unconfirmed:
        unread.add("frames_size_not_confirmed", len(unconfirmed), "the decoder's own line for %d frame(s) (the first %d) was not read: their size was not confirmed" % (len(unconfirmed), unconfirmed[0]))
    if state["stopped"] is None:
        unread.add("bytes_after_the_last_whole_frame", state["left"], "the decoder's output ended inside a frame (%d bytes over)" % state["left"])
    if len(written) < wanted and not unread:
        unread.add("frames_the_stream_did_not_give", wanted - len(written), "the stream gave %d of the %d frames asked for: it ends at frame %d, or is damaged there" % (len(written), wanted, first + len(written) - 1))
    reasons = unread.reasons()
    status = "failed" if not written else "partial" if unread else "complete"
    answer = {**common, "mode": "extract", "status": status, "complete": status == "complete", "not_read_or_judged": dict(unread.counts), "first": first, "last": last, "frames_written": len(written),
              "size": "%d x %d (native)" % (width, height), "frames": written[:MAX_EXTRACT], "output_directory": place.shown, **turned(info),
              "status_basis": ("every frame asked for (%d to %d) was decoded and written at native size as a PNG, each frame's size confirmed by the decoder's own line"
                               % (first, last)) if status == "complete" else
                              "%d of %d frames were written: %s" % (len(written), wanted, "; ".join(reasons))}
    if problem[0] and "could not be written" in problem[0]:
        answer["write_error"] = problem[0]
    if reasons:
        answer["partial_reasons"] = reasons
    return answer, place


def mp4_boxes(fd, size):
    """The top-level boxes of an ISO media file: [(type, offset, size said, size in the file)], and what is wrong with the walk."""
    boxes, offset, problem = [], 0, None
    while offset + 8 <= size and len(boxes) < 10000:
        tick()
        head = os.pread(fd, 16, offset)
        length, kind = struct.unpack(">I4s", head[:8])
        if length == 1 and len(head) == 16:
            length = struct.unpack(">Q", head[8:16])[0]
            minimum = 16
        elif length == 0:
            length, minimum = size - offset, 8
        else:
            minimum = 8
        if length < minimum or not all(32 <= b < 127 for b in kind):
            problem = "at offset %d the bytes are no box header: the box walk stops there" % offset
            break
        boxes.append((kind.decode("ascii"), offset, length, min(length, size - offset)))
        offset += length
    if problem is None and offset < size and len(boxes) < 10000:
        problem = "%d bytes after the last box are no box" % (size - offset)
    if problem is None and offset < size:
        problem = "the walk stopped at its bound of 10000 top-level boxes, at offset %d: the %d bytes after it were not walked" % (offset, size - offset)
    return boxes, problem


def diagnose(fd, size):
    """What the container itself says is wrong, read without a decoder: {container, findings, boxes | chunks}."""
    head = os.pread(fd, 16, 0)
    if head[4:8] in (b"ftyp", b"moov", b"mdat", b"free", b"skip", b"wide", b"moof", b"styp"):
        boxes, problem = mp4_boxes(fd, size)
        kinds = [b[0] for b in boxes]
        findings = []
        if "moov" not in kinds:
            findings.append({"finding": "moov missing", "what": "the file has no moov box (the sample tables and the codec's configuration): a recording that was not closed, or a file cut before its end"})
        elif "mdat" in kinds and kinds.index("moov") > kinds.index("mdat"):
            findings.append({"finding": "moov at end", "what": "the moov box follows the media data: a whole file, but one a player cannot start before it has all of it"})
        for kind, offset, said, held in boxes:
            if held < said:
                findings.append({"finding": "%s cut" % kind, "what": "the %s box at offset %d says %d bytes and the file holds %d of them" % (kind, offset, said, held)})
        if "moof" in kinds:
            findings.append({"finding": "fragmented", "what": "the file is fragmented (moof boxes): each fragment carries its own tables"})
        if problem:
            findings.append({"finding": "box walk stopped", "what": problem})
        return {"container": "ISO media (MP4, MOV, 3GP)", "findings": findings, "boxes": [{"type": b[0], "offset": b[1], "size_said": b[2], "size_in_file": b[3]} for b in boxes[:50]]}
    if head[:4] == b"RIFF" and head[8:12] == b"AVI ":
        said = struct.unpack("<I", head[4:8])[0] + 8
        findings, chunks, offset, movi, index = [], [], 12, None, None
        if said > size:
            findings.append({"finding": "RIFF cut", "what": "the RIFF header says %d bytes and the file holds %d" % (said, size)})
        while offset + 8 <= size and len(chunks) < 10000:
            tick()
            chunk = os.pread(fd, 12, offset)
            kind, length = chunk[:4], struct.unpack("<I", chunk[4:8])[0]
            name = kind.decode("latin-1") + (":" + chunk[8:12].decode("latin-1") if kind == b"LIST" and len(chunk) == 12 else "")
            name = "".join(ch if " " <= ch < "\x7f" else "?" for ch in name)
            chunks.append({"chunk": name, "offset": offset, "size_said": length, "size_in_file": min(length, size - offset - 8)})
            if name == "LIST:movi":
                movi = chunks[-1]
            if kind == b"idx1":
                index = chunks[-1]
            offset += 8 + length + (length & 1)
        if offset + 8 <= size:
            findings.append({"finding": "chunk walk stopped", "what": "the walk stopped at its bound of 10000 top-level chunks, at offset %d: the %d bytes after it were not walked" % (offset, size - offset)})
        if movi is None:
            findings.append({"finding": "movi missing", "what": "no movi list (the frames) was found among the top-level chunks"})
        elif movi["size_in_file"] < movi["size_said"]:
            findings.append({"finding": "movi cut", "what": "the movi list says %d bytes and the file holds %d of them" % (movi["size_said"], movi["size_in_file"])})
        if index is None:
            findings.append({"finding": "index missing", "what": "no idx1 chunk follows the movi list (an OpenDML file keeps its index elsewhere: then this is no fault)"})
        elif index["size_in_file"] < index["size_said"] or index["size_said"] % 16:
            findings.append({"finding": "index broken", "what": "the idx1 chunk says %d bytes, holds %d, and an index is rows of 16 bytes" % (index["size_said"], index["size_in_file"])})
        return {"container": "AVI (RIFF)", "findings": findings, "chunks": chunks[:50]}
    return {"container": None, "findings": [{"finding": "not an MP4 or an AVI", "what": "the first bytes are neither an ISO media box nor a RIFF AVI header: this mode repairs those two containers only"}]}


def first_lines(data, keep=3):
    """The first `keep` lines of a program's output that hold anything, cleaned, and how many lines follow them: the output is not split
    whole (a decoder can write a line a frame)."""
    kept, at = [], 0
    while at < len(data) and len(kept) < keep:
        end = data.find(b"\n", at)
        end = len(data) if end < 0 else end
        if data[at:end].strip():
            kept.append(clean(data[at:min(end, at + 4096)]))
        at = end + 1
    return kept, (data.count(b"\n", at) + (1 if at < len(data) and not data.endswith(b"\n") else 0)) if at < len(data) else 0


def count_decoded(ffmpeg, path):
    """How many frames of the first video stream decode, and how the decoder ended: (frames, exit, first error lines, error lines in all, cut).
    The frames are decoded to nothing; the count is read from the decoder's own progress report (its last frame= line). `cut` is None, or the
    sentence of an output that passed its cap: the decoder was ended there, its exit is None and the count is the frames it reached by then."""
    code, out, err, timed_out = preflight([ffmpeg, "-nostdin", "-hide_banner", "-loglevel", "error", "-max_pixels", str(MAX_PIXELS), "-i", "file:" + target_of(path),
                                           "-map", "0:v:0", "-an", "-sn", "-f", "null", "-progress", "pipe:1", "-"], seconds_left(MAX_SECONDS))
    frames = None
    found = re.findall(rb"(?:^|\n)frame=([^\n]*)", out[-65536:])
    if found:
        try:
            frames = int(found[-1].strip())
        except ValueError:
            frames = None
    lines, more = first_lines(err)
    cut = output_cut(out, err)
    return frames, (None if timed_out or cut else code), lines, len(lines) + more, cut


def repair(video, ffmpeg, ffprobe, common, size):
    fd = os.open(video, os.O_RDONLY | getattr(os, "O_NONBLOCK", 0))
    try:
        found = diagnose(fd, size)
    finally:
        os.close(fd)
    answer = {**common, "mode": "repair", "diagnosis": found}
    if found["container"] is None:
        answer.update({"status": "failed", "error": found["findings"][0]["what"], "status_basis": "the file is neither an MP4 nor an AVI by its first bytes: nothing was repaired"})
        return answer, None
    names = [f["finding"] for f in found["findings"]]
    if ffmpeg is None:
        answer.update({"status": "failed", "error": common.get("decoder_missing"),
                       "status_basis": "the container was read (diagnosis) but nothing was repaired or verified: " + (common.get("decoder_missing") or "no decoder")})
        return answer, None
    # A name ffmpeg's picture-sequence demuxer takes (a printf pattern and a picture extension) would be read as other files, or as a
    # picture: the repair reads the file it names or nothing.
    _code, form_out, _err, _timed_out = preflight([ffprobe, "-v", "error", "-pattern_type", "none", "-show_entries", "format=format_name", "-of", "json",
                                                   "-i", "file:" + target_of(video)], seconds_left(PROBE_SECONDS), caps=(1 << 20, 1 << 20))
    if output_cut(form_out, _err):
        answer.update({"status": "failed", "error": "ffprobe's output was not read whole: %s" % output_cut(form_out, _err),
                       "status_basis": "the container was read (diagnosis) but nothing was repaired: the format ffmpeg reads the file as could not be read (ffprobe printed past its cap)"})
        return answer, None
    try:
        form = (json.loads(form_out.decode("utf-8", "replace")).get("format") or {}).get("format_name")
    except (ValueError, AttributeError, RecursionError):
        form = None
    if picture_reader(form):
        answer.update({"status": "failed", "error": "ffmpeg reads this file as a picture by its name (a printf pattern such as %d with a picture extension)",
                       "status_basis": "the container was read (diagnosis) but nothing was repaired: ffmpeg takes the file's name as a picture or a numbered "
                                       "sequence of pictures, not as the %s it holds; copy it under a name without %% and a picture extension" % found["container"]})
        return answer, None
    before_frames, before_exit, before_errors, before_lines, before_cut = count_decoded(ffmpeg, video)
    answer["original"] = {"frames_that_decode": before_frames, "decoder_exit": before_exit, "decoder_said": before_errors[:3], "decoder_lines": before_lines}
    if before_cut:
        answer["original"]["output_cut"] = before_cut      # the count is the frames the decoder reached before it was ended at the cap
    if "moov missing" in names:
        answer.update({"status": "failed", "rebuilt": [], "could_not": ["the moov box: its sample tables and codec configuration are not in the file, and this tool does not rebuild them from the media data. "
                                                                           "A second, whole file from the same recorder and settings supplies them to a repair program that takes a reference file; none is run here"],
                       "status_basis": "the file has no moov box and %s frames of it decode as it is: no repaired copy was written" % (
                           ("at least %s (the decoder's output passed its cap and it was ended there)" % (before_frames or 0)) if before_cut else "no" if not before_frames else before_frames)})
        return answer, None
    place = Place("frame_survey")
    suffix = ".avi" if found["container"].startswith("AVI") else ".mp4"
    out_name = "repaired" + suffix
    out_path = os.path.join(place.path, out_name)
    temp_hold(out_path)
    argv = [ffmpeg, "-nostdin", "-hide_banner", "-loglevel", "error", "-n", "-err_detect", "ignore_err", "-fflags", "+genpts", "-i", "file:" + target_of(video),
            "-map", "0", "-c", "copy"] + (["-movflags", "+faststart"] if suffix == ".mp4" else []) + ["file:" + target_of(out_path)]
    code, _out, err, timed_out = preflight(argv, seconds_left(MAX_SECONDS))
    said, _more = first_lines(err)
    remux_cut = output_cut(_out, err)
    if timed_out or remux_cut or not os.path.isfile(out_path) or os.path.islink(out_path) or os.path.getsize(out_path) == 0:
        temp_drop(out_path)
        answer.update({"status": "failed", "rebuilt": [], "could_not": ["a remuxed copy: the decoder's remux %s" % (
                           "was ended at the clock" if timed_out else "was ended when its output passed its cap (%s)" % remux_cut if remux_cut else "wrote nothing (exit %s)" % code)],
                       "decoder_said": said, "output_directory": place.shown,
                       "status_basis": "no repaired copy was written: the remux %s" % ("did not finish in time" if timed_out else "was ended at its output cap" if remux_cut else "failed")})
        return answer, place
    temp_done(out_path)
    after_frames, after_exit, after_errors, after_lines, after_cut = count_decoded(ffmpeg, out_path)
    with open(out_path, "rb") as fh:
        digest = hashlib.sha256()
        for block in iter(lambda: fh.read(1 << 20), b""):
            tick()
            digest.update(block)
    rebuilt, could_not = [], []
    if suffix == ".mp4":
        rebuilt.append("the moov box, written again in front of the media data from the samples the demuxer read (a remux with the streams copied, no frame re-encoded)")
        if any(n.endswith(" cut") for n in names):
            could_not.append("the samples that lay past the end of the file: the copy holds the samples that were whole, and its tables name only those")
    else:
        rebuilt.append("the index (idx1) and the RIFF sizes, written again from the chunks the demuxer read in order (a remux with the streams copied, no frame re-encoded)")
        if "movi cut" in names or "RIFF cut" in names:
            could_not.append("the chunks that lay past the end of the file")
    verified = after_frames is not None and after_frames > 0
    unread = Unread("copy_decoder_exit_not_zero", "copy_decoder_error_lines", "remux_exit_not_zero", "container_not_walked", "decoder_output_cut")
    unread.add("decoder_output_cut", sum(1 for cut in (before_cut, after_cut) if cut),
               "the decoder's output passed its cap and it was ended there, so a count of frames is the frames it reached by then (%s)" % (after_cut or before_cut))
    if verified and after_exit != 0 and not after_cut:
        unread.add("copy_decoder_exit_not_zero", 1, "the repaired copy decodes %d frames and the decoder then %s" % (
            after_frames, "did not finish in the time it was given" if after_exit is None else "ended with exit code %s" % after_exit))
    if verified:
        unread.add("copy_decoder_error_lines", after_lines, "the decoder wrote %d line(s) about errors while it decoded the repaired copy (repaired.decoder_said has the first)" % after_lines)
    if code != 0:
        unread.add("remux_exit_not_zero", 1, "the remux ended with exit code %s" % code)
    unread.add("container_not_walked", sum(1 for f in found["findings"] if "its bound of 10000" in f["what"]),
               "the container's own walk (diagnosis) stopped before its end: what lies after it was not diagnosed")
    reasons = unread.reasons()
    status = "failed" if not verified else "partial" if unread else "complete"
    answer.update({"status": status, "complete": status == "complete", "not_read_or_judged": dict(unread.counts), "rebuilt": rebuilt, "could_not": could_not,
                   "repaired": {"file": "%s/%s" % (place.shown, out_name), "bytes": os.path.getsize(out_path), "sha256": digest.hexdigest(),
                                "frames_that_decode": after_frames, "decoder_exit": after_exit, "decoder_said": after_errors[:3], "decoder_lines": after_lines},
                   "verified_by": "decoding the repaired copy's first video stream to nothing and counting the frames",
                   "decoder_said": said, "output_directory": place.shown,
                   "claim": "the repaired copy decodes %s frames; the original decodes %s as it is. That count is all that was verified: not that the frames are the scene's, in order, or all there were" % (
                       after_frames, before_frames if before_frames is not None else "none"),
                   "status_basis": ("the copy was written and every frame of it decodes without an error: %d frames" % after_frames) if status == "complete" else
                                   ("a copy was written but it does not decode a single frame: it is not a repair" if status == "failed" else "; ".join(reasons))})
    if reasons:
        answer["partial_reasons"] = reasons
    return answer, place


def main():
    args, unknown = read_args(KNOWN_PARAMS)
    mode = choice_param(args, "mode", "survey", MODES)
    seconds = int_param(args, "max_seconds", DEFAULT_SECONDS, 5, MAX_SECONDS)
    for key, (low, high) in RANGES.items():
        int_param(args, key, None, low, high)
    if args.get("video") is None:
        raise Refused("video is required: the path of a video file. " + RULES[0])
    video = path_param(args.get("video"), "video")
    set_deadline(seconds)
    started = time.monotonic()
    try:
        st = os.stat(video)
    except OSError as exc:
        raise Refused("video cannot be read (%s)" % describe(exc))
    if not stat.S_ISREG(st.st_mode):
        raise Refused("video is not a regular file")
    ffmpeg, ffprobe, missing = programs()
    common = {"tool": TOOL, "parser": PARSER, "video": printable(video), "bytes": st.st_size, "rules": RULES,
              "decoder": {"ffmpeg": bool(ffmpeg), "ffprobe": bool(ffprobe)}, **({"unrecognised_parameters": unknown} if unknown else {})}
    place = None
    try:
        if mode == "repair":
            if missing:
                common["decoder_missing"] = missing
            answer, place = repair(video, ffmpeg if not missing else None, ffprobe, common, st.st_size)
            answer.pop("decoder_missing", None)
        elif missing:
            answer = {**common, "status": "failed", "error": missing, "status_basis": "%s: no frame was decoded, and that says nothing about the video" % missing}
        else:
            info, why = probe(ffprobe, video)
            if info is None:
                answer = {**common, "status": "failed", "error": why,
                          "status_basis": "the video stream could not be read (%s): no frame was decoded. %s" % (why, RULES[3])}
            else:
                common["stream"] = info
                answer, place = survey(args, video, info, ffmpeg, common, started) if mode == "survey" else extract(args, video, info, ffmpeg, common)
    except Clock:
        left = drop_temporaries()
        answer = {**common, "status": "failed", "error": "the tool's clock ran out", "status_basis": "the clock (max_seconds %d) ran out inside a step that has no partial result: what was written before it is not claimed" % seconds,
                  **({"temporaries_left": left[:10]} if left else {})}
    answer["seconds"] = round(time.monotonic() - started, 2)
    if place is not None and place.note():
        answer["note"] = place.note()
    notes = process_notes()
    if notes:
        answer["process_notes"] = notes
    process_apply(answer)
    print_answer(answer, indent=1)
    if answer["status"] == "failed":
        raise SystemExit(1)


if __name__ == "__main__":
    exit_code = 0
    try:
        answered(main)
    except SystemExit as stop:
        exit_code = _code(stop)
    _leave(exit_code)
