#!/usr/bin/env python3
"""Build a super timeline with Plaso, and hand back something a swarm can read.

Our own timeline is the ledger: facts an agent decided were worth recording,
each with a citation. Plaso's is the opposite and the two are complementary:
what the enabled parsers produced from the sources they could read, with no
judgement applied. An examiner wants both: the machine timeline to find the
window, the ledger to say what happened in it. It is not every timestamp on the
volume: a parser that is not enabled, a source it could not open and a record
it could not read add no row.

Two things this wrapper exists to enforce.

The first is the parser filter. A default log2timeline run over a 60 GB image
takes hours and returns tens of millions of events, most of them filestat
noise. Naming the parsers you actually need turns that into minutes, and the
output says which filter produced it so a reviewer can repeat it.

The second is the timezone. Plaso writes UTC, but it needs the evidence
machine's own zone to interpret the formats that store local time. Getting it
wrong shifts a whole class of artefacts and nothing in the output says so,
which is why the zone given is returned with the result.

What it reports, so that a failed run cannot look like a normal one: each
stage's exit code, a status (complete: both programs exited 0 and wrote their
files and every line parsed; partial: something ran and something did not;
failed: nothing usable), the versions the programs print, how many output lines
parsed and how many did not (with where), and that `complete` says the programs
finished, not that every parser read every source (the storage file's own
processing report, read with Plaso's pinfo, says what each parser did).

`mode: export` runs only psort, over a storage file that already exists, so a
new filter does not collect the evidence again. The default, `full`, runs
log2timeline then psort and refuses an out_dir that already holds files unless
`resume` is true, in which case only files written after the run began count.
Each program writes its log to out_dir (--logfile), its stdout and stderr to
files there, and runs from out_dir: the run's own directory is read-only in an
agent's VM and in a job's worker.
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
import json
import os
import shutil
import signal
import stat
import subprocess
import sys
import time
import re
from datetime import datetime, timezone
from pathlib import Path

TOOL = {"name": "timeline_super", "version": 20}
DEFAULT_TIMEOUT = 1800
TIMEOUT_MAX = 3300                # the manifest's own limit is 3600: the rest is for the version calls and the counting
TOOL_SECONDS = 3500               # the whole call, counting included, ends before the manifest's limit
SAMPLE_MAX = 1000
VERSION_TIMEOUT = 20
LINE_MAX = 8 * 1024 * 1024        # a line past this is counted invalid, its tail skipped; the file keeps it whole
MESSAGE_PREVIEW = 2000
CLOCK_BYTES = 1 << 20              # the clock is read at least every this many bytes of psort's output
INVALID_LISTED = 1000
ZONE = re.compile(r"^[A-Za-z0-9_+\-/]{1,64}$")
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
    if "answer_a_stop" in globals():     # (a block run on its own, by a test, has no ENDS block)
        answer_a_stop(signum)
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


def _early_last_word(signum):
    """Until main() has its own: a stop before the arguments are read gives one document, `failed` and `interrupted`, and depends on nothing
    defined later."""
    sys.stdout.write(json.dumps({"ok": False, "tool": TOOL, "status": "failed", "interrupted": True, "signal": signum,
                                 "status_basis": "the tool was stopped by signal %d before it had started a program, so it did nothing" % signum}) + "\n")
    sys.stdout.flush()


STATE["last_word"] = _early_last_word
install_signal_handlers()


def emit(obj, code=0):
    print_answer(obj, indent=2)
    raise SystemExit(code)


def fail(message, **extra):
    print_answer({"error": message, "status": "failed", "status_basis": "the tool stopped with an error: %s" % message, "tool": TOOL, **extra})
    raise SystemExit(1)


def resolve_output(out):
    """Where `out` really lands, refusing anything outside the run directory.

    A string check is not enough: `work/../inputs/x` and an absolute path
    both name a file the tool must not write, and neither starts with
    "inputs/". Resolving first and comparing directories is what actually
    holds, and the read-only inputs are the one place extracted bytes must
    never appear -- a later integrity check would report the evidence as
    modified.
    """
    root = Path.cwd().resolve()
    try:
        dest = (root / out).resolve() if not Path(out).is_absolute() else Path(out).resolve()
    except (OSError, RuntimeError, ValueError) as exc:     # a symlink loop, a name too long, a lone surrogate
        fail("output cannot be resolved: %s" % (exc.__class__.__name__ if not getattr(exc, "strerror", None) else exc.strerror), output=str(out))
    if dest != root and root not in dest.parents:
        fail("output must stay inside the run directory", output=str(out))
    inputs = root / "inputs"
    if dest == inputs or inputs in dest.parents:
        fail("output cannot be under inputs/", output=str(out))
    bound = job_out()
    if bound is not None and dest != bound and bound not in dest.parents:
        fail("in a job an output is a directory under $OUT, the one place a job writes (the rest of the run is read-only there)",
             output=str(out), out=str(bound), hint="leave out_dir out, or give {OUT}/timeline, or work/<your id>/timeline, which the harness maps there")
    return dest


def job_out():
    """$OUT when this runs as a job, else None."""
    job, out = os.environ.get("JOB_ID"), os.environ.get("OUT")
    return Path(out).resolve() if job and out else None


def unused(path):
    """`path`, or the first name beside it that nothing holds (timeline.2.jsonl): a resumed directory keeps an
    earlier run's files as they were, and this run's are named apart."""
    if not os.path.lexists(path):
        return path
    folder, name = os.path.split(path)
    stem, dot, ext = name.partition(".")
    k = 2
    while True:
        candidate = os.path.join(folder, "%s.%d%s%s" % (stem, k, dot, ext))
        if not os.path.lexists(candidate):
            return candidate
        k += 1


def readable(stamp):
    """Plaso writes microseconds since the epoch; an examiner reads ISO 8601 UTC."""
    if stamp is None:
        return None
    if isinstance(stamp, str):
        return stamp
    try:
        micro = int(stamp)
        whole, frac = divmod(micro, 1_000_000)
        text = datetime.fromtimestamp(whole, timezone.utc).isoformat().replace("+00:00", "")
        return text + ("." + "%06d" % frac if frac else "") + "Z"
    except (ValueError, OverflowError, OSError, TypeError):
        return str(stamp)


class Stage:
    """One program run: its command, its exit, how long, and where its words went."""

    def __init__(self, name, argv, out_dir):
        self.name, self.argv, self.out_dir = name, argv, out_dir
        self.exit = None
        self.timed_out = False
        self.seconds = None
        self.stdout_file = unused(os.path.join(out_dir, name + ".stdout"))
        self.stderr_file = unused(os.path.join(out_dir, name + ".stderr"))

    def run(self, deadline):
        started = time.monotonic()
        budget = deadline - started
        if budget <= 0:
            self.exit, self.timed_out, self.seconds = None, True, 0
            return self
        with open(self.stdout_file, "xb") as so, open(self.stderr_file, "xb") as se:        # new files: never over an earlier run's
            proc = spawn(self.argv, stdout=so, stderr=se, cwd=self.out_dir)
            ACTIVE.append(proc)
            try:
                self.exit = proc.wait(timeout=budget)
            except subprocess.TimeoutExpired:
                self.timed_out = True
                kill_tree(proc)
                proc.wait()
                self.exit = None
            finally:
                ACTIVE.remove(proc)
        self.seconds = round(time.monotonic() - started, 1)
        return self

    def record(self):
        rec = {"command": " ".join(self.argv), "exit": self.exit, "seconds": self.seconds,
               "stdout": self.stdout_file, "stderr": self.stderr_file}
        if self.timed_out:
            rec["timed_out"] = True
        return rec


def version_of(program, out_dir):
    """The first line `program --version` prints. The probe is a program of the shared block (spawn, ACTIVE, communicate_bounded), so a deadline or a stop signal ends
    it with what it started, never only its own process as subprocess.run's timeout did."""
    try:
        proc = spawn([program, "--version"], stdout=subprocess.PIPE, stderr=subprocess.PIPE, cwd=out_dir)
    except OSError:
        return None
    ACTIVE.append(proc)
    try:
        out, err, timed_out = communicate_bounded(proc, VERSION_TIMEOUT)
    finally:
        ACTIVE.remove(proc)
    if timed_out:
        return None
    text = (out.decode("utf-8", "replace") + err.decode("utf-8", "replace")).strip().splitlines()
    return text[0][:200] if text else None


def program_problems():
    """Why the files log2timeline and psort wrote (the storage file, the output, their logs and captured words) cannot be taken as final, from the shared block's
    verdict: settle() ended a process that a program left behind before the output was read and counted, so what it would still have written is missing; or nothing
    can show that none was left (a host that is not Linux, a kernel that refuses PR_SET_CHILD_SUBREAPER)."""
    verdict = process_verdict()
    reasons = []
    if verdict["left_behind"]:
        reasons.append("log2timeline or psort left %d process(es) running after it ended (a child that held one of its files, in the tool's process group or, in a session of its own, outside it); "
                       "settle() killed and reaped them before the output was read and counted, so the storage file, the output and the captured words are what they held at that "
                       "moment and what the leftover would still have written is missing" % verdict["left_behind"])
    reasons.extend(why + ": the storage file and the output cannot be shown to be final" for why in verdict["unproven"])
    return reasons


def stamp_value(row):
    """The event's time as an aware datetime, or None: what a number or an ISO 8601 text can be said to be."""
    raw = row.get("datetime") or row.get("timestamp")
    try:
        if isinstance(raw, bool) or raw is None:
            return None, raw
        if isinstance(raw, (int, float)):
            return datetime.fromtimestamp(int(raw) // 1_000_000, timezone.utc).replace(microsecond=int(raw) % 1_000_000), raw
        text = str(raw)
        when = datetime.fromisoformat(text[:-1] + "+00:00" if text.endswith("Z") else text)
        return (when if when.tzinfo else when.replace(tzinfo=timezone.utc)), raw
    except (ValueError, OverflowError, OSError):
        return None, raw


def open_regular(path):
    """The file opened without blocking and checked on the descriptor to be a regular file (a pipe put where psort's output was cannot hold the run)."""
    fd = os.open(path, os.O_RDONLY | getattr(os, "O_NONBLOCK", 0))
    try:
        if not stat.S_ISREG(os.fstat(fd).st_mode):
            raise OSError(errno.ESPIPE, "not a regular file")
        return os.fdopen(fd, "rb")
    except BaseException:
        os.close(fd)
        raise


def summarise(output, sample, out_dir, stop_at, invalid_path):
    """Valid and invalid lines of psort's JSON Lines, read line by line with a cap on
    a line's size, so a hostile line cannot fill memory and a bad one is not a count.

    first_event and last_event are the earliest and latest time among the events (the file's order is
    not trusted to be time order); an event with no time a reader can place is counted apart. The
    counting stops at `stop_at` (a monotonic time): what was counted is then a lower bound, and says so."""
    events = invalid = oversized = untimed = 0
    earliest = latest = None
    parsers_seen, head, bad = {}, [], []
    stopped_at_line = None
    with open_regular(output) as fh:
        number, offset, since_check = 0, 0, 0
        while True:
            line = fh.readline(LINE_MAX + 1)
            if not line:
                break
            start = offset
            number += 1
            since_check += len(line)
            # The clock is read every 20,000 lines and every CLOCK_BYTES bytes read: a file of a few enormous lines is as long as one of many small ones.
            if (number % 20000 == 0 or since_check >= CLOCK_BYTES) and time.monotonic() > stop_at:
                stopped_at_line = number
                break
            if since_check >= CLOCK_BYTES:
                since_check = 0
            if len(line) > LINE_MAX and not line.endswith(b"\n"):
                rest = 0
                out_of_time = False
                while True:
                    if time.monotonic() > stop_at:
                        out_of_time = True
                        break
                    chunk = fh.readline(LINE_MAX)
                    rest += len(chunk)
                    if not chunk or chunk.endswith(b"\n"):
                        break
                if out_of_time:
                    stopped_at_line = number
                    break
                offset += len(line) + rest
                oversized += 1
                invalid += 1
                if len(bad) < INVALID_LISTED:
                    bad.append((number, start, len(line) + rest, "longer than %d bytes: not parsed" % LINE_MAX, line[:200]))
                continue
            offset += len(line)
            text = line.strip()
            if not text:
                continue
            try:
                row = json.loads(text.decode("utf-8"))             # strict: a byte that is not UTF-8 is not quietly replaced
                if not isinstance(row, dict):
                    raise ValueError("not a JSON object")
            except ValueError as exc:                               # UnicodeDecodeError is one
                invalid += 1
                if len(bad) < INVALID_LISTED:
                    bad.append((number, start, len(line), str(exc), text[:200]))
                continue
            events += 1
            when, raw = stamp_value(row)
            stamp = readable(raw)
            if when is None:
                untimed += 1
            else:
                if earliest is None or when < earliest[0]:
                    earliest = (when, raw)
                if latest is None or when > latest[0]:
                    latest = (when, raw)
            name = row.get("parser") or row.get("data_type") or "unknown"
            parsers_seen[name] = parsers_seen.get(name, 0) + 1
            if len(head) < sample:
                entry = {k: row.get(k) for k in ("timestamp_desc", "parser", "data_type", "display_name") if row.get(k) is not None}
                entry["datetime"] = stamp
                msg = str(row.get("message") or "")
                entry["message"] = msg[:MESSAGE_PREVIEW]
                if len(msg) > MESSAGE_PREVIEW:
                    entry["message_length"] = len(msg)
                    entry["message_note"] = "a preview: the whole line is line %d of the output file" % number
                head.append(entry)
    invalid_error = None
    if bad:
        try:
            with open(invalid_path, "x", encoding="utf-8") as fh:
                fh.write("line\tbyte_offset\tbytes\treason\tfirst 200 bytes (the whole line stays in the output file)\n")
                for n, off, size, why, snippet in bad:
                    fh.write("%d\t%d\t%d\t%s\t%s\n" % (n, off, size, why.replace("\t", " ").replace("\n", " "),
                                                       snippet.decode("utf-8", "replace").replace("\t", " ").replace("\n", " ")))
        except OSError as exc:                  # a full disk or a file-size limit: the counts stay whole, the half listing is removed
            invalid_error = getattr(exc, "strerror", None) or exc.__class__.__name__
            try:
                os.unlink(invalid_path)
            except OSError:
                pass
    return {"events": events, "invalid_lines": invalid, "oversized_lines": oversized, "events_without_a_time": untimed,
            "first_event": readable(earliest[1]) if earliest else None, "last_event": readable(latest[1]) if latest else None,
            "parsers_seen": parsers_seen, "head": head,
            "invalid_lines_file": invalid_path if bad and not invalid_error else None, "invalid_lines_file_error": invalid_error,
            "invalid_lines_listed": len(bad) if not invalid_error else 0, "invalid_lines_listing_complete": len(bad) == invalid and not invalid_error,
            "stopped_at_line": stopped_at_line}


def main():
    try:
        args = json.load(sys.stdin)
    except (ValueError, RecursionError) as exc:
        fail("arguments are not valid JSON", reason=str(exc)[:200])
    if not isinstance(args, dict):
        fail("arguments are a JSON object")

    for name in ("parsers", "timezone", "psort_filter"):
        value = args.get(name)
        if value is not None and (not isinstance(value, str) or not value or "\0" in value):
            fail("%s is a non-empty string (no NUL)" % name, **{name: value})
    for name in ("parsers", "psort_filter"):
        if isinstance(args.get(name), str) and args[name].startswith("-"):
            fail("%s does not begin with '-': it would be read as an option of the program" % name, **{name: args[name]})
    if args.get("timezone") is not None and not ZONE.match(args["timezone"]):
        fail("timezone is a zone name such as Europe/Istanbul", timezone=args["timezone"])
    mode = args.get("mode", "full")
    if not isinstance(mode, str) or mode not in ("full", "export"):
        fail("mode is full (log2timeline then psort) or export (psort over an existing storage file)", mode=mode)
    resume = args.get("resume", False)
    if not isinstance(resume, bool):
        fail("resume is true or false")

    out_dir = args.get("out_dir")
    if out_dir is None and job_out() is not None:
        out_dir = str(job_out() / "timeline")         # in a job the one place that can be written
    if not isinstance(out_dir, str) or not out_dir or "\0" in out_dir:
        fail("out_dir is required: a directory under work/<your id>/ for the storage file and the output (in a job, under $OUT, and the default there)")
    dest = resolve_output(out_dir)

    source = args.get("source")
    storage_arg = args.get("storage_file")
    if mode == "full":
        if not isinstance(source, str) or not source:
            fail("source is required: an image, a partition or a collection directory")
        if not os.path.exists(source):
            fail("no such source", source=source)
        if storage_arg is not None:
            fail("storage_file is for mode export; mode full makes timeline.plaso in out_dir")
    else:
        if not isinstance(storage_arg, str) or not storage_arg:
            fail("mode export needs storage_file: the .plaso file psort should read")
        if not os.path.isfile(storage_arg):
            fail("no such storage file", storage_file=storage_arg)

    l2t = shutil.which("log2timeline.py") or shutil.which("log2timeline")
    psort = shutil.which("psort.py") or shutil.which("psort")
    needed = [("psort.py", psort)] + ([("log2timeline.py", l2t)] if mode == "full" else [])
    if any(not p for _, p in needed):
        fail("Plaso is not on PATH", missing=[n for n, p in needed if not p],
             install="python3 -m pip install plaso, or apt-get install -y plaso-tools")

    timeout = args.get("timeout_seconds", DEFAULT_TIMEOUT)
    if not isinstance(timeout, int) or isinstance(timeout, bool) or not 30 <= timeout <= TIMEOUT_MAX:
        fail("timeout_seconds must be an integer from 30 to %d (the tool's own limit is 3600 seconds, and the counting needs the rest)" % TIMEOUT_MAX)
    sample = args.get("sample", 20)
    if not isinstance(sample, int) or isinstance(sample, bool) or not 0 <= sample <= SAMPLE_MAX:
        fail("sample must be a whole number from 0 to %d" % SAMPLE_MAX)

    call_started = time.monotonic()
    began = time.time()
    deadline = time.monotonic() + timeout            # one budget for every stage
    preexisting = []
    try:
        dest_exists = dest.exists()
        dest_is_dir = dest.is_dir() if dest_exists else False
        if dest_exists and dest_is_dir:
            preexisting = sorted(os.listdir(dest))
    except OSError as exc:       # a name too long, a parent that cannot be searched, a directory that cannot be listed
        fail("out_dir cannot be looked at: %s" % (exc.strerror or exc), out_dir=out_dir,
             hint="in a job only $OUT is writable; elsewhere only work/<your id>/ is")
    if os.path.lexists(dest) and not dest_is_dir:
        fail("out_dir is not a directory", out_dir=out_dir)
    if dest_exists:
        if preexisting and not resume:
            fail("out_dir already holds files, and a file left by an earlier run would be taken for this one's: "
                 "give a new directory, or resume: true to write beside them (only files written after this run began count)",
                 out_dir=out_dir, holds=preexisting[:20])
    try:
        os.makedirs(dest, exist_ok=True)
    except OSError as exc:
        fail("out_dir cannot be made: %s" % (exc.strerror or exc), out_dir=out_dir,
             hint="in a job only $OUT is writable; elsewhere only work/<your id>/ is")
    out_abs = str(dest)
    names = [os.path.join(out_abs, n) for n in ("timeline.jsonl", "timeline.plaso", "timeline.invalid_lines.txt")]
    for logname in ("log2timeline", "psort"):
        names += [os.path.join(out_abs, logname + ext) for ext in (".log.gz", ".stdout", ".stderr")]
    for path in names:
        if os.path.islink(path):
            fail("a link stands where this tool writes; it will not write through it", path=path)
    # A resumed directory keeps an earlier run's files as they were: this run's are named beside them (timeline.2.jsonl).
    store = unused(os.path.join(out_abs, "timeline.plaso")) if mode == "full" else os.path.abspath(storage_arg)
    output = unused(os.path.join(out_abs, "timeline.jsonl"))
    invalid_path = unused(os.path.join(out_abs, "timeline.invalid_lines.txt"))

    def fresh(path):
        try:
            return os.path.isfile(path) and os.stat(path).st_mtime >= began - 1
        except OSError:
            return False

    result = {"tool": TOOL, "mode": mode, "out_dir": out_abs, "storage_file": store, "output": output,
              "versions": {}, "stages": {}, "problems": []}
    if preexisting:
        result["preexisting"] = preexisting

    def last_word(signum):
        """Said when a signal ends the tool: what had run, and that the programs were ended with it."""
        name = signal.Signals(signum).name
        word = dict(result, status="failed", stopped_by_signal=name,
                    error="stopped by %s before it finished: log2timeline and psort were ended with it; what they had written is in out_dir and may be partial" % name)
        sys.stdout.write(json.dumps(word) + "\n")
        sys.stdout.flush()
    STATE["last_word"] = last_word
    result["versions"]["psort"] = version_of(psort, out_abs)
    if mode == "full":
        result["source"] = source
        result["versions"]["log2timeline"] = version_of(l2t, out_abs)
        collect_log = unused(os.path.join(out_abs, "log2timeline.log.gz"))
        collect = [l2t, "--status_view", "none", "--logfile", collect_log, "--partitions", "all", "--volumes", "all", "--unattended", "--quiet"]
        if args.get("parsers"):
            collect += ["--parsers", str(args["parsers"])]
        if args.get("timezone"):
            collect += ["--timezone", str(args["timezone"])]
        collect += ["--storage_file", store, os.path.abspath(source)]
        try:
            stage = Stage("log2timeline", collect, out_abs).run(deadline)
        except OSError as exc:
            fail("out_dir cannot be written: %s" % (exc.strerror or exc), out_dir=out_dir)
        result["stages"]["collect"] = stage.record()
        result["collect_exit"] = stage.exit
        if stage.timed_out:
            result["problems"].append("log2timeline did not finish within the %ds budget; narrow it with parsers" % timeout)
        elif stage.exit != 0:
            result["problems"].append("log2timeline exited %s; its output is in %s and %s, its log in %s" % (stage.exit, stage.stdout_file, stage.stderr_file, collect_log))
        storage_ok = fresh(store)
        if not storage_ok:
            result["problems"].append("log2timeline wrote no storage file (or none newer than this run's start)")
    else:
        storage_ok = os.path.isfile(store)
        result["collect_exit"] = None
        result["stages"]["collect"] = {"skipped": "mode export: log2timeline was not run; the storage file is the one given"}

    export_log = unused(os.path.join(out_abs, "psort.log.gz"))
    export = [psort, "--status_view", "none", "--logfile", export_log, "-o", "json_line", "-w", output]
    if args.get("psort_filter"):
        export += ["--filter", str(args["psort_filter"])]
    export += [store]
    result["export_exit"] = None
    output_ok = False
    # psort reads a storage file, so it is run when there is one even after a nonzero collect (a partial
    # storage can still be read), and its status then says what each stage did.
    if storage_ok and time.monotonic() < deadline:
        try:
            stage = Stage("psort", export, out_abs).run(deadline)
        except OSError as exc:
            fail("out_dir cannot be written: %s" % (exc.strerror or exc), out_dir=out_dir)
        result["stages"]["export"] = stage.record()
        result["export_exit"] = stage.exit
        if stage.timed_out:
            result["problems"].append("psort did not finish within the %ds budget" % timeout)
        elif stage.exit != 0:
            result["problems"].append("psort exited %s; its output is in %s and %s, its log in %s" % (stage.exit, stage.stdout_file, stage.stderr_file, export_log))
        output_ok = fresh(output)
        if not output_ok:
            result["problems"].append("psort wrote no output file (or none newer than this run's start)")
    elif storage_ok:
        result["problems"].append("the time budget was used before psort could run")

    # Only what this run wrote: a log or a captured output left in a resumed directory is an earlier run's, and is listed under preexisting.
    result["logs"] = [p for p in ((collect_log if mode == "full" else None), export_log) if p and fresh(p)]
    result["captured_output"] = [str(p) for p in sorted(Path(out_abs).glob("*.std*")) if fresh(str(p))]
    result["parsers_filter"] = args.get("parsers") or ("all (the default, and usually the wrong choice)" if mode == "full" else "as in the storage file given")
    result["timezone_given"] = args.get("timezone") or None
    result["timezone_note"] = ("the zone given to log2timeline for the formats that store local time" if args.get("timezone")
                               else "none given: for the formats that store local time Plaso used its own default, which this tool does not read back; "
                                    "the storage file records what it used (pinfo)")
    result["psort_filter"] = args.get("psort_filter")

    if output_ok:
        try:
            summary = summarise(output, sample, out_abs, call_started + TOOL_SECONDS, invalid_path)
        except OSError as exc:
            summary = None
            result["problems"].append("psort's output could not be read: %s" % (exc.strerror or exc))
        if summary:
            result["events"] = summary["events"]
            result["invalid_lines"] = summary["invalid_lines"]
            result["oversized_lines"] = summary["oversized_lines"]
            if summary["invalid_lines_file_error"]:
                result["problems"].append("the file listing the invalid lines could not be written (%s): the count is whole, the listing is not" % summary["invalid_lines_file_error"])
            if summary["invalid_lines_file"]:
                result["invalid_lines_file"] = summary["invalid_lines_file"]
                result["invalid_lines_listing_complete"] = summary["invalid_lines_listing_complete"]
            result["events_without_a_time"] = summary["events_without_a_time"]
            result["first_event"], result["last_event"] = summary["first_event"], summary["last_event"]
            result["first_last_note"] = "the earliest and the latest time among the events, whatever their order in the file"
            result["summary_complete"] = summary["stopped_at_line"] is None
            if summary["stopped_at_line"] is not None:
                result["problems"].append("counting psort's output stopped at the tool's time limit, at line %d: events, by_parser, first_event and "
                                          "last_event cover the lines before it only (the timeline file itself is whole)" % summary["stopped_at_line"])
            top = sorted(summary["parsers_seen"].items(), key=lambda kv: -kv[1])[:15]
            result["by_parser"] = [{"parser": n, "events": c} for n, c in top]
            result["sample"] = summary["head"]
            result["sample_note"] = "a preview; the whole timeline is the output file, one JSON object per line"
            result["contains_evidence_text"] = True
            result["sensitive_output_note"] = ("the timeline, the storage file and the sample are text the parsers read from the evidence (command lines, "
                                               "addresses, names, URLs with their parameters): when the source may hold credentials, run the job with "
                                               "secret_output: true and ask for sample: 0")
            if summary["invalid_lines"]:
                result["problems"].append("%d line(s) of the output are not valid JSON events and are not in the count; see %s"
                                          % (summary["invalid_lines"], summary["invalid_lines_file"] or "the output file"))

    empty = bool(output_ok and result.get("events") == 0 and result.get("invalid_lines") == 0 and not result["problems"] and result["export_exit"] == 0)
    if output_ok and result.get("events") == 0 and result.get("invalid_lines") == 0:
        result["problems"].append("the programs ran and wrote no event: an empty timeline is not evidence that the source holds nothing, and whether a parser "
                                  "failed is not established (read the storage file's processing report, Plaso's pinfo)")
    clean = (not result["problems"] and result["export_exit"] == 0 and (mode == "export" or result["collect_exit"] == 0))
    if clean and output_ok:
        result["status"] = "complete"
    elif output_ok:
        result["status"] = "partial"
    else:
        result["status"] = "failed"
        result["error"] = result["problems"][0] if result["problems"] else "no timeline was produced"
    result["status_basis"] = {"complete": "the programs exited 0, wrote their files and every output line parsed",
                              "partial": ("the programs ran and wrote no event, so nothing is shown about the source (see problems)" if empty else
                                          "a program did not exit 0, the counting did not finish, or an output line did not parse, and what was written is kept (see problems)"),
                              "failed": "no timeline was produced"}[result["status"]]
    notes = process_notes()
    if notes:
        result["process_notes"] = notes
    if result["stages"].get("export") or result["stages"]["collect"].get("command"):
        result["problems"].extend(program_problems())
    process_apply(result)             # program_group: what settle() ended and why absence is unproven; a complete answer becomes partial
    result["coverage_note"] = ("complete here means the programs exited 0, wrote their files and every output line parsed. It does not say every "
                               "parser read every source: read the storage file's processing report (Plaso's pinfo) before a negative rests on it. "
                               "A timestamp in this timeline is what a parser read, in UTC; it is a pointer to an artefact, which the artefact's own "
                               "skill then examines.")
    hold_stop_signals()
    STATE["last_word"] = None
    emit(result, 0 if result["status"] == "complete" else 1)


if __name__ == "__main__":
    exit_code = 0
    try:
        main()
    except SystemExit as stop:
        exit_code = _code(stop)
    _leave(exit_code)
