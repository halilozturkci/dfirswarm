#!/usr/bin/env python3
"""Cut a crop that holds one line of text into its glyphs, count them, and count the readings a confusable character leaves open.

The crop (a PNG by a reader of its own; any format Pillow reads when Pillow imports) is thresholded, the ink is taken as the minority
colour, and every run of columns with ink in it is one glyph: its box, a crop of it, and its place in one strip picture where each
glyph is enlarged and carries its index. Glyphs that are the same drawing are grouped. The count is of ink runs: characters that
touch count as one and a character drawn as two strokes side by side as two, and the answer names the runs where that may be so.

Given a reading and the positions that are uncertain (each with the characters it could be, or, without them, the confusable class
of its character: ' and `, l I 1 |, O 0 o, and so on), the candidate set is the product of the alternatives; positions whose glyphs
are the same drawing and that the reading gives the same character are tied. The answer carries the set's size; the set itself, the reading and any OCR text go to files, never
into the answer. When tesseract is on PATH it is run on the crop as a second reader and the answer says which reader read what;
when it is not, the answer says so.
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


import array
import collections
import errno
import hashlib
import itertools
import math
import re
import shutil
import stat
import struct
import subprocess
import time
import warnings
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
        if "kill_decoder" in globals():
            kill_decoder()
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


TOOL = {"name": "glyph_strip", "version": 9}
PARSER = "glyph_strip/5"
DEFAULT_SECONDS, MAX_SECONDS = 50, 55           # under the manifest's 60
OCR_SECONDS = 20
OCR_START_SECONDS = 2              # the OCR engine is started only with this much of the clock left (it is given at least a second, and its pipes one more)
MAX_GLYPHS = 400
MAX_CROP_PIXELS = 6_000_000        # a crop of one line; a whole photograph is cropped first
MAX_CROP_HEIGHT, MAX_CROP_WIDTH = 2000, 50000      # its shape: a line is neither a column of pixels nor a thread (the rows held, the strip built)
MAX_CROP_SCALE_PIXELS = 4_000_000  # a glyph's crop is enlarged four times, or less when that would pass this many pixels
MAX_OCR_BYTES = 1 << 16            # what the OCR engine may write for one line (and for its version); more is not read
MAX_READING = 400
DEFAULT_CANDIDATES, MAX_CANDIDATES = 4096, 200000
KNOWN_PARAMS = {"image", "reading", "uncertain", "classes", "max_candidates", "ocr", "reader", "max_seconds"}
# Characters one glyph can be taken for in a screenshot or a photograph, a class a line: the default alternatives of an uncertain position.
CLASSES = ["'`", "lI1|", "oO0", "sS5", "zZ2", "cC", "vV", "wW", "xX", "uU", "kK", "pP", "8B", "6G", "9gq", ".,", ":;", "-_"]
RULES = [
    "Text read from a picture is a reading with an error rate. A reading with a confusable character at a position that matters (' or `, "
    "l or I or 1, O or 0) is recorded at MEDIUM confidence as a candidate set, never as one string: give the reading and the uncertain "
    "positions, and cite candidate_set_size and the candidates file.",
    "The count is the number of separate ink runs along the line. It is the number of characters only when no two characters touch and "
    "no character is drawn as two strokes side by side: check wide and narrow_pairs, and look at the strip (every glyph has its index).",
    "Give `uncertain` as positions with their alternatives ([{\"at\": 4, \"among\": \"lI\"}], positions from 0, spaces counted): the set "
    "is the product of the alternatives. Without `uncertain`, every character of the reading that is in a confusable class is uncertain.",
    "The reading, the OCR text and the candidates are evidence text and can be a password or a key: they go to files, never into the "
    "answer. When the line is a credential, run the job with secret_output: true and cite the file.",
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
                agent = re.sub(r"[^A-Za-z0-9_.-]", "_", os.environ.get("AGENT_ID") or "tool")
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


STATE["last_word"] = lambda signum: (kill_decoder(), _stopped(signum))     # the child that decodes a picture with Pillow ends first
install_signal_handlers()
STOP_CLOCK = {"deadline": None}


def set_deadline(seconds):
    STOP_CLOCK["deadline"] = time.monotonic() + seconds


def out_of_time():
    return STOP_CLOCK["deadline"] is not None and time.monotonic() > STOP_CLOCK["deadline"]


def seconds_until_clock():
    return float("inf") if STOP_CLOCK["deadline"] is None else STOP_CLOCK["deadline"] - time.monotonic()


def seconds_left(most):
    left = (STOP_CLOCK["deadline"] - time.monotonic()) if STOP_CLOCK["deadline"] is not None else most
    return max(0.5, min(most, left))


def find_program(name):
    """The program's path on PATH, or None."""
    return shutil.which(name)


# ---- pictures: a small PNG reader and writer of its own, and Pillow when it imports ---------------------------------------------------
PNG_MAGIC = b"\x89PNG\r\n\x1a\n"
MAX_PIXELS = 36_000_000            # a picture larger than this is refused (its rows would not fit the tool's memory and clock)
MAX_IMAGE_BYTES = 256 << 20
MAX_PNG_ROWS = 256 << 20           # the inflated rows of a PNG the built-in reader holds


class NotAPicture(Exception):
    """The file is not a picture this tool can read; the text says what was found and what would read it. `damaged` is True when the
    file is a picture of its kind that is cut or corrupt (not one of a form the reader does not take)."""

    def __init__(self, text, damaged=False):
        super().__init__(text)
        self.damaged = damaged


def check_crop(width, height):
    """Refuse a picture that is not a crop of one line, by its header, before a row of it is decoded: more than MAX_CROP_PIXELS, or a shape
    no line has (taller than MAX_CROP_HEIGHT, wider than MAX_CROP_WIDTH). The rows of a picture are held one object a row, and the strip
    is built at the line's height: the shape bounds both, not the pixel count alone."""
    if width * height > MAX_CROP_PIXELS or height > MAX_CROP_HEIGHT or width > MAX_CROP_WIDTH:
        raise Refused("the picture is %d x %d pixels: this tool takes a crop of one line (up to %d pixels, at most %d high and %d wide). Crop the line "
                      "first. %s" % (width, height, MAX_CROP_PIXELS, MAX_CROP_HEIGHT, MAX_CROP_WIDTH, RULES[1]))


class Picture:
    """A picture as rows of bytes: `gray` (one byte a pixel, 0 black to 255 white) always, `rgb` (three bytes a pixel) when it was asked for.
    It is the picture's first frame; `more_frames` is True when the file holds others (they are not read), None when that is not known."""

    def __init__(self, width, height, gray, rgb=None, reader=""):
        self.width, self.height, self.gray, self.rgb, self.reader = width, height, gray, rgb, reader
        self.more_frames = False
        self.damage, self.damage_by, self.unchecked = None, "the built-in reader", None


def _unfilter(kind, line, previous, bpp):
    if kind == 0:
        return line
    out = bytearray(line)
    if kind == 1:
        for i in range(bpp, len(out)):
            out[i] = (out[i] + out[i - bpp]) & 255
    elif kind == 2:
        if previous is not None:
            out = bytearray((a + b) & 255 for a, b in zip(out, previous))
    elif kind == 3:
        for i in range(len(out)):
            left = out[i - bpp] if i >= bpp else 0
            up = previous[i] if previous is not None else 0
            out[i] = (out[i] + ((left + up) >> 1)) & 255
    elif kind == 4:
        for i in range(len(out)):
            a = out[i - bpp] if i >= bpp else 0
            b = previous[i] if previous is not None else 0
            c = previous[i - bpp] if previous is not None and i >= bpp else 0
            p = a + b - c
            pa, pb, pc = abs(p - a), abs(p - b), abs(p - c)
            out[i] = (out[i] + (a if pa <= pb and pa <= pc else b if pb <= pc else c)) & 255
    else:
        raise NotAPicture("a PNG row with the unknown filter %d" % kind)
    return bytes(out)


def read_png(data, want_rgb=False, tick=None):
    """A PNG read with the standard library alone: 8 and 16-bit grey, RGB, palette and alpha forms and the 1, 2 and 4-bit grey and palette
    forms, not interlaced. Transparency is put on white. NotAPicture for anything else; tick() is the clock, read every 1024 chunks and
    once a row (a row is at most MAX_CROP_WIDTH pixels: the header is checked as soon as it is read)."""
    if data[:8] != PNG_MAGIC:
        raise NotAPicture("not a PNG (no PNG signature)")
    at, header, palette, alpha, parts, chunks, animation, default_in_animation = 8, None, None, None, [], 0, None, False
    while at + 12 <= len(data):
        chunks += 1
        if tick and chunks % 1024 == 0:
            tick()
        length = int.from_bytes(data[at:at + 4], "big")
        kind = data[at + 4:at + 8]
        body = data[at + 8:at + 8 + length]
        if len(body) != length:
            raise NotAPicture("a PNG cut inside its %s chunk" % "".join(ch if ch.isalpha() else "?" for ch in kind.decode("latin-1")), damaged=True)
        if zlib.crc32(kind + body) != int.from_bytes(data[at + 8 + length:at + 12 + length], "big"):
            raise NotAPicture("a PNG whose %s chunk fails its CRC" % "".join(ch if ch.isalpha() else "?" for ch in kind.decode("latin-1")), damaged=True)
        at += 12 + length
        if kind == b"acTL" and length == 8:
            animation = int.from_bytes(body[:4], "big")
        elif kind == b"fcTL" and not parts:
            default_in_animation = True
        if kind == b"IHDR":
            if length != 13:
                raise NotAPicture("a PNG with a header of the wrong length")
            header = struct.unpack(">IIBBBBB", body)
            check_crop(header[0], header[1])
        elif kind == b"PLTE":
            palette = body
        elif kind == b"tRNS":
            alpha = body
        elif kind == b"IDAT":
            parts.append(body)
        elif kind == b"IEND":
            break
    if header is None or not parts:
        raise NotAPicture("a PNG with no header or no image data", damaged=True)
    width, height, depth, colour, _compression, _filter, interlace = header
    if width == 0 or height == 0 or width * height > MAX_PIXELS:
        raise NotAPicture("a PNG of %d x %d pixels (this tool reads up to %d pixels)" % (width, height, MAX_PIXELS))
    check_crop(width, height)
    channels = {0: 1, 2: 3, 3: 1, 4: 2, 6: 4}.get(colour)
    if channels is None or depth not in (1, 2, 4, 8, 16) or (depth < 8 and colour not in (0, 3)) or (depth == 16 and colour == 3):
        raise NotAPicture("a PNG of colour type %d at %d bits, which the format does not define" % (colour, depth))
    if interlace:
        # Not read here, but its image data is measured, so that a cut file is not handed to Pillow as a whole one.
        want = 0
        for x0, y0, dx, dy in ((0, 0, 8, 8), (4, 0, 8, 8), (0, 4, 4, 8), (2, 0, 4, 4), (0, 2, 2, 4), (1, 0, 2, 2), (0, 1, 1, 2)):
            pass_width, pass_height = (width - x0 + dx - 1) // dx, (height - y0 + dy - 1) // dy
            if pass_width > 0 and pass_height > 0:
                want += pass_height * (1 + (pass_width * channels * depth + 7) // 8)
        got = _inflated_length(parts, want, tick)
        if got < want:
            raise NotAPicture("an interlaced PNG whose image data ends after %d of %d bytes" % (got, want), damaged=True)
        raise NotAPicture("an interlaced PNG: the built-in reader does not read Adam7 (Pillow does, when it is installed)")
    if colour == 3 and palette is None:
        raise NotAPicture("a palette PNG with no palette", damaged=True)
    stride = (width * channels * depth + 7) // 8
    bpp = max(1, channels * depth // 8)
    if height * (stride + 1) > MAX_PNG_ROWS:
        raise NotAPicture("a PNG whose rows are %d bytes when inflated (the built-in reader takes up to %d; Pillow, when it is installed, reads it)" % (height * (stride + 1), MAX_PNG_ROWS))
    inflater = zlib.decompressobj()
    raw = bytearray()
    want = height * (stride + 1)
    try:
        for part in parts:
            raw += inflater.decompress(part, want - len(raw) + 1)
            if len(raw) > want:
                break
            if tick:
                tick()
    except zlib.error:
        raise NotAPicture("a PNG whose image data is not a zlib stream that inflates (after %d bytes)" % len(raw), damaged=True)
    if len(raw) < want:
        raise NotAPicture("a PNG whose image data ends after %d of %d bytes" % (len(raw), want), damaged=True)
    if palette is not None:
        entries = len(palette) // 3
        pal_gray = bytearray(256)
        pal_rgb = [b"\xff\xff\xff"] * 256
        for i in range(min(256, entries)):
            r, g, b = palette[3 * i:3 * i + 3]
            a = alpha[i] if alpha is not None and i < len(alpha) else 255
            r, g, b = ((v * a + 255 * (255 - a)) // 255 for v in (r, g, b))
            pal_gray[i] = (r * 299 + g * 587 + b * 114) // 1000
            pal_rgb[i] = bytes((r, g, b))
    gray, rgb, previous = [], [] if want_rgb else None, None
    for y in range(height):
        if tick:
            tick()
        start = y * (stride + 1)
        line = _unfilter(raw[start], bytes(raw[start + 1:start + 1 + stride]), previous, bpp)
        previous = line
        if depth == 16:
            line = line[0::2]
        elif depth < 8:
            mask, scale = (1 << depth) - 1, 255 // ((1 << depth) - 1) if colour == 0 else 1
            line = bytes(((line[(x * depth) >> 3] >> (8 - depth - (x * depth) % 8)) & mask) * scale for x in range(width))
        if colour == 0:
            g = line
        elif colour == 3:
            g = line.translate(bytes(pal_gray))
        elif colour == 2:
            g = bytes((line[i] * 299 + line[i + 1] * 587 + line[i + 2] * 114) // 1000 for i in range(0, 3 * width, 3))
        elif colour == 4:
            g = bytes((line[i] * line[i + 1] + 255 * (255 - line[i + 1])) // 255 for i in range(0, 2 * width, 2))
        else:
            g = bytes(((line[i] * 299 + line[i + 1] * 587 + line[i + 2] * 114) // 1000 * line[i + 3] + 255 * (255 - line[i + 3])) // 255 for i in range(0, 4 * width, 4))
        gray.append(g)
        if want_rgb:
            if colour == 2:
                rgb.append(line)
            elif colour == 3:
                rgb.append(b"".join(pal_rgb[v] for v in line))
            elif colour == 6:
                rgb.append(bytes((line[i + k] * line[i + 3] + 255 * (255 - line[i + 3])) // 255 for i in range(0, 4 * width, 4) for k in range(3)))
            else:
                rgb.append(bytes(v for v in g for _ in range(3)))
    picture = Picture(width, height, gray, rgb, "the built-in PNG reader")
    picture.more_frames = animation is not None and animation + (0 if default_in_animation else 1) > 1     # an animated PNG: its default image is read
    return picture


INFLATE_PIECE = 1 << 22            # the inflated bytes of a PNG measured between two readings of the clock


def _inflated_length(parts, want, tick=None):
    """How many bytes the zlib stream of the IDAT chunks inflates to, counted up to want + 1 and never held: the stream is inflated
    INFLATE_PIECE bytes at a time and each piece is dropped, the clock read between them. Pillow takes a zlib stream that ends before the
    rows do as the end of the picture and fills the rows it did not get, and says nothing: a PNG the built-in reader does not read (an
    interlaced one, one whose rows pass MAX_PNG_ROWS) is measured here before Pillow is given it. NotAPicture (damaged) for a stream that
    is not zlib."""
    inflater, got = zlib.decompressobj(), 0
    try:
        for part in parts:
            pending = part
            while got <= want:
                asked = min(INFLATE_PIECE, want + 1 - got)
                out = len(inflater.decompress(pending, asked))
                got += out
                pending = inflater.unconsumed_tail
                if tick:
                    tick()
                if not pending and out < asked:
                    break
            if got > want or inflater.eof:
                break
    except zlib.error:
        raise NotAPicture("a PNG whose image data is not a zlib stream that inflates (after %d bytes)" % got, damaged=True)
    return got


def pillow():
    """The Pillow module, or None when it does not import here. The plugins of PILLOW_FORMATS are loaded here, once, before a child is forked."""
    if "module" not in _PILLOW:
        try:
            from PIL import Image
            Image.MAX_IMAGE_PIXELS = MAX_PIXELS
            for plugin in ("BmpImagePlugin", "GifImagePlugin", "JpegImagePlugin", "MpoImagePlugin", "PngImagePlugin", "TiffImagePlugin", "WebPImagePlugin"):
                try:
                    __import__("PIL." + plugin)
                except Exception:  # noqa: BLE001 - a plugin that does not load leaves its format unread
                    pass
            _PILLOW["module"] = Image
            _PILLOW["version"] = getattr(__import__("PIL"), "__version__", "?")
        except Exception:  # noqa: BLE001 - not installed, or broken: the built-in reader is what there is
            _PILLOW["module"] = None
    return _PILLOW["module"]


_PILLOW = {}


def clock_deadline():
    """When the tool's clock runs out (time.monotonic()), or None before it is set."""
    return STOP_CLOCK["deadline"]


# ---- Pillow in a child process that the clock ends (the same code is in qr_read and glyph_strip) --------------------------------------
# Pillow's decoders do not read this tool's clock: a progressive JPEG of a quarter of a million scans, a TIFF of a quarter of a million
# pages (Pillow counts them by walking every page) and a format Pillow decodes in Python each ran for minutes inside one call. So Pillow
# never runs in the tool's own process. A child is forked for one picture; it opens the picture as one of PILLOW_FORMATS only, and sends
# each frame's size and then its grey rows on a pipe, frame after frame (seeking to the next, never asking how many there are), up to the
# frames asked for, and then whether there is another. The tool reads the pipe against its clock and kills the child (SIGKILL) when the
# clock runs out or the picture is done. The child's address space is bounded (DECODE_MEMORY more than it was forked with; Linux, where
# the limit is enforced), its CPU time by the clock, it dies with the tool (Linux), it takes the stop signals' default action, it writes
# nothing on standard output, and it ends with os._exit (no hook of the tool runs in it). A JPEG is counted before it is handed over: one
# with more than MAX_JPEG_SCANS start-of-scan markers is refused (a picture has one, a progressive one about ten).
#
# What the gate does with each format Pillow may open here (PILLOW_FORMATS; nothing else is opened). A decoder that meets data cut short
# or zeroed may raise (the picture is then not read), or fill what it lacks and say nothing (the tool must then find the damage itself).
# Every format, and every TIFF shape, is in one of three groups:
#   walked by the tool:    PNG (every PNG Pillow decodes has its image data, and each animation frame's, inflated and measured against
#                          what its rows need: png_check); JPEG, the first picture of the file (its coded data walked block by block:
#                          jpeg_check); TIFF pages whose shape is on the allowlist in tiff_check: uncompressed (as many pieces as its size needs, byte counts against
#                          the rows, Pillow's own decoder) and JPEG (each strip or tile walked as a JPEG, its frame the strip's or
#                          tile's size).
#   shown to raise:        GIF and BMP (and BMP's RLE) data cut short; WebP cut short; TIFF pages coded with LZW, either Deflate or
#                          PackBits in photometric 0 to 3 with one of strip or tile tags (Pillow reads them strip by strip through
#                          libtiff, which fails the read on a strip that does not decode).
#   counted as not walked: every other TIFF shape (any other codec, YCbCr or another photometric that sends Pillow to libtiff's RGBA
#                          interface, which fills and only prints, a tag named twice, strip and tile tags together, a directory the walk
#                          cannot follow); the pictures of a JPEG past its first (MPO).
# Under all three, a safety net that does not depend on parsing: the child's standard error (where libtiff, and libjpeg and zlib under
# it, print what they could not decode) is read, its first DECODER_SAID_BYTES kept, and any line on it but a note on a tag libtiff does
# not know makes the frame damaged. A known limit: WebP and BMP data whose tail is zeroed, which decodes as zeros without a word.
import resource as _resource
import select as _decode_select

PILLOW_FORMATS = ("PNG", "JPEG", "BMP", "GIF", "WEBP", "TIFF")     # a JPEG of several pictures (MPO) is opened by the JPEG plugin
PILLOW_FORMAT_NAMES = "PNG, JPEG, BMP, GIF, WebP and TIFF"
MAX_ROWS = 100_000                 # a picture higher than this is refused: each row is one object, and a picture one pixel wide would take gigabytes
MAX_JPEG_SCANS = int(os.environ.get("TOOL_MAX_JPEG_SCANS") or 256)        # the environment variable is for the tests
DECODE_MEMORY = 1 << 30            # what the decoding child may add to the address space it was forked with (Linux)
DECODER = {"pid": None}            # the decoding child that is running, which the stop's last word and the exit end
DECODER_SAID_BYTES = 1 << 16       # what is kept of the decoding child's standard error (the rest is read and dropped, and counted)
DECODER_QUIET = (b"Unknown field with tag",)   # libtiff's note on a tag it does not know: about the directory, not the image data
DECODER_SAID_BY = "Pillow's decoder (libtiff, or libjpeg or zlib under it)"


def kill_decoder():
    """End the decoding child that is running, if one is, and reap it."""
    pid, DECODER["pid"] = DECODER["pid"], None
    if pid:
        try:
            os.kill(pid, signal.SIGKILL)
        except OSError:
            pass
        try:
            os.waitpid(pid, 0)
        except OSError:
            pass


atexit.register(kill_decoder)


def jpeg_scans(data):
    """The start-of-scan markers of a JPEG (0 for any other format). Inside entropy-coded data a 0xFF byte is always followed by 0x00 or a
    restart marker, so FF DA is a marker wherever it is; one inside an embedded thumbnail is counted too, which only errs on the side of
    refusing."""
    return data.count(b"\xff\xda") if data[:2] == b"\xff\xd8" else 0


# ---- the tool's own walk of a JPEG's coded data ------------------------------------------------------------------------------------
# libjpeg (and so Pillow) takes a JPEG cut short and given its end-of-image marker back (what a carver makes of a fragmented file) as a
# whole picture: it fills the blocks it did not find with grey and only warns, and Pillow does not pass the warning on. So a JPEG Pillow
# decoded is walked here too, block by block through its Huffman codes, and must code every block its frame's size implies.
JPEG_CHECK_SECONDS = 30            # at most this, and half of what the clock has left, for the walk of one picture

class JpegUnchecked(Exception):
    """The tool's own check of a JPEG's coded data does not reach this picture: the text says why (a coding it does not walk, its share
    of the clock)."""


def _jpeg_huffman(counts, symbols):
    """A lookup of 65,536 entries for one Huffman table: (code length << 8) | symbol, 0 where no code begins with those 16 bits; None
    for a table whose codes do not fit their lengths."""
    table = [0] * 65536
    code, at = 0, 0
    for length in range(1, 17):
        for _ in range(counts[length - 1]):
            if code >= (1 << length):
                return None
            span = 1 << (16 - length)
            start = code << (16 - length)
            table[start:start + span] = [(length << 8) | symbols[at]] * span
            code += 1
            at += 1
        code <<= 1
    return table


def _jpeg_pieces(data, at, most, check):
    """The entropy-coded data of one scan from byte `at`: ([(the piece with its stuffed bytes taken out, the restart marker after it or
    None)], the offset of the marker that ends the scan, or None when the file ends first; -1 past `most` pieces). check() is called
    every 4096 bytes 0xFF met."""
    pieces, start, size, met = [], at, len(data), 0
    while True:
        met += 1
        if met % 4096 == 0:
            check(0)
        i = data.find(b"\xff", at)
        if i < 0 or i + 1 >= size:
            return pieces, None
        following = data[i + 1]
        if following == 0x00:
            at = i + 2
            continue
        if following == 0xFF:
            at = i + 1
            continue
        if 0xD0 <= following <= 0xD7:
            pieces.append((data[start:i].replace(b"\xff\x00", b"\xff"), following - 0xD0))
            if len(pieces) > most:
                return pieces, -1
            start = at = i + 2
            continue
        pieces.append((data[start:i].replace(b"\xff\x00", b"\xff"), None))
        return pieces, i


def _jpeg_scan(data, at, frame, scan, ss, se, ah, al, dc, ac, restart, nonzero, lowest, check):
    """Walk one scan's coded data from byte `at`, block by block: the offset of the marker after it, or a sentence saying where the
    data is cut or corrupt."""
    progressive = frame["progressive"]
    layout = frame["layout"]
    if progressive:
        if (ss == 0) != (se == 0) or se > 63 or ss > se or (ss > 0 and len(scan) != 1) or (ah and al != ah - 1) or al > 13:
            return "a progressive scan whose spectral selection or approximation is not one the standard allows"
        for cid, _d, _a in scan:
            for k in range(ss, se + 1):
                if (lowest[cid][k] is not None) if ah == 0 else (lowest[cid][k] != ah):
                    return "a progressive scan that codes coefficients out of order (a scan missing before it, or one repeated)"
    elif ss != 0 or se != 63 or ah or al:
        return "a sequential scan whose spectral selection is not the whole block"
    tables = []
    for cid, d, a in scan:
        need_dc = ss == 0 and ah == 0
        need_ac = se > 0
        if (need_dc and d not in dc) or (need_ac and a not in ac):
            return "a scan of component %d names a Huffman table not defined before it" % cid
        tables.append((cid, dc.get(d), ac.get(a)))
    if len(scan) == 1:
        cid = scan[0][0]
        units = layout[cid]["bw"] * layout[cid]["bh"]
    else:
        units = frame["mcux"] * frame["mcuy"]
    intervals = -(-units // restart) if restart else 1
    pieces, end = _jpeg_pieces(data, at, intervals, check)
    if end is None:
        return "the file ends inside the scan's coded data, with no marker after it"
    if end == -1:
        return "more restart intervals than the scan has blocks"
    if len(pieces) < intervals:
        return ("the coded data ends after %d of the %d restart intervals the frame's size implies (a cut file given its end back)"
                % (len(pieces), intervals))
    if len(pieces) > intervals or pieces[-1][1] is not None:
        return "more restart intervals than the scan has blocks"
    for index, (_piece, number) in enumerate(pieces[:-1]):
        if number != index % 8:
            return "restart marker RST%d where RST%d was due (interval %d of %d)" % (number, index % 8, index + 1, intervals)
    walked = 0
    for index, (piece, _number) in enumerate(pieces):
        count = min(restart, units - index * restart) if restart else units
        found = _jpeg_interval(piece, frame, scan, tables, ss, se, ah, al, nonzero, walked, count, len(scan) == 1, check)
        if found is not None:
            return found
        walked += count
    if progressive:
        for cid, _d, _a in scan:
            for k in range(ss, se + 1):
                lowest[cid][k] = al
    return end


def _ended_or(pos, bits, said):
    """What a walk that went wrong at bit `pos` of `bits` says: that the data ends there (a code that would reach past the last byte) or
    what it found."""
    if pos + 16 > bits:
        return ("the coded data ends before the last unit the frame's size implies (a cut file given its end back: the decoder fills what "
                "follows, it is not read)")
    return said


def _jpeg_interval(piece, frame, scan, tables, ss, se, ah, al, nonzero, first, count, single, check):
    """Walk `count` units (an MCU, or a block of a scan of one component) from unit `first` through one restart interval's data: None,
    or a sentence saying where it is cut or corrupt."""
    buf = piece + b"\x00\x00\x00\x00"
    bits = len(piece) * 8
    pos = 0
    layout = frame["layout"]
    eobrun = 0
    if single:
        cid, dct, act = tables[0]
        geometry = layout[cid]
        plan = None
    else:
        plan = []
        for cid, dct, act in tables:
            g = layout[cid]
            for v in range(g["v"]):
                for h in range(g["h"]):
                    plan.append((dct, act))
    progressive = frame["progressive"]
    for unit in range(first, first + count):
        if unit % 512 == 0:
            check(unit)
        if single:
            blocks = ((dct, act),)
        else:
            blocks = plan
        for dct, act in blocks:
            if not progressive:
                e = dct[(int.from_bytes(buf[pos >> 3:(pos >> 3) + 3], "big") >> (8 - (pos & 7))) & 0xFFFF]
                if not e:
                    return _ended_or(pos, bits, "a code no Huffman table holds, at bit %d of an interval" % pos)
                pos += (e >> 8) + (e & 255)
                k = 1
                while k < 64:
                    e = act[(int.from_bytes(buf[pos >> 3:(pos >> 3) + 3], "big") >> (8 - (pos & 7))) & 0xFFFF]
                    if not e:
                        return _ended_or(pos, bits, "a code no Huffman table holds, at bit %d of an interval" % pos)
                    pos += e >> 8
                    s = e & 15
                    if s:
                        k += ((e & 255) >> 4) + 1
                        pos += s
                    elif (e & 255) == 0xF0:
                        k += 16
                    else:
                        break
                if k > 64:
                    return _ended_or(pos, bits, "a block whose coefficients run past the 64th")
            elif ss == 0:
                if ah:
                    pos += 1
                else:
                    e = dct[(int.from_bytes(buf[pos >> 3:(pos >> 3) + 3], "big") >> (8 - (pos & 7))) & 0xFFFF]
                    if not e:
                        return _ended_or(pos, bits, "a code no Huffman table holds, at bit %d of an interval" % pos)
                    pos += (e >> 8) + (e & 255)
            else:
                cid = scan[0][0]
                g = layout[cid]
                block = (unit // g["bw"]) * g["pw"] + unit % g["bw"]
                marks = nonzero[cid]
                if ah == 0:
                    if eobrun:
                        eobrun -= 1
                        continue
                    k = ss
                    mask = marks[block]
                    while k <= se:
                        e = act[(int.from_bytes(buf[pos >> 3:(pos >> 3) + 3], "big") >> (8 - (pos & 7))) & 0xFFFF]
                        if not e:
                            return _ended_or(pos, bits, "a code no Huffman table holds, at bit %d of an interval" % pos)
                        pos += e >> 8
                        r, s = (e & 255) >> 4, e & 15
                        if s:
                            k += r
                            if k > se:
                                return _ended_or(pos, bits, "a block whose coefficients run past the scan's last")
                            pos += s
                            mask |= 1 << k
                            k += 1
                        elif r == 15:
                            k += 16
                        else:
                            eobrun = (1 << r) - 1
                            if r:
                                eobrun += (int.from_bytes(buf[pos >> 3:(pos >> 3) + 3], "big") >> (24 - (pos & 7) - r)) & ((1 << r) - 1)
                                pos += r
                            break
                    if k > se + 1:
                        return _ended_or(pos, bits, "a block whose coefficients run past the scan's last")
                    marks[block] = mask
                else:
                    k = ss
                    mask = marks[block]
                    if eobrun == 0:
                        while k <= se:
                            e = act[(int.from_bytes(buf[pos >> 3:(pos >> 3) + 3], "big") >> (8 - (pos & 7))) & 0xFFFF]
                            if not e:
                                return _ended_or(pos, bits, "a code no Huffman table holds, at bit %d of an interval" % pos)
                            pos += e >> 8
                            r, s = (e & 255) >> 4, e & 15
                            if s:
                                if s != 1:
                                    return _ended_or(pos, bits, "a refinement code of a size other than one")
                                pos += 1
                            elif r != 15:
                                eobrun = 1 << r
                                if r:
                                    eobrun += (int.from_bytes(buf[pos >> 3:(pos >> 3) + 3], "big") >> (24 - (pos & 7) - r)) & ((1 << r) - 1)
                                    pos += r
                                break
                            while k <= se:
                                if mask >> k & 1:
                                    pos += 1
                                else:
                                    if r == 0:
                                        break
                                    r -= 1
                                k += 1
                            if s:
                                if k > se:
                                    return _ended_or(pos, bits, "a refinement that places a coefficient past the scan's last")
                                mask |= 1 << k
                            k += 1
                    if eobrun > 0:
                        while k <= se:
                            if mask >> k & 1:
                                pos += 1
                            k += 1
                        eobrun -= 1
                    marks[block] = mask
            if pos > bits:
                return ("the coded data ends inside unit %d, before the last the frame's size implies (a cut file given its end back: the "
                        "decoder fills what follows, it is not read)" % (unit + 1))
    if pos > bits:
        return "the coded data ends before the interval's last unit"
    if bits - pos >= 8:
        return "%d bytes of coded data follow the last unit the frame's size implies" % ((bits - pos) // 8)
    return None


def jpeg_check(data, tick, budget):
    """The tool's own walk of a JPEG's entropy-coded data (Huffman-coded, sequential or progressive; ISO/IEC 10918-1 Annexes F and G),
    without decoding a pixel: every scan is walked block by block through its Huffman codes, its restart markers are checked in order,
    and the walk must code every block the frame's size implies before the scan's data ends; the scans must code every component (a
    progressive set: every coefficient of every component to its last bit). Returns None when the data is whole, or a sentence saying
    where it is cut or corrupt (libjpeg, and so Pillow, fills what is missing with grey and goes on). JpegUnchecked for what it does not
    walk, and when `budget()` (seconds the walk may still take) runs out; tick() reads the tool's clock."""
    size = len(data)
    if data[:2] != b"\xff\xd8":
        raise JpegUnchecked("not a JPEG")
    at, dc, ac, frame, restart, scans = 2, {}, {}, None, 0, 0
    nonzero, lowest, sequential = {}, {}, {}

    def check(unit):
        tick()
        if budget() <= 0:
            raise JpegUnchecked("the check's share of the clock ran out in scan %d" % scans)

    while True:
        check(0)
        if at + 2 > size:
            return "the data ends at byte %d without an end-of-image marker" % at
        if data[at] != 0xFF:
            return "at byte %d a marker was expected" % at
        marker = data[at + 1]
        if marker == 0xFF:
            at += 1
            continue
        if marker == 0xD9:
            break
        if 0xD0 <= marker <= 0xD8 or marker == 0x01:
            at += 2
            continue
        if at + 4 > size:
            return "the data ends inside the marker at byte %d" % at
        length = int.from_bytes(data[at + 2:at + 4], "big")
        if length < 2 or at + 2 + length > size:
            return "the segment of marker FF%02X at byte %d runs past the end of the file" % (marker, at)
        body = data[at + 4:at + 2 + length]
        segment_end = at + 2 + length
        if marker in (0xC0, 0xC1, 0xC2):
            if frame is not None:
                raise JpegUnchecked("a JPEG with more than one frame header")
            if len(body) < 6:
                return "a frame header too short"
            height, width, count = int.from_bytes(body[1:3], "big"), int.from_bytes(body[3:5], "big"), body[5]
            if height == 0:
                raise JpegUnchecked("a JPEG whose height is given after its first scan (a DNL marker)")
            if width * height > MAX_PIXELS:
                raise JpegUnchecked("a JPEG whose frame header says %d x %d pixels, more than the %d this tool reads" % (width, height, MAX_PIXELS))
            if width == 0 or count == 0 or len(body) < 6 + 3 * count:
                return "a frame header that names no size or no component"
            sampling = {}
            for i in range(count):
                cid, factors = body[6 + 3 * i], body[7 + 3 * i]
                if not 1 <= factors >> 4 <= 4 or not 1 <= factors & 15 <= 4:
                    return "a component with a sampling factor out of range"
                sampling[cid] = (factors >> 4, factors & 15)
            hmax = max(h for h, _v in sampling.values())
            vmax = max(v for _h, v in sampling.values())
            mcux, mcuy = -(-width // (8 * hmax)), -(-height // (8 * vmax))
            layout = {}
            for cid, (h, v) in sampling.items():
                cw, ch = -(-width * h // hmax), -(-height * v // vmax)
                layout[cid] = {"h": h, "v": v, "bw": -(-cw // 8), "bh": -(-ch // 8), "pw": mcux * h, "ph": mcuy * v}
            frame = {"progressive": marker == 0xC2, "layout": layout, "mcux": mcux, "mcuy": mcuy}
            for cid in sampling:
                sequential[cid] = 0
                lowest[cid] = [None] * 64
                if frame["progressive"]:
                    nonzero[cid] = array.array("Q", bytes(8 * layout[cid]["pw"] * layout[cid]["ph"]))
        elif 0xC3 <= marker <= 0xCF and marker not in (0xC4, 0xC8):
            raise JpegUnchecked("a JPEG coded in a way the check does not walk (marker FF%02X: lossless, hierarchical or arithmetic coding)" % marker)
        elif marker == 0xC4:
            p = 0
            while p < len(body):
                if p + 17 > len(body):
                    return "a Huffman table segment cut short"
                kind, index = body[p] >> 4, body[p] & 15
                counts = list(body[p + 1:p + 17])
                total = sum(counts)
                if p + 17 + total > len(body) or kind > 1 or index > 3:
                    return "a Huffman table segment that does not hold its table"
                table = _jpeg_huffman(counts, body[p + 17:p + 17 + total])
                if table is None:
                    return "a Huffman table whose codes do not fit their lengths"
                (dc if kind == 0 else ac)[index] = table
                p += 17 + total
        elif marker == 0xDD:
            if len(body) < 2:
                return "a restart interval segment too short"
            restart = int.from_bytes(body[:2], "big")
        elif marker == 0xDA:
            if frame is None:
                return "a scan before the frame header"
            ns = body[0] if body else 0
            if ns < 1 or ns > 4 or len(body) < 1 + 2 * ns + 3:
                return "a scan header that does not hold its components"
            scan = []
            for i in range(ns):
                cid, chosen = body[1 + 2 * i], body[2 + 2 * i]
                if cid not in frame["layout"]:
                    return "a scan of a component the frame does not have"
                scan.append((cid, chosen >> 4, chosen & 15))
            ss, se, ah, al = body[1 + 2 * ns], body[2 + 2 * ns], body[3 + 2 * ns] >> 4, body[3 + 2 * ns] & 15
            scans += 1
            found = _jpeg_scan(data, segment_end, frame, scan, ss, se, ah, al, dc, ac, restart, nonzero, lowest, check)
            if isinstance(found, str):
                return "scan %d: %s" % (scans, found)
            for cid, _d, _a in scan:
                sequential[cid] += 1
            at = found
            continue
        at = segment_end
    if frame is None:
        return "no frame header before the end-of-image marker"
    if scans == 0:
        return "no scan before the end-of-image marker"
    for cid in frame["layout"]:
        if frame["progressive"]:
            missing = sum(1 for k in range(64) if lowest[cid][k] != 0)
            if missing:
                return ("the scans end before every coefficient of component %d is coded to its last bit (%d of 64 are not): the data "
                        "that follows was not there to read" % (cid, missing))
        elif sequential[cid] == 0:
            return "component %d is in no scan before the end-of-image marker" % cid
        elif sequential[cid] > 1:
            return "component %d is in more than one sequential scan" % cid
    return None

# ---- the tool's own walk of a TIFF's strips and tiles ------------------------------------------------------------------------------
# libtiff hands a strip or tile of JPEG data (TIFF compression 7, and the old style, 6) to libjpeg, which takes one cut short and given its
# end marker back as whole, fills what is missing with grey and only warns; a JPEG strip whose frame is smaller than the strip leaves the
# rows it lacks unwritten. Pillow reads an uncompressed strip or tile itself, at its offset, for the bytes its rows need, whatever its
# byte count says (one of byte count 0, a strip the file does not hold, is read from wherever its offset points). libtiff's RGBA
# interface, which Pillow uses for YCbCr pages (but JPEG-coded ones of one plane), fills a strip that does not decode and only prints.
# So a TIFF Pillow decoded is walked here too, page by page, as many pages as are searched, and a page passes only when its shape is
# one the walk sees as libtiff and Pillow do (an allowlist): no tag named twice in its directory (Pillow keeps the last copy, libtiff
# the first), the tags of a size or a coding given once, strip tags or tile tags but not both (Pillow's own decoder takes the strips,
# the walk would take the tiles), and one of: uncompressed (1) in photometric 0, 1, 2, 3 or 5, whose strips or tiles must hold the bytes
# their rows need; JPEG (7) in photometric 0, 1, 2 or 6, of one plane, each strip or tile walked as a JPEG (the page's JPEGTables put
# before its own data) whose frame is the strip's or tile's size with a component for each sample; or LZW, Deflate (either) or
# PackBits in photometric 0 to 3, which Pillow reads strip by strip through libtiff and which fail the read on data that does not
# decode. Every other page is counted as not walked.
TIFF_MAGICS = (b"II*\x00", b"MM\x00*", b"II+\x00", b"MM\x00+")
TIFF_TYPE_SIZES = {1: 1, 2: 1, 3: 2, 4: 4, 5: 8, 6: 1, 7: 1, 8: 2, 9: 4, 10: 8, 11: 4, 12: 8, 13: 4, 16: 8, 17: 8, 18: 8}
TIFF_TAGS = (256, 257, 258, 259, 262, 273, 277, 278, 279, 284, 322, 323, 324, 325, 347)
TIFF_SINGLE_TAGS = (256, 257, 259, 262, 277, 278, 284, 322, 323)    # tags of one value: a page that gives more is not walked
MAX_TIFF_PIECES = 1 << 20          # the strips or tiles of one page that are walked; a page with more is not walked


def _tiff_pages(data, most, tick):
    """The directories of a TIFF (classic or BigTIFF) in the order of their chain, up to `most`, the clock read as they are read: each a
    pair (a dict of the TIFF_TAGS it holds, tag -> list of numbers (JPEGTables -> its bytes); the tags, of any number, its directory
    names more than once). JpegUnchecked when the chain cannot be followed."""
    order = "little" if data[:2] == b"II" else "big"
    big = data[2:4] in (b"+\x00", b"\x00+")
    size = len(data)

    def number(at, width):
        if at < 0 or at + width > size:
            raise JpegUnchecked("the TIFF's directory points past the end of the file (byte %d)" % at)
        return int.from_bytes(data[at:at + width], order)

    word, entry, head = (8, 20, 8) if big else (4, 12, 2)
    offset = number(8, 8) if big else number(4, 4)
    pages, seen = [], set()
    while offset and len(pages) < most:
        if offset in seen:
            break                           # a chain that comes back to a directory ends there (Pillow stops there too)
        seen.add(offset)
        count = number(offset, head)
        if offset + head + count * entry + word > size:
            raise JpegUnchecked("the TIFF's directory %d runs past the end of the file" % (len(pages) + 1))
        tags, named, twice = {}, set(), set()
        for i in range(count):
            if i % 1024 == 0:
                tick()
            at = offset + head + i * entry
            tag, kind, n = number(at, 2), number(at + 2, 2), number(at + 4, word)
            if tag in named:
                twice.add(tag)
            named.add(tag)
            if tag not in TIFF_TAGS or tag in twice:
                continue
            width = TIFF_TYPE_SIZES.get(kind)
            if width is None:
                raise JpegUnchecked("tag %d of page %d is of the type %d, which the walk does not take" % (tag, len(pages) + 1, kind))
            if n > MAX_TIFF_PIECES and tag != 347:
                raise JpegUnchecked("tag %d of page %d holds %d values, more than the %d the walk takes" % (tag, len(pages) + 1, n, MAX_TIFF_PIECES))
            where = at + 4 + word if n * width <= word else number(at + 4 + word, word)
            if where + n * width > size:
                raise JpegUnchecked("tag %d of page %d runs past the end of the file" % (tag, len(pages) + 1))
            if tag == 347:
                tags[tag] = data[where:where + n * width]
            else:
                values = []
                for k in range(n):
                    if k % 65536 == 0:
                        tick()
                    values.append(number(where + k * width, width))
                tags[tag] = values
        pages.append((tags, sorted(twice)))
        offset = number(offset + head + count * entry, word)
    return pages


def _tiff_needs(tags, tiled, pieces):
    """For an uncompressed page: the bytes Pillow reads for each of its strips or tiles (a function of the piece's index), and the pieces
    it reads at all (a page of one strip that covers it is read from its last offset alone, as Pillow does)."""
    width, height = (tags.get(256) or [0])[0], (tags.get(257) or [0])[0]
    samples = (tags.get(277) or [1])[0]
    depths = tags.get(258) or [1]
    planar = (tags.get(284) or [1])[0] == 2
    bits = depths[0] if planar else (sum(depths) if len(depths) == samples else depths[0] * samples)
    if tiled:
        across, down = (tags.get(322) or [0])[0], (tags.get(323) or [0])[0]
    else:
        across, down = width, (tags.get(278) or [height])[0]
    if not width or not height or not across or not down or not bits:
        raise JpegUnchecked("an uncompressed page whose size, strips or tiles are not given")
    per_row = -(-width // across)
    per_plane = per_row * -(-height // down)
    stride = -(-across * bits // 8)
    expected = per_plane * (samples if planar else 1)
    if pieces != expected:
        # Pillow's decoder sets up one tile for each offset the directory names and writes nothing for the rest: the rows no piece holds stay
        # black, with no error and nothing on stderr.
        raise JpegUnchecked("an uncompressed page holds %d %s%s where its size needs %d; the walk does not take it" % (
            pieces, "tile" if tiled else "strip", "" if pieces == 1 else "s", expected))

    def need(k):
        k %= per_plane
        x, y = (k % per_row) * across, (k // per_row) * down
        rows = max(0, min(down, height - y))
        return 0 if rows == 0 else (rows - 1) * stride + -(-min(across, width - x) * bits // 8)

    read = range(pieces - 1, pieces) if across == width and down == height and not planar else range(pieces)
    return need, read


def _jpeg_frame(data):
    """The frame header of a JPEG stream: (height, width, components), or None when no frame header comes before its first scan."""
    at, size = 2, len(data)
    while at + 4 <= size:
        if data[at] != 0xFF:
            return None
        marker = data[at + 1]
        if marker == 0xFF:
            at += 1
            continue
        if marker in (0xD8, 0xD9, 0xDA):
            return None
        if 0xD0 <= marker <= 0xD7 or marker == 0x01:
            at += 2
            continue
        length = int.from_bytes(data[at + 2:at + 4], "big")
        if 0xC0 <= marker <= 0xCF and marker not in (0xC4, 0xC8, 0xCC):
            body = data[at + 4:at + 2 + length]
            if length < 8 or len(body) < 6:
                return None
            return int.from_bytes(body[1:3], "big"), int.from_bytes(body[3:5], "big"), body[5]
        at += 2 + length
    return None


# The TIFF codecs whose decoder in Pillow's libtiff was shown to raise on a cut or damaged strip when Pillow reads the page strip by
# strip (LZW, Adobe and zlib Deflate, PackBits): their pages need no walk of their own, in the photometric interpretations that keep
# Pillow off libtiff's RGBA interface. Every other codec but none (1) and JPEG (7), which the walk takes, is counted as not walked:
# CCITT (2, 3, 4) fills a damaged strip and says nothing.
TIFF_CODECS_THAT_RAISE = (5, 8, 32773, 32946)
TIFF_PHOTOMETRIC_STRIP_BY_STRIP = (0, 1, 2, 3)      # grey (either way), RGB, palette: not YCbCr (6), which Pillow reads through RGBA
TIFF_PHOTOMETRIC_UNCOMPRESSED = (0, 1, 2, 3, 5)     # Pillow's own decoder, the bytes of whose rows the walk counts (5: CMYK)
TIFF_PHOTOMETRIC_JPEG = (0, 1, 2, 6)                # libjpeg's frame of one plane, YCbCr given back as RGB by libjpeg itself
TIFF_STRIP_TAGS, TIFF_TILE_TAGS = (273, 278, 279), (322, 323, 324, 325)


def tiff_check(data, pages, tick, budget):
    """The tool's own walk of the strips and tiles of a TIFF's first `pages` pages (see above). Returns None when every page is of a
    shape the walk takes and every strip and tile Pillow reads holds what its rows need, or a sentence saying where one does not.
    JpegUnchecked for every page of a shape the allowlist does not hold (old-style JPEG, another codec, a photometric interpretation
    that sends Pillow to libtiff's RGBA interface, a tag named twice, strip and tile tags together, a directory it cannot follow, a
    JPEG coding the JPEG walk does not take) and when `budget()` (seconds the walk may still take) runs out; tick() reads the clock."""
    for page, (tags, twice) in enumerate(_tiff_pages(data, pages, tick), 1):
        if twice:
            raise JpegUnchecked("page %d names tag%s %s more than once in its directory (Pillow reads the last copy, libtiff the first); "
                                "the walk does not take it" % (page, "s" if len(twice) > 1 else "", ", ".join(str(t) for t in twice[:8])))
        for tag in TIFF_SINGLE_TAGS:
            if tag in tags and len(tags[tag]) != 1:
                raise JpegUnchecked("page %d gives tag %d %d values where it takes one; the walk does not take it" % (page, tag, len(tags[tag])))
        compression = (tags.get(259) or [1])[0]
        photometric = (tags.get(262) or [0])[0]
        planar = (tags.get(284) or [1])[0]
        stripped, tiled = any(t in tags for t in TIFF_STRIP_TAGS), any(t in tags for t in TIFF_TILE_TAGS)
        if stripped and tiled:
            raise JpegUnchecked("page %d holds both strip and tile tags (Pillow's decoder and libtiff may read different ones); the walk "
                                "does not take it" % page)
        if compression == 6:
            raise JpegUnchecked("page %d is coded as old-style JPEG (TIFF compression 6), whose data the walk does not take" % page)
        if compression in TIFF_CODECS_THAT_RAISE:
            if photometric not in TIFF_PHOTOMETRIC_STRIP_BY_STRIP:
                raise JpegUnchecked("page %d is coded with TIFF compression %d in photometric interpretation %d, which Pillow reads through "
                                    "libtiff's RGBA interface; that fills a strip that does not decode and only prints; the walk does not "
                                    "take it" % (page, compression, photometric))
            continue
        if compression not in (1, 7):
            raise JpegUnchecked("page %d is coded with TIFF compression %d, whose decoder may fill a cut strip and only warn; the walk does "
                                "not take it" % (page, compression))
        if photometric not in (TIFF_PHOTOMETRIC_UNCOMPRESSED if compression == 1 else TIFF_PHOTOMETRIC_JPEG) or (compression == 7 and planar != 1):
            raise JpegUnchecked("page %d is coded with TIFF compression %d in photometric interpretation %d%s, which the walk does not "
                                "take" % (page, compression, photometric, "" if planar == 1 else " in separate planes"))
        what = "tile" if tiled else "strip"
        offsets, counts = tags.get(324 if tiled else 273), tags.get(325 if tiled else 279)
        if not offsets or counts is None or len(offsets) != len(counts):
            raise JpegUnchecked("page %d: its %s offsets and byte counts do not pair" % (page, what))
        if compression == 1:
            need, read = _tiff_needs(tags, tiled, len(offsets))
            for k in read:
                if k % 1024 == 0:
                    tick()
                if counts[k] < need(k):
                    return ("page %d, %s %d of uncompressed data: its byte count is %d and its rows need %d (Pillow reads them from the "
                            "file at its offset all the same)" % (page, what, k + 1, counts[k], need(k)))
            continue
        width, height, samples = (tags.get(256) or [0])[0], (tags.get(257) or [0])[0], (tags.get(277) or [1])[0]
        if tiled:
            across, down = (tags.get(322) or [0])[0], (tags.get(323) or [0])[0]
        else:
            across, down = width, min(height, (tags.get(278) or [height])[0])
        if not width or not height or not across or not down:
            raise JpegUnchecked("page %d: a JPEG page whose size, strips or tiles are not given" % page)
        per_row = -(-width // across)
        expected = per_row * -(-height // down)
        if len(offsets) != expected:
            raise JpegUnchecked("page %d holds %d %ss of JPEG data where its size needs %d; the walk does not take it" % (page, len(offsets), what, expected))
        tables = tags.get(347)
        if tables is not None and (tables[:2] != b"\xff\xd8" or tables[-2:] != b"\xff\xd9"):
            raise JpegUnchecked("page %d: its JPEGTables are not a JPEG of tables (start and end markers)" % page)
        for k, (start, length) in enumerate(zip(offsets, counts)):
            tick()
            if budget() <= 0:
                raise JpegUnchecked("the walk's share of the clock ran out at page %d, %s %d" % (page, what, k + 1))
            if length == 0 or start + length > len(data):
                return "page %d, %s %d of JPEG data: it is not in the file (byte count %d at byte %d)" % (page, what, k + 1, length, start)
            piece = data[start:start + length]
            if piece[:2] != b"\xff\xd8":
                raise JpegUnchecked("page %d, %s %d of JPEG data does not begin with a start-of-image marker" % (page, what, k + 1))
            stream = tables[:-2] + piece[2:] if tables else piece
            frame = _jpeg_frame(stream)
            if frame is None:
                raise JpegUnchecked("page %d, %s %d of JPEG data: no frame header before its first scan" % (page, what, k + 1))
            rows = down if tiled else min(down, height - (k // per_row) * down)
            if frame != (rows, across, samples):
                if frame[1:] == (across, samples) and 0 < frame[0] < rows:
                    return ("page %d, %s %d of JPEG data: its frame is %d rows high where the %s is %d (libtiff leaves the rows it lacks "
                            "unwritten)" % (page, what, k + 1, frame[0], what, rows))
                raise JpegUnchecked("page %d, %s %d of JPEG data: its frame is %d x %d pixels of %d component(s) where the %s is %d x %d of "
                                    "%d sample(s); the walk does not take it" % (page, what, k + 1, frame[1], frame[0], frame[2], what, across, rows, samples))
            try:
                found = jpeg_check(stream, tick, budget)
            except JpegUnchecked as exc:
                raise JpegUnchecked("page %d, %s %d of JPEG data: %s" % (page, what, k + 1, exc))
            if found is not None:
                return "page %d, %s %d of JPEG data: %s" % (page, what, k + 1, found)
    return None


# ---- the tool's own measure of a PNG's image data ----------------------------------------------------------------------------------
# Pillow takes a zlib stream that ends before the rows do as the end of the picture and fills the rows it did not get, and says nothing.
# So every PNG handed to Pillow, whatever the built-in reader said of it, has its image data measured here, as Pillow reads it: the
# header's first 13 bytes (Pillow takes a longer header chunk), the run of IDAT chunks that begins at the first one (Pillow reads no
# IDAT after another chunk), and each animation frame's run of fdAT chunks after its fcTL. The data is inflated a piece at a time and
# dropped, never held.
PNG_CHANNELS = {0: 1, 2: 3, 3: 1, 4: 2, 6: 4}
PNG_DEPTHS = {0: (1, 2, 4, 8, 16), 2: (8, 16), 3: (1, 2, 4, 8), 4: (8, 16), 6: (8, 16)}


def _png_data_length(width, height, channels, depth, interlace):
    """The bytes a PNG image of this size and form inflates to: its rows, each with its filter byte, or the rows of its seven passes."""
    if not interlace:
        return height * (1 + (width * channels * depth + 7) // 8)
    want = 0
    for x0, y0, dx, dy in ((0, 0, 8, 8), (4, 0, 8, 8), (0, 4, 4, 8), (2, 0, 4, 4), (0, 2, 2, 4), (1, 0, 2, 2), (0, 1, 1, 2)):
        pass_width, pass_height = (width - x0 + dx - 1) // dx, (height - y0 + dy - 1) // dy
        if pass_width > 0 and pass_height > 0:
            want += pass_height * (1 + (pass_width * channels * depth + 7) // 8)
    return want


def png_check(data, pages, tick, budget):
    """The tool's own measure of a PNG's image data (see above), and of the data of up to `pages` animation frames after it. Returns None
    when each inflates to every byte its rows need, or a sentence saying which does not. JpegUnchecked for chunks that cannot be walked
    as Pillow reads them, and when `budget()` runs out; tick() reads the tool's clock."""
    def check():
        tick()
        if budget() <= 0:
            raise JpegUnchecked("the measure's share of the clock ran out")

    at, size, header, image, closed, frames, previous, chunks = 8, len(data), None, None, False, [], None, 0
    while at + 8 <= size:
        chunks += 1
        if chunks % 1024 == 0:
            check()
        length = int.from_bytes(data[at:at + 4], "big")
        kind = data[at + 4:at + 8]
        body = data[at + 8:min(size, at + 8 + length)]
        if kind == b"IHDR":
            if header is not None:
                raise JpegUnchecked("a PNG with a second header chunk")
            if length < 13 or len(body) < 13:
                raise JpegUnchecked("a PNG whose header chunk is %d bytes (it takes 13)" % length)
            header = struct.unpack(">IIBBBBB", body[:13])
        elif kind == b"IDAT":
            if image is None:
                image = [body]
            elif not closed:
                image.append(body)
        elif kind == b"fcTL" and image is not None and len(frames) < pages:
            if len(body) < 12:
                raise JpegUnchecked("a PNG whose frame control chunk is cut")
            frames.append((int.from_bytes(body[4:8], "big"), int.from_bytes(body[8:12], "big"), []))
        elif kind == b"fdAT" and frames and previous in (b"fcTL", b"fdAT") and len(body) > 4:
            frames[-1][2].append(body[4:])
        elif kind == b"IEND":
            break
        if image is not None and kind != b"IDAT":
            closed = True
        previous = kind
        at += 12 + length
    if header is None or image is None:
        raise JpegUnchecked("a PNG with no header or no image data before its end")
    width, height, depth, colour, _compression, _filter, interlace = header
    channels = PNG_CHANNELS.get(colour)
    if channels is None or depth not in PNG_DEPTHS[colour] or not 0 < width * height <= MAX_PIXELS:
        raise JpegUnchecked("a PNG of %d x %d pixels, colour type %d at %d bits, which the measure does not take" % (width, height, colour, depth))
    try:
        want = _png_data_length(width, height, channels, depth, interlace)
        got = _inflated_length(image, want, check)
        if got < want:
            return "its image data (IDAT) inflates to %d of the %d bytes its rows need" % (got, want)
        for number, (frame_width, frame_height, parts) in enumerate(frames, 1):
            if not 0 < frame_width * frame_height <= MAX_PIXELS:
                raise JpegUnchecked("animation frame %d after the image data is %d x %d pixels, which the measure does not take" % (number, frame_width, frame_height))
            want = _png_data_length(frame_width, frame_height, channels, depth, interlace)
            got = _inflated_length(parts, want, check)
            if got < want:
                return "animation frame %d after the image data (fdAT) inflates to %d of the %d bytes its rows need" % (number, got, want)
    except NotAPicture as exc:
        return str(exc)
    return None


def walk_coded_data(data, picture, tick, pages):
    """The tool's own walk of a picture Pillow decoded, for the formats whose decoder fills a cut picture and says nothing: a JPEG's coded
    data (its first picture), a TIFF's strips and tiles (its first `pages` pages) and a PNG's image data (and its first `pages` animation
    frames'). It sets picture.damage and picture.damage_by when the walk finds the data cut or corrupt, picture.unchecked when the walk
    does not reach it; a picture of another format (GIF, BMP, WebP: their decoders raise on data cut short) is left as it is. The walk
    takes at most JPEG_CHECK_SECONDS and half of what the clock has left."""
    if data[:2] == b"\xff\xd8":
        walk, by = jpeg_check, "the tool's own walk of the JPEG's coded data"
    elif data[:4] in TIFF_MAGICS:
        walk, by = (lambda whole, read_clock, left: tiff_check(whole, pages, read_clock, left)), "the tool's own walk of the TIFF's strips and tiles"
    elif data[:8] == PNG_MAGIC:
        walk, by = (lambda whole, read_clock, left: png_check(whole, pages, read_clock, left)), "the tool's own measure of the PNG's image data"
    else:
        return
    until = time.monotonic() + min(JPEG_CHECK_SECONDS, max(0.5, (clock_deadline() - time.monotonic()) / 2.0 if clock_deadline() is not None else JPEG_CHECK_SECONDS))
    try:
        found = walk(data, tick or (lambda: None), lambda: until - time.monotonic())
    except JpegUnchecked as exc:
        picture.unchecked = str(exc)
    else:
        if found is not None:
            picture.damage, picture.damage_by = found, by


def _send(fd, kind, body=b""):
    for part in (kind + len(body).to_bytes(4, "big"), body):
        view = memoryview(part)
        while len(view):
            view = view[os.write(fd, view[:1 << 20]):]


def _bound_decoder(parent):
    deadline = clock_deadline()
    if deadline is not None:
        cpu = int(max(1.0, deadline - time.monotonic())) + 2
        try:
            _resource.setrlimit(_resource.RLIMIT_CPU, (cpu, cpu + 1))
        except (ValueError, OSError, AttributeError):
            pass
    if sys.platform.startswith("linux"):
        try:
            with open("/proc/self/status", "rb") as status:
                size = next(int(line.split()[1]) for line in status if line.startswith(b"VmSize:")) * 1024
            _hard = _resource.getrlimit(_resource.RLIMIT_AS)[1]
            limit = size + DECODE_MEMORY
            _resource.setrlimit(_resource.RLIMIT_AS, (limit if _hard == _resource.RLIM_INFINITY else min(limit, _hard), _hard))
        except Exception:  # noqa: BLE001 - the clock still bounds the child
            pass
        try:
            import ctypes
            ctypes.CDLL(None).prctl(1, signal.SIGKILL)       # PR_SET_PDEATHSIG: the child dies with the tool
            if os.getppid() != parent:                       # the tool was gone before the request was made (the tool can be pid 1)
                os._exit(1)
        except Exception:  # noqa: BLE001
            pass


def _decode_frames(data, image_module, fd, frames):
    import io
    k = 0
    with warnings.catch_warnings():
        warnings.simplefilter("error")         # a decompression-bomb warning is an error, as in the tool
        try:
            image = image_module.open(io.BytesIO(data), formats=PILLOW_FORMATS)
        except Exception as exc:  # noqa: BLE001 - the class is sent, never the message
            _send(fd, b"U" if type(exc).__name__ == "UnidentifiedImageError" else b"X", json.dumps({"frame": 0, "class": type(exc).__name__}).encode("ascii"))
            return
        try:
            while True:
                width, height = image.size
                _send(fd, b"H", struct.pack(">II", width, height))
                if width * height > MAX_PIXELS or height > MAX_ROWS:
                    return                     # the tool refuses it by the size it was sent
                image.load()
                frame = image
                if frame.mode in ("RGBA", "LA", "PA") or "transparency" in frame.info:
                    frame = frame.convert("RGBA")
                    flat = image_module.new("RGB", frame.size, (255, 255, 255))
                    flat.paste(frame, mask=frame.split()[3])
                    frame = flat
                _send(fd, b"F", frame.convert("L").tobytes())
                k += 1
                try:
                    image.seek(k)
                except EOFError:
                    _send(fd, b"E", struct.pack(">I", k))
                    return
                if k >= frames:
                    _send(fd, b"M", struct.pack(">I", k))
                    return
        except Exception as exc:  # noqa: BLE001 - the class is sent, never the message
            _send(fd, b"X", json.dumps({"frame": k, "class": type(exc).__name__}).encode("ascii"))


def _decoder_child(data, image_module, fd, frames, parent, said_fd):
    """The forked child: it never returns. Its standard error is `said_fd`, the pipe on which the tool reads what libtiff, libjpeg and
    zlib print there; its standard input and output are /dev/null."""
    code = 0
    try:
        for signum in (signal.SIGTERM, signal.SIGINT, signal.SIGHUP):
            signal.signal(signum, signal.SIG_DFL)
        try:
            signal.pthread_sigmask(signal.SIG_SETMASK, set())
        except (AttributeError, ValueError, OSError):
            pass
        null = os.open(os.devnull, os.O_RDWR)
        for target in (0, 1):
            os.dup2(null, target)
        os.dup2(said_fd, 2)
        _bound_decoder(parent)
        _decode_frames(data, image_module, fd, frames)
    except BaseException as exc:  # noqa: BLE001 - nothing may return into the tool's own code
        try:
            _send(fd, b"X", json.dumps({"frame": None, "class": type(exc).__name__}).encode("ascii"))
        except BaseException:  # noqa: BLE001
            code = 1
    finally:
        os._exit(code)


class PillowFrames:
    """The frames of one picture as Pillow decodes them in a child. next_frame() is the next frame as a Picture, or None when there is no
    other: then `total` is how many frames the picture has, or `more` is True when it has more than were asked for. NotAPicture when
    Pillow does not read it (or a frame of it), Clock when the clock runs out first; either way the child is ended. `check(width, height)`
    may refuse a frame by its size before its rows are taken. close() ends the child. The child's standard error is read as its frames
    are: a frame before whose rows the child printed a line there (a decoder's warning or error) comes with that line in its `damage`."""

    def __init__(self, data, image_module, frames, check=None):
        self.total, self.more, self.check, self.k, self.buf, self.pid, self.fd = None, False, check, 0, bytearray(), None, None
        self.said, self.said_fd, self.said_dropped, self.said_seen, self.said_dropped_seen = bytearray(), None, 0, 0, 0
        said_read, said_write = os.pipe()
        try:
            read_fd, write_fd = os.pipe()
        except OSError:
            os.close(said_read)
            os.close(said_write)
            raise
        stops = (signal.SIGTERM, signal.SIGINT, signal.SIGHUP)
        try:
            before = signal.pthread_sigmask(signal.SIG_BLOCK, stops)   # a stop between the fork and the child's own handlers waits
        except (AttributeError, ValueError, OSError):
            before = None
        parent = os.getpid()
        try:
            pid = os.fork()
        except OSError as exc:
            for end in (read_fd, write_fd, said_read, said_write):
                os.close(end)
            if before is not None:
                signal.pthread_sigmask(signal.SIG_SETMASK, before)
            raise NotAPicture("Pillow decodes in a child process here, and none could be started (%s)" % describe(exc))
        if pid == 0:
            os.close(read_fd)
            os.close(said_read)
            _decoder_child(data, image_module, write_fd, frames, parent, said_write)
        DECODER["pid"] = self.pid = pid
        os.close(write_fd)
        os.close(said_write)
        self.fd, self.said_fd = read_fd, said_read
        if before is not None:
            signal.pthread_sigmask(signal.SIG_SETMASK, before)

    def close(self, kill=True):
        """End the child (kill, or wait up to a second for one that has said its last) and reap it: its wait status, or None."""
        status, pid, self.pid = None, self.pid, None
        if pid:
            if DECODER["pid"] == pid:
                DECODER["pid"] = None
            try:
                if not kill:
                    for _wait in range(100):
                        done, status = os.waitpid(pid, os.WNOHANG)
                        if done:
                            break
                        time.sleep(0.01)
                    else:
                        kill = True
                if kill:
                    try:
                        os.kill(pid, signal.SIGKILL)
                    except OSError:
                        pass
                    _done, status = os.waitpid(pid, 0)
            except OSError:
                pass
        if self.fd is not None:
            os.close(self.fd)
            self.fd = None
        if self.said_fd is not None:
            os.close(self.said_fd)
            self.said_fd = None
        return status

    def _read_said(self):
        """Read once from the child's standard error: the first DECODER_SAID_BYTES are kept, the rest counted and dropped."""
        block = os.read(self.said_fd, 1 << 16)
        if not block:
            os.close(self.said_fd)
            self.said_fd = None
            return
        room = max(0, DECODER_SAID_BYTES - len(self.said))
        self.said += block[:room]
        self.said_dropped += len(block) - min(room, len(block))

    def _decoder_said(self):
        """What the child printed on its standard error since the last call, read to what is there now: (lines, first line), or None
        when it printed nothing but notes on tags libtiff does not know. The child writes there before it sends the frame's rows, so
        what it printed while it decoded a frame is there when the rows have come."""
        for _read in range(256):
            if self.said_fd is None or not _decode_select.select([self.said_fd], [], [], 0)[0]:
                break
            self._read_said()
        text, self.said_seen = bytes(self.said[self.said_seen:]), len(self.said)
        dropped, self.said_dropped_seen = self.said_dropped - self.said_dropped_seen, self.said_dropped
        lines = [line.strip() for line in text.splitlines() if line.strip() and not any(quiet in line for quiet in DECODER_QUIET)]
        if dropped:
            lines.append(b"(%d more bytes past the %d kept)" % (dropped, DECODER_SAID_BYTES))
        if not lines:
            return None
        return len(lines), printable(lines[0].decode("utf-8", "replace"))

    def _fill(self, need):
        while len(self.buf) < need:
            deadline = clock_deadline()
            wait = 1.0 if deadline is None else deadline - time.monotonic()
            if wait <= 0:
                raise Clock()
            watched = [self.fd] if self.said_fd is None else [self.fd, self.said_fd]
            ready = _decode_select.select(watched, [], [], min(wait, 1.0))[0]
            if self.said_fd is not None and self.said_fd in ready:
                self._read_said()
            if self.fd not in ready:
                continue
            block = os.read(self.fd, max(1 << 16, min(need - len(self.buf), 1 << 22)))
            if not block:
                return False
            self.buf += block
        return True

    def _ended(self):
        status = self.close(kill=False)
        if status is not None and os.WIFSIGNALED(status):
            return ("Pillow's decoding process was ended by signal %d before it answered (past its bound of memory or of CPU time, or a "
                    "fault in a decoder)" % os.WTERMSIG(status))
        return "Pillow's decoding process ended without an answer (exit code %s)" % (os.WEXITSTATUS(status) if status is not None and os.WIFEXITED(status) else "unknown")

    def _message(self):
        if not self._fill(5):
            raise NotAPicture(self._ended())
        kind, length = bytes(self.buf[:1]), int.from_bytes(self.buf[1:5], "big")
        if length > MAX_PIXELS + 4096 or not self._fill(5 + length):
            raise NotAPicture(self._ended())
        body = bytes(self.buf[5:5 + length])
        del self.buf[:5 + length]
        return kind, body

    def _refusal(self, kind, body):
        try:
            said = json.loads(body.decode("ascii"))
            frame, name = said.get("frame"), str(said.get("class"))[:80]
        except (ValueError, UnicodeDecodeError, AttributeError):
            frame, name = None, "an unreadable report"
        if kind == b"U":
            return "Pillow does not read it as a picture of the formats this tool hands it (%s: %s)" % (PILLOW_FORMAT_NAMES, name)
        if frame:
            return "Pillow does not read frame %d (%s)" % (frame + 1, name)
        return "Pillow does not read it as a picture (%s)" % name

    def next_frame(self):
        if self.total is not None or self.more or self.pid is None:
            return None
        try:
            kind, body = self._message()
            if kind in (b"E", b"M"):
                if kind == b"E":
                    self.total = int.from_bytes(body, "big")
                else:
                    self.more = True
                self.close(kill=False)
                return None
            if kind != b"H" or len(body) != 8:
                raise NotAPicture(self._refusal(kind, body) if kind in (b"U", b"X") else "Pillow's decoding process sent what it should not")
            width, height = struct.unpack(">II", body)
            what = "frame %d is" % (self.k + 1) if self.k else "a picture of"
            if width * height > MAX_PIXELS or width == 0 or height == 0:
                raise NotAPicture("%s %d x %d pixels (this tool reads up to %d pixels)" % (what, width, height, MAX_PIXELS))
            if height > MAX_ROWS:
                raise NotAPicture("%s %d x %d pixels (this tool reads up to %d rows)" % (what, width, height, MAX_ROWS))
            if self.check is not None:
                self.check(width, height)
            kind, body = self._message()
            if kind != b"F" or len(body) != width * height:
                raise NotAPicture(self._refusal(kind, body) if kind in (b"U", b"X") else "Pillow's decoding process sent what it should not")
            self.k += 1
            gray = [body[y * width:(y + 1) * width] for y in range(height)]
            picture = Picture(width, height, gray, None, "Pillow %s" % _PILLOW.get("version", "?"))
            said = self._decoder_said()
            if said is not None:
                picture.damage = "frame %d: it printed %d line(s) on its standard error while it decoded, the first: %s" % (self.k, said[0], said[1])
                picture.damage_by = DECODER_SAID_BY
            return picture
        except BaseException:
            self.close()
            raise


def read_picture(data, want_rgb=False, reader="auto", tick=None):
    """The picture in `data` (its first frame): a PNG by the built-in reader when it reads it (or when reader is "builtin"), anything else,
    and a PNG the built-in reader refuses, by Pillow in a child when it imports (grey only: want_rgb is for the built-in reader).
    NotAPicture says which reader said what; Refused for a picture that is no crop of one line (by its size, before its rows are taken);
    Clock when the clock runs out first. `more_frames` says whether the file holds frames after the first. `damage` is what the built-in
    reader found cut or corrupt in a PNG Pillow then read, what Pillow's decoder printed on its standard error while it decoded the
    frame, or what the tool's own walk of a JPEG's coded data, of a TIFF's strips and tiles or of a PNG's image data found (Pillow fills
    what is missing), or None; `damage_by` says which; `unchecked` is why that walk did not reach it, or None."""
    first = damage = None
    if data[:8] == PNG_MAGIC or reader == "builtin":
        try:
            return read_png(data, want_rgb, tick)
        except NotAPicture as exc:
            first = str(exc)
            damage = first if exc.damaged else None
            if reader == "builtin":
                raise
    image_module = pillow() if reader != "builtin" else None
    if image_module is None:
        raise NotAPicture(first or "not a PNG, and Pillow, which reads the other picture formats, does not import here")
    said = "the built-in reader: %s; " % first if first else ""
    scans = jpeg_scans(data)
    if scans > MAX_JPEG_SCANS:
        raise NotAPicture("%sa JPEG of %d scans (start-of-scan markers): this tool hands Pillow a JPEG of up to %d (a picture has one, a "
                          "progressive one about ten)" % (said, scans, MAX_JPEG_SCANS))
    stream = PillowFrames(data, image_module, 1, check_crop)
    try:
        picture = stream.next_frame()
        if picture is None:
            raise NotAPicture("Pillow found no frame in it")
        try:
            stream.next_frame()                 # whether a second frame is there: the child says so after the first
            picture.more_frames = stream.more
        except NotAPicture:
            picture.more_frames = None          # Pillow could not say (it does not read past the first frame)
    except NotAPicture as exc:
        raise NotAPicture("%s%s" % (said, exc))
    finally:
        stream.close()
    if damage is not None:
        picture.damage, picture.damage_by = damage, "the built-in reader"
    if picture.damage is None:
        walk_coded_data(data, picture, tick, 1)
    return picture


def png_bytes(width, height, rows, channels=1):
    """A PNG (8-bit grey, or RGB with channels 3) from rows of bytes (any iterable), compressed row by row: the rows are never joined into
    one copy, and the clock is read every 64 rows (Clock)."""
    packer = zlib.compressobj(6)
    parts = []
    for y, row in enumerate(rows):
        if y % 64 == 0:
            tick()
        parts.append(packer.compress(b"\x00"))
        parts.append(packer.compress(row))
    parts.append(packer.flush())
    body = b"".join(parts)

    def chunk(kind, data):
        return struct.pack(">I", len(data)) + kind + data + struct.pack(">I", zlib.crc32(kind + data))

    return (PNG_MAGIC + chunk(b"IHDR", struct.pack(">IIBBBBB", width, height, 8, 0 if channels == 1 else 2, 0, 0, 0))
            + chunk(b"IDAT", body) + chunk(b"IEND", b""))


def otsu(gray_rows, tick=None):
    """The threshold that best splits the grey values in two (Otsu): a pixel below it is dark."""
    histogram = [0] * 256
    step = max(1, len(gray_rows) // 400)
    for row in gray_rows[::step]:
        if tick:
            tick()
        for value, count in collections.Counter(row).items():
            histogram[value] += count
    total = sum(histogram)
    if total == 0:
        return 128
    sum_all = sum(i * h for i, h in enumerate(histogram))
    best, threshold, weight, running = -1.0, 128, 0, 0
    for i in range(256):
        weight += histogram[i]
        if weight == 0:
            continue
        if weight == total:
            break
        running += i * histogram[i]
        mean_low, mean_high = running / weight, (sum_all - running) / (total - weight)
        between = weight * (total - weight) * (mean_low - mean_high) ** 2
        if between > best:
            best, threshold = between, i + 1
    return threshold


def binarise(gray_rows, threshold=None, tick=None):
    """Rows of 0 (light) and 1 (dark)."""
    threshold = otsu(gray_rows, tick) if threshold is None else threshold
    table = bytes(1 if v < threshold else 0 for v in range(256))
    return [row.translate(table) for row in gray_rows], threshold


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


RUNS = re.compile(rb"\x01+|\x00+")


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


UNREAD = ("frames_not_read", "picture_damaged", "jpeg_data_not_walked", "shape_groups_not_whole", "crops_not_written", "ocr_not_run_by_the_clock",
          "ocr_not_read", "ocr_text_not_written", "comparison_not_written", "ties_not_sought", "read_apart_pairs_not_listed",
          "candidates_not_written", "candidates_file_not_written")


class Clock(Exception):
    """The tool's own clock ran out inside a loop."""


def tick():
    if out_of_time():
        raise Clock()


def dark_box(binary, width, height):
    """(left, top, right, bottom) of the ink, right and bottom exclusive, or None for a picture with none."""
    top = bottom = None
    left, right = width, 0
    for y, row in enumerate(binary):
        first = row.find(b"\x01")
        if first < 0:
            continue
        if top is None:
            top = y
        bottom = y + 1
        left = min(left, first)
        right = max(right, row.rfind(b"\x01") + 1)
    return None if top is None else (left, top, right, bottom)


def segment(picture):
    """The line's glyphs: ink runs along the line, each trimmed to its ink. Returns a dict (polarity, band, glyphs, gaps, specks)."""
    binary, threshold = binarise(picture.gray, None, tick)
    width, height = picture.width, picture.height
    dark = sum(row.count(1) for row in binary)
    polarity = "dark on light"
    if dark * 2 > width * height:
        binary = [row.translate(FLIP) for row in binary]
        polarity = "light on dark"
    box = dark_box(binary, width, height)
    if box is None:
        return {"polarity": polarity, "threshold": threshold, "glyphs": [], "binary": binary, "box": None, "bands": 0, "specks": 0}
    left, top, right, bottom = box
    bands, inside = 0, False
    for y in range(top, bottom):
        has = 1 in binary[y]
        if has and not inside:
            bands += 1
        inside = has
    # A column holds ink when any row has ink in it: the rows (bytes of 0 and 1) OR-ed together as whole numbers, a byte a column.
    union = 0
    for y in range(top, bottom):
        if y % 256 == 0:
            tick()
        union |= int.from_bytes(binary[y], "big")
    ink = union.to_bytes(width, "big")
    glyphs, specks, x = [], 0, left
    while x < right:
        if not ink[x]:
            x += 1
            continue
        start = x
        while x < right and ink[x]:
            x += 1
        rows = [binary[y][start:x] for y in range(top, bottom)]
        first = next(i for i, row in enumerate(rows) if 1 in row)
        last = max(i for i, row in enumerate(rows) if 1 in row)
        pixels = sum(row.count(1) for row in rows)
        if pixels < 2:
            specks += 1
            continue
        kept = rows[first:last + 1]
        glyphs.append({"x": start, "y": top + first, "width": x - start, "height": last - first + 1, "ink": pixels, "rows": kept,
                       "bits": int.from_bytes(b"".join(kept), "big")})
        if len(glyphs) > MAX_GLYPHS:
            raise Refused("more than %d ink runs along the line: this is not a crop of one line of text" % MAX_GLYPHS)
    return {"polarity": polarity, "threshold": threshold, "glyphs": glyphs, "binary": binary, "box": box, "bands": bands, "specks": specks}


FLIP = bytes((1, 0)) + bytes(254)


def same_shape(a, b):
    """Whether two glyphs are the same drawing: the same size and at most one pixel in sixteen different. The pixels are bytes of 0 and 1,
    so the pixels that differ are the bits set in the XOR of the two glyphs taken as whole numbers."""
    if a["width"] != b["width"] or a["height"] != b["height"] or abs((a["y"]) - (b["y"])) > 1:
        return False
    return bin(a["bits"] ^ b["bits"]).count("1") * 16 <= a["width"] * a["height"]


def strip_picture(glyphs, top, bottom):
    """Every glyph in a row, enlarged and at its own height in the line (a mark that sits high stays high), a frame between them, its
    index (from 1) below: (width, height, grey rows)."""
    tallest = bottom - top
    scale = max(1, min(8, 48 // max(1, tallest)))
    label_scale = 2
    cell_height = tallest * scale + 6
    cells = []
    for index, glyph in enumerate(glyphs, 1):
        tick()
        label_width, label = label_rows(str(index), label_scale)
        cell_width = max(glyph["width"] * scale, label_width) + 8
        rows = []
        pad_top = (glyph["y"] - top) * scale + 3
        pad_left = (cell_width - glyph["width"] * scale) // 2
        drawn = [widen(row, scale) for row in glyph["rows"]]
        for y in range(cell_height):
            if y % 256 == 0:
                tick()
            source = (y - pad_top) // scale if y >= pad_top else -1
            if 0 <= source < glyph["height"]:
                line = drawn[source]
                rows.append(b"\xff" * pad_left + line + b"\xff" * (cell_width - pad_left - len(line)))
            else:
                rows.append(b"\xff" * cell_width)
        rows.append(b"\xc0" * cell_width)
        pad_label = (cell_width - label_width) // 2
        rows.append(b"\xff" * cell_width)
        for line in label:
            rows.append(b"\xff" * pad_label + line.translate(INK) + b"\xff" * (cell_width - pad_label - label_width))
        rows.append(b"\xff" * cell_width)
        cells.append((cell_width, rows))
    height = len(cells[0][1])
    out = []
    for y in range(height):
        out.append(b"\x80".join(rows[y] for _w, rows in cells))
    return len(out[0]), height, out


INK = bytes((255, 0)) + bytes(254)


def widen(row, scale):
    """A row of 0 (paper) and 1 (ink) as grey bytes, ink black, each pixel repeated `scale` times."""
    grey = row.translate(INK)
    return grey if scale == 1 else bytes(itertools.chain.from_iterable(zip(*([grey] * scale))))


def crop_scale(glyph):
    """How many times a glyph's crop is enlarged: four, or two or one when four would pass MAX_CROP_SCALE_PIXELS."""
    for scale in (4, 2):
        if glyph["width"] * glyph["height"] * scale * scale <= MAX_CROP_SCALE_PIXELS:
            return scale
    return 1


def glyph_png(glyph, scale=4):
    def rows():
        for i, line in enumerate(glyph["rows"]):
            if i % 64 == 0:
                tick()
            drawn = widen(line, scale)
            for _ in range(scale):
                yield drawn
    return png_bytes(glyph["width"] * scale, glyph["height"] * scale, rows())


def class_of(ch, classes):
    for members in classes:
        if ch in members:
            return members
    return None


def parse_uncertain(value, reading, classes):
    """{position: alternatives (a string, the reading's own character first)} from the `uncertain` parameter, or from the classes."""
    chosen = {}
    if value is None:
        for at, ch in enumerate(reading):
            members = class_of(ch, classes)
            if members:
                chosen[at] = ch + "".join(m for m in members if m != ch)
        return chosen, "every character of the reading that is in a confusable class"
    if not isinstance(value, list) or len(value) > MAX_READING:
        raise Refused("uncertain must be a list of positions: [{\"at\": 4, \"among\": \"lI\"}] or [4, 9]. " + RULES[2])
    for item in value:
        among = None
        if isinstance(item, dict):
            at, among = item.get("at"), item.get("among")
        else:
            at = item
        if isinstance(at, bool) or not isinstance(at, int) or not 0 <= at < len(reading):
            raise Refused("an uncertain position must be a whole number from 0 to %d, the index of a character of the reading" % (len(reading) - 1))
        if at in chosen:
            raise Refused("position %d is named twice in uncertain" % at)
        if among is None:
            among = class_of(reading[at], classes)
            if among is None:
                raise Refused("position %d of the reading is in no confusable class: say its alternatives with among" % at)
        if not isinstance(among, str) or not 1 <= len(among) <= 16 or len(set(among)) != len(among) or any(ch < " " or 0xD800 <= ord(ch) <= 0xDFFF for ch in among):
            raise Refused("among must be a string of 1 to 16 different characters: the characters the glyph at that position could be")
        chosen[at] = reading[at] + "".join(m for m in among if m != reading[at])
    return chosen, "the positions named in uncertain"


def read_program(argv, seconds, most, merge=False):
    """Run a program and read its standard output, bounded: (exit code or None, the bytes, why the reading was cut or None). Past `most`
    bytes, or at `seconds`, the program is ended with what it started and the output is not used (cut says why). Once it has ended, its
    pipe is given PIPE_GRACE seconds and POST_EXIT_BYTES bytes: a process it left that holds the pipe, silent or writing, does not hold the
    tool, and what such a process writes is kept only within those bounds. Standard error is read with it when `merge`, else not at all."""
    try:
        proc = spawn(argv, stdout=subprocess.PIPE, stderr=subprocess.STDOUT if merge else subprocess.DEVNULL)
    except OSError as exc:
        return None, b"", "it could not be started (%s)" % describe(exc)
    ACTIVE.append(proc)
    out, cut, ended, extra, at_end, sampled = bytearray(), None, None, 0, False, 0.0
    deadline = time.monotonic() + max(1.0, seconds)
    fd = proc.stdout.fileno()
    try:
        while True:
            now = time.monotonic()
            if ended is None:
                if proc.poll() is not None:
                    ended = now
                elif now >= deadline:
                    cut = "it was ended at its clock"
                    break
                elif now - sampled >= 0.2:
                    sampled = now
                    _sample(proc.pid)
            if ended is not None and (now - ended >= PIPE_GRACE or extra >= POST_EXIT_BYTES):
                break
            if not _select.select([fd], [], [], 0.1)[0]:
                continue
            data = os.read(fd, 65536)
            if not data:
                at_end = True
                break
            if ended is not None:
                extra += len(data)
            out += data
            if len(out) > most:
                cut = "it wrote more than %d bytes" % most
                break
        if cut:
            kill_tree(proc)
        try:
            proc.wait(timeout=PIPE_GRACE)
        except subprocess.TimeoutExpired:
            kill_tree(proc)
            proc.wait()
        if not at_end:
            reap_orphans(_pipe_inodes(proc))
    finally:
        _close_pipe(proc.stdout)
        ACTIVE.remove(proc)
    settle()
    return (None if cut else proc.returncode), bytes(out[:most]), cut


def run_ocr(picture, place):
    """A second reader, when the image holds one: tesseract as one line (--psm 7) on the crop as this tool decoded it (its first frame, grey,
    written as a PNG of the tool's own and removed after), never on the file itself, so that the engine reads the pixels this tool counted
    and no decoder of its own. {engine, ...}; the text goes to a file. What the engine writes is read up to MAX_OCR_BYTES: a line of text is
    far less, and more is not read. `_partial` says why the reading asked for was not made (the clock, a cut, an exit code or a signal, an
    output that is no text)."""
    program = find_program("tesseract")
    if program is None:
        return {"available": False, "said": "no OCR engine is in this image (tesseract is not on PATH): the count and the strip are this tool's own, and no second reading was made"}, None
    _code, out, cut = read_program([program, "--version"], seconds_left(10), MAX_OCR_BYTES, merge=True)     # an older tesseract prints it on stderr
    if seconds_until_clock() < OCR_START_SECONDS:
        return {"available": True, "read": False, "said": "the OCR engine was not run on the crop: the tool's clock had less than %d seconds left" % OCR_START_SECONDS,
                "_partial": "the OCR engine was not run on the crop: the clock had run out, or nearly"}, None
    version = out.decode("utf-8", "replace").splitlines()[0].strip()[:60] if out.strip() and not cut else "tesseract, version not printed"
    version = "".join(ch if " " <= ch < "\x7f" else "?" for ch in version)
    name = ".ocr-input.png"
    full = os.path.join(place.path, name)
    try:
        place.write(name, png_bytes(picture.width, picture.height, picture.gray), 0o600)
        temp_hold(full)
    except (OSError, Clock) as exc:
        return {"available": True, "engine": version, "read": False, "said": "the decoded crop could not be written for the OCR engine (%s)" % (
            "the clock ran out" if isinstance(exc, Clock) else describe(exc)), "_partial": "the OCR engine was not run: the decoded crop could not be written for it"}, None
    try:
        target = full if os.path.isabs(full) else os.path.join(".", full)
        code, out, cut = read_program([program, target, "stdout", "--psm", "7"], seconds_left(OCR_SECONDS), MAX_OCR_BYTES)
    finally:
        place.remove(name)
        temp_done(full)
    if cut or code != 0:
        how = cut or ("it was ended by signal %d" % -code if code is not None and code < 0 else "exit code %s" % code)
        return {"available": True, "engine": version, "read": False, "said": "the OCR engine did not read the crop (%s)" % how,
                "_partial": "the OCR engine did not read the crop (%s): no second reading was made" % how}, None
    try:
        text = out.decode("utf-8").split("\n")[0].rstrip("\r")
    except UnicodeDecodeError:
        return {"available": True, "engine": version, "read": False, "said": "the OCR engine's output is not UTF-8 text",
                "_partial": "the OCR engine's output is not UTF-8 text: no second reading was made"}, None
    result = {"available": True, "engine": version, "read": True, "read_from": "the crop as this tool decoded it (its first frame, grey), not the file"}
    try:
        result["text_file"] = place.write("ocr.txt", (text + "\n").encode("utf-8"), 0o600)
    except OSError as exc:
        result["write_error"] = "the OCR text could not be written (%s)" % describe(exc)
    return result, text


def main():
    args, unknown = read_args(KNOWN_PARAMS)
    seconds = int_param(args, "max_seconds", DEFAULT_SECONDS, 5, MAX_SECONDS)
    most = int_param(args, "max_candidates", DEFAULT_CANDIDATES, 1, MAX_CANDIDATES)
    ocr_mode = choice_param(args, "ocr", "auto", ("auto", "none"))
    reader = choice_param(args, "reader", "auto", ("auto", "builtin"))
    classes = args.get("classes")
    if classes is None:
        classes = CLASSES
    elif (not isinstance(classes, list) or not 1 <= len(classes) <= 64
          or any(not isinstance(c, str) or not 2 <= len(c) <= 16 or len(set(c)) != len(c) or any(ch < " " or 0xD800 <= ord(ch) <= 0xDFFF for ch in c) for c in classes)
          or len(set("".join(classes))) != len("".join(classes))):
        raise Refused("classes must be a list of 1 to 64 strings of 2 to 16 different characters (no control character, no lone surrogate), no character in "
                      "two classes: each string is one class of look-alikes")
    reading = args.get("reading")
    if reading is not None and (not isinstance(reading, str) or not 1 <= len(reading) <= MAX_READING or any(ch < " " or 0xD800 <= ord(ch) <= 0xDFFF for ch in reading)):
        raise Refused("reading must be the line as you read it: a string of 1 to %d characters on one line" % MAX_READING)
    if args.get("uncertain") is not None and reading is None:
        raise Refused("uncertain goes with reading: the positions are indexes into it. " + RULES[2])
    uncertain, uncertain_from = parse_uncertain(args.get("uncertain"), reading, classes) if reading is not None else ({}, None)
    image = args.get("image")
    if image is None:
        raise Refused("image is required: the path of a crop that holds one line of text (PNG by the built-in reader; other formats when Pillow imports). " + RULES[1])
    image = path_param(image, "image")
    set_deadline(seconds)
    started = time.monotonic()
    data = read_file(image, MAX_IMAGE_BYTES, "the picture")
    try:
        picture = read_picture(data, False, reader, tick)
    except NotAPicture as exc:
        raise Refused("the picture was not read: %s" % exc)
    except Clock:
        raise Refused("the tool's clock (max_seconds %d) ran out while the picture was being read: nothing was counted" % seconds)
    check_crop(picture.width, picture.height)
    unread = Unread(*UNREAD)
    frames_not_read = None
    if picture.more_frames is None:
        frames_not_read = "whether the picture holds frames after the first is not known (Pillow did not say): the first was read"
    elif picture.more_frames:
        frames_not_read = "the picture holds frames after the first, and they were not read: this tool reads the first frame of a crop"
    if frames_not_read:
        unread.add("frames_not_read", 1, frames_not_read)
    if picture.damage:
        unread.add("picture_damaged", 1, "the picture is cut or corrupt (%s: %s): Pillow read it all the same and filled what is missing, so ink may be "
                                         "missing from the line" % (picture.damage_by, picture.damage))
    if picture.unchecked:
        unread.add("jpeg_data_not_walked", 1, "the tool's own walk of the picture's coded data did not reach it (%s): coded data cut short (a JPEG's "
                                              "given its end marker back, a TIFF strip's or tile's, a PNG's image data) is not told from whole data" % picture.unchecked)
    common = {"tool": TOOL, "parser": PARSER, "image": printable(image), "sha256": hashlib.sha256(data).hexdigest(), "pixels": "%d x %d" % (picture.width, picture.height),
              "picture_reader": picture.reader, "rules": RULES, **({"unrecognised_parameters": unknown} if unknown else {}),
              **({"frames_not_read": frames_not_read} if frames_not_read else {}),
              **({"picture_damaged": picture.damage, "picture_damaged_by": picture.damage_by} if picture.damage else {}),
              **({"jpeg_data_not_walked": picture.unchecked} if picture.unchecked else {})}
    try:
        found = segment(picture)
    except Clock:
        print_answer({**common, "status": "failed", "error": "the tool's clock ran out while the line was being cut",
                      "status_basis": "the clock (max_seconds %d) ran out before the glyphs were cut: nothing was counted" % seconds})
        raise SystemExit(1)
    glyphs = found["glyphs"]
    if not glyphs and reading is None:
        reasons = unread.reasons()
        print_answer({**common, "status": "partial" if unread else "complete", "complete": not unread, "count": 0, "polarity": found["polarity"],
                      "not_read_or_judged": dict(unread.counts),
                      "status_basis": "the whole %s was read and it holds no ink against its background at the threshold %d: no glyph, and nothing was written%s"
                      % ("first frame" if frames_not_read else "picture", found["threshold"], "; but %s" % "; ".join(reasons) if reasons else ""),
                      **({"partial_reasons": reasons} if reasons else {})})
        return
    place = Place("glyph_strip")
    files = {}
    spaces, wide, narrow_pairs, groups, rows = [], [], [], [], []
    if glyphs:
        widths = sorted(g["width"] for g in glyphs)
        heights = sorted(g["height"] for g in glyphs)
        median_width, median_height = widths[len(widths) // 2], heights[len(heights) // 2]
        gaps = [glyphs[i + 1]["x"] - (glyphs[i]["x"] + glyphs[i]["width"]) for i in range(len(glyphs) - 1)]
        median_gap = sorted(gaps)[len(gaps) // 2] if gaps else 0
        space_at = max(median_height * 0.35, median_gap * 2.5, 2)
        spaces = [i + 1 for i, gap in enumerate(gaps) if gap > space_at]
        # A run that may be two touching characters is wide against the line's usual glyph: the median width, or the median height where
        # that is smaller (a line whose runs are mostly touching pairs has a median width that is itself a pair).
        usual = min(median_width, median_height)
        wide = [i + 1 for i, g in enumerate(glyphs) if g["width"] > 1.8 * usual and g["width"] > g["height"] * 1.3]
        narrow_pairs = [[i + 1, i + 2] for i, gap in enumerate(gaps) if gap <= max(1, median_gap // 3) and glyphs[i]["width"] + glyphs[i + 1]["width"] < median_width * 1.2 and len(gaps) > 2]
        placed = set()
        for i in range(len(glyphs)):
            if i in placed:
                continue
            if out_of_time():
                unread.add("shape_groups_not_whole", len(glyphs) - i, "the clock ran out while the glyphs were compared: same_shape_groups is not whole")
                break
            group = [i] + [j for j in range(i + 1, len(glyphs)) if j not in placed and same_shape(glyphs[i], glyphs[j])]
            if len(group) > 1:
                groups.append([g + 1 for g in group])
                placed.update(group)
        left, top, right, bottom = found["box"]
        rows = [{"index": i + 1, "x": g["x"], "y": g["y"], "width": g["width"], "height": g["height"], "ink_pixels": g["ink"],
                 "above_line_bottom": bottom - (g["y"] + g["height"]), "below_line_top": g["y"] - top} for i, g in enumerate(glyphs)]
        try:
            width, height, strip = strip_picture(glyphs, top, bottom)
            files["strip"] = place.write("strip.png", png_bytes(width, height, strip))
            for i, g in enumerate(glyphs, 1):
                scale = crop_scale(g)
                rows[i - 1]["crop"] = place.write("glyph-%03d.png" % i, glyph_png(g, scale))
                rows[i - 1]["crop_scale"] = scale
        except Clock:
            unread.add("crops_not_written", len(glyphs) - sum(1 for r in rows if "crop" in r) + ("strip" not in files),
                       "the clock ran out while the strip and the crops were being written: %d of %d crops are there" % (sum(1 for r in rows if "crop" in r), len(glyphs)))
        except OSError as exc:
            files["write_error"] = "a crop could not be written (%s)" % describe(exc)
            unread.add("crops_not_written", len(glyphs) - sum(1 for r in rows if "crop" in r) + ("strip" not in files), "the strip or a crop could not be written")
    answer = {**common, "count": len(glyphs), "count_is": "separate ink runs along the line, specks of one pixel left out",
              "polarity": found["polarity"], "threshold": found["threshold"], "line_box": list(found["box"]) if found["box"] else None, "ink_bands": found["bands"],
              "specks_ignored": found["specks"], "spaces_after": spaces, "wide": wide, "narrow_pairs": narrow_pairs, "same_shape_groups": groups,
              "glyphs": rows, "files": files, "output_directory": place.shown}
    if found["bands"] > 2:
        answer["bands_note"] = "the ink is in %d bands from top to bottom: a crop of one line has one (two with dots or accents); with more, the runs of several lines are counted together" % found["bands"]
    # The readers: the caller's reading, and an OCR engine when the image holds one.
    readers = []
    ocr_text = None
    if ocr_mode == "auto" and seconds_until_clock() < OCR_START_SECONDS:
        ocr = {"available": None, "read": False, "said": "the OCR engine was not run: the tool's clock (max_seconds %d) had less than %d seconds left" % (seconds, OCR_START_SECONDS)}
        unread.add("ocr_not_run_by_the_clock", 1, "the OCR engine was not run: the clock had run out, or nearly")
    elif ocr_mode == "auto":
        ocr, ocr_text = run_ocr(picture, place)
        if "_partial" in ocr:
            unread.add("ocr_not_read", 1, ocr.pop("_partial"))
        if "write_error" in ocr:
            unread.add("ocr_text_not_written", 1, "the OCR text could not be written")
    else:
        ocr = {"available": None, "said": "no OCR engine was asked for (ocr: none)"}
    answer["ocr"] = ocr
    if ocr.get("read"):
        # The OCR text's length is not printed (it is evidence text, and a length is a hint of it): whether its characters besides spaces are
        # as many as the ink runs is.
        readers.append({"reader": ocr["engine"], "read": "the line as text (in text_file)", "agrees_with_count": len(ocr_text.replace(" ", "")) == len(glyphs)})
    readers.append({"reader": "glyph_strip (this tool)", "read": "the count of ink runs and their boxes, no character"})
    if reading is not None:
        bare = len(reading.replace(" ", ""))
        readers.append({"reader": "the caller", "read": "the reading given", "characters": len(reading), "characters_without_spaces": bare, "agrees_with_count": bare == len(glyphs)})
        if ocr_text is not None:
            # Where the two texts differ follows the OCR text, which the answer does not show, and so does its length: the positions go to a
            # file beside it, a row for each of the first MAX_READING positions whatever the two lengths (a position past either text differs),
            # so that the file's size says nothing of the OCR text; whether the two have the same length is in the file's last line.
            span = MAX_READING
            against = {"what": "the positions where the reading and the OCR text differ, which of them are uncertain, and whether the two texts have the same "
                               "length, are in the file, not here: they follow the OCR text, which the answer does not show"}
            try:
                against["file"] = place.write("reading_against_ocr.tsv", (b"at\tdiffers\tuncertain\n",
                                                                         *(("%d\t%d\t%d\n" % (i, int(i >= len(reading) or i >= len(ocr_text) or reading[i] != ocr_text[i]),
                                                                                              int(i in uncertain))).encode("ascii") for i in range(span)),
                                                                         b"same_length\t%d\t-\n" % int(len(reading) == len(ocr_text))), 0o600)
            except OSError as exc:
                against["write_error"] = "the comparison could not be written (%s)" % describe(exc)
                unread.add("comparison_not_written", 1, "the comparison with the OCR text could not be written")
            answer["reading_against_ocr"] = against
        # The glyph of a position: by order, when the reading has as many characters besides spaces as there are ink runs.
        glyph_of = {}
        if glyphs and bare == len(glyphs):
            k = 0
            for at, ch in enumerate(reading):
                if ch != " ":
                    glyph_of[at] = k
                    k += 1
        # Two uncertain positions are tied when their glyphs are the same drawing, they have the same alternatives AND the reading gives
        # them the same character: the set then takes them as one choice. A pair that is the same drawing and that the reading gives two
        # characters is not tied (the reading stays in the set) and is named, because one of the two readings, or the drawing, says
        # otherwise. A tie that the clock leaves unsought only makes the set larger, never drops a member of it.
        ties, parent, read_apart = [], {at: at for at in uncertain}, []

        def root_of(at):
            while parent[at] != at:
                at = parent[at]
            return at

        if glyph_of:
            order = [at for at in sorted(uncertain) if at in glyph_of]
            for i, a in enumerate(order):
                if out_of_time():
                    unread.add("ties_not_sought", len(order) - i, "the clock ran out while ties were sought: the positions from %d on were not tied, so the set is counted with fewer ties (larger, never smaller)" % a)
                    break
                for b in order[i + 1:]:
                    if set(uncertain[a]) != set(uncertain[b]) or not same_shape(glyphs[glyph_of[a]], glyphs[glyph_of[b]]):
                        continue
                    if reading[a] != reading[b]:
                        read_apart.append([a, b])
                        continue
                    root_a, root_b = root_of(a), root_of(b)
                    if root_a != root_b:
                        parent[root_b] = root_a
                        ties.append([a, b])
        roots = sorted(at for at in uncertain if parent[at] == at)
        size = 1
        for at in roots:
            size *= len(uncertain[at])
        written = 0
        first_line = []
        candidates = {"candidate_set_size": size, "uncertain_positions": [{"at": at, "alternatives": len(uncertain[at]), **({"glyph": glyph_of[at] + 1} if at in glyph_of else {})} for at in sorted(uncertain)],
                      "uncertain_from": uncertain_from, "confidence": "medium" if size > 1 else "as the reading itself: no position is uncertain",
                      "record_as": ("a candidate set of %d, at medium confidence, with the candidates file: not one string" % size) if size > 1 else "the reading, with the strip"}
        if ties:
            candidates["positions_tied"] = ties
            candidates["tied_because"] = ("their glyphs are the same drawing, they have the same alternatives and the reading gives them the same character: the set "
                                          "takes them as one choice (an assumption where a font draws two of the alternatives alike)")
        if read_apart:
            candidates["same_drawing_read_apart"] = read_apart[:50]
            candidates["same_drawing_read_apart_total"] = len(read_apart)
            if len(read_apart) > 50:
                unread.add("read_apart_pairs_not_listed", len(read_apart) - 50, "%d pairs of positions are the same drawing read apart and the answer lists the first 50: "
                           "the other %d are not printed (the candidates file is whole)" % (len(read_apart), len(read_apart) - 50))
            candidates["read_apart_means"] = ("the glyphs at these positions are the same drawing but the reading gives them different characters: they were not "
                                              "tied and the reading is in the set; one of the two readings is likely wrong, unless the font draws the two alike")
        if not glyph_of:
            candidates["glyphs_not_matched"] = "the reading has %d characters besides spaces and the line has %d ink runs: positions were not matched to glyphs, and nothing was tied" % (bare, len(glyphs))

        def lines():
            nonlocal written
            for combo in itertools.islice(itertools.product(*[uncertain[at] for at in roots]), most):
                pick = dict(zip(roots, combo))
                text = "".join(pick[root_of(at)] if at in uncertain else ch for at, ch in enumerate(reading))
                if not written:
                    first_line.append(text)
                written += 1
                yield (text + "\n").encode("utf-8")
                if written % 256 == 0 and out_of_time():
                    return

        try:
            candidates["candidates_file"] = place.write("candidates.txt", lines(), 0o600)
            candidates["candidates_written"] = written
            candidates["first_line_is_the_reading"] = first_line == [reading]
            if written < size:
                candidates["truncated"] = True
                unread.add("candidates_not_written", size - written, "the candidate set has %d members and %d were written (max_candidates %d, or the clock)" % (size, written, most))
        except OSError as exc:
            candidates["write_error"] = "the candidates could not be written (%s)" % describe(exc)
            unread.add("candidates_file_not_written", 1, "the candidates file could not be written")
        answer["candidates"] = candidates
    answer["readers"] = readers
    reasons = unread.reasons()
    answer["not_read_or_judged"] = dict(unread.counts)
    status = "partial" if unread else "complete"
    answer["status"] = status
    answer["complete"] = status == "complete"
    answer["status_basis"] = (("the whole picture was read: %d ink runs along the line, each written as a crop and in the strip" % len(glyphs) if glyphs else
                               "the whole picture was read and it holds no ink against its background at the threshold %d: no glyph, and the reading has none to match" % found["threshold"])
                              + ("; the candidate set of %d was written whole" % answer["candidates"]["candidate_set_size"] if reading is not None and not reasons else "")
                              + ("; but %s" % "; ".join(reasons) if reasons else "")
                              + ". The count is of ink runs, a character only where glyphs neither touch nor split (wide, narrow_pairs)")
    if reasons:
        answer["partial_reasons"] = reasons
    answer["seconds"] = round(time.monotonic() - started, 2)
    if place.note():
        answer["note"] = place.note()
    process_apply(answer)
    print_answer(answer, indent=1)


if __name__ == "__main__":
    exit_code = 0
    try:
        answered(main)
    except SystemExit as stop:
        exit_code = _code(stop)
    _leave(exit_code)
