#!/usr/bin/env python3
"""An Android adb backup's app data, laid out as ALEAPP reads it, and then parsed by ALEAPP.

The android-backup recipe lists an adb backup's members and extracts nothing. ALEAPP reads a file-system layout
(data/data/<package>/databases/...), and an adb backup keeps each app's data under apps/<package>/<domain>/..., so nothing
parsed an adb backup's apps until this: the backup is laid out as the ab_layout tool lays it out (the logic is copied here: a
recipe does not import a tool), and ALEAPP then runs over the layout with `-t fs`.

    run.py detect --target T [--probe-out DIR]   exit 0 applies, 1 does not, 2 cannot tell
    run.py run --target T --out DIR

WHAT THE RESULT IS. A derivative of an adb backup, never a file-system acquisition: it holds what the backup agent put in the
backup, under the backup's own domains, mapped by a table (the FullBackup tree tokens r, f, db, sp, nb, c and the device-protected
d_ forms) that is the author's recollection of AOSP's constants and has not been checked against the source. The APK, obb,
external storage and shared/ are listed and not laid out; links, devices, FIFOs and directories are listed and never created; a hostile member
name (`..` as a component, an absolute path, an empty component, a NUL, an over-long name) is rejected and listed. derivative/DERIVATIVE.json
and coverage.json both say "derivative of an adb backup". Member names are written as the backup spelled them (this recipe does not withhold a
recovery-password-shaped name; the pack's ab_layout tool does). No password is read: an encrypted backup (AES-256) is refused as failed.

WHAT `complete` MEANS. The layout was made from a payload read to the end of its zlib stream, the tar's two end blocks came with nothing
after them (a lone zero block, bytes after the stream and data after the end are each partial), every member that is laid out by design was
written, and then everything the ALEAPP receipt requires (as in android-aleapp): ALEAPP exited 0, wrote a TSV report, its log was
recognised, says how many modules it parses and that many started, every module is completed, no_record or unsupported, no line outside a
module speaks of an error, stderr holds only log lines, and the log ends with "Processes completed.". modules.tsv has one row per module;
ab-members.tsv one row per member of the backup. coverage.json is written before ALEAPP starts and says partial, so a run that is stopped
leaves it. A run never writes over an earlier run's output. ALEAPP runs in this recipe's process group (the shared PROCESS block).
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


import argparse
import io
import json
import os
import re
import shutil
import signal
import stat
import struct
import subprocess
import sys
import time
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

TEMPS = []                 # hidden temporaries of the layout phase, removed by a stop signal

NOT_COVERED = ("what ab_layout's mapping does not lay out (the APK, obb, external storage, shared/, links, devices, directories, unknown domains and rejected names, "
               "each listed in ab-members.tsv); artefacts no module of the pinned ALEAPP release parses; deleted records beyond what a module reads itself (no carving); "
               "protected data that needs a key it does not have; a module the log does not account for as completed")
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


# --- the adb backup, laid out as ab_layout lays it out (copied: a recipe does not import a tool) --------------------------------------------
# Header versions 1 to 5, encryption none. The tar is streamed once under a decompression budget; `apps/<package>/<domain>/<path>` members go
# to derivative/data/data/<package>/... by the table below (the author's recollection of AOSP's FullBackup tree tokens: NOT checked against the
# source). Links, devices, FIFOs, directories, the APK, obb, external storage and shared/ are listed and never created. A hostile name is rejected.
# The result is a derivative of an adb backup, and says so in derivative/DERIVATIVE.json and in coverage.json. No password is read.
import hashlib
import unicodedata

AB_MAGIC = b"ANDROID BACKUP\n"
AB_VERSIONS = (1, 2, 3, 4, 5)
PIECE = 1 << 20
ZERO = b"\0" * 512
COMPONENT_BYTES = 255
PATH_BYTES = 4096
MAX_COMPONENTS = 64
MAX_CLAIMS = 2000000
EXTENDED_LIMIT = 1 << 20
DEFAULT_MAX_MEMBERS = 500000
DEFAULT_MAX_BYTES = 64 << 30
DEFAULT_MAX_DECOMPRESSED = 128 << 30
PACKAGE = re.compile(r"[A-Za-z0-9_.-]{1,255}\Z")
DOMAINS = {
    "r": ("data/data", ""), "f": ("data/data", "files"), "db": ("data/data", "databases"), "sp": ("data/data", "shared_prefs"),
    "nb": ("data/data", "no_backup"), "c": ("data/data", "cache"),
    "d_r": ("data/user_de/0", ""), "d_f": ("data/user_de/0", "files"), "d_db": ("data/user_de/0", "databases"),
    "d_sp": ("data/user_de/0", "shared_prefs"), "d_nb": ("data/user_de/0", "no_backup"), "d_c": ("data/user_de/0", "cache"),
}
NOT_LAID_OUT = ("a", "obb", "ef")
TAR_TYPES = {b"0": "file", b"\0": "file", b"7": "file", b"1": "hardlink", b"2": "symlink", b"3": "character_device", b"4": "block_device",
             b"5": "directory", b"6": "fifo", b"S": "sparse", b"x": "pax", b"g": "pax_global", b"L": "gnu_longname", b"K": "gnu_longlink"}
BY_DESIGN = ("directory", "not_laid_out", "shared_storage", "symlink", "hardlink", "character_device", "block_device", "fifo")
BANNER = {"kind": "derivative of an adb backup", "recipe": "android-backup-apps",
          "is_not": "a file-system acquisition of the phone; it holds only what the backup agent put in the backup",
          "layout": "data/data/<package>/{files,databases,shared_prefs,no_backup,cache}/... and data/user_de/0/<package>/...; ab_layout_meta/<package>/_manifest"}


def ab_header(path):
    """(status, header or reason): the backup's header, read from a regular file opened without waiting and without following a link."""
    try:
        fd = os.open(path, os.O_RDONLY | getattr(os, "O_NONBLOCK", 0) | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0))
    except OSError as exc:
        return "unknown", "the file could not be opened, so it cannot be told whether it is an Android backup: %s" % exc.strerror
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode):
            return "unknown", "not a regular file"
        head = os.pread(fd, 4096, 0)
    finally:
        os.close(fd)
    if not head.startswith(AB_MAGIC):
        return False, "no Android backup signature"
    lines = head.split(b"\n", 4)
    if len(lines) < 5 or not re.fullmatch(rb"[0-9]{1,4}", lines[1]) or lines[2] not in (b"0", b"1") or not re.fullmatch(rb"[A-Za-z0-9._-]{1,16}", lines[3]):
        return False, "the header is not a version, a compression flag and an encryption scheme"
    version, scheme = int(lines[1]), lines[3].decode("ascii")
    header = {"version": version, "compressed": lines[2] == b"1", "encryption": scheme,
              "payload_at": len(AB_MAGIC) + len(lines[1]) + len(lines[2]) + len(lines[3]) + 3, "size": info.st_size}
    if scheme != "none":
        return False, "an encrypted Android backup (%s): this recipe reads no password and opens no encrypted payload" % scheme
    if version not in AB_VERSIONS:
        return False, "header version %d is not one this recipe reads (%s)" % (version, ", ".join(map(str, AB_VERSIONS)))
    return True, header


class Source:
    """The decompressed payload in pieces under a byte budget and the clock; read(n) returns n bytes or fewer at the end."""

    def __init__(self, fd, size, offset, compressed, budget, deadline):
        self.fd, self.size, self.file_pos = fd, size, offset
        self.d = zlib.decompressobj() if compressed else None
        self.budget, self.deadline = budget, deadline
        self.buf, self.pos, self.produced = bytearray(), 0, 0
        self.done, self.state, self.tail, self.after, self.error = False, "reading", b"", 0, None

    def _more(self):
        if self.done:
            return False
        if time.monotonic() > self.deadline:
            self.state, self.done, self.error = "not_reached", True, "the clock"
            return False
        room = self.budget - self.produced
        if room <= 0:
            self.state, self.done, self.error = "not_reached", True, "the decompression budget"
            return False
        if self.d is None:
            chunk = os.pread(self.fd, min(PIECE, room), self.file_pos)
            if not chunk:
                self.state, self.done = "reached", True
                return False
            self.file_pos += len(chunk)
            self.produced += len(chunk)
            self.buf += chunk
            return True
        data = self.tail
        if not data:
            data = os.pread(self.fd, PIECE, self.file_pos)
            self.file_pos += len(data)
            if not data:
                self.state, self.done = "truncated", True
                return False
        try:
            out = self.d.decompress(data, min(PIECE, room))
        except zlib.error as exc:
            self.state, self.done, self.error = "damaged", True, str(exc)[:200]
            return False
        self.tail = self.d.unconsumed_tail
        self.produced += len(out)
        self.buf += out
        if self.d.eof:
            self.state, self.done = "reached", True
            self.after = len(self.d.unused_data) + max(self.size - self.file_pos, 0)
        return True

    def read(self, n):
        while len(self.buf) < n and self._more():
            pass
        out = bytes(self.buf[:n])
        del self.buf[:n]
        self.pos += len(out)
        return out

    def skip(self, n):
        got = 0
        while got < n:
            chunk = self.read(min(PIECE, n - got))
            if not chunk:
                break
            got += len(chunk)
        return got


def cstr(raw):
    end = raw.find(b"\0")
    return raw if end < 0 else raw[:end]


def tar_num(field):
    if field and field[0] & 0x80:
        return None if field[0] & 0x40 else int.from_bytes(bytes([field[0] & 0x7f]) + field[1:], "big")
    text = cstr(field).strip(b" \0")
    if not text:
        return 0
    return int(text, 8) if re.fullmatch(rb"[0-7]+", text) else None


def parse_header(block):
    stored = tar_num(block[148:156])
    if stored is None or stored != sum(block[:148]) + 256 + sum(block[156:]):
        return None
    size, mode, mtime = tar_num(block[124:136]), tar_num(block[100:108]), tar_num(block[136:148])
    if size is None or mode is None or mtime is None:
        return None
    name = cstr(block[0:100])
    if block[257:262] == b"ustar" and cstr(block[345:500]):
        name = cstr(block[345:500]) + b"/" + name
    return {"name": name, "size": size, "type": block[156:157]}


def pax_records(data):
    out, pos = {}, 0
    while pos < len(data):
        space = data.find(b" ", pos)
        if space < 0 or not data[pos:space].isdigit():
            return None
        length = int(data[pos:space])
        if length <= space - pos + 1 or pos + length > len(data) or data[pos + length - 1:pos + length] != b"\n":
            return None
        key, eq, value = data[space + 1:pos + length - 1].partition(b"=")
        if not eq:
            return None
        out[key] = value
        pos += length
    return out


def nbytes(text):
    return len(text.encode("utf-8", "surrogateescape"))


def classify_name(name):
    """(kind, package, domain, rest, why)."""
    if "\0" in name:
        return "rejected", None, None, None, "the name holds a NUL"
    if nbytes(name) > PATH_BYTES:
        return "rejected", None, None, None, "a name of over %d bytes" % PATH_BYTES
    if name.startswith("/"):
        return "rejected", None, None, None, "an absolute path"
    parts = name.rstrip("/").split("/") if name not in ("", "/") else [""]
    if len(parts) > MAX_COMPONENTS:
        return "rejected", None, None, None, "more than %d components" % MAX_COMPONENTS
    for part in parts:
        if part in ("", ".", ".."):
            return "rejected", None, None, None, "a component that is empty, '.' or '..'"
        if nbytes(part) > COMPONENT_BYTES:
            return "rejected", None, None, None, "a component of over %d bytes" % COMPONENT_BYTES
    if parts[0] == "apps":
        if len(parts) < 2:
            return "other", None, None, None, None
        if not PACKAGE.fullmatch(parts[1]):
            return "rejected", None, None, None, "a package name that is not an Android package name"
        if len(parts) == 3 and parts[2] == "_manifest":
            return "manifest", parts[1], "_manifest", [], None
        return "apps", parts[1], parts[2] if len(parts) >= 3 else None, parts[3:], None
    if parts[0] == "shared":
        return "shared", None, None, parts[1:], None
    return "other", None, None, parts, None


def fold(text):
    return unicodedata.normalize("NFC", text).casefold()


class Tree:
    """The names the layout holds, case-folding collisions included (digest chain, linear memory); a name that is taken takes name-2, name-3."""

    def __init__(self):
        self.claimed = {}

    def resolve(self, parts):
        final, key = [], b""
        for i, part in enumerate(parts):
            last = i == len(parts) - 1
            name, origin = part, None
            while True:
                k = hashlib.blake2b(key + b"\0" + fold(name).encode("utf-8", "surrogatepass"), digest_size=16).digest()
                have = self.claimed.get(k)
                if have is None:
                    if len(self.claimed) >= MAX_CLAIMS:
                        raise OverflowError("the layout is full")
                    self.claimed[k] = ["file" if last else "dir", name, 2]
                    break
                if not last and have[0] == "dir":
                    name = have[1]
                    break
                origin = origin or have
                stem, suffix = os.path.splitext(part) if last else (part, "")
                extra = "-%d%s" % (origin[2], suffix)
                raw = stem.encode("utf-8", "surrogateescape")
                room = COMPONENT_BYTES - nbytes(extra)
                if len(raw) > room:
                    stem = raw[:max(room, 1)].decode("utf-8", "surrogateescape")
                name = stem + extra
                origin[2] += 1
            final.append(name)
            key = k
        return final


def ensure_dir(root_fd, parts):
    fd = os.dup(root_fd)
    try:
        for part in parts:
            try:
                os.mkdir(part, 0o700, dir_fd=fd)
            except FileExistsError:
                pass
            nxt = os.open(part, os.O_RDONLY | os.O_DIRECTORY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0), dir_fd=fd)
            os.close(fd)
            fd = nxt
        return fd
    except BaseException:
        os.close(fd)
        raise


DEST = [None]


def write_member(src, size, root_fd, parts, left_bytes, deadline, progress, nonce):
    """Stream `size` bytes into derivative/<parts> through a hidden temporary beside the name and a rename that never replaces; returns the sha256."""
    dir_fd = ensure_dir(root_fd, parts[:-1])
    tmp_name = ".ab-%s.tmp" % nonce
    tmp_path = os.path.join(DEST[0], *parts[:-1], tmp_name)
    TEMPS.append(tmp_path)
    out_fd = None
    try:
        if size > left_bytes:
            raise OverflowError("max_bytes")
        out_fd = os.open(tmp_name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o600, dir_fd=dir_fd)
        digest, left = hashlib.sha256(), size
        while left > 0:
            if time.monotonic() > deadline:
                raise TimeoutError("max_seconds")
            chunk = src.read(min(left, PIECE))
            if not chunk:
                raise EOFError("the payload ended inside the member")
            left -= len(chunk)
            progress[0] += len(chunk)
            digest.update(chunk)
            view = memoryview(chunk)
            while len(view):
                view = view[os.write(out_fd, view):]
        os.close(out_fd)
        out_fd = None
        os.link(tmp_name, parts[-1], src_dir_fd=dir_fd, dst_dir_fd=dir_fd, follow_symlinks=False)
        return digest.hexdigest()
    finally:
        if out_fd is not None:
            os.close(out_fd)
        try:
            os.unlink(tmp_name, dir_fd=dir_fd)
        except OSError:
            pass
        if tmp_path in TEMPS:
            TEMPS.remove(tmp_path)
        os.close(dir_fd)


def materialise(path, header, dest, rows_path, deadline, max_members=DEFAULT_MAX_MEMBERS, max_bytes=DEFAULT_MAX_BYTES, max_decompressed=DEFAULT_MAX_DECOMPRESSED):
    """Lay the backup out under `dest` (which must not exist yet). Returns the account: counts, the state of the stream, and `problems`, the sentences
    that make the run partial. One line per member goes to rows_path (TSV, flushed per line)."""
    os.makedirs(dest, mode=0o700)
    DEST[0] = dest
    with open(os.path.join(dest, "DERIVATIVE.json"), "x", encoding="utf-8") as banner:
        json.dump(BANNER, banner, indent=2, sort_keys=True)
        banner.write("\n")
    root_fd = os.open(dest, os.O_RDONLY | os.O_DIRECTORY | getattr(os, "O_CLOEXEC", 0))
    fd = os.open(path, os.O_RDONLY | getattr(os, "O_NONBLOCK", 0) | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0))
    src = Source(fd, header["size"], header["payload_at"], header["compressed"], max_decompressed, deadline)
    tree, nonce = Tree(), "%d-%d" % (os.getpid(), time.time_ns())
    counts = {"members_read": 0, "extracted_files": 0, "extracted_bytes": 0, "states": {}, "lone_zero_blocks": 0}
    problems, extended, zeros, tar_end, left_bytes = [], {}, 0, "missing", max_bytes
    data_after = 0
    with open(rows_path, "w", encoding="utf-8", newline="\n") as rows:
        rows.write("n\tstate\tpayload_offset\tsize\ttype\tderivative_path\tsha256\tmember\treason\n")
        rows.flush()
        try:
            while True:
                if counts["members_read"] >= max_members:
                    problems.append("max_members (%d) was reached: the rest of the payload is not read" % max_members)
                    tar_end = "not_reached"
                    break
                offset = src.pos
                block = src.read(512)
                if not block:
                    break
                if len(block) < 512:
                    problems.append("the payload ends %d bytes into a tar header" % len(block))
                    tar_end = "truncated"
                    break
                if block == ZERO:
                    zeros += 1
                    if zeros == 2:
                        tar_end = "reached"
                        break
                    continue
                if zeros == 1:
                    counts["lone_zero_blocks"] += 1
                zeros = 0
                h = parse_header(block)
                if h is None:
                    problems.append("a tar header at payload offset %d does not hold (checksum or number): the walk stops" % offset)
                    tar_end = "damaged"
                    break
                kind, size = TAR_TYPES.get(h["type"], "other"), h["size"]
                if h["type"] == b"S" and block[482]:
                    # An old GNU sparse header: its map's extension blocks sit between the header and the data, and are passed over.
                    extension_blocks = 0
                    while True:
                        ext = src.read(512)
                        extension_blocks += 1
                        if len(ext) < 512:
                            problems.append("the payload ends inside the sparse map of a member at offset %d" % offset)
                            tar_end = "truncated"
                            break
                        if not ext[504]:
                            break
                        if extension_blocks >= 65536:
                            problems.append("the sparse map of the member at offset %d has more than 65536 extension blocks: the walk stops" % offset)
                            tar_end = "damaged"
                            break
                    if tar_end in ("truncated", "damaged"):
                        break
                if kind in ("pax", "pax_global", "gnu_longname", "gnu_longlink"):
                    if size > EXTENDED_LIMIT:
                        problems.append("an extended header of %d bytes at payload offset %d is over the %d this recipe reads: the walk stops" % (size, offset, EXTENDED_LIMIT))
                        tar_end = "damaged"
                        break
                    data = src.read(size)
                    pad = (-size) % 512
                    if len(data) < size or src.skip(pad) < pad:
                        problems.append("the payload ends inside an extended header at offset %d" % offset)
                        tar_end = "truncated"
                        break
                    if kind == "pax":
                        records = pax_records(data)
                        if records is None:
                            problems.append("a pax header at payload offset %d does not parse" % offset)
                        else:
                            for key, field in ((b"path", "name"), (b"linkpath", "linkname")):
                                if key in records:
                                    extended[field] = records[key]
                            if b"size" in records and records[b"size"].isdigit():
                                extended["size"] = int(records[b"size"])
                            if any(key.startswith(b"GNU.sparse.") for key in records):
                                extended["sparse"] = True
                    elif kind == "gnu_longname":
                        extended["name"] = cstr(data)
                    elif kind == "gnu_longlink":
                        extended["linkname"] = cstr(data)
                    continue
                if "name" in extended:
                    h["name"] = extended["name"]
                if "size" in extended:
                    size = extended["size"]
                if extended.get("sparse") and kind in ("file", "other"):
                    kind = "sparse"
                extended = {}
                counts["members_read"] += 1
                name = h["name"].decode("utf-8", "surrogateescape")
                kind_n, package, domain, rest, why = classify_name(name)
                state, reason, sha, derived, progress = None, None, "", "", [0]
                if kind_n == "rejected":
                    state, reason = "rejected_name", why
                elif kind == "sparse":
                    state, reason = "sparse_not_extracted", "a sparse member is listed and not extracted"
                elif kind_n == "other":
                    state, reason = "outside_layout", "a member outside apps/ and shared/"
                elif kind_n == "shared":
                    state, reason = "shared_storage", "shared storage is not part of the app data layout"
                elif kind_n == "apps" and domain is None:
                    state, reason = ("directory", None) if kind == "directory" else ("outside_layout", "a member directly under the package directory")
                elif kind_n == "apps" and domain in NOT_LAID_OUT:
                    state, reason = "not_laid_out", "the APK, obb and external storage files are not laid out"
                elif kind_n == "apps" and domain not in DOMAINS:
                    state, reason = "unknown_domain", "the domain token is not in the mapping table"
                elif kind in ("symlink", "hardlink", "character_device", "block_device", "fifo"):
                    state, reason = kind, "listed, never created or followed"
                elif kind == "directory":
                    state = "directory"
                elif kind != "file":
                    state, reason = "outside_layout", "a member of type %s" % kind
                mapped = None
                if state is None:
                    if kind_n == "manifest":
                        mapped = ["ab_layout_meta", package, "_manifest"]
                    else:
                        root, sub = DOMAINS[domain]
                        mapped = root.split("/") + [package] + ([sub] if sub else []) + list(rest)
                        if not rest:
                            state = "directory"
                if state is None:
                    try:
                        final = tree.resolve(mapped)
                    except OverflowError:
                        state, reason = "layout_full", "the layout holds %d names" % MAX_CLAIMS
                if state is None:
                    derived = "/".join(final)
                    try:
                        sha = write_member(src, size, root_fd, final, left_bytes, deadline, progress, nonce)
                    except OverflowError:
                        state, reason = "not_extracted_max_bytes", "the member would pass max_bytes"
                        src.skip(size - progress[0])
                    except TimeoutError:
                        state, reason = "not_attempted_max_seconds", "the clock ran out while the member was being written"
                        src.skip(size - progress[0])
                    except EOFError:
                        state, reason = "truncated_member", "the payload ended inside this member"
                        tar_end = "truncated"
                    except FileExistsError:
                        state, reason = "write_failed", "the name is taken in the layout"
                        src.skip(size - progress[0])
                    except OSError as exc:
                        state, reason = "write_failed", "%s" % (exc.strerror or type(exc).__name__)
                        src.skip(size - progress[0])
                    else:
                        state = "extracted"
                        left_bytes -= size
                        counts["extracted_files"] += 1
                        counts["extracted_bytes"] += size
                    if state != "truncated_member":
                        pad = (-size) % 512
                        if src.skip(pad) < pad:
                            tar_end = "truncated"
                elif kind in ("file", "sparse", "other"):
                    if src.skip(size) < size:
                        state = "truncated_member" if src.error != "the clock" else "not_attempted_max_seconds"
                        tar_end = "truncated"
                    elif src.skip((-size) % 512) < (-size) % 512:
                        tar_end = "truncated"
                counts["states"][state] = counts["states"].get(state, 0) + 1
                rows.write("%d\t%s\t%d\t%d\t%s\t%s\t%s\t%s\t%s\n" % (counts["members_read"], state, offset, size, kind, tsv_escape(derived), sha, tsv_escape(name), tsv_escape(reason or "")))
                rows.flush()
                if tar_end in ("truncated", "damaged"):
                    break
            if tar_end == "reached":
                while True:
                    chunk = src.read(PIECE)
                    if not chunk:
                        break
                    data_after += sum(1 for b in chunk if b)
        finally:
            os.close(fd)
            os.close(root_fd)
    if src.error == "the clock" and tar_end in ("missing", "truncated"):
        tar_end = "not_reached"
    if src.error == "the clock":
        problems.append("the time given to the extraction ran out")
    if src.error == "the decompression budget":
        problems.append("the decompression budget (%d bytes) ended the payload" % max_decompressed)
    if src.state == "truncated":
        problems.append("the zlib stream ends before its end marker")
    if src.state == "damaged":
        problems.append("the zlib stream is damaged")
    if src.after:
        problems.append("%d byte(s) follow the end of the zlib stream and are not read" % src.after)
    if tar_end != "reached" and not any("max_members" in p for p in problems):
        problems.append("the tar's two end blocks were not reached (%s)" % tar_end)
    if counts["lone_zero_blocks"]:
        problems.append("%d lone zero block(s) were read past (a header followed them)" % counts["lone_zero_blocks"])
    if data_after:
        problems.append("data follows the tar's end blocks")
    bad = {k: n for k, n in counts["states"].items() if k not in BY_DESIGN and k != "extracted"}
    if bad:
        problems.append("%d member(s) are not in the layout for a reason that is not by design (%s)" % (sum(bad.values()), ", ".join("%s %d" % kv for kv in sorted(bad.items()))))
    return {"header": {k: header[k] for k in ("version", "compressed", "encryption")}, "stream": src.state, "tar_end": tar_end, "bytes_decompressed": src.produced,
            "bytes_after_stream": src.after, "counts": counts, "members_listed_in": "ab-members.tsv", "problems": problems,
            "kind": "derivative of an adb backup", "derivative": "derivative/"}, problems


def basis_of(lead, reasons):
    """The sentence status_basis is: the lead, then the first reasons (all of them are in `errors`)."""
    reasons = [str(r).replace("\n", " ") for r in reasons]
    return lead + "; ".join(reasons[:3]) + (" (and %d more in errors)" % (len(reasons) - 3) if len(reasons) > 3 else "")


def write_coverage(out, status, covered, errors, basis, limits=(), **more):
    with open(os.path.join(out, "coverage.json"), "w", encoding="utf-8") as handle:
        json.dump({"recipe": "android-backup-apps", "status": status, "status_basis": basis, "covered": covered, "not_covered": NOT_COVERED,
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
        handle.write("ab-members.tsv\tone row per member of the adb backup: its state, its offset, size and type, the name in the layout and the member as spelled\n")
        handle.write("derivative/\tthe derivative of the adb backup that ALEAPP read, with DERIVATIVE.json\n")
        handle.write("modules.tsv\tone row per module the ALEAPP log names: completed, no_record, unsupported, errored, errors_logged or unknown, with the records it reports and the log line\n")
        handle.write("aleapp.stdout\tALEAPP's standard output, whole: the log that modules.tsv points into\n")
        handle.write("aleapp.stderr\tALEAPP's standard error, whole\n")


def program_group_problems(what, held=True):
    """Sentences for the answer's problems from the shared process block's verdict, for an answer that reports `what`. A process settle() ended means what the program
    wrote (or printed on a pipe it held) was cut where it was ended; where the absence of one cannot be proven (not Linux, PR_SET_CHILD_SUBREAPER refused) files a program
    wrote cannot be shown to be final. held=False is a recipe that reports only what a program printed on a pipe: it is not held to the second rule (program_group still
    says why), but processes that were adopted and could not all be ended are still named."""
    verdict = process_verdict()
    found = []
    if verdict["left_behind"]:
        found.append("a program left %d process(es) running after it ended (in the recipe's process group, in a session of its own, or after a double fork); the shared process block "
                     "stopped, killed and reaped them before %s were read, so what they would still have written is missing from %s" % (verdict["left_behind"], what, what))
    for why in verdict["unproven"]:
        if held or verdict["subreaper"]:
            found.append("%s: %s cannot be shown to be final" % (why, what))
    return found


def child_files(directory):
    """How many files and links a program left in a directory this recipe gave it: kept, never deleted."""
    count = 0
    for _dirpath, dirs, files in os.walk(directory):
        count += len(files) + sum(1 for d in dirs if os.path.islink(os.path.join(_dirpath, d)))
    return count


LEAPP_SECONDS = 14100      # recipe.json limits.seconds (14400) less the time to write the account of the run
def last_word(signum):
    """The one line a stopped recipe prints (exit 128 plus the signal): the account written before the program started already says partial."""
    for temp in list(TEMPS):
        try:
            os.unlink(temp)
        except OSError:
            pass
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


def run(path, header, out, seconds=LEAPP_SECONDS):
    out = os.path.abspath(out)       # the program runs from a directory under out: nothing here may be relative
    report = os.path.join(out, "aleapp")
    derivative = os.path.join(out, "derivative")
    if os.path.lexists(report) or os.path.lexists(derivative) or os.path.lexists(os.path.join(out, "coverage.json")):
        # Before anything is written: an earlier run's coverage and report stay as they are.
        print(json.dumps({"ok": False, "status": "failed", "status_basis": "the output directory already holds the files of an earlier run, and this recipe never writes over one: nothing was run", "why": "the output directory already holds aleapp/ or coverage.json: the recipe does not write over an earlier run"}))
        return 2
    os.makedirs(out, exist_ok=True)
    STATE["last_word"] = last_word       # a stop in the layout phase gives one answer and leaves no hidden temporary
    install_signal_handlers()
    # Said before ALEAPP starts: a run stopped at its limit leaves this, and is read as partial.
    write_coverage(out, "partial", "started; ALEAPP did not finish (stopped before its end)", ["the run ended before ALEAPP did"],
                   "the run started and ALEAPP had not finished when this was written: a run that is stopped before its end leaves this account")
    prog = program()
    if not prog:
        write_coverage(out, "failed", "nothing: ALEAPP is not in this image", ["aleapp is not on PATH in this job image"],
                       "ALEAPP is not in this image, so nothing was parsed")
        return 1
    path = os.path.abspath(path)
    began = time.monotonic()
    ab_account, ab_problems = None, []
    try:
        ab_account, ab_problems = materialise(path, header, derivative, os.path.join(out, "ab-members.tsv"), began + seconds * 0.4)
    except OSError as exc:
        write_coverage(out, "failed", "nothing: the backup could not be laid out", ["the layout could not be made: %s" % (exc.strerror or exc)],
                       "the adb backup could not be laid out, so nothing was parsed: %s" % (exc.strerror or exc))
        return 1
    if not ab_account["counts"]["extracted_files"]:
        write_coverage(out, "failed", "nothing: the layout holds no file", ab_problems or ["the backup holds no member that is laid out"],
                       "the layout holds no file, so nothing was parsed", adb_backup=ab_account)
        return 1
    seconds = max(1.0, seconds - (time.monotonic() - began))
    kind = "layout of the adb backup (a derivative, ALEAPP -t fs)"
    scratch = os.path.join(out, "aleapp-run")
    # The run directory is read-only in a job: the program's working directory and its temporary files
    # are under the output, and every file it leaves there is kept and counted.
    cwd = os.path.join(out, "aleapp-cwd")
    temp = os.path.join(out, "aleapp-tmp")
    for directory in (scratch, cwd, temp):
        os.makedirs(directory, exist_ok=True)
    env = dict(os.environ, TMPDIR=temp)
    with open(os.path.join(out, "aleapp.stdout"), "wb") as so, open(os.path.join(out, "aleapp.stderr"), "wb") as se:
        rc, timed_out = run_program([prog, "-t", "fs", "-i", derivative, "-o", scratch], so, se, cwd, env, seconds)
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
    receipt_json = {"adb_backup": ab_account, "log_format_recognised": recognised, "counts": counts, "modules_listed_in": "modules.tsv",
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
    problems = list(ab_problems)
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
    # the reports, the logs and the files kept are what the program wrote: a process it left behind (ended by settle() before they were counted and read), or one that
    # cannot be ruled out (not Linux, PR_SET_CHILD_SUBREAPER refused), keeps the run from `complete`
    problems[0:0] = program_group_problems("the reports, the logs and the files ALEAPP kept")
    gated = counts["unsupported"]
    if rc == 0 and tsvs and not problems and not timed_out:
        write_coverage(out, "complete", "ALEAPP exited 0 over the %s and its log accounts for %d module(s): %d completed, %d with no record (no source file or no data)%s; %d TSV report(s)"
                       % (kind, len(modules), counts["completed"], counts["no_record"],
                          ", %d that do not take this operating-system version (see modules.tsv)" % gated if gated else "", tsvs), errors,
                       "ALEAPP exited 0, wrote %d TSV report(s) and its log accounts for every module it started as completed, no_record or unsupported" % tsvs,
                       modules=receipt_json, program_group=process_verdict())
    elif reports:
        write_coverage(out, "partial", "ALEAPP wrote %d report file(s); %d module(s) in its log: %d completed, %d no_record, %d unsupported, %d errored, %d errors_logged, %d unknown"
                       % (len(reports), len(modules), counts["completed"], counts["no_record"], gated, counts["errored"], counts["errors_logged"], counts["unknown"]),
                       (errors + problems) or ["ALEAPP wrote no TSV report"],
                       basis_of("partial because ", (errors + problems) or ["ALEAPP wrote no TSV report"]), modules=receipt_json, program_group=process_verdict())
    else:
        write_coverage(out, "failed", "nothing parsed", (errors + problems) or ["ALEAPP wrote no report"],
                       basis_of("nothing was parsed: ", (errors + problems) or ["ALEAPP wrote no report"]), modules=receipt_json, program_group=process_verdict())
    return 0 if rc == 0 and not timed_out else 1


def detect(path):
    """(applies, why, header)."""
    status, got = ab_header(path)
    if status is True:
        return True, "an unencrypted Android adb backup (version %d)" % got["version"], got
    return status, got, None


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("command", choices=("detect", "run"))
    parser.add_argument("--target", required=True)
    parser.add_argument("--out")
    parser.add_argument("--probe-out")
    parser.add_argument("--max-seconds", type=float, default=LEAPP_SECONDS)
    args = parser.parse_args()
    try:
        _, path = target_of(args.target)
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        print(json.dumps({"ok": False, "status": "failed", "status_basis": "the target could not be read, so nothing was run", "error": str(exc)}))
        return 2
    applies, why, header = detect(path)
    if args.command == "detect":
        print(json.dumps({"applies": applies, "why": why}))
        return 2 if applies == "unknown" else 0 if applies else 1
    if not args.out:
        print(json.dumps({"ok": False, "status": "failed", "status_basis": "run was given no output directory, so nothing was run", "error": "run needs --out DIR"}))
        return 2
    if applies is not True:
        print(json.dumps({"ok": False, "status": "failed", "status_basis": "the target is not one this recipe reads, so nothing was run", "why": why}))
        return 2
    rc = run(path, header, args.out, args.max_seconds)
    if rc == 2:
        return rc
    account = json.load(open(os.path.join(os.path.abspath(args.out), "coverage.json"), encoding="utf-8"))
    print(json.dumps({"ok": rc == 0, "status": account.get("status"), "status_basis": account.get("status_basis"),
                      **({"program_group": account["program_group"]} if "program_group" in account else {})}))
    return rc


if __name__ == "__main__":
    exit_code = 0
    try:
        sys.exit(main())
    except SystemExit as stop:
        exit_code = _code(stop)
    _leave(exit_code)
