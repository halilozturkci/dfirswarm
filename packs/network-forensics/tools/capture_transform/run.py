#!/usr/bin/env python3
"""Make derivative captures from original captures, and account for every packet.

An original capture is evidence and is never written: it is opened for reading only, by this tool (its size and SHA-256)
and by the Wireshark and tcpdump programs it runs (`editcap`, `mergecap`, `tcpdump -r`, `text2pcap`, and `capinfos` for the
packet counts). Every output is a DERIVATIVE, written under out_dir and labelled "derivative, not evidence". A filter, a
split, a merge or a dedup changes which packets are in the file, so the answer says, for every operation, how many
packets went in, how many came out and how many were dropped, and why. Nothing here is the original capture.

One operation per call (`operation`):

  split     editcap -c (packets per file) or -i (seconds per file): the parts together hold every packet.
  merge     mergecap, chronological or -a (appended in the order given): the effect on the order and the interfaces is read
            back from capinfos for the inputs and the output.
  filter    tcpdump -n -r IN -w OUT -- FILTER: a recorded BPF filter; the packets it dropped are counted, not listed.
  dedup     editcap -d, -D (a window of packets) or -w (a window of seconds): the removed duplicates are counted.
  convert   editcap -F pcap or pcapng. pcapng to pcap loses what the pcap format has no place for (said in the answer).
  hexdump   text2pcap: a text hex dump becomes a capture with SYNTHETIC timestamps and, when an option asks for them, synthetic
            headers. It is never evidence that traffic occurred.

A time shift (editcap -t) is refused: the tool has no parameter for it. Each derivative is written first to a temporary
directory inside out_dir and placed with place_without_replacing: an output never replaces a file that is there (the next
free name, -2, -3, takes it), and a stop leaves no half file under a final name. SIGTERM, SIGINT and SIGHUP end the tool
with partial JSON that names the derivatives already placed, and exit 128 plus the signal.
"""
import json
import os
import signal
import sys

TOOL = {"name": "capture_transform", "version": 3}
PARSER = "capture_transform/1"

# BEGIN SHARED STOP
# The same text is in every tool that carries this block (tests/pack-shared-stop.test.ts holds the copies equal). SIGTERM, SIGINT and SIGHUP end the tool with JSON
# (status failed with interrupted true: a stop is not a status, the statuses are complete, partial and failed; exit 128 + the signal) and remove the temporary file a page was writing; the tool's own clock (set_deadline) is below the manifest's.
# The handlers are in as soon as the module has run as far as this block, with a minimal last word until main() installs the tool's own (only
# the start of the interpreter and the compiling of the file come before it). The first signal counts: a second one does nothing while the
# first is answered. print_answer holds the stop signals back while the answer is printed, so exactly one complete document is written
# (the ransomware tools print through it; the windows tools hold the signals in the emit of their boundary block, and carry this text unused).
import signal
import time

STOP = {"last_word": None, "deadline": None}


def set_deadline(seconds):
    STOP["deadline"] = time.monotonic() + seconds


def out_of_time():
    return STOP["deadline"] is not None and time.monotonic() > STOP["deadline"]


def _on_signal(signum, _frame):
    for other in (signal.SIGTERM, signal.SIGINT, signal.SIGHUP):
        signal.signal(other, signal.SIG_IGN)
    for page in list(globals().get("PAGES", ())):
        tmp = getattr(page, "_tmp", None)
        if tmp is not None:
            try:
                os.unlink(tmp)
            except OSError:
                pass
    last_word = STOP["last_word"]
    if last_word:
        try:
            last_word(signum)
        except Exception:  # noqa: BLE001 - a last word is best effort
            pass
    os._exit(128 + signum)


def install_signal_handlers(last_word=None):
    STOP["last_word"] = last_word
    for signum in (signal.SIGTERM, signal.SIGINT, signal.SIGHUP):
        signal.signal(signum, _on_signal)


def interrupted_answer(signum, **extra):
    print(json.dumps({"error": "stopped by signal %d before the answer was complete" % signum, "status": "failed", "interrupted": True,
                      "status_basis": "the tool was stopped by signal %d; nothing it had read is an answer" % signum,
                      "signal": signum, **extra}), flush=True)


def print_answer(answer, **dumps_kwargs):
    """Print the answer with the stop signals held back: a signal that came in the middle of the write would end the process there, with the
    answer cut. The tool ends by itself right after, so a signal that is held is not lost for good."""
    try:
        signal.pthread_sigmask(signal.SIG_BLOCK, {signal.SIGTERM, signal.SIGINT, signal.SIGHUP})
    except (AttributeError, ValueError, OSError):
        pass
    STOP["last_word"] = None
    print(json.dumps(answer, **dumps_kwargs))


install_signal_handlers(lambda signum: interrupted_answer(signum))
# END SHARED STOP

import errno
import hashlib
import re
import shutil
import stat
import subprocess
import tempfile
import time
from pathlib import Path

MANIFEST_SECONDS = 1200       # the manifest's limit; the tool's own clock (max_seconds) ends well before it
DEFAULT_SECONDS = 900
MAX_SECONDS = 1000
PREFLIGHT_SECONDS = 30
CAPINFOS_SECONDS = 120        # one batch of capinfos
CAPINFOS_BATCH = 100          # files to one capinfos call
MAX_INPUTS = 64
MAX_OUTPUTS = 10_000          # parts of a split: more is refused before anything is placed
DIAG_LINES = 20               # lines of a program's output answered inline; the whole is in a file
DIAG_CHARS = 300
DIAG_READ = 1 << 16
HASH_CLOCK_BYTES = 1 << 24
OPERATIONS = ("split", "merge", "filter", "dedup", "convert", "hexdump")
FORMATS = ("pcap", "pcapng")
ALLOWED = ("operation", "inputs", "out_dir", "packets", "seconds", "dedup_window", "dedup_seconds", "bpf_filter", "format", "merge_order",
           "link_type", "ethernet_type", "ip_protocol", "udp_ports", "tcp_ports", "limit", "max_seconds")
TIME_SHIFT = ("time_shift", "time_adjustment", "shift", "adjust_time", "strict_time_adjustment")
LABEL = "derivative, not evidence"
SYNTHETIC_LABEL = ("derivative, not evidence: synthetic. The headers and timestamps were made by text2pcap from a text dump; the file "
                   "shows nothing about traffic that occurred")
PCAPNG_ONLY = ("Name Resolution Blocks, Interface Statistics Blocks, Decryption Secrets Blocks, packet and section comments and the "
               "options of the Section Header and Interface Description Blocks, and, past the first, every interface with a different "
               "link type (a pcap file has one)")


def describe(exc):
    code = errno.errorcode.get(exc.errno, "") if getattr(exc, "errno", None) else ""
    return "%s%s: %s" % (type(exc).__name__, " " + code if code else "", getattr(exc, "strerror", None) or str(exc))


def in_job():
    return bool(os.environ.get("JOB_ID") and os.environ.get("OUT"))


def open_regular(path, follow=True):
    """A file opened for reading that is never waited on: the open does not block (a name that became a pipe since it was checked would otherwise wait
    for a writer), the type is read from the descriptor, and anything but a regular file is refused."""
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


PROGRESS = {"stage": "arguments", "out_dir": None, "work": None, "placed": []}
STOP_LISTED = 200


def cleanup():
    """What this run left that is not a derivative: the temporary directory (every part not yet placed is in it) and the hidden file of a page."""
    for page in list(PAGES):
        tmp = getattr(page, "_tmp", None)
        if tmp is not None:
            try:
                os.unlink(tmp)
            except OSError:
                pass
    work, PROGRESS["work"] = PROGRESS.get("work"), None
    if work:
        shutil.rmtree(work, ignore_errors=True)


def fail(message, **extra):
    if hasattr(signal, "pthread_sigmask"):
        signal.pthread_sigmask(signal.SIG_BLOCK, {signal.SIGTERM, signal.SIGINT, signal.SIGHUP})     # one document: a stop that arrives while this is written waits
    STATE["last_word"] = None
    STOP["last_word"] = None
    cleanup()
    basis = "the tool stopped with an error (see error); " + ("the derivatives already placed are whole" if PROGRESS["placed"] else "nothing was placed")
    print(json.dumps({"error": message, "tool": TOOL, "status": "failed", "status_basis": basis,
                      **({"derivatives_placed": PROGRESS["placed"][:STOP_LISTED]} if PROGRESS["placed"] else {}), **extra}))
    raise SystemExit(1)


def resolve_output(out, what="output"):
    """Where `out` really lands, as a path under the run directory; a place outside it, the run directory itself, or anything under inputs/ is refused, and in a
    job so is anything outside $OUT. Resolving first and comparing directories is what holds: `work/../inputs/x`, an absolute path and a link that points out
    all name a place the tool must not write."""
    root = Path.cwd().resolve()
    dest = (root / out).resolve() if not Path(out).is_absolute() else Path(out).resolve()
    if dest == root or root not in dest.parents:
        fail("%s must stay inside the run directory" % what, **{what: str(out)})
    inputs = root / "inputs"
    if dest == inputs or inputs in dest.parents:
        fail("%s cannot be under inputs/" % what, **{what: str(out)})
    if in_job():
        job_out = Path(os.environ["OUT"]).resolve()
        if dest != job_out and job_out not in dest.parents:
            fail("in a job %s is a directory under $OUT, the one place a job writes" % what, **{what: str(out), "out": str(job_out)})
    return str(dest.relative_to(root))


class LosslessPage:
    def __init__(self, tool: str, key: object, limit: int):
        if isinstance(limit, bool) or not isinstance(limit, int) or limit < 1:
            raise ValueError("limit must be a positive integer")
        self.tool = re.sub(r"[^A-Za-z0-9_.-]", "_", tool)
        self.limit = limit
        self.page: list[object] = []
        self.total = 0
        self._out = None
        self._tmp: Path | None = None
        digest = hashlib.sha256(
            json.dumps(key, sort_keys=True, default=str).encode("utf-8")
        ).hexdigest()[:16]
        name = f"{self.tool}-{digest}.jsonl"
        job, out = os.environ.get("JOB_ID"), os.environ.get("OUT")
        if job and out:
            # In a job only $OUT is written, and it is sealed as the job's
            # output: the whole result is cited from there.
            self.path = Path(out) / "tool-output" / name
            self.shown = "store/jobs/%s/out/tool-output/%s" % (re.sub(r"[^A-Za-z0-9_.-]", "_", job), name)
        else:
            agent = re.sub(
                r"[^A-Za-z0-9_.-]", "_", os.environ.get("AGENT_ID") or "tool"
            )
            self.path = Path("work") / agent / "tool-output" / name
            self.shown = str(self.path)

    def _cannot_write(self, exc: BaseException) -> None:
        """The whole result cannot be kept: say so as JSON and stop, never a traceback."""
        import sys as _sys
        _sys.stdout.write(json.dumps({
            "error": "the whole result (%d rows so far) cannot be written to %s: %s. Outside a job the place is your own "
                     "work/<your id>/ directory; in a job it is $OUT." % (self.total, self.shown, exc),
            "status": "failed",
        }) + "\n")
        _sys.exit(1)

    def _write(self, row: object) -> None:
        assert self._out is not None
        text = json.dumps(row, ensure_ascii=False, default=str)
        try:
            text.encode("utf-8")
        except UnicodeEncodeError:
            # A lone surrogate (a file name that is not UTF-8): escape it, lose nothing.
            text = json.dumps(row, ensure_ascii=True, default=str)
        try:
            self._out.write(text)
            self._out.write("\n")
        except OSError as exc:
            self._cannot_write(exc)

    def add(self, row: object) -> None:
        self.total += 1
        if len(self.page) < self.limit:
            self.page.append(row)
            return
        if self._out is None:
            try:
                self.path.parent.mkdir(parents=True, exist_ok=True)
                fd, name = tempfile.mkstemp(
                    dir=self.path.parent, prefix=f".{self.path.name}-"
                )
                self._tmp = Path(name)
                self._out = os.fdopen(fd, "w", encoding="utf-8")
            except OSError as exc:
                self._cannot_write(exc)
            for kept in self.page:
                self._write(kept)
        self._write(row)

    def finish(self) -> dict:
        result = {
            "matched": self.total,
            "returned": len(self.page),
            "truncated": self.total > len(self.page),
        }
        if self._out is not None:
            try:
                self._out.flush()
                os.fsync(self._out.fileno())
                self._out.close()
                assert self._tmp is not None
                os.replace(self._tmp, self.path)
            except OSError as exc:
                self._cannot_write(exc)
            result["all_results"] = self.shown
            result["all_results_format"] = "JSON Lines, one complete result per line"
        return result


# BEGIN SHARED PLACE
# The same text is in every windows-forensics tool that keeps a result file (a windows-forensics test holds the copies equal).
# A result file that is there is never replaced by another result: a file of the same bytes is named again, any other result takes the next free
# <stem>-<n><suffix>. A result written at the same moment cannot be replaced either: taking a name fails when it is there.
# Only regular files are ever compared: both names are opened with O_NONBLOCK and O_NOFOLLOW and looked at with fstat before a byte is
# read, so a FIFO, a device, a directory or a link at a name (the caller's own results_to, say) is another result's and cannot hold the
# tool. The comparing of one call has PLACE_COMPARE_SECONDS in all; past it an earlier result is taken as different and this one takes
# the next free name (nothing is replaced, but an identical rerun may then be named anew).
# The name is taken with a hard link of the finished file, so it never holds an empty file, whatever stops the tool and when (SIGKILL
# included). Where the file system refuses the link, the name is taken with an exclusive create and the file is moved over it: a stop
# that unwinds (an exception) takes the empty name back while it is still the empty file this call made; a stop that ends the process
# without unwinding (SIGKILL, the handlers of the STOP block) between the create and the move leaves the empty name, and the next run takes -2.
PLACE_COMPARE_SECONDS = 5   # all the comparing one call to place_without_replacing does; past it an earlier result is taken as different


def same_bytes(a, b, deadline=None):
    """Whether two files hold the same bytes (read in blocks, never whole). Each is opened without waiting and without following a link
    (O_NONBLOCK, O_NOFOLLOW) and looked at with fstat first: only two regular files of one size are read, so a FIFO, a device, a
    directory or a link at either name is never read (a FIFO would hold the tool for ever). Past `deadline` (a monotonic time) the
    answer is False."""
    flags = os.O_RDONLY | getattr(os, "O_NONBLOCK", 0) | getattr(os, "O_NOFOLLOW", 0)
    fa = fb = None
    try:
        fa = os.fdopen(os.open(str(a), flags), "rb")
        fb = os.fdopen(os.open(str(b), flags), "rb")
        sa, sb = os.fstat(fa.fileno()), os.fstat(fb.fileno())
        if (sa.st_mode & 0o170000) != 0o100000 or (sb.st_mode & 0o170000) != 0o100000 or sa.st_size != sb.st_size:
            return False
        while True:
            if deadline is not None and time.monotonic() > deadline:
                return False
            x, y = fa.read(1 << 20), fb.read(1 << 20)
            if x != y:
                return False
            if not x:
                return True
    except OSError:
        return False
    finally:
        for fh in (fa, fb):
            if fh is not None:
                fh.close()


def _take_name(tmp, candidate):
    """Give the finished `tmp` the name `candidate` if it is free, and say whether it now has it (False: the name is taken, by a file, a
    link, a FIFO or a directory). The name is taken with a hard link, so it never holds an empty file; where the file system refuses the
    link it is taken with an exclusive create and the file is moved over it, and a stop that unwinds in between takes the empty name back."""
    try:
        os.link(tmp, candidate)
    except FileExistsError:
        return False
    except OSError:
        pass                                   # no hard links here: the older way, below
    else:
        try:
            os.unlink(tmp)
        except OSError:
            pass                               # the hidden name stays beside the placed file; the stop path of the page removes it
        return True
    fd = made = None
    try:
        fd = os.open(str(candidate), os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o600)
        made = os.fstat(fd)
        closing, fd = fd, None
        os.close(closing)
        os.replace(tmp, candidate)             # only replaces the empty file this call just made
        return True
    except FileExistsError:
        return False
    except BaseException:
        try:
            if made is None and fd is not None:
                made = os.fstat(fd)
        except OSError:
            pass
        try:
            if fd is not None:
                os.close(fd)
        except OSError:
            pass
        try:
            now = os.lstat(candidate)
            if made is not None and (now.st_mode & 0o170000) == 0o100000 and now.st_size == 0 and (now.st_dev, now.st_ino) == (made.st_dev, made.st_ino):
                os.unlink(candidate)           # the empty name this call took is not left behind
        except OSError:
            pass
        raise


def place_without_replacing(tmp, path):
    """Move the finished `tmp` to `path` and never replace what is there. A name that is taken (by a file, a link, a FIFO or a directory) is
    left as it is: a regular file of the same bytes is named again, any other result takes the next free <stem>-<n><suffix>. Returns the
    path that holds it. The comparing with earlier results has PLACE_COMPARE_SECONDS in all: past it an earlier result is taken as
    different and this one takes the next free name."""
    deadline = time.monotonic() + PLACE_COMPARE_SECONDS
    for n in range(1, 1000):
        candidate = path if n == 1 else path.with_name("%s-%d%s" % (path.stem, n, path.suffix))
        if _take_name(tmp, candidate):
            return candidate
        if not os.path.islink(candidate) and same_bytes(tmp, candidate, deadline):
            os.unlink(tmp)
            return candidate
    raise OSError("no free name beside %s" % path)
# END SHARED PLACE


# BEGIN SHARED PAGE
# The same text is in every windows-forensics tool that pages through LosslessPage (held equal by a windows-forensics test): LosslessPage replaces a file of the
# same name; this one places its finished file with place_without_replacing, and registers itself so that a stop can remove its temporary file.
PAGES = []


class NoReplacePage(LosslessPage):
    """LosslessPage whose finished file is placed without replacing an earlier file of the same name (a rerun with other limits, or one
    the time limit stopped, must not leave a smaller file where a larger one was)."""

    def __init__(self, tool, key, limit):
        super().__init__(tool, key, limit)
        PAGES.append(self)

    def finish(self) -> dict:
        result = {"matched": self.total, "returned": len(self.page), "truncated": self.total > len(self.page)}
        if self._out is not None:
            try:
                self._out.flush()
                os.fsync(self._out.fileno())
                self._out.close()
                assert self._tmp is not None
                placed = place_without_replacing(self._tmp, self.path)
            except OSError as exc:
                self._cannot_write(exc)
            self._tmp = None
            self.path = placed
            self.shown = self.shown[: len(self.shown) - len(Path(self.shown).name)] + placed.name
            result["all_results"] = self.shown
            result["all_results_format"] = "JSON Lines, one complete result per line"
        return result
# END SHARED PAGE


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
        if pid in table and (table[pid] is None or table[pid] == ident):
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
        if row is None or listed != SEEN_IDENT[pid] or row[0] == me:
            continue
        parent = row[0]
        if parent in table and SEEN_IDENT.get(parent) is not None and table.ident.get(parent) == SEEN_IDENT[parent]:
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
    turn a complete answer into a partial one (status "partial", the ok and complete flags that are there false, a sentence in status_basis):
    what a program wrote while the tool read it is not a complete result. A carrier calls it once where it prints its answer. Returns `answer`."""
    verdict = process_verdict()
    answer["program_group"] = verdict
    if (verdict["left_behind"] > 0 or verdict["unproven"]) and answer.get("status") == "complete":
        answer["status"] = "partial"
        for flag in ("ok", "complete"):
            if flag in answer:
                answer[flag] = False
        if verdict["left_behind"] > 0:
            sentence = "a program left %d process%s running after it ended; the tool ended them, and what they wrote before that is in the files named here" % (
                verdict["left_behind"], "" if verdict["left_behind"] == 1 else "es")
        else:
            sentence = "the tool cannot prove that no program left a process behind (see program_group.unproven)"
        basis = answer.get("status_basis")
        answer["status_basis"] = "%s; %s" % (basis, sentence) if isinstance(basis, str) and basis else sentence
    return answer


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
            settle()
            return out or b"", err or b"", False
        except subprocess.TimeoutExpired as exc:
            started = True
            out, err = exc.stdout or b"", exc.stderr or b""
    try:
        out, err = proc.communicate(None if started else input, timeout=PIPE_GRACE)
    except subprocess.TimeoutExpired as exc:
        out, err = exc.stdout or b"", exc.stderr or b""
        reap_orphans(_pipe_inodes(proc))
        settle()
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
    settle()
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


class TransformPage(NoReplacePage):
    """NoReplacePage whose refused write is this tool's own failed answer, with the derivatives already placed named and the temporary files removed
    (the parent prints its own text and leaves the hidden file of the page behind)."""

    def _cannot_write(self, exc):
        fail("the whole list of derivatives (%d rows so far) cannot be written to %s (%s); the derivatives already placed are whole files" % (self.total, self.shown, describe(exc)))


def last_word(signum):
    """What a stopped run says on stdout: partial, the stage, and the derivatives already placed (each a whole file)."""
    cleanup()
    placed = PROGRESS["placed"]
    print(json.dumps({"tool": TOOL, "parser": PARSER, "status": "partial", "ok": False,
                      "status_basis": "the tool was stopped by signal %d while it was %s; the programs it had started were killed with what they started, the temporary directory "
                                      "was removed, and the derivatives listed were placed whole before the stop (a part still being written is not among them)" % (signum, PROGRESS["stage"]),
                      "interrupted_by_signal": signum, "stage": PROGRESS["stage"], "out_dir": PROGRESS["out_dir"],
                      "derivatives_placed": placed[:STOP_LISTED], "derivatives_placed_total": len(placed)}), flush=True)


def answer_out(text):
    """Print the final answer as one unit a stop signal cannot cut or follow: signals are held while it is written and there is no last
    word to add to it, so a signal that arrives during or after it ends the tool (exit 128 plus the signal) with this one document."""
    held = (signal.SIGTERM, signal.SIGINT, signal.SIGHUP)
    signal.pthread_sigmask(signal.SIG_BLOCK, held)
    try:
        STATE["last_word"] = None
        STOP["last_word"] = None
        print(text, flush=True)
    finally:
        signal.pthread_sigmask(signal.SIG_UNBLOCK, held)


def positive_int(args, key, low=1, high=None):
    value = args.get(key)
    if value is None:
        return None
    if isinstance(value, bool) or not isinstance(value, int) or value < low or (high is not None and value > high):
        fail("%s must be an integer from %d%s" % (key, low, " to %d" % high if high is not None else " up"), **{key: value if isinstance(value, (int, float)) else None})
    return value


def read_arguments():
    try:
        args = json.load(sys.stdin)
    except ValueError as exc:
        fail("arguments are not valid JSON", reason=str(exc))
    if not isinstance(args, dict):
        fail("arguments must be a JSON object")
    for name in TIME_SHIFT:
        if name in args:
            fail("a time shift is refused: this tool has no parameter that changes a packet's time (editcap -t and -S are not offered); a derivative keeps the "
                 "times of the packets it holds", parameter=name)
    unknown = sorted(k for k in args if k not in ALLOWED)
    if unknown:
        fail("unknown parameters: %s" % ", ".join(k[:40] for k in unknown[:10]), allowed=list(ALLOWED))
    operation = args.get("operation")
    if operation not in OPERATIONS:
        fail("operation must be one of %s" % ", ".join(OPERATIONS))
    inputs = args.get("inputs")
    if (not isinstance(inputs, list) or not inputs or len(inputs) > MAX_INPUTS or any(not isinstance(p, str) or not p or "\0" in p for p in inputs)):
        fail("inputs must be a list of 1 to %d file names" % MAX_INPUTS)
    if operation == "merge" and len(inputs) < 2:
        fail("merge takes two or more inputs")
    if operation != "merge" and len(inputs) != 1:
        fail("%s takes exactly one input" % operation)
    out_dir = args.get("out_dir")
    if not isinstance(out_dir, str) or not out_dir or "\0" in out_dir:
        fail("out_dir is required: a directory under work/ (in a job, under $OUT) for the derivatives")
    packets, seconds = positive_int(args, "packets"), positive_int(args, "seconds")
    window, window_seconds = positive_int(args, "dedup_window", 0, 1_000_000), args.get("dedup_seconds")
    fmt = args.get("format")
    if fmt is not None and fmt not in FORMATS:
        fail("format must be pcap or pcapng")
    order = args.get("merge_order", "chronological")
    if order not in ("chronological", "append"):
        fail("merge_order must be chronological or append")
    flt = args.get("bpf_filter")
    if flt is not None and (not isinstance(flt, str) or not flt.strip() or len(flt) > 4096 or "\0" in flt):
        fail("bpf_filter must be a non-empty string of at most 4096 characters")
    link_type, ip_protocol = positive_int(args, "link_type", 0, 65535), positive_int(args, "ip_protocol", 0, 255)
    ethernet_type = args.get("ethernet_type")
    if ethernet_type is not None and (not isinstance(ethernet_type, str) or not re.fullmatch(r"0x[0-9A-Fa-f]{1,4}", ethernet_type)):
        fail("ethernet_type must be a hexadecimal number such as 0x0800")
    ports = {}
    for key in ("udp_ports", "tcp_ports"):
        value = args.get(key)
        if value is not None:
            if (not isinstance(value, list) or len(value) != 2 or any(isinstance(p, bool) or not isinstance(p, int) or not 0 <= p <= 65535 for p in value)):
                fail("%s must be [source port, destination port]" % key)
            ports[key] = value
    if window_seconds is not None and (isinstance(window_seconds, bool) or not isinstance(window_seconds, (int, float)) or not 0 < window_seconds <= 3600):
        fail("dedup_seconds must be a number above 0 and at most 3600")
    limit = args.get("limit", 200)
    if isinstance(limit, bool) or not isinstance(limit, int) or limit < 1:
        fail("limit must be a positive integer")
    max_seconds = args.get("max_seconds", DEFAULT_SECONDS)
    if isinstance(max_seconds, bool) or not isinstance(max_seconds, int) or not 10 <= max_seconds <= MAX_SECONDS:
        fail("max_seconds must be an integer from 10 to %d: kept under the manifest's %d seconds so that this tool stops its programs itself" % (MAX_SECONDS, MANIFEST_SECONDS))
    # What each operation takes, and what it does not.
    given = {"packets": packets, "seconds": seconds, "dedup_window": window, "dedup_seconds": window_seconds, "bpf_filter": flt, "format": fmt,
             "link_type": link_type, "ethernet_type": ethernet_type, "ip_protocol": ip_protocol, **ports, "merge_order": args.get("merge_order")}
    own = {"split": ("packets", "seconds", "format"), "dedup": ("dedup_window", "dedup_seconds", "format"), "filter": ("bpf_filter",), "convert": ("format",),
           "merge": ("merge_order", "format"), "hexdump": ("link_type", "ethernet_type", "ip_protocol", "udp_ports", "tcp_ports", "format")}[operation]
    stray = sorted(k for k, v in given.items() if v is not None and k not in own)
    if stray:
        fail("%s does not take %s" % (operation, ", ".join(stray)))
    if operation == "split" and (packets is None) == (seconds is None):
        fail("split takes exactly one of packets (a part every N packets) and seconds (a part every N seconds)")
    if operation == "dedup" and window is not None and window_seconds is not None:
        fail("dedup takes at most one of dedup_window and dedup_seconds")
    if operation == "filter" and flt is None:
        fail("filter needs bpf_filter")
    if operation == "convert" and fmt is None:
        fail("convert needs format")
    if operation == "hexdump" and sum(1 for v in (ethernet_type, ip_protocol, ports.get("udp_ports"), ports.get("tcp_ports")) if v is not None) > 1:
        fail("hexdump takes at most one of ethernet_type, ip_protocol, udp_ports and tcp_ports: they are alternative ways text2pcap makes headers")
    return dict(operation=operation, inputs=inputs, out_dir=out_dir, packets=packets, seconds=seconds, window=window, window_seconds=window_seconds,
                format=fmt, order=order, bpf_filter=flt, link_type=link_type, ethernet_type=ethernet_type, ip_protocol=ip_protocol,
                udp_ports=ports.get("udp_ports"), tcp_ports=ports.get("tcp_ports"), limit=limit, max_seconds=max_seconds)


def digest_of(path, deadline):
    """(size, SHA-256) of a regular file, read in blocks; the clock is looked at every HASH_CLOCK_BYTES. A FIFO, a device or a directory is refused
    before a byte is read."""
    h, size, since = hashlib.sha256(), 0, 0
    with open_regular(path) as fh:
        while True:
            block = fh.read(1 << 20)
            if not block:
                return size, h.hexdigest()
            h.update(block)
            size += len(block)
            since += len(block)
            if since >= HASH_CLOCK_BYTES:
                since = 0
                if time.monotonic() > deadline:
                    raise TimeoutError("the tool's own clock ran out while %s was read" % os.path.basename(path)[:80])


def first_line(blob):
    for line in blob.decode("utf-8", "replace").splitlines():
        if line.strip():
            return line.strip()[:200]
    return None


def program_version(binary, deadline):
    """The first line of `<program> --version`, or None (tcpdump prints it on stderr)."""
    code, out, err, timed_out = preflight([binary, "--version"], max(1.0, min(PREFLIGHT_SECONDS, deadline - time.monotonic())))
    return first_line(out) or first_line(err)


CAPINFOS_FIELDS = (
    ("packets", re.compile(r"^Number of packets(?: in file)?:\s+(\d+)\s*$")),
    ("file_type", re.compile(r"^File type:\s+(.+?)\s*$")),
    ("encapsulation", re.compile(r"^File encapsulation:\s+(.+?)\s*$")),
    ("interfaces", re.compile(r"^Number of interfaces in file:\s+(\d+)\s*$")),
)


def parse_capinfos(blob):
    """capinfos -M output for one or more files, as one dict per file in the order printed (each starts at its `File name:` line). Only the lines
    this tool uses are read; a line it does not know is left, and a file with no packet count has packets None."""
    entries, current = [], None
    for raw in blob.decode("utf-8", "replace").splitlines():
        line = raw.strip()[:2000]
        if line.startswith("File name:"):
            current = {"packets": None, "file_type": None, "encapsulation": None, "interfaces": None}
            entries.append(current)
            continue
        if current is None:
            continue
        for key, pattern in CAPINFOS_FIELDS:
            m = pattern.match(line)
            if m:
                current[key] = int(m.group(1)) if key in ("packets", "interfaces") else m.group(1)
    return entries


def capinfos(binary, paths, deadline, work):
    """capinfos on `paths` in batches. ([one dict per path, or None for a file capinfos did not describe], the problems as sentences)."""
    out, problems = [], []
    for start in range(0, len(paths), CAPINFOS_BATCH):
        batch = paths[start:start + CAPINFOS_BATCH]
        left = deadline - time.monotonic()
        if left < 1:
            out.extend([None] * len(batch))
            problems.append("the tool's own clock ran out before capinfos described %d file(s)" % len(batch))
            continue
        o, e = os.path.join(work, "capinfos.stdout"), os.path.join(work, "capinfos.stderr")
        code, timed_out = run_to_files([binary, "-M"] + batch, o, e, min(CAPINFOS_SECONDS, left))
        with open_regular(o, follow=False) as fh:
            blob = fh.read(64 << 20)
        entries = parse_capinfos(blob)
        if timed_out or len(entries) != len(batch):
            out.extend([None] * len(batch))
            problems.append("capinfos %s for %d file(s) (it described %d)" % ("did not finish in time" if timed_out else "exited %s" % code, len(batch), len(entries)))
            continue
        if code not in (0, None):
            problems.append("capinfos exited %s: at least one file is cut short or not a capture it reads" % code)
        out.extend(entries)
    return out, problems


def diagnostics(stdout_path, stderr_path):
    """The first DIAG_LINES lines of a program's output (each cut to DIAG_CHARS) and the counts; the whole is in the two files."""
    lines, total, size = [], 0, 0
    for path in (stderr_path, stdout_path):
        try:
            with open_regular(path, follow=False) as fh:
                while True:
                    raw = fh.readline(DIAG_READ)
                    if not raw:
                        break
                    total += 1
                    size += len(raw)
                    text = raw.decode("utf-8", "replace").strip()
                    if text and len(lines) < DIAG_LINES:
                        lines.append(text[:DIAG_CHARS] + (" ...(%d more characters)" % (len(text) - DIAG_CHARS) if len(text) > DIAG_CHARS else ""))
        except OSError:
            continue
    return {"lines": lines, "lines_total": total, "bytes": size}


def commands(p, binaries, work, input_paths, kind):
    """(the steps, as [label, argv, output file name or None]) for the operation. Every output is written inside `work`."""
    op = p["operation"]
    ext = ".pcapng" if (p["format"] or kind) == "pcapng" else ".pcap"
    fmt = ["-F", p["format"]] if p["format"] else []
    src = [os.path.abspath(i) for i in input_paths]
    out = lambda name: os.path.join(work, name)       # noqa: E731
    if op == "split":
        cut = ["-c", str(p["packets"])] if p["packets"] else ["-i", str(p["seconds"])]
        return [["editcap", [binaries["editcap"]] + cut + fmt + [src[0], out("part" + ext)], None]], ext
    if op == "dedup":
        mode = ["-D", str(p["window"])] if p["window"] is not None else (["-w", repr(float(p["window_seconds"]))] if p["window_seconds"] is not None else ["-d"])
        return [["editcap", [binaries["editcap"]] + mode + fmt + [src[0], out("deduplicated" + ext)], "deduplicated" + ext]], ext
    if op == "convert":
        return [["editcap", [binaries["editcap"]] + fmt + [src[0], out("converted" + ext)], "converted" + ext]], ext
    if op == "merge":
        return [["mergecap", [binaries["mergecap"]] + (["-a"] if p["order"] == "append" else []) + fmt + ["-w", out("merged" + ext)] + src, "merged" + ext]], ext
    if op == "filter":
        return [["tcpdump", [binaries["tcpdump"], "-n", "-r", src[0], "-w", out("filtered.pcap"), "--", p["bpf_filter"]], "filtered.pcap"]], ".pcap"
    synthetic = []
    if p["link_type"] is not None:
        synthetic += ["-l", str(p["link_type"])]
    if p["ethernet_type"] is not None:
        synthetic += ["-e", p["ethernet_type"]]
    if p["ip_protocol"] is not None:
        synthetic += ["-i", str(p["ip_protocol"])]
    if p["udp_ports"] is not None:
        synthetic += ["-u", "%d,%d" % tuple(p["udp_ports"])]
    if p["tcp_ports"] is not None:
        synthetic += ["-T", "%d,%d" % tuple(p["tcp_ports"])]
    ext = ".pcap" if p["format"] == "pcap" else ".pcapng"
    return [["text2pcap", [binaries["text2pcap"]] + synthetic + fmt + [src[0], out("text2pcap" + ext)], "text2pcap" + ext]], ext


def main():
    started = time.monotonic()
    STATE["last_word"] = last_word
    STOP["last_word"] = last_word
    install_signal_handlers()
    p = read_arguments()
    deadline = started + p["max_seconds"]
    operation = p["operation"]
    out_dir = resolve_output(p["out_dir"], "out_dir")
    PROGRESS["out_dir"] = out_dir
    PROGRESS["operation"] = operation
    needed = {"split": ["editcap"], "dedup": ["editcap"], "convert": ["editcap"], "merge": ["mergecap"], "filter": ["tcpdump"], "hexdump": ["text2pcap"]}[operation] + ["capinfos"]
    binaries = {name: shutil.which(name) for name in needed}
    missing = [n for n in needed if not binaries[n]]
    if missing:
        fail("%s is not on PATH" % ", ".join(missing), requires=needed,
             note="install the Wireshark command-line tools (editcap, mergecap, text2pcap, capinfos) and tcpdump; nothing was read or written")
    os.umask(0o077)
    PROGRESS["stage"] = "reading the inputs"
    inputs, input_paths = [], []
    for path in p["inputs"]:
        if not os.path.exists(path):
            fail("no such file", input=path)
        try:
            size, sha = digest_of(path, deadline)
        except TimeoutError as exc:
            fail(str(exc))
        except OSError as exc:
            fail("an input is not a regular file that can be read (%s)" % describe(exc), input=path)
        inputs.append({"path": path, "bytes": size, "sha256": sha})
        input_paths.append(path)
    try:
        os.makedirs(out_dir, mode=0o700, exist_ok=True)
        os.chmod(out_dir, 0o700)
    except OSError as exc:
        fail("the output directory could not be created (%s)" % describe(exc), out_dir=out_dir)
    hold = {signal.SIGTERM, signal.SIGINT, signal.SIGHUP}
    was = signal.pthread_sigmask(signal.SIG_BLOCK, hold)
    try:
        work = tempfile.mkdtemp(dir=out_dir, prefix=".capture_transform-")
        PROGRESS["work"] = work                    # registered at once: a stop between the two would leave it, and the stop handler removes only what is registered
    except OSError as exc:
        signal.pthread_sigmask(signal.SIG_SETMASK, was)
        fail("the temporary directory could not be created in out_dir (%s)" % describe(exc), out_dir=out_dir)
    signal.pthread_sigmask(signal.SIG_SETMASK, was)

    try:
        return transform(p, started, deadline, out_dir, work, binaries, inputs, input_paths)
    except SystemExit:
        raise
    except BaseException as exc:  # noqa: BLE001 - never a traceback, and the temporary directory never stays
        fail("unexpected failure: %s" % describe(exc) if isinstance(exc, Exception) else "interrupted: %s" % type(exc).__name__)


def transform(p, started, deadline, out_dir, work, binaries, inputs, input_paths):
    operation = p["operation"]
    problems = []
    versions = {}
    PROGRESS["stage"] = "reading the versions of the programs"
    for name, binary in binaries.items():
        versions[name] = program_version(binary, deadline)
        if versions[name] is None:
            problems.append("`%s --version` gave no version line, so the version of that program is not recorded" % name)

    PROGRESS["stage"] = "counting the packets of the inputs"
    kind, counted = None, []
    if operation != "hexdump":
        counted, notes = capinfos(binaries["capinfos"], [os.path.abspath(i) for i in input_paths], deadline, work)
        problems.extend(notes)
        for row, c in zip(inputs, counted):
            row["packets"] = c["packets"] if c else None
            row["file_type"] = c["file_type"] if c else None
            row["encapsulation"] = c["encapsulation"] if c else None
            row["interfaces"] = c["interfaces"] if c else None
        if any(c is None for c in counted) or any(c["packets"] is None for c in counted):
            fail("capinfos could not describe every input as a capture, so nothing was run: a derivative of a file that is not read as a capture has no packet accounting",
                 inputs=inputs, capinfos_problems=problems)
        types = [(c["file_type"] or "").lower() for c in counted]
        kind = "pcapng" if all("pcapng" in t for t in types) else "pcap"
    else:
        for row in inputs:
            row["packets"], row["file_type"] = None, "text hex dump (not read as a capture)"

    steps, ext = commands(p, binaries, work, input_paths, kind)
    runs = []
    produced = []
    for label, argv, single in steps:
        PROGRESS["stage"] = "running %s" % label
        left = deadline - time.monotonic()
        if left < 2:
            fail("the tool's own clock (max_seconds) ran out before %s was run; nothing was placed" % label)
        so, se = os.path.join(work, label + ".stdout"), os.path.join(work, label + ".stderr")
        try:
            code, timed_out = run_to_files(argv, so, se, left, cwd=work)
        except OSError as exc:
            fail("%s could not be run (%s)" % (label, describe(exc)), command=argv)
        diag = diagnostics(so, se)
        if timed_out:
            fail("%s did not finish before the tool's own clock and was killed with everything it had started; nothing was placed" % label, command=argv,
                 after_seconds=p["max_seconds"], diagnostics=diag)
        if code != 0:
            fail("%s exited %s, so nothing was placed (a derivative the program did not finish is not kept)" % (label, code), command=argv, exit_code=code,
                 diagnostics=diag, inputs=inputs)
        runs.append({"program": label, "version": versions.get(label), "command": argv, "exit_code": code, "diagnostics": diag, "_stdout": so, "_stderr": se})

    # What the program(s) produced: regular files in `work` that are not the tool's own, in a stable order.
    PROGRESS["stage"] = "collecting the outputs"
    try:
        names = []
        with os.scandir(work) as entries:
            for e in entries:
                if len(names) > MAX_OUTPUTS:
                    break
                if e.name.startswith(("part", "deduplicated", "converted", "merged", "filtered", "text2pcap")) and not e.name.endswith((".stdout", ".stderr")):
                    names.append(e.name)
    except OSError as exc:
        fail("the temporary directory could not be listed (%s)" % describe(exc))
    names.sort()
    if len(names) > MAX_OUTPUTS:
        fail("the split made more than %d parts, so nothing was placed: raise packets or seconds" % MAX_OUTPUTS, command=runs[0]["command"])
    outputs = []
    for name in names:
        full = os.path.join(work, name)
        try:
            st = os.lstat(full)
        except OSError as exc:
            fail("an output could not be looked at (%s)" % describe(exc))
        if not stat.S_ISREG(st.st_mode):
            fail("%s left something that is not a regular file among its outputs, so nothing was placed" % runs[0]["program"])
        outputs.append(full)
    if not outputs:
        fail("%s exited 0 and wrote no output file, so nothing was placed" % runs[0]["program"], command=runs[0]["command"], diagnostics=runs[0]["diagnostics"])
    if operation != "split" and len(outputs) != 1:
        fail("%s wrote %d output files where one was expected, so nothing was placed" % (runs[0]["program"], len(outputs)))

    PROGRESS["stage"] = "counting the packets of the outputs"
    out_counts, notes = capinfos(binaries["capinfos"], outputs, deadline, work)
    problems.extend(notes)
    if any(c is None or c["packets"] is None for c in out_counts):
        problems.append("capinfos did not give a packet count for every output: the accounting is not established")

    # Names, digests, and the accounting. A derivative is described before it is placed and placed only whole.
    stem = {"split": "split", "dedup": "deduplicated", "convert": "converted", "merge": "merged", "filter": "filtered", "hexdump": "text2pcap"}[operation]
    rows = []
    for index, (full, c) in enumerate(zip(outputs, out_counts), 1):
        try:
            size, sha = digest_of(full, deadline)
        except (OSError, TimeoutError) as exc:
            fail("an output could not be read for its digest (%s)" % (describe(exc) if isinstance(exc, OSError) else exc))
        # the name follows what capinfos says the file is: mergecap and text2pcap write pcapng unless told otherwise, whatever the inputs were
        ftype = (c["file_type"] if c else None) or ""
        own_ext = ".pcapng" if "pcapng" in ftype.lower() else (".pcap" if ftype else ext)
        final_name = ("%s-%05d%s" % (stem, index, own_ext)) if operation == "split" else (stem + own_ext)
        row = {"kind": "derivative", "operation": operation, "name": final_name, "bytes": size, "sha256": sha,
               "packets": c["packets"] if c else None, "file_type": c["file_type"] if c else None,
               "encapsulation": c["encapsulation"] if c else None, "interfaces": c["interfaces"] if c else None,
               "label": SYNTHETIC_LABEL if operation == "hexdump" else LABEL,
               "provenance": {"source": "the output of %s" % runs[0]["program"], "parser": PARSER, "program_version": versions.get(runs[0]["program"]),
                              "packet_count_by": "capinfos %s" % (versions.get("capinfos") or "(version not recorded)")}}
        if operation == "hexdump":
            row["synthetic"] = True
        rows.append((full, final_name, row))

    packets_in = None if operation == "hexdump" else sum(r["packets"] for r in inputs)
    packets_out = None if any(r[2]["packets"] is None for r in rows) else sum(r[2]["packets"] for r in rows)
    accounting = {"packets_in": packets_in, "packets_out": packets_out, "dropped": None, "dropped_by": None, "balanced": None}
    reason = None
    if packets_in is not None and packets_out is not None:
        if operation in ("split", "merge", "convert"):
            accounting["dropped"] = packets_in - packets_out
            accounting["balanced"] = packets_in == packets_out
            reason = "none by design: %s keeps every packet" % operation
        elif operation == "filter":
            accounting["dropped"] = packets_in - packets_out
            accounting["balanced"] = packets_out <= packets_in
            reason = "dropped by the BPF filter recorded in settings"
        elif operation == "dedup":
            accounting["dropped"] = packets_in - packets_out
            accounting["balanced"] = packets_out <= packets_in
            reason = "removed as duplicates by editcap (%s)" % ("a window of %d packets" % p["window"] if p["window"] is not None else
                                                              "a window of %s seconds" % p["window_seconds"] if p["window_seconds"] is not None else "its default window")
        accounting["dropped_by"] = reason
        if accounting["balanced"] is False:
            problems.append("the packets do not add up: %d in, %d out, %s: the derivative is placed and its accounting is not balanced" % (
                packets_in, packets_out, "more came out than went in" if packets_out > packets_in else "packets are missing that the operation should keep"))
    elif packets_in is None and operation == "hexdump":
        accounting["dropped_by"] = "not applicable: a text dump is not a capture"
    zero = [r[1] for r in rows if r[2]["packets"] == 0]

    PROGRESS["stage"] = "placing the derivatives"
    limit = p["limit"]
    page = TransformPage(TOOL["name"], [operation, [i["sha256"] for i in inputs], p["bpf_filter"], p["packets"], p["seconds"], p["window"], p["window_seconds"], p["format"], p["order"]], limit)
    placed_rows, not_placed = [], 0
    for full, final_name, row in rows:
        if time.monotonic() > deadline:
            not_placed += 1               # the tool's own clock: a part not placed is removed with the temporary directory, and the answer says how many
            continue
        try:
            placed = place_without_replacing(Path(full), Path(out_dir) / final_name)
        except OSError as exc:
            fail("a derivative could not be placed in out_dir (%s); the derivatives placed before it are whole" % describe(exc), out_dir=out_dir)
        row["path"] = str(placed)
        PROGRESS["placed"].append(str(placed))
        placed_rows.append(row)
        page.add(row)
    if not_placed:
        problems.append("the tool's own clock (max_seconds) ran out while the derivatives were placed: %d of %d were not placed (they are not on disk), so the derivatives that are "
                        "there are not the whole of the operation" % (not_placed, len(rows)))
    # The diagnostics of each program: the first lines inline, the whole in a file beside the derivatives.
    logs = []
    for run in runs:
        for key, label in (("_stdout", "stdout"), ("_stderr", "stderr")):
            path = run.pop(key)
            try:
                if os.path.getsize(path) > 0:
                    logs.append(str(place_without_replacing(Path(path), Path(out_dir) / ("%s.%s" % (run["program"], label)))))
            except OSError as exc:
                problems.append("the %s of %s could not be kept in out_dir (%s)" % (label, run["program"], describe(exc)))
    shown = page.finish()
    cleanup()
    notes = []
    if operation == "filter":
        notes.append("A filter drops packets: the derivative is not the capture. The packets it dropped are counted here and not listed; the original holds them.")
    if operation == "dedup":
        notes.append("Removing duplicates drops packets that were on the wire as sent or retransmitted: the derivative is not the capture.")
    if operation == "merge":
        notes.append("%s The interface counts of the inputs and the output are in inputs and derivatives (capinfos): a difference is the merge's doing." %
                     ("Chronological: packets are ordered by time, which interleaves the inputs." if p["order"] == "chronological" else
                      "Appended with -a: the inputs are concatenated in the order given and their times are not compared, so the output can run backwards in time."))
    if operation == "convert":
        notes.append("pcapng to pcap loses what the pcap format has no place for: %s. This tool does not read the input's blocks; pcap_summary counts them for the original." % PCAPNG_ONLY)
    if operation == "hexdump":
        notes.append("text2pcap made the packets from a text dump: their timestamps (and headers, if an option asked) are synthetic. The file is not evidence that traffic occurred.")
    if zero:
        notes.append("%d derivative(s) hold no packet (%s): the operation selected none." % (len(zero), ", ".join(zero[:5])))
    ok = not problems
    if ok:
        basis = "%s ran, exited 0, and its %d output(s) were counted by capinfos and placed whole; %s" % (
            runs[0]["program"], len(placed_rows),
            "packets in and out are accounted for" if packets_in is not None else "the packets come from a text dump")
    else:
        basis = "; ".join(problems[:5]) + (" (and %d more, all in problems)" % (len(problems) - 5) if len(problems) > 5 else "") + ": the derivatives are placed whole"
    answer_out(json.dumps({
        "tool": TOOL, "parser": PARSER, "status": "complete" if ok else "partial", "status_basis": basis,
        "operation": operation, "label": LABEL, "out_dir": out_dir,
        "settings": {k: p[k] for k in ("packets", "seconds", "window", "window_seconds", "format", "order", "bpf_filter", "link_type", "ethernet_type", "ip_protocol",
                                       "udp_ports", "tcp_ports") if p[k] is not None},
        "tool_versions": versions,
        "inputs": inputs,
        "derivatives": page.page,
        "derivatives_total": page.total, "derivatives_returned": len(page.page), **{k: v for k, v in shown.items() if k not in ("matched", "returned")},
        "accounting": accounting, "zero_packet_derivatives": zero,
        "runs": runs, "logs": logs,
        "problems": problems, "notes": notes,
        "ok": ok,
        "originals_untouched": "the inputs were opened for reading only; their size and SHA-256 are in inputs",
    }, indent=2))
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except SystemExit:
        raise
    except BaseException as exc:  # noqa: BLE001 - never a traceback, never a clean answer for a failure
        fail("unexpected failure: %s" % describe(exc))
