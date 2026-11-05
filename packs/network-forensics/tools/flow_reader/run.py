#!/usr/bin/env python3
"""Read an nfcapd flow file with the pinned nfdump, and say what its records mean and what they do not.

An nfcapd file is nfdump's own file of decoded flow records: the NetFlow v5, NetFlow v9 or IPFIX packets an exporter sent, as nfcapd
stored them. This tool reads such files, and only such files, with `nfdump` (`-V`, `-v`, `-I`, `-E` and `-o json`), as a reader:
it never runs `nfcapd` or `nfpcapd`, nothing here listens on a port, and no file is written except under the place a result is kept
(`$OUT/tool-output` in a job, `work/<agent>/tool-output` outside one). The input is opened for reading only.

What it refuses, by name, before any program runs: a capture (pcap or pcapng; no mode of the pinned nfdump turns the export packets in a
capture into records, and `nfpcapd` would build new flows from the packets, which are not the exporter's records), sFlow (the pinned
package ships `nfcapd` and `nfpcapd`; its `nfcapd` does not decode sFlow, and `sfcapd` is not installed), and any file that does not start
with the nfcapd magic. `declared_format` says what the caller believes the dataset is; the exporters the file lists are checked against it.

An answer says, per file: the exporters nfdump lists (collector-seen address, protocol version, observation domain or engine, sequence
failures, announced samplers); the records, each with its source file, its position in nfdump's output and the parser; the times nfdump
printed, in UTC, beside the collector's receive time; sampled records beside unsampled ones, a sampled record's counters never exact; the
direction and the translated (post-NAT) fields nfdump names; the records that could not be read, and the checks that did not agree (nfdump's
exit codes are not trusted: it exits 0 on a file it could not read, so its messages and the file's own record count are compared).
"""
import json
import os
import signal
import sys

TOOL = {"name": "flow_reader", "version": 2}
PARSER = "flow_reader/1"

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

import calendar
import datetime
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
INFO_SECONDS = 120            # each of nfdump -V, -v, -I and -E
MAX_INPUTS = 32
DEFAULT_MAX_RECORDS = 100_000
MAX_RECORDS = 500_000
INFO_BYTES = 1 << 20          # what is read of the output of -v, -I and -E
LINE_BYTES = 1 << 16          # the longest line of nfdump's JSON that is read whole
MAX_FIELDS = 200              # fields in one record
FAILURES_KEPT = 10
IDENT_CHARS = 4096
HASH_CLOCK_BYTES = 1 << 24
CLOCK_EVERY = 1000            # lines between two looks at the clock
EXPORTERS_KEPT = 1000
TYPES_KEPT = 20
SYSIDS_KEPT = 10_000
ALLOWED = ("inputs", "declared_format", "limit", "max_records", "max_seconds")
FORMATS = ("netflow_v5", "netflow_v9", "ipfix", "sflow", "nfcapd")
VERSIONS = {"netflow_v5": {5}, "netflow_v9": {9}, "ipfix": {10}}
NFCAPD_MAGIC = b"\x0c\xa5"
CAPTURE_MAGICS = {bytes.fromhex("d4c3b2a1"): "pcap", bytes.fromhex("a1b2c3d4"): "pcap", bytes.fromhex("4d3cb2a1"): "pcap",
                  bytes.fromhex("a1b23c4d"): "pcap", bytes.fromhex("0a0d0d0a"): "pcapng"}
PROTOCOLS = {1: "icmp", 2: "igmp", 6: "tcp", 17: "udp", 41: "ipv6", 47: "gre", 50: "esp", 51: "ah", 58: "icmp6", 89: "ospf", 132: "sctp"}
EXPORT_LABELS = {5: "NetFlow v5", 9: "NetFlow v9", 10: "IPFIX"}

NOT_PROVIDED = [
    "template ids and templates: an nfcapd file keeps the decoded records, not the export templates",
    "the exporter's active and inactive timeouts: they are not stored in an nfcapd file",
    "whether a record is one direction or both: nfdump's JSON carries no such marker",
    "a byte offset of a record in the file: a record is located by its position in nfdump's output",
    "the export packets themselves, and whether any were lost beyond the sequence failures nfdump counted",
]
SEMANTICS = {
    "time": "Times are what nfdump printed with TZ=UTC, so they are UTC; `received` is the collector's clock when it stored the record, not the exporter's. "
            "For NetFlow v5 and v9, first and last switched are exporter uptime values that nfcapd turned into absolute times with the export header's time, so they "
            "are only as good as the exporter's clock; IPFIX carries absolute start and end times. A record is not a connection: an active timeout splits a long flow.",
    "sampling": "A record nfdump flagged sampled has counters nfdump scaled by the sampling the exporter announced (observed for a NetFlow v5 header interval): an "
                "estimate, never an exact count (`counters_exact` is false). A record not flagged is not shown to be unsampled: nfdump flags only the sampling it "
                "understood, so `counters_exact` is null for it, never true.",
    "direction": "`direction` is nfdump's value: 0 is ingress or no direction field at all (NetFlow v5 has none), 1 is egress. Only 1 says something by itself.",
    "nat": "`src_addr` and `dst_addr` are the exporter's source and destination address fields. The translated fields nfdump names `xlt` are in `nat`; "
           "which side of a NAT the exporter observed is the exporter's configuration and is not in the file.",
    "exporter": "The exporter address is the UDP source address the collector saw: a relay or a NAT can hide the real exporter. `domain_or_engine` is the "
                "observation domain (IPFIX), the source id (NetFlow v9) or, for NetFlow v5, the engine type and id.",
}


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


PROGRESS = {"stage": "arguments", "work": None, "file": None, "records": 0}


def cleanup():
    """What this run left that is not a result: the temporary directory (nfdump's output is in it) and the hidden file of a page."""
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
    print(json.dumps({"error": message, "tool": TOOL, "status": "failed",
                      "status_basis": "the tool stopped with an error (see error); no record is an answer", **extra}))
    raise SystemExit(1)


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
SUB = {"tried": False, "on": False}        # whether the subreaper was asked for, and is on
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
            _unproven(_note("this host refused PR_SET_CHILD_SUBREAPER: a process a program left behind outside the walk is not adopted and may not be found"))
    else:
        reason = "this host cannot adopt orphaned processes (no PR_SET_CHILD_SUBREAPER): a process a program left behind may not be found"
        if NONLINUX_UNPROVEN_DOWNGRADE:
            _unproven(_note(reason))
        else:
            _note(reason)
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
        before = LEFT["left_behind"]
        ended += (_end_children if SUB["on"] else _end_seen)(found, deadline)
        LEFT["left_behind"] = before + (ended - (LEFT["left_behind"] - before) if False else 0) + 0
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
    return {"subreaper": SUB["on"], "left_behind": LEFT["left_behind"], "unproven": list(LEFT["unproven"]), "notes": process_notes()}


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


class FlowPage(NoReplacePage):
    """NoReplacePage whose refused write is this tool's own failed answer, with the temporary files removed (the parent prints its own text and
    leaves the hidden file of the page behind)."""

    def _cannot_write(self, exc):
        fail("the whole list of records (%d so far) cannot be written to %s (%s); nothing was placed" % (self.total, self.shown, describe(exc)))


def last_word(signum):
    """What a stopped run says on stdout: partial, the stage and the file it was on. The result file being written is removed with the temporary
    directory, so nothing the run had read is kept."""
    cleanup()
    print(json.dumps({"tool": TOOL, "parser": PARSER, "status": "partial", "ok": False,
                      "status_basis": "the tool was stopped by signal %d while it was %s; the programs it had started were killed with what they started, the "
                                      "temporary directory and the result file being written were removed, and the records read so far are not kept" % (signum, PROGRESS["stage"]),
                      "interrupted_by_signal": signum, "stage": PROGRESS["stage"], "file_number": PROGRESS["file"], "records_read": PROGRESS["records"]}), flush=True)


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


def int_in(args, key, default, low, high):
    value = args.get(key, default)
    if isinstance(value, bool) or not isinstance(value, int) or not low <= value <= high:
        fail("%s must be an integer from %d to %d" % (key, low, high), **{key: value if isinstance(value, (int, float)) and not isinstance(value, bool) else None})
    return value


def read_arguments():
    try:
        args = json.load(sys.stdin)
    except ValueError as exc:
        fail("arguments are not valid JSON", reason=str(exc))
    if not isinstance(args, dict):
        fail("arguments must be a JSON object")
    unknown = sorted(k for k in args if k not in ALLOWED)
    if unknown:
        fail("unknown parameters: %s" % ", ".join(str(k)[:40] for k in unknown[:10]), allowed=list(ALLOWED))
    inputs = args.get("inputs")
    if (not isinstance(inputs, list) or not inputs or len(inputs) > MAX_INPUTS
            or any(not isinstance(i, str) or not i or "\0" in i or len(i) > 4096 for i in inputs)):
        fail("inputs must be a list of 1 to %d file names (each at most 4096 characters)" % MAX_INPUTS)
    declared = args.get("declared_format")
    if declared not in FORMATS:
        fail("declared_format is required: what the dataset is said to be, one of %s. This reader refuses a dataset it was not told the kind of" % ", ".join(FORMATS))
    max_seconds = args.get("max_seconds", DEFAULT_SECONDS)
    if isinstance(max_seconds, bool) or not isinstance(max_seconds, int) or not 10 <= max_seconds <= MAX_SECONDS:
        fail("max_seconds must be an integer from 10 to %d: kept under the manifest's %d seconds so that this tool stops its programs itself" % (MAX_SECONDS, MANIFEST_SECONDS))
    return dict(inputs=inputs, declared=declared, limit=int_in(args, "limit", 200, 1, 1_000_000), max_records=int_in(args, "max_records", DEFAULT_MAX_RECORDS, 1, MAX_RECORDS),
                max_seconds=max_seconds)


def safe(text, limit=300):
    """Text from a file or a program, for a sentence: printable only, cut at `limit` with the number of characters left out."""
    text = str(text)
    shown = "".join(c if (c.isprintable() or c == " ") else "�" for c in text[:limit])
    return shown + (" ...(%d more characters)" % (len(text) - limit) if len(text) > limit else "")


def digest_of(path, deadline):
    """(size, SHA-256) of a regular file, read in blocks; the clock is looked at every HASH_CLOCK_BYTES."""
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
                    raise TimeoutError("the tool's own clock ran out while %s was read" % safe(os.path.basename(path), 80))


def classify(path):
    """(kind, first bytes as hex) from the first four bytes only: nfcapd (its magic), pcap, pcapng, or something this reader does not read."""
    with open_regular(path) as fh:
        head = fh.read(4)
    if head[:2] == NFCAPD_MAGIC:
        return "nfcapd", head.hex()
    if head in CAPTURE_MAGICS:
        return CAPTURE_MAGICS[head], head.hex()
    return ("empty or shorter than a header" if len(head) < 2 else "unknown"), head.hex()


REFUSALS = {
    "pcap": "a capture, not an nfcapd file. No mode of the pinned nfdump turns the NetFlow, IPFIX or sFlow packets inside a capture into records (`nfpcapd` builds new "
            "flows from the packets themselves, which are not the exporter's records, and is not offered). This reader does not collect, and nothing here listens on a port",
    "sflow": "sFlow is not read: the pinned package ships `nfcapd` and `nfpcapd`, its `nfcapd` does not decode sFlow (it counts an sFlow datagram as a bad packet) and "
             "`sfcapd` is not installed. An nfcapd file that holds records already decoded can be given with declared_format `nfcapd`",
    "unknown": "not an nfcapd file: it does not start with the nfcapd magic, and a layout is not guessed from a sample",
}


def refusal_text(kind):
    if kind in ("pcap", "pcapng"):
        return "%s: %s" % (kind, REFUSALS["pcap"])
    if kind == "unknown":
        return REFUSALS["unknown"]
    return "%s: not an nfcapd file, which starts with the nfcapd magic" % kind


def run_nfdump(argv, work, tag, seconds, deadline):
    """One nfdump run with its output in two files in `work`; a dict with the exit code (None when it was killed, not run or could not start)."""
    out = {"argv": argv, "tag": tag, "stdout": os.path.join(work, tag + ".stdout"), "stderr": os.path.join(work, tag + ".stderr"),
           "code": None, "timed_out": False, "skipped": False, "error": None}
    left = deadline - time.monotonic()
    if left < 2:
        out["skipped"] = True
        return out
    try:
        out["code"], out["timed_out"] = run_to_files(argv, out["stdout"], out["stderr"], max(1.0, min(seconds, left - 1)), cwd=work)
    except OSError as exc:
        out["error"] = describe(exc)
    return out


def read_text(path, limit=INFO_BYTES):
    """(text, cut): a small output file read whole, up to `limit` bytes; `cut` is True when there was more."""
    try:
        with open_regular(path, follow=False) as fh:
            blob = fh.read(limit + 1)
    except OSError:
        return "", False
    return blob[:limit].decode("utf-8", "replace"), len(blob) > limit


def judge(label, run, problems, texts):
    """Read a run's outputs; what is wrong with the run is a sentence in `problems`. nfdump exits 0 on a file it could not read, so the exit code alone is
    never taken as a clean run: any message on stderr, and any output line the parser below does not know, is a problem as well."""
    if run["skipped"]:
        problems.append("%s was not run: the tool's own clock ran out" % label)
        return "", ""
    if run["error"]:
        problems.append("%s could not be run (%s)" % (label, run["error"]))
        return "", ""
    out, out_cut = read_text(run["stdout"])
    err, err_cut = read_text(run["stderr"])
    texts.append((label, run["code"], out, err))
    if run["timed_out"]:
        problems.append("%s did not finish before the tool's own clock and was killed with everything it had started" % label)
    elif run["code"] != 0:
        problems.append("%s exited %s%s" % (label, run["code"], ("; it said: " + safe(first_line(err or out), 200)) if (err or out).strip() else ""))
    if err.strip() and run["code"] == 0:
        problems.append("%s wrote to stderr: %s" % (label, safe(first_line(err), 200)))
    if out_cut or err_cut:
        problems.append("%s wrote more than %d bytes; only the first %d were read, so the checks on it are not whole" % (label, INFO_BYTES, INFO_BYTES))
    return out, err


def first_line(text):
    for line in lines_of(text):
        if line.strip():
            return line.strip()
    return ""


def lines_of(text):
    """The lines of a program's text. nfdump draws a progress spinner with a carriage return (a bar, then CR, before the next message), so a line is what follows the
    last carriage return in it, and only a newline ends one."""
    return [piece.rstrip("\r").split("\r")[-1] for piece in text.split("\n")]


VERIFY_LINES = (
    ("file", re.compile(r"^File\s*:.*$")),
    ("layout", re.compile(r"^Version\s*:\s*(\d+) - (.{1,40})$")),
    ("created", re.compile(r"^Created\s*:\s*(.{1,40})$")),
    ("created_by", re.compile(r"^nfdump\s*:\s*(\d+)$")),
    ("encryption", re.compile(r"^encryption\s*:\s*(.{1,20})$")),
    ("appendix_blocks", re.compile(r"^Appdx blks\s*:\s*(\d+)$")),
    ("data_blocks", re.compile(r"^Data blks\s*:\s*(\d+)$")),
    ("quiet", re.compile(r"^(?:Checking data blocks|Checking appendix blocks|Total|\s*[|/\-]?\s*)$")),     # the last alternative: nothing, or what is left of a progress spinner
    ("blocks", re.compile(r"^Type (\d+) blocks\s*:\s*(\d+)$")),
    ("records_all_types", re.compile(r"^Records\s*:\s*(\d+)$")),
)


def parse_verify(text):
    """nfdump -v: ({what it said}, [lines this parser does not know]). A line it does not know is a message, and a message is a problem."""
    info, unknown = {}, []
    for line in lines_of(text):
        for key, pattern in VERIFY_LINES:
            m = pattern.match(line)
            if m:
                if key == "layout":
                    info["layout_version"], info["compression"] = int(m.group(1)), m.group(2).strip()
                elif key in ("created", "encryption"):
                    info[key] = m.group(1).strip()
                elif key in ("created_by", "appendix_blocks", "data_blocks", "records_all_types"):
                    info[key] = int(m.group(1))
                elif key == "blocks":
                    info.setdefault("blocks_by_type", {})[m.group(1)] = int(m.group(2))
                break
        else:
            unknown.append(line)
    return info, unknown


INFO_KEYS = {"Ident", "Flows", "Flows_tcp", "Flows_udp", "Flows_icmp", "Flows_other", "Packets", "Packets_tcp", "Packets_udp", "Packets_icmp", "Packets_other",
             "Bytes", "Bytes_tcp", "Bytes_udp", "Bytes_icmp", "Bytes_other", "First", "Last", "msec_first", "msec_last", "Sequence failures"}
INFO_LINE = re.compile(r"^([A-Za-z_][A-Za-z_ ]{0,30}):\s?(.*)$")


def parse_statistics(text):
    """nfdump -I: ({key: value}, [unknown lines], ident cut?). The ident is text the collector's operator typed; it is shown whole up to IDENT_CHARS."""
    stats, unknown = {}, []
    for line in lines_of(text):
        if not line.strip():
            continue
        m = INFO_LINE.match(line)
        if not m or m.group(1) not in INFO_KEYS or m.group(1) in stats:
            unknown.append(line)
            continue
        key, value = m.group(1), m.group(2).strip()
        stats[key] = int(value) if re.fullmatch(r"\d{1,20}", value) else value
    return stats, unknown


EXPORTER_LINE = re.compile(r"^SysID: (\d+), IP:\s*(\S+), version: (\d+), ID:\s*(\d+), Sequence failures: (\d+), packets: (\d+), flows: (\d+)\s*$")
NO_STATS_LINE = re.compile(r"^SysID: (\d+), IP:\s*(\S+), version: (\d+), ID:\s*(\d+) - no flows sent\s*$")
SAMPLER_LINE = re.compile(r"^\s+Sampler: (.{1,300})$")


def parse_exporters(text):
    """nfdump -E: ([exporter], [unknown lines])."""
    exporters, unknown = [], []
    for line in lines_of(text):
        if not line.strip() or line.strip() in ("Exporters:", "No Exporter records found"):
            continue
        m = EXPORTER_LINE.match(line) or NO_STATS_LINE.match(line)
        if m:
            sysid, address, version, ident = m.groups()[:4]
            counts = [int(x) for x in m.groups()[4:]] or [None, None, None]     # a file nfdump wrote itself (nfdump -w) lists the exporter without its statistics
            row = {"sysid": int(sysid), "address": address, "version": int(version), "protocol": EXPORT_LABELS.get(int(version), "version %s" % version),
                   "domain_or_engine": int(ident), "sequence_failures": counts[0], "export_packets": counts[1], "flows": counts[2], "samplers": []}
            if counts[0] is None:
                row["statistics"] = "not in the file: nfdump listed the exporter as `no flows sent`"
            if int(version) == 5:
                row["engine_type"], row["engine_id"] = int(ident) >> 8, int(ident) & 0xFF
            if len(exporters) < EXPORTERS_KEPT:
                exporters.append(row)
            else:
                unknown.append("(more exporters than the %d listed)" % EXPORTERS_KEPT)
            continue
        s = SAMPLER_LINE.match(line)
        if s and exporters:
            exporters[-1]["samplers"].append(s.group(1))
            continue
        unknown.append(line)
    return exporters, unknown


TIME_FORM = re.compile(r"^(\d{4})-(\d\d)-(\d\d)T(\d\d):(\d\d):(\d\d)(?:\.(\d{1,9}))?$")


def parse_time(text):
    """{raw, utc, epoch_ms} from the form nfdump prints under TZ=UTC (2023-11-14T22:12:20.250), or None when the text is not that form."""
    if not isinstance(text, str):
        return None
    m = TIME_FORM.match(text)
    if not m:
        return None
    y, mo, d, h, mi, s = (int(x) for x in m.groups()[:6])
    try:
        datetime.datetime(y, mo, d, h, mi, s)
    except ValueError:
        return None
    ms = int((m.group(7) or "0")[:3].ljust(3, "0"))
    return {"raw": text, "utc": text + "Z", "epoch_ms": calendar.timegm((y, mo, d, h, mi, s, 0, 0, 0)) * 1000 + ms}


FIELD_LINE = re.compile(r'^\t"([A-Za-z0-9_]{1,64})" : (.*)$', re.S)
INT_FIELDS = ("in_packets", "in_bytes", "out_packets", "out_bytes", "proto", "src_port", "dst_port", "src_tos", "dst_tos", "input_snmp", "output_snmp", "direction",
              "export_sysid", "sampled")


def _no_constant(name):
    raise ValueError("not a JSON constant: %s" % name)


def build_row(index, source, fields, problems, exporters):
    """One record as a row: the fields nfdump gave that this tool reads, put under names that say what they are, the rest under `extra`."""
    used = set()
    row = {"record": index, "source": source, "parser": PARSER, "nfdump_type": fields.get("type") if isinstance(fields.get("type"), str) else None}
    used.add("type")

    def number(key):
        value = fields.get(key)
        if value is None:
            return None
        if isinstance(value, bool) or not isinstance(value, int):
            problems.append("%s is not an integer" % key)
            return None
        used.add(key)
        return value

    def text(key):
        value = fields.get(key)
        if value is None:
            return None
        if not isinstance(value, str):
            problems.append("%s is not a string" % key)
            return None
        used.add(key)
        return value

    times = {"zone": "UTC (nfdump ran with TZ=UTC)"}
    for key in ("first", "last", "received"):
        raw = fields.get(key)
        if raw is None:
            continue
        used.add(key)
        parsed = parse_time(raw)
        if parsed is None:
            problems.append("%s is not a time in the form nfdump prints" % key)
            times[key] = {"raw": raw if isinstance(raw, (str, int, float)) else None, "utc": None, "epoch_ms": None}
        else:
            times[key] = parsed
    first, last = times.get("first"), times.get("last")
    times["duration_ms"] = None
    if first and last and first.get("epoch_ms") is not None and last.get("epoch_ms") is not None:
        times["duration_ms"] = last["epoch_ms"] - first["epoch_ms"]
        if times["duration_ms"] < 0:
            times["last_before_first"] = True
    row["times"] = times
    proto = number("proto")
    row["protocol"] = {"number": proto, "name": PROTOCOLS.get(proto)} if proto is not None else None
    row["src_addr"] = text("src4_addr") or text("src6_addr")
    row["dst_addr"] = text("dst4_addr") or text("dst6_addr")
    row["src_port"], row["dst_port"] = number("src_port"), number("dst_port")
    row["tcp_flags"] = text("tcp_flags")
    sampled = number("sampled")
    packets, octets = number("in_packets"), number("in_bytes")
    row["counters"] = {"packets": packets, "bytes": octets, "out_packets": number("out_packets"), "out_bytes": number("out_bytes"),
                       "flagged_sampled": None if sampled is None else bool(sampled),
                       "counters_exact": False if sampled else None,
                       "basis": ("an estimate: nfdump flagged the record sampled and scaled the counters by the sampling the exporter announced" if sampled else
                                 "as nfdump stored them; no sampling was announced that nfdump understood, which does not show the exporter did not sample")}
    direction = number("direction")
    row["direction"] = {"value": direction, "label": {0: "ingress or none exported", 1: "egress"}.get(direction)} if direction is not None else None
    row["nat"] = {k: fields[k] for k in sorted(fields) if "_xlt_" in k}
    used.update(row["nat"])
    row["interfaces"] = {"input_snmp": number("input_snmp"), "output_snmp": number("output_snmp")}
    row["tos"] = {"src": number("src_tos"), "dst": number("dst_tos")}
    sysid = number("export_sysid")
    router = text("ip4_router") or text("ip6_router")
    exporter = next((e for e in exporters if e["sysid"] == sysid), None) if sysid is not None else None
    row["exporter"] = ({"sysid": sysid, "address_seen_by_collector": router, **{k: exporter[k] for k in ("protocol", "version", "domain_or_engine")}} if exporter
                       else {"sysid": sysid, "address_seen_by_collector": router, "listed_by_nfdump": False})
    row["extra"] = {k: v for k, v in fields.items() if k not in used}
    if problems:
        row["problems"] = list(problems)
    return row, sampled, packets, octets, proto, sysid, times


class Tally:
    def __init__(self):
        self.records = 0
        self.flagged = 0
        self.unflagged = 0
        self.sum_unflagged = [0, 0]
        self.sum_flagged = [0, 0]
        self.by_protocol, self.by_exporter, self.by_type = {}, {}, {}
        self.first_ms = self.last_ms = None
        self.last_before_first = 0
        self.with_problems = 0
        self.rejected = 0

    def add(self, sampled, packets, octets, proto, sysid, type_name, times, had_problems):
        self.records += 1
        target = self.sum_flagged if sampled else self.sum_unflagged
        if sampled:
            self.flagged += 1
        else:
            self.unflagged += 1
        target[0] += packets or 0
        target[1] += octets or 0
        for table, key, cap in ((self.by_protocol, "other" if proto is None else str(proto), 300), (self.by_exporter, "none" if sysid is None else str(sysid), SYSIDS_KEPT),
                                (self.by_type, "none" if type_name is None else safe(type_name, 32), TYPES_KEPT)):
            if key not in table and len(table) >= cap:
                key = "(others)"
            table[key] = table.get(key, 0) + 1
        for key in ("first", "last"):
            t = times.get(key)
            if t and t.get("epoch_ms") is not None:
                if self.first_ms is None or t["epoch_ms"] < self.first_ms:
                    self.first_ms = t["epoch_ms"]
                if self.last_ms is None or t["epoch_ms"] > self.last_ms:
                    self.last_ms = t["epoch_ms"]
        if times.get("last_before_first"):
            self.last_before_first += 1
        if had_problems:
            self.with_problems += 1

    def summary(self):
        iso = lambda ms: None if ms is None else datetime.datetime.fromtimestamp(ms // 1000, datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%S") + ".%03dZ" % (ms % 1000)   # noqa: E731
        return {"records": self.records, "records_flagged_sampled": self.flagged, "records_not_flagged": self.unflagged,
                "sum_not_flagged": {"packets": self.sum_unflagged[0], "bytes": self.sum_unflagged[1], "basis": "as stored; not shown to be exact (see sampling)"},
                "sum_flagged_sampled_estimate": {"packets": self.sum_flagged[0], "bytes": self.sum_flagged[1], "basis": "an estimate, never exact"},
                "by_protocol_number": self.by_protocol, "by_export_sysid": self.by_exporter, "by_nfdump_type": self.by_type,
                "earliest_first_or_last": iso(self.first_ms), "latest_first_or_last": iso(self.last_ms),
                "last_before_first": self.last_before_first, "records_with_problems": self.with_problems, "records_rejected": self.rejected}


def read_json_records(path, source, cap, page, tally, exporters, deadline):
    """Parse the output of `nfdump -o json` as a stream: one record from `{` to `},`. Each record becomes a row of the page. A line that is not part of a record,
    a field that is not JSON, a record cut off, a line over LINE_BYTES: counted, and the first ones named. Returns what was seen."""
    res = {"started": False, "ended": False, "no_matching": False, "records": 0, "stray": 0, "stray_samples": [], "failures": [], "truncated": False,
           "timed_out": False, "empty": True, "long_lines": 0}
    inside, fields, problems, index, lines = False, None, None, 0, 0

    def failure(reason):
        if len(res["failures"]) < FAILURES_KEPT:
            res["failures"].append({"record": index, "reason": reason})

    def finish():
        nonlocal inside
        inside = False
        if len(fields) >= MAX_FIELDS:
            problems.append("more than %d fields: the rest were not read" % MAX_FIELDS)
        row, sampled, packets, octets, proto, sysid, times = build_row(index, source, fields, problems, exporters)
        page.add(row)
        tally.add(sampled, packets, octets, proto, sysid, row["nfdump_type"], times, bool(problems))
        res["records"] += 1
        PROGRESS["records"] += 1
        if problems:
            failure("; ".join(problems[:3]))

    with open_regular(path, follow=False) as fh:
        while True:
            raw = fh.readline(LINE_BYTES + 1)
            if not raw:
                break
            res["empty"] = False
            lines += 1
            if lines % CLOCK_EVERY == 0 and time.monotonic() > deadline:
                res["timed_out"] = True
                break
            if len(raw) > LINE_BYTES and not raw.endswith(b"\n"):
                while True:                                    # the rest of an over-long line is read in blocks and dropped, clock in hand
                    more = fh.readline(LINE_BYTES)
                    if not more or more.endswith(b"\n"):
                        break
                    if time.monotonic() > deadline:
                        res["timed_out"] = True
                        break
                res["long_lines"] += 1
                if inside:
                    problems.append("a line longer than %d bytes was dropped" % LINE_BYTES)
                else:
                    res["stray"] += 1
                if res["timed_out"]:
                    break
                continue
            try:
                s = raw.decode("utf-8").rstrip("\r\n")
                bad_text = False
            except UnicodeDecodeError:
                s = raw.decode("utf-8", "replace").rstrip("\r\n")
                bad_text = True
            if inside:
                if bad_text:
                    problems.append("a line that is not UTF-8 was read with replacement characters")
                if s in ("},", "}", "}]"):
                    finish()
                    if s == "}]":
                        res["ended"] = True
                    continue
                if s == "{":
                    problems.append("the record was not closed before the next one began")
                    finish()
                    index += 1
                    if index > cap:
                        res["truncated"] = True
                        index -= 1
                        break
                    inside, fields, problems = True, {}, []
                    continue
                m = FIELD_LINE.match(s)
                if not m:
                    problems.append("a line that is not a field: %s" % safe(s, 80))
                    continue
                key, value_text = m.group(1), m.group(2)
                if value_text.endswith(","):
                    value_text = value_text[:-1]
                if key in fields:
                    problems.append("field %s appears twice" % key)
                    continue
                if len(fields) >= MAX_FIELDS:
                    continue
                try:
                    fields[key] = json.loads(value_text, parse_constant=_no_constant)
                except ValueError:
                    problems.append("the value of %s is not JSON: %s" % (key, safe(value_text, 60)))
                    fields[key] = None
                continue
            if s == "[" and not res["started"]:
                res["started"] = True
            elif s == "{":
                index += 1
                if index > cap:
                    res["truncated"] = True
                    index -= 1
                    break
                inside, fields, problems = True, {}, []
            elif s == "]":
                res["ended"] = True
            elif s == "No matching flows":
                res["no_matching"] = True
            elif s.strip():
                res["stray"] += 1
                if len(res["stray_samples"]) < 3:
                    res["stray_samples"].append(safe(s, 120))
    if inside:                                               # the output ended inside a record
        problems.append("the output ends inside the record")
        tally.rejected += 1
        failure("the output of nfdump ends inside a record (it was cut off, killed or the file ends there)")
        inside = False
    return res


def process_file(number, path, sha, size, p, page, tally, work, nfdump, deadline, info_dir):
    """Read one nfcapd file: its verification, statistics, exporters and records. A dict for the answer; every sentence about it that is not good is in `problems`."""
    PROGRESS["file"] = number
    problems, texts = [], []
    absolute = os.path.abspath(path)
    entry = {"number": number, "path": path, "bytes": size, "sha256": sha, "kind": "nfcapd"}
    PROGRESS["stage"] = "verifying %s (nfdump -v)" % safe(os.path.basename(path), 60)
    v_out, _ = judge("`nfdump -v`", run_nfdump([nfdump, "-v", absolute], work, "v%d" % number, INFO_SECONDS, deadline), problems, texts)
    verify, v_unknown = parse_verify(v_out)
    if v_unknown:
        problems.append("`nfdump -v` said something the verification parser does not know, which is taken as damage: %s" % safe(v_unknown[0], 160))
    PROGRESS["stage"] = "reading the statistics (nfdump -I)"
    i_out, _ = judge("`nfdump -I`", run_nfdump([nfdump, "-I", "-r", absolute], work, "i%d" % number, INFO_SECONDS, deadline), problems, texts)
    stats, i_unknown = parse_statistics(i_out)
    if i_unknown:
        problems.append("`nfdump -I` said something the statistics parser does not know: %s" % safe(i_unknown[0], 160))
    ident = stats.pop("Ident", None)
    if isinstance(ident, str) and len(ident) > IDENT_CHARS:
        problems.append("the ident string in the file is %d characters; only the first %d are shown" % (len(ident), IDENT_CHARS))
        ident = ident[:IDENT_CHARS]
    PROGRESS["stage"] = "reading the exporters (nfdump -E)"
    e_out, _ = judge("`nfdump -E`", run_nfdump([nfdump, "-E", absolute], work, "e%d" % number, INFO_SECONDS, deadline), problems, texts)
    exporters, e_unknown = parse_exporters(e_out)
    if e_unknown:
        problems.append("`nfdump -E` said something the exporter parser does not know: %s" % safe(e_unknown[0], 160))
    PROGRESS["stage"] = "reading the records (nfdump -o json)"
    left = deadline - time.monotonic()
    with_problems_before, rejected_before = tally.with_problems, tally.rejected
    j = run_nfdump([nfdump, "-r", absolute, "-c", str(p["max_records"] + 1), "-o", "json"], work, "j%d" % number, max(5.0, left * 0.6), deadline)
    err, err_cut = ("", False)
    if j["skipped"]:
        problems.append("`nfdump -o json` was not run: the tool's own clock ran out")
        read = None
    elif j["error"]:
        problems.append("`nfdump -o json` could not be run (%s)" % j["error"])
        read = None
    else:
        err, err_cut = read_text(j["stderr"])
        texts.append(("`nfdump -o json`", j["code"], "(the records: see all_results or records)", err))
        if j["timed_out"]:
            problems.append("`nfdump -o json` did not finish in time and was killed with everything it had started: the records are those it had printed")
        elif j["code"] != 0:
            problems.append("`nfdump -o json` exited %s" % j["code"])
        if err.strip():
            problems.append("`nfdump -o json` wrote to stderr: %s" % safe(first_line(err), 200))
        if err_cut:
            problems.append("`nfdump -o json` wrote more than %d bytes to stderr; only the first were read" % INFO_BYTES)
        try:
            read = read_json_records(j["stdout"], path, p["max_records"], page, tally, exporters, deadline)
        except TimeoutError:
            read = None
        except OSError as exc:
            problems.append("the output of nfdump could not be read back (%s)" % describe(exc))
            read = None
        if read is not None:
            if read["timed_out"]:
                problems.append("the tool's own clock ran out while the records were read: %d records were kept, the rest of the file was not read" % read["records"])
            if read["empty"]:
                problems.append("`nfdump -o json` printed nothing")
            elif not read["started"] and not read["timed_out"]:
                problems.append("the output of `nfdump -o json` does not start as nfdump's JSON array does")
            elif not read["ended"] and not read["truncated"] and not read["timed_out"] and not j["timed_out"]:
                problems.append("the output of `nfdump -o json` does not end with its closing bracket: it was cut off")
            if read["stray"]:
                problems.append("%d line(s) of the output of `nfdump -o json` are not part of a record%s" % (
                    read["stray"], ("; the first: " + read["stray_samples"][0]) if read["stray_samples"] else ""))
            if read["long_lines"]:
                problems.append("%d line(s) over %d bytes were dropped" % (read["long_lines"], LINE_BYTES))
            if read["truncated"]:
                problems.append("the file holds more than the %d records max_records allows: the rest were not read (the input file holds them)" % p["max_records"])
    records_read = read["records"] if read else 0
    bad_records = (tally.with_problems - with_problems_before) + (tally.rejected - rejected_before)
    if bad_records:
        problems.append("%d record(s) had a field or a line that could not be read as nfdump prints it%s" % (
            bad_records, ("; the first: record %d, %s" % (read["failures"][0]["record"], read["failures"][0]["reason"])) if read and read["failures"] else ""))
    flows = stats.get("Flows")
    if read is not None and not read["truncated"] and not read["timed_out"] and not j["timed_out"]:
        if isinstance(flows, int):
            if flows != records_read:
                problems.append("the file's own statistics count %d flows and %d records were read" % (flows, records_read))
        elif not any("nfdump -I" in x for x in problems):
            problems.append("the file's statistics gave no flow count, so the record count could not be checked")
    elif read is not None and read["truncated"] and isinstance(flows, int):
        entry["flows_in_file"] = flows
    if p["declared"] in VERSIONS and records_read:
        versions = {e["version"] for e in exporters}
        entry["declared_format_matches"] = bool(versions) and versions <= VERSIONS[p["declared"]]
        if not entry["declared_format_matches"]:
            problems.append("declared_format is %s and the file lists %s" % (
                p["declared"], ", ".join(sorted(EXPORT_LABELS.get(v, "version %d" % v) for v in versions)) if versions else "no exporter"))
    else:
        entry["declared_format_matches"] = None
    # The whole of what nfdump said about the file, kept beside the records.
    info_name = None
    try:
        body = []
        for label, code, o, e in texts:
            body.append("== %s (exit %s)\n--- stdout\n%s\n--- stderr\n%s\n" % (label, code, o, e))
        tmp = os.path.join(work, "info-%d.txt" % number)
        with open(tmp, "w", encoding="utf-8", errors="replace") as fh:
            fh.write("".join(body))
        placed = place_without_replacing(Path(tmp), Path(info_dir) / ("flow_reader-info-%s.txt" % sha[:16]))
        info_name = placed.name
    except OSError as exc:
        problems.append("the output of the nfdump runs could not be kept (%s)" % describe(exc))
    entry.update({
        "verification": verify, "statistics": stats, "ident": ident, "exporters": exporters,
        "records_read": records_read, "record_failures": read["failures"] if read else [], "truncated": bool(read and read["truncated"]),
        "problems": problems, "nfdump_output_file": info_name,
        "status": "failed" if (problems and records_read == 0) else ("partial" if problems else "complete"),
    })
    return entry


def main():
    started = time.monotonic()
    STATE["last_word"] = last_word
    STOP["last_word"] = last_word
    install_signal_handlers()
    p = read_arguments()
    deadline = started + p["max_seconds"]
    nfdump = shutil.which("nfdump")
    if not nfdump:
        fail("nfdump is not on PATH", requires=["nfdump"], note="install nfdump (the package ships nfdump; this tool never runs nfcapd or nfpcapd); nothing was read or written")
    os.umask(0o077)
    os.environ["TZ"], os.environ["LC_ALL"], os.environ["LANG"] = "UTC", "C", "C"
    if p["declared"] == "sflow":
        fail("refused by name: " + REFUSALS["sflow"], declared_format="sflow", supported=["nfcapd file of NetFlow v5, NetFlow v9 or IPFIX records"])
    PROGRESS["stage"] = "looking at the inputs"
    refused = []
    for path in p["inputs"]:
        if not os.path.exists(path):
            fail("no such file", input=safe(path, 300))
        try:
            kind, magic = classify(path)
        except OSError as exc:
            fail("an input is not a regular file that can be read (%s)" % describe(exc), input=safe(path, 300))
        if kind != "nfcapd":
            refused.append({"input": safe(path, 300), "kind": kind, "first_bytes": magic, "reason": refusal_text(kind)})
    if refused:
        fail("%d of %d input(s) refused by name before any program ran: %s" % (len(refused), len(p["inputs"]), refused[0]["reason"]), refused=refused[:20],
             supported=["an nfcapd file holding NetFlow v5, NetFlow v9 or IPFIX records, read with nfdump"])
    PROGRESS["stage"] = "reading the inputs"
    digests = []
    for path in p["inputs"]:
        try:
            digests.append(digest_of(path, deadline))
        except TimeoutError as exc:
            fail(str(exc))
        except OSError as exc:
            fail("an input could not be read (%s)" % describe(exc), input=safe(path, 300))
    page = FlowPage(TOOL["name"], [[d[1] for d in digests], p["max_records"], p["declared"]], p["limit"])
    info_dir = page.path.parent
    try:
        info_dir.mkdir(parents=True, exist_ok=True)
    except OSError as exc:
        fail("the place for the result could not be made (%s)" % describe(exc), place=str(info_dir))
    hold = {signal.SIGTERM, signal.SIGINT, signal.SIGHUP}
    was = signal.pthread_sigmask(signal.SIG_BLOCK, hold)
    try:
        work = tempfile.mkdtemp(dir=str(info_dir), prefix=".flow_reader-")
        PROGRESS["work"] = work                    # registered at once: a stop between the two would leave it
    except OSError as exc:
        signal.pthread_sigmask(signal.SIG_SETMASK, was)
        fail("the temporary directory could not be created (%s)" % describe(exc), place=str(info_dir))
    signal.pthread_sigmask(signal.SIG_SETMASK, was)
    try:
        return answer(p, started, deadline, nfdump, digests, page, work, info_dir)
    except SystemExit:
        raise
    except BaseException as exc:  # noqa: BLE001 - never a traceback, and the temporary directory never stays
        fail("unexpected failure: %s" % describe(exc) if isinstance(exc, Exception) else "interrupted: %s" % type(exc).__name__)


def answer(p, started, deadline, nfdump, digests, page, work, info_dir):
    PROGRESS["stage"] = "reading the version of nfdump"
    code, out, err, timed_out = preflight([nfdump, "-V"], max(1.0, min(PREFLIGHT_SECONDS, deadline - time.monotonic())))
    version = first_line(out.decode("utf-8", "replace")) or first_line(err.decode("utf-8", "replace")) or None
    tally = Tally()
    files = []
    for number, (path, (size, sha)) in enumerate(zip(p["inputs"], digests), 1):
        files.append(process_file(number, path, sha, size, p, page, tally, work, nfdump, deadline, info_dir))
        if time.monotonic() > deadline:
            break
    not_read = len(p["inputs"]) - len(files)
    problems = []
    if version is None:
        problems.append("`nfdump -V` gave no version line, so the version of nfdump is not recorded")
    for f in files:
        problems.extend("file %d: %s" % (f["number"], x) for x in f["problems"])
    if not_read:
        problems.append("the tool's own clock (max_seconds) ran out: %d of %d input(s) were not read" % (not_read, len(p["inputs"])))
    PROGRESS["stage"] = "placing the records"
    shown = page.finish()
    cleanup()
    readable = [f for f in files if f["records_read"] > 0 or not f["problems"]]
    if not files or not readable:
        status = "failed"
    elif problems:
        status = "partial"
    else:
        status = "complete"
    if status == "complete":
        basis = ("nfdump read %d file(s) and every check agreed: the verification said nothing, the statistics, the exporters and the records parsed, no message was "
                 "printed, and each file's own flow count equals the records read (%d)" % (len(files), tally.records))
    else:
        basis = "; ".join(problems[:5]) + (" (and %d more, all in problems)" % (len(problems) - 5) if len(problems) > 5 else "")
    answer_out(json.dumps({
        "tool": TOOL, "parser": PARSER, "status": status, "status_basis": basis,
        "declared_format": p["declared"], "backend": {"program": "nfdump", "version": version, "run_as": "a reader: nfcapd and nfpcapd are never run and nothing listens on a port"},
        "time_zone": "UTC", "settings": {"max_records": p["max_records"], "limit": p["limit"], "max_seconds": p["max_seconds"]},
        "files": files, "files_total": len(p["inputs"]), "files_not_read": not_read,
        "records": page.page, "records_total": page.total, "records_returned": len(page.page), **{k: v for k, v in shown.items() if k not in ("matched", "returned")},
        "totals": tally.summary(), "semantics": SEMANTICS, "not_provided": NOT_PROVIDED,
        "problems": problems, "ok": status == "complete",
        "originals_untouched": "the inputs were opened for reading only; their size and SHA-256 are in files",
    }, indent=2))
    return 1 if status == "failed" else 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except SystemExit:
        raise
    except BaseException as exc:  # noqa: BLE001 - never a traceback, never a clean answer for a failure
        fail("unexpected failure: %s" % describe(exc))
