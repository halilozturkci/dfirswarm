#!/usr/bin/env python3
"""A broad extraction of a disk image: Plaso's super timeline.

disk-volumes lists every file entry and its MAC times, and reads no file's
contents. This one runs log2timeline over the whole image (every partition
and volume it finds, every parser it carries) into one storage file, then
psort writes it out as a CSV timeline: the searchable form of what the
image's artefacts say happened when. It takes hours on a large image, so its
pack does not run it by itself: the harness offers it as a lead, and a seat
runs it (catalog_request recipe=computer-forensics-base/disk-timeline) or
declines it with why.

    run.py detect --target T [--probe-out DIR]   exit 0 a disk image, 1 not
    run.py run --target T --out DIR

Detect reads signatures only (an EWF, VMDK, VHD(X) or QCOW container, a
partition table, a filesystem's boot sector), so it answers the same on any
host. A run stopped before its end leaves coverage.json saying partial. An --out
that already holds a timeline.plaso or timeline.csv is refused, and said in
coverage.refused.json: the earlier run's coverage.json, which describes the
files that are still there, is left as it was.

Plaso writes its log to the working directory unless told otherwise
(log2timeline-<timestamp>.log.gz, psort-<timestamp>.log.gz), and a job starts
in the run's directory, which is read-only in its worker: on the Belka run
log2timeline and psort both failed there with EROFS on that log. Each is
given its log under --out (--logfile, which Plaso's tools have taken, with
--log_file and --log-file as its aliases, since at least 20180818; the images
install 20260720), and each runs with --out as its working directory, so
nothing either writes lands beside the run.
"""
import argparse
import gzip
import json
import os
import re
import shutil
import struct
import subprocess
import sys
import time

try:
    import ctypes
except ImportError:  # pragma: no cover
    ctypes = None


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
        # The document is whole. A stop that came while it was written is delivered now; the last word was cleared, so it ends the tool
        # (128 plus the signal) with nothing more on stdout. The mask is also what an in-process caller (a test) had before.
        signal.pthread_sigmask(signal.SIG_SETMASK, before)


_shared_print_answer = print_answer


def print_answer(answer, **dumps_kwargs):
    _reconcile(answer)
    _guarded_write(lambda: _shared_print_answer(answer, **dumps_kwargs))


def _probe_out(directory):
    """The output directory is written to once, up front: a directory that cannot be written (not owned, mounted read-only, a full disk) is a refusal
    before anything is run, not a PermissionError in the middle of the coverage file."""
    probe = _os.path.join(directory, ".write-probe-%d" % _os.getpid())
    temp_hold(probe)                 # registered before it is made: whatever stops this, it is removed
    try:
        fd = _os.open(probe, _os.O_WRONLY | _os.O_CREAT | _os.O_EXCL, 0o600)
        _os.close(fd)
        if not temp_drop(probe):
            raise OSError(0, "the probe file could not be removed")
    except (OSError, ValueError) as exc:
        temp_drop(probe)
        print_answer({"ok": False, "status": "failed", "error": "--out cannot be written: %s" % (getattr(exc, "strerror", None) or exc.__class__.__name__),
                      "status_basis": "the output directory cannot be written, so nothing was run"})
        _sys.exit(2)


def _unexpected_recipe(kind, value, _tb):
    """What nobody foresaw (a file that cannot be written half way, a target of an odd type) is an answer too: its class only, exit 2."""
    try:
        drop_temporaries()
    except BaseException:   # noqa: BLE001
        pass
    why = "a path, a file or the target could not be used: %s" % kind.__name__
    if len(_sys.argv) > 1 and _sys.argv[1] == "detect":
        doc = {"applies": "unknown", "why": why, "ok": False, "error": why}
    else:
        doc = {"ok": False, "status": "failed", "error": why, "status_basis": "the recipe stopped on %s, so what it had written is not a complete result" % kind.__name__}
    try:
        _sys.stdout.write(json.dumps(doc) + "\n")
        _sys.stdout.flush()
    except (OSError, ValueError):
        pass
    _os._exit(2)


_sys.excepthook = _unexpected_recipe


def open_regular(path):
    """open(path, "rb") for a caller's path that was checked as a regular file a moment ago: opened without waiting (O_NONBLOCK) and looked at with
    fstat on the descriptor, so a FIFO or a device put in its place is refused and never waited on (a FIFO would hold the tool for ever)."""
    fd = os.open(path, os.O_RDONLY | getattr(os, "O_NONBLOCK", 0))
    try:
        if os.fstat(fd).st_mode & 0o170000 != 0o100000:
            raise OSError(22, "is not a regular file (it changed after it was checked)")
    except BaseException:
        os.close(fd)
        raise
    return open(fd, "rb")

CHILD = {"proc": None}     # the Plaso program being run, ended by its pid on a stop

# What `complete` says: the pipeline finished. Plaso's own processing report says what each parser did.
PIPELINE_NOTE = ("complete means log2timeline and psort both exited 0, wrote their files, said no error and no zero event count in what they "
                 "printed, in their logs or in pinfo's report, and the timeline holds an event; it does not say every parser read every "
                 "source or that no record was skipped. pinfo.txt, when it was written, is Plaso's own processing report of the storage "
                 "file: read it before a negative rests on this timeline")
ZONE = re.compile(r"^[A-Za-z0-9_+\-/]{1,64}$")
NOT_COVERED = ("volume shadow copies (run with --vss_stores none); encrypted volumes without their key; unallocated space and "
               "deleted file contents (nothing is carved); formats no parser of the installed Plaso handles, and the text inside documents")


def target_of(value):
    text = value
    if os.path.isfile(value):
        try:
            with open(value, encoding="utf-8") as fh:
                text = fh.read(1 << 20)
        except (OSError, ValueError) as exc:               # ValueError: bytes that are not UTF-8
            raise ValueError("the target file cannot be read as UTF-8 text: %s" % (getattr(exc, "strerror", None) or exc.__class__.__name__))
    try:
        target = json.loads(text)
    except (ValueError, RecursionError) as exc:
        raise ValueError("the target is not valid JSON: %s" % exc)
    if not isinstance(target, dict):
        raise ValueError("the target is a JSON object with a paths list")
    paths = target.get("paths") or []
    if not isinstance(paths, list):
        raise ValueError("the target is a JSON object with a paths list")
    if not paths or not isinstance(paths[0], str):
        raise ValueError("the target names no path")
    return target, paths[0]


def mbr_partitions(head):
    """Whether bytes 446..509 hold at least one partition entry with a type and a size."""
    for i in range(4):
        entry = head[446 + 16 * i: 462 + 16 * i]
        if len(entry) < 16:
            return False
        ptype = entry[4]
        sectors = struct.unpack("<I", entry[12:16])[0]
        if ptype and sectors:
            return True
    return False


def detect(path):
    if not os.path.isfile(path):
        return "unknown", "not a readable file, so it cannot be told whether it is a disk image"
    try:
        with open_regular(path) as fh:
            head = fh.read(65536)
            size = os.path.getsize(path)
            tail = b""
            if size >= 512:
                fh.seek(size - 512)
                tail = fh.read(512)
    except OSError as exc:
        return "unknown", "unreadable, so it cannot be told whether it is a disk image: %s" % exc
    containers = [
        (0, b"EVF\x09\x0d\x0a\xff\x00", "an EWF image (Plaso reads it through libewf)"),
        (0, b"EVF2\x0d\x0a\x81\x00", "an EWF2 image (Plaso reads it through libewf)"),
        (0, b"KDMV", "a VMDK sparse extent"),
        (0, b"# Disk DescriptorFile", "a VMDK descriptor"),
        (0, b"vhdxfile", "a VHDX disk"),
        (0, b"conectix", "a dynamic VHD disk"),
        (0, b"QFI\xfb", "a QCOW disk"),
        (512, b"EFI PART", "a GPT partition table"),
        (3, b"NTFS    ", "an NTFS volume at sector 0"),
        (3, b"EXFAT   ", "an exFAT volume at sector 0"),
        (54, b"FAT", "a FAT volume at sector 0"),
        (82, b"FAT32", "a FAT32 volume at sector 0"),
        (1080, b"\x53\xef", "an ext volume at sector 0"),
        (1024, b"H+", "an HFS+ volume at sector 0"),
        (1024, b"HX", "an HFSX volume at sector 0"),
        (32, b"NXSB", "an APFS container at sector 0"),
    ]
    for offset, magic, why in containers:
        if head[offset:offset + len(magic)] == magic:
            return True, why
    if tail[:8] == b"conectix":
        return True, "a fixed VHD disk"
    if head[510:512] == b"\x55\xaa" and mbr_partitions(head):
        return True, "an MBR partition table with at least one partition"
    return False, "no disk image, partition table or filesystem signature"


# What Plaso's own words say when a step finished its job and not its work: an error line, a traceback, a worker that was
# killed, a count of events that is zero. Matched in what each step printed, in its log and in pinfo's report; the exit codes
# alone do not say this.
PLASO_ERROR = re.compile(r"\[(?:ERROR|CRITICAL)\]|Traceback \(most recent call last\)|\bworkers?\b.{0,40}\b(?:killed|died|crashed|terminated|not responding)\b", re.I)
PLASO_ZERO = re.compile(r"\bevents?\s+(?:extracted|written|exported|processed)\s*:?\s*0\b", re.I)
SCAN_BYTES = 32 * 1024 * 1024


def plaso_signals(out, names, unread=None):
    """The lines in these files of `out` that say Plaso failed or found nothing: [(file, kind, count, first line)].
    A file is read to SCAN_BYTES, and a .gz that is not gzip is read as it is. When `unread` is a list, each file that goes on past
    SCAN_BYTES is added to it as (file, bytes not read, or None when that is not known: the rest of a gzip stream is not measured)."""
    found = []
    for name in names:
        path = os.path.join(out, name)
        if not os.path.isfile(path):
            continue
        counts, first = {"error": 0, "zero events": 0}, {}
        try:
            try:
                with gzip.open(path, "rb") as handle:
                    raw = handle.read(SCAN_BYTES)
                    more = bool(handle.read(1))
                    left = None
            except (OSError, EOFError):
                with open_regular(path) as handle:
                    raw = handle.read(SCAN_BYTES)
                    more = bool(handle.read(1))
                    left = max(0, os.path.getsize(path) - SCAN_BYTES) if more else 0
            if more and unread is not None:
                unread.append((name, left))
            lines = iter(raw.decode("utf-8", "replace").splitlines())
            for line in lines:
                for kind, rx in (("error", PLASO_ERROR), ("zero events", PLASO_ZERO)):
                    if rx.search(line):
                        counts[kind] += 1
                        first.setdefault(kind, line.strip()[:200])
        except OSError:
            continue
        for kind in ("error", "zero events"):
            if counts[kind]:
                found.append((name, kind, counts[kind], first[kind]))
    return found


def program(*names):
    for name in names:
        found = shutil.which(name)
        if found:
            return found
    return None


def write_coverage(out, status, covered, errors, extra=None, name="coverage.json"):
    path = os.path.join(out, name)
    tmp = path + ".tmp"
    temp_hold(tmp)
    try:                        # whole or not at all: written beside, then renamed over the name
        with open(tmp, "w", encoding="utf-8") as handle:
            json.dump({"recipe": "disk-timeline", "status": status, "status_basis": covered, "covered": covered, "not_covered": NOT_COVERED,
                       "limits_hit": [], "errors": list(errors), "coverage_note": PIPELINE_NOTE, **(extra or {})}, handle, indent=2, sort_keys=True)
            handle.write("\n")
        temp_replace(tmp, path)
    except BaseException:
        temp_drop(tmp)
        raise


# What a step leaves behind. This recipe carries no shared PROCESS block (its text is held equal in many files by tests, and the recipe starts one program at a time),
# so the mechanism is its own and small: on Linux the recipe makes itself a subreaper (PR_SET_CHILD_SUBREAPER), so that a process log2timeline, psort or pinfo leaves
# behind when it exits (a worker, a helper, one in a session of its own, one that holds none of the recipe's descriptors) becomes a child of the recipe, and settle_steps()
# stops it and what it started, kills and reaps them, before the recipe reads, counts or lists the files the step wrote. What it ended makes the run partial, and so does a
# host where none can be ruled out (not Linux, or a kernel that refuses). The same call ends everything below the recipe when a stop signal arrives.
LEFT = {"left_behind": 0, "unproven": [], "subreaper": False, "tried": False}
KNOWN_KIDS = {}            # the children the recipe already had when it asked to be a subreaper: pid -> start time (they are not a step's)
SETTLE_SECONDS = 3         # the most one look for leftovers works, in seconds


def _stat_row(pid):
    """(state, parent pid, start time) of a process from /proc/<pid>/stat (the fields after the last ')'), or None."""
    try:
        with open("/proc/%d/stat" % pid, "rb") as fh:
            raw = fh.read().decode("utf-8", "replace")
        rest = raw[raw.rfind(")") + 2:].split()
        return rest[0], int(rest[1]), rest[19]
    except (OSError, ValueError, IndexError):
        return None


def _table():
    table = {}
    for name in os.listdir("/proc"):
        if name.isdigit():
            row = _stat_row(int(name))
            if row is not None:
                table[int(name)] = row
    return table


def become_subreaper():
    """Ask the kernel to make this process the parent of every process a step leaves behind. Once. Says in LEFT["unproven"] why none can be ruled out when it
    cannot be done."""
    if LEFT["tried"]:
        return LEFT["subreaper"]
    LEFT["tried"] = True
    if sys.platform.startswith("linux") and ctypes is not None:
        try:
            LEFT["subreaper"] = ctypes.CDLL(None, use_errno=True).prctl(36, 1, 0, 0, 0) == 0
        except Exception:  # noqa: BLE001 - no libc symbol, a sandbox: the caller falls back
            LEFT["subreaper"] = False
        if LEFT["subreaper"]:
            try:
                me = os.getpid()
                KNOWN_KIDS.update({pid: row[2] for pid, row in _table().items() if row[1] == me})
            except OSError:
                LEFT["unproven"].append("the children the recipe already had could not be listed: one of them may be taken for a step's")
        else:
            LEFT["unproven"].append("this host refused PR_SET_CHILD_SUBREAPER: a process a step left behind is not adopted and may not be found")
    else:
        LEFT["unproven"].append("this host cannot adopt orphaned processes (no PR_SET_CHILD_SUBREAPER): a process a step left behind may not be found")
    return LEFT["subreaper"]


def settle_steps():
    """End what a step left behind: the recipe's children that are no known child, with everything below them (stopped first, so that nothing forks on while they are
    found, then killed, then reaped), for at most SETTLE_SECONDS. Returns how many live processes it ended; LEFT["left_behind"] has the total. Never raises."""
    if not LEFT["subreaper"]:
        return 0
    ended, looked = 0, False
    deadline = time.monotonic() + SETTLE_SECONDS
    try:
        me = os.getpid()
        while True:
            table = _table()
            victims = {pid: row for pid, row in table.items() if row[1] == me and KNOWN_KIDS.get(pid) != row[2]}
            if not victims:
                if ended and not looked:
                    looked = True
                    time.sleep(0.05)               # a fork that was under way when the first one died
                    continue
                return ended
            if time.monotonic() >= deadline:
                LEFT["unproven"].append("%d processes a step left behind were still there after %d seconds: they were not all ended" % (len(victims), SETTLE_SECONDS))
                return ended
            group = dict(victims)
            for _round in range(8):                # stop each one, then what it had started, until no new one turns up
                for pid, (state, _ppid, start) in list(group.items()):
                    if state not in ("Z", "X"):
                        row = _stat_row(pid)
                        if row is not None and row[2] == start:
                            try:
                                os.kill(pid, 19)   # SIGSTOP
                            except OSError:
                                pass
                more = {pid: row for pid, row in _table().items() if row[1] in group and pid not in group}
                if not more:
                    break
                group.update(more)
            for pid, (state, _ppid, start) in group.items():
                if state not in ("Z", "X"):
                    row = _stat_row(pid)
                    if row is not None and row[2] == start:
                        try:
                            os.kill(pid, 9)
                            ended += 1
                        except OSError:
                            pass
            for pid in victims:                    # reap: a zombie is not counted, and not left
                while time.monotonic() < deadline:
                    try:
                        if os.waitpid(pid, os.WNOHANG)[0] != 0:
                            break
                    except ChildProcessError:
                        break
                    time.sleep(0.005)
    except Exception as exc:  # noqa: BLE001 - never into the finally of the recipe: say it could not be proven
        LEFT["unproven"].append("the look for what a step left behind failed (%s)" % type(exc).__name__)
        return ended
    finally:
        LEFT["left_behind"] += ended


def leftover_errors():
    """The sentences for the errors of the run: a step left processes that were ended before the files were read, or none can be ruled out."""
    errors = []
    if LEFT["left_behind"]:
        errors.append("log2timeline, psort or pinfo left %d process(es) running after it ended (a child that held one of the step's files, in the recipe's process group or, in a session of its own, "
                      "outside it); they were killed and reaped before the files were read, counted or listed, so timeline.plaso, timeline.csv, the logs and the captured "
                      "words are what they held at that moment and what the leftover would still have written is missing" % LEFT["left_behind"])
    errors.extend(why + ": the files the steps wrote cannot be shown to be final" for why in LEFT["unproven"])
    return errors


def step(out, name, argv):
    # cwd=out: what a step writes where it stands lands in out, never in the
    # (read-only) directory the job started in.
    with open(os.path.join(out, name + ".stdout"), "wb") as so, open(os.path.join(out, name + ".stderr"), "wb") as se:
        proc = subprocess.Popen(argv, stdout=so, stderr=se, cwd=out)
        CHILD["proc"] = proc
        try:
            return proc.wait()
        finally:
            CHILD["proc"] = None
            settle_steps()                 # before the files are read: what the step left behind is ended


def run(image, out, zone=None):
    out = os.path.abspath(out)
    image = os.path.abspath(image)
    try:
        os.makedirs(out, exist_ok=True)
    except (OSError, ValueError) as exc:        # a name too long, a loop, a file in the way, a directory that cannot be entered
        print_answer({"ok": False, "status": "failed", "error": "--out cannot be used: %s" % (getattr(exc, "strerror", None) or exc.__class__.__name__),
                      "status_basis": "the output directory could not be made, so nothing was run"})
        sys.exit(2)
    _probe_out(out)
    extra = {"timezone": zone or "not given", "timezone_note": (
        "the zone given to log2timeline for the formats that store local time; psort writes its CSV in UTC" if zone else
        "none given: for the formats that store local time Plaso used its own default, which this recipe does not read back (the "
        "storage file records what it used); pass a timezone in the target (\"timezone\") or RECIPE_TIMEZONE when the machine's zone is known")}
    # A timeline left by an earlier run would be mistaken for this one's.
    stale = [n for n in ("timeline.plaso", "timeline.csv") if os.path.lexists(os.path.join(out, n))]
    if stale:
        # The earlier run's coverage.json describes the files that are still there: it is left as it is, and the
        # refusal is said beside it, so neither record is lost or mistaken for the other.
        write_coverage(out, "failed", "nothing: the output directory already holds %s from an earlier run" % " and ".join(stale),
                       ["%s was already in the output directory; this run will not take it for its own" % " and ".join(stale)], extra,
                       name="coverage.refused.json")
        return 1, "coverage.refused.json"
    began = time.time()
    become_subreaper()
    write_coverage(out, "partial", "started; log2timeline or psort did not finish (stopped before its end)", ["the run ended before Plaso did"], extra)

    def _stopped(signum):
        proc = CHILD["proc"]
        if proc is not None:
            try:
                proc.kill()
                proc.wait(timeout=5)
            except Exception:  # noqa: BLE001 - best effort
                pass
        settle_steps()                       # what the step started and lost is a child of the recipe now: ended with it
        try:
            write_coverage(out, "partial", "the recipe was stopped by signal %d: the program running was ended, and what it had written is in out, not counted" % signum,
                           ["stopped by signal %d before Plaso finished" % signum], dict(extra, interrupted=True, signal=signum))
        except OSError:
            pass
        print(json.dumps({"ok": False, "status": "partial", "interrupted": True, "signal": signum, "coverage": "coverage.json"}), flush=True)
    install_signal_handlers(_stopped)
    l2t = program("log2timeline", "log2timeline.py")
    psort = program("psort", "psort.py")
    if not l2t or not psort:
        missing = [n for n, p in (("log2timeline", l2t), ("psort", psort)) if not p]
        write_coverage(out, "failed", "nothing: Plaso is not in this image", ["%s not on PATH in this job image" % " and ".join(missing)], extra)
        return 1, "coverage.json"
    storage = os.path.join(out, "timeline.plaso")
    collect = [l2t, "--unattended", "--logfile", os.path.join(out, "log2timeline.log.gz"), "--partitions", "all", "--volumes", "all", "--vss_stores", "none"]
    if zone:
        collect += ["--timezone", zone]
    collect += ["--storage-file", storage, image]
    rc = step(out, "log2timeline", collect)
    errors = []
    if rc != 0:
        errors.append("log2timeline exited %d; its output is kept whole in log2timeline.stdout and log2timeline.stderr, its log in log2timeline.log.gz" % rc)

    def fresh(path):
        # written by this run, not left from before it
        return os.path.isfile(path) and os.path.getmtime(path) >= began - 1

    rows = []
    if fresh(storage):
        rows.append(("timeline.plaso", "Plaso storage file of the whole image (psort, pinfo)"))
        prc = step(out, "psort", [psort, "--logfile", os.path.join(out, "psort.log.gz"), "-o", "dynamic", "-w", os.path.join(out, "timeline.csv"), storage])
        if prc != 0:
            errors.append("psort exited %d; its output is kept whole in psort.stdout and psort.stderr, its log in psort.log.gz" % prc)
        if fresh(os.path.join(out, "timeline.csv")):
            rows.append(("timeline.csv", "super timeline (psort -o dynamic): one event per row, every parser's, in time order"))
        pinfo = program("pinfo", "pinfo.py")
        if pinfo:
            # Plaso's processing report of the storage file, kept whole; its text is not parsed here.
            prc = step(out, "pinfo", [pinfo, storage])
            if os.path.isfile(os.path.join(out, "pinfo.stdout")):
                os.replace(os.path.join(out, "pinfo.stdout"), os.path.join(out, "pinfo.txt"))
                rows.append(("pinfo.txt", "Plaso's own processing report of the storage file (pinfo): what its parsers did, warnings included"))
            if prc != 0:
                errors.append("pinfo exited %d; the processing report may be incomplete (pinfo.stderr)" % prc)
    # The programs exited, and said what they did: a worker that was killed or an error line makes it partial, and so does a timeline of no events.
    not_read = []
    signals = plaso_signals(out, ["log2timeline.stdout", "log2timeline.stderr", "log2timeline.log.gz", "psort.stdout", "psort.stderr", "psort.log.gz",
                                  "pinfo.txt", "pinfo.stderr"], not_read)
    if not_read:
        extra["plaso_signals_not_read"] = [{"file": f, "bytes_not_read": b if b is not None else "more follows the first %d bytes (a gzip stream: not measured)" % SCAN_BYTES}
                                           for f, b in not_read]
        for f, b in not_read:
            errors.append("%s: only its first %d bytes were read for error and no-event lines; %s, so a line past them is not looked at"
                          % (f, SCAN_BYTES, ("%d bytes were not read" % b) if b is not None else "the rest of the stream was not read"))
    for name, kind, count, first in signals:
        errors.append("%s: %d line(s) say %s, the first: %s" % (name, count, "an error" if kind == "error" else "no events were extracted or written", first))
    csv_path = os.path.join(out, "timeline.csv")
    if fresh(csv_path):
        try:
            with open(csv_path, "rb") as handle:
                data_rows = sum(1 for _ in handle) - 1
            if data_rows < 1:
                errors.append("timeline.csv holds no event (only its header, or nothing): psort wrote a timeline of no events; whether the image holds none "
                              "or a parser failed is not established (read pinfo.txt)")
        except OSError:
            pass
    if signals:
        extra["plaso_signals"] = [{"file": f, "kind": k, "lines": c, "first": first} for f, k, c, first in signals]
    with open(os.path.join(out, "index.tsv"), "w", encoding="utf-8", newline="\n") as handle:
        for rel, what in rows:
            handle.write("%s\t%s\n" % (rel, what))
    names = [r for r, _ in rows if r in ("timeline.plaso", "timeline.csv")]
    errors.extend(leftover_errors())
    extra["program_group"] = {"subreaper": LEFT["subreaper"], "left_behind": LEFT["left_behind"], "unproven": list(LEFT["unproven"])}
    if not errors and len(names) == 2:
        write_coverage(out, "complete", "log2timeline over every partition and volume of the image, and psort's timeline of it (the pipeline finished: see coverage_note)", [], extra)
        return 0, "coverage.json"
    if rows:
        kept = "Plaso wrote %s before it ended" % " and ".join(names or ["nothing usable"])
        if LEFT["left_behind"] or LEFT["unproven"]:
            kept += (", but a step left %d process(es) that were ended before the files were read (they may be cut short)" % LEFT["left_behind"]) if LEFT["left_behind"] else \
                ", but nothing shows that no step left a process behind, so the files cannot be shown to be final"
        write_coverage(out, "partial", kept, errors, extra)
    else:
        write_coverage(out, "failed", "nothing parsed", errors or ["log2timeline wrote no storage file"], extra)
    return 1, "coverage.json"


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("command", choices=("detect", "run"))
    parser.add_argument("--target", required=True)
    parser.add_argument("--out")
    # The census asks every detect step with --probe-out DIR; detect keeps nothing there.
    parser.add_argument("--probe-out")
    args = parser.parse_args()
    try:
        target, image = target_of(args.target)
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        print_answer({"ok": False, "error": str(exc)})
        return 2
    applies, why = detect(image)
    if args.command == "detect":
        print_answer({"applies": applies, "why": why})
        return 2 if applies == "unknown" else 0 if applies else 1
    if not args.out:
        print_answer({"ok": False, "error": "run needs --out DIR"})
        return 2
    if applies is not True:
        print_answer({"ok": False, "status": "unsupported", "why": why})
        return 2
    zone = target.get("timezone") if isinstance(target, dict) else None
    zone = zone or os.environ.get("RECIPE_TIMEZONE") or None
    if zone is not None and not (isinstance(zone, str) and ZONE.match(zone)):
        print_answer({"ok": False, "error": "timezone is a zone name such as Europe/Istanbul"})
        return 2
    rc, coverage_file = run(image, args.out, zone)
    status = json.load(open(os.path.join(args.out, coverage_file), encoding="utf-8")).get("status")
    result = {"ok": rc == 0, "status": status}
    if coverage_file != "coverage.json":
        result["coverage"] = coverage_file
    print_answer(result)
    return rc


# BEGIN SHARED LEAVE
# The same text is in every pack tool and recipe and in their tool-library twins (tests/shared-blocks-census.test.ts holds the copies equal):
# how a call ends once its answer has begun. The interpreter's own teardown resets the signal handlers to their defaults before it frees what
# the call held, and a stop signal that landed there killed a process that had printed its whole answer; a handler that raises or writes a
# last word, run after the answer was out, wrote a second document or a traceback after a whole one. So, when the file runs as a program:
# * Standard output is wrapped, and its first write is the first byte of the answer: from there the stop signals are held for good (blocked
#   in this thread, and given a handler that does nothing for any other), so no handler runs into the answer or after it, and an error Python
#   can only report (a file the call left open whose last write the file system refuses, closed when the frame that held it is freed) is
#   not printed (Python 3.11 and 3.12 say nothing of it; 3.14 prints a traceback). A handler that was already due runs on the way in, before
#   any byte is written, and its own answer is then the one.
# * _code(stop) is a SystemExit's exit code, and _leave(code) ends the call: both hold the signals first; _leave then flushes standard output
#   and standard error, runs the atexit hooks (a hook that removes a temporary file), each step on its own and none able to raise, and ends
#   the process with os._exit, never through the teardown. A stop signal after the hold is not answered: the exit code is the call's own.
# The modules are imported here, as the file is loaded, never inside the ending (an import there ran a due handler inside the import system).
import atexit
import os
import signal
import sys

_ENDING = {"held": False}
_ENDING_SIGNALS = (signal.SIGTERM, signal.SIGINT, signal.SIGHUP)


def _ending_nothing(*_ignored):
    """The stop signals' handler, and sys.unraisablehook, once the answer has begun: nothing."""


def hold_stop_signals():
    """Hold the stop signals for good. A handler that was due runs first, in the first call that can run it, and may raise: that is before
    any byte of the answer is written. Called by a thread that is not the main one, it blocks the signals there and leaves the rest to the
    main thread's next write."""
    if _ENDING["held"]:
        return
    try:
        signal.pthread_sigmask(signal.SIG_BLOCK, _ENDING_SIGNALS)
    except (AttributeError, ValueError, OSError):
        pass                          # no pthread_sigmask here: the handler below holds them
    main_thread = True
    for signum in _ENDING_SIGNALS:
        try:
            signal.signal(signum, _ending_nothing)
        except (ValueError, OSError):
            main_thread = False
    sys.unraisablehook = _ending_nothing
    _ENDING["held"] = main_thread


def _hold_at_the_end():
    for _attempt in range(len(_ENDING_SIGNALS) + 2):
        try:
            hold_stop_signals()
            return
        except BaseException:  # noqa: BLE001 - a handler that was due ran on the way in; the hold is made again
            continue


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
    _hold_at_the_end()
    code = getattr(stop, "code", 1)
    return code if isinstance(code, int) else (0 if code is None else 1)


def _leave(code):
    _hold_at_the_end()
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.flush()
        except BaseException:  # noqa: BLE001 - a reader that is gone, a stream that is closed: the exit code is the call's own
            pass
    try:
        atexit._run_exitfuncs()
    except BaseException:  # noqa: BLE001 - a hook that fails is not a failure of the answer
        pass
    code = code if isinstance(code, int) else 1
    os._exit(code)


if __name__ == "__main__" and sys.stdout is not None and not isinstance(sys.stdout, _AnswerStream):
    sys.stdout = _AnswerStream(sys.stdout)
# END SHARED LEAVE


if __name__ == "__main__":
    exit_code = 0
    try:
        sys.exit(main())
    except SystemExit as stop:
        exit_code = _code(stop)
    _leave(exit_code)
