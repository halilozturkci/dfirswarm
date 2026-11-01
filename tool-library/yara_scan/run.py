#!/usr/bin/env python3
"""Sweep a file or directory with a YARA rule file and report where every rule matched.

No rules ship with this. A curated rule set is a maintenance commitment that
does not belong in a tool library, and a stale rule reads like a finding. The
caller names the rules it trusts; this runs them and reports what matched,
where, and at what offset. A rule match is not a verdict on the file: it says
the rule's condition held, and a rule written for one family matches other
things.

Extracted material is the usual target, and the quarantine guard means the
files there cannot execute, which is why scanning them is safe and running
them is not. Links inside a scanned directory are not followed (-N, when the
installed yara has it).

THE SECRET-SAFE OUTPUT PATTERN (docs/packs.md, "Secrets and sensitive output"). `yara -s`
prints the bytes a string matched, so a rule that finds `password=` or a key header puts the
secret in the output. The answer here carries the rule, the file, the string identifier, the
offset and the length of every string match, and never the matched bytes. The bytes are
written only when the caller asks (`write_matches: true`), only when this runs as a job
(JOB_ID and OUT set; the skill says the job runs with `secret_output: true`), and only to a
file under $OUT (JSON Lines, mode 0600, one row per string match carrying the same
`finding_id`); outside a job the request is refused and nothing is written. The matched bytes
are not written to disk otherwise: yara's output is read as a stream and its text discarded.

Nothing is held whole in memory: yara's output is parsed line by line as it arrives. A run
that is stopped by its time limit says complete: false and keeps what was read.
"""
import hashlib
import json
import os
import re
import shutil
import signal
import stat
import subprocess
import sys
import tempfile
import threading
from pathlib import Path

# Lossless paging (the same in every library tool that pages): the page an
# agent reads stays small, and when there are more rows the whole result is
# written as JSON Lines under work/<agent>/tool-output (in a job, $OUT/tool-output)
# and named.

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
# <stem>-<n><suffix>. The name is taken first, with an exclusive create, so a result written at the same moment cannot be replaced either.
# Only regular files are ever compared: both names are opened with O_NONBLOCK and O_NOFOLLOW and looked at with fstat before a byte is
# read, so a FIFO, a device, a directory or a link at a name (the caller's own results_to, say) is another result's and cannot hold the
# tool. The comparing of one call has PLACE_COMPARE_SECONDS in all; past it an earlier result is taken as different and this one takes
# the next free name (nothing is replaced, but an identical rerun may then be named anew).
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


def place_without_replacing(tmp, path):
    """Move the finished `tmp` to `path` and never replace what is there. The name is taken first, with an exclusive create, so a
    result written at the same moment cannot be replaced either. Returns the path that holds it.
    The comparing with earlier results has PLACE_COMPARE_SECONDS in all: past it an earlier result is taken as different and this
    one takes the next free name."""
    deadline = time.monotonic() + PLACE_COMPARE_SECONDS
    for n in range(1, 1000):
        candidate = path if n == 1 else path.with_name("%s-%d%s" % (path.stem, n, path.suffix))
        try:
            fd = os.open(str(candidate), os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o600)
        except FileExistsError:
            if not os.path.islink(candidate) and same_bytes(tmp, candidate, deadline):
                os.unlink(tmp)
                return candidate
            continue
        os.close(fd)
        os.replace(tmp, candidate)             # only replaces the empty file this call just made
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


class SecretValuesRefused(Exception):
    pass


def describe(exc):
    if isinstance(exc, OSError):
        return "%s: %s" % (type(exc).__name__, exc.strerror or exc)
    return "%s: %s" % (type(exc).__name__, exc)


class SecretValues:
    """Where a value goes when, and only when, the caller asked for it.

    The secret-safe output pattern of docs/packs.md ("Secrets and sensitive output"),
    copied from its reference implementation (recovery_key_scan, encrypted-containers)
    and parameterised by the tool, the flag and the file's name. Call `add` once per
    finding with the finding's id, its locator and the value. With `enabled` false it
    writes nothing and `summary()` says so.
    """

    def __init__(self, enabled, tool, flag, name):
        self.enabled = enabled
        self.tool = tool
        self.flag = flag
        self.name = name
        self.written = 0
        self._fh = None
        self.job = os.environ.get("JOB_ID") or ""
        self.out = os.environ.get("OUT") or ""
        self.path = None
        self.shown = None
        if not enabled:
            return
        if not (self.job and self.out):
            raise SecretValuesRefused(
                "%s is refused outside a job: a value written here would be an ordinary "
                "file, not a sealed secret output. Run this as job_run tool=%s with "
                "secret_output: true, and ask again there. Nothing was written." % (flag, tool)
            )
        self.path = Path(self.out) / name
        self.shown = "store/jobs/%s/out/%s" % (re.sub(r"[^A-Za-z0-9_.-]", "_", self.job), name)
        # Created now, before anything is scanned: a file or a link already at that name is
        # refused by name at once (O_EXCL does not follow a link, a dangling one included),
        # instead of failing, or writing through it, after the scan. With nothing found it
        # stays as an empty file, mode 0600, and the answer says written: 0.
        try:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            fd = os.open(str(self.path), os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o600)
        except FileExistsError:
            raise SecretValuesRefused("the values file already exists: %s" % self.path)
        except OSError as exc:
            raise SecretValuesRefused("the values file could not be created: %s (%s)" % (self.path, describe(exc)))
        self._fh = os.fdopen(fd, "w", encoding="utf-8")

    def add(self, finding_id, locator, value):
        if not self.enabled:
            return
        self._fh.write(json.dumps({"finding_id": finding_id, **locator, "value": value}, ensure_ascii=False))
        self._fh.write("\n")
        self.written += 1

    def close(self):
        if self._fh is not None:
            self._fh.flush()
            os.fsync(self._fh.fileno())
            self._fh.close()
            self._fh = None

    def summary(self, format_note):
        return {
            "requested": self.enabled,
            "written": self.written,
            "values_file": self.shown if self.enabled else None,
            "contains_secret_values": self.written > 0,
            "format": format_note if self.enabled else None,
        }


PARSER = "yara_scan/5"
DEADLINE_SECONDS = 112            # the manifest allows 120: one clock over the probes, the walk, yara, the digest and the answer
RESERVE = 6                       # seconds of that clock kept for the pages, the digest of the rules and the answer
MAX_LIMIT = 10000                 # the largest inline page; the whole result is in the file the answer names
PROGRESS = {"phase": "starting"}
HELD = {"values": None, "deadline": None}
TEMPS = []                        # temporary files not yet placed (the standard error file)
RULE_NAME = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")


# BEGIN SHARED PROCESS
# The same text is in esedb_query, extract_stream, sigma_hunt, vss_stores and yara_scan; tests/pack-windows-forensics-process.test.ts
# holds the copies equal. A program a tool runs is started in THIS tool's process group, never in a session of its own: the
# harness ends a tool that runs too long, or is aborted, by killing the tool's group (process.kill(-pid, SIGKILL)), and a
# program in a group of its own goes on writing after the tool is gone. On Linux the kernel is also asked to kill it if the
# tool dies. The tool's own deadline kills the program and what it started by walking the process tree, and SIGTERM, SIGINT
# and SIGHUP do the same and then give the tool a last word. Only what is
# below a program this tool started and has not yet waited for is ever signalled: the walk starts at that program's pid
# and nowhere else, and a program that has been waited for (its pid may be another process's by now) is left alone. The
# walk has no bound but the number of processes. Two cases leave the tree running: a ps that needs more than PS_WAIT
# seconds, and a sandbox that denies both libproc and ps (macOS). A stop signal is the one case that reaches further: it also
# ends everything below the tool itself (a program that was forked a moment before it was entered in ACTIVE is among it) and what
# the tool started and lost (reap_orphans): a process that was seen below the tool, in the tool's own group, and whose parent has since
# ended. Nothing else is ever ended: a process the tool never saw in its tree (the next stage of a pipeline the tool heads, a process a
# launcher put in the group) is left alone, whoever leads the group. A program that has ended while something it started still
# holds its pipes does not hold the tool: communicate_bounded gives the pipes PIPE_GRACE seconds and goes on without them. (In the
# windows lineage only the windows-artefacts recipe and lnk_jumplist call it; the lineage is one text, so the others carry it unused.)
import time

try:
    import ctypes
except ImportError:  # pragma: no cover
    ctypes = None

STATE = {"last_word": None}    # what to do, with the signal number, when the tool is stopped by a signal
ACTIVE = []                    # the programs running now
SEEN = set()                   # the pids seen below a program this tool started: the only ones reap_orphans may end once their parent is gone


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
    return proc


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
    found, seen, stack = [], {pid}, [pid]
    while stack:
        for child in kids.get(stack.pop(), []):
            if child not in seen:
                seen.add(child)
                found.append(child)
                stack.append(child)
    return found


def _libproc_works(pid):
    """Whether an empty libproc answer for `pid` can be believed: libproc has just listed `pid` as this tool's own child, or, when `pid`
    is the tool itself, has just listed the tool as its parent's child. A library that lists nothing for a live process is not working
    (as in a sandbox that denies it)."""
    if pid in (_children_libproc(os.getpid()) or []):
        return True
    return pid == os.getpid() and os.getpid() in (_children_libproc(os.getppid()) or [])


def descendants(pid):
    """Every process below `pid` (never one beside it): from /proc where there is one, else from libproc, else from ps
    (given PS_WAIT seconds). libproc is believed when it lists a child; an empty answer is believed only when libproc has
    just listed this tool's own child `pid` (a library that answers nothing for a live child is not working, as in a
    sandbox that denies it), and otherwise ps is asked."""
    kids = {}
    try:
        if os.path.isdir("/proc/self"):
            for entry in os.listdir("/proc"):
                if entry.isdigit():
                    try:
                        with open("/proc/%s/stat" % entry, "rb") as fh:
                            fields = fh.read().rsplit(b")", 1)[1].split()
                        kids.setdefault(int(fields[1]), []).append(int(entry))
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
                return found
            if first is not None and _libproc_works(pid):
                return []
            out = subprocess.run(["ps", "-A", "-o", "pid=,ppid="], capture_output=True, text=True, timeout=PS_WAIT).stdout
            for line in out.splitlines():
                parts = line.split()
                if len(parts) == 2 and parts[0].isdigit() and parts[1].isdigit():
                    kids.setdefault(int(parts[1]), []).append(int(parts[0]))
    except (OSError, subprocess.SubprocessError):
        return []
    return _below(kids, pid)


def _process_table():
    """{pid: (parent pid, process group)} for every process, from /proc where there is one, else from ps (given PS_WAIT seconds);
    None when neither answers."""
    table = {}
    try:
        if os.path.isdir("/proc/self"):
            for entry in os.listdir("/proc"):
                if entry.isdigit():
                    try:
                        with open("/proc/%s/stat" % entry, "rb") as fh:
                            fields = fh.read().rsplit(b")", 1)[1].split()
                        table[int(entry)] = (int(fields[1]), int(fields[2]))
                    except (OSError, IndexError, ValueError):
                        continue
        else:
            out = subprocess.run(["ps", "-A", "-o", "pid=,ppid=,pgid="], capture_output=True, text=True, timeout=PS_WAIT).stdout
            for line in out.splitlines():
                parts = line.split()
                if len(parts) == 3 and all(part.isdigit() for part in parts):
                    table[int(parts[0])] = (int(parts[1]), int(parts[2]))
    except (OSError, subprocess.SubprocessError):
        return None
    return table


def _sample(pid):
    """Remember what is below `pid` now, by the cheap routes only (/proc, or libproc on macOS; never a program): a process that is seen
    here and later loses its parent is the tool's to end, and one that was never seen is not."""
    try:
        if os.path.isdir("/proc/self"):
            kids = {}
            for child, (parent, _group) in (_process_table() or {}).items():
                kids.setdefault(parent, []).append(child)
            SEEN.update(_below(kids, pid))
        else:
            seen, stack = {pid}, [pid]
            while stack:
                for child in _children_libproc(stack.pop()) or []:
                    if child not in seen:
                        seen.add(child)
                        stack.append(child)
            SEEN.update(seen - {pid})
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
    at, and a pid is checked against the group again at the moment it is signalled. Returns the pids signalled."""
    me = os.getpid()
    try:
        if os.getpgrp() != me:
            return []
    except OSError:
        return []
    table = _process_table()
    if not table:
        return []
    kids = {}
    for pid, (parent, _group) in table.items():
        kids.setdefault(parent, []).append(pid)
    below = set(_below(kids, me))
    on_linux = os.path.isdir("/proc/self")
    killed = []
    for pid, (_parent, group) in table.items():
        if group != me or pid == me or pid in below:
            continue
        if pid not in SEEN and not (inodes and on_linux and _holds_pipe(pid, inodes)):
            continue
        try:
            if os.getpgid(pid) != me:
                continue
            os.kill(pid, signal.SIGKILL)
            killed.append(pid)
        except OSError:
            pass
    return killed


def kill_tree(proc):
    """Kill the program and everything it started. The children are listed first: once the parent is gone they are
    adopted by init and can no longer be found below it. A program already waited for is not touched: its pid is free to
    be another process's, and the walk below it would be that process's children."""
    if proc.poll() is not None:
        return
    try:
        proc.send_signal(signal.SIGSTOP)    # a program that is stopped forks nothing more while its tree is listed
    except OSError:
        pass
    try:
        victims = descendants(proc.pid)
        SEEN.update(victims)
    finally:
        try:
            proc.kill()
        except OSError:
            pass
    for pid in victims:
        try:
            os.kill(pid, signal.SIGKILL)
        except OSError:
            pass


def wait_for(proc, seconds):
    """(exit code, timed out): wait for the program for at most `seconds`; at the deadline it and what it started are killed."""
    ACTIVE.append(proc)
    try:
        try:
            return proc.wait(timeout=seconds), False
        except subprocess.TimeoutExpired:
            kill_tree(proc)
            return proc.wait(), True
    finally:
        if proc in ACTIVE:
            ACTIVE.remove(proc)


PIPE_GRACE = 1.0    # seconds the pipes of a program that has ended are given to reach end of file


def communicate_bounded(proc, seconds, input=None):
    """(stdout bytes, stderr bytes, timed out) for a program started with pipes, in bytes. At `seconds` the program and what it started
    are killed (timed out). A program that has ended while something it started still holds its pipes (a daemon, a helper that
    inherited them) does not hold the tool: the pipes are given PIPE_GRACE seconds, what the program wrote is kept, what the tool
    lost is killed (reap_orphans), and the pipes are let go. The pipes are read here and by nothing else, so letting them go is safe."""
    deadline = time.monotonic() + max(0.1, seconds)
    out = err = b""
    started, timed_out = False, False
    while proc.poll() is None:
        now = time.monotonic()
        if now >= deadline:
            timed_out = True
            kill_tree(proc)
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
    return out or b"", err or b"", timed_out


def kill_all():
    """End every program the tool has running, with what each started. Then everything below the tool itself, which is the tool's own: a
    program forked a moment before it was entered in ACTIVE is among it. Then what an earlier program started and lost (reap_orphans)."""
    for proc in list(ACTIVE):
        kill_tree(proc)
    below = descendants(os.getpid())
    SEEN.update(below)
    for pid in below:
        try:
            os.kill(pid, signal.SIGKILL)
        except OSError:
            pass
    reap_orphans()


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


def install_signal_handlers():
    for signum in (signal.SIGTERM, signal.SIGINT, signal.SIGHUP):
        signal.signal(signum, _on_signal)
# END SHARED PROCESS
# `0x6:20:$a: data` with -s -L; `0x6:$a: data` with -s alone (an older yara has no -L).
SCAN_ERROR = re.compile(r"^error scanning (.+)$")
STRING_LINE = re.compile(r"^0x([0-9a-fA-F]+):(?:(\d+):)?(\$[A-Za-z0-9_]*): ?")


def print_answer(answer, **dumps_kwargs):
    """Print the answer with the stop signals held back (a signal in the middle of the write would end the process there, with the answer cut)
    and the last word cleared (a signal that is held and then lets go must not print a second document). The tool ends by itself right after."""
    try:
        signal.pthread_sigmask(signal.SIG_BLOCK, {signal.SIGTERM, signal.SIGINT, signal.SIGHUP})
    except (AttributeError, ValueError, OSError):
        pass
    STATE["last_word"] = None
    print(json.dumps(answer, **dumps_kwargs))


def drop_pages():
    """Remove the temporary files of the pages that were being written, and the standard error file that was being filled."""
    for page in list(PAGES):
        tmp = getattr(page, "_tmp", None)
        if tmp is not None:
            try:
                os.unlink(tmp)
            except OSError:
                pass
            page._tmp = None
    for name in list(TEMPS):
        try:
            os.unlink(name)
        except OSError:
            pass
    del TEMPS[:]


def close_values():
    values = HELD.get("values")
    if values is not None:
        try:
            values.close()
        except (OSError, ValueError):
            pass


def last_word(signum):
    """The tool's own last word: the programs are ended by the PROCESS handler before it runs; this removes the pages' temporary files, closes the values
    file and answers with one document."""
    drop_pages()
    close_values()
    print(json.dumps({"error": "stopped by signal %d before yara finished" % signum, "status": "interrupted", "signal": signum,
                      "status_basis": "the tool was stopped by signal %d (yara and what it started were ended, the temporary files removed); nothing it had read is an answer, and what was "
                                      "written to the values file, if one was asked for, is partial" % signum,
                      "phase": PROGRESS["phase"]}), flush=True)


# Installed as soon as the module has run as far as here, with a last word that needs nothing the tool has not made yet.
STATE["last_word"] = last_word
install_signal_handlers()


def fail(message, **extra):
    drop_pages()
    close_values()
    print_answer({"error": message, "status": "failed", "status_basis": "the tool stopped with an error and returned no match (see error)", **extra})
    raise SystemExit(1)


def sha256_of(path, until=None):
    """The file's digest, read in pieces with the clock looked at; None when the clock ran out."""
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            if until is not None and time.monotonic() > until:
                return None
            h.update(chunk)
    return h.hexdigest()


def tool_output_dir():
    out, job = os.environ.get("OUT"), os.environ.get("JOB_ID")
    if job and out:
        return Path(out) / "tool-output", "store/jobs/%s/out/tool-output" % re.sub(r"[^A-Za-z0-9_.-]", "_", job)
    d = Path("work") / re.sub(r"[^A-Za-z0-9_.-]", "_", os.environ.get("AGENT_ID") or "tool") / "tool-output"
    return d, str(d)


def left():
    return HELD["deadline"] - time.monotonic()


def main():
    HELD["deadline"] = time.monotonic() + DEADLINE_SECONDS
    try:
        args = json.load(sys.stdin)
    except ValueError as exc:
        fail("arguments are not valid JSON", reason=str(exc))
    if not isinstance(args, dict):
        fail("the arguments must be a JSON object")

    rules = args.get("rules")
    target = args.get("target")
    if not isinstance(rules, str) or not rules:
        fail("rules is required: a path to a .yar or .yara file")
    if not os.path.isfile(rules):
        fail("no such rules file", rules=rules)
    if not isinstance(target, str) or not target:
        fail("target is required: a file or directory to scan")
    if not os.path.exists(target):
        fail("no such target", target=target)

    timeout = args.get("timeout_seconds", 60)
    if not isinstance(timeout, int) or isinstance(timeout, bool) or timeout < 1:
        fail("timeout_seconds must be a positive integer")
    timeout = min(timeout, 110)
    limit = args.get("limit", 200)
    if not isinstance(limit, int) or isinstance(limit, bool) or not 1 <= limit <= MAX_LIMIT:
        fail("limit must be a whole number from 1 to %d (the inline page; the whole result is in the file the answer names)" % MAX_LIMIT)
    write_matches = args.get("write_matches", False)
    if not isinstance(write_matches, bool):
        fail("write_matches must be true or false")
    if write_matches and os.environ.get("SECRET_OUTPUT") != "1":
        fail("write_matches is refused: the matched bytes are written only in a job the harness runs as secret output (job_run with secret_output: true, which the "
             "manifest declares for this parameter). Nothing was opened or created.")

    if shutil.which("yara") is None:
        fail("yara is not on PATH", hint="brew install yara; scripts/toolbox.sh reports it with the dfir set")

    values = None
    for number in range(1, 1000):
        name = "yara-matched-strings.jsonl" if number == 1 else "yara-matched-strings-%d.jsonl" % number
        try:
            values = SecretValues(write_matches, "yara_scan", "write_matches", name)
            break
        except SecretValuesRefused as exc:
            # A values file of an earlier run in this job is never replaced and never a reason not to scan: the
            # next free number is this run's file, and the answer names it.
            if write_matches and "already exists" in str(exc):
                continue
            fail(str(exc))
    if values is None:
        fail("no free name for the values file after 999 tries")
    HELD["values"] = values

    # A target that is not a regular file or a directory (a FIFO, a socket, a device) is not opened: yara would wait
    # on it until the time limit. In a directory yara skips such entries itself; they are looked for here and said.
    if not (os.path.isdir(target) or os.path.isfile(target)):
        fail("target is not a regular file or a directory (a FIFO, a socket or a device is not scanned)", target=target, not_attempted=1)

    PROGRESS["phase"] = "asking yara for its version and flags"
    try:
        probe = max(1, min(10, int(left() - RESERVE)))
        version = subprocess.run(["yara", "--version"], stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=probe).stdout.decode("utf-8", "replace").strip()
        probe = max(1, min(10, int(left() - RESERVE)))
        help_text = subprocess.run(["yara", "--help"], stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=probe).stdout.decode("utf-8", "replace")
    except (OSError, subprocess.TimeoutExpired) as exc:
        fail("yara could not be run", reason=str(exc))

    # -s prints the matching strings (read here, never returned), -L their lengths, -r recurses,
    # -N does not follow links out of the scanned tree, -q turns off a rule's console output (a rule can print any text to
    # the same stream as its matches). A flag the installed yara lacks is left out.
    argv = ["yara", "-s"]
    if "--print-string-length" in help_text:
        argv.append("-L")
    if "--disable-console-logs" in help_text:
        argv.append("-q")
    if os.path.isdir(target):
        argv.append("-r")
        if "--no-follow-symlinks" in help_text:
            argv.append("-N")
    argv += [rules, target]

    # What yara will not scan, said before it runs: special files in a directory (it skips them without a word) and,
    # when it does not follow links (-N), the links it passes over. The walk has a share of the clock; past it the list is incomplete and said so.
    PROGRESS["phase"] = "walking the target"
    not_attempted = NoReplacePage("yara_scan", [rules, target, "not_attempted"], limit)
    skipped_links = "-N" in argv
    walk_cut = False
    walk_until = time.monotonic() + max(0.0, min(35.0, left() - RESERVE - 5))
    if os.path.isdir(target):
        for root, dirs, names in os.walk(target, followlinks=False):
            if time.monotonic() > walk_until:
                walk_cut = True
                break
            for entry in sorted(dirs + names):
                if time.monotonic() > walk_until:
                    walk_cut = True
                    break
                full = os.path.join(root, entry)
                try:
                    mode = os.lstat(full).st_mode
                except OSError as exc:
                    not_attempted.add({"file": full, "reason": "could not be examined: %s" % describe(exc)})
                    continue
                if stat.S_ISLNK(mode):
                    if skipped_links:
                        not_attempted.add({"file": full, "reason": "a symbolic link, not followed (yara -N)"})
                elif not (stat.S_ISREG(mode) or stat.S_ISDIR(mode)):
                    kind = "a FIFO" if stat.S_ISFIFO(mode) else "a socket" if stat.S_ISSOCK(mode) else "a device" if (stat.S_ISCHR(mode) or stat.S_ISBLK(mode)) else "a special file"
                    not_attempted.add({"file": full, "reason": "%s: yara does not scan it" % kind})

    outdir, outshown = tool_output_dir()
    key = [rules, target, timeout, argv]
    digest = hashlib.sha256(json.dumps(key, sort_keys=True).encode("utf-8")).hexdigest()[:16]
    rule_rows = NoReplacePage("yara_scan", [rules, target, "rules"], limit)
    string_rows = NoReplacePage("yara_scan", [rules, target, "strings"], limit)

    # yara gets what is left of the whole run, less the reserve for the pages, the digest and the answer.
    yara_seconds = min(timeout, int(left() - RESERVE))
    errfd, errname = tempfile.mkstemp(prefix=".yara-stderr-", dir=_ensure(outdir))
    TEMPS.append(errname)
    timed_out = [False]
    never_ran = yara_seconds < 1
    ignored = 0           # lines that are neither a rule line for a path of the target nor a string line: counted, never shown
    current = None        # [rule, file, string count]
    files_with_matches = set()
    string_total = 0
    unparsed = 0          # string lines seen before any rule line: counted, never shown (a line holds matched bytes)
    rc = None
    base = target.rstrip("/") + "/" if target not in ("/", "") else target
    if never_ran:
        os.close(errfd)
    else:
        PROGRESS["phase"] = "yara is running"
        try:
            proc = spawn(argv, stdout=subprocess.PIPE, stderr=errfd)
        except OSError as exc:
            os.close(errfd)
            fail("yara could not be started", reason=str(exc))
        os.close(errfd)
        ACTIVE.append(proc)

        def stop():
            timed_out[0] = True
            kill_tree(proc)

        timer = threading.Timer(yara_seconds, stop)
        timer.start()
        # The output is read by a thread of its own and the main thread waits in short turns: a stop signal that arrives in the instant before a blocking read
        # begins is then handled within half a second, where a main thread already blocked in the read would never run its handler.
        box = {}

        def consume():
            nonlocal current, string_total, unparsed, ignored
            try:
                for raw in proc.stdout:
                    line = raw.decode("utf-8", "replace").rstrip("\r\n")
                    if not line.strip():
                        continue
                    m = STRING_LINE.match(line)
                    if m:
                        if current is None:
                            unparsed += 1
                            continue
                        string_total += 1
                        finding = "S%06d" % string_total
                        offset = int(m.group(1), 16)
                        length = int(m.group(2)) if m.group(2) is not None else None
                        row = {"finding_id": finding, "rule": current[0], "file": current[1], "identifier": m.group(3),
                               "offset": offset, "offset_hex": "0x%x" % offset, "length": length}
                        string_rows.add(row)
                        current[2] += 1
                        # The matched bytes are the rest of the line. They go nowhere unless the caller asked, in a job.
                        values.add(finding, {"rule": current[0], "file": current[1], "identifier": m.group(3), "offset": offset, "length": length},
                                   line[m.end():])
                        continue
                    rule, _, path = line.partition(" ")
                    rule, path = rule.strip(), path.strip()
                    # A rule line is `<rule> <path>` with a path that is the target or lies under it. Any other line (a rule's console output that -q did
                    # not silence, or text a yara of another version prints) is counted and not shown: it is not a rule name.
                    if not RULE_NAME.match(rule) or not (path == target or path.startswith(base)):
                        ignored += 1
                        continue
                    if current is not None:
                        rule_rows.add({"rule": current[0], "file": current[1], "string_matches": current[2]})
                    current = [rule, path, 0]
                    files_with_matches.add(current[1])
                if current is not None:
                    rule_rows.add({"rule": current[0], "file": current[1], "string_matches": current[2]})
            except BaseException as exc:  # noqa: BLE001 - handed to the main thread
                box['error'] = exc

        reader = threading.Thread(target=consume, daemon=True)
        reader.start()
        try:
            while reader.is_alive():
                reader.join(0.5)
            if 'error' in box:
                raise box['error']
        finally:
            timer.cancel()
            rc = proc.wait()
            if proc in ACTIVE:
                ACTIVE.remove(proc)
            values.close()
    values.close()

    PROGRESS["phase"] = "reading yara's standard error"
    stderr_file = None
    stderr_count = 0
    warnings, first_errors = [], []
    scan_errors = NoReplacePage("yara_scan", [rules, target, "scan_errors"], limit)
    stderr_unread = False
    with open(errname, "rb") as fh:
        for raw in fh:
            line = raw.decode("utf-8", "replace").rstrip("\r\n")
            if not line.strip():
                continue
            stderr_count += 1
            if not (stderr_count & 4095) and left() < 2:
                stderr_unread = True
                break
            if len(warnings) < 20:
                warnings.append(line)
            if "error" in line.lower() and len(first_errors) < 5:
                first_errors.append(line)
            m = SCAN_ERROR.match(line)
            if m:
                path, _, reason = m.group(1).rpartition(": ")
                scan_errors.add({"file": path if path else m.group(1), "reason": reason if path else None, "line": line})
    if stderr_count:
        # Never over an earlier run's file: the next free number names this one.
        for number in range(1, 1000):
            final = outdir / ("yara_scan-%s.stderr.txt" % digest if number == 1 else "yara_scan-%s.stderr.%d.txt" % (digest, number))
            try:
                os.link(errname, final)
                os.unlink(errname)
                break
            except FileExistsError:
                continue
            except OSError:
                if not os.path.lexists(final):
                    os.rename(errname, final)
                    break
        else:
            fail("no free name for the standard error file after 999 tries")
        stderr_file = "%s/%s" % (outshown, final.name)
    else:
        os.unlink(errname)
    del TEMPS[:]

    PROGRESS["phase"] = "writing the answer"
    rule_page, string_page = rule_rows.finish(), string_rows.finish()
    error_page, skipped_page = scan_errors.finish(), not_attempted.finish()
    rules_digest = sha256_of(rules, time.monotonic() + max(1.0, left() - 1))
    complete = (not never_ran and rc == 0 and not timed_out[0] and error_page["matched"] == 0 and skipped_page["matched"] == 0 and not walk_cut
                and not stderr_unread and rules_digest is not None)
    if complete:
        status = "complete"
    elif never_ran or timed_out[0] or (rc == 0 and not timed_out[0]) or rule_page["matched"] or string_page["matched"]:
        status = "partial"
    else:
        status = "failed"
    reasons = []
    if never_ran:
        reasons.append("the tool's own clock (%d s) left yara no time to run (the probes and the walk of the target used it): nothing was scanned" % DEADLINE_SECONDS)
    if timed_out[0]:
        reasons.append("yara was stopped after %d s (its share of the tool's %d s clock, or timeout_seconds): what it printed before is listed" % (yara_seconds, DEADLINE_SECONDS))
    if walk_cut:
        reasons.append("the walk of the target for files yara skips was cut by the clock: not_attempted is incomplete")
    if rc not in (0, None) and not timed_out[0]:
        reasons.append("yara exited %d" % rc)
    if error_page["matched"]:
        reasons.append("%d file(s) could not be scanned (scan_errors)" % error_page["matched"])
    if skipped_page["matched"]:
        reasons.append("%d entr(ies) yara does not scan (not_attempted)" % skipped_page["matched"])
    if stderr_unread or rules_digest is None:
        reasons.append("the tool's clock ran out while its standard error was read or the rules file hashed")
    answer = {
        "parser": PARSER,
        "status": status,
        "status_basis": "; ".join(reasons) if reasons else "yara ran to its end over the target (exit 0), printed no scan error, skipped nothing, and its output was read whole",
        "complete": complete,
        "yara_version": version,
        "yara_argv": argv,
        "yara_exit_status": rc,
        "timed_out": timed_out[0],
        "timeout_seconds": timeout,
        "rules": rules,
        "rules_sha256": rules_digest,
        "target": target,
        "matches": rule_rows.page,
        "match_count": rule_page["matched"],
        "matches_page": rule_page,
        "string_matches": string_rows.page,
        "string_match_count": string_page["matched"],
        "string_matches_page": string_page,
        "files_with_matches": len(files_with_matches),
        "unparsed_string_lines": unparsed,
        "ignored_lines": ignored,
        "scan_errors": scan_errors.page,
        "scan_error_count": error_page["matched"],
        "scan_errors_page": error_page,
        "not_attempted": not_attempted.page,
        "not_attempted_count": skipped_page["matched"],
        "not_attempted_page": skipped_page,
        "stderr_file": stderr_file,
        "stderr_line_count": stderr_count,
        "warnings": warnings,
        "first_errors": first_errors,
        "matched_bytes": "not in this answer; write_matches: true, in a job run with secret_output: true, writes them to a file under $OUT",
        "secret_values": values.summary("JSON Lines, mode 0600: finding_id, rule, file, identifier, offset, length, value (as yara prints it)"),
        "note": "A rule match says the rule's condition held, not that the file is malicious. Rules that `include` other files are not hashed beyond the file named. "
                + ("" if complete else "The run did not complete: what is listed is what was read before it stopped."),
    }
    print_answer(answer, indent=2)
    if status == "failed":
        raise SystemExit(1)


def _ensure(path):
    path.mkdir(parents=True, exist_ok=True)
    return str(path)


if __name__ == "__main__":
    try:
        main()
    except SystemExit:
        raise
    except OSError as exc:
        fail("a file operation failed: %s" % describe(exc), reason=type(exc).__name__)
    except Exception as exc:                                  # whatever hostile input does, the answer is JSON
        drop_pages()
        close_values()
        print_answer({"error": "the scan failed", "status": "failed", "status_basis": "the tool stopped with an unexpected error",
                      "reason": "%s: %s" % (type(exc).__name__, exc)})
        sys.exit(1)
