#!/usr/bin/env python3
"""Run a Sigma ruleset over event logs, with whichever engine the host carries.

Querying by event id answers a question you already knew to ask. A ruleset
tests patterns you did not think of: each rule is a pattern somebody described,
run over the records the engine reads. How many rules there are, how many the
engine loaded and how many it skipped depend on the ruleset you name and on the
engine, and the tool does not count them: the engine's own output says. A result
shows what these rules, in this engine, found in these records.

Two engines do the same job and neither is shipped here:

    Zircolite   Python; loads the records into SQLite and runs the rules as queries.
    Hayabusa    one Rust binary; it also builds a timeline.

Both are invoked as executables, and either one is enough: this tool needs ONE
of them, not both. A comparison of their speed or memory is not claimed here.

The output is normalised to the same shape whichever ran, because an agent
should not have to learn two formats, and because the thing that goes in the
report is not the detection anyway. A rule firing is a hypothesis with a name.
The evidence is the record it matched, which you then read with evtx_query and
cite by its record id and channel.

out_dir is a place the run can write: work/<your id>/hunt (or work/extracted/<id>/..., work/quarantine/<id>/...,
tool-output/<id>/...) in an agent's VM, $OUT in a job; any other is refused with the places that work named.
Every run gets a directory of its own under out_dir (hunt-<UTC time>-<id>), so a
result left by an earlier invocation can never be taken for this one's. The engine's
exit status is judged: a non-zero status with a result file is a PARTIAL run, not a
clean one. The engine's result is read as a stream and its detections normalised into
detections.jsonl, sorted by level and time with a bounded-memory merge sort. A level
the tool does not know is never ranked as the lowest and dropped: such a detection is
kept, counted under `unknown_levels` and shown first. The engines' own level words are
read (Hayabusa writes `crit`, `med` and `info`). A line of the engine's result that
cannot be read is counted and kept whole in a file, never skipped.

Nothing is cut. Every field of a matched record is kept, every rule that fired
is counted, and the engine's own stdout and stderr are kept whole beside its
result. Past `limit` the detections are a page, and all of them, normalised,
are in detections.jsonl in the run directory; each file is named with its path, size
and sha256. The ruleset the caller names is recorded by digest; where the engine's
own bundled rules are used, that is said, and their content is not recorded here.

Neither engine writes beside the run. Each would put its log in the working
directory, which is the run's, read-only in an agent's VM and in a job's
worker: Zircolite its zircolite.log, which --logfile moves into the run directory
(Zircolite has taken -l/--logfile since 2.x, and 4.0, the images' pin, still
does); Hayabusa its ./logs/errorlog-<time>.log, whose place no option names
(-Q only drops it), so Hayabusa runs in the run directory, given every path
absolute, and its error log is kept there.
"""
import datetime
import hashlib
import heapq
import json
import os
import re
import secrets
import shutil
import signal
import subprocess
import sys
import tempfile
from pathlib import Path

PARSER = "sigma_hunt/7"
DEADLINE_SECONDS = 1170           # the manifest allows 1,200: one clock over the probes, the engine, the parse, the sort, the write and the answer
POST_SECONDS = 120                # kept back for what follows the engine (the parse, the sort, the write, the answer)
PARSE_STOPS_AT = 40               # the read of the engine's result stops when this many seconds are left
WRITE_STOPS_AT = 5                # the write of detections.jsonl stops when this many seconds are left
MAX_LIMIT = 10000                 # the largest inline page; the whole result is in the file the answer names
TEMPS = []                        # the sort's temporary files that are not yet merged
HELD = {"deadline": None, "phase": "starting", "command": None}
MAX_TIMEOUT = 1000


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
DEFAULT_TIMEOUT = 900
LEVELS = ["informational", "low", "medium", "high", "critical"]
# The level words the engines write: Zircolite the full ones, Hayabusa the short ones.
LEVEL_RANK = {"informational": 0, "info": 0, "low": 1, "medium": 2, "med": 2, "high": 3, "critical": 4, "crit": 4}
SORT_RUN_BYTES = 64 * 1024 * 1024
JSON_VALUE_CAP = 256 * 1024 * 1024


# Where the run directory is once it exists, so a failure after the engine ran can name it.
STATE = {"run_dir": None}


def fail(message, **extra):
    if STATE["run_dir"] and "run_dir" not in extra:
        extra["run_dir"] = STATE["run_dir"]
    drop_temps()
    print_answer({"error": message, "status": "failed", "status_basis": "the tool stopped with an error and returned no detection (see error)", **extra})
    raise SystemExit(1)


def writable_place(out_dir):
    """Refuse an out_dir that this run cannot write, naming the places that work. In a job only $OUT is writable; in an
    agent's VM the harness maps the agent's own work/<id>/, work/extracted/<id>/, work/quarantine/<id>/ and
    tool-output/<id>/ and nothing else under them (work/hunt, a bare work/ or another agent's directory fail
    with a permission error after the engine has been looked for). With neither a job nor an agent id there is
    no map to hold the path to."""
    root = Path.cwd().resolve()
    dest = (root / out_dir).resolve()
    if os.environ.get("JOB_ID") and os.environ.get("OUT"):
        base = Path(os.environ["OUT"]).resolve()
        if dest == base or base in dest.parents:
            return
        fail("out_dir must be under $OUT in a job: the run directory is read-only there", out_dir=out_dir,
             writable=[os.path.relpath(base, root) if root in base.parents else str(base)])
    agent = os.environ.get("AGENT_ID")
    if not agent:
        return
    safe = re.sub(r"[^A-Za-z0-9_.-]", "_", agent)
    places = [root / "work" / safe, root / "work" / "extracted" / safe, root / "work" / "quarantine" / safe,
              root / "tool-output" / safe]
    if any(dest == p or p in dest.parents for p in places):
        return
    fail("out_dir is not a place this run can write: use a directory under your own work/%s/" % safe, out_dir=out_dir,
         writable=["work/%s/..." % safe, "work/extracted/%s/..." % safe, "work/quarantine/%s/..." % safe,
                   "tool-output/%s/..." % safe])


def resolve_output(out, what="output"):
    """Where `out` really lands, as a path under the run directory; a place
    outside it, the run directory itself, or anything under inputs/ is refused.

    A string check is not enough: `work/../inputs/x`, an absolute path and a
    symlink that points out all name a place the tool must not write, and none
    of them starts with "inputs/". Resolving first and comparing directories
    is what actually holds, and the read-only inputs are the one place
    extracted bytes must never appear -- a later integrity check would report
    the evidence as modified. In a job $OUT is inside the run directory.
    """
    root = Path.cwd().resolve()
    dest = (root / out).resolve() if not Path(out).is_absolute() else Path(out).resolve()
    if dest == root or root not in dest.parents:
        fail("%s must stay inside the run directory" % what, **{what: str(out)})
    inputs = root / "inputs"
    if dest == inputs or inputs in dest.parents:
        fail("%s cannot be under inputs/" % what, **{what: str(out)})
    return str(dest.relative_to(root))


def file_ref(path, rows=None):
    """Name a file the tool wrote or the engine wrote: path, bytes and sha256, streamed."""
    h = hashlib.sha256()
    n = 0
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
            n += len(chunk)
    named = {"path": path, "bytes": n, "sha256": h.hexdigest()}
    if rows is not None:
        named["rows"] = rows
    return named


def engine_logs(engine, run_dir, zircolite_log):
    """The logs the engine wrote in run_dir: Zircolite's one file, Hayabusa's logs/."""
    if engine == "zircolite":
        return [zircolite_log] if os.path.isfile(zircolite_log) else []
    logs = os.path.join(run_dir, "logs")
    if not os.path.isdir(logs):
        return []
    return sorted(os.path.join(logs, name) for name in os.listdir(logs) if os.path.isfile(os.path.join(logs, name)))


def rank(level):
    """The rank of a level word, or None when it is not one the engines write (or there is none)."""
    if level is None:
        return None
    return LEVEL_RANK.get(str(level).strip().lower())


class Malformed:
    """What of an engine's result could not be read, kept whole in a file."""

    def __init__(self, path):
        self.path = path
        self.count = 0
        self.bytes = 0
        self._fh = None

    def add(self, text, where):
        if self._fh is None:
            self._fh = open(self.path, "w", encoding="utf-8", errors="surrogateescape")
        self.count += 1
        data = "%s\t%s\n" % (where, text.replace("\n", "\\n"))
        self._fh.write(data)
        self.bytes += len(data.encode("utf-8", "surrogateescape"))

    def add_stream(self, first, fh, where):
        """Keep `first` and everything still to be read from `fh` as one unreadable item, copied across in chunks:
        the rest of a document that stopped making sense can be as large as the file."""
        if self._fh is None:
            self._fh = open(self.path, "w", encoding="utf-8", errors="surrogateescape")
        self.count += 1

        def put(text):
            self._fh.write(text)
            self.bytes += len(text.encode("utf-8", "surrogateescape"))

        put("%s\t" % where)
        put(first.replace("\n", "\\n"))
        for chunk in iter(lambda: fh.read(1 << 20), ""):
            put(chunk.replace("\n", "\\n"))
        put("\n")

    def close(self):
        if self._fh is not None:
            self._fh.close()
            self._fh = None


def json_values(path, malformed):
    """Yield the JSON values of an engine's result file, as a stream: the elements of a top-level
    array, objects written one after another (pretty-printed or one to a line). A line of a
    line-delimited file that is not JSON is counted and kept in `malformed`, and the next line is read;
    a document that stops making sense is kept whole from that point, copied to the file in chunks (it is
    never held in memory), and ends the read.

    Which of the two it is comes from the first line alone: a line that begins an object and says more than the
    brace (`{"RuleTitle": ...`) is the first of a line-delimited file whether or not it is whole, so a damaged
    first line costs one line; a lone `{`, a `[` and anything else is a document."""
    decoder = json.JSONDecoder()
    with open(path, "r", encoding="utf-8", errors="replace") as fh:
        first = ""
        pos = fh.tell()
        for line in fh:
            if line.strip():
                first = line.strip()
                break
        fh.seek(pos)
        if first.startswith("{") and first != "{":
            for number, line in enumerate(fh, 1):
                text = line.strip()
                if not text:
                    continue
                try:
                    yield json.loads(text)
                except ValueError:
                    malformed.add(text, "line %d" % number)
            return
        buf, eof = "", False
        while True:
            i = 0
            while True:
                while i < len(buf) and buf[i] in " \t\r\n,[]":
                    i += 1
                if i < len(buf):
                    break
                buf, i = "", 0
                if eof:
                    return
                chunk = fh.read(1 << 20)
                if not chunk:
                    eof = True
                else:
                    buf += chunk
            buf = buf[i:]
            try:
                value, end = decoder.raw_decode(buf)
            except ValueError as exc:
                # More of the file can finish a value only when the error is where the text ends (a cut value,
                # a string not yet closed); an error in the middle of what is held is the document's.
                near_end = isinstance(exc, json.JSONDecodeError) and (
                    exc.pos >= len(buf) - 12 or exc.msg.startswith("Unterminated string"))
                if not eof and near_end and len(buf) < JSON_VALUE_CAP:
                    chunk = fh.read(1 << 20)
                    if chunk:
                        buf += chunk
                        continue
                    eof = True
                    continue
                # What is left does not parse: it is kept whole, streamed to the file, and the read ends here.
                malformed.add_stream(buf, fh, "from the value at the start of this text")
                return
            yield value
            buf = buf[end:]


def zircolite_rows(values, malformed):
    """Zircolite writes a list of rules, each with the events that matched it."""
    for rule in values:
        if not isinstance(rule, dict):
            malformed.add(json.dumps(rule, default=str), "not a rule object")
            continue
        title = rule.get("title") or rule.get("rule_title") or "unnamed rule"
        if not isinstance(title, str):
            malformed.add(json.dumps(rule, default=str), "the rule title is not text")
            continue
        level = rule.get("rule_level") or rule.get("level")
        found = rule.get("matches") or []
        if not isinstance(found, list):
            malformed.add(json.dumps(rule, default=str), "matches is not a list")
            continue
        for match in found:
            if not isinstance(match, dict):
                malformed.add(json.dumps(match, default=str), "a match of rule %s is not an object" % json.dumps(title)[:80])
                continue
            yield {
                "rule": title,
                "level": level,
                "rule_id": rule.get("id"),
                "time": match.get("SystemTime") or match.get("UtcTime") or match.get("timestamp"),
                "event_id": match.get("EventID"),
                "channel": match.get("Channel"),
                "computer": match.get("Computer"),
                "record_id": match.get("EventRecordID"),
                "detail": match,
            }


def hayabusa_rows(values, malformed):
    """Hayabusa's JSON timeline is one detection per object, or one per line."""
    for row in values:
        if not isinstance(row, dict):
            malformed.add(json.dumps(row, default=str), "not a detection object")
            continue
        details = row.get("Details")
        title = row.get("RuleTitle") or row.get("RuleFile") or "unnamed rule"
        if not isinstance(title, str):
            malformed.add(json.dumps(row, default=str), "the rule title is not text")
            continue
        yield {
            "rule": title,
            "level": row.get("Level"),
            "rule_id": row.get("RuleID"),
            "time": row.get("Timestamp") or row.get("timestamp"),
            "event_id": row.get("EventID"),
            "channel": row.get("Channel"),
            "computer": row.get("Computer"),
            "record_id": row.get("RecordID"),
            "detail": details if isinstance(details, dict) else {"details": details},
        }


class Sorted:
    """Normalised detections written to a file in the order the answer gives them (unknown
    levels first, then critical down to informational, then by time), with a merge sort whose
    memory is one run of at most SORT_RUN_BYTES."""

    def __init__(self, directory):
        self.directory = directory
        self.runs = []
        self.buffer = []
        self.size = 0
        self.seq = 0

    def add(self, row, level_rank):
        group = 0 if level_rank is None else 1 + (4 - level_rank)
        key = "%d\t%s\t%012d" % (group, str(row.get("time") or "").replace("\t", " ").replace("\n", " "), self.seq)
        self.seq += 1
        line = key + "\t" + json.dumps(row, default=str)          # ASCII: a lone surrogate in a field (a name that is not UTF-8) is escaped, not an encoding error later
        self.buffer.append(line)
        self.size += len(line)
        if self.size >= SORT_RUN_BYTES:
            self._spill()

    def _spill(self):
        self.buffer.sort()
        fd, name = tempfile.mkstemp(prefix=".sort-", dir=self.directory)
        TEMPS.append(name)
        with os.fdopen(fd, "w", encoding="utf-8", errors="surrogateescape") as fh:
            for line in self.buffer:
                fh.write(line + "\n")
        self.runs.append(name)
        self.buffer, self.size = [], 0

    def write(self, destination, keep, stop=None):
        """Write the sorted rows to destination as JSON Lines; return the first `keep` of them, the count and whether `stop()` cut the write."""
        first, count, cut = [], 0, False
        streams = []
        if self.runs:
            if self.buffer:
                self._spill()
            streams = [open(r, "r", encoding="utf-8", errors="surrogateescape") for r in self.runs]
            merged = heapq.merge(*[(l.rstrip("\n") for l in s) for s in streams])
        else:
            self.buffer.sort()
            merged = iter(self.buffer)
        with open(destination, "w", encoding="utf-8", errors="surrogateescape") as out:
            for line in merged:
                if stop is not None and not (count & 4095) and stop():
                    cut = True
                    break
                row_json = line.split("\t", 3)[3]
                out.write(row_json + "\n")
                if count < keep:
                    first.append(json.loads(row_json))
                count += 1
        for s in streams:
            s.close()
        for r in self.runs:
            os.unlink(r)
            if r in TEMPS:
                TEMPS.remove(r)
        return first, count, cut


def ruleset_record(rules, until=None):
    """The ruleset the caller named, by digest: a file by its sha256, a directory by the digest of its
    sorted relative paths and file digests. Without one, the engine's own bundled rules are in use. `until` is the clock's end; a digest it cuts is none, and says so."""
    if not rules:
        return {"source": "the engine's bundled rules", "digest": None,
                "note": "no ruleset was named, so the rules in use are whatever the engine carries; their content is not recorded here"}

    def hashed(path, h):
        with open(path, "rb") as fh:
            for chunk in iter(lambda: fh.read(1 << 20), b""):
                if until is not None and time.monotonic() > until:
                    return False
                h.update(chunk)
        return True

    p = Path(rules)
    if p.is_file():
        h = hashlib.sha256()
        if not hashed(p, h):
            return {"source": str(rules), "kind": "file", "files": 1, "digest": None, "cut_by_clock": True}
        return {"source": str(rules), "kind": "file", "files": 1, "digest": h.hexdigest()}
    if p.is_dir():
        outer = hashlib.sha256()
        files = 0
        for root, dirs, names in os.walk(p):
            dirs.sort()
            if until is not None and time.monotonic() > until:
                return {"source": str(rules), "kind": "directory", "files": files, "digest": None, "cut_by_clock": True}
            for name in sorted(names):
                full = os.path.join(root, name)
                if os.path.islink(full) or not os.path.isfile(full):
                    continue
                h = hashlib.sha256()
                if not hashed(full, h):
                    return {"source": str(rules), "kind": "directory", "files": files, "digest": None, "cut_by_clock": True}
                outer.update(("%s\t%s\n" % (os.path.relpath(full, p), h.hexdigest())).encode("utf-8", "surrogateescape"))
                files += 1
        return {"source": str(rules), "kind": "directory", "files": files, "digest": outer.hexdigest(),
                "digest_of": "sorted relative paths with each regular file's sha256; links are not followed"}
    return {"source": str(rules), "digest": None, "note": "not a file or directory on this host; the engine may resolve it itself"}


def engine_version(binary, budget):
    """The engine's version line, asking at most twice and never longer than `budget` seconds in all."""
    until = time.monotonic() + budget
    for flag in ("--version", "-V"):
        wait = min(15, until - time.monotonic())
        if wait < 1:
            return None
        try:
            p = subprocess.run([binary, flag], stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=wait, stdin=subprocess.DEVNULL)
        except (OSError, subprocess.TimeoutExpired):
            return None
        text = p.stdout.decode("utf-8", "replace").strip().splitlines()
        if p.returncode == 0 and text:
            return text[0].strip()
    return None


def count_evtx(path, until):
    """How many .evtx files lie under `path` (a file counts as one), looked for until the clock `until`; the second value says the look was cut short."""
    if os.path.isfile(path):
        return 1, False
    n = 0
    for _root, _dirs, names in os.walk(path):
        if time.monotonic() > until:
            return n, True
        n += sum(1 for name in names if name.lower().endswith(".evtx"))
    return n, False


NONE_READ = re.compile(rb"(?i)no\s+evtx\s+files?|evtx\s+files?\s*(?:read|found|loaded)?\s*[:=]\s*0\b|total\s+evtx\s+files?\s*[:=]\s*0\b|0\s+evtx\s+files?")


def engine_says_none_read(*paths):
    """Whether the first 64 KiB of the engine's own words say it read no .evtx file."""
    for p in paths:
        try:
            with open(p, "rb") as fh:
                if NONE_READ.search(fh.read(65536)):
                    return True
        except OSError:
            pass
    return False


def print_answer(answer, **dumps_kwargs):
    """Print the answer with the stop signals held back and the last word cleared: a signal at that point gives no second document."""
    try:
        signal.pthread_sigmask(signal.SIG_BLOCK, {signal.SIGTERM, signal.SIGINT, signal.SIGHUP})
    except (AttributeError, ValueError, OSError):
        pass
    STATE["last_word"] = None
    print(json.dumps(answer, **dumps_kwargs))


def drop_temps():
    """Remove the temporary files of the sort that were not yet merged."""
    for name in list(TEMPS):
        try:
            os.unlink(name)
        except OSError:
            pass
    del TEMPS[:]


def last_word(signum):
    """After the PROCESS handler has ended the engine: remove the sort's temporary files and answer with one document."""
    drop_temps()
    print(json.dumps({"error": "stopped by signal %d before the hunt finished" % signum, "status": "interrupted", "signal": signum,
                      "status_basis": "the tool was stopped by signal %d (the engine and what it started were ended, the sort's temporary files removed); nothing it had read is an answer" % signum,
                      "phase": HELD["phase"], "run_dir": STATE["run_dir"], "command": HELD.get("command"),
                      "note": "No statement about detections follows from an interrupted run."}), flush=True)


# Installed as soon as the module has run as far as here, before main() creates anything.
STATE["last_word"] = last_word
install_signal_handlers()


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

    path = args.get("path")
    if not isinstance(path, str) or not path:
        fail("path is required: an .evtx file or a directory of them")
    if not os.path.exists(path):
        fail("no such file or directory", path=path)

    out_dir = args.get("out_dir")
    if not isinstance(out_dir, str) or not out_dir:
        fail("out_dir is required: a directory under work/ for the engine's own output")
    out_dir = resolve_output(out_dir, "out_dir")
    writable_place(out_dir)

    min_level = args.get("min_level") or "medium"
    if not isinstance(min_level, str) or min_level.lower() not in LEVELS:
        fail("min_level must be one of %s" % ", ".join(LEVELS))
    min_level = min_level.lower()
    limit = args.get("limit", 200)
    if not isinstance(limit, int) or isinstance(limit, bool) or not 1 <= limit <= MAX_LIMIT:
        fail("limit must be a whole number from 1 to %d (the inline page; the whole result is in the file the answer names)" % MAX_LIMIT)
    timeout = args.get("timeout_seconds", DEFAULT_TIMEOUT)
    if not isinstance(timeout, int) or isinstance(timeout, bool) or timeout < 10:
        fail("timeout_seconds must be an integer of at least 10")
    timeout = min(timeout, MAX_TIMEOUT)             # the tool's own limit is 1,200 s: the engine stops before it, and its result is read after
    rules_arg = args.get("rules")
    if rules_arg is not None and not isinstance(rules_arg, str):
        fail("rules must be a string: the path of a ruleset (a file or a directory)")

    wanted = args.get("engine") or "auto"
    if not isinstance(wanted, str) or wanted.lower() not in ("auto", "zircolite", "hayabusa"):
        fail("engine must be auto, zircolite or hayabusa")
    wanted = wanted.lower()
    # Every detection row carries the whole matched record, so the files this tool writes are secret output: the manifest makes every job of it one,
    # and a job that was not run as such is refused here, before anything is created.
    if os.environ.get("JOB_ID") and os.environ.get("SECRET_OUTPUT") != "1":
        fail("sigma_hunt is refused in a job that was not run as secret output: its detections carry the whole matched records, and its files would be sealed as ordinary "
             "output. Run it as job_run(tool: \"sigma_hunt\", ...), whose manifest makes every job of this tool secret output. Nothing was created.")

    zircolite = shutil.which("zircolite") or shutil.which("zircolite.py")
    hayabusa = shutil.which("hayabusa")
    engine = None
    if wanted in ("auto", "zircolite") and zircolite:
        engine, binary = "zircolite", zircolite
    elif wanted in ("auto", "hayabusa") and hayabusa:
        engine, binary = "hayabusa", hayabusa
    if engine is None:
        fail("no Sigma engine on PATH",
             looked_for=["zircolite", "hayabusa"],
             install={"zircolite": "https://github.com/wagga40/Zircolite/releases",
                      "hayabusa": "https://github.com/Yamato-Security/hayabusa/releases"},
             note="Either engine is enough. Both are invoked as executables.")

    # A directory of this run's own: whatever an earlier invocation left in out_dir is never read as this one's.
    stamp = datetime.datetime.now(datetime.timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    run_dir = resolve_output(os.path.join(out_dir, "hunt-%s-%s" % (stamp, secrets.token_hex(3))), "out_dir")
    try:
        os.makedirs(out_dir, exist_ok=True)
        os.makedirs(run_dir, exist_ok=False)
    except OSError as exc:
        fail("the run directory cannot be made under out_dir: %s" % exc, out_dir=out_dir, status="failed")
    STATE["run_dir"] = run_dir
    result = resolve_output(os.path.join(run_dir, "%s.json" % engine), "out_dir")
    zircolite_log = resolve_output(os.path.join(run_dir, "zircolite.log"), "out_dir")

    if engine == "zircolite":
        # No --noexternal: Zircolite 3 removed it (it reads EVTX through its
        # Python bindings only) and refuses the flag; 2.x without it uses its
        # own bundled evtx_dump. --logfile: its log in the run directory, not in the
        # working directory (the run's, read-only in a VM and in a job).
        argv = [binary, "--evtx", path, "--outfile", result, "--logfile", zircolite_log]
        if rules_arg:
            argv += ["--ruleset", rules_arg]
        cwd = None
    else:
        # Hayabusa saves its error log under ./logs/ and no option moves it:
        # it runs in the run directory, so every path it is given is absolute, and a
        # link left there as logs is followed to where it lands first.
        resolve_output(os.path.join(run_dir, "logs"), "out_dir")
        argv = [binary, "json-timeline", "-d" if os.path.isdir(path) else "-f", os.path.abspath(path),
                "-o", os.path.abspath(result), "-w", "-q"]
        if rules_arg:
            argv += ["-r", os.path.abspath(rules_arg) if os.path.exists(rules_arg) else rules_arg]
        cwd = os.path.abspath(run_dir)
    HELD["command"] = " ".join(argv)

    # One clock over the whole run: the probes, the count of .evtx files, the digest of the ruleset, the engine, then the parse, the sort and the write,
    # for which POST_SECONDS are kept back. A phase the clock cuts ends the run partial, and says which.
    cut = []
    HELD["phase"] = "asking the engine for its version"
    version = engine_version(binary, max(0.0, min(30.0, left() - POST_SECONDS - 10)))
    HELD["phase"] = "counting the .evtx files"
    evtx_files, evtx_cut = count_evtx(path, time.monotonic() + max(0.0, min(30.0, left() - POST_SECONDS - 10)))
    if evtx_cut:
        cut.append("the count of .evtx files under the path was cut by the clock")
    HELD["phase"] = "recording the ruleset"
    ruleset = ruleset_record(rules_arg, time.monotonic() + max(0.0, min(60.0, left() - POST_SECONDS - 10)))
    if ruleset.get("cut_by_clock"):
        cut.append("the digest of the ruleset was cut by the clock")

    # The engine's own words, whole, beside its result: they used to be
    # dropped when it succeeded and cut to their last few hundred characters
    # when it did not. They are streamed to files, never held in memory.
    stdout_path = resolve_output(os.path.join(run_dir, "%s.stdout" % engine), "out_dir")
    stderr_path = resolve_output(os.path.join(run_dir, "%s.stderr" % engine), "out_dir")
    engine_seconds = min(timeout, int(left() - POST_SECONDS))
    if engine_seconds < 10:
        fail("the tool's own clock (%d s) left the engine no time to run: nothing was hunted" % DEADLINE_SECONDS, run_dir=run_dir, command=" ".join(argv))
    HELD["phase"] = "the engine is running"
    with open(stdout_path, "wb") as so, open(stderr_path, "wb") as se:
        try:
            proc = spawn(argv, stdout=so, stderr=se, cwd=cwd)
        except OSError as exc:
            fail("%s could not be started: %s" % (engine, exc), command=" ".join(argv), status="failed")
        rc, timed_out = wait_for(proc, engine_seconds)
    said = {"stdout": file_ref(stdout_path), "stderr": file_ref(stderr_path)}

    if not os.path.isfile(result):
        if timed_out:
            fail("%s did not finish in time" % engine, after_seconds=engine_seconds, command=" ".join(argv), run_dir=run_dir, **said,
                 engine_logs=engine_logs(engine, run_dir, zircolite_log))
        fail("%s wrote no result file" % engine, exit_code=rc, run_dir=run_dir,
             command=" ".join(argv), **said, engine_logs=engine_logs(engine, run_dir, zircolite_log),
             note="Engine command lines change between versions; the exact invocation is above "
                  "so it can be corrected by hand and re-run. Its whole stdout and stderr are "
                  "the files named here.")

    HELD["phase"] = "reading the engine's result"
    malformed = Malformed(os.path.join(run_dir, "%s-malformed.txt" % engine))
    floor = LEVEL_RANK[min_level]
    ordered = Sorted(run_dir)
    by_rule = {}
    read = below = 0
    unknown_levels = {}
    parse_cut = False
    try:
        values = json_values(result, malformed)
        rows = zircolite_rows(values, malformed) if engine == "zircolite" else hayabusa_rows(values, malformed)
        for row in rows:
            if not (read & 1023) and left() < PARSE_STOPS_AT:
                parse_cut = True
                break
            read += 1
            r = rank(row.get("level"))
            if r is None:
                key = "(no level)" if row.get("level") is None else str(row.get("level"))
                unknown_levels[key] = unknown_levels.get(key, 0) + 1
            elif r < floor:
                below += 1
                continue
            row["level_rank"] = r
            by_rule[row["rule"]] = by_rule.get(row["rule"], 0) + 1
            ordered.add(row, r)
    except OSError as exc:
        malformed.close()
        fail("%s wrote a result this tool could not read" % engine, result=result, reason=str(exc))
    malformed.close()

    HELD["phase"] = "sorting and writing the detections"
    detections_path = resolve_output(os.path.join(run_dir, "detections.jsonl"), "out_dir")
    shown, kept_count, write_cut = ordered.write(detections_path, limit, lambda: left() < WRITE_STOPS_AT)
    all_detections = file_ref(detections_path, rows=kept_count)
    fired = sorted(({"rule": r, "count": c} for r, c in by_rule.items()), key=lambda x: (-x["count"], str(x["rule"])))
    fired_file = None
    if len(fired) > limit:
        fired_path = resolve_output(os.path.join(run_dir, "rules-fired.jsonl"), "out_dir")
        with open(fired_path, "w", encoding="utf-8") as fh:
            for item in fired:
                fh.write(json.dumps(item) + "\n")
        fired_file = file_ref(fired_path, rows=len(fired))
    if parse_cut:
        cut.append("the tool's own clock ran out while the engine's result was read: %d detections were read, the rest were not" % read)
    if write_cut:
        cut.append("the tool's own clock ran out while the detections were sorted and written: detections.jsonl holds %d of them" % kept_count)

    reasons = []
    if timed_out:
        reasons.append("the engine was stopped by its time limit (%d s)" % engine_seconds)
    elif rc != 0:
        reasons.append("the engine exited with status %s" % rc)
    if malformed.count:
        reasons.append("%d line(s) of its result could not be read (malformed_file)" % malformed.count)
    if evtx_files == 0 and not evtx_cut:
        reasons.append("no .evtx file lies under the path, so no record was read")
    elif engine_says_none_read(stdout_path, stderr_path):
        reasons.append("the engine's own output says it read no .evtx file")
    if read == 0 and below == 0 and not malformed.count:
        # Nothing was read. An engine that found nothing writes an empty list; an empty file, a lone object or brackets with nothing in them is not that.
        try:
            with open(result, "rb") as rf:
                head = re.sub(rb"\s+", b"", rf.read(4096))
            size_read = os.path.getsize(result)
        except OSError:
            head, size_read = b"?", -1
        if head != b"[]":
            reasons.append("no detection was read from the engine's result file (%d bytes; it is empty, or not a list of detections): zero detections here is not a statement that no rule matched" % size_read)
    reasons += cut
    complete = not reasons
    answer = {
        "parser": PARSER,
        "status": "complete" if complete else "partial",
        "status_basis": "; ".join(reasons) if reasons else "the engine exited 0, its whole result was read and sorted, no line of it was unreadable, and %d .evtx file(s) lie under the path" % evtx_files,
        "complete": complete,
        "path": path,
        "evtx_files_under_path": evtx_files,
        "engine": engine,
        "engine_version": version,
        "ruleset": ruleset,
        "exit_code": rc,
        "timed_out": timed_out,
        "run_dir": run_dir,
        "command": " ".join(argv),
        "result_file": result,
        "detections": shown,
        "detection_count": kept_count,
        "returned": len(shown),
        "truncated": kept_count > limit,
        "all_detections": all_detections,
        "engine_detections_read": read,
        "below_min_level": below,
        "min_level": min_level,
        "unknown_levels": unknown_levels,
        "malformed_lines": malformed.count,
        "malformed_file": file_ref(malformed.path) if malformed.count else None,
        "rules_that_fired": fired[:limit],
        "rules_fired": len(by_rule),
        "rules_fired_file": fired_file,
        "engine_stdout": said["stdout"],
        "engine_stderr": said["stderr"],
        "engine_logs": engine_logs(engine, run_dir, zircolite_log),
        "note": "A rule firing is a hypothesis with a name, not a finding. Take its record id and "
                "channel to evtx_query, read the record, and cite the record. Community rulesets "
                "are tuned for live estates and produce false positives on a forensic image: an "
                "administrator doing their job trips a dozen of them. A detection whose level this tool does not "
                "know is kept and counted under unknown_levels, never dropped by min_level. "
                + ("" if complete else "The run is PARTIAL: see status_basis; the detections are what its result file held."),
    }
    print_answer(answer, indent=2)


if __name__ == "__main__":
    try:
        main()
    except SystemExit:
        raise
    except OSError as exc:
        fail("a file could not be read or written: %s" % exc, status="failed")
    except Exception as exc:                                  # whatever hostile input does, the answer is JSON
        drop_temps()
        print_answer({"error": "the hunt failed", "status": "failed", "status_basis": "the tool stopped with an unexpected error",
                      "run_dir": STATE["run_dir"], "reason": "%s: %s" % (type(exc).__name__, exc)})
        sys.exit(1)
