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

PARSER = "sigma_hunt/6"
MAX_TIMEOUT = 1000


# BEGIN SHARED PROCESS
# The same text is in esedb_query, extract_stream, sigma_hunt, vss_stores and yara_scan; tests/pack-windows-forensics-process.test.ts
# holds the copies equal. A program a tool runs is started in THIS tool's process group, never in a session of its own: the
# harness ends a tool that runs too long, or is aborted, by killing the tool's group (process.kill(-pid, SIGKILL)), and a
# program in a group of its own goes on writing after the tool is gone. On Linux the kernel is also asked to kill it if the
# tool dies. The tool's own deadline kills the program and what it started by walking the process tree, and SIGTERM, SIGINT
# and SIGHUP do the same and then give the tool a last word.
try:
    import ctypes
except ImportError:  # pragma: no cover
    ctypes = None

STATE = {"last_word": None}    # what to do, with the signal number, when the tool is stopped by a signal
ACTIVE = []                    # the programs running now


def _die_with_parent():  # runs in the child between fork and exec
    try:
        ctypes.CDLL(None).prctl(1, signal.SIGKILL)   # PR_SET_PDEATHSIG
    except Exception:  # noqa: BLE001
        pass


def spawn(argv, **kwargs):
    kwargs.setdefault("stdin", subprocess.DEVNULL)
    if sys.platform.startswith("linux") and ctypes is not None:
        kwargs["preexec_fn"] = _die_with_parent
    return subprocess.Popen(argv, **kwargs)


def descendants(pid):
    """Every process below `pid`, from /proc where there is one, else from ps."""
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
            out = subprocess.run(["ps", "-A", "-o", "pid=,ppid="], capture_output=True, text=True, timeout=10).stdout
            for line in out.splitlines():
                parts = line.split()
                if len(parts) == 2 and parts[0].isdigit() and parts[1].isdigit():
                    kids.setdefault(int(parts[1]), []).append(int(parts[0]))
    except (OSError, subprocess.SubprocessError):
        return []
    found, stack = [], [pid]
    while stack:
        for child in kids.get(stack.pop(), []):
            found.append(child)
            stack.append(child)
    return found


def kill_tree(proc):
    """Kill the program and everything it started. The children are listed first: once the parent is gone they are
    adopted by init and can no longer be found below it."""
    victims = descendants(proc.pid)
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


def _on_signal(signum, _frame):
    for proc in list(ACTIVE):
        kill_tree(proc)
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
    print(json.dumps({"error": message, **extra}))
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
        level = rule.get("rule_level") or rule.get("level")
        for match in rule.get("matches") or []:
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
        yield {
            "rule": row.get("RuleTitle") or row.get("RuleFile") or "unnamed rule",
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
        line = key + "\t" + json.dumps(row, ensure_ascii=False, default=str)
        self.buffer.append(line)
        self.size += len(line)
        if self.size >= SORT_RUN_BYTES:
            self._spill()

    def _spill(self):
        self.buffer.sort()
        fd, name = tempfile.mkstemp(prefix=".sort-", dir=self.directory)
        with os.fdopen(fd, "w", encoding="utf-8", errors="surrogateescape") as fh:
            for line in self.buffer:
                fh.write(line + "\n")
        self.runs.append(name)
        self.buffer, self.size = [], 0

    def write(self, destination, keep):
        """Write the sorted rows to destination as JSON Lines; return the first `keep` of them and the count."""
        first, count = [], 0
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
                row_json = line.split("\t", 3)[3]
                out.write(row_json + "\n")
                if count < keep:
                    first.append(json.loads(row_json))
                count += 1
        for s in streams:
            s.close()
        for r in self.runs:
            os.unlink(r)
        return first, count


def ruleset_record(rules):
    """The ruleset the caller named, by digest: a file by its sha256, a directory by the digest of its
    sorted relative paths and file digests. Without one, the engine's own bundled rules are in use."""
    if not rules:
        return {"source": "the engine's bundled rules", "digest": None,
                "note": "no ruleset was named, so the rules in use are whatever the engine carries; their content is not recorded here"}
    p = Path(rules)
    if p.is_file():
        h = hashlib.sha256()
        with open(p, "rb") as fh:
            for chunk in iter(lambda: fh.read(1 << 20), b""):
                h.update(chunk)
        return {"source": str(rules), "kind": "file", "files": 1, "digest": h.hexdigest()}
    if p.is_dir():
        outer = hashlib.sha256()
        files = 0
        for root, dirs, names in os.walk(p):
            dirs.sort()
            for name in sorted(names):
                full = os.path.join(root, name)
                if os.path.islink(full) or not os.path.isfile(full):
                    continue
                h = hashlib.sha256()
                with open(full, "rb") as fh:
                    for chunk in iter(lambda: fh.read(1 << 20), b""):
                        h.update(chunk)
                outer.update(("%s\t%s\n" % (os.path.relpath(full, p), h.hexdigest())).encode("utf-8", "surrogateescape"))
                files += 1
        return {"source": str(rules), "kind": "directory", "files": files, "digest": outer.hexdigest(),
                "digest_of": "sorted relative paths with each regular file's sha256; links are not followed"}
    return {"source": str(rules), "digest": None, "note": "not a file or directory on this host; the engine may resolve it itself"}


def engine_version(binary):
    for flag in ("--version", "-V"):
        try:
            p = subprocess.run([binary, flag], stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=15, stdin=subprocess.DEVNULL)
        except (OSError, subprocess.TimeoutExpired):
            return None
        text = p.stdout.decode("utf-8", "replace").strip().splitlines()
        if p.returncode == 0 and text:
            return text[0].strip()
    return None


def main():
    install_signal_handlers()
    try:
        args = json.load(sys.stdin)
    except ValueError as exc:
        fail("arguments are not valid JSON", reason=str(exc))

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

    min_level = str(args.get("min_level") or "medium").lower()
    if min_level not in LEVELS:
        fail("min_level must be one of %s" % ", ".join(LEVELS), min_level=args.get("min_level"))
    limit = args.get("limit", 200)
    if not isinstance(limit, int) or isinstance(limit, bool) or limit < 1:
        fail("limit must be a positive integer")
    timeout = args.get("timeout_seconds", DEFAULT_TIMEOUT)
    if not isinstance(timeout, int) or isinstance(timeout, bool) or timeout < 10:
        fail("timeout_seconds must be an integer of at least 10")
    timeout = min(timeout, MAX_TIMEOUT)             # the tool's own limit is 1,200 s: the engine stops before it, and its result is read after

    wanted = str(args.get("engine") or "auto").lower()
    if wanted not in ("auto", "zircolite", "hayabusa"):
        fail("engine must be auto, zircolite or hayabusa", engine=args.get("engine"))

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
        if args.get("rules"):
            argv += ["--ruleset", str(args["rules"])]
        cwd = None
    else:
        # Hayabusa saves its error log under ./logs/ and no option moves it:
        # it runs in the run directory, so every path it is given is absolute, and a
        # link left there as logs is followed to where it lands first.
        resolve_output(os.path.join(run_dir, "logs"), "out_dir")
        argv = [binary, "json-timeline", "-d" if os.path.isdir(path) else "-f", os.path.abspath(path),
                "-o", os.path.abspath(result), "-w", "-q"]
        if args.get("rules"):
            rules = str(args["rules"])
            argv += ["-r", os.path.abspath(rules) if os.path.exists(rules) else rules]
        cwd = os.path.abspath(run_dir)

    version = engine_version(binary)
    ruleset = ruleset_record(args.get("rules"))

    # The engine's own words, whole, beside its result: they used to be
    # dropped when it succeeded and cut to their last few hundred characters
    # when it did not. They are streamed to files, never held in memory.
    stdout_path = resolve_output(os.path.join(run_dir, "%s.stdout" % engine), "out_dir")
    stderr_path = resolve_output(os.path.join(run_dir, "%s.stderr" % engine), "out_dir")
    def interrupted(signum):
        print(json.dumps({"error": "stopped by signal %d before %s finished" % (signum, engine), "status": "interrupted", "signal": signum,
                          "run_dir": run_dir, "command": " ".join(argv), "stdout_file": str(stdout_path), "stderr_file": str(stderr_path),
                          "note": "No statement about detections follows from an interrupted run."}), flush=True)

    STATE["last_word"] = interrupted
    with open(stdout_path, "wb") as so, open(stderr_path, "wb") as se:
        try:
            proc = spawn(argv, stdout=so, stderr=se, cwd=cwd)
        except OSError as exc:
            fail("%s could not be started: %s" % (engine, exc), command=" ".join(argv), status="failed")
        rc, timed_out = wait_for(proc, timeout)
    said = {"stdout": file_ref(stdout_path), "stderr": file_ref(stderr_path)}

    if not os.path.isfile(result):
        if timed_out:
            fail("%s did not finish in time" % engine, after_seconds=timeout, command=" ".join(argv), run_dir=run_dir, **said,
                 engine_logs=engine_logs(engine, run_dir, zircolite_log))
        fail("%s wrote no result file" % engine, exit_code=rc, run_dir=run_dir,
             command=" ".join(argv), **said, engine_logs=engine_logs(engine, run_dir, zircolite_log),
             note="Engine command lines change between versions; the exact invocation is above "
                  "so it can be corrected by hand and re-run. Its whole stdout and stderr are "
                  "the files named here.")

    malformed = Malformed(os.path.join(run_dir, "%s-malformed.txt" % engine))
    floor = LEVEL_RANK[min_level]
    ordered = Sorted(run_dir)
    by_rule = {}
    read = below = 0
    unknown_levels = {}
    try:
        values = json_values(result, malformed)
        rows = zircolite_rows(values, malformed) if engine == "zircolite" else hayabusa_rows(values, malformed)
        for row in rows:
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

    detections_path = resolve_output(os.path.join(run_dir, "detections.jsonl"), "out_dir")
    shown, kept_count = ordered.write(detections_path, limit)
    all_detections = file_ref(detections_path, rows=kept_count)
    complete = rc == 0 and not timed_out and malformed.count == 0
    answer = {
        "parser": PARSER,
        "status": "complete" if complete else "partial",
        "complete": complete,
        "path": path,
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
        "rules_that_fired": sorted(({"rule": r, "count": c} for r, c in by_rule.items()),
                                   key=lambda x: (-x["count"], str(x["rule"]))),
        "rules_fired": len(by_rule),
        "engine_stdout": said["stdout"],
        "engine_stderr": said["stderr"],
        "engine_logs": engine_logs(engine, run_dir, zircolite_log),
        "note": "A rule firing is a hypothesis with a name, not a finding. Take its record id and "
                "channel to evtx_query, read the record, and cite the record. Community rulesets "
                "are tuned for live estates and produce false positives on a forensic image: an "
                "administrator doing their job trips a dozen of them. A detection whose level this tool does not "
                "know is kept and counted under unknown_levels, never dropped by min_level. "
                + ("" if complete else "The run is PARTIAL: the engine exited with status %s%s%s; the detections are what its result file held."
                   % (rc, ", was stopped by its time limit" if timed_out else "", ", and %d line(s) of its result could not be read" % malformed.count if malformed.count else "")),
    }
    print(json.dumps(answer, indent=2))


if __name__ == "__main__":
    try:
        main()
    except OSError as exc:
        fail("a file could not be read or written: %s" % exc, status="failed")
