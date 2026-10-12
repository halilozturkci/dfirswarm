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
import json
import os
import shutil
import signal
import subprocess
import sys
import time
import re
from datetime import datetime, timezone
from pathlib import Path

TOOL = {"name": "timeline_super", "version": 4}
DEFAULT_TIMEOUT = 1800
TIMEOUT_MAX = 3300                # the manifest's own limit is 3600: the rest is for the version calls and the counting
TOOL_SECONDS = 3500               # the whole call, counting included, ends before the manifest's limit
SAMPLE_MAX = 1000
VERSION_TIMEOUT = 20
LINE_MAX = 8 * 1024 * 1024        # a line past this is counted invalid, its tail skipped; the file keeps it whole
MESSAGE_PREVIEW = 2000
INVALID_LISTED = 1000
ZONE = re.compile(r"^[A-Za-z0-9_+\-/]{1,64}$")
# BEGIN SHARED PROCESS
# The same shape as the network-forensics pack's engine tools. A program this tool runs is started in THIS tool's process
# group, never in a session of its own: the harness ends a tool that runs too long, or is aborted, by killing the tool's
# group (process.kill(-pid, SIGKILL)), and an engine in a group of its own goes on writing into the output directory after
# the tool is gone. On Linux the kernel is also asked to kill it if the tool dies. A deadline kills the program and what it
# started by walking the process tree, and SIGTERM, SIGINT and SIGHUP do the same and then give the tool a last word.
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


def emit(obj, code=0):
    print(json.dumps(obj, indent=2))
    raise SystemExit(code)


def fail(message, **extra):
    print(json.dumps({"error": message, "tool": TOOL, **extra}))
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
    dest = (root / out).resolve() if not Path(out).is_absolute() else Path(out).resolve()
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
    try:
        p = subprocess.run([program, "--version"], capture_output=True, text=True, timeout=VERSION_TIMEOUT, cwd=out_dir)
    except (subprocess.TimeoutExpired, OSError):
        return None
    text = ((p.stdout or "") + (p.stderr or "")).strip().splitlines()
    return text[0][:200] if text else None


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
    with open(output, "rb") as fh:
        number, offset = 0, 0
        while True:
            line = fh.readline(LINE_MAX + 1)
            if not line:
                break
            start = offset
            number += 1
            if number % 20000 == 0 and time.monotonic() > stop_at:
                stopped_at_line = number
                break
            if len(line) > LINE_MAX and not line.endswith(b"\n"):
                rest = 0
                while True:
                    chunk = fh.readline(LINE_MAX)
                    rest += len(chunk)
                    if not chunk or chunk.endswith(b"\n"):
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
    if bad:
        with open(invalid_path, "x", encoding="utf-8") as fh:
            fh.write("line\tbyte_offset\tbytes\treason\tfirst 200 bytes (the whole line stays in the output file)\n")
            for n, off, size, why, snippet in bad:
                fh.write("%d\t%d\t%d\t%s\t%s\n" % (n, off, size, why.replace("\t", " ").replace("\n", " "),
                                                   snippet.decode("utf-8", "replace").replace("\t", " ").replace("\n", " ")))
    return {"events": events, "invalid_lines": invalid, "oversized_lines": oversized, "events_without_a_time": untimed,
            "first_event": readable(earliest[1]) if earliest else None, "last_event": readable(latest[1]) if latest else None,
            "parsers_seen": parsers_seen, "head": head,
            "invalid_lines_file": invalid_path if bad else None,
            "invalid_lines_listed": len(bad), "invalid_lines_listing_complete": len(bad) == invalid,
            "stopped_at_line": stopped_at_line}


def main():
    try:
        args = json.load(sys.stdin)
    except ValueError as exc:
        fail("arguments are not valid JSON", reason=str(exc))
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
    install_signal_handlers()

    call_started = time.monotonic()
    began = time.time()
    deadline = time.monotonic() + timeout            # one budget for every stage
    preexisting = []
    if dest.exists():
        if not dest.is_dir():
            fail("out_dir is not a directory", out_dir=out_dir)
        preexisting = sorted(os.listdir(dest))
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

    clean = (not result["problems"] and result["export_exit"] == 0 and (mode == "export" or result["collect_exit"] == 0))
    if clean and output_ok:
        result["status"] = "complete"
    elif output_ok:
        result["status"] = "partial"
    else:
        result["status"] = "failed"
        result["error"] = result["problems"][0] if result["problems"] else "no timeline was produced"
    result["coverage_note"] = ("complete here means the programs exited 0, wrote their files and every output line parsed. It does not say every "
                               "parser read every source: read the storage file's processing report (Plaso's pinfo) before a negative rests on it. "
                               "A timestamp in this timeline is what a parser read, in UTC; it is a pointer to an artefact, which the artefact's own "
                               "skill then examines.")
    emit(result, 0 if result["status"] == "complete" else 1)


if __name__ == "__main__":
    main()
