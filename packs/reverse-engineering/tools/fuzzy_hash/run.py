#!/usr/bin/env python3
"""SHA-256 and fuzzy hashes of one file, or a comparison of two, for static sample clustering.

SHA-256 is computed here, from the bytes, and establishes identity. ssdeep and TLSH are computed by the
installed programs and measure byte similarity only; they are leads, not attribution, and a score between
two files is a statement about their bytes.

Each engine runs on its own, under a time limit, with its whole output kept in a log file under the tool-output
directory (in a job, under $OUT) and none of it held in memory. A digest is accepted only when it has the shape
of that engine's digest: any other text is a diagnostic, never a digest. An engine that times out, fails, or
prints something unrecognised is a structured per-engine result and the answer is partial; the other engine's
result stands. A comparison that cannot be made names the input that prevented it. What each program printed for its
version command is recorded as printed.
"""
import errno
import hashlib
import json
import os
import re
import signal
import stat
import subprocess
import sys
import time
from pathlib import Path

TOOL = {"name": "fuzzy_hash", "version": 2}
PARSER = "fuzzy_hash/2"
DEFAULT_ENGINE_TIMEOUT = 120
TOTAL_BUDGET = 270                       # seconds for the whole call: the manifest's own limit is 300
VERSION_TIMEOUT = 10
PARSE_BYTES = 1 << 16                    # how much of an engine's stdout is read back for parsing
# TLSH's encodings have fixed lengths: a one- or three-byte checksum, a length byte, a quantile byte and 32 (128 buckets) or 64
# (256 buckets) bytes of body, as 70, 74, 134 or 138 hexadecimal digits, after an optional version prefix.
TLSH_RX = re.compile(r"^(?:T1)?(?:[0-9A-F]{70}|[0-9A-F]{74}|[0-9A-F]{134}|[0-9A-F]{138})$")
SSDEEP_RX = re.compile(r"^[0-9]+:[A-Za-z0-9+/]{1,64}:[A-Za-z0-9+/]{0,64}$")
SSDEEP_EMPTY_RX = re.compile(r"^[0-9]+::$")      # what ssdeep prints for an input too small to hash
DISTANCE_RX = re.compile(r"^[0-9]+$")
TLSH_SHORT = "the file is too short or has too little byte diversity for TLSH"


def describe(exc):
    code = errno.errorcode.get(exc.errno, "") if getattr(exc, "errno", None) else ""
    return "%s%s: %s" % (type(exc).__name__, " " + code if code else "", getattr(exc, "strerror", None) or str(exc))


def fail(message, **extra):
    print(json.dumps({"error": message, "status": extra.pop("status", "failed"), "tool": TOOL, **extra}))
    raise SystemExit(1)


# BEGIN SHARED PROCESS
# The same text is in pcap_extract, zeek_run, suricata_run and the network-capture recipe; tests/pack-network-process.test.ts
# holds the copies equal. A program an engine tool runs is started in THIS tool's process group, never in a session of
# its own: the harness ends a tool that runs too long, or is aborted, by killing the tool's group (process.kill(-pid,
# SIGKILL)), and an engine in a group of its own goes on writing into the output directory after the tool is gone. On
# Linux the kernel is also asked to kill it if the tool dies. A deadline kills the program and what it started by
# walking the process tree, and SIGTERM, SIGINT and SIGHUP do the same and then give the tool a last word.
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


def preflight(argv, seconds):
    """Run a short program, bounded; (exit code or None, stdout bytes, stderr bytes, timed out)."""
    try:
        proc = spawn(argv, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    except OSError as exc:
        return None, b"", describe(exc).encode("utf-8", "replace"), False
    ACTIVE.append(proc)
    try:
        out, err = proc.communicate(timeout=max(1.0, seconds))
        return proc.returncode, out, err, False
    except subprocess.TimeoutExpired:
        kill_tree(proc)
        out, err = proc.communicate()
        return None, out, err, True
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


def file_problem(path):
    """Why `path` is not a file this tool can read, in words that fit: a missing file, a directory, a pipe, a loop."""
    try:
        mode = os.stat(path).st_mode
    except FileNotFoundError:
        return "no such file"
    except OSError as exc:
        return "the file could not be examined: %s" % describe(exc)
    if stat.S_ISREG(mode):
        return None
    kinds = ((stat.S_ISDIR, "a directory"), (stat.S_ISFIFO, "a named pipe"), (stat.S_ISSOCK, "a socket"), (stat.S_ISBLK, "a block device"),
             (stat.S_ISCHR, "a character device"))
    return "not a regular file (%s)" % next((n for t, n in kinds if t(mode)), "a special file")


def shutil_which(name):
    for directory in os.environ.get("PATH", "").split(os.pathsep):
        candidate = os.path.join(directory, name)
        if os.path.isfile(candidate) and os.access(candidate, os.X_OK):
            return candidate
    return None


def sha256_of(path):
    digest = hashlib.sha256()
    size = 0
    with open(path, "rb") as fh:
        while True:
            block = fh.read(1 << 20)
            if not block:
                break
            size += len(block)
            digest.update(block)
    return digest.hexdigest(), size


class Logs:
    """Two files, one for every engine's standard output and one for its standard error, each invocation preceded by
    a header line. The child writes straight into them (appending), so what it prints is never held here."""

    def __init__(self, key):
        out = os.environ.get("OUT")
        if out:
            self.dir = Path(out) / "tool-output"
        else:
            agent = re.sub(r"[^A-Za-z0-9_.-]", "_", os.environ.get("AGENT_ID") or "tool")
            self.dir = Path("work") / agent / "tool-output"
        digest = hashlib.sha256(json.dumps(key).encode("utf-8", "surrogatepass")).hexdigest()[:12]
        self.names = {}
        self.fhs = {}
        self.error = None
        try:
            self.dir.mkdir(parents=True, exist_ok=True)
            for stream in ("stdout", "stderr"):
                self.fhs[stream], self.names[stream] = self._create("fuzzy-hash-%s.%s.log" % (digest, stream))
        except OSError as exc:
            self.error = "the engines' logs could not be created in %s (%s): their output is not kept" % (self.dir, describe(exc))
            for fh in self.fhs.values():
                fh.close()
            self.fhs, self.names = {}, {}

    def _create(self, name):
        stem, _dot, ext = name.rpartition(".")
        flags = os.O_RDWR | os.O_CREAT | os.O_EXCL | os.O_APPEND | getattr(os, "O_NOFOLLOW", 0)
        for n in range(1, 1000):
            candidate = name if n == 1 else "%s-%d.%s" % (stem, n, ext)
            try:
                fd = os.open(str(self.dir / candidate), flags, 0o644)
            except FileExistsError:
                continue
            return os.fdopen(fd, "ab", buffering=0), candidate
        raise OSError(errno.EEXIST, "a thousand files of this name already exist")

    @property
    def kept(self):
        return bool(self.fhs)


def run_engine(logs, argv, label, timeout):
    """Run one invocation. Returns a dict: status (ok, timeout, failed, launch_failed), returncode, stdout (the first
    64 KiB, as text), stderr (the first 2 KiB), bytes written to each stream, seconds."""
    import tempfile
    result = {"argv": argv, "label": label}
    started = time.monotonic()
    temps = []
    if logs.kept:
        handles = {}
        for stream, fh in logs.fhs.items():
            fh.write(("## %s: %s\n" % (label, " ".join(argv))).encode("utf-8", "replace"))
            handles[stream] = (fh, os.fstat(fh.fileno()).st_size)
    else:
        handles = {}
        for stream in ("stdout", "stderr"):
            fh = tempfile.TemporaryFile()
            temps.append(fh)
            handles[stream] = (fh, 0)
    try:
        proc = spawn(argv, stdout=handles["stdout"][0], stderr=handles["stderr"][0])
    except OSError as exc:
        result.update({"status": "launch_failed", "reason": "the program could not be started: %s" % describe(exc), "returncode": None,
                       "stdout": "", "stderr": "", "stdout_bytes": 0, "stderr_bytes": 0, "seconds": round(time.monotonic() - started, 3)})
        for fh in temps:
            fh.close()
        return result
    ACTIVE.append(proc)
    status = "ok"
    try:
        proc.wait(timeout=timeout)
    except subprocess.TimeoutExpired:
        status = "timeout"
        kill_tree(proc)
        proc.wait()
    finally:
        ACTIVE.remove(proc)
    result["returncode"] = proc.returncode
    result["seconds"] = round(time.monotonic() - started, 3)
    text = {}
    for stream, (fh, start) in handles.items():
        end = os.fstat(fh.fileno()).st_size
        n = min(end - start, PARSE_BYTES if stream == "stdout" else 2048)
        text[stream] = os.pread(fh.fileno(), n, start).decode("utf-8", "surrogateescape") if n > 0 else ""
        result[stream + "_bytes"] = max(0, end - start)
    for fh in temps:
        fh.close()
    result["stdout"], result["stderr"] = text["stdout"], text["stderr"]
    if status == "timeout":
        result["status"] = "timeout"
        result["reason"] = "the program was stopped at its time limit of %d second(s)" % timeout
    elif proc.returncode != 0:
        result["status"] = "failed"
        first = next((l.strip() for l in text["stderr"].splitlines() if l.strip()), "")
        result["reason"] = first or "the program exited %d" % proc.returncode
    else:
        result["status"] = "ok"
    return result


def first_line(text):
    return next((line.strip() for line in text.splitlines() if line.strip()), "")


def parse_tlsh(run, path):
    """(digest or None, status, reason or None) for `tlsh -f FILE`: one row, a digest and, when the row names a file, this file."""
    if run["status"] != "ok":
        return None, run["status"], run["reason"]
    if run["stdout_bytes"] > PARSE_BYTES:
        return None, "unrecognised_output", "the program printed %d bytes where a digest line was expected" % run["stdout_bytes"]
    rows = [l.strip() for l in run["stdout"].splitlines() if l.strip()]
    if len(rows) != 1:
        return None, "unrecognised_output", "the program printed %d rows where one was expected" % len(rows)
    token, _tab, name = rows[0].partition("\t")
    token = token.strip()
    if token == "TNULL":
        return None, "insufficient_input", TLSH_SHORT
    if not TLSH_RX.match(token):
        return None, "unrecognised_output", "the program printed %r where a TLSH digest was expected" % rows[0][:200]
    if name.strip() and name.strip() != path:
        return None, "unrecognised_output", "the row names another file than the one asked for (%r)" % name.strip()[:200]
    return token, "ok", None


def parse_ssdeep(run, path):
    """The same for `ssdeep -b -- FILE`: a header line, then one row `blocksize:hash:hash,"name"` whose name, when present, is this file's."""
    if run["status"] != "ok":
        return None, run["status"], run["reason"]
    if run["stdout_bytes"] > PARSE_BYTES:
        return None, "unrecognised_output", "the program printed %d bytes where a digest line was expected" % run["stdout_bytes"]
    rows = [l.strip() for l in run["stdout"].splitlines() if l.strip() and not l.startswith("ssdeep,")]
    if not rows:
        return None, "unrecognised_output", "the program printed no digest line"
    if len(rows) != 1:
        return None, "unrecognised_output", "the program printed %d rows where one was expected" % len(rows)
    token, _comma, name = rows[0].partition(",")
    name = name.strip().strip('"')
    if SSDEEP_EMPTY_RX.match(token):
        return None, "insufficient_input", "the input is too small for ssdeep to hash"
    if not SSDEEP_RX.match(token):
        return None, "unrecognised_output", "the program printed %r where an ssdeep digest was expected" % rows[0][:200]
    if name and name != os.path.basename(path):
        return None, "unrecognised_output", "the row names another file than the one asked for (%r)" % name[:200]
    return token, "ok", None


class Run:
    def __init__(self, logs, engine_timeout):
        self.logs = logs
        self.engine_timeout = engine_timeout
        self.deadline = time.monotonic() + TOTAL_BUDGET
        self.partial = []                # the file entries, filled as the engines answer, for the last word of a stopped call
        self.problems = []

    def call(self, argv, label, cap=None):
        remaining = self.deadline - time.monotonic()
        if remaining <= 0:
            return {"argv": argv, "label": label, "status": "not_attempted", "returncode": None, "stdout": "", "stderr": "", "stdout_bytes": 0,
                    "stderr_bytes": 0, "reason": "the call's time budget of %d seconds was spent before this engine ran" % TOTAL_BUDGET}
        timeout = max(1, min(cap or self.engine_timeout, self.engine_timeout, int(remaining)))
        run = run_engine(self.logs, argv, label, timeout)
        if run["status"] == "timeout":
            run["reason"] = "the program was stopped at its time limit of %d second%s" % (timeout, "" if timeout == 1 else "s")
        return run


def hash_one(runner, path, label):
    sha, size = sha256_of(path)
    entry = {"path": path, "bytes": size, "sha256": sha}
    runner.partial.append(entry)
    for engine, argv, parse in (("ssdeep", ["ssdeep", "-b", "--", path], parse_ssdeep), ("tlsh", ["tlsh", "-f", path], parse_tlsh)):
        run = runner.call(argv, "%s %s" % (label, engine))
        digest, status, reason = parse(run, path)
        entry[engine] = digest
        entry[engine + "_status"] = status
        entry[engine + "_unavailable"] = reason
        if status not in ("ok", "insufficient_input"):
            runner.problems.append("%s of %s: %s (%s)" % (engine, label, status, reason))
    return entry


def engine_info(runner, name, version_argv, package):
    info = {"program": shutil_which(name), "version_command": version_argv}
    run = runner.call(version_argv, name + " version", VERSION_TIMEOUT)
    line = first_line(run["stdout"]) or first_line(run["stderr"])
    if run["status"] == "ok" and line:
        info["version_command_output"] = line[:200]
    else:
        info["version_command_output"] = None
        info["version_note"] = "the version command %s produced no usable output (%s)" % (" ".join(version_argv), run.get("reason") or "no output")
    if shutil_which("dpkg-query"):
        pkg = runner.call(["dpkg-query", "-W", "-f=${Version}", package], name + " package version", VERSION_TIMEOUT)
        if pkg["status"] == "ok" and first_line(pkg["stdout"]):
            info["package"] = {"name": package, "version": first_line(pkg["stdout"])[:100]}
    return info


def main():
    try:
        args = json.load(sys.stdin)
    except ValueError as exc:
        fail("arguments are not valid JSON", reason=str(exc))
    if not isinstance(args, dict):
        fail("arguments must be a JSON object")
    paths = [args.get("path")]
    if args.get("compare_to") is not None:
        paths.append(args.get("compare_to"))
    for path in paths:
        if not isinstance(path, str) or not path:
            fail("path and compare_to must be non-empty strings when supplied")
        why_not = file_problem(path)
        if why_not:
            fail(why_not, path=path)
    timeout = args.get("engine_timeout_seconds", DEFAULT_ENGINE_TIMEOUT)
    if isinstance(timeout, bool) or not isinstance(timeout, int) or not 1 <= timeout <= 600:
        fail("engine_timeout_seconds must be an integer from 1 to 600")
    if not shutil_which("ssdeep"):
        fail("ssdeep is not installed; this image cannot produce the declared fuzzy hash")
    if not shutil_which("tlsh"):
        fail("tlsh is not installed; this image cannot produce the declared TLSH result")

    logs = Logs([os.path.realpath(p) for p in paths])
    runner = Run(logs, timeout)
    install_signal_handlers()

    def last_word(signum):
        # A stop signal ends the engines (the handler did that) and the tool says it was stopped, with what it had.
        print(json.dumps({"error": "stopped by signal %d before the engines finished" % signum, "status": "failed", "tool": TOOL,
                          "stopped_by_signal": signum, "files": runner.partial, "problems": runner.problems,
                          "logs": logs.names if logs.kept else None}))
        sys.stdout.flush()

    STATE["last_word"] = last_word
    if logs.error:
        runner.problems.append(logs.error)
    try:
        files = [hash_one(runner, path, "path" if i == 0 else "compare_to") for i, path in enumerate(paths)]
    except OSError as exc:
        fail("a file could not be read: %s" % describe(exc))
    comparison = None
    if len(files) == 2:
        distance, unavailable = None, None
        a, b = files[0]["tlsh"], files[1]["tlsh"]
        if a and b:
            run = runner.call(["tlsh", "-c", paths[0], "-f", paths[1]], "tlsh compare")
            line = first_line(run["stdout"])
            token = line.split(None, 1)[0] if line else ""
            if run["status"] != "ok":
                unavailable = {"input": "both", "reason": "tlsh comparison %s: %s" % (run["status"], run["reason"])}
            elif DISTANCE_RX.match(token):
                distance = int(token)
            else:
                unavailable = {"input": "both", "reason": "tlsh returned an unrecognised comparison line: %r" % line[:200]}
        else:
            missing = [k for k, d in (("path", a), ("compare_to", b)) if not d]
            reasons = {k: files[0 if k == "path" else 1]["tlsh_unavailable"] for k in missing}
            unavailable = {"input": "both" if len(missing) == 2 else missing[0],
                           "reason": "; ".join("%s: %s" % (k, reasons[k]) for k in missing) if len(missing) == 2 else reasons[missing[0]]}
        if unavailable and unavailable["reason"] and "unrecognised" in unavailable["reason"]:
            runner.problems.append("tlsh comparison: %s" % unavailable["reason"])
        elif unavailable and unavailable["reason"] and re.search(r"timeout|failed|launch_failed", unavailable["reason"]):
            runner.problems.append("tlsh comparison: %s" % unavailable["reason"])
        comparison = {
            "same_sha256": files[0]["sha256"] == files[1]["sha256"],
            "tlsh_distance": distance,
            "unavailable": unavailable,
            "note": "A smaller TLSH distance means more similar bytes; it is a lead, not attribution. A distance of its own proves nothing "
                    "about shared code: shared libraries, packaging and padding produce it too.",
        }
    engines = {
        "ssdeep": {**engine_info(runner, "ssdeep", ["ssdeep", "-V"], "ssdeep"), "argv_per_file": ["ssdeep", "-b", "--", "<file>"]},
        "tlsh": {**engine_info(runner, "tlsh", ["tlsh", "-version"], "tlsh-tools"), "argv_per_file": ["tlsh", "-f", "<file>"],
                 "argv_comparison": ["tlsh", "-c", "<path>", "-f", "<compare_to>"]},
    }
    result = {
        "tool": TOOL,
        "parser": PARSER,
        "files": files,
        "comparison": comparison,
        "engines": engines,
        "status": "partial" if runner.problems else "complete",
        "problems": runner.problems,
        "engine_timeout_seconds": timeout,
        "logs": {**logs.names, "format": "each invocation is preceded by a '## label: argv' line; the engine's whole output follows"} if logs.kept else None,
        "note": "SHA-256 establishes identity. ssdeep and TLSH measure byte similarity only; explain shared code or structure before assigning "
                "a family. 'insufficient_input' is an engine's own answer for a file that is too short or too uniform, not a failure.",
    }
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    try:
        main()
    except SystemExit:
        raise
    except Exception as exc:  # never a traceback and never a clean answer for a failure
        fail("unexpected failure: %s" % (describe(exc) if isinstance(exc, OSError) else "%s: %s" % (type(exc).__name__, exc)))
