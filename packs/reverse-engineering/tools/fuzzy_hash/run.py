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
TLSH_RX = re.compile(r"^(?:T\d+)?[0-9A-Fa-f]{70,140}$")
SSDEEP_RX = re.compile(r"^[0-9]+:[A-Za-z0-9+/]{1,64}:[A-Za-z0-9+/]{0,64}$")
DISTANCE_RX = re.compile(r"^[0-9]+$")
TLSH_SHORT = "the file is too short or has too little byte diversity for TLSH"


def describe(exc):
    code = errno.errorcode.get(exc.errno, "") if getattr(exc, "errno", None) else ""
    return "%s%s: %s" % (type(exc).__name__, " " + code if code else "", getattr(exc, "strerror", None) or str(exc))


def fail(message, **extra):
    print(json.dumps({"error": message, "status": extra.pop("status", "failed"), "tool": TOOL, **extra}))
    raise SystemExit(1)


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
        proc = subprocess.Popen(argv, stdin=subprocess.DEVNULL, stdout=handles["stdout"][0], stderr=handles["stderr"][0], start_new_session=True)
    except OSError as exc:
        result.update({"status": "launch_failed", "reason": "the program could not be started: %s" % describe(exc), "returncode": None,
                       "stdout": "", "stderr": "", "seconds": round(time.monotonic() - started, 3)})
        return result
    status = "ok"
    try:
        proc.wait(timeout=timeout)
    except subprocess.TimeoutExpired:
        status = "timeout"
        try:
            os.killpg(proc.pid, signal.SIGKILL)
        except (ProcessLookupError, PermissionError, OSError):
            pass
        try:
            proc.kill()
        except OSError:
            pass
        proc.wait()
    result["returncode"] = proc.returncode
    result["seconds"] = round(time.monotonic() - started, 3)
    text = {}
    for stream, (fh, start) in handles.items():
        end = os.fstat(fh.fileno()).st_size
        n = min(end - start, PARSE_BYTES if stream == "stdout" else 2048)
        text[stream] = os.pread(fh.fileno(), n, start).decode("utf-8", "replace") if n > 0 else ""
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


def parse_tlsh(run):
    """(digest or None, status, reason or None) for `tlsh -f FILE`."""
    if run["status"] != "ok":
        return None, run["status"], run["reason"]
    if run["stdout_bytes"] > PARSE_BYTES:
        return None, "unrecognised_output", "the program printed %d bytes where a digest line was expected" % run["stdout_bytes"]
    line = first_line(run["stdout"])
    token = line.split("\t", 1)[0].strip() if line else ""
    if token == "TNULL":
        return None, "insufficient_input", TLSH_SHORT
    if TLSH_RX.match(token):
        return token, "ok", None
    return None, "unrecognised_output", "the program printed %r where a TLSH digest was expected" % line[:200]


def parse_ssdeep(run):
    if run["status"] != "ok":
        return None, run["status"], run["reason"]
    if run["stdout_bytes"] > PARSE_BYTES:
        return None, "unrecognised_output", "the program printed %d bytes where a digest line was expected" % run["stdout_bytes"]
    rows = [l.strip() for l in run["stdout"].splitlines() if l.strip() and not l.startswith("ssdeep,")]
    if not rows:
        return None, "unrecognised_output", "the program printed no digest line"
    token = rows[-1].split(",", 1)[0]
    if SSDEEP_RX.match(token):
        return token, "ok", None
    return None, "unrecognised_output", "the program printed %r where an ssdeep digest was expected" % rows[-1][:200]


class Run:
    def __init__(self, logs, engine_timeout):
        self.logs = logs
        self.engine_timeout = engine_timeout
        self.deadline = time.monotonic() + TOTAL_BUDGET
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
    for engine, argv, parse in (("ssdeep", ["ssdeep", "-b", "--", path], parse_ssdeep), ("tlsh", ["tlsh", "-f", path], parse_tlsh)):
        run = runner.call(argv, "%s %s" % (label, engine))
        digest, status, reason = parse(run)
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
        if not os.path.isfile(path):
            fail("no such file", path=path)
    timeout = args.get("engine_timeout_seconds", DEFAULT_ENGINE_TIMEOUT)
    if isinstance(timeout, bool) or not isinstance(timeout, int) or not 1 <= timeout <= 600:
        fail("engine_timeout_seconds must be an integer from 1 to 600")
    if not shutil_which("ssdeep"):
        fail("ssdeep is not installed; this image cannot produce the declared fuzzy hash")
    if not shutil_which("tlsh"):
        fail("tlsh is not installed; this image cannot produce the declared TLSH result")

    logs = Logs([os.path.realpath(p) for p in paths])
    runner = Run(logs, timeout)
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
