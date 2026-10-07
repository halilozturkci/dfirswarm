#!/usr/bin/env python3
"""Lossless Linux triage through dissect.target, one function at a time, with a status for each.

Each artefact family is written to its own complete file (JSON Lines, or text for the identity family),
every selected dissect.target function appended to it in turn, and its stderr kept whole in a file of its
own. Stdout is a small manifest: for each function the exit code, the records it produced, the lines that
were not JSON, its time, and a status; for each file its size, hash and line count.

The status is what was observed, never a promise about the evidence:

    parsed         the function exited 0 and produced records (every line JSON)
    empty          it exited 0, produced nothing and wrote nothing to stderr
    unsupported    it exited 0, produced nothing, and a line of its stderr naming this function says it is not
                   available for this target (the patterns are in UNSUPPORTED_STDERR; which messages
                   dissect.target writes for which causes is not validated here, so a message that does not
                   name the function, or does not match, leaves it `unknown`)
    failed         a non-zero exit, or it ran past its deadline
    not_attempted  the time left in the total deadline was less than this function's own timeout, so it was not started
    unknown        it exited 0 and the output or the stderr cannot be read as one of the above (a line that is
                   not JSON, a stderr that names no cause for an empty result, or a traceback beside records):
                   read the files

`execution_complete` says that every function was started and exited 0 within its deadline. It is not
artefact coverage: an exit code does not say which artefacts the target had, which of them the function reads,
or whether it read them. Coverage is the counts of statuses, and even `parsed` means only that the function
produced records. A family's name is not what it covers: each family says its functions and what they do not
cover. Empty output is a parser's result, not proof that the artefact is absent.

Time. Each function runs for at most `timeout_seconds`, and all of them within `total_timeout_seconds`
(default 13800, under the manifest's 14400): a function is started only if the time left covers its own
timeout, so a function that is cut off by the total deadline never exists; what was not started is marked
`not_attempted`, and `summary.json` in the output directory is rewritten after every function, so a run that
is killed from outside still leaves what it had done.

Every answer carries `status` (complete, partial or failed) and `status_basis`, the same pair the recipes'
coverage.json carries. `complete` says every selected function ran and produced records or nothing; it is not
coverage of the host.
"""
import hashlib
import json
import os
import re
import shutil
import signal
import subprocess
import sys
import time
from pathlib import Path

TOOL = "linux_triage"
PARSER = "linux_triage/3"
DEFAULT_FUNCTION_SECONDS = 1800
DEFAULT_TOTAL_SECONDS = 13800
SUMMARY_NAME = "summary.json"
FIRST_FAILURES = 20

# family -> its dissect.target functions, what it covers and what it does not
GROUPS = {
    "identity": {"functions": ["os", "hostname", "version", "ips"], "strings": True,
                 "covers": "the OS name, hostname, version and IP addresses as dissect.target reports them, as text",
                 "does_not_cover": "the timezone, the machine id, the install date or the installed packages"},
    "users": {"functions": ["users"],
              "covers": "the accounts dissect.target's users function reports",
              "does_not_cover": "shadow verifiers, group membership, sudoers, SSH policy or accounts of a central identity source"},
    "sessions": {"functions": ["wtmp", "btmp", "lastlog"],
                 "covers": "classic wtmp, btmp and lastlog records",
                 "does_not_cover": "wtmpdb or lastlog2 (SQLite) databases, utmp, audit login records or the journal"},
    "authentication": {"functions": ["authlog"],
                       "covers": "auth.log or secure lines as dissect.target's authlog function parses them",
                       "does_not_cover": "the journal, the audit log, or a log kept under another name or place"},
    "history": {"functions": ["bashhistory"],
                "covers": "bash history files only",
                "does_not_cover": "zsh, fish or client histories, a custom HISTFILE, or what a shell did not save"},
    "persistence": {"functions": ["cronjobs", "services"],
                    "covers": "cron jobs and services as the two functions report them",
                    "does_not_cover": "per-user systemd units, drop-ins, enablement, at jobs or the other persistence mechanisms"},
    "packages": {"functions": ["dpkg.status", "packagemanager.logs"],
                 "covers": "the Debian-family package status file and package-manager logs",
                 "does_not_cover": "an RPM database or any package verification"},
    "ssh": {"functions": ["ssh.authorized_keys", "ssh.known_hosts", "ssh.public_keys"],
            "covers": "authorized_keys, known_hosts and public keys as the functions read them",
            "does_not_cover": "sshd_config, certificates' authorities or private keys"},
    "logs": {"functions": ["journal", "syslog"],
             "covers": "the journal and syslog as the two functions parse them",
             "does_not_cover": "the audit log, application logs, or entries the journal reader does not decode"},
    "web": {"functions": ["webserver.logs"],
            "covers": "access and error logs of the web servers dissect.target knows",
            "does_not_cover": "a proxy, application or database log, or a server it does not recognise"},
    "containers": {"functions": ["container.logs"],
                   "covers": "container logs only",
                   "does_not_cover": "container configuration, layers, volumes, environment or runtime state"},
}
UNSUPPORTED_STDERR = re.compile(
    r"(unsupported|not\s+(?:available|supported|applicable|implemented)|no\s+such\s+(?:function|plugin)|"
    r"unknown\s+(?:function|plugin)|unrecogni[sz]ed\s+(?:function|plugin)|failed\s+to\s+find\s+(?:function|plugin))", re.I)


def names_function(function):
    """A pattern that finds this function's own name in a line: the whole dotted name, as a word. `os` is not found inside
    `hostos` or `os.hostname`, and `ips` is not found inside `ships`."""
    return re.compile(r"(?<![\w.])" + re.escape(function) + r"(?!\w|\.\w)")

def fail(message, **extra):
    print(json.dumps({"error": message, "status": "failed", "status_basis": "the tool stopped with an error (see error)", **extra}))
    raise SystemExit(1)


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
    job_out = os.environ.get("OUT") or ""
    if os.environ.get("JOB_ID") and job_out:
        # In a job work/ is read-only and only $OUT is writable: a directory made anywhere else cannot be made.
        place = Path(job_out).resolve()
        if dest == place or place not in dest.parents:
            fail("in a job %s must be a new directory under work/<your agent id>/, which the job maps to its output directory: "
                 "%s is not under it" % (what, out), **{what: str(out)})
    return str(dest.relative_to(root))


def digest(path):
    value = hashlib.sha256()
    with path.open("rb") as fh:
        while chunk := fh.read(1024 * 1024):
            value.update(chunk)
    return value.hexdigest()


def count_region(path, start, end, as_json):
    """(records, invalid lines, first invalid line numbers) of one function's bytes in its family's file."""
    records = invalid = 0
    first = []
    line_no = 0
    with path.open("rb") as fh:
        fh.seek(start)
        remaining = end - start
        for raw in fh:
            remaining -= len(raw)
            if raw.strip():
                line_no += 1
                if as_json:
                    try:
                        json.loads(raw)
                        records += 1
                    except ValueError:
                        invalid += 1
                        if len(first) < FIRST_FAILURES:
                            first.append(line_no)
                else:
                    records += 1
            if remaining <= 0:
                break
    return records, invalid, first


def scan_stderr(path, function):
    """What a function's stderr says, read in pieces: whether it wrote anything, whether a line names this function and says
    it is not available, whether any line says the plugin or function is unavailable without naming one, and whether a
    traceback is in it. Only a sample of it is kept in memory."""
    seen = {"bytes": 0, "text": False, "unsupported_named": False, "unsupported_unattributed": False, "traceback": False, "sample": ""}
    named = names_function(function)
    with path.open("rb") as fh:
        while True:
            piece = fh.readline(1 << 16)
            if not piece:
                break
            seen["bytes"] += len(piece)
            line = piece.decode("utf-8", "replace")
            if line.strip():
                seen["text"] = True
            if len(seen["sample"]) < 4096:
                seen["sample"] += line[: 4096 - len(seen["sample"])]
            if "Traceback (most recent call last)" in line:
                seen["traceback"] = True
            if UNSUPPORTED_STDERR.search(line):
                if named.search(line):
                    seen["unsupported_named"] = True
                else:
                    seen["unsupported_unattributed"] = True
    return seen


def classify(exit_code, timed_out, records, invalid, scan):
    if timed_out or exit_code != 0:
        return "failed"
    if invalid:
        return "unknown"
    if records == 0 and scan["unsupported_named"]:
        return "unsupported"
    if records > 0:
        return "unknown" if scan["traceback"] else "parsed"
    return "unknown" if scan["text"] else "empty"


def group_status(functions):
    statuses = [f["status"] for f in functions]
    if all(s == "not_attempted" for s in statuses):
        return "not_attempted"
    if "failed" in statuses:
        return "failed"
    if all(s == "unsupported" for s in statuses):
        return "unsupported"
    if "unsupported" in statuses:
        return "partial_unsupported"
    if "not_attempted" in statuses or "pending" in statuses or "running" in statuses:
        return "partial_not_attempted"
    if any(f.get("records", 0) > 0 for f in functions):
        return "produced_records"
    return "unknown" if "unknown" in statuses else "empty"


def coverage_of(groups):
    counts = {"parsed": 0, "empty": 0, "unsupported": 0, "failed": 0, "not_attempted": 0, "unknown": 0}
    for g in groups:
        for f in g["functions"]:
            if f["status"] in counts:
                counts[f["status"]] += 1
    counts["note"] = ("These count the selected functions by what each produced. Artefact coverage of the host is not established by "
                      "this tool: `parsed` means a function produced records, `empty` that it produced none and wrote nothing, and "
                      "neither says which artefacts the target had or which of them the function reads.")
    return counts


def status_of(groups, finished):
    """(status, basis) for the run: complete only if the run ended and every selected function ran and produced records or
    nothing; failed if no function ran to an exit (all failed or none started); partial otherwise."""
    counts = {}
    for g in groups:
        for f in g["functions"]:
            counts[f["status"]] = counts.get(f["status"], 0) + 1
    total = sum(counts.values())
    ran = total - counts.get("failed", 0) - counts.get("not_attempted", 0) - counts.get("pending", 0) - counts.get("running", 0)
    if not finished:
        return "partial", "the run has not ended: %d of %d selected functions have an outcome" % (total - counts.get("pending", 0) - counts.get("running", 0), total)
    if ran == 0:
        return "failed", "no selected function ran to an exit: %d failed, %d not attempted" % (counts.get("failed", 0), counts.get("not_attempted", 0))
    clean = all(counts.get(k, 0) == 0 for k in ("unsupported", "failed", "not_attempted", "unknown", "pending", "running"))
    if clean:
        return "complete", "every one of the %d selected functions ran to exit 0 and produced records or nothing: this is not coverage of the host" % total
    parts = ["%d %s" % (counts[k], k) for k in ("unsupported", "failed", "not_attempted", "unknown") if counts.get(k)]
    return "partial", "%d of %d selected functions ran; %s: the files and the per-function statuses say which" % (ran, total, ", ".join(parts))


def write_summary(out, state):
    tmp = out / ".summary.json.tmp"
    try:
        tmp.write_text(json.dumps(state, indent=2) + "\n")
        os.replace(tmp, out / SUMMARY_NAME)
    except OSError as exc:
        fail("the summary could not be written: %s" % (exc.strerror or exc), out_dir=str(out))


CURRENT = {"proc": None, "entry": None, "out": None, "state": None}


def on_term(signum, _frame):
    """Told to stop from outside: end the function that is running, say so in the summary, and leave."""
    proc, entry = CURRENT["proc"], CURRENT["entry"]
    if proc is not None and proc.poll() is None:
        for sig in (signal.SIGTERM, signal.SIGKILL):
            try:
                os.killpg(proc.pid, sig)
            except (OSError, ProcessLookupError):
                pass
            try:
                proc.wait(timeout=3)
                break
            except subprocess.TimeoutExpired:
                continue
    if entry is not None and entry.get("status") == "running":
        entry.update({"status": "failed", "exit_code": 128 + signum, "timed_out": False, "reason": "this process was told to stop (signal %d) while the function ran" % signum})
    if CURRENT["state"] is not None:
        state = CURRENT["state"]("terminated")
        write_summary(CURRENT["out"], state)
    raise SystemExit(128 + signum)


def main():
    try:
        args = json.load(sys.stdin)
    except ValueError as exc:
        fail("arguments are not valid JSON", reason=str(exc))
    if not isinstance(args, dict):
        fail("arguments must be a JSON object")
    source = args.get("source")
    out_arg = args.get("out_dir")
    if not isinstance(source, str) or not source or not os.path.exists(source):
        fail("source is required and must exist", source=source)
    if not isinstance(out_arg, str) or not out_arg:
        fail("out_dir is required")
    out = Path(resolve_output(out_arg, "out_dir"))
    if out.exists():
        fail("out_dir already exists; refusing to overwrite an earlier result", out_dir=str(out))
    binary = shutil.which("target-query")
    if not binary:
        fail("target-query is not on PATH", install="the computer-forensics-base image requirement 'dissect'")
    if "groups" in args and args["groups"] is not None:
        selected = args["groups"]
        if not isinstance(selected, list):
            fail("groups must be a list of family names, or omitted to run every family", known=list(GROUPS))
        if not selected:
            fail("groups is empty: omit it to run every family, or name the families to run", known=list(GROUPS))
        unknown = [g for g in selected if not isinstance(g, str) or g not in GROUPS]
        if unknown:
            fail("groups must name known families", unknown=[str(u) for u in unknown], known=list(GROUPS))
        repeated = sorted({g for g in selected if selected.count(g) > 1})
        if repeated:
            fail("groups names a family more than once, which would write its file twice", repeated=repeated)
    else:
        selected = list(GROUPS)
    per_function = args.get("timeout_seconds", DEFAULT_FUNCTION_SECONDS)
    total = args.get("total_timeout_seconds", DEFAULT_TOTAL_SECONDS)
    for name, value in (("timeout_seconds", per_function), ("total_timeout_seconds", total)):
        if not isinstance(value, int) or isinstance(value, bool) or value < 1:
            fail("%s must be a positive integer" % name)

    try:
        out.mkdir(parents=True)
    except OSError as exc:
        fail("out_dir could not be created: %s" % (exc.strerror or exc), out_dir=str(out))
    started_at = time.time()
    deadline = time.monotonic() + total
    groups = [{"group": g, "functions": [{"name": f, "status": "pending"} for f in GROUPS[g]["functions"]],
               "covers": GROUPS[g]["covers"], "does_not_cover": GROUPS[g]["does_not_cover"], "status": "pending"} for g in selected]

    def state(kind):
        status, basis = status_of(groups, kind == "finished")
        return {"state": kind, "status": status, "status_basis": basis, "parser": PARSER, "source": source, "out_dir": str(out),
                "started": started_at, "updated": time.time(), "total_timeout_seconds": total, "timeout_seconds": per_function,
                "groups": groups, "coverage": coverage_of(groups)}

    CURRENT["out"], CURRENT["state"] = out, state
    signal.signal(signal.SIGTERM, on_term)
    write_summary(out, state("running"))
    stop = False
    for group in groups:
        spec = GROUPS[group["group"]]
        result_path = out / (group["group"] + (".txt" if spec.get("strings") else ".jsonl"))
        group["file"] = str(result_path)
        try:
            stdout = result_path.open("wb")
        except OSError as exc:
            fail("a result file could not be created: %s (%s)" % (result_path, exc.strerror or exc), out_dir=str(out))
        with stdout:
            for entry in group["functions"]:
                name = entry["name"]
                remaining = deadline - time.monotonic()
                if stop or remaining < per_function:
                    entry.update({"status": "not_attempted", "reason": "%.0f s of the total deadline (%d s) were left, less than this function's own timeout (%d s): it was not started" % (max(remaining, 0), total, per_function)})
                    stop = True
                    write_summary(out, state("running"))
                    continue
                entry["status"] = "running"
                write_summary(out, state("running"))
                limit = per_function
                err_path = out / ("%s.%s.stderr" % (group["group"], re.sub(r"[^A-Za-z0-9_.-]", "_", name)))
                argv = [binary, "--no-cache", "-f", name] + (["-s"] if spec.get("strings") else ["-j"]) + [source]
                begin = stdout.tell()
                began = time.monotonic()
                timed_out = False
                with err_path.open("wb") as stderr:
                    proc = subprocess.Popen(argv, stdout=stdout, stderr=stderr, start_new_session=True)
                    CURRENT["proc"], CURRENT["entry"] = proc, entry
                    try:
                        code = proc.wait(timeout=limit)
                    except subprocess.TimeoutExpired:
                        timed_out, code = True, 124
                        try:
                            os.killpg(proc.pid, signal.SIGKILL)
                        except (OSError, ProcessLookupError):
                            proc.kill()
                        proc.wait()
                    CURRENT["proc"] = None
                stdout.flush()
                end = stdout.tell()
                # A function that stopped in the middle of a line leaves it unterminated; the line is ended so that the next
                # function's first record is not glued to it, and the entry says so (the byte count is the function's own).
                unterminated = False
                if end > begin:
                    with result_path.open("rb") as fh:
                        fh.seek(end - 1)
                        unterminated = fh.read(1) != b"\n"
                    if unterminated:
                        stdout.write(b"\n")
                        stdout.flush()
                scan = scan_stderr(err_path, name)
                records, invalid, first_bad = count_region(result_path, begin, end, not spec.get("strings"))
                entry.update({"exit_code": code, "timed_out": timed_out, "seconds": round(time.monotonic() - began, 3),
                              "bytes": end - begin, "byte_offset": begin, "records": records, "invalid_lines": invalid,
                              "argv": argv[1:]})
                if unterminated:
                    entry["last_line_unterminated"] = True
                if timed_out:
                    entry["deadline"] = "function"
                if first_bad:
                    entry["first_invalid_line_numbers"] = first_bad      # lines of this function's own output
                if scan["unsupported_unattributed"] and not scan["unsupported_named"]:
                    entry["stderr_says_unavailable_without_naming_this_function"] = True
                if err_path.stat().st_size:
                    entry.update({"stderr": str(err_path), "stderr_bytes": err_path.stat().st_size, "stderr_sha256": digest(err_path)})
                else:
                    err_path.unlink()
                entry["status"] = classify(code, timed_out, records, invalid, scan)
                if scan["traceback"]:
                    entry["stderr_has_a_traceback"] = True
                write_summary(out, state("running"))
        group["status"] = group_status(group["functions"])
        if result_path.exists():
            group.update({"bytes": result_path.stat().st_size, "sha256": digest(result_path)})
            with result_path.open("rb") as fh:
                group["lines"] = sum(1 for _ in fh)
    final = state("finished")
    final["execution_complete"] = all(f.get("exit_code") == 0 and not f.get("timed_out") and f["status"] != "not_attempted"
                                      for g in groups for f in g["functions"])
    final["source"], final["note"] = source, (
        "Every byte a function wrote is in its family's file, and its stderr is in its own file. execution_complete says every function was "
        "started and exited 0 within its deadline: it is not artefact coverage (see coverage). Empty output is a parser's result, not proof "
        "that the artefact is absent; read the paired stderr and confirm the source scope before recording an absence. dissect.target is "
        "run on the source as given; whether an extracted root is read as well as an image is shown by the statuses, not assumed.")
    write_summary(out, final)
    print(json.dumps(final, indent=2))


if __name__ == "__main__":
    main()
