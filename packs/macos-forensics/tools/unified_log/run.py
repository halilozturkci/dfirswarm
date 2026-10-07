#!/usr/bin/env python3
"""Read Apple unified logs without hiding parser failures or dropping output.

Two readers, by platform. On macOS Apple's own `log show --archive` reads a
.logarchive. Elsewhere Mandiant's `unifiedlog_iterator` (declared in requires) reads a
.logarchive, or a copy of /private/var/db (diagnostics and uuidtext side by side),
which this tool stages as one archive first. Both keep every decoded entry as a
file in out_dir (nothing is cut: the answer's `entries` is only a preview).

What `status` means, and what it does not. `status` is about this run: the reader
exited cleanly, wrote its output, and every line of that output parsed as a JSON
record carrying the fields an entry has. It says nothing about whether the acquired
files were all decodable, whether uuidtext covered every message, whether timesync
covered the interval, or whether retention kept the period asked about: those are
`decoded_coverage` (counts of what was read) and `support_files` (an inventory of
what the input holds), and a skill judges them against the case. A reader exiting 0
with no output file is `failed`; an output with no entries is `empty`; malformed
lines or a reader that exits non-zero or overruns its time leave `partial` with what
was written kept; `complete` is none of those, and is still not a coverage claim.

The whole output is read once, in a stream, so counts cover the whole of it and only
the preview is held in memory.
"""
import hashlib
import json
import os
import platform
import shutil
import stat
import subprocess
import sys
from pathlib import Path

PARSER = "unified_log/3"
DEFAULT_TIMEOUT = 900
MAX_TIMEOUT = 1100            # the manifest's outer limit is 1200: leave time to count and answer
DEFAULT_MAX_STAGE_FILES = 1_000_000
DEFAULT_MAX_STAGE_BYTES = 16 << 30
KEEP = ["timestamp", "processImagePath", "process", "subsystem", "category",
        "senderImagePath", "eventMessage", "messageType", "processID", "threadID",
        "activityIdentifier", "eventType"]
# A record is an entry when it carries at least one of these (Apple's ndjson and Mandiant's JSONL
# name their fields differently); a JSON record with none is counted apart, not as an entry.
ENTRY_KEYS = {"timestamp", "time", "eventMessage", "message", "raw_message", "process", "subsystem"}
OUTPUT_NAMES = ("unifiedlogs.jsonl", "unifiedlogs.ndjson", "unifiedlog.stderr", ".logarchive-input")
FIRST = 10


def fail(message, **extra):
    print(json.dumps({"error": message, **extra}))
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
    return str(dest.relative_to(root))


def digest(path):
    value = hashlib.sha256()
    with open(path, "rb") as fh:
        for block in iter(lambda: fh.read(1 << 20), b""):
            value.update(block)
    return value.hexdigest()


def same_bytes(a, b):
    if os.path.getsize(a) != os.path.getsize(b):
        return False
    with open(a, "rb") as fa, open(b, "rb") as fb:
        while True:
            x, y = fa.read(1 << 20), fb.read(1 << 20)
            if x != y:
                return False
            if not x:
                return True


def walk_tree(root, rel_to, on_file):
    """Every entry under `root`, not followed through links: a link, a special file, or a directory or file
    that cannot be read is refused by name, and nothing is staged (a directory left out would be a silent gap)."""
    def unreadable(exc):
        fail("a directory in the tree to be staged could not be read, so nothing was staged: a tree with a part left out is not the evidence",
             directory=getattr(exc, "filename", None), reason="%s: %s" % (type(exc).__name__, exc))

    for dirpath, dirs, names in os.walk(root, followlinks=False, onerror=unreadable):
        dirs.sort()
        for name in sorted(dirs) + sorted(names):
            full = os.path.join(dirpath, name)
            rel = os.path.relpath(full, rel_to)
            try:
                st = os.lstat(full)
            except OSError as exc:
                fail("an entry in the tree to be staged could not be examined, so nothing was staged",
                     path=full, reason="%s: %s" % (type(exc).__name__, exc))
            if stat.S_ISLNK(st.st_mode):
                fail("a link in the tree to be staged: the reader would be handed a way out of it, so nothing was staged",
                     link=full, found_as=rel)
            if stat.S_ISDIR(st.st_mode):
                continue
            if not stat.S_ISREG(st.st_mode):
                fail("a file that is not a regular file in the tree to be staged; nothing was staged", file=full)
            on_file(full, rel, st.st_size)


def inventory(path, budget):
    """What the input holds, by name: a census, not a verdict on whether it is complete. A directory that
    cannot be read is counted and named, never left out silently."""
    census = {"tracev3_files": 0, "timesync_files": 0, "uuidtext_files": 0, "dsc_files": 0, "other_files": 0,
              "directories_unreadable": 0, "first_directories_unreadable": []}

    def unreadable(exc):
        census["directories_unreadable"] += 1
        if len(census["first_directories_unreadable"]) < FIRST:
            census["first_directories_unreadable"].append({"directory": getattr(exc, "filename", None),
                                                           "reason": "%s: %s" % (type(exc).__name__, exc)})

    seen = 0
    for dirpath, _dirs, names in os.walk(path, followlinks=False, onerror=unreadable):
        parts = os.path.relpath(dirpath, path).split(os.sep)
        for name in names:
            seen += 1
            if seen > budget:
                census["stopped_at_files"] = budget
                return census
            low = name.lower()
            if low.endswith(".tracev3"):
                census["tracev3_files"] += 1
            elif low.endswith(".timesync") or "timesync" in parts:
                census["timesync_files"] += 1
            elif "dsc" in parts:
                census["dsc_files"] += 1
            elif "uuidtext" in parts or (parts and len(parts[0]) == 2 and all(c in "0123456789ABCDEFabcdef" for c in parts[0])):
                census["uuidtext_files"] += 1
            else:
                census["other_files"] += 1
    return census


def stage(path, scratch, max_files, max_bytes):
    """Merge diagnostics and uuidtext into one archive under `scratch`: counted, bounded, refusing a link,
    a special file or a member that is in both trees with different bytes. Nothing is cut: over a bound it refuses."""
    diagnostics = os.path.join(path, "diagnostics")
    uuidtext = os.path.join(path, "uuidtext")
    for root in (diagnostics, uuidtext):
        if os.path.islink(root):
            fail("diagnostics or uuidtext is itself a link: the reader would be handed a way out of the tree, so nothing was staged", link=root)
    totals = {"files": 0, "bytes": 0}
    held = {}
    plan = []

    def take(tree):
        def on_file(full, rel, size):
            totals["files"] += 1
            totals["bytes"] += size
            if totals["files"] > max_files or totals["bytes"] > max_bytes:
                which = "max_stage_files" if totals["files"] > max_files else "max_stage_bytes"
                fail("staging this tree would pass %s (%d): nothing was staged and the reader did not run; raise it or point the tool at "
                     "a .logarchive" % (which, max_files if which == "max_stage_files" else max_bytes),
                     files=totals["files"], bytes=totals["bytes"], max_stage_files=max_files, max_stage_bytes=max_bytes)
            plan.append((tree, full, rel))
        return on_file

    walk_tree(uuidtext, uuidtext, take("uuidtext"))
    for tree, full, rel in plan:
        held[rel] = full
    first = len(plan)
    walk_tree(diagnostics, diagnostics, take("diagnostics"))
    conflicts, duplicates = [], set()
    for tree, full, rel in plan[first:]:
        if rel in held:
            try:
                same = same_bytes(held[rel], full)
            except OSError as exc:
                fail("a member in both trees could not be compared, so nothing was staged", path=full, reason="%s: %s" % (type(exc).__name__, exc))
            if same:
                duplicates.add(full)
            else:
                conflicts.append(rel)
    if conflicts:
        fail("a member is in both diagnostics and uuidtext with different bytes; nothing was staged: which one the reader should see is "
             "not for this tool to choose", conflicts=sorted(conflicts)[:FIRST], conflict_count=len(conflicts))
    try:
        os.makedirs(scratch, exist_ok=False)
    except OSError as exc:
        fail("the staging directory could not be created, so nothing was staged", path=scratch, reason="%s: %s" % (type(exc).__name__, exc))
    copied, size = 0, 0
    try:
        for tree, full, rel in plan:
            if full in duplicates:
                continue
            target = os.path.join(scratch, rel)
            os.makedirs(os.path.dirname(target), exist_ok=True)
            shutil.copyfile(full, target)
            copied += 1
            size += os.path.getsize(full)
    except OSError as exc:
        shutil.rmtree(scratch, ignore_errors=True)
        fail("a file could not be copied into the staging directory, so nothing was staged and the reader did not run",
             path=getattr(exc, "filename", None), reason="%s: %s" % (type(exc).__name__, exc))
    except BaseException:
        shutil.rmtree(scratch, ignore_errors=True)
        raise
    return {"staged": True, "files": copied, "bytes": size, "duplicates_identical": len(duplicates),
            "sources": [diagnostics, uuidtext]}


def reader_version(argv_first):
    try:
        proc = subprocess.run([argv_first, "--version"], capture_output=True, text=True, timeout=10)
        line = (proc.stdout or proc.stderr).strip().splitlines()
        return line[0][:200] if proc.returncode == 0 and line else None
    except (OSError, subprocess.SubprocessError):
        return None


def count_output(path, limit):
    """Read the whole output once, in a stream. Only the preview is held."""
    cov = {"lines": 0, "json_records": 0, "entry_records": 0, "unparsed_lines": 0, "records_without_entry_fields": 0,
           "array_delimiter_lines": 0}
    entries, first_unparsed, first_without = [], [], []
    with open(path, "rb") as fh:
        for number, raw in enumerate(fh, 1):
            line = raw.strip()
            if not line:
                continue
            cov["lines"] += 1
            if line in (b"[", b"]"):
                cov["array_delimiter_lines"] += 1
                continue
            try:
                row = json.loads(line)
            except ValueError:
                row = None
            if not isinstance(row, dict):
                cov["unparsed_lines"] += 1
                if len(first_unparsed) < FIRST:
                    first_unparsed.append(number)
                continue
            cov["json_records"] += 1
            if not (ENTRY_KEYS & row.keys()):
                cov["records_without_entry_fields"] += 1
                if len(first_without) < FIRST:
                    first_without.append({"line": number, "keys": sorted(row)[:20]})
                continue
            cov["entry_records"] += 1
            if len(entries) < limit:
                kept = {k: row.get(k) for k in KEEP if row.get(k) is not None}
                entries.append(kept or row)
    cov["first_unparsed_lines"] = first_unparsed
    cov["first_records_without_entry_fields"] = first_without
    return cov, entries


def main():
    try:
        args = json.load(sys.stdin)
    except ValueError as exc:
        fail("arguments are not valid JSON", reason=str(exc))
    path = args.get("path")
    if not isinstance(path, str) or not path:
        fail("path is required: a .logarchive or a directory holding diagnostics and uuidtext")
    if not os.path.exists(path):
        fail("no such file or directory", path=path)
    out_dir = args.get("out_dir")
    if not isinstance(out_dir, str) or not out_dir:
        fail("out_dir is required: a directory under work/ for the reader's complete output")
    out_dir = resolve_output(out_dir, "out_dir")
    limit = args.get("limit", 500)
    if not isinstance(limit, int) or isinstance(limit, bool) or limit < 1:
        fail("limit must be a positive integer")
    requested = args.get("timeout_seconds", DEFAULT_TIMEOUT)
    if not isinstance(requested, int) or isinstance(requested, bool) or requested < 1:
        fail("timeout_seconds must be a positive integer")
    timeout = min(requested, MAX_TIMEOUT)
    max_files = args.get("max_stage_files", DEFAULT_MAX_STAGE_FILES)
    max_bytes = args.get("max_stage_bytes", DEFAULT_MAX_STAGE_BYTES)
    for name, value in (("max_stage_files", max_files), ("max_stage_bytes", max_bytes)):
        if not isinstance(value, int) or isinstance(value, bool) or value < 1:
            fail("%s must be a positive integer" % name, **{name: value})

    apple = shutil.which("log") if sys.platform == "darwin" else None
    iterator = shutil.which("unifiedlog_iterator")
    if not apple and not iterator:
        fail("no unified log reader on PATH", looked_for=["log (macOS)", "unifiedlog_iterator"],
             note="Linux images should install Mandiant macos-UnifiedLogs v0.7.0 or later.")
    if not apple and any(args.get(k) for k in ("predicate", "start", "end")):
        fail("predicate/start/end require Apple's log command; unifiedlog_iterator keeps the full JSONL for downstream queries")

    # Where every file this run writes would land, checked before the directory is touched; a name that
    # already exists (a file, or a link) is an earlier run's output and is not overwritten.
    names = {n: resolve_output(os.path.join(out_dir, n), "out_dir") for n in OUTPUT_NAMES}
    job, job_out = os.environ.get("JOB_ID"), os.environ.get("OUT")
    if job and job_out:
        # A job writes only $OUT; the rest of the run directory is read-only to it. The harness gives a
        # path under work/<your id>/ as a place under $OUT, so one that is not there is a mistake worth a reason.
        dest, root = (Path.cwd() / out_dir).resolve(), Path(job_out).resolve()
        if dest != root and root not in dest.parents:
            fail("as a job this tool writes only under $OUT, and out_dir is not there: give it as work/<your id>/<name>, which the job "
                 "maps to $OUT/<name>", out_dir=out_dir, out=str(root))
    try:
        os.makedirs(out_dir, exist_ok=True)
    except OSError as exc:
        fail("out_dir could not be created", out_dir=out_dir, reason="%s: %s" % (type(exc).__name__, exc))
    held = [n for n in OUTPUT_NAMES if os.path.lexists(os.path.join(out_dir, n))]
    if held:
        fail("out_dir already holds %s from an earlier run; the tool does not overwrite it: use a new directory" % ", ".join(held),
             out_dir=out_dir, holds=held)
    stderr_path = names["unifiedlog.stderr"]
    scratch = os.path.join(out_dir, ".logarchive-input")
    problems, warnings = [], []
    staging = None
    timed_out = False
    returncode = None

    if apple:
        engine = "log"
        output_path = names["unifiedlogs.ndjson"]
        reader = {"path": apple, "version": None, "platform": "macOS %s" % (platform.mac_ver()[0] or "unknown")}
        if os.path.isdir(os.path.join(path, "diagnostics")) and os.path.isdir(os.path.join(path, "uuidtext")):
            warnings.append("the input holds diagnostics and uuidtext, not a .logarchive: this tool stages such a copy only for "
                            "unifiedlog_iterator, and `log show --archive` may refuse it")
        argv = [apple, "show", "--archive", path, "--style", "ndjson", "--info", "--debug"]
        for flag, key in (("--predicate", "predicate"), ("--start", "start"), ("--end", "end")):
            if args.get(key):
                argv += [flag, str(args[key])]
        input_seen = path
    else:
        engine = "unifiedlog_iterator"
        output_path = names["unifiedlogs.jsonl"]
        reader = {"path": iterator, "version": reader_version(iterator), "platform": platform.platform()}
        input_seen = path
        if os.path.isdir(os.path.join(path, "diagnostics")) and os.path.isdir(os.path.join(path, "uuidtext")):
            staging = stage(path, scratch, max_files, max_bytes)
            input_seen = scratch
        argv = [iterator, "--mode", "log-archive", "--input", input_seen, "--output", output_path, "--format", "jsonl"]

    census = inventory(input_seen, max_files) if os.path.isdir(input_seen) else None
    if census is not None:
        if census["directories_unreadable"]:
            warnings.append("%d director%s under the input could not be read by this tool, so they are not in the census "
                            "(the reader may not have read them either; the first: %s)" % (census["directories_unreadable"], "y" if census["directories_unreadable"] == 1 else "ies",
                                                 census["first_directories_unreadable"][0]["directory"]))
        if not census["tracev3_files"]:
            warnings.append("no .tracev3 file was found under the input: the reader had no log to decode")
        if not census["timesync_files"]:
            warnings.append("no timesync file was found under the input: timestamps may not be placed in wall time")
        if not census["uuidtext_files"] and not census["dsc_files"]:
            warnings.append("no uuidtext or dsc file was found under the input: message text may not render")

    try:
        try:
            with open(stderr_path, "xb") as err:
                if apple:
                    with open(output_path, "xb") as out:
                        proc = subprocess.run(argv, stdout=out, stderr=err, timeout=timeout)
                else:
                    proc = subprocess.run(argv, stdout=subprocess.DEVNULL, stderr=err, timeout=timeout)
            returncode = proc.returncode
        except subprocess.TimeoutExpired:
            timed_out = True
        except OSError as exc:
            fail("the reader's output could not be created or started, and it did not run", out_dir=out_dir,
                 reason="%s: %s" % (type(exc).__name__, exc))
    finally:
        if staging:
            shutil.rmtree(scratch, ignore_errors=True)

    stderr_bytes = os.path.getsize(stderr_path) if os.path.isfile(stderr_path) else 0
    if not stderr_bytes:
        try:
            os.unlink(stderr_path)
        except OSError:
            pass
        stderr_path = None
    output_exists = os.path.isfile(output_path)
    if output_exists:
        coverage, entries = count_output(output_path, limit)
    else:
        coverage, entries = {"lines": 0, "json_records": 0, "entry_records": 0, "unparsed_lines": 0,
                             "records_without_entry_fields": 0, "array_delimiter_lines": 0,
                             "first_unparsed_lines": [], "first_records_without_entry_fields": []}, []
    coverage["support_files"] = census
    got = coverage["entry_records"]

    if timed_out:
        status = "partial" if got else "failed"
        problems.append("the reader did not finish in %d second(s) and was stopped; what it had written is kept and counted" % timeout)
    elif returncode != 0:
        status = "partial" if got else "failed"
        problems.append("the reader exited with code %s" % returncode)
    elif not output_exists:
        status = "failed"
        problems.append("the reader exited 0 and wrote no output file: nothing was decoded")
    elif not got:
        status = "empty"
        problems.append("the output holds no entries (%d line(s), %d JSON record(s) without an entry's fields): this is not a negative "
                        "about the logs" % (coverage["lines"], coverage["records_without_entry_fields"]))
    elif coverage["unparsed_lines"]:
        status = "partial"
    else:
        status = "complete"
    if coverage["unparsed_lines"]:
        problems.append("%d line(s) of the output are not JSON records (the first at line %s)"
                        % (coverage["unparsed_lines"], ", ".join(str(n) for n in coverage["first_unparsed_lines"][:3])))
    if coverage["records_without_entry_fields"] and got:
        warnings.append("%d JSON record(s) have none of an entry's fields (timestamp, time, message, process, subsystem) and are not "
                        "counted as entries: read them before relying on entry_count" % coverage["records_without_entry_fields"])

    result = {
        "path": path,
        "parser": PARSER,
        "engine": engine,
        "reader": reader,
        "status": status,
        "exit_code": returncode,
        "timed_out": timed_out,
        "command": " ".join(argv),
        "output": output_path if output_exists else None,
        "output_sha256": digest(output_path) if output_exists else None,
        "entry_count": got,
        "entries": entries,
        "entries_inline": len(entries),
        "unparsed_lines": coverage["unparsed_lines"],
        "decoded_coverage": coverage,
        "staging": staging,
        "problems": problems,
        "warnings": warnings,
        "stderr": stderr_path,
        "stderr_bytes": stderr_bytes,
        "timeout_seconds_used": timeout,
        **({"timeout_clamped": True, "timeout_requested": requested} if timeout != requested else {}),
        "note": "The complete reader output is named in output; inline entries are only a preview. status says what happened to this run, "
                "not that the archive was fully decoded: decoded_coverage counts what was read and support_files is a census of "
                "what the input holds. Retention varies with log volume and policy, so absence must be scoped to the archive "
                "actually acquired. Messages can carry command lines, paths and account names.",
    }
    print(json.dumps(result, indent=2, default=str))
    if status == "failed" or timed_out or returncode not in (0,):
        raise SystemExit(1)


if __name__ == "__main__":
    main()
