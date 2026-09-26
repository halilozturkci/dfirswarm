#!/usr/bin/env python3
"""Read Apple unified logs without hiding parser failures or dropping output."""
import hashlib
import json
import os
import shutil
import subprocess
import sys

DEFAULT_TIMEOUT = 900
KEEP = ["timestamp", "processImagePath", "process", "subsystem", "category",
        "senderImagePath", "eventMessage", "messageType", "processID", "threadID",
        "activityIdentifier", "eventType"]


def fail(message, **extra):
    print(json.dumps({"error": message, **extra}))
    raise SystemExit(1)


def digest(path):
    value = hashlib.sha256()
    with open(path, "rb") as fh:
        for block in iter(lambda: fh.read(1 << 20), b""):
            value.update(block)
    return value.hexdigest()


def merge_logarchive(path, scratch):
    """Return a Mandiant logarchive path, copying only a /var/db layout."""
    diagnostics = os.path.join(path, "diagnostics")
    uuidtext = os.path.join(path, "uuidtext")
    if not (os.path.isdir(diagnostics) and os.path.isdir(uuidtext)):
        return path, False
    os.makedirs(scratch, exist_ok=False)
    shutil.copytree(uuidtext, scratch, dirs_exist_ok=True, symlinks=True)
    shutil.copytree(diagnostics, scratch, dirs_exist_ok=True, symlinks=True)
    return scratch, True


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
    limit = args.get("limit", 500)
    if not isinstance(limit, int) or isinstance(limit, bool) or limit < 1:
        fail("limit must be a positive integer")
    timeout = args.get("timeout_seconds", DEFAULT_TIMEOUT)
    if not isinstance(timeout, int) or isinstance(timeout, bool) or timeout < 10:
        fail("timeout_seconds must be an integer of at least 10")

    apple = shutil.which("log") if sys.platform == "darwin" else None
    iterator = shutil.which("unifiedlog_iterator")
    if not apple and not iterator:
        fail("no unified log reader on PATH", looked_for=["log (macOS)", "unifiedlog_iterator"],
             note="Linux images should install Mandiant macos-UnifiedLogs v0.7.0 or later.")

    os.makedirs(out_dir, exist_ok=True)
    entries, unparsed = [], 0
    stderr_path = os.path.join(out_dir, "unifiedlog.stderr")
    status = "complete"
    scratch = os.path.join(out_dir, ".logarchive-input")
    if os.path.lexists(scratch):
        fail("out_dir already contains .logarchive-input", path=scratch)

    if apple:
        engine = "log"
        output_path = os.path.join(out_dir, "unifiedlogs.ndjson")
        argv = [apple, "show", "--archive", path, "--style", "ndjson", "--info", "--debug"]
        for flag, key in (("--predicate", "predicate"), ("--start", "start"), ("--end", "end")):
            if args.get(key):
                argv += [flag, str(args[key])]
        try:
            with open(output_path, "w", encoding="utf-8", newline="\n") as out, \
                    open(stderr_path, "w", encoding="utf-8", newline="\n") as err:
                proc = subprocess.run(argv, stdout=out, stderr=err, text=True, timeout=timeout)
        except subprocess.TimeoutExpired:
            fail("log did not finish in time", after_seconds=timeout,
                 output=output_path, stderr=stderr_path, command=" ".join(argv))
        entry_count = 0
        with open(output_path, encoding="utf-8", errors="replace") as fh:
            for line in fh:
                line = line.strip()
                if not line or line.startswith("["):
                    continue
                entry_count += 1
                if len(entries) >= limit:
                    continue
                try:
                    row = json.loads(line)
                except ValueError:
                    unparsed += 1
                    continue
                entries.append({k: row.get(k) for k in KEEP if row.get(k) is not None})
    else:
        engine = "unifiedlog_iterator"
        if any(args.get(k) for k in ("predicate", "start", "end")):
            fail("predicate/start/end require Apple's log command; unifiedlog_iterator keeps the full JSONL for downstream queries")
        output_path = os.path.join(out_dir, "unifiedlogs.jsonl")
        made_scratch = False
        try:
            input_path, made_scratch = merge_logarchive(path, scratch)
            argv = [iterator, "--mode", "log-archive", "--input", input_path,
                    "--output", output_path, "--format", "jsonl"]
            with open(stderr_path, "w", encoding="utf-8", newline="\n") as err:
                proc = subprocess.run(argv, stdout=subprocess.DEVNULL, stderr=err,
                                      text=True, timeout=timeout)
        except subprocess.TimeoutExpired:
            fail("unifiedlog_iterator did not finish in time", after_seconds=timeout,
                 output=output_path, stderr=stderr_path, command=" ".join(argv))
        finally:
            if made_scratch:
                shutil.rmtree(scratch, ignore_errors=True)
        entry_count = 0
        if os.path.isfile(output_path):
            with open(output_path, encoding="utf-8", errors="replace") as fh:
                entry_count = sum(1 for line in fh if line.strip())
        if proc.returncode != 0:
            status = "partial" if entry_count else "failed"

    if proc.returncode != 0:
        status = "partial" if entry_count else "failed"
    stderr_bytes = os.path.getsize(stderr_path) if os.path.isfile(stderr_path) else 0
    if not stderr_bytes:
        try:
            os.unlink(stderr_path)
        except OSError:
            pass
        stderr_path = None
    result = {
        "path": path,
        "engine": engine,
        "status": status,
        "exit_code": proc.returncode,
        "command": " ".join(argv),
        "output": output_path,
        "output_sha256": digest(output_path) if os.path.isfile(output_path) else None,
        "entry_count": entry_count,
        "entries": entries,
        "entries_inline": len(entries),
        "unparsed_lines": unparsed,
        "stderr": stderr_path,
        "stderr_bytes": stderr_bytes,
        "note": "The complete parser output is named in output; inline entries are only a preview. "
                "Retention varies with log volume and policy, so absence must be scoped to the archive actually acquired.",
    }
    print(json.dumps(result, indent=2, default=str))
    if proc.returncode != 0:
        raise SystemExit(1)


if __name__ == "__main__":
    main()
