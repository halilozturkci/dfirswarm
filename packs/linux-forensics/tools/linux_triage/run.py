#!/usr/bin/env python3
"""Lossless Linux triage through dissect.target.

Each artefact family is written to its own complete JSONL file. Stdout is a
small manifest of those files, their sizes, hashes, record counts and status.
This lets an agent page/search the files without the tool cutting the evidence.
"""

import hashlib
import json
import os
import shutil
import subprocess
import sys
from pathlib import Path


GROUPS = {
    "identity": {"functions": "os,hostname,version,ips", "strings": True},
    "users": {"functions": "users"},
    "sessions": {"functions": "wtmp,btmp,lastlog"},
    "authentication": {"functions": "authlog"},
    "history": {"functions": "bashhistory"},
    "persistence": {"functions": "cronjobs,services"},
    "packages": {"functions": "dpkg.status,packagemanager.logs"},
    "ssh": {"functions": "ssh.authorized_keys,ssh.known_hosts,ssh.public_keys"},
    "logs": {"functions": "journal,syslog"},
    "web": {"functions": "webserver.logs"},
    "containers": {"functions": "container.logs"},
}


def fail(message, **extra):
    print(json.dumps({"error": message, **extra}))
    raise SystemExit(1)


def digest(path):
    value = hashlib.sha256()
    with path.open("rb") as fh:
        while chunk := fh.read(1024 * 1024):
            value.update(chunk)
    return value.hexdigest()


def line_count(path):
    with path.open("rb") as fh:
        return sum(1 for _ in fh)


def main():
    try:
        args = json.load(sys.stdin)
    except ValueError as exc:
        fail("arguments are not valid JSON", reason=str(exc))
    source = args.get("source")
    out_arg = args.get("out_dir")
    if not isinstance(source, str) or not source or not os.path.exists(source):
        fail("source is required and must exist", source=source)
    if not isinstance(out_arg, str) or not out_arg:
        fail("out_dir is required")
    out = Path(out_arg)
    if out.exists():
        fail("out_dir already exists; refusing to overwrite an earlier result", out_dir=str(out))
    binary = shutil.which("target-query")
    if not binary:
        fail("target-query is not on PATH", install="the computer-forensics-base image requirement 'dissect'")
    selected = args.get("groups") or list(GROUPS)
    if not isinstance(selected, list) or not selected or any(g not in GROUPS for g in selected):
        fail("groups must be a non-empty list of known families", known=list(GROUPS))
    timeout = args.get("timeout_seconds", 1800)
    if not isinstance(timeout, int) or isinstance(timeout, bool) or timeout < 1:
        fail("timeout_seconds must be a positive integer")

    out.mkdir(parents=True)
    results = []
    for group in selected:
        spec = GROUPS[group]
        result_path = out / (group + (".txt" if spec.get("strings") else ".jsonl"))
        error_path = out / f"{group}.stderr"
        argv = [binary, "--no-cache", "-f", spec["functions"]]
        argv += ["-s"] if spec.get("strings") else ["-j"]
        argv.append(source)
        timed_out = False
        with result_path.open("wb") as stdout, error_path.open("wb") as stderr:
            try:
                proc = subprocess.run(argv, stdout=stdout, stderr=stderr, timeout=timeout)
                returncode = proc.returncode
            except subprocess.TimeoutExpired:
                timed_out = True
                returncode = 124
        if not error_path.stat().st_size:
            error_path.unlink()
        row = {
            "group": group,
            "functions": spec["functions"],
            "file": str(result_path),
            "bytes": result_path.stat().st_size,
            "lines": line_count(result_path),
            "sha256": digest(result_path),
            "exit_code": returncode,
            "timed_out": timed_out,
        }
        if error_path.exists():
            row["stderr"] = str(error_path)
            row["stderr_bytes"] = error_path.stat().st_size
            row["stderr_sha256"] = digest(error_path)
        results.append(row)

    print(json.dumps({
        "source": source,
        "out_dir": str(out),
        "groups": results,
        "complete": all(r["exit_code"] == 0 and not r["timed_out"] for r in results),
        "note": "Every byte target-query returned is in the named file. Empty output means the "
                "selected parser found no records, not that the artefact family is absent; read "
                "the paired stderr and confirm the source scope before recording an absence.",
    }, indent=2))


if __name__ == "__main__":
    main()
