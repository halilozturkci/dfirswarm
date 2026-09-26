#!/usr/bin/env python3
"""Export every Wireshark protocol object and index it without model-bound binary output."""

import hashlib
import json
import os
import shutil
import subprocess
import sys


DEFAULT_PROTOCOLS = ["http", "smb", "smb2", "tftp", "imf"]


def fail(message, **extra):
    print(json.dumps({"error": message, **extra}))
    raise SystemExit(1)


def digest(path):
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def shown(path):
    return path.replace("\\", "\\\\").replace("\t", "\\t").replace("\r", "\\r").replace("\n", "\\n")


def main():
    try:
        args = json.load(sys.stdin)
    except ValueError as exc:
        fail("arguments are not valid JSON", reason=str(exc))
    path, out_dir = args.get("path"), args.get("out_dir")
    if not isinstance(path, str) or not os.path.isfile(path):
        fail("path must name a capture file", path=path)
    if not isinstance(out_dir, str) or not out_dir:
        fail("out_dir is required: an empty directory under work/")
    if os.path.exists(out_dir) and os.listdir(out_dir):
        fail("out_dir already holds files", out_dir=out_dir)
    protocols = args.get("protocols") or DEFAULT_PROTOCOLS
    if not isinstance(protocols, list) or not protocols or any(not isinstance(p, str) or not p or not p.replace("_", "").isalnum() for p in protocols):
        fail("protocols must be a non-empty list of Wireshark export protocol names")
    timeout = args.get("timeout_seconds", 900)
    if not isinstance(timeout, int) or isinstance(timeout, bool) or timeout < 10:
        fail("timeout_seconds must be an integer of at least 10")
    display_filter = args.get("display_filter")
    if display_filter is not None and not isinstance(display_filter, str):
        fail("display_filter must be a string")
    binary = shutil.which("tshark")
    if not binary:
        fail("tshark is not on PATH")

    os.makedirs(out_dir, exist_ok=True)
    runs, errors = [], []
    log_dir = os.path.join(out_dir, "_logs")
    os.makedirs(log_dir)
    for protocol in dict.fromkeys(protocols):
        destination = os.path.join(out_dir, protocol)
        os.makedirs(destination)
        argv = [binary, "-n", "-r", os.path.abspath(path)]
        if display_filter:
            argv += ["-Y", display_filter]
        argv += ["--export-objects", "%s,%s" % (protocol, destination)]
        stdout_path = os.path.join(log_dir, protocol + ".stdout")
        stderr_path = os.path.join(log_dir, protocol + ".stderr")
        try:
            with open(stdout_path, "wb") as stdout, open(stderr_path, "wb") as stderr:
                proc = subprocess.run(argv, stdout=stdout, stderr=stderr, timeout=timeout)
        except subprocess.TimeoutExpired:
            errors.append({"protocol": protocol, "error": "timeout", "after_seconds": timeout,
                           "stdout": stdout_path, "stderr": stderr_path})
            continue
        files = sum(len(names) for _, _, names in os.walk(destination))
        runs.append({"protocol": protocol, "exit_code": proc.returncode, "files": files,
                     "stdout": stdout_path, "stderr": stderr_path})
        if proc.returncode:
            errors.append({"protocol": protocol, "exit_code": proc.returncode,
                           "stdout": stdout_path, "stderr": stderr_path})

    index = os.path.join(out_dir, "index.tsv")
    rows = []
    for root, dirs, files in os.walk(out_dir):
        dirs.sort()
        for name in sorted(files):
            full = os.path.join(root, name)
            if full == index:
                continue
            rel = os.path.relpath(full, out_dir)
            protocol = rel.split(os.sep, 1)[0]
            if protocol not in protocols:
                continue
            rows.append((protocol, rel, os.path.getsize(full), digest(full)))
    with open(index, "w", encoding="utf-8", newline="\n") as fh:
        fh.write("protocol\tpath\tbytes\tsha256\n")
        for protocol, rel, size, sha256 in rows:
            fh.write("%s\t%s\t%d\t%s\n" % (protocol, shown(rel), size, sha256))
    print(json.dumps({
        "path": path, "out_dir": out_dir, "index_tsv": index, "objects": len(rows),
        "bytes": sum(row[2] for row in rows), "runs": runs, "errors": errors,
        "ok": not errors,
        "note": "No object content is returned here. index.tsv names every exported object with size and SHA-256; preserve the capture hash and protocol/session context with any object used in a report. Complete stdout and stderr are retained under _logs/.",
    }, indent=2))
    return 1 if errors else 0


if __name__ == "__main__":
    raise SystemExit(main())
