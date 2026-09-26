#!/usr/bin/env python3
"""Cryptographic and fuzzy hashes for static sample clustering."""
import hashlib
import json
import os
import subprocess
import sys


def fail(message, **extra):
    print(json.dumps({"error": message, **extra}))
    raise SystemExit(1)


def hashes(path):
    sha256 = hashlib.sha256()
    size = 0
    with open(path, "rb") as fh:
        while True:
            block = fh.read(1 << 20)
            if not block:
                break
            size += len(block)
            sha256.update(block)
    tlsh_proc = subprocess.run(
        ["tlsh", "-f", path], capture_output=True, text=True
    )
    tlsh_digest = None
    tlsh_reason = None
    if tlsh_proc.returncode:
        tlsh_reason = tlsh_proc.stderr.strip() or "tlsh exited %d" % tlsh_proc.returncode
    else:
        line = next((line for line in tlsh_proc.stdout.splitlines() if line.strip()), "")
        tlsh_digest = line.split("\t", 1)[0].strip() or None
        if not tlsh_digest or tlsh_digest == "TNULL":
            tlsh_digest = None
            tlsh_reason = "the file is too short or has too little byte diversity for TLSH"

    proc = subprocess.run(
        ["ssdeep", "-b", "--", path], capture_output=True, text=True
    )
    if proc.returncode:
        ssdeep_digest = None
        ssdeep_reason = proc.stderr.strip() or "ssdeep exited %d" % proc.returncode
    else:
        rows = [line for line in proc.stdout.splitlines()
                if line and not line.startswith("ssdeep,")]
        ssdeep_digest = rows[-1].split(",", 1)[0] if rows else None
        ssdeep_reason = None if ssdeep_digest else "ssdeep produced no digest"

    return {
        "path": path,
        "bytes": size,
        "sha256": sha256.hexdigest(),
        "ssdeep": ssdeep_digest,
        "ssdeep_unavailable": ssdeep_reason,
        "tlsh": tlsh_digest,
        "tlsh_unavailable": tlsh_reason,
    }


def main():
    try:
        args = json.load(sys.stdin)
    except ValueError as exc:
        fail("arguments are not valid JSON", reason=str(exc))
    paths = [args.get("path")]
    if args.get("compare_to") is not None:
        paths.append(args.get("compare_to"))
    for path in paths:
        if not isinstance(path, str) or not path:
            fail("path and compare_to must be non-empty strings when supplied")
        if not os.path.isfile(path):
            fail("no such file", path=path)
    if not shutil_which("ssdeep"):
        fail("ssdeep is not installed; this image cannot produce the declared fuzzy hash")
    if not shutil_which("tlsh"):
        fail("tlsh is not installed; this image cannot produce the declared TLSH result")

    results = [hashes(path) for path in paths]
    comparison = None
    if len(results) == 2:
        tlsh_distance = None
        tlsh_reason = None
        if results[0]["tlsh"] and results[1]["tlsh"]:
            proc = subprocess.run(
                ["tlsh", "-c", paths[0], "-f", paths[1]], capture_output=True, text=True
            )
            if proc.returncode:
                tlsh_reason = proc.stderr.strip() or "tlsh comparison exited %d" % proc.returncode
            else:
                line = next((line for line in proc.stdout.splitlines() if line.strip()), "")
                try:
                    tlsh_distance = int(line.split()[0])
                except (IndexError, ValueError):
                    tlsh_reason = "tlsh returned an unrecognised comparison line"
        comparison = {
            "same_sha256": results[0]["sha256"] == results[1]["sha256"],
            "tlsh_distance": tlsh_distance,
            "tlsh_unavailable": tlsh_reason,
            "note": "A smaller TLSH distance means more similar bytes; it is a lead, not attribution.",
        }
    print(json.dumps({
        "files": results,
        "comparison": comparison,
        "note": "SHA-256 establishes identity. ssdeep and TLSH measure byte similarity only; explain shared code or structure before assigning a family.",
    }, indent=2))


def shutil_which(name):
    for directory in os.environ.get("PATH", "").split(os.pathsep):
        candidate = os.path.join(directory, name)
        if os.path.isfile(candidate) and os.access(candidate, os.X_OK):
            return candidate
    return None


if __name__ == "__main__":
    main()
