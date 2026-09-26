#!/usr/bin/env python3
"""Sweep a directory with a YARA rule file and report every match.

No rules ship with this. A curated rule set is a maintenance commitment that
does not belong in a tool library, and a stale rule reads like a finding. The
caller names the rules it trusts; this runs them and reports what matched,
where, and at what offset.

Extracted material is the usual target, and the quarantine guard means the
files there cannot execute — which is why scanning them is safe and running
them is not.
"""
import json
import os
import shutil
import subprocess
import sys


def fail(message, **extra):
    print(json.dumps({"error": message, **extra}))
    raise SystemExit(1)


def main():
    try:
        args = json.load(sys.stdin)
    except ValueError as exc:
        fail("arguments are not valid JSON", reason=str(exc))

    rules = args.get("rules")
    target = args.get("target")
    if not isinstance(rules, str) or not rules:
        fail("rules is required: a path to a .yar or .yara file")
    if not os.path.isfile(rules):
        fail("no such rules file", rules=rules)
    if not isinstance(target, str) or not target:
        fail("target is required: a file or directory to scan")
    if not os.path.exists(target):
        fail("no such target", target=target)

    timeout = args.get("timeout_seconds", 60)
    if not isinstance(timeout, int) or isinstance(timeout, bool) or timeout < 1:
        fail("timeout_seconds must be a positive integer")
    timeout = min(timeout, 110)

    if shutil.which("yara") is None:
        fail("yara is not on PATH", hint="brew install yara; scripts/toolbox.sh reports it with the dfir set")

    # -s prints the matching strings with their offsets, -r recurses, -w drops
    # the warnings that would otherwise be mistaken for findings.
    argv = ["yara", "-w", "-s"]
    if os.path.isdir(target):
        argv.append("-r")
    argv += [rules, target]

    try:
        proc = subprocess.run(argv, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=timeout)
    except subprocess.TimeoutExpired:
        fail("yara did not finish in time", timeout_seconds=timeout, target=target)

    stdout = proc.stdout.decode("utf-8", "replace")
    stderr = proc.stderr.decode("utf-8", "replace").strip()
    if proc.returncode not in (0, 1) and not stdout:
        fail("yara failed", status=proc.returncode, stderr=stderr)

    matches = []
    current = None
    for line in stdout.split("\n"):
        if not line.strip():
            continue
        if line.startswith("0x"):
            # 0x1f4:$needle: MZ...
            offset, _, rest = line.partition(":")
            ident, _, value = rest.partition(":")
            if current is not None:
                current["strings"].append({
                    "offset": offset.strip(),
                    "identifier": ident.strip(),
                    "value": value.strip(),
                })
            continue
        rule, _, path = line.partition(" ")
        current = {"rule": rule.strip(), "file": path.strip(), "strings": []}
        matches.append(current)

    print(json.dumps({
        "rules": rules,
        "target": target,
        "matches": matches,
        "match_count": len(matches),
        "files_matched": sorted({m["file"] for m in matches}),
        "warnings": stderr or None,
    }, indent=2))


if __name__ == "__main__":
    main()
