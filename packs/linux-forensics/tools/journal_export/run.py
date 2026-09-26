#!/usr/bin/env python3
"""Read the evidence's journal, and never your own.

journalctl with no arguments reads the journal of the machine you are sitting
at. That is the single easiest mistake to make here, and its output looks
entirely plausible in a report, so this tool refuses to run without a path and
puts the path it read in its own result.

The journal carries what /var/log/auth.log does not: _EXE and _CMDLINE for the
process that logged, _SYSTEMD_UNIT for the service, _AUDIT_SESSION for the login
session, and _BOOT_ID, which groups a boot together and lets you order events
when the clock moved.
"""
import json
import os
import shutil
import subprocess
import sys

KEEP = ["__REALTIME_TIMESTAMP", "_BOOT_ID", "_PID", "_UID", "_COMM", "_EXE", "_CMDLINE",
        "_SYSTEMD_UNIT", "_AUDIT_SESSION", "_HOSTNAME", "SYSLOG_IDENTIFIER", "PRIORITY",
        "MESSAGE", "_TRANSPORT"]


def fail(message, **extra):
    print(json.dumps({"error": message, **extra}))
    raise SystemExit(1)


def readable(micro):
    import datetime
    try:
        return datetime.datetime.fromtimestamp(
            int(micro) / 1_000_000, datetime.timezone.utc).isoformat().replace("+00:00", "Z")
    except (ValueError, TypeError, OverflowError, OSError):
        return None


def main():
    try:
        args = json.load(sys.stdin)
    except ValueError as exc:
        fail("arguments are not valid JSON", reason=str(exc))
    path = args.get("path")
    if not isinstance(path, str) or not path:
        fail("path is required: journalctl with no path reads this machine's own journal, "
             "which is never the evidence")
    if not os.path.exists(path):
        fail("no such file or directory", path=path)
    if os.path.islink(path):
        fail("refusing a symlink: pass the journal file or directory inside the evidence", path=path,
             target=os.readlink(path))
    binary = shutil.which("journalctl")
    if not binary:
        fail("journalctl is not on PATH",
             install="apt-get install -y systemd; the journal is a binary format and no other "
                     "tool reads it reliably",
             note="On macOS there is no journalctl at all: copy the journal to a Linux host.")
    argv = [binary, "--directory" if os.path.isdir(path) else "--file", path,
            "-o", "json", "--no-pager"]
    for flag, key in (("--unit", "unit"), ("--since", "since"), ("--until", "until"),
                      ("--grep", "grep"), ("--priority", "priority")):
        if args.get(key):
            argv += [flag, str(args[key])]
    try:
        proc = subprocess.run(argv, capture_output=True, text=True, timeout=240)
    except subprocess.TimeoutExpired:
        fail("journalctl did not finish in time", command=" ".join(argv))
    if proc.returncode != 0 and not proc.stdout.strip():
        fail("journalctl refused this journal", exit_code=proc.returncode,
             stderr=(proc.stderr or "").strip(), command=" ".join(argv))

    records, boots, parse_errors = [], set(), []
    for line in proc.stdout.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            row = json.loads(line)
        except ValueError as exc:
            parse_errors.append({"line": line, "error": str(exc)})
            continue
        entry = {k.lower().lstrip("_"): row.get(k) for k in KEEP if row.get(k) is not None}
        entry["time"] = readable(row.get("__REALTIME_TIMESTAMP"))
        entry.pop("realtime_timestamp", None)
        if row.get("_BOOT_ID"):
            boots.add(row["_BOOT_ID"])
        records.append(entry)

    print(json.dumps({
        "path": path,
        "records": records,
        "record_count": len(records),
        "boots_seen": len(boots),
        "command": " ".join(argv),
        "warnings": (proc.stderr or "").strip() or None,
        "parse_errors": parse_errors,
        "exit_code": proc.returncode,
        "complete": proc.returncode == 0 and not parse_errors,
        "note": "Order by boot_id first and time second: within one boot the clock is consistent, "
                "across boots it may not be. A journal with no /var/log/journal directory behind "
                "it was volatile, and everything before the last boot is gone — a configuration "
                "fact, not a gap in the analysis. journalctl --verify reports missing files.",
    }, indent=2))


if __name__ == "__main__":
    main()
