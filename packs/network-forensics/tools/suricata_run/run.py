#!/usr/bin/env python3
"""Run local Suricata rules offline and summarise its complete EVE output."""

import collections
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
    path, rules, out_dir = args.get("path"), args.get("rules"), args.get("out_dir")
    for label, value in (("path", path), ("rules", rules)):
        if not isinstance(value, str) or not os.path.isfile(value):
            fail("%s must name a readable file" % label, **{label: value})
    if not isinstance(out_dir, str) or not out_dir:
        fail("out_dir is required: an empty directory under work/")
    if os.path.exists(out_dir) and os.listdir(out_dir):
        fail("out_dir already holds files", out_dir=out_dir)
    limit = args.get("return_alerts", 100)
    if not isinstance(limit, int) or isinstance(limit, bool) or limit < 0:
        fail("return_alerts must be a non-negative integer")
    timeout = args.get("timeout_seconds", 900)
    if not isinstance(timeout, int) or isinstance(timeout, bool) or timeout < 10:
        fail("timeout_seconds must be an integer of at least 10")
    checksum_mode = str(args.get("checksum_mode") or "none").lower()
    if checksum_mode not in ("none", "all"):
        fail("checksum_mode must be none or all", checksum_mode=checksum_mode)
    binary = shutil.which("suricata")
    if not binary:
        fail("suricata is not on PATH")

    os.makedirs(out_dir, exist_ok=True)
    argv = [binary, "-r", os.path.abspath(path), "-S", os.path.abspath(rules), "-l", out_dir,
            "-k", checksum_mode,
            "--set", "app-layer.protocols.tls.ja3-fingerprints=yes",
            "--set", "app-layer.protocols.tls.ja4-fingerprints=yes",
            "--set", "outputs.1.eve-log.types.5.tls.extended=yes",
            "--set", "outputs.1.eve-log.types.5.tls.ja4=on"]
    stdout_path, stderr_path = os.path.join(out_dir, "suricata.stdout"), os.path.join(out_dir, "suricata.stderr")
    try:
        with open(stdout_path, "wb") as stdout, open(stderr_path, "wb") as stderr:
            proc = subprocess.run(argv, stdout=stdout, stderr=stderr, timeout=timeout)
    except subprocess.TimeoutExpired:
        fail("suricata did not finish in time", after_seconds=timeout, partial_output=out_dir,
             stdout=stdout_path, stderr=stderr_path)
    eve = os.path.join(out_dir, "eve.json")
    if not os.path.isfile(eve):
        fail("suricata wrote no eve.json", exit_code=proc.returncode,
             stdout=stdout_path, stderr=stderr_path, out_dir=out_dir)

    event_types, signatures = collections.Counter(), collections.Counter()
    alerts, tls_with_ja3, tls_with_ja4, invalid = [], 0, 0, 0
    with open(eve, "r", encoding="utf-8", errors="replace") as fh:
        for line_no, line in enumerate(fh, 1):
            try:
                event = json.loads(line)
            except ValueError:
                invalid += 1
                continue
            kind = str(event.get("event_type") or "unknown")
            event_types[kind] += 1
            if kind == "alert":
                alert = event.get("alert") or {}
                signatures[str(alert.get("signature") or alert.get("signature_id") or "unknown")] += 1
                if len(alerts) < limit:
                    alerts.append({"line": line_no, "timestamp": event.get("timestamp"),
                                   "src_ip": event.get("src_ip"), "src_port": event.get("src_port"),
                                   "dest_ip": event.get("dest_ip"), "dest_port": event.get("dest_port"),
                                   "signature_id": alert.get("signature_id"), "signature": alert.get("signature")})
            tls = event.get("tls") or {}
            tls_with_ja3 += int(bool(tls.get("ja3")))
            tls_with_ja4 += int(bool(tls.get("ja4")))

    print(json.dumps({
        "path": path, "rules": rules, "out_dir": out_dir, "eve_json": eve,
        "checksum_mode": checksum_mode,
        "exit_code": proc.returncode, "event_types": dict(event_types),
        "alert_count": event_types.get("alert", 0), "alerts_returned": len(alerts),
        "alerts": alerts, "signatures": dict(signatures), "tls_with_ja3": tls_with_ja3,
        "tls_with_ja4": tls_with_ja4, "invalid_eve_lines": invalid,
        "stdout": stdout_path, "stderr": stderr_path, "ok": proc.returncode == 0,
        "note": "Inline alerts are bounded, but eve.json is the complete result and is named above. Complete stdout and stderr are retained beside it. Checksum validation defaults to none because capture offload commonly leaves invalid TCP checksums; use all to test integrity. JA3/JA4 are pivots, not unique binary identities.",
    }, indent=2))
    return 0 if proc.returncode == 0 else 1


if __name__ == "__main__":
    raise SystemExit(main())
