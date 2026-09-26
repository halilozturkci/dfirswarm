#!/usr/bin/env python3
"""Turn a capture into Zeek's logs, and hand them back as records.

Zeek reads a capture once and writes a log per protocol: conn.log for every
session with byte counts each way, dns.log for every query and answer, ssl.log
for the handshake including the server name and the certificate, http.log,
files.log with a hash per object it reassembled, and notice.log for what its own
policies flagged.

That is the form every later question wants, and building it by hand from
packets is most of a day. Where the host has Zeek, this is an hour saved on
every capture; where it does not, pcap_summary still answers the first four
questions and the report should say which route was taken.

Zeek's TSV logs carry their field names in a #fields header, which is what makes
them parseable without guessing. JSON output is read too, where the host is
configured for it.
"""
import json
import os
import shutil
import subprocess
import sys

DEFAULT_TIMEOUT = 900


def fail(message, **extra):
    print(json.dumps({"error": message, **extra}))
    raise SystemExit(1)


def read_log(path, limit):
    """Zeek TSV: #separator, #fields and #types lines, then rows."""
    fields, rows, empty, total = None, [], "-", 0
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as fh:
            for line in fh:
                line = line.rstrip("\n")
                if line.startswith("#"):
                    if line.startswith("#fields"):
                        fields = line.split("\t")[1:]
                    elif line.startswith("#unset_field"):
                        empty = line.split("\t")[-1]
                    continue
                if not line.strip():
                    continue
                if fields is None:
                    try:
                        record = json.loads(line)
                        total += 1
                        if len(rows) < limit:
                            rows.append(record)
                        continue
                    except ValueError:
                        continue
                values = line.split("\t")
                total += 1
                if len(rows) < limit:
                    rows.append({k: (None if v == empty else v)
                                 for k, v in zip(fields, values)})
    except OSError as exc:
        return None, None, str(exc)
    return rows, total, None


def main():
    try:
        args = json.load(sys.stdin)
    except ValueError as exc:
        fail("arguments are not valid JSON", reason=str(exc))
    path = args.get("path")
    if not isinstance(path, str) or not path:
        fail("path is required: a capture file")
    if not os.path.isfile(path):
        fail("no such file", path=path)
    out_dir = args.get("out_dir")
    if not isinstance(out_dir, str) or not out_dir:
        fail("out_dir is required: a directory under work/ for Zeek's logs")
    if os.path.exists(out_dir) and os.listdir(out_dir):
        fail("out_dir already holds files; stale Zeek logs would contaminate the result", out_dir=out_dir)
    limit = args.get("limit", 200)
    if not isinstance(limit, int) or isinstance(limit, bool) or limit < 1:
        fail("limit must be a positive integer")
    timeout = args.get("timeout_seconds", DEFAULT_TIMEOUT)
    if not isinstance(timeout, int) or isinstance(timeout, bool) or timeout < 10:
        fail("timeout_seconds must be an integer of at least 10")

    binary = shutil.which("zeek") or shutil.which("bro")
    if not binary:
        fail("zeek is not on PATH",
             install="brew install zeek, or the Zeek project's own packages "
                     "(https://software.opensuse.org/download.html?project=security%3Azeek&package=zeek): "
                     "zeek is in neither Debian's nor Ubuntu's archive",
             note="Without it, pcap_summary still answers the first four questions about a "
                  "capture. Say in the report which route was taken.")

    os.makedirs(out_dir, exist_ok=True)
    argv = [binary, "-C", "-r", os.path.abspath(path)]
    stdout_path = os.path.join(out_dir, "zeek.stdout")
    stderr_path = os.path.join(out_dir, "zeek.stderr")
    try:
        with open(stdout_path, "wb") as stdout, open(stderr_path, "wb") as stderr:
            proc = subprocess.run(argv, stdout=stdout, stderr=stderr, timeout=timeout, cwd=out_dir)
    except subprocess.TimeoutExpired:
        fail("zeek did not finish in time", after_seconds=timeout, command=" ".join(argv),
             partial_output=out_dir, stdout=stdout_path, stderr=stderr_path)

    written = sorted(n for n in os.listdir(out_dir) if n.endswith(".log"))
    if not written:
        fail("zeek wrote no logs", exit_code=proc.returncode, command=" ".join(argv),
             stdout=stdout_path, stderr=stderr_path)

    wanted = {str(n) for n in (args.get("logs") or [])}
    logs, problems = {}, []
    for name in written:
        stem = name[:-4]
        if wanted and stem not in wanted:
            continue
        log_path = os.path.join(out_dir, name)
        rows, total, problem = read_log(log_path, limit)
        if problem:
            problems.append({"log": stem, "why": problem})
            continue
        logs[stem] = {"file": log_path, "records": rows, "returned": len(rows),
                      "total": total, "omitted": total - len(rows)}

    print(json.dumps({
        "path": path,
        "out_dir": out_dir,
        "logs_written": [n[:-4] for n in written],
        "logs": logs,
        "exit_code": proc.returncode,
        "stdout": stdout_path,
        "stderr": stderr_path,
        "ok": proc.returncode == 0 and not problems,
        "problems": problems,
        "note": "conn.log's orig_bytes and resp_bytes are the asymmetry an exfiltration question "
                "turns on. files.log carries a hash per reassembled object, and its conn_uids tie "
                "each one back to the session it came out of — which is the provenance an "
                "extracted file needs before it can go in a report. Inline records may be bounded, "
                "but each complete log is retained and named in its entry. Complete Zeek stdout "
                "and stderr are retained beside the logs.",
    }, indent=2))
    return 0 if proc.returncode == 0 and not problems else 1


if __name__ == "__main__":
    raise SystemExit(main())
