#!/usr/bin/env python3
"""Catalogue a capture without truncating any packet or protocol listing."""

import json
import os
import shutil
import subprocess
import sys


MAGICS = {b"\xd4\xc3\xb2\xa1", b"\xa1\xb2\xc3\xd4", b"\x4d\x3c\xb2\xa1",
          b"\xa1\xb2\x3c\x4d", b"\x0a\x0d\x0d\x0a"}


def target_of(arg):
    text = open(arg, encoding="utf-8").read() if os.path.isfile(arg) else arg
    target = json.loads(text)
    paths = target.get("paths") or []
    if not paths or not isinstance(paths[0], str):
        raise ValueError("the target names no path")
    return target, paths[0]


def detect(path):
    try:
        with open(path, "rb") as fh:
            magic = fh.read(4)
    except OSError as exc:
        return False, "unreadable: %s" % (exc.strerror or exc)
    if magic in MAGICS:
        return True, "pcap or pcapng file signature"
    return False, "no pcap or pcapng file signature"


def count_rows(path):
    with open(path, "rb") as fh:
        return max(0, sum(1 for _ in fh) - 1)


def main():
    if len(sys.argv) < 4 or sys.argv[2] != "--target":
        print(json.dumps({"ok": False, "error": "usage: run.py detect --target T | run --target T --out DIR"}))
        return 2
    mode, target_arg = sys.argv[1], sys.argv[3]
    try:
        target, path = target_of(target_arg)
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        print(json.dumps({"ok": False, "error": str(exc)}))
        return 2
    applies, why = detect(path)
    if mode == "detect":
        print(json.dumps({"applies": applies, "why": why}))
        return 0 if applies else 1
    if mode != "run" or "--out" not in sys.argv:
        print(json.dumps({"ok": False, "error": "run needs --out DIR"}))
        return 2
    out_dir = sys.argv[sys.argv.index("--out") + 1]
    os.makedirs(out_dir, exist_ok=True)
    coverage = {"recipe": "network-capture", "target": target.get("name") or path,
                "covered": "capture metadata and complete packet, DNS, HTTP and TLS field listings",
                "not_covered": "encrypted payloads, unsupported dissectors, and packets absent from the source",
                "errors": [], "files": []}
    if not applies:
        coverage.update(status="unsupported", why=why)
        json.dump(coverage, open(os.path.join(out_dir, "coverage.json"), "w"), indent=2)
        return 2
    tshark, capinfos = shutil.which("tshark"), shutil.which("capinfos")
    if not tshark or not capinfos:
        coverage.update(status="failed", errors=["missing program(s): " + ", ".join(name for name, value in (("tshark", tshark), ("capinfos", capinfos)) if not value)])
        json.dump(coverage, open(os.path.join(out_dir, "coverage.json"), "w"), indent=2)
        return 2

    def execute(name, argv):
        output = os.path.join(out_dir, name)
        stderr = output + ".stderr"
        with open(output, "wb") as stdout, open(stderr, "wb") as err:
            proc = subprocess.run(argv, stdout=stdout, stderr=err)
        if os.path.getsize(stderr) == 0:
            os.remove(stderr)
        else:
            coverage["files"].append({"path": os.path.basename(stderr), "description": "complete stderr for " + name})
        if proc.returncode:
            coverage["errors"].append("%s exited %d" % (" ".join(argv[:2]), proc.returncode))
        return output, proc.returncode

    capture, _ = execute("capture.txt", [capinfos, "-M", "-c", "-a", "-e", "-u", "-s", "-x", path])
    coverage["files"].append({"path": "capture.txt", "description": "capinfos capture metadata"})
    base = [tshark, "-n", "-r", path, "-T", "fields", "-E", "header=y", "-E", "separator=/t", "-E", "quote=d", "-E", "occurrence=a"]
    listings = [
        ("packets.tsv", None, ["frame.number", "frame.time_epoch", "frame.cap_len", "frame.len", "_ws.col.Protocol", "ip.src", "ipv6.src", "tcp.srcport", "udp.srcport", "ip.dst", "ipv6.dst", "tcp.dstport", "udp.dstport"]),
        ("dns.tsv", "dns", ["frame.number", "frame.time_epoch", "ip.src", "ipv6.src", "dns.id", "dns.flags.response", "dns.qry.name", "dns.qry.type", "dns.a", "dns.aaaa", "dns.resp.name", "dns.flags.rcode"]),
        ("http.tsv", "http", ["frame.number", "frame.time_epoch", "ip.src", "ip.dst", "tcp.stream", "http.request.method", "http.host", "http.request.uri", "http.response.code", "http.content_length", "http.user_agent"]),
        ("tls.tsv", "tls", ["frame.number", "frame.time_epoch", "ip.src", "ip.dst", "tcp.stream", "tls.handshake.type", "tls.handshake.extensions_server_name", "tls.handshake.ja3", "x509sat.uTF8String"]),
    ]
    for name, display_filter, fields in listings:
        argv = list(base)
        if display_filter:
            argv += ["-Y", display_filter]
        for field in fields:
            argv += ["-e", field]
        output, _ = execute(name, argv)
        coverage["files"].append({"path": name, "description": "complete %s field listing" % name[:-4], "rows": count_rows(output)})

    index = os.path.join(out_dir, "index.tsv")
    with open(index, "w", encoding="utf-8", newline="\n") as fh:
        fh.write("path\tdescription\trows\n")
        for item in coverage["files"]:
            fh.write("%s\t%s\t%s\n" % (item["path"], item["description"], item.get("rows", "")))
    coverage["status"] = "partial" if coverage["errors"] else "complete"
    json.dump(coverage, open(os.path.join(out_dir, "coverage.json"), "w"), indent=2)
    print(json.dumps({"ok": not coverage["errors"], "status": coverage["status"]}))
    return 0 if not coverage["errors"] else 2


if __name__ == "__main__":
    raise SystemExit(main())
