#!/usr/bin/env python3
"""Normalise common web, proxy and firewall logs without dropping a line."""

import collections
import datetime
import gzip
import json
import os
import re
import sys


COLUMNS = ["line", "format", "timestamp", "src", "dst", "src_port", "dst_port",
           "protocol", "method", "target", "status", "bytes", "action", "user",
           "user_agent", "elapsed_ms", "hierarchy", "mime", "in_if", "out_if",
           "nat_src", "nat_dst", "tcp_flags", "raw"]
WEB = re.compile(
    r'^(?P<src>\S+)\s+\S+\s+(?P<user>\S+)\s+\[(?P<time>[^]]+)\]\s+'
    r'"(?P<request>[^"]*)"\s+(?P<status>\S+)\s+(?P<bytes>\S+)'
    r'(?:\s+"(?P<ref>[^"]*)"\s+"(?P<ua>[^"]*)")?.*$')
KV = re.compile(r'\b([A-Z][A-Z0-9_]*)=("[^"]*"|\S*)')


def fail(message, **extra):
    print(json.dumps({"error": message, **extra}))
    raise SystemExit(1)


def esc(value):
    return str(value or "").replace("\\", "\\\\").replace("\t", "\\t").replace("\r", "\\r").replace("\n", "\\n")


def web(line):
    m = WEB.match(line)
    if not m:
        return None
    request = m.group("request").split()
    method = request[0] if request else ""
    target = request[1] if len(request) > 1 else ""
    return {"format": "web", "timestamp": m.group("time"), "src": m.group("src"),
            "method": method, "target": target, "status": m.group("status"),
            "bytes": "" if m.group("bytes") == "-" else m.group("bytes"),
            "user": "" if m.group("user") == "-" else m.group("user"),
            "user_agent": m.group("ua") or ""}


def squid(line):
    parts = line.split()
    if len(parts) < 9 or not re.fullmatch(r"\d+(?:\.\d+)?", parts[0]):
        return None
    if "/" not in parts[3] or not re.fullmatch(r"\d+", parts[4]):
        return None
    try:
        stamp = datetime.datetime.fromtimestamp(float(parts[0]), datetime.timezone.utc).isoformat().replace("+00:00", "Z")
    except (OverflowError, OSError, ValueError):
        stamp = parts[0]
    status = parts[3].split("/", 1)[1]
    return {"format": "squid", "timestamp": stamp, "src": parts[2], "method": parts[5],
            "target": parts[6], "status": status, "bytes": parts[4],
            "action": parts[3].split("/", 1)[0], "elapsed_ms": parts[1],
            "user": "" if parts[7] == "-" else parts[7], "hierarchy": parts[8],
            "mime": parts[9] if len(parts) > 9 else ""}


def firewall(line):
    pairs = {k: v.strip('"') for k, v in KV.findall(line)}
    if not pairs or not ({"SRC", "DST", "PROTO"} & set(pairs)):
        return None
    action = pairs.get("ACTION", "")
    if not action:
        for candidate in ("DROP", "REJECT", "ACCEPT", "ALLOW", "DENY", "BLOCK"):
            if re.search(r"(?:^|\s)%s(?:\s|$)" % candidate, line, re.I):
                action = candidate.upper()
                break
    first_kv = min((m.start() for m in KV.finditer(line)), default=0)
    flags = [flag for flag in ("SYN", "ACK", "FIN", "RST", "PSH", "URG", "ECE", "CWR")
             if re.search(r"(?:^|\s)%s(?:\s|$)" % flag, line, re.I)]
    def first(*names):
        return next((pairs[name] for name in names if pairs.get(name)), "")
    return {"format": "firewall", "timestamp": line[:first_kv].strip(),
            "src": pairs.get("SRC", ""), "dst": pairs.get("DST", ""),
            "src_port": pairs.get("SPT", pairs.get("SRC_PORT", "")),
            "dst_port": pairs.get("DPT", pairs.get("DST_PORT", "")),
            "protocol": pairs.get("PROTO", ""), "bytes": pairs.get("LEN", ""),
            "action": action, "in_if": pairs.get("IN", ""), "out_if": pairs.get("OUT", ""),
            "nat_src": first("NATSRC", "NAT_SRC", "ORIGSRC", "ORIG_SRC", "TRANS_SRC"),
            "nat_dst": first("NATDST", "NAT_DST", "ORIGDST", "ORIG_DST", "TRANS_DST"),
            "tcp_flags": ",".join(flags)}


def parse(line, wanted):
    parsers = {"web": web, "squid": squid, "firewall": firewall}
    if wanted != "auto":
        return parsers[wanted](line)
    for parser in (web, squid, firewall):
        found = parser(line)
        if found:
            return found
    return None


def opener(path):
    with open(path, "rb") as fh:
        magic = fh.read(2)
    return gzip.open(path, "rt", encoding="utf-8", errors="replace") if magic == b"\x1f\x8b" else open(path, "r", encoding="utf-8", errors="replace")


def main():
    try:
        args = json.load(sys.stdin)
    except ValueError as exc:
        fail("arguments are not valid JSON", reason=str(exc))
    path, out_dir = args.get("path"), args.get("out_dir")
    if not isinstance(path, str) or not os.path.isfile(path):
        fail("path must name a readable log file", path=path)
    if not isinstance(out_dir, str) or not out_dir:
        fail("out_dir is required: an empty directory under work/")
    if os.path.exists(out_dir) and os.listdir(out_dir):
        fail("out_dir already holds files", out_dir=out_dir)
    wanted = str(args.get("format") or "auto").lower()
    if wanted not in ("auto", "web", "squid", "firewall"):
        fail("format must be auto, web, squid or firewall", format=wanted)
    top = args.get("top", 20)
    if not isinstance(top, int) or isinstance(top, bool) or top < 1:
        fail("top must be a positive integer")

    os.makedirs(out_dir, exist_ok=True)
    normal_path, bad_path = os.path.join(out_dir, "normalized.tsv"), os.path.join(out_dir, "unparsed.tsv")
    counts = {name: collections.Counter() for name in ("format", "src", "dst", "method", "status", "action")}
    total = parsed = blank = 0
    with opener(path) as source, open(normal_path, "w", encoding="utf-8", newline="\n") as normal, open(bad_path, "w", encoding="utf-8", newline="\n") as bad:
        normal.write("\t".join(COLUMNS) + "\n")
        bad.write("line\traw\n")
        for number, raw in enumerate(source, 1):
            total += 1
            line = raw.rstrip("\r\n")
            if not line.strip():
                blank += 1
                bad.write("%d\t%s\n" % (number, esc(line)))
                continue
            row = parse(line, wanted)
            if row is None:
                bad.write("%d\t%s\n" % (number, esc(line)))
                continue
            parsed += 1
            row.update(line=number, raw=line)
            normal.write("\t".join(esc(row.get(column, "")) for column in COLUMNS) + "\n")
            for name, counter in counts.items():
                if row.get(name):
                    counter[str(row[name])] += 1

    def leading(counter):
        return [{"value": value, "count": count} for value, count in counter.most_common(top)]
    print(json.dumps({
        "path": path, "format_requested": wanted, "lines": total, "parsed": parsed,
        "unparsed": total - parsed, "blank": blank, "normalized_tsv": normal_path,
        "unparsed_tsv": bad_path,
        "aggregate": {name: leading(counter) for name, counter in counts.items()},
        "note": "Every source line is preserved in normalized.tsv or unparsed.tsv. Returned aggregates are bounded; the complete result is on disk.",
    }, indent=2))


if __name__ == "__main__":
    main()
