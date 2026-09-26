#!/usr/bin/env python3
import json, sys, os, re
from collections import defaultdict
from pathlib import Path

# Lossless paging (the same in every library tool that pages): the page an
# agent reads stays small, and when there are more rows the whole result is
# written as JSON Lines under work/<agent>/tool-output and named.
import hashlib
import json
import os
import re
import tempfile
from pathlib import Path


class LosslessPage:
    def __init__(self, tool: str, key: object, limit: int):
        if isinstance(limit, bool) or not isinstance(limit, int) or limit < 1:
            raise ValueError("limit must be a positive integer")
        self.tool = re.sub(r"[^A-Za-z0-9_.-]", "_", tool)
        self.limit = limit
        self.page: list[object] = []
        self.total = 0
        self._out = None
        self._tmp: Path | None = None
        digest = hashlib.sha256(
            json.dumps(key, sort_keys=True, default=str).encode("utf-8")
        ).hexdigest()[:16]
        agent = re.sub(
            r"[^A-Za-z0-9_.-]", "_", os.environ.get("AGENT_ID") or "tool"
        )
        self.path = Path("work") / agent / "tool-output" / f"{self.tool}-{digest}.jsonl"

    def _write(self, row: object) -> None:
        assert self._out is not None
        self._out.write(json.dumps(row, ensure_ascii=False, default=str))
        self._out.write("\n")

    def add(self, row: object) -> None:
        self.total += 1
        if len(self.page) < self.limit:
            self.page.append(row)
            return
        if self._out is None:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            fd, name = tempfile.mkstemp(
                dir=self.path.parent, prefix=f".{self.path.name}-"
            )
            self._tmp = Path(name)
            self._out = os.fdopen(fd, "w", encoding="utf-8")
            for kept in self.page:
                self._write(kept)
        self._write(row)

    def finish(self) -> dict:
        result = {
            "matched": self.total,
            "returned": len(self.page),
            "truncated": self.total > len(self.page),
        }
        if self._out is not None:
            self._out.flush()
            os.fsync(self._out.fileno())
            self._out.close()
            assert self._tmp is not None
            os.replace(self._tmp, self.path)
            result["all_results"] = str(self.path)
            result["all_results_format"] = "JSON Lines, one complete result per line"
        return result

args = json.load(sys.stdin)
path = args.get("path") or "inputs/[UNALLOCATED]"
needles = args.get("needles")  # list of ascii strings, or pipe-separated string
if isinstance(needles, str):
    needles = [n for n in needles.split("|") if n]
if not needles:
    needles = [
        "http://", "https://", "ftp://",
        "powershell", "cmd.exe", "rundll32", "mshta", "wscript", "cscript",
        "schtasks", "bitsadmin", "certutil", "regsvr32",
        "Invoke-", "IEX(", "-enc ", "FromBase64",
        "HKEY_", "CurrentVersion\\Run", "UserInit",
        "mimikatz", "meterpreter", "cobalt", "beacon",
        ".onion", "bitcoin", "ransom", "wallet",
        "psexec", "procexp", "sysinternals", "tcpview", "autoruns",
        "IEUser", "@gmail", "@yahoo", "@hotmail",
        "password", "Password", "C2", "user-agent", "User-Agent",
        ".exe", ".ps1", ".bat", ".vbs", ".js",
        "AppData\\", "\\Temp\\", "Downloads\\",
        "From:", "Subject:", "mailto:",
        "192.168.", "10.0.", "172.16.",
    ]
max_hits = int(args.get("max_hits") or 80)
context = int(args.get("context") or 96)
start = int(args.get("start") or 0)
length = args.get("length")
chunk = int(args.get("chunk") or 8 * 1024 * 1024)
skip_zeros = bool(args.get("skip_zeros", False))
unique_only = bool(args.get("unique_only", True))
if skip_zeros:
    print(json.dumps({
        "error": "skip_zeros would make the scan lossy and is not supported",
        "hint": "omit skip_zeros or pass false",
    }))
    sys.exit(1)

needles_b = []
for n in needles:
    b = n.encode("utf-8", "ignore")
    if b:
        needles_b.append(("ascii", n, b))
        needles_b.append(("utf16", n, n.encode("utf-16le")))
# A read carries the longest needle's length less one, so a hit across a
# boundary is seen once.
overlap = max(256, max((len(nb) - 1 for _, _, nb in needles_b), default=0))

if os.path.isdir(path):
    print(json.dumps({"error": "a directory, not a file: scan one file at a time", "path": path}))
    sys.exit(1)
if not os.path.isfile(path):
    print(json.dumps({"error": "no such file", "path": path}))
    sys.exit(1)
size = os.path.getsize(path)
end = size if length is None else min(size, start + int(length))
hits = LosslessPage(
    "ioc_scan",
    [path, needles, start, end, context, skip_zeros, unique_only],
    max_hits,
)
seen = set()
counts = defaultdict(int)

def add_hit(kind, name, off, blob, local):
    # extract a readable snippet around the match
    i = local
    s = max(0, i - 16)
    e = min(len(blob), i + len(name.encode("utf-8")) + context)
    raw = blob[s:e]
    # prefer ascii printable
    snip = "".join(chr(c) if 32 <= c < 127 else "." for c in raw)
    key = (name.lower(), snip[:80])
    counts[name] += 1
    if unique_only and key in seen:
        return
    if unique_only:
        seen.add(key)
    hits.add({
        "offset": off,
        "needle": name,
        "enc": kind,
        "snippet": snip,
    })

with open(path, "rb") as f:
    f.seek(start)
    pos = start
    prev = b""
    while pos < end:
        want = min(chunk, end - pos)
        data = f.read(want)
        if not data:
            break
        blob = prev + data
        base = pos - len(prev)
        for kind, name, nb in needles_b:
            start_i = 0
            while True:
                i = blob.find(nb, start_i)
                if i < 0:
                    break
                abs_off = base + i
                # Skip only a hit wholly inside the carry. A signature split
                # across the chunk boundary must be counted here.
                if not prev or abs_off + len(nb) > pos:
                    add_hit(kind, name, abs_off, blob, i)
                start_i = i + max(1, len(nb))
        prev = data[-overlap:] if len(data) >= overlap else data
        pos += len(data)

page = hits.finish()
print(json.dumps({
    "path": path,
    "scanned_start": start,
    "scanned_end": end,
    "size": size,
    "hit_count_returned": page["returned"],
    "counts": dict(sorted(counts.items(), key=lambda kv: -kv[1])),
    "hits": hits.page,
    **page,
}, indent=2))
