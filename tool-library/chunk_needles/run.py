#!/usr/bin/env python3
import json, sys, subprocess, os
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
needles = args.get("needles") or ""
path = args.get("path") or ""
inode = args.get("inode")
context = int(args.get("context") or 60)
max_hits = int(args.get("max_hits") or 20)
chunk = int(args.get("chunk") or 8 * 1024 * 1024)
need_list = [n for n in needles.split("|") if n]
if not need_list:
    print(json.dumps({"error": "needles required, pipe-separated"}))
    sys.exit(1)
variants = []
for n in need_list:
    b = n.encode("utf-8")
    variants.append((n, "ascii", b))
    variants.append((n, "utf16le", n.encode("utf-16le")))

def scan_fh(fh):
    counts = {n: {"ascii": 0, "utf16le": 0} for n in need_list}
    pages = {
        n: LosslessPage("chunk_needles", [path, inode, n, context], max_hits)
        for n in need_list
    }
    overlap = max(1024, max((len(pat) - 1 for _, _, pat in variants), default=0))
    prev = b""
    offset = 0
    while True:
        buf = fh.read(chunk)
        if not buf:
            break
        data = prev + buf
        base = offset - len(prev)
        for n, enc, pat in variants:
            start = 0
            while True:
                i = data.find(pat, start)
                if i < 0:
                    break
                absolute = base + i
                # A hit wholly inside the carry was already counted. A hit
                # that starts in carry but ends in the new chunk is new.
                if prev and absolute + len(pat) <= offset:
                    start = i + 1
                    continue
                counts[n][enc] += 1
                a = max(0, i - context)
                b = min(len(data), i + len(pat) + context)
                snip = data[a:b]
                txt = "".join(chr(c) if 32 <= c < 127 else "." for c in snip)
                pages[n].add({"off": absolute, "enc": enc, "text": txt})
                start = i + 1
        prev = data[-overlap:]
        offset += len(buf)
        if not buf:
            break
    hits = {}
    for n in need_list:
        page = pages[n].finish()
        hits[n] = {**counts[n], "snippets": pages[n].page, **page}
    return hits, offset

if path:
    if not os.path.isfile(path):
        print(json.dumps({"error": f"path not found: {path}"}))
        sys.exit(1)
    with open(path, "rb") as f:
        hits, scanned = scan_fh(f)
    src = path
else:
    if inode is None:
        print(json.dumps({"error": "path or inode required"}))
        sys.exit(1)
    image = args.get("image") or "inputs/SysInternalsCase.E01"
    offset = args.get("offset")
    if not os.path.isfile(image):
        print(json.dumps({"error": f"image not found: {image}"}))
        sys.exit(1)
    cmd = ["icat"]
    if offset is not None:
        cmd += ["-o", str(offset)]
    cmd += [image, str(inode)]
    # Streamed, never held whole: capture_output kept a pagefile's gigabytes
    # in memory until the VM's kernel killed the tool (sixth CTF round).
    import tempfile
    with tempfile.TemporaryFile() as errf:
        proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=errf)
        hits, scanned = scan_fh(proc.stdout)
        rc = proc.wait()
        errf.seek(0)
        err_text = errf.read().decode("utf-8", "replace").strip()
    if rc != 0:
        print(json.dumps({"error": err_text or f"icat exit {rc}", "image": image, "inode": inode, "scanned_bytes": scanned}))
        sys.exit(1)
    src = f"icat:{inode}"
print(json.dumps({"source": src, "scanned_bytes": scanned, "hits": hits}))
