import sys, json, hashlib, os, struct
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

# Read input
inp = json.load(sys.stdin)
path = inp.get("path", "")
sig_name = inp.get("sig", "")  # specific sig or "all"
context = inp.get("context", 64)
max_hits = inp.get("max_hits", 500)

# File signatures: name -> (header_hex, footer_hex_or_none, min_size, max_size)
SIGS = {
    "MZ":    ("4D5A", None, 64, 50*1024*1024),     # PE/DOS executable
    "PK":    ("504B0304", None, 32, 200*1024*1024), # ZIP/DOCX/XLSX
    "regf":  ("72656766", None, 4096, 200*1024*1024), # Registry hive
    "MAM":   ("4D414D", None, 1024, 50*1024*1024),  # MAM prefetch
    "SCCA":  ("53434341", None, 1024, 50*1024*1024), # SCCA prefetch
    "EVTX":  ("456C6646696C6500", None, 4096, 200*1024*1024), # EVTX event log
    "OLE":   ("D0CF11E0A1B11AE1", None, 512, 100*1024*1024),  # OLE2/Office
    "LNK":   ("4C0000000114020000000000C000000000000046", None, 512, 64*1024), # LNK
    "SQLite":("53514C69746520666F726D6174203300", None, 512, 100*1024*1024), # SQLite
    "RAR":   ("526172211A0700", None, 32, 100*1024*1024),  # RAR
    "7z":    ("377ABCAF271C", None, 32, 100*1024*1024),    # 7-zip
    "GZ":    ("1F8B08", None, 32, 100*1024*1024),          # gzip
    "BZ2":   ("425A68", None, 32, 100*1024*1024),          # bzip2
    "PDF":   ("255044462D", None, 64, 50*1024*1024),       # PDF
    "PNG":   ("89504E470D0A1A0A", None, 64, 50*1024*1024), # PNG
    "JFIF":  ("FFD8FFE0", "FFD9", 64, 20*1024*1024),       # JPEG
    "PCH":   ("4D414D04", None, 1024, 50*1024*1024),       # MAM v2 prefetch
}

def hex_to_bytes(h):
    return bytes.fromhex(h)

def scan_file(filepath, sig_defs, context, max_hits):
    results = {}
    file_size = os.path.getsize(filepath)
    
    # Read the file in chunks to find signatures
    # For efficiency, read whole file in streaming mode
    CHUNK = 64 * 1024 * 1024  # 64MB chunks
    
    with open(filepath, 'rb') as f:
        for name, (header_hex, footer_hex, minsize, maxsize) in sig_defs.items():
            header = hex_to_bytes(header_hex)
            hits = LosslessPage("sig_carve-" + name, [filepath, name], max_hits)
            
            f.seek(0)
            offset = 0
            overlap = len(header) - 1
            buf = b''
            
            while offset < file_size:
                f.seek(offset)
                chunk = f.read(CHUNK + overlap)
                if not chunk:
                    break
                
                buf = buf[-overlap:] + chunk if buf else chunk
                
                pos = 0
                while True:
                    idx = buf.find(header, pos)
                    if idx == -1:
                        break
                    abs_offset = offset + idx - (overlap if offset > 0 else 0)
                    if abs_offset >= 0:
                        # Get context bytes
                        f.seek(max(0, abs_offset - 16))
                        ctx = f.read(context + 16 + len(header))
                        ctx_start = min(16, abs_offset)
                        ctx_snippet = ctx[ctx_start:ctx_start + context]
                        
                        hits.add({
                            "offset": abs_offset,
                            "hex_preview": ctx_snippet[:32].hex(' '),
                            "ascii_preview": ''.join(chr(b) if 32<=b<127 else '.' for b in ctx_snippet[:64])
                        })
                    pos = idx + 1
                
                offset += CHUNK
            page = hits.finish()
            results[name] = {
                "count": page["matched"],
                "hits": hits.page,
                **page,
            }
    
    return results

if sig_name and sig_name != "all":
    sigs_to_scan = {sig_name: SIGS[sig_name]} if sig_name in SIGS else {}
else:
    sigs_to_scan = SIGS

results = scan_file(path, sigs_to_scan, context, max_hits)
print(json.dumps(results, indent=2))
