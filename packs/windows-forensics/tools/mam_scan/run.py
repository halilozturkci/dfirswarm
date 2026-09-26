#!/usr/bin/env python3
import json, sys, struct, datetime
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

def ft(v):
    if not v or v in (0, 0xFFFFFFFFFFFFFFFF):
        return None
    try:
        epoch = datetime.datetime(1601, 1, 1, tzinfo=datetime.timezone.utc)
        return (epoch + datetime.timedelta(microseconds=v / 10)).strftime("%Y-%m-%dT%H:%M:%S.%fZ")
    except Exception:
        return None

def utf16_strings(buf, minlen=6):
    out = []
    i = 0
    L = len(buf)
    while i + 2 < L:
        if buf[i + 1] == 0 and 32 <= buf[i] < 127:
            chars = []
            j = i
            while j + 1 < L and buf[j + 1] == 0 and 32 <= buf[j] < 127:
                chars.append(chr(buf[j]))
                j += 2
            if len(chars) >= minlen:
                out.append("".join(chars))
            i = j + 2
        else:
            i += 1
    return out

def try_decompress(payload, uncomp):
    from dissect.util.compression import lzxpress_huffman
    cuts = []
    if payload:
        cuts.append(len(payload))
    for c in (uncomp, uncomp + 8, uncomp + 64, 4096, 8192, 16384, 24576, 32768, 65536, 131072):
        if 8 < c <= len(payload):
            cuts.append(c)
    seen = set()
    for c in cuts:
        if c in seen:
            continue
        seen.add(c)
        try:
            dec = lzxpress_huffman.decompress(payload[:c])
            if dec and (dec[4:8] == b"SCCA" or dec[:4] == b"SCCA"):
                return dec, c
        except Exception:
            continue
    return None, None

def parse_scca(dec, off, blob_sha=None):
    ver = struct.unpack_from("<I", dec, 0)[0]
    name = dec[0x10:0x10 + 60].decode("utf-16le", "replace").split("\x00")[0]
    fsize = struct.unpack_from("<I", dec, 0x0C)[0] if len(dec) >= 16 else 0
    pfhash = struct.unpack_from("<I", dec, 0x4C)[0] if len(dec) >= 0x50 else 0
    times = []
    if len(dec) >= 0x80 + 64:
        for i in range(8):
            iso = ft(struct.unpack_from("<Q", dec, 0x80 + i * 8)[0])
            if iso:
                times.append(iso)
    runc = struct.unpack_from("<I", dec, 0xD0)[0] if len(dec) >= 0xD4 else None
    strs = utf16_strings(dec, 8)
    paths = [s for s in strs if "\\" in s]
    return {
        "offset": off,
        "version": ver,
        "name": name,
        "prefetch_hash": f"{pfhash:08X}",
        "file_size_field": fsize,
        "run_count": runc,
        "last_runs": times,
        "dec_len": len(dec),
        "paths": paths,
        "strings": strs,
    }

def main():
    args = json.loads(sys.stdin.read() or "{}")
    path = args.get("path")
    if not path:
        print(json.dumps({"ok": False, "error": "path is required: the raw dump or image to scan"}))
        raise SystemExit(0)
    start = int(args.get("start") or 0)
    length = args.get("length")
    length = int(length) if length is not None else None
    max_hits = int(args.get("max_hits") or 80)
    chunk = int(args.get("chunk") or 8 * 1024 * 1024)
    parse = bool(args.get("parse", True))
    min_uncomp = int(args.get("min_uncomp") or 1024)
    max_uncomp = int(args.get("max_uncomp") or 2_000_000)
    needle = (args.get("name_filter") or "").upper()
    hits = LosslessPage(
        "mam_scan",
        [path, start, length, parse, min_uncomp, max_uncomp, needle],
        max_hits,
    )
    sig = b"MAM\x04"
    overlap = 8
    with open(path, "rb") as f:
        f.seek(start)
        remaining = length
        pos = start
        carry = b""
        while remaining is None or remaining > 0:
            toread = chunk if remaining is None else min(chunk, remaining)
            data = f.read(toread)
            if not data:
                break
            buf = carry + data
            abs_base = pos - len(carry)
            i = 0
            found = []
            while True:
                j = buf.find(sig, i)
                if j < 0:
                    break
                if j + 8 <= len(buf):
                    uncomp = struct.unpack_from("<I", buf, j + 4)[0]
                    if min_uncomp <= uncomp <= max_uncomp:
                        found.append((abs_base + j, uncomp, j))
                i = j + 4
            for off, uncomp, j in found:
                rec = {"offset": off, "uncomp": uncomp}
                if parse:
                    # take up to uncomp+8*2 or rest of buffer
                    end = min(len(buf), j + max(uncomp + 16, 131072))
                    payload = buf[j + 8:end]
                    # if payload short, read more from file
                    if len(payload) < min(uncomp, 65536):
                        cur = f.tell()
                        f.seek(off + 8)
                        payload = f.read(min(uncomp + 16, 262144))
                        f.seek(cur)
                    dec, cut = try_decompress(payload, uncomp)
                    if dec:
                        rec.update(parse_scca(dec, off))
                        rec["comp_cut"] = cut
                    else:
                        rec["parse_error"] = "decompress_failed"
                if needle:
                    if needle not in (rec.get("name") or "").upper() and needle not in " ".join(rec.get("paths") or []).upper():
                        continue
                hits.add(rec)
            pos += len(data)
            if remaining is not None:
                remaining -= len(data)
            carry = buf[-(overlap - 1):] if len(buf) >= overlap else buf
            if not data or len(data) < toread:
                break
    page = hits.finish()
    json.dump({"count": page["matched"], "hits": hits.page, "scanned_to": pos, **page}, sys.stdout)

if __name__ == "__main__":
    main()
