import json, sys, re, struct, datetime
from pathlib import Path
from dissect.util.compression import lzxpress_huffman

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


def filetime_to_iso(ft):
    if not ft:
        return None
    dt = datetime.datetime(1601,1,1) + datetime.timedelta(microseconds=ft/10)
    return dt.isoformat() + 'Z'


def parse_prefetch(data):
    compressed = False
    declared_uncompressed_size = None
    if data[:4] == b'MAM\x04':
        compressed = True
        declared_uncompressed_size = struct.unpack_from('<I', data, 4)[0]
        data = lzxpress_huffman.decompress(data[8:])
    if data[4:8] != b'SCCA':
        raise SystemExit('not a Windows Prefetch file after optional MAM decompression')
    version = struct.unpack_from('<I', data, 0)[0]
    file_size = struct.unpack_from('<I', data, 12)[0]
    exe_name = data[16:76].decode('utf-16le', 'ignore').rstrip('\x00')
    last_runs = []
    for off in range(0x80, 0xC0, 8):
        if off + 8 <= len(data):
            ft = struct.unpack_from('<Q', data, off)[0]
            if ft:
                last_runs.append(filetime_to_iso(ft))
    strings = []
    for m in re.finditer(rb'(?:[ -~]\x00){4,}', data):
        s = m.group().decode('utf-16le', 'ignore')
        if any(c.isalpha() for c in s):
            strings.append(s)
    seen = set()
    uniq = []
    for s in strings:
        if s not in seen:
            seen.add(s)
            uniq.append(s)
    paths = [s for s in uniq if '\\' in s or '/' in s]
    return {
        'compressed': compressed,
        'declared_uncompressed_size': declared_uncompressed_size,
        'decompressed_size': len(data),
        'version': version,
        'file_size_field': file_size,
        'exe_name': exe_name,
        'last_runs': last_runs,
        'all_strings': uniq,
        'paths': paths,
    }


def main():
    args = json.load(sys.stdin)
    path = args['path']
    max_strings = int(args.get('max_strings', 50))
    data = Path(path).read_bytes()
    res = parse_prefetch(data)
    strings = LosslessPage("prefetch_mam-strings", [path], max_strings)
    for value in res['all_strings']:
        strings.add(value)
    paths = LosslessPage("prefetch_mam-paths", [path], max_strings)
    for value in res['paths']:
        paths.add(value)
    res['all_strings'] = strings.page
    res['all_strings_page'] = strings.finish()
    res['paths'] = paths.page
    res['paths_page'] = paths.finish()
    print(json.dumps(res, indent=2))

if __name__ == '__main__':
    main()
