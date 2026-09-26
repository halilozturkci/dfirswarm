#!/usr/bin/env python3
"""Parse a Windows $Recycle.Bin $I metadata file.

Three of the measured cases did this by hand with `xxd` and arithmetic, which
is exactly the kind of work a tool should absorb: the format is fixed and
small, and getting the FILETIME conversion wrong by an hour is easy and
invisible.

$I layout (Vista and later):
  0x00  8  header: 1 (Vista/7) or 2 (8 and later)
  0x08  8  original file size, little-endian
  0x10  8  deletion time, FILETIME (100 ns since 1601-01-01 UTC)
  0x18     header 1: 520 bytes, UTF-16LE path, NUL padded
           header 2: 4-byte character count, then that many UTF-16LE chars
"""
import datetime
import json
import os
import struct
import sys
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
        name = f"{self.tool}-{digest}.jsonl"
        job, out = os.environ.get("JOB_ID"), os.environ.get("OUT")
        if job and out:
            # In a job only $OUT is written, and it is sealed as the job's
            # output: the whole result is cited from there.
            self.path = Path(out) / "tool-output" / name
            self.shown = "store/jobs/%s/out/tool-output/%s" % (re.sub(r"[^A-Za-z0-9_.-]", "_", job), name)
        else:
            agent = re.sub(
                r"[^A-Za-z0-9_.-]", "_", os.environ.get("AGENT_ID") or "tool"
            )
            self.path = Path("work") / agent / "tool-output" / name
            self.shown = str(self.path)

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
            result["all_results"] = self.shown
            result["all_results_format"] = "JSON Lines, one complete result per line"
        return result

FILETIME_EPOCH = datetime.datetime(1601, 1, 1, tzinfo=datetime.timezone.utc)


def fail(message, **extra):
    print(json.dumps({"error": message, **extra}))
    raise SystemExit(1)


def filetime(value):
    if value <= 0:
        return None
    try:
        return (FILETIME_EPOCH + datetime.timedelta(microseconds=value // 10)).isoformat().replace("+00:00", "Z")
    except OverflowError:
        return None


def parse(data, name):
    if len(data) < 0x18:
        return {"file": name, "error": f"too short: {len(data)} bytes, need at least 24"}
    header, size, deleted = struct.unpack_from("<qqq", data, 0)
    entry = {
        "file": name,
        "header_version": header,
        "original_size": size,
        "deleted_at": filetime(deleted),
        "deleted_filetime": deleted,
    }
    if header == 1:
        raw = data[0x18:0x18 + 520]
        entry["original_path"] = raw.decode("utf-16-le", "replace").split("\x00", 1)[0]
    elif header == 2:
        if len(data) < 0x1C:
            entry["error"] = "header 2 with no path length"
            return entry
        chars = struct.unpack_from("<I", data, 0x18)[0]
        raw = data[0x1C:0x1C + chars * 2]
        entry["original_path"] = raw.decode("utf-16-le", "replace").split("\x00", 1)[0]
    else:
        # An unknown header is not a reason to guess: say so and stop, rather
        # than decoding whatever happens to be at 0x18.
        entry["error"] = f"unknown header version {header}; the path was not decoded"
    return entry


def main():
    try:
        args = json.load(sys.stdin)
    except ValueError as exc:
        fail("arguments are not valid JSON", reason=str(exc))

    path = args.get("path")
    if not isinstance(path, str) or not path:
        fail("path is required: a $I file, or a directory holding them")

    targets = []
    if os.path.isdir(path):
        for root, _dirs, names in os.walk(path):
            for name in sorted(names):
                if name.startswith("$I"):
                    targets.append(os.path.join(root, name))
    elif os.path.isfile(path):
        targets = [path]
    else:
        fail("no such file or directory", path=path)

    if not targets:
        fail("no $I files under that directory", path=path)

    limit = args.get("limit", 500)
    if not isinstance(limit, int) or isinstance(limit, bool) or limit < 1:
        fail("limit must be a positive integer", limit=args.get("limit"))

    entries = LosslessPage("recyclebin_i", [path], limit)
    for target in targets:
        try:
            with open(target, "rb") as fh:
                data = fh.read(4096)
        except OSError as exc:
            entries.add({"file": target, "error": str(exc)})
            continue
        entries.add(parse(data, target))

    page = entries.finish()
    print(json.dumps({
        "entries": entries.page,
        "entry_count": page["matched"],
        "found": len(targets),
        **page,
    }, indent=2))


if __name__ == "__main__":
    main()
