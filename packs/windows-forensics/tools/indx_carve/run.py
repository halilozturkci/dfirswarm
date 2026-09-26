#!/usr/bin/env python3
"""Recover the names a directory used to hold.

When a file is deleted its entry is removed from the parent directory's index,
but NTFS does not clear what it removed: the index node's live entries shrink
and the bytes past the end stay where they were. That slack holds whole
$FILE_NAME structures — the name, the parent, the four times, the sizes — for
files whose $MFT record may long since have been reused. It is the artefact
that proves what was in a folder before somebody emptied it.

INDX block layout, little-endian:

  0x00  "INDX", update sequence array offset at 0x04 and count at 0x06,
        $LogFile sequence number at 0x08, the node's VCN at 0x10.
  0x18  the node header: offset to the first entry (relative to 0x18),
        total size of the live entries, allocated size, flags.
  entry MFT reference (8), entry length (2), key length (2), flags (2),
        then the $FILE_NAME attribute itself at offset 0x10 of the entry.

Live entries run from the first-entry offset to total-size. From total-size to
allocated-size is the slack, and that is where this tool does its real work: it
walks the region looking for a structure whose parent reference, name length
and namespace are all sane and whose name decodes, and reports each hit with
the byte offset it came from.

The update sequence fixup is applied first. Without it the last two bytes of
every sector are a checksum, and a name that straddles a sector boundary comes
back with two bytes of rubbish in the middle of it.

Every block is read. The page returned inline is `limit` long, and when more
entries match the whole list is written to a file the output names; the same
holds for the problems.
"""
import datetime
import json
import mmap
import os
import re
import struct
import sys

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

FILETIME_EPOCH = datetime.datetime(1601, 1, 1, tzinfo=datetime.timezone.utc)
MAGIC = b"INDX"
NAMESPACE = {0: "POSIX", 1: "Win32", 2: "DOS", 3: "Win32 and DOS"}
FN_FIXED = 0x42          # the $FILE_NAME header, before the name itself


def fail(message, **extra):
    print(json.dumps({"error": message, **extra}))
    raise SystemExit(1)


def filetime(value):
    if not value:
        return None
    try:
        return (FILETIME_EPOCH + datetime.timedelta(microseconds=value // 10)).isoformat().replace("+00:00", "Z")
    except (OverflowError, OSError):
        return None


def apply_fixup(block):
    usa_offset, usa_count = struct.unpack_from("<HH", block, 0x04)
    if usa_count == 0 or usa_offset + usa_count * 2 > len(block):
        return block, "the update sequence array is outside the block"
    signature = block[usa_offset:usa_offset + 2]
    out = bytearray(block)
    for i in range(1, usa_count):
        end = i * 512 - 2
        if end + 2 > len(out):
            return bytes(out), "the block is shorter than its sector count claims"
        if bytes(out[end:end + 2]) != signature:
            return bytes(out), "sector %d does not carry the update sequence number" % i
        out[end:end + 2] = block[usa_offset + i * 2:usa_offset + i * 2 + 2]
    return bytes(out), None


def read_filename(buf, at):
    """The $FILE_NAME attribute content. Returns None when it is not plausibly one."""
    if at + FN_FIXED > len(buf):
        return None
    parent, = struct.unpack_from("<Q", buf, at)
    parent_entry = parent & 0xFFFFFFFFFFFF
    if parent_entry == 0 or parent_entry > 0xFFFFFFFF:
        return None
    created, modified, mft_modified, accessed = struct.unpack_from("<QQQQ", buf, at + 8)
    alloc, real = struct.unpack_from("<QQ", buf, at + 0x28)
    flags, = struct.unpack_from("<I", buf, at + 0x38)
    name_chars = buf[at + 0x40]
    namespace = buf[at + 0x41]
    if not 1 <= name_chars <= 255 or namespace not in NAMESPACE:
        return None
    end = at + FN_FIXED + name_chars * 2
    if end > len(buf):
        return None
    raw = buf[at + FN_FIXED:end]
    try:
        name = raw.decode("utf-16-le")
    except UnicodeDecodeError:
        return None
    if not name or any(ord(c) < 0x20 for c in name):
        return None
    if not any(filetime(v) for v in (created, modified)):
        return None
    return {
        "name": name,
        "namespace": NAMESPACE[namespace],
        "parent_entry": parent_entry,
        "parent_sequence": parent >> 48,
        "created": filetime(created),
        "modified": filetime(modified),
        "mft_modified": filetime(mft_modified),
        "accessed": filetime(accessed),
        "allocated_size": alloc,
        "real_size": real,
        "is_directory": bool(flags & 0x10000000),
        "length": FN_FIXED + name_chars * 2,
    }


def live_entries(block, base_offset):
    """Walk the node's live entries, the ones the directory still lists."""
    out = []
    if len(block) < 0x28:
        return out, 0, 0
    first, total, allocated = struct.unpack_from("<III", block, 0x18)
    start = 0x18 + first
    end = min(0x18 + total, len(block))
    at = start
    while at + 0x10 <= end:
        reference, length, key_length = struct.unpack_from("<QHH", block, at)
        entry_flags, = struct.unpack_from("<H", block, at + 0x0C)
        if length < 0x10 or at + length > len(block):
            break
        if entry_flags & 0x02:                     # the end-of-node marker
            break
        found = read_filename(block, at + 0x10) if key_length else None
        if found:
            found.update({"source": "live", "mft_entry": reference & 0xFFFFFFFFFFFF,
                          "mft_sequence": reference >> 48, "offset": base_offset + at})
            out.append(found)
        at += length
    return out, 0x18 + total, 0x18 + allocated


def carve_slack(block, slack_start, slack_end, base_offset):
    """Past the live entries, look for a $FILE_NAME that still parses.

    Entries sit on 8-byte boundaries, so after a hit the walk goes on from the
    next boundary. Stepping by the name's own length left the walk misaligned
    for every name whose length is not a multiple of 8, and every entry after
    it in the slack was then missed.
    """
    out = []
    at = max(0x18, slack_start)
    at += (-at) % 8
    limit = min(slack_end, len(block))
    while at + FN_FIXED <= limit:
        found = read_filename(block, at)
        if found:
            found.update({"source": "slack", "offset": base_offset + at})
            out.append(found)
            at += found["length"]
            at += (-at) % 8
            continue
        at += 8                                    # entries are 8-byte aligned
    return out


def main():
    try:
        args = json.load(sys.stdin)
    except ValueError as exc:
        fail("arguments are not valid JSON", reason=str(exc))

    path = args.get("path")
    if not isinstance(path, str) or not path:
        fail("path is required: an extracted $I30 stream or a blob to sweep")
    if not os.path.isfile(path):
        fail("no such file", path=path)

    block_size = args.get("block_size", 4096)
    if not isinstance(block_size, int) or isinstance(block_size, bool) or block_size % 512 or block_size < 512:
        fail("block_size must be a multiple of 512", block_size=args.get("block_size"))
    limit = args.get("limit", 500)
    if not isinstance(limit, int) or isinstance(limit, bool) or limit < 1:
        fail("limit must be a positive integer")
    pattern = None
    if args.get("name"):
        try:
            pattern = re.compile(args["name"], re.I)
        except re.error as exc:
            fail("name is not a valid regex", reason=str(exc))

    key = [path, block_size, bool(args.get("slack_only")), args.get("name")]
    entries = LosslessPage("indx_carve", key, limit)
    problems = LosslessPage("indx_carve-problems", key, 40)
    blocks, from_slack = 0, 0

    with open(path, "rb") as fh:
        size = os.fstat(fh.fileno()).st_size
        # Mapped rather than read: a raw blob to sweep can be larger than memory.
        data = mmap.mmap(fh.fileno(), 0, access=mmap.ACCESS_READ) if size else b""
        try:
            at = 0
            while True:
                at = data.find(MAGIC, at)
                if at < 0:
                    break
                block = data[at:at + block_size]
                start_of_block = at
                at += 4
                if len(block) < 0x28:
                    problems.add({"offset": start_of_block, "why": "the block runs past the end of the file"})
                    continue
                fixed, problem = apply_fixup(block)
                if problem:
                    problems.add({"offset": start_of_block, "why": problem})
                blocks += 1
                live, slack_start, slack_end = live_entries(fixed, start_of_block)
                found = live + carve_slack(fixed, slack_start, slack_end, start_of_block)
                for entry in found:
                    if args.get("slack_only") and entry["source"] != "slack":
                        continue
                    if pattern and not pattern.search(entry["name"]):
                        continue
                    entries.add(entry)
                    if entry["source"] == "slack":
                        from_slack += 1
                if not problem:
                    # A block whose fixup holds is a block: the next one starts
                    # after it, not at the next magic. One whose fixup fails may
                    # be a false positive, so the search goes on inside it.
                    at = start_of_block + block_size
        finally:
            if size:
                data.close()

    page = entries.finish()
    problem_page = problems.finish()
    out = {
        "path": path,
        "block_size": block_size,
        "blocks": blocks,
        "entries": entries.page,
        "entry_count": page["matched"],
        "from_slack": from_slack,
        "from_live": page["matched"] - from_slack,
        **page,
        "problems": problems.page,
        "problem_count": problem_page["matched"],
        "note": "A slack entry is a name the directory no longer lists. Its times are $FILE_NAME "
                "times, written by the kernel on create, rename and move, so they are the set a "
                "timestomper does not reach. It does not say the file was deleted: a rename or a "
                "move out of the directory leaves the same trace, and the USN journal tells you "
                "which. See filesystem/journals.",
    }
    if problem_page.get("all_results"):
        out["all_problems"] = problem_page["all_results"]
    print(json.dumps(out, indent=2))


if __name__ == "__main__":
    main()
