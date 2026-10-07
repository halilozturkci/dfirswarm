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

Integrity travels with every entry. A block is `fixup_ok` when every 512-byte unit
carries its update sequence number and the array covers the whole block, and `node_ok`
when the node header and each live entry's length, alignment and key length fit inside
the live region. An entry carries its `block_offset` and `salvaged` (true when either
check failed). A salvaged block's entries are left out of the answer unless
`include_unreliable` is true, and the answer counts the blocks and entries it left out.
A name that parses is structurally plausible (a sane parent, a decodable name, a known
namespace, a valid time), not verified.
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

    def _cannot_write(self, exc: BaseException) -> None:
        """The whole result cannot be kept: say so as JSON and stop, never a traceback."""
        import sys as _sys
        _sys.stdout.write(json.dumps({
            "error": "the whole result (%d rows so far) cannot be written to %s: %s. Outside a job the place is your own "
                     "work/<your id>/ directory; in a job it is $OUT." % (self.total, self.shown, exc),
            "status": "failed",
        }) + "\n")
        _sys.exit(1)

    def _write(self, row: object) -> None:
        assert self._out is not None
        text = json.dumps(row, ensure_ascii=False, default=str)
        try:
            text.encode("utf-8")
        except UnicodeEncodeError:
            # A lone surrogate (a file name that is not UTF-8): escape it, lose nothing.
            text = json.dumps(row, ensure_ascii=True, default=str)
        try:
            self._out.write(text)
            self._out.write("\n")
        except OSError as exc:
            self._cannot_write(exc)

    def add(self, row: object) -> None:
        self.total += 1
        if len(self.page) < self.limit:
            self.page.append(row)
            return
        if self._out is None:
            try:
                self.path.parent.mkdir(parents=True, exist_ok=True)
                fd, name = tempfile.mkstemp(
                    dir=self.path.parent, prefix=f".{self.path.name}-"
                )
                self._tmp = Path(name)
                self._out = os.fdopen(fd, "w", encoding="utf-8")
            except OSError as exc:
                self._cannot_write(exc)
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
            try:
                self._out.flush()
                os.fsync(self._out.fileno())
                self._out.close()
                assert self._tmp is not None
                os.replace(self._tmp, self.path)
            except OSError as exc:
                self._cannot_write(exc)
            result["all_results"] = self.shown
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
    """ISO 8601 UTC with seven fractional digits, by integer arithmetic; None for 0 or a date past 9999."""
    if not value:
        return None
    try:
        whole, ticks = divmod(value, 10_000_000)
        return (FILETIME_EPOCH + datetime.timedelta(seconds=whole)).strftime("%Y-%m-%dT%H:%M:%S") + ".%07dZ" % ticks
    except (OverflowError, ValueError, OSError):
        return None


def apply_fixup(block):
    """Undo the update sequence fixup of a 512-byte-unit record: the last two bytes of each unit hold the
    sequence number, and the real bytes are in the array. Returns the fixed block and a problem or None.
    The array must cover the whole block."""
    usa_offset, usa_count = struct.unpack_from("<HH", block, 0x04)
    if usa_count == 0 or usa_offset + usa_count * 2 > len(block):
        return block, "the update sequence array is outside the block"
    units = len(block) // 512
    if usa_count - 1 != units:
        return block, "the update sequence array holds %d fixup value(s) and the block has %d 512-byte unit(s)" % (usa_count - 1, units)
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


def read_filename(buf, at, key_end=None, strict=True):
    """The $FILE_NAME attribute content at `at`, as (found, why). `found` is None when it is not plausibly one, and
    `why` says what failed. `key_end` bounds the name to the index entry's own key; `strict` adds the plausibility rules
    a search of slack needs (a parent that is a real entry, a believable time) and a live entry, which the node walk
    has already placed, does not: its odd values are kept and flagged `unreliable` with the reasons."""
    limit = len(buf) if key_end is None else min(key_end, len(buf))
    if at + FN_FIXED > limit:
        return None, "the key holds %d bytes, fewer than the %d a $FILE_NAME header needs" % (max(limit - at, 0), FN_FIXED)
    parent, = struct.unpack_from("<Q", buf, at)
    parent_entry = parent & 0xFFFFFFFFFFFF
    created, modified, mft_modified, accessed = struct.unpack_from("<QQQQ", buf, at + 8)
    alloc, real = struct.unpack_from("<QQ", buf, at + 0x28)
    flags, = struct.unpack_from("<I", buf, at + 0x38)
    name_chars = buf[at + 0x40]
    namespace = buf[at + 0x41]
    if not 1 <= name_chars <= 255:
        return None, "the name length is %d characters" % name_chars
    if namespace not in NAMESPACE:
        return None, "the namespace byte is %d" % namespace
    end = at + FN_FIXED + name_chars * 2
    if end > limit:
        return None, "the name is %d characters (%d bytes from the start of the key) and the key holds %d" % (
            name_chars, FN_FIXED + name_chars * 2, max(limit - at, 0))
    raw = buf[at + FN_FIXED:end]
    try:
        name = raw.decode("utf-16-le")
    except UnicodeDecodeError:
        return None, "the name is not valid UTF-16"
    if not name or any(ord(c) < 0x20 for c in name):
        return None, "the name holds a control character"
    reasons = []
    if parent_entry == 0 or parent_entry > 0xFFFFFFFF:
        reasons.append("the parent reference (entry %d) is not a believable directory" % parent_entry)
    if not any(filetime(v) for v in (created, modified)):
        reasons.append("the created and modified times are both 0, all ones or past the year 9999")
    if strict and reasons:
        return None, "; ".join(reasons)
    found = {
        "name": name,
        "namespace": NAMESPACE[namespace],
        "parent_entry": parent_entry,
        "parent_sequence": parent >> 48,
        "created": filetime(created),
        "modified": filetime(modified),
        "mft_modified": filetime(mft_modified),
        "accessed": filetime(accessed),
        "created_filetime": str(created),
        "modified_filetime": str(modified),
        "mft_modified_filetime": str(mft_modified),
        "accessed_filetime": str(accessed),
        "allocated_size": alloc,
        "real_size": real,
        "is_directory": bool(flags & 0x10000000),
        "length": FN_FIXED + name_chars * 2,
    }
    if reasons:
        found["unreliable"] = True
        found["unreliable_reasons"] = reasons
    return found, None


def node_problems(block):
    """The node header's own consistency: the first entry, the live total and the allocated size must
    be ordered, 8-byte aligned and inside the block. Returns a problem or None."""
    if len(block) < 0x28:
        return "the block is shorter than a node header"
    first, total, allocated = struct.unpack_from("<III", block, 0x18)
    if first < 0x10 or first % 8 or total < first or allocated < total or 0x18 + allocated > len(block) or total % 8:
        return ("the node header is inconsistent (first entry %d, live size %d, allocated size %d, block %d bytes)"
                % (first, total, allocated, len(block)))
    return None


def live_entries(block, base_offset):
    """Walk the node's live entries, the ones the directory still lists. Every length is checked against
    the live region and the key length against the entry: the first entry that does not fit is a problem,
    named, and the walk of this node's live entries ends there."""
    out, problems, unreadable = [], [], []
    if len(block) < 0x28:
        return out, 0, 0, problems, unreadable
    first, total, allocated = struct.unpack_from("<III", block, 0x18)
    start = 0x18 + first
    end = min(0x18 + total, len(block))
    at = start
    while at + 0x10 <= end:
        reference, length, key_length = struct.unpack_from("<QHH", block, at)
        entry_flags, = struct.unpack_from("<H", block, at + 0x0C)
        if length < 0x10 or length % 8 or at + length > end or key_length > length - 0x10:
            problems.append("the live entry at block offset %d has a length (%d) or key length (%d) that does not fit the live region"
                            % (at, length, key_length))
            break
        if entry_flags & 0x02:                     # the end-of-node marker
            break
        if key_length:
            found, why = read_filename(block, at + 0x10, key_end=at + 0x10 + key_length, strict=False)
        else:
            found, why = None, "the entry has no key"
        if found:
            found.update({"source": "live", "mft_entry": reference & 0xFFFFFFFFFFFF,
                          "mft_sequence": reference >> 48, "offset": base_offset + at})
            out.append(found)
        else:
            unreadable.append({"offset": base_offset + at, "mft_entry": reference & 0xFFFFFFFFFFFF,
                               "mft_sequence": reference >> 48, "why": why})
        at += length
    return out, 0x18 + total, 0x18 + allocated, problems, unreadable


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
        found, _ = read_filename(block, at)
        if found:
            found.update({"source": "slack", "offset": base_offset + at})
            out.append(found)
            at += found["length"]
            at += (-at) % 8
            continue
        at += 8                                    # entries are 8-byte aligned
    return out


def run(args):
    path = args.get("path")
    if not isinstance(path, str) or not path:
        fail("path is required: an extracted $I30 stream or a blob to sweep")
    if not os.path.isfile(path):
        if os.path.exists(path):
            fail("not a regular file: it is not opened", path=path, not_attempted=1)
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

    include_unreliable = args.get("include_unreliable", False)
    if not isinstance(include_unreliable, bool):
        fail("include_unreliable must be true or false")

    key = [path, block_size, bool(args.get("slack_only")), args.get("name"), include_unreliable]
    entries = LosslessPage("indx_carve", key, limit)
    problems = LosslessPage("indx_carve-problems", key, 40)
    blocks, from_slack = 0, 0
    blocks_fixup_failed = blocks_salvaged = excluded = 0
    live_unreadable_count = live_flagged = 0

    try:
        fh = open(path, "rb")
        size = os.fstat(fh.fileno()).st_size
        # Mapped rather than read: a raw blob to sweep can be larger than memory.
        data = mmap.mmap(fh.fileno(), 0, access=mmap.ACCESS_READ) if size else b""
    except (OSError, ValueError) as exc:
        fail("could not read the file", path=path, reason=str(exc))
    with fh:
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
                    blocks_fixup_failed += 1
                blocks += 1
                node_problem = node_problems(fixed) if not problem else None
                if node_problem:
                    problems.add({"offset": start_of_block, "why": node_problem})
                live, slack_start, slack_end, live_problems, live_unreadable = live_entries(fixed, start_of_block)
                for why in live_problems:
                    problems.add({"offset": start_of_block, "why": why})
                for lost in live_unreadable:
                    live_unreadable_count += 1
                    problems.add({"offset": lost["offset"], "block_offset": start_of_block,
                                  "why": "a live entry (MFT entry %d, sequence %d) was not read as a name: %s"
                                         % (lost["mft_entry"], lost["mft_sequence"], lost["why"])})
                live_flagged += sum(1 for e in live if e.get("unreliable"))
                salvaged = bool(problem or node_problem or live_problems)
                if salvaged:
                    blocks_salvaged += 1
                found = live + carve_slack(fixed, slack_start, slack_end, start_of_block)
                for entry in found:
                    if args.get("slack_only") and entry["source"] != "slack":
                        continue
                    if pattern and not pattern.search(entry["name"]):
                        continue
                    entry.update({"block_offset": start_of_block, "fixup_ok": problem is None,
                                  "node_ok": not (node_problem or live_problems), "salvaged": salvaged})
                    if salvaged and not include_unreliable:
                        excluded += 1
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
        "parser": "indx_carve/3",
        "status": "partial" if (blocks_salvaged or live_unreadable_count) else "complete",
        "path": path,
        "block_size": block_size,
        "blocks": blocks,
        "blocks_fixup_failed": blocks_fixup_failed,
        "blocks_salvaged": blocks_salvaged,
        "include_unreliable": include_unreliable,
        "entries_excluded_unreliable": excluded,
        "live_entries_unreadable": live_unreadable_count,
        "live_entries_flagged_unreliable": live_flagged,
        "entries": entries.page,
        "entry_count": page["matched"],
        "from_slack": from_slack,
        "from_live": page["matched"] - from_slack,
        **page,
        "problems": problems.page,
        "problem_count": problem_page["matched"],
        "note": "A slack entry is stale index material: a $FILE_NAME as the directory's index held it when the entry "
                "was removed or the node rewritten. Its times are that structure's historical metadata, not the file's "
                "current times and not evidence that they were left unaltered, and a name that parses is structurally "
                "plausible, not verified. It does not say the file was deleted: a rename or a move out of the directory "
                "leaves the same trace; the USN journal and the $MFT record, where one survives, can corroborate. "
                + ("%d block(s) failed an integrity check (see problems): their entries are %s. " % (
                    blocks_salvaged, "included and marked salvaged" if include_unreliable else
                    "left out (%d), unless include_unreliable is true" % excluded) if blocks_salvaged else "")
                + ("%d live entry(ies) were walked but could not be read as a name (see problems: each says why, with its MFT "
                   "reference), and none is dropped silently. " % live_unreadable_count if live_unreadable_count else "")
                + ("%d live entry(ies) carry values that are odd (a parent that is not a believable directory, no believable time): "
                   "they are returned, flagged unreliable with the reasons. " % live_flagged if live_flagged else "")
                + "See filesystem/journals.",
    }
    if problem_page.get("all_results"):
        out["all_problems"] = problem_page["all_results"]
    print(json.dumps(out, indent=2))


def main():
    try:
        args = json.load(sys.stdin)
    except ValueError as exc:
        fail("arguments are not valid JSON", reason=str(exc))
    if not isinstance(args, dict):
        fail("arguments must be a JSON object")
    try:
        run(args)
    except OSError as exc:
        fail("the file could not be read", reason=str(exc))


if __name__ == "__main__":
    main()
