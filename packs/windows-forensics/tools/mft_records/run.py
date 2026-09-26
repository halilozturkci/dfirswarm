#!/usr/bin/env python3
"""Read $MFT records directly, because istat answers one inode at a time.

The published runs kept needing the same three things and had no tool for any
of them: both time sets side by side for a whole directory, the bytes of a
resident file that is too small to have clusters, and every named stream on a
volume in one pass. Each was being done by hand with icat and arithmetic, and
the arithmetic is where the errors were.

Layout, all little-endian (Microsoft's own on-disk format):

  record   "FILE" magic, update sequence array at 0x04/0x06, sequence at 0x10,
           first attribute at 0x14, flags at 0x16 (1 in use, 2 directory),
           used size 0x18, allocated size 0x1C, base record 0x20, number 0x2C.
  attr     type 0x00, length 0x04, non-resident 0x08, name length 0x09,
           name offset 0x0A, id 0x0E; resident content at 0x14 for 0x10 bytes;
           non-resident allocated 0x28, real 0x30, initialised 0x38.
  $SI 0x10 created, modified, mft-modified, accessed, each a FILETIME.
  $FN 0x30 parent reference, the same four times, allocated and real size,
           name length in characters at 0x40, namespace 0x41, name UTF-16LE.

The update sequence array is not decoration: the last two bytes of every sector
in the record are held in it, and a parser that skips the fixup reads two bytes
of checksum in the middle of a timestamp. That is the classic silent corruption
in hand-rolled MFT code, so it is applied here first and a record whose fixup
does not match is reported as unreliable rather than parsed.

Every record is read. The page returned inline is `limit` long, and when more
records match the whole list is written to a file the output names. A record
too damaged to parse is listed as a problem with its offset, and the sweep goes
on to the next one.
"""
import base64
import datetime
import json
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
STANDARD_INFORMATION = 0x10
ATTRIBUTE_LIST = 0x20
FILE_NAME = 0x30
OBJECT_ID = 0x40
DATA = 0x80
INDEX_ROOT = 0x90
INDEX_ALLOCATION = 0xA0
END = 0xFFFFFFFF

NAMESPACE = {0: "POSIX", 1: "Win32", 2: "DOS", 3: "Win32 and DOS"}
# Whole-second timestamps are left off this set on purpose: modern stompers write
# arbitrary sub-second values, so the old tell is noise and would swamp the filter.
STOMP_FLAGS = {"si_created_before_fn_created", "si_modified_before_si_created",
               "si_times_identical"}
SI_FLAGS = [
    (0x0001, "read_only"), (0x0002, "hidden"), (0x0004, "system"),
    (0x0020, "archive"), (0x0040, "device"), (0x0080, "normal"),
    (0x0100, "temporary"), (0x0200, "sparse"), (0x0400, "reparse_point"),
    (0x0800, "compressed"), (0x1000, "offline"), (0x2000, "not_indexed"),
    (0x4000, "encrypted"),
]


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


def times(buf, off):
    """The four FILETIMEs $SI and $FN both start with, in the same order."""
    created, modified, mft_modified, accessed = struct.unpack_from("<QQQQ", buf, off)
    return {
        "created": filetime(created),
        "modified": filetime(modified),
        "mft_modified": filetime(mft_modified),
        "accessed": filetime(accessed),
        "raw": [created, modified, mft_modified, accessed],
    }


def apply_fixup(record):
    """Put the update sequence array's bytes back where the sectors' ends belong."""
    usa_offset, usa_count = struct.unpack_from("<HH", record, 0x04)
    if usa_count == 0 or usa_offset + usa_count * 2 > len(record):
        return record, "the update sequence array is outside the record"
    signature = record[usa_offset:usa_offset + 2]
    out = bytearray(record)
    for i in range(1, usa_count):
        end = i * 512 - 2
        if end + 2 > len(out):
            return bytes(out), "the record is shorter than its sector count claims"
        if bytes(out[end:end + 2]) != signature:
            return bytes(out), "sector %d does not carry the update sequence number" % i
        out[end:end + 2] = record[usa_offset + i * 2:usa_offset + i * 2 + 2]
    return bytes(out), None


def attributes(record, first):
    """Walk the attribute chain, stopping on anything that does not advance."""
    offset = first
    while offset + 4 <= len(record):
        atype = struct.unpack_from("<I", record, offset)[0]
        if atype == END:
            return
        if offset + 16 > len(record):
            return
        length = struct.unpack_from("<I", record, offset + 4)[0]
        if length < 16 or offset + length > len(record):
            return
        yield atype, offset, length
        offset += length


def attribute_name(record, offset):
    name_len = record[offset + 9]
    if not name_len:
        return ""
    name_off = struct.unpack_from("<H", record, offset + 0x0A)[0]
    raw = record[offset + name_off:offset + name_off + name_len * 2]
    return raw.decode("utf-16-le", "replace")


def parse_record(record, number_hint, want_resident):
    if record[:4] == b"\x00" * 4:
        return None
    if record[:4] not in (b"FILE", b"BAAD"):
        return None
    fixed, fixup_problem = apply_fixup(record)
    sequence, = struct.unpack_from("<H", fixed, 0x10)
    first_attr, flags = struct.unpack_from("<HH", fixed, 0x14)
    used, allocated = struct.unpack_from("<II", fixed, 0x18)
    base_ref, = struct.unpack_from("<Q", fixed, 0x20)
    number, = struct.unpack_from("<I", fixed, 0x2C)
    entry = {
        "entry": number if number else number_hint,
        "entry_from_record": bool(number),
        "sequence": sequence,
        "in_use": bool(flags & 0x01),
        "is_directory": bool(flags & 0x02),
        "used_bytes": used,
        "allocated_bytes": allocated,
        "base_record": (base_ref & 0xFFFFFFFFFFFF) if base_ref else None,
        "names": [],
        "data_streams": [],
        "flags": [],
    }
    if record[:4] == b"BAAD":
        entry["flags"].append("record_marked_bad")
    if fixup_problem:
        entry["flags"].append("fixup_failed")
        entry["fixup_problem"] = fixup_problem
        entry["unreliable"] = True

    for atype, offset, length in attributes(fixed, first_attr):
        non_resident = fixed[offset + 8]
        if atype == STANDARD_INFORMATION and not non_resident:
            content = struct.unpack_from("<H", fixed, offset + 0x14)[0]
            if offset + content + 0x24 <= len(fixed):
                entry["standard_information"] = times(fixed, offset + content)
                dos, = struct.unpack_from("<I", fixed, offset + content + 0x20)
                entry["standard_information"]["attributes"] = [n for bit, n in SI_FLAGS if dos & bit]
        elif atype == FILE_NAME and not non_resident:
            content = struct.unpack_from("<H", fixed, offset + 0x14)[0]
            base = offset + content
            if base + 0x42 > len(fixed):
                continue
            parent, = struct.unpack_from("<Q", fixed, base)
            name_chars = fixed[base + 0x40]
            namespace = fixed[base + 0x41]
            raw = fixed[base + 0x42:base + 0x42 + name_chars * 2]
            fn = times(fixed, base + 0x08)
            alloc, real = struct.unpack_from("<QQ", fixed, base + 0x28)
            fn.update({
                "name": raw.decode("utf-16-le", "replace"),
                "namespace": NAMESPACE.get(namespace, str(namespace)),
                "parent_entry": parent & 0xFFFFFFFFFFFF,
                "parent_sequence": parent >> 48,
                "allocated_size": alloc,
                "real_size": real,
            })
            entry["names"].append(fn)
        elif atype == DATA:
            stream = {"name": attribute_name(fixed, offset), "resident": not non_resident}
            if non_resident:
                alloc, real, init = struct.unpack_from("<QQQ", fixed, offset + 0x28)
                stream.update({"allocated_size": alloc, "real_size": real, "initialised_size": init})
                if real and not init:
                    entry["flags"].append("zero_initialised_size")
            else:
                size, content = struct.unpack_from("<IH", fixed, offset + 0x10)
                stream["real_size"] = size
                if want_resident and offset + content + size <= len(fixed):
                    data = fixed[offset + content:offset + content + size]
                    stream["content_base64"] = base64.b64encode(data).decode("ascii")
            entry["data_streams"].append(stream)
        elif atype in (INDEX_ROOT, INDEX_ALLOCATION):
            entry.setdefault("index_attributes", []).append(attribute_name(fixed, offset) or "$I30")
        elif atype == ATTRIBUTE_LIST:
            entry["flags"].append("has_attribute_list")

    entry["ads"] = [s["name"] for s in entry["data_streams"] if s["name"]]
    si = entry.get("standard_information")
    fns = entry["names"]
    if si and fns:
        best = max(fns, key=lambda f: 0 if f["namespace"] == "DOS" else 1)
        entry["file_name_times_source"] = best["name"]
        # $FN is written by the kernel on create, rename and move; $SI is what the
        # public API changes. Report a disagreement, never call it proof on its own.
        if si["raw"][0] and best["raw"][0] and si["raw"][0] < best["raw"][0]:
            entry["flags"].append("si_created_before_fn_created")
        if si["raw"][1] and si["raw"][0] and si["raw"][1] < si["raw"][0]:
            entry["flags"].append("si_modified_before_si_created")
        if all(si["raw"][:4]) and len(set(si["raw"][:4])) == 1:
            entry["flags"].append("si_times_identical")
        if si["raw"][0] and all(v % 10000000 == 0 for v in si["raw"][:4] if v):
            entry["flags"].append("si_times_whole_seconds")
    entry["primary_name"] = entry.get("file_name_times_source")
    return entry


def detect_record_size(fh, size):
    """Records are 1024 on almost every volume; measure rather than assume.

    The first two FILE magics are looked for through the whole file, not a
    first window: a slice of an $MFT can open with a run of zeroed records.
    """
    fh.seek(0)
    hits, carry, base = [], b"", 0
    while len(hits) < 2:
        block = fh.read(1 << 20)
        if not block:
            break
        buf = carry + block
        at = buf.find(b"FILE")
        while at >= 0 and len(hits) < 2:
            if not hits or base + at >= hits[-1] + 4:
                hits.append(base + at)
            at = buf.find(b"FILE", at + 1)
        carry = buf[-3:]
        base += len(buf) - len(carry)
    if not hits:
        return None
    if len(hits) < 2:
        return 1024
    gap = hits[1] - hits[0]
    return gap if gap in (256, 512, 1024, 2048, 4096) else 1024


def main():
    try:
        args = json.load(sys.stdin)
    except ValueError as exc:
        fail("arguments are not valid JSON", reason=str(exc))

    path = args.get("path")
    if not isinstance(path, str) or not path:
        fail("path is required: an extracted $MFT")
    if not os.path.isfile(path):
        fail("no such file", path=path)

    limit = args.get("limit", 200)
    if not isinstance(limit, int) or isinstance(limit, bool) or limit < 1:
        fail("limit must be a positive integer", limit=args.get("limit"))

    pattern = None
    if args.get("name"):
        try:
            pattern = re.compile(args["name"], re.I)
        except re.error as exc:
            fail("name is not a valid regex", reason=str(exc))

    want_entry = args.get("entry")
    if want_entry is not None and (not isinstance(want_entry, int) or isinstance(want_entry, bool)):
        fail("entry must be a record number")

    size = os.path.getsize(path)
    with open(path, "rb") as fh:
        record_size = args.get("record_size") or detect_record_size(fh, size)
        if not record_size:
            fail("no FILE record found; this does not look like an $MFT", path=path, bytes=size)
        if not isinstance(record_size, int) or isinstance(record_size, bool) or record_size < 256:
            fail("record_size must be an integer of at least 256", record_size=record_size)

        key = [path, record_size, args.get("name"), want_entry, bool(args.get("deleted_only")),
               bool(args.get("streams_only")), bool(args.get("timestomp_only")),
               bool(args.get("with_resident"))]
        entries = LosslessPage("mft_records", key, limit)
        problems = LosslessPage("mft_records-problems", key, 40)
        scanned, parsed = 0, 0
        trailing = 0
        fh.seek(0)
        while True:
            chunk = fh.read(record_size)
            if not chunk:
                break
            if len(chunk) < 42:
                trailing = len(chunk)
                break
            index = scanned
            scanned += 1
            try:
                entry = parse_record(chunk, index, bool(args.get("with_resident")))
            except (struct.error, IndexError, ValueError) as exc:
                problems.add({"record": index, "offset": index * record_size,
                              "why": "the record did not parse: %s" % exc})
                continue
            if entry is None:
                continue
            parsed += 1
            if want_entry is not None:
                if entry["entry"] != want_entry:
                    continue
            else:
                if args.get("deleted_only") and entry["in_use"]:
                    continue
                if args.get("streams_only") and not entry["ads"]:
                    continue
                if args.get("timestomp_only") and not (set(entry["flags"]) & STOMP_FLAGS):
                    continue
                if pattern and not any(pattern.search(n["name"]) for n in entry["names"]):
                    continue
            entries.add(entry)

    page = entries.finish()
    problem_page = problems.finish()
    out = {
        "path": path,
        "record_size": record_size,
        "records_scanned": scanned,
        "records_parsed": parsed,
        "entries": entries.page,
        "entry_count": page["matched"],
        **page,
        "problems": problems.page,
        "problem_count": problem_page["matched"],
        "note": "A flag beginning si_ is an indicator, not proof. $FN can be made to "
                "follow $SI by creating, stomping and then renaming; the defensible "
                "confirmation is $LogFile, which records when the driver wrote the value.",
    }
    if problem_page.get("all_results"):
        out["all_problems"] = problem_page["all_results"]
    if trailing:
        out["trailing_bytes"] = trailing
        out["trailing_note"] = ("the file ends %d bytes into a record, too few to hold a record "
                                "header" % trailing)
    print(json.dumps(out, indent=2))


if __name__ == "__main__":
    main()
