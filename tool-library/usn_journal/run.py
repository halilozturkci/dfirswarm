#!/usr/bin/env python3
"""Parse an NTFS change journal ($UsnJrnl:$J) into records.

Asked for in two of the measured cases and forged badly in one. The journal
is the closest thing NTFS has to an audit log of file names: every create,
rename, write and delete, with a timestamp and the reason bits that say which.

$J is sparse — the front of it is usually a long run of zeros — so this scans
forward for the first plausible record rather than assuming an offset, and
says where it started.

USN_RECORD_V2:
  0x00  4  RecordLength
  0x04  2  MajorVersion (2)
  0x06  2  MinorVersion
  0x08  8  FileReferenceNumber
  0x10  8  ParentFileReferenceNumber
  0x18  8  Usn
  0x20  8  TimeStamp (FILETIME)
  0x28  4  Reason
  0x2C  4  SourceInfo
  0x30  4  SecurityId
  0x34  4  FileAttributes
  0x38  2  FileNameLength
  0x3A  2  FileNameOffset
"""
import datetime
import json
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

REASONS = [
    (0x00000001, "DATA_OVERWRITE"), (0x00000002, "DATA_EXTEND"), (0x00000004, "DATA_TRUNCATION"),
    (0x00000010, "NAMED_DATA_OVERWRITE"), (0x00000020, "NAMED_DATA_EXTEND"), (0x00000040, "NAMED_DATA_TRUNCATION"),
    (0x00000100, "FILE_CREATE"), (0x00000200, "FILE_DELETE"), (0x00000400, "EA_CHANGE"),
    (0x00000800, "SECURITY_CHANGE"), (0x00001000, "RENAME_OLD_NAME"), (0x00002000, "RENAME_NEW_NAME"),
    (0x00004000, "INDEXABLE_CHANGE"), (0x00008000, "BASIC_INFO_CHANGE"), (0x00010000, "HARD_LINK_CHANGE"),
    (0x00020000, "COMPRESSION_CHANGE"), (0x00040000, "ENCRYPTION_CHANGE"), (0x00080000, "OBJECT_ID_CHANGE"),
    (0x00100000, "REPARSE_POINT_CHANGE"), (0x00200000, "STREAM_CHANGE"), (0x00400000, "TRANSACTED_CHANGE"),
    (0x00800000, "INTEGRITY_CHANGE"), (0x80000000, "CLOSE"),
]

ATTRIBUTES = [
    (0x00000001, "READONLY"), (0x00000002, "HIDDEN"), (0x00000004, "SYSTEM"), (0x00000010, "DIRECTORY"),
    (0x00000020, "ARCHIVE"), (0x00000080, "NORMAL"), (0x00000100, "TEMPORARY"), (0x00000200, "SPARSE_FILE"),
    (0x00000400, "REPARSE_POINT"), (0x00000800, "COMPRESSED"), (0x00001000, "OFFLINE"),
    (0x00004000, "ENCRYPTED"),
]


def fail(message, **extra):
    print(json.dumps({"error": message, **extra}))
    raise SystemExit(1)


def flags(value, table):
    return [name for bit, name in table if value & bit]


def filetime(value):
    if value <= 0:
        return None
    try:
        return (FILETIME_EPOCH + datetime.timedelta(microseconds=value // 10)).isoformat().replace("+00:00", "Z")
    except OverflowError:
        return None


def main():
    try:
        args = json.load(sys.stdin)
    except ValueError as exc:
        fail("arguments are not valid JSON", reason=str(exc))

    path = args.get("path")
    if not isinstance(path, str) or not path:
        fail("path is required: the $J stream, extracted with icat")
    limit = args.get("limit", 500)
    if not isinstance(limit, int) or isinstance(limit, bool) or limit < 1:
        fail("limit must be a positive integer", limit=args.get("limit"))
    limit = min(limit, 100000)
    name_filter = args.get("name")
    if name_filter is not None and not isinstance(name_filter, str):
        fail("name must be a string")
    needle = name_filter.lower() if name_filter else None

    try:
        with open(path, "rb") as fh:
            data = fh.read()
    except OSError as exc:
        fail("could not read the journal", path=path, reason=str(exc))

    if len(data) < 0x3C:
        fail("too short to hold a record", bytes=len(data))

    # The sparse front of $J is zeros. Walk forward to the first record whose
    # length and version are plausible, and report where that was.
    start = 0
    while start + 0x3C <= len(data):
        length, major = struct.unpack_from("<IH", data, start)
        if 0x3C <= length <= 0x10000 and major == 2:
            break
        start += 8
    else:
        fail("no USN_RECORD_V2 found", bytes=len(data), hint="is this the $J stream rather than $Max?")

    records = LosslessPage("usn_journal", [path, name_filter], limit)
    offset = start
    skipped = 0
    while offset + 0x3C <= len(data):
        length, major, minor = struct.unpack_from("<IHH", data, offset)
        if length == 0:
            offset += 8
            continue
        if not (0x3C <= length <= 0x10000) or major != 2 or offset + length > len(data):
            skipped += 1
            offset += 8
            continue
        ref, parent, usn, stamp, reason, source, sec, attrs, name_len, name_off = struct.unpack_from(
            "<QQQqIIIIHH", data, offset + 0x08
        )
        name = ""
        if 0 < name_len and name_off + name_len <= length:
            name = data[offset + name_off:offset + name_off + name_len].decode("utf-16-le", "replace")
        if needle is None or needle in name.lower():
            records.add({
                "usn": usn,
                "timestamp": filetime(stamp),
                "name": name,
                "file_reference": ref & 0x0000FFFFFFFFFFFF,
                "file_sequence": ref >> 48,
                "parent_reference": parent & 0x0000FFFFFFFFFFFF,
                "reason": flags(reason, REASONS),
                "reason_raw": reason,
                "attributes": flags(attrs, ATTRIBUTES),
                "offset": offset,
            })
        offset += length

    page = records.finish()
    print(json.dumps({
        "path": path,
        "bytes": len(data),
        "first_record_offset": start,
        "records": records.page,
        "record_count": page["matched"],
        "malformed_skipped": skipped,
        **page,
    }, indent=2))


if __name__ == "__main__":
    main()
