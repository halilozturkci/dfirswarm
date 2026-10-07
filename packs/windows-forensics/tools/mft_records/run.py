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
in hand-rolled MFT code, so it is applied here first. A record whose fixup does not
match is still parsed, flagged `fixup_failed` and `unreliable`, and counted under
`records_fixup_failed`; it does not make the run partial, so read that count. A slot
that holds neither FILE nor BAAD (zeroed or damaged) is not a record and is not
listed: it is counted under `slots_without_signature`.

The slots are counted from the first record that looks like one (a FILE signature with an
update sequence array of the size the record size implies): a file that does not begin on a
record boundary is read at its own alignment, which is reported as `alignment_offset`. A
slot of zeros is counted under `slots_zeroed`; one that holds data and neither signature is a
problem and is counted under `slots_unrecognised`.

Every record is read. The page returned inline is `limit` long, and when more
records match the whole list is written to a file the output names. A record
too damaged to parse is listed as a problem with its offset, and the sweep goes
on to the next one.

Every nested range is checked against the attribute that holds it, and the attribute chain against the
record's used size: a $STANDARD_INFORMATION shorter than its times, a $FILE_NAME whose name runs past its
attribute, a resident $DATA past its attribute, a non-resident header shorter than the sizes it carries, a
chain that ends without its end marker. None is read as if it were whole: the record keeps what was
sound and says what was not under `structural_errors` (and is `unreliable`), and the record is also a
problem of the run, with its offset.

What it does NOT do: it does not resolve $ATTRIBUTE_LIST (a record that has one says so, and its other
attributes live in extension records this tool reads as records of their own, with `base_record`), and it
does not rebuild a parent path (each name carries its parent entry and sequence; join them with another
reading of the volume). Each name and stream carries its attribute `instance` id.
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
    """ISO 8601 UTC with seven fractional digits, by integer arithmetic; None for 0 or past year 9999."""
    if not value:
        return None
    try:
        whole, ticks = divmod(value, 10_000_000)
        return (FILETIME_EPOCH + datetime.timedelta(seconds=whole)).strftime("%Y-%m-%dT%H:%M:%S") + ".%07dZ" % ticks
    except (OverflowError, ValueError, OSError):
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


def attributes(record, first, errors, used=None):
    """Walk the attribute chain. It ends at the end marker; anything else that ends it (a header that does not fit,
    a length that is not a multiple of 8 or runs past the used part of the record, running out of record before
    the marker) is appended to `errors`, not passed over."""
    end = len(record)
    if used and first < used <= len(record):
        end = used
    offset = first
    while True:
        if offset + 4 > end:
            errors.append("the attribute chain runs out at offset %d without an end marker" % offset)
            return
        atype = struct.unpack_from("<I", record, offset)[0]
        if atype == END:
            return
        if offset + 16 > end:
            errors.append("the attribute header at offset %d does not fit the record" % offset)
            return
        length = struct.unpack_from("<I", record, offset + 4)[0]
        if length < 16 or length % 8 or offset + length > end:
            errors.append("the attribute at offset %d (type 0x%x) has an invalid length %d" % (offset, atype, length))
            return
        yield atype, offset, length
        offset += length


def attribute_name(record, offset, length, errors):
    name_len = record[offset + 9]
    if not name_len:
        return ""
    name_off = struct.unpack_from("<H", record, offset + 0x0A)[0]
    if name_off + name_len * 2 > length:
        errors.append("the attribute name at offset %d does not fit its attribute" % offset)
        return ""
    raw = record[offset + name_off:offset + name_off + name_len * 2]
    return raw.decode("utf-16-le", "replace")


def resident(record, offset, length, errors, what, minimum=0):
    """(content offset, content length) of a resident attribute, checked against the attribute's own length;
    None, with an error, when it does not fit."""
    content_len, content_off = struct.unpack_from("<IH", record, offset + 0x10)
    if content_off < 0x18 or content_off + content_len > length or content_len < minimum:
        errors.append("the resident %s at offset %d declares %d bytes at %d, which does not fit its %d-byte attribute (or is shorter than the %d it needs)"
                      % (what, offset, content_len, content_off, length, minimum))
        return None
    return offset + content_off, content_len


def parse_record(record, number_hint, want_resident):
    if record[:4] == b"\x00" * 4:
        return None
    if record[:4] not in (b"FILE", b"BAAD"):
        return None
    fixed, fixup_problem = apply_fixup(record)
    errors = []
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
        "base_sequence": (base_ref >> 48) if base_ref else None,
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

    if used > len(fixed):
        errors.append("the record's used size (%d) is larger than the record (%d bytes); its attribute chain was read to the end of the record, not to the used size" % (used, len(fixed)))
    elif used < first_attr + 4:
        errors.append("the record's used size (%d) does not reach past its first attribute at %d; its attribute chain was read to the end of the record, not to the used size" % (used, first_attr))
    for atype, offset, length in attributes(fixed, first_attr, errors, used):
        non_resident = fixed[offset + 8]
        instance = struct.unpack_from("<H", fixed, offset + 0x0E)[0]
        if atype == STANDARD_INFORMATION and not non_resident:
            got = resident(fixed, offset, length, errors, "$STANDARD_INFORMATION", 0x24)
            if got:
                base, _ = got
                entry["standard_information"] = times(fixed, base)
                dos, = struct.unpack_from("<I", fixed, base + 0x20)
                entry["standard_information"]["attributes"] = [n for bit, n in SI_FLAGS if dos & bit]
                entry["standard_information"]["instance"] = instance
        elif atype == FILE_NAME and not non_resident:
            got = resident(fixed, offset, length, errors, "$FILE_NAME", 0x42)
            if not got:
                continue
            base, content_len = got
            parent, = struct.unpack_from("<Q", fixed, base)
            name_chars = fixed[base + 0x40]
            namespace = fixed[base + 0x41]
            if 0x42 + name_chars * 2 > content_len:
                errors.append("the $FILE_NAME at offset %d declares a %d-character name, which runs past its content (%d bytes)" % (offset, name_chars, content_len))
                continue
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
                "instance": instance,
            })
            entry["names"].append(fn)
        elif atype == DATA:
            stream = {"name": attribute_name(fixed, offset, length, errors), "resident": not non_resident, "instance": instance}
            if non_resident:
                if length < 0x40:
                    errors.append("the non-resident $DATA header at offset %d is %d bytes, shorter than the 64 that hold its sizes" % (offset, length))
                else:
                    alloc, real, init = struct.unpack_from("<QQQ", fixed, offset + 0x28)
                    stream.update({"allocated_size": alloc, "real_size": real, "initialised_size": init})
                    if real and not init:
                        entry["flags"].append("zero_initialised_size")
            else:
                got = resident(fixed, offset, length, errors, "$DATA")
                if got:
                    base, size = got
                    stream["real_size"] = size
                    if want_resident:
                        stream["content_base64"] = base64.b64encode(fixed[base:base + size]).decode("ascii")
            entry["data_streams"].append(stream)
        elif atype in (INDEX_ROOT, INDEX_ALLOCATION):
            entry.setdefault("index_attributes", []).append(attribute_name(fixed, offset, length, errors) or "$I30")
        elif atype == ATTRIBUTE_LIST:
            entry["flags"].append("has_attribute_list")
            entry["attribute_list_resolved"] = False
    if errors:
        entry["structural_errors"] = errors
        entry["flags"].append("structural_error")
        entry["unreliable"] = True
    if entry["base_record"]:
        entry["is_extension_record"] = True

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
    """Records are 1024 on almost every volume; measure rather than assume. Returns (size, how it was found).

    The first two FILE magics are looked for through the whole file, not a first window: a slice of an $MFT
    can open with a run of zeroed records. The first record's own allocated size (its header, at 0x1C) is the
    primary evidence; the gap between the first two magics is the second, and when they disagree the header's
    value is used and the disagreement said by the caller."""
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
        return None, None, None
    fh.seek(hits[0] + 0x1C)
    raw = fh.read(4)
    declared = struct.unpack("<I", raw)[0] if len(raw) == 4 else None
    gap = (hits[1] - hits[0]) if len(hits) > 1 else None
    if declared in (256, 512, 1024, 2048, 4096):
        return declared, "the allocated size in the first record's header", gap
    if gap in (256, 512, 1024, 2048, 4096):
        return gap, "the gap between the first two FILE signatures", gap
    return 1024, "the default (neither the header nor the gap gave a record size)", gap


def first_record_offset(fh, record_size):
    """Where the first record that looks like one begins: a FILE signature followed by an update sequence array
    of the size the record size implies. Slots are counted from here, so a file that opens with a part of a
    record (or with bytes that are not records) is read at its own alignment instead of as slots that match
    nothing. At most 4096 candidate signatures are looked at; None when none qualifies."""
    fh.seek(0)
    carry, base, tried = b"", 0, 0
    wanted = record_size // 512 + 1 if record_size >= 512 else None
    while True:
        block = fh.read(1 << 20)
        if not block:
            return None
        buf = carry + block
        at = buf.find(b"FILE")
        while at >= 0 and at + 8 <= len(buf):
            tried += 1
            usa_offset, usa_count = struct.unpack_from("<HH", buf, at + 4)
            if 0x28 <= usa_offset <= 0x80 and 1 <= usa_count <= 17 and (wanted is None or usa_count == wanted):
                return base + at
            if tried >= 4096:
                return None
            at = buf.find(b"FILE", at + 1)
        keep = 7 if len(buf) >= 7 else len(buf)
        carry = buf[-keep:]
        base += len(buf) - len(carry)


def run(args):
    path = args.get("path")
    if not isinstance(path, str) or not path:
        fail("path is required: an extracted $MFT")
    if not os.path.isfile(path):
        if os.path.exists(path):
            fail("not a regular file: it is not opened", path=path, not_attempted=1)
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

    try:
        size = os.path.getsize(path)
        fh = open(path, "rb")
    except OSError as exc:
        fail("could not read the $MFT", path=path, reason=str(exc))
    with fh:
        given = args.get("record_size")
        if given is not None and (not isinstance(given, int) or isinstance(given, bool) or given < 256):
            fail("record_size must be an integer of at least 256", record_size=given)
        try:
            record_size, record_size_from, gap = (given, "the record_size argument", None) if given else detect_record_size(fh, size)
            if not record_size:
                fail("no FILE record found; this does not look like an $MFT", path=path, bytes=size)
            first_at = first_record_offset(fh, record_size)
        except OSError as exc:
            fail("could not read the $MFT", path=path, reason=str(exc))
        alignment = (first_at % record_size) if first_at is not None else 0

        key = [path, record_size, args.get("name"), want_entry, bool(args.get("deleted_only")),
               bool(args.get("streams_only")), bool(args.get("timestomp_only")),
               bool(args.get("with_resident"))]
        entries = LosslessPage("mft_records", key, limit)
        problems = LosslessPage("mft_records-problems", key, 40)
        structural = 0
        fixup_failed = 0
        zeroed = unrecognised = 0
        scanned, parsed = 0, 0
        trailing = 0
        if alignment:
            problems.add({"offset": 0, "why": "the first record begins at byte %d, which is not a multiple of the %d-byte record size: the %d bytes before byte %d are not read as records, and the slots are counted from there" % (first_at, record_size, alignment, alignment)})
        try:
            fh.seek(alignment)
        except OSError as exc:
            fail("could not read the $MFT", path=path, reason=str(exc))
        while True:
            try:
                chunk = fh.read(record_size)
            except OSError as exc:
                problems.add({"offset": alignment + scanned * record_size, "why": "the read failed here and the scan stopped: %s" % exc})
                break
            if not chunk:
                break
            if len(chunk) < 48:
                trailing = len(chunk)
                break
            index = scanned
            offset = alignment + index * record_size
            scanned += 1
            if len(chunk) < record_size:
                problems.add({"record": index, "offset": offset,
                              "why": "the file ends inside this record: %d of its %d bytes are there" % (len(chunk), record_size)})
            try:
                entry = parse_record(chunk, index, bool(args.get("with_resident")))
            except Exception as exc:        # a hostile record must not end the sweep
                problems.add({"record": index, "offset": offset,
                              "why": "the record did not parse: %s" % exc})
                continue
            if entry is None:
                if not chunk.strip(b"\0"):
                    zeroed += 1
                else:
                    unrecognised += 1
                    problems.add({"record": index, "offset": offset,
                                  "why": "the slot holds data but neither a FILE nor a BAAD signature (it begins %s)" % chunk[:4].hex()})
                continue
            parsed += 1
            if "fixup_failed" in entry["flags"]:
                fixup_failed += 1
            if entry.get("structural_errors"):
                structural += 1
                problems.add({"record": index, "offset": offset,
                              "why": "the record did not parse cleanly: %s" % "; ".join(entry["structural_errors"])})
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

    if scanned and not parsed:
        problems.add({"offset": alignment, "why": "no record was read: %d slot(s) of %d bytes were looked at and none holds a FILE or BAAD signature at its start (is the record size right, or is this an $MFT?)" % (scanned, record_size)})
    page = entries.finish()
    problem_page = problems.finish()
    out = {
        "parser": "mft_records/3",
        "status": "partial" if problem_page["matched"] else "complete",
        "path": path,
        "record_size": record_size,
        "record_size_from": record_size_from,
        "records_scanned": scanned,
        "records_parsed": parsed,
        "records_with_structural_errors": structural,
        "records_fixup_failed": fixup_failed,
        "slots_zeroed": zeroed,
        "slots_unrecognised": unrecognised,
        "slots_without_signature": zeroed + unrecognised,
        "alignment_offset": alignment,
        "entries": entries.page,
        "entry_count": page["matched"],
        **page,
        "problems": problems.page,
        "problem_count": problem_page["matched"],
        "note": "A flag beginning si_ is an indicator, not proof: $SI and $FN times can each be changed by software, and a "
                "disagreement between them has more than one cause. Corroborate with the USN journal and other sources; the pack does "
                "not read $LogFile. $ATTRIBUTE_LIST is not resolved and no parent path is rebuilt (each name carries its parent entry "
                "and sequence). A record with structural_errors kept what was sound and is unreliable. A record whose update sequence "
                "fixup failed is parsed, flagged fixup_failed and unreliable and counted in records_fixup_failed, and does not make the "
                "run partial. A slot with neither a FILE nor a BAAD signature is not listed as a record: an all-zero one is counted in "
                "slots_zeroed (an unused slot, ordinary at the end of an $MFT) and one that holds data in slots_unrecognised, which is also "
                "a problem; slots_without_signature is their sum. alignment_offset is where the first record begins modulo the record size "
                "(0 when the file is aligned); a file that does not begin on a record boundary is read from there and is partial.",
    }
    if problem_page.get("all_results"):
        out["all_problems"] = problem_page["all_results"]
    if trailing:
        out["trailing_bytes"] = trailing
        out["trailing_note"] = ("the file ends %d bytes into a record, too few to hold a record "
                                "header" % trailing)
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
        fail("the $MFT could not be read", reason=str(exc))


if __name__ == "__main__":
    main()
