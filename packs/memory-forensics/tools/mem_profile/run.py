#!/usr/bin/env python3
"""Say what a memory file's header shows, before anything is run against it.

Memory arrives in half a dozen shapes and they are not interchangeable. A
framework handed the wrong one returns an error that reads exactly like a
corrupt image, and an hour goes into the wrong question.

This is a first pass at the file's header and a sample of its bytes. It names a
container only when the header says so; a file with no header this tool knows is
"unrecognised", which is what a flat capture (a raw image, a .vmem) looks like and
also what a file that is not memory looks like. It is not validation: confirm the
format, the architecture, the captured ranges and the completeness before framework
analysis.

The one that matters most: **a Windows crash dump is not contiguous physical
memory**. Its header carries a run list, pairs of (starting page, page count), and
the file holds the runs one after another, so a physical address is not a file
offset. The runs are printed with both, and checked against each other and against
the size of the file, so that mistake is visible rather than silent.

Headers recognised:

    "PAGEDUMP" / "PAGEDU64"   Windows crash dump, 32- and 64-bit
    "HIBR" / "WAKE" / zeroed  hibernation file: a saved state, not read here
    "EMiL"                    LiME: its ranges are walked, header by header
    "AVML"                    recognised by its first four bytes; its framing is not read
    \\x7fELF                   an ELF file; type 4 is a core dump (byte order from e_ident)
"""
import hashlib
import json
import os
import re
import struct
import sys
import tempfile
from datetime import datetime, timedelta, timezone
from pathlib import Path

PARSER = "mem_profile/2"
HINTS = [
    (b"Windows", "Windows"), (b"Linux version ", "Linux"),
    (b"Darwin Kernel Version", "macOS or iOS"), (b"FreeBSD", "FreeBSD"),
]
STRUCTURES = [
    (b"regf", "registry hive"), (b"ElfChnk\x00", "event log chunk"),
    (b"MAM\x04", "compressed prefetch record"), (b"MZ\x90\x00", "PE header"),
    (b"SQLite format 3\x00", "SQLite database"), (b"INDX", "NTFS index block"),
    (b"FILE0", "MFT record"),
]
CHUNK = 1 << 22
MAX_SCAN_MB = 4096
FIRST_OFFSETS = 5
LIME_MAGIC = 0x4C694D45  # the bytes "EMiL"
LIME_HEADER = 32
LIME_WALK_CAP = 1_000_000
RANGE_PAGE = 200


# Lossless paging (the same in every library tool that pages): the page an agent
# reads stays small, and when there are more rows the whole result is written as
# JSON Lines under work/<agent>/tool-output (in a job, $OUT/tool-output) and named.
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
            self._out = None
            result["all_results"] = self.shown
            result["all_results_format"] = "JSON Lines, one complete result per line"
        return result


def fail(message, **extra):
    print(json.dumps({"error": message, **extra}))
    raise SystemExit(1)


def filetime(value):
    """A Windows FILETIME (100 ns ticks since 1601-01-01 UTC) as ISO 8601 with its seven fractional digits.

    Returns (text, None) or (None, why): a value that is not a time this tool can write is
    said with its raw value, never turned into a silent null.
    """
    try:
        seconds, ticks = divmod(value, 10_000_000)
        moment = datetime(1601, 1, 1, tzinfo=timezone.utc) + timedelta(seconds=seconds)
    except (OverflowError, ValueError):
        return None, "the FILETIME %d is out of range: it is past the year 9999, so it is not a time" % value
    return moment.strftime("%Y-%m-%dT%H:%M:%S") + ".%07dZ" % ticks, None


def crash_dump(fh, wide, size):
    """The run list is the whole reason to read this header."""
    out = {"format": "Windows crash dump", "bits": 64 if wide else 32}
    problems = []
    fh.seek(0)
    header_bytes = 0x2000 if wide else 0x1000
    head = fh.read(header_bytes)
    try:
        if wide:
            out["major_version"], out["minor_version"] = struct.unpack_from("<II", head, 0x08)
            out["directory_table_base"] = struct.unpack_from("<Q", head, 0x10)[0]
            out["machine_image_type"] = hex(struct.unpack_from("<I", head, 0x30)[0])
            out["processors"] = struct.unpack_from("<I", head, 0x34)[0]
            bugcheck = struct.unpack_from("<I", head, 0x38)[0]
            out["bugcheck_code"] = hex(bugcheck)
            marker = struct.pack("<I", bugcheck)
            if all(0x20 <= b < 0x7f for b in marker):
                out["bugcheck_code_note"] = (
                    "the field contains printable bytes %r and may be acquisition-tool filler, "
                    "not a Windows bugcheck" % marker.decode("ascii", "replace"))
            runs_at = 0x88
            runs_start = runs_at + 0x10  # descriptor padding + 64-bit NumberOfPages
            dump_type_at, system_time_at, uptime_at = 0xF98, 0xFA8, 0x1030
            version_at = 0x60
        else:
            out["major_version"], out["minor_version"] = struct.unpack_from("<II", head, 0x08)
            out["directory_table_base"] = struct.unpack_from("<I", head, 0x10)[0]
            out["machine_image_type"] = hex(struct.unpack_from("<I", head, 0x20)[0])
            out["processors"] = struct.unpack_from("<I", head, 0x24)[0]
            runs_at = 0x64
            runs_start = runs_at + 8
            dump_type_at, system_time_at, uptime_at = 0xF88, 0xFC0, 0xFB8
            version_at = 0x3C

        version_raw = head[version_at:version_at + 32].split(b"\0", 1)[0]
        # Some acquisition tools fill unused header fields with a repeated
        # four-byte marker (for example PAGE).  Do not present that as an OS
        # version string.
        chunks = [version_raw[i:i + 4] for i in range(0, len(version_raw), 4)]
        if version_raw and not (len(version_raw) % 4 == 0 and len(set(chunks)) == 1):
            out["version_user"] = version_raw.decode("ascii", "replace")
        out["dump_type"] = struct.unpack_from("<I", head, dump_type_at)[0]
        system_time = struct.unpack_from("<Q", head, system_time_at)[0]
        # The raw FILETIME beside the decoded time (epoch 1601-01-01, UTC, 100 ns ticks).
        out["system_time_filetime"] = system_time
        out["system_time_utc"], why = filetime(system_time)
        if why:
            problems.append("SystemTime: " + why)
        elif system_time == 0:
            out["system_time_note"] = ("FILETIME 0 is 1601-01-01T00:00:00Z itself: the header may simply not have been "
                                       "filled in, so it records no time")
        out["system_uptime_100ns"] = struct.unpack_from("<Q", head, uptime_at)[0]

        # Only a complete dump (type 1) describes memory as a run array here.
        # Bitmap/active dumps use a summary bitmap after the header instead.
        if out["dump_type"] == 1:
            count = struct.unpack_from("<I", head, runs_at)[0]
            pages = struct.unpack_from("<Q" if wide else "<I", head, runs_at + (8 if wide else 4))[0]
            width = 8 if wide else 4
            available = max(0, (len(head) - runs_start) // (width * 2))
            if not 0 < count <= available:
                problems.append(
                    "the physical-memory run count is %d, but the header holds at most %d" %
                    (count, available))
            else:
                runs, cursor, file_offset = [], runs_start, header_bytes
                for _ in range(count):
                    if wide:
                        base, length = struct.unpack_from("<QQ", head, cursor)
                    else:
                        base, length = struct.unpack_from("<II", head, cursor)
                    cursor += width * 2
                    # physical_start is an address in the guest's physical memory; file_offset is
                    # where the run's first page is in this file: the runs are stored in order,
                    # one after another, after the header.
                    runs.append({"start_page": base, "pages": length,
                                 "physical_start": base * 4096, "bytes": length * 4096,
                                 "file_offset": file_offset})
                    file_offset += length * 4096
                out["memory_runs"] = runs
                out["run_count"] = count
                out["pages_total"] = pages
                out["runs_pages_total"] = sum(run["pages"] for run in runs)
                out["header_bytes"] = header_bytes
                if out["runs_pages_total"] != pages:
                    problems.append(
                        "the run lengths total %d pages, not the descriptor's %d" %
                        (out["runs_pages_total"], pages))
                for before, after in zip(runs, runs[1:]):
                    if after["start_page"] < before["start_page"]:
                        problems.append(
                            "the runs are not in ascending order: the run at page %d follows the run at page %d" %
                            (after["start_page"], before["start_page"]))
                    elif after["start_page"] < before["start_page"] + before["pages"]:
                        problems.append(
                            "runs overlap: the run at page %d starts inside the run at page %d (%d pages)" %
                            (after["start_page"], before["start_page"], before["pages"]))
                # Adjacent means each run starts at the page after the previous one ends.
                out["contiguous"] = all(
                    after["start_page"] == before["start_page"] + before["pages"]
                    for before, after in zip(runs, runs[1:]))
                payload = max(0, size - header_bytes)
                declared = out["runs_pages_total"] * 4096
                out["payload_bytes"] = payload
                out["runs_declare_bytes"] = declared
                if payload < declared:
                    problems.append(
                        "the file holds %d bytes after the header and the runs declare %d: the dump is shorter than its run list" %
                        (payload, declared))
                elif payload > declared:
                    out["trailing_bytes"] = payload - declared
        else:
            out["memory_layout"] = (
                "dump type %d uses a bitmap/summary layout; use a crash-dump-aware framework "
                "to map its physical pages" % out["dump_type"])
    except struct.error:
        problems.append("the header is shorter than the format requires")
    if problems:
        out["problems"] = problems
    return out


def elf_header(head):
    """e_ident gives the class (byte 4) and the byte order (byte 5) of every later field."""
    out = {"format": "ELF"}
    problems = []
    if len(head) < 20:
        problems.append("the ELF header is shorter than 20 bytes (%d): no type or machine to read" % len(head))
        out["problems"] = problems
        return out
    cls, data = head[4], head[5]
    if cls not in (1, 2):
        problems.append("EI_CLASS is %d, neither 1 (32-bit) nor 2 (64-bit)" % cls)
    else:
        out["bits"] = 32 if cls == 1 else 64
    if data not in (1, 2):
        problems.append("EI_DATA is %d, neither 1 (little-endian) nor 2 (big-endian): the type is not read" % data)
        out["problems"] = problems
        return out
    order = "<" if data == 1 else ">"
    out["endian"] = "little" if data == 1 else "big"
    elf_type, machine = struct.unpack_from(order + "HH", head, 16)
    out["elf_type"] = elf_type
    out["machine"] = machine
    out["format"] = "ELF core" if elf_type == 4 else "ELF (type %d)" % elf_type
    if elf_type == 4:
        out["segments"] = "not enumerated: a core's PT_LOAD segments map file bytes to addresses, and this tool does not read them"
    if problems:
        out["problems"] = problems
    return out


def lime_ranges(fh, size):
    """Walk a LiME file range by range: each is a 32-byte header and then the bytes it frames."""
    page = LosslessPage("mem_profile", [os.path.realpath(fh.name), "lime ranges"], RANGE_PAGE)
    problems, position, total, version = [], 0, 0, None
    while position < size and page.total < LIME_WALK_CAP:
        fh.seek(position)
        head = fh.read(LIME_HEADER)
        if len(head) < LIME_HEADER:
            problems.append("the file ends inside a LiME header at offset %d (%d bytes of 32)" % (position, len(head)))
            break
        magic, found_version, start, end = struct.unpack_from("<IIQQ", head, 0)
        if magic != LIME_MAGIC:
            problems.append("no LiME magic at offset %d: the walk stopped there, with %d bytes after it not walked" % (position, size - position))
            break
        if version is None:
            version = found_version
        if found_version != 1:
            problems.append("the LiME header at offset %d has version %d; only version 1 is read, so the walk stopped there" % (position, found_version))
            break
        if end < start:
            problems.append("the LiME header at offset %d ends (0x%x) before it starts (0x%x)" % (position, end, start))
            break
        length = end - start + 1
        data_at = position + LIME_HEADER
        page.add({"physical_start": start, "physical_end": end, "bytes": length, "file_offset": data_at})
        total += length
        if data_at + length > size:
            problems.append(
                "the range at offset %d declares %d bytes and the file holds %d after its header: the file ends inside the range" %
                (position, length, size - data_at))
            break
        position = data_at + length
    else:
        if position < size:
            problems.append("the walk stopped at %d ranges (the cap), with %d bytes after offset %d not walked" % (page.total, size - position, position))
    paged = page.finish()
    out = {"format": "LiME", "version": version, "range_count": paged["matched"], "ranges": page.page,
           "physical_bytes_total": total,
           "ranges_note": "the ranges as the LiME headers frame them, in file order; the file is the ranges one after another, so a physical address is not a file offset"}
    if paged.get("all_results"):
        out["ranges_all"] = paged["all_results"]
        out["ranges_truncated"] = True
    if problems:
        out["problems"] = problems
    return out


def identify(path):
    size = os.path.getsize(path)
    with open(path, "rb") as fh:
        head = fh.read(64)
        if head[:8] == b"PAGEDUMP":
            return {**crash_dump(fh, False, size), "recognition_basis": "the first 8 bytes are PAGEDUMP"}, size
        if head[:8] == b"PAGEDU64":
            return {**crash_dump(fh, True, size), "recognition_basis": "the first 8 bytes are PAGEDU64"}, size
        if head[:4] in (b"HIBR", b"hibr", b"WAKE", b"wake"):
            return {"format": "hibernation file", "state": head[:4].decode("ascii", "replace"),
                    "compression": "not read: a hibernation file's pages are usually compressed, and this tool does not decode them",
                    "recognition_basis": "the first 4 bytes are %s" % head[:4].decode("ascii", "replace")}, size
        if head[:4] == b"EMiL":
            return {**lime_ranges(fh, size), "recognition_basis": "the first 4 bytes are the LiME magic"}, size
        if head[:4] == b"AVML":
            return {"format": "AVML", "recognition_basis": "the first 4 bytes are AVML",
                    "framing": "not read by this tool: its ranges and compression are not described here"}, size
        if head[:4] == b"\x7fELF":
            return {**elf_header(head), "recognition_basis": "the first 4 bytes are the ELF magic"}, size
        if not any(head[:16]) and path.lower().endswith("hiberfil.sys"):
            return {"format": "hibernation file, header cleared",
                    "recognition_basis": "the first 16 bytes are zero and the name is hiberfil.sys",
                    "note": "a resumed hibernation file has its header zeroed; the compressed "
                            "pages are usually still there"}, size
        container = {
            "format": "unrecognised",
            "recognition_basis": "no known container header in the first 64 bytes",
            "interpretation": "the file may be flat physical memory (a raw capture or a .vmem has no header), "
                              "a container this tool does not know, or not memory at all; nothing here shows which",
        }
        extension = os.path.splitext(path.lower())[1]
        if extension in (".vmem", ".raw", ".mem", ".lime", ".dmp", ".bin"):
            container["name_hint"] = "the extension %s is a hint only" % extension
        return container, size


def sample_ranges(size, megabytes):
    """The head, the middle and the tail, merged where they touch or overlap.

    Each range is scanned on its own, so a match is never joined across two
    windows that are not adjacent in the file, and a byte is never counted twice.
    """
    window = megabytes * 1024 * 1024 // 3 or 1
    spots = [0, max(0, size // 2 - window // 2), max(0, size - window)]
    raw = sorted((spot, min(size, spot + window)) for spot in spots)
    merged = []
    for lo, hi in raw:
        if merged and lo <= merged[-1][1]:
            merged[-1] = (merged[-1][0], max(merged[-1][1], hi))
        else:
            merged.append((lo, hi))
    return merged


def scan(path, ranges, needles):
    """Count each needle in each range separately, streaming; return the counts and the first offsets.

    A range is read in blocks, and a block is searched with the end of the one before it, so a
    needle across a block boundary is counted once. The count is made by the engine's own
    counter over the part of the buffer no earlier block owned, so a dense file costs a count
    and not a loop per match.
    """
    overlap = max(len(n) for n, _label in needles) - 1
    counts = {label: 0 for _n, label in needles}
    first = {label: [] for _n, label in needles}
    with open(path, "rb") as fh:
        for lo, hi in ranges:
            position, tail, tail_at, accept_lo = lo, b"", lo, lo
            while position < hi:
                fh.seek(position)
                block = fh.read(min(CHUNK, hi - position))
                if not block:
                    break
                buf, base = tail + block, tail_at
                block_end = position + len(block)
                # A needle that starts before accept_hi lies wholly inside buf; one that starts
                # later is found in the next buffer, which begins at accept_hi.
                accept_hi = hi if block_end >= hi else max(accept_lo, block_end - overlap)
                for needle, label in needles:
                    own = buf[accept_lo - base:accept_hi - base + len(needle) - 1]
                    counts[label] += own.count(needle)
                    at = 0
                    while len(first[label]) < FIRST_OFFSETS:
                        found = own.find(needle, at)
                        if found < 0:
                            break
                        first[label].append(accept_lo + found)
                        at = found + 1
                accept_lo = accept_hi
                keep = accept_hi - base
                tail, tail_at = buf[keep:], base + keep
                position = block_end
    return counts, first


def main():
    try:
        args = json.load(sys.stdin)
    except ValueError as exc:
        fail("arguments are not valid JSON", reason=str(exc))
    if not isinstance(args, dict):
        fail("arguments must be a JSON object")
    path = args.get("path")
    if not isinstance(path, str) or not path:
        fail("path is required: a memory image, dump or hibernation file")
    if not os.path.isfile(path):
        fail("no such file", path=path)
    megabytes = args.get("scan_mb", 64)
    if not isinstance(megabytes, int) or isinstance(megabytes, bool) or not 1 <= megabytes <= MAX_SCAN_MB:
        fail("scan_mb must be an integer from 1 to %d: it is a sample for hints, and the ranges actually read are in the answer" % MAX_SCAN_MB)
    size = os.path.getsize(path)
    if size == 0:
        fail("the file is empty: there is nothing to profile", path=path)

    container, size = identify(path)
    ranges = sample_ranges(size, megabytes)
    os_counts, os_first = scan(path, ranges, [(n, label) for n, label in HINTS])
    struct_counts, struct_first = scan(path, ranges, [(n, label) for n, label in STRUCTURES])
    systems = sorted(label for label, n in os_counts.items() if n)
    structures = {label: n for label, n in struct_counts.items() if n}
    build, build_at = None, None
    if os_first.get("Linux"):
        build_at = os_first["Linux"][0]
        with open(path, "rb") as fh:
            fh.seek(build_at)
            found = re.match(rb"Linux version ([0-9][^\x00\n]{0,80})", fh.read(120))
        if found:
            build = found.group(1).decode("ascii", "replace")

    problems = list(container.get("problems", []))
    out = {
        "path": path,
        "parser": PARSER,
        "bytes": size,
        "file_pages_4k_estimate": size // 4096,
        "container": container,
        "operating_system_hints": systems,
        "operating_system_hint_offsets": {label: offsets for label, offsets in os_first.items() if offsets},
        "kernel_build": build,
        "kernel_build_offset": build_at,
        "structures_in_sample": structures,
        "structure_first_offsets": {label: offsets for label, offsets in struct_first.items() if offsets},
        "sampled_megabytes": megabytes,
        "sampled_ranges": [{"offset": lo, "bytes": hi - lo} for lo, hi in ranges],
        "bytes_sampled": sum(hi - lo for lo, hi in ranges),
        "problems": problems,
        "notes": [
            "file_pages_4k_estimate is the file's length divided by 4096. It is not a count of captured "
            "physical pages: a container's framing, its ranges and any gaps are not accounted for in it.",
            "Structure and operating-system counts are signature counts in the sampled ranges only "
            "(sampled_ranges), each range read on its own; they are hints, not counts for the file.",
        ],
    }
    if out["bytes_sampled"] < size:
        out["notes"].append(
            "Only %d of %d bytes were sampled (head, middle and tail). Raise scan_mb for more; a hint "
            "that is absent from the sample says nothing about the rest of the file." % (out["bytes_sampled"], size))
    if container.get("format", "").startswith("Windows crash dump") and container.get("contiguous") is False:
        out["notes"].append(
            "This dump is not contiguous: %d memory runs with gaps between them. A tool that "
            "treats the file as flat physical memory reads the wrong offset for everything after "
            "the first gap." % container.get("run_count", 0))
    if "hibernation" in container.get("format", ""):
        out["notes"].append(
            "A hibernation file is a saved state, not the state at acquisition. Say which moment you "
            "are quoting once its time has been established from the file and the acquisition record.")
    if not systems:
        out["notes"].append(
            "No operating-system string in the sample. That is normal for a small sample of a "
            "large image; raise scan_mb before concluding anything from it.")
    print(json.dumps(out, indent=2))


if __name__ == "__main__":
    try:
        main()
    except SystemExit:
        raise
    except Exception as exc:  # never an empty or clean answer for a failure
        fail("unexpected failure: %s: %s" % (type(exc).__name__, exc))
