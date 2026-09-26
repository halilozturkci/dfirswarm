#!/usr/bin/env python3
"""Name the container before anything is run against it.

Memory arrives in half a dozen shapes and they are not interchangeable. A
framework handed the wrong one returns an error that reads exactly like a
corrupt image, and an hour goes into the wrong question.

The one that matters most: **a Windows crash dump is not contiguous physical
memory**. Its header carries a run list — pairs of (starting page, page count)
with gaps between them — and a tool that treats the file as flat reads the wrong
offset for everything after the first gap. The runs are printed here so that
mistake is visible rather than silent.

Headers recognised:

    "PAGEDUMP" / "PAGEDU64"   Windows crash dump, 32- and 64-bit
    "HIBR" / "WAKE" / zeroed  hibernation file; compressed, and a PAST state
    "EMiL"                    LiME, little-endian magic
    "AVML"                    Microsoft's Linux acquisition format
    \\x7fELF with type 4       an ELF core dump
    none                      flat physical memory, which is the common case
"""
import json
import os
import re
import struct
import sys
from datetime import datetime, timedelta, timezone

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


def fail(message, **extra):
    print(json.dumps({"error": message, **extra}))
    raise SystemExit(1)


def filetime(value):
    """Render a Windows FILETIME without letting an invalid header abort triage."""
    try:
        return (datetime(1601, 1, 1, tzinfo=timezone.utc) +
                timedelta(microseconds=value // 10)).isoformat().replace("+00:00", "Z")
    except (OverflowError, ValueError):
        return None


def crash_dump(fh, wide):
    """The run list is the whole reason to read this header."""
    out = {"format": "Windows crash dump", "bits": 64 if wide else 32}
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
        out["system_time_utc"] = filetime(system_time)
        out["system_uptime_100ns"] = struct.unpack_from("<Q", head, uptime_at)[0]

        # Only a complete dump (type 1) describes memory as a run array here.
        # Bitmap/active dumps use a summary bitmap after the header instead.
        if out["dump_type"] == 1:
            count = struct.unpack_from("<I", head, runs_at)[0]
            pages = struct.unpack_from("<Q" if wide else "<I", head, runs_at + (8 if wide else 4))[0]
            width = 8 if wide else 4
            available = max(0, (len(head) - runs_start) // (width * 2))
            if not 0 < count <= available:
                out["header_problem"] = (
                    "the physical-memory run count is %d, but the header holds at most %d" %
                    (count, available))
            else:
                runs, cursor = [], runs_start
                for _ in range(count):
                    if wide:
                        base, length = struct.unpack_from("<QQ", head, cursor)
                    else:
                        base, length = struct.unpack_from("<II", head, cursor)
                    cursor += width * 2
                    runs.append({"start_page": base, "pages": length,
                                 "start_byte": base * 4096, "bytes": length * 4096})
                out["memory_runs"] = runs
                out["run_count"] = count
                out["pages_total"] = pages
                out["runs_pages_total"] = sum(run["pages"] for run in runs)
                out["contiguous"] = len(runs) <= 1
                if out["runs_pages_total"] != pages:
                    out["header_problem"] = (
                        "the run lengths total %d pages, not the descriptor's %d" %
                        (out["runs_pages_total"], pages))
        else:
            out["memory_layout"] = (
                "dump type %d uses a bitmap/summary layout; use a crash-dump-aware framework "
                "to map its physical pages" % out["dump_type"])
    except struct.error:
        out["header_problem"] = "the header is shorter than the format requires"
    return out


def identify(path):
    size = os.path.getsize(path)
    with open(path, "rb") as fh:
        head = fh.read(64)
        if head[:8] == b"PAGEDUMP":
            return crash_dump(fh, wide=False), size
        if head[:8] == b"PAGEDU64":
            return crash_dump(fh, wide=True), size
        if head[:4] in (b"HIBR", b"hibr", b"WAKE", b"wake"):
            return {"format": "hibernation file", "state": head[:4].decode("ascii", "replace"),
                    "compressed": True}, size
        if head[:4] == b"EMiL":
            version, = struct.unpack_from("<I", head, 4)
            return {"format": "LiME", "version": version}, size
        if head[:4] == b"AVML":
            return {"format": "AVML"}, size
        if head[:4] == b"\x7fELF":
            elf_type, = struct.unpack_from("<H", head, 16)
            return {"format": "ELF core" if elf_type == 4 else "ELF (type %d)" % elf_type,
                    "bits": 64 if head[4] == 2 else 32}, size
        if not any(head[:16]) and path.lower().endswith("hiberfil.sys"):
            return {"format": "hibernation file, header cleared",
                    "note": "a resumed hibernation file has its header zeroed; the compressed "
                            "pages are usually still there"}, size
        return {"format": "flat physical memory (no container header)"}, size


def sample(path, size, megabytes):
    """Read the head, the middle and the tail rather than the whole file."""
    window = megabytes * 1024 * 1024 // 3 or 1
    spots = [0, max(0, size // 2 - window // 2), max(0, size - window)]
    seen = bytearray()
    with open(path, "rb") as fh:
        for spot in spots:
            fh.seek(spot)
            seen += fh.read(window)
    return bytes(seen)


def main():
    try:
        args = json.load(sys.stdin)
    except ValueError as exc:
        fail("arguments are not valid JSON", reason=str(exc))
    path = args.get("path")
    if not isinstance(path, str) or not path:
        fail("path is required: a memory image, dump or hibernation file")
    if not os.path.isfile(path):
        fail("no such file", path=path)
    megabytes = args.get("scan_mb", 64)
    if not isinstance(megabytes, int) or isinstance(megabytes, bool) or megabytes < 1:
        fail("scan_mb must be a positive integer")

    container, size = identify(path)
    blob = sample(path, size, megabytes)
    systems = sorted({name for needle, name in HINTS if needle in blob})
    structures = {}
    for needle, name in STRUCTURES:
        count = blob.count(needle)
        if count:
            structures[name] = count
    build = None
    found = re.search(rb"Linux version ([0-9][^\x00\n]{0,80})", blob)
    if found:
        build = found.group(1).decode("ascii", "replace")

    out = {
        "path": path,
        "bytes": size,
        "pages_4k": size // 4096,
        "container": container,
        "operating_system_hints": systems,
        "kernel_build": build,
        "structures_in_sample": structures,
        "sampled_megabytes": megabytes,
        "notes": [],
    }
    if container.get("format", "").startswith("Windows crash dump") and not container.get("contiguous", True):
        out["notes"].append(
            "This dump is not contiguous: %d memory runs with gaps between them. A tool that "
            "treats the file as flat physical memory reads the wrong offset for everything after "
            "the first gap." % container.get("run_count", 0))
    if "hibernation" in container.get("format", ""):
        out["notes"].append(
            "A hibernation file is a PAST state, not the state at acquisition, and it is "
            "compressed. Say which moment you are quoting.")
    if not systems:
        out["notes"].append(
            "No operating-system string in the sample. That is normal for a small sample of a "
            "large image; raise scan_mb before concluding anything from it.")
    print(json.dumps(out, indent=2))


if __name__ == "__main__":
    main()
