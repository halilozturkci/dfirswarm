#!/usr/bin/env python3
"""Read the FSEvents log: what changed on this volume, in order.

macOS writes a per-volume change log into /.fseventsd for Spotlight and backup
software, and it keeps going whether anyone is watching or not. It records the
path, not the contents, so it survives the file it describes — which is why it
answers "was this ever here" when nothing else on the volume does.

Each record file is gzip-compressed, sometimes as several streams end to end,
and holds pages:

    magic "1SLD" or "2SLD", 4 unknown bytes, page length (u32)
    then records to the end of the page:
        path, NUL-terminated UTF-8
        event id (u64)
        flags (u32)
        node id (u64) — version 2 only

**There is no timestamp anywhere in the format.** Event ids are a monotonic
counter per volume. That makes this excellent for order and useless for time
until you anchor it: date one path from another artefact and every id before and
after it is bracketed. The output says so rather than letting the id be mistaken
for a clock.
"""
import gzip
import io
import json
import os
import re
import struct
import sys

MAGICS = (b"1SLD", b"2SLD")
FLAGS = [
    (0x00000001, "FolderEvent"), (0x00000002, "Mount"), (0x00000004, "Unmount"),
    (0x00000020, "EndOfTransaction"), (0x00000800, "LastHardLinkRemoved"),
    (0x00001000, "HardLink"), (0x00004000, "SymbolicLink"), (0x00008000, "FileEvent"),
    (0x00010000, "PermissionChange"), (0x00020000, "ExtendedAttrModified"),
    (0x00040000, "ExtendedAttrRemoved"), (0x00100000, "DocumentRevision"),
    (0x00400000, "ItemCloned"), (0x01000000, "Created"), (0x02000000, "Removed"),
    (0x04000000, "InodeMetaMod"), (0x08000000, "Renamed"), (0x10000000, "Modified"),
    (0x20000000, "Exchange"), (0x40000000, "FinderInfoMod"), (0x80000000, "FolderCreated"),
]


def fail(message, **extra):
    print(json.dumps({"error": message, **extra}))
    raise SystemExit(1)


def decode_flags(value):
    return [name for bit, name in FLAGS if value & bit]


def inflate(path):
    """A record file can hold several gzip streams one after another."""
    with open(path, "rb") as fh:
        raw = fh.read()
    if not raw.startswith(b"\x1f\x8b"):
        return raw, False
    out, cursor = bytearray(), 0
    while cursor < len(raw):
        try:
            stream = zlib_decompress(raw[cursor:])
        except Exception:
            break
        out += stream[0]
        if stream[1] <= 0:
            break
        cursor += stream[1]
    return bytes(out), True


def zlib_decompress(blob):
    import zlib
    engine = zlib.decompressobj(16 + zlib.MAX_WBITS)
    data = engine.decompress(blob)
    used = len(blob) - len(engine.unused_data)
    return data, used


def read_pages(blob, source):
    records, problems = [], []
    at = 0
    while at + 12 <= len(blob):
        magic = blob[at:at + 4]
        if magic not in MAGICS:
            found = -1
            for candidate in MAGICS:
                hit = blob.find(candidate, at + 1)
                if hit >= 0 and (found < 0 or hit < found):
                    found = hit
            if found < 0:
                break
            problems.append({"file": source, "offset": at, "why": "no page magic; skipped to the next"})
            at = found
            continue
        version = 2 if magic == b"2SLD" else 1
        page_length, = struct.unpack_from("<I", blob, at + 8)
        if page_length < 12 or at + page_length > len(blob):
            page_length = len(blob) - at
        page = blob[at:at + page_length]
        cursor = 12
        while cursor < len(page):
            end = page.find(b"\x00", cursor)
            if end < 0:
                break
            fixed = 12 + (8 if version == 2 else 0)
            if end + 1 + fixed > len(page):
                break
            path = page[cursor:end].decode("utf-8", "replace")
            event_id, flags = struct.unpack_from("<QI", page, end + 1)
            node = None
            if version == 2:
                node, = struct.unpack_from("<Q", page, end + 1 + 12)
            if path:
                records.append({"path": path, "event_id": event_id, "flags": decode_flags(flags),
                                "flags_raw": flags, "node_id": node,
                                "version": version, "file": source})
            cursor = end + 1 + fixed
        at += page_length
    return records, problems


def main():
    try:
        args = json.load(sys.stdin)
    except ValueError as exc:
        fail("arguments are not valid JSON", reason=str(exc))
    path = args.get("path")
    if not isinstance(path, str) or not path:
        fail("path is required: an /.fseventsd directory or one record file")
    if not os.path.exists(path):
        fail("no such file or directory", path=path)
    limit = args.get("limit", 2000)
    if not isinstance(limit, int) or isinstance(limit, bool) or limit < 1:
        fail("limit must be a positive integer")
    out_file = args.get("out_file")
    if out_file is not None and (not isinstance(out_file, str) or not out_file):
        fail("out_file must be a non-empty string")
    pattern = None
    if args.get("contains"):
        try:
            pattern = re.compile(args["contains"], re.I)
        except re.error as exc:
            fail("contains is not a valid regex", reason=str(exc))
    wanted = {str(f) for f in (args.get("flags") or [])}

    targets = []
    if os.path.isdir(path):
        for name in sorted(os.listdir(path)):
            full = os.path.join(path, name)
            if os.path.isfile(full) and name != "fseventsd-uuid":
                targets.append(full)
    else:
        targets = [path]
    if not targets:
        fail("no record files there", path=path)

    records, problems, compressed = [], [], 0
    for target in targets:
        try:
            blob, was_gzip = inflate(target)
        except OSError as exc:
            problems.append({"file": target, "why": str(exc)})
            continue
        compressed += 1 if was_gzip else 0
        found, trouble = read_pages(blob, target)
        problems += trouble
        records += found

    kept = []
    for record in records:
        if pattern and not pattern.search(record["path"]):
            continue
        if wanted and not (wanted & set(record["flags"])):
            continue
        kept.append(record)
    ids = [r["event_id"] for r in kept if r["event_id"]]
    if out_file:
        with open(out_file, "w", encoding="utf-8", newline="\n") as fh:
            for record in kept:
                fh.write(json.dumps(record, sort_keys=True) + "\n")
        inline = kept[:limit]
    else:
        inline = kept

    print(json.dumps({
        "path": path,
        "files": len(targets),
        "gzip_files": compressed,
        "records": inline,
        "record_count": len(kept),
        "records_inline": len(inline),
        "complete_records": out_file,
        "records_before_filter": len(records),
        "event_id_range": [min(ids), max(ids)] if ids else None,
        "inline_limited": bool(out_file and len(kept) > len(inline)),
        "problems": problems,
        "note": "There is no timestamp in this format. Event ids are a per-volume counter, so this "
                "gives order and not time: date one path from another artefact and every id either "
                "side of it is bracketed. A record carrying Renamed is a move, not a deletion, and "
                "records are coalesced, so an absent path was not necessarily never touched.",
    }, indent=2))


if __name__ == "__main__":
    main()
