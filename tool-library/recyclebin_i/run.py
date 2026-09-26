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

sys.path.insert(0, str(Path(sys.argv[0]).resolve().parents[1]))
from _output import LosslessPage

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
