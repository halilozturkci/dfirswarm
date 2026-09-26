#!/usr/bin/env python3
import json, sys, subprocess, os
from pathlib import Path

sys.path.insert(0, str(Path(sys.argv[0]).resolve().parents[1]))
from _output import LosslessPage

args = json.load(sys.stdin)
image = args.get("image", "inputs/Case4.E01")
needle_hex = args.get("needle_hex")
needle_ascii = args.get("needle_ascii")
start = int(args.get("start", 2048 * 512))  # byte offset; default NTFS volume
length = args.get("length")
max_hits = int(args.get("max_hits", 20))
chunk = int(args.get("chunk", 16 * 1024 * 1024))
context = int(args.get("context", 64))
sector_size = 512

if needle_hex:
    needle = bytes.fromhex(needle_hex.replace(" ", ""))
elif needle_ascii:
    needle = needle_ascii.encode("utf-8")
else:
    print(json.dumps({"error": "need needle_hex or needle_ascii"}))
    sys.exit(1)

# Determine media size via img_stat.
#
# This used to fall back to a hard-coded 42949672960 (40 GiB) whenever
# img_stat failed, and then report that number as the image's media_size. On
# an image of any other length the scan walked a range that does not exist,
# img_cat returned nothing for every chunk past the real end, and the tool
# reported "no hits" over a span it had never read. A size it does not know
# is not a size it may invent: either the caller bounds the scan with
# `length`, or the tool says it cannot.
media_size = None
size_source = None
stat_error = None
try:
    out = subprocess.check_output(["img_stat", image], text=True, stderr=subprocess.PIPE)
    for line in out.splitlines():
        if "Size of data in bytes" in line:
            media_size = int(line.split(":")[-1].strip())
            size_source = "img_stat"
except subprocess.CalledProcessError as exc:
    stat_error = (exc.stderr or "").strip()[:500] or f"img_stat exited {exc.returncode}"
except FileNotFoundError:
    stat_error = "img_stat is not on PATH"
except Exception as exc:
    stat_error = str(exc)[:500]

if media_size is None and length is None:
    print(json.dumps({
        "error": "cannot determine the media size of the image, and no length was given",
        "image": image,
        "img_stat": stat_error or "img_stat printed no size",
        "hint": "pass length to bound the scan, or make img_stat work on this image",
    }))
    sys.exit(1)

if length is not None:
    end = start + int(length)
    if media_size is not None:
        end = min(end, media_size)
    if size_source is None:
        size_source = "length argument"
else:
    end = media_size
requested_start = start
if start < sector_size:
    # TSK img_cat refuses sector zero. Do not silently rewrite the requested
    # range: name the first sector as unread and continue at sector one.
    start = sector_size

hits = LosslessPage(
    "sigscan_e01",
    [image, needle.hex(), requested_start, end, context],
    max_hits,
)
read_errors = LosslessPage(
    "sigscan_e01-unread",
    [image, requested_start, end],
    20,
)
if requested_start < sector_size:
    read_errors.add({
        "start": requested_start,
        "end": min(sector_size, end),
        "stderr": "img_cat cannot read sector zero; scan continued at byte 512",
    })
scanned = 0
pos = start
overlap_buf = b""
while pos < end:
    n = min(chunk, end - pos)
    s_sec = pos // sector_size
    e_sec = (pos + n - 1) // sector_size  # inclusive stop
    if s_sec < 1:
        s_sec = 1
    proc = subprocess.run(
        ["img_cat", "-s", str(s_sec), "-e", str(e_sec), image],
        stdout=subprocess.PIPE, stderr=subprocess.PIPE,
    )
    buf = proc.stdout
    if not buf:
        # A chunk that read back empty is a hole or a read error, and the two
        # are not the same thing to a reader deciding whether "no hits" means
        # the signature is absent. Count them and say so in the result.
        read_errors.add({
            "start_sector": s_sec,
            "end_sector": e_sec,
            "stderr": proc.stderr.decode("utf-8", "replace").strip()[:200],
        })
        pos += n
        continue
    # img_cat returns from s_sec, which may be earlier than pos if pos not sector-aligned
    abs_base = s_sec * sector_size
    data = overlap_buf + buf
    data_base = abs_base - len(overlap_buf)
    start_find = 0
    while True:
        i = data.find(needle, start_find)
        if i < 0:
            break
        abs_off = data_base + i
        if abs_off >= start:
            ctx_s = max(0, i - context)
            ctx = data[ctx_s:i + len(needle) + context]
            hits.add({
                "offset": abs_off,
                "sector": abs_off // sector_size,
                "hex": ctx[:160].hex(),
                "ascii": "".join(chr(b) if 32 <= b < 127 else "." for b in ctx[:120]),
            })
        start_find = i + 1
    keep = max(0, len(needle) - 1)
    overlap_buf = data[-keep:] if keep else b""
    scanned += len(buf)
    pos = (e_sec + 1) * sector_size

hit_page = hits.finish()
error_page = read_errors.finish()
print(json.dumps({
    "backend": "img_cat",
    "needle_len": len(needle),
    "hits": hits.page,
    "hit_count": hit_page["matched"],
    **hit_page,
    "scanned_bytes": scanned,
    "start": requested_start,
    "scan_start": start,
    "end": end,
    "reached_end": pos >= end,
    "media_size": media_size,
    "media_size_source": size_source,
    "unread_ranges": read_errors.page,
    "unread_range_count": error_page["matched"],
    **({"all_unread_ranges": error_page["all_results"]} if error_page.get("all_results") else {}),
}, indent=2))
