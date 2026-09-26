#!/usr/bin/env python3
"""Measure entropy across a file, so packing is visible before any disassembly.

Shannon entropy over a window of bytes is a cheap, honest measure of how
compressed or encrypted that window is. English text sits around 4.5 bits per
byte, ordinary machine code around 6, and compressed or encrypted data close to
8. A section at 7.9 is packed, and disassembling it produces nonsense that looks
like analysis.

It says nothing about intent. Every installer, every signed binary with a
compressed resource, and every archive reads the same way. What makes a high
figure interesting is where it is: an executable section that is high, a region
inside an otherwise ordinary file, or a run that starts exactly at a section
boundary.
"""
import json
import math
import os
import sys


def fail(message, **extra):
    print(json.dumps({"error": message, **extra}))
    raise SystemExit(1)


def entropy(block):
    if not block:
        return 0.0
    counts = [0] * 256
    for byte in block:
        counts[byte] += 1
    total = len(block)
    out = 0.0
    for count in counts:
        if count:
            p = count / total
            out -= p * math.log2(p)
    return out


def main():
    try:
        args = json.load(sys.stdin)
    except ValueError as exc:
        fail("arguments are not valid JSON", reason=str(exc))
    path = args.get("path")
    if not isinstance(path, str) or not path:
        fail("path is required: the file to measure")
    if not os.path.isfile(path):
        fail("no such file", path=path)
    window = args.get("window", 4096)
    if not isinstance(window, int) or isinstance(window, bool) or window < 64:
        fail("window must be an integer of at least 64")
    threshold = args.get("threshold", 7.2)
    if not isinstance(threshold, (int, float)) or isinstance(threshold, bool) or not 0 < threshold <= 8:
        fail("threshold must be a number above 0 and at most 8")
    max_windows = args.get("max_windows", 256)
    if not isinstance(max_windows, int) or isinstance(max_windows, bool) or max_windows < 1:
        fail("max_windows must be a positive integer")

    size = os.path.getsize(path)
    if not size:
        fail("the file is empty", path=path)

    readings, runs = [], []
    windows_measured = high_windows = 0
    current = None
    counts = [0] * 256
    out_dir = os.environ.get("OUT")
    profile_file = None
    listing = None
    if out_dir:
        os.makedirs(out_dir, exist_ok=True)
        profile_file = os.path.join(out_dir, "entropy-windows.tsv")
        listing = open(profile_file, "w", encoding="utf-8")
        listing.write("offset\tbytes\tentropy\n")
    with open(path, "rb") as fh:
        offset = 0
        while True:
            block = fh.read(window)
            if not block:
                break
            for byte in block:
                counts[byte] += 1
            value = round(entropy(block), 3)
            windows_measured += 1
            if not listing or len(readings) < max_windows:
                readings.append({"offset": offset, "bytes": len(block), "entropy": value})
            if listing:
                listing.write(f"{offset}\t{len(block)}\t{value}\n")
            if value >= threshold:
                high_windows += 1
                if current is None:
                    current = {"start": offset, "end": offset + len(block), "peak": value}
                else:
                    current["end"] = offset + len(block)
                    current["peak"] = max(current["peak"], value)
            elif current is not None:
                runs.append(current)
                current = None
            offset += len(block)
    if listing:
        listing.close()
    if current is not None:
        runs.append(current)

    total = sum(counts)
    overall = 0.0
    for count in counts:
        if count:
            p = count / total
            overall -= p * math.log2(p)

    step = 1
    profile = readings
    for run in runs:
        run["bytes"] = run["end"] - run["start"]
    runs.sort(key=lambda r: -r["bytes"])

    print(json.dumps({
        "path": path,
        "bytes": size,
        "window": window,
        "threshold": threshold,
        "overall_entropy": round(overall, 3),
        "windows_measured": windows_measured,
        "high_entropy_windows": high_windows,
        "high_entropy_runs": runs,
        "profile": profile,
        "profile_step": step,
        "profile_complete": bool(profile_file) or len(profile) == windows_measured,
        "inline_profile_complete": len(profile) == windows_measured,
        "profile_file": os.path.basename(profile_file) if profile_file else None,
        "note": "Around 4.5 bits per byte is text, around 6 is machine code, and close to 8 is "
                "compressed or encrypted. A high figure is not evidence of anything on its own: "
                "installers, signed binaries with compressed resources and archives all read this "
                "way. What makes it interesting is where the run starts — an executable section, "
                "or a region inside an otherwise ordinary file.",
    }, indent=2))


if __name__ == "__main__":
    main()
