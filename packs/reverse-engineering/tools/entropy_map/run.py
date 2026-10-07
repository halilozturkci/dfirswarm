#!/usr/bin/env python3
"""Measure Shannon entropy across a file, window by window.

Shannon entropy over a window of bytes measures how evenly the byte values are spread: English text sits
around 4.5 bits per byte, ordinary machine code around 6, and compressed or encrypted data close to 8.
That is all it measures. A high value is consistent with compression, encryption, embedded media or
random-looking data; it says nothing about intent, and it does not identify packing by itself. What makes a
value worth examining is where it is: an executable section, a region inside an otherwise ordinary file, a
run that starts at a section boundary. Installers, signed binaries with compressed resources and archives
all read high.

The whole profile is written to a file, one row per window, and never to a file another call wrote: the name
is chosen from the source (or by the caller), and a name already taken gets a new one, with the earlier file
named in the answer. The answer holds a preview of the profile, the high-entropy runs (the whole list in a
file when there are more than the answer holds), the overall entropy, the bytes actually processed and
whether the pass finished. A window counts as high when its UNROUNDED entropy is >= the threshold.
"""
import errno
import hashlib
import heapq
import json
import math
import os
import re
import sys
from collections import Counter
from pathlib import Path

TOOL = {"name": "entropy_map", "version": 2}
PARSER = "entropy_map/2"
SCHEMA_VERSION = 2
MAX_WINDOW = 1 << 26                    # 64 MiB: one window is held in memory at a time
MAX_INLINE_RUNS = 1000                  # runs held in memory and in the answer; the whole list is a file past this
MAX_PREVIEW = 1_000_000
NAME_RX = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,99}$")


def describe(exc):
    code = errno.errorcode.get(exc.errno, "") if getattr(exc, "errno", None) else ""
    return "%s%s: %s" % (type(exc).__name__, " " + code if code else "", getattr(exc, "strerror", None) or str(exc))


def fail(message, **extra):
    print(json.dumps({"error": message, "status": extra.pop("status", "failed"), "tool": TOOL, **extra}))
    raise SystemExit(1)


def entropy_of(counts, total):
    out = 0.0
    for c in counts.values():
        p = c / total
        out -= p * math.log2(p)
    return out


def output_dir():
    """Where a file this tool writes goes: under $OUT when there is one (a job's output, or a recipe's), otherwise under
    work/<agent>/tool-output, the agent's own place."""
    out = os.environ.get("OUT")
    if out:
        return Path(out)
    agent = re.sub(r"[^A-Za-z0-9_.-]", "_", os.environ.get("AGENT_ID") or "tool")
    return Path("work") / agent / "tool-output"


def create_unique(directory, name):
    """Create a new file `name` in `directory`, exclusively; a name that is taken gets -2, -3, ... before its extension.
    Returns (path, file object, name used). Nothing that exists is replaced or followed."""
    directory.mkdir(parents=True, exist_ok=True)
    stem, dot, ext = name.rpartition(".")
    if not dot:
        stem, ext = name, ""
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
    for n in range(1, 1000):
        candidate = name if n == 1 else "%s-%d%s" % (stem, n, "." + ext if ext else "")
        try:
            fd = os.open(str(directory / candidate), flags, 0o644)
        except FileExistsError:
            continue
        return directory / candidate, os.fdopen(fd, "w", encoding="utf-8"), candidate
    raise OSError(errno.EEXIST, "a thousand files of this name already exist in %s" % directory)


def main():
    try:
        args = json.load(sys.stdin)
    except ValueError as exc:
        fail("arguments are not valid JSON", reason=str(exc))
    if not isinstance(args, dict):
        fail("arguments must be a JSON object")
    path = args.get("path")
    if not isinstance(path, str) or not path:
        fail("path is required: the file to measure")
    if not os.path.isfile(path):
        fail("no such file", path=path)
    window = args.get("window", 4096)
    if not isinstance(window, int) or isinstance(window, bool) or not 64 <= window <= MAX_WINDOW:
        fail("window must be an integer from 64 to %d" % MAX_WINDOW)
    threshold = args.get("threshold", 7.2)
    if not isinstance(threshold, (int, float)) or isinstance(threshold, bool) or not 0 < threshold <= 8:
        fail("threshold must be a number above 0 and at most 8")
    max_windows = args.get("max_windows", 256)
    if not isinstance(max_windows, int) or isinstance(max_windows, bool) or not 1 <= max_windows <= MAX_PREVIEW:
        fail("max_windows must be an integer from 1 to %d" % MAX_PREVIEW)
    requested = args.get("output_name")
    if requested is not None and (not isinstance(requested, str) or not NAME_RX.match(requested)):
        fail("output_name must be a plain file name: letters, digits, '.', '_' and '-', not starting with a dot, no path")

    try:
        size = os.path.getsize(path)
    except OSError as exc:
        fail("the file could not be examined: %s" % describe(exc), path=path)
    if not size:
        fail("the file is empty", path=path)

    directory = output_dir()
    digest = hashlib.sha256(json.dumps([os.path.realpath(path), window]).encode("utf-8", "surrogatepass")).hexdigest()[:12]
    wanted = requested or "entropy-windows-%s-w%d.tsv" % (digest, window)
    try:
        profile_path, profile, profile_name = create_unique(directory, wanted)
    except OSError as exc:
        fail("the complete profile could not be created in %s: %s" % (directory, describe(exc)), path=path)
    profile.write("offset\tbytes\tentropy\n")

    preview = []
    totals = Counter()
    windows = high_windows = processed = 0
    last_bytes = 0
    problems = []
    run_count = 0
    current = None
    first_runs = []                      # runs in the order found, held only until there are more than the answer holds
    biggest = []                         # a heap of the largest runs: (bytes, -start, run)
    runs_file = runs_name = None
    runs_name_wanted = re.sub(r"\.tsv$", "", profile_name) + "-runs.tsv"

    def finish_run(run):
        nonlocal run_count, runs_file, runs_name
        run["bytes"] = run["end"] - run["start"]
        run_count += 1
        item = (run["bytes"], -run["start"], run_count, run)
        if len(biggest) < MAX_INLINE_RUNS:
            heapq.heappush(biggest, item)
        else:
            heapq.heappushpop(biggest, item)
        if runs_file is None and run_count <= MAX_INLINE_RUNS:
            first_runs.append(run)
            return
        if runs_file is None:
            _p, runs_file, runs_name = create_unique(directory, runs_name_wanted)
            runs_file.write("start\tend\tbytes\tpeak\n")
            for kept in first_runs:
                runs_file.write("%d\t%d\t%d\t%.6f\n" % (kept["start"], kept["end"], kept["bytes"], kept["peak"]))
            first_runs.clear()
        runs_file.write("%d\t%d\t%d\t%.6f\n" % (run["start"], run["end"], run["bytes"], run["peak"]))

    complete = True
    try:
        with open(path, "rb") as fh:
            offset = 0
            while True:
                try:
                    block = fh.read(window)
                except OSError as exc:
                    problems.append("a read failed after %d bytes: %s" % (processed, describe(exc)))
                    complete = False
                    break
                if not block:
                    break
                counts = Counter(block)
                totals.update(counts)
                raw = entropy_of(counts, len(block))
                value = round(raw, 6)
                windows += 1
                processed += len(block)
                last_bytes = len(block)
                if len(preview) < max_windows:
                    preview.append({"offset": offset, "bytes": len(block), "entropy": value})
                profile.write("%d\t%d\t%.6f\n" % (offset, len(block), raw))
                if raw >= threshold:
                    high_windows += 1
                    if current is None:
                        current = {"start": offset, "end": offset + len(block), "peak": value}
                    else:
                        current["end"] = offset + len(block)
                        current["peak"] = max(current["peak"], value)
                elif current is not None:
                    finish_run(current)
                    current = None
                offset += len(block)
            if current is not None:
                finish_run(current)
    except OSError as exc:
        problems.append("the pass stopped after %d bytes: %s" % (processed, describe(exc)))
        complete = False
    finally:
        try:
            profile.flush()
            os.fsync(profile.fileno())
            profile.close()
            if runs_file is not None:
                runs_file.flush()
                os.fsync(runs_file.fileno())
                runs_file.close()
        except OSError as exc:
            problems.append("writing the profile failed: %s" % describe(exc))
            complete = False
    if processed != size and complete:
        problems.append("the file is %d bytes and %d were processed (it changed while it was read, or it is not a regular file)" % (size, processed))
        complete = False

    runs = [item[3] for item in sorted(biggest, key=lambda i: (-i[0], -i[1]))] if runs_name else sorted(first_runs, key=lambda r: (-r["bytes"], r["start"]))
    overall = entropy_of(totals, processed) if processed else 0.0
    result = {
        "tool": TOOL,
        "parser": PARSER,
        "schema_version": SCHEMA_VERSION,
        "path": path,
        "bytes": size,
        "bytes_processed": processed,
        "status": "complete" if complete else "partial",
        "problems": problems,
        "window": window,
        "threshold": threshold,
        "threshold_basis": "a window is high when its unrounded entropy is >= the threshold; values are written to 6 decimals",
        "overall_entropy": round(overall, 6),
        "windows_measured": windows,
        "final_window_bytes": last_bytes,
        "high_entropy_windows": high_windows,
        "high_entropy_run_count": run_count,
        "high_entropy_runs": runs,
        "profile": preview,
        "profile_complete": complete,
        "inline_profile_complete": len(preview) == windows,
        "profile_file": profile_name,
        "profile_written_to": str(profile_path),
        "note": "Entropy is a measurement of how evenly byte values are spread: around 4.5 bits per byte is text, around 6 machine code, "
                "close to 8 compressed or encrypted data, and a high value is a feature of the bytes, not a finding. Installers, signed "
                "binaries with compressed resources, archives and media all read high. What makes a run worth examining is where it "
                "starts: an executable section, or a region inside an otherwise ordinary file. It does not identify packing by itself.",
    }
    if profile_name != wanted:
        result["earlier_file_kept"] = wanted
        result["name_note"] = "a file named %s already existed and was left as it was; this profile is %s" % (wanted, profile_name)
    if runs_name:
        result["runs_file"] = runs_name
        result["runs_file_format"] = "tab-separated: start, end, bytes, peak entropy; every run, in the order found"
    if not complete:
        result["error"] = problems[0] if problems else "the pass did not finish"
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    try:
        main()
    except SystemExit:
        raise
    except Exception as exc:  # never a traceback and never a clean answer for a failure
        fail("unexpected failure: %s" % (describe(exc) if isinstance(exc, OSError) else "%s: %s" % (type(exc).__name__, exc)))
