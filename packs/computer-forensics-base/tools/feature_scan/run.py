#!/usr/bin/env python3
"""Run bulk_extractor and summarise what it found, instead of leaving a directory.

bulk_extractor reads the bytes and ignores the file system entirely, which is
why it finds an address in a deleted mail store, a URL in a pagefile and a card
number in unallocated space when nothing in the listing points at any of them.
That is also its weakness: it returns everything, and a directory of feature
files with a million lines is not an answer.

So this returns the shape first — which feature files exist, how many lines
each holds, and the most frequent distinct values in each — and leaves the
files on disk for the agent to grep when a hit is worth following. The offset
on each line is the provenance; there is no path.
"""
import collections
import json
import os
import shutil
import subprocess
import sys

DEFAULT_TIMEOUT = 900
# Written by bulk_extractor beside the features; they describe the run, not the evidence.
NOT_FEATURES = {"report.xml", "alerts.txt"}
# The scanners bulk_extractor 2.x ships. The ntfs* and win* ones carve records, not
# strings: an $MFT entry, an INDX slack name, a USN record, a prefetch or link file,
# recovered from bytes with no file system around them.
SCANNERS = ["accts", "aes", "base16", "base64", "elf", "email", "evtx", "exif", "facebook",
            "find", "gps", "gzip", "hiberfile", "httplogs", "json", "kml_carved", "msxml",
            "net", "ntfsindx", "ntfslogfile", "ntfsmft", "ntfsusn", "outlook", "pdf", "rar",
            "rtti", "sqlite", "utmp", "vcard_carved", "vin", "windirs", "winlnk", "winpe",
            "winprefetch", "wordlist", "xor", "zip"]


def fail(message, **extra):
    print(json.dumps({"error": message, **extra}))
    raise SystemExit(1)


def summarise(path, top):
    """Feature files are TSV: offset, feature, context. Blank and # lines are headers."""
    counts = collections.Counter()
    lines = 0
    first_offset = None
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as fh:
            for line in fh:
                if not line.strip() or line.startswith("#"):
                    continue
                lines += 1
                parts = line.rstrip("\n").split("\t")
                if len(parts) >= 2:
                    counts[parts[1]] += 1
                    if first_offset is None:
                        first_offset = parts[0]
    except OSError as exc:
        return {"feature": os.path.basename(path), "error": str(exc)}
    return {
        "feature": os.path.basename(path)[:-4] if path.endswith(".txt") else os.path.basename(path),
        "file": path,
        "lines": lines,
        "distinct": len(counts),
        "first_offset": first_offset,
        "top": [{"value": v, "count": c} for v, c in counts.most_common(top)],
    }


def main():
    try:
        args = json.load(sys.stdin)
    except ValueError as exc:
        fail("arguments are not valid JSON", reason=str(exc))

    path = args.get("path")
    if not isinstance(path, str) or not path:
        fail("path is required: an image or any blob")
    if not os.path.isfile(path):
        fail("no such file", path=path)

    out_dir = args.get("out_dir")
    if not isinstance(out_dir, str) or not out_dir:
        fail("out_dir is required: a directory under work/ that does not exist yet")
    if os.path.exists(out_dir) and os.listdir(out_dir):
        fail("out_dir already holds files; bulk_extractor refuses to write into one", out_dir=out_dir)

    binary = shutil.which("bulk_extractor")
    if not binary:
        fail("bulk_extractor is not on PATH",
             install="brew install bulk_extractor, or apt-get install -y bulk-extractor")

    top = args.get("top", 15)
    if not isinstance(top, int) or isinstance(top, bool) or top < 1:
        fail("top must be a positive integer")
    timeout = args.get("timeout_seconds", DEFAULT_TIMEOUT)
    if not isinstance(timeout, int) or isinstance(timeout, bool) or timeout < 10:
        fail("timeout_seconds must be an integer of at least 10")

    argv = [binary, "-o", out_dir]
    only = [str(n) for n in (args.get("only") or [])]
    if len(only) == 1:
        argv += ["-E", only[0]]            # -E is "-x all -E scanner", and only takes one
    elif len(only) > 1:
        argv += ["-x", "all"]
        for name in only:
            argv += ["-e", name]
    for name in (args.get("disable") or []):
        argv += ["-x", str(name)]
    argv.append(path)

    try:
        proc = subprocess.run(argv, capture_output=True, text=True, timeout=timeout)
    except subprocess.TimeoutExpired:
        fail("bulk_extractor did not finish in time", after_seconds=timeout,
             command=" ".join(argv), partial_output=out_dir)

    said = ((proc.stderr or "") + (proc.stdout or ""))
    if "no such scanner" in said:
        named = [l.strip() for l in said.splitlines() if "no such scanner" in l]
        fail("bulk_extractor does not have a scanner by that name", refused=named,
             scanners=SCANNERS, command=" ".join(argv))
    if not os.path.isdir(out_dir):
        fail("bulk_extractor wrote no output directory", exit_code=proc.returncode,
             stderr=(proc.stderr or "").strip(), command=" ".join(argv))

    features = []
    for name in sorted(os.listdir(out_dir)):
        full = os.path.join(out_dir, name)
        if not os.path.isfile(full) or name in NOT_FEATURES or not name.endswith(".txt"):
            continue
        if os.path.getsize(full) == 0:
            continue
        entry = summarise(full, top)
        if entry.get("lines"):
            features.append(entry)

    features.sort(key=lambda f: -(f.get("lines") or 0))
    print(json.dumps({
        "path": path,
        "out_dir": out_dir,
        "exit_code": proc.returncode,
        "scanners_only": args.get("only") or None,
        "features": features,
        "feature_count": len(features),
        "empty_features_omitted": True,
        "note": "Each line in a feature file starts with the byte offset it was found at, and that "
                "offset is the whole provenance: there is no path and no file. A hit is a lead, not "
                "a finding, until you have cut the surrounding bytes and identified what they are.",
    }, indent=2))


if __name__ == "__main__":
    main()
