#!/usr/bin/env python3
"""Measure what was encrypted, rather than assuming everything was.

Four numbers decide most of what an organisation does next, and all four come
from walking the tree:

**How much was actually encrypted.** Campaigns skip by extension, by directory
and by size, and the skipped set is routinely larger than anyone assumes. That
proportion is the first thing a recovery plan needs.

**Whether a file is encrypted throughout or only at the head.** Speed matters to
the operator, so many families encrypt the first few megabytes, or every other
block, or a percentage. A large database encrypted at the head may be
substantially recoverable by somebody who knows the format. Measuring entropy
across the file rather than at the front is what tells them apart, and this does
that.

**The trailing bytes.** Many families write a magic value, a wrapped key or the
original size at the end of each file. The extension is configurable and
affiliates change it; the marker is a far better identifier, and the tails of a
sample are reported for it.

**When it ran.** Encryption rewrites modification times in a tight cluster, so
the histogram of modification times brackets the run on that machine to the
minute.
"""
import collections
import datetime
import json
import math
import os
import sys

KNOWN = {"jpg", "png", "gif", "pdf", "docx", "xlsx", "pptx", "zip", "txt", "csv", "xml",
         "json", "html", "mp4", "mp3", "exe", "dll", "sql", "bak", "vhd", "vmdk", "db",
         "doc", "xls", "ppt", "rtf", "log", "ini", "sys", "dat"}
NOTE_HINTS = ("readme", "decrypt", "restore", "how_to", "howto", "recover", "unlock",
              "ransom", "help_", "_note", "instruction")


def fail(message, **extra):
    print(json.dumps({"error": message, **extra}))
    raise SystemExit(1)


def entropy(block):
    if not block:
        return 0.0
    counts = [0] * 256
    for byte in block:
        counts[byte] += 1
    out, total = 0.0, len(block)
    for count in counts:
        if count:
            p = count / total
            out -= p * math.log2(p)
    return round(out, 3)


def profile(path, size, tail_bytes):
    """Entropy at the head, the middle and the end says how much was rewritten."""
    window = 65536
    spots = [("head", 0), ("middle", max(0, size // 2 - window // 2)),
             ("end", max(0, size - window))]
    out, tail = {}, b""
    try:
        with open(path, "rb") as fh:
            for name, at in spots:
                fh.seek(at)
                out[name] = entropy(fh.read(min(window, size)))
            fh.seek(max(0, size - tail_bytes))
            tail = fh.read(tail_bytes)
    except OSError as exc:
        return {"error": str(exc)}, ""
    return out, tail.hex()


def head_entropy(path, size):
    try:
        with open(path, "rb") as fh:
            return entropy(fh.read(min(65536, size)))
    except OSError:
        return None


def main():
    try:
        args = json.load(sys.stdin)
    except ValueError as exc:
        fail("arguments are not valid JSON", reason=str(exc))
    root = args.get("root")
    if not isinstance(root, str) or not root:
        fail("root is required: a directory to survey")
    if not os.path.isdir(root):
        fail("no such directory", root=root)
    sample_size = args.get("sample", 200)
    if not isinstance(sample_size, int) or isinstance(sample_size, bool) or sample_size < 1:
        fail("sample must be a positive integer")
    tail_bytes = args.get("tail_bytes", 32)
    if not isinstance(tail_bytes, int) or isinstance(tail_bytes, bool) or tail_bytes < 0:
        fail("tail_bytes must be a non-negative integer")
    limit = args.get("limit", 200)
    if not isinstance(limit, int) or isinstance(limit, bool) or limit < 1:
        fail("limit must be a positive integer")

    extensions = collections.Counter()
    double = collections.Counter()
    tails = collections.Counter()
    by_hour = collections.Counter()
    notes, listed = [], []
    total = encrypted_like = skipped = 0
    encrypted_bytes = intact_bytes = 0
    sampled = 0
    head_only = []
    out_dir = os.environ.get("OUT")
    complete_path = None
    complete = None
    if out_dir:
        os.makedirs(out_dir, exist_ok=True)
        complete_path = os.path.join(out_dir, "encrypted-files.jsonl")
        complete = open(complete_path, "w", encoding="utf-8")

    for dirpath, dirs, names in os.walk(root):
        dirs[:] = [d for d in dirs if d not in ("proc", "sys", "dev")]
        for name in sorted(names):
            full = os.path.join(dirpath, name)
            try:
                stat = os.stat(full)
            except OSError:
                continue
            if not os.path.isfile(full):
                continue
            total += 1
            lowered = name.lower()
            if any(hint in lowered for hint in NOTE_HINTS) and stat.st_size < 100000:
                notes.append(full)
            parts = lowered.rsplit(".", 2)
            last = parts[-1] if len(parts) > 1 else ""
            penultimate = parts[-2] if len(parts) > 2 else ""
            extensions[last] += 1
            looks_encrypted = bool(last) and last not in KNOWN and penultimate in KNOWN
            if looks_encrypted:
                double["." + last] += 1
            when = datetime.datetime.fromtimestamp(stat.st_mtime, datetime.timezone.utc)
            by_hour[when.strftime("%Y-%m-%dT%H")] += 1

            head = head_entropy(full, stat.st_size) if stat.st_size > 4096 else None
            high = head is not None and head >= 7.5
            profiled, tail = None, None
            if sampled < sample_size and stat.st_size > 4096 and (high or looks_encrypted):
                profiled, tail = profile(full, stat.st_size, tail_bytes)
                sampled += 1
                if tail:
                    tails[tail] += 1
            if high or looks_encrypted:
                encrypted_like += 1
                encrypted_bytes += stat.st_size
                if profiled and isinstance(profiled, dict) and profiled.get("end", 8) < 6.5:
                    head_only.append({"file": full, "bytes": stat.st_size, **profiled})
            else:
                skipped += 1
                intact_bytes += stat.st_size
            if high or looks_encrypted:
                entry = {"file": full, "bytes": stat.st_size,
                         "modified": when.isoformat().replace("+00:00", "Z"),
                         "appended_extension": "." + last if looks_encrypted else None,
                         "head_entropy": head}
                if profiled:
                    entry["entropy"] = profiled
                if tail:
                    entry["tail_hex"] = tail
                if complete:
                    complete.write(json.dumps(entry, sort_keys=True) + "\n")
                    if len(listed) < limit:
                        listed.append(entry)
                else:
                    listed.append(entry)

    if complete:
        complete.close()

    busiest = by_hour.most_common()
    common_tails = [{"tail_hex": t, "files": c} for t, c in tails.most_common() if c > 1]
    # A family marker sits at a fixed position from the end, with whatever came before
    # it differing per file. The shared suffix across the sampled tails is that marker.
    shared = None
    if sum(tails.values()) > 1:
        raw = [bytes.fromhex(t) for t in tails]
        length = min(len(t) for t in raw)
        keep = 0
        while keep < length and len({t[-(keep + 1)] for t in raw}) == 1:
            keep += 1
        if keep >= 4:
            shared = {"suffix_hex": raw[0][-keep:].hex(), "bytes": keep,
                      "across_files": sum(tails.values()),
                      "why": "every sampled file ends with these bytes: a family marker, and a "
                             "better identifier than the extension"}
    print(json.dumps({
        "root": root,
        "files": total,
        "encrypted_like": encrypted_like,
        "not_encrypted": skipped,
        "proportion_encrypted": round(encrypted_like / total, 4) if total else None,
        "bytes_encrypted_like": encrypted_bytes,
        "bytes_intact": intact_bytes,
        "appended_extensions": [{"extension": e, "files": c} for e, c in double.most_common()],
        "modification_time_clusters": [{"hour_utc": h + ":00Z", "files": c} for h, c in busiest],
        "repeated_file_tails": common_tails,
        "shared_file_suffix": shared,
        "partially_encrypted": head_only,
        "ransom_note_candidates": notes,
        "files_sampled": sampled,
        "examples": listed,
        "examples_complete": complete_path is None or len(listed) == encrypted_like,
        "examples_file": os.path.basename(complete_path) if complete_path else None,
        "note": "A file counts as encrypted-like when its head is high entropy or its name carries "
                "an extension appended after a known one. Both are heuristics: a compressed "
                "archive reads the same way. The partially_encrypted list is the one to act on — "
                "a large file encrypted at the head and intact at the end may be substantially "
                "recoverable by somebody who knows the format. Repeated file tails are a family "
                "marker and a better identifier than the extension, which affiliates change.",
    }, indent=2))


if __name__ == "__main__":
    main()
