#!/usr/bin/env python3
"""Find the structures inside a memory image that other parsers already read.

A framework needs a symbol profile that matches the build, and on an unusual
build there may not be one. Meanwhile the image is a large blob with recognisable
structures in it, and every one of those structures has a parser in this
project already: a hive carved out of memory goes to regkv exactly as one taken
off a disk would, a chunk goes to evtx_carve, a prefetch record to mam_scan.

That is the whole idea here. This tool finds and cuts; it does not parse. The
offset it returns is the entire provenance of whatever comes out — there is no
path and no file name — so the offset belongs in the report beside anything the
downstream parser says.

Sizes are the amount cut out per hit, chosen to be large enough to hold a
typical instance of that structure. A cut that ends mid-record is truncated, not
corrupt, and the parser that reads it will say so.
"""
import hashlib
import json
import os
import sys
import tempfile
from pathlib import Path

SIGNATURES = [
    (b"regf", "registry hive", 1 << 20),
    (b"ElfChnk\x00", "event log chunk", 65536),
    (b"ElfFile\x00", "event log file", 1 << 20),
    (b"MAM\x04", "compressed prefetch record", 1 << 17),
    (b"SCCA", "prefetch record", 1 << 17),
    (b"MZ\x90\x00\x03", "PE header", 1 << 20),
    (b"SQLite format 3\x00", "SQLite database", 1 << 21),
    (b"FILE0", "MFT record", 1024),
    (b"INDX(", "NTFS index block", 4096),
    (b"\x50\x4b\x03\x04", "zip or office document", 1 << 20),
    (b"%PDF-", "PDF", 1 << 20),
    (b"bplist00", "binary property list", 1 << 16),
]
WINDOW = 1 << 22


def fail(message, **extra):
    print(json.dumps({"error": message, **extra}))
    raise SystemExit(1)


def resolve_output(out):
    """Resolve an output below this agent's work/<id>/ directory.

    A string check is not enough: `work/../inputs/x` and an absolute path
    both name a file the tool must not write, and neither starts with
    "inputs/". Resolving first and comparing directories is what actually
    holds, and the read-only inputs are the one place extracted bytes must
    never appear -- a later integrity check would report the evidence as
    modified.
    """
    root = Path.cwd().resolve()
    dest = (root / out).resolve() if not Path(out).is_absolute() else Path(out).resolve()
    if dest != root and root not in dest.parents:
        fail("output must stay inside the run directory", output=str(out))
    work = (root / "work").resolve()
    if dest == work or work not in dest.parents:
        fail("output must be under your own work/<your id>/ directory", output=str(out))
    relative = dest.relative_to(work)
    if len(relative.parts) < 2 or relative.parts[0] in ("", ".", ".."):
        fail("output must name a path inside work/<your id>/, not work/ itself",
             output=str(out))
    return dest


def main():
    try:
        args = json.load(sys.stdin)
    except ValueError as exc:
        fail("arguments are not valid JSON", reason=str(exc))
    path = args.get("path")
    if not isinstance(path, str) or not path:
        fail("path is required: a memory image, page file or blob")
    if not os.path.isfile(path):
        fail("no such file", path=path)
    limit = args.get("limit")
    if limit is not None and (not isinstance(limit, int) or isinstance(limit, bool) or limit < 1):
        fail("limit must be a positive integer or null")
    max_extract = args.get("max_extract", 25)
    if not isinstance(max_extract, int) or isinstance(max_extract, bool) or max_extract < 0:
        fail("max_extract must be a non-negative integer")
    wanted = {str(k) for k in (args.get("kinds") or [])}
    known = {name for _sig, name, _size in SIGNATURES}
    unknown = wanted - known
    if unknown:
        fail("no signature by that name", unknown=sorted(unknown), kinds=sorted(known))
    signatures = [(s, n, z) for s, n, z in SIGNATURES if not wanted or n in wanted]

    size = os.path.getsize(path)
    start = args.get("start", 0) or 0
    if not isinstance(start, int) or isinstance(start, bool) or start < 0 or start > size:
        fail("start must be a byte offset inside the file")
    max_bytes = args.get("max_bytes")
    if max_bytes is not None and (not isinstance(max_bytes, int) or isinstance(max_bytes, bool) or max_bytes < 1):
        fail("max_bytes must be a positive integer")
    end = min(size, start + max_bytes) if max_bytes is not None else size
    extract_to = args.get("extract_to")
    if extract_to:
        extract_to = resolve_output(extract_to)
        extract_to.mkdir(parents=True, exist_ok=True)

    results_to = args.get("results_to")
    if results_to:
        results_to = resolve_output(results_to)
        source = Path(path).resolve()
        if results_to == source or (results_to.exists() and os.path.samefile(results_to, source)):
            fail("results_to cannot name the source being scanned", output=str(results_to),
                 path=path)
        results_to.parent.mkdir(parents=True, exist_ok=True)
    elif limit is not None:
        fail("results_to is required when limit bounds the JSON preview; the complete hit list must be kept")

    longest = max(len(s) for s, _n, _z in signatures)
    hits, hit_count, extracted, counts = [], 0, 0, {}
    results, temporary_results = None, None
    if results_to:
        fd, temporary_results = tempfile.mkstemp(
            dir=results_to.parent, prefix=".%s." % results_to.name, suffix=".partial")
        results = os.fdopen(fd, "w", encoding="utf-8")
    try:
        with open(path, "rb") as fh:
            position, tail, tail_at = start, b"", start
            while position < end:
                fh.seek(position)
                block = fh.read(min(WINDOW, end - position))
                if not block:
                    break
                buf = tail + block
                base = tail_at
                for signature, name, cut in signatures:
                    at = 0
                    while True:
                        found = buf.find(signature, at)
                        if found < 0:
                            break
                        at = found + 1
                        absolute = base + found
                        # The tail is searched again so a signature split across
                        # two blocks is found.  Do not report one wholly contained
                        # in that tail twice.
                        if absolute + len(signature) <= position:
                            continue
                        entry = {"kind": name, "offset": absolute,
                                 "page_aligned": absolute % 4096 == 0}
                        if extract_to and extracted < max_extract:
                            fh.seek(absolute)
                            piece = fh.read(min(cut, size - absolute))
                            fh.seek(position + len(block))
                            safe = "%012x-%s.bin" % (absolute, name.replace(" ", "_"))
                            target = extract_to / safe
                            with open(target, "wb") as out:
                                out.write(piece)
                            entry["extracted_to"] = str(target)
                            entry["extracted_bytes"] = len(piece)
                            entry["sha256"] = hashlib.sha256(piece).hexdigest()
                            extracted += 1
                        hit_count += 1
                        counts[name] = counts.get(name, 0) + 1
                        if limit is None or len(hits) < limit:
                            hits.append(entry)
                        if results:
                            results.write(json.dumps(entry, separators=(",", ":")) + "\n")
                tail = buf[-(longest - 1):] if len(buf) >= longest else buf
                tail_at = base + len(buf) - len(tail)
                position += len(block)
        if results:
            results.flush()
            os.fsync(results.fileno())
            results.close()
            results = None
            os.replace(temporary_results, results_to)
            temporary_results = None
    finally:
        if results:
            results.close()
        if temporary_results:
            try:
                os.unlink(temporary_results)
            except FileNotFoundError:
                pass
    hits.sort(key=lambda h: h["offset"])
    result = {
        "path": path,
        "bytes_swept": max(0, end - start),
        "hits": hits,
        "hit_count": hit_count,
        "by_kind": counts,
        "extracted": extracted,
        "preview_limited": limit is not None and hit_count > limit,
        "note": "The offset is the whole provenance: a structure carved from memory has no path "
                "and no file name, so the offset belongs in the report beside whatever the parser "
                "says about it. Hand each extract to the tool that reads that format — a hive to "
                "regkv, a chunk to evtx_carve, a prefetch record to mam_scan. A cut that ends "
                "mid-record is truncated, not corrupt.",
    }
    if results_to:
        digest = hashlib.sha256()
        with open(results_to, "rb") as complete:
            for block in iter(lambda: complete.read(1 << 20), b""):
                digest.update(block)
        result["complete_results"] = str(results_to)
        result["complete_results_sha256"] = digest.hexdigest()
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
