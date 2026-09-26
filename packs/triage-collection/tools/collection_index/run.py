#!/usr/bin/env python3
"""Map every file back to the path it had on the machine.

Collectors rewrite paths so they are safe on the examiner's file system, and
each does it differently: a drive letter becomes a directory, a named stream's
colon becomes an underscore, a reserved name is escaped, a long path is
truncated. Citing the path you can see, without the mapping, cites something
that never existed.

So this produces both, per file, with a hash: the path in the collection and the
reconstructed original. A citation that carries both can be followed in either
direction, which is what a reviewer needs.

It also flags the two losses that are otherwise silent: a named stream whose
colon was replaced (the stream may have been dropped instead, and on a Windows
case that can be the whole answer), and a tree whose files all carry the
collection date rather than their own timestamps — which means an intermediate
copy dropped the metadata, and every timestamp conclusion in the case is about
the copy rather than the machine.
"""
import collections
import datetime
import hashlib
import json
import os
import re
import sys

DRIVE_DIR = re.compile(r"^([A-Za-z])(?:\$|_|%3A)?$")
# Greedy, so the split is at the LAST underscore: report.txt_Zone.Identifier
# has to give "report.txt" and "Zone.Identifier", not "report" and the rest.
STREAM_HINT = re.compile(r"^(.+)_(\$?[A-Za-z][\w.$-]{1,40})$")
KNOWN_STREAMS = {"zone.identifier", "sumarryinformation", "favicon", "encryptable",
                 "afp_afpinfo", "afp_resource", "com.dropbox.attributes",
                 "com.apple.quarantine", "ads", "$data"}
RESERVED = {"CON", "PRN", "AUX", "NUL", "COM1", "COM2", "LPT1", "LPT2"}


def fail(message, **extra):
    print(json.dumps({"error": message, **extra}))
    raise SystemExit(1)


def original_path(relative):
    """Undo the rewrites, and say which ones were applied."""
    parts = [p for p in relative.split(os.sep) if p not in ("", ".")]
    notes = []
    if parts:
        found = DRIVE_DIR.match(parts[0])
        if found:
            parts[0] = found.group(1).upper() + ":"
            notes.append("the first component was a drive letter")
        elif parts[0].lower() in ("uploads", "[root]", "root"):
            parts = parts[1:]
            notes.append("the collector's own container directory was removed")
    rebuilt = "\\".join(parts)
    if parts and parts[0].endswith(":"):
        rebuilt = parts[0] + "\\" + "\\".join(parts[1:])
    else:
        rebuilt = "/" + "/".join(parts)
    return rebuilt, notes


def main():
    try:
        args = json.load(sys.stdin)
    except ValueError as exc:
        fail("arguments are not valid JSON", reason=str(exc))
    root = args.get("root")
    if not isinstance(root, str) or not root:
        fail("root is required: the collection directory")
    if not os.path.isdir(root):
        fail("no such directory", root=root)
    disk_images = sorted(n for n in os.listdir(root) if n.lower().endswith(
        (".e01", ".ex01", ".dd", ".raw", ".img", ".vhd", ".vhdx", ".vmdk", ".qcow2")))
    if disk_images:
        fail("this is a disk-image directory, not a logical collection",
             images=disk_images,
             next="run the disk-volumes recipe; do not invent original paths for an image container")
    limit = args.get("limit", 2000)
    if not isinstance(limit, int) or isinstance(limit, bool) or limit < 1:
        fail("limit must be a positive integer")
    want_hash = args.get("hash", True)
    if not isinstance(want_hash, bool):
        fail("hash must be boolean")
    out_file = args.get("out_file")
    if out_file is not None and (not isinstance(out_file, str) or not out_file):
        fail("out_file must be a non-empty string")
    pattern = None
    if args.get("contains"):
        try:
            pattern = re.compile(args["contains"], re.I)
        except re.error as exc:
            fail("contains is not a valid regex", reason=str(exc))

    entries, stream_candidates = [], []
    complete = open(out_file, "w", encoding="utf-8", newline="\n") if out_file else None
    total, indexed, total_bytes = 0, 0, 0
    mtimes = collections.Counter()
    for dirpath, dirs, names in os.walk(root):
        for name in sorted(names):
            full = os.path.join(dirpath, name)
            try:
                stat = os.stat(full)
            except OSError:
                continue
            if not os.path.isfile(full):
                continue
            total += 1
            total_bytes += stat.st_size
            when = datetime.datetime.fromtimestamp(stat.st_mtime, datetime.timezone.utc)
            mtimes[when.strftime("%Y-%m-%d")] += 1
            relative = os.path.relpath(full, root)
            rebuilt, notes = original_path(relative)
            base, extension = os.path.splitext(name)
            if base.upper() in RESERVED or (extension and base.upper() in RESERVED):
                notes.append("a reserved device name, which a Windows collector renames")
            found = STREAM_HINT.match(name)
            if found and "." in found.group(1):
                suffix = found.group(2)
                # A known stream name, or something that looks like one rather than
                # like an ordinary word appended to a file name.
                if suffix.lower() in KNOWN_STREAMS or "." in suffix or suffix.startswith("$"):
                    stream_candidates.append({
                        "file": relative,
                        "possible_original": "%s:%s" % (found.group(1), suffix),
                        "known_stream": suffix.lower() in KNOWN_STREAMS})
            if pattern and not (pattern.search(relative) or pattern.search(rebuilt)):
                continue
            indexed += 1
            entry = {"in_collection": relative, "original_path": rebuilt,
                     "bytes": stat.st_size,
                     "modified": when.isoformat().replace("+00:00", "Z")}
            if notes:
                entry["rewrites_undone"] = notes
            if want_hash:
                digest = hashlib.sha256()
                try:
                    with open(full, "rb") as fh:
                        for block in iter(lambda: fh.read(1 << 20), b""):
                            digest.update(block)
                    entry["sha256"] = digest.hexdigest()
                except OSError as exc:
                    entry["hash_error"] = str(exc)
            if complete:
                complete.write(json.dumps(entry, sort_keys=True) + "\n")
                if len(entries) < limit:
                    entries.append(entry)
            else:
                entries.append(entry)

    if complete:
        complete.close()

    dominant = mtimes.most_common(1)
    flat_times = None
    if dominant and total and dominant[0][1] / total > 0.9 and total > 20:
        flat_times = ("%d of %d files share one modification date (%s). An intermediate copy "
                      "probably dropped the original timestamps, and every timestamp conclusion "
                      "drawn from this tree would be about the copy rather than the machine."
                      % (dominant[0][1], total, dominant[0][0]))

    print(json.dumps({
        "root": root,
        "files": total,
        "bytes": total_bytes,
        "entries": entries,
        "entry_count": indexed,
        "entries_inline": len(entries),
        "complete_index": out_file,
        "inline_limited": bool(out_file and indexed > len(entries)),
        "possible_renamed_streams": stream_candidates,
        "modification_dates": dict(mtimes.most_common(10)),
        "flat_timestamps": flat_times,
        "note": "Cite both paths. 'C:\\\\Users\\\\alice\\\\NTUSER.DAT (in the collection at "
                "C/Users/alice/NTUSER.DAT, sha256 …)' can be followed in either direction; one "
                "without the other cannot. The possible_renamed_streams list is a guess from the "
                "file name shape — check it against the collector's manifest, because a stream "
                "that was DROPPED rather than renamed is a silent loss and on a Windows case can "
                "be the whole answer.",
    }, indent=2))


if __name__ == "__main__":
    main()
