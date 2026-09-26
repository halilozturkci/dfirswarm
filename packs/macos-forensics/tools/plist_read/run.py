#!/usr/bin/env python3
"""Read an XML or binary property list and return JSON-safe values.

Most system plists on a modern macOS are binary. A grep over one finds nothing
while the value sits there in plain sight, and `strings` gives you keys without
values and values without keys — which is how an answer gets assembled out of
two unrelated halves. This is the single commonest wasted hour on the platform,
and plistlib in the standard library removes it entirely.

Dates are the other trap. A plist date is a real type holding seconds since
2001-01-01 UTC, the Apple epoch, and a reader that treats the number as Unix
time is off by thirty-one years. Those are converted here, and every converted
value says it is UTC.
"""
import base64
import datetime
import hashlib
import json
import os
import plistlib
import sys


def fail(message, **extra):
    print(json.dumps({"error": message, **extra}))
    raise SystemExit(1)


def plain(value, max_blob):
    """Make a plist tree JSON-safe without silently losing what a value was."""
    if isinstance(value, dict):
        return {str(k): plain(v, max_blob) for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        return [plain(v, max_blob) for v in value]
    if isinstance(value, datetime.datetime):
        when = value if value.tzinfo else value.replace(tzinfo=datetime.timezone.utc)
        return when.astimezone(datetime.timezone.utc).isoformat().replace("+00:00", "Z")
    if isinstance(value, (bytes, bytearray)):
        head = bytes(value[:max_blob])
        return {"_binary_bytes": len(value),
                "_sha256": hashlib.sha256(bytes(value)).hexdigest(),
                "_base64_head": base64.b64encode(head).decode("ascii"),
                "_head_truncated": len(value) > len(head)}
    if isinstance(value, plistlib.UID):
        return {"_uid": value.data}
    return value


def dig(tree, path):
    cursor = tree
    for part in path.split("."):
        if isinstance(cursor, dict) and part in cursor:
            cursor = cursor[part]
        elif isinstance(cursor, list) and part.isdigit() and int(part) < len(cursor):
            cursor = cursor[int(part)]
        else:
            return None, "no key %r at that level" % part
    return cursor, None


def read_one(path, key, max_blob):
    try:
        with open(path, "rb") as fh:
            head = fh.read(8)
            fh.seek(0)
            tree = plistlib.load(fh)
    except (OSError, plistlib.InvalidFileException, ValueError) as exc:
        return {"file": path, "error": "%s: %s" % (type(exc).__name__, exc)}
    encoding = "binary" if head.startswith(b"bplist") else (
        "xml" if head.lstrip().startswith(b"<") else "unknown")
    out = {"file": path, "encoding": encoding}
    try:
        out["modified"] = datetime.datetime.fromtimestamp(
            os.path.getmtime(path), datetime.timezone.utc).isoformat().replace("+00:00", "Z")
    except OSError:
        pass
    if key:
        value, problem = dig(tree, key)
        if problem:
            out["error"] = problem
            return out
        out["key"] = key
        out["value"] = plain(value, max_blob)
    else:
        out["value"] = plain(tree, max_blob)
        if isinstance(tree, dict):
            out["keys"] = sorted(str(k) for k in tree)
    return out


def main():
    try:
        args = json.load(sys.stdin)
    except ValueError as exc:
        fail("arguments are not valid JSON", reason=str(exc))
    path = args.get("path")
    if not isinstance(path, str) or not path:
        fail("path is required: a .plist file or a directory to walk")
    if not os.path.exists(path):
        fail("no such file or directory", path=path)
    max_blob = args.get("max_blob", 64)
    if not isinstance(max_blob, int) or isinstance(max_blob, bool) or max_blob < 0:
        fail("max_blob must be a non-negative integer")
    limit = args.get("limit", 200)
    if not isinstance(limit, int) or isinstance(limit, bool) or limit < 1:
        fail("limit must be a positive integer")
    out_file = args.get("out_file")
    if out_file is not None and (not isinstance(out_file, str) or not out_file):
        fail("out_file must be a non-empty string")

    targets = []
    if os.path.isdir(path):
        for dirpath, _dirs, names in os.walk(path):
            for name in sorted(names):
                if name.endswith(".plist") or name.endswith(".btm"):
                    targets.append(os.path.join(dirpath, name))
    else:
        targets = [path]
    parsed = [read_one(t, args.get("key"), max_blob) for t in targets]
    if out_file:
        with open(out_file, "w", encoding="utf-8", newline="\n") as fh:
            for item in parsed:
                fh.write(json.dumps(item, default=str, sort_keys=True) + "\n")
        files = parsed[:limit]
    else:
        files = parsed
    print(json.dumps({
        "path": path,
        "files": files,
        "file_count": len(parsed),
        "files_inline": len(files),
        "found": len(targets),
        "complete_files": out_file,
        "inline_limited": bool(out_file and len(parsed) > len(files)),
        "binary_files": sum(1 for f in parsed if f.get("encoding") == "binary"),
        "note": "Dates are converted from the Apple epoch (2001-01-01 UTC) and returned as UTC. A "
                "preference file says what a setting is now, not what it was or who changed it; "
                "its own modified time is when it last changed.",
    }, indent=2, default=str))


if __name__ == "__main__":
    main()
