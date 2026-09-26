#!/usr/bin/env python3
"""Turn an iOS backup back into a file system.

A backup is not a file tree. It is a flat set of directories named 00 to ff
holding files named by a SHA-1 hash, and `Manifest.db` is the map: for each
hash, the domain it belonged to and its path within that domain. Without the
map the files are unusable; with it they are an iPhone.

The first thing this reports is whether the backup is encrypted, because that
decides whether anything else is possible. The flag is in `Manifest.plist`, and
an encrypted backup is encrypted per file: the databases are inert, and reading
them returns nothing rather than failing loudly. An examiner who misses the flag
reports an empty phone.

The Files table's `file` column is a binary property list holding the real
metadata — size, mode, the four timestamps, the protection class — so those are
decoded here rather than left as a blob.
"""
import datetime
import json
import os
import plistlib
import re
import sqlite3
import sys
import urllib.parse

APPLE_EPOCH = 978307200


def fail(message, **extra):
    print(json.dumps({"error": message, **extra}))
    raise SystemExit(1)


def when(value):
    if value in (None, 0):
        return None
    try:
        number = float(value)
    except (TypeError, ValueError):
        return None
    # iOS has written both epochs into this structure over the years.
    for base in (0, APPLE_EPOCH):
        try:
            made = datetime.datetime.fromtimestamp(number + base, datetime.timezone.utc)
        except (OverflowError, OSError, ValueError):
            continue
        if 2005 <= made.year <= datetime.datetime.now(datetime.timezone.utc).year + 2:
            return made.isoformat().replace("+00:00", "Z")
    return None


def decode_metadata(blob):
    """The file column is a binary plist with an NSKeyedArchiver object graph."""
    if not isinstance(blob, (bytes, bytearray)) or not blob[:8].startswith(b"bplist"):
        return {}
    try:
        tree = plistlib.loads(bytes(blob))
    except Exception:
        return {}
    objects = tree.get("$objects") if isinstance(tree, dict) else None
    if not isinstance(objects, list):
        return {}
    for item in objects:
        if isinstance(item, dict) and "Size" in item:
            out = {}
            for key, target in (("Size", "size"), ("Mode", "mode"),
                                ("UserID", "uid"), ("GroupID", "gid"),
                                ("ProtectionClass", "protection_class"),
                                ("Flags", "flags"), ("InodeNumber", "inode")):
                if key in item:
                    out[target] = item[key]
            for key, target in (("Birth", "created"), ("LastModified", "modified"),
                                ("LastStatusChange", "changed")):
                if key in item:
                    out[target] = when(item[key])
            return out
    return {}


def main():
    try:
        args = json.load(sys.stdin)
    except ValueError as exc:
        fail("arguments are not valid JSON", reason=str(exc))
    path = args.get("path")
    if not isinstance(path, str) or not path:
        fail("path is required: a backup directory or its Manifest.db")
    if not os.path.exists(path):
        fail("no such file or directory", path=path)

    root = path if os.path.isdir(path) else os.path.dirname(path)
    db = path if os.path.isfile(path) else os.path.join(path, "Manifest.db")
    if not os.path.isfile(db):
        fail("no Manifest.db there", looked_at=db,
             note="A backup without a Manifest.db is either iOS 9 or older, which used "
                  "Manifest.mbdb, or not a backup at all.")

    encrypted = None
    info = {}
    plist = os.path.join(root, "Manifest.plist")
    if os.path.isfile(plist):
        try:
            with open(plist, "rb") as fh:
                manifest = plistlib.load(fh)
            encrypted = bool(manifest.get("IsEncrypted"))
            info = {k: manifest.get(k) for k in ("Version", "Date", "WasPasscodeSet")
                    if k in manifest}
            lockdown = manifest.get("Lockdown") or {}
            for key in ("ProductVersion", "ProductType", "DeviceName", "SerialNumber",
                        "UniqueDeviceID"):
                if key in lockdown:
                    info[key] = lockdown[key]
        except Exception as exc:
            info = {"Manifest.plist": "unreadable: %s" % exc}

    if encrypted:
        print(json.dumps({
            "path": path, "manifest_db": db, "encrypted": True, "device": info,
            "entries": [], "entry_count": 0,
            "note": "This backup is encrypted, and iOS encrypts it per file. Without the backup "
                    "password nothing inside it can be read, and the databases will appear empty "
                    "rather than failing. Say that in the report; do not report an empty phone.",
        }, indent=2, default=str))
        return

    pattern = None
    if args.get("contains"):
        try:
            pattern = re.compile(args["contains"], re.I)
        except re.error as exc:
            fail("contains is not a valid regex", reason=str(exc))

    try:
        uri = "file:%s?mode=ro" % urllib.parse.quote(os.path.abspath(db))
        connection = sqlite3.connect(uri, uri=True)
        connection.row_factory = sqlite3.Row
        rows = list(connection.execute("SELECT fileID, domain, relativePath, flags, file FROM Files"))
    except sqlite3.Error as exc:
        fail("Manifest.db would not open", db=db, reason=str(exc))

    entries, domains = [], {}
    for row in rows:
        domain = row["domain"] or ""
        domains[domain] = domains.get(domain, 0) + 1
        relative = row["relativePath"] or ""
        if args.get("domain") and domain != args["domain"]:
            continue
        if pattern and not pattern.search(relative):
            continue
        file_id = row["fileID"] or ""
        on_disk = os.path.join(root, file_id[:2], file_id) if file_id else None
        entry = {"file_id": file_id, "domain": domain, "relative_path": relative,
                 "flags": row["flags"], "kind": {1: "file", 2: "directory", 4: "symlink"}.get(
                     row["flags"], row["flags"]),
                 "on_disk": on_disk if on_disk and os.path.isfile(on_disk) else None}
        entry.update(decode_metadata(row["file"]))
        entries.append(entry)
    connection.close()

    print(json.dumps({
        "path": path, "manifest_db": db, "encrypted": encrypted, "device": info,
        "entries": entries, "entry_count": len(entries),
        "files_in_manifest": len(rows),
        "domains": dict(sorted(domains.items(), key=lambda kv: (-kv[1], kv[0]))),
        "note": "on_disk is where the file actually sits in the backup: the first two characters "
                "of its id are the directory. Cite both the relative path and the file id, "
                "because the path is what the phone called it and the id is what you opened. "
                "A logical backup has no unallocated space, so a question about deletion can only "
                "be answered from inside a database's own free pages. encrypted is null when "
                "Manifest.plist was absent or unreadable; do not treat that as unencrypted.",
    }, indent=2, default=str))


if __name__ == "__main__":
    main()
