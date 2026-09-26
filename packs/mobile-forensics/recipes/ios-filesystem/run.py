#!/usr/bin/env python3
"""Catalogue the forensic structures in an iOS full file-system tar.

The recipe is deliberately structural. It reads every tar header and no member
body, so the catalogue says which parser targets exist without turning a path
into a finding or extracting protected content.
"""
import argparse
import datetime
import json
import os
import re
import sys
import tarfile


IOS_MARKERS = (
    "private/var/mobile/",
    "private/var/containers/",
    "system/library/coreservices/systemversion.plist",
)
SQLITE_SUFFIXES = (".db", ".sqlite", ".sqlite3", ".sqlitedb", ".storedata")


def target_of(value):
    text = open(value, encoding="utf-8").read() if os.path.isfile(value) else value
    target = json.loads(text)
    paths = target.get("paths") or []
    if not paths or not isinstance(paths[0], str):
        raise ValueError("the target names no path")
    return target, paths[0]


def escaped(value):
    return (value.replace("\\", "\\\\").replace("\t", "\\t")
            .replace("\r", "\\r").replace("\n", "\\n"))


def utc(value):
    try:
        return datetime.datetime.fromtimestamp(value, datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    except (OverflowError, OSError, ValueError):
        return ""


def classify(path):
    low = "/" + path.lower().strip("/")
    base = low.rsplit("/", 1)[-1]
    if base in ("sms.db", "callhistory.storedata", "addressbook.sqlitedb"):
        return "communications"
    if base == "knowledgec.db" or "/coreduet/knowledge/" in low:
        return "knowledge"
    if "/biome/" in low or "/biomestreams/" in low or base.endswith(".segb"):
        return "biome-segb"
    if ("/uuidtext/" in low or "/timesync/" in low or "/logd/" in low
            or base.endswith(".tracev3") or ".logarchive/" in low):
        return "unified-log"
    if "/keychains/" in low or base in ("keychain-2.db", "keychain-backup.plist"):
        return "keychain"
    if base == "photos.sqlite" or "/photodata/" in low:
        return "photos"
    if (base == ".com.apple.mobile_container_manager.metadata.plist"
            or "/mobileinstallation/" in low or base == "applicationstate.db"):
        return "app-container-map"
    if base in ("systemversion.plist", "lastbuildinfo.plist"):
        return "device-info"
    return None


def sqlite_base(path):
    low = path.lower()
    for suffix in ("-wal", "-shm", "-journal"):
        if low.endswith(suffix):
            return path[:-len(suffix)], suffix[1:]
    if low.endswith(SQLITE_SUFFIXES):
        return path, "db"
    return None, None


def detect(path):
    if not os.path.isfile(path):
        return False, "not a readable file"
    try:
        with tarfile.open(path, "r:*") as archive:
            for member in archive:
                low = member.name.lower().lstrip("./")
                if any(marker in low for marker in IOS_MARKERS):
                    return True, "tar members have an iOS full file-system root"
    except (tarfile.TarError, OSError) as exc:
        return False, "not a readable tar: %s" % exc
    return False, "tar has no iOS full file-system marker"


def run(path, out):
    os.makedirs(out, exist_ok=True)
    artifacts_path = os.path.join(out, "artifacts.tsv")
    sqlite_path = os.path.join(out, "sqlite.tsv")
    artifacts = []
    databases = {}
    members = 0
    errors = []
    try:
        with tarfile.open(path, "r:*") as archive:
            for member in archive:
                members += 1
                name = member.name.lstrip("./")
                category = classify(name)
                if category:
                    artifacts.append((category, name, member.size, utc(member.mtime), "file" if member.isfile() else "other"))
                base, role = sqlite_base(name)
                if base:
                    item = databases.setdefault(base, {"db": "", "wal": "", "shm": "", "journal": ""})
                    item[role] = str(member.size)
                archive.members = []
    except (tarfile.TarError, EOFError, OSError) as exc:
        errors.append("tar traversal stopped: %s" % exc)

    with open(artifacts_path, "w", encoding="utf-8", newline="\n") as handle:
        handle.write("category\tpath\tbytes\tmtime_utc\ttype\n")
        for category, name, size, mtime, kind in artifacts:
            handle.write("%s\t%s\t%d\t%s\t%s\n" % (category, escaped(name), size, mtime, kind))
    with open(sqlite_path, "w", encoding="utf-8", newline="\n") as handle:
        handle.write("path\tdb_bytes\twal_bytes\tshm_bytes\tjournal_bytes\n")
        for name in sorted(databases):
            item = databases[name]
            handle.write("%s\t%s\t%s\t%s\t%s\n" % (
                escaped(name), item["db"], item["wal"], item["shm"], item["journal"]))
    with open(os.path.join(out, "index.tsv"), "w", encoding="utf-8", newline="\n") as handle:
        handle.write("file\twhat\n")
        handle.write("artifacts.tsv\tiOS forensic structures by category, path, size and archive mtime\n")
        handle.write("sqlite.tsv\tSQLite-family files grouped with WAL, SHM and rollback-journal companions\n")
    categories = {}
    for category, *_ in artifacts:
        categories[category] = categories.get(category, 0) + 1
    coverage = {
        "recipe": "ios-filesystem",
        "status": "partial" if errors else "complete",
        "covered": "%d tar members; %d forensic structures; %d SQLite families" % (
            members, len(artifacts), len(databases)),
        "categories": dict(sorted(categories.items())),
        "not_covered": "artifact contents, deleted data, decryption, semantic findings, nested archives",
        "limits_hit": [],
        "errors": errors,
    }
    with open(os.path.join(out, "coverage.json"), "w", encoding="utf-8") as handle:
        json.dump(coverage, handle, indent=2, sort_keys=True)
        handle.write("\n")
    return coverage


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("command", choices=("detect", "run"))
    parser.add_argument("--target", required=True)
    parser.add_argument("--out")
    args = parser.parse_args()
    try:
        _, path = target_of(args.target)
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        print(json.dumps({"ok": False, "error": str(exc)}))
        return 2
    if args.command == "detect":
        applies, why = detect(path)
        print(json.dumps({"applies": applies, "why": why}))
        return 0 if applies else 1
    if not args.out:
        print(json.dumps({"ok": False, "error": "run needs --out DIR"}))
        return 2
    applies, why = detect(path)
    if not applies:
        print(json.dumps({"ok": False, "status": "unsupported", "why": why}))
        return 2
    coverage = run(path, args.out)
    print(json.dumps({"ok": True, "status": coverage["status"], "artifacts": sum(coverage["categories"].values())}))
    return 0


if __name__ == "__main__":
    sys.exit(main())
