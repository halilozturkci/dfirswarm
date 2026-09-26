#!/usr/bin/env python3
"""Catalogue an Android adb backup without extracting it."""
import argparse
import datetime
import io
import json
import os
import sys
import tarfile
import zlib


MAGIC = b"ANDROID BACKUP\n"


class ZlibReader(io.RawIOBase):
    def __init__(self, source):
        self.source = source
        self.decoder = zlib.decompressobj()
        self.buffer = bytearray()
        self.finished = False

    def readable(self):
        return True

    def readinto(self, target):
        wanted = len(target)
        while len(self.buffer) < wanted and not self.finished:
            chunk = self.source.read(1 << 20)
            if chunk:
                self.buffer.extend(self.decoder.decompress(chunk))
            else:
                self.buffer.extend(self.decoder.flush())
                self.finished = True
        count = min(wanted, len(self.buffer))
        target[:count] = self.buffer[:count]
        del self.buffer[:count]
        return count


def target_of(value):
    text = open(value, encoding="utf-8").read() if os.path.isfile(value) else value
    target = json.loads(text)
    paths = target.get("paths") or []
    if not paths or not isinstance(paths[0], str):
        raise ValueError("the target names no path")
    return paths[0]


def line(handle, label):
    raw = handle.readline(4096)
    if not raw.endswith(b"\n"):
        raise ValueError("Android backup header has no complete %s line" % label)
    return raw[:-1].decode("ascii", "strict")


def header(handle):
    if handle.read(len(MAGIC)) != MAGIC:
        raise ValueError("no Android backup signature")
    version = line(handle, "version")
    compressed = line(handle, "compression")
    encryption = line(handle, "encryption")
    if not version.isdigit():
        raise ValueError("Android backup version is not numeric")
    if compressed not in ("0", "1"):
        raise ValueError("Android backup compression flag is not 0 or 1")
    details = {"version": int(version), "compressed": compressed == "1", "encryption": encryption}
    if encryption != "none":
        details["encryption_header"] = {
            "user_salt": line(handle, "user salt"),
            "checksum_salt": line(handle, "checksum salt"),
            "rounds": line(handle, "rounds"),
            "user_iv": line(handle, "user IV"),
            "master_key_blob": line(handle, "master key blob"),
        }
    details["payload_offset"] = handle.tell()
    return details


def escaped(value):
    return (value.replace("\\", "\\\\").replace("\t", "\\t")
            .replace("\r", "\\r").replace("\n", "\\n"))


def utc(value):
    try:
        return datetime.datetime.fromtimestamp(value, datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    except (OverflowError, OSError, ValueError):
        return ""


def member_type(member):
    if member.isfile():
        return "file"
    if member.isdir():
        return "dir"
    if member.issym():
        return "symlink"
    if member.islnk():
        return "hardlink"
    return "other"


def detect(path):
    try:
        with open(path, "rb") as handle:
            details = header(handle)
        return True, "Android backup header version %d, encryption %s" % (
            details["version"], details["encryption"])
    except (OSError, UnicodeError, ValueError) as exc:
        return False, str(exc)


def run(path, out):
    os.makedirs(out, exist_ok=True)
    errors = []
    member_count = 0
    with open(path, "rb") as source:
        details = header(source)
        with open(os.path.join(out, "backup.json"), "w", encoding="utf-8") as handle:
            json.dump(details, handle, indent=2, sort_keys=True)
            handle.write("\n")
        members_path = os.path.join(out, "members.tsv")
        with open(members_path, "w", encoding="utf-8", newline="\n") as listing:
            listing.write("n\ttype\tpath\tbytes\tmtime_utc\tmode\tlink\n")
            if details["encryption"] == "none":
                stream = io.BufferedReader(ZlibReader(source)) if details["compressed"] else source
                try:
                    with tarfile.open(fileobj=stream, mode="r|") as archive:
                        for member in archive:
                            listing.write("%d\t%s\t%s\t%d\t%s\t%o\t%s\n" % (
                                member_count, member_type(member), escaped(member.name), member.size,
                                utc(member.mtime), member.mode, escaped(member.linkname or "")))
                            member_count += 1
                            archive.members = []
                except (tarfile.TarError, EOFError, OSError, zlib.error) as exc:
                    errors.append("embedded tar traversal stopped: %s" % exc)
    with open(os.path.join(out, "index.tsv"), "w", encoding="utf-8", newline="\n") as handle:
        handle.write("file\twhat\n")
        handle.write("backup.json\tAndroid backup header fields and payload offset\n")
        handle.write("members.tsv\tevery embedded tar member when the payload is not encrypted\n")
    if details["encryption"] != "none":
        status = "partial"
        covered = "header only; encrypted payload not opened"
        errors.append("payload encryption is %s; a password is required" % details["encryption"])
    else:
        status = "partial" if errors else "complete"
        covered = "%d embedded tar members" % member_count
    coverage = {
        "recipe": "android-backup",
        "status": status,
        "covered": covered,
        "not_covered": "files excluded by adb backup policy, deleted data, artifact contents, password recovery",
        "limits_hit": [],
        "errors": errors,
    }
    with open(os.path.join(out, "coverage.json"), "w", encoding="utf-8") as handle:
        json.dump(coverage, handle, indent=2, sort_keys=True)
        handle.write("\n")
    return coverage, member_count


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("command", choices=("detect", "run"))
    parser.add_argument("--target", required=True)
    parser.add_argument("--out")
    args = parser.parse_args()
    try:
        path = target_of(args.target)
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
    try:
        coverage, members = run(path, args.out)
    except (OSError, UnicodeError, ValueError) as exc:
        print(json.dumps({"ok": False, "error": str(exc)}))
        return 2
    print(json.dumps({"ok": True, "status": coverage["status"], "members": members}))
    return 0


if __name__ == "__main__":
    sys.exit(main())
