#!/usr/bin/env python3
"""Identify a file from its bytes, and say when the name disagrees.

A `.jpg` that is a ZIP, a `.txt` with a PE header, a `.pdf` that is an HTML page
with a script in it — these are not edge cases, they are how things are hidden,
and an examiner who trusts the extension walks past them. So this reads the
header and then compares the answer with what the name claimed.

The hash comes back with it, because the first thing a sample needs is an
identity the report can refer to for the rest of the case.
"""
import hashlib
import json
import os
import sys

class _AdSegments:
    """.ad1, .ad2, ... .ad10 and on: FTK Imager numbers an AD1 image's segments without end."""

    def __contains__(self, ext):
        return len(ext) > 2 and ext[:2] == "ad" and ext[2:].isdigit()

    def __bool__(self):
        return True


AD_SEGMENTS = _AdSegments()

MAGIC = [
    (0, b"MZ", "PE or DOS executable", {"exe", "dll", "sys", "scr", "ocx", "cpl", "efi", "mui", "msi"}),
    (0, b"\x7fELF", "ELF executable or object", {"so", "o", "elf", "bin", ""}),
    (0, b"\xca\xfe\xba\xbe", "Mach-O universal binary", {"dylib", "bundle", ""}),
    (0, b"\xcf\xfa\xed\xfe", "Mach-O 64-bit", {"dylib", "bundle", "o", ""}),
    (0, b"\xce\xfa\xed\xfe", "Mach-O 32-bit", {"dylib", "bundle", "o", ""}),
    (0, b"PK\x03\x04", "ZIP container", {"zip", "docx", "xlsx", "pptx", "docm", "xlsm", "pptm",
                                          "jar", "apk", "odt", "ods", "epub", "whl", "ipa", "aff4"}),
    (0, b"Rar!\x1a\x07", "RAR archive", {"rar"}),
    (0, b"7z\xbc\xaf\x27\x1c", "7-Zip archive", {"7z"}),
    (0, b"\x1f\x8b", "gzip", {"gz", "tgz", "svg", "log"}),
    (0, b"BZh", "bzip2", {"bz2"}),
    (0, b"\xfd7zXZ\x00", "xz", {"xz"}),
    (0, b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1", "OLE compound file", {"doc", "xls", "ppt", "msg",
                                                                   "msi", "db", "ms", "automaticdestinations-ms"}),
    (0, b"%PDF-", "PDF", {"pdf"}),
    (0, b"{\\rtf", "RTF", {"rtf", "doc"}),
    (0, b"\x89PNG\r\n\x1a\n", "PNG", {"png"}),
    (0, b"\xff\xd8\xff", "JPEG", {"jpg", "jpeg"}),
    (0, b"GIF8", "GIF", {"gif"}),
    (0, b"RIFF", "RIFF container (wav, avi, webp)", {"wav", "avi", "webp"}),
    (0, b"SQLite format 3\x00", "SQLite database", {"db", "sqlite", "sqlite3", "history",
                                                    "cookies", "places", "dat", ""}),
    (0, b"regf", "Windows registry hive", {"dat", "hve", "hiv", ""}),
    (0, b"ElfFile\x00", "Windows event log", {"evtx"}),
    (0, b"bplist00", "binary property list", {"plist", "btm", "db", ""}),
    (0, b"<?xml", "XML", {"xml", "plist", "svg", "rels", "config"}),
    (0, b"#!", "script with a shebang", {"sh", "py", "pl", "rb", ""}),
    (0, b"\x4c\x00\x00\x00\x01\x14\x02\x00", "Windows shortcut", {"lnk"}),
    (0, b"MAM\x04", "compressed prefetch record", {"pf"}),
    (0, b"SCCA", "prefetch record", {"pf"}),
    (0, b"\x1f\x8b\x08", "gzip", {"gz"}),
    (0, b"EVF\x09", "EnCase E01 image", {"e01", "ex01"}),
    (0, b"ADSEGMENTEDFILE\x00", "AccessData AD1 logical image (a segment)", AD_SEGMENTS),
    (0, b"ADCRYPT", "AccessData AD1 logical image, encrypted", {"ad1"}),
    (0, b"AVML", "AVML memory capture", {"lime", "raw", "mem"}),
    (0, b"EMiL", "LiME memory capture", {"lime", "raw", "mem"}),
    (0, b"PAGEDU", "Windows crash dump", {"dmp"}),
    (257, b"ustar", "tar archive", {"tar"}),
]
TEXTY = bytes(range(0x20, 0x7f)) + b"\r\n\t\f\b"


def fail(message, **extra):
    print(json.dumps({"error": message, **extra}))
    raise SystemExit(1)


def identify(head):
    for offset, signature, name, extensions in MAGIC:
        if head[offset:offset + len(signature)] == signature:
            return name, extensions
    sample = head[:512]
    if sample and all(b in TEXTY for b in sample):
        lowered = sample.lstrip().lower()
        if lowered.startswith(b"<!doctype html") or lowered.startswith(b"<html"):
            return "HTML", {"html", "htm"}
        return "text", {"txt", "log", "csv", "json", "md", "ini", "conf", "cfg", "yml", "yaml", ""}
    return "unrecognised", set()


def look(path):
    try:
        with open(path, "rb") as fh:
            head = fh.read(4096)
            digest = hashlib.sha256()
            digest.update(head)
            while True:
                block = fh.read(1 << 20)
                if not block:
                    break
                digest.update(block)
    except OSError as exc:
        return {"file": path, "error": str(exc)}
    name, extensions = identify(head)
    claimed = os.path.splitext(path)[1].lstrip(".").lower()
    mismatch = bool(extensions) and claimed not in extensions
    return {"file": path, "bytes": os.path.getsize(path), "type": name,
            "extension": claimed or None, "extension_matches": not mismatch,
            "sha256": digest.hexdigest(),
            "head_hex": head[:16].hex()}


def main():
    try:
        args = json.load(sys.stdin)
    except ValueError as exc:
        fail("arguments are not valid JSON", reason=str(exc))
    path = args.get("path")
    if not isinstance(path, str) or not path:
        fail("path is required: a file or a directory to walk")
    if not os.path.exists(path):
        fail("no such file or directory", path=path)
    limit = args.get("limit", 500)
    if not isinstance(limit, int) or isinstance(limit, bool) or limit < 1:
        fail("limit must be a positive integer")

    targets = []
    if os.path.isdir(path):
        for dirpath, _dirs, names in os.walk(path):
            for name in sorted(names):
                targets.append(os.path.join(dirpath, name))
    else:
        targets = [path]

    files, mismatches = [], 0
    for target in targets:
        entry = look(target)
        if entry.get("extension_matches") is False:
            mismatches += 1
        elif args.get("mismatch_only"):
            continue
        if len(files) >= limit:
            break
        files.append(entry)

    print(json.dumps({
        "path": path,
        "files": files,
        "file_count": len(files),
        "examined": len(targets),
        "extension_mismatches": mismatches,
        "note": "A mismatch is a lead, not a finding: plenty of legitimate files carry an "
                "unexpected extension, and a container type such as ZIP covers a dozen document "
                "formats. What matters is the direction — an executable named .txt is worth a "
                "sentence, a .docx that is a ZIP is simply what a .docx is.",
    }, indent=2))


if __name__ == "__main__":
    main()
