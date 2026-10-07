#!/usr/bin/env python3
"""Say which scheme a volume's or file's first bytes show, and what they do not.

A signature is a lead for a reader, not a finding about the data. This tool
recognises the signatures below from the first kilobytes at a byte offset, reads
the header fields that sit at fixed places in them, and names the reader that
establishes the rest. It parses no BitLocker protector, no LUKS2 keyslot, no APFS
volume flag and no document encryption structure, and it never turns "no
signature found" into "not encrypted".

    BitLocker        "-FVE-FS-" at offset 3 of the volume
    BitLocker To Go  a FAT header ("MSWIN4.1") with an FVE block in its first 4 KiB
    LUKS1 / LUKS2    "LUKS\\xba\\xbe" at offset 0, then the version (1 and 2 only)
    Core Storage     the signature at offset 88
    APFS container   "NXSB" at offset 32 (whether any volume is encrypted is not read)
    ZIP, 7-Zip, PDF, OLE compound file: recognised, with archive_probe as the reader
    no signature     high entropy over the sample is a lead, never an identification

LUKS1 (the LUKS1 on-disk specification): the 592-byte header is 208 bytes of fixed
fields, then eight key slots of 48 bytes: active (4), password iterations (4),
salt (32), key material offset in sectors (4), stripes (4); integers are big-endian.
LUKS2 (cryptsetup's luks2_hdr_disk): a 4096-byte binary header with the label at 24
(48 bytes) and the UUID at 168 (40 bytes), then a JSON area this tool does not read.
"""
import json
import math
import os
import struct
import sys
from collections import Counter

PARSER = "crypto_id/2"
LUKS_MAGIC = b"LUKS\xba\xbe"
SLOT_ENABLED = 0x00AC71F3
SLOT_DISABLED = 0x0000DEAD
LUKS1_FIXED = 208
LUKS1_HEADER = 592
LUKS2_BINARY = 4096
HEAD_BYTES = 8192
MIN_SAMPLE = 1024
MAX_SAMPLE = 1 << 24


def fail(message, **extra):
    print(json.dumps({"error": message, **extra}))
    raise SystemExit(1)


def entropy(blob):
    if not blob:
        return 0.0
    total = len(blob)
    out = 0.0
    for count in Counter(blob).values():
        p = count / total
        out -= p * math.log2(p)
    return round(out, 3)


def text(raw):
    return raw.split(b"\x00", 1)[0].decode("utf-8", "replace")


def read_luks(head):
    if len(head) < 8:
        return {"scheme": "LUKS (version not readable)", "supported": None,
                "header_problem": "the file ends after %d bytes, before the version field is complete" % len(head),
                "basis": "the LUKS magic at offset 0",
                "next_reader": "cryptsetup luksDump, on a complete copy of the header",
                "not_determined": ["the LUKS version", "every header field"]}
    version, = struct.unpack_from(">H", head, 6)
    basis = "the LUKS magic at offset 0 and version %d at offset 6" % version
    if version == 1:
        out = {"scheme": "LUKS1", "version": 1, "basis": basis,
               "next_reader": "cryptsetup luksDump reads and validates the header",
               "not_determined": ["whether any key slot's key material is intact", "which secret opens a slot",
                                  "who added a slot or when"]}
        if len(head) >= LUKS1_FIXED:
            out["cipher"] = text(head[8:40])
            out["cipher_mode"] = text(head[40:72])
            out["hash"] = text(head[72:104])
            out["payload_offset_sectors"], out["key_bytes"] = struct.unpack_from(">II", head, 104)
            out["uuid"] = text(head[168:208])
        if len(head) < LUKS1_HEADER:
            out["header_problem"] = ("the header is cut short: %d of %d bytes (the fixed fields and eight key slots), "
                                     "so the key-slot table was not read" % (len(head), LUKS1_HEADER))
            out["not_determined"].insert(0, "the key slots (the table was not read)")
            return out
        slots = []
        for i in range(8):
            at = LUKS1_FIXED + i * 48
            active, iterations = struct.unpack_from(">II", head, at)
            key_material_offset, stripes = struct.unpack_from(">II", head, at + 40)
            slots.append({"slot": i,
                          "state": "enabled" if active == SLOT_ENABLED else
                                   ("disabled" if active == SLOT_DISABLED else hex(active)),
                          "iterations": iterations,
                          "key_material_offset_sectors": key_material_offset,
                          "stripes": stripes})
        out["key_slots"] = slots
        out["enabled_slots"] = sum(1 for s in slots if s["state"] == "enabled")
        out["slot_note"] = ("An enabled slot is one unlock path in the metadata. It is not a count of distinct "
                            "passwords or people, and the header does not say who added it or when.")
        return out
    if version == 2:
        out = {"scheme": "LUKS2", "version": 2, "basis": basis,
               "next_reader": "cryptsetup luksDump (or --dump-json-metadata) reads the keyslots, digests, segments and tokens",
               "not_determined": ["the keyslots", "the digests", "the segments and where the data starts",
                                  "the tokens", "whether the second copy of the metadata agrees"]}
        if len(head) >= 264:
            out["header_size_bytes"], out["sequence_id"] = struct.unpack_from(">QQ", head, 8)
            out["label"] = text(head[24:72])
            out["checksum_alg"] = text(head[72:104])
            out["uuid"] = text(head[168:208])
            out["subsystem"] = text(head[208:256])
        if len(head) < LUKS2_BINARY:
            out["header_problem"] = "the header is cut short: %d of %d bytes of the binary header" % (len(head), LUKS2_BINARY)
        out["note"] = ("LUKS2 keeps its keyslots, digests, segments and tokens as JSON after the 4096-byte binary "
                       "header; this tool reads the binary header only.")
        return out
    return {"scheme": "LUKS version %d (unsupported by this tool)" % version, "version": version, "supported": False,
            "basis": basis,
            "next_reader": "cryptsetup luksDump, from a build that supports this version",
            "not_determined": ["every header field: this version's layout is not read"]}


def identify(head, sample):
    if head[3:11] == b"-FVE-FS-":
        return {"scheme": "BitLocker", "basis": "\"-FVE-FS-\" at offset 3 of the volume",
                "next_reader": "bdeinfo (libbde) lists the key protectors, a clear key included, with no secret",
                "not_determined": ["the key protectors", "whether a clear key is present",
                                   "the encryption method and the volume's state"]}
    if head[0:6] == LUKS_MAGIC:
        return read_luks(head)
    if head[3:11] == b"MSWIN4.1" and b"-FVE-FS-" in head[:4096]:
        return {"scheme": "BitLocker To Go",
                "basis": "a FAT header (OEM \"MSWIN4.1\") with an FVE block in the first 4 KiB",
                "next_reader": "bdeinfo (libbde) on the BitLocker volume; the plain FAT discovery volume is why a "
                               "stick can look unencrypted",
                "not_determined": ["the key protectors", "whether the data area is the volume this header describes"]}
    if head[88:96] == b"CS\x00\x00\x00\x00\x00\x00":
        return {"scheme": "Apple Core Storage (the layout of legacy FileVault 2), possibly encrypted",
                "basis": "the Core Storage signature at offset 88",
                "next_reader": "fvdeinfo (libfvde), for the Core Storage layout; whether it reads an APFS volume is not established here",
                "not_determined": ["whether the logical volume is encrypted", "which recovery routes exist"]}
    if head[32:36] == b"NXSB":
        return {"scheme": "APFS container", "basis": "\"NXSB\" at offset 32",
                "next_reader": "fsapfsinfo (libfsapfs) lists the container's volumes; its documented limits apply",
                "not_determined": ["whether any volume in the container is encrypted",
                                   "the hardware the encryption depends on"]}
    if head[0:4] == b"\x50\x4b\x03\x04":
        return {"scheme": "ZIP container", "basis": "a ZIP local file header at offset 0",
                "next_reader": "archive_probe lists the members with per-member encryption",
                "not_determined": ["whether any member is encrypted"]}
    if head[0:6] == b"7z\xbc\xaf\x27\x1c":
        return {"scheme": "7-Zip container", "basis": "the 7-Zip signature at offset 0",
                "next_reader": "archive_probe, which lists through 7z where it is installed",
                "not_determined": ["whether the data or the header is encrypted"]}
    if head[0:8] == b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1":
        return {"scheme": "OLE compound file", "basis": "the compound file signature at offset 0",
                "next_reader": "archive_probe reports encryption markers as a heuristic; a structural document "
                               "reader is not provided by this pack",
                "not_determined": ["whether the document is encrypted", "which scheme it uses"]}
    if head[0:5] == b"%PDF-":
        return {"scheme": "PDF", "basis": "\"%PDF-\" at offset 0",
                "next_reader": "archive_probe reports encryption markers as a heuristic; a structural document "
                               "reader is not provided by this pack",
                "not_determined": ["whether the document is encrypted", "whether an opening password is required",
                                   "its permission restrictions"]}
    value = entropy(sample)
    leads = ["VeraCrypt or TrueCrypt", "a detached-header LUKS volume", "plain dm-crypt", "other ciphertext",
             "compressed or random data", "wiped or damaged space", "the wrong offset or the wrong storage layer"]
    if value >= 7.9 and not any(head[:16]):
        return {"scheme": "no signature, high entropy, header zeroed", "entropy": value,
                "basis": "no signature in the first bytes; Shannon entropy %.3f bits per byte over the sample" % value,
                "candidates": leads,
                "next_reader": "none: no reader for VeraCrypt or TrueCrypt is provided. The exhibit list, the "
                               "container's provenance and configuration traces are the corroboration",
                "not_determined": ["whether the data is encrypted", "which scheme, if so"]}
    if value >= 7.9:
        return {"scheme": "no signature, high entropy", "entropy": value,
                "basis": "no signature in the first bytes; Shannon entropy %.3f bits per byte over the sample" % value,
                "candidates": leads,
                "next_reader": "none: high entropy alone is not encryption; a compressed archive reads the same way",
                "not_determined": ["whether the data is encrypted", "which scheme, if so"]}
    return {"scheme": "no scheme this tool recognises", "entropy": value,
            "basis": "no signature in the first bytes; Shannon entropy %.3f bits per byte over the sample" % value,
            "next_reader": "file_type for other formats",
            "not_determined": ["whether the data is encrypted"]}


def main():
    try:
        args = json.load(sys.stdin)
    except ValueError as exc:
        fail("arguments are not valid JSON", reason=str(exc))
    if not isinstance(args, dict):
        fail("arguments must be a JSON object")
    path = args.get("path")
    if not isinstance(path, str) or not path:
        fail("path is required: a volume image, a partition or a file")
    if not os.path.isfile(path):
        fail("no such file", path=path)
    offset = args.get("offset", 0) or 0
    if not isinstance(offset, int) or isinstance(offset, bool) or offset < 0:
        fail("offset must be a byte offset, not a sector offset", offset=args.get("offset"))
    window = args.get("entropy_sample", 65536)
    if not isinstance(window, int) or isinstance(window, bool) or window < MIN_SAMPLE:
        fail("entropy_sample must be an integer of at least %d" % MIN_SAMPLE)
    if window > MAX_SAMPLE:
        fail("entropy_sample must be at most %d (16 MiB)" % MAX_SAMPLE, entropy_sample=window)
    want_head = args.get("include_head_hex", False)
    if not isinstance(want_head, bool):
        fail("include_head_hex must be true or false")

    size = os.path.getsize(path)
    if size == 0:
        fail("the file is empty", path=path, bytes=0)
    if offset >= size:
        fail("the offset is past the end of the file", offset=offset, bytes=size)
    with open(path, "rb") as fh:
        fh.seek(offset)
        head = fh.read(HEAD_BYTES)
        sample = head
        if window > len(head):
            sample = head + fh.read(window - len(head))
        sample = sample[:window]

    body = identify(head, sample)
    out = {"path": path, "offset_bytes": offset, "bytes": size, "parser": PARSER, **body}
    out["entropy_sample_bytes"] = len(sample)
    if want_head:
        out["head_hex"] = head[:32].hex()
        out["head_hex_note"] = ("The first 32 raw bytes of the file supplied, as asked for. If the file is a key or "
                                "credential file these bytes are key material: do not copy them into a report or the ledger.")
    out["note"] = ("A signature identifies a candidate for a reader; it does not show the data is encrypted, intact or "
                   "openable, and no match does not show it is not. An unreadable volume is not necessarily encrypted: "
                   "rule out a logical volume manager, a damaged partition table and a wrong offset first. This tool "
                   "takes a BYTE offset, where mmls and the Sleuth Kit work in sectors.")
    print(json.dumps(out, indent=2))


if __name__ == "__main__":
    main()
