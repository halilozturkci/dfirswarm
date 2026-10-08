#!/usr/bin/env python3
"""ad1-items: the item list of an AccessData AD1 logical image, each file's
content inflated to check the digests the image records; nothing extracted.

    run.py detect --target TARGET [--probe-out DIR]   exit 0 applies, 1 does not, 2 error
    run.py run --target TARGET --out DIR              members.tsv, attributes.tsv, image.json,
                                                      index.tsv and coverage.json in DIR

TARGET is JSON (inline or a file path): {"paths": [...], "ref": ..., "name": ...};
the image is paths[0], its first segment; paths[1:] are its further segments
when given, else they are looked for beside it (x.ad2, x.ad3, ...). Every
item is one row of members.tsv:

    n  type  path  path_b64  size  packed  mtime  tz  mode  uid  gid  link  locator  flags
    atime  btime  md5  sha1  sha256  check  class

The first fourteen columns are archive-members' own, so catalog_search
which=members and a member:<generation>#<n> reference read it the same way.
`n` counts from 0 in the image's own order (an item, its children, then its
next sibling) and is what ad1_extract takes; a folder's n takes its subtree.
When the listing is partial (a segment missing, an item that cannot be
read), the items after a break are numbered without it, so a whole read
numbers them otherwise: `locator` (ad1:item=<address>) names an item the
same way in both, and ad1_extract takes it too. `path` is the item's names
joined by "/" under the image's data source name (image.json), escaped as
archive-members escapes them, and `path_b64` its exact bytes. `type` is
file, dir or other:<n>; an item the image marks as a file of unknown kind or
as deleted is a file, flagged so. `size` is the content's size, `packed` the
bytes of its zlib chunks. The times are the image's own text, as dissect
reads them: mtime the modified time (key 0x9), atime the accessed (0x7),
btime the created (0x8), with no zone the image records (`tz` is unknown).
`md5` and `sha1` are the digests the image records for the item; `sha256`
is of the content as this recipe inflated it; `check` says whether that
content matches the recorded digests: ok, mismatch, no-stored-hash, or
not-read (why is in coverage.json). `class` is the file class the image
records (regular file, folder, reparse point, ...). `flags` names what an
examiner should know first: escapes-root (a name that is empty, "." or
"..", or holds a "/"), name-not-utf8, hash-mismatch, unknown-file, deleted,
and encrypted (the source file system's encryption flag: the content may be
ciphertext). attributes.tsv holds every metadata entry of every item (n,
category, key, label, text), so nothing the image records is left out, and
image.json the segment and logical image headers and the image's own
metadata (its data source name).
"""
import base64
import hashlib
import json
import os
import re
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
MAX_ITEMS = 5_000_000
COLUMNS = ["n", "type", "path", "path_b64", "size", "packed", "mtime", "tz", "mode", "uid", "gid", "link", "locator", "flags",
           "atime", "btime", "md5", "sha1", "sha256", "check", "class"]
# The metadata keys as dissect.evidence names them (its MetaType); a key
# not here keeps its number, and attributes.tsv has every one.
LABELS = {
    0x01: "content hashes", 0x02: "file class", 0x03: "file size", 0x04: "physical size", 0x05: "timestamps",
    0x06: "start cluster", 0x07: "accessed", 0x08: "created", 0x09: "modified", 0x0D: "encrypted", 0x0E: "compressed",
    0x1E: "actual file", 0x1F: "start sector", 0x24: "alternate data streams",
    0x1001: "short name", 0x1002: "hidden", 0x1003: "system", 0x1004: "read-only", 0x1005: "archive",
    0x2001: "POSIX permissions", 0x5001: "md5", 0x5002: "sha1",
    0x9001: "cluster size", 0x9002: "cluster count", 0x9003: "free clusters", 0x9006: "volume serial number",
    0xA001: "MFT record number", 0xA002: "MFT record changed", 0xA003: "MFT resident", 0xA004: "MFT offline",
    0xA005: "MFT sparse", 0xA006: "MFT temporary", 0xA007: "owner SID", 0xA008: "owner name", 0xA009: "group SID",
    0xA00A: "group name", 0xA01C: "$FILE_NAME created", 0xA01D: "$FILE_NAME modified", 0xA01E: "$FILE_NAME accessed",
    0xA01F: "$FILE_NAME changed", 0xA020: "$FILE_NAME size", 0xA021: "$FILE_NAME physical size", 0xA028: "$I30 name",
    0xA029: "$I30 size", 0xA02A: "$I30 physical size", 0xA02B: "$I30 created", 0xA02C: "$I30 modified",
    0xA02D: "$I30 accessed", 0xA02E: "$I30 changed", 0x10002: "data source name",
}
CLASSES = {b"1": "regular file", b"2": "placeholder", b"3": "folder", b"4": "file system metadata", b"6": "file slack",
           b"9": "symbolic link", b"11": "reparse point"}


# --- AD1 reader ---------------------------------------------------------------
# The same block in recipes/ad1-items/run.py and tools/ad1_extract/run.py;
# tests/ad1-pack.test.ts holds the two equal. An AccessData AD1 logical image
# (FTK Imager's "custom content image") as the public descriptions of the
# format lay it out (dissect.evidence's ad1, AD1-tools' libad1, pyad1):
#
#   every segment file   a header: "ADSEGMENTEDFILE", at 0x18 its number
#                        (from 1), at 0x1c the number of segments, at 0x20
#                        its size in bytes with the header, at 0x28 the
#                        header's own size (512); then its share of the data
#   the image's data     one address space running on from segment to
#                        segment; at address 0 the logical image header:
#                        "ADLOGICALIMAGE", +16 version (4), +24 zlib chunk
#                        size, +28 the image's own metadata, +36 the first
#                        item, +44 the data source name's length, +52 its
#                        address
#   an item              +0 next sibling, +8 first child, +16 first metadata
#                        entry, +24 chunk table, +32 size, +40 type (0 a
#                        file, 1 a file of unknown kind, 2 deleted, 5 a
#                        folder), +44 name length, +48 the name (UTF-8)
#   a metadata entry     +0 next, +8 category, +12 key, +16 length, +20 text
#   a chunk table        +0 count, +8 count + 1 addresses: chunk i is the
#                        zlib stream from address i to address i + 1
#
# Every address is held to the data the segments hold, every chain to one
# visit per address, the tree to a depth, every count to what the image can
# hold and to a ceiling, every chunk to the chunk size and every file to its
# size: a damaged or hostile image is named, never followed.
import bisect as _bisect
import os as _os
import struct as _struct
import zlib as _zlib

AD1_SEGMENT_MAGIC = b"ADSEGMENTEDFILE\x00"
AD1_LOGICAL_MAGIC = b"ADLOGICALIMAGE"
AD1_ENCRYPTED_MAGIC = b"ADCRYPT"
AD1_VERSION = 4
AD1_FILE, AD1_UNKNOWN_FILE, AD1_DELETED, AD1_FOLDER = 0, 1, 2, 5
AD1_SEGMENTS_MAX = 4096           # 6 TB at FTK Imager's default 1500 MB a segment
AD1_CHUNK_MIN, AD1_CHUNK_MAX = 512, 1 << 24   # FTK Imager writes 65536
AD1_NAME_MAX = 1 << 16
AD1_TEXT_MAX = 1 << 20
AD1_META_MAX = 1 << 16            # entries in one metadata chain
AD1_META_BYTES_MAX = 64 << 20     # bytes of text in one metadata chain
AD1_DEPTH_MAX = 1024
AD1_OPEN_MAX = 64                 # segment files held open at once
AD1_TABLE_BATCH = 4096            # chunk addresses read at a time
AD1_CHUNKS_MAX = 1 << 26          # one file's chunks: 4 TiB at FTK Imager's 64 KiB


class AD1Error(Exception):
    pass


def ad1_segment_header(head):
    """The segment header's fields from a file's first bytes, or an AD1Error."""
    if head.startswith(AD1_ENCRYPTED_MAGIC):
        raise AD1Error("an encrypted AD1 image (ADCRYPT header): it is read only once decrypted with its key")
    if len(head) < 0x2C or not head.startswith(AD1_SEGMENT_MAGIC):
        raise AD1Error("no ADSEGMENTEDFILE header")
    number, count, size = _struct.unpack_from("<IIQ", head, 0x18)
    header = _struct.unpack_from("<I", head, 0x28)[0]
    if not 0x30 <= header <= 0x10000:
        raise AD1Error("the segment header says it is %d bytes long" % header)
    if not 1 <= count <= AD1_SEGMENTS_MAX:
        raise AD1Error("the segment header says the image has %d segments (this reader takes 1 to %d)" % (count, AD1_SEGMENTS_MAX))
    if not 1 <= number <= count:
        raise AD1Error("the segment header says segment %d of %d" % (number, count))
    if size <= header:
        raise AD1Error("the segment header says a segment is %d bytes, header included" % size)
    return {"index": number, "count": count, "bytes": size, "header": header}


def ad1_where(parent):
    return parent.decode("utf-8", "replace") if parent else "the root"


class AD1:
    """An AD1 image opened read-only from its first segment (and the paths of
    the rest, when given; else beside it, x.ad2, x.ad3, ...). `missing` names
    the segments that are not there; an address in one of them is an
    AD1Error where it is read. `errors` names what the headers said that
    could not be taken."""

    def __init__(self, first, more=()):
        with open(first, "rb") as fh:
            self.segment = ad1_segment_header(fh.read(0x30))
        if self.segment["index"] != 1:
            raise AD1Error("segment %d of %d of an AD1 image: the image is read from its first segment" % (self.segment["index"], self.segment["count"]))
        count = self.segment["count"]
        given = [first] + list(more)
        stem, ext = _os.path.splitext(first)
        beside = ext[1:3].lower() == "ad" and ext[3:] == "1"
        self.paths, self.names, self.missing, self.errors, self.walk_errors = [], [], [], [], []
        self.margins, self.starts = [], [0]
        for k in range(1, count + 1):
            p = given[k - 1] if k <= len(given) else (stem + ext[:-1] + str(k) if beside else None)
            margin, span = self.segment["header"], self.segment["bytes"] - self.segment["header"]
            if p and _os.path.isfile(p):
                with open(p, "rb") as fh:
                    h = ad1_segment_header(fh.read(0x30))
                    size = _os.fstat(fh.fileno()).st_size
                if h["index"] != k or h["count"] != count:
                    raise AD1Error("%s says it is segment %d of %d, where segment %d of %d belongs" % (_os.path.basename(p), h["index"], h["count"], k, count))
                margin, span = h["header"], h["bytes"] - h["header"]
                if size - margin > span:
                    raise AD1Error("%s holds more than the %d bytes of data its header says" % (_os.path.basename(p), span))
            else:
                self.missing.append(_os.path.basename(p) if p else "segment %d (the first is not named .ad1)" % k)
                p = None
            self.names.append(_os.path.basename(p) if p else self.missing[-1])
            self.paths.append(p)
            self.margins.append(margin)
            self.starts.append(self.starts[-1] + span)
        self.end = self.starts[-1]
        self._open = {}
        if self.read(0, 14) != AD1_LOGICAL_MAGIC:
            raise AD1Error("no ADLOGICALIMAGE header at the start of the image's data")
        (self.version,) = _struct.unpack("<I", self.read(16, 4))
        if self.version != AD1_VERSION:
            raise AD1Error("an AD1 logical image of version %d: this reader reads version %d" % (self.version, AD1_VERSION))
        (self.chunk_size,) = _struct.unpack("<I", self.read(24, 4))
        if not AD1_CHUNK_MIN <= self.chunk_size <= AD1_CHUNK_MAX:
            raise AD1Error("the logical image header says its chunks are %d bytes (this reader takes %d to %d)" % (self.chunk_size, AD1_CHUNK_MIN, AD1_CHUNK_MAX))
        self.meta_addr, self.first_item, name_len = _struct.unpack("<QQI", self.read(28, 20))
        (name_addr,) = _struct.unpack("<Q", self.read(52, 8))
        self.source_name = b""
        if name_len > AD1_TEXT_MAX:
            self.errors.append("the data source name says it is %d bytes long: not read" % name_len)
        elif name_addr:
            try:
                self.source_name = self.read(name_addr, name_len)
            except AD1Error as e:
                self.errors.append("the data source name cannot be read: %s" % e)

    def close(self):
        for fh in self._open.values():
            fh.close()
        self._open = {}

    def _fh(self, k):
        fh = self._open.pop(k, None)
        if fh is None:
            if len(self._open) >= AD1_OPEN_MAX:
                self._open.pop(next(iter(self._open))).close()
            fh = open(self.paths[k], "rb")
        self._open[k] = fh
        return fh

    def read(self, addr, n):
        """n bytes of the image's data from addr, across segments."""
        if addr < 0 or n < 0 or addr + n > self.end:
            raise AD1Error("address %d (+%d) is outside the image's data" % (addr, n))
        out = bytearray()
        while len(out) < n:
            at = addr + len(out)
            k = _bisect.bisect_right(self.starts, at) - 1
            if self.paths[k] is None:
                raise AD1Error("address %d is in segment %d, which is not there (%s)" % (at, k + 1, self.names[k]))
            off = at - self.starts[k]
            want = min(n - len(out), self.starts[k + 1] - at)
            got = _os.pread(self._fh(k).fileno(), want, self.margins[k] + off)
            if len(got) < want:
                raise AD1Error("address %d (+%d) runs past the end of segment %d: the image is truncated" % (addr, n, k + 1))
            out += got
        return bytes(out)

    def metadata(self, addr):
        """[(category, key, text bytes, address)] of a metadata chain."""
        out, seen, held = [], set(), 0
        while addr:
            if addr in seen:
                raise AD1Error("the metadata chain loops back to address %d" % addr)
            seen.add(addr)
            nxt, cat, key, length = _struct.unpack("<QIII", self.read(addr, 20))
            if length > AD1_TEXT_MAX:
                raise AD1Error("a metadata entry at address %d says it is %d bytes" % (addr, length))
            held += length
            if len(out) >= AD1_META_MAX or held > AD1_META_BYTES_MAX:
                raise AD1Error("a metadata chain holds more than %d entries or %d bytes of text: not read further" % (AD1_META_MAX, AD1_META_BYTES_MAX))
            out.append((cat, key, self.read(addr + 20, length), addr))
            addr = nxt
        return out

    def walk(self):
        """Every item, depth first in the image's own order (an item, its
        children, then its next sibling), numbered from 0, with its path
        (names joined by "/"). A node that cannot be read ends its chain,
        and is named in walk_errors: a numbering after it is not the
        numbering of a whole read, and an item's address (locator) is."""
        seen, n = set(), 0
        stack = [(self.first_item, b"", None, 0)] if self.first_item else []
        while stack:
            addr, parent, parent_n, depth = stack.pop()
            if addr in seen:
                self.walk_errors.append("the tree loops back to item address %d under %s: not followed" % (addr, ad1_where(parent)))
                continue
            seen.add(addr)
            if depth >= AD1_DEPTH_MAX:
                self.walk_errors.append("item at address %d under %s is nested deeper than %d levels: it and the siblings after it are not listed" % (addr, ad1_where(parent), AD1_DEPTH_MAX))
                continue
            try:
                nxt, child, meta, table, size, kind, name_len = _struct.unpack("<QQQQQII", self.read(addr, 48))
                if name_len > AD1_NAME_MAX:
                    raise AD1Error("its name is %d bytes long" % name_len)
                name = self.read(addr + 48, name_len)
                meta = self.metadata(meta)
            except AD1Error as e:
                self.walk_errors.append("item at address %d under %s cannot be read: %s; it and the siblings after it are not listed" % (addr, ad1_where(parent), e))
                continue
            path = parent + b"/" + name if parent_n is not None else name
            item = {"n": n, "addr": addr, "parent": parent_n, "path": path, "name": name, "type": kind,
                    "size": size, "table": table, "meta": meta}
            n += 1
            if nxt:
                stack.append((nxt, parent, parent_n, depth))
            if child:
                stack.append((child, path, item["n"], depth + 1))
            yield item

    def chunks(self, item):
        """The compressed byte ranges of an item's content, its chunk table
        read a batch at a time; an AD1Error at the first range out of order,
        outside the data or larger than a chunk's zlib stream can be."""
        table = item["table"]
        if not table:
            if item["size"]:
                raise AD1Error("it has no chunk table for its %d bytes" % item["size"])
            return
        (count,) = _struct.unpack("<Q", self.read(table, 8))
        most = (item["size"] + self.chunk_size - 1) // self.chunk_size
        room = (self.end - table - 8) // 8 - 1
        if count > max(most, 1) or count > room or count > AD1_CHUNKS_MAX:
            raise AD1Error("its chunk table lists %d chunks for %d bytes" % (count, item["size"]))
        packed_max = 2 * self.chunk_size + 1024
        prev, i, at, left = None, 0, table + 8, count + 1
        while left:
            take = min(left, AD1_TABLE_BATCH)
            for a in _struct.unpack("<%dQ" % take, self.read(at, 8 * take)):
                if prev is not None:
                    if a < prev or a > self.end or a - prev > packed_max:
                        raise AD1Error("its chunk %d runs from address %d to %d" % (i, prev, a))
                    yield prev, a
                    i += 1
                prev = a
            at += 8 * take
            left -= take

    def content(self, item):
        """An item's content, chunk by chunk, each inflated within the chunk
        size; an AD1Error when a chunk does not inflate whole or the content
        is not the item's size."""
        bound = self.chunk_size
        total = 0
        for i, (start, end) in enumerate(self.chunks(item)):
            z = _zlib.decompressobj()
            try:
                block = z.decompress(self.read(start, end - start), bound + 1)
            except _zlib.error as e:
                raise AD1Error("its chunk %d does not inflate: %s" % (i, e))
            if len(block) > bound or z.unconsumed_tail:
                raise AD1Error("its chunk %d inflates past the chunk size of %d" % (i, bound))
            if not z.eof or z.unused_data:
                raise AD1Error("its chunk %d is not one whole zlib stream" % i)
            total += len(block)
            if total > item["size"]:
                raise AD1Error("its content runs past its size of %d bytes" % item["size"])
            yield block
        if total != item["size"]:
            raise AD1Error("its content is %d bytes, not its size of %d" % (total, item["size"]))


def ad1_text(meta, key):
    """The text of the first metadata entry with this key, or None."""
    for _c, k, v, _a in meta:
        if k == key:
            return v
    return None
# --- end of the AD1 reader ----------------------------------------------------


def limits():
    try:
        lim = json.load(open(os.path.join(HERE, "recipe.json"))).get("limits", {})
    except Exception:
        lim = {}
    return int(os.environ.get("RECIPE_SECONDS") or lim.get("seconds") or 3600)


def target_of(arg):
    text = open(arg, encoding="utf-8").read() if os.path.isfile(arg) else arg
    t = json.loads(text)
    paths = t.get("paths") or []
    if not paths or not all(isinstance(p, str) for p in paths):
        raise SystemExit(json.dumps({"ok": False, "error": "the target names no path"}))
    return t, paths


def esc(raw):
    """A name or a text for a reader: one line, one field, nothing hidden."""
    out = []
    for ch in raw.decode("utf-8", "surrogateescape"):
        o = ord(ch)
        if 0xDC80 <= o <= 0xDCFF:
            out.append("\\x%02x" % (o - 0xDC00))
        elif ch == "\\":
            out.append("\\\\")
        elif ch == "\t":
            out.append("\\t")
        elif ch == "\n":
            out.append("\\n")
        elif ch == "\r":
            out.append("\\r")
        elif o < 0x20 or o == 0x7F:
            out.append("\\x%02x" % o)
        else:
            out.append(ch)
    return "".join(out)


STAMP = re.compile(rb"^(\d{4})(\d{2})(\d{2})T(\d{2})(\d{2})(\d{2})(\.\d+)?$")


def stamp(raw):
    """The image's time text (20231004T101112.123456) as ISO 8601 with no zone; any other text as it is."""
    if raw is None:
        return ""
    m = STAMP.match(raw.strip())
    if not m:
        return esc(raw)
    g = [x.decode() for x in m.groups(b"")]
    return "%s-%s-%sT%s:%s:%s%s" % tuple(g)


def detect(path):
    """(format, why) or (None, why), from the headers alone."""
    try:
        with open(path, "rb") as fh:
            head = fh.read(0x30)
            seg = ad1_segment_header(head)
            if seg["index"] != 1:
                return None, "segment %d of %d of an AD1 image: the image is read, and catalogued, from its first segment (.ad1)" % (seg["index"], seg["count"])
            fh.seek(seg["header"])
            logical = fh.read(20)
    except OSError as e:
        return None, "unreadable: %s" % (e.strerror or e)
    except AD1Error as e:
        return None, str(e)
    if not logical.startswith(AD1_LOGICAL_MAGIC):
        return None, "an ADSEGMENTEDFILE header with no ADLOGICALIMAGE header after it"
    version = int.from_bytes(logical[16:20], "little")
    if version != AD1_VERSION:
        return None, "an AD1 logical image of version %d: this recipe reads version %d" % (version, AD1_VERSION)
    return "AD1", "an AD1 logical image (version 4, segment 1 of %d)" % seg["count"]


def row_of(img, item, w, deadline, cov, escapes):
    meta = item["meta"]
    raw_path = item["path"]
    flags = []
    try:
        item["name"].decode("utf-8")
    except UnicodeDecodeError:
        flags.append("name-not-utf8")
    # A name that climbs, or one under it: the parent's mark is carried down.
    if item["name"] in (b"", b".", b"..") or b"/" in item["name"] or item["parent"] in escapes:
        flags.append("escapes-root")
        escapes.add(item["n"])
    if item["type"] == AD1_UNKNOWN_FILE:
        flags.append("unknown-file")
    if item["type"] == AD1_DELETED:
        flags.append("deleted")
    if (ad1_text(meta, 0x0D) or b"").strip().lower() == b"true":
        flags.append("encrypted")
    is_file = item["type"] in (AD1_FILE, AD1_UNKNOWN_FILE, AD1_DELETED)
    kind = "dir" if item["type"] == AD1_FOLDER else "file" if is_file else "other:%d" % item["type"]
    # As recorded, escaped as any text is: a field never breaks the row.
    md5 = esc((ad1_text(meta, 0x5001) or b"").strip()).lower()
    sha1 = esc((ad1_text(meta, 0x5002) or b"").strip()).lower()
    packed, sha256, check = "", "", ""
    ranges = True
    try:
        packed = ""
        if item["table"]:
            packed = 0
            for k, (c_start, c_end) in enumerate(img.chunks(item)):
                packed += c_end - c_start
                if k and k % 4096 == 0 and time.monotonic() > deadline:
                    packed = ""        # cut by the clock: not known, and the file is not inflated either
                    break
    except AD1Error as e:
        ranges = None
        cov["errors"].append("item %d (%s, %s): %s" % (item["n"], esc(raw_path), "ad1:item=%d" % item["addr"], e))
    if item["type"] != AD1_FOLDER:
        if ranges is None:
            check = "not-read"
        elif time.monotonic() > deadline:
            check = "not-read"
            cov["unread_at_limit"] += 1
        else:
            hs = [hashlib.md5(), hashlib.sha1(), hashlib.sha256()]
            try:
                cut = False
                for block in img.content(item):
                    for h in hs:
                        h.update(block)
                    if time.monotonic() > deadline:
                        cut = True     # past the limit part way through one file: it is not a checked file, and says so
                        break
                if cut:
                    check = "not-read"
                    cov["unread_at_limit"] += 1
                else:
                    sha256 = hs[2].hexdigest()
                    if not md5 and not sha1:
                        check = "no-stored-hash"
                        cov["no_stored_hash"] += 1
                    elif (md5 and md5 != hs[0].hexdigest()) or (sha1 and sha1 != hs[1].hexdigest()):
                        check = "mismatch"
                        flags.append("hash-mismatch")
                        cov["mismatches"].append(item["n"])
                    else:
                        check = "ok"
                    cov["checked"] += 1
            except AD1Error as e:
                check = "not-read"
                cov["errors"].append("item %d (%s, %s): %s" % (item["n"], esc(raw_path), "ad1:item=%d" % item["addr"], e))
    klass = ad1_text(meta, 0x02)
    w.write("\t".join(str(v) for v in (
        item["n"], kind, esc(raw_path), base64.b64encode(raw_path).decode("ascii"), item["size"], packed,
        stamp(ad1_text(meta, 0x09)), "unknown", "", "", "", "", "ad1:item=%d" % item["addr"], ",".join(flags),
        stamp(ad1_text(meta, 0x07)), stamp(ad1_text(meta, 0x08)), md5, sha1, sha256, check,
        CLASSES.get((klass or b"").strip(), esc(klass or b"")))) + "\n")
    cov["folders" if item["type"] == AD1_FOLDER else "files"] += 1


def missing_words(img):
    """The segments not there, in words: on the host they are not beside the
    first; in a job they may also be outside its view, which holds only what
    the job declared. coverage.json's segments_missing has every name."""
    names = img.missing if len(img.missing) <= 5 else img.missing[:2] + ["...", img.missing[-1]]
    return ("the image has %d segments and %d of them (%s) %s not there, beside the first or in this job's view (a job is given "
            "only the segments it declares): what lies in them is not read"
            % (img.segment["count"], len(img.missing), ", ".join(names), "is" if len(img.missing) == 1 else "are"))


def label(key):
    return LABELS.get(key, "")


def run(target, paths, out_dir):
    deadline = time.monotonic() + limits() * 0.9      # past this, no further file's content is inflated
    os.makedirs(out_dir, exist_ok=True)
    cov = {"recipe": "ad1-items", "target": paths[0], "format": "AD1", "items": 0, "files": 0, "folders": 0, "checked": 0,
           "mismatches": [], "no_stored_hash": 0, "unread_at_limit": 0, "segments_missing": [],
           "covered": "every item of the image's tree, with its metadata, and each file's content inflated and checked against the digests the image records",
           "not_covered": "anything the imager did not put in the image (a logical image holds no unallocated space, and slack only where it was taken as an item); files inside the files; an encrypted (ADCRYPT) image",
           "limits_hit": [], "errors": []}

    def write_cov():
        with open(os.path.join(out_dir, "coverage.json"), "w") as cf:
            json.dump(cov, cf, indent=2)

    def finish(status, code):
        cov["status"] = status
        if "integrity_status" not in cov:
            cov["integrity_status"] = "mismatch" if cov["mismatches"] else "unverified" if cov["files"] > cov["checked"] or cov["no_stored_hash"] else "verified" if cov["files"] else "not_applicable"
        write_cov()
        print(json.dumps({"ok": code == 0, "status": status, "format": "AD1", "items": cov["items"]}))
        return code

    # Said before the first read: a run cut short leaves a coverage file that says it was, never none.
    cov["status"] = "partial"
    cov["why"] = "started; the run did not reach its end"
    write_cov()
    del cov["why"]
    img_source = b""
    try:
        img = AD1(paths[0], paths[1:])
    except AD1Error as e:
        cov["why"] = str(e)
        return finish("unsupported", 2)
    except OSError as e:
        cov["errors"].append("%s: %s" % (paths[0], e.strerror or e))
        return finish("failed", 2)
    cov["segments_missing"] = img.missing
    if img.missing:
        cov["errors"].append(missing_words(img))
    cov["errors"] += img.errors
    try:
        with open(os.path.join(out_dir, "members.tsv"), "w", encoding="utf-8", newline="\n") as w, \
                open(os.path.join(out_dir, "attributes.tsv"), "w", encoding="utf-8", newline="\n") as a:
            w.write("\t".join(COLUMNS) + "\n")
            a.write("n\tcategory\tkey\tlabel\ttext\n")
            escapes = set()
            for item in img.walk():
                if cov["items"] >= MAX_ITEMS:
                    # The listing is not stopped by the clock (it is cheap, and every item stays listed past the
                    # limit); it is bounded by an item budget, and says so.
                    cov["limits_hit"].append("items: the listing stopped after %d items; every item after it in the image's order is not listed" % cov["items"])
                    break
                row_of(img, item, w, deadline, cov, escapes)
                for cat, key, text, _addr in item["meta"]:
                    a.write("%d\t%d\t0x%x\t%s\t%s\n" % (item["n"], cat, key, label(key), esc(text)))
                cov["items"] += 1
        cov["errors"] += img.walk_errors
        try:
            own = [{"category": c, "key": "0x%x" % k, "label": label(k), "text": esc(t)} for c, k, t, _a in img.metadata(img.meta_addr)]
        except AD1Error as e:
            own = []
            cov["errors"].append("the image's own metadata: %s" % e)
        segs = []
        for k, p in enumerate(img.paths, 1):
            segs.append({"segment": k, "name": img.names[k - 1], "present": p is not None, **({"bytes": os.path.getsize(p)} if p else {})})
        json.dump({"format": "AD1", "segment_header": img.segment, "segments": segs,
                   "logical_image": {"version": img.version, "chunk_size": img.chunk_size, "first_item": img.first_item, "metadata": img.meta_addr},
                   "data_source_name": esc(img.source_name), "metadata": own,
                   "items": cov["items"], "files": cov["files"], "folders": cov["folders"]},
                  open(os.path.join(out_dir, "image.json"), "w"), indent=2, ensure_ascii=False)
    finally:
        img_source = img.source_name
        img.close()
    if cov["unread_at_limit"]:
        cov["limits_hit"].append("seconds: past the limit, the content of %d file(s) was not inflated, so their digests were not checked (check not-read); every item is still listed" % cov["unread_at_limit"])
    with open(os.path.join(out_dir, "index.tsv"), "w", encoding="utf-8") as fh:
        mism = len(cov["mismatches"])
        fh.write("members.tsv\tAD1 item list (%d items: %d files, %d folders), paths under the data source name %s: n, type, path, path_b64, size, packed, mtime, tz, mode, uid, gid, link, locator, flags, atime, btime, md5, sha1, sha256, check, class; ad1_extract takes n or the locator%s\n"
                 % (cov["items"], cov["files"], cov["folders"], esc(img_source) or "(none recorded)", "; %d file(s) whose content does not match the digests the image records (check mismatch)" % mism if mism else ""))
        fh.write("attributes.tsv\tevery metadata entry of every item: n, category, key, label, text\n")
        fh.write("image.json\tthe AD1 segment and logical image headers, its segments, its data source name and its own metadata\n")
    status = "complete" if not cov["limits_hit"] and not cov["errors"] else ("partial" if cov["items"] else "failed")
    return finish(status, 0 if status in ("complete", "partial") else 2)


def main(argv):
    if len(argv) < 2 or argv[1] not in ("detect", "run"):
        print(json.dumps({"ok": False, "error": "usage: run.py detect --target T [--probe-out DIR] | run --target T --out DIR"}))
        return 2
    args = dict(zip(argv[2::2], argv[3::2]))
    if "--target" not in args:
        print(json.dumps({"ok": False, "error": "--target is required"}))
        return 2
    target, paths = target_of(args["--target"])
    if argv[1] == "detect":
        fmt, why = detect(paths[0])
        print(json.dumps({"applies": fmt is not None, "format": fmt, "why": why}))
        return 0 if fmt else 1
    if "--out" not in args:
        print(json.dumps({"ok": False, "error": "run needs --out DIR"}))
        return 2
    return run(target, paths, args["--out"])


if __name__ == "__main__":
    sys.exit(main(sys.argv))
