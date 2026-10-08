#!/usr/bin/env python3
"""ad1_extract: write the files and folders of an AccessData AD1 logical image
out as a tree, each file inflated, hashed and checked against the digests the
image records, with a manifest of what went where.

Args, JSON on stdin:
  image     the image's first segment (.ad1); its further segments are
            looked for beside it (x.ad2, x.ad3, ...)
  members   items from the catalogue's members.tsv for this image (the
            ad1-items recipe): their numbers (n), or their locators
            (ad1:item=<address>); a folder takes its subtree. Default: every
            item. A listing that was partial (a segment missing, an item it
            could not read) numbers the items after a break otherwise than a
            whole read does; a locator names the same item in both
  out_dir   where the tree goes, a new or empty directory. Default: in a job
            ($OUT set) $OUT/<image name less .ad1>, and in a job it must be
            inside $OUT; called directly, work/<AGENT_ID>/ad1/<image name
            less .ad1>
  max_items, max_walk, max_bytes, max_seconds
            budgets for the whole call (items taken, items looked at, bytes
            written, wall clock): defaults 5,000,000, 5,000,000, 256 GiB and
            1500 s. A call that reaches one stops, keeps what it wrote, and
            says it was partial. What is held while it walks is the depth of
            the tree, not the number of items

Run it as a job (job_run tool=ad1_extract): what it writes is then sealed
into the store, citable as job:<id>/<path>, and the derived catalogue offers
each file to the recipes, so an archive, a disk image or an executable inside
the AD1 image is catalogued in turn.

Each item lands at out_dir/<its path in the image>. A name this file system
cannot hold as it is (empty, "." or "..", holding "/" or a NUL, not UTF-8,
past 255 bytes, or one a sibling already took, letter case and Unicode
normalisation aside) is written renamed, and the manifest,
out_dir/ad1_extract.tsv, names both (an item at the top named like the
manifest is renamed too):

    n  type  path  path_b64  locator  written  size  sha256  check  note

`path`, `path_b64` and `locator` are as ad1-items lists them; `written` is
under out_dir; `check` is ok, mismatch, no-stored-hash or not-read, as
ad1-items says it, or not-written (this file system refused it). A file
whose content breaks part way, or whose write fails (a full disk), is kept
as <name>.partial, holding what was written, and says so: no truncated file
keeps its own name, and the name it is kept under is one no other item
of that directory holds, partial or whole. Nothing is written outside
out_dir, under inputs/, or outside the run directory (in a job, its $OUT).

Two statuses, kept apart. `processing_status` says whether every item asked
for was written (complete), some were not (partial: a budget, an item that
broke) or nothing was (failed). `integrity_status` says whether what was
written matches the digests the image records: verified (every file had a
stored digest and matched), mismatch (at least one did not), or unverified
(some had no stored digest or were not read); `ok` is true only for a complete
processing with no mismatch. The exit code is 0 when the tool ran and what it
examined is whole or said not to be: processing complete (a mismatch included: the
files were written, and the mismatch is a finding about the image's content, not a
failure of this tool), or partial only because a budget stopped it between items
(`stopped_by_budget` says which). An item that broke or could not be written, a
segment that is not there or a manifest that could not be written is exit 1.
ad1_extract.coverage.json
is written as incomplete before the first item and again at the end.
"""
import base64
import hashlib
import json
import os
import sys
import time
import unicodedata
from pathlib import Path

NAME_MAX = 255
SHOWN_ERRORS = 20
MANIFEST = "ad1_extract.tsv"
ERRORS = "ad1_extract.errors.txt"
COVERAGE = "ad1_extract.coverage.json"
ITEMS_DEFAULT, ITEMS_CEILING = 5_000_000, 100_000_000
WALK_DEFAULT, WALK_CEILING = 5_000_000, 100_000_000       # items looked at, taken or not
BYTES_DEFAULT, BYTES_CEILING = 256 * 1024 ** 3, 1024 ** 4
SECONDS_DEFAULT, SECONDS_CEILING = 1500, 1700          # the ceiling is inside the manifest's own 1800-second limit


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


def fail(message, **extra):
    print(json.dumps({"ok": False, "error": message, **extra}))
    raise SystemExit(1)


def esc(raw):
    """A name for a reader: one line, one field, nothing hidden (as ad1-items writes it)."""
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


def resolve_output(out):
    """Where `out` really lands, links resolved first: in a job, inside its
    $OUT (the one place a job writes); called directly, inside the run
    directory (not the run directory itself); never under inputs/."""
    root = Path.cwd().resolve()
    dest = Path(out).resolve() if Path(out).is_absolute() else (root / out).resolve()
    if os.environ.get("OUT") and os.environ.get("JOB_ID"):
        job_out = Path(os.environ["OUT"]).resolve()
        if dest != job_out and job_out not in dest.parents:
            fail("in a job out_dir must be inside $OUT, the one place a job writes ({OUT}/<name>)", out_dir=str(out))
    elif dest == root or root not in dest.parents:
        fail("out_dir must be inside the run directory, not the run directory itself", out_dir=str(out))
    inputs = root / "inputs"
    if dest == inputs or inputs in dest.parents:
        fail("out_dir cannot be under inputs/", out_dir=str(out))
    return dest


def fold(name):
    return unicodedata.normalize("NFC", name).casefold()


def safe_name(raw):
    """A name this file system holds, and whether it had to change."""
    try:
        text = raw.decode("utf-8")
        changed = False
    except UnicodeDecodeError:
        text = "".join(ch if not 0xDC80 <= ord(ch) <= 0xDCFF else "%%%02X" % (ord(ch) - 0xDC00) for ch in raw.decode("utf-8", "surrogateescape"))
        changed = True
    if "/" in text or "\x00" in text:
        text = text.replace("%", "%25").replace("/", "%2F").replace("\x00", "%00")
        changed = True
    if text in ("", ".", ".."):
        text = "%2E" * len(text) if text else "%"
        changed = True
    if len(text.encode("utf-8")) > NAME_MAX - 40:
        digest = hashlib.sha256(raw).hexdigest()[:16]
        keep = text.encode("utf-8")[:NAME_MAX - 58].decode("utf-8", "ignore")
        text = "%s~%s" % (keep, digest)
        changed = True
    return text, changed


def unique(used, name, n):
    """`name`, or a variant no sibling holds (letter case and Unicode
    normalisation aside, as APFS compares names), reserved in `used`."""
    cand, k = name, 0
    while fold(cand) in used:
        k += 1
        cand = "%s~n%d" % (name, n) if k == 1 else "%s~n%d.%d" % (name, n, k)
    used.add(fold(cand))
    return cand


def parse_members(members):
    """The item numbers and the item addresses a members list names."""
    if members is None:
        return None, None
    if not isinstance(members, list) or not members:
        fail("members is a non-empty list of item numbers (n) or locators (ad1:item=<address>) from the catalogue's members.tsv; leave it out to take every item")
    ns, addrs = set(), set()
    for m in members:
        if isinstance(m, int) and not isinstance(m, bool) and m >= 0:
            ns.add(m)
        elif isinstance(m, str) and m.startswith("ad1:item=") and m[9:].isascii() and m[9:].isdecimal() and len(m) <= 40:
            addrs.add(int(m[9:]))
        else:
            fail("members holds %s: an item number (n) or a locator (ad1:item=<address>) from members.tsv" % json.dumps(m))
    return ns, addrs


class Budget(Exception):
    pass


def write_file(img, item, dest, notes, used, stop):
    """Write one item's content to dest: (size, hashes, check, why, the name
    it is kept under). A content that breaks, a budget that is reached, or a
    write that fails, leaves what was written as <name>.partial (or nothing),
    and says so; the partial's name is one no other item of its directory
    holds, and its size and sha256 (the sixth value) are those of the bytes kept."""
    hs = [hashlib.md5(), hashlib.sha1(), hashlib.sha256()]
    size, broke, kept_hash = 0, None, ""
    try:
        fh = open(dest, "xb")
    except OSError as e:
        return 0, None, "not-written", "cannot be written: %s" % (e.strerror or e), "", ""
    try:
        with fh:
            for block in img.content(item):
                reason = stop(len(block))
                if reason:
                    raise Budget(reason)
                fh.write(block)
                size += len(block)
                for h in hs:
                    h.update(block)
    except Budget as e:
        broke = ("not-read", str(e))
    except AD1Error as e:
        broke = ("not-read", str(e))
    except OSError as e:
        broke = ("not-written", "the write failed: %s" % (e.strerror or e))
    if broke is None:
        return size, hs, "", "", dest.name, ""
    # One allocator for every name in the directory, whole or partial; and a name that is on disk is taken.
    k, kept_name = 0, unique(used, dest.name + ".partial", item["n"])
    part = dest.with_name(kept_name)
    while part.exists() or part.is_symlink():
        k += 1
        kept_name = unique(used, dest.name + ".partial", item["n"] + k)
        part = dest.with_name(kept_name)
    kept = part.name
    try:
        try:
            os.link(dest, part)        # fails where the name is taken: never over another file
            os.unlink(dest)
        except FileExistsError:
            raise
        except OSError:
            # A file system with no hard links (exFAT, a mounted share): a rename, once the name is seen to be free.
            if part.exists() or part.is_symlink():
                raise
            os.rename(dest, part)
        try:
            kept_size = os.path.getsize(part)
        except OSError:
            kept_size = size
        h = hashlib.sha256()
        with open(part, "rb") as rf:
            for chunk in iter(lambda: rf.read(1 << 20), b""):
                h.update(chunk)
        notes.append("partial: %d of %d bytes kept" % (kept_size, item["size"]))
        size, kept_hash = kept_size, h.hexdigest()
    except OSError:
        try:
            os.unlink(dest)
            kept = ""
            notes.append("partial: nothing kept (it could not be renamed)")
        except OSError:
            kept = dest.name
            notes.append("partial: %d of %d bytes left under its own name (it could be neither renamed nor removed)" % (size, item["size"]))
    return size, None, broke[0], broke[1], kept, kept_hash


def main():
    try:
        args = json.load(sys.stdin)
    except ValueError as e:
        fail("arguments are JSON on stdin: %s" % e)
    image = args.get("image")
    if not isinstance(image, str) or not image:
        fail("image is required: the AD1 image's first segment (.ad1)")
    want_n, want_addr = parse_members(args.get("members"))
    budgets = {}
    for key, default, ceiling in (("max_items", ITEMS_DEFAULT, ITEMS_CEILING), ("max_walk", WALK_DEFAULT, WALK_CEILING), ("max_bytes", BYTES_DEFAULT, BYTES_CEILING), ("max_seconds", SECONDS_DEFAULT, SECONDS_CEILING)):
        v = args.get(key, default)
        if not isinstance(v, int) or isinstance(v, bool) or not 1 <= v <= ceiling:
            fail("%s is a whole number from 1 to %d" % (key, ceiling), **{key: v})
        budgets[key] = v
    started = time.monotonic()
    deadline = started + budgets["max_seconds"]
    stem = os.path.basename(image)
    if stem.lower().endswith(".ad1"):
        stem = stem[:-4]
    in_job = bool(os.environ.get("OUT") and os.environ.get("JOB_ID"))
    out_arg = args.get("out_dir") or (os.path.join(os.environ["OUT"], stem) if in_job else os.path.join("work", os.environ.get("AGENT_ID") or "ad1", "ad1", stem))
    out = resolve_output(out_arg)
    if out.exists() and (not out.is_dir() or any(out.iterdir())):
        fail("out_dir already holds something: name a new or empty directory", out_dir=str(out_arg))
    try:
        img = AD1(image)
    except AD1Error as e:
        fail("not an AD1 image this tool reads: %s" % e, image=image)
    except OSError as e:
        fail("cannot read %s: %s" % (image, e.strerror or e))
    errors = list(img.errors)
    soft = [0]         # errors that are only a budget's stop: the answer is valid for what was examined, and says where it stopped
    if img.missing:
        names = img.missing if len(img.missing) <= 5 else img.missing[:2] + ["...", img.missing[-1]]
        errors.append("the image has %d segments and %d of them (%s) %s not there, beside the first or in this job's view (declare every segment in inputs): what lies in them is not read"
                      % (img.segment["count"], len(img.missing), ", ".join(names), "is" if len(img.missing) == 1 else "are"))
    # The names and places of the directories the walk is inside, and nothing else: the walk is depth first, so when it leaves a
    # subtree that subtree's state is dropped, and what is held is the depth of the tree, not the number of items.
    chain = []         # [{n, selected, placed_rel, dir_of, children_dir, is_dir}], the ancestors of the item being looked at
    # The manifest's own names, at the top of out_dir, are not an item's.
    taken = {"": {fold(MANIFEST), fold(ERRORS), fold(COVERAGE)}}  # directory (relative) -> folded names already used there
    walked = 0
    seen_n, seen_addr = set(), set()       # the wanted numbers and addresses that were met, not every item's
    counts = {"items": 0, "files": 0, "folders": 0, "bytes": 0, "renamed": 0, "mismatches": 0, "checked": 0}
    tally = {"no_stored_hash": 0, "not_read": 0}
    reached = [None]                      # the budget that stopped the call, if one did
    this_file = [0]

    def stop(nbytes):
        """Why the call must stop, or None: the time budget, or the bytes budget with this block counted."""
        this_file[0] += nbytes
        if time.monotonic() > deadline:
            reached[0] = reached[0] or "the time budget of %d seconds was reached" % budgets["max_seconds"]
        elif counts["bytes"] + this_file[0] > budgets["max_bytes"]:
            reached[0] = reached[0] or "the output budget of %d bytes was reached" % budgets["max_bytes"]
        return reached[0]

    def coverage(status, extra=None):
        doc = {"tool": "ad1_extract", "image": image, "processing_status": status, "budgets": budgets, **counts, **tally,
               "elapsed_seconds": round(time.monotonic() - started, 1), **(extra or {})}
        try:
            with open(out / COVERAGE, "w", encoding="utf-8") as cf:
                json.dump(doc, cf, indent=2)
                cf.write("\n")
        except OSError:
            pass
    try:
        out.mkdir(parents=True, exist_ok=True)
        man = open(out / MANIFEST, "x", encoding="utf-8", newline="\n")
    except OSError as e:
        img.close()
        fail("cannot write in out_dir: %s" % (e.strerror or e), out_dir=str(out_arg))
    stopped = None
    coverage("incomplete")                # said before the first item, so a run cut short leaves this file
    with man:
        man.write("n\ttype\tpath\tpath_b64\tlocator\twritten\tsize\tsha256\tcheck\tnote\n")
        try:
            for item in img.walk():
                n = item["n"]
                if time.monotonic() > deadline and not reached[0]:
                    reached[0] = "the time budget of %d seconds was reached" % budgets["max_seconds"]
                if reached[0]:
                    # Checked for every item, wanted or not: a long walk past the last wanted item is not free either.
                    errors.append("stopped: %s; item %d (%s) and every item after it in the image's order were not examined" % (reached[0], n, esc(item["path"])))
                    soft[0] += 1
                    break
                walked += 1
                if walked > budgets["max_walk"]:
                    reached[0] = "the walk budget of %d items was reached" % budgets["max_walk"]
                    errors.append("stopped: %s; item %d (%s) and every item after it in the image's order were not examined" % (reached[0], n, esc(item["path"])))
                    soft[0] += 1
                    break
                if want_n is not None and n in want_n:
                    seen_n.add(n)
                if want_addr is not None and item["addr"] in want_addr:
                    seen_addr.add(item["addr"])
                # Leaving a subtree: the chain is cut back to this item's parent, and the state of what was left goes with it.
                while chain and chain[-1]["n"] != item["parent"]:
                    left = chain.pop()
                    if left["children_dir"] is not None and left["children_dir"] != "":
                        taken.pop(left["children_dir"], None)
                if item["parent"] is None:
                    parent_dir, parent_selected = "", False
                else:
                    owner = chain[-1]
                    if owner["children_dir"] is None:
                        # A file's children (a stream, say) go beside it, in a directory of their own, named when the first one arrives.
                        owner["children_dir"] = os.path.join(owner["dir_of"], unique(taken[owner["dir_of"]], owner["placed"] + ".ad1-children", owner["n"]))
                    parent_dir, parent_selected = owner["children_dir"], owner["selected"]
                used = taken.setdefault(parent_dir, set())
                name, changed = safe_name(item["name"])
                placed = unique(used, name, n)
                changed = changed or placed != name
                rel = os.path.join(parent_dir, placed) if parent_dir else placed
                is_dir = item["type"] == AD1_FOLDER
                take = (want_n is None or n in want_n or item["addr"] in want_addr or (item["parent"] is not None and parent_selected))
                chain.append({"n": n, "selected": take, "placed": placed, "dir_of": parent_dir, "children_dir": rel if is_dir else None})
                if not take:
                    continue
                if counts["items"] >= budgets["max_items"]:
                    reached[0] = "the item budget of %d items was reached" % budgets["max_items"]
                elif time.monotonic() > deadline:
                    reached[0] = reached[0] or "the time budget of %d seconds was reached" % budgets["max_seconds"]
                if reached[0]:
                    errors.append("stopped: %s; item %d (%s) and every item after it in the image's order were not written or listed" % (reached[0], n, esc(item["path"])))
                    soft[0] += 1
                    break
                raw_path = item["path"]
                locator = "ad1:item=%d" % item["addr"]
                notes = ["renamed"] if changed else []
                if item["type"] == AD1_UNKNOWN_FILE:
                    notes.append("a file of unknown kind")
                if item["type"] == AD1_DELETED:
                    notes.append("deleted")
                counts["items"] += 1
                counts["renamed"] += changed
                dest = out / rel
                head = "%d\t%s\t%s\t%s\t%s\t" % (n, "dir" if is_dir else "file" if item["type"] in (AD1_FILE, AD1_UNKNOWN_FILE, AD1_DELETED) else "other:%d" % item["type"],
                                               esc(raw_path), base64.b64encode(raw_path).decode(), locator)
                try:
                    dest.parent.mkdir(parents=True, exist_ok=True)
                    if is_dir:
                        dest.mkdir(exist_ok=True)
                except OSError as e:
                    errors.append("item %d (%s, %s): cannot be written at %s: %s" % (n, esc(raw_path), locator, esc(rel.encode()), e.strerror or e))
                    man.write(head + "\t\t\tnot-written\t%s\n" % ",".join(notes + ["cannot be written"]))
                    continue
                if is_dir:
                    counts["folders"] += 1
                    man.write(head + "%s\t\t\t\t%s\n" % (esc(rel.encode()), ",".join(notes)))
                    continue
                md5 = (ad1_text(item["meta"], 0x5001) or b"").strip().decode("ascii", "replace").lower()
                sha1 = (ad1_text(item["meta"], 0x5002) or b"").strip().decode("ascii", "replace").lower()
                this_file[0] = 0
                size, hs, check, why, kept, kept_hash = write_file(img, item, dest, notes, used, stop)
                if hs is None:
                    errors.append("item %d (%s, %s): %s" % (n, esc(raw_path), locator, why))
                    if reached[0] and why == reached[0]:
                        soft[0] += 1                          # the item was cut by the budget: the budget's stop is said once more below
                    written = esc(os.path.join(os.path.dirname(rel), kept).encode()) if kept else ""
                    # The sha256 of a partial row is of the bytes kept, not of the item.
                    man.write(head + "%s\t%d\t%s\t%s\t%s\n" % (written, size, kept_hash, check, ",".join(notes)))
                    counts["files"] += 1
                    counts["bytes"] += size
                    tally["not_read"] += 1
                    if reached[0]:
                        errors.append("stopped: %s; item %d is kept as a partial, and every item after it in the image's order was not written or listed" % (reached[0], n))
                        soft[0] += 1
                        break
                    continue
                if not md5 and not sha1:
                    check = "no-stored-hash"
                    tally["no_stored_hash"] += 1
                elif (md5 and md5 != hs[0].hexdigest()) or (sha1 and sha1 != hs[1].hexdigest()):
                    check = "mismatch"
                    counts["mismatches"] += 1
                else:
                    check = "ok"
                counts["checked"] += 1
                counts["files"] += 1
                counts["bytes"] += size
                man.write(head + "%s\t%d\t%s\t%s\t%s\n" % (esc(rel.encode()), size, hs[2].hexdigest(), check, ",".join(notes)))
        except OSError as e:
            # The manifest itself could not be written (a full disk): stop, say so.
            stopped = "stopped: %s; the manifest lists what was written before" % (e.strerror or e)
        finally:
            img.close()
    errors += img.walk_errors
    absent = sorted(want_n - seen_n) if want_n is not None else []
    gone = sorted(want_addr - seen_addr) if want_addr is not None else []
    # After a stop (a budget, a manifest that could not be written) the walk did not reach the end of the image: an item not
    # seen is not an item that is not there, and is not claimed to be absent.
    walked_all = not (reached[0] or stopped)
    if absent:
        soft[0] += 0 if walked_all else 1
        errors.append(("no item %s in this read of the image (it listed %d items)" if walked_all else
                       "item %s was not reached before the call stopped (it had looked at %d items): it is not claimed absent") % (", ".join(map(str, absent)), walked))
    if gone:
        soft[0] += 0 if walked_all else 1
        errors.append(("no item at %s in this read of the image" if walked_all else
                       "the item at %s was not reached before the call stopped: it is not claimed absent") % ", ".join("ad1:item=%d" % a for a in gone))
    if stopped:
        errors.insert(0, stopped)
    processing = "complete" if not errors else ("partial" if counts["files"] or counts["folders"] else "failed")
    if counts["mismatches"]:
        integrity = "mismatch"
    elif counts["files"] == 0:
        integrity = "not_applicable"
    elif tally["no_stored_hash"] or tally["not_read"]:
        integrity = "unverified"
    else:
        integrity = "verified"
    coverage(processing, {"integrity_status": integrity})
    result = {"ok": processing == "complete" and integrity != "mismatch", "processing_status": processing, "integrity_status": integrity,
              "image": image, "out_dir": str(out_arg), "manifest": os.path.join(str(out_arg), MANIFEST), "coverage": os.path.join(str(out_arg), COVERAGE),
              **counts, **tally, "segments_missing": img.missing, "budgets": budgets}
    if integrity == "mismatch":
        result["integrity_note"] = ("%d file(s) were written whose content does not match the digests the image records (check mismatch in the manifest). "
                                    "The files were written; the exit status is 0 for a complete extraction, so read integrity_status" % counts["mismatches"])
    elif integrity == "unverified":
        result["integrity_note"] = "%d file(s) have no stored digest and %d were not read: their content is not checked against the image" % (tally["no_stored_hash"], tally["not_read"])
    if reached[0]:
        result["stopped_by_budget"] = reached[0]
    if errors:
        result["errors"] = errors[:SHOWN_ERRORS]
        result["errors_total"] = len(errors)
        if len(errors) > SHOWN_ERRORS:
            try:
                with open(out / ERRORS, "x", encoding="utf-8") as fh:
                    fh.write("\n".join(errors) + "\n")
                result["errors_file"] = os.path.join(str(out_arg), ERRORS)
            except OSError as e:
                result["errors_file_error"] = "the whole list could not be written: %s" % (e.strerror or e)
    if not in_job:
        result["note"] = "written where you called it, not sealed: run it as a job (job_run tool=ad1_extract) to have the files sealed into the store, citable as job:<id>/<path>, and catalogued by the derived catalogue"
    print(json.dumps(result))
    # Exit 0 means the tool ran and what it examined is whole or said not to be: complete, or partial only because a budget stopped it
    # between items (processing_status says partial and stopped_by_budget says which). An item that broke or could not be written, a
    # manifest that could not be written, a segment that is not there: 1.
    return 0 if len(errors) == soft[0] else 1


if __name__ == "__main__":
    sys.exit(main())
