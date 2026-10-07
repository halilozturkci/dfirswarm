#!/usr/bin/env python3
"""Catalogue the forensic structures in an iOS full file-system tar.

The recipe is deliberately structural. It reads every tar header and no member
body, so the catalogue says which parser targets exist without turning a path
into a finding or extracting protected content.

Names are kept as the tar reader returned them. A member name is never trimmed
here (a leading dot or slash is part of it; the reader itself drops the trailing
slash of a directory's name): `path` shows it with tabs, newlines, backslashes
and bytes that are not UTF-8 escaped, and `path_b64` is its exact bytes. `n` is the member's position in the archive, from 0, so two members of
one name are two rows, and a database that occurs twice keeps both sizes and
both positions (sqlite.tsv: sizes joined with `|`, `members` listing
role=position, `types` the kind of each: a link has the size 0 and is not an
empty database). The classification of a name reads a lower-cased copy; the copy
is never what is written.

A database family is a main database with its -wal, -shm and -journal companions.
The main database is found by its suffix (.db, .sqlite, .sqlite3, .sqlitedb,
.storedata) or by being the file a companion belongs to (`x/db` with `x/db-wal`).
A database with neither a suffix nor a companion is not found by its name.

The tar is followed header by header, apart from the library that lists it
(the data between members is not read). The archive is complete only when its
end-of-archive block was seen (`tar_end` in coverage.json: reached or missing), a
header the library would refuse (a checksum that does not match, a number that
does not parse) stops the listing and is said, the number of members listed is
compared with the number of headers counted, and an extended header (a GNU long
name, a pax header) that declares more than 16 MiB is not read, since the library
would hold it whole in memory. A compressed tar (gzip, bzip2 or xz, by its magic)
is decoded in pieces. A run never writes over an earlier run's output: if the
output directory already holds one of its files, it refuses.

The database families are grouped in a scratch SQLite file under the output
(deleted when the run ends), so a very large archive does not hold them in
memory, and the artefact rows are written as they are met.
"""
import argparse
import base64
import datetime
import io
import json
import os
import sqlite3
import struct
import sys
import tarfile
import zlib


IOS_MARKERS = (
    "private/var/mobile/",
    "private/var/containers/",
    "system/library/coreservices/systemversion.plist",
)
SQLITE_SUFFIXES = (".db", ".sqlite", ".sqlite3", ".sqlitedb", ".storedata")
ROLES = ("db", "wal", "shm", "journal")
OUTPUTS = ("artifacts.tsv", "sqlite.tsv", "index.tsv", "coverage.json")


def target_of(value):
    text = open(value, encoding="utf-8").read() if os.path.isfile(value) else value
    target = json.loads(text)
    paths = target.get("paths") or []
    if not paths or not isinstance(paths[0], str):
        raise ValueError("the target names no path")
    return target, paths[0]


# --- tar watch: begin ----------------------------------------------------------------------------
# Held byte for byte equal in the four recipes that read a tar (a test compares the copies). The watch
# follows a tar header by header, apart from the library that lists it, and says what that library does
# not: whether the end-of-archive block came, whether a header would be refused (a checksum that does not
# match, a number that does not parse), how many members there are, and whether an extended header declares
# more than the library should be allowed to hold in memory (it reads a GNU long name or a pax header whole).
EXTENDED_HEADER_LIMIT = 16 << 20
NO_DATA_TYPES = set(b"123456")        # hard link, symbolic link, character and block device, directory, fifo: the size is not followed by data


def tar_number(field):
    """A tar numeric field as the tar library reads it: octal text, or base-256 when the top bit is set."""
    if field[0] in (0o200, 0o377):
        n = 0
        for i in range(len(field) - 1):
            n = (n << 8) + field[i + 1]
        return -(256 ** (len(field) - 1) - n) if field[0] == 0o377 else n
    return int(bytes(field).split(b"\0")[0].decode("ascii").strip() or "0", 8)


def tar_header(block):
    """The size field of a header the tar library would accept, or None if it would refuse it."""
    try:
        for start, end in ((100, 108), (108, 116), (116, 124), (136, 148), (329, 337), (337, 345)):
            tar_number(block[start:end])
        checksum = tar_number(block[148:156])
        size = tar_number(block[124:136])
    except ValueError:
        return None
    unsigned = 256 + sum(block[:148]) + sum(block[156:])
    signed = 256 + sum(struct.unpack_from("148b", block)) + sum(struct.unpack_from("356b", block, 156))
    return size if checksum in (unsigned, signed) else None


def pax_size(data):
    """The `size` record of a pax header ("<length> <key>=<value>\\n" records), or None; one that is not a number reads as 0, as the library reads it."""
    size, pos = None, 0
    while pos < len(data):
        space = data.find(b" ", pos)
        if space < 0:
            break
        try:
            length = int(data[pos:space])
        except ValueError:
            break
        if length <= 0 or pos + length > len(data):
            break
        key, _, value = data[space + 1:pos + length - 1].partition(b"=")
        if key == b"size":
            try:
                size = int(value)
            except ValueError:
                size = 0
        pos += length
    return size


class TarWatch:
    def __init__(self):
        self.block = bytearray()
        self.skip = 0
        self.collect = 0
        self.collect_padding = 0
        self.collecting = None
        self.acc = bytearray()
        self.position = 0
        self.ended = False
        self.end_at = None           # where the end-of-archive block starts
        self.violation = None        # the size an extended header declares, over the limit
        self.violation_at = None     # where that header starts
        self.bad_at = None           # where a header starts that the tar library would refuse
        self.truncated = False       # a walk reached the end of the file inside a header or its data
        self.members = 0
        self.next_size = None        # a pax `size` for the next member
        self.global_size = None      # one from a global pax header
        self.in_ext = False          # inside the extension blocks of a GNU sparse header
        self.after_ext = 0

    def stopped(self):
        return self.ended or self.violation is not None or self.bad_at is not None

    def stop_at(self):
        """Where the library must see the end of the data: before a header it must not read, or at the end block."""
        for at in (self.violation_at, self.bad_at, self.end_at):
            if at is not None:
                return at
        return None

    def feed(self, data):
        """Follow bytes as they flow past."""
        i, n = 0, len(data)
        while i < n and not self.stopped():
            if self.collect:
                take = min(self.collect, n - i)
                self.acc += data[i:i + take]
                self.collect -= take
                i += take
                self.position += take
                if not self.collect:
                    self.finish_pax()
                continue
            if self.skip:
                step = min(self.skip, n - i)
                self.skip -= step
                i += step
                self.position += step
                continue
            take = min(512 - len(self.block), n - i)
            self.block += data[i:i + take]
            i += take
            self.position += take
            if len(self.block) == 512:
                self.header(bytes(self.block))
                self.block.clear()
        if self.stopped():
            self.position += n - i

    def walk(self, fh, size, until=None):
        """Follow a file that can seek, header to header: the data between headers is jumped over, not read."""
        while not self.stopped() and not self.truncated and (until is None or self.position < until):
            if self.collect:
                data = fh.read(self.collect)
                if len(data) < self.collect:
                    self.truncated = True
                    return
                self.acc += data
                self.position += len(data)
                self.collect = 0
                self.finish_pax()
                continue
            if self.skip:
                if self.position + self.skip > size:
                    self.truncated = True
                    return
                fh.seek(self.position + self.skip)
                self.position += self.skip
                self.skip = 0
                continue
            fh.seek(self.position)
            block = fh.read(512)
            if len(block) < 512:
                self.truncated = True
                return
            self.position += 512
            self.header(block)

    def finish_pax(self):
        size = pax_size(bytes(self.acc))
        if self.collecting in (ord("x"), ord("X")):
            # The library starts from the global records and lets this header's override them.
            self.next_size = size if size is not None else self.global_size
        else:
            if size is not None:
                self.global_size = size
            self.next_size = self.global_size     # a global header applies to the member that follows it
        self.acc.clear()
        self.skip = self.collect_padding

    def header(self, block):
        start = self.position - 512
        if self.in_ext:
            if not block[504]:
                self.in_ext = False
                self.skip = self.after_ext
            return
        if block == b"\0" * 512:
            self.ended, self.end_at = True, start
            return
        size = tar_header(block)
        if size is None or size < 0:
            self.bad_at = start
            return
        flag = block[156]
        if flag in b"xgX":
            if size > EXTENDED_HEADER_LIMIT:
                self.violation, self.violation_at = size, start
                return
            self.collecting, self.collect, self.collect_padding = flag, size, -size % 512
            if not size:
                self.finish_pax()
            return
        if flag in b"LK":
            if size > EXTENDED_HEADER_LIMIT:
                self.violation, self.violation_at = size, start
                return
            self.skip = -(-size // 512) * 512
            return
        self.members += 1
        if flag in NO_DATA_TYPES:
            self.next_size = None
            return
        if self.next_size is not None:
            # A pax `size` record is the size of the entry it precedes, over the header's own.
            size = self.next_size
        self.next_size = None
        padded = -(-size // 512) * 512
        if flag == ord("S") and block[482]:
            self.in_ext, self.after_ext = True, padded
        else:
            self.skip = padded


def tar_verdict(watch, listed, cut_short=False):
    """What the watch saw, set against the `listed` members the library returned: (tar_end, limits, errors).

    `cut_short`: the bytes were stopped by a budget, so neither the end block nor the count is judged.
    """
    limits, errors = [], []
    if watch.violation is not None:
        tar_end = "not_reached"
        limits.append("a tar extended header at offset %d declares %d bytes, over the limit of %d: it is not read, and the listing stopped after %d members"
                      % (watch.violation_at, watch.violation, EXTENDED_HEADER_LIMIT, listed))
    elif watch.bad_at is not None:
        tar_end = "not_reached"
        errors.append("the tar header at offset %d is not one the tar reader accepts (a checksum that does not match, or a number that does not parse): the listing stopped there, after %d members"
                      % (watch.bad_at, listed))
    elif watch.ended:
        tar_end = "reached"
    elif cut_short:
        tar_end = "not_reached"
    else:
        tar_end = "missing"
        errors.append("the tar ends without its end-of-archive block (%d bytes read): the archive is cut short or damaged, and the listing is what came before the cut" % watch.position)
    if not cut_short and listed != watch.members:
        errors.append("the tar reader listed %d members and a header-by-header walk counted %d: the two disagree, so the listing may be missing members" % (listed, watch.members))
    return tar_end, limits, errors
# --- tar watch: end ------------------------------------------------------------------------------


# --- tar listing: begin --------------------------------------------------------------------------
# Held byte for byte equal in the three recipes that open a tar by its path (a test compares the copies).
# A plain tar is read through Guarded and a gzip, bzip2 or xz one through Decoded; both keep the watch
# just ahead of the library and give it an end of data where the watch stops it.
def compression_of(head):
    if head[:2] == b"\x1f\x8b":
        return "gz"
    if head[:3] == b"BZh":
        return "bz2"
    if head[:6] == b"\xfd7zXZ\x00":
        return "xz"
    return None


class Guarded(io.RawIOBase):
    """A plain tar on disk as a file for the tar library. A walk of the same file runs just ahead of the library, and
    the library is given an end of file where the walk stops it: before an extended header too large to hold, before a
    header it would refuse, or at the end-of-archive block."""

    def __init__(self, handle, walker, size, watch):
        self.handle, self.walker, self.size, self.watch = handle, walker, size, watch
        self.pos = 0

    def readable(self):
        return True

    def seekable(self):
        return True

    def tell(self):
        return self.pos

    def seek(self, offset, whence=0):
        self.pos = max(0, (offset, self.pos + offset, self.size + offset)[whence])
        return self.pos

    def readinto(self, target):
        self.watch.walk(self.walker, self.size, self.pos + len(target))
        stop = self.watch.stop_at()
        limit = self.size if stop is None else min(stop, self.size)
        count = max(0, min(len(target), limit - self.pos))
        if not count:
            return 0
        self.handle.seek(self.pos)
        data = self.handle.read(count)
        target[:len(data)] = data
        self.pos += len(data)
        return len(data)

    def finish(self):
        """The rest of the headers, so that the watch has its whole answer."""
        self.watch.walk(self.walker, self.size)


class Decoded(io.RawIOBase):
    """A gzip, bzip2 or xz stream as a plain file for the tar library, read in pieces and followed by the watch; nothing
    is served from the point where the watch stops it."""

    PIECE = 1 << 20

    def __init__(self, source, kind, watch):
        self.source, self.kind, self.watch = source, kind, watch
        self.errors = (zlib.error, ValueError, OSError)
        if kind == "gz":
            self.decoder = zlib.decompressobj(31)
        elif kind == "bz2":
            import bz2
            self.decoder = bz2.BZ2Decompressor()
        else:
            import lzma
            self.decoder = lzma.LZMADecompressor()
            self.errors += (lzma.LZMAError,)
        self.pending = b""
        self.buffer = bytearray()
        self.served = 0
        self.finished = False
        self.trouble = None    # what is wrong with the stream: it ended before its end marker, or its checksum does not hold

    def readable(self):
        return True

    def piece(self):
        d = self.decoder
        if self.kind == "gz":
            if not self.pending:
                if d.eof:
                    return None
                self.pending = self.source.read(self.PIECE)
                if not self.pending:
                    self.trouble = "the gzip stream ends before its end marker"
                    return None
            out = d.decompress(self.pending, self.PIECE)
            self.pending = d.unconsumed_tail
            return out
        if d.eof:
            return None
        chunk = b""
        if d.needs_input:
            chunk = self.source.read(self.PIECE)
            if not chunk:
                self.trouble = "the %s stream ends before its end marker" % self.kind
                return None
        return d.decompress(chunk, self.PIECE)

    def fill(self):
        while not self.buffer and not self.finished:
            try:
                out = self.piece()
            except self.errors as exc:
                raise OSError("the %s stream is damaged: %s" % (self.kind, exc))
            if out is None:
                self.finished = True
                break
            self.watch.feed(out)
            self.buffer += out
            stop = self.watch.stop_at()
            if stop is not None and self.served + len(self.buffer) > stop:
                del self.buffer[max(0, stop - self.served):]
                self.finished = True

    def readinto(self, target):
        self.fill()
        count = min(len(target), len(self.buffer))
        target[:count] = self.buffer[:count]
        del self.buffer[:count]
        self.served += count
        return count

    def finish(self):
        """The rest of the stream, so that the watch has its whole answer and the stream's own end marker and checksum are
        verified. A tar that stopped at a header the library would not read is not followed further."""
        while self.watch.violation is None and self.watch.bad_at is None:
            try:
                out = self.piece()
            except self.errors as exc:
                self.trouble = "the %s stream is damaged: %s" % (self.kind, exc)
                return
            if out is None:
                return
            self.watch.feed(out)


class NoMembers:
    """The listing of a tar whose very first header the watch would not let the library read."""

    members = []

    def __iter__(self):
        return iter(())

    def close(self):
        pass


class TarList:
    """A tar on disk, listed by the tar library behind a watch: `archive` is the library's TarFile, `watch` the watch.

    The data between members is not read for a plain tar, and a compressed one is read once, decoded in pieces. The
    library is given an end of data before any extended header the watch will not let it hold, and before a header it
    would refuse; `finish()` lets the watch follow the rest, and `watch` then says whether the end block came.
    """

    def __init__(self, path):
        self.watch = TarWatch()
        self.handle = open(path, "rb")
        self.walker = None
        head = self.handle.read(6)
        self.handle.seek(0)
        kind = compression_of(head)
        try:
            if kind is None:
                self.walker = open(path, "rb")
                self.source = Guarded(self.handle, self.walker, os.fstat(self.handle.fileno()).st_size, self.watch)
                mode = "r:"
            else:
                self.source = Decoded(self.handle, kind, self.watch)
                mode = "r|"
                self.source = io.BufferedReader(self.source)
            self.archive = tarfile.open(fileobj=self.source, mode=mode, encoding="utf-8", errors="surrogateescape")
        except tarfile.TarError:
            if self.watch.violation is not None:
                self.archive = NoMembers()
                return
            trouble = getattr(getattr(self.source, "raw", self.source), "trouble", None)
            self.close()
            if trouble:
                raise tarfile.ReadError(trouble)
            if self.watch.bad_at == 0:
                raise tarfile.ReadError("the first header is not a tar header (a checksum that does not match, or a number that does not parse)")
            raise

    def finish(self):
        source = self.source.raw if isinstance(self.source, io.BufferedReader) else self.source
        source.finish()

    def trouble(self):
        """For a compressed tar, what is wrong with the stream itself (cut before its end marker, a checksum that does not hold); otherwise None."""
        source = self.source.raw if isinstance(self.source, io.BufferedReader) else self.source
        return getattr(source, "trouble", None)

    def close(self):
        archive = getattr(self, "archive", None)
        if archive is not None:
            archive.close()
        for handle in (self.handle, self.walker):
            if handle is not None:
                handle.close()

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.close()
        return False
# --- tar listing: end ----------------------------------------------------------------------------


def escaped(value):
    """One line, one field, nothing hidden; a byte that is not UTF-8 shows as \\xNN."""
    out = []
    for ch in value:
        o = ord(ch)
        if 0xDC80 <= o <= 0xDCFF:
            out.append("\\x%02x" % (o - 0xDC00))
        elif ch == "\\":
            out.append("\\\\")
        elif ch == "\t":
            out.append("\\t")
        elif ch == "\r":
            out.append("\\r")
        elif ch == "\n":
            out.append("\\n")
        elif o < 0x20 or o == 0x7F:
            out.append("\\x%02x" % o)
        else:
            out.append(ch)
    return "".join(out)


def b64(value):
    return base64.b64encode(value.encode("utf-8", "surrogateescape")).decode("ascii")


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
        with TarList(path) as listing:
            for member in listing.archive:
                low = member.name.lower()
                if any(marker in low for marker in IOS_MARKERS):
                    return True, "tar members have an iOS full file-system root"
                listing.archive.members = []
            if listing.watch.violation is not None:
                return False, "tar has no iOS full file-system marker before a header the scan does not read (an extended header of %d bytes at offset %d)" % (listing.watch.violation, listing.watch.violation_at)
    except (tarfile.TarError, OSError, EOFError) as exc:
        return False, "not a readable tar: %s" % exc
    return False, "tar has no iOS full file-system marker"


def run(path, out):
    if any(os.path.lexists(os.path.join(out, name)) for name in OUTPUTS):
        # Before anything is written: an earlier run's files stay as they are.
        print(json.dumps({"ok": False, "status": "refused", "why": "the output directory already holds a file of an earlier run (%s): the recipe does not write over it" % ", ".join(n for n in OUTPUTS if os.path.lexists(os.path.join(out, n)))}))
        return None
    os.makedirs(out, exist_ok=True)
    artifacts_path = os.path.join(out, "artifacts.tsv")
    sqlite_path = os.path.join(out, "sqlite.tsv")
    scratch = os.path.join(out, "sqlite-families.work.db")
    if os.path.lexists(scratch):
        os.unlink(scratch)
    work = sqlite3.connect(scratch)
    # m: the members of a database family; a: every other member, to find a main database that has no suffix.
    work.execute("CREATE TABLE m (base BLOB NOT NULL, role TEXT NOT NULL, size INTEGER NOT NULL, n INTEGER NOT NULL, kind TEXT NOT NULL)")
    work.execute("CREATE TABLE a (name BLOB NOT NULL, size INTEGER NOT NULL, n INTEGER NOT NULL, kind TEXT NOT NULL)")
    members = 0
    families_rows = 0
    categories = {}
    artifact_rows = 0
    errors, limits = [], []
    tar_end = "missing"
    try:
        with open(artifacts_path, "w", encoding="utf-8", newline="\n") as artifacts:
            artifacts.write("category\tpath\tbytes\tmtime_utc\ttype\tn\tpath_b64\n")
            try:
                with TarList(path) as listing:
                    try:
                        for member in listing.archive:
                            name = member.name
                            kind = member_type(member)
                            category = classify(name)
                            if category:
                                categories[category] = categories.get(category, 0) + 1
                                artifact_rows += 1
                                artifacts.write("%s\t%s\t%d\t%s\t%s\t%d\t%s\n" % (
                                    category, escaped(name), member.size, utc(member.mtime), kind, members, b64(name)))
                            base, role = sqlite_base(name)
                            raw = name.encode("utf-8", "surrogateescape")
                            if base is not None:
                                work.execute("INSERT INTO m VALUES (?,?,?,?,?)", (base.encode("utf-8", "surrogateescape"), role, member.size, members, kind))
                                families_rows += 1
                            else:
                                work.execute("INSERT INTO a VALUES (?,?,?,?)", (raw, member.size, members, kind))
                            members += 1
                            listing.archive.members = []
                    except (tarfile.TarError, EOFError, OSError) as exc:
                        errors.append("tar traversal stopped: %s" % exc)
                    try:
                        listing.finish()
                    except (tarfile.TarError, EOFError, OSError):
                        pass
                    if listing.trouble():
                        errors.append("the compressed tar is cut short or damaged: %s" % listing.trouble())
                    tar_end, found_limits, found_errors = tar_verdict(listing.watch, members)
                    limits += found_limits
                    errors += found_errors
            except (tarfile.TarError, EOFError, OSError) as exc:
                errors.append("tar traversal stopped: %s" % exc)
        work.execute("CREATE INDEX a_name ON a (name)")
        work.execute("CREATE INDEX m_base ON m (base, n)")
        # A main database with no suffix is the member a companion belongs to: the one whose name is the companion's base.
        work.execute("INSERT INTO m SELECT a.name, 'db', a.size, a.n, a.kind FROM a WHERE a.name IN (SELECT base FROM m WHERE role != 'db')")
        work.commit()
        databases = 0
        with open(sqlite_path, "w", encoding="utf-8", newline="\n") as handle:
            handle.write("path\tdb_bytes\twal_bytes\tshm_bytes\tjournal_bytes\tpath_b64\tmembers\ttypes\n")
            bases = [row[0] for row in work.execute("SELECT DISTINCT base FROM m ORDER BY base")]
            for base in bases:
                sizes = {role: [] for role in ROLES}
                where, kinds = [], []
                for role, size, n, kind in work.execute("SELECT role, size, n, kind FROM m WHERE base = ? ORDER BY n", (base,)):
                    sizes[role].append(str(size))
                    where.append("%s=%d" % (role, n))
                    kinds.append("%s=%s" % (role, kind))
                name = base.decode("utf-8", "surrogateescape")
                handle.write("%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n" % (
                    escaped(name), "|".join(sizes["db"]), "|".join(sizes["wal"]), "|".join(sizes["shm"]),
                    "|".join(sizes["journal"]), base_to_b64(base), ",".join(where), ",".join(kinds)))
                databases += 1
    finally:
        work.close()
        try:
            os.unlink(scratch)
        except OSError:
            pass
    with open(os.path.join(out, "index.tsv"), "w", encoding="utf-8", newline="\n") as handle:
        handle.write("file\twhat\n")
        handle.write("artifacts.tsv\tiOS forensic structures by category, path, size, archive mtime, type and member position (path_b64 is the exact name)\n")
        handle.write("sqlite.tsv\tSQLite-family files grouped with WAL, SHM and rollback-journal companions: every occurrence's size, member position and type (| joins repeats); a database with no suffix and no companion is not found by its name\n")
    coverage = {
        "recipe": "ios-filesystem",
        "status": "partial" if errors or limits else "complete",
        "covered": "%d tar members; %d forensic structures; %d SQLite families" % (members, artifact_rows, databases),
        "categories": dict(sorted(categories.items())),
        "not_covered": "artifact contents, deleted data, decryption, semantic findings, nested archives",
        "limits_hit": limits,
        "errors": errors,
        "tar_end": tar_end,
    }
    with open(os.path.join(out, "coverage.json"), "w", encoding="utf-8") as handle:
        json.dump(coverage, handle, indent=2, sort_keys=True)
        handle.write("\n")
    return coverage


def base_to_b64(base):
    return base64.b64encode(base).decode("ascii")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("command", choices=("detect", "run"))
    parser.add_argument("--target", required=True)
    parser.add_argument("--out")
    # The kickoff's census asks every detect step with --probe-out DIR, a
    # place for what the probe wants kept (evidence_catalog.py). Refused here,
    # it was a usage error (exit 2) for every input of a run, and a phone's
    # tar was catalogued as a member list only. Detect reads tar headers
    # and keeps nothing, so the directory is taken and left empty.
    parser.add_argument("--probe-out")
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
    if coverage is None:
        return 2
    print(json.dumps({"ok": True, "status": coverage["status"], "artifacts": sum(coverage["categories"].values())}))
    return 0


if __name__ == "__main__":
    sys.exit(main())
