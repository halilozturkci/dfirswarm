#!/usr/bin/env python3
"""Read the FSEvents log: what changed on this volume, in order, and what was not read.

macOS writes a per-volume change log into /.fseventsd for Spotlight and backup
software. It records the path, not the contents, so it can describe a file that
is gone. It is a change-notification history, not a complete audit: records are
coalesced, files roll off, and a volume's log can be absent, damaged or restored.

Each record file is gzip, sometimes several members end to end, and holds pages:

    page header (12 bytes): magic "1SLD" or "2SLD", 4 bytes of unknown, the page
                            length as u32 little-endian, header included
    then records to the end of the page:
        path, NUL-terminated UTF-8
        event id (u64)
        flags (u32)
        node id (u64), version 2 only

**There is no timestamp anywhere in the format.** Event ids are a counter within
one volume's log. They order records; they do not date them.

Only the two page versions above are read. A page whose magic has the shape of a
page header and is another version (3SLD, say) is `unsupported`, named with the
magic seen and where, and the rest of that file is not decoded: its page length
field is not known to sit where the older ones keep it. Nothing is guessed.

What this tool never does is turn a failure into a clean result. Per file it says
parsed, partial, empty, unsupported or failed; per gzip member complete, truncated
or failed (with its compressed offset); per page parsed, unsupported, invalid
length or truncated; per record decoded, empty path or incomplete; and every byte
it could not place in a page is counted and its position named. Decoding is
streamed (a member is inflated a block at a time, a page is held while it is
read), expansion is capped (`max_expanded_bytes`), and records go to the output as
they are decoded, never collected first.
"""
import hashlib
import json
import os
import re
import struct
import sys
import tempfile
import zlib
from bisect import bisect_right
from pathlib import Path

PARSER = "fsevents_parse/3"
SUPPORTED = {b"1SLD": 1, b"2SLD": 2}
SHAPE = re.compile(rb"[0-9A-Za-z]SLD")
CHUNK = 1 << 20
DEFAULT_MAX_EXPANDED = 256 << 20
DEFAULT_MAX_PAGE = 64 << 20
DEFAULT_INLINE_BYTES = 1 << 20
FIRST_BYTES = 256 << 10
FIRST_PROBLEMS = 100
FLAGS = [
    (0x00000001, "FolderEvent"), (0x00000002, "Mount"), (0x00000004, "Unmount"),
    (0x00000020, "EndOfTransaction"), (0x00000800, "LastHardLinkRemoved"),
    (0x00001000, "HardLink"), (0x00004000, "SymbolicLink"), (0x00008000, "FileEvent"),
    (0x00010000, "PermissionChange"), (0x00020000, "ExtendedAttrModified"),
    (0x00040000, "ExtendedAttrRemoved"), (0x00100000, "DocumentRevision"),
    (0x00400000, "ItemCloned"), (0x01000000, "Created"), (0x02000000, "Removed"),
    (0x04000000, "InodeMetaMod"), (0x08000000, "Renamed"), (0x10000000, "Modified"),
    (0x20000000, "Exchange"), (0x40000000, "FinderInfoMod"), (0x80000000, "FolderCreated"),
]
KNOWN_BITS = 0
for _bit, _name in FLAGS:
    KNOWN_BITS |= _bit
FLAG_NAMES = {name for _bit, name in FLAGS}
UUID_TEXT = re.compile(r"[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12}")


def fail(message, **extra):
    print(json.dumps({"error": message, **extra}))
    raise SystemExit(1)


def resolve_output(out, what="output"):
    """Where `out` really lands, as a path under the run directory; a place
    outside it, the run directory itself, or anything under inputs/ is refused.

    A string check is not enough: `work/../inputs/x`, an absolute path and a
    symlink that points out all name a place the tool must not write, and none
    of them starts with "inputs/". Resolving first and comparing directories
    is what actually holds, and the read-only inputs are the one place
    extracted bytes must never appear -- a later integrity check would report
    the evidence as modified. In a job $OUT is inside the run directory.
    """
    root = Path.cwd().resolve()
    dest = (root / out).resolve() if not Path(out).is_absolute() else Path(out).resolve()
    if dest == root or root not in dest.parents:
        fail("%s must stay inside the run directory" % what, **{what: str(out)})
    inputs = root / "inputs"
    if dest == inputs or inputs in dest.parents:
        fail("%s cannot be under inputs/" % what, **{what: str(out)})
    return str(dest.relative_to(root))


# Lossless paging (the same in every library tool that pages): the page an
# agent reads stays small, bounded by rows and by bytes, and when there are more
# rows the whole result is written as JSON Lines under work/<agent>/tool-output
# (in a job, $OUT/tool-output) and named. The file name is a digest of the page's
# key (a path), never of a value. Rows are written with ensure_ascii on: a path
# the filesystem gave as bytes that are not UTF-8 reaches Python as lone
# surrogates, which a UTF-8 file cannot hold and an escape can. A rerun that
# would replace a larger earlier file of the same name writes a new name and says
# which earlier file it kept.
class LosslessPage:
    def __init__(self, tool, key, limit, byte_limit=None):
        if isinstance(limit, bool) or not isinstance(limit, int) or limit < 1:
            raise ValueError("limit must be a positive integer")
        self.tool = re.sub(r"[^A-Za-z0-9_.-]", "_", tool)
        self.limit = limit
        self.byte_limit = byte_limit
        self.page = []
        self.page_bytes = 0
        self.full = False
        self.bytes_bound_hit = False
        self.total = 0
        self._out = None
        self._tmp = None
        digest = hashlib.sha256(json.dumps(key, sort_keys=True, default=str).encode("utf-8")).hexdigest()[:16]
        name = "%s-%s.jsonl" % (self.tool, digest)
        job, out = os.environ.get("JOB_ID"), os.environ.get("OUT")
        if job and out:
            # In a job only $OUT is written, and it is sealed as the job's
            # output: the whole result is cited from there.
            self.path = Path(out) / "tool-output" / name
            self.shown = "store/jobs/%s/out/tool-output/%s" % (re.sub(r"[^A-Za-z0-9_.-]", "_", job), name)
        else:
            agent = re.sub(r"[^A-Za-z0-9_.-]", "_", os.environ.get("AGENT_ID") or "tool")
            self.path = Path("work") / agent / "tool-output" / name
            self.shown = str(self.path)

    def _write(self, row):
        self._out.write(json.dumps(row, default=str))
        self._out.write("\n")

    def add(self, row):
        self.total += 1
        if not self.full and len(self.page) < self.limit:
            size = len(json.dumps(row, default=str)) if self.byte_limit is not None else 0
            if self.byte_limit is None or self.page_bytes + size <= self.byte_limit:
                self.page.append(row)
                self.page_bytes += size
                return
            self.bytes_bound_hit = True
        # From the first row that does not fit, every later row goes to the file only: the page is a prefix.
        self.full = True
        if self._out is None:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            fd, name = tempfile.mkstemp(dir=self.path.parent, prefix=".%s-" % self.path.name)
            self._tmp = Path(name)
            self._out = os.fdopen(fd, "w", encoding="utf-8")
            for kept in self.page:
                self._write(kept)
        self._write(row)

    def finish(self):
        result = {"matched": self.total, "returned": len(self.page), "truncated": self.total > len(self.page)}
        if self.byte_limit is not None:
            result["inline_byte_limit"] = self.byte_limit
            if self.bytes_bound_hit:
                result["inline_bounded_by_bytes"] = True
        if self._out is not None:
            self._out.flush()
            os.fsync(self._out.fileno())
            self._out.close()
            target, shown = self.path, self.shown
            if target.exists() and target.stat().st_size > os.path.getsize(self._tmp):
                n = 2
                while target.with_name("%s-%d%s" % (target.stem, n, target.suffix)).exists():
                    n += 1
                target = target.with_name("%s-%d%s" % (target.stem, n, target.suffix))
                shown = self.shown.rsplit("/", 1)[0] + "/" + target.name
                result["kept_earlier_larger_result"] = self.shown
            os.replace(self._tmp, target)
            result["all_results"] = shown
            result["all_results_format"] = "JSON Lines, one complete result per line"
        return result


def decode_flags(value):
    return [name for bit, name in FLAGS if value & bit]


class FileScan:
    """What happened while one record file was read."""

    def __init__(self, path):
        self.path = path
        self.compressed = None
        self.compressed_bytes = 0
        self.expanded = 0                 # decompressed bytes handed on so far
        self.member_starts = []           # (decompressed offset, member index)
        self.members = {"complete": 0, "truncated": 0, "failed": 0}
        self.pages = {"parsed": 0, "unsupported": 0, "invalid_length": 0, "truncated": 0}
        self.records = {"decoded": 0, "empty_path": 0, "incomplete": 0}
        self.bytes_skipped = 0
        self.padding_bytes = 0
        self.not_decoded_bytes = 0
        self.magic_seen = None
        self.problems = []
        self.state = None
        self.error = None

    def problem(self, kind, why, **extra):
        self.problems.append({"file": self.path, "kind": kind, "why": why, **extra})

    def member_at(self, offset):
        if not self.member_starts:
            return None
        i = bisect_right([s[0] for s in self.member_starts], offset) - 1
        return self.member_starts[max(i, 0)][1]


def inflate(fh, scan, cap):
    """The decompressed bytes of the gzip members of `fh`, in order, a block at a time.

    A member that ends early, a stream that does not decode and the expansion cap
    each end the file's decoding and are named; what was decoded before is handed on.
    """
    pending = fh.read(CHUNK)
    offset = 0                            # compressed offset of `pending`'s first byte
    index = 0
    while pending:
        if pending[:2] != b"\x1f\x8b":
            rest = len(pending)
            while True:
                more = fh.read(CHUNK)
                if not more:
                    break
                rest += len(more)
            scan.not_decoded_bytes += rest
            scan.problem("bytes after the last gzip member", "%d byte(s) at compressed offset %d are not a gzip member" % (rest, offset),
                         compressed_offset=offset, bytes=rest, first_bytes_hex=pending[:8].hex())
            return
        engine = zlib.decompressobj(16 + zlib.MAX_WBITS)
        scan.member_starts.append((scan.expanded, index))
        fed = 0
        buf = pending
        status, unused, why = None, b"", None
        try:
            while True:
                out = engine.decompress(buf, CHUNK)
                fed += len(buf) - len(engine.unconsumed_tail) - (len(engine.unused_data) if engine.eof else 0)
                if out:
                    room = cap - scan.expanded
                    if len(out) > room:
                        if room > 0:
                            scan.expanded += room
                            yield out[:room]
                        scan.problem("expansion cap reached",
                                     "%s expanded past max_expanded_bytes (%d) in member %d; the rest of the file is not decoded "
                                     "(the whole is the file itself, %d compressed byte(s) from offset %d were being read)"
                                     % (scan.path, cap, index, fed, offset),
                                     member=index, compressed_offset=offset, cap=cap)
                        scan.members["truncated"] += 1
                        scan.not_decoded_bytes += max(scan.compressed_bytes - (offset + fed), 0)
                        return
                    scan.expanded += len(out)
                    yield out
                if engine.eof:
                    status, unused = "complete", engine.unused_data
                    break
                buf = engine.unconsumed_tail
                if not buf:
                    buf = fh.read(CHUNK)
                    if not buf:
                        status = "truncated"
                        break
        except zlib.error as exc:
            status, why = "failed", str(exc)
        if status == "complete":
            scan.members["complete"] += 1
            offset += fed
            index += 1
            pending = unused or fh.read(CHUNK)
            continue
        if status == "truncated":
            scan.members["truncated"] += 1
            scan.problem("gzip member truncated",
                         "member %d, starting at compressed offset %d, ends before its deflate stream does: the file is cut short; "
                         "what decoded before the cut is read" % (index, offset), member=index, compressed_offset=offset)
        else:
            scan.members["failed"] += 1
            scan.problem("gzip member failed", "member %d, starting at compressed offset %d, does not decode (%s); "
                         "the rest of the file is not read" % (index, offset, why), member=index, compressed_offset=offset)
        remaining = len(engine.unconsumed_tail)
        while True:
            more = fh.read(CHUNK)
            if not more:
                break
            remaining += len(more)
        scan.not_decoded_bytes += remaining
        return


def raw(fh):
    while True:
        block = fh.read(CHUNK)
        if not block:
            return
        yield block


class Source:
    """Decompressed bytes read forward with a lookahead; `offset` is the absolute position of the next byte."""

    def __init__(self, chunks):
        self.chunks = chunks
        self.buf = bytearray()
        self.pos = 0
        self.base = 0                     # absolute offset of buf[0]
        self.done = False

    @property
    def offset(self):
        return self.base + self.pos

    def _more(self):
        if self.done:
            return False
        try:
            block = next(self.chunks)
        except StopIteration:
            self.done = True
            return False
        if self.pos >= CHUNK:
            del self.buf[:self.pos]
            self.base += self.pos
            self.pos = 0
        self.buf += block
        return True

    def peek(self, n):
        while len(self.buf) - self.pos < n and self._more():
            pass
        return bytes(self.buf[self.pos:self.pos + n])

    def take(self, n):
        got = self.peek(n)
        self.pos += len(got)
        return got

    def skip_to_magic(self):
        """Consume bytes up to the next supported page magic (or the end); how many."""
        skipped = 0
        while True:
            window = self.peek(1 << 16)
            if not window:
                return skipped
            hits = [h for h in (window.find(m) for m in SUPPORTED) if h >= 0]
            if hits:
                at = min(hits)
                self.pos += at
                return skipped + at
            if len(window) < (1 << 16):       # the end of the data: there is nothing more to find
                self.pos += len(window)
                return skipped + len(window)
            step = len(window) - 3            # a magic may straddle the window
            self.pos += step
            skipped += step

    def drain(self):
        total = 0
        while True:
            got = self.take(1 << 20)
            if not got:
                return total
            total += len(got)


def last_nonzero(page, start):
    """The offset just past the last byte of `page` (from `start` on) that is not NUL, found from the end in
    blocks, so a page is not copied whole to strip its padding."""
    end = len(page)
    while end > start:
        lo = max(start, end - 65536)
        kept = page[lo:end].rstrip(b"\x00")
        if kept:
            return lo + len(kept)
        end = lo
    return start


def parse_records(page, at, version, scan, emit, member):
    """The records of one page, which began at decompressed offset `at`; its 12-byte header is skipped."""
    fixed = 12 + (8 if version == 2 else 0)
    cursor = 12
    used = last_nonzero(page, cursor)      # what follows is NUL padding, counted and not read as records
    while cursor < len(page):
        if cursor >= used:
            scan.padding_bytes += len(page) - cursor
            return
        end = page.find(b"\x00", cursor)
        if end < 0 or end + 1 + fixed > len(page):
            scan.records["incomplete"] += 1
            scan.bytes_skipped += len(page) - cursor
            scan.problem("incomplete record",
                         "a record at decompressed offset %d is cut off by the end of its page (%d byte(s) left, %s)"
                         % (at + cursor, len(page) - cursor, "no path terminator" if end < 0 else "fixed fields short"),
                         offset=at + cursor, bytes=len(page) - cursor)
            return
        event_id, flags = struct.unpack_from("<QI", page, end + 1)
        node = struct.unpack_from("<Q", page, end + 1 + 12)[0] if version == 2 else None
        start, cursor = cursor, end + 1 + fixed
        if end == start:
            scan.records["empty_path"] += 1
            continue
        raw_path = page[start:end]
        scan.records["decoded"] += 1
        text = raw_path.decode("utf-8", "replace")
        record = {"path": text, "event_id": event_id, "flags": decode_flags(flags), "flags_raw": flags,
                  "node_id": node, "version": version, "file": scan.path, "member": member,
                  "page_offset": at, "record_offset": at + start, "parser": PARSER}
        undecoded = flags & ~KNOWN_BITS
        if undecoded:
            record["flags_undecoded"] = undecoded
        if "\ufffd" in text:
            record["path_invalid_utf8"] = True
            record["path_raw_hex"] = raw_path.hex()
        emit(record)


def parse_pages(src, scan, emit, max_page):
    while True:
        at = src.offset
        head = src.peek(12)
        if not head:
            return
        if len(head) < 12:
            src.take(len(head))
            scan.bytes_skipped += len(head)
            scan.problem("bytes not placed in a page", "%d byte(s) at decompressed offset %d are too few for a page header" % (len(head), at),
                         offset=at, bytes=len(head))
            return
        magic = head[:4]
        version = SUPPORTED.get(magic)
        if version is None:
            if SHAPE.fullmatch(magic):
                text = magic.decode("ascii")
                scan.pages["unsupported"] += 1
                scan.magic_seen = scan.magic_seen or text
                rest = src.drain()
                scan.not_decoded_bytes += rest
                scan.problem("unsupported page magic",
                             "a page of version %r at decompressed offset %d is not read: only 1SLD and 2SLD are; its page length is not "
                             "known to sit where theirs does, so the remaining %d byte(s) of the file are not decoded" % (text, at, rest),
                             offset=at, magic=text, bytes=rest)
                return
            skipped = src.skip_to_magic()
            scan.bytes_skipped += skipped
            scan.problem("bytes not placed in a page",
                         "%d byte(s) from decompressed offset %d are not a page header and were skipped to the next 1SLD or 2SLD" % (skipped, at),
                         offset=at, bytes=skipped, first_bytes_hex=head[:8].hex())
            continue
        length = struct.unpack_from("<I", head, 8)[0]
        if length < 12 or length > max_page:
            scan.pages["invalid_length"] += 1
            scan.problem("invalid page length",
                         "the page at decompressed offset %d declares %d byte(s): below the 12-byte header, or above max_page_bytes (%d); "
                         "its header is skipped and the next page header is looked for" % (at, length, max_page),
                         offset=at, declared=length)
            src.take(12)
            scan.bytes_skipped += 12
            continue
        page = src.take(length)
        if len(page) < length:
            scan.pages["truncated"] += 1
            scan.problem("page truncated", "the page at decompressed offset %d declares %d byte(s) and %d are left in the file" % (at, length, len(page)),
                         offset=at, declared=length, available=len(page))
        else:
            scan.pages["parsed"] += 1
        parse_records(page, at, version, scan, emit, scan.member_at(at))


def scan_file(path, emit, max_expanded, max_page):
    scan = FileScan(path)
    try:
        size = os.path.getsize(path)
        fh = open(path, "rb")
    except OSError as exc:
        scan.state, scan.error = "failed", "%s: %s" % (type(exc).__name__, exc)
        scan.problem("file not readable", scan.error)
        return scan
    with fh:
        scan.compressed_bytes = size
        if size == 0:
            scan.compressed = False
            scan.state = "empty"
            return scan
        head = fh.read(4)
        fh.seek(0)
        if head[:2] == b"\x1f\x8b":
            scan.compressed = True
            chunks = inflate(fh, scan, max_expanded)
        elif head in SUPPORTED or SHAPE.fullmatch(head or b""):
            scan.compressed = False
            chunks = raw(fh)
        else:
            scan.compressed = False
            scan.state = "unsupported"
            scan.problem("not an FSEvents record file", "neither gzip nor a page header: it starts with %s" % (head.hex() or "nothing"),
                         first_bytes_hex=head.hex())
            return scan
        try:
            parse_pages(Source(chunks), scan, emit, max_page)
        except OSError as exc:
            scan.error = "%s: %s" % (type(exc).__name__, exc)
            scan.problem("read failed", scan.error)
    decoded = scan.records["decoded"] + scan.records["empty_path"]
    if scan.pages["unsupported"] and not decoded:
        scan.state = "unsupported"
    elif scan.problems:
        scan.state = "partial" if decoded else "failed"
    elif scan.expanded == 0 and not scan.pages["parsed"]:
        scan.state = "empty"
    else:
        scan.state = "parsed"
    return scan


def log_identity(directory):
    path = os.path.join(directory, "fseventsd-uuid")
    if not os.path.isfile(path) or os.path.islink(path):
        return None
    try:
        size = os.path.getsize(path)
        with open(path, "rb") as fh:
            data = fh.read(256)
    except OSError as exc:
        return {"file": path, "error": "%s: %s" % (type(exc).__name__, exc)}
    text = data.decode("utf-8", "replace").strip()
    out = {"file": path, "bytes": size}
    if UUID_TEXT.fullmatch(text):
        out["uuid"] = text
    else:
        out["raw_hex"] = data[:64].hex()
    out["note"] = "the log's own identity, not the APFS volume's UUID"
    return out


def main():
    try:
        args = json.load(sys.stdin)
    except ValueError as exc:
        fail("arguments are not valid JSON", reason=str(exc))
    path = args.get("path")
    if not isinstance(path, str) or not path:
        fail("path is required: an /.fseventsd directory or one record file")
    if not os.path.exists(path):
        fail("no such file or directory", path=path)
    limit = args.get("limit", 2000)
    if not isinstance(limit, int) or isinstance(limit, bool) or limit < 1:
        fail("limit must be a positive integer")
    max_expanded = args.get("max_expanded_bytes", DEFAULT_MAX_EXPANDED)
    max_page = args.get("max_page_bytes", DEFAULT_MAX_PAGE)
    for name, value in (("max_expanded_bytes", max_expanded), ("max_page_bytes", max_page)):
        if not isinstance(value, int) or isinstance(value, bool) or value < 1:
            fail("%s must be a positive integer" % name, **{name: value})
    inline_bytes = args.get("max_inline_bytes", DEFAULT_INLINE_BYTES)
    if not isinstance(inline_bytes, int) or isinstance(inline_bytes, bool) or inline_bytes < 1:
        fail("max_inline_bytes must be a positive integer", max_inline_bytes=inline_bytes)
    out_name = args.get("out_file")
    if out_name is not None and (not isinstance(out_name, str) or not out_name):
        fail("out_file must be a non-empty string")
    if out_name is not None:
        resolve_output(out_name, "out_file")   # refuses a place outside the run, or under inputs/
    pattern = None
    if args.get("contains"):
        try:
            pattern = re.compile(args["contains"], re.I)
        except re.error as exc:
            fail("contains is not a valid regex", reason=str(exc))
    wanted = {str(f) for f in (args.get("flags") or [])}
    unknown_flags = sorted(wanted - FLAG_NAMES)

    notes = {"links_not_followed": 0, "not_regular_files": 0}
    identity = None
    targets = []
    if os.path.isdir(path):
        identity = log_identity(path)
        for name in sorted(os.listdir(path)):
            full = os.path.join(path, name)
            if name == "fseventsd-uuid":
                continue
            if os.path.islink(full):
                notes["links_not_followed"] += 1
            elif os.path.isfile(full):
                targets.append(full)
            else:
                notes["not_regular_files"] += 1
    else:
        targets = [path]
        identity = log_identity(os.path.dirname(os.path.abspath(path)))
    if not targets:
        fail("no record files there", path=path, **notes)

    sink = None
    if out_name:
        try:
            Path(out_name).parent.mkdir(parents=True, exist_ok=True)
            # The name as the caller gave it: O_EXCL refuses a name that exists, a link (a dangling one included) as much as a file.
            fd = os.open(out_name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o644)
        except FileExistsError:
            fail("out_file already exists; the tool does not overwrite: use a new name", out_file=out_name)
        except OSError as exc:
            fail("out_file could not be created", out_file=out_name, reason="%s: %s" % (type(exc).__name__, exc))
        sink = os.fdopen(fd, "w", encoding="utf-8", newline="\n")
    paging = None if sink else LosslessPage("fsevents_parse", [path, args.get("contains"), sorted(wanted)], limit, inline_bytes)
    inline = []
    inline_state = {"bytes": 0, "full": False, "bounded_by_bytes": False}
    totals = {"before_filter": 0, "kept": 0}
    ids = [None, None]

    def emit(record):
        totals["before_filter"] += 1
        if pattern and not pattern.search(record["path"]):
            return
        if wanted and not (wanted & set(record["flags"])):
            return
        totals["kept"] += 1
        if record["event_id"]:
            ids[0] = record["event_id"] if ids[0] is None else min(ids[0], record["event_id"])
            ids[1] = record["event_id"] if ids[1] is None else max(ids[1], record["event_id"])
        if sink:
            line = json.dumps(record, sort_keys=True)
            sink.write(line + "\n")
            if not inline_state["full"] and len(inline) < limit:
                if inline_state["bytes"] + len(line) <= inline_bytes:
                    inline.append(record)
                    inline_state["bytes"] += len(line)
                else:
                    inline_state["bounded_by_bytes"] = True
                    inline_state["full"] = True
            else:
                inline_state["full"] = True
        else:
            paging.add(record)

    states = {"parsed": 0, "partial": 0, "empty": 0, "unsupported": 0, "failed": 0}
    coverage = {"compressed_bytes": 0, "expanded_bytes": 0,
                "members": {"complete": 0, "truncated": 0, "failed": 0},
                "pages": {"parsed": 0, "unsupported": 0, "invalid_length": 0, "truncated": 0},
                "records": {"decoded": 0, "empty_path": 0, "incomplete": 0},
                "bytes_skipped": 0, "padding_bytes": 0, "bytes_not_decoded": 0}
    per_file = LosslessPage("fsevents_parse_files", [path], 200, FIRST_BYTES)
    problems = LosslessPage("fsevents_parse_problems", [path], FIRST_PROBLEMS, FIRST_BYTES)
    gzip_files = 0
    for target in targets:
        scan = scan_file(target, emit, max_expanded, max_page)
        states[scan.state] += 1
        gzip_files += 1 if scan.compressed else 0
        coverage["compressed_bytes"] += scan.compressed_bytes
        coverage["expanded_bytes"] += scan.expanded
        for group in ("members", "pages", "records"):
            for k, v in getattr(scan, group).items():
                coverage[group][k] += v
        coverage["bytes_skipped"] += scan.bytes_skipped
        coverage["padding_bytes"] += scan.padding_bytes
        coverage["bytes_not_decoded"] += scan.not_decoded_bytes
        row = {"file": target, "state": scan.state, "gzip": scan.compressed, "compressed_bytes": scan.compressed_bytes,
               "expanded_bytes": scan.expanded, "members": scan.members, "pages": scan.pages, "records": scan.records,
               "problems": len(scan.problems)}
        if scan.magic_seen:
            row["magic_seen"] = scan.magic_seen
        if scan.error:
            row["error"] = scan.error
        per_file.add(row)
        for p in scan.problems:
            problems.add(p)

    if sink:
        sink.flush()
        os.fsync(sink.fileno())
        sink.close()
        shown, complete = inline, out_name
        limited = totals["kept"] > len(inline)
        page = {"inline_bounded_by_bytes": inline_state["bounded_by_bytes"]}
    else:
        page = paging.finish()
        shown, complete, limited = paging.page, page.get("all_results"), page["truncated"]
    files_page, problems_page = per_file.finish(), problems.finish()
    readable = states["parsed"] + states["partial"] + states["empty"]
    if states["parsed"] + states["empty"] == len(targets):
        status = "complete"
    elif readable:
        status = "partial"
    else:
        status = "unsupported" if states["unsupported"] and not states["failed"] else "failed"
    ids_range = [ids[0], ids[1]] if ids[0] is not None else None
    print(json.dumps({
        "path": path,
        "parser": PARSER,
        "status": status,
        "files": len(targets),
        "gzip_files": gzip_files,
        "files_by_state": states,
        "per_file": per_file.page,
        "per_file_pages": files_page,
        "log_identity": identity,
        "records": shown,
        "record_count": totals["kept"],
        "records_inline": len(shown),
        "complete_records": complete,
        "records_before_filter": totals["before_filter"],
        "event_id_range": ids_range,
        "inline_limited": bool(limited),
        "inline_bounded_by_bytes": bool(page.get("inline_bounded_by_bytes")),
        "inline_byte_limit": inline_bytes,
        **({"kept_earlier_larger_result": page["kept_earlier_larger_result"]} if page.get("kept_earlier_larger_result") else {}),
        "coverage": coverage,
        "problems": problems.page,
        "problems_total": problems_page["matched"],
        "problems_pages": problems_page,
        "filters": {"contains": args.get("contains"), "flags": sorted(wanted), **({"flags_unknown": unknown_flags} if unknown_flags else {})},
        "limits": {"max_expanded_bytes": max_expanded, "max_page_bytes": max_page, "max_inline_bytes": inline_bytes},
        "directory": notes,
        "note": "There is no timestamp in this format. Event ids are a counter within one volume's log, so this gives order within "
                "that log and not time. A record carrying Renamed means the path took part in a rename; the old and the new name "
                "are not paired by it. Records are coalesced and logs roll off, so an absent path was not necessarily never touched. "
                "Only 1SLD and 2SLD pages are read; any other page magic is reported as unsupported. A zero count is what this parser "
                "decoded from these files, not a finding about the volume.",
    }, indent=2))
    if status in ("unsupported", "failed"):
        raise SystemExit(1)


if __name__ == "__main__":
    main()
