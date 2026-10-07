#!/usr/bin/env python3
"""Read a jump list, and hand the link structures inside it to lnk_parse.

A jump list can outlive the Recent folder and the file it points at, so it can
still name a target that is gone. It records that an application or the shell listed
an item, which is not by itself an opening event and does not say who. Two formats:

  *.automaticDestinations-ms  an OLE compound file. Each numbered stream is a
                              link structure; the DestList stream is the index,
                              holding for each entry the entry number, the
                              NetBIOS name of the host, the last access time, the
                              pin state and the target path.
  *.customDestinations-ms     no container at all: link structures one after
                              another. They are CARVED by their own 20-byte
                              header; the container's own structure is not parsed,
                              so a header-shaped run of bytes inside a link is cut
                              as if it began another one.

The DestList layout depends on its version (the first word of the stream). Version 1
has a 114-byte fixed part per entry, with the path length, in characters, at 0x70 and
the path from 0x72. Versions 3 and 4 have a 130-byte fixed part, with the path length
at 0x80, the path from 0x82 and a 4-byte trailer after it. In all of them the NetBIOS
name is at 0x48 (16 bytes), the entry number at 0x58, the last-access FILETIME at
0x64 and the pin state at 0x6C (-1 is not pinned). Any other version is refused, with
a problem and no entries: a layout is not guessed. The counters between those fields
differ by version, and their meaning is not established here, so they are returned
as raw hex under `undecoded_*` and no access count is claimed.

The target path, the volume serial and the three target timestamps are the link
structures', so they are written out for `lnk_parse`, which reads them. `out_dir` is a
directory under work/<your id>/ (work/extracted/<your id>/ and work/quarantine/<your id>/
also work); run as a job, the harness gives a work/<your id>/... path to $OUT. Any other place
in the run is refused, naming the places that work. A file is never read whole: a stream is
read in pieces and a customDestinations file is searched in place, so a very large one costs
time, not memory; a FIFO, a socket or a device named by the path or found in a directory is
not opened, and is counted under `not_attempted`.
"""
import binascii
import datetime
import json
import os
import re
import stat
import struct
import sys
from pathlib import Path

# Lossless paging (the same in every library tool that pages): the page an
# agent reads stays small, and when there are more rows the whole result is
# written as JSON Lines under work/<agent>/tool-output and named.
import hashlib
import json
import os
import re
import tempfile
from pathlib import Path


class LosslessPage:
    def __init__(self, tool: str, key: object, limit: int):
        if isinstance(limit, bool) or not isinstance(limit, int) or limit < 1:
            raise ValueError("limit must be a positive integer")
        self.tool = re.sub(r"[^A-Za-z0-9_.-]", "_", tool)
        self.limit = limit
        self.page: list[object] = []
        self.total = 0
        self._out = None
        self._tmp: Path | None = None
        digest = hashlib.sha256(
            json.dumps(key, sort_keys=True, default=str).encode("utf-8")
        ).hexdigest()[:16]
        name = f"{self.tool}-{digest}.jsonl"
        job, out = os.environ.get("JOB_ID"), os.environ.get("OUT")
        if job and out:
            # In a job only $OUT is written, and it is sealed as the job's
            # output: the whole result is cited from there.
            self.path = Path(out) / "tool-output" / name
            self.shown = "store/jobs/%s/out/tool-output/%s" % (re.sub(r"[^A-Za-z0-9_.-]", "_", job), name)
        else:
            agent = re.sub(
                r"[^A-Za-z0-9_.-]", "_", os.environ.get("AGENT_ID") or "tool"
            )
            self.path = Path("work") / agent / "tool-output" / name
            self.shown = str(self.path)

    def _cannot_write(self, exc: BaseException) -> None:
        """The whole result cannot be kept: say so as JSON and stop, never a traceback."""
        import sys as _sys
        _sys.stdout.write(json.dumps({
            "error": "the whole result (%d rows so far) cannot be written to %s: %s. Outside a job the place is your own "
                     "work/<your id>/ directory; in a job it is $OUT." % (self.total, self.shown, exc),
            "status": "failed",
        }) + "\n")
        _sys.exit(1)

    def _write(self, row: object) -> None:
        assert self._out is not None
        text = json.dumps(row, ensure_ascii=False, default=str)
        try:
            text.encode("utf-8")
        except UnicodeEncodeError:
            # A lone surrogate (a file name that is not UTF-8): escape it, lose nothing.
            text = json.dumps(row, ensure_ascii=True, default=str)
        try:
            self._out.write(text)
            self._out.write("\n")
        except OSError as exc:
            self._cannot_write(exc)

    def add(self, row: object) -> None:
        self.total += 1
        if len(self.page) < self.limit:
            self.page.append(row)
            return
        if self._out is None:
            try:
                self.path.parent.mkdir(parents=True, exist_ok=True)
                fd, name = tempfile.mkstemp(
                    dir=self.path.parent, prefix=f".{self.path.name}-"
                )
                self._tmp = Path(name)
                self._out = os.fdopen(fd, "w", encoding="utf-8")
            except OSError as exc:
                self._cannot_write(exc)
            for kept in self.page:
                self._write(kept)
        self._write(row)

    def finish(self) -> dict:
        result = {
            "matched": self.total,
            "returned": len(self.page),
            "truncated": self.total > len(self.page),
        }
        if self._out is not None:
            try:
                self._out.flush()
                os.fsync(self._out.fileno())
                self._out.close()
                assert self._tmp is not None
                os.replace(self._tmp, self.path)
            except OSError as exc:
                self._cannot_write(exc)
            result["all_results"] = self.shown
            result["all_results_format"] = "JSON Lines, one complete result per line"
        return result

FILETIME_EPOCH = datetime.datetime(1601, 1, 1, tzinfo=datetime.timezone.utc)
LNK_MAGIC = bytes([0x4C, 0x00, 0x00, 0x00]) + binascii.unhexlify("0114020000000000c000000000000046")
DESTLIST_HEADER = 32
PARSER = "jumplist/4"
MAX_PATH_CHARS = 32767
# A DestList stream is read whole before it is parsed; a real one is a few hundred
# kilobytes at most, so a stream past this is refused by name instead of held in memory.
MAX_DESTLIST_BYTES = 64 * 1024 * 1024
# olefile holds an opened stream whole in memory; a link structure is small by nature, so a stream past this is named and not read.
MAX_STREAM_BYTES = 32 * 1024 * 1024
# The fixed part of an entry, the offset of its path length (a 16-bit count of UTF-16
# characters) and the bytes after the path, by DestList version.
LAYOUTS = {
    1: {"fixed": 114, "chars_at": 0x70, "trailer": 0},
    3: {"fixed": 130, "chars_at": 0x80, "trailer": 4},
    4: {"fixed": 130, "chars_at": 0x80, "trailer": 4},
}


def fail(message, **extra):
    print(json.dumps({"error": message, **extra}))
    raise SystemExit(1)


def filetime(value):
    """ISO 8601 UTC with all seven fractional digits, from integer arithmetic; None for 0
    or a date past year 9999. The caller keeps the raw value beside it."""
    if not value:
        return None
    try:
        whole, ticks = divmod(value, 10_000_000)
        moment = FILETIME_EPOCH + datetime.timedelta(seconds=whole)
        return moment.strftime("%Y-%m-%dT%H:%M:%S") + ".%07dZ" % ticks
    except (OverflowError, ValueError):
        return None


def parse_destlist(data):
    """The DestList stream, by the layout of its version (see the module note)."""
    out = {"entries": [], "problems": []}
    if len(data) < DESTLIST_HEADER:
        out["problems"].append("the DestList stream is %d bytes, shorter than its 32-byte header" % len(data))
        return out
    version, count, pinned = struct.unpack_from("<III", data, 0)
    out["destlist_version"] = version
    out["entries_claimed"] = count
    out["pinned_claimed"] = pinned
    layout = LAYOUTS.get(version)
    if layout is None:
        out["problems"].append(
            "DestList version %d is not one this parser reads (1, 3 and 4 are); no entry is read, and none is guessed" % version)
        return out
    fixed, chars_at, trailer = layout["fixed"], layout["chars_at"], layout["trailer"]
    offset = DESTLIST_HEADER
    while offset + fixed <= len(data):
        chars = struct.unpack_from("<H", data, offset + chars_at)[0]
        end = offset + fixed + chars * 2
        if chars > MAX_PATH_CHARS or end + trailer > len(data):
            out["problems"].append(
                "entry %d at stream offset %d claims a %d-character path, which does not fit in the stream; stopped here"
                % (len(out["entries"]) + 1, offset, chars))
            break
        host = data[offset + 0x48:offset + 0x58].split(b"\x00", 1)[0].decode("ascii", "replace")
        number, = struct.unpack_from("<I", data, offset + 0x58)
        modified, = struct.unpack_from("<Q", data, offset + 0x64)
        pin, = struct.unpack_from("<i", data, offset + 0x6C)
        path = data[offset + fixed:end].decode("utf-16-le", "replace")
        entry = {
            "stream_offset": offset,
            "entry_number": number,
            "entry_field_hex": data[offset + 0x58:offset + 0x60].hex(),
            "stream": "%x" % number,
            "path": path,
            "path_chars": chars,
            "hostname": host,
            "last_access": filetime(modified),
            "last_access_filetime": str(modified),
            "pin_status": pin,
            "pinned": pin != -1,
            "undecoded_0x5c_0x64_hex": data[offset + 0x5C:offset + 0x64].hex(),
        }
        if version >= 3:
            entry["undecoded_0x70_0x80_hex"] = data[offset + 0x70:offset + 0x80].hex()
        out["entries"].append(entry)
        offset = end + trailer
    if count and len(out["entries"]) != count:
        out["problems"].append(
            "the header claims %d entries and %d were read" % (count, len(out["entries"])))
    if offset < len(data) and not out["problems"]:
        out["problems"].append("%d byte(s) after the last entry were not read" % (len(data) - offset))
    out["not_decoded"] = ["access or interaction counters (their position and encoding differ by version and are not decoded)",
                          "the droid identifiers and the checksum at the start of each entry"]
    return out


def lnk_starts(fh, size, window=1 << 20):
    """The offset of every link header in the file `fh` (`size` bytes), read a window at a time with the header's length
    carried over, so a header that straddles two windows is found once. Nothing but the offsets is kept."""
    starts, carry, base = [], b"", 0          # base: the file offset of carry[0]
    keep = len(LNK_MAGIC) - 1
    fh.seek(0)
    while True:
        block = fh.read(window)
        if not block:
            break
        data = carry + block
        at = 0
        while True:
            hit = data.find(LNK_MAGIC, at)
            if hit < 0:
                break
            starts.append(base + hit)
            at = hit + 4
        tail = min(keep, len(data))
        base += len(data) - tail
        carry = data[len(data) - tail:]
    return starts


def split_lnks(data):
    """The link structures in `data` (bytes) as (start, length): each by its own header, running to the next header or
    to the end. The same search `lnk_starts` makes on a file, for bytes already in hand."""
    import io
    starts = lnk_starts(io.BytesIO(data), len(data))
    return [(start, (starts[i + 1] if i + 1 < len(starts) else len(data)) - start) for i, start in enumerate(starts)]


def own_places():
    """The places this tool may write, resolved, and how to say them. In a job only $OUT is writable (the harness
    maps work/<id>/x to it); anywhere else the agent's own directories under work/ are, and nothing else in the run."""
    job, out = os.environ.get("JOB_ID"), os.environ.get("OUT")
    if job and out:
        return [Path(out).resolve()], "$OUT (run as a job, only $OUT is writable; write the path as work/<your id>/...)"
    agent = re.sub(r"[^A-Za-z0-9_.-]", "_", os.environ.get("AGENT_ID") or "tool")
    root = Path.cwd().resolve()
    places = [root / "work" / agent, root / "work" / "extracted" / agent, root / "work" / "quarantine" / agent]
    return places, "work/%s/, work/extracted/%s/ or work/quarantine/%s/" % (agent, agent, agent)


def resolve_output(out):
    """Where `out` really lands, refusing anything outside the run directory, under inputs/, or outside the places
    the agent may write.

    A string check is not enough: `work/../inputs/x` and an absolute path
    both name a file the tool must not write, and neither starts with
    "inputs/". Resolving first and comparing directories is what actually
    holds, and the read-only inputs are the one place extracted bytes must
    never appear -- a later integrity check would report the evidence as
    modified.
    """
    root = Path.cwd().resolve()
    dest = (root / out).resolve() if not Path(out).is_absolute() else Path(out).resolve()
    places, said = own_places()
    in_a_job = bool(os.environ.get("JOB_ID") and os.environ.get("OUT"))
    if not in_a_job and (dest == root or root not in dest.parents):
        fail("out_dir must be a directory inside the run directory, in %s" % said, out_dir=str(out))
    inputs = root / "inputs"
    if dest == inputs or inputs in dest.parents:
        fail("out_dir cannot be under inputs/", out_dir=str(out))
    if not (dest in places or any(place in dest.parents for place in places)):
        fail("out_dir must be a directory inside the run directory, in %s" % said, out_dir=str(out))
    return dest


def same_bytes(path, chunks, length):
    """Whether the file at `path` holds exactly these bytes (given as pieces, `length` in all), read in pieces."""
    try:
        if os.path.getsize(path) != length:
            return False
        with open(path, "rb") as fh:
            for piece in chunks():
                if fh.read(len(piece)) != bytes(piece):
                    return False
        return True
    except OSError:
        return False


def write_stream(out_dir, name, chunks, length):
    """Write one link structure, and never over another one.

    The name is the source file's name and the stream's, whole. When that file
    already holds different bytes (a jump list of the same name from another
    folder, or two names that differ only in characters a file name cannot
    carry) the next free numbered name is used instead. `chunks` is a function
    that gives the bytes as pieces, `length` their total: the structure is never
    held whole.
    """
    safe = re.sub(r"[^A-Za-z0-9._-]", "_", name) or "stream"
    if len(safe) > 200:
        # A file system refuses a name much longer than this. The digest keeps
        # the shortened name unique; the whole name stays in the output.
        safe = safe[:160] + "-" + hashlib.sha256(name.encode("utf-8")).hexdigest()[:16]
    target = os.path.join(out_dir, safe + ".lnk")
    n = 2
    # A name already taken, by a file or by a link, is never written through:
    # out_dir was checked, but a link left inside it (dangling ones included,
    # which os.path.exists calls absent) would take the write wherever it
    # points, inputs/ as well. Only a regular file is read to compare, and the
    # new file is created, never opened over something already there.
    while os.path.lexists(target):
        if os.path.isfile(target) and not os.path.islink(target) and same_bytes(target, chunks, length):
            return target
        target = os.path.join(out_dir, "%s-%d.lnk" % (safe, n))
        n += 1
    fd = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o644)
    with os.fdopen(fd, "wb") as fh:
        for piece in chunks():
            fh.write(piece)
    return target


def page_links(result, links):
    page = links.finish()
    result["links"] = links.page
    result["link_count"] = page["matched"]
    result.update(page)
    if page["truncated"]:
        result["links_truncated"] = True


def read_automatic(path, out_dir, limit):
    try:
        import olefile
    except ImportError as exc:
        return {"file": path, "error": "olefile is not installed: python3 -m pip install olefile",
                "reason": str(exc)}
    if not olefile.isOleFile(path):
        return {"file": path, "error": "not an OLE compound file; is it a customDestinations-ms?"}
    ole = olefile.OleFileIO(path)
    result = {"file": path, "format": "automaticDestinations-ms", "streams": [], "links": []}
    try:
        names = ["/".join(p) for p in ole.listdir()]
        result["stream_names"] = names
        by_stream = {}
        if "DestList" in names:
            size = ole.get_size("DestList") if hasattr(ole, "get_size") else None
            if size is not None and size > MAX_DESTLIST_BYTES:
                result["problems"] = ["the DestList stream is %d bytes, over the %d this tool reads whole; it was not parsed" % (size, MAX_DESTLIST_BYTES)]
            else:
                parsed = parse_destlist(ole.openstream("DestList").read())
                entries = LosslessPage("jumplist", [path, "entries", out_dir], limit)
                everything = parsed.pop("entries")
                for entry in everything:
                    entries.add(entry)
                by_stream = {e["stream"]: e for e in everything}
                result.update(parsed)
                kept = entries.finish()
                result["entries"] = entries.page
                result["entry_count"] = kept["matched"]
                result["entries_page"] = kept
        else:
            result["problems"] = ["there is no DestList stream in this file"]
        links = LosslessPage("jumplist", [path, "links", out_dir], limit)
        for name in names:
            if name == "DestList":
                continue
            # olefile holds an opened stream whole in memory, so a stream is sized from its directory entry first: a link
            # structure is small by nature, and one past MAX_STREAM_BYTES is named and left unread, never read whole.
            length = ole.get_size(name) if hasattr(ole, "get_size") else None
            if length is not None and length > MAX_STREAM_BYTES:
                result.setdefault("problems", []).append(
                    "the stream %s is %d bytes, over the %d this tool reads (olefile holds an opened stream in memory); it was not read"
                    % (name, length, MAX_STREAM_BYTES))
                links.add({"stream": name, "bytes": length, "is_link": None, "not_read": True})
                continue
            payload = ole.openstream(name).read()
            # The whole 20-byte header: the 4-byte size and the shell link CLSID.
            entry = {"stream": name, "bytes": len(payload), "is_link": payload[:20] == LNK_MAGIC}
            known = by_stream.get(name.lower())
            if known:
                entry["path"] = known["path"]
                entry["last_access"] = known["last_access"]
                entry["last_access_filetime"] = known["last_access_filetime"]
            if out_dir and entry["is_link"]:
                view = memoryview(payload)

                def pieces(view=view):
                    for at in range(0, len(view), 1 << 20):
                        yield view[at:at + (1 << 20)]
                entry["written_to"] = shown_path(write_stream(out_dir, os.path.basename(path) + "-" + name, pieces, len(payload)))
            links.add(entry)
        page_links(result, links)
    finally:
        ole.close()
    return result


def read_custom(path, out_dir, limit):
    result = {"file": path, "format": "customDestinations-ms", "links": [],
              "method": "carved: the file is split at every 20-byte link header; its own container structure is not parsed"}
    links = LosslessPage("jumplist", [path, "links", out_dir], limit)
    with open(path, "rb") as fh:
        size = os.fstat(fh.fileno()).st_size
        # Only the offsets are kept; the file is read a window at a time, and each structure is written from its own
        # range in pieces, so a very large file costs time, not memory.
        starts = lnk_starts(fh, size)
        for i, offset in enumerate(starts):
            length = (starts[i + 1] if i + 1 < len(starts) else size) - offset
            entry = {"offset": offset, "bytes": length, "is_link": True, "carved": True}
            if out_dir:
                def pieces(offset=offset, length=length):
                    fh.seek(offset)
                    left = length
                    while left:
                        piece = fh.read(min(left, 1 << 20))
                        if not piece:
                            return
                        left -= len(piece)
                        yield piece
                entry["written_to"] = shown_path(write_stream(out_dir, "%s-%04d" % (os.path.basename(path), i), pieces, length))
            links.add(entry)
    page_links(result, links)
    if not result["links"]:
        result["problems"] = ["no link structure header found in this file"]
    return result


def shown_path(written):
    """A written file as the answer names it: from the run directory when it is under it, else whole."""
    try:
        return str(Path(written).resolve().relative_to(Path.cwd().resolve()))
    except ValueError:
        return str(written)


def main():
    try:
        args = json.load(sys.stdin)
    except ValueError as exc:
        fail("arguments are not valid JSON", reason=str(exc))

    path = args.get("path")
    if not isinstance(path, str) or not path:
        fail("path is required: a jump list file or a directory of them")

    limit = args.get("limit", 500)
    if not isinstance(limit, int) or isinstance(limit, bool) or limit < 1:
        fail("limit must be a positive integer", limit=args.get("limit"))

    out_dir = args.get("out_dir")
    if out_dir is not None and (not isinstance(out_dir, str) or not out_dir):
        fail("out_dir must be a directory path under work/")
    if out_dir is not None:
        resolved = resolve_output(out_dir)
        try:
            resolved.mkdir(parents=True, exist_ok=True)
        except OSError as exc:
            fail("out_dir could not be created", out_dir=out_dir, reason=str(exc))
        out_dir = shown_path(resolved)

    targets = []
    not_attempted = []          # a FIFO, a socket, a device or a file that could not be examined: never opened
    if os.path.isdir(path):
        for root, dirs, names in os.walk(path):
            dirs.sort()                                   # the same order on every run
            for name in sorted(names):
                if name.lower().endswith(("destinations-ms",)):
                    full = os.path.join(root, name)
                    try:
                        regular = stat.S_ISREG(os.stat(full).st_mode)
                        kind = "not a regular file"
                    except OSError as exc:
                        regular, kind = False, "could not be examined: %s" % exc
                    if regular:
                        targets.append(full)
                    else:
                        not_attempted.append({"file": full, "reason": kind + ": it was not opened"})
    elif os.path.exists(path):
        try:
            regular = stat.S_ISREG(os.stat(path).st_mode)
        except OSError as exc:
            fail("the path could not be examined", path=path, reason=str(exc))
        if not regular:
            fail("path is not a regular file or a directory (a FIFO, a socket or a device is not opened)", path=path, not_attempted=1)
        targets = [path]
    else:
        fail("no such file or directory", path=path)
    if not targets and not not_attempted:
        fail("no jump list files under that directory", path=path)
    if not targets:
        fail("no jump list file under that directory could be opened", path=path, not_attempted=len(not_attempted),
             first_not_attempted=not_attempted[:5])

    files = []
    for target in targets:
        try:
            if target.lower().endswith("customdestinations-ms"):
                files.append(read_custom(target, out_dir, limit))
            else:
                files.append(read_automatic(target, out_dir, limit))
        except Exception as exc:                              # one bad file must not end the sweep
            files.append({"file": target, "error": "%s: %s" % (type(exc).__name__, exc)})
        app_id = os.path.basename(target).split(".")[0]
        if re.fullmatch(r"[0-9a-f]{16}", app_id):
            files[-1]["application_id"] = app_id

    failed = [f for f in files if f.get("error")]
    with_problems = [f for f in files if f.get("problems")]
    skipped = LosslessPage("jumplist", [path, "not_attempted", out_dir], limit)
    for item in not_attempted:
        skipped.add(item)
    skipped_page = skipped.finish()
    page = LosslessPage("jumplist", [path, "files", out_dir], limit)
    for f in files:
        page.add(f)
    kept = page.finish()
    status = "failed" if len(failed) == len(files) else "partial" if failed or with_problems or not_attempted else "complete"
    print(json.dumps({
        "parser": PARSER,
        "status": status,
        "files": page.page,
        "file_count": len(files),
        "files_failed": len(failed),
        "files_with_problems": len(with_problems),
        "first_failures": [{"file": f["file"], "error": f["error"]} for f in failed[:5]],
        "files_page": kept,
        "files_not_attempted": skipped_page["matched"],
        "not_attempted": skipped.page,
        "not_attempted_page": skipped_page,
        "note": "The DestList gives the index: entry number, host, last access, pin state and path. The target path, the volume "
                "serial and the three target timestamps come from the link structures, so run lnk_parse over what was written "
                "to out_dir before citing any of them. Access counters are not decoded. A customDestinations-ms is carved, not parsed.",
    }, indent=2))
    if status == "failed":
        raise SystemExit(1)


if __name__ == "__main__":
    try:
        main()
    except OSError as exc:
        fail("a file operation failed: %s" % exc, reason=type(exc).__name__)
