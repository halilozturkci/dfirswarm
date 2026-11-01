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

# BEGIN SHARED PLACE
# The same text is in every windows-forensics tool that keeps a result file (a windows-forensics test holds the copies equal).
# A result file that is there is never replaced by another result: a file of the same bytes is named again, any other result takes the next free
# <stem>-<n><suffix>. The name is taken first, with an exclusive create, so a result written at the same moment cannot be replaced either.
# Only regular files are ever compared: both names are opened with O_NONBLOCK and O_NOFOLLOW and looked at with fstat before a byte is
# read, so a FIFO, a device, a directory or a link at a name (the caller's own results_to, say) is another result's and cannot hold the
# tool. The comparing of one call has PLACE_COMPARE_SECONDS in all; past it an earlier result is taken as different and this one takes
# the next free name (nothing is replaced, but an identical rerun may then be named anew).
PLACE_COMPARE_SECONDS = 5   # all the comparing one call to place_without_replacing does; past it an earlier result is taken as different


def same_bytes(a, b, deadline=None):
    """Whether two files hold the same bytes (read in blocks, never whole). Each is opened without waiting and without following a link
    (O_NONBLOCK, O_NOFOLLOW) and looked at with fstat first: only two regular files of one size are read, so a FIFO, a device, a
    directory or a link at either name is never read (a FIFO would hold the tool for ever). Past `deadline` (a monotonic time) the
    answer is False."""
    flags = os.O_RDONLY | getattr(os, "O_NONBLOCK", 0) | getattr(os, "O_NOFOLLOW", 0)
    fa = fb = None
    try:
        fa = os.fdopen(os.open(str(a), flags), "rb")
        fb = os.fdopen(os.open(str(b), flags), "rb")
        sa, sb = os.fstat(fa.fileno()), os.fstat(fb.fileno())
        if (sa.st_mode & 0o170000) != 0o100000 or (sb.st_mode & 0o170000) != 0o100000 or sa.st_size != sb.st_size:
            return False
        while True:
            if deadline is not None and time.monotonic() > deadline:
                return False
            x, y = fa.read(1 << 20), fb.read(1 << 20)
            if x != y:
                return False
            if not x:
                return True
    except OSError:
        return False
    finally:
        for fh in (fa, fb):
            if fh is not None:
                fh.close()


def place_without_replacing(tmp, path):
    """Move the finished `tmp` to `path` and never replace what is there. The name is taken first, with an exclusive create, so a
    result written at the same moment cannot be replaced either. Returns the path that holds it.
    The comparing with earlier results has PLACE_COMPARE_SECONDS in all: past it an earlier result is taken as different and this
    one takes the next free name."""
    deadline = time.monotonic() + PLACE_COMPARE_SECONDS
    for n in range(1, 1000):
        candidate = path if n == 1 else path.with_name("%s-%d%s" % (path.stem, n, path.suffix))
        try:
            fd = os.open(str(candidate), os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o600)
        except FileExistsError:
            if not os.path.islink(candidate) and same_bytes(tmp, candidate, deadline):
                os.unlink(tmp)
                return candidate
            continue
        os.close(fd)
        os.replace(tmp, candidate)             # only replaces the empty file this call just made
        return candidate
    raise OSError("no free name beside %s" % path)
# END SHARED PLACE


# BEGIN SHARED PAGE
# The same text is in every windows-forensics tool that pages through LosslessPage (held equal by a windows-forensics test): LosslessPage replaces a file of the
# same name; this one places its finished file with place_without_replacing, and registers itself so that a stop can remove its temporary file.
PAGES = []


class NoReplacePage(LosslessPage):
    """LosslessPage whose finished file is placed without replacing an earlier file of the same name (a rerun with other limits, or one
    the time limit stopped, must not leave a smaller file where a larger one was)."""

    def __init__(self, tool, key, limit):
        super().__init__(tool, key, limit)
        PAGES.append(self)

    def finish(self) -> dict:
        result = {"matched": self.total, "returned": len(self.page), "truncated": self.total > len(self.page)}
        if self._out is not None:
            try:
                self._out.flush()
                os.fsync(self._out.fileno())
                self._out.close()
                assert self._tmp is not None
                placed = place_without_replacing(self._tmp, self.path)
            except OSError as exc:
                self._cannot_write(exc)
            self._tmp = None
            self.path = placed
            self.shown = self.shown[: len(self.shown) - len(Path(self.shown).name)] + placed.name
            result["all_results"] = self.shown
            result["all_results_format"] = "JSON Lines, one complete result per line"
        return result
# END SHARED PAGE


# BEGIN SHARED STOP
# The same text is in regkv, shellbags and amcache_apps (held equal by a windows-forensics test). SIGTERM, SIGINT and SIGHUP end the tool with JSON (status
# interrupted, exit 128 + the signal) and remove the temporary file a page was writing; the tool's own clock (set_deadline) is below the manifest's.
# The handlers are in as soon as the module has run as far as this block, with a minimal last word until main() installs the tool's own (only
# the start of the interpreter and the compiling of the file come before it). The first signal counts: a second one does nothing while the
# first is answered. print_answer holds the stop signals back while the answer is printed, so exactly one complete document is written
# (the ransomware tools print through it; the windows tools hold the signals in the emit of their boundary block, and carry this text unused).
import signal
import time

STOP = {"last_word": None, "deadline": None}


def set_deadline(seconds):
    STOP["deadline"] = time.monotonic() + seconds


def out_of_time():
    return STOP["deadline"] is not None and time.monotonic() > STOP["deadline"]


def _on_signal(signum, _frame):
    for other in (signal.SIGTERM, signal.SIGINT, signal.SIGHUP):
        signal.signal(other, signal.SIG_IGN)
    for page in list(globals().get("PAGES", ())):
        tmp = getattr(page, "_tmp", None)
        if tmp is not None:
            try:
                os.unlink(tmp)
            except OSError:
                pass
    last_word = STOP["last_word"]
    if last_word:
        try:
            last_word(signum)
        except Exception:  # noqa: BLE001 - a last word is best effort
            pass
    os._exit(128 + signum)


def install_signal_handlers(last_word=None):
    STOP["last_word"] = last_word
    for signum in (signal.SIGTERM, signal.SIGINT, signal.SIGHUP):
        signal.signal(signum, _on_signal)


def interrupted_answer(signum, **extra):
    print(json.dumps({"error": "stopped by signal %d before the answer was complete" % signum, "status": "interrupted",
                      "status_basis": "the tool was stopped by signal %d; nothing it had read is an answer" % signum,
                      "signal": signum, **extra}), flush=True)


def print_answer(answer, **dumps_kwargs):
    """Print the answer with the stop signals held back: a signal that came in the middle of the write would end the process there, with the
    answer cut. The tool ends by itself right after, so a signal that is held is not lost for good."""
    try:
        signal.pthread_sigmask(signal.SIG_BLOCK, {signal.SIGTERM, signal.SIGINT, signal.SIGHUP})
    except (AttributeError, ValueError, OSError):
        pass
    STOP["last_word"] = None
    print(json.dumps(answer, **dumps_kwargs))


install_signal_handlers(lambda signum: interrupted_answer(signum))
# END SHARED STOP


FILETIME_EPOCH = datetime.datetime(1601, 1, 1, tzinfo=datetime.timezone.utc)
LNK_MAGIC = bytes([0x4C, 0x00, 0x00, 0x00]) + binascii.unhexlify("0114020000000000c000000000000046")
DESTLIST_HEADER = 32
PARSER = "jumplist/5"
DEADLINE_SECONDS = 114            # the manifest allows 120: the walk, the files and the streams stop here, so that the pages are placed and the answer printed before the harness ends it
MAX_LIMIT = 10000                 # the largest bound on the rows shown inline; the whole is in the files the answers name
INLINE_STREAM_NAMES = 200         # the stream names of a compound file shown inline (every stream is a row of the links file)
PROGRESS = {"file": 0}
BUDGET = {"entries": 500, "links": 500}   # the bound on the inline rows of each kind over the WHOLE answer (not per file); set from limit in main()
MAX_PATH_CHARS = 32767
# A DestList stream is read whole before it is parsed; a real one is a few hundred
# kilobytes at most, so a stream past this is refused by name instead of held in memory.
MAX_DESTLIST_BYTES = 64 * 1024 * 1024
# Every entry read is a record of about fifteen fields that is kept until the file's rows are written; Windows keeps a
# few thousand entries at most, so a stream that holds more than this is read to this many entries and the rest is
# named by where it starts, never decoded one dictionary at a time into memory.
MAX_DESTLIST_ENTRIES = 50_000
# olefile holds an opened stream whole in memory; a link structure is small by nature, so a stream past this is named and not read.
MAX_STREAM_BYTES = 32 * 1024 * 1024
# The fixed part of an entry, the offset of its path length (a 16-bit count of UTF-16
# characters) and the bytes after the path, by DestList version.
LAYOUTS = {
    1: {"fixed": 114, "chars_at": 0x70, "trailer": 0},
    3: {"fixed": 130, "chars_at": 0x80, "trailer": 4},
    4: {"fixed": 130, "chars_at": 0x80, "trailer": 4},
}


class ClockStop(Exception):
    """The tool's own clock ran out inside a file."""


def drop_pages():
    """Remove the temporary files of the pages that were being written (the STOP block does the same on a signal)."""
    for page in list(PAGES):
        tmp = getattr(page, "_tmp", None)
        if tmp is not None:
            try:
                os.unlink(tmp)
            except OSError:
                pass
            page._tmp = None


def fail(message, **extra):
    drop_pages()
    print_answer({"error": message, "status": "failed", "status_basis": "the tool stopped with an error and read no result (see error)", **extra})
    raise SystemExit(1)


def last_word(signum):
    interrupted_answer(signum, file_index=PROGRESS["file"])


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
        if not (len(out["entries"]) & 1023) and out_of_time():
            raise ClockStop()
        if len(out["entries"]) >= MAX_DESTLIST_ENTRIES:
            out["entries_not_read_from"] = offset
            out["problems"].append(
                "the stream holds more than the %d entries this tool reads: the first %d are read, and the rest (from stream offset %d, %d bytes) is not"
                % (MAX_DESTLIST_ENTRIES, MAX_DESTLIST_ENTRIES, offset, len(data) - offset))
            break
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
    if count and len(out["entries"]) != count and "entries_not_read_from" not in out:
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
        if out_of_time():
            raise ClockStop()
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


def same_stream_bytes(path, chunks, length):
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
        safe = safe[:160] + "-" + hashlib.sha256(name.encode("utf-8", "surrogatepass")).hexdigest()[:16]
    target = os.path.join(out_dir, safe + ".lnk")
    n = 2
    # A name already taken, by a file or by a link, is never written through:
    # out_dir was checked, but a link left inside it (dangling ones included,
    # which os.path.exists calls absent) would take the write wherever it
    # points, inputs/ as well. Only a regular file is read to compare, and the
    # new file is created, never opened over something already there.
    while os.path.lexists(target):
        if os.path.isfile(target) and not os.path.islink(target) and same_stream_bytes(target, chunks, length):
            return target
        target = os.path.join(out_dir, "%s-%d.lnk" % (safe, n))
        n += 1
    fd = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o600)    # a link keeps its arguments and strings
    with os.fdopen(fd, "wb") as fh:
        for piece in chunks():
            fh.write(piece)
    return target


def page_links(result, links):
    page = links.finish()
    result["links"] = links.page
    BUDGET["links"] -= len(links.page)
    result["link_count"] = page["matched"]
    result.update(page)
    if page["truncated"]:
        result["links_truncated"] = True


def inline_rows(kind):
    """The inline page a file's rows of this kind may take: what is left of the bound on the inline rows of that kind over the whole answer. A page is never
    smaller than one row (a page of none does not exist); the rest of a file's rows are in the file the answer names."""
    return max(1, BUDGET[kind])


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
    links = None
    try:
        names = ["/".join(p) for p in ole.listdir()]
        result["stream_names"] = names[:INLINE_STREAM_NAMES]
        if len(names) > INLINE_STREAM_NAMES:
            result["stream_names_not_shown"] = len(names) - INLINE_STREAM_NAMES
        by_stream = {}
        try:
            if "DestList" in names:
                size = ole.get_size("DestList") if hasattr(ole, "get_size") else None
                if size is not None and size > MAX_DESTLIST_BYTES:
                    result["problems"] = ["the DestList stream is %d bytes, over the %d this tool reads whole; it was not parsed" % (size, MAX_DESTLIST_BYTES)]
                else:
                    parsed = parse_destlist(ole.openstream("DestList").read())
                    entries = NoReplacePage("jumplist", [path, "entries", out_dir], inline_rows("entries"))
                    everything = parsed.pop("entries")
                    for entry in everything:
                        entries.add(entry)
                    by_stream = {e["stream"]: e for e in everything}
                    result.update(parsed)
                    kept = entries.finish()
                    result["entries"] = entries.page
                    BUDGET["entries"] -= len(entries.page)
                    result["entry_count"] = kept["matched"]
                    result["entries_page"] = kept
            else:
                result["problems"] = ["there is no DestList stream in this file"]
            links = NoReplacePage("jumplist", [path, "links", out_dir], inline_rows("links"))
            for name in names:
                if name == "DestList":
                    continue
                if out_of_time():
                    raise ClockStop()
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
        except ClockStop:
            result.setdefault("problems", []).append("the tool's own clock (%d s) ran out in this file: the streams after this point were not read" % DEADLINE_SECONDS)
            result["stopped_by_time_limit"] = True
        if links is None:
            links = NoReplacePage("jumplist", [path, "links", out_dir], 1)
        page_links(result, links)
    finally:
        ole.close()
    return result


def read_custom(path, out_dir, limit):
    result = {"file": path, "format": "customDestinations-ms", "links": [],
              "method": "carved: the file is split at every 20-byte link header; its own container structure is not parsed"}
    links = NoReplacePage("jumplist", [path, "links", out_dir], inline_rows("links"))
    with open(path, "rb") as fh:
        size = os.fstat(fh.fileno()).st_size
        # Only the offsets are kept; the file is read a window at a time, and each structure is written from its own
        # range in pieces, so a very large file costs time, not memory.
        try:
            starts = lnk_starts(fh, size)
            for i, offset in enumerate(starts):
                if not (i & 63) and out_of_time():
                    raise ClockStop()
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
        except ClockStop:
            result["problems"] = ["the tool's own clock (%d s) ran out in this file: the link structures after this point were not listed or written" % DEADLINE_SECONDS]
            result["stopped_by_time_limit"] = True
    page_links(result, links)
    if not result["links"] and "problems" not in result:
        result["problems"] = ["no link structure header found in this file"]
    return result


def shown_path(written):
    """A written file as the answer names it: from the run directory when it is under it, else whole."""
    try:
        return str(Path(written).resolve().relative_to(Path.cwd().resolve()))
    except ValueError:
        return str(written)


def main():
    set_deadline(DEADLINE_SECONDS)
    install_signal_handlers(last_word)
    try:
        args = json.load(sys.stdin)
    except ValueError as exc:
        fail("arguments are not valid JSON", reason=str(exc))
    if not isinstance(args, dict):
        fail("arguments must be a JSON object")

    path = args.get("path")
    if not isinstance(path, str) or not path:
        fail("path is required: a jump list file or a directory of them")

    limit = args.get("limit", 500)
    if isinstance(limit, bool) or not isinstance(limit, int) or not 1 <= limit <= MAX_LIMIT:
        fail("limit must be a whole number from 1 to %d (the one bound on the rows shown inline; the whole is in the files the answer names)" % MAX_LIMIT)
    BUDGET["entries"] = BUDGET["links"] = limit

    out_dir = args.get("out_dir")
    if out_dir is not None and (not isinstance(out_dir, str) or not out_dir):
        fail("out_dir must be a directory path under work/")
    write_links = args.get("write_links", False)
    if not isinstance(write_links, bool):
        fail("write_links must be true or false")
    if write_links and out_dir is None:
        fail("write_links needs out_dir: the directory the link structures are written to")
    if out_dir is not None and not write_links:
        fail("out_dir needs write_links: true. The link structures are written whole, and a link keeps its arguments and strings, so writing them is secret "
             "output and is asked for by name. Nothing was written.")
    if write_links and os.environ.get("SECRET_OUTPUT") != "1":
        fail("write_links is refused: the link structures keep their arguments and strings, and are written only in a job the harness runs as secret output "
             "(job_run with secret_output: true). Nothing was written.")
    if out_dir is not None:
        resolved = resolve_output(out_dir)
        try:
            resolved.mkdir(parents=True, exist_ok=True)
        except OSError as exc:
            fail("out_dir could not be created", out_dir=out_dir, reason=str(exc))
        out_dir = shown_path(resolved)

    targets = []
    not_attempted = []          # a FIFO, a socket, a device or a file that could not be examined: never opened
    walk_stopped = False
    if os.path.isdir(path):
        for root, dirs, names in os.walk(path):
            if out_of_time():
                walk_stopped = True
                break
            dirs.sort()                                   # the same order on every run
            for name in sorted(names):
                if out_of_time():
                    walk_stopped = True
                    break
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
    if not targets and not not_attempted and not walk_stopped:
        fail("no jump list files under that directory", path=path)
    if not targets and not walk_stopped:
        fail("no jump list file under that directory could be opened", path=path, not_attempted=len(not_attempted),
             first_not_attempted=not_attempted[:5])

    files = []
    not_read = 0
    for index, target in enumerate(targets):
        if out_of_time():
            not_read = len(targets) - index
            break
        PROGRESS["file"] = index
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
    stopped_files = [f for f in files if f.get("stopped_by_time_limit")]
    skipped = NoReplacePage("jumplist", [path, "not_attempted", out_dir], limit)
    for item in not_attempted:
        skipped.add(item)
    skipped_page = skipped.finish()
    page = NoReplacePage("jumplist", [path, "files", out_dir], limit)
    for f in files:
        page.add(f)
    kept = page.finish()
    reasons = []
    if walk_stopped or not_read or stopped_files:
        reasons.append("the tool's own clock (%d s) ran out: %s" % (DEADLINE_SECONDS, "; ".join(filter(None, [
            "the directory walk was cut short" if walk_stopped else "",
            "%d file(s) were not read" % not_read if not_read else "",
            "%d file(s) were read only in part" % len(stopped_files) if stopped_files else ""]))))
    if failed:
        reasons.append("%d file(s) failed" % len(failed))
    if with_problems:
        reasons.append("%d file(s) name a problem" % len(with_problems))
    if not_attempted:
        reasons.append("%d file(s) were not opened (a pipe, a socket, a device or a file that could not be examined)" % len(not_attempted))
    if len(failed) == len(files) and files:
        status = "failed"
        basis = "every file failed (%d)" % len(files)
    elif not files:
        status = "partial"
        basis = reasons[0] if reasons else "no file was read"
    else:
        status = "partial" if reasons else "complete"
        basis = "; ".join(reasons) if reasons else "every file was read to its end, every DestList and every stream was listed, and no problem is named"
    print_answer({
        "parser": PARSER,
        "status": status,
        "status_basis": basis,
        "stopped_by_time_limit": bool(walk_stopped or not_read or stopped_files),
        "files": page.page,
        "file_count": len(files),
        "files_failed": len(failed),
        "files_with_problems": len(with_problems),
        "files_not_read_for_time": not_read,
        "first_failures": [{"file": f["file"], "error": f["error"]} for f in failed[:5]],
        "files_page": kept,
        "files_not_attempted": skipped_page["matched"],
        "not_attempted": skipped.page,
        "not_attempted_page": skipped_page,
        "inline_rows_bound": limit,
        "note": "The DestList gives the index: entry number, host, last access, pin state and path. The target path, the volume "
                "serial and the three target timestamps come from the link structures, so run lnk_parse over what was written "
                "to out_dir before citing any of them. Access counters are not decoded. A customDestinations-ms is carved, not parsed. "
                "The entries and the links shown inline are each bounded by limit over the whole answer, not per file; every row is in the file its page names.",
    }, indent=2)
    if status == "failed":
        raise SystemExit(1)


if __name__ == "__main__":
    try:
        main()
    except SystemExit:
        raise
    except OSError as exc:
        fail("a file operation failed: %s" % exc, reason=type(exc).__name__)
    except Exception as exc:                                  # whatever hostile input does, the answer is JSON
        drop_pages()
        print_answer({"error": "the read failed", "status": "failed", "status_basis": "the tool stopped with an unexpected error",
                      "reason": "%s: %s" % (type(exc).__name__, exc)})
        sys.exit(1)
