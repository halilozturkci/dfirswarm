#!/usr/bin/env python3
"""Parse an NTFS change journal ($UsnJrnl:$J) into records.

Asked for in two of the measured cases and forged badly in one. The journal
is the closest thing NTFS has to an audit log of file names: every create,
rename, write and delete, with a timestamp and the reason bits that say which.

$J is sparse. Extracted with icat, its front is a run of zeros as long as
everything the journal has already let go (tens of megabytes, or gigabytes on
a volume that has lived), and the live records sit at the end. So the file is
mapped, never read whole; zeros are skipped in steps of up to a megabyte, at
the front and wherever they pad a page inside the live part; and the output
says where the first record was and how many zero bytes it passed.

Every record is read. `name` narrows what is returned, never what is read:
records_read says how many records the journal holds, so a filter that
matched nothing reads as that and not as an empty journal. `name` is a
case-insensitive regex over the file name, as in mft_records and indx_carve
(a|b for either); a run passed an alternation to the substring match this
tool used to do, and read "0 records" as "the journal is empty".

USN_RECORD_V2 (the usual one):
  0x00  4  RecordLength
  0x04  2  MajorVersion (2)
  0x06  2  MinorVersion
  0x08  8  FileReferenceNumber
  0x10  8  ParentFileReferenceNumber
  0x18  8  Usn
  0x20  8  TimeStamp (FILETIME)
  0x28  4  Reason
  0x2C  4  SourceInfo
  0x30  4  SecurityId
  0x34  4  FileAttributes
  0x38  2  FileNameLength
  0x3A  2  FileNameOffset

USN_RECORD_V3 (ReFS, and NTFS with 128-bit file ids): the two references are
16 bytes each, so everything after them is 0x10 further on (Usn at 0x28, the
name's length and offset at 0x48 and 0x4A).

USN_RECORD_V4 (range tracking, written after a v3 record): the two 16-byte
references, Usn at 0x28, Reason 0x30, SourceInfo 0x34, RemainingExtents 0x38,
NumberOfExtents 0x3C, ExtentSize 0x3E, then the extents (offset and length,
8 bytes each). It has no name and no timestamp.

A record's length is a multiple of 8 and records start on 8-byte boundaries.

Every decoded field is kept: both file references with their sequence numbers (`file_sequence`,
`parent_sequence`), `source_info`, `security_id`, the attributes as names and as the raw word
(`attributes_raw`), the reason as names and raw (`reason_raw`), and the timestamp as ISO 8601 UTC
with seven fractional digits and as the raw FILETIME (`timestamp_filetime`, a decimal string). What is not a
record is accounted for in bytes, not in steps: `unrecognised_bytes` after the first record (its
ranges are a page, `unrecognised_ranges`), and `prefix_unrecognised_bytes` before it, apart from the
zero bytes the sparse front is made of.

A V4 record carries no name. A `name` filter matches names, so it leaves V4 records out; they are counted
(`nameless_excluded_by_filter`) and `include_nameless: true` keeps them.
"""
import datetime
import json
import mmap
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
        # The hidden temp file goes first: a page that cannot be written leaves nothing behind (a full disk, a quota).
        out, self._out = self._out, None
        try:
            if out is not None:
                out.close()
        except BaseException:
            pass
        try:
            if self._tmp is not None:
                os.unlink(self._tmp)
        except OSError:
            pass
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
# <stem>-<n><suffix>. A result written at the same moment cannot be replaced either: taking a name fails when it is there.
# Only regular files are ever compared: both names are opened with O_NONBLOCK and O_NOFOLLOW and looked at with fstat before a byte is
# read, so a FIFO, a device, a directory or a link at a name (the caller's own results_to, say) is another result's and cannot hold the
# tool. The comparing of one call has PLACE_COMPARE_SECONDS in all; past it an earlier result is taken as different and this one takes
# the next free name (nothing is replaced, but an identical rerun may then be named anew).
# The name is taken with a hard link of the finished file, so it never holds an empty file, whatever stops the tool and when (SIGKILL
# included). Where the file system refuses the link, the name is taken with an exclusive create and the file is moved over it: a stop
# that unwinds (an exception) takes the empty name back while it is still the empty file this call made; a stop that ends the process
# without unwinding (SIGKILL, the handlers of the STOP block) between the create and the move leaves the empty name, and the next run takes -2.
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


def _take_name(tmp, candidate):
    """Give the finished `tmp` the name `candidate` if it is free, and say whether it now has it (False: the name is taken, by a file, a
    link, a FIFO or a directory). The name is taken with a hard link, so it never holds an empty file; where the file system refuses the
    link it is taken with an exclusive create and the file is moved over it, and a stop that unwinds in between takes the empty name back."""
    try:
        os.link(tmp, candidate)
    except FileExistsError:
        return False
    except OSError:
        pass                                   # no hard links here: the older way, below
    else:
        try:
            os.unlink(tmp)
        except OSError:
            pass                               # the hidden name stays beside the placed file; the stop path of the page removes it
        return True
    fd = made = None
    try:
        fd = os.open(str(candidate), os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o600)
        made = os.fstat(fd)
        closing, fd = fd, None
        os.close(closing)
        os.replace(tmp, candidate)             # only replaces the empty file this call just made
        return True
    except FileExistsError:
        return False
    except BaseException:
        try:
            if made is None and fd is not None:
                made = os.fstat(fd)
        except OSError:
            pass
        try:
            if fd is not None:
                os.close(fd)
        except OSError:
            pass
        try:
            now = os.lstat(candidate)
            if made is not None and (now.st_mode & 0o170000) == 0o100000 and now.st_size == 0 and (now.st_dev, now.st_ino) == (made.st_dev, made.st_ino):
                os.unlink(candidate)           # the empty name this call took is not left behind
        except OSError:
            pass
        raise


def place_without_replacing(tmp, path):
    """Move the finished `tmp` to `path` and never replace what is there. A name that is taken (by a file, a link, a FIFO or a directory) is
    left as it is: a regular file of the same bytes is named again, any other result takes the next free <stem>-<n><suffix>. Returns the
    path that holds it. The comparing with earlier results has PLACE_COMPARE_SECONDS in all: past it an earlier result is taken as
    different and this one takes the next free name."""
    deadline = time.monotonic() + PLACE_COMPARE_SECONDS
    for n in range(1, 1000):
        candidate = path if n == 1 else path.with_name("%s-%d%s" % (path.stem, n, path.suffix))
        if _take_name(tmp, candidate):
            return candidate
        if not os.path.islink(candidate) and same_bytes(tmp, candidate, deadline):
            os.unlink(tmp)
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
# The same text is in every tool that carries this block (tests/pack-shared-stop.test.ts holds the copies equal). SIGTERM, SIGINT and SIGHUP end the tool with JSON
# (status failed with interrupted true: a stop is not a status, the statuses are complete, partial and failed; exit 128 + the signal) and remove the temporary file a page was writing; the tool's own clock (set_deadline) is below the manifest's.
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
    print(json.dumps({"error": "stopped by signal %d before the answer was complete" % signum, "status": "failed", "interrupted": True,
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

REASONS = [
    (0x00000001, "DATA_OVERWRITE"), (0x00000002, "DATA_EXTEND"), (0x00000004, "DATA_TRUNCATION"),
    (0x00000010, "NAMED_DATA_OVERWRITE"), (0x00000020, "NAMED_DATA_EXTEND"), (0x00000040, "NAMED_DATA_TRUNCATION"),
    (0x00000100, "FILE_CREATE"), (0x00000200, "FILE_DELETE"), (0x00000400, "EA_CHANGE"),
    (0x00000800, "SECURITY_CHANGE"), (0x00001000, "RENAME_OLD_NAME"), (0x00002000, "RENAME_NEW_NAME"),
    (0x00004000, "INDEXABLE_CHANGE"), (0x00008000, "BASIC_INFO_CHANGE"), (0x00010000, "HARD_LINK_CHANGE"),
    (0x00020000, "COMPRESSION_CHANGE"), (0x00040000, "ENCRYPTION_CHANGE"), (0x00080000, "OBJECT_ID_CHANGE"),
    (0x00100000, "REPARSE_POINT_CHANGE"), (0x00200000, "STREAM_CHANGE"), (0x00400000, "TRANSACTED_CHANGE"),
    (0x00800000, "INTEGRITY_CHANGE"), (0x80000000, "CLOSE"),
]

ATTRIBUTES = [
    (0x00000001, "READONLY"), (0x00000002, "HIDDEN"), (0x00000004, "SYSTEM"), (0x00000010, "DIRECTORY"),
    (0x00000020, "ARCHIVE"), (0x00000080, "NORMAL"), (0x00000100, "TEMPORARY"), (0x00000200, "SPARSE_FILE"),
    (0x00000400, "REPARSE_POINT"), (0x00000800, "COMPRESSED"), (0x00001000, "OFFLINE"),
    (0x00004000, "ENCRYPTED"),
]


# The fixed part of each version: a record shorter than this is not one.
HEAD = {2: 0x3C, 3: 0x4C, 4: 0x40}
# Where each version keeps the name's length and offset.
NAME_AT = {2: 0x38, 3: 0x48}
MAX_RECORD = 0x10000
ZERO_STEP = 1 << 20


PARSER = "usn_journal/6"
DEADLINE_SECONDS = 114            # the manifest allows 120: the sweep stops here, so that the pages are placed and the answer printed before the harness ends it
MAX_LIMIT = 10000                 # the largest inline page; the whole result is in the file the answer names
MAX_NAME = 500                    # the longest name filter
PATTERN_SECONDS = 0.5             # one name is tested against the caller's expression for at most this long
PROGRESS = {"read": 0, "offset": 0}


class PatternTooSlow(Exception):
    pass


def _pattern_alarm(_signum, _frame):
    raise PatternTooSlow()


def matches(pattern, text):
    """Whether the caller's expression matches `text`, for at most PATTERN_SECONDS (the re module looks at signals while it matches, so an
    expression that takes exponential time on a name is stopped instead of outrunning the tool's clock)."""
    signal.signal(signal.SIGALRM, _pattern_alarm)
    signal.setitimer(signal.ITIMER_REAL, PATTERN_SECONDS)
    try:
        return pattern.search(text) is not None
    finally:
        signal.setitimer(signal.ITIMER_REAL, 0)


class ClockStop(Exception):
    """The tool's own clock ran out inside a skip over bytes that are not a record."""


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
    interrupted_answer(signum, records_read=PROGRESS["read"], offset_reached=PROGRESS["offset"])


def flags(value, table):
    return [name for bit, name in table if value & bit]


def filetime(value):
    """ISO 8601 UTC with seven fractional digits, by integer arithmetic; None for 0 or past year 9999."""
    if value <= 0:
        return None
    try:
        whole, ticks = divmod(value, 10_000_000)
        return (FILETIME_EPOCH + datetime.timedelta(seconds=whole)).strftime("%Y-%m-%dT%H:%M:%S") + ".%07dZ" % ticks
    except (OverflowError, ValueError):
        return None


def next_nonzero(data, offset, end):
    """The first 8-byte boundary at or after `offset` whose 8 bytes are not all
    zero, or `end`. The look ahead doubles up to a megabyte: a record starts
    within the first few bytes, and the sparse front of $J, which can be
    gigabytes, would take minutes 8 bytes at a time."""
    step = 64
    while offset < end:
        if out_of_time():
            raise ClockStop(offset)
        chunk = data[offset:min(offset + step, end)]
        rest = chunk.lstrip(b"\0")
        if rest:
            return offset + ((len(chunk) - len(rest)) & ~7)
        offset += len(chunk)
        step = min(step * 2, ZERO_STEP)
    return end


def reference(raw):
    """A 128-bit file id: the NTFS reference (entry and sequence) when the high
    half is zero, as it is on NTFS; the whole id, in hex, either way."""
    low, high = struct.unpack("<QQ", raw)
    out = {"id": "%016x%016x" % (high, low)}
    if high == 0:
        out["entry"] = low & 0x0000FFFFFFFFFFFF
        out["sequence"] = low >> 48
    return out


def record_at(data, offset, end):
    """The record at `offset` as a dict with its length, or None when the bytes
    there are not a plausible v2, v3 or v4 record."""
    if offset + 8 > end:
        return None
    length, major, minor = struct.unpack_from("<IHH", data, offset)
    head = HEAD.get(major)
    if head is None or not (head <= length <= MAX_RECORD) or length % 8 or offset + length > end:
        return None
    if major == 4:
        ref, parent = reference(data[offset + 0x08:offset + 0x18]), reference(data[offset + 0x18:offset + 0x28])
        usn, reason, source, remaining, count, size = struct.unpack_from("<QIIIHH", data, offset + 0x28)
        if size != 16 or 0x40 + count * size > length:
            return None
        extents = [dict(zip(("offset", "length"), struct.unpack_from("<qq", data, offset + 0x40 + i * 16)))
                   for i in range(count)]
        return {"length": length, "row": {
            "version": 4, "minor_version": minor, "usn": usn, "name": None,
            "file_reference": ref.get("entry"), "file_sequence": ref.get("sequence"), "file_id": ref["id"],
            "parent_reference": parent.get("entry"), "parent_sequence": parent.get("sequence"), "parent_id": parent["id"],
            "reason": flags(reason, REASONS), "reason_raw": reason, "source_info": source,
            "extents": extents, "remaining_extents": remaining, "offset": offset,
        }}
    name_len, name_off = struct.unpack_from("<HH", data, offset + NAME_AT[major])
    if name_off < head or name_off + name_len > length or name_len % 2:
        return None
    name = data[offset + name_off:offset + name_off + name_len].decode("utf-16-le", "replace")
    if major == 2:
        ref, parent, usn, stamp, reason, source, sec, attrs = struct.unpack_from("<QQQqIIII", data, offset + 0x08)
        row = {"version": 2, "minor_version": minor, "usn": usn, "timestamp": filetime(stamp), "timestamp_filetime": str(stamp), "name": name,
               "file_reference": ref & 0x0000FFFFFFFFFFFF, "file_sequence": ref >> 48,
               "parent_reference": parent & 0x0000FFFFFFFFFFFF, "parent_sequence": parent >> 48}
    else:
        ref, parent = reference(data[offset + 0x08:offset + 0x18]), reference(data[offset + 0x18:offset + 0x28])
        usn, stamp, reason, source, sec, attrs = struct.unpack_from("<QqIIII", data, offset + 0x28)
        row = {"version": 3, "minor_version": minor, "usn": usn, "timestamp": filetime(stamp), "timestamp_filetime": str(stamp), "name": name,
               "file_reference": ref.get("entry"), "file_sequence": ref.get("sequence"), "file_id": ref["id"],
               "parent_reference": parent.get("entry"), "parent_sequence": parent.get("sequence"), "parent_id": parent["id"]}
    row.update({"reason": flags(reason, REASONS), "reason_raw": reason, "source_info": source, "security_id": sec,
                "attributes": flags(attrs, ATTRIBUTES), "attributes_raw": attrs, "offset": offset})
    return {"length": length, "row": row}


def unsupported_header(data, offset, end):
    """A record whose major version this tool does not read, when it still has the shape of one: a length that is a
    multiple of 8 and fits, and after it the end of the journal, zeros or a record this tool reads. Returns its
    offset, versions and length, or None (then the bytes are stepped over 8 at a time, as unrecognised)."""
    if offset + 8 > end:
        return None
    length, major, minor = struct.unpack_from("<IHH", data, offset)
    if major in HEAD or length % 8 or not (0x20 <= length <= MAX_RECORD) or offset + length > end:
        return None
    after = offset + length
    if after < end and any(data[after:min(after + 8, end)]) and record_at(data, after, end) is None:
        return None
    return {"offset": offset, "major_version": major, "minor_version": minor, "length": length}


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
        fail("path is required: the $J stream, extracted with icat")
    limit = args.get("limit", 500)
    if isinstance(limit, bool) or not isinstance(limit, int) or not 1 <= limit <= MAX_LIMIT:
        fail("limit must be a whole number from 1 to %d (the inline page; the whole result is in the file the answer names)" % MAX_LIMIT)
    name_filter = args.get("name")
    if name_filter is not None and (not isinstance(name_filter, str) or len(name_filter) > MAX_NAME):
        fail("name must be a string of at most %d characters: a case-insensitive regex over the file name" % MAX_NAME)
    include_nameless = args.get("include_nameless", False)
    if not isinstance(include_nameless, bool):
        fail("include_nameless must be true or false")
    pattern = None
    if name_filter:
        try:
            pattern = re.compile(name_filter, re.I)
        except re.error as exc:
            fail("name is not a valid regex", reason=str(exc))

    try:
        if not stat.S_ISREG(os.stat(path).st_mode):
            fail("not a regular file: it is not opened", path=path, not_attempted=1)
        fh = open(path, "rb")
        size = os.fstat(fh.fileno()).st_size
    except OSError as exc:
        fail("could not read the journal", path=path, reason=str(exc))
    if size < HEAD[2]:
        fail("too short to hold a record", bytes=size)
    try:
        data = mmap.mmap(fh.fileno(), 0, access=mmap.ACCESS_READ)
    except (OSError, ValueError) as exc:
        fail("could not map the journal", path=path, reason=str(exc))

    records = NoReplacePage("usn_journal", [path, name_filter, include_nameless], limit)
    unrecognised = NoReplacePage("usn_journal-unrecognised", [path], 40)
    unsupported = NoReplacePage("usn_journal-unsupported", [path], 40)
    unsupported_by_major = {}
    unsupported_bytes = 0
    versions = {}
    start = None
    read = zeros = 0
    unrecognised_bytes = prefix_unrecognised = nameless_excluded = 0
    open_range = None
    offset = 0
    stopped = None
    while offset < size:
        if out_of_time():
            stopped = "the tool's own clock (%d s) ran out" % DEADLINE_SECONDS
            break
        PROGRESS["read"], PROGRESS["offset"] = read, offset
        # The sparse front, and the zeros that pad the end of each page.
        try:
            ahead = next_nonzero(data, offset, size)
        except ClockStop as stop:
            zeros += stop.args[0] - offset
            offset = stop.args[0]
            stopped = "the tool's own clock (%d s) ran out" % DEADLINE_SECONDS
            break
        zeros += ahead - offset
        offset = ahead
        if offset >= size:
            break
        found = record_at(data, offset, size)
        if found is None:
            # Before the first record this is the search for it; after it, a
            # stretch that is not a record, counted in bytes and kept as a range.
            step = min(8, size - offset)
            odd = unsupported_header(data, offset, size)
            if odd is not None:
                step = odd["length"]
                unsupported.add(odd)
                unsupported_bytes += step
                unsupported_by_major[str(odd["major_version"])] = unsupported_by_major.get(str(odd["major_version"]), 0) + 1
            if start is not None:
                unrecognised_bytes += step
                if open_range is not None and open_range[0] + open_range[1] == offset:
                    open_range[1] += step
                else:
                    if open_range is not None:
                        unrecognised.add({"offset": open_range[0], "bytes": open_range[1]})
                    open_range = [offset, step]
            else:
                prefix_unrecognised += step
            offset += step if odd is not None else 8
            continue
        if open_range is not None:
            unrecognised.add({"offset": open_range[0], "bytes": open_range[1]})
            open_range = None
        if start is None:
            start = offset
        row = found["row"]
        read += 1
        versions[str(row["version"])] = versions.get(str(row["version"]), 0) + 1
        if pattern is None:
            records.add(row)
        elif row["name"] is None:
            if include_nameless:
                records.add(row)
            else:
                nameless_excluded += 1
        else:
            try:
                hit = matches(pattern, row["name"])
            except PatternTooSlow:
                stopped = ("the name expression took more than %s s on the name of the record at byte %d, so the sweep stopped there; use a simpler expression"
                           % (PATTERN_SECONDS, offset))
                break
            if hit:
                records.add(row)
        offset += found["length"]
    if open_range is not None:
        unrecognised.add({"offset": open_range[0], "bytes": open_range[1]})
    data.close()
    fh.close()

    if start is None and not stopped:
        fail("no USN record (v2, v3 or v4) found", bytes=size, zero_bytes=zeros,
             unsupported_version_records=sum(unsupported_by_major.values()), unsupported_versions=unsupported_by_major,
             hint="is this the $J stream rather than $Max? A record of another major version is listed under unsupported_versions, not read.")

    page = records.finish()
    unsupported_page = unsupported.finish()
    unrecognised_page = unrecognised.finish()
    if stopped:
        basis = "%s at byte %d of %d, after %d records: the rest of the journal was not read" % (stopped, offset, size, read)
    else:
        basis = ("every byte of the %d-byte journal was read (%d records, %d zero bytes skipped, %d bytes that are not a record counted under unrecognised_bytes)"
                 % (size, read, zeros, unrecognised_bytes + prefix_unrecognised))
    result = {
        "path": path,
        "status": "partial" if stopped else "complete",
        "status_basis": basis,
        "stopped_by_time_limit": bool(stopped),
        "bytes": size,
        "first_record_offset": start,
        "zero_bytes_skipped": zeros,
        "records_read": read,
        "records_by_version": versions,
        "name_filter": name_filter,
        "records": records.page,
        "record_count": page["matched"],
        "unrecognised_bytes": unrecognised_bytes,
        "unrecognised_ranges": unrecognised.page,
        "unrecognised_range_count": unrecognised_page["matched"],
        "prefix_unrecognised_bytes": prefix_unrecognised,
        "nameless_excluded_by_filter": nameless_excluded,
        "include_nameless": include_nameless,
        "unsupported_version_records": sum(unsupported_by_major.values()),
        "unsupported_version_bytes": unsupported_bytes,
        "unsupported_versions": unsupported_by_major,
        "unsupported_version_list": unsupported.page,
        "parser": PARSER,
        **page,
    }
    if unrecognised_page.get("all_results"):
        result["all_unrecognised_ranges"] = unrecognised_page["all_results"]
    if unsupported_page.get("all_results"):
        result["all_unsupported_version_list"] = unsupported_page["all_results"]
    if pattern is not None and not page["matched"] and not stopped:
        result["note"] = ("%d records were read and none has a file name matching %r "
                          "(a case-insensitive regex); the journal is not empty" % (read, name_filter))
    print_answer(result, indent=2)


if __name__ == "__main__":
    try:
        main()
    except SystemExit:
        raise
    except Exception as exc:                                  # whatever hostile input does, the answer is JSON
        drop_pages()
        print_answer({"error": "the read failed", "status": "failed", "status_basis": "the tool stopped with an unexpected error",
                      "reason": "%s: %s" % (type(exc).__name__, exc)})
        sys.exit(1)
