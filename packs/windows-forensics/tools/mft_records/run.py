#!/usr/bin/env python3
"""Read $MFT records directly, because istat answers one inode at a time.

The published runs kept needing the same three things and had no tool for any
of them: both time sets side by side for a whole directory, the bytes of a
resident file that is too small to have clusters, and every named stream on a
volume in one pass. Each was being done by hand with icat and arithmetic, and
the arithmetic is where the errors were.

Layout, all little-endian (Microsoft's own on-disk format):

  record   "FILE" magic, update sequence array at 0x04/0x06, sequence at 0x10,
           first attribute at 0x14, flags at 0x16 (1 in use, 2 directory),
           used size 0x18, allocated size 0x1C, base record 0x20, number 0x2C.
  attr     type 0x00, length 0x04, non-resident 0x08, name length 0x09,
           name offset 0x0A, id 0x0E; resident content at 0x14 for 0x10 bytes;
           non-resident allocated 0x28, real 0x30, initialised 0x38.
  $SI 0x10 created, modified, mft-modified, accessed, each a FILETIME.
  $FN 0x30 parent reference, the same four times, allocated and real size,
           name length in characters at 0x40, namespace 0x41, name UTF-16LE.

The update sequence array is not decoration: the last two bytes of every sector
in the record are held in it, and a parser that skips the fixup reads two bytes
of checksum in the middle of a timestamp. That is the classic silent corruption
in hand-rolled MFT code, so it is applied here first. A record whose fixup does not
match is still parsed, flagged `fixup_failed` and `unreliable`, and counted under
`records_fixup_failed`; it does not make the run partial, so read that count. A slot
that holds neither FILE nor BAAD (zeroed or damaged) is not a record and is not
listed: it is counted under `slots_without_signature`.

The slots are counted from the first record that looks like one (a FILE signature with an
update sequence array of the size the record size implies): a file that does not begin on a
record boundary is read at its own alignment, which is reported as `alignment_offset`. A
slot of zeros is counted under `slots_zeroed`; one that holds data and neither signature is a
problem and is counted under `slots_unrecognised`.

Every record is read. The page returned inline is `limit` long, and when more
records match the whole list is written to a file the output names. A record
too damaged to parse is listed as a problem with its offset, and the sweep goes
on to the next one.

Every nested range is checked against the attribute that holds it, and the attribute chain against the
record's used size: a $STANDARD_INFORMATION shorter than its times, a $FILE_NAME whose name runs past its
attribute, a resident $DATA past its attribute, a non-resident header shorter than the sizes it carries, a
chain that ends without its end marker. None is read as if it were whole: the record keeps what was
sound and says what was not under `structural_errors` (and is `unreliable`), and the record is also a
problem of the run, with its offset.

What it does NOT do: it does not resolve $ATTRIBUTE_LIST (a record that has one says so, and its other
attributes live in extension records this tool reads as records of their own, with `base_record`), and it
does not rebuild a parent path (each name carries its parent entry and sequence; join them with another
reading of the volume). Each name and stream carries its attribute `instance` id.
"""
import base64
import datetime
import json
import os
import re
import struct
import sys

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

    def add(self, row: object) -> None:
        """The hidden temporary file is made, and registered in `_tmp`, with the stop signals held: a stop that landed between mkstemp and the
        registration found no file to remove and left a hidden one behind (the SIGTERM case of tests/pack-windows-forensics-fs-contract.test.ts, 1 run
        in many on a loaded Mac). A signal that comes in meanwhile waits and is answered, by the handler that removes the file, as soon as the
        registration is in."""
        if self._out is not None or len(self.page) < self.limit:
            return super().add(row)
        before = None
        try:
            before = signal.pthread_sigmask(signal.SIG_BLOCK, {signal.SIGTERM, signal.SIGINT, signal.SIGHUP})
        except (AttributeError, ValueError, OSError):
            pass
        try:
            return super().add(row)
        finally:
            if before is not None:
                signal.pthread_sigmask(signal.SIG_SETMASK, before)

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
STANDARD_INFORMATION = 0x10
ATTRIBUTE_LIST = 0x20
FILE_NAME = 0x30
OBJECT_ID = 0x40
DATA = 0x80
INDEX_ROOT = 0x90
INDEX_ALLOCATION = 0xA0
END = 0xFFFFFFFF

NAMESPACE = {0: "POSIX", 1: "Win32", 2: "DOS", 3: "Win32 and DOS"}
# Whole-second timestamps are left off this set on purpose: modern stompers write
# arbitrary sub-second values, so the old tell is noise and would swamp the filter.
STOMP_FLAGS = {"si_created_before_fn_created", "si_modified_before_si_created",
               "si_times_identical"}
SI_FLAGS = [
    (0x0001, "read_only"), (0x0002, "hidden"), (0x0004, "system"),
    (0x0020, "archive"), (0x0040, "device"), (0x0080, "normal"),
    (0x0100, "temporary"), (0x0200, "sparse"), (0x0400, "reparse_point"),
    (0x0800, "compressed"), (0x1000, "offline"), (0x2000, "not_indexed"),
    (0x4000, "encrypted"),
]


PARSER = "mft_records/5"
DEADLINE_SECONDS = 285            # the manifest allows 300: the sweep stops here, so that the pages are placed and the answer printed before the harness ends it
RECORD_SIZES = (256, 512, 1024, 2048, 4096)
MAX_RECORD_SIZE = 65536           # the largest record size the record_size argument may force (NTFS uses 1024 or 4096)
MAX_LIMIT = 10000                 # the largest inline page; the whole result is in the file the answer names
MAX_NAME = 500                    # the longest name filter
PATTERN_SECONDS = 0.5             # one record's names are tested against the caller's expression for at most this long
PROGRESS = {"scanned": 0, "offset": 0}


class PatternTooSlow(Exception):
    pass


def _pattern_alarm(_signum, _frame):
    raise PatternTooSlow()


def matches(pattern, texts):
    """Whether the caller's expression matches any of `texts`, for at most PATTERN_SECONDS (the re module looks at signals while it matches, so an
    expression that takes exponential time on a name is stopped instead of outrunning the tool's clock)."""
    signal.signal(signal.SIGALRM, _pattern_alarm)
    signal.setitimer(signal.ITIMER_REAL, PATTERN_SECONDS)
    try:
        return any(pattern.search(text) for text in texts)
    finally:
        signal.setitimer(signal.ITIMER_REAL, 0)


class ClockStop(Exception):
    """The tool's own clock ran out while it was still looking for the first record."""


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
    interrupted_answer(signum, records_scanned=PROGRESS["scanned"], offset_reached=PROGRESS["offset"])


def filetime(value):
    """ISO 8601 UTC with seven fractional digits, by integer arithmetic; None for 0 or past year 9999."""
    if not value:
        return None
    try:
        whole, ticks = divmod(value, 10_000_000)
        return (FILETIME_EPOCH + datetime.timedelta(seconds=whole)).strftime("%Y-%m-%dT%H:%M:%S") + ".%07dZ" % ticks
    except (OverflowError, ValueError, OSError):
        return None


def times(buf, off):
    """The four FILETIMEs $SI and $FN both start with, in the same order."""
    created, modified, mft_modified, accessed = struct.unpack_from("<QQQQ", buf, off)
    return {
        "created": filetime(created),
        "modified": filetime(modified),
        "mft_modified": filetime(mft_modified),
        "accessed": filetime(accessed),
        "raw": [created, modified, mft_modified, accessed],
    }


def apply_fixup(record):
    """Put the update sequence array's bytes back where the sectors' ends belong."""
    usa_offset, usa_count = struct.unpack_from("<HH", record, 0x04)
    if usa_count == 0 or usa_offset + usa_count * 2 > len(record):
        return record, "the update sequence array is outside the record"
    signature = record[usa_offset:usa_offset + 2]
    out = bytearray(record)
    for i in range(1, usa_count):
        end = i * 512 - 2
        if end + 2 > len(out):
            return bytes(out), "the record is shorter than its sector count claims"
        if bytes(out[end:end + 2]) != signature:
            return bytes(out), "sector %d does not carry the update sequence number" % i
        out[end:end + 2] = record[usa_offset + i * 2:usa_offset + i * 2 + 2]
    return bytes(out), None


def attributes(record, first, errors, used=None):
    """Walk the attribute chain. It ends at the end marker; anything else that ends it (a header that does not fit,
    a length that is not a multiple of 8 or runs past the used part of the record, running out of record before
    the marker) is appended to `errors`, not passed over."""
    end = len(record)
    if used and first < used <= len(record):
        end = used
    offset = first
    while True:
        if offset + 4 > end:
            errors.append("the attribute chain runs out at offset %d without an end marker" % offset)
            return
        atype = struct.unpack_from("<I", record, offset)[0]
        if atype == END:
            return
        if offset + 16 > end:
            errors.append("the attribute header at offset %d does not fit the record" % offset)
            return
        length = struct.unpack_from("<I", record, offset + 4)[0]
        if length < 16 or length % 8 or offset + length > end:
            errors.append("the attribute at offset %d (type 0x%x) has an invalid length %d" % (offset, atype, length))
            return
        yield atype, offset, length
        offset += length


def attribute_name(record, offset, length, errors):
    name_len = record[offset + 9]
    if not name_len:
        return ""
    name_off = struct.unpack_from("<H", record, offset + 0x0A)[0]
    if name_off + name_len * 2 > length:
        errors.append("the attribute name at offset %d does not fit its attribute" % offset)
        return ""
    raw = record[offset + name_off:offset + name_off + name_len * 2]
    return raw.decode("utf-16-le", "replace")


def resident(record, offset, length, errors, what, minimum=0):
    """(content offset, content length) of a resident attribute, checked against the attribute's own length;
    None, with an error, when it does not fit."""
    content_len, content_off = struct.unpack_from("<IH", record, offset + 0x10)
    if content_off < 0x18 or content_off + content_len > length or content_len < minimum:
        errors.append("the resident %s at offset %d declares %d bytes at %d, which does not fit its %d-byte attribute (or is shorter than the %d it needs)"
                      % (what, offset, content_len, content_off, length, minimum))
        return None
    return offset + content_off, content_len


def parse_record(record, number_hint, want_resident):
    if record[:4] == b"\x00" * 4:
        return None
    if record[:4] not in (b"FILE", b"BAAD"):
        return None
    fixed, fixup_problem = apply_fixup(record)
    errors = []
    sequence, = struct.unpack_from("<H", fixed, 0x10)
    first_attr, flags = struct.unpack_from("<HH", fixed, 0x14)
    used, allocated = struct.unpack_from("<II", fixed, 0x18)
    base_ref, = struct.unpack_from("<Q", fixed, 0x20)
    number, = struct.unpack_from("<I", fixed, 0x2C)
    entry = {
        "entry": number if number else number_hint,
        "entry_from_record": bool(number),
        "sequence": sequence,
        "in_use": bool(flags & 0x01),
        "is_directory": bool(flags & 0x02),
        "used_bytes": used,
        "allocated_bytes": allocated,
        "base_record": (base_ref & 0xFFFFFFFFFFFF) if base_ref else None,
        "base_sequence": (base_ref >> 48) if base_ref else None,
        "names": [],
        "data_streams": [],
        "flags": [],
    }
    if record[:4] == b"BAAD":
        entry["flags"].append("record_marked_bad")
    if fixup_problem:
        entry["flags"].append("fixup_failed")
        entry["fixup_problem"] = fixup_problem
        entry["unreliable"] = True

    if used > len(fixed):
        errors.append("the record's used size (%d) is larger than the record (%d bytes); its attribute chain was read to the end of the record, not to the used size" % (used, len(fixed)))
    elif used < first_attr + 4:
        errors.append("the record's used size (%d) does not reach past its first attribute at %d; its attribute chain was read to the end of the record, not to the used size" % (used, first_attr))
    for atype, offset, length in attributes(fixed, first_attr, errors, used):
        non_resident = fixed[offset + 8]
        instance = struct.unpack_from("<H", fixed, offset + 0x0E)[0]
        if atype == STANDARD_INFORMATION and not non_resident:
            got = resident(fixed, offset, length, errors, "$STANDARD_INFORMATION", 0x24)
            if got:
                base, _ = got
                entry["standard_information"] = times(fixed, base)
                dos, = struct.unpack_from("<I", fixed, base + 0x20)
                entry["standard_information"]["attributes"] = [n for bit, n in SI_FLAGS if dos & bit]
                entry["standard_information"]["instance"] = instance
        elif atype == FILE_NAME and not non_resident:
            got = resident(fixed, offset, length, errors, "$FILE_NAME", 0x42)
            if not got:
                continue
            base, content_len = got
            parent, = struct.unpack_from("<Q", fixed, base)
            name_chars = fixed[base + 0x40]
            namespace = fixed[base + 0x41]
            if 0x42 + name_chars * 2 > content_len:
                errors.append("the $FILE_NAME at offset %d declares a %d-character name, which runs past its content (%d bytes)" % (offset, name_chars, content_len))
                continue
            raw = fixed[base + 0x42:base + 0x42 + name_chars * 2]
            fn = times(fixed, base + 0x08)
            alloc, real = struct.unpack_from("<QQ", fixed, base + 0x28)
            fn.update({
                "name": raw.decode("utf-16-le", "replace"),
                "namespace": NAMESPACE.get(namespace, str(namespace)),
                "parent_entry": parent & 0xFFFFFFFFFFFF,
                "parent_sequence": parent >> 48,
                "allocated_size": alloc,
                "real_size": real,
                "instance": instance,
            })
            entry["names"].append(fn)
        elif atype == DATA:
            stream = {"name": attribute_name(fixed, offset, length, errors), "resident": not non_resident, "instance": instance}
            if non_resident:
                if length < 0x40:
                    errors.append("the non-resident $DATA header at offset %d is %d bytes, shorter than the 64 that hold its sizes" % (offset, length))
                else:
                    alloc, real, init = struct.unpack_from("<QQQ", fixed, offset + 0x28)
                    stream.update({"allocated_size": alloc, "real_size": real, "initialised_size": init})
                    if real and not init:
                        entry["flags"].append("zero_initialised_size")
            else:
                got = resident(fixed, offset, length, errors, "$DATA")
                if got:
                    base, size = got
                    stream["real_size"] = size
                    if want_resident:
                        stream["content_base64"] = base64.b64encode(fixed[base:base + size]).decode("ascii")
            entry["data_streams"].append(stream)
        elif atype in (INDEX_ROOT, INDEX_ALLOCATION):
            entry.setdefault("index_attributes", []).append(attribute_name(fixed, offset, length, errors) or "$I30")
        elif atype == ATTRIBUTE_LIST:
            entry["flags"].append("has_attribute_list")
            entry["attribute_list_resolved"] = False
    if errors:
        entry["structural_errors"] = errors
        entry["flags"].append("structural_error")
        entry["unreliable"] = True
    if entry["base_record"]:
        entry["is_extension_record"] = True

    entry["ads"] = [s["name"] for s in entry["data_streams"] if s["name"]]
    si = entry.get("standard_information")
    fns = entry["names"]
    if si and fns:
        best = max(fns, key=lambda f: 0 if f["namespace"] == "DOS" else 1)
        entry["file_name_times_source"] = best["name"]
        # $FN is written by the kernel on create, rename and move; $SI is what the
        # public API changes. Report a disagreement, never call it proof on its own.
        if si["raw"][0] and best["raw"][0] and si["raw"][0] < best["raw"][0]:
            entry["flags"].append("si_created_before_fn_created")
        if si["raw"][1] and si["raw"][0] and si["raw"][1] < si["raw"][0]:
            entry["flags"].append("si_modified_before_si_created")
        if all(si["raw"][:4]) and len(set(si["raw"][:4])) == 1:
            entry["flags"].append("si_times_identical")
        if si["raw"][0] and all(v % 10000000 == 0 for v in si["raw"][:4] if v):
            entry["flags"].append("si_times_whole_seconds")
    entry["primary_name"] = entry.get("file_name_times_source")
    return entry


def detect_record_size(fh, size):
    """Records are 1024 on almost every volume; measure rather than assume. Returns (size, how it was found).

    The first two FILE magics are looked for through the whole file, not a first window: a slice of an $MFT
    can open with a run of zeroed records. The first record's own allocated size (its header, at 0x1C) is the
    primary evidence; the gap between the first two magics is the second, and when they disagree the header's
    value is used and the disagreement said by the caller."""
    fh.seek(0)
    hits, carry, base = [], b"", 0
    while len(hits) < 2:
        if out_of_time():
            raise ClockStop(base)
        block = fh.read(1 << 20)
        if not block:
            break
        buf = carry + block
        at = buf.find(b"FILE")
        while at >= 0 and len(hits) < 2:
            if not hits or base + at >= hits[-1] + 4:
                hits.append(base + at)
            at = buf.find(b"FILE", at + 1)
        carry = buf[-3:]
        base += len(buf) - len(carry)
    if not hits:
        return None, None, None, None
    fh.seek(hits[0] + 0x1C)
    raw = fh.read(4)
    declared = struct.unpack("<I", raw)[0] if len(raw) == 4 else None
    gap = (hits[1] - hits[0]) if len(hits) > 1 else None
    if declared in RECORD_SIZES:
        return declared, "the allocated size in the first record's header", gap, declared
    if gap in RECORD_SIZES:
        return gap, "the gap between the first two FILE signatures", gap, declared
    return 1024, "the default (neither the header nor the gap gave a record size)", gap, declared


def first_record_offset(fh, record_size):
    """Where the first record that looks like one begins: a FILE signature followed by an update sequence array
    of the size the record size implies. Slots are counted from here, so a file that opens with a part of a
    record (or with bytes that are not records) is read at its own alignment instead of as slots that match
    nothing. At most 4096 candidate signatures are looked at; None when none qualifies."""
    fh.seek(0)
    carry, base, tried = b"", 0, 0
    wanted = record_size // 512 + 1 if record_size >= 512 else None
    while True:
        if out_of_time():
            raise ClockStop(base)
        block = fh.read(1 << 20)
        if not block:
            return None
        buf = carry + block
        at = buf.find(b"FILE")
        while at >= 0 and at + 8 <= len(buf):
            tried += 1
            usa_offset, usa_count = struct.unpack_from("<HH", buf, at + 4)
            if 0x28 <= usa_offset <= 0x80 and 1 <= usa_count <= 17 and (wanted is None or usa_count == wanted):
                return base + at
            if tried >= 4096:
                return None
            at = buf.find(b"FILE", at + 1)
        keep = 7 if len(buf) >= 7 else len(buf)
        carry = buf[-keep:]
        base += len(buf) - len(carry)


def whole(args, name, low, high, default):
    value = args.get(name, default)
    if value is None:
        return None
    if isinstance(value, bool) or not isinstance(value, int) or value < low or value > high:
        fail("%s must be a whole number from %d to %d" % (name, low, high))
    return value


def flag(args, name):
    value = args.get(name, False)
    if not isinstance(value, bool):
        fail("%s must be true or false" % name)
    return value


def early_stop(path, size, where):
    """The clock ran out before the first record was found: nothing was read, and the answer says so."""
    print_answer({
        "parser": PARSER, "status": "partial",
        "status_basis": "the tool's own clock (%d s) ran out while it looked for the first record, %d of %d bytes into the file: no record was read" % (DEADLINE_SECONDS, where, size),
        "path": path, "bytes": size, "records_scanned": 0, "records_parsed": 0, "entries": [], "entry_count": 0, "stopped_by_time_limit": True,
        "offset_reached": where,
    }, indent=2)


def run(args):
    path = args.get("path")
    if not isinstance(path, str) or not path:
        fail("path is required: an extracted $MFT")
    limit = whole(args, "limit", 1, MAX_LIMIT, 200)
    name = args.get("name")
    if name is not None and (not isinstance(name, str) or len(name) > MAX_NAME):
        fail("name must be a string of at most %d characters: a case-insensitive regular expression over the file names" % MAX_NAME)
    want_entry = args.get("entry")
    if want_entry is not None and (isinstance(want_entry, bool) or not isinstance(want_entry, int) or want_entry < 0):
        fail("entry must be a record number (a whole number, 0 or more)")
    given = whole(args, "record_size", 256, MAX_RECORD_SIZE, None)
    deleted_only, streams_only, timestomp_only = flag(args, "deleted_only"), flag(args, "streams_only"), flag(args, "timestomp_only")
    with_resident = flag(args, "with_resident")
    if with_resident and os.environ.get("SECRET_OUTPUT") != "1":
        fail("with_resident is refused: the bytes of resident files can hold a secret, and are returned only in a job the harness runs as secret output "
             "(job_run with secret_output: true). Nothing was opened or read.")
    pattern = None
    if name:
        try:
            pattern = re.compile(name, re.I)
        except re.error as exc:
            fail("name is not a valid regex", reason=str(exc))
    if not os.path.isfile(path):
        if os.path.exists(path):
            fail("not a regular file: it is not opened", path=path, not_attempted=1)
        fail("no such file", path=path)

    try:
        size = os.path.getsize(path)
        fh = open(path, "rb")
    except OSError as exc:
        fail("could not read the $MFT", path=path, reason=str(exc))
    with fh:
        disagreement = None
        try:
            detected, detected_from, gap, declared = detect_record_size(fh, size)
            if given:
                record_size, record_size_from = given, "the record_size argument"
                # The evidence is the first record's own header; the gap between the first two signatures is the second. They are compared with
                # the forced size and a disagreement is a problem of the run, not a correction.
                evidence = declared if declared in RECORD_SIZES else (gap if gap in RECORD_SIZES else None)
                if evidence and evidence != given:
                    disagreement = ("the record_size argument (%d) disagrees with the %s (%d); the records were read at %d bytes as asked, and the "
                                    "slots that result are probably not records" % (given, "allocated size in the first record's header" if declared in RECORD_SIZES else "gap between the first two FILE signatures", evidence, given))
            else:
                record_size, record_size_from = detected, detected_from
            if not record_size:
                fail("no FILE record found; this does not look like an $MFT", path=path, bytes=size)
            first_at = first_record_offset(fh, record_size)
        except ClockStop as stop:
            early_stop(path, size, stop.args[0])
            return
        except OSError as exc:
            fail("could not read the $MFT", path=path, reason=str(exc))
        alignment = (first_at % record_size) if first_at is not None else 0

        key = [path, record_size, name, want_entry, deleted_only, streams_only, timestomp_only, with_resident]
        entries = NoReplacePage("mft_records", key, limit)
        problems = NoReplacePage("mft_records-problems", key, 40)
        structural = 0
        fixup_failed = 0
        zeroed = unrecognised = 0
        scanned, parsed = 0, 0
        trailing = 0
        stopped = None
        if disagreement:
            problems.add({"offset": first_at or 0, "why": disagreement})
        if alignment:
            problems.add({"offset": 0, "why": "the first record begins at byte %d, which is not a multiple of the %d-byte record size: the %d bytes before byte %d are not read as records, and the slots are counted from there" % (first_at, record_size, alignment, alignment)})
        try:
            fh.seek(alignment)
        except OSError as exc:
            fail("could not read the $MFT", path=path, reason=str(exc))
        while True:
            if out_of_time():
                stopped = ("the tool's own clock (%d s) ran out at byte %d of %d, after %d record slots: the rest of the file was not read"
                           % (DEADLINE_SECONDS, alignment + scanned * record_size, size, scanned))
                break
            try:
                chunk = fh.read(record_size)
            except OSError as exc:
                problems.add({"offset": alignment + scanned * record_size, "why": "the read failed here and the scan stopped: %s" % exc})
                break
            if not chunk:
                break
            if len(chunk) < 48:
                trailing = len(chunk)
                break
            index = scanned
            offset = alignment + index * record_size
            scanned += 1
            PROGRESS["scanned"], PROGRESS["offset"] = scanned, offset
            if len(chunk) < record_size:
                problems.add({"record": index, "offset": offset,
                              "why": "the file ends inside this record: %d of its %d bytes are there" % (len(chunk), record_size)})
            try:
                entry = parse_record(chunk, index, with_resident)
            except Exception as exc:        # a hostile record must not end the sweep
                problems.add({"record": index, "offset": offset,
                              "why": "the record did not parse: %s" % exc})
                continue
            if entry is None:
                if not chunk.strip(b"\0"):
                    zeroed += 1
                else:
                    unrecognised += 1
                    problems.add({"record": index, "offset": offset,
                                  "why": "the slot holds data but neither a FILE nor a BAAD signature (it begins %s)" % chunk[:4].hex()})
                continue
            parsed += 1
            if "fixup_failed" in entry["flags"]:
                fixup_failed += 1
            if entry.get("structural_errors"):
                structural += 1
                problems.add({"record": index, "offset": offset,
                              "why": "the record did not parse cleanly: %s" % "; ".join(entry["structural_errors"])})
            if want_entry is not None:
                if entry["entry"] != want_entry:
                    continue
            else:
                if deleted_only and entry["in_use"]:
                    continue
                if streams_only and not entry["ads"]:
                    continue
                if timestomp_only and not (set(entry["flags"]) & STOMP_FLAGS):
                    continue
                if pattern:
                    try:
                        if not matches(pattern, [n["name"] for n in entry["names"]]):
                            continue
                    except PatternTooSlow:
                        stopped = ("the name expression took more than %s s on the names of record %d (byte %d), so the sweep stopped there: %d record slots were read, "
                                   "the rest were not; use a simpler expression" % (PATTERN_SECONDS, index, offset, scanned))
                        break
            entries.add(entry)

    if scanned and not parsed and not stopped:
        problems.add({"offset": alignment, "why": "no record was read: %d slot(s) of %d bytes were looked at and none holds a FILE or BAAD signature at its start (is the record size right, or is this an $MFT?)" % (scanned, record_size)})
    page = entries.finish()
    problem_page = problems.finish()
    reasons = []
    if stopped:
        reasons.append(stopped)
    if problem_page["matched"]:
        reasons.append("%d problem(s) are named under problems" % problem_page["matched"])
    out = {
        "parser": PARSER,
        "status": "partial" if reasons else "complete",
        "status_basis": "; ".join(reasons) if reasons else "every %d-byte slot of the file was read to its end (%d slots, %d records) and no problem is named" % (record_size, scanned, parsed),
        "path": path,
        "record_size": record_size,
        "record_size_from": record_size_from,
        "records_scanned": scanned,
        "records_parsed": parsed,
        "records_with_structural_errors": structural,
        "records_fixup_failed": fixup_failed,
        "slots_zeroed": zeroed,
        "slots_unrecognised": unrecognised,
        "slots_without_signature": zeroed + unrecognised,
        "alignment_offset": alignment,
        "stopped_by_time_limit": bool(stopped),
        "entries": entries.page,
        "entry_count": page["matched"],
        **page,
        "problems": problems.page,
        "problem_count": problem_page["matched"],
        "note": "A flag beginning si_ is an indicator, not proof: $SI and $FN times can each be changed by software, and a "
                "disagreement between them has more than one cause. Corroborate with the USN journal and other sources; the pack does "
                "not read $LogFile. $ATTRIBUTE_LIST is not resolved and no parent path is rebuilt (each name carries its parent entry "
                "and sequence). A record with structural_errors kept what was sound and is unreliable. A record whose update sequence "
                "fixup failed is parsed, flagged fixup_failed and unreliable and counted in records_fixup_failed, and does not make the "
                "run partial. A slot with neither a FILE nor a BAAD signature is not listed as a record: an all-zero one is counted in "
                "slots_zeroed (an unused slot, ordinary at the end of an $MFT) and one that holds data in slots_unrecognised, which is also "
                "a problem; slots_without_signature is their sum. alignment_offset is where the first record begins modulo the record size "
                "(0 when the file is aligned); a file that does not begin on a record boundary is read from there and is partial.",
    }
    if problem_page.get("all_results"):
        out["all_problems"] = problem_page["all_results"]
    if trailing:
        out["trailing_bytes"] = trailing
        out["trailing_note"] = ("the file ends %d bytes into a record, too few to hold a record "
                                "header" % trailing)
    print_answer(out, indent=2)


def main():
    set_deadline(DEADLINE_SECONDS)
    install_signal_handlers(last_word)
    try:
        args = json.load(sys.stdin)
    except ValueError as exc:
        fail("arguments are not valid JSON", reason=str(exc))
    if not isinstance(args, dict):
        fail("arguments must be a JSON object")
    try:
        run(args)
    except OSError as exc:
        fail("the $MFT could not be read", reason=str(exc))


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
