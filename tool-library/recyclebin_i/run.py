#!/usr/bin/env python3
"""Parse a Windows $Recycle.Bin $I metadata file.

Three of the measured cases did this by hand with `xxd` and arithmetic, which
is exactly the kind of work a tool should absorb: the format is fixed and
small, and getting the FILETIME conversion wrong by an hour is easy and
invisible.

$I layout (Vista and later), little-endian, unsigned:
  0x00  8  header: 1 (Vista/7) or 2 (8 and later)
  0x08  8  original file size
  0x10  8  deletion time, FILETIME (100 ns since 1601-01-01 UTC)
  0x18     header 1: 520 bytes, UTF-16LE path, NUL padded (544 bytes in all)
           header 2: 4-byte character count (the terminating NUL included), then
           that many UTF-16LE characters (0x1C plus twice the count in all)

Every length is checked against the bytes the file has. A file shorter than its layout needs is
reported `truncated: true` with the bytes it has and the path decoded from them as far as it goes,
never as a complete record; one longer than its layout says carries `trailing_bytes`. The whole file is
read (a $I is a few hundred bytes; one over 1 MiB is not a $I and is reported as such). An unknown
header is not guessed at.

Only a regular file is opened, and without blocking and without following a link: a name that is a
link, a FIFO, a device, a socket or a directory is not read, is named with the reason and is counted
under `not_attempted`, and a directory that cannot be listed or a link to a directory is named the same
way. A path that is itself a link to a directory is refused, not followed.

The directory a $I sits in is a per-user bin named by a SID (`bin_directory_sid`): the account whose
bin received the item. The record does not say who deleted the file, or from where the deletion was
asked, and a $R file of the same name (reported as `r_file`) holds the content only while it lasts.
"""
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
V1_SIZE = 0x18 + 520
MAX_I_BYTES = 1024 * 1024
SID = re.compile(r"^S-\d+(?:-\d+)+$", re.I)
PARSER = "recyclebin_i/4"
DEADLINE_SECONDS = 54             # the manifest allows 60: the walk and the reads stop here, so that the pages are placed and the answer printed before the harness ends it
MAX_LIMIT = 10000                 # the largest inline page; the whole result is in the file the answer names
PROGRESS = {"walked": 0, "parsed": 0}
KINDS = [(stat.S_ISFIFO, "a FIFO"), (stat.S_ISDIR, "a directory"), (stat.S_ISCHR, "a character device"),
         (stat.S_ISBLK, "a block device"), (stat.S_ISSOCK, "a socket")]


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
    interrupted_answer(signum, names_walked=PROGRESS["walked"], files_parsed=PROGRESS["parsed"])


def filetime(value):
    """ISO 8601 UTC with seven fractional digits, by integer arithmetic; None for 0 or past year 9999."""
    if value <= 0:
        return None
    try:
        whole, ticks = divmod(value, 10_000_000)
        return (FILETIME_EPOCH + datetime.timedelta(seconds=whole)).strftime("%Y-%m-%dT%H:%M:%S") + ".%07dZ" % ticks
    except (OverflowError, ValueError):
        return None


def text_of(raw):
    """A UTF-16LE path up to its first NUL; an odd byte at the end is not a character and is said so by the caller."""
    return raw[:len(raw) - (len(raw) % 2)].decode("utf-16-le", "replace").split("\x00", 1)[0]


def parse(data, name, file_bytes):
    if len(data) < 0x18:
        return {"file": name, "file_bytes": file_bytes, "truncated": True, "error": f"too short: {len(data)} bytes, need at least 24"}
    header, size, deleted = struct.unpack_from("<QQQ", data, 0)
    entry = {
        "file": name,
        "file_bytes": file_bytes,
        "header_version": header,
        "original_size": size,
        "deleted_at": filetime(deleted),
        "deleted_filetime": str(deleted),
        "truncated": False,
    }
    if header == 1:
        raw = data[0x18:V1_SIZE]
        entry["original_path"] = text_of(raw)
        if len(data) < V1_SIZE:
            entry["truncated"] = True
            entry["note"] = "a version 1 record is %d bytes and this file has %d; the path is what those bytes hold" % (V1_SIZE, len(data))
        elif len(data) > V1_SIZE:
            entry["trailing_bytes"] = len(data) - V1_SIZE
    elif header == 2:
        if len(data) < 0x1C:
            entry["truncated"] = True
            entry["error"] = "header 2 with no path length"
            return entry
        chars = struct.unpack_from("<I", data, 0x18)[0]
        entry["path_characters_declared"] = chars
        need = 0x1C + chars * 2
        raw = data[0x1C:need]
        entry["original_path"] = text_of(raw)
        if len(data) < need:
            entry["truncated"] = True
            entry["note"] = "the record declares %d path characters (%d bytes in all) and this file has %d bytes; the path is what they hold" % (chars, need, len(data))
        elif len(data) > need:
            entry["trailing_bytes"] = len(data) - need
        if len(data) >= need and chars and raw[-2:] != b"\x00\x00":
            entry["note"] = "the declared path is not NUL-terminated"
    else:
        # An unknown header is not a reason to guess: say so and stop, rather
        # than decoding whatever happens to be at 0x18.
        entry["error"] = f"unknown header version {header}; the path was not decoded"
    return entry


def kind_of(mode):
    for test, name in KINDS:
        if test(mode):
            return name
    return "not a regular file"


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
        fail("path is required: a $I file, or a directory holding them")

    targets = []
    stopped = None
    not_listed = []        # directories and links that were not entered, and why
    if os.path.islink(path) and os.path.isdir(path):
        fail("the path is a symbolic link to a directory: it is not followed (name the directory itself)", path=path, not_attempted=1)
    if os.path.isdir(path):
        def unreadable_directory(exc):
            not_listed.append({"file": getattr(exc, "filename", None) or path,
                               "error": "the directory could not be listed: %s" % exc.strerror, "not_attempted": True})
        for root, dirs, names in os.walk(path, onerror=unreadable_directory):
            if out_of_time():
                stopped = "the tool's own clock (%d s) ran out while the directory was walked, after %d names" % (DEADLINE_SECONDS, PROGRESS["walked"])
                break
            dirs.sort()
            for d in dirs:
                if os.path.islink(os.path.join(root, d)):
                    not_listed.append({"file": os.path.join(root, d), "error": "a link to a directory, not followed",
                                       "not_attempted": True})
            PROGRESS["walked"] += len(names)
            for name in sorted(names):
                if out_of_time():
                    stopped = "the tool's own clock (%d s) ran out while the directory was walked, after %d names" % (DEADLINE_SECONDS, PROGRESS["walked"])
                    break
                if name.upper().startswith("$I"):
                    targets.append(os.path.join(root, name))
    elif os.path.isfile(path):
        targets = [path]
    elif os.path.lexists(path):
        fail("not a regular file or a directory: it is not opened", path=path, not_attempted=1)
    else:
        fail("no such file or directory", path=path)

    if not targets and not not_listed and not stopped:
        fail("no $I files under that directory", path=path)

    limit = args.get("limit", 500)
    if isinstance(limit, bool) or not isinstance(limit, int) or not 1 <= limit <= MAX_LIMIT:
        fail("limit must be a whole number from 1 to %d (the inline page; the whole result is in the file the answer names)" % MAX_LIMIT)

    entries = NoReplacePage("recyclebin_i", [path], limit)
    counts = {"parsed": 0, "truncated": 0, "unknown_header": 0, "unreadable": 0, "not_attempted": 0}
    for skipped in not_listed:
        counts["not_attempted"] += 1
        entries.add(skipped)
    read_targets = 0
    for target in targets:
        if out_of_time():
            stopped = stopped or ("the tool's own clock (%d s) ran out after %d of the %d $I files found" % (DEADLINE_SECONDS, read_targets, len(targets)))
            break
        read_targets += 1
        PROGRESS["parsed"] = read_targets
        base = os.path.basename(target)
        directory = os.path.dirname(os.path.abspath(target))
        entry = None
        try:
            mode = os.lstat(target).st_mode
            if stat.S_ISLNK(mode):
                entry = {"file": target, "error": "a link, not followed", "not_attempted": True}
            elif not stat.S_ISREG(mode):
                # A FIFO named $I... would block the read until the time limit and lose the whole bin.
                entry = {"file": target, "error": "%s, not a regular file: it is not opened" % kind_of(mode), "not_attempted": True}
            else:
                # Opened without blocking and without following a link, and looked at again once open: a name
                # swapped for a FIFO between the check and the open is still not read.
                fd = os.open(target, os.O_RDONLY | os.O_NONBLOCK | getattr(os, "O_NOFOLLOW", 0))
                with os.fdopen(fd, "rb") as fh:
                    opened = os.fstat(fh.fileno())
                    if not stat.S_ISREG(opened.st_mode):
                        entry = {"file": target, "error": "%s, not a regular file: it is not opened" % kind_of(opened.st_mode), "not_attempted": True}
                    elif opened.st_size > MAX_I_BYTES:
                        entry = {"file": target, "file_bytes": opened.st_size, "error": "%d bytes: a $I file is a few hundred bytes, and this one is not read" % opened.st_size}
                    else:
                        data = fh.read(MAX_I_BYTES + 1)
                        entry = parse(data, target, opened.st_size)
        except OSError as exc:
            entry = {"file": target, "error": str(exc)}
        # The $R file of the same name holds the content while it lasts; the bin directory is named for a SID.
        counterpart = "$R" + base[2:]
        entry["r_file"] = counterpart if os.path.isfile(os.path.join(directory, counterpart)) else None
        sid = os.path.basename(directory)
        if SID.match(sid):
            entry["bin_directory_sid"] = sid
        if entry.get("not_attempted"):
            counts["not_attempted"] += 1
        elif entry.get("error") and "unknown header" in str(entry["error"]):
            counts["unknown_header"] += 1
        elif entry.get("error"):
            counts["unreadable"] += 1
        else:
            counts["parsed"] += 1
        if entry.get("truncated"):
            counts["truncated"] += 1
        entries.add(entry)

    page = entries.finish()
    problems = counts["truncated"] + counts["unknown_header"] + counts["unreadable"] + counts["not_attempted"]
    reasons = []
    if stopped:
        reasons.append(stopped + ": the rest were not read")
    if problems:
        reasons.append("%d record(s) are truncated, of an unknown header, unreadable or not attempted (see entries)" % problems)
    print_answer({
        "parser": PARSER,
        "status": "partial" if reasons else "complete",
        "status_basis": "; ".join(reasons) if reasons else "every $I file found under the path (%d) was read and none is truncated, of an unknown header, unreadable or skipped" % len(targets),
        "stopped_by_time_limit": bool(stopped),
        "entries": entries.page,
        "entry_count": page["matched"],
        "found": len(targets) + len(not_listed),
        "parsed": counts["parsed"],
        "records_truncated": counts["truncated"],
        "unknown_header": counts["unknown_header"],
        "unreadable": counts["unreadable"],
        "not_attempted": counts["not_attempted"],
        "note": "A $I record names the original path, size and deletion time of an item the Recycle Bin took. "
                "The directory SID is the account whose bin received it; it does not say who deleted the file or from where.",
        **page,
    }, indent=2)


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
