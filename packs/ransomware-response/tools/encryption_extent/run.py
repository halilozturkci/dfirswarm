#!/usr/bin/env python3
"""Measure where in a file the bytes look encrypted, and say exactly which bytes were and were not looked at.

This is a MEASUREMENT of entropy and of a few structural facts. It does not say how much of a file was
encrypted, who the family is, or that a file is recoverable. What it does:

  * reads explicit files, or the candidate rows of an `encrypted_survey` census given by reference
    (a path to the census; its receipt's `parser` must be one this tool knows, and an unknown one is refused by
    name), under a policy the caller declares: `sampling` (a bounded number of windows spread over each file)
    or `full` (every byte, in order, while the read budget and the clock last);
  * measures the entropy of windows of `window` bytes with ONE formula (`entropy_exact`, the survey's, held equal by
    a test), lists the runs of adjacent windows at or above `threshold`, and writes every window, run and
    uninspected range to a profile file under the output directory, a file that is never replaced by a smaller one;
  * names the bytes it did NOT inspect, as ranges, per file;
  * checks the file's structure at its head and its end: the magic and the footer of the format its name or the
    caller names, and whether the container's directory parses; no byte of a file is ever printed;
  * compares each inspected window with a plaintext counterpart the caller names, when it has one;
  * judges the file against a layout only when the caller supplies one, rule by rule, and never names a family.

`high_entropy_fraction` is the share of the INSPECTED bytes that lie in windows at or above the threshold. It is not
a percentage of the file that was encrypted: compressed and random-looking formats are high entropy too, and a
window that was not read says nothing. An intermittent or partial pattern is reported as an observed block pattern.

Nothing is cut: the whole profile and every table longer than `limit` are written as JSON Lines (under
$OUT/tool-output in a job, else work/<agent>/tool-output) and named in the answer. A result file that is already
there is never replaced by another result. `max_seconds` is the tool's own clock (below the manifest's timeout); a
stop signal (SIGTERM, SIGINT, SIGHUP) ends the tool with one JSON answer, status `failed` and `interrupted`, exit code
128 + the signal, after removing the files it was still writing.
"""

# BEGIN SHARED ENDS
# The same text is in every pack tool and recipe and in their tool-library twins, before the file's own imports (tests/shared-blocks-census.test.ts
# holds the copies equal): the two ends of a call, where a stop signal (SIGTERM, SIGINT, SIGHUP) found no handler, or one that did harm.
# * The start. From here a stop is answered by ONE JSON document and exit 128 + the signal, until the tool installs its own handlers (which then
#   answer it), and for good for a signal the tool never takes. Only the start of the interpreter and the compiling of the file come before
#   it: a stop there ends the process with no answer, before anything was read. answer_a_stop() is that document: a handler whose own last word
#   wrote nothing on standard output calls it before it ends the process, so that a stop is never answered by silence.
# * The end. The interpreter's own teardown resets the handlers to their defaults before it frees what the call held, and a stop that landed
#   there killed a process that had printed its whole answer; a handler that raises, writes a last word or ends the process, run once the
#   answer was decided, wrote a second document, a traceback, or nothing at all. Python runs a handler on the main thread whichever thread the
#   signal reached, so a mask of the main thread alone holds nothing while another thread runs. hold_stop_signals() holds the stop signals for
#   good: blocked in this thread and given a handler that does nothing, which is the hold whatever thread the signal reaches; an error Python
#   can only report from then on (a file left open whose last write the file system refuses, closed when the frame that held it is freed) is
#   not printed (3.11 and 3.12 say nothing of it, 3.14 a traceback). A handler that was due runs on the way in, and never raises out of it.
#   Every writer of a final answer calls it before it commits to writing, every error branch at the end calls it, and, when the file runs as
#   a program, standard output is wrapped so that its first write calls it too. _code(stop) is a SystemExit's exit code (its text, if it has
#   one, goes to standard error as the interpreter puts it), and _leave(code) ends the call: both hold the signals first; _leave flushes
#   standard output (a write that fails there makes a 0 an exit 120, as the interpreter does) and standard error, runs the atexit hooks (a hook
#   that removes a temporary file), each step on its own and none able to raise, and ends the process with os._exit, never through the teardown.
# The modules are imported here, as the file is loaded, never inside the ending (an import there ran a due handler inside the import system).
import atexit
import json
import os
import signal
import sys

_ENDING = {"held": False}
_ENDING_SIGNALS = (signal.SIGTERM, signal.SIGINT, signal.SIGHUP)


def answer_a_stop(signum, when="before it had answered"):
    """The one document of a stop that ends the call before any answer was begun (nothing once one has): status failed, interrupted, and
    no claim about what was read or written. A handler whose own last word printed nothing calls it before it ends the process."""
    if _ENDING["held"]:
        return
    _ENDING["held"] = True
    name = {signal.SIGTERM: "SIGTERM", signal.SIGINT: "SIGINT", signal.SIGHUP: "SIGHUP"}.get(signum, "signal %d" % signum)
    text = json.dumps({"error": "the tool was stopped by %s %s" % (name, when), "status": "failed", "interrupted": name,
                       "status_basis": "stopped by %s %s: no answer was made, and what it had read or written by then is not described" % (name, when)})
    try:
        os.write(1, (text + "\n").encode("ascii"))
    except OSError:
        pass


def _stopped_without_handler(signum, _frame):
    for other in _ENDING_SIGNALS:
        try:
            signal.signal(other, signal.SIG_IGN)
        except (ValueError, OSError):
            pass
    answer_a_stop(signum, "while it was being loaded, or at a point where it has no stop handling of its own")
    os._exit(128 + signum)


def _ending_nothing(*_ignored):
    """The stop signals' handler, and sys.unraisablehook, once the answer has begun: nothing."""


def hold_stop_signals():
    """Hold the stop signals for good. Never raises. Called by a thread that is not the main one, it blocks them there and leaves the rest to
    the main thread's next call."""
    for _attempt in range(len(_ENDING_SIGNALS) + 2):
        if _ENDING["held"]:
            return
        try:
            try:
                signal.pthread_sigmask(signal.SIG_BLOCK, _ENDING_SIGNALS)
            except (AttributeError, ValueError, OSError):
                pass                  # no pthread_sigmask here: the handler below is the hold
            main_thread = True
            for signum in _ENDING_SIGNALS:
                try:
                    signal.signal(signum, _ending_nothing)
                except (ValueError, OSError):
                    main_thread = False
            sys.unraisablehook = _ending_nothing
            _ENDING["held"] = main_thread
            return
        except BaseException:  # noqa: BLE001 - a handler that was due ran on the way in (and raised): the hold is made again
            continue


class _AnswerStream:
    """Standard output of a call: the first write holds the stop signals (above); everything else is the stream's own."""

    def __init__(self, stream):
        self._stream = stream

    def write(self, text):
        if not _ENDING["held"]:
            hold_stop_signals()
        return self._stream.write(text)

    def writelines(self, lines):
        if not _ENDING["held"]:
            hold_stop_signals()
        return self._stream.writelines(lines)

    def __getattr__(self, name):
        if name == "_stream":
            raise AttributeError(name)
        return getattr(self._stream, name)


def _code(stop):
    hold_stop_signals()
    code = getattr(stop, "code", 1)
    if isinstance(code, int):
        return code
    if code is not None:
        try:
            sys.stderr.write("%s\n" % (code,))
        except BaseException:  # noqa: BLE001
            pass
    return 0 if code is None else 1


def _leave(code):
    hold_stop_signals()
    code = code if isinstance(code, int) else 1
    try:
        sys.stdout.flush()
    except BaseException:  # noqa: BLE001 - a reader that is gone: the answer did not reach it
        code = code or 120
    try:
        sys.stderr.flush()
    except BaseException:  # noqa: BLE001
        pass
    try:
        atexit._run_exitfuncs()
    except BaseException:  # noqa: BLE001 - a hook that fails is not a failure of the answer
        pass
    os._exit(code)


if __name__ == "__main__":
    for _signum in _ENDING_SIGNALS:
        signal.signal(_signum, _stopped_without_handler)
    if sys.stdout is not None and not isinstance(sys.stdout, _AnswerStream):
        sys.stdout = _AnswerStream(sys.stdout)
# END SHARED ENDS


import builtins
import collections
import datetime
import errno
import functools
import hashlib
import json
import math
import os
import re
import stat
import sys
import tempfile
import unicodedata
from pathlib import Path

PARSER = "encryption_extent/1"
WORK = "measurement"
TOOL = "encryption_extent"
ACCEPTED_CENSUS_PARSERS = ("encrypted_survey/3",)
CENSUS_STATUSES = ("candidate", "noncandidate", "unmeasured", "read_failed")
DEFAULT_WINDOW, MIN_WINDOW, MAX_WINDOW = 4096, 64, 67108864
DEFAULT_THRESHOLD = 7.5      # this pack's: the survey's head threshold, so that the two tools agree on what is high (the reverse-engineering pack's is 7.2)
DEFAULT_SAMPLE_WINDOWS, MAX_SAMPLE_WINDOWS = 64, 4096
DEFAULT_BUDGET, MIN_BUDGET = 4 << 30, 4096
DEFAULT_SECONDS, MAX_SECONDS = 780, 840    # the manifest allows 900: the work stops here so that what it has is written and sealed
MAX_FILES = 20000            # explicit files in one call (a census is streamed and has no such count)
MAX_LINE = 1 << 20           # the longest census line read; a longer one is counted and skipped
MAX_RULES = 32
INLINE_RUNS = 16             # runs and ranges shown in a file's row; every one is in the profile file
INLINE_RANGES = 16
TAIL_READ = 65557            # the end of a file read for a footer or a zip directory: 64 KiB and the end-of-directory record
HEAD_READ = 4096

# The pattern ransom_note_scan uses to take a file for a note by its name, so that the tools agree on which names are note names.
NAME_HINTS = re.compile(
    r"(readme|read_me|decrypt|restore|recover|unlock|how[\W_]*to|ransom|help[\W_]*|"
    r"your[\W_]*files|instruction|_note|!!!)", re.I)

# Formats whose structure is checked, by the extension that names them (the first one in the name, so that report.docx.locked is a docx).
FORMATS = {"pdf": "pdf", "zip": "zip", "docx": "zip", "xlsx": "zip", "pptx": "zip", "odt": "zip", "ods": "zip", "odp": "zip",
           "jar": "zip", "apk": "zip", "epub": "zip", "png": "png", "jpg": "jpeg", "jpeg": "jpeg", "gif": "gif",
           "sqlite": "sqlite", "sqlite3": "sqlite", "db": "sqlite", "gz": "gzip", "tgz": "gzip", "7z": "7z",
           "txt": "text", "csv": "text", "log": "text", "json": "text", "xml": "text", "html": "text", "md": "text"}
FORMAT_NAMES = ("pdf", "zip", "png", "jpeg", "gif", "sqlite", "gzip", "7z", "text")
# Formats that are normally compressed or packed: a high-entropy window is what they look like whole.
COMPRESSED = {"zip", "png", "jpeg", "gif", "gzip", "7z"}
COMPRESSED_EXTENSIONS = {"pdf", "docx", "xlsx", "pptx", "odt", "ods", "odp", "epub", "zip", "jar", "apk", "gz", "tgz", "7z",
                         "png", "jpg", "jpeg", "gif", "webp", "heic", "mp4", "mp3", "mkv", "avi", "mov", "rar", "xz", "bz2", "zst"}

# Lossless paging (the same in every library tool that pages): the page an
# agent reads stays small, and when there are more rows the whole result is
# written as JSON Lines under work/<agent>/tool-output and named.
import hashlib

# The rows a table shows inline are cut by size as well as by count: the answer is judged, serialised and read back within the run's
# clock, and a `limit` of 1,000,000 over rows of a few hundred bytes would take longer than max_seconds (and leave the answer without
# its keys). The cut is lossless: every row is in the paging file, named by all_results. The same text is in encrypted_survey, and a test
# holds the two classes equal; the model is snapshot_chain_check's LosslessPage.
INLINE_BYTES = 1 << 19


class LosslessPage:
    def __init__(self, tool: str, key: object, limit: int):
        if isinstance(limit, bool) or not isinstance(limit, int) or limit < 1:
            raise ValueError("limit must be a positive integer")
        self.tool = re.sub(r"[^A-Za-z0-9_.-]", "_", tool)
        self.limit = limit
        self.page: list[object] = []
        self.page_bytes = 0
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
                     "work/<your id>/ directory; in a job it is $OUT." % (self.total, self.shown, describe(exc)),
            "status": "failed",
            "status_basis": "the tool stopped with an error (see error); the whole result could not be kept, so there is no answer",
        }) + "\n")
        _sys.exit(1)

    def _write(self, row: object) -> None:
        assert self._out is not None
        # ASCII only: U+2028, U+0085, a bidi override and a lone surrogate (a file name that is not UTF-8) are escaped, lose nothing, and a
        # line of the file is always a row.
        text = json.dumps(row, ensure_ascii=True, default=str)
        try:
            self._out.write(text)
            self._out.write("\n")
        except OSError as exc:
            self._cannot_write(exc)

    def add(self, row: object, evidence: str | None = None) -> object:
        """Keep a row: read back by the backstop first (`evidence` is the name of a file printed as it is on purpose), then paged. Returns
        the row as kept."""
        row = seal_row(row, evidence)
        self.total += 1
        if len(self.page) < self.limit and self.page_bytes < INLINE_BYTES:
            self.page.append(row)
            self.page_bytes += len(repr(row))
            return row
        if self._out is None:
            # A stop must not come between the temporary file and its registration (self._tmp): the stop handler removes only the
            # registered files. The three stop signals are held for these steps and delivered right after; where the call is missing it is a no-op.
            hold = getattr(signal, "pthread_sigmask", None)
            was = hold(signal.SIG_BLOCK, {signal.SIGTERM, signal.SIGINT, signal.SIGHUP}) if hold else None
            try:
                self.path.parent.mkdir(parents=True, exist_ok=True)
                fd, name = tempfile.mkstemp(
                    dir=self.path.parent, prefix=f".{self.path.name}-"
                )
                self._tmp = Path(name)
                self._out = os.fdopen(fd, "w", encoding="utf-8")
            except OSError as exc:
                self._cannot_write(exc)
            finally:
                if hold:
                    hold(signal.SIG_SETMASK, was)
            for kept in self.page:
                self._write(kept)
        self._write(row)
        return row

    def finish(self) -> dict:
        result = {
            "matched": self.total,
            "returned": len(self.page),
            "truncated": self.total > len(self.page),
        }
        if self.total > len(self.page) and len(self.page) < self.limit:
            result["inline_cut_by_size"] = (
                "the rows shown inline stop at about %d bytes whatever limit says; the whole list is in all_results" % INLINE_BYTES
            )
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

    def add(self, row: object, *rest) -> object:
        """The hidden temporary file is made, and registered in `_tmp`, with the stop signals held: a stop that landed between mkstemp and the
        registration found no file to remove and left a hidden one behind (the SIGTERM case of tests/pack-windows-forensics-fs-contract.test.ts, 1 run
        in many on a loaded Mac). A signal that comes in meanwhile waits and is answered, by the handler that removes the file, as soon as the
        registration is in."""
        if self._out is not None or len(self.page) < self.limit:
            return super().add(row, *rest)
        before = None
        try:
            before = signal.pthread_sigmask(signal.SIG_BLOCK, {signal.SIGTERM, signal.SIGINT, signal.SIGHUP})
        except (AttributeError, ValueError, OSError):
            pass
        try:
            return super().add(row, *rest)
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


def finish_page(page) -> dict:
    """page.finish(), with the size cut named: NoReplacePage (the shared block above) replaces LosslessPage.finish, so the cut that
    LosslessPage makes by INLINE_BYTES is said here, outside the block, for every table. The same text is in ransom_note_scan."""
    result = page.finish()
    if page.total > len(page.page) and len(page.page) < page.limit:
        result["inline_cut_by_size"] = (
            "the rows shown inline stop at about %d bytes whatever limit says; the whole list is in all_results" % INLINE_BYTES
        )
    return result


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
    answer_a_stop(signum)
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
    hold_stop_signals()
    STOP["last_word"] = None
    print(json.dumps(answer, **dumps_kwargs))


install_signal_handlers(lambda signum: interrupted_answer(signum))
# END SHARED STOP

# BEGIN SHARED WITHHOLDING
# The same text is in every tool that withholds identifier-shaped strings and credentials (the network, base, encrypted-containers,
# memory, virtualization, ransomware and reverse-engineering packs, and the three tools of the cloud pack), so that they withhold the
# same strings; the tests that hold the copies equal are tests/shared-blocks-census.test.ts (how many carry it),
# tests/pack-re-delta10.test.ts (every copy equal, found by the marker), tests/pack-network-withholding.test.ts,
# tests/pack-base-shared.test.ts, tests/pack-virtualization-shared.test.ts, tests/pack-re-process.test.ts and
# tests/pack-cloud-shared.test.ts. An identifier-shaped string is withheld wherever the tool would print one: a name, a path
# component, a URL, a message that quotes either; and a credential (a value given to a password, a token, a cookie, a pair, a
# switch) by the name it is given under. A carrier may set two names above this block: WITHHOLD_LIMIT, the length past which a text is
# withheld whole (65536 when it sets none), and WITHHOLD_TICK, a hook that long scans call and that may raise to end them at the
# carrier's deadline (none when it sets none). Nothing else in the block is a carrier's to change.
COUNTS = {"names": 0, "urls": 0, "text": 0}
# A run of name characters long enough to be a token. `=` is only a padding at the end (so a key= prefix stays);
# `/` joins pieces of a base64 token and is handled apart, below.
_RUN = re.compile(r"[A-Za-z0-9_+%-]{20,}={0,2}|[A-Za-z0-9_+%-]{14,}={2}")
_SLASHED = re.compile(r"[A-Za-z0-9_+/%-]{30,}={0,2}")
_HEX = re.compile(r"[0-9a-fA-F]{32,}")
# The prefixed secrets that one expression finds. A JWT is not among them: `eyJ` + 8 name characters + `.` + 8 + `.` + the rest, tried at
# every `eyJ`, runs to the end of the run of name characters and fails again at each next `eyJ` of a text made of them, which costs the
# square of the length. `_prefixed_spans` reads a JWT in one pass instead, and puts it in order with these.
_PREFIX_RULES = re.compile(r"(?:AKIA|ASIA)[0-9A-Z]{16}|gh[pousr]_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{20,}"
                           r"|xox[abeprs]-[A-Za-z0-9-]{10,}|sk-[A-Za-z0-9_-]{20,}"
                           r"|(?i:basic|bearer)\s+[A-Za-z0-9+/=._~-]{8,}")
_JWT_RUN = re.compile(r"[A-Za-z0-9_-]+")
# User-info: after `//` (a URL, or a scheme-relative one), or bare as name:password@host. A mailto: address is not one.
_USERINFO = re.compile(r"(?<=//)[^/?#\s@]+(?=@)")
_BARE_USERINFO = re.compile(r"(?<![\w.%+:/-])(?!mailto:)[\w.%+-]{1,64}:[^\s/@:]{1,128}(?=@[\w\[])")


def _withheld(what, length, kind):
    COUNTS[kind] = COUNTS.get(kind, 0) + 1
    return ("<%s withheld %d characters>" % (what, length)) if what else ("<withheld %d characters>" % length)


def _token_run(run):
    """Is this run of name characters shaped like a token, and not like words, dates or versions?"""
    if _HEX.search(run):
        return True
    chunks = [(m.group()[0].isdigit(), m.start(), m.end()) for m in re.finditer(r"[A-Za-z]+|[0-9]+", run)]
    # digits packed between letters ("a9b2c7"), which words, dates and versions do not do
    packed = 0
    for i, (is_digit, start, end) in enumerate(chunks):
        if not is_digit or end - start > 3:
            continue
        before = i > 0 and not chunks[i - 1][0] and chunks[i - 1][2] == start
        after = i + 1 < len(chunks) and not chunks[i + 1][0] and chunks[i + 1][1] == end
        packed += 1 if before or after else 0
    if packed >= 3:
        return True
    letters = [c for c in run if c.isalpha()]
    case_flips = sum(1 for a, b in zip(letters, letters[1:]) if a.islower() != b.islower())
    if len(letters) >= 20 and case_flips >= max(8, 0.4 * len(letters)):
        return True
    if run.endswith("==") and len(run) >= 16:
        return True
    if run.endswith("=") and len(run) >= 24:
        return True
    return len(run) >= 40 and run.isalnum() and any(c.isdigit() for c in run) and any(c.isalpha() for c in run)


def _randomish(piece):
    """A piece of a path that is not a plain word: digits among letters, or capitals inside a word."""
    if len(piece) < 4 or "." in piece or re.fullmatch(r"[A-Z][a-z]+", piece):
        return False
    letters = [c for c in piece if c.isalpha()]
    mixed = any(c.islower() for c in letters) and any(c.isupper() for c in letters)
    return (any(c.isdigit() for c in piece) and bool(letters)) or mixed


_SPAN_PIECE = re.compile(r"[A-Za-z0-9_+%-]+")
# A text longer than this is withheld whole, by its length, and not examined: no name, path or URL is tens of thousands of characters
# long, and the answer says how long the text was. Every rule below reads a text of this length in well under a second whatever its
# characters are, so that no call of `scrub` or `token_spans` can run for long on a text a file chose; the limit is the backstop for
# a shape of text that no rule was tried on, and the rules themselves are linear.
TEXT_LIMIT = globals().get("WITHHOLD_LIMIT", 65536)


def _prefixed_spans(text, tail=None):
    """The spans of the prefixed secrets in the text (a vendor prefix, a JWT, `Basic`/`Bearer` and its value), left to right and apart,
    as one expression holding all of them would find them (the first match at each offset, the next search where the last ended), in
    time linear in the text. With `tail`, an expression matched where each span ends, the span takes what it matches.

    A JWT is read from the runs of name characters (`[A-Za-z0-9_-]+`), cut once: its head is the first `eyJ` of a run that is followed
    by 8 or more characters of that run, and it ends where the third part of the JWT does; every later `eyJ` of the run reads the same
    rest, so the first one is the one that matches and a run that does not hold a JWT is not read again for each `eyJ` in it."""
    from bisect import bisect_right
    size = len(text)
    starts, ends, rest = [], [], {}
    if "eyJ" in text:
        for m in _JWT_RUN.finditer(text):
            starts.append(m.start())
            ends.append(m.end())

    def jwt_end(r):      # where a JWT whose head is in run r ends, or -1: `.`, a run of 8 or more, `.`, then the rest of the next run
        if r not in rest:
            end, last = -1, ends[r] + 1
            if (last < size and text[last - 1] == "." and r + 1 < len(starts) and starts[r + 1] == last
                    and ends[r + 1] - last >= 8 and ends[r + 1] < size and text[ends[r + 1]] == "."):
                end = ends[r + 1] + 1
                if r + 2 < len(starts) and starts[r + 2] == end:
                    end = ends[r + 2]
            rest[r] = end
        return rest[r]

    def next_jwt(at):    # (start, end) of the first JWT that starts at or after `at`, or None
        while True:
            p = text.find("eyJ", at)
            if p < 0:
                return None
            r = bisect_right(starts, p) - 1
            if p + 11 <= ends[r] and jwt_end(r) >= 0:
                return p, jwt_end(r)
            at = ends[r]  # no `eyJ` further in this run can be a head either

    spans, at = [], 0
    other = _PREFIX_RULES.search(text)
    jwt = next_jwt(0) if starts else None
    while other is not None or jwt is not None:
        if other is not None and other.start() < at:      # it began inside the span just taken: look again from its end
            other = _PREFIX_RULES.search(text, at)
        elif jwt is not None and jwt[0] < at:
            jwt = next_jwt(at)
        else:
            start, end = other.span() if jwt is None or (other is not None and other.start() < jwt[0]) else jwt
            if tail is not None:
                end = tail.match(text, end).end()
            spans.append((start, end))
            at = end
    return spans


def _grow_spans(text, spans):
    """Each flagged span takes the random-looking pieces next to it across a `/`: the head of a token is not printed.

    One pass cuts the text into pieces (runs of name characters) and keeps where each starts and ends. A span then walks
    that array by index; a piece is judged once, and a walk that reaches a piece an earlier walk has settled stops there, so
    the work is linear in the text and no range is sliced or searched again. (Looking back with a search over everything
    before a piece costs the cube of the length for a name of many `/`-joined pieces.)"""
    from bisect import bisect_left
    starts, ends = [], []
    for m in _SPAN_PIECE.finditer(text):
        starts.append(m.start())
        ends.append(m.end())
    count, size = len(starts), len(text)
    judged_left, judged_right, settled_left, settled_right = {}, {}, {}, {}

    def padded(k):       # where piece k ends with the up to two `=` of padding after it
        e = ends[k]
        if e < size and text[e] == "=":
            e += 2 if e + 1 < size and text[e + 1] == "=" else 1
        return e

    def left_ok(j):
        if j not in judged_left:
            judged_left[j] = _randomish(text[starts[j]:ends[j]])
        return judged_left[j]

    def right_ok(k):
        if k not in judged_right:
            judged_right[k] = _randomish(text[starts[k]:padded(k)])
        return judged_right[k]

    def before(at):      # the piece that growing left from offset `at` takes, or -1. `$` also ends a match before a final line break.
        if at < 2 or text[at - 1] != "/":
            return -1
        for stop in ((at - 1, at - 2) if text[at - 2] == "\n" else (at - 1,)):
            j = bisect_left(ends, stop)
            if j < count and ends[j] == stop:
                return j if left_ok(j) else -1
        return -1

    def after(k):        # the piece that growing right from the end of piece k takes, or -1
        e = padded(k)
        if k + 1 >= count or e >= size - 1 or text[e] != "/" or starts[k + 1] != e + 1:
            return -1
        return k + 1 if right_ok(k + 1) else -1

    def settle(i, step, memo):
        trail = []
        while i not in memo:
            trail.append(i)
            j = step(i)
            if j < 0:
                memo[i] = i
                break
            i = j
        final = memo[i]
        for t in trail:
            memo[t] = final
        return final

    grown = []
    for start, end in spans:
        j = before(start)
        if j >= 0:
            start = starts[settle(j, lambda i: before(starts[i]), settled_left)]
        if end < size - 1 and text[end] == "/":
            k = bisect_left(starts, end + 1)
            if k < count and starts[k] == end + 1 and right_ok(k):
                end = padded(settle(k, after, settled_right))
        grown.append((start, end))
    return grown


def token_spans(text):
    if len(text) > TEXT_LIMIT:
        return [(0, len(text))]
    spans = _prefixed_spans(text)
    for m in _RUN.finditer(text):
        if _token_run(m.group()):
            spans.append(m.span())
    # A base64 token holds `/`: pieces too short to be one alone (an AWS-style secret has two) are caught as a whole.
    for m in _SLASHED.finditer(text):
        run = m.group()
        if "/" in run and sum(1 for p in run.split("/") if _randomish(p)) >= 3 and re.search(r"[0-9+]", run):
            spans.append(m.span())
    grown = _grow_spans(text, spans) if spans else []
    grown.sort()
    merged = []
    for start, end in grown:
        if merged and start <= merged[-1][1]:
            merged[-1] = (merged[-1][0], max(merged[-1][1], end))
        else:
            merged.append((start, end))
    return merged


def token_shaped(text):
    return bool(token_spans(text))


# ---- credentials: a value is withheld by the name it is given under and by the text around it ----------------------------------
# The rules above find strings that are shaped like an identifier. These find a secret that has no shape, because of what it is
# assigned to (`password=`, a `Name`/`Value` pair, a `-Password` switch, `curl -u user:pass`, `mysql -pSECRET`), and the common
# token families, private key blocks and hashes of an account database. A name decides whether a value is a secret, a value
# decides nothing. Every rule runs in time linear in the text (a bounded stretch after each anchor, no nested repeat), and a
# carrier whose texts are long (a cloud log: a megabyte) sets WITHHOLD_TICK to a hook that ends the work at its deadline.
_CRED_CHECKSUM_NAME = re.compile(r"(?i)checksum|digest|sha[0-9]|md5|etag|crc[0-9]")
_CRED_REDACTED = re.compile(r"^\W*(?:hidden_due_to_security_reasons|redacted|masked|removed|\*+|x{3,}|\[\])\W*$", re.I)
_CRED_NOT_A_VALUE = frozenset(("true", "false", "null", "none", "nil", "undefined", "required", "optional", "enabled", "disabled"))
_CRED_EXACT = {
    "password", "newpassword", "oldpassword", "currentpassword", "passwd", "pwd", "passphrase", "passcode", "pin", "otp",
    "pass", "dbpass", "userpass", "adminpass", "rootpass", "plaintext",
    "secret", "clientsecret", "secretkey", "secretaccesskey", "awssecretaccesskey", "awssecretkey", "secretstring",
    "secretbinary", "secrettext", "secretvalue", "accesskeysecret",
    "sessiontoken", "securitytoken", "accesstoken", "refreshtoken", "idtoken", "bearertoken", "authtoken", "token",
    "tokencode", "mfacode", "verificationcode", "authorizationcode",
    "authorization", "proxyauthorization", "cookie", "setcookie", "apikey", "privatekey", "privatekeypem",
    "sharedaccesskey", "sharedaccesssignature", "accountkey", "primarykey", "secondarykey", "keyvalue", "masterkey",
    "storagekey", "subscriptionkey", "ocpapimsubscriptionkey",
    "connectionstring", "credential", "credentials", "assertion", "samlresponse", "mfasecret",
    "sastoken", "sassignature", "signature", "sig",
    "passwordhash", "nthash", "ntlmhash", "lmhash",
}
_CRED_SUFFIX = ("password", "passwd", "passphrase", "secret", "apikey", "privatekey", "sessiontoken", "securitytoken",
                "accesstoken", "refreshtoken", "clientsecret", "token", "secrettext", "secretkey", "secretaccesskey",
                "primarykey", "secondarykey", "accountkey", "sharedaccesskey", "subscriptionkey", "passwordhash",
                "ntlmhash", "nthash", "passcode", "signature", "cookie")
# a position or an idempotency key under a name that ends in `token`
_CRED_NOT_SECRET = ("nexttoken", "pagetoken", "continuationtoken", "paginationtoken", "nextpagetoken", "pagingtoken",
                    "startingtoken", "nextmarkertoken", "clienttoken", "clientrequesttoken", "idempotencytoken",
                    "nextforwardtoken", "nextbackwardtoken", "requesttoken")
_CRED_CONTAINERS = ("credential", "credentials")
_CRED_NAME_CACHE = {}
_CRED_NAME_KEYS = ("Name", "name", "Key", "key")
_CRED_VALUE_KEYS = ("Value", "NewValue", "OldValue", "value", "newValue", "oldValue")


def is_container_name(name):
    """`credentials` names a group of fields (an access key id, an expiry, a token): each is judged by its own name."""
    return re.sub(r"[^a-z0-9]", "", str(name).lower()) in _CRED_CONTAINERS


def name_is_sensitive(name):
    """Does a field or a parameter of this name hold a secret? (`Password`, `client_secret`, `x-api-key`; not `nextToken`.)"""
    hit = _CRED_NAME_CACHE.get(name)
    if hit is None:
        flat = re.sub(r"[^a-z0-9]", "", str(name).lower())
        hit = flat in _CRED_EXACT or (len(flat) > 6 and flat.endswith(_CRED_SUFFIX) and not flat.endswith(_CRED_NOT_SECRET))
        if len(_CRED_NAME_CACHE) < 20000:
            _CRED_NAME_CACHE[name] = hit
    return hit


_CRED_B64 = "A-Za-z0-9+/_-"
_CRED_B64_RUN = re.compile(r"(?<![%s])[%s]{128,}={0,2}(?![%s])" % (_CRED_B64, _CRED_B64, _CRED_B64))
_CRED_B64_EDGE = "(?<![A-Za-z0-9+/=_-])"
_CRED_B64_END = "(?![A-Za-z0-9+/=_-])"
# The names an assignment is recognised by. A long compound name may carry any prefix (dbPassword=, apiToken=, adminSecret:);
# a short one needs the edge of a word (sig= is not design=).
_CRED_STRONG = (r"password|passwd|passphrase|secret|api[_-]?key|access[_-]?token|refresh[_-]?token|id[_-]?token|session[_-]?token|"
                r"security[_-]?token|auth[_-]?token|bearer[_-]?token|account[_-]?key|shared[_-]?access[_-]?key|primary[_-]?key|"
                r"secondary[_-]?key|private[_-]?key|subscription[_-]?key|sas[_-]?token|password[_-]?hash|nt[_-]?hash|ntlm[_-]?hash|"
                r"lm[_-]?hash|client[_-]?secret|secret[_-]?access[_-]?key|secret[_-]?key|secret[_-]?text|secret[_-]?value|token|signature|plaintext")
_CRED_SHORT = r"(?<![A-Za-z0-9])(?:pwd|pass|sig|pin|otp|sas)"
_CRED_SEP = r"""(?:\\*["']|["'])?\s*(?:[:=]|%3[dD]|%3[aA])\s*"""
# a short name is a name only as `pwd=value` or `pass:value`: "pass: 3 attempts" is prose
_CRED_SEPS = r"""(?:\\*["']|["'])?(?:\s*(?:=|%3[dD])\s*|:(?=\S))"""
_CRED_NAME = r"(?:(?:%s)%s|%s%s)" % (_CRED_STRONG, _CRED_SEP, _CRED_SHORT, _CRED_SEPS)
_CRED_ARN_TAIL = re.compile(r"arn:[A-Za-z0-9-]+:[A-Za-z0-9-]+:[A-Za-z0-9-]*:[0-9]*:$")
_CRED_PAIR_WHY = "a value paired with a credential name"
_CRED_RULES = [
    # anchored at the start of a run and possessive, so that a megabyte of `eyJ` is read once, not once per `eyJ`
    ("a JSON Web Token", re.compile(r"(?<![A-Za-z0-9_-])eyJ[A-Za-z0-9_-]{6,}+\.[A-Za-z0-9_-]{2,}+(?:\.[A-Za-z0-9_-]*+)?"), 0),
    ("a JSON Web Encryption token", re.compile(r"(?<![A-Za-z0-9_-])eyJ[A-Za-z0-9_-]{6,}+(?:\.[A-Za-z0-9_-]*+){4}"), 0),
    ("a password in a URL", re.compile(r"(?i)(?<![A-Za-z0-9+.-])[a-z][a-z0-9+.-]{1,20}://[^\s:/@\"'<>\\]{0,256}:([^\s/\"'<>\\]{1,1024})@(?=[^\s/@\"'<>]{1,255})"), 1),
    ("an Azure Functions key", re.compile(r"""(?i)(?:x-functions-key["']?\s*[:=]\s*(?:\\*["'])?|[?&;]code=)([A-Za-z0-9_/+=-]{16,512})"""), 1),
    ("a private key block", re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----(?:[\s\S]*?-----END [A-Z ]*PRIVATE KEY-----|[\s\S]*)"), 0),
    ("a base64 block of key lines", re.compile(r"(?:[A-Za-z0-9+/]{60,80}={0,2}\r?\n){2,}[A-Za-z0-9+/]{2,80}={0,2}"), 0),
    ("an authorization header value", re.compile(
        r"""(?i)authorization["']?\s*[:=]\s*(?:\\*["'])?(?:(?:bearer|basic|digest|negotiate|ntlm|token)\s+)?([^\s"'&,;\\]{1,4096})"""), 1),
    ("a cookie header value", re.compile(r"""(?i)cookie["']?\s*[:=]\s*(?:\\*["'])?([^\r\n"'\\]{1,4096})"""), 1),
    ("a scheme and its credential", re.compile(r"(?i)\b(?:bearer|basic)\s+([A-Za-z0-9._~+/=-]{3,4096})|\b(?:negotiate|ntlm|digest)\s+([A-Za-z0-9._~+/=-]{24,4096})"), -2),
    ("a value assigned to a credential name (quoted)", re.compile(
        r"""(?i)%s\\*(["'])(.{1,4096}?)(?=\\*\1)""" % _CRED_NAME), 2),
    ("a value assigned to a credential name", re.compile(
        r"""(?i)%s((?:(?!%%26)[^\s"'&<>\\]){1,4096})""" % _CRED_NAME), 1),
    ("a value given to a credential switch", re.compile(
        r"""(?i)(?<![A-Za-z0-9_])-(?:password|pass|pwd|passphrase|secret|clientsecret|apikey|accesstoken|token)\s+(?:\\*(["'])(.{1,4096}?)(?=\\*\1)|([^\s"'-][^\s"']{0,4095}))"""), -1),
    ("a secret given to ConvertTo-SecureString", re.compile(
        r"""(?i)ConvertTo-SecureString\s+(?:\\*(["'])(.{1,4096}?)(?=\\*\1)|([^\s"'-][^\s"']{0,4095}))"""), -1),
    # `mysql -u<user> -p<password>`: with `-p` glued to its value, and only as an option of a MySQL or MariaDB client (`ssh -p 22`,
    # `nc -p 80` and `mysql -p` alone, which asks for the password, name a port or nothing). The options are read up to the next
    # command of the kind, so that a text of many of them is read once, not once for each
    ("a password given to a MySQL client", re.compile(
        r"""(?i:(?<![\w.-])(?:mysql|mysqldump|mysqladmin|mysqlcheck|mysqlimport|mysqlshow|mariadb|mariadb-dump|mariadb-admin)(?:\.exe)?(?=\s))(?:(?!(?i:mysql|mariadb)\b)[^\n]){0,512}?(?<=\s)-p(?=[^\s`,;)])(?:"([^"\n]{1,256})"|'([^'\n]{1,256})'|([^\s"']{1,256}))"""), -3),
    # `curl -u user:password`: the part after the colon, and only when there is one (`curl -u user` asks for it)
    ("a password given to curl", re.compile(
        r"""(?i:(?<![\w.-])curl(?:\.exe)?(?=\s))(?:(?!(?i:curl)\b)[^\n]){0,512}?(?<=\s)(?:-u|-U|--user|--proxy-user)(?:\s+|=)(?:"[^":\n]*:([^"\n]{1,256})"|'[^':\n]*:([^'\n]{1,256})'|[^\s:"']*:([^\s"']{1,256}))"""), -3),
    ("a hash pair of an account database", re.compile(r"(?<![0-9a-fA-F])[0-9a-fA-F]{32}:([0-9a-fA-F]{32})(?![0-9a-fA-F])"), 1),
    ("a bcrypt hash", re.compile(r"(?<![A-Za-z0-9$])\$2[abxy]?\$[0-9]{2}\$[./A-Za-z0-9]{53}(?![./A-Za-z0-9])"), 0),
    ("a token of a known family", re.compile(
        r"(?:GOCSPX-[A-Za-z0-9_-]{20,}|gh[pousr]_[A-Za-z0-9]{36,}|github_pat_[A-Za-z0-9_]{50,}|xox[abprs]-[A-Za-z0-9-]{10,}|AIza[0-9A-Za-z_-]{35}(?![0-9A-Za-z_-])|"
        r"ya29\.[0-9A-Za-z_-]{20,}|1//0[0-9A-Za-z_-]{30,}|(?:IQoJb3JpZ2lu|FQoGZXIvYXdz|FwoGZXIvYXdz)[A-Za-z0-9+/=]{40,}|"
        r"[A-Za-z0-9_.~-]{3}[0-9]Q~[A-Za-z0-9_.~-]{30,}|[01]\.A[A-Za-z0-9_-]{50,}|[sr]k_(?:live|test)_[A-Za-z0-9]{16,})"), 0),
]
_CRED_GROUPS = {-1: (1, 2, 3), -2: (1, 2), -3: (1, 2, 3)}
# A random-looking run of an exact length that keys have: 32, 40 (an AWS secret access key), 43 + "=" and 86 + "==" (a base64 key).
_CRED_SHAPES = [
    ("a key-length base64 string", re.compile(_CRED_B64_EDGE + r"(?:[A-Za-z0-9+/]{32}|[A-Za-z0-9+/]{40}|[A-Za-z0-9+/]{43}=|[A-Za-z0-9+/]{86}==)" + _CRED_B64_END), True),
]
# A Name/Value pair written as JSON text inside a string (an AuditData in a column of another name, a parameter list in a cell): the
# structure rule (clean_value) cannot see it, so the text rule reads the head of the pair, and the name decides as it does there. The
# value is read by hand, not by an expression: a string up to its first quote (the backslashes before the quote are not part of it), a
# number, a flat array of up to 4,096 characters, or a literal; and the next value of the same pair (`OldValue`, then `NewValue`).
_CRED_PAIR_HEAD = re.compile(r"""(?i)\b(?:name|key)\\*"\s*:\s*\\*"([^"\\]{1,64})\\*"\s*,\s*\\*"(?:new|old)?value\\*"\s*:\s*""")
_CRED_NEXT_VALUE = re.compile(r"""(?i)\s*,\s*\\*"(?:new|old)?value\\*"\s*:\s*""")
_CRED_QUOTE = re.compile(r'\\*"')
# a format directive (`%s`, `%d`), a template field (`{0}`, `{name}`) or a `%VAR%` is where a value goes, not a value
_CRED_PLACEHOLDER = re.compile(r"%[-+ #0-9.]*[sdiuxXfeEgGcr](?![A-Za-z0-9])|\{\w*\}|%\w+%$|\.{2,}|\u2026")
_CRED_BARE = re.compile(r"-?[0-9][0-9.eE+-]{0,39}|\[[^\[\]]{0,4096}\]|(?:null|true|false)\b")
# What a text must hold for a rule to match it: a literal (lower case) of which one must be in the text, checked before the rule runs, so
# that a text with none of them (most names, addresses and ids) costs a few substring tests and no expression. An assignment rule also
# needs a separator in the text. Each is a necessary condition of its rule.
_CRED_ASSIGN = ("pass", "pwd", "secret", "key", "token", "signature", "plaintext", "sig", "pin", "otp", "sas", "hash")
_CRED_NEEDLES = {
    "a JSON Web Token": ("eyj",), "a JSON Web Encryption token": ("eyj",), "a password in a URL": ("://",),
    "an Azure Functions key": ("x-functions-key", "code="), "a private key block": ("-----begin",), "a base64 block of key lines": ("\n",),
    "an authorization header value": ("authorization",), "a cookie header value": ("cookie",),
    "a scheme and its credential": ("bearer", "basic", "negotiate", "ntlm", "digest"),
    "a value assigned to a credential name (quoted)": _CRED_ASSIGN, "a value assigned to a credential name": _CRED_ASSIGN,
    "a value given to a credential switch": ("password", "pass", "pwd", "secret", "apikey", "accesstoken", "token"),
    "a secret given to ConvertTo-SecureString": ("securestring",), "a password given to a MySQL client": ("mysql", "mariadb"),
    "a password given to curl": ("curl",), "a hash pair of an account database": (":",), "a bcrypt hash": ("$2",),
    "a token of a known family": ("gocspx-", "ghp_", "gho_", "ghu_", "ghs_", "ghr_", "github_pat_", "xoxa-", "xoxb-", "xoxp-", "xoxr-", "xoxs-",
                                  "aiza", "ya29.", "1//0", "iqojb3", "fqogzx", "fwogzx", "q~", "0.a", "1.a", "sk_", "rk_"),
}
_CRED_CLEAN = set()               # short texts already judged to hold nothing (names, addresses and ids repeat)
_CRED_GATE = 4096                 # a text longer than this is scanned with the carrier's hook in view, rule by rule
# The carrier's hook for long scans: called with the work done so far (1 per stretch found, 4096 between rules over a long text); it may
# raise to end the scan at the carrier's deadline. Most carriers set none and the calls do nothing.
_tick = globals().get("WITHHOLD_TICK") or (lambda units=1: None)


def _cred_json_value(text, at):
    """(start, end, after) of the JSON value whose text starts at `at`: `end` is where what is withheld ends, `after` where the next
    token of the pair begins. None when no value starts there."""
    q = _CRED_QUOTE.match(text, at)
    if q:
        start = q.end()
        close = text.find('"', start)
        if close < 0:
            return start, len(text), len(text)      # a value that is cut off: the rest of the text is the value
        return start, start + len(text[start:close].rstrip("\\")), close + 1
    m = _CRED_BARE.match(text, at)
    if m is None:
        return None
    if m.group()[0] in "nft":
        return at, at, m.end()                     # null, true and false are not secrets
    return m.start(), m.end(), m.end()


def _cred_pair_spans(text, spans):
    for head in _CRED_PAIR_HEAD.finditer(text):
        if not name_is_sensitive(head.group(1)):
            continue
        at = head.end()
        for _ in range(3):
            got = _cred_json_value(text, at)
            if got is None:
                break
            start, end, after = got
            if end > start:
                value = text[start:end]
                if not (_CRED_REDACTED.match(value) or value.lower() in _CRED_NOT_A_VALUE or value.startswith(("${", "{{")) or _CRED_PLACEHOLDER.match(value)):
                    spans.append((start, end, _CRED_PAIR_WHY))
            more = _CRED_NEXT_VALUE.match(text, after)
            if more is None:
                break
            at = more.end()


def _cred_random_like(run):
    """A run that looks like random base64 and not like a path, a name or a hash: mixed case and digits in the proportions
    random text has (a long path is mostly lower case with few capitals; a hex digest has no case to mix)."""
    n = len(run)
    upper = sum(1 for ch in run if "A" <= ch <= "Z")
    lower = sum(1 for ch in run if "a" <= ch <= "z")
    digit = sum(1 for ch in run if "0" <= ch <= "9")
    return upper * 100 >= 15 * n and lower * 100 >= 15 * n and digit * 100 >= 5 * n


def _cred_name_before(text, at):
    """The letters and digits of the name an assigned value follows (`nextToken=` gives `nexttoken`)."""
    return re.sub(r"[^a-z0-9]", "", text[max(0, at - 64):at].lower())


def _cred_spans(text, shapes, skip=()):
    spans = []
    big = len(text) > _CRED_GATE
    low = text.lower()
    sep = "=" in text or ":" in text or "%3" in low
    if "value" in low:
        _cred_pair_spans(text, spans)
    for why, rx, group in _CRED_RULES:
        if why in skip:
            continue
        need = _CRED_NEEDLES[why]
        if need is _CRED_ASSIGN and not sep:
            continue
        for n in need:
            if n in low:
                break
        else:
            continue
        if big:
            _tick(4096)
        for m in rx.finditer(text):
            if big:
                _tick(1)
            if "assigned to a credential name" in why:
                if _CRED_ARN_TAIL.search(text[max(0, m.start() - 120):m.start()]):
                    continue                              # arn:aws:secretsmanager:...:secret:NAME is a name, not a value
                if _cred_name_before(text, m.start(m.lastindex or 0)).endswith(_CRED_NOT_SECRET):
                    continue                              # nextToken=, pageToken=, clientToken=: a position or an idempotency key
            for g in _CRED_GROUPS.get(group, (group,)):
                if g and m.group(g) is None:
                    continue
                start, end = m.span(g)
                value = text[start:end]
                if g and (_CRED_REDACTED.match(value) or value.lower() in _CRED_NOT_A_VALUE or value.startswith(("${", "{{")) or _CRED_PLACEHOLDER.match(value)):
                    continue
                if why == "a scheme and its credential" and g == 1 and not (re.search(r"[0-9+/=_.~-]", value) or len(value) >= 16):
                    continue                              # "basic authentication" is prose, "Basic dXNlcjpwYXNz" is not
                if g == 1 and group == -1 and len(m.groups()) >= 2 and m.group(1) in ("'", '"'):
                    continue                              # group 1 of the switch rules is the quote
                spans.append((start, end, why))
    if big:
        _tick(4096)
    for m in (_CRED_B64_RUN.finditer(text) if len(text) >= 128 and "a long unbroken base64-like run" not in skip else ()):
        if _cred_random_like(m.group(0)):
            spans.append((m.start(), m.end(), "a long unbroken base64-like run"))
    if shapes and len(text) >= 32 and "a key-length base64 string" not in skip:
        for why, rx, check in _CRED_SHAPES:
            for m in rx.finditer(text):
                if not check or _cred_random_like(m.group(0)):
                    spans.append((m.start(), m.end(), why))
    spans.sort()
    merged = []
    for s in spans:
        if merged and s[0] < merged[-1][1]:
            if s[1] > merged[-1][1]:
                merged[-1] = (merged[-1][0], s[1], merged[-1][2])
            continue
        merged.append(s)
    return merged


def credential_spans(text, shapes=True, skip=()):
    """(start, end, why) of each stretch of `text` that is a credential by the name it is given under or by its text, in order and
    not overlapping. `shapes` False leaves out the rules that recognise a key by its length alone (a value that is named a checksum or
    a digest is not scanned for them). This is not `token_spans`: an identifier (a GUID, a hex digest, an access key id, an ARN) is
    not a credential here, and a tool that prints identifiers on purpose asks only for these."""
    if len(text) > TEXT_LIMIT:
        return [(0, len(text), "text longer than %d characters" % TEXT_LIMIT)]
    if shapes and not skip and text in _CRED_CLEAN:
        return []
    spans = _cred_spans(text, shapes, skip)
    if shapes and not skip and not spans and len(text) <= 256 and len(_CRED_CLEAN) < 100000:
        _CRED_CLEAN.add(text)
    return spans


def clean_value(value, leaf, note, key=None, pointer="", depth=0, shapes=True, max_depth=200):
    """The structure rule: `value` (what a JSON document decoded to) with every credential in it replaced. A string goes to
    `leaf(text, pointer, shapes)`, which returns what is printed for it. A field whose name says it holds a secret (or a `Value` whose
    `Name` does), at any depth, is not read at all: `note(pointer, why, original)` returns what is printed for it (a number under such
    a name is withheld too: 0 and 1 are not nothing). A key goes through `key(text)` when one is given. A value nested deeper than
    `max_depth` is replaced the same way."""
    if isinstance(value, str):
        return leaf(value, pointer, shapes)
    _tick(1)
    if depth > max_depth and isinstance(value, (dict, list)):
        return note(pointer, "nested deeper than %d levels" % max_depth, value)
    if isinstance(value, dict):
        named = None
        for k in _CRED_NAME_KEYS:
            if isinstance(value.get(k), str):
                named = value[k]
                break
        pair_secret = named is not None and name_is_sensitive(named)
        out = {}
        for k, v in value.items():
            ks = str(k)
            point = "%s/%s" % (pointer, ks.replace("~", "~0").replace("/", "~1"))
            safe_key = key(ks) if key is not None else ks
            if safe_key in out:
                safe_key = "%s#%d" % (safe_key, len(out))
            sensitive = name_is_sensitive(ks) or (pair_secret and ks in _CRED_VALUE_KEYS)
            if sensitive and is_container_name(ks) and isinstance(v, (dict, list)):
                sensitive = False
            if sensitive and not (v is None or isinstance(v, bool) or v == "") and not (isinstance(v, str) and (_CRED_REDACTED.match(v) or v.lower() in _CRED_NOT_A_VALUE)):
                out[safe_key] = note(point, "credential-named field", v)
            else:
                out[safe_key] = clean_value(v, leaf, note, key, point, depth + 1, shapes and not _CRED_CHECKSUM_NAME.search(ks), max_depth)
        return out
    if isinstance(value, list):
        return [clean_value(v, leaf, note, key, "%s/%d" % (pointer, i), depth + 1, shapes, max_depth) for i, v in enumerate(value)]
    return value


# what the rules of the block above already withhold whole, with their own markers: the first pass leaves these to them
_CRED_OLD_COVERS = frozenset(("a JSON Web Token", "a password in a URL", "an authorization header value", "a scheme and its credential",
                              "a long unbroken base64-like run", "a key-length base64 string"))


def _credentials_withheld(text, kind, skip=()):
    """`text` with each credential in it withheld. It runs after the rules above, on text that may hold their markers: a stretch that
    begins at a marker is theirs already."""
    out, last = [], 0
    for start, end, why in credential_spans(text, True, skip):
        if text.startswith("<", start):
            continue
        out.append(text[last:start])
        out.append(_withheld(why, end - start, kind))
        last = end
    if not out:
        return text
    out.append(text[last:])
    return "".join(out)


def scrub(text, kind="text"):
    """The text with every token-shaped run, every user-info and every credential withheld."""
    if len(text) > TEXT_LIMIT:
        return _withheld("over-long text", len(text), kind)
    text = _credentials_withheld(text, kind, _CRED_OLD_COVERS)     # first: the rules above cut a secret into pieces that no rule for a whole one can match
    text = _USERINFO.sub(lambda m: _withheld("userinfo", len(m.group()), kind), text)
    text = _BARE_USERINFO.sub(lambda m: _withheld("userinfo", len(m.group()), kind), text)
    out, last = [], 0
    for start, end in token_spans(text):
        out.append(text[last:start])
        out.append(_withheld("token-shaped text", end - start, kind))
        last = end
    out.append(text[last:])
    return _credentials_withheld("".join(out), kind)


def redact_url(url):
    """A URL or request target without its user-info, its token-shaped path text, its query values or its fragment."""
    rest, fragment = (url.split("#", 1) + [None])[:2]
    rest, query = (rest.split("?", 1) + [None])[:2]
    scheme = authority = ""
    m = re.match(r"^((?:[A-Za-z][A-Za-z0-9+.-]*:)?//)([^/]*)(.*)$", rest, re.S)
    if m:
        scheme, authority, rest = m.group(1), m.group(2), m.group(3)
        if "@" in authority:
            userinfo, authority = authority.rsplit("@", 1)
            authority = _withheld("userinfo", len(userinfo), "urls") + "@" + authority
    out = scheme + authority + scrub(rest, "urls")
    if query is not None:
        pairs = []
        for pair in query.split("&"):
            name, eq, value = pair.partition("=")
            pairs.append(scrub(name, "urls") + (eq + _withheld("", len(value), "urls") if eq else ""))
        out += "?" + "&".join(pairs)
    if fragment is not None:
        out += "#" + _withheld("", len(fragment), "urls")
    return out


def cell(value):
    """Text for one tab-separated cell or one printed path: no tab or line break, and a byte that was not UTF-8
    (a lone surrogate) written as \\xNN, so that no writer raises on it."""
    text = value if isinstance(value, str) else str(value)
    out = []
    for ch in text:
        o = ord(ch)
        if ch == "\\":
            out.append("\\\\")
        elif ch == "\t":
            out.append("\\t")
        elif ch == "\r":
            out.append("\\r")
        elif ch == "\n":
            out.append("\\n")
        elif 0xDC80 <= o <= 0xDCFF:
            out.append("\\x%02x" % (o - 0xDC00))
        elif 0xD800 <= o <= 0xDFFF:
            out.append("\\u%04x" % o)
        elif o < 0x20 or o == 0x7F:
            out.append("\\x%02x" % o)
        else:
            out.append(ch)
    return "".join(out)
# END SHARED WITHHOLDING


# BEGIN SHARED NAMES
# The same text is in encrypted_survey and ransom_note_scan, so that the two tools judge a name alike (a ransomware-response test holds
# the copies equal). A path is printed only through shown(): every component is judged, and no directory above a file is exempt.
# Everything derived from a name that is withheld (an extension, a stem, a length, the place of the name among its siblings) is withheld
# with it: a name that is withheld is replaced by one constant marker, and the order of a listing never follows the text that was withheld.
WITHHELD = "<identifier-shaped name withheld>"
WITHHELD_PATHS = [0]              # printed paths that had a component withheld (one per call of shown)
_IDRUN = re.compile(r"[A-Za-z0-9]{8,}")
_WORDY = re.compile(r"[A-Z]?[a-z]+(?:[A-Z][a-z]+)*|[A-Z]+")
_PAIR_SEPARATORS = re.compile(r"[^0-9A-Za-z]")
_DIGIT_GROUPS = re.compile(r"(?<![0-9])[0-9]{3,}(?:[ ,][0-9]{3,})+(?![0-9])")
HEX_DIGITS = frozenset("0123456789abcdefABCDEF")
SINGLE_CASE_RUN = 16              # a run of letters of one case is a word below this many letters, a random run from here on
HEX_PAIRS = 8                     # this many pairs of hex digits joined by one separator are a byte string
# Directory names every Windows, Linux and ESXi host has, whose letters and digits would otherwise be taken for an identifier, and the names
# of the exceptions Python raises (the tools print the type of an error: IsADirectoryError reads as letters that are not words). A component
# is printed as it is when it is one of these, whole and in any case.
WELL_KNOWN = frozenset((
    "system32", "syswow64", "inetcache", "inetcookies", "inethistory", "msocache", "psreadline", "framework", "framework64",
    "sqlserver", "gpucache", "dawnwebgpucache", "dawngraphitecache", "grshadercache", "indexeddb", "overlay2", "datastore1")
) | frozenset(name.lower() for name, value in vars(builtins).items() if isinstance(value, type) and issubclass(value, BaseException))


# The characters whose NFKC form holds a slash (a full-width solidus, the "a/c", "a/s", "c/o" and "c/u" signs) each read as one backslash, a
# separator that is not a slash: a path is split at the real slashes only, and a folded one would cut a run of pairs into pieces of one.
_SLASH_LIKE = dict.fromkeys((0x2100, 0x2101, 0x2105, 0x2106, 0xFF0F), "\\")
# Characters that show nothing and are not format characters: a combining grapheme joiner, variation selectors, Mongolian free variation
# selectors, hangul and khmer fillers, a braille blank, tag and musical controls, the other default-ignorable code points.
_INVISIBLE = re.compile("[\u00ad\u034f\u061c\u115f\u1160\u17b4\u17b5\u180b-\u180f\u200b-\u200f\u202a-\u202e\u2060-\u206f\u2800\u3164"
                        "\ufe00-\ufe0f\ufeff\uffa0\ufff0-\ufff8\U0001bca0-\U0001bca3\U0001d173-\U0001d17a\U000e0000-\U000e0fff]")


def _unseen(ch):
    """Whether a non-ASCII character shows nothing of its own: a format character, a combining mark, a default-ignorable code point."""
    return unicodedata.category(ch) in ("Cf", "Mn", "Mc", "Me") or _INVISIBLE.match(ch) is not None


def fold(name):
    """The name as the rule reads it: NFKC (a full-width letter or digit is the ASCII one; a full-width solidus is a separator, not a
    slash), every decimal digit of any script as its ASCII digit, and nothing that shows nothing: no format character, no combining mark
    (taken off the letter it sits on before the two are composed), no default-ignorable code point (a zero-width space, a variation
    selector, a filler cannot split a token)."""
    if name.isascii():
        return name
    out = []
    for ch in unicodedata.normalize("NFKC", "".join(c for c in name.translate(_SLASH_LIKE) if c.isascii() or not _unseen(c))):
        if ord(ch) < 128:
            out.append(ch)
        elif unicodedata.category(ch) == "Nd":
            out.append(str(unicodedata.decimal(ch)))
        elif not _unseen(ch):
            out.append(ch)
    return "".join(out)


def _hex_pairs(text):
    """Whether HEX_PAIRS or more pairs of hex digits follow each other, one separator between two. A separator is any character that is not
    an ASCII letter or a digit (the pairs of `id[aa-bb-...-hh]`, `key=aa:bb:...` and `(aa.bb...)` are found: a neighbour of the run that is
    not a letter or a digit does not hide a pair at its end), and only a letter or a digit glued to a pair makes it no pair. A run does not
    cross a slash: a path is read one component at a time (a full-width solidus is not a slash: fold turns it into a separator)."""
    for part in text.split("/"):
        run = 0
        for piece in _PAIR_SEPARATORS.split(part):
            if len(piece) == 2 and piece[0] in HEX_DIGITS and piece[1] in HEX_DIGITS:
                run += 1
                if run >= HEX_PAIRS:
                    return True
            else:
                run = 0
    return False


def _digit_groups(text):
    """Whether groups of three or more digits, joined by a space or a comma, hold ten or more digits together."""
    return any(sum(c.isdigit() for c in m.group(0)) >= 10 for m in _DIGIT_GROUPS.finditer(text))


def shaped(name):
    """Whether a name holds a token shaped like an identifier. The name is folded first (fold). A token is a run of 8 or more ASCII
    letters and digits. It is identifier-shaped when it holds both letters and digits, or is 10 or more digits, or is letters only and is
    not one word, one capitalised word, several capitalised words or all capitals, or is 16 or more letters of one case. So are 8 or more
    pairs of hex digits joined by one separator (any character that is not a letter, a digit or a slash: a colon, a dash, a dot, an underscore,
    a space, a bracket, an equals sign; a letter or a digit glued to a pair at an end of the run makes that pair no pair), and groups of
    digits joined by a space or a comma that hold 10 digits or more. The rule is a shape: a longer or different separator, a different
    grouping and other scripts are not covered (see the manifests)."""
    text = fold(name)
    for m in _IDRUN.finditer(text):
        token = m.group(0)
        if token.isdigit():
            if len(token) >= 10:
                return True
        elif any(c.isdigit() for c in token):
            return True
        elif not _WORDY.fullmatch(token):
            return True
        elif len(token) >= SINGLE_CASE_RUN and (token.islower() or token.isupper()):
            return True
    return len(text) >= 23 and _hex_pairs(text) or len(text) >= 11 and _digit_groups(text)


@functools.lru_cache(maxsize=65536)
def _judge(part):
    """What to print in place of one path component, or None to print it as it is. A component that is judged is withheld whole, by
    one marker that says nothing of its length or its shape."""
    if part.lower() in WELL_KNOWN:
        return None
    if shaped(part):
        return WITHHELD
    return WITHHELD if scrub(part, "names") != part else None


def shown(path, values=(), keep_last=False, count=True):
    """A path as it may be printed: every component that could carry an identifier is withheld.

    A component is withheld when it holds a token shaped like an identifier (shaped), when the shared withholding rules above find a
    token, a key or user-info in it, or when it contains a value the note held (case-insensitive, 8 characters or more). The same rule
    applies to every path a tool prints, so a name is never hidden on one line and printed on the next; a harmless name can be withheld
    with it, and the directory can be listed. keep_last leaves the final component as it is (a name that is itself the evidence).
    """
    if not isinstance(path, str):
        return path
    parts = path.split("/")
    last = len(parts) - 1
    lows = [v.lower() for v in values if len(v) >= 8]
    changed = False
    for i, part in enumerate(parts):
        if not part or (keep_last and i == last):
            continue
        replaced = _judge(part)
        if replaced is None and lows:
            low = part.lower()
            if any(v in low for v in lows):
                replaced = WITHHELD
        if replaced is not None:
            parts[i] = replaced
            changed = True
    if changed and count:
        WITHHELD_PATHS[0] += 1
    return "/".join(parts)


_ORDER_SALT = os.urandom(16)


def print_order(entries, judged, hidden=None):
    """The directory entries in the order an answer prints them: by the text printed for each (the marker for a name that is judged
    and withheld, the name itself otherwise; `judged(entry)` says whether the answer prints the entry's name through the judge;
    `hidden(entry)`, when given, says that a name the first rule lets through is withheld all the same, because the note beneath it holds
    its value: it sorts as the marker does), and the entries that print alike in an order drawn afresh every run (a keyed hash of the whole
    path, the directory above included, under a salt of this run: the same name in two directories has two unrelated ranks). The rank of a
    withheld name among its siblings, the order a directory lists them in and the inode never show in what an answer lists, in the
    order of its rows, in the numbers it hands out or in which entries a limit keeps."""
    texts = []
    for entry in entries:
        name = entry.name
        try:
            if hidden is not None and hidden(entry):
                texts.append(WITHHELD)
            else:
                texts.append((_judge(name) or name) if judged(entry) else name)
        except OSError:
            texts.append(_judge(name) or name)
    order = sorted(range(len(entries)), key=texts.__getitem__)
    out, i = [], 0
    while i < len(order):
        j = i + 1
        while j < len(order) and texts[order[j]] == texts[order[i]]:
            j += 1
        group = order[i:j]
        if len(group) > 1:
            group.sort(key=lambda n: (hashlib.blake2b(entries[n].path.encode("utf-8", "surrogatepass"), key=_ORDER_SALT, digest_size=8).digest(), n))
        out.extend(group)
        i = j
    return [entries[n] for n in out]
# END SHARED NAMES


# BEGIN SHARED BACKSTOP
# The same text is in encrypted_survey and ransom_note_scan (a ransomware-response test holds the copies equal). Every row a page or the census
# keeps and the answer itself pass through here on their way out, whatever the code that made them did: a second check, written apart from
# shown() (it reads a string whole, not component by component, and calls neither the judge, scrub nor any call site's decision), that
# replaces a string holding an identifier-shaped text by a marker, counts it, and makes a complete answer partial. The one exception is on
# purpose: the name of a file that is not named like a note is evidence and is printed as it is (the caller says so with `evidence`, and the
# check refuses that claim for a name that is note-named). Content that is hex by nature (a digest, a tail) is passed by its key.
BOUNDARY = {"replaced": 0, "by": {}, "where": [], "not_listed": 0}
OWN_NAMES = set()                 # the names of the files this run wrote (their digest is the name of the root and of the table)
FREE_KEYS = frozenset(("sha256", "tail_hex", "suffix_hex"))
PROSE_KEYS = frozenset(("reason", "status_basis", "partial_reasons"))    # the tool's own sentences: "(4294967296 bytes)" there is a size, not a name
SERIAL_KEYS = frozenset(("note_id", "finding_id", "first_note_id", "duplicate_of"))      # a sequence number this tool counted: N000001, F1000000
_SERIAL = re.compile(r"[NF][0-9]{6,12}")
MAX_REPLACED_LISTED = 20
MAX_JUDGED = 1 << 16
_SUSPECT = re.compile(r"[A-Za-z0-9]{8}|(?:[0-9A-Fa-f]{2}[^0-9A-Za-z/]){4}|[0-9]{3}[ ,][0-9]{3}")
_ALNUM_RUN = re.compile(r"[A-Za-z0-9]+")
_PAIRS = re.compile(r"(?<![0-9A-Za-z])[0-9A-Fa-f]{2}(?:[^0-9A-Za-z/][0-9A-Fa-f]{2}){7}(?![0-9A-Za-z])")
_GROUPS = re.compile(r"(?<![0-9])[0-9]{3,}(?:[ ,][0-9]{3,})+(?![0-9])")


class Sealed(dict):
    """A row that has been through the backstop: it is not read again (its evidence name would not pass without the claim made for it)."""


_FOLDS_TO_SLASH = dict.fromkeys((0x2100, 0x2101, 0x2105, 0x2106, 0xFF0F), "\\")      # NFKC turns these into a slash: not a path separator here
_UNSEEN = re.compile("[\u00ad\u034f\u061c\u115f\u1160\u17b4\u17b5\u180b-\u180f\u200b-\u200f\u202a-\u202e\u2060-\u206f\u2800\u3164"
                     "\ufe00-\ufe0f\ufeff\uffa0\ufff0-\ufff8\U0001bca0-\U0001bca3\U0001d173-\U0001d17a\U000e0000-\U000e0fff]")


def _read_as(text):
    """The string as the check reads it: NFKC (a full-width solidus is a separator, not a slash), decimal digits of any script as ASCII
    digits, nothing that shows nothing (no format character, no combining mark, no default-ignorable code point; a mark is taken off the
    character it sits on before the two are composed into one)."""
    if text.isascii():
        return text
    seen = lambda ch: unicodedata.category(ch) in ("Cf", "Mn", "Mc", "Me") or _UNSEEN.match(ch) is not None     # noqa: E731
    kept = []
    for ch in unicodedata.normalize("NFKC", "".join(c for c in text.translate(_FOLDS_TO_SLASH) if c.isascii() or not seen(c))):
        if ch.isascii():
            kept.append(ch)
        elif unicodedata.category(ch) == "Nd":
            kept.append(str(unicodedata.decimal(ch)))
        elif not seen(ch):
            kept.append(ch)
    return "".join(kept)


@functools.lru_cache(maxsize=65536)
def _why(text, prose=False):
    """The reason a string may not be printed (a fixed sentence, never a part of the string), or None. `prose` is a sentence of the tool's
    own (a reason, a status basis): a number of 10 or more digits followed by " bytes" is a size there and is not read as a name."""
    flat = _read_as(text)
    for found in _ALNUM_RUN.finditer(flat):
        run = found.group()
        size = len(run)
        if size < 8 or run.lower() in WELL_KNOWN:
            continue
        digits = sum(1 for c in run if c.isdigit())
        if digits == size:
            if size >= 10 and not (prose and flat.startswith(" bytes", found.end())):
                return "a long run of digits"
        elif digits:
            return "letters and digits in one run"
        elif run.isupper() or run.islower():
            if size >= 16:
                return "a long run of letters of one case"
        elif any(c.isupper() and not (i + 1 < size and run[i + 1].islower()) for i, c in enumerate(run)):
            return "letters that do not read as words"
    if _PAIRS.search(flat):
        return "pairs of hex digits"
    for m in _GROUPS.finditer(flat):
        if sum(c.isdigit() for c in m.group(0)) >= 10:
            return "groups of digits"
    return None


_CLEAN = set()                    # short strings already found clean (keys, repeated words): not read again


def _refuse(text, evidence, prose=False):
    """Why this string may not be printed, or None. `prose` is set for the tool's own sentences (see _why)."""
    size = len(text)
    if size < 8 or text in _CLEAN or text in OWN_NAMES:
        return None
    if size > MAX_JUDGED:
        return "a string too long to check"
    if evidence and not NAME_HINTS.search(evidence):
        if text.lower() in evidence.lower():              # the name itself, or a piece of it (its extension)
            return None
        if text.endswith("/" + evidence):                 # a path whose last component is the evidence
            text = text[:-len(evidence) - 1]
            size = len(text)
            if size < 8:
                return None
    why = None if text.isascii() and not _SUSPECT.search(text) else _why(text, prose)
    if why is None and not prose and size <= 64 and len(_CLEAN) < 20000:
        _CLEAN.add(text)
    return why


def _place(where):
    """The place of a string as text: the keys that are plain words and the indexes above it, never a key that came from a name (a key is a
    word only when it is also one to the second check: a key of letters and digits is not printed, whatever it looks like)."""
    parts = []
    while where is not None:
        where, label = where
        word = not isinstance(label, int) and re.fullmatch(r"[a-z][a-z_0-9]{0,40}", str(label)) and _why(str(label)) is None
        parts.append(label if isinstance(label, int) or word else "*")
    return "/" + "/".join(str(p) for p in reversed(parts))


def _replaced(why, where):
    BOUNDARY["replaced"] += 1
    BOUNDARY["by"][why] = BOUNDARY["by"].get(why, 0) + 1
    if len(BOUNDARY["where"]) < MAX_REPLACED_LISTED:
        BOUNDARY["where"].append({"at": _place(where), "check": why})
    else:
        BOUNDARY["not_listed"] += 1
    return "<withheld at the output: %s>" % why


def _read_back(value, where, key, evidence):
    """`value` with every string checked; the same object when nothing was replaced."""
    if isinstance(value, Sealed):
        return value
    if isinstance(value, str):
        if len(value) < 8 or key in FREE_KEYS or (key in SERIAL_KEYS and _SERIAL.fullmatch(value)):
            return value
        why = _refuse(value, evidence, key in PROSE_KEYS)
        return _replaced(why, where) if why else value
    if isinstance(value, dict):
        pairs, changed = [], False
        for k, v in value.items():
            nk = _read_back(k, (where, "(key)"), None, None) if isinstance(k, str) and len(k) >= 8 else k
            if isinstance(v, (str, dict, list, tuple)):
                nv = _read_back(v, (where, k if nk is k else "(key)"), k if isinstance(k, str) else None, evidence)
            else:
                nv = v
            changed = changed or nk is not k or nv is not v
            pairs.append((nk, nv))
        if not changed:
            return value
        out = {}
        for nk, nv in pairs:
            while nk in out:
                nk = "%s #" % nk
            out[nk] = nv
        return out
    if isinstance(value, (list, tuple)):
        items = [_read_back(v, (where, i), key, evidence) for i, v in enumerate(value)]
        return value if all(a is b for a, b in zip(items, value)) else items
    return value


def seal_row(row, evidence=None):
    """A row on its way to a page or the census: every string read back. `evidence` is the name of the file the row is about when it is
    printed as it is on purpose (a file that is not named like a note)."""
    if isinstance(row, Sealed):
        return row
    out = _read_back(row, None, None, evidence)
    return Sealed(out) if isinstance(out, dict) else out


def release(doc):
    """The answer: every string that was not read back already is read back now. A complete answer that had a string replaced is partial."""
    out = _read_back(doc, None, None, None)
    if BOUNDARY["replaced"] and isinstance(out, dict):
        note = {"strings_replaced_at_the_output": BOUNDARY["replaced"], "by_check": dict(BOUNDARY["by"]), "replaced_at": list(BOUNDARY["where"]),
                "replaced_not_listed": BOUNDARY["not_listed"],
                "note": "every string of this answer and of the files it names was read back by a second check, written apart from the rule "
                        "that withholds names; a string it found identifier-shaped is replaced by a marker and its place is in replaced_at"}
        merged = {}
        for k, v in out.items():
            merged[k] = v
            if k == "status_basis":
                merged["boundary"] = note
        merged.setdefault("boundary", note)
        if merged.get("status") == "complete":
            merged["status"] = "partial"
            if "complete" in merged:
                merged["complete"] = "partial"
            merged["status_basis"] = "%s; %d strings held an identifier-shaped text that the first rule missed and were replaced at the output (see boundary)" % (
                merged.get("status_basis") or "every entry was visited", BOUNDARY["replaced"])
        out = merged
    return out
# END SHARED BACKSTOP


def output_place(tool, key):
    """Where a whole result is written and how the answer names it: (real path, path as cited)."""
    digest = hashlib.sha256(json.dumps(key, sort_keys=True, default=str).encode("utf-8")).hexdigest()[:16]
    name = f"{tool}-{digest}.jsonl"
    job, out = os.environ.get("JOB_ID"), os.environ.get("OUT")
    if job and out:
        # In a job only $OUT is written, and it is sealed as the job's output.
        return Path(out) / "tool-output" / name, "store/jobs/%s/out/tool-output/%s" % (re.sub(r"[^A-Za-z0-9_.-]", "_", job), name)
    agent = re.sub(r"[^A-Za-z0-9_.-]", "_", os.environ.get("AGENT_ID") or "tool")
    path = Path("work") / agent / "tool-output" / name
    return path, str(path)


class Profile:
    """One JSON line per record (the tool says which), then a receipt; written whole or not at all.

    The file is made under a temporary name and placed when the receipt is written, so an interrupted run leaves no file with
    the profile's name: a profile that exists ends in its receipt. It is placed without replacing a profile already there (a
    rerun with other limits writes a different profile, and the earlier one, which may be the larger, stays); the answer names
    the file that holds this one. The name is made from the parameters, never from a name of any file.
    """

    def __init__(self, key):
        self.path, self.shown = output_place(TOOL + "-profile", key)
        self.rows = 0
        # A stop must not come between the temporary file and its registration in PAGES, which is how the stop handler finds it. The three
        # stop signals are held for these steps and delivered right after; where the call is missing it is a no-op.
        hold = getattr(signal, "pthread_sigmask", None)
        was = hold(signal.SIG_BLOCK, {signal.SIGTERM, signal.SIGINT, signal.SIGHUP}) if hold else None
        try:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            fd, name = tempfile.mkstemp(dir=self.path.parent, prefix=f".{self.path.name}-")
            self._tmp = Path(name)
            self._out = os.fdopen(fd, "w", encoding="utf-8")
            PAGES.append(self)
        finally:
            if hold:
                hold(signal.SIG_SETMASK, was)

    def add(self, row, evidence=None):
        row = seal_row(row, evidence)
        self._out.write(json.dumps(row, ensure_ascii=True, default=str))
        self._out.write("\n")
        self.rows += 1
        return row

    def finish(self, receipt):
        receipt = release({"record": "receipt", "rows": self.rows, **receipt})
        self._out.write(json.dumps(receipt, ensure_ascii=True, default=str))
        self._out.write("\n")
        self._out.flush()
        os.fsync(self._out.fileno())
        self._out.close()
        placed = place_without_replacing(self._tmp, self.path)
        self._tmp = None
        self.path = placed
        self.shown = self.shown[: len(self.shown) - len(Path(self.shown).name)] + placed.name


class NoProfile:
    """Stands in for the profile when no file can be made for it: the windows are measured and counted, none is kept."""

    shown = None

    def __init__(self):
        self.rows = 0

    def add(self, row, evidence=None):
        self.rows += 1
        return row

    def finish(self, receipt):
        pass


def fail(message, **extra):
    print_answer(release({"error": message, "status": "failed",
                          "status_basis": "the tool stopped with an error (see error); it produced no %s" % WORK, **extra}))
    raise SystemExit(1)


def describe(exc):
    """An error without the path it names: type, errno name and the system's own words (never the text of an exception that has none:
    it can name the place of the output)."""
    code = errno.errorcode.get(exc.errno, "") if getattr(exc, "errno", None) else ""
    words = getattr(exc, "strerror", None) or ("no free name for a result file" if str(exc).startswith("no free name") else "no system message")
    return "%s%s: %s" % (type(exc).__name__, " " + code if code else "", words)


def where_it_failed(exc):
    """The line of this tool an unexpected exception was raised on: enough to find it, and no text of the exception (which can name a path)."""
    tb = exc.__traceback__
    line = None
    while tb is not None:
        if tb.tb_frame.f_code.co_filename == __file__:
            line = tb.tb_lineno
        tb = tb.tb_next
    return "line %s of the tool" % line if line else "an unknown line"


PROGRESS = {}


def last_word(signum):
    """What the tool says when a stop signal ends it: one JSON answer, never a clean-looking partial one."""
    print(json.dumps({"error": "stopped by signal %d before the %s was complete" % (signum, WORK), "status": "failed",
                      "status_basis": "the tool was stopped by signal %d; the profile and the tables it was still writing were removed, "
                                      "so nothing it had read is an answer" % signum,
                      "interrupted": True, "signal": signum, "coverage_so_far": PROGRESS.get("coverage")}), flush=True)


def drop_temporary_files():
    """Remove the files a page or the profile was still writing (a failure, not a stop signal, ended the tool)."""
    for page in list(PAGES):
        tmp = getattr(page, "_tmp", None)
        if tmp is not None:
            try:
                os.unlink(tmp)
            except OSError:
                pass


COST = {"per_byte": 6e-8}     # seconds per byte read and measured: the floor is about 1.7 times what 64 MiB took when measured; the slowest window seen so far raises it


def time_left():
    return float("inf") if STOP["deadline"] is None else STOP["deadline"] - time.monotonic()


def too_late(length):
    """True when a window of `length` bytes would not be read and measured before the tool's own clock runs out: it is not started, so that
    the clock is honoured to within a window's cost of the largest window that was already measured, and not by the 2 s a 64 MiB window takes."""
    return out_of_time() or time_left() < length * COST["per_byte"]


def entropy_exact(block):
    """Shannon entropy of the bytes of a block, in bits per byte, unrounded: the value every threshold is compared with."""
    if not block:
        return 0.0
    total = len(block)
    bits = -sum((c / total) * math.log2(c / total) for c in collections.Counter(block).values())
    return max(0.0, bits)


def shown_entropy(exact):
    """The entropy as it is printed: three places. A reading of 7.4996 prints as 7.5 and is not at the threshold."""
    return round(exact, 3)


def expected_random_entropy(n):
    """The entropy a block of n uniformly random bytes is expected to read (the plug-in estimate's bias: 255 / (2 n ln 2) bits too low)."""
    if n <= 0:
        return 0.0
    return max(0.0, min(math.log2(min(n, 256)), 8.0 - 255.0 / (2.0 * n * math.log(2))))


def pread_full(fd, length, offset):
    chunks, got = [], 0
    while got < length:
        data = os.pread(fd, length - got, offset + got)
        if not data:
            break
        chunks.append(data)
        got += len(data)
    return b"".join(chunks)


def evidence_of(name):
    """The name of a file when it is printed as it is on purpose (a file that is not named like a note), else None."""
    return None if NAME_HINTS.search(name) else name


def display(path):
    """The path as it may be printed. Every directory above the file is judged by shown(); the file's own name is withheld when it
    is named like a note and holds an identifier-shaped token, and is otherwise printed as it is: a file that is not named like a
    note is an encrypted file or an ordinary one, and its name is evidence."""
    return shown(path, keep_last=not NAME_HINTS.search(os.path.basename(path)))


def kind_of(mode):
    for test, text in ((stat.S_ISFIFO, "a named pipe"), (stat.S_ISSOCK, "a socket"), (stat.S_ISBLK, "a block device"),
                       (stat.S_ISCHR, "a character device"), (stat.S_ISDIR, "a directory")):
        if test(mode):
            return text
    return "a special file"


def open_regular(path):
    """A descriptor for a regular file, opened without following a link and without blocking (a named pipe opens at once and is
    refused by its fstat); its fstat comes with it."""
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0)
    fd = os.open(path, flags)
    try:
        st = os.fstat(fd)
        if not stat.S_ISREG(st.st_mode):
            raise OSError(errno.EINVAL, "not a regular file (%s)" % kind_of(st.st_mode))
    except OSError:
        os.close(fd)
        raise
    return fd, st


def why_not_opened(exc):
    """(reason code, description) for a file that could not be opened: no text of the exception, which can name a path."""
    if isinstance(exc, ValueError):
        return "path_invalid", "ValueError: the path cannot be used as a file name (a NUL byte or a character the system cannot encode)"
    if getattr(exc, "errno", None) == errno.ELOOP:
        return "link_not_followed", describe(exc)
    if getattr(exc, "errno", None) == errno.EINVAL and "not a regular file" in str(getattr(exc, "strerror", "")):
        return "not_a_regular_file", describe(exc)
    return "read_failed", describe(exc)


class Budget:
    def __init__(self, total):
        self.total = total
        self.read = 0

    def allows(self, n):
        return self.read + n <= self.total

    def spend(self, n):
        self.read += n


class Spans:
    """The byte ranges read in one file, merged when they touch: a full scan is one range, a sampled file has one per window."""

    def __init__(self):
        self.spans = []

    def add(self, start, length):
        if self.spans and self.spans[-1][1] == start:
            self.spans[-1][1] = start + length
        else:
            self.spans.append([start, start + length])

    def inspected(self):
        return sum(e - s for s, e in self.spans)

    def gaps(self, size):
        out, at = [], 0
        for s, e in self.spans:
            if s > at:
                out.append((at, s - at))
            at = max(at, e)
        if at < size:
            out.append((at, size - at))
        return out


def plan_windows(size, window, policy, samples):
    """(offset, length) of the windows to read, in order. A full scan tiles the file. A sampled file is tiled too when it holds no more than
    `samples` windows, and otherwise gets `samples` windows of `window` bytes spread evenly from the first byte to the last, which cannot
    overlap (the spacing is more than `window`). Returns (iterator, contiguous)."""
    if size <= 0:
        return iter(()), True
    total = -(-size // window)
    if policy == "full" or total <= samples:
        return ((off, min(window, size - off)) for off in range(0, size, window)), True
    if samples == 1:
        return iter(((0, window),)), False
    return (((i * (size - window)) // (samples - 1), window) for i in range(samples)), False


def format_of(name, given):
    """(format, how it was named): the caller's word, else the first extension of the name that names a format, else none."""
    if given:
        return given, "caller"
    for part in name.lower().split(".")[1:]:
        if part in FORMATS:
            return FORMATS[part], "name"
    return None, None


def decodable(block, cut_at_start, cut_at_end):
    """Whether the bytes are UTF-8; a character cut by the edge of a sample (at the start or the end, where the sample was cut) is not a failure."""
    if cut_at_start:
        i = 0
        while i < 3 and i < len(block) and 0x80 <= block[i] < 0xC0:
            i += 1
        block = block[i:]
    for trim in ((0, 1, 2, 3) if cut_at_end else (0,)):
        try:
            block[:max(0, len(block) - trim)].decode("utf-8")
            return True
        except UnicodeDecodeError:
            continue
    return False


def structure_of(fd, size, fmt, budget):
    """Facts about the head and the end of a file, as booleans: the magic of the format, its footer, whether its directory parses.
    No byte is returned. None means the check does not apply to the format."""
    out = {"expected_format": fmt, "magic_present": None, "footer_present": None, "container_parses": None}
    if fmt is None:
        out["checked"] = False
        out["reason"] = "no format is named: the name has no extension of a supported format and the caller named none"
        return out
    head_n, tail_n = min(size, HEAD_READ), min(size, TAIL_READ)
    if not budget.allows(head_n + tail_n):
        out["checked"] = False
        out["reason"] = "read_budget_spent"
        return out
    head = pread_full(fd, head_n, 0)
    tail = pread_full(fd, tail_n, size - tail_n) if size else b""
    budget.spend(len(head) + len(tail))
    out["checked"] = True
    out["checked_bytes"] = {"head": len(head), "end": len(tail)}
    if fmt == "pdf":
        out["magic_present"] = head.startswith(b"%PDF-")
        out["footer_present"] = b"%%EOF" in tail[-1024:]
        m = re.search(rb"startxref\s+(\d+)\s", tail[-2048:])
        parses = False
        if m and len(m.group(1)) <= 18:
            at = int(m.group(1))
            if 0 <= at < size:
                probe = pread_full(fd, 32, at)
                budget.spend(len(probe))
                parses = bool(re.match(rb"\s*(xref|\d+\s+\d+\s+obj)", probe))
        out["container_parses"] = parses
    elif fmt == "zip":
        out["magic_present"] = head[:4] in (b"PK\x03\x04", b"PK\x05\x06")
        at = tail.rfind(b"PK\x05\x06")
        parses = False
        if at >= 0 and len(tail) - at >= 22:
            cd_size = int.from_bytes(tail[at + 12:at + 16], "little")
            cd_off = int.from_bytes(tail[at + 16:at + 20], "little")
            eocd = size - len(tail) + at
            if cd_size == 0xFFFFFFFF or cd_off == 0xFFFFFFFF:
                out["zip64"] = True
            elif cd_off + cd_size <= eocd:
                start = eocd - cd_size          # the directory ends where its end record begins; a prefix moves it
                probe = pread_full(fd, 4, start) if cd_size else b""
                budget.spend(len(probe))
                parses = cd_size == 0 or probe == b"PK\x01\x02"
        out["footer_present"] = at >= 0
        out["container_parses"] = parses
    elif fmt == "png":
        out["magic_present"] = head.startswith(b"\x89PNG\r\n\x1a\n")
        out["footer_present"] = size >= 12 and tail[-12:] == b"\x00\x00\x00\x00IEND\xaeB`\x82"
        out["container_parses"] = len(head) >= 24 and head[12:16] == b"IHDR" and head[8:12] == b"\x00\x00\x00\x0d"
    elif fmt == "jpeg":
        out["magic_present"] = head.startswith(b"\xff\xd8\xff")
        out["footer_present"] = tail.rstrip(b"\x00")[-2:] == b"\xff\xd9"
    elif fmt == "gif":
        out["magic_present"] = head[:6] in (b"GIF87a", b"GIF89a")
        out["footer_present"] = tail[-1:] == b"\x3b"
    elif fmt == "sqlite":
        out["magic_present"] = head.startswith(b"SQLite format 3\x00")
        if len(head) >= 18:
            page = int.from_bytes(head[16:18], "big")
            page = 65536 if page == 1 else page
            out["container_parses"] = 512 <= page <= 65536 and page & (page - 1) == 0 and size % page == 0
    elif fmt == "gzip":
        out["magic_present"] = head[:3] == b"\x1f\x8b\x08"
    elif fmt == "7z":
        out["magic_present"] = head[:6] == b"7z\xbc\xaf\x27\x1c"
        if len(head) >= 32:
            import zlib
            out["container_parses"] = zlib.crc32(head[12:32]) == int.from_bytes(head[8:12], "little")
    elif fmt == "text":
        end = tail[-HEAD_READ:] if size > HEAD_READ else b""
        out["magic_present"] = None
        out["container_parses"] = decodable(head, False, size > len(head)) and (not end or decodable(end, True, False)) and b"\x00" not in head + end
        out["text_decodable"] = out["container_parses"]
    return out


def layout_findings(fd, size, rules, threshold, budget):
    """Each rule of a supplied layout against the bytes it names: the observed entropy and whether it matches what the rule expects."""
    found = []
    for i, rule in enumerate(rules):
        length = rule["length"]
        if too_late(length):
            found.append({"rule": i, "result": "not_read", "reason": "time_limit"})
            continue
        start = rule["offset"] if rule["from"] == "start" else size - rule["offset"] - length
        if start < 0 or start + length > size:
            found.append({"rule": i, "result": "outside_file", "start": max(start, 0), "length": length})
            continue
        if not budget.allows(length):
            found.append({"rule": i, "result": "not_read", "reason": "read_budget_spent"})
            continue
        block = pread_full(fd, length, start)
        budget.spend(len(block))
        e = entropy_exact(block)
        high = e >= threshold
        want_high = rule["expect"] == "high_entropy"
        found.append({"rule": i, "start": start, "length": len(block), "expect": rule["expect"], "entropy": shown_entropy(e),
                      "result": "consistent" if high == want_high and len(block) == length else
                                ("inconsistent" if len(block) == length else "not_read")})
    return found


def inspect_file(ctx, file_id, shown_path, path, given_format, counterpart, authenticated, evidence):
    """Measure one file; returns its row (already sealed by the page it goes to) and updates the counters."""
    c = ctx["counters"]
    row = {"file": shown_path, "file_id": file_id}
    fd = cfd = None
    reason, error = None, None
    spans = Spans()
    hist = [0] * 8
    n_windows = high_windows = high_bytes = 0
    runs_total = 0
    run = None            # (start, length) of the run being extended
    last_end = None
    runs_shown = []
    pattern = {"len0": None, "period": None, "prev": None, "last_len": None, "regular": True}
    compared = equal = 0
    first_diff = last_diff = None
    cmp_state = None
    try:
        try:
            fd, st = open_regular(path)
        except (OSError, ValueError) as exc:
            code, text = why_not_opened(exc)
            row.update({"status": "not_inspected", "reason": code, "error": text})
            c["files_not_inspected"] += 1
            c["not_inspected_by_reason"][code] += 1
            return row
        size = st.st_size
        row["bytes"] = size
        c["bytes_named"] += size
        fmt, fmt_from = format_of(os.path.basename(path), given_format)
        cmp_row = None
        if counterpart is not None:
            cmp_row = {"file": display(counterpart), "authenticated_by_caller": authenticated,
                       "authentication": "recorded as the caller gave it; the tool does not verify it"}
            try:
                cfd, cst = open_regular(counterpart)
                if cst.st_size != size:
                    cmp_row.update({"compared": False, "reason": "size_differs", "counterpart_bytes": cst.st_size})
                    os.close(cfd)
                    cfd = None
                else:
                    cmp_state = True
            except (OSError, ValueError) as exc:
                code, text = why_not_opened(exc)
                cmp_row.update({"compared": False, "reason": code, "error": text})
                cfd = None
        windows, contiguous = plan_windows(size, ctx["window"], ctx["policy"], ctx["samples"])
        pending_short = False
        for off, length in windows:
            if too_late(length * (2 if cfd is not None else 1)):
                reason = "time_limit"
                break
            if not ctx["budget"].allows(length * (2 if cfd is not None else 1)):
                reason = "read_budget_spent"
                break
            began = time.monotonic()
            try:
                block = pread_full(fd, length, off)
            except OSError as exc:
                reason, error = "read_failed", describe(exc)
                break
            ctx["budget"].spend(len(block))
            if not block:
                reason = "file_shorter_than_when_opened"
                break
            e = entropy_exact(block)
            if len(block) >= 1 << 20:
                COST["per_byte"] = max(COST["per_byte"], (time.monotonic() - began) / len(block))
            high = e >= ctx["threshold"]
            spans.add(off, len(block))
            n_windows += 1
            hist[min(7, int(e))] += 1
            prow = {"record": "window", "file_id": file_id, "offset": off, "length": len(block), "entropy": shown_entropy(e), "high": high}
            if cfd is not None:
                try:
                    other = pread_full(cfd, len(block), off)
                except OSError as exc:
                    cmp_row.update({"compared": False, "reason": "read_failed", "error": describe(exc)})
                    os.close(cfd)
                    cfd = None
                    other = None
                if other is not None:
                    ctx["budget"].spend(len(other))
                    same = other == block
                    prow["equal_to_counterpart"] = same
                    compared += 1
                    equal += 1 if same else 0
                    if not same:
                        first_diff = off if first_diff is None else first_diff
                        last_diff = off
            ctx["profile"].add(prow)
            c["windows_inspected"] += 1
            if high:
                high_windows += 1
                high_bytes += len(block)
                if run is not None and last_end == off and contiguous:
                    run = (run[0], run[1] + len(block))
                else:
                    if run is not None:
                        runs_total, pattern = close_run(ctx, file_id, run, runs_total, runs_shown, pattern, False, size)
                    run = (off, len(block))
            elif run is not None:
                runs_total, pattern = close_run(ctx, file_id, run, runs_total, runs_shown, pattern, False, size)
                run = None
            last_end = off + len(block)
            if len(block) < length:
                reason, error = "file_shorter_than_when_opened", None
                break
        if run is not None:
            runs_total, pattern = close_run(ctx, file_id, run, runs_total, runs_shown, pattern, run[0] + run[1] >= size, size)
            run = None
        if cmp_row is not None and cmp_state and cfd is not None:
            cmp_row.update({"compared": True, "windows_compared": compared, "windows_equal": equal, "windows_differ": compared - equal,
                            "first_differing_offset": first_diff, "last_differing_offset": last_diff,
                            "basis": "each inspected window compared byte for byte with the window at the same offset of the counterpart; "
                                     "windows that were not inspected are not compared"})
        elif cmp_row is not None and "compared" not in cmp_row:
            cmp_row["compared"] = False
        if cmp_row is not None and not cmp_row.get("compared"):
            c["counterparts_unread"] += 1
            c["counterpart_reasons"][cmp_row.get("reason", "not_compared")] += 1
        gaps = spans.gaps(size)
        inspected = spans.inspected()
        for g_off, g_len in gaps:
            ctx["profile"].add({"record": "uninspected", "file_id": file_id, "offset": g_off, "length": g_len})
        if reason is None and gaps and ctx["policy"] == "sampling":
            reason = "policy_sampling"
        if size == 0:
            reason = None
        # structure, layout: after the windows, with what is left of the budget and the clock
        structure = None
        if ctx["structure"]:
            if out_of_time():
                structure = {"expected_format": fmt, "checked": False, "reason": "time_limit"}
            else:
                try:
                    structure = structure_of(fd, size, fmt, ctx["budget"])
                except OSError as exc:
                    structure = {"expected_format": fmt, "checked": False, "reason": "read_failed", "error": describe(exc)}
            structure["expected_from"] = fmt_from
        lay = None
        if ctx["layout"] is not None:
            lay = {"name": ctx["layout"]["name"], "validated_by_caller": ctx["layout"]["validated"],
                   "findings": layout_findings(fd, size, ctx["layout"]["rules"], ctx["threshold"], ctx["budget"]),
                   "note": "observations against the layout the caller supplied; they identify no family, and the tool does not validate the layout"}
        status = "inspected" if (reason is None and not gaps) else "partial"
        if inspected == 0 and size > 0:
            status = "not_inspected"
        row.update({"status": status, "policy": ctx["policy"], "windows_inspected": n_windows, "bytes_inspected": inspected,
                    "bytes_uninspected": size - inspected, "uninspected_ranges_total": len(gaps),
                    "uninspected_ranges": [{"offset": o, "length": n} for o, n in gaps[:INLINE_RANGES]]})
        if reason:
            row["reason"] = reason
        if error:
            row["error"] = error
        row["high_entropy_windows"] = high_windows
        row["high_entropy_bytes"] = high_bytes
        row["high_entropy_fraction"] = round(high_bytes / inspected, 4) if inspected else None
        row["fraction_basis"] = ("bytes in windows at or above the threshold over the bytes inspected, not over the file; it is not a "
                                 "percentage encrypted: compressed and random-looking formats are high entropy too")
        row["entropy_histogram"] = {"%d-%d" % (i, i + 1): n for i, n in enumerate(hist) if n}
        row["high_entropy_runs_total"] = runs_total
        row["high_entropy_runs"] = runs_shown
        if not contiguous:
            row["block_pattern"] = {"observed": False, "reason": "the windows are sampled and not contiguous: a run is one window and no spacing is measured"}
        else:
            row["block_pattern"] = block_pattern(pattern, runs_total)
        if structure is not None:
            row["structure"] = structure
        if cmp_row is not None:
            row["counterpart"] = cmp_row
        if lay is not None:
            row["layout"] = lay
        notes = []
        ext_parts = os.path.basename(path).lower().split(".")[1:]
        if high_windows and (any(p in COMPRESSED_EXTENSIONS for p in ext_parts) or (structure or {}).get("expected_format") in COMPRESSED):
            row["alternative_explanation"] = ("the name or the format names a format that is normally compressed or packed: high entropy is what it looks like whole")
        if n_windows and size > 0 and min(ctx["window"], size) < 1024:
            notes.append("a window of %d bytes reads about %.2f bits per byte when it is random: against a threshold of %s a window this "
                         "small seldom reaches it" % (min(ctx["window"], size), expected_random_entropy(min(ctx["window"], size)), ctx["threshold"]))
        if ctx["policy"] == "sampling" and gaps:
            notes.append("only the sampled windows were read: a region between them can differ from them, and an intermittent layout can fall between them")
        if notes:
            row["uncertainty"] = notes
        c["files_" + status] += 1
        if status == "not_inspected":
            c["not_inspected_by_reason"][reason or "nothing_read"] += 1
            if not reason:
                row["reason"] = "nothing_read"
        c["bytes_inspected"] += inspected
        c["bytes_uninspected"] += size - inspected
        c["high_entropy_windows"] += high_windows
        if reason and status == "partial":
            c["partial_by_reason"][reason] += 1
        ctx["profile"].add({"record": "file", "file_id": file_id, "bytes": size, "status": status, "windows": n_windows,
                            "bytes_inspected": inspected, "high_entropy_runs": runs_total}, None)
        return row
    finally:
        for d in (fd, cfd):
            if d is not None:
                try:
                    os.close(d)
                except OSError:
                    pass


def close_run(ctx, file_id, run, runs_total, shown_runs, pattern, reaches_end, size):
    """A run of adjacent high windows ends: it goes to the profile, the first few into the file's row, and the spacing is tracked."""
    start, length = run
    runs_total += 1
    ctx["counters"]["high_entropy_runs"] += 1
    entry = {"offset": start, "length": length}
    ctx["profile"].add({"record": "run", "file_id": file_id, **entry})
    if len(shown_runs) < INLINE_RUNS:
        shown_runs.append(entry)
    if pattern["regular"]:
        if pattern["len0"] is None:
            pattern["len0"] = length
        else:
            if pattern["last_len"] != pattern["len0"]:
                pattern["regular"] = False
            gap = start - pattern["prev"]
            if pattern["period"] is None:
                pattern["period"] = gap
            elif gap != pattern["period"]:
                pattern["regular"] = False
    pattern["prev"] = start
    pattern["last_len"] = length
    pattern["last_reaches_end"] = reaches_end
    return runs_total, pattern


def block_pattern(pattern, runs_total):
    if runs_total < 3 or not pattern["regular"] or pattern["period"] is None:
        return {"observed": False, "runs": runs_total}
    if pattern["last_len"] != pattern["len0"] and not pattern.get("last_reaches_end"):
        return {"observed": False, "runs": runs_total}
    return {"observed": True, "runs": runs_total, "run_bytes": pattern["len0"], "period_bytes": pattern["period"],
            "basis": "observation: runs of the same length at the same spacing, measured in whole windows; it names no family and "
                     "does not say that the gaps are plaintext"}


def read_census(path, statuses, ctx, files_out):
    """Yield (path, bytes) for each selected row of an encrypted_survey census, streaming; the receipt (its last line) is read first and its
    `parser` must be one this tool knows. `files_out` collects what the census itself says about its completeness."""
    fd, st = open_regular(path)
    try:
        size = st.st_size
        tail = pread_full(fd, min(size, MAX_LINE), max(0, size - MAX_LINE)).rstrip(b"\n")
        pieces = tail.rsplit(b"\n", 1)
        # the last line is whole when the tail starts at the file's start or holds a newline; a last line longer than MAX_LINE is not read
        last = pieces[-1] if (size <= MAX_LINE or len(pieces) == 2) else b""
        receipt = None
        try:
            doc = json.loads(last) if last else None
            receipt = doc if isinstance(doc, dict) and doc.get("record") == "receipt" else None
        except (ValueError, RecursionError):
            receipt = None
        if receipt is None:
            files_out["receipt"] = "missing"
        else:
            parser = receipt.get("parser")
            files_out["receipt"] = "present"
            files_out["parser"] = parser[:80] if isinstance(parser, str) else None
            if parser not in ACCEPTED_CENSUS_PARSERS:
                fail("the census was written by a parser this tool does not read: %r (it reads %s); an unknown version is refused, not guessed at"
                     % (parser[:80] if isinstance(parser, str) else parser, ", ".join(ACCEPTED_CENSUS_PARSERS)))
            files_out["receipt_status"] = receipt.get("status") if isinstance(receipt.get("status"), str) else None
        with os.fdopen(os.dup(fd), "rb") as handle:
            while True:
                if out_of_time():
                    files_out["stopped_by_clock"] = True
                    return
                line = handle.readline(MAX_LINE + 1)
                if not line:
                    return
                files_out["rows"] = files_out.get("rows", 0) + 1
                if len(line) > MAX_LINE:
                    files_out["rows_too_long"] = files_out.get("rows_too_long", 0) + 1
                    while line and not line.endswith(b"\n"):
                        line = handle.readline(MAX_LINE + 1)
                        if out_of_time():
                            files_out["stopped_by_clock"] = True
                            return
                    continue
                try:
                    row = json.loads(line)
                except (ValueError, RecursionError):
                    files_out["rows_unreadable"] = files_out.get("rows_unreadable", 0) + 1
                    continue
                if not isinstance(row, dict) or row.get("record") != "file":
                    continue
                if row.get("status") not in statuses:
                    files_out["rows_not_selected"] = files_out.get("rows_not_selected", 0) + 1
                    continue
                name = row.get("file")
                if not isinstance(name, str) or not name:
                    files_out["rows_unreadable"] = files_out.get("rows_unreadable", 0) + 1
                    continue
                yield name
    finally:
        os.close(fd)


KNOWN_PARAMS = {"files", "census", "census_statuses", "policy", "window", "threshold", "sample_windows", "layout", "limit",
                "read_budget_bytes", "max_seconds", "check_structure"}
FILE_KEYS = {"path", "format", "counterpart", "counterpart_authenticated"}


def int_param(args, key, default, low, high=None, why=""):
    value = args.get(key, default)
    if isinstance(value, bool) or not isinstance(value, int):
        fail("%s must be an integer" % key)
    if value < low:
        fail("%s must be at least %d" % (key, low))
    if high is not None and value > high:
        fail("%s must be at most %d%s" % (key, high, why))
    return value


def string_param(value, what):
    if not isinstance(value, str) or not value:
        fail("%s must be a non-empty string" % what)
    return value


def read_layout(value):
    if not isinstance(value, dict):
        fail("layout must be an object: {name, validated, rules: [{from, offset, length, expect}]}")
    unknown = sorted(k for k in value if k not in ("name", "validated", "source", "rules"))
    if unknown:
        fail("layout has keys this tool does not read (name, validated, source, rules)")
    name = string_param(value.get("name"), "layout.name")
    validated = value.get("validated", False)
    if not isinstance(validated, bool):
        fail("layout.validated must be true or false (the caller's word: the tool does not validate a layout)")
    rules = value.get("rules")
    if not isinstance(rules, list) or not rules or len(rules) > MAX_RULES:
        fail("layout.rules must be a list of 1 to %d rules" % MAX_RULES)
    clean = []
    for rule in rules:
        if not isinstance(rule, dict) or set(rule) - {"from", "offset", "length", "expect"}:
            fail("each layout rule is {from: start|end, offset, length, expect: high_entropy|not_high_entropy}")
        origin, off, length, expect = rule.get("from"), rule.get("offset"), rule.get("length"), rule.get("expect")
        if origin not in ("start", "end") or expect not in ("high_entropy", "not_high_entropy"):
            fail("a layout rule's from is start or end, and its expect is high_entropy or not_high_entropy")
        for label, n, low, high in (("offset", off, 0, 1 << 62), ("length", length, 1, MAX_WINDOW)):
            if isinstance(n, bool) or not isinstance(n, int) or n < low or n > high:
                fail("a layout rule's %s must be an integer from %d to %d" % (label, low, high))
        clean.append({"from": origin, "offset": off, "length": length, "expect": expect})
    return {"name": name, "validated": validated, "source": value.get("source") if isinstance(value.get("source"), str) else None, "rules": clean}


def main():
    install_signal_handlers(last_word)
    try:
        args = json.load(sys.stdin)
    except (ValueError, RecursionError):
        fail("arguments are not valid JSON")
    if not isinstance(args, dict):
        fail("arguments must be a JSON object")
    policy = args.get("policy")
    if policy not in ("sampling", "full"):
        fail("policy is required and is declared: sampling (a bounded number of windows spread over each file) or full (every byte, while the budget and the clock last)")
    window = int_param(args, "window", DEFAULT_WINDOW, MIN_WINDOW, MAX_WINDOW)
    threshold = args.get("threshold", DEFAULT_THRESHOLD)
    if isinstance(threshold, bool) or not isinstance(threshold, (int, float)) or not math.isfinite(threshold) or not (0 < threshold <= 8):
        fail("threshold must be a number above 0 and at most 8 (bits per byte)")
    samples = int_param(args, "sample_windows", DEFAULT_SAMPLE_WINDOWS, 1, MAX_SAMPLE_WINDOWS)
    limit = int_param(args, "limit", 200, 1, 1000000000)
    budget = Budget(int_param(args, "read_budget_bytes", DEFAULT_BUDGET, MIN_BUDGET, 1 << 50))
    max_seconds = int_param(args, "max_seconds", DEFAULT_SECONDS, 1, MAX_SECONDS, " (the tool's own clock; the manifest's timeout is 900)")
    check_structure = args.get("check_structure", True)
    if not isinstance(check_structure, bool):
        fail("check_structure must be true or false")
    statuses = args.get("census_statuses", ["candidate"])
    if (not isinstance(statuses, list) or not statuses or len(statuses) > len(CENSUS_STATUSES)
            or not all(isinstance(s, str) and s in CENSUS_STATUSES for s in statuses)):
        fail("census_statuses is a list of census statuses: " + ", ".join(CENSUS_STATUSES))
    layout = read_layout(args["layout"]) if "layout" in args else None
    files = args.get("files")
    census_path = args.get("census")
    if files is None and census_path is None:
        fail("name what to measure: files (a list of paths) or census (the path of an encrypted_survey census)")
    entries = []
    if files is not None:
        if not isinstance(files, list) or not files:
            fail("files must be a non-empty list of paths or {path, format, counterpart, counterpart_authenticated} objects")
        if len(files) > MAX_FILES:
            fail("files holds at most %d entries; name an encrypted_survey census to measure more" % MAX_FILES)
        for item in files:
            if isinstance(item, str):
                item = {"path": item}
            if not isinstance(item, dict) or set(item) - FILE_KEYS:
                fail("each file is a path or an object with the keys path, format, counterpart, counterpart_authenticated")
            path = item.get("path")
            if not isinstance(path, str) or not path:
                fail("each file needs a non-empty path")
            fmt = item.get("format")
            if fmt is not None and fmt not in FORMAT_NAMES:
                fail("format is one of: " + ", ".join(FORMAT_NAMES))
            cp = item.get("counterpart")
            if cp is not None and (not isinstance(cp, str) or not cp):
                fail("counterpart must be a non-empty path")
            auth = item.get("counterpart_authenticated", False)
            if not isinstance(auth, bool):
                fail("counterpart_authenticated must be true or false (the caller's word)")
            entries.append((path, fmt, cp, auth))
    if census_path is not None:
        string_param(census_path, "census")
    unknown = sorted(k for k in args if k not in KNOWN_PARAMS)
    set_deadline(max_seconds)

    key = [policy, window, threshold, samples, "profile"]
    try:
        profile = Profile(key)
        profile_problem = None
    except OSError as exc:
        profile, profile_problem = NoProfile(), "the profile file could not be created (%s): the windows are measured and counted, they are not kept" % describe(exc)
    files_page = NoReplacePage("encryption_extent", [policy, window, threshold, samples, "files"], limit)
    counters = {"files_named": 0, "files_inspected": 0, "files_partial": 0, "files_not_inspected": 0, "windows_inspected": 0,
                "high_entropy_windows": 0, "high_entropy_runs": 0, "bytes_named": 0, "bytes_inspected": 0, "bytes_uninspected": 0,
                "not_inspected_by_reason": collections.Counter(), "partial_by_reason": collections.Counter(), "empty_files": 0,
                "counterparts_unread": 0, "counterpart_reasons": collections.Counter()}
    PROGRESS["coverage"] = counters
    ctx = {"counters": counters, "window": window, "policy": policy, "samples": samples, "threshold": threshold, "budget": budget,
           "profile": profile, "layout": layout, "structure": check_structure}
    census_facts = {}
    stopped = {}

    def work(path, fmt, cp, auth, from_census):
        counters["files_named"] += 1
        file_id = counters["files_named"]
        withheld = from_census and WITHHELD in path
        shown_path = display(path)
        if withheld:
            row = {"file": shown_path, "file_id": file_id, "status": "not_inspected", "reason": "name_withheld_in_census",
                   "error": "the census printed a name withheld by the survey's rule: there is no path to open"}
            counters["files_not_inspected"] += 1
            counters["not_inspected_by_reason"]["name_withheld_in_census"] += 1
        else:
            row = inspect_file(ctx, file_id, shown_path, path, fmt, cp, auth, None)
            if row.get("bytes") == 0:
                counters["empty_files"] += 1
        files_page.add(row, evidence_of(os.path.basename(path)) if not withheld else None)

    for path, fmt, cp, auth in entries:
        if out_of_time():
            stopped["files_not_examined"] = len(entries) - counters["files_named"]
            break
        work(path, fmt, cp, auth, False)
    if census_path is not None and not stopped:
        try:
            for name in read_census(census_path, set(statuses), ctx, census_facts):
                if out_of_time():
                    census_facts["stopped_by_clock"] = True
                    break
                work(name, None, None, False, True)
        except (OSError, ValueError) as exc:
            code, text = why_not_opened(exc)
            fail("the census could not be read (%s)" % text)
    if census_facts.get("stopped_by_clock"):
        stopped["census_rows_not_read"] = True

    page_summary = finish_page(files_page)
    pages = {"files": page_summary}
    OWN_NAMES.update(p["all_results"] for p in pages.values() if p.get("all_results"))

    c = counters
    reasons = []
    if not c["files_named"]:
        reasons.append("no file was measured: %s" % ("the census held no row of the selected statuses (%s)" % ", ".join(statuses) if census_path is not None
                                                      else "none was named"))
    if c["files_not_inspected"]:
        reasons.append("%d files were not inspected (%s)" % (c["files_not_inspected"], ", ".join("%s %d" % kv for kv in sorted(c["not_inspected_by_reason"].items()))))
    if c["partial_by_reason"].get("policy_sampling"):
        reasons.append("policy sampling: %d files have bytes outside the sampled windows (%d bytes in all were not inspected; the ranges are in the "
                       "profile file)" % (c["partial_by_reason"]["policy_sampling"], c["bytes_uninspected"]))
    for code, n in sorted(c["partial_by_reason"].items()):
        if code != "policy_sampling":
            reasons.append("%d files were left partly unread: %s" % (n, code))
    if census_facts.get("receipt") == "missing":
        reasons.append("the census has no receipt line: it is itself partial, and the files it lists are not all the files the survey visited")
    elif census_facts.get("receipt_status") not in (None, "complete"):
        reasons.append("the census's own receipt says %s: files the survey did not examine are not in it" % census_facts.get("receipt_status"))
    for field, text in (("rows_too_long", "census lines were longer than %d bytes and were skipped" % MAX_LINE),
                        ("rows_unreadable", "census lines could not be read as a file row and were skipped")):
        if census_facts.get(field):
            reasons.append("%d %s" % (census_facts[field], text))
    if stopped.get("files_not_examined"):
        reasons.append("the time limit (max_seconds %d) was reached: %d named files were not examined" % (max_seconds, stopped["files_not_examined"]))
    if stopped.get("census_rows_not_read"):
        reasons.append("the time limit (max_seconds %d) was reached while the census was being read: the rows after the last one read were not read "
                       "(their number is not known)" % max_seconds)
    if c["counterparts_unread"]:
        reasons.append("%d counterparts could not be compared (%s)" % (c["counterparts_unread"], ", ".join("%s %d" % kv for kv in sorted(c["counterpart_reasons"].items()))))
    clock_cut = bool(c["partial_by_reason"].get("time_limit") or c["not_inspected_by_reason"].get("time_limit"))
    if profile_problem:
        reasons.append(profile_problem)
    if BOUNDARY["replaced"]:
        reasons.append("%d strings held an identifier-shaped text that the first rule missed and were replaced at the output (see boundary)"
                       % BOUNDARY["replaced"])
    if c["files_named"] and not c["bytes_inspected"]:
        reasons.append("no byte was inspected")
    complete = "partial" if reasons else "complete"
    basis = ("; ".join(reasons) if reasons else
             "every named file was opened and every one of its bytes was inspected under policy full; the read budget and the time limit "
             "were not reached")
    exp = expected_random_entropy(window)
    receipt = {"parser": PARSER, "complete": complete, "status": complete, "status_basis": basis, "partial_reasons": reasons,
               "coverage": {k: (dict(v) if isinstance(v, collections.Counter) else v) for k, v in counters.items()},
               "parameters": {"policy": policy, "window": window, "threshold": threshold, "sample_windows": samples,
                              "read_budget_bytes": budget.total, "max_seconds": max_seconds}}
    if getattr(profile, "shown", None):
        OWN_NAMES.add(profile.shown)
    answer = release({
        "parser": PARSER,
        "complete": complete,
        "status": complete,
        "status_basis": basis,
        "partial_reasons": reasons,
        "policy": policy,
        "window": window,
        "sample_windows": samples if policy == "sampling" else None,
        "measures": "Where, in the bytes that were read, the entropy of a window of %d bytes is at or above %s bits per byte; the runs of adjacent "
                    "windows that are; the structure at the head and the end of the file; and, when the caller supplies them, a comparison with a "
                    "plaintext counterpart and the observations against a layout. It does not measure how much of any file was encrypted, whether a "
                    "file is recoverable, or which family wrote it." % (window, threshold),
        "high_entropy_fraction_note": "high_entropy_fraction is the share of the inspected bytes that lie in high-entropy windows. It is not a percentage "
                                      "encrypted: compressed, packed and random-looking formats are high entropy too, and bytes that were not inspected say nothing.",
        "uncertainty": "Entropy of a window is a statistic of its bytes, not a decryption test. A partial or intermittent pattern is reported as an observed "
                       "block pattern and is not a family. A pattern finer than the window is not located. The bytes listed as uninspected were not "
                       "read, and nothing here applies to them.",
        "threshold": {"value": threshold, "window": window, "random_data_reads_about": round(exp, 3), "reachable_by_random_data": exp >= threshold,
                      "basis": "the default 7.5 is this pack's (encrypted_survey's head threshold), so that the two tools agree on what is high; "
                               "the reverse-engineering pack uses 7.2 to find packed regions of executables, which is too low to keep compressed "
                               "data apart from encrypted data. Compared unrounded; entropy prints to three places."},
        "coverage": {k: (dict(v) if isinstance(v, collections.Counter) else v) for k, v in counters.items()},
        "bytes_read": budget.read,
        "read_budget_bytes": budget.total,
        "time_limit": {"max_seconds": max_seconds, "reached": bool(stopped) or clock_cut, **stopped},
        "census": ({"file": "the census named by the census parameter", **census_facts} if census_path is not None else None),
        "files": files_page.page,
        "profile": None if profile_problem else {"file": profile.shown, "rows": profile.rows,
                                                  "scope": "one row per window read (offset, length, entropy, high), per high-entropy run, per "
                                                           "uninspected range and per file, then a receipt; the file rows say where the answer's rows are"},
        "pages": pages,
        "truncated": any(p["truncated"] for p in pages.values()),
        "paths_withheld": WITHHELD_PATHS[0],
        **({"unrecognised_parameters": unknown} if unknown else {}),
    })
    if getattr(profile, "shown", None):
        OWN_NAMES.add(profile.shown)
    profile.finish(receipt)
    if getattr(profile, "shown", None):
        OWN_NAMES.add(profile.shown)
        if isinstance(answer.get("profile"), dict):
            answer["profile"]["file"] = profile.shown
    print_answer(answer, indent=2)


if __name__ == "__main__":
    exit_code = 0
    try:
        try:
            main()
        except SystemExit as exc:
            if exc.code not in (0, None):
                drop_temporary_files()
            raise
        except Exception as exc:  # never an empty or clean answer for a failure
            hold_stop_signals()
            drop_temporary_files()
            detail = describe(exc) if isinstance(exc, OSError) else "%s at %s" % (type(exc).__name__, where_it_failed(exc))
            fail("unexpected failure: %s" % detail)
    except SystemExit as stop:
        exit_code = _code(stop)
    _leave(exit_code)
