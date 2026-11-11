#!/usr/bin/env python3
"""Read a Windows shell link (.lnk), or every link structure in a slice of a dump.

What is decoded, by the layout MS-SHLLINK gives it: the 76-byte header (flags,
attributes, the three FILETIMEs with their raw values, size, show command), the
LinkInfo structure (flags, VolumeID with drive type, serial number and label,
LocalBasePath and CommonPathSuffix in ANSI and in Unicode, CommonNetworkRelativeLink
with net name, device name and provider type), the string data, and the extra data
blocks it recognises. What is only a heuristic: `idlist_ascii`, `idlist_paths` and
`utf16_strings` are printable runs searched for in the bytes, not a decode of the
shell item list. ANSI strings are in the writer's code page, which the file does
not say; they are shown as Latin-1 and the Unicode form, where the file has one,
is preferred. The tool executes nothing, resolves no target and reads no file the
link points to.

Args, JSON on stdin: path (or dump), offset, size, scan, each, max. A read that ends
inside the structure says so under `problems` and `structure_complete`.
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
#   not printed (3.11 and 3.12 say nothing of it, 3.14 a traceback). A handler that was due runs on the way in: what it raises reaches the
#   writer that asked (the tool's own handling then answers the stop, before any byte of the answer), or, quietly, is dropped (the end of a
#   call, an error branch). Every writer of a final answer calls it before it commits to writing, every error branch at the end calls it
#   quietly, and, when the file runs as a program, standard output is wrapped so that its first write calls it too. _code(stop) is a
#   SystemExit's exit code (its text, if it has one, goes to standard error as the interpreter puts it), and _leave(code) ends the call: both
#   hold the signals first, quietly; _leave flushes
#   standard output (a write that fails there makes a 0 an exit 120, as the interpreter does) and standard error, runs the atexit hooks (a hook
#   that removes a temporary file), each step on its own and none able to raise, and ends the process with os._exit, never through the teardown.
# The modules are imported here, as the file is loaded, never inside the ending (an import there ran a due handler inside the import system).
import atexit
import json
import os
import signal
import sys

_ENDING = {"held": False, "program": __name__ == "__main__"}      # imported (a test that loads the file as a module), the block holds nothing
_ENDING_SIGNALS = (signal.SIGTERM, signal.SIGINT, signal.SIGHUP)


def answer_a_stop(signum, when="before it had answered"):
    """The one document of a stop that ends the call before any answer was begun (nothing once one has): status failed, interrupted, and
    no claim about what was read or written. A handler whose own last word printed nothing calls it before it ends the process. It writes
    only when the file runs as a program: its wrapped standard output is what knows whether an answer was begun."""
    if _ENDING["held"] or not isinstance(sys.stdout, _AnswerStream):
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


def hold_stop_signals(quietly=False):
    """Hold the stop signals for good. A handler that was due runs on the way in, before the hold and before any byte of the answer, and what
    it raises is raised here, so that the tool's own handling of a stop answers it; quietly (the end of a call, an error branch, where nothing
    may escape) it is dropped and the hold is made all the same. Called by a thread that is not the main one, it blocks the signals there and
    leaves the rest to the main thread's next call."""
    for _attempt in range(len(_ENDING_SIGNALS) + 2):
        if _ENDING["held"] or not _ENDING["program"]:
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
        except BaseException:  # noqa: BLE001 - a handler that was due ran on the way in, and raised
            if not quietly:
                raise



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
    hold_stop_signals(quietly=True)
    code = getattr(stop, "code", 1)
    if isinstance(code, int):
        return code
    if code is not None:
        try:
            sys.stderr.flush()
            os.write(2, ("%s\n" % (code,)).encode("utf-8", "backslashreplace"))
        except BaseException:  # noqa: BLE001
            pass
    return 0 if code is None else 1


def _leave(code):
    hold_stop_signals(quietly=True)
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
    if sys.stdout is not None and not isinstance(sys.stdout, _AnswerStream):
        sys.stdout = _AnswerStream(sys.stdout)
    for _signum in _ENDING_SIGNALS:
        signal.signal(_signum, _stopped_without_handler)
# END SHARED ENDS


import array, json, sys, struct, datetime, os, stat
from pathlib import Path

PARSER = "lnk_parse/7"
MAX_READ = 256 * 1024 * 1024
DEADLINE_SECONDS = 24             # the manifest allows 30: the read, the walks and the scan stop here, so that the pages are placed and the answer printed before the harness ends it
MAX_LIMIT = 10000                 # the largest inline page; the whole result is in the file the answer names
EXTRA_INLINE = 50                 # ExtraData blocks shown inline per link; every block is counted and the whole list is in a file the answer names
TRACKER_KEEP = 16                 # tracker blocks kept in the decoded link whatever the inline page holds (a link has one; the rest are counted)
PROGRESS = {"phase": "starting", "offset": 0}

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
    if "answer_a_stop" in globals():     # (a block run on its own, by a test, has no ENDS block)
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
    answer cut. A signal that is held is not answered once the answer is out (the shared ENDS block): the answer stands, and the call ends
    with its own exit code."""
    try:
        signal.pthread_sigmask(signal.SIG_BLOCK, {signal.SIGTERM, signal.SIGINT, signal.SIGHUP})
    except (AttributeError, ValueError, OSError):
        pass
    hold_stop_signals()
    STOP["last_word"] = None
    print(json.dumps(answer, **dumps_kwargs))


install_signal_handlers(lambda signum: interrupted_answer(signum))
# END SHARED STOP


FILETIME_EPOCH = datetime.datetime(1601, 1, 1, tzinfo=datetime.timezone.utc)


def ft(raw):
    """A FILETIME (100 ns ticks since 1601-01-01 UTC) as ISO 8601 UTC with all seven
    fractional digits, from integer arithmetic only; None for 0, all ones or a date
    past year 9999. The raw value is kept beside it by the caller."""
    if not raw or raw == 0xFFFFFFFFFFFFFFFF:
        return None
    try:
        whole, ticks = divmod(raw, 10_000_000)
        moment = FILETIME_EPOCH + datetime.timedelta(seconds=whole)
        return moment.strftime("%Y-%m-%dT%H:%M:%S") + ".%07dZ" % ticks
    except (OverflowError, ValueError):
        return None


class SecretValuesRefused(Exception):
    pass


def describe(exc):
    if isinstance(exc, OSError):
        return "%s: %s" % (type(exc).__name__, exc.strerror or exc)
    return "%s: %s" % (type(exc).__name__, exc)


class SecretValues:
    """Where a value goes when, and only when, the caller asked for it.

    The secret-safe output pattern of docs/packs.md ("Secrets and sensitive output"),
    copied from its reference implementation (recovery_key_scan, encrypted-containers)
    and parameterised by the tool, the flag and the file's name. Call `add` once per
    finding with the finding's id, its locator and the value. With `enabled` false it
    writes nothing and `summary()` says so.
    """

    def __init__(self, enabled, tool, flag, name):
        self.enabled = enabled
        self.tool = tool
        self.flag = flag
        self.name = name
        self.written = 0
        self._fh = None
        self.job = os.environ.get("JOB_ID") or ""
        self.out = os.environ.get("OUT") or ""
        self.path = None
        self.shown = None
        if not enabled:
            return
        if not (self.job and self.out):
            raise SecretValuesRefused(
                "%s is refused outside a job: a value written here would be an ordinary "
                "file, not a sealed secret output. Run this as job_run tool=%s with "
                "secret_output: true, and ask again there. Nothing was written." % (flag, tool)
            )
        if os.environ.get("SECRET_OUTPUT") != "1":
            raise SecretValuesRefused(
                "%s is refused: the values are written only in a job the harness runs as secret output (job_run with "
                "secret_output: true, which the manifest declares for this parameter). Nothing was written." % flag
            )
        self.path = Path(self.out) / name
        self.shown = "store/jobs/%s/out/%s" % (re.sub(r"[^A-Za-z0-9_.-]", "_", self.job), name)
        # Created now, before anything is scanned: a file or a link already at that name is
        # refused by name at once (O_EXCL does not follow a link, a dangling one included),
        # instead of failing, or writing through it, after the scan. With nothing found it
        # stays as an empty file, mode 0600, and the answer says written: 0.
        try:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            fd = os.open(str(self.path), os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o600)
        except FileExistsError:
            raise SecretValuesRefused("the values file already exists: %s" % self.path)
        except OSError as exc:
            raise SecretValuesRefused("the values file could not be created: %s (%s)" % (self.path, describe(exc)))
        self._fh = os.fdopen(fd, "w", encoding="utf-8")

    def add(self, finding_id, locator, value):
        if not self.enabled:
            return
        text = json.dumps({"finding_id": finding_id, **locator, "value": value}, ensure_ascii=False)
        try:
            text.encode("utf-8")
        except UnicodeEncodeError:
            text = json.dumps({"finding_id": finding_id, **locator, "value": value}, ensure_ascii=True)
        self._fh.write(text)
        self._fh.write("\n")
        self.written += 1

    def close(self):
        if self._fh is not None:
            self._fh.flush()
            os.fsync(self._fh.fileno())
            self._fh.close()
            self._fh = None

    def summary(self, format_note):
        return {
            "requested": self.enabled,
            "written": self.written,
            "values_file": self.shown if self.enabled else None,
            "contains_secret_values": self.written > 0,
            "format": format_note if self.enabled else None,
        }


# --- what a link can carry that the answer must not print ---------------------------------------------------
#
# A link carries free text a person or a program wrote: its arguments, a description, a working directory, a path. Any of
# it can hold a secret (`-u admin --password Hunter2`, `https://user:pw@host/`, a token in a path). Arguments and the
# string scan are never printed inline (only their length, whether there are any and, for the arguments, a first word that
# can only be a switch name or a program). A path-like field is printed unless it has the shape of a secret, when a marker
# holding only its length stands in its place. The values themselves go, when `write_strings` asks for them and only in a job,
# to a 0600 file under $OUT, each under a finding id the answer cites.
# The shapes one expression finds. A URL with a password and a web token are not among them: their expressions are tried at every
# letter of a long run of name characters, run to the end of the run, fail there and start again one character on, so that a string of
# 65,535 characters (the longest a link records) cost the square of its length and took 25 s. `secret_shaped` reads both in one pass
# over the runs instead, and gives the answer the single expression gave (a test holds them equal).
SECRET_SHAPES = re.compile(
    r"(?i)(?:pass(?:word|wd|phrase)?|pwd|secret|token|api[-_]?key|access[-_]?key|client[-_]?secret|credential|private[-_]?key|bearer|authorization)s?\s*[=:]\s*\S"
    r"|\bAKIA[0-9A-Z]{16}\b|\bgh[pousr]_[A-Za-z0-9]{20,}|\bxox[abprs]-[A-Za-z0-9-]{10,}"
    r"|-----BEGIN [A-Z ]*PRIVATE KEY"
    r"|(?:^|\s)--?(?:p|pw|pass|passw|password|passwd|pwd|token|secret|apikey|api-key)\s+\S"
)
# a run of scheme characters that stands right before `://`; it starts where its run starts (the look-behind), so a run is read once
SCHEME_RUN = re.compile(r"(?i)(?<![a-z0-9+.-])[a-z0-9+.-]+(?=://)")
SCHEME_LETTER = re.compile(r"(?i)[a-z]")
USERINFO_TAIL = re.compile(r"[^/\s:@]+:[^/\s@]+@")
NAME_RUN = re.compile(r"(?i)[A-Za-z0-9_-]+")
JWT_HEAD = re.compile(r"(?i)\beyJ")


def url_with_password(text):
    """Whether the text holds `scheme://user:password@`: a scheme is a run of letters, digits, `+`, `.` and `-` that holds a letter and
    stands right before `://` (the first letter of the run is as good a start as any other), so each run is looked at once."""
    for run in SCHEME_RUN.finditer(text):
        if SCHEME_LETTER.search(run.group()) and USERINFO_TAIL.match(text, run.end() + 3):
            return True
    return False


def web_token(text):
    """Whether the text holds a JSON web token: `eyJ` at a word boundary, ten or more name characters, a `.`, ten or more more. Every
    `eyJ` of a run of name characters reads the same rest of the run, so the first one decides: when it has ten characters after it
    and a `.` and ten more follow the run, the text holds a token, and when it does not no later `eyJ` of the run does either."""
    at = 0
    while True:
        head = JWT_HEAD.search(text, at)
        if head is None:
            return False
        end = NAME_RUN.match(text, head.start()).end()
        if end - head.end() >= 10 and text[end:end + 1] == ".":
            second = NAME_RUN.match(text, end + 1)
            if second is not None and second.end() - second.start() >= 10:
                return True
        at = end


def secret_shaped(text):
    """Whether the text has the shape of a secret: a name assigned a value, a URL with a password, a web token, a vendor key, a private
    key, a password option. Linear in the length of the text."""
    return SECRET_SHAPES.search(text) is not None or url_with_password(text) or web_token(text)


# A switch is shown only when its name is one of these, exactly (case does not matter): a token such as `-pSECRET` or `/pSECRET` is a switch
# name and its value in one word, and no pattern tells the two apart, so every other switch-shaped word is withheld.
KNOWN_SWITCHES = frozenset(s.lower() for s in (
    "-noprofile", "-nop", "-noni", "-noninteractive", "-nologo", "-sta", "-mta", "-w", "-win", "-window", "-windowstyle", "-hidden", "-enc", "-e",
    "-ec", "-encodedcommand", "-ep", "-executionpolicy", "-bypass", "-c", "-command", "-f", "-file", "-version", "-psconsolefile", "-inputformat",
    "-outputformat", "-noexit", "-config", "-help", "-h", "-?", "--help", "--version", "--silent", "--quiet", "--verbose", "--no-sandbox",
    "-k", "-q", "-s", "-r", "-i", "-u", "-v", "-y", "-n", "-x", "-a", "-d", "-t", "-l", "-o", "-m", "-p",
    "/c", "/k", "/q", "/s", "/r", "/i", "/u", "/v", "/y", "/n", "/x", "/a", "/d", "/t", "/l", "/o", "/m", "/p", "/e", "/f", "/w", "/?", "/min", "/max",
    "/select", "/root", "/separate", "/idlist", "/noconfirm", "/silent", "/quiet", "/passive", "/norestart", "/forcerestart", "/qn", "/qb", "/log",
))
SWITCH = re.compile(r"^[-/]{1,2}[A-Za-z?][A-Za-z0-9_?-]{0,31}$")
PROGRAM_FILE = re.compile(r"^[A-Za-z0-9_.:\\ -]{1,80}\.(?:exe|com|bat|cmd|ps1|vbs|vbe|js|jse|wsf|hta|dll|msi|msc|cpl|scr|py|jar|lnk)$", re.I)
PROGRAM_WORDS = {"cmd", "powershell", "pwsh", "wscript", "cscript", "mshta", "rundll32", "regsvr32", "msiexec", "explorer",
                 "python", "perl", "node", "java", "bash", "sh", "wsl", "schtasks", "sc", "net", "reg", "start"}


def withheld_marker(text):
    return "[withheld: %d characters]" % len(text)


class Held:
    """What the answer withholds, and where it goes when the caller asked: one finding id each, in order. With the
    values file off nothing is written, and the ids still say which locator is which."""

    def __init__(self, values):
        self.values = values
        self.count = 0

    def _next(self):
        self.count += 1
        return "L%06d" % self.count

    def hold(self, locator, value):
        finding = self._next()
        self.values.add(finding, locator, value)
        return finding

    def hold_text(self, locator, pieces):
        """A long text, written (when asked) in pieces, a surrogate pair never split; `pieces` is not iterated otherwise."""
        finding = self._next()
        if self.values.enabled:
            previous, index = None, 0
            for piece in pieces():
                if previous is not None:
                    self.values.add(finding, {**locator, "piece": index - 1, "continued_in_next": True}, previous)
                previous, index = piece, index + 1
            if previous is not None:
                self.values.add(finding, {**locator, "piece": index - 1, "continued_in_next": False}, previous)
        return finding


# A string longer than this is not read for the shape of a secret: no path, name or description of a link is a quarter of a million
# characters long (the string data of a link holds 65,535 at most), so it is withheld whole, by its length, and the sink row says so.
SCAN_LIMIT = 1 << 18


def guard(held, sink, locator, text):
    """A string of the link as the answer may show it: itself, or, when it has the shape of a secret (or is too long to be read for
    one), a marker."""
    if isinstance(text, str):
        too_long = len(text) > SCAN_LIMIT
        if too_long or secret_shaped(text):
            finding = held.hold(locator, text)
            row = {"field": locator["field"], "chars": len(text), "finding_id": finding}
            if too_long:
                row["not_scanned"] = "longer than %d characters: withheld whole, not read for the shape of a secret" % SCAN_LIMIT
            sink.append(row)
            return withheld_marker(text)
    return text


def guard_keys(held, sink, base_off, container, keys, prefix=""):
    for key in keys:
        if key in container:
            container[key] = guard(held, sink, {"link_offset": base_off, "field": prefix + key}, container[key])


def first_token(arguments):
    """The first word of the arguments when it can only be a switch's name, a program or a script (the value of a
    `--switch=value` is cut off), else None: any other first word may be the secret itself."""
    text = arguments.strip()
    if not text:
        return None
    if text[0] in "\"'":
        end = text.find(text[0], 1)
        token = text[1:end] if end > 0 else text[1:]
    else:
        token = text.split(None, 1)[0]
    token = token.split("=", 1)[0]
    if len(token) > SCAN_LIMIT or secret_shaped(token):
        return None
    if token.lower() in KNOWN_SWITCHES or PROGRAM_FILE.match(token) or token.lower() in PROGRAM_WORDS:
        return token
    return None


# --- the UTF-16 string scan, a window at a time ---------------------------------------------------------------------
UNIT_WINDOW = 1 << 20
NONZERO_UNITS = re.compile(rb"[^\x00]+")
MIN_STRING_UNITS = 6


def utf16_runs(data, start):
    """The runs of non-zero 16-bit units in data[start:], even-aligned to `start`, as (first unit, end unit). One
    window of units is looked at at a time: a unit is non-zero when either of its two bytes is, found by one
    OR over the two halves, so a file of zeros or of one repeated byte costs a pass, not a Python loop per unit."""
    units = (len(data) - start) // 2
    run = None
    pos = 0
    while pos < units:
        if out_of_time():
            raise ClockStop(start + 2 * pos)
        take = min(UNIT_WINDOW, units - pos)
        base = start + 2 * pos
        low = data[base:base + 2 * take:2]
        high = data[base + 1:base + 2 * take:2]
        mask = (int.from_bytes(low, "little") | int.from_bytes(high, "little")).to_bytes(take, "little")
        for m in NONZERO_UNITS.finditer(mask):
            a, b = pos + m.start(), pos + m.end()
            if run is not None and run[1] == a:
                run = (run[0], b)
            else:
                if run is not None:
                    yield run
                run = (a, b)
        pos += take
    if run is not None:
        yield run


LETTER_CANDIDATE = re.compile(r"[^\W\d_]")


def run_has_letter(data, start, a, b):
    """Whether the run holds a letter (str.isalpha). The regular expression finds the candidates at C speed, a run of
    digits or punctuation costs a pass and no Python loop, and each candidate is confirmed by isalpha itself."""
    step = 1 << 16
    for u in range(a, b, step):
        if out_of_time():
            raise ClockStop(start + 2 * u)
        chunk = data[start + 2 * u:start + 2 * min(u + step, b)]
        if any(m.group().isalpha() for m in LETTER_CANDIDATE.finditer(chunk.decode("utf-16-le", "replace"))):
            return True
    return False


def run_pieces(data, start, a, b, size=1 << 16):
    """The text of a run in pieces of at most `size` units (a high surrogate takes its pair with it)."""
    u = a
    while u < b:
        e = min(u + size, b)
        if e < b and 0xD8 <= data[start + 2 * (e - 1) + 1] <= 0xDB:
            e += 1
        yield data[start + 2 * u:start + 2 * e].decode("utf-16-le", "replace")
        u = e


DRIVE_TYPES = {0: "unknown", 1: "no root directory", 2: "removable", 3: "fixed", 4: "remote", 5: "CD-ROM", 6: "RAM disk"}
# WNNC_NET_* values MS-SHLLINK lists; only the one every SMB share carries is named here,
# and the raw value is always returned beside it.
PROVIDER_TYPES = {0x00020000: "LANMAN (Microsoft Windows Network, SMB)"}


def cstr(buf, off, wide=False):
    """A NUL-terminated string at `off` in `buf`, ANSI (Latin-1, the code page is not
    recorded) or UTF-16LE, or None when `off` is outside the buffer."""
    if off < 0 or off >= len(buf):
        return None
    if wide:
        # The first even-aligned pair of zero bytes, found a megabyte at a time by the array's own search (a Python loop over a
        # 100 MB structure took minutes); the string runs to the end of an odd-length buffer when there is none.
        end, stop = off, off + 2 * ((len(buf) - off) // 2)
        while end < stop:
            take = min(stop - end, 1 << 20)
            units = array.array("H")
            units.frombytes(bytes(buf[end:end + take]))
            try:
                end += 2 * units.index(0)
                break
            except ValueError:
                end += take
        return buf[off:end].decode("utf-16-le", "replace")
    z = buf.find(b"\x00", off)
    return buf[off:len(buf) if z < 0 else z].decode("latin1")


def parse_volume_id(vid, problems):
    """VolumeID (MS-SHLLINK 2.3.1): size, drive type, serial number, label offset, and
    the Unicode label offset when the label offset is 0x14."""
    if len(vid) < 0x10:
        problems.append("VolumeID is %d bytes, shorter than its 16-byte fixed part" % len(vid))
        return None
    size, drive, serial, label_off = struct.unpack_from("<IIII", vid, 0)
    out = {
        "size": size,
        "drive_type": drive,
        "drive_type_name": DRIVE_TYPES.get(drive, "not a defined drive type"),
        "serial_number": "%08X" % serial,
    }
    if label_off == 0x14 and len(vid) >= 0x14:
        wide_off = struct.unpack_from("<I", vid, 0x10)[0]
        out["label_unicode"] = cstr(vid, wide_off, wide=True)
        out["label"] = out["label_unicode"]
    else:
        out["label_ansi"] = cstr(vid, label_off)
        out["label"] = out["label_ansi"]
    return out


def parse_network_link(cnrl, problems):
    """CommonNetworkRelativeLink (MS-SHLLINK 2.3.2): size, flags, net name offset, device
    name offset, provider type, and the Unicode offsets when the net name offset is above 0x14."""
    if len(cnrl) < 0x14:
        problems.append("CommonNetworkRelativeLink is %d bytes, shorter than its 20-byte fixed part" % len(cnrl))
        return None
    size, flags, net_off, dev_off, provider = struct.unpack_from("<IIIII", cnrl, 0)
    out = {
        "size": size,
        "flags": flags,
        "valid_device": bool(flags & 1),
        "valid_net_type": bool(flags & 2),
        "net_name": cstr(cnrl, net_off),
        "device_name": cstr(cnrl, dev_off) if flags & 1 else None,
        "provider_type": "0x%08X" % provider if flags & 2 else None,
    }
    if flags & 2 and provider in PROVIDER_TYPES:
        out["provider_name"] = PROVIDER_TYPES[provider]
    if net_off > 0x14 and len(cnrl) >= 0x1C:
        net_u, dev_u = struct.unpack_from("<II", cnrl, 0x14)
        out["net_name_unicode"] = cstr(cnrl, net_u, wide=True)
        if flags & 1 and dev_u:
            out["device_name_unicode"] = cstr(cnrl, dev_u, wide=True)
    return out


def parse_linkinfo(li, problems):
    """LinkInfo (MS-SHLLINK 2.3), field by field in the order the specification gives:
    LinkInfoSize, LinkInfoHeaderSize, LinkInfoFlags, VolumeIDOffset, LocalBasePathOffset,
    CommonNetworkRelativeLinkOffset, CommonPathSuffixOffset, then LocalBasePathOffsetUnicode
    and CommonPathSuffixOffsetUnicode when the header is 0x24 bytes or more. Every offset
    is from the start of LinkInfo."""
    size, hsize, flags, vol_off, local_off, net_off, suffix_off = struct.unpack_from("<7I", li, 0)
    out = {"linkinfo_size": size, "linkinfo_header_size": hsize, "linkinfo_flags": flags}
    if hsize < 0x1C:
        problems.append("LinkInfoHeaderSize is %d, below the 28 bytes the layout needs; LinkInfo is not decoded" % hsize)
        return out
    local_u = suffix_u = 0
    if hsize >= 0x24:
        if len(li) < 0x24:
            problems.append("LinkInfo is shorter than the header it declares")
            return out
        local_u, suffix_u = struct.unpack_from("<II", li, 0x1C)
    has_volume = bool(flags & 1)
    has_network = bool(flags & 2)
    out["has_volume_id_and_local_base_path"] = has_volume
    out["has_common_network_relative_link"] = has_network
    if has_volume:
        vid_size = struct.unpack_from("<I", li, vol_off)[0] if 0 < vol_off <= len(li) - 4 else 0
        vid = li[vol_off:vol_off + vid_size] if vid_size else b""
        if not vid:
            problems.append("VolumeIDOffset %d is outside LinkInfo (%d bytes)" % (vol_off, len(li)))
        else:
            out["volume"] = parse_volume_id(vid, problems)
        out["local_base_path_ansi"] = cstr(li, local_off) if local_off else None
        if local_u:
            out["local_base_path_unicode"] = cstr(li, local_u, wide=True)
        out["local_base_path"] = out.get("local_base_path_unicode") or out["local_base_path_ansi"]
    if has_network:
        cn_size = struct.unpack_from("<I", li, net_off)[0] if 0 < net_off <= len(li) - 4 else 0
        cnrl = li[net_off:net_off + cn_size] if cn_size else b""
        if not cnrl:
            problems.append("CommonNetworkRelativeLinkOffset %d is outside LinkInfo (%d bytes)" % (net_off, len(li)))
        else:
            out["network"] = parse_network_link(cnrl, problems)
    out["common_path_suffix_ansi"] = cstr(li, suffix_off) if suffix_off else None
    if suffix_u:
        out["common_path_suffix_unicode"] = cstr(li, suffix_u, wide=True)
    out["common_path"] = out.get("common_path_suffix_unicode") or out["common_path_suffix_ansi"]
    # The target path MS-SHLLINK defines: the local base path joined to the suffix, or the
    # network name joined to it.
    if has_volume and out.get("local_base_path") is not None:
        out["linkinfo_target"] = out["local_base_path"] + (out["common_path"] or "")
        out["linkinfo_target_kind"] = "local"
    elif has_network and out.get("network") and out["network"].get("net_name") is not None:
        net_name = out["network"].get("net_name_unicode") or out["network"]["net_name"]
        out["linkinfo_target"] = net_name + ("\\" + out["common_path"] if out["common_path"] else "")
        out["linkinfo_target_kind"] = "network"
    return out


def parse_idlist(data, off, size):
    items = []
    end = off + size
    p = off
    while p+2 <= end:
        sz = struct.unpack_from('<H', data, p)[0]
        if sz < 2 or p+sz > end:
            break
        blob = data[p:p+sz]
        # try ascii and utf16
        s = ''.join(chr(b) if 32<=b<127 else '' for b in blob)
        items.append({'size': sz, 'ascii': s})
        p += sz
    return items

def parse_lnk(data, base_off, held, strings, extras_sink=None):
    """Decode one link structure. `extras_sink` (a page) receives every ExtraData block as a row; `out['extra']` holds the first EXTRA_INLINE and
    `extra_count` how many there are, so that a structure of millions of tiny blocks is read in bounded memory."""
    if len(data) < 0x4C or data[0:4] != b'L\x00\x00\x00' or data[4:20] != bytes.fromhex('0114020000000000c000000000000046'):
        return {'ok': False, 'error': 'not a LNK header'}
    flags = struct.unpack_from('<I', data, 0x14)[0]
    attr = struct.unpack_from('<I', data, 0x18)[0]
    c,a,w = struct.unpack_from('<QQQ', data, 0x1C)
    flen, icon_idx, show, hot = struct.unpack_from('<IIII', data, 0x34)
    p = 0x4C
    problems = []
    sink = []          # what this link's answer withholds: field, characters, finding id
    stop_reading = False
    out = {
        'ok': True,
        'parser': PARSER,
        'offset': base_off,
        'flags': flags,
        'flags_hex': hex(flags),
        'file_attr': attr,
        'created': ft(c),
        'accessed': ft(a),
        'written': ft(w),
        # Raw FILETIMEs as decimal strings: a JSON number past 2**53 is not exact in every reader.
        'created_filetime': str(c),
        'accessed_filetime': str(a),
        'written_filetime': str(w),
        'time_basis': 'FILETIME, 100 ns ticks since 1601-01-01 UTC, as the link recorded them; they are the target file\'s times when the link was last written, not the link file\'s',
        'file_length': flen,
        'show_cmd': show,
    }
    if flags & 0x1 and p+2 <= len(data):
        id_size = struct.unpack_from('<H', data, p)[0]
        p += 2
        out['idlist_size'] = id_size
        if p + id_size > len(data):
            problems.append("the shell item list declares %d bytes and %d were read; read more bytes (size)" % (id_size, len(data) - p))
            stop_reading = True
        blob = data[p:p+id_size]
        out['idlist_ascii'] = guard(held, sink, {'link_offset': base_off, 'field': 'idlist_ascii'}, ''.join(chr(b) if 32<=b<127 else '.' for b in blob))
        # extract path-like utf16/ascii from extra
        paths = []
        # SHELL_ITEM file entries often have utf16 name at end
        q = 0
        while q+2 <= len(blob):
            isz = struct.unpack_from('<H', blob, q)[0]
            if isz < 2 or q+isz > len(blob):
                break
            item = blob[q:q+isz]
            # look for drive "C:\\" ascii
            if b':' in item:
                ascii = ''.join(chr(b) if 32<=b<127 else '' for b in item)
                if ascii:
                    paths.append(ascii)
            # utf16 strings
            try:
                u = item.decode('utf-16le', errors='ignore')
                u = ''.join(ch if ch.isprintable() else ' ' for ch in u).strip()
                if len(u) >= 3 and any(x in u.lower() for x in ['.exe','.lnk','.dll','.ps1','users','windows','temp','appdata',':\\','http']):
                    paths.append(u)
            except Exception:
                pass
            q += isz
        out['idlist_paths'] = [guard(held, sink, {'link_offset': base_off, 'field': 'idlist_paths[%d]' % n}, x) for n, x in enumerate(paths)]
        p += id_size
    if flags & 0x2:
        if p + 4 > len(data):
            problems.append("HasLinkInfo is set but the read ends before LinkInfo starts; read more bytes")
        else:
            li_size = struct.unpack_from('<I', data, p)[0]
            if li_size < 0x1C:
                problems.append("LinkInfoSize is %d, below the 28 bytes of its header; LinkInfo and what follows it are not read" % li_size)
                stop_reading = True
            elif li_size > len(data) - p:
                problems.append("LinkInfo declares %d bytes and %d were read from it; read more bytes (size)" % (li_size, len(data) - p))
                stop_reading = True
            else:
                info = parse_linkinfo(data[p:p + li_size], problems)
                guard_keys(held, sink, base_off, info, ('local_base_path_ansi', 'local_base_path_unicode', 'local_base_path',
                                                         'common_path_suffix_ansi', 'common_path_suffix_unicode', 'common_path', 'linkinfo_target'))
                if isinstance(info.get('volume'), dict):
                    guard_keys(held, sink, base_off, info['volume'], ('label', 'label_ansi', 'label_unicode'), 'volume.')
                if isinstance(info.get('network'), dict):
                    guard_keys(held, sink, base_off, info['network'], ('net_name', 'net_name_unicode', 'device_name', 'device_name_unicode'), 'network.')
                out.update(info)
                p += li_size
    # string data in order based on flags
    def read_str(pp, nm, unicode=bool(flags & 0x80)):
        if pp+2 > len(data):
            problems.append("the %s string starts past the end of what was read" % nm)
            return None, pp
        n = struct.unpack_from('<H', data, pp)[0]
        pp += 2
        if unicode:
            nbytes = n*2
        else:
            nbytes = n
        if pp + nbytes > len(data):
            problems.append("the %s string declares %d characters and the read ends inside it; it is cut at the end of what was read" % (nm, n))
        raw = data[pp:pp+nbytes]
        s = raw.decode('utf-16le', errors='replace') if unicode else raw.decode('latin1', errors='replace')
        pp += nbytes
        return s, pp
    names = []
    bit_names = [(0x4,'name'),(0x8,'relative_path'),(0x10,'working_dir'),(0x20,'arguments'),(0x40,'icon_location')]
    out['arguments_present'] = False
    for bit, nm in bit_names:
        if flags & bit and not stop_reading:
            s, p = read_str(p, nm)
            if nm == 'arguments':
                # Never printed: its length, whether there are any, and a first word only when that can only be a
                # switch name or a program. The text goes to the values file when it was asked for.
                out['arguments_present'] = True
                out['arguments_chars'] = len(s) if s is not None else 0
                token = first_token(s) if s else None
                out['arguments_first_token'] = token
                if s:
                    out['arguments_finding_id'] = held.hold({'link_offset': base_off, 'field': 'arguments'}, s)
                    if token is None:
                        out['arguments_first_token_withheld'] = True
                    sink.append({'field': 'arguments', 'chars': len(s), 'finding_id': out['arguments_finding_id']})
            else:
                out[nm] = guard(held, sink, {'link_offset': base_off, 'field': nm}, s)
            names.append((nm, s))
    # extra blocks, up to the terminal block. When the bytes read end first the
    # structure runs past them, and structure_complete says so.
    extras = []            # the first EXTRA_INLINE blocks, in order
    trackers = []          # the first TRACKER_KEEP tracker blocks, wherever they stand
    extra_count = tracker_count = 0
    stopped_by_clock = False
    complete = False
    while p+4 <= len(data) and not stop_reading:
        if not (extra_count & 255) and out_of_time():
            stopped_by_clock = True
            break
        PROGRESS['offset'] = base_off + p
        bsz = struct.unpack_from('<I', data, p)[0]
        if bsz < 4:
            complete = True
            break
        if bsz < 8 or p+bsz > len(data):
            break
        sig = struct.unpack_from('<I', data, p+4)[0]
        blk = data[p:p+bsz]
        rec = {'size': bsz, 'sig': hex(sig)}
        at = extra_count       # the block's place in the list, which the field names of the sink rows carry
        if sig == 0xA0000001:  # environment
            rec['env_ascii'] = guard(held, sink, {'link_offset': base_off, 'field': 'extra[%d].env_ascii' % at}, blk[8:8+260].split(b'\x00',1)[0].decode('latin1','replace'))
            rec['env_u16'] = guard(held, sink, {'link_offset': base_off, 'field': 'extra[%d].env_u16' % at}, blk[8+260:].decode('utf-16le','replace').split('\x00',1)[0] if len(blk)>268 else None)
        elif sig == 0xA0000003:  # tracker
            rec['tracker'] = guard(held, sink, {'link_offset': base_off, 'field': 'extra[%d].tracker' % at}, blk[8:64].decode('latin1','replace',).split('\x00')[0] if len(blk)>16 else None)
            # machine name at +16 typically
            rec['machine'] = guard(held, sink, {'link_offset': base_off, 'field': 'extra[%d].machine' % at}, blk[16:16+16].split(b'\x00',1)[0].decode('latin1','replace') if len(blk)>32 else None)
            # the two 32-byte droid pairs (volume and object identifiers), whole
            if len(blk) >= 96:
                rec['droid_hex'] = blk[32:64].hex()
                rec['droid_birth_hex'] = blk[64:96].hex()
            tracker_count += 1
            if len(trackers) < TRACKER_KEEP:
                trackers.append({'machine': rec.get('machine'), 'droid_hex': rec.get('droid_hex'), 'droid_birth_hex': rec.get('droid_birth_hex'), 'block': at})
        elif sig == 0xA0000007:  # icon environment: the same two paths as the environment block
            icon_ascii = blk[8:8+260].split(b'\x00',1)[0].decode('latin1','replace')
            icon_u16 = blk[8+260:].decode('utf-16le','replace').split('\x00',1)[0] if len(blk)>268 else None
            rec['icon_env_ascii'] = guard(held, sink, {'link_offset': base_off, 'field': 'extra[%d].icon_env_ascii' % at}, icon_ascii)
            rec['icon_env_u16'] = guard(held, sink, {'link_offset': base_off, 'field': 'extra[%d].icon_env_u16' % at}, icon_u16)
            if rec['icon_env_ascii'] == icon_ascii and rec['icon_env_u16'] == icon_u16:
                rec['hex'] = blk.hex()          # the hex would give a withheld path back
        else:
            # A block this reader does not know can hold anything: the first characters inline (their shape judged
            # like any other field), its length, and the whole of it in the values file when it was asked for.
            printable = ''.join(chr(b) if 32<=b<127 else '.' for b in blk[:128])
            rec['ascii'] = guard(held, sink, {'link_offset': base_off, 'field': 'extra[%d].ascii' % at}, printable)
            rec['ascii_chars'] = len(blk)
            if len(blk) > 128:
                rec['ascii_inline_cut'] = True
                rec['ascii_finding_id'] = held.hold({'link_offset': base_off, 'field': 'extra[%d].block_hex' % at}, blk.hex())
        extra_count += 1
        if len(extras) < EXTRA_INLINE:
            extras.append(rec)
        if extras_sink is not None:
            extras_sink.add({'link_offset': base_off, 'block': at, **rec})
        p += bsz
        if bsz == 0:
            break
    if stopped_by_clock:
        problems.append("the ExtraData walk stopped at block %d (byte %d of the structure) because the tool's own clock (%d s) ran out; the blocks after it were not read" % (extra_count, p, DEADLINE_SECONDS))
        out['stopped_by_time_limit'] = True
    out['extra'] = extras
    out['extra_count'] = extra_count
    out['extra_not_shown'] = extra_count - len(extras)
    out['tracker'] = trackers
    out['tracker_count'] = tracker_count
    out['structure_complete'] = complete
    if not complete and not problems:
        problems.append("the read ends before the terminal block; read more bytes (size) to complete the structure")
    out['problems'] = problems
    out['heuristic_fields'] = ['idlist_ascii', 'idlist_paths', 'utf16_strings (locators; the text is in the values file)', 'extra[].ascii', 'extra[].tracker', 'extra[].machine']
    out['bytes_read'] = len(data)
    # The UTF-16 string scan: a run of at least six non-zero units with a letter in it, even-aligned from the end of
    # the header. The text is never in the answer: its offset and length are (the page `strings`), and the text is
    # in the values file under the finding id when write_strings asked for it.
    found = 0
    scanned_runs = 0
    try:
        for a, b in utf16_runs(data, 0x4C):
            scanned_runs += 1
            if not (scanned_runs & 1023) and out_of_time():
                raise ClockStop(0x4C + 2 * a)
            if b - a >= MIN_STRING_UNITS and run_has_letter(data, 0x4C, a, b):
                found += 1
                at = 0x4C + 2 * a
                finding = held.hold_text({'link_offset': base_off, 'field': 'utf16_string', 'offset': at},
                                         lambda a=a, b=b: run_pieces(data, 0x4C, a, b))
                strings.add({'link_offset': base_off, 'offset': at, 'file_offset': base_off + at, 'chars': b - a, 'finding_id': finding})
    except ClockStop as stop:
        problems.append("the UTF-16 string scan stopped at byte %d of the structure because the tool's own clock (%d s) ran out; the strings after it were not searched" % (stop.args[0], DEADLINE_SECONDS))
        out['stopped_by_time_limit'] = True
    out['utf16_string_count'] = found
    if sink:
        out['sensitive_fields_withheld'] = sink
    return out

class ClockStop(Exception):
    """The tool's own clock ran out inside a walk."""


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
    print_answer({'error': message, 'status': 'failed', 'status_basis': 'the tool stopped with an error and read no result (see error)', **extra})
    sys.exit(1)


def last_word(signum):
    interrupted_answer(signum, phase=PROGRESS['phase'], offset_reached=PROGRESS['offset'])


def whole(args, name, default, low=0, high=None):
    v = args.get(name)
    if v is None or v == 0 and name in ('size', 'max'):
        v = default
    if isinstance(v, bool) or not isinstance(v, int) or v < low or (high is not None and v > high):
        fail('%s must be a whole number%s' % (name, ' from %d to %d' % (low, high) if high is not None else ' of at least %d' % low))
    return v


def read_slice(src, offset, size):
    """The bytes at [offset, offset+size) of the file, read in pieces with the clock looked at, into one buffer sized by what the file can give.
    Returns (data, file_size, stopped_at) where stopped_at is the byte count read when the clock ran out, else None."""
    with open(src, 'rb') as f:
        file_size = os.fstat(f.fileno()).st_size
        want = max(0, min(size, file_size - offset))
        buf = bytearray(want)
        view = memoryview(buf)
        f.seek(offset)
        got = 0
        while got < want:
            if out_of_time():
                return buf[:got], file_size, got
            n = f.readinto(view[got:min(want, got + (8 << 20))])
            if not n:
                break
            got += n
            PROGRESS['offset'] = offset + got
        return (buf if got == want else buf[:got]), file_size, None


def main():
    set_deadline(DEADLINE_SECONDS)
    install_signal_handlers(last_word)
    try:
        args = json.load(sys.stdin)
    except ValueError as exc:
        fail('arguments are not valid JSON', reason=str(exc))
    if not isinstance(args, dict):
        fail('the arguments must be a JSON object')
    path = args.get('path')
    offset = whole(args, 'offset', 0)
    size = whole(args, 'size', 4096, 1, MAX_READ)
    limit = whole(args, 'limit', 50, 1, MAX_LIMIT)
    write_strings = args.get('write_strings', False)
    if not isinstance(write_strings, bool):
        fail('write_strings must be true or false')
    scan = args.get('scan', False)
    if not isinstance(scan, bool):
        fail('scan must be true or false')
    dump = args.get('dump')  # if set, read from dump at offset
    src = dump or path
    if not src:
        fail('need path or dump')
    if not isinstance(src, str):
        fail('path and dump must be file paths')
    if scan:
        limit_hits = whole(args, 'max', 50, 1, MAX_LIMIT)
        each = args.get('each')
        if each is not None:
            each = whole(args, 'each', 0, 1, MAX_READ)
    if write_strings and os.environ.get('SECRET_OUTPUT') != '1':
        fail('write_strings is refused: the text of a link is written only in a job the harness runs as secret output (job_run with secret_output: true), '
             'where the file is a sealed secret output. Nothing was opened or created.')
    if not os.path.isfile(src):
        if os.path.exists(src):
            fail('not a regular file (a directory, a FIFO, a socket or a device is not opened)', path=src, not_attempted=1)
        fail('no such file', path=src)

    values = None
    for number in range(1, 1000):
        name = 'lnk-strings.jsonl' if number == 1 else 'lnk-strings-%d.jsonl' % number
        try:
            values = SecretValues(write_strings, 'lnk_parse', 'write_strings', name)
            break
        except SecretValuesRefused as exc:
            # A values file of an earlier run in this job is never replaced and never a reason not to read the link:
            # the next free number is this run's file, and the answer names it.
            if write_strings and 'already exists' in str(exc):
                continue
            fail(str(exc))
    if values is None:
        fail('no free name for the values file after 999 tries')
    held = Held(values)

    PROGRESS['phase'] = 'reading the file'
    try:
        data, file_size, read_stopped = read_slice(src, offset, size)
    except OSError as exc:
        values.close()
        fail('the file could not be read', path=src, reason=describe(exc))
    clock_note = None
    if read_stopped is not None:
        clock_note = "the tool's own clock (%d s) ran out while the file was read: %d of the %d bytes asked for were read" % (DEADLINE_SECONDS, read_stopped, min(size, max(0, file_size - offset)))
    if read_stopped is not None and not data:
        values.close()
        print_answer({'parser': PARSER, 'source': src, 'status': 'partial', 'status_basis': clock_note + ': nothing was decoded', 'stopped_by_time_limit': True,
                      'offset': offset, 'bytes_read': 0, 'file_bytes': file_size}, indent=2)
        return
    strings = NoReplacePage("lnk_parse", [src, offset, size, 'strings'], limit)
    extras_page = NoReplacePage("lnk_parse-extra", [src, offset, size, 'extra', each if scan else None], EXTRA_INLINE)
    summary = lambda: {
        'secret_values': values.summary('JSON Lines, mode 0600: finding_id, link_offset, field, [offset, piece, continued_in_next,] value'),
        'findings_held': held.count,
    }

    def string_paging(answer):
        page = strings.finish()
        answer['utf16_strings'] = strings.page
        answer['utf16_strings_page'] = page
        answer['utf16_strings_note'] = ('offsets and lengths of the UTF-16 text found by search (runs of six or more non-zero units with a letter); '
                                        'the text is not in this answer: write_strings, in a job, writes it to the values file under each finding_id')

    def extra_paging(answer):
        page = extras_page.finish()
        answer['extra_blocks_total'] = page['matched']
        if page.get('all_results'):
            answer['all_extra_blocks'] = page['all_results']
            answer['all_extra_blocks_format'] = 'JSON Lines, one ExtraData block per line (link_offset, block, size, sig and the decoded fields)'

    PROGRESS['phase'] = 'decoding'
    if scan:
        magic = bytes.fromhex('4c0000000114020000000000c000000000000046')

        def link_starts():
            i = 0
            while True:
                j = data.find(magic, i)
                if j < 0:
                    return
                yield j
                i = j + 4

        hits = NoReplacePage("lnk_parse", [src, offset, size, each], limit_hits)
        incomplete = 0
        stopped = clock_note
        starts = link_starts()
        current = next(starts, None)
        while current is not None:
            if out_of_time():
                stopped = stopped or ("the tool's own clock (%d s) ran out after %d candidates, at byte %d of the slice: the rest of the slice was not decoded" % (DEADLINE_SECONDS, hits.total, current))
                break
            following = next(starts, None)
            # Without `each`, a link runs to the next header or to the end of
            # what was read, never to a fixed cut.
            stop = current + each if each else (following if following is not None else len(data))
            rec = parse_lnk(data[current:stop], offset + current, held, strings, extras_page)
            rec['rel'] = current
            rec['source'] = src
            if not rec.get('structure_complete'):
                incomplete += 1
            hits.add(rec)
            current = following
        page = hits.finish()
        values.close()
        beyond = max(0, file_size - offset - len(data))
        reasons = []
        if stopped:
            reasons.append(stopped)
        if incomplete:
            reasons.append('%d candidate(s) ended before their terminal block (structures_incomplete)' % incomplete)
        if beyond and not stopped:
            reasons.append('%d byte(s) of the file lie past the slice that was read and were not searched (offset, size)' % beyond)
        answer = {'parser': PARSER, 'source': src,
                  'status': 'partial' if reasons else 'complete',
                  'status_basis': '; '.join(reasons) if reasons else 'the %d-byte slice at offset %d was searched whole (to the end of the file) and every candidate structure was read to its terminal block' % (len(data), offset),
                  'stopped_by_time_limit': bool(stopped),
                  'count': page['matched'], 'hits': hits.page, **page,
                  'structures_incomplete': incomplete,
                  'offset': offset, 'bytes_read': len(data), 'file_bytes': file_size,
                  **summary(),
                  'note': 'a scan finds link structures by their 20-byte header signature (carving); a hit is a candidate, and `structure_complete` and `problems` say how much of it was read. Arguments and the string scan are not printed: see arguments_chars, utf16_strings and secret_values'}
        extra_paging(answer)
        string_paging(answer)
        print_answer(answer, indent=2)
        return
    rec = parse_lnk(data, offset, held, strings, extras_page)
    rec['source'] = src
    values.close()
    if not rec.get('ok'):
        # Not what it was read as: how many bytes, and nothing of their content (it can be anything).
        rec['bytes_read'] = len(data)
        rec['starts_with_link_header'] = False
        rec['status'] = 'failed'
        rec['status_basis'] = 'the bytes read do not begin with a shell link header, so nothing was decoded'
        drop_pages()
        print_answer(rec, indent=2)
        sys.exit(1)
    rec.update(summary())
    reasons = []
    if clock_note:
        reasons.append(clock_note)
    if rec.get('stopped_by_time_limit'):
        reasons.append("the tool's own clock (%d s) ran out inside the structure (see problems)" % DEADLINE_SECONDS)
    if not rec.get('structure_complete'):
        reasons.append('the structure did not end at its terminal block (structure_complete is false; see problems)')
    elif rec.get('problems'):
        reasons.append('%d problem(s) are named under problems' % len(rec['problems']))
    rec['status'] = 'partial' if reasons else 'complete'
    rec['status_basis'] = '; '.join(reasons) if reasons else 'the structure was read from its header to its terminal block and no problem is named'
    extra_paging(rec)
    string_paging(rec)
    print_answer(rec, indent=2)


if __name__ == "__main__":
    exit_code = 0
    try:
        try:
            main()
        except SystemExit:
            raise
        except OSError as exc:
            fail('a file operation failed: %s' % describe(exc), reason=type(exc).__name__)
        except Exception as exc:                                  # whatever hostile input does, the answer is JSON
            hold_stop_signals(quietly=True)
            drop_pages()
            print_answer({'error': 'the read failed', 'status': 'failed', 'status_basis': 'the tool stopped with an unexpected error',
                          'reason': '%s: %s' % (type(exc).__name__, exc)})
            sys.exit(1)
    except SystemExit as stop:
        exit_code = _code(stop)
    _leave(exit_code)
