#!/usr/bin/env python3
"""String candidates for URLs, `file:` and `Visited:` entries and 192.168.x.x addresses in a file.

This is a STRING SCANNER, not a browser parser. It says where a URL-shaped or history-shaped run of
characters is in the bytes of a file, in two encodings:

  ascii     `http://` or `https://` followed by at least six URL characters, to the first byte that is not
            one. No length is cut off: a URL of any length is returned whole.
  utf16le   a run of at least eight UTF-16LE characters that begins with a printable ASCII character
            (its second byte 0, which also fixes the run's alignment) and contains `http`, `file:`,
            `visited:` or `192.168`. After that first character the run goes on through printable
            ASCII, Latin-1 and the letters of Latin Extended, Greek, Cyrillic, Hebrew, Arabic, Indic and
            Thai (not CJK: its code units are pairs of ASCII letters), so `https://örnek.test/` is one
            candidate; a NUL, a control character, a surrogate or any other code unit ends it.
            The run is everything printable around the anchor, not a parsed URL.

Every occurrence is kept, with its byte offset and its encoding: an offset is where the run starts, and
the same text twice is two candidates. A `groups` view lists each distinct text once with its occurrence
count and first offset (bounded: past `max_distinct` distinct texts the view stops growing and says so; every
occurrence is still in the candidates). A string is a candidate: nothing here says it was visited, typed,
downloaded or opened by anyone.

SENSITIVE OUTPUT. A URL can carry a session token or a password in its query string, its fragment or its
user-info. Every candidate's text is returned with those values replaced by a marker that holds only
their length, `url_secrets_withheld` says how many, of what kind and at which offset, and `contains` is
matched against the text as returned (so it cannot be used to test a guess at a withheld value). The text
is written whole only with `write_url_secrets: true`, in a job run with secret_output: true, to a file under
$OUT of mode 0600; the request is refused anywhere else. A secret in a path or in free text is not found.

The file is read in windows of `chunk` bytes with a carry, never whole, so a match that straddles a window
is found once. A run that touches the end of a window and is longer than the carry is cut there and goes on in
the next window as a piece (`continued: true` on every piece but the last), so the memory is bounded and no
character is lost.
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


import hashlib
import json
import os
import re
import sys
import tempfile
from pathlib import Path

PARSER = "utf16_urls/5"
DEADLINE_SECONDS = 54             # the manifest allows 60: the scan stops here, so that the pages are placed and the answer printed before the harness ends it
MAX_CHUNK = 32 * 1024 * 1024      # a window of this size costs about four times its size in memory (the window, its carry, the next read, the match)
MAX_LIMIT = 10000                 # the largest inline page; the whole result is in the file the answer names
MAX_DISTINCT = 1_000_000          # distinct strings counted (memory); past it the groups are said to be incomplete
MAX_CONTAINS = 1000
PROGRESS = {"offset": 0}
DEFAULT_CHUNK = 8 * 1024 * 1024
CARRY = 64 * 1024
URL_CHARS = rb"[A-Za-z0-9._~:/?#\[\]@!$&'()*+,;=%\-]"
ASCII_START = re.compile(rb"https?://" + URL_CHARS + rb"{6,}")
ASCII_CONT = re.compile(URL_CHARS + rb"+")
# A UTF-16LE code unit that is printable: ASCII or Latin-1 (second byte 0), or a letter of a script whose block number is a control
# character in ASCII (Latin Extended, Greek, Cyrillic, Hebrew, Arabic, Indic, Thai, Latin Extended Additional), so 8-bit text next to
# a run is not read as such letters. CJK is left out on purpose: its code units are ASCII letter pairs. A run must BEGIN with an ASCII
# unit, which fixes its alignment: a pattern that could begin anywhere would read ASCII text shifted by one byte as such letters.
UTF16_UNIT = rb"(?:[\x20-\x7e\xa0-\xff]\x00|[\x00-\xff][\x01-\x06\x09\x0e\x1e])"
UTF16_START = re.compile(rb"[\x20-\x7e]\x00" + UTF16_UNIT + rb"{7,}")
UTF16_CONT = re.compile(UTF16_UNIT + rb"+")
UTF16_ANCHORS = ("http", "file:", "visited:", "192.168")


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


# The URL-secrets block further down is one text in three tools (a test holds the copies equal) and builds its locator page by the name LosslessPage.
# In this tool that name is the page that never replaces a result file, so a rerun with fewer locators cannot put a smaller file over a larger one.
LosslessPage = NoReplacePage


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


# ---- URL secrets: one design in browser_history, utf16_urls and esedb_query (a test holds the three copies identical)
#
# A URL can carry a session token, an API key or a password in its query string, its fragment or its user-info. Every URL in an
# answer has those values replaced by a marker that holds only their length ("[withheld: 12 characters]"), and the answer says how
# many were withheld, of what kind and where. The text is written whole only when the caller asks (write_url_secrets: true), only in
# a job (JOB_ID and OUT), to a file of mode 0600 that is created first and never replaced. NOT covered: a secret in a URL's path or
# title, a URL whose scheme this does not see, and a secret in free text.
import urllib.parse


class SecretValuesRefused(Exception):
    pass


def describe(exc):
    if isinstance(exc, OSError):
        return "%s: %s" % (type(exc).__name__, exc.strerror or exc)
    return "%s: %s" % (type(exc).__name__, exc)


class SecretValues:
    """Where a value goes when, and only when, the caller asked for it (the secret-safe pattern of docs/packs.md)."""

    def __init__(self, enabled, tool, flag, name):
        self.enabled = enabled
        self.tool = tool
        self.flag = flag
        self.written = 0
        self._fh = None
        self.shown = None
        if not enabled:
            return
        job, out = os.environ.get("JOB_ID") or "", os.environ.get("OUT") or ""
        if not (job and out):
            raise SecretValuesRefused(
                "%s is refused outside a job: a value written here would be an ordinary file, not a sealed secret output. "
                "Run this as job_run tool=%s with secret_output: true, and ask again there. Nothing was written." % (flag, tool)
            )
        path = Path(out) / name
        self.shown = "store/jobs/%s/out/%s" % (re.sub(r"[^A-Za-z0-9_.-]", "_", job), name)
        # Created now, before anything is read: a file or a link already at that name is refused by name at once (O_EXCL does
        # not follow a link, a dangling one included). With nothing found it stays an empty file, mode 0600.
        try:
            path.parent.mkdir(parents=True, exist_ok=True)
            fd = os.open(str(path), os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o600)
        except FileExistsError:
            raise SecretValuesRefused("the values file already exists: %s" % path)
        except OSError as exc:
            raise SecretValuesRefused("the values file could not be created: %s (%s)" % (path, describe(exc)))
        self._fh = os.fdopen(fd, "w", encoding="utf-8")

    def add(self, finding_id, locator, value):
        if self._fh is None:
            return
        text = json.dumps({"finding_id": finding_id, **locator, "value": value}, ensure_ascii=False)
        try:
            text.encode("utf-8")
        except UnicodeEncodeError:
            text = json.dumps({"finding_id": finding_id, **locator, "value": value}, ensure_ascii=True)
        self._fh.write(text + "\n")
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


URL_RE = re.compile(r"\b[A-Za-z][A-Za-z0-9+.\-]{1,15}://[^\s\"'<>\\^`{|}\x00-\x1f]+")
SECRET_SUBSTRINGS = ("token", "secret", "passw", "pwd", "auth", "bearer", "session", "signature", "credential", "assertion",
                     "jwt", "csrf", "xsrf", "ticket", "apikey", "accesskey")
SECRET_WORDS = {"sig", "sid", "key", "code", "pass", "otp", "sas", "saml", "hmac"}


def secret_parameter(name):
    """A query or fragment parameter whose name says its value is a credential: by a whole word (key, sig, code) or a substring (token)."""
    lowered = urllib.parse.unquote(name).lower()
    if any(s in lowered for s in SECRET_SUBSTRINGS):
        return True
    return any(w.lower() in SECRET_WORDS for w in re.findall(r"[A-Z]+(?![a-z])|[A-Z]?[a-z]+|[0-9]+", urllib.parse.unquote(name)))


def url_marker(value):
    return "[withheld: %d characters]" % len(value)


def mask_parameters(text, kind, found, url):
    parts = re.split(r"([&;])", text)
    for i, part in enumerate(parts):
        if "=" not in part or part in ("&", ";"):
            continue
        key, value = part.split("=", 1)
        if value and secret_parameter(key):
            found.append((kind, key, value, url))
            parts[i] = key + "=" + url_marker(value)
    return "".join(parts)


def mask_url(url):
    """The URL with its secrets replaced by markers, and what was withheld: [(kind, parameter, value, url)]."""
    found = []
    start = url.index("://") + 3
    rest = url[start:]
    boundary = re.search(r"[/?#]", rest)
    cut = boundary.start() if boundary else len(rest)
    authority, tail = rest[:cut], rest[cut:]
    if "@" in authority:
        userinfo, host = authority.rsplit("@", 1)
        if ":" in userinfo:
            user, password = userinfo.split(":", 1)
            if password:
                found.append(("userinfo_password", None, password, url))
                userinfo = user + ":" + url_marker(password)
        elif len(userinfo) >= 16 and re.fullmatch(r"[A-Za-z0-9_.~%\-]+", userinfo):
            found.append(("userinfo_token", None, userinfo, url))
            userinfo = url_marker(userinfo)
        authority = userinfo + "@" + host
    before_hash, hash_mark, fragment = tail.partition("#")
    path, query_mark, query = before_hash.partition("?")
    if query:
        query = mask_parameters(query, "query_parameter", found, url)
    if "=" in fragment:
        fragment = mask_parameters(fragment, "fragment_parameter", found, url)
    return url[:start] + authority + path + query_mark + query + hash_mark + fragment, found


def mask_text(text):
    """`text` with the secrets of every URL in it withheld, and what was withheld."""
    if "://" not in text:
        return text, []
    found = []

    def one(match):
        masked, withheld = mask_url(match.group(0))
        found.extend(withheld)
        return masked

    return URL_RE.sub(one, text), found


class UrlSecrets:
    """Counts and locates what mask_text withheld; the values themselves go only to `values` (a SecretValues)."""

    def __init__(self, values, tool, key, limit):
        self.values = values
        self.count = 0
        self.by_kind = {}
        self.by_parameter = {}
        self.locators = LosslessPage(tool + "-url-secrets", key, limit)

    def mask(self, text, where):
        masked, found = mask_text(text)
        for kind, parameter, value, url in found:
            self.count += 1
            finding_id = "U%06d" % self.count
            self.by_kind[kind] = self.by_kind.get(kind, 0) + 1
            if parameter is not None:
                self.by_parameter[parameter] = self.by_parameter.get(parameter, 0) + 1
            self.locators.add({"finding_id": finding_id, "kind": kind, "parameter": parameter, "length": len(value), **where})
            self.values.add(finding_id, {"kind": kind, "parameter": parameter, **where, "url": url}, value)
        return masked

    def summary(self):
        page = self.locators.finish()
        return {
            "count": self.count,
            "by_kind": self.by_kind,
            "by_parameter": self.by_parameter,
            "locators": self.locators.page,
            "locators_page": page,
            "marker": "a withheld value is replaced by [withheld: N characters] (N is its length in the URL's own text); "
                      "where it was, its kind and its length are in locators; the value is not in this answer",
            "not_covered": "a secret in a URL's path, in a title, in free text, or in a URL whose scheme is not followed by ://",
        }
# ---- end of URL secrets


class ClockStop(Exception):
    """The tool's own clock ran out inside the scan."""


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
    print_answer({"error": message, "status": "failed", "status_basis": "the tool stopped with an error and scanned nothing it can report (see error)", **extra})
    raise SystemExit(1)


def last_word(signum):
    interrupted_answer(signum, offset_reached=PROGRESS["offset"])


class Spec:
    """One encoding's scanner state: where its first undecided byte is, and whether a run was cut at a window's end."""

    def __init__(self, name, start, cont, width):
        self.name = name
        self.start = start
        self.cont = cont
        self.width = width            # bytes per character
        self.done_to = 0              # absolute offset: everything before it is decided
        self.continuing = False
        self.run_start = None
        self.anchor_ok = False


def window(spec, buf, base, eof, emit):
    """Decide the candidates of `spec` in buf (absolute offset base)."""
    n = len(buf)
    pos = max(spec.done_to - base, 0)
    if spec.continuing and spec.done_to >= base:
        m = spec.cont.match(buf, pos)
        if m and m.end() > pos:
            more = m.end() >= n - (spec.width - 1) and not eof
            emit(spec, base + pos, buf[pos:m.end()], more, True)
            spec.done_to = base + m.end()
            pos = m.end()
            spec.continuing = more
            if more:
                return
        else:
            spec.continuing = False
    while True:
        m = spec.start.search(buf, pos)
        if not m:
            break
        touches = m.end() >= n - (spec.width - 1) and not eof     # a half character at the end is part of the run
        if touches:
            if m.start() >= n - CARRY:
                break                      # undecided: the next window starts at the carry and sees all of it
            emit(spec, base + m.start(), buf[m.start():m.end()], True, False)
            spec.continuing = True
            spec.done_to = base + m.end()
            return
        emit(spec, base + m.start(), buf[m.start():m.end()], False, False)
        spec.done_to = base + m.end()
        pos = m.end()


def main():
    set_deadline(DEADLINE_SECONDS)
    install_signal_handlers(last_word)
    try:
        d = json.load(sys.stdin)
    except ValueError as exc:
        fail("arguments are not valid JSON", reason=str(exc))
    if not isinstance(d, dict):
        fail("the arguments must be a JSON object")
    path = d.get("path")
    if not isinstance(path, str) or not path:
        fail("path is required: the file to scan")
    if not os.path.isfile(path):
        fail("no such file", path=path)
    contains = d.get("contains") or ""
    if not isinstance(contains, str) or len(contains) > MAX_CONTAINS:
        fail("contains must be a string of at most %d characters" % MAX_CONTAINS)
    contains = contains.lower()
    limit = d.get("limit", 200)
    if isinstance(limit, bool) or not isinstance(limit, int) or not 1 <= limit <= MAX_LIMIT:
        fail("limit must be a whole number from 1 to %d (the inline page; the whole result is in the file the answer names)" % MAX_LIMIT)
    chunk = d.get("chunk", DEFAULT_CHUNK)
    if isinstance(chunk, bool) or not isinstance(chunk, int) or not 2 * CARRY <= chunk <= MAX_CHUNK:
        fail("chunk must be a whole number of bytes from %d to %d" % (2 * CARRY, MAX_CHUNK))
    max_distinct = d.get("max_distinct", 100000)
    if isinstance(max_distinct, bool) or not isinstance(max_distinct, int) or not 1 <= max_distinct <= MAX_DISTINCT:
        fail("max_distinct must be a whole number from 1 to %d" % MAX_DISTINCT)
    write_url_secrets = d.get("write_url_secrets", False)
    if not isinstance(write_url_secrets, bool):
        fail("write_url_secrets must be true or false")
    if write_url_secrets and os.environ.get("SECRET_OUTPUT") != "1":
        fail("write_url_secrets is refused: the whole text of the URLs whose secrets were withheld is written only in a job the harness runs as secret output "
             "(job_run with secret_output: true, which the manifest declares for this parameter). Nothing was opened or created.")
    try:
        values = SecretValues(write_url_secrets, "utf16_urls", "write_url_secrets", "utf16_urls-url-secrets.jsonl")
    except SecretValuesRefused as exc:
        fail(str(exc))
    url_secrets = UrlSecrets(values, "utf16_urls", [path, contains], limit)

    out = NoReplacePage("utf16_urls", [path, contains], limit)
    groups = {}
    totals = {"ascii": 0, "utf16le": 0, "filtered_out": 0, "pieces": 0}
    state = {"groups_complete": True}

    def emit(spec, offset, raw, more, is_cont):
        PROGRESS["offset"] = offset
        if out_of_time():
            raise ClockStop()
        text = raw.decode("ascii", "replace") if spec.width == 1 else raw.decode("utf-16-le", "replace")
        if spec.name == "utf16le":
            present = any(a in text.lower() for a in UTF16_ANCHORS)
            if not is_cont:
                spec.anchor_ok = present          # each run is judged on its own: a stale yes is not carried over
                if not present:
                    return
            elif not spec.anchor_ok:
                if not present:
                    return
                spec.anchor_ok = True
        if contains and contains not in mask_text(text)[0].lower():
            totals["filtered_out"] += 1
            return
        shown = url_secrets.mask(text, {"offset": offset, "encoding": spec.name})
        row = {"encoding": spec.name, "offset": offset, "length_bytes": len(raw), "text": shown}
        if more or is_cont:
            row["continued"] = bool(more)
            row["piece_of_a_longer_run"] = True
            totals["pieces"] += 1
        out.add(row)
        totals[spec.name] += 1
        key = (spec.name, text)
        g = groups.get(key)
        if g is not None:
            g[0] += 1
        elif len(groups) < max_distinct:
            groups[key] = [1, offset, shown]
        else:
            state["groups_complete"] = False

    ascii_spec = Spec("ascii", ASCII_START, ASCII_CONT, 1)
    utf16_spec = Spec("utf16le", UTF16_START, UTF16_CONT, 2)
    scanned = 0
    whole_to = 0
    stopped = None
    try:
        size = os.path.getsize(path)
        with open(path, "rb") as fh:
            carry = b""
            base = 0
            nxt = fh.read(chunk)
            while True:
                if out_of_time():
                    stopped = True
                    break
                data, nxt = nxt, fh.read(chunk) if nxt else b""
                eof = not nxt
                buf = carry + data
                try:
                    window(ascii_spec, buf, base, eof, emit)
                    window(utf16_spec, buf, base, eof, emit)
                except ClockStop:
                    stopped = True
                    break
                scanned += len(data)
                whole_to = scanned
                if eof:
                    break
                keep = min(CARRY, len(buf))
                base += len(buf) - keep
                carry = buf[len(buf) - keep:]
    except OSError as exc:
        values.close()
        fail("the file could not be read: nothing was reported as scanned beyond what is named here",
             path=path, status="failed", bytes_scanned=scanned, candidates_found_before=out.total, reason=describe(exc))

    page = out.finish()
    distinct = NoReplacePage("utf16_urls-groups", [path, contains, "groups"], limit)
    for (enc, _text), (count, first, shown_text) in sorted(groups.items(), key=lambda kv: kv[1][1]):
        distinct.add({"text": shown_text, "encoding": enc, "occurrences": count, "first_offset": first})
    group_page = distinct.finish()
    reasons = []
    if stopped:
        reasons.append("the tool's own clock (%d s) ran out: the first %d of the %d bytes were scanned whole, and the scan reached about byte %d; the rest of the file was not scanned" % (
            DEADLINE_SECONDS, whole_to, size, PROGRESS["offset"]))
    if not state["groups_complete"]:
        reasons.append("more than max_distinct (%d) distinct strings: the groups list is incomplete (the candidates and their count are not)" % max_distinct)
    answer = {
        "parser": PARSER,
        "status": "partial" if reasons else "complete",
        "status_basis": "; ".join(reasons) if reasons else "every byte of the %d-byte file was scanned in windows of %d bytes and every candidate is counted" % (size, chunk),
        "stopped_by_time_limit": bool(stopped),
        "path": path,
        "file_bytes": size,
        "bytes_scanned": scanned,
        "candidates": out.page,
        "candidate_count": page["matched"],
        "by_encoding": {"ascii": totals["ascii"], "utf16le": totals["utf16le"]},
        "filtered_out_by_contains": totals["filtered_out"],
        "pieces": totals["pieces"],
        "groups": distinct.page,
        "distinct_count": group_page["matched"],
        "groups_complete": state["groups_complete"],
        "groups_page": group_page,
        "url_secrets_withheld": url_secrets.summary(),
        "secret_values": values.summary("JSON Lines, mode 0600: finding_id, kind, parameter, offset, encoding, url (the whole text), value (the secret)"),
        **page,
        "note": "These are string candidates: where a URL-shaped or history-shaped run of characters is in the bytes, not "
                "a parsed browser record. A string does not say it was visited, typed, downloaded or opened, or by whom. "
                "A UTF-16LE run begins at a printable ASCII character and goes on through printable ASCII, Latin-1 and the letters of Latin "
                "Extended, Greek, Cyrillic, Hebrew, Arabic, Indic and Thai; a run longer than the carry is judged piece by piece. The text of a candidate has the secrets of its URLs "
                "withheld (url_secrets_withheld).",
    }
    values.close()
    print_answer(answer)


if __name__ == "__main__":
    exit_code = 0
    try:
        try:
            main()
        except SystemExit:
            raise
        except Exception as exc:                                  # whatever hostile input does, the answer is JSON
            hold_stop_signals(quietly=True)
            drop_pages()
            print_answer({"error": "the scan failed", "status": "failed", "status_basis": "the tool stopped with an unexpected error",
                          "reason": "%s: %s" % (type(exc).__name__, exc)})
            sys.exit(1)
    except SystemExit as stop:
        exit_code = _code(stop)
    _leave(exit_code)
