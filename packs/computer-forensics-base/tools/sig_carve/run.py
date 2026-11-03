#!/usr/bin/env python3
"""Scan one file for known file signatures, in one pass, and list every offset.

A signature scan, not a carver: it finds where a header's bytes occur and returns the
offsets with a short preview, and it estimates no sizes. A hit is where the bytes
occur: it may be inside a file, a string or an unrelated blob, so a decisive hit is
cut with `file_carver` (or read in place) and checked with a parser of that format.
Every signature is looked for in the same single read of the file, with a carry of
the longest header less one byte between reads, so a header cut by a read boundary
is found once, at its true offset. The result says what file and what range were
scanned. It reads the file as given: an E01 or another container is its container
bytes, not the disk inside.
"""
import hashlib
import json
import os
import re
import signal
import sys
import tempfile
import time
from pathlib import Path


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

import os as _os
import sys as _sys
import threading as _threading

# ---- the one protected printer of an answer (outside the shared block) ------------------------------------------------------------
# The stop signals are held while the answer is written, so that a signal cannot cut the document. A reader that stops taking it (a full
# pipe) would make that tool unkillable by SIGTERM: the held write is therefore bounded. If a stop signal is waiting when
# HELD_WRITE_SECONDS have passed, the tool says so on stderr and ends with 128 plus that signal; nothing is claimed about the answer.
HELD_WRITE_SECONDS = int(_os.environ.get("TOOL_HELD_WRITE_SECONDS") or 30)       # the environment variable is for the tests
_STOPS = (signal.SIGTERM, signal.SIGINT, signal.SIGHUP)


def _unstick():
    try:
        waiting = signal.sigpending()
    except (AttributeError, OSError):
        waiting = set()
    held = [s for s in _STOPS if s in waiting]
    if held:
        try:
            _os.write(2, ("the answer could not be written in %d seconds (the reader is not taking it); ended by the stop signal that was held\n" % HELD_WRITE_SECONDS).encode())
        except OSError:
            pass
        _os._exit(128 + int(held[0]))
    again = _threading.Timer(1.0, _unstick)
    again.daemon = True
    again.start()


ERROR_FLAGS = ("all_results_error", "all_matches_error", "receipt_error", "receipts_error", "rows_file_error", "rows_error", "invalid_lines_file_error",
               "write_error", "values_error")


def _flagged(node, depth=0):
    """The first error flag found in an answer (top level, and two levels of dicts below it), or None."""
    if not isinstance(node, dict) or depth > 2:
        return None
    for key in ERROR_FLAGS:
        if node.get(key):
            return key
    for value in node.values():
        found = _flagged(value, depth + 1)
        if found:
            return found
    return None


def _reconcile(answer):
    """status, complete and ok are one fact: an error flag in the answer (a file that should hold the rest could not be written) is not a
    complete answer, and a complete or ok that survives a partial or failed status is a wrong claim. Said once, here, for every answer."""
    if not isinstance(answer, dict):
        return
    flag = _flagged(answer)
    if flag and answer.get("status") == "complete":
        answer["status"] = "partial"
        basis = answer.get("status_basis")
        answer["status_basis"] = ("%s; but %s says part of what was asked for could not be kept" % (basis, flag)) if basis else "%s says part of what was asked for could not be kept" % flag
    if answer.get("status") in ("partial", "failed") or flag:
        if answer.get("complete") is True:
            answer["complete"] = False
    if answer.get("status") == "failed" and answer.get("ok") is True:
        answer["ok"] = False


# BEGIN SHARED TEMPS
# One lifecycle for the hidden temporary files of a run. A file is made by temp_create (or its name is registered with temp_hold before it is
# made), it is registered before anything else is done with it, and it stays registered until temp_done says it was renamed into place. What is
# still registered when the run ends is removed: by atexit on a normal end or any exception, by drop_temporaries in the last-resort handler, and
# by the stop signal's own cleanup, which removes the _tmp of every object in PAGES (a registered name is one such object).
import atexit
import tempfile

if "PAGES" not in globals():
    PAGES = []                 # objects with a hidden temporary file (_tmp) that a stop removes


class _HeldTemp:
    def __init__(self, name):
        self._tmp = name


def temp_hold(name):
    """Register a temporary file that is about to be made (or has been): it is removed on every way out unless temp_done is called."""
    held = _HeldTemp(os.fspath(name))
    PAGES.append(held)
    return held._tmp


def temp_create(directory, prefix, suffix=""):
    """tempfile.mkstemp with the new name registered at once: (fd, name)."""
    fd, name = tempfile.mkstemp(dir=os.fspath(directory), prefix=prefix, suffix=suffix)
    temp_hold(name)
    return fd, name


def temp_done(name):
    """The file was renamed into place (or is kept on purpose): it is no longer a temporary."""
    name = os.fspath(name)
    PAGES[:] = [p for p in PAGES if not (isinstance(p, _HeldTemp) and p._tmp == name)]


def temp_drop(name):
    """Remove one temporary now; False when it could not be removed (it stays registered, and the end of the run tries again)."""
    try:
        os.unlink(name)
    except FileNotFoundError:
        pass
    except OSError:
        return False
    temp_done(name)
    return True


def temp_replace(tmp, dest):
    os.replace(tmp, dest)
    temp_done(tmp)


def drop_temporaries():
    """Remove every temporary still registered (the pages being written and the held names); the names that could not be removed come back."""
    left = []
    for page in list(PAGES):
        tmp = None
        try:
            tmp = getattr(page, "_tmp", None)
            if tmp is not None:
                os.unlink(tmp)
        except FileNotFoundError:
            pass
        except Exception:   # noqa: BLE001 - every one is tried
            left.append(str(tmp))
    return left


atexit.register(drop_temporaries)
# END SHARED TEMPS


def _guarded_write(write):
    try:
        before = signal.pthread_sigmask(signal.SIG_BLOCK, set(_STOPS))      # before the timer thread exists, so that the thread holds them too
    except (AttributeError, ValueError, OSError):
        before = None
    watch = _threading.Timer(HELD_WRITE_SECONDS, _unstick)
    watch.daemon = True
    watch.start()
    try:
        write()
        _sys.stdout.flush()
    except BrokenPipeError:                       # the reader is gone: there is nobody to tell
        _os._exit(1)
    watch.cancel()
    if before is not None:
        # The document is whole. A stop that came while it was written is delivered now; the last word was cleared, so it ends the tool
        # (128 plus the signal) with nothing more on stdout. The mask is also what an in-process caller (a test) had before.
        signal.pthread_sigmask(signal.SIG_SETMASK, before)


_shared_print_answer = print_answer


def print_answer(answer, **dumps_kwargs):
    _reconcile(answer)
    _guarded_write(lambda: _shared_print_answer(answer, **dumps_kwargs))


def _unexpected_tool(kind, value, _tb):
    """Last resort: an error nobody foresaw is an answer too. The hidden temporaries are removed first (a name that cannot be removed is said in the
    answer), then one JSON document with the class and, for a file-system error, its reason (a message can quote a name from the evidence), and
    exit 1; what was written before it is not claimed. A stop signal that arrives while this runs is held with the answer's write and is answered by
    this document and exit 1, not by 128 + the signal."""
    try:
        left = drop_temporaries()
        reason = getattr(value, "strerror", None) if issubclass(kind, OSError) else None
        said = ("a path or file could not be used: %s" % (reason or kind.__name__)) if issubclass(kind, (OSError, ValueError)) else "internal error: %s" % kind.__name__
        answer = {"tool": globals().get("TOOL"), "status": "failed", "error": said,
                  "status_basis": "the tool stopped on an error it did not foresee (%s); what it had written before is not claimed" % kind.__name__}
        if left:
            answer["temporaries_left"] = left[:10]
            answer["status_basis"] += "; hidden temporary files that could not be removed are listed in temporaries_left"
        print_answer(answer)
    except BaseException:       # noqa: BLE001 - nothing may stop the exit
        pass
    os._exit(1)


sys.excepthook = _unexpected_tool

TOOL = {"name": "sig_carve", "version": 15}
WINDOW = 8 * 1024 * 1024
BUDGET_SECONDS = 100              # inside the manifest's 120: past it the scan stops, says so, and names where to continue
CONTEXT_MAX = 4096
HITS_MAX = 1_000_000
ROWS_PER_SIGNATURE = 2_000_000       # rows kept in the whole-result file per signature; counting goes on past it

# BEGIN SHARED SCAN
# The same text is in ioc_scan, chunk_needles and sig_carve (tests/test_scan_core.py holds the copies equal and holds the
# engine to a brute-force search over every way of cutting a stream into reads). One engine finds literal byte strings in a
# stream read in blocks: every occurrence once, at its true offset, overlapping ones included, in (offset, needle) order,
# whatever the block size. A match is held back until `after` bytes of context follow it (or the stream has ended), and
# `before` bytes of context are kept behind the searched position, so a match, or its context, cut by a read boundary is
# neither lost nor counted twice. Each tool keeps its own answer: what it reports for a match, its pages and its budgets.
import heapq

SCAN_SLICE = 256 * 1024            # positions searched and handed out together


def _positions(buf, needle, index, lo, stop):
    """(position, index) wherever `needle` starts in buf[lo:stop], one at a time: nothing is collected, so a stream that is one repeated
    byte searched for many nested needles holds one position per needle, not every match of a slice."""
    j = buf.find(needle, lo, stop)
    while j >= 0:
        yield j, index
        j = buf.find(needle, j + 1, stop)


class StreamScan:
    """feed() each block as it is read; every call returns (offset, needle index, buffer, buffer's offset) for the matches that can
    be decided now, in (offset, needle index) order. The buffer holds the match and its context. Exhaust the generator before the
    next feed: the buffer is trimmed when it ends. A caller may instead stop taking matches between two of them (a clock): every
    match it took came in order, none after it was handed out, and the scan is over (this object is not fed again).

    needles   the byte strings (a needle's index is its position in this list)
    before    bytes of context behind a match that stay in the buffer
    after     bytes of context after a match a match waits for
    start     the stream offset of the first byte fed
    prefix    the bytes that precede `start` in the stream, when a match may begin in them and end after `start` (a resumed scan)
    final     the last block (it may be empty): everything fully inside the buffer is handed out. Also what a scan stopped before its end
              calls: the matches that end inside what was read are all reported, and one that crosses the end is the next scan's.
    """

    def __init__(self, needles, before=0, after=0, start=0, prefix=b""):
        self.needles = list(needles)
        self.longest = max(len(n) for n in self.needles)
        self.before, self.after = before, after
        self.buf = prefix
        self.base = start - len(prefix)
        self.done = self.base
        # a match is this scan's when it ends after `start`: the first start position of a needle is start - len + 1
        self.first = [start - len(n) + 1 if prefix else start for n in self.needles]

    def feed(self, data, final=False):
        self.buf += data
        have = self.base + len(self.buf)
        process_end = have if final else have - (self.longest + self.after)
        if process_end > self.done:
            lo, hi = self.done - self.base, process_end - self.base
            a = lo
            while a < hi:
                b = min(hi, a + SCAN_SLICE)
                # One lazy stream per needle, merged by (offset, needle index): the same order for any block size, and the caller
                # can stop between any two matches (a clock looked at per match) without a slice's matches having been collected.
                streams = [_positions(self.buf, nb, vi, max(a, self.first[vi] - self.base), min(len(self.buf), b + len(nb) - 1))
                           for vi, nb in enumerate(self.needles)]
                for j, vi in heapq.merge(*streams):
                    yield self.base + j, vi, self.buf, self.base
                a = b
            self.done = process_end
        if not final:
            keep_from = max(0, (self.done - self.before) - self.base)
            self.buf, self.base = self.buf[keep_from:], self.base + keep_from
# END SHARED SCAN


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


class SafePage(LosslessPage):
    """The pager, with a whole-result file that may not be writable (a read-only run directory, a full disk).

    The count and the page stay whole; the answer says the file was not written (all_results_error) and no
    half file is left. LosslessPage itself is the pager every library tool carries, byte for byte.
    """

    error = None

    def _cannot_write(self, exc):
        """The pager above ends the call with a JSON failure when its file cannot be written; this one keeps the call and says so in
        the answer (all_results_error): the failure is handed back as the OSError add() and finish() below catch."""
        raise exc if isinstance(exc, OSError) else OSError(str(exc))

    def _give_up(self, exc):
        self.error = "%s: %s" % (self.path.parent, exc.strerror or exc)
        if self._out is not None:
            try:
                self._out.close()
            except OSError:
                pass
            self._out = None
        if self._tmp is not None:
            try:
                self._tmp.unlink()
            except OSError:
                pass
            self._tmp = None

    def discard(self):
        """Close and remove the file being written: a scan that did not end keeps no half file."""
        if self._out is not None:
            try:
                self._out.close()
            except OSError:
                pass
            self._out = None
        if self._tmp is not None:
            try:
                self._tmp.unlink()
            except OSError:
                pass
            self._tmp = None

    def add(self, row):
        if self.error is not None:
            self.total += 1
            if len(self.page) < self.limit:
                self.page.append(row)
            return
        try:
            super().add(row)
        except OSError as exc:
            self._give_up(exc)

    def finish(self):
        if self.error is None:
            try:
                # The base class moves its file to self.path: the name is chosen here so that nothing already there is replaced.
                if self._out is not None and os.path.lexists(self.path):
                    self._out.flush()
                    stem, ext = os.path.splitext(str(self.path))
                    shown_stem, _ = os.path.splitext(self.shown)
                    k = 1
                    while os.path.lexists(self.path if k == 1 else "%s.%d%s" % (stem, k, ext)) and not _same_bytes(self._tmp, self.path if k == 1 else "%s.%d%s" % (stem, k, ext)):
                        k += 1
                    if k > 1:
                        self.path, self.shown = Path("%s.%d%s" % (stem, k, ext)), "%s.%d%s" % (shown_stem, k, ext)
                return super().finish()
            except OSError as exc:
                self._give_up(exc)
        return {
            "matched": self.total,
            "returned": len(self.page),
            "truncated": self.total > len(self.page),
            "all_results_error": (
                "the whole result could not be written (%s); the hits past the page are counted, not listed: "
                "run again with a larger max_hits, or in a place that can be written" % self.error
            ),
        }


# File signatures: name -> (header_hex, where the candidate file starts relative to the hit, note)
SIGS = {
    "MZ":    ("4D5A", 0, "PE or DOS executable: two bytes, so many hits are not executables"),
    "PK":    ("504B0304", 0, "a ZIP local file header (also docx, xlsx, jar, apk)"),
    "regf":  ("72656766", 0, "a registry hive base block"),
    "MAM":   ("4D414D", 0, "three bytes: also inside text; MAM prefetch is PCH"),
    "SCCA":  ("53434341", -4, "an uncompressed prefetch file's signature, which sits 4 bytes after its start (after the version)"),
    "EVTX":  ("456C6646696C6500", 0, "an event log file header (ElfFile)"),
    "OLE":   ("D0CF11E0A1B11AE1", 0, "an OLE2 compound file (Office 97-2003, MSI, Jump Lists)"),
    "LNK":   ("4C0000000114020000000000C000000000000046", 0, "a Windows shortcut header"),
    "SQLite":("53514C69746520666F726D6174203300", 0, "a SQLite database header"),
    "RAR":   ("526172211A0700", 0, "a RAR (version 4) archive"),
    "7z":    ("377ABCAF271C", 0, "a 7-Zip archive"),
    "GZ":    ("1F8B08", 0, "a gzip stream"),
    "BZ2":   ("425A68", 0, "three bytes: a bzip2 stream, or text"),
    "PDF":   ("255044462D", 0, "a PDF header"),
    "PNG":   ("89504E470D0A1A0A", 0, "a PNG header"),
    "JFIF":  ("FFD8FFE0", 0, "a JPEG (JFIF) start"),
    "PCH":   ("4D414D04", 0, "a compressed (MAM) prefetch file"),
}


def open_regular(path):
    """open(path, "rb") for a path that was just checked as a regular file: opened without waiting (O_NONBLOCK) and looked at with fstat on the
    descriptor, so a FIFO or a device put in its place after the check is refused and never waited on (a FIFO would hold the tool for ever)."""
    fd = os.open(path, os.O_RDONLY | getattr(os, "O_NONBLOCK", 0))
    try:
        if os.fstat(fd).st_mode & 0o170000 != 0o100000:
            raise OSError(22, "is not a regular file (it changed after it was checked)")
    except BaseException:
        os.close(fd)
        raise
    return open(fd, "rb")


def _same_bytes(a, b, deadline=None):
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


def earlier_answers(path):
    """How many other files answer this same question in the folder (name.ext, name.2.ext, ...): one more for every different
    answer, and none is deleted, so the count is said."""
    stem, ext = os.path.splitext(os.path.basename(str(path)))
    base = re.sub(r"\.\d+$", "", stem)
    rx = re.compile(r"^%s(\.\d+)?%s$" % (re.escape(base), re.escape(ext)))
    try:
        return max(0, sum(1 for n in os.listdir(os.path.dirname(str(path)) or ".") if rx.match(n)) - 1)
    except OSError:
        return 0


PAGES = []                         # the pages being written: a SIGTERM removes their half files before the scan ends


def fail(message, **extra):
    print_answer({"ok": False, "status": "failed", "status_basis": "the tool stopped with an error: %s" % message, "error": message, "tool": TOOL, **extra})
    raise SystemExit(1)


def whole_number(args, key, default, low, high):
    value = args.get(key, default)
    if not isinstance(value, int) or isinstance(value, bool) or not low <= value <= high:
        fail("%s is a whole number from %d to %d" % (key, low, high), **{key: value})
    return value


def main():
    try:
        args = json.load(sys.stdin)
    except (ValueError, RecursionError) as exc:
        fail("arguments are not valid JSON", reason=str(exc))
    if not isinstance(args, dict):
        fail("arguments are a JSON object")
    path = args.get("path", "")
    sig_name = args.get("sig") or "all"
    context = whole_number(args, "context", 64, 0, CONTEXT_MAX)
    max_hits = whole_number(args, "max_hits", 500, 1, HITS_MAX)
    window = whole_number(args, "window_bytes", WINDOW, 16, 256 * 1024 * 1024)
    if not isinstance(path, str) or not path or "\0" in path:
        fail("path is required: the binary file to scan")
    if not os.path.isfile(path):
        fail("no such file", path=path)
    try:
        size = os.path.getsize(path)
    except OSError as exc:
        fail("the file cannot be read: %s" % (exc.strerror or exc), path=path)
    start = whole_number(args, "start", 0, 0, size)
    if not isinstance(sig_name, str):
        fail("sig is a signature name or all", sig=sig_name, signatures=sorted(SIGS))
    if sig_name != "all" and sig_name not in SIGS:
        fail("no such signature", sig=sig_name, signatures=sorted(SIGS), hint="sig is one of these names, or all")
    chosen = SIGS if sig_name == "all" else {sig_name: SIGS[sig_name]}
    headers = {name: bytes.fromhex(h) for name, (h, _a, _n) in chosen.items()}
    carry_len = max(len(h) for h in headers.values()) - 1
    pages = {name: SafePage("sig_carve-" + name, [path, name, size, context, start], max_hits) for name in chosen}
    PAGES.extend(pages.values())
    deadline = time.monotonic() + BUDGET_SECONDS
    totals = {name: 0 for name in chosen}
    capped = {}

    def preview(fh, window, base, at):
        """The bytes from a hit to `context` bytes on, from the window when it holds them, else from the file."""
        i = at - base
        if i + context <= len(window):
            return window[i:i + context]
        fh.seek(at)
        return fh.read(context)

    scanned = start
    stopped, read_error = None, None

    def _stopped(signum):
        print(json.dumps({"tool": TOOL, "status": "partial", "interrupted": True, "signal": signum, "source": {"path": path},
                          "scanned": {"start": start, "end": scanned, "complete": False},
                          "status_basis": "the tool was stopped by signal %d: [start, end) was read, no half-written results file was kept, and the counts so far were not kept; "
                                          "run again with start=%d to go on" % (signum, scanned)}), flush=True)
    install_signal_handlers(_stopped)
    try:
        fh = open_regular(path)
    except OSError as exc:
        fail("the file cannot be opened: %s" % (exc.strerror or exc), path=path)
    with fh:
        # From `start` on. The bytes just before it are read as the prefix, so a header that begins before `start` and ends after it
        # is found once (one wholly before it is not this scan's); a continuation of a stopped scan loses no seam and repeats no hit.
        carry = b""
        if start and carry_len:
            try:
                fh.seek(max(0, start - carry_len))
                carry = fh.read(min(carry_len, start))
            except OSError as exc:
                fail("the file could not be read at offset %d: %s" % (start, exc.strerror or exc), path=path)
        fh.seek(start)
        # The shared engine (StreamScan, above) finds each header once, at its true offset, whatever window is read.
        names = list(headers)
        scan = StreamScan([headers[n] for n in names], start=start, prefix=carry)

        def record(found):
            for at, vi, buf, base in found:
                name = names[vi]
                totals[name] += 1
                if totals[name] <= ROWS_PER_SIGNATURE:
                    snippet = preview(fh, buf, base, at) if context else b""
                    row = {"offset": at, "hex_preview": snippet[:32].hex(" "),
                           "ascii_preview": "".join(chr(b) if 32 <= b < 127 else "." for b in snippet[:64])}
                    adjust = chosen[name][1]
                    if adjust and at + adjust >= 0:
                        row["candidate_start"] = at + adjust
                    pages[name].add(row)
                elif name not in capped:
                    capped[name] = at

        pos = start
        while pos < size:
            if time.monotonic() > deadline:
                stopped = ("the %d-second time budget was used after %d bytes of the file: the counts and hits are for [%d, %d) only; "
                           "run again with start=%d to go on" % (BUDGET_SECONDS, pos - start, start, pos, pos))
                break
            try:
                block = fh.read(min(window, size - pos))
            except OSError as exc:
                read_error = "the file could not be read at offset %d: %s" % (pos, exc.strerror or exc)
                break
            if not block:
                break
            record(scan.feed(block))
            try:
                fh.seek(pos + len(block))          # a preview may have moved the file position
            except OSError as exc:
                read_error = "the file could not be read at offset %d: %s" % (pos + len(block), exc.strerror or exc)
                pos += len(block)
                scanned = pos
                break
            pos += len(block)
            scanned = pos
        # Whatever ended the scan, every header wholly inside what was read is reported; one that crosses the end is the next scan's.
        try:
            record(scan.feed(b"", final=True))
        except OSError as exc:
            read_error = read_error or "the file could not be read at offset %d: %s" % (scanned, exc.strerror or exc)
    results = {}
    for name in chosen:
        page = pages[name].finish()
        entry = {"count": totals[name], "hits": pages[name].page, **page, "matched": totals[name], "note": chosen[name][2]}
        entry["truncated"] = totals[name] > len(pages[name].page)
        if "all_results" in entry:
            entry["earlier_answers"] = earlier_answers(pages[name].path)
        if name in capped:
            entry["rows_file_stopped_at_offset"] = capped[name]
            entry["rows_file_cap"] = ROWS_PER_SIGNATURE
        results[name] = entry
    complete = scanned == size and stopped is None and read_error is None
    scan = {"start": start, "end": scanned, "bytes": scanned - start, "complete": complete, "passes": 1,
            "window_bytes": window, "carry_bytes": carry_len}
    if stopped:
        scan["stopped"] = stopped
    if read_error:
        scan["read_error"] = read_error
    unwritten = [n for n, e in results.items() if "all_results_error" in e]      # hits past the page that no file holds
    print_answer({
        "tool": TOOL,
        "status": "complete" if complete and not unwritten else "partial" if not read_error else "failed",
        "status_basis": ("the whole requested range was read and every header in it is reported" if complete and not unwritten else
                         "the whole range was read and the counts and pages are right, but the file that should hold every hit could not be written for %s "
                         "(all_results_error): the hits past the page are counted, not listed" % ", ".join(unwritten) if complete else
                         "the scan stopped at its clock (scanned.stopped says where to go on)" if not read_error else
                         "the file could not be read all the way (scanned.read_error)"),
        "source": {"path": path, "bytes": size, "address_space": "the bytes of this file as given; a container (E01, VMDK) is not decoded"},
        "scanned": scan,
        "context_bytes": context,
        "signatures": results,
        "note": "A hit is where a header's bytes occur, not a file: cut it with file_carver or read it in place and check it with a parser of that format. "
                "A signature that is not listed here, an encrypted or compressed region and a file split across the scan's source are not found by this scan.",
    }, indent=2)
    # Exit 0 means the engine ran: a stop at the time budget is a valid answer for [start, end) with the position to go on from
    # (scanned.complete is false and scanned.stopped says where). A read error is a failure.
    sys.exit(1 if read_error else 0)


if __name__ == "__main__":
    main()
