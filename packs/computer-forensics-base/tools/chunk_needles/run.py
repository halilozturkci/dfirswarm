#!/usr/bin/env python3
"""Scan a file, or one inode of an image streamed through icat, for ASCII and UTF-16LE needles.

The answer is where each needle is: per needle the number of occurrences as ASCII and as
UTF-16LE, and for each occurrence a locator (an id, the offset in the scanned stream, the
encoding, how many bytes of context surround it). The context bytes are NOT returned by
default: they are where a password, a token or a card number sits. `write_values: true`, in a
job run with `secret_output: true`, writes them to a 0600 file under $OUT, and the answer names
the file. Never put a secret in `needles`: the arguments of a call are recorded in the trace.

What it finds, exactly: every occurrence of each needle, overlapping ones included, whatever
`chunk` is; a match is held back until its context is in the read, so a read boundary neither
loses a match nor cuts its context. `source` names the stream: the file, or the image, the
volume offset, the inode, and any sector size given. The stream is read once and never held whole.

The scan has a clock (`max_seconds`, default 100, at most 110, inside the manifest's 120): one that reaches it answers for the
occurrences that start before `next_start` in the stream, says `complete: false` and `status: partial`, and how to go on (a file:
ioc_scan with `start`; an inode: icat_extract it, then ioc_scan the file).
"""
import json, re, shutil, sys, subprocess, os, time


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

PAGES = []                 # objects with a hidden temporary file (_tmp) that a stop removes
CHILD = {"proc": None}      # the icat being read, ended by pid on a stop
PROGRESS = {"scanned": 0}

TOOL = {"name": "chunk_needles", "version": 16}
CHUNK_DEFAULT = 8 * 1024 * 1024
CHUNK_MIN, CHUNK_MAX = 16, 256 * 1024 * 1024
CONTEXT_MAX = 65536
HITS_MAX = 1_000_000
NEEDLES_MAX = 1000
NEEDLE_BYTES_MAX = 4096
ROW_CAP = 20_000_000
VALUES_ROWS_MAX = 20_000_000       # rows in the values file (write_values); the scan and its locators go on past it
LOCATORS_BYTES_MAX = int(os.environ.get("CHUNK_NEEDLES_LOCATORS_BYTES") or 1 << 30)  # bytes in one needle's whole-result file (a smaller cap can be asked for)
VALUES_BYTES_MAX = int(os.environ.get("CHUNK_NEEDLES_VALUES_BYTES") or 1 << 30)    # bytes in the values file (a smaller cap can be asked for)
SECONDS_DEFAULT, SECONDS_MAX = 100, 110   # the scan's own clock, inside the manifest's 120
FEED = 256 * 1024                  # bytes handed to the engine at a time: the clock is looked at between feeds
CLOCK_EVERY = 256                  # and between this many matches of one feed: a feed of dense matches times many needles is millions of them
STARTED = time.monotonic()
SECTOR_MAX = 65536
INODE = re.compile(r"^\d+(-\d+(-\d+)?)?$")
RESOLVE_SECONDS = 60               # the search for the image under inputs/ (when image= is not given)
CANDIDATES_MAX = 200               # and the images it keeps before it asks the caller to say which

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

def _catalogue_slug(path):
    """The directory name the kickoff's catalogue gives an input: its path under
    inputs/ with every byte outside [A-Za-z0-9._-] made "_" (evidence-catalog.sh)."""
    import os, re
    rel = os.fsencode(os.path.relpath(path, "inputs"))
    return os.fsdecode(re.sub(rb"[^A-Za-z0-9._-]", b"_", rel))


def _inputs_roots():
    """inputs/, and each set held in place as a link directly under it (inputs.json names the sets): the only links followed.
    Any other link under inputs/ is a name and not a place to walk: following one could leave the evidence for the rest of the file system."""
    import json, os
    roots = ["inputs"]
    try:
        with open("inputs.json", encoding="utf-8") as fh:
            sets = json.load(fh).get("sets") or []
    except (OSError, ValueError, AttributeError):
        sets = []
    for entry in sets:
        name = entry.get("name") if isinstance(entry, dict) else None
        if isinstance(name, str) and name and "/" not in name and os.path.islink(os.path.join("inputs", name)):
            roots.append(os.path.join("inputs", name))
    return roots


def _resolve_image(explicit=None):
    """A pack tool belongs to no case: find the image under inputs/ instead of
    baking one in. One candidate is used; several mean the caller must say which.
    An image is known by its extension or, lacking one (a raw `dd` of a web
    server named after the host), by the catalogue: the kickoff writes
    catalog/<input>/partitions.txt for every input it read as a disk.
    The search is on a clock (RESOLVE_SECONDS, read for every entry) and keeps at most CANDIDATES_MAX names:
    a tree it cannot finish, or one with more images than that, is said, and the caller passes image=."""
    import glob, os, time
    if explicit:
        return explicit
    deadline = time.monotonic() + RESOLVE_SECONDS
    cands = []
    for ext in ("*.E01", "*.e01", "*.raw", "*.dd", "*.001", "*.img", "*.vhd", "*.vhdx"):
        cands += glob.glob(os.path.join("inputs", ext))
    for root_dir in _inputs_roots():
        stack = [root_dir]
        while stack:
            here = stack.pop()
            try:
                scan = os.scandir(here)
            except OSError:
                continue
            with scan:
                for entry in scan:
                    if time.monotonic() > deadline:
                        raise SystemExit(json.dumps({"ok": False, "error": "looking for the image under inputs/ used its %d seconds before it was done; pass image=" % RESOLVE_SECONDS}))
                    try:
                        is_dir = entry.is_dir()
                        if is_dir and entry.is_symlink():
                            continue                         # a directory link is a name and not a place to walk
                    except OSError:
                        continue
                    if is_dir:
                        stack.append(entry.path)
                    elif os.path.isfile(os.path.join("catalog", _catalogue_slug(entry.path), "partitions.txt")):
                        cands.append(entry.path)
                        if len(set(cands)) > CANDIDATES_MAX:
                            raise SystemExit(json.dumps({"ok": False, "error": "more than %d images under inputs/; pass image=" % CANDIDATES_MAX}))
    cands = sorted(set(cands))
    if len(cands) == 1:
        return cands[0]
    if not cands:
        raise SystemExit('{"ok": false, "error": "no disk image under inputs/; pass image="}')
    raise SystemExit('{"ok": false, "error": "several images under inputs/; pass image=", "candidates": %s}' % json.dumps(cands))


def _resolve_offset(image, explicit=None):
    """The volume's start sector for icat -o. Given, it is used as is; not
    given, the catalogue says: one filesystem catalogued (catalog/<input>/p<start>/)
    is that start, several mean the caller must say which, none is sector 0."""
    import os, re
    if explicit is not None:
        return explicit
    root = os.path.join("catalog", _catalogue_slug(image))
    starts = sorted(int(d[1:]) for d in (os.listdir(root) if os.path.isdir(root) else [])
                    if re.fullmatch(r"p\d+", d) and os.path.isdir(os.path.join(root, d)))
    if len(starts) == 1:
        return starts[0]
    if not starts:
        return 0
    raise SystemExit('{"ok": false, "error": "several filesystems in %s; pass offset= (a start sector, see %s/partitions.txt)", "candidates": %s}' % (image, root, json.dumps(starts)))


def _resolve_catalog(explicit=None):
    """The catalogue directory for the one image the kickoff catalogued, or
    the one named: by its name under catalog/, as the index lists it
    (catalog=Case4.E01 was a traceback), or by its path."""
    import os
    root = "catalog"
    subs = sorted(d for d in os.listdir(root) if os.path.isdir(os.path.join(root, d))) if os.path.isdir(root) else []
    if explicit:
        for cand in (explicit, os.path.join(root, explicit)):
            if os.path.isdir(cand):
                return cand
        raise SystemExit(json.dumps({"ok": False, "error": "no catalogue %s" % explicit, "candidates": subs}))
    if not os.path.isdir(root):
        raise SystemExit('{"ok": false, "error": "no catalog/ in this run; pass catalog="}')
    if len(subs) == 1:
        return os.path.join(root, subs[0])
    if not subs:
        raise SystemExit('{"ok": false, "error": "catalog/ is empty; pass catalog="}')
    # A disk and a memory image catalogue two directories, and only the
    # disk's has filesystems (partitions.txt): with one such, it is the one.
    disks = [d for d in subs if os.path.isfile(os.path.join(root, d, "partitions.txt"))]
    if len(disks) == 1:
        return os.path.join(root, disks[0])
    raise SystemExit('{"ok": false, "error": "several catalogues; pass catalog=", "candidates": %s}' % json.dumps(subs))

import errno
import select
import hashlib
import tempfile
from pathlib import Path


def describe(exc):
    code = errno.errorcode.get(exc.errno, "") if getattr(exc, "errno", None) else ""
    return "%s%s: %s" % (type(exc).__name__, " " + code if code else "", getattr(exc, "strerror", None) or str(exc))


class SecretValuesRefused(Exception):
    pass


class SecretValues:
    """Where a value goes when, and only when, the caller asked for it.

    The reference implementation of the secret-safe output pattern: copy this
    class unchanged into a tool that has to produce a secret, and call `add`
    once per finding with the finding's id, its locator and the value. With
    `enabled` false it writes nothing and `summary()` says so.
    """

    NAME = "chunk-needles-values.jsonl"

    def __init__(self, enabled: bool):
        self.enabled = enabled
        self.written = 0
        self.bytes = 0
        self.stopped_at = None
        self._fh = None
        self.job = os.environ.get("JOB_ID") or ""
        self.out = os.environ.get("OUT") or ""
        self.path = None
        self.shown = None
        if not enabled:
            return
        if not (self.job and self.out):
            raise SecretValuesRefused(
                "write_values is refused outside a job: a value written here would be an ordinary "
                "file, not a sealed secret output. Run this as job_run tool=chunk_needles with "
                "secret_output: true, and ask again there. Nothing was written."
            )
        if os.environ.get("SECRET_OUTPUT") != "1":
            raise SecretValuesRefused(
                "write_values is refused in a job that was not run as secret output: its files would be sealed as ordinary "
                "output. The harness sets SECRET_OUTPUT=1 for a secret job's process and it is not set here. Run it as "
                "job_run(tool: \"chunk_needles\", args: {...}), whose manifest makes a job that sets write_values secret output, or give "
                "a command job secret_output: true. Nothing was written."
            )
        self.path = Path(self.out) / self.NAME
        self.shown = "store/jobs/%s/out/%s" % (re.sub(r"[^A-Za-z0-9_.-]", "_", self.job), self.NAME)
        # Created now, before anything is scanned: a file or a link already at that name is
        # refused by name at once (O_EXCL does not follow a link, a dangling one included),
        # instead of failing, or writing through it, after the scan. With nothing found it
        # stays as an empty file, mode 0600, and the answer says written: 0.
        try:
            refused = own_dir(self.path.parent)
            if refused:
                raise SecretValuesRefused("the values file could not be created: %s" % refused)
            fd = os.open(str(self.path), os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o600)
        except FileExistsError:
            raise SecretValuesRefused("the values file already exists: %s" % self.path)
        except OSError as exc:
            raise SecretValuesRefused("the values file could not be created: %s (%s)" % (self.path, describe(exc)))
        self._fh = os.fdopen(fd, "w", encoding="utf-8")

    def add(self, finding_id: str, locator: dict, value: str) -> None:
        if not self.enabled:
            return
        # ensure_ascii: a source label that is not UTF-8 (a path's bytes arrive as lone surrogates) is written as an escape, never an encoding error.
        line = json.dumps({"finding_id": finding_id, **locator, "value": value}, ensure_ascii=True) + "\n"
        if self.stopped_at is not None or self.written >= VALUES_ROWS_MAX or self.bytes + len(line) > VALUES_BYTES_MAX:
            if self.stopped_at is None:
                self.stopped_at = locator.get("offset")
            return      # from the first occurrence that did not fit on, none is written: the file is a prefix
        self._fh.write(line)
        self.written += 1
        self.bytes += len(line)

    def close(self) -> None:
        if self._fh is not None:
            self._fh.flush()
            os.fsync(self._fh.fileno())
            self._fh.close()
            self._fh = None

    def summary(self) -> dict:
        return {
            "requested": self.enabled,
            "written": self.written,
            "values_file": self.shown if self.enabled else None,
            "contains_secret_values": self.written > 0,
            **({"complete": self.stopped_at is None} if self.enabled else {}),
            **({"stopped_at_offset": self.stopped_at, "cap_rows": VALUES_ROWS_MAX, "cap_bytes": VALUES_BYTES_MAX,
                "resume": "the file holds every occurrence that starts before stopped_at_offset; to get the rest, scan again from there in a new job (ioc_scan start=)"}
               if self.stopped_at is not None else {}),
            "format": "JSON Lines, mode 0600: finding_id, source, offset, needle, encoding, value (the printable context around the match)" if self.enabled else None,
        }


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


def publish(tmp, path, shown):
    """Move a finished file to `path` without replacing what is there: a file at the name is an earlier answer (a complete
    one, perhaps, where this run was cut short) and stays; this one is kept beside it as name.2.ext, unless it is the
    same bytes, when the file already there is it. Returns the path it has
    and the name to show for it."""
    stem, ext = os.path.splitext(str(path))
    shown_stem, _ = os.path.splitext(shown)
    k = 1
    while True:
        suffix = "" if k == 1 else ".%d" % k
        candidate = Path(stem + suffix + ext)
        try:
            os.link(tmp, candidate)
        except FileExistsError:
            if same_bytes(tmp, candidate):                # the same answer again (a page of the same search): the file is already there
                os.unlink(tmp)
                return candidate, shown_stem + suffix + ext
            k += 1
            continue
        except OSError:                                   # a file system with no hard links: a look, then a rename
            if os.path.lexists(candidate):
                if same_bytes(tmp, candidate):
                    os.unlink(tmp)
                    return candidate, shown_stem + suffix + ext
                k += 1
                continue
            os.rename(tmp, candidate)
            return candidate, shown_stem + suffix + ext
        os.unlink(tmp)
        return candidate, shown_stem + suffix + ext


def own_dir(path):
    """Create the tool-output directory and return None, or say why it is not used: a symbolic link anywhere on the way (the directory itself,
    or work/ or the agent's directory under it) would send the tables and the private names file somewhere else, and O_NOFOLLOW guards only
    the last name of a file. In a job only the part under $OUT is checked ($OUT is the job service's)."""
    path = Path(path)
    out = os.environ.get("OUT")
    start = len(Path(out).parts) if out and path.parts[:len(Path(out).parts)] == Path(out).parts else 0
    for i in range(max(start, 1), len(path.parts) + 1):
        step = Path(*path.parts[:i])
        if os.path.islink(step):
            return "%s is a symbolic link: refused, nothing written through it" % step
    path.mkdir(parents=True, exist_ok=True)
    return None


SHOWN_MAX = 120      # characters of a needle shown in a locator row; needle_index is the exact key


class LocatorFile:
    """The locators of every needle that went past its inline page, in ONE JSON Lines file: each row names its needle (needle_index,
    the position in the needles given once a repeated one is dropped, and needle, its shown form), so the number of open files is one
    however many needles there are. Rows are written in the order the scan finds them, and from the first that does not fit under the
    cap none is written (the file holds every occurrence that starts before the offset it stopped at). A file that cannot be created
    or written to its end is not kept: the answer says so (all_results_error) and is partial."""

    def __init__(self, tool, key):
        self.tool = re.sub(r"[^A-Za-z0-9_.-]", "_", tool)
        digest = hashlib.sha256(json.dumps(key, sort_keys=True, default=str).encode("utf-8")).hexdigest()[:16]
        name = "%s-%s.jsonl" % (self.tool, digest)
        job, out = os.environ.get("JOB_ID"), os.environ.get("OUT")
        if job and out:
            self.path = Path(out) / "tool-output" / name
            self.shown = "store/jobs/%s/out/tool-output/%s" % (re.sub(r"[^A-Za-z0-9_.-]", "_", job), name)
        else:
            agent = re.sub(r"[^A-Za-z0-9_.-]", "_", os.environ.get("AGENT_ID") or "tool")
            self.path = Path("work") / agent / "tool-output" / name
            self.shown = str(self.path)
        self.fh = self.tmp = self.error = None
        self.written = self.bytes = 0
        self.rows = {}                     # needle_index -> rows of it in the file
        self.stopped_at = None
        self.published = False

    @property
    def _tmp(self):
        return self.tmp

    def _open(self):
        refused = own_dir(self.path.parent)
        if refused:
            raise OSError(0, refused)
        fd, name = tempfile.mkstemp(dir=self.path.parent, prefix=".%s-" % self.tool)
        self.tmp, self.fh = Path(name), os.fdopen(fd, "w", encoding="utf-8")

    def _lose(self, why):
        self.error = "the whole result could not be written (%s); none of it was kept: the counts and the inline pages are of the whole scan" % why
        self.discard()

    def write(self, index, name, row):
        """One row of needle `index`. True when it is in the file."""
        if self.error is not None or self.stopped_at is not None:
            return False
        if self.fh is None:
            try:
                self._open()
            except OSError as exc:
                self._lose("%s: %s" % (self.path.parent, exc.strerror or exc))
                return False
        line = json.dumps({"needle_index": index, "needle": name if len(name) <= SHOWN_MAX else name[:SHOWN_MAX] + "...", **row}, ensure_ascii=True) + "\n"
        if self.written >= ROW_CAP or self.bytes + len(line) > LOCATORS_BYTES_MAX:
            self.stopped_at = row["off"]       # from the first row that did not fit on, none is written: the file is a prefix
            return False
        try:
            self.fh.write(line)
        except OSError as exc:
            self._lose("a write failed after %d rows: %s" % (self.written, exc.strerror or exc))
            return False
        self.written += 1
        self.bytes += len(line)
        self.rows[index] = self.rows.get(index, 0) + 1
        return True

    def discard(self):
        """Close and remove the file being written, if it is still there: a run that did not finish keeps no half file."""
        try:
            if self.fh and not self.fh.closed:
                self.fh.close()
        except OSError:
            pass
        self.fh = None
        if self.tmp is not None:
            try:
                os.unlink(self.tmp)
            except OSError:
                pass
            self.tmp = None
        self.rows = {}

    def finish(self):
        """Publish the file (never over one that is there). After this, `shown` names it, or `error` says why there is none."""
        if self.fh is None:
            return
        try:
            self.fh.flush()
            os.fsync(self.fh.fileno())
            self.fh.close()
            self.path, self.shown = publish(self.tmp, self.path, self.shown)
            self.tmp = None
            self.fh = None
            self.published = True
        except OSError as exc:
            self._lose("the file could not be completed: %s" % (exc.strerror or exc))


class Locators:
    """One needle's locators: an inline page, and the whole list in the shared LocatorFile once it is more than the page."""

    def __init__(self, shared, index, name, limit):
        self.shared, self.index, self.name, self.limit = shared, index, name, limit
        self.page, self.total, self.spilled = [], 0, False

    def add(self, row):
        self.total += 1
        if len(self.page) < self.limit:
            self.page.append(row)
            return
        if not self.spilled:
            self.spilled = True
            for kept in self.page:             # this needle's page goes into the file first, so the file holds its whole list
                self.shared.write(self.index, self.name, kept)
        self.shared.write(self.index, self.name, row)

    def finish(self):
        s = self.shared
        info = {"needle_index": self.index, "matched": self.total, "returned": len(self.page), "truncated": self.total > len(self.page)}
        if self.spilled:
            have = s.rows.get(self.index, 0)
            if s.published:
                info["all_results"] = s.shown
                info["earlier_answers"] = earlier_answers(s.path)
                info["all_results_format"] = ("JSON Lines, one locator per occurrence of any needle that went past its page: needle_index (the position of the "
                                              "needle in the needles given, a repeated one dropped), needle (its shown form), finding_id, off, enc, context_length")
                info["all_results_rows"] = have
                if have < self.total:
                    info["all_results_complete"] = False
                    info["all_results_stopped_at_offset"] = s.stopped_at
                    info["all_results_cap_rows"] = ROW_CAP
                    info["all_results_cap_bytes"] = LOCATORS_BYTES_MAX
                    info["all_results_note"] = ("the file holds %d of this needle's %d occurrences. It reached its cap and stopped at offset %s: from there on no "
                                                "row of any needle was written, and a needle that went past its page after that has none in it. The counts and "
                                                "the inline page are of the whole scan" % (have, self.total, s.stopped_at))
            if s.error:
                info["all_results_error"] = s.error
        return info


FAILED_BASIS = "the tool stopped with an error and scanned nothing (see error)"


def fail(message, **extra):
    print_answer({"error": message, "status": "failed", "status_basis": "the tool stopped with an error: %s" % message, "tool": TOOL, **extra})
    sys.exit(1)


def unexpected(kind, value, _tb):
    """An error nobody expected is an answer too: its class only, since its message can quote what was read."""
    print(json.dumps({"error": "internal error: %s" % kind.__name__, "tool": TOOL, "status": "failed", "status_basis": FAILED_BASIS}))
    sys.stdout.flush()
    os._exit(1)


sys.excepthook = unexpected


def on_stdout(resolve, *given):
    """The image and offset resolvers end with SystemExit(<JSON text>), which Python prints on stderr: the answer belongs on stdout."""
    try:
        return resolve(*given)
    except SystemExit as exc:
        if isinstance(exc.code, str):
            try:
                doc = json.loads(exc.code)
            except ValueError:
                doc = {"ok": False, "error": exc.code}
            if isinstance(doc, dict):
                doc = {"ok": False, "status": "failed", "status_basis": "the tool stopped with an error: %s" % doc.get("error"), **doc}
            print_answer(doc)
            sys.exit(1)
        raise


def whole(args, key, default, low, high):
    value = args.get(key)
    if value is None:
        return default
    if not isinstance(value, int) or isinstance(value, bool) or not low <= value <= high:
        fail("%s is a whole number from %d to %d" % (key, low, high), **{key: value})
    return value


try:
    args = json.load(sys.stdin)
except (ValueError, RecursionError) as exc:
    fail("arguments are not valid JSON", reason=str(exc)[:200])
if not isinstance(args, dict):
    fail("arguments are a JSON object")
needles = args.get("needles") or ""
if isinstance(needles, list) and all(isinstance(n, str) for n in needles):
    need_list = [n for n in needles if n]
elif isinstance(needles, str):
    need_list = [n for n in needles.split("|") if n]
else:
    fail("needles is a pipe-separated string or a list of strings")
path = args.get("path") or ""
if not isinstance(path, str) or "\0" in path:
    fail("path is a string without a NUL byte")
inode = args.get("inode")
context = whole(args, "context", 60, 0, CONTEXT_MAX)          # 0 is 0, not the default
max_hits = whole(args, "max_hits", 20, 1, HITS_MAX)
chunk = whole(args, "chunk", CHUNK_DEFAULT, CHUNK_MIN, CHUNK_MAX)
max_seconds = whole(args, "max_seconds", SECONDS_DEFAULT, 1, SECONDS_MAX)
sector_size = args.get("sector_size")
if sector_size is not None and (not isinstance(sector_size, int) or isinstance(sector_size, bool)
                                or sector_size < 512 or sector_size > SECTOR_MAX or sector_size % 512):
    fail("sector_size must be a multiple of 512 from 512 to %d (the Sleuth Kit's -b takes no other)" % SECTOR_MAX, sector_size=sector_size)
write_values = args.get("write_values", False)
if not isinstance(write_values, bool):
    fail("write_values is true or false")
need_list = list(dict.fromkeys(need_list))          # a needle given twice is one needle
if not need_list:
    fail("needles required, pipe-separated")
if len(need_list) > NEEDLES_MAX:
    fail("at most %d needles" % NEEDLES_MAX, given=len(need_list))
variants = []
for n in need_list:
    try:
        raw, wide = n.encode("utf-8"), n.encode("utf-16le")
    except UnicodeEncodeError:
        fail("a needle is not text that can be encoded")
    if len(raw) > NEEDLE_BYTES_MAX:
        fail("a needle is longer than %d bytes" % NEEDLE_BYTES_MAX)
    variants.append((n, "ascii", raw))
    variants.append((n, "utf16le", wide))
longest = max(len(v[2]) for v in variants)
try:
    secret = SecretValues(write_values)
except SecretValuesRefused as exc:
    fail(str(exc), write_values="refused")


def _stopped(signum):
    proc = CHILD["proc"]
    if proc is not None:
        try:
            proc.kill()
            proc.wait(timeout=5)
        except Exception:  # noqa: BLE001 - best effort: the process is ended with the tool anyway
            pass
    try:
        secret.close()
    except Exception:  # noqa: BLE001
        pass
    print(json.dumps({"tool": TOOL, "status": "partial", "interrupted": True, "signal": signum, "scanned_bytes": PROGRESS["scanned"],
                      "secret_values": secret.summary(),
                      "status_basis": "the tool was stopped by signal %d: the icat it was reading (if any) was ended, the counts and locators so far were not kept, and a values file "
                                      "already begun holds the rows written before the stop" % signum}), flush=True)


install_signal_handlers(_stopped)


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


def read_some(pipe, chunk, deadline):
    """Up to `chunk` bytes from icat's pipe, waiting on the clock: b"" at the end of the stream, None when the clock ran out first. A blocking
    read would wait for an icat that stalls (a damaged image, a hung disk) for as long as it likes."""
    fd = pipe.fileno()
    while True:
        left = deadline - time.monotonic()
        if left <= 0:
            return None
        ready, _, _ = select.select([fd], [], [], min(left, 0.2))
        if ready:
            return os.read(fd, chunk)


def scan_fh(fh, source, total=None):
    counts = {n: {"ascii": 0, "utf16le": 0} for n in need_list}
    key = [source["label"], source.get("image"), source.get("volume_offset_sectors"), source.get("inode"), source.get("sector_size"), context]
    shared = LocatorFile("chunk_needles", key + [need_list])
    PAGES.append(shared)
    pages = {n: Locators(shared, i, n, max_hits) for i, n in enumerate(need_list)}

    def emit(at, name, enc, nb, buf, base, vi):
        i = at - base
        a, b = max(0, i - context), min(len(buf), i + len(nb) + context)
        raw = buf[a:b]
        # Named by where the occurrence starts in the stream and which needle variant it is, so a scan that goes on from next_start never
        # gives an id an earlier call gave to another occurrence.
        fid = "F%d-%d" % (at, vi)
        counts[name][enc] += 1
        pages[name].add({"finding_id": fid, "off": at, "enc": enc, "context_length": len(raw)})
        if write_values:
            secret.add(fid, {"source": source["label"], "offset": at, "needle": name, "encoding": enc},
                       "".join(chr(c) if 32 <= c < 127 else "." for c in raw))

    # The shared engine finds every occurrence once, in (offset, needle) order, whatever chunk is (see StreamScan above). The clock is
    # looked at between feeds and every CLOCK_EVERY matches: between feeds the occurrences that start before scanner.done are the answer,
    # inside a feed those that start at or before the offset of the match it stopped at (all of that offset's first), so next_start is that
    # offset + 1.
    scanner = StreamScan([v[2] for v in variants], before=context, after=context)
    deadline = STARTED + max_seconds
    stopped = None
    scanned = 0
    taken, cut = [0], [None]

    def drain(matches):
        """Emit the matches a feed hands out; False when the clock stopped them, after the last one of the offset it stopped at."""
        for at, vi, buf, base in matches:
            if cut[0] is not None and at != cut[0]:
                return False
            name, enc, nb = variants[vi]
            emit(at, name, enc, nb, buf, base, vi)
            taken[0] += 1
            if cut[0] is None and taken[0] % CLOCK_EVERY == 0 and time.monotonic() > deadline:
                cut[0] = at
        return True
    piped = source["kind"] == "icat"
    try:
        while stopped is None:
            data = read_some(fh, chunk, deadline) if piped else fh.read(chunk)
            if data is None:                    # icat said nothing until the clock ran out: what it had given is scanned, the rest is the next scan's
                stopped = scanner.done
                break
            if not data:
                break
            for off in range(0, len(data), FEED):
                block = data[off:off + FEED] if len(data) > FEED else data
                inside = not drain(scanner.feed(block))
                scanned += len(block)
                PROGRESS["scanned"] = scanned
                if inside:
                    stopped = cut[0] + 1
                    break
                if time.monotonic() > deadline and (total is None or scanned < total):
                    stopped = scanner.done        # every occurrence that starts before this is reported; the rest are the next scan's
                    break
        if stopped is None and not drain(scanner.feed(b"", final=True)):
            stopped = cut[0] + 1
        shared.finish()
        hits = {}
        for n in need_list:
            page = pages[n].finish()
            hits[n] = {**counts[n], "locations": pages[n].page, **page}
    finally:
        shared.discard()                        # no half-written file is left when the run did not finish
    return hits, scanned, stopped


if path:
    if not os.path.isfile(path):
        fail(f"path not found: {path}")
    source = {"kind": "file", "path": path, "bytes": os.path.getsize(path)}
    source["label"] = path
    try:
        with open_regular(path) as f:
            hits, scanned, stopped = scan_fh(f, source, source["bytes"])
    except OSError as exc:
        fail("cannot read %s: %s" % (path, exc.strerror or exc))
else:
    if inode is None:
        fail("path or inode required")
    if isinstance(inode, bool) or not (isinstance(inode, int) and inode >= 0 or isinstance(inode, str) and INODE.match(inode)):
        fail("inode is a Sleuth Kit address: a number, or number-type-id for an NTFS stream (168-128-4)", inode=inode)
    if args.get("image") is not None and (not isinstance(args.get("image"), str) or "\0" in args.get("image")):
        fail("image is a string without a NUL byte")
    image = on_stdout(_resolve_image, args.get("image"))
    if not os.path.isfile(image):
        fail(f"image not found: {image}")
    given_offset = args.get("offset")
    if given_offset is not None and (isinstance(given_offset, bool) or not isinstance(given_offset, int) or given_offset < 0):
        fail("offset is a volume offset in sectors, a whole number", offset=given_offset)
    if not shutil.which("icat"):
        fail("icat is not on PATH", install="brew install sleuthkit, or apt-get install -y sleuthkit")
    offset = on_stdout(_resolve_offset, image, given_offset)
    inode = "-".join(str(int(p)) for p in str(inode).split("-"))      # 084284 is address 84284
    cmd = ["icat"] + (["-b", str(sector_size)] if sector_size else []) + ["-o", str(offset), image, str(inode)]
    source = {"kind": "icat", "image": image, "volume_offset_sectors": offset, "inode": str(inode),
              "sector_size": sector_size, "command": " ".join(cmd)}
    source["label"] = f"icat:{inode}@{offset}"
    # Streamed, never held whole: capture_output kept a pagefile's gigabytes
    # in memory until the VM's kernel killed the tool, with no word said
    # (sixth CTF round, twice). stderr goes to a file so a chatty icat
    # cannot stall the pipe being read.
    try:
        open_regular(image).close()       # the image was checked a moment ago: a FIFO or device put in its place is refused, not handed to icat
    except (OSError, ValueError) as exc:
        fail("the image is not a regular file that can be read: %s" % (getattr(exc, "strerror", None) or exc.__class__.__name__), image=image)
    with tempfile.TemporaryFile() as errf:
        proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=errf)
        CHILD["proc"] = proc
        hits, scanned, stopped = scan_fh(proc.stdout, source)
        if stopped is not None:
            proc.kill()                       # icat is blocked writing to a pipe nobody reads any more; its exit is not a failure
        rc = proc.wait()
        errf.seek(0)
        err_text = errf.read().decode("utf-8", "replace").strip()
    if rc != 0 and stopped is None:
        secret.close()
        print_answer({"error": err_text or f"icat exit {rc}", "tool": TOOL, "status": "failed", "status_basis": "icat failed, so what was found before it is not a result (see error)",
                          "image": image, "inode": inode, "offset": offset, "scanned_bytes": scanned,
                          "note": "what was found before icat failed is not a result; any locator or values file written meanwhile is partial",
                          "secret_values": secret.summary()})
        sys.exit(1)
secret.close()
# A needle whose list past the inline page is not whole in a file (the file could not be written, or reached its cap) is a loss the
# counts do not show: it makes the answer partial, and the basis names the needles and where the rest is.
lost = [h["needle_index"] for h in hits.values() if h.get("all_results_error") or h.get("all_results_complete") is False]
answer = {
    "tool": TOOL, "source": source, "scanned_bytes": scanned, "hits": hits,
    "complete": stopped is None and secret.stopped_at is None and not lost,
    "status": "complete" if stopped is None and not lost else "partial",
    "status_basis": ("the whole stream was read and every occurrence in it is reported" if stopped is None
                     else "the scan stopped at its clock before the end of the stream (see stopped): only occurrences that start before next_start are reported"),
    "match_policy": "every occurrence by its start offset in the scanned stream, overlapping ones included, case-sensitive; each needle as UTF-8 and as UTF-16LE",
    "context": {"bytes_each_side": context, "returned_inline": False,
                "note": "context bytes are not returned: they are where a secret sits. write_values: true, in a job run as secret output, writes them to a file under $OUT."},
    "secret_values": secret.summary(),
}
if stopped is not None:
    answer["next_start"] = stopped
    answer["stopped"] = ("the %d-second time budget was used after %d bytes of the stream: the counts and hits are for the occurrences that start before offset %d; %s"
                         % (max_seconds, scanned, stopped,
                            "go on with ioc_scan path=%s start=%d and the same needles" % (path, stopped) if path else
                            "extract the inode (icat_extract) and go on with ioc_scan on the file, start=%d" % stopped))
if lost:
    shown = ", ".join(str(i) for i in lost[:10]) + (" and %d more" % (len(lost) - 10) if len(lost) > 10 else "")
    answer["status_basis"] = answer["status_basis"].replace(
        "the whole stream was read and every occurrence in it is reported",
        "the whole stream was read and the count and the inline page of every needle are of all of it") + (
        "; the list of locators past the inline page is not whole for %d needle(s) (needle_index %s: all_results_error or all_results_complete in "
        "hits) and the rest of it is not on disk: scan again with max_hits at least the needle's count (matched), or with fewer needles" % (len(lost), shown))
if secret.stopped_at is not None:
    answer["status"] = "partial"
    answer["status_basis"] += "; the values file stopped at its cap (secret_values.stopped_at_offset), the locators did not"
print_answer(answer)
