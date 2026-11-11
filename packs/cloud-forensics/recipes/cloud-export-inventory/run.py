#!/usr/bin/env python3
"""Inventory a set of cloud log exports: what is in each file, what it names as missing, and how the set compares with what was asked for.

    run.py detect --target T          exit 0 when the target holds a cloud log export, 1 when it does not, 2 when it cannot be read
    run.py run --target T --out DIR

The target is the export set: a directory (walked without following links) or files named one by one. A small JSON file the caller writes
beside the export, named `acquisition.json` or ending in `.acquisition.json`, is the acquisition metadata and is read, not inventoried:
{"exported_by": ..., "query": ..., "permission": ..., "interval_requested": {"start": ..., "end": ...}, "result_size": ..., "expected_pages": ...}.
Every key is optional; a key that is not there is reported as not recorded, never guessed.

Per file the recipe states the format (JSON, JSON Lines, CSV, gzip of those; archives are named and not opened), the provider and tenant,
project or account the records name, how many records it counted, how many of them a reader of this pack takes (cloud_normalise's adapters,
cloudtrail_parse, ual_parse, signin_analyse) and how many nothing here reads, the time range the records carry, the markers of a next page
(`nextPageToken`, `NextToken`, `nextLink`, `@odata.nextLink`), and whether the count equals a result cap (5,000 or 50,000 rows, or the
`result_size` the caller recorded). For the set it states the interval requested against the interval returned, the duplicates (within a file
and across files), the gaps between the files' time ranges, and the pages named `page-K-of-N` that are not there.

EXPORT completeness is not LOGGING completeness. This recipe reads the exports that were supplied: it says nothing about what the provider
logged, how long it kept it, or what was never exported, and `coverage.json` says so apart. A record count that equals a cap, a next-page
marker, a missing page and a gap between ranges are reasons to doubt that the export is whole; their absence does not show that it is.

The receipt, coverage.json, exists from the first moment and is rewritten after every step, so a run that is cut off (the outer time limit, a
signal, a kill) leaves what was done: status "partial" with finished false until the last step. Every input has its own status (complete, partial,
unsupported, empty, failed, not_attempted). One deadline (CLOUD_EXPORT_INVENTORY_SECONDS, default 3300, under the recipe's 3600) covers the walk and
the reads. An earlier run's receipt is never overwritten: a directory that already holds coverage.json is refused.

The recipe starts no program. It prints no record value: a file's counts, ranges and the identifiers of its tenant, project or account (at most 20
a file) are what it keeps. files.tsv and findings.tsv hold file names and those identifiers and are marked secret_bearing in the receipt (the mark is
informational: nothing in the harness reads it for a decision).
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
            sys.stderr.write("%s\n" % (code,))
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


import json
import os
import signal
import sys


def _before_start(signum, _frame):
    """A stop that arrives while the rest of this file is still loading: the first signal counts, nothing was read or written, and the one answer
    says so. main() installs the recipe's own handlers and replaces this one."""
    for other in (signal.SIGTERM, signal.SIGINT, signal.SIGHUP):
        signal.signal(other, signal.SIG_IGN)
    try:
        sys.stdout.write(json.dumps({"recipe": "cloud-export-inventory", "status": "partial", "ok": False, "stage": "starting",
                                     "status_basis": "stopped by signal %d before any work: nothing was read or written" % signum,
                                     "interrupted_by_signal": signum}) + "\n")
        sys.stdout.flush()
    except (OSError, ValueError):
        pass
    os._exit(128 + signum)


for _signum in (signal.SIGTERM, signal.SIGINT, signal.SIGHUP):
    signal.signal(_signum, _before_start)   # replaced by main() once the module is loaded


import calendar
import codecs
import csv
import datetime
import errno
import hashlib
import itertools
import re
import stat
import struct
import time
import zlib

RECIPE = "cloud-export-inventory"
RECIPE_SECONDS = 3600.0       # the recipe's limit
DEADLINE = min(float(os.environ.get("CLOUD_EXPORT_INVENTORY_SECONDS", "3300")), 3500.0)   # under the recipe's 3600-second limit

# ---- copied from the cloud tools' shared block, byte for byte (tests/pack-cloud-export-inventory.test.ts holds them equal) ----------------------
FIRST_PROBLEMS = 25               # how many failures an answer names inline; every one is in the file the page names
MAX_RECORD_BYTES = 16 << 20       # one record (a JSON Lines line, an array element, a CSV field) larger than this is rejected, named
MAX_DOCUMENT_BYTES = 64 << 20     # what may sit in front of a document's array of records, or a document with none, larger than this is refused, named
MAX_EXPANDED_BYTES = 4 << 30      # per file, after decompression
MAX_INT_DIGITS = 4000             # an integer written with more digits is kept as the text it was written as (Python cannot print one past 4300)
MAX_FIELD_BYTES = 16 << 20        # one CSV line (a field may span lines) longer than this stops the file, named
CHUNK = 1 << 20

# ---- timestamps -------------------------------------------------------------------------------------------------

_EPOCH = datetime.datetime(1970, 1, 1)
ISO_STAMP = re.compile(r"^\s*(\d{4})-(\d{2})-(\d{2})[T ](\d{2}):(\d{2})(?::(\d{2})(?:[.,](\d{1,9}))?)?\s*(Z|z|[+-]\d{2}(?::?\d{2})?)?\s*$")
SLASH_STAMP = re.compile(r"^\s*(\d{1,2})/(\d{1,2})/(\d{4})[ ,T]+(\d{1,2}):(\d{2})(?::(\d{2})(?:[.,](\d{1,9}))?)?\s*([AaPp][Mm])?\s*(Z|z|[+-]\d{2}(?::?\d{2})?)?\s*$")


def _clock_ok(y, mo, d, h, mi, s):
    return 1 <= mo <= 12 and 1 <= d <= calendar.monthrange(y, mo)[1] and 0 <= h <= 23 and 0 <= mi <= 59 and 0 <= s <= 59


def slash_order(raw):
    """'mdy', 'dmy', 'either' (the two fields are equal) or 'ambiguous' for a day/month/year string; None if it is not one."""
    m = SLASH_STAMP.match(raw) if isinstance(raw, str) else None
    if not m:
        return None
    a, b = int(m.group(1)), int(m.group(2))
    if a == b:
        return "either"
    if a > 12 >= b:
        return "dmy"
    if b > 12 >= a:
        return "mdy"
    return "ambiguous" if a <= 12 and b <= 12 else None


def proven_order(raw):
    """'dmy' or 'mdy' when the day/month/year string can be read only that way and read that way it is a real date; else None."""
    got = slash_order(raw)
    if got in ("dmy", "mdy") and parse_stamp(raw, got, True)["ns"] is not None:
        return got
    return None


def parse_stamp(raw, order=None, assume_utc=False):
    """A time as the export wrote it, decoded without a guess.

    Returns {utc, ns, status, basis}. `utc` is ISO 8601 UTC with the fractions as written; `ns` is nanoseconds from the
    1970 epoch (for sorting and differences). `status` is zoned (the string carried an offset or Z), assumed_utc (it carried
    none and the caller said to read it as UTC), no_zone (it carried none and nothing was assumed), ambiguous_date_order
    (a day/month/year string with both fields up to 12 and no declared order), unparseable or missing. Nothing is
    assumed unless asked: a clock with no zone is not UTC because it is convenient, and 03/04/2026 is not March because
    a program was written in one country."""
    if raw is None or raw == "":
        return {"utc": None, "ns": None, "status": "missing", "basis": "no time in the record"}
    if not isinstance(raw, str):
        return {"utc": None, "ns": None, "status": "unparseable", "basis": "the time is not a string (%s)" % type(raw).__name__}
    m = ISO_STAMP.match(raw)
    if m:
        y, mo, d, h, mi = (int(m.group(i)) for i in (1, 2, 3, 4, 5))
        s, frac, zone = int(m.group(6) or 0), m.group(7) or "", m.group(8)
        am = None
    else:
        m = SLASH_STAMP.match(raw)
        if not m:
            return {"utc": None, "ns": None, "status": "unparseable", "basis": "not an ISO 8601 or day/month/year time"}
        got = slash_order(raw)
        use = order if order in ("mdy", "dmy") else ("mdy" if got == "mdy" else "dmy" if got == "dmy" else "mdy" if got == "either" else None)
        if use is None:
            return {"utc": None, "ns": None, "status": "ambiguous_date_order",
                    "basis": "both leading fields are 12 or less and no date_order was declared or proved by other rows"}
        if got in ("mdy", "dmy") and got != use:
            return {"utc": None, "ns": None, "status": "unparseable", "basis": "the field order contradicts date_order %s" % use}
        a, b, y = int(m.group(1)), int(m.group(2)), int(m.group(3))
        mo, d = (a, b) if use == "mdy" else (b, a)
        h, mi, s, frac, am, zone = int(m.group(4)), int(m.group(5)), int(m.group(6) or 0), m.group(7) or "", m.group(8), m.group(9)
        if am:
            if not 1 <= h <= 12:
                return {"utc": None, "ns": None, "status": "unparseable", "basis": "an hour outside 1-12 beside AM or PM"}
            h = h % 12 + (12 if am.lower() == "pm" else 0)
    if not _clock_ok(y, mo, d, h, mi, s):
        return {"utc": None, "ns": None, "status": "unparseable", "basis": "a date or clock value out of range"}
    offset = 0
    if zone and zone not in ("Z", "z"):
        digits = zone[1:].replace(":", "")
        offset = (int(digits[:2]) * 3600 + int(digits[2:4] or 0) * 60) * (1 if zone[0] == "+" else -1)
        status, basis = "zoned", "the string carries the offset %s" % zone
    elif zone:
        status, basis = "zoned", "the string carries Z"
    elif assume_utc:
        status, basis = "assumed_utc", "the string carries no zone; read as UTC because assume_utc was set"
    else:
        return {"utc": None, "ns": None, "status": "no_zone", "basis": "the string carries no zone and assume_utc was not set"}
    try:
        secs = calendar.timegm((y, mo, d, h, mi, s, 0, 0, 0)) - offset
        base = (_EPOCH + datetime.timedelta(seconds=secs)).strftime("%Y-%m-%dT%H:%M:%S")
    except (ValueError, OverflowError):
        return {"utc": None, "ns": None, "status": "unparseable", "basis": "a date outside the years 1 to 9999"}
    ns = secs * 1000000000 + (int(frac.ljust(9, "0")) if frac else 0)
    if not -(1 << 63) < ns < (1 << 63):
        return {"utc": None, "ns": None, "status": "unparseable", "basis": "a date outside 1678-2261, the range of nanoseconds a 64-bit integer holds"}
    return {"utc": base + ("." + frac if frac else "") + "Z", "ns": ns, "status": status, "basis": basis}


def ns_to_utc(ns):
    if ns is None:
        return None
    secs, rest = divmod(ns, 1000000000)
    try:
        base = (_EPOCH + datetime.timedelta(seconds=secs)).strftime("%Y-%m-%dT%H:%M:%S")
    except (ValueError, OverflowError):
        return None
    return base + ("." + ("%09d" % rest).rstrip("0") if rest else "") + "Z"


# ---- reading files: a bounded stream of JSON values -------------------------------------------------------------

BOM = "\ufeff"
REPLACEMENT = "\ufffd"
_SPACE = re.compile(r"\s*")
ARCHIVE_EXT = (".zip", ".7z", ".rar", ".tar", ".tgz", ".bz2", ".xz", ".zst", ".lz4")
ARCHIVE_MAGIC = ((b"PK\x03\x04", "a ZIP archive"), (b"PK\x05\x06", "a ZIP archive"), (b"PK\x07\x08", "a ZIP archive"),
                 (b"BZh", "a bzip2 file"), (b"\xfd7zXZ\x00", "an xz file"), (b"\x28\xb5\x2f\xfd", "a Zstandard file"),
                 (b"7z\xbc\xaf\x27\x1c", "a 7-Zip archive"), (b"Rar!", "a RAR archive"), (b"\x04\x22\x4d\x18", "an LZ4 file"))


def _no_constant(name):
    raise json.JSONDecodeError("%s is not JSON" % name, "", 0)


def _number(text):
    """A number written with a decimal point or an exponent. One that does not fit a float (1e999) is kept as the text it was written as,
    not turned into an infinity that no JSON answer can hold."""
    value = float(text)
    return text if value in (_INF, -_INF) else value


def _integer(text):
    """An integer. One of more than MAX_INT_DIGITS digits is kept as its text: Python refuses to print one past 4300 digits."""
    return int(text) if len(text) <= MAX_INT_DIGITS else text


_INF = float("inf")
_DEC = json.JSONDecoder(parse_constant=_no_constant, parse_float=_number, parse_int=_integer)
DECODE_ERRORS = [0]


def _count_replace(exc):
    DECODE_ERRORS[0] += exc.end - exc.start
    return (REPLACEMENT * (exc.end - exc.start), exc.end)


codecs.register_error("cloud_replace", _count_replace)


def loads_strict(text):
    """json.loads that refuses NaN, Infinity and -Infinity (an answer holding one is not JSON to the next reader)."""
    return _DEC.decode(text)


def archive_kind(head):
    for magic, name in ARCHIVE_MAGIC:
        if head.startswith(magic):
            return name
    if head[257:262] == b"ustar":
        return "a tar archive"
    return None


def walk_inputs(top, wanted, skipped):
    """The regular files under `top`: the files of a directory in name order, then its subdirectories in name order. A link,
    a special file (a pipe is never opened), an unlistable directory and an archive are named in `skipped`, and so is a file
    whose name `wanted` refuses."""
    stack = [top]
    found = []
    while stack:
        if out_of_time():
            skipped.append({"path": shown_path(stack[-1]), "reason": "the time limit ended the listing of directories: this one and the rest were not listed"})
            return found
        directory = stack.pop()
        try:
            with os.scandir(directory) as it:
                entries = sorted(it, key=lambda e: e.name)
        except OSError as exc:
            skipped.append({"path": shown_path(directory), "reason": "the directory could not be listed", "error": describe(exc)})
            continue
        subdirs = []
        for n, entry in enumerate(entries):
            if n % 4096 == 4095 and out_of_time():
                skipped.append({"path": shown_path(directory), "reason": "the time limit ended the listing of this directory: its entries from %s on were not examined" % shown_path(entry.name)})
                return found
            try:
                if entry.is_symlink():
                    skipped.append({"path": shown_path(entry.path), "reason": "a symbolic link: links are not followed"})
                elif entry.is_dir(follow_symlinks=False):
                    subdirs.append(entry.path)
                elif not stat.S_ISREG(entry.stat(follow_symlinks=False).st_mode):
                    skipped.append({"path": shown_path(entry.path), "reason": "not a regular file: it is not opened"})
                elif wanted(entry.name):
                    found.append(entry.path)
                elif entry.name.lower().endswith(ARCHIVE_EXT):
                    skipped.append({"path": shown_path(entry.path), "reason": "an archive: extract it first; it was not read"})
                else:
                    skipped.append({"path": shown_path(entry.path), "reason": "its name is not one this tool reads"})
            except OSError as exc:
                skipped.append({"path": shown_path(entry.path), "reason": "the entry could not be examined", "error": describe(exc)})
        stack.extend(reversed(subdirs))
    return found


def gzip_header_length(buf):
    """The length of the gzip member header at the start of `buf`, None if `buf` ends inside it; ValueError if it is not one."""
    if len(buf) < 2:
        if buf[:1] and buf[:1] != b"\x1f":
            raise ValueError("not gzip")
        return None
    if buf[:2] != b"\x1f\x8b":
        raise ValueError("not gzip")
    if len(buf) < 10:
        return None
    if buf[2] != 8:
        raise ValueError("not deflate")
    flags, pos = buf[3], 10
    if flags & 4:
        if len(buf) < pos + 2:
            return None
        pos += 2 + int.from_bytes(buf[pos:pos + 2], "little")
    for bit in (8, 16):
        if flags & bit:
            end = buf.find(b"\x00", pos)
            if end < 0:
                return None
            pos = end + 1
    if flags & 2:
        pos += 2
    return pos if len(buf) >= pos else None


class Source:
    """One file as a stream of text. Gzip is recognised by its magic bytes (not its name) and expanded as it is read, at most
    `cap` bytes of expansion, every byte up to a break kept (a gzip that ends early, or fails its check, gives what came before
    it and says so in `error`); an archive (ZIP, tar, bzip2, xz, 7-Zip...) is named and not read. UTF-8 is assumed, UTF-16
    where a byte order mark says so; each byte that does not decode becomes U+FFFD and is counted in `replaced`. The read
    ends at the deadline (`timed_out`). Zero bytes after the last gzip member, to the end of the file, are padding (GNU gzip
    ignores them): they are counted in `trailing_zero_bytes` and are not a problem. Every problem of a file is kept in
    `problems` (the first FIRST_PROBLEMS), the rest counted, and `error` is the first."""

    def __init__(self, path, cap):
        self.path, self.cap = path, cap
        self.buf, self.pos = "", 0
        self.eof = False
        self.bytes_read = 0
        self.compressed = False
        self.error = None          # the first problem of the file; `problems` holds them in order, `problem_lines()` is what the answer lists
        self.problems = []
        self.problems_total = 0
        self.trailing_zero_bytes = 0
        self._zero_run = 0
        self._member = 0
        self.archive = None
        self.capped = False
        self.timed_out = False
        self.replaced = 0
        self.line = 1
        self.chars_before = 0
        self.encoding = "utf-8"
        self._dec = codecs.getincrementaldecoder("utf-8")("cloud_replace")
        self._first = True
        self._pending = b""
        self._ended = False
        self._state, self._hdr, self._tr, self._d, self._crc, self._isize = "header", b"", b"", None, 0, 0
        self.fh = self._raw = None
        try:
            if not stat.S_ISREG(os.stat(path).st_mode):
                raise OSError(errno.EINVAL, "not a regular file")
            self._raw = open(path, "rb")
            head = self._raw.read(512)
            self._raw.seek(0)
            kind = archive_kind(head)
            if kind:
                self.archive = kind
                self._problem("%s: extract it first; it was not read" % kind)
                self.eof = True
            elif head[:2] == b"\x1f\x8b":
                self.compressed = True
            self.fh = self._raw
        except OSError as exc:
            self._problem(describe(exc))
            self.eof = True

    def _problem(self, text):
        """Keep a problem of this file. The first stays in `error`; the first FIRST_PROBLEMS are listed, the rest are counted."""
        self.problems_total += 1
        if len(self.problems) < FIRST_PROBLEMS:
            self.problems.append(text)
        if self.error is None:
            self.error = text

    def problem_lines(self):
        """Every problem of the file in the order it happened (the first FIRST_PROBLEMS), and a line counting the rest."""
        lines = list(self.problems)
        if self.problems_total > len(self.problems):
            lines.append("%d more problem(s) of this file were counted and are not listed" % (self.problems_total - len(self.problems)))
        return lines

    def close(self):
        for h in (self.fh, self._raw):
            try:
                if h is not None:
                    h.close()
            except OSError:
                pass

    def _expand(self, want):
        """Up to `want` bytes of expansion of a gzip file (members one after another), bounded in memory by `want`. The members are
        read here, header, deflate data and trailer, so that a break or a failed check costs only the step it happened in: every
        byte before it is returned."""
        out = []
        got = 0
        while got < want and not self._ended:
            if out_of_time():                 # millions of empty members are many steps and no output: the deadline is checked here too
                self.timed_out = True
                self._ended = True
                break
            if not self._pending:
                raw = self._raw.read(1 << 18)
                if not raw:
                    if self._state != "header" or self._hdr:
                        self._problem("the compressed stream ends early, after %d bytes of expansion: what came before it was read" % (self.bytes_read + got))
                    else:
                        self.trailing_zero_bytes = self._zero_run         # zero padding after the last member, to the end of the file: counted, not damage
                    self._ended = True
                    break
                self._pending = raw
            if self._state == "header":
                buf = self._hdr + self._pending
                if self._zero_run or buf[:1] == b"\x00":
                    stripped = buf.lstrip(b"\x00")                 # zeros cannot begin a member; GNU gzip ignores such padding at the end of a file
                    self._zero_run += len(buf) - len(stripped)
                    buf = stripped
                    if not buf:
                        self._hdr = self._pending = b""
                        continue
                try:
                    if self._zero_run:
                        raise ValueError("zeros, then something that is not the end of the file")
                    n = gzip_header_length(buf)
                except ValueError:
                    self._problem("%d bytes follow the end of the compressed stream and are not another member: they were not read" % (self._zero_run + len(buf)))
                    self._ended = True
                    self._pending = b""
                    break
                if n is None:
                    self._hdr, self._pending = buf, b""
                    continue
                self._pending, self._hdr = buf[n:], b""
                self._d, self._crc, self._isize, self._state = zlib.decompressobj(-15), 0, 0, "body"
            elif self._state == "body":
                try:
                    piece = self._d.decompress(self._pending, min(want - got, 32768))
                except zlib.error as exc:
                    self._problem("the compressed stream is damaged after %d bytes of expansion (%s): what came before it was read" % (self.bytes_read + got, exc))
                    self._ended = True
                    self._pending = b""
                    break
                self._pending = self._d.unconsumed_tail
                if self._d.eof:
                    self._pending = self._d.unused_data      # at the end of the stream the tail repeats what is already here
                if piece:
                    out.append(piece)
                    got += len(piece)
                    self._crc = zlib.crc32(piece, self._crc)
                    self._isize += len(piece)
                if self._d.eof:
                    self._state = "trailer"
            else:
                take = self._pending[:8 - len(self._tr)]
                self._tr += take
                self._pending = self._pending[len(take):]
                if len(self._tr) == 8:
                    crc, size = struct.unpack("<II", self._tr)
                    self._tr = b""
                    self._member += 1
                    failed = (["CRC-32"] if crc != self._crc & 0xFFFFFFFF else []) + (["length"] if size != self._isize & 0xFFFFFFFF else [])
                    if failed:
                        self._problem("member %d of the compressed stream fails its %s check: its bytes were read and may be wrong" % (self._member, " and ".join(failed)))
                    self._state = "header"
        return b"".join(out)


    def fill(self):
        """Read one more chunk into the buffer; False at the end."""
        if self.eof:
            return False
        if out_of_time():
            self.timed_out = True
            self.eof = True
            return False
        room = self.cap - self.bytes_read
        want = min(CHUNK, room + 1)
        try:
            data = self._expand(want) if self.compressed else self.fh.read(want)
        except OSError as exc:
            self._problem(describe(exc))
            self.eof = True
            data = b""
        if self._first and self.compressed and data[257:262] == b"ustar":
            self.archive = "a tar archive"
            self._problem("a tar archive (gzip-compressed): extract it first; it was not read")
            self.eof = True
            data = b""
        if self._ended:
            self.eof = True
        if len(data) > room:
            data = data[:room]
            self.capped = True
            self.eof = True
        elif not data:
            self.eof = True
        if self._first and data[:2] in (b"\xff\xfe", b"\xfe\xff"):
            # A byte order mark: the export is UTF-16 (PowerShell's Export-Csv -Encoding Unicode writes it), not UTF-8.
            self._dec = codecs.getincrementaldecoder("utf-16")("cloud_replace")
            self.encoding = "utf-16"
        self.bytes_read += len(data)
        before = DECODE_ERRORS[0]
        text = self._dec.decode(data, final=self.eof)
        self.replaced += DECODE_ERRORS[0] - before
        if self._first and text:
            self._first = False
            if text[0] == BOM:
                text = text[1:]
        self.buf += text
        return bool(data)

    def advance(self, new_pos):
        self.line += self.buf.count("\n", self.pos, new_pos)
        self.pos = new_pos
        if self.pos > 4 * CHUNK:
            self.chars_before += self.pos
            self.buf = self.buf[self.pos:]
            self.pos = 0

    def ensure(self, n):
        while len(self.buf) - self.pos < n and self.fill():
            pass

    def skip_ws(self):
        while True:
            end = _SPACE.match(self.buf, self.pos).end()
            self.advance(end)
            if self.pos < len(self.buf) or not self.fill():
                return

    def offset(self):
        return self.chars_before + self.pos


class TooLong(Exception):
    pass


def _decode_at(src, limit, lead=""):
    """One JSON value at the read position (with `lead` put in front of the text, to read the rest of an object whose
    first key was already consumed), reading more while it is incomplete; `limit` bounds the text held while waiting for it
    to end. Returns the value and the buffer index after it. The position is not moved."""
    while True:
        text = lead + src.buf[src.pos:] if lead else src.buf
        at = 0 if lead else src.pos
        try:
            value, end = _DEC.raw_decode(text, at)
            if not isinstance(value, (dict, list)) and end >= len(text) and not src.eof:
                raise json.JSONDecodeError("a value that may continue", text, end)
            return value, (src.pos + end - len(lead)) if lead else end
        except json.JSONDecodeError as exc:
            if src.eof:
                raise
            # An error well inside the text is a real one; at its end, or in an unterminated string, the record may only be
            # incomplete, and more is read (within `limit`).
            if exc.pos < len(text) - 16 and not exc.msg.startswith("Unterminated string"):
                raise
            if len(src.buf) - src.pos > limit:
                raise TooLong()
            src.fill()
        except RecursionError:
            raise json.JSONDecodeError("nested too deeply", text, at)


_STRING = re.compile(r'"(?:[^"\\]|\\.)*"', re.S)
_TOKEN = re.compile(r'["{}\[\]]')
_BARE = re.compile(r'[^\s,}\]"\[{:]+')


def _more(src, i, limit):
    """Make buffer index `i` exist, reading as needed; False when the file ends first. Raises TooLong past `limit`."""
    while i >= len(src.buf):
        if len(src.buf) - src.pos > limit:
            raise TooLong()
        if not src.fill():
            return False
    return True


def _skip_ws_at(src, i, limit):
    while True:
        if not _more(src, i, limit):
            return i
        i = _SPACE.match(src.buf, i).end()
        if i < len(src.buf) or not _more(src, i, limit):
            return i


def _skip_value(src, i, limit):
    """The buffer index after the JSON value that starts at `i` (a scalar, a string, or a balanced object or array), found without
    parsing it; None if the file ends or the text is not JSON."""
    i = _skip_ws_at(src, i, limit)
    if not _more(src, i, limit):
        return None
    c = src.buf[i]
    if c == '"':
        while True:
            m = _STRING.match(src.buf, i)
            if m:
                return m.end()
            if not _more(src, len(src.buf), limit):
                return None
    if c in "{[":
        depth, j = 0, i
        while True:
            m = _TOKEN.search(src.buf, j)
            if not m:
                j = len(src.buf)
                if not _more(src, j, limit):
                    return None
                continue
            ch = m.group(0)
            if ch == '"':
                s = _STRING.match(src.buf, m.start())
                if not s:
                    if not _more(src, len(src.buf), limit):
                        return None
                    j = m.start()
                    continue
                j = s.end()
                continue
            depth += 1 if ch in "{[" else -1
            j = m.end()
            if depth == 0:
                return j
            if depth < 0:
                return None
    m = _BARE.match(src.buf, i)
    while m and m.end() >= len(src.buf) and not src.eof:
        if not _more(src, len(src.buf), limit):
            break
        m = _BARE.match(src.buf, i)
    return m.end() if m else None


_STR_RUN = re.compile(r'[^"\\]*+(?:\\.[^"\\]*+)*+', re.S)  # a string's body up to its closing quote, or to a lone backslash at the buffer's end (possessive, Python 3.11 and later: the plain form keeps state for every escape)
_JSON_RUN = re.compile(r'(?:[^"{}\[\]]++|"[^"\\]*+(?:\\.[^"\\]*+)*+")*+', re.S)   # plain text and whole strings, up to the next bracket or a string the buffer ends inside
_BRACKET = re.compile(r'[{}\[\]]')
_NOT_BRACKET = re.compile(r'[^{}\[\]]+')
_DEPTH_STEP = [0] * 256
_DEPTH_STEP[ord("{")] = _DEPTH_STEP[ord("[")] = 1
_DEPTH_STEP[ord("}")] = _DEPTH_STEP[ord("]")] = -1


def _skip_stream(src):
    """Move the read position past the JSON value that starts at it, holding none of it: the scan takes what the buffer has, moves
    the position on and reads the next chunk, so memory stays at one chunk whatever the size of the value (a record over
    max_record_bytes is skipped this way). It steps over strings and counts brackets and looks at nothing else, so it needs no
    valid JSON inside the value. The clock is read every 4096 steps, and `fill` reads it too. Returns "ok" (the position is after
    the value), "bad" (what stands there is not a value) or "end" (the file, the clock or the expansion cap ended it first:
    `src.timed_out` and `src.capped` say which)."""
    src.ensure(1)
    if src.pos >= len(src.buf):
        return "end"
    first = src.buf[src.pos]
    depth, in_string, steps = 0, False, 0
    if first in "{[":
        depth = 1
        src.advance(src.pos + 1)
    elif first == '"':
        in_string = True
        src.advance(src.pos + 1)
    else:
        m = _BARE.match(src.buf, src.pos)
        if not m:
            return "bad"
        while True:
            src.advance(m.end())
            if src.pos < len(src.buf) or not src.fill():
                return "ok"
            m = _BARE.match(src.buf, src.pos)
            if not m:
                return "ok"
    while True:
        buf, j, n = src.buf, src.pos, len(src.buf)
        while j < n:
            steps += 1
            if not steps & 4095 and out_of_time():
                src.advance(j)
                src.timed_out = True
                src.eof = True
                return "end"
            if in_string:
                e = _STR_RUN.match(buf, j).end()
                if e < n and buf[e] == '"':
                    j = e + 1
                    in_string = False
                    if depth == 0:
                        src.advance(j)
                        return "ok"
                    continue
                j = e                       # the buffer ends inside the string, or on a backslash whose next character is still to come
                break
            j = _JSON_RUN.match(buf, j).end()    # plain text and whole strings, at C speed, up to a bracket
            if j >= n:
                break
            if buf[j] == '"':               # a string the buffer ends inside
                in_string = True
                j += 1
                continue
            q = buf.find('"', j)            # a bracket: the stretch up to the next string
            end = q if q >= 0 else n
            closers = buf.count("}", j, end) + buf.count("]", j, end)
            if closers and depth - closers <= 0:
                # The value may end in this stretch. The lowest depth it reaches is found at C speed (the brackets alone, summed as they come);
                # only a stretch that does reach zero is walked bracket by bracket, to find where.
                lowest = min(itertools.accumulate(map(_DEPTH_STEP.__getitem__, _NOT_BRACKET.sub("", buf[j:end]).encode())))
                if depth + lowest <= 0:
                    for m in _BRACKET.finditer(buf, j, end):
                        depth += 1 if m.group() in "{[" else -1
                        if depth <= 0:
                            src.advance(m.end())
                            return "ok"
            depth += buf.count("{", j, end) + buf.count("[", j, end) - closers
            j = end
        src.advance(j)
        if not src.fill():
            return "end"


def envelope_scan(src, envelope_keys, limit):
    """For an object that starts at the read position: ("envelope", key, index after its `[`, names of the members before it)
    if a member named in `envelope_keys` holds an array, with the members in front of it skipped whatever they hold;
    ("plain", None, None, names) if the object ends without one; ("bad", reason, None, names) if it is not JSON. Nothing
    is consumed: the buffer only grows."""
    i = src.pos + 1
    names = []
    while True:
        i = _skip_ws_at(src, i, limit)
        if not _more(src, i, limit):
            return "bad", "the object is not closed", None, names
        c = src.buf[i]
        if c == "}":
            return "plain", None, i + 1, names
        if c == ",":
            i += 1
            continue
        if c != '"':
            return "bad", "a member name was expected", None, names
        while True:
            m = _STRING.match(src.buf, i)
            if m or not _more(src, len(src.buf), limit):
                break
        if not m:
            return "bad", "a member name is not closed", None, names
        key = m.group(0)[1:-1]
        i = _skip_ws_at(src, m.end(), limit)
        if not _more(src, i, limit) or src.buf[i] != ":":
            return "bad", "a colon was expected after a member name", None, names
        i = _skip_ws_at(src, i + 1, limit)
        if key in envelope_keys and _more(src, i, limit) and src.buf[i] == "[":
            return "envelope", key, i + 1, names
        names.append(key)
        j = _skip_value(src, i, limit)
        if j is None:
            return "bad", "the value of a member is not JSON or is not closed", None, names
        i = j


def read_units(src, envelope_keys, record_cap=MAX_RECORD_BYTES, document_cap=MAX_DOCUMENT_BYTES):
    """Yield the records of a JSON file as ("item", info, value) or ("reject", info, reason), one by one, whatever the
    shape: an array, an object with a named array of records (streamed, however much sits in front of it, and the object's
    other keys read after it), JSON Lines (a bad line is rejected and the next is read), or one pretty-printed document
    (read whole, within `document_cap`, and parsed once); several arrays or envelopes one after another are read in turn.
    `info` is {record, line, offset, chars, envelope}. After the last unit (or when the reader is closed early)
    `src.mode` names the shape, `src.extra_keys` the other top-level keys of the envelopes (names only) and `src.stopped`
    says why reading ended before the end of the file, if it did."""
    src.mode, src.extra_keys, src.stopped, src.envelope = "empty", [], None, None
    count, modes, extra = [0], [], set()

    def info(line, offset, chars, envelope):
        count[0] += 1
        return {"record": count[0], "line": line, "offset": offset, "chars": chars, "envelope": envelope}

    def skip_oversize(start_line, start_off, key):
        """A record over the cap, which the read position stands at: scan to its end without holding it (clocked, one chunk of
        memory). Returns the reject to yield, and whether the read must stop. A skipped record is rejected with where it was
        and how long; the records after it are read."""
        outcome = _skip_stream(src)
        if outcome == "ok":
            return ("reject", info(start_line, start_off, src.offset() - start_off, key),
                    "a record larger than max_record_bytes (%d): skipped, and the records after it are read" % record_cap), False
        if outcome == "bad":
            src.stopped = "what stands at line %d, where a record larger than max_record_bytes should be, is not a JSON value: the rest of the array was not read" % start_line
            return ("reject", info(start_line, start_off, None, key), "a record larger than max_record_bytes (%d), and not a JSON value" % record_cap), True
        src.stopped = ("the time limit ended the read" if src.timed_out else
                       "the expansion reached max_expanded_bytes inside a record larger than max_record_bytes at line %d" % start_line if src.capped else
                       "the array was not closed: the file ends inside a record larger than max_record_bytes at line %d" % start_line)
        return ("reject", info(start_line, start_off, None, key), "a record larger than max_record_bytes (%d), and the read ended inside it" % record_cap), True

    def finish():
        src.extra_keys = sorted(extra)
        src.mode = modes[0] if len(set(modes)) == 1 else ("mixed" if modes else "empty")
        if src.timed_out and not src.stopped:
            src.stopped = "the time limit ended the read"

    try:
        while True:
            src.ensure(4096)
            src.skip_ws()
            src.ensure(65536)
            if src.pos >= len(src.buf):
                break
            first = src.buf[src.pos]
            key, names, bracket, one_line = None, [], None, ""
            if first == "{":
                line_end = src.buf.find("\n", src.pos)
                one_line = src.buf[src.pos: line_end if line_end >= 0 else len(src.buf)].strip()
                if one_line == "{" or line_end < 0 or line_end - src.pos > 65536:
                    # a pretty-printed object, or one too long to be a JSON Lines record: look for the array of records in it
                    try:
                        kind, key, bracket, names = envelope_scan(src, envelope_keys, document_cap)
                    except TooLong:
                        src.stopped = ("the object around the records is larger than %d characters before its array of records: it was not read" % document_cap)
                        yield "reject", info(src.line, src.offset(), None, None), src.stopped
                        return
                    if kind != "envelope":
                        key, bracket = None, None
            if first == "[" or bracket is not None:
                modes.append("envelope" if bracket is not None else "array")
                if key:
                    src.envelope = src.envelope or key
                    extra.update(names)
                src.advance(bracket if bracket is not None else src.pos + 1)
                src.skip_ws()
                expecting_item = True
                while True:
                    while src.pos >= len(src.buf):
                        if not src.fill():
                            src.stopped = src.stopped or ("the time limit ended the read" if src.timed_out else "the array was not closed: the file ends inside it")
                            return
                    here = src.buf[src.pos]
                    if here == "]":
                        src.advance(src.pos + 1)
                        break
                    if here == ",":
                        if expecting_item:
                            src.stopped = "an unexpected comma at line %d: the rest of the array was not read" % src.line
                            yield "reject", info(src.line, src.offset(), None, key), "malformed JSON: an unexpected comma"
                            return
                        src.advance(src.pos + 1)
                        src.skip_ws()
                        expecting_item = True
                        continue
                    if not expecting_item:
                        src.stopped = "no comma between records at line %d: the rest of the array was not read" % src.line
                        yield "reject", info(src.line, src.offset(), None, key), "malformed JSON: no comma between records"
                        return
                    start_line, start_off, start_pos = src.line, src.offset(), src.pos
                    try:
                        value, end = _decode_at(src, record_cap)
                    except TooLong:
                        reject, stop = skip_oversize(start_line, start_off, key)
                        yield reject
                        if stop:
                            return
                        expecting_item = False
                        src.skip_ws()
                        if src.timed_out:
                            return
                        continue
                    except json.JSONDecodeError as exc:
                        if src.timed_out:       # the deadline cut the record, the JSON is not damaged
                            src.stopped = "the time limit ended the read"
                            yield "reject", info(start_line, start_off, None, key), "the last record is cut off where the read ended (the time limit)"
                            return
                        if exc.msg == "nested too deeply":
                            # a record the decoder cannot hold is valid JSON as far as can be told: it is skipped without parsing it (by counting
                            # its brackets), rejected, and the records after it are read
                            try:
                                skip_end = _skip_value(src, start_pos, record_cap)
                            except TooLong:             # over the cap as well: the scan that holds nothing skips it
                                reject, stop = skip_oversize(start_line, start_off, key)
                                yield reject
                                if stop:
                                    return
                                expecting_item = False
                                src.skip_ws()
                                if src.timed_out:
                                    return
                                continue
                            if skip_end is not None:
                                src.advance(skip_end)
                                yield "reject", info(start_line, start_off, skip_end - start_pos, key), "a record nested too deeply to be read (deeper than the JSON decoder holds)"
                                expecting_item = False
                                src.skip_ws()
                                continue
                        src.stopped = "the JSON stopped being valid at line %d (%s): the rest was not read" % (start_line, exc.msg)
                        yield "reject", info(start_line, start_off, None, key), "malformed JSON: %s" % exc.msg
                        return
                    src.advance(end)
                    yield "item", info(start_line, start_off, end - start_pos, key), value
                    expecting_item = False
                    src.skip_ws()
                    if src.timed_out:
                        return
                if key:
                    # the rest of the envelope object: its other keys, names only (a next-page token is a token)
                    src.skip_ws()
                    if src.pos < len(src.buf) and src.buf[src.pos] == ",":
                        src.advance(src.pos + 1)
                    try:
                        obj, end = _decode_at(src, record_cap, lead="{")
                    except (TooLong, json.JSONDecodeError):
                        src.stopped = "the time limit ended the read" if src.timed_out else "the object around the records does not end validly: its other keys were not read"
                        return
                    src.advance(end)
                    extra.update(str(k) for k in obj)
                continue
            # not an array, not an envelope: one pretty-printed document, or JSON Lines to the end of the file
            if first == "{" and one_line == "{":
                modes.append("document")
                start_line, start_off = src.line, src.offset()
                try:
                    value, end = _DEC.raw_decode(src.buf, src.pos)
                except (json.JSONDecodeError, RecursionError) as exc:
                    if src.timed_out:
                        src.stopped = "the time limit ended the read"
                        return
                    src.stopped = "the JSON stopped being valid near line %d (%s): the rest was not read" % (start_line, getattr(exc, "msg", "nested too deeply"))
                    yield "reject", info(start_line, start_off, None, None), "malformed JSON: %s" % getattr(exc, "msg", "nested too deeply")
                    return
                src.advance(end)
                yield from _expand(value, envelope_keys, info, start_line, start_off, src, extra)
                continue
            modes.append("lines")
            while True:
                src.skip_ws()
                if src.pos >= len(src.buf):
                    break
                i = src.buf.find("\n", src.pos)
                while i < 0 and not src.eof and len(src.buf) - src.pos <= record_cap:
                    src.fill()
                    i = src.buf.find("\n", src.pos)
                start_line, start_off = src.line, src.offset()
                if (i if i >= 0 else len(src.buf)) - src.pos > record_cap:
                    size = 0
                    while True:
                        i = src.buf.find("\n", src.pos)
                        if i >= 0:
                            size += i - src.pos
                            src.advance(i + 1)
                            break
                        size += len(src.buf) - src.pos
                        src.advance(len(src.buf))
                        if not src.fill():
                            break
                    yield "reject", info(start_line, start_off, size, None), "a line larger than max_record_bytes (%d)" % record_cap
                    continue
                text = src.buf[src.pos: i if i >= 0 else len(src.buf)]
                src.advance(i + 1 if i >= 0 else len(src.buf))
                stripped = text.strip()
                if not stripped:
                    continue
                try:
                    value = loads_strict(stripped)
                except (ValueError, RecursionError) as exc:
                    reason = "malformed JSON: %s" % getattr(exc, "msg", type(exc).__name__)
                    if i < 0 and src.eof and (src.error or src.capped or src.timed_out):
                        reason = "the last record is cut off where the read ended (%s)" % (src.error or "the expansion cap" if not src.timed_out else "the time limit")
                    yield "reject", info(start_line, start_off, len(text), None), reason
                    continue
                yield from _expand(value, envelope_keys, info, start_line, start_off, src, extra)
                if src.timed_out:
                    return
            break
    finally:
        finish()


def _expand(value, envelope_keys, info, line, offset, src, extra):
    """A parsed top-level value of a lines or document file: an envelope object yields its records, a list its elements."""
    if isinstance(value, dict):
        for key in envelope_keys:
            if isinstance(value.get(key), list):
                src.envelope = src.envelope or key
                extra.update(str(k) for k in value if k != key)
                for element in value[key]:
                    yield "item", info(line, offset, None, key), element
                return
        yield "item", info(line, offset, None, None), value
    elif isinstance(value, list):
        for element in value:
            yield "item", info(line, offset, None, None), element
    else:
        yield "reject", info(line, offset, None, None), "a JSON %s, not a record" % type(value).__name__


# ---- CSV and what both CSV and JSON rows need ------------------------------------------------------------------------


def csv_lines(src, cap=MAX_FIELD_BYTES):
    """The lines of a CSV file, newline kept, one at a time (a quoted field may span several). A line longer than `cap` (the call's
    max_record_bytes, 16 MiB unless it is raised, as for a JSON record) stops the file, named."""
    while True:
        i = src.buf.find("\n", src.pos)
        while i < 0 and not src.eof and len(src.buf) - src.pos <= cap:
            src.fill()
            i = src.buf.find("\n", src.pos)
        if i < 0 and src.pos >= len(src.buf):
            return
        end = i + 1 if i >= 0 else len(src.buf)
        if end - src.pos > cap:
            raise TooLong()
        line = src.buf[src.pos:end]
        src.advance(end)
        yield line


def csv_rows(src, delimiter, field_limit, record_cap=MAX_FIELD_BYTES):
    """Yield ("row", info, dict) / ("reject", info, reason) for a CSV file; a bad row is rejected and the next is read; a failure
    of the reader itself stops the file, says where, and keeps what was read. A header name that repeats keeps every column
    (the second is `name#2`)."""
    src.mode, src.stopped, src.extra_keys, src.envelope, src.header = "csv", None, [], None, None
    csv.field_size_limit(field_limit)
    line_cap = record_cap
    reader = csv.reader(csv_lines(src, line_cap), delimiter=delimiter)
    header, count = None, 0
    while True:
        before = reader.line_num
        try:
            row = next(reader)
        except StopIteration:
            break
        except TooLong:
            src.stopped = "a line longer than %d characters at line %d: the rest of the file was not read" % (line_cap, before + 1)
            yield "reject", {"record": count + 1, "line": before + 1, "offset": src.offset(), "chars": None, "envelope": None}, src.stopped
            return
        except csv.Error as exc:
            src.stopped = "the CSV reader stopped at line %d (%s): the rest of the file was not read" % (before + 1, exc)
            yield "reject", {"record": count + 1, "line": before + 1, "offset": src.offset(), "chars": None, "envelope": None}, "CSV error: %s" % exc
            return
        if not row:
            continue
        if header is None:
            seen = {}
            header = []
            for name in row:
                seen[name] = seen.get(name, 0) + 1
                header.append(name if seen[name] == 1 else "%s#%d" % (name, seen[name]))
            src.header = header
            if len(header) == 1 and re.search(r"[;\t|]", header[0]):
                src.stopped = "the header is one column that contains ';', a tab or '|': the file may use another delimiter (pass delimiter)"
                yield "reject", {"record": 0, "line": before + 1, "offset": 0, "chars": None, "envelope": None}, src.stopped
                return
            continue
        count += 1
        info = {"record": count, "line": before + 1, "offset": None, "chars": None, "envelope": None}
        if len(row) != len(header):
            yield "reject", info, "the row has %d fields and the header %d" % (len(row), len(header))
            continue
        yield "row", info, dict(zip(header, row))
        if src.timed_out:
            return
    if src.timed_out and not src.stopped:
        src.stopped = "the time limit ended the read"


def sniff(path):
    """'json' or 'csv', from the first characters of the file's own content (decompressed if it is gzip), never its name."""
    src = Source(path, MAX_EXPANDED_BYTES)
    try:
        src.ensure(4096)
        head = src.buf[src.pos:].lstrip()
    finally:
        src.close()
    return "json" if head[:1] in ("{", "[") else "csv"


def key_map(item):
    return {k.strip().lower(): k for k in item if isinstance(k, str)}


def first_of(item, keys, *names):
    for n in names:
        k = keys.get(n.lower())
        if k is not None and item.get(k) not in (None, ""):
            return item[k]
    return None


# ---- what the recipe adds to the text above ---------------------------------------------------------------------------------------------------

ENVELOPE_KEYS = ("entries", "items", "value", "records", "Records")
READ_NAMES = (".json", ".jsonl", ".ndjson", ".csv", ".log", ".gz")
KNOWN_CAPS = (5000, 50000)         # result sizes a log search is known to stop at; a count equal to one is a reason to doubt, never a finding
MAX_IDS = 500000                   # distinct record keys held to find duplicates; past it the duplicate check says it stopped
MAX_TENANTS = 20
MAX_FINDINGS = 1000
GAP_SECONDS = 86400                # a gap between two files' time ranges this long is named
PAGINATION = re.compile(r"(?i)next.?(page.?)?(token|link|uri|url)|continuation")
PAGE_NAME = re.compile(r"(?i)(?:page|part|p)[-_ .]?0*(\d{1,6})[-_ .]?of[-_ .]?0*(\d{1,6})")
STEPS = ("acquisition metadata", "walk", "files", "set", "write")
SECRET_BEARING = {
    "files.tsv": "file names and the tenant, project and account identifiers the records name",
    "findings.tsv": "file names and the identifiers of the records or tenants a finding names",
}


class Skips(list):
    def append(self, item):          # the walk reports what it did not take
        super().append(item)


def describe(exc):
    code = errno.errorcode.get(exc.errno, "") if getattr(exc, "errno", None) else ""
    return "%s%s: %s" % (type(exc).__name__, " " + code if code else "", getattr(exc, "strerror", None) or str(exc))


def shown_path(path):
    """A path as it is written in a receipt: a control character in a file name is not printed."""
    return re.sub(r"[\x00-\x1f\x7f]", "?", path) if isinstance(path, str) else path


DEADLINE_AT = [None]


def out_of_time():
    return DEADLINE_AT[0] is not None and time.monotonic() > DEADLINE_AT[0]


def key_text(value):
    return value if isinstance(value, str) else None


def classify(item):
    """(family, reader, tenant, raw time, record key) of one record by the fields it carries. A record no reader of this pack takes has no
    family (None). Nothing here reads a value other than the identifiers it returns."""
    pp = item.get("protoPayload")
    if isinstance(pp, dict) and (str(pp.get("@type", "")).endswith("google.cloud.audit.AuditLog") or "cloudaudit.googleapis.com" in str(item.get("logName") or "") or "methodName" in pp):
        tenant = None
        res = item.get("resource")
        if isinstance(res, dict) and isinstance(res.get("labels"), dict):
            tenant = key_text(res["labels"].get("project_id"))
        if tenant is None and isinstance(item.get("logName"), str):
            m = re.match(r"^(?:projects|organizations|folders|billingAccounts)/([^/]+)/logs/", item["logName"])
            tenant = m.group(1) if m else None
        return "gcp_audit", "cloud_normalise (gcp_audit)", tenant, item.get("timestamp"), key_text(item.get("insertId"))
    api = item.get("apiVersion")
    if (isinstance(api, str) and api.startswith("audit.k8s.io/") and item.get("kind") in (None, "Event")) or (item.get("auditID") and "stage" in item and ("verb" in item or "requestURI" in item)):
        audit = key_text(item.get("auditID"))
        return "kubernetes_audit", "cloud_normalise (kubernetes_audit)", None, item.get("stageTimestamp"), (audit + "/" + str(item.get("stage"))) if audit else None
    keys = {k.strip().lower(): k for k in item if isinstance(k, str)}
    if "activitydisplayname" in keys and "activitydatetime" in keys:
        return "entra_directory_audit", "cloud_normalise (entra_directory_audit)", None, item.get(keys["activitydatetime"]), key_text(item.get(keys.get("id", "id")))
    if "eventversion" in keys and "eventsource" in keys:
        return "cloudtrail", "cloudtrail_parse", key_text(item.get(keys.get("recipientaccountid", ""))), item.get(keys.get("eventtime", "")), key_text(item.get(keys.get("eventid", "")))
    if "operation" in keys and ("recordtype" in keys or "auditdata" in keys or "creationdate" in keys or "creationtime" in keys):
        return "m365_unified_audit_log", "ual_parse", key_text(item.get(keys.get("organizationid", ""))), item.get(keys.get("creationdate", keys.get("creationtime", ""))), key_text(item.get(keys.get("id", keys.get("identity", ""))))
    if "userprincipalname" in keys and ("appdisplayname" in keys or "conditionalaccessstatus" in keys or "createddatetime" in keys):
        return "entra_signin", "signin_analyse", None, item.get(keys.get("createddatetime", "")), key_text(item.get(keys.get("id", "")))
    ident = item.get("id")
    if isinstance(ident, dict) and "applicationName" in ident and isinstance(item.get("events"), list):
        app = ident.get("applicationName")
        return ("workspace_login" if app == "login" else "workspace_activity:" + str(app)), ("signin_analyse" if app == "login" else None), None, ident.get("time"), key_text(ident.get("uniqueQualifier"))
    return None, None, None, None, None


class Receipt:
    """coverage.json, index.tsv, files.tsv and findings.tsv, rewritten whole (under a temporary name, then moved into place) after every step."""

    def __init__(self, out_dir, target_name):
        self.out_dir = out_dir
        self.files, self.findings = [], []
        self.data = {
            "recipe": RECIPE, "target": target_name, "status": "partial", "finished": False, "status_basis": "the recipe has not finished",
            "covered": "the files of the export set: format, provider, tenant or project or account, record counts, which of them a reader of this pack takes, "
                       "the time range they carry, next-page markers, result-cap suspects, duplicates, gaps between ranges, missing named pages, and the interval requested against the interval returned",
            "not_covered": "what the provider logged, how long it kept it, audit configuration, delivery delay and anything that was never exported; "
                           "record values are not read out, and a record is classified by the fields it carries and is not parsed",
            "export_completeness": {"state": "not_assessed_yet", "basis": "the recipe has not finished"},
            "logging_completeness": {"state": "not_assessed", "basis": "an export says what was exported; retention, licence, audit configuration and delivery delay are not in it, and no finding here is a statement about them"},
            "steps": [{"step": s, "status": "not_attempted", "reason": "planned"} for s in STEPS], "inputs": [], "errors": [], "deadline_seconds": DEADLINE,
            "secret_bearing": dict(SECRET_BEARING), "acquisition": {"state": "not read"}, "set": {}, "findings_total": 0,
        }

    def write(self):
        self.data["inputs"] = [{k: v for k, v in f.items() if k in ("path", "status", "why", "format", "family", "records", "unsupported_records")} for f in self.files]
        self.data["findings_total"] = len(self.findings)
        parts = (("coverage.json", json.dumps(self.data, indent=2, default=str) + "\n"), ("index.tsv", self._index()), ("files.tsv", self._files()), ("findings.tsv", self._findings()))
        for name, content in parts:
            final = os.path.join(self.out_dir, name)
            tmp = final + ".tmp"
            with open(os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600), "w", encoding="utf-8", newline="\n") as fh:
                fh.write(content)
                fh.flush()
                os.fsync(fh.fileno())
            os.replace(tmp, final)

    @staticmethod
    def cell(value):
        return "" if value is None else re.sub(r"[\t\r\n]", " ", str(value))

    def _index(self):
        rows = [("coverage.json", "the receipt: status per step and per input, export completeness apart from logging completeness", ""),
                ("files.tsv", "one row per input file", len(self.files)), ("findings.tsv", "what the set names as missing, doubtful or inconsistent", len(self.findings))]
        return "path\tdescription\trows\n" + "\n".join("%s\t%s\t%s" % r for r in rows) + "\n"

    def _files(self):
        cols = ("path", "status", "format", "compressed", "families", "tenants", "records", "parsed", "rejected", "unsupported", "first_utc", "last_utc",
                "next_page_markers", "duplicates_in_file", "duplicates_across_files", "times_without_a_zone", "why")
        out = ["\t".join(cols)]
        for f in self.files:
            out.append("\t".join(self.cell(x) for x in (f["path"], f["status"], f.get("format"), f.get("compressed"), ",".join(sorted(f.get("families", {}))), ",".join(f.get("tenants", [])),
                                                         f.get("records"), f.get("parsed"), f.get("rejected"), f.get("unsupported_records"), f.get("first_utc"), f.get("last_utc"),
                                                         ",".join(f.get("pagination_markers", [])), f.get("duplicates_in_file"), f.get("duplicates_across_files"),
                                                         f.get("times_without_a_zone"), f.get("why"))))
        return "\n".join(out) + "\n"

    def _findings(self):
        out = ["kind\tfile\tdetail"]
        for k, f, d in self.findings:
            out.append("%s\t%s\t%s" % (self.cell(k), self.cell(f), self.cell(d)))
        return "\n".join(out) + "\n"

    def find(self, kind, path, detail):
        if len(self.findings) < MAX_FINDINGS:
            self.findings.append((kind, path, detail))
        else:
            self.data["findings_not_listed"] = self.data.get("findings_not_listed", 0) + 1


def target_of(arg):
    if os.path.isfile(arg):
        with open(arg, "rb") as fh:
            text = fh.read(1 << 20).decode("utf-8")
    else:
        text = arg
    target = json.loads(text)
    paths = target.get("paths") if isinstance(target, dict) else None
    if not isinstance(paths, list) or not paths or not all(isinstance(p, str) for p in paths):
        raise ValueError("the target names no path")
    return target, paths


MARKER = re.compile(r'"(?:protoPayload|auditID|activityDisplayName|eventVersion|AuditData|userPrincipalName|applicationName|logName)"\s*:')


def head_of(path, size=65536):
    """The first bytes of a regular file, decompressed when gzip; None when it cannot be read as one. A FIFO is never opened."""
    flags = os.O_RDONLY | getattr(os, "O_NONBLOCK", 0) | getattr(os, "O_NOFOLLOW", 0)
    fd = os.open(path, flags)
    try:
        if not stat.S_ISREG(os.fstat(fd).st_mode):
            raise OSError(errno.EINVAL, "not a regular file")
        with os.fdopen(os.dup(fd), "rb") as fh:
            raw = fh.read(size)
    finally:
        os.close(fd)
    if raw[:2] == b"\x1f\x8b":
        d = zlib.decompressobj(31)
        try:
            raw = d.decompress(raw, size)
        except zlib.error:
            return raw
    return raw


def detect(paths):
    """(True | False | "unknown", why). A directory is asked about by looking at the heads of up to 50 of its files, in name order."""
    seen = 0
    for p in paths:
        try:
            if os.path.isdir(p):
                names = sorted(os.listdir(p))[:200]
                files = [os.path.join(p, n) for n in names]
            else:
                files = [p]
        except OSError as exc:
            return "unknown", "unreadable, so it cannot be told whether it is a cloud log export: %s" % (exc.strerror or exc)
        for f in files:
            if seen >= 50:
                break
            try:
                if os.path.islink(f) or not os.path.isfile(f) and os.path.exists(f) and not os.path.isdir(f):
                    if not os.path.isdir(p):
                        return "unknown", "not a regular file, so it cannot be read"
                    continue
                if os.path.isdir(f):
                    continue
                head = head_of(f).decode("utf-8", "replace")
            except OSError as exc:
                if not os.path.isdir(p):
                    return "unknown", "unreadable, so it cannot be told whether it is a cloud log export: %s" % (exc.strerror or exc)
                continue
            seen += 1
            if head.lstrip()[:1] in ("{", "[") and MARKER.search(head):
                return True, "the file carries the fields of a cloud log record (%s)" % os.path.basename(f)
    return False, "no file carries the fields of a cloud log record that a reader of this pack takes"


def iso_ns(raw):
    st = parse_stamp(raw, None, False)
    return st["ns"], st["status"]


def read_acquisition(path, receipt):
    info = {"state": "read", "file": shown_path(path)}
    try:
        with open(path, "rb") as fh:
            blob = fh.read((1 << 20) + 1)
        if len(blob) > (1 << 20):
            raise ValueError("larger than 1 MiB")
        meta = json.loads(blob.decode("utf-8"))
        if not isinstance(meta, dict):
            raise ValueError("not a JSON object")
    except (OSError, ValueError, UnicodeDecodeError, RecursionError) as exc:
        return {"state": "unreadable", "file": shown_path(path), "why": str(exc)[:200]}, None
    interval = meta.get("interval_requested")
    req = {}
    if isinstance(interval, dict):
        for k in ("start", "end"):
            ns, status = iso_ns(interval.get(k))
            req[k] = {"raw": interval.get(k), "ns": ns, "status": status}
    info["recorded"] = {k: (v if isinstance(v, (str, int, float, bool)) else "(a %s)" % type(v).__name__) for k, v in meta.items() if k != "interval_requested"}
    info["interval_requested"] = {k: {"raw": v["raw"], "status": v["status"]} for k, v in req.items()} if req else None
    return info, {"interval": req or None, "result_size": meta.get("result_size") if isinstance(meta.get("result_size"), int) and not isinstance(meta.get("result_size"), bool) else None,
                  "expected_pages": meta.get("expected_pages") if isinstance(meta.get("expected_pages"), int) and not isinstance(meta.get("expected_pages"), bool) else None}


def inventory_file(path, shown, seen_ids, acq):
    """One file: its counts, ranges and markers. Nothing a record holds is kept except the identifiers named in the module's text."""
    row = {"path": shown, "status": "complete", "format": None, "compressed": False, "families": {}, "readers": {}, "tenants": [], "records": 0, "parsed": 0, "rejected": 0,
           "unsupported_records": 0, "first_utc": None, "last_utc": None, "pagination_markers": [], "duplicates_in_file": 0, "duplicates_across_files": 0,
           "times_without_a_zone": 0, "times_unparseable": 0, "problems": []}
    first = last = None
    src = None
    local = set()
    try:
        seen = sniff(path)
        src = Source(path, MAX_EXPANDED_BYTES)
        row["format"] = "csv" if seen == "csv" else None
        units = read_units(src, ENVELOPE_KEYS, MAX_RECORD_BYTES, MAX_DOCUMENT_BYTES) if seen == "json" else csv_rows(src, ",", MAX_RECORD_BYTES, MAX_RECORD_BYTES)
        for kind, info, item in units:
            if out_of_time():
                src.timed_out = True
                break
            row["records"] += 1
            if kind == "reject" or not isinstance(item, dict):
                row["rejected"] += 1
                continue
            family, reader, tenant, raw_time, rkey = classify(item)
            if family is None:
                row["unsupported_records"] += 1
                row["families"]["(no reader recognises it)"] = row["families"].get("(no reader recognises it)", 0) + 1
                continue
            row["families"][family] = row["families"].get(family, 0) + 1
            if reader is None:
                row["unsupported_records"] += 1
            else:
                row["parsed"] += 1
                row["readers"][reader] = row["readers"].get(reader, 0) + 1
            if tenant is not None and tenant not in row["tenants"] and len(row["tenants"]) < MAX_TENANTS:
                row["tenants"].append(tenant)
            if raw_time is not None:
                ns, status = iso_ns(raw_time)
                if ns is not None:
                    first = ns if first is None else min(first, ns)
                    last = ns if last is None else max(last, ns)
                elif status == "no_zone":
                    row["times_without_a_zone"] += 1
                else:
                    row["times_unparseable"] += 1
            if rkey is not None:
                h = int.from_bytes(hashlib.blake2b((family + "\x00" + rkey).encode("utf-8", "backslashreplace"), digest_size=8).digest(), "big")
                if h in local:
                    row["duplicates_in_file"] += 1
                elif h in seen_ids:
                    row["duplicates_across_files"] += 1
                elif len(seen_ids) < MAX_IDS:
                    seen_ids.add(h)
                    local.add(h)
                else:
                    seen_ids.add(None)      # a marker that the check stopped
        if seen == "json":
            row["format"] = {"lines": "jsonl", "array": "json (array)", "document": "json (document)", "object": "json (object)", "empty": None}.get(getattr(src, "mode", None), "json")
            row["envelope"] = getattr(src, "envelope", None)
        row["compressed"] = src.compressed
        row["bytes_read"] = src.bytes_read
        row["pagination_markers"] = sorted(k for k in getattr(src, "extra_keys", []) if PAGINATION.search(str(k)))[:20]
        if src.archive:
            row["status"], row["why"] = "unsupported", "%s: extract it first; it was not opened" % src.archive
        elif src.error:
            row["status"], row["why"] = "partial", src.problem_lines()[0]
            row["problems"] = src.problem_lines()
        if src.capped:
            row["status"] = "partial"
            row["problems"].append("the expansion reached the cap of %d bytes: the rest of the file was not counted" % MAX_EXPANDED_BYTES)
        if getattr(src, "stopped", None):
            row["status"] = "partial"
            row["problems"].append(src.stopped)
        if src.timed_out:
            row["status"] = "partial"
            row["why"] = "the recipe's deadline ended the read of this file; its counts are those at that moment"
        if src.replaced:
            row["problems"].append("%d byte(s) were not valid UTF-8 and were replaced" % src.replaced)
        if row["rejected"]:
            row["status"] = "partial"
            row["problems"].append("%d record(s) could not be read as records (malformed JSON, a record over %d bytes, a row of the wrong width)" % (row["rejected"], MAX_RECORD_BYTES))
        if row["status"] == "complete" and row["records"] == 0 and not src.archive:
            row["status"], row["why"] = "empty", "the file holds no records"
        elif row["status"] == "complete" and row["parsed"] == 0 and row["records"] > 0:
            row["status"], row["why"] = "unsupported", "no record is of a shape a reader of this pack takes"
    except OSError as exc:
        row["status"], row["why"] = "failed", describe(exc)
    except (ValueError, RecursionError) as exc:
        row["status"], row["why"] = "failed", "%s: %s" % (type(exc).__name__, str(exc)[:200])
    finally:
        if src is not None:
            src.close()
    if first is not None:
        row["first_ns"], row["last_ns"] = first, last
        row["first_utc"], row["last_utc"] = ns_to_utc(first), ns_to_utc(last)
    if row["problems"] and row["status"] == "complete":
        row["status"] = "partial"
    return row


def main():
    mode = sys.argv[1] if len(sys.argv) > 1 else ""
    state = {"receipt": None, "stage": "checking its arguments"}

    def early_word(signum):
        print(json.dumps({"ok": False, "status": "partial", "interrupted_by_signal": signum, "stage": state["stage"],
                          "status_basis": "the recipe was stopped by signal %d while it was %s; no input had been read" % (signum, state["stage"])}), flush=True)

    def on_signal(signum, _frame):
        for other in (signal.SIGTERM, signal.SIGINT, signal.SIGHUP):
            signal.signal(other, signal.SIG_IGN)       # the first signal counts
        rc = state["receipt"]
        if rc is None:
            early_word(signum)
            answer_a_stop(signum)
            os._exit(128 + signum)
        try:
            for s in rc.data["steps"]:
                if s["status"] == "running":
                    s.update(status="interrupted", reason="the recipe was stopped by signal %d while this step ran" % signum)
            rc.data["errors"].append("the recipe was stopped by signal %d before it finished" % signum)
            rc.data["status_basis"] = "the recipe was stopped by signal %d: the inputs read so far are in the receipt, the one being read is partial" % signum
            for f in rc.files:
                if f["status"] == "reading":
                    f["status"], f["why"] = "partial", "the recipe was stopped by signal %d while this file was read" % signum
            rc.write()
            print(json.dumps({"ok": False, "status": "partial", "status_basis": rc.data["status_basis"], "interrupted_by_signal": signum}), flush=True)
        except Exception:  # noqa: BLE001 - a last word is best effort
            pass
        answer_a_stop(signum)
        os._exit(128 + signum)

    for signum in (signal.SIGTERM, signal.SIGINT, signal.SIGHUP):
        signal.signal(signum, on_signal)
    if len(sys.argv) < 4 or sys.argv[2] != "--target" or mode not in ("detect", "run"):
        print(json.dumps({"ok": False, "applies": "unknown", "error": "usage: run.py detect --target T | run --target T --out DIR"}))
        return 2
    try:
        target, paths = target_of(sys.argv[3])
    except (OSError, ValueError, UnicodeDecodeError, RecursionError) as exc:
        print(json.dumps({"ok": False, "applies": "unknown", "error": "the target could not be read: %s" % str(exc)[:200]}))
        return 2
    if mode == "detect":
        applies, why = detect(paths)
        print(json.dumps({"applies": applies, "why": why}))
        return 2 if applies == "unknown" else 0 if applies else 1
    if "--out" not in sys.argv[4:] or sys.argv.index("--out") + 1 >= len(sys.argv):
        print(json.dumps({"ok": False, "error": "run needs --out DIR"}))
        return 2
    out_dir = sys.argv[sys.argv.index("--out") + 1]
    state["stage"] = "preparing the output directory"
    os.umask(0o077)
    try:
        os.makedirs(out_dir, mode=0o700, exist_ok=True)
        os.chmod(out_dir, 0o700)
        if os.path.lexists(os.path.join(out_dir, "coverage.json")):
            print(json.dumps({"ok": False, "status": "failed", "error": "the output directory already holds a receipt (coverage.json) of an earlier run, which is never overwritten: give a new --out", "out": out_dir}))
            return 2
    except OSError as exc:
        print(json.dumps({"ok": False, "error": "the output directory could not be created (%s)" % describe(exc), "out": out_dir}))
        return 2
    started = time.monotonic()
    DEADLINE_AT[0] = started + DEADLINE
    receipt = Receipt(out_dir, target.get("name") or shown_path(paths[0]))
    state["receipt"] = receipt
    data = receipt.data

    def step(name):
        return next(s for s in data["steps"] if s["step"] == name)

    def begin(name):
        s = step(name)
        s.pop("reason", None)
        s["status"] = "running"
        receipt.write()

    def end(name, status="ok", reason=None):
        s = step(name)
        s["status"] = status
        if reason:
            s["reason"] = reason
        receipt.write()

    receipt.write()
    # step 1: the acquisition metadata and the files
    begin("acquisition metadata")
    skipped = Skips()
    targets, acq_files, seen_real = [], [], set()
    for p in paths:
        try:
            if os.path.isdir(p):
                found = walk_inputs(p, lambda n: n.lower().endswith(READ_NAMES), skipped)
            elif os.path.isfile(p):
                found = [p]
            else:
                skipped.append({"path": shown_path(p), "reason": "not a regular file or a directory: it is not opened"})
                found = []
        except OSError as exc:
            skipped.append({"path": shown_path(p), "reason": describe(exc)})
            found = []
        for f in found:
            real = os.path.realpath(f)
            if real in seen_real:
                continue
            seen_real.add(real)
            name = os.path.basename(f).lower()
            (acq_files if name == "acquisition.json" or name.endswith(".acquisition.json") else targets).append(f)
    acq = None
    if acq_files:
        data["acquisition"], acq = read_acquisition(acq_files[0], receipt)
        if len(acq_files) > 1:
            data["acquisition"]["note"] = "%d acquisition files were supplied; the first (in the order given) was read" % len(acq_files)
    else:
        data["acquisition"] = {"state": "not supplied", "why": "no acquisition.json beside the export: who exported, the query, the permission and the interval requested are not recorded, and none is assumed"}
    end("acquisition metadata")

    begin("walk")
    data["skipped"] = {"total": len(skipped), "first": skipped[:50]}
    for s in skipped:
        receipt.find("input_not_read", s["path"], s["reason"])
    data["inputs_found"] = len(targets)
    end("walk", "ok" if not out_of_time() else "partial", "the deadline ended the walk" if out_of_time() else None)

    begin("files")
    seen_ids = set()
    for path in targets:
        shown = shown_path(path)
        if out_of_time():
            receipt.files.append({"path": shown, "status": "not_attempted", "why": "the recipe's deadline was used up before this file"})
            continue
        placeholder = {"path": shown, "status": "reading"}
        receipt.files.append(placeholder)
        receipt.write()
        row = inventory_file(path, shown, seen_ids, acq)
        receipt.files[-1] = row
        receipt.write()
    ids_full = None in seen_ids
    end("files", "ok" if not out_of_time() else "partial", "the deadline ended the reads; the files after it are not_attempted" if out_of_time() else None)

    begin("set")
    files = receipt.files
    total = sum(f.get("records", 0) for f in files)
    ranges = sorted((f["first_ns"], f["last_ns"], f["path"]) for f in files if f.get("first_ns") is not None)
    first_all = min((r[0] for r in ranges), default=None)
    last_all = max((r[1] for r in ranges), default=None)
    data["set"] = {"files": len(files), "records": total, "parsed": sum(f.get("parsed", 0) for f in files), "unsupported_records": sum(f.get("unsupported_records", 0) for f in files),
                   "rejected": sum(f.get("rejected", 0) for f in files), "first_utc": ns_to_utc(first_all), "last_utc": ns_to_utc(last_all),
                   "duplicates_in_files": sum(f.get("duplicates_in_file", 0) for f in files), "duplicates_across_files": sum(f.get("duplicates_across_files", 0) for f in files),
                   "duplicate_check": "complete" if not ids_full else "stopped after %d distinct record keys: later duplicates are not counted" % MAX_IDS}
    doubts = 0
    for f in files:
        if f.get("pagination_markers"):
            doubts += 1
            receipt.find("next_page_marker", f["path"], "names a next page (%s): the page it points to is not in this file" % ", ".join(f["pagination_markers"]))
        caps = list(KNOWN_CAPS) + ([acq["result_size"]] if acq and acq.get("result_size") and acq["result_size"] not in KNOWN_CAPS else [])
        if f.get("records") in caps and f.get("records"):
            doubts += 1
            receipt.find("result_cap_suspect", f["path"], "holds exactly %d records, a result size a log search stops at: the result may have been cut (a reason to doubt, not a finding)" % f["records"])
        if f.get("duplicates_in_file") or f.get("duplicates_across_files"):
            receipt.find("duplicates", f["path"], "%d record(s) repeat an earlier one in this file and %d repeat one in an earlier file (kept, not removed)" % (f.get("duplicates_in_file", 0), f.get("duplicates_across_files", 0)))
        if f.get("times_without_a_zone"):
            receipt.find("times_without_a_zone", f["path"], "%d record(s) carry a time with no zone: they are left out of the range" % f["times_without_a_zone"])
        if f["status"] == "empty":
            doubts += 1
            receipt.find("empty_export", f["path"], "holds no records: an empty export is not an empty log (the query, the permission and the interval decide which)")
        if f["status"] in ("partial", "unsupported", "failed", "not_attempted"):
            doubts += 1
            receipt.find("input_" + f["status"], f["path"], f.get("why") or "; ".join(f.get("problems", [])[:2]))
        if f.get("unsupported_records") and f["status"] != "unsupported":
            receipt.find("records_no_reader_takes", f["path"], "%d of %d record(s) are of a shape no reader of this pack takes" % (f["unsupported_records"], f.get("records", 0)))
    # gaps between the files' ranges (a gap is a place to ask, not a finding about the provider)
    reach = None
    for lo, hi, name in ranges:
        if reach is not None and lo - reach[0] > GAP_SECONDS * 1000000000:
            doubts += 1
            receipt.find("gap_between_files", name, "starts %s, %d s after %s ended: no file covers the time between" % (ns_to_utc(lo), (lo - reach[0]) // 1000000000, reach[1]))
        if reach is None or hi > reach[0]:
            reach = (hi, name)
    # named pages: page-K-of-N
    pages = {}
    for f in files:
        m = PAGE_NAME.search(os.path.basename(f["path"]))
        if m:
            pages.setdefault(int(m.group(2)), set()).add(int(m.group(1)))
    expected = acq.get("expected_pages") if acq else None
    for n, have in sorted(pages.items()):
        missing = sorted(set(range(1, n + 1)) - have)
        if missing:
            doubts += 1
            receipt.find("page_missing", "(set)", "files are named page K of %d; page(s) %s of %d are not in the set" % (n, ", ".join(map(str, missing[:20])), n))
    if expected is not None and not pages:
        have = len([f for f in files if f.get("records")])
        if have < expected:
            doubts += 1
            receipt.find("page_missing", "(set)", "the acquisition metadata expects %d page(s) and %d file(s) hold records" % (expected, have))
    # the interval requested against the interval returned
    interval = acq.get("interval") if acq else None
    comparison = {"state": "no interval was requested in the acquisition metadata, so none is compared"}
    if interval and interval.get("start") and interval.get("end"):
        s, e = interval["start"], interval["end"]
        if s["ns"] is None or e["ns"] is None:
            comparison = {"state": "cannot_compare", "why": "the requested interval is not a time with a zone (start: %s, end: %s)" % (s["status"], e["status"])}
        elif first_all is None:
            comparison = {"state": "nothing_returned", "why": "no record with a usable time was read, so the returned interval is empty"}
            doubts += 1
        else:
            lead = (first_all - s["ns"]) // 1000000000
            tail = (e["ns"] - last_all) // 1000000000
            outside = first_all < s["ns"] or last_all > e["ns"]
            comparison = {"state": "returned_outside_requested" if outside else "returned_inside_requested", "requested": {"start": s["raw"], "end": e["raw"]},
                          "returned": {"first_utc": ns_to_utc(first_all), "last_utc": ns_to_utc(last_all)},
                          "first_record_after_requested_start_seconds": lead, "last_record_before_requested_end_seconds": tail,
                          "meaning": "the records span this part of the requested interval; it does not show that every event in it was exported, and an end earlier than the interval's end may be a quiet period or a cut"}
            if outside:
                doubts += 1
                receipt.find("interval_mismatch", "(set)", "records fall outside the requested interval (%s to %s)" % (s["raw"], e["raw"]))
            elif lead > GAP_SECONDS or tail > GAP_SECONDS:
                doubts += 1
                receipt.find("interval_not_reached", "(set)", "the first record is %d s after the requested start and the last is %d s before the requested end" % (lead, tail))
    elif interval is not None and (not interval.get("start") or not interval.get("end")):
        comparison = {"state": "cannot_compare", "why": "the acquisition metadata names no complete interval (start and end)"}
    data["set"]["interval_requested_against_returned"] = comparison
    unread = [f for f in files if f["status"] in ("not_attempted", "failed")]
    data["export_completeness"] = {
        "state": "doubts_found" if doubts else "no_reason_to_doubt_found" if files and not unread and not out_of_time() else "cannot_tell",
        "doubts": doubts,
        "basis": ("%d reason(s) to doubt that the supplied export is whole (see findings.tsv)" % doubts) if doubts else
                 "no next-page marker, result-cap match, gap, missing named page or interval mismatch was found in the supplied files; that does not show that the export is whole",
    }
    end("set")

    begin("write")
    unfinished = [s["step"] for s in data["steps"] if s["status"] in ("not_attempted", "running", "interrupted")]
    unfinished = [u for u in unfinished if u != "write"]
    problem_inputs = [f for f in files if f["status"] not in ("complete",)]
    complete = not unfinished and not problem_inputs and not skipped and not out_of_time() and bool(files)
    data.update(status="complete" if complete else "partial", finished=True, elapsed_seconds=round(time.monotonic() - started, 3))
    reasons = []
    if not files:
        reasons.append("no input file was found")
    if problem_inputs:
        reasons.append("%d input(s) are not complete (%s)" % (len(problem_inputs), ", ".join(sorted({f["status"] for f in problem_inputs}))))
    if skipped:
        reasons.append("%d entr%s of the target were not taken (links, special files, archives, names the recipe does not read)" % (len(skipped), "y" if len(skipped) == 1 else "ies"))
    if unfinished or out_of_time():
        reasons.append("the recipe's deadline or a failed step ended it before every step finished")
    data["status_basis"] = ("every input was read to its end and the set was compared; this says what the supplied export holds, and nothing about the provider's logging" if complete
                            else "; ".join(reasons) or "the recipe did not finish every step")
    end("write")
    print(json.dumps({"ok": complete or bool(files), "status": data["status"], "status_basis": data["status_basis"], "export_completeness": data["export_completeness"]["state"]}))
    return 0 if files else 2


if __name__ == "__main__":
    exit_code = 0
    try:
        sys.exit(main())
    except SystemExit as stop:
        exit_code = _code(stop)
    _leave(exit_code)
