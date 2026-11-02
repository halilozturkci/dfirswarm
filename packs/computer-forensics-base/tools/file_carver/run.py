#!/usr/bin/env python3
"""Cut one candidate file out of a raw dump at a known offset, and say how its end was decided.

You give a path, an offset and a signature type. The result is a candidate
fragment: the bytes from that offset to the end the format's own structure
gives, with a SHA-256, written to a new file when you ask for one. It is a
candidate, not a recovered file: nothing here shows the bytes are the whole of
the original, unfragmented or unaltered, and the end is only as good as the
check that found it. Every result says which:

    boundary: validated   a structure walk reached the format's own end: PNG
                          chunks to IEND with every CRC, JPEG segments to EOI,
                          GIF blocks to the trailer, ZIP's end-of-central-directory
                          record whose offsets agree with where it stands, a
                          registry hive's hive-bin chain adding up to the size its
                          base block states, a SQLite header whose page count is
                          valid, a PDF whose last startxref points at an xref
                          table or object
    boundary: heuristic   the end rests on a header field or marker that was not
                          cross-checked (a PE's section table, a ZIP or SQLite or
                          hive header that did not agree with itself). Read the
                          checks and notes; overlay_uncertain says bytes follow a PE

The scan reads the file at `path` as it is: an E01 or another container is its
container bytes here, not the disk inside, and an offset taken from a decoded
image does not belong to the container. The file is streamed, never held whole,
and the output file is created new (an existing one is an error, not
overwritten).

The walk has a clock of its own (25 seconds, inside the manifest's 30): every read of the source looks at it, so a structure that
makes the walk long (a window of a gigabyte, a file of a million tiny segments) is refused with how far the walk got
(`reached_bytes`), not killed with nothing said. A bigger `max_size` is a longer walk.
"""
import hashlib
import json
import os
import re
import struct
import sys
import tempfile
import time
import zlib
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


def _drop_temporaries():
    """The hidden temporaries go before the tool ends, as they do when a stop signal ends it: the pages being written (_tmp) and the TEMPS list."""
    for page in list(globals().get("PAGES", ())):
        try:
            tmp = getattr(page, "_tmp", None)
            if tmp is not None:
                os.unlink(tmp)
        except Exception:   # noqa: BLE001 - best effort, and every one is tried
            pass
    for name in list(globals().get("TEMPS", ())):
        try:
            os.unlink(name)
        except Exception:   # noqa: BLE001
            pass


def _unexpected_tool(kind, value, _tb):
    """Last resort: an error nobody foresaw is an answer too. The hidden temporaries are removed, then one JSON document with the class and, for a
    file-system error, its reason (a message can quote a name from the evidence), and exit 1; what was written before it is not claimed. A stop signal
    that arrives while this runs is held with the answer's write and is answered by this document and exit 1, not by 128 + the signal."""
    try:
        _drop_temporaries()
        reason = getattr(value, "strerror", None) if issubclass(kind, OSError) else None
        said = ("a path or file could not be used: %s" % (reason or kind.__name__)) if issubclass(kind, (OSError, ValueError)) else "internal error: %s" % kind.__name__
        print_answer({"tool": globals().get("TOOL"), "status": "failed", "error": said,
                      "status_basis": "the tool stopped on an error it did not foresee (%s); what it had written before is not claimed" % kind.__name__})
    except BaseException:       # noqa: BLE001 - nothing may stop the exit
        pass
    os._exit(1)


sys.excepthook = _unexpected_tool

PAGES = []                 # objects with a hidden temporary file (_tmp) that a stop removes


class _Held:
    _tmp = None


HELD = _Held()             # the hidden file of the carved copy being written
PAGES.append(HELD)

TOOL = {"name": "file_carver", "version": 11}
CHUNK = 1 << 20
DEFAULT_MAX = 100_000_000
PDF_EOF_LIMIT = 1000
SECONDS = min(25.0, float(os.environ.get("FILE_CARVER_SECONDS") or 25))   # the walk's own clock, inside the manifest's 30 (a shorter one can be asked for)
STARTED = time.monotonic()


class Refuse(Exception):
    """The carve cannot give a candidate; the message says why."""

    def __init__(self, message, **extra):
        super().__init__(message)
        self.extra = extra


def fail(message, **extra):
    print_answer({"ok": False, "status": "failed", "status_basis": "the tool refused or stopped with an error (see error)", "error": message, "tool": TOOL, **extra})
    raise SystemExit(1)


def resolve_output(out):
    """Where `out` really lands, refusing anything outside the run directory.

    A string check is not enough: `work/../inputs/x` and an absolute path
    both name a file the tool must not write, and neither starts with
    "inputs/". Resolving first and comparing directories is what actually
    holds, and the read-only inputs are the one place extracted bytes must
    never appear -- a later integrity check would report the evidence as
    modified.
    """
    if not isinstance(out, str) or not out or "\x00" in out:
        fail("output is a path under the run directory")
    root = Path.cwd().resolve()
    try:
        dest = (root / out).resolve() if not Path(out).is_absolute() else Path(out).resolve()
    except (OSError, RuntimeError, ValueError) as exc:     # a symlink loop, a name too long, a lone surrogate
        fail("output cannot be resolved: %s" % (exc.__class__.__name__ if not getattr(exc, "strerror", None) else exc.strerror), output=str(out))
    if dest == root or root not in dest.parents:
        fail("output must stay inside the run directory, not be the run directory itself", output=str(out))
    inputs = root / "inputs"
    if dest == inputs or inputs in dest.parents:
        fail("output cannot be under inputs/", output=str(out))
    job, bound = os.environ.get("JOB_ID"), os.environ.get("OUT")
    if job and bound:
        bound = Path(bound).resolve()
        if bound not in dest.parents:
            fail("in a job an output is a path under $OUT, the one place a job writes (the rest of the run is read-only there)",
                 output=str(out), out=str(bound), hint="give {OUT}/<name>, or work/extracted/<your id>/<name>, which the harness maps there")
    return dest


MAGICS = {
    'PE': b'MZ',
    'ZIP': b'PK\x03\x04',
    'PDF': b'%PDF-',
    'SQLite': b'SQLite format 3\x00',
    'regf': b'regf',
    'PNG': b'\x89PNG\r\n\x1a\n',
    'JPEG': b'\xff\xd8\xff',
    'GIF': (b'GIF87a', b'GIF89a'),
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


class Src:
    """The source file, read at absolute offsets, a block at a time."""

    def __init__(self, path):
        self.fh = open_regular(path)
        self.size = os.fstat(self.fh.fileno()).st_size
        self.origin = 0                # where the candidate starts, for the distance a refusal names
        self.reached = 0               # the furthest byte any read has reached

    def read(self, offset, n):
        if offset < 0 or n < 0 or offset > self.size:
            return b""
        self.reached = max(self.reached, offset + n)
        if time.monotonic() - STARTED > SECONDS:
            raise Refuse("the %g-second time budget was used before the candidate's end was found: the walk had read as far as %d bytes from the offset "
                         "(a larger max_size is a longer walk; cut a smaller window, or read the structure in place)" % (SECONDS, min(self.reached, self.size) - self.origin),
                         reached_bytes=min(self.reached, self.size) - self.origin, time_budget_seconds=SECONDS)
        self.fh.seek(offset)
        return self.fh.read(n)

    def find_all(self, marker, start, end):
        """Offsets of `marker` in [start, end), found a block at a time with a carry between blocks."""
        keep = len(marker) - 1
        pos, tail = start, b""
        while pos < end:
            data = self.read(pos, min(CHUNK, end - pos))
            if not data:
                return
            buf = tail + data
            base = pos - len(tail)
            i = buf.find(marker)
            while i >= 0:
                at = base + i
                if at >= start and at + len(marker) <= end:
                    yield at
                i = buf.find(marker, i + 1)
            tail = buf[-keep:] if keep else b""
            pos += len(data)

    def close(self):
        self.fh.close()


# --- one function per type: (size, boundary, basis, checks, notes) -------------------

def carve_png(src, off, limit):
    pos = off + 8
    checks, n = [], 0
    while True:
        head = src.read(pos, 8)
        if len(head) < 8:
            raise Refuse("the PNG's chunks run off the end of the source at byte %d" % (pos - off))
        length, kind = struct.unpack(">I4s", head)
        end = pos + 12 + length
        if end > limit:
            raise Refuse("complete file is larger than max_size: a PNG chunk (%r, %d bytes) runs past max_size or the source; the file is longer than max_size or damaged" % (kind, length), required_at_least=end - off)
        # The CRC covers the chunk type and data; it is taken a block at a time, so a chunk of any size is never held whole.
        crc, at, left = zlib.crc32(kind), pos + 8, length
        while left:
            block = src.read(at, min(CHUNK, left))
            if not block:
                raise Refuse("the source ends inside a PNG chunk")
            crc = zlib.crc32(block, crc)
            at += len(block)
            left -= len(block)
        stored = src.read(at, 4)
        if len(stored) < 4:
            raise Refuse("the source ends inside a PNG chunk")
        if crc & 0xFFFFFFFF != struct.unpack(">I", stored)[0]:
            raise Refuse("the CRC of PNG chunk %d (%r) does not match: the structure is damaged or this is not a PNG here" % (n, kind), chunk=n)
        n += 1
        pos = end
        if kind == b"IEND":
            checks.append("%d chunks walked, every CRC matched, to IEND" % n)
            return pos - off, "validated", "chunk walk to IEND", checks, []


def carve_jpeg(src, off, limit):
    pos = off + 2
    checks = []
    while True:
        # a marker: 0xFF, then a code (fill 0xFF bytes may precede it)
        b = src.read(pos, 2)
        if len(b) < 2:
            raise Refuse("the JPEG's segments run off the end of the source")
        if b[0] != 0xFF:
            raise Refuse("expected a JPEG marker at byte %d, found 0x%02x" % (pos - off, b[0]))
        code = b[1]
        if code == 0xFF:
            pos += 1
            continue
        pos += 2
        if code == 0xD9:                      # EOI at the top level
            checks.append("segments walked to EOI; a thumbnail's own EOI inside an APPn segment is skipped by its length")
            return pos - off, "validated", "marker walk to EOI", checks, ["the entropy-coded image data is not decoded"]
        if code == 0xD8:
            # A start-of-image where a segment or an EOI should be: this image never reached its own EOI, and the bytes that follow
            # are another JPEG's. The candidate ends where that one begins, and its boundary is a guess.
            return pos - 2 - off, "heuristic", "the next JPEG's start-of-image", checks, [
                "no EOI was found before another JPEG's start-of-image: the image is truncated, overwritten or this window ends at the next header"]
        if code in (0x01,) or 0xD0 <= code <= 0xD7:      # no length: TEM, RSTn
            continue
        ln = src.read(pos, 2)
        if len(ln) < 2:
            raise Refuse("a JPEG segment's length is cut off")
        seg = struct.unpack(">H", ln)[0]
        if seg < 2:
            raise Refuse("a JPEG segment says it is %d bytes long" % seg)
        pos += seg
        if pos > limit:
            raise Refuse("complete file is larger than max_size: a JPEG segment runs past max_size or the source", required_at_least=pos - off)
        if code == 0xDA:                      # SOS: entropy-coded data follows, up to the next real marker
            while True:
                block = src.read(pos, CHUNK)
                if not block:
                    raise Refuse("the JPEG's image data runs off the end of the source")
                i, found = 0, None
                while i < len(block) - 1:
                    j = block.find(b"\xff", i, len(block) - 1)
                    if j < 0:
                        break
                    nxt = block[j + 1]
                    if nxt == 0x00 or 0xD0 <= nxt <= 0xD7 or nxt == 0xFF:
                        i = j + 2 if nxt != 0xFF else j + 1
                        continue
                    found = j
                    break
                if found is not None:
                    pos += found
                    break
                pos += max(1, len(block) - 1)
                if pos > limit:
                    raise Refuse("complete file is larger than max_size: the JPEG's image data runs past max_size", required_at_least=pos - off)


def carve_gif(src, off, limit):
    hdr = src.read(off, 13)
    if len(hdr) < 13:
        raise Refuse("the GIF's header is cut off")
    flags = hdr[10]
    pos = off + 13
    if flags & 0x80:
        pos += 3 * (1 << ((flags & 7) + 1))
    frames = 0

    def sub_blocks(p):
        while True:
            n = src.read(p, 1)
            if not n:
                raise Refuse("a GIF data block runs off the end of the source")
            p += 1 + n[0]
            if p > limit:
                raise Refuse("complete file is larger than max_size: a GIF data block runs past max_size", required_at_least=p - off)
            if n[0] == 0:
                return p

    while True:
        b = src.read(pos, 1)
        if not b:
            raise Refuse("the GIF's blocks run off the end of the source")
        if b[0] == 0x3B:
            return pos + 1 - off, "validated", "block walk to the trailer", ["%d image(s) walked, to the 0x3B trailer" % frames], []
        if b[0] == 0x21:                       # extension: label, then sub-blocks
            pos = sub_blocks(pos + 2)
        elif b[0] == 0x2C:                     # image descriptor, optional local table, LZW size byte, sub-blocks
            d = src.read(pos, 10)
            if len(d) < 10:
                raise Refuse("a GIF image descriptor is cut off")
            pos += 10
            if d[9] & 0x80:
                pos += 3 * (1 << ((d[9] & 7) + 1))
            pos = sub_blocks(pos + 1)
            frames += 1
        else:
            raise Refuse("unexpected GIF block 0x%02x at byte %d" % (b[0], pos - off))


def carve_zip(src, off, limit):
    notes = []
    first = None
    for pos in src.find_all(b"PK\x05\x06", off + 4, limit):
        rec = src.read(pos, 22)
        if len(rec) < 22:
            break
        _sig, _disk, _cd_disk, n_disk, n_total, cd_size, cd_off, clen = struct.unpack("<IHHHHIIH", rec)
        end = pos + 22 + clen
        if end > limit:
            continue
        rel = pos - off
        if first is None:
            first = (end - off, n_total)
        # ZIP64: a locator right before this end record names the ZIP64 end record, which holds the real directory offset and size. It is
        # looked for whenever there is a locator (an archive of 65536 entries or more has one although its end record's size and offset fit),
        # and always when the end record's size or offset are the placeholder 0xFFFFFFFF; a count of 0xFFFF alone is an ordinary 65535 entries.
        loc = src.read(pos - 20, 20) if pos - 20 >= off else b""
        has_locator = len(loc) == 20 and loc[:4] == b"PK\x06\x07"
        placeholder = cd_size == 0xFFFFFFFF or cd_off == 0xFFFFFFFF
        if has_locator or placeholder:
            if has_locator:
                z64_rel = struct.unpack("<Q", loc[8:16])[0]
                z = src.read(off + z64_rel, 56) if z64_rel <= limit - off else b""
                if len(z) == 56 and z[:4] == b"PK\x06\x06":
                    z_cd_size, z_cd_off = struct.unpack("<Q", z[40:48])[0], struct.unpack("<Q", z[48:56])[0]
                    if z_cd_off + z_cd_size == z64_rel and (z_cd_size == 0 or src.read(off + z_cd_off, 4) == b"PK\x01\x02"):
                        return end - off, "validated", "ZIP64 end-of-central-directory record", ["the ZIP64 record's directory offset and size agree with where it stands"], notes
            if placeholder:
                continue
        # n_total == 0xFFFF is an ordinary count of 65535 entries unless the sizes above say ZIP64.
        if cd_off + cd_size == rel and (cd_size == 0 or src.read(off + cd_off, 4) == b"PK\x01\x02"):
            return end - off, "validated", "end-of-central-directory record", [
                "the directory (%d entries, %d bytes at +%d) ends where the end record starts, and begins with a central file header" % (n_total, cd_size, cd_off)], notes
    if first is None:
        raise Refuse("no ZIP end-of-central-directory record in the window: the archive is longer than max_size, damaged, or this is not a ZIP here")
    notes.append("no end-of-central-directory record had directory offsets that agree with its position; the first record is returned (a prefix such as a self-extractor stub, a damaged directory or a concatenation would do this)")
    return first[0], "heuristic", "the first end-of-central-directory marker", ["its directory offsets do not match: unverified"], notes


def pdf_candidates(src, off, limit):
    """Each %%EOF in the window with what its startxref says and whether that offset holds an xref table or an indirect object."""
    out = []
    for pos in src.find_all(b"%%EOF", off, limit):
        if len(out) >= PDF_EOF_LIMIT:
            break
        back = src.read(max(off, pos - 64), pos - max(off, pos - 64))
        m = re.search(rb"startxref\s+(\d+)\s*$", back)
        entry = {"eof": pos - off, "end": pos + 5, "startxref": None, "xref_ok": False}
        if m:
            entry["startxref"] = int(m.group(1))
            probe = src.read(off + entry["startxref"], 64) if off + entry["startxref"] < limit else b""
            entry["xref_ok"] = bool(re.match(rb"\s*xref\b", probe) or re.match(rb"\s*\d+\s+\d+\s+obj\b", probe))
        out.append(entry)
    return out


def carve_pdf(src, off, limit):
    cands = pdf_candidates(src, off, limit)
    capped = len(cands) >= PDF_EOF_LIMIT
    cut = limit < src.size           # the source goes on past the window: a later revision may lie beyond it
    if not cands:
        raise Refuse("no %%EOF in the window: the PDF is longer than max_size, truncated, or this is not a PDF here")
    chosen, notes = None, []
    for c in cands:
        if not c["xref_ok"]:
            continue
        # A later %%EOF is part of this file when its startxref names an xref after the previous end
        # (a revision appended to the file); one that does not is not followed.
        if chosen is None or c["startxref"] > chosen["eof"]:
            chosen = c
    revisions = sum(1 for c in cands if c["xref_ok"] and (chosen is not None and c["eof"] <= chosen["eof"]))
    if chosen is None:
        first = cands[0]
        notes.append("no %%EOF had a startxref pointing at an xref table or object; the first %%EOF is returned")
        end = first["end"]
        basis, boundary, checks = "the first %%EOF marker", "heuristic", ["startxref not confirmed"]
    else:
        end = chosen["end"]
        basis, boundary = "last %%EOF whose startxref points at an xref table or object", "validated"
        checks = ["%d revision(s) of the file, each with a startxref that lands on an xref table or object; the last is taken" % revisions]
        later = [c for c in cands if c["eof"] > chosen["eof"]]
        if later:
            notes.append("%d further %%EOF marker(s) lie after the end chosen (at +%s): bytes that belong to another object, or to a revision whose xref this check could not confirm" % (len(later), ", +".join(str(c["eof"]) for c in later[:5])))
    if capped:
        boundary = "heuristic"
        notes.append("%d %%EOF markers were examined, the most this tool takes, so the revisions beyond them were not seen" % PDF_EOF_LIMIT)
    if cut:
        boundary = "heuristic"
        notes.append("the window ended at max_size and the source goes on: a later revision beyond it was not seen; raise max_size to look")
    # trailing end-of-line bytes after the marker belong to the line
    tail = src.read(end, 2)
    for ch in tail:
        if ch in (0x0D, 0x0A):
            end += 1
        else:
            break
    return end - off, boundary, basis, checks, notes


def carve_sqlite(src, off, limit):
    h = src.read(off, 100)
    if len(h) < 100:
        raise Refuse("the SQLite header is cut off")
    page = struct.unpack(">H", h[16:18])[0]
    if page == 1:
        page = 65536
    if page < 512 or page > 65536 or page & (page - 1):
        raise Refuse("the SQLite header's page size is %d: not a power of two from 512 to 65536" % page)
    pages = struct.unpack(">I", h[28:32])[0]
    counter, valid_for = struct.unpack(">I", h[24:28])[0], struct.unpack(">I", h[92:96])[0]
    if pages < 1:
        raise Refuse("the SQLite header's page count is 0")
    checks, notes = [], []
    structure_ok = h[21:24] == bytes([64, 32, 32]) and h[18] in (1, 2) and h[19] in (1, 2) and struct.unpack(">I", h[56:60])[0] in (1, 2, 3)
    if not structure_ok:
        notes.append("the header's fixed fields (payload fractions, versions, text encoding) are not what SQLite writes")
    if counter == valid_for:
        checks.append("the file change counter and the version-valid-for number agree (%d), so the header's page count (%d) is valid" % (counter, pages))
    else:
        notes.append("the file change counter (%d) and the version-valid-for number (%d) differ: the header's page count is not trustworthy and the size is a guess" % (counter, valid_for))
    if h[18] == 2 or h[19] == 2:
        notes.append("the database is in WAL mode: a -wal file beside the original is not part of this carve, and rows committed only there are not in these bytes")
    return page * pages, ("validated" if counter == valid_for and structure_ok else "heuristic"), "page size x page count from the header", checks, notes


def carve_regf(src, off, limit):
    base = src.read(off, 512)
    if len(base) < 512 or base[:4] != b"regf":
        raise Refuse("no registry hive base block here")
    major, minor, ftype, fmt, root, bins = struct.unpack("<IIIIII", base[20:44])
    checks, notes = [], []
    if major != 1 or minor not in (3, 4, 5, 6) or fmt != 1:
        raise Refuse("the base block's version (%d.%d) or file format (%d) is not one a hive has" % (major, minor, fmt))
    if bins == 0 or bins % 4096:
        raise Refuse("the base block's hive bins data size (%d) is not a positive multiple of 4096" % bins)
    total = 4096 + bins
    x = 0
    for (word,) in struct.iter_unpack("<I", base[:508]):
        x ^= word
    x = 1 if x == 0 else (0xFFFFFFFE if x == 0xFFFFFFFF else x)
    stored = struct.unpack("<I", base[508:512])[0]
    sums = x == stored
    (checks if sums else notes).append("base block checksum %s" % ("matches" if sums else "does NOT match (%08x stored, %08x computed): a damaged or edited base block" % (stored, x)))
    # the hive bins: a chain of hbin headers, each at its stated offset, adding up to the size the base block states
    pos, walked, ok = 0, 0, True
    if off + total > limit:
        ok = False
        notes.append("the hive bins run past max_size or the end of the source, so the hive-bin chain was not walked")
        pos = bins
    while pos < bins:
        h = src.read(off + 4096 + pos, 32)
        if len(h) < 32 or h[:4] != b"hbin":
            ok = False
            notes.append("no hive bin header at +%d of the hive bins (found %r)" % (pos, h[:4]))
            break
        rel, size = struct.unpack("<II", h[4:12])
        if rel != pos or size < 4096 or size % 4096 or pos + size > bins:
            ok = False
            notes.append("the hive bin at +%d says offset %d size %d: it does not fit the chain" % (pos, rel, size))
            break
        pos += size
        walked += 1
    if ok:
        checks.append("%d hive bin(s) walked, their sizes add up to the %d bytes the base block states" % (walked, bins))
    return total, ("validated" if ok else "heuristic"), "4096-byte base block + hive bins data size (offset 0x28)", checks, notes


def carve_pe(src, off, limit):
    head = src.read(off, 0x40)
    if len(head) < 0x40:
        raise Refuse("the source ends inside the DOS header (%d bytes after the offset)" % len(head))
    lfanew = struct.unpack_from("<I", head, 0x3C)[0]
    if lfanew < 0x40 or lfanew > 0x1000:
        raise Refuse("e_lfanew (%d) is not where a PE header can be" % lfanew)
    coff = src.read(off + lfanew, 24)
    if len(coff) < 24 or coff[:4] != b"PE\x00\x00":
        raise Refuse("no PE signature at e_lfanew (%d): a DOS or other MZ executable, or not an executable" % lfanew)
    num_sec, opt_sz = struct.unpack_from("<H", coff, 6)[0], struct.unpack_from("<H", coff, 20)[0]
    if num_sec == 0 or num_sec > 96:
        raise Refuse("the PE header says %d sections" % num_sec)
    opt = src.read(off + lfanew + 24, opt_sz)
    if len(opt) < opt_sz or opt_sz < 2:
        raise Refuse("the optional header is cut off")
    magic = struct.unpack_from("<H", opt, 0)[0]
    checks, notes = [], []
    end = 0
    if magic in (0x10B, 0x20B):
        dd_at = 96 if magic == 0x10B else 112
        size_headers = struct.unpack_from("<I", opt, 60)[0] if opt_sz >= 64 else 0
        end = size_headers
        if opt_sz >= dd_at + 8 * 5:
            n_dd = struct.unpack_from("<I", opt, dd_at - 4)[0]
            if n_dd > 4:
                cert_off, cert_size = struct.unpack_from("<II", opt, dd_at + 8 * 4)
                if cert_off and cert_size:
                    end = max(end, cert_off + cert_size)
                    checks.append("the certificate table (a file offset, not an RVA) ends at +%d" % (cert_off + cert_size))
    else:
        notes.append("the optional header's magic is 0x%x (not PE32 or PE32+): the certificate table was not read" % magic)
    sec = src.read(off + lfanew + 24 + opt_sz, 40 * num_sec)
    if len(sec) < 40 * num_sec:
        raise Refuse("the section table is cut off: the PE header is truncated")
    for i in range(num_sec):
        raw_sz, raw_off = struct.unpack_from("<II", sec, i * 40 + 16)
        end = max(end, raw_off + raw_sz)
    if end <= 0:
        raise Refuse("the PE's section table gives no data")
    checks.append("end = the furthest of the section raw extents%s" % (", the headers and the certificate table" if magic in (0x10B, 0x20B) else ""))
    after = src.read(off + end, 4096)
    overlay = any(after)
    if overlay:
        notes.append("non-zero bytes follow the end the headers give: an overlay (an installer's payload, appended data) or the next object. The headers do not say which, so the end is uncertain")
    return end, "heuristic", "section table, headers and certificate table", checks, notes, {"overlay_uncertain": overlay}


CARVERS = {"PNG": carve_png, "JPEG": carve_jpeg, "GIF": carve_gif, "ZIP": carve_zip, "PDF": carve_pdf,
           "SQLite": carve_sqlite, "regf": carve_regf, "PE": carve_pe}


def copy_range(src, off, size, dest):
    """Stream the range to a new file, hashing as it goes; returns (sha256, first_bytes)."""
    h, first = hashlib.sha256(), b""
    tmp = None
    if dest is not None:
        dest.parent.mkdir(parents=True, exist_ok=True)
        fd, tmp = tempfile.mkstemp(dir=dest.parent, prefix=".file_carver-")
        HELD._tmp = tmp
        out = os.fdopen(fd, "wb")
    else:
        out = None
    try:
        pos, left = off, size
        while left:
            data = src.read(pos, min(CHUNK, left))
            if not data:
                raise Refuse("the source ended before the candidate's end: wanted %d bytes, got %d" % (size, size - left))
            if not first:
                first = data[:128]
            h.update(data)
            if out:
                out.write(data)
            pos += len(data)
            left -= len(data)
        if out:
            out.flush()
            os.fsync(out.fileno())
            out.close()
            # An existing file is never replaced: a hard link fails where one stands.
            try:
                os.link(tmp, dest)
            except FileExistsError:
                raise Refuse("the output file already exists; this tool does not overwrite one", output=str(dest))
            except OSError:
                if dest.exists() or dest.is_symlink():
                    raise Refuse("the output file already exists; this tool does not overwrite one", output=str(dest))
                os.rename(tmp, dest)
                tmp = None
    finally:
        try:
            if out and not out.closed:
                out.close()                 # on a full disk this flushes and raises; the temporary file must go anyway
        finally:
            if tmp and os.path.exists(tmp):
                os.unlink(tmp)
    return h.hexdigest(), first


def carve(path, offset, sig_type, max_size, dest=None):
    if sig_type not in MAGICS:
        raise Refuse("this signature has no boundary check here", sig_type=sig_type, supported=sorted(MAGICS),
                     hint="find its offset with sig_carve, then use a format-aware extractor")
    src = Src(path)
    src.origin = offset
    try:
        header = src.read(offset, 16)
        expected = MAGICS[sig_type]
        valid = header.startswith(expected) if isinstance(expected, bytes) else any(header.startswith(m) for m in expected)
        if not valid:
            raise Refuse("the requested signature is not at the offset", sig_type=sig_type, offset=offset)
        limit = min(src.size, offset + max_size)
        got = CARVERS[sig_type](src, offset, limit)
        size, boundary, basis, checks, notes = got[:5]
        extra = got[5] if len(got) > 5 else {}
        if size < 4:
            raise Refuse("the boundary check gave a size of %d bytes" % size)
        if size > max_size:
            raise Refuse("complete file is larger than max_size", required_size=size, max_size=max_size,
                         hint="retry with max_size at least required_size; no partial output was written")
        if offset + size > src.size:
            raise Refuse("the source ends before the candidate's end", wanted=size, available=src.size - offset)
        digest, first = copy_range(src, offset, size, dest)
        result = {
            "ok": True, "tool": TOOL, "kind": "candidate_fragment",
            "status": "complete",
            "status_basis": "the structure walk for %s ended and the bytes up to its end were read; boundary says how far the end is trusted" % sig_type,
            "source": {"path": path, "bytes": src.size, "address_space": "the bytes of this file as given; a container (E01, VMDK) is not decoded"},
            "offset": offset, "size": size, "sha256": digest, "sig_type": sig_type,
            "boundary": boundary, "boundary_basis": basis, "checks": checks, "notes": notes, **extra,
            "not_established": "that these bytes are the whole original file, unfragmented and unaltered: a boundary check gives where a structure ends, not what the file was",
            "first_hex": first.hex(),
            "first_ascii": ''.join(chr(b) if 32 <= b < 127 else '.' for b in first),
        }
        return result
    finally:
        src.close()


def main():
    try:
        args = json.load(sys.stdin)
    except (ValueError, RecursionError) as exc:
        fail("arguments are not valid JSON", reason=str(exc))
    if not isinstance(args, dict):
        fail("arguments are a JSON object")
    path, offset, sig_type = args.get("path"), args.get("offset"), args.get("sig_type")
    max_size = args.get("max_size", DEFAULT_MAX)
    output = args.get("output")
    if not isinstance(path, str) or not path:
        fail("path is required: the raw dump to carve from")
    if not isinstance(offset, int) or isinstance(offset, bool) or offset < 0:
        fail("offset must be a non-negative integer", offset=offset)
    if not isinstance(sig_type, str) or not sig_type:
        fail("sig_type is required", supported=sorted(MAGICS))
    if not isinstance(max_size, int) or isinstance(max_size, bool) or max_size < 1:
        fail("max_size must be a positive integer", max_size=max_size)
    if not os.path.isfile(path):
        fail("no such file", path=path)
    dest = resolve_output(output) if output else None

    def _stopped(signum):
        print(json.dumps({"ok": False, "tool": TOOL, "status": "partial", "interrupted": True, "signal": signum, "path": path, "offset": offset, "sig_type": sig_type,
                          "status_basis": "the tool was stopped by signal %d: the carve was not finished, the hidden copy was removed, and an output file exists only when its copy "
                                          "was whole" % signum}), flush=True)
    install_signal_handlers(_stopped)
    try:
        result = carve(path, offset, sig_type, max_size, dest)
    except Refuse as exc:
        fail(str(exc), **{"sig_type": sig_type, **exc.extra})
    except OSError as exc:
        fail("the source could not be read or the output could not be written: %s" % (exc.strerror or exc), path=path)
    except (struct.error, ValueError, OverflowError) as exc:
        fail("a header of this signature is malformed: %s" % exc, sig_type=sig_type, offset=offset)
    if dest is not None:
        result["output"] = output
    print_answer(result)


if __name__ == "__main__":
    main()
