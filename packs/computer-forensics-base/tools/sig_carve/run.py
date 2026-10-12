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

TOOL = {"name": "sig_carve", "version": 2}
WINDOW = 8 * 1024 * 1024
BUDGET_SECONDS = 100              # inside the manifest's 120: past it the scan stops, says so, and names where to continue
CONTEXT_MAX = 4096
HITS_MAX = 1_000_000
ROWS_PER_SIGNATURE = 2_000_000       # rows kept in the whole-result file per signature; counting goes on past it

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

    def _write(self, row: object) -> None:
        assert self._out is not None
        self._out.write(json.dumps(row, ensure_ascii=False, default=str))
        self._out.write("\n")

    def add(self, row: object) -> None:
        self.total += 1
        if len(self.page) < self.limit:
            self.page.append(row)
            return
        if self._out is None:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            fd, name = tempfile.mkstemp(
                dir=self.path.parent, prefix=f".{self.path.name}-"
            )
            self._tmp = Path(name)
            self._out = os.fdopen(fd, "w", encoding="utf-8")
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
            self._out.flush()
            os.fsync(self._out.fileno())
            self._out.close()
            assert self._tmp is not None
            os.replace(self._tmp, self.path)
            result["all_results"] = self.shown
            result["all_results_format"] = "JSON Lines, one complete result per line"
        return result


class SafePage(LosslessPage):
    """The pager, with a whole-result file that may not be writable (a read-only run directory, a full disk).

    The count and the page stay whole; the answer says the file was not written (all_results_error) and no
    half file is left. LosslessPage itself is the pager every library tool carries, byte for byte.
    """

    error = None

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


def _same_bytes(a, b):
    """Two files with the same bytes (compared in blocks, never whole)."""
    try:
        if os.path.getsize(a) != os.path.getsize(b):
            return False
        with open(a, "rb") as fa, open(b, "rb") as fb:
            while True:
                x, y = fa.read(1 << 20), fb.read(1 << 20)
                if x != y:
                    return False
                if not x:
                    return True
    except OSError:
        return False


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


def _terminated(signum, _frame):
    for page in PAGES:
        page.discard()
    raise SystemExit(128 + signum)


def fail(message, **extra):
    print(json.dumps({"ok": False, "error": message, "tool": TOOL, **extra}))
    raise SystemExit(1)


def whole_number(args, key, default, low, high):
    value = args.get(key, default)
    if not isinstance(value, int) or isinstance(value, bool) or not low <= value <= high:
        fail("%s is a whole number from %d to %d" % (key, low, high), **{key: value})
    return value


def main():
    try:
        args = json.load(sys.stdin)
    except ValueError as exc:
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
    for sig in (signal.SIGTERM, signal.SIGHUP, signal.SIGINT):
        signal.signal(sig, _terminated)
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
    try:
        fh = open(path, "rb")
    except OSError as exc:
        fail("the file cannot be opened: %s" % (exc.strerror or exc), path=path)
    with fh:
        # From `start` on. The bytes just before it are read as the carry, so a header that begins before `start` and ends after it
        # is found once (one wholly before it is not this scan's); a continuation of a stopped scan loses no seam and repeats no hit.
        carry = b""
        if start and carry_len:
            try:
                fh.seek(max(0, start - carry_len))
                carry = fh.read(min(carry_len, start))
            except OSError as exc:
                fail("the file could not be read at offset %d: %s" % (start, exc.strerror or exc), path=path)
        fh.seek(start)
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
            buf = carry + block
            base = pos - len(carry)
            for name, header in headers.items():
                i = buf.find(header)
                while i >= 0:
                    # A hit wholly inside the carry was found in the window before: it is counted once.
                    if i + len(header) > len(carry):
                        at = base + i
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
                    i = buf.find(header, i + 1)
            try:
                fh.seek(pos + len(block))          # a preview may have moved the file position
            except OSError as exc:
                read_error = "the file could not be read at offset %d: %s" % (pos + len(block), exc.strerror or exc)
                pos += len(block)
                scanned = pos
                break
            carry = buf[-carry_len:] if carry_len else b""
            pos += len(block)
            scanned = pos
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
    print(json.dumps({
        "tool": TOOL,
        "source": {"path": path, "bytes": size, "address_space": "the bytes of this file as given; a container (E01, VMDK) is not decoded"},
        "scanned": scan,
        "context_bytes": context,
        "signatures": results,
        "note": "A hit is where a header's bytes occur, not a file: cut it with file_carver or read it in place and check it with a parser of that format. "
                "A signature that is not listed here, an encrypted or compressed region and a file split across the scan's source are not found by this scan.",
    }, indent=2))
    # Exit 0 means the engine ran: a stop at the time budget is a valid answer for [start, end) with the position to go on from
    # (scanned.complete is false and scanned.stopped says where). A read error is a failure.
    sys.exit(1 if read_error else 0)


if __name__ == "__main__":
    main()
