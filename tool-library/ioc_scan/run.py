#!/usr/bin/env python3
"""Stream a binary for ASCII and UTF-16LE needles and say where each one is.

The answer is a list of locators: for every occurrence, an id, the offset it starts at,
the needle and encoding that matched and how many bytes of context lie around it.
No context bytes come back by default. Context around a hit in a memory image, a
pagefile or unallocated space is where a password, a token or a card number sits, so
the bytes are written only when the caller asks (`write_values: true`), only in a job,
and only to a file under $OUT (JSON Lines, mode 0600, created new), which the skill
says to run with `secret_output: true`. The answer then says where that file is and
that it holds secret values, not what they are. Never put a secret in `needles`: the
arguments of a call are recorded in the trace.

What it finds, exactly: every occurrence of each needle, by the offset it starts at,
overlapping occurrences included, so the count does not depend on `chunk`. Matching is
case-sensitive and on the needle's bytes: ASCII/UTF-8 as given, and the same text as
UTF-16LE. Each read keeps back the bytes a needle or its context could still need, so a
match or its context cut by a read boundary is found once, whole. `scanned_*` and
`bytes_scanned` are the bytes actually read, not the range asked for.

The scan has a clock (`max_seconds`, default 100, at most 110, inside the manifest's 120): a scan that reaches it answers for the
range it decided, says `complete: false` and `status: partial`, and gives `next_start`, the offset to go on from (`start`). Every
occurrence that starts before `next_start` is reported once; one that starts at or after it is the next scan's, found there once.
"""
import errno
import hashlib
import json
import os
import re
import sys
import tempfile
import time
from collections import defaultdict
from pathlib import Path

TOOL = {"name": "ioc_scan", "version": 6}
CHUNK_DEFAULT = 8 * 1024 * 1024
CHUNK_MIN, CHUNK_MAX = 16, 256 * 1024 * 1024
CONTEXT_MAX = 65536
BEFORE = 16                        # bytes of context before a match
HITS_MAX = 1_000_000
NEEDLES_MAX = 1000
NEEDLE_BYTES_MAX = 4096
SEEN_CAP = 100_000                 # distinct contexts remembered for the inline view
ROW_CAP = 20_000_000               # rows in the whole-result file; counting goes on past it
VALUES_ROWS_MAX = 20_000_000       # rows in the values file (write_values); the scan and its locators go on past it
VALUES_BYTES_MAX = int(os.environ.get("IOC_SCAN_VALUES_BYTES") or 1 << 30)    # bytes in the values file (a smaller cap can be asked for)
SECONDS_DEFAULT, SECONDS_MAX = 100, 110   # the scan's own clock, inside the manifest's 120
FEED = 256 * 1024                  # bytes handed to the engine at a time: the clock is looked at between feeds


# BEGIN SHARED SCAN
# The same text is in ioc_scan, chunk_needles and sig_carve (tests/test_scan_core.py holds the copies equal and holds the
# engine to a brute-force search over every way of cutting a stream into reads). One engine finds literal byte strings in a
# stream read in blocks: every occurrence once, at its true offset, overlapping ones included, in (offset, needle) order,
# whatever the block size. A match is held back until `after` bytes of context follow it (or the stream has ended), and
# `before` bytes of context are kept behind the searched position, so a match, or its context, cut by a read boundary is
# neither lost nor counted twice. Each tool keeps its own answer: what it reports for a match, its pages and its budgets.
SCAN_SLICE = 256 * 1024            # positions searched, sorted and handed out together


class StreamScan:
    """feed() each block as it is read; every call returns (offset, needle index, buffer, buffer's offset) for the matches that can
    be decided now, in order. The buffer holds the match and its context. Exhaust the generator before the next feed: the
    buffer is trimmed when it ends.

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
                found = []
                for vi, nb in enumerate(self.needles):
                    stop = min(len(self.buf), b + len(nb) - 1)
                    j = self.buf.find(nb, max(a, self.first[vi] - self.base), stop)
                    while j >= 0:
                        found.append((j, vi))
                        j = self.buf.find(nb, j + 1, stop)
                found.sort()                      # by offset, then by needle order: the same list for any block size
                for j, vi in found:
                    yield self.base + j, vi, self.buf, self.base
                a = b
            self.done = process_end
        if not final:
            keep_from = max(0, (self.done - self.before) - self.base)
            self.buf, self.base = self.buf[keep_from:], self.base + keep_from
# END SHARED SCAN


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

    NAME = "ioc-scan-values.jsonl"

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
                "file, not a sealed secret output. Run this as job_run tool=ioc_scan with "
                "secret_output: true, and ask again there. Nothing was written."
            )
        if os.environ.get("SECRET_OUTPUT") != "1":
            raise SecretValuesRefused(
                "write_values is refused in a job that was not run as secret output: its files would be sealed as ordinary "
                "output. The harness sets SECRET_OUTPUT=1 for a secret job's process and it is not set here. Run it as "
                "job_run(tool: \"ioc_scan\", args: {...}), whose manifest makes a job that sets write_values secret output, or give "
                "a command job secret_output: true. Nothing was written."
            )
        self.path = Path(self.out) / self.NAME
        self.shown = "store/jobs/%s/out/%s" % (re.sub(r"[^A-Za-z0-9_.-]", "_", self.job), self.NAME)
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

    def add(self, finding_id: str, locator: dict, value: str) -> None:
        if not self.enabled:
            return
        # ensure_ascii: a path that is not UTF-8 (its bytes arrive as lone surrogates) is written as an escape, never an encoding error.
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
                "resume": "the file holds every occurrence that starts before stopped_at_offset; to get the rest, scan again from start=stopped_at_offset in a new job"}
               if self.stopped_at is not None else {}),
            "format": "JSON Lines, mode 0600: finding_id, file, offset, needle, encoding, value (the printable context around the match)" if self.enabled else None,
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


def same_bytes(a, b):
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


class Locators:
    """Every locator goes to a file as it is found; the inline page is the view of them the caller asked for.
    The file is published when the page is not the whole (more rows than the page, or repeats hidden from it)."""

    def __init__(self, key, page_limit):
        self.limit, self.page, self.total, self.hidden = page_limit, [], 0, 0
        digest = hashlib.sha256(json.dumps(key, sort_keys=True, default=str).encode("utf-8")).hexdigest()[:16]
        name = "ioc_scan-%s.jsonl" % digest
        job, out = os.environ.get("JOB_ID"), os.environ.get("OUT")
        if job and out:
            self.path = Path(out) / "tool-output" / name
            self.shown = "store/jobs/%s/out/tool-output/%s" % (re.sub(r"[^A-Za-z0-9_.-]", "_", job), name)
        else:
            agent = re.sub(r"[^A-Za-z0-9_.-]", "_", os.environ.get("AGENT_ID") or "tool")
            self.path = Path("work") / agent / "tool-output" / name
            self.shown = str(self.path)
        self.tmp = self.fh = self.error = None
        self.written = 0
        self.stopped_at = None
        try:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            fd, tmp = tempfile.mkstemp(dir=self.path.parent, prefix=".ioc_scan-")
            self.tmp, self.fh = Path(tmp), os.fdopen(fd, "w", encoding="utf-8")
        except OSError as exc:
            self.error = "the whole result could not be kept (%s: %s)" % (self.path.parent, exc.strerror or exc)

    def add(self, row, show):
        self.total += 1
        if self.fh:
            if self.written < ROW_CAP:
                self.fh.write(json.dumps(row, ensure_ascii=True) + "\n")
                self.written += 1
            elif self.stopped_at is None:
                self.stopped_at = row["offset"]
        if show and len(self.page) < self.limit:
            self.page.append(row)
        elif show is False:
            self.hidden += 1

    def discard(self):
        """Close and remove the file being written, if it is still there: the whole result is not kept when the run did not finish."""
        try:
            if self.fh and not self.fh.closed:
                self.fh.close()
        except OSError:
            pass
        if self.tmp is not None:
            try:
                os.unlink(self.tmp)
            except OSError:
                pass

    def finish(self):
        info = {"matched": self.total, "returned": len(self.page), "truncated": self.total > len(self.page)}
        if self.fh:
            self.fh.flush()
            os.fsync(self.fh.fileno())
            self.fh.close()
            if self.total > len(self.page):
                self.path, self.shown = publish(self.tmp, self.path, self.shown)
                self.tmp = None
                info["all_results"] = self.shown
                info["earlier_answers"] = earlier_answers(self.path)
                info["all_results_format"] = "JSON Lines, one locator per occurrence: finding_id, offset, needle, enc, context_length"
                if self.stopped_at is not None:
                    info["all_results_stopped_at_offset"] = self.stopped_at
                    info["all_results_cap_rows"] = ROW_CAP
            else:
                os.unlink(self.tmp)
        if self.error:
            info["all_results_error"] = self.error
        return info


def fail(message, **extra):
    print(json.dumps({"error": message, "tool": TOOL, **extra}))
    sys.exit(1)


def whole(args, key, default, low, high):
    value = args.get(key)
    if value is None:
        return default
    if not isinstance(value, int) or isinstance(value, bool) or not low <= value <= high:
        fail("%s is a whole number from %d to %d" % (key, low, high), **{key: value})
    return value


DEFAULT_NEEDLES = [
    "http://", "https://", "ftp://",
    "powershell", "cmd.exe", "rundll32", "mshta", "wscript", "cscript",
    "schtasks", "bitsadmin", "certutil", "regsvr32",
    "Invoke-", "IEX(", "-enc ", "FromBase64",
    "HKEY_", "CurrentVersion\\Run", "UserInit",
    "mimikatz", "meterpreter", "cobalt", "beacon",
    ".onion", "bitcoin", "ransom", "wallet",
    "psexec", "procexp", "sysinternals", "tcpview", "autoruns",
    "IEUser", "@gmail", "@yahoo", "@hotmail",
    "password", "Password", "C2", "user-agent", "User-Agent",
    ".exe", ".ps1", ".bat", ".vbs", ".js",
    "AppData\\", "\\Temp\\", "Downloads\\",
    "From:", "Subject:", "mailto:",
    "192.168.", "10.0.", "172.16.",
]


def main():
    started = time.monotonic()
    try:
        args = json.load(sys.stdin)
    except ValueError as exc:
        fail("arguments are not valid JSON", reason=str(exc))
    if not isinstance(args, dict):
        fail("arguments are a JSON object")
    path = args.get("path") or "inputs/[UNALLOCATED]"
    needles = args.get("needles")  # a list of strings, or a pipe-separated string
    if isinstance(needles, str):
        needles = [n for n in needles.split("|") if n]
    if needles is not None and (not isinstance(needles, list) or not all(isinstance(n, str) for n in needles)):
        fail("needles is a pipe-separated string or a list of strings")
    if "needles" in args and args["needles"] is not None and not needles:
        fail("needles is empty: give at least one needle, or leave needles out for the default set (the answer lists which ran)")
    needles_source = "given" if needles else "the default set: no needles were given"
    if not needles:
        needles = DEFAULT_NEEDLES
    needles = list(dict.fromkeys(needles))          # a needle given twice is one needle
    if len(needles) > NEEDLES_MAX:
        fail("at most %d needles" % NEEDLES_MAX, given=len(needles))
    max_hits = whole(args, "max_hits", 80, 1, HITS_MAX)
    context = whole(args, "context", 96, 0, CONTEXT_MAX)
    start = whole(args, "start", 0, 0, 1 << 62)
    length = args.get("length")
    if length is not None:
        length = whole(args, "length", None, 0, 1 << 62)
    chunk = whole(args, "chunk", CHUNK_DEFAULT, CHUNK_MIN, CHUNK_MAX)
    max_seconds = whole(args, "max_seconds", SECONDS_DEFAULT, 1, SECONDS_MAX)
    if args.get("skip_zeros", False):
        fail("skip_zeros would make the scan lossy and is not supported", hint="omit skip_zeros or pass false")
    unique_only = bool(args.get("unique_only", True))
    write_values = args.get("write_values", False)
    if not isinstance(write_values, bool):
        fail("write_values is true or false")

    variants = []
    for n in needles:
        try:
            raw = n.encode("utf-8")
            wide = n.encode("utf-16le")
        except UnicodeEncodeError:
            fail("a needle is not text that can be encoded", needle_index=needles.index(n))
        if not raw:
            continue
        if len(raw) > NEEDLE_BYTES_MAX:
            fail("a needle is longer than %d bytes" % NEEDLE_BYTES_MAX, needle_index=needles.index(n))
        variants.append(("ascii", n, raw))
        variants.append(("utf16", n, wide))
    if not variants:
        fail("no needle to look for")
    longest = max(len(v[2]) for v in variants)

    if os.path.isdir(path):
        fail("a directory, not a file: scan one file at a time", path=path)
    if not os.path.isfile(path):
        fail("no such file", path=path)
    size = os.path.getsize(path)
    if start > size:
        fail("start is past the end of the file", start=start, size=size)
    end = size if length is None else min(size, start + length)

    try:
        secret = SecretValues(write_values)
    except SecretValuesRefused as exc:
        fail(str(exc), write_values="refused")
    locators = Locators([path, needles, start, end, context, unique_only, size], max_hits)
    counts = defaultdict(int)
    seen = set()
    next_id = [0]

    def emit(at, kind, name, nb, buf, base):
        i = at - base
        s = max(0, i - BEFORE)
        e = min(len(buf), i + len(nb) + context)
        raw = buf[s:e]
        next_id[0] += 1
        fid = "F%06d" % next_id[0]
        counts[name] += 1
        row = {"finding_id": fid, "offset": at, "needle": name, "enc": kind, "context_length": len(raw)}
        show = True
        if unique_only:
            key = (name, kind, raw[:80])
            if key in seen:
                show = False
            elif len(seen) < SEEN_CAP:
                seen.add(key)
        locators.add(row, show)
        if write_values:
            text = "".join(chr(c) if 32 <= c < 127 else "." for c in raw)
            secret.add(fid, {"file": path, "offset": at, "needle": name, "encoding": kind}, text)

    # The shared engine finds every occurrence once, in offset order, whatever chunk is (see StreamScan above). The bytes of a read go
    # to it FEED at a time and the clock is looked at between feeds: a scan that has used its seconds stops there, and the matches that
    # start before scanner.done (all of which the engine has handed out) are its answer; the rest are the next scan's, from next_start.
    scanner = StreamScan([v[2] for v in variants], before=BEFORE, after=context, start=start)
    deadline = started + max_seconds
    scanned = start
    stopped = None
    try:
        with open(path, "rb") as fh:
            fh.seek(start)
            while scanned < end and stopped is None:
                data = fh.read(min(chunk, end - scanned))
                if not data:
                    break
                for off in range(0, len(data), FEED):
                    block = data[off:off + FEED] if len(data) > FEED else data
                    for at, vi, buf, base in scanner.feed(block):
                        kind, name, nb = variants[vi]
                        emit(at, kind, name, nb, buf, base)
                    scanned += len(block)
                    if scanned < end and time.monotonic() > deadline:
                        stopped = ("the %d-second time budget was used after %d bytes: the counts and hits are for the occurrences that start in [%d, %d); "
                                   "run again with start=%d to go on" % (max_seconds, scanned - start, start, scanner.done, scanner.done))
                        break
        if stopped is None and scanned < end:
            stopped_short = "the file ended after %d bytes, before the requested end at %d (it changed while it was read, or its size was wrong)" % (scanned, end)
        else:
            stopped_short = None
        if stopped is None:
            for at, vi, buf, base in scanner.feed(b"", final=True):
                kind, name, nb = variants[vi]
                emit(at, kind, name, nb, buf, base)
        secret.close()
        page = locators.finish()
    except OSError as exc:
        secret.close()
        locators.discard()
        fail("the file could not be read all the way: %s" % (exc.strerror or exc), path=path, scanned_end=scanned,
             note="what was found before the read failed is not a result; the values file, when one was asked for, holds those rows only",
             secret_values=secret.summary())
    finally:
        locators.discard()                 # a half-written locators file is never left behind (a no-op once it is published or dropped)
    result = {
        "tool": TOOL,
        "path": path,
        "source": {"path": path, "bytes": size, "address_space": "the bytes of this file as given; a container (E01, VMDK) is not decoded"},
        "scanned_start": start,
        "scanned_end": scanned,
        "bytes_scanned": scanned - start,
        "requested": {"start": start, "length": length, "end": end},
        "complete": scanned >= end and stopped is None,
        "status": "complete" if scanned >= end and stopped is None else "partial",
        "status_basis": ("every byte of the requested range was read and every occurrence that starts in it is reported" if scanned >= end and stopped is None
                         else "the scan did not read the whole requested range (see stopped): only the occurrences it reports are known"),
        "size": size,
        "case_sensitive": True,
        "match_policy": "every occurrence by its start offset, overlapping ones included; a needle is searched as given (UTF-8) and as UTF-16LE",
        "context": {"after_bytes": context, "before_bytes": BEFORE, "returned_inline": False,
                    "note": "context bytes are not returned: they are where a secret sits. write_values: true, in a job run with secret_output: true, writes them to a file under $OUT."},
        "hit_count_returned": page["returned"],
        "needles_that_ran": needles,
        "needles_source": needles_source,
        "counts": dict(sorted(counts.items(), key=lambda kv: -kv[1])),
        "hits": locators.page,
        **page,
        "secret_values": secret.summary(),
    }
    if stopped or stopped_short:
        result["stopped"] = stopped or stopped_short
    if stopped:
        result["next_start"] = scanner.done
    if secret.stopped_at is not None:
        result["status"] = "partial"
        result["status_basis"] += "; the values file stopped at its cap (secret_values.stopped_at_offset), the locators did not"
    if unique_only and locators.hidden:
        result["repeats_hidden_inline"] = locators.hidden
        result["repeats_note"] = "occurrences whose context repeats one already listed are not in the inline page; every one is in all_results"
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
