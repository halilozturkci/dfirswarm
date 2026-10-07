#!/usr/bin/env python3
"""Scan a raw dump or image region for MAM-compressed Prefetch records, and read each one.

A candidate is the 4-byte signature `MAM\x04` followed by a plausible declared uncompressed size
(`min_uncomp` to `max_uncomp`); it is a candidate, not a record, until it inflates to a Prefetch
(SCCA) structure. Every candidate is accounted for: how many there were, how many parsed, how many
failed and why (`failed_by_reason`, with the first failures kept in `failures`), how many the
`name_filter` left out, and how many `MAM\x84` (checksum-bearing) signatures were seen and not read.
Failures are counted BEFORE the name filter, so a record that could not be read is never lost to it.

Decompression is bounded: each candidate is read from the file at its own offset, up to the declared
size plus a margin for the worst case of the format, and decoded until it holds the declared size.
The stream's own end is not found by guessing cut sizes; four zero bytes follow the bytes read (see
LOOKAHEAD_PAD), so a stream that ends at the end of the dump without padding is decoded to its last
byte. A window of the scan is read into one buffer and released before the next, and a source that
cannot be read is a JSON failure that says how far the scan got. The decoder is dissect.util's, shared with
prefetch_mam (same text, so the two do not check each other). Fields are read by the layout of the
SCCA version, as prefetch_mam does; a version that is not read is reported as such and no
version-dependent field is interpreted. A hit in a dump is a fragment of memory or unallocated space:
it carries no file name, owner or path of the file it came from.
"""
import datetime
import hashlib
import json
import os
import re
import struct
import sys
import tempfile
from pathlib import Path

PARSER = "mam_scan/3"
MAX_CHUNK = 256 * 1024 * 1024

# Lossless paging (the same in every library tool that pages): the page an
# agent reads stays small, and when there are more rows the whole result is
# written as JSON Lines under work/<agent>/tool-output and named.
import hashlib
import re
import tempfile


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


# ---- Shared by prefetch_mam and mam_scan: the same text in both (the tools are standalone; a test holds
# ---- the two copies identical). MAM framing, bounded LZXPRESS-Huffman decompression, and the SCCA
# ---- (Prefetch) layouts by version.

FILETIME_EPOCH = datetime.datetime(1601, 1, 1, tzinfo=datetime.timezone.utc)
# MAM\x04: the "MAM" magic and the compression-method byte 4 (Xpress Huffman), then the declared
# uncompressed size (u32 little-endian), then the compressed data. Any other method byte (a variant
# that carries a checksum, say) is refused by name, not guessed at.
MAM_MAGIC = b"MAM"
MAM_METHOD_XPRESS_HUFFMAN = 4
MAM_HEADER = 8
# The decoder runs on until its input is exhausted and a well-formed stream ends with a few bytes
# past the declared size (an end-of-stream symbol and padding), so the output cap is the declared
# size plus this slack, never the declared size alone.
OUTPUT_SLACK = 64 * 1024
# dissect.util's loop stops when the read position reaches the end of the input, but its bit reader
# has already taken up to 32 bits ahead of that position: the symbols still in that lookahead are
# never decoded, and a stream that ends without padding comes out a few bytes short of its declared
# size. Four zero bytes after the payload let the decoder reach them; what it decodes from the zeros
# lies past the declared size and is cut. A stream that is genuinely short is still short.
LOOKAHEAD_PAD = b"\x00\x00\x00\x00"
# A Prefetch file is a few hundred kilobytes at most; a declared size past this is refused.
MAX_DECLARED = 64 * 1024 * 1024
SCCA = b"SCCA"
# Layouts by SCCA version: the last-run FILETIMEs (where they start, how many) and the run count.
# These are the versions the layout notes for Prefetch (libscca) describe; version 31 is treated as
# version 30's layout, which is an assumption and is reported as one. Any other version is not read.
# In the versions with eight last-run slots the run count does not sit at one place: the file
# information that holds it is followed by the file metrics array, whose offset is its first word
# (at 0x54), and Windows 10 files carry two sizes of it. The last-run FILETIMEs start at 0x80 in both;
# the run count is at 0xD0 when the metrics array offset is 0x130 (a file information size, that
# offset minus 0x50, of 224) and at 0xC8 when it is 0x128 (216). Any other size is a layout this
# does not read: no run count and no time is interpreted from it, and the answer says so.
INFO_SIZE_BASE = 0x50
RUN_COUNT_AT_BY_INFO_SIZE = {224: 0xD0, 216: 0xC8}
SCCA_VERSIONS = {
    17: {"last_run_at": 0x78, "last_runs": 1, "run_count_at": 0x90},
    23: {"last_run_at": 0x80, "last_runs": 1, "run_count_at": 0x98},
    26: {"last_run_at": 0x80, "last_runs": 8, "run_count_by_info_size": True},
    30: {"last_run_at": 0x80, "last_runs": 8, "run_count_by_info_size": True},
    31: {"last_run_at": 0x80, "last_runs": 8, "run_count_by_info_size": True},
}


def filetime_iso(ft):
    """A FILETIME as ISO 8601 UTC with all seven fractional digits, by integer arithmetic; None for 0 or past 9999."""
    if not ft:
        return None
    try:
        whole, ticks = divmod(ft, 10_000_000)
        return (FILETIME_EPOCH + datetime.timedelta(seconds=whole)).strftime("%Y-%m-%dT%H:%M:%S") + ".%07dZ" % ticks
    except (OverflowError, ValueError):
        return None


class OutputCapExceeded(Exception):
    """The decompressor produced more than its cap."""


class EnoughOutput(Exception):
    """The decompressor reached the declared size (soft mode); `data` is what it had."""

    def __init__(self, data):
        super().__init__("declared size reached")
        self.data = data


class _CappedBytes(bytearray):
    """The output buffer of the decompressor, which grows without a bound of its own. In strict mode it
    refuses to hold more than `cap` bytes; in soft mode it stops the decoder once it holds `cap` bytes.
    The decoder adds at most one match (a few tens of kilobytes) between two checks."""

    cap = 0
    soft = False

    def _after(self):
        if self.soft:
            if len(self) >= self.cap:
                raise EnoughOutput(bytes(self)[:self.cap])
        elif len(self) > self.cap:
            raise OutputCapExceeded("the stream inflates past %d bytes" % self.cap)

    def append(self, value):
        super().append(value)
        self._after()

    def __iadd__(self, other):
        super().__iadd__(other)
        self._after()
        return self


def bounded_decompress(payload, cap, soft=False):
    """LZXPRESS-Huffman decompression with a bound on the output. dissect.util's decoder grows its
    output until its input ends, so a small payload can inflate without limit; this runs it with an
    output buffer that stops it. Strict mode raises OutputCapExceeded past `cap`. Soft mode (a payload
    cut from a dump, longer than the real stream) returns the first `cap` bytes once the decoder has
    produced them. The decoder is dissect.util's, so a tool using this does not check it against an
    independent one. LOOKAHEAD_PAD is appended to the payload (see there)."""
    from dissect.util.compression import lzxpress_huffman
    import inspect
    if "dst = bytearray()" not in inspect.getsource(lzxpress_huffman.decompress):
        raise RuntimeError("the installed dissect.util decompressor is not the shape this bound is written for; refusing to run it unbounded")
    _CappedBytes.cap = cap
    _CappedBytes.soft = soft
    lzxpress_huffman.bytearray = _CappedBytes
    try:
        return lzxpress_huffman.decompress(bytes(payload) + LOOKAHEAD_PAD)
    except EnoughOutput as done:
        return done.data
    finally:
        del lzxpress_huffman.bytearray


def mam_header(data):
    """(status, info): the MAM framing of `data`, if it has one. status is "plain" (no MAM magic),
    "ok" (method 4 and a declared size), or "unsupported" (a MAM header this does not read)."""
    if data[:3] != MAM_MAGIC:
        return "plain", {}
    if len(data) < MAM_HEADER:
        return "unsupported", {"why": "a MAM header cut short (%d bytes)" % len(data)}
    method = data[3]
    declared = struct.unpack_from("<I", data, 4)[0]
    if method != MAM_METHOD_XPRESS_HUFFMAN:
        return "unsupported", {"why": "MAM method byte 0x%02x is not the Xpress Huffman method (4) this reads; a variant with a checksum is not handled" % method,
                               "method": method, "declared_uncompressed_size": declared}
    if declared > MAX_DECLARED:
        return "unsupported", {"why": "the declared uncompressed size %d is past the %d this tool will inflate" % (declared, MAX_DECLARED),
                               "method": method, "declared_uncompressed_size": declared}
    return "ok", {"method": method, "declared_uncompressed_size": declared}


def utf16_text(raw):
    return raw.decode("utf-16-le", "replace")


def parse_scca(data):
    """A Prefetch (SCCA) file, by the layout of its version. Returns the fields and a `problems` list. A version
    that is not in SCCA_VERSIONS gets the version-independent header (name, hash, size) and nothing else."""
    out = {"problems": []}
    if len(data) < 0x54 or data[4:8] != SCCA:
        out["problems"].append("not a Prefetch (SCCA) structure: %d bytes, signature %r" % (len(data), bytes(data[4:8])))
        out["scca"] = False
        return out
    out["scca"] = True
    version = struct.unpack_from("<I", data, 0)[0]
    out["version"] = version
    out["file_size_field"] = struct.unpack_from("<I", data, 12)[0]
    out["file_size_matches"] = out["file_size_field"] == len(data)
    out["exe_name"] = utf16_text(bytes(data[0x10:0x4C])).split("\x00")[0]
    out["prefetch_hash"] = "%08X" % struct.unpack_from("<I", data, 0x4C)[0]
    layout = SCCA_VERSIONS.get(version)
    out["supported"] = layout is not None
    if layout is None:
        out["problems"].append("SCCA version %d is not one this parser reads (17, 23, 26, 30 and 31 are); the run count, the times, the "
                               "strings and the volumes are not interpreted" % version)
        return out
    if version == 31:
        out["problems"].append("version 31 is read with version 30's layout, which is an assumption")
    if not out["file_size_matches"]:
        out["problems"].append("the file size field (%d) is not the length of the data (%d)" % (out["file_size_field"], len(data)))
    # The first word of the file information is the offset of the file metrics array: the file
    # information size is that offset less INFO_SIZE_BASE, and it tells which layout the run count has.
    info_size = None
    if len(data) >= 0x58:
        info_size = struct.unpack_from("<I", data, 0x54)[0] - INFO_SIZE_BASE
        out["file_information_size"] = info_size
    if layout.get("run_count_by_info_size"):
        count_at = RUN_COUNT_AT_BY_INFO_SIZE.get(info_size)
        if count_at is None:
            out["run_count"] = None
            out["problems"].append(
                "the file information size is %s (the file metrics array offset at 0x54 less 0x50), and the layouts read have 224 "
                "(run count at 0xD0) and 216 (run count at 0xC8): the run count and the last-run times are not interpreted"
                % ("not readable" if info_size is None else info_size))
    else:
        count_at = layout["run_count_at"]
    if count_at is not None:
        out["run_count"] = struct.unpack_from("<I", data, count_at)[0] if count_at + 4 <= len(data) else None
        runs = []
        for slot in range(layout["last_runs"]):
            at = layout["last_run_at"] + slot * 8
            if at + 8 > len(data):
                out["problems"].append("last-run slot %d is past the end of the data" % slot)
                break
            raw = struct.unpack_from("<Q", data, at)[0]
            if raw:
                runs.append({"slot": slot, "filetime": str(raw), "utc": filetime_iso(raw)})
        out["last_runs"] = [r["utc"] for r in runs]
        out["last_runs_detail"] = runs
    # File information fields common to these versions: the metrics array, the trace chains, the
    # filename strings and the volume information, each an offset and a size or count from byte 0x54.
    metrics_at, metrics_n, chains_at, chains_n, names_at, names_size, vols_at, vols_n, vols_size = struct.unpack_from("<9I", data, 0x54) \
        if len(data) >= 0x54 + 36 else (0,) * 9
    out["sections"] = {"metrics": {"offset": metrics_at, "entries": metrics_n}, "trace_chains": {"offset": chains_at, "entries": chains_n},
                       "filename_strings": {"offset": names_at, "size": names_size},
                       "volumes": {"offset": vols_at, "entries": vols_n, "size": vols_size}}
    if names_size:
        if names_at < 0x54 or names_at + names_size > len(data) or names_size % 2:
            out["problems"].append("the filename strings section (offset %d, %d bytes) does not fit the data" % (names_at, names_size))
            out["filename_strings"] = []
        else:
            text = utf16_text(bytes(data[names_at:names_at + names_size]))
            names = text.split("\x00")
            if names and names[-1] == "":
                names.pop()
            out["filename_strings"] = names
            if metrics_n and metrics_n != len(names):
                out["problems"].append("the header counts %d file metric entries and the filename strings section holds %d string(s)" % (metrics_n, len(names)))
    else:
        out["filename_strings"] = []
    out["volumes_decoded"] = []
    if vols_n:
        # Each volume entry begins with the device path offset and character count (from the start of the
        # volume information), the volume creation FILETIME and the serial number, in every version. The
        # size of an entry differs by version and is not applied here: the first entry is decoded and the
        # rest are counted.
        if vols_at < 0x54 or vols_at + 20 > len(data):
            out["problems"].append("the volume information (offset %d) does not fit the data" % vols_at)
        else:
            dev_off, dev_chars = struct.unpack_from("<II", data, vols_at)
            created = struct.unpack_from("<Q", data, vols_at + 8)[0]
            serial = struct.unpack_from("<I", data, vols_at + 16)[0]
            start = vols_at + dev_off
            device = None
            if dev_chars and 0 <= dev_off and start + dev_chars * 2 <= len(data):
                device = utf16_text(bytes(data[start:start + dev_chars * 2])).split("\x00")[0]
            elif dev_chars:
                out["problems"].append("the first volume's device path does not fit the data")
            out["volumes_decoded"].append({"index": 0, "device_path": device, "serial_number": "%08X" % serial,
                                           "created_filetime": str(created), "created_utc": filetime_iso(created)})
        out["volumes_claimed"] = vols_n
        if vols_n > 1:
            out["problems"].append("%d volumes are claimed and the first is decoded: the entry size by version is not applied" % vols_n)
    return out


SIG4 = MAM_MAGIC + bytes([MAM_METHOD_XPRESS_HUFFMAN])
SIG84 = MAM_MAGIC + b"\x84"
OVERLAP = MAM_HEADER - 1


def fail(message, **extra):
    print(json.dumps({"error": message, "ok": False, **extra}))
    raise SystemExit(1)


def whole(args, name, default, low, high=None):
    v = args.get(name)
    if v is None:
        v = default
    if isinstance(v, bool) or not isinstance(v, int) or v < low or (high is not None and v > high):
        fail("%s must be a whole number%s" % (name, " from %d to %d" % (low, high) if high is not None else " of at least %d" % low), got=args.get(name))
    return v


def read_candidate(path, offset, declared):
    """Inflate the record at `offset`: the payload is read from the file itself, up to the declared size plus
    the worst-case expansion of the format, and decoding stops once the declared size is reached."""
    try:
        with open(path, "rb") as fh:
            fh.seek(offset + MAM_HEADER)
            payload = fh.read(declared + declared // 4 + 4096)
    except OSError as exc:
        return None, "read_failed: %s" % type(exc).__name__, [offset + MAM_HEADER, offset + MAM_HEADER]
    attempted = [offset + MAM_HEADER, offset + MAM_HEADER + len(payload)]
    try:
        dec = bounded_decompress(payload, declared, soft=True)
    except Exception as exc:                                   # the decoder's own errors on rubbish
        return None, "decompress_failed: %s" % type(exc).__name__, attempted
    if len(dec) < declared:
        return None, "stream_ended_before_declared_size", attempted
    if dec[4:8] != SCCA:
        return None, "not_prefetch", attempted
    return dec[:declared], None, attempted


def main():
    try:
        args = json.loads(sys.stdin.read() or "{}")
    except ValueError as exc:
        fail("arguments are not valid JSON", reason=str(exc))
    if not isinstance(args, dict):
        fail("arguments must be a JSON object")
    path = args.get("path")
    if not path:
        print(json.dumps({"ok": False, "error": "path is required: the raw dump or image to scan"}))
        raise SystemExit(0)
    if not isinstance(path, str) or not os.path.isfile(path):
        fail("no such file", path=path)
    start = whole(args, "start", 0, 0)
    length = args.get("length")
    if length is not None:
        length = whole(args, "length", 0, 0)
    max_hits = whole(args, "max_hits", 80, 1)
    chunk = whole(args, "chunk", 8 * 1024 * 1024, 4096, MAX_CHUNK)
    parse = bool(args.get("parse", True))
    min_uncomp = whole(args, "min_uncomp", 1024, 1)
    max_uncomp = whole(args, "max_uncomp", 2_000_000, 1, MAX_DECLARED)
    needle = (args.get("name_filter") or "").upper()
    key = [path, start, length, parse, min_uncomp, max_uncomp, needle]
    hits = LosslessPage("mam_scan", key, max_hits)
    failures = LosslessPage("mam_scan-failures", key, 40)
    counts = {"candidates": 0, "size_out_of_range": 0, "parsed": 0, "filtered_by_name": 0, "unsupported_variant_signatures": 0}
    failed_by_reason = {}
    pos = start
    try:
        with open(path, "rb") as f:
            f.seek(start)
            file_size = os.fstat(f.fileno()).st_size
            remaining = length
            carry = b""
            while remaining is None or remaining > 0:
                toread = chunk if remaining is None else min(chunk, remaining)
                toread = min(toread, max(file_size - pos, 0))          # never a buffer for bytes the file does not have
                if not toread:
                    break
                # One buffer for the carried bytes and the window: the window is read into it in place, so a
                # window of 256 MiB costs 256 MiB and not a copy of it besides the read and the join.
                buf = bytearray(len(carry) + toread)
                buf[:len(carry)] = carry
                got = f.readinto(memoryview(buf)[len(carry):])
                if not got:
                    break
                del buf[len(carry) + got:]
                abs_base = pos - len(carry)
                counts["unsupported_variant_signatures"] += _count84(buf, len(carry))
                i = 0
                while True:
                    j = buf.find(SIG4, i)
                    if j < 0:
                        break
                    i = j + 4
                    if j + MAM_HEADER > len(buf):
                        continue                                   # its size field is in the next window: found there, once
                    declared = struct.unpack_from("<I", buf, j + 4)[0]
                    off = abs_base + j
                    if not min_uncomp <= declared <= max_uncomp:
                        counts["size_out_of_range"] += 1
                        continue
                    counts["candidates"] += 1
                    rec = {"offset": off, "uncomp": declared}
                    if parse:
                        dec, why, attempted = read_candidate(path, off, declared)
                        if dec is None:
                            failed_by_reason[why] = failed_by_reason.get(why, 0) + 1
                            failures.add({"offset": off, "uncomp": declared, "reason": why, "attempted_range": attempted})
                            continue
                        scca = parse_scca(dec)
                        scca.pop("scca", None)
                        rec.update(scca)
                        rec["name"] = rec.get("exe_name")
                        rec["dec_len"] = len(dec)
                        rec["attempted_range"] = attempted
                        counts["parsed"] += 1
                        if needle and needle not in (rec.get("exe_name") or "").upper() and \
                                needle not in " ".join(rec.get("filename_strings") or []).upper():
                            counts["filtered_by_name"] += 1
                            continue
                    hits.add(rec)
                pos += got
                if remaining is not None:
                    remaining -= got
                carry = bytes(buf[-OVERLAP:]) if len(buf) >= OVERLAP else bytes(buf)
                del buf                                                # the window is gone before the next is allocated
                if got < toread:
                    break
    except OSError as exc:
        fail("the source could not be read: %s" % exc, path=path, scanned_from=start, scanned_to=pos, candidates=counts["candidates"],
             parsed=counts["parsed"], failed=sum(failed_by_reason.values()))
    page = hits.finish()
    failure_page = failures.finish()
    failed_total = sum(failed_by_reason.values())
    out = {
        "parser": PARSER,
        "status": "complete" if not failed_total else "partial",
        "count": page["matched"],
        "hits": hits.page,
        "scanned_from": start,
        "scanned_to": pos,
        "candidates": counts["candidates"],
        "parsed": counts["parsed"],
        "failed": failed_total,
        "failed_by_reason": failed_by_reason,
        "failures": failures.page,
        "size_out_of_range": counts["size_out_of_range"],
        "filtered_by_name": counts["filtered_by_name"],
        "unsupported_variant_signatures": counts["unsupported_variant_signatures"],
        "note": "A hit is a Prefetch structure found in raw bytes: it carries no file name, owner or path of the file it came from, "
                "and a candidate that did not inflate to a Prefetch structure is counted under failed, not dropped.",
        **page,
    }
    if failure_page.get("all_results"):
        out["all_failures"] = failure_page["all_results"]
    json.dump(out, sys.stdout)


def _count84(buf, already):
    """MAM signatures with a method byte of 0x84 in `buf`, not counting any that lie wholly in the first `already` bytes (seen in the last window)."""
    n, i = 0, 0
    while True:
        j = buf.find(SIG84, i)
        if j < 0:
            return n
        if j + 4 > already:
            n += 1
        i = j + 4


if __name__ == "__main__":
    main()
