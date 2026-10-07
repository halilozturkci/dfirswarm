#!/usr/bin/env python3
"""Read a Windows Prefetch file, MAM-compressed or plain, field by field.

What is decoded, by the layout of its SCCA version (17, 23, 26, 30 and 31; any other version is
reported unsupported and no version-dependent field is interpreted): the executable name and hash,
the run count, the last-run FILETIMEs (raw and ISO 8601 UTC with seven fractional digits, by integer
arithmetic), the filename strings section as the header locates it (every string whole, a UTF-16LE
list, not a search for printable runs), and the first volume entry (device path, serial number,
creation time). The other volume entries, the file metrics and the trace chains are located and
counted, not decoded.

MAM framing is checked before anything is inflated: the `MAM` magic, the method byte (4, Xpress
Huffman; any other, a checksum-bearing variant included, is refused by name) and a declared
uncompressed size no larger than the cap. The decompressor, dissect.util's, has no output bound of
its own, so it is run with one: the declared size plus a small slack, past which the run fails and
says so. It is also given four zero bytes after the stream, because its bit reader takes 32 bits
ahead of its read position and a stream that ends without padding would otherwise lose its last
symbols (a file a few bytes short of its declared size is not a short stream). A stream that still
inflates to less than its declared size fails.

The run count is read where the file's layout puts it: the file information size (the file metrics
array offset at 0x54 less 0x50) is 224 or 216 in the versions with eight last-run slots, with the
run count at 0xD0 or 0xC8, and `file_information_size` is returned; any other size is a layout this
does not read, and no run count or last-run time is interpreted from it.

A compressed Prefetch file is unpacked by the same decoder mam_scan uses: agreement between the two
tools says nothing about the decoder. A Prefetch file does not say who ran the program, from where
the program was started, or that the program finished.
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

PARSER = "prefetch_mam/3"
MAX_FILE = 16 * 1024 * 1024


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



def fail(message, **extra):
    print(json.dumps({"error": message, "status": "failed", **extra}))
    raise SystemExit(1)


def main():
    try:
        args = json.load(sys.stdin)
    except ValueError as exc:
        fail("arguments are not valid JSON", reason=str(exc))
    path = args.get("path") if isinstance(args, dict) else None
    if not isinstance(path, str) or not path:
        fail("path is required: a Prefetch file, compressed (MAM) or plain SCCA")
    if not os.path.isfile(path):
        fail("no such file", path=path)
    try:
        size = os.path.getsize(path)
    except OSError as exc:
        fail("the file cannot be read: %s" % exc, path=path)
    if size > MAX_FILE:
        fail("the file is %d bytes, over the %d this tool reads whole; a Prefetch file is far smaller" % (size, MAX_FILE), path=path, bytes=size)
    try:
        data = Path(path).read_bytes()
    except OSError as exc:
        fail("the file cannot be read: %s" % exc, path=path)

    out = {"parser": PARSER, "source": path, "file_bytes": len(data)}
    kind, info = mam_header(data)
    container = {"mam": kind != "plain"}
    container.update(info)
    out["container"] = container
    if kind == "unsupported":
        out.update({"status": "unsupported", "problems": [info["why"]],
                    "note": "The file is not inflated and no field is read from it."})
        print(json.dumps(out, indent=2))
        return
    if kind == "ok":
        declared = info["declared_uncompressed_size"]
        try:
            inflated = bounded_decompress(data[MAM_HEADER:], declared + OUTPUT_SLACK)
        except OutputCapExceeded:
            fail("the MAM stream inflates past its declared size of %d bytes plus %d: it is damaged or hostile, and was stopped" % (declared, OUTPUT_SLACK),
                 path=path, declared_uncompressed_size=declared, cap=declared + OUTPUT_SLACK)
        except Exception as exc:                                  # the decoder's own errors on a damaged stream
            fail("the MAM stream could not be decompressed: %s: %s" % (type(exc).__name__, exc), path=path, declared_uncompressed_size=declared)
        if len(inflated) < declared:
            fail("the MAM stream ended before its declared uncompressed size", path=path, declared_uncompressed_size=declared, decompressed_size=len(inflated))
        container["decompressed_size"] = len(inflated)
        container["bytes_past_declared_size"] = len(inflated) - declared
        data = inflated[:declared]
    result = parse_scca(data)
    if not result.get("scca"):
        fail("not a Windows Prefetch file after the optional MAM decompression", path=path, problems=result["problems"])
    problems = result.pop("problems")
    out.update(result)
    out["problems"] = problems
    out["status"] = "complete" if out.get("supported") and not [p for p in problems if "assumption" not in p] else \
        ("unsupported" if not out.get("supported") else "partial")
    out["compressed"] = container["mam"]
    out["declared_uncompressed_size"] = container.get("declared_uncompressed_size")
    out["decompressed_size"] = len(data)
    print(json.dumps(out, indent=2))


if __name__ == "__main__":
    main()
