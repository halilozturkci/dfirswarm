#!/usr/bin/env python3
"""Find the structures inside a memory image that other parsers already read.

A framework needs symbols that match the build, and on an unusual build there may
be none. Meanwhile the image is a large blob with recognisable structures in it,
and a parser for most of them exists in the windows-forensics pack when that pack
is loaded: a hive carved out of memory goes to regkv exactly as one taken off a
disk would, a chunk to evtx_carve, a prefetch record to mam_scan or prefetch_mam.

This tool finds and cuts; it does not parse, and it does not reconstruct. A hit is
a signature at a byte offset of the file named by `path`. What it cuts is a slice
of that file's bytes: the pages of one structure in memory need not be adjacent
in a physical image, so a slice can run into unrelated pages or end before the
structure does. Each hit therefore says three separate things:

    signature_offset   where the signature bytes are
    object_offset      where the structure starts, when the format puts something
                       before its signature (a plain Prefetch record starts four
                       bytes earlier, at its version field); null when that is not
                       established
    validation         "header plausible", "header implausible", "truncated" (the
                       file ends before the header can be read, or before the
                       length the header declares) or "unknown" (no structural
                       check exists for the kind: a signature only)

The offsets are the whole provenance, since a structure carved from memory has no
path and no file name, so they belong in the report beside whatever a downstream
parser says. A cut is made at `object_offset` when it is known and at
`signature_offset` otherwise, and the amount cut is the kind's fixed size, not the
structure's own length: `declared_bytes` is the length the header declares, where
it declares one. Hits are found and numbered in offset order, so `max_extract`
takes the earliest candidates and the answer says how many it did not extract.
"""
import errno
import hashlib
import json
import os
import re
import struct
import sys
import tempfile
from pathlib import Path

PARSER = "mem_carve/3"
SIGNATURES = [
    (b"regf", "registry hive", 1 << 20),
    (b"ElfChnk\x00", "event log chunk", 65536),
    (b"ElfFile\x00", "event log file", 1 << 20),
    (b"MAM\x04", "compressed prefetch record", 1 << 17),
    (b"SCCA", "prefetch record", 1 << 17),
    (b"MZ\x90\x00\x03", "PE header", 1 << 20),
    (b"SQLite format 3\x00", "SQLite database", 1 << 21),
    (b"FILE0", "MFT record", 1024),
    (b"INDX(", "NTFS index block", 4096),
    (b"\x50\x4b\x03\x04", "zip or office document", 1 << 20),
    (b"%PDF-", "PDF", 1 << 20),
    (b"bplist00", "binary property list", 1 << 16),
]
WINDOW = 1 << 22
DEFAULT_PREVIEW = 200
# How much of a structure's start a validator may look at.
HEAD = 4096
# The versions a plain Prefetch record carries in its first four bytes (libscca's
# format notes): 17 Windows XP and 2003, 23 Vista and 7, 26 8 and 8.1, 30 10, 31 11.
PREFETCH_VERSIONS = (17, 23, 26, 30, 31)
MAX_PROBLEMS = 20


# Lossless paging (the same in every library tool that pages): the page an agent
# reads stays small, and when there are more rows the whole result is written as
# JSON Lines under work/<agent>/tool-output (in a job, $OUT/tool-output) and named.
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
            self._out = None
            result["all_results"] = self.shown
            result["all_results_format"] = "JSON Lines, one complete result per line"
        return result

    def abort(self) -> None:
        """Drop the hidden temporary file of a run that failed part way."""
        if self._out is not None:
            self._out.close()
            self._out = None
        if self._tmp is not None:
            try:
                os.unlink(self._tmp)
            except FileNotFoundError:
                pass


class ExtractManifest:
    """extract-manifest.jsonl in the extract directory: one row per extract with its size and sha256.

    The digests live here, in a private file beside the extracts, and not in the answer: an
    extract can be a credential store, and the answer is what an agent pastes from. A name
    taken by an earlier run is not reused (extract-manifest.1.jsonl, and so on).
    """

    def __init__(self, directory):
        self.directory = directory
        self.path = None
        self._fh = None

    def add(self, row):
        if self._fh is None:
            for n in range(1000):
                name = "extract-manifest.jsonl" if n == 0 else "extract-manifest.%d.jsonl" % n
                try:
                    fd = os.open(str(self.directory / name),
                                 os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o600)
                except FileExistsError:
                    continue
                self.path = self.directory / name
                self._fh = os.fdopen(fd, "w", encoding="utf-8")
                break
            else:
                raise OSError(errno.EEXIST, "no free extract-manifest name in the extract directory")
        self._fh.write(json.dumps(row, ensure_ascii=False) + "\n")
        self._fh.flush()

    def close(self):
        if self._fh is not None:
            self._fh.flush()
            os.fsync(self._fh.fileno())
            self._fh.close()
            self._fh = None


def fail(message, **extra):
    print(json.dumps({"error": message, **extra}))
    raise SystemExit(1)


def resolve_output(out):
    """Resolve an output below this agent's work/<id>/ directory.

    A string check is not enough: `work/../inputs/x` and an absolute path
    both name a file the tool must not write, and neither starts with
    "inputs/". Resolving first and comparing directories is what actually
    holds, and the read-only inputs are the one place extracted bytes must
    never appear -- a later integrity check would report the evidence as
    modified.
    """
    root = Path.cwd().resolve()
    dest = (root / out).resolve() if not Path(out).is_absolute() else Path(out).resolve()
    # In a job only $OUT is written, and it is sealed as the job's output.
    job_out = Path(os.environ["OUT"]).resolve() if os.environ.get("JOB_ID") and os.environ.get("OUT") else None
    if job_out is not None and job_out in dest.parents:
        return dest
    if dest != root and root not in dest.parents:
        fail("output must stay inside the run directory", output=str(out))
    work = (root / "work").resolve()
    if dest == work or work not in dest.parents:
        fail("output must be under your own work/<your id>/ directory", output=str(out))
    relative = dest.relative_to(work)
    if len(relative.parts) < 2 or relative.parts[0] in ("", ".", ".."):
        fail("output must name a path inside work/<your id>/, not work/ itself",
             output=str(out))
    return dest


# --- what each kind's first bytes say ------------------------------------------
#
# A validator reads at most HEAD bytes from the structure's start and returns
# (state, declared_bytes, detail). It checks fields the format fixes and nothing
# more: "header plausible" is not "a whole, readable structure".

PLAUSIBLE, IMPLAUSIBLE, TRUNCATED, UNKNOWN = "header plausible", "header implausible", "truncated", "unknown"
PAGE_SIZES = {512 << n for n in range(8)}  # 512 to 65536, powers of two


def check_regf(head):
    # Base block: the major version at 0x14 is 1 and the minor at 0x18 is 3 to 6.
    if len(head) < 0x1C:
        return TRUNCATED, None, "the file ends inside the hive's base block"
    major, minor = struct.unpack_from("<II", head, 0x14)
    if major == 1 and 3 <= minor <= 6:
        return PLAUSIBLE, None, "format version 1.%d" % minor
    return IMPLAUSIBLE, None, "major %d, minor %d are not a registry hive version" % (major, minor)


def check_evtx_chunk(head):
    # Chunk header: its own size, at 0x28, is 128; a chunk is 64 KiB.
    if len(head) < 0x2C:
        return TRUNCATED, None, "the file ends inside the chunk header"
    size, = struct.unpack_from("<I", head, 0x28)
    if size == 128:
        return PLAUSIBLE, 65536, "a chunk is 65536 bytes"
    return IMPLAUSIBLE, None, "header size %d, not 128" % size


def check_evtx_file(head):
    # File header: its size, 128, at 0x20; major version 3 at 0x26; chunk count at 0x2A.
    if len(head) < 0x2C:
        return TRUNCATED, None, "the file ends inside the file header"
    size, = struct.unpack_from("<I", head, 0x20)
    major, = struct.unpack_from("<H", head, 0x26)
    chunks, = struct.unpack_from("<H", head, 0x2A)
    if size == 128 and major == 3:
        return PLAUSIBLE, 4096 + chunks * 65536, "%d chunks declared" % chunks
    return IMPLAUSIBLE, None, "header size %d, major version %d" % (size, major)


def check_mam(head):
    # "MAM" 0x04, then the uncompressed size (a Prefetch file is far below 16 MiB).
    if len(head) < 8:
        return TRUNCATED, None, "the file ends inside the 8-byte MAM header"
    size, = struct.unpack_from("<I", head, 4)
    if 0 < size <= 1 << 24:
        return PLAUSIBLE, None, "declared uncompressed size %d" % size
    return IMPLAUSIBLE, None, "declared uncompressed size %d" % size


def check_scca(head):
    # head starts at the version field: the version at 0, "SCCA" at 4, the file size at 0x0C.
    if len(head) < 0x10:
        return TRUNCATED, None, "the file ends inside the Prefetch header"
    version, = struct.unpack_from("<I", head, 0)
    size, = struct.unpack_from("<I", head, 0x0C)
    if version not in PREFETCH_VERSIONS:
        return IMPLAUSIBLE, None, "version %d is not one of %s" % (version, ", ".join(map(str, PREFETCH_VERSIONS)))
    if not 0x54 <= size <= 1 << 24:
        return IMPLAUSIBLE, None, "version %d, declared file size %d" % (version, size)
    return PLAUSIBLE, size, "version %d" % version


def check_pe(head):
    # DOS header: e_lfanew at 0x3C names the "PE\0\0" signature.
    if len(head) < 0x40:
        return TRUNCATED, None, "the file ends inside the DOS header"
    lfanew, = struct.unpack_from("<I", head, 0x3C)
    if lfanew < 0x40:
        return IMPLAUSIBLE, None, "e_lfanew is %d" % lfanew
    if lfanew + 4 > len(head):
        if len(head) < HEAD:
            return TRUNCATED, None, "e_lfanew is %d and the file ends before it" % lfanew
        return UNKNOWN, None, "e_lfanew is %d, beyond the %d bytes examined" % (lfanew, HEAD)
    if head[lfanew:lfanew + 4] == b"PE\x00\x00":
        return PLAUSIBLE, None, "PE signature at +0x%x" % lfanew
    return IMPLAUSIBLE, None, "no PE signature at e_lfanew (+0x%x)" % lfanew


def check_sqlite(head):
    # The 100-byte header: page size at 16 (2 bytes; 1 means 65536), write and read
    # format versions at 18 and 19, file change counter at 24, size in pages at 28,
    # version-valid-for number at 92 (the size in pages can be trusted only when it
    # equals the change counter).
    if len(head) < 100:
        return TRUNCATED, None, "the file ends inside the 100-byte header"
    page, = struct.unpack_from(">H", head, 16)
    page = 65536 if page == 1 else page
    write, read = head[18], head[19]
    if page not in PAGE_SIZES or write not in (1, 2) or read not in (1, 2):
        return IMPLAUSIBLE, None, "page size %d, format versions %d and %d" % (page, write, read)
    counter, pages = struct.unpack_from(">II", head, 24)
    valid_for, = struct.unpack_from(">I", head, 92)
    if pages and counter == valid_for:
        return PLAUSIBLE, pages * page, "%d pages of %d bytes" % (pages, page)
    return PLAUSIBLE, None, "page size %d; the size in pages is not valid for this change counter" % page


def check_mft(head):
    # FILE record: update sequence count at 6 (3 for a 1024-byte record), allocated size at 0x1C.
    if len(head) < 0x20:
        return TRUNCATED, None, "the file ends inside the record header"
    count, = struct.unpack_from("<H", head, 6)
    allocated, = struct.unpack_from("<I", head, 0x1C)
    if count == 3 and allocated == 1024:
        return PLAUSIBLE, 1024, "a 1024-byte record"
    return IMPLAUSIBLE, None, "update sequence count %d, allocated size %d" % (count, allocated)


def check_indx(head):
    # INDX block: the update sequence count at 6 is 1 plus the block size over 512.
    if len(head) < 8:
        return TRUNCATED, None, "the file ends inside the block header"
    count, = struct.unpack_from("<H", head, 6)
    if count - 1 in (2, 8, 16):
        return PLAUSIBLE, (count - 1) * 512, "update sequence count %d" % count
    return IMPLAUSIBLE, None, "update sequence count %d" % count


def check_pdf(head):
    if len(head) < 8:
        return TRUNCATED, None, "the file ends inside the version marker"
    if re.match(rb"%PDF-\d\.\d", head[:8]):
        return PLAUSIBLE, None, "version marker %s" % head[5:8].decode("ascii")
    return IMPLAUSIBLE, None, "no version marker after %PDF-"


def no_check(_head):
    return UNKNOWN, None, "a signature only: no structural check exists for this kind"


VALIDATORS = {
    "registry hive": check_regf,
    "event log chunk": check_evtx_chunk,
    "event log file": check_evtx_file,
    "compressed prefetch record": check_mam,
    "prefetch record": check_scca,
    "PE header": check_pe,
    "SQLite database": check_sqlite,
    "MFT record": check_mft,
    "NTFS index block": check_indx,
    "PDF": check_pdf,
}


def main():
    try:
        args = json.load(sys.stdin)
    except ValueError as exc:
        fail("arguments are not valid JSON", reason=str(exc))
    if not isinstance(args, dict):
        fail("arguments must be a JSON object")
    path = args.get("path")
    if not isinstance(path, str) or not path:
        fail("path is required: a memory image, page file or blob")
    if not os.path.isfile(path):
        fail("no such file", path=path)
    limit = args.get("limit")
    if limit is not None and (not isinstance(limit, int) or isinstance(limit, bool) or limit < 1):
        fail("limit must be a positive integer or null")
    preview = limit if limit is not None else DEFAULT_PREVIEW
    max_extract = args.get("max_extract", 25)
    if not isinstance(max_extract, int) or isinstance(max_extract, bool) or max_extract < 0:
        fail("max_extract must be a non-negative integer")
    wanted = {str(k) for k in (args.get("kinds") or [])}
    known = {name for _sig, name, _size in SIGNATURES}
    unknown = wanted - known
    if unknown:
        fail("no signature by that name", unknown=sorted(unknown), kinds=sorted(known))
    signatures = [(s, n, z) for s, n, z in SIGNATURES if not wanted or n in wanted]

    size = os.path.getsize(path)
    start = args.get("start", 0) or 0
    if not isinstance(start, int) or isinstance(start, bool) or start < 0 or start > size:
        fail("start must be a byte offset inside the file")
    max_bytes = args.get("max_bytes")
    if max_bytes is not None and (not isinstance(max_bytes, int) or isinstance(max_bytes, bool) or max_bytes < 1):
        fail("max_bytes must be a positive integer")
    end = min(size, start + max_bytes) if max_bytes is not None else size
    extract_to = args.get("extract_to")
    if extract_to:
        extract_to = resolve_output(extract_to)
        extract_to.mkdir(parents=True, exist_ok=True)

    results_to = args.get("results_to")
    if results_to:
        results_to = resolve_output(results_to)
        source = Path(path).resolve()
        if results_to == source or (results_to.exists() and os.path.samefile(results_to, source)):
            fail("results_to cannot name the source being scanned", output=str(results_to),
                 path=path)
        results_to.parent.mkdir(parents=True, exist_ok=True)

    overlap = max(len(s) for s, _n, _z in signatures) - 1
    preview_hits, hit_count, counts, validations = [], 0, {}, {}
    extraction = {"max_extract": max_extract, "extracted": 0, "not_extracted": 0, "refused": 0, "failed": 0}
    manifest = ExtractManifest(extract_to) if extract_to else None
    problems, problem_count = [], 0
    bytes_read, ended = 0, "end of range"

    # Where every hit goes. An explicit results_to holds all of them; without one, a
    # page of `preview` hits is returned and, past it, the whole result is written to
    # a file the answer names. Either way no hit list is held in memory.
    results, temporary_results, page = None, None, None
    if results_to:
        fd, temporary_results = tempfile.mkstemp(
            dir=results_to.parent, prefix=".%s." % results_to.name, suffix=".partial")
        results = os.fdopen(fd, "w", encoding="utf-8")
    else:
        page = LosslessPage("mem_carve", [str(Path(path).resolve()), start, end, sorted(wanted)], preview)

    def note_problem(offset, kind, text):
        nonlocal problem_count
        problem_count += 1
        if len(problems) < MAX_PROBLEMS:
            problems.append({"offset": offset, "kind": kind, "problem": text})

    finished = False
    try:
        with open(path, "rb") as fh, open(path, "rb") as side:
            def read_at(offset, n):
                side.seek(offset)
                return side.read(n)

            def peek(offset, n, buf, base):
                """n bytes of the file at offset: from the sweep's buffer when it holds them, else from the file."""
                lo = offset - base
                if 0 <= lo and lo + n <= len(buf):
                    return buf[lo:lo + n]
                return read_at(offset, n)

            position, tail, tail_at, accept_lo = start, b"", start, start
            while position < end:
                fh.seek(position)
                block = fh.read(min(WINDOW, end - position))
                if not block:
                    ended = ("early end of file: a read at offset %d returned no bytes, %d bytes before the end of the range"
                             % (position, end - position))
                    break
                bytes_read += len(block)
                buf, base = tail + block, tail_at
                block_end = position + len(block)
                # A signature that starts before accept_hi lies wholly inside buf; one that
                # starts later may be cut by the end of the block, and is found in the next
                # buffer, which begins at accept_hi. Every hit is found once, in offset order.
                accept_hi = end if block_end >= end else max(accept_lo, block_end - overlap)
                found_here = []
                for index, (signature, _name, _cut) in enumerate(signatures):
                    at = max(0, accept_lo - base)
                    while True:
                        found = buf.find(signature, at)
                        if found < 0:
                            break
                        at = found + 1
                        absolute = base + found
                        if absolute >= accept_hi:
                            break
                        found_here.append((absolute, index))
                found_here.sort()
                for absolute, index in found_here:
                    _signature, name, cut = signatures[index]
                    object_offset = absolute
                    if name == "prefetch record":
                        # A plain Prefetch record starts with its version, four bytes before
                        # "SCCA". The start is claimed only when those four bytes are a version
                        # the format has.
                        object_offset = None
                        if absolute >= 4:
                            version, = struct.unpack("<I", peek(absolute - 4, 4, buf, base))
                            if version in PREFETCH_VERSIONS:
                                object_offset = absolute - 4
                    cut_from = object_offset if object_offset is not None else absolute
                    if name == "prefetch record" and object_offset is None:
                        state, declared, detail = UNKNOWN, None, (
                            "the four bytes before SCCA are not a known Prefetch version, so where the structure starts is not established")
                    else:
                        state, declared, detail = VALIDATORS.get(name, no_check)(peek(cut_from, HEAD, buf, base))
                    available = max(0, min(cut, size - cut_from))
                    if state == PLAUSIBLE and declared is not None and declared > available:
                        state = TRUNCATED
                        detail += "; the header declares %d bytes and %d are available from the cut" % (declared, available)
                    elif state == PLAUSIBLE and declared is not None and declared > cut:
                        detail += "; the header declares %d bytes and this kind is cut at %d" % (declared, cut)
                    entry = {"kind": name, "signature_offset": absolute, "object_offset": object_offset,
                             "page_aligned": cut_from % 4096 == 0, "validation": state, "validation_detail": detail}
                    if declared is not None:
                        entry["declared_bytes"] = declared
                    entry["requested_bytes"] = cut
                    entry["available_bytes"] = available
                    if extract_to:
                        if extraction["extracted"] < max_extract:
                            safe = "%012x-%s.bin" % (cut_from, name.replace(" ", "_"))
                            target = extract_to / safe
                            try:
                                # Exclusive, and never through a link: a name that already exists
                                # (a file, or a link anywhere) is refused, not written over.
                                out_fd = os.open(str(target), os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o600)
                            except FileExistsError:
                                entry["extract_status"] = "refused: %s already exists in the extract directory (a file or a link); use an empty directory" % safe
                                extraction["refused"] += 1
                                note_problem(absolute, name, entry["extract_status"])
                            except OSError as exc:
                                entry["extract_status"] = "failed: %s" % (errno.errorcode.get(exc.errno, "") or exc)
                                extraction["failed"] += 1
                                note_problem(absolute, name, entry["extract_status"])
                            else:
                                with os.fdopen(out_fd, "wb") as out:
                                    piece = read_at(cut_from, available) if available else b""
                                    out.write(piece)
                                entry["extracted_to"] = str(target)
                                entry["extracted_bytes"] = len(piece)
                                manifest.add({"row": "extract", "kind": name, "signature_offset": absolute,
                                              "object_offset": object_offset, "file": safe, "bytes": len(piece),
                                              "sha256": hashlib.sha256(piece).hexdigest()})
                                extraction["extracted"] += 1
                        else:
                            extraction["not_extracted"] += 1
                    hit_count += 1
                    counts[name] = counts.get(name, 0) + 1
                    validations[state] = validations.get(state, 0) + 1
                    if results:
                        results.write(json.dumps(entry, separators=(",", ":")) + "\n")
                        if len(preview_hits) < preview:
                            preview_hits.append(entry)
                    else:
                        page.add(entry)
                accept_lo = accept_hi
                keep = accept_hi - base
                tail, tail_at = buf[keep:], base + keep
                position = block_end
        if results:
            results.flush()
            os.fsync(results.fileno())
            results.close()
            results = None
            os.replace(temporary_results, results_to)
            temporary_results = None
        finished = True
    finally:
        if results:
            results.close()
        if temporary_results:
            try:
                os.unlink(temporary_results)
            except FileNotFoundError:
                pass
        if page is not None and not finished:
            page.abort()

    if page is not None:
        paged = page.finish()
        preview_hits = page.page
    else:
        paged = {}

    result = {
        "path": path,
        "parser": PARSER,
        "bytes_swept": max(0, end - start),
        "coverage": {
            "start": start,
            "end": end,
            "file_bytes": size,
            "bytes_read": bytes_read,
            "ended": ended,
            "signatures": [name for _s, name, _z in signatures],
            "address_space": "byte offsets in the file named by path; they are guest physical addresses only "
                             "if that file is a flat physical-memory image, and never virtual addresses",
            "contiguity": "not determined: a slice is the file's own bytes, and the pages of one structure "
                          "need not be adjacent in a physical image",
        },
        "hits": preview_hits,
        "hit_count": hit_count,
        "by_kind": counts,
        "validation_counts": validations,
        "extracted": extraction["extracted"],
        "preview_limited": hit_count > len(preview_hits),
        "truncated": hit_count > len(preview_hits),
        "problems": problems,
        "problem_count": problem_count,
        "note": "A hit is a signature at an offset, not a recovered file. signature_offset is where the "
                "signature bytes are; object_offset is where the structure starts (a plain Prefetch record "
                "starts four bytes before SCCA; null when not established). validation says what the header's "
                "own fields support: 'unknown' means a signature only, and 'header plausible' is not a whole, "
                "readable structure. The cut is a fixed-size slice of the file from the structure's start, so "
                "it can run into unrelated pages or end mid-structure (declared_bytes is the header's own "
                "length where it declares one). Hand each extract to the tool that reads that format when the "
                "pack that carries it is loaded, and keep the offsets in the report beside what it says. An "
                "extract can hold credential material (a SAM or SECURITY hive, a browser database): cite it "
                "by job or path, never by content. The extracts are private (0600), and their sizes and sha256 are in the "
                "extract manifest the answer names (extraction.manifest), not in this answer.",
    }
    if results_to and manifest is not None:
        # The digest of the whole hit list goes where the extracts' digests go, not into the answer.
        digest = hashlib.sha256()
        with open(results_to, "rb") as complete:
            for block in iter(lambda: complete.read(1 << 20), b""):
                digest.update(block)
        manifest.add({"row": "results", "file": str(results_to), "hits": hit_count, "sha256": digest.hexdigest()})
    if manifest is not None:
        manifest.close()
        extraction["manifest"] = str(manifest.path) if manifest.path else None
        result["extraction"] = extraction
    if results_to:
        result["complete_results"] = str(results_to)
        result["complete_results_format"] = "JSON Lines, one complete hit per line, in offset order"
    elif paged.get("all_results"):
        result["complete_results"] = paged["all_results"]
        result["complete_results_format"] = paged["all_results_format"]
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    try:
        main()
    except SystemExit:
        raise
    except Exception as exc:  # never an empty or clean answer for a failure
        fail("unexpected failure: %s: %s" % (type(exc).__name__, exc))
