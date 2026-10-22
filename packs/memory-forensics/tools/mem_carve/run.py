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
                       file itself ends before the header can be read, or before the
                       length the header declares) or "unknown" (no structural
                       check exists for the kind: a signature only)

The offsets are the whole provenance, since a structure carved from memory has no
path and no file name, so they belong in the report beside whatever a downstream
parser says. A cut is made at `object_offset` when it is known and at
`signature_offset` otherwise. Its length is the kind's fixed size, or, where the
header declares a length longer than that and the kind has a cap, the declared length
up to the cap: `declared_bytes` is the length the header declares, `requested_bytes`
what is cut, and `cut_complete` says whether the cut holds the declared length
(null when the header declares none). A cut shorter than the declared length is a
statement about the cut, never `truncated`, which is only the file ending first.
Hits are found and numbered in offset order, so `max_extract` takes the earliest
candidates and the answer says how many it did not extract.

THE TOOL'S OWN CLOCK. A sweep stops by itself at `max_seconds` (default 600, at most
780, inside the manifest's 900) or when the hit list and the slices cut out have reached
`max_results_bytes`, and says so: status "partial", and `coverage.resume_start`, the
offset to give as `start` for the rest. Every hit whose signature lies before that offset
is in the answer and in the hit list; nothing after it was looked at, nothing is lost.
The clock is looked at before every slice that is cut out (a slice is up to 64 MiB), at
every 4,096th hit otherwise, and inside the search of a window. Every call makes progress:
the first window is always searched whole and the first hit always reported, so a call
that is given so little time that it cannot finish even that runs past `max_seconds` by
that one window of work and still moves `resume_start` forward; a resume loop ends.

MEMORY CONTENT. A slice is memory content: it can be a credential store (a SAM, SYSTEM
or SECURITY hive, a browser database) or run into the pages next to one. The hit list
(offsets, kinds, validation) is always available; cutting slices out (`extract_to`)
needs `write_values: true`, a job, and a job run as secret output (SECRET_OUTPUT=1,
which the tool's manifest makes the harness set). Credential hives are extracted
deliberately: a cracking tool downstream is a legitimate next step and stays
available; the slices are written into a directory with mode 0700, as files with mode
0600, and the answer names them and never prints their content or a digest of it.
"""
import errno
import hashlib
import json
import os
import re
import signal
import struct
import sys
import tempfile
import time
from pathlib import Path

PARSER = "mem_carve/5"
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
# Where a header declares a length longer than the kind's fixed cut, the cut grows to the declared length up to this cap.
DECLARED_CAPS = {
    "prefetch record": 16 << 20,
    "event log file": 64 << 20,
    "SQLite database": 64 << 20,
    "NTFS index block": 65536,
    "event log chunk": 65536,
}
WINDOW = 1 << 22
DEFAULT_PREVIEW = 200
MAX_PREVIEW = 5000
# How much of a structure's start a validator may look at.
HEAD = 4096
# The versions a plain Prefetch record carries in its first four bytes (libscca's
# format notes): 17 Windows XP and 2003, 23 Vista and 7, 26 8 and 8.1, 30 10, 31 11.
PREFETCH_VERSIONS = (17, 23, 26, 30, 31)
MAX_PROBLEMS = 20
# The clock and the size of the hit list. 780 + the end of a sweep (closing, placing, the answer) stays inside the manifest's 900.
MAX_SECONDS_DEFAULT, MAX_SECONDS_CAP = 600, 780
MAX_RESULT_BYTES_DEFAULT, MAX_RESULT_BYTES_CAP, MAX_RESULT_BYTES_FLOOR = 1 << 30, 16 << 30, 1 << 20
CHECK_EVERY = 4096          # hits between two looks at the clock (a hit with a slice cut out is looked at every time)
MAX_EXTRACT_CAP = 1000      # slices one call may cut: each is up to 64 MiB, and a larger number is a second call from resume_start
FIND_CHECK_EVERY = 1 << 16  # finds between two looks at the clock inside one window


# BEGIN SHARED PAGE
# The same text is in mem_carve, mem_fs and mem_profile (tests/pack-memory-shared.test.ts holds the copies equal).
# LosslessPage keeps the page an agent reads small and, when there are more rows, writes the whole result as JSON Lines
# under work/<agent>/tool-output (in a job, $OUT/tool-output) and names it. A row is serialised with the default ASCII
# escapes, so a name that is not valid UTF-8 (a lone surrogate) is written as a \udcXX escape and cannot break the writer.
# The finished file is placed without replacing an earlier one (a rerun that stopped sooner never leaves a smaller file
# where a larger one was; the name actually used is the one in `shown`), and a stop removes or names the temporary file.
def same_bytes(a, b):
    """Whether two files hold the same bytes (read in blocks, never whole)."""
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


def place_without_replacing(tmp, path):
    """Move the finished `tmp` to `path` and never replace what is there, a file or a link: the name is taken first with an
    exclusive create that does not follow links; a file of the same bytes is named again, any other result takes the next free
    <stem>-<n><suffix>. Returns the path that holds it."""
    for n in range(1, 1000):
        candidate = path if n == 1 else path.with_name("%s-%d%s" % (path.stem, n, path.suffix))
        try:
            fd = os.open(str(candidate), os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o600)
        except FileExistsError:
            if not os.path.islink(candidate) and same_bytes(tmp, candidate):
                os.unlink(tmp)
                return candidate
            continue
        os.close(fd)
        os.replace(tmp, candidate)             # only replaces the empty file this call just made
        return candidate
    raise OSError(errno.EEXIST, "no free name beside %s" % path)


PAGES = []


class LosslessPage:
    def __init__(self, tool: str, key: object, limit: int):
        if isinstance(limit, bool) or not isinstance(limit, int) or limit < 1:
            raise ValueError("limit must be a positive integer")
        self.tool = re.sub(r"[^A-Za-z0-9_.-]", "_", tool)
        self.limit = limit
        self.page: list[object] = []
        self.total = 0
        self.bytes = 0                          # what the whole result takes as JSON Lines, kept in memory or not
        self._out = None
        self._tmp: Path | None = None
        digest = hashlib.sha256(
            json.dumps(key, sort_keys=True, default=str).encode("utf-8", "surrogatepass")
        ).hexdigest()[:16]
        name = f"{self.tool}-{digest}.jsonl"
        job, out = os.environ.get("JOB_ID"), os.environ.get("OUT")
        if job and out:
            # In a job only $OUT is written, and it is sealed as the job's output: the whole result is cited from there.
            self.path = Path(out) / "tool-output" / name
            self.shown = "store/jobs/%s/out/tool-output/%s" % (re.sub(r"[^A-Za-z0-9_.-]", "_", job), name)
        else:
            agent = re.sub(r"[^A-Za-z0-9_.-]", "_", os.environ.get("AGENT_ID") or "tool")
            self.path = Path("work") / agent / "tool-output" / name
            self.shown = str(self.path)
        PAGES.append(self)

    def _write(self, line: str) -> None:
        assert self._out is not None
        self._out.write(line)
        self._out.write("\n")

    def add(self, row: object, line: str | None = None) -> None:
        self.total += 1
        if line is None:
            line = json.dumps(row, default=str)
        self.bytes += len(line) + 1
        if len(self.page) < self.limit:
            self.page.append(row)
            return
        if self._out is None:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            fd, name = tempfile.mkstemp(dir=self.path.parent, prefix=f".{self.path.name}-")
            self._tmp = Path(name)
            self._out = os.fdopen(fd, "w", encoding="ascii")
            for kept in self.page:
                self._write(json.dumps(kept, default=str))
        self._write(line)

    def finish(self) -> dict:
        result = {"matched": self.total, "returned": len(self.page), "truncated": self.total > len(self.page)}
        if self._out is not None:
            self._out.flush()
            os.fsync(self._out.fileno())
            self._out.close()
            self._out = None
            assert self._tmp is not None
            placed = place_without_replacing(self._tmp, self.path)
            self._tmp = None
            self.path = placed
            self.shown = self.shown[: len(self.shown) - len(self.shown.rsplit("/", 1)[-1])] + placed.name
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
            self._tmp = None

    def keep_partial(self):
        """Close the temporary file and give it a visible name ending in .partial (never replacing a file); returns the
        path, or None when nothing was being written. Whole lines only are in it when the rows were added whole."""
        if self._out is None or self._tmp is None:
            return None
        try:
            self._out.flush()
            self._out.close()
        except OSError:
            pass
        self._out = None
        placed = place_without_replacing(self._tmp, self.path.with_name(self.path.name + ".partial"))
        self._tmp = None
        return placed
# END SHARED PAGE


def make_private_dirs(path):
    """mkdir -p where every directory it creates has mode 0700 (Path.mkdir(parents=True, mode=...) gives the parents the default mode,
    so the names of what is below them would be listed by anyone)."""
    missing, here = [], Path(path)
    while not os.path.lexists(here):
        missing.append(here)
        if here.parent == here:
            break
        here = here.parent
    for directory in reversed(missing):
        try:
            os.mkdir(str(directory), 0o700)
        except FileExistsError:
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
                self._fh = os.fdopen(fd, "w", encoding="ascii")
                break
            else:
                raise OSError(errno.EEXIST, "no free extract-manifest name in the extract directory")
        self._fh.write(json.dumps(row) + "\n")
        self._fh.flush()

    def close(self):
        if self._fh is not None:
            self._fh.flush()
            os.fsync(self._fh.fileno())
            self._fh.close()
            self._fh = None


# --- stopping: a signal ends the tool with one JSON answer ------------------------------

class Terminated(BaseException):
    """Raised by the signal handler. A BaseException, so no `except Exception` swallows it and every `finally` runs."""

    def __init__(self, signum):
        super().__init__(signum)
        self.signum = signum


GUARD = {"depth": 0, "pending": None, "stopping": False}
STATE = {"partial": None, "resume_start": None, "extract_manifest": None, "hits_so_far": 0, "extracted": 0}


def _on_signal(signum, _frame):
    if GUARD["stopping"]:
        return
    if GUARD["depth"]:
        GUARD["pending"] = signum            # inside one hit's bookkeeping: finished first, so no half row, no extract without its row
        return
    GUARD["stopping"] = True
    raise Terminated(signum)


def checkpoint():
    signum = GUARD["pending"]
    if signum is not None and not GUARD["depth"]:
        GUARD["pending"] = None
        GUARD["stopping"] = True
        raise Terminated(signum)


def interrupted_answer(signum, **extra):
    print(json.dumps({
        "error": "stopped by signal %d before the sweep was complete" % signum,
        "status": "interrupted",
        "status_basis": "the tool was stopped by signal %d; the hits written so far are named in partial_results and every "
                        "hit with a signature offset before resume_start is in them" % signum,
        "signal": signum, "parser": PARSER, **extra}), flush=True)


def fail(message, **extra):
    print(json.dumps({"error": message, "status": "failed",
                      "status_basis": "the call was refused or ended before an answer; nothing in this document is a finding",
                      **extra}))
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
    return IMPLAUSIBLE, None, "update sequence count %d, allocated size %d: not the header of a 1024-byte record" % (count, allocated)


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


def whole_number(args, key, default, low, high):
    value = args.get(key, default)
    if value is None:
        value = default
    if not isinstance(value, int) or isinstance(value, bool) or not low <= value <= high:
        fail("%s must be an integer from %d to %d" % (key, low, high), **{key: value if isinstance(value, (int, str)) else None})
    return value


def main():
    started = time.monotonic()
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
    limit_clamped = None
    if preview > MAX_PREVIEW:
        limit_clamped, preview = limit, MAX_PREVIEW
    max_extract = args.get("max_extract", 25)
    if not isinstance(max_extract, int) or isinstance(max_extract, bool) or not 0 <= max_extract <= MAX_EXTRACT_CAP:
        fail("max_extract must be an integer from 0 to %d: each slice is up to 64 MiB, so a call cuts at most %d; cut more with another "
             "call whose start is coverage.resume_start or the offset after the last slice" % (MAX_EXTRACT_CAP, MAX_EXTRACT_CAP),
             max_extract=max_extract if isinstance(max_extract, (int, str)) else None)
    kinds = args.get("kinds")
    if kinds is not None and (not isinstance(kinds, list) or not all(isinstance(k, str) for k in kinds)):
        fail("kinds must be a list of signature names (strings)")
    wanted = set(kinds or [])
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
    max_seconds = whole_number(args, "max_seconds", MAX_SECONDS_DEFAULT, 1, MAX_SECONDS_CAP)
    max_result_bytes = whole_number(args, "max_results_bytes", MAX_RESULT_BYTES_DEFAULT, MAX_RESULT_BYTES_FLOOR, MAX_RESULT_BYTES_CAP)
    write_values = args.get("write_values", False)
    if write_values is None:
        write_values = False
    if not isinstance(write_values, bool):
        fail("write_values must be true or false")
    for name in ("extract_to", "results_to"):
        if args.get(name) is not None and not isinstance(args.get(name), str):
            fail("%s must be a path (a string)" % name)
    end = min(size, start + max_bytes) if max_bytes is not None else size
    deadline = started + max_seconds

    # Cutting slices out writes memory content: decided before anything is opened or created.
    extract_to = args.get("extract_to") or None
    if extract_to:
        if not write_values:
            fail("extract_to cuts memory content out of the image (a slice can be a credential hive or a browser database): "
                 "ask for it with write_values: true, in a job run as secret output. Nothing was written and the image was "
                 "not read. The hit list (offsets, kinds, validation) needs neither.", extract_to="refused", written=False)
        job, out = os.environ.get("JOB_ID") or "", os.environ.get("OUT") or ""
        if not (job and out):
            fail("extract_to is refused outside a job: a slice written here would be an ordinary file, not a sealed secret "
                 "output. Run this as job_run tool=mem_carve (its manifest makes the job secret output) and ask again there. "
                 "Nothing was written and the image was not read.", extract_to="refused", written=False)
        if os.environ.get("SECRET_OUTPUT") != "1":
            fail("extract_to is refused in a job that was not run as secret output: its slices would be sealed as ordinary "
                 "output. Run this as job_run tool=mem_carve (its manifest makes the job secret output). Nothing was written "
                 "and the image was not read.", extract_to="refused", written=False)
        extract_to = resolve_output(extract_to)
        if Path(out).resolve() not in extract_to.parents and extract_to != Path(out).resolve():
            fail("extract_to must be a directory under $OUT in a job", extract_to=str(args.get("extract_to")))
        make_private_dirs(extract_to)
        try:
            os.chmod(extract_to, 0o700)
        except OSError:
            pass

    results_to = args.get("results_to") or None
    requested_results = None
    if results_to:
        requested_results = results_to
        link = Path(results_to) if Path(results_to).is_absolute() else Path.cwd() / results_to
        if os.path.islink(link):
            fail("results_to is a symbolic link: it is not written through or replaced; name a file", output=str(results_to))
        results_to = resolve_output(results_to)
        source = Path(path).resolve()
        if results_to == source or (results_to.exists() and os.path.samefile(results_to, source)):
            fail("results_to cannot name the source being scanned", output=str(results_to),
                 path=path)
        if results_to.is_dir():
            fail("results_to names a directory", output=str(results_to))
        results_to.parent.mkdir(parents=True, exist_ok=True)

    overlap = max(len(s) for s, _n, _z in signatures) - 1
    preview_hits, hit_count, counts, validations = [], 0, {}, {}
    extraction = {"max_extract": max_extract, "extracted": 0, "not_extracted": 0, "refused": 0, "failed": 0}
    manifest = ExtractManifest(extract_to) if extract_to else None
    problems, problem_count = [], 0
    bytes_read, ended = 0, "end of range"
    stop = None                      # why the sweep ended before the end of its range, when it did
    resume_at = None                 # the offset to give as `start` for the rest
    result_bytes = 0
    extract_bytes = 0                # what the slices cut out so far take: counted with the hit list toward max_results_bytes
    results_digest = hashlib.sha256()

    # Where every hit goes. An explicit results_to holds all of them; without one, a
    # page of `preview` hits is returned and, past it, the whole result is written to
    # a file the answer names. Either way no hit list is held in memory.
    results, temporary_results, page = None, None, None
    if results_to:
        fd, temporary_results = tempfile.mkstemp(
            dir=results_to.parent, prefix=".%s." % results_to.name, suffix=".partial")
        results = os.fdopen(fd, "w", encoding="ascii")
        STATE["partial"] = temporary_results
    else:
        page = LosslessPage("mem_carve", [str(Path(path).resolve()), start, end, sorted(wanted)], preview)

    def note_problem(offset, kind, text):
        nonlocal problem_count
        problem_count += 1
        if len(problems) < MAX_PROBLEMS:
            problems.append({"offset": offset, "kind": kind, "problem": text})

    def limit_reached():
        """Why the sweep must stop now, or None."""
        if time.monotonic() >= deadline:
            return "time limit: max_seconds %d was reached" % max_seconds
        if result_bytes + extract_bytes >= max_result_bytes:
            return ("result size limit: the hit list and the slices cut out reached max_results_bytes %d (%d bytes of hit list, %d of slices)"
                    % (max_result_bytes, result_bytes, extract_bytes))
        return None

    finished = False
    interrupted = None
    sweep_end = end                  # where the sweep really ends: the end of the range, or where the file ended first
    accept_lo = start
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
            while position < sweep_end and stop is None:
                # The first window of a call is never given up: a call always moves resume_start forward.
                if position > start and time.monotonic() >= deadline:
                    stop, resume_at = "time limit: max_seconds %d was reached" % max_seconds, accept_lo
                    break
                fh.seek(position)
                block = fh.read(min(WINDOW, sweep_end - position))
                if not block:
                    ended = ("early end of file: a read at offset %d returned no bytes, %d bytes before the end of the range"
                             % (position, sweep_end - position))
                    # What was read is all there is: the signatures in its last bytes (held back for the next window) are reported now.
                    sweep_end = position
                bytes_read += len(block)
                buf, base = tail + block, tail_at
                block_end = position + len(block)
                # A signature that starts before accept_hi lies wholly inside buf; one that
                # starts later may be cut by the end of the block, and is found in the next
                # buffer, which begins at accept_hi. Every hit is found once, in offset order.
                accept_hi = sweep_end if block_end >= sweep_end else max(accept_lo, block_end - overlap)
                found_here = []
                finds = 0
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
                        finds += 1
                        if finds % FIND_CHECK_EVERY == 0 and position > start and time.monotonic() >= deadline:
                            stop, resume_at = "time limit: max_seconds %d was reached" % max_seconds, accept_lo
                            break
                    if stop:
                        break
                if stop:
                    break                # nothing of this window was reported: the rest starts at its first byte
                found_here.sort()
                for absolute, index in found_here:
                    # Looked at every 4,096th hit, and before every hit that may cut a slice (up to 64 MiB). The first hit of a call is always reported.
                    cutting = bool(extract_to) and extraction["extracted"] + extraction["refused"] + extraction["failed"] < max_extract
                    if ((hit_count % CHECK_EVERY) == 0 or cutting) and (hit_count > 0 or accept_lo > start):
                        why = limit_reached()
                        if why:
                            stop, resume_at = why, absolute
                            break
                    GUARD["depth"] += 1
                    try:
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
                        file_left = max(0, size - cut_from)
                        # Where the header declares more than the kind's fixed cut, the cut grows to the declared length, up to the kind's cap.
                        wants = cut
                        if state == PLAUSIBLE and declared is not None and declared > cut and name in DECLARED_CAPS:
                            wants = min(declared, DECLARED_CAPS[name])
                        available = min(wants, file_left)
                        cut_complete = None
                        if state == PLAUSIBLE and declared is not None:
                            if declared > file_left:
                                # Only the file ending first is "truncated".
                                state = TRUNCATED
                                detail += "; the file ends %d bytes after the structure's start, before the %d bytes the header declares" % (file_left, declared)
                                cut_complete = False
                            elif declared > available:
                                cut_complete = False
                                detail += "; the header declares %d bytes and the cut keeps the first %d (the image holds the rest)" % (declared, available)
                            else:
                                cut_complete = True
                        entry = {"kind": name, "signature_offset": absolute, "object_offset": object_offset,
                                 "page_aligned": cut_from % 4096 == 0, "validation": state, "validation_detail": detail}
                        if declared is not None:
                            entry["declared_bytes"] = declared
                        entry["requested_bytes"] = wants
                        entry["available_bytes"] = available
                        entry["cut_complete"] = cut_complete
                        if extract_to:
                            if extraction["extracted"] + extraction["refused"] + extraction["failed"] < max_extract:
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
                                    extract_bytes += len(piece)
                                    manifest.add({"row": "extract", "kind": name, "signature_offset": absolute,
                                                  "object_offset": object_offset, "file": safe, "bytes": len(piece),
                                                  "sha256": hashlib.sha256(piece).hexdigest()})
                                    extraction["extracted"] += 1
                                    STATE["extracted"] = extraction["extracted"]
                            else:
                                extraction["not_extracted"] += 1
                        hit_count += 1
                        counts[name] = counts.get(name, 0) + 1
                        validations[state] = validations.get(state, 0) + 1
                        line = json.dumps(entry, separators=(",", ":"))
                        result_bytes += len(line) + 1
                        if results:
                            results.write(line + "\n")
                            results_digest.update(line.encode("ascii") + b"\n")
                            if len(preview_hits) < preview:
                                preview_hits.append(entry)
                        else:
                            page.add(entry, line)
                        STATE["resume_start"] = absolute + 1
                        STATE["hits_so_far"] = hit_count
                    finally:
                        GUARD["depth"] -= 1
                    checkpoint()
                if stop:
                    break
                accept_lo = accept_hi
                keep = accept_hi - base
                tail, tail_at = buf[keep:], base + keep
                position = block_end
                STATE["resume_start"] = accept_lo
                checkpoint()
        if stop:
            ended = stop
        if results:
            results.flush()
            os.fsync(results.fileno())
            results.close()
            results = None
            placed = place_without_replacing(Path(temporary_results), results_to)
            temporary_results = None
            STATE["partial"] = None
            results_to = placed
        finished = True
    except Terminated as stopped:
        interrupted = stopped.signum
    finally:
        if results:
            try:
                results.close()
            except OSError:
                pass
        if interrupted is None:
            if temporary_results:
                try:
                    os.unlink(temporary_results)
                except FileNotFoundError:
                    pass
            if page is not None and not finished:
                page.abort()

    if interrupted is not None:
        # The hits found so far are kept and named; every hit before resume_start is in them.
        named = None
        if temporary_results:
            try:
                named = place_without_replacing(Path(temporary_results), results_to.with_name(results_to.name + ".partial"))
            except OSError:
                named = Path(temporary_results)
        elif page is not None:
            try:
                kept = page.keep_partial()
            except OSError:
                kept = None
            named = kept
        if manifest is not None:
            manifest.close()
        resume = STATE["resume_start"] if STATE["resume_start"] is not None else start
        extra = {"partial_results": str(named) if named else None,
                 "partial_results_note": "JSON Lines, one hit per line, in offset order; every hit whose signature offset is below resume_start is in "
                                         "it or in hits (the first rows, kept in memory until the file was started)",
                 "resume_start": resume, "hit_count_so_far": hit_count, "extracted_so_far": extraction["extracted"],
                 "extract_manifest": str(manifest.path) if manifest is not None and manifest.path else None}
        if page is not None and not named:
            extra["hits"] = page.page
        interrupted_answer(interrupted, **extra)
        raise SystemExit(128 + interrupted)

    if page is not None:
        paged = page.finish()
        preview_hits = page.page
    else:
        paged = {}

    covered_to = resume_at if resume_at is not None else sweep_end
    partial_reasons = []
    if stop:
        partial_reasons.append(stop)
    if ended.startswith("early end of file"):
        partial_reasons.append(ended)
    if extraction["refused"] or extraction["failed"]:
        partial_reasons.append("%d slice(s) were refused or failed (extraction, and each hit's extract_status)" % (extraction["refused"] + extraction["failed"]))
    if partial_reasons:
        status = "partial"
        status_basis = "; ".join(partial_reasons) + ("; every hit with a signature offset before resume_start is reported" if stop else "")
    else:
        status = "complete"
        status_basis = ("every byte of the range %d to %d was swept for the named signatures and every hit is reported%s"
                        % (start, end, "" if not extraction["not_extracted"] else
                           "; %d hit(s) were not cut out because max_extract is %d" % (extraction["not_extracted"], max_extract)))

    result = {
        "path": path,
        "parser": PARSER,
        "status": status,
        "status_basis": status_basis,
        "bytes_swept": max(0, covered_to - start),
        "coverage": {
            "start": start,
            "end": end,
            "file_bytes": size,
            "bytes_read": bytes_read,
            "ended": ended,
            "seconds": round(time.monotonic() - started, 2),
            "max_seconds": max_seconds,
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
        "problems_note": "problems lists the first %d; every hit, with its extract_status, is in the hit list file" % MAX_PROBLEMS,
        "note": "A hit is a signature at an offset, not a recovered file. signature_offset is where the "
                "signature bytes are; object_offset is where the structure starts (a plain Prefetch record "
                "starts four bytes before SCCA; null when not established). validation says what the header's "
                "own fields support: 'unknown' means a signature only, 'header plausible' is not a whole, "
                "readable structure, and 'truncated' means the file itself ends before the header or the length "
                "it declares. The cut starts at the structure's start and is the kind's fixed size or, where the "
                "header declares more and the kind has a cap, the declared length; cut_complete says whether it "
                "holds the declared length. Hand each extract to the tool that reads that format when the "
                "pack that carries it is loaded, and keep the offsets in the report beside what it says. An "
                "extract can hold credential material (a SAM or SECURITY hive, a browser database): that is "
                "deliberate, and a cracking tool downstream stays available; cite an extract by job or path, "
                "never by content. The extracts are private (directory 0700, files 0600), and their sizes and sha256 are in the "
                "extract manifest the answer names (extraction.manifest), not in this answer.",
    }
    if limit_clamped is not None:
        result["limit_clamped_to"] = MAX_PREVIEW
        result["limit_requested"] = limit_clamped
    if stop:
        result["coverage"]["resume_start"] = resume_at
        result["coverage"]["resume_note"] = ("pass resume_start as `start` for the rest (and a results_to of another name); every hit with a "
                                             "signature offset below it is in this answer and in the hit list, and nothing at or after it was looked at")
    if results_to and manifest is not None:
        # The digest of the whole hit list goes where the extracts' digests go, not into the answer.
        manifest.add({"row": "results", "file": str(results_to), "hits": hit_count, "sha256": results_digest.hexdigest()})
    if manifest is not None:
        manifest.close()
        extraction["manifest"] = str(manifest.path) if manifest.path else None
        extraction["extracted_bytes"] = extract_bytes
        result["extraction"] = extraction
    if results_to:
        result["complete_results"] = str(results_to)
        result["complete_results_format"] = "JSON Lines, one complete hit per line, in offset order"
        if requested_results is not None and Path(requested_results).name != results_to.name:
            result["complete_results_note"] = ("the name you asked for was taken by an earlier, different file, which was kept: "
                                               "this result is under the next free name")
    elif paged.get("all_results"):
        result["complete_results"] = paged["all_results"]
        result["complete_results_format"] = paged["all_results_format"]
    print(json.dumps(result, indent=2))


def run_guarded():
    for signum in (signal.SIGTERM, signal.SIGINT, signal.SIGHUP):
        signal.signal(signum, _on_signal)
    try:
        main()
    except SystemExit:
        raise
    except Terminated as stopped:   # a signal before the sweep started, or while its answer was being made
        interrupted_answer(stopped.signum, partial_results=STATE["partial"], resume_start=STATE["resume_start"],
                           hit_count_so_far=STATE["hits_so_far"])
        raise SystemExit(128 + stopped.signum)
    except Exception as exc:  # never an empty or clean answer for a failure
        fail("unexpected failure: %s: %s" % (type(exc).__name__, exc))


if __name__ == "__main__":
    run_guarded()
