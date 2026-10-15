#!/usr/bin/env python3
"""Carve Windows event records out of a blob that is not an event log.

Clearing a log rewrites or replaces the file; it does not by itself destroy every
record. An .evtx file is a 4096-byte file header followed by 64 KiB chunks, each one
self-contained: its own magic ElfChnk\\x00, its own string and template tables, its own
checksums, and its records inside it. Whether old chunks survive in unallocated
space, a pagefile, a memory image or another copy of the file depends on allocation,
overwrite, discard and what was acquired; this tool reads the bytes it is given as
stored (a hibernation file is compressed and is not decompressed here). A chunk needs
no file header to be read.

So the sweep is: find every ElfChnk\\x00, check that the 128 bytes after it are a chunk header
(header size 0x80, the record offsets inside the 64 KiB, the first record number not past
the last), hand the 64 KiB that follows to the chunk parser, check its checksums, and read the
records. The library's ChunkHeader does not refuse garbage: a signature that fails the header
check is a problem line and counts only under `candidates` and `signatures_rejected`, never as
a chunk found or parsed. A record carries its
own Channel, so a carved record can be attributed without knowing which file it
came from — and that is the thing to quote in the report, because the file it
was carved from is usually not a log file at all.

A cleared log is where the search starts: "no records recovered" is bounded by the
sources and ranges that were swept, and is not a statement about the log.

Nothing found is dropped. Every matching record is kept, with its whole XML, in
a file the output names (always written when anything was found); the page
returned inline is `limit` long and carries the summary, without the XML unless
`with_xml` is true. A chunk cut short by the end of the file is still read for the
records it holds. `chunk_limit` (chunks parsed) and `candidate_limit` (places where
the chunk magic was found, whether or not it is a chunk) bound the work of one call,
not the result: the sweep stops before the next one, and resume_start is the offset
to pass as start to carry on from there. The answer says the range asked for and the
range examined; `sweep_complete` means the range asked for was swept.

A repeated field name in a record's EventData is kept as a list, not overwritten, and
the XML in the result file is the whole record. A chunk is "verified" when its own
checksums hold; a record in an unverified chunk may still be sound, and is marked.
"""
import json
import os
import stat
import struct
import sys
import xml.etree.ElementTree as ET

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

NS = {"e": "http://schemas.microsoft.com/win/2004/08/events/event"}
PARSER = "evtx_carve/4"
DEADLINE_SECONDS = 590            # the manifest allows 600
INLINE_CHANNELS = 100


# BEGIN SHARED PLACE
# The same text is in every windows-forensics tool that keeps a result file (a windows-forensics test holds the copies equal).
# A result file that is there is never replaced by another result: a file of the same bytes is named again, any other result takes the next free
# <stem>-<n><suffix>. The name is taken first, with an exclusive create, so a result written at the same moment cannot be replaced either.
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
    """Move the finished `tmp` to `path` and never replace what is there. The name is taken first, with an exclusive create, so a
    result written at the same moment cannot be replaced either. Returns the path that holds it."""
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
    raise OSError("no free name beside %s" % path)
# END SHARED PLACE


# BEGIN SHARED PAGE
# The same text is in every windows-forensics tool that pages through LosslessPage (held equal by a windows-forensics test): LosslessPage replaces a file of the
# same name; this one places its finished file with place_without_replacing, and registers itself so that a stop can remove its temporary file.
PAGES = []


class NoReplacePage(LosslessPage):
    """LosslessPage whose finished file is placed without replacing an earlier file of the same name (a rerun with other limits, or one
    the time limit stopped, must not leave a smaller file where a larger one was)."""

    def __init__(self, tool, key, limit):
        super().__init__(tool, key, limit)
        PAGES.append(self)

    def finish(self) -> dict:
        result = {"matched": self.total, "returned": len(self.page), "truncated": self.total > len(self.page)}
        if self._out is not None:
            try:
                self._out.flush()
                os.fsync(self._out.fileno())
                self._out.close()
                assert self._tmp is not None
                placed = place_without_replacing(self._tmp, self.path)
            except OSError as exc:
                self._cannot_write(exc)
            self._tmp = None
            self.path = placed
            self.shown = self.shown[: len(self.shown) - len(Path(self.shown).name)] + placed.name
            result["all_results"] = self.shown
            result["all_results_format"] = "JSON Lines, one complete result per line"
        return result
# END SHARED PAGE


# BEGIN SHARED EVTX READ
# The same text is in evtx_query and evtx_carve (a windows-forensics test holds the copies equal). python-evtx follows a chunk's string and
# template tables without a bound: a table entry whose next pointer names itself never ends, and nothing in the library has a clock. So a
# chunk is checked before the library is given it (chain_problem), whatever else it holds is read under a timer of its own (chunk_guard,
# which raises ChunkTimeout inside the library and gives the chunk up), and the whole run has a clock below the manifest's (out_of_time).
# SIGTERM, SIGINT and SIGHUP are cooperative: inside the library they unwind it (Interrupted), elsewhere they are noted and the next
# check_stop() raises, so that a result file is closed between two rows and never in the middle of one.
import signal
import struct
import time

CHUNK_MAGIC = b"ElfChnk\x00"
CHUNK_SIZE = 65536
HEADER_BYTES = 0x80
CHUNK_SECONDS = 8
CLOCK = {"deadline": None}
STOP = {"signal": None, "in_library": False}


class ChunkTimeout(BaseException):
    """A chunk took longer than CHUNK_SECONDS to read. BaseException: a library that catches Exception does not swallow it."""


class Interrupted(BaseException):
    def __init__(self, signum):
        super().__init__(signum)
        self.signum = signum


def set_deadline(seconds):
    CLOCK["deadline"] = time.monotonic() + seconds


def out_of_time():
    return CLOCK["deadline"] is not None and time.monotonic() > CLOCK["deadline"]


def _on_alarm(signum, _frame):
    raise ChunkTimeout()


def _on_signal(signum, _frame):
    if STOP["in_library"]:
        raise Interrupted(signum)
    STOP["signal"] = signum


def install_signal_handlers():
    signal.signal(signal.SIGALRM, _on_alarm)
    for signum in (signal.SIGTERM, signal.SIGINT, signal.SIGHUP):
        signal.signal(signum, _on_signal)


def check_stop():
    if STOP["signal"] is not None:
        raise Interrupted(STOP["signal"])


class chunk_guard:
    """`with chunk_guard():` the library is called under a CHUNK_SECONDS timer (and never longer than the run's clock has left); a stop
    signal unwinds it. Not for code that writes a result: that runs outside it."""

    def __enter__(self):
        left = CLOCK["deadline"] - time.monotonic() if CLOCK["deadline"] is not None else CHUNK_SECONDS
        check_stop()
        STOP["in_library"] = True
        signal.setitimer(signal.ITIMER_REAL, max(0.05, min(CHUNK_SECONDS, left)))
        return self

    def __exit__(self, *exc):
        signal.setitimer(signal.ITIMER_REAL, 0)
        STOP["in_library"] = False
        return False


def reject_signature(head):
    """Why the 128 bytes after an ElfChnk signature are not a chunk header, or None when they could be one. The layout is the format's (the
    libevtx notes on the EVTX chunk header): the first and last record numbers at 0x08 and 0x10, the header size (0x80) at 0x28, the offset
    of the last record at 0x2C and of the free space at 0x30, each inside the 64 KiB chunk. python-evtx's ChunkHeader reads whatever it is
    given without complaint, so this check is the tool's own."""
    if len(head) < HEADER_BYTES:
        return "the file ends %d bytes after the signature and a chunk header is %d bytes" % (len(head), HEADER_BYTES)
    first, last = struct.unpack_from("<QQ", head, 0x08)
    header_size, last_offset, next_offset = struct.unpack_from("<III", head, 0x28)
    if header_size != HEADER_BYTES:
        return "its header size is %d, not %d" % (header_size, HEADER_BYTES)
    if last_offset > CHUNK_SIZE or next_offset > CHUNK_SIZE:
        return ("its record offsets (last %d, free space %d) lie outside a %d-byte chunk"
                % (last_offset, next_offset, CHUNK_SIZE))
    if next_offset > 0x200 and first > last:
        return "its first record number %d is after its last, %d" % (first, last)
    return None


def chain_problem(raw):
    """Why `raw` (one chunk) must not be handed to python-evtx, or None. It mirrors ChunkHeader._load_strings and _load_templates, which
    follow 64 string chains and 32 template chains until a next pointer of 0: a pointer that names an offset already seen is a loop, one
    outside the chunk is a read past it."""
    if len(raw) < 0x200:
        return "the chunk is shorter than its 0x200-byte header area"
    for count, base, label in ((64, 0x80, "string"), (32, 0x180, "template")):
        for i in range(count):
            ofs = struct.unpack_from("<I", raw, base + 4 * i)[0]
            seen = set()
            while ofs > 0:
                if ofs in seen:
                    return "%s table entry %d loops back to offset 0x%x" % (label, i, ofs)
                seen.add(ofs)
                if label == "string":
                    if ofs + 8 > len(raw):
                        return "%s table entry %d points outside the chunk (0x%x)" % (label, i, ofs)
                    ofs = struct.unpack_from("<I", raw, ofs)[0]
                else:
                    if ofs < 10 or ofs + 4 > len(raw):
                        return "%s table entry %d points outside the chunk (0x%x)" % (label, i, ofs)
                    if raw[ofs - 10] != 0x0C or struct.unpack_from("<I", raw, ofs - 4)[0] != ofs:
                        break                       # python-evtx stops here itself (it logs "Unexpected token")
                    ofs = struct.unpack_from("<I", raw, ofs)[0]
                if len(seen) > 100000:
                    return "%s table entry %d chain longer than any chunk can hold" % (label, i)
    return None
# END SHARED EVTX READ



class CompletePage(NoReplacePage):
    """A page whose whole result is ALWAYS kept in a file (LosslessPage writes the file only when there are more rows than the page). The
    rows hold the whole XML; what is shown inline is made from them afterwards."""

    def finish(self) -> dict:
        if self._out is None and self.page:
            try:
                self.path.parent.mkdir(parents=True, exist_ok=True)
                fd, name = tempfile.mkstemp(dir=self.path.parent, prefix=f".{self.path.name}-")
                self._tmp = Path(name)
                self._out = os.fdopen(fd, "w", encoding="utf-8")
            except OSError as exc:
                self._cannot_write(exc)
            for kept in self.page:
                self._write(kept)
        return super().finish()


def keep(out, name, value):
    """Add a value under `name`; a name seen again becomes a list, never an overwrite."""
    if name in out:
        if isinstance(out[name], list):
            out[name].append(value)
        else:
            out[name] = [out[name], value]
    else:
        out[name] = value


def fail(message, **extra):
    print(json.dumps({"error": message, "status": "failed", "status_basis": "the tool stopped with an error (see error); nothing was swept", **extra}))
    raise SystemExit(1)


def summarise(xml, offset, chunk_offset, verified):
    root = ET.fromstring(xml)
    system = root.find("e:System", NS)
    out = {"chunk_offset": chunk_offset, "record_offset": offset, "chunk_verified": verified}
    if system is not None:
        def text(tag):
            return system.findtext("e:" + tag, default="", namespaces=NS) or ""
        try:
            out["event_id"] = int(text("EventID"))
        except ValueError:
            out["event_id"] = None
        try:
            out["record_id"] = int(text("EventRecordID"))
        except ValueError:
            out["record_id"] = None
        out["channel"] = text("Channel")
        out["computer"] = text("Computer")
        provider = system.find("e:Provider", NS)
        if provider is not None:
            out["provider"] = provider.get("Name", "")
        created = system.find("e:TimeCreated", NS)
        if created is not None:
            out["time_created"] = created.get("SystemTime", "")
        execution = system.find("e:Execution", NS)
        if execution is not None:
            out["process_id"] = execution.get("ProcessID", "")
    data = {}
    for node in root.iterfind(".//e:EventData/e:Data", NS):
        name = node.get("Name") or "Data%d" % len(data)
        keep(data, name, (node.text or "").strip())
    if data:
        out["data"] = data
    user = root.find(".//e:UserData", NS)
    if user is not None and not data:
        flat = {}
        for c in user.iter():
            if c is user:
                continue
            keep(flat, c.tag.rsplit("}", 1)[-1] if isinstance(c.tag, str) else str(c.tag), (c.text or "").strip())
        out["user_data"] = flat
    return out


def whole(args, name, default, low):
    v = args.get(name)
    if v is None:
        return default
    if isinstance(v, bool) or not isinstance(v, int) or v < low:
        fail("%s must be a whole number of at least %d" % (name, low), **{name: args.get(name)})
    return v


def main():
    set_deadline(DEADLINE_SECONDS)
    install_signal_handlers()
    try:
        args = json.load(sys.stdin)
    except ValueError as exc:
        fail("arguments are not valid JSON", reason=str(exc))
    if not isinstance(args, dict):
        fail("the arguments must be a JSON object")

    path = args.get("path")
    if not isinstance(path, str) or not path:
        fail("path is required: a blob to sweep for chunk headers")
    try:
        mode = os.stat(path).st_mode
    except (OSError, ValueError):
        fail("no such file", path=path)
    if not stat.S_ISREG(mode):
        # A named pipe or a device would be opened and waited on: it is not read.
        fail("the path is not a regular file, so it was not opened", path=path, not_attempted=1)

    limit = whole(args, "limit", 300, 1)
    chunk_limit = whole(args, "chunk_limit", 200, 1)
    candidate_limit = whole(args, "candidate_limit", 20000, 1)
    start = whole(args, "start", 0, 0)
    max_bytes = whole(args, "max_bytes", None, 1)
    raw_ids = args.get("event_ids") or []
    if not isinstance(raw_ids, list) or any(isinstance(e, bool) or not isinstance(e, int) for e in raw_ids):
        fail("event_ids must be a list of whole numbers", event_ids=args.get("event_ids"))
    wanted = set(raw_ids)
    contains = args.get("contains")
    if contains is not None and not isinstance(contains, str):
        fail("contains must be a string")
    contains_l = contains.lower() if contains else None
    with_xml = bool(args.get("with_xml"))

    try:
        from Evtx.Evtx import ChunkHeader
    except ImportError as exc:
        fail("python-evtx is not installed: python3 -m pip install python-evtx", reason=str(exc))

    size = os.path.getsize(path)
    if start > size:
        fail("start is past the end of the file", start=start, size=size)
    end = size if not max_bytes else min(size, start + max_bytes)

    # The names of the whole results are made from what was asked about and never from `contains`: a needle can be a secret, and a name,
    # like the answer, is not a place for it or for a digest of it (a digest is a way to confirm a guess offline). Whether a needle was
    # given is in the name; a result file is never replaced, so another needle takes the next free name.
    records = CompletePage("evtx_carve", [path, start, end, sorted(wanted), bool(contains), chunk_limit, candidate_limit], limit)
    problems = NoReplacePage("evtx_carve-problems", [path, start, end, chunk_limit, candidate_limit], 40)
    channel_page = NoReplacePage("evtx_carve-channels", [path, start, end, sorted(wanted), bool(contains), chunk_limit, candidate_limit], INLINE_CHANNELS)
    channels = set()
    c = {"seen": 0, "parsed": 0, "verified": 0, "candidates": 0, "rejected": 0, "tables_refused": 0, "timed_out": 0, "unverified_empty": 0,
         "malformed": 0, "problems": 0}
    resume_start = None
    stop = {"time": None, "signal": None}

    def problem(offset, why):
        c["problems"] += 1
        problems.add({"offset": offset, "why": why})

    def read_chunk(chunk):
        """The records of one chunk as [(kind, offset, xml, message)] read under the chunk's timer: kind is 'record' or 'record_error'
        (the library could not render that record), 'chain' (the record chain ended early) or 'timeout'."""
        items = []
        try:
            with chunk_guard():
                for record in chunk.records():
                    try:
                        items.append(("record", record.offset(), record.xml(), None))
                    except Exception as exc:
                        items.append(("record_error", None, None, str(exc)))
        except ChunkTimeout:
            c["timed_out"] += 1
            items.append(("timeout", None, None, None))
        except Exception as exc:
            items.append(("chain", None, None, str(exc)))
        return items

    # A chunk whose magic starts before `end` is found even when the magic itself runs over it.
    read_end = min(size, end + len(CHUNK_MAGIC) - 1)
    position = start
    swept_candidate = start
    try:
        try:
            with open(path, "rb") as fh:
                window = 1 << 22                    # read in 4 MiB steps, overlapping by a magic
                position = start
                tail = b""
                tail_at = start
                while position < read_end and resume_start is None:
                    check_stop()
                    fh.seek(position)
                    block = fh.read(min(window, read_end - position))
                    if not block:
                        break
                    buf = tail + block
                    base = tail_at
                    search = 0
                    while True:
                        hit = buf.find(CHUNK_MAGIC, search)
                        if hit < 0:
                            break
                        search = hit + 1
                        absolute = base + hit
                        if absolute >= end:
                            break
                        check_stop()
                        if c["parsed"] >= chunk_limit or c["candidates"] >= candidate_limit:
                            # Stop before this one, and say where: nothing is skipped.
                            resume_start = absolute
                            break
                        if out_of_time():
                            resume_start = absolute
                            stop["time"] = "the tool's own time limit (%d seconds) was reached" % DEADLINE_SECONDS
                            break
                        c["candidates"] += 1
                        swept_candidate = absolute
                        fh.seek(absolute)
                        refusal = reject_signature(fh.read(HEADER_BYTES))
                        if refusal is not None:
                            c["rejected"] += 1
                            problem(absolute, "an ElfChnk signature that is not a chunk: %s" % refusal)
                            fh.seek(position + len(block))
                            continue
                        c["seen"] += 1
                        fh.seek(absolute)
                        raw = fh.read(CHUNK_SIZE)
                        fh.seek(position + len(block))
                        if len(raw) < CHUNK_SIZE:
                            problem(absolute, "the chunk runs past the end of the file: %d of its "
                                              "%d bytes are there, and the records in them are read"
                                              % (len(raw), CHUNK_SIZE))
                        loop = chain_problem(raw)
                        if loop is not None:
                            c["tables_refused"] += 1
                            problem(absolute, "the chunk was not read: its %s" % loop)
                            continue
                        try:
                            chunk = ChunkHeader(raw, 0)
                        except Exception as exc:                      # a false positive on the magic
                            problem(absolute, "not a readable chunk: %s" % exc)
                            continue
                        try:
                            with chunk_guard():
                                verified = bool(chunk.verify())
                        except ChunkTimeout:
                            verified = False
                            problem(absolute, "the checksums could not be computed in time")
                        except Exception as exc:
                            verified = False
                            problem(absolute, "the checksums could not be computed: %s" % exc)
                        c["parsed"] += 1
                        if verified:
                            c["verified"] += 1
                        read_any = 0
                        for kind, offset, xml, message in read_chunk(chunk):
                            check_stop()
                            if kind == "timeout":
                                problem(absolute, "the chunk took more than %d seconds to read; the records after this point in it were not read" % CHUNK_SECONDS)
                                continue
                            if kind == "chain":
                                problem(absolute, "the record list ended early: %s" % message)
                                continue
                            if kind == "record_error":
                                problem(absolute, "a record did not parse: %s" % message)
                                continue
                            read_any += 1
                            if contains_l and contains_l not in xml.lower():
                                continue
                            try:
                                entry = summarise(xml, absolute + offset, absolute, verified)
                            except ET.ParseError as exc:
                                # python-evtx does not escape a quote in an attribute: the record is kept, with its XML and the reason.
                                c["malformed"] += 1
                                problem(absolute, "record XML is malformed (kept in the result file with parse_error): %s" % exc)
                                entry = {"chunk_offset": absolute, "record_offset": absolute + offset, "chunk_verified": verified,
                                         "parse_error": "record XML is malformed: %s" % exc}
                                if wanted:
                                    continue                  # its event id cannot be read, so a filter on ids cannot place it
                            if wanted and entry.get("event_id") not in wanted:
                                continue
                            # The whole XML goes in the result file; the page shown inline drops it unless asked.
                            entry["xml"] = xml
                            records.add(entry)
                            if entry.get("channel") and entry["channel"] not in channels:
                                channels.add(entry["channel"])
                                channel_page.add(entry["channel"])
                        if not verified and not read_any:
                            c["unverified_empty"] += 1
                            problem(absolute, "the header checks passed, but the checksums do not hold and no record could be read: this is probably not a chunk")
                    tail = buf[-(len(CHUNK_MAGIC) - 1):] if len(buf) >= len(CHUNK_MAGIC) else buf
                    tail_at = base + len(buf) - len(tail)
                    position += len(block)
        except Interrupted as interrupt:
            stop["signal"] = interrupt.signum
            resume_start = swept_candidate if c["candidates"] else start
    except OSError as exc:
        fail("the sweep could not read %s (or write its result): %s" % (path, exc), candidates=c["candidates"],
             signatures_rejected=c["rejected"], chunks_parsed=c["parsed"], swept_to=position)

    swept_to = resume_start if resume_start is not None else max(start, min(end, size))
    page = records.finish()
    problem_page = problems.finish()
    channels_result = channel_page.finish()
    inline = records.page if with_xml else [{k: v for k, v in r.items() if k != "xml"} for r in records.page]
    if stop["signal"] is not None:
        status, basis = "interrupted", "the tool was stopped by signal %d; what was swept before it is in the result file, and resume_start says where to go on" % stop["signal"]
    elif resume_start is None and not c["problems"]:
        status, basis = "complete", "the whole range asked for was swept and every chunk found was read without a problem"
    else:
        reasons = []
        if resume_start is not None:
            reasons.append("the sweep stopped at %s (resume_start)" % (stop["time"] or "chunk_limit or candidate_limit"))
        if c["problems"]:
            reasons.append("%d problem(s) are named under problems" % c["problems"])
        status, basis = "partial", "; ".join(reasons)
    out = {
        "parser": PARSER,
        "status": status,
        "status_basis": basis,
        "signal": stop["signal"],
        "path": path,
        "range_requested": {"start": start, "end": end, "file_bytes": size},
        "range_examined": {"start": start, "end": swept_to},
        "bytes_swept": max(0, swept_to - start),
        "candidates": c["candidates"],
        "signatures_rejected": c["rejected"],
        "chunks_found": c["seen"],
        "chunks_parsed": c["parsed"],
        "chunks_checksum_ok": c["verified"],
        "chunks_not_read_tables": c["tables_refused"],
        "chunks_timed_out": c["timed_out"],
        "chunks_unverified_and_empty": c["unverified_empty"],
        "records_malformed_kept": c["malformed"],
        "records": inline,
        "record_count": page["matched"],
        "channels": channel_page.page,
        "channel_count": channels_result["matched"],
        **page,
        "sweep_complete": resume_start is None,
        "resume_start": resume_start,
        "walk_stopped_by_time_limit": stop["time"] is not None,
        "problems": problems.page,
        "problem_count": c["problems"],
        "note": "Cite the Channel on the record, not the file this was carved from: a chunk "
                "in a pagefile or in unallocated space no longer belongs to any file. A chunk "
                "whose checksum does not verify may still hold sound records, but say so. "
                "sweep_complete means the range asked for was swept, not that every log record "
                "that ever existed was recovered. Records after a chunk's free-space offset (slack of a recycled chunk) are not read."
                + ("" if resume_start is None else
                   " The sweep stopped at chunk_limit, candidate_limit or the time limit: run again with start=%d to read on "
                   "from there." % resume_start),
    }
    if channels_result.get("all_results"):
        out["all_channels"] = channels_result["all_results"]
    if problem_page.get("all_results"):
        out["all_problems"] = problem_page["all_results"]
    print(json.dumps(out, indent=2))
    if stop["signal"] is not None:
        sys.exit(128 + stop["signal"])


if __name__ == "__main__":
    try:
        main()
    except SystemExit:
        raise
    except Interrupted as interrupt:
        print(json.dumps({"error": "stopped by signal %d" % interrupt.signum, "status": "interrupted", "status_basis": "the tool was stopped by signal %d" % interrupt.signum, "signal": interrupt.signum}), flush=True)
        sys.exit(128 + interrupt.signum)
    except Exception as exc:                                  # whatever hostile input does, the answer is JSON
        print(json.dumps({"error": "the sweep failed", "status": "failed", "status_basis": "the tool stopped with an unexpected error", "reason": "%s: %s" % (type(exc).__name__, exc)}))
        sys.exit(1)
