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

CHUNK_MAGIC = b"ElfChnk\x00"
CHUNK_SIZE = 65536
NS = {"e": "http://schemas.microsoft.com/win/2004/08/events/event"}
PARSER = "evtx_carve/3"
HEADER_BYTES = 0x80


class CompletePage(LosslessPage):
    """A page whose whole result is ALWAYS kept in a file (LosslessPage writes the file only when there are more
    rows than the page). The rows hold the whole XML; what is shown inline is made from them afterwards."""

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
    print(json.dumps({"error": message, **extra}))
    raise SystemExit(1)


def reject_signature(head):
    """Why the 128 bytes after an ElfChnk signature are not a chunk header, or None when they could be one. The
    layout is the format's (the libevtx notes on the EVTX chunk header): the first and last record numbers at 0x08 and
    0x10, the header size (0x80) at 0x28, the offset of the last record at 0x2C and of the free space at 0x30, each
    inside the 64 KiB chunk. python-evtx's ChunkHeader reads whatever it is given without complaint, so this check is
    the tool's own."""
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
    try:
        args = json.load(sys.stdin)
    except ValueError as exc:
        fail("arguments are not valid JSON", reason=str(exc))
    if not isinstance(args, dict):
        fail("the arguments must be a JSON object")

    path = args.get("path")
    if not isinstance(path, str) or not path:
        fail("path is required: a blob to sweep for chunk headers")
    if not os.path.isfile(path):
        fail("no such file", path=path)

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

    records = CompletePage(
        "evtx_carve", [path, start, end, sorted(wanted), contains], limit)
    problems = LosslessPage("evtx_carve-problems", [path, start, end], 40)
    channels = set()
    chunks_seen, chunks_parsed, chunks_verified, candidates, rejected = 0, 0, 0, 0, 0
    problem_count = 0
    resume_start = None

    def problem(offset, why):
        nonlocal problem_count
        problem_count += 1
        problems.add({"offset": offset, "why": why})

    # A chunk whose magic starts before `end` is found even when the magic
    # itself runs over it.
    read_end = min(size, end + len(CHUNK_MAGIC) - 1)
    position = start
    try:
        with open(path, "rb") as fh:
            window = 1 << 22                    # read in 4 MiB steps, overlapping by a magic
            position = start
            tail = b""
            tail_at = start
            while position < read_end and resume_start is None:
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
                    if chunks_parsed >= chunk_limit or candidates >= candidate_limit:
                        # Stop before this one, and say where: nothing is skipped.
                        resume_start = absolute
                        break
                    candidates += 1
                    fh.seek(absolute)
                    refusal = reject_signature(fh.read(HEADER_BYTES))
                    if refusal is not None:
                        rejected += 1
                        problem(absolute, "an ElfChnk signature that is not a chunk: %s" % refusal)
                        fh.seek(position + len(block))
                        continue
                    chunks_seen += 1
                    fh.seek(absolute)
                    raw = fh.read(CHUNK_SIZE)
                    fh.seek(position + len(block))
                    if len(raw) < CHUNK_SIZE:
                        problem(absolute, "the chunk runs past the end of the file: %d of its "
                                          "%d bytes are there, and the records in them are read"
                                          % (len(raw), CHUNK_SIZE))
                    try:
                        chunk = ChunkHeader(raw, 0)
                    except Exception as exc:                      # a false positive on the magic
                        problem(absolute, "not a readable chunk: %s" % exc)
                        continue
                    try:
                        verified = bool(chunk.verify())
                    except Exception as exc:
                        verified = False
                        problem(absolute, "the checksums could not be computed: %s" % exc)
                    chunks_parsed += 1
                    if verified:
                        chunks_verified += 1
                    try:
                        for record in chunk.records():
                            try:
                                xml = record.xml()
                            except Exception as exc:
                                problem(absolute, "a record did not parse: %s" % exc)
                                continue
                            if contains_l and contains_l not in xml.lower():
                                continue
                            try:
                                entry = summarise(xml, absolute + record.offset(), absolute, verified)
                            except ET.ParseError as exc:
                                problem(absolute, "record XML is malformed: %s" % exc)
                                continue
                            if wanted and entry.get("event_id") not in wanted:
                                continue
                            # The whole XML goes in the result file; the page shown inline drops it unless asked.
                            entry["xml"] = xml
                            records.add(entry)
                            if entry.get("channel"):
                                channels.add(entry["channel"])
                    except Exception as exc:
                        problem(absolute, "the record list ended early: %s" % exc)
                tail = buf[-(len(CHUNK_MAGIC) - 1):] if len(buf) >= len(CHUNK_MAGIC) else buf
                tail_at = base + len(buf) - len(tail)
                position += len(block)
    except OSError as exc:
        fail("the sweep could not read %s (or write its result): %s" % (path, exc), status="failed", candidates=candidates,
             signatures_rejected=rejected, chunks_parsed=chunks_parsed, swept_to=position)

    swept_to = resume_start if resume_start is not None else max(start, min(end, size))
    page = records.finish()
    problem_page = problems.finish()
    inline = records.page if with_xml else [{k: v for k, v in r.items() if k != "xml"} for r in records.page]
    out = {
        "parser": PARSER,
        "status": "complete" if resume_start is None and not problem_count else "partial",
        "path": path,
        "range_requested": {"start": start, "end": end, "file_bytes": size},
        "range_examined": {"start": start, "end": swept_to},
        "bytes_swept": max(0, swept_to - start),
        "candidates": candidates,
        "signatures_rejected": rejected,
        "chunks_found": chunks_seen,
        "chunks_parsed": chunks_parsed,
        "chunks_checksum_ok": chunks_verified,
        "records": inline,
        "record_count": page["matched"],
        "channels": sorted(channels),
        **page,
        "sweep_complete": resume_start is None,
        "resume_start": resume_start,
        "problems": problems.page,
        "problem_count": problem_count,
        "note": "Cite the Channel on the record, not the file this was carved from: a chunk "
                "in a pagefile or in unallocated space no longer belongs to any file. A chunk "
                "whose checksum does not verify may still hold sound records, but say so. "
                "sweep_complete means the range asked for was swept, not that every log record "
                "that ever existed was recovered."
                + ("" if resume_start is None else
                   " The sweep stopped at chunk_limit or candidate_limit: run again with start=%d to read on "
                   "from there." % resume_start),
    }
    if problem_page.get("all_results"):
        out["all_problems"] = problem_page["all_results"]
    print(json.dumps(out, indent=2))


if __name__ == "__main__":
    main()
