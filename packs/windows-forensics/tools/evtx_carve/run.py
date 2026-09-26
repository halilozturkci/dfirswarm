#!/usr/bin/env python3
"""Carve Windows event records out of a blob that is not an event log.

Clearing a log does not destroy the records. An .evtx file is a 4096-byte file
header followed by 64 KiB chunks, each one self-contained: its own magic
ElfChnk\\x00, its own string and template tables, its own checksums, and its
records inside it. When the log is cleared the file is rewritten, but the old
chunks stay in unallocated space, in the pagefile, in hiberfil.sys, and in any
shadow copy of the volume. A chunk needs no file header to be read.

So the sweep is: find every ElfChnk\\x00, hand the 64 KiB that follows to the
chunk parser, check its checksums, and read the records. A record carries its
own Channel, so a carved record can be attributed without knowing which file it
came from — and that is the thing to quote in the report, because the file it
was carved from is usually not a log file at all.

Anti-forensics note worth keeping in view: an examiner who reports "the log was
cleared, so there is nothing" has stopped one command early.

Nothing found is dropped. Every matching record is kept: the page returned
inline is `limit` long, and when there are more the whole list is written to a
file the output names. A chunk cut short by the end of the file is still read
for the records it holds. `chunk_limit` bounds the work of one call, not the
result: the sweep stops before the next chunk, and resume_start is the offset
to pass as start to carry on from there.
"""
import json
import os
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

CHUNK_MAGIC = b"ElfChnk\x00"
CHUNK_SIZE = 65536
NS = {"e": "http://schemas.microsoft.com/win/2004/08/events/event"}


def fail(message, **extra):
    print(json.dumps({"error": message, **extra}))
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
        data[name] = (node.text or "").strip()
    if data:
        out["data"] = data
    user = root.find(".//e:UserData", NS)
    if user is not None and not data:
        out["user_data"] = {c.tag.rsplit("}", 1)[-1] if isinstance(c.tag, str) else str(c.tag):
                            (c.text or "").strip()
                            for c in user.iter() if c is not user}
    return out


def main():
    try:
        args = json.load(sys.stdin)
    except ValueError as exc:
        fail("arguments are not valid JSON", reason=str(exc))

    path = args.get("path")
    if not isinstance(path, str) or not path:
        fail("path is required: a blob to sweep for chunk headers")
    if not os.path.isfile(path):
        fail("no such file", path=path)

    try:
        from Evtx.Evtx import ChunkHeader
    except ImportError as exc:
        fail("python-evtx is not installed: python3 -m pip install python-evtx", reason=str(exc))

    limit = int(args.get("limit", 300) or 300)
    chunk_limit = int(args.get("chunk_limit", 200) or 200)
    start = int(args.get("start", 0) or 0)
    max_bytes = args.get("max_bytes")
    wanted = {int(e) for e in (args.get("event_ids") or [])}
    contains = args.get("contains")
    contains_l = contains.lower() if contains else None
    with_xml = bool(args.get("with_xml"))
    if limit < 1 or chunk_limit < 1:
        fail("limit and chunk_limit must be positive integers")

    size = os.path.getsize(path)
    end = size if not max_bytes else min(size, start + int(max_bytes))

    records = LosslessPage(
        "evtx_carve", [path, start, end, sorted(wanted), contains, with_xml], limit)
    channels = set()
    chunks_seen, chunks_parsed, chunks_verified = 0, 0, 0
    problems = []
    resume_start = None

    # A chunk whose magic starts before `end` is found even when the magic
    # itself runs over it.
    read_end = min(size, end + len(CHUNK_MAGIC) - 1)
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
                if chunks_parsed >= chunk_limit:
                    # Stop before this chunk, and say where: nothing is skipped.
                    resume_start = absolute
                    break
                chunks_seen += 1
                fh.seek(absolute)
                raw = fh.read(CHUNK_SIZE)
                fh.seek(position + len(block))
                if len(raw) < CHUNK_SIZE:
                    problems.append({"offset": absolute,
                                     "why": "the chunk runs past the end of the file: %d of its "
                                            "%d bytes are there, and the records in them are read"
                                            % (len(raw), CHUNK_SIZE)})
                try:
                    chunk = ChunkHeader(raw, 0)
                except Exception as exc:                      # a false positive on the magic
                    problems.append({"offset": absolute, "why": "not a readable chunk: %s" % exc})
                    continue
                try:
                    verified = bool(chunk.verify())
                except Exception as exc:
                    verified = False
                    problems.append({"offset": absolute,
                                     "why": "the checksums could not be computed: %s" % exc})
                chunks_parsed += 1
                if verified:
                    chunks_verified += 1
                try:
                    for record in chunk.records():
                        try:
                            xml = record.xml()
                        except Exception as exc:
                            problems.append({"offset": absolute, "why": "a record did not parse: %s" % exc})
                            continue
                        if contains_l and contains_l not in xml.lower():
                            continue
                        try:
                            entry = summarise(xml, absolute + record.offset(), absolute, verified)
                        except ET.ParseError as exc:
                            problems.append({"offset": absolute, "why": "record XML is malformed: %s" % exc})
                            continue
                        if wanted and entry.get("event_id") not in wanted:
                            continue
                        if with_xml:
                            entry["xml"] = xml
                        records.add(entry)
                        if entry.get("channel"):
                            channels.add(entry["channel"])
                except Exception as exc:
                    problems.append({"offset": absolute, "why": "the record list ended early: %s" % exc})
            tail = buf[-(len(CHUNK_MAGIC) - 1):] if len(buf) >= len(CHUNK_MAGIC) else buf
            tail_at = base + len(buf) - len(tail)
            position += len(block)

    swept_to = resume_start if resume_start is not None else max(start, min(end, size))
    page = records.finish()
    print(json.dumps({
        "path": path,
        "bytes_swept": max(0, swept_to - start),
        "chunks_found": chunks_seen,
        "chunks_parsed": chunks_parsed,
        "chunks_checksum_ok": chunks_verified,
        "records": records.page,
        "record_count": page["matched"],
        "channels": sorted(channels),
        **page,
        "sweep_complete": resume_start is None,
        "resume_start": resume_start,
        "problems": problems,
        "note": "Cite the Channel on the record, not the file this was carved from: a chunk "
                "in a pagefile or in unallocated space no longer belongs to any file. A chunk "
                "whose checksum does not verify may still hold sound records, but say so."
                + ("" if resume_start is None else
                   " The sweep stopped at chunk_limit: run again with start=%d to read on "
                   "from the next chunk." % resume_start),
    }, indent=2))


if __name__ == "__main__":
    main()
