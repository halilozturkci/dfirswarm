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
"""
import json
import os
import sys
import xml.etree.ElementTree as ET

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

    size = os.path.getsize(path)
    end = size if not max_bytes else min(size, start + int(max_bytes))

    records, chunks_seen, chunks_parsed, chunks_verified = [], 0, 0, 0
    problems, truncated = [], False

    with open(path, "rb") as fh:
        window = 1 << 22                    # read in 4 MiB steps, overlapping by a chunk
        position = start
        tail = b""
        tail_at = start
        while position < end:
            fh.seek(position)
            block = fh.read(min(window, end - position))
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
                if absolute + CHUNK_SIZE > size:
                    break
                chunks_seen += 1
                if chunks_parsed >= chunk_limit:
                    truncated = True
                    break
                fh.seek(absolute)
                raw = fh.read(CHUNK_SIZE)
                fh.seek(position + len(block))
                if len(raw) < CHUNK_SIZE:
                    problems.append({"offset": absolute, "why": "the chunk runs past the end of the file"})
                    continue
                try:
                    chunk = ChunkHeader(raw, 0)
                    verified = bool(chunk.verify())
                except Exception as exc:                      # a false positive on the magic
                    problems.append({"offset": absolute, "why": "not a readable chunk: %s" % exc})
                    continue
                chunks_parsed += 1
                if verified:
                    chunks_verified += 1
                found_here = 0
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
                        if len(records) >= limit:
                            truncated = True
                            break
                        records.append(entry)
                        found_here += 1
                except Exception as exc:
                    problems.append({"offset": absolute, "why": "the record list ended early: %s" % exc})
                if truncated:
                    break
            if truncated:
                break
            tail = buf[-(len(CHUNK_MAGIC) - 1):] if len(buf) >= len(CHUNK_MAGIC) else buf
            tail_at = base + len(buf) - len(tail)
            position += len(block)

    channels = sorted({r.get("channel", "") for r in records if r.get("channel")})
    print(json.dumps({
        "path": path,
        "bytes_swept": max(0, min(end, size) - start),
        "chunks_found": chunks_seen,
        "chunks_parsed": chunks_parsed,
        "chunks_checksum_ok": chunks_verified,
        "records": records,
        "record_count": len(records),
        "channels": channels,
        "truncated": truncated,
        "problems": problems,
        "note": "Cite the Channel on the record, not the file this was carved from: a chunk "
                "in a pagefile or in unallocated space no longer belongs to any file. A chunk "
                "whose checksum does not verify may still hold sound records, but say so.",
    }, indent=2))


if __name__ == "__main__":
    main()
