/**
 * Stand-ins for python-evtx, and a builder for the EVTX structures the carve tests need.
 *
 * evtx_query is exercised through a JSON description of chunks and records (python-evtx cannot be installed on a CI host,
 * and BinXML is its business, not the tool's). evtx_carve is exercised through real bytes: a 64 KiB chunk written to the
 * layout libevtx documents (the EVTX notes: a chunk header of 128 bytes with the first and last record numbers at 0x08 and
 * 0x10, the header size at 0x28, the offsets of the last record and of the free space at 0x2C and 0x30, the CRC-32 of the
 * records at 0x34 and of the header at 0x7C; records from 0x200, each "**\0\0", its size, its number, its FILETIME, the
 * XML, and its size again). The stand-in library reads them as python-evtx does and, like python-evtx, REFUSES NOTHING when
 * it is built over garbage: ChunkHeader() does not raise, verify() says no, records() yields nothing. Only the rendering
 * of a record's XML is a stand-in: the record body is the XML text itself, where the real library expands BinXML.
 */
import { crc32 } from "node:zlib";

/** python-evtx on a JSON description: Evtx(path), .get_file_header(), .chunks(); chunk.offset(), chunk.records(); record.offset(), .xml(), .unpack_qword(0x10). */
export const EVTX_QUERY_STUB = String.raw`
import json


class _Header:
    def __init__(self, spec):
        self.spec = spec

    def header_chunk_size(self):
        return 4096

    def chunk_count(self):
        return self.spec["chunk_count"]

    def next_record_number(self):
        return self.spec["next_record_number"]


class _Rec:
    def __init__(self, spec):
        self.spec = spec

    def offset(self):
        return self.spec["offset"]

    def xml(self):
        if "xml_error" in self.spec:
            raise ValueError(self.spec["xml_error"])
        return self.spec["xml"]

    def unpack_qword(self, off):
        assert off == 0x10
        return int(self.spec["filetime"])


class _Chunk:
    def __init__(self, spec):
        self.spec = spec

    def offset(self):
        return self.spec["offset"]

    def records(self):
        def gen():
            for r in self.spec["records"]:
                if "chain_error" in r:
                    raise ValueError(r["chain_error"])
                yield _Rec(r)
        return gen()


class Evtx:
    def __init__(self, path):
        with open(path, encoding="utf-8") as fh:
            self.spec = json.load(fh)

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False

    def get_file_header(self):
        if "header_error" in self.spec:
            raise ValueError(self.spec["header_error"])
        chunks = self.spec["chunks"]
        declared = self.spec.get("header", {})
        return _Header({
            "chunk_count": declared.get("chunk_count", len(chunks)),
            "next_record_number": declared.get("next_record_number", 1 + max([r.get("number", 0) for c in chunks for r in c["records"]] or [0])),
        })

    def chunks(self):
        for c in self.spec["chunks"]:
            if "enumeration_error" in c:
                raise ValueError(c["enumeration_error"])
            yield _Chunk(c)
`;

/**
 * python-evtx's ChunkHeader and Record over real bytes, as the library has them: ChunkHeader(buf, offset) never raises,
 * check_magic()/verify()/records(); the checksums as the library calculates them (CRC-32 of the first 0x78 bytes and of
 * 0x80..0x200 for the header, of 0x200..next_record_offset for the records); records() starts at 0x200 and ends at the
 * first thing that is not a record. A read past the end of the buffer raises struct.error, as the library's unpackers do.
 */
export const EVTX_CARVE_STUB = String.raw`
import struct
import zlib


class InvalidRecordException(Exception):
    pass


class Record:
    def __init__(self, buf, offset, chunk):
        self._buf, self._offset, self._chunk = buf, offset, chunk
        if struct.unpack_from("<I", buf, offset)[0] != 0x00002A2A:
            raise InvalidRecordException()

    def offset(self):
        return self._offset

    def length(self):
        return struct.unpack_from("<I", self._buf, self._offset + 4)[0]

    def xml(self):
        n = self.length()
        if n < 28 or self._offset + n > len(self._buf):
            raise ValueError("record length %d does not fit" % n)
        return bytes(self._buf[self._offset + 24:self._offset + n - 4]).rstrip(b"\x00").decode("utf-8")


class ChunkHeader:
    def __init__(self, buf, offset):
        self._buf, self._offset = buf, offset

    def _dword(self, at):
        return struct.unpack_from("<I", self._buf, self._offset + at)[0]

    def check_magic(self):
        return bytes(self._buf[self._offset:self._offset + 8]) == b"ElfChnk\x00"

    def header_size(self):
        return self._dword(0x28)

    def last_record_offset(self):
        return self._dword(0x2C)

    def next_record_offset(self):
        return self._dword(0x30)

    def data_checksum(self):
        return self._dword(0x34)

    def header_checksum(self):
        return self._dword(0x7C)

    def calculate_header_checksum(self):
        crc = zlib.crc32(bytes(self._buf[self._offset:self._offset + 0x78]))
        return zlib.crc32(bytes(self._buf[self._offset + 0x80:self._offset + 0x200]), crc) & 0xFFFFFFFF

    def calculate_data_checksum(self):
        data = bytes(self._buf[self._offset + 0x200:self._offset + self.next_record_offset()])
        return zlib.crc32(data) & 0xFFFFFFFF

    def verify(self):
        return (self.header_checksum() == self.calculate_header_checksum()
                and self.data_checksum() == self.calculate_data_checksum())

    def records(self):
        try:
            record = Record(self._buf, self._offset + 0x200, self)
        except (InvalidRecordException, struct.error):
            return
        while record._offset < self._offset + self.next_record_offset() and record.length() > 0:
            yield record
            try:
                record = Record(self._buf, record._offset + record.length(), self)
            except (InvalidRecordException, struct.error):
                return
`;

export const CHUNK_BYTES = 0x10000;

export type ChunkRecord = { number: number; xml: string; filetime?: bigint };

/** A 64 KiB chunk to the layout above, its records packed from 0x200 and both checksums set; `corrupt` leaves the records' checksum wrong (the records themselves intact). */
export function evtxChunk(records: ChunkRecord[], o: { corrupt?: boolean } = {}): Buffer {
  const chunk = Buffer.alloc(CHUNK_BYTES);
  chunk.write("ElfChnk\u0000", 0, "latin1");
  let at = 0x200;
  let lastAt = 0x200;
  for (const r of records) {
    const xml = Buffer.from(r.xml, "utf8");
    const size = Math.ceil((24 + xml.length + 4) / 8) * 8;
    chunk.writeUInt32LE(0x00002a2a, at);
    chunk.writeUInt32LE(size, at + 4);
    chunk.writeBigUInt64LE(BigInt(r.number), at + 8);
    chunk.writeBigUInt64LE(r.filetime ?? 133_443_104_001_234_567n, at + 16);
    xml.copy(chunk, at + 24);
    chunk.writeUInt32LE(size, at + size - 4);
    lastAt = at;
    at += size;
  }
  const first = records.length ? records[0].number : 1;
  const last = records.length ? records[records.length - 1].number : 0;
  chunk.writeBigUInt64LE(BigInt(first), 0x08);
  chunk.writeBigUInt64LE(BigInt(last), 0x10);
  chunk.writeBigUInt64LE(BigInt(first), 0x18);
  chunk.writeBigUInt64LE(BigInt(last), 0x20);
  chunk.writeUInt32LE(0x80, 0x28);
  chunk.writeUInt32LE(records.length ? lastAt : 0, 0x2c);
  chunk.writeUInt32LE(at, 0x30);
  const dataCrc = crc32(chunk.subarray(0x200, at));
  chunk.writeUInt32LE(o.corrupt ? (dataCrc ^ 1) >>> 0 : dataCrc, 0x34);
  chunk.writeUInt32LE(crc32(Buffer.concat([chunk.subarray(0, 0x78), chunk.subarray(0x80, 0x200)])), 0x7c);
  return chunk;
}

/** The XML of an event as the tests need it: Security, one EventData name per entry (a repeated name is two entries). */
export function eventXml(o: { eid: number; rec: number; time?: string; channel?: string; data?: Array<[string, string]> }): string {
  const data = (o.data ?? []).map(([k, v]) => `<Data Name="${k}">${v}</Data>`).join("");
  const time = o.time ? `<TimeCreated SystemTime="${o.time}"></TimeCreated>` : "";
  return `<?xml version="1.0" encoding="utf-8" standalone="yes"?><Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event"><System><Provider Name="Microsoft-Windows-Security-Auditing"></Provider><EventID>${o.eid}</EventID>${time}<EventRecordID>${o.rec}</EventRecordID><Channel>${o.channel ?? "Security"}</Channel><Computer>WS01</Computer></System><EventData>${data}</EventData></Event>`;
}

/** The 4096-byte file header (libevtx): "ElfFile\0", the oldest and current chunk numbers, the next record number, header size 128, version 3.1, header chunk size 4096, the chunk count at 0x2A, the CRC-32 of the first 0x78 bytes at 0x7C. */
export function evtxFileHeader(chunkCount: number, nextRecordNumber = 1): Buffer {
  const h = Buffer.alloc(4096);
  h.write("ElfFile\u0000", 0, "latin1");
  h.writeBigUInt64LE(0n, 0x08);
  h.writeBigUInt64LE(BigInt(Math.max(0, chunkCount - 1)), 0x10);
  h.writeBigUInt64LE(BigInt(nextRecordNumber), 0x18);
  h.writeUInt32LE(128, 0x20);
  h.writeUInt16LE(1, 0x24);
  h.writeUInt16LE(3, 0x26);
  h.writeUInt16LE(4096, 0x28);
  h.writeUInt16LE(chunkCount, 0x2a);
  h.writeUInt32LE(crc32(h.subarray(0, 0x78)), 0x7c);
  return h;
}
