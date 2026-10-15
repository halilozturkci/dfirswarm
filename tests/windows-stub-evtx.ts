/**
 * Stand-ins for python-evtx, and a builder for the EVTX structures the carve tests need.
 *
 * Both tools are exercised through real bytes (python-evtx cannot be installed on a CI host, and BinXML is its business, not
 * the tools'): a file header and 64 KiB chunks written to the
 * layout libevtx documents (the EVTX notes: a chunk header of 128 bytes with the first and last record numbers at 0x08 and
 * 0x10, the header size at 0x28, the offsets of the last record and of the free space at 0x2C and 0x30, the CRC-32 of the
 * records at 0x34 and of the header at 0x7C; records from 0x200, each "**\0\0", its size, its number, its FILETIME, the
 * XML, and its size again). The stand-in library reads them as python-evtx does and, like python-evtx, REFUSES NOTHING when
 * it is built over garbage: ChunkHeader() does not raise, verify() says no, records() yields nothing. Only the rendering
 * of a record's XML is a stand-in: the record body is the XML text itself, where the real library expands BinXML.
 */
import { crc32 } from "node:zlib";

/**
 * python-evtx's ChunkHeader and Record over real bytes, as the library has them: ChunkHeader(buf, offset) never raises,
 * check_magic()/verify()/records(); the checksums as the library calculates them (CRC-32 of the first 0x78 bytes and of
 * 0x80..0x200 for the header, of 0x200..next_record_offset for the records); records() starts at 0x200 and ends at the
 * first thing that is not a record. A read past the end of the buffer raises struct.error, as the library's unpackers do.
 */
export const EVTX_CARVE_STUB = String.raw`
import json
import os
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

    def unpack_qword(self, off):
        return struct.unpack_from("<Q", self._buf, self._offset + off)[0]

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

    def offset(self):
        return self._offset

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


# What a test injects into the library's behaviour, from <log>.inject.json: header_error (the file header cannot be read),
# xml_error / chain_error ({"<chunk>:<record>": message}: that record's XML cannot be rendered / the chain breaks before it),
# enumeration_error_at (the enumeration of chunks fails when it reaches that chunk).
def _inject(path):
    try:
        with open(path + ".inject.json", encoding="utf-8") as fh:
            return json.load(fh)
    except OSError:
        return {}


class _InjectedChunk(ChunkHeader):
    def __init__(self, buf, offset, index, inject):
        super().__init__(buf, offset)
        self._index, self._inject = index, inject

    def records(self):
        j = 0
        for record in super().records():
            self._break_here(j)
            key = "%d:%d" % (self._index, j)
            if key in self._inject.get("xml_error", {}):
                message = self._inject["xml_error"][key]
                record.xml = lambda message=message: (_ for _ in ()).throw(ValueError(message))
            yield record
            j += 1
        self._break_here(j)

    def _break_here(self, j):
        key = "%d:%d" % (self._index, j)
        if key in self._inject.get("chain_error", {}):
            raise ValueError(self._inject["chain_error"][key])


class FileHeader:
    def __init__(self, buf, inject):
        self._buf, self._inject = buf, inject

    def header_chunk_size(self):
        return struct.unpack_from("<H", self._buf, 0x28)[0]

    def chunk_count(self):
        return struct.unpack_from("<H", self._buf, 0x2A)[0]

    def next_record_number(self):
        return struct.unpack_from("<Q", self._buf, 0x18)[0]

    def flags(self):
        return struct.unpack_from("<I", self._buf, 0x78)[0]

    def chunks(self, include_inactive=False):
        count = (1 << 62) if include_inactive else self.chunk_count()
        ofs, i = self.header_chunk_size(), 0
        while ofs + 0x10000 <= len(self._buf) and i < count:
            if self._inject.get("enumeration_error_at") == i:
                raise ValueError("unexpected end of file at chunk %d" % (i + 1))
            yield _InjectedChunk(self._buf, ofs, i, self._inject)
            ofs += 0x10000
            i += 1


class Evtx:
    def __init__(self, path):
        with open(path, "rb") as fh:
            self._buf = fh.read()
        if self._buf[:8] != b"ElfFile\x00":
            raise ValueError("not an event log")
        self._inject = _inject(path)

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False

    def get_file_header(self):
        if "header_error" in self._inject:
            raise ValueError(self._inject["header_error"])
        return FileHeader(self._buf, self._inject)
`;

/** The stand-in the evtx_query tests use: the same module as the carve stub (the library has one module for both). */
export const EVTX_QUERY_STUB = EVTX_CARVE_STUB;

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
export function evtxFileHeader(chunkCount: number, nextRecordNumber = 1, flags = 0): Buffer {
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
  h.writeUInt32LE(flags, 0x78);
  h.writeUInt32LE(crc32(h.subarray(0, 0x78)), 0x7c);
  return h;
}
