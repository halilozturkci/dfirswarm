"""Fixtures for the browser_storage tests, written from the formats' specifications and not from the reader's code.

  * LevelDB log format (leveldb/doc/log_format.md): 32 KiB blocks, records of checksum (masked CRC32C of type and data), length, type
    (FULL 1, FIRST 2, MIDDLE 3, LAST 4), a write batch of sequence number, count and entries (1 put / 0 delete, length-prefixed key
    and value).
  * LevelDB table format (leveldb/doc/table_format.md): data blocks of prefix-compressed entries with a restart array, each followed by a
    trailer (compression type, masked CRC32C), an index block of block handles, a 48-byte footer ending in the table magic.
  * Snappy (the format description of google/snappy): a varint length, then literal and copy elements.
  * Chromium's IndexedDB coding scheme (content/browser/indexed_db/docs/leveldb_coding_scheme.md): a key prefix of one length byte and the
    little-endian database, object store and index ids; the metadata keys; UTF-16BE strings; a record value of a varint and the Blink
    envelope (0xFF, wire version, trailer from version 21) around a V8 serialized value (0xFF, version 15, tagged values).
"""
import struct

MASK_DELTA = 0xA282EAD8


def _crc32c_table():
    table = []
    for i in range(256):
        crc = i
        for _ in range(8):
            crc = (crc >> 1) ^ 0x82F63B78 if crc & 1 else crc >> 1
        table.append(crc)
    return table


_TABLE = _crc32c_table()


def crc32c(data, crc=0):
    crc ^= 0xFFFFFFFF
    for b in data:
        crc = _TABLE[(crc ^ b) & 0xFF] ^ (crc >> 8)
    return crc ^ 0xFFFFFFFF


def masked(crc):
    return ((((crc >> 15) | (crc << 17)) & 0xFFFFFFFF) + MASK_DELTA) & 0xFFFFFFFF


def varint(n):
    out = bytearray()
    while True:
        b = n & 0x7F
        n >>= 7
        if n:
            out.append(b | 0x80)
        else:
            out.append(b)
            return bytes(out)


# ---- LevelDB log ----
def write_batch(seq, entries):
    """entries: [(key, value)] for a put, [(key, None)] for a delete."""
    body = struct.pack("<QI", seq, len(entries))
    for key, value in entries:
        if value is None:
            body += b"\x00" + varint(len(key)) + key
        else:
            body += b"\x01" + varint(len(key)) + key + varint(len(value)) + value
    return body


def log_file(batches, wrong_crc=False):
    """A .log file holding the batches (bytes), each as one logical record split over 32 KiB blocks as the format says."""
    out = bytearray()
    for batch in batches:
        pos, first = 0, True
        while True:
            room = 32768 - (len(out) % 32768)
            if room < 7:
                out += b"\x00" * room
                room = 32768
            take = min(len(batch) - pos, room - 7)
            last = pos + take == len(batch)
            kind = 1 if first and last else 2 if first else 4 if last else 3
            data = batch[pos:pos + take]
            crc = masked(crc32c(bytes([kind]) + data))
            if wrong_crc:
                crc ^= 0xFFFFFFFF
            out += struct.pack("<IHB", crc, take, kind) + data
            pos += take
            first = False
            if last:
                break
    return bytes(out)


# ---- snappy ----
def snappy_literal(data):
    out = bytearray(varint(len(data)))
    pos = 0
    while pos < len(data):
        n = min(len(data) - pos, 60)
        out.append((n - 1) << 2)
        out += data[pos:pos + n]
        pos += n
    return bytes(out)


def snappy_compress(data):
    """Literals and two-byte-offset copies (element type 2), greedy on four-byte matches."""
    out = bytearray(varint(len(data)))
    seen, lit_start, i = {}, 0, 0

    def literal(upto):
        nonlocal lit_start
        pos = lit_start
        while pos < upto:
            n = min(upto - pos, 60)
            out.append((n - 1) << 2)
            out.extend(data[pos:pos + n])
            pos += n
        lit_start = upto
    while i + 4 <= len(data):
        cand = seen.get(data[i:i + 4])
        seen[data[i:i + 4]] = i
        if cand is not None and i - cand < 65536:
            n = 4
            while i + n < len(data) and n < 64 and data[cand + n] == data[i + n]:
                n += 1
            literal(i)
            out.append(((n - 1) << 2) | 2)
            out += struct.pack("<H", i - cand)
            i += n
            lit_start = i
        else:
            i += 1
    literal(len(data))
    return bytes(out)


# ---- LevelDB table ----
def _block(entries, restart_every=16):
    """A data block of (key, value) sorted entries with prefix compression."""
    out, restarts, prev = bytearray(), [], b""
    for n, (key, value) in enumerate(entries):
        if n % restart_every == 0:
            restarts.append(len(out))
            shared = 0
        else:
            shared = 0
            while shared < min(len(prev), len(key)) and prev[shared] == key[shared]:
                shared += 1
        out += varint(shared) + varint(len(key) - shared) + varint(len(value)) + key[shared:] + value
        prev = key
    if not restarts:
        restarts.append(0)
    for r in restarts:
        out += struct.pack("<I", r)
    out += struct.pack("<I", len(restarts))
    return bytes(out)


def internal_key(user_key, seq, put=True):
    return user_key + struct.pack("<Q", (seq << 8) | (1 if put else 0))


def table_file(records, snappy=False, per_block=4, wrong_crc=False, block_type=None, tamper=None):
    """A .ldb file. records: [(user_key, seq, value or None for a delete)]; sorted here by user key and descending sequence."""
    rows = sorted(records, key=lambda r: (r[0], -r[1]))
    out, index = bytearray(), []

    def put_block(raw, data=False):
        if tamper is not None and data:
            raw = tamper(raw)
        contents = snappy_compress(raw) if snappy else raw
        kind = block_type if (block_type is not None and data) else (1 if snappy else 0)
        crc = masked(crc32c(contents + bytes([kind])))
        if wrong_crc:
            crc ^= 0xFFFFFFFF
        offset = len(out)
        out.extend(contents + bytes([kind]) + struct.pack("<I", crc))
        return offset, len(contents)
    for start in range(0, len(rows), per_block):
        chunk = rows[start:start + per_block]
        entries = [(internal_key(k, s, v is not None), v or b"") for k, s, v in chunk]
        offset, size = put_block(_block(entries), data=True)
        index.append((entries[-1][0], varint(offset) + varint(size)))
    meta_off, meta_size = put_block(_block([]))
    idx_off, idx_size = put_block(_block(index, restart_every=1))
    footer = varint(meta_off) + varint(meta_size) + varint(idx_off) + varint(idx_size)
    footer += b"\x00" * (40 - len(footer)) + struct.pack("<Q", 0xDB4775248B80FB57)
    return bytes(out) + footer


# ---- IndexedDB ----
def le_min(n):
    out = bytearray()
    while True:
        out.append(n & 0xFF)
        n >>= 8
        if not n:
            return bytes(out)


def prefix(db, store, index):
    d, s, i = le_min(db), le_min(store), le_min(index)
    return bytes([((len(d) - 1) << 5) | ((len(s) - 1) << 2) | (len(i) - 1)]) + d + s + i


def idb_string(text):
    return varint(len(text)) + text.encode("utf-16-be")


def global_metadata(databases, schema_version=3):
    """databases: [(db id, origin, name, max object store id, {store id: name})] -> [(key, value)] records."""
    recs = [(prefix(0, 0, 0) + b"\x00", varint(schema_version)), (prefix(0, 0, 0) + b"\x01", le_min(max(d[0] for d in databases)))]
    for db, origin, name, top, stores in databases:
        recs.append((prefix(0, 0, 0) + b"\xc9" + idb_string(origin) + idb_string(name), le_min(db)))
        recs.append((prefix(db, 0, 0) + b"\x03", le_min(top)))
        for sid, sname in stores.items():
            recs.append((prefix(db, 0, 0) + b"\x32" + varint(sid) + b"\x00", sname.encode("utf-16-be")))
    return recs


def key_string(text):
    return b"\x01" + idb_string(text)


def key_number(x):
    return b"\x03" + struct.pack("<d", x)


def key_date(ms):
    return b"\x02" + struct.pack("<d", ms)


def record_key(db, store, key_bytes):
    return prefix(db, store, 1) + key_bytes


# V8 value serialization (version 15)
def v8_string(text):
    return b'"' + varint(len(text.encode("latin-1"))) + text.encode("latin-1")


def v8_int(n):
    return b"I" + varint((n << 1) ^ (n >> 63) if n >= 0 else ((-n) << 1) - 1)


def v8_double(x):
    return b"N" + struct.pack("<d", x)


def v8_date(ms):
    return b"D" + struct.pack("<d", ms)


def v8_object(pairs):
    out = b"o"
    for k, v in pairs:
        out += v8_string(k) + v
    return out + b"{" + varint(len(pairs))


def v8_array(items):
    return b"A" + varint(len(items)) + b"".join(items) + b"$" + varint(0) + varint(len(items))


V8_TRUE, V8_FALSE, V8_NULL, V8_UNDEFINED = b"T", b"F", b"0", b"_"


def idb_value(v8_body, blink_version=21, snappy=False, version=1):
    """The stored value of an object store record: a varint, the Blink envelope and the V8 data."""
    inner = b"\xff" + varint(blink_version) + (b"\xfe" + struct.pack(">QI", 0, len(v8_body) + 2) if blink_version >= 21 else b"") + b"\xff\x0f" + v8_body
    if snappy:
        return varint(version) + b"\xff" + varint(0x11) + b"\x02" + snappy_compress(inner)
    return varint(version) + inner


def external_value(version=1):
    """A value the browser moved to a blob file (kReplaceWithBlob): the envelope names a blob entry that is not there."""
    return varint(version) + b"\xff" + varint(0x11) + b"\x01" + varint(10) + varint(0)


# ---- MANIFEST (leveldb/db/version_edit.cc: tag-prefixed fields; the file has the log format) ----
def manifest_edit(new_files=(), comparator=b"leveldb.BytewiseComparator", log_number=4, next_file=9, last_seq=100):
    """new_files: [(level, file number, size, smallest key, largest key)]."""
    out = varint(1) + varint(len(comparator)) + comparator + varint(2) + varint(log_number) + varint(3) + varint(next_file) + varint(4) + varint(last_seq)
    for level, number, size, smallest, largest in new_files:
        out += varint(7) + varint(level) + varint(number) + varint(size) + varint(len(smallest)) + smallest + varint(len(largest)) + largest
    return out
