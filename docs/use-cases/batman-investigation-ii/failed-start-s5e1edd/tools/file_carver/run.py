import sys, json, struct, hashlib, os
from pathlib import Path


def fail(message, **extra):
    print(json.dumps({"ok": False, "error": message, **extra}))
    raise SystemExit(1)


def resolve_output(out):
    """Where `out` really lands, refusing anything outside the run directory.

    A string check is not enough: `work/../inputs/x` and an absolute path
    both name a file the tool must not write, and neither starts with
    "inputs/". Resolving first and comparing directories is what actually
    holds, and the read-only inputs are the one place extracted bytes must
    never appear -- a later integrity check would report the evidence as
    modified.
    """
    root = Path.cwd().resolve()
    dest = (root / out).resolve() if not Path(out).is_absolute() else Path(out).resolve()
    if dest != root and root not in dest.parents:
        fail("output must stay inside the run directory", output=str(out))
    inputs = root / "inputs"
    if dest == inputs or inputs in dest.parents:
        fail("output cannot be under inputs/", output=str(out))
    return dest


def carve_pe(data, off):
    """PE file: use section headers to find actual file size"""
    if len(data) - off < 0x40:
        return 0
    pe_lfanew = struct.unpack_from('<I', data, off + 0x3C)[0]
    if pe_lfanew < 64 or pe_lfanew > 8192:
        return 0
    pe_sig_off = off + pe_lfanew
    if data[pe_sig_off:pe_sig_off+4] != b'PE\x00\x00':
        return 0
    num_sec = struct.unpack_from('<H', data, pe_sig_off + 6)[0]
    opt_sz = struct.unpack_from('<H', data, pe_sig_off + 20)[0]
    sec_start = pe_sig_off + 24 + opt_sz
    max_end = 0
    for i in range(num_sec):
        sec = sec_start + i * 40
        if sec + 40 > len(data):
            break
        raw_sz = struct.unpack_from('<I', data, sec + 16)[0]
        raw_off = struct.unpack_from('<I', data, sec + 20)[0]
        end = raw_off + raw_sz
        if end > max_end:
            max_end = end
    return max_end

def carve_sqlite(data, off):
    """SQLite: page_size * page_count from header"""
    if len(data) - off < 100:
        return 0
    if data[off:off+16] != b'SQLite format 3\x00':
        return 0
    page_size = struct.unpack_from('>H', data, off + 16)[0]
    if page_size == 1:
        page_size = 65536
    if page_size < 512 or page_size > 65536:
        return 0
    page_count = struct.unpack_from('>I', data, off + 28)[0]
    if page_count < 1 or page_count > 10000000:
        return 0
    return page_size * page_count

def carve_regf(data, off):
    """Registry hive: primary file size at offset 0x20"""
    if len(data) - off < 0x30:
        return 0
    if data[off:off+4] != b'regf':
        return 0
    sz = struct.unpack_from('<I', data, off + 0x20)[0]
    if 4096 <= sz <= 500_000_000:
        return sz
    return 0

def carve_pdf(data, off):
    """PDF: start at %PDF, end at %%EOF"""
    eof = data.find(b'%%EOF', off, off + 50_000_000)
    if eof < 0:
        return 0
    end = eof + 5
    while end < len(data) and data[end:end+1] in (b'\r', b'\n'):
        end += 1
    return end - off  # end already points past any trailing newline

FOOTER_MARKERS = {
    'ZIP': b'PK\x05\x06',  # end of central directory
    'PNG': b'IEND\xaeB`\x82',
    'JPEG': b'\xff\xd9',
    'GIF': b'\x3b',
}

MAGICS = {
    'PE': b'MZ',
    'ZIP': b'PK\x03\x04',
    'PDF': b'%PDF-',
    'SQLite': b'SQLite format 3\x00',
    'regf': b'regf',
    'PNG': b'\x89PNG\r\n\x1a\n',
    'JPEG': b'\xff\xd8\xff',
    'GIF': (b'GIF87a', b'GIF89a'),
}

def carve_footer(data, off, sig_type, max_size):
    """Carve using footer marker"""
    marker = FOOTER_MARKERS.get(sig_type)
    if not marker:
        return 0
    search_end = min(len(data), off + max_size)
    idx = data.find(marker, off + len(marker), search_end)
    if idx < 0:
        return 0
    # For ZIP, the end is at the end of central directory
    if sig_type == 'ZIP':
        if idx + 22 <= len(data):
            # EOCD record: comment length at offset 20 (2 bytes)
            comment_len = struct.unpack_from('<H', data, idx + 20)[0]
            return idx + 22 + comment_len - off
    elif sig_type == 'PNG':
        return idx + 8 - off  # IEND + 4 byte CRC
    elif sig_type == 'JPEG':
        return idx + 2 - off
    elif sig_type == 'GIF':
        return idx + 1 - off
    return idx - off + len(marker)

def main():
    args = json.load(sys.stdin)
    path = args['path']
    offset = args['offset']
    sig_type = args['sig_type']
    max_size = args.get('max_size', 100_000_000)
    output = args.get('output')
    if not isinstance(offset, int) or isinstance(offset, bool) or offset < 0:
        fail("offset must be a non-negative integer", offset=offset)
    if not isinstance(max_size, int) or isinstance(max_size, bool) or max_size < 1:
        fail("max_size must be a positive integer", max_size=max_size)
    if sig_type not in MAGICS:
        fail(
            "this signature has no lossless size parser",
            sig_type=sig_type,
            supported=sorted(MAGICS),
            hint="find its offset with sig_carve, then use a format-aware extractor",
        )
    dest = resolve_output(output) if output else None

    with open(path, 'rb') as f:
        f.seek(offset)
        header = f.read(16)
        expected = MAGICS[sig_type]
        valid = header.startswith(expected) if isinstance(expected, bytes) else any(header.startswith(m) for m in expected)
        if not valid:
            fail("the requested signature is not at offset", sig_type=sig_type, offset=offset)
        # Read enough to determine size
        if sig_type in ('PE', 'SQLite', 'regf'):
            read_size = min(max(1_048_576, max_size), 20_000_000)
        elif sig_type == 'PDF':
            read_size = min(max_size, 50_000_000)
        else:
            read_size = max_size
        
        f.seek(offset)
        data = f.read(read_size)

    size = 0
    if sig_type == 'PE':
        size = carve_pe(data, 0)
    elif sig_type == 'SQLite':
        size = carve_sqlite(data, 0)
    elif sig_type == 'regf':
        size = carve_regf(data, 0)
    elif sig_type == 'PDF':
        size = carve_pdf(data, 0)
    elif sig_type in FOOTER_MARKERS:
        size = carve_footer(data, 0, sig_type, max_size)

    if not size or size < 4:
        fail(
            "could not determine the complete file size within max_size",
            sig_type=sig_type,
            max_size=max_size,
            hint="retry with a larger max_size; no partial output was written",
        )
    if size > max_size:
        fail(
            "complete file is larger than max_size",
            sig_type=sig_type,
            required_size=size,
            max_size=max_size,
            hint="retry with max_size at least required_size; no partial output was written",
        )

    # Re-read exactly
    with open(path, 'rb') as f:
        f.seek(offset)
        file_data = f.read(size)
    if len(file_data) != size:
        fail("source ended before the complete file", wanted=size, got=len(file_data))

    sha256 = hashlib.sha256(file_data).hexdigest()
    
    result = {
        "ok": True,
        "offset": offset,
        "size": len(file_data),
        "sha256": sha256,
        "sig_type": sig_type,
        "first_hex": file_data[:128].hex(),
        "first_ascii": ''.join(chr(b) if 32 <= b < 127 else '.' for b in file_data[:128])
    }

    if dest is not None:
        dest.parent.mkdir(parents=True, exist_ok=True)
        dest.write_bytes(file_data)
        result['output'] = output

    print(json.dumps(result))

if __name__ == '__main__':
    main()
