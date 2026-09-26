import json, sys, re, struct, datetime
from pathlib import Path
from dissect.util.compression import lzxpress_huffman


def filetime_to_iso(ft):
    if not ft:
        return None
    dt = datetime.datetime(1601,1,1) + datetime.timedelta(microseconds=ft/10)
    return dt.isoformat() + 'Z'


def parse_prefetch(data):
    compressed = False
    declared_uncompressed_size = None
    if data[:4] == b'MAM\x04':
        compressed = True
        declared_uncompressed_size = struct.unpack_from('<I', data, 4)[0]
        data = lzxpress_huffman.decompress(data[8:])
        if len(data) < declared_uncompressed_size:
            raise SystemExit('MAM stream ended before its declared uncompressed size')
        data = data[:declared_uncompressed_size]
    if data[4:8] != b'SCCA':
        raise SystemExit('not a Windows Prefetch file after optional MAM decompression')
    version = struct.unpack_from('<I', data, 0)[0]
    file_size = struct.unpack_from('<I', data, 12)[0]
    exe_name = data[16:76].decode('utf-16le', 'ignore').rstrip('\x00')
    prefetch_hash = struct.unpack_from('<I', data, 76)[0]
    run_count_offsets = {17: 0x90, 23: 0x98, 26: 0xD0, 30: 0xD0, 31: 0xD0}
    run_count_offset = run_count_offsets.get(version)
    run_count = (struct.unpack_from('<I', data, run_count_offset)[0]
                 if run_count_offset is not None and run_count_offset + 4 <= len(data) else None)
    last_run_start = 0x78 if version == 17 else 0x80
    last_run_slots = 1 if version in (17, 23) else 8
    last_runs = []
    for off in range(last_run_start, last_run_start + last_run_slots * 8, 8):
        if off + 8 <= len(data):
            ft = struct.unpack_from('<Q', data, off)[0]
            if ft:
                last_runs.append(filetime_to_iso(ft))
    strings = []
    for m in re.finditer(rb'(?:[ -~]\x00){4,}', data):
        s = m.group().decode('utf-16le', 'ignore')
        if any(c.isalpha() for c in s):
            strings.append(s)
    seen = set()
    uniq = []
    for s in strings:
        if s not in seen:
            seen.add(s)
            uniq.append(s)
    paths = [s for s in uniq if '\\' in s or '/' in s]
    return {
        'compressed': compressed,
        'declared_uncompressed_size': declared_uncompressed_size,
        'decompressed_size': len(data),
        'version': version,
        'file_size_field': file_size,
        'exe_name': exe_name,
        'prefetch_hash': '%08X' % prefetch_hash,
        'run_count': run_count,
        'last_runs': last_runs,
        'all_strings': uniq,
        'paths': paths,
    }


def main():
    args = json.load(sys.stdin)
    path = args['path']
    data = Path(path).read_bytes()
    res = parse_prefetch(data)
    print(json.dumps(res, indent=2))

if __name__ == '__main__':
    main()
