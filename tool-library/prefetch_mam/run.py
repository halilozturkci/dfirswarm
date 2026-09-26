import json, sys, re, struct, datetime
from pathlib import Path
from dissect.util.compression import lzxpress_huffman

sys.path.insert(0, str(Path(sys.argv[0]).resolve().parents[1]))
from _output import LosslessPage


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
    if data[4:8] != b'SCCA':
        raise SystemExit('not a Windows Prefetch file after optional MAM decompression')
    version = struct.unpack_from('<I', data, 0)[0]
    file_size = struct.unpack_from('<I', data, 12)[0]
    exe_name = data[16:76].decode('utf-16le', 'ignore').rstrip('\x00')
    last_runs = []
    for off in range(0x80, 0xC0, 8):
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
        'last_runs': last_runs,
        'all_strings': uniq,
        'paths': paths,
    }


def main():
    args = json.load(sys.stdin)
    path = args['path']
    max_strings = int(args.get('max_strings', 50))
    data = Path(path).read_bytes()
    res = parse_prefetch(data)
    strings = LosslessPage("prefetch_mam-strings", [path], max_strings)
    for value in res['all_strings']:
        strings.add(value)
    paths = LosslessPage("prefetch_mam-paths", [path], max_strings)
    for value in res['paths']:
        paths.add(value)
    res['all_strings'] = strings.page
    res['all_strings_page'] = strings.finish()
    res['paths'] = paths.page
    res['paths_page'] = paths.finish()
    print(json.dumps(res, indent=2))

if __name__ == '__main__':
    main()
