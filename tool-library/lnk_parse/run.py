#!/usr/bin/env python3
import json, sys, struct, datetime, os
from pathlib import Path

sys.path.insert(0, str(Path(sys.argv[0]).resolve().parents[1]))
from _output import LosslessPage

def ft(raw):
    if not raw or raw in (0, 0xFFFFFFFFFFFFFFFF):
        return None
    try:
        return (datetime.datetime(1601,1,1, tzinfo=datetime.timezone.utc) + datetime.timedelta(microseconds=raw/10)).strftime('%Y-%m-%dT%H:%M:%S.%fZ')
    except Exception:
        return None

def u16z(data, off, maxlen=1024):
    end = min(len(data), off+maxlen)
    i = off
    out = []
    while i+1 < end:
        w = data[i] | (data[i+1]<<8)
        i += 2
        if w == 0:
            break
        if 32 <= w < 0xD800:
            out.append(chr(w))
        elif w < 32:
            out.append(' ')
        else:
            try:
                out.append(chr(w))
            except Exception:
                break
    return ''.join(out), i

def parse_idlist(data, off, size):
    items = []
    end = off + size
    p = off
    while p+2 <= end:
        sz = struct.unpack_from('<H', data, p)[0]
        if sz < 2 or p+sz > end:
            break
        blob = data[p:p+sz]
        # try ascii and utf16
        s = ''.join(chr(b) if 32<=b<127 else '' for b in blob)
        items.append({'size': sz, 'ascii': s})
        p += sz
    return items

def parse_lnk(data, base_off=0):
    if len(data) < 0x4C or data[0:4] != b'L\x00\x00\x00' or data[4:20] != bytes.fromhex('0114020000000000c000000000000046'):
        return {'ok': False, 'error': 'not a LNK header'}
    flags = struct.unpack_from('<I', data, 0x14)[0]
    attr = struct.unpack_from('<I', data, 0x18)[0]
    c,a,w = struct.unpack_from('<QQQ', data, 0x1C)
    flen, icon_idx, show, hot = struct.unpack_from('<IIII', data, 0x34)
    p = 0x4C
    out = {
        'ok': True,
        'offset': base_off,
        'flags': flags,
        'flags_hex': hex(flags),
        'file_attr': attr,
        'created': ft(c),
        'accessed': ft(a),
        'written': ft(w),
        'file_length': flen,
        'show_cmd': show,
    }
    if flags & 0x1 and p+2 <= len(data):
        id_size = struct.unpack_from('<H', data, p)[0]
        p += 2
        out['idlist_size'] = id_size
        blob = data[p:p+id_size]
        out['idlist_ascii'] = ''.join(chr(b) if 32<=b<127 else '.' for b in blob)
        # extract path-like utf16/ascii from extra
        paths = []
        # SHELL_ITEM file entries often have utf16 name at end
        q = 0
        while q+2 <= len(blob):
            isz = struct.unpack_from('<H', blob, q)[0]
            if isz < 2 or q+isz > len(blob):
                break
            item = blob[q:q+isz]
            # look for drive "C:\\" ascii
            if b':' in item:
                ascii = ''.join(chr(b) if 32<=b<127 else '' for b in item)
                if ascii:
                    paths.append(ascii)
            # utf16 strings
            try:
                u = item.decode('utf-16le', errors='ignore')
                u = ''.join(ch if ch.isprintable() else ' ' for ch in u).strip()
                if len(u) >= 3 and any(x in u.lower() for x in ['.exe','.lnk','.dll','.ps1','users','windows','temp','appdata',':\\','http']):
                    paths.append(u)
            except Exception:
                pass
            q += isz
        out['idlist_paths'] = paths
        p += id_size
    if flags & 0x2 and p+4 <= len(data):
        li_size = struct.unpack_from('<I', data, p)[0]
        if 0x1C <= li_size <= len(data)-p:
            li = data[p:p+li_size]
            hdr = struct.unpack_from('<IIIIIIII', li, 0) if len(li)>=32 else None
            if hdr:
                _, lhdr, vol_off, local_off, net_off, _cb, common_off, _ = hdr[:8]
                def zs(buf, o):
                    if o <= 0 or o >= len(buf):
                        return None
                    z = buf.find(b'\x00', o)
                    if z < 0: z = len(buf)
                    return buf[o:z].decode('latin1', errors='replace')
                def u16(buf, o):
                    if o <= 0 or o >= len(buf):
                        return None
                    s, _ = u16z(buf, o, 2048)
                    return s
                out['local_base_path'] = zs(li, local_off)
                out['common_path'] = zs(li, common_off)
                # unicode extra often after
                # LinkInfo unicode local path if volume flags
                out['local_base_path_u16'] = u16(li, local_off) if local_off else None
            out['linkinfo_size'] = li_size
            p += li_size
    # string data in order based on flags
    def read_str(pp, unicode=bool(flags & 0x80)):
        if pp+2 > len(data):
            return None, pp
        n = struct.unpack_from('<H', data, pp)[0]
        pp += 2
        if unicode:
            nbytes = n*2
            s = data[pp:pp+nbytes].decode('utf-16le', errors='replace')
            pp += nbytes
        else:
            s = data[pp:pp+n].decode('latin1', errors='replace')
            pp += n
        return s, pp
    names = []
    bit_names = [(0x4,'name'),(0x8,'relative_path'),(0x10,'working_dir'),(0x20,'arguments'),(0x40,'icon_location')]
    for bit, nm in bit_names:
        if flags & bit:
            s, p = read_str(p)
            out[nm] = s
            names.append((nm,s))
    # extra blocks
    extras = []
    while p+4 <= len(data):
        bsz = struct.unpack_from('<I', data, p)[0]
        if bsz < 8 or p+bsz > len(data):
            break
        sig = struct.unpack_from('<I', data, p+4)[0]
        blk = data[p:p+bsz]
        rec = {'size': bsz, 'sig': hex(sig)}
        if sig == 0xA0000001:  # environment
            rec['env_ascii'] = blk[8:8+260].split(b'\x00',1)[0].decode('latin1','replace')
            rec['env_u16'] = blk[8+260:].decode('utf-16le','replace').split('\x00',1)[0] if len(blk)>268 else None
        elif sig == 0xA0000003:  # tracker
            rec['tracker'] = blk[8:64].decode('latin1','replace',).split('\x00')[0] if len(blk)>16 else None
            # machine name at +16 typically
            rec['machine'] = blk[16:16+16].split(b'\x00',1)[0].decode('latin1','replace') if len(blk)>32 else None
        elif sig == 0xA0000007:  # unicode properties / darwin? actually SPECIAL_FOLDER
            rec['hex'] = blk[:32].hex()
        else:
            rec['ascii'] = ''.join(chr(b) if 32<=b<127 else '.' for b in blk)
        extras.append(rec)
        p += bsz
        if bsz == 0:
            break
    out['extra'] = extras
    # collect utf16 strings from whole remaining
    strs = []
    i = 0x4C
    while i+4 < min(len(data), 8192):
        s, ni = u16z(data, i, 512)
        if len(s) >= 6 and any(c.isalpha() for c in s):
            strs.append(s)
            i = ni+2
        else:
            i += 2
    out['utf16_strings'] = strs
    return out

def main():
    args = json.load(sys.stdin)
    path = args.get('path')
    offset = int(args.get('offset') or 0)
    size = int(args.get('size') or 4096)
    dump = args.get('dump')  # if set, read from dump at offset
    src = dump or path
    if not src:
        print(json.dumps({'error':'need path or dump'})); sys.exit(1)
    if not os.path.isfile(src):
        print(json.dumps({'error':'no such file', 'path': src})); sys.exit(1)
    with open(src,'rb') as f:
        f.seek(offset)
        data = f.read(size)
    if args.get('scan'):
        limit = int(args.get('max') or 50)
        hits = LosslessPage("lnk_parse", [src, offset, size, args.get('each')], limit)
        magic = bytes.fromhex('4c0000000114020000000000c000000000000046')
        i = 0
        while True:
            j = data.find(magic, i)
            if j < 0:
                break
            rec = parse_lnk(data[j:j+int(args.get('each') or 2048)], offset+j)
            rec['rel'] = j
            hits.add(rec)
            i = j+4
        page = hits.finish()
        print(json.dumps({'count': page['matched'], 'hits': hits.page, **page}, indent=2))
        return
    print(json.dumps(parse_lnk(data, offset), indent=2))

if __name__ == '__main__':
    main()
