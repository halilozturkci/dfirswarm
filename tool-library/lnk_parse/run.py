#!/usr/bin/env python3
import json, sys, struct, datetime, os
from pathlib import Path

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
        agent = re.sub(
            r"[^A-Za-z0-9_.-]", "_", os.environ.get("AGENT_ID") or "tool"
        )
        self.path = Path("work") / agent / "tool-output" / f"{self.tool}-{digest}.jsonl"

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
            result["all_results"] = str(self.path)
            result["all_results_format"] = "JSON Lines, one complete result per line"
        return result

def ft(raw):
    if not raw or raw in (0, 0xFFFFFFFFFFFFFFFF):
        return None
    try:
        return (datetime.datetime(1601,1,1, tzinfo=datetime.timezone.utc) + datetime.timedelta(microseconds=raw/10)).strftime('%Y-%m-%dT%H:%M:%S.%fZ')
    except Exception:
        return None

def u16z(data, off, maxlen=None):
    """A NUL-terminated UTF-16 string, read to its NUL or to the end of data."""
    end = len(data) if maxlen is None else min(len(data), off+maxlen)
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
                    s, _ = u16z(buf, o)
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
    # extra blocks, up to the terminal block. When the bytes read end first the
    # structure runs past them, and structure_complete says so.
    extras = []
    complete = False
    while p+4 <= len(data):
        bsz = struct.unpack_from('<I', data, p)[0]
        if bsz < 4:
            complete = True
            break
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
            # the two 32-byte droid pairs (volume and object identifiers), whole
            if len(blk) >= 96:
                rec['droid_hex'] = blk[32:64].hex()
                rec['droid_birth_hex'] = blk[64:96].hex()
        elif sig == 0xA0000007:  # icon environment: the same two paths as the environment block
            rec['hex'] = blk.hex()
            rec['icon_env_ascii'] = blk[8:8+260].split(b'\x00',1)[0].decode('latin1','replace')
            rec['icon_env_u16'] = blk[8+260:].decode('utf-16le','replace').split('\x00',1)[0] if len(blk)>268 else None
        else:
            rec['ascii'] = ''.join(chr(b) if 32<=b<127 else '.' for b in blk)
        extras.append(rec)
        p += bsz
        if bsz == 0:
            break
    out['extra'] = extras
    out['structure_complete'] = complete
    out['bytes_read'] = len(data)
    # collect utf16 strings from everything read, each one whole. A string is
    # read to its NUL; the next one starts right after it. A run that is too
    # short or has no letter is passed over whole, since no tail of it can
    # qualify either.
    strs = []
    i = 0x4C
    while i+4 < len(data):
        s, ni = u16z(data, i)
        if len(s) >= 6 and any(c.isalpha() for c in s):
            strs.append(s)
        i = max(ni, i + 2)
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
        each = args.get('each')
        hits = LosslessPage("lnk_parse", [src, offset, size, each], limit)
        magic = bytes.fromhex('4c0000000114020000000000c000000000000046')
        starts = []
        i = 0
        while True:
            j = data.find(magic, i)
            if j < 0:
                break
            starts.append(j)
            i = j+4
        for n, j in enumerate(starts):
            # Without `each`, a link runs to the next header or to the end of
            # what was read, never to a fixed cut.
            stop = j + int(each) if each else (starts[n+1] if n+1 < len(starts) else len(data))
            rec = parse_lnk(data[j:stop], offset+j)
            rec['rel'] = j
            hits.add(rec)
        page = hits.finish()
        print(json.dumps({'count': page['matched'], 'hits': hits.page, **page,
                          'offset': offset, 'bytes_read': len(data)}, indent=2))
        return
    print(json.dumps(parse_lnk(data, offset), indent=2))

if __name__ == '__main__':
    main()
