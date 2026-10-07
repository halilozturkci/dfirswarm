/**
 * A stand-in for dissect.util.compression.lzxpress_huffman, so the tests of prefetch_mam and mam_scan that inflate a MAM
 * stream run where the library is not installed (CI installs the apt packages only).
 *
 * It decodes the one code the suite's encoder writes (every one of the 512 symbols given a 9-bit code, so symbol s has code s)
 * and does it the way dissect.util does: a 32-bit bit buffer refilled one 16-bit word at a time, a loop that stops when the read
 * position reaches the end of the input (so the symbols still in the bit buffer are not decoded: a stream that ends without
 * padding comes out a few bytes short, exactly as it does with the real library), the output grown in a bytearray named `dst`
 * that the tools' bound replaces, and a short read padded with zeros. A table that is not the all-9-bit one is refused, since this
 * does not build a tree. tests/pack-windows-forensics-prefetch.test.ts holds it to the real library where that is installed.
 */
const DECODER = String.raw`
import io
import struct


def _read_16_bit(fh):
    return struct.unpack("<H", fh.read(2).rjust(2, b"\x00"))[0]


class BitString:
    def init(self, fh):
        self.mask = (_read_16_bit(fh) << 16) + _read_16_bit(fh)
        self.bits = 32
        self.source = fh

    def lookup(self, n):
        return 0 if n == 0 else self.mask >> (32 - n)

    def skip(self, n):
        self.mask = (self.mask << n) & 0xFFFFFFFF
        self.bits -= n
        if self.bits < 16:
            self.mask += _read_16_bit(self.source) << (16 - self.bits)
            self.bits += 16


def decompress(src):
    if not hasattr(src, "read"):
        src = io.BytesIO(src)
    dst = bytearray()
    start_offset = src.tell()
    src.seek(0, io.SEEK_END)
    size = src.tell() - start_offset
    src.seek(start_offset, io.SEEK_SET)
    bitstring = BitString()
    while src.tell() - start_offset < size:
        if src.read(256) != b"\x99" * 256:
            raise ValueError("the stand-in reads only the all-9-bit code table")
        bitstring.init(src)
        chunk_size = 0
        while chunk_size < 65536 and src.tell() - start_offset < size:
            symbol = bitstring.lookup(9)
            bitstring.skip(9)
            if symbol < 256:
                dst.append(symbol)
                chunk_size += 1
            else:
                symbol -= 256
                length = symbol & 0x0F
                symbol >>= 4
                offset = (1 << symbol) + bitstring.lookup(symbol)
                if length == 15:
                    length = ord(src.read(1)) + 15
                    if length == 270:
                        length = _read_16_bit(src)
                bitstring.skip(symbol)
                length += 3
                remaining = length
                while remaining > 0:
                    match_size = min(remaining, offset)
                    dst += dst[-offset : (-offset + match_size) or None]
                    remaining -= match_size
                chunk_size += length
    return bytes(dst)
`;

/** The files of the stand-in, for stubModule(cwd, DISSECT_STAND_IN): a regular package that shadows the real one. */
export const DISSECT_STAND_IN: Record<string, string> = {
  "dissect/__init__.py": "",
  "dissect/util/__init__.py": "",
  "dissect/util/compression/__init__.py": "",
  "dissect/util/compression/lzxpress_huffman.py": DECODER,
};
