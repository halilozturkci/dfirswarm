/**
 * A PNG made smaller for a model to look at, with no library.
 *
 * `read` hands a model an image whole. In the runs the median image a seat
 * read was 0.3 to 1.7 MB (contact sheets, frames, renderings), 32 in one
 * seat's cycle, and the seat that reads most pays for it in context. A
 * model does not see more in an image past about 1,568 pixels on its long
 * side. This decodes an 8-bit, non-interlaced PNG (grey, RGB, palette, with
 * or without alpha), averages blocks of pixels down to that size, and
 * writes it again as RGB or RGBA. Anything else (JPEG, 16-bit, interlaced,
 * a file that is not what it says) is given back untouched: the original is
 * always on disk, and a crop of it at full size is one job away.
 */
import { deflateSync, inflateSync } from "node:zlib";

export const LONG_SIDE_MAX = 1568;
/** Below this many bytes an image is left as it is, whatever its size in pixels. */
export const SCALE_MIN_BYTES = 300 * 1024;

const SIG = Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]);
const crcTable = (() => {
  const t = new Uint32Array(256);
  for (let n = 0; n < 256; n += 1) {
    let c = n;
    for (let k = 0; k < 8; k += 1) c = c & 1 ? 0xedb88320 ^ (c >>> 1) : c >>> 1;
    t[n] = c >>> 0;
  }
  return t;
})();
function crc32(buf: Buffer): number {
  let c = 0xffffffff;
  for (let i = 0; i < buf.length; i += 1) c = crcTable[(c ^ buf[i]!) & 0xff]! ^ (c >>> 8);
  return (c ^ 0xffffffff) >>> 0;
}
function chunk(type: string, body: Buffer): Buffer {
  const head = Buffer.alloc(8);
  head.writeUInt32BE(body.length, 0);
  head.write(type, 4, "latin1");
  const tail = Buffer.alloc(4);
  tail.writeUInt32BE(crc32(Buffer.concat([head.subarray(4), body])), 0);
  return Buffer.concat([head, body, tail]);
}

export type Decoded = { width: number; height: number; channels: 3 | 4; pixels: Buffer };

/** The pixels of an 8-bit non-interlaced PNG as RGB or RGBA, or null for anything this does not read. */
export function decodePng(png: Buffer): Decoded | null {
  if (png.length < 33 || !png.subarray(0, 8).equals(SIG)) return null;
  let off = 8;
  let width = 0, height = 0, depth = 0, type = 0, interlace = 0;
  let palette: Buffer | null = null;
  let trns: Buffer | null = null;
  const idat: Buffer[] = [];
  while (off + 12 <= png.length) {
    const len = png.readUInt32BE(off);
    const name = png.toString("latin1", off + 4, off + 8);
    const body = png.subarray(off + 8, off + 8 + len);
    if (body.length !== len) return null;
    if (name === "IHDR") {
      if (len < 13) return null;
      width = body.readUInt32BE(0); height = body.readUInt32BE(4); depth = body[8]!; type = body[9]!; interlace = body[12]!;
    } else if (name === "PLTE") palette = Buffer.from(body);
    else if (name === "tRNS") trns = Buffer.from(body);
    else if (name === "IDAT") idat.push(body);
    else if (name === "IEND") break;
    off += 12 + len;
  }
  if (!width || !height || depth !== 8 || interlace !== 0 || !idat.length) return null;
  if (width > 20000 || height > 20000 || width * height > 120_000_000) return null;
  const inCh = type === 0 ? 1 : type === 2 ? 3 : type === 3 ? 1 : type === 4 ? 2 : type === 6 ? 4 : 0;
  if (!inCh || (type === 3 && !palette)) return null;
  let raw: Buffer;
  try {
    raw = inflateSync(Buffer.concat(idat));
  } catch {
    return null;
  }
  const stride = width * inCh;
  if (raw.length < (stride + 1) * height) return null;
  // Undo the filters in place, a row at a time.
  const rows = Buffer.alloc(stride * height);
  for (let y = 0; y < height; y += 1) {
    const filter = raw[y * (stride + 1)]!;
    const src = y * (stride + 1) + 1;
    const dst = y * stride;
    for (let x = 0; x < stride; x += 1) {
      const a = x >= inCh ? rows[dst + x - inCh]! : 0;
      const b = y > 0 ? rows[dst - stride + x]! : 0;
      const c = x >= inCh && y > 0 ? rows[dst - stride + x - inCh]! : 0;
      let v = raw[src + x]!;
      if (filter === 1) v += a;
      else if (filter === 2) v += b;
      else if (filter === 3) v += (a + b) >> 1;
      else if (filter === 4) {
        const p = a + b - c;
        const pa = Math.abs(p - a), pb = Math.abs(p - b), pc = Math.abs(p - c);
        v += pa <= pb && pa <= pc ? a : pb <= pc ? b : c;
      } else if (filter !== 0) return null;
      rows[dst + x] = v & 0xff;
    }
  }
  const alpha = type === 4 || type === 6 || (type === 3 && trns !== null);
  const channels: 3 | 4 = alpha ? 4 : 3;
  const pixels = Buffer.alloc(width * height * channels);
  for (let i = 0, n = width * height; i < n; i += 1) {
    const o = i * channels;
    if (type === 0) { const g = rows[i]!; pixels[o] = g; pixels[o + 1] = g; pixels[o + 2] = g; }
    else if (type === 2) { pixels[o] = rows[i * 3]!; pixels[o + 1] = rows[i * 3 + 1]!; pixels[o + 2] = rows[i * 3 + 2]!; }
    else if (type === 3) {
      const p = rows[i]! * 3;
      pixels[o] = palette![p] ?? 0; pixels[o + 1] = palette![p + 1] ?? 0; pixels[o + 2] = palette![p + 2] ?? 0;
      if (alpha) pixels[o + 3] = trns![rows[i]!] ?? 255;
    } else if (type === 4) { const g = rows[i * 2]!; pixels[o] = g; pixels[o + 1] = g; pixels[o + 2] = g; pixels[o + 3] = rows[i * 2 + 1]!; }
    else { pixels[o] = rows[i * 4]!; pixels[o + 1] = rows[i * 4 + 1]!; pixels[o + 2] = rows[i * 4 + 2]!; pixels[o + 3] = rows[i * 4 + 3]!; }
  }
  return { width, height, channels, pixels };
}

export function encodePng(img: Decoded): Buffer {
  const stride = img.width * img.channels;
  const raw = Buffer.alloc((stride + 1) * img.height);
  for (let y = 0; y < img.height; y += 1) img.pixels.copy(raw, y * (stride + 1) + 1, y * stride, (y + 1) * stride);
  const ihdr = Buffer.alloc(13);
  ihdr.writeUInt32BE(img.width, 0);
  ihdr.writeUInt32BE(img.height, 4);
  ihdr[8] = 8;
  ihdr[9] = img.channels === 4 ? 6 : 2;
  return Buffer.concat([SIG, chunk("IHDR", ihdr), chunk("IDAT", deflateSync(raw, { level: 6 })), chunk("IEND", Buffer.alloc(0))]);
}

/** The image with its long side at most `max`, each new pixel the mean of the block it stands for. */
export function scaleDown(img: Decoded, max = LONG_SIDE_MAX): Decoded {
  const long = Math.max(img.width, img.height);
  if (long <= max) return img;
  const w = Math.max(1, Math.round((img.width * max) / long));
  const h = Math.max(1, Math.round((img.height * max) / long));
  const out = Buffer.alloc(w * h * img.channels);
  const ch = img.channels;
  for (let y = 0; y < h; y += 1) {
    const y0 = Math.floor((y * img.height) / h);
    const y1 = Math.max(y0 + 1, Math.floor(((y + 1) * img.height) / h));
    for (let x = 0; x < w; x += 1) {
      const x0 = Math.floor((x * img.width) / w);
      const x1 = Math.max(x0 + 1, Math.floor(((x + 1) * img.width) / w));
      const sum = [0, 0, 0, 0];
      let n = 0;
      for (let yy = y0; yy < y1; yy += 1) {
        let p = (yy * img.width + x0) * ch;
        for (let xx = x0; xx < x1; xx += 1, p += ch) {
          for (let c = 0; c < ch; c += 1) sum[c]! += img.pixels[p + c]!;
          n += 1;
        }
      }
      const o = (y * w + x) * ch;
      for (let c = 0; c < ch; c += 1) out[o + c] = Math.round(sum[c]! / n);
    }
  }
  return { width: w, height: h, channels: ch, pixels: out };
}

export type Scaled = { data: Buffer; from: { width: number; height: number; bytes: number }; to: { width: number; height: number; bytes: number } };

/**
 * A PNG for a model: scaled when it is large in bytes and in pixels, else null (leave it as it is). Null too for
 * anything this cannot read, and when scaling made it no smaller.
 */
export function pngForModel(png: Buffer, o: { max?: number; minBytes?: number } = {}): Scaled | null {
  if (png.length < (o.minBytes ?? SCALE_MIN_BYTES)) return null;
  const img = decodePng(png);
  if (!img || Math.max(img.width, img.height) <= (o.max ?? LONG_SIDE_MAX)) return null;
  const small = scaleDown(img, o.max ?? LONG_SIDE_MAX);
  const data = encodePng(small);
  if (data.length >= png.length) return null;
  return { data, from: { width: img.width, height: img.height, bytes: png.length }, to: { width: small.width, height: small.height, bytes: data.length } };
}
