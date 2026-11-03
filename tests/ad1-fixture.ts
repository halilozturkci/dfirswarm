/**
 * A synthetic AccessData AD1 logical image, built in code from the layout
 * the public descriptions of the format give (dissect.evidence's ad1,
 * AD1-tools' libad1, pyad1) and the base pack's reader follows: no evidence
 * file is read or kept. It mirrors the reader's own assumptions, so the
 * suite also reads a real FTK Imager image (tests/fixtures/ad1/) to hold
 * both to the format. Every segment file starts with a 512-byte header
 * ("ADSEGMENTEDFILE", 1 and 2 as FTK Imager writes them, its number, the
 * number of segments, its size in bytes with the header, the header's size);
 * the image's data runs on from segment to segment and opens with the
 * logical image header ("ADLOGICALIMAGE", version, chunk size, the image's
 * own metadata, the first item, the data source name). An item is a node of
 * the tree with its metadata chain and, for a file, a chunk table of zlib
 * streams.
 */
import { createHash } from "node:crypto";
import { closeSync, ftruncateSync, openSync, writeSync } from "node:fs";
import { deflateSync } from "node:zlib";

export type Ad1Node = {
  name: string | Buffer;
  folder?: boolean;
  content?: Buffer;
  children?: Ad1Node[];
  /** Metadata entries written instead of the usual ones: [category, key, text]. */
  meta?: Array<[number, number, string | Buffer]>;
  /** The image records an MD5 that is not the content's. */
  wrongMd5?: boolean;
  /** Compressed chunks written as they are, with `size` as the item's size. */
  chunks?: Buffer[];
  size?: number;
};

export const md5 = (b: Buffer): string => createHash("md5").update(b).digest("hex");
export const sha1 = (b: Buffer): string => createHash("sha1").update(b).digest("hex");
export const sha256 = (b: Buffer): string => createHash("sha256").update(b).digest("hex");

/** The times every node carries unless it says otherwise, as dissect names the keys: accessed (0x7), created (0x8, FTK Imager writes it without a fraction at times), modified (0x9). */
export const TIMES: Array<[number, number, string]> = [
  [5, 7, "20240102T030405.123456"],
  [5, 8, "20240101T000000"],
  [5, 9, "20240102T030406.654321"],
];

function metaFor(node: Ad1Node): Array<[number, number, Buffer]> {
  const B = (v: string | Buffer) => (Buffer.isBuffer(v) ? v : Buffer.from(v));
  if (node.meta) return node.meta.map(([c, k, v]) => [c, k, B(v)]);
  const times = TIMES.map(([c, k, v]) => [c, k, B(v)] as [number, number, Buffer]);
  if (node.folder) return [[2, 2, B("3")], ...times];
  const c = node.content ?? Buffer.alloc(0);
  return [
    [1, 0x5001, B(node.wrongMd5 ? "0".repeat(32) : md5(c))],
    [1, 0x5002, B(sha1(c))],
    [2, 2, B("1")],
    [3, 3, B(String(c.length))],
    [4, 0x1002, B("false")],
    ...times,
  ];
}

/**
 * The image's data (logical address 0 onwards) and each node's item
 * address, so a test can damage it where it means to.
 */
export type Put = (b: Buffer) => number;
/** A run of zero bytes that costs no memory and, written by writeSparseAd1, no disk. */
export type Hole = { hole: number };
export type PutAny = (b: Buffer | Hole) => number;
type LogicalOpts = { chunkSize?: number; version?: number; source?: string };

/**
 * The image's data around items a caller lays out itself: `items` puts them
 * (put returns an address, at() the next one) and returns the first item's
 * address. The logical image header and the image's own metadata (the data
 * source name) are written around them.
 */
export function ad1Logical(items: (put: Put, at: () => number, chunkSize: number) => number, opts: LogicalOpts = {}): Buffer {
  return Buffer.concat(ad1LogicalParts(items, opts) as Buffer[]);
}

/** The same layout as ad1Logical, as its parts: buffers, and holes where a caller put({ hole: n }). */
export function ad1LogicalParts(items: (put: PutAny, at: () => number, chunkSize: number) => number, opts: LogicalOpts = {}): Array<Buffer | Hole> {
  const chunkSize = opts.chunkSize ?? 65536;
  const parts: Array<Buffer | Hole> = [];
  let len = 0;
  const put: PutAny = (b) => {
    const at = len;
    parts.push(b);
    len += Buffer.isBuffer(b) ? b.length : b.hole;
    return at;
  };
  const header = Buffer.alloc(92);
  put(header);
  const source = Buffer.from(opts.source ?? "synthetic source [NTFS]");
  const sourceAt = put(source);
  header.write("ADLOGICALIMAGE", 0, "latin1");
  header.writeUInt32LE(opts.version ?? 4, 16);
  header.writeUInt32LE(1, 20);
  header.writeUInt32LE(chunkSize, 24);
  header.writeUInt32LE(source.length, 44);
  header.write("AD", 48, "latin1");
  header.writeBigUInt64LE(BigInt(sourceAt), 52);
  header.writeBigUInt64LE(BigInt(items(put, () => len, chunkSize)), 36);
  const own = Buffer.alloc(20 + source.length);
  header.writeBigUInt64LE(BigInt(put(own)), 28);
  own.writeUInt32LE(1, 8);
  own.writeUInt32LE(0x10002, 12);
  own.writeUInt32LE(source.length, 16);
  source.copy(own, 20);
  return parts;
}

/** One-segment image file of `parts`, with every hole left unwritten (a sparse file): returns the length of the image's data. */
export function writeSparseAd1(path: string, parts: Array<Buffer | Hole>): number {
  const len = parts.reduce((n, p) => n + (Buffer.isBuffer(p) ? p.length : p.hole), 0);
  const head = Buffer.alloc(512);
  head.write("ADSEGMENTEDFILE", 0, "latin1");
  head.writeUInt32LE(1, 0x10);
  head.writeUInt32LE(2, 0x14);
  head.writeUInt32LE(1, 0x18);
  head.writeUInt32LE(1, 0x1c);
  head.writeBigUInt64LE(BigInt(512 + len), 0x20);
  head.writeUInt32LE(512, 0x28);
  const fd = openSync(path, "w");
  try {
    writeSync(fd, head, 0, 512, 0);
    let at = 512;
    for (const p of parts) {
      if (Buffer.isBuffer(p)) {
        writeSync(fd, p, 0, p.length, at);
        at += p.length;
      } else {
        at += p.hole;
      }
    }
    ftruncateSync(fd, at);
  } finally {
    closeSync(fd);
  }
  return len;
}

/** One item's header, put; the caller links it by writing next (+0) and child (+8). */
export function ad1Item(put: Put, name: string | Buffer, f: { folder?: boolean; size?: number; table?: number; meta?: number; next?: number; child?: number } = {}): { at: number; header: Buffer } {
  const n = Buffer.isBuffer(name) ? name : Buffer.from(name);
  const h = Buffer.alloc(48 + n.length + 8);
  h.writeBigUInt64LE(BigInt(f.next ?? 0), 0);
  h.writeBigUInt64LE(BigInt(f.child ?? 0), 8);
  h.writeBigUInt64LE(BigInt(f.meta ?? 0), 16);
  h.writeBigUInt64LE(BigInt(f.table ?? 0), 24);
  h.writeBigUInt64LE(BigInt(f.size ?? 0), 32);
  h.writeUInt32LE(f.folder ? 5 : 0, 40);
  h.writeUInt32LE(n.length, 44);
  n.copy(h, 48);
  return { at: put(h), header: h };
}

export function ad1Data(tree: Ad1Node[], opts: LogicalOpts = {}): { data: Buffer; addr: Map<Ad1Node, number> } {
  const addr = new Map<Ad1Node, number>();
  const data = ad1Logical((put, at, chunkSize) => chain(put, at, chunkSize, tree, addr), opts);
  return { data, addr };
}

/** A sibling chain of nodes, each with its metadata, its chunks and its children; the first one's address. */
function chain(put: Put, at0: () => number, chunkSize: number, nodes: Ad1Node[], addr: Map<Ad1Node, number>): number {
  let first = 0;
  let prev: Buffer | null = null;
  for (const node of nodes) {
    const name = Buffer.isBuffer(node.name) ? node.name : Buffer.from(node.name);
    const h = Buffer.alloc(48 + name.length + 8);
    const at = put(h);
    addr.set(node, at);
    if (prev) prev.writeBigUInt64LE(BigInt(at), 0);
    else first = at;
    prev = h;
    h.writeUInt32LE(node.folder ? 5 : 0, 40);
    h.writeUInt32LE(name.length, 44);
    name.copy(h, 48);
    let mprev: Buffer | null = null;
    for (const [c, k, v] of metaFor(node)) {
      const m = Buffer.alloc(20 + v.length);
      const mat = put(m);
      if (mprev) mprev.writeBigUInt64LE(BigInt(mat), 0);
      else h.writeBigUInt64LE(BigInt(mat), 16);
      mprev = m;
      m.writeUInt32LE(c, 8);
      m.writeUInt32LE(k, 12);
      m.writeUInt32LE(v.length, 16);
      v.copy(m, 20);
    }
    const content = node.content ?? Buffer.alloc(0);
    const pieces = node.chunks ?? [];
    if (!node.chunks) for (let i = 0; i < content.length; i += chunkSize) pieces.push(deflateSync(content.subarray(i, i + chunkSize)));
    if (!node.folder && pieces.length) {
      const table = Buffer.alloc(8 + 8 * (pieces.length + 1));
      h.writeBigUInt64LE(BigInt(put(table)), 24);
      table.writeBigUInt64LE(BigInt(pieces.length), 0);
      pieces.forEach((p, i) => table.writeBigUInt64LE(BigInt(put(p)), 8 + 8 * i));
      table.writeBigUInt64LE(BigInt(at0()), 8 + 8 * pieces.length);
    }
    h.writeBigUInt64LE(BigInt(node.size ?? content.length), 32);
    if (node.children?.length) h.writeBigUInt64LE(BigInt(chain(put, at0, chunkSize, node.children, addr)), 8);
  }
  return first;
}

/** The segment files of an image's data, each `segmentBytes` long at most, header included (FTK Imager's default: 1500 MB). */
export function ad1Segments(data: Buffer, segmentBytes = 1500 * 1024 * 1024): Buffer[] {
  const span = segmentBytes - 512;
  const count = Math.max(1, Math.ceil(data.length / span));
  const out: Buffer[] = [];
  for (let k = 0; k < count; k += 1) {
    const head = Buffer.alloc(512);
    head.write("ADSEGMENTEDFILE", 0, "latin1");
    head.writeUInt32LE(1, 0x10);
    head.writeUInt32LE(2, 0x14);
    head.writeUInt32LE(k + 1, 0x18);
    head.writeUInt32LE(count, 0x1c);
    head.writeBigUInt64LE(BigInt(segmentBytes), 0x20);
    head.writeUInt32LE(512, 0x28);
    out.push(Buffer.concat([head, data.subarray(k * span, (k + 1) * span)]));
  }
  return out;
}

/** One-segment image of a tree. */
export function ad1Image(tree: Ad1Node[], opts: { chunkSize?: number; version?: number; source?: string } = {}): Buffer {
  return ad1Segments(ad1Data(tree, opts).data)[0];
}
