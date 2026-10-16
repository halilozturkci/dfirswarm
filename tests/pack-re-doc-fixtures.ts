/**
 * Fixtures for doc_structure, built from the format specifications and never from the tool's output:
 *   - OLE compound files: [MS-CFB] (the 512-byte header, the FAT, the DIFAT, the mini FAT, 128-byte directory entries
 *     whose siblings form a binary tree, the mini stream below the 4096-byte cutoff);
 *   - VBA projects: [MS-OVBA] (the dir stream's records, a module stream = a cache + a compressed container, and a
 *     compressor that writes literal tokens, plus a hand-made copy token);
 *   - the encryption structures: [MS-OFFCRYPTO] EncryptionInfo (standard and agile), [MS-DOC] FIB flags, [MS-XLS]
 *     FILEPASS and BOUNDSHEET8, [MS-PPT] CurrentUserAtom;
 *   - PDF: ISO 32000-1 (objects, xref tables and streams, trailers, incremental updates, object streams);
 *   - RTF: the RTF specification (groups, control words, \binN, \object/\objdata hex data) and [MS-OLEDS] ObjectHeader.
 */
import { deflateSync } from "node:zlib";
import { u16, u32, u64 } from "./pack-re-harness.ts";

// --- MS-CFB --------------------------------------------------------------------------------------------------------------

export type OleNode = { name: string; data?: Buffer; children?: OleNode[]; clsid?: Buffer; created?: bigint; modified?: bigint };
export type CfbOptions = {
  major?: 3 | 4;
  /** Entries written but linked from no storage (orphans), in the root's directory. */
  orphans?: OleNode[];
  /** Extra 128-byte directory records appended raw (to build hostile directories). */
  rawEntries?: Buffer[];
  rootClsid?: Buffer;
  rootModified?: bigint;
};

const FREESECT = 0xffffffff, ENDOFCHAIN = 0xfffffffe, FATSECT = 0xfffffffd, DIFSECT = 0xfffffffc, NOSTREAM = 0xffffffff;

function compareNames(a: string, b: string): number {
  // [MS-CFB] 2.6.4: shorter names sort first, then by upper-cased UTF-16 code units.
  if (a.length !== b.length) return a.length - b.length;
  const x = a.toUpperCase(), y = b.toUpperCase();
  return x < y ? -1 : x > y ? 1 : 0;
}

function dirEntry(name: string, kind: number, o: { left?: number; right?: number; child?: number; start?: number; size?: bigint | number; clsid?: Buffer; created?: bigint; modified?: bigint }): Buffer {
  const e = Buffer.alloc(128);
  const raw = Buffer.from(name, "utf16le");
  if (raw.length > 62) throw new Error("name too long");
  raw.copy(e, 0);
  e.writeUInt16LE(kind === 0 ? 0 : raw.length + 2, 64);
  e[66] = kind;
  e[67] = 1; // black
  e.writeUInt32LE(o.left ?? NOSTREAM, 68);
  e.writeUInt32LE(o.right ?? NOSTREAM, 72);
  e.writeUInt32LE(o.child ?? NOSTREAM, 76);
  if (o.clsid) o.clsid.copy(e, 80);
  e.writeBigUInt64LE(o.created ?? 0n, 100);
  e.writeBigUInt64LE(o.modified ?? 0n, 108);
  e.writeUInt32LE(o.start ?? 0, 116);
  e.writeBigUInt64LE(BigInt(o.size ?? 0), 120);
  return e;
}

type Flat = { node: OleNode; kind: 1 | 2; sid: number; children: Flat[] };

export function buildCfb(top: OleNode[], o: CfbOptions = {}): Buffer {
  const major = o.major ?? 3;
  const ss = major === 3 ? 512 : 4096;
  // 1. Flatten: sid 0 is the root; the rest are numbered depth-first.
  const flat: Flat[] = [];
  const make = (nodes: OleNode[]): Flat[] =>
    nodes.map((node) => {
      const f: Flat = { node, kind: node.children ? 1 : 2, sid: 0, children: [] };
      return f;
    });
  const number = (list: Flat[]): void => {
    for (const f of list) {
      f.sid = flat.length + 1;
      flat.push(f);
      if (f.node.children) {
        f.children = make(f.node.children);
        number(f.children);
      }
    }
  };
  const roots = make(top);
  number(roots);
  const orphanFlat = make(o.orphans ?? []);
  for (const f of orphanFlat) {
    f.sid = flat.length + 1;
    flat.push(f);
  }
  // 2. Streams: below the cutoff -> the mini stream; otherwise regular sectors.
  const mini: Buffer[] = [];
  const miniFat: number[] = [];
  const startOf = new Map<Flat, number>();
  const regular: { f: Flat; data: Buffer }[] = [];
  for (const f of flat) {
    if (f.kind !== 2) continue;
    const data = f.node.data ?? Buffer.alloc(0);
    if (data.length === 0) continue;
    if (data.length < 4096) {
      const count = Math.ceil(data.length / 64);
      const first = miniFat.length;
      for (let i = 0; i < count; i++) {
        miniFat.push(i === count - 1 ? ENDOFCHAIN : first + i + 1);
        const piece = Buffer.alloc(64);
        data.subarray(i * 64, (i + 1) * 64).copy(piece);
        mini.push(piece);
      }
      startOf.set(f, first);
    } else regular.push({ f, data });
  }
  const miniStream = Buffer.concat(mini);
  const perSector = ss / 4;
  const miniFatSectors = Math.ceil(miniFat.length / perSector);
  const miniStreamSectors = Math.ceil(miniStream.length / ss);
  const dirCount = 1 + flat.length + (o.rawEntries?.length ?? 0);
  const dirSectors = Math.ceil(dirCount / (ss / 128));
  const regSectors = regular.map((r) => Math.ceil(r.data.length / ss));
  const dataSectors = dirSectors + miniFatSectors + miniStreamSectors + regSectors.reduce((a, b) => a + b, 0);
  // 3. How many FAT (and DIFAT) sectors: they are in the FAT themselves.
  let fatSectors = 1, difatSectors = 0;
  for (;;) {
    difatSectors = fatSectors > 109 ? Math.ceil((fatSectors - 109) / (perSector - 1)) : 0;
    const total = fatSectors + difatSectors + dataSectors;
    if (fatSectors * perSector >= total) break;
    fatSectors++;
  }
  // 4. Sector numbers.
  let next = 0;
  const fatIds = Array.from({ length: fatSectors }, () => next++);
  const difatIds = Array.from({ length: difatSectors }, () => next++);
  const dirIds = Array.from({ length: dirSectors }, () => next++);
  const miniFatIds = Array.from({ length: miniFatSectors }, () => next++);
  const miniStreamIds = Array.from({ length: miniStreamSectors }, () => next++);
  const regIds = regSectors.map((n) => Array.from({ length: n }, () => next++));
  const fat = new Array<number>(fatSectors * perSector).fill(FREESECT);
  for (const id of fatIds) fat[id] = FATSECT;
  for (const id of difatIds) fat[id] = DIFSECT;
  const chain = (ids: number[]): void => ids.forEach((id, i) => (fat[id] = i === ids.length - 1 ? ENDOFCHAIN : ids[i + 1]!));
  chain(dirIds);
  chain(miniFatIds);
  chain(miniStreamIds);
  regIds.forEach(chain);
  regular.forEach((r, i) => startOf.set(r.f, regIds[i]![0]!));
  // 5. The directory: each storage's children form a binary tree built from the sorted names.
  const entries: Buffer[] = [];
  const treeRoot = (list: Flat[]): { root: number; links: Map<Flat, [number, number]> } => {
    const sorted = [...list].sort((a, b) => compareNames(a.node.name, b.node.name));
    const links = new Map<Flat, [number, number]>();
    const build = (lo: number, hi: number): number => {
      if (lo > hi) return NOSTREAM;
      const mid = (lo + hi) >> 1;
      const f = sorted[mid]!;
      links.set(f, [build(lo, mid - 1), build(mid + 1, hi)]);
      return f.sid;
    };
    return { root: build(0, sorted.length - 1), links };
  };
  const allLinks = new Map<Flat, [number, number]>();
  const rootTree = treeRoot(roots);
  rootTree.links.forEach((v, k) => allLinks.set(k, v));
  const childRoot = new Map<Flat, number>();
  const visit = (list: Flat[]): void => {
    for (const f of list) {
      if (f.children.length) {
        const t = treeRoot(f.children);
        t.links.forEach((v, k) => allLinks.set(k, v));
        childRoot.set(f, t.root);
        visit(f.children);
      }
    }
  };
  visit(roots);
  entries.push(dirEntry("Root Entry", 5, { child: roots.length ? rootTree.root : NOSTREAM, start: miniStreamIds.length ? miniStreamIds[0]! : ENDOFCHAIN, size: miniStream.length, clsid: o.rootClsid, modified: o.rootModified }));
  for (const f of flat) {
    const [left, right] = allLinks.get(f) ?? [NOSTREAM, NOSTREAM];
    const isOrphan = orphanFlat.includes(f);
    entries.push(
      dirEntry(f.node.name, f.kind, {
        left: isOrphan ? NOSTREAM : left,
        right: isOrphan ? NOSTREAM : right,
        child: f.kind === 1 ? childRoot.get(f) ?? NOSTREAM : NOSTREAM,
        start: f.kind === 2 ? (startOf.get(f) ?? ENDOFCHAIN) : 0,
        size: f.kind === 2 ? (f.node.data?.length ?? 0) : 0,
        clsid: f.node.clsid,
        created: f.node.created,
        modified: f.node.modified,
      }),
    );
  }
  for (const raw of o.rawEntries ?? []) entries.push(raw);
  while (entries.length % (ss / 128)) entries.push(dirEntry("", 0, {}));
  // 6. Assemble the sectors.
  const total = next;
  const body = Buffer.alloc(total * ss);
  const put = (id: number, data: Buffer): void => void data.copy(body, id * ss);
  fatIds.forEach((id, i) => {
    const b = Buffer.alloc(ss);
    for (let k = 0; k < perSector; k++) b.writeUInt32LE(fat[i * perSector + k]! >>> 0, k * 4);
    put(id, b);
  });
  difatIds.forEach((id, i) => {
    const b = Buffer.alloc(ss, 0xff);
    const from = 109 + i * (perSector - 1);
    for (let k = 0; k < perSector - 1; k++) b.writeUInt32LE((fatIds[from + k] ?? FREESECT) >>> 0, k * 4);
    b.writeUInt32LE((i === difatIds.length - 1 ? ENDOFCHAIN : difatIds[i + 1]!) >>> 0, (perSector - 1) * 4);
    put(id, b);
  });
  dirIds.forEach((id, i) => put(id, Buffer.concat(entries).subarray(i * ss, (i + 1) * ss)));
  miniFatIds.forEach((id, i) => {
    const b = Buffer.alloc(ss, 0xff);
    for (let k = 0; k < perSector; k++) if (miniFat[i * perSector + k] !== undefined) b.writeUInt32LE(miniFat[i * perSector + k]! >>> 0, k * 4);
    put(id, b);
  });
  miniStreamIds.forEach((id, i) => put(id, miniStream.subarray(i * ss, (i + 1) * ss)));
  regular.forEach((r, i) => regIds[i]!.forEach((id, k) => put(id, r.data.subarray(k * ss, (k + 1) * ss))));
  // 7. The header.
  const head = Buffer.alloc(512);
  Buffer.from("d0cf11e0a1b11ae1", "hex").copy(head, 0);
  head.writeUInt16LE(0x003e, 24);
  head.writeUInt16LE(major, 26);
  head.writeUInt16LE(0xfffe, 28);
  head.writeUInt16LE(major === 3 ? 9 : 12, 30);
  head.writeUInt16LE(6, 32);
  head.writeUInt32LE(major === 4 ? dirSectors : 0, 40);
  head.writeUInt32LE(fatSectors, 44);
  head.writeUInt32LE(dirIds[0]!, 48);
  head.writeUInt32LE(4096, 56);
  head.writeUInt32LE(miniFatIds.length ? miniFatIds[0]! : ENDOFCHAIN, 60);
  head.writeUInt32LE(miniFatSectors, 64);
  head.writeUInt32LE(difatIds.length ? difatIds[0]! : ENDOFCHAIN, 68);
  head.writeUInt32LE(difatSectors, 72);
  for (let k = 0; k < 109; k++) head.writeUInt32LE((fatIds[k] ?? FREESECT) >>> 0, 76 + k * 4);
  const first = major === 4 ? Buffer.concat([head, Buffer.alloc(4096 - 512)]) : head;
  return Buffer.concat([first, body]);
}

/** The offset of sector `n` in a built file (header sector included). */
export const sectorAt = (n: number, major: 3 | 4 = 3): number => (n + 1) * (major === 3 ? 512 : 4096);

/** A FILETIME for a UTC instant given in milliseconds. */
export const filetime = (ms: number): bigint => (BigInt(ms) + 11644473600000n) * 10000n;

// --- MS-OVBA -------------------------------------------------------------------------------------------------------------

/** A compressed container made of literal tokens only: valid, and independent of the decompressor's copy handling. */
export function ovbaCompress(data: Buffer): Buffer {
  const chunks: Buffer[] = [Buffer.from([1])];
  for (let at = 0; at < data.length || at === 0; at += 3640) {
    const piece = data.subarray(at, at + 3640);
    const body: number[] = [];
    for (let i = 0; i < piece.length; i += 8) {
      body.push(0);
      for (const b of piece.subarray(i, i + 8)) body.push(b);
    }
    const size = body.length + 2;
    chunks.push(u16(((size - 3) & 0x0fff) | (3 << 12) | 0x8000), Buffer.from(body));
    if (piece.length === 0) break;
  }
  return Buffer.concat(chunks);
}

/** One chunk whose last six bytes are a copy token: "abcabcabc". */
export const OVBA_COPY_CHUNK = Buffer.concat([Buffer.from([1]), u16(((8 - 3) & 0x0fff) | (3 << 12) | 0x8000), Buffer.from([0x08, 0x61, 0x62, 0x63, 0x03, 0x20])]);

function rec(id: number, data: Buffer | string = Buffer.alloc(0)): Buffer {
  const d = typeof data === "string" ? Buffer.from(data, "latin1") : data;
  return Buffer.concat([u16(id), u32(d.length), d]);
}

export type VbaModule = { name: string; source: Buffer | string; type?: "procedural" | "class"; cache?: Buffer; compressed?: Buffer };

/** The decompressed `dir` stream of a VBA project ([MS-OVBA] 2.3.4.2). */
export function vbaDirStream(modules: VbaModule[], cacheLens: number[], o: { declared?: number; codepage?: number; name?: string } = {}): Buffer {
  const parts: Buffer[] = [
    rec(0x0001, u32(1)), rec(0x0002, u32(0x409)), rec(0x0014, u32(0x409)), rec(0x0003, u16(o.codepage ?? 1252)),
    rec(0x0004, o.name ?? "VBAProject"), rec(0x0005), rec(0x0040), rec(0x0006), rec(0x003d), rec(0x0007, u32(0)), rec(0x0008, u32(2)),
    // PROJECTVERSION: Id, Reserved (4), VersionMajor (4), VersionMinor (2)
    Buffer.concat([u16(0x0009), u32(4), u32(1), u16(1)]),
    rec(0x000c), rec(0x003c),
    rec(0x0016, "stdole"), rec(0x003e, Buffer.from("stdole", "utf16le")),
    rec(0x000d, Buffer.concat([u32(4), Buffer.from("*\\G{}"), u32(0), u16(0)])),
    rec(0x000f, u16(o.declared ?? modules.length)), rec(0x0013, u16(0xffff)),
  ];
  modules.forEach((m, i) => {
    parts.push(
      rec(0x0019, m.name), rec(0x0047, Buffer.from(m.name, "utf16le")), rec(0x001a, m.name), rec(0x0032, Buffer.from(m.name, "utf16le")),
      rec(0x001c), rec(0x0048), rec(0x0031, u32(cacheLens[i]!)), rec(0x001e, u32(0)), rec(0x002c, u16(0xffff)),
      rec(m.type === "class" ? 0x0022 : 0x0021), rec(0x002b),
    );
  });
  parts.push(rec(0x0010));
  return Buffer.concat(parts);
}

/** A vbaProject.bin-shaped compound file: VBA/dir, VBA/_VBA_PROJECT, VBA/<modules>, PROJECT. */
export function buildVbaProject(modules: VbaModule[], o: { project?: string; declared?: number; storage?: string; major?: 3 | 4 } = {}): Buffer {
  const cacheLens = modules.map((m) => (m.cache ?? Buffer.alloc(24, 0xab)).length);
  const vba: OleNode = {
    name: "VBA",
    children: [
      { name: "dir", data: ovbaCompress(vbaDirStream(modules, cacheLens, { declared: o.declared })) },
      { name: "_VBA_PROJECT", data: Buffer.concat([u16(0x61cc), u16(0xffff), Buffer.from([0]), u16(0), Buffer.alloc(40, 0x11)]) },
      ...modules.map((m, i) => ({
        name: m.name,
        data: Buffer.concat([m.cache ?? Buffer.alloc(24, 0xab), m.compressed ?? ovbaCompress(typeof m.source === "string" ? Buffer.from(m.source, "latin1") : m.source)]),
      })),
    ],
  };
  const project: OleNode = { name: "PROJECT", data: Buffer.from(o.project ?? 'ID="{00000000-0000-0000-0000-000000000000}"\r\nModule=Module1\r\nName="VBAProject"\r\n', "latin1") };
  const tree: OleNode[] = o.storage ? [{ name: o.storage, children: [vba, project] }] : [vba, project];
  return buildCfb(tree, { major: o.major });
}

// --- encryption structures ----------------------------------------------------------------------------------------------

/** [MS-OFFCRYPTO] 2.3.3 standard EncryptionInfo with a recognisable salt and verifier. */
export function standardEncryptionInfo(o: { alg?: number; hash?: number; bits?: number; salt?: Buffer; verifier?: Buffer; verifierHash?: Buffer } = {}): Buffer {
  const header = Buffer.concat([u32(0x24), u32(0), u32(o.alg ?? 0x660e), u32(o.hash ?? 0x8004), u32(o.bits ?? 128), u32(0x18), u32(0), u32(0), Buffer.from("Microsoft Enhanced RSA and AES Cryptographic Provider\0", "utf16le")]);
  const verifier = Buffer.concat([u32(16), o.salt ?? Buffer.from("SALTSALTSALTSALT"), o.verifier ?? Buffer.from("VERIFIERVERIFIER"), u32(20), o.verifierHash ?? Buffer.from("VERIFIERHASH_32BYTES_VERIFIERHAS")]);
  return Buffer.concat([u16(3), u16(2), u32(0x24), u32(header.length), header, verifier]);
}

/** [MS-OFFCRYPTO] 2.3.4.10 agile EncryptionInfo: version 4.4, reserved 0x40, then the XML descriptor. */
export function agileEncryptionInfo(o: { keyBits?: number; spin?: number; salt?: string; encryptedKey?: string } = {}): Buffer {
  const xml =
    `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>` +
    `<encryption xmlns="http://schemas.microsoft.com/office/2006/encryption" xmlns:p="http://schemas.microsoft.com/office/2006/keyEncryptor/password">` +
    `<keyData saltSize="16" blockSize="16" keyBits="${o.keyBits ?? 256}" hashSize="64" cipherAlgorithm="AES" cipherChaining="ChainingModeCBC" hashAlgorithm="SHA512" saltValue="${o.salt ?? "U0FMVFNBTFRTQUxUU0FMVA=="}"/>` +
    `<dataIntegrity encryptedHmacKey="ZW5jcnlwdGVkSG1hY0tleQ==" encryptedHmacValue="ZW5jcnlwdGVkSG1hY1ZhbHVl"/>` +
    `<keyEncryptors><keyEncryptor uri="http://schemas.microsoft.com/office/2006/keyEncryptor/password"><p:encryptedKey spinCount="${o.spin ?? 100000}" saltSize="16" blockSize="16" keyBits="${o.keyBits ?? 256}" hashSize="64" cipherAlgorithm="AES" cipherChaining="ChainingModeCBC" hashAlgorithm="SHA512" saltValue="${o.salt ?? "U0FMVFNBTFRTQUxUU0FMVA=="}" encryptedVerifierHashInput="${"VkVSSUZJRVJJTlBVVA=="}" encryptedVerifierHashValue="${o.encryptedKey ?? "VkVSSUZJRVJIQVNIVkFMVUU="}" encryptedKeyValue="RU5DUllQVEVES0VZVkFMVUU="/></keyEncryptor></keyEncryptors></encryption>`;
  return Buffer.concat([u16(4), u16(4), u32(0x40), Buffer.from(xml, "utf8")]);
}

/** [MS-DOC] 2.5.1 FIB base: wIdent, nFib, ..., the flags word at 0x0A (fEncrypted bit 8, fWhichTblStm bit 9, fObfuscated bit 15). */
export function wordFib(o: { encrypted?: boolean; obfuscated?: boolean; table1?: boolean } = {}): Buffer {
  const b = Buffer.alloc(512);
  b.writeUInt16LE(0xa5ec, 0);
  b.writeUInt16LE(0x00c1, 2);
  let flags = 0;
  if (o.encrypted) flags |= 0x0100;
  if (o.table1 ?? true) flags |= 0x0200;
  if (o.obfuscated) flags |= 0x8000;
  b.writeUInt16LE(flags, 0x0a);
  return b;
}

const biff = (type: number, data: Buffer): Buffer => Buffer.concat([u16(type), u16(data.length), data]);

/** [MS-XLS] a BIFF8 globals substream: BOF, an optional FILEPASS, BOUNDSHEET8 records, EOF. */
export function excelWorkbook(o: { filepass?: { type: 0 | 1; major?: number; minor?: number }; sheets?: { name: string; state?: number; kind?: number }[]; noEof?: boolean } = {}): Buffer {
  const parts: Buffer[] = [biff(0x0809, Buffer.concat([u16(0x0600), u16(0x0005), u16(0x0dbb), u16(0x07cc), u32(0), u32(0x06)]))];
  if (o.filepass) {
    parts.push(biff(0x002f, o.filepass.type === 0 ? Buffer.concat([u16(0), u16(0x1234), u16(0x5678)]) : Buffer.concat([u16(1), u16(o.filepass.major ?? 1), u16(o.filepass.minor ?? 1), Buffer.alloc(48, 0x77)])));
  }
  for (const s of o.sheets ?? []) {
    parts.push(biff(0x0085, Buffer.concat([u32(0x1000), Buffer.from([s.state ?? 0, s.kind ?? 0]), Buffer.from([s.name.length, 1]), Buffer.from(s.name, "utf16le")])));
  }
  if (!o.noEof) parts.push(biff(0x000a, Buffer.alloc(0)));
  return Buffer.concat(parts);
}

/** [MS-PPT] 2.3.2 CurrentUserAtom: record header, size 0x14, headerToken, ... */
export function currentUser(token: number): Buffer {
  return Buffer.concat([u16(0), u16(0x0ff6), u32(0x1c), u32(0x14), u32(token), Buffer.alloc(16)]);
}

// --- PDF -----------------------------------------------------------------------------------------------------------------

export type PdfObj = { num: number; body: string; stream?: Buffer; gen?: number; extra?: string };

/** The bytes of `1 0 obj ... endobj`, with a stream when given (the dictionary's /Length is written unless the body already holds one). */
export function pdfObject(o: PdfObj): Buffer {
  const head = `${o.num} ${o.gen ?? 0} obj\n`;
  if (!o.stream) return Buffer.from(`${head}${o.body}\nendobj\n`, "latin1");
  const dict = /\/Length\b/.test(o.body) ? o.body : o.body.replace(/>>\s*$/, ` /Length ${o.stream.length} >>`);
  return Buffer.concat([Buffer.from(`${head}${dict}\nstream\n`, "latin1"), o.stream, Buffer.from("\nendstream\nendobj\n", "latin1")]);
}

/** A PDF with a classic cross-reference table over the objects given, in the order given. */
export function buildPdf(objects: PdfObj[], trailer: string, o: { header?: string; prefix?: Buffer; free?: number[] } = {}): { file: Buffer; offsets: Map<number, number>; xrefAt: number } {
  const parts: Buffer[] = [Buffer.from(o.header ?? "%PDF-1.7\n%\xe2\xe3\xcf\xd3\n", "latin1")];
  let at = parts[0]!.length;
  const offsets = new Map<number, number>();
  for (const ob of objects) {
    offsets.set(ob.num, at);
    const b = pdfObject(ob);
    parts.push(b);
    at += b.length;
  }
  const max = Math.max(...objects.map((x) => x.num)) + 1;
  let xref = `xref\n0 ${max}\n`;
  for (let n = 0; n < max; n++) {
    const off = offsets.get(n);
    xref += n === 0 || off === undefined ? `0000000000 ${n === 0 ? "65535" : "00000"} f \n` : `${String(off).padStart(10, "0")} 00000 n \n`;
  }
  const body = Buffer.from(`${xref}trailer\n<< /Size ${max} ${trailer} >>\nstartxref\n${at}\n%%EOF\n`, "latin1");
  return { file: Buffer.concat([...(o.prefix ? [o.prefix] : []), ...parts, body]), offsets, xrefAt: at };
}

/** A PDF 1.5 file whose cross-reference is a stream (W [1 2 1], Flate, PNG Up predictor) and whose objects 3.. may sit in an object stream. */
export function buildPdfWithStreams(o: { objstmExtra?: Buffer } = {}): { file: Buffer; objstmNum: number; compressed: number[] } {
  // Objects: 1 catalog, 2 pages, 4 an object stream holding objects 5 (page) and 6 (an action dictionary); 7 the xref stream.
  const inner = ["<< /Type /Page /Parent 2 0 R /Annots [ 6 0 R ] >>", "<< /S /URI /URI (http://example.test/x) >>"];
  let header = "";
  let bodyText = "";
  const nums = [5, 6];
  inner.forEach((text, i) => {
    header += `${nums[i]} ${bodyText.length} `;
    bodyText += text + "\n";
  });
  const objstmData = deflateSync(Buffer.concat([Buffer.from(header + bodyText, "latin1"), o.objstmExtra ?? Buffer.alloc(0)]));
  const parts: Buffer[] = [Buffer.from("%PDF-1.5\n%\xe2\xe3\xcf\xd3\n", "latin1")];
  let at = parts[0]!.length;
  const offs = new Map<number, number>();
  const add = (o: PdfObj): void => {
    offs.set(o.num, at);
    const b = pdfObject(o);
    parts.push(b);
    at += b.length;
  };
  add({ num: 1, body: "<< /Type /Catalog /Pages 2 0 R /OpenAction 6 0 R >>" });
  add({ num: 2, body: "<< /Type /Pages /Kids [ 5 0 R ] /Count 1 >>" });
  add({ num: 4, body: `<< /Type /ObjStm /N 2 /First ${header.length} /Filter /FlateDecode >>`, stream: objstmData });
  // The xref stream: entries for objects 0..7 as (type, field2, field3), each row 4 bytes, with the PNG "Up" predictor (filter byte 2).
  const xrefAt = at;
  const rows: number[][] = [
    [0, 0, 255],
    [1, offs.get(1)!, 0],
    [1, offs.get(2)!, 0],
    [0, 0, 0],
    [1, offs.get(4)!, 0],
    [2, 4, 0],
    [2, 4, 1],
    [1, xrefAt, 0],
  ];
  const raw = rows.map((r) => Buffer.from([r[0]!, (r[1]! >> 8) & 0xff, r[1]! & 0xff, r[2]!]));
  const filtered: Buffer[] = [];
  let prev = Buffer.alloc(4);
  for (const row of raw) {
    filtered.push(Buffer.concat([Buffer.from([2]), Buffer.from(row.map((b, i) => (b - prev[i]! + 256) & 0xff))]));
    prev = row;
  }
  add({
    num: 7,
    body: `<< /Type /XRef /Size 8 /W [1 2 1] /Root 1 0 R /Filter /FlateDecode /DecodeParms << /Predictor 12 /Columns 4 >> >>`,
    stream: deflateSync(Buffer.concat(filtered)),
  });
  parts.push(Buffer.from(`startxref\n${xrefAt}\n%%EOF\n`, "latin1"));
  return { file: Buffer.concat(parts), objstmNum: 4, compressed: [5, 6] };
}

// --- RTF + OLE 1.0 ---------------------------------------------------------------------------------------------------------

/** [MS-OLEDS] 2.2.4 ObjectHeader + native data, as an embedded object (format ID 2). */
export function ole1Object(className: string, native: Buffer): Buffer {
  const lps = (s: string): Buffer => Buffer.concat([u32(s.length + 1), Buffer.from(s + "\0", "latin1")]);
  return Buffer.concat([u32(0x501), u32(2), lps(className), u32(0), u32(0), u32(native.length), native]);
}

export const hex = (b: Buffer, wrap = 0): string => {
  const h = b.toString("hex");
  return wrap ? h.replace(new RegExp(`(.{${wrap}})`, "g"), "$1\n") : h;
};

export { u16, u32, u64 };

// --- PE data directories (Microsoft PE/COFF specification) -----------------------------------------------------------------

export type PeDirOptions = {
  plus?: boolean;
  imageBase?: number;
  exports?: { imageName?: string; base?: number; stamp?: number; functions: { name?: string; rva?: number; forward?: string }[] };
  delayImports?: { dll: string; functions: (string | number)[]; vaForm?: boolean }[];
  tlsCallbacks?: number[];                 // RVAs inside .text
  resources?: { type: number | string; name: number | string; lang: number; data: Buffer; declaredSize?: number }[];
  clr?: { flags?: number; entryToken?: number; version?: string; streams?: { name: string; size: number }[]; strongName?: boolean; managedNative?: Buffer; noMetadata?: boolean; badSignature?: boolean };
  debug?: { type: number; stamp?: number; guid?: Buffer; age?: number; pdb?: string }[];
  rich?: { key: number; entries: [number, number][]; breakPadding?: boolean };
  exportDirSizeOverride?: number;
};

export type BuiltPeDirs = { file: Buffer; rdataRva: number; rsrcRva: number; textRva: number; rvas: Record<string, number>; rawOf: (rva: number) => number };

const utf16z = (s: string): Buffer => Buffer.from(s + "\0", "utf16le");
const align = (n: number, a: number): number => Math.ceil(n / a) * a;
const padTo = (b: Buffer, a: number): Buffer => (b.length % a ? Buffer.concat([b, Buffer.alloc(a - (b.length % a))]) : b);

/** [VS_VERSIONINFO] a block: wLength, wValueLength, wType, the key, padding, the value, padding, the children. */
export function vsBlock(key: string, value: Buffer, children: Buffer[], o: { text?: boolean; valueLength?: number } = {}): Buffer {
  const head = padTo(Buffer.concat([Buffer.alloc(6), utf16z(key)]), 4);
  const body = padTo(Buffer.concat([head, value]), 4);
  const kids = Buffer.concat(children.map((c) => padTo(c, 4)));
  const all = Buffer.concat([body, kids]);
  all.writeUInt16LE(all.length, 0);
  all.writeUInt16LE(o.valueLength ?? value.length, 2);
  all.writeUInt16LE(o.text ? 1 : 0, 4);
  return all;
}

export function versionResource(o: { fileVersion?: [number, number, number, number]; productVersion?: [number, number, number, number]; strings?: Record<string, string>; flags?: number } = {}): Buffer {
  const fv = o.fileVersion ?? [1, 2, 3, 4], pv = o.productVersion ?? [5, 6, 7, 8];
  const fixed = Buffer.alloc(52);
  fixed.writeUInt32LE(0xfeef04bd, 0);
  fixed.writeUInt32LE(0x00010000, 4);
  fixed.writeUInt32LE(((fv[0] << 16) | fv[1]) >>> 0, 8);
  fixed.writeUInt32LE(((fv[2] << 16) | fv[3]) >>> 0, 12);
  fixed.writeUInt32LE(((pv[0] << 16) | pv[1]) >>> 0, 16);
  fixed.writeUInt32LE(((pv[2] << 16) | pv[3]) >>> 0, 20);
  fixed.writeUInt32LE(0x3f, 24);
  fixed.writeUInt32LE(o.flags ?? 0, 28);
  fixed.writeUInt32LE(0x00040004, 32);
  fixed.writeUInt32LE(1, 36);
  const strings = Object.entries(o.strings ?? { CompanyName: "Example Corp", OriginalFilename: "tool.exe", FileDescription: "A tool" }).map(([k, v]) => vsBlock(k, utf16z(v), [], { text: true, valueLength: v.length + 1 }));
  const table = vsBlock("040904b0", Buffer.alloc(0), strings, { text: true });
  const sfi = vsBlock("StringFileInfo", Buffer.alloc(0), [table], { text: true });
  const vfi = vsBlock("VarFileInfo", Buffer.alloc(0), [vsBlock("Translation", Buffer.from([9, 4, 0xb0, 4]), [])], { text: true });
  return vsBlock("VS_VERSION_INFO", fixed, [sfi, vfi]);
}

export function buildPeDirs(o: PeDirOptions = {}): BuiltPeDirs {
  const plus = o.plus ?? true;
  const base = o.imageBase ?? (plus ? 0x140000000 : 0x400000);
  const ptr = plus ? 8 : 4;
  const TEXT_RVA = 0x1000, RDATA_RVA = 0x2000, RSRC_RVA = 0x5000;
  const FILE_ALIGN = 0x200;
  const rvas: Record<string, number> = {};
  // .rdata: a growing blob; alloc returns the RVA of what is appended.
  const rdata: Buffer[] = [];
  let rlen = 0;
  const alloc = (b: Buffer, a = 4): number => {
    const pad = align(rlen, a) - rlen;
    if (pad) { rdata.push(Buffer.alloc(pad)); rlen += pad; }
    const rva = RDATA_RVA + rlen;
    rdata.push(b);
    rlen += b.length;
    return rva;
  };
  const dirs: Array<[number, number]> = Array.from({ length: 16 }, () => [0, 0]);

  // exports: one blob so that a forwarder string lies inside the directory's range
  if (o.exports) {
    const fns = o.exports.functions;
    const named = fns.map((f, i) => ({ f, i })).filter((x) => x.f.name !== undefined).sort((a, b) => (a.f.name! < b.f.name! ? -1 : 1));
    const dirLen = 40, eatLen = 4 * fns.length, namesLen = 4 * named.length, ordLen = 2 * named.length;
    let strOff = dirLen + eatLen + namesLen + ordLen;
    const blob: Buffer[] = [];
    const strings: Buffer[] = [];
    const putString = (s: string): number => { const off = strOff; const b = Buffer.from(s + "\0", "utf8"); strings.push(b); strOff += b.length; return off; };
    const imageNameOff = putString(o.exports.imageName ?? "sample.dll");
    const nameOffs = named.map((x) => putString(x.f.name!));
    const fwdOffs = fns.map((f) => (f.forward !== undefined ? putString(f.forward) : -1));
    const start = align(rlen, 4);
    const exportRva = RDATA_RVA + start;
    const dir = Buffer.alloc(40);
    dir.writeUInt32LE(o.exports.stamp ?? 0, 4);
    dir.writeUInt32LE(exportRva + imageNameOff, 12);
    dir.writeUInt32LE(o.exports.base ?? 1, 16);
    dir.writeUInt32LE(fns.length, 20);
    dir.writeUInt32LE(named.length, 24);
    dir.writeUInt32LE(exportRva + dirLen, 28);
    dir.writeUInt32LE(exportRva + dirLen + eatLen, 32);
    dir.writeUInt32LE(exportRva + dirLen + eatLen + namesLen, 36);
    const eat = Buffer.alloc(eatLen);
    fns.forEach((f, i) => eat.writeUInt32LE(f.forward !== undefined ? exportRva + fwdOffs[i]! : (f.rva ?? TEXT_RVA), i * 4));
    const names = Buffer.alloc(namesLen);
    named.forEach((_x, j) => names.writeUInt32LE(exportRva + nameOffs[j]!, j * 4));
    const ords = Buffer.alloc(ordLen);
    named.forEach((x, j) => ords.writeUInt16LE(x.i, j * 2));
    blob.push(dir, eat, names, ords, ...strings);
    const all = Buffer.concat(blob);
    alloc(all, 4);
    rvas.exports = exportRva;
    dirs[0] = [exportRva, o.exportDirSizeOverride ?? all.length];
  }

  // delay imports
  if (o.delayImports) {
    const descs = Buffer.alloc(32 * (o.delayImports.length + 1));
    const pieces = o.delayImports.map((d) => {
      const nameRva = alloc(Buffer.from(d.dll + "\0"));
      const hintRvas = d.functions.map((fn) => (typeof fn === "string" ? alloc(Buffer.concat([u16(0), Buffer.from(fn + "\0")]), 2) : 0));
      const thunks = Buffer.alloc(ptr * (d.functions.length + 1));
      d.functions.forEach((fn, k) => {
        const v = typeof fn === "string" ? BigInt(d.vaForm ? hintRvas[k]! + base : hintRvas[k]!) : (1n << BigInt(ptr * 8 - 1)) | BigInt(fn);
        if (plus) thunks.writeBigUInt64LE(v, k * 8);
        else thunks.writeUInt32LE(Number(v), k * 4);
      });
      return { nameRva, intRva: alloc(thunks) };
    });
    const at = alloc(descs, 4);
    o.delayImports.forEach((d, i) => {
      const f = (rva: number): number => (d.vaForm ? rva + base : rva);
      descs.writeUInt32LE(d.vaForm ? 0 : 1, i * 32);
      descs.writeUInt32LE(f(pieces[i]!.nameRva), i * 32 + 4);
      descs.writeUInt32LE(f(pieces[i]!.intRva), i * 32 + 16);
    });
    rvas.delayImports = at;
    dirs[13] = [at, descs.length];
  }

  // TLS
  if (o.tlsCallbacks) {
    const arr = Buffer.alloc(ptr * (o.tlsCallbacks.length + 1));
    o.tlsCallbacks.forEach((rva, k) => (plus ? arr.writeBigUInt64LE(BigInt(base + rva), k * 8) : arr.writeUInt32LE(base + rva, k * 4)));
    const arrRva = alloc(arr, 8);
    const dir = Buffer.alloc(plus ? 40 : 24);
    if (plus) { dir.writeBigUInt64LE(BigInt(base + RDATA_RVA), 0); dir.writeBigUInt64LE(BigInt(base + RDATA_RVA + 16), 8); dir.writeBigUInt64LE(BigInt(base + RDATA_RVA + 32), 16); dir.writeBigUInt64LE(BigInt(base + arrRva), 24); }
    else { dir.writeUInt32LE(base + RDATA_RVA, 0); dir.writeUInt32LE(base + RDATA_RVA + 16, 4); dir.writeUInt32LE(base + RDATA_RVA + 32, 8); dir.writeUInt32LE(base + arrRva, 12); }
    const at = alloc(dir, 8);
    rvas.tls = at;
    dirs[9] = [at, dir.length];
  }

  // CLR
  if (o.clr) {
    const c = o.clr;
    const ver = Buffer.from((c.version ?? "v4.0.30319") + "\0");
    const verPadded = padTo(ver, 4);
    const streams = c.streams ?? [{ name: "#~", size: 0x100 }, { name: "#Strings", size: 0x80 }, { name: "#US", size: 8 }, { name: "#GUID", size: 16 }, { name: "#Blob", size: 0x40 }];
    const headers = Buffer.concat(streams.map((s) => Buffer.concat([u32(0x200), u32(s.size), padTo(Buffer.from(s.name + "\0"), 4)])));
    const root = Buffer.concat([u32(c.badSignature ? 0x11111111 : 0x424a5342), u16(1), u16(1), u32(0), u32(verPadded.length), verPadded, u16(0), u16(streams.length), headers]);
    const mdBlob = Buffer.concat([root, Buffer.alloc(0x400)]);
    const mdRva = c.noMetadata ? 0 : alloc(mdBlob, 4);
    const hdr = Buffer.alloc(72);
    hdr.writeUInt32LE(72, 0);
    hdr.writeUInt16LE(2, 4);
    hdr.writeUInt16LE(5, 6);
    hdr.writeUInt32LE(c.noMetadata ? 0x9fffff0 : mdRva, 8);
    hdr.writeUInt32LE(mdBlob.length, 12);
    hdr.writeUInt32LE(c.flags ?? 1, 16);
    hdr.writeUInt32LE(c.entryToken ?? 0x06000001, 20);
    if (c.strongName) { hdr.writeUInt32LE(RDATA_RVA, 32); hdr.writeUInt32LE(128, 36); }
    if (c.managedNative) { hdr.writeUInt32LE(alloc(c.managedNative, 4), 64); hdr.writeUInt32LE(c.managedNative.length, 68); }
    const at = alloc(hdr, 4);
    rvas.clr = at;
    dirs[14] = [at, 72];
  }

  // The resource section: [Microsoft PE/COFF] 5.9. Three directory levels (type, name, language), each a 16-byte header and 8-byte entries
  // (named entries first, then id entries, each group sorted), then the name strings, the data entries and the data.
  let rsrc = Buffer.alloc(0);
  if (o.resources && o.resources.length) {
    type Leaf = NonNullable<PeDirOptions["resources"]>[number];
    type Id = number | string;
    const byType = new Map<Id, Map<Id, Leaf[]>>();
    for (const r of o.resources) {
      const names = byType.get(r.type) ?? new Map<Id, Leaf[]>();
      byType.set(r.type, names);
      names.set(r.name, [...(names.get(r.name) ?? []), r]);
    }
    const ordered = <T>(m: Map<Id, T>): Array<[Id, T]> => {
      const all = [...m.entries()];
      return [...all.filter(([k]) => typeof k === "string").sort((x, y) => (x[0] < y[0] ? -1 : 1)), ...all.filter(([k]) => typeof k === "number").sort((x, y) => (x[0] as number) - (y[0] as number))];
    };
    const types = ordered(byType);
    // sizes of the three levels, in layout order: the root, then for each type its name directory followed by its language directories
    let tree = 16 + 8 * types.length;
    const nameDirAt = new Map<Id, number>();
    const langDirAt = new Map<string, number>();
    for (const [t, names] of types) {
      nameDirAt.set(t, tree);
      tree += 16 + 8 * names.size;
      for (const [n, langs] of ordered(names)) {
        langDirAt.set(`${String(t)}|${String(n)}`, tree);
        tree += 16 + 8 * langs.length;
      }
    }
    const strings = new Map<string, number>();
    let cursor = tree;
    const stringBufs: Buffer[] = [];
    for (const [t, names] of types) {
      for (const id of [t, ...names.keys()]) {
        if (typeof id === "string" && !strings.has(id)) {
          const b = padTo(Buffer.concat([u16(id.length), Buffer.from(id, "utf16le")]), 4);
          strings.set(id, cursor);
          stringBufs.push(b);
          cursor += b.length;
        }
      }
    }
    const leafEntryAt = new Map<Leaf, number>();
    for (const r of o.resources) { leafEntryAt.set(r, cursor); cursor += 16; }
    const leafDataAt = new Map<Leaf, number>();
    for (const r of o.resources) { leafDataAt.set(r, cursor); cursor += align(r.data.length, 4); }
    const dir = (entries: Array<[Id, number, boolean]>): Buffer => {
      const named = entries.filter(([id]) => typeof id === "string").length;
      const b = Buffer.alloc(16 + 8 * entries.length);
      b.writeUInt16LE(named, 12);
      b.writeUInt16LE(entries.length - named, 14);
      entries.forEach(([id, target, sub], i) => {
        b.writeUInt32LE(typeof id === "string" ? (strings.get(id)! | 0x80000000) >>> 0 : id, 16 + 8 * i);
        b.writeUInt32LE(((sub ? 0x80000000 : 0) | target) >>> 0, 20 + 8 * i);
      });
      return b;
    };
    const dirs3: Buffer[] = [dir(types.map(([t]) => [t, nameDirAt.get(t)!, true]))];
    for (const [t, names] of types) {
      dirs3.push(dir(ordered(names).map(([n]) => [n, langDirAt.get(`${String(t)}|${String(n)}`)!, true] as [Id, number, boolean])));
      for (const [, langs] of ordered(names)) dirs3.push(dir(langs.map((r) => [r.lang, leafEntryAt.get(r)!, false] as [Id, number, boolean])));
    }
    const dataEntries = o.resources.map((r) => {
      const b = Buffer.alloc(16);
      b.writeUInt32LE(RSRC_RVA + leafDataAt.get(r)!, 0);
      b.writeUInt32LE(r.declaredSize ?? r.data.length, 4);
      b.writeUInt32LE(1252, 8);
      return b;
    });
    rsrc = Buffer.concat([...dirs3, ...stringBufs, ...dataEntries, ...o.resources.map((r) => padTo(r.data, 4))]);
    dirs[2] = [RSRC_RVA, rsrc.length];
    rvas.resources = RSRC_RVA;
  }

  // debug: the entries, then each CodeView record (its file offset is the raw pointer)
  if (o.debug) {
    const records = o.debug.map((d) => {
      if (d.type !== 2) return Buffer.alloc(8, 0x11);
      return Buffer.concat([Buffer.from("RSDS"), d.guid ?? Buffer.alloc(16, 0x22), u32(d.age ?? 1), Buffer.from((d.pdb ?? "C:\\build\\sample.pdb") + "\0", "utf8")]);
    });
    const recRvas = records.map((r) => alloc(r, 4));
    const table = Buffer.alloc(28 * o.debug.length);
    o.debug.forEach((d, i) => {
      table.writeUInt32LE(d.stamp ?? 0x65000000, i * 28 + 4);
      table.writeUInt32LE(d.type, i * 28 + 12);
      table.writeUInt32LE(records[i]!.length, i * 28 + 16);
      table.writeUInt32LE(recRvas[i]!, i * 28 + 20);
      table.writeUInt32LE(0, i * 28 + 24); // patched below, when the raw offsets are known
    });
    const at = alloc(table, 4);
    rvas.debug = at;
    dirs[6] = [at, table.length];
    (rvas as Record<string, number>)._debugTable = at - RDATA_RVA;
    (rvas as Record<string, number>)._debugCount = o.debug.length;
  }

  const rdataBuf = Buffer.concat(rdata);
  const text = Buffer.alloc(0x200, 0x90);
  // headers
  const rich = o.rich
    ? (() => {
        const words = [0x536e6144, 0, 0, 0, ...o.rich.entries.flat()].map((w, i) => ((i < 4 ? (i === 0 ? w : o.rich!.breakPadding && i === 1 ? 0x1234 : 0) : w) ^ o.rich!.key) >>> 0);
        const b = Buffer.alloc(words.length * 4 + 8);
        words.forEach((w, i) => b.writeUInt32LE(w, i * 4));
        b.write("Rich", words.length * 4, "latin1");
        b.writeUInt32LE(o.rich!.key >>> 0, words.length * 4 + 4);
        return b;
      })()
    : Buffer.alloc(0);
  const peAt = align(0x80 + rich.length, 8);
  const optSize = plus ? 240 : 224;
  const nSections = 2 + (rsrc.length ? 1 : 0);
  const headersEnd = peAt + 24 + optSize + 40 * nSections;
  const sizeOfHeaders = align(headersEnd, FILE_ALIGN);
  const textRaw = sizeOfHeaders;
  const rdataRaw = textRaw + align(text.length, FILE_ALIGN);
  const rsrcRaw = rdataRaw + align(rdataBuf.length, FILE_ALIGN);
  const rawOf = (rva: number): number => {
    if (rva >= RSRC_RVA && rsrc.length) return rsrcRaw + (rva - RSRC_RVA);
    if (rva >= RDATA_RVA) return rdataRaw + (rva - RDATA_RVA);
    return textRaw + (rva - TEXT_RVA);
  };
  if (o.debug) {
    const tableOff = rvas._debugTable!;
    o.debug.forEach((_d, i) => rdataBuf.writeUInt32LE(rdataRaw + (rdataBuf.readUInt32LE(tableOff + i * 28 + 20) - RDATA_RVA), tableOff + i * 28 + 24));
    delete rvas._debugTable;
    delete rvas._debugCount;
  }
  const file = Buffer.alloc((o.resources && rsrc.length ? rsrcRaw + align(rsrc.length, FILE_ALIGN) : rdataRaw + align(rdataBuf.length, FILE_ALIGN)));
  file.write("MZ", 0, "latin1");
  file.writeUInt32LE(peAt, 0x3c);
  rich.copy(file, 0x80);
  file.write("PE\0\0", peAt, "latin1");
  const coff = peAt + 4;
  file.writeUInt16LE(plus ? 0x8664 : 0x14c, coff);
  file.writeUInt16LE(nSections, coff + 2);
  file.writeUInt32LE(0x65000000, coff + 4);
  file.writeUInt16LE(optSize, coff + 16);
  file.writeUInt16LE(0x0022, coff + 18);
  const opt = coff + 20;
  file.writeUInt16LE(plus ? 0x20b : 0x10b, opt);
  file.writeUInt32LE(TEXT_RVA, opt + 16);
  if (plus) file.writeBigUInt64LE(BigInt(base), opt + 24);
  else file.writeUInt32LE(base, opt + 28);
  file.writeUInt32LE(0x1000, opt + 32);
  file.writeUInt32LE(FILE_ALIGN, opt + 36);
  file.writeUInt32LE(RSRC_RVA + align(Math.max(rsrc.length, 0x1000), 0x1000), opt + 56);
  file.writeUInt32LE(sizeOfHeaders, opt + 60);
  file.writeUInt16LE(3, opt + 68);
  file.writeUInt32LE(16, opt + (plus ? 108 : 92));
  dirs.forEach(([rva, size], i) => { file.writeUInt32LE(rva, opt + (plus ? 112 : 96) + i * 8); file.writeUInt32LE(size, opt + (plus ? 112 : 96) + i * 8 + 4); });
  const sec = opt + optSize;
  const section = (i: number, name: string, vaddr: number, vsize: number, raw: number, rawsize: number, flags: number): void => {
    const at = sec + 40 * i;
    file.write(name, at, "latin1");
    file.writeUInt32LE(vsize, at + 8);
    file.writeUInt32LE(vaddr, at + 12);
    file.writeUInt32LE(rawsize, at + 16);
    file.writeUInt32LE(raw, at + 20);
    file.writeUInt32LE(flags, at + 36);
  };
  section(0, ".text", TEXT_RVA, text.length, textRaw, align(text.length, FILE_ALIGN), 0x60000020);
  section(1, ".rdata", RDATA_RVA, rdataBuf.length, rdataRaw, align(rdataBuf.length, FILE_ALIGN), 0x40000040);
  if (rsrc.length) section(2, ".rsrc", RSRC_RVA, rsrc.length, rsrcRaw, align(rsrc.length, FILE_ALIGN), 0x40000040);
  text.copy(file, textRaw);
  rdataBuf.copy(file, rdataRaw);
  if (rsrc.length) rsrc.copy(file, rsrcRaw);
  return { file, rdataRva: RDATA_RVA, rsrcRva: RSRC_RVA, textRva: TEXT_RVA, rvas, rawOf };
}

/** A 40-character GitHub token shape, the run a string's address points right after in afterTokenRun. */
export const TOKEN_RUN = "ghp_" + "Q7wErTy9uIoP3aSdF6gHjK2lZxC5vBnM8qW1";

/** Exports named TOKEN_RUN + tail (one each) and as many short names whose pointers are then moved to the first byte after each TOKEN_RUN. */
export function afterTokenRun(tails: string[]): Buffer {
  const fns = [...tails.map((t) => ({ name: TOKEN_RUN + t })), ...tails.map((_t, i) => ({ name: `zz${i}` }))];
  const pe = buildPeDirs({ exports: { imageName: "m.dll", functions: fns } });
  const dir = pe.rawOf(pe.rvas.exports!);
  const count = pe.file.readUInt32LE(dir + 24);
  const names = pe.rawOf(pe.file.readUInt32LE(dir + 32));
  const at = new Map<string, number>();
  for (let k = 0; k < count; k++) {
    const rva = pe.file.readUInt32LE(names + 4 * k);
    const raw = pe.rawOf(rva);
    at.set(pe.file.subarray(raw, pe.file.indexOf(0, raw)).toString("latin1"), names + 4 * k);
  }
  tails.forEach((t, i) => {
    const longPtr = at.get(TOKEN_RUN + t)!, shortPtr = at.get(`zz${i}`)!;
    pe.file.writeUInt32LE(pe.file.readUInt32LE(longPtr) + TOKEN_RUN.length, shortPtr);
  });
  return pe.file;
}
