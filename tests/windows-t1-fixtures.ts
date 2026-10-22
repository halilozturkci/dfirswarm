/**
 * Fixtures for registry_recover and lnk_jumplist, written from the formats' own layouts and never from a tool's output.
 *
 *   transaction logs   Suhanov, "Windows registry file format specification" and libyal's REGF notes: a log starts with a
 *                      512-byte copy of the base block; a new-format log (Windows 8.1 and later) then holds HvLE entries
 *                      (signature, size, flags, sequence number, hive bins data size, dirty page count, hash-1, hash-2, the
 *                      page references, the pages), each a multiple of 512 bytes long, with the 64-bit Marvin32 hash
 *                      (seed 0x82EF4D887A4E55C5) of the header's first 32 bytes in hash-2 and of everything after the
 *                      40-byte header in hash-1; an old-format log holds a "DIRT" dirty vector (one bit per 512-byte sector
 *                      of the hive bins) padded with its signature to a sector, then the dirty sectors.
 *   shell links        MS-SHLLINK: the 76-byte header, the link target ID list, LinkInfo with its VolumeID and
 *                      CommonNetworkRelativeLink, the string data, the extra data terminator.
 *   compound files     MS-CFB version 3: a 512-byte header with the first 109 FAT sector numbers, the FAT, a directory of
 *                      128-byte entries, a mini FAT and a mini stream for streams under 4096 bytes.
 *   jump lists         the DestList stream as libyal's jump list notes lay it out (see tests/pack-windows-forensics.test.ts).
 */

import { spawnSync } from "node:child_process";
import { chmod, mkdir, writeFile } from "node:fs/promises";
import { join } from "node:path";

/**
 * A directory to use as the whole PATH of a tool: it holds python3 and nothing else, so a program the tool looks for with `which` is
 * not found. python3 is a script that runs the interpreter of this host by its real path, because a virtual environment's interpreter
 * finds its packages from where it stands and a link to it from elsewhere would not.
 */
export async function pathWithOnlyPython(where: string): Promise<string> {
  const python = spawnSync("python3", ["-c", "import sys; print(sys.executable)"], { encoding: "utf8" }).stdout.trim();
  const dir = join(where, "onlypython");
  await mkdir(dir, { recursive: true });
  await writeFile(join(dir, "python3"), `#!/bin/sh\nexec "${python}" "$@"\n`, "utf8");
  await chmod(join(dir, "python3"), 0o755);
  return dir;
}

const rol = (x: number, n: number): number => ((x << n) | (x >>> (32 - n))) >>> 0;

/** The .NET Marvin32 hash, as the registry's transaction logs use it: seeded with a 64-bit seed, the result is the high word shifted up beside the low one. */
export function marvin32(data: Buffer, seed = 0x82ef4d887a4e55c5n): bigint {
  let lo = Number(seed & 0xffffffffn) >>> 0;
  let hi = Number(seed >> 32n) >>> 0;
  const block = (): void => {
    hi = (hi ^ lo) >>> 0;
    lo = rol(lo, 20);
    lo = (lo + hi) >>> 0;
    hi = rol(hi, 9);
    hi = (hi ^ lo) >>> 0;
    lo = rol(lo, 27);
    lo = (lo + hi) >>> 0;
    hi = rol(hi, 19);
  };
  let i = 0;
  for (; i + 4 <= data.length; i += 4) {
    lo = (lo + data.readUInt32LE(i)) >>> 0;
    block();
  }
  const rest = data.length - i;
  // The padding byte 0x80 sits right after the last byte; the bytes above it are zero.
  let tail = 0;
  for (let k = 0; k < rest; k++) tail |= data[i + k] << (8 * k);
  tail |= 0x80 << (8 * rest);
  lo = (lo + (tail >>> 0)) >>> 0;
  block();
  block();
  return (BigInt(hi) << 32n) | BigInt(lo);
}

// ---- registry hive logs ------------------------------------------------------------------------------------------------------

export const BASE_BLOCK = 4096;

export function xorChecksum(base: Buffer): number {
  let sum = 0;
  for (let i = 0; i < 127; i++) sum = (sum ^ base.readUInt32LE(i * 4)) >>> 0;
  return sum;
}

/** A hive's base block with other sequence numbers (and a checksum that follows). */
export function withSequences(hive: Buffer, primary: number, secondary: number): Buffer {
  const out = Buffer.from(hive);
  out.writeUInt32LE(primary, 4);
  out.writeUInt32LE(secondary, 8);
  out.writeUInt32LE(xorChecksum(out), 0x1fc);
  return out;
}

/** The 4096-byte pages of the hive bins data in which `a` and `b` differ, as log pages (offsets are from the start of the hive bins). */
export function differingPages(a: Buffer, b: Buffer): LogPage[] {
  const pages: LogPage[] = [];
  for (let at = BASE_BLOCK; at < b.length; at += 4096) {
    const x = a.subarray(at, at + 4096);
    const y = b.subarray(at, at + 4096);
    if (x.length !== y.length || !x.equals(y)) pages.push({ offset: at - BASE_BLOCK, data: Buffer.from(y) });
  }
  return pages;
}

export type LogPage = { offset: number; data: Buffer };
export type LogEntry = {
  sequence: number;
  hiveBinsDataSize: number;
  pages: LogPage[];
  /** break one of the two hashes after they were computed */
  corrupt?: "hash1" | "hash2";
  /** write this size in the header instead of the right one */
  sizeOverride?: number;
};

/** The first 512 bytes of a log: the hive's base block with the log's own sequence numbers and file type (6 for a new-format log, 1 for an old one). */
export function logHeader(hive: Buffer, o: { primary: number; secondary?: number; fileType?: number }): Buffer {
  const head = Buffer.from(hive.subarray(0, 512));
  head.writeUInt32LE(o.primary, 4);
  head.writeUInt32LE(o.secondary ?? o.primary, 8);
  head.writeUInt32LE(o.fileType ?? 6, 0x1c);
  head.writeUInt32LE(xorChecksum(head), 0x1fc);
  return head;
}

export function hvleEntry(e: LogEntry): Buffer {
  const refs = Buffer.alloc(8 * e.pages.length);
  e.pages.forEach((p, i) => {
    refs.writeUInt32LE(p.offset, 8 * i);
    refs.writeUInt32LE(p.data.length, 8 * i + 4);
  });
  const body = Buffer.concat([refs, ...e.pages.map((p) => p.data)]);
  const size = Math.ceil((40 + body.length) / 512) * 512;
  const entry = Buffer.alloc(size);
  entry.write("HvLE", 0, "latin1");
  entry.writeUInt32LE(e.sizeOverride ?? size, 4);
  entry.writeUInt32LE(0, 8);
  entry.writeUInt32LE(e.sequence, 12);
  entry.writeUInt32LE(e.hiveBinsDataSize, 16);
  entry.writeUInt32LE(e.pages.length, 20);
  body.copy(entry, 40);
  const h1 = marvin32(entry.subarray(40));
  entry.writeBigUInt64LE(e.corrupt === "hash1" ? h1 ^ 1n : h1, 24);
  const h2 = marvin32(entry.subarray(0, 32));
  entry.writeBigUInt64LE(e.corrupt === "hash2" ? h2 ^ 1n : h2, 32);
  return entry;
}

export function hvleLog(hive: Buffer, entries: LogEntry[], o: { primary?: number; secondary?: number; zeroPad?: number } = {}): Buffer {
  const first = entries[0]?.sequence ?? o.primary ?? 0;
  return Buffer.concat([logHeader(hive, { primary: o.primary ?? first, secondary: o.secondary ?? first }), ...entries.map(hvleEntry), Buffer.alloc(o.zeroPad ?? 0)]);
}

/** An old-format log: the base block copy, "DIRT" and the dirty vector padded to a sector, then the dirty 512-byte sectors in order. */
export function dirtLog(hive: Buffer, hiveBinsDataSize: number, sectors: Array<{ index: number; data: Buffer }>, o: { primary: number; secondary?: number }): Buffer {
  const vectorBytes = Math.ceil(hiveBinsDataSize / 512 / 8);
  const vector = Buffer.alloc(Math.ceil((4 + vectorBytes) / 512) * 512);
  vector.write("DIRT", 0, "latin1");
  for (const s of sectors) vector[4 + (s.index >> 3)] |= 1 << (s.index & 7);
  const ordered = [...sectors].sort((a, b) => a.index - b.index);
  return Buffer.concat([logHeader(hive, { primary: o.primary, secondary: o.secondary ?? o.primary, fileType: 1 }), vector, ...ordered.map((s) => s.data)]);
}

// ---- shell links ------------------------------------------------------------------------------------------------------------

const CLSID = Buffer.from("0114020000000000c000000000000046", "hex");
const u16le = (text: string): Buffer => Buffer.from(text, "utf16le");
const asciiz = (text: string): Buffer => Buffer.concat([Buffer.from(text, "latin1"), Buffer.from([0])]);
const u16z = (text: string): Buffer => Buffer.concat([u16le(text), Buffer.from([0, 0])]);

export const FILETIME_A = 133_443_104_001_234_567n; // 2023-11-13T00:53:20.1234567Z

export type LnkSpec = {
  times?: [bigint, bigint, bigint];
  size?: number;
  idList?: Buffer[];
  local?: { path: string; serial: number; label: string; driveType?: number; suffix?: string };
  network?: { net: string; device: string; provider?: number; suffix?: string };
  name?: string;
  relative?: string;
  workDir?: string;
  args?: string;
  icon?: string;
  tracker?: { machine: string };
};

export function lnk(s: LnkSpec): Buffer {
  const t = s.times ?? [FILETIME_A, FILETIME_A + 10_000_000n, FILETIME_A + 20_000_000n];
  let flags = 0x80; // IsUnicode
  if (s.idList) flags |= 0x01;
  if (s.local || s.network) flags |= 0x02;
  if (s.name !== undefined) flags |= 0x04;
  if (s.relative !== undefined) flags |= 0x08;
  if (s.workDir !== undefined) flags |= 0x10;
  if (s.args !== undefined) flags |= 0x20;
  if (s.icon !== undefined) flags |= 0x40;
  const header = Buffer.alloc(0x4c);
  header.writeUInt32LE(0x4c, 0);
  CLSID.copy(header, 4);
  header.writeUInt32LE(flags, 0x14);
  header.writeUInt32LE(0x20, 0x18);
  header.writeBigUInt64LE(t[0], 0x1c);
  header.writeBigUInt64LE(t[1], 0x24);
  header.writeBigUInt64LE(t[2], 0x2c);
  header.writeUInt32LE(s.size ?? 4321, 0x34);
  header.writeUInt32LE(1, 0x3c);
  const parts: Buffer[] = [header];
  if (s.idList) {
    const items = Buffer.concat(s.idList.map((item) => Buffer.concat([Buffer.from([(item.length + 2) & 0xff, (item.length + 2) >> 8]), item])));
    const list = Buffer.concat([items, Buffer.from([0, 0])]);
    parts.push(Buffer.from([list.length & 0xff, list.length >> 8]), list);
  }
  if (s.local || s.network) {
    const headerSize = 0x24;
    const chunks: Buffer[] = [];
    let at = headerSize;
    const place = (b: Buffer | undefined): number => {
      if (!b) return 0;
      const where = at;
      chunks.push(b);
      at += b.length;
      return where;
    };
    let volumeOffset = 0;
    let localOffset = 0;
    let networkOffset = 0;
    if (s.local) {
      const label = asciiz(s.local.label);
      const v = Buffer.alloc(0x10 + label.length);
      v.writeUInt32LE(v.length, 0);
      v.writeUInt32LE(s.local.driveType ?? 3, 4);
      v.writeUInt32LE(s.local.serial, 8);
      v.writeUInt32LE(0x10, 12);
      label.copy(v, 0x10);
      volumeOffset = place(v);
      localOffset = place(asciiz(s.local.path));
    }
    if (s.network) {
      const net = asciiz(s.network.net);
      const dev = asciiz(s.network.device);
      const n = Buffer.alloc(0x14 + net.length + dev.length);
      n.writeUInt32LE(n.length, 0);
      n.writeUInt32LE(3, 4);
      n.writeUInt32LE(0x14, 8);
      n.writeUInt32LE(0x14 + net.length, 12);
      n.writeUInt32LE(s.network.provider ?? 0x00020000, 16);
      net.copy(n, 0x14);
      dev.copy(n, 0x14 + net.length);
      networkOffset = place(n);
    }
    const suffixAnsi = place(asciiz(s.local?.suffix ?? s.network?.suffix ?? ""));
    const localUnicode = s.local ? place(u16z(s.local.path)) : 0;
    const suffixUnicode = place(u16z(s.local?.suffix ?? s.network?.suffix ?? ""));
    const info = Buffer.alloc(headerSize);
    info.writeUInt32LE(at, 0);
    info.writeUInt32LE(headerSize, 4);
    info.writeUInt32LE((s.local ? 1 : 0) | (s.network ? 2 : 0), 8);
    info.writeUInt32LE(volumeOffset, 12);
    info.writeUInt32LE(localOffset, 16);
    info.writeUInt32LE(networkOffset, 20);
    info.writeUInt32LE(suffixAnsi, 24);
    info.writeUInt32LE(localUnicode, 28);
    info.writeUInt32LE(suffixUnicode, 32);
    parts.push(info, ...chunks);
  }
  for (const text of [s.name, s.relative, s.workDir, s.args, s.icon]) {
    if (text === undefined) continue;
    const count = Buffer.alloc(2);
    count.writeUInt16LE(text.length);
    parts.push(count, u16le(text));
  }
  if (s.tracker) {
    const b = Buffer.alloc(0x60);
    b.writeUInt32LE(0x60, 0);
    b.writeUInt32LE(0xa0000003, 4);
    b.writeUInt32LE(0x58, 8);
    b.writeUInt32LE(0, 12);
    Buffer.from(s.tracker.machine.padEnd(16, "\0"), "latin1").copy(b, 16);
    parts.push(b);
  }
  parts.push(Buffer.alloc(4));
  return Buffer.concat(parts);
}

// ---- compound files (MS-CFB, version 3) ---------------------------------------------------------------------------------------

const FREE = 0xffffffff;
const END = 0xfffffffe;
const FATSECT = 0xfffffffd;

export type CfbStream = { name: string; data: Buffer };

/** The MS-CFB name order: shorter names first, then by upper-cased code unit. */
const cfbOrder = (a: string, b: string): number => (a.length !== b.length ? a.length - b.length : a.toUpperCase() < b.toUpperCase() ? -1 : a.toUpperCase() > b.toUpperCase() ? 1 : 0);

export function cfb(streams: CfbStream[], o: { miniCutoff?: number; swapFatLinks?: boolean; loopFirstStream?: boolean } = {}): Buffer {
  const cutoff = o.miniCutoff ?? 4096;
  const small = streams.filter((s) => s.data.length < cutoff && s.data.length > 0);
  const big = streams.filter((s) => s.data.length >= cutoff);
  const empty = streams.filter((s) => s.data.length === 0);
  const entries = 1 + streams.length;
  const dirSectors = Math.ceil((entries * 128) / 512);
  const miniCounts = small.map((s) => Math.ceil(s.data.length / 64));
  const miniTotal = miniCounts.reduce((a, b) => a + b, 0);
  const miniFatSectors = Math.ceil((miniTotal * 4) / 512);
  const miniContainerSectors = Math.ceil((miniTotal * 64) / 512);
  const bigCounts = big.map((s) => Math.ceil(s.data.length / 512));
  const dataSectors = dirSectors + miniFatSectors + miniContainerSectors + bigCounts.reduce((a, b) => a + b, 0);
  let fat = 1;
  while (fat * 128 < fat + dataSectors) fat++;
  const total = fat + dataSectors;
  const table = new Array<number>(fat * 128).fill(FREE);
  for (let i = 0; i < fat; i++) table[i] = FATSECT;
  let next = fat;
  const chain = (count: number): number => {
    const first = next;
    for (let i = 0; i < count; i++) table[next + i] = i === count - 1 ? END : next + i + 1;
    next += count;
    return first;
  };
  const dirStart = chain(dirSectors);
  const miniFatStart = miniFatSectors ? chain(miniFatSectors) : END;
  const miniContainerStart = miniContainerSectors ? chain(miniContainerSectors) : END;
  const bigStarts = big.map((_s, i) => chain(bigCounts[i]));
  const file = Buffer.alloc(512 + total * 512);
  // header
  Buffer.from("d0cf11e0a1b11ae1", "hex").copy(file, 0);
  file.writeUInt16LE(0x3e, 0x18);
  file.writeUInt16LE(3, 0x1a);
  file.writeUInt16LE(0xfffe, 0x1c);
  file.writeUInt16LE(9, 0x1e);
  file.writeUInt16LE(6, 0x20);
  file.writeUInt32LE(0, 0x28);
  file.writeUInt32LE(fat, 0x2c);
  file.writeUInt32LE(dirStart, 0x30);
  file.writeUInt32LE(cutoff, 0x38);
  file.writeUInt32LE(miniFatStart, 0x3c);
  file.writeUInt32LE(miniFatSectors, 0x40);
  file.writeUInt32LE(END, 0x44);
  file.writeUInt32LE(0, 0x48);
  for (let i = 0; i < 109; i++) file.writeUInt32LE(i < fat ? i : FREE, 0x4c + 4 * i);
  const at = (sector: number): number => 512 + sector * 512;
  // mini FAT and mini stream
  const miniFat = new Array<number>(Math.max(miniFatSectors * 128, 1)).fill(FREE);
  const miniStarts: number[] = [];
  let m = 0;
  small.forEach((s, i) => {
    miniStarts.push(m);
    for (let k = 0; k < miniCounts[i]; k++) miniFat[m + k] = k === miniCounts[i] - 1 ? END : m + k + 1;
    s.data.copy(file, at(miniContainerStart) + m * 64);
    m += miniCounts[i];
  });
  miniFat.forEach((v, i) => {
    if (miniFatSectors) file.writeUInt32LE(v, at(miniFatStart) + 4 * i);
  });
  big.forEach((s, i) => s.data.copy(file, at(bigStarts[i])));
  if (o.swapFatLinks && bigStarts.length) table[bigStarts[0]] = bigStarts[0]; // a chain that points at itself
  if (o.loopFirstStream && bigStarts.length && bigCounts[0] > 1) table[bigStarts[0] + bigCounts[0] - 1] = bigStarts[0];
  table.forEach((v, i) => file.writeUInt32LE(v >>> 0, at(Math.floor(i / 128)) + 4 * (i % 128)));
  // directory
  const sorted = [...streams].sort((a, b) => cfbOrder(a.name, b.name));
  const idOf = new Map(sorted.map((s, i) => [s, i + 1] as const));
  const entry = (index: number, name: string, type: number, start: number, size: number, left: number, right: number, child: number): void => {
    const e = Buffer.alloc(128);
    const raw = u16le(name);
    raw.copy(e, 0);
    e.writeUInt16LE(raw.length + 2, 64);
    e[66] = type;
    e[67] = 1;
    e.writeUInt32LE(left >>> 0, 68);
    e.writeUInt32LE(right >>> 0, 72);
    e.writeUInt32LE(child >>> 0, 76);
    e.writeUInt32LE(start >>> 0, 116);
    e.writeUInt32LE(size, 120);
    e.copy(file, at(dirStart) + index * 128);
  };
  entry(0, "Root Entry", 5, miniContainerStart, miniTotal * 64, FREE, FREE, sorted.length ? 1 : FREE);
  sorted.forEach((s, i) => {
    let start = END;
    if (small.includes(s)) start = miniStarts[small.indexOf(s)];
    else if (big.includes(s)) start = bigStarts[big.indexOf(s)];
    else if (empty.includes(s)) start = END;
    entry(i + 1, s.name, 2, start, s.data.length, FREE, i + 1 < sorted.length ? idOf.get(sorted[i + 1])! : FREE, FREE);
  });
  for (let i = entries; i < dirSectors * 4; i++) entry(i, "", 0, 0, 0, FREE, FREE, FREE);
  // a directory slot with no name is written as unallocated: its name length and type stay zero
  for (let i = entries; i < dirSectors * 4; i++) {
    const base = at(dirStart) + i * 128;
    file.fill(0, base, base + 68);
    file.writeUInt32LE(0, base + 116);
  }
  return file;
}

export type DestEntry = { number: number; host: string; filetime: bigint; pin: number; path: string };

/** A DestList stream: the 32-byte header, then an entry per record in the version's layout (fixed part 114 bytes for 1, 130 for 3 and 4; the path length at 0x70 or 0x80). */
export function destList(version: 1 | 3 | 4, entries: DestEntry[]): Buffer {
  const header = Buffer.alloc(32);
  header.writeUInt32LE(version, 0);
  header.writeUInt32LE(entries.length, 4);
  header.writeUInt32LE(entries.filter((e) => e.pin !== -1).length, 8);
  const parts: Buffer[] = [header];
  for (const e of entries) {
    const fixed = version === 1 ? 114 : 130;
    const b = Buffer.alloc(fixed);
    b.writeBigUInt64LE(0x1234n, 0);
    Buffer.from(e.host.padEnd(16, "\0"), "latin1").copy(b, 0x48);
    b.writeUInt32LE(e.number, 0x58);
    b.writeBigUInt64LE(e.filetime, 0x64);
    b.writeInt32LE(e.pin, 0x6c);
    b.writeUInt16LE(e.path.length, version === 1 ? 0x70 : 0x80);
    parts.push(b, u16le(e.path));
    if (version !== 1) parts.push(Buffer.alloc(4));
  }
  return Buffer.concat(parts);
}
