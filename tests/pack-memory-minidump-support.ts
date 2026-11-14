/**
 * Synthetic Windows process dumps (minidumps) for tests/pack-memory-minidump*.test.ts, built here from the layouts minidumpapiset.h
 * publishes and never from the tool's output: MINIDUMP_HEADER (32 bytes: "MDMP", version 0xA793, stream count, directory RVA, checksum,
 * time, 64-bit flags), MINIDUMP_DIRECTORY (type, size, RVA), MINIDUMP_SYSTEM_INFO (56), MINIDUMP_MISC_INFO_4 (832), MINIDUMP_MODULE (108)
 * with its VS_FIXEDFILEINFO and an RSDS record, MINIDUMP_UNLOADED_MODULE (24), MINIDUMP_THREAD (48), MINIDUMP_THREAD_INFO (64),
 * MINIDUMP_MEMORY_INFO (48), MINIDUMP_MEMORY_DESCRIPTOR (16, with an RVA each) and MINIDUMP_MEMORY_DESCRIPTOR64 (16, data consecutive from
 * BaseRva), MINIDUMP_EXCEPTION_STREAM (168), MINIDUMP_HANDLE_DESCRIPTOR (32), MINIDUMP_THREAD_NAME (12), and the x86 (716 bytes) and x64
 * (1,232 bytes) CONTEXT records.
 *
 * The scene is one process, `payload.exe`, in a 64-bit full-memory dump (Memory64List) or a 32-bit partial dump (MemoryList, with the data
 * of two ranges that are adjacent in the address space placed apart in the file). The image of payload.exe is a small PE in memory layout
 * whose .rdata page is NOT in the dump (a gap); ntdll.dll is whole. The TEB, the PEB and the process parameters are in the dump, so the
 * command line can be reached. Every address-to-offset fact the tests compare with comes from this generator (`offsetOf`).
 */
import { spawn, spawnSync } from "node:child_process";
import { join } from "node:path";
import { PYTHON3 } from "./host-gates.ts";
import { ROOT } from "./tool-library-harness.ts";

export const TOOL_DIR = join(ROOT, "packs", "memory-forensics", "tools", "minidump_map");
export const SCRIPT = join(TOOL_DIR, "run.py");

export const u16 = (v: number): Buffer => { const b = Buffer.alloc(2); b.writeUInt16LE(v); return b; };
export const u32 = (v: number): Buffer => { const b = Buffer.alloc(4); b.writeUInt32LE(v >>> 0); return b; };
export const u64 = (v: bigint | number): Buffer => { const b = Buffer.alloc(8); b.writeBigUInt64LE(BigInt(v)); return b; };
export const hex = (v: bigint | number): string => "0x" + BigInt(v).toString(16);
const wide = (t: string): Buffer => Buffer.from(t, "utf16le");

export type Range = { va: bigint; data: Buffer };
export type Mod = { base: bigint; size: number; name: string; stamp: number; checksum: number; version?: [number, number, number, number]; pdb?: string };
export type Region = { base: bigint; size: number; state: number; protect: number; type: number; abase?: bigint };
export type Thread = { id: number; teb: bigint; stackVa: bigint; stackSize: number; ip: bigint; sp: bigint; ax: bigint; start: bigint; created: bigint; name?: string };
export type Scene = {
  bits: 32 | 64; flags: bigint; time: number; ranges: Range[]; modules: Mod[]; unloaded: Mod[]; regions: Region[]; threads: Thread[];
  pid: number; created: number; commandLine: string; imagePath: string; currentDirectory: string; secret: string;
  payload: bigint; ntdll: bigint; heap: bigint; rwx: bigint; stack: bigint; teb: bigint; peb: bigint; commandLineVa: bigint;
  payloadImage: Buffer; ntdllImage: Buffer;
};
export type Built = { file: Buffer; scene: Scene; offsetOf: (va: bigint) => number | null; streams: Record<string, { at: number; size: number }>; memoryAt: number; mapped: number };

export const SIGMA = "expand 32-byte k";            // planted in payload.exe's .data, as bytes
export const WIDE_NEEDLE = "SwarmNeedle";           // planted in the heap, as UTF-16LE
export const STRADDLE = "STRADDLE-MARK";            // planted across the boundary of two ranges adjacent in the address space
export const PAGE = 0x1000;
export const COMMIT = 0x1000, RESERVE = 0x2000;
export const PRIVATE = 0x20000, IMAGE = 0x1000000;
export const RO = 0x02, RW = 0x04, RX = 0x20, RWX = 0x40;

/** A PE image in memory layout: DOS header, PE signature, file header, optional header (entry point, SizeOfImage), section table. */
export function peImage(bits: 32 | 64, size: number, stamp: number, sections: Array<{ name: string; rva: number; vsize: number; flags: number; fill: number }>): Buffer {
  const img = Buffer.alloc(size);
  img.write("MZ", 0, "latin1");
  img.writeUInt32LE(0x80, 0x3c);
  img.write("PE\0\0", 0x80, "latin1");
  const optSize = bits === 64 ? 0xf0 : 0xe0;
  img.writeUInt16LE(bits === 64 ? 0x8664 : 0x14c, 0x84);
  img.writeUInt16LE(sections.length, 0x86);
  img.writeUInt32LE(stamp, 0x88);
  img.writeUInt16LE(optSize, 0x94);
  img.writeUInt16LE(0x22, 0x96);
  img.writeUInt16LE(bits === 64 ? 0x20b : 0x10b, 0x98);
  img.writeUInt32LE(0x1000, 0x98 + 16);
  img.writeUInt32LE(size, 0x98 + 56);
  sections.forEach((s, i) => {
    const at = 0x98 + optSize + 40 * i;
    img.write(s.name, at, "latin1");
    img.writeUInt32LE(s.vsize, at + 8);
    img.writeUInt32LE(s.rva, at + 12);
    img.writeUInt32LE(s.vsize, at + 16);
    img.writeUInt32LE(s.rva, at + 20);
    img.writeUInt32LE(s.flags >>> 0, at + 36);
    for (let k = 0; k < s.vsize; k++) img[s.rva + k] = (s.fill + ((k * 7) & 0x3f)) & 0xff;
  });
  return img;
}

/** The process the dumps describe. `secret` is put in the command line as the value of --token= and must never be printed. */
export function scene(bits: 32 | 64, secret: string): Scene {
  const w = bits === 64;
  const payload = w ? 0x7ff6a1b20000n : 0x400000n;
  const ntdll = w ? 0x7ffa10000000n : 0x77000000n;
  const heap = w ? 0x1d4a0000000n : 0x250000n;
  const rwx = w ? 0x1d4b0000000n : 0x2a0000n;
  const stack = w ? 0xe51f700000n : 0x18e000n;
  const teb = w ? 0xe51f400000n : 0x7ffde000n;
  const peb = w ? 0xe51f300000n : 0x7ffdf000n;
  const P = w ? 8 : 4;
  const ptr = (v: bigint): Buffer => (w ? u64(v) : u32(Number(v)));
  const stamp = 0x65f0a1b2;

  const payloadImage = peImage(bits, 0x5000, stamp, [
    { name: ".text", rva: 0x1000, vsize: 0x1000, flags: 0x60000020, fill: 0x40 },
    { name: ".rdata", rva: 0x2000, vsize: 0x1000, flags: 0x40000040, fill: 0x80 },
    { name: ".data", rva: 0x3000, vsize: 0x2000, flags: 0xc0000040, fill: 0xa0 },
  ]);
  payloadImage.write(SIGMA, 0x3010, "latin1");
  const ntdllImage = peImage(bits, 0x4000, 0x5aa5c001, [{ name: ".text", rva: 0x1000, vsize: 0x3000, flags: 0x60000020, fill: 0x10 }]);

  const imagePath = "C:\\Users\\bob\\AppData\\Local\\Temp\\payload.exe";
  const currentDirectory = "C:\\Users\\bob\\";
  const commandLine = `"${imagePath}" --mode fast --token=${secret}`;
  const heapData = Buffer.alloc(0x2000, 0x2e);
  const params = heap + 0x100n;
  const ustr = (at: number, text: string, buffer: bigint): void => {
    const len = Buffer.byteLength(text, "utf16le");
    Buffer.concat(w ? [u16(len), u16(len + 2), u32(0), ptr(buffer)] : [u16(len), u16(len + 2), ptr(buffer)]).copy(heapData, 0x100 + at);
  };
  ustr(w ? 0x38 : 0x24, currentDirectory, heap + 0x300n);
  ustr(w ? 0x60 : 0x38, imagePath, heap + 0x400n);
  ustr(w ? 0x70 : 0x40, commandLine, heap + 0x600n);
  wide(currentDirectory).copy(heapData, 0x300);
  wide(imagePath).copy(heapData, 0x400);
  wide(commandLine).copy(heapData, 0x600);
  heapData.write(STRADDLE, 0x1000 - 6, "latin1");
  wide(WIDE_NEEDLE).copy(heapData, 0x1800);

  const tebData = Buffer.alloc(PAGE);
  ptr(peb).copy(tebData, w ? 0x60 : 0x30);
  const pebData = Buffer.alloc(PAGE);
  ptr(payload).copy(pebData, w ? 0x10 : 0x08);
  ptr(params).copy(pebData, w ? 0x20 : 0x10);
  const stackData = Buffer.alloc(0x2000, 0x5a);
  const rwxData = Buffer.alloc(PAGE, 0x90);

  const ranges: Range[] = [
    { va: payload, data: payloadImage.subarray(0, 0x2000) },            // headers and .text
    { va: payload + 0x3000n, data: payloadImage.subarray(0x3000, 0x5000) }, // .data; .rdata (0x2000..0x3000) is the gap
    { va: ntdll, data: ntdllImage },
    { va: heap, data: heapData.subarray(0, 0x1000) },
    { va: heap + 0x1000n, data: heapData.subarray(0x1000) },            // adjacent to the one before in the address space
    { va: rwx, data: rwxData },
    { va: stack, data: stackData },
    { va: teb, data: tebData },
    { va: peb, data: pebData },
  ].sort((a, b) => (a.va < b.va ? -1 : 1));
  const regions: Region[] = [
    { base: payload, size: 0x1000, state: COMMIT, protect: RO, type: IMAGE, abase: payload },
    { base: payload + 0x1000n, size: 0x1000, state: COMMIT, protect: RX, type: IMAGE, abase: payload },
    { base: payload + 0x2000n, size: 0x1000, state: COMMIT, protect: RO, type: IMAGE, abase: payload },
    { base: payload + 0x3000n, size: 0x2000, state: COMMIT, protect: RW, type: IMAGE, abase: payload },
    { base: ntdll, size: 0x4000, state: COMMIT, protect: RX, type: IMAGE, abase: ntdll },
    { base: heap, size: 0x2000, state: COMMIT, protect: RW, type: PRIVATE },
    { base: heap + 0x2000n, size: 0xe000, state: RESERVE, protect: 0, type: PRIVATE, abase: heap },
    { base: rwx, size: 0x1000, state: COMMIT, protect: RWX, type: PRIVATE },
    { base: stack, size: 0x2000, state: COMMIT, protect: RW, type: PRIVATE },
    { base: teb, size: 0x1000, state: COMMIT, protect: RW, type: PRIVATE },
    { base: peb, size: 0x1000, state: COMMIT, protect: RW, type: PRIVATE },
  ].sort((a, b) => (a.base < b.base ? -1 : 1));
  // 2026-03-01T12:00:00Z as a FILETIME, plus 1,234,567 ticks of 100 ns.
  const created = (BigInt(Date.UTC(2026, 2, 1, 12, 0, 0)) + 11644473600000n) * 10000n + 1234567n;
  return {
    bits, flags: w ? 0x1826n : 0x1800n, time: 1772366400 + 600, ranges, regions, pid: 6068, created: 1772366400,
    modules: [
      { base: payload, size: 0x5000, name: imagePath, stamp, checksum: 0x1a2b3, version: [1, 2, 3, 4], pdb: "D:\\build\\payload.pdb" },
      { base: ntdll, size: 0x4000, name: "C:\\Windows\\System32\\ntdll.dll", stamp: 0x5aa5c001, checksum: 0x2f1e0, version: [10, 0, 19041, 3996], pdb: "ntdll.pdb" },
    ],
    unloaded: [{ base: w ? 0x7ffa20000000n : 0x71000000n, size: 0x9000, name: "C:\\Windows\\System32\\winhttp.dll", stamp: 0x5bb5d002, checksum: 0x3c3c3 }],
    threads: [
      { id: 4242, teb, stackVa: stack, stackSize: 0x2000, ip: payload + 0x1234n, sp: stack + 0x1f00n, ax: w ? 0x1122334455667788n : 0x11223344n, start: ntdll + 0x100n, created, name: "main" },
      { id: 4343, teb: teb + 0x100000n, stackVa: stack, stackSize: 0x2000, ip: rwx + 0x20n, sp: stack + 0x1000n, ax: 7n, start: rwx + 0x10n, created: created + 10000000n },
    ],
    commandLine, imagePath, currentDirectory, secret, payload, ntdll, heap, rwx, stack, teb, peb, commandLineVa: heap + 0x600n, payloadImage, ntdllImage,
  };
}

function contextRecord(bits: 32 | 64, t: Thread): Buffer {
  if (bits === 64) {
    const c = Buffer.alloc(1232);
    c.writeUInt32LE(0x10000b, 0x30);
    c.writeUInt16LE(0x33, 0x38);
    c.writeUInt16LE(0x2b, 0x42);
    c.writeUInt32LE(0x246, 0x44);
    c.writeBigUInt64LE(t.ax, 0x78);
    c.writeBigUInt64LE(t.sp, 0x98);
    c.writeBigUInt64LE(t.ip, 0xf8);
    return c;
  }
  const c = Buffer.alloc(716);
  c.writeUInt32LE(0x1003f, 0);
  c.writeUInt32LE(Number(t.ax), 0xb0);
  c.writeUInt32LE(Number(t.ip), 0xb8);
  c.writeUInt32LE(0x23, 0xbc);
  c.writeUInt32LE(0x246, 0xc0);
  c.writeUInt32LE(Number(t.sp), 0xc4);
  return c;
}

/**
 * The dump file. Layout: header, directory, strings and context records, the stream bodies, then the memory. `memoryList` writes a
 * MemoryList (an RVA per range) with the ranges' data in reverse address order, so two ranges adjacent in the address space are apart in
 * the file; otherwise a Memory64List (data consecutive, in address order).
 */
export function encode(s: Scene, o: { memoryList?: boolean; dropStreams?: string[]; version?: number; comment?: string } = {}): Built {
  const w = s.bits === 64;
  const kinds: Array<[string, number, number]> = [                     // name, type, body size
    ["SystemInfo", 7, 56], ["MiscInfo", 15, 832], ["ModuleList", 4, 4 + 108 * s.modules.length], ["UnloadedModuleList", 14, 12 + 24 * s.unloaded.length],
    ["ThreadList", 3, 4 + 48 * s.threads.length], ["ThreadInfoList", 17, 12 + 64 * s.threads.length], ["ThreadNames", 24, 4 + 12 * s.threads.filter((t) => t.name).length],
    ["MemoryInfoList", 16, 16 + 48 * s.regions.length], ["Exception", 6, 168], ["HandleData", 12, 16 + 32 * 3],
    o.memoryList ? ["MemoryList", 5, 4 + 16 * s.ranges.length] : ["Memory64List", 9, 16 + 16 * s.ranges.length],
    ...(o.comment ? [["CommentW", 11, Buffer.byteLength(o.comment, "utf16le") + 2]] : []),
  ].filter(([name]) => !(o.dropStreams ?? []).includes(name as string)) as Array<[string, number, number]>;
  const chunks: Array<{ at: number; buf: Buffer }> = [];
  let cursor = 32 + 12 * kinds.length;
  const put = (buf: Buffer): number => { const at = cursor; chunks.push({ at, buf }); cursor += buf.length; return at; };
  const str = (t: string): number => put(Buffer.concat([u32(Buffer.byteLength(t, "utf16le")), wide(t), Buffer.alloc(2)]));

  const csd = str("Service Pack 1");
  const modName = s.modules.map((m) => str(m.name));
  const unlName = s.unloaded.map((m) => str(m.name));
  const cv = s.modules.map((m) => (m.pdb ? put(Buffer.concat([Buffer.from("RSDS"), Buffer.from("00112233445566778899aabbccddeeff", "hex"), u32(3), Buffer.from(m.pdb + "\0", "utf8")])) : 0));
  const ctx = s.threads.map((t) => put(contextRecord(s.bits, t)));
  const threadName = s.threads.map((t) => (t.name ? str(t.name) : 0));
  const handleType = [str("File"), str("Mutant")];
  const handleName = str("\\Device\\HarddiskVolume3\\Users\\bob\\notes.txt");

  const streams: Record<string, { at: number; size: number }> = {};
  for (const [name, , size] of kinds) { streams[name] = { at: cursor, size }; cursor += size; }
  const memoryAt = cursor;
  const order = o.memoryList ? [...s.ranges].reverse() : s.ranges;
  const where = new Map<bigint, number>();
  for (const r of order) where.set(r.va, put(r.data));
  const offsetOf = (va: bigint): number | null => {
    for (const r of s.ranges) if (va >= r.va && va < r.va + BigInt(r.data.length)) return (where.get(r.va) as number) + Number(va - r.va);
    return null;
  };

  const body: Record<string, Buffer> = {};
  body.SystemInfo = Buffer.concat([u16(w ? 9 : 0), u16(6), u16(0x9e0d), Buffer.from([8, 1]), u32(10), u32(0), u32(19045), u32(2), u32(csd), u16(0x100), u16(0), Buffer.alloc(24)]);
  const misc = Buffer.alloc(832);
  misc.writeUInt32LE(832, 0);
  misc.writeUInt32LE(0x1 | 0x2 | 0x10 | 0x100, 4);
  misc.writeUInt32LE(s.pid, 8);
  misc.writeUInt32LE(s.created, 12);
  misc.writeUInt32LE(3, 16);
  misc.writeUInt32LE(1, 20);
  misc.writeUInt32LE(0x3000, 44);
  wide("19041.1.amd64fre.vb_release.191206-1406").copy(misc, 232);
  body.MiscInfo = misc;
  body.ModuleList = Buffer.concat([u32(s.modules.length), ...s.modules.map((m, i) => {
    const v = m.version ?? [0, 0, 0, 0];
    const fixed = m.version ? Buffer.concat([u32(0xfeef04bd), u32(0x10000), u32((v[0] << 16) | v[1]), u32((v[2] << 16) | v[3]), u32((v[0] << 16) | v[1]), u32((v[2] << 16) | v[3]), Buffer.alloc(28)]) : Buffer.alloc(52);
    const cvSize = m.pdb ? 24 + Buffer.byteLength(m.pdb) + 1 : 0;
    return Buffer.concat([u64(m.base), u32(m.size), u32(m.checksum), u32(m.stamp), u32(modName[i]), fixed, u32(cvSize), u32(cv[i]), u32(0), u32(0), u64(0), u64(0)]);
  })]);
  body.UnloadedModuleList = Buffer.concat([u32(12), u32(24), u32(s.unloaded.length), ...s.unloaded.map((m, i) => Buffer.concat([u64(m.base), u32(m.size), u32(m.checksum), u32(m.stamp), u32(unlName[i])]))]);
  body.ThreadList = Buffer.concat([u32(s.threads.length), ...s.threads.map((t, i) => Buffer.concat([
    u32(t.id), u32(0), u32(0x20), u32(8), u64(t.teb), u64(t.stackVa), u32(t.stackSize), u32(offsetOf(t.stackVa) ?? 0), u32(w ? 1232 : 716), u32(ctx[i])]))]);
  body.ThreadInfoList = Buffer.concat([u32(12), u32(64), u32(s.threads.length), ...s.threads.map((t) => Buffer.concat([
    u32(t.id), u32(0), u32(0), u32(0x103), u64(t.created), u64(0), u64(1000), u64(2000), u64(t.start), u64(0xff)]))]);
  body.ThreadNames = Buffer.concat([u32(s.threads.filter((t) => t.name).length), ...s.threads.flatMap((t, i) => (t.name ? [u32(t.id), u64(threadName[i])] : []))]);
  body.MemoryInfoList = Buffer.concat([u32(16), u32(48), u64(s.regions.length), ...s.regions.map((r) => Buffer.concat([
    u64(r.base), u64(r.abase ?? r.base), u32(r.state === COMMIT ? r.protect || RW : RW), u32(0), u64(r.size), u32(r.state), u32(r.protect), u32(r.type), u32(0)]))]);
  const exc = Buffer.alloc(168);
  exc.writeUInt32LE(s.threads[0].id, 0);
  exc.writeUInt32LE(0xc0000005, 8);
  exc.writeBigUInt64LE(s.threads[0].ip, 24);
  exc.writeUInt32LE(2, 32);
  exc.writeBigUInt64LE(0n, 40);
  exc.writeBigUInt64LE(0xdeadbeefn, 48);
  exc.writeUInt32LE(w ? 1232 : 716, 160);
  exc.writeUInt32LE(ctx[0], 164);
  body.Exception = exc;
  const handle = (h: number, type: number, name: number): Buffer => Buffer.concat([u64(h), u32(type), u32(name), u32(0), u32(0x120089), u32(1), u32(2)]);
  body.HandleData = Buffer.concat([u32(16), u32(32), u32(3), u32(0), handle(4, handleType[0], handleName), handle(8, handleType[0], 0), handle(12, handleType[1], 0)]);
  body.CommentW = Buffer.concat([wide(o.comment ?? ""), Buffer.alloc(2)]);
  body.MemoryList = Buffer.concat([u32(s.ranges.length), ...s.ranges.map((r) => Buffer.concat([u64(r.va), u32(r.data.length), u32(where.get(r.va) as number)]))]);
  body.Memory64List = Buffer.concat([u64(s.ranges.length), u64(memoryAt), ...s.ranges.map((r) => Buffer.concat([u64(r.va), u64(r.data.length)]))]);

  const file = Buffer.alloc(cursor);
  Buffer.concat([Buffer.from("MDMP"), u32(o.version ?? 0x0000a793 | (0x6380 << 16)), u32(kinds.length), u32(32), u32(0), u32(s.time), u64(s.flags)]).copy(file, 0);
  kinds.forEach(([name, type, size], i) => {
    Buffer.concat([u32(type), u32(size), u32(streams[name].at)]).copy(file, 32 + 12 * i);
    if (body[name].length !== size) throw new Error(`${name}: body of ${body[name].length} bytes, declared ${size}`);
    body[name].copy(file, streams[name].at);
  });
  for (const c of chunks) c.buf.copy(file, c.at);
  return { file, scene: s, offsetOf, streams, memoryAt, mapped: s.ranges.reduce((n, r) => n + r.data.length, 0) };
}

/** A header and one Memory64List over `ranges` (address, length), the data starting right after it: the head of a large sparse dump. */
export function bareDump(ranges: Array<{ va: bigint; size: number }>, extra?: { module?: { base: bigint; size: number; name: string } }): { head: Buffer; memoryAt: number } {
  const nameAt = 32 + 24;
  const name = extra?.module ? Buffer.concat([u32(Buffer.byteLength(extra.module.name, "utf16le")), wide(extra.module.name), Buffer.alloc(2)]) : Buffer.alloc(0);
  const modAt = nameAt + name.length;
  const mod = extra?.module ? Buffer.concat([u32(1), u64(extra.module.base), u32(extra.module.size), u32(0), u32(0), u32(nameAt), Buffer.alloc(84)]) : Buffer.alloc(0);
  const listAt = modAt + mod.length;
  const listSize = 16 + 16 * ranges.length;
  const memoryAt = listAt + listSize;
  const head = Buffer.concat([
    Buffer.from("MDMP"), u32(0xa793), u32(2), u32(32), u32(0), u32(1772366400), u64(2n),
    u32(9), u32(listSize), u32(listAt), u32(extra?.module ? 4 : 0), u32(mod.length), u32(extra?.module ? modAt : 0),
    name, mod, u64(ranges.length), u64(memoryAt), ...ranges.map((r) => Buffer.concat([u64(r.va), u64(r.size)])),
  ]);
  return { head, memoryAt };
}

/** A MINIDUMP_STRING: a u32 byte length, the text as UTF-16LE, a terminator. */
export const mdString = (t: string): Buffer => Buffer.concat([u32(Buffer.byteLength(t, "utf16le")), wide(t), Buffer.alloc(2)]);
/** A MINIDUMP_MODULE (108 bytes): base, size, checksum, time stamp, name RVA, VS_FIXEDFILEINFO (52), the CodeView record's size and RVA, the misc record, two reserved. */
export const moduleEntry = (m: { base: bigint; size: number; nameRva: number; cv?: [number, number] }): Buffer =>
  Buffer.concat([u64(m.base), u32(m.size), u32(0x1234), u32(0x60000000), u32(m.nameRva), Buffer.alloc(52), u32(m.cv?.[0] ?? 0), u32(m.cv?.[1] ?? 0), u32(0), u32(0), u64(0), u64(0)]);
/** A MINIDUMP_MEMORY_INFO (48 bytes). */
export const memoryInfo = (r: { base: bigint; size: number; protect: number; type: number; state?: number }): Buffer =>
  Buffer.concat([u64(r.base), u64(r.base), u32(RW), u32(0), u64(r.size), u32(r.state ?? COMMIT), u32(r.protect), u32(r.type), u32(0)]);
/** A MINIDUMP_HANDLE_DESCRIPTOR (32 bytes). */
export const handleEntry = (handle: number, typeRva: number, nameRva = 0): Buffer => Buffer.concat([u64(handle), u32(typeRva), u32(nameRva), u32(0), u32(0x120089), u32(1), u32(2)]);

/**
 * A dump of any streams, laid out here and not by the tool: the header, then whatever `make` places with `put` (strings, records; each at
 * a multiple of four, its file offset returned), then the bodies of the streams `make` returns, the directory, and `memory` last (its
 * offset is `memoryAt`, which a Memory64List's BaseRva is set to when `memory` is given: the u64 at byte 8 of the stream of type 9). A
 * stream's `size` is what the directory declares for it when that is not the body's length.
 */
export function assemble(make: (put: (b: Buffer) => number) => Array<{ type: number; body: Buffer; size?: number }>, o: { flags?: bigint; memory?: Buffer } = {}): { file: Buffer; at: Record<number, number>; memoryAt: number } {
  const parts: Buffer[] = [Buffer.alloc(32)];
  let cursor = 32;
  const put = (b: Buffer): number => {
    const pad = (4 - (cursor % 4)) % 4;
    if (pad) { parts.push(Buffer.alloc(pad)); cursor += pad; }
    const at = cursor;
    parts.push(b);
    cursor += b.length;
    return at;
  };
  const streams = make(put);
  const at: Record<number, number> = {};
  const entries = streams.map((st) => { const where = put(st.body); at[st.type] = where; return Buffer.concat([u32(st.type), u32(st.size ?? st.body.length), u32(where)]); });
  const directory = put(Buffer.concat(entries));
  put(Buffer.alloc(0));
  const memoryAt = cursor;
  const file = Buffer.concat([...parts, o.memory ?? Buffer.alloc(0)]);
  Buffer.concat([Buffer.from("MDMP"), u32(0xa793), u32(streams.length), u32(directory), u32(0), u32(1772366400), u64(o.flags ?? 0n)]).copy(file, 0);
  if (o.memory && at[9] !== undefined) file.writeBigUInt64LE(BigInt(memoryAt), at[9] + 8);
  return { file, at, memoryAt };
}

/**
 * The tool's own functions, called in one Python process with three things a test cannot make happen from outside at a chosen moment:
 * `chunk` (the bytes `find` reads a piece, so that a small dump has many piece boundaries), `lateAfter` (once the dump's tables are read,
 * the clock says "not yet" that many times it is looked at and "max_seconds is over" ever after, so that a search stops after every piece
 * it may stop after) and `failAt` (a read that reaches this file offset comes back short, as from a file that was cut while the tool
 * ran). The answer is the tool's, printed by its own `emit`.
 */
export function inProcess(cwd: string, args: Record<string, unknown>, mode: { chunk?: number; lateAfter?: number; failAt?: number }): Record<string, any> {
  const code = [
    "import importlib.util, json, sys, time",
    "spec = importlib.util.spec_from_file_location('minidump_map_run', sys.argv[1])",
    "m = importlib.util.module_from_spec(spec)",
    "spec.loader.exec_module(m)",
    "mode = json.loads(sys.argv[3])",
    "p = m.parse_args(json.loads(sys.argv[2]))",
    "p['started'] = time.monotonic()",
    "p['deadline'] = p['started'] + p['seconds']",
    "m.CLOCK['deadline'], m.CLOCK['seconds'] = p['deadline'], p['seconds']",
    "dump = m.load(p['path'])",
    "if mode.get('chunk'): m.CHUNK = mode['chunk']",
    "looks = [0]",
    "def late():",
    "    looks[0] += 1",
    "    return looks[0] > mode['lateAfter']",
    "if mode.get('lateAfter') is not None: m.late = late",
    "if mode.get('failAt') is not None:",
    "    whole = m.Dump.read",
    "    def short(self, offset, length):",
    "        data = whole(self, offset, length)",
    "        return data[:max(0, mode['failAt'] - offset)] if offset + length > mode['failAt'] else data",
    "    m.Dump.read = short",
    "getattr(m, 'view_' + p['view'])(dump, p)",
  ].join("\n");
  const ran = spawnSync(PYTHON3, ["-c", code, SCRIPT, JSON.stringify(args), JSON.stringify(mode)], { cwd, encoding: "utf8", env: { ...process.env, PYTHONDONTWRITEBYTECODE: "1" }, maxBuffer: 1 << 26 });
  if (ran.status !== 0 || /Traceback/.test(ran.stderr)) throw new Error(`in-process call failed (exit ${ran.status}): ${ran.stderr.slice(-800)}`);
  return JSON.parse(ran.stdout) as Record<string, any>;
}

export type Run = { code: number | null; signal: string | null; stdout: string; stderr: string; ms: number };

/** Run the tool with `args` on stdin; `env` is added to a clean environment (no JOB_ID, OUT or SECRET_OUTPUT unless given). */
export function call(cwd: string, args: unknown, env: Record<string, string> = {}, stop?: { signal: NodeJS.Signals; when: () => Promise<boolean> | boolean }): Promise<Run> {
  const e: NodeJS.ProcessEnv = { ...process.env, AGENT_ID: "s1", PYTHONDONTWRITEBYTECODE: "1" };
  delete e.JOB_ID; delete e.OUT; delete e.SECRET_OUTPUT;
  Object.assign(e, env);
  const t0 = Date.now();
  return new Promise((resolve, reject) => {
    const child = spawn(PYTHON3, [SCRIPT], { cwd, env: e });
    const out: Buffer[] = [];
    const err: Buffer[] = [];
    let closed = false;
    const timer = setTimeout(() => { try { child.kill("SIGKILL"); } catch { /* gone */ } }, 120_000);
    child.stdout.on("data", (c: Buffer) => out.push(c));
    child.stderr.on("data", (c: Buffer) => err.push(c));
    child.on("error", reject);
    child.on("close", (code, signal) => { closed = true; clearTimeout(timer); resolve({ code, signal, stdout: Buffer.concat(out).toString("utf8"), stderr: Buffer.concat(err).toString("utf8"), ms: Date.now() - t0 }); });
    child.stdin.on("error", () => undefined);
    child.stdin.end(typeof args === "string" ? args : JSON.stringify(args));
    if (stop) {
      void (async () => {
        while (!closed && Date.now() - t0 < 60_000) {
          try { if (await stop.when()) break; } catch { /* not yet */ }
          await new Promise((r) => setTimeout(r, 5));
        }
        if (!closed) try { child.kill(stop.signal); } catch { /* gone */ }
      })();
    }
  });
}

/** The one JSON document of a run; throws on a traceback, on no document and on more than one. */
export function doc<T = Record<string, any>>(run: Run): T {
  if (/Traceback/.test(run.stderr)) throw new Error(`traceback: ${run.stderr.slice(-800)}`);
  if (run.signal) throw new Error(`killed by ${run.signal}`);
  return JSON.parse(run.stdout) as T;
}
