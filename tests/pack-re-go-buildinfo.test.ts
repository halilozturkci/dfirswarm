/**
 * go_buildinfo against Go build information built here from the format: the header of runtime/debug.BuildInfo as the Go
 * toolchain writes it (the 14-byte magic `\xff Go buildinf:`, a pointer size, a flags byte whose bit 1 selects the inline
 * format; a 32-byte header; then two varint-prefixed strings, or two pointers to Go string headers), the module framing
 * (the 16-byte sentinels cmd/go writes around the text) and the object formats' own layouts (ELF gABI, PE/COFF, Mach-O and
 * the fat header). Nothing here is read from the tool's output. One real Go binary is read when `go` is on the machine.
 *
 * What is held: both header formats in all three containers (thin, and a slice of a universal binary); a pointer is turned
 * into an offset only through a mapped section or segment; a cut module block, a varint overflow, a pointer past the end of
 * the file and a magic at an unaligned offset are named and never complete; the dependencies are paged whole in a 0600 file;
 * the strings are withheld by shape, with the miss rate counted; write_values is a job's secret output only; hostile
 * parameters and special files are JSON refusals.
 */
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { mkdir, readFile, readdir, rm, stat, symlink, truncate, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { test } from "node:test";
import { TOOLS, asJob, body, put, refused, tool, withCwd } from "./pack-re-harness.ts";
import type { Json } from "./pack-re-harness.ts";
import { canaries, needles, prng } from "./pack-re-canary-shapes.ts";

const GO_BUILDINFO = join(TOOLS, "go_buildinfo", "run.py");

// --- the Go build information, from runtime/debug and cmd/go --------------------------------------------------------------

const MAGIC = Buffer.from([0xff, 0x20, 0x47, 0x6f, 0x20, 0x62, 0x75, 0x69, 0x6c, 0x64, 0x69, 0x6e, 0x66, 0x3a]);   // "\xff Go buildinf:"
const INFO_START = Buffer.from("3077af0c9274080241e1c107e6d618e6", "hex");                                           // cmd/go/internal/modload.infoStart
const INFO_END = Buffer.from("f932433186182072008242104116d8f2", "hex");                                             // and infoEnd

function uvarint(n: number): Buffer {
  const out: number[] = [];
  let v = BigInt(n);
  while (v >= 0x80n) {
    out.push(Number(v & 0x7fn) | 0x80);
    v >>= 7n;
  }
  out.push(Number(v));
  return Buffer.from(out);
}

/** The text the go command embeds: `path`, `mod`, `dep`, `=>` and `build` lines, between the two sentinels. */
function modBlock(lines: string[]): Buffer {
  return Buffer.concat([INFO_START, Buffer.from(lines.join("\n") + "\n", "latin1"), INFO_END]);
}

/** A header and its two strings, inline (Go 1.18 and later): bit 1 of the flags byte set. */
function inlineInfo(version: string, mod: Buffer, o: { ptr?: number; big?: boolean } = {}): Buffer {
  const head = Buffer.alloc(32);
  MAGIC.copy(head);
  head[14] = o.ptr ?? 8;
  head[15] = 2 | (o.big ? 1 : 0);
  return Buffer.concat([head, uvarint(version.length), Buffer.from(version, "latin1"), uvarint(mod.length), mod]);
}

/** A header in the older pointer format: two virtual addresses of Go string headers (data pointer, length), then the strings. */
function pointerInfo(version: string, mod: Buffer, base: bigint, ptr: 4 | 8, big: boolean, o: { modPointer?: bigint; versionPointer?: bigint } = {}): Buffer {
  const word = (v: bigint): Buffer => {
    const b = Buffer.alloc(ptr);
    if (ptr === 8) (big ? b.writeBigUInt64BE(v) : b.writeBigUInt64LE(v));
    else (big ? b.writeUInt32BE(Number(v)) : b.writeUInt32LE(Number(v)));
    return b;
  };
  const vbytes = Buffer.from(version, "latin1");
  const vhdrAt = 32;
  const mhdrAt = vhdrAt + 2 * ptr;
  const vdataAt = mhdrAt + 2 * ptr;
  const mdataAt = vdataAt + vbytes.length;
  const head = Buffer.alloc(32);
  MAGIC.copy(head);
  head[14] = ptr;
  head[15] = big ? 1 : 0;
  word(o.versionPointer ?? base + BigInt(vhdrAt)).copy(head, 16);
  word(o.modPointer ?? base + BigInt(mhdrAt)).copy(head, 16 + ptr);
  return Buffer.concat([head, word(base + BigInt(vdataAt)), word(BigInt(vbytes.length)), word(base + BigInt(mdataAt)), word(BigInt(mod.length)), vbytes, mod]);
}

// --- containers, from their specifications ---------------------------------------------------------------------------------

function pad(buf: Buffer, to: number): Buffer {
  const n = (to - (buf.length % to)) % to;
  return n ? Buffer.concat([buf, Buffer.alloc(n)]) : buf;
}

type ElfOpts = { cls?: 32 | 64; big?: boolean; section?: boolean; segment?: boolean; vaddr?: bigint; at?: number };

/** An ELF file whose data is `payload` at file offset `at` (0x100), named `.go.buildinfo` by a section header and/or mapped by a writable PT_LOAD at `vaddr`. */
function elf(payload: Buffer, o: ElfOpts = {}): Buffer {
  const cls = o.cls ?? 64;
  const big = !!o.big;
  const at = o.at ?? 0x100;
  const vaddr = o.vaddr ?? (cls === 64 ? 0x4a0100n : 0x8049100n);
  const w16 = (v: number): Buffer => { const b = Buffer.alloc(2); big ? b.writeUInt16BE(v) : b.writeUInt16LE(v); return b; };
  const w32 = (v: number): Buffer => { const b = Buffer.alloc(4); big ? b.writeUInt32BE(v >>> 0) : b.writeUInt32LE(v >>> 0); return b; };
  const w64 = (v: bigint): Buffer => { const b = Buffer.alloc(8); big ? b.writeBigUInt64BE(v) : b.writeBigUInt64LE(v); return b; };
  const wa = (v: bigint | number): Buffer => (cls === 64 ? w64(BigInt(v)) : w32(Number(v)));
  const shstr = Buffer.from("\0.go.buildinfo\0.shstrtab\0", "latin1");
  const ehsize = cls === 64 ? 64 : 52;
  const phsize = cls === 64 ? 56 : 32;
  const shsize = cls === 64 ? 64 : 40;
  const withSegment = o.segment !== false;
  const withSection = o.section !== false;
  const strAt = at + payload.length;
  const shAt = strAt + shstr.length + ((8 - ((strAt + shstr.length) % 8)) % 8);
  const ident = Buffer.alloc(16);
  ident.set([0x7f, 0x45, 0x4c, 0x46, cls === 64 ? 2 : 1, big ? 2 : 1, 1]);
  const header = Buffer.concat([
    ident, w16(2), w16(cls === 64 ? 0x3e : 0x14), w32(1), wa(0), wa(withSegment ? ehsize : 0), wa(withSection ? shAt : 0), w32(0), w16(ehsize),
    w16(withSegment ? phsize : 0), w16(withSegment ? 1 : 0), w16(withSection ? shsize : 0), w16(withSection ? 3 : 0), w16(withSection ? 2 : 0),
  ]);
  const phdr = cls === 64
    ? Buffer.concat([w32(1), w32(6), w64(BigInt(at)), w64(vaddr), w64(vaddr), w64(BigInt(payload.length)), w64(BigInt(payload.length)), w64(16n)])
    : Buffer.concat([w32(1), w32(at), w32(Number(vaddr)), w32(Number(vaddr)), w32(payload.length), w32(payload.length), w32(6), w32(16)]);
  const sh = (name: number, type: number, addr: bigint, off: number, size: number): Buffer => cls === 64
    ? Buffer.concat([w32(name), w32(type), w64(3n), w64(addr), w64(BigInt(off)), w64(BigInt(size)), w32(0), w32(0), w64(16n), w64(0n)])
    : Buffer.concat([w32(name), w32(type), w32(3), w32(Number(addr)), w32(off), w32(size), w32(0), w32(0), w32(16), w32(0)]);
  const shdrs = Buffer.concat([Buffer.alloc(shsize), sh(1, 1, vaddr, at, payload.length), sh(14, 3, 0n, strAt, shstr.length)]);
  const parts: Buffer[] = [header];
  if (withSegment) parts.push(phdr);
  const head = Buffer.concat(parts);
  const out = Buffer.concat([head, Buffer.alloc(at - head.length), payload, shstr]);
  return withSection ? Buffer.concat([out, Buffer.alloc(shAt - out.length), shdrs]) : out;
}

/** A PE32 or PE32+ file whose `.data` section holds `payload`; the section's address is imageBase + 0x2000. */
function pe(payload: Buffer, o: { plus?: boolean; imageBase?: bigint } = {}): { file: Buffer; base: bigint } {
  const plus = o.plus !== false;
  const imageBase = o.imageBase ?? (plus ? 0x140000000n : 0x400000n);
  const lfanew = 0x80;
  const dos = Buffer.alloc(lfanew);
  dos.write("MZ", 0, "latin1");
  dos.writeUInt32LE(lfanew, 0x3c);
  const optSize = plus ? 240 : 224;
  const coff = Buffer.alloc(24);
  coff.write("PE\0\0", 0, "latin1");
  coff.writeUInt16LE(plus ? 0x8664 : 0x14c, 4);
  coff.writeUInt16LE(2, 6);
  coff.writeUInt16LE(optSize, 20);
  coff.writeUInt16LE(0x22, 22);
  const opt = Buffer.alloc(optSize);
  opt.writeUInt16LE(plus ? 0x20b : 0x10b, 0);
  if (plus) opt.writeBigUInt64LE(imageBase, 24);
  else opt.writeUInt32LE(Number(imageBase), 28);
  const section = (name: string, vsize: number, rva: number, rawSize: number, rawAt: number, flags: number): Buffer => {
    const b = Buffer.alloc(40);
    b.write(name, 0, "latin1");
    b.writeUInt32LE(vsize, 8);
    b.writeUInt32LE(rva, 12);
    b.writeUInt32LE(rawSize, 16);
    b.writeUInt32LE(rawAt, 20);
    b.writeUInt32LE(flags, 36);
    return b;
  };
  const raw = pad(payload, 0x200);
  const table = Buffer.concat([section(".text", 0x10, 0x1000, 0x200, 0x400, 0x60000020), section(".data", payload.length, 0x2000, raw.length, 0x600, 0xc0000040)]);
  const head = Buffer.concat([dos, coff, opt, table]);
  return { file: Buffer.concat([head, Buffer.alloc(0x400 - head.length), Buffer.alloc(0x200, 0x90), raw]), base: imageBase + 0x2000n };
}

/** A 64-bit little-endian Mach-O with a __DATA segment holding a `__go_buildinfo` section whose contents are `payload`, at file offset 0x1000. */
function macho(payload: Buffer, o: { vmaddr?: bigint; sectionName?: string; magic?: number } = {}): { file: Buffer; base: bigint } {
  const vmaddr = o.vmaddr ?? 0x100001000n;
  const header = Buffer.alloc(32);
  header.writeUInt32LE(o.magic ?? 0xfeedfacf, 0);
  header.writeUInt32LE(0x01000007, 4);
  header.writeUInt32LE(2, 12);
  header.writeUInt32LE(1, 16);
  header.writeUInt32LE(72 + 80, 20);
  const seg = Buffer.alloc(72);
  seg.writeUInt32LE(0x19, 0);
  seg.writeUInt32LE(72 + 80, 4);
  seg.write("__DATA", 8, "latin1");
  seg.writeBigUInt64LE(vmaddr, 24);
  seg.writeBigUInt64LE(BigInt(payload.length), 32);
  seg.writeBigUInt64LE(0x1000n, 40);
  seg.writeBigUInt64LE(BigInt(payload.length), 48);
  seg.writeUInt32LE(1, 64);
  const sect = Buffer.alloc(80);
  sect.write(o.sectionName ?? "__go_buildinfo", 0, "latin1");
  sect.write("__DATA", 16, "latin1");
  sect.writeBigUInt64LE(vmaddr, 32);
  sect.writeBigUInt64LE(BigInt(payload.length), 40);
  sect.writeUInt32LE(0x1000, 48);
  sect.writeUInt32LE(4, 52);
  const head = Buffer.concat([header, seg, sect]);
  return { file: Buffer.concat([head, Buffer.alloc(0x1000 - head.length), payload]), base: vmaddr };
}

/** A fat (universal) Mach-O: the big-endian fat header of <mach-o/fat.h> and the slices at 0x4000 multiples. */
function fat(slices: { cpu: number; data: Buffer }[]): Buffer {
  const head = Buffer.alloc(8 + 20 * slices.length);
  head.writeUInt32BE(0xcafebabe, 0);
  head.writeUInt32BE(slices.length, 4);
  let at = 0x4000;
  let cursor = head.length;
  const parts: Buffer[] = [];
  slices.forEach((s, i) => {
    head.writeInt32BE(s.cpu, 8 + 20 * i);
    head.writeUInt32BE(at, 8 + 20 * i + 8);
    head.writeUInt32BE(s.data.length, 8 + 20 * i + 12);
    head.writeUInt32BE(14, 8 + 20 * i + 16);
    parts.push(Buffer.alloc(at - cursor), s.data);
    cursor = at + s.data.length;
    at = Math.ceil(cursor / 0x4000) * 0x4000;
  });
  return Buffer.concat([head, ...parts]);
}

const SUM = (n: number): string => "h1:" + Buffer.alloc(32, n).toString("base64");
const REVISION = "0123456789abcdef0123456789abcdef01234567";
const BASIC = [
  "path\texample.org/cmd/tool",
  "mod\texample.org/tool\tv1.4.0\t",
  `dep\tgolang.org/x/sys\tv0.20.0\t${SUM(1)}`,
  `dep\tgithub.com/pkg/errors\tv0.9.1\t${SUM(2)}`,
  `=>\texample.org/fork/errors\tv0.9.2\t${SUM(3)}`,
  `dep\tgolang.org/x/text\tv0.0.0-20240101123456-abcdef123456\t${SUM(4)}`,
  "build\t-buildmode=exe",
  "build\t-compiler=gc",
  'build\t-ldflags="-s -w -X main.version=1.4.0"',
  "build\tCGO_ENABLED=0",
  "build\tGOARCH=amd64",
  "build\tGOOS=linux",
  "build\tvcs=git",
  `build\tvcs.revision=${REVISION}`,
  "build\tvcs.time=2024-05-01T10:20:30Z",
  "build\tvcs.modified=false",
];

async function run(cwd: string, file: Buffer, args: Json = {}, name = "work/sample.bin"): Promise<Json> {
  await put(cwd, name, file);
  return body(await tool(GO_BUILDINFO, cwd, { path: name, ...args }));
}

function only(answer: Json): Json {
  assert.equal(answer.builds.length, 1);
  return answer.builds[0];
}

function checkBasic(build: Json): void {
  assert.equal(build.found, true);
  assert.equal(build.go_version, "go1.22.5");
  assert.equal(build.main_package, "example.org/cmd/tool");
  assert.deepEqual(build.main_module, { path: "example.org/tool", version: "v1.4.0", sum: "", replacement: null });
  const deps = build.dependencies.rows;
  assert.deepEqual(deps.map((d: Json) => d.path), ["golang.org/x/sys", "github.com/pkg/errors", "golang.org/x/text"]);
  assert.deepEqual(deps.map((d: Json) => d.version), ["v0.20.0", "v0.9.1", "v0.0.0-20240101123456-abcdef123456"]);
  assert.equal(deps[0].sum, SUM(1));
  assert.deepEqual(deps[1].replacement, { path: "example.org/fork/errors", version: "v0.9.2", sum: SUM(3) });
  assert.equal(deps[0].replacement, null);
  assert.equal(build.dependencies.matched, 3);
  const settings = Object.fromEntries(build.build_settings.rows.map((r: Json) => [r.key, r.value]));
  assert.equal(settings["-compiler"], "gc");
  assert.equal(settings["-ldflags"], "-s -w -X main.version=1.4.0");
  assert.equal(settings.CGO_ENABLED, "0");
  assert.equal(settings.GOOS, "linux");
  assert.equal(settings.GOARCH, "amd64");
  assert.equal(settings["vcs.revision"], REVISION);
  assert.equal(build.build_settings_selected["-compiler"], "gc");
  assert.equal(build.status, "complete");
  assert.match(build.status_basis, /start sentinel to the end sentinel/);
}

// --- both header formats, the three containers --------------------------------------------------------------------------------

test("ELF64 little-endian, inline format: the version, the main module, every dependency with its replacement, and the build settings", async () => {
  await withCwd(async (cwd) => {
    const file = elf(inlineInfo("go1.22.5", modBlock(BASIC)));
    const answer = await run(cwd, file);
    const build = only(answer);
    checkBasic(build);
    assert.equal(build.container, "elf");
    assert.equal(build.header.format, "inline");
    assert.equal(build.header.offset, 0x100);
    assert.equal(build.header.found_in, "the .go.buildinfo section");
    assert.equal(answer.status, "complete");
    assert.equal(answer.found, true);
    assert.ok(answer.status_basis.length > 10);
  });
});

test("ELF32 big-endian, pointer format: the addresses are turned into offsets through the program header", async () => {
  await withCwd(async (cwd) => {
    const vaddr = 0x8049100n;
    const file = elf(pointerInfo("go1.17.13", modBlock(BASIC), vaddr, 4, true), { cls: 32, big: true, vaddr });
    const build = only(await run(cwd, file));
    assert.equal(build.go_version, "go1.17.13");
    assert.equal(build.header.format, "pointer");
    assert.equal(build.header.pointer_size, 4);
    assert.equal(build.byte_order, "big");
    assert.equal(build.dependencies.matched, 3);
    assert.equal(build.status, "complete");
    assert.equal(build.main_package, "example.org/cmd/tool");
  });
});

test("an ELF without a .go.buildinfo section is searched through its writable data segment, and one with no headers at all by a scan of the file", async () => {
  await withCwd(async (cwd) => {
    const payload = inlineInfo("go1.21.0", modBlock(BASIC));
    const bySegment = only(await run(cwd, elf(payload, { section: false })));
    assert.match(bySegment.header.found_in, /writable data segment/);
    assert.equal(bySegment.status, "complete");
    const byScan = only(await run(cwd, elf(payload, { section: false, segment: false }), {}, "work/scan.bin"));
    assert.equal(byScan.header.found_in, "a scan of the file for the magic");
    assert.equal(byScan.dependencies.matched, 3);
    assert.equal(byScan.status, "complete");
  });
});

test("PE32+ pointer format: the pointers are virtual addresses, image base plus the section's address", async () => {
  await withCwd(async (cwd) => {
    const probe = pe(Buffer.alloc(16));
    const built = pe(pointerInfo("go1.16.15", modBlock(BASIC), probe.base, 8, false));
    const build = only(await run(cwd, built.file, {}, "work/win.exe"));
    assert.equal(build.container, "pe");
    assert.equal(build.go_version, "go1.16.15");
    assert.equal(build.header.format, "pointer");
    assert.equal(build.header.found_in, "the .data section");
    assert.equal(build.dependencies.matched, 3);
    assert.equal(build.status, "complete");
  });
});

test("PE32 inline format reads from the .data section", async () => {
  await withCwd(async (cwd) => {
    const built = pe(inlineInfo("go1.22.5", modBlock(BASIC), { ptr: 4 }), { plus: false });
    const build = only(await run(cwd, built.file, {}, "work/win32.exe"));
    checkBasic(build);
    assert.equal(build.bits, 32);
  });
});

test("Mach-O 64 inline format, read from the __DATA,__go_buildinfo section", async () => {
  await withCwd(async (cwd) => {
    const build = only(await run(cwd, macho(inlineInfo("go1.22.5", modBlock(BASIC))).file, {}, "work/mac"));
    checkBasic(build);
    assert.equal(build.container, "macho");
    assert.equal(build.header.found_in, "the __DATA,__go_buildinfo section");
  });
});

test("Mach-O pointer format maps an address through the segment's vmaddr and file offset", async () => {
  await withCwd(async (cwd) => {
    const vmaddr = 0x100001000n;
    const build = only(await run(cwd, macho(pointerInfo("go1.15.15", modBlock(BASIC), vmaddr, 8, false), { vmaddr }).file, {}, "work/mac15"));
    assert.equal(build.go_version, "go1.15.15");
    assert.equal(build.dependencies.matched, 3);
    assert.equal(build.status, "complete");
  });
});

test("a universal binary is read slice by slice: a slice with a header is read in full, a slice without one is searched in full", async () => {
  await withCwd(async (cwd) => {
    const withInfo = macho(inlineInfo("go1.22.5", modBlock(BASIC))).file;
    const without = macho(Buffer.alloc(64), { sectionName: "__other" }).file;
    const answer = await run(cwd, fat([{ cpu: 0x01000007, data: withInfo }, { cpu: 0x0100000c, data: without }]), {}, "work/uni");
    assert.equal(answer.container, "universal");
    assert.equal(answer.builds.length, 2);
    checkBasic(answer.builds[0]);
    assert.equal(answer.builds[0].slice.index, 0);
    assert.equal(answer.builds[0].header.offset, 0x4000 + 0x1000);
    assert.equal(answer.builds[1].found, false);
    assert.equal(answer.builds[1].status, "complete");
    assert.equal(answer.found, true);
    assert.equal(answer.status, "complete");
  });
});

// --- found: false, and what is not accepted ------------------------------------------------------------------------------------

test("a file with no header is found: false and complete, and says that absence is not 'not Go'", async () => {
  await withCwd(async (cwd) => {
    const answer = await run(cwd, elf(Buffer.alloc(64)));
    assert.equal(answer.found, false);
    assert.equal(answer.status, "complete");
    assert.match(answer.status_basis, /absence is not 'not Go'/);
  });
});

test("a magic at an offset that is not a multiple of 16 is not a header: found false, the copy named", async () => {
  await withCwd(async (cwd) => {
    const info = inlineInfo("go1.22.5", modBlock(BASIC));
    const answer = await run(cwd, elf(Buffer.concat([Buffer.alloc(5), info]), { section: false, segment: false }));
    const build = only(answer);
    assert.equal(build.found, false);
    assert.equal(build.unaligned_copies.count, 1);
    assert.deepEqual(build.unaligned_copies.first_offsets, [0x105]);
    assert.equal(build.status, "complete");
  });
});

test("a file that is not an ELF, PE or Mach-O is unsupported, not 'no header found'", async () => {
  await withCwd(async (cwd) => {
    const answer = await run(cwd, Buffer.concat([Buffer.from("not an executable\n"), inlineInfo("go1.22.5", modBlock(BASIC))]));
    assert.equal(answer.status, "unsupported");
    assert.equal(answer.found, false);
    assert.match(answer.status_basis, /not an ELF, PE or Mach-O/);
  });
});

// --- damaged build information: named, never complete ---------------------------------------------------------------------------

test("a module block cut by the end of the file is partial: the cut is named and the half line is not read", async () => {
  await withCwd(async (cwd) => {
    const file = elf(inlineInfo("go1.22.5", modBlock(BASIC)));
    const cut = file.subarray(0, file.indexOf(Buffer.from("build\tvcs.revision")) + 20);
    const answer = await run(cwd, cut, {}, "work/cut.bin");
    const build = only(answer);
    assert.equal(build.found, true);
    assert.equal(build.go_version, "go1.22.5");
    assert.equal(build.status, "partial");
    assert.equal(answer.status, "partial");
    assert.ok(answer.problems.some((p: string) => /cut|declared/.test(p)), answer.problems.join("|"));
    assert.equal(build.dependencies.matched, 3);
    const keys = build.build_settings.rows.map((r: Json) => r.key);
    assert.ok(keys.includes("vcs.time") === false && !keys.includes("vcs.revision"), "the line that was cut is not a setting");
  });
});

test("a varint that overflows 64 bits is a named problem and the answer is not complete", async () => {
  await withCwd(async (cwd) => {
    const head = Buffer.alloc(32);
    MAGIC.copy(head);
    head[14] = 8;
    head[15] = 2;
    // ten bytes whose last one is 0x7f: more than 64 bits
    const bad = Buffer.concat([head, Buffer.from([0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x7f]), Buffer.alloc(40)]);
    const answer = await run(cwd, elf(bad));
    assert.equal(answer.status, "partial");
    assert.equal(only(answer).found, true);
    assert.equal(only(answer).go_version, null);
    assert.ok(answer.problems.some((p: string) => /overflow/.test(p)), answer.problems.join("|"));
    // eleven bytes of continuation: also an overflow, and no read past them
    const long = Buffer.concat([head, Buffer.alloc(11, 0x80), Buffer.alloc(40)]);
    const second = await run(cwd, elf(long), {}, "work/long.bin");
    assert.equal(second.status, "partial");
    assert.ok(second.problems.some((p: string) => /overflow/.test(p)));
  });
});

test("a declared string longer than the file is a named problem, never a read past the end", async () => {
  await withCwd(async (cwd) => {
    const head = Buffer.alloc(32);
    MAGIC.copy(head);
    head[14] = 8;
    head[15] = 2;
    const bad = Buffer.concat([head, uvarint(2 ** 40), Buffer.from("go1.22.5")]);
    const answer = await run(cwd, elf(bad));
    assert.equal(answer.status, "partial");
    assert.ok(answer.problems.some((p: string) => /version string/.test(p)), answer.problems.join("|"));
  });
});

test("a pointer past the end of the file, and one outside every segment, are named: the version is kept, the module block is not guessed", async () => {
  await withCwd(async (cwd) => {
    const vaddr = 0x4a0100n;
    const outside = only(await run(cwd, elf(pointerInfo("go1.17.13", modBlock(BASIC), vaddr, 8, false, { modPointer: 0xdead0000n }), { vaddr }), {}, "work/outside.bin"));
    assert.equal(outside.status, "partial");
    assert.equal(outside.go_version, "go1.17.13");
    assert.equal(outside.dependencies.matched, 0);
    const answer = await run(cwd, elf(pointerInfo("go1.17.13", modBlock(BASIC), vaddr, 8, false, { modPointer: 0xdead0000n }), { vaddr }), {}, "work/outside2.bin");
    assert.ok(answer.problems.some((p: string) => /outside every section or segment/.test(p)), answer.problems.join("|"));
    // a segment that claims more file bytes than the file holds: the pointer into the missing part runs past the end
    const full = elf(pointerInfo("go1.17.13", modBlock(BASIC), vaddr, 8, false), { vaddr });
    const shortened = full.subarray(0, 0x100 + 200);
    const past = await run(cwd, shortened, {}, "work/past.bin");
    assert.equal(past.status, "partial");
    assert.ok(past.problems.length > 0);
  });
});

test("a module block whose sentinels are not the ones the go command writes is read but never complete", async () => {
  await withCwd(async (cwd) => {
    const text = Buffer.from(BASIC.join("\n") + "\n", "latin1");
    const wrong = Buffer.concat([Buffer.alloc(16, 0x41), text, Buffer.alloc(16, 0x42)]);
    const answer = await run(cwd, elf(inlineInfo("go1.22.5", wrong)));
    assert.equal(answer.status, "partial");
    assert.equal(only(answer).dependencies.matched, 3);
    assert.ok(answer.problems.some((p: string) => /sentinel/.test(p)));
  });
});

test("a module block of no bytes is a binary built outside module mode: complete, with the version", async () => {
  await withCwd(async (cwd) => {
    const answer = await run(cwd, elf(inlineInfo("go1.22.5", Buffer.alloc(0))));
    assert.equal(answer.status, "complete");
    assert.equal(only(answer).go_version, "go1.22.5");
    assert.equal(only(answer).module_block.present, false);
    assert.match(only(answer).status_basis, /no module information/);
  });
});

test("an unknown line kind and a build line the go command would not write are counted, kept as text, and make the answer partial", async () => {
  await withCwd(async (cwd) => {
    const lines = [...BASIC.slice(0, 4), "weird\tfoo", 'build\t"unterminated=1', ...BASIC.slice(6)];
    const answer = await run(cwd, elf(inlineInfo("go1.22.5", modBlock(lines))));
    assert.equal(answer.status, "partial");
    assert.ok(answer.problems.some((p: string) => /kind the tool does not read/.test(p)));
    assert.ok(answer.problems.some((p: string) => /not in the form the go command writes/.test(p)));
    const rows = only(answer).build_settings.rows;
    assert.equal(rows.filter((r: Json) => r.parsed === false).length, 1);
  });
});

// --- the answer is bounded, the whole is on disk ----------------------------------------------------------------------------------

test("1,200 dependencies with limit 100: 100 inline, all 1,200 in a 0600 JSON Lines file, in order, under a umask of 022", async () => {
  await withCwd(async (cwd) => {
    const deps = Array.from({ length: 1200 }, (_, i) => `dep\texample.org/mod${String(i).padStart(4, "0")}\tv1.0.${i}\t${SUM(i % 250)}`);
    const answer = await run(cwd, elf(inlineInfo("go1.22.5", modBlock(["path\texample.org/main", ...deps, "build\tGOOS=linux"]))), { limit: 100 });
    const build = only(answer);
    assert.equal(build.dependencies.matched, 1200);
    assert.equal(build.dependencies.returned, 100);
    assert.equal(build.dependencies.truncated, true);
    assert.equal(build.status, "complete");
    const file = build.dependencies.all_results as string;
    assert.match(file, /^work\/s1\/tool-output\/go_buildinfo-dependencies-[0-9a-f]{16}\.jsonl$/);
    const rows = (await readFile(join(cwd, file), "utf8")).trim().split("\n").map((l) => JSON.parse(l));
    assert.equal(rows.length, 1200);
    assert.deepEqual(rows.map((r) => r.n), Array.from({ length: 1200 }, (_, i) => i + 1));
    assert.equal(rows[1199].path, "example.org/mod1199");
    assert.equal(((await stat(join(cwd, file))).mode & 0o777).toString(8), "600");
    // a rerun never replaces the file: the second call's whole table has a name of its own
    const second = only(await run(cwd, elf(inlineInfo("go1.22.5", modBlock(["path\texample.org/main", ...deps, "build\tGOOS=linux"]))), { limit: 100 }));
    assert.notEqual(second.dependencies.all_results, file);
    assert.equal((await readFile(join(cwd, file), "utf8")).trim().split("\n").length, 1200);
  });
});

test("a module block of 80 MiB is read to the cap, named, and never complete", async () => {
  await withCwd(async (cwd) => {
    const filler = "build\tfiller=" + "x".repeat(100_000);
    const lines = Array.from({ length: 700 }, () => filler);
    const block = modBlock(lines);
    assert.ok(block.length > 64 << 20);
    const answer = await run(cwd, elf(inlineInfo("go1.22.5", block)), { limit: 10 }, "work/big.bin");
    assert.equal(answer.status, "partial");
    assert.ok(answer.limits_hit.some((t: string) => /module block: \d+ bytes are declared/.test(t)), answer.limits_hit.join("|"));
    assert.equal(only(answer).build_settings.returned, 10);
  });
});

// --- withholding ------------------------------------------------------------------------------------------------------------------

async function planted(cwd: string, slot: string, seed: number): Promise<{ stdout: string; files: string; needleList: ReturnType<typeof needles>[]; built: number }> {
  const list = canaries(slot === "version" ? 40 : 200, seed);
  const lines: string[] = ["path\texample.org/cmd/tool"];
  const needleList: ReturnType<typeof needles>[] = [];
  let version = "go1.22.5";
  list.forEach(([, canary], i) => {
    needleList.push(needles(canary));
    const text = canary.plant;
    switch (slot) {
      case "dep_path": lines.push(`dep\texample.org/${text}\tv1.0.${i}\t${SUM(i)}`); break;
      case "dep_version": lines.push(`dep\texample.org/m${i}\tv1.0.0-${text}\t${SUM(i)}`); break;
      case "dep_sum": lines.push(`dep\texample.org/m${i}\tv1.0.${i}\t${text}`); break;
      case "replacement": lines.push(`dep\texample.org/m${i}\tv1.0.${i}\t${SUM(i)}`, `=>\t../${text}\tv1.0.${i}\t${text}`); break;
      case "main_module": lines.push(`mod\texample.org/${text}\tv1.0.${i}\t${text}`); break;
      case "setting_key": lines.push(`build\t${text}=1`); break;
      case "setting_value": lines.push(`build\tflag${i}=${text}`); break;
      case "ldflags": lines.push(`build\t-ldflags="-s -w -X main.build${i}=${text}"`); break;
      case "version": version = "go1.22.5 " + text; break;
      case "main_package": lines[0] = `path\texample.org/${text}`; break;
      default: throw new Error(slot);
    }
  });
  const file = elf(inlineInfo(version, modBlock(lines)));
  await put(cwd, "work/canary.bin", file);
  const out = await tool(GO_BUILDINFO, cwd, { path: "work/canary.bin", limit: 5 });
  assert.equal(out.code, 0, out.stderr);
  assert.equal(JSON.parse(out.stdout).found, true, "the header was found and read, so the absence of a canary means something");
  const parts: string[] = [out.stdout];
  const dir = join(cwd, "work", "s1", "tool-output");
  const names = await readdir(dir).catch(() => [] as string[]);
  for (const n of names) parts.push(await readFile(join(dir, n), "latin1"));
  return { stdout: out.stdout, files: parts.join("\n"), needleList, built: list.length };
}

const SEEDS = Number(process.env.RE_CANARY_SEEDS ?? 4);
const SLOTS = ["dep_path", "dep_version", "dep_sum", "replacement", "main_module", "setting_key", "setting_value", "ldflags", "version", "main_package"];

test("canaries of every shape the shared block names, planted in every printed slot (path, version, sum, replacement, main module and package, setting key and value, -ldflags, toolchain version), are withheld from the answer and the files", async () => {
  await withCwd(async (cwd) => {
    let planted_ = 0;
    let missed = 0;
    const misses: string[] = [];
    for (const slot of SLOTS) {
      for (let seed = 1; seed <= SEEDS; seed++) {
        const r = await planted(cwd, slot, seed);
        const text = Buffer.from(r.files, "latin1");
        r.needleList.forEach((list, i) => {
          planted_ += 1;
          const hit = list.find((n) => text.includes(n.bytes));
          if (hit) {
            missed += 1;
            misses.push(`${slot}#${seed}.${i}: ${hit.label}`);
          }
        });
        await rm(join(cwd, "work", "s1"), { recursive: true, force: true });
      }
    }
    // The miss rate is stated in the manifest (the Wilson bound at 95% for the measured count); a shape the block does not cover is printed.
    console.log(`canaries: ${missed} of ${planted_} reached an output; ${misses.slice(0, 40).join("; ")}`);
    assert.ok(planted_ >= 600, `${planted_} canaries planted`);
    // 17 shapes, 10 slots: with RE_CANARY_SEEDS=50 that is 500 per shape and none of those reached an output (the Wilson upper bound at 95% is 0.8% per shape for these shapes and slots; it does not cover a 30-character base64 run in -tags, which a later review measured leaking,
    // the figure the manifest states). A shape the rules do not name, and a secret of no shape, are printed: this test says nothing of them.
    assert.equal(missed, 0, `${missed} of ${planted_} canaries reached an output: ${misses.slice(0, 12).join("; ")}`);
  });
});

test("the value of an -X whose symbol name says secret (token, password, key) is withheld whole, whatever its shape", async () => {
  await withCwd(async (cwd) => {
    const secret = "hunter2-plain-words";
    const lines = ["path\texample.org/cmd", `build\t-ldflags="-s -w -X main.apiToken=${secret} -X main.version=1.2.3 -X 'main.dbPassword=${secret}2'"`];
    const answer = await run(cwd, elf(inlineInfo("go1.22.5", modBlock(lines))));
    assert.ok(!JSON.stringify(answer).includes(secret), "the secret-named values are not in the answer");
    const flags = only(answer).build_settings.rows[0].value as string;
    assert.match(flags, /main\.apiToken=<secret-named value withheld 19 characters>/);
    assert.match(flags, /main\.version=1\.2\.3/);
    assert.match(flags, /main\.dbPassword=.*<secret-named value withheld 20 characters>/);
  });
});

test("a token split by a NUL, a zero-width character or a soft hyphen is withheld whole", async () => {
  await withCwd(async (cwd) => {
    const key = "AKIA" + "QWERTYUIOP123456";
    const split = `${key.slice(0, 8)}​${key.slice(8)}`;
    const lines = ["path\texample.org/cmd", `build\tnote=${split}`, `build\tnote2=${key.slice(0, 6)}\x00${key.slice(6)}`, `build\tnote3=${key.slice(0, 10)}­${key.slice(10)}`];
    await put(cwd, "work/split.bin", elf(inlineInfo("go1.22.5", modBlock(lines))));
    const out = await tool(GO_BUILDINFO, cwd, { path: "work/split.bin" });
    const text = out.stdout;
    assert.equal(out.code, 0, out.stderr);
    assert.equal(JSON.parse(text).builds[0].build_settings.matched, 3, "the three settings were read");
    for (const piece of [key.slice(6, 16), key.slice(8, 16), "QWERTYUI"]) assert.ok(!text.includes(piece), `holds ${piece}`);
  });
});

test("write_values: refused as JSON before anything is read outside a job and in a job that is not secret output; in a secret job the whole strings are in a 0600 file and not in the answer", async () => {
  await withCwd(async (cwd) => {
    const token = "ghp_" + "aB3dE5fG7hJ9kL1mN3pQ5rS7tU9vW1xY3zA5";
    const lines = ["path\texample.org/cmd", `build\t-ldflags="-X main.build=${token}"`, "build\tGOOS=linux"];
    await put(cwd, "work/v.bin", elf(inlineInfo("go1.22.5", modBlock(lines))));
    const outside = refused(await tool(GO_BUILDINFO, cwd, { path: "work/v.bin", write_values: true }));
    assert.equal(outside.write_values, "refused");
    assert.equal(outside.status, "failed");
    assert.match(outside.status_basis, /secret output/);
    const plainJob = refused(await asJob(GO_BUILDINFO, cwd, { path: "work/v.bin", write_values: true }));
    assert.equal(plainJob.write_values, "refused");
    assert.deepEqual(await readdir(join(cwd, "out")), []);
    const secret = await asJob(GO_BUILDINFO, cwd, { path: "work/v.bin", write_values: true }, undefined, { SECRET_OUTPUT: "1" }, "out2");
    const answer = body(secret);
    assert.ok(!secret.stdout.includes(token), "the answer holds no part of the token");
    assert.equal(answer.secret_values.written, 1);
    assert.equal(answer.secret_values.contains_secret_values, true);
    const values = join(cwd, "out2", "go-buildinfo-values.jsonl");
    assert.equal(((await stat(values)).mode & 0o777).toString(8), "600");
    const row = JSON.parse((await readFile(values, "utf8")).trim());
    assert.ok(row.value.includes(token));
    assert.equal(row.field, "build_setting[1].value");
  });
});

test("the backstop holds with the sanitiser removed: raw strings from the file and an injected one reach no output, the fields are counted and the answer is partial", async () => {
  await withCwd(async (cwd) => {
    const aws = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY";
    const gh = "ghp_Ab3dEf5hIj7lMn9pQr1tUv3xYz5bCd7fGh9j";
    const lines = ["path\texample.org/cmd", ...Array.from({ length: 6 }, (_, i) => `dep\texample.org/${aws}${i}\tv1.0.${i}\t${SUM(i)}`), `build\tnote=${gh}`, "build\tGOOS=linux"];
    await put(cwd, "work/bypass.bin", elf(inlineInfo("go1.22.5", modBlock(lines))));
    const code = [
      "import importlib.util, io, json, sys",
      "spec = importlib.util.spec_from_file_location('tool_under_test', sys.argv[1])",
      "m = importlib.util.module_from_spec(spec)",
      "spec.loader.exec_module(m)",
      "m.shown_answer = lambda value, key='': value",
      "m.text_of = lambda value: value if isinstance(value, str) else str(value)",
      "emit = m.emit",
      `m.emit = lambda result: emit({**result, 'injected': '${gh}'})`,
      "sys.stdin = io.StringIO(json.dumps({'path': 'work/bypass.bin', 'limit': 2}))",
      "try:",
      "    m.main()",
      "except SystemExit:",
      "    pass",
    ].join("\n");
    const r = spawnSync("python3", ["-c", code, GO_BUILDINFO], { cwd, encoding: "utf8", env: { ...process.env, AGENT_ID: "s1" } });
    assert.doesNotMatch(r.stderr, /Traceback/, r.stderr);
    const answer = JSON.parse(r.stdout) as Json;
    const files: string[] = [r.stdout];
    for (const n of await readdir(join(cwd, "work", "s1", "tool-output"))) files.push(await readFile(join(cwd, "work", "s1", "tool-output", n), "latin1"));
    const text = files.join("\n");
    for (const secret of [aws, gh]) for (let i = 0; i + 9 <= secret.length; i++) assert.ok(!text.includes(secret.slice(i, i + 9)), `an output holds ${secret.slice(i, i + 9)}`);
    assert.ok(answer.withheld_by_final_check >= 3, String(answer.withheld_by_final_check));
    assert.equal(answer.status, "partial");
    assert.ok(answer.problems.some((p: string) => /the final check withheld \d+ field/.test(p)));
  });
});

// --- hostile input and parameters -------------------------------------------------------------------------------------------------

test("hostile parameters give a JSON refusal and never a traceback", async () => {
  await withCwd(async (cwd) => {
    await put(cwd, "work/ok.bin", elf(inlineInfo("go1.22.5", modBlock(BASIC))));
    const cases: Json[] = [
      {}, { path: 5 }, { path: "" }, { path: "work/ok\u0000.bin" }, { path: "work/\ud800.bin" }, { path: "work/ok.bin", limit: 10 ** 30 }, { path: "work/ok.bin", limit: -1 },
      { path: "work/ok.bin", limit: "5" }, { path: "work/ok.bin", limit: 1.5 }, { path: "work/ok.bin", max_seconds: true }, { path: "work/ok.bin", max_scan_bytes: [] },
      { path: "work/ok.bin", write_values: "yes" }, { path: "work/ok.bin", surprise: 1 }, [], "text", null, { path: ["work/ok.bin"] }, { path: "work/ok.bin", limit: null },
    ];
    for (const args of cases) {
      const out = refused(await tool(GO_BUILDINFO, cwd, args));
      assert.equal(out.status, "failed", JSON.stringify(args));
      assert.ok(typeof out.status_basis === "string" && out.status_basis.length > 0);
    }
    const deep = "[".repeat(100_000);
    for (const raw of [deep, "{" + '"path":'.repeat(50_000), "1".repeat(100_000), "\ud800"]) {
      const r = spawnSync("python3", [GO_BUILDINFO], { input: raw, cwd, encoding: "utf8", env: { ...process.env, AGENT_ID: "s1" } });
      assert.doesNotMatch(r.stderr, /Traceback/);
      assert.notEqual(r.status, 0);
      assert.equal(JSON.parse(r.stdout).status, "failed");
    }
  });
});

test("a FIFO, a directory, a symbolic link, an empty file and a missing file are refused as JSON, and a FIFO does not hang the tool", async () => {
  await withCwd(async (cwd) => {
    await put(cwd, "work/real.bin", elf(inlineInfo("go1.22.5", modBlock(BASIC))));
    await symlink(join(cwd, "work", "real.bin"), join(cwd, "work", "link.bin"));
    await put(cwd, "work/empty.bin", Buffer.alloc(0));
    await mkdir(join(cwd, "work", "dir.bin"));
    const fifo = join(cwd, "work", "pipe.bin");
    assert.equal(spawnSync("mkfifo", [fifo]).status, 0);
    const started = Date.now();
    for (const [name, pattern] of [["work/pipe.bin", /not a regular file \(a named pipe\)/], ["work/dir.bin", /a directory/], ["work/link.bin", /symbolic link/], ["work/empty.bin", /empty/], ["work/missing.bin", /no such file/]] as const) {
      const out = refused(await tool(GO_BUILDINFO, cwd, { path: name }));
      assert.match(out.error, pattern, name);
      assert.equal(out.status, "failed");
    }
    assert.ok(Date.now() - started < 20_000, "no refusal waited for a pipe's writer");
  });
});

test("the scan for the header stops at its byte budget and at max_seconds, and says so: absence is not claimed", async () => {
  await withCwd(async (cwd) => {
    const file = join(cwd, "work", "huge.bin");
    await mkdir(join(cwd, "work"), { recursive: true });
    await writeFile(file, elf(Buffer.alloc(64), { section: false, segment: false }));
    await truncate(file, 3 << 20);
    const budget = body(await tool(GO_BUILDINFO, cwd, { path: "work/huge.bin", max_scan_bytes: 1 << 20 }));
    assert.equal(budget.status, "partial");
    assert.equal(budget.found, false);
    assert.ok(budget.limits_hit.some((t: string) => /scan: the budget of 1048576 bytes was reached/.test(t)), budget.limits_hit.join("|"));
    assert.match(budget.status_basis, /limit/);
    const whole = body(await tool(GO_BUILDINFO, cwd, { path: "work/huge.bin" }));
    assert.equal(whole.status, "complete");
  });
});

test("max_seconds ends the scan of a sparse 12 GiB file and the reading of a module block of 600,000 lines: partial, the limit named, the call back within seconds", async () => {
  await withCwd(async (cwd) => {
    const sparse = join(cwd, "work", "sparse.bin");
    await mkdir(join(cwd, "work"), { recursive: true });
    await writeFile(sparse, elf(Buffer.alloc(64), { section: false, segment: false }));
    await truncate(sparse, 12 * 2 ** 30);
    let started = Date.now();
    const scan = body(await tool(GO_BUILDINFO, cwd, { path: "work/sparse.bin", max_seconds: 1, max_scan_bytes: 2 ** 32 }));
    assert.equal(scan.status, "partial");
    assert.equal(scan.found, false);
    assert.ok(scan.limits_hit.some((t: string) => /^time: the scan for the header stopped at max_seconds \(1\)|^scan: the budget of 4294967296/.test(t)), scan.limits_hit.join("|"));
    assert.ok(Date.now() - started < 30_000, `${Date.now() - started} ms`);
    await rm(sparse);
    const deps = Array.from({ length: 600_000 }, (_, i) => `dep\tex.org/m${i}\tv1.0.0\t`);
    await put(cwd, "work/lines.bin", elf(inlineInfo("go1.22.5", modBlock(["path\tex.org/main", ...deps]))));
    started = Date.now();
    const lines = body(await tool(GO_BUILDINFO, cwd, { path: "work/lines.bin", max_seconds: 1, limit: 10 }));
    assert.equal(lines.status, "partial");
    assert.ok(lines.limits_hit.some((t: string) => /^time: the module block stopped at max_seconds \(1\)/.test(t)), lines.limits_hit.join("|"));
    const build = only(lines);
    assert.ok(build.dependencies.matched > 0 && build.dependencies.matched < 600_000, String(build.dependencies.matched));
    assert.equal(build.dependencies.returned, 10);
    assert.ok(Date.now() - started < 30_000, `${Date.now() - started} ms`);
  });
});

// --- one real Go binary, when the toolchain is here -------------------------------------------------------------------------------------

const GO = spawnSync("go", ["version"], { encoding: "utf8" });

test("a binary built by the machine's own Go toolchain is read: the version `go version` prints, the main module and the build settings", { skip: GO.status === 0 ? false : "go is not on this machine" }, async () => {
  await withCwd(async (cwd) => {
    const dir = join(cwd, "src");
    await mkdir(dir, { recursive: true });
    await writeFile(join(dir, "go.mod"), "module example.org/hello\n\ngo 1.18\n");
    await writeFile(join(dir, "main.go"), 'package main\n\nimport "fmt"\n\nvar token = "unset"\n\nfunc main() { fmt.Println("hello", token) }\n');
    const built = spawnSync("go", ["build", "-ldflags", "-X main.token=plain-words-here", "-o", join(cwd, "work", "hello")], { cwd: dir, encoding: "utf8", env: { ...process.env, GOFLAGS: "-mod=mod", GOCACHE: join(cwd, "gocache") } });
    assert.equal(built.status, 0, built.stderr);
    const answer = body(await tool(GO_BUILDINFO, cwd, { path: "work/hello" }));
    const build = only(answer);
    assert.equal(build.found, true);
    assert.equal(`go version ${build.go_version}`, GO.stdout.trim().split(" ").slice(0, 3).join(" "));
    assert.equal(build.main_module.path, "example.org/hello");
    assert.equal(build.status, "complete");
    assert.ok(!JSON.stringify(answer).includes("plain-words-here") || build.build_settings.rows.some((r: Json) => r.key === "-ldflags"));
  });
});

// --- round 2: the unaligned copies are counted, not kept ---------------------------------------------------------------------

test("P3 millions of unaligned copies of the magic are counted with a bounded memory: the tool kept every offset in a set nothing read", async () => {
  await withCwd(async (cwd) => {
    const magic = Buffer.from("\xff Go buildinf:", "latin1");
    const unit = Buffer.concat([magic, Buffer.alloc(4)]);                 // a stride of 18 from an odd start: never a multiple of 16 from the start
    const copies = 3_000_000;
    await put(cwd, "work/many.bin", elf(Buffer.concat([Buffer.alloc(5), Buffer.alloc(unit.length * copies).fill(unit)])));
    const script = [
      "import json, resource, subprocess, sys",
      "p = subprocess.run(['python3', sys.argv[1]], input=json.dumps({'path': 'work/many.bin', 'max_seconds': 40}).encode(), capture_output=True)",
      "a = json.loads(p.stdout)",
      "b = a['builds'][0]",
      "print(json.dumps({'rss_mb': resource.getrusage(resource.RUSAGE_CHILDREN).ru_maxrss // 1024, 'count': b['unaligned_copies']['count'], 'status': a['status']}))",
    ].join("\n");
    const r = spawnSync("python3", ["-c", script, GO_BUILDINFO], { cwd, encoding: "utf8", env: { ...process.env, AGENT_ID: "s1" }, timeout: 120_000 });
    assert.equal(r.status, 0, r.stderr);
    const out = JSON.parse(r.stdout) as Json;
    assert.ok(out.count > 1_000_000, `copies counted: ${out.count} (${out.status})`);
    assert.ok(out.rss_mb < 250, `peak memory ${out.rss_mb} MB for a ${(3_000_000 * 18 / 1e6).toFixed(0)} MB file`);
  });
});

test("P2 the manifest says what the withholding bound was measured on, and the rates of uniformly random token-shaped strings", async () => {
  const text = JSON.parse(await readFile(join(TOOLS, "go_buildinfo", "manifest.json"), "utf8")).description as string;
  assert.match(text, /forced to hold a lower-case letter, a capital and a digit/);
  assert.match(text, /drawn uniformly at random/);
  assert.match(text, /about 11% of sk_live_ keys, about 5% of Slack webhook URLs and about 3% of 30-character AWS secret keys/);
  assert.match(text, /rely on those rates, not on the bound above/);
});
