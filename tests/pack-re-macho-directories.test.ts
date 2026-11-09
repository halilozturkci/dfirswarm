/**
 * macho_directories: Mach-O files built here from <mach-o/loader.h>, <mach-o/fat.h>, <mach-o/nlist.h>, <mach-o/fixup-chains.h> and the code-signing
 * blob layout (cs_blobs.h), in both byte orders and both widths, read by the tool. A fixture is built from the format's layout and never from the
 * tool's output; agreement with `otool -l` is tested only where otool exists.
 *
 * What these cases hold: a universal binary is read slice by slice with each slice's own offsets, a truncated load command, a load-command count
 * larger than the file, a range past the end of the slice and a cut stream are problems and never an empty list, bind opcodes and an export trie
 * decode to the symbols the specification says, a trie that loops ends, the first `limit` rows of each table are in the answer and the whole table is
 * in a file, a string that is token-shaped is withheld on every path, and a pipe, a link and hostile parameters are refused as JSON.
 */
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { mkdir, readFile, readdir, stat, symlink } from "node:fs/promises";
import { join } from "node:path";
import { test } from "node:test";
import { MACHO_DIRECTORIES, body, buildFat, filesUnder, put, refused, startDetached, termHandlerIn, tool, withCwd } from "./pack-re-harness.ts";
import type { Json } from "./pack-re-harness.ts";

const CPU_X86_64 = 0x01000007, CPU_ARM64 = 0x0100000c, CPU_X86 = 7, CPU_PPC = 18;
const LC_SEGMENT_64 = 0x19, LC_SYMTAB = 2, LC_DYSYMTAB = 0xb, LC_LOAD_DYLIB = 0xc, LC_ID_DYLIB = 0xd, LC_LOAD_DYLINKER = 0xe, LC_UUID = 0x1b, LC_CODE_SIGNATURE = 0x1d;
const LC_DYLD_INFO_ONLY = 0x80000022, LC_BUILD_VERSION = 0x32, LC_RPATH = 0x8000001c, LC_LOAD_WEAK_DYLIB = 0x80000018, LC_FUNCTION_STARTS = 0x26;
const LC_EXPORTS_TRIE = 0x80000033, LC_CHAINED_FIXUPS = 0x80000034, LC_VERSION_MIN_MACOSX = 0x24;

/** Integers in the byte order of one fixture. */
function ints(big: boolean) {
  const u16 = (v: number) => { const b = Buffer.alloc(2); big ? b.writeUInt16BE(v) : b.writeUInt16LE(v); return b; };
  const u32 = (v: number) => { const b = Buffer.alloc(4); big ? b.writeUInt32BE(v >>> 0) : b.writeUInt32LE(v >>> 0); return b; };
  const u64 = (v: number | bigint) => { const b = Buffer.alloc(8); big ? b.writeBigUInt64BE(BigInt(v)) : b.writeBigUInt64LE(BigInt(v)); return b; };
  return { u16, u32, u64 };
}
const pad = (b: Buffer, a: number) => Buffer.concat([b, Buffer.alloc((a - (b.length % a)) % a)]);
const cstr = (s: string) => Buffer.from(s + "\0", "latin1");
const uleb = (v: number | bigint) => {
  let n = BigInt(v);
  const out: number[] = [];
  do { let b = Number(n & 0x7fn); n >>= 7n; if (n) b |= 0x80; out.push(b); } while (n);
  return Buffer.from(out);
};
const be32 = (v: number) => { const b = Buffer.alloc(4); b.writeUInt32BE(v >>> 0); return b; };

type Nlist = { name?: string; strx?: number; type?: number; sect?: number; desc?: number; value?: number };
type Opts = {
  wide?: boolean; big?: boolean; cputype?: number; filetype?: number; flags?: number; ncmds?: number; sizeofcmds?: number;
  /** Builds the commands; `alloc` places a buffer in the data region (after the commands) and returns its offset. */
  commands?: (c: Cmds, alloc: (b: Buffer, align?: number) => number) => Buffer[];
};
const DATA = 4096;

class Cmds {
  wide: boolean; big: boolean;
  u16: (v: number) => Buffer; u32: (v: number) => Buffer; u64: (v: number | bigint) => Buffer;
  constructor(wide: boolean, big: boolean) { this.wide = wide; this.big = big; ({ u16: this.u16, u32: this.u32, u64: this.u64 } = ints(big)); }
  cmd(cmd: number, body: Buffer = Buffer.alloc(0)) { return Buffer.concat([this.u32(cmd), this.u32(8 + body.length), body]); }
  dylib(cmd: number, name: string, current = 0x00010203, compat = 0x00010000, stamp = 2) {
    const n = pad(cstr(name), this.wide ? 8 : 4);
    return Buffer.concat([this.u32(cmd), this.u32(24 + n.length), this.u32(24), this.u32(stamp), this.u32(current), this.u32(compat), n]);
  }
  path(cmd: number, name: string) { const n = pad(cstr(name), this.wide ? 8 : 4); return Buffer.concat([this.u32(cmd), this.u32(12 + n.length), this.u32(12), n]); }
  symtab(symoff: number, nsyms: number, stroff: number, strsize: number) { return this.cmd(LC_SYMTAB, Buffer.concat([symoff, nsyms, stroff, strsize].map((v) => this.u32(v)))); }
  dysymtab(f: number[]) { return this.cmd(LC_DYSYMTAB, Buffer.concat(f.map((v) => this.u32(v)))); }
  dyld(v: number[], cmd = LC_DYLD_INFO_ONLY) { return this.cmd(cmd, Buffer.concat(v.map((x) => this.u32(x)))); }
  linkedit(cmd: number, off: number, size: number) { return this.cmd(cmd, Buffer.concat([this.u32(off), this.u32(size)])); }
  build(platform: number, minos: number, sdk: number, tools: [number, number][] = []) {
    return this.cmd(LC_BUILD_VERSION, Buffer.concat([this.u32(platform), this.u32(minos), this.u32(sdk), this.u32(tools.length), ...tools.flatMap(([t, v]) => [this.u32(t), this.u32(v)])]));
  }
  uuid(hex: string) { return this.cmd(LC_UUID, Buffer.from(hex, "hex")); }
  nlist(n: Nlist, strx: number) {
    const base = [this.u32(strx), Buffer.from([n.type ?? 0x0f, n.sect ?? 1]), this.u16(n.desc ?? 0)];
    return Buffer.concat([...base, this.wide ? this.u64(n.value ?? 0) : this.u32(n.value ?? 0)]);
  }
}

function macho(o: Opts = {}): Buffer {
  const wide = o.wide !== false, big = !!o.big;
  const c = new Cmds(wide, big);
  const data: Buffer[] = [];
  let at = DATA;
  const alloc = (b: Buffer, align = 8) => { while (at % align) { data.push(Buffer.alloc(1)); at += 1; } const where = at; data.push(b); at += b.length; return where; };
  const cmds = o.commands ? o.commands(c, alloc) : [];
  const bodyBytes = Buffer.concat(cmds);
  const magic = wide ? (big ? [0xfe, 0xed, 0xfa, 0xcf] : [0xcf, 0xfa, 0xed, 0xfe]) : big ? [0xfe, 0xed, 0xfa, 0xce] : [0xce, 0xfa, 0xed, 0xfe];
  const header = Buffer.concat([Buffer.from(magic), c.u32(o.cputype ?? (wide ? CPU_X86_64 : CPU_X86)), c.u32(0), c.u32(o.filetype ?? 2), c.u32(o.ncmds ?? cmds.length),
    c.u32(o.sizeofcmds ?? bodyBytes.length), c.u32(o.flags ?? 0x200085), ...(wide ? [c.u32(0)] : [])]);
  const head = Buffer.concat([header, bodyBytes]);
  assert.ok(head.length <= DATA, "the commands fit before the data region");
  return Buffer.concat([head, Buffer.alloc(DATA - head.length), ...data]);
}

/** A string table (a leading NUL, then the names) and the offsets of the names. */
function strings(names: string[]): { table: Buffer; at: number[] } {
  const parts = [Buffer.from([0])];
  let n = 1;
  const at = names.map((s) => { const o = n; const b = cstr(s); parts.push(b); n += b.length; return o; });
  return { table: Buffer.concat(parts), at };
}

/** A file with an nlist table and its strings, and LC_SYMTAB. */
function withSymbols(syms: Nlist[], o: Opts = {}, extra: (c: Cmds, alloc: (b: Buffer, a?: number) => number) => Buffer[] = () => []): Buffer {
  return macho({
    ...o,
    commands: (c, alloc) => {
      const s = strings(syms.map((x) => x.name ?? ""));
      const table = Buffer.concat(syms.map((x, i) => c.nlist(x, x.strx ?? (x.name ? s.at[i]! : 0))));
      const symoff = alloc(table, 8);
      const stroff = alloc(s.table, 1);
      return [c.symtab(symoff, syms.length, stroff, s.table.length), ...extra(c, alloc)];
    },
  });
}

const run = async (cwd: string, name: string, data: Buffer, args: Json = {}) => {
  await put(cwd, `work/${name}`, data);
  return tool(MACHO_DIRECTORIES, cwd, { path: `work/${name}`, ...args });
};
const rowsOf = (out: Json, table: string): Json[] => out.tables[table]?.rows ?? [];

const FAMILIES: [string, Opts][] = [
  ["64-bit little-endian", { wide: true }], ["64-bit big-endian", { wide: true, big: true }], ["32-bit little-endian", { wide: false, cputype: CPU_X86 }], ["32-bit big-endian", { wide: false, big: true, cputype: CPU_PPC }],
];

for (const [label, base] of FAMILIES) {
  test(`${label}: the header, libraries, build version, uuid, symbols and the dysymtab ranges are read`, async () => {
    await withCwd(async (cwd) => {
      const syms: Nlist[] = [
        { name: "_main", type: 0x0f, sect: 1, value: 0x1000 }, { name: "_printf", type: 0x01, sect: 0, desc: 0x0100 }, { name: "_dyn", type: 0x01, sect: 0, desc: 0xfe00 },
        { name: "_local", type: 0x0e, sect: 2, value: 0x2000 }, { name: "-[Thing method]", type: 0x24, sect: 0, desc: 0 },
      ];
      const data = withSymbols(syms, base, (c) => [
        c.dylib(LC_LOAD_DYLIB, "/usr/lib/libSystem.B.dylib", 0x04c70000, 0x00010000), c.dylib(LC_LOAD_WEAK_DYLIB, "@rpath/libweak.dylib"), c.dylib(LC_ID_DYLIB, "@rpath/libme.dylib"),
        c.path(LC_RPATH, "@loader_path/../Frameworks"), c.path(LC_LOAD_DYLINKER, "/usr/lib/dyld"), c.uuid("00112233445566778899aabbccddeeff"),
        c.build(1, 0x000a0f00, 0x000b0100, [[3, 0x2ab800]]),
        c.dysymtab([0, 2, 2, 1, 3, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]),
      ]);
      const out = body(await run(cwd, "a.macho", data));
      assert.equal(out.status, "complete", JSON.stringify([out.problems, out.limits_hit]));
      const s = out.slices[0];
      assert.equal(s.bits, base.wide === false ? 32 : 64);
      assert.equal(s.byte_order, base.big ? "big" : "little");
      assert.equal(s.file_type, "executable");
      assert.deepEqual(s.build_version, { platform: "macOS", platform_value: 1, minimum_os: "10.15.0", sdk: "11.1.0", minimum_os_value: "0xa0f00", sdk_value: "0xb0100", tools: [{ tool: "ld", version: "42.184.0" }] });
      assert.equal(s.uuid, "00112233-4455-6677-8899-AABBCCDDEEFF");
      assert.equal(s.symtab.nsyms, 5);
      assert.equal(s.dysymtab.nundefsym, 2);
      const libs = rowsOf(out, "libraries");
      assert.deepEqual(libs.map((r) => [r.kind, r.name]), [["load", "/usr/lib/libSystem.B.dylib"], ["weak", "@rpath/libweak.dylib"], ["id", "@rpath/libme.dylib"], ["rpath", "@loader_path/../Frameworks"], ["dylinker", "/usr/lib/dyld"]]);
      assert.equal(libs[0].current_version, "1223.0.0");
      assert.equal(libs[0].compatibility_version, "1.0.0");
      const rows = rowsOf(out, "symbols");
      assert.deepEqual(rows.map((r) => r.name), ["_main", "_printf", "_dyn", "_local", "-[Thing method]"]);
      assert.deepEqual(rows.map((r) => r.type), ["SECT", "UNDF", "UNDF", "SECT", "STAB 0x24"]);
      assert.equal(rows[0].value, "0x1000");
      assert.equal(rows[0].external, true);
      assert.equal(rows[3].external, false);
      assert.equal(rows[1].library_ordinal, 1);
      assert.equal(rows[2].library_ordinal, "flat lookup");
      assert.deepEqual(rowsOf(out, "load_commands").map((r) => r.cmd).slice(0, 3), ["LC_SYMTAB", "LC_LOAD_DYLIB", "LC_LOAD_WEAK_DYLIB"]);
    });
  });
}

test("LC_VERSION_MIN_MACOSX gives the platform, the minimum OS and the SDK", async () => {
  await withCwd(async (cwd) => {
    const out = body(await run(cwd, "min.macho", macho({ commands: (c) => [c.cmd(LC_VERSION_MIN_MACOSX, Buffer.concat([c.u32(0x000a0900), c.u32(0x000a0c00)]))] })));
    assert.deepEqual(out.slices[0].version_min, [{ platform: "macOS", minimum_os: "10.9.0", sdk: "10.12.0", command: "LC_VERSION_MIN_MACOSX" }]);
    assert.equal(out.slices[0].build_version, null);
  });
});

test("a universal binary is read slice by slice with each slice's own offsets, in a big-endian and a little-endian fat header and with 64-bit entries", async () => {
  await withCwd(async (cwd) => {
    const arm = withSymbols([{ name: "_arm_main", value: 0x100 }], { cputype: CPU_ARM64 }, (c) => [c.dylib(LC_LOAD_DYLIB, "/usr/lib/libarm.dylib")]);
    const x86 = withSymbols([{ name: "_x86_main", value: 0x200 }, { name: "_x86_two" }], { cputype: CPU_X86_64 }, (c) => [c.dylib(LC_LOAD_DYLIB, "/usr/lib/libx86.dylib")]);
    for (const o of [{}, { littleEndianHeader: true }, { arch64: true }, { arch64: true, littleEndianHeader: true }]) {
      const out = body(await run(cwd, "fat.bin", buildFat([{ cputype: CPU_X86_64, data: x86 }, { cputype: CPU_ARM64, data: arm }], o)));
      assert.equal(out.format, "Mach-O universal binary", JSON.stringify(o));
      assert.equal(out.status, "complete", JSON.stringify([o, out.problems]));
      assert.equal(out.coverage.slices_read_in_full, 2);
      assert.equal(out.coverage.slices_declared, 2);
      assert.deepEqual(out.slices.map((s: Json) => s.cpu_type_name), ["x86-64", "ARM64"]);
      assert.ok(out.slices[1].offset >= 0x4000);
      const names = rowsOf(out, "symbols").map((r) => [r.slice, r.name]);
      assert.deepEqual(names, [[0, "_x86_main"], [0, "_x86_two"], [1, "_arm_main"]]);
      assert.deepEqual(rowsOf(out, "libraries").map((r) => [r.slice, r.name]), [[0, "/usr/lib/libx86.dylib"], [1, "/usr/lib/libarm.dylib"]]);
    }
  });
});

test("a slice outside the file, one that is no Mach-O, overlapping slices and a universal binary inside one are problems of that slice, and the other slices are read", async () => {
  await withCwd(async (cwd) => {
    const good = withSymbols([{ name: "_ok" }]);
    const fat = Buffer.from(buildFat([{ cputype: CPU_X86_64, data: good }, { cputype: CPU_ARM64, data: Buffer.from("not a mach-o at all, but long enough to be a slice: 0123456789".repeat(2)) }]));
    const out = body(await run(cwd, "mixed.bin", fat));
    assert.equal(out.status, "partial");
    assert.equal(out.slices[0].status, "complete");
    assert.equal(out.slices[1].status, "unsupported");
    assert.equal(out.coverage.slices_read_in_full, 1);
    assert.ok(out.problems.some((p: string) => /slice 1: no Mach-O magic/.test(p)), JSON.stringify(out.problems));
    assert.equal(rowsOf(out, "symbols")[0].name, "_ok");
    // the second slice declared past the end of the file
    const cut = fat.subarray(0, fat.length - 40);
    const out2 = body(await run(cwd, "cut.bin", cut));
    assert.equal(out2.status, "partial");
    assert.ok(out2.problems.some((p: string) => /slice 1: the slice \[/.test(p)), JSON.stringify(out2.problems));
    // an inner universal binary
    const inner = buildFat([{ cputype: CPU_X86_64, data: good }]);
    const out3 = body(await run(cwd, "nested.bin", buildFat([{ cputype: CPU_X86_64, data: inner }, { cputype: CPU_ARM64, data: good }])));
    assert.equal(out3.slices[0].status, "unsupported");
    assert.ok(out3.problems.some((p: string) => /universal binary inside a universal binary/.test(p)));
    assert.equal(out3.slices[1].status, "complete");
  });
});

test("a Java class file, which begins with the universal-binary magic, is unsupported, and an implausible slice count is failed", async () => {
  await withCwd(async (cwd) => {
    const klass = Buffer.concat([Buffer.from([0xca, 0xfe, 0xba, 0xbe, 0, 0, 0, 52]), Buffer.alloc(64)]);
    const a = refused(await run(cwd, "Hello.class", klass));
    assert.equal(a.status, "unsupported");
    assert.match(a.error, /Java class file/);
    const none = refused(await run(cwd, "zero.bin", Buffer.concat([Buffer.from([0xca, 0xfe, 0xba, 0xbe, 0, 0, 0, 0]), Buffer.alloc(64)])));
    assert.equal(none.status, "failed");
    const many = refused(await run(cwd, "many.bin", Buffer.concat([Buffer.from([0xca, 0xfe, 0xba, 0xbe, 0, 0, 0x03, 0xe8]), Buffer.alloc(200)])));
    assert.equal(many.status, "failed");
    assert.ok(many.problems.some((p: string) => /slices: 1000 declared, 10 architecture entries fit inside the file/.test(p)), JSON.stringify(many.problems));
  });
});

test("a load command cut short, with a cmdsize below 8, not a multiple of 4, or past sizeofcmds, stops the walk with a named problem and keeps the commands before it", async () => {
  await withCwd(async (cwd) => {
    const lib = (c: Cmds) => c.dylib(LC_LOAD_DYLIB, "/usr/lib/libA.dylib");
    const cases: [string, Opts, RegExp][] = [
      ["tiny", { commands: (c) => [lib(c), Buffer.concat([c.u32(0x99), c.u32(4)]), lib(c)] }, /cmdsize 4, below the 8 bytes/],
      ["odd", { commands: (c) => [lib(c), Buffer.concat([c.u32(0x99), c.u32(10), Buffer.alloc(8)]), lib(c)] }, /cmdsize 10, not a multiple of 4/],
      ["long", { commands: (c) => [lib(c), Buffer.concat([c.u32(0x99), c.u32(4000), Buffer.alloc(8)])] }, /runs past the end of the command table/],
    ];
    for (const [name, o, re] of cases) {
      const out = body(await run(cwd, `${name}.macho`, macho(o)));
      assert.equal(out.status, "partial", name);
      assert.ok(out.problems.some((p: string) => re.test(p)), `${name}: ${JSON.stringify(out.problems)}`);
      assert.equal(rowsOf(out, "libraries").length, 1, name);
      assert.equal(out.slices[0].status, "partial");
    }
  });
});

test("ncmds larger than the commands that fit, and sizeofcmds past the end of the file, are problems and bounded work", async () => {
  await withCwd(async (cwd) => {
    const t0 = Date.now();
    const huge = body(await run(cwd, "huge.macho", macho({ ncmds: 0xffffffff, commands: (c) => [c.dylib(LC_LOAD_DYLIB, "/usr/lib/libA.dylib")], sizeofcmds: 0x7fffffff })));
    assert.ok(Date.now() - t0 < 10_000, `took ${Date.now() - t0} ms`);
    assert.equal(huge.status, "partial");
    assert.ok(huge.problems.some((p: string) => /sizeofcmds 2147483647 runs past the end of the slice/.test(p)), JSON.stringify(huge.problems));
    assert.ok(huge.problems.some((p: string) => /ncmds declares 4294967295 load commands/.test(p)), JSON.stringify(huge.problems));
    assert.equal(rowsOf(huge, "libraries").length, 1, "the command that is there is read");
    const few = body(await run(cwd, "few.macho", macho({ ncmds: 1, commands: (c) => [c.dylib(LC_LOAD_DYLIB, "/usr/lib/libA.dylib"), c.dylib(LC_LOAD_DYLIB, "/usr/lib/libB.dylib")] })));
    assert.equal(few.status, "partial", "sizeofcmds holds more than ncmds says");
    assert.ok(few.problems.some((p: string) => /before sizeofcmds says the table does/.test(p)), JSON.stringify(few.problems));
    const more = body(await run(cwd, "more.macho", macho({ ncmds: 3, commands: (c) => [c.dylib(LC_LOAD_DYLIB, "/usr/lib/libA.dylib"), c.dylib(LC_LOAD_DYLIB, "/usr/lib/libB.dylib")] })));
    assert.equal(more.status, "partial");
    assert.ok(more.problems.some((p: string) => /load command 2 starts at \d+, with fewer than 8 bytes before the end of the command table/.test(p)), JSON.stringify(more.problems));
    const short = refused(await run(cwd, "short.macho", macho().subarray(0, 20)));
    assert.equal(short.status, "failed");
  });
});

test("a symbol table, a string table and a dysymtab that run past the end of the slice are problems, and the rows that are there are read", async () => {
  await withCwd(async (cwd) => {
    const syms: Nlist[] = Array.from({ length: 50 }, (_, i) => ({ name: `sym${i}` }));
    const whole = withSymbols(syms, {}, (c) => [c.dysymtab([0, 30, 30, 30, 60, 5, 0, 0, 0, 0, 0, 0, 0xfff0, 100, 0, 0, 0, 0])]);
    const cut = whole.subarray(0, whole.length - 300);
    const out = body(await run(cwd, "cut.macho", cut));
    assert.equal(out.status, "partial");
    assert.ok(out.problems.some((p: string) => /LC_SYMTAB declares 50 symbols/.test(p)), JSON.stringify(out.problems));
    assert.ok(out.problems.some((p: string) => /string table/.test(p)), JSON.stringify(out.problems));
    assert.ok(out.problems.some((p: string) => /LC_DYSYMTAB's undefined symbols/.test(p)), JSON.stringify(out.problems));
    assert.ok(out.problems.some((p: string) => /indirect symbol table/.test(p)), JSON.stringify(out.problems));
    assert.ok(rowsOf(out, "symbols").length > 0);
    const badName = body(await run(cwd, "badname.macho", withSymbols([{ name: "a", strx: 0x7fff }, { name: "b" }])));
    assert.ok(badName.problems.some((p: string) => /1 symbol name offset\(s\) are outside the string table/.test(p)), JSON.stringify(badName.problems));
    assert.equal(rowsOf(badName, "symbols")[0].name, null);
    assert.equal(rowsOf(badName, "symbols")[1].name, "b");
  });
});

test("a string table without a NUL, megabytes long, ends fast and names are given as cut", async () => {
  await withCwd(async (cwd) => {
    const strtab = Buffer.concat([Buffer.from([0]), Buffer.alloc(3_000_000, 0x61)]);
    const data = macho({ commands: (c, alloc) => { const at = alloc(c.nlist({ type: 0x0f }, 1), 8); const s = alloc(strtab, 1); return [c.symtab(at, 1, s, strtab.length)]; } });
    const t0 = Date.now();
    const out = body(await run(cwd, "nonul.macho", data));
    assert.ok(Date.now() - t0 < 10_000);
    const row = rowsOf(out, "symbols")[0];
    assert.equal(row.name_unterminated, true);
    assert.ok(String(row.name).length < 600, "a name that long is given by its length");
  });
});

// --- dyld bind opcodes ------------------------------------------------------------------------------------------------------------------

/** The bind opcodes of <mach-o/loader.h>: the high nibble is the opcode, the low nibble the immediate. */
const BIND = { DONE: 0x00, ORDINAL_IMM: 0x10, ORDINAL_ULEB: 0x20, SPECIAL_IMM: 0x30, SYMBOL: 0x40, TYPE_IMM: 0x50, ADDEND_SLEB: 0x60, SEGMENT: 0x70, ADD_ADDR_ULEB: 0x80, DO_BIND: 0x90,
  DO_BIND_ADD_ADDR_ULEB: 0xa0, DO_BIND_ADD_ADDR_IMM_SCALED: 0xb0, DO_BIND_ULEB_TIMES_SKIPPING_ULEB: 0xc0, THREADED: 0xd0 };

function dyldFile(streams: { bind?: Buffer; weak?: Buffer; lazy?: Buffer; exp?: Buffer; rebase?: Buffer }, o: Opts = {}): Buffer {
  return macho({
    ...o,
    commands: (c, alloc) => {
      const at = (b?: Buffer) => (b ? alloc(b, 8) : 0);
      const [r, bi, w, l, e] = [streams.rebase, streams.bind, streams.weak, streams.lazy, streams.exp];
      return [c.dyld([at(r), r?.length ?? 0, at(bi), bi?.length ?? 0, at(w), w?.length ?? 0, at(l), l?.length ?? 0, at(e), e?.length ?? 0])];
    },
  });
}

test("bind, weak-bind and lazy-bind opcodes decode to the symbols, ordinals, segments and offsets the specification gives", async () => {
  await withCwd(async (cwd) => {
    const bind = Buffer.concat([
      Buffer.from([BIND.ORDINAL_IMM | 2, BIND.SYMBOL | 0]), cstr("_open"), Buffer.from([BIND.TYPE_IMM | 1, BIND.SEGMENT | 2]), uleb(0x10), Buffer.from([BIND.DO_BIND]),
      Buffer.from([BIND.SYMBOL | 1]), cstr("_weak_thing"), Buffer.from([BIND.SPECIAL_IMM | 0xf, BIND.DO_BIND_ADD_ADDR_IMM_SCALED | 3]),
      Buffer.from([BIND.ORDINAL_ULEB]), uleb(300), Buffer.from([BIND.ADDEND_SLEB]), Buffer.from([0x7f]), Buffer.from([BIND.DO_BIND_ADD_ADDR_ULEB]), uleb(0x20),
      Buffer.from([BIND.DO_BIND_ULEB_TIMES_SKIPPING_ULEB]), uleb(5), uleb(8), Buffer.from([BIND.DONE]),
    ]);
    const weak = Buffer.concat([Buffer.from([BIND.SYMBOL | 8]), cstr("__ZdlPv"), Buffer.from([BIND.SEGMENT | 3]), uleb(0x40), Buffer.from([BIND.DO_BIND, BIND.DONE])]);
    const lazy = Buffer.concat([
      Buffer.from([BIND.SEGMENT | 3]), uleb(0x100), Buffer.from([BIND.ORDINAL_IMM | 1, BIND.SYMBOL]), cstr("_puts"), Buffer.from([BIND.DO_BIND, BIND.DONE]),
      Buffer.from([BIND.SEGMENT | 3]), uleb(0x108), Buffer.from([BIND.ORDINAL_IMM | 1, BIND.SYMBOL]), cstr("_free"), Buffer.from([BIND.DO_BIND, BIND.DONE, BIND.DONE]),
    ]);
    const out = body(await run(cwd, "bind.macho", dyldFile({ bind, weak, lazy })));
    assert.equal(out.status, "complete", JSON.stringify([out.problems, out.limits_hit]));
    const rows = rowsOf(out, "bind_opcodes");
    const b = rows.filter((r) => r.stream === "bind");
    assert.equal(b.length, 4);
    assert.deepEqual([b[0].symbol, b[0].dylib_ordinal, b[0].type, b[0].segment_index, b[0].segment_offset, b[0].weak_import, b[0].op], ["_open", 2, "POINTER", 2, "0x10", false, "DO_BIND"]);
    assert.deepEqual([b[1].symbol, b[1].dylib_ordinal, b[1].dylib_ordinal_meaning, b[1].segment_offset, b[1].weak_import, b[1].op], ["_weak_thing", -1, "main executable", "0x18", true, "DO_BIND_ADD_ADDR_IMM_SCALED"]);
    assert.deepEqual([b[2].dylib_ordinal, b[2].addend, b[2].segment_offset, b[2].op], [300, -1, "0x38", "DO_BIND_ADD_ADDR_ULEB"]);
    assert.deepEqual([b[3].count, b[3].segment_offset, b[3].op], [5, "0x60", "DO_BIND_ULEB_TIMES_SKIPPING_ULEB"], "a repeat count is a field and is not expanded");
    const w = rows.filter((r) => r.stream === "weak_bind");
    assert.deepEqual([w.length, w[0].symbol, w[0].segment_index, w[0].segment_offset], [1, "__ZdlPv", 3, "0x40"]);
    const l = rows.filter((r) => r.stream === "lazy_bind");
    assert.deepEqual(l.map((r) => [r.symbol, r.segment_offset]), [["_puts", "0x100"], ["_free", "0x108"]], "DONE separates the entries of a lazy-bind stream");
    assert.equal(out.slices[0].dyld_info.bind.decoded.binds, 4);
  });
});

test("an opcode that is not a bind opcode, a symbol name cut by the end of the stream and a LEB128 longer than ten bytes end the decoding of that stream with a problem and keep the rows before it", async () => {
  await withCwd(async (cwd) => {
    const good = Buffer.concat([Buffer.from([BIND.ORDINAL_IMM | 1, BIND.SYMBOL]), cstr("_first"), Buffer.from([BIND.DO_BIND])]);
    const cases: [string, Buffer, RegExp][] = [
      ["opcode", Buffer.concat([good, Buffer.from([0xe0, BIND.DO_BIND])]), /holds the opcode 0xe0 at offset \d+, which is not a bind opcode/],
      ["cut", Buffer.concat([good, Buffer.from([BIND.SYMBOL]), Buffer.from("_unfinished")]), /symbol name in the bind stream at offset \d+ has no terminator/],
      ["leb", Buffer.concat([good, Buffer.from([BIND.ORDINAL_ULEB]), Buffer.alloc(11, 0xff), Buffer.from([0x01])]), /LEB128 value is longer than 10 bytes/],
      ["threaded", Buffer.concat([good, Buffer.from([BIND.THREADED | 5])]), /THREADED opcode with the sub-opcode 5/],
      ["ulebcut", Buffer.concat([good, Buffer.from([BIND.SEGMENT, 0x80])]), /stream is cut: a LEB128 value runs past the end of its stream/],
    ];
    for (const [name, bind, re] of cases) {
      const out = body(await run(cwd, `${name}.macho`, dyldFile({ bind })));
      assert.equal(out.status, "partial", name);
      assert.ok(out.problems.some((p: string) => re.test(p)), `${name}: ${JSON.stringify(out.problems)}`);
      assert.equal(rowsOf(out, "bind_opcodes")[0].symbol, "_first", name);
    }
  });
});

test("a dyld range outside the slice is a problem, and the part that is there is decoded", async () => {
  await withCwd(async (cwd) => {
    const bind = Buffer.concat([Buffer.from([BIND.ORDINAL_IMM | 1, BIND.SYMBOL]), cstr("_a"), Buffer.from([BIND.DO_BIND]), Buffer.from([BIND.SYMBOL]), cstr("_b"), Buffer.from([BIND.DO_BIND])]);
    const file = dyldFile({ bind });
    const out = body(await run(cwd, "range.macho", file.subarray(0, file.length - 5)));
    assert.equal(out.status, "partial");
    assert.ok(out.problems.some((p: string) => /LC_DYLD_INFO's bind range/.test(p)), JSON.stringify(out.problems));
    assert.ok(out.problems.some((p: string) => /bind: the range \[\d+, \d+\) runs past the end of the slice \(\d+ bytes\): the part that is there is read/.test(p)), JSON.stringify(out.problems));
    assert.equal(rowsOf(out, "bind_opcodes").length, 1, "the stream that is there is decoded as far as it goes");
  });
});

// --- the export trie ------------------------------------------------------------------------------------------------------------------

/** A trie for the names, built from the node layout of <mach-o/loader.h>: terminal size, [flags, address], child count, then (label, node offset) pairs. */
function trie(entries: { name: string; address?: number; flags?: number; resolver?: number; reexport?: { ordinal: number; import: string } }[]): Buffer {
  type Node = { terminal?: Buffer; kids: [string, Node][] };
  const root: Node = { kids: [] };
  for (const e of entries) {
    let n = root;
    let rest = e.name;
    while (rest) {
      const hit = n.kids.find(([label]) => label[0] === rest[0]);
      if (!hit) { const leaf: Node = { kids: [] }; n.kids.push([rest, leaf]); n = leaf; rest = ""; break; }
      let k = 0;
      while (k < hit[0].length && k < rest.length && hit[0][k] === rest[k]) k++;
      if (k < hit[0].length) { const mid: Node = { kids: [[hit[0].slice(k), hit[1]]] }; hit[0] = hit[0].slice(0, k); hit[1] = mid; }
      n = hit[1];
      rest = rest.slice(k);
    }
    n.terminal = e.reexport
      ? Buffer.concat([uleb(e.flags ?? 8), uleb(e.reexport.ordinal), cstr(e.reexport.import)])
      : Buffer.concat([uleb(e.flags ?? 0), uleb(e.address ?? 0), ...(e.resolver !== undefined ? [uleb(e.resolver)] : [])]);
  }
  // lay the nodes out until the offsets settle: each child offset is a ULEB, so its width depends on the layout
  const nodes: Node[] = [];
  const walk = (n: Node) => { nodes.push(n); n.kids.forEach(([, k]) => walk(k)); };
  walk(root);
  let offsets = new Map<Node, number>(nodes.map((n) => [n, 0]));
  let out: Buffer[] = [];
  for (let round = 0; round < 8; round++) {
    const next = new Map<Node, number>();
    out = [];
    let at = 0;
    for (const n of nodes) {
      next.set(n, at);
      const t = n.terminal ?? Buffer.alloc(0);
      const b = Buffer.concat([uleb(t.length), t, Buffer.from([n.kids.length]), ...n.kids.flatMap(([label, k]) => [cstr(label), uleb(offsets.get(k)!)])]);
      out.push(b);
      at += b.length;
    }
    offsets = next;
  }
  return Buffer.concat(out);
}

test("an export trie is walked to the names it exports, with kind, address, flags and a re-export's import", async () => {
  await withCwd(async (cwd) => {
    const exp = trie([{ name: "_main", address: 0x1000 }, { name: "_mh_execute_header", address: 0 }, { name: "_tls", address: 0x40, flags: 1 }, { name: "_abs", address: 0x77, flags: 2 },
      { name: "_weak", address: 0x500, flags: 4 }, { name: "_resolved", address: 0x600, flags: 0x10, resolver: 0x700 }, { name: "_viaother", reexport: { ordinal: 3, import: "_realname" } }, { name: "_samename", reexport: { ordinal: 2, import: "" } }]);
    const out = body(await run(cwd, "exp.macho", dyldFile({ exp })));
    assert.equal(out.status, "complete", JSON.stringify([out.problems, out.limits_hit]));
    const rows = rowsOf(out, "exports");
    const byName = Object.fromEntries(rows.map((r) => [r.name, r]));
    assert.deepEqual(Object.keys(byName).sort(), ["_abs", "_main", "_mh_execute_header", "_resolved", "_samename", "_tls", "_viaother", "_weak"]);
    assert.deepEqual([byName._main.kind, byName._main.address], ["regular", "0x1000"]);
    assert.equal(byName._tls.kind, "thread-local");
    assert.equal(byName._abs.kind, "absolute");
    assert.equal(byName._weak.weak_definition, true);
    assert.deepEqual([byName._resolved.stub_and_resolver, byName._resolved.resolver], [true, "0x700"]);
    assert.equal(byName._viaother.kind, "re-export");
    assert.deepEqual([byName._viaother.dylib_ordinal, byName._viaother.import_name], [3, "_realname"]);
    assert.equal(byName._samename.import_name, "");
    assert.equal(out.slices[0].dyld_info.export.decoded.exports, 8);
  });
});

test("LC_DYLD_EXPORTS_TRIE is walked the same way", async () => {
  await withCwd(async (cwd) => {
    const exp = trie([{ name: "_alpha", address: 0x10 }, { name: "_alpine", address: 0x20 }]);
    const out = body(await run(cwd, "trie.macho", macho({ commands: (c, alloc) => [c.linkedit(LC_EXPORTS_TRIE, alloc(exp, 8), exp.length)] })));
    assert.equal(out.status, "complete", JSON.stringify(out.problems));
    assert.deepEqual(rowsOf(out, "exports").map((r) => r.name).sort(), ["_alpha", "_alpine"]);
    assert.equal(out.slices[0].exports_trie.exports, 2);
    assert.equal(out.slices[0].linkedit_data[0].kind, "exports_trie");
  });
});

test("a trie that points back at itself, at its root, past its end, or with an edge that has no terminator ends, with a named problem and the names it reached", async () => {
  await withCwd(async (cwd) => {
    // root: no terminal, one child "_a" at node 6 (a leaf exporting "_a"), and a second child "x" whose node offset is the root again
    const leaf = Buffer.concat([uleb(2), uleb(0), uleb(0x10), Buffer.from([0])]);
    const root = (kids: [string, number][]) => Buffer.concat([uleb(0), Buffer.from([kids.length]), ...kids.flatMap(([l, o]) => [cstr(l), uleb(o)])]);
    const probe = root([["_a", 0], ["x", 0]]);
    const leafAt = probe.length;
    const loops = Buffer.concat([root([["_a", leafAt], ["x", 0]]), leaf]);
    const t0 = Date.now();
    const a = body(await run(cwd, "loop.macho", dyldFile({ exp: loops })));
    assert.ok(Date.now() - t0 < 10_000);
    assert.equal(a.status, "partial");
    assert.ok(a.problems.some((p: string) => /reaches the node at offset 0 twice/.test(p)), JSON.stringify(a.problems));
    assert.deepEqual(rowsOf(a, "exports").map((r) => r.name), ["_a"]);
    const past = body(await run(cwd, "past.macho", dyldFile({ exp: root([["_z", 900]]) })));
    assert.ok(past.problems.some((p: string) => /points to a node at offset 900, outside the/.test(p)), JSON.stringify(past.problems));
    const noterm = body(await run(cwd, "noterm.macho", dyldFile({ exp: Buffer.concat([uleb(0), Buffer.from([1]), Buffer.from("_noend")]) })));
    assert.ok(noterm.problems.some((p: string) => /edge label of the dyld_info_export_trie at offset \d+ has no terminator/.test(p)), JSON.stringify(noterm.problems));
    const cut = body(await run(cwd, "cutnode.macho", dyldFile({ exp: Buffer.from([0x80]) })));
    assert.ok(cut.problems.some((p: string) => /node at offset 0 is cut or malformed/.test(p)), JSON.stringify(cut.problems));
  });
});

test("a long chain of edges is bounded in name length and in memory, and ends within the clock", async () => {
  await withCwd(async (cwd) => {
    // a chain of nodes, each with a 2,000-byte edge: the name passes 4,096 bytes after two and the rest is not walked
    const label = "a".repeat(2000);
    const nodes: Buffer[] = [];
    const nodeLen = 1 + 1 + (label.length + 1) + 3;
    const uleb3 = (v: number) => Buffer.from([(v & 0x7f) | 0x80, ((v >> 7) & 0x7f) | 0x80, v >> 14]);
    for (let i = 0; i < 40; i++) nodes.push(Buffer.concat([uleb(0), Buffer.from([1]), cstr(label), uleb3((i + 1) * nodeLen)]));
    const t0 = Date.now();
    const out = body(await run(cwd, "chain.macho", dyldFile({ exp: Buffer.concat(nodes) })));
    assert.ok(Date.now() - t0 < 10_000);
    assert.equal(out.status, "partial");
    assert.equal(out.slices[0].dyld_info.export.decoded.nodes, 3, "the walk stops where a name would pass 4,096 bytes");
    assert.ok(out.problems.some((p: string) => /1 edge\(s\) whose name would be longer than 4096 bytes/.test(p)), JSON.stringify(out.problems));
  });
});

test("a trie of 255 edges per node over a megabyte stays inside the node and memory bounds and the clock", async () => {
  await withCwd(async (cwd) => {
    // the root has 255 children that all point at one leaf: it is walked once and the rest are reported
    const leaf = Buffer.concat([uleb(2), uleb(0), uleb(0x10), Buffer.from([0])]);
    const kids = Array.from({ length: 255 }, (_, i) => cstr(String.fromCharCode(1 + i % 120) + String(i)));
    const rootProbe = Buffer.concat([uleb(0), Buffer.from([255]), ...kids.flatMap((k) => [k, uleb(0)])]);
    const root = Buffer.concat([uleb(0), Buffer.from([255]), ...kids.flatMap((k) => [k, uleb(rootProbe.length + 255)])]);   // each offset is two bytes, one more than the probe's
    const t0 = Date.now();
    const out = body(await run(cwd, "fan.macho", dyldFile({ exp: Buffer.concat([root, leaf]) })));
    assert.ok(Date.now() - t0 < 10_000);
    assert.equal(out.status, "partial");
    assert.equal(rowsOf(out, "exports").length, 1);
  });
});

// --- chained fixups -----------------------------------------------------------------------------------------------------------------

/** dyld_chained_fixups_header (<mach-o/fixup-chains.h>): seven uint32 fields, then dyld_chained_starts_in_image, the imports and the symbol strings. */
function chained(format: 1 | 2 | 3, imports: { name: string; ordinal: number; weak?: boolean; addend?: number }[], o: { symbolsFormat?: number; version?: number } = {}): Buffer {
  const s = strings(imports.map((i) => i.name));
  const width = { 1: 4, 2: 8, 3: 16 }[format];
  const startsOffset = 28, importsOffset = 36, symbolsOffset = importsOffset + imports.length * width;
  const header = Buffer.concat([o.version ?? 0, startsOffset, importsOffset, symbolsOffset, imports.length, format, o.symbolsFormat ?? 0].map((v) => Buffer.from(new Uint32Array([v]).buffer)));
  const starts = Buffer.concat([Buffer.from(new Uint32Array([1]).buffer), Buffer.alloc(4)]);
  const rows = imports.map((im, i) => {
    const le32 = (v: number) => Buffer.from(new Uint32Array([v >>> 0]).buffer);
    if (format === 3) {
      const v = BigInt(im.ordinal & 0xffff) | (BigInt(im.weak ? 1 : 0) << 16n) | (BigInt(s.at[i]!) << 32n);
      const b = Buffer.alloc(16);
      b.writeBigUInt64LE(v, 0);
      b.writeBigInt64LE(BigInt(im.addend ?? 0), 8);
      return b;
    }
    const v = (im.ordinal & 0xff) | ((im.weak ? 1 : 0) << 8) | (s.at[i]! << 9);
    return format === 1 ? le32(v) : Buffer.concat([le32(v), Buffer.from(new Int32Array([im.addend ?? 0]).buffer)]);
  });
  return Buffer.concat([header, starts, ...rows, s.table]);
}

test("the chained-fixups header and its imports decode in the three formats, with the special ordinals", async () => {
  await withCwd(async (cwd) => {
    for (const format of [1, 2, 3] as const) {
      const cf = chained(format, [{ name: "_malloc", ordinal: 1 }, { name: "_free", ordinal: -2, weak: true }, { name: "_environ", ordinal: -1, addend: format === 1 ? 0 : 7 }]);
      const out = body(await run(cwd, `cf${format}.macho`, macho({ commands: (c, alloc) => [c.linkedit(LC_CHAINED_FIXUPS, alloc(cf, 8), cf.length)] })));
      assert.equal(out.status, "complete", `${format}: ${JSON.stringify(out.problems)}`);
      const info = out.slices[0].chained_fixups;
      assert.equal(info.imports_count, 3);
      assert.equal(info.imports_format, { 1: "DYLD_CHAINED_IMPORT", 2: "DYLD_CHAINED_IMPORT_ADDEND", 3: "DYLD_CHAINED_IMPORT_ADDEND64" }[format]);
      const rows = rowsOf(out, "chained_imports");
      assert.deepEqual(rows.map((r) => r.name), ["_malloc", "_free", "_environ"]);
      assert.deepEqual(rows.map((r) => r.dylib_ordinal), [1, -2, -1]);
      assert.equal(rows[1].weak_import, true);
      assert.equal(rows[2].dylib_ordinal_meaning, "main executable");
      if (format !== 1) assert.equal(rows[2].addend, 7);
    }
  });
});

test("chained-fixups imports past the data, a name offset outside it, a compressed symbol area and a version other than 0 are problems", async () => {
  await withCwd(async (cwd) => {
    const mk = (cf: Buffer) => macho({ commands: (c, alloc) => [c.linkedit(LC_CHAINED_FIXUPS, alloc(cf, 8), cf.length)] });
    const base = chained(1, [{ name: "_a", ordinal: 1 }, { name: "_b", ordinal: 1 }]);
    const declared = Buffer.from(base);
    declared.writeUInt32LE(5000, 16);                       // imports_count
    const a = body(await run(cwd, "many.macho", mk(declared)));
    assert.ok(a.problems.some((p: string) => /declares 5000 imports/.test(p)), JSON.stringify(a.problems));
    assert.ok(rowsOf(a, "chained_imports").length >= 2, "the imports that are there are listed");
    const badName = Buffer.from(base);
    badName.writeUInt32LE((1 | (0x7ffff << 9)) >>> 0, 36);
    const b = body(await run(cwd, "badname.macho", mk(badName)));
    assert.ok(b.problems.some((p: string) => /import name offset\(s\) are outside the data/.test(p)), JSON.stringify(b.problems));
    const compressed = Buffer.from(base);
    compressed.writeUInt32LE(1, 24);
    const c = body(await run(cwd, "zlib.macho", mk(compressed)));
    assert.ok(c.problems.some((p: string) => /symbol strings are zlib-compressed/.test(p)), JSON.stringify(c.problems));
    const versioned = Buffer.from(base);
    versioned.writeUInt32LE(7, 0);
    const d = body(await run(cwd, "v7.macho", mk(versioned)));
    assert.ok(d.problems.some((p: string) => /version is 7, not 0/.test(p)), JSON.stringify(d.problems));
    const tiny = body(await run(cwd, "tiny.macho", mk(Buffer.alloc(12))));
    assert.ok(tiny.problems.some((p: string) => /shorter than its 28-byte header/.test(p)), JSON.stringify(tiny.problems));
  });
});

// --- the code signature ----------------------------------------------------------------------------------------------------------------

type CdOptions = { identifier?: string; team?: string; flags?: number; hashType?: number; nSpecial?: number; nCode?: number; hashSize?: number; version?: number; hashOffsetPad?: number };
/** A CodeDirectory (cs_blobs.h, version 0x20200: fixed part of 52 bytes), big-endian. */
function codeDirectory(o: CdOptions = {}): Buffer {
  const ident = cstr(o.identifier ?? "com.example.tool");
  const team = o.team ? cstr(o.team) : Buffer.alloc(0);
  const hashSize = o.hashSize ?? 32, nCode = o.nCode ?? 2, nSpecial = o.nSpecial ?? 2;
  const identOffset = 52, teamOffset = o.team ? identOffset + ident.length : 0;
  const hashOffset = identOffset + ident.length + team.length + nSpecial * hashSize + (o.hashOffsetPad ?? 0);
  const hashes = Buffer.alloc((nSpecial + nCode) * hashSize, 0xab);
  const total = hashOffset - nSpecial * hashSize + hashes.length;
  const fixed = Buffer.concat([be32(0xfade0c02), be32(total), be32(o.version ?? 0x20200), be32(o.flags ?? 0x2), be32(hashOffset), be32(identOffset), be32(nSpecial), be32(nCode), be32(0x8000),
    Buffer.from([hashSize, o.hashType ?? 2, 0, 12]), be32(0), be32(0), be32(teamOffset)]);
  return Buffer.concat([fixed, ident, team, Buffer.alloc(hashOffset - nSpecial * hashSize - identOffset - ident.length - team.length), hashes]);
}
function superBlob(blobs: { slot: number; data: Buffer }[]): Buffer {
  const head = 12 + blobs.length * 8;
  let at = head;
  const index = blobs.map((b) => { const e = Buffer.concat([be32(b.slot), be32(at)]); at += b.data.length; return e; });
  return Buffer.concat([be32(0xfade0cc0), be32(at), be32(blobs.length), ...index, ...blobs.map((b) => b.data)]);
}
const blob = (magic: number, payload: Buffer) => Buffer.concat([be32(magic), be32(8 + payload.length), payload]);
const signed = (sig: Buffer, o: Opts = {}) => macho({ ...o, commands: (c, alloc) => [c.linkedit(LC_CODE_SIGNATURE, alloc(sig, 16), sig.length)] });

test("the code signature is read as a structure: blobs, the CodeDirectory's fields, the identifier and team, and entitlements by length only", async () => {
  await withCwd(async (cwd) => {
    const entitlements = blob(0xfade7171, Buffer.from('<?xml version="1.0"?><plist><dict><key>com.apple.security.cs.allow-jit</key><true/></dict></plist>'));
    const sig = superBlob([{ slot: 0, data: codeDirectory({ team: "ABCDE12345", flags: 0x10002 }) }, { slot: 2, data: blob(0xfade0c01, Buffer.alloc(4)) }, { slot: 5, data: entitlements },
      { slot: 0x10000, data: blob(0xfade0b01, Buffer.alloc(16)) }]);
    for (const big of [false, true]) {
      const out = body(await run(cwd, "sig.macho", signed(sig, { big })));
      assert.equal(out.status, "complete", JSON.stringify(out.problems));
      const info = out.slices[0].code_signature;
      assert.equal(info.magic, "EmbeddedSignature");
      assert.equal(info.blob_count, 4);
      const cd = info.code_directories[0];
      assert.deepEqual([cd.identifier, cd.team_identifier, cd.hash_type, cd.hash_size, cd.code_slots, cd.special_slots, cd.version], ["com.example.tool", "ABCDE12345", "SHA-256", 32, 2, 2, "0x20200"]);
      assert.deepEqual(cd.flags, ["adhoc", "runtime"]);
      assert.equal(cd.page_size, 4096);
      assert.deepEqual(info.entitlements_blob_bytes, { xml: entitlements.length });
      assert.ok(!JSON.stringify(out).includes("allow-jit"), "the contents of the entitlements are not read");
      assert.match(cd.verification, /^none/);
      assert.deepEqual(rowsOf(out, "signature_blobs").map((r) => [r.slot, r.magic]), [["CodeDirectory", "CodeDirectory"], ["Requirements", "RequirementsSet"], ["Entitlements", "Entitlements (XML)"], ["CMS signature", "CMS signature wrapper"]]);
    }
  });
});

test("a SuperBlob with the wrong magic, a length past its data, a blob count past its bytes, a blob offset outside it and a CodeDirectory with its hashes outside it are problems", async () => {
  await withCwd(async (cwd) => {
    const good = superBlob([{ slot: 0, data: codeDirectory() }]);
    const wrong = Buffer.from(good);
    wrong.writeUInt32BE(0xdeadbeef, 0);
    assert.ok(body(await run(cwd, "m.macho", signed(wrong))).problems.some((p: string) => /does not begin with an embedded-signature SuperBlob \(magic 0xdeadbeef\)/.test(p)));
    const longer = Buffer.from(good);
    longer.writeUInt32BE(good.length + 500, 4);
    assert.ok(body(await run(cwd, "l.macho", signed(longer))).problems.some((p: string) => /declares \d+ bytes and LC_CODE_SIGNATURE holds/.test(p)));
    const many = Buffer.from(good);
    many.writeUInt32BE(99999, 8);
    const m = body(await run(cwd, "c.macho", signed(many)));
    assert.ok(m.problems.some((p: string) => /declares 99999 blobs/.test(p)), JSON.stringify(m.problems));
    const off = Buffer.from(good);
    off.writeUInt32BE(100000, 16);
    assert.ok(body(await run(cwd, "o.macho", signed(off))).problems.some((p: string) => /blob 0 of the SuperBlob is at offset 100000, outside/.test(p)));
    const bigCd = codeDirectory();
    bigCd.writeUInt32BE(50000, 28);                           // nCodeSlots, far more than the blob holds
    const hashes = superBlob([{ slot: 0, data: bigCd }]);
    assert.ok(body(await run(cwd, "h.macho", signed(hashes))).problems.some((p: string) => /hash slots of 32 bytes around offset \d+, outside its \d+ bytes/.test(p)));
    const shortCd = superBlob([{ slot: 0, data: blob(0xfade0c02, Buffer.alloc(8)) }]);
    assert.ok(body(await run(cwd, "s.macho", signed(shortCd))).problems.some((p: string) => /shorter than its 44-byte fixed part/.test(p)));
    const cut = body(await run(cwd, "cut.macho", signed(good).subarray(0, signed(good).length - 60)));
    assert.equal(cut.status, "partial");
  });
});

// --- linkedit data --------------------------------------------------------------------------------------------------------------------------

test("the other linkedit data commands are given by offset and size, and one outside the slice is a problem", async () => {
  await withCwd(async (cwd) => {
    const out = body(await run(cwd, "le.macho", macho({ commands: (c, alloc) => [c.linkedit(LC_FUNCTION_STARTS, alloc(Buffer.from([1, 2, 3, 0]), 8), 4), c.linkedit(0x29, 900000, 16)] })));
    assert.equal(out.status, "partial");
    assert.deepEqual(out.slices[0].linkedit_data.map((d: Json) => [d.kind, d.datasize, d.in_slice]), [["function_starts", 4, true], ["data_in_code", 16, false]]);
    assert.ok(out.problems.some((p: string) => /LC_DATA_IN_CODE data \[900000, 900016\) is not inside the slice/.test(p)), JSON.stringify(out.problems));
  });
});

// --- tables, files and withholding -----------------------------------------------------------------------------------------------------

test("a table longer than limit is in the answer as its first rows and whole in a file, and the count equals the file", async () => {
  await withCwd(async (cwd) => {
    const syms = Array.from({ length: 300 }, (_, i) => ({ name: `symbol_${i}` }));
    const out = body(await run(cwd, "many.macho", withSymbols(syms), { limit: 10 }));
    const t = out.tables.symbols;
    assert.equal(t.matched, 300);
    assert.equal(t.rows.length, 10);
    assert.equal(t.truncated, true);
    assert.ok(t.all_results);
    const files = await filesUnder(join(cwd, "work/s1/tool-output"));
    const file = files.find((f) => f.includes("symbols"));
    assert.ok(file, files.join());
    const lines = (await readFile(join(cwd, "work/s1/tool-output", file!), "utf8")).trim().split("\n");
    assert.equal(lines.length, 300);
    assert.equal(JSON.parse(lines[299]!).name, "symbol_299");
    assert.equal(out.slices[0].symtab.listed, 300);
  });
});

const CANARY = "AKIAIOSFODNN7EXAMPLE";
const JWT = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U";

/** A file with a secret-shaped string in every place the tool prints one. */
function canaryFile(): Buffer {
  const bind = Buffer.concat([Buffer.from([BIND.ORDINAL_IMM | 1, BIND.SYMBOL]), cstr(`_${CANARY}_bound`), Buffer.from([BIND.DO_BIND, BIND.SYMBOL]), cstr(`_${CANARY}_bound_two`), Buffer.from([BIND.DO_BIND, BIND.DONE])]);
  const exp = trie([{ name: `_${CANARY}_exported`, address: 0x10 }, { name: "_viaother", reexport: { ordinal: 1, import: `_${CANARY}_orig` } }]);
  const cd = codeDirectory({ identifier: `${CANARY}.signed`, team: JWT.slice(0, 10) });
  const cf = chained(1, [{ name: `_${CANARY}_imported`, ordinal: 1 }, { name: `_${CANARY}_imported_two`, ordinal: 1 }]);
  const sig = superBlob([{ slot: 0, data: cd }, { slot: 2, data: blob(0xfade0c01, Buffer.alloc(4)) }]);
  return withSymbols([{ name: `${CANARY}_sym` }, { name: JWT }], {}, (c, alloc) => [
    c.dylib(LC_LOAD_DYLIB, `/opt/${CANARY}/libx.dylib`), c.path(LC_RPATH, `/opt/${JWT}`),
    c.dyld([0, 0, alloc(bind, 8), bind.length, 0, 0, 0, 0, alloc(exp, 8), exp.length]),
    c.linkedit(LC_CHAINED_FIXUPS, alloc(cf, 8), cf.length), c.linkedit(LC_CODE_SIGNATURE, alloc(sig, 16), sig.length),
  ]);
}

test("a canary in an install name, an rpath, a symbol, a bind symbol, an export, a re-export, an import and an identifier is withheld on every path, and the answer says it was", async () => {
  await withCwd(async (cwd) => {
    const out = await run(cwd, "canary.macho", canaryFile(), { limit: 1 });
    const a = JSON.parse(out.stdout) as Json;
    assert.equal(out.code, 0, out.stderr);
    for (const secret of [CANARY, JWT]) assert.ok(!out.stdout.includes(secret), `the answer prints ${secret.slice(0, 8)}...`);
    const files = await filesUnder(join(cwd, "work/s1/tool-output"));
    assert.ok(files.length >= 7, files.join());
    for (const f of files) {
      const content = await readFile(join(cwd, "work/s1/tool-output", f), "utf8");
      for (const secret of [CANARY, JWT]) assert.ok(!content.includes(secret) || f.includes("withheld-names"), `${f} prints ${secret.slice(0, 8)}`);
    }
    assert.ok(a.withheld.names + a.withheld.text > 0);
    assert.equal(a.withheld_by_final_check, undefined, "the sanitiser withholds before the backstop does: nothing is left for the backstop to catch in a real call");
    // the places the canaries are in, all read
    assert.deepEqual(["symbols", "bind_opcodes", "exports", "chained_imports", "signature_blobs", "libraries"].map((t) => a.tables[t].matched), [2, 2, 2, 2, 2, 2]);
    assert.equal(a.slices[0].code_signature.code_directories[0].identifier.includes(CANARY), false);
  });
});

test("write_values in a job run as secret output writes the whole strings to a 0600 file under $OUT and nowhere else; outside such a job it is refused before anything is created", async () => {
  await withCwd(async (cwd) => {
    await put(cwd, "work/canary.macho", canaryFile());
    await mkdir(join(cwd, "out"), { recursive: true });
    const refusedRun = await tool(MACHO_DIRECTORIES, cwd, { path: "work/canary.macho", write_values: true }, { JOB_ID: "j000001", OUT: join(cwd, "out") });
    assert.match(refused(refusedRun).error, /write_values is refused outside a job run as secret output/);
    assert.deepEqual(await readdir(join(cwd, "out")), []);
    const none = refused(await tool(MACHO_DIRECTORIES, cwd, { path: "work/canary.macho", write_values: true }));
    assert.match(none.error, /write_values is refused outside a job/);
    const r = await tool(MACHO_DIRECTORIES, cwd, { path: "work/canary.macho", write_values: true }, { JOB_ID: "j000002", OUT: join(cwd, "out"), SECRET_OUTPUT: "1" });
    for (const secret of [CANARY, JWT]) assert.ok(!r.stdout.includes(secret), "the answer still withholds");
    const answer = JSON.parse(r.stdout) as Json;
    assert.equal(answer.secret_values.requested, true);
    assert.ok(answer.secret_values.written > 0);
    const values = join(cwd, "out", "macho-directories-values.jsonl");
    assert.equal((await stat(values)).mode & 0o777, 0o600);
    const text = await readFile(values, "utf8");
    assert.ok(text.includes(CANARY) && text.includes(JWT), "the values file holds the whole strings");
  });
});

test("not a Mach-O file is unsupported; a link, a pipe, a directory and a missing file are refused as JSON, and a pipe does not hang", async () => {
  await withCwd(async (cwd) => {
    const x = refused(await run(cwd, "plain.bin", Buffer.from("MZ not mach-o")));
    assert.equal(x.status, "unsupported");
    await put(cwd, "work/real.macho", macho());
    await symlink(join(cwd, "work/real.macho"), join(cwd, "work/link.macho"));
    assert.match(refused(await tool(MACHO_DIRECTORIES, cwd, { path: "work/link.macho" })).error, /symbolic link/);
    spawnSync("mkfifo", [join(cwd, "work/pipe.macho")]);
    const t0 = Date.now();
    assert.match(refused(await tool(MACHO_DIRECTORIES, cwd, { path: "work/pipe.macho" })).error, /named pipe/);
    assert.ok(Date.now() - t0 < 20_000);
    await mkdir(join(cwd, "work/d"), { recursive: true });
    assert.match(refused(await tool(MACHO_DIRECTORIES, cwd, { path: "work/d" })).error, /directory/);
    assert.match(refused(await tool(MACHO_DIRECTORIES, cwd, { path: "work/none.macho" })).error, /no such file/);
    const tiny = refused(await run(cwd, "tiny.macho", Buffer.from([0xcf, 0xfa, 0xed, 0xfe, 7, 0, 0, 1])));
    assert.equal(tiny.status, "failed");
  });
});

test("a tool-output directory reached through a symbolic link is refused: nothing is written through it, and the answer is still given", async () => {
  await withCwd(async (cwd) => {
    await mkdir(join(cwd, "work/s1"), { recursive: true });
    await mkdir(join(cwd, "elsewhere"), { recursive: true });
    await symlink(join(cwd, "elsewhere"), join(cwd, "work/s1/tool-output"));
    const out = body(await run(cwd, "a.macho", withSymbols([{ name: "_a" }, { name: "_b" }]), { limit: 1 }));
    assert.deepEqual(await readdir(join(cwd, "elsewhere")), []);
    assert.equal(out.status, "partial");
    assert.ok(out.problems.some((p: string) => /could not be written to a file/.test(p)), JSON.stringify(out.problems));
  });
});

test("hostile parameters are refused as JSON, never a traceback", async () => {
  await withCwd(async (cwd) => {
    await put(cwd, "work/ok.macho", macho());
    const cases: unknown[] = [null, [], "x", { path: 1 }, { path: "" }, { path: "a\u0000b" }, { path: "work/ok.macho", limit: 10 ** 30 }, { path: "work/ok.macho", limit: true },
      { path: "work/ok.macho", max_seconds: 0 }, { path: "work/ok.macho", extra: 1 }, { path: "work/ok.macho", write_values: "yes" }, { path: "\ud800" }];
    for (const c of cases) {
      const r = await tool(MACHO_DIRECTORIES, cwd, c);
      assert.doesNotMatch(r.stderr, /Traceback/, JSON.stringify(c));
      assert.notEqual(r.code, 0);
      assert.equal((JSON.parse(r.stdout) as Json).status, "failed");
    }
    let nest: unknown = [];
    for (let i = 0; i < 4000; i++) nest = [nest];
    const deep = await tool(MACHO_DIRECTORIES, cwd, nest);
    assert.doesNotMatch(deep.stderr, /Traceback/);
    assert.equal((JSON.parse(deep.stdout) as Json).status, "failed");
  });
});

// --- time, memory and signals -----------------------------------------------------------------------------------------------------------

test("a bind stream of millions of opcodes ends under max_seconds 1, partial, naming the clock", async () => {
  await withCwd(async (cwd) => {
    const bind = Buffer.concat([Buffer.from([BIND.ORDINAL_IMM | 1, BIND.SYMBOL]), cstr("_x"), Buffer.alloc(3_000_000, BIND.DO_BIND)]);
    const t0 = Date.now();
    const out = body(await run(cwd, "bigbind.macho", dyldFile({ bind }), { max_seconds: 1 }));
    assert.ok(Date.now() - t0 < 15_000, `took ${Date.now() - t0} ms`);
    assert.equal(out.status, "partial");
    assert.ok(out.limits_hit.some((l: string) => /time: the bind stream stopped at max_seconds/.test(l)), JSON.stringify(out.limits_hit));
    const count = out.tables.bind_opcodes.matched;
    assert.ok(count > 0 && count < 3_000_000);
    const file = (await filesUnder(join(cwd, "work/s1/tool-output"))).find((f) => f.includes("bind_opcodes"));
    assert.ok(file);
    assert.equal((await readFile(join(cwd, "work/s1/tool-output", file!), "utf8")).trim().split("\n").length, count, "the count equals the rows in the file");
  });
});

test("a bind stream of more than 4,000,000 opcodes that bind nothing is cut at the bound, with a limit that names it", async () => {
  await withCwd(async (cwd) => {
    const bind = Buffer.alloc(4_100_000, BIND.TYPE_IMM | 1);
    const out = body(await run(cwd, "manyops.macho", dyldFile({ bind })));
    assert.equal(out.status, "partial");
    assert.ok(out.limits_hit.some((l: string) => /the bind stream holds more than 4000000 opcodes: the first 4000000 are decoded/.test(l)), JSON.stringify(out.limits_hit));
    assert.equal(out.slices[0].dyld_info.bind.decoded.opcodes, 4_000_000);
  });
});

test("SIGTERM during a read answers with one JSON document and exit 143", async () => {
  await withCwd(async (cwd) => {
    const syms = Array.from({ length: 60000 }, (_, i) => ({ name: `symbol_name_${i}_${"x".repeat(40)}` }));
    await put(cwd, "work/big.macho", withSymbols(syms));
    const run1 = startDetached(MACHO_DIRECTORIES, cwd, { path: "work/big.macho", limit: 20000 });
    try {
      await termHandlerIn(run1.pid);          // counted from the handler, not from the spawn: an interpreter still loading has nothing to answer with
      await new Promise((r) => setTimeout(r, 300));
      run1.signal("SIGTERM");
      run1.signal("SIGTERM");
      const code = await run1.closed;
      if (code === 0) return;               // finished before the signal: nothing to hold
      assert.equal(code, 143);
      const docs = run1.stdout().trim().split("\n").filter(Boolean);
      assert.equal(docs.length, 1, "one document");
      assert.equal((JSON.parse(docs[0]!) as Json).status, "failed");
    } finally {
      try { run1.signal("SIGKILL"); } catch { /* gone */ }
    }
  });
});

test("a second SIGTERM that lands while the first is being answered does not take the document away (exit 143, one document)", async () => {
  // A signal handler can be entered again between two bytecodes of itself. Two stops sent one after the other are usually both pending when the first is
  // handled, so on a loaded host the second came in after the first had marked the answer as begun and before it had written it: no document at all.
  // Here the second stop is sent from inside the first handler, at the moment the handler builds its document, so every host gets that order.
  await withCwd(async (cwd) => {
    const syms = Array.from({ length: 60000 }, (_, i) => ({ name: `symbol_name_${i}_${"x".repeat(40)}` }));
    await put(cwd, "work/big.macho", withSymbols(syms));
    await put(cwd, "shim/sitecustomize.py", [
      "import json, os, signal, sys",
      "_dumps, _sent = json.dumps, []",
      "def _dumps_then_stop_again(*a, **k):",
      "    if not _sent and sys._getframe(1).f_code.co_name == '_stopped_by_signal':",
      "        _sent.append(1)",
      "        os.kill(os.getpid(), signal.SIGTERM)",
      "    return _dumps(*a, **k)",
      "json.dumps = _dumps_then_stop_again",
      "",
    ].join("\n"));
    const run1 = startDetached(MACHO_DIRECTORIES, cwd, { path: "work/big.macho", limit: 20000 }, { PYTHONPATH: join(cwd, "shim") });
    try {
      await termHandlerIn(run1.pid);
      await new Promise((r) => setTimeout(r, 300));
      run1.signal("SIGTERM");
      const code = await run1.closed;
      if (code === 0) return;               // finished before the signal: nothing to hold
      assert.equal(code, 143);
      const docs = run1.stdout().trim().split("\n").filter(Boolean);
      assert.equal(docs.length, 1, "one document");
      assert.equal((JSON.parse(docs[0]!) as Json).status, "failed");
    } finally {
      try { run1.signal("SIGKILL"); } catch { /* gone */ }
    }
  });
});

// --- agreement with otool, where it exists ------------------------------------------------------------------------------------------------

const haveOtool = spawnSync("sh", ["-c", "command -v otool"]).status === 0;
test("agreement with otool -l and otool -L on binaries present on this machine (read only)", { skip: haveOtool ? false : "otool is not installed on this machine (macOS only); not verified here" }, async () => {
  await withCwd(async (cwd) => {
    for (const p of ["/bin/ls", "/bin/sh", "/usr/bin/true"]) {
      if (spawnSync("test", ["-f", p]).status !== 0) continue;
      const out = JSON.parse((await tool(MACHO_DIRECTORIES, cwd, { path: p, limit: 20000 })).stdout) as Json;
      const libs = spawnSync("otool", ["-L", p], { encoding: "utf8" }).stdout.split("\n").filter((l) => l.startsWith("\t")).map((l) => l.trim().split(" (")[0]);
      const ours = rowsOf(out, "libraries").filter((r) => r.kind !== "id").map((r) => r.name);
      for (const l of libs) assert.ok(ours.includes(l), `${p}: ${l}`);
      // (a universal binary: the tool reads every slice, so otool is asked for every slice too; without -arch it prints the one of the host)
      const cmds = (spawnSync("otool", ["-arch", "all", "-l", p], { encoding: "utf8" }).stdout.match(/^Load command \d+/gm) ?? []).length;
      assert.equal(out.tables.load_commands.matched, cmds, p);
    }
  });
});

// --- a cut string is partial, a long name is given as such, memory and a full disk ---------------------------------------------------------

test("a name longer than the 4,096 bytes read is a problem and the answer is partial, in a symbol and in a chained-fixups import, and the text states no length it did not see", async () => {
  await withCwd(async (cwd) => {
    const long = "A".repeat(9000);
    const a = body(await run(cwd, "longsym.macho", withSymbols([{ name: long }, { name: "_ok" }])));
    assert.equal(a.status, "partial");
    assert.ok(a.problems.some((p: string) => /symbol name at file offset \d+ has no terminator within its table or 4096 bytes/.test(p)), JSON.stringify(a.problems));
    const row = rowsOf(a, "symbols")[0];
    assert.equal(row.name_unterminated, true);
    assert.match(row.name, /^<a string of at least 4096 characters, cut where it was read: longer than the 512 shown, so not shown>$/);
    assert.equal(rowsOf(a, "symbols")[1].name, "_ok");
    const cf = chained(1, [{ name: long, ordinal: 1 }, { name: "_free", ordinal: 1 }]);
    const b = body(await run(cwd, "longimp.macho", macho({ commands: (c, alloc) => [c.linkedit(LC_CHAINED_FIXUPS, alloc(cf, 8), cf.length)] })));
    assert.equal(b.status, "partial");
    assert.ok(b.problems.some((p: string) => /import name at file offset \d+ has no terminator/.test(p)), JSON.stringify(b.problems));
    assert.match(rowsOf(b, "chained_imports")[0].name, /^<a string of at least 4096 characters/);
    // a team identifier and a re-export import name are cut the same way
    const exp = trie([{ name: "_viaother", reexport: { ordinal: 1, import: long } }]);
    const c = body(await run(cwd, "longre.macho", dyldFile({ exp })));
    assert.equal(c.status, "partial");
    assert.ok(c.problems.some((p: string) => /reexport name at file offset \d+ has no terminator/.test(p)), JSON.stringify(c.problems));
  });
});

test("a terminated name over 512 characters is given by its length, one of 512 is shown, and the kind decides", async () => {
  await withCwd(async (cwd) => {
    const name600 = "word_".repeat(120), name500 = "word_".repeat(100);
    const a = body(await run(cwd, "n600.macho", withSymbols([{ name: name600 }, { name: name500 }])));
    assert.equal(a.status, "complete", JSON.stringify(a.problems));
    assert.equal(rowsOf(a, "symbols")[0].name, "<a name of 600 characters: longer than the 512 shown, so not shown>");
    assert.equal(rowsOf(a, "symbols")[1].name, name500);
    const lib = body(await run(cwd, "lib600.macho", macho({ commands: (c) => [c.dylib(LC_LOAD_DYLIB, "/usr/lib/" + "dir_".repeat(150) + ".dylib")] })));
    assert.match(rowsOf(lib, "libraries")[0].name, /^<a name of \d+ characters: longer than the 512 shown, so not shown>$/);
  });
});

test("an export trie whose every node has 255 edges with empty names to the next node stays inside a memory ceiling (ulimit -v) and answers", async () => {
  await withCwd(async (cwd) => {
    const K = 16000;
    const uleb4 = (v: number) => Buffer.from([(v & 0x7f) | 0x80, ((v >> 7) & 0x7f) | 0x80, ((v >> 14) & 0x7f) | 0x80, (v >> 21) & 0x7f]);
    const nodeLen = 2 + 255 * 5;
    const nodes: Buffer[] = [];
    for (let k = 0; k < K; k++) {
      if (k === K - 1) { nodes.push(Buffer.from([0, 0])); continue; }
      const edge = Buffer.concat([Buffer.from([0]), uleb4((k + 1) * nodeLen)]);
      nodes.push(Buffer.concat([Buffer.from([0, 255]), ...Array.from({ length: 255 }, () => edge)]));
    }
    await put(cwd, "work/deep.macho", dyldFile({ exp: Buffer.concat(nodes) }));
    const r = spawnSync("bash", ["-c", `ulimit -v 300000; exec python3 "${MACHO_DIRECTORIES}"`], { cwd, input: JSON.stringify({ path: "work/deep.macho", max_seconds: 60 }), env: { ...process.env, AGENT_ID: "s1" }, encoding: "utf8", maxBuffer: 1 << 26 });
    assert.doesNotMatch(r.stderr, /Traceback|MemoryError/);
    const a = JSON.parse(r.stdout) as Json;
    assert.ok(["partial", "complete"].includes(a.status), r.stdout.slice(0, 300));
    assert.equal(a.slices[0].dyld_info.export.decoded.nodes, K, "every node is walked once");
  });
});

test("a disk that fills while a table file is written leaves no partial table file behind and names none", async () => {
  await withCwd(async (cwd) => {
    const syms = Array.from({ length: 3000 }, (_, i) => ({ name: `symbol_name_${i}` }));
    await put(cwd, "work/full.macho", withSymbols(syms));
    const r = spawnSync("bash", ["-c", `ulimit -f 8; exec python3 "${MACHO_DIRECTORIES}"`], { cwd, input: JSON.stringify({ path: "work/full.macho", limit: 5 }), env: { ...process.env, AGENT_ID: "s1" }, encoding: "utf8", maxBuffer: 1 << 26 });
    assert.doesNotMatch(r.stderr, /Traceback/);
    const a = JSON.parse(r.stdout) as Json;
    assert.equal(a.status, "partial");
    assert.ok(a.tables.symbols.not_written, JSON.stringify(a.tables.symbols));
    assert.equal(a.tables.symbols.all_results, undefined);
    const files = await filesUnder(join(cwd, "work/s1/tool-output")).catch(() => [] as string[]);
    assert.deepEqual(files.filter((f) => f.includes("symbols")), [], files.join());
  });
});
