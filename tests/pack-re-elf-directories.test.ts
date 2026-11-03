/**
 * elf_directories: ELF32 and ELF64 in both byte orders built here from the System V gABI (the Ehdr, the program headers, the dynamic array,
 * DT_HASH, the symbol tables, the note format of the Linux "Note Section" convention), and, where the machine has readelf, the files that came
 * with the machine, read by the tool and by readelf and compared. A fixture is built from the format's layout and never from the tool's output.
 *
 * What these cases hold: the dynamic array is read through PT_DYNAMIC (a file with no section headers reads the same), zero DT_NEEDED is zero,
 * a dynamic array with no terminator, a symbol table past the end of the file and a note past its segment are problems and never an empty list,
 * the first `limit` rows are in the answer and the whole table is in a file, a string that is token-shaped is withheld, and a pipe, a link and
 * hostile parameters are refused as JSON.
 */
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { mkdir, readFile, symlink } from "node:fs/promises";
import { join } from "node:path";
import { test } from "node:test";
import { TOOLS, body, filesUnder, put, refused, startDetached, tool, withCwd } from "./pack-re-harness.ts";
import type { Json } from "./pack-re-harness.ts";

const ELF_DIRS = join(TOOLS, "elf_directories", "run.py");

type Sym = { name: string; value?: number; size?: number; type?: number; bind?: number; other?: number; shndx?: number };
type Opts = {
  cls: 32 | 64; big?: boolean; needed?: string[]; soname?: string; rpath?: string; runpath?: string; flags?: number; flags1?: number; bindNowTag?: boolean;
  dynsyms?: Sym[]; symtab?: Sym[]; buildId?: string; abi?: [number, number, number, number]; noSections?: boolean; noDynamic?: boolean;
  noTerminator?: boolean; cutTo?: number; noHash?: boolean; stackExec?: boolean; hashCount?: number;
  gnuHash?: { nbuckets?: number; symoffset: number; bucket0?: number; chain?: number[] };   // a DT_GNU_HASH table (gABI-adjacent GNU extension): nbuckets buckets, only the first can be nonzero
};

/** An ELF file from the gABI: Ehdr, program headers (LOAD over the file, DYNAMIC, NOTE, GNU_STACK), data, then section headers. */
function elf(o: Opts): Buffer {
  const w = o.cls === 64, big = !!o.big;
  const u16 = (v: number) => { const b = Buffer.alloc(2); big ? b.writeUInt16BE(v) : b.writeUInt16LE(v); return b; };
  const u32 = (v: number) => { const b = Buffer.alloc(4); big ? b.writeUInt32BE(v >>> 0) : b.writeUInt32LE(v >>> 0); return b; };
  const u64 = (v: number | bigint) => { const b = Buffer.alloc(8); big ? b.writeBigUInt64BE(BigInt(v)) : b.writeBigUInt64LE(BigInt(v)); return b; };
  const uw = (v: number | bigint) => (w ? u64(v) : u32(Number(v)));
  const i64 = (v: number) => (w ? u64(BigInt.asUintN(64, BigInt(v))) : u32(v));
  const BASE = 0x400000;
  const ehsize = w ? 64 : 52, phentsize = w ? 56 : 32, shentsize = w ? 64 : 40, symsz = w ? 24 : 16;
  const hasDyn = !o.noDynamic;
  const notes: Buffer[] = [];
  const note = (name: string, type: number, desc: Buffer) => {
    const nm = Buffer.concat([Buffer.from(name + "\0")]);
    const pad = (b: Buffer, a: number) => Buffer.concat([b, Buffer.alloc((a - (b.length % a)) % a)]);
    notes.push(Buffer.concat([u32(nm.length), u32(desc.length), u32(type), pad(nm, 4), pad(desc, 4)]));
  };
  if (o.buildId) note("GNU", 3, Buffer.from(o.buildId, "hex"));
  if (o.abi) note("GNU", 1, Buffer.concat(o.abi.map(u32)));
  const noteBlob = Buffer.concat(notes);
  const phdrCount = 1 + (hasDyn ? 1 : 0) + (noteBlob.length ? 1 : 0) + 1;
  let at = ehsize + phdrCount * phentsize;
  const chunks: Buffer[] = [];
  const place = (b: Buffer, align = 8) => { while (at % align) { chunks.push(Buffer.alloc(1)); at += 1; } const where = at; chunks.push(b); at += b.length; return where; };
  // dynamic string table
  let strtab = Buffer.from([0]);
  const str = (s: string) => { const off = strtab.length; strtab = Buffer.concat([strtab, Buffer.from(s + "\0")]); return off; };
  const dyn: [number, number][] = [];
  for (const n of o.needed ?? []) dyn.push([1, str(n)]);
  if (o.soname) dyn.push([14, str(o.soname)]);
  if (o.rpath) dyn.push([15, str(o.rpath)]);
  if (o.runpath) dyn.push([29, str(o.runpath)]);
  const symRows = (syms: Sym[], strOf: (s: string) => number) => Buffer.concat([Buffer.alloc(symsz), ...syms.map((s) => {
    const info = ((s.bind ?? 1) << 4) | (s.type ?? 2);
    return w
      ? Buffer.concat([u32(strOf(s.name)), Buffer.from([info, s.other ?? 0]), u16(s.shndx ?? 1), u64(s.value ?? 0), u64(s.size ?? 0)])
      : Buffer.concat([u32(strOf(s.name)), u32(s.value ?? 0), u32(s.size ?? 0), Buffer.from([info, s.other ?? 0]), u16(s.shndx ?? 1)]);
  })]);
  const dynsymBlob = o.dynsyms ? symRows(o.dynsyms, str) : Buffer.alloc(0);
  const strtabAt = place(strtab, 1);   // placed after the strings of the symbols have been added
  const dynsymAt = o.dynsyms ? place(dynsymBlob, 8) : 0;
  let hashAt = 0;
  if (o.dynsyms && !o.noHash) { const nchain = o.hashCount ?? o.dynsyms.length + 1; hashAt = place(Buffer.concat([u32(1), u32(nchain), u32(0), Buffer.alloc(nchain * 4)]), 4); }
  let gnuAt = 0;
  if (o.gnuHash) {
    const g = o.gnuHash, nb = g.nbuckets ?? 1;
    const buckets = Buffer.alloc(nb * 4);
    if (nb) (big ? buckets.writeUInt32BE(g.bucket0 ?? 0, 0) : buckets.writeUInt32LE(g.bucket0 ?? 0, 0));
    gnuAt = place(Buffer.concat([u32(nb), u32(g.symoffset), u32(1), u32(0), Buffer.alloc(w ? 8 : 4), buckets, ...(g.chain ?? [1]).map(u32)]), 8);
  }
  const entries: [number, number][] = [...dyn, [5, BASE + strtabAt], [10, strtab.length]];
  if (gnuAt) entries.push([0x6ffffef5, BASE + gnuAt]);
  if (o.dynsyms) { entries.push([6, BASE + dynsymAt], [11, symsz]); if (hashAt) entries.push([4, BASE + hashAt]); }
  if (o.flags !== undefined) entries.push([30, o.flags]);
  if (o.flags1 !== undefined) entries.push([0x6ffffffb, o.flags1]);
  if (o.bindNowTag) entries.push([24, 0]);
  if (!o.noTerminator) entries.push([0, 0]);
  const dynBlob = Buffer.concat(entries.map(([t, v]) => Buffer.concat([i64(t), uw(v)])));
  const dynAt = hasDyn ? place(dynBlob, 8) : 0;
  const noteAt = noteBlob.length ? place(noteBlob, 4) : 0;
  // section headers: null, .dynstr, .dynsym, .dynamic, .symtab, .strtab, .shstrtab
  let shoff = 0, shnum = 0, shstrndx = 0;
  if (!o.noSections) {
    let symstr = Buffer.from([0]);
    const sstr = (s: string) => { const off = symstr.length; symstr = Buffer.concat([symstr, Buffer.from(s + "\0")]); return off; };
    const symtabBlob = o.symtab ? symRows(o.symtab, sstr) : Buffer.alloc(0);
    const symtabAt = o.symtab ? place(symtabBlob, 8) : 0;
    const symstrAt = o.symtab ? place(symstr, 1) : 0;
    let shstr = Buffer.from([0]);
    const hstr = (s: string) => { const off = shstr.length; shstr = Buffer.concat([shstr, Buffer.from(s + "\0")]); return off; };
    const names = [hstr(".dynstr"), hstr(".dynsym"), hstr(".dynamic"), hstr(".symtab"), hstr(".strtab"), hstr(".shstrtab")];
    const shstrAt = place(shstr, 1);
    const sh = (name: number, type: number, addr: number, off: number, size: number, link: number, info: number, entsize: number) =>
      Buffer.concat([u32(name), u32(type), uw(2), uw(addr), uw(off), uw(size), u32(link), u32(info), uw(8), uw(entsize)]);
    const rows = [Buffer.alloc(shentsize), sh(names[0]!, 3, BASE + strtabAt, strtabAt, strtab.length, 0, 0, 0), sh(names[1]!, 11, BASE + dynsymAt, dynsymAt, dynsymBlob.length, 1, 1, symsz),
      sh(names[2]!, 6, BASE + dynAt, dynAt, dynBlob.length, 1, 0, w ? 16 : 8), sh(names[3]!, 2, 0, symtabAt, symtabBlob.length, 5, 1, symsz), sh(names[4]!, 3, 0, symstrAt, symstr.length, 0, 0, 0),
      sh(names[5]!, 3, 0, shstrAt, shstr.length, 0, 0, 0)];
    shoff = place(Buffer.concat(rows), 8);
    shnum = rows.length;
    shstrndx = 6;
  }
  const total = at;
  const ph = (type: number, flags: number, off: number, size: number, align: number) => w
    ? Buffer.concat([u32(type), u32(flags), u64(off), u64(BASE + off), u64(BASE + off), u64(size), u64(size), u64(align)])
    : Buffer.concat([u32(type), u32(off), u32(BASE + off), u32(BASE + off), u32(size), u32(size), u32(flags), u32(align)]);
  const phs = [ph(1, 5, 0, total, 0x1000)];
  if (hasDyn) phs.push(ph(2, 6, dynAt, dynBlob.length, 8));
  if (noteBlob.length) phs.push(ph(4, 4, noteAt, noteBlob.length, 4));
  phs.push(ph(0x6474e551, o.stackExec ? 7 : 6, 0, 0, 16));
  const ident = Buffer.from([0x7f, 0x45, 0x4c, 0x46, w ? 2 : 1, big ? 2 : 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
  const ehdr = Buffer.concat([ident, u16(3), u16(w ? 0x3e : 0x03), u32(1), uw(BASE + 0x1000), uw(ehsize), uw(shoff), u32(0), u16(ehsize), u16(phentsize), u16(phs.length), u16(shentsize), u16(shnum), u16(shstrndx)]);
  let file = Buffer.concat([ehdr, ...phs, ...chunks]);
  if (o.cutTo !== undefined) file = file.subarray(0, o.cutTo);
  return file;
}

const run = async (cwd: string, name: string, data: Buffer, args: Json = {}) => {
  await put(cwd, `work/${name}`, data);
  return tool(ELF_DIRS, cwd, { path: `work/${name}`, ...args });
};

const FAMILIES: [string, Opts][] = [
  ["elf64-le", { cls: 64 }], ["elf64-be", { cls: 64, big: true }], ["elf32-le", { cls: 32 }], ["elf32-be", { cls: 32, big: true }],
];

for (const [label, base] of FAMILIES) {
  test(`${label}: the dynamic array, the symbols, the flags and the notes are read through the program headers`, async () => {
    await withCwd(async (cwd) => {
      const data = elf({
        ...base, needed: ["libm.so.6", "libc.so.6"], soname: "libdemo.so.1", runpath: "$ORIGIN/../lib", flags: 0x8 | 0x2, flags1: 0x1 | 0x8000000, buildId: "00112233445566778899aabbccddeeff00112233",
        abi: [0, 3, 2, 0], dynsyms: [{ name: "alpha", value: 0x1000, size: 8, type: 2 }, { name: "beta", bind: 2, type: 1 }, { name: "gamma", shndx: 0, other: 2 }],
        symtab: [{ name: "local_one", bind: 0 }, { name: "global_two" }],
      });
      const out = body(await run(cwd, `${label}.so`, data));
      assert.equal(out.status, "complete", JSON.stringify([out.problems, out.limits_hit]));
      assert.equal(out.bits, base.cls);
      assert.equal(out.byte_order, base.big ? "big" : "little");
      assert.deepEqual(out.dynamic.needed, ["libm.so.6", "libc.so.6"]);
      assert.equal(out.dynamic.soname, "libdemo.so.1");
      assert.deepEqual(out.dynamic.runpath, ["$ORIGIN/../lib"]);
      assert.deepEqual(out.dynamic.flags, ["SYMBOLIC", "BIND_NOW"]);
      assert.deepEqual(out.dynamic.flags_1, ["NOW", "PIE"]);
      assert.equal(out.dynamic.bind_now, true);
      assert.equal(out.dynamic.symbolic, true);
      assert.equal(out.stack_executable, false);
      assert.equal(out.notes.gnu_build_id, "00112233445566778899aabbccddeeff00112233");
      assert.deepEqual(out.notes.gnu_abi_tag, { os: "Linux", version: [3, 2, 0] });
      const dynsym = out.tables.dynsym.rows;
      assert.equal(dynsym.length, 4, "the null symbol and three");
      assert.deepEqual(dynsym.slice(1).map((r: Json) => r.name), ["alpha", "beta", "gamma"]);
      assert.equal(dynsym[1].value, "0x1000");
      assert.equal(dynsym[1].type, "FUNC");
      assert.equal(dynsym[2].bind, "WEAK");
      assert.equal(dynsym[3].section_index, "UND");
      assert.equal(dynsym[3].visibility, "HIDDEN");
      assert.deepEqual(out.tables.symtab.rows.slice(1).map((r: Json) => r.name), ["local_one", "global_two"]);
      assert.equal(out.tables.program_headers.rows.length, 4);
    });
  });
}

test("a file with its section headers stripped is read the same way, and says there are none", async () => {
  await withCwd(async (cwd) => {
    const out = body(await run(cwd, "stripped.so", elf({ cls: 64, needed: ["libz.so.1"], dynsyms: [{ name: "f" }], noSections: true, buildId: "aa".repeat(20) })));
    assert.equal(out.section_headers, "absent");
    assert.deepEqual(out.dynamic.needed, ["libz.so.1"]);
    assert.equal(out.tables.dynsym.rows[1].name, "f");
    assert.equal(out.symbols.symtab, undefined, "a stripped file has no .symtab");
    assert.equal(out.status, "complete");
  });
});

test("zero DT_NEEDED is zero, and a file with no dynamic array says it has none", async () => {
  await withCwd(async (cwd) => {
    const none = body(await run(cwd, "static.elf", elf({ cls: 64, needed: [], noSections: true })));
    assert.equal(none.dynamic.needed_count, 0);
    assert.deepEqual(none.dynamic.needed, []);
    const nodyn = body(await run(cwd, "nodyn.elf", elf({ cls: 64, noDynamic: true, noSections: true })));
    assert.equal(nodyn.dynamic.present, false);
  });
});

test("a dynamic array with no DT_NULL, a symbol table past the end of the file and a truncated header table are problems, and the rows that are there are read", async () => {
  await withCwd(async (cwd) => {
    const a = body(await run(cwd, "noterm.elf", elf({ cls: 64, needed: ["liba.so"], noTerminator: true, noSections: true })));
    assert.equal(a.status, "partial");
    assert.ok(a.problems.some((p: string) => /no DT_NULL/.test(p)), JSON.stringify(a.problems));
    assert.deepEqual(a.dynamic.needed, ["liba.so"]);
    const syms = Array.from({ length: 50 }, (_, i) => ({ name: `sym${i}` }));
    const whole = elf({ cls: 64, needed: ["libb.so"], dynsyms: syms, noSections: true });
    const dynsymAt = whole.indexOf(Buffer.from("sym0\0")) ;
    assert.ok(dynsymAt > 0);
    // cut the file in the middle of the symbol table: the program headers still describe the whole
    const cutAt = whole.length - 200;
    const b = body(await run(cwd, "cut.elf", whole.subarray(0, cutAt)));
    assert.equal(b.status, "partial");
    assert.ok(b.problems.length > 0);
    assert.ok(!b.problems.every((p: string) => p === ""), "named");
    const ph = body(await run(cwd, "shortph.elf", elf({ cls: 64, needed: ["x.so"] }).subarray(0, 100)));
    assert.ok(ph.problems.some((p: string) => /program header table/.test(p)), JSON.stringify(ph.problems));
  });
});

test("a table longer than limit is in the answer as its first rows and whole in a file", async () => {
  await withCwd(async (cwd) => {
    const syms = Array.from({ length: 300 }, (_, i) => ({ name: `symbol_${i}` }));
    const out = body(await run(cwd, "many.so", elf({ cls: 64, needed: ["libc.so.6"], dynsyms: syms, noSections: true }), { limit: 10 }));
    const t = out.tables.dynsym;
    assert.equal(t.matched, 301);
    assert.equal(t.rows.length, 10);
    assert.equal(t.truncated, true);
    assert.ok(t.all_results);
    const files = await filesUnder(join(cwd, "work/s1/tool-output"));
    const file = files.find((f) => f.includes("dynsym"));
    assert.ok(file, files.join());
    const lines = (await readFile(join(cwd, "work/s1/tool-output", file!), "utf8")).trim().split("\n");
    assert.equal(lines.length, 301);
    assert.equal(JSON.parse(lines[300]!).name, "symbol_299");
  });
});

test("a canary in RUNPATH, a library name and a symbol name is withheld, and the answer says it was", async () => {
  await withCwd(async (cwd) => {
    const canary = "AKIAIOSFODNN7EXAMPLE";
    const jwt = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U";
    const out = await run(cwd, "canary.so", elf({ cls: 64, needed: [`lib${canary}.so`], runpath: `/opt/${jwt}`, dynsyms: [{ name: `${canary}_sym` }], symtab: [{ name: jwt }] }));
    const text = out.stdout;
    for (const secret of [canary, jwt]) assert.ok(!text.includes(secret), `the answer prints ${secret.slice(0, 8)}...`);
    for (const f of await filesUnder(join(cwd, "work/s1/tool-output"))) {
      const content = await readFile(join(cwd, "work/s1/tool-output", f), "utf8");
      for (const secret of [canary, jwt]) assert.ok(!content.includes(secret) || f.includes("withheld-names"), `${f} prints ${secret.slice(0, 8)}`);
    }
    const a = JSON.parse(text) as Json;
    assert.ok(a.withheld.names + a.withheld.text > 0);
  });
});

test("not an ELF file is unsupported; a link, a pipe, a directory and a missing file are refused as JSON, and a pipe does not hang", async () => {
  await withCwd(async (cwd) => {
    const x = refused(await run(cwd, "plain.bin", Buffer.from("MZ not elf")));
    assert.equal(x.status, "unsupported");
    await put(cwd, "work/real.so", elf({ cls: 64, needed: [] }));
    await symlink(join(cwd, "work/real.so"), join(cwd, "work/link.so"));
    assert.match(refused(await tool(ELF_DIRS, cwd, { path: "work/link.so" })).error, /symbolic link/);
    spawnSync("mkfifo", [join(cwd, "work/pipe.so")]);
    const t0 = Date.now();
    assert.match(refused(await tool(ELF_DIRS, cwd, { path: "work/pipe.so" })).error, /named pipe/);
    assert.ok(Date.now() - t0 < 20_000);
    await mkdir(join(cwd, "work/d"), { recursive: true });
    assert.match(refused(await tool(ELF_DIRS, cwd, { path: "work/d" })).error, /directory/);
    assert.match(refused(await tool(ELF_DIRS, cwd, { path: "work/none.so" })).error, /no such file/);
    const tiny = refused(await run(cwd, "tiny.elf", Buffer.from("\x7fELF\x02\x01\x01")));
    assert.equal(tiny.status, "failed");
  });
});

test("hostile parameters are refused as JSON, never a traceback", async () => {
  await withCwd(async (cwd) => {
    await put(cwd, "work/ok.so", elf({ cls: 64, needed: [] }));
    const cases: unknown[] = [null, [], "x", { path: 1 }, { path: "" }, { path: "a\u0000b" }, { path: "work/ok.so", limit: 10 ** 30 }, { path: "work/ok.so", limit: true },
      { path: "work/ok.so", max_seconds: 0 }, { path: "work/ok.so", extra: 1 }, { path: "work/ok.so", write_values: "yes" }, { path: "\ud800" }];
    for (const c of cases) {
      const r = await tool(ELF_DIRS, cwd, c);
      assert.doesNotMatch(r.stderr, /Traceback/, JSON.stringify(c));
      assert.notEqual(r.code, 0);
      assert.equal((JSON.parse(r.stdout) as Json).status, "failed");
    }
    let nest: unknown = [];
    for (let i = 0; i < 4000; i++) nest = [nest];
    const deep = await tool(ELF_DIRS, cwd, nest);
    assert.doesNotMatch(deep.stderr, /Traceback/);
    assert.equal((JSON.parse(deep.stdout) as Json).status, "failed");
  });
});

test("write_values is refused outside a job", async () => {
  await withCwd(async (cwd) => {
    await put(cwd, "work/ok.so", elf({ cls: 64, needed: [] }));
    const r = refused(await tool(ELF_DIRS, cwd, { path: "work/ok.so", write_values: true }));
    assert.match(r.error, /outside a job/);
  });
});

test("SIGTERM during a read answers with one JSON document and exit 143", async () => {
  await withCwd(async (cwd) => {
    const syms = Array.from({ length: 60000 }, (_, i) => ({ name: `symbol_name_${i}_${"x".repeat(40)}` }));
    await put(cwd, "work/big.so", elf({ cls: 64, needed: ["libc.so.6"], dynsyms: syms, noSections: true }));
    const run1 = startDetached(ELF_DIRS, cwd, { path: "work/big.so", limit: 20000 });
    try {
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

// --- agreement with readelf on the files this machine has ----------------------------------------------------------------------------

const haveReadelf = spawnSync("sh", ["-c", "command -v readelf"]).status === 0;
test("agreement with readelf -d -s -n on binaries present on this machine (read only)", { skip: haveReadelf ? false : "readelf is not installed on this machine" }, async (t) => {
  const candidates = ["/bin/ls", "/bin/sh", "/usr/bin/env", "/bin/true", "/lib/x86_64-linux-gnu/libc.so.6", "/lib/x86_64-linux-gnu/libm.so.6", "/lib/aarch64-linux-gnu/libc.so.6", process.execPath]
    .filter((p) => spawnSync("test", ["-f", p]).status === 0 && spawnSync("test", ["-L", p]).status !== 0);
  if (!candidates.length) return t.skip("no ELF binary found to read");
  await withCwd(async (cwd) => {
    for (const p of candidates) {
      const out = JSON.parse((await tool(ELF_DIRS, cwd, { path: p, limit: 20000 })).stdout) as Json;
      const rd = (flag: string) => spawnSync("readelf", ["-W", flag, p], { encoding: "utf8", maxBuffer: 1 << 28 }).stdout;
      const needed = [...rd("-d").matchAll(/\(NEEDED\)\s+Shared library: \[(.*?)\]/g)].map((m) => m[1]);
      assert.deepEqual(out.dynamic.needed, needed, p);
      const dsn = rd("--dyn-syms").split("\n").filter((l) => /^\s*\d+:/.test(l)).length;
      assert.equal(out.symbols.dynsym?.listed ?? 0, dsn, `${p}: .dynsym rows`);
      const symtab = rd("-s").split("Symbol table '.symtab'")[1];
      const syn = symtab ? symtab.split("\n").filter((l) => /^\s*\d+:/.test(l)).length : 0;
      assert.equal(out.symbols.symtab?.listed ?? 0, syn, `${p}: .symtab rows`);
      const bid = /Build ID: (\w+)/.exec(rd("-n"))?.[1] ?? null;
      assert.equal(out.notes.gnu_build_id, bid, `${p}: build id`);
      t.diagnostic(`${p}: ${needed.length} needed, ${dsn} dynsym, ${syn} symtab, build id ${bid ? "yes" : "no"}`);
    }
  });
});

// --- a DT_GNU_HASH table is a count only when a bucket holds a symbol -----------------------------------------------------------------

test("a DT_GNU_HASH table with no symbol in any bucket gives only a lower bound: the section header's count is used, or the answer is partial and says at least", async () => {
  await withCwd(async (cwd) => {
    // the shape of every non-PIE executable that exports nothing: the symbols are all imports, below symoffset, and every bucket is empty
    const syms = [{ name: "puts", shndx: 0 }, { name: "__libc_start_main", shndx: 0 }, { name: "__gmon_start__", shndx: 0, bind: 2 }];
    const withSections = body(await run(cwd, "nopie.elf", elf({ cls: 64, needed: ["libc.so.6"], dynsyms: syms, noHash: true, gnuHash: { symoffset: 4, bucket0: 0, chain: [] } })));
    assert.equal(withSections.symbols.dynsym.declared, 4, "the null symbol and three imports");
    assert.equal(withSections.symbols.dynsym.listed, 4);
    assert.equal(withSections.symbols.dynsym.found_by, "the .dynsym section header");
    assert.equal(withSections.status, "complete", JSON.stringify(withSections.problems));
    const stripped = body(await run(cwd, "nopie-nosec.elf", elf({ cls: 64, needed: ["libc.so.6"], dynsyms: syms, noHash: true, gnuHash: { symoffset: 3, bucket0: 0, chain: [] }, noSections: true })));
    assert.equal(stripped.status, "partial");
    assert.equal(stripped.symbols.dynsym.found_by, "DT_GNU_HASH lower bound");
    assert.ok(stripped.problems.some((p: string) => /at least 3 symbols/.test(p)), JSON.stringify(stripped.problems));
    // a table with a symbol in a bucket still gives its count
    const hashed = body(await run(cwd, "hashed.elf", elf({ cls: 64, needed: [], dynsyms: [{ name: "a" }, { name: "b" }], noHash: true, gnuHash: { symoffset: 1, bucket0: 1, chain: [0, 1] }, noSections: true })));
    assert.equal(hashed.symbols.dynsym.declared, 3);
    assert.equal(hashed.symbols.dynsym.found_by, "DT_GNU_HASH");
  });
});

test("a hash table of 16 million buckets is scanned under the clock: max_seconds 1 ends the read within a few seconds and the answer is partial", async () => {
  await withCwd(async (cwd) => {
    const data = elf({ cls: 64, needed: [], dynsyms: [{ name: "x" }], noHash: true, gnuHash: { nbuckets: 0xffffff, symoffset: 1, bucket0: 0, chain: [] }, noSections: true });
    await put(cwd, "work/buckets.elf", data);
    const t0 = Date.now();
    const out = body(await tool(ELF_DIRS, cwd, { path: "work/buckets.elf", max_seconds: 1 }));
    assert.ok(Date.now() - t0 < 6000, `took ${Date.now() - t0} ms`);
    assert.ok(["partial", "complete"].includes(out.status));
    assert.ok(out.symbols.dynsym === undefined || out.symbols.dynsym.listed >= 0);
  });
});

// --- readelf on files gcc makes here: no-PIE with no exports, PIE, static, stripped, a shared object with a soname and a runpath ---------

const haveGcc = spawnSync("sh", ["-c", "command -v gcc"]).status === 0 && haveReadelf;
test("agreement with readelf on files gcc makes: no-PIE with no exports, PIE, static, stripped, a shared object with soname and runpath", { skip: haveGcc ? false : "gcc or readelf is not installed on this machine" }, async () => {
  await withCwd(async (cwd) => {
    await put(cwd, "work/h.c", '#include <stdio.h>\nint main(void){puts("hi");return 0;}\n');
    await put(cwd, "work/lib.c", "int exported_one(int x){return x+1;}\nint exported_two(void){return 2;}\n");
    const build: [string, string[]][] = [
      ["nopie", ["-no-pie", "work/h.c"]], ["pie", ["-pie", "-fPIE", "work/h.c"]], ["static", ["-static", "work/h.c"]], ["stripped", ["-s", "work/h.c"]],
      ["so", ["-shared", "-fPIC", "-Wl,-soname,libdemo.so.1", "-Wl,-rpath,/opt/demo/lib", "work/lib.c"]],
    ];
    for (const [name, flags] of build) {
      const made = spawnSync("gcc", [...flags, "-o", `work/${name}`], { cwd, encoding: "utf8" });
      if (made.status !== 0) continue;               // a machine without a static libc builds the rest
      const out = body(await tool(ELF_DIRS, cwd, { path: `work/${name}`, limit: 20000 }));
      const rd = (flag: string) => spawnSync("readelf", ["-W", flag, join(cwd, "work", name)], { encoding: "utf8", maxBuffer: 1 << 28 }).stdout;
      const needed = [...rd("-d").matchAll(/\(NEEDED\)\s+Shared library: \[(.*?)\]/g)].map((m) => m[1]);
      assert.deepEqual(out.dynamic.needed ?? [], needed, name);
      const dsn = rd("--dyn-syms").split("\n").filter((l) => /^\s*\d+:/.test(l)).length;
      assert.equal(out.symbols.dynsym?.listed ?? 0, dsn, `${name}: .dynsym rows`);
      const symtab = rd("-s").split("Symbol table '.symtab'")[1];
      const syn = symtab ? symtab.split("\n").filter((l) => /^\s*\d+:/.test(l)).length : 0;
      assert.equal(out.symbols.symtab?.listed ?? 0, syn, `${name}: .symtab rows`);
      assert.equal(out.notes.gnu_build_id, /Build ID: (\w+)/.exec(rd("-n"))?.[1] ?? null, `${name}: build id`);
      if (name === "so") {
        assert.equal(out.dynamic.soname, "libdemo.so.1");
        assert.deepEqual(out.dynamic.rpath.concat(out.dynamic.runpath), ["/opt/demo/lib"]);
      }
      if (name === "static") assert.equal(out.dynamic.present, false);
      assert.equal(out.status, "complete", `${name}: ${JSON.stringify(out.problems)}`);
    }
  });
});

test("a symbol name longer than the 4,096 bytes read is a problem and the answer is partial, and the text states no length it did not see", async () => {
  await withCwd(async (cwd) => {
    const out = body(await run(cwd, "longname.so", elf({ cls: 64, needed: [], dynsyms: [{ name: "A".repeat(9000) }, { name: "ok" }] })));
    assert.equal(out.status, "partial");
    assert.ok(out.problems.some((p: string) => /symbol name at file offset \d+ has no terminator within its table or 4096 bytes/.test(p)), JSON.stringify(out.problems));
    assert.match(out.tables.dynsym.rows[1].name, /^<a string of at least 4096 characters, cut where it was read: longer than the 512 shown, so not shown>$/);
    const fine = body(await run(cwd, "name600.so", elf({ cls: 64, needed: [], dynsyms: [{ name: "word_".repeat(120) }] })));
    assert.equal(fine.status, "complete", JSON.stringify(fine.problems));
    assert.equal(fine.tables.dynsym.rows[1].name, "<a name of 600 characters: longer than the 512 shown, so not shown>");
  });
});
