/**
 * pe_directories with clr_tables: the ECMA-335 metadata table stream (#~) of a managed assembly, built here from the standard (II.22 table layouts,
 * II.23.2 compressed integers, II.24.2 the metadata root, stream headers and heaps), inside a minimal PE32+ file built from the PE/COFF specification.
 * A fixture is built from the standard's layout, with every column written at the width the standard gives it, and never from the tool's output.
 *
 * What these cases hold: the heap-size byte, the valid mask, the row counts and the coded-index widths decide where the next table starts; the rows of
 * the eleven listed tables come out with their file offsets, names from #Strings, blobs by offset and size, GUIDs and user strings; a #- stream, an
 * edit-and-continue stream and a table the standard does not give are refused as unsupported (the answer is partial and says why); heap offsets past
 * their stream, row counts the stream cannot hold and cut heaps are problems and never an empty list; a token-shaped name is withheld on every path.
 */
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { readFile } from "node:fs/promises";
import { join } from "node:path";
import { test } from "node:test";
import { PE_DIRECTORIES, body, filesUnder, put, tool, withCwd } from "./pack-re-harness.ts";
import type { Json } from "./pack-re-harness.ts";

const u16 = (v: number) => { const b = Buffer.alloc(2); b.writeUInt16LE(v); return b; };
const u32 = (v: number) => { const b = Buffer.alloc(4); b.writeUInt32LE(v >>> 0); return b; };
const u64 = (v: bigint) => { const b = Buffer.alloc(8); b.writeBigUInt64LE(v); return b; };
const pad4 = (b: Buffer) => Buffer.concat([b, Buffer.alloc((4 - (b.length % 4)) % 4)]);

/** One column at an explicit width: the fixture never asks the tool how wide a column is. */
type Col = [1 | 2 | 4, number];
const row = (...cols: Col[]) => Buffer.concat(cols.map(([w, v]) => (w === 1 ? Buffer.from([v]) : w === 2 ? u16(v) : u32(v))));

/** #Strings: a leading NUL, then each string and its NUL. */
function stringsHeap(names: string[]) {
  const parts = [Buffer.from([0])];
  let n = 1;
  const at: Record<string, number> = {};
  for (const s of names) { at[s] = n; const b = Buffer.from(s + "\0", "utf8"); parts.push(b); n += b.length; }
  return { buf: Buffer.concat(parts), at };
}
/** II.23.2: a blob's length, compressed to 1, 2 or 4 bytes. */
function blobLength(n: number): Buffer {
  if (n < 0x80) return Buffer.from([n]);
  if (n < 0x4000) return Buffer.from([0x80 | (n >> 8), n & 0xff]);
  return Buffer.from([0xc0 | (n >> 24), (n >> 16) & 0xff, (n >> 8) & 0xff, n & 0xff]);
}
function blobHeap(blobs: Buffer[]) {
  const parts = [Buffer.from([0])];
  let n = 1;
  const at: number[] = [];
  for (const b of blobs) { at.push(n); const e = Buffer.concat([blobLength(b.length), b]); parts.push(e); n += e.length; }
  return { buf: Buffer.concat(parts), at };
}
/** A GUID in its mixed-endian storage: Data1, Data2, Data3 little-endian, then the eight bytes. */
function guidBytes(text: string): Buffer {
  const h = text.replace(/-/g, "");
  const b = Buffer.from(h, "hex");
  return Buffer.concat([Buffer.from(b.subarray(0, 4)).reverse(), Buffer.from(b.subarray(4, 6)).reverse(), Buffer.from(b.subarray(6, 8)).reverse(), b.subarray(8, 16)]);
}
/** #US: a leading NUL, then for each string its compressed byte length (UTF-16 bytes + 1), the UTF-16LE characters and a flag byte. */
function usHeap(strings: string[]) {
  const parts = [Buffer.from([0])];
  let n = 1;
  const at: number[] = [];
  for (const s of strings) { at.push(n); const data = Buffer.from(s, "utf16le"); const e = Buffer.concat([blobLength(data.length + 1), data, Buffer.from([0])]); parts.push(e); n += e.length; }
  return { buf: Buffer.concat(parts), at };
}

type Tables = { heapSizes?: number; rows: Record<number, Buffer[]>; declared?: Record<number, number>; validExtra?: bigint; version?: [number, number]; extra?: boolean; short?: number };
/** II.24.2.6: the #~ stream header, the row counts and then the tables in table-id order. */
function tablesStream(t: Tables): Buffer {
  const ids = [...new Set([...Object.keys(t.rows).map(Number), ...Object.keys(t.declared ?? {}).map(Number)])].sort((a, b) => a - b);
  let valid = t.validExtra ?? 0n;
  for (const id of ids) valid |= 1n << BigInt(id);
  const head = Buffer.concat([u32(0), Buffer.from([t.version?.[0] ?? 2, t.version?.[1] ?? 0, t.heapSizes ?? 0, 1]), u64(valid), u64(0n)]);
  const counts = ids.map((id) => u32(t.declared?.[id] ?? t.rows[id]?.length ?? 0));
  const data = ids.map((id) => Buffer.concat(t.rows[id] ?? []));
  return Buffer.concat([head, ...counts, ...(t.extra ? [u32(0)] : []), ...data]);
}

/** II.24.2.1 and II.24.2.2: the metadata root and its stream headers, then the streams, each on a 4-byte boundary. */
function metadataRoot(streams: { name: string; data: Buffer }[], version = "v4.0.30319") {
  const ver = pad4(Buffer.from(version + "\0"));
  const headerSize = (s: { name: string }) => 8 + pad4(Buffer.from(s.name + "\0")).length;
  const rootSize = 16 + ver.length + 4 + streams.reduce((n, s) => n + headerSize(s), 0);
  let off = rootSize;
  const offsets: number[] = [];
  for (const s of streams) { offsets.push(off); off += pad4(s.data).length; }
  const headers = streams.map((s, i) => Buffer.concat([u32(offsets[i]!), u32(s.data.length), pad4(Buffer.from(s.name + "\0"))]));
  const root = Buffer.concat([u32(0x424a5342), u16(1), u16(1), u32(0), u32(ver.length), ver, u16(0), u16(streams.length), ...headers]);
  return { blob: Buffer.concat([root, ...streams.map((s) => pad4(s.data))]), offsets };
}

/** A PE32+ file (PE/COFF specification): DOS header, signature, COFF header, optional header with 16 data directories, one section; the CLR header at the section's start. */
function pe(metadata: Buffer, o: { noClr?: boolean } = {}) {
  const textRva = 0x1000, raw = 0x200, mdRva = textRva + 0x100;
  const clrHdr = Buffer.concat([u32(72), u16(2), u16(5), u32(mdRva), u32(metadata.length), u32(1), u32(0x06000001), Buffer.alloc(72 - 28)]);
  const section = Buffer.concat([clrHdr, Buffer.alloc(0x100 - clrHdr.length), metadata]);
  const sizeRaw = Math.ceil(section.length / 0x200) * 0x200;
  const dirs = Buffer.alloc(16 * 8);
  if (!o.noClr) { dirs.writeUInt32LE(textRva, 14 * 8); dirs.writeUInt32LE(72, 14 * 8 + 4); }
  const optional = Buffer.concat([u16(0x20b), Buffer.from([14, 0]), u32(sizeRaw), u32(0), u32(0), u32(0), u32(textRva), u64(0x180000000n), u32(0x1000), u32(0x200),
    u16(6), u16(0), u16(0), u16(0), u16(6), u16(0), u32(0), u32(textRva + Math.ceil(section.length / 0x1000) * 0x1000), u32(0x200), u32(0), u16(3), u16(0x8160),
    u64(0x100000n), u64(0x1000n), u64(0x100000n), u64(0x1000n), u32(0), u32(16), dirs]);
  assert.equal(optional.length, 240);
  const coff = Buffer.concat([u16(0x8664), u16(1), u32(0x5f000000), u32(0), u32(0), u16(240), u16(0x2022)]);
  const sectionHeader = Buffer.concat([Buffer.from(".text\0\0\0"), u32(section.length), u32(textRva), u32(sizeRaw), u32(raw), u32(0), u32(0), u16(0), u16(0), u32(0x60000020)]);
  const dos = Buffer.alloc(0x40);
  dos.write("MZ", 0, "latin1");
  dos.writeUInt32LE(0x40, 0x3c);
  const headers = Buffer.concat([dos, Buffer.from("PE\0\0"), coff, optional, sectionHeader]);
  const file = Buffer.concat([headers, Buffer.alloc(raw - headers.length), section, Buffer.alloc(sizeRaw - section.length)]);
  return { file, mdFile: raw + 0x100 };
}

/** A small assembly with one row in each listed table (and two in some) and one row in two tables the tool does not list, between them: they decide where the next table starts. */
function assembly(o: { heapSizes?: number; names?: Partial<Record<"assembly" | "typeref", string>>; user?: string[] } = {}) {
  const wide = (o.heapSizes ?? 0) as number;
  const sw = wide & 1 ? 4 : 2, gw = wide & 2 ? 4 : 2, bw = wide & 4 ? 4 : 2;
  const asmName = o.names?.assembly ?? "TestAsm", objName = o.names?.typeref ?? "Object";
  const S = stringsHeap(["<Module>", "Program", "Test.dll", asmName, "System", objName, "Console", "Main", ".ctor", "value", "arg", "WriteLine", "MessageBeep", "user32.dll", "res.txt", "en-US"]);
  const B = blobHeap([Buffer.from([0x06, 0x08]), Buffer.from([0x20, 0x00, 0x01]), Buffer.from("0123456789abcdef"), Buffer.alloc(300, 7)]);
  const G = Buffer.concat([guidBytes("00112233-4455-6677-8899-aabbccddeeff"), guidBytes("a1b2c3d4-e5f6-4789-8abc-def012345678")]);
  const U = usHeap(o.user ?? ["Hello", "World"]);
  const s = (n: string): Col => [sw, S.at[n]!];
  const g = (i: number): Col => [gw, i];
  const b = (i: number): Col => [bw, i < 0 ? 0 : B.at[i]!];
  const tables: Tables = {
    heapSizes: wide,
    rows: {
      0x00: [row([2, 0], s("Test.dll"), g(1), g(0), g(0))],
      0x01: [row([2, (1 << 2) | 2], s(objName), s("System")), row([2, (1 << 2) | 2], s("Console"), s("System"))],
      0x02: [row([4, 0], s("<Module>"), [sw, 0], [2, 0], [2, 1], [2, 1]), row([4, 0x100001], s("Program"), [sw, 0], [2, (1 << 2) | 1], [2, 1], [2, 1])],
      0x04: [row([2, 6], s("value"), b(0))],
      0x06: [row([4, 0x2050], [2, 0], [2, 0x96], s("Main"), b(1), [2, 1]), row([4, 0x2060], [2, 0], [2, 0x1886], s(".ctor"), b(1), [2, 2])],
      0x08: [row([2, 0], [2, 1], s("arg"))],
      0x0a: [row([2, (1 << 3) | 1], s(".ctor"), b(1)), row([2, (2 << 3) | 1], s("WriteLine"), b(1))],
      0x0c: [row([2, 0x2e], [2, (2 << 3) | 3], b(2))],               // CustomAttribute: HasCustomAttribute (5 tag bits), CustomAttributeType (3 tag bits), Value
      0x1a: [row(s("user32.dll"))],                                   // ModuleRef
      0x1c: [row([2, 0x100], [2, (1 << 1) | 1], s("MessageBeep"), [2, 1])],
      0x20: [row([4, 0x8004], [2, 1], [2, 2], [2, 3], [2, 4], [4, 0x1], b(2), s(asmName), s("en-US"))],
      0x23: [row([2, 4], [2, 0], [2, 0], [2, 0], [4, 0], b(2), s("System"), [sw, 0], b(-1))],
      0x28: [row([4, 0x20], [4, 1], s("res.txt"), [2, 0])],
    },
  };
  const streams = [{ name: "#~", data: tablesStream(tables) }, { name: "#Strings", data: S.buf }, { name: "#US", data: U.buf }, { name: "#GUID", data: G }, { name: "#Blob", data: B.buf }];
  const md = metadataRoot(streams);
  const built = pe(md.blob);
  return { ...built, tablesAt: built.mdFile + md.offsets[0]!, stringsAt: built.mdFile + md.offsets[1]!, S, B, streams, tables };
}

const run = async (cwd: string, name: string, data: Buffer, args: Json = {}) => {
  await put(cwd, `work/${name}`, data);
  return tool(PE_DIRECTORIES, cwd, { path: `work/${name}`, clr_tables: true, ...args });
};
const answer = async (cwd: string, name: string, data: Buffer, args: Json = {}): Promise<Json> => { const r = await run(cwd, name, data, args); assert.equal(r.code, 0, r.stderr + r.stdout); assert.doesNotMatch(r.stderr, /Traceback/); return JSON.parse(r.stdout); };
const rows = (a: Json, t: string): Json[] => a.tables[t]?.rows ?? [];

test("the heap sizes, the valid mask, the row counts and the coded-index widths are read, and the rows of the eleven listed tables come out with names, blobs, GUIDs and offsets", async () => {
  await withCwd(async (cwd) => {
    const asm = assembly();
    const a = await answer(cwd, "a.dll", asm.file);
    assert.equal(a.status, "complete", JSON.stringify([a.problems, a.limits_hit]));
    const t = a.clr_tables;
    assert.equal(t.status, "read");
    assert.deepEqual([t.version, t.heap_sizes, t.string_index_bytes, t.guid_index_bytes, t.blob_index_bytes], ["2.0", "0x0", 2, 2, 2]);
    assert.equal(t.file_offset, asm.tablesAt);
    assert.deepEqual(t.row_counts, { Module: 1, TypeRef: 2, TypeDef: 2, Field: 1, MethodDef: 2, Param: 1, MemberRef: 2, CustomAttribute: 1, ModuleRef: 1, ImplMap: 1, Assembly: 1, AssemblyRef: 1, ManifestResource: 1 });
    assert.deepEqual([t.coded_index_bytes.TypeDefOrRef, t.coded_index_bytes.ResolutionScope, t.table_index_bytes.Field], [2, 2, 2]);
    const dataStart = asm.tablesAt + 24 + 4 * 13;
    const module = rows(a, "clr_module")[0];
    assert.deepEqual([module.row, module.file_offset, module.name, module.mvid, module.enc_id], [1, dataStart, "Test.dll", "00112233-4455-6677-8899-AABBCCDDEEFF", null]);
    const typerefs = rows(a, "clr_typeref");
    assert.deepEqual(typerefs.map((r) => [r.row, r.file_offset, r.resolution_scope, r.namespace, r.name]), [[1, dataStart + 10, "AssemblyRef:1", "System", "Object"], [2, dataStart + 16, "AssemblyRef:1", "System", "Console"]]);
    const typedefs = rows(a, "clr_typedef");
    assert.deepEqual(typedefs.map((r) => [r.name, r.flags, r.extends, r.field_list, r.method_list]), [["<Module>", "0x0", null, 1, 1], ["Program", "0x100001", "TypeRef:1", 1, 1]]);
    assert.deepEqual(rows(a, "clr_field").map((r) => [r.name, r.flags, r.signature.size]), [["value", "0x6", 2]]);
    const methods = rows(a, "clr_methoddef");
    assert.deepEqual(methods.map((r) => [r.name, r.rva, r.impl_flags, r.flags, r.param_list, r.signature.size]), [["Main", "0x2050", "0x0", "0x96", 1, 3], [".ctor", "0x2060", "0x0", "0x1886", 2, 3]]);
    assert.deepEqual(rows(a, "clr_param").map((r) => [r.name, r.sequence]), [["arg", 1]]);
    assert.deepEqual(rows(a, "clr_memberref").map((r) => [r.class, r.name]), [["TypeRef:1", ".ctor"], ["TypeRef:2", "WriteLine"]]);
    assert.deepEqual(rows(a, "clr_implmap").map((r) => [r.mapping_flags, r.member_forwarded, r.import_name, r.import_scope]), [["0x100", "MethodDef:1", "MessageBeep", 1]]);
    const assemblyRow = rows(a, "clr_assembly")[0];
    assert.deepEqual([assemblyRow.name, assemblyRow.culture, assemblyRow.hash_algorithm, assemblyRow.major, assemblyRow.minor, assemblyRow.build, assemblyRow.revision, assemblyRow.public_key.size], ["TestAsm", "en-US", "0x8004", 1, 2, 3, 4, 16]);
    const ref = rows(a, "clr_assemblyref")[0];
    assert.deepEqual([ref.name, ref.major, ref.public_key_or_token.size, ref.hash_value.size], ["System", 4, 16, 0]);
    assert.deepEqual(rows(a, "clr_manifestresource").map((r) => [r.name, r.offset, r.implementation]), [["res.txt", "0x20", null]]);
    assert.deepEqual(rows(a, "clr_guids").map((r) => r.guid), ["00112233-4455-6677-8899-AABBCCDDEEFF", "A1B2C3D4-E5F6-4789-8ABC-DEF012345678"]);
    assert.deepEqual(rows(a, "clr_user_strings").map((r) => [r.string, r.characters]), [["Hello", 5], ["World", 5]]);
    assert.deepEqual(a.clr_tables.heaps["#Strings"].size, asm.S.buf.length);
    // a blob is by offset and size only: the bytes are not in the answer
    assert.ok(!JSON.stringify(a).includes("0123456789abcdef"));
    // without clr_tables the answer is what it was
    const plain = await answer(cwd, "a.dll", asm.file, { clr_tables: false });
    assert.equal(plain.clr_tables, undefined);
    assert.equal(plain.tables?.clr_typedef, undefined);
    assert.match(plain.clr.notes[2], /metadata tables are not read/);
    assert.match(a.clr.notes[2], /read only as far as `clr_tables` lists them/);
  });
});

test("4-byte heap indexes (the heap-sizes byte 0x07) and the 4-byte extra-data word (0x40) move every column and every table", async () => {
  await withCwd(async (cwd) => {
    const a = await answer(cwd, "wide.dll", assembly({ heapSizes: 0x07 }).file);
    assert.equal(a.status, "complete", JSON.stringify(a.problems));
    assert.deepEqual([a.clr_tables.string_index_bytes, a.clr_tables.guid_index_bytes, a.clr_tables.blob_index_bytes], [4, 4, 4]);
    assert.deepEqual(rows(a, "clr_typedef").map((r) => r.name), ["<Module>", "Program"]);
    assert.equal(rows(a, "clr_module")[0].mvid, "00112233-4455-6677-8899-AABBCCDDEEFF");
    assert.equal(rows(a, "clr_assembly")[0].name, "TestAsm");
    assert.equal(rows(a, "clr_assemblyref")[0].name, "System");
    assert.equal(rows(a, "clr_manifestresource")[0].name, "res.txt");
  });
});

test("coded-index and table-index widths change at their thresholds: 2^14 TypeDef rows make TypeDefOrRef 4 bytes, 2^16 Field rows make the Field index 4 bytes", async () => {
  await withCwd(async (cwd) => {
    const S = stringsHeap(["T", "ns"]);
    const mk = (typedefs: number, fields: number) => {
      const wideCoded = typedefs >= 1 << 14;
      const wideField = fields >= 1 << 16;
      const td = Array.from({ length: typedefs }, (_, i) => row([4, i], [2, S.at.T!], [2, S.at.ns!], [wideCoded ? 4 : 2, (i % 3) << 2], [wideField ? 4 : 2, 1], [2, 1]));
      const fd = Array.from({ length: fields }, (_, i) => row([2, i & 0xff], [2, S.at.T!], [2, 0]));
      const streams = [{ name: "#~", data: tablesStream({ rows: { 0x02: td, 0x04: fd } }) }, { name: "#Strings", data: S.buf }];
      return pe(metadataRoot(streams).blob).file;
    };
    for (const [typedefs, fields, coded, index] of [[16383, 10, 2, 2], [16384, 10, 4, 2], [100, 65535, 2, 2], [100, 65536, 2, 4]] as const) {
      const a = await answer(cwd, `w${typedefs}-${fields}.dll`, mk(typedefs, fields), { limit: 5 });
      assert.equal(a.status, "complete", `${typedefs}/${fields}: ${JSON.stringify(a.problems)}`);
      assert.deepEqual([a.clr_tables.coded_index_bytes.TypeDefOrRef, a.clr_tables.table_index_bytes.Field], [coded, index], `${typedefs}/${fields}`);
      assert.equal(a.tables.clr_typedef.matched, typedefs);
      assert.equal(a.tables.clr_field.matched, fields);
    }
    // the last row of a wide table is read where it is
    const last = await answer(cwd, "last.dll", mk(16384, 10), { limit: 20000 });
    const lastRow = rows(last, "clr_typedef").at(-1)!;
    assert.deepEqual([lastRow.row, lastRow.name, lastRow.extends], [16384, "T", null]);
    assert.equal(lastRow.flags, "0x3fff");
  });
});

test("a #- stream, an edit-and-continue table, the delta heap bit and a table the standard does not give are refused as unsupported, and the answer is partial and says why", async () => {
  await withCwd(async (cwd) => {
    const S = stringsHeap(["x"]);
    const base = (t: Tables, name = "#~") => pe(metadataRoot([{ name, data: tablesStream(t) }, { name: "#Strings", data: S.buf }]).blob).file;
    const cases: [string, Buffer, RegExp][] = [
      ["#-", base({ rows: { 0x00: [row([2, 0], [2, 1], [2, 0], [2, 0], [2, 0])] } }, "#-"), /uses the #- stream/],
      ["enc-log", base({ rows: { 0x00: [row([2, 0], [2, 1], [2, 0], [2, 0], [2, 0])], 0x1e: [row([4, 1], [4, 2])] } }), /EncLog table, which exists only in an edit-and-continue stream/],
      ["fieldptr", base({ rows: { 0x03: [row([2, 1])] } }), /FieldPtr table/],
      ["delta", base({ heapSizes: 0x20, rows: { 0x00: [] } }), /delta bit \(0x20\)/],
      ["pdb", base({ rows: { 0x00: [] }, validExtra: 1n << 0x30n }), /table 0x30/],
    ];
    for (const [name, file, re] of cases) {
      const a = await answer(cwd, `${name.replace("#", "h")}.dll`, file);
      assert.equal(a.status, "partial", name);
      assert.equal(a.clr_tables.status, "unsupported", name);
      assert.match(a.clr_tables.reason, re, name);
      assert.ok(a.problems.some((p: string) => re.test(p)), `${name}: ${JSON.stringify(a.problems)}`);
      assert.equal(a.tables.clr_module, undefined, `${name}: no row of a stream that is refused`);
      assert.ok(a.clr, "the rest of the PE directories were still read");
    }
    const none = await answer(cwd, "nostream.dll", pe(metadataRoot([{ name: "#Strings", data: S.buf }]).blob).file);
    assert.match(none.clr_tables.reason, /no #~ table stream/);
  });
});

test("a metadata root that was not read, no CLR header and a stream header cut short make clr_tables a problem and never an empty list", async () => {
  await withCwd(async (cwd) => {
    const noClr = await answer(cwd, "noclr.dll", pe(Buffer.alloc(16), { noClr: true }).file);
    assert.equal(noClr.status, "partial");
    assert.equal(noClr.clr_tables.status, "no_clr_header");
    assert.ok(noClr.problems.some((p: string) => /clr_tables: no CLR runtime header is declared/.test(p)));
    const bad = await answer(cwd, "badroot.dll", pe(Buffer.concat([u32(0x11111111), Buffer.alloc(60)])).file);
    assert.equal(bad.clr_tables.status, "unavailable");
    assert.equal(bad.status, "partial");
    const asm = assembly().file;
    const cut = await answer(cwd, "cut.dll", asm.subarray(0, asm.length - 700));
    assert.equal(cut.status, "partial");
    assert.ok(cut.problems.length > 0);
  });
});

test("row counts the stream cannot hold, a valid mask that names more tables than it has counts for, and a table that runs past the stream are problems, bounded and fast", async () => {
  await withCwd(async (cwd) => {
    const S = stringsHeap(["x"]);
    const pe1 = (t: Tables) => pe(metadataRoot([{ name: "#~", data: tablesStream(t) }, { name: "#Strings", data: S.buf }]).blob).file;
    const t0 = Date.now();
    const huge = await answer(cwd, "huge.dll", pe1({ rows: { 0x01: [row([2, 0], [2, 1], [2, 1])] }, declared: { 0x0a: 0xffffffff } }));
    assert.ok(Date.now() - t0 < 10_000, `took ${Date.now() - t0} ms`);
    assert.equal(huge.status, "partial");
    assert.ok(huge.problems.some((p: string) => /the MemberRef table declares 4294967295 rows of 6 bytes/.test(p)), JSON.stringify(huge.problems));
    assert.ok(huge.problems.some((p: string) => /need \d+ bytes of table data and the #~ stream holds/.test(p)), JSON.stringify(huge.problems));
    assert.equal(rows(huge, "clr_typeref").length, 1, "the row that is there is read");
    const stream = tablesStream({ rows: { 0x01: [row([2, 0], [2, 1], [2, 1])] } });
    const mask = Buffer.from(stream);
    mask.writeBigUInt64LE((1n << 1n) | (1n << 2n) | (1n << 4n) | (1n << 6n), 8);       // four tables valid, one row count in the stream
    const m = await answer(cwd, "mask.dll", pe(metadataRoot([{ name: "#~", data: mask.subarray(0, 24 + 4) }, { name: "#Strings", data: S.buf }]).blob).file);
    assert.equal(m.status, "partial");
    assert.ok(m.problems.some((p: string) => /names 4 tables and the #~ stream is too short for their row counts/.test(p)), JSON.stringify(m.problems));
    const tiny = await answer(cwd, "tiny.dll", pe(metadataRoot([{ name: "#~", data: Buffer.alloc(10) }, { name: "#Strings", data: S.buf }]).blob).file);
    assert.ok(tiny.problems.some((p: string) => /shorter than its 24-byte header/.test(p)), JSON.stringify(tiny.problems));
  });
});

test("string, blob and GUID indexes past their heap, and a heap that runs past the metadata root, are problems and the row is still listed", async () => {
  await withCwd(async (cwd) => {
    const S = stringsHeap(["ok"]);
    const bad = row([2, 0], [2, 0x7fff], [2, 0x7fff], [2, 0x7fff], [2, 0x7fff]);                // Module: name, mvid, encid, encbaseid all outside their heaps
    const a = await answer(cwd, "idx.dll", pe(metadataRoot([{ name: "#~", data: tablesStream({ rows: { 0: [bad] } }) }, { name: "#Strings", data: S.buf }, { name: "#GUID", data: Buffer.alloc(16) }]).blob).file);
    assert.equal(a.status, "partial");
    assert.ok(a.problems.some((p: string) => /4 string, blob or GUID index\(es\) of the Module table point outside their heap/.test(p)), JSON.stringify(a.problems));
    assert.equal(rows(a, "clr_module")[0].name, null);
    assert.equal(rows(a, "clr_module")[0].mvid, null);
    // a heap whose declared size is larger than the root: the part inside the root is read, and the problem is named
    const md = metadataRoot([{ name: "#~", data: tablesStream({ rows: { 0: [row([2, 0], [2, 1], [2, 1], [2, 0], [2, 0])] } }) }, { name: "#Strings", data: S.buf }]);
    const lying = Buffer.from(md.blob);
    const at = lying.indexOf(Buffer.from("#Strings\0"));
    lying.writeUInt32LE(0x7fffff, at - 4);                                                       // the size field in the #Strings header
    const l = await answer(cwd, "lying.dll", pe(lying).file);
    assert.ok(l.problems.some((p: string) => /the #Strings heap \[\d+, \d+\) runs past the end of the metadata root/.test(p)), JSON.stringify(l.problems));
    assert.equal(rows(l, "clr_module")[0].name, "ok");
  });
});

test("the #US heap is walked with every length prefix checked: a prefix that runs past the heap, an invalid prefix and a 100-million-character entry end the walk with a problem and allocate nothing", async () => {
  await withCwd(async (cwd) => {
    const S = stringsHeap(["x"]);
    const tables = tablesStream({ rows: { 0: [row([2, 0], [2, 1], [2, 0], [2, 0], [2, 0])] } });
    const mk = (us: Buffer) => pe(metadataRoot([{ name: "#~", data: tables }, { name: "#Strings", data: S.buf }, { name: "#US", data: us }]).blob).file;
    const good = usHeap(["a", "bc"]).buf;
    const cases: [string, Buffer, RegExp, number][] = [
      ["past", Buffer.concat([good, Buffer.from([0x81, 0xff, 1, 2, 3])]), /declares 511 bytes and the heap ends/, 2],
      ["invalid", Buffer.concat([good, Buffer.from([0xff, 1, 2, 3])]), /length prefix at offset \d+ that is not valid/, 2],
      ["huge", Buffer.concat([good, Buffer.from([0xdf, 0xff, 0xff, 0xff, 1, 2, 3, 4])]), /declares 536870911 bytes and the heap ends/, 2],
    ];
    for (const [name, us, re, listed] of cases) {
      const a = await answer(cwd, `us-${name}.dll`, mk(us));
      assert.equal(a.status, "partial", name);
      assert.ok(a.problems.some((p: string) => re.test(p)), `${name}: ${JSON.stringify(a.problems)}`);
      assert.equal(a.clr_tables.user_strings.listed, listed, name);
    }
    const long = usHeap(["x".repeat(3000)]);
    const a = await answer(cwd, "us-long.dll", mk(long.buf));
    assert.match(rows(a, "clr_user_strings")[0].string, /^<a string of 3000 characters: longer than the 2048 shown, so not shown>$/);
  });
});

const CANARY = "AKIAIOSFODNN7EXAMPLE";
const JWT = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U";

test("a token-shaped assembly name, type name and user string is withheld in the answer and in every file, and an ordinary name stays readable", async () => {
  await withCwd(async (cwd) => {
    const r = await run(cwd, "canary.dll", assembly({ names: { assembly: CANARY, typeref: JWT }, user: [`password=${JWT}`, CANARY, "Hello"] }).file, { limit: 1 });
    assert.equal(r.code, 0, r.stderr);
    for (const secret of [CANARY, JWT]) assert.ok(!r.stdout.includes(secret), `the answer prints ${secret.slice(0, 8)}...`);
    const files = await filesUnder(join(cwd, "work/s1/tool-output"));
    assert.ok(files.some((f) => f.includes("clr_user_strings")) && files.some((f) => f.includes("clr_typeref")), files.join());
    for (const f of files) {
      const content = await readFile(join(cwd, "work/s1/tool-output", f), "utf8");
      for (const secret of [CANARY, JWT]) assert.ok(!content.includes(secret) || f.includes("withheld-names"), `${f} prints ${secret.slice(0, 8)}`);
    }
    const a = JSON.parse(r.stdout) as Json;
    assert.ok(a.withheld.names + a.withheld.text > 0);
    assert.equal(rows(a, "clr_module")[0].name, "Test.dll", "an ordinary name stays readable");
  });
});

test("a table of half a million rows is read under the clock: max_seconds 1 ends within seconds, and the count equals the rows in the file", async () => {
  await withCwd(async (cwd) => {
    const S = stringsHeap(["n"]);
    const one = row([2, 5], [2, S.at.n!], [2, 1]);
    const t = tablesStream({ rows: { 0x0a: Array(500_000).fill(one) } });
    const t0 = Date.now();
    const a = await answer(cwd, "big.dll", pe(metadataRoot([{ name: "#~", data: t }, { name: "#Strings", data: S.buf }]).blob).file, { max_seconds: 1, limit: 3 });
    assert.ok(Date.now() - t0 < 20_000, `took ${Date.now() - t0} ms`);
    assert.ok(["partial", "complete"].includes(a.status));
    const file = (await filesUnder(join(cwd, "work/s1/tool-output"))).find((f) => f.includes("clr_memberref"));
    assert.ok(file);
    const lines = (await readFile(join(cwd, "work/s1/tool-output", file!), "utf8")).trim().split("\n").length;
    assert.equal(a.tables.clr_memberref.matched, lines, "the count equals what the file holds");
    if (a.status === "partial") assert.ok(a.limits_hit.some((l: string) => /max_seconds/.test(l)), JSON.stringify(a.limits_hit));
  });
});

test("a stream declared twice is read once, from the first, and the second is a problem", async () => {
  await withCwd(async (cwd) => {
    const S = stringsHeap(["first"]);
    const other = stringsHeap(["second"]);
    const t = tablesStream({ rows: { 0: [row([2, 0], [2, 1], [2, 0], [2, 0], [2, 0])] } });
    const a = await answer(cwd, "dup.dll", pe(metadataRoot([{ name: "#~", data: t }, { name: "#Strings", data: S.buf }, { name: "#Strings", data: other.buf }]).blob).file);
    assert.equal(a.status, "partial");
    assert.ok(a.problems.some((p: string) => /the stream #Strings is declared more than once: the first is read/.test(p)), JSON.stringify(a.problems));
    assert.equal(rows(a, "clr_module")[0].name, "first");
  });
});

test("clr_tables must be a boolean", async () => {
  await withCwd(async (cwd) => {
    const r = await run(cwd, "x.dll", assembly().file, { clr_tables: "yes" });
    assert.notEqual(r.code, 0);
    assert.equal((JSON.parse(r.stdout) as Json).status, "failed");
  });
});

const haveCompiler = spawnSync("sh", ["-c", "command -v mcs || command -v csc"]).status === 0;
test("agreement with a C# compiler's own output where one exists", { skip: haveCompiler ? false : "no C# compiler (mcs or csc) is installed on this machine; not verified here" }, async () => {
  await withCwd(async (cwd) => {
    await put(cwd, "work/p.cs", "class Program { static void Main() { System.Console.WriteLine(\"hi\"); } }\n");
    const cc = spawnSync("sh", ["-c", "(command -v mcs && mcs -out:work/p.exe work/p.cs) || (csc -out:work/p.exe work/p.cs)"], { cwd, encoding: "utf8" });
    if (cc.status !== 0) return;
    const r = await tool(PE_DIRECTORIES, cwd, { path: "work/p.exe", clr_tables: true });
    const a = JSON.parse(r.stdout) as Json;
    assert.equal(a.clr_tables.status, "read", JSON.stringify(a.problems));
    assert.ok(rows(a, "clr_typedef").some((x) => x.name === "Program"));
    assert.equal(rows(a, "clr_module")[0].name, "p.exe");
  });
});

test("a #Strings entry longer than the 4,096 bytes read, and one with no terminator, are problems and the answer is partial, with no length stated that was not seen", async () => {
  await withCwd(async (cwd) => {
    const a = await answer(cwd, "longname.dll", assembly({ names: { assembly: "N".repeat(9000) } }).file);
    assert.equal(a.status, "partial");
    assert.ok(a.problems.some((p: string) => /clr name at file offset \d+ has no terminator within its table or 4096 bytes/.test(p)), JSON.stringify(a.problems));
    assert.match(rows(a, "clr_assembly")[0].name, /^<a string of at least 4096 characters, cut where it was read: longer than the 512 shown, so not shown>$/);
    const b = await answer(cwd, "ok600.dll", assembly({ names: { assembly: "word_".repeat(120) } }).file);
    assert.equal(b.status, "complete", JSON.stringify(b.problems));
    assert.equal(rows(b, "clr_assembly")[0].name, "<a name of 600 characters: longer than the 512 shown, so not shown>");
  });
});
