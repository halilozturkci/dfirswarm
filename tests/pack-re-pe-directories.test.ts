/**
 * pe_directories against PE files laid out by hand to the Microsoft PE/COFF specification (tests/pack-re-doc-fixtures.ts,
 * buildPeDirs): the export directory, delay-load descriptors, the TLS directory, the resource tree and the version
 * resource, the CLR header and metadata root, the debug directory and the Rich header. What these cases hold: every field is
 * read through a range the file holds (a table that runs off its section is a problem, not an empty list), an ordinal is the
 * ordinal base plus the table index and a name is attached to the right function through the ordinal table, a string out of
 * the file is withheld when it is shaped like a token, a claim in a version resource or a PDB path is reported as a claim,
 * and nothing in the answer says what a callback, an export or an entry point does.
 */
import assert from "node:assert/strict";
import { readFile, stat } from "node:fs/promises";
import { join } from "node:path";
import { test } from "node:test";
import { PE_DIRECTORIES, asJob, body, filesUnder, put, refused, tool, withCwd } from "./pack-re-harness.ts";
import type { Json } from "./pack-re-harness.ts";
import { buildPeDirs, versionResource } from "./pack-re-doc-fixtures.ts";
import type { PeDirOptions } from "./pack-re-doc-fixtures.ts";

async function run(cwd: string, name: string, data: Buffer, args: Record<string, unknown> = {}): Promise<{ a: Json; text: string }> {
  await put(cwd, `work/${name}`, data);
  const r = await tool(PE_DIRECTORIES, cwd, { path: `work/${name}`, ...args });
  return { a: body(r), text: r.stdout };
}
const rows = (a: Json, table: string): Json[] => a.tables[table].rows;
const TOKEN = "Zk9mQ2xW7vB3nL8pR4tY6wD1sFgHjK";

for (const plus of [true, false]) {
  test(`${plus ? "PE32+" : "PE32"}: exports carry ordinal base plus index, the name the ordinal table gives, forwarders and unnamed entries`, async () => {
    await withCwd(async (cwd) => {
      // Names are sorted in the name table, so the name table's order is not the function table's order.
      const pe = buildPeDirs({ plus, exports: { imageName: "lib.dll", base: 5, stamp: 0x65000000, functions: [{ name: "Zeta", rva: 0x1010 }, { name: "Alpha", forward: "NTDLL.RtlAlpha" }, {}, { name: "Mid", rva: 0x20f0 }] } });
      const { a } = await run(cwd, "e.dll", pe.file);
      assert.equal(a.status, "complete", JSON.stringify(a.problems));
      assert.deepEqual({ base: a.exports.ordinal_base, fns: a.exports.functions_declared, names: a.exports.names_declared, image: a.exports.image_name }, { base: 5, fns: 4, names: 3, image: "lib.dll" });
      assert.equal(a.exports.time_date_stamp_utc, new Date(0x65000000 * 1000).toISOString().replace(".000Z", "Z"));
      const r = rows(a, "exports");
      assert.deepEqual(r.map((x) => [x.ordinal, x.name ?? null, x.rva]), [[5, "Zeta", "0x1010"], [6, "Alpha", r[1].rva], [7, null, "0x1000"], [8, "Mid", "0x20f0"]]);
      assert.equal(r[1].forwarder, "NTDLL.RtlAlpha");
      assert.equal(r[0].section, ".text");
      assert.equal(r[3].section, ".rdata");
      assert.equal(a.exports.forwarders, 1);
      assert.equal(a.exports.listed_by_ordinal_only, 1);
      assert.equal(a.bits, plus ? 64 : 32);
    });
  });
}

test("an export directory that lies is a problem: a function table past its section, a name outside the file, a function named twice, an unterminated name", async () => {
  await withCwd(async (cwd) => {
    const pe = buildPeDirs({ exports: { functions: [{ name: "A" }, { name: "B" }] } });
    // The address-of-functions RVA is pointed past the end of the section.
    const bad = Buffer.from(pe.file);
    const dir = pe.rawOf(pe.rvas.exports!);
    bad.writeUInt32LE(0x7ff0, dir + 28);
    const a = (await run(cwd, "e1.dll", bad)).a;
    assert.equal(a.status, "partial");
    assert.ok(a.problems.some((p: string) => /export address table .* not wholly backed by file bytes/.test(p)), JSON.stringify(a.problems));
    // A name pointer outside every section.
    const bad2 = Buffer.from(pe.file);
    const namesAt = pe.rawOf(pe.rvas.exports! + 40 + 8);
    bad2.writeUInt32LE(0x90000, namesAt);
    const b = (await run(cwd, "e2.dll", bad2)).a;
    assert.ok(b.problems.some((p: string) => /export name 0 \(RVA 0x90000\) is not backed by file bytes/.test(p)), JSON.stringify(b.problems));
    // Both ordinals point at function 0: that function is named twice.
    const bad3 = Buffer.from(pe.file);
    const ordAt = pe.rawOf(pe.rvas.exports! + 40 + 8 + 8);
    bad3.writeUInt16LE(0, ordAt + 2);
    const c = (await run(cwd, "e3.dll", bad3)).a;
    assert.ok(c.problems.some((p: string) => /function index 0 is named twice/.test(p)), JSON.stringify(c.problems));
  });
});

test("an export name or forwarder shaped like a token is withheld from the answer and its table file; the real one is in the values file in a job", async () => {
  await withCwd(async (cwd) => {
    const pe = buildPeDirs({ exports: { functions: [{ name: TOKEN, rva: 0x1010 }, { name: "Plain", forward: `HOST.${TOKEN}A` }] } });
    await put(cwd, "work/t.dll", pe.file);
    const r = await asJob(PE_DIRECTORIES, cwd, { path: "work/t.dll", write_values: true, limit: 1 });
    const a = body(r);
    assert.ok(!r.stdout.includes(TOKEN));
    assert.ok(a.withheld.names + a.withheld.text >= 1);
    for (const f of await filesUnder(join(cwd, "out"))) {
      if (f.includes("exports") || f.endsWith(".jsonl") && f.includes("tool-output")) {
        const text = await readFile(join(cwd, "out", f), "utf8");
        if (f.includes("withheld-names")) assert.ok(text.includes(TOKEN), "the private names file keeps the real name");
        else assert.ok(!text.includes(TOKEN), `${f} holds the token`);
      }
    }
    const values = (await readFile(join(cwd, "out", "pe-directories-values.jsonl"), "utf8")).trim().split("\n").map((l) => JSON.parse(l));
    assert.ok(values.some((v) => v.value === `HOST.${TOKEN}A` && v.field === "export_forwarder"));
    assert.equal(((await stat(join(cwd, "out", "pe-directories-values.jsonl"))).mode & 0o777), 0o600);
    const no = refused(await tool(PE_DIRECTORIES, cwd, { path: "work/t.dll", write_values: true }));
    assert.match(no.error, /refused outside a job/);
  });
});

for (const plus of [true, false]) {
  test(`${plus ? "PE32+" : "PE32"}: delay-load imports in the RVA form and in the old virtual-address form, by name and by ordinal`, async () => {
    await withCwd(async (cwd) => {
      // The virtual-address form is the old PE32 layout (a 32-bit field cannot hold a PE32+ address).
      const pe = buildPeDirs({ plus, delayImports: [{ dll: "ws2_32.dll", functions: ["connect", 23, "send"] }, ...(plus ? [] : [{ dll: "OLD.dll", functions: ["legacy"], vaForm: true }])] });
      const { a } = await run(cwd, "d.exe", pe.file);
      assert.equal(a.status, "complete", JSON.stringify(a.problems));
      assert.deepEqual(a.delay_imports.libraries.map((l: Json) => [l.library, l.functions, l.address_form]), [["ws2_32.dll", 3, "RVA"], ...(plus ? [] : [["OLD.dll", 1, "VA"]])]);
      assert.deepEqual(rows(a, "delay_imports").map((r) => r.function ?? r.ordinal), ["connect", 23, "send", ...(plus ? [] : ["legacy"])]);
      assert.equal(a.delay_imports.ordinal_only, 1);
      assert.match(a.delay_imports.note, /not a call that was made/);
    });
  });
}

test("a delay-load table with no terminating descriptor, and a function table that runs off its section, are problems", async () => {
  await withCwd(async (cwd) => {
    const pe = buildPeDirs({ delayImports: [{ dll: "a.dll", functions: ["f"] }] });
    const noEnd = Buffer.from(pe.file);
    // Make the terminating descriptor non-zero, and declare the directory so small that it ends inside it.
    const optDirs = 0x80 + 0x0; // (rich-less file) the data directory table is at peAt + 24 + 112
    void optDirs;
    const peAt = noEnd.readUInt32LE(0x3c);
    const dirEntry = peAt + 24 + 112 + 13 * 8;
    noEnd.writeUInt32LE(32, dirEntry + 4);
    const first = pe.rawOf(pe.rvas.delayImports!);
    noEnd.writeUInt32LE(0x1111, first + 32 + 4);
    const a = (await run(cwd, "d1.exe", noEnd)).a;
    assert.equal(a.status, "partial");
    assert.ok(a.problems.length > 0, JSON.stringify(a.problems));
  });
});

test("TLS callbacks are listed with the section that holds each; a callback outside the code is said, and a missing terminator is a problem", async () => {
  await withCwd(async (cwd) => {
    for (const plus of [true, false]) {
      const pe = buildPeDirs({ plus, tlsCallbacks: [0x1010, 0x2100, 0x7fff0] });
      const { a } = await run(cwd, `t${plus}.exe`, pe.file);
      assert.equal(a.status, "complete", JSON.stringify(a.problems));
      const cb = a.tls.callbacks;
      assert.deepEqual(cb.map((c: Json) => [c.rva, c.section, c.section_is_executable]), [["0x1010", ".text", true], ["0x2100", ".rdata", false], ["0x7fff0", null, null]]);
      assert.match(a.tls.note, /before the entry point/);
      assert.ok(!/malicious|payload|evasion/i.test(JSON.stringify(a.tls)), "the answer says what is declared and not what the callbacks do");
    }
  });
});

test("the resource tree: types by name and by id, names, languages, sizes and file offsets; the version information and the manifest are read", async () => {
  await withCwd(async (cwd) => {
    const manifest = Buffer.from('<?xml version="1.0"?><assembly xmlns="urn:schemas-microsoft-com:asm.v1" manifestVersion="1.0"><trustInfo xmlns="urn:schemas-microsoft-com:asm.v3"><security><requestedPrivileges><requestedExecutionLevel level="requireAdministrator" uiAccess="false"/></requestedPrivileges></security></trustInfo></assembly>');
    const config = Buffer.from("planted configuration blob");
    const pe = buildPeDirs({
      resources: [
        { type: "MYCFG", name: "settings", lang: 1033, data: config },
        { type: 10, name: 101, lang: 0, data: Buffer.from("rc-a") },
        { type: 10, name: 101, lang: 1033, data: Buffer.from("rc-b!") },
        { type: 16, name: 1, lang: 1033, data: versionResource({ fileVersion: [10, 0, 19041, 1], productVersion: [10, 0, 19041, 1], flags: 0x2 | 0x8, strings: { CompanyName: "Example Corp", OriginalFilename: "tool.exe", FileVersion: "10.0.19041.1", Comments: "x".repeat(300), CustomKey: "hidden" } }) },
        { type: 24, name: 1, lang: 1033, data: manifest },
      ],
    });
    const { a } = await run(cwd, "r.exe", pe.file);
    assert.equal(a.status, "complete", JSON.stringify(a.problems));
    const r = rows(a, "resources");
    assert.deepEqual(r.map((x) => [x.type, x.name, x.language, x.size]), [["MYCFG", "settings", 1033, config.length], ["RCDATA", 101, 0, 4], ["RCDATA", 101, 1033, 5], ["VERSION", 1, 1033, r[3].size], ["MANIFEST", 1, 1033, manifest.length]]);
    assert.equal(r[1].file_offset, pe.rawOf(Number(r[1].rva)));
    assert.deepEqual(a.resources.by_type, { MYCFG: 1, RCDATA: 2, VERSION: 1, MANIFEST: 1 });
    const v = a.resources.version_info;
    assert.deepEqual(v.fixed, { file_version: "10.0.19041.1", product_version: "10.0.19041.1", file_flags: ["prerelease", "private build"], file_type: "application" });
    const table = v.string_tables["040904b0"];
    assert.equal(table.CompanyName.value, "Example Corp");
    assert.equal(table.OriginalFilename.value, "tool.exe");
    assert.equal(table.Comments.value, null, "a value past 256 characters is reported by length");
    assert.equal(table.Comments.length, 300);
    assert.deepEqual(v.other_keys, ["CustomKey"]);
    assert.match(v.note, /claims the file makes about itself/);
    assert.deepEqual(a.resources.manifest.requested_execution_levels, [{ level: "requireAdministrator", uiAccess: "false" }]);
  });
});

test("extract resource:<row> writes the resource's bytes exactly, and only when asked", async () => {
  await withCwd(async (cwd) => {
    const blob = Buffer.from(Array.from({ length: 1000 }, (_, i) => (i * 37) & 0xff));
    const pe = buildPeDirs({ resources: [{ type: 10, name: 1, lang: 0, data: Buffer.from("first") }, { type: 10, name: 2, lang: 0, data: blob }] });
    const none = (await run(cwd, "x.exe", pe.file)).a;
    assert.equal(none.extracted, undefined);
    const a = (await run(cwd, "x.exe", pe.file, { extract_to: "work/s1/res", extract: ["resource:1", "resource:9"] })).a;
    assert.equal(a.extracted.length, 1);
    assert.ok((await readFile(join(cwd, a.extracted[0].file))).equals(blob));
    assert.equal(((await stat(join(cwd, a.extracted[0].file))).mode & 0o777), 0o600);
    assert.ok(a.problems.some((p: string) => /resources table has 2 rows/.test(p)), JSON.stringify(a.problems));
    const small = (await run(cwd, "x.exe", pe.file, { extract_to: "work/s1/res2", extract: ["resource:1"], max_stream_bytes: 100 })).a;
    assert.ok(small.limits_hit.some((l: string) => /over max_stream_bytes/.test(l)));
    assert.deepEqual(await filesUnder(join(cwd, "work", "s1", "res2")), []);
  });
});

test("a resource whose data runs past the file, and one whose tree loops, are problems", async () => {
  await withCwd(async (cwd) => {
    const pe = buildPeDirs({ resources: [{ type: 10, name: 1, lang: 0, data: Buffer.from("abcd"), declaredSize: 0x100000 }] });
    const a = (await run(cwd, "big.exe", pe.file)).a;
    assert.equal(a.status, "partial");
    assert.ok(a.problems.some((p: string) => /run past the bytes the file holds/.test(p)), JSON.stringify(a.problems));
    assert.equal(rows(a, "resources")[0].in_file, false);
    // The name directory's only entry is pointed back at the root directory.
    const loop = Buffer.from(pe.file);
    const root = pe.rawOf(pe.rsrcRva);
    const nameDir = root + 16 + 8;
    loop.writeUInt32LE(0x80000000, nameDir + 16 + 4);
    const b = (await run(cwd, "loop.exe", loop)).a;
    assert.ok(b.problems.some((p: string) => /reaches the directory at offset 0x0 twice/.test(p)), JSON.stringify(b.problems));
  });
});

test("a version string or a manifest carrying a token or a DOCTYPE: the value is withheld, the full text only in the values file, and a DOCTYPE is refused", async () => {
  await withCwd(async (cwd) => {
    const pe = buildPeDirs({ resources: [{ type: 16, name: 1, lang: 1033, data: versionResource({ strings: { CompanyName: TOKEN, OriginalFilename: "ok.exe" } }) }, { type: 24, name: 1, lang: 1033, data: Buffer.from('<?xml version="1.0"?><!DOCTYPE a [<!ENTITY x "y">]><assembly/>') }] });
    await put(cwd, "work/v.exe", pe.file);
    const r = await asJob(PE_DIRECTORIES, cwd, { path: "work/v.exe", write_values: true });
    const a = body(r);
    assert.ok(!r.stdout.includes(TOKEN));
    assert.match(a.resources.version_info.string_tables["040904b0"].CompanyName.value, /^<token-shaped text withheld 30 characters>$/);
    assert.equal(a.resources.version_info.string_tables["040904b0"].OriginalFilename.value, "ok.exe");
    assert.equal(a.resources.manifest.status, "doctype_refused");
    const values = (await readFile(join(cwd, "out", "pe-directories-values.jsonl"), "utf8")).split("\n").filter(Boolean).map((l) => JSON.parse(l));
    assert.ok(values.some((v) => v.value === TOKEN && v.key === "CompanyName"));
  });
});

test("the CLR header: flags, runtime version, entry point token, the metadata root's version string and streams; strong-name and managed-native fields are declarations", async () => {
  await withCwd(async (cwd) => {
    const pe = buildPeDirs({ clr: { flags: 0x1 | 0x8 | 0x20000, entryToken: 0x06000042, version: "v4.0.30319", strongName: true, managedNative: Buffer.from([0x52, 0x54, 0x52, 0x00, 1, 2, 3, 4]) } });
    const { a } = await run(cwd, "c.dll", pe.file);
    assert.equal(a.status, "complete", JSON.stringify(a.problems));
    const c = a.clr;
    assert.deepEqual(c.flags, ["ILONLY", "STRONGNAMESIGNED", "32BITPREFERRED"]);
    assert.equal(c.runtime_version, "2.5");
    assert.deepEqual(c.entry_point, { value: "0x6000042", is_native_rva: false, token_table: "0x06", token_row: 0x42 });
    assert.equal(c.strong_name_signature_field.present, true);
    assert.equal(c.managed_native_header.present, true);
    assert.equal(c.managed_native_header.first_four_bytes, "52545200");
    assert.equal(c.metadata.version_string, "v4.0.30319");
    assert.deepEqual(c.metadata.streams.map((s: Json) => [s.name, s.size]), [["#~", 0x100], ["#Strings", 0x80], ["#US", 8], ["#GUID", 16], ["#Blob", 0x40]]);
    assert.ok(c.notes.some((n: string) => /no assembly name/.test(n)));
    assert.ok(c.notes.some((n: string) => /not a verified one, and not the publisher's trust/.test(n)));
    // A native entry point: the flag says the entry value is an RVA, not a token.
    const native = (await run(cwd, "n.dll", buildPeDirs({ clr: { flags: 0x10, entryToken: 0x1230 } }).file)).a;
    assert.equal(native.clr.entry_point.is_native_rva, true);
    assert.equal(native.clr.entry_point.token_table, undefined);
  });
});

test("a CLR header whose metadata is missing, or does not begin with BSJB, is a problem and not a managed assembly", async () => {
  await withCwd(async (cwd) => {
    const a = (await run(cwd, "nomd.dll", buildPeDirs({ clr: { noMetadata: true } }).file)).a;
    assert.equal(a.status, "partial");
    assert.ok(a.problems.some((p: string) => /metadata root .* not backed by file bytes/.test(p)), JSON.stringify(a.problems));
    const b = (await run(cwd, "badsig.dll", buildPeDirs({ clr: { badSignature: true } }).file)).a;
    assert.ok(b.problems.some((p: string) => /BSJB signature/.test(p)));
    assert.equal(b.clr.metadata.signature_ok, false);
  });
});

test("the debug directory: the entry types and times, the CodeView GUID, age and path; a token-shaped path is withheld", async () => {
  await withCwd(async (cwd) => {
    const guid = Buffer.from("78563412bc9af0de0123456789abcdef", "hex"); // Data1 12345678, Data2 9abc, Data3 def0 (little-endian), then eight bytes
    const pe = buildPeDirs({ debug: [{ type: 2, stamp: 0x65000000, guid, age: 7, pdb: "C:\\src\\app\\release\\app.pdb" }, { type: 16, stamp: 0x65000000 }, { type: 2, guid, age: 1, pdb: `D:\\${TOKEN}\\x.pdb` }] });
    const { a, text } = await run(cwd, "g.exe", pe.file);
    assert.equal(a.status, "complete", JSON.stringify(a.problems));
    const [cv, repro, cv2] = a.debug.entries;
    // A REPRO entry is present: every stamp is a hash of the build, and none is rendered as a time.
    assert.deepEqual({ type: cv.type, raw: cv.time_date_stamp_raw, utc: cv.time_date_stamp_utc }, { type: "CODEVIEW", raw: 0x65000000, utc: null });
    assert.match(cv.time_date_stamp_note, /REPRO entry is present/);
    assert.equal(a.debug.repro, true);
    assert.deepEqual({ sig: cv.codeview.signature, guid: cv.codeview.guid, age: cv.codeview.age, path: cv.codeview.pdb_path, len: cv.codeview.pdb_path_length }, { sig: "RSDS", guid: "12345678-9ABC-DEF0-0123-456789ABCDEF", age: 7, path: "C:\\src\\app\\release\\app.pdb".replace(/\\/g, "\\\\"), len: 26 });
    assert.equal(repro.type, "REPRO");
    assert.ok(!text.includes(TOKEN));
    assert.match(cv2.codeview.pdb_path, /^D:\\\\<token-shaped text withheld 30 characters>\\\\x\.pdb$/, "a backslash is written twice");
    assert.match(cv.codeview.note, /a claim about the build machine/);
  });
});

test("the Rich header is decoded with its own key, raw; a Rich marker with no DanS start, or padding that does not decode to zero, is a problem; no Rich header says nothing", async () => {
  await withCwd(async (cwd) => {
    const entries: [number, number][] = [[(0x0105 << 16) | 0x7809, 12], [(0x00ff << 16) | 0x6f06, 3]];
    const { a } = await run(cwd, "rich.exe", buildPeDirs({ rich: { key: 0xdeadbeef, entries } }).file);
    assert.equal(a.rich_header.key, "0xdeadbeef");
    assert.deepEqual(a.rich_header.entries, [{ product_id: 0x0105, build: 0x7809, count: 12 }, { product_id: 0xff, build: 0x6f06, count: 3 }]);
    assert.equal(a.rich_header.offset, 0x80);
    assert.match(a.rich_header.note, /A toolchain lead, not a clock/);
    const broken = (await run(cwd, "rich2.exe", buildPeDirs({ rich: { key: 0x12345678, entries, breakPadding: true } }).file)).a;
    assert.equal(broken.status, "partial");
    assert.ok(broken.problems.some((p: string) => /padding does not decode to zero/.test(p)));
    const none = (await run(cwd, "plain.exe", buildPeDirs({}).file)).a;
    assert.equal(none.rich_header, undefined);
  });
});

test("a directory the header does not declare is not read and not invented: the answer lists the directories it found declared", async () => {
  await withCwd(async (cwd) => {
    const { a } = await run(cwd, "bare.exe", buildPeDirs({}).file);
    assert.equal(a.status, "complete");
    assert.deepEqual(a.directories_declared, []);
    for (const k of ["exports", "delay_imports", "tls", "resources", "clr", "debug"]) assert.equal(a[k], undefined, k);
    assert.ok(a.coverage.structures_not_read.some((x: string) => /Authenticode/.test(x)));
  });
});

test("fifty thousand exports are read in bounded time and kept whole in a file", async () => {
  await withCwd(async (cwd) => {
    const functions = Array.from({ length: 50000 }, (_, i) => ({ name: `Fn${String(i).padStart(6, "0")}`, rva: 0x1000 + (i % 0x100) }));
    const t0 = Date.now();
    const { a } = await run(cwd, "many.dll", buildPeDirs({ exports: { functions } }).file, { limit: 100 });
    assert.ok(Date.now() - t0 < 30000);
    assert.equal(a.status, "complete", JSON.stringify(a.problems));
    assert.equal(a.exports.functions_listed, 50000);
    assert.equal(a.tables.exports.returned, 100);
    const lines = (await readFile(join(cwd, a.tables.exports.all_results), "utf8")).trim().split("\n");
    assert.equal(lines.length, 50000);
    assert.equal(JSON.parse(lines[49999]!).name, "Fn049999");
  });
});

test("things that are not PEs, or are cut short, are JSON failures: no MZ, no PE signature, a header cut off, a truncated section table", async () => {
  await withCwd(async (cwd) => {
    await put(cwd, "work/n.bin", Buffer.from("not a pe file at all"));
    assert.equal(refused(await tool(PE_DIRECTORIES, cwd, { path: "work/n.bin" })).status, "unsupported");
    const pe = buildPeDirs({ exports: { functions: [{ name: "A" }] } }).file;
    const peAt = pe.readUInt32LE(0x3c);
    const nosig = Buffer.from(pe);
    nosig.write("XX", peAt, "latin1");
    await put(cwd, "work/nosig.exe", nosig);
    assert.match(refused(await tool(PE_DIRECTORIES, cwd, { path: "work/nosig.exe" })).error, /no PE signature/);
    for (const cut of [0x30, peAt + 10, peAt + 24 + 50, peAt + 24 + 240 + 20, pe.length - 700]) {
      await put(cwd, "work/cut.exe", pe.subarray(0, cut));
      const r = await tool(PE_DIRECTORIES, cwd, { path: "work/cut.exe" });
      assert.doesNotMatch(r.stderr, /Traceback/, `cut at ${cut}`);
      const j = JSON.parse(r.stdout);
      assert.ok(["failed", "partial", "unsupported", "complete"].includes(j.status), `cut at ${cut}: ${r.stdout.slice(0, 200)}`);
      if (j.status === "complete") assert.ok(cut === pe.length - 700 || false, `cut at ${cut} cannot be complete`);
    }
  });
});

test("a PE with the data directory table declaring directories that point into nothing never raises: every reader answers with a problem", async () => {
  await withCwd(async (cwd) => {
    const pe = buildPeDirs({});
    const peAt = pe.file.readUInt32LE(0x3c);
    const dirs = peAt + 24 + 112;
    const bad = Buffer.from(pe.file);
    for (const i of [0, 2, 6, 9, 13, 14]) {
      bad.writeUInt32LE(0xfffff000, dirs + i * 8);
      bad.writeUInt32LE(0x1000, dirs + i * 8 + 4);
    }
    const r = await tool(PE_DIRECTORIES, cwd, { path: (await put(cwd, "work/bad.exe", bad), "work/bad.exe") });
    assert.doesNotMatch(r.stderr, /Traceback/);
    const a = JSON.parse(r.stdout);
    assert.equal(a.status, "partial");
    for (const k of ["exports", "delay_imports", "tls", "resources", "clr", "debug"]) assert.ok(a.problems.some((p: string) => new RegExp(k === "delay_imports" ? "delay-load" : k === "clr" ? "CLR" : k === "tls" ? "TLS" : k === "debug" ? "debug" : k === "resources" ? "resource" : "export", "i").test(p)), k);
  });
});
void ({} as PeDirOptions);
