/**
 * doc_structure, the OLE compound file and OOXML/ZIP halves, against fixtures built from the specifications
 * (tests/pack-re-doc-fixtures.ts: [MS-CFB], [MS-OVBA], [MS-OFFCRYPTO], [MS-DOC], [MS-XLS], [MS-PPT]) and never from the
 * tool's own output. What these cases hold: the directory is read whole, orphan and looping entries are said, every sector
 * chain is bounded, a VBA project is listed (names, stream sizes, compressed and decompressed source sizes) with its source
 * written out only on request and exactly, the encryption structures are reported as scheme, algorithm and key size and a
 * salt, verifier, hash or protection value that a structure holds is in no answer and no file the answer names, and a
 * budget that is reached is a limit and a partial status.
 */
import assert from "node:assert/strict";
import { readFile, stat } from "node:fs/promises";
import { join } from "node:path";
import { test } from "node:test";
import { DOC_STRUCTURE, asJob, body, buildZip, everythingUnder, filesUnder, put, refused, tool, withCwd } from "./pack-re-harness.ts";
import type { Json, ZipEntry } from "./pack-re-harness.ts";
import { OVBA_COPY_CHUNK, agileEncryptionInfo, buildCfb, buildVbaProject, currentUser, excelWorkbook, filetime, ovbaCompress, sectorAt, standardEncryptionInfo, wordFib } from "./pack-re-doc-fixtures.ts";
import { u16, u32 } from "./pack-re-harness.ts";

async function run(cwd: string, name: string, data: Buffer | string, args: Record<string, unknown> = {}, env: Record<string, string> = {}): Promise<Json> {
  await put(cwd, `work/${name}`, data);
  return body(await tool(DOC_STRUCTURE, cwd, { path: `work/${name}`, ...args }, env));
}

async function runJob(cwd: string, name: string, data: Buffer | string, args: Record<string, unknown> = {}): Promise<{ answer: Json; text: string }> {
  await put(cwd, `work/${name}`, data);
  const out = await asJob(DOC_STRUCTURE, cwd, { path: `work/${name}`, ...args });
  return { answer: body(out), text: out.stdout };
}

const rowsByPath = (answer: Json, table = "ole_directory"): Record<string, Json> => Object.fromEntries(answer.tables[table].rows.map((r: Json) => [r.path, r]));
const WORD_CLSID = Buffer.from("0609020000000000c000000000000046", "hex"); // {00020906-0000-0000-C000-000000000046}, stored as the spec's mixed-endian GUID
const WHEN = Date.UTC(2024, 4, 17, 10, 30, 15, 250);

// --- the directory --------------------------------------------------------------------------------------------------------

for (const major of [3, 4] as const) {
  test(`version ${major}: every directory entry is listed with its size, start sector, class id and times, and mini and regular streams are told apart by size`, async () => {
    await withCwd(async (cwd) => {
      const cfb = buildCfb(
        [
          { name: "small", data: Buffer.from("hello") },
          { name: "big", data: Buffer.alloc(9000, 1), modified: filetime(WHEN) },
          { name: "Storage", clsid: WORD_CLSID, created: filetime(WHEN), children: [{ name: "inner", data: Buffer.alloc(100, 2) }, { name: "empty", data: Buffer.alloc(0) }] },
        ],
        { major, rootClsid: WORD_CLSID, rootModified: filetime(WHEN) },
      );
      const a = await run(cwd, "plain.bin", cfb);
      assert.equal(a.status, "complete", JSON.stringify(a.problems));
      assert.equal(a.container, "OLE compound file");
      assert.equal(a.cfb.major_version, major);
      assert.equal(a.cfb.sector_bytes, major === 3 ? 512 : 4096);
      assert.equal(a.cfb.mini_stream_cutoff, 4096);
      const rows = rowsByPath(a);
      assert.deepEqual(Object.keys(rows).sort(), ["", "Storage", "Storage/empty", "Storage/inner", "big", "small"]);
      assert.equal(rows["small"].size, 5);
      assert.equal(rows["big"].size, 9000);
      assert.equal(rows["Storage/inner"].size, 100);
      assert.equal(rows["Storage/empty"].size, 0);
      assert.equal(rows["Storage"].type, "storage");
      assert.equal(rows["Storage"].clsid, "00020906-0000-0000-C000-000000000046");
      assert.equal(rows["big"].modified.utc, "2024-05-17T10:30:15.2500000Z", "a FILETIME keeps its fraction");
      assert.equal(rows["big"].modified.raw, Number(filetime(WHEN)));
      assert.equal(rows["Storage"].created.utc, "2024-05-17T10:30:15.2500000Z");
      assert.equal(a.root_clsid, "00020906-0000-0000-C000-000000000046");
      assert.ok(rows[""].type === "root");
      assert.equal(a.orphan_entries, 0);
    });
  });
}

test("an allocated entry that no storage reaches is listed as unreachable, and said", async () => {
  await withCwd(async (cwd) => {
    const cfb = buildCfb([{ name: "kept", data: Buffer.from("k") }], { orphans: [{ name: "hidden-stream", data: Buffer.from("secret-ish bytes") }] });
    const a = await run(cwd, "orphan.bin", cfb);
    assert.equal(a.orphan_entries, 1);
    const rows = rowsByPath(a);
    assert.equal(rows["hidden-stream"].reachable, false);
    assert.equal(rows["kept"].reachable, true);
    assert.equal(a.status, "partial");
    assert.ok(a.problems.some((p: string) => /no storage reaches/.test(p)), JSON.stringify(a.problems));
  });
});

test("a directory tree that loops back is a problem, not an endless walk", async () => {
  await withCwd(async (cwd) => {
    const cfb = buildCfb([{ name: "a", data: Buffer.from("1") }, { name: "bb", data: Buffer.from("2") }, { name: "ccc", data: Buffer.from("3") }]);
    // The directory is the sector after the FAT sector (sector 1); entry 2's right link is pointed back at the entry that links to it.
    const dir = sectorAt(1);
    const top = cfb.readUInt32LE(dir + 76); // the root's child: the top node of the tree
    cfb.writeUInt32LE(top, dir + top * 128 + 72); // its right link points at itself
    const a = await run(cwd, "loop.bin", cfb);
    assert.equal(a.status, "partial");
    assert.ok(a.problems.some((p: string) => /reached twice/.test(p)), JSON.stringify(a.problems));
  });
});

test("a looping FAT chain on a stream that is read is a failed read, named, and the call still answers", async () => {
  await withCwd(async (cwd) => {
    const cfb = buildCfb([{ name: "EncryptionInfo", data: Buffer.alloc(5000, 3) }, { name: "EncryptedPackage", data: Buffer.alloc(5000, 4) }]);
    // EncryptionInfo is the first regular stream: find its start sector in its directory entry, then make the FAT point it at itself.
    const dir = sectorAt(1);
    let start = -1;
    for (let sid = 1; sid < 4; sid++) {
      const name = cfb.subarray(dir + sid * 128, dir + sid * 128 + 28).toString("utf16le");
      if (name.startsWith("EncryptionInfo")) start = cfb.readUInt32LE(dir + sid * 128 + 116);
    }
    assert.ok(start > 0);
    cfb.writeUInt32LE(start, sectorAt(0) + start * 4); // FAT sector 0 is the first sector: the entry for sector `start` is at start * 4 in it
    const a = await run(cwd, "fatloop.bin", cfb);
    assert.equal(a.status, "partial");
    assert.ok(a.problems.some((p: string) => /EncryptionInfo could not be read/.test(p) && /loop|chain/.test(p)), JSON.stringify(a.problems));
  });
});

test("a file cut short is read as far as it goes: partial, with the missing sectors named", async () => {
  await withCwd(async (cwd) => {
    const cfb = buildCfb([{ name: "EncryptionInfo", data: agileEncryptionInfo() }, { name: "EncryptedPackage", data: Buffer.alloc(6000, 9) }]);
    const a = await run(cwd, "cut.bin", cfb.subarray(0, cfb.length - 1536));
    assert.equal(a.status, "partial", JSON.stringify(a));
    assert.ok(a.problems.length > 0);
    assert.ok(rowsByPath(a)["EncryptedPackage"], "the entries are still listed");
  });
});

test("things that are not a compound file the tool can read are failures in JSON: a bad byte-order mark, a layout it does not read, a header only", async () => {
  await withCwd(async (cwd) => {
    const good = buildCfb([{ name: "s", data: Buffer.from("x") }]);
    const bom = Buffer.from(good);
    bom.writeUInt16LE(0xfeff, 28);
    const odd = Buffer.from(good);
    odd.writeUInt16LE(10, 30);
    for (const [name, data, re] of [["bom.bin", bom, /byte-order/], ["shift.bin", odd, /sector shift/], ["head.bin", good.subarray(0, 512), /root storage|directory/]] as Array<[string, Buffer, RegExp]>) {
      await put(cwd, `work/${name}`, data);
      const a = refused(await tool(DOC_STRUCTURE, cwd, { path: `work/${name}` }));
      assert.equal(a.status, "failed");
      assert.match(a.error, re, name);
    }
  });
});

test("the entry limit stops the directory read and says so; the whole table is kept in a file", async () => {
  await withCwd(async (cwd) => {
    const streams = Array.from({ length: 40 }, (_, i) => ({ name: `s${String(i).padStart(2, "0")}`, data: Buffer.from("x") }));
    const a = await run(cwd, "many.bin", buildCfb(streams), { max_entries: 10, limit: 5 });
    assert.equal(a.status, "partial");
    assert.ok(a.limits_hit.some((l: string) => /directory holds .* entries: the first 10 were read/.test(l)), JSON.stringify(a.limits_hit));
    const table = a.tables.ole_directory;
    assert.equal(table.returned, 5);
    assert.equal(table.truncated, true);
    assert.ok(table.all_results, "the whole table is in a named file");
    const lines = (await readFile(join(cwd, table.all_results), "utf8")).trim().split("\n");
    assert.equal(lines.length, table.matched);
  });
});

// --- the VBA project -------------------------------------------------------------------------------------------------------

const MARKER = "PlantedSourceMarkerQ7Z";
const SOURCE = `Attribute VB_Name = "Module1"\r\nSub AutoOpen()\r\n  ' ${MARKER}\r\nEnd Sub\r\n`;

test("a VBA project's modules are listed with their stream, compressed-source and decompressed-source sizes, and no source is in the answer", async () => {
  await withCwd(async (cwd) => {
    const big = "x".repeat(10000);
    const cfb = buildVbaProject([{ name: "Module1", source: SOURCE }, { name: "ThisDocument", source: big, type: "class" }], { storage: "Macros" });
    await put(cwd, "work/word.bin", cfb);
    const r = await tool(DOC_STRUCTURE, cwd, { path: "work/word.bin" });
    const a = body(r);
    assert.equal(a.status, "complete", JSON.stringify(a.problems));
    assert.ok(!r.stdout.includes(MARKER), "no source text in the answer");
    assert.deepEqual(a.applications, ["VBA project"]);
    const p = a.vba_projects[0];
    assert.equal(p.storage, "Macros/VBA");
    assert.equal(p.project_name, "VBAProject");
    assert.equal(p.codepage, 1252);
    assert.equal(p.modules_declared, 2);
    const mods = Object.fromEntries(p.modules.map((m: Json) => [m.name, m]));
    assert.equal(mods["Module1"].type, "procedural");
    assert.equal(mods["ThisDocument"].type, "document, class or designer");
    assert.equal(mods["Module1"].text_offset, 24);
    assert.equal(mods["Module1"].compiled_cache_bytes_before_source, 24);
    assert.equal(mods["Module1"].source_bytes, SOURCE.length);
    assert.equal(mods["Module1"].compressed_source_bytes, ovbaCompress(Buffer.from(SOURCE)).length);
    assert.equal(mods["Module1"].stream_bytes, 24 + ovbaCompress(Buffer.from(SOURCE)).length);
    assert.equal(mods["ThisDocument"].source_bytes, 10000, "a source of three chunks decompresses to its length");
    assert.equal(p.references, 1);
  });
});

test("extract vba writes each module's source byte for byte, and only when asked", async () => {
  await withCwd(async (cwd) => {
    const cfb = buildVbaProject([{ name: "Module1", source: SOURCE }, { name: "Other", source: "x".repeat(10000) }]);
    const none = await run(cwd, "p.bin", cfb, {});
    assert.equal(none.extracted, undefined);
    assert.deepEqual(await filesUnder(join(cwd, "work", "s1", "parts")), []);
    const a = await run(cwd, "p.bin", cfb, { extract_to: "work/s1/parts", extract: ["vba"] });
    assert.equal(a.status, "complete", JSON.stringify(a.problems));
    assert.equal(a.extracted.length, 2);
    const written = new Map<string, Buffer>();
    for (const row of a.extracted) {
      assert.equal(row.status, "written");
      written.set(row.locator, await readFile(join(cwd, row.file)));
      assert.equal(((await stat(join(cwd, row.file))).mode & 0o777), 0o600);
    }
    assert.deepEqual(written.get("VBA/Module1"), Buffer.from(SOURCE, "latin1"));
    assert.equal([...written.values()].some((b) => b.equals(Buffer.from("x".repeat(10000)))), true);
    assert.equal(a.extracted_parts_may_contain_secrets, true);
  });
});

test("a copy token in a compressed chunk is followed: the decompressor agrees with the spec's own example of a back-reference", async () => {
  await withCwd(async (cwd) => {
    const cfb = buildVbaProject([{ name: "Copy", source: "", compressed: OVBA_COPY_CHUNK }]);
    const a = await run(cwd, "copy.bin", cfb, { extract_to: "work/s1/parts", extract: ["vba"] });
    assert.equal(a.status, "complete", JSON.stringify(a.problems));
    assert.equal(a.vba_projects[0].modules[0].source_bytes, 9);
    assert.deepEqual(await readFile(join(cwd, a.extracted[0].file)), Buffer.from("abcabcabc"));
  });
});

test("a module whose source expands past the stream budget is over budget, named, and not extracted", async () => {
  await withCwd(async (cwd) => {
    // One chunk: a literal "a" then a copy token of offset 1 and length 4095 = 4096 bytes from 6; 600 chunks = 2.4 MB from 3.6 KB.
    const chunk = Buffer.concat([u16(0xb003), Buffer.from([0x02, 0x61, 0xfc, 0x0f])]);
    const bomb = Buffer.concat([Buffer.from([1]), ...Array.from({ length: 600 }, () => chunk)]);
    const cfb = buildVbaProject([{ name: "Bomb", source: "", compressed: bomb }]);
    const a = await run(cwd, "bomb.bin", cfb, { max_stream_bytes: 1 << 20, extract_to: "work/s1/parts", extract: ["vba"] });
    assert.equal(a.status, "partial");
    assert.ok(a.limits_hit.some((l: string) => /max_stream_bytes/.test(l)), JSON.stringify(a.limits_hit));
    assert.deepEqual(await filesUnder(join(cwd, "work", "s1", "parts")), [], "a cut copy would pass for the source");
    const whole = await run(cwd, "bomb.bin", cfb, {});
    assert.equal(whole.vba_projects[0].modules[0].source_bytes, 600 * 4096);
  });
});

test("a project locked with a password reports which protection fields are present and never their values", async () => {
  await withCwd(async (cwd) => {
    const cmg = "AABBCCDDEEFF00112233445566778899";
    const project = `ID="{11111111-2222-3333-4444-555555555555}"\r\nModule=Module1\r\nCMG="${cmg}"\r\nDPB="${cmg.toUpperCase().split("").reverse().join("")}"\r\nGC="0123456789ABCDEF"\r\n`;
    const cfb = buildVbaProject([{ name: "Module1", source: SOURCE }], { project });
    await put(cwd, "work/locked.bin", cfb);
    const r = await tool(DOC_STRUCTURE, cwd, { path: "work/locked.bin" });
    const a = body(r);
    assert.deepEqual(a.vba_projects[0].project_properties.protection_fields_present, ["CMG", "DPB", "GC"]);
    for (const secret of [cmg, cmg.split("").reverse().join(""), "0123456789ABCDEF"]) assert.ok(!r.stdout.includes(secret), "a protection value is in the answer");
  });
});

test("a dir stream that declares more modules than it lists, and a module with no stream, are problems", async () => {
  await withCwd(async (cwd) => {
    const a = await run(cwd, "declared.bin", buildVbaProject([{ name: "Module1", source: SOURCE }], { declared: 3 }));
    assert.equal(a.status, "partial");
    assert.ok(a.problems.some((p: string) => /declares 3 module\(s\) and lists 1/.test(p)), JSON.stringify(a.problems));
    // The module stream is renamed in the directory: the dir stream names one the directory does not hold.
    const cfb = buildVbaProject([{ name: "Module1", source: SOURCE }]);
    const dir = sectorAt(1);
    let hit = 0;
    for (let off = dir; off < cfb.length - 20; off += 128) {
      if (cfb.subarray(off, off + 14).toString("utf16le") === "Module1") {
        cfb.write("Modulex", off, "utf16le");
        hit++;
      }
    }
    assert.equal(hit, 1, "the fixture's directory entry was found");
    const b = await run(cwd, "missing.bin", cfb);
    assert.equal(b.vba_projects[0].modules[0].stream, "missing");
    assert.ok(b.problems.some((p: string) => /names a stream that the directory does not hold/.test(p)), JSON.stringify(b.problems));
  });
});

// --- encryption structures ---------------------------------------------------------------------------------------------------

test("an agile EncryptionInfo is read for scheme, cipher, key size, hash and spin count; the salt and the verifier are in no answer", async () => {
  await withCwd(async (cwd) => {
    const salt = "UExBTlRFRFNBTFRWQUxVRTEyMw==";
    const verifier = "UExBTlRFRFZFUklGSUVSSEFTSFZBTFVF";
    const cfb = buildCfb([{ name: "EncryptionInfo", data: agileEncryptionInfo({ salt, encryptedKey: verifier, spin: 100000, keyBits: 256 }) }, { name: "EncryptedPackage", data: Buffer.concat([u32(1234), u32(0), Buffer.alloc(1240, 5)]) }]);
    await put(cwd, "work/agile.bin", cfb);
    const r = await tool(DOC_STRUCTURE, cwd, { path: "work/agile.bin" });
    const a = body(r);
    assert.equal(a.status, "complete", JSON.stringify(a.problems));
    assert.equal(a.encryption_summary.found, true);
    const item = a.encryption_summary.items[0];
    assert.equal(item.scheme, "agile");
    assert.equal(item.version, "4.4");
    assert.equal(item.data.keyBits, 256);
    assert.equal(item.data.cipherAlgorithm, "AES");
    assert.equal(item.data.hashAlgorithm, "SHA512");
    assert.equal(item.key_encryptors[0].kind, "password");
    assert.equal(item.key_encryptors[0].spinCount, 100000);
    assert.equal(item.encrypted_package_declared_size, 1234);
    assert.deepEqual(a.applications, ["encrypted OOXML package in an OLE wrapper"]);
    for (const secret of [salt, verifier, "VkVSSUZJRVJJTlBVVA", "RU5DUllQVEVES0VZVkFMVUU", "ZW5jcnlwdGVkSG1hY0tleQ"]) assert.ok(!r.stdout.includes(secret), `${secret} (a salt, verifier or key) is in the answer`);
    assert.match(a.encryption_summary.not_determined, /no key is tried/);
  });
});

test("a standard EncryptionInfo is read for algorithm, hash and key size; the salt, verifier and verifier hash are in no answer", async () => {
  await withCwd(async (cwd) => {
    const info = standardEncryptionInfo({ alg: 0x660e, hash: 0x8004, bits: 128, salt: Buffer.from("S4LT-S4LT-S4LT-1"), verifier: Buffer.from("V3RIFIER-V3RIFIE"), verifierHash: Buffer.from("VH4SH-VH4SH-VH4SH-VH4SH-VH4SH-12") });
    const cfb = buildCfb([{ name: "EncryptionInfo", data: info }, { name: "EncryptedPackage", data: Buffer.alloc(100, 1) }]);
    await put(cwd, "work/std.bin", cfb);
    const r = await tool(DOC_STRUCTURE, cwd, { path: "work/std.bin" });
    const item = body(r).encryption_summary.items[0];
    assert.equal(item.scheme, "standard");
    assert.equal(item.algorithm, "AES-128");
    assert.equal(item.hash, "SHA-1");
    assert.equal(item.key_bits, 128);
    assert.equal(item.version, "3.2");
    assert.deepEqual(item.flags, { crypto_api: true, doc_props_not_encrypted: false, external: false, aes: true });
    for (const secret of ["S4LT-S4LT", "V3RIFIER", "VH4SH", Buffer.from("S4LT-S4LT-S4LT-1").toString("hex"), Buffer.from("V3RIFIER-V3RIFIE").toString("hex")]) assert.ok(!r.stdout.includes(secret), `${secret} is in the answer`);
    // RC4 is read as RC4.
    const rc4 = standardEncryptionInfo({ alg: 0x6801, bits: 40 });
    const b = await run(cwd, "rc4.bin", buildCfb([{ name: "EncryptionInfo", data: rc4 }, { name: "EncryptedPackage", data: Buffer.alloc(100, 1) }]));
    assert.equal(b.encryption_summary.items[0].algorithm, "RC4");
    assert.equal(b.encryption_summary.items[0].key_bits, 40);
  });
});

test("an EncryptionInfo with a DOCTYPE is not parsed, and one that is cut short is a problem, not a scheme", async () => {
  await withCwd(async (cwd) => {
    const doctype = Buffer.concat([u16(4), u16(4), u32(0x40), Buffer.from('<?xml version="1.0"?><!DOCTYPE e [<!ENTITY x "y">]><encryption xmlns="http://schemas.microsoft.com/office/2006/encryption"/>')]);
    const a = await run(cwd, "dt.bin", buildCfb([{ name: "EncryptionInfo", data: doctype }, { name: "EncryptedPackage", data: Buffer.alloc(20) }]));
    assert.equal(a.status, "partial");
    assert.ok(a.problems.some((p: string) => /DOCTYPE/.test(p)));
    const b = await run(cwd, "short.bin", buildCfb([{ name: "EncryptionInfo", data: Buffer.from([4, 0]) }, { name: "EncryptedPackage", data: Buffer.alloc(20) }]));
    assert.equal(b.status, "partial");
    assert.ok(b.problems.some((p: string) => /shorter than its version/.test(p)));
  });
});

test("Word: the FIB flags and the table stream's version say RC4, CryptoAPI or XOR obfuscation; an unencrypted document says none was found, bounded", async () => {
  await withCwd(async (cwd) => {
    const table = (major: number, minor: number): Buffer => Buffer.concat([u16(major), u16(minor), Buffer.alloc(40, 6)]);
    const cases: Array<[string, Buffer, string, string?]> = [
      ["rc4.doc", buildCfb([{ name: "WordDocument", data: wordFib({ encrypted: true }) }, { name: "1Table", data: table(1, 1) }]), "RC4 (Office 97-2003)", "1.1"],
      ["capi.doc", buildCfb([{ name: "WordDocument", data: wordFib({ encrypted: true }) }, { name: "1Table", data: table(3, 2) }]), "RC4 CryptoAPI", "3.2"],
      ["zero.doc", buildCfb([{ name: "WordDocument", data: wordFib({ encrypted: true, table1: false }) }, { name: "0Table", data: table(1, 1) }]), "RC4 (Office 97-2003)", "1.1"],
      ["xor.doc", buildCfb([{ name: "WordDocument", data: wordFib({ encrypted: true, obfuscated: true }) }, { name: "1Table", data: table(0, 0) }]), "XOR obfuscation (fObfuscated)"],
    ];
    for (const [name, data, scheme, version] of cases) {
      const a = await run(cwd, name, data);
      assert.equal(a.encryption_summary.found, true, name);
      assert.equal(a.encryption_summary.items[0].scheme, scheme, name);
      if (version) assert.equal(a.encryption_summary.items[0].version, version, name);
    }
    const plain = await run(cwd, "plain.doc", buildCfb([{ name: "WordDocument", data: wordFib() }, { name: "1Table", data: table(0, 0) }]));
    assert.equal(plain.encryption_summary.found, false);
    assert.match(plain.encryption_summary.basis, /not excluded/, "a negative is bounded");
    // A FIB that says encrypted while its table stream is absent is a problem.
    const lost = await run(cwd, "lost.doc", buildCfb([{ name: "WordDocument", data: wordFib({ encrypted: true }) }]));
    assert.ok(lost.problems.some((p: string) => /table stream it names is not in the directory/.test(p)));
  });
});

test("Excel: FILEPASS is read for its scheme, BOUNDSHEET gives each sheet's kind and visibility, a macro sheet is said, and an unfinished globals substream is a problem", async () => {
  await withCwd(async (cwd) => {
    const sheets = [{ name: "Data" }, { name: "Hidden", state: 1 }, { name: "Macro1", state: 2, kind: 1 }, { name: "Chart", kind: 2 }];
    const a = await run(cwd, "x.xls", buildCfb([{ name: "Workbook", data: excelWorkbook({ sheets }) }]));
    assert.deepEqual(a.excel.sheets, [
      { name: "Data", state: "visible", kind: "worksheet" },
      { name: "Hidden", state: "hidden", kind: "worksheet" },
      { name: "Macro1", state: "very hidden", kind: "Excel 4.0 macro sheet" },
      { name: "Chart", state: "visible", kind: "chart" },
    ]);
    assert.equal(a.protection_items[0].kind, "macro_sheets");
    assert.equal(a.protection_items[0].count, 1);
    assert.equal(a.encryption_summary.found, false);
    for (const [fp, scheme] of [[{ type: 1, major: 1, minor: 1 }, "RC4 (Office 97-2003)"], [{ type: 1, major: 4, minor: 2 }, "RC4 CryptoAPI"], [{ type: 0 }, "XOR obfuscation"]] as const) {
      const b = await run(cwd, "e.xls", buildCfb([{ name: "Workbook", data: excelWorkbook({ filepass: fp as { type: 0 | 1; major?: number; minor?: number } }) }]));
      assert.equal(b.encryption_summary.found, true);
      assert.equal(b.encryption_summary.items[0].scheme, scheme);
    }
    const cut = await run(cwd, "cut.xls", buildCfb([{ name: "Workbook", data: excelWorkbook({ sheets, noEof: true }) }]));
    assert.equal(cut.status, "partial");
    assert.ok(cut.problems.some((p: string) => /did not end with an EOF record/.test(p)));
  });
});

test("PowerPoint: the Current User header token says encrypted or not, and any other value is a problem", async () => {
  await withCwd(async (cwd) => {
    const mk = (token: number) => buildCfb([{ name: "PowerPoint Document", data: Buffer.alloc(80, 1) }, { name: "Current User", data: currentUser(token) }]);
    const enc = await run(cwd, "enc.ppt", mk(0xf3d1c4df));
    assert.equal(enc.encryption_summary.found, true);
    const plain = await run(cwd, "plain.ppt", mk(0xe391c05f));
    assert.equal(plain.encryption_summary.found, false);
    const odd = await run(cwd, "odd.ppt", mk(0x12345678));
    assert.equal(odd.status, "partial");
  });
});

test("a stream of the file can be extracted by path, exactly; a stream over the budget is refused whole", async () => {
  await withCwd(async (cwd) => {
    const payload = Buffer.from(Array.from({ length: 7000 }, (_, i) => (i * 31) & 0xff));
    const cfb = buildCfb([{ name: "Dir", children: [{ name: "payload", data: payload }] }, { name: "tiny", data: Buffer.from("abc") }]);
    const a = await run(cwd, "e.bin", cfb, { extract_to: "work/s1/parts", extract: ["ole:Dir/payload", "ole:tiny"] });
    assert.equal(a.status, "complete", JSON.stringify(a.problems));
    const files = Object.fromEntries(await Promise.all(a.extracted.map(async (r: Json) => [r.locator, await readFile(join(cwd, r.file))])));
    assert.ok((files["Dir/payload"] as Buffer).equals(payload));
    assert.ok((files["tiny"] as Buffer).equals(Buffer.from("abc")));
    const small = await run(cwd, "e.bin", cfb, { extract_to: "work/s1/parts2", extract: ["ole:Dir/payload", "ole:nothere"], max_stream_bytes: 4096 });
    assert.equal(small.status, "partial");
    assert.ok(small.limits_hit.some((l: string) => /max_stream_bytes/.test(l)));
    assert.ok(small.problems.some((p: string) => /ole:nothere matched nothing/.test(p)));
    assert.deepEqual(await filesUnder(join(cwd, "work", "s1", "parts2")), []);
  });
});

test("the total budget is shared by every stream read: the next read after it is spent is a limit, not a quiet skip", async () => {
  await withCwd(async (cwd) => {
    const cfb = buildVbaProject([{ name: "A", source: "a".repeat(6000) }, { name: "B", source: "b".repeat(6000) }, { name: "C", source: "c".repeat(6000) }]);
    const a = await run(cwd, "total.bin", cfb, { max_total_bytes: 9000 });
    assert.equal(a.status, "partial");
    assert.ok(a.limits_hit.some((l: string) => /max_total_bytes/.test(l)), JSON.stringify(a.limits_hit));
  });
});

// --- OOXML / ZIP -------------------------------------------------------------------------------------------------------------

const TYPES = (extra = ""): ZipEntry => ({
  name: "[Content_Types].xml",
  data: Buffer.from(
    `<?xml version="1.0"?><Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types"><Default Extension="bin" ContentType="application/vnd.ms-office.vbaProject"/>` +
      `<Override PartName="/word/document.xml" ContentType="application/vnd.ms-word.document.macroEnabled.main+xml"/>${extra}</Types>`,
  ),
});

test("a vbaProject.bin inside a package is read as a compound file; the content types, and the protection elements by attribute with no hash, salt or password value", async () => {
  await withCwd(async (cwd) => {
    const hash = "aGFzaGhhc2hoYXNoaGFzaGhhc2hoYXNoaGFzaA==";
    const salt = "c2FsdHNhbHRzYWx0c2FsdA==";
    const settings = `<?xml version="1.0"?><w:settings xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main"><w:documentProtection w:edit="readOnly" w:enforcement="1" w:cryptProviderType="rsaAES" w:cryptAlgorithmClass="hash" w:cryptAlgorithmSid="14" w:cryptSpinCount="100000" w:hash="${hash}" w:salt="${salt}"/><w:writeProtection w:recommended="1"/></w:settings>`;
    const zip = buildZip([
      TYPES(),
      { name: "word/document.xml", data: Buffer.from("<w:document/>") },
      { name: "word/settings.xml", data: Buffer.from(settings) },
      { name: "word/vbaProject.bin", data: buildVbaProject([{ name: "Module1", source: SOURCE }]) },
    ]);
    await put(cwd, "work/m.docm", zip);
    const r = await tool(DOC_STRUCTURE, cwd, { path: "work/m.docm" });
    const a = body(r);
    assert.equal(a.status, "complete", JSON.stringify(a.problems));
    assert.equal(a.container, "OOXML or ZIP");
    assert.equal(a.kind, "Word");
    assert.equal(a.vbaproject_parts[0].part, "word/vbaProject.bin");
    assert.equal(a.vbaproject_parts[0].vba_projects[0].modules[0].name, "Module1");
    assert.equal(a.vbaproject_parts[0].vba_projects[0].modules[0].source_bytes, SOURCE.length);
    const notable = a.content_types.notable.map((n: Json) => n.content_type);
    assert.ok(notable.includes("application/vnd.ms-office.vbaProject"));
    assert.ok(notable.includes("application/vnd.ms-word.document.macroEnabled.main+xml"));
    const dp = a.protection_items.find((p: Json) => p.element === "documentProtection");
    assert.equal(dp.where, "word/settings.xml");
    assert.equal(dp.attributes.edit, "readOnly");
    assert.equal(dp.attributes.enforcement, "1");
    assert.equal(dp.attributes.cryptSpinCount, "100000");
    assert.deepEqual(dp.secret_bearing_attributes.map((x: Json) => x.name).sort(), ["hash", "salt"]);
    assert.equal(dp.secret_bearing_attributes.find((x: Json) => x.name === "hash").length, hash.length);
    assert.match(dp.note, /not encryption/);
    for (const secret of [hash, salt, MARKER]) assert.ok(!r.stdout.includes(secret), `${secret.slice(0, 8)}... is in the answer`);
    assert.ok(a.protection_items.some((p: Json) => p.element === "writeProtection"));
  });
});

test("the OOXML read is bounded: a part that inflates past its budget is counted, an encrypted member is flagged, a DOCTYPE is refused", async () => {
  await withCwd(async (cwd) => {
    const zip = buildZip([
      { name: "[Content_Types].xml", data: Buffer.from('<?xml version="1.0"?><!DOCTYPE t [<!ENTITY a "b">]><Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types"/>') },
      { name: "word/settings.xml", data: Buffer.alloc(3 << 20) },
      { name: "word/enc.xml", data: Buffer.from("x"), flags: 1, compressed: Buffer.from("garbage"), method: 8 },
    ]);
    const a = await run(cwd, "b.docx", zip, { max_stream_bytes: 1 << 20 });
    assert.equal(a.status, "partial");
    assert.ok(a.problems.some((p: string) => /DOCTYPE/.test(p)));
    assert.ok(a.limits_hit.some((l: string) => /word\/settings\.xml/.test(l) && /max_stream_bytes|ratio/.test(l)), JSON.stringify(a.limits_hit));
    assert.equal(a.members.flagged_encrypted, 1);
    assert.equal(a.encryption_summary.items[0].members, 1);
  });
});

test("zip:<member> extracts a member exactly; a package with no [Content_Types].xml says so", async () => {
  await withCwd(async (cwd) => {
    const data = Buffer.from("<w:document>hello</w:document>");
    const a = await run(cwd, "e.docx", buildZip([{ name: "word/document.xml", data }]), { extract_to: "work/s1/parts", extract: ["zip:word/document.xml"] });
    assert.ok(a.problems.some((p: string) => /no \[Content_Types\]\.xml/.test(p)));
    assert.ok((await readFile(join(cwd, a.extracted[0].file))).equals(data));
  });
});

// --- values, names, jobs ----------------------------------------------------------------------------------------------------

const TOKEN = "Zk9mQ2xW7vB3nL8pR4tY6wD1sFgHjK";

test("a stream, module or sheet named like a token is withheld from the answer and its table file; the real name is in a private file only", async () => {
  await withCwd(async (cwd) => {
    const cfb = buildCfb([{ name: TOKEN, data: Buffer.from("x") }, { name: "plain", data: Buffer.from("y") }]);
    const { answer, text } = await runJob(cwd, "t.bin", cfb, { limit: 1 });
    assert.ok(!text.includes(TOKEN), "the token is in the answer");
    assert.ok(answer.withheld.names >= 1);
    const everything = await everythingUnder(cwd, text, ["out"]);
    const names = (await filesUnder(join(cwd, "out"))).filter((f) => f.includes("withheld-names"));
    assert.equal(names.length, 1);
    assert.equal(((await stat(join(cwd, "out", names[0]!))).mode & 0o777), 0o600);
    const table = (await filesUnder(join(cwd, "out"))).filter((f) => f.includes("ole_directory"));
    for (const f of table) assert.ok(!(await readFile(join(cwd, "out", f), "utf8")).includes(TOKEN), "a table file holds the token");
    assert.ok(everything.includes(TOKEN), "the private names file keeps the real name");
    assert.ok((await readFile(join(cwd, "out", names[0]!), "utf8")).includes(TOKEN));
    assert.equal(answer.withheld_names_file.startsWith("store/jobs/"), true);
  });
});

test("write_values is refused outside a job, with nothing written; in a job an empty 0600 file says written 0, and a second call in the same job is refused by name", async () => {
  await withCwd(async (cwd) => {
    await put(cwd, "work/v.bin", buildCfb([{ name: "s", data: Buffer.from("x") }]));
    const no = refused(await tool(DOC_STRUCTURE, cwd, { path: "work/v.bin", write_values: true }));
    assert.match(no.error, /refused outside a job/);
    assert.deepEqual(await filesUnder(join(cwd, "out")), []);
    const first = body(await asJob(DOC_STRUCTURE, cwd, { path: "work/v.bin", write_values: true }));
    assert.equal(first.secret_values.written, 0);
    assert.equal(first.secret_values.contains_secret_values, false);
    const file = (await filesUnder(join(cwd, "out"))).find((f) => f.endsWith("doc-structure-values.jsonl"))!;
    assert.equal(((await stat(join(cwd, "out", file))).mode & 0o777), 0o600);
    assert.equal((await readFile(join(cwd, "out", file))).length, 0);
    const second = refused(await tool(DOC_STRUCTURE, cwd, { path: "work/v.bin", write_values: true }, { JOB_ID: "j000001", OUT: join(cwd, "out") }));
    assert.match(second.error, /already exists/);
  });
});

test("extraction in a job lands under $OUT and nowhere else; outside $OUT, under inputs/ or outside the run directory is refused", async () => {
  await withCwd(async (cwd) => {
    const cfb = buildVbaProject([{ name: "Module1", source: SOURCE }]);
    await put(cwd, "work/j.bin", cfb);
    const ok = body(await asJob(DOC_STRUCTURE, cwd, { path: "work/j.bin", extract_to: "out/parts", extract: ["vba"] }));
    assert.equal(ok.extracted[0].status, "written");
    assert.match(ok.extracted[0].file, /^out\/parts\/extract-0001\.bin$/);
    for (const bad of ["work/elsewhere", "inputs/x", "../escape", "/tmp/escape"]) {
      const r = refused(await asJob(DOC_STRUCTURE, cwd, { path: "work/j.bin", extract_to: bad, extract: ["vba"] }));
      assert.match(r.error, /extract_to/, bad);
    }
    const noDir = refused(await tool(DOC_STRUCTURE, cwd, { path: "work/j.bin", extract: ["vba"] }));
    assert.match(noDir.error, /needs extract_to/);
    const bad = refused(await tool(DOC_STRUCTURE, cwd, { path: "work/j.bin", extract_to: "work/s1/p", extract: ["nonsense"] }));
    assert.match(bad.error, /not a selector/);
  });
});

test("things that are not documents are JSON: unsupported formats, empty files, directories, a name that is not there, and no traceback anywhere", async () => {
  await withCwd(async (cwd) => {
    await put(cwd, "work/junk.bin", Buffer.from("this is not a document at all"));
    const unsup = refused(await tool(DOC_STRUCTURE, cwd, { path: "work/junk.bin" }));
    assert.equal(unsup.status, "unsupported");
    await put(cwd, "work/empty.bin", "");
    assert.match(refused(await tool(DOC_STRUCTURE, cwd, { path: "work/empty.bin" })).error, /empty/);
    assert.match(refused(await tool(DOC_STRUCTURE, cwd, { path: "work" })).error, /not a regular file/);
    assert.match(refused(await tool(DOC_STRUCTURE, cwd, { path: "work/none\udcfe.bin" })).error, /no such file/);
    for (const bad of [{}, { path: 5 }, { path: "work/junk.bin", max_seconds: 0 }, { path: "work/junk.bin", max_entries: "x" }, { path: "work/junk.bin", write_values: "yes" }]) {
      const r = await tool(DOC_STRUCTURE, cwd, bad);
      assert.notEqual(r.code, 0);
      assert.doesNotMatch(r.stderr, /Traceback/);
      assert.ok(JSON.parse(r.stdout).error);
    }
    // random garbage behind each magic is a failure or a partial answer, never a traceback
    for (const head of ["\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1", "PK\x03\x04", "%PDF-1.4", "{\\rtf1"]) {
      await put(cwd, "work/g.bin", Buffer.concat([Buffer.from(head, "latin1"), Buffer.from(Array.from({ length: 3000 }, (_, i) => (i * 131 + 7) & 0xff))]));
      const r = await tool(DOC_STRUCTURE, cwd, { path: "work/g.bin" });
      assert.doesNotMatch(r.stderr, /Traceback/, head);
      const j = JSON.parse(r.stdout);
      assert.ok(["failed", "partial", "complete"].includes(j.status), `${head}: ${r.stdout.slice(0, 200)}`);
    }
  });
});
