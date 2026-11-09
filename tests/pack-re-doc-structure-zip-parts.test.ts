/**
 * doc_structure reads a ZIP central directory that is past the limits for opening the package (100,000 members, 64 MiB) in parts, so that
 * a directory padded past a limit no longer hides its members: every member is listed in the parts table (the first `limit` in the answer,
 * the whole in its file), counted, and none is opened; the answer is partial and says how many were listed and how many were not.
 * And the scans after the member listing each have a share of max_seconds of their own: the check of members for the compound file
 * signature cannot use the time that reading the VBA project parts needs, and the answer says which scan stopped.
 *
 * Every input is built here from the PKWARE APPNOTE (the tests/pack-re-harness.ts writer); the end record is patched by hand to name a
 * larger directory, which is what padding does.
 */
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { readFile } from "node:fs/promises";
import { join } from "node:path";
import { test } from "node:test";
import { DOC_STRUCTURE, buildZip, put, refused, tool, withCwd } from "./pack-re-harness.ts";
import type { Json, ZipEntry } from "./pack-re-harness.ts";

const CT: ZipEntry = { name: "[Content_Types].xml", data: Buffer.from('<?xml version="1.0"?><Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types"/>') };

/** The same archive with `pad` zero bytes between the last central directory entry and the end record, which now names the longer directory. */
function padded(zip: Buffer, pad: number): Buffer {
  const eocd = zip.subarray(zip.length - 22);
  assert.equal(eocd.readUInt32LE(0), 0x06054b50);
  const cdSize = eocd.readUInt32LE(12);
  const cdOff = eocd.readUInt32LE(16);
  const patched = Buffer.from(eocd);
  patched.writeUInt32LE(cdSize + pad, 12);
  return Buffer.concat([zip.subarray(0, cdOff + cdSize), Buffer.alloc(pad), patched]);
}

async function run(cwd: string, name: string, args: Json = {}): Promise<{ answer: Json; code: number | null }> {
  const r = await tool(DOC_STRUCTURE, cwd, { path: `work/${name}`, ...args });
  assert.doesNotMatch(r.stderr, /Traceback/, r.stderr);
  return { answer: JSON.parse(r.stdout) as Json, code: r.code };
}

test("a central directory of 100,001 members is listed in parts: every member in the parts table and its file, none opened, partial, the counts read and not read named", async () => {
  await withCwd(async (cwd) => {
    const entries: ZipEntry[] = [CT];
    for (let i = 0; i < 100_000; i++) entries.push({ name: `m${String(i).padStart(6, "0")}.bin`, data: Buffer.from("x"), method: 0 });
    await put(cwd, "work/many.docx", buildZip(entries, { zip64: true }));
    const { answer: a, code } = await run(cwd, "many.docx", { max_seconds: 80 });
    assert.equal(code, 0);
    assert.equal(a.status, "partial");
    assert.equal(a.members.declared, 100_001);
    assert.equal(a.members.listed, 100_001);
    assert.equal(a.members.read, 0, "no member was opened");
    assert.equal(a.members.not_attempted, 100_001);
    assert.ok(a.limits_hit.some((l: string) => /declares 100001 members .* over the 100000-member and 67108864-byte limits for opening the package, so no member was opened or read; the directory was read in parts instead: 100001 members listed in the parts table .*, 0 of the declared members not listed/.test(l)), JSON.stringify(a.limits_hit));
    const table = a.tables.parts;
    assert.equal(table.matched, 100_001);
    assert.ok(table.rows.length <= 1000 && table.truncated === true);
    const rows = (await readFile(join(cwd, table.all_results), "utf8")).trim().split("\n").map((l) => JSON.parse(l) as Json);
    assert.equal(rows.length, 100_001);
    assert.equal(rows[0].name, "[Content_Types].xml");
    assert.equal(rows[100_000].name, "m099999.bin");
    assert.equal(rows[5].method, 0);
    assert.equal(rows[5].bytes, 1);
  });
});

test("a central directory padded with 70 MiB past the byte limit lists the three members it holds and says how much of the directory is entries", async () => {
  await withCwd(async (cwd) => {
    const zip = buildZip([CT, { name: "word/document.xml", data: Buffer.from("<w:document/>") }, { name: "word/vbaProject.bin", data: Buffer.from("not a compound file") }]);
    await put(cwd, "work/padded.docm", padded(zip, 70 << 20));
    const { answer: a, code } = await run(cwd, "padded.docm", { max_seconds: 80 });
    assert.equal(code, 0);
    assert.equal(a.status, "partial");
    assert.equal(a.members.declared, 3);
    assert.equal(a.members.listed, 3);
    assert.equal(a.members.read, 0);
    assert.deepEqual(a.tables.parts.rows.map((r: Json) => r.name), ["[Content_Types].xml", "word/document.xml", "word/vbaProject.bin"]);
    const limit = a.limits_hit.find((l: string) => /over the 100000-member and 67108864-byte limits/.test(l));
    assert.ok(limit, JSON.stringify(a.limits_hit));
    assert.match(limit, /3 members listed in the parts table/);
    assert.match(limit, /0 of the declared members not listed/);
    assert.match(limit, /of its 73\d{6} bytes are entries/);
    assert.ok(a.coverage.structures_read.some((s: string) => /central directory entries \(listed in parts, none opened\)/.test(s)));
  });
});

test("the names in the parts table pass the sanitiser: a key-shaped name is withheld, its real name goes to the private names file", async () => {
  await withCwd(async (cwd) => {
    const secret = "AKIA" + "QWERTYUIOP123456";
    const entries: ZipEntry[] = [CT, { name: `word/${secret}.xml`, data: Buffer.from("<a/>"), method: 0 }];
    for (let i = 0; i < 100_001; i++) entries.push({ name: `n${i}`, data: Buffer.alloc(0), method: 0 });
    await put(cwd, "work/named.docx", buildZip(entries, { zip64: true }));
    const r = await tool(DOC_STRUCTURE, cwd, { path: "work/named.docx", max_seconds: 80 });
    assert.doesNotMatch(r.stdout, new RegExp(secret.slice(4, 14)));
    const a = JSON.parse(r.stdout) as Json;
    const rows = (await readFile(join(cwd, a.tables.parts.all_results), "utf8")).trim().split("\n").map((l) => JSON.parse(l) as Json);
    assert.equal(rows.length, 100_003);
    const hit = rows.find((row) => row.name_withheld);
    assert.ok(hit, "a row says its name is withheld");
    assert.doesNotMatch(JSON.stringify(rows.slice(0, 5)), new RegExp(secret.slice(4, 14)));
    assert.ok(a.withheld_names_file, "the names file is named");
    assert.match(await readFile(join(cwd, a.withheld_names_file), "utf8"), new RegExp(secret));
  });
});

// A clock that moves 2 ms at every look: what each scan may spend is then a count of looks, the same on every machine and under any load.
const CLOCK = [
  "import importlib.util, io, json, sys, time",
  "spec = importlib.util.spec_from_file_location('tool_under_test', sys.argv[1])",
  "m = importlib.util.module_from_spec(spec)",
  "spec.loader.exec_module(m)",
  "ticks = [time.monotonic()]",
  "def fake():",
  "    ticks[0] += 0.002",
  "    return ticks[0]",
  "time.monotonic = fake",
  "sys.stdin = io.StringIO(json.dumps({'path': sys.argv[2], 'max_seconds': 10}))",
  "try:",
  "    m.main()",
  "except SystemExit:",
  "    pass",
].join("\n");

test("the scan of members for the compound file signature stops at its share and says so, and the VBA project the package declares is still read", async () => {
  await withCwd(async (cwd) => {
    // the project is among the first 5,000 members (max_entries), which are the ones the package is indexed by; the 6,000 after it are what the scan checks
    const entries: ZipEntry[] = [CT, { name: "word/vbaProject.bin", data: Buffer.from("not a compound file at all") }];
    for (let i = 0; i < 6_000; i++) entries.push({ name: `m${i}.bin`, data: Buffer.from("x"), method: 0 });
    await put(cwd, "work/scan.docm", buildZip(entries));
    const r = spawnSync("python3", ["-c", CLOCK, DOC_STRUCTURE, "work/scan.docm"], { cwd, encoding: "utf8", env: { ...process.env, AGENT_ID: "s1" }, timeout: 300_000 });
    assert.doesNotMatch(r.stderr, /Traceback/, r.stderr);
    const a = JSON.parse(r.stdout) as Json;
    assert.ok(a.limits_hit.some((l: string) => /the compound file signature check stopped at 95% of max_seconds \(10\); the VBA project parts keep the last 0\.5 s/.test(l)), JSON.stringify(a.limits_hit));
    assert.ok(a.problems.some((p: string) => /did not reach every member/.test(p)), JSON.stringify(a.problems));
    // the declared project (its name is shown withheld here: the listing's clock ran out first) was read, and is not a compound file
    assert.ok(a.problems.some((p: string) => /is not read as a compound file: the file is shorter than the 512-byte compound file header/.test(p)), `the declared project was read: ${JSON.stringify(a.problems)}`);
    assert.ok(!a.problems.some((p: string) => /the clock ended before every member the package declares as its VBA project was read/.test(p)), JSON.stringify(a.problems));
    assert.ok(!a.limits_hit.some((l: string) => /the VBA project parts stopped at max_seconds/.test(l)), JSON.stringify(a.limits_hit));
    assert.equal(a.members.read, 2, "the content types and the VBA project were read");
  });
});

test("an argument error is still a JSON refusal and a file that is no ZIP is still not read as one", async () => {
  await withCwd(async (cwd) => {
    await put(cwd, "work/plain.txt", "just text");
    const out = refused(await tool(DOC_STRUCTURE, cwd, { path: "work/plain.txt" }));
    assert.equal(out.status, "failed");
  });
});
