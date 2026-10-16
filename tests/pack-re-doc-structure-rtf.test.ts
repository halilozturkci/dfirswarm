/**
 * doc_structure on RTF, against text written by hand to the RTF specification: groups, control words, the \binN rule (N raw
 * bytes follow, whatever they look like), \object groups with \objclass and hex-encoded \objdata, and the OLE 1.0 ObjectHeader
 * of [MS-OLEDS] inside the data. What these cases hold: groups and control words are counted by a tokenizer, not by a byte
 * search for "\objdata"; binary data is skipped by its declared length; an object's data is decoded from hex for its header and,
 * when it is a compound file, read as one; a field instruction or a template is reported by its first word and its length,
 * the whole only in the values file; and a file of ten million open braces ends at the clock, not never.
 */
import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import { join } from "node:path";
import { test } from "node:test";
import { DOC_STRUCTURE, asJob, body, put, tool, withCwd } from "./pack-re-harness.ts";
import type { Json } from "./pack-re-harness.ts";
import { buildCfb, buildVbaProject, hex, ole1Object, wordFib } from "./pack-re-doc-fixtures.ts";

async function run(cwd: string, name: string, data: Buffer | string, args: Record<string, unknown> = {}): Promise<{ a: Json; text: string }> {
  await put(cwd, `work/${name}`, data);
  const r = await tool(DOC_STRUCTURE, cwd, { path: `work/${name}`, ...args });
  return { a: body(r), text: r.stdout };
}

test("groups, depth and control words are counted by a tokenizer: a small document, counted by hand", async () => {
  await withCwd(async (cwd) => {
    // {\rtf1\ansi {\fonttbl {\f0 Arial;}} Hello \b bold\b0 {\par}}  -> 4 groups, depth 3
    const { a } = await run(cwd, "s.rtf", "{\\rtf1\\ansi {\\fonttbl {\\f0 Arial;}} Hello \\b bold\\b0 {\\par}}");
    assert.equal(a.status, "complete", JSON.stringify(a.problems));
    assert.equal(a.rtf_version_word, "rtf1");
    assert.deepEqual({ groups: a.structure.groups, depth: a.structure.max_depth_seen, open: a.structure.open_groups_at_end, closeWithoutOpen: a.structure.close_without_open }, { groups: 4, depth: 3, open: 0, closeWithoutOpen: 0 });
    const words = Object.fromEntries(a.control_words.top.map((w: Json) => [w.word, w.count]));
    // \b0 is the word \b with the parameter 0, so \b is counted twice
    assert.deepEqual(words, { rtf: 1, ansi: 1, fonttbl: 1, f: 1, b: 2, par: 1 });
    assert.equal(a.control_words.distinct, 6);
    assert.equal(a.control_words.watched.fonttbl, 1);
  });
});

const CLASS = "Word.Document.8";

function objectGroup(data: Buffer, o: { cls?: string; wrap?: number; kind?: string } = {}): string {
  return `{\\object\\${o.kind ?? "objemb"}\\objw100\\objh100{\\*\\objclass ${o.cls ?? CLASS}}{\\*\\objname Obj1}{\\*\\objdata ${hex(data, o.wrap ?? 64).replace(/\n/g, "\r\n")}}{\\result {\\pict x}}}`;
}

test("an object group is listed with its kind, class, the hex length of its data and the decoded OLE 1.0 object header; the data is not in the answer", async () => {
  await withCwd(async (cwd) => {
    const native = Buffer.from("PLANTED-NATIVE-PAYLOAD-BYTES");
    const obj = ole1Object(CLASS, native);
    const { a, text } = await run(cwd, "o.rtf", `{\\rtf1 text${objectGroup(obj)}\r\n}`);
    assert.equal(a.status, "complete", JSON.stringify(a.problems));
    assert.equal(a.objects.count, 1);
    const row = a.objects.first[0];
    assert.equal(row.kind, "objemb");
    assert.equal(row.class_name, CLASS);
    assert.equal(row.object_name, "Obj1");
    assert.deepEqual(row.flags.sort(), ["objh", "objw"]);
    assert.equal(row.data.hex_digits, obj.length * 2, "white space and line breaks in the hex are not digits");
    assert.equal(row.data.non_hex_bytes, 0);
    // The start of the data is named by its signature; no byte of the data is printed.
    assert.equal(row.data.decoded_start.signature, "OLE 1.0 ObjectHeader (version 0x00000501)");
    assert.equal("first_bytes_hex" in row.data.decoded_start, false);
    assert.deepEqual({ v: row.ole1_header.ole_version, f: row.ole1_header.format, c: row.ole1_header.class_name, n: row.ole1_header.native_data_bytes }, { v: "0x00000501", f: "embedded", c: CLASS, n: native.length });
    assert.ok(!text.includes("PLANTED-NATIVE") && !text.includes(Buffer.from("PLANTED-NATIVE").toString("hex")), "the payload is not in the answer");
  });
});

test("an object whose payload is a compound file is read as one: its streams, its VBA project and its encryption structures are in the object's row", async () => {
  await withCwd(async (cwd) => {
    const vba = buildVbaProject([{ name: "Module1", source: "Sub AutoOpen()\r\nEnd Sub\r\n" }], { storage: "Macros" });
    const { a } = await run(cwd, "n.rtf", `{\\rtf1${objectGroup(ole1Object("Package", vba))}}`);
    const nested = a.objects.first[0].nested_compound_file;
    assert.equal(nested.bytes, vba.length);
    assert.ok(nested.applications.includes("VBA project"));
    assert.equal(nested.vba_projects[0].modules[0].name, "Module1");
    assert.equal(nested.vba_projects[0].storage, "Macros/VBA");
    // A payload that only begins like a compound file is said, not trusted.
    const bad = Buffer.concat([Buffer.from("d0cf11e0a1b11ae1", "hex"), Buffer.alloc(100, 1)]);
    const b = (await run(cwd, "bad.rtf", `{\\rtf1${objectGroup(ole1Object("Package", bad))}}`)).a;
    assert.equal(b.status, "partial");
    assert.ok(b.problems.some((p: string) => /begins like a compound file and is not read as one/.test(p)), JSON.stringify(b.problems));
  });
});

test("rtf:<n> writes the object's data, hex decoded, exactly; a data group with no end is a problem", async () => {
  await withCwd(async (cwd) => {
    const obj = ole1Object(CLASS, buildCfb([{ name: "WordDocument", data: wordFib() }]));
    const text = `{\\rtf1${objectGroup(obj, { wrap: 80 })}${objectGroup(Buffer.from("second object bytes"), { cls: "Other.Class" })}}`;
    const { a } = await run(cwd, "e.rtf", text, { extract_to: "work/s1/e", extract: ["rtf:1", "rtf:2"] });
    assert.equal(a.objects.count, 2);
    const files = await Promise.all(a.extracted.map(async (r: Json) => [r.locator, await readFile(join(cwd, r.file))] as const));
    const byLoc = Object.fromEntries(files);
    assert.ok((byLoc["rtf object 1"] as Buffer).equals(obj));
    assert.ok((byLoc["rtf object 2"] as Buffer).equals(Buffer.from("second object bytes")));
    const open = (await run(cwd, "open.rtf", "{\\rtf1{\\object\\objemb{\\*\\objdata 0105000002")).a;
    assert.equal(open.status, "partial");
    assert.ok(open.problems.some((p: string) => /still open/.test(p)));
  });
});

test("\\binN skips N raw bytes: braces and control words inside them are not groups and not objects; a \\bin that declares more than the file holds is a problem", async () => {
  await withCwd(async (cwd) => {
    const raw = "{\\*\\objdata 0105}}}{{{";
    const { a } = await run(cwd, "bin.rtf", `{\\rtf1{\\pict\\bin${raw.length} ${raw}}{\\par}}`);
    assert.equal(a.status, "complete", JSON.stringify(a.problems));
    assert.equal(a.objects.count, 0);
    assert.equal(a.structure.groups, 3, "the braces inside the binary block are not groups");
    assert.deepEqual({ blocks: a.structure.binary_blocks, bytes: a.structure.binary_bytes }, { blocks: 1, bytes: raw.length });
    assert.equal(a.control_words.watched.objdata, undefined);
    const over = (await run(cwd, "binover.rtf", "{\\rtf1{\\pict\\bin99999 xx}}")).a;
    assert.ok(over.problems.some((p: string) => /declares more bytes than the file holds/.test(p)), JSON.stringify(over.problems));
  });
});

test("brace balance: groups left open, a stray closing brace and bytes after the last group are each a problem with its count", async () => {
  await withCwd(async (cwd) => {
    const open = (await run(cwd, "open.rtf", "{\\rtf1{\\b open{\\i")).a;
    assert.deepEqual({ open: open.structure.open_groups_at_end, status: open.status }, { open: 3, status: "partial" });
    assert.ok(open.problems.some((p: string) => /3 group\(s\) still open/.test(p)));
    const stray = (await run(cwd, "stray.rtf", "{\\rtf1 x}}}")).a;
    assert.equal(stray.structure.close_without_open, 2);
    assert.ok(stray.problems.some((p: string) => /2 closing brace/.test(p)));
    const tail = (await run(cwd, "tail.rtf", "{\\rtf1 x} MZ trailing bytes\n")).a;
    assert.equal(tail.bytes_after_last_group, "MZ trailing bytes".length);
    const lead = (await run(cwd, "lead.rtf", "JUNKJUNK{\\rtf1 x}")).a;
    assert.equal(lead.rtf_header_offset, 8);
    assert.ok(lead.problems.some((p: string) => /header starts at offset 8/.test(p)));
  });
});

test("nesting past max_depth is a limit, the counts stay right, and 10,000 open groups do not break the tool", async () => {
  await withCwd(async (cwd) => {
    const n = 10000;
    const { a } = await run(cwd, "deep.rtf", `{\\rtf1${"{".repeat(n)}x${"}".repeat(n)}}`, { max_depth: 100 });
    assert.equal(a.structure.max_depth_seen, n + 1);
    assert.equal(a.structure.open_groups_at_end, 0, "every brace was matched");
    assert.equal(a.structure.depth_over_limit, true);
    assert.ok(a.limits_hit.some((l: string) => /nest to 10001, past max_depth \(100\)/.test(l)), JSON.stringify(a.limits_hit));
  });
});

test("fields and templates are reported by their first word and length; the whole text is in the values file only, in a job", async () => {
  await withCwd(async (cwd) => {
    const instr = 'DDEAUTO c:\\windows\\system32\\cmd.exe "/c planted-command"'; // the text a reader shows: single backslashes
    const rtfInstr = instr.replace(/\\/g, "\\\\"); // written in the file with each backslash escaped, as RTF requires
    const template = "http://user:hunter2@host.example.test/tpl.dotm";
    const text = `{\\rtf1{\\field{\\*\\fldinst ${rtfInstr}}{\\fldrslt x}}{\\*\\template ${template}}{\\*\\datastore 0102}}`;
    await put(cwd, "work/f.rtf", text);
    const r = await asJob(DOC_STRUCTURE, cwd, { path: "work/f.rtf", write_values: true });
    const a = body(r);
    assert.equal(a.fields.count, 1);
    assert.equal(a.fields.listed[0].instruction_word, "DDEAUTO");
    assert.equal(a.fields.listed[0].instruction_length, instr.length);
    assert.equal(a.templates[0].target_length, template.length);
    assert.match(a.templates[0].target, /^http:\/\/<userinfo withheld \d+ characters>@host\.example\.test\/tpl\.dotm$/);
    assert.equal(a.data_stores, 1);
    for (const secret of ["planted-command", "hunter2", "cmd.exe"]) assert.ok(!r.stdout.includes(secret), secret);
    const values = (await readFile(join(cwd, "out", "doc-structure-values.jsonl"), "utf8")).trim().split("\n").map((l) => JSON.parse(l));
    assert.deepEqual(values.map((v) => v.value).sort(), [instr, template].sort());
  });
});

test("an odd number of hex digits and bytes that are not hex are problems with their counts; a class name that is token-shaped is withheld", async () => {
  await withCwd(async (cwd) => {
    const token = "Zk9mQ2xW7vB3nL8pR4tY6wD1sFgHjK";
    const { a, text } = await run(cwd, "odd.rtf", `{\\rtf1{\\object\\objemb{\\*\\objclass ${token}}{\\*\\objdata 01050000 0 zz}}}`);
    assert.equal(a.status, "partial");
    assert.ok(a.problems.some((p: string) => /odd number of hex digits/.test(p)), JSON.stringify(a.problems));
    assert.ok(a.problems.some((p: string) => /2 byte\(s\) of its data are not hex digits/.test(p)), JSON.stringify(a.problems));
    assert.ok(!text.includes(token));
    assert.match(a.objects.first[0].class_name, /^<token-shaped text withheld 30 characters>$/);
  });
});

test("thirty million open braces end at the clock: partial, the counts are lower bounds, and the call returns", async () => {
  await withCwd(async (cwd) => {
    const t0 = Date.now();
    const { a } = await run(cwd, "storm.rtf", Buffer.concat([Buffer.from("{\\rtf1"), Buffer.alloc(30_000_000, 0x7b)]), { max_seconds: 1 });
    assert.ok(Date.now() - t0 < 20000, "the call returned");
    assert.equal(a.status, "partial");
    assert.ok(a.limits_hit.some((l: string) => /max_seconds/.test(l) && /lower bounds/.test(l)), JSON.stringify(a.limits_hit));
  });
});
