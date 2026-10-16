/**
 * doc_structure, the findings of the fourth review. Each fixture is built from the format's own rules (ECMA-376-2 content types and
 * relationships, the PKWARE APPNOTE's Unicode Path extra field 4.6.9, [MS-CFB] and [MS-OVBA], the RTF specification's \uN and \ucN,
 * [MS-OLEDS] 2.2.4, ISO 32000-1), never from the tool's output, and each test fails on the code before this round.
 */
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { readFile } from "node:fs/promises";
import { join } from "node:path";
import { test } from "node:test";
import { DOC_STRUCTURE, body, buildZip, crc32, put, rels, tool, u16, u32, withCwd } from "./pack-re-harness.ts";
import type { Json } from "./pack-re-harness.ts";
import { buildCfb, buildPdf, buildVbaProject, excelWorkbook, hex } from "./pack-re-doc-fixtures.ts";

const VBA_CT = "application/vnd.ms-office.vbaProject";
const ct = (body: string): string => `<?xml version="1.0" encoding="UTF-8"?><Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">` +
  `<Default Extension="xml" ContentType="application/xml"/><Override PartName="/word/document.xml" ContentType="application/vnd.ms-word.document.macroEnabled.main+xml"/>${body}</Types>`;
const vba = (): Buffer => buildVbaProject([{ name: "Module1", source: "Sub AutoOpen()\r\nEnd Sub\r\n" }]);

function py(code: string): { status: number | null; stdout: string; stderr: string } {
  const r = spawnSync("python3", ["-I", "-c", ["import importlib.util, json, sys", "spec = importlib.util.spec_from_file_location('t', sys.argv[1])",
    "m = importlib.util.module_from_spec(spec)", "spec.loader.exec_module(m)", code].join("\n"), DOC_STRUCTURE], { encoding: "utf8" });
  return { status: r.status, stdout: r.stdout, stderr: r.stderr };
}

async function read(cwd: string, name: string, data: Buffer, extra: Record<string, unknown> = {}): Promise<Json> {
  await put(cwd, `work/${name}`, data);
  return body(await tool(DOC_STRUCTURE, cwd, { path: `work/${name}`, ...extra }));
}

test("P1-3 a VBA project part not named vbaProject.bin is read when the content types or a vbaProject relationship declare it", async () => {
  await withCwd(async (cwd) => {
    const docRels = rels([{ id: "rId1", type: "vbaProject", target: "macros.bin" }]).replace(`${"http://schemas.openxmlformats.org/officeDocument/2006/relationships"}/vbaProject`,
      "http://schemas.microsoft.com/office/2006/relationships/vbaProject");
    const both = await read(cwd, "renamed.docm", buildZip([
      { name: "[Content_Types].xml", data: Buffer.from(ct(`<Override PartName="/word/macros.bin" ContentType="${VBA_CT}"/>`)) },
      { name: "word/document.xml", data: Buffer.from("<w:document/>") }, { name: "word/_rels/document.xml.rels", data: Buffer.from(docRels) },
      { name: "word/macros.bin", data: vba() }]));
    const part = (both.vbaproject_parts as Json[]).find((p) => p.part === "word/macros.bin");
    assert.ok(part, JSON.stringify(both.vbaproject_parts));
    assert.deepEqual(part.selected_by, ["content_type", "relationship"]);
    assert.deepEqual(part.vba_projects[0].modules.map((x: Json) => x.name), ["Module1"]);
    // by the relationship alone, and by a Default extension alone
    const relOnly = await read(cwd, "rel.docm", buildZip([{ name: "[Content_Types].xml", data: Buffer.from(ct("")) }, { name: "word/document.xml", data: Buffer.from("<a/>") },
      { name: "word/_rels/document.xml.rels", data: Buffer.from(docRels) }, { name: "word/macros.bin", data: vba() }]));
    assert.deepEqual(relOnly.vbaproject_parts.map((p: Json) => [p.part, p.selected_by]), [["word/macros.bin", ["relationship"]]]);
    const byExt = await read(cwd, "ext.docm", buildZip([{ name: "[Content_Types].xml", data: Buffer.from(ct(`<Default Extension="dat" ContentType="${VBA_CT}"/>`)) },
      { name: "word/document.xml", data: Buffer.from("<a/>") }, { name: "word/x.dat", data: vba() }]));
    assert.deepEqual(byExt.vbaproject_parts.map((p: Json) => [p.part, p.selected_by]), [["word/x.dat", ["content_type"]]]);
  });
});

test("P1-3 a part's own Override content type wins over the Default of its extension: an Excel package that types .bin as the VBA project reads only its VBA project", async () => {
  await withCwd(async (cwd) => {
    const a = await read(cwd, "excel.xlsm", buildZip([
      { name: "[Content_Types].xml", data: Buffer.from(ct(`<Default Extension="bin" ContentType="${VBA_CT}"/>` +
        `<Override PartName="/xl/printerSettings/printerSettings1.bin" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.printerSettings"/>` +
        `<Override PartName="/xl/activeX/activeX1.bin" ContentType="application/vnd.ms-office.activeX"/>`)) },
      { name: "xl/workbook.xml", data: Buffer.from("<workbook/>") }, { name: "xl/vbaProject.bin", data: vba() },
      { name: "xl/printerSettings/printerSettings1.bin", data: Buffer.alloc(300, 1) }, { name: "xl/activeX/activeX1.bin", data: Buffer.alloc(64, 2) }]));
    assert.deepEqual(a.vbaproject_parts.map((p: Json) => [p.part, p.selected_by]), [["xl/vbaProject.bin", ["content_type", "name"]]]);
    assert.equal(a.status, "complete", JSON.stringify(a.problems));
  });
});

test("P1-3 a declared VBA project part that the package does not hold is a problem, and the answer is partial", async () => {
  await withCwd(async (cwd) => {
    const a = await read(cwd, "missing.docm", buildZip([{ name: "[Content_Types].xml", data: Buffer.from(ct(`<Override PartName="/word/macros.bin" ContentType="${VBA_CT}"/>`)) },
      { name: "word/document.xml", data: Buffer.from("<a/>") }]));
    assert.equal(a.status, "partial");
    assert.ok(a.problems.some((p: string) => /declares word\/macros\.bin its VBA project \(content_type\), and no member of that name is listed/.test(p)), JSON.stringify(a.problems));
  });
});

test("P1-3 an undeclared member that begins with the compound file signature and holds a VBA storage is read and said; an embedded compound file without one is not listed", async () => {
  await withCwd(async (cwd) => {
    const a = await read(cwd, "sig.docx", buildZip([{ name: "[Content_Types].xml", data: Buffer.from(ct("")) }, { name: "word/document.xml", data: Buffer.from("<a/>") },
      { name: "word/embeddings/oleObject1.bin", data: buildCfb([{ name: "\u0001Ole", data: Buffer.alloc(20) }, { name: "Contents", data: Buffer.alloc(5000, 1) }]) },
      { name: "word/media/x.dat", data: vba() }]));
    assert.deepEqual(a.vbaproject_parts.map((p: Json) => [p.part, p.selected_by]), [["word/media/x.dat", ["cfb_signature"]]]);
    assert.match(a.vbaproject_parts[0].note, /no content type, relationship or vbaProject\.bin name declares/);
    assert.deepEqual(a.vbaproject_parts[0].vba_projects[0].modules.map((x: Json) => x.name), ["Module1"]);
  });
});

/** A Unicode Path extra field (APPNOTE 4.6.9): version 1, the CRC-32 of the central name's bytes, then the name in UTF-8. */
const unicodePath = (central: string, name: Buffer): Buffer => {
  const data = Buffer.concat([Buffer.from([1]), u32(crc32(Buffer.from(central, "utf8"))), name]);
  return Buffer.concat([u16(0x7075), u16(data.length), data]);
};

test("P2-6 a Unicode Path field that is not UTF-8 no longer loses the archive; one that renames the VBA project still has it read, by either name", async () => {
  await withCwd(async (cwd) => {
    const base = [{ name: "[Content_Types].xml", data: Buffer.from(ct(`<Override PartName="/word/vbaProject.bin" ContentType="${VBA_CT}"/>`)) },
      { name: "word/document.xml", data: Buffer.from("<a/>") }];
    const bad = await read(cwd, "bad.docm", buildZip([...base, { name: "word/media/a.png", data: Buffer.from("png"), centralExtra: unicodePath("word/media/a.png", Buffer.from([0xff, 0xfe, 0x41])) },
      { name: "word/vbaProject.bin", data: vba() }]));
    assert.equal(bad.status, "partial");
    assert.equal(bad.members.listed, 4);
    assert.equal(bad.vbaproject_parts[0].part, "word/vbaProject.bin");
    assert.ok(bad.problems.some((p: string) => /Unicode Path extra field \(0x7075\)/.test(p)), JSON.stringify(bad.problems));
    // the field renames the VBA project (a reader that honours it no longer sees vbaProject.bin); and the field names an image vbaProject.bin
    const hid = await read(cwd, "hid.docm", buildZip([...base, { name: "word/vbaProject.bin", data: vba(), centralExtra: unicodePath("word/vbaProject.bin", Buffer.from("word/media/image1.png")) }]));
    assert.deepEqual(hid.vbaproject_parts.map((p: Json) => p.part), ["word/vbaProject.bin"]);
    const row = (await readTable(cwd, hid, "parts")).find((r) => r.name === "word/vbaProject.bin");
    assert.equal(row?.unicode_path_field?.name, "word/media/image1.png", JSON.stringify(row));
    assert.equal(row?.local_header_differs, undefined, "read by the central name, the local header agrees");
    const alias = await read(cwd, "alias.docm", buildZip([base[0]!, base[1]!, { name: "word/media/a.png", data: vba(), centralExtra: unicodePath("word/media/a.png", Buffer.from("word/vbaProject.bin")) }]));
    assert.deepEqual(alias.vbaproject_parts.map((p: Json) => [p.part, p.selected_by]), [["word/media/a.png", ["content_type", "name"]]]);
  });
});

async function readTable(cwd: string, a: Json, name: string): Promise<Json[]> {
  const t = a.tables?.[name];
  if (t?.rows) return t.rows as Json[];
  const file = t?.all_results as string;
  return (await readFile(join(cwd, file), "utf8")).split("\n").filter(Boolean).map((l) => JSON.parse(l));
}

const rtf = (s: string): Buffer => Buffer.from(`{\\rtf1\\ansi ${s}}`, "latin1");
const u = (s: string, fallback = "?"): string => s.split("").map((ch) => `\\u${ch.charCodeAt(0) > 32767 ? ch.charCodeAt(0) - 65536 : ch.charCodeAt(0)}${fallback}`).join("");

test("P2-4 \\uN in a field instruction and a template is decoded, its \\ucN fallback dropped: the field type is named and the template target read", async () => {
  await withCwd(async (cwd) => {
    const a = await read(cwd, "u.rtf", rtf(`{\\field{\\*\\fldinst ${u("INCLUDEPICTURE")} "http://h.example/a.png"}{\\fldrslt x}}` +
      `{\\field{\\*\\fldinst {\\uc2 ${u("HYPERLINK", "\\'3f\\'3f")} "http://h.example/"}}{\\fldrslt y}}{\\*\\template ${u("\\\\host.example\\share\\t.dotm")}}` +
      `{\\field{\\*\\fldinst {\\uc0 \\u-3913 ${"QUOTE"}}}{\\fldrslt z}}`));
    assert.deepEqual(a.fields.listed.map((f: Json) => f.instruction_word), ["INCLUDEPICTURE", "HYPERLINK", null]);
    assert.equal(a.fields.listed[0].instruction_length, `INCLUDEPICTURE "http://h.example/a.png"`.length);
    assert.equal(a.templates[0].target, "\\\\\\\\host.example\\\\share\\\\t.dotm");
    assert.equal(a.status, "complete", JSON.stringify(a.problems));
  });
});

test("P2-1 an OLE 1.0 class name written as UTF-16 in its ANSI field is read as UTF-16: a token in it is withheld, a plain class name shown", async () => {
  await withCwd(async (cwd) => {
    const header = (name: Buffer): Buffer => Buffer.concat([u32(0x501), u32(2), u32(name.length), name, u32(0), u32(0), u32(4), Buffer.from("abcd")]);
    const token = "ghp_" + "Ab3dEf5hIj7lMn9pQr1tUv3xYz5bCd7fGh9j";
    const a = await read(cwd, "ole1.rtf", rtf(`{\\object\\objemb{\\*\\objclass Package}{\\*\\objdata ${hex(header(Buffer.from(token + "\0", "utf16le")))}}}` +
      `{\\object\\objemb{\\*\\objclass Package}{\\*\\objdata ${hex(header(Buffer.from("Package\0", "utf16le")))}}}`));
    const [first, second] = a.objects.first as Json[];
    assert.match(first.ole1_header.class_name, /^<token-shaped text withheld \d+ characters>$/);
    assert.equal(first.ole1_header.class_name_encoding, "UTF-16LE in a field MS-OLEDS 2.2.4 makes an ANSI string");
    assert.equal(second.ole1_header.class_name, "Package");
    const text = JSON.stringify(a);
    for (let i = 0; i + 9 <= token.length; i++) assert.ok(!text.includes(token.slice(i, i + 9)) && !text.includes(token.slice(i, i + 9).split("").join("\\\\x00")), token.slice(i, i + 9));
  });
});

test("P2-5 a PDF name is charged by the bytes Python holds it in (four per character past U+FFFF), a key twice, and one parse is bounded by its estimated memory", () => {
  const code = [
    "class M:",
    "    def charge(self, n): pass",
    "name = '\\U0001F600' * 500",
    "raw = ('/' + name).encode('utf-8')",
    "lx = m.Lexer(raw, 0, len(raw), True, 256, M(), 1 << 24)",
    "lx.parse()",
    "d = ('<< /' + name + ' 1 >>').encode('utf-8')",
    "lk = m.Lexer(d, 0, len(d), True, 256, M(), 1 << 24)",
    "lk.parse()",
    "m.PARSE_BYTES = 1 << 20",
    "arr = ('[' + ' '.join('/' + chr(0x1F600 + i % 50) * 500 for i in range(600)) + ']').encode('utf-8')",
    "la = m.Lexer(arr, 0, len(arr), True, 256, M(), 1 << 24)",
    "try:",
    "    la.parse()",
    "    bound = None",
    "except m.ParseBound as exc:",
    "    bound = str(exc)",
    "print(json.dumps({'name': lx.held, 'key': lk.held, 'bound': bound}))",
  ].join("\n");
  const r = py(code);
  assert.equal(r.status, 0, r.stderr);
  const o = JSON.parse(r.stdout) as Json;
  assert.equal(o.name, 2000);
  assert.equal(o.key, 4000);
  assert.match(o.bound, /an object whose parsed values take more than 1048576 bytes of memory \(estimated\) in one parse/);
});

test("P3 two Workbook streams at the root: both are read (the second's very hidden macro sheet is listed) and `ole:Workbook` writes both", async () => {
  await withCwd(async (cwd) => {
    const benign = excelWorkbook({ sheets: [{ name: "Sheet1" }] });
    const macro = excelWorkbook({ sheets: [{ name: "Sheet1" }, { name: "Auto_Open", state: 2, kind: 1 }] });
    const file = buildCfb([{ name: "Workbook", data: Buffer.concat([benign, Buffer.alloc(4200)]) }, { name: "WORKBOOK", data: Buffer.concat([macro, Buffer.alloc(4200)]) }]);
    const a = await read(cwd, "dup.xls", file, { extract: ["ole:Workbook"], extract_to: "work/x" });
    assert.equal(a.status, "partial");
    const copies = [a.excel, ...(a.excel.other_copies ?? [])];
    assert.equal(copies.length, 2, JSON.stringify(a.excel));
    assert.ok(copies.some((c: Json) => c.sheets.some((s: Json) => s.name === "Auto_Open" && s.kind === "Excel 4.0 macro sheet")), JSON.stringify(copies));
    assert.ok(copies.every((c: Json) => typeof c.sid === "number"));
    assert.ok(a.protection_items.some((p: Json) => p.kind === "macro_sheets"));
    assert.equal(a.extracted.filter((e: Json) => e.status === "written").length, 2, JSON.stringify(a.extracted));
    assert.ok(a.problems.some((p: string) => /every copy is read/.test(p)), JSON.stringify(a.problems));
  });
});

test("P3 CFB names compare by the simple upper-case mapping: U+1FB3 and U+1FBC are one name, U+00DF and SS two", () => {
  const r = py("print(json.dumps([m.cfb_key('\\u1fb3') == m.cfb_key('\\u1fbc'), m.cfb_key('\\u00df') == m.cfb_key('SS'), m.cfb_key('dir') == m.cfb_key('DIR')]))");
  assert.equal(r.status, 0, r.stderr);
  assert.deepEqual(JSON.parse(r.stdout), [true, false, true]);
});

test("P3 a class id that spells text with a NUL every few bytes is withheld; an Office class id is printed", () => {
  const r = py([
    "text = bytes(b'ghp_Ab3d\\x00Ef5hIj\\x00')",
    "office = bytes.fromhex('0609020000000000c000000000000046')",
    "print(json.dumps([m.guid(text), m.guid(office)]))",
  ].join("\n"));
  assert.equal(r.status, 0, r.stderr);
  assert.deepEqual(JSON.parse(r.stdout), ["<16 bytes that read as text, withheld>", "00020906-0000-0000-C000-000000000046"]);
});

const pdfPages = (annots: string, extra: { num: number; body: string }[] = []) => buildPdf([{ num: 1, body: "<< /Type /Catalog /Pages 2 0 R >>" },
  { num: 2, body: "<< /Type /Pages /Kids [3 0 R 4 0 R] /Count 2 >>" }, { num: 3, body: `<< /Type /Page /Parent 2 0 R /Annots ${annots} >>` },
  { num: 4, body: `<< /Type /Page /Parent 2 0 R /Annots ${annots} >>` }, ...extra], "/Root 1 0 R").file;

test("P3 a direct action in an /Annots array two pages share is one row, and a direct action's row names the object and key path that hold it", async () => {
  await withCwd(async (cwd) => {
    const a = await read(cwd, "shared.pdf", pdfPages("5 0 R", [{ num: 5, body: "[ << /Type /Annot /Subtype /Link /A << /S /URI /URI (http://h.example/a) >> >> ]" }]));
    assert.equal(a.actions.count, 1, JSON.stringify(a.actions));
    const row = (await readTable(cwd, a, "pdf_actions"))[0]!;
    assert.equal(row.object, null);
    assert.deepEqual(row.held_by, { object: 5, path: "[0]/A" });
  });
});

test("P3 with no catalog, the action objects read are still listed, reached from no catalog", async () => {
  await withCwd(async (cwd) => {
    const file = buildPdf([{ num: 1, body: "<< /Type /NotACatalog >>" }, { num: 5, body: "<< /S /JavaScript /JS (app.alert(1)) >>" }], "/Root 9 0 R").file;
    const a = await read(cwd, "nocat.pdf", file);
    assert.equal(a.status, "partial");
    assert.equal(a.actions.traced, false);
    assert.equal(a.actions.count, 1, JSON.stringify(a.actions));
    assert.equal(a.actions.unreached_from_catalog, 1);
  });
});
