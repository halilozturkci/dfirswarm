/**
 * The slot-by-slot canary harness (the cases and the runner; tests/pack-re-canary-slots-<family>.test.ts run one family each): every string slot of an OLE compound file, an OOXML package, a PDF, an RTF and a PE that the
 * reverse-engineering tools print from (names, paths, targets, keys of dictionaries, name-tree keys, class names, templates, nested
 * names, table and spill files) holds, one file each, a canary of every shape the one way out says it withholds
 * (tests/pack-re-canary-shapes.ts: AWS key ids, GitHub and Slack tokens, `sk-` keys, JWTs, long hex, base64, the AWS secret key with
 * its `/`, a PEM body, URL user-info, a `name:password@` cut after the `@`, a mailto: password, a connection string's password, and
 * a token head after a letter). Each file is read four times: outside a job and in one, with limit 1 (so every table goes to a file)
 * and with the default limit. stdout, stderr, every file the call writes and every file NAME hold no nine characters of a canary (the
 * rule allows four and four of a secret, never more) and no six of a password, in the canary's bytes, in hex or in UTF-16. The private
 * names file (mode 0600) holds the real names by design and is only checked for its mode.
 *
 * The fixtures are built from the formats' own rules ([MS-CFB], [MS-OVBA], [MS-XLS], [MS-OFFCRYPTO], [MS-PPT], ECMA-376-2 and the
 * PKWARE APPNOTE, ISO 32000-1, the RTF specification and [MS-OLEDS], the PE/COFF specification), never from a tool's output.
 */
import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { mkdir, mkdtemp, readFile, readdir, rm, stat, writeFile } from "node:fs/promises";
import { cpus, tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "node:test";
import { DOC_STRUCTURE, PE_DIRECTORIES, buildZip, u16, u32 } from "./pack-re-harness.ts";
import { afterTokenRun, agileEncryptionInfo, buildCfb, buildPdf, buildPeDirs, buildVbaProject, excelWorkbook, hex, ole1Object, ovbaCompress, vbaDirStream, versionResource } from "./pack-re-doc-fixtures.ts";
import type { PdfObj } from "./pack-re-doc-fixtures.ts";
import { canaries, needles } from "./pack-re-canary-shapes.ts";
import type { Canary } from "./pack-re-canary-shapes.ts";

export type Family = "ole" | "zip" | "pdf" | "rtf" | "pe";
type Case = { file: string; tool: string; family: Family; slot: string; shape: string; canary: Canary; data: () => Buffer | null };

const cases: Case[] = [];
let seed = 1;
/** Every slot with every shape that fits it. A file is built only when its family's suite runs it. */
function each(family: Family, max: number, tool: string, ext: string, slots: Record<string, (c: Canary) => Buffer | null>): void {
  for (const [slot, make] of Object.entries(slots)) {
    for (const [shape, canary] of canaries(max, seed++)) cases.push({ file: `${slot}__${shape}${ext}`, tool, family, slot, shape, canary, data: () => make(canary) });
  }
}

const pad = (b: Buffer): Buffer => Buffer.concat([b, Buffer.alloc(Math.max(0, 4200 - b.length))]);
const xml = (s: string): string => s.replace(/&/g, "&amp;").replace(/"/g, "&quot;").replace(/</g, "&lt;");

// --- OLE: names hold at most 31 UTF-16 code units ([MS-CFB] 2.6.1) ----------------------------------------------------------------
each("ole", 31, DOC_STRUCTURE, ".doc", {
  "ole-stream-name": (c) => buildCfb([{ name: c.plant, data: pad(Buffer.from("x")) }]),
  "ole-storage-name": (c) => buildCfb([{ name: c.plant, children: [{ name: "s", data: pad(Buffer.from("x")) }] }]),
  "ole-vba-module-name": (c) => buildVbaProject([{ name: c.plant, source: "Sub A()\r\nEnd Sub\r\n" }]),
  "ole-vba-storage": (c) => buildVbaProject([{ name: "Module1", source: "Sub A()\r\nEnd Sub\r\n" }], { storage: c.plant }),
  "xls-sheet-name": (c) => buildCfb([{ name: "Workbook", data: pad(excelWorkbook({ sheets: [{ name: c.plant }] })) }]),
  "xls-hidden-macro-sheet": (c) => buildCfb([{ name: "Workbook", data: pad(excelWorkbook({ sheets: [{ name: c.plant, state: 2, kind: 1 }] })) }]),
  "ole-dataspaces-name": (c) => buildCfb([{ name: "\u0006DataSpaces", children: [{ name: "TransformInfo", children: [{ name: c.plant, children: [{ name: "x", data: Buffer.from("y") }] }] }] }]),
});
each("ole", 200, DOC_STRUCTURE, ".doc", {
  "vba-project-name": (c) => {
    const mods = [{ name: "Module1", source: "Sub A()\r\nEnd Sub\r\n" }];
    const dir = ovbaCompress(vbaDirStream(mods, [24], { name: c.plant }));
    const vba = { name: "VBA", children: [{ name: "dir", data: dir }, { name: "_VBA_PROJECT", data: Buffer.concat([u16(0x61cc), u16(0xffff), Buffer.from([0]), u16(0), Buffer.alloc(40, 0x11)]) },
      { name: "Module1", data: Buffer.concat([Buffer.alloc(24, 0xab), ovbaCompress(Buffer.from("Sub A()\r\nEnd Sub\r\n"))]) }] };
    return buildCfb([vba, { name: "PROJECT", data: Buffer.from(`Name="${c.plant}"\r\nModule=Module1\r\n`) }]);
  },
  "encryption-csp-name": (c) => {
    const header = Buffer.concat([u32(0x24), u32(0), u32(0x660e), u32(0x8004), u32(128), u32(0x18), u32(0), u32(0), Buffer.from(c.plant + "\0", "utf16le")]);
    const ver = Buffer.concat([u32(16), Buffer.alloc(16, 1), Buffer.alloc(16, 2), u32(20), Buffer.alloc(32, 3)]);
    const ei = Buffer.concat([u16(3), u16(2), u32(0x24), u32(header.length), header, ver]);
    return buildCfb([{ name: "EncryptionInfo", data: pad(ei) }, { name: "EncryptedPackage", data: pad(Buffer.alloc(100)) }]);
  },
  "encryption-agile-attribute": (c) => {
    const ag = Buffer.from(agileEncryptionInfo().toString("latin1").replace('cipherAlgorithm="AES"', `cipherAlgorithm="${xml(c.plant)}"`), "latin1");
    return buildCfb([{ name: "EncryptionInfo", data: pad(ag) }, { name: "EncryptedPackage", data: pad(Buffer.alloc(100)) }]);
  },
  "ppt-current-user": (c) => {
    const nm = Buffer.from(c.plant, "latin1");
    const cu = Buffer.concat([u16(0), u16(0x0ff6), u32(0x14 + 4 + nm.length), u32(0x14), u32(0xe391c05f), u32(0), u16(nm.length), u16(0x03f4), Buffer.from([3, 0]), u16(0), nm, u32(8)]);
    return buildCfb([{ name: "Current User", data: pad(cu) }, { name: "PowerPoint Document", data: pad(Buffer.alloc(10)) }]);
  },
});

// --- ZIP / OOXML --------------------------------------------------------------------------------------------------------------
const CT = (over = ""): string => `<?xml version="1.0" encoding="UTF-8"?><Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types"><Default Extension="xml" ContentType="application/xml"/>` +
  `<Override PartName="/word/document.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml"/>${over}</Types>`;
const zip = (es: [string, string | Buffer][], o: { comment?: string } = {}): Buffer => buildZip(es.map(([n, d]) => ({ name: n, data: Buffer.isBuffer(d) ? d : Buffer.from(d) })), o);
const VP = (): Buffer => buildVbaProject([{ name: "Module1", source: "Sub A()\r\nEnd Sub\r\n" }]);
each("zip", 200, DOC_STRUCTURE, ".docm", {
  "zip-member-name": (c) => zip([["[Content_Types].xml", CT()], [`word/${c.plant}.xml`, "<a/>"], ["word/document.xml", "<a/>"]]),
  "zip-member-name-spilled": (c) => zip([["[Content_Types].xml", CT()], ...Array.from({ length: 150 }, (_x, i): [string, string] => [`word/media/p${i}.xml`, "<a/>"]), [`word/${c.plant}.xml`, "<a/>"]]),
  // part names compare without case: the canary's own spelling and forty case variants of it, every one a spelling of one name
  "zip-member-case-variants": (c) => {
    const name = `word/${c.plant}.xml`;
    const variants = new Set<string>([name]);
    for (let i = 1; variants.size < 41 && i < 400; i++) variants.add([...name].map((ch, k) => ((i >> (k % 9)) & 1 ? ch.toUpperCase() : ch.toLowerCase())).join(""));
    return zip([["[Content_Types].xml", CT()], ...[...variants].map((v): [string, string] => [v, "<a/>"])]);
  },
  "content-types-part-name": (c) => zip([["[Content_Types].xml", CT(`<Override PartName="/word/${xml(c.plant)}" ContentType="application/xml"/>`)], ["word/document.xml", "<a/>"]]),
  "content-types-type": (c) => zip([["[Content_Types].xml", CT(`<Override PartName="/word/a.xml" ContentType="${xml(c.plant)}"/>`)], ["word/document.xml", "<a/>"]]),
  "content-types-default-extension": (c) => zip([["[Content_Types].xml", CT(`<Default Extension="${xml(c.plant)}" ContentType="application/x"/>`)], ["word/document.xml", "<a/>"]]),
  "protection-attribute": (c) => zip([["[Content_Types].xml", CT()], ["word/settings.xml", `<w:settings xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main"><w:documentProtection w:edit="readOnly" w:enforcement="1" w:cryptProviderType="${xml(c.plant)}" w:salt="${xml(c.plant)}"/><w:writeProtection w:recommended="${xml(c.plant)}"/></w:settings>`], ["word/document.xml", "<a/>"]]),
  "nested-vba-label": (c) => zip([["[Content_Types].xml", CT()], ["word/document.xml", "<a/>"], [`word/${c.plant}/vbaProject.bin`, VP()]]),
  "zip-comment": (c) => zip([["[Content_Types].xml", CT()]], { comment: c.plant }),
  "xml-encoding-name": (c) => zip([["[Content_Types].xml", CT()], ["customXml/item1.xml", `<?xml version="1.0" encoding="${xml(c.plant)}"?><x/>`]]),
});
each("zip", 31, DOC_STRUCTURE, ".docm", {
  "nested-vba-module-name": (c) => zip([["[Content_Types].xml", CT()], ["word/document.xml", "<a/>"], ["word/vbaProject.bin", buildVbaProject([{ name: c.plant, source: "Sub A()\r\nEnd Sub\r\n" }])]]),
  "nested-vba-storage-name": (c) => zip([["[Content_Types].xml", CT()], ["word/document.xml", "<a/>"], ["word/vbaProject.bin", buildVbaProject([{ name: "M", source: "Sub A()\r\nEnd Sub\r\n" }], { storage: c.plant })]]),
});

// --- PDF ----------------------------------------------------------------------------------------------------------------------
const lit = (s: string): string => s.replace(/\\/g, "\\\\").replace(/\(/g, "\\(").replace(/\)/g, "\\)");
const nm = (s: string): string => s.replace(/[^A-Za-z0-9_.+-]/g, (ch) => "#" + ch.charCodeAt(0).toString(16).padStart(2, "0"));
const pdf = (catalog: string, more: PdfObj[] = [], trailer = "/Root 1 0 R"): Buffer => buildPdf([{ num: 1, body: `<< /Type /Catalog /Pages 2 0 R ${catalog} >>` },
  { num: 2, body: "<< /Type /Pages /Kids [3 0 R] /Count 1 >>" }, { num: 3, body: "<< /Type /Page /Parent 2 0 R /MediaBox [0 0 10 10] >>" }, ...more], trailer).file;
each("pdf", 2000, DOC_STRUCTURE, ".pdf", {
  "pdf-uri": (c) => pdf(`/OpenAction << /S /URI /URI (${lit(c.plant)}) >>`),
  "pdf-uri-path": (c) => pdf(`/OpenAction << /S /URI /URI (https://h.example/${lit(c.plant)}) >>`),
  "pdf-uri-no-authority": (c) => pdf(`/OpenAction << /S /URI /URI (file:${lit(c.plant)}) >>`),
  "pdf-launch-target": (c) => pdf(`/OpenAction << /S /Launch /F (${lit(c.plant)}) >>`),
  "pdf-launch-path": (c) => pdf(`/OpenAction << /S /Launch /F (C:/x/${lit(c.plant)}) >>`),
  "pdf-gotor-filespec": (c) => pdf(`/OpenAction << /S /GoToR /F << /Type /Filespec /UF (${lit(c.plant)}) /Desc (${lit(c.plant)}) >> /D [0 /Fit] >>`),
  "pdf-submitform-target": (c) => pdf(`/OpenAction << /S /SubmitForm /F << /FS /URL /F (${lit(c.plant)}) >> >>`),
  "pdf-named-action": (c) => pdf(`/OpenAction << /S /Named /N /${nm(c.plant)} >>`),
  "pdf-action-subtype": (c) => pdf(`/OpenAction << /S /${nm(c.plant)} >>`),
  "pdf-catalog-key": (c) => pdf(`/${nm(c.plant)} 1`),
  "pdf-aa-key": (c) => pdf(`/AA << /${nm(c.plant)} << /S /URI /URI (http://h.example/) >> >>`),
  "pdf-type-name-key": (c) => pdf("", [{ num: 4, body: `<< /Type /${nm(c.plant)} >>` }]),
  "pdf-subtype-name": (c) => pdf("", [{ num: 4, body: `<< /Type /X /Subtype /${nm(c.plant)} >>` }]),
  "pdf-filter-chain-key": (c) => pdf("", [{ num: 4, body: `<< /Filter /${nm(c.plant)} >>`, stream: Buffer.from("abc") }]),
  "pdf-annotation-subtype-key": (c) => buildPdf([{ num: 1, body: "<< /Type /Catalog /Pages 2 0 R >>" }, { num: 2, body: "<< /Type /Pages /Kids [3 0 R] /Count 1 >>" },
    { num: 3, body: "<< /Type /Page /Parent 2 0 R /Annots [4 0 R] >>" }, { num: 4, body: `<< /Type /Annot /Subtype /${nm(c.plant)} /A << /S /URI /URI (http://h.example/) >> >>` }], "/Root 1 0 R").file,
  "pdf-annotation-launch": (c) => buildPdf([{ num: 1, body: "<< /Type /Catalog /Pages 2 0 R >>" }, { num: 2, body: "<< /Type /Pages /Kids [3 0 R] /Count 1 >>" },
    { num: 3, body: "<< /Type /Page /Parent 2 0 R /Annots [4 0 R] >>" }, { num: 4, body: `<< /Type /Annot /Subtype /Link /A << /S /Launch /F (${lit(c.plant)}) /Win << /F (${lit(c.plant)}) >> >> >>` }], "/Root 1 0 R").file,
  "pdf-javascript-name-tree-key": (c) => pdf(`/Names << /JavaScript << /Names [(${lit(c.plant)}) << /S /JavaScript /JS (app.alert(1)) >>] >> >>`),
  "pdf-embedded-files-key-and-names": (c) => pdf(`/Names << /EmbeddedFiles << /Names [(${lit(c.plant)}) 5 0 R] >> >>`, [{ num: 5, body: `<< /Type /Filespec /F (${lit(c.plant)}) /UF (${lit(c.plant)}) /Desc (${lit(c.plant)}) /EF << /F 6 0 R >> >>` },
    { num: 6, body: "<< /Type /EmbeddedFile >>", stream: Buffer.from("hello") }]),
  "pdf-filespec-outside-tree": (c) => pdf("", [{ num: 5, body: `<< /Type /Filespec /F (${lit(c.plant)}) /EF << /F 6 0 R >> >>` }, { num: 6, body: "<< /Type /EmbeddedFile >>", stream: Buffer.from("hello") }]),
  "pdf-info-strings": (c) => pdf("", [{ num: 4, body: `<< /Title (${lit(c.plant)}) /Author (${lit(c.plant)}) >>` }], "/Root 1 0 R /Info 4 0 R"),
  "pdf-lexer-error": (c) => pdf("", [{ num: 4, body: `<< /A ${c.plant.replace(/[()<>[\]{}/%]/g, "")} >>` }]),
  "pdf-lexer-error-mid": (c) => pdf("", [{ num: 4, body: `<< /A 1 >> } ${c.plant} ` }]),
  "pdf-trailer-key-and-strings": (c) => pdf("", [], `/Root 1 0 R /ID [(${lit(c.plant)}) (${lit(c.plant)})] /${nm(c.plant)} (${lit(c.plant)})`),
  "pdf-crypt-filter-key": (c) => pdf("", [{ num: 4, body: `<< /Filter /${nm(c.plant)} /V 4 /R 4 /O (${lit(c.plant)}) /U (${lit(c.plant)}) /P -4 /CF << /${nm(c.plant)} << /CFM /AESV2 /AuthEvent /${nm(c.plant)} >> >> /StmF /${nm(c.plant)} /StrF /${nm(c.plant)} >>` }],
    "/Root 1 0 R /Encrypt 4 0 R /ID [(a) (a)]"),
  "pdf-object-stream-header": (c) => pdf("", [{ num: 4, body: "<< /Type /ObjStm /N 1 /First 3 >>", stream: Buffer.from(`${c.plant} 0 ${c.plant}`) }]),
  "pdf-trailer-root-name": (c) => pdf("", [], `/Root /${nm(c.plant)}`),
  "pdf-outline-target": (c) => pdf("/Outlines 4 0 R", [{ num: 4, body: "<< /Type /Outlines /First 5 0 R /Last 5 0 R /Count 1 >>" }, { num: 5, body: `<< /Title (${lit(c.plant)}) /Parent 4 0 R /A << /S /URI /URI (${lit(c.plant)}) >> >>` }]),
  "pdf-form-field": (c) => pdf("/AcroForm << /Fields [4 0 R] >>", [{ num: 4, body: `<< /FT /Tx /T (${lit(c.plant)}) /V (${lit(c.plant)}) /AA << /K << /S /JavaScript /JS (${lit(c.plant)}) >> >> >>` }]),
});

// --- RTF ----------------------------------------------------------------------------------------------------------------------
const rtf = (b: string): Buffer => Buffer.from(`{\\rtf1\\ansi ${b}}`, "latin1");
const PKG = (): string => hex(ole1Object("Package", Buffer.from("x")));
each("rtf", 2000, DOC_STRUCTURE, ".rtf", {
  "rtf-object-class": (c) => rtf(`{\\object\\objemb{\\*\\objclass ${c.plant.replace(/[\\{}]/g, "")}}{\\*\\objdata ${PKG()}}}`),
  "rtf-ole1-class-name": (c) => rtf(`{\\object\\objemb{\\*\\objdata ${hex(ole1Object(c.plant.replace(/[\\{}]/g, ""), Buffer.from("x")))}}}`),
  "rtf-object-name": (c) => rtf(`{\\object\\objemb{\\*\\objname ${c.plant.replace(/[\\{}]/g, "")}}{\\*\\objdata ${PKG()}}}`),
  "rtf-object-data": (c) => rtf(`{\\object\\objemb{\\*\\objdata ${hex(Buffer.from(c.plant, "latin1"))}}}`),
  "rtf-field-hyperlink": (c) => rtf(`{\\field{\\*\\fldinst HYPERLINK "${c.plant.replace(/[\\{}]/g, "")}"}{\\fldrslt x}}`),
  "rtf-field-include": (c) => rtf(`{\\field{\\*\\fldinst INCLUDETEXT "C:/x/${c.plant.replace(/[\\{}]/g, "")}"}{\\fldrslt x}}`),
  "rtf-field-first-word": (c) => rtf(`{\\field{\\*\\fldinst ${c.plant.replace(/[\\{}]/g, "")} x}{\\fldrslt x}}`),
  "rtf-template": (c) => rtf(`{\\*\\template ${c.plant.replace(/[\\{}]/g, "")}}`),
  "rtf-nested-cfb-name": (c) => rtf(`{\\object\\objemb{\\*\\objdata ${hex(ole1Object("Word.Document.8", buildCfb([{ name: c.plant.slice(0, 31), data: pad(Buffer.from("x")) }])))}}}`),
});

// --- PE -------------------------------------------------------------------------------------------------------------------------
each("pe", 200, PE_DIRECTORIES, ".dll", {
  "pe-export-name": (c) => buildPeDirs({ exports: { imageName: "a.dll", functions: [{ name: c.plant }] } }).file,
  "pe-export-image-name": (c) => buildPeDirs({ exports: { imageName: c.plant, functions: [{ name: "f" }] } }).file,
  "pe-export-forwarder": (c) => buildPeDirs({ exports: { imageName: "a.dll", functions: [{ name: "f", forward: "x." + c.plant }] } }).file,
  "pe-delay-dll": (c) => buildPeDirs({ delayImports: [{ dll: c.plant, functions: ["f"] }] }).file,
  "pe-delay-function": (c) => buildPeDirs({ delayImports: [{ dll: "a.dll", functions: [c.plant] }] }).file,
  "pe-resource-type-and-name": (c) => buildPeDirs({ resources: [{ type: c.plant.toUpperCase(), name: c.plant, lang: 1033, data: Buffer.from("abc") }] }).file,
  "pe-version-value": (c) => buildPeDirs({ resources: [{ type: 16, name: 1, lang: 1033, data: versionResource({ strings: { CompanyName: c.plant, OriginalFilename: c.plant, FileDescription: "x" } }) }] }).file,
  "pe-version-key": (c) => buildPeDirs({ resources: [{ type: 16, name: 1, lang: 1033, data: versionResource({ strings: { [c.plant]: "x", CompanyName: "y" } }) }] }).file,
  "pe-pdb-path": (c) => buildPeDirs({ debug: [{ type: 2, pdb: "C:\\b\\" + c.plant + ".pdb" }] }).file,
  "pe-pdb-slashed-path": (c) => buildPeDirs({ debug: [{ type: 2, pdb: "C:/b/" + c.plant + ".pdb" }] }).file,
  "pe-clr-version": (c) => buildPeDirs({ clr: { version: c.plant, streams: [{ name: "#~", size: 16 }] } }).file,
  "pe-manifest-attribute": (c) => buildPeDirs({ resources: [{ type: 24, name: 1, lang: 1033, data: Buffer.from(`<?xml version="1.0"?><assembly><trustInfo><security><requestedPrivileges><requestedExecutionLevel level="${xml(c.plant)}" uiAccess="false"/></requestedPrivileges></security></trustInfo></assembly>`) }] }).file,
});
// a string whose address points right after a run of token characters (a name read a field late): its head is tested with that run
each("pe", 200, PE_DIRECTORIES, ".dll", {
  "pe-export-name-after-token-run": (c) => afterTokenRun([c.plant]),
});
each("pe", 31, PE_DIRECTORIES, ".dll", {
  "pe-clr-stream-name": (c) => buildPeDirs({ clr: { version: "v4.0.30319", streams: [{ name: c.plant, size: 16 }, { name: "#~", size: 16 }] } }).file,
});

// --- the runs -------------------------------------------------------------------------------------------------------------------

type Config = { job: boolean; limit: number | null };
// Each file is read twice, in a job and outside one, once with limit 1 (every table to a file) and once with the default; the pairing
// alternates from file to file, so that each slot meets all four combinations across its shapes.
const PAIRS: [Config, Config][] = [[{ job: false, limit: 1 }, { job: true, limit: null }], [{ job: true, limit: 1 }, { job: false, limit: null }]];

function runTool(script: string, cwd: string, args: unknown, env: Record<string, string>): Promise<{ code: number | null; stdout: Buffer; stderr: Buffer }> {
  return new Promise((resolve, reject) => {
    const child = spawn("python3", [script], { cwd, env: { ...process.env, AGENT_ID: "s1", ...env } });
    const out: Buffer[] = [], err: Buffer[] = [];
    child.stdout.on("data", (b: Buffer) => out.push(b));
    child.stderr.on("data", (b: Buffer) => err.push(b));
    child.on("error", reject);
    child.on("close", (code) => resolve({ code, stdout: Buffer.concat(out), stderr: Buffer.concat(err) }));
    child.stdin.end(JSON.stringify(args));
  });
}

async function walk(dir: string, prefix = ""): Promise<string[]> {
  const out: string[] = [];
  for (const e of await readdir(dir, { withFileTypes: true }).catch(() => [])) {
    if (e.isDirectory()) out.push(...(await walk(join(dir, e.name), `${prefix}${e.name}/`)));
    else out.push(`${prefix}${e.name}`);
  }
  return out;
}

async function one(c: Case, cfg: Config): Promise<string[]> {
  const cwd = await mkdtemp(join(tmpdir(), "re-slots-"));
  const label = `${c.file} (${cfg.job ? "job" : "no job"}, limit ${cfg.limit ?? "default"})`;
  try {
    await mkdir(join(cwd, "work", "in"), { recursive: true });
    await writeFile(join(cwd, "work", "in", `sample${c.file.slice(c.file.lastIndexOf("."))}`), c.data()!);
    const env: Record<string, string> = {};
    if (cfg.job) {
      await mkdir(join(cwd, "out"), { recursive: true });
      env.JOB_ID = "j000001";
      env.OUT = join(cwd, "out");
    }
    const args: Record<string, unknown> = { path: `work/in/sample${c.file.slice(c.file.lastIndexOf("."))}` };
    if (cfg.limit !== null) args.limit = cfg.limit;
    const r = await runTool(c.tool, cwd, args, env);
    const found: string[] = [];
    if (/Traceback/.test(r.stderr.toString("utf8"))) found.push(`${label}: a traceback`);
    try {
      const answer = JSON.parse(r.stdout.toString("utf8"));
      if (typeof answer.status !== "string") found.push(`${label}: no status`);
      // the sanitiser itself withholds every shape: the backstop behind it has nothing left to catch
      if (answer.withheld_by_final_check) found.push(`${label}: the final check withheld ${answer.withheld_by_final_check} field(s) the sanitiser let through`);
    } catch {
      found.push(`${label}: stdout is not JSON`);
    }
    const list = needles(c.canary);
    const scan = (where: string, data: Buffer): void => {
      for (const n of list) if (data.includes(n.bytes)) { found.push(`${label}: ${where} holds ${n.label}`); return; }
    };
    scan("stdout", r.stdout);
    scan("stderr", r.stderr);
    for (const dir of ["work", "out"]) {
      for (const f of await walk(join(cwd, dir))) {
        if (dir === "work" && f.startsWith("in/")) continue;
        scan(`the file name ${dir}/${f}`, Buffer.from(f, "utf8"));
        if (/withheld-names/.test(f)) {
          if (((await stat(join(cwd, dir, f))).mode & 0o777) !== 0o600) found.push(`${label}: ${dir}/${f} is the private names file and is not 0600`);
          continue;
        }
        scan(`${dir}/${f}`, await readFile(join(cwd, dir, f)));
      }
    }
    return found;
  } finally {
    await rm(cwd, { recursive: true, force: true });
  }
}

async function pool<T>(items: T[], n: number, fn: (x: T) => Promise<string[]>): Promise<string[]> {
  const out: string[] = [];
  let next = 0;
  await Promise.all(Array.from({ length: n }, async () => {
    while (next < items.length) {
      const k = next++;
      out.push(...(await fn(items[k]!)));
    }
  }));
  return out;
}

/** The suite of one family: every slot of it with every shape, each file read twice (see PAIRS). */
export function slotSuite(family: Family): void {
  const mine = cases.filter((c) => c.family === family && c.data() !== null);
  const slots = new Set(mine.map((c) => c.slot));
  const shapes = new Set(mine.map((c) => c.shape));
  test(`canary slots, ${family}: ${mine.length} files (${slots.size} slots x ${shapes.size} shapes), each read in a job and outside one, with limit 1 and the default: no window of a canary in stdout, stderr, any file or any file name`, { timeout: 280_000 }, async () => {
    // every shape reaches every slot that can hold it, and the short slots get every shape that fits 31 characters
    for (const slot of slots) {
      const n = new Set(mine.filter((c) => c.slot === slot).map((c) => c.shape)).size;
      assert.ok(n >= 11, `${slot}: only ${n} shapes`);
    }
    const runs = mine.flatMap((c, i) => PAIRS[i % 2]!.map((cfg) => ({ c, cfg })));
    const found = await pool(runs, Math.max(2, Math.min(8, Math.floor(cpus().length / 2))), ({ c, cfg }) => one(c, cfg));
    if (process.env.RE_SLOTS_DUMP) await writeFile(`${process.env.RE_SLOTS_DUMP}.${family}`, found.join("\n") + "\n");
    assert.deepEqual(found.slice(0, 40), [], `${found.length} finding(s) over ${runs.length} runs`);
  });
}
