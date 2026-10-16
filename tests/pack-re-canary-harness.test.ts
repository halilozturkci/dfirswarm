/**
 * The canary harness: every string slot of a PDF, an RTF, an OLE compound file, an OOXML package and a PE holds a canary of its own (a
 * GitHub token, an AWS key id, a long hex secret, a URL whose user-info holds a password), member and storage names and nested names
 * included, dictionary keys included; each seed is then mutated (bytes flipped, inserted or blanked outside the canaries, the file cut,
 * a piece repeated) so that the readers' error paths and their messages are reached too. For every run, in a job and outside one, with
 * limit 1 so that every table is written to a file: stdout, stderr, every file the call writes and every file NAME hold no window of
 * nine characters of any canary (the rule allows the first four and the last four of a secret, never more), in the canary's own bytes,
 * in hex or in UTF-16, and no six characters of a password. The one exception is the private names file (mode 0600), which holds the
 * real names by design. A canary that a mutation cut in two is left out of the window check for that run: a fragment in the file is
 * not a token any more, and no shape-based withholding can know it was one.
 *
 * The seeds are built from the formats' own rules (ISO 32000-1, the RTF specification and [MS-OLEDS], [MS-CFB] / [MS-OVBA] /
 * [MS-XLS] / [MS-OFFCRYPTO], ECMA-376-2 and the PKWARE APPNOTE, the PE/COFF specification), never from a tool's output.
 */
import assert from "node:assert/strict";
import { readFile, rm, stat } from "node:fs/promises";
import { join } from "node:path";
import { test } from "node:test";
import { DOC_STRUCTURE, PE_DIRECTORIES, asJob, buildZip, filesUnder, put, tool, withCwd } from "./pack-re-harness.ts";
import type { Run } from "./pack-re-harness.ts";
import { agileEncryptionInfo, buildCfb, buildPdf, buildPeDirs, buildVbaProject, excelWorkbook, hex, ole1Object, versionResource } from "./pack-re-doc-fixtures.ts";
import type { PdfObj } from "./pack-re-doc-fixtures.ts";

/** A small deterministic generator (mulberry32), so that every run plants and mutates the same way. */
function prng(seed: number): () => number {
  let a = seed >>> 0;
  return () => {
    a = (a + 0x6d2b79f5) >>> 0;
    let t = a;
    t = Math.imul(t ^ (t >>> 15), t | 1);
    t ^= t + Math.imul(t ^ (t >>> 7), t | 61);
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}

const ALNUM = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
const UPPER = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";

/** The canaries of one seed: each one made once, for one slot. */
class Canaries {
  all: string[] = [];
  passwords: string[] = [];
  private rnd: () => number;
  constructor(seed: number) {
    this.rnd = prng(seed);
  }
  private pick(alphabet: string, n: number): string {
    let s = "";
    for (let i = 0; i < n; i++) s += alphabet[Math.floor(this.rnd() * alphabet.length)];
    return s;
  }
  private keep(s: string): string {
    this.all.push(s);
    return s;
  }
  ghp(len = 40): string { return this.keep("ghp_" + this.pick(ALNUM, len - 4)); }
  /** Letters only, with the case flips of a random token: what a control word or an XML attribute name can hold. */
  letters(len = 30): string { return this.keep(this.pick("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz", len)); }
  akia(): string { return this.keep("AKIA" + this.pick(UPPER, 16)); }
  hex(len = 40): string { return this.keep(this.pick("0123456789abcdef", len)); }
  password(): string {
    const p = "Pw" + this.pick(ALNUM, 10);
    this.passwords.push(p);
    return p;
  }
  url(): string { return `https://user${this.pick("abc", 2)}:${this.password()}@host.example/p`; }
  /** A key id split by a line break, which RTF readers ignore: planted in two pieces, checked whole (and by its windows) in the output. */
  split: string[] = [];
  akiaSplit(at: number, by: string): string {
    const key = this.akia();
    this.split.push(key, key.slice(0, at), key.slice(at));
    return key.slice(0, at) + by + key.slice(at);
  }
}

type Seed = { name: string; tool: string; ext: string; data: Buffer; canaries: Canaries };

const forms = (c: string): Buffer[] => {
  const u16 = Buffer.from(c, "utf16le").toString("hex");
  return [Buffer.from(c, "latin1"), Buffer.from(Buffer.from(c, "latin1").toString("hex"), "latin1"), Buffer.from(Buffer.from(c, "latin1").toString("hex").toUpperCase(), "latin1"), Buffer.from(c, "utf16le"),
    Buffer.from(u16, "latin1"), Buffer.from(u16.toUpperCase(), "latin1")];
};

/** Where each canary lies in the seed, in every form a format stores it (its bytes, hex, UTF-16): the ranges a mutation must not touch. */
function ranges(data: Buffer, canaries: string[], extra: string[] = []): { canary: string; start: number; end: number }[] {
  const out: { canary: string; start: number; end: number }[] = [];
  for (const c of [...canaries, ...extra]) {
    for (const f of forms(c)) {
      for (let at = data.indexOf(f); at >= 0; at = data.indexOf(f, at + 1)) out.push({ canary: c, start: at, end: at + f.length });
    }
  }
  return out;
}

/** One mutant of a seed: the bytes, and the canaries still whole in it. */
function mutate(seed: Seed, k: number): { data: Buffer; whole: string[] } {
  const rnd = prng(1000 + k * 7919 + seed.name.length);
  let data = Buffer.from(seed.data);
  const extra = [...seed.canaries.passwords, ...seed.canaries.split];
  let marks = ranges(data, seed.canaries.all, extra);
  const cut = new Set<string>();
  const free = (at: number): boolean => !marks.some((r) => r.start <= at && at < r.end);
  const freeAt = (): number => {
    for (let i = 0; i < 64; i++) {
      const at = Math.floor(rnd() * data.length);
      if (free(at)) return at;
    }
    return -1;
  };
  const ops = 1 + Math.floor(rnd() * 3);
  for (let i = 0; i < ops; i++) {
    const op = Math.floor(rnd() * 5);
    if (op === 0) {
      // flip bytes: a length, an offset, a count, a keyword
      for (let n = 0; n < 1 + Math.floor(rnd() * 6); n++) {
        const at = freeAt();
        if (at >= 0) data[at] = data[at]! ^ (1 + Math.floor(rnd() * 255));
      }
    } else if (op === 1) {
      // blank four bytes: an offset or a size field read as 0xFFFFFFFF
      const at = freeAt();
      if (at >= 0) for (let j = at; j < Math.min(data.length, at + 4) && free(j); j++) data[j] = 0xff;
    } else if (op === 2) {
      // insert junk: every offset after it moves
      const at = freeAt();
      if (at >= 0) data = Buffer.concat([data.subarray(0, at), Buffer.from(Array.from({ length: 1 + Math.floor(rnd() * 64) }, () => Math.floor(rnd() * 256))), data.subarray(at)]);
    } else if (op === 3) {
      // cut the file: a canary the cut falls inside is no longer a token
      const at = Math.max(16, Math.floor(rnd() * data.length));
      for (const r of marks) if (r.start < at && at < r.end) cut.add(r.canary);
      data = data.subarray(0, at);
    } else {
      // repeat a piece: a duplicated object, entry or member
      const a = freeAt(), b = freeAt();
      if (a >= 0 && b >= 0) {
        const [lo, hi] = a < b ? [a, b] : [b, a];
        const at = freeAt();
        if (at >= 0 && hi - lo < 1 << 16) data = Buffer.concat([data.subarray(0, at), data.subarray(lo, hi), data.subarray(at)]);
      }
    }
    marks = ranges(data, seed.canaries.all, extra);
  }
  return { data, whole: seed.canaries.all.filter((c) => !cut.has(c)) };
}

/** Every nine-character window of each canary, in its bytes, in hex and in UTF-16; and every six characters of each password. */
function needles(whole: string[], passwords: string[]): { text: string; hexed: boolean; bytes: Buffer; label: string }[] {
  const out: { text: string; hexed: boolean; bytes: Buffer; label: string }[] = [];
  for (const c of whole) {
    for (let i = 0; i + 9 <= c.length; i++) {
      const w = c.slice(i, i + 9);
      out.push({ text: w, hexed: false, bytes: Buffer.from(w, "latin1"), label: w });
      out.push({ text: Buffer.from(w, "latin1").toString("hex"), hexed: true, bytes: Buffer.alloc(0), label: `hex of ${w}` });
      out.push({ text: "", hexed: false, bytes: Buffer.from(w, "utf16le"), label: `UTF-16 of ${w}` });
    }
  }
  for (const p of passwords) for (let i = 0; i + 6 <= p.length; i++) out.push({ text: p.slice(i, i + 6), hexed: false, bytes: Buffer.from(p.slice(i, i + 6), "latin1"), label: `password ${p.slice(i, i + 6)}` });
  return out;
}

function hits(where: string, data: Buffer, list: ReturnType<typeof needles>): string[] {
  const lower = data.toString("latin1").toLowerCase();
  const found: string[] = [];
  for (const n of list) {
    if (n.hexed ? lower.includes(n.text) : n.bytes.length && data.includes(n.bytes)) found.push(`${where}: ${n.label}`);
  }
  return found;
}

// --- the seeds --------------------------------------------------------------------------------------------------------------

function pdfSeed(): Seed {
  const c = new Canaries(1);
  const g = (): string => c.ghp(), k = (): string => c.akia(), h = (): string => c.hex();
  const hexOf = (s: string): string => Buffer.from(s, "latin1").toString("hex");
  const objs: PdfObj[] = [
    { num: 1, body: `<< /Type /Catalog /Pages 2 0 R /OpenAction 4 0 R /AA << /WC 5 0 R >> /Names << /JavaScript 7 0 R /EmbeddedFiles 8 0 R >> /Outlines 13 0 R /AcroForm << /Fields [ 14 0 R ] >> /${g()} 1 >>` },
    { num: 2, body: "<< /Type /Pages /Kids [ 3 0 R ] /Count 1 >>" },
    { num: 3, body: "<< /Type /Page /Parent 2 0 R /Annots [ 12 0 R ] /AA << /O 16 0 R >> >>" },
    { num: 4, body: `<< /S /URI /URI (${c.url()}/${g()}?k=${h()}#${g()}) /Next 6 0 R >>` },
    { num: 5, body: `<< /S /Launch /F (C:\\\\Users\\\\${g()}\\\\x.exe) /Win << /F (${g()}) /P (${k()}) >> >>` },
    { num: 6, body: `<< /S /SubmitForm /F (https://h.example/${g()}) /Next 20 0 R >>` },
    { num: 7, body: `<< /Names [ (${g()}) 9 0 R <${hexOf(g())}> 10 0 R ] >>` },
    { num: 8, body: `<< /Names [ (${k()}.txt) 11 0 R ] >>` },
    { num: 9, body: `<< /S /JavaScript /JS (var k='${g()}';) >>` },
    { num: 10, body: `<< /S /GoToR /F (${h()}.pdf) >>` },
    { num: 11, body: `<< /Type /Filespec /F (${g()}.txt) /UF <${hexOf(k())}> /EF << /F 15 0 R >> >>` },
    { num: 12, body: `<< /Type /Annot /Subtype /${g()} /Contents (${k()}) /A << /S /URI /URI (http://x.example/${h()}) >> >>` },
    { num: 13, body: "<< /First 17 0 R >>" },
    { num: 14, body: `<< /T (${g()}) /A << /S /Named /N /${k()} >> >>` },
    { num: 15, body: `<< /Type /EmbeddedFile /Subtype /${g()} >>`, stream: Buffer.from(`content ${g()}`) },
    { num: 16, body: "<< /S /JavaScript /JS 18 0 R >>" },
    { num: 17, body: `<< /Title (${g()}) /A << /S /URI /URI (mailto:me:${c.password()}@host.example) >> >>` },
    { num: 18, body: `<< /Filter /${g()} /DecodeParms << /${k()} 1 >> >>`, stream: Buffer.from("x") },
    { num: 19, body: `<< /Type /${k()} /${g()} (${h()}) /K [ ${g()} ] >>` },
    { num: 20, body: `<< /S /URI /URI (//${c.password()}:${c.password()}@h.example/) /Next 6 0 R >>` },
    { num: 21, body: `${k()} ${g()}` },
    { num: 22, body: `%${g()}\n<< /Type /X /${h()} /Y >>` },
  ];
  return { name: "c.pdf", tool: DOC_STRUCTURE, ext: "pdf", data: buildPdf(objs, `/Root 1 0 R /${g()} (${k()}) /Info << /Author (${g()}) >>`).file, canaries: c };
}

function pdfEncryptedSeed(): Seed {
  const c = new Canaries(2);
  const g = (): string => c.ghp(), k = (): string => c.akia();
  const objs: PdfObj[] = [
    { num: 1, body: `<< /Type /Catalog /Pages 2 0 R /OpenAction 4 0 R /Names << /EmbeddedFiles 5 0 R >> >>` },
    { num: 2, body: "<< /Type /Pages /Kids [ ] /Count 0 >>" },
    { num: 4, body: `<< /S /URI /URI (${g()}) >>` },
    { num: 5, body: `<< /Names [ (${g()}) 6 0 R ] >>` },
    { num: 6, body: `<< /Type /Filespec /F (${k()}) >>` },
    { num: 7, body: `<< /Filter /Standard /V 4 /R 4 /Length 128 /P -4 /CF << /${g()} << /CFM /${k()} /AuthEvent /${g()} >> /StdCF << /CFM /AESV2 >> >> /StmF /StdCF /StrF /${g()} /O (${g()}) /U (${g()}) >>` },
  ];
  return { name: "e.pdf", tool: DOC_STRUCTURE, ext: "pdf", data: buildPdf(objs, "/Root 1 0 R /Encrypt 7 0 R /ID [<00> <00>]").file, canaries: c };
}

function rtfSeed(): Seed {
  const c = new Canaries(3);
  const g = (): string => c.ghp(), k = (): string => c.akia(), h = (): string => c.hex();
  const vba = buildVbaProject([{ name: c.ghp(27), source: "Sub A()\r\nEnd Sub\r\n" }], { project: `ID="{00000000-0000-0000-0000-000000000000}"\r\nModule=M\r\nName="${k()}"\r\n` });
  const text = `{\\rtf1\\ansi{\\*\\${c.letters()}}` +
    `{\\object\\objemb{\\*\\objclass ${g()}}{\\*\\objname ${k()}}{\\*\\objdata ${hex(ole1Object(`Pkg${g()}`, Buffer.from(k())))}}}` +
    `{\\object\\objemb{\\*\\objclass Word.Document.8}{\\*\\objdata ${hex(ole1Object("Word.Document.8", vba))}}}` +
    `{\\field{\\*\\fldinst HYPERLINK "${c.url()}/${g()}"}{\\fldrslt ${k()}}}` +
    `{\\field{\\*\\fldinst ${k()} ${g()}}{\\fldrslt x}}` +
    `{\\field{\\*\\fldinst QUOTE {\\field{\\*\\fldinst DDEAUTO ${h()} ${g()}}}}}` +
    `{\\*\\template https://${h()}.example/t.dotm}{\\*\\template \\\\\\\\${k()}\\\\share\\\\${g()}.dotm}` +
    `\\${k()} \\${c.letters(32)} text ${g()} \\'41\\'42 {\\*\\datastore ${hex(Buffer.from(g()))}}` +
    `{\\object\\objemb{\\*\\objclass ${c.akiaSplit(9, "\r\n")}}{\\*\\objdata 00}}}`;
  return { name: "c.rtf", tool: DOC_STRUCTURE, ext: "rtf", data: Buffer.from(text, "latin1"), canaries: c };
}

function rtfHeaderSeed(): Seed {
  const c = new Canaries(4);
  return { name: "h.rtf", tool: DOC_STRUCTURE, ext: "rtf", data: Buffer.from(`{\\rt${c.akia()}{\\${c.akia()} x}{\\*\\${c.letters()} y}}`, "latin1"), canaries: c };
}

function oleSeed(): Seed {
  const c = new Canaries(5);
  const cfb = buildCfb([
    { name: c.ghp(27), data: Buffer.from("x"), clsid: Buffer.from(c.ghp(16), "latin1") },
    { name: c.akia(), children: [{ name: c.hex(30), data: Buffer.alloc(5000, 0x41) }] },
    { name: "Workbook", data: excelWorkbook({ sheets: [{ name: c.ghp(27) }, { name: c.akia(), state: 2, kind: 1 }] }) },
    { name: "\u0006DataSpaces", children: [{ name: "TransformInfo", children: [{ name: c.ghp(27), children: [{ name: "x", data: Buffer.from("y") }] }] }] },
    { name: "EncryptionInfo", data: Buffer.from(agileEncryptionInfo({ salt: c.ghp() }).toString("latin1").replace('cipherAlgorithm="AES"', `cipherAlgorithm="${c.ghp()}"`), "latin1") },
    { name: "EncryptedPackage", data: Buffer.concat([Buffer.from([16, 0, 0, 0, 0, 0, 0, 0]), Buffer.from(c.ghp())]) },
  ], { rootClsid: Buffer.from(c.ghp(16), "latin1") });
  return { name: "c.xls", tool: DOC_STRUCTURE, ext: "xls", data: cfb, canaries: c };
}

function vbaSeed(): Seed {
  const c = new Canaries(6);
  const data = buildVbaProject([{ name: c.ghp(27), source: "Sub A()\r\nEnd Sub\r\n" }, { name: c.akia(), source: "Sub B()\r\nEnd Sub\r\n" }],
    { project: `ID="{00000000-0000-0000-0000-000000000000}"\r\nName="${c.ghp()}"\r\nDPB="${c.hex()}"\r\nCMG="${c.hex()}"\r\n`, storage: c.ghp(27) });
  return { name: "v.bin", tool: DOC_STRUCTURE, ext: "bin", data, canaries: c };
}

function zipSeed(): Seed {
  const c = new Canaries(7);
  const g = (): string => c.ghp(), k = (): string => c.akia();
  const types = `<?xml version="1.0"?><Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types"><Default Extension="${k()}" ContentType="application/${g()}"/><Override PartName="/word/${g()}.xml" ContentType="${g()}"/></Types>`;
  const settings = `<?xml version="1.0"?><w:settings xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main"><w:documentProtection w:edit="${g()}" w:${c.letters()}="1" w:hashValue="${k()}" w:saltValue="${g()}"/></w:settings>`;
  const zip = buildZip([
    { name: "[Content_Types].xml", data: Buffer.from(types), method: 0 },
    { name: "word/settings.xml", data: Buffer.from(settings), method: 0 },
    { name: `word/${g()}/vbaProject.bin`, data: buildVbaProject([{ name: c.ghp(27), source: "Sub A()\r\nEnd Sub\r\n" }]), method: 0 },
    { name: `word/VBAPROJECT.BIN`, data: buildVbaProject([{ name: c.akia(), source: "Sub B()\r\nEnd Sub\r\n" }], { storage: c.ghp(27) }), method: 0 },
    { name: `xl/${k()}/media/${c.hex()}.png`, data: Buffer.from("png"), method: 0 },
    { name: `customXml/${g()}.xml`, data: Buffer.from(`<?xml version="1.0" encoding="${g()}"?><x/>`), method: 0 },
  ], { comment: g() });
  return { name: "c.docm", tool: DOC_STRUCTURE, ext: "docm", data: zip, canaries: c };
}

function peSeed(): Seed {
  const c = new Canaries(8);
  const g = (): string => c.ghp(), k = (): string => c.akia();
  const manifest = Buffer.from(`<?xml version="1.0"?><assembly><trustInfo><security><requestedPrivileges><requestedExecutionLevel level="${g()}" uiAccess="${k()}"/></requestedPrivileges></security></trustInfo></assembly>`);
  const pe = buildPeDirs({
    exports: { imageName: `${g()}.dll`, functions: [{ name: k() }, { name: `x${g()}` }, { name: "Plain", forward: `HOST.${g()}` }] },
    delayImports: [{ dll: `${k()}.dll`, functions: [g(), "plain", 7] }],
    resources: [
      { type: c.ghp(30), name: k(), lang: 1033, data: Buffer.from("r") },
      { type: 16, name: 1, lang: 1033, data: versionResource({ strings: { CompanyName: g(), [k()]: "x", FileDescription: k(), Comments: c.url() } }) },
      { type: 24, name: 1, lang: 1033, data: manifest },
    ],
    debug: [{ type: 2, pdb: `C:\\${g()}\\${k()}.pdb`, guid: Buffer.from(c.ghp(16), "latin1") }],
    clr: { version: c.ghp(30), streams: [{ name: c.akia(), size: 4 }, { name: "#~", size: 4 }] },
  });
  return { name: "c.dll", tool: PE_DIRECTORIES, ext: "dll", data: pe.file, canaries: c };
}

// --- the run --------------------------------------------------------------------------------------------------------------

async function check(cwd: string, seed: Seed, data: Buffer, whole: string[], job: boolean, label: string): Promise<string[]> {
  await rm(join(cwd, "work"), { recursive: true, force: true });
  await rm(join(cwd, "out"), { recursive: true, force: true });
  await put(cwd, `work/in/${seed.name}`, data);
  const args = { path: `work/in/${seed.name}`, limit: 1 };
  const r: Run = job ? await asJob(seed.tool, cwd, args) : await tool(seed.tool, cwd, args);
  assert.doesNotMatch(r.stderr, /Traceback/, `${label}: a traceback`);
  const answer = JSON.parse(r.stdout);
  assert.ok(typeof answer.status === "string", `${label}: no status`);
  const list = needles(whole, seed.canaries.passwords);
  const found = [...hits(`${label} stdout`, Buffer.from(r.stdout), list), ...hits(`${label} stderr`, Buffer.from(r.stderr), list)];
  for (const dir of ["work", "out"]) {
    for (const f of await filesUnder(join(cwd, dir)).catch(() => [] as string[])) {
      if (dir === "work" && f.startsWith("in/")) continue;
      found.push(...hits(`${label} file name ${dir}/${f}`, Buffer.from(f), list));
      if (/withheld-names/.test(f)) {
        assert.equal((await stat(join(cwd, dir, f))).mode & 0o777, 0o600, `${label}: ${dir}/${f} is the private names file and must be 0600`);
        continue;
      }
      found.push(...hits(`${label} ${dir}/${f}`, await readFile(join(cwd, dir, f)), list));
    }
  }
  return found;
}

const SEEDS = [pdfSeed, pdfEncryptedSeed, rtfSeed, rtfHeaderSeed, oleSeed, vbaSeed, zipSeed, peSeed];
const MUTANTS = 24;

for (const make of SEEDS) {
  const seed = make();
  test(`canary harness: ${seed.name} (${seed.canaries.all.length} canaries, ${seed.canaries.passwords.length} passwords), the seed and ${MUTANTS} mutants, in a job and outside one: no window of a canary anywhere the call writes`, async () => {
    await withCwd(async (cwd) => {
      // the seed holds what it should: every canary is planted whole
      for (const cn of seed.canaries.all) assert.ok(seed.canaries.split.includes(cn) || forms(cn).some((f) => seed.data.includes(f)), `${seed.name}: ${cn} is not in the seed`);
      const found: string[] = [];
      found.push(...(await check(cwd, seed, seed.data, seed.canaries.all, false, `${seed.name} seed`)));
      found.push(...(await check(cwd, seed, seed.data, seed.canaries.all, true, `${seed.name} seed (job)`)));
      for (let k = 0; k < MUTANTS; k++) {
        const m = mutate(seed, k);
        found.push(...(await check(cwd, seed, m.data, m.whole, k % 3 === 0, `${seed.name} mutant ${k}${k % 3 === 0 ? " (job)" : ""}`)));
      }
      assert.deepEqual(found.slice(0, 20), [], `${found.length} hit(s)`);
    });
  });
}
