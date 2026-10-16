/**
 * doc_structure, the findings of the review of its first version, one case each, named after the finding. Every hostile file is
 * written here from the format's own rules (ISO 32000-1 for PDF: objects, cross-reference tables and streams, object streams,
 * the ASCII base-85 filter; [MS-CFB] directory entries; [MS-OVBA] chunks; [MS-XLS] FILEPASS and BoundSheet8; ECMA-376-2 part
 * names; the RTF specification and [MS-OLEDS]), never from the tool's output. What these cases hold: a filter's output is held to
 * its budget before it is allocated, the clock holds inside a parse, a failed read is not repeated, a canary planted in every
 * printable place is in no file the call writes, and nothing the review found cut is cut silently.
 */
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import { readFile, stat } from "node:fs/promises";
import { join } from "node:path";
import { test } from "node:test";
import { deflateSync } from "node:zlib";
import { DOC_STRUCTURE, asJob, body, buildZip, filesUnder, put, tool, withCwd } from "./pack-re-harness.ts";
import type { Json, Run } from "./pack-re-harness.ts";
import { buildCfb, buildPdf, buildVbaProject, excelWorkbook, hex, ole1Object, ovbaCompress } from "./pack-re-doc-fixtures.ts";
import type { PdfObj } from "./pack-re-doc-fixtures.ts";
import { u16 } from "./pack-re-harness.ts";

const AKIA = "AKIAIOSFODNN7EXAMPLE";
const GHP = "ghp_Ab3dEf5hIj7lMn9pQr1tUv3xYz5bCd7fGh9j";
const CANARY_SLICES = [AKIA, AKIA.slice(0, 12), GHP, GHP.slice(0, 12), Buffer.from(GHP).toString("hex").slice(0, 16), Buffer.from(AKIA).toString("hex").slice(0, 16)];

async function run(cwd: string, name: string, data: Buffer | string, args: Record<string, unknown> = {}): Promise<{ a: Json; text: string }> {
  await put(cwd, `work/${name}`, data);
  const r = await tool(DOC_STRUCTURE, cwd, { path: `work/${name}`, ...args });
  return { a: body(r), text: r.stdout };
}

/** The tool with a hard limit on its wall time (killed past it, so a hang fails the case instead of the suite) and the child's peak RSS. */
function bounded(cwd: string, args: Record<string, unknown>, killAfterMs: number, env: Record<string, string> = {}): { run: Run; seconds: number; rssMb: number } {
  const wrapper = [
    "import json, resource, subprocess, sys, time",
    "t = time.monotonic()",
    "try:",
    "    p = subprocess.run([sys.executable, sys.argv[1]], input=sys.stdin.buffer.read(), capture_output=True, timeout=float(sys.argv[2]))",
    "    code, out, err = p.returncode, p.stdout.decode('utf-8', 'replace'), p.stderr.decode('utf-8', 'replace')",
    "except subprocess.TimeoutExpired as exc:",
    "    code, out, err = None, (exc.stdout or b'').decode('utf-8', 'replace'), 'killed at the case limit'",
    "r = resource.getrusage(resource.RUSAGE_CHILDREN).ru_maxrss",
    "print(json.dumps({'code': code, 'stdout': out, 'stderr': err, 'seconds': time.monotonic() - t, 'rss_mb': r / (1 << 20) if sys.platform == 'darwin' else r / 1024}))",
  ].join("\n");
  const r = spawnSync("python3", ["-c", wrapper, DOC_STRUCTURE, String(killAfterMs / 1000)], { cwd, input: JSON.stringify(args), encoding: "utf8", maxBuffer: 1 << 28, env: { ...process.env, AGENT_ID: "s1", ...env } });
  assert.equal(r.status, 0, r.stderr);
  const o = JSON.parse(r.stdout);
  return { run: { code: o.code, stdout: o.stdout, stderr: o.stderr }, seconds: o.seconds, rssMb: o.rss_mb };
}

const CATALOG = (extra = ""): PdfObj => ({ num: 1, body: `<< /Type /Catalog /Pages 2 0 R ${extra} >>` });
const PAGES: PdfObj = { num: 2, body: "<< /Type /Pages /Kids [ 3 0 R ] /Count 1 >>" };
const PAGE = (extra = ""): PdfObj => ({ num: 3, body: `<< /Type /Page /Parent 2 0 R ${extra} >>` });

/**
 * A PDF 1.5 file whose cross-reference is a stream (ISO 32000-1 7.5.8: W [1 4 2], no predictor, Flate), with direct objects and,
 * when given, one object stream holding `compressed` (7.5.7: N pairs of "number offset", then the objects from /First). The
 * object stream's data is written with `objstmFilter`'s encoding when given (its bytes are the caller's), else Flate.
 */
function xrefStreamPdf(direct: PdfObj[], o: { objstm?: { num: number; items: [number, string][]; filter?: string; data?: Buffer }; freeLast?: number[] } = {}): Buffer {
  const parts: Buffer[] = [Buffer.from("%PDF-1.7\n%\xe2\xe3\xcf\xd3\n", "latin1")];
  let at = parts[0]!.length;
  const entries = new Map<number, [number, number, number]>();
  const add = (ob: PdfObj): void => {
    entries.set(ob.num, [1, at, 0]);
    const b = Buffer.concat([Buffer.from(`${ob.num} 0 obj\n`, "latin1"), ob.stream ? Buffer.concat([Buffer.from(`${ob.body.replace(/>>\s*$/, ` /Length ${ob.stream.length} >>`)}\nstream\n`, "latin1"), ob.stream, Buffer.from("\nendstream", "latin1")]) : Buffer.from(ob.body, "latin1"), Buffer.from("\nendobj\n", "latin1")]);
    parts.push(b);
    at += b.length;
  };
  for (const ob of direct) add(ob);
  if (o.objstm) {
    let head = "", bodies = "";
    o.objstm.items.forEach(([n, text], i) => {
      head += `${n} ${bodies.length} `;
      bodies += text + "\n";
      entries.set(n, [2, o.objstm!.num, i]);
    });
    head += "\n";
    const plain = Buffer.from(head + bodies, "latin1");
    const data = o.objstm.data ?? deflateSync(plain);
    add({ num: o.objstm.num, body: `<< /Type /ObjStm /N ${o.objstm.items.length} /First ${head.length} /Filter ${o.objstm.filter ?? "/FlateDecode"} >>`, stream: data });
  }
  const xnum = Math.max(...entries.keys()) + 1;
  const xrefAt = at;
  entries.set(xnum, [1, xrefAt, 0]);
  const rows: Buffer[] = [];
  for (let n = 0; n <= xnum; n++) {
    const [t, f2, f3] = entries.get(n) ?? [0, 0, n === 0 ? 65535 : 0];
    const r = Buffer.alloc(7);
    r[0] = t;
    r.writeUInt32BE(f2, 1);
    r.writeUInt16BE(f3, 5);
    rows.push(r);
  }
  const xdata = deflateSync(Buffer.concat(rows));
  parts.push(Buffer.from(`${xnum} 0 obj\n<< /Type /XRef /Size ${xnum + 1} /W [1 4 2] /Root 1 0 R /Filter /FlateDecode /Length ${xdata.length} >>\nstream\n`, "latin1"), xdata, Buffer.from(`\nendstream\nendobj\nstartxref\n${xrefAt}\n%%EOF\n`, "latin1"));
  return Buffer.concat(parts);
}

// --- P1-1: every filter's output is bounded, before it is allocated --------------------------------------------------------

test("P1-1 ASCII85: an object stream of 8 MB of 'z' (32 MB decoded) is stopped at max_stream_bytes, named, and the call stays small in memory", async () => {
  await withCwd(async (cwd) => {
    // 'z' is four zero bytes (ISO 32000-1 7.4.3): 8 Mi of them decode to 32 MiB, twice the default stream budget of 16 MiB.
    const data = Buffer.concat([Buffer.alloc(8 << 20, 0x7a), Buffer.from("~>")]);
    const pdf = xrefStreamPdf([CATALOG(), PAGES, PAGE()], { objstm: { num: 5, items: [[4, "<< /S /JavaScript /JS (x) >>"]], filter: "/ASCII85Decode", data } });
    await put(cwd, "work/z.pdf", pdf);
    const { run, rssMb } = bounded(cwd, { path: "work/z.pdf" }, 60_000);
    const a = body(run);
    assert.equal(a.status, "partial");
    assert.ok(a.limits_hit.some((l: string) => /object stream 5: a stream expanded past max_stream_bytes \(16777216\)/.test(l)), JSON.stringify(a.limits_hit));
    assert.ok(rssMb < 300, `the call peaked at ${rssMb.toFixed(0)} MB of memory: a decoder built an output it may not keep`);
  });
});

test("P1-1 ASCII85 and a filter chain: a stream that decodes past max_stream_bytes or max_ratio is a named limit when extracted, and nothing is written", async () => {
  await withCwd(async (cwd) => {
    // 300,000 'z' are 1.2 MB decoded from 300 KB: within twice the 1 MiB stream budget before decoding, past it after.
    const z = Buffer.concat([Buffer.alloc(300_000, 0x7a), Buffer.from("~>")]);
    // Flate of 900,000 'z', then ASCII85: the first step's output is under the ratio's 1 MiB floor, the second's is 3.6 MB from
    // about 1 KB on disk.
    const chain = deflateSync(Buffer.concat([Buffer.alloc(900_000, 0x7a), Buffer.from("~>")]), { level: 9 });
    const pdf = buildPdf([CATALOG(), PAGES, PAGE(), { num: 4, body: "<< /Filter /ASCII85Decode >>", stream: z }, { num: 5, body: "<< /Filter [ /FlateDecode /ASCII85Decode ] >>", stream: chain }], "/Root 1 0 R");
    const { a } = await run(cwd, "a85.pdf", pdf.file, { max_stream_bytes: 1 << 20, extract_to: "work/s1/x", extract: ["pdf:4"] });
    assert.ok(a.limits_hit.some((l: string) => /extract pdf:4: a stream expanded past max_stream_bytes \(1048576\)/.test(l)), JSON.stringify(a.limits_hit));
    assert.deepEqual(await filesUnder(join(cwd, "work/s1/x")), [], "a stream over its budget is not written, cut or whole");
    assert.ok(!a.problems.some((p: string) => /matched nothing/.test(p)), "the object was found: its reason is a limit, not 'matched nothing'");
    const { a: b } = await run(cwd, "chain.pdf", pdf.file, { extract_to: "work/s1/y", extract: ["pdf:5"] });
    assert.ok(b.limits_hit.some((l: string) => /extract pdf:5: a stream expanded past max_ratio \(1000\)/.test(l)), JSON.stringify(b.limits_hit));
    assert.deepEqual(await filesUnder(join(cwd, "work/s1/y")), []);
  });
});

// --- P1-2: the clock holds inside a parse, and a failed read is read once --------------------------------------------------

test("P1-2 an unterminated object of millions of values, referenced by six entries, ends within max_seconds with a named limit: no window re-growth loop", async () => {
  await withCwd(async (cwd) => {
    // One object: an array that never closes, of 16 arrays of 250,000 numbers each (about 8 MB). Entries 4 to 9 all point at it.
    const inner = "[" + "1 ".repeat(250_000) + "]\n";
    const big = Buffer.from("4 0 obj\n[" + inner.repeat(16) + "\nendobj\n", "latin1");
    const head = buildPdf([CATALOG(), PAGES, PAGE()], "/Root 1 0 R");
    const body0 = head.file.subarray(0, head.xrefAt);
    const slowAt = body0.length;
    const xrefAt = slowAt + big.length;
    let xref = "xref\n0 10\n0000000000 65535 f \n";
    for (let n = 1; n < 10; n++) xref += `${String(n < 4 ? head.offsets.get(n)! : slowAt).padStart(10, "0")} 00000 n \n`;
    const file = Buffer.concat([body0, big, Buffer.from(`${xref}trailer\n<< /Size 10 /Root 1 0 R >>\nstartxref\n${xrefAt}\n%%EOF\n`, "latin1")]);
    await put(cwd, "work/slow.pdf", file);
    const { run, seconds } = bounded(cwd, { path: "work/slow.pdf", max_seconds: 3 }, 60_000);
    const a = body(run);
    assert.ok(seconds < 3 + 6, `the call took ${seconds.toFixed(1)} s with max_seconds 3`);
    assert.equal(a.status, "partial");
    assert.ok(a.limits_hit.some((l: string) => /a bound of the parser|max_seconds/.test(l)), JSON.stringify(a.limits_hit));
  });
});

test("P1-2 an object stream that fails after an expensive predictor is read once: two hundred references do not decode it two hundred times", async () => {
  await withCwd(async (cwd) => {
    // The object stream's data: 4,000 rows of 1,000 bytes under the PNG Up predictor (ISO 32000-1 7.4.4.4), all zero, so its
    // header ("number offset" pairs before /First) lists no object: every object said to be in it is unreadable.
    const rows = Buffer.alloc(4000 * 1001);
    for (let r = 0; r < 4000; r++) rows[r * 1001] = 2;
    const data = deflateSync(rows);
    const parts: Buffer[] = [Buffer.from("%PDF-1.7\n", "latin1")];
    let at = parts[0]!.length;
    const offs = new Map<number, number>();
    const add = (b: Buffer, n: number): void => { offs.set(n, at); parts.push(b); at += b.length; };
    add(Buffer.from("1 0 obj\n<< /Type /Catalog /Pages 2 0 R >>\nendobj\n", "latin1"), 1);
    add(Buffer.from("2 0 obj\n<< /Type /Pages /Kids [ ] /Count 0 >>\nendobj\n", "latin1"), 2);
    add(Buffer.concat([Buffer.from(`5 0 obj\n<< /Type /ObjStm /N 1 /First 4 /Filter /FlateDecode /DecodeParms << /Predictor 12 /Columns 1000 >> /Length ${data.length} >>\nstream\n`, "latin1"), data, Buffer.from("\nendstream\nendobj\n", "latin1")]), 5);
    const size = 207, xnum = 206, xrefAt = at;
    const rowsX: Buffer[] = [];
    for (let n = 0; n < size; n++) {
      const r = Buffer.alloc(6);
      if (n === 1 || n === 2 || n === 5) { r[0] = 1; r.writeUInt32BE(offs.get(n)!, 1); }
      else if (n === xnum) { r[0] = 1; r.writeUInt32BE(xrefAt, 1); }
      else if (n >= 6) { r[0] = 2; r.writeUInt32BE(5, 1); r[5] = 0; }
      rowsX.push(r);
    }
    const xd = deflateSync(Buffer.concat(rowsX));
    parts.push(Buffer.from(`${xnum} 0 obj\n<< /Type /XRef /Size ${size} /W [1 4 1] /Root 1 0 R /Filter /FlateDecode /Length ${xd.length} >>\nstream\n`, "latin1"), xd, Buffer.from(`\nendstream\nendobj\nstartxref\n${xrefAt}\n%%EOF\n`, "latin1"));
    await put(cwd, "work/pred.pdf", Buffer.concat(parts));
    const { run, seconds } = bounded(cwd, { path: "work/pred.pdf", max_seconds: 2 }, 60_000);
    const a = body(run);
    assert.ok(seconds < 2 + 5, `the call took ${seconds.toFixed(1)} s with max_seconds 2`);
    assert.equal(a.problems.filter((p: string) => /object stream 5 cannot be read/.test(p)).length, 1, JSON.stringify(a.problems));
    assert.equal(a.census.objects_unreadable, 200);
  });
});

test("P1-2 a cross-reference table of five million empty subsections ends at max_seconds, named, and the file is still read by scanning", async () => {
  await withCwd(async (cwd) => {
    // ISO 32000-1 7.5.4: a subsection is "first count" and count entries; "0 0" is a subsection of none, and nothing bounds
    // how many there are. The table holds only those, so no entry of it would ever give a clock check a turn.
    const head = buildPdf([CATALOG(), PAGES, PAGE()], "/Root 1 0 R");
    const objects = head.file.subarray(0, head.xrefAt);
    const file = Buffer.concat([objects, Buffer.from("xref\n", "latin1"), Buffer.from("0 0\n".repeat(5_000_000), "latin1"), Buffer.from(`trailer\n<< /Size 4 /Root 1 0 R >>\nstartxref\n${head.xrefAt}\n%%EOF\n`, "latin1")]);
    await put(cwd, "work/xsub.pdf", file);
    const { run, seconds } = bounded(cwd, { path: "work/xsub.pdf", max_seconds: 1 }, 90_000);
    const a = body(run);
    assert.ok(seconds < 1 + 6, `the call took ${seconds.toFixed(1)} s with max_seconds 1`);
    assert.ok(a.limits_hit.some((l: string) => /a cross-reference table stopped at max_seconds/.test(l)), JSON.stringify(a.limits_hit));
  });
});

// --- P1-3: no byte of RTF object data is printed ----------------------------------------------------------------------------

test("P1-3 RTF object data is named by its signature and no byte of it is printed: a token as object data leaves no hex of it in the answer", async () => {
  await withCwd(async (cwd) => {
    const { a, text } = await run(cwd, "r1.rtf", `{\\rtf1{\\object\\objemb{\\*\\objclass Package}{\\*\\objdata ${Buffer.from(GHP).toString("hex")}}}}`);
    const row = a.objects.first[0];
    assert.equal(row.data.decoded_start.signature, null);
    assert.equal("first_bytes_hex" in row.data.decoded_start, false);
    for (const slice of CANARY_SLICES) assert.ok(!text.includes(slice), `${slice} is in the answer`);
    assert.ok(!text.includes(Buffer.from(GHP).toString("hex").slice(0, 8)), "four bytes of the token, as hex, are in the answer");
  });
});

// --- P1-4: a canary in every printable place is in no file the call writes -------------------------------------------------

/** Every file under work/ and out/ except the inputs (under work/in/) and the private withheld-names file (mode 0600: the real names, by design). */
async function writtenFiles(cwd: string): Promise<{ path: string; text: string }[]> {
  const out: { path: string; text: string }[] = [];
  for (const dir of ["work", "out"]) {
    for (const f of await filesUnder(join(cwd, dir))) {
      const path = `${dir}/${f}`;
      if (path.startsWith("work/in/")) continue;
      if (/withheld-names/.test(f)) {
        assert.equal(((await stat(join(cwd, path))).mode & 0o777), 0o600, `${path} is the private names file and must be 0600`);
        continue;
      }
      out.push({ path, text: (await readFile(join(cwd, path))).toString("latin1") });
    }
  }
  return out;
}

function canaryPdf(): Buffer {
  return buildPdf([
    CATALOG(`/OpenAction 4 0 R /AA << /WC 5 0 R /WS 6 0 R >> /Names << /JavaScript 7 0 R /EmbeddedFiles 8 0 R >>`),
    PAGES,
    PAGE("/Annots [ 12 0 R ]"),
    { num: 4, body: `<< /S /URI /URI (https://${AKIA}.s3.amazonaws.com/${GHP}?sig=abc#frag) >>` },
    { num: 5, body: `<< /S /URI /URI (https://user:hunter2@${GHP}.example.com/) >>` },
    { num: 6, body: `<< /S /Launch /F (C:\\\\Users\\\\${GHP}\\\\run.exe) /Win << /F (cmd.exe) /P (/c echo ${GHP}) >> >>` },
    { num: 7, body: `<< /Names [ (${GHP}) 9 0 R ] >>` },
    { num: 9, body: `<< /S /JavaScript /JS (var k='${GHP}';) >>` },
    { num: 8, body: `<< /Names [ (${AKIA}.txt) 10 0 R ] >>` },
    { num: 10, body: `<< /Type /Filespec /F (${GHP}.txt) /UF (${GHP}.txt) /EF << /F 11 0 R >> >>` },
    { num: 11, body: "<< /Type /EmbeddedFile >>", stream: Buffer.from(`secret ${GHP}`) },
    { num: 12, body: `<< /Type /Annot /Subtype /${GHP} /Contents (${GHP}) /A << /S /URI /URI (http://${AKIA}.example/) >> >>` },
    { num: 13, body: `<< /Type /${AKIA} /${GHP} 1 >>` },
    { num: 14, body: `<< /Title (${GHP}) /Author (${AKIA}) >>` },
    { num: 15, body: `<< /Filter /${GHP} >>`, stream: Buffer.from("xx") },
  ], "/Root 1 0 R /Info 14 0 R").file;
}

function canaryRtf(): string {
  const field = (instr: string): string => `{\\field{\\*\\fldinst ${instr}}{\\fldrslt x}}`;
  return `{\\rtf1${field(`${AKIA} https://u:p@h/x?token=${GHP}`)}${field(`HYPERLINK "https://${AKIA}.example/${GHP}"`)}` +
    `{\\*\\template https://${GHP}.evil.example/t.dotm}{\\*\\template \\\\\\\\${AKIA}\\\\share\\\\t.dotm}` +
    `{\\object\\objemb{\\*\\objclass ${AKIA}}{\\*\\objname ${GHP}}{\\*\\objdata ${hex(ole1Object(`Pkg${GHP}`, Buffer.from(GHP)))}}}}`;
}

function canaryOle(): Buffer {
  return buildCfb([
    { name: GHP.slice(0, 31), data: Buffer.from("x") },
    { name: AKIA, children: [{ name: "inner", data: Buffer.from("y") }] },
    { name: "Workbook", data: excelWorkbook({ sheets: [{ name: GHP.slice(0, 31) }, { name: AKIA }] }) },
  ]);
}

function canaryZip(): Buffer {
  return buildZip([
    { name: "[Content_Types].xml", data: Buffer.from(`<?xml version="1.0"?><Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types"><Default Extension="${AKIA}" ContentType="application/${GHP}"/><Override PartName="/word/${GHP}.xml" ContentType="x"/></Types>`) },
    { name: `word/${GHP}.xml`, data: Buffer.from("<x/>") },
    { name: `word/media/${AKIA}.png`, data: Buffer.from("png") },
    { name: "word/vbaProject.bin", data: buildVbaProject([{ name: `M${AKIA}`, source: "Sub A()\r\nEnd Sub\r\n" }]) },
  ]);
}

test("P1-4 a canary planted in every printable place of a PDF, an RTF, an OLE file and an OOXML package is in no table file and no answer, with limit 1, in a job and outside one", async () => {
  await withCwd(async (cwd) => {
    const cases: [string, Buffer | string][] = [["c.pdf", canaryPdf()], ["c.rtf", canaryRtf()], ["c.xls", canaryOle()], ["c.docm", canaryZip()]];
    for (const [name, data] of cases) {
      await put(cwd, `work/in/${name}`, data);
      for (const job of [false, true]) {
        const r = job ? await asJob(DOC_STRUCTURE, cwd, { path: `work/in/${name}`, limit: 1 }) : await tool(DOC_STRUCTURE, cwd, { path: `work/in/${name}`, limit: 1 });
        const a = body(r);
        assert.ok(Object.values(a.tables).some((t: Json) => t.all_results), `${name}: limit 1 writes at least one table file`);
        for (const slice of CANARY_SLICES) assert.ok(!r.stdout.includes(slice), `${name}${job ? " (job)" : ""}: ${slice} is in the answer`);
        for (const f of await writtenFiles(cwd)) {
          for (const slice of CANARY_SLICES) assert.ok(!f.text.includes(slice), `${name}${job ? " (job)" : ""}: ${slice} is in ${f.path}`);
        }
      }
    }
  });
});

test("P1-4 a URL's host is withheld when it is token-shaped, and a plain host stays", async () => {
  await withCwd(async (cwd) => {
    const pdf = buildPdf([CATALOG("/OpenAction 4 0 R /AA << /WC 5 0 R >>"), PAGES, PAGE(), { num: 4, body: `<< /S /URI /URI (https://${AKIA}.s3.amazonaws.com/x) >>` }, { num: 5, body: "<< /S /URI /URI (https://files.example.test/report.pdf) >>" }], "/Root 1 0 R");
    const { a } = await run(cwd, "host.pdf", pdf.file, { limit: 1 });
    // limit 1: the second row is only in the table file, which must withhold the host as the answer does.
    const lines = (await readFile(join(cwd, a.tables.pdf_actions.all_results), "utf8")).trim().split("\n").map((l) => JSON.parse(l));
    const targets = lines.map((r: Json) => r.target).sort();
    assert.deepEqual(targets, ["https://<token-shaped text withheld 20 characters>.s3.amazonaws.com/x", "https://files.example.test/report.pdf"]);
  });
});

// --- P1-5: part names compare case-insensitively ------------------------------------------------------------------------------

test("P1-5 OOXML: two part names that differ only in case are a duplicate, named; the VBA project and the protection element in either copy are read, and the status is not complete", async () => {
  await withCwd(async (cwd) => {
    const types = { name: "[Content_Types].xml", data: Buffer.from('<?xml version="1.0"?><Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types"/>') };
    const settings = '<?xml version="1.0"?><w:settings xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main"><w:documentProtection w:edit="readOnly" w:enforcement="1"/></w:settings>';
    const zip = buildZip([
      types,
      { name: "word/document.xml", data: Buffer.from("<w:document/>") },
      { name: "word/vbaProject.bin", data: buildCfb([{ name: "nothing", data: Buffer.from("x") }]) },
      { name: "word/VBAPROJECT.BIN", data: buildVbaProject([{ name: "Module1", source: "Sub AutoOpen()\r\nEnd Sub\r\n" }]) },
      { name: "word/settings.xml", data: Buffer.from('<?xml version="1.0"?><w:settings xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main"/>') },
      { name: "WORD/SETTINGS.XML", data: Buffer.from(settings) },
    ]);
    const { a } = await run(cwd, "dup.docm", zip);
    assert.equal(a.status, "partial");
    assert.ok(a.problems.some((p: string) => /word\/vbaProject\.bin appears 2 times \(spelled 2 ways\): part names compare case-insensitively/.test(p)), JSON.stringify(a.problems));
    assert.deepEqual(a.duplicate_part_names.map((d: Json) => d.copies), [2, 2]);
    const modules = a.vbaproject_parts.flatMap((p: Json) => p.vba_projects.flatMap((v: Json) => v.modules.map((m: Json) => m.name)));
    assert.deepEqual(modules, ["Module1"], "the VBA project in the second spelling is read");
    assert.ok(a.protection_items.some((p: Json) => p.element === "documentProtection"), "the protection element in the second spelling is read");
  });
});

// --- P1-6: no silent slice in the PDF walkers ---------------------------------------------------------------------------------

test("P1-6 actions past the old slices are listed: a page /AA with 40 keys before /O, the 10,001st annotation, the 10,001st form field and the 40th action of a /Next chain", async () => {
  await withCwd(async (cwd) => {
    const junk = Array.from({ length: 40 }, (_v, i) => `/K${i} 1`).join(" ");
    const c1 = buildPdf([CATALOG(), PAGES, PAGE(`/AA << ${junk} /O << /S /JavaScript /JS (app.alert(1)) >> >>`)], "/Root 1 0 R");
    const r1 = await run(cwd, "c1.pdf", c1.file);
    assert.deepEqual(r1.a.tables.pdf_actions.rows.map((r: Json) => [r.action, r.trigger]), [["JavaScript", "Page/AA/O"]]);
    const annots = Array.from({ length: 10_000 }, () => "<< /Subtype /Text >>").join(" ") + " << /Subtype /Link /A << /S /URI /URI (http://x.example/) >> >>";
    const r2 = await run(cwd, "c2.pdf", buildPdf([CATALOG(), PAGES, PAGE(`/Annots [ ${annots} ]`)], "/Root 1 0 R").file);
    assert.equal(r2.a.actions.by_type.URI, 1, "the 10,001st annotation's action");
    const kids = Array.from({ length: 10_000 }, () => "null").join(" ") + " << /T (f) /A << /S /SubmitForm /F (http://z.example/) >> >>";
    const r3 = await run(cwd, "c5.pdf", buildPdf([CATALOG(`/AcroForm << /Fields [ << /T (parent) /Kids [ ${kids} ] >> ] >>`), PAGES, PAGE()], "/Root 1 0 R").file);
    assert.equal(r3.a.actions.by_type.SubmitForm, 1, "the action of a field's 10,001st kid");
    // A /Next chain of 40 actions, each a separate object: the old walker stopped at depth 32.
    const chain: PdfObj[] = Array.from({ length: 40 }, (_v, i) => ({ num: 10 + i, body: i < 39 ? `<< /S /Named /N /NextPage /Next ${11 + i} 0 R >>` : "<< /S /JavaScript /JS (last) >>" }));
    const r4 = await run(cwd, "next.pdf", buildPdf([CATALOG("/OpenAction 10 0 R"), PAGES, PAGE(), ...chain], "/Root 1 0 R").file);
    assert.equal(r4.a.actions.by_type.JavaScript, 1, "the end of a 40-action /Next chain");
    assert.equal(r4.a.actions.unreached_from_catalog, 0);
  });
});

// --- P2: OLE ---------------------------------------------------------------------------------------------------------------------

/** The offset of the 128-byte directory entry named `name` ([MS-CFB] 2.6.1: the name in UTF-16LE at 0, its byte length with the terminator at 64). */
function entryAt(cfb: Buffer, name: string): number {
  const raw = Buffer.from(name, "utf16le");
  for (let at = cfb.indexOf(raw); at >= 0; at = cfb.indexOf(raw, at + 1)) {
    if (at % 128 === 0 && cfb.readUInt16LE(at + 64) === raw.length + 2) return at;
  }
  throw new Error(`no directory entry ${name}`);
}

test("D1 an odd directory name length is a broken entry, named, never a decoding failure: in a compound file, in a zip and in an RTF object", async () => {
  await withCwd(async (cwd) => {
    const cfb = buildCfb([{ name: "Stream1", data: Buffer.from("x") }, { name: "WordDocument", data: Buffer.alloc(64) }]);
    cfb.writeUInt16LE(5, entryAt(cfb, "Stream1") + 64);
    const { a } = await run(cwd, "odd.doc", cfb);
    assert.ok(a.problems.some((p: string) => /a name length that does not fit the name field/.test(p)), JSON.stringify(a.problems));
    assert.ok(a.tables.ole_directory.rows.some((r: Json) => r.name_length_inconsistent === true));
    const zip = buildZip([{ name: "[Content_Types].xml", data: Buffer.from("<Types/>") }, { name: "word/vbaProject.bin", data: cfb }]);
    const { a: z } = await run(cwd, "odd.docm", zip);
    assert.ok(z.problems.some((p: string) => /word\/vbaProject\.bin: 1 directory entry has a name length/.test(p)), JSON.stringify(z.problems));
    const { a: r } = await run(cwd, "odd.rtf", `{\\rtf1{\\object\\objemb{\\*\\objdata ${hex(ole1Object("Package", cfb))}}}}`);
    assert.ok(r.problems.some((p: string) => /rtf-object-1: 1 directory entry has a name length/.test(p)), JSON.stringify(r.problems));
  });
});

test("D2 a WordDocument, Workbook or EncryptionInfo entry of type 0, 3, 4 or 5 is not read as a stream, and said; the call answers", async () => {
  await withCwd(async (cwd) => {
    for (const [name, data] of [["WordDocument", Buffer.alloc(64)], ["Workbook", excelWorkbook({ sheets: [{ name: "S" }] })], ["EncryptionInfo", Buffer.alloc(64)]] as [string, Buffer][]) {
      for (const kind of [0, 3, 4, 5]) {
        const top = name === "EncryptionInfo" ? [{ name, data }, { name: "EncryptedPackage", data: Buffer.alloc(64) }] : [{ name, data }];
        const cfb = buildCfb(top);
        cfb[entryAt(cfb, name) + 66] = kind;
        const { a } = await run(cwd, `k${kind}.bin`, cfb);
        assert.equal(a.status, "partial", `${name} type ${kind}`);
        assert.ok(a.problems.some((p: string) => new RegExp(`the root entry ${name} is of type [\\w ]+, not a stream`).test(p)), `${name} type ${kind}: ${JSON.stringify(a.problems)}`);
      }
    }
  });
});

test("D6 a VBA storage whose dir entry is not a stream, or an entry named VBA that is not a storage, is listed and said, never dropped", async () => {
  await withCwd(async (cwd) => {
    const flipDir = buildVbaProject([{ name: "Module1", source: "Sub A()\r\nEnd Sub\r\n" }]);
    flipDir[entryAt(flipDir, "dir") + 66] = 1;
    const { a } = await run(cwd, "flip.bin", flipDir);
    assert.equal(a.status, "partial");
    assert.deepEqual(a.vba_projects.map((p: Json) => p.status), ["dir_not_a_stream"]);
    assert.ok(a.problems.some((p: string) => /VBA: a VBA storage that holds a dir entry of type storage, not a stream/.test(p)), JSON.stringify(a.problems));
    const flipVba = buildVbaProject([{ name: "Module1", source: "Sub A()\r\nEnd Sub\r\n" }]);
    flipVba[entryAt(flipVba, "VBA") + 66] = 2;
    const { a: b } = await run(cwd, "flip2.bin", flipVba);
    assert.equal(b.status, "partial");
    assert.ok(b.vba_projects.some((p: Json) => p.status === "not_a_storage"), JSON.stringify(b.vba_projects));
  });
});

test("encrypted XLS: after FILEPASS a sheet's name, visibility and type are ciphertext: only the count and lbPlyPos are reported, and no macro sheet is derived", async () => {
  await withCwd(async (cwd) => {
    const xls = buildCfb([{ name: "Workbook", data: excelWorkbook({ filepass: { type: 1, major: 4, minor: 2 }, sheets: [{ name: "Macro1", state: 2, kind: 1 }, { name: "Data" }] }) }]);
    const { a, text } = await run(cwd, "enc.xls", xls);
    assert.deepEqual(a.excel.sheets.map((s: Json) => [s.lbPlyPos, s.name, s.state, s.kind]), [[0x1000, null, null, null], [0x1000, null, null, null]]);
    assert.equal(a.excel.sheets_encrypted, 2);
    assert.match(a.excel.sheets[0].encrypted, /not readable/);
    assert.equal((a.protection_items ?? []).some((p: Json) => p.kind === "macro_sheets"), false);
    assert.ok(!text.includes("Macro1") && !text.includes("very hidden"));
  });
});

test("OVBA: an uncompressed chunk is read from its own bytes only; one that does not declare 4096 bytes is a problem", async () => {
  await withCwd(async (cwd) => {
    // [MS-OVBA] 2.4.1.1.4: a chunk header is size-3 in 12 bits, the signature 3 and the flag; flag 0 means 4096 raw bytes follow.
    const raw = Buffer.concat([Buffer.from([1]), u16((10 - 3) | (3 << 12)), Buffer.from("ABCDEFGH"), ovbaCompress(Buffer.from("xyz")).subarray(1)]);
    const vba = buildVbaProject([{ name: "Module1", source: "", compressed: raw }]);
    const { a } = await run(cwd, "raw.bin", vba);
    const mod = a.vba_projects[0].modules[0];
    assert.match(mod.source, /decompressed in part \(an uncompressed chunk declares 10 bytes, not 4098/);
    assert.equal(mod.source_bytes, 0, "nothing past the chunk is taken for its data");
  });
});

test("an extracted object's digest is in no answer (a hash of a planted token confirms it); with write_values, in a job, it is in the values file only", async () => {
  await withCwd(async (cwd) => {
    const { a, text } = await run(cwd, "v.bin", buildVbaProject([{ name: "Module1", source: "Sub A()\r\nEnd Sub\r\n" }]), { extract_to: "work/s1/v", extract: ["vba"] });
    const row = a.extracted[0];
    const digest = createHash("sha256").update(await readFile(join(cwd, row.file))).digest("hex");
    assert.equal("sha256" in row, false);
    assert.ok(!text.includes(digest), "the digest is in the answer");
    await put(cwd, "work/v2.bin", buildVbaProject([{ name: "Module1", source: "Sub A()\r\nEnd Sub\r\n" }]));
    const r = await asJob(DOC_STRUCTURE, cwd, { path: "work/v2.bin", extract_to: "out/v", extract: ["vba"], write_values: true });
    const job = body(r);
    assert.ok(!r.stdout.includes(digest), "the digest is in the job's answer");
    const values = (await readFile(join(cwd, "out", "doc-structure-values.jsonl"), "utf8")).trim().split("\n").map((l) => JSON.parse(l));
    const v = values.find((x: Json) => x.kind === "extracted_object_sha256");
    assert.equal(v.value, digest);
    assert.equal(v.finding_id, job.extracted[0].sha256_in_values_file);
  });
});

// --- P2: PDF ---------------------------------------------------------------------------------------------------------------------

test("D3 a catalog in an object stream over the stream budget is a named limit with partial results, not a failed answer", async () => {
  await withCwd(async (cwd) => {
    const pdf = xrefStreamPdf([PAGES, PAGE()], { objstm: { num: 5, items: [[1, "<< /Type /Catalog /Pages 2 0 R /OpenAction << /S /URI /URI (http://x.example/) >> >>"], [4, "(" + "p".repeat(400) + ")"]] } });
    const { a } = await run(cwd, "cat.pdf", pdf, { max_stream_bytes: 100 });
    assert.equal(a.status, "partial");
    assert.ok(a.limits_hit.some((l: string) => /object stream 5: a stream (of \d+ bytes is over twice|expanded past) max_stream_bytes \(100\)/.test(l)), JSON.stringify(a.limits_hit));
    assert.equal(a.structure_source, "cross-reference chain");
  });
});

test("D4 an XML part that declares an encoding the reader cannot decode is a problem, not a failure", async () => {
  await withCwd(async (cwd) => {
    const zip = buildZip([
      { name: "[Content_Types].xml", data: Buffer.from('<?xml version="1.0" encoding="UTV-8"?><Types/>') },
      { name: "word/settings.xml", data: Buffer.from('<?xml version="1.0" encoding="x-no-such-codec"?><w:settings/>') },
    ]);
    const { a } = await run(cwd, "enc.docx", zip);
    assert.equal(a.status, "partial");
    assert.ok(a.problems.some((p: string) => /\[Content_Types\]\.xml declares an encoding the XML reader cannot decode/.test(p)), JSON.stringify(a.problems));
    assert.ok(a.problems.some((p: string) => /word\/settings\.xml declares an encoding the XML reader cannot decode/.test(p)), JSON.stringify(a.problems));
  });
});

test("scan mode: a 'trailer <<' inside a stream's data or in a comment is not taken for the current trailer", async () => {
  await withCwd(async (cwd) => {
    const enc: PdfObj = { num: 9, body: `<< /Filter /Standard /V 2 /R 3 /Length 128 /P -4 /O <${"11".repeat(32)}> /U <${"22".repeat(32)}> >>` };
    // The real trailer names no encryption; a stream written after it holds a trailer-shaped dictionary that does. startxref is wrong,
    // so the index is rebuilt by scanning.
    const plain = buildPdf([CATALOG(), PAGES, PAGE(), enc], "/Root 1 0 R");
    const fakeTrailer = Buffer.from("trailer\n<< /Size 10 /Root 1 0 R /Encrypt 9 0 R >>\n", "latin1");
    const tail = Buffer.concat([Buffer.from(`10 0 obj\n<< /Length ${fakeTrailer.length} >>\nstream\n`, "latin1"), fakeTrailer, Buffer.from("\nendstream\nendobj\n", "latin1")]);
    const e4 = Buffer.concat([Buffer.from(plain.file.toString("latin1").replace(`startxref\n${plain.xrefAt}`, `startxref\n${plain.xrefAt + 3}`), "latin1"), tail]);
    const { a } = await run(cwd, "e4.pdf", e4);
    assert.equal(a.structure_source, "scan of the file for object headers");
    assert.notEqual(a.encryption_summary.found, true, "a dictionary inside a stream chose the current trailer");
    assert.equal(a.trailer_keywords_ignored.in_stream_data, 1);
    // The real trailer names the encryption dictionary; a comment after it holds a trailer-shaped dictionary that does not.
    const encrypted = buildPdf([CATALOG(), PAGES, PAGE(), enc], "/Root 1 0 R /Encrypt 9 0 R");
    const e4b = Buffer.concat([Buffer.from(encrypted.file.toString("latin1").replace(`startxref\n${encrypted.xrefAt}`, `startxref\n${encrypted.xrefAt + 3}`), "latin1"), Buffer.from("% trailer << /Size 10 /Root 1 0 R >>\n", "latin1")]);
    const { a: b } = await run(cwd, "e4b.pdf", e4b);
    assert.equal(b.encryption_summary.found, true, "a comment chose the current trailer");
    assert.equal(b.trailer_keywords_ignored.in_a_comment, 1);
  });
});

test("hybrid: an object a newer revision deleted is not brought back by an older revision's cross-reference stream", async () => {
  await withCwd(async (cwd) => {
    // Revision 1 (hybrid): a table that lists 7 as free, and an /XRefStm stream that defines it (ISO 32000-1 7.5.8.4).
    // Revision 2: a table that frees 7 again with a higher generation: the object is deleted.
    const parts: Buffer[] = [Buffer.from("%PDF-1.7\n", "latin1")];
    let at = parts[0]!.length;
    const offs = new Map<number, number>();
    const add = (n: number, text: string | Buffer): void => { offs.set(n, at); const b = typeof text === "string" ? Buffer.from(text, "latin1") : text; parts.push(b); at += b.length; };
    add(1, "1 0 obj\n<< /Type /Catalog /Pages 2 0 R >>\nendobj\n");
    add(2, "2 0 obj\n<< /Type /Pages /Kids [ 3 0 R ] /Count 1 >>\nendobj\n");
    add(3, "3 0 obj\n<< /Type /Page /Parent 2 0 R >>\nendobj\n");
    add(7, "7 0 obj\n<< /S /JavaScript /JS (old) >>\nendobj\n");
    const rows = Buffer.alloc(9 * 6);
    rows[7 * 6] = 1;
    rows.writeUInt32BE(offs.get(7)!, 7 * 6 + 1);
    const xd = deflateSync(rows);
    add(8, Buffer.concat([Buffer.from(`8 0 obj\n<< /Type /XRef /Size 9 /W [1 4 1] /Filter /FlateDecode /Length ${xd.length} >>\nstream\n`, "latin1"), xd, Buffer.from("\nendstream\nendobj\n", "latin1")]));
    const t1 = at;
    let x1 = "xref\n0 9\n0000000000 65535 f \n";
    for (let n = 1; n < 9; n++) x1 += n <= 3 ? `${String(offs.get(n)!).padStart(10, "0")} 00000 n \n` : "0000000000 00001 f \n";
    add(100, `${x1}trailer\n<< /Size 9 /Root 1 0 R /XRefStm ${offs.get(8)} >>\nstartxref\n${t1}\n%%EOF\n`);
    const t2 = at;
    add(101, `xref\n7 1\n0000000000 00002 f \ntrailer\n<< /Size 9 /Root 1 0 R /Prev ${t1} >>\nstartxref\n${t2}\n%%EOF\n`);
    const { a } = await run(cwd, "hyb.pdf", Buffer.concat(parts));
    // Not brought back: no entry of the chain uses it and it is not in the census. Its bytes are still in the file, so it is the one
    // action listed, as outside the chain (freed), never as reached.
    assert.deepEqual(a.tables.pdf_actions.rows.map((r: Json) => [r.object, r.reached_from_catalog, r.outside_chain]), [[7, false, "freed"]]);
    assert.equal(a.tables.objects.rows.some((r: Json) => r.object === 7), false, "a deleted object is listed");
  });
});

test("ciphertext: in an encrypted PDF a plain object's URI action is listed, and its target is marked ciphertext and given by length only", async () => {
  await withCwd(async (cwd) => {
    const enc: PdfObj = { num: 9, body: `<< /Filter /Standard /V 2 /R 3 /Length 128 /P -4 /O <${"11".repeat(32)}> /U <${"22".repeat(32)}> >>` };
    const pdf = buildPdf([CATALOG("/OpenAction 4 0 R"), PAGES, PAGE(), { num: 4, body: "<< /S /URI /URI <a1b2c3d4e5f60718293a> >>" }, enc], "/Root 1 0 R /Encrypt 9 0 R");
    await put(cwd, "work/c.pdf", pdf.file);
    const a = body(await asJob(DOC_STRUCTURE, cwd, { path: "work/c.pdf", write_values: true }));
    const row = a.tables.pdf_actions.rows[0];
    assert.deepEqual({ action: row.action, target: row.target, length: row.target_length, ciphertext: row.ciphertext }, { action: "URI", target: null, length: 10, ciphertext: true });
    assert.match(a.actions.ciphertext_note, /ciphertext: true/);
    assert.equal(a.secret_values.written, 0, "ciphertext is not a value");
  });
});

test("PDF objects are parsed to a nesting of 150 whatever max_depth says, and the answer says so", async () => {
  await withCwd(async (cwd) => {
    const { a } = await run(cwd, "n.pdf", buildPdf([CATALOG(), PAGES, PAGE()], "/Root 1 0 R").file);
    assert.deepEqual({ followed: a.object_nesting.followed, max_depth: a.object_nesting.max_depth }, { followed: 150, max_depth: 256 });
    const { a: b } = await run(cwd, "n.pdf", buildPdf([CATALOG(), PAGES, PAGE()], "/Root 1 0 R").file, { max_depth: 100 });
    assert.equal("object_nesting" in b, false);
  });
});

// --- P2: RTF ---------------------------------------------------------------------------------------------------------------------

test("RTF instruction word: a lowercase field type is named, and an instruction that begins with a key prints no slice of it", async () => {
  await withCwd(async (cwd) => {
    const field = (instr: string): string => `{\\field{\\*\\fldinst ${instr}}{\\fldrslt x}}`;
    const { a, text } = await run(cwd, "w.rtf", `{\\rtf1${field('hyperlink "http://x.example/"')}${field(`${AKIA} https://h.example/`)}${field("INCLUDEPICTURE x.png")}}`);
    assert.deepEqual(a.fields.listed.map((f: Json) => f.instruction_word), ["HYPERLINK", null, "INCLUDEPICTURE"]);
    for (const slice of CANARY_SLICES) assert.ok(!text.includes(slice), `${slice} is in the answer`);
  });
});

test("RTF fields and templates are not cut silently: 2,500 fields and 300 templates are rows of their tables and in the values file; a field longer than its bound is a limit", async () => {
  await withCwd(async (cwd) => {
    const fields = Array.from({ length: 2500 }, (_v, i) => `{\\field{\\*\\fldinst HYPERLINK "https://h.example/x?n=${i}"}{\\fldrslt x}}`).join("");
    const templates = Array.from({ length: 300 }, (_v, i) => `{\\*\\template C:\\\\t\\\\${i}.dotm}`).join("");
    await put(cwd, "work/many.rtf", `{\\rtf1${fields}${templates}}`);
    const a = body(await asJob(DOC_STRUCTURE, cwd, { path: "work/many.rtf", write_values: true }));
    assert.equal(a.fields.count, 2500);
    assert.equal(a.tables.rtf_fields.matched, 2500);
    assert.equal(a.tables.rtf_templates.matched, 300);
    const values = (await readFile(join(cwd, "out", "doc-structure-values.jsonl"), "utf8")).trim().split("\n").map((l) => JSON.parse(l));
    assert.equal(values.filter((v) => v.kind === "field_instruction").length, 2500);
    assert.equal(values.filter((v) => v.kind === "template").length, 300);
    assert.equal(a.limits_hit.length, 0, JSON.stringify(a.limits_hit));
    const long = "INCLUDETEXT " + "a".repeat(6000);
    const { a: b } = await run(cwd, "long.rtf", `{\\rtf1{\\field{\\*\\fldinst ${long}}{\\fldrslt x}}}`, { max_stream_bytes: 4096 });
    assert.equal(b.fields.listed[0].instruction_cut, true);
    assert.equal(b.fields.listed[0].instruction_bytes_in_file, long.length);
    assert.ok(b.limits_hit.some((l: string) => /longer than their bound/.test(l)), JSON.stringify(b.limits_hit));
  });
});

test("RTF: a nested compound file over max_stream_bytes is a named limit, not a silent skip; a cut OLE 1.0 header is a problem", async () => {
  await withCwd(async (cwd) => {
    const cfb = buildCfb([{ name: "WordDocument", data: Buffer.alloc(64) }]);
    const { a } = await run(cwd, "big.rtf", `{\\rtf1{\\object\\objemb{\\*\\objdata ${hex(cfb)}}}}`, { max_stream_bytes: 1000 });
    assert.ok(a.limits_hit.some((l: string) => /RTF object 1: its data is \d+ bytes, over max_stream_bytes \(1000\): the object it holds was not read/.test(l)), JSON.stringify(a.limits_hit));
    assert.equal(a.objects.first[0].nested_compound_file.status, "over_budget");
    const cut = ole1Object("Package", Buffer.alloc(0)).subarray(0, 14);
    const { a: b } = await run(cwd, "cut.rtf", `{\\rtf1{\\object\\objemb{\\*\\objdata ${hex(cut)}}}}`);
    assert.ok(b.problems.some((p: string) => /RTF object 1: its OLE 1.0 ObjectHeader is cut short/.test(p)), JSON.stringify(b.problems));
  });
});

test("a file that begins with {\\rt is read as RTF, and the header is said", async () => {
  await withCwd(async (cwd) => {
    const { a } = await run(cwd, "rt.rtf", "{\\rt1{\\object\\objemb{\\*\\objdata d0cf11e0a1b11ae1}}}");
    assert.equal(a.container, "RTF");
    assert.equal(a.rtf_version_word, "rt1");
    assert.ok(a.problems.some((p: string) => /the header is \{\\rt, not \{\\rtf/.test(p)), JSON.stringify(a.problems));
    assert.equal(a.objects.count, 1);
  });
});

test("an unsupported file's head_hex is its first four bytes only", async () => {
  await withCwd(async (cwd) => {
    await put(cwd, "work/t.bin", GHP);
    const r = await tool(DOC_STRUCTURE, cwd, { path: "work/t.bin" });
    const a = JSON.parse(r.stdout);
    assert.equal(a.status, "unsupported");
    assert.equal(a.head_hex, Buffer.from(GHP.slice(0, 4)).toString("hex"));
  });
});

test("fuzz: in scan mode an object stream's objects past max_objects are not indexed, a limit says so, and the call answers", async () => {
  await withCwd(async (cwd) => {
    const pdf = xrefStreamPdf([CATALOG(), PAGES, PAGE()], { objstm: { num: 5, items: [[4, "<< /S /JavaScript /JS (x) >>"], [6, "(y)"]] } });
    // A startxref that points nowhere: the index is rebuilt by scanning, and the object stream is read for what it holds.
    const broken = Buffer.from(pdf.toString("latin1").replace(/startxref\n(\d+)/, (_m, n) => `startxref\n${Number(n) + 3}`), "latin1");
    const { a } = await run(cwd, "scan.pdf", broken, { max_objects: 5 });
    assert.equal(a.structure_source, "scan of the file for object headers");
    assert.ok(a.limits_hit.some((l: string) => /more than max_objects \(5\) objects/.test(l)), JSON.stringify(a.limits_hit));
  });
});

test("fuzz: a number of thousands of digits is an unreadable object, not a failure of the call", async () => {
  await withCwd(async (cwd) => {
    const pdf = buildPdf([CATALOG(), PAGES, PAGE(), { num: 4, body: `[ ${"9".repeat(6000)} ]` }], "/Root 1 0 R");
    const { a } = await run(cwd, "digits.pdf", pdf.file);
    assert.ok(a.problems.some((p: string) => /object 4 could not be read: a number of 6000 characters/.test(p)), JSON.stringify(a.problems));
  });
});

test("fuzz: thousands of trailer dictionaries that never close, read by scanning, do not keep their windows in memory", async () => {
  await withCwd(async (cwd) => {
    const head = buildPdf([CATALOG(), PAGES, PAGE()], "/Root 1 0 R");
    const broken = Buffer.from(head.file.toString("latin1").replace(`startxref\n${head.xrefAt}`, `startxref\n${head.xrefAt + 3}`), "latin1");
    // Each "trailer <<" opens a dictionary that the next line's "trailer" keyword breaks: every one is a failed parse at its own offset.
    const file = Buffer.concat([broken, Buffer.from("trailer\n<< /Size 9 /Root 1 0000000000 00001 f \n".repeat(6000), "latin1")]);
    await put(cwd, "work/trailers.pdf", file);
    const { run: r, rssMb } = bounded(cwd, { path: "work/trailers.pdf" }, 60_000);
    body(r);
    assert.ok(rssMb < 300, `the call peaked at ${rssMb.toFixed(0)} MB of memory`);
  });
});

test("fuzz: a target of hundreds of thousands of characters is not shown, by length only, and the call ends in time", async () => {
  await withCwd(async (cwd) => {
    // A URI whose path is 10,000 tokens between slashes, the shape a mutation of a template made: withholding each token looks back
    // across its slash, so the work is not linear in the length.
    const uri = "https://h.example/" + "x/ghp_Ab3dEf5hIj7lMn9pQr1tUv/".repeat(10_000);
    const pdf = buildPdf([CATALOG("/OpenAction 4 0 R"), PAGES, PAGE(), { num: 4, body: `<< /S /URI /URI (${uri}) >>` }], "/Root 1 0 R");
    await put(cwd, "work/long.pdf", pdf.file);
    const { run: r, seconds } = bounded(cwd, { path: "work/long.pdf", max_seconds: 5 }, 60_000);
    const a = body(r);
    assert.ok(seconds < 5 + 5, `the call took ${seconds.toFixed(1)} s`);
    const row = a.tables.pdf_actions.rows[0];
    assert.equal(row.target_length, uri.length);
    assert.match(row.target, /^<a target of \d+ characters: longer than the 2048 shown, so not shown/);
  });
});
