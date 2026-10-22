/**
 * The reverse-engineering tools, the review of the Phase-1 tools: the time the shared withholding block takes on a name of many
 * `/`-joined pieces (the growth across a slash was cubic: 13 KB of pieces took 41 s in doc_probe, twenty library names 22 s in
 * pe_info), a file whose bytes carry two formats, a ZIP whose end record names another directory than the one the standard
 * library reads, an import library name printed without the display function, the entropy pass and the DT_NEEDED loop under the
 * tool's own clock, and fuzzy_hash's SHA-256 pass and a comparison its budget did not allow.
 *
 * Every input is built here from the format's rules or from draws with a fixed seed, never from a tool's output. The secrets are
 * random strings made on the fly. Each test fails on the code before.
 */
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { readFile, readdir, truncate } from "node:fs/promises";
import { join } from "node:path";
import { test } from "node:test";
import { DOC_PROBE, DOC_STRUCTURE, FUZZY, PE_DIRECTORIES, PE_INFO, RE, body, buildElf, buildPe, buildZip, put, refused, rels, stub, tool, withCwd } from "./pack-re-harness.ts";
import type { Json, ZipEntry } from "./pack-re-harness.ts";
import { ROOT } from "./tool-library-harness.ts";

const CAPA_FLOSS = join(RE, "recipes", "capa-floss", "run.py");
const RE_COPIES = [DOC_PROBE, DOC_STRUCTURE, PE_DIRECTORIES, PE_INFO, CAPA_FLOSS];

const ALNUM = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
/** A fixed-seed generator (mulberry32): the same draws on every run. */
function rng(seed: number): () => number {
  let a = seed >>> 0;
  return () => {
    a = (a + 0x6d2b79f5) >>> 0;
    let t = a;
    t = Math.imul(t ^ (t >>> 15), t | 1);
    t ^= t + Math.imul(t ^ (t >>> 7), t | 61);
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}
const draw = (r: () => number, n: number): string => Array.from({ length: n }, () => ALNUM[Math.floor(r() * ALNUM.length)]).join("");
/** A name of `n` pieces of 25 random characters joined by `/`: each piece reads as random, so every one is judged. */
const pieces = (seed: number, n: number): string => Array.from({ length: n }, (() => { const r = rng(seed); return () => draw(r, 25); })()).join("/");

const LOAD = [
  "import importlib.util, io, json, os, random, sys, time",
  "spec = importlib.util.spec_from_file_location('tool_under_test', sys.argv[1])",
  "m = importlib.util.module_from_spec(spec)",
  "spec.loader.exec_module(m)",
].join("\n");

function py(path: string, code: string, argv: string[] = [], opts: { cwd?: string; input?: string; env?: Record<string, string>; timeout?: number } = {}): { status: number | null; stdout: string; stderr: string; seconds: number } {
  const started = Date.now();
  const r = spawnSync("python3", ["-I", "-c", `${LOAD}\n${code}`, path, ...argv], {
    encoding: "utf8", cwd: opts.cwd, input: opts.input, maxBuffer: 1 << 28, timeout: opts.timeout ?? 120_000, env: { ...process.env, AGENT_ID: "s1", ...opts.env },
  });
  return { status: r.status, stdout: r.stdout, stderr: r.stderr, seconds: (Date.now() - started) / 1000 };
}

// ---- P1: the growth across a slash is linear, in every copy of the block ---------------------------------------------------------------------------------

async function walk(dir: string, out: string[]): Promise<void> {
  for (const e of await readdir(dir, { withFileTypes: true })) {
    if (e.name === "node_modules" || e.name === ".git") continue;
    if (e.isDirectory()) await walk(join(dir, e.name), out);
    else if (e.name === "run.py") out.push(join(dir, e.name));
  }
}

async function withholdingBlock(path: string): Promise<string | null> {
  const text = await readFile(path, "utf8");
  const start = text.indexOf("# BEGIN SHARED WITHHOLDING");
  const end = text.indexOf("# END SHARED WITHHOLDING");
  return start >= 0 && end > start ? text.slice(start, end + "# END SHARED WITHHOLDING".length) : null;
}

test("every tool that carries the shared withholding block carries the same text, and on a name of 1,000 `/`-joined random pieces it takes under a second", async () => {
  const all: string[] = [];
  await walk(join(ROOT, "packs"), all);
  await walk(join(ROOT, "tool-library"), all);
  const carriers: { path: string; block: string }[] = [];
  for (const path of all) {
    const block = await withholdingBlock(path);
    if (block !== null) carriers.push({ path, block });
  }
  assert.ok(carriers.length >= 17, `${carriers.length} tools carry the block`);
  for (const c of carriers) assert.equal(c.block, carriers[0]!.block, `${c.path} carries the same block as ${carriers[0]!.path}`);
  const code = [
    "import json, re, sys, time",
    "ns = {'re': re}",
    "exec(sys.stdin.read(), ns)",
    "url = 'http://h/' + sys.argv[1]",
    "start = time.process_time()",
    "shown = ns['redact_url'](url)",
    "took = time.process_time() - start",
    "start = time.process_time()",
    "ns['scrub'](sys.argv[1])",
    "print(json.dumps({'took': took, 'scrub': time.process_time() - start, 'shown': shown}))",
  ].join("\n");
  const name = pieces(1, 1000);
  const r = spawnSync("python3", ["-I", "-c", code, name], { input: carriers[0]!.block, encoding: "utf8", timeout: 60_000 });
  assert.equal(r.status, 0, r.stderr);
  const out = JSON.parse(r.stdout) as { took: number; scrub: number; shown: string };
  assert.ok(out.took < 1 && out.scrub < 1, `redact_url took ${out.took.toFixed(2)} s and scrub ${out.scrub.toFixed(2)} s of CPU`);
  assert.match(out.shown, /^http:\/\/h\/?<token-shaped text withheld \d+ characters>$/);
});

test("the linear growth finds the spans the cubic one found, on generated texts that join pieces by `/`, `=` padding and line breaks, in each copy in the reverse-engineering pack", () => {
  // The code the shared block had before: the reference every text is compared against.
  const reference = [
    "def reference(text):",
    "    spans = [m.span() for m in m._PREFIXED.finditer(text)]",
    "    for x in m._RUN.finditer(text):",
    "        if m._token_run(x.group()):",
    "            spans.append(x.span())",
    "    for x in m._SLASHED.finditer(text):",
    "        run = x.group()",
    "        if '/' in run and sum(1 for p in run.split('/') if m._randomish(p)) >= 3 and m.re.search(r'[0-9+]', run):",
    "            spans.append(x.span())",
    "    grown = []",
    "    for start, end in spans:",
    "        while start > 1 and text[start - 1] == '/':",
    "            x = m.re.search(r'[A-Za-z0-9_+%-]+$', text[:start - 1])",
    "            if not x or not m._randomish(x.group()):",
    "                break",
    "            start = x.start()",
    "        while end < len(text) - 1 and text[end] == '/':",
    "            x = m.re.match(r'[A-Za-z0-9_+%-]+={0,2}', text[end + 1:])",
    "            if not x or not m._randomish(x.group()):",
    "                break",
    "            end = end + 1 + x.end()",
    "        grown.append((start, end))",
    "    grown.sort()",
    "    merged = []",
    "    for start, end in grown:",
    "        if merged and start <= merged[-1][1]:",
    "            merged[-1] = (merged[-1][0], max(merged[-1][1], end))",
    "        else:",
    "            merged.append((start, end))",
    "    return merged",
  ].join("\n");
  const drive = [
    "atoms = ['/', '=', '==', '\\n', '.', ':', '@', '//', ' ', 'aB3d', 'xY7z', 'Word', 'word', 'ghp_Ab3dEf5hIj7lMn9pQr1tUv3x', 'AKIAIOSFODNN7EXAMPLE', 'a9b2c7',",
    "         '0123456789abcdef0123456789abcdef', 'wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY', '_', '-', '+', '%', 'Q', '7', 'eyJhbGciOi.eyJzdWIiOi.sig', 'bearer abcdefgh123', 'Ab1', 'Ab12']",
    "rnd = random.Random(int(sys.argv[2]))",
    "bad = 0",
    "for i in range(1000):",
    "    s = ''.join(rnd.choice(atoms) if rnd.random() < 0.6 else rnd.choice('aZ09/=_-\\n.') for _ in range(rnd.randint(0, 60)))",
    "    bad += reference(s) != m.token_spans(s)",
    "print(bad)",
  ].join("\n");
  RE_COPIES.forEach((path, i) => {
    const r = py(path, `${reference}\n${drive}`, [String(100 + i)]);
    assert.equal(r.status, 0, r.stderr);
    assert.equal(r.stdout.trim(), "0", path);
  });
});

test("a text longer than the block's limit is withheld whole, by its length, in every copy in the reverse-engineering pack", () => {
  for (const path of RE_COPIES) {
    const r = py(path, [
      "n = m.TEXT_LIMIT + 1",
      "print(json.dumps([m.scrub('x' * n), m.scrub('x' * m.TEXT_LIMIT) == 'x' * m.TEXT_LIMIT, m.token_shaped('x/' * (n // 2 + 1)), m.redact_url('http://h/' + 'a' * n)]))",
    ].join("\n"));
    assert.equal(r.status, 0, `${path}: ${r.stderr}`);
    const [long, atLimit, shaped, url] = JSON.parse(r.stdout) as [string, boolean, boolean, string];
    assert.match(long, /^<over-long text withheld 2097153 characters>$/, path);
    assert.ok(atLimit, `${path}: a text of exactly the limit is examined, not withheld`);
    assert.ok(shaped, path);
    assert.match(url, /^http:\/\/h\/?<over-long text withheld \d+ characters>$/, path);
  }
});

const CT: ZipEntry = { name: "[Content_Types].xml", data: Buffer.from('<?xml version="1.0"?><Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types"/>') };

test("doc_probe: a .docx whose external target is 500 random pieces joined by `/` (13 KB) is answered in seconds, the target given by its length; before, 41 s", async () => {
  await withCwd(async (cwd) => {
    const target = "http://h.example/" + pieces(5, 500);
    const zip = buildZip([CT, { name: "word/_rels/document.xml.rels", data: Buffer.from(rels([{ id: "rId1", type: "hyperlink", target, mode: "External" }])) }]);
    await put(cwd, "work/hang.docx", zip);
    const started = Date.now();
    const r = await tool(DOC_PROBE, cwd, { path: "work/hang.docx" });
    const seconds = (Date.now() - started) / 1000;
    const a = body(r);
    assert.ok(seconds < 10, `${seconds.toFixed(1)} s`);
    assert.equal(a.status, "complete", JSON.stringify(a.problems));
    assert.equal(a.external_targets[0].target_length, target.length);
    assert.doesNotMatch(r.stdout, new RegExp(target.slice(30, 60)));
  });
});

test("doc_probe: a relationship part of 300,000 relationships ends at max_seconds, partial, with the relationships before that point listed and the clock named", async () => {
  await withCwd(async (cwd) => {
    const REL_TYPE = "http://schemas.openxmlformats.org/officeDocument/2006/relationships/hyperlink";
    const REL_NS = "http://schemas.openxmlformats.org/package/2006/relationships";
    const head = `<?xml version="1.0"?><Relationships xmlns="${REL_NS}">`;
    const rows: string[] = [];
    for (let i = 0; i < 300_000; i++) rows.push(`<Relationship Id="rId${i}" Type="${REL_TYPE}" Target="http://h.example/${i}" TargetMode="External"/>`);
    const part = Buffer.from(head + rows.join("") + "</Relationships>");
    await put(cwd, "work/many.docx", buildZip([CT, { name: "word/_rels/document.xml.rels", data: part }]));
    const started = Date.now();
    const a = body(await tool(DOC_PROBE, cwd, { path: "work/many.docx", max_seconds: 1 }));
    const seconds = (Date.now() - started) / 1000;
    assert.ok(seconds < 8, `${seconds.toFixed(1)} s with max_seconds 1`);
    assert.equal(a.status, "partial", a.status_basis);
    assert.ok(a.limits_hit.some((l: string) => /time: the relationship read stopped at max_seconds/.test(l)), JSON.stringify(a.limits_hit));
    assert.ok(a.problems.some((p: string) => /relationship read stopped at the tool's own clock/.test(p)), JSON.stringify(a.problems));
    assert.ok(a.external_targets.length > 0, "the relationships before the stop are listed");
  });
});

test("pe_info: twenty DT_NEEDED names of 3.9 KB each, with a query, are answered in seconds, and 4,096 of them are read inside 8 s, or end at max_seconds, partial, saying how many were not read", async () => {
  await withCwd(async (cwd) => {
    const name = "a/" + pieces(7, 150) + "?x=1";
    await put(cwd, "work/twenty.elf", buildElf({ cls: 64, needed: Array.from({ length: 20 }, () => name) }));
    let started = Date.now();
    const a = body(await tool(PE_INFO, cwd, { path: "work/twenty.elf" }));
    assert.ok((Date.now() - started) / 1000 < 10, "twenty names are linear");
    assert.equal(a.needed_libraries.length, 20);
    assert.equal(a.status, "complete", JSON.stringify(a.problems));
    await put(cwd, "work/many.elf", buildElf({ cls: 64, needed: Array.from({ length: 4096 }, (_v, i) => `${i}${name}`) }));
    started = Date.now();
    const b = body(await tool(PE_INFO, cwd, { path: "work/many.elf", max_seconds: 1 }));
    const seconds = (Date.now() - started) / 1000;
    assert.ok(seconds < 8, `${seconds.toFixed(1)} s with max_seconds 1`);
    if (b.status === "complete") {
      // a machine fast enough to read all 4,096 names inside the second: every name is there and nothing is claimed unread
      assert.equal(b.needed_libraries.length, 4096);
    } else {
      assert.equal(b.status, "partial");
      assert.ok(b.limits_hit.some((l: string) => /the DT_NEEDED read stopped at max_seconds/.test(l)), JSON.stringify(b.limits_hit));
      const unread = b.problems.map((p: string) => /DT_NEEDED: (\d+) of 4096 names were not read/.exec(p)).find((m: RegExpExecArray | null) => m);
      assert.ok(unread, JSON.stringify(b.problems));
      assert.equal(b.needed_libraries.length + Number(unread![1]), 4096, "every name is either listed or counted as unread");
    }
  });
});

// ---- P2-1: which container --------------------------------------------------------------------------------------------------------------------------

test("doc_probe: a file that begins {\\rtf and holds %PDF-1.4 in a control group is an RTF first, its object markers found, and the PDF reading is added with a problem", async () => {
  await withCwd(async (cwd) => {
    const rtf = "{\\rtf1\\ansi {\\*\\comment %PDF-1.4 }{\\object\\objemb{\\*\\objclass Package}{\\*\\objdata 0105000002000000}}}";
    await put(cwd, "work/poly.rtf", rtf);
    const a = body(await tool(DOC_PROBE, cwd, { path: "work/poly.rtf" }));
    assert.equal(a.container, "RTF");
    assert.equal(a.objdata_markers, 1);
    assert.deepEqual(a.classes, ["Package"]);
    assert.equal(a.status, "partial");
    assert.ok(a.problems.some((p: string) => /reads as RTF .* and also carries PDF/.test(p)), JSON.stringify(a.problems));
    assert.equal(a.also_read_as.length, 1);
    assert.equal(a.also_read_as[0].container, "PDF");
    assert.equal(a.also_read_as[0].reading.pdf_header.version, "1.4");
  });
});

test("doc_probe: a PDF with a ZIP appended is read as a PDF and as a ZIP, with a problem; a plain PDF is still complete", async () => {
  await withCwd(async (cwd) => {
    const pdf = Buffer.from("%PDF-1.4\n1 0 obj << /Type /Catalog /OpenAction 2 0 R >> endobj\ntrailer << /Root 1 0 R >>\n%%EOF\n");
    const zip = buildZip([CT, { name: "word/vbaProject.bin", data: Buffer.from("vba") }]);
    await put(cwd, "work/poly.pdf", Buffer.concat([pdf, zip]));
    const a = body(await tool(DOC_PROBE, cwd, { path: "work/poly.pdf" }));
    assert.equal(a.container, "PDF");
    assert.equal(a.status, "partial");
    assert.ok(a.problems.some((p: string) => /reads as PDF .* and also carries ZIP \(a ZIP end of central directory record at offset \d+\)/.test(p)), JSON.stringify(a.problems));
    const second = a.also_read_as.find((x: Json) => x.container === "ZIP");
    assert.ok(second, JSON.stringify(a.also_read_as));
    assert.ok(second.reading.code_related_parts.includes("word/vbaProject.bin"), JSON.stringify(second.reading));
    await put(cwd, "work/plain.pdf", pdf);
    const b = body(await tool(DOC_PROBE, cwd, { path: "work/plain.pdf" }));
    assert.equal(b.container, "PDF");
    assert.equal(b.also_read_as, undefined);
    assert.deepEqual(b.problems, []);
  });
});

// ---- P2-2: the directory the end record names ---------------------------------------------------------------------------------------------------------

/** A ZIP whose end record names directory A (at cd_off) and whose last cd_size bytes before the end record are directory B, the same size with
 * `vbaProject` spelled `vbaProjecX`: the standard library reads B, a reader that follows the offset reads A. */
function twoDirectories(): Buffer {
  const zip = buildZip([CT, { name: "word/vbaProject.bin", data: Buffer.from("vba") }, { name: "word/document.xml", data: Buffer.from("<w:document/>") }]);
  const eocd = zip.subarray(zip.length - 22);
  const cdSize = eocd.readUInt32LE(12);
  const cdOff = eocd.readUInt32LE(16);
  const a = zip.subarray(cdOff, cdOff + cdSize);
  const b = Buffer.from(a.toString("latin1").replace("vbaProject", "vbaProjecX"), "latin1");
  assert.equal(b.length, a.length);
  return Buffer.concat([zip.subarray(0, cdOff + cdSize), b, eocd]);
}

test("doc_probe: a ZIP whose end record names another directory than the one the library reads lists both, partial, with the code-related part of the second", async () => {
  await withCwd(async (cwd) => {
    await put(cwd, "work/twodir.docx", twoDirectories());
    const a = body(await tool(DOC_PROBE, cwd, { path: "work/twodir.docx" }));
    assert.equal(a.status, "partial", JSON.stringify(a.problems));
    assert.deepEqual(a.code_related_parts, [], "the directory the library read has no vbaProject.bin");
    assert.equal(a.other_directory.listed, true);
    assert.deepEqual(a.other_directory.code_related_parts, ["word/vbaProject.bin"]);
    assert.equal(a.other_directory.members_only_here, 1);
    assert.equal(a.other_directory.members_only_in_listed_directory, 1);
    assert.equal(a.other_directory.parts.length, 3);
    assert.ok(a.problems.some((p: string) => /the end record names the central directory at offset \d+, and the directory listed here is the one at offset \d+/.test(p)), JSON.stringify(a.problems));
    const plain = body(await tool(DOC_PROBE, cwd, { path: "work/twodir.docx", limit: 1 }));
    assert.equal(plain.other_directory.parts.length, 1, "limit holds the second table to a page and the whole is in a file");
    assert.equal(plain.tables.other_directory_parts.truncated, true);
  });
});

test("doc_probe: a ZIP with bytes between its members and its directory is partial and says no readable directory lies at the record's offset; an ordinary one has no other_directory", async () => {
  await withCwd(async (cwd) => {
    const zip = buildZip([CT, { name: "word/document.xml", data: Buffer.from("<w:document/>") }]);
    const cdOff = zip.readUInt32LE(zip.length - 6);
    await put(cwd, "work/padded.docx", Buffer.concat([zip.subarray(0, cdOff), Buffer.from("x".repeat(16)), zip.subarray(cdOff)]));
    const a = body(await tool(DOC_PROBE, cwd, { path: "work/padded.docx" }));
    assert.equal(a.status, "partial");
    assert.equal(a.other_directory.listed, false);
    assert.equal(a.other_directory.listed_directory_offset - a.other_directory.offset, 16);
    assert.ok(a.problems.some((p: string) => /No readable directory lies at the record's offset/.test(p)), JSON.stringify(a.problems));
    await put(cwd, "work/ordinary.docx", zip);
    const b = body(await tool(DOC_PROBE, cwd, { path: "work/ordinary.docx" }));
    assert.equal(b.status, "complete", JSON.stringify(b.problems));
    assert.equal(b.other_directory, undefined);
  });
});

// ---- P3 of doc_probe -------------------------------------------------------------------------------------------------------------------------------

test("doc_probe: limit is a whole number from 1 to 100,000, and the PDF marker scan looks at the clock before each pattern", async () => {
  await withCwd(async (cwd) => {
    await put(cwd, "work/a.pdf", "%PDF-1.4\n/OpenAction /JS\n");
    const r = refused(await tool(DOC_PROBE, cwd, { path: "work/a.pdf", limit: 100001 }));
    assert.match(r.error, /limit must be an integer from 1 to 100000/);
    const ok = body(await tool(DOC_PROBE, cwd, { path: "work/a.pdf", limit: 100000 }));
    assert.equal(ok.markers.length, 2);
    const out = py(DOC_PROBE, [
      "ctx = m.Ctx('k', 10, m.SecretValues(False), 100)",
      "ctx.expired = lambda where: True",
      "print(json.dumps(m.probe_pdf(b'%PDF-1.4 /OpenAction /JS', ctx)['markers']))",
    ].join("\n"), [], { cwd });
    assert.equal(out.status, 0, out.stderr);
    assert.equal(out.stdout.trim(), "[]");
  });
});

// ---- P2-3: an import library name is printed through the display function ---------------------------------------------------------------------------

test("pe_info: a PE import library name with user-info and a query value is withheld, where it lies is listed, and neither the secrets nor the password reach any row", async () => {
  await withCwd(async (cwd) => {
    const r = rng(11);
    const password = draw(r, 16), token = draw(r, 18);
    const library = `http://user:${password}@host.example/a.dll?token=${token}`;
    await put(cwd, "work/imports.dll", buildPe({ plus: true, imports: [{ dll: library, functions: ["Connect", "Send"] }, { dll: "KERNEL32.dll", functions: ["ExitProcess"] }] }).file);
    const out = await tool(PE_INFO, cwd, { path: "work/imports.dll", limit: 1 });
    const a = body(out);
    assert.ok(!out.stdout.includes(password) && !out.stdout.includes(token), "no secret in the answer");
    assert.equal(a.imports[1].library, "KERNEL32.dll");
    assert.match(a.imports[0].library, /^http:\/\/<userinfo withheld \d+ characters>@host\.example\/a\.dll\?token=<withheld \d+ characters>$/);
    assert.ok(a.withheld_fields.some((f: Json) => f.field === "import_library" && f.length === library.length), JSON.stringify(a.withheld_fields));
    // limit 1 keeps the whole import table in a file: its rows carry the shown name too
    const file = await readFile(join(cwd, a.tables.imports.all_results), "utf8");
    assert.ok(!file.includes(password) && !file.includes(token), "no secret in the table file");
    const rows = file.trim().split("\n").map((l) => JSON.parse(l) as Json);
    assert.equal(rows.length, 3);
    assert.equal(rows.find((x) => x.function === "Connect")!.library, a.imports[0].library);
    assert.equal(rows.find((x) => x.function === "ExitProcess")!.library, "KERNEL32.dll");
  });
});

const FOUR_GIB = 2 ** 32;

// ---- P2-4: the entropy pass has a clock and a ceiling -----------------------------------------------------------------------------------------------

test("pe_info: the entropy pass over a 400 MB section ends at max_seconds, the range is not measured and says why, the answer is partial; max_entropy_bytes has a ceiling", async () => {
  await withCwd(async (cwd) => {
    const section = { name: ".big", data: Buffer.alloc(1024), flags: 0x40000000 | 0x40, rawSizeOverride: 400 << 20 };
    const built = buildPe({ sections: [section] });
    const path = await put(cwd, "work/big.exe", built.file);
    await truncate(path, built.file.length + (410 << 20));
    const started = Date.now();
    const a = body(await tool(PE_INFO, cwd, { path: "work/big.exe", max_seconds: 1, max_entropy_bytes: FOUR_GIB }));
    const seconds = (Date.now() - started) / 1000;
    assert.ok(seconds < 5, `${seconds.toFixed(1)} s with max_seconds 1`);
    assert.equal(a.status, "partial", a.status_basis);
    assert.ok(a.limits_hit.some((l: string) => /time: the entropy pass stopped at max_seconds/.test(l)), JSON.stringify(a.limits_hit));
    const row = a.sections.find((s: Json) => s.name === ".big");
    assert.equal(row.entropy, null);
    assert.match(row.entropy_note ?? row.note ?? JSON.stringify(row), /not measured: the tool's own clock ran out/);
    assert.ok(a.entropy_work.bytes_measured < (400 << 20));
    const r = refused(await tool(PE_INFO, cwd, { path: "work/big.exe", max_entropy_bytes: (FOUR_GIB) + 1 }));
    assert.match(r.error, /max_entropy_bytes must be an integer from 0 to 4294967296/);
  });
});

// ---- P2-5: fuzzy_hash --------------------------------------------------------------------------------------------------------------------------------

const TLSH_DIGEST = "T1" + "A1B2C3D4E5".repeat(7);
const SSDEEP_DIGEST = "96:aBcDeF0123456789+/aBcDeF0123456789+/:XyZ0123456789+/";

async function engines(bin: string): Promise<void> {
  await stub(bin, "ssdeep", `if [ "$1" = "-V" ]; then echo "2.14.1"; exit 0; fi
echo 'ssdeep,1.1--blocksize:hash:hash,filename'
echo "${SSDEEP_DIGEST},\"$(basename "$3")\""`);
  await stub(bin, "tlsh", `if [ "$1" = "-version" ]; then echo "tlsh 4.12.0"; exit 0; fi
if [ "$1" = "-c" ]; then printf '57\\t%s\\n' "$4"; exit 0; fi
printf '${TLSH_DIGEST}\\t%s\\n' "$2"`);
}

test("fuzzy_hash: the SHA-256 pass is under the call's clock: with the budget spent it gives no digest, the bytes hashed, a problem, and a comparison does not call two missing digests the same file", async () => {
  await withCwd(async (cwd, bin) => {
    await engines(bin);
    await put(cwd, "work/a.bin", Buffer.from("some bytes ".repeat(500)));
    await put(cwd, "work/b.bin", Buffer.from("some bytes ".repeat(500)));
    const env = { PATH: `${bin}:${process.env.PATH}` };
    const r = py(FUZZY, [
      "m.TOTAL_BUDGET = -1",
      "sys.stdin = io.StringIO(json.dumps({'path': 'work/a.bin', 'compare_to': 'work/b.bin'}))",
      "m.main()",
    ].join("\n"), [], { cwd, env });
    assert.equal(r.status, 0, r.stderr);
    const a = JSON.parse(r.stdout) as Json;
    assert.equal(a.status, "partial");
    for (const f of a.files) {
      assert.equal(f.sha256, null);
      assert.equal(f.sha256_status, "not_attempted");
      assert.equal(f.bytes_hashed, 0);
      assert.equal(f.bytes, 5500);
    }
    assert.ok(a.problems.some((p: string) => /sha256 of path: the call's time budget of -?\d+ seconds ran out after 0 of 5500 bytes: no digest is given/.test(p)), JSON.stringify(a.problems));
    assert.equal(a.comparison.same_sha256, null, "two digests that were not made are not the same digest");
    const unit = py(FUZZY, [
      "p = sys.argv[2]",
      "print(json.dumps([m.sha256_of(p, time.monotonic() - 1), m.sha256_of(p, time.monotonic() + 100)]))",
    ].join("\n"), [join(cwd, "work/a.bin")]);
    const [late, early] = JSON.parse(unit.stdout) as [Json, Json];
    assert.deepEqual(late, [null, 0, false]);
    assert.equal(early[2], true);
    assert.equal(early[1], 5500);
  });
});

test("fuzzy_hash: a tlsh comparison the budget did not allow is a problem and the answer is partial, not complete", async () => {
  await withCwd(async (cwd, bin) => {
    await engines(bin);
    await put(cwd, "work/a.bin", Buffer.from("some bytes ".repeat(500)));
    await put(cwd, "work/b.bin", Buffer.from("other bytes ".repeat(500)));
    const env = { PATH: `${bin}:${process.env.PATH}` };
    const r = py(FUZZY, [
      // the fifth engine call is `tlsh -c`: the budget is spent just before it
      "calls = [0]",
      "original = m.Run.call",
      "def call(self, argv, label, cap=None):",
      "    calls[0] += 1",
      "    if '-c' in argv:",
      "        self.deadline = time.monotonic() - 1",
      "    return original(self, argv, label, cap)",
      "m.Run.call = call",
      "sys.stdin = io.StringIO(json.dumps({'path': 'work/a.bin', 'compare_to': 'work/b.bin'}))",
      "m.main()",
    ].join("\n"), [], { cwd, env });
    assert.equal(r.status, 0, r.stderr);
    const a = JSON.parse(r.stdout) as Json;
    assert.equal(a.comparison.tlsh_distance, null);
    assert.match(a.comparison.unavailable.reason, /^tlsh comparison not_attempted: the call's time budget/);
    assert.equal(a.status, "partial");
    assert.ok(a.problems.some((p: string) => /^tlsh comparison: tlsh comparison not_attempted/.test(p)), JSON.stringify(a.problems));
    assert.equal(a.comparison.same_sha256, false);
  });
});
