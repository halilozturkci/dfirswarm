/**
 * doc_structure, the findings of the second review (the delta review of the fixes), one case each, named after the finding, and the
 * two central guarantees the fixes are built on:
 *   - one way out (shown_answer): every key and every value the tool prints or writes, every table name and file name, every message
 *     built from the file's bytes is withheld the same way, and no list in the answer is longer than the larger of `limit` and 100;
 *   - one budget for the PDF parser (Meter): the lexer charges every piece of input it walks, in every window it is retried in, so a
 *     string, a hex string, a name, a comment, an array or a retry never outlives max_seconds, and the call ends with a named limit.
 * Every hostile file is written here from the format's own rules (ISO 32000-1 objects, cross-reference tables and incremental updates,
 * streams and the ASCIIHex filter; [MS-CFB] sectors, the FAT and directory entries; ECMA-376-2 part names; the RTF specification's
 * groups, control words and destinations; [MS-OLEDS] ObjectHeader), never from the tool's output.
 */
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import { readFile, realpath } from "node:fs/promises";
import { join } from "node:path";
import { test } from "node:test";
import { DOC_STRUCTURE, asJob, body, buildZip, filesUnder, put, tool, withCwd } from "./pack-re-harness.ts";
import type { Json, Run } from "./pack-re-harness.ts";
import { buildCfb, buildPdf, buildVbaProject, hex, ole1Object } from "./pack-re-doc-fixtures.ts";
import type { PdfObj } from "./pack-re-doc-fixtures.ts";

const AKIA = "AKIAIOSFODNN7EXAMPLE";
const GHP = "ghp_Ab3dEf5hIj7lMn9pQr1tUv3xYz5bCd7fGh9j";
const AWS_SECRET = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY";

/** Every window of nine characters of a canary: the rule allows the first four and the last four of a secret, never more. */
function windows(canary: string, n = 9): string[] {
  const out: string[] = [];
  for (let i = 0; i + n <= canary.length; i++) out.push(canary.slice(i, i + n));
  return out;
}

function noCanary(text: string, canaries: string[], where: string): void {
  for (const c of canaries) for (const w of windows(c)) assert.ok(!text.includes(w), `${where}: '${w}' of a canary is there`);
}

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

/** A case that must end within max_seconds + 2 s, as valid JSON, partial, with a named limit, and under 400 MB of peak RSS. */
function inTime(cwd: string, path: string, seconds: number, extra: Record<string, unknown> = {}, limit: RegExp | null = /max_seconds|budget|bound|max_stream_bytes|time/): Json {
  const { run: r, seconds: took, rssMb } = bounded(cwd, { path, max_seconds: seconds, ...extra }, (seconds + 30) * 1000);
  assert.notEqual(r.code, null, `${path}: killed at ${seconds + 30} s`);
  const a = JSON.parse(r.stdout);
  assert.ok(took <= seconds + 2, `${path}: ${took.toFixed(1)} s with max_seconds ${seconds}`);
  assert.ok(rssMb < 400, `${path}: ${rssMb.toFixed(0)} MB peak RSS`);
  assert.notEqual(a.status, "complete", `${path}: status complete`);
  if (limit) assert.ok(a.limits_hit.some((l: string) => limit.test(l)), `${path}: no named limit in ${JSON.stringify(a.limits_hit)}`);
  return a;
}

const CATALOG = (extra = ""): PdfObj => ({ num: 1, body: `<< /Type /Catalog /Pages 2 0 R ${extra} >>` });
const PAGES: PdfObj = { num: 2, body: "<< /Type /Pages /Kids [ 3 0 R ] /Count 1 >>" };
const PAGE = (extra = ""): PdfObj => ({ num: 3, body: `<< /Type /Page /Parent 2 0 R ${extra} >>` });
const pdfOf = (objs: PdfObj[], trailer = "/Root 1 0 R"): Buffer => buildPdf([CATALOG(), PAGES, PAGE(), ...objs], trailer).file;

// --- the one way out --------------------------------------------------------------------------------------------------------

test("the linear span finder this tool binds finds what the shared block's token_spans finds, on 30,000 generated texts", () => {
  const code = [
    "import importlib.util, random, sys",
    "spec = importlib.util.spec_from_file_location('ds', sys.argv[1]); ds = importlib.util.module_from_spec(spec); spec.loader.exec_module(ds)",
    "assert ds.token_spans is ds._linear_token_spans and ds._shared_token_spans is not ds._linear_token_spans",
    "rnd = random.Random(136)",
    "atoms = ['/', '=', '==', '\\n', '.', ':', '@', '//', ' ', 'aB3d', 'xY7z', 'Word', 'word', 'ghp_Ab3dEf5hIj7lMn9pQr1tUv3x', 'AKIAIOSFODNN7EXAMPLE', 'a9b2c7',",
    "         '0123456789abcdef0123456789abcdef', 'wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY', '_', '-', '+', '%', 'Q', '7', 'eyJhbGciOi.eyJzdWIiOi.sig', 'bearer abcdefgh123']",
    "bad = 0",
    "for i in range(30000):",
    "    s = ''.join(rnd.choice(atoms) if rnd.random() < 0.6 else rnd.choice('aZ09/=_-\\n.') for _ in range(rnd.randint(0, 60)))",
    "    bad += ds._shared_token_spans(s) != ds._linear_token_spans(s)",
    "print(bad)",
  ].join("\n");
  const r = spawnSync("python3", ["-I", "-c", code, DOC_STRUCTURE], { encoding: "utf8" });
  assert.equal(r.status, 0, r.stderr);
  assert.equal(r.stdout.trim(), "0");
});

test("every key is withheld like a value, and two keys withheld to one text are both kept: two /Type names shaped like tokens are two counts", async () => {
  await withCwd(async (cwd) => {
    const other = "ghp_Zz9yXw8vUt7sRq6pOn5mLk4jIh3gFe2dCb1a";
    const { a, text } = await run(cwd, "keys.pdf", pdfOf([
      { num: 4, body: `<< /Type /${GHP} >>` },
      { num: 5, body: `<< /Type /${other} >>` },
      { num: 6, body: `<< /Type /${GHP} >>` },
    ]));
    noCanary(text, [GHP, other], "the answer");
    const withheld = Object.entries(a.object_types).filter(([k]) => /withheld/.test(k));
    assert.equal(withheld.length, 2, JSON.stringify(a.object_types));
    assert.deepEqual(withheld.map(([, v]) => v).sort(), [1, 2]);
  });
});

test("a class id whose sixteen bytes read as text is withheld, by its length; a binary one is a GUID", async () => {
  await withCwd(async (cwd) => {
    const cfb = buildCfb([{ name: "S", data: Buffer.from("x"), clsid: Buffer.from(GHP.slice(0, 16)) }], { rootClsid: Buffer.from("0609020000000000c000000000000046", "hex") });
    const { a, text } = await run(cwd, "c.doc", cfb);
    noCanary(text, [GHP], "the answer");
    assert.equal(a.root_clsid, "00020906-0000-0000-C000-000000000046");
    assert.equal(a.tables.ole_directory.rows.find((r: Json) => r.path === "S").clsid, "<16 bytes that read as text, withheld>");
  });
});

test("the paging file of a path that holds a token is named by a digest of the path as it is printed, never of the token", async () => {
  await withCwd(async (cwd) => {
    const objs: PdfObj[] = Array.from({ length: 5 }, (_v, i) => ({ num: 4 + i, body: "<< /Type /X >>" }));
    const { a } = await run(cwd, `${GHP}/p.pdf`, pdfOf(objs), { limit: 1 });
    const file = a.tables.objects.all_results as string;
    const digest = file.match(/-([0-9a-f]{16})\.jsonl$/)![1]!;
    const real = join(await realpath(cwd), "work", GHP, "p.pdf");
    // Python's json.dumps of [key, "objects"], which names the file, with the real path as the key: what the old tool hashed
    const of = (key: string): string => createHash("sha256").update(`[${JSON.stringify(key)}, "objects"]`).digest("hex").slice(0, 16);
    assert.notEqual(digest, of(real), "the digest is of the real path, token and all");
    const shown = spawnSync("python3", ["-I", "-c", "import importlib.util, sys\nspec = importlib.util.spec_from_file_location('ds', sys.argv[1]); ds = importlib.util.module_from_spec(spec); spec.loader.exec_module(ds)\nprint(ds.shown_path(sys.argv[2]))", DOC_STRUCTURE, real], { encoding: "utf8" }).stdout.trim();
    assert.ok(!shown.includes(GHP));
    assert.equal(digest, of(shown), "the digest is of the path as it is printed");
  });
});

// --- P1-1, P1-2, P1-3: the budget of the PDF parser, and withholding that is linear ----------------------------------------------

test("P1-1 the clock holds inside a string: one escape-dense string of 30 MB, and forty unterminated ones, end within max_seconds + 2 s, named, partial", async () => {
  await withCwd(async (cwd) => {
    await put(cwd, "work/lit1.pdf", pdfOf([{ num: 4, body: "(" + "\\(".repeat(15 << 20) + ")" }]));
    inTime(cwd, "work/lit1.pdf", 1);
    const forty: PdfObj[] = Array.from({ length: 40 }, (_v, i) => ({ num: 4 + i, body: "(" + "\\\\".repeat(250_000) }));
    await put(cwd, "work/lit40.pdf", pdfOf(forty));
    inTime(cwd, "work/lit40.pdf", 2);
  });
});

test("P1-1 every lexer primitive is charged: names, comments, white space, numbers, arrays and windows re-grown for many objects end within max_seconds + 2 s", async () => {
  await withCwd(async (cwd) => {
    const many = (n: number, f: (i: number) => string): PdfObj[] => Array.from({ length: n }, (_v, i) => ({ num: 4 + i, body: f(i) }));
    // Each object is unterminated, so each one's parse runs on into the next object's bytes: those that can only end at the clock or a
    // budget name it; comments and white space are walked so fast (one possessive match per run) that they end in an error first.
    const cases: [string, Buffer, boolean][] = [
      ["names", pdfOf(many(300, () => "<< /K " + "/a".repeat(60_000))), true],
      ["numbers", pdfOf(many(300, () => "[ " + "1 ".repeat(60_000))), true],
      ["nested", pdfOf(many(300, () => "[".repeat(140) + "1 ".repeat(50_000))), true],
      ["comments", pdfOf(many(300, () => "[ " + "%x\n".repeat(40_000))), false],
      ["whitespace", pdfOf(many(300, () => "[ " + " ".repeat(120_000))), false],
    ];
    for (const [name, file, named] of cases) {
      await put(cwd, `work/${name}.pdf`, file);
      inTime(cwd, `work/${name}.pdf`, 1, {}, named ? undefined : null);
    }
  });
});

test("P1-2 a hex string of 30 MB, a space every two digits or all filler, is read a piece at a time: peak RSS stays under 400 MB", async () => {
  await withCwd(async (cwd) => {
    await put(cwd, "work/hexws.pdf", pdfOf([{ num: 4, body: "<" + "4a ".repeat(10 << 20) + ">" }]));
    const one = bounded(cwd, { path: "work/hexws.pdf" }, 60_000);
    assert.ok(one.rssMb < 400, `${one.rssMb.toFixed(0)} MB`);
    assert.equal(JSON.parse(one.run.stdout).census.objects_listed, 4);
    await put(cwd, "work/hexfill.pdf", pdfOf([{ num: 4, body: "<" + "g".repeat(30 << 20) + ">" }]));
    const two = bounded(cwd, { path: "work/hexfill.pdf" }, 60_000);
    assert.ok(two.rssMb < 400, `${two.rssMb.toFixed(0)} MB`);
  });
});

test("P1-3 a /Type name of 13 KB of #2F-joined tokens, and an RTF class name and template of slash-joined tokens, end in time, given by length", async () => {
  await withCwd(async (cwd) => {
    const tokens = Array.from({ length: 300 }, (_v, i) => `ghp_${String(i).padStart(4, "0")}Ab3dEf5hIj7lMn9pQr1tUv3x`);
    await put(cwd, "work/ns.pdf", pdfOf([{ num: 4, body: `<< /Type /${tokens.slice(0, 13_000 / 40).join("#2F")} >>` }]));
    const { run: r, seconds } = bounded(cwd, { path: "work/ns.pdf", max_seconds: 2 }, 60_000);
    assert.ok(seconds <= 4, `${seconds.toFixed(1)} s`);
    const a = JSON.parse(r.stdout);
    assert.ok(Object.keys(a.object_types).some((k) => /^<a name of \d+ bytes at offset \d+>$/.test(k)), JSON.stringify(a.object_types));
    noCanary(r.stdout, tokens.slice(0, 3), "the answer");
    const slashed = tokens.join("/");
    await put(cwd, "work/cs.rtf", `{\\rtf1{\\object\\objemb{\\*\\objclass ${slashed.slice(0, 4000)}}{\\*\\objdata 00}}{\\*\\template ${slashed}}{\\*\\template ${slashed.slice(0, 2000)}}}`);
    const rt = bounded(cwd, { path: "work/cs.rtf", max_seconds: 2 }, 60_000);
    assert.ok(rt.seconds <= 4, `${rt.seconds.toFixed(1)} s`);
    noCanary(rt.run.stdout, tokens, "the RTF answer");
  });
});

// --- P1-4, P1-5: nothing of the file in a message, a table name or a file name ------------------------------------------------------

test("P1-4 no message quotes the file: a token where the lexer expects a value, and an object stream offset into a token, are described by length and offset", async () => {
  await withCwd(async (cwd) => {
    const { a, text } = await run(cwd, "lex.pdf", pdfOf([{ num: 4, body: `[ ${GHP} ]` }, { num: 5, body: `<< /K ${AWS_SECRET} >>` }, { num: 6, body: `${AKIA}` }]));
    noCanary(text, [GHP, AWS_SECRET, AKIA], "the answer");
    assert.ok(a.problems.some((p: string) => /an unexpected token of \d+ bytes at offset \d+/.test(p)), JSON.stringify(a.problems));
    for (const f of await filesUnder(join(cwd, "work"))) if (!f.endsWith("lex.pdf") && !/withheld-names/.test(f)) noCanary(await readFile(join(cwd, "work", f), "latin1"), [GHP, AWS_SECRET, AKIA], f);
  });
});

test("P1-5 a nested compound file's directory is a row of one table the tool names: a ZIP member named after a token names no table and no file, in a job or not", async () => {
  await withCwd(async (cwd) => {
    const zip = buildZip([
      { name: "[Content_Types].xml", data: Buffer.from('<?xml version="1.0"?><Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types"/>') },
      { name: `word/${GHP}/vbaProject.bin`, data: buildVbaProject([{ name: "Module1", source: "Sub A()\r\nEnd Sub\r\n" }]) },
      { name: `xl/${AKIA}x/vbaProject.bin`, data: buildVbaProject([{ name: "Module1", source: "Sub B()\r\nEnd Sub\r\n" }]) },
    ]);
    await put(cwd, "work/in/z.docm", zip);
    for (const job of [false, true]) {
      const r = job ? await asJob(DOC_STRUCTURE, cwd, { path: "work/in/z.docm", limit: 1 }) : await tool(DOC_STRUCTURE, cwd, { path: "work/in/z.docm", limit: 1 });
      const a = body(r);
      noCanary(r.stdout, [GHP, AKIA], `the answer${job ? " (job)" : ""}`);
      assert.deepEqual(Object.keys(a.tables).filter((k) => k.startsWith("ole_")), ["ole_nested_directories"]);
      assert.deepEqual(a.vbaproject_parts.map((p: Json) => p.directory.container), [1, 2]);
      assert.ok(a.tables.ole_nested_directories.matched > 2);
      for (const dir of ["work", "out"]) {
        for (const f of await filesUnder(join(cwd, dir)).catch(() => [] as string[])) {
          if (f.startsWith("in/")) continue;
          noCanary(f, [GHP, AKIA], `a file name under ${dir}`);
          if (!/withheld-names/.test(f)) noCanary(await readFile(join(cwd, dir, f), "latin1"), [GHP, AKIA], `${dir}/${f}`);
        }
      }
    }
  });
});

// --- P2 ----------------------------------------------------------------------------------------------------------------------

test("P2-2 a stream padded to the 64 KiB window's edge is still a stream: a JavaScript OpenAction's stream is found at gaps 0 to 15 around the edge", async () => {
  await withCwd(async (cwd) => {
    const js = Buffer.from("app.alert('edge');", "latin1");
    for (const gap of [0, 1, 3, 8, 15]) {
      // Object 4 comes first, so its window starts at its header: its dictionary ends `gap` bytes before the 64 KiB edge, and the
      // 'stream' keyword lies past it.
      const head = `<< /Length ${js.length} /Pad (`;
      const tail = ") >>";
      const pad = 65536 - "4 0 obj\n".length - head.length - tail.length - gap;
      const pdf = buildPdf([{ num: 4, body: head + "a".repeat(pad) + tail + "\n".repeat(gap), stream: js }, CATALOG("/OpenAction << /S /JavaScript /JS 4 0 R >>"), PAGES, PAGE()], "/Root 1 0 R");
      assert.equal(pdf.file.indexOf(">>", pdf.offsets.get(4)! + 8 + head.length + pad) + 2 - pdf.offsets.get(4)!, 65536 - gap);
      const { a } = await run(cwd, `edge${gap}.pdf`, pdf.file);
      const row = a.tables.pdf_actions.rows.find((r: Json) => r.trigger === "Catalog/OpenAction");
      assert.equal(row.script.form, "stream", `gap ${gap}: ${JSON.stringify(row)}`);
      assert.equal(a.streams.count, 1);
    }
  });
});

test("P2-3 a /Next chain that returns to itself is one action and a named cycle, in time", async () => {
  await withCwd(async (cwd) => {
    const pdf = buildPdf([CATALOG("/OpenAction 4 0 R"), PAGES, PAGE(), { num: 4, body: "<< /S /URI /URI (http://example.test/) /Next 4 0 R >>" }], "/Root 1 0 R").file;
    const { a: b } = await run(cwd, "loop2.pdf", pdf, { max_depth: 10000 });
    assert.equal(b.actions.count, 1, JSON.stringify(b.tables.pdf_actions.rows.slice(0, 3)));
    assert.ok(b.problems.some((p: string) => /returns to object 4: a cycle/.test(p)));
    // 700 actions in a chain whose last returns to the first: 700 rows, one cycle, no growing trigger text
    const chain: PdfObj[] = Array.from({ length: 700 }, (_v, i) => ({ num: 4 + i, body: `<< /S /URI /URI (http://e.test/${i}) /Next ${4 + ((i + 1) % 700)} 0 R >>` }));
    const big = buildPdf([CATALOG("/OpenAction 4 0 R"), PAGES, PAGE(), ...chain], "/Root 1 0 R").file;
    await put(cwd, "work/chain.pdf", big);
    const { run: r, seconds } = bounded(cwd, { path: "work/chain.pdf", max_depth: 10000, max_seconds: 10 }, 60_000);
    assert.ok(seconds < 12);
    const c = JSON.parse(r.stdout);
    assert.equal(c.actions.count, 700);
    assert.ok(r.stdout.length < 2 << 20, `${r.stdout.length} bytes of answer`);
    assert.ok(c.tables.pdf_actions.rows.every((x: Json) => x.trigger === null || x.trigger.length < 64));
  });
});

test("P2-4 RTF: thousands of objects that each hold a compound file with a VBA project end within max_seconds + 2 s, named, and the answer stays small", async () => {
  await withCwd(async (cwd) => {
    const obj = `{\\object\\objemb{\\*\\objclass Word.Document.8}{\\*\\objdata ${hex(ole1Object("Word.Document.8", buildVbaProject([{ name: "Module1", source: "Sub A()\r\nEnd Sub\r\n" }])))}}}`;
    await put(cwd, "work/many.rtf", "{\\rtf1" + obj.repeat(6000) + "}");
    const a = inTime(cwd, "work/many.rtf", 1);
    assert.ok(JSON.stringify(a).length < 4 << 20);
  });
});

test("P2-5 the answer is bounded: 1,200 spellings of word/vbaProject.bin are one nested-directory table, and no list is longer than the larger of limit and 100", async () => {
  await withCwd(async (cwd) => {
    const vba = buildVbaProject([{ name: "Module1", source: "Sub A()\r\nEnd Sub\r\n" }]);
    const base = "word/vbaProject.bin";
    const letters = [...base].map((c, k) => (/[a-z]/i.test(c) ? k : -1)).filter((k) => k >= 0);
    const spell = (i: number): string => [...base].map((c, k) => (letters.indexOf(k) >= 0 && (i >> letters.indexOf(k)) & 1 ? c.toUpperCase() : c.toLowerCase())).join("");
    const names = new Set<string>(Array.from({ length: 1200 }, (_v, i) => spell(i)));
    const zip = buildZip([{ name: "[Content_Types].xml", data: Buffer.from('<?xml version="1.0"?><Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types"/>') },
      ...[...names].map((name) => ({ name, data: vba }))]);
    await put(cwd, "work/v.docm", zip);
    const { run: r } = bounded(cwd, { path: "work/v.docm", limit: 50 }, 120_000);
    const a = JSON.parse(r.stdout);
    assert.ok(r.stdout.length < 2 << 20, `${r.stdout.length} bytes of answer`);
    assert.deepEqual(Object.keys(a.tables).filter((k) => k.startsWith("ole_")), ["ole_nested_directories"]);
    const longest = (v: Json): number => Array.isArray(v) ? Math.max(v.length, ...v.map(longest)) : v && typeof v === "object" ? Math.max(0, ...Object.values(v).map(longest)) : 0;
    assert.ok(longest(a) <= 100, `a list of ${longest(a)} items`);
    assert.equal(a.vbaproject_parts_not_shown.items, a.duplicate_part_names[0].copies);
  });
});

test("P2-6 RTF readers ignore CR and LF in text: a class name, a field type and a key split by a line break are read joined, and the key is withheld", async () => {
  await withCwd(async (cwd) => {
    const { a, text } = await run(cwd, "crlf.rtf", `{\\rtf1{\\object\\objemb{\\*\\objclass Equ\r\nation.3}{\\*\\objdata 00}}{\\object\\objemb{\\*\\objclass ${AKIA.slice(0, 9)}\r\n${AKIA.slice(9)}}{\\*\\objdata 00}}{\\field{\\*\\fldinst HYPER\r\nLINK "x"}{\\fldrslt y}}}`);
    assert.equal(a.objects.first[0].class_name, "Equation.3");
    noCanary(text, [AKIA], "the answer");
    assert.equal(a.fields.listed[0].instruction_word, "HYPERLINK");
  });
});

test("P2-7 a field inside another field's instruction, and a field inside a template, are rows of their own", async () => {
  await withCwd(async (cwd) => {
    const { a } = await run(cwd, "nest.rtf", `{\\rtf1{\\field{\\*\\fldinst QUOTE {\\field{\\*\\fldinst DDEAUTO c:\\\\x y}{\\fldrslt r}} }{\\fldrslt q}}{\\*\\template {\\field{\\*\\fldinst INCLUDETEXT "t"}}}}`);
    assert.deepEqual(a.fields.listed.map((f: Json) => [f.instruction_word, !!f.inside_another_instruction]).sort(), [["DDEAUTO", true], ["INCLUDETEXT", true], ["QUOTE", false]]);
    assert.equal(a.fields.count, 3);
    assert.equal(a.templates.length, 1);
  });
});

test("P2-8 an object the newest cross-reference section frees is counted, and a JavaScript action in it is listed and leaves the answer partial", async () => {
  await withCwd(async (cwd) => {
    const first = buildPdf([CATALOG(), PAGES, PAGE(), { num: 4, body: "<< /S /JavaScript /JS (app.alert\\(1\\)) >>" }], "/Root 1 0 R");
    const at = first.file.length;
    const update = Buffer.from(`xref\n4 1\n0000000000 00001 f \ntrailer\n<< /Size 5 /Root 1 0 R /Prev ${first.xrefAt} >>\nstartxref\n${at}\n%%EOF\n`, "latin1");
    const { a } = await run(cwd, "del.pdf", Buffer.concat([first.file, update]));
    assert.equal(a.objects_scan.headers_freed_in_newest_chain, 1);
    assert.deepEqual(a.actions.outside_chain, { freed: 1, absent: 0 });
    assert.deepEqual(a.tables.pdf_actions.rows.map((r: Json) => [r.object, r.action, r.outside_chain, r.reached_from_catalog]), [[4, "JavaScript", "freed", false]]);
    assert.equal(a.status, "partial");
    assert.ok(a.problems.some((p: string) => /does not use/.test(p)));
  });
});

// --- P3 ----------------------------------------------------------------------------------------------------------------------

test("RTF control words with a capital letter are counted and never printed (the specification's are lowercase); the header word too; every word is a table row", async () => {
  await withCwd(async (cwd) => {
    const words = Array.from({ length: 60 }, (_v, i) => `\\w${String.fromCharCode(97 + (i % 26))}${String.fromCharCode(97 + Math.floor(i / 26))}`).join(" ");
    const { a, text } = await run(cwd, "cw.rtf", `{\\rt${AKIA}{\\${AKIA} x}{\\*\\${GHP.slice(4, 30)} y} ${words}}`);
    noCanary(text, [AKIA, GHP.slice(4)], "the answer");
    assert.equal(a.rtf_version_word, null);
    assert.ok(a.control_words.with_capital_letters.occurrences >= 2);
    assert.equal(a.tables.rtf_control_words.matched, a.control_words.distinct);
    assert.ok(a.control_words.distinct > 40 && a.control_words.top.length === 40);
  });
});

test("scan mode: an 'endstream' inside a stream's data does not end it when its direct /Length says where it ends, and a trailer on a line longer than 4,096 bytes is not called a comment", async () => {
  await withCwd(async (cwd) => {
    const data = Buffer.from("x endstream\ntrailer << /Size 3 /Root 9 0 R >>\n y", "latin1");
    const body = `%PDF-1.7\n1 0 obj\n<< /Type /Catalog /Pages 2 0 R >>\nendobj\n2 0 obj\n<< /Type /Pages /Kids [] /Count 0 >>\nendobj\n3 0 obj\n<< /Length ${data.length} >>\nstream\n${data.toString("latin1")}\nendstream\nendobj\n`;
    const { a } = await run(cwd, "s1.pdf", Buffer.from(`${body}trailer\n<< /Size 4 /Root 1 0 R >>\n%%EOF\n`, "latin1"));
    assert.equal(a.trailer_keywords_ignored.in_stream_data, 1, JSON.stringify(a.trailer_keywords_ignored));
    assert.equal(a.catalog.object, 1);
    const long = `%PDF-1.7\n1 0 obj\n<< /Type /Catalog /Pages 2 0 R >>\nendobj\n2 0 obj\n<< /Type /Pages /Kids [] /Count 0 >>\nendobj\n${" ".repeat(5000)}trailer\n<< /Size 3 /Root 1 0 R >>\n%%EOF\n`;
    const { a: b } = await run(cwd, "s2.pdf", Buffer.from(long, "latin1"));
    assert.equal(b.trailer_keywords_ignored, undefined, JSON.stringify(b.anomalies));
    assert.equal(b.catalog.object, 1);
  });
});

test("an outline whose /Next returns to itself is a named cycle", async () => {
  await withCwd(async (cwd) => {
    const { a } = await run(cwd, "ol.pdf", buildPdf([CATALOG("/Outlines 4 0 R"), PAGES, PAGE(), { num: 4, body: "<< /First 5 0 R >>" }, { num: 5, body: "<< /Title (a) /Next 5 0 R >>" }], "/Root 1 0 R").file);
    assert.ok(a.problems.some((p: string) => /the outline returns to object 5: a cycle/.test(p)), JSON.stringify(a.problems));
    assert.equal(a.status, "partial");
  });
});

/** Patch a built compound file: the FAT entry of sector n, and directory entry fields by name ([MS-CFB] 2.2, 2.6). */
function cfbPatch(file: Buffer): { fatAt: (n: number) => number; entry: (name: string) => number; start: (name: string) => number } {
  const fatSector = file.readUInt32LE(76);
  const dirSector = file.readUInt32LE(48);
  const fatAt = (n: number): number => (fatSector + 1) * 512 + 4 * n;
  const entry = (name: string): number => {
    for (let i = 0; i < 4; i++) {
      const at = (dirSector + 1) * 512 + i * 128;
      if (file.subarray(at, at + file.readUInt16LE(at + 64) - 2).toString("utf16le") === name) return at;
    }
    throw new Error("no entry " + name);
  };
  return { fatAt, entry, start: (name) => file.readUInt32LE(entry(name) + 116) };
}

test("OLE: a stream chain that goes on past its size and loops, two streams sharing a chain, and a FAT sector not marked FATSECT are each a problem", async () => {
  await withCwd(async (cwd) => {
    const base = (): Buffer => buildCfb([{ name: "A", data: Buffer.alloc(5000, 0x41) }, { name: "B", data: Buffer.alloc(5000, 0x42) }]);
    const tail = base();
    const p = cfbPatch(tail);
    const a0 = p.start("A");
    tail.writeUInt32LE(a0, p.fatAt(a0 + 9)); // A holds sectors a0..a0+9 (5000 bytes): its last one links back to its first
    const { a } = await run(cwd, "tail.doc", tail);
    assert.ok(a.problems.some((x: string) => /stream A: its chain goes on past the 10 sector\(s\) its size needs and ends with loop/.test(x)), JSON.stringify(a.problems));
    const shared = base();
    const q = cfbPatch(shared);
    shared.writeUInt32LE(q.start("A"), q.entry("B") + 116);
    const { a: b } = await run(cwd, "shared.doc", shared);
    assert.ok(b.problems.some((x: string) => /stream B: sector \d+ of its chain is also in the chain of directory entry \d+/.test(x)), JSON.stringify(b.problems));
    const fat = base();
    const r = cfbPatch(fat);
    fat.writeUInt32LE(0xfffffffe, r.fatAt(fat.readUInt32LE(76)));
    const { a: c } = await run(cwd, "fat.doc", fat);
    assert.ok(c.problems.some((x: string) => /1 FAT sector\(s\) are not marked FATSECT/.test(x)), JSON.stringify(c.problems));
  });
});

test("an action in an object after the last %%EOF, with no entry in the chain, is listed as outside the chain (absent), and the answer is partial", async () => {
  await withCwd(async (cwd) => {
    const pdf = buildPdf([CATALOG(), PAGES, PAGE()], "/Root 1 0 R").file;
    const { a } = await run(cwd, "after.pdf", Buffer.concat([pdf, Buffer.from("9 0 obj\n<< /S /Launch /F (cmd.exe) >>\nendobj\n", "latin1")]));
    assert.equal(a.objects_scan.headers_not_in_the_cross_reference_chain, 1);
    assert.deepEqual(a.actions.outside_chain, { freed: 0, absent: 1 });
    assert.equal(a.status, "partial");
  });
});

test("a cross-reference stream whose /Index holds 400,000 pairs past its data ends at the clock", async () => {
  await withCwd(async (cwd) => {
    // ISO 32000-1 7.5.8.2: /Index is pairs of (first object, count). The stream holds four entries; every pair after the first asks for
    // one more, so each one is a short read that is said, and the clock has to hold between pairs, not only between entries.
    const { deflateSync } = await import("node:zlib");
    const head = "%PDF-1.7\n";
    const data = deflateSync(Buffer.alloc(4 * 7));
    const index = "0 4 " + "10 1 ".repeat(400_000);
    const xs = Buffer.concat([Buffer.from(`4 0 obj\n<< /Type /XRef /Size 5 /W [1 4 2] /Index [${index}] /Filter /FlateDecode /Length ${data.length} >>\nstream\n`, "latin1"), data, Buffer.from("\nendstream\nendobj\n", "latin1")]);
    await put(cwd, "work/idx.pdf", Buffer.concat([Buffer.from(head, "latin1"), xs, Buffer.from(`startxref\n${head.length}\n%%EOF\n`, "latin1")]));
    const { seconds } = bounded(cwd, { path: "work/idx.pdf", max_seconds: 3 }, 60_000);
    assert.ok(seconds <= 5, `${seconds.toFixed(1)} s`);
  });
});

test("an ASCIIHex stream that decodes to exactly max_stream_bytes is read, white space and all; one byte more is a named limit", async () => {
  await withCwd(async (cwd) => {
    const cap = 1 << 16;
    const enc = (n: number): Buffer => Buffer.from("4a  ".repeat(n) + ">", "latin1");
    const pdf = buildPdf([CATALOG("/OpenAction << /S /JavaScript /JS 4 0 R >>"), PAGES, PAGE(), { num: 4, body: "<< /Filter /ASCIIHexDecode >>", stream: enc(cap) }, { num: 5, body: "<< /Filter /ASCIIHexDecode >>", stream: enc(cap + 1) }], "/Root 1 0 R").file;
    const { a } = await run(cwd, "ahx.pdf", pdf, { max_stream_bytes: cap, extract_to: "work/s1/x", extract: ["pdf:4", "pdf:5"] });
    assert.deepEqual(a.extracted.map((r: Json) => [r.locator, r.status, r.bytes]), [["object 4", "written", cap]]);
    assert.ok(a.limits_hit.some((l: string) => /extract pdf:5: a stream expanded past max_stream_bytes/.test(l)), JSON.stringify(a.limits_hit));
  });
});

test("the objects of an object stream refused at the stream budget are counted as not read at a limit, and the census is not complete", async () => {
  await withCwd(async (cwd) => {
    const { deflateSync } = await import("node:zlib");
    const inner = "5 0 6 20 ";
    const plain = Buffer.concat([Buffer.from(inner + "<< /Type /Page >>   << /S /URI /URI (http://x.test/) >>", "latin1"), Buffer.alloc(200_000, 0x20)]);
    const parts: Buffer[] = [Buffer.from("%PDF-1.7\n", "latin1")];
    let at = parts[0]!.length;
    const off = new Map<number, number>();
    const add = (n: number, b: Buffer): void => { off.set(n, at); parts.push(b); at += b.length; };
    add(1, Buffer.from("1 0 obj\n<< /Type /Catalog /Pages 2 0 R /OpenAction 6 0 R >>\nendobj\n", "latin1"));
    add(2, Buffer.from("2 0 obj\n<< /Type /Pages /Kids [ ] /Count 0 >>\nendobj\n", "latin1"));
    const data = deflateSync(plain);
    add(4, Buffer.concat([Buffer.from(`4 0 obj\n<< /Type /ObjStm /N 2 /First ${inner.length} /Filter /FlateDecode /Length ${data.length} >>\nstream\n`, "latin1"), data, Buffer.from("\nendstream\nendobj\n", "latin1")]));
    const rows = [[0, 0, 0], [1, off.get(1)!, 0], [1, off.get(2)!, 0], [0, 0, 0], [1, off.get(4)!, 0], [2, 4, 0], [2, 4, 1], [1, at, 0]];
    const xr = deflateSync(Buffer.concat(rows.map((r) => Buffer.from([r[0]!, (r[1]! >> 24) & 255, (r[1]! >> 16) & 255, (r[1]! >> 8) & 255, r[1]! & 255, r[2]!]))));
    add(7, Buffer.concat([Buffer.from(`7 0 obj\n<< /Type /XRef /Size 8 /W [1 4 1] /Root 1 0 R /Filter /FlateDecode /Length ${xr.length} >>\nstream\n`, "latin1"), xr, Buffer.from("\nendstream\nendobj\n", "latin1")]));
    parts.push(Buffer.from(`startxref\n${off.get(7)}\n%%EOF\n`, "latin1"));
    const { a } = await run(cwd, "os.pdf", Buffer.concat(parts), { max_stream_bytes: 1000 });
    assert.equal(a.census.objects_not_read_at_a_limit, 2, JSON.stringify(a.census));
    assert.equal(a.census.objects_unreadable, 0);
    assert.equal(a.census.complete, false);
  });
});

test("in an encrypted file pdf-raw:<n> is written marked ciphertext, and pdf:<n> is not decoded (no key is tried)", async () => {
  await withCwd(async (cwd) => {
    const pdf = buildPdf([CATALOG(), PAGES, PAGE(), { num: 4, body: "<< /Filter /FlateDecode >>", stream: Buffer.from("not deflate: ciphertext") },
      { num: 5, body: "<< /Filter /Standard /V 2 /R 3 /Length 128 /P -4 /O (0123456789abcdef0123456789abcdef) /U (0123456789abcdef0123456789abcdef) >>" }], "/Root 1 0 R /Encrypt 5 0 R /ID [<00> <00>]").file;
    const { a } = await run(cwd, "enc.pdf", pdf, { extract_to: "work/s1/e", extract: ["pdf:4", "pdf-raw:4"] });
    assert.deepEqual(a.extracted.map((r: Json) => [r.locator, r.status, r.ciphertext]), [["object 4", "written", true]]);
    assert.match(a.extracted[0].source, /ciphertext/);
    assert.ok(a.problems.some((p: string) => /extract pdf:4: the file is encrypted and no key is tried/.test(p)), JSON.stringify(a.problems));
  });
});

test("an embedded file's withheld name is kept in the names file as a PDF file specification name", async () => {
  await withCwd(async (cwd) => {
    const pdf = buildPdf([CATALOG("/Names << /EmbeddedFiles 4 0 R >>"), PAGES, PAGE(), { num: 4, body: "<< /Names [ (a) 5 0 R ] >>" }, { num: 5, body: `<< /Type /Filespec /F (${GHP}.txt) >>` }], "/Root 1 0 R").file;
    const { a } = await run(cwd, "ef.pdf", pdf);
    const names = (await readFile(join(cwd, a.withheld_names_file), "utf8")).trim().split("\n").map((l) => JSON.parse(l));
    assert.ok(names.some((n: Json) => n.kind === "pdf_filespec_name" && n.name === `${GHP}.txt`), JSON.stringify(names));
  });
});

