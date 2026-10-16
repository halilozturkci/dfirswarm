/**
 * doc_structure, pe_directories and the capa-floss recipe, the ninth review: the repeated part names of a ZIP read no clock and the
 * package's own content types, relationships and VBA project came after them, a mask or padding in front of a value that begins with `<`,
 * the element forms (a namespace prefix, `<property name=...>`, `<entry key=...>`, a setting with spaces around `=`), a partial answer
 * written to a pipe nobody reads, a signal while it is built, a table file that ended in the middle of a line, and `matched` one more
 * than the rows. Every input is generated here from the format's rules or from random draws with a fixed seed, never from a tool's output;
 * each test fails on the code before. The secrets drawn here are random strings made on the fly, never literals.
 */
import assert from "node:assert/strict";
import { spawn, spawnSync } from "node:child_process";
import { readFile } from "node:fs/promises";
import { join } from "node:path";
import { test } from "node:test";
import { DOC_STRUCTURE, PE_DIRECTORIES, RE, body, buildZip, put, tool, withCwd } from "./pack-re-harness.ts";
import { buildPeDirs, buildVbaProject } from "./pack-re-doc-fixtures.ts";
import { GROWTH_PY, LINEAR_ABSOLUTE, linearOk } from "./pack-re-timing.ts";

const CAPA_FLOSS = join(RE, "recipes", "capa-floss", "run.py");
const COPIES = [DOC_STRUCTURE, PE_DIRECTORIES, CAPA_FLOSS];
const CT_NS = "http://schemas.openxmlformats.org/package/2006/content-types";
const VBA_CT = "application/vnd.ms-office.vbaProject";
const EMPTY_TYPES = Buffer.from(`<?xml version="1.0"?><Types xmlns="${CT_NS}"></Types>`);

const LOAD = [
  "import importlib.util, io, json, os, random, signal, sys, time",
  "spec = importlib.util.spec_from_file_location('tool_under_test', sys.argv[1])",
  "m = importlib.util.module_from_spec(spec)",
  "spec.loader.exec_module(m)",
].join("\n");

type Ran = { status: number | null; stdout: string; stderr: string; seconds: number };

/** Python code run with the tool's module loaded as `m`; `argv` follows the module path in sys.argv (sys.argv[2] ...). */
function py(path: string, code: string, argv: string[] = [], cwd?: string, timeout = 120_000): Ran {
  const started = Date.now();
  const r = spawnSync("python3", ["-I", "-c", `${LOAD}\n${code}`, path, ...argv], { encoding: "utf8", stdio: ["ignore", "pipe", "pipe"], cwd, env: { ...process.env, AGENT_ID: "s1" }, maxBuffer: 1 << 28, timeout });
  return { status: r.status, stdout: r.stdout, stderr: r.stderr, seconds: (Date.now() - started) / 1000 };
}

// ---- P2-1: the repeated part names of a ZIP are under the clock, and the package's own parts are read before them ------------------------------------

/** A name of `length` characters of `a:b@` (the shape of a user-info: the sanitiser works on every character of it) and the same in capitals. */
const hostileBase = (i: number, length: number): string => `${i}${"a:b@".repeat(Math.ceil(length / 4))}`.slice(0, length);
const pairs = (count: number, length: number): { name: string; data: Buffer }[] =>
  Array.from({ length: count }, (_v, i) => [
    { name: `word/${hostileBase(i, length)}.xml`, data: Buffer.from("<x/>") },
    { name: `word/${hostileBase(i, length).toUpperCase()}.xml`, data: Buffer.from("<x/>") },
  ]).flat();

// A fake clock: time.monotonic is a counter; every sanitising of a string that is not already known clean moves it by 0.0004 s a character
// (the real cost is about 2 microseconds a character on this shape; this scales it up so that a small package runs out of the default clock).
const SLOW_CLOCK = [
  "now = [1000.0]",
  "time.monotonic = lambda: now[0]",
  "original = m.shown_path",
  "def slow(text):",
  "    if isinstance(text, str) and text not in m._CLEAN:",
  "        now[0] += 0.0004 * len(text)",
  "    return original(text)",
  "m.shown_path = slow",
  "m.START = now[0]",
].join("\n");

function fakeFinish(r: Ran): { answer: Record<string, any>; elapsed: number } {
  const lines = r.stdout.trim().split("\n");
  const elapsed = Number(lines.pop()!.replace("FAKE ", ""));
  return { answer: JSON.parse(lines.join("\n")), elapsed };
}

const RUN_FAKE = [
  SLOW_CLOCK,
  "sys.stdin = io.StringIO(json.dumps({'path': sys.argv[2]}))",
  "m.main()",
  "print('FAKE %.1f' % (now[0] - m.START))",
].join("\n");

test("P2-1 at the DEFAULT max_seconds (70) a package of case-variant part names, whose names, member rows and repeated-name list cost 168 s of a slowed clock on the code before, ends inside the hard limit (105 s) with its content types read", async () => {
  await withCwd(async (cwd) => {
    const file = await put(cwd, "work/dups.docx", buildZip([{ name: "[Content_Types].xml", data: EMPTY_TYPES }, ...pairs(17, 1900)]));
    const r = py(DOC_STRUCTURE, RUN_FAKE, [file], cwd, 300_000);
    assert.equal(r.status, 0, r.stderr);
    const { answer, elapsed } = fakeFinish(r);
    assert.ok(elapsed <= 105, `the call ended ${elapsed} s after it began, over the hard limit of 105 s`);
    assert.equal(answer.content_types?.read, true, "the content types were read");
    assert.equal(answer.duplicate_part_names.length, 17);
    assert.ok(["partial", "complete"].includes(answer.status), answer.status);
  });
});

test("P2-1 a package whose lists use the clock up still has its macros looked for: 70 pairs of long case-variant names (the listing alone costs more than its share of the default clock on a slowed clock) and a VBA project the content types declare are read, and the listing says it stopped", async () => {
  await withCwd(async (cwd) => {
    const vba = buildVbaProject([{ name: "Module1", source: "Sub A()\r\nEnd Sub\r\n" }]);
    const types = Buffer.from(`<?xml version="1.0"?><Types xmlns="${CT_NS}"><Override PartName="/word/macros.bin" ContentType="${VBA_CT}"/></Types>`);
    // the project is the last member: a listing that stops early never reaches it, and the scan must
    const file = await put(cwd, "work/hidden.docm", buildZip([{ name: "[Content_Types].xml", data: types }, ...pairs(70, 1900), { name: "word/macros.bin", data: vba }]));
    const r = py(DOC_STRUCTURE, RUN_FAKE, [file], cwd, 300_000);
    assert.equal(r.status, 0, r.stderr);
    const { answer, elapsed } = fakeFinish(r);
    assert.ok(elapsed <= 105, `the call ended ${elapsed} s after it began`);
    assert.equal(answer.content_types?.read, true);
    assert.deepEqual((answer.vbaproject_parts ?? []).map((p: any) => p.selected_by), [["content_type"]], JSON.stringify(answer.problems));
    assert.ok(answer.limits_hit.some((l: string) => /the (check of the part names|member loop) stopped at max_seconds \(70\) less the 28 s kept for reading the content types, the relationships and the VBA project/.test(l)), JSON.stringify(answer.limits_hit));
    assert.equal(answer.status, "partial");
  });
});

test("P2-1 the repeated-name loop reads the clock itself: a clock that moves 20 s at each problem raised ends the list after a few names, says so, and the call is back inside the hard limit", async () => {
  await withCwd(async (cwd) => {
    const entries = Array.from({ length: 40 }, (_v, i) => [{ name: `word/dup${i}.xml`, data: Buffer.from("<x/>") }, { name: `word/DUP${i}.xml`, data: Buffer.from("<x/>") }]).flat();
    const file = await put(cwd, "work/clocked.docx", buildZip([{ name: "[Content_Types].xml", data: EMPTY_TYPES }, ...entries]));
    const r = py(DOC_STRUCTURE, [
      "now = [1000.0]",
      "time.monotonic = lambda: now[0]",
      "m.START = now[0]",
      "inner = m.Ctx.problem",
      "def costly(self, text):",
      "    if 'appears' in text:",
      "        now[0] += 20",
      "    return inner(self, text)",
      "m.Ctx.problem = costly",
      "sys.stdin = io.StringIO(json.dumps({'path': sys.argv[2]}))",
      "m.main()",
      "print('FAKE %.1f' % (now[0] - m.START))",
    ].join("\n"), [file], cwd);
    assert.equal(r.status, 0, r.stderr);
    const { answer, elapsed } = fakeFinish(r);
    assert.ok(elapsed <= 105, `${elapsed} s`);
    assert.ok(answer.duplicate_part_names.length < 40 && answer.duplicate_part_names.length >= 1, `${answer.duplicate_part_names.length} names listed`);
    assert.ok(answer.limits_hit.some((l: string) => /the list of repeated part names stopped at max_seconds \(70\)/.test(l)), JSON.stringify(answer.limits_hit));
    assert.equal(answer.content_types?.read, true);
  });
});

test("P2-1 in real time: 150 or more pairs of 1,900-character case-variant names (sized from the wall-clock cost of one name on this machine now) end inside max_seconds plus two, with the content types read and the list of repeated names capped at 100 (the code before listed every one of them, 8 sanitisings of a name each, outside the clock)", async () => {
  await withCwd(async (cwd) => {
    const calibrate = py(DOC_STRUCTURE, [
      "name = 'word/' + ('0' + 'a:b@' * 475)[:1900] + '.xml'",
      "m.shown_name(name)",
      "start = time.monotonic()",
      "for i in range(12):",
      "    m.shown_name(name + str(i))",
      "print((time.monotonic() - start) / 12)",
    ].join("\n"));
    assert.equal(calibrate.status, 0, calibrate.stderr);
    const cost = Number(calibrate.stdout);
    // 0.35 s of one name's cost per pair-count: the listing takes two sanitisings of a name per pair, the code before took thirteen
    const count = Math.min(600, Math.max(150, Math.round(0.35 / cost)));
    // the lists have 60% of the clock: at least three times what they take here
    const maxSeconds = Math.max(5, Math.ceil((count * cost * 2 * 3) / 0.6));
    const file = await put(cwd, "work/real.docx", buildZip([{ name: "[Content_Types].xml", data: EMPTY_TYPES }, ...pairs(count, 1900)]));
    const started = Date.now();
    const r = await tool(DOC_STRUCTURE, cwd, { path: file, max_seconds: maxSeconds });
    const seconds = (Date.now() - started) / 1000;
    const a = body(r);
    assert.ok(seconds < maxSeconds + 2, `${count} pairs took ${seconds} s at max_seconds ${maxSeconds} (one name costs ${cost} s)`);
    assert.equal(a.content_types?.read, true);
    assert.equal(a.duplicate_part_names.length, 100, "the list is capped at 100");
    assert.equal(a.duplicate_part_names_total, count);
    assert.ok(a.problems.some((p: string) => new RegExp(`^${count} part names appear more than once in all: 10 are named in the problems and 100 are listed`).test(p)), JSON.stringify(a.problems.slice(-3)));
  });
});

test("P2-1 the repeated names are capped and said: 150 repeated names list 100, name 10 in the problems, count all 150, and the later problems of the package are not pushed out", async () => {
  await withCwd(async (cwd) => {
    const dups = Array.from({ length: 150 }, (_v, i) => [{ name: `word/dup${i}.xml`, data: Buffer.from("<x/>") }, { name: `word/DUP${i}.xml`, data: Buffer.from("<x/>") }]).flat();
    const types = Buffer.from(`<?xml version="1.0"?><Types xmlns="${CT_NS}"><Override PartName="/word/gone.bin" ContentType="${VBA_CT}"/></Types>`);
    const file = await put(cwd, "work/many.docx", buildZip([{ name: "[Content_Types].xml", data: types }, ...dups]));
    const a = body(await tool(DOC_STRUCTURE, cwd, { path: file }));
    assert.equal(a.duplicate_part_names.length, 100);
    assert.equal(a.duplicate_part_names_total, 150);
    assert.equal(a.problems.filter((p: string) => /appears 2 times/.test(p)).length, 10);
    assert.ok(a.problems.some((p: string) => /^150 part names appear more than once in all/.test(p)), JSON.stringify(a.problems));
    assert.ok(a.problems.some((p: string) => /declares word\/gone\.bin its VBA project/.test(p)), "a problem after the repeated names is still said");
    assert.equal(a.problems_not_listed, undefined);
  });
});

// ---- P2-2: the ratio check holds on a noisy runner and still fails a quadratic rule ------------------------------------------------------------------

test("P2-2 the growth check passes a linear function and fails a quadratic one (a regex that rescans the rest of the text from every position), sizes four times apart", () => {
  const r = py(DOC_STRUCTURE, [
    GROWTH_PY,
    "import re",
    "quadratic = re.compile(r'\\s*x')",
    "make = lambda n: [' ' * n, ' ' * (4 * n)]",
    "lin = growth(lambda t: t.count('x'), [' ' * 400000, ' ' * 1600000])",
    "quad = growth(lambda t: quadratic.sub('', t), make(8000))",
    "print(json.dumps({'lin': lin, 'quad': quad}))",
  ].join("\n"), [], undefined, 300_000);
  assert.equal(r.status, 0, r.stderr);
  const { lin, quad } = JSON.parse(r.stdout) as { lin: number[]; quad: number[] };
  assert.ok(linearOk(lin[0]!, lin[1]!), `linear: ${lin}`);
  assert.ok(!linearOk(quad[0]!, quad[1]!), `quadratic: ${quad}`);
  assert.ok(quad[1]! <= LINEAR_ABSOLUTE * 4, "the quadratic probe itself is quick");
});

// ---- P3-1 / P3-2: a mask or padding before a value that begins with `<`; the element forms ---------------------------------------------------------

test("P3-1 a mask, a variable, a format or padding in front of a value that begins with `<` is withheld with it: 1,000 random 12-character passwords from the 94 printable characters in each of four forms, at most two printed whole (a value that begins with a complete tag, a comment or a closing tag is markup), in all three copies; and the shapes that were printed are withheld", () => {
  for (const path of COPIES) {
    const r = py(path, [
      "pr = [chr(c) for c in range(33, 127)]",
      "rnd = random.Random(909)",
      "prefixes = [('<Password>', '</Password>', '*****'), ('<Password>', '</Password>', '${x}'), ('<Password>', '</Password>', '%s '), ('<ApiKey>', '</ApiKey>', ' ')]",
      "out = []",
      "for open_, close, mask in prefixes:",
      "    whole = 0",
      "    for _ in range(1000):",
      "        p = ''.join(rnd.choice(pr) for _ in range(12))",
      "        whole += p in m.shown_path(open_ + mask + p + close)",
      "    out.append(whole)",
      "fixed = [('<Password>*****<8r$Epb]pD</Password>', '<8r$Epb]pD'), ('<Password>${x}<Xq9Lm2rT</Password>', '<Xq9Lm2rT'), ('<Password>%s <Xq9Lm2rT</Password>', '<Xq9Lm2rT'),",
      "         ('<ApiKey> <Xq9Lm2rT </ApiKey>', '<Xq9Lm2rT'), ('<Password>** *<8r$Epb]pD', '<8r$Epb]pD'), ('&lt;Password&gt;*****&lt;8r$Epb]pD&lt;/Password&gt;', '&lt;8r$Epb]pD')]",
      "print(json.dumps({'whole': out, 'fixed': [secret in m.shown_path(text) for text, secret in fixed]}))",
    ].join("\n"));
    assert.equal(r.status, 0, `${path}: ${r.stderr}`);
    const a = JSON.parse(r.stdout) as { whole: number[]; fixed: boolean[] };
    a.whole.forEach((n, i) => assert.ok(n <= 2, `${path}: form ${i} printed ${n} of 1000 whole`));
    assert.deepEqual(a.fixed, a.fixed.map(() => false), path);
  }
});

test("P3-1 a padded placeholder is still a placeholder (`<Password> **** </Password>` is kept), and a mask followed by more text is not", () => {
  for (const path of COPIES) {
    const r = py(path, [
      "kept = ['<Password> **** </Password>', '<Password>\\t${DB_PASS}\\t</Password>', '<token> %TOKEN% </token>']",
      "gone = ['<Password> **** x</Password>', '<Password>**** <8r$Epb]pD</Password>', '<Password> ${a}${b} z</Password>']",
      "print(json.dumps({'kept': [m.shown_path(t) == t for t in kept], 'gone': [m.shown_path(t) != t for t in gone]}))",
    ].join("\n"));
    assert.equal(r.status, 0, `${path}: ${r.stderr}`);
    assert.deepEqual(JSON.parse(r.stdout), { kept: [true, true, true], gone: [true, true, true] }, path);
  }
});

test("P3-2 the element forms the review named are withheld: a namespace prefix, <property name=...>, <entry key=...>, a setting with spaces around `=`; and what is not covered is still not (CDATA, DbPassword, a setting named ApiToken)", () => {
  for (const path of COPIES) {
    const r = py(path, [
      "pw = 'Zq7' + 'kP2' + 'xw9R'",
      "covered = ['<wsse:Password>%s</wsse:Password>', '<ns1.a-b:Token>%s</ns1.a-b:Token>', '<property name=\"password\">%s</property>', \"<entry key='api_key'>%s</entry>\",",
      "           '<entry key=\"password\" type=\"x\">%s</entry>', '<property name = \"token\">%s</property>', '<setting name = \"Password\" serializeAs=\"String\"><value>%s</value></setting>',",
      "           '<wsse:Password Type=\"x\">%s']",
      "not_covered = ['<Password><![CDATA[%s]]></Password>', '<DbPassword>%s</DbPassword>', '<setting name=\"ApiToken\"><value>%s</value></setting>']",
      "print(json.dumps({'covered': [pw in m.shown_path(t % pw) for t in covered], 'not_covered': [pw in m.shown_path(t % pw) for t in not_covered]}))",
    ].join("\n"));
    assert.equal(r.status, 0, `${path}: ${r.stderr}`);
    const a = JSON.parse(r.stdout) as { covered: boolean[]; not_covered: boolean[] };
    assert.deepEqual(a.covered, a.covered.map(() => false), `${path}: a covered form printed the password`);
    assert.deepEqual(a.not_covered, [true, true, true], `${path}: the changelog says these are not covered`);
  }
});

test("P3-2 the wider element rule takes time linear in the text: 128 KB and 512 KB of each hostile shape of the new forms (namespace prefixes, entry/property open tags, settings with spaces, masks and padding in front of a `<`), best of three", () => {
  for (const path of COPIES) {
    const r = py(path, [
      GROWTH_PY,
      "units = ['<a:', '<a:' * 3 + 'Password', '<wsse:Password>', '<wsse:Password>' + '*' * 50, '<entry key=\"', '<entry key=\"password\"', '<entry key=\"password\" a=\"b\"' * 30,",
      "         '<property name = \"token\">', '<property name=', '<setting name = \"Password\">' + ' ' * 300, '<setting name   =   ', '<Password>' + '* ' * 300 + '<',",
      "         '<Password>' + ' ' * 600, '<Password>' + '${x}' * 100, '<Password>' + '%s' * 100 + '<', '<Password>' + '\\t' * 600 + '<a', '<ns:' + 'a' * 40 + ':Password>',",
      "         '<entry key=\"password\">' + '<' * 50, '<property name=\"token\">' + '&lt;' * 50]",
      "rows = []",
      "for u in units:",
      "    texts = [(u * ((1 << k) // len(u) + 1))[:1 << k] for k in (17, 19)]",
      "    rows.append([u[:24]] + growth(m.shown_path, texts))",
      "print(json.dumps(rows))",
    ].join("\n"), [], undefined, 600_000);
    assert.equal(r.status, 0, `${path}: ${r.stderr}`);
    for (const [unit, small, large] of JSON.parse(r.stdout) as [string, number, number][]) {
      assert.ok(large <= LINEAR_ABSOLUTE, `${path}: ${unit} took ${large.toFixed(2)} s for 512 KB`);
      assert.ok(linearOk(small, large), `${path}: ${unit} took ${small.toFixed(2)} s for 128 KB and ${large.toFixed(2)} s for 512 KB`);
    }
  }
});

// ---- P3-3: the partial answer of the hard limit and the pipe, and a signal while it is built ----------------------------------------------------

// A hard limit of one second and a grace of two; the first answer step never ends, so the partial answer is the document.
const STUCK_FIRST_ANSWER = [
  "m.HARD_SECONDS = 1",
  "first = [True]",
  "inner = m.final_check",
  "def stuck(*a, **k):",
  "    if first[0] and isinstance(a[0], dict) and 'status' in a[0]:",
  "        first[0] = False",
  "        time.sleep(30)",
  "    return inner(*a, **k)",
  "m.final_check = stuck",
];

function spawnPy(code: string, cwd: string, argv: string[]): { stdout: () => string; signal: (s: NodeJS.Signals) => void; start: () => void; closed: Promise<number | null> } {
  const child = spawn("python3", ["-I", "-c", `${LOAD}\n${code}`, DOC_STRUCTURE, ...argv], { cwd, env: { ...process.env, AGENT_ID: "s1" }, stdio: ["ignore", "pipe", "pipe"] });
  let out = "";
  const closed = new Promise<number | null>((resolve) => child.on("close", (c) => resolve(c)));
  return { stdout: () => out, signal: (s) => child.kill(s), start: () => child.stdout.on("data", (d: Buffer) => { out += d.toString("latin1"); }), closed };
}

test("P3-3 the hard limit's partial answer is one document: when the reader takes no byte for the whole grace, nothing is appended to what was written (the failed document does not follow a started partial)", async () => {
  await withCwd(async (cwd) => {
    // 100 Overrides and 100 members of 1,870 ordinary characters each: the partial holds well over what a pipe holds
    const word = (i: number): string => `${"alpha-beta.gamma ".repeat(110)}${i}`;
    const types = Buffer.from(`<?xml version="1.0"?><Types xmlns="${CT_NS}">${Array.from({ length: 100 }, (_v, i) => `<Override PartName="/word/${word(i)}.xml" ContentType="x/${i}"/>`).join("")}</Types>`);
    const file = await put(cwd, "work/big.docx", buildZip([{ name: "[Content_Types].xml", data: types }, ...Array.from({ length: 100 }, (_v, i) => ({ name: `word/${word(i)}.xml`, data: Buffer.from("<x/>") }))]));
    // the tool writes into a pipe whose reader (`cat`, after a sleep) takes no byte for 6 s: more than the one second plus the grace of two
    const code = [...STUCK_FIRST_ANSWER, "m.HARD_GRACE = 2", "sys.stdin = io.StringIO(json.dumps({'path': sys.argv[2]}))", "m.main()"].join("\n");
    const run = spawnSync("bash", ["-o", "pipefail", "-c", 'python3 -I -c "$CODE" "$TOOL" "$FILE" | { sleep 6; cat; }'],
      { cwd, encoding: "latin1", maxBuffer: 1 << 28, env: { ...process.env, AGENT_ID: "s1", CODE: `${LOAD}\n${code}`, TOOL: DOC_STRUCTURE, FILE: file } });
    const text = run.stdout;
    const exit = run.status;
    assert.ok(text.length >= 60_000 && text.length <= 140_000, `what the pipe took of the partial answer: ${text.length} bytes (the partial is cut where the pipe was full)`);
    assert.ok(text.startsWith("{"), text.slice(0, 40));
    assert.ok(!text.includes('"status": "failed"'), "the failed document was appended to the partial answer");
    assert.equal((text.match(/\{"tool": /g) ?? []).length, 1, "one document");
    assert.equal(exit, 1);
  });
});

test("P3-3 a signal while the partial answer of the hard limit is being built is answered by one minimal failed document, exit 128 + the signal", async () => {
  await withCwd(async (cwd) => {
    const file = await put(cwd, "work/small.docx", buildZip([{ name: "[Content_Types].xml", data: EMPTY_TYPES }, { name: "word/document.xml", data: Buffer.from("<x/>") }]));
    const run = spawnPy([...STUCK_FIRST_ANSWER, "m.HARD_GRACE = 30",
      // the build of the partial answer never ends either (PRINTING is set from the alarm on, and in a normal call only when the answer is built)
      "build = m.shown_answer",
      "def never(*a, **k):",
      "    if m.PRINTING[0]:",
      "        time.sleep(30)",
      "    return build(*a, **k)",
      "m.shown_answer = never",
      "sys.stdin = io.StringIO(json.dumps({'path': sys.argv[2]}))", "m.main()"].join("\n"), cwd, [file]);
    run.start();
    await new Promise((resolve) => setTimeout(resolve, 3500));
    run.signal("SIGTERM");
    const code = await run.closed;
    const a = JSON.parse(run.stdout()) as { status: string; error: string };
    assert.equal(a.status, "failed");
    assert.match(a.error, /stopped by signal 15/);
    assert.equal(code, 143);
  });
});

// ---- P3-4 / P3-5: a table file ends at a row; `matched` is the rows ---------------------------------------------------------------------------------

test("P3-4 a table file is complete at every row while the call runs: a page that has written 30 rows of 20 KB ends in a line break before it is closed, in both tools", () => {
  for (const path of [DOC_STRUCTURE, PE_DIRECTORIES]) {
    const r = py(path, [
      "import tempfile",
      "os.chdir(tempfile.mkdtemp())",
      "page = m.LosslessPage('t', ['k'], 2)",
      "for i in range(30):",
      "    page.add({'n': i, 'text': 'word ' * 4000})",
      "data = open(page.shown, 'rb').read()",
      "print(json.dumps({'ends_with_newline': data.endswith(b'\\n'), 'lines': data.count(b'\\n'), 'total': page.total}))",
    ].join("\n"));
    assert.equal(r.status, 0, `${path}: ${r.stderr}`);
    const a = JSON.parse(r.stdout) as { ends_with_newline: boolean; lines: number; total: number };
    assert.equal(a.ends_with_newline, true, path);
    assert.equal(a.lines, 30, path);
  }
});

test("P3-4 the partial answer of the hard limit names the table file that was started, and the file ends at a row", async () => {
  await withCwd(async (cwd) => {
    const entries = Array.from({ length: 40 }, (_v, i) => ({ name: `word/part${i}.xml`, data: Buffer.from("<x/>") }));
    const file = await put(cwd, "work/forty.docx", buildZip([{ name: "[Content_Types].xml", data: EMPTY_TYPES }, ...entries]));
    const r = py(DOC_STRUCTURE, [...STUCK_FIRST_ANSWER, "sys.stdin = io.StringIO(json.dumps({'path': sys.argv[2], 'limit': 5}))", "m.main()"].join("\n"), [file], cwd, 60_000);
    assert.equal(r.status, 0, r.stderr);
    const a = JSON.parse(r.stdout) as { status: string; tables: { parts: { matched: number; all_results?: string } }; limits_hit: string[] };
    assert.equal(a.status, "partial");
    assert.ok(a.tables.parts.all_results, JSON.stringify(a.tables.parts));
    assert.ok(a.limits_hit.some((l) => /a table file named in `all_results` holds the rows written so far, one complete row to a line, and its last line can be cut/.test(l)), JSON.stringify(a.limits_hit));
    const text = await readFile(join(cwd, a.tables.parts.all_results!), "utf8");
    assert.ok(text.endsWith("\n"));
    assert.equal(text.trim().split("\n").length, a.tables.parts.matched);
  });
});

test("P3-5 a table the clock stops counts the rows it holds: a tick that raises on the sixth row leaves `matched` at five and five lines in the file, and the ZIP's listed count is the rows", () => {
  const r = py(DOC_STRUCTURE, [
    "import tempfile",
    "os.chdir(tempfile.mkdtemp())",
    "calls = [0]",
    "def tick():",
    "    calls[0] += 1",
    "    if calls[0] > 5:",
    "        raise m.TimeUp('x')",
    "page = m.LosslessPage('t', ['k'], 2, tick)",
    "added = 0",
    "try:",
    "    for i in range(10):",
    "        page.add({'n': i})",
    "        added += 1",
    "except m.TimeUp:",
    "    pass",
    "done = page.finish()",
    "print(json.dumps({'added': added, 'matched': done['matched'], 'file': open(page.shown).read().count('\\n')}))",
  ].join("\n"));
  assert.equal(r.status, 0, r.stderr);
  const a = JSON.parse(r.stdout) as { added: number; matched: number; file: number };
  assert.equal(a.added, 5);
  assert.equal(a.matched, 5);
  assert.equal(a.file, 5);
});
