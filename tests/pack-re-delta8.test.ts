/**
 * doc_structure, pe_directories and the capa-floss recipe, the eighth review: the element form of a secret-named key (a `>` in the
 * password, no closing tag, a long value, attributes in the open tag, a .NET setting), placeholders, and the answer's own time (rows
 * withheld while they are added, strings the answer has no time for, the part-name check under the clock, a cap on `limit`, a partial
 * answer at the hard limit). Every input is generated here from the format's rules or from random draws with a fixed seed, never
 * from a tool's output; each test fails on the code before. Random secrets are drawn from the 94 printable characters.
 */
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "node:test";
import { DOC_STRUCTURE, PE_DIRECTORIES, RE, body, buildZip, put, refused, tool, withCwd } from "./pack-re-harness.ts";
import { buildPeDirs } from "./pack-re-doc-fixtures.ts";
import { GROWTH_PY, LINEAR_ABSOLUTE, linearOk } from "./pack-re-timing.ts";

const CAPA_FLOSS = join(RE, "recipes", "capa-floss", "run.py");
const COPIES = [DOC_STRUCTURE, PE_DIRECTORIES, CAPA_FLOSS];

const LOAD = [
  "import importlib.util, io, json, os, random, signal, sys, time",
  "spec = importlib.util.spec_from_file_location('tool_under_test', sys.argv[1])",
  "m = importlib.util.module_from_spec(spec)",
  "spec.loader.exec_module(m)",
].join("\n");

type Ran = { status: number | null; stdout: string; stderr: string; seconds: number };

/** Python code run with the tool's module loaded as `m`; `argv` follows the module path in sys.argv (sys.argv[2] ... ); stdin is not used. */
function py(path: string, code: string, argv: string[] = [], cwd?: string, timeout = 120_000): Ran {
  const started = Date.now();
  const r = spawnSync("python3", ["-I", "-c", `${LOAD}\n${code}`, path, ...argv], { encoding: "utf8", stdio: ["ignore", "pipe", "pipe"], cwd, env: { ...process.env, AGENT_ID: "s1" }, maxBuffer: 1 << 28, timeout });
  return { status: r.status, stdout: r.stdout, stderr: r.stderr, seconds: (Date.now() - started) / 1000 };
}

// ---- P1: the element form withholds to the end of its text ---------------------------------------------------------------------------

// each template is Python source that makes the text from the password `p`
const ELEMENT_FORMS: [string, string][] = [
  ["raw element", "'<Password>' + p + '</Password>'"],
  ["escaped element", "'&lt;Password&gt;' + p + '&lt;/Password&gt;'"],
  ["raw, no closing tag", "'<Password>' + p"],
  ["escaped, no closing tag", "'&lt;Password&gt;' + p"],
  ["raw, text after it on the line", "'<Password>' + p + '\\tmore text'"],
  ["attribute in the open tag", "'<Password Type=\"x\">' + p + '</Password>'"],
  ["two attributes, one unquoted", "'<Password Type=\"x\" Enc=y>' + p + '</Password>'"],
  ["escaped attribute", "'&lt;Password Type=&quot;x&quot;&gt;' + p + '&lt;/Password&gt;'"],
  ["token element", "'<token>' + p + '</token>'"],
  [".NET setting", "'<setting name=\"Password\" serializeAs=\"String\">\\n  <value>' + p + '</value>\\n</setting>'"],
];

test("P1 the element form withholds a random 12-character password from the 94 printable characters: 1,000 of each of ten forms, printed whole at most twice in a thousand (a value that begins with a tag), in all three copies", () => {
  for (const path of COPIES) {
    const r = py(path, [
      "pr = [chr(c) for c in range(33, 127)]",
      "rnd = random.Random(808)",
      `forms = [lambda p: ${ELEMENT_FORMS.map(([, f]) => f).join(", lambda p: ")}]`,
      "whole = []",
      "for f in forms:",
      "    n = 0",
      "    for _ in range(1000):",
      "        p = ''.join(rnd.choice(pr) for _ in range(12))",
      "        if p in m.shown_path(m.cell(f(p))):",
      "            n += 1",
      "    whole.append(n)",
      "print(json.dumps(whole))",
    ].join("\n"));
    assert.equal(r.status, 0, `${path}: ${r.stderr}`);
    (JSON.parse(r.stdout) as number[]).forEach((n, i) => assert.ok(n <= 2, `${path}: ${ELEMENT_FORMS[i]![0]} printed ${n} of 1000 whole`));
  }
});

test("P1 the shapes the review built: a `>` in the password, no closing tag, a 720-character value, a value that begins with `<` that is no tag, attributes, a setting, `pass_word`", () => {
  for (const path of COPIES) {
    const r = py(path, [
      "cases = [('<Password>ab>cdefgh</Password>', 'ab>cdefgh'), ('<Password>Zq7!kP2#xw9R', 'Zq7!kP2#xw9R'), ('&lt;Password&gt;ab&gt;cd&lt;/Password&gt;', 'ab&gt;cd'),",
      "         ('&lt;Password&gt;Zq7!kP2#xw9R', 'Zq7!kP2#xw9R'), ('<Password>*<8r<$Epb]pD', '*<8r<$Epb]pD'), ('<Password><8r$Epb]pD</Password>', '<8r$Epb]pD'),",
      "         ('&lt;Password&gt;&lt;8r$Epb]pD&lt;/Password&gt;', '&lt;8r$Epb]pD'),",
      "         ('<Password Type=\"x\">Zq7!kP2#xw9R</Password>', 'Zq7!kP2#xw9R'), ('&lt;Password Type=&quot;x&quot;&gt;Zq7kP2xw9R&lt;/Password&gt;', 'Zq7kP2xw9R'),",
      "         ('<setting name=\"Password\" serializeAs=\"String\">\\n  <value>Zq7!kP2#>w9R</value>', 'Zq7!kP2#>w9R'),",
      "         ('pass_word=Zq7kP2xw9R;', 'Zq7kP2xw9R'), ('Pass-Word: Zq7kP2xw9R', 'Zq7kP2xw9R'), ('pass_phrase=Zq7kP2xw9R', 'Zq7kP2xw9R'),",
      "         ('<Password> padded Zq7kP2xw9R </Password>', 'padded Zq7kP2xw9R')]",
      "long = ''.join(random.Random(5).choice([chr(c) for c in range(33, 60)] + ['>', '#']) for _ in range(720))",
      "cases.append(('<Password>' + long + '</Password>', long))",
      "cases.append(('<Password>' + long, long))",
      "bad = [c[0][:40] for c in cases if c[1] in m.shown_path(c[0]) or c[1] in m.shown_path(m.cell(c[0]))]",
      "print(json.dumps(bad))",
    ].join("\n"));
    assert.equal(r.status, 0, `${path}: ${r.stderr}`);
    assert.deepEqual(JSON.parse(r.stdout), [], path);
  }
});

test("P1 placeholders are kept where they are the whole text of the element and followed by its end (a mask, ${NAME}, %NAME%, a format), and not when more text follows", () => {
  for (const path of COPIES) {
    const r = py(path, [
      "kept = ['<Password>****</Password>', '<token>${TOKEN}</token>', '<token>%TOKEN%</token>', '<Password>%s</Password>', 'Password=****;', 'Password=${DB_PASS};',",
      "        '<token>${TOKEN}', '&lt;Password&gt;****&lt;/Password&gt;']",
      "gone = ['<Password>****Zq7kP2xw9R</Password>', '<Password>*<8r<$Epb]pD', '<token>${TOKEN}zz9Q</token>', 'Password=****Zq7;']",
      "print(json.dumps({'kept': [m.shown_path(t) == t for t in kept], 'gone': [m.shown_path(t) != t for t in gone]}))",
    ].join("\n"));
    assert.equal(r.status, 0, `${path}: ${r.stderr}`);
    const a = JSON.parse(r.stdout) as { kept: boolean[]; gone: boolean[] };
    assert.deepEqual(a.kept, a.kept.map(() => true), `${path} kept`);
    assert.deepEqual(a.gone, [true, true, true, true], `${path} gone`);
  }
});

test("P1 text that merely looks like the element form is kept: prose with a tag-like name, a self-closed tag, an element of another name", () => {
  for (const path of COPIES) {
    const r = py(path, [
      "kept = ['a <secret key> thing', '<Password/>rest of the line', '<Password />rest', '<Password Type=\"x\"/>rest', '<Name>Example</Name>', 'the <secret> is shown']",
      "print(json.dumps([m.shown_path(t) == t for t in kept]))",
    ].join("\n"));
    assert.equal(r.status, 0, `${path}: ${r.stderr}`);
    const kept = JSON.parse(r.stdout) as boolean[];
    // 'the <secret> is shown': the text after the name begins with a space and nothing closes it, so it is no value
    assert.deepEqual(kept, [true, true, true, true, true, true], path);
  }
});

test("P1 the element rule takes time linear in the text: 128 KB and 512 KB of each hostile shape (runs of `>`, `<`, `&lt;`, open tags, attributes, settings, tokens that make a second pass), the larger at most 8 times the smaller (never taken as less than 0.05 s; best CPU time of up to three rounds: linear code takes 4 times, a quadratic rule 16), and none over 5 s", () => {
  for (const path of COPIES) {
    const r = py(path, [
      GROWTH_PY,
      "tok = 'AKIA' + 'A2B3C4D5E6F7G8H9'",
      "units = ['<Password>', '<Password>>', '<Password>' + '>' * 50, '<Password>' + '<' * 50, '<Password>' + 'a>' * 600, '<Password>' + '&' * 100, '<Password>&lt;',",
      "         '<Password> ' + '&' * 600, '<Password>' + ' ' * 600, '&lt;Password&gt;' + '&gt;' * 50, '<Password><' + 'a' * 300, '<Password><abc ' + 'a=\"b\" ' * 60,",
      "         '<Password ', '<Password a=b', '<Password' + ' a=\"b\"' * 60, '<Password' + ' a=b' * 60, '<Password' + ' a=\"b\"' * 60 + ' c', '<Password a=\"' + 'b' * 200,",
      "         '&lt;Password a=&quot;' + 'b' * 200, '<Password' + ' ' * 600, '<Password a' + '=' * 200, '<setting name=\"Password\" ', '<setting name=\"Password\">' + ' ' * 300,",
      "         '<setting name=\"Password\">' + '\\\\n ' * 200, '<setting name=\"Password\"' + ' a=\"b\"' * 60, '<setting name=', '<Password><token><secret><pwd><pass_word>',",
      "         '<Password>' + tok + ' ', '<Password>' + tok + '/' + tok + ' ', '<Password>{\\\\\"password\\\\\": \\\\\"x', '{\\\\\"password\\\\\": \\\\\"<Password>x', '&lt;Password&gt;&lt;Password&gt;x',",
      "         '<>&lt;&gt;', 'pass_word=\\\\\"x', 'pass_word' * 50]",
      "rows = []",
      "for u in units:",
      "    texts = [(u * ((1 << k) // len(u) + 1))[:1 << k] for k in (17, 19)]",
      "    rows.append([u[:24]] + growth(m.shown_path, texts))",
      "print(json.dumps(rows))",
    ].join("\n"), [], undefined, 900_000);
    assert.equal(r.status, 0, `${path}: ${r.stderr}`);
    for (const [unit, small, large] of JSON.parse(r.stdout) as [string, number, number][]) {
      assert.ok(large <= LINEAR_ABSOLUTE, `${path}: ${unit} took ${large.toFixed(2)} s for 512 KB`);
      assert.ok(linearOk(small, large), `${path}: ${unit} took ${small.toFixed(2)} s for 128 KB and ${large.toFixed(2)} s for 512 KB`);
    }
  }
});

// ---- P2: the answer's own time ----------------------------------------------------------------------------------------------------------

// A fake clock: time.monotonic is a counter; every sanitising of a string that is not already known clean moves it by 0.0004 s a character
// (the real cost is about 6 microseconds a character on a string that holds a user-info; this scales it up so that a small file runs
// out of time). The call is run through main(), and the fake time at its end is printed after the answer.
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

function fakeFinish(r: Ran): { answer: { status: string; limits_hit: string[]; tables?: Record<string, { rows: unknown[] }> } & Record<string, any>; elapsed: number } {
  const lines = r.stdout.trim().split("\n");
  const elapsed = Number(lines.pop()!.replace("FAKE ", ""));
  return { answer: JSON.parse(lines.join("\n")), elapsed };
}

test("P2 a package whose names cost more than the clock allows ends inside the manifest's limit on a slowed clock: 40 members with names of 1,900 characters of `a:b@` at max_seconds 90, whole JSON, partial, ended well inside the 105 s of the hard limit", async () => {
  await withCwd(async (cwd) => {
    const types = Buffer.from('<?xml version="1.0"?><Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types"></Types>');
    const entries = [{ name: "[Content_Types].xml", data: types }, ...Array.from({ length: 40 }, (_, i) => ({ name: `word/${"a:b@".repeat(475)}${i}.xml`, data: Buffer.from("<x/>") }))];
    const file = await put(cwd, "work/names.docx", buildZip(entries));
    const r = py(DOC_STRUCTURE, [
      SLOW_CLOCK,
      "sys.stdin = io.StringIO(json.dumps({'path': sys.argv[2], 'max_seconds': 90}))",
      "m.main()",
      "print('FAKE %.1f' % (now[0] - m.START))",
    ].join("\n"), [file], cwd, 300_000);
    assert.equal(r.status, 0, r.stderr);
    const { answer, elapsed } = fakeFinish(r);
    assert.ok(elapsed <= 105, `the call ended ${elapsed} s after it began, over the hard limit of 105 s`);
    assert.ok(["partial", "complete"].includes(answer.status), answer.status);
    assert.ok(Object.keys(answer.tables ?? {}).length > 0 || answer.parts !== undefined || answer.limits_hit.length > 0, "an answer with what was read");
  });
});

test("P2 the answer has a time of its own: past it a long string not already clean is given by its length, the answer says so, and what was withheld before it stays", async () => {
  for (const path of [DOC_STRUCTURE, PE_DIRECTORIES]) {
    const r = py(path, [
      "now = [1000.0]",
      "time.monotonic = lambda: now[0]",
      "m.START = now[0]",
      "original = m.shown_path",
      "def slow(text):",
      "    if isinstance(text, str) and len(text) > 200:",
      "        now[0] += 400",
      "    return original(text)",
      "m.shown_path = slow",
      "raw = lambda c: c * 150 + ' a:b@host ' + c * 150",
      "result = {'tool': 'x', 'status': 'complete', 'rows': [{'name': 'word/document.xml', 'first': raw('x'), 'second': raw('y'), 'third': raw('z')}], 'limits_hit': []}",
      "answer = m.build_answer(result, None)",
      "print(json.dumps(answer))",
    ].join("\n"));
    assert.equal(r.status, 0, `${path}: ${r.stderr}`);
    const a = JSON.parse(r.stdout) as { status: string; rows: { name: string; first: string; second: string; third: string }[]; limits_hit: string[] };
    assert.equal(a.rows[0]!.name, "word/document.xml");
    assert.match(a.rows[0]!.first, /userinfo withheld/, "the string read before the time ran out is withheld by the rule");
    assert.match(a.rows[0]!.second, /^<310 characters: not shown, the answer ran out of time>$/);
    assert.match(a.rows[0]!.third, /^<310 characters: not shown, the answer ran out of time>$/);
    assert.equal(a.status, "partial");
    assert.ok(a.limits_hit.some((l) => /the answer ran out of time/.test(l)), JSON.stringify(a.limits_hit));
  }
});

test("P2 rows are withheld when they are added: the string of a table row is sanitised once, in the reading's time, and the answer reads the settled result from the cache", async () => {
  for (const path of [DOC_STRUCTURE, PE_DIRECTORIES]) {
    const r = py(path, [
      "calls = []",
      "original = m.shown_path",
      "def counting(text):",
      "    if isinstance(text, str) and len(text) > 1000:",
      "        calls.append(text in m._CLEAN)",
      "    return original(text)",
      "m.shown_path = counting",
      "page = m.LosslessPage('t', ['k'], 10)",
      "row = {'name': 'a:b@' * 1000 + 'x', 'n': 1}",
      "page.add(row)",
      "kept = page.page[0]['name']",
      "answer = m.build_answer({'status': 'complete', 'tables': {'t': {'rows': page.page}}}, None)",
      "print(json.dumps({'kept_differs': kept != row['name'], 'calls': calls, 'answer_has_it': answer['tables']['t']['rows'][0]['name'] == kept}))",
    ].join("\n"));
    assert.equal(r.status, 0, `${path}: ${r.stderr}`);
    const a = JSON.parse(r.stdout) as { kept_differs: boolean; calls: boolean[]; answer_has_it: boolean };
    assert.equal(a.kept_differs, true, "the kept row is the withheld one");
    assert.equal(a.answer_has_it, true);
    // the first reading of the long raw string is not cached; every later reading of the withheld one (the answer's and the backstop's) is
    assert.equal(a.calls[0], false);
    assert.ok(a.calls.slice(1).every((x) => x === true), JSON.stringify(a.calls));
  }
});

test("P2 the part-name check of a ZIP reads the clock: 60 members and a clock that moves a second at each sanitising of a name end the check after a handful, name them withheld by length, say so, and the answer is partial JSON", async () => {
  await withCwd(async (cwd) => {
    const entries = Array.from({ length: 60 }, (_, i) => ({ name: `word/part${i}.xml`, data: Buffer.from("<x/>") }));
    entries.unshift({ name: "[Content_Types].xml", data: Buffer.from('<?xml version="1.0"?><Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types"></Types>') });
    const file = await put(cwd, "work/many.docx", buildZip(entries));
    const r = py(DOC_STRUCTURE, [
      "now = [1000.0]",
      "time.monotonic = lambda: now[0]",
      "m.START = now[0]",
      "calls = [0]",
      "inner = m.shown_name",
      "def slow(text):",
      "    calls[0] += 1",
      "    now[0] += 1.0",
      "    return inner(text)",
      "m.shown_name = slow",
      "sys.stdin = io.StringIO(json.dumps({'path': sys.argv[2], 'max_seconds': 5}))",
      "m.main()",
      "print('CALLS %d' % calls[0])",
    ].join("\n"), [file], cwd);
    assert.equal(r.status, 0, r.stderr);
    const lines = r.stdout.trim().split("\n");
    const calls = Number(lines.pop()!.replace("CALLS ", ""));
    const a = JSON.parse(lines.join("\n")) as { status: string; limits_hit: string[] };
    assert.ok(calls <= 12, `${calls} names were checked at a second each with a clock of 5 s`);
    assert.equal(a.status, "partial");
    assert.ok(a.limits_hit.some((l) => /the check of the part names stopped at max_seconds \(5\)/.test(l)), JSON.stringify(a.limits_hit));
  });
});

test("P2 `limit` is at most 20,000: a larger one is refused as JSON by both tools, 20,000 is accepted", async () => {
  await withCwd(async (cwd) => {
    const pe = await put(cwd, "work/small.dll", buildPeDirs({ debug: [{ type: 2, stamp: 1, guid: Buffer.alloc(16, 7), age: 1, pdb: "C:\\a.pdb" }] }).file);
    const rtf = await put(cwd, "work/small.rtf", "{\\rtf1\\ansi hello}");
    for (const [script, file] of [[PE_DIRECTORIES, pe], [DOC_STRUCTURE, rtf]] as const) {
      const over = await tool(script, cwd, { path: file, limit: 20001 });
      const a = refused(over);
      assert.equal(a.status, "failed");
      assert.match(a.error, /limit must be an integer from 1 to 20000/);
      const accepted = await tool(script, cwd, { path: file, limit: 20000 });
      assert.equal(accepted.code, 0, accepted.stderr);
    }
  });
});

test("P2 the hard limit answers with what is assembled: a first answer step that never ends, a hard limit of one second, and the call ends with one partial JSON answer (problems, limits, the first rows of each table), exit 0, before the harness's kill", async () => {
  await withCwd(async (cwd) => {
    const pe = await put(cwd, "work/small.dll", buildPeDirs({ exports: { functions: [{ name: "Alpha", rva: 0x1000 }, { name: "Beta", rva: 0x1000 }] } }).file);
    const rtf = await put(cwd, "work/small.rtf", "{\\rtf1\\ansi {\\field{\\*\\fldinst HYPERLINK \"http://example.com/a\"}{\\fldrslt x}}}");
    for (const [path, file] of [[PE_DIRECTORIES, pe], [DOC_STRUCTURE, rtf]] as const) {
      const r = py(path, [
        "m.HARD_SECONDS = 1",
        "first = [True]",
        "inner = m.final_check",
        "def stuck(*a, **k):",
        "    if first[0] and isinstance(a[0], dict) and 'status' in a[0]:",
        "        first[0] = False",
        "        time.sleep(30)",
        "    return inner(*a, **k)",
        "m.final_check = stuck",
        "sys.stdin = io.StringIO(json.dumps({'path': sys.argv[2]}))",
        "m.main()",
      ].join("\n"), [file], cwd, 60_000);
      assert.equal(r.status, 0, `${path}: ${r.stderr}`);
      assert.ok(r.seconds < 15, `${path}: took ${r.seconds} s`);
      assert.doesNotMatch(r.stderr, /Traceback/);
      assert.equal(r.stdout.trim().split("\n").length, 1, "one answer");
      const a = JSON.parse(r.stdout) as { status: string; limits_hit: string[]; tables: Record<string, { matched: number; rows: unknown[] }>; path: string };
      assert.equal(a.status, "partial");
      assert.ok(a.limits_hit.some((l) => /had not answered within 1 seconds \(the manifest's limit is 120\)/.test(l)), JSON.stringify(a.limits_hit));
      assert.ok(a.path.length > 0);
      if (path === PE_DIRECTORIES) assert.equal(a.tables.exports!.rows.length, 2);
    }
  });
});

test("P2 when the partial answer of the hard limit is not finished either, the failed one ends the call after the grace: every answer step stuck, a hard limit of one second", async () => {
  await withCwd(async (cwd) => {
    const pe = await put(cwd, "work/small.dll", buildPeDirs({ debug: [{ type: 2, stamp: 1, guid: Buffer.alloc(16, 7), age: 1, pdb: "C:\\a.pdb" }] }).file);
    const r = py(PE_DIRECTORIES, [
      "m.HARD_SECONDS = 1",
      "m.HARD_GRACE = 2",
      "inner = m.shown_answer",
      "def stuck(*a, **k):",
      "    time.sleep(30)",
      "    return inner(*a, **k)",
      "m.shown_answer = stuck",
      "sys.stdin = io.StringIO(json.dumps({'path': sys.argv[2]}))",
      "m.main()",
    ].join("\n"), [pe], cwd, 60_000);
    assert.equal(r.status, 1, r.stderr);
    assert.ok(r.seconds < 15, `took ${r.seconds} s`);
    const a = JSON.parse(r.stdout) as { status: string; error: string };
    assert.equal(a.status, "failed");
    assert.match(a.error, /was not finished within 1 seconds \(the manifest's limit is 120\)/);
  });
});

test("P2 the constants leave the answer its time: the largest reading clock plus the least answer time is under the answer's end, which is 15 s under the hard limit, which is 10 s under the manifest's limit; the manifest says what the answer's time is", async () => {
  for (const name of ["doc_structure", "pe_directories"] as const) {
    const path = name === "doc_structure" ? DOC_STRUCTURE : PE_DIRECTORIES;
    const manifest = JSON.parse(await (await import("node:fs/promises")).readFile(join(RE, "tools", name, "manifest.json"), "utf8")) as { timeout_seconds: number; params: { max_seconds: { description: string }; limit: { description: string } } };
    const r = py(path, "print(json.dumps({'x': m.MAX_SECONDS, 'd': m.DEFAULT_SECONDS, 'by': m.ANSWER_BY, 'min': m.ANSWER_MIN, 'h': m.HARD_SECONDS, 'g': m.HARD_GRACE, 'l': m.MAX_LIMIT}))");
    assert.equal(r.status, 0, r.stderr);
    const c = JSON.parse(r.stdout) as { x: number; d: number; by: number; min: number; h: number; g: number; l: number };
    assert.ok(c.x <= c.by && c.by + 15 <= c.h, `${name}: the largest clock ${c.x} s, the answer's end ${c.by} s, the hard limit ${c.h} s`);
    assert.ok(c.x + c.min + 6 <= c.h, `${name}: the latest reading, the least answer time and 6 s for writing are over the hard limit`);
    assert.ok(c.d < c.by, `${name}: the default clock ${c.d} s leaves the answer until ${c.by} s`);
    assert.ok(c.h + c.g + 5 <= manifest.timeout_seconds, `${name}: the hard limit and its grace are within 5 s of the manifest's ${manifest.timeout_seconds} s`);
    assert.equal(c.l, 20000);
    assert.ok(manifest.params.limit.description.includes("at most 20000"), manifest.params.limit.description);
    assert.ok(manifest.params.max_seconds.description.includes("about 90 s after the call began"), manifest.params.max_seconds.description);
  }
});
