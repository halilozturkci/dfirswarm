/**
 * doc_structure, pe_directories and the capa-floss recipe, the seventh review: the debug directory read no clock, the answer was built
 * after the clock with nothing to hold it inside the manifest's limit, a secret-named key written with an escaped quote, an entity, a
 * tab as written, an attribute pair or an element, and the signals the two tools did not handle. Every input is generated here from
 * the format's rules or from random draws with a fixed seed, never from a tool's output; each test fails on the code before.
 */
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { readFile } from "node:fs/promises";
import { join } from "node:path";
import { test } from "node:test";
import { DOC_STRUCTURE, PE_DIRECTORIES, RE, TOOLS, put, withCwd } from "./pack-re-harness.ts";
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

/** Python code run with the tool's module loaded as `m` and the extra arguments after the module path in sys.argv; stdin is not used by the code. */
function py(path: string, code: string, argv: string[] = [], cwd?: string, timeout = 120_000): Ran {
  const started = Date.now();
  const r = spawnSync("python3", ["-I", "-c", `${LOAD}\n${code}`, path, ...argv], { encoding: "utf8", cwd, env: { ...process.env, AGENT_ID: "s1" }, maxBuffer: 1 << 28, timeout });
  return { status: r.status, stdout: r.stdout, stderr: r.stderr, seconds: (Date.now() - started) / 1000 };
}

// ---- P1: the debug directory reads the clock ----------------------------------------------------------------------------------------

test("P1 the debug directory stops at the deadline: a clock that moves a quarter of a second at each reading ends 300 entries after a handful, with the time limit named", async () => {
  await withCwd(async (cwd) => {
    const pe = buildPeDirs({ debug: Array.from({ length: 300 }, (_, i) => ({ type: 2, stamp: i, guid: Buffer.alloc(16, 7), age: 1, pdb: `C:\\build\\obj${i}.pdb` })) });
    const file = await put(cwd, "work/many-debug.dll", pe.file);
    const r = py(PE_DIRECTORIES, [
      "tick = [0.0]",
      "def clock():",
      "    tick[0] += 0.25",
      "    return tick[0]",
      "time.monotonic = clock",
      "sys.stdin = io.StringIO(json.dumps({'path': sys.argv[2], 'max_seconds': 1}))",
      "m.main()",
    ].join("\n"), [file], cwd);
    assert.equal(r.status, 0, r.stderr);
    const a = JSON.parse(r.stdout);
    const entries = a.debug.entries as unknown[];
    assert.ok(entries.length >= 1 && entries.length <= 6, `${entries.length} entries were read`);
    assert.ok((a.limits_hit as string[]).some((l) => /time: the debug directory stopped at max_seconds \(1\)/.test(l)), JSON.stringify(a.limits_hit));
    assert.equal(a.status, "partial");
  });
});

test("P1 the same file at the real clock reads every entry: the check costs nothing when time is left", async () => {
  await withCwd(async (cwd) => {
    const pe = buildPeDirs({ debug: Array.from({ length: 300 }, (_, i) => ({ type: 2, stamp: i, guid: Buffer.alloc(16, 7), age: 1, pdb: `C:\\build\\obj${i}.pdb` })) });
    const file = await put(cwd, "work/many-debug.dll", pe.file);
    const r = py(PE_DIRECTORIES, [
      "sys.stdin = io.StringIO(json.dumps({'path': sys.argv[2]}))",
      "m.main()",
    ].join("\n"), [file], cwd);
    assert.equal(r.status, 0, r.stderr);
    const a = JSON.parse(r.stdout);
    assert.equal((a.debug.entries as unknown[]).length, 300);
    assert.equal(a.status, "complete");
  });
});

// ---- P1: the answer is built after the clock; nothing may take the call past the manifest's limit --------------------------------------

test("P1 the constants leave the answer its time: the hard limit sits under the manifest's limit and over the largest reading clock, and the manifest names the clock (what the answer's time is, and what it is worth, is held by tests/pack-re-delta8.test.ts on a slowed clock)", async () => {
  for (const [name, path] of [["doc_structure", DOC_STRUCTURE], ["pe_directories", PE_DIRECTORIES]] as const) {
    const manifest = JSON.parse(await readFile(join(TOOLS, name, "manifest.json"), "utf8")) as { timeout_seconds: number; params: { max_seconds: { description: string } } };
    const r = py(path, "print(json.dumps({'d': m.DEFAULT_SECONDS, 'x': m.MAX_SECONDS, 'h': m.HARD_SECONDS}))");
    assert.equal(r.status, 0, r.stderr);
    const c = JSON.parse(r.stdout) as { d: number; x: number; h: number };
    const limit = manifest.timeout_seconds;
    assert.ok(c.x + 15 <= c.h, `${name}: the largest clock ${c.x} s leaves under 15 s before the hard limit ${c.h} s`);
    assert.ok(c.h + 10 <= limit, `${name}: the hard limit ${c.h} s is not 10 s under ${limit} s`);
    const text = manifest.params.max_seconds.description;
    assert.ok(text.includes(`from 1 to ${c.x} (default ${c.d})`), `${name}: the manifest says: ${text}`);
  }
});

test("P1 an answer that is still being built at the hard limit, and a partial answer that is not finished either, end the call with one failed JSON answer and exit 1, before the harness's kill (every answer step slowed, a hard limit of one second, a grace of two)", async () => {
  await withCwd(async (cwd) => {
    const pe = await put(cwd, "work/small.dll", buildPeDirs({ debug: [{ type: 2, stamp: 1, guid: Buffer.alloc(16, 7), age: 1, pdb: "C:\\a.pdb" }] }).file);
    const rtf = await put(cwd, "work/small.rtf", "{\\rtf1\\ansi hello}");
    for (const [path, file] of [[PE_DIRECTORIES, pe], [DOC_STRUCTURE, rtf]] as const) {
      const r = py(path, [
        "m.HARD_SECONDS = 1",
        "m.HARD_GRACE = 2",
        "inner = m.shown_answer",
        "def slow(*a, **k):",
        "    time.sleep(30)",
        "    return inner(*a, **k)",
        "m.shown_answer = slow",
        "sys.stdin = io.StringIO(json.dumps({'path': sys.argv[2]}))",
        "m.main()",
      ].join("\n"), [file], cwd, 60_000);
      assert.equal(r.status, 1, `${path}: ${r.stderr}`);
      assert.ok(r.seconds < 15, `${path}: took ${r.seconds} s`);
      assert.doesNotMatch(r.stderr, /Traceback/);
      const a = JSON.parse(r.stdout);
      assert.equal(a.status, "failed");
      assert.match(a.error, /was not finished within 1 seconds \(the manifest's limit is 120\)/);
      assert.equal(r.stdout.trim().split("\n").length, 1, "one answer");
    }
  });
});

test("P1 an answer already being written at the hard limit is not written twice", () => {
  for (const path of [DOC_STRUCTURE, PE_DIRECTORIES]) {
    const r = py(path, [
      "m.PRINTING[0] = True",
      "m._hard_limit(signal.SIGALRM, None)",
      "print('still running')",
    ].join("\n"));
    assert.equal(r.status, 0, r.stderr);
    assert.equal(r.stdout.trim(), "still running");
  }
});

// ---- P3-4: signals --------------------------------------------------------------------------------------------------------------------

test("P3-4 SIGINT, SIGTERM and SIGHUP end doc_structure and pe_directories with one JSON answer and the exit code 128 + the signal, not a traceback and not silence", () => {
  for (const path of [DOC_STRUCTURE, PE_DIRECTORIES]) {
    for (const [name, code] of [["SIGINT", 130], ["SIGTERM", 143], ["SIGHUP", 129]] as const) {
      const r = py(path, [
        "m.install_signal_handlers()",
        "signal.setitimer(signal.ITIMER_REAL, 0)",
        `os.kill(os.getpid(), signal.${name})`,
        "time.sleep(20)",
        "print('not reached')",
      ].join("\n"), [], undefined, 60_000);
      assert.equal(r.status, code, `${path} ${name}: ${r.stderr}`);
      assert.doesNotMatch(r.stderr, /Traceback/);
      const a = JSON.parse(r.stdout);
      assert.equal(a.status, "failed");
      assert.match(a.error, new RegExp(`stopped by signal ${code - 128}\\b`));
    }
  }
});

test("P3-4 a signal after the answer began to be written adds nothing to it", () => {
  for (const path of [DOC_STRUCTURE, PE_DIRECTORIES]) {
    const r = py(path, [
      "m.install_signal_handlers()",
      "m.PRINTING[0] = True",
      "os.kill(os.getpid(), signal.SIGTERM)",
      "time.sleep(20)",
    ].join("\n"), [], undefined, 60_000);
    assert.equal(r.status, 143);
    assert.equal(r.stdout, "");
  }
});

// ---- P2-2: a secret-named key, written with an escaped quote, an entity, a tab as written, an attribute pair or an element ------------

const FORMS = [
  "'{\\\\\"password\\\\\": \\\\\"%s\\\\\"}' % p",                       // JSON inside a JSON string: {\"password\": \"...\"}
  "'&quot;password&quot;: &quot;%s&quot;' % p",
  "'&#34;Password&#34;: &#34;%s&#34;' % p",
  "'<add key=\"Password\" value=\"%s\"/>' % p",
  "'<add key=\\\\\"Password\\\\\" value=\\\\\"%s\\\\\"/>' % p",
  "'<Password>%s</Password>' % p",
  "'&lt;Password&gt;%s&lt;/Password&gt;' % p",
  "'Password\\t=\\t%s' % p",
  "'Password\\\\x09=\\\\x09%s' % p",
  "'Pwd = \\t%s;' % p",
];

test("P2-2 the escaped forms of a secret-named key withhold a random 12-character password: 300 of each of ten forms with an alphanumeric password, printed whole 0 times (passwords from all 94 printable characters: tests/pack-re-delta8.test.ts), in all three copies, both as the text is and as a cell prints it", () => {
  for (const path of COPIES) {
    const r = py(path, [
      "alnum = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789'",
      "rnd = random.Random(61)",
      `forms = [lambda p: ${FORMS.join(", lambda p: ")}]`,
      "whole = []",
      "for f in forms:",
      "    n = 0",
      "    for _ in range(300):",
      "        p = ''.join(rnd.choice(alnum) for _ in range(12))",
      "        text = f(p)",
      "        for shown in (m.shown_path(text), m.shown_path(m.cell(text))):",
      "            if p in shown:",
      "                n += 1",
      "    whole.append(n)",
      "print(json.dumps(whole))",
    ].join("\n"));
    assert.equal(r.status, 0, `${path}: ${r.stderr}`);
    assert.deepEqual(JSON.parse(r.stdout), FORMS.map(() => 0), path);
  }
});

test("P2-2 text that merely looks like these forms is kept: a key with no value, an element of another name, a format, a name inside a word", () => {
  for (const path of COPIES) {
    const r = py(path, [
      "kept = ['<Password></Password>', '<add key=\"Timeout\" value=\"30\"/>', '<Name>Example</Name>', 'Password=%s;', '<Password>%d</Password>',",
      "        '&quot;bypass&quot;: &quot;allowed&quot;', 'the password policy', '<add key=\"Password\"/>']",
      "print(json.dumps([m.shown_path(t) == t for t in kept]))",
    ].join("\n"));
    assert.equal(r.status, 0, `${path}: ${r.stderr}`);
    assert.deepEqual(JSON.parse(r.stdout), [true, true, true, true, true, true, true, true], path);
  }
});

test("P2-2 the cheap pre-test of the secret-named key rule holds every name the rule has, and the rule finds nothing in a text the pre-test passes over (2,000 random strings, in every copy)", () => {
  for (const path of COPIES) {
    const r = py(path, [
      "names = ['password', 'passwd', 'passphrase', 'pwd', 'pswd', 'psw', 'secret_key', 'private-key', 'secret', 'client_secret', 'token', 'api_key', 'access-key',",
      "         'account_key', 'shared_access_key', 'credential', 'credentials', 'pw', 'pass', 'auth', 'sig']",
      "missing = [n for n in names if not m.KEYVALUE_HINT.search(n)]",
      "rnd = random.Random(88)",
      `atoms = ['=', ':', ' ', '\\t', '"', "'", '&quot;', '\\\\"', 'value', 'x', 'abc', '12', ';', '/', '@', '<', '>', 'word', 'a_b']`,
      "bad = 0",
      "for _ in range(2000):",
      "    t = ''.join(rnd.choice(atoms) for _ in range(rnd.randrange(1, 40)))",
      "    if not m.KEYVALUE_HINT.search(t) and m.KEYVALUE_SECRET.search(t):",
      "        bad += 1",
      "print(json.dumps({'missing': missing, 'bad': bad}))",
    ].join("\n"));
    assert.equal(r.status, 0, `${path}: ${r.stderr}`);
    assert.deepEqual(JSON.parse(r.stdout), { missing: [], bad: 0 }, path);
  }
});

test("P2-2 the secret-named key rule and the element rule take time linear in the text: 128 KB and 512 KB of each hostile shape, the larger at most 8 times the smaller (never taken as less than 0.05 s; best CPU time of up to three rounds), and none over 5 s", () => {
  for (const path of COPIES) {
    const r = py(path, [
      GROWTH_PY,
      "units = ['password=', 'password=\"', 'password=\\\\\"', 'password=&quot;', 'password=&quot;a', 'password=&quot;' + 'a' * 600, 'password=\"' + 'a' * 600,",
      "         '\"token\": \"', '<add key=\"password\" value=', '<add key=\\\\\"password\\\\\" value=\\\\\"', '<password>', '<password>a', '&lt;password&gt;a&lt;',",
      "         '<password>' + 'a' * 600, 'password' + '\\\\t' * 50 + '=', 'password\\\\x09', 'password' + ' ' * 64, '&#' + '0' * 40, '\\\\\\\\\\\\\\\\\\\\\"', 'password=&quot;password=&quot;password=']",
      "rows = []",
      "def both(s):",
      "    m.KEYVALUE_SECRET.sub(lambda x: 'x', s)",
      "    m.ELEMENT_SECRET.sub(lambda x: 'x', s)",
      "for u in units:",
      "    texts = [(u * ((1 << k) // len(u) + 1))[:1 << k] for k in (17, 19)]",
      "    rows.append([u[:24]] + growth(both, texts))",
      "print(json.dumps(rows))",
    ].join("\n"), [], undefined, 600_000);
    assert.equal(r.status, 0, `${path}: ${r.stderr}`);
    for (const [unit, small, large] of JSON.parse(r.stdout) as [string, number, number][]) {
      assert.ok(large <= LINEAR_ABSOLUTE, `${path}: ${unit} took ${large.toFixed(2)} s for 512 KB`);
      assert.ok(linearOk(small, large), `${path}: ${unit} took ${small.toFixed(2)} s for 128 KB and ${large.toFixed(2)} s for 512 KB`);
    }
  }
});
