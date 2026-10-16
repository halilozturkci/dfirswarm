/**
 * doc_structure, pe_directories and the capa-floss recipe, the fifth review: a `mailto:` rule whose cost grew with the square of the
 * text and was handed strings of any length, a clock read once in 4,096 names, values of a secret-named key that hold a delimiter or
 * an unterminated quote, user-info whose password holds `/`, `?` or `#`, an unreadable member the answer did not mention, characters
 * that print as nothing, and the small things of the recipe. Every input is generated here from the format's rules (ECMA-376-2,
 * ISO 32000-1, PE/COFF) or from random draws with a fixed seed, never from a tool's output; each test fails on the code before.
 */
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { chmod, readFile, stat } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "node:test";
import { DOC_STRUCTURE, PE_DIRECTORIES, RE, body, buildZip, put, rels, tool, withCwd } from "./pack-re-harness.ts";
import type { Json } from "./pack-re-harness.ts";
import { buildPdf, buildPeDirs, buildVbaProject } from "./pack-re-doc-fixtures.ts";
import { prng } from "./pack-re-canary-shapes.ts";

const CAPA_FLOSS = join(RE, "recipes", "capa-floss", "run.py");
const COPIES = [DOC_STRUCTURE, PE_DIRECTORIES, CAPA_FLOSS];

const LOAD = [
  "import importlib.util, io, json, os, sys, time",
  "sys.stdin = open(os.environ['RE_TEST_INPUT'], encoding='utf-8')",
  "spec = importlib.util.spec_from_file_location('tool_under_test', sys.argv[1])",
  "m = importlib.util.module_from_spec(spec)",
  "spec.loader.exec_module(m)",
].join("\n");

/**
 * Python code run with the tool's module loaded as `m`; stdin is the JSON of `input`, stdout is what the code prints. The input goes in
 * a file that the child opens as its stdin, never through a pipe: node's spawnSync with a large `input` has left the child blocked in
 * its stdin read while the parent idled (2 of 14 loops of the one-way-out file on macOS, Node 22.23.1).
 */
function py(path: string, code: string, input: unknown = null, timeout = 120_000): { status: number | null; stdout: string; stderr: string } {
  const dir = mkdtempSync(join(tmpdir(), "re-input-"));
  const file = join(dir, "input.json");
  writeFileSync(file, JSON.stringify(input));
  try {
    const r = spawnSync("python3", ["-I", "-c", `${LOAD}\n${code}`, path], { stdio: ["ignore", "pipe", "pipe"], encoding: "utf8", env: { ...process.env, AGENT_ID: "s1", RE_TEST_INPUT: file }, maxBuffer: 1 << 28, timeout });
    return { status: r.status, stdout: r.stdout, stderr: r.stderr };
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
}

const PRINTABLE = Array.from({ length: 94 }, (_, i) => String.fromCharCode(33 + i)).join("");
const ALNUM = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
const draw = (rnd: () => number, alphabet: string, n: number): string => Array.from({ length: n }, () => alphabet[Math.floor(rnd() * alphabet.length)]).join("");

// ---- P1-1: the mailto: rule ------------------------------------------------------------------------------------------------------

test("P1-1 shown_path on a million characters of `mailto:a:` takes CPU time linear in the text (under 1 s), in every copy; a password in a mailto: address is still withheld", () => {
  for (const path of COPIES) {
    const r = py(path, [
      "texts = ['mailto:a:' * 100000, 'mailto:a:' * 100000 + '@', ('mailto:' + 'a' * 50 + ':') * 20000]",
      "times = []",
      "for t in texts:",
      "    start = time.process_time()",
      "    m.shown_path(t)",
      "    times.append(time.process_time() - start)",
      "print(json.dumps({'times': times, 'kept': m.shown_path('mailto:bob@example.test'), 'cut': m.shown_path('mailto:bob:Secr3tPassw0rd@example.test'),",
      "                  'long': m.shown_path('mailto:bob:' + 'x' * 600 + '@example.test')[:30]}))",
    ].join("\n"), null, 60_000);
    assert.equal(r.status, 0, `${path}: ${r.stderr}`);
    const out = JSON.parse(r.stdout) as { times: number[]; kept: string; cut: string };
    // the third text ends in an `@`, so that every other rule of the sanitiser meets 900 KB of user-info shapes too: linear, not 1 s
    out.times.forEach((t, i) => assert.ok(t < [1.0, 4.0, 3.0][i]!, `${path}: text ${i} took ${t.toFixed(2)} s of CPU`));
    assert.equal(out.kept, "mailto:bob@example.test");
    assert.equal(out.cut, "mailto:bob:<userinfo withheld 14 characters>@example.test");
  }
});

const CT_NS = "http://schemas.openxmlformats.org/package/2006/content-types";

test("P1-1 a package whose [Content_Types].xml holds an Override with a 1 MB PartName ends within max_seconds + 2 s, the part given by its length", async () => {
  await withCwd(async (cwd) => {
    const part = "/" + "mailto:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa:".repeat(Math.ceil(1_000_000 / 58));
    const ct = `<?xml version="1.0"?><Types xmlns="${CT_NS}"><Default Extension="xml" ContentType="application/xml"/><Override PartName="${part}" ContentType="x/y"/></Types>`;
    await put(cwd, "work/big.docx", buildZip([
      { name: "[Content_Types].xml", data: Buffer.from(ct) },
      { name: "_rels/.rels", data: Buffer.from(rels([{ id: "rId1", type: "officeDocument", target: "word/document.xml" }])) },
      { name: "word/document.xml", data: Buffer.from("<w:document xmlns:w='http://schemas.openxmlformats.org/wordprocessingml/2006/main'/>") },
    ]));
    const started = Date.now();
    const r = await tool(DOC_STRUCTURE, cwd, { path: "work/big.docx", max_seconds: 10 });
    const seconds = (Date.now() - started) / 1000;
    const a = body(r);
    assert.ok(seconds < 12, `took ${seconds} s`);
    assert.ok(r.stdout.includes("longer than the 2048 shown"), "the part is given by its length");
    assert.ok(["complete", "partial"].includes(a.status), a.status);
  });
});

test("P1-1 a PDF whose name-tree key and embedded file's /F are 800,000 characters long ends within max_seconds + 2 s, each given by its length", async () => {
  await withCwd(async (cwd) => {
    const key = "mailto:a:".repeat(90_000);
    const objs = [
      { num: 1, body: "<< /Type /Catalog /Pages 2 0 R /Names << /EmbeddedFiles 4 0 R >> >>" },
      { num: 2, body: "<< /Type /Pages /Kids [ 3 0 R ] /Count 1 >>" },
      { num: 3, body: "<< /Type /Page /Parent 2 0 R >>" },
      { num: 4, body: `<< /Names [ (${key}) 5 0 R ] >>` },
      { num: 5, body: `<< /Type /Filespec /F (${key}) /EF << /F 6 0 R >> >>` },
      { num: 6, body: "<< /Type /EmbeddedFile >>", stream: Buffer.from("not executed") },
    ];
    await put(cwd, "work/long.pdf", buildPdf(objs, "/Root 1 0 R").file);
    const started = Date.now();
    const r = await tool(DOC_STRUCTURE, cwd, { path: "work/long.pdf", max_seconds: 10 });
    const seconds = (Date.now() - started) / 1000;
    const a = body(r);
    assert.ok(seconds < 12, `took ${seconds} s`);
    assert.ok(r.stdout.includes("longer than the 2048 shown"), "given by length");
    assert.ok(!r.stdout.includes("mailto:a:mailto"), "no part of the key is printed");
    assert.ok(["complete", "partial"].includes(a.status), a.status);
  });
});

// ---- P1-2: pe_directories reads the clock for every name -------------------------------------------------------------------------

test("P1-2 5,000 exports whose names are 2,000 characters of `a:b@` (a 10 MB file) at max_seconds 5: the answer is back within 7 s, bounded, and the names are given by their length", async () => {
  await withCwd(async (cwd) => {
    const name = "a:b@".repeat(500);
    const pe = buildPeDirs({ exports: { functions: Array.from({ length: 5000 }, (_, i) => ({ name: `${name}${String(i).padStart(4, "0")}`.slice(0, 2000), rva: 0x1000 })) } });
    await put(cwd, "work/hostile.dll", pe.file);
    const started = Date.now();
    const r = await tool(PE_DIRECTORIES, cwd, { path: "work/hostile.dll", max_seconds: 5 });
    const seconds = (Date.now() - started) / 1000;
    assert.ok(seconds < 7, `took ${seconds} s`);
    assert.ok(r.stdout.length < 2_000_000, `answer of ${r.stdout.length} bytes`);
    const a = body(r);
    const rows = a.tables.exports.rows as Json[];
    assert.ok(rows.length > 0 && rows.every((x) => /^<a name of 2000 characters: longer than the 512 shown, so not shown>$/.test(x.name)), JSON.stringify(rows[0]));
  });
});

test("P1-2 5,000 exports whose names are 500 characters of `a:b@` at max_seconds 2: the clock is read at every name, so the answer is back within 4 s with the time limit named", async () => {
  await withCwd(async (cwd) => {
    const pe = buildPeDirs({ exports: { functions: Array.from({ length: 5000 }, (_, i) => ({ name: `${"a:b@".repeat(124)}${String(i).padStart(4, "0")}`, rva: 0x1000 })) } });
    await put(cwd, "work/hostile500.dll", pe.file);
    const started = Date.now();
    const r = await tool(PE_DIRECTORIES, cwd, { path: "work/hostile500.dll", max_seconds: 2 });
    const seconds = (Date.now() - started) / 1000;
    const a = body(r);
    assert.ok(seconds < 4, `took ${seconds} s`);
    assert.ok(a.limits_hit.some((l: string) => /time: the export (names|table) stopped at max_seconds/.test(l)), JSON.stringify(a.limits_hit));
    assert.equal(a.status, "partial");
  });
});

// ---- P2-2: the value of a secret-named key ----------------------------------------------------------------------------------------

test("P2-2 a value that holds `,` `&` `<` `>` or `=` is withheld whole, an unterminated quote is read, and the key names secret_key, private_key, psw, pswd, sig and JSON \"token\"/\"secret\" count: 4,000 random passwords of 12 characters in each form", () => {
  const rnd = prng(515);
  const alphabet = PRINTABLE.replace(/[;"']/g, "");
  const forms: ((pw: string) => string)[] = [
    (pw) => `Password=${pw};`, (pw) => `Pwd='${pw}'`, (pw) => `Password="${pw}`, (pw) => `Password='${pw}`, (pw) => `password: ${pw}`, (pw) => `secret_key=${pw}`,
    (pw) => `private_key = ${pw}`, (pw) => `psw=${pw}`, (pw) => `PSWD=${pw};`, (pw) => `sig=${pw}`, (pw) => `{"token": "${pw}"}`, (pw) => `{"secret":"${pw}"}`, (pw) => `{"password": "${pw}"}`,
  ];
  const items: { text: string; pw: string }[] = [];
  for (let n = 0; n < 4000; n++) {
    const pw = draw(rnd, alphabet, 12);
    if (/^%/.test(pw)) continue;
    items.push({ text: forms[n % forms.length]!(pw), pw });
  }
  for (const path of COPIES) {
    const r = py(path, "items = json.load(sys.stdin)\nprint(json.dumps([m.shown_path(m.cell(t)) for t in items]))", items.map((i) => i.text));
    assert.equal(r.status, 0, r.stderr);
    const out = JSON.parse(r.stdout) as string[];
    let whole = 0, six = 0, first = "";
    items.forEach((it, i) => {
      if (out[i]!.includes(it.pw)) whole++;
      for (let k = 0; k + 6 <= it.pw.length; k++) if (out[i]!.includes(it.pw.slice(k, k + 6))) { six++; first ||= `${it.text} -> ${out[i]}`; break; }
    });
    assert.equal(whole, 0, `${path}: ${whole} of ${items.length} printed whole`);
    assert.equal(six, 0, `${path}: ${six} of ${items.length} have six characters printed, first ${first}`);
  }
});

test("P2-2 the residue is stated: a password that holds `;`, a space or the other quote is withheld up to it; measured over 4,000 random 12-character passwords of the 94 printable characters in `Password=%s;`", () => {
  const rnd = prng(616);
  const items = Array.from({ length: 4000 }, () => draw(rnd, PRINTABLE, 12)).filter((pw) => !pw.startsWith("%"));
  for (const path of COPIES) {
    const r = py(path, "items = json.load(sys.stdin)\nprint(json.dumps([m.shown_path(m.cell('Password=' + t + ';')) for t in items]))", items);
    assert.equal(r.status, 0, r.stderr);
    const out = JSON.parse(r.stdout) as string[];
    const whole = items.filter((pw, i) => out[i]!.includes(pw)).length / items.length;
    const some = items.filter((pw, i) => { for (let k = 0; k + 6 <= pw.length; k++) if (out[i]!.includes(pw.slice(k, k + 6))) return true; return false; }).length / items.length;
    // measured 1.0% whole (a password that begins with `;`, a quote or a space leaves nothing to withhold) and 19% with six characters printed (the changelog states these); the bounds leave room for the sample's spread
    assert.ok(whole <= 0.02, `${path}: ${whole} printed whole`);
    assert.ok(some <= 0.26, `${path}: ${some} with six characters printed`);
  }
});

test("P2-2 a value is not a marker the tool wrote, so a second pass changes nothing", () => {
  for (const path of COPIES) {
    const r = py(path, [
      "texts = ['Password=a,b&c<d>e;', \"Password='Hunter2Secret\", '{\"token\": \"x1y2z3\"}', 'psw=abc sig=def']",
      "once = [m.shown_path(t) for t in texts]",
      "print(json.dumps({'once': once, 'twice': [m.shown_path(t) for t in once]}))",
    ].join("\n"));
    assert.equal(r.status, 0, r.stderr);
    const o = JSON.parse(r.stdout) as { once: string[]; twice: string[] };
    assert.deepEqual(o.twice, o.once);
    assert.deepEqual(o.once, ["Password=<withheld 9 characters>;", "Password=<withheld 13 characters>", '{"token": "<withheld 6 characters>"}', "psw=<withheld 3 characters> sig=<withheld 3 characters>"]);
  }
});

// ---- P2-3: user-info whose password holds / ? # -----------------------------------------------------------------------------------

test("P2-3 URL user-info whose password holds `/`, `?` or `#` is withheld to the last `@` of the token: 3,000 random passwords of 12 characters, in a URL target and in any string, in every copy; a port and an @ in a path are kept", () => {
  const rnd = prng(717);
  const alphabet = PRINTABLE.replace(/[@<>]/g, "");
  const items: { text: string; pw: string }[] = [];
  while (items.length < 3000) {
    const pw = draw(rnd, alphabet, 12);
    if (!/[/?#]/.test(pw) || /^\d{1,5}[/?#]/.test(pw) || pw.startsWith("%")) continue;
    const text = [`https://admin:${pw}@host.example/p`, `ftp://u:${pw}@host.example/x?y=1`, `sftp://svc:${pw}@10.0.0.5`][items.length % 3]!;
    items.push({ text, pw });
  }
  for (const path of COPIES) {
    const r = py(path, [
      "items = json.load(sys.stdin)",
      "shown = [m.shown_path(m.shown_target(t)) if hasattr(m, 'shown_target') else m.shown_path(m.cell(t)) for t in items]",
      "print(json.dumps({'shown': shown, 'kept': [m.shown_path(t) for t in ['http://localhost:3000/@vite/client', 'https://registry.example:443/@scope/pkg', 'file:///C:/Dir/icon@2x.png', 'https://user@host.example/p', 'C:/Dir/icon@2x.png']]}))",
    ].join("\n"), items.map((i) => i.text));
    assert.equal(r.status, 0, r.stderr);
    const o = JSON.parse(r.stdout) as { shown: string[]; kept: string[] };
    let whole = 0, six = 0;
    items.forEach((it, i) => {
      if (o.shown[i]!.includes(it.pw)) whole++;
      for (let k = 0; k + 6 <= it.pw.length; k++) if (o.shown[i]!.includes(it.pw.slice(k, k + 6))) { six++; break; }
    });
    assert.equal(whole, 0, `${path}: ${whole} printed whole`);
    assert.equal(six, 0, `${path}: ${six} with six characters printed`);
    assert.deepEqual(o.kept.slice(0, 3), ["http://localhost:3000/@vite/client", "https://registry.example:443/@scope/pkg", "file:///C:/Dir/icon@2x.png"]);
    assert.equal(o.kept[3], "https://<userinfo withheld 4 characters>@host.example/p");
    assert.equal(o.kept[4], "C:/Dir/icon@2x.png");
  }
});

// ---- P2-4: a member nothing declares and a bound ----------------------------------------------------------------------------------

test("P2-4 a compound file nothing declares, with the compound signature, that passes max_stream_bytes: said, in the limits, and the answer is partial; read once", async () => {
  await withCwd(async (cwd) => {
    const project = Buffer.concat([buildVbaProject([{ name: "Module1", source: "Sub AutoOpen()\r\nEnd Sub\r\n" }]), Buffer.alloc(1 << 20)]);
    const entries = (name: string, declare: boolean) => [
      { name: "[Content_Types].xml", data: Buffer.from(`<?xml version="1.0"?><Types xmlns="${CT_NS}"><Default Extension="xml" ContentType="application/xml"/>${declare ? `<Override PartName="/${name}" ContentType="application/vnd.ms-office.vbaProject"/>` : ""}</Types>`) },
      { name, data: project },
    ];
    await put(cwd, "work/undeclared.docm", buildZip(entries("word/blob.dat", false)));
    const a = body(await tool(DOC_STRUCTURE, cwd, { path: "work/undeclared.docm", max_stream_bytes: 65536 }));
    assert.equal(a.status, "partial", JSON.stringify(a.limits_hit));
    assert.ok(a.limits_hit.some((l: string) => /word\/blob\.dat: the member declares \d+ bytes, over max_stream_bytes/.test(l)), JSON.stringify(a.limits_hit));
    assert.equal(a.members.over_budget, 1);
    // read once: a declared project part that passes the budget counts one over-budget member, and one that does not is read one time
    await put(cwd, "work/declared.docm", buildZip(entries("word/blob.dat", true)));
    const d = body(await tool(DOC_STRUCTURE, cwd, { path: "work/declared.docm", max_stream_bytes: 4 << 20 }));
    assert.equal(d.members.read, 2, JSON.stringify(d.members));
  });
});

// ---- P2-5: characters that print as nothing --------------------------------------------------------------------------------------

test("P2-5 an AWS key id or `Password=` split by a UTF-8 invisible character read as Latin-1 or CP437, or by U+2800, U+3164, U+115F, U+1160, U+FFA0, U+2028, U+2029, is withheld: 300 random keys at each position, in every copy", () => {
  const rnd = prng(818);
  const invisibles = ["\u200b", "\u200d", "\u2060", "\ufeff", "\u00ad", "\u2800", "\u3164", "\u115f", "\u1160", "\uffa0", "\u2028", "\u2029"];
  const items: { text: string; secret: string }[] = [];
  for (let n = 0; n < 300; n++) {
    const key = "AKIA" + draw(rnd, "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567", 16);
    const pw = draw(rnd, ALNUM, 12);
    const at = 1 + Math.floor(rnd() * 18);
    const ch = invisibles[n % invisibles.length]!;
    const mojibake = (c: string, enc: "latin1" | "cp437"): string => (enc === "latin1" ? Buffer.from(c, "utf8").toString("latin1") : Buffer.from(c, "utf8").toString("latin1").replace(/[\x80-\xff]/g, (b) => cp437High[b.charCodeAt(0) - 0x80]!));
    for (const visible of [ch, mojibake(ch, "latin1"), mojibake(ch, "cp437")]) {
      items.push({ text: `${key.slice(0, at)}${visible}${key.slice(at)}`, secret: key });
      items.push({ text: `Pass${visible}word=${pw};`, secret: pw });
    }
  }
  for (const path of COPIES) {
    const r = py(path, "items = json.load(sys.stdin)\nprint(json.dumps([m.shown_path(t) for t in items]))", items.map((i) => i.text));
    assert.equal(r.status, 0, r.stderr);
    const out = JSON.parse(r.stdout) as string[];
    const bad = items.filter((it, i) => out[i]!.includes(it.secret) || [...Array(it.secret.length - 8).keys()].some((k) => out[i]!.includes(it.secret.slice(k, k + 9))));
    assert.equal(bad.length, 0, `${path}: ${bad.length} of ${items.length} printed, first ${JSON.stringify(bad[0]?.text)}`);
  }
});

/** CP437 characters of the bytes 0x80..0xFF, from IBM's code page table. */
const cp437High = Array.from("ÇüéâäàåçêëèïîìÄÅÉæÆôöòûùÿÖÜ¢£¥₧ƒáíóúñÑªº¿⌐¬½¼¡«»░▒▓│┤╡╢╖╕╣║╗╝╜╛┐└┴┬├─┼╞╟╚╔╩╦╠═╬╧╨╤╥╙╘╒╓╫╪┘┌█▄▌▐▀αßΓπΣσµτΦΘΩδ∞φε∩≡±≥≤⌠⌡÷≈°∙·√ⁿ²■\u00a0");

// ---- P3: the capa-floss recipe ----------------------------------------------------------------------------------------------------

const PYTHON = spawnSync("python3", ["-c", "import sys; print(sys.executable)"], { encoding: "utf8" }).stdout.trim();

test("P3 capa-floss: a --target that is not a JSON object with a list of paths is JSON and a refusal, never a traceback", () => {
  for (const target of ["[1]", '"s"', "null", '{"paths":5}', '{"paths":[5]}', "{", "[".repeat(100_000)]) {
    for (const verb of ["detect", "run"]) {
      const r = spawnSync(PYTHON, [CAPA_FLOSS, verb, "--target", target, "--out", "/nonexistent/never-made"], { encoding: "utf8" });
      assert.doesNotMatch(r.stderr, /Traceback/, `${verb} ${target.slice(0, 20)}: ${r.stderr.slice(-300)}`);
      assert.equal(r.status, 2, `${verb} ${target.slice(0, 20)}`);
      assert.equal(JSON.parse(r.stdout).ok, false);
    }
  }
});

test("P3 capa-floss: what an engine wrote (capa.json, floss.json, the stderr files) is mode 0600 and the directory it made 0700", async () => {
  await withCwd(async (cwd, bin) => {
    const { stub } = await import("./pack-re-harness.ts");
    await stub(bin, "capa", `if [ "$1" = "--version" ]; then echo v; exit 0; fi\necho '{"rules": {}}'\necho oops >&2\n`);
    await stub(bin, "floss", `if [ "$1" = "--version" ]; then echo v; exit 0; fi\necho '{"analysis": {"enable_static_strings": true}, "strings": {}}'\necho oops >&2\n`);
    const { buildPe } = await import("./pack-re-harness.ts");
    await put(cwd, "inputs/s.exe", buildPe({}).file);
    const out = join(cwd, "made-here");
    const r = spawnSync(PYTHON, [CAPA_FLOSS, "run", "--target", JSON.stringify({ paths: ["inputs/s.exe"] }), "--out", out], { cwd, encoding: "utf8", env: { ...process.env, PATH: `${bin}:/usr/bin:/bin` } });
    assert.equal(r.status, 0, r.stderr + r.stdout);
    const modes: Record<string, number> = {};
    for (const name of ["capa.json", "capa.stderr", "floss.json", "floss.stderr"]) modes[name] = (await stat(join(out, name))).mode & 0o777;
    assert.deepEqual(modes, { "capa.json": 0o600, "capa.stderr": 0o600, "floss.json": 0o600, "floss.stderr": 0o600 });
    assert.equal((await stat(out)).mode & 0o777, 0o700);
  });
});

test("P3 capa-floss, Linux: a process an engine started in a session of its own, left running when the engine exited, is ended before the receipt; the engine is partial and says so", async (t) => {
  if (process.platform !== "linux") { t.skip("PR_SET_CHILD_SUBREAPER is Linux only; on macOS an orphan of an engine that exited by itself is not found"); return; }
  await withCwd(async (cwd, bin) => {
    const { stub, buildPe } = await import("./pack-re-harness.ts");
    const script = `if [ "$1" = "--version" ]; then echo v; exit 0; fi\n${PYTHON} - <<'PY'\nimport os, time\nif os.fork() == 0:\n    os.setsid()\n    time.sleep(3)\n    os.write(1, b'LATE')\n    os._exit(0)\nprint('{"rules": {}}', flush=True)\nPY\n`;
    await stub(bin, "capa", script);
    await stub(bin, "floss", `if [ "$1" = "--version" ]; then echo v; exit 0; fi\necho '{"analysis": {"enable_static_strings": true}, "strings": {}}'\n`);
    await put(cwd, "inputs/s.exe", buildPe({}).file);
    const out = join(cwd, "catalog");
    const r = spawnSync(PYTHON, [CAPA_FLOSS, "run", "--target", JSON.stringify({ paths: ["inputs/s.exe"] }), "--out", out], { cwd, encoding: "utf8", env: { ...process.env, PATH: `${bin}:/usr/bin:/bin` } });
    assert.equal(r.status, 0, r.stderr + r.stdout);
    await new Promise((resolve) => setTimeout(resolve, 4500));
    assert.ok(!(await readFile(join(out, "capa.json"), "utf8")).includes("LATE"), "the orphan wrote after the receipt");
    const c = JSON.parse(await readFile(join(out, "coverage.json"), "utf8")) as Json;
    assert.equal(c.engines.capa.status, "partial", JSON.stringify(c.engines.capa));
    assert.equal(c.engines.capa.orphans_ended, 1);
  });
});

void chmod;
