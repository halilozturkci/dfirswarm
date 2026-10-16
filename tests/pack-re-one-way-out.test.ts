/**
 * The one way out of doc_structure, pe_directories and the capa-floss recipe, as a structural guarantee rather than a list of cases:
 *   - the sanitiser (shown_path) withholds every shape of tests/pack-re-canary-shapes.ts in every copy of the shared block, also when
 *     the shape is joined to a path by `/`, cut right after an `@`, or has a letter in front of it, and its output is a fixed point;
 *   - the backstop (final_check) sits between the sanitiser and every byte a tool writes: with the sanitiser taken out of a real call
 *     (shown_answer replaced by the identity) and unsanitised strings injected into the answer and into every table row, stdout and
 *     every table file still hold no window of a canary, every caught field is counted in `withheld_by_final_check` and named in
 *     `problems`, and a complete answer becomes partial;
 *   - numbers of 32 digits or more, a file key spelled like a marker the tool writes, and a file key spelled `<key>_not_shown` are
 *     handled without loss and without a fake marker.
 * Every input is generated here; nothing is read from a tool's output to build one.
 */
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { readFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "node:test";
import { DOC_STRUCTURE, PE_DIRECTORIES, RE, body, buildZip, filesUnder, put, tool, withCwd } from "./pack-re-harness.ts";
import type { Json } from "./pack-re-harness.ts";
import { buildPdf, buildPeDirs } from "./pack-re-doc-fixtures.ts";
import { SHAPES, canaries, needles, prng } from "./pack-re-canary-shapes.ts";

const CAPA_FLOSS = join(RE, "recipes", "capa-floss", "run.py");
const COPIES = [DOC_STRUCTURE, PE_DIRECTORIES, CAPA_FLOSS];

const LOAD = [
  "import importlib.util, io, json, os, sys",
  "sys.stdin = open(os.environ['RE_TEST_INPUT'], encoding='utf-8')",
  "spec = importlib.util.spec_from_file_location('tool_under_test', sys.argv[1])",
  "m = importlib.util.module_from_spec(spec)",
  "spec.loader.exec_module(m)",
].join("\n");

/**
 * Python code run with the tool's module loaded as `m`; stdin is the JSON of `input`, stdout is what the code prints. The input goes in
 * a file that the child opens as its stdin, never through a pipe: node's spawnSync with a large `input` has left the child blocked in
 * its stdin read while the parent idled (2 of 14 loops of this file on macOS, Node 22.23.1).
 */
function py(path: string, code: string, input: unknown = null, cwd?: string, env: Record<string, string> = {}): { status: number | null; stdout: string; stderr: string } {
  const dir = mkdtempSync(join(tmpdir(), "re-input-"));
  const file = join(dir, "input.json");
  writeFileSync(file, JSON.stringify(input));
  try {
    const r = spawnSync("python3", ["-I", "-c", `${LOAD}\n${code}`, path], { stdio: ["ignore", "pipe", "pipe"], encoding: "utf8", cwd, env: { ...process.env, AGENT_ID: "s1", ...env, RE_TEST_INPUT: file }, maxBuffer: 1 << 28 });
    return { status: r.status, stdout: r.stdout, stderr: r.stderr };
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
}

function clean(where: string, data: string | Buffer, list: ReturnType<typeof needles>): void {
  const buf = Buffer.isBuffer(data) ? data : Buffer.from(data, "utf8");
  for (const n of list) assert.ok(!buf.includes(n.bytes), `${where}: holds ${n.label}`);
}

test("the sanitiser in each copy of the shared block withholds every shape, 300 canaries of each, alone, inside a path, after a `/`, with a letter in front and cut after an `@`", () => {
  const texts: { text: string; c: ReturnType<typeof canaries>[number][1] }[] = [];
  for (let seed = 0; seed < 300; seed++) {
    const max = [31, 200, 2000][seed % 3]!;
    for (const [, c] of canaries(max, 10_000 + seed)) {
      for (const wrap of [(s: string) => s, (s: string) => `word/${s}.xml`, (s: string) => `C:/Users/x/${s}`, (s: string) => `a b ${s} c`, (s: string) => `x${s}`, (s: string) => `Macros/VBA/${s}/dir`]) {
        texts.push({ text: wrap(c.plant), c });
      }
    }
  }
  for (const path of COPIES) {
    const r = py(path, "texts = json.load(sys.stdin)\nprint(json.dumps([m.shown_path(t) for t in texts]))", texts.map((t) => t.text));
    assert.equal(r.status, 0, r.stderr);
    const out = JSON.parse(r.stdout) as string[];
    out.forEach((shown, i) => clean(`${path} shown_path(${JSON.stringify(texts[i]!.text)}) = ${JSON.stringify(shown)}`, shown, needles(texts[i]!.c)));
  }
});

test("the sanitiser's output is a fixed point, so the backstop catches only what did not pass it: 20,000 generated strings in each copy", () => {
  const rnd = prng(77);
  const alphabet = "abcXYZ019/_-+=:@.%~ <>#;?&\\";
  const texts: string[] = [];
  const names = Object.values(SHAPES);
  for (let i = 0; i < 20000; i++) {
    let s = "";
    const n = 1 + Math.floor(rnd() * 6);
    for (let k = 0; k < n; k++) {
      if (rnd() < 0.3) {
        const c = names[Math.floor(rnd() * names.length)]!(200, prng(i * 13 + k));
        if (c) s += c.plant;
      } else {
        for (let j = Math.floor(rnd() * 24); j > 0; j--) s += alphabet[Math.floor(rnd() * alphabet.length)];
      }
    }
    texts.push(s);
  }
  for (const path of COPIES) {
    const r = py(path, "texts = json.load(sys.stdin)\nbad = [t for t in texts if m.shown_path(m.shown_path(t)) != m.shown_path(t)]\nprint(json.dumps(bad[:5]))", texts);
    assert.equal(r.status, 0, r.stderr);
    assert.deepEqual(JSON.parse(r.stdout), [], `${path}: not a fixed point`);
  }
});

test("final_check withholds an unsanitised key and value, a long number and a value JSON does not carry, counts each, and lets through only a registered string under a safe key", () => {
  const code = [
    "made = m.made('AKIAIOSFODNN7EXAMPLE') if hasattr(m, 'made') else None",
    "safe = (lambda k, v: k == 'clsid' and v == 'AKIAIOSFODNN7EXAMPLE')",
    "value = {'path': 'word/wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY.xml', 'wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY': 1, 'n': 10 ** 33, 'b': b'x',",
    "         'clsid': 'AKIAIOSFODNN7EXAMPLE', 'other': 'AKIAIOSFODNN7EXAMPLE', 'fine': 'Macros/VBA/ThisDocument', 'list': ['u:PwSecret123@', 'ok']}",
    "out = m.final_check(value, safe)",
    "print(json.dumps({'out': out, 'fields': m.FINAL['fields']}))",
  ].join("\n");
  for (const path of COPIES) {
    const r = py(path, code);
    assert.equal(r.status, 0, r.stderr);
    const o = JSON.parse(r.stdout) as Json;
    assert.equal(o.fields, 6, `${path}: ${r.stdout}`);
    assert.equal(o.out.clsid, "AKIAIOSFODNN7EXAMPLE", "a registered string under a safe key passes");
    assert.match(o.out.other, /^<withheld by the final check: 20 characters>$/);
    assert.match(o.out.path, /^<withheld by the final check: \d+ characters>$/);
    assert.match(o.out.n, /^<withheld by the final check: a number of 110 bits>$/);
    assert.match(o.out.b, /^<withheld by the final check: a value of type bytes>$/);
    assert.equal(o.out.fine, "Macros/VBA/ThisDocument");
    assert.deepEqual(o.out.list, ["<withheld by the final check: 14 characters>", "ok"]);
    assert.ok(Object.keys(o.out).some((k) => /^<withheld by the final check: a key of 40 characters>$/.test(k)));
    clean(path, r.stdout, needles({ plant: "", check: ["wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"], pw: "PwSecret123" }));
  }
});

// A real call with the sanitiser removed: shown_answer is the identity, and every table row and the answer carry a raw canary key
// and value. Only the backstop stands between them and the output.
const BYPASS = [
  "CANARY = 'wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY'",
  "m.shown_answer = lambda value, key='', spill=None: value",
  "add = m.LosslessPage.add",
  "m.LosslessPage.add = lambda self, row: add(self, {**row, 'planted/' + CANARY: 'u:PwQx7Zr3Kd99@'})",
  "emit = m.emit",
  "m.emit = lambda result, spill=None, indent=2: emit({**result, 'injected': 'ghp_' + 'Ab3dEf5hIj7lMn9pQr1tUv3xYz5bCd7fGh9j'}, spill, indent)",
  "sys.stdin = io.StringIO(sys.stdin.read())",
  "try:",
  "    m.main()",
  "except SystemExit:",
  "    pass",
].join("\n");

const INJECTED = needles({ plant: "", check: ["wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY", "ghp_Ab3dEf5hIj7lMn9pQr1tUv3xYz5bCd7fGh9j"], pw: "PwQx7Zr3Kd99" });

for (const [label, script, name, make] of [
  ["doc_structure (a ZIP package)", DOC_STRUCTURE, "p.docx", () => buildZip([{ name: "[Content_Types].xml", data: Buffer.from("<Types/>") }, { name: "word/document.xml", data: Buffer.from("<a/>") }, { name: "word/b.xml", data: Buffer.from("<a/>") }])],
  ["doc_structure (a PDF)", DOC_STRUCTURE, "p.pdf", () => buildPdf([{ num: 1, body: "<< /Type /Catalog /Pages 2 0 R /OpenAction << /S /URI /URI (http://h.example/) >> >>" }, { num: 2, body: "<< /Type /Pages /Kids [] /Count 0 >>" }], "/Root 1 0 R").file],
  ["pe_directories", PE_DIRECTORIES, "p.dll", () => buildPeDirs({ exports: { imageName: "a.dll", functions: [{ name: "f" }, { name: "g" }] } }).file],
] as const) {
  test(`the backstop holds with the sanitiser removed: ${label}, unsanitised strings injected into the answer and every table row`, async () => {
    await withCwd(async (cwd) => {
      // the same file through the real tool: complete, nothing caught
      await put(cwd, `work/in/${name}`, make());
      const plain = body(await tool(script, cwd, { path: `work/in/${name}`, limit: 1 }));
      assert.equal(plain.withheld_by_final_check, undefined, "nothing for the backstop to catch in a real call");
      const r = py(script, BYPASS, { path: `work/in/${name}`, limit: 1 }, cwd);
      assert.doesNotMatch(r.stderr, /Traceback/, r.stderr);
      const a = JSON.parse(r.stdout) as Json;
      clean(`${label} stdout`, r.stdout, INJECTED);
      let files = 0;
      for (const f of await filesUnder(join(cwd, "work"))) {
        if (f.startsWith("in/") || /withheld-names/.test(f)) continue;
        files += 1;
        clean(`${label} work/${f}`, await readFile(join(cwd, "work", f)), INJECTED);
      }
      assert.ok(files >= 1, "limit 1 wrote at least one table file");
      assert.ok(a.withheld_by_final_check >= 2, JSON.stringify(a.withheld_by_final_check));
      assert.equal(a.status, "partial");
      assert.ok(a.problems.some((p: string) => /the final check withheld \d+ field/.test(p)), JSON.stringify(a.problems));
    });
  });
}

test("a number of 32 digits or more (a /Count, a /Prev) is given by its size; a shorter one is printed", async () => {
  await withCwd(async (cwd) => {
    const big = "123456789012345678901234567890123";
    await put(cwd, "work/n.pdf", buildPdf([{ num: 1, body: "<< /Type /Catalog /Pages 2 0 R >>" }, { num: 2, body: `<< /Type /Pages /Kids [] /Count ${big} >>` }], `/Root 1 0 R /Size 3 /Prev ${big}`).file);
    const r = await tool(DOC_STRUCTURE, cwd, { path: "work/n.pdf" });
    const a = JSON.parse(r.stdout) as Json;
    assert.ok(!r.stdout.includes(big.slice(0, 20)), "the digits are not printed");
    assert.equal(a.withheld_by_final_check, undefined);
    assert.match(JSON.stringify(a), /<a number of 107 bits, withheld>/);
  });
  for (const path of [DOC_STRUCTURE, PE_DIRECTORIES]) {
    const r = py(path, "print(json.dumps([m.shown_answer(10 ** 31), m.shown_answer(10 ** 31 - 1), m.shown_answer(-(10 ** 40)), m.shown_answer(True)]))");
    assert.equal(r.status, 0, r.stderr);
    assert.equal(r.stdout.trim(), `["<a number of 103 bits, withheld>", ${"9".repeat(31)}, "<a number of 133 bits, withheld>", true]`);
  }
});

test("a key out of the file spelled like a marker the tool writes keeps its '<' escaped, and a file key `<key>_not_shown` is kept beside the spill file's", async () => {
  await withCwd(async (cwd) => {
    const fake = "<token-shaped text withheld 20 characters> #2";
    const esc = fake.replace(/[^A-Za-z0-9]/g, (ch) => "#" + ch.charCodeAt(0).toString(16).padStart(2, "0"));
    const cf = `/CF << /AKIAAAAAAAAAAAAAAAAA << /CFM /V2 >> /${esc} << /CFM /AESV3 >> /AKIABBBBBBBBBBBBBBBB << /CFM /None >> >>`;
    await put(cwd, "work/c.pdf", buildPdf([{ num: 1, body: "<< /Type /Catalog /Pages 2 0 R >>" }, { num: 2, body: "<< /Type /Pages /Kids [] /Count 0 >>" },
      { num: 4, body: `<< /Filter /Standard /V 4 /R 4 /O (aaaa) /U (aaaa) /P -4 ${cf} /StmF /StdCF /StrF /StdCF >>` }], "/Root 1 0 R /Encrypt 4 0 R /ID [(a) (a)]").file);
    const a = body(await tool(DOC_STRUCTURE, cwd, { path: "work/c.pdf" }));
    const keys = Object.keys(a.encryption.dictionary.crypt_filters);
    assert.equal(keys.length, 3, JSON.stringify(keys));
    assert.ok(keys.includes("\\x3ctoken-shaped text withheld 20 characters> #2"), JSON.stringify(keys));
    assert.equal(keys.filter((k) => k.startsWith("<token-shaped text withheld 20 characters>")).length, 2);
  });
  for (const path of [DOC_STRUCTURE, PE_DIRECTORIES]) {
    const code = [
      "class C: key = 'k'",
      "spill = m.Spill(C(), 2)",
      "spill.write = lambda key, items: {'items': len(items)}",
      "print(json.dumps(m.shown_answer({'x_not_shown': 'the file value', 'x': [1, 2, 3, 4]}, '', spill)))",
    ].join("\n");
    const r = py(path, code);
    assert.equal(r.status, 0, r.stderr);
    const o = JSON.parse(r.stdout) as Json;
    assert.equal(o.x_not_shown, "the file value", r.stdout);
    assert.deepEqual(o["x_not_shown #2"], { items: 4 });
    assert.deepEqual(o.x, [1, 2]);
  }
});

test("an sk- head of four to eleven characters that ends a name or a path component is withheld (a name cut by its declared length); a hyphenated word is not", () => {
  const texts = ["sk-LmariHjr", "Macros/sk-N21d6CS69cd", "sk-Ab3d/dir", "desk-top", "risk-assessment-module", "task-list/a", "sk-ab"];
  for (const path of COPIES) {
    const r = py(path, "print(json.dumps([m.shown_path(t) for t in json.load(sys.stdin)]))", texts);
    assert.equal(r.status, 0, r.stderr);
    assert.deepEqual(JSON.parse(r.stdout), ["<token-shaped text withheld 11 characters>", "Macros/<token-shaped text withheld 14 characters>", "<token-shaped text withheld 7 characters>/dir",
      "desk-top", "risk-assessment-module", "task-list/a", "sk-ab"], path);
  }
});

// --- the fourth review: real-shaped secrets at a measured rate, hidden characters, secret-named values, word heads ----------------

const B64 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
/** Random secrets as they are, not as a rule would like them: an AWS secret access key (40 characters of the base64 alphabet) and the
 * base64 of 16, 20, 24 and 32 random bytes, each kept only when it holds a `/` (the case the shape rules have to read across). */
function realistic(seed: number, perShape: number): { shape: string; secret: string }[] {
  const rnd = prng(seed);
  const out: { shape: string; secret: string }[] = [];
  const make: Record<string, () => string> = {
    aws40: () => Array.from({ length: 40 }, () => B64[Math.floor(rnd() * 64)]).join(""),
    b64_16: () => Buffer.from(Array.from({ length: 16 }, () => Math.floor(rnd() * 256))).toString("base64"),
    b64_20: () => Buffer.from(Array.from({ length: 20 }, () => Math.floor(rnd() * 256))).toString("base64"),
    b64_24: () => Buffer.from(Array.from({ length: 24 }, () => Math.floor(rnd() * 256))).toString("base64"),
    b64_32: () => Buffer.from(Array.from({ length: 32 }, () => Math.floor(rnd() * 256))).toString("base64"),
  };
  for (const [shape, f] of Object.entries(make)) {
    for (let n = 0; n < perShape;) {
      const s = f();
      if (s.includes("/")) { out.push({ shape, secret: s }); n++; }
    }
  }
  return out;
}
const WRAPS = [(s: string) => s, (s: string) => `word/${s}.xml`, (s: string) => `https://h.example/${s}`, (s: string) => `../${s}/x.exe`, (s: string) => `Macros/VBA/${s}`, (s: string) => `/C/Users/x/${s}`];
// The measured residue of the `/` rules (the changelog states the same numbers): the share of secrets printed whole, and the share of
// which some nine characters are printed, over these shapes. Measured on 7,000 of each (seeded): whole 1.2% (AWS), 1.4% (16 bytes),
// 0.7% (20), 2.9% (24), 0.1% (32); nine characters 1.7%, 1.5%, 0.8%, 3.2%, 0.8%. The bounds here leave room for the sample's spread.
const RESIDUE: Record<string, { whole: number; nine: number }> = {
  aws40: { whole: 0.025, nine: 0.03 }, b64_16: { whole: 0.03, nine: 0.03 }, b64_20: { whole: 0.02, nine: 0.02 }, b64_24: { whole: 0.045, nine: 0.05 }, b64_32: { whole: 0.01, nine: 0.02 },
};

test("P1-1 random real-shaped secrets holding `/` (AWS secret keys, base64 of 16 to 32 bytes), 400 of each in six places, in every copy: printed at no more than the measured residue", () => {
  const items = realistic(4242, 400).flatMap((x) => WRAPS.map((w) => ({ ...x, text: w(x.secret) })));
  for (const path of COPIES) {
    // a URL goes through shown_target and then, as every string the tool writes, through shown_path (shown_answer)
    const r = py(path, "texts = json.load(sys.stdin)\nprint(json.dumps([m.shown_path(m.shown_target(t)) if hasattr(m, 'shown_target') and t.startswith('https:') else m.shown_path(t) for t in texts]))", items.map((i) => i.text));
    assert.equal(r.status, 0, r.stderr);
    const out = JSON.parse(r.stdout) as string[];
    const tally: Record<string, { n: number; whole: number; nine: number }> = {};
    items.forEach((it, k) => {
      const shown = out[k]!;
      const t = (tally[it.shape] ??= { n: 0, whole: 0, nine: 0 });
      t.n++;
      if (shown.includes(it.secret)) t.whole++;
      for (let i = 0; i + 9 <= it.secret.length; i++) if (shown.includes(it.secret.slice(i, i + 9))) { t.nine++; break; }
    });
    for (const [shape, t] of Object.entries(tally)) {
      assert.ok(t.whole / t.n <= RESIDUE[shape]!.whole, `${path}: ${shape} printed whole ${t.whole} of ${t.n}`);
      assert.ok(t.nine / t.n <= RESIDUE[shape]!.nine, `${path}: ${shape} nine characters printed ${t.nine} of ${t.n}`);
    }
  }
});

/** Launch and GoToR targets as files hold them (ISO 32000-1 7.11.2 file specification strings, relative paths, UNC paths, a mail
 * client's cache folder, /Win /F programs): generated, seeded. */
function targets(seed: number, n: number): string[] {
  const rnd = prng(seed);
  const pick = <T>(a: T[]): T => a[Math.floor(rnd() * a.length)]!;
  const users = ["JohnSmith", "alice.wong", "svc_backup", "Administrator", "m.mueller", "jdoe", "Public", "kim.lee2"];
  const dirs = ["Documents", "Downloads", "Desktop", "Invoices2024", "ClientABC", "Q3Report2024", "FinalDraftV2", "Projects", "HR", "Finance", "Scans", "Archive2019", "Temp", "OneDrive - Contoso"];
  const names = ["Invoice123", "Report_Q3_2024", "setup", "update", "Payment-Advice", "scan0042", "PO-778812", "statement_202409", "Resume_JSmith", "Agreement v2"];
  const exts = ["pdf", "exe", "docx", "xlsx", "bat", "cmd", "vbs", "js", "hta", "lnk", "scr", "ps1", "zip"];
  const some = (k: number) => Array.from({ length: 1 + Math.floor(rnd() * k) }, () => pick(dirs)).join("/");
  const cache = () => Array.from({ length: 8 }, () => "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"[Math.floor(rnd() * 36)]).join("");
  const out: string[] = [];
  for (let i = 0; i < n; i++) {
    const k = rnd();
    if (k < 0.3) out.push(`/C/Users/${pick(users)}/${some(3)}/${pick(names)}.${pick(exts)}`);
    else if (k < 0.45) out.push(`${"../".repeat(Math.floor(rnd() * 3))}${some(3)}/${pick(names)}.${pick(exts)}`);
    else if (k < 0.55) out.push(`//${pick(["fileserver01", "nas", "10.0.0.5", "corp-fs.contoso.local"])}/${pick(["share", "Public", "IT$"])}/${pick(dirs)}/${pick(names)}.${pick(exts)}`);
    else if (k < 0.8) out.push(`/C/Users/${pick(users)}/AppData/Local/Microsoft/Windows/INetCache/Content.Outlook/${cache()}/${pick(names)}.${pick(exts)}`);
    else if (k < 0.9) out.push(pick(["cmd.exe", "/C/Windows/System32/WindowsPowerShell/v1.0/powershell.exe", "mshta.exe", "/C/Windows/SysWOW64/rundll32.exe"]));
    else out.push(`${pick(names)}.${pick(exts)}`);
  }
  return out;
}

test("P2-3 Launch and GoToR targets as files hold them stay readable: 3,000 generated, at most 1% with anything withheld (measured 0.16% on 12,000), the review's examples whole", () => {
  const fixed = ["/C/Users/JohnSmith/Documents/Invoices2024/ClientABC/Invoice123.pdf", "../Q3Report2024/FinalDraftV2/Invoice2024.exe",
    "/C/Users/x/AppData/Local/Microsoft/Windows/INetCache/Content.Outlook/8X2Q4ZTL/invoice.pdf", "//fileserver01/share/Finance/PO-778812.xlsx",
    "/System/Library/CoreServices/ManagedClient.app/Contents/PlugIns/FileVault2.profileDomainPlugin", "\u0006DataSpaces/DataSpaceInfo/StrongEncryptionDataSpace"];
  const all = [...fixed, ...targets(77, 3000)];
  for (const path of COPIES) {
    const r = py(path, "print(json.dumps([m.shown_path(t) for t in json.load(sys.stdin)]))", all);
    assert.equal(r.status, 0, r.stderr);
    const out = JSON.parse(r.stdout) as string[];
    fixed.forEach((t, i) => assert.equal(out[i], t, `${path}: ${t}`));
    const changed = out.slice(fixed.length).filter((o, i) => o !== all[fixed.length + i]!).length;
    assert.ok(changed <= 30, `${path}: ${changed} of 3000 targets changed`);
  }
});

const HIDE: Record<string, (s: string) => string> = {
  nul: (s) => s.split("").join("\0"),
  nul_escaped: (s) => s.split("").join("\\x00"),
  utf16_as_8bit: (s) => s.split("").map((ch) => ch + "\0").join(""),
  zero_width: (s) => s.replace(/(...)/g, "$1\u200b"),
  soft_hyphen: (s) => s.replace(/(....)/g, "$1\u00ad"),
  bidi: (s) => s.replace(/(.....)/g, "$1\u2066"),
  combining: (s) => s.replace(/(..)/g, "$1\u0301"),
  full_width: (s) => s.replace(/[!-~]/g, (ch) => String.fromCharCode(ch.charCodeAt(0) + 0xfee0)),
  no_break_space: (s) => s.replace(/(.......)/g, "$1\u00a0"),
};

test("P2-1 a token split by NUL, its \\x00 escape, UTF-16 read as 8-bit text, zero-width, soft hyphen, bidi or combining marks, or in full-width forms, is withheld whole, in every copy and for every shape", () => {
  const texts: { text: string; c: ReturnType<typeof canaries>[number][1]; how: string }[] = [];
  for (let seed = 0; seed < 20; seed++) {
    for (const [, c] of canaries(200, 50_000 + seed)) {
      for (const [how, hide] of Object.entries(HIDE)) texts.push({ text: `word/${hide(c.plant)}.xml`, c, how });
    }
  }
  const strip = (s: string): string => s.normalize("NFKC").replace(/\\x[0-9a-fA-F]{2}|[\0\u200b\u00ad\u2066\u0300-\u036f\u00a0 ]/g, "");
  for (const path of COPIES) {
    const r = py(path, "texts = json.load(sys.stdin)\nprint(json.dumps([m.shown_path(t) for t in texts]))", texts.map((t) => t.text));
    assert.equal(r.status, 0, r.stderr);
    const out = JSON.parse(r.stdout) as string[];
    out.forEach((shown, i) => {
      const bare = strip(shown);
      for (const s of texts[i]!.c.check) for (let k = 0; k + 9 <= s.length; k++) assert.ok(!bare.includes(s.slice(k, k + 9)), `${path} ${texts[i]!.how}: ${JSON.stringify(shown)}`);
      const pw = texts[i]!.c.pw;
      if (pw) for (let k = 0; k + 6 <= pw.length; k++) assert.ok(!bare.includes(pw.slice(k, k + 6)), `${path} ${texts[i]!.how}: ${JSON.stringify(shown)}`);
    });
    // a name that only holds such characters, and no token, is printed as it is
    const plain = py(path, "print(json.dumps([m.shown_path(t) for t in json.load(sys.stdin)]))", ["\u0005SummaryInformation", "\u0001CompObj", "Caf\u00e9/R\u00e9sum\u00e9.docx", "\\x06DataSpaces/DataSpaceMap"]);
    assert.deepEqual(JSON.parse(plain.stdout), ["\u0005SummaryInformation", "\u0001CompObj", "Caf\u00e9/R\u00e9sum\u00e9.docx", "\\x06DataSpaces/DataSpaceMap"], path);
  }
});

test("P2-2 the value of a secret-named key is withheld after `=` or `:`, quoted or not; P3 a format string and a word that ends in a key name are not", () => {
  const cases: [string, string][] = [
    ["Provider=SQLOLEDB;Data Source=db1;User ID=sa;Password='Hunter2Secret';", "Provider=SQLOLEDB;Data Source=db1;User ID=sa;Password='<withheld 13 characters>';"],
    ["password: Hunter2Secret", "password: <withheld 13 characters>"],
    ['{"AccountKey": "Zm9vYmFyYmF6"}', '{"AccountKey": "<withheld 12 characters>"}'],
    ['Pwd="Hunter 2 Secret"', 'Pwd="<withheld 15 characters>"'],
    ["pass=Hunter2Secret&x=1", "pass=<withheld 17 characters>"],   // `&` stays in the value: a password may hold one (a URL query is split at `&` before, in redact_url)
    ["passphrase=Hunter2Secret", "passphrase=<withheld 13 characters>"],
    ["pw=Hunter2Secret", "pw=<withheld 13 characters>"],
    ["credential=Hunter2Secret", "credential=<withheld 13 characters>"],
    ["x-api-key: Hunter2Secret", "x-api-key: <withheld 13 characters>"],
    ["auth=Hunter2Secret", "auth=<withheld 13 characters>"],
    ["token=%s", "token=%s"], ["user:%s@%s", "user:%s@%s"], ["bypass: true", "bypass: true"], ["OAuth=1", "OAuth=1"],
  ];
  for (const path of COPIES) {
    const r = py(path, "print(json.dumps([m.shown_path(t) for t in json.load(sys.stdin)]))", cases.map((c) => c[0]));
    assert.equal(r.status, 0, r.stderr);
    assert.deepEqual(JSON.parse(r.stdout), cases.map((c) => c[1]), path);
  }
});

test("P3 GitHub and sk- heads in words are not withheld (Risk-Assessment, highs_lows); a head after a non-letter, a long one anywhere and an AWS key id after a letter are", () => {
  const kept = ["Risk-Assessment", "Task-Scheduler-Helper.exe", "Desk-2022", "Kiosk-Mode-V2", "weighs_count.exe", "highs_lows_v2", "C:\\b\\Risk-Assessment\\RiskTool.pdb"];
  const gone = ["ghp_Ab3d", "x/ghp_Ab3dEf", "XAKIAIOSFODNN7", "Xghp_Ab3dEf5hIj7lMn9pQr1tUv", "a_sk-Ab3dEf5hIj7lMn9pQr1t"];
  for (const path of COPIES) {
    const r = py(path, "print(json.dumps([m.shown_path(t) for t in json.load(sys.stdin)]))", [...kept, ...gone]);
    assert.equal(r.status, 0, r.stderr);
    const out = JSON.parse(r.stdout) as string[];
    kept.forEach((t, i) => assert.equal(out[i], t, path));
    gone.forEach((t, i) => assert.match(out[kept.length + i]!, /<token-shaped text withheld \d+ characters>/, `${path}: ${t} -> ${out[kept.length + i]}`));
  }
});

test("the sanitiser's output is a fixed point also for text with hidden characters and escapes: 10,000 generated strings in each copy", () => {
  const rnd = prng(91);
  const alphabet = ["a", "X", "0", "9", "/", "_", "-", "+", "=", ":", "@", ".", "%", " ", "<", ">", "\\x00", "\0", "\u200b", "\u00ad", "\u0301", "\uff21", "\\"];
  const names = Object.values(SHAPES);
  const texts: string[] = [];
  for (let i = 0; i < 10000; i++) {
    let s = "";
    for (let k = 1 + Math.floor(rnd() * 5); k > 0; k--) {
      if (rnd() < 0.3) {
        const c = names[Math.floor(rnd() * names.length)]!(120, prng(i * 7 + k));
        if (c) s += c.plant.split("").map((ch) => (rnd() < 0.1 ? ch + alphabet[16 + Math.floor(rnd() * 6)] : ch)).join("");
      } else for (let j = Math.floor(rnd() * 20); j > 0; j--) s += alphabet[Math.floor(rnd() * alphabet.length)];
    }
    texts.push(s);
  }
  for (const path of COPIES) {
    const r = py(path, "texts = json.load(sys.stdin)\nbad = [t for t in texts if m.shown_path(m.shown_path(t)) != m.shown_path(t)]\nprint(json.dumps(bad[:5]))", texts);
    assert.equal(r.status, 0, r.stderr);
    assert.deepEqual(JSON.parse(r.stdout), [], `${path}: not a fixed point`);
  }
});

test("a piece of a key next to a piece withheld alone is withheld with it (the growth across `/`, also after a `\\`), a key holding `//` is read across it, and a space other than U+0020 does not end a user-info", () => {
  const cases: [string, string][] = [
    ["ehbmtdzvALrzIy/kzvaretHImjWVidK6ccSkU1kG.pdf", "<token-shaped text withheld 40 characters>.pdf"],
    ["iWVgTdB+Maj9AtILVHX58weguemi/2acrXHHBpsh", "<token-shaped text withheld 40 characters>"],
    ["tXCWPlepyJcdP+D/GFHMqaDni2BBVndGWULOwK8r", "<token-shaped text withheld 40 characters>"],
    ["ghp_Q7wErTy9uIoP3aSdF6gHjK2lZxC5vBnM8qW1k4BREtyo2fBeI0cHYq+wBchO/FsOL3gu00I1Hd/G", "<token-shaped text withheld 78 characters>/G"],
    ["Documents/" + "ghp_Ab3dEf5hIj7lMn9pQr1tUv3xYz5bCd7fGh9j" + "/Invoices", "Documents/<token-shaped text withheld 40 characters>/Invoices"],
    ["\\\\srv\\13IYrtjICzAx/kzvaretHImjWVidK6ccSkU1kG", "\\\\srv\\<token-shaped text withheld 38 characters>"],
    ["3Ze2Shi//ZX/omccMcR74A==", "<token-shaped text withheld 24 characters>"],
    ["word/3Ze2Shi//ZX/omccMcR74A==.xml", "word/<token-shaped text withheld 24 characters>.xml"],
    ["C://Users//JohnSmith//Documents", "C://Users//JohnSmith//Documents"],
    ["https://u:Secr3t\u3000Pass@h.example/p", "<token-shaped text withheld 33 characters>"],
  ];
  for (const path of COPIES) {
    const r = py(path, "print(json.dumps([m.shown_path(t) for t in json.load(sys.stdin)]))", cases.map((c) => c[0]));
    assert.equal(r.status, 0, r.stderr);
    assert.deepEqual(JSON.parse(r.stdout), cases.map((c) => c[1]), path);
  }
});

test("a URL target's path is read by the `/` rule in shown_target itself, not only when the answer is sanitised again: random AWS and base64 keys in https:// paths at the measured residue", () => {
  const items = realistic(5151, 400).map((x) => ({ ...x, text: `https://h.example/${x.secret}` }));
  const r = py(DOC_STRUCTURE, "print(json.dumps([m.shown_target(t) for t in json.load(sys.stdin)]))", items.map((i) => i.text));
  assert.equal(r.status, 0, r.stderr);
  const out = JSON.parse(r.stdout) as string[];
  const tally: Record<string, { n: number; whole: number }> = {};
  items.forEach((it, k) => {
    const t = (tally[it.shape] ??= { n: 0, whole: 0 });
    t.n++;
    if (out[k]!.includes(it.secret)) t.whole++;
  });
  for (const [shape, t] of Object.entries(tally)) assert.ok(t.whole / t.n <= RESIDUE[shape]!.whole, `${shape}: printed whole ${t.whole} of ${t.n}`);
  // the review's example
  const one = py(DOC_STRUCTURE, "print(json.dumps(m.shown_target('https://h.example/FpZlLqsVwBAfe5y41rIEM/i8VNUPl9SmEEoWL2Hy')))");
  assert.equal(JSON.parse(one.stdout), "https://h.example/<token-shaped text withheld 40 characters>");
});

test("a password that holds `@` is withheld to the last `@` before the host, cut or not, and in a mailto: address; plain addresses are kept", () => {
  const cases: [string, string][] = [
    ["u:p@ss@host.example", "<userinfo withheld 6 characters>@host.example"],
    ["x/u:p@ss@w0rd@host.example/a", "x/<userinfo withheld 11 characters>@host.example/a"],
    ["svc:Hunter@2Secret@", "<userinfo withheld 18 characters>@"],
    ["mailto:usr:pa@ss@host.example", "mailto:usr:<userinfo withheld 5 characters>@host.example"],
    ["contact a@b.com and c@d.com", "contact a@b.com and c@d.com"],
  ];
  for (const path of COPIES) {
    const r = py(path, "print(json.dumps([m.shown_path(t) for t in json.load(sys.stdin)]))", cases.map((c) => c[0]));
    assert.equal(r.status, 0, r.stderr);
    assert.deepEqual(JSON.parse(r.stdout), cases.map((c) => c[1]), path);
  }
  const url = py(DOC_STRUCTURE, "print(json.dumps(m.shown_target('https://u:p@ss@h.example/x')))");
  assert.equal(JSON.parse(url.stdout), "https://<userinfo withheld 6 characters>@h.example/x");
});
