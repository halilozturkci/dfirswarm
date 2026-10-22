/**
 * ransomware-response: how the two tools print a path. Both go through the same shown() (a block the two run.py files carry byte for
 * byte), so a directory above a note, an unreadable directory and an exclusion are judged like the note's own name, and the rates of
 * the identifier shape are measured here, with the shapes built from pieces at test time (a random draw, never a literal that looks
 * like a real secret).
 */
import assert from "node:assert/strict";
import { randomBytes, randomInt } from "node:crypto";
import { chmod, mkdir, readFile, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { test } from "node:test";
import { ROOT, runPySnippet, withCwd } from "./tool-library-harness.ts";
import { NOTES, SURVEY, body, filesUnder, tool } from "./ransomware-pack-harness.ts";

const pick = (alphabet: string, n: number): string => Array.from({ length: n }, () => alphabet[randomInt(alphabet.length)]).join("");
const LETTERS = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ";
const DIGITS = "0123456789";
const HEX = "0123456789abcdef";
const B58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
function mixed(n: number): string {
  for (;;) {
    const s = pick(LETTERS + DIGITS, n);
    if (/\d/.test(s) && /[A-Za-z]/.test(s)) return s;
  }
}
const fullwidth = (s: string): string => [...s].map((c) => String.fromCodePoint(c.charCodeAt(0) - 0x21 + 0xff01)).join("");
const uuid = (): string => `${pick(HEX, 8)}-${pick(HEX, 4)}-4${pick(HEX, 3)}-a${pick(HEX, 3)}-${pick(HEX, 12)}`;

/** The shapes the rule is documented to withhold, each with a builder. */
const WITHHELD_SHAPES: Record<string, () => string> = {
  hex16: () => pick(HEX, 16),
  hex32: () => pick(HEX, 32),
  hex64: () => pick(HEX, 64),
  alnum12: () => mixed(12),
  alnum40: () => mixed(40),
  decimal12: () => pick(DIGITS, 12),
  decimal20: () => pick(DIGITS, 20),
  letters24: () => pick(LETTERS, 24),
  base58_22: () => pick(B58, 22),
  uuid,
  fullwidth12: () => fullwidth(mixed(12)),
};

const NOTE = "Your files are encrypted. To decrypt your files, pay in bitcoin and restore your files.\n";

async function printedAnywhere(cwd: string, stdout: string): Promise<string> {
  let all = stdout;
  for (const text of Object.values(await filesUnder(join(cwd, "work", "s1")))) all += "\n" + text;
  return all;
}

type Counted = { paths_withheld: number; status: string };

test("both tools withhold an identifier in a directory above a note, in a directory below one, in an unreadable directory and in an exclusion, in every shape the rule claims", async () => {
  await withCwd(async (cwd) => {
    const ev = join(cwd, "work", "ev");
    const ids: string[] = [];
    const locked: string[] = [];
    let n = 0;
    for (const build of Object.values(WITHHELD_SHAPES)) {
      for (let k = 0; k < 3; k++) {
        const id = build();
        ids.push(id);
        const top = join(ev, `g${n++}`);
        await mkdir(join(top, id, "sub"), { recursive: true });
        await writeFile(join(top, id, "README.txt"), NOTE);
        await writeFile(join(top, id, "sub", "HOWTO.txt"), NOTE);
        await writeFile(join(top, id, "report.docx.locked"), randomBytes(6000));
        // an unreadable directory named by an identifier (root reads it anyway: then it is not a failure, and still not printed)
        const hidden = pick(HEX, 16) + pick(LETTERS, 4);
        ids.push(hidden);
        await mkdir(join(top, hidden), { recursive: true });
        await writeFile(join(top, hidden, "README.txt"), NOTE);
        await chmod(join(top, hidden), 0);
        locked.push(join(top, hidden));
      }
    }
    // a top-level directory named by an identifier, excluded by name: the root itself carries it
    const excludedRoot = join(cwd, "work", `case-${pick(HEX, 16)}`);
    ids.push(excludedRoot.split("case-")[1]);
    await mkdir(join(excludedRoot, "dev", "x"), { recursive: true });
    try {
      for (const tool_ of [SURVEY, NOTES]) {
        for (const root of [ev, excludedRoot]) {
          const out = await tool(tool_, cwd, { root: root.slice(cwd.length + 1), limit: 2 });
          const answer = body<Counted>(out);
          const printed = await printedAnywhere(cwd, out.stdout);
          for (const id of ids) assert.ok(!printed.includes(id), `${tool_.includes("survey") ? "encrypted_survey" : "ransom_note_scan"} printed ${id}`);
          if (root === ev) assert.ok(answer.paths_withheld > 0);
        }
      }
    } finally {
      for (const d of locked) await chmod(d, 0o755);
    }
  });
});

test("encrypted_survey still prints the name of an encrypted file, an identifier in it included: it is the evidence", async () => {
  await withCwd(async (cwd) => {
    const ev = join(cwd, "work", "ev", "Users", "bob");
    await mkdir(ev, { recursive: true });
    const appended = pick(HEX, 12);
    await writeFile(join(ev, `budget.xlsx.id-${appended}.locked`), randomBytes(6000));
    const out = await tool(SURVEY, cwd, { root: "work/ev" });
    const answer = body<{ candidates: { file: string }[] }>(out);
    assert.equal(answer.candidates.length, 1);
    assert.ok(answer.candidates[0].file.endsWith(`budget.xlsx.id-${appended}.locked`), answer.candidates[0].file);
    assert.match(answer.candidates[0].file, /^work\/ev\/Users\/bob\//, "an ordinary directory stays");
  });
});

test("a note-named file is withheld by its name in encrypted_survey too, and the count is once per printed path", async () => {
  await withCwd(async (cwd) => {
    const dir = join(cwd, "work", "ev", "Users", "bob");
    await mkdir(dir, { recursive: true });
    for (let i = 0; i < 3; i++) await writeFile(join(dir, `README_${mixed(14)}.txt`), NOTE);
    const out = await tool(SURVEY, cwd, { root: "work/ev" });
    const answer = body<Counted & { note_name_candidates: { file: string }[]; paths_note?: string }>(out);
    assert.equal(answer.note_name_candidates.length, 3);
    assert.ok(answer.note_name_candidates.every((r) => r.file === "work/ev/Users/bob/<identifier-shaped name withheld>"));
    assert.equal(answer.paths_withheld, 3, "three files, each printed path counted once");
    assert.match(answer.paths_note ?? "", /once per printed path/);
  });
});

// --- the rates of the shape --------------------------------------------------------

const MEASURE = String.raw`
import importlib.util, json, random, string, sys
def load(p, n):
    s = importlib.util.spec_from_file_location(n, p); m = importlib.util.module_from_spec(s); s.loader.exec_module(m); return m
tools = {"encrypted_survey": load(sys.argv[1], "es"), "ransom_note_scan": load(sys.argv[2], "rns")}
rnd = random.Random(20261020)
N = int(sys.argv[3])
ALN = string.ascii_letters + string.digits
def pick(a, n): return "".join(rnd.choice(a) for _ in range(n))
def groups(k, size, sep, a): return sep.join(pick(a, size) for _ in range(k))
shapes = {
  "random_alnum_7": lambda: pick(ALN, 7), "random_alnum_8": lambda: pick(ALN, 8), "random_alnum_9": lambda: pick(ALN, 9),
  "random_alnum_12": lambda: pick(ALN, 12), "random_alnum_16": lambda: pick(ALN, 16),
  "base32_16": lambda: pick("ABCDEFGHIJKLMNOPQRSTUVWXYZ234567", 16), "lower_digits_8": lambda: pick(string.ascii_lowercase + string.digits, 8),
  "decimal_12": lambda: pick(string.digits, 12), "decimal_20": lambda: pick(string.digits, 20), "letters_24": lambda: pick(string.ascii_letters, 24),
  "hex_16": lambda: pick("0123456789abcdef", 16), "hex_32": lambda: pick("0123456789abcdef", 32),
  "base58_22": lambda: pick("123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz", 22),
  "fullwidth_12": lambda: "".join(chr(ord(c) - 0x21 + 0xFF01) for c in pick(ALN, 12)),
  "dash_4x4": lambda: groups(4, 4, "-", string.ascii_uppercase + string.digits), "underscore_4x4": lambda: groups(4, 4, "_", "0123456789abcdef"),
  "dot_4x4": lambda: groups(4, 4, ".", string.ascii_uppercase + string.digits),
}
out = {tool: {} for tool in tools}
for name, g in shapes.items():
    ids = [g() for _ in range(N)]
    for tool, m in tools.items():
        out[tool][name] = sum(1 for i in ids if i in m.shown("/x/%s/README.txt" % i, count=False)) / N
print(json.dumps(out))
`;

test("the shape rule prints no more than its documented share of each random identifier shape, in both tools", async () => {
  const N = 1500;
  const run = await runPySnippet(MEASURE, [SURVEY, NOTES, String(N)], null);
  assert.equal(run.code, 0, run.stderr);
  const rates = JSON.parse(run.stdout) as Record<string, Record<string, number>>;
  assert.deepEqual(rates.encrypted_survey, rates.ransom_note_scan, "the two tools judge a name alike");
  const r = rates.ransom_note_scan;
  for (const shape of ["decimal_12", "decimal_20", "hex_16", "hex_32", "base58_22"]) assert.equal(r[shape], 0, shape);
  assert.ok(r.fullwidth_12 <= 0.02, `fullwidth_12 ${r.fullwidth_12}`);
  assert.ok(r.letters_24 <= 0.015, `letters_24 ${r.letters_24}`); // mixed-case letters: 0.5% read as words
  // what is printed anyway, as the manifest states it (random draws: bounds with room for the sampling error at N = 1,500)
  assert.ok(r.random_alnum_8 > 0.015 && r.random_alnum_8 < 0.065, `random_alnum_8 ${r.random_alnum_8}`);
  assert.ok(r.random_alnum_9 < 0.045, `random_alnum_9 ${r.random_alnum_9}`);
  assert.ok(r.random_alnum_12 < 0.025, `random_alnum_12 ${r.random_alnum_12}`);
  assert.ok(r.random_alnum_16 < 0.01, `random_alnum_16 ${r.random_alnum_16}`);
  assert.ok(r.base32_16 <= 0.003, `base32_16 ${r.base32_16}`); // all capitals is one case of 16 letters now: withheld
  assert.ok(r.lower_digits_8 > 0.04 && r.lower_digits_8 < 0.12, `lower_digits_8 ${r.lower_digits_8}`);
  // the classes the manifest says are printed whole
  for (const shape of ["random_alnum_7", "dash_4x4", "underscore_4x4", "dot_4x4"]) assert.equal(r[shape], 1, shape);
});

test("each manifest states the shape, the rates that were measured and that a name of another shape is printed", async () => {
  for (const name of ["encrypted_survey", "ransom_note_scan"]) {
    const manifest = JSON.parse(await readFile(join(ROOT, "packs", "ransomware-response", "tools", name, "manifest.json"), "utf8")) as { description: string };
    const d = manifest.description;
    for (const text of ["100%", "3.3%", "2.2%", "0.6%", "0.1%", "2.4%", "0.5%", "7.1%", "0.7%", "4.9%", "38%", "5.8%", "41.8%", "an identifier of another shape is printed", "paths_withheld", "once per printed path"]) {
      assert.ok(d.includes(text), `${name} does not say ${text}`);
    }
  }
});

// --- the shared text ---------------------------------------------------------------

async function block(path: string, name: string): Promise<string> {
  const text = await readFile(path, "utf8");
  const begin = `# BEGIN SHARED ${name}`;
  const end = `# END SHARED ${name}`;
  const start = text.indexOf(begin);
  const stop = text.indexOf(end);
  assert.ok(start >= 0 && stop > start, `${path} carries the ${name} block`);
  assert.equal(text.indexOf(begin, start + 1), -1, `${path} carries it once`);
  return text.slice(start, stop + end.length);
}

const PACKS = join(ROOT, "packs");

test("the two tools carry the same name block, and the network pack's withholding block and the windows pack's place, page and stop blocks as shipped there", async () => {
  assert.equal(await block(SURVEY, "NAMES"), await block(NOTES, "NAMES"));
  assert.equal(await block(SURVEY, "BACKSTOP"), await block(NOTES, "BACKSTOP"));
  const network = await block(join(PACKS, "network-forensics", "tools", "pcap_extract", "run.py"), "WITHHOLDING");
  const regkv = join(PACKS, "windows-forensics", "tools", "regkv", "run.py");
  for (const path of [SURVEY, NOTES]) {
    assert.equal(await block(path, "WITHHOLDING"), network, `${path}: withholding`);
    for (const name of ["PLACE", "PAGE", "STOP"]) assert.equal(await block(path, name), await block(regkv, name), `${path}: ${name}`);
    const text = await readFile(path, "utf8");
    assert.doesNotMatch(text.replace(/^\s*#.*$/gm, "").replace(/"""[\s\S]*?"""/g, ""), /start_new_session|setsid|process_group/, `${path} starts a program outside its group`);
  }
});

// --- time ---------------------------------------------------------------------------

const HOSTILE = String.raw`
import importlib.util, json, sys, time
def load(p, n):
    s = importlib.util.spec_from_file_location(n, p); m = importlib.util.module_from_spec(s); s.loader.exec_module(m); return m
out = {}
for n, p in (("encrypted_survey", sys.argv[1]), ("ransom_note_scan", sys.argv[2])):
    m = load(p, n)
    for size in (4096, 32768):
        cases = {
          "lower": "a" * size, "mixed": "aB" * (size // 2), "camel": "Ab" * (size // 2), "caps_lower": "A" * (size // 2) + "a" * (size // 2),
          "camel_then_digit": "Ab" * (size // 2 - 1) + "1", "dashes": "a-" * (size // 2), "dots": "a." * (size // 2),
          "userinfo": "a:" * (size // 4) + "@", "slashes": "a1/" * (size // 3), "digits": "1" * size, "padded": "a" * (size - 3) + "===",
          "path": "/".join(["Ab1x"] * (size // 5)),
        }
        for label, text in cases.items():
            t0 = time.perf_counter()
            m.shown(text, count=False)
            m.shown(text, ["x" * 8], count=False)
            out["%s %s %d" % (n, label, size)] = time.perf_counter() - t0
print(json.dumps(out))
`;

test("the name rule and the shared withholding rules are linear on hostile names of 4,096 and 32,768 characters", async () => {
  const run = await runPySnippet(HOSTILE, [SURVEY, NOTES], null);
  assert.equal(run.code, 0, run.stderr);
  const times = JSON.parse(run.stdout) as Record<string, number>;
  for (const [label, seconds] of Object.entries(times)) assert.ok(seconds < 1.5, `${label}: ${seconds} s`);
});
