/**
 * ransomware-response: what a name is read as before it is judged, and what the first pass costs.
 *
 * - a full-width solidus (and the signs a/c, a/s, c/o, c/u) is NFKC's `/`, which ends a run of pairs: both rules read each of the five as one
 *   separator that is not a slash (not the two or three characters NFKC would give), so pairs joined by it are withheld like any other;
 * - a character that shows nothing but is not a format character (a combining grapheme joiner, a variation selector, a filler, a braille
 *   blank, a combining mark) cannot split a token either;
 * - the scan matches a note for the values its path holds only when the note holds a piece of such a name, matches the URL and identifier
 *   patterns piece by piece with the clock looked at between pieces, and keeps no URL among the values that withhold a name;
 * - the manifests, the skill and the changelog say which shapes are printed (a deny-list is not finite), with rates.
 *
 * Every identifier is drawn at test time from pieces, never a literal that looks like a real secret. Fuzz volumes are at most 1,000 cases per
 * tool and are only counted.
 */
import assert from "node:assert/strict";
import { randomInt } from "node:crypto";
import { mkdir, readFile, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { test } from "node:test";
import { ROOT, runPySnippet, withCwd } from "./tool-library-harness.ts";
import { LOAD, NOTES, SURVEY, filesUnder, runPatched, runWithoutFirstRule, tool } from "./ransomware-pack-harness.ts";

const HEX = "0123456789abcdef";
const pick = (alphabet: string, n: number): string => Array.from({ length: n }, () => alphabet[randomInt(alphabet.length)]).join("");
const pairs = (k: number, sep: string): string => Array.from({ length: k }, () => pick(HEX, 2)).join(sep);
const NOTE = "Your files are encrypted. To decrypt your files, pay in bitcoin and restore your files.\n";

// ---- a full-width solidus is a separator, not a slash --------------------------------------------------------------------------------

const SLASH = LOAD + String.raw`
import random, unicodedata
rnd = random.Random(int(sys.argv[3]))
HEX = "0123456789abcdef"
def pairs(k, sep): return sep.join("".join(rnd.choice(HEX) for _ in range(2)) for _ in range(k))
wrap = [lambda t: t, lambda t: "id[" + t + "]", lambda t: "key=" + t, lambda t: "(" + t + ")"]
SEPS = ["\uff0f", "\u2100", "\u2101", "\u2105", "\u2106"]
slashy = [c for c in map(chr, range(0x80, 0x110000)) if not 0xD800 <= ord(c) < 0xE000 and "/" in unicodedata.normalize("NFKC", c)]
out = {}
for n, p in (("encrypted_survey", sys.argv[1]), ("ransom_note_scan", sys.argv[2])):
    m = load(p, n)
    total = first = second = in_path = 0
    for w in wrap:
        for k in (8, 9, 16):
          for sep in SEPS:
            for _ in range(10):
                name = w(pairs(k, sep))
                total += 1
                if name in m.shown("/x/" + name + "/README.txt", count=False):
                    first += 1
                if m._why(name) is None:
                    second += 1
                if m._why("a/" + name + "/b") is None:
                    in_path += 1
    held = [hex(ord(c)) for c in slashy if "/" in m.fold(c) or "/" in m._read_as(c)]
    out[n] = [total, first, second, in_path, len(slashy), held]
print(json.dumps(out))
`;

test("pairs of hex digits joined by a full-width solidus or by one of the signs a/c, a/s, c/o, c/u are withheld by both rules, and no character folds to a slash (600 cases per tool, count only)", async () => {
  const run = await runPySnippet(SLASH, [SURVEY, NOTES, String(randomInt(1, 1e9))], null);
  assert.equal(run.code, 0, run.stderr);
  const out = JSON.parse(run.stdout) as Record<string, [number, number, number, number, number, string[]]>;
  for (const [name, [total, first, second, inPath, slashy, held]] of Object.entries(out)) {
    assert.equal(total, 600, name);
    assert.equal(first, 0, `${name}: the first rule printed a run of pairs joined by U+FF0F or one of the four signs`);
    assert.equal(second, 0, `${name}: the second check missed it`);
    assert.equal(inPath, 0, `${name}: the second check missed it in a path`);
    assert.ok(slashy >= 5, `${name}: the characters whose NFKC form holds a slash were not found (${slashy})`);
    assert.deepEqual(held, [], `${name}: these characters still fold to a slash`);
  }
});

// ---- characters that show nothing do not split a token ---------------------------------------------------------------------------------

const INVISIBLE = LOAD + String.raw`
import random, unicodedata
rnd = random.Random(int(sys.argv[3]))
HEX, DG, AN = "0123456789abcdef", "0123456789", "abcdefghijklmnopqrstuvwxyz0123456789"
named = [0x34f, 0x180b, 0x180c, 0x180d, 0x180f, 0x3164, 0xffa0, 0x115f, 0x1160, 0x17b4, 0x17b5, 0x2800, 0x301, 0x300, 0x20d0, 0x903,
         0xfe00, 0xfe01, 0xfe0e, 0xfe0f, 0xe0100, 0xe01ef, 0x1d173, 0xe0001, 0x200b]
pool = [c for c in map(chr, range(0x80, 0x110000)) if not 0xD800 <= ord(c) < 0xE000 and unicodedata.category(c) in ("Cf", "Mn", "Mc", "Me")]
chars = [chr(o) for o in named] + rnd.sample(pool, 250)
def pieces(shape):
    if shape == "hex32":
        s = "".join(rnd.choice(HEX) for _ in range(32)); return [s[i:i + 4] for i in range(0, 32, 4)]
    if shape == "dec12":
        s = "".join(rnd.choice(DG) for _ in range(12)); return [s[i:i + 3] for i in range(0, 12, 3)]
    s = "".join(rnd.choice(AN) for _ in range(11)) + "7"; return [s[:6], s[6:]]
out = {}
for n, p in (("encrypted_survey", sys.argv[1]), ("ransom_note_scan", sys.argv[2])):
    m = load(p, n)
    row = {}
    for shape in ("hex32", "dec12", "alnum12"):
        total = first = second = 0
        for c in chars:
            name = c.join(pieces(shape))
            total += 1
            if name in m.shown("/x/" + name + "/README.txt", count=False):
                first += 1
            if m._why(name) is None:
                second += 1
        row[shape] = [total, first, second]
    out[n] = row
print(json.dumps(out))
`;

test("a token split by a character that shows nothing (a joiner, a variation selector, a filler, a blank, a combining mark) is withheld by both rules (about 825 cases per tool, count only)", async () => {
  const run = await runPySnippet(INVISIBLE, [SURVEY, NOTES, String(randomInt(1, 1e9))], null);
  assert.equal(run.code, 0, run.stderr);
  const out = JSON.parse(run.stdout) as Record<string, Record<string, [number, number, number]>>;
  for (const [name, shapes] of Object.entries(out)) {
    let cases = 0;
    for (const [shape, [total, first, second]] of Object.entries(shapes)) {
      cases += total;
      assert.equal(first, 0, `${name}: the first rule printed ${first} of ${total} ${shape} tokens split by an invisible character`);
      assert.equal(second, 0, `${name}: the second check missed ${second} of ${total} ${shape} tokens`);
    }
    assert.ok(cases <= 1000 && cases >= 800, `${name}: ${cases} cases`);
  }
});

test("a mark is taken off the character it sits on, and a precomposed letter next to a run of pairs is still a neighbour that is not an ASCII letter", async () => {
  const code = LOAD + String.raw`
for n, p in (("encrypted_survey", sys.argv[1]), ("ransom_note_scan", sys.argv[2])):
    m = load(p, n)
    assert m.fold("áb️c͏d") == "abcd", n
    assert m._read_as("áb️c͏d") == "abcd", n
    assert m.fold("é") == "é" and m._read_as("é") == "é", n
    ids = ":".join(["aa", "bb", "cc", "dd", "ee", "ff", "00", "11"])
    for name in ("é" + ids, ids + "é"):
        assert m.shaped(name), n
        assert m._why(name) == "pairs of hex digits", n
print("ok")
`;
  const run = await runPySnippet(code, [SURVEY, NOTES], null);
  assert.equal(run.code, 0, run.stderr);
  assert.equal(run.stdout.trim(), "ok");
});

// ---- end to end: a whole id in a directory, a note name and an extension, with and without the first rule ----------------------------

/** What a JSON answer with ensure_ascii prints for a string: every non-ASCII character as \uXXXX. */
const escaped = (text: string): string => text.replace(/[^\x00-\x7f]/gu, (c) => "\\u" + c.charCodeAt(0).toString(16).padStart(4, "0"));

type Entry = { slot: string; raw: string };

async function classTree(root: string): Promise<Entry[]> {
  const entries: Entry[] = [];
  let n = 0;
  const hex32 = (sep: string): string => Array.from({ length: 8 }, () => pick(HEX, 4)).join(sep);
  const makers: (() => string)[] = [
    () => pairs(8, "／"),
    () => `id[${pairs(8, "／")}]`,
    () => pairs(9, "／"),
    ...["͏", "️", "ㅤ", "⠀", "́", "᠋", "ﾠ"].map((c) => () => hex32(c)),
  ];
  for (const make of makers) {
    const base = join(root, `t${n++}`);
    const dir = make();
    await mkdir(join(base, dir), { recursive: true });
    await writeFile(join(base, dir, "README.txt"), NOTE);
    entries.push({ slot: "directory", raw: dir });
    const name = make();
    await writeFile(join(base, `README_${name}.txt`), NOTE);
    entries.push({ slot: "note name", raw: name });
    const ext = make();
    await writeFile(join(base, `README.txt.${ext}`), NOTE);
    entries.push({ slot: "extension", raw: ext });
  }
  return entries;
}

const leaks = (printed: string, entries: Entry[]): string[] =>
  entries.filter((e) => printed.includes(e.raw) || printed.includes(escaped(e.raw))).map((e) => `${e.slot}`);

test("an id joined by a full-width solidus or split by an invisible character is printed nowhere (answer, pages, census, job files), with the first rule and with the second check alone", async () => {
  await withCwd(async (cwd) => {
    const entries = await classTree(join(cwd, "work", "ev"));
    assert.equal(entries.length, 10 * 3);
    for (const [script, label] of [[SURVEY, "encrypted_survey"], [NOTES, "ransom_note_scan"]] as const) {
      const out = join(cwd, "out-" + label);
      await mkdir(out);
      const run = await tool(script, cwd, { root: "work/ev", limit: 5 }, { JOB_ID: "j000001", OUT: out });
      assert.equal(run.code, 0, run.stderr + run.stdout);
      assert.deepEqual(leaks(run.stdout + Object.values(await filesUnder(out)).join("\n"), entries), [], `${label}: an id was printed`);
      const alone = join(cwd, "out-alone-" + label);
      await mkdir(alone);
      const without = await runWithoutFirstRule(script, JSON.stringify({ root: "work/ev", limit: 5 }), cwd, alone);
      assert.doesNotMatch(without.stderr, /Traceback/, label);
      assert.deepEqual(leaks(without.stdout + Object.values(await filesUnder(alone)).join("\n"), entries), [], `${label}: an id was printed with the first rule removed`);
    }
  });
});

// ---- the scan: the URL and identifier patterns are matched between pieces; a URL names no path --------------------------------------

const CHUNKS = LOAD + String.raw`
import random
m = load(sys.argv[1], "rns")
m.STOP["deadline"] = None
rnd = random.Random(int(sys.argv[2]))
bits = ["https://", "http://", "ab", "identifier", " ", "  ", "your personal id: ", "victim id=", "token", "aaaaaaaa", "1234567", "\n",
        "x@y.zz ", "-", "_", "\t", " " * 40, "decryption id", "your key", "/", "http", "id", "\u00a0",
        "abcdefghijklmnop.onion ", "ABCDEFGHIJKLMNOP.ONION ", "0x" + "a" * 40 + " ", "0x", "@", ".onion"]
cases = differing = 0
for size in (7, 11, 64, 300):
    m.CHUNK = size
    for _ in range(200):
        text = "".join(rnd.choice(bits) for _ in range(rnd.randint(1, 120)))
        for kind, pattern, group in m.KINDS:
            cases += 1
            if [(x.start(), x.end()) for x in pattern.finditer(text)] != [(x.start(), x.end()) for x in m.matches(pattern, text, kind)]:
                differing += 1
# the clock is looked at between pieces for every kind, the unbounded ones too
m.CHUNK = 1 << 18
text = ("identifier" + " " * 64 + "!") * 40000 + " a.onion x@y 0x"      # the literals a note must hold to be matched for onion, email and ethereum
checks = {}
for kind, pattern, group in m.KINDS:
    calls = []
    real = m.out_of_time
    m.out_of_time = lambda: calls.append(1) or False
    try:
        list(m.matches(pattern, text, kind))
    finally:
        m.out_of_time = real
    checks[kind] = len(calls)
print(json.dumps({"cases": cases, "differing": differing, "text": len(text), "chunk": m.CHUNK, "checks": checks}))
`;

test("ransom_note_scan finds exactly the matches of one search piece by piece, and looks at the clock between pieces for the URL and identifier patterns too", async () => {
  const run = await runPySnippet(CHUNKS, [NOTES, String(randomInt(1, 1e9))], null);
  assert.equal(run.code, 0, run.stderr);
  const out = JSON.parse(run.stdout) as { cases: number; differing: number; text: number; chunk: number; checks: Record<string, number> };
  assert.equal(out.cases, 800 * 8);
  assert.equal(out.differing, 0, "a piece-by-piece search found other matches than one search");
  const pieces = Math.ceil(out.text / out.chunk);
  for (const [kind, calls] of Object.entries(out.checks)) {
    assert.ok(calls >= pieces, `${kind}: the clock was looked at ${calls} times for ${pieces} pieces`);
  }
});

const WINDOWS = LOAD + String.raw`
import random
m = load(sys.argv[1], "rns")
m.STOP["deadline"] = None
rnd = random.Random(int(sys.argv[2]))
LO = "abcdefghijklmnopqrstuvwxyz0123456789"
cases = missed = 0
for _ in range(400):
    value = "".join(rnd.choice(LO) for _ in range(rnd.randint(8, 20)))
    label = rnd.choice(["your personal id: ", "victim id=", "identifier "])
    text = "x" * rnd.randint(0, 30) + label + value + " end " + "y" * rnd.randint(0, 30)
    if rnd.random() < 0.5:
        text = text.upper()
    # a name that holds the value, with something before and after (cased as it pleases): a note that names it must be matched
    name = ("r" * rnd.randint(0, 3) + value + "_x" * rnd.randint(0, 2)).lower()
    values = [v.lower() for v in m.first_values(text) if len(v) >= 8]
    cases += 1
    if any(v in name for v in values) and not m.can_name(text, [name]):
        missed += 1
    # a note with none of the pieces of the names is not matched
none = m.can_name("a note that holds nothing of the kind " * 100, ["readme.txt", "case_directory"])
some = m.can_name("see README.txt for the rest", ["readme.txt"])
many = m.can_name("nothing", ["".join(rnd.choice(LO) for _ in range(40)) for _ in range(5)])
print(json.dumps({"cases": cases, "missed": missed, "none": none, "some": some, "many": many}))
`;

test("the first pass skips a note that holds no piece of the names on its path, and never one that holds a value inside a name (400 cases, count only)", async () => {
  const run = await runPySnippet(WINDOWS, [NOTES, String(randomInt(1, 1e9))], null);
  assert.equal(run.code, 0, run.stderr);
  const out = JSON.parse(run.stdout) as { cases: number; missed: number; none: boolean; some: boolean; many: boolean };
  assert.equal(out.cases, 400);
  assert.equal(out.missed, 0, "a note that holds a value inside a name was skipped by the first pass");
  assert.equal(out.none, false, "a note with no piece of any name was matched");
  assert.equal(out.some, true);
  assert.equal(out.many, true, "with many pieces to look for the note is matched, as before");
});

test("the first pass matches no note that holds nothing of its path, and matches one that names a directory", async () => {
  await withCwd(async (cwd) => {
    const patch = "orig = m.first_values\ncalls = []\ndef counted(text):\n    calls.append(1)\n    return orig(text)\nm.first_values = counted\n"
      + "import atexit\natexit.register(lambda: sys.stderr.write('FIRST_CALLS=%d' % len(calls)))";
    const quiet = join(cwd, "work", "quiet");
    for (const d of ["alpha_directory", "beta_directory", "gamma_directory"]) {
      await mkdir(join(quiet, d), { recursive: true });
      await writeFile(join(quiet, d, "README.txt"), NOTE + "your personal id: " + pick(HEX, 12) + "\n");
    }
    const none = join(cwd, "out-none");
    await mkdir(none);
    const first = await runPatched(NOTES, patch, JSON.stringify({ root: "work/quiet" }), cwd, none);
    assert.match(first.stderr, /FIRST_CALLS=0$/, first.stderr);
    const named = join(cwd, "work", "named", "qwertyui");
    await mkdir(named, { recursive: true });
    await writeFile(join(named, "README.txt"), NOTE + "your personal id: qwertyui\n");
    const out = join(cwd, "out-named");
    await mkdir(out);
    const second = await runPatched(NOTES, patch, JSON.stringify({ root: "work/named" }), cwd, out);
    assert.match(second.stderr, /FIRST_CALLS=1$/, second.stderr);
    assert.doesNotMatch(second.stdout, /qwertyui/, "the directory named like a value of its note was printed");
  });
});

test("a URL is no value that withholds a name: 5,100 URLs do not use up the values kept for the identifier after them", async () => {
  await withCwd(async (cwd) => {
    const dir = join(cwd, "work", "ev", "qwertyui");
    await mkdir(dir, { recursive: true });
    const urls = Array.from({ length: 5100 }, (_, i) => `https://a.bc/${i}`).join("\n");
    await writeFile(join(dir, "README.txt"), `${NOTE}${urls}\nyour personal id: qwertyui\n`);
    const run = await tool(NOTES, cwd, { root: "work/ev", max_size: 500000 });
    assert.equal(run.code, 0, run.stderr + run.stdout);
    assert.doesNotMatch(run.stdout, /qwertyui/, "the directory named like the identifier of its note was printed");
    const answer = JSON.parse(run.stdout) as { paths_withheld: number; first_pass: string };
    assert.ok(answer.paths_withheld >= 1);
    assert.match(answer.first_pass, /^complete/);
  });
});

// ---- the manifests, the skill and the changelog say what is printed -----------------------------------------------------------------

test("the manifests, the skill and the changelog name the classes that are printed, and the invisible characters and the full-width solidus that are not", async () => {
  const read = (rel: string) => readFile(join(ROOT, rel), "utf8");
  for (const name of ["encrypted_survey", "ransom_note_scan"]) {
    const d = (JSON.parse(await read(`packs/ransomware-response/tools/${name}/manifest.json`)) as { description: string }).description;
    for (const text of [
      "a deny-list of shapes that is not finite",
      "joined by one character that is not a letter, a digit or a slash",
      "a full-width solidus as a separator",
      "variation selectors, fillers",
      "separator of two characters or more",
      "a 6-pair MAC address",
      "an IPv6 address",
      "16 CJK ideographs",
      "words joined by a dash",
      "eight two-digit-hex directories one under another",
      "by a dash 3 to 15%",
      "0 of 7,875 each",
    ]) {
      assert.ok(d.includes(text), `${name} does not say: ${text}`);
    }
    assert.ok(!d.includes("whatever stands at either end of the run"), `${name}: the glued exception is worded as a general rule`);
    assert.ok(!d.includes("hex split by zero-width characters, "), `${name}: the zero-width claim was measured with U+200B only`);
  }
  const scan = (JSON.parse(await read("packs/ransomware-response/tools/ransom_note_scan/manifest.json")) as { description: string }).description;
  assert.ok(scan.includes("is read a second time, and matched a second time only when it holds a piece of such a name"));
  assert.ok(scan.includes("the URL and identifier patterns too"));
  assert.ok(!scan.includes("each note is read twice"));
  const skill = await read("packs/ransomware-response/skills/scope/triage-tools.md");
  for (const text of ["deny-list", "pairs joined by 2 characters", "MAC and IPv6", "8 or more hex pairs with one separator"]) {
    assert.ok(skill.replace(/\s+/g, " ").includes(text), `the skill does not say: ${text}`);
  }
  const log = await read("changelog.d/claude-pack-ransomware-response-p1-fixes.md");
  for (const text of ["A full-width solidus is not a slash", "The first pass is not a second scan of every note", "The clock is looked at inside the URL and identifier patterns too", "deny-list of shapes"]) {
    assert.ok(log.includes(text), `the changelog does not say: ${text}`);
  }
  assert.ok(!log.includes("28 names that the first rule printed are withheld now"), "the cost of the pairs rule is overstated");
});
