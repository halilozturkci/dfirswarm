/**
 * ransomware-response: pairs of hex digits with a neighbour glued to the run, and the second check read as a whole.
 *
 * - 8 or more pairs of hex digits are an identifier wherever they stand in a name: bounded by a slash (a path component), by a bracket, an
 *   equals sign, a parenthesis or the end of the name, with any separator a name can hold between the pairs (before, the first rule counted
 *   `id[aa:bb:...]` as 7 pairs and the second check needed a separator, not a slash, on either side of the run);
 * - the second check alone holds the same shapes (with the first rule removed), in every slot a name is printed in: a directory, a note name,
 *   the extension of a note-named file;
 * - the classes that are printed anyway are written down with their rates.
 *
 * Every identifier is drawn at test time from pieces, never a literal that looks like a real secret.
 */
import assert from "node:assert/strict";
import { randomInt } from "node:crypto";
import { mkdir, readFile, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { test } from "node:test";
import { ROOT, runPySnippet, withCwd } from "./tool-library-harness.ts";
import { LOAD, NOTES, SURVEY, filesUnder, runWithoutFirstRule, tool } from "./ransomware-pack-harness.ts";

const HEX = "0123456789abcdef";
const pick = (alphabet: string, n: number): string => Array.from({ length: n }, () => alphabet[randomInt(alphabet.length)]).join("");
const pairs = (k: number, sep: string): string => Array.from({ length: k }, () => pick(HEX, 2)).join(sep);
const NOTE = "Your files are encrypted. To decrypt your files, pay in bitcoin and restore your files.\n";

const SEPARATORS: [string, string][] = [["space", " "], ["dot", "."], ["colon", ":"], ["dash", "-"], ["underscore", "_"]];
const WRAPPERS: [string, (t: string) => string][] = [["plain", (t) => t], ["id[..]", (t) => `id[${t}]`], ["key=..", (t) => `key=${t}`], ["(..)", (t) => `(${t})`]];

// ---- the predicate: every separator, every neighbour, 8 / 9 / 16 pairs --------------------------------------------------------------

const PREDICATE = LOAD + String.raw`
import random
seed = int(sys.argv[3])
rnd = random.Random(seed)
HEX = "0123456789abcdef"
def pairs(k, sep): return sep.join("".join(rnd.choice(HEX) for _ in range(2)) for _ in range(k))
seps = [" ", ".", ":", "-", "_", ",", ";", "|"]
wrap = [lambda t: t, lambda t: "id[" + t + "]", lambda t: "key=" + t, lambda t: "(" + t + ")", lambda t: t + "@mail", lambda t: "#" + t,
        lambda t: "<" + t + ">", lambda t: "{" + t + "}"]
out = {}
for n, p in (("encrypted_survey", sys.argv[1]), ("ransom_note_scan", sys.argv[2])):
    m = load(p, n)
    withheld_missed = backstop_missed = path_backstop_missed = total = 0
    for sep in seps:
        for w in wrap:
            for k in (8, 9, 16):
                for _ in range(5):
                    raw = pairs(k, sep)
                    name = w(raw)
                    total += 1
                    if raw in m.shown("/x/" + name + "/README.txt", count=False):
                        withheld_missed += 1
                    if m._why(name) is None:
                        backstop_missed += 1
                    if m._why("a/" + name + "/b") is None:
                        path_backstop_missed += 1
    out[n] = [total, withheld_missed, backstop_missed, path_backstop_missed]
print(json.dumps(out))
`;

test("8 or more pairs of hex digits are withheld by the first rule and read by the second check whatever stands next to the run (960 cases per tool, count only)", async () => {
  const run = await runPySnippet(PREDICATE, [SURVEY, NOTES, String(randomInt(1, 1e9))], null);
  assert.equal(run.code, 0, run.stderr);
  const out = JSON.parse(run.stdout) as Record<string, number[]>;
  for (const [name, [total, first, second, secondInPath]] of Object.entries(out)) {
    assert.equal(total, 960, name);
    assert.equal(first, 0, `${name}: the first rule printed a run of pairs`);
    assert.equal(second, 0, `${name}: the second check missed a run of pairs`);
    assert.equal(secondInPath, 0, `${name}: the second check missed a run of pairs in a path`);
  }
});

const RATES = LOAD + String.raw`
import random
rnd = random.Random(int(sys.argv[3]))
N = int(sys.argv[4])
HEX, DG = "0123456789abcdef", "0123456789"
def pick(a, n): return "".join(rnd.choice(a) for _ in range(n))
def pairs(k, sep): return sep.join(pick(HEX, 2) for _ in range(k))
shapes = {
  "pairs_colon_7": lambda: pairs(7, ":"), "pairs_space_7": lambda: pairs(7, " "), "pairs_dot_7": lambda: pairs(7, "."),
  "digit_groups_dash_3_3_4": lambda: "-".join((pick(DG, 3), pick(DG, 3), pick(DG, 4))),
  "pairs_colon_8_glued_to_letters": lambda: "id" + pairs(8, ":"), "pairs_space_8_glued_to_a_digit": lambda: pairs(8, " ") + "7",
  "pairs_dash_8_in_brackets": lambda: "id[" + pairs(8, "-") + "]", "pairs_colon_8_in_brackets": lambda: "id[" + pairs(8, ":") + "]",
  "pairs_dash_9_in_brackets": lambda: "[" + pairs(9, "-") + "]", "pairs_dot_8_in_parentheses": lambda: "(" + pairs(8, ".") + ")",
  "pairs_dash_7": lambda: pairs(7, "-"),
}
drawn = {name: [g() for _ in range(N)] for name, g in shapes.items()}
out = {}
for n, p in (("encrypted_survey", sys.argv[1]), ("ransom_note_scan", sys.argv[2])):
    m = load(p, n)
    out[n] = {name: sum(1 for i in ids if i in m.shown("/x/%s/README.txt" % i, count=False)) / N for name, ids in drawn.items()}
print(json.dumps(out))
`;

test("the classes of pairs and groups that are printed, and the ones that are not, are measured (1,000 draws each)", async () => {
  const run = await runPySnippet(RATES, [SURVEY, NOTES, String(randomInt(1, 1e9)), "1000"], null);
  assert.equal(run.code, 0, run.stderr);
  const rates = JSON.parse(run.stdout) as Record<string, Record<string, number>>;
  assert.deepEqual(rates.encrypted_survey, rates.ransom_note_scan, "the two tools judge a name alike");
  const r = rates.ransom_note_scan;
  // printed whole, and written in the manifests: 7 pairs, groups of 3-3-4 digits joined by a dash, a pair glued to a letter or a digit
  for (const shape of ["pairs_colon_7", "pairs_space_7", "digit_groups_dash_3_3_4", "pairs_colon_8_glued_to_letters", "pairs_space_8_glued_to_a_digit"]) {
    assert.ok(r[shape] >= 0.99, `${shape} printed ${r[shape]}`);
  }
  assert.ok(r.pairs_dot_7 >= 0.99, `pairs_dot_7 printed ${r.pairs_dot_7}`);
  assert.ok(r.pairs_dash_7 > 0.1 && r.pairs_dash_7 < 0.5, `pairs_dash_7 ${r.pairs_dash_7}`); // the 20-character run rule of the shared withholding catches some
  // withheld: a neighbour that is not a letter or a digit does not hide the run
  for (const shape of ["pairs_dash_8_in_brackets", "pairs_colon_8_in_brackets", "pairs_dash_9_in_brackets", "pairs_dot_8_in_parentheses"]) {
    assert.equal(r[shape], 0, `${shape} printed ${r[shape]}`);
  }
});

// ---- the second check alone: a table of shapes and slots --------------------------------------------------------------------------

const SHAPES = LOAD + String.raw`
import random
rnd = random.Random(int(sys.argv[3]))
HEX, DG, LO, UP = "0123456789abcdef", "0123456789", "abcdefghijklmnopqrstuvwxyz", "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
def pick(a, n): return "".join(rnd.choice(a) for _ in range(n))
def pairs(k, sep, case=str.lower): return case(sep.join(pick(HEX, 2) for _ in range(k)))
def mixed(alphabet, n):
    while True:
        s = pick(alphabet, n)
        if any(c.isdigit() for c in s) and any(c.isalpha() for c in s): return s
def hexid(n):
    while True:
        s = pick(HEX, n)
        if any(c.isdigit() for c in s) and any(c in "abcdef" for c in s): return s
shapes = {
  "hex_16": lambda: hexid(16), "hex_32": lambda: hexid(32), "hex_24_upper": lambda: hexid(24).upper(),
  "uuid": lambda: "-".join((hexid(8), hexid(4), hexid(4), hexid(4), hexid(12))),
  "alnum_8": lambda: mixed(LO + DG, 8), "alnum_12_mixed": lambda: mixed(LO + UP + DG, 12),
  "lower_16": lambda: pick(LO, 16), "lower_24": lambda: pick(LO, 24), "upper_16": lambda: pick(UP, 16), "upper_24": lambda: pick(UP, 24),
  "decimal_10": lambda: pick(DG, 10), "decimal_12": lambda: pick(DG, 12),
  "arabic_indic_12": lambda: "".join(chr(0x660 + int(c)) for c in pick(DG, 12)),
  "fullwidth_12": lambda: "".join(chr(ord(c) + 0xFEE0) for c in mixed(LO + DG, 12)),
  "zero_width_split_hex": lambda: "​".join(hexid(4) for _ in range(4)),
  "groups_space_3x4": lambda: " ".join(pick(DG, 4) for _ in range(3)), "groups_comma_3x4": lambda: ",".join(pick(DG, 4) for _ in range(3)),
}
for sep, label in ((" ", "space"), (".", "dot"), (":", "colon"), ("-", "dash"), ("_", "underscore"), (",", "comma"), ("|", "bar")):
    for k in (8, 9, 12, 16):
        shapes["pairs_%s_%d" % (label, k)] = (lambda sep=sep, k=k: pairs(k, sep))
        shapes["pairs_%s_%d_upper" % (label, k)] = (lambda sep=sep, k=k: pairs(k, sep, str.upper))
        shapes["pairs_%s_%d_in_brackets" % (label, k)] = (lambda sep=sep, k=k: "id[" + pairs(k, sep) + "]")
        shapes["pairs_%s_%d_after_equals" % (label, k)] = (lambda sep=sep, k=k: "key=" + pairs(k, sep))
slots = {
  "directory": lambda s: "work/ev/%s/sub/README.txt" % s, "note_name": lambda s: "work/ev/README_%s.txt" % s, "extension": lambda s: "work/ev/README.txt.%s" % s,
  "root": lambda s: "work/case-%s" % s, "key": lambda s: None,
}
out = {}
for n, p in (("encrypted_survey", sys.argv[1]), ("ransom_note_scan", sys.argv[2])):
    m = load(p, n)
    missed = []
    total = 0
    for shape, g in shapes.items():
        ident = g()
        for slot, f in slots.items():
            total += 1
            if slot == "key":
                row = m.seal_row({ident: {"x": "fine"}})
            elif slot == "extension":
                row = m.seal_row({"appended_extension": "." + ident})
            else:
                row = m.seal_row({"file": f(ident)})
            if ident in json.dumps(row, ensure_ascii=False):
                missed.append("%s/%s" % (shape, slot))
    out[n] = [total, sorted(set(missed))]
print(json.dumps(out))
`;

test("the second check alone replaces every class the first rule withholds, in a directory, a note name, an extension, a root and a key (shape table)", async () => {
  const run = await runPySnippet(SHAPES, [SURVEY, NOTES, String(randomInt(1, 1e9))], null);
  assert.equal(run.code, 0, run.stderr);
  const out = JSON.parse(run.stdout) as Record<string, [number, string[]]>;
  for (const [name, [total, missed]] of Object.entries(out)) {
    assert.ok(total <= 1000 && total > 500, `${name}: ${total} cases`);
    assert.deepEqual(missed, [], `${name}: the second check let these through`);
  }
});

// ---- end to end: a whole 8-pair id in a directory, a note name and an extension, with and without the first rule ----------------------

type Entry = { slot: string; raw: string };

async function pairsTree(root: string): Promise<Entry[]> {
  const entries: Entry[] = [];
  let n = 0;
  for (const [, sep] of SEPARATORS) {
    for (const [, wrap] of WRAPPERS) {
      for (let draw = 0; draw < 2; draw++) {
        const raw = pairs(8, sep);
        const wrapped = wrap(raw);
        const base = join(root, `t${n++}`);
        await mkdir(join(base, wrapped), { recursive: true });
        await writeFile(join(base, wrapped, "README.txt"), NOTE);
        entries.push({ slot: "directory", raw });
        const second = pairs(8, sep);
        await writeFile(join(base, `README_${wrap(second)}.txt`), NOTE);
        entries.push({ slot: "note name", raw: second });
        const third = pairs(8, sep);
        await writeFile(join(base, `README.txt.${wrap(third)}`), NOTE);
        entries.push({ slot: "extension", raw: third });
      }
    }
  }
  return entries;
}

test("a whole 8-pair id is printed nowhere (answer, pages, census, job files) in a directory, a note name or an extension, with any separator and neighbour, in both tools", async () => {
  await withCwd(async (cwd) => {
    const entries = await pairsTree(join(cwd, "work", "ev"));
    assert.equal(entries.length, 5 * 4 * 2 * 3);
    for (const [script, label] of [[SURVEY, "encrypted_survey"], [NOTES, "ransom_note_scan"]] as const) {
      const out = join(cwd, "out-" + label);
      await mkdir(out);
      const run = await tool(script, cwd, { root: "work/ev", limit: 5 }, { JOB_ID: "j000001", OUT: out });
      assert.equal(run.code, 0, run.stderr + run.stdout);
      const printed = run.stdout + Object.values(await filesUnder(out)).join("\n");
      const leaked = entries.filter((e) => printed.includes(e.raw));
      assert.deepEqual(leaked.map((e) => e.slot), [], `${label}: an id was printed`);
    }
  });
});

test("the same trees with the first rule removed: the second check alone keeps every 8-pair id out of the answer and the files, and the answer is partial", async () => {
  await withCwd(async (cwd) => {
    const entries = await pairsTree(join(cwd, "work", "ev"));
    for (const [script, label] of [[SURVEY, "encrypted_survey"], [NOTES, "ransom_note_scan"]] as const) {
      const out = join(cwd, "out-alone-" + label);
      await mkdir(out);
      const run = await runWithoutFirstRule(script, JSON.stringify({ root: "work/ev", limit: 5 }), cwd, out);
      assert.doesNotMatch(run.stderr, /Traceback/, label);
      const printed = run.stdout + Object.values(await filesUnder(out)).join("\n");
      const leaked = entries.filter((e) => printed.includes(e.raw));
      assert.deepEqual(leaked.map((e) => e.slot), [], `${label}: an id was printed with the first rule removed`);
      const answer = JSON.parse(run.stdout) as { status: string; boundary?: { strings_replaced_at_the_output: number } };
      assert.equal(answer.status, "partial", label);
      assert.ok((answer.boundary?.strings_replaced_at_the_output ?? 0) >= entries.length / 3, label);
    }
  });
});

test("a run of pairs does not cross a slash: eight two-digit directories one under another are eight ordinary names", async () => {
  const code = LOAD + String.raw`
for n, p in (("encrypted_survey", sys.argv[1]), ("ransom_note_scan", sys.argv[2])):
    m = load(p, n)
    path = "work/ev/" + "/".join(("aa", "bb", "cc", "dd", "ee", "ff", "00", "11")) + "/README.txt"
    assert m.shown(path, count=False) == path, n
    assert m._why(path) is None, n
    assert m._hex_pairs("aa/bb/cc/dd/ee/ff/00/11") is False
print("ok")
`;
  const run = await runPySnippet(code, [SURVEY, NOTES], null);
  assert.equal(run.code, 0, run.stderr);
  assert.equal(run.stdout.trim(), "ok");
});

test("the manifests and the skill list the pairs and groups that are printed, with their rates, and the neighbours that do not hide a run", async () => {
  const read = (rel: string) => readFile(join(ROOT, "packs", "ransomware-response", rel), "utf8");
  for (const name of ["encrypted_survey", "ransom_note_scan"]) {
    const d = (JSON.parse(await read(`tools/${name}/manifest.json`)) as { description: string }).description;
    for (const text of [
      "joined by one character that is not a letter, a digit or a slash",
      "glued to a pair",
      "7 pairs of hex digits joined by a colon, a dot or a space 100% (by a dash 29%)",
      "three groups of 3, 3 and 4 digits joined by a dash 100%",
      "also inside brackets, after an equals sign or in parentheses",
      "keyed hash of the whole path",
    ]) {
      assert.ok(d.includes(text), `${name} does not say: ${text}`);
    }
  }
  const scan = (JSON.parse(await read("tools/ransom_note_scan/manifest.json")) as { description: string }).description;
  for (const text of ["first pass", "first_pass", "sorts as a withheld name too", "is read a second time", "pieces of 256 KiB"]) {
    assert.ok(scan.includes(text), `ransom_note_scan does not say: ${text}`);
  }
  const skill = await read("skills/scope/triage-tools.md");
  for (const text of ["7 hex pairs", "deny-list", "8 or more hex pairs with one separator"]) assert.ok(skill.replace(/\s+/g, " ").includes(text), `the skill does not say: ${text}`);
});
