/**
 * ransom_note_scan and encrypted_survey: the order of a listing, the values a note holds, and the clock inside a note.
 *
 * - a name withheld because the note beneath it holds its value is withheld before the walk is ordered: it sorts as every withheld name does
 *   (the notes are read in a first pass), and the rank of its text among its siblings does not show;
 * - names that print alike come in an order that depends on the whole path: the same withheld names under two parents have two unrelated
 *   orders;
 * - the clock is looked at between pieces of a note, not only when a match arrives: a note with no match at all (megabytes of an identifier label and white space) is
 *   cut at the limit, and the pieces find exactly the matches one search of the whole text finds.
 *
 * Every identifier is drawn at test time from pieces, never a literal that looks like a real secret.
 */
import assert from "node:assert/strict";
import { randomInt } from "node:crypto";
import { mkdir, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { test } from "node:test";
import { runPySnippet, withCwd } from "./tool-library-harness.ts";
import { LOAD, NOTES, SURVEY, body, runPatched, tool } from "./ransomware-pack-harness.ts";

const LOWER = "abcdefghijklmnopqrstuvwxyz";
const HEX = "0123456789abcdef";
const pick = (alphabet: string, n: number): string => Array.from({ length: n }, () => alphabet[randomInt(alphabet.length)]).join("");
const hexId = (n = 16): string => {
  for (;;) {
    const s = pick(HEX, n);
    if (/[a-f]/.test(s) && /\d/.test(s)) return s;
  }
};
const NOTE = "Your files are encrypted. To decrypt your files, pay in bitcoin and restore your files.\n";

type Row = Record<string, unknown>;

/** `count` distinct lower-case words of `length` letters: ordinary names to the first rule (a word, 15 letters or fewer). */
function words(count: number, length: number, taken = new Set<string>()): string[] {
  const out: string[] = [];
  while (out.length < count) {
    const w = pick(LOWER, length);
    if (!taken.has(w)) {
      taken.add(w);
      out.push(w);
    }
  }
  return out;
}

const rawSorted = (names: string[]): string[] => [...names].sort();
const sameOrder = (a: string[], b: string[]): boolean => a.length === b.length && a.every((x, i) => x === b[i]);

// ---- a name withheld for a value the note holds ---------------------------------------------------------------------------------------------

/** 30 visible directories, and 12 directories named by a word that the note beneath them gives as "your personal id"; the size of a note says whose it is. */
async function valueTree(root: string, nameLength: number): Promise<{ bySize: Map<number, { kind: string; name: string }>; hidden: string[] }> {
  const taken = new Set<string>();
  const visible = words(30, nameLength, taken);
  const hidden = words(12, nameLength + 2, taken);
  const bySize = new Map<number, { kind: string; name: string }>();
  let k = 0;
  for (const name of visible) {
    await mkdir(join(root, name), { recursive: true });
    const text = NOTE + "x".repeat(k++);
    await writeFile(join(root, name, "README.txt"), text);
    bySize.set(Buffer.byteLength(text), { kind: "visible", name });
  }
  for (const name of hidden) {
    await mkdir(join(root, name), { recursive: true });
    const text = `${NOTE}your personal id: ${name}\n` + "y".repeat(k++);
    await writeFile(join(root, name, "README.txt"), text);
    bySize.set(Buffer.byteLength(text), { kind: "hidden", name });
  }
  return { bySize, hidden };
}

test("ransom_note_scan: a directory named by a value its note holds is not ordered by its text: the withheld ones come together, in an order drawn afresh", async () => {
  await withCwd(async (cwd) => {
    const { bySize, hidden } = await valueTree(join(cwd, "work", "ev"), 6);
    const rawHidden = rawSorted(hidden);
    let different = 0;
    for (let run = 0; run < 3; run++) {
      const answer = body<{ notes: { bytes: number; file: string }[]; first_pass: string }>(await tool(NOTES, cwd, { root: "work/ev", limit: 100 }));
      assert.equal(answer.notes.length, 42);
      assert.match(answer.first_pass, /^complete/);
      const order = answer.notes.map((n) => bySize.get(n.bytes) as { kind: string; name: string });
      const marked = answer.notes.map((n) => n.file.includes("withheld"));
      assert.deepEqual(marked, order.map((o) => o.kind === "hidden"), "a name was withheld in a row but not for its value, or the other way");
      // the withheld rows sit together (they sort as the marker), not between the visible neighbours their text would put them by
      const positions = order.flatMap((o, i) => (o.kind === "hidden" ? [i] : []));
      assert.deepEqual(positions, positions.map((_, i) => positions[0] + i), "the withheld rows are spread by their text");
      const names = order.filter((o) => o.kind === "hidden").map((o) => o.name);
      if (!sameOrder(names, rawHidden)) different++;
      // the visible ones keep the readable order
      const visibleNames = order.filter((o) => o.kind === "visible").map((o) => o.name);
      assert.ok(sameOrder(visibleNames, rawSorted(visibleNames)));
    }
    assert.equal(different, 3, "the withheld rows come in the raw order of their names");
  });
});

test("ransom_note_scan: a note file named by its own value is ordered as a withheld name too", async () => {
  await withCwd(async (cwd) => {
    const ev = join(cwd, "work", "ev");
    await mkdir(ev, { recursive: true });
    const taken = new Set<string>();
    const visible = words(25, 6, taken);
    const hidden = words(12, 9, taken);
    const bySize = new Map<number, { kind: string; name: string }>();
    let k = 0;
    for (const w of visible) {
      const text = NOTE + "x".repeat(k++);
      await writeFile(join(ev, `README_${w}.txt`), text);
      bySize.set(Buffer.byteLength(text), { kind: "visible", name: w });
    }
    for (const w of hidden) {
      const text = `${NOTE}your personal id: ${w}\n` + "y".repeat(k++);
      await writeFile(join(ev, `README_${w}.txt`), text);
      bySize.set(Buffer.byteLength(text), { kind: "hidden", name: w });
    }
    const answer = body<{ notes: { bytes: number; file: string }[] }>(await tool(NOTES, cwd, { root: "work/ev", limit: 100 }));
    const order = answer.notes.map((n) => bySize.get(n.bytes) as { kind: string; name: string });
    assert.deepEqual(answer.notes.map((n) => n.file.includes("withheld")), order.map((o) => o.kind === "hidden"));
    const positions = order.flatMap((o, i) => (o.kind === "hidden" ? [i] : []));
    assert.deepEqual(positions, positions.map((_, i) => positions[0] + i), "the withheld file names are spread by their text");
    assert.ok(!sameOrder(order.filter((o) => o.kind === "hidden").map((o) => o.name), rawSorted(hidden)), "in raw order");
  });
});

test("ransom_note_scan: when the first pass cannot finish, every name of 8 characters or more is ordered like a withheld one, and the answer says so", async () => {
  await withCwd(async (cwd) => {
    const ev = join(cwd, "work", "ev");
    const { bySize } = await valueTree(ev, 8);
    const out = join(cwd, "out");
    await mkdir(out);
    const run = await runPatched(NOTES, "m.values_pass = lambda *a, **k: None", JSON.stringify({ root: "work/ev", limit: 100 }), cwd, out);
    assert.equal(run.code, 0, run.stderr + run.stdout);
    const answer = JSON.parse(run.stdout) as { notes: { bytes: number }[]; first_pass: string; status: string; status_basis: string };
    assert.match(answer.first_pass, /^stopped by its share of the time limit/);
    assert.equal(answer.status, "complete");
    assert.match(answer.status_basis, /first pass stopped by its share/, "a caller that reads status_basis alone sees it");
    const names = answer.notes.map((n) => (bySize.get(n.bytes) as { name: string }).name);
    assert.equal(names.length, 42);
    assert.ok(!sameOrder(names, rawSorted(names)), "the names come in raw order although the values were not known");
    assert.ok(names.slice(0, 30).some((n, i) => n !== rawSorted(names)[i]));
  });
});

const PASS = LOAD + String.raw`
import time
m = load(sys.argv[1])
root = sys.argv[2]
matched = m.values_pass(root, set(), 200000)
rel = sorted(os.path.relpath(p, root) for p in matched)
m.STOP["deadline"] = time.monotonic() - 1
expired = m.values_pass(root, set(), 200000)
print(json.dumps({"matched": rel, "expired": expired}))
`;

test("values_pass names the directories and files whose name holds a value of the note beneath, and is None when the clock ran out", async () => {
  await withCwd(async (cwd) => {
    const root = join(cwd, "work", "ev");
    await mkdir(join(root, "plainname", "inner"), { recursive: true });
    await mkdir(join(root, "carriedvalue", "deeper"), { recursive: true });
    await mkdir(join(root, "other"), { recursive: true });
    await writeFile(join(root, "plainname", "README.txt"), NOTE);
    await writeFile(join(root, "carriedvalue", "deeper", "README.txt"), `${NOTE}your personal id: carriedvalue\n`);
    await writeFile(join(root, "other", "README_notecarried.txt"), `${NOTE}victim id: notecarried\n`);
    const run = await runPySnippet(PASS, [NOTES, root], null);
    assert.equal(run.code, 0, run.stderr);
    const out = JSON.parse(run.stdout) as { matched: string[]; expired: unknown };
    assert.deepEqual(out.matched, ["carriedvalue", "other/README_notecarried.txt"]);
    assert.equal(out.expired, null);
  });
});

test("ransom_note_scan: the first pass lists nothing and counts nothing twice (one failed directory is one exception, one visit each)", async () => {
  await withCwd(async (cwd) => {
    const ev = join(cwd, "work", "ev");
    for (const d of ["a1", "denied", "b2/inner"]) await mkdir(join(ev, d), { recursive: true });
    await writeFile(join(ev, "a1", "README.txt"), NOTE);
    await writeFile(join(ev, "b2", "inner", "README.txt"), NOTE);
    await writeFile(join(ev, "link_target"), "x");
    const patch = "_real = os.scandir\ndef _scandir(p):\n    if str(p).endswith('denied'):\n        raise PermissionError(13, 'Permission denied')\n    return _real(p)\nos.scandir = _scandir";
    const out = join(cwd, "out");
    await mkdir(out);
    const run = await runPatched(NOTES, patch, JSON.stringify({ root: "work/ev" }), cwd, out);
    assert.equal(run.code, 0, run.stderr + run.stdout);
    const answer = JSON.parse(run.stdout) as { coverage: Record<string, number>; exceptions: Row[]; candidate_count: number; paths_withheld: number };
    assert.equal(answer.coverage.directories_failed, 1);
    assert.equal(answer.exceptions.length, 1);
    assert.equal(answer.coverage.directories_visited, 4); // root, a1, b2, b2/inner; denied is not listed
    assert.equal(answer.candidate_count, 2);
    assert.equal(answer.paths_withheld, 0);
  });
});

// ---- the same withheld names under two parents -----------------------------------------------------------------------------------------------

/** Two parents that hold the same 12 withheld directory names; a note's size says which parent and which name. */
async function twoParents(root: string): Promise<{ bySize: Map<number, { parent: string; name: string }>; names: string[] }> {
  const names = new Set<string>();
  while (names.size < 12) names.add(hexId());
  const list = [...names];
  const bySize = new Map<number, { parent: string; name: string }>();
  let k = 0;
  for (const parent of ["A", "B"]) {
    for (const name of list) {
      await mkdir(join(root, parent, name), { recursive: true });
      const text = NOTE + "x".repeat(k++);
      await writeFile(join(root, parent, name, "README.txt"), text);
      bySize.set(Buffer.byteLength(text), { parent, name });
    }
  }
  return { bySize, names: list };
}

test("the same withheld names under two parents come in two unrelated orders, in both tools", async () => {
  await withCwd(async (cwd) => {
    const { bySize } = await twoParents(join(cwd, "work", "ev"));
    for (const [script, key] of [[NOTES, "notes"], [SURVEY, "note_name_candidates"]] as const) {
      let identical = 0;
      for (let run = 0; run < 3; run++) {
        const answer = body<Record<string, { bytes: number }[]>>(await tool(script, cwd, { root: "work/ev", limit: 100 }));
        const rows = answer[key].map((r) => bySize.get(r.bytes) as { parent: string; name: string });
        assert.equal(rows.length, 24);
        const under = (p: string) => rows.filter((r) => r.parent === p).map((r) => r.name);
        if (sameOrder(under("A"), under("B"))) identical++;
      }
      // chance of two equal orders of 12 names: 1 in 479,001,600 per run
      assert.equal(identical, 0, `${script}: two parents with the same withheld names list them in the same order`);
    }
  });
});

// ---- the clock inside a note ----------------------------------------------------------------------------------------------------------------

const PIECES = LOAD + String.raw`
import random
rnd = random.Random(int(sys.argv[2]))
m = load(sys.argv[1])
HEX, B32, ALNUM = "0123456789abcdef", "abcdefghijklmnopqrstuvwxyz234567", "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
def pick(a, n): return "".join(rnd.choice(a) for _ in range(n))
makers = [
    lambda: pick(ALNUM, rnd.randint(1, 12)) + "@" + pick(ALNUM, rnd.randint(1, 9)) + "." + pick("abcdef.-", rnd.randint(2, 20)),
    lambda: pick(ALNUM + "._+-", rnd.randint(1, 70)) + "@" + pick(ALNUM + "-", rnd.randint(1, 70)) + "." + pick(ALNUM + ".-", rnd.randint(2, 260)),
    lambda: pick(B32, 16) + ".onion", lambda: pick(B32, 56) + ".onion", lambda: pick(B32, 15) + ".onion",
    lambda: "https://" + pick(ALNUM + "./-", rnd.randint(6, 90)), lambda: "1" + pick("123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz", rnd.randint(25, 34)),
    lambda: "bc1" + pick("qpzry9x8gf2tvdw0s3jn54khce6mua7l", rnd.randint(11, 71)), lambda: "0x" + pick(HEX, 40), lambda: pick(HEX.upper(), 76),
    lambda: "4" + rnd.choice("0123456789AB") + pick("123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz", 93),
    lambda: "your personal id: " + pick(ALNUM + "-_", rnd.randint(7, 40)), lambda: "victim id" + " " * rnd.randint(0, 9) + pick(ALNUM, rnd.randint(8, 20)),
    lambda: pick(ALNUM + " ._-@", rnd.randint(1, 30)), lambda: "é" * rnd.randint(1, 5),
]
glue = ["", " ", "\n", "\t", ".", "-", "@", "  "]
cases = bad = 0
for _ in range(120):
    text = "".join(rnd.choice(makers)() + rnd.choice(glue) for _ in range(rnd.randint(1, 40)))
    m.CHUNK = rnd.choice((1, 7, 16, 64, 100, 257, 1000))
    for kind, pattern, group in m.KINDS:
        cases += 1
        whole = [(x.start(), x.end(), x.group(group)) for x in pattern.finditer(text)]
        pieces = [(x.start(), x.end(), x.group(group)) for x in m.matches(pattern, text, kind)]
        if whole != pieces:
            bad += 1
print(json.dumps({"cases": cases, "different": bad}))
`;

test("matching a note piece by piece finds exactly what one search of the whole text finds, at any piece size (960 cases, count only)", async () => {
  const run = await runPySnippet(PIECES, [NOTES, String(randomInt(1, 1e9))], null);
  assert.equal(run.code, 0, run.stderr);
  assert.deepEqual(JSON.parse(run.stdout), { cases: 960, different: 0 });
});

test("ransom_note_scan: the clock stops the matching of a 16 MiB note that holds no match at all, and the note is counted as partly scanned", async () => {
  await withCwd(async (cwd) => {
    const ev = join(cwd, "work", "ev");
    await mkdir(ev, { recursive: true });
    // No indicator in it, and the label of an identifier over and over: one search of it takes seconds and returns nothing (a note of "a.a.a." took
    // as long before the onion pattern was gated on its literal).
    const unit = "identifier" + " ".repeat(64) + "!";
    await writeFile(join(ev, "README.txt"), unit.repeat(Math.ceil((16 << 20) / unit.length)).slice(0, 16 << 20));
    const started = Date.now();
    const answer = body<{ status: string; status_basis: string; coverage: Record<string, number>; notes: Row[]; indicator_counts: Record<string, unknown> }>(
      await tool(NOTES, cwd, { root: "work/ev", max_size: 16 << 20, max_seconds: 2 }),
    );
    const seconds = (Date.now() - started) / 1000;
    assert.equal(answer.status, "partial");
    assert.match(answer.status_basis, /time limit/);
    if (answer.notes.length > 0) {
      // the note was reached, and the clock stopped the matching inside it
      assert.equal(answer.coverage.notes_partly_scanned, 1);
      assert.match(String(answer.notes[0].scan_stopped), /time limit/);
      assert.match(answer.status_basis, /partly scanned/);
    } // (on a CPU so starved that the limit runs out before the note is begun, the stop is the walk's: also partial, with the same basis)
    assert.ok(seconds < 9, `the run took ${seconds} s past a 2 s limit`);
  });
});

test("ransom_note_scan: with write_values and a limit, a note of many e-mail addresses stops at the limit and the values file holds whole rows", async () => {
  await withCwd(async (cwd) => {
    const ev = join(cwd, "work", "ev");
    await mkdir(ev, { recursive: true });
    await writeFile(join(ev, "README.txt"), "x@y.zz ".repeat(600_000));
    const out = join(cwd, "out");
    await mkdir(out);
    const run = await tool(NOTES, cwd, { root: "work/ev", max_size: 8_000_000, max_seconds: 2, write_values: true }, { JOB_ID: "j000001", OUT: out, SECRET_OUTPUT: "1" });
    const answer = body<{ status: string; coverage: Record<string, number>; secret_values: { written: number } }>(run);
    assert.equal(answer.status, "partial");
    assert.equal(answer.coverage.notes_partly_scanned, 1);
    assert.ok(answer.secret_values.written > 0 && answer.secret_values.written < 600_000);
  });
});
