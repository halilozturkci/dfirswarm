/**
 * ransomware-response 1.14.5: what the fifth verification of stream_kpa_check found (AGENTS.md rule 2, round 5: five rounds in a row
 * found a P1 in the footer hypothesis, the last two a tie left to the order of the listing). Every fixture is built here with node:crypto's
 * ChaCha20, which shares nothing with the tool's pure-Python cipher.
 *
 *   - Two pairs equal in every byte the order of the pairs compares (the same key, size, ciphertext head and kept tail) were one
 *     hypothesis, tried in its first pass only with the variant that opened the member listed first. Two such members can differ in a
 *     nonce slice outside the kept bytes, and so in the counter that opened them: the place became a rule in the first pass or in the
 *     second depending on which was listed first, the rules were numbered in the order they were made, and a tie between two rules
 *     went the other way: another recipe mask, both answers complete. Pairs equal in those bytes are now one group carrying all its
 *     members and the union of their variants, a place carries every pair that gave it, and the rules are numbered and ranked by
 *     their place, never by when they were made.
 *   - A place whose second step a bound cut was still made a rule from its first step's hits (fewer members than it explains). It is
 *     now no rule, and a place is begun only when the trials it takes fit in what max_trials leaves (whole or not at all).
 *   - derived_rules was not paged by `limit` (65,536 rules: up to 100 MB of answer): it is now, with the whole list in the result file.
 */
import assert from "node:assert/strict";
import { createCipheriv, randomBytes, randomInt } from "node:crypto";
import { mkdir, mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { after, test } from "node:test";
import { PACK, tool } from "./ransomware-pack-harness.ts";
import type { Run } from "./ransomware-pack-harness.ts";

const KPA = join(PACK, "stream_kpa_check", "run.py");
const xor = (a: Buffer, b: Buffer): Buffer => Buffer.from(a.map((v, i) => v ^ b[i]!));
type Doc = Record<string, any>;

const dirs: string[] = [];
after(async () => {
  for (const d of dirs) await rm(d, { recursive: true, force: true });
});

async function sandbox(): Promise<string> {
  const cwd = await mkdtemp(join(tmpdir(), "rw-tied-pairs-"));
  dirs.push(cwd);
  await mkdir(join(cwd, "work"), { recursive: true });
  return cwd;
}

async function job(cwd: string, id: string, args: unknown): Promise<{ run: Run; out: string }> {
  const out = join(cwd, "store", "jobs", id, "out");
  await mkdir(out, { recursive: true });
  return { run: await tool(KPA, cwd, args, { JOB_ID: id, OUT: out, SECRET_OUTPUT: "1" }), out };
}

function answer(run: Run): Doc {
  assert.doesNotMatch(run.stderr, /Traceback/);
  assert.equal(run.code, 0, run.stdout.slice(0, 2000) + run.stderr);
  return JSON.parse(run.stdout) as Doc;
}

/** OpenSSL's ChaCha20 (RFC 8439 layout): the IV is the 32-bit block counter, little-endian, then the 12-byte nonce. */
function chacha(key: Buffer, nonce: Buffer, data: Buffer, counter = 0): Buffer {
  const iv = Buffer.alloc(16);
  iv.writeUInt32LE(counter, 0);
  nonce.copy(iv, 4);
  return createCipheriv("chacha20", key, iv).update(data);
}

const TWO = Buffer.alloc(2);

/** A nonce under which `key` at block 1 gives the same first two keystream bytes as `nonce` at block 0, and at block 0 does not (and
 * `nonce` at block 1 does not either): a member made with it holds the same ciphertext head and opens at counter 1 only. */
function twinNonce(key: Buffer, nonce: Buffer): Buffer | null {
  const want = chacha(key, nonce, TWO, 0);
  if (chacha(key, nonce, TWO, 1).equals(want)) return null;
  for (;;) {
    const n = randomBytes(12);
    if (chacha(key, n, TWO, 1).equals(want) && !chacha(key, n, TWO, 0).equals(want)) return n;
  }
}

/** One member: ciphertext | nonce (12) | filler (64) | key XOR mask (32). The nonce sits 96 bytes from the end, outside the 96 bytes the
 * tool keeps of a member's tail for the hypothesis, so two members that differ only in it are equal in every byte the pairs are ordered by. */
const member = (ct: Buffer, nonce: Buffer, filler: Buffer, key: Buffer, mask: Buffer): Buffer => Buffer.concat([ct, nonce, filler, xor(key, mask)]);
const exe = (size: number): Buffer => Buffer.concat([Buffer.from("MZ"), randomBytes(size - 2)]);

type Family = { files: Record<string, Buffer>; keys: Buffer[]; mask1: Buffer; mask2: Buffer };

/** N1 and its kin. Subfamily 1 (mask1): X and Y share key K, ciphertext and filler, X's nonce opens it at counter 0 and Y's at counter 1;
 * Z0.. at counter 0. Subfamily 2 (mask2): W0.. at counter 0 (with `twinW`, W0 and V share their key, ciphertext and filler the same way).
 * Both subfamilies have as many members, so the two rules tie on members explained. The dump holds K and W0's key. */
function tiedFamily(z: number, size: number, twinW = false): Family {
  for (;;) {
    const mask1 = randomBytes(32), mask2 = randomBytes(32), K = randomBytes(32), nX = randomBytes(12);
    const nY = twinNonce(K, nX);
    if (!nY) continue;
    const files: Record<string, Buffer> = {};
    const ct = chacha(K, nX, exe(size)), filler = randomBytes(64);
    files.X = member(ct, nX, filler, K, mask1);
    files.Y = member(ct, nY, filler, K, mask1);
    for (let i = 0; i < z; i++) {
      const k = randomBytes(32), n = randomBytes(12);
      files[`Z${i}`] = member(chacha(k, n, exe(size)), n, randomBytes(64), k, mask1);
    }
    const kW = randomBytes(32), nW = randomBytes(12);
    const nV = twinW ? twinNonce(kW, nW) : null;
    if (twinW && !nV) continue;
    const ctW = chacha(kW, nW, exe(size)), fillerW = randomBytes(64);
    files.W0 = member(ctW, nW, fillerW, kW, mask2);
    if (nV) files.V = member(ctW, nV, fillerW, kW, mask2);
    for (let i = 1; Object.keys(files).filter((t) => t.startsWith("W") || t === "V").length < z + 2; i++) {
      const k = randomBytes(32), n = randomBytes(12);
      files[`W${i}`] = member(chacha(k, n, exe(size)), n, randomBytes(64), k, mask2);
    }
    // No chance opening (a 2-byte crib gives one in 65,536): each dump key opens only its own members, so the counts below are exact.
    const owners: Array<[Buffer, string[]]> = [[K, ["X", "Y"]], [kW, ["W0", "V"]]];
    const opens = (k: Buffer, data: Buffer): boolean =>
      [0, 1].some((c) => chacha(k, data.subarray(data.length - 108, data.length - 96), data.subarray(0, 2), c).equals(Buffer.from("MZ")));
    const chance = Object.entries(files).some(([tag, data]) => owners.some(([k, own]) => !own.includes(tag) && opens(k, data)));
    if (!chance) return { files, keys: [K, kW], mask1, mask2 };
  }
}

const ARGS = { ciphers: ["chacha20-ietf"], counters: [0, 1], key_sources: [{ candidates: "work/v.jsonl" }],
               nonce_sources: [{ slice: "tail", length: 12, skip: 96 }] };

async function writeValues(cwd: string, keys: Buffer[]): Promise<void> {
  await writeFile(join(cwd, "work", "v.jsonl"), keys.map((k, i) => JSON.stringify({ finding_id: `K${i}`, key_hex: k.toString("hex") })).join("\n") + "\n");
}

/** An answer and its recipe with every path replaced by the member's tag, and the one label that names a file by its path (from_file)
 * left out: what must not depend on the names or the order the members were listed in. */
async function normalised(kpa: Doc, out: string, tagOf: (path: string) => string, fam: Family): Promise<Doc> {
  const recipe = kpa.recipe_file ? JSON.parse(await readFile(join(out, kpa.recipe_file.split("/").pop()), "utf8")) as Doc : null;
  if (recipe) {
    recipe.key.xor_hex = recipe.key.xor_hex === fam.mask1.toString("hex") ? "mask1" : recipe.key.xor_hex === fam.mask2.toString("hex") ? "mask2" : recipe.key.xor_hex;
    recipe.assignments = Object.entries(recipe.assignments).map(([k, v]) => [tagOf(k), v]).sort();
  }
  return {
    status: kpa.status, outcome: kpa.outcome, finding: kpa.finding, partial_reasons: kpa.partial_reasons, trials: kpa.trials, members: kpa.members,
    recipe_said: kpa.recipe, derivation: kpa.tried.derivation, not_tried: kpa.not_tried,
    derived: kpa.derived_rules.map(({ from_file: _f, ...rest }: Doc) => rest),
    rows: kpa.files.map((r: Doc) => ({ ...r, file: tagOf(r.file) })).sort((a: Doc, b: Doc) => (a.file < b.file ? -1 : 1)),
    recipe,
  };
}

const tagFrom = (path: string): string => path.split("/").pop()!.replace(/^[^_]*_/, "").replace(/\.exe\.locked$/, "");

test("N1: two members equal in every byte the pairs are ordered by and opened at different counters: both orders of the names and of `files` give one recipe", { timeout: 300_000 }, async () => {
  const fam = tiedFamily(3, 200);
  const seen: Doc[] = [];
  for (const [label, first] of [["X named first", "X"], ["Y named first", "Y"], ["X first in files", "X"], ["Y first in files", "Y"]] as const) {
    const cwd = await sandbox();
    await writeValues(cwd, fam.keys);
    const dir = join(cwd, "work", "share");
    await mkdir(dir);
    const names: Record<string, string> = { [first]: "a", [first === "X" ? "Y" : "X"]: "b" };
    const paths: Record<string, string> = {};
    for (const [tag, data] of Object.entries(fam.files)) {
      paths[tag] = `work/share/${names[tag] ?? "m"}_${tag}.exe.locked`;
      await writeFile(join(cwd, paths[tag]!), data);
    }
    const inFiles = label.endsWith("files");
    const order = [first, first === "X" ? "Y" : "X", ...Object.keys(fam.files).filter((t) => t !== "X" && t !== "Y")];
    const { run, out } = await job(cwd, "j000001", { ...ARGS, ...(inFiles ? { files: order.map((t) => paths[t]) } : { dir: "work/share" }) });
    const kpa = answer(run);
    assert.equal(kpa.status, "complete", `${label}: ${kpa.status_basis}`);
    assert.equal(kpa.outcome, "some_members_explained", `${label}: ${kpa.finding}`);
    assert.equal(kpa.recipe.explains, "5 of the 10 members that have a crib");
    const recipe = JSON.parse(await readFile(join(out, "stream-recipe.json"), "utf8")) as Doc;
    // The two rules tie on five members each; the one at the earlier place wins: the pairs of K (the first key of the dump) come first.
    assert.equal(recipe.key.xor_hex, fam.mask1.toString("hex"), `${label}: the mask of X, Y and the Zs`);
    assert.equal(recipe.made_by, "stream_kpa_check/6");
    assert.deepEqual(Object.keys(recipe.assignments).map(tagFrom).sort(), ["X", "Y", "Z0", "Z1", "Z2"]);
    assert.deepEqual(Object.keys(recipe.assignments), [...Object.keys(recipe.assignments)].sort(), "the assignments are written in the order of the paths");
    // X and Y are one group of two pairs; the rule at the tail with no skip is made from both.
    assert.equal(kpa.tried.derivation.pairs, 3);
    assert.equal(kpa.tried.derivation.pair_groups, 2);
    const first0 = kpa.derived_rules[0];
    assert.deepEqual([first0.region, first0.skip, first0.explains, first0.also_from_files], ["tail", 0, 5, 1]);
    kpa.derived_rules.forEach((d: Doc, i: number) => assert.ok(d.rule.startsWith(`derived_rules[${i}]: `), d.rule));
    seen.push(await normalised(kpa, out, (p) => tagFrom(p), fam));
  }
  for (const other of seen.slice(1)) assert.deepEqual(other, seen[0], "the answer and the recipe do not follow the names or the order of the listing");
});

test("families with tied members, under shuffled names and shuffled `files`: one outcome, one recipe, one set of rules", { timeout: 600_000 }, async () => {
  for (const [z, size, twinW] of [[1, 120, false], [2, 300, true], [3, 160, true], [2, 200, false]] as const) {
    const fam = tiedFamily(z, size, twinW);
    const tags = Object.keys(fam.files);
    const seen: Doc[] = [];
    for (let run = 0; run < 3; run++) {
      const cwd = await sandbox();
      // The order of the keys in the dump is part of the call: it is shuffled per family, not per run.
      await writeValues(cwd, z % 2 ? fam.keys : [...fam.keys].reverse());
      const dir = join(cwd, "work", "share");
      await mkdir(dir);
      const tagOfName: Record<string, string> = {};
      const paths: string[] = [];
      for (const tag of tags) {
        const name = `${randomInt(0, 2 ** 32).toString(16).padStart(8, "0")}${tag.length}${tags.indexOf(tag)}.exe.locked`;
        tagOfName[name] = tag;
        paths.push(`work/share/${name}`);
        await writeFile(join(dir, name), fam.files[tag]!);
      }
      const shuffled = [...paths].sort(() => Math.random() - 0.5);
      const { run: r, out } = await job(cwd, "j000001", { ...ARGS, ...(run === 2 ? { files: shuffled } : { dir: "work/share" }) });
      const kpa = answer(r);
      assert.notEqual(kpa.recipe_file, null, kpa.recipe_file_why);
      seen.push(await normalised(kpa, out, (p) => tagOfName[p.split("/").pop()!]!, fam));
    }
    assert.equal(seen[0]!.status, "complete", JSON.stringify(seen[0]!.partial_reasons));
    for (const other of seen.slice(1)) assert.deepEqual(other, seen[0], `z ${z}, size ${size}, twinW ${twinW}: the answer does not follow the names or the listing`);
  }
});

test("a place whose second step does not fit in max_trials is no rule, and one whose first step does not fit is not begun", { timeout: 300_000 }, async () => {
  const cwd = await sandbox();
  await mkdir(join(cwd, "work", "share"));
  const mask = randomBytes(32), nonce = randomBytes(12);
  const png = Buffer.from("89504e470d0a1a0a", "hex");
  const keys: Record<string, Buffer> = {};
  // A is the member the dump key opens; B and C start at block 1, D, E and F at block 0. The place at the tail with no skip opens D, E
  // and F in its first step (5 trials: its own variant on the 5 others) and B and C in its second (2 trials: counter 1 on B and C).
  for (const m of ["A", "B", "C", "D", "E", "F"]) {
    keys[m] = randomBytes(32);
    const ct = chacha(keys[m]!, nonce, Buffer.concat([png, randomBytes(200)]), m === "B" || m === "C" ? 1 : 0);
    await writeFile(join(cwd, "work", "share", `${m}.png.locked`), Buffer.concat([ct, xor(keys[m]!, mask)]));
  }
  await writeFile(join(cwd, "work", "key.bin"), keys.A!);
  const args = { dir: "work/share", key_sources: [{ file: "work/key.bin", offset: 0, length: 32 }], nonce_sources: [{ hex: nonce.toString("hex") }],
                 ciphers: ["chacha20-ietf"], counters: [0, 1], trailer_bytes: 32 };
  // The sources' trials: 6 members x 2 counters = 12.
  const whole = answer((await job(cwd, "j000001", { ...args, max_trials: 19 })).run);
  assert.equal(whole.outcome, "one_rule_explains_every_member", whole.finding);
  assert.equal(whole.status, "complete", whole.status_basis);
  assert.equal(whole.trials, 19);
  assert.deepEqual([whole.derived_rules.length, whole.derived_rules[0].explains], [1, 6]);
  assert.equal(whole.tried.derivation.places_not_tried_once_one_rule_explained_every_member, 64);
  for (const maxTrials of [18, 17]) {
    // The first step fits, the second does not: the place is no rule (before 1.14.5 it was one of A, D, E and F).
    const cut = answer((await job(cwd, `j00000${maxTrials}`, { ...args, max_trials: maxTrials })).run);
    assert.deepEqual(cut.derived_rules, [], `max_trials ${maxTrials}`);
    assert.equal(cut.status, "partial");
    assert.equal(cut.trials, 17);
    assert.equal(cut.tried.derivation.stopped_by, "max_trials");
    assert.equal(cut.tried.derivation.places_tried_on_every_member, 0);
    assert.equal(cut.recipe.explains, "1 of the 6 members that have a crib");
    assert.equal(cut.recipe_file, null);
    for (const row of cut.files.filter((r: Doc) => r.verdict === "no_match")) assert.match(row.note, /footer hypothesis was stopped by max_trials before every place was tried on it/);
  }
  // The first step does not fit: it is not begun, and no trial of it is made.
  const none = answer((await job(cwd, "j000016", { ...args, max_trials: 16 })).run);
  assert.deepEqual([none.trials, none.tried.derivation.trials, none.tried.derivation.stopped_by, none.status], [12, 0, "max_trials", "partial"]);
});

test("derived_rules is paged by limit, and the result file holds every rule and every member row", { timeout: 300_000 }, async () => {
  const fam = tiedFamily(3, 200);
  const cwd = await sandbox();
  await writeValues(cwd, fam.keys);
  await mkdir(join(cwd, "work", "share"));
  for (const [tag, data] of Object.entries(fam.files)) await writeFile(join(cwd, "work", "share", `${tag}.exe.locked`), data);
  const whole = answer((await job(cwd, "j000001", { ...ARGS, dir: "work/share" })).run);
  assert.ok(whole.derived_rules.length > 2, `${whole.derived_rules.length} rules`);
  assert.equal(whole.truncated, false);
  assert.equal("result_file" in whole, false, "nothing is cut, so no result file is written");
  const { run, out } = await job(cwd, "j000002", { ...ARGS, dir: "work/share", limit: 2 });
  const paged = answer(run);
  assert.equal(paged.derived_rules.length, 2);
  assert.equal(paged.derived_rules_not_listed, whole.derived_rules.length - 2);
  assert.equal(paged.files.length, 2);
  assert.equal(paged.files_not_listed, 8);
  assert.equal(paged.truncated, true);
  assert.equal(paged.status, "complete", paged.status_basis);
  assert.equal(paged.result_file, "store/jobs/j000002/out/stream-kpa-check.json");
  const kept = JSON.parse(await readFile(join(out, "stream-kpa-check.json"), "utf8")) as Doc;
  assert.equal(kept.parser, "stream_kpa_check/6");
  assert.deepEqual(kept.derived_rules, whole.derived_rules);
  assert.deepEqual(kept.files, whole.files);
  const text = await readFile(join(out, "stream-kpa-check.json"), "utf8");
  for (const secret of [fam.mask1, fam.mask2, ...fam.keys]) assert.equal(text.includes(secret.toString("hex")), false, "no key or mask byte in the result file");
});
