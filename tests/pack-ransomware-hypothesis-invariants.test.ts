/**
 * ransomware-response 1.14.6: what the sixth verification of stream_kpa_check found (AGENTS.md rule 2, round 6: six rounds in a row
 * found a P1 in the footer hypothesis). The block is now reviewed as one unit and holds two invariants, stated at the top of its comment
 * in run.py; each has its regression here. Every fixture is built with node:crypto's ChaCha20 or a plain XOR, which share nothing with
 * the tool's pure-Python ciphers.
 *
 *   I1 - a place whose rule explains every member was found in the first pass, and a bound stopped the second pass (the places before it,
 *        tried with every variant) before it had tried them all: the answer said complete with stopped_by null, and one trial less of
 *        max_trials changed the recipe's mask while both answers said complete. The hypothesis is now complete only when every place
 *        before the chosen rule's is settled (read from what was tried, not from how the loops ended); a bound that stops it before
 *        that makes the answer partial, with stopped_by.
 *   I2 - every rule held the members it explains, and every member every match of every rule: 4,160 rules of 4,999 members each took
 *        3.5 GB and was killed in a 2 GB container, with no JSON. One memory budget now holds every structure of the hypothesis that
 *        grows with rules x members, pairs x places or kept matches; a rule keeps a count, a member the matches its row prints, and the
 *        listing of places stops before the budget would be passed (partial, stopped_by max_memory).
 */
import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { createCipheriv, randomBytes, randomInt } from "node:crypto";
import { mkdir, mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { after, test } from "node:test";
import { PYTHON3 } from "./host-gates.ts";
import { PACK } from "./ransomware-pack-harness.ts";
import type { Run } from "./ransomware-pack-harness.ts";

const KPA = join(PACK, "stream_kpa_check", "run.py");
const BUDGET = 512 * 1024 * 1024;           // HYPOTHESIS_MEMORY, as the manifest states it
const xor = (a: Buffer, b: Buffer): Buffer => Buffer.from(a.map((v, i) => v ^ b[i]!));
type Doc = Record<string, any>;

const dirs: string[] = [];
after(async () => {
  for (const d of dirs) await rm(d, { recursive: true, force: true });
});

async function sandbox(): Promise<string> {
  const cwd = await mkdtemp(join(tmpdir(), "rw-hyp-inv-"));
  dirs.push(cwd);
  await mkdir(join(cwd, "work", "share"), { recursive: true });
  return cwd;
}

/** The tool run as a job (secret output, so the recipe is written) from a Python parent that reports the child's exit and its peak
 * resident memory in bytes (getrusage of the child: bytes on macOS, KiB on Linux). */
const MEASURED = String.raw`
import resource, subprocess, sys
with open(sys.argv[2], "rb") as fh:
    done = subprocess.run([sys.executable, sys.argv[1]], stdin=fh, capture_output=True)
peak = resource.getrusage(resource.RUSAGE_CHILDREN).ru_maxrss * (1 if sys.platform == "darwin" else 1024)
sys.stderr.write(done.stderr.decode("utf-8", "replace"))
sys.stdout.write("%d %d\n" % (done.returncode, peak))
sys.stdout.write(done.stdout.decode("utf-8", "replace"))
`;

type Measured = { code: number; peak: number; doc: Doc; stderr: string; out: string };

async function job(cwd: string, id: string, args: unknown): Promise<Measured> {
  const out = join(cwd, "store", "jobs", id, "out");
  await mkdir(out, { recursive: true });
  const input = join(cwd, `${id}.args.json`);
  await writeFile(input, JSON.stringify(args));
  const run = await new Promise<Run>((resolve, reject) => {
    const child = spawn(PYTHON3, ["-c", MEASURED, KPA, input], { cwd, env: { ...process.env, AGENT_ID: "s1", JOB_ID: id, OUT: out, SECRET_OUTPUT: "1" } });
    const so: Buffer[] = [], se: Buffer[] = [];
    child.stdout.on("data", (c: Buffer) => so.push(c));
    child.stderr.on("data", (c: Buffer) => se.push(c));
    child.on("error", reject);
    child.on("close", (code) => resolve({ code, stdout: Buffer.concat(so).toString("utf8"), stderr: Buffer.concat(se).toString("utf8") }));
  });
  assert.equal(run.code, 0, run.stderr);
  const [head, ...rest] = run.stdout.split("\n");
  const [code, peak] = head!.split(" ").map(Number);
  assert.doesNotMatch(run.stderr, /Traceback/);
  assert.equal(code, 0, rest.join("\n").slice(0, 2000) + run.stderr);
  return { code: code!, peak: peak!, doc: JSON.parse(rest.join("\n")) as Doc, stderr: run.stderr, out };
}

async function recipeOf(m: Measured): Promise<Doc | null> {
  return m.doc.recipe_file ? JSON.parse(await readFile(join(m.out, m.doc.recipe_file.split("/").pop()), "utf8")) as Doc : null;
}

/** OpenSSL's ChaCha20 (RFC 8439 layout): the IV is the 32-bit block counter, little-endian, then the 12-byte nonce. */
function chacha(key: Buffer, nonce: Buffer, data: Buffer, counter = 0): Buffer {
  const iv = Buffer.alloc(16);
  iv.writeUInt32LE(counter, 0);
  nonce.copy(iv, 4);
  return createCipheriv("chacha20", key, iv).update(data);
}

const exe = (size: number): Buffer => Buffer.concat([Buffer.from("MZ"), randomBytes(size - 2)]);

type Values = { keys: Buffer[]; nonces: Buffer[] };

async function writeValues(cwd: string, v: Values): Promise<void> {
  const rows = [...v.keys.map((k, i) => ({ finding_id: `K${i}`, key_hex: k.toString("hex") })),
                ...v.nonces.map((n, i) => ({ finding_id: `N${i}`, layouts: { ietf: { nonce_hex: n.toString("hex") } } }))];
  await writeFile(join(cwd, "work", "v.jsonl"), rows.map((r) => JSON.stringify(r)).join("\n") + "\n");
}

const CANDIDATES = { key_sources: [{ candidates: "work/v.jsonl" }], nonce_sources: [{ candidates: "work/v.jsonl" }] };

test("I1: a bound that stops the second pass before every place before the chosen rule's is settled leaves the answer partial; no smaller max_trials gives another recipe as complete", { timeout: 600_000 }, async () => {
  // Two members, each ciphertext | K_i XOR mask | 40 bytes of junk: the true place is the tail at skip 40, so places 0 to 39 come
  // before it. The first pass screens them with the one variant that opened A (chacha20-ietf, n0, counter 0) and finds the rule at 40;
  // the second pass then tries 0 to 39 with every nonce and counter (an earlier place could tie by chance with a 2-byte crib and be
  // preferred). The dump holds A's key and 32 nonces; counters 0 to 7.
  const mask = randomBytes(32), nonces = Array.from({ length: 32 }, () => randomBytes(12));
  const cwd = await sandbox();
  const keys = [randomBytes(32), randomBytes(32)];
  for (const [i, k] of keys.entries()) {
    await writeFile(join(cwd, "work", "share", `m${i}.exe.locked`), Buffer.concat([chacha(k, nonces[0]!, exe(200)), xor(k, mask), randomBytes(40)]));
  }
  await writeValues(cwd, { keys: [keys[0]!], nonces });
  const args = { dir: "work/share", ...CANDIDATES, ciphers: ["chacha20-ietf"], counters: [0, 1, 2, 3, 4, 5, 6, 7], trailer_bytes: 72, max_trials: 5_000_000 };
  const whole = await job(cwd, "j000001", args);
  const w = whole.doc;
  assert.equal(w.status, "complete", w.status_basis);
  assert.equal(w.outcome, "one_rule_explains_every_member");
  const wd = w.tried.derivation;
  assert.equal(wd.stopped_by, null);
  assert.equal(wd.places, 65);
  // The chosen rule is the first derived rule (the earliest place that explains both); the count after it is of the places after its
  // own that were not tried with every variant (the one at skip 40, settled in the first pass, is not among them when it is later).
  const chosen = w.derived_rules[0];
  assert.equal(chosen.explains, 2);
  assert.ok(chosen.skip <= 40, JSON.stringify(chosen));
  // Settled: every place up to the chosen one, and the one at skip 40 when the first pass found it before a chance tie was found earlier.
  assert.ok([chosen.skip + 1, chosen.skip + 2].includes(wd.places_tried_on_every_member), JSON.stringify(wd));
  assert.equal(wd.places_not_tried_once_one_rule_explained_every_member, wd.places - wd.places_tried_on_every_member);
  const recipe = await recipeOf(whole);
  assert.ok(recipe);
  if (chosen.skip === 40) assert.equal(recipe.key.xor_hex, mask.toString("hex"));

  // One trial less: the last place of the second pass is not begun. Before 1.14.6 this answer said complete, stopped_by null.
  const sources = w.trials - wd.trials;
  const cuts = [w.trials - 1, w.trials - 100, w.trials - 1000, sources + Math.floor(wd.trials / 2), sources + 300].filter((c) => c > sources && c < w.trials);
  assert.ok(cuts.length >= 2, `${cuts}`);
  for (const [n, cut] of cuts.entries()) {
    const m = await job(cwd, `j00010${n}`, { ...args, max_trials: cut });
    const a = m.doc;
    assert.equal(a.status, "partial", `max_trials ${cut}: ${a.status_basis}`);
    assert.equal(a.complete, false);
    assert.equal(a.tried.derivation.stopped_by, "max_trials", `max_trials ${cut}`);
    assert.equal(a.tried.derivation.places_not_tried_once_one_rule_explained_every_member, 0, "no rule ended the hypothesis");
    assert.ok(a.partial_reasons.some((r: string) => /^max_trials \(\d+\) was reached while the footer hypothesis was being tried/.test(r)), a.status_basis);
    if (a.outcome === "one_rule_explains_every_member") {
      assert.ok(a.partial_reasons.some((r: string) => /A rule explains every member, and \d+ places before its place were not tried/.test(r)), a.status_basis);
    }
    // Never another recipe said complete: a complete answer (none here) would have to carry the uncut recipe.
    if ((a.status as string) === "complete") assert.deepEqual(await recipeOf(m), recipe);
  }
});

test("I1: once a rule explains every member and every place before it is settled, the answer is complete, and only the places after it are counted", { timeout: 300_000 }, async () => {
  // Six members, one counter and nonce: the true place is the tail at skip 0, found in the first pass; nothing comes before it.
  const cwd = await sandbox();
  const mask = randomBytes(32), nonce = randomBytes(12);
  const keys = Array.from({ length: 6 }, () => randomBytes(32));
  for (const [i, k] of keys.entries()) await writeFile(join(cwd, "work", "share", `m${i}.exe.locked`), Buffer.concat([chacha(k, nonce, exe(150)), xor(k, mask)]));
  await writeValues(cwd, { keys: [keys[3]!], nonces: [nonce] });
  const a = (await job(cwd, "j000001", { dir: "work/share", ...CANDIDATES, ciphers: ["chacha20-ietf"], counters: [0], trailer_bytes: 32 })).doc;
  assert.equal(a.status, "complete", a.status_basis);
  assert.equal(a.outcome, "one_rule_explains_every_member");
  assert.deepEqual([a.derived_rules[0].skip, a.derived_rules[0].explains], [0, 6]);
  assert.deepEqual([a.tried.derivation.places_tried_on_every_member, a.tried.derivation.places_not_tried_once_one_rule_explained_every_member], [1, 64]);
  assert.equal(a.tried.derivation.memory_budget_bytes, BUDGET);
  assert.ok(a.tried.derivation.memory_counted_at_most_bytes > 0 && a.tried.derivation.memory_counted_at_most_bytes <= BUDGET);
});

/** M1 of the verification: N-1 members whose first two bytes XOR every one of 64 dump keys give 00 00 (a 2-byte crib given in magics,
 * the xor cipher), and a decoy no key opens: every key opens every member, every place of the hypothesis is a rule of N-1 members, and no
 * rule explains the decoy, so every place is tried. `tied`: the N-1 members are byte-identical (64 groups of N-1 pairs); otherwise their
 * heads differ (one group per pair) while their tails are all zero, so each place carries N-1 groups. */
async function rulesTimesMembers(cwd: string, n: number, tied: boolean): Promise<void> {
  const p = Buffer.from([0x5a, 0xa5]);
  const same = Buffer.concat([p, randomBytes(162), Buffer.alloc(96)]);
  for (let i = 0; i < n - 1; i++) {
    await writeFile(join(cwd, "work", "share", `m${String(i).padStart(5, "0")}.zz.locked`), tied ? same : Buffer.concat([p, randomBytes(162), Buffer.alloc(96)]));
  }
  await writeFile(join(cwd, "work", "share", "zdecoy.zz.locked"), Buffer.concat([Buffer.from([0, 1]), randomBytes(260)]));
  await writeFile(join(cwd, "work", "v.jsonl"), Array.from({ length: 64 }, (_v, i) => JSON.stringify({ finding_id: `F${i}`, key_hex: Buffer.concat([p, randomBytes(30)]).toString("hex") })).join("\n") + "\n");
}

const M1 = { dir: "work/share", max_files: 5000, magics: { zz: "0000" }, ciphers: ["xor"], key_sources: [{ candidates: "work/v.jsonl" }],
             max_trials: 5_000_000, max_seconds: 300, limit: 20 };

test("I2: 4,160 rules of 2,999 members each are held as counts: complete, JSON, the matches each row lists and their count, inside the budget", { timeout: 600_000 }, async () => {
  const cwd = await sandbox();
  await rulesTimesMembers(cwd, 3000, true);
  const m = await job(cwd, "j000001", M1);
  const a = m.doc;
  assert.equal(a.status, "complete", a.status_basis);
  assert.equal(a.outcome, "some_members_explained");
  const d = a.tried.derivation;
  assert.deepEqual([d.pairs, d.pair_groups, d.places, d.places_not_listed, d.places_tried_on_every_member, d.stopped_by], [64 * 2999, 64, 4160, 0, 4160, null]);
  assert.ok(d.memory_counted_at_most_bytes <= d.memory_budget_bytes);
  assert.equal(a.derived_rules_not_listed, 4160 - 20);
  assert.ok(a.derived_rules.every((r: Doc) => r.explains === 2999 && r.of === 3000));
  // Every member but the decoy: 64 matches of the dump's keys and one of each of the 4,160 rules; the row lists 6, in the order of
  // the rules (the call's sources first) and counts the others.
  const row = a.files.find((r: Doc) => r.file.endsWith("m00000.zz.locked"));
  assert.equal(row.verdict, "match");
  assert.equal(row.matches.length, 6);
  assert.equal(row.matches_not_listed, 64 + 4160 - 6);
  assert.ok(row.matches.every((x: Doc) => x.key.startsWith("key_sources[0]")), JSON.stringify(row.matches));
  // The tool as a whole stays inside the hypothesis's budget here (4.2 GB of tuples before 1.14.6 at N 5000; 900 MB at N 1000).
  assert.ok(m.peak < BUDGET, `peak resident memory ${m.peak} bytes`);
});

test("I2: when the listing would pass the memory budget it stops: JSON, partial, stopped_by max_memory, every place listed tried, inside the budget", { timeout: 600_000 }, async () => {
  const cwd = await sandbox();
  await rulesTimesMembers(cwd, 5000, false);
  const m = await job(cwd, "j000001", M1);
  const a = m.doc;
  const d = a.tried.derivation;
  assert.equal(a.status, "partial", a.status_basis);
  assert.equal(d.stopped_by, "max_memory");
  assert.equal(d.pairs, 64 * 4999);
  assert.ok(d.places > 0 && d.places < 4160, `${d.places} places listed`);
  assert.ok(d.places_not_listed > 0);
  assert.equal(d.places_tried_on_every_member, d.places, "every place listed is tried");
  assert.ok(d.memory_counted_at_most_bytes <= BUDGET && d.memory_counted_at_most_bytes > BUDGET * 0.9, `${d.memory_counted_at_most_bytes}`);
  assert.ok(a.partial_reasons.some((r: string) => /memory budget \(512 MiB/.test(r)), a.status_basis);
  assert.ok(a.not_tried.some((l: string) => /^the footer hypothesis, in part/.test(l)));
  // The decoy (no rule opens it) is past the rows shown: the result file holds every row, and its row says the hypothesis was cut.
  const kept = JSON.parse(await readFile(join(m.out, a.result_file.split("/").pop()), "utf8")) as Doc;
  const decoy = kept.files.find((r: Doc) => r.file.endsWith("zdecoy.zz.locked"));
  assert.equal(decoy?.verdict, "no_match");
  assert.match(decoy?.note ?? "", /stopped by max_memory before every place was tried on it/);
  assert.ok(m.peak < BUDGET, `peak resident memory ${m.peak} bytes`);
});

/** A family with ties and chance (a 2-byte crib, several nonces and counters, byte-identical clones, a member of another rule, a decoy)
 * whose rule sits at a skip past places that chance can open. */
function chanceFamily(): { files: Record<string, Buffer>; values: Values; mask: Buffer } {
  const mask = randomBytes(32), nonces = Array.from({ length: 4 }, () => randomBytes(12)), skip = randomInt(3, 12);
  const files: Record<string, Buffer> = {};
  const keys: Buffer[] = [];
  const n = randomInt(4, 7);
  for (let i = 0; i < n; i++) {
    const k = randomBytes(32);
    keys.push(k);
    files[`M${i}`] = Buffer.concat([chacha(k, nonces[i % 4]!, exe(randomInt(90, 140)), i % 3), xor(k, mask), randomBytes(skip)]);
  }
  files.C0 = files.M0!;
  files.C1 = files.M0!;
  const other = randomBytes(32);
  files.O = Buffer.concat([chacha(other, nonces[1]!, exe(120), 1), xor(other, randomBytes(32)), randomBytes(skip)]);
  files.D = randomBytes(150);
  return { files, values: { keys: [keys[0]!, keys[1]!, other, randomBytes(32)], nonces }, mask };
}

async function normalised(m: Measured, tagOf: (path: string) => string, mask: Buffer): Promise<Doc> {
  const a = m.doc;
  const recipe = await recipeOf(m);
  if (recipe) {
    recipe.key.xor_hex = recipe.key.xor_hex === mask.toString("hex") ? "mask" : recipe.key.xor_hex;
    recipe.assignments = Object.entries(recipe.assignments).map(([k, v]) => [tagOf(k), v]).sort();
  }
  return {
    status: a.status, outcome: a.outcome, finding: a.finding, partial_reasons: a.partial_reasons, trials: a.trials, members: a.members,
    recipe_said: a.recipe, derivation: a.tried.derivation, not_tried: a.not_tried,
    derived: a.derived_rules.map(({ from_file: _f, from_key: _k, ...rest }: Doc) => rest),
    rows: a.files.map((r: Doc) => ({ ...r, file: tagOf(r.file) })).sort((x: Doc, y: Doc) => (x.file < y.file ? -1 : x.file > y.file ? 1 : 0)),
    recipe,
  };
}

test("order fuzz: families with ties and chance, under shuffled names and listings, uncut and cut by max_trials in either pass, give one answer", { timeout: 900_000 }, async () => {
  for (let family = 0; family < 3; family++) {
    const fam = chanceFamily();
    const tags = Object.keys(fam.files);
    const args = { ...CANDIDATES, ciphers: ["chacha20-ietf"], counters: [0, 1, 2, 3], trailer_bytes: 64 };
    let bounds: Array<number | null> = [null];
    for (let b = 0; b < bounds.length; b++) {
      const seen: Doc[] = [];
      for (let run = 0; run < 3; run++) {
        const cwd = await sandbox();
        await writeValues(cwd, fam.values);
        const tagOfName: Record<string, string> = {};
        const paths: string[] = [];
        for (const tag of tags) {
          const name = `${randomInt(0, 2 ** 32).toString(16).padStart(8, "0")}${tags.indexOf(tag)}.exe.locked`;
          tagOfName[name] = tag;
          paths.push(`work/share/${name}`);
          await writeFile(join(cwd, "work", "share", name), fam.files[tag]!);
        }
        const listing = run === 2 ? { files: [...paths].sort(() => Math.random() - 0.5) } : { dir: "work/share" };
        const m = await job(cwd, "j000001", { ...args, ...listing, ...(bounds[b] === null ? {} : { max_trials: bounds[b] }) });
        seen.push(await normalised(m, (p) => tagOfName[p.split("/").pop()!]!, fam.mask));
      }
      for (const other of seen.slice(1)) assert.deepEqual(other, seen[0], `family ${family}, max_trials ${bounds[b]}: the answer does not follow the names or the listing`);
      if (bounds[b] === null) {
        // Cuts in the first and the second pass of the hypothesis: a few trials in, halfway, and one trial short.
        const whole = seen[0]!;
        const sources = whole.trials - whole.derivation.trials;
        bounds = [null, ...new Set([sources + 7, sources + Math.floor(whole.derivation.trials / 2), whole.trials - 1].filter((t) => t > sources))];
        if (whole.status === "complete" && whole.outcome === "one_rule_explains_every_member") assert.equal(whole.derivation.stopped_by, null);
      } else {
        assert.equal(seen[0]!.status, "partial", `family ${family}, max_trials ${bounds[b]}`);
        assert.notEqual(seen[0]!.derivation.stopped_by, null);
      }
    }
  }
});
