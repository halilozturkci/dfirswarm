/**
 * ransomware-response 1.14.4: what the fourth verification of stream_kpa_check found, and the review of the footer hypothesis it led to
 * (AGENTS.md rule 2: four rounds in a row found a P1 in the shortcuts that bound the hypothesis' work). Every fixture is built here with
 * node:crypto's ChaCha20, which shares nothing with the tool's pure-Python cipher.
 *
 *   stream_kpa_check
 *     - a key that opened several members was paired with one member per crib length, the first by NAME: a dump key that opens its own
 *       member B and, by chance, a member A of the same crib length was paired with whichever sorted first, so with A first the mask was
 *       wrong and the answer `complete`. Every (key, member it opened) is now a pair, the pairs are taken in an order of their bytes, and
 *       both orders of the names give the same outcome and mask; a bound that stops the hypothesis before the pair that holds the rule
 *       makes the answer partial.
 *     - a derived rule's matches past 64 on a member were counted only in a total: the reason could say "on 0 members" and the rows
 *       had no matches_not_kept. They are on the rows now, and the reason is made from the rows.
 *     - the best rule on a tie was the one whose first match came first in the order of the members' names; it is now the earliest
 *       source of the call.
 *     - every slice of every member was read and kept for the whole call, those no cipher can take included (5000 members x 64 slices
 *       of 4096 bytes: about 1.4 GB); a slice of a length no cipher asked for takes is now never read, and not_tried names it.
 *     - a values-file row with nine layouts gave no nonce at all; its first eight give one now, the ninth is counted as not usable.
 *     - with `files`, max_files takes the first ones in the order given (said now); a recursive listing stops once max_files is full,
 *       and the count past it is then a lower bound.
 *     - on a file system without hard links the recipe was given its name by a rename that could replace a file appearing at that
 *       name; it is now not written there, and the answer says why.
 *   backup_destruction_correlate
 *     - a shell history named five times for the same host was read five times (command_seen 5, complete): the named-again check now
 *       covers the streamed text files too.
 */
import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { createCipheriv, createHash, randomBytes } from "node:crypto";
import { mkdir, mkdtemp, readdir, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { after, test } from "node:test";
import { PYTHON3 } from "./host-gates.ts";
import { PACK, tool } from "./ransomware-pack-harness.ts";
import type { Run } from "./ransomware-pack-harness.ts";

const KPA = join(PACK, "stream_kpa_check", "run.py");
const CORRELATE = join(PACK, "backup_destruction_correlate", "run.py");
const xor = (a: Buffer, b: Buffer): Buffer => Buffer.from(a.map((v, i) => v ^ b[i]!));
type Doc = Record<string, any>;

const dirs: string[] = [];
after(async () => {
  for (const d of dirs) await rm(d, { recursive: true, force: true });
});

async function sandbox(): Promise<string> {
  const cwd = await mkdtemp(join(tmpdir(), "rw-pair-order-"));
  dirs.push(cwd);
  await mkdir(join(cwd, "work"), { recursive: true });
  return cwd;
}

async function job(script: string, cwd: string, id: string, args: unknown): Promise<Run> {
  const out = join(cwd, "store", "jobs", id, "out");
  await mkdir(out, { recursive: true });
  return tool(script, cwd, args, { JOB_ID: id, OUT: out, SECRET_OUTPUT: "1" });
}

function answer(run: Run, code = 0): Doc {
  assert.doesNotMatch(run.stderr, /Traceback/);
  assert.equal(run.code, code, run.stdout.slice(0, 2000) + run.stderr);
  return JSON.parse(run.stdout) as Doc;
}

/** OpenSSL's ChaCha20 (RFC 8439 layout): the IV is the 32-bit block counter, little-endian, then the 12-byte nonce. */
function chacha(key: Buffer, nonce: Buffer, data: Buffer, counter = 0): Buffer {
  const iv = Buffer.alloc(16);
  iv.writeUInt32LE(counter, 0);
  nonce.copy(iv, 4);
  return createCipheriv("chacha20", key, iv).update(data);
}

/** The first keystream byte of blocks 0 to 7. */
const firstBytes = (key: Buffer, nonce: Buffer): number[] => {
  const ks = chacha(key, nonce, Buffer.alloc(512));
  return [0, 1, 2, 3, 4, 5, 6, 7].map((c) => ks[64 * c]!);
};

/** A deterministic 32-byte key: the n-th of a named series. */
const keyOf = (series: string, n: number): Buffer => createHash("sha256").update(`${series}:${n}`).digest();

// ---- the pairs of the footer hypothesis: every pair, in an order of their bytes ----

type Family = { mask: Buffer; nonce: Buffer; key: Buffer; files: Record<string, Buffer> };
/** Eight exe members (the 2-byte crib "MZ"), each ChaCha20 under its own key with one nonce, the key XOR a constant mask appended. The
 * dump key K is B's; A's key is found so that K's keystream also gives "MZ" on A (the chance a 2-byte crib has), and A is the smaller
 * file, so that the pair (K, A) comes first in the order of the pairs' bytes: the pair that a by-name rule picked when A sorted first. */
function chanceFamily(): Family {
  const mask = randomBytes(32), nonce = randomBytes(12), key = randomBytes(32);
  const target = chacha(key, nonce, Buffer.alloc(2));
  let kA: Buffer | null = null;
  for (let i = 0; kA === null; i++) {
    const k = keyOf(`A-${nonce.toString("hex")}`, i);
    if (chacha(k, nonce, Buffer.alloc(2)).equals(target)) kA = k;
  }
  const exe = (size: number): Buffer => Buffer.concat([Buffer.from("4d5a90000300000004000000ffff0000", "hex"), randomBytes(size)]);
  const plain: Record<string, Buffer> = { A: exe(300), B: exe(400) };
  const keys: Record<string, Buffer> = { A: kA, B: key };
  for (let i = 0; i < 6; i++) {
    plain[`o${i}`] = exe(400);
    keys[`o${i}`] = randomBytes(32);
  }
  const files: Record<string, Buffer> = {};
  for (const m of Object.keys(plain)) files[m] = Buffer.concat([chacha(keys[m]!, nonce, plain[m]!), xor(keys[m]!, mask)]);
  return { mask, nonce, key, files };
}

async function writeFamily(cwd: string, fam: Family, naming: Record<string, string>): Promise<void> {
  const dir = join(cwd, "work", "share");
  await mkdir(dir, { recursive: true });
  for (const [m, data] of Object.entries(fam.files)) await writeFile(join(dir, `${naming[m] ?? `z_${m}`}.exe.locked`), data);
  await writeFile(join(cwd, "work", "dumpkey.bin"), fam.key);
}

const NAMINGS: Array<[string, Record<string, string>]> = [["B first", { B: "a01", A: "a02" }], ["A first", { A: "a01", B: "a02" }]];

test("a dump key that opens its own member and, by chance, another of the same crib length: both orders of the names give the rule and its mask", { timeout: 300_000 }, async () => {
  const fam = chanceFamily();
  const seen: Doc[] = [];
  for (const [label, naming] of NAMINGS) {
    const cwd = await sandbox();
    await writeFamily(cwd, fam, naming);
    const kpa = answer(await job(KPA, cwd, "j000001", { dir: "work/share", glob: "*.locked", key_sources: [{ file: "work/dumpkey.bin", offset: 0, length: 32 }],
      nonce_sources: [{ hex: fam.nonce.toString("hex") }], ciphers: ["chacha20-ietf"], counters: [0], trailer_bytes: 32 }));
    assert.equal(kpa.status, "complete", `${label}: ${kpa.status_basis}`);
    assert.deepEqual(kpa.partial_reasons, []);
    assert.equal(kpa.outcome, "one_rule_explains_every_member", `${label}: ${kpa.finding}`);
    assert.equal(kpa.members.by_verdict.match, 8);
    // Both openings of the key are pairs: (K, A) by chance, (K, B) its own; no pair is dropped.
    assert.equal(kpa.tried.derivation.pairs, 2, label);
    assert.equal("pairs_not_used" in kpa.tried.derivation, false);
    assert.equal(kpa.tried.derivation.stopped_by, null);
    assert.ok(kpa.recipe_file, label);
    const recipe = JSON.parse(await readFile(join(cwd, kpa.recipe_file), "utf8")) as Doc;
    assert.equal(recipe.key.xor_hex, fam.mask.toString("hex"), `${label}: the mask is the family's, not the one the chance opening gives`);
    assert.equal(recipe.made_by, "stream_kpa_check/6");
    seen.push({ explains: kpa.recipe.explains, key: kpa.recipe.key, rules: kpa.derived_rules.map(({ from_file: _f, ...rest }: Doc) => rest),
                derivation: kpa.tried.derivation, trials: kpa.trials });
  }
  assert.deepEqual(seen[0], seen[1], "the answer does not follow the order of the members' names");
});

test("a bound that stops the hypothesis before the pair that holds the rule: partial, and the no_match rows say the hypothesis was not tried whole", { timeout: 300_000 }, async () => {
  const fam = chanceFamily();
  const seen: Doc[] = [];
  for (const [label, naming] of NAMINGS) {
    const cwd = await sandbox();
    await writeFamily(cwd, fam, naming);
    // The sources' trials: 8. The pair (K, A) comes first by its bytes (A is the smaller file): its 65 places on 7 members are 455
    // trials, so 100 more stop the hypothesis before the pair (K, B) is reached. A place is begun only when its 7 trials fit in what
    // is left (1.14.5): 14 places, 98 trials, and the 15th is not begun.
    const kpa = answer(await job(KPA, cwd, "j000001", { dir: "work/share", glob: "*.locked", key_sources: [{ file: "work/dumpkey.bin", offset: 0, length: 32 }],
      nonce_sources: [{ hex: fam.nonce.toString("hex") }], ciphers: ["chacha20-ietf"], counters: [0], trailer_bytes: 32, max_trials: 108 }));
    assert.equal(kpa.status, "partial", label);
    assert.equal(kpa.complete, false);
    assert.equal(kpa.trials, 106);
    assert.equal(kpa.tried.derivation.pairs, 2);
    assert.equal(kpa.tried.derivation.stopped_by, "max_trials");
    assert.ok(kpa.partial_reasons.some((r: string) => /^max_trials \(108\) was reached while the footer hypothesis was being tried/.test(r)), kpa.status_basis);
    assert.ok(kpa.not_tried.some((l: string) => /^the footer hypothesis, in part/.test(l)));
    assert.equal(kpa.outcome, "some_members_explained");
    const misses = kpa.files.filter((r: Doc) => r.verdict === "no_match");
    assert.equal(misses.length, 6);
    for (const r of misses) assert.match(r.note, /footer hypothesis was stopped by max_trials before every place was tried on it/);
    seen.push({ outcome: kpa.outcome, derivation: kpa.tried.derivation, verdicts: kpa.files.map((r: Doc) => r.verdict).sort() });
  }
  assert.deepEqual(seen[0], seen[1], "the same stop, whatever the order of the names");
});

// ---- the matches a derived rule keeps ----

test("a derived rule that matches more than 64 combinations on a member: the row counts the others and the reason names the members", { timeout: 300_000 }, async () => {
  const cwd = await sandbox();
  const dir = join(cwd, "work", "share");
  await mkdir(dir);
  const mask = randomBytes(32), nonce = randomBytes(12);
  nonce[0] = 0x5a;                         // the file starts with the header: a 0x00 there would read as a head in plaintext
  // The 32 nonce sources are 32 slices of the same 12 header bytes, so each (cipher, counter) is 32 identical combinations. The dump key
  // K opens A at block 0 and at no other block of 0 to 7. B, C and D start at block 1, under keys whose blocks 1, 2 and 3 begin with
  // the same byte (and blocks 0 and 4 to 7 do not), and K's blocks never give that byte on them: the footer rule (found by its second
  // pass, since block 0 opens none of them) matches 3 x 32 = 96 combinations on each, 64 kept and 32 counted.
  let key = keyOf("K", 0);
  for (let i = 1; ; i++) {
    const b = firstBytes(key, nonce);
    if (b.slice(1).every((v) => v !== b[0])) break;
    key = keyOf("K", i);
  }
  const kBytes = firstBytes(key, nonce);
  const keys: Record<string, Buffer> = { a: key };
  for (const m of ["b", "c", "d"]) {
    for (let i = 0; ; i++) {
      const k = keyOf(`${m}-${nonce.toString("hex")}`, i);
      const b = firstBytes(k, nonce);
      if (b[1] === b[2] && b[1] === b[3] && [0, 4, 5, 6, 7].every((c) => b[c] !== b[1]) && !kBytes.includes(b[1]!)) {
        keys[m] = k;
        break;
      }
    }
  }
  for (const [m, k] of Object.entries(keys)) {
    const plain = Buffer.concat([Buffer.from([0]), randomBytes(300)]);
    await writeFile(join(dir, `${m}.x.locked`), Buffer.concat([nonce, chacha(k, nonce, plain, m === "a" ? 0 : 1), xor(k, mask)]));
  }
  await writeFile(join(cwd, "work", "key.bin"), key);
  const kpa = answer(await job(KPA, cwd, "j000001", { dir: "work/share", magics: { x: "00" }, key_sources: [{ file: "work/key.bin", offset: 0, length: 32 }],
    nonce_sources: Array.from({ length: 32 }, () => ({ slice: "head", length: 12, skip: 0 })), ciphers: ["chacha20-ietf"], counters: [0, 1, 2, 3, 4, 5, 6, 7], trailer_bytes: 32 }));
  assert.equal(kpa.outcome, "one_rule_explains_every_member", kpa.finding);
  const rule = kpa.derived_rules.find((d: Doc) => d.explains === 4);
  assert.deepEqual([rule.region, rule.skip], ["tail", 0]);
  const notKept = Object.fromEntries(kpa.files.map((r: Doc) => [r.file.split("/").pop(), r.matches_not_kept ?? 0]));
  assert.deepEqual(notKept, { "a.x.locked": 0, "b.x.locked": 32, "c.x.locked": 32, "d.x.locked": 32 });
  assert.equal(kpa.status, "partial");
  assert.ok(kpa.partial_reasons.some((r: string) => /^96 matching combinations were counted and not kept: more than 64 matched on 3 members/.test(r)), kpa.status_basis);
});

// ---- the best rule on a tie ----

test("two keys that each open one member: the best rule is the earlier source of the call, whatever the order of the names", { timeout: 120_000 }, async () => {
  const k0 = randomBytes(16), k1 = randomBytes(16);
  const png = Buffer.from("89504e470d0a1a0a0000000d49484452", "hex");
  const enc = (k: Buffer): Buffer => {
    const plain = Buffer.concat([png, randomBytes(200)]);
    return Buffer.from(plain.map((b, i) => b ^ k[i % 16]!));
  };
  const x = enc(k0), y = enc(k1);
  const labels: string[] = [];
  for (const [first, second] of [[x, y], [y, x]]) {
    const cwd = await sandbox();
    await mkdir(join(cwd, "work", "share"));
    await writeFile(join(cwd, "work", "share", "a.png.locked"), first!);
    await writeFile(join(cwd, "work", "share", "b.png.locked"), second!);
    const kpa = answer(await job(KPA, cwd, "j000001", { dir: "work/share", key_sources: [{ hex: k0.toString("hex") }, { hex: k1.toString("hex") }], ciphers: ["xor"], derive: false }));
    assert.equal(kpa.outcome, "some_members_explained");
    labels.push(kpa.recipe.key);
  }
  assert.deepEqual(labels, ["key_sources[0]: a literal of 16 bytes", "key_sources[0]: a literal of 16 bytes"]);
});

// ---- what is read and kept of each member ----

/** The tool run from a Python parent that reports the child's peak resident memory in bytes (getrusage: bytes on macOS, KiB on Linux),
 * and, with `noLink`, the tool with os.link made to fail as on a file system that takes no hard link. */
const PARENT = String.raw`
import os, resource, subprocess, sys
child = [sys.executable, sys.argv[1]]
if sys.argv[3] == "no-link":
    child = [sys.executable, "-c", """
import errno, os, runpy, sys
def link(a, b, **kw):
    raise OSError(errno.EPERM, "Operation not permitted")
os.link = link
sys.argv = [sys.argv[1]]
runpy.run_path(sys.argv[0], run_name="__main__")
""", sys.argv[1]]
with open(sys.argv[2], "rb") as fh:
    done = subprocess.run(child, stdin=fh, capture_output=True)
peak = resource.getrusage(resource.RUSAGE_CHILDREN).ru_maxrss * (1 if sys.platform == "darwin" else 1024)
sys.stderr.write(done.stderr.decode("utf-8", "replace"))
sys.stdout.write("%d %d\n" % (done.returncode, peak))
sys.stdout.write(done.stdout.decode("utf-8", "replace"))
`;

async function parent(cwd: string, id: string, args: unknown, mode = "plain"): Promise<{ code: number; peak: number; doc: Doc; out: string }> {
  const out = join(cwd, "store", "jobs", id, "out");
  await mkdir(out, { recursive: true });
  const input = join(cwd, `${id}.args.json`);
  await writeFile(input, JSON.stringify(args));
  const run = await new Promise<Run>((resolve, reject) => {
    const child = spawn(PYTHON3, ["-c", PARENT, KPA, input, mode], { cwd, env: { ...process.env, AGENT_ID: "s1", JOB_ID: id, OUT: out, SECRET_OUTPUT: "1" } });
    const so: Buffer[] = [], se: Buffer[] = [];
    child.stdout.on("data", (c: Buffer) => so.push(c));
    child.stderr.on("data", (c: Buffer) => se.push(c));
    child.on("error", reject);
    child.on("close", (code) => resolve({ code, stdout: Buffer.concat(so).toString("utf8"), stderr: Buffer.concat(se).toString("utf8") }));
  });
  assert.equal(run.code, 0, run.stderr);
  assert.doesNotMatch(run.stderr, /Traceback/);
  const [head, ...rest] = run.stdout.split("\n");
  const [code, peak] = head!.split(" ").map(Number);
  return { code: code!, peak: peak!, doc: JSON.parse(rest.join("\n")) as Doc, out };
}

test("slices no cipher asked for can take are not read: 1500 members with 62 slices of 4096 bytes each stay small, and not_tried names them", { timeout: 300_000 }, async () => {
  const cwd = await sandbox();
  const dir = join(cwd, "work", "many");
  await mkdir(dir);
  const body = randomBytes(64 * 31 + 4096 + 64);
  for (let i = 0; i < 1500; i++) await writeFile(join(dir, `m${String(i).padStart(4, "0")}.png.locked`), body);
  const big = (region: string) => Array.from({ length: 31 }, (_x, j) => ({ slice: region, length: 4096, skip: 64 * j }));
  // Before: every member kept its 62 slices of 4096 bytes for the whole call (about 400 MB here; 1.4 GB for 5000 members of 64).
  const run = await parent(cwd, "j000001", { dir: "work/many", max_files: 5000, header_bytes: 0, trailer_bytes: 0, derive: false, ciphers: ["chacha20-ietf"], counters: [0],
    key_sources: [...big("tail"), { slice: "tail", length: 32 }], nonce_sources: [...big("head"), { slice: "head", length: 12 }] });
  assert.equal(run.code, 0);
  const kpa = run.doc;
  assert.equal(kpa.members.named, 1500);
  assert.equal(kpa.trials, 1500, "one usable key slice and one usable nonce slice: one trial a member");
  assert.ok(kpa.not_tried.includes("key_sources[0]: a slice of 4096 bytes, a length that no cipher asked for takes as a key; it was not read"), JSON.stringify(kpa.not_tried));
  assert.ok(kpa.not_tried.includes("nonce_sources[30]: a slice of 4096 bytes, a length that no cipher asked for takes as a nonce; it was not read"));
  assert.ok(run.peak < 150e6, `peak resident memory ${run.peak} bytes`);
});

test("a values-file row with nine layouts gives the nonces of its first eight, and counts the ninth as not usable", { timeout: 120_000 }, async () => {
  const cwd = await sandbox();
  await mkdir(join(cwd, "work", "share"));
  await writeFile(join(cwd, "work", "share", "a.png.locked"), randomBytes(300));
  const layouts = Object.fromEntries(Array.from({ length: 9 }, (_x, i) => [`l${i}`, { nonce_hex: randomBytes(12).toString("hex") }]));
  await writeFile(join(cwd, "work", "values.jsonl"), JSON.stringify({ finding_id: "F000001", kind: "chacha-state", offset: 0, key_hex: randomBytes(32).toString("hex"), layouts }) + "\n");
  const kpa = answer(await job(KPA, cwd, "j000001", { dir: "work/share", key_sources: [{ candidates: "work/values.jsonl" }], nonce_sources: [{ candidates: "work/values.jsonl" }], ciphers: ["chacha20-ietf"], counters: [0] }));
  assert.deepEqual(kpa.tried.nonce_sources, [{ index: 0, kind: "candidates", rows: 1, rows_not_usable: 1, distinct_nonces: 8 }]);
  assert.equal(kpa.trials, 8);
});

// ---- which members are listed ----

test("with files, max_files takes the first ones in the order given; a recursive listing stops once max_files is full and says the count is a lower bound", { timeout: 120_000 }, async () => {
  const cwd = await sandbox();
  const flat = join(cwd, "work", "flat");
  await mkdir(flat);
  for (const n of ["a", "b", "c"]) await writeFile(join(flat, `${n}.png.locked`), randomBytes(200));
  const base = { key_sources: [{ hex: "00".repeat(16) }], ciphers: ["xor"], derive: false };
  const given = answer(await job(KPA, cwd, "j000001", { ...base, files: ["work/flat/c.png.locked", "work/flat/b.png.locked", "work/flat/a.png.locked"], max_files: 2 }));
  assert.deepEqual(given.files.map((r: Doc) => r.file), ["work/flat/c.png.locked", "work/flat/b.png.locked"]);
  assert.ok(given.partial_reasons.includes("1 more files matched and were not checked: max_files is 2"), given.status_basis);
  const tree = join(cwd, "work", "tree");
  for (const d of ["d1", "d2", "d3", "d4", "d5"]) {
    await mkdir(join(tree, d), { recursive: true });
    await writeFile(join(tree, d, "a.png.locked"), randomBytes(200));
  }
  await writeFile(join(tree, "d1", "b.png.locked"), randomBytes(200));
  const deep = answer(await job(KPA, cwd, "j000002", { ...base, dir: "work/tree", recursive: true, max_files: 1 }));
  assert.deepEqual(deep.files.map((r: Doc) => r.file), ["work/tree/d1/a.png.locked"]);
  assert.equal(deep.status, "partial");
  assert.ok(deep.partial_reasons.includes("at least 1 more files matched and were not checked: max_files is 1"), deep.status_basis);
  assert.ok(deep.partial_reasons.includes("in the directory: 4 directories not listed past max files"), deep.status_basis);
});

// ---- the recipe's name ----

test("an output directory that takes no hard link gets no recipe: it is not renamed into place, and the answer says why", { timeout: 120_000 }, async () => {
  const cwd = await sandbox();
  const key = randomBytes(16);
  const png = Buffer.from("89504e470d0a1a0a0000000d49484452", "hex");
  await mkdir(join(cwd, "work", "share"));
  for (const name of ["a.png.locked", "b.png.locked"]) {
    const plain = Buffer.concat([png, randomBytes(200)]);
    await writeFile(join(cwd, "work", "share", name), Buffer.from(plain.map((b, i) => b ^ key[i % 16]!)));
  }
  const run = await parent(cwd, "j000001", { dir: "work/share", key_sources: [{ hex: key.toString("hex") }], ciphers: ["xor"], derive: false }, "no-link");
  assert.equal(run.code, 0);
  assert.equal(run.doc.outcome, "one_rule_explains_every_member");
  assert.equal(run.doc.recipe_file, null);
  assert.equal(run.doc.contains_secret_values, false);
  assert.match(run.doc.recipe_file_why, /^not written: the recipe file could not be created \(.*takes no hard link/);
  assert.deepEqual(await readdir(run.out), [], "no recipe and no temporary file is left");
});

// ---- backup_destruction_correlate: a history named again ----

test("a shell history named five times for one host is read once: its command is seen once, and the others are counted as named again", { timeout: 120_000 }, async () => {
  const cwd = await sandbox();
  await writeFile(join(cwd, "work", "hist.jsonl"), JSON.stringify({ parser: "shell_history/14", command: "lvremove -f /dev/vg0/snap1", time: "2026-01-01T00:00:00Z", id: "r1", user: "root" }) + "\n");
  const out = answer(await tool(CORRELATE, cwd, { shell_histories: Array.from({ length: 5 }, () => ({ host: "h1", file: "work/hist.jsonl" })) }));
  assert.equal(out.observation_counts.command_seen, 1, "before: 5, one for each time the history was named");
  assert.deepEqual(out.inputs_read, { shell_histories: 1 });
  assert.deepEqual(out.inputs_named_again, { shell_histories: 4 });
  // Another host is another use: read again.
  const two = answer(await tool(CORRELATE, cwd, { shell_histories: [{ host: "h1", file: "work/hist.jsonl" }, { host: "h2", file: "work/hist.jsonl" }] }));
  assert.equal(two.observation_counts.command_seen, 2);
  assert.deepEqual(two.inputs_read, { shell_histories: 2 });
});
