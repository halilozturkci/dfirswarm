/**
 * ransomware-response 1.14.2: what a second independent verification of the pack found, each pinned on a fixture built here.
 *
 *   stream_kpa_check
 *     - a values file given as both the key and the nonce source used to be turned into a list of every (key, nonce, counter) of every
 *       member, kept until every member was read, before the count was compared with max_trials: 1000 states made about 10 million
 *       tuples per member (gigabytes for a few members; a job VM ran out of memory and printed no JSON). The trials are now counted from
 *       the lengths of what the sources give: a call that passes max_trials on one member is refused before any member is opened, one
 *       that passes it on all of them together once they are read, both with the count, in a few megabytes; the trials that are run are
 *       made one at a time and give the same counts and verdicts.
 *   encrypted_survey
 *     - copies of one encrypted file have one tail: the common suffix is taken over different tails only, so no whole tail is printed.
 *   cipher_state_scan
 *     - outside a job the list of all hits goes to work/<agent>/tool-output (it went to a doubled tool-output/tool-output), and a
 *       work/<agent>/tool-output that is a link is not written through.
 *   family_decrypt
 *     - a directory with no member: nothing was decrypted, and the status is failed, as the manifest says.
 *   encryption_extent
 *     - a complete answer under policy sampling names that policy, not "full".
 */
import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { createCipheriv, randomBytes } from "node:crypto";
import { mkdir, mkdtemp, readdir, rm, symlink, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { after, test } from "node:test";
import { PYTHON3 } from "./host-gates.ts";
import { PACK, tool } from "./ransomware-pack-harness.ts";
import type { Run } from "./ransomware-pack-harness.ts";

const KPA = join(PACK, "stream_kpa_check", "run.py");
const SURVEY = join(PACK, "encrypted_survey", "run.py");
const SCAN = join(PACK, "cipher_state_scan", "run.py");
const DECRYPT = join(PACK, "family_decrypt", "run.py");
const EXTENT = join(PACK, "encryption_extent", "run.py");
const PNG = Buffer.from("89504e470d0a1a0a0000000d49484452", "hex");
const SIGMA = Buffer.from("expand 32-byte k");
type Doc = Record<string, any>;
const NO_JOB = { JOB_ID: "", OUT: "", SECRET_OUTPUT: "" };

const dirs: string[] = [];
after(async () => {
  for (const d of dirs) await rm(d, { recursive: true, force: true });
});

async function sandbox(): Promise<string> {
  const cwd = await mkdtemp(join(tmpdir(), "rw-verify2-"));
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

/** OpenSSL's ChaCha20: the IV is the 32-bit block counter (little-endian) and then the 12-byte nonce. */
function chacha(key: Buffer, nonce: Buffer, data: Buffer, counter = 0): Buffer {
  const iv = Buffer.alloc(16);
  iv.writeUInt32LE(counter, 0);
  nonce.copy(iv, 4);
  return createCipheriv("chacha20", key, iv).update(data);
}

/** A values file in cipher_state_scan's layout: one row per state, a 32-byte key and a nonce in each of the two ChaCha layouts. */
async function valuesFile(path: string, n: number, plant?: { at: number; key: Buffer; nonce: Buffer }): Promise<void> {
  const rows: string[] = [];
  for (let i = 0; i < n; i++) {
    const key = plant && plant.at === i ? plant.key : randomBytes(32);
    const ietf = plant && plant.at === i ? plant.nonce : randomBytes(12);
    rows.push(JSON.stringify({ finding_id: `F${String(i + 1).padStart(6, "0")}`, kind: "chacha-state", offset: 64 * i, key_hex: key.toString("hex"),
      layouts: { ietf: { nonce_hex: ietf.toString("hex") }, original: { nonce_hex: randomBytes(8).toString("hex") } } }));
  }
  await writeFile(path, rows.join("\n") + "\n");
}

/** The tool run from a Python parent that reports the child's peak resident memory in bytes (getrusage: bytes on macOS, KiB on Linux). */
const MEASURED = String.raw`
import os, resource, subprocess, sys, time
started = time.monotonic()
with open(sys.argv[2], "rb") as fh:
    done = subprocess.run([sys.executable, sys.argv[1]], stdin=fh, capture_output=True)
peak = resource.getrusage(resource.RUSAGE_CHILDREN).ru_maxrss * (1 if sys.platform == "darwin" else 1024)
sys.stderr.write(done.stderr.decode("utf-8", "replace"))
sys.stdout.write("%d %d %.2f\n" % (done.returncode, peak, time.monotonic() - started))
sys.stdout.write(done.stdout.decode("utf-8", "replace"))
`;

async function measured(cwd: string, id: string, args: unknown): Promise<{ code: number; peak: number; seconds: number; doc: Doc; stderr: string }> {
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
  const [code, peak, seconds] = head!.split(" ").map(Number);
  return { code: code!, peak: peak!, seconds: seconds!, doc: JSON.parse(rest.join("\n")) as Doc, stderr: run.stderr };
}

// ---- stream_kpa_check: the trials are counted, not listed ----

test("a values file of 1000 states as key and nonce source: refused before any member is opened, with the count, in a few megabytes", { timeout: 120_000 }, async () => {
  const cwd = await sandbox();
  await valuesFile(join(cwd, "work", "c1000.jsonl"), 1000);
  const share = join(cwd, "work", "share");
  await mkdir(share);
  for (let i = 1; i <= 4; i++) await writeFile(join(share, `f${i}.png.locked`), randomBytes(5000));
  // 1000 keys of 32 bytes; 1000 nonces of 12 bytes and 1000 of 8; counters 0 and 1. Per member: 2,000,000 for each ChaCha layout and
  // Salsa20 (one nonce length each), 4,000,000 for AES-CTR (both), 1000 for RC4 and for XOR. The old code listed them all (about 700 MB
  // per member).
  const run = await measured(cwd, "j000001", { dir: "work/share", key_sources: [{ candidates: "work/c1000.jsonl" }], nonce_sources: [{ candidates: "work/c1000.jsonl" }] });
  assert.doesNotMatch(run.stderr, /Traceback/);
  assert.equal(run.code, 1);
  assert.equal(run.doc.status, "failed");
  assert.match(run.doc.error, /^10002000 trials would be made on each member that has a crib \(chacha20-ietf 2000000, chacha20-original 2000000, salsa20 2000000, aes-ctr 4000000, rc4 1000, xor 1000; [^)]*\) and 4 members are named, and max_trials is 500000: [\s\S]*Nothing was opened and nothing was tried$/);
  assert.ok(run.peak < 200e6, `peak resident memory ${run.peak} bytes`);
  assert.ok(run.seconds < 30, `${run.seconds} s`);
  assert.deepEqual(await readdir(join(cwd, "store", "jobs", "j000001", "out")), [], "nothing was written");
});

test("200 states on 50 members: each member alone fits max_trials and all of them do not; refused once they are read, without listing a trial", { timeout: 180_000 }, async () => {
  const cwd = await sandbox();
  await valuesFile(join(cwd, "work", "c200.jsonl"), 200);
  const share = join(cwd, "work", "share");
  await mkdir(share);
  for (let i = 0; i < 50; i++) await writeFile(join(share, `f${String(i).padStart(2, "0")}.png.locked`), randomBytes(3000));
  // 400,400 trials a member (under 500,000), 20,020,000 for the 50: the old code held 20 million tuples (gigabytes) before it said so.
  const run = await measured(cwd, "j000001", { dir: "work/share", key_sources: [{ candidates: "work/c200.jsonl" }], nonce_sources: [{ candidates: "work/c200.jsonl" }] });
  assert.doesNotMatch(run.stderr, /Traceback/);
  assert.equal(run.code, 1);
  assert.match(run.doc.error, /^20020000 trials would be made \(50 members with a crib, [\s\S]*max_trials is 500000: [\s\S]*Nothing was tried$/);
  assert.ok(run.peak < 200e6, `peak resident memory ${run.peak} bytes`);
});

test("trials made one at a time give the counts the arithmetic gives, and the member a planted state opens", { timeout: 180_000 }, async () => {
  const cwd = await sandbox();
  const key = randomBytes(32), nonce = randomBytes(12);
  await valuesFile(join(cwd, "work", "c40.jsonl"), 40, { at: 17, key, nonce });
  const share = join(cwd, "work", "share");
  await mkdir(share);
  for (const name of ["a.png.locked", "b.png.locked", "c.png.locked"]) await writeFile(join(share, name), chacha(key, nonce, Buffer.concat([PNG, randomBytes(4000)])));
  const kpa = answer(await job(KPA, cwd, "j000001", { dir: "work/share", derive: false, key_sources: [{ candidates: "work/c40.jsonl" }], nonce_sources: [{ candidates: "work/c40.jsonl" }] }));
  assert.equal(kpa.status, "complete", kpa.status_basis);
  assert.equal(kpa.outcome, "one_rule_explains_every_member");
  // 40 keys of 32 bytes, 40 nonces of 12 and 40 of 8, counters 0 and 1, on three members.
  assert.deepEqual(kpa.tried.trials_by_cipher, { "chacha20-ietf": 9600, "chacha20-original": 9600, salsa20: 9600, "aes-ctr": 19200, rc4: 120, xor: 120 });
  assert.equal(kpa.trials, 3 * 16080);
  assert.deepEqual(kpa.files.map((r: Doc) => [r.verdict, r.trials]), [["match", 16080], ["match", 16080], ["match", 16080]]);
  for (const row of kpa.files) {
    assert.ok(row.matches.some((m: Doc) => m.cipher === "chacha20-ietf" && m.counter === 0 && /F000018/.test(m.key) && /ietf nonce of F000018/.test(m.nonce)), JSON.stringify(row.matches));
  }
  assert.ok(!JSON.stringify(kpa).includes(key.toString("hex")));
});

// ---- encrypted_survey: copies of one file ----

test("copies of one encrypted file have one tail: the tail is counted and measured, never printed as a shared suffix", { timeout: 120_000 }, async () => {
  const cwd = await sandbox();
  const root = join(cwd, "work", "root");
  await mkdir(root);
  const member = Buffer.concat([randomBytes(7000), randomBytes(32)]);
  const tail = member.subarray(-32).toString("hex");
  for (const name of ["c1.xlsx.locked", "c2.xlsx.locked", "c3.xlsx.locked"]) await writeFile(join(root, name), member);
  const run = await tool(SURVEY, cwd, { root: "work/root" }, NO_JOB);
  const survey = answer(run);
  assert.equal(survey.shared_tail_suffix, null);
  assert.deepEqual(survey.repeated_tails.map((t: Doc) => [t.files, t.bytes]), [[3, 32]]);
  for (let i = 0; i + 8 <= tail.length; i += 2) assert.ok(!run.stdout.includes(tail.slice(i, i + 8)), "four bytes of the tail are in the answer");
  // One different member beside the copies: two different tails, whose common suffix (if any) is shorter than a tail.
  await writeFile(join(root, "d.xlsx.locked"), Buffer.concat([randomBytes(7000), randomBytes(28), member.subarray(-4)]));
  const two = answer(await tool(SURVEY, cwd, { root: "work/root" }, NO_JOB));
  assert.ok(two.shared_tail_suffix === null || two.shared_tail_suffix.bytes < 32, JSON.stringify(two.shared_tail_suffix));
});

// ---- cipher_state_scan outside a job ----

test("outside a job the list of all hits is written to work/<agent>/tool-output itself, and a link there is not written through", { timeout: 120_000 }, async () => {
  const cwd = await sandbox();
  await writeFile(join(cwd, "d.bin"), Buffer.concat(Array.from({ length: 40 }, () => Buffer.concat([SIGMA, randomBytes(48), randomBytes(100)]))));
  const good = answer(await tool(SCAN, cwd, { file: "d.bin", limit: 5 }, NO_JOB));
  assert.match(good.all_hits, /^work\/s1\/tool-output\/cipher_state_scan-hits-[0-9a-f]{16}\.jsonl$/);
  assert.deepEqual((await readdir(join(cwd, "work", "s1", "tool-output"))).filter((n) => !n.startsWith(".")).length, 1);
  // A tool-output that is a link, and a work/<agent> that is one: neither is written through.
  for (const [agent, link] of [["s2", ["work", "s2", "tool-output"]], ["s3", ["work", "s3"]]] as const) {
    const elsewhere = join(cwd, `elsewhere-${agent}`);
    await mkdir(elsewhere);
    await mkdir(join(cwd, ...link.slice(0, -1)), { recursive: true });
    await symlink(elsewhere, join(cwd, ...link));
    const scan = answer(await tool(SCAN, cwd, { file: "d.bin", limit: 5 }, { ...NO_JOB, AGENT_ID: agent }));
    assert.equal(scan.status, "partial");
    assert.equal(scan.all_hits, undefined);
    assert.match(scan.status_basis, /the list of all hits could not be written \([\s\S]*tool-output is there and is not a directory of this run/);
    assert.deepEqual(await readdir(elsewhere, { recursive: true }), [], "nothing was written through the link");
  }
});

// ---- family_decrypt: nothing to decrypt ----

test("family_decrypt on a directory with no member: nothing was decrypted, and the status is failed", { timeout: 120_000 }, async () => {
  const cwd = await sandbox();
  await mkdir(join(cwd, "work", "empty"));
  await writeFile(join(cwd, "work", "recipe.json"), JSON.stringify({ recipe: "stream-family/1", key: { hex: randomBytes(16).toString("hex") },
    variants: [{ cipher: "rc4", counter: 0, nonce: null }], header_bytes: 0, trailer_bytes: 0, member_suffix: ".locked" }));
  const dec = answer(await job(DECRYPT, cwd, "j000001", { recipe_file: "work/recipe.json", dir: "work/empty" }));
  assert.equal(dec.status, "failed");
  assert.equal(dec.complete, false);
  assert.match(dec.status_basis, /no file matched: nothing was decrypted/);
  assert.equal(dec.members.decrypted, 0);
});

// ---- encryption_extent: the policy named is the one used ----

test("a complete answer under policy sampling names sampling, and under policy full names full", { timeout: 120_000 }, async () => {
  const cwd = await sandbox();
  await writeFile(join(cwd, "work", "a.bin"), randomBytes(20_000));
  const sampled = answer(await tool(EXTENT, cwd, { files: ["work/a.bin"], policy: "sampling" }, NO_JOB));
  assert.equal(sampled.status, "complete", sampled.status_basis);
  assert.match(sampled.status_basis, /inspected under policy sampling \(no file was larger than its \d+ sample windows, so each was read whole\)/);
  assert.doesNotMatch(sampled.status_basis, /policy full/);
  const full = answer(await tool(EXTENT, cwd, { files: ["work/a.bin"], policy: "full" }, NO_JOB));
  assert.equal(full.status, "complete", full.status_basis);
  assert.match(full.status_basis, /inspected under policy full;/);
});
