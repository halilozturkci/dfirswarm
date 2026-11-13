/**
 * ransomware-response 1.14.3: work done before or outside a tool's own budget. Three verification rounds in a row found a P1 of one
 * pattern in stream_kpa_check: an input read, or a loop run, before the clock was set, without reading it, or without a bound on what it
 * kept, so that a large or crafted input ran past the manifest's 600 s or died without JSON. Each case below ran for minutes or took
 * gigabytes before; each must now answer fast, in bounded memory, with the right status and the count of what was not done.
 *
 *   stream_kpa_check
 *     - a candidates file was read whole and parsed before the clock was set, once per source that named it: one 64 MiB file of `{}`
 *       lines took 88 s and 2.9 GB, sixteen references 712 s. It is now read one line at a time under the clock, once per role (the
 *       same file by device and inode), refused at its 20,001st line, and its rows with no value are not even made printable.
 *     - every hit of a fixed key rebuilt a set of the pairs found so far, and the footer hypothesis listed every place of every pair
 *       before any bound: 20,000 keys that each open two members took 15 s past max_seconds 5 and answered complete. At most 64 matches
 *       a member are kept (the others counted, the answer partial), a key is paired once per crib length, and at most 65,536 places are
 *       listed (the others counted, the hypothesis stopped by max_places).
 *     - a stop while the recipe was written could leave a 0-byte stream-recipe.json beside an answer that said no recipe was written.
 *       It is written under a temporary name with the stop signals held, given its name without replacing a file, and removed by a stop
 *       that comes before the answer.
 *     - a directory is listed one entry at a time, keeping only the names max_files can take.
 *   backup_destruction_correlate
 *     - forty references to one 16 MiB document held two parses at once (1 GB): it is read once per use and one is held at a time.
 */
import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { mkdir, mkdtemp, open, readdir, readFile, rm, stat, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { after, test } from "node:test";
import { PYTHON3 } from "./host-gates.ts";
import { PACK } from "./ransomware-pack-harness.ts";
import type { Run } from "./ransomware-pack-harness.ts";

const KPA = join(PACK, "stream_kpa_check", "run.py");
const CORRELATE = join(PACK, "backup_destruction_correlate", "run.py");
const PNG = Buffer.from("89504e470d0a1a0a0000000d49484452", "hex");
type Doc = Record<string, any>;

const dirs: string[] = [];
after(async () => {
  for (const d of dirs) await rm(d, { recursive: true, force: true });
});

async function sandbox(): Promise<string> {
  const cwd = await mkdtemp(join(tmpdir(), "rw-kpa-bounds-"));
  dirs.push(cwd);
  await mkdir(join(cwd, "work"), { recursive: true });
  return cwd;
}

/** The tool run from a Python parent that reports the child's exit, its peak resident memory in bytes (getrusage: bytes on macOS, KiB on
 * Linux) and the wall time; `mode` patches the child before the tool runs (runpy) to stop it at one point of the recipe's writing. */
const MEASURED = String.raw`
import os, resource, subprocess, sys, time
started = time.monotonic()
child = [sys.executable, sys.argv[1]]
if sys.argv[3] != "plain":
    child = [sys.executable, "-c", """
import os, runpy, signal, sys
mode, path = sys.argv[1], sys.argv[2]
if mode == "term-at-link":
    real_link = os.link
    def link(a, b, **kw):
        os.kill(os.getpid(), signal.SIGTERM)       # held while the recipe is written: answered once the signals are let go
        return real_link(a, b, **kw)
    os.link = link
elif mode == "kill-at-fsync":
    def fsync(fd):
        os.kill(os.getpid(), signal.SIGKILL)       # no handler sees it
    os.fsync = fsync
sys.argv = [path]
runpy.run_path(path, run_name="__main__")
""", sys.argv[3], sys.argv[1]]
with open(sys.argv[2], "rb") as fh:
    done = subprocess.run(child, stdin=fh, capture_output=True)
peak = resource.getrusage(resource.RUSAGE_CHILDREN).ru_maxrss * (1 if sys.platform == "darwin" else 1024)
sys.stderr.write(done.stderr.decode("utf-8", "replace"))
sys.stdout.write("%d %d %.2f\n" % (done.returncode, peak, time.monotonic() - started))
sys.stdout.write(done.stdout.decode("utf-8", "replace"))
`;

type Measured = { code: number; peak: number; seconds: number; doc: Doc | null; stdout: string; stderr: string; out: string };

async function measured(script: string, cwd: string, id: string, args: unknown, mode = "plain"): Promise<Measured> {
  const out = join(cwd, "store", "jobs", id, "out");
  await mkdir(out, { recursive: true });
  const input = join(cwd, `${id}.args.json`);
  await writeFile(input, JSON.stringify(args));
  const run = await new Promise<Run>((resolve, reject) => {
    const child = spawn(PYTHON3, ["-c", MEASURED, script, input, mode], { cwd, env: { ...process.env, AGENT_ID: "s1", JOB_ID: id, OUT: out, SECRET_OUTPUT: "1" } });
    const so: Buffer[] = [], se: Buffer[] = [];
    child.stdout.on("data", (c: Buffer) => so.push(c));
    child.stderr.on("data", (c: Buffer) => se.push(c));
    child.on("error", reject);
    child.on("close", (code) => resolve({ code, stdout: Buffer.concat(so).toString("utf8"), stderr: Buffer.concat(se).toString("utf8") }));
  });
  assert.equal(run.code, 0, run.stderr);
  const [head, ...rest] = run.stdout.split("\n");
  const [code, peak, seconds] = head!.split(" ").map(Number);
  const text = rest.join("\n");
  let doc: Doc | null = null;
  try {
    doc = JSON.parse(text) as Doc;
  } catch {
    doc = null;
  }
  return { code: code!, peak: peak!, seconds: seconds!, doc, stdout: text, stderr: run.stderr, out };
}

/** A file of `size` bytes made of `line` repeated (and one `last` line), written a block at a time. */
async function repeated(path: string, line: string, size: number, last = ""): Promise<void> {
  const fh = await open(path, "w");
  const block = Buffer.from(line.repeat(Math.floor((1 << 20) / line.length)));
  let written = 0;
  while (written + block.length + last.length <= size) {
    await fh.write(block);
    written += block.length;
  }
  if (last) await fh.write(last);
  await fh.close();
}

// ---- stream_kpa_check: a candidates file is read once, one line at a time, under the clock ----

test("a 64 MiB candidates file of empty objects named 16 times: refused at its 20,001st line, in a fraction of a second, without reading on", { timeout: 300_000 }, async () => {
  const cwd = await sandbox();
  await mkdir(join(cwd, "work", "m"));
  await writeFile(join(cwd, "work", "m", "a.png.locked"), Buffer.alloc(4096, 7));
  await repeated(join(cwd, "work", "empty.jsonl"), "{}\n", 64 << 20);
  assert.ok((await stat(join(cwd, "work", "empty.jsonl"))).size <= 64 << 20);
  // Before: the file was read whole and every line parsed, once per reference, before the clock was set (712 s and 4.75 GB for 16).
  const named: Doc[] = [...Array(16)].map(() => ({ candidates: "work/empty.jsonl" }));
  const run = await measured(KPA, cwd, "j000001", { dir: "work/m", key_sources: [...named, { hex: "00".repeat(32) }], nonce_sources: named, max_seconds: 5 });
  assert.doesNotMatch(run.stderr, /Traceback/);
  assert.equal(run.code, 1, run.stdout);
  assert.equal(run.doc!.status, "failed");
  assert.match(run.doc!.error, /^key_sources\[0\]\.candidates holds more than 20000 lines \(the values file of cipher_state_scan holds 5000 rows at most\)[\s\S]*Nothing was tried$/);
  assert.ok(run.seconds < 30, `${run.seconds} s`);
  assert.ok(run.peak < 200e6, `peak resident memory ${run.peak} bytes`);
  assert.deepEqual(await readdir(run.out), [], "nothing was written");
});

test("a 60 MiB values file of 20,000 rows named 16 times as key and 16 times as nonce source: parsed once per role, fast and bounded", { timeout: 300_000 }, async () => {
  const cwd = await sandbox();
  await mkdir(join(cwd, "work", "m"));
  await writeFile(join(cwd, "work", "m", "a.png.locked"), Buffer.alloc(4096, 7));
  const rows: string[] = [];
  const pad = "p".repeat(2900);
  const hex = (n: number, i: number) => (i.toString(16).padStart(8, "0") + "5a".repeat(n)).slice(0, 2 * n);
  for (let i = 0; i < 20_000; i++) {
    rows.push(JSON.stringify({ finding_id: `F${String(i + 1).padStart(6, "0")}`, kind: "chacha-state", offset: 64 * i, key_hex: hex(32, i), pad,
      layouts: { ietf: { nonce_hex: hex(12, i) }, original: { nonce_hex: hex(8, i) } } }));
  }
  await writeFile(join(cwd, "work", "big.jsonl"), rows.join("\n") + "\n");
  const size = (await stat(join(cwd, "work", "big.jsonl"))).size;
  assert.ok(size > 56 << 20 && size <= 64 << 20, `${size} bytes`);
  const named = [...Array(16)].map(() => ({ candidates: "work/big.jsonl" }));
  const run = await measured(KPA, cwd, "j000001", { dir: "work/m", key_sources: named, nonce_sources: named, ciphers: ["xor"], max_seconds: 60 });
  assert.doesNotMatch(run.stderr, /Traceback/);
  assert.equal(run.code, 0, run.stdout.slice(0, 2000));
  const kpa = run.doc!;
  assert.equal(kpa.status, "complete", kpa.status_basis);
  assert.equal(kpa.trials, 20_000);
  assert.deepEqual(kpa.tried.key_sources[0], { index: 0, kind: "candidates", rows: 20_000, rows_not_usable: 0, distinct_keys: 20_000 });
  assert.deepEqual(kpa.tried.nonce_sources[0], { index: 0, kind: "candidates", rows: 20_000, rows_not_usable: 0, distinct_nonces: 40_000 });
  for (const [role, said] of [["key", kpa.tried.key_sources], ["nonce", kpa.tried.nonce_sources]] as const) {
    assert.equal(said.length, 16);
    for (const later of said.slice(1)) {
      assert.equal(later.same_file_as, `${role}_sources[0]`);
      assert.equal(later[`distinct_${role}s`], 0);
    }
  }
  assert.ok(run.seconds < 60, `${run.seconds} s`);
  assert.ok(run.peak < 300e6, `peak resident memory ${run.peak} bytes`);
});

test("lines too long to be rows are counted, not parsed; keys and nonces of a length no cipher takes are counted, not kept", { timeout: 120_000 }, async () => {
  const cwd = await sandbox();
  await mkdir(join(cwd, "work", "m"));
  await writeFile(join(cwd, "work", "m", "a.png.locked"), Buffer.alloc(4096, 7));
  const lines = ["[" + "1,".repeat(1 << 20) + "1]", JSON.stringify({ key_hex: "41".repeat(300) }), JSON.stringify({ key_hex: "42".repeat(32), layouts: { a: { nonce_hex: "00".repeat(9) }, b: { nonce_hex: "01".repeat(12) } } })];
  await writeFile(join(cwd, "work", "odd.jsonl"), lines.join("\n") + "\n");
  const run = await measured(KPA, cwd, "j000001", { dir: "work/m", key_sources: [{ candidates: "work/odd.jsonl" }], nonce_sources: [{ candidates: "work/odd.jsonl" }], ciphers: ["xor", "chacha20-ietf"] });
  assert.equal(run.code, 0, run.stdout.slice(0, 2000));
  assert.deepEqual(run.doc!.tried.key_sources[0], { index: 0, kind: "candidates", rows: 2, rows_not_usable: 1, distinct_keys: 1, keys_of_a_length_no_cipher_takes: 1 });
  assert.deepEqual(run.doc!.tried.nonce_sources[0], { index: 0, kind: "candidates", rows: 2, rows_not_usable: 1, distinct_nonces: 1, nonces_of_a_length_no_cipher_takes: 1 });
  assert.ok(run.peak < 200e6, `peak resident memory ${run.peak} bytes`);
});

// ---- stream_kpa_check: the hits and the footer hypothesis are bounded ----

/** `members` files named f000.x.locked ... whose first bytes are 0x41 and the member's number, and a values file of keys of 4 bytes: 0x41,
 * then the number of the member it is made for (or 0), then a count. With the 2-byte crib "0000" (or the 1-byte "00") a key opens every
 * member whose second byte it carries (or every member). */
async function xorFamily(cwd: string, members: number, keys: (i: number) => string[]): Promise<void> {
  await mkdir(join(cwd, "work", "m"));
  for (let i = 0; i < members; i++) {
    await writeFile(join(cwd, "work", "m", `f${String(i).padStart(3, "0")}.x.locked`), Buffer.concat([Buffer.from([0x41, i]), Buffer.alloc(998, 0x33 + i)]));
  }
  const all: string[] = [];
  for (let i = 0; i < members; i++) all.push(...keys(i).map((k) => JSON.stringify({ key_hex: k })));
  await writeFile(join(cwd, "work", "keys.jsonl"), all.join("\n") + "\n");
}

test("20,000 keys that each open both members on a 1-byte crib: 64 matches kept a member, the rest counted, partial, in seconds", { timeout: 300_000 }, async () => {
  const cwd = await sandbox();
  await xorFamily(cwd, 2, (i) => (i ? [] : [...Array(20_000)].map((_x, j) => "41" + j.toString(16).padStart(6, "0"))));
  const base = { dir: "work/m", glob: "*.locked", magics: { x: "00" }, ciphers: ["xor"], key_sources: [{ candidates: "work/keys.jsonl" }], max_trials: 5_000_000, max_seconds: 5 };
  // Before: every hit rebuilt a set of the pairs so far (14.9 s past max_seconds 5, and `complete`); with derive the hypothesis listed
  // every place of every pair before any bound (3.25 million places for 25,000 keys, 1 GB).
  for (const derive of [false, true]) {
    const run = await measured(KPA, cwd, derive ? "j000002" : "j000001", { ...base, derive });
    assert.doesNotMatch(run.stderr, /Traceback/);
    assert.equal(run.code, 0, run.stdout.slice(0, 2000));
    const kpa = run.doc!;
    assert.equal(kpa.status, "partial");
    assert.deepEqual(kpa.files.map((r: Doc) => [r.verdict, r.matches_not_kept]), [["match", 20_000 - 64], ["match", 20_000 - 64]]);
    assert.ok(kpa.partial_reasons.some((r: string) => /^39872 matching combinations were counted and not kept: more than 64 matched on 2 members/.test(r)), kpa.status_basis);
    if (derive) {
      // One pair a key per crib length: the 64 keys kept on the first member are not paired again with the second.
      assert.equal(kpa.tried.derivation.pairs, 64);
      assert.equal(kpa.tried.derivation.pairs_not_used, 64);
      assert.equal(kpa.tried.derivation.places, 64 * 65);
      assert.equal(kpa.tried.derivation.places_not_listed, 0);
      assert.ok(kpa.not_tried.some((l: string) => /^the footer hypothesis from a key paired with a second member of the same crib length: 64 such pairs/.test(l)));
    } else {
      assert.equal(kpa.trials, 40_000);
      assert.deepEqual(kpa.tried.derivation, { made: false });
    }
    assert.ok(run.seconds < 60, `${run.seconds} s`);
    assert.ok(run.peak < 200e6, `peak resident memory ${run.peak} bytes`);
  }
});

test("more places than the hypothesis lists: 65,536 are listed, the others counted, and the hypothesis is stopped by max_trials or max_places", { timeout: 600_000 }, async () => {
  const cwd = await sandbox();
  // 20 members, 100 keys each that open only it: 64 kept a member, so 1280 pairs and 1280 x 65 = 83,200 places (a 4-byte key at every
  // skip from 0 to 64 of a 1000-byte member's tail).
  await xorFamily(cwd, 20, (i) => [...Array(100)].map((_x, j) => "41" + i.toString(16).padStart(2, "0") + j.toString(16).padStart(4, "0")));
  const base = { dir: "work/m", glob: "*.locked", magics: { x: "0000" }, ciphers: ["xor"], key_sources: [{ candidates: "work/keys.jsonl" }] };
  const tight = await measured(KPA, cwd, "j000001", { ...base, max_trials: 140_000, max_seconds: 120 });
  assert.equal(tight.code, 0, tight.stdout.slice(0, 2000));
  const t = tight.doc!;
  assert.equal(t.status, "partial");
  assert.deepEqual([t.tried.derivation.pairs, t.tried.derivation.places, t.tried.derivation.places_not_listed, t.tried.derivation.stopped_by],
    [1280, 65_536, 83_200 - 65_536, "max_trials"]);
  assert.equal(t.trials, 140_000);
  assert.ok(t.partial_reasons.some((r: string) => /^max_trials \(140000\) was reached while the footer hypothesis was being tried: [\s\S]* 17664 more places \(past the first 65536 listed/.test(r)), t.status_basis);
  assert.ok(t.files.every((r: Doc) => r.matches_not_kept === 36));
  assert.ok(tight.peak < 300e6, `peak resident memory ${tight.peak} bytes`);
  const whole = await measured(KPA, cwd, "j000002", { ...base, max_trials: 5_000_000, max_seconds: 480 });
  assert.equal(whole.code, 0, whole.stdout.slice(0, 2000));
  const w = whole.doc!;
  assert.equal(w.status, "partial");
  assert.deepEqual([w.tried.derivation.places, w.tried.derivation.places_not_listed, w.tried.derivation.places_tried_on_every_member, w.tried.derivation.stopped_by],
    [65_536, 17_664, 65_536, "max_places"]);
  assert.ok(w.partial_reasons.some((r: string) => /^the footer hypothesis has more places [\s\S]* than the 65536 it lists: the 65536 listed were tried on every member no rule explains[\s\S]* 17664 more places/.test(r)), w.status_basis);
  assert.ok(w.files.every((r: Doc) => r.verdict === "match"));
  assert.ok(whole.seconds < 400, `${whole.seconds} s`);
  assert.ok(whole.peak < 300e6, `peak resident memory ${whole.peak} bytes`);
});

test("a directory of 5000 matching files and max_files 5: the five first names are checked and the others counted, the names kept bounded", { timeout: 300_000 }, async () => {
  const cwd = await sandbox();
  const dir = join(cwd, "work", "many");
  await mkdir(dir);
  // Written in an order that is not the order of their names.
  for (let n = 0; n < 5000; n++) {
    const i = (n * 7919) % 5000;
    await writeFile(join(dir, `f${String(i).padStart(5, "0")}.png.locked`), Buffer.alloc(200, 1));
  }
  const run = await measured(KPA, cwd, "j000001", { dir: "work/many", glob: "*.locked", max_files: 5, ciphers: ["xor"], key_sources: [{ hex: "00".repeat(16) }], derive: false });
  assert.equal(run.code, 0, run.stdout.slice(0, 2000));
  const kpa = run.doc!;
  assert.deepEqual(kpa.files.map((r: Doc) => r.file), [0, 1, 2, 3, 4].map((i) => `work/many/f${String(i).padStart(5, "0")}.png.locked`));
  assert.ok(kpa.partial_reasons.includes("4995 more files matched and were not checked: max_files is 5"), kpa.status_basis);
});

// ---- stream_kpa_check: the recipe is never left cut, nor beside an answer that says none was written ----

/** Three members of one PNG XORed with one 16-byte key: a literal key opens all three, and the recipe is written in a secret job. */
async function xorRecipeFamily(cwd: string): Promise<{ args: Doc; key: Buffer }> {
  const key = Buffer.from("8899aabbccddeeff0011223344556677", "hex");
  await mkdir(join(cwd, "work", "share"));
  for (const name of ["a.png.locked", "b.png.locked", "c.png.locked"]) {
    const plain = Buffer.concat([PNG, Buffer.alloc(400, name.charCodeAt(0))]);
    await writeFile(join(cwd, "work", "share", name), Buffer.from(plain.map((b, i) => b ^ key[i % 16]!)));
  }
  return { args: { dir: "work/share", key_sources: [{ hex: key.toString("hex") }], ciphers: ["xor"], derive: false }, key };
}

test("the recipe is written under a temporary name and given a free one; a stop then removes it, and a kill leaves only the .part file", { timeout: 300_000 }, async () => {
  const cwd = await sandbox();
  const { args, key } = await xorRecipeFamily(cwd);
  const plain = await measured(KPA, cwd, "j000001", args);
  assert.equal(plain.code, 0, plain.stdout.slice(0, 2000));
  assert.equal(plain.doc!.outcome, "one_rule_explains_every_member");
  assert.equal(plain.doc!.recipe_file, "store/jobs/j000001/out/stream-recipe.json");
  assert.deepEqual(await readdir(plain.out), ["stream-recipe.json"]);
  const recipe = JSON.parse(await readFile(join(plain.out, "stream-recipe.json"), "utf8")) as Doc;
  assert.equal(recipe.key.hex, key.toString("hex"));
  assert.equal(recipe.made_by, "stream_kpa_check/3");
  // A recipe already there is not replaced.
  const second = join(cwd, "store", "jobs", "j000002", "out");
  await mkdir(second, { recursive: true });
  await writeFile(join(second, "stream-recipe.json"), "not mine\n");
  const again = await measured(KPA, cwd, "j000002", args);
  assert.equal(again.doc!.recipe_file, "store/jobs/j000002/out/stream-recipe-2.json");
  assert.deepEqual((await readdir(again.out)).sort(), ["stream-recipe-2.json", "stream-recipe.json"]);
  assert.equal(await readFile(join(again.out, "stream-recipe.json"), "utf8"), "not mine\n");
  // A SIGTERM sent while the recipe is written is held, then answered: the recipe it had named is removed and the answer says so.
  const stopped = await measured(KPA, cwd, "j000003", args, "term-at-link");
  assert.doesNotMatch(stopped.stderr, /Traceback/);
  assert.equal(stopped.code, 143, stopped.stdout);
  assert.equal(stopped.doc!.interrupted, true);
  assert.match(stopped.doc!.status_basis, /no recipe was written/);
  assert.deepEqual(await readdir(stopped.out), [], "no recipe and no temporary file is left");
  // A kill no handler sees, during the write: the temporary file is left, whole up to the kill, and no stream-recipe.json, cut or not.
  const killed = await measured(KPA, cwd, "j000004", args, "kill-at-fsync");
  assert.equal(killed.code, -9);
  assert.equal(killed.stdout, "");
  const left = await readdir(killed.out);
  assert.deepEqual(left, [".stream-recipe.json.part"]);
  assert.ok((await stat(join(killed.out, left[0]!))).size > 0);
});

// ---- backup_destruction_correlate: one document at a time, and once per use ----

test("forty references to one 16 MiB document: read once, one parse held at a time, the others counted", { timeout: 300_000 }, async () => {
  const cwd = await sandbox();
  const n = Math.floor((16 << 20) / 3) - 40;
  const body = Buffer.concat([Buffer.from('{"parser":"backup_audit_normalise/2","status":"complete","events":['), Buffer.from("{},".repeat(n - 1)), Buffer.from("{}]}")]);
  assert.ok(body.length <= 16 << 20);
  await writeFile(join(cwd, "work", "audit.json"), body);
  // Before: each reference was parsed again while the one before was still held (two parses at once, 1036 MB for forty references).
  const run = await measured(CORRELATE, cwd, "j000001", { backup_audits: [...Array(40)].map(() => ({ host: "h1", file: "work/audit.json" })), max_seconds: 300 });
  assert.doesNotMatch(run.stderr, /Traceback/);
  assert.equal(run.code, 0, run.stdout.slice(0, 2000));
  assert.equal(run.doc!.status, "complete", run.doc!.status_basis);
  assert.deepEqual(run.doc!.inputs_read, { backup_audits: 1 });
  assert.deepEqual(run.doc!.inputs_named_again, { backup_audits: 39 });
  assert.ok(run.peak < 800e6, `peak resident memory ${run.peak} bytes`);
  assert.ok(run.seconds < 120, `${run.seconds} s`);
});
