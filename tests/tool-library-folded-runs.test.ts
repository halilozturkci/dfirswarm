/**
 * Tools folded into the library from two real runs on one published case (an
 * AD1 image, a Windows memory image and a capture): aes_schedule_scan and
 * aes_inverse_scan (key schedules in memory), encoded_literal_scan (a known
 * literal hidden in an encoding), marshal_inspect (a Python marshal stream,
 * read and never run) and destlist_v4 (a jump list's DestList stream). Each
 * was made general first: what the run's copy knew of its case is a parameter.
 *
 * Every fixture is built here, at test time, from the documented layouts: a
 * buffer holding a real AES key schedule (checked against node's own AES
 * first), text in each encoding, a marshal stream from the interpreter's own
 * marshal, a DestList entry laid out byte by byte. Nothing from a case is
 * read. Each tool is also given what it must say no to.
 */
import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { createCipheriv, createHash } from "node:crypto";
import { chmod, lstat, mkdir, mkdtemp, readdir, readFile, rm, stat, symlink, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "node:test";
import {
  decryptBlockEquivalent, encryptBlock, expandKey, inverseSchedule, keyFor, mixState, noise, roundKeys, reverseWords, SBOX,
} from "./aes-fixture.ts";
import { LIB, runPy } from "./tool-library-harness.ts";

type Run = { code: number | null; stdout: string; stderr: string };

async function inTemp(fn: (cwd: string) => Promise<void>): Promise<void> {
  const cwd = await mkdtemp(join(tmpdir(), "lib-folded-"));
  try {
    await mkdir(join(cwd, "work"), { recursive: true });
    await mkdir(join(cwd, "inputs"), { recursive: true });
    await fn(cwd);
  } finally {
    await rm(cwd, { recursive: true, force: true });
  }
}

function runNode(script: string, cwd: string, stdin: unknown, env: Record<string, string> = {}): Promise<Run> {
  return new Promise((resolve, reject) => {
    const child = spawn(process.execPath, [script], { cwd, env: { ...process.env, JOB_ID: "", OUT: "", AGENT_ID: "t1", ...env } });
    const out: Buffer[] = [];
    const err: Buffer[] = [];
    child.stdout.on("data", (c: Buffer) => out.push(c));
    child.stderr.on("data", (c: Buffer) => err.push(c));
    child.on("error", reject);
    child.on("close", (code) => resolve({ code, stdout: Buffer.concat(out).toString("utf8"), stderr: Buffer.concat(err).toString("utf8") }));
    child.stdin.end(JSON.stringify(stdin));
  });
}

const sha256 = (b: Buffer) => createHash("sha256").update(b).digest("hex");

function ok<T>(out: Run): T {
  assert.equal(out.code, 0, out.stderr + out.stdout);
  assert.doesNotMatch(out.stderr, /Traceback|Error:/);
  return JSON.parse(out.stdout) as T;
}
function refused(out: Run): { ok?: boolean; error: string } & Record<string, unknown> {
  assert.notEqual(out.code, 0, out.stdout);
  assert.doesNotMatch(out.stderr, /Traceback/);
  return JSON.parse(out.stdout);
}

// --- AES: the fixture is checked against node's own AES first ---------------------

test("the AES fixture is a real AES: node's cipher agrees with its schedule, and the inverse layout decrypts", () => {
  for (const bytes of [16, 32] as const) {
    const key = keyFor(bytes, "self");
    const plain = noise(16, "plain");
    const ref = createCipheriv(`aes-${bytes * 8}-ecb`, key, null);
    ref.setAutoPadding(false);
    const cipher = Buffer.concat([ref.update(plain), ref.final()]);
    const schedule = expandKey(key);
    assert.equal(schedule.length, bytes === 16 ? 176 : 240);
    assert.deepEqual(encryptBlock(plain, schedule), cipher, `${bytes * 8}-bit encryption with the fixture's schedule`);
    // The decryption schedule in the order a routine uses it: first round key
    // last, InvMixColumns on the middle ones, the original key at the end.
    const rks = roundKeys(schedule);
    const used = [rks[rks.length - 1], ...rks.slice(1, -1).reverse().map((k) => Buffer.from(mixState([...k], true))), rks[0]];
    assert.deepEqual(decryptBlockEquivalent(cipher, used), plain, `${bytes * 8}-bit equivalent inverse cipher`);
    const reversed = inverseSchedule(key, { reverseRounds: true, reverseWords: false });
    assert.deepEqual(reversed, Buffer.concat(used), "the reverse-order layout is the order the decryption uses");
  }
});

type Hit = { offset: number; key_bits: number; word_order: string; round_order?: string; key_file: string };
type Scan = { ok: boolean; hits: Hit[]; hit_count: number; complete: boolean; next_start?: number; scanned_to: number; result_file: string; window: { start: number; end: number }; prefilter_candidates: number; full_schedule_checks: number; seconds: number };

const SCHEDULE_TOOL = join(LIB, "aes_schedule_scan", "run.mjs");
const INVERSE_TOOL = join(LIB, "aes_inverse_scan", "run.mjs");

/** Noise with each piece planted at its offset. */
function plant(size: number, seed: string, pieces: Array<[number, Buffer]>): Buffer {
  const b = noise(size, seed);
  for (const [at, piece] of pieces) piece.copy(b, at);
  return b;
}

test("aes_schedule_scan finds AES-128 and AES-256 schedules at any alignment, in either word order, and prints no key", async () => {
  await inTemp(async (cwd) => {
    const k128 = keyFor(16, "a"), k256 = keyFor(32, "b"), k128w = keyFor(16, "c"), k256w = keyFor(32, "d");
    const placed: Array<[number, Buffer, number, string]> = [
      [1001, expandKey(k128), 128, "standard"],
      [20007, expandKey(k256), 256, "standard"],
      [30003, reverseWords(expandKey(k128w), true), 128, "reversed-each-32bit-word"],
      [45001, reverseWords(expandKey(k256w), true), 256, "reversed-each-32bit-word"],
    ];
    const image = plant(60000, "forward", placed.map(([at, b]) => [at, b]));
    await writeFile(join(cwd, "inputs", "mem.raw"), image);
    const before = sha256(await readFile(join(cwd, "inputs", "mem.raw")));

    const res = ok<Scan>(await runNode(SCHEDULE_TOOL, cwd, { path: "inputs/mem.raw", out_dir: "work/t1/aes" }));
    assert.equal(res.complete, true);
    assert.deepEqual(
      res.hits.map((h) => [h.offset, h.key_bits, h.word_order]),
      placed.map(([at, , bits, order]) => [at, bits, order]),
    );
    const keys = [k128, k256, k128w, k256w];
    for (const [i, h] of res.hits.entries()) {
      const file = join(cwd, "work", "t1", "aes", h.key_file);
      assert.deepEqual(await readFile(file), keys[i], "the key file holds the key");
      assert.equal((await stat(file)).mode & 0o077, 0, "a key file is private to its owner");
    }
    // A key is never printed, not as hex and not as base64.
    const out = (await runNode(SCHEDULE_TOOL, cwd, { path: "inputs/mem.raw", out_dir: "work/t1/aes" })).stdout;
    for (const k of keys) {
      assert.ok(!out.includes(k.toString("hex")) && !out.includes(k.toString("base64")), "the result must not carry a key");
    }
    assert.ok((await readFile(join(cwd, res.result_file), "utf8")).includes(res.hits[0].key_file), "the whole result is kept in out_dir and named");
    assert.equal(sha256(await readFile(join(cwd, "inputs", "mem.raw"))), before, "the source is read, never changed");
  });
});

test("aes_schedule_scan finds a schedule across chunk boundaries and says no to what is not a whole schedule", async () => {
  await inTemp(async (cwd) => {
    const key = keyFor(32, "edge");
    const schedule = expandKey(key);
    // Every offset of a small image, with a chunk size that puts the schedule across a boundary.
    const image = plant(4000, "edge", [[1500, schedule]]);
    await writeFile(join(cwd, "inputs", "edge.raw"), image);
    for (const chunk_bytes of [480, 1000, 1499, 1501, 4096]) {
      const res = ok<Scan>(await runNode(SCHEDULE_TOOL, cwd, { path: "inputs/edge.raw", out_dir: "work/t1/e", chunk_bytes }));
      assert.deepEqual(res.hits.map((h) => h.offset), [1500], `chunk ${chunk_bytes}`);
    }

    // A byte of the schedule changed: the relations that fail are the ones near the change, so try each region.
    for (const flip of [3, 20, 33, 40, 100, 160, 239]) {
      const bad = Buffer.from(image);
      bad[1500 + flip] ^= 0x01;
      await writeFile(join(cwd, "inputs", "bad.raw"), bad);
      const res = ok<Scan>(await runNode(SCHEDULE_TOOL, cwd, { path: "inputs/bad.raw", out_dir: "work/t1/bad" }));
      assert.equal(res.hit_count, 0, `a schedule with byte ${flip} changed is not a schedule`);
    }
    // A schedule that stops one byte short of its end, at the end of the file.
    await writeFile(join(cwd, "inputs", "short.raw"), image.subarray(0, 1500 + 239));
    assert.equal(ok<Scan>(await runNode(SCHEDULE_TOOL, cwd, { path: "inputs/short.raw", out_dir: "work/t1/short" })).hit_count, 0);
    // Zeros and noise hold none; the decryption layout is not this tool's.
    await writeFile(join(cwd, "inputs", "zero.raw"), Buffer.alloc(100000));
    assert.equal(ok<Scan>(await runNode(SCHEDULE_TOOL, cwd, { path: "inputs/zero.raw", out_dir: "work/t1/zero" })).hit_count, 0);
    await writeFile(join(cwd, "inputs", "noise.raw"), noise(200000, "only noise"));
    assert.equal(ok<Scan>(await runNode(SCHEDULE_TOOL, cwd, { path: "inputs/noise.raw", out_dir: "work/t1/noise" })).hit_count, 0);
    const inverse = plant(3000, "inv", [[777, inverseSchedule(keyFor(32, "inv"), { reverseRounds: true, reverseWords: false })]]);
    await writeFile(join(cwd, "inputs", "inverse.raw"), inverse);
    assert.equal(ok<Scan>(await runNode(SCHEDULE_TOOL, cwd, { path: "inputs/inverse.raw", out_dir: "work/t1/inv" })).hit_count, 0, "a decryption schedule is not an encryption schedule");
  });
});

test("aes_schedule_scan works a window and carries on where a call stopped, with no hit lost or doubled", async () => {
  await inTemp(async (cwd) => {
    const keys = [keyFor(16, "w1"), keyFor(32, "w2"), keyFor(16, "w3")];
    const offsets = [5000, 11990, 23000];
    const image = plant(40000, "window", keys.map((k, i) => [offsets[i], expandKey(k)] as [number, Buffer]));
    await writeFile(join(cwd, "inputs", "w.raw"), image);
    const call = (extra: Record<string, unknown>) => runNode(SCHEDULE_TOOL, cwd, { path: "inputs/w.raw", out_dir: "work/t1/w", ...extra });
    // Slices that cut inside the second schedule (11990..12230): it belongs to the slice it starts in.
    const a = ok<Scan>(await call({ start: 0, length: 12000 }));
    const b = ok<Scan>(await call({ start: 12000, length: 28000 }));
    assert.deepEqual(a.hits.map((h) => h.offset), [5000, 11990]);
    assert.deepEqual(b.hits.map((h) => h.offset), [23000]);
    assert.equal(a.complete, true);
    assert.deepEqual(a.window, { start: 0, end: 12000 });
    // A window starting inside a schedule does not see it.
    const inside = ok<Scan>(await call({ start: 5001, length: 1000 }));
    assert.equal(inside.hit_count, 0);
    // A budget that runs out after one chunk: the call says where to go on from, and going on finds the rest.
    let next = 0, found: number[] = [], calls = 0;
    for (;;) {
      const r = ok<Scan>(await call({ start: next, chunk_bytes: 2048, budget_seconds: 0.0000001 }));
      found = found.concat(r.hits.map((h) => h.offset));
      calls++;
      if (r.complete) break;
      assert.ok(r.next_start! > next, "every call makes progress");
      next = r.next_start!;
    }
    assert.deepEqual(found, offsets);
    assert.ok(calls > 3, `the budget cut the scan into pieces (${calls} calls)`);
    // Past the end, and empty.
    assert.equal(refused(await call({ start: 40001 })).ok, false);
    assert.equal(ok<Scan>(await call({ start: 40000 })).hit_count, 0);
  });
});

test("aes_schedule_scan and aes_inverse_scan refuse what they must: no file, a directory, an out_dir outside the run or under inputs", async () => {
  await inTemp(async (cwd) => {
    await writeFile(join(cwd, "inputs", "x.raw"), noise(1000, "x"));
    for (const tool of [SCHEDULE_TOOL, INVERSE_TOOL]) {
      assert.match(String(refused(await runNode(tool, cwd, {})).error), /path is required/);
      assert.match(String(refused(await runNode(tool, cwd, { path: "inputs/none.raw" })).error), /cannot read/);
      assert.match(String(refused(await runNode(tool, cwd, { path: "inputs" })).error), /not a regular file/);
      for (const out_dir of ["inputs/keys", "../outside", "/tmp/aes-outside", ".", "ledger/x", "tools/x"]) {
        const r = refused(await runNode(tool, cwd, { path: "inputs/x.raw", out_dir }));
        assert.match(String(r.error), /out_dir/, `${out_dir}: ${r.error}`);
      }
      assert.match(String(refused(await runNode(tool, cwd, { path: "inputs/x.raw", out_dir: "work/a", chunk_bytes: 10 })).error), /chunk_bytes/);
      assert.match(String(refused(await runNode(tool, cwd, "not an object" as unknown as object)).error), /path is required|arguments/);
    }
    // Where nothing is said, the output goes under work/quarantine/<agent>/.
    const r = ok<Scan>(await runNode(SCHEDULE_TOOL, cwd, { path: "inputs/x.raw" }));
    assert.match(r.result_file, /^work\/quarantine\/t1\/aes_schedule_scan\/aes_schedule_scan\.0\.json$/, "keys go where a handover package leaves things in the sandbox");
  });
});

test("aes_inverse_scan finds decryption schedules in all four layouts, for AES-128 and AES-256", async () => {
  await inTemp(async (cwd) => {
    const pieces: Array<[number, Buffer, number, string, string, Buffer]> = [];
    let at = 700;
    for (const bytes of [16, 32] as const) {
      for (const reverseRounds of [true, false]) {
        for (const rw of [false, true]) {
          const key = keyFor(bytes, `inv-${bytes}-${reverseRounds}-${rw}`);
          const sched = inverseSchedule(key, { reverseRounds, reverseWords: rw });
          pieces.push([at, sched, bytes * 8, reverseRounds ? "reversed" : "forward", rw ? "reversed-each-32bit-word" : "standard", key]);
          at += 1111 + (pieces.length % 5); // every alignment mod 5, and a different one each time
        }
      }
    }
    const image = plant(at + 2000, "inverse", pieces.map(([o, b]) => [o, b] as [number, Buffer]));
    await writeFile(join(cwd, "inputs", "mem.raw"), image);
    for (const chunk_bytes of [undefined, 513]) {
      const res = ok<Scan>(await runNode(INVERSE_TOOL, cwd, { path: "inputs/mem.raw", out_dir: "work/t1/inv", chunk_bytes }));
      assert.deepEqual(
        res.hits.map((h) => [h.offset, h.key_bits, h.round_order, h.word_order]),
        pieces.map(([o, , bits, rounds, words]) => [o, bits, rounds, words]),
        `chunk ${chunk_bytes}`,
      );
      for (const [i, h] of res.hits.entries()) {
        // The key it names is the encryption key the schedule came from.
        assert.deepEqual(await readFile(join(cwd, "work", "t1", "inv", h.key_file)), pieces[i][5]);
      }
      assert.ok(!JSON.stringify(res).includes(pieces[0][5].toString("hex")));
    }
  });
});

test("aes_inverse_scan says no to a schedule with a byte wrong, to an encryption schedule, to zeros and to noise", async () => {
  await inTemp(async (cwd) => {
    for (const bytes of [16, 32] as const) {
      const key = keyFor(bytes, `neg-${bytes}`);
      const sched = inverseSchedule(key, { reverseRounds: true, reverseWords: false });
      const image = plant(3000, `neg${bytes}`, [[900, sched]]);
      await writeFile(join(cwd, "inputs", "good.raw"), image);
      assert.equal(ok<Scan>(await runNode(INVERSE_TOOL, cwd, { path: "inputs/good.raw", out_dir: "work/t1/g" })).hit_count, 1);
      for (const flip of [0, 5, 17, 50, 100, sched.length - 17, sched.length - 1]) {
        const bad = Buffer.from(image);
        bad[900 + flip] ^= 0x40;
        await writeFile(join(cwd, "inputs", "bad.raw"), bad);
        assert.equal(ok<Scan>(await runNode(INVERSE_TOOL, cwd, { path: "inputs/bad.raw", out_dir: "work/t1/b" })).hit_count, 0, `${bytes * 8}-bit, byte ${flip} changed`);
      }
      const plain = plant(3000, `plain${bytes}`, [[900, expandKey(key)]]);
      await writeFile(join(cwd, "inputs", "plain.raw"), plain);
      assert.equal(ok<Scan>(await runNode(INVERSE_TOOL, cwd, { path: "inputs/plain.raw", out_dir: "work/t1/p" })).hit_count, 0, "an encryption schedule is not a decryption schedule");
    }
    await writeFile(join(cwd, "inputs", "zero.raw"), Buffer.alloc(100000));
    assert.equal(ok<Scan>(await runNode(INVERSE_TOOL, cwd, { path: "inputs/zero.raw", out_dir: "work/t1/z" })).hit_count, 0);
    await writeFile(join(cwd, "inputs", "noise.raw"), noise(300000, "noise for the inverse"));
    assert.equal(ok<Scan>(await runNode(INVERSE_TOOL, cwd, { path: "inputs/noise.raw", out_dir: "work/t1/n" })).hit_count, 0);
  });
});

test("both AES scanners say what to do about a key file in a handover, and keep their budget under the tool's own timeout", async () => {
  await inTemp(async (cwd) => {
    const key = keyFor(16, "note");
    await writeFile(join(cwd, "inputs", "n.raw"), plant(2000, "note", [[100, expandKey(key)], [900, inverseSchedule(keyFor(16, "note2"), { reverseRounds: true, reverseWords: false })]]));
    for (const tool of [SCHEDULE_TOOL, INVERSE_TOOL]) {
      const r = ok<Scan & { note: string; budget_seconds: number; out_dir: string }>(await runNode(tool, cwd, { path: "inputs/n.raw", budget_seconds: 100000 }));
      assert.equal(r.hit_count, 1);
      assert.equal(r.budget_seconds, 110, "a budget past the tool's 120 s timeout is brought down to what can be kept");
      assert.match(r.out_dir, /^work\/quarantine\/t1\//);
      assert.match(r.note, /work\/quarantine\/<agent>/);
      assert.match(r.note, /sensitive ledger entry that cites key_file/);
      assert.match(r.note, /secret_output/);
      // In a job the keys go to $OUT/quarantine/, which is where work/quarantine/<id>/ maps to.
      await mkdir(join(cwd, "store", "jobs", "j1", "out"), { recursive: true });
      const job = await new Promise<Run>((resolve, reject) => {
        const child = spawn(process.execPath, [tool], { cwd, env: { ...process.env, JOB_ID: "j1", OUT: join(cwd, "store", "jobs", "j1", "out"), AGENT_ID: "t1" } });
        const out: Buffer[] = [];
        child.stdout.on("data", (c: Buffer) => out.push(c));
        child.on("error", reject);
        child.on("close", (code) => resolve({ code, stdout: Buffer.concat(out).toString("utf8"), stderr: "" }));
        child.stdin.end(JSON.stringify({ path: "inputs/n.raw" }));
      });
      assert.match(ok<Scan>(job).result_file, /^store\/jobs\/j1\/out\/quarantine\//);
    }
  });
});

/** Every regular file under dir, as a path relative to dir, leaving out the subtrees in skip. */
async function filesUnder(dir: string, skip: string[]): Promise<string[]> {
  const found: string[] = [];
  for (const rel of await readdir(dir, { recursive: true })) {
    if (skip.some((s) => rel === s || rel.startsWith(`${s}/`))) continue;
    if ((await stat(join(dir, rel))).isFile()) found.push(rel);
  }
  return found.sort();
}

test("the AES scanners print and write no digest of a key: no 64-hex string, no key bytes and no digest in a name anywhere but the 0600 key files", async () => {
  const HIT_FIELDS = ["key_bits", "key_file", "offset", "offset_hex", "round_order", "schedule_bytes", "word_order"];
  for (const [tool, name] of [[SCHEDULE_TOOL, "aes_schedule_scan"], [INVERSE_TOOL, "aes_inverse_scan"]] as const) {
    for (const inJob of [false, true]) {
      await inTemp(async (cwd) => {
        const keys = [keyFor(16, `nd-${name}-a`), keyFor(32, `nd-${name}-b`), keyFor(16, `nd-${name}-c`), keyFor(32, `nd-${name}-d`)];
        const pieces: Array<[number, Buffer]> = tool === SCHEDULE_TOOL
          ? [[1001, expandKey(keys[0])], [5003, expandKey(keys[1])], [9007, reverseWords(expandKey(keys[2]), true)], [13001, reverseWords(expandKey(keys[3]), true)], [17011, expandKey(keys[0])]]
          : [[1001, inverseSchedule(keys[0], { reverseRounds: true, reverseWords: false })], [5003, inverseSchedule(keys[1], { reverseRounds: false, reverseWords: false })],
             [9007, inverseSchedule(keys[2], { reverseRounds: true, reverseWords: true })], [13001, inverseSchedule(keys[3], { reverseRounds: false, reverseWords: true })],
             [17011, inverseSchedule(keys[0], { reverseRounds: true, reverseWords: false })]];
        await writeFile(join(cwd, "inputs", "mem.raw"), plant(21000, `nd-${name}`, pieces));
        const env: Record<string, string> = {};
        if (inJob) {
          env.JOB_ID = "j1";
          env.OUT = join(cwd, "store", "jobs", "j1", "out");
          await mkdir(env.OUT, { recursive: true });
        }
        // Twice: a second run in the same directory writes no other file and breaks nothing.
        const runs = [await runNode(tool, cwd, { path: "inputs/mem.raw" }, env), await runNode(tool, cwd, { path: "inputs/mem.raw" }, env)];
        for (const r of runs) assert.equal(r.stderr, "", "nothing on stderr");
        const first = ok<Scan & { out_dir: string; note: string }>(runs[0]);
        assert.equal(ok<Scan>(runs[1]).hit_count, 5);
        assert.equal(first.hit_count, 5, "four keys, one of them at two offsets");

        // A hit says where, how big and which file; nothing that is a hash, a digest or a derived quantity of the key.
        for (const h of first.hits) {
          for (const field of Object.keys(h)) assert.ok(HIT_FIELDS.includes(field), `${name}: unexpected hit field ${field}`);
          assert.doesNotMatch(Object.keys(h).join(" "), /sha|digest|hash/i);
        }
        assert.match(first.note, /never a digest/);
        assert.match(first.note, /offset and key_file name/);
        assert.doesNotMatch(first.note, /sha-?256|ledger:|what to record in the ledger/i);

        // The key files: private, one per distinct key, holding the key and nothing else.
        const keyFiles = [...new Set(first.hits.map((h) => join(first.out_dir, h.key_file)))].sort();
        assert.equal(keyFiles.length, 4, "a key found twice has one file");
        const held: Buffer[] = [];
        for (const rel of keyFiles) {
          const mode = (await stat(join(cwd, rel))).mode;
          assert.equal(mode & 0o077, 0, `${rel} is private to its owner`);
          held.push(await readFile(join(cwd, rel)));
        }
        assert.deepEqual(held.map((b) => b.toString("hex")).sort(), keys.map((k) => k.toString("hex")).sort(), "the key files hold the four keys");

        // Everything else the run left, and what it printed: no key, in any spelling, and no digest, whole or in part.
        const digests = keys.map((k) => sha256(k));
        const names = await filesUnder(cwd, ["inputs"]);
        const others = names.filter((n) => !keyFiles.includes(n));
        assert.ok(others.some((n) => n.endsWith(".json")), "the whole result is kept beside the keys");
        const texts: Array<[string, Buffer]> = [["stdout", Buffer.from(runs[0].stdout)], ["stderr", Buffer.from(runs[0].stderr)], ["second stdout", Buffer.from(runs[1].stdout)]];
        for (const n of others) texts.push([n, await readFile(join(cwd, n))]);
        for (const [where, data] of texts) {
          const asText = data.toString("latin1");
          assert.doesNotMatch(asText, /[0-9a-fA-F]{64}/, `${where}: a 64-hex string`);
          for (const [i, k] of keys.entries()) {
            for (const form of [k, Buffer.from(k.toString("hex")), Buffer.from(k.toString("base64")), Buffer.from(k.toString("base64url")), Buffer.from(digests[i]), Buffer.from(digests[i], "hex"), Buffer.from(digests[i].slice(0, 16)), Buffer.from(digests[i].slice(0, 8))]) {
              assert.equal(data.indexOf(form), -1, `${where}: a key or a digest of one (${form.length} bytes)`);
            }
          }
        }
        // A path is no place for a digest either (the key file used to be named for the start of one).
        for (const n of names) {
          assert.doesNotMatch(n, /[0-9a-fA-F]{16}/, `${n}: a name that carries 16 hex digits`);
          for (const d of digests) assert.ok(!n.includes(d.slice(0, 8)), `${n}: a name that carries the start of a digest`);
        }
      });
    }
  }
});

/** The schedule of a key in the layout the given scanner reads. */
function aesPiece(tool: string, key: Buffer): Buffer {
  return tool === SCHEDULE_TOOL ? expandKey(key) : inverseSchedule(key, { reverseRounds: true, reverseWords: false });
}

test("the AES scanners give a key found in a later call the file an earlier call wrote, at another offset too", async () => {
  for (const tool of [SCHEDULE_TOOL, INVERSE_TOOL]) {
    await inTemp(async (cwd) => {
      const k128 = keyFor(16, "xw-a"), k256 = keyFor(32, "xw-b");
      // The same two keys at 1000 and 30000 (window 1 holds the first of each, window 2 the second), and a third key only late.
      const image = plant(60000, "xw", [[1000, aesPiece(tool, k128)], [2001, aesPiece(tool, k256)], [30000, aesPiece(tool, k128)], [31001, aesPiece(tool, k256)]]);
      await writeFile(join(cwd, "inputs", "mem.raw"), image);
      const one = ok<Scan>(await runNode(tool, cwd, { path: "inputs/mem.raw", out_dir: "work/t1/aes", start: 0, length: 10000 }));
      const two = ok<Scan>(await runNode(tool, cwd, { path: "inputs/mem.raw", out_dir: "work/t1/aes", start: 10000, length: 40000 }));
      assert.deepEqual(one.hits.map((h) => h.offset), [1000, 2001]);
      assert.deepEqual(two.hits.map((h) => h.offset), [30000, 31001]);
      assert.deepEqual(two.hits.map((h) => h.key_file), one.hits.map((h) => h.key_file), "the same key names the same file in the next call");
      const files = (await readdir(join(cwd, "work", "t1", "aes"))).filter((f) => f.startsWith("key-")).sort();
      assert.deepEqual(files, ["key-3e8-128.bin", "key-7d1-256.bin"], "two keys, two files, however many calls");
      // A same-size file of the same pattern that holds another key is passed over, not read as this key's.
      await writeFile(join(cwd, "work", "t1", "aes", "key-1-128.bin"), keyFor(16, "xw-other"), { mode: 0o600 });
      const three = ok<Scan>(await runNode(tool, cwd, { path: "inputs/mem.raw", out_dir: "work/t1/aes", start: 29000, length: 3000 }));
      assert.deepEqual(three.hits.map((h) => h.key_file), ["key-3e8-128.bin", "key-7d1-256.bin"]);
      assert.deepEqual(await readFile(join(cwd, "work", "t1", "aes", "key-1-128.bin")), keyFor(16, "xw-other"), "a file of another key is left as it was");
    });
  }
});

test("the AES scanners reuse a key file only when it is a plain file holding the key: a directory, a symlink or a wrong file at the name never costs a trace or a follow", async () => {
  for (const tool of [SCHEDULE_TOOL, INVERSE_TOOL]) {
    await inTemp(async (cwd) => {
      const kA = keyFor(16, "sq-a"), kB = keyFor(32, "sq-b"), kC = keyFor(16, "sq-c"), kD = keyFor(16, "sq-d");
      await writeFile(join(cwd, "inputs", "mem.raw"), plant(30000, "sq", [[1001, aesPiece(tool, kA)], [5003, aesPiece(tool, kB)], [9007, aesPiece(tool, kC)], [13001, aesPiece(tool, kD)]]));
      const dir = join(cwd, "work", "t1", "aes");
      await mkdir(dir, { recursive: true });
      // 0x3e9 = 1001: a directory at the name. 0x138b = 5003: a dangling symlink. 0x232f = 9007: a symlink to a world-readable
      // file that holds exactly the key. 0x34c9 = 13001: a plain file of the key with a loose mode.
      await mkdir(join(dir, "key-3e9-128.bin"));
      await symlink(join(cwd, "missing-target"), join(dir, "key-138b-256.bin"));
      const decoy = join(cwd, "decoy.bin");
      await writeFile(decoy, kC);
      await chmod(decoy, 0o644);
      await symlink(decoy, join(dir, "key-232f-128.bin"));
      await writeFile(join(dir, "key-34c9-128.bin"), kD, { mode: 0o644 });
      await chmod(join(dir, "key-34c9-128.bin"), 0o644);

      const res = await runNode(tool, cwd, { path: "inputs/mem.raw", out_dir: "work/t1/aes" });
      assert.equal(res.stderr, "", "no stack trace, nothing on stderr");
      const scan = ok<Scan>(res);
      assert.deepEqual(scan.hits.map((h) => [h.offset, h.key_file]), [
        [1001, "key-3e9-128-2.bin"],
        [5003, "key-138b-256-2.bin"],
        [9007, "key-232f-128-2.bin"],
        [13001, "key-34c9-128.bin"],
      ]);
      for (const [file, key] of [["key-3e9-128-2.bin", kA], ["key-138b-256-2.bin", kB], ["key-232f-128-2.bin", kC], ["key-34c9-128.bin", kD]] as const) {
        const st = await lstat(join(dir, file));
        assert.ok(st.isFile() && !st.isSymbolicLink(), `${file} is a plain file`);
        assert.deepEqual(await readFile(join(dir, file)), key);
        assert.equal(st.mode & 0o077, 0, `${file} is private to its owner, also when it was there before`);
      }
      assert.ok((await lstat(join(dir, "key-3e9-128.bin"))).isDirectory(), "the directory is left alone");
      assert.ok((await lstat(join(dir, "key-138b-256.bin"))).isSymbolicLink(), "the dangling symlink is left alone");
      assert.ok((await lstat(join(dir, "key-232f-128.bin"))).isSymbolicLink(), "the symlink is left alone");
      assert.equal((await stat(decoy)).mode & 0o777, 0o644, "what a symlink points at is never touched");
      // A second call changes nothing and finds the same names.
      const again = ok<Scan>(await runNode(tool, cwd, { path: "inputs/mem.raw", out_dir: "work/t1/aes" }));
      assert.deepEqual(again.hits.map((h) => h.key_file), scan.hits.map((h) => h.key_file));
      assert.deepEqual((await readdir(dir)).sort(), ["key-138b-256-2.bin", "key-138b-256.bin", "key-232f-128-2.bin", "key-232f-128.bin", "key-34c9-128.bin", "key-3e9-128-2.bin", "key-3e9-128.bin", `${tool === SCHEDULE_TOOL ? "aes_schedule_scan" : "aes_inverse_scan"}.0.json`].sort());
    });
  }
});

test("the AES scanners' manifests and the library README promise offsets and a key file, not a digest", async () => {
  const { readFileSync } = await import("node:fs");
  for (const name of ["aes_schedule_scan", "aes_inverse_scan"]) {
    const manifest = JSON.parse(readFileSync(join(LIB, name, "manifest.json"), "utf8")) as { description: string };
    assert.doesNotMatch(manifest.description, /sha-?256|hash/i, `${name}: the description`);
    assert.match(manifest.description, /offset,[^.]*, key file name\./);
    assert.ok(manifest.description.length <= 400, `${name}: the description fits the harness's 400 characters`);
    const script = readFileSync(join(LIB, name, "run.mjs"), "utf8");
    assert.doesNotMatch(script, /key_sha256|createHash|sha-?256/i, `${name}: the script keeps no digest of a key`);
  }
  const readme = readFileSync(join(LIB, "README.md"), "utf8");
  const section = readme.slice(readme.indexOf("- `aes_schedule_scan` and `aes_inverse_scan`"), readme.indexOf("- `encoded_literal_scan`"));
  assert.ok(section.length > 200, "found the AES entry");
  assert.doesNotMatch(section, /sha-?256/i);
  assert.match(section, /offset/);
  assert.match(section, /never a digest/);
});

test("aes_inverse_scan finds the schedule of a key built to zero the words its filter once skipped, and crosses zeros and sparse memory fast", async () => {
  await inTemp(async (cwd) => {
    // A key whose expansion has w5 = w8 = w9 = 0 (w1 = g2(w2^w3), w0 = w1 ^ g1(w3)): the three words of the AES-128
    // relation are all zero, which a zero-skip on those words would have taken for empty memory.
    const g = (w: number[], rcon: number) => [SBOX[w[1]] ^ rcon, SBOX[w[2]], SBOX[w[3]], SBOX[w[0]]];
    const xor = (a: number[], b: number[]) => a.map((v, i) => v ^ b[i]);
    const w2 = [0x11, 0x22, 0x33, 0x44], w3 = [0x55, 0x66, 0x77, 0x88];
    const w1 = g(xor(w2, w3), 2);
    const w0 = xor(w1, g(w3, 1));
    const crafted = Buffer.from([...w0, ...w1, ...w2, ...w3]);
    const sched = expandKey(crafted);
    for (const w of [5, 8, 9]) assert.deepEqual([...sched.subarray(4 * w, 4 * w + 4)], [0, 0, 0, 0], `w${w} of the crafted schedule`);
    await writeFile(join(cwd, "inputs", "crafted.raw"), plant(3000, "crafted", [[500, inverseSchedule(crafted, { reverseRounds: true, reverseWords: false })], [1500, inverseSchedule(crafted, { reverseRounds: false, reverseWords: true })]]));
    const r = ok<Scan>(await runNode(INVERSE_TOOL, cwd, { path: "inputs/crafted.raw", out_dir: "work/t1/c" }));
    assert.deepEqual(r.hits.map((h) => h.offset), [500, 1500]);
    for (const h of r.hits) assert.deepEqual(await readFile(join(cwd, "work", "t1", "c", h.key_file)), crafted, "both hits name a file that holds the crafted key");
    await writeFile(join(cwd, "inputs", "plain.raw"), plant(3000, "craftedp", [[700, sched]]));
    assert.deepEqual(ok<Scan>(await runNode(SCHEDULE_TOOL, cwd, { path: "inputs/plain.raw", out_dir: "work/t1/p" })).hits.map((h) => h.offset), [700]);

    // Zeros are crossed, and memory that is zeros but for a byte now and then costs no more than noise does.
    const sparse = Buffer.alloc(4 * 1024 * 1024);
    for (let i = 7; i < sparse.length; i += 301) sparse[i] = 1 + (i % 251);
    const keyed = Buffer.from(sparse);
    inverseSchedule(keyFor(32, "sparse"), { reverseRounds: true, reverseWords: false }).copy(keyed, 2_000_003);
    await writeFile(join(cwd, "inputs", "zeros.raw"), Buffer.alloc(32 * 1024 * 1024));
    await writeFile(join(cwd, "inputs", "sparse.raw"), keyed);
    // "Fast" is asked of the tool's own counters of work, which do not move with the machine's load: a wall-clock bound failed
    // here on a loaded runner without the scan having done any more. Zeros are crossed without a single candidate. The sparse
    // memory is the worst case the filter has (a nonzero byte every 301 bytes, so that the relation words are mostly zero and
    // pass the prefilter): at most 8 full schedule checks a position are possible (4 relations, 2 word orders) and this file costs
    // 4.4, so a bound of 5 holds the filter where it is. The scan also ends inside its own 90-second budget (`complete`), which is
    // the tool's own clock.
    for (const [name, want, size] of [["zeros", [], 32 * 1024 * 1024], ["sparse", [2_000_003], 4 * 1024 * 1024]] as const) {
      const z = ok<Scan>(await runNode(INVERSE_TOOL, cwd, { path: `inputs/${name}.raw`, out_dir: `work/t1/${name}` }));
      assert.deepEqual(z.hits.map((h) => h.offset), want, name);
      assert.equal(z.complete, true, `${name}: the scan ended inside its own budget`);
      if (name === "zeros") assert.deepEqual([z.prefilter_candidates, z.full_schedule_checks], [0, 0], "zeros are crossed, not tested");
      else assert.ok(z.full_schedule_checks <= 5 * size, `${name}: ${z.full_schedule_checks} full schedule checks over ${size} bytes`);
    }
  });
});

test("aes_inverse_scan carries on where a budget stopped it, and a window sees only what starts in it", async () => {
  await inTemp(async (cwd) => {
    const keys = [keyFor(32, "i1"), keyFor(16, "i2")];
    const offsets = [3000, 9000];
    const image = plant(14000, "iw", keys.map((k, i) => [offsets[i], inverseSchedule(k, { reverseRounds: i === 0, reverseWords: false })] as [number, Buffer]));
    await writeFile(join(cwd, "inputs", "w.raw"), image);
    let next = 0, found: number[] = [];
    for (;;) {
      const r = ok<Scan>(await runNode(INVERSE_TOOL, cwd, { path: "inputs/w.raw", out_dir: "work/t1/w", start: next, chunk_bytes: 1024, budget_seconds: 0.0000001 }));
      found = found.concat(r.hits.map((h) => h.offset));
      if (r.complete) break;
      next = r.next_start!;
    }
    assert.deepEqual(found, offsets);
    // A window that starts inside the first schedule does not see it, and sees the one that starts in it.
    const w = ok<Scan>(await runNode(INVERSE_TOOL, cwd, { path: "inputs/w.raw", out_dir: "work/t1/w", start: 3001, length: 8000 }));
    assert.deepEqual(w.hits.map((h) => h.offset), [9000]);
  });
});

// --- encoded_literal_scan ----------------------------------------------------------------

const LITERAL_TOOL = join(LIB, "encoded_literal_scan", "run.py");
const PY_ENV = { AGENT_ID: "t1", JOB_ID: "", OUT: "" };

const B32 = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
function base32(data: Buffer): string {
  let bits = "";
  for (const b of data) bits += b.toString(2).padStart(8, "0");
  let out = "";
  for (let i = 0; i < bits.length; i += 5) out += B32[parseInt(bits.slice(i, i + 5).padEnd(5, "0"), 2)];
  return out + "=".repeat((8 - (out.length % 8)) % 8);
}
const rot13 = (s: string) => s.replace(/[a-z]/gi, (c) => {
  const base = c <= "Z" ? 65 : 97;
  return String.fromCharCode(((c.charCodeAt(0) - base + 13) % 26) + base);
});
const utf16 = (s: string, order: "le" | "be") => {
  const le = Buffer.from(s, "utf16le");
  return order === "le" ? le : Buffer.from(le).swap16();
};
function utf32(s: string, order: "le" | "be"): Buffer {
  const cps = [...s].map((c) => c.codePointAt(0)!);
  const b = Buffer.alloc(cps.length * 4);
  cps.forEach((cp, i) => (order === "le" ? b.writeUInt32LE(cp, i * 4) : b.writeUInt32BE(cp, i * 4)));
  return b;
}
const asText = (s: string, enc: "utf-8" | "utf-16le" | "utf-16be") => (enc === "utf-8" ? Buffer.from(s, "utf8") : utf16(s, enc === "utf-16le" ? "le" : "be"));

type LitHit = { encoding: string; text_encoding: string; phase?: number; offset: number; candidates: string[]; status: string; context_capped?: boolean };
type LitResult = {
  ok: boolean; hit_count: number; literal_hits: number; candidates: string[]; complete: boolean; next_start?: number; result_file: string; scanned_to: number;
  hits?: LitHit[]; window: { start: number; end: number }; context_capped_hits: number; candidate_count: number; stopped_by?: string;
};
const wholeResult = async (cwd: string, r: LitResult): Promise<Required<Pick<LitResult, "hits">> & LitResult> => JSON.parse(await readFile(join(cwd, r.result_file), "utf8"));

const MARKER = "ACME-{";
const LITERAL = "ACME-{synthetic body value 42}";

test("encoded_literal_scan finds a literal in every encoding, at every phase, and reads only the literal out", async () => {
  await inTemp(async (cwd) => {
    const planted: Array<{ offset: number; name: string; encoding: string; text: string | null; phase?: number }> = [];
    const pieces: Array<[number, Buffer]> = [];
    let at = 500;
    const put = (data: Buffer, name: string, encoding: string, text: string | null, phase?: number) => {
      pieces.push([at, data]);
      planted.push({ offset: at, name, encoding, text, phase });
      at += data.length + 1700 + planted.length;
    };
    // The text around a literal in an encoded run must never be printed.
    const around = "BEFORE-THE-LITERAL ";
    const after = " AFTER-THE-LITERAL";
    for (const text of ["utf-8", "utf-16le", "utf-16be"] as const) {
      for (let pad = 0; pad < 3; pad++) {
        const plain = Buffer.concat([Buffer.alloc(pad, 0x7a), asText(around + LITERAL + after, text)]);
        put(Buffer.from(plain.toString("base64")), `base64 ${text} pad ${pad}`, "base64", text, pad);
      }
      for (let pad = 0; pad < 5; pad++) {
        const plain = Buffer.concat([Buffer.alloc(pad, 0x7a), asText(around + LITERAL + after, text)]);
        const b32 = base32(plain);
        put(Buffer.from(pad % 2 ? b32.toLowerCase() : b32), `base32 ${text} pad ${pad}`, "base32", text, pad);
      }
      put(Buffer.from(asText(LITERAL, text).toString("hex")), `hex ${text}`, "hex", text);
    }
    put(Buffer.from(rot13(LITERAL)), "rot13", "rot13", "utf-8");
    put(utf16(LITERAL, "le"), "utf-16le", "wide", "utf-16le");
    put(utf16(LITERAL, "be"), "utf-16be", "wide", "utf-16be");
    put(utf32(LITERAL, "le"), "utf-32le", "wide", "utf-32le");
    put(utf32(LITERAL, "be"), "utf-32be", "wide", "utf-32be");
    const image = plant(at + 3000, "literals", pieces);
    await writeFile(join(cwd, "inputs", "mem.raw"), image);

    const raw = await runPy(LITERAL_TOOL, cwd, { path: "inputs/mem.raw", marker: MARKER, closer: "}" }, undefined, PY_ENV);
    const res = ok<LitResult>(raw);
    assert.equal(res.complete, true);
    assert.deepEqual(res.candidates, [LITERAL], "the literal, and nothing else");
    const full = await wholeResult(cwd, res);
    for (const p of planted) {
      // The marker lies some way into the encoded text (after the words put in front of it), at most 120 characters on.
      const h = full.hits.find((x) => x.offset >= p.offset && x.offset <= p.offset + 120 && x.encoding === p.encoding && x.candidates.includes(LITERAL) && (p.text === null || x.text_encoding === p.text));
      assert.ok(h, `${p.name} at ${p.offset} was not found with its literal`);
      assert.equal(h.status === "literal" || h.status === "complete", true, `${p.name}: ${h.status}`);
    }
    // What lies around the literal in the encoded text is not decoded into the answer or the file.
    assert.ok(!raw.stdout.includes("BEFORE-THE-LITERAL") && !raw.stdout.includes("AFTER-THE-LITERAL"));
    assert.ok(!JSON.stringify(full).includes("BEFORE-THE-LITERAL"), "the result file holds the literal, not what surrounds it");
    assert.ok(raw.stdout.includes(MARKER), "the marker is the caller's own word");
    // The source is read, never changed.
    assert.deepEqual(await readFile(join(cwd, "inputs", "mem.raw")), image);
    assert.match(res.result_file, /^work\/t1\/encoded_literal_scan\/encoded_literal_scan-[0-9a-f]{12}\.json$/);
  });
});

test("encoded_literal_scan finds a literal across chunk boundaries once, and carries on where a budget stopped it", async () => {
  await inTemp(async (cwd) => {
    const pieces: Array<[number, Buffer]> = [];
    const offsets: number[] = [];
    // Pieces of different encodings that straddle each multiple of the chunk size.
    const chunk = 4096;
    const make: Array<(s: string) => Buffer> = [
      (s) => Buffer.from(Buffer.from(s).toString("base64")),
      (s) => Buffer.from(base32(Buffer.from(s))),
      (s) => Buffer.from(Buffer.from(s).toString("hex")),
      (s) => utf16(s, "le"),
      (s) => utf32(s, "be"),
    ];
    make.forEach((f, i) => {
      const data = f(LITERAL);
      const at = chunk * (i + 1) - Math.floor(data.length / 2) + i;
      pieces.push([at, data]);
      offsets.push(at);
    });
    const image = plant(chunk * 8, "chunky", pieces);
    await writeFile(join(cwd, "inputs", "c.raw"), image);
    const base = { path: "inputs/c.raw", marker: MARKER, closer: "}", chunk_bytes: chunk };
    const res = ok<LitResult>(await runPy(LITERAL_TOOL, cwd, base, undefined, PY_ENV));
    const full = await wholeResult(cwd, res);
    const lit = full.hits.filter((h) => h.candidates.length);
    assert.equal(lit.length, make.length, `one literal each, none twice: ${JSON.stringify(lit.map((h) => [h.encoding, h.offset]))}`);
    for (const o of offsets) assert.ok(lit.some((h) => Math.abs(h.offset - o) <= 4), `the literal at ${o}`);
    // The same by budget: every call makes progress, and the pieces together are the whole.
    let next = 0;
    const seen: number[] = [];
    let calls = 0;
    for (;;) {
      const r = ok<LitResult>(await runPy(LITERAL_TOOL, cwd, { ...base, start: next, budget_seconds: 0.0000001 }, undefined, PY_ENV));
      seen.push(...(await wholeResult(cwd, r)).hits.filter((h) => h.candidates.length).map((h) => h.offset));
      calls++;
      if (r.complete) break;
      assert.ok(r.next_start! > next);
      next = r.next_start!;
    }
    assert.ok(calls >= 8, "a call ends after a chunk or between two hits, never later");
    assert.deepEqual(seen.sort((a, b) => a - b), lit.map((h) => h.offset).sort((a, b) => a - b));
  });
});

test("encoded_literal_scan says no to a marker with no closer in reach, to the wrong shape, and to noise", async () => {
  await inTemp(async (cwd) => {
    const call = async (marker: string, extra: Record<string, unknown> = {}) =>
      ok<LitResult>(await runPy(LITERAL_TOOL, cwd, { path: "inputs/n.raw", marker, closer: "}", ...extra }, undefined, PY_ENV));
    const long = `${MARKER}${"x".repeat(400)}}`;            // closer 400 characters on
    const noClose = `${MARKER}no end at all`;
    const newline = `${MARKER}two\nlines}`;
    const pieces: Array<[number, Buffer]> = [
      [1000, Buffer.from(Buffer.from(noClose).toString("base64"))],
      [3000, Buffer.from(Buffer.from(long).toString("base64"))],
      [6000, Buffer.from(Buffer.from(newline).toString("base64"))],
      [9000, utf16(`${MARKER}${"y".repeat(400)}`, "le")],          // a body that never closes within max_body
      [9900, utf32(newline, "le")],                                  // a line break in the body
      [10500, Buffer.concat([utf32(MARKER, "le"), Buffer.from([0x00, 0x00, 0x11, 0x00]), utf32("}", "le")])], // a scalar past U+10FFFF
    ];
    const tail = utf16(`${MARKER}ab`, "be");                          // the file ends before the literal does
    const image = Buffer.concat([plant(14000, "neg", pieces), tail]);
    await writeFile(join(cwd, "inputs", "n.raw"), image);
    const res = await call(MARKER);
    assert.equal(res.literal_hits, 0, JSON.stringify(res.candidates));
    assert.deepEqual(res.candidates, []);
    assert.ok(res.hit_count >= 6, "the markers themselves are listed, by offset alone");
    const full = await wholeResult(cwd, res);
    for (const h of full.hits) assert.deepEqual(h.candidates, []);
    const statuses = new Set(full.hits.filter((h) => h.encoding === "wide").map((h) => h.status));
    for (const s of ["no_closer_within_max_body", "excluded_character", "invalid_scalar", "truncated"]) assert.ok(statuses.has(s), `${s} in ${[...statuses]}`);
    // The long one is found when the body is allowed to be that long.
    const longer = await call(MARKER, { max_body: 500 });
    assert.deepEqual(longer.candidates, [long]);
    // Noise holds none. A 4-character marker still anchors a search that finds nothing in it.
    await writeFile(join(cwd, "inputs", "noise.raw"), noise(300000, "literal noise"));
    for (const marker of ["ZQXW", "ACME-{"]) {
      const r = ok<LitResult>(await runPy(LITERAL_TOOL, cwd, { path: "inputs/noise.raw", marker }, undefined, PY_ENV));
      assert.equal(r.candidate_count, 0, marker);
    }
  });
});

test("encoded_literal_scan takes any marker and closer, only the encodings asked for, and refuses what it cannot search", async () => {
  await inTemp(async (cwd) => {
    const lit = "user=ana@example.org;";
    await writeFile(join(cwd, "inputs", "a.raw"), plant(20000, "any", [
      [100, Buffer.from(Buffer.from(lit).toString("base64"))],
      [5000, Buffer.from(Buffer.from(lit).toString("hex"))],
      [9000, utf16(lit, "le")],
    ]));
    const only = async (encodings: string[]) =>
      ok<LitResult>(await runPy(LITERAL_TOOL, cwd, { path: "inputs/a.raw", marker: "user=", closer: ";", encodings }, undefined, PY_ENV));
    assert.deepEqual((await only(["base64"])).candidates, [lit]);
    const hexOnly = await wholeResult(cwd, await only(["hex"]));
    assert.deepEqual(hexOnly.hits.filter((h) => h.candidates.length).map((h) => h.encoding), ["hex"]);
    const wideOnly = await wholeResult(cwd, await only(["wide"]));
    assert.deepEqual(wideOnly.hits.filter((h) => h.candidates.length).map((h) => h.offset), [9000]);
    assert.equal((await only(["base32"])).literal_hits, 0, "an encoding not present is not found");
    // Refusals say what and why.
    const bad = async (args: Record<string, unknown>) => refused(await runPy(LITERAL_TOOL, cwd, { path: "inputs/a.raw", ...args }, undefined, PY_ENV));
    assert.match(String((await bad({})).error), /marker is required/);
    assert.match(String((await bad({ marker: "abc" })).error), /marker must be 4 to 64/);
    assert.match(String((await bad({ marker: "abéd" })).error), /marker must be 4 to 64/);
    assert.match(String((await bad({ marker: "abcd", closer: "" })).error), /closer must be 1 to 16/);
    assert.match(String((await bad({ marker: "abcd", encodings: ["rot47"] })).error), /encodings is a list/);
    assert.match(String((await bad({ marker: "abcd", max_body: 0 })).error), /max_body/);
    assert.match(String((await bad({ marker: "abcd", out_dir: "inputs/x" })).error), /out_dir/);
    assert.match(String((await bad({ marker: "abcd", out_dir: "../x" })).error), /out_dir/);
    assert.match(String((await bad({ marker: "abcd", start: 99999 })).error), /past the end/);
    assert.match(String(refused(await runPy(LITERAL_TOOL, cwd, { path: "inputs/none.raw", marker: "abcd" }, undefined, PY_ENV)).error), /regular file/);
  });
});

test("encoded_literal_scan stops inside a chunk that holds more hits than it was told to take, and loses none by going on", async () => {
  await inTemp(async (cwd) => {
    const unit = Buffer.from(Buffer.from(`${MARKER}pathological body}`).toString("base64"));
    const repeat = (bytes: number) => Buffer.concat(Array.from({ length: Math.ceil(bytes / unit.length) }, () => unit)).subarray(0, bytes);
    // One mebibyte of base64 text that is the marker's text over and over: tens of thousands of hits in one chunk.
    await writeFile(join(cwd, "inputs", "everywhere.raw"), repeat(1024 * 1024));
    for (const chunk_bytes of [1024 * 1024, undefined]) {
      const began = Date.now();
      const r = ok<LitResult>(await runPy(LITERAL_TOOL, cwd, { path: "inputs/everywhere.raw", marker: MARKER, encodings: ["base64"], max_hits: 10, chunk_bytes }, undefined, PY_ENV));
      assert.ok(Date.now() - began < 30_000, `the call came back in ${Date.now() - began} ms, not after every hit of the chunk`);
      assert.equal(r.complete, false);
      assert.equal(r.stopped_by, "max_hits");
      assert.ok(r.hit_count >= 10 && r.hit_count < 10 + 8, `${r.hit_count} hits held for a cap of 10`);
      assert.ok(r.next_start! > 0 && r.next_start! < 4096, "it stops between two hits, near where it began");
      assert.match(String((r as unknown as { stopped_hint: string }).stopped_hint), /start=next_start/);
      assert.ok((await stat(join(cwd, r.result_file))).size > 0, "the partial result is on disk and named");
    }
    // The budget is kept inside a chunk too.
    const began = Date.now();
    const b = ok<LitResult>(await runPy(LITERAL_TOOL, cwd, { path: "inputs/everywhere.raw", marker: MARKER, encodings: ["base64"], budget_seconds: 0.0000001, chunk_bytes: 1024 * 1024 }, undefined, PY_ENV));
    assert.ok(Date.now() - began < 30_000);
    assert.equal(b.complete, false);
    assert.equal(b.stopped_by, "budget_seconds");
    assert.ok(b.hit_count >= 1, "a call that stops on its budget has still made progress");

    // Going on from each stop reaches the end, and the hits together are the single pass's, none twice.
    await writeFile(join(cwd, "inputs", "dense.raw"), repeat(40_000));
    const every = async (extra: Record<string, unknown>) => {
      const offsets: number[] = [];
      let next = 0, calls = 0;
      for (;;) {
        const r = ok<LitResult>(await runPy(LITERAL_TOOL, cwd, { path: "inputs/dense.raw", marker: MARKER, encodings: ["base64"], start: next, ...extra }, undefined, PY_ENV));
        offsets.push(...(await wholeResult(cwd, r)).hits.map((h) => h.offset));
        calls++;
        if (r.complete) return { offsets, calls };
        assert.ok(r.next_start! > next, "every call makes progress");
        next = r.next_start!;
      }
    };
    const single = await every({});
    const stepped = await every({ max_hits: 100, chunk_bytes: 8192 });
    assert.equal(single.calls, 1);
    assert.ok(stepped.calls > 3, `${stepped.calls} calls`);
    assert.ok(single.offsets.length > 500);
    assert.deepEqual(stepped.offsets.sort((a, c) => a - c), single.offsets.sort((a, c) => a - c));
    assert.equal(new Set(stepped.offsets).size, stepped.offsets.length, "no hit twice");
  });
});

test("encoded_literal_scan finds a marker whose fixed characters are + or / in the URL-safe alphabet too", async () => {
  await inTemp(async (cwd) => {
    const lit = ">>>>?? body;";
    for (const [name, text] of [["standard", Buffer.from(lit).toString("base64")], ["url", Buffer.from(lit).toString("base64url")]]) {
      await writeFile(join(cwd, "inputs", `${name}.raw`), plant(4000, name, [[300, Buffer.from(text)]]));
      const r = ok<LitResult>(await runPy(LITERAL_TOOL, cwd, { path: `inputs/${name}.raw`, marker: ">>>>", closer: ";", encodings: ["base64"] }, undefined, PY_ENV));
      assert.deepEqual(r.candidates, [lit], name);
    }
  });
});

test("encoded_literal_scan says when the encoded text around a hit runs past what it read", async () => {
  await inTemp(async (cwd) => {
    // A base64 text of 60 000 characters with the literal in the middle: 8192 characters a side are read, and no more.
    const lit = Buffer.from(`${MARKER}in a long run}`);
    const text = Buffer.concat([noise(22000, "long-before"), lit, noise(22000, "long-after")]).toString("base64");
    await writeFile(join(cwd, "inputs", "long.raw"), Buffer.from(text));
    const res = ok<LitResult>(await runPy(LITERAL_TOOL, cwd, { path: "inputs/long.raw", marker: MARKER, encodings: ["base64"] }, undefined, PY_ENV));
    assert.deepEqual(res.candidates, [lit.toString()]);
    assert.equal(res.context_capped_hits, res.literal_hits, "every hit says its context was cut");
    assert.ok(res.literal_hits >= 1);
    // A short run is not capped.
    await writeFile(join(cwd, "inputs", "short.raw"), Buffer.from(Buffer.from(lit).toString("base64")));
    assert.equal(ok<LitResult>(await runPy(LITERAL_TOOL, cwd, { path: "inputs/short.raw", marker: MARKER, encodings: ["base64"] }, undefined, PY_ENV)).context_capped_hits, 0);
  });
});

test("encoded_literal_scan keeps a body that is not ASCII, and stops where it is told when a marker is everywhere", async () => {
  await inTemp(async (cwd) => {
    const lit = "ACME-{caf\u00e9 \u65e5\u672c}";
    await writeFile(join(cwd, "inputs", "u.raw"), plant(9000, "unicode", [
      [100, Buffer.from(Buffer.from(lit, "utf8").toString("base64"))],
      [3000, Buffer.from(Buffer.from(lit, "utf8").toString("hex"))],
      [5000, utf16(lit, "be")],
    ]));
    const res = ok<LitResult>(await runPy(LITERAL_TOOL, cwd, { path: "inputs/u.raw", marker: MARKER }, undefined, PY_ENV));
    assert.deepEqual(res.candidates, [lit]);
    assert.ok(res.literal_hits >= 3);
    // A marker that is everywhere is not a search: it stops at a chunk boundary, says why, and goes on from there.
    const many = Buffer.from(`${MARKER}x} `.repeat(3000));
    await writeFile(join(cwd, "inputs", "many.raw"), many);
    const base = { path: "inputs/many.raw", marker: MARKER, encodings: ["wide", "rot13"], chunk_bytes: 4096 };
    let r = ok<LitResult & { stopped_by?: string }>(await runPy(LITERAL_TOOL, cwd, { ...base, max_hits: 1 }, undefined, PY_ENV));
    assert.equal(r.complete, true, "plain text holds the marker in no encoding this file is searched in: nothing to stop for");
    // Four hundred copies, each followed by two bytes of text, so that no copy reads as another at an odd offset.
    const utf = Buffer.concat(Array.from({ length: 400 }, () => Buffer.concat([utf16(`${MARKER}x}`, "le"), Buffer.from("ZZ")])));
    await writeFile(join(cwd, "inputs", "wide.raw"), Buffer.concat([utf, Buffer.alloc(8000)]));
    r = ok<LitResult & { stopped_by?: string }>(await runPy(LITERAL_TOOL, cwd, { path: "inputs/wide.raw", marker: MARKER, encodings: ["wide"], chunk_bytes: 4096, max_hits: 10 }, undefined, PY_ENV));
    assert.equal(r.complete, false);
    assert.equal(r.stopped_by, "max_hits");
    assert.ok(r.next_start! > 0 && r.next_start! < 8000 + utf.length);
    // Going on from there reaches the end; together the hits are all of them.
    let next = 0, total = 0, calls = 0;
    for (;;) {
      const c = ok<LitResult>(await runPy(LITERAL_TOOL, cwd, { path: "inputs/wide.raw", marker: MARKER, encodings: ["wide"], chunk_bytes: 4096, max_hits: 10, start: next }, undefined, PY_ENV));
      total += c.hit_count;
      calls++;
      if (c.complete) break;
      next = c.next_start!;
    }
    assert.equal(total, 400);
    assert.ok(calls >= 2);
  });
});

// --- marshal_inspect ---------------------------------------------------------------------

const MARSHAL_TOOL = join(LIB, "marshal_inspect", "run.py");

/** Run a python3 snippet (the test's own, for building a fixture) and return what it wrote to stdout. */
function pyOut(code: string, args: string[] = [], stdin = ""): Promise<Buffer> {
  return new Promise((resolve, reject) => {
    const child = spawn("python3", ["-c", code, ...args]);
    const out: Buffer[] = [];
    const err: Buffer[] = [];
    child.stdout.on("data", (c: Buffer) => out.push(c));
    child.stderr.on("data", (c: Buffer) => err.push(c));
    child.on("error", reject);
    child.on("close", (rc) => (rc === 0 ? resolve(Buffer.concat(out)) : reject(new Error(`python3 exited ${rc}: ${Buffer.concat(err)}`))));
    child.stdin.end(stdin);
  });
}
const pyVersion = JSON.parse((await pyOut("import sys, json; print(json.dumps(sys.version_info[:2]))")).toString()) as [number, number];
const HAS_311_LAYOUT = pyVersion[0] === 3 && pyVersion[1] >= 11 && pyVersion[1] <= 13;

type MCode = {
  code: number; name: string; qualname: string; filename: string; firstlineno: number; argcount: number; posonlyargcount: number; kwonlyargcount: number;
  flags: number; flag_names: string[]; names: unknown; consts: unknown[]; bytecode_bytes: number; bytecode_sha256: string; bytecode_hex?: string; stream_start: number;
};
type MResult = {
  ok: boolean; error?: string; stopped_at?: number; code_objects: number; objects: number; references: number; consumed_bytes: number; trailing_bytes: number;
  codes: MCode[]; root: unknown; result_file: string; source: { stream_offset: number; pyc_header?: Record<string, unknown> }; max_depth: number;
};
type Truth = { name: string; qualname: string; firstlineno: number; argcount: number; posonlyargcount: number; kwonlyargcount: number; flags: number; names: string[]; bytecode: string; strings: string[] };

const SOURCE = [
  "import os, sys",
  "SECRET_TABLE = ('alpha', b'\\x00\\x01raw', 3.5, 10**25, None, True)",
  "def first(a, b=2, *rest, **kw):",
  "    return os.path.join(a, 'tail-' + str(b) + 'a constant longer than the twelve characters shown')",
  "class Holder:",
  "    def method(self, x):",
  "        return lambda y: x + y + len('inner-constant')",
  "async def waits(n):",
  "    return n",
  "open('PWNED-BY-EXECUTION', 'w').write('x')",
].join("\n");

// Writes inputs/m.bin (a marshal stream) and inputs/m.pyc (the same behind a .pyc header) in the directory it is given,
// and prints what the interpreter itself says each code object is.
const BUILD_STREAM = `
import marshal, sys, json, importlib.util, os
os.chdir(sys.argv[1])
src = sys.stdin.read()
code = compile(src, "<synthetic>", "exec")
def walk(c, out):
    out.append({"name": c.co_name, "qualname": c.co_qualname, "firstlineno": c.co_firstlineno, "argcount": c.co_argcount,
                "posonlyargcount": c.co_posonlyargcount, "kwonlyargcount": c.co_kwonlyargcount, "flags": c.co_flags,
                "names": list(c.co_names), "bytecode": c.co_code.hex(), "strings": [k for k in c.co_consts if isinstance(k, str)]})
    for k in c.co_consts:
        if hasattr(k, "co_code"): walk(k, out)
    return out
data = marshal.dumps(code)
open("inputs/m.bin", "wb").write(data)
header = importlib.util.MAGIC_NUMBER + (0).to_bytes(4, "little") + (1760000000).to_bytes(4, "little") + len(src).to_bytes(4, "little")
open("inputs/m.pyc", "wb").write(header + data)
print(json.dumps(walk(code, [])))
`;

test("marshal_inspect reads a real stream: every code object, its bytecode, names and constants, and runs none of it", async (t) => {
  if (!HAS_311_LAYOUT) return t.skip(`needs CPython 3.11 to 3.13 to build a stream; this is ${pyVersion.join(".")}`);
  await inTemp(async (cwd) => {
    const truth = JSON.parse((await pyOut(BUILD_STREAM, [cwd], SOURCE)).toString()) as Truth[];
    for (const file of ["m.bin", "m.pyc"]) {
      const res = ok<MResult>(await runPy(MARSHAL_TOOL, cwd, { path: `inputs/${file}`, preview: 12 }, undefined, PY_ENV));
      assert.equal(res.ok, true);
      assert.equal(res.code_objects, truth.length);
      assert.equal(res.trailing_bytes, 0, "the whole stream is accounted for");
      assert.equal(res.source.stream_offset, file === "m.pyc" ? 16 : 0);
      if (file === "m.pyc") {
        assert.equal(res.source.pyc_header?.source_mtime, new Date(1760000000 * 1000).toISOString().replace(/\.\d+Z$/, "Z"));
        assert.equal(res.source.pyc_header?.source_size, SOURCE.length);
      }
      const whole = JSON.parse(await readFile(join(cwd, res.result_file), "utf8")) as MResult;
      for (const want of truth) {
        const got = whole.codes.find((c) => c.qualname === want.qualname)!;
        assert.ok(got, `${want.qualname} is listed`);
        assert.equal(got.name, want.name);
        assert.equal(got.firstlineno, want.firstlineno);
        assert.equal(got.argcount, want.argcount);
        assert.equal(got.posonlyargcount, want.posonlyargcount);
        assert.equal(got.kwonlyargcount, want.kwonlyargcount);
        assert.equal(got.flags, want.flags);
        assert.equal(got.filename, "<synthetic>");
        assert.equal(got.bytecode_hex, want.bytecode, `${want.qualname}: the bytecode is the interpreter's own`);
        assert.equal(got.bytecode_sha256, sha256(Buffer.from(want.bytecode, "hex")));
        assert.equal(got.bytecode_bytes, want.bytecode.length / 2);
        assert.deepEqual(got.names, want.names);
        for (const s of want.strings) assert.ok(JSON.stringify(got.consts).includes(JSON.stringify(s).slice(1, -1)), `${want.qualname}: constant ${s}`);
      }
      assert.ok(whole.codes.find((c) => c.name === "first")!.flag_names.includes("VARARGS"));
      assert.ok(whole.codes.find((c) => c.name === "waits")!.flag_names.includes("COROUTINE"));
      // The answer shortens a long string and keeps the whole in the file; only the file holds the bytecode.
      const answer = res.codes.find((c) => c.name === "first")!;
      assert.equal(answer.bytecode_hex, undefined);
      assert.ok(JSON.stringify(answer.consts).includes('"shown":12'), "a long constant is shown by its start, and says so");
      assert.ok(JSON.stringify(whole.codes.find((c) => c.name === "first")!.consts).includes("a constant longer than the twelve characters shown"));
    }
    // Nothing of it ran: the source opens a file when run, and the tool did not.
    await assert.rejects(stat(join(cwd, "PWNED-BY-EXECUTION")), /ENOENT/);
    // An older .pyc magic is named and refused; a stream over max_bytes is refused.
    const stream = await readFile(join(cwd, "inputs", "m.bin"));
    await writeFile(join(cwd, "inputs", "old.pyc"), Buffer.concat([Buffer.from([0x6f, 0x0d, 0x0d, 0x0a]), Buffer.alloc(12), stream]));
    assert.match(String(refused(await runPy(MARSHAL_TOOL, cwd, { path: "inputs/old.pyc" }, undefined, PY_ENV)).error), /older than 3\.11/);
    assert.match(String(refused(await runPy(MARSHAL_TOOL, cwd, { path: "inputs/m.bin", max_bytes: 100 }, undefined, PY_ENV)).error), /over max_bytes/);
    // A stream carved out of something bigger: given at its offset, with bytes after it.
    await writeFile(join(cwd, "inputs", "carved.bin"), Buffer.concat([Buffer.from("JUNKJUNKJUNK"), stream, Buffer.from("TRAILING")]));
    const carved = ok<MResult>(await runPy(MARSHAL_TOOL, cwd, { path: "inputs/carved.bin", offset: 12 }, undefined, PY_ENV));
    assert.equal(carved.code_objects, truth.length);
    assert.equal(carved.trailing_bytes, 8);
    assert.equal(carved.codes[0].stream_start, 12);
    // A stream cut in the middle names where, and still says what it read whole before that.
    await writeFile(join(cwd, "inputs", "cut.bin"), stream.subarray(0, stream.length - 40));
    const cut = refused(await runPy(MARSHAL_TOOL, cwd, { path: "inputs/cut.bin" }, undefined, PY_ENV)) as unknown as MResult;
    assert.equal(cut.ok, false);
    assert.match(String(cut.error), /cut short|cannot fit/);
    assert.equal(typeof cut.stopped_at, "number");
  });
});

test("marshal_inspect reads data objects of every kind, names a reference without following it, and is bounded", async () => {
  await inTemp(async (cwd) => {
    const data = await pyOut(`
import marshal, sys
shared = ("shared", "tuple", 1)
big = tuple(range(40))
obj = {"ints": (1, -2, 2**40, -(10**30)), "floats": (0.5, float("inf")), "complex": 1 + 2j, "text": "caf\\u00e9", "bytes": b"\\x00\\xffraw",
       "none": None, "bools": (True, False), "sets": ({1, 2}, frozenset({3})), "ell": Ellipsis, "shared": [shared, shared], "big": [big, big],
       "list": [1, [2, [3]]]}
sys.stdout.buffer.write(marshal.dumps(obj, 4))
`);
    await writeFile(join(cwd, "inputs", "data.bin"), data);
    const res = ok<MResult>(await runPy(MARSHAL_TOOL, cwd, { path: "inputs/data.bin" }, undefined, PY_ENV));
    assert.equal(res.trailing_bytes, 0);
    assert.equal(res.code_objects, 0);
    const file = await readFile(join(cwd, res.result_file), "utf8");
    const root = JSON.parse(file).root as { dict: Array<[string, unknown]> };
    const get = (k: string) => root.dict.find(([key]) => key === k)![1];
    assert.deepEqual((get("ints") as unknown[]).slice(0, 3), [1, -2, 2 ** 40]);
    assert.ok(file.includes("-1000000000000000000000000000000"), "a long integer is kept whole");
    assert.deepEqual(get("floats"), [0.5, { float: "inf" }]);
    assert.deepEqual(get("complex"), { complex: [1, 2] });
    assert.equal(get("text"), "caf\u00e9");
    assert.deepEqual(get("bytes"), { bytes: 5, hex: "00ff726177" });
    assert.equal(get("none"), null);
    assert.deepEqual(get("bools"), [true, false]);
    assert.deepEqual(get("ell"), { const: "Ellipsis" });
    assert.deepEqual((get("shared") as { list: unknown[] }).list, [["shared", "tuple", 1], ["shared", "tuple", 1]], "a small tuple referred to again is shown where it is referred to");
    const big = (get("big") as { list: unknown[] }).list;
    const first = big[0] as { tuple: number[]; ref: number };
    assert.equal(first.tuple.length, 40, "a large tuple is shown whole where the stream defines it, with its reference number");
    assert.deepEqual(big[1], { ref: first.ref }, "its second appearance is its reference number, not a second copy");
    assert.deepEqual(get("list"), { list: [1, { list: [2, { list: [3] }] }] });

    // Damaged and hostile streams end with a named reason, not a traceback or an allocation.
    const u32 = (n: number) => { const b = Buffer.alloc(4); b.writeInt32LE(n); return b; };
    const bad = async (name: string, bytes: Buffer, want: RegExp, args: Record<string, unknown> = {}) => {
      await writeFile(join(cwd, "inputs", `${name}.bin`), bytes);
      const r = refused(await runPy(MARSHAL_TOOL, cwd, { path: `inputs/${name}.bin`, ...args }, undefined, PY_ENV)) as unknown as MResult;
      assert.equal(r.ok, false, name);
      assert.match(String(r.error), want, `${name}: ${r.error}`);
      return r;
    };
    await bad("count", Buffer.concat([Buffer.from("("), u32(0x7fffffff)]), /cannot fit/);
    await bad("negative", Buffer.concat([Buffer.from("["), u32(-5)]), /cannot fit/);
    await bad("type", Buffer.from([0x7e, 0, 0, 0]), /not one this reader knows/);
    await bad("ref", Buffer.concat([Buffer.from("("), u32(1), Buffer.from("r"), u32(7)]), /reference to object 7/);
    await bad("deep", Buffer.concat([...Array.from({ length: 300 }, () => Buffer.concat([Buffer.from("["), u32(1)])), Buffer.from("N")]), /nesting deeper than 200/);
    await bad("long", Buffer.concat([Buffer.from("l"), u32(2), Buffer.from([0xff, 0xff, 0x01, 0x00])]), /out of range/);
    await bad("empty", Buffer.alloc(0), /cut short/);
    // A container that holds itself is named, not followed.
    await writeFile(join(cwd, "inputs", "self.bin"), Buffer.concat([Buffer.from([0x80 | "[".charCodeAt(0)]), u32(1), Buffer.from("r"), u32(0)]));
    const self = ok<MResult>(await runPy(MARSHAL_TOOL, cwd, { path: "inputs/self.bin" }, undefined, PY_ENV));
    assert.deepEqual(self.root, { list: [{ ref: 0 }], ref: 0 });
    // The same small tuple referred to forty times over, each level twice the last: the result stays small.
    const levels: Buffer[] = [Buffer.concat([Buffer.from([0x80 | ")".charCodeAt(0)]), Buffer.from([0])])];
    for (let i = 0; i < 40; i++) levels.push(Buffer.concat([Buffer.from([0x80 | ")".charCodeAt(0)]), Buffer.from([2]), Buffer.from("r"), u32(i), Buffer.from("r"), u32(i)]));
    await writeFile(join(cwd, "inputs", "laughs.bin"), Buffer.concat([Buffer.from("("), u32(levels.length), ...levels]));
    const laughs = ok<MResult>(await runPy(MARSHAL_TOOL, cwd, { path: "inputs/laughs.bin" }, undefined, PY_ENV));
    assert.ok((await stat(join(cwd, laughs.result_file))).size < 200_000, "forty doublings did not become a trillion nodes");
    // One long text referred to two thousand times shows as two thousand copies of it: refused, not written.
    const text = "x".repeat(100_000);
    const shared = Buffer.concat([
      Buffer.from("("), u32(2001),
      Buffer.from([0x80 | "u".charCodeAt(0)]), u32(text.length), Buffer.from(text),
      ...Array.from({ length: 2000 }, () => Buffer.concat([Buffer.from("r"), u32(0)])),
    ]);
    await writeFile(join(cwd, "inputs", "shared.bin"), shared);
    assert.match(String(refused(await runPy(MARSHAL_TOOL, cwd, { path: "inputs/shared.bin" }, undefined, PY_ENV)).error), /shares text or numbers/);
    // A long integer of many digits is built in a step a digit and shown in hex; it does not hang or fail on the digit limit.
    const digits = 20_000;
    const longInt = Buffer.concat([Buffer.from("l"), u32(digits), Buffer.concat(Array.from({ length: digits }, (_, i) => { const b = Buffer.alloc(2); b.writeUInt16LE(i % 2 ? 0x7fff : 0x0001); return b; }))]);
    await writeFile(join(cwd, "inputs", "longint.bin"), longInt);
    const li = ok<MResult>(await runPy(MARSHAL_TOOL, cwd, { path: "inputs/longint.bin" }, undefined, PY_ENV));
    const shownInt = li.root as { int_bits: number; hex: string };
    assert.equal(shownInt.int_bits, 15 * digits, "the top digit is 0x7fff, which fills its fifteen bits");
    assert.match(shownInt.hex, /^0x[0-9a-f]+$/);
    // Refusals before reading: no file, a bad out_dir, bad numbers.
    assert.match(String(refused(await runPy(MARSHAL_TOOL, cwd, {}, undefined, PY_ENV)).error), /path is required/);
    assert.match(String(refused(await runPy(MARSHAL_TOOL, cwd, { path: "inputs/data.bin", out_dir: "inputs/o" }, undefined, PY_ENV)).error), /out_dir/);
    assert.match(String(refused(await runPy(MARSHAL_TOOL, cwd, { path: "inputs/data.bin", offset: 10_000_000 }, undefined, PY_ENV)).error), /past the end/);
    assert.match(String(refused(await runPy(MARSHAL_TOOL, cwd, { path: "inputs/data.bin", preview: 2 }, undefined, PY_ENV)).error), /preview/);
  });
});

// --- destlist_v4 -------------------------------------------------------------------------

const DESTLIST_TOOL = join(LIB, "destlist_v4", "run.py");
const filetime = (iso: string) => (BigInt(Date.parse(iso)) + 11644473600000n) * 10000n;

/** One version-4 DestList entry: a 130-byte fixed part, the path as UTF-16LE, four bytes after it. */
function destEntry(o: { id: number; host?: string; time?: string; pin?: number; path: string }): Buffer {
  const fixed = Buffer.alloc(130);
  fixed.write(o.host ?? "WS-TEST-01", 72, "ascii");
  fixed.writeUInt32LE(o.id, 88);
  fixed.writeUInt32LE(0xdeadbeef, 92); // the dword after the entry number is not part of it
  fixed.writeBigUInt64LE(o.time ? filetime(o.time) : 0n, 100);
  fixed.writeInt32LE(o.pin ?? -1, 108);
  fixed.writeUInt16LE(o.path.length, 128);
  return Buffer.concat([fixed, Buffer.from(o.path, "utf16le"), Buffer.alloc(4)]);
}
const destHeader = (version: number, entries: number, pinned: number) => {
  const h = Buffer.alloc(32);
  h.writeUInt32LE(version, 0);
  h.writeUInt32LE(entries, 4);
  h.writeUInt32LE(pinned, 8);
  return h;
};

type Dest = {
  version: number; entries_claimed: number; entries_read: number; pinned_claimed: number; problems: string[]; matched: number; returned: number; truncated: boolean;
  all_results?: string; end_offset: number; trailing_bytes: number; empty?: boolean;
  entries: Array<{ n: number; offset: number; entry_id: number; hostname: string; last_access: string | null; filetime: number; pin: number; pinned: boolean; path: string; path_offset: number }>;
};

test("destlist_v4 reads the entries of a version 4 DestList stream, and says where each lies", async () => {
  await inTemp(async (cwd) => {
    const e1 = destEntry({ id: 7, time: "2026-03-04T05:06:07.5Z", pin: 0, path: "C:\\Users\\someone\\Documents\\Report \u00e9.docx" });
    const e2 = destEntry({ id: 9, host: "OTHER-HOST", time: "2025-12-31T23:59:59Z", path: "\\\\server\\share\\file.txt" });
    const e3 = destEntry({ id: 12, path: "" });
    const stream = Buffer.concat([destHeader(4, 3, 1), e1, e2, e3]);
    await writeFile(join(cwd, "inputs", "DestList"), stream);
    const res = ok<Dest>(await runPy(DESTLIST_TOOL, cwd, { path: "inputs/DestList" }, undefined, PY_ENV));
    assert.equal(res.version, 4);
    assert.equal(res.entries_claimed, 3);
    assert.equal(res.pinned_claimed, 1);
    assert.equal(res.entries_read, 3);
    assert.deepEqual(res.problems, []);
    assert.equal(res.trailing_bytes, 0);
    assert.equal(res.end_offset, stream.length);
    const [a, b, c] = res.entries;
    assert.equal(a.offset, 32);
    assert.equal(a.entry_id, 7);
    assert.equal(a.hostname, "WS-TEST-01");
    assert.equal(a.last_access, "2026-03-04T05:06:07.500000Z");
    assert.equal(a.filetime, Number(filetime("2026-03-04T05:06:07.5Z")));
    assert.equal(a.pin, 0);
    assert.equal(a.pinned, true);
    assert.equal(a.path, "C:\\Users\\someone\\Documents\\Report \u00e9.docx");
    assert.equal(a.path_offset, 32 + 130);
    assert.equal(b.offset, 32 + e1.length, "the next entry starts after the path and its four bytes");
    assert.equal(b.hostname, "OTHER-HOST");
    assert.equal(b.last_access, "2025-12-31T23:59:59Z");
    assert.equal(b.pinned, false);
    assert.equal(b.path, "\\\\server\\share\\file.txt");
    assert.equal(c.last_access, null, "a zero FILETIME is no time at all");
    assert.equal(c.path, "");
    // The same stream behind other bytes, by offset; with bytes after it.
    await writeFile(join(cwd, "inputs", "carved"), Buffer.concat([Buffer.from("PREFIX--"), stream, Buffer.from("tail")]));
    const carved = ok<Dest>(await runPy(DESTLIST_TOOL, cwd, { path: "inputs/carved", offset: 8 }, undefined, PY_ENV));
    assert.deepEqual(carved.entries.map((e) => e.path), res.entries.map((e) => e.path));
    assert.equal(carved.entries[0].offset, 8 + 32);
    assert.equal(carved.trailing_bytes, 4);
    assert.match(carved.problems.join(), /4 byte\(s\) follow the last entry/);
  });
});

test("destlist_v4 pages without cutting: every entry is in the file the answer names", async () => {
  await inTemp(async (cwd) => {
    const n = 25;
    const entries = Array.from({ length: n }, (_, i) => destEntry({ id: i + 1, time: "2026-01-01T00:00:00Z", path: `C:\\dir\\file${i + 1}.txt` }));
    await writeFile(join(cwd, "inputs", "DestList"), Buffer.concat([destHeader(4, n, 0), ...entries]));
    const res = ok<Dest>(await runPy(DESTLIST_TOOL, cwd, { path: "inputs/DestList", limit: 5 }, undefined, PY_ENV));
    assert.equal(res.matched, n);
    assert.equal(res.returned, 5);
    assert.equal(res.truncated, true);
    assert.match(String(res.all_results), /^work\/t1\/tool-output\/destlist_v4-[0-9a-f]{16}\.jsonl$/);
    const kept = (await readFile(join(cwd, res.all_results!), "utf8")).trimEnd().split("\n").map((l) => JSON.parse(l) as Dest["entries"][number]);
    assert.deepEqual(kept.map((e) => e.path), Array.from({ length: n }, (_, i) => `C:\\dir\\file${i + 1}.txt`));
  });
});

test("destlist_v4 reads as far as a damaged stream goes, and refuses what is not version 4", async () => {
  await inTemp(async (cwd) => {
    const e1 = destEntry({ id: 1, time: "2026-01-01T00:00:00Z", path: "C:\\one.txt" });
    const second = "C:\\two-two-two.txt";
    const e2 = destEntry({ id: 2, time: "2026-01-02T00:00:00Z", path: second });
    const w = (name: string, b: Buffer) => writeFile(join(cwd, "inputs", name), b);
    // Cut in the middle of the second entry's path.
    await w("cut", Buffer.concat([destHeader(4, 2, 0), e1, e2.subarray(0, 130 + 6)]));
    let res = ok<Dest>(await runPy(DESTLIST_TOOL, cwd, { path: "inputs/cut" }, undefined, PY_ENV));
    assert.equal(res.entries_read, 1);
    assert.deepEqual(res.entries.map((e) => e.path), ["C:\\one.txt"]);
    assert.match(res.problems.join(), new RegExp(`entry 2 claims a path of ${second.length} characters, which does not fit`));
    // The header counts more entries than the stream holds.
    await w("short", Buffer.concat([destHeader(4, 5, 0), e1, e2]));
    res = ok<Dest>(await runPy(DESTLIST_TOOL, cwd, { path: "inputs/short" }, undefined, PY_ENV));
    assert.equal(res.entries_read, 2);
    assert.match(res.problems.join(), /entry 3 is cut short/);
    // An entry that says its path is huge.
    const huge = destEntry({ id: 3, path: "x" });
    huge.writeUInt16LE(60000, 128);
    await w("huge", Buffer.concat([destHeader(4, 1, 0), huge]));
    res = ok<Dest>(await runPy(DESTLIST_TOOL, cwd, { path: "inputs/huge" }, undefined, PY_ENV));
    assert.equal(res.entries_read, 0);
    assert.match(res.problems.join(), /does not fit/);
    // An empty stream is a jump list with nothing in it.
    await w("empty", Buffer.alloc(0));
    res = ok<Dest>(await runPy(DESTLIST_TOOL, cwd, { path: "inputs/empty" }, undefined, PY_ENV));
    assert.equal(res.empty, true);
    assert.deepEqual(res.entries, []);
    // Other versions, the compound file whole, and a stream shorter than its header are named and refused.
    for (const version of [1, 3, 5]) {
      await w(`v${version}`, Buffer.concat([destHeader(version, 1, 0), e1]));
      assert.match(String(refused(await runPy(DESTLIST_TOOL, cwd, { path: `inputs/v${version}` }, undefined, PY_ENV)).error), new RegExp(`version ${version} is not one this reads`));
    }
    await w("ole", Buffer.concat([Buffer.from("d0cf11e0a1b11ae1", "hex"), Buffer.alloc(600)]));
    assert.match(String(refused(await runPy(DESTLIST_TOOL, cwd, { path: "inputs/ole" }, undefined, PY_ENV)).error), /OLE compound file/);
    await w("tiny", Buffer.alloc(10, 4));
    assert.match(String(refused(await runPy(DESTLIST_TOOL, cwd, { path: "inputs/tiny" }, undefined, PY_ENV)).error), /shorter than its 32-byte header/);
    assert.match(String(refused(await runPy(DESTLIST_TOOL, cwd, {}, undefined, PY_ENV)).error), /path is required/);
    assert.match(String(refused(await runPy(DESTLIST_TOOL, cwd, { path: "inputs/none" }, undefined, PY_ENV)).error), /cannot read/);
    assert.match(String(refused(await runPy(DESTLIST_TOOL, cwd, { path: "inputs/short", offset: 100000 }, undefined, PY_ENV)).error), /past the end/);
    assert.match(String(refused(await runPy(DESTLIST_TOOL, cwd, { path: "inputs/short", max_bytes: 40 }, undefined, PY_ENV)).error), /over max_bytes/);
    assert.match(String(refused(await runPy(DESTLIST_TOOL, cwd, { path: "inputs/short", limit: 0 }, undefined, PY_ENV)).error), /limit/);
  });
});
