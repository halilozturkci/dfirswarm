/**
 * ransomware-response: cipher_state_scan, stream_kpa_check and family_decrypt under hostile parameters, a stop signal and their own clocks.
 *
 *   - Hostile parameters, driven from the manifests as tests/tool-contract-hostile.test.ts does for the base tools: for every parameter a
 *     value of the wrong type, a string with a NUL, a lone surrogate, 300 characters, a huge integer, a nested list, an object and null, each
 *     in an otherwise sensible call, in a secret-output job. Every answer is one JSON object with `status` and `status_basis`, no traceback,
 *     in time. Hostile sources and recipes (the nested objects the manifest cannot describe) get the same treatment by hand.
 *   - A stop signal (SIGTERM, SIGINT, SIGHUP) in the middle of the work ends each tool with ONE JSON document and exit 128 + the signal.
 *     family_decrypt's is a truthful partial: the members decrypted before the stop are counted and keep their files and receipts, the file
 *     being written is removed.
 *   - The tools' own clocks: a scan that runs out of time is partial and says the offset it reached; a decrypt that runs out of time removes
 *     the partial file and lists the member as not decrypted.
 */
import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { randomBytes } from "node:crypto";
import { mkdir, mkdtemp, readFile, readdir, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { after, test } from "node:test";
import { PYTHON3 } from "./host-gates.ts";
import { PACK } from "./ransomware-pack-harness.ts";

const TOOLS = ["cipher_state_scan", "stream_kpa_check", "family_decrypt"] as const;
const script = (tool: string): string => join(PACK, tool, "run.py");
const LIMIT_MS = 30_000;
type Doc = Record<string, any>;
type Ran = { code: number | null; signal: string | null; stdout: string; stderr: string; killed: boolean };

const dirs: string[] = [];
after(async () => {
  for (const d of dirs) await rm(d, { recursive: true, force: true });
});

function run(tool: string, cwd: string, out: string, args: unknown, signalAfter?: { signal: NodeJS.Signals; when: (stdoutSoFar: string) => boolean | Promise<boolean>; ms: number }): Promise<Ran> {
  return new Promise((resolve) => {
    const child = spawn(PYTHON3, [script(tool)], { cwd, env: { ...process.env, AGENT_ID: "s1", JOB_ID: "j000001", OUT: out, SECRET_OUTPUT: "1" } });
    const so: Buffer[] = [];
    const se: Buffer[] = [];
    let killed = false;
    const timer = setTimeout(() => {
      killed = true;
      child.kill("SIGKILL");
    }, LIMIT_MS);
    let poll: NodeJS.Timeout | undefined;
    if (signalAfter) {
      const started = Date.now();
      poll = setInterval(async () => {
        if (Date.now() - started >= signalAfter.ms && (await signalAfter.when(Buffer.concat(so).toString("utf8")))) {
          clearInterval(poll);
          child.kill(signalAfter.signal);
        }
      }, 20);
    }
    child.stdout.on("data", (c: Buffer) => so.push(c));
    child.stderr.on("data", (c: Buffer) => se.push(c));
    child.on("error", () => undefined);
    child.on("close", (code, signal) => {
      clearTimeout(timer);
      if (poll) clearInterval(poll);
      resolve({ code, signal, stdout: Buffer.concat(so).toString("utf8"), stderr: Buffer.concat(se).toString("utf8"), killed });
    });
    child.stdin.on("error", () => undefined);
    child.stdin.end(typeof args === "string" ? args : JSON.stringify(args));
  });
}

/** Why an answer is a crash, or null: the contract is one JSON object with the status pair, and no traceback. */
function crash(r: Ran): string | null {
  if (r.killed) return `no answer in ${LIMIT_MS / 1000} s`;
  if (/Traceback/.test(r.stderr)) return `a traceback: ${r.stderr.trim().split("\n").pop()?.slice(0, 160)}`;
  if (r.signal) return `killed by ${r.signal}`;
  let doc: Doc;
  try {
    doc = JSON.parse(r.stdout.trim());
  } catch {
    return `stdout is not one JSON document: ${r.stdout.slice(0, 120)}`;
  }
  if (!doc || typeof doc !== "object" || Array.isArray(doc)) return "stdout is not a JSON object";
  if (!["complete", "partial", "failed"].includes(doc.status) || typeof doc.status_basis !== "string") return "the answer has no status and status_basis";
  if (r.code !== 0 && doc.status !== "failed") return `exit ${r.code} with status ${doc.status}`;
  return null;
}

const nest = (n: number): unknown => (n === 0 ? [] : [nest(n - 1)]);
const HOSTILE: Array<[string, unknown]> = [
  ["a list", [1]], ["an object", { a: 1 }], ["a number", 5], ["a float", 1.5], ["true", true], ["null", null], ["the empty string", ""],
  ["a NUL", "a\u0000b"], ["a lone surrogate", "x\udcffy"], ["300 characters", "n".repeat(300)], ["a huge integer", 10 ** 30], ["a negative integer", -1],
  ["a nested list", nest(40)], ["a list of strings", ["a", "b"]], ["a dot-dot path", "../../x"], ["an absolute path", "/proc/self/mem"], ["a list of objects", [{ hex: "zz" }, { slice: 3 }, {}]],
];

async function fixture(): Promise<{ cwd: string; out: () => Promise<string>; recipe: Doc }> {
  const cwd = await mkdtemp(join(tmpdir(), "rw-hostile-"));
  dirs.push(cwd);
  await mkdir(join(cwd, "work", "fam"), { recursive: true });
  await writeFile(join(cwd, "work", "dump.bin"), Buffer.concat([randomBytes(5000), Buffer.from("expand 32-byte k"), randomBytes(48), randomBytes(5000)]));
  for (const name of ["a.png.locked", "b.pdf.locked", "c.docx.locked"]) await writeFile(join(cwd, "work", "fam", name), randomBytes(700));
  const recipe = { recipe: "stream-family/1", key: { slice: "tail", length: 32, skip: 0, xor_hex: "11".repeat(32) }, variants: [{ cipher: "chacha20-ietf", counter: 0, nonce: { hex: "00".repeat(12) } }],
    assignments: {}, header_bytes: 0, trailer_bytes: 32, member_suffix: ".locked" };
  await writeFile(join(cwd, "work", "recipe.json"), JSON.stringify(recipe));
  let n = 0;
  const out = async (): Promise<string> => {
    const dir = join(cwd, "out", String(++n));
    await mkdir(dir, { recursive: true });
    return dir;
  };
  return { cwd, out, recipe };
}

const BASE: Record<(typeof TOOLS)[number], Doc> = {
  cipher_state_scan: { file: "work/dump.bin" },
  stream_kpa_check: { dir: "work/fam", key_sources: [{ slice: "tail", length: 32 }], nonce_sources: [{ hex: "00".repeat(12) }] },
  family_decrypt: { dir: "work/fam", recipe_file: "work/recipe.json" },
};

async function pool<T>(items: T[], width: number, fn: (item: T) => Promise<void>): Promise<void> {
  let next = 0;
  await Promise.all(Array.from({ length: width }, async () => {
    while (next < items.length) await fn(items[next++]!);
  }));
}

test("every parameter of the three tools, given a hostile value, ends in one JSON answer with a status, and no traceback", { timeout: 900_000 }, async () => {
  const fx = await fixture();
  const cases: Array<{ tool: (typeof TOOLS)[number]; args: Doc; label: string }> = [];
  for (const tool of TOOLS) {
    const manifest = JSON.parse(await readFile(join(PACK, tool, "manifest.json"), "utf8")) as { params: Record<string, unknown> };
    for (const param of Object.keys(manifest.params)) {
      for (const [label, value] of HOSTILE) {
        const args: Doc = { ...BASE[tool] };
        // The two ways to name the members, and the two ways to give a recipe, exclude each other: a hostile value takes the place of its pair.
        if (param === "files") delete args.dir;
        if (param === "recipe") delete args.recipe_file;
        args[param] = value;
        cases.push({ tool, args, label: `${tool} ${param} = ${label}` });
      }
    }
    cases.push({ tool, args: {}, label: `${tool} with no arguments` });
    for (const text of ["", "not json", "[1, 2]", "null", "{\"file\": ", "[".repeat(100_000)]) cases.push({ tool, args: text as unknown as Doc, label: `${tool} stdin ${JSON.stringify(text.slice(0, 12))}` });
  }
  // What the manifests cannot describe: the objects inside sources and recipes.
  const sources: unknown[] = [
    [{ hex: "zz" }], [{ hex: "abc" }], [{ hex: "00".repeat(5000) }], [{ file: "work/nope", length: 4 }], [{ file: "work/dump.bin" }], [{ file: "work/dump.bin", offset: 10 ** 30, length: 4 }],
    [{ file: "work/dump.bin", offset: 99_999_999, length: 32 }], [{ file: "work", length: 4 }], [{ candidates: "work/dump.bin" }], [{ candidates: "work/nope" }], [{ candidates: "work" }],
    [{ slice: "middle", length: 4 }], [{ slice: "tail" }], [{ slice: "tail", length: 0 }], [{ slice: "tail", length: 32, skip: -1 }], [{ slice: "tail", length: 32, xor: "aa" }],
    [{ slice: "tail", length: 32, xor: { hex: "aa" } }], [{ slice: "tail", length: 32, xor: { hex: "aa", file: "x" } }], [{ slice: "tail", length: 4096, skip: 1 << 20 }], [{ hex: "00", file: "x" }],
    [{}], [null], [[]], ["x"], Array.from({ length: 33 }, () => ({ hex: "00" })), [{ slice: "head", length: 32, xor: { file: "a\u0000b", length: 32 } }], [{ file: "x\udcffy", length: 4 }],
  ];
  for (const s of sources) {
    cases.push({ tool: "stream_kpa_check", args: { ...BASE.stream_kpa_check, key_sources: s }, label: `stream_kpa_check key_sources = ${JSON.stringify(s).slice(0, 70)}` });
    cases.push({ tool: "stream_kpa_check", args: { ...BASE.stream_kpa_check, nonce_sources: s }, label: `stream_kpa_check nonce_sources = ${JSON.stringify(s).slice(0, 70)}` });
  }
  for (const magics of [{ "": "00" }, { png: "zz" }, { png: { hex: "00", offset: 64 } }, { png: { offset: 1 } }, { "a/b": "00" }, { png: null }, { png: { hex: "00".repeat(65) } }]) {
    cases.push({ tool: "stream_kpa_check", args: { ...BASE.stream_kpa_check, magics }, label: `stream_kpa_check magics = ${JSON.stringify(magics)}` });
  }
  for (const extra of [{ counters: [] }, { counters: [-1] }, { counters: [1.5] }, { counters: [true] }, { counters: Array.from({ length: 9 }, (_, i) => i) }, { ciphers: ["des"] }, { ciphers: [] }, { glob: "a/b" }, { glob: "[" }, { files: [] }, { files: ["work/fam/a.png.locked", 5] }, { max_trials: 1 }]) {
    cases.push({ tool: "stream_kpa_check", args: { ...BASE.stream_kpa_check, ...extra }, label: `stream_kpa_check ${JSON.stringify(extra)}` });
  }
  const r = fx.recipe;
  const recipes: unknown[] = [
    { ...r, recipe: "other/1" }, { ...r, key: null }, { ...r, key: { hex: "zz" } }, { ...r, key: { slice: "tail", length: 10 ** 30 } }, { ...r, key: { slice: "tail", length: 32, xor_hex: "11" } },
    { ...r, key: { hex: "00".repeat(5) } }, { ...r, variants: [] }, { ...r, variants: [{ cipher: "des" }] }, { ...r, variants: [{ cipher: "rc4", nonce: { hex: "00" } }] },
    { ...r, variants: [{ cipher: "aes-ctr", counter: 0, nonce: null }] }, { ...r, variants: [{ cipher: "aes-ctr", counter: -1, nonce: { hex: "00".repeat(12) } }] },
    { ...r, variants: [{ cipher: "chacha20-ietf", counter: 0, nonce: { hex: "00".repeat(5) } }] }, { ...r, variants: [{ cipher: "chacha20-ietf", counter: 2 ** 40, nonce: { hex: "00".repeat(12) } }] },
    { ...r, variants: [{ cipher: "salsa20", counter: 0, nonce: { slice: "head", length: 8, skip: 0 } }] }, { ...r, variants: Array.from({ length: 17 }, () => r.variants[0]) },
    { ...r, assignments: { "a.png.locked": 7 } }, { ...r, assignments: [] }, { ...r, header_bytes: -1 }, { ...r, trailer_bytes: "32" }, { ...r, header_bytes: 10 ** 30 }, { ...r, member_suffix: "locked" },
    { ...r, member_suffix: "../x" }, { ...r, key: { slice: "tail", length: 4096, skip: 0, xor_hex: null } }, { ...r, key: { hex: "00".repeat(32) }, variants: [{ cipher: "xor", counter: 0, nonce: null }] },
  ];
  for (const recipe of recipes) cases.push({ tool: "family_decrypt", args: { dir: "work/fam", recipe }, label: `family_decrypt recipe = ${JSON.stringify(recipe).slice(0, 110)}` });
  await writeFile(join(fx.cwd, "work", "bad-recipe.json"), "{ not json");
  for (const recipe_file of ["work/bad-recipe.json", "work/dump.bin", "work", "work/nope.json"]) cases.push({ tool: "family_decrypt", args: { dir: "work/fam", recipe_file }, label: `family_decrypt recipe_file = ${recipe_file}` });
  cases.push({ tool: "family_decrypt", args: { dir: "work/fam", recipe_file: "work/recipe.json", recipe: r }, label: "family_decrypt with both recipe and recipe_file" });
  for (const file of ["work", "work/nope", "/dev/null", "work/fam/"]) cases.push({ tool: "cipher_state_scan", args: { file }, label: `cipher_state_scan file = ${file}` });
  for (const extra of [{ look_for: [] }, { look_for: ["des"] }, { look_for: "rc4" }, { offset: 10 ** 12 }, { limit: 0 }, { self_test: "yes" }]) cases.push({ tool: "cipher_state_scan", args: { file: "work/dump.bin", ...extra }, label: `cipher_state_scan ${JSON.stringify(extra)}` });

  const failures: string[] = [];
  await pool(cases, 8, async (c) => {
    const why = crash(await run(c.tool, fx.cwd, await fx.out(), c.args));
    if (why) failures.push(`${c.label}: ${why}`);
  });
  assert.ok(cases.length > 600, `${cases.length} cases`);
  assert.deepEqual(failures, [], `${failures.length} of ${cases.length} cases`);
});

test("a refusal quotes no byte of a key: a hex value that is refused is not repeated, and a refused recipe names its field only", async () => {
  const fx = await fixture();
  const secret = "deadbeefcafef00d0123456789abcdef";
  const kpa = await run("stream_kpa_check", fx.cwd, await fx.out(), { ...BASE.stream_kpa_check, key_sources: [{ hex: secret + "zz" }] });
  assert.equal(crash(kpa), null);
  assert.ok(!kpa.stdout.includes(secret.slice(0, 12)), kpa.stdout);
  const good = await run("stream_kpa_check", fx.cwd, await fx.out(), { ...BASE.stream_kpa_check, key_sources: [{ hex: secret }], nonce_sources: [{ hex: "0f1e2d3c4b5a69788796a5b4" }] });
  assert.equal(crash(good), null);
  assert.ok(!good.stdout.includes(secret.slice(0, 12)) && !good.stdout.includes("0f1e2d3c4b5a"), "a literal given in the call is described by its length, not repeated");
  const dec = await run("family_decrypt", fx.cwd, await fx.out(), { dir: "work/fam", recipe: { ...fx.recipe, key: { hex: secret }, variants: [{ cipher: "des" }] } });
  assert.equal(crash(dec), null);
  assert.ok(!dec.stdout.includes(secret.slice(0, 12)));
});

// ---- Stop signals and the tools' own clocks ----

const NUMBER = { SIGTERM: 15, SIGINT: 2, SIGHUP: 1 } as const;

function oneDocument(r: Ran): Doc {
  assert.doesNotMatch(r.stderr, /Traceback/);
  assert.equal(r.killed, false);
  return JSON.parse(r.stdout) as Doc;           // throws when it is not exactly one document
}

for (const signal of ["SIGTERM", "SIGINT", "SIGHUP"] as const) {
  test(`cipher_state_scan stopped by ${signal} in the middle of a file answers once: failed, interrupted, exit ${128 + NUMBER[signal]}`, { timeout: 120_000 }, async () => {
    const fx = await fixture();
    const big = Buffer.alloc(400 << 20);
    for (let at = 0; at < big.length; at += 1 << 20) big.writeUInt32LE((at * 2654435761) >>> 0, at);          // not a zero file: every piece is worked on
    randomBytes(8 << 20).copy(big, 0);
    await writeFile(join(fx.cwd, "work", "big.dmp"), big);
    const out = await fx.out();
    const r = await run("cipher_state_scan", fx.cwd, out, { file: "work/big.dmp" }, { signal, ms: 700, when: () => true });
    const doc = oneDocument(r);
    assert.equal(r.code, 128 + NUMBER[signal], r.stdout.slice(0, 300));
    assert.equal(doc.status, "failed");
    assert.equal(doc.interrupted, true);
    assert.equal(doc.signal, NUMBER[signal]);
    assert.ok(doc.offset_reached_so_far < big.length);
    assert.match(doc.status_basis, /not read to its end, so this is no negative/);
    assert.equal(doc.hits, undefined);
  });

  test(`family_decrypt stopped by ${signal} answers once with a truthful partial: what was decrypted stays with its receipt, the file being written is removed`, { timeout: 120_000 }, async () => {
    const fx = await fixture();
    await mkdir(join(fx.cwd, "work", "big"), { recursive: true });
    await writeFile(join(fx.cwd, "work", "big", "a-first.png.locked"), randomBytes(3000));
    await writeFile(join(fx.cwd, "work", "big", "b-large.bin.locked"), randomBytes(160 << 20));
    await writeFile(join(fx.cwd, "work", "big", "c-never.png.locked"), randomBytes(3000));
    const recipe = { ...fx.recipe, key: { hex: "07".repeat(16) }, variants: [{ cipher: "rc4", counter: 0, nonce: null }], trailer_bytes: 0 };
    const out = await fx.out();
    // The stop is sent once the first member's receipt is on disk and the large member is being written.
    const receiptThere = async (): Promise<boolean> => (await readFile(join(out, "decrypt-receipts.jsonl"), "utf8").catch(() => "")).includes("a-first");
    const r = await run("family_decrypt", fx.cwd, out, { dir: "work/big", recipe }, { signal, ms: 300, when: receiptThere });
    const doc = oneDocument(r);
    assert.equal(r.code, 128 + NUMBER[signal], r.stdout.slice(0, 300));
    assert.equal(doc.status, "partial");
    assert.equal(doc.interrupted, true);
    assert.equal(doc.members, 3);
    assert.equal(doc.decrypted_before_the_stop, 1);
    assert.match(doc.status_basis, /1 of 3 members had been decrypted and each has its receipt; the file being\s+written at the stop was removed/);
    assert.deepEqual(await readdir(join(out, "decrypted")), ["0001_a-first.png"]);
    const receipts = (await readFile(join(out, "decrypt-receipts.jsonl"), "utf8")).trim().split("\n");
    assert.equal(receipts.length, 1);
    assert.equal(JSON.parse(receipts[0]!).verdict, "decrypted, type not confirmed");
  });
}

test("a stop before any member is decrypted is failed, not partial; a stop while stream_kpa_check works gives no verdict and no recipe", { timeout: 120_000 }, async () => {
  const fx = await fixture();
  await mkdir(join(fx.cwd, "work", "one"), { recursive: true });
  await writeFile(join(fx.cwd, "work", "one", "large.bin.locked"), randomBytes(160 << 20));
  const recipe = { ...fx.recipe, key: { hex: "07".repeat(16) }, variants: [{ cipher: "rc4", counter: 0, nonce: null }], trailer_bytes: 0 };
  const out = await fx.out();
  const begun = async (): Promise<boolean> => (await readdir(join(out, "decrypted")).catch(() => [])).length > 0;
  const r = await run("family_decrypt", fx.cwd, out, { dir: "work/one", recipe }, { signal: "SIGTERM", ms: 300, when: begun });
  const doc = oneDocument(r);
  assert.equal(r.code, 143);
  assert.equal(doc.status, "failed");
  assert.equal(doc.decrypted_before_the_stop, 0);
  assert.deepEqual(await readdir(join(out, "decrypted")), []);
  // stream_kpa_check with many trials: enough work to be stopped in.
  await mkdir(join(fx.cwd, "work", "many"), { recursive: true });
  for (let i = 0; i < 150; i++) await writeFile(join(fx.cwd, "work", "many", `f${i}.png.locked`), randomBytes(300));
  // Keys that differ per member (slices at twenty skips), so that no keystream block is made once and used for every member.
  const keys = Array.from({ length: 20 }, (_, skip) => ({ slice: "tail", length: 32, skip }));
  const nonces = Array.from({ length: 10 }, () => ({ hex: randomBytes(12).toString("hex") }));
  const out2 = await fx.out();
  const k = await run("stream_kpa_check", fx.cwd, out2, { dir: "work/many", key_sources: keys, nonce_sources: nonces, ciphers: ["chacha20-ietf", "aes-ctr"], derive: false }, { signal: "SIGTERM", ms: 600, when: () => true });
  const kd = oneDocument(k);
  assert.equal(k.code, 143, k.stdout.slice(0, 300));
  assert.equal(kd.status, "failed");
  assert.equal(kd.interrupted, true);
  assert.match(kd.status_basis, /no verdict is given, no recipe was written/);
  assert.deepEqual(await readdir(out2), []);
});

test("the tools' own clocks: a scan out of time is partial at the offset it reached and resumes from it; a decrypt out of time removes the partial file", { timeout: 180_000 }, async () => {
  const fx = await fixture();
  const big = Buffer.alloc(320 << 20);
  for (let at = 0; at < big.length; at += 4096) big.writeUInt32LE((at * 2654435761) >>> 0, at);
  Buffer.concat([Buffer.from("expand 32-byte k"), randomBytes(48)]).copy(big, big.length - 5000);
  await writeFile(join(fx.cwd, "work", "big.dmp"), big);
  const first = await run("cipher_state_scan", fx.cwd, await fx.out(), { file: "work/big.dmp", max_seconds: 1 });
  const doc = oneDocument(first);
  assert.equal(first.code, 0);
  assert.equal(doc.status, "partial");
  assert.equal(doc.complete, false);
  assert.ok(doc.scanned_to > 0 && doc.scanned_to < big.length && doc.scanned_to % (16 << 20) === 0, String(doc.scanned_to));
  assert.match(doc.status_basis, new RegExp(`time limit \\(max_seconds 1\\) was reached: bytes 0 to ${doc.scanned_to} of ${big.length} were scanned[\\s\\S]*run again with offset ${doc.scanned_to}`));
  assert.deepEqual(doc.hits, [], "the state near the end was not reached, and the answer does not call that a negative");
  // Going on from where it stopped, in steps, reaches the state: nothing between the steps is skipped.
  let at = doc.scanned_to as number;
  let found: Doc[] = [];
  for (let step = 0; step < 40 && at < big.length; step++) {
    const next = oneDocument(await run("cipher_state_scan", fx.cwd, await fx.out(), { file: "work/big.dmp", offset: at, max_seconds: 4 }));
    assert.equal(next.scanned_from, at);
    found = found.concat(next.hits);
    at = next.scanned_to;
  }
  assert.equal(at, big.length);
  assert.deepEqual(found.map((h) => [h.kind, h.offset]), [["chacha-state", big.length - 5000]]);

  await mkdir(join(fx.cwd, "work", "slow"), { recursive: true });
  await writeFile(join(fx.cwd, "work", "slow", "a-first.png.locked"), randomBytes(3000));
  await writeFile(join(fx.cwd, "work", "slow", "b-large.bin.locked"), randomBytes(160 << 20));
  await writeFile(join(fx.cwd, "work", "slow", "c-after.png.locked"), randomBytes(3000));
  const recipe = { ...fx.recipe, key: { hex: "07".repeat(16) }, variants: [{ cipher: "rc4", counter: 0, nonce: null }], trailer_bytes: 0 };
  const out = await fx.out();
  const dec = oneDocument(await run("family_decrypt", fx.cwd, out, { dir: "work/slow", recipe, max_seconds: 1 }));
  assert.equal(dec.status, "partial");
  assert.equal(dec.members.decrypted, 1);
  assert.equal(dec.members.not_decrypted_time, 2);
  assert.match(dec.files[1].failure, /time limit \(max_seconds 1\) was reached \d+ bytes into this member; its\s+partial output was removed/);
  assert.match(dec.files[2].failure, /time limit \(max_seconds 1\) was reached before this member/);
  assert.deepEqual(await readdir(join(out, "decrypted")), ["0001_a-first.png"]);
});
