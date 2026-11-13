/**
 * ransomware-response: an encrypted-file family whose key scheme is in the evidence, end to end and with no code written in between
 * (IMPROVEMENT-PLAN-2 item E1; eight runs of one case each wrote the scan, the known-plaintext check and the decrypt by hand).
 *
 * The family is built here with node:crypto (OpenSSL), which shares nothing with the tools' pure-Python ciphers: two ciphers (ChaCha20 and
 * AES-256-CTR, alternating), a random key per file kept XORed with one constant in a 32-byte trailer, one nonce for all, a "process dump"
 * of random bytes that holds one live ChaCha state (the key of ONE member), one plaintext twin and a ransom note beside the members.
 *
 *   encrypted_survey  -> the constant 32-byte overhead against the twin and a tail unique per file, said in status_basis;
 *   cipher_state_scan -> the state at its planted offset, its key and nonce in the sealed values file, none of it in the answer;
 *   stream_kpa_check  -> that key opens one member; the tool forms the footer rule by itself and it explains every member; the recipe
 *                        file holds the nonce and the mask;
 *   family_decrypt    -> N of N members, each equal to its plaintext by sha256 and by type.
 *
 * And the contract around it: a dump with no state is `complete` with no hit and says what it looked for; a 4-byte crib reports its
 * false-positive expectation; a negative lists what was tried and never says that no key exists; no key, nonce, mask or plaintext byte is
 * in any answer; outside a secret-output job the values, the recipe and the plaintext are not written; shapes planted from independent
 * code (an AES schedule expanded here from FIPS-197, an RC4 state from its key schedule) are found at their offsets across a piece edge.
 */
import assert from "node:assert/strict";
import { createCipheriv, createHash, randomBytes } from "node:crypto";
import { mkdir, mkdtemp, readFile, readdir, rm, stat, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { after, test } from "node:test";
import { PACK, SURVEY, tool } from "./ransomware-pack-harness.ts";
import type { Run } from "./ransomware-pack-harness.ts";

const SCAN = join(PACK, "cipher_state_scan", "run.py");
const KPA = join(PACK, "stream_kpa_check", "run.py");
const DECRYPT = join(PACK, "family_decrypt", "run.py");
const SIGMA = Buffer.from("expand 32-byte k");
const sha = (b: Buffer): string => createHash("sha256").update(b).digest("hex");
const xor = (a: Buffer, b: Buffer): Buffer => Buffer.from(a.map((v, i) => v ^ b[i]!));

type Doc = Record<string, any>;
const dirs: string[] = [];
after(async () => {
  for (const d of dirs) await rm(d, { recursive: true, force: true });
});

async function sandbox(): Promise<string> {
  const cwd = await mkdtemp(join(tmpdir(), "rw-chain-"));
  dirs.push(cwd);
  await mkdir(join(cwd, "work"), { recursive: true });
  return cwd;
}

/** Run a tool as job `id` of the sandbox: its $OUT is where the answer's store/jobs/<id>/out/... paths point. */
async function job(script: string, cwd: string, id: string, args: unknown, secret = true): Promise<Run> {
  const out = join(cwd, "store", "jobs", id, "out");
  await mkdir(out, { recursive: true });
  return tool(script, cwd, args, { JOB_ID: id, OUT: out, ...(secret ? { SECRET_OUTPUT: "1" } : { SECRET_OUTPUT: "" }) });
}

function answer(run: Run, code = 0): Doc {
  assert.doesNotMatch(run.stderr, /Traceback/);
  assert.equal(run.code, code, run.stdout.slice(0, 2000) + run.stderr);
  return JSON.parse(run.stdout) as Doc;
}

const HEADS: Record<string, Buffer> = {
  png: Buffer.from("89504e470d0a1a0a0000000d49484452", "hex"),
  jpg: Buffer.from("ffd8ffe000104a464946", "hex"),
  pdf: Buffer.from("%PDF-1.7\n%\xe2\xe3\xcf\xd3\n", "latin1"),
  docx: Buffer.from("504b0304140006000800", "hex"),
  xlsx: Buffer.from("504b0304140006000800", "hex"),
  mp4: Buffer.from("000000186674797069736f6d", "hex"),
  avi: Buffer.concat([Buffer.from("RIFF"), Buffer.from([0x24, 0x10, 0, 0]), Buffer.from("AVI LIST")]),
  wav: Buffer.concat([Buffer.from("RIFF"), Buffer.from([0x24, 0x08, 0, 0]), Buffer.from("WAVEfmt ")]),
  gif: Buffer.from("GIF89a\x10\x00\x10\x00", "latin1"),
  bmp: Buffer.concat([Buffer.from("BM"), Buffer.from([0x36, 0x10, 0, 0, 0, 0, 0, 0, 0x36, 0, 0, 0])]),
  sqlite: Buffer.from("SQLite format 3\0\x10\x00\x01\x01", "latin1"),
};

type Member = { name: string; plain: Buffer; key: Buffer; cipher: "chacha20" | "aes-256-ctr" };
type Family = { cwd: string; dir: string; members: Member[]; mask: Buffer; nonce: Buffer; stateAt: number; stateOf: Member; dump: string; secrets: Buffer[] };

/** The family, the dump and what must never be printed. `trailer` bytes are appended after the masked key when it is more than 32. */
async function family(extra = 0): Promise<Family> {
  const cwd = await sandbox();
  const dir = join(cwd, "work", "share");
  await mkdir(dir, { recursive: true });
  const mask = randomBytes(32);
  const nonce = randomBytes(12);
  const members: Member[] = [];
  let n = 0;
  for (const [ext, head] of Object.entries(HEADS)) {
    for (const copy of [0, 1]) {
      n += 1;
      const plain = Buffer.concat([head, randomBytes(300 + 61 * n + (copy ? 5000 : 0))]);
      const key = randomBytes(32);
      const cipher = n % 2 ? "chacha20" : "aes-256-ctr";
      // OpenSSL: chacha20 takes counter (32 bits, little-endian) then nonce; aes-256-ctr takes the whole first counter block.
      const iv = cipher === "chacha20" ? Buffer.concat([Buffer.alloc(4), nonce]) : Buffer.concat([nonce, Buffer.alloc(4)]);
      const body = createCipheriv(cipher, key, iv).update(plain);
      const name = `${ext === "pdf" && !copy ? "report" : `file${n}`}.${ext}.crypted`;
      await writeFile(join(dir, name), Buffer.concat([body, xor(key, mask), randomBytes(extra)]));
      members.push({ name, plain, key, cipher });
    }
  }
  const twin = members.find((m) => m.name === "report.pdf.crypted")!;
  await writeFile(join(dir, "report.pdf"), twin.plain);
  await writeFile(join(dir, "HOW_TO_RESTORE.txt"), "Your files are encrypted.\n");
  const stateOf = members.find((m) => m.cipher === "chacha20" && m.name.includes(".jpg."))!;
  const dumpBytes = randomBytes(3 << 20);
  const stateAt = 1_234_567;
  Buffer.concat([SIGMA, stateOf.key, Buffer.from([9, 0, 0, 0]), nonce]).copy(dumpBytes, stateAt);
  const dump = join(cwd, "work", "encryptor.dmp");
  await writeFile(dump, dumpBytes);
  return { cwd, dir, members, mask, nonce, stateAt, stateOf, dump, secrets: [mask, nonce, ...members.map((m) => m.key), ...members.map((m) => xor(m.key, mask))] };
}

/** No 8 bytes of a secret, as hex in either case, and no 12 bytes of any plaintext body, in a text an answer printed. */
function assertNothingLeaked(text: string, fam: Family, what: string): void {
  const lower = text.toLowerCase();
  for (const secret of fam.secrets) {
    const hex = secret.toString("hex");
    for (let i = 0; i + 16 <= hex.length; i += 2) assert.ok(!lower.includes(hex.slice(i, i + 16)), `${what}: 8 bytes of a key, mask, trailer or nonce are in the answer`);
    assert.ok(!text.includes(secret.toString("base64").slice(0, 12)), `${what}: base64 of a secret is in the answer`);
  }
  for (const m of fam.members) {
    const hex = m.plain.subarray(40, 52).toString("hex");
    assert.ok(!lower.includes(hex), `${what}: plaintext bytes are in the answer`);
  }
}

test("the chain: survey, scan, known-plaintext check and decrypt return the nonce, the rule and N of N members, with no code in between", { timeout: 300_000 }, async () => {
  const fam = await family();
  const N = fam.members.length;

  // 0. What the encryptor added.
  const survey = answer(await tool(SURVEY, fam.cwd, { root: "work/share" }));
  assert.equal(survey.scheme_pointers.plaintext_twins.pairs, 1);
  assert.equal(survey.scheme_pointers.plaintext_twins.constant_overhead_bytes, 32);
  assert.equal(survey.scheme_pointers.tails.unique_per_file, true);
  assert.equal(survey.scheme_pointers.tails.members_read, N, "small members are profiled too");
  assert.equal(survey.scheme_pointers.trailer_seen, true);
  assert.match(survey.status_basis, /same 32 bytes[\s\S]*where per-file key material is usually kept[\s\S]*stream_kpa_check[\s\S]*before hunting memory/);
  assert.equal(survey.scheme_pointers.smallest_member.bytes, Math.min(...fam.members.map((m) => m.plain.length + 32)));
  assertNothingLeaked(JSON.stringify(survey.scheme_pointers), fam, "the survey's scheme pointers");

  // 1. The dump: one state, at its offset; values only in the sealed file.
  const scanRun = await job(SCAN, fam.cwd, "j000001", { file: "work/encryptor.dmp" });
  const scan = answer(scanRun);
  assert.equal(scan.status, "complete", scan.status_basis);
  assert.equal(scan.control.passed, true);
  assert.deepEqual(scan.hits.map((h: Doc) => [h.kind, h.offset, h.candidate]), [["chacha-state", fam.stateAt, true]]);
  assert.equal(scan.hits[0].counter_32bit, 9);
  assert.equal(scan.hits[0].key_shape, "looks random");
  assert.equal(scan.candidates.values_file, "store/jobs/j000001/out/cipher-state-candidates.jsonl");
  assert.equal(scan.candidates.written, 1);
  assertNothingLeaked(scanRun.stdout, fam, "cipher_state_scan");
  const valuesPath = join(fam.cwd, scan.candidates.values_file);
  assert.equal((await stat(valuesPath)).mode & 0o777, 0o600);
  const values = (await readFile(valuesPath, "utf8")).trim().split("\n").map((l) => JSON.parse(l) as Doc);
  assert.equal(values[0]!.key_hex, fam.stateOf.key.toString("hex"));
  assert.equal(values[0]!.layouts.ietf.nonce_hex, fam.nonce.toString("hex"), "the nonce is returned, in the sealed file");
  assert.equal(values[0]!.layouts.ietf.counter, 9);
  assert.equal(values[0]!.layouts.original.nonce_hex, fam.nonce.subarray(4).toString("hex"));

  // 2. The check: the dump's key opens one member, and the tool makes the footer rule from that pair.
  const source = { candidates: scan.candidates.values_file };
  const kpaRun = await job(KPA, fam.cwd, "j000002", { dir: "work/share", key_sources: [source], nonce_sources: [source] });
  const kpa = answer(kpaRun);
  assert.equal(kpa.status, "complete", kpa.status_basis);
  assert.equal(kpa.outcome, "one_rule_explains_every_member", kpa.finding);
  assert.equal(kpa.members.with_a_crib, N);
  assert.deepEqual(kpa.members.by_verdict, { head_is_plaintext: 1, match: N, no_crib: 1 }, "the twin is plaintext and the note has no crib");
  assert.equal(kpa.derived_rules.length, 1);
  assert.deepEqual([kpa.derived_rules[0].region, kpa.derived_rules[0].skip, kpa.derived_rules[0].length, kpa.derived_rules[0].mask_all_zero, kpa.derived_rules[0].explains],
    ["tail", 0, 32, false, N]);
  assert.match(kpa.derived_rules[0].from_file, /\.jpg\.crypted$/);
  assert.match(kpa.recipe.key, /the last 32 bytes of each file XOR a 32-byte constant/);
  assert.deepEqual(kpa.recipe.variants.map((v: Doc) => [v.cipher, v.counter, v.members]).sort(), [["aes-ctr", 0, N / 2], ["chacha20-ietf", 0, N / 2]]);
  assert.equal(kpa.recipe.trailer_bytes, 32);
  assert.equal(kpa.recipe.member_suffix, ".crypted");
  assert.equal(kpa.recipe_file, "store/jobs/j000002/out/stream-recipe.json");
  assertNothingLeaked(kpaRun.stdout, fam, "stream_kpa_check");
  const recipe = JSON.parse(await readFile(join(fam.cwd, kpa.recipe_file), "utf8")) as Doc;
  assert.equal(recipe.key.xor_hex, fam.mask.toString("hex"), "the rule: the mask, in the sealed recipe");
  assert.ok(recipe.variants.every((v: Doc) => v.nonce.hex === fam.nonce.toString("hex")), "the nonce, in the sealed recipe");
  // Every row: a crib length, the trials made and the false positives to expect from them.
  for (const row of kpa.files.filter((r: Doc) => r.verdict === "match")) {
    assert.ok(row.crib_bytes >= 3 && row.trials > 0 && row.expected_false_positives >= 0, JSON.stringify(row));
    assert.ok(Math.abs(row.expected_false_positives - row.trials * 2 ** (-8 * row.crib_bytes)) <= row.expected_false_positives * 0.02 + 1e-300 || row.expected_type === "gif" || row.expected_type === "pdf",
      `${row.file}: ${row.expected_false_positives} for ${row.trials} trials on ${row.crib_bytes} bytes`);
  }
  const docx = kpa.files.find((r: Doc) => /\.docx\.crypted$/.test(r.file));
  assert.equal(docx.crib_bytes, 4);
  assert.ok(docx.expected_false_positives > 0 && docx.expected_false_positives < 1e-3);
  assert.match(docx.crib_note, /a 4-byte crib: one wrong trial in 4294967296 passes by chance/);
  assert.match(kpa.files.find((r: Doc) => /report\.pdf\.crypted$/.test(r.file)).twin, /first 64 bytes are a crib too/);

  // 3. Every member, from the recipe file alone.
  const decRun = await job(DECRYPT, fam.cwd, "j000003", { dir: "work/share", recipe_file: kpa.recipe_file });
  const dec = answer(decRun);
  assert.equal(dec.status, "complete", dec.status_basis);
  assert.equal(dec.members.named, N, "the twin and the note are not members: the recipe's suffix chose the files");
  assert.equal(dec.members.decrypted_type_confirmed, N);
  assert.equal(dec.authenticated, false);
  assert.match(dec.authentication, /a stream cipher gives no integrity/);
  assertNothingLeaked(decRun.stdout, fam, "family_decrypt");
  assert.doesNotMatch(decRun.stdout, /sha256_plaintext"\s*:/, "the digest of decrypted content is in the receipts, not in the answer");
  const receipts = (await readFile(join(fam.cwd, dec.receipts), "utf8")).trim().split("\n").map((l) => JSON.parse(l) as Doc);
  assert.equal(receipts.length, N);
  for (const m of fam.members) {
    const row = dec.files.find((r: Doc) => r.file.endsWith(`/${m.name}`));
    assert.equal(row.verdict, "decrypted, type confirmed", m.name);
    assert.equal(row.cipher, m.cipher === "chacha20" ? "chacha20-ietf" : "aes-ctr");
    assert.equal(row.payload_bytes, m.plain.length);
    const written = await readFile(join(fam.cwd, row.output));
    assert.ok(written.equals(m.plain), `${m.name} decrypts to its plaintext`);
    assert.equal((await stat(join(fam.cwd, row.output))).mode & 0o777, 0o600);
    const receipt = receipts.find((r) => r.file === row.file)!;
    assert.equal(receipt.sha256_plaintext, sha(m.plain));
    assert.equal(receipt.sha256_ciphertext, sha(await readFile(join(fam.dir, m.name))));
    assert.equal(receipt.authenticated, false);
    assert.match(row.output, new RegExp(`/decrypted/\\d{4}_${m.name.replace(".crypted", "").replace(/\./g, "\\.")}$`));
  }
});

test("a trailer the caller names: the masked-tail source with the constant from a file gives the same recipe without a dump", { timeout: 120_000 }, async () => {
  const fam = await family();
  await writeFile(join(fam.cwd, "work", "sample.bin"), Buffer.concat([randomBytes(700), fam.mask, randomBytes(50)]));
  await writeFile(join(fam.cwd, "work", "nonce.bin"), fam.nonce);
  const run = await job(KPA, fam.cwd, "j000004", {
    dir: "work/share", glob: "*.crypted",
    key_sources: [{ slice: "tail", length: 32 }, { slice: "tail", length: 32, xor: { file: "work/sample.bin", offset: 700, length: 32 } }],
    nonce_sources: [{ file: "work/nonce.bin", offset: 0, length: 12 }], ciphers: ["chacha20-ietf", "aes-ctr"],
  });
  const kpa = answer(run);
  assert.equal(kpa.outcome, "one_rule_explains_every_member", kpa.finding);
  assert.match(kpa.recipe.key, /^key_sources\[1\]: the last 32 bytes of each file XOR 32 bytes at offset 700 of a file$/);
  assert.equal(kpa.tried.trailer_bytes, 32);
  assert.deepEqual(kpa.derived_rules, [], "nothing to derive: no key that is not a slice opened a member");
  assertNothingLeaked(run.stdout, fam, "stream_kpa_check with a masked-tail source");
  // The plain tail (no mask) is one of the sources and opens nothing: its trials are counted all the same.
  assert.equal(kpa.trials, fam.members.length * 2 * 2 * 2);
});

test("a dump with no state is complete with no hit and says what it looked for; a negative of the check lists what was tried", { timeout: 120_000 }, async () => {
  const fam = await family();
  await writeFile(join(fam.cwd, "work", "other.dmp"), randomBytes(2 << 20));
  const scan = answer(await job(SCAN, fam.cwd, "j000005", { file: "work/other.dmp" }));
  assert.equal(scan.status, "complete");
  assert.equal(scan.complete, true);
  assert.deepEqual(scan.hits, []);
  assert.equal(scan.counts.hits, 0);
  assert.equal(scan.bytes_scanned, 2 << 20);
  assert.ok(scan.looked_for.length >= 5 && scan.looked_for.some((l: string) => /expand 32-byte k/.test(l)) && scan.looked_for.some((l: string) => /FIPS-197/.test(l)));
  assert.ok(scan.not_looked_for.some((l: string) => /no constant beside it/.test(l)));
  assert.equal(scan.control.passed, true);
  assert.equal(scan.control.planted, scan.control.found_at_planted_offset);
  assert.match(scan.status_basis, /whole file \(2097152 bytes\) was read, none of the shapes in looked_for was found, and the planted control passed/);
  assert.match(scan.status_basis, /does not say that no key exists/);
  assert.equal(scan.candidates.written, 0);
  assert.equal((await stat(join(fam.cwd, scan.candidates.values_file))).size, 0, "the values file is there and empty");

  // The check with keys that are not the family's: no match, and the answer bounds its negative.
  await writeFile(join(fam.cwd, "work", "wrong.key"), randomBytes(32));
  const run = await job(KPA, fam.cwd, "j000006", {
    dir: "work/share", glob: "*.crypted", key_sources: [{ file: "work/wrong.key", offset: 0, length: 32 }, { slice: "head", length: 16 }],
    nonce_sources: [{ hex: "00".repeat(12) }, { hex: "00".repeat(8) }],
  });
  const kpa = answer(run);
  assert.equal(kpa.status, "complete", "the check ran whole");
  assert.equal(kpa.outcome, "no_combination_matched");
  assert.match(kpa.finding, /negative for the\s+ciphers, counters, layouts and sources in `tried` only: it does not say that no key exists/);
  assert.equal(kpa.recipe, null);
  assert.equal(kpa.recipe_file, null);
  assert.deepEqual(kpa.tried.ciphers, ["chacha20-ietf", "chacha20-original", "salsa20", "aes-ctr", "rc4", "xor"]);
  assert.deepEqual(kpa.tried.counters, [0, 1]);
  assert.match(kpa.tried.layouts, /chacha20-ietf: 12-byte nonce, 32-bit counter; chacha20-original: 8-byte nonce, 64-bit counter/);
  assert.deepEqual(kpa.tried.key_sources, [{ index: 0, kind: "file", bytes: 32 }, { index: 1, kind: "slice", region: "head", length: 16, skip: 0, xor: null }]);
  assert.equal(kpa.tried.header_bytes, 16, "a head slice is taken off the payload");
  assert.ok(kpa.not_tried.length >= 4 && kpa.not_tried.some((l: string) => /CBC/.test(l)) && kpa.not_tried.some((l: string) => /KDF/.test(l)));
  assert.ok(kpa.files.every((r: Doc) => r.verdict === "no_match" && r.trials > 0 && r.matches.length === 0));
  assert.equal(kpa.trials, kpa.files.reduce((n: number, r: Doc) => n + r.trials, 0));
});

test("a key from the dump that opens one member and no footer rule: one known pair, said as such, and no recipe for the family", { timeout: 120_000 }, async () => {
  const fam = await family();
  // The same dump, and members whose trailers are noise: the key of one member is in the dump, the others' keys are nowhere.
  for (const m of fam.members) {
    const path = join(fam.dir, m.name);
    const data = await readFile(path);
    randomBytes(32).copy(data, data.length - 32);
    await writeFile(path, data);
  }
  const scan = answer(await job(SCAN, fam.cwd, "j000007", { file: "work/encryptor.dmp" }));
  const source = { candidates: scan.candidates.values_file };
  const kpa = answer(await job(KPA, fam.cwd, "j000008", { dir: "work/share", glob: "*.crypted", key_sources: [source], nonce_sources: [source] }));
  assert.equal(kpa.outcome, "some_members_explained");
  assert.equal(kpa.members.by_verdict.match, 1);
  assert.match(kpa.finding, /1 of 22 members[\s\S]*known\s+\(file, key\) pair/);
  assert.deepEqual(kpa.derived_rules, []);
  assert.equal(kpa.recipe_file, null);
  assert.match(kpa.recipe_file_why, /one known \(file, key\) pair, not a rule for the family/);
  assert.equal(kpa.tried.derivation.made, true);
  assert.ok(kpa.tried.derivation.trials > 0);
});

test("outside a secret-output job nothing secret is written: no values, no recipe, no plaintext", { timeout: 120_000 }, async () => {
  const fam = await family();
  // Not a job at all.
  const scanRun = await tool(SCAN, fam.cwd, { file: "work/encryptor.dmp" });
  const scan = answer(scanRun);
  assert.equal(scan.status, "partial");
  assert.equal(scan.hits.length, 1);
  assert.equal(scan.candidates.values_file, null);
  assert.match(scan.candidates.why, /not a job/);
  assertNothingLeaked(scanRun.stdout, fam, "cipher_state_scan outside a job");
  // A job that is not secret output.
  const plain = answer(await job(SCAN, fam.cwd, "j000009", { file: "work/encryptor.dmp" }, false));
  assert.equal(plain.candidates.values_file, null);
  assert.match(plain.candidates.why, /SECRET_OUTPUT is not 1/);
  assert.deepEqual(await readdir(join(fam.cwd, "store", "jobs", "j000009", "out")), []);
  // The check gives its verdicts and writes no recipe.
  await writeFile(join(fam.cwd, "work", "mask.bin"), fam.mask);
  await writeFile(join(fam.cwd, "work", "nonce.bin"), fam.nonce);
  const args = { dir: "work/share", glob: "*.crypted", key_sources: [{ slice: "tail", length: 32, xor: { file: "work/mask.bin", offset: 0, length: 32 } }], nonce_sources: [{ file: "work/nonce.bin", offset: 0, length: 12 }] };
  const kpa = answer(await job(KPA, fam.cwd, "j000010", args, false));
  assert.equal(kpa.outcome, "one_rule_explains_every_member");
  assert.equal(kpa.recipe_file, null);
  assert.match(kpa.recipe_file_why, /not a job run as secret output/);
  assert.deepEqual(await readdir(join(fam.cwd, "store", "jobs", "j000010", "out")), []);
  // The decrypt refuses, in a job and outside one, and writes nothing.
  const good = answer(await job(KPA, fam.cwd, "j000011", args));
  for (const run of [await tool(DECRYPT, fam.cwd, { dir: "work/share", recipe_file: good.recipe_file }), await job(DECRYPT, fam.cwd, "j000012", { dir: "work/share", recipe_file: good.recipe_file }, false)]) {
    const refused = answer(run, 1);
    assert.equal(refused.status, "failed");
    assert.equal(refused.written, false);
    assert.match(refused.error, /refused outside a job run as secret output/);
  }
  assert.deepEqual(await readdir(join(fam.cwd, "store", "jobs", "j000012", "out")), []);
  assert.equal(await stat(join(fam.cwd, "work", "s1")).then(() => true, () => false), false, "nothing was written under work/ either");
});

test("family_decrypt: a member the recipe does not fit is 'type not confirmed' and the answer is partial; budgets leave members undone and say so", { timeout: 120_000 }, async () => {
  const fam = await family();
  await writeFile(join(fam.cwd, "work", "mask.bin"), fam.mask);
  await writeFile(join(fam.cwd, "work", "nonce.bin"), fam.nonce);
  const kpa = answer(await job(KPA, fam.cwd, "j000013", { dir: "work/share", glob: "*.crypted", key_sources: [{ slice: "tail", length: 32, xor: { file: "work/mask.bin", offset: 0, length: 32 } }], nonce_sources: [{ file: "work/nonce.bin", offset: 0, length: 12 }] }));
  // Two members that are not what the recipe says: a png whose trailer is noise, and a file of no known type.
  await writeFile(join(fam.dir, "broken.png.crypted"), randomBytes(900));
  await writeFile(join(fam.dir, "notes.xyz.crypted"), randomBytes(400));
  await writeFile(join(fam.dir, "tiny.png.crypted"), randomBytes(10));
  const dec = answer(await job(DECRYPT, fam.cwd, "j000014", { dir: "work/share", recipe_file: kpa.recipe_file }));
  assert.equal(dec.status, "partial");
  const row = (name: string): Doc => dec.files.find((r: Doc) => r.file.endsWith(`/${name}`));
  assert.equal(row("broken.png.crypted").verdict, "decrypted, type not confirmed");
  assert.match(row("broken.png.crypted").why_not_confirmed, /does not start with the bytes of a png/);
  assert.equal(row("notes.xyz.crypted").verdict, "decrypted, type not confirmed");
  assert.match(row("notes.xyz.crypted").variant_chosen_by, /a default: the recipe's first variant/);
  assert.equal(row("tiny.png.crypted").verdict, "failed");
  assert.match(row("tiny.png.crypted").failure, /smaller than the recipe's header and trailer/);
  assert.equal(dec.members.decrypted_type_confirmed, fam.members.length);
  assert.match(dec.status_basis, /1 members failed/);
  assert.match(dec.status_basis, /1 members were decrypted and do not start with the bytes of the type their name promises/);
  assert.match(dec.status_basis, /2 members were decrypted with a variant chosen by default/, "the png no variant fits, and the file of no known type");
  // max_files and max_bytes.
  const few = answer(await job(DECRYPT, fam.cwd, "j000015", { dir: "work/share", recipe_file: kpa.recipe_file, max_files: 3, max_bytes: 1500 }));
  assert.equal(few.status, "partial");
  assert.equal(few.members.named, 3);
  assert.match(few.status_basis, /22 more files matched and were not decrypted: max_files is 3/);
  assert.ok(few.members.not_decrypted_budget >= 1);
  assert.ok(few.files.some((r: Doc) => r.verdict === "not decrypted" && /max_bytes \(1500\) would be passed/.test(r.failure)));
  assert.ok(few.bytes_decrypted <= 1500);
  // The recipe given as JSON, as the check wrote it, does the same as the file.
  const recipe = JSON.parse(await readFile(join(fam.cwd, kpa.recipe_file), "utf8"));
  const inline = answer(await job(DECRYPT, fam.cwd, "j000016", { files: fam.members.slice(0, 4).map((m) => `work/share/${m.name}`), recipe }));
  assert.equal(inline.status, "complete");
  assert.equal(inline.members.decrypted_type_confirmed, 4);
  // A second run into the same $OUT replaces nothing: its files take second names.
  const again = answer(await job(DECRYPT, fam.cwd, "j000016", { files: [`work/share/${fam.members[0]!.name}`], recipe }));
  assert.match(again.files[0].output, /-2(\.[a-z0-9]+)?$/);
  assert.equal(again.receipts, "store/jobs/j000016/out/decrypt-receipts-2.jsonl");
});

test("a key kept 8 bytes before the end of a 40-byte trailer: the footer rule is found at its skip and the recipe takes the whole trailer off", { timeout: 120_000 }, async () => {
  const fam = await family(8);
  const survey = answer(await tool(SURVEY, fam.cwd, { root: "work/share" }));
  assert.equal(survey.scheme_pointers.plaintext_twins.constant_overhead_bytes, 40);
  const scan = answer(await job(SCAN, fam.cwd, "j000001", { file: "work/encryptor.dmp" }));
  const source = { candidates: scan.candidates.values_file };
  const kpa = answer(await job(KPA, fam.cwd, "j000002", { dir: "work/share", glob: "*.crypted", key_sources: [source], nonce_sources: [source], ciphers: ["chacha20-ietf", "aes-ctr"] }));
  assert.equal(kpa.outcome, "one_rule_explains_every_member", kpa.finding);
  assert.deepEqual([kpa.derived_rules[0].region, kpa.derived_rules[0].skip, kpa.derived_rules[0].length], ["tail", 8, 32]);
  assert.equal(kpa.recipe.trailer_bytes, 40);
  assert.match(kpa.recipe.trailer_basis, /at least the bytes the key and nonce slices take from the end/);
  const dec = answer(await job(DECRYPT, fam.cwd, "j000003", { dir: "work/share", recipe_file: kpa.recipe_file }));
  assert.equal(dec.status, "complete", dec.status_basis);
  for (const m of fam.members) {
    const row = dec.files.find((r: Doc) => r.file.endsWith(`/${m.name}`));
    assert.ok((await readFile(join(fam.cwd, row.output))).equals(m.plain), m.name);
  }
});

// ---- Shapes planted from code that shares nothing with the scanner ----

function gmul(a: number, b: number): number {
  let p = 0;
  for (let i = 0; i < 8; i++) {
    if (b & 1) p ^= a;
    const high = a & 0x80;
    a = (a << 1) & 0xff;
    if (high) a ^= 0x1b;
    b >>= 1;
  }
  return p;
}
const rotl8 = (v: number, n: number): number => ((v << n) | (v >> (8 - n))) & 0xff;
// FIPS-197 5.1.1: the multiplicative inverse (found by search), then the affine transformation.
const SBOX = Array.from({ length: 256 }, (_, x) => {
  let inv = 0;
  for (let y = 1; y < 256 && x; y++) if (gmul(x, y) === 1) inv = y;
  return inv ^ rotl8(inv, 1) ^ rotl8(inv, 2) ^ rotl8(inv, 3) ^ rotl8(inv, 4) ^ 0x63;
});

/** FIPS-197 5.2, written from the standard's pseudo-code. */
function expandKey(key: Buffer): Buffer {
  const nk = key.length / 4;
  const words: number[][] = [];
  for (let i = 0; i < nk; i++) words.push([...key.subarray(4 * i, 4 * i + 4)]);
  let rcon = 1;
  for (let i = nk; i < 4 * (nk + 7); i++) {
    let t = [...words[i - 1]!];
    if (i % nk === 0) {
      t = [SBOX[t[1]!]! ^ rcon, SBOX[t[2]!]!, SBOX[t[3]!]!, SBOX[t[0]!]!];
      rcon = gmul(rcon, 2);
    } else if (nk > 6 && i % nk === 4) t = t.map((b) => SBOX[b]!);
    words.push(words[i - nk]!.map((b, j) => b ^ t[j]!));
  }
  return Buffer.from(words.flat());
}

function rc4State(key: Buffer): Buffer {
  const s = Array.from({ length: 256 }, (_, i) => i);
  let j = 0;
  for (let i = 0; i < 256; i++) {
    j = (j + s[i]! + key[i % key.length]!) & 0xff;
    [s[i], s[j]] = [s[j]!, s[i]!];
  }
  return Buffer.from(s);
}

test("cipher_state_scan finds every shape at its planted offset, across the edge of a 16 MiB piece, and tells a bare constant from a state", { timeout: 300_000 }, async () => {
  assert.equal(expandKey(Buffer.from("2b7e151628aed2a6abf7158809cf4f3c", "hex")).subarray(160).toString("hex"), "d014f9a8c9ee2589e13f0cc8b6630ca6", "the test's own key expansion is FIPS-197's");
  const cwd = await sandbox();
  const EDGE = 16 << 20;
  const data = randomBytes(2 * EDGE + (1 << 20));
  const k128 = randomBytes(16), k192 = randomBytes(24), k256 = randomBytes(32), kc = randomBytes(32), ks = randomBytes(32), k16 = randomBytes(16);
  const nonce8 = randomBytes(8), nonce12 = randomBytes(12);
  const plants: Array<[number, Buffer, string]> = [
    [5000, expandKey(k128), "aes-128-key-schedule"],
    [EDGE - 100, expandKey(k192), "aes-192-key-schedule"],                                    // runs over the piece edge
    [EDGE + 4000, expandKey(k256), "aes-256-key-schedule"],                                   // starts inside the first piece's overlap
    [900_001, Buffer.concat(Array.from({ length: 60 }, (_, i) => Buffer.from(expandKey(k256).subarray(4 * i, 4 * i + 4)).reverse())), "aes-256-key-schedule"],
    [2 * EDGE - 30, Buffer.concat([SIGMA, kc, Buffer.from([1, 0, 0, 0]), nonce12]), "chacha-state"],          // over the second piece edge
    [70_000, Buffer.concat([Buffer.from("expand 16-byte k"), k16, k16, Buffer.alloc(8), nonce8]), "chacha-state"],
    [80_000, Buffer.concat([Buffer.from("expa"), ks.subarray(0, 16), Buffer.from("nd 3"), nonce8, Buffer.from([3, 0, 0, 0, 0, 0, 0, 0]), Buffer.from("2-by"), ks.subarray(16), Buffer.from("te k")]), "salsa20-state"],
    [90_000, Buffer.concat([SIGMA, Buffer.alloc(48)]), "chacha-state"],                       // the constant in a program's data, zeros after it
    [3_000_000, rc4State(Buffer.from("a key")), "rc4-permutation"],
    [4_000_000, Buffer.from(SBOX), "constant-table"],
    [EDGE + 500_000, Buffer.from(Array.from({ length: 256 }, (_, i) => i)), "identity"],
  ];
  for (const [at, blob] of plants) blob.copy(data, at);
  await writeFile(join(cwd, "work", "proc.dmp"), data);
  const run = await job(SCAN, cwd, "j000001", { file: "work/proc.dmp" });
  const scan = answer(run);
  assert.equal(scan.status, "complete", scan.status_basis);
  assert.equal(scan.bytes_scanned, data.length);
  const found = new Map<number, Doc>(scan.hits.map((h: Doc) => [h.offset, h]));
  // A permutation's own shape does not say where it starts when the byte before it equals its last byte (one time in 256): the hit is
  // then one byte early and says that the next offset is a permutation too.
  const perm = scan.hits.find((h: Doc) => h.kind === "rc4-permutation") as Doc;
  assert.ok(perm.offset <= 3_000_000 && 3_000_000 <= perm.offset + perm.also_a_permutation_at_the_next_offsets, JSON.stringify(perm));
  for (const [at, , kind] of plants) {
    if (kind === "identity" || kind === "rc4-permutation") continue;
    assert.equal(found.get(at)?.kind, kind, `${kind} at ${at}`);
  }
  assert.equal(scan.hits.length, plants.length - 1, "nothing else is reported in random bytes");
  assert.equal(scan.counts.identity_tables, 1, "the identity table is counted, not reported as a state");
  assert.equal(found.get(900_001)!.word_order, "byte-swapped words (a 32-bit big-endian load on a little-endian machine)");
  assert.equal(found.get(5000)!.word_order, "as FIPS-197 writes them");
  assert.equal(found.get(2 * EDGE - 30)!.key_shape, "looks random");
  assert.match(found.get(90_000)!.key_shape, /low variety[\s\S]*bare constant/);
  assert.equal(found.get(70_000)!.key_halves_equal, true);
  assert.equal(found.get(80_000)!.counter_32bit, 3);
  assert.deepEqual([found.get(4_000_000)!.matched, found.get(4_000_000)!.whole], ["AES S-box", true]);
  for (const secret of [k128, k192, k256, kc, ks, k16, nonce8, nonce12]) assert.ok(!run.stdout.toLowerCase().includes(secret.toString("hex").slice(0, 16)), "no key or nonce byte in the answer");
  const values = (await readFile(join(cwd, scan.candidates.values_file), "utf8")).trim().split("\n").map((l) => JSON.parse(l) as Doc);
  const value = (at: number): Doc => values.find((v) => v.offset === at)!;
  assert.equal(value(5000).key_hex, k128.toString("hex"));
  assert.equal(value(EDGE - 100).key_hex, k192.toString("hex"));
  assert.equal(value(EDGE + 4000).key_hex, k256.toString("hex"));
  assert.equal(value(900_001).key_hex, k256.toString("hex"), "a byte-swapped schedule gives the key in FIPS-197 order");
  assert.equal(value(2 * EDGE - 30).key_hex, kc.toString("hex"));
  assert.equal(value(2 * EDGE - 30).layouts.ietf.nonce_hex, nonce12.toString("hex"));
  assert.equal(value(70_000).key_hex, k16.toString("hex"));
  assert.equal(value(80_000).key_hex, ks.toString("hex"));
  assert.equal(value(80_000).layouts.salsa20.nonce_hex, nonce8.toString("hex"));
  assert.ok((value(perm.offset).permutation_hex + value(perm.offset).bytes_after_hex).includes(rc4State(Buffer.from("a key")).toString("hex")));
  assert.equal(scan.candidates.written, values.length);
  assert.equal(scan.candidates.key_or_state_candidates, 9);

  // look_for narrows what is looked for, and says so; offset resumes, and an answer that began past 0 is partial.
  const narrowed = answer(await job(SCAN, cwd, "j000002", { file: "work/proc.dmp", look_for: ["chacha-salsa"] }));
  assert.deepEqual([...new Set(narrowed.hits.map((h: Doc) => h.kind))].sort(), ["chacha-state", "salsa20-state"]);
  assert.ok(narrowed.not_looked_for.some((l: string) => /left out by look_for: aes-schedule, rc4, tables/.test(l)));
  const resumed = answer(await job(SCAN, cwd, "j000003", { file: "work/proc.dmp", offset: EDGE - 100 }));
  assert.equal(resumed.status, "partial");
  assert.match(resumed.status_basis, /began at offset 16777116/);
  assert.deepEqual(resumed.hits.map((h: Doc) => h.offset), [EDGE - 100, EDGE + 4000, 2 * EDGE - 30]);

  // The control alone.
  const self = answer(await tool(SCAN, cwd, { self_test: true }));
  assert.equal(self.status, "complete");
  assert.equal(self.self_test.passed, true);
  assert.ok(self.self_test.planted >= 10 && self.self_test.planted === self.self_test.found_at_planted_offset);
  assert.deepEqual(self.self_test.missed, []);
});

test("cipher_state_scan: a compressed container is answered partial with the reason, and a broken scanner fails its control instead of answering 'no hit'", { timeout: 120_000 }, async () => {
  const cwd = await sandbox();
  await writeFile(join(cwd, "work", "image.ad1"), Buffer.concat([Buffer.from("ADSEGMENTEDFILE\0"), randomBytes(200_000)]));
  const ad1 = answer(await job(SCAN, cwd, "j000001", { file: "work/image.ad1" }));
  assert.equal(ad1.status, "partial");
  assert.match(ad1.status_basis, /begins like AD1 \(zlib-compressed items\): its content was not decompressed, so a state inside it could not match/);
  // A scanner whose constant search finds nothing: the control catches it, the file is not read and no negative is given.
  const { runPatched } = await import("./ransomware-pack-harness.ts");
  await writeFile(join(cwd, "work", "x.dmp"), randomBytes(100_000));
  const out = join(cwd, "store", "jobs", "j000002", "out");
  await mkdir(out, { recursive: true });
  const broken = await runPatched(SCAN, "m.find_all = lambda buf, needle, end: iter(())", JSON.stringify({ file: "work/x.dmp" }), cwd, out, { SECRET_OUTPUT: "1" });
  assert.doesNotMatch(broken.stderr, /Traceback/);
  const doc = JSON.parse(broken.stdout) as Doc;
  assert.equal(doc.status, "failed");
  assert.match(doc.error, /the planted control failed/);
  assert.equal(doc.control.passed, false);
  assert.ok(doc.control.missed.length >= 3);
  assert.equal(doc.hits, undefined, "no list of hits, and so no negative");
});
