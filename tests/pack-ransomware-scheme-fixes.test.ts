/**
 * ransomware-response 1.14.1: what an independent verification of cipher_state_scan, stream_kpa_check and family_decrypt found, each
 * pinned on a fixture built here with code that shares nothing with the tools (node:crypto's ChaCha20, and the test's own FIPS-197 key
 * expansion, checked against the standard's appendix A.1 before it is used).
 *
 *   stream_kpa_check
 *     - the footer hypothesis is tried on EVERY other member: a family gives the same rule whatever the order of its members' names
 *       (three members whose content is not what their name promises, sorted right after the opened one, used to end the derivation and
 *       leave the others a wrong no_match in a `complete` answer); members that use another counter than the opened one are found too;
 *     - the derived trials count against max_trials and the clock, and a bound that stops them makes the answer partial and says so in
 *       not_tried; max_seconds holds while the hypothesis runs;
 *     - whether a mask is all zero is in the recipe file, not in the answer;
 *     - the shared extension is matched in any case and keeps its case, and a file without it is not a member for family_decrypt;
 *     - a recipe names a member by its path below the directory of the call (two members of one name under `recursive`);
 *     - a cipher with no fitting nonce makes no trial: that is `not_tried`, not a negative; a candidates file with no key says what it held;
 *     - one member is open at a time (400 members with 64 descriptors); a name that is not ASCII is printed as given.
 *   cipher_state_scan
 *     - an AES schedule whose last byte is zero, followed by zero bytes, is found (it was missed with a `complete` negative), and so are one
 *       with leading zero bytes after zero bytes, a byte-swapped one, and the schedule of the all-zero key between zero pages;
 *     - whether nonce bytes of a state are zero is in the values file, not in the answer;
 *     - an S-box met by the permutation search alone is counted; a tool-output that is a link is not written through.
 *   family_decrypt
 *     - outside a secret-output job it refuses before it reads the recipe; a large header is hashed in pieces.
 */
import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { createCipheriv, createHash, randomBytes } from "node:crypto";
import { mkdir, mkdtemp, readFile, readdir, rm, symlink, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { after, test } from "node:test";
import { PYTHON3 } from "./host-gates.ts";
import { PACK, tool } from "./ransomware-pack-harness.ts";
import type { Run } from "./ransomware-pack-harness.ts";

const SCAN = join(PACK, "cipher_state_scan", "run.py");
const KPA = join(PACK, "stream_kpa_check", "run.py");
const DECRYPT = join(PACK, "family_decrypt", "run.py");
const SIGMA = Buffer.from("expand 32-byte k");
const xor = (a: Buffer, b: Buffer): Buffer => Buffer.from(a.map((v, i) => v ^ b[i]!));
const sha = (b: Buffer): string => createHash("sha256").update(b).digest("hex");
type Doc = Record<string, any>;

const dirs: string[] = [];
after(async () => {
  for (const d of dirs) await rm(d, { recursive: true, force: true });
});

async function sandbox(): Promise<string> {
  const cwd = await mkdtemp(join(tmpdir(), "rw-fixes-"));
  dirs.push(cwd);
  await mkdir(join(cwd, "work"), { recursive: true });
  return cwd;
}

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

/** OpenSSL's ChaCha20: the IV is the 32-bit block counter (little-endian) and then the 12-byte nonce. */
function chacha(key: Buffer, nonce: Buffer, data: Buffer, counter = 0): Buffer {
  const iv = Buffer.alloc(16);
  iv.writeUInt32LE(counter, 0);
  nonce.copy(iv, 4);
  return createCipheriv("chacha20", key, iv).update(data);
}

const HEADS: Record<string, Buffer> = {
  png: Buffer.from("89504e470d0a1a0a0000000d49484452", "hex"),
  jpg: Buffer.from("ffd8ffe000104a464946", "hex"),
  pdf: Buffer.from("%PDF-1.7\n%\xe2\xe3\xcf\xd3\n", "latin1"),
  docx: Buffer.from("504b0304140006000800", "hex"),
  ole: Buffer.from("d0cf11e0a1b11ae1", "hex"),
};

type Made = { name: string; plain: Buffer; key: Buffer };
/** One member per [name, first bytes]: ChaCha20 under a random key, the key XOR `mask` appended; `counterOf` gives a member's first block. */
async function members(dir: string, list: Array<[string, Buffer]>, mask: Buffer, nonce: Buffer, counterOf: (name: string) => number = () => 0, size = 1500): Promise<Made[]> {
  await mkdir(dir, { recursive: true });
  const made: Made[] = [];
  for (const [name, head] of list) {
    const plain = Buffer.concat([head, randomBytes(size + made.length)]);
    const key = randomBytes(32);
    await writeFile(join(dir, name), Buffer.concat([chacha(key, nonce, plain, counterOf(name)), xor(key, mask)]));
    made.push({ name, plain, key });
  }
  return made;
}

// ---- stream_kpa_check: the footer hypothesis ----

test("the footer hypothesis is tried on every other member: the same family gives the same rule in either order of its members' names", { timeout: 300_000 }, async () => {
  const good: Array<[string, Buffer]> = [["c.docx", HEADS.docx!], ["d.jpg", HEADS.jpg!], ["e.pdf", HEADS.pdf!]];
  // Three members named .db whose content is an OLE file, not SQLite: encrypted by the family's rule, and their crib can never hold.
  const odd = ["Thumbs.db", "ehthumbs.db", "cache.db"];
  const results: Doc[] = [];
  for (const prefix of ["b_", "z_"]) {
    // "b_..." sorts right after the opened member (a.png), "z_..." after every other member.
    const cwd = await sandbox();
    const dir = join(cwd, "work", "share");
    const mask = randomBytes(32), nonce = randomBytes(12);
    const list: Array<[string, Buffer]> = [["a.png", HEADS.png!], ...good, ...odd.map((n): [string, Buffer] => [prefix + n, HEADS.ole!])];
    const made = await members(dir, list.map(([n, h]) => [`${n}.locked`, h]), mask, nonce);
    await writeFile(join(cwd, "work", "key.bin"), made[0]!.key);
    const run = await job(KPA, cwd, "j000001", { dir: "work/share", glob: "*.locked", key_sources: [{ file: "work/key.bin", offset: 0, length: 32 }], nonce_sources: [{ hex: nonce.toString("hex") }] });
    const kpa = answer(run);
    assert.equal(kpa.status, "complete", kpa.status_basis);
    assert.equal(kpa.outcome, "some_members_explained", `${prefix}: ${kpa.finding}`);
    assert.equal(kpa.derived_rules.length, 1, `${prefix}: the rule is derived wherever the odd members sort`);
    assert.deepEqual([kpa.derived_rules[0].region, kpa.derived_rules[0].skip, kpa.derived_rules[0].explains, kpa.derived_rules[0].of], ["tail", 0, 4, 7]);
    const verdict = Object.fromEntries(kpa.files.map((r: Doc) => [r.file.split("/").pop().replace(prefix, ""), r.verdict]));
    results.push(verdict);
    for (const [name] of [["a.png"], ...good]) assert.equal(verdict[`${name}.locked`], "match", `${prefix}: ${name}`);
    for (const name of odd) assert.equal(verdict[`${name}.locked`], "no_match", `${prefix}: ${name} never shows a SQLite head`);
    // Their no_match is not left bare: the row says the content may not be what the name promises, and that this is no evidence against the rule.
    for (const r of kpa.files.filter((r: Doc) => r.verdict === "no_match")) assert.match(r.note, /no crib, and this is no evidence against the rule/);
    // Every place was tried on the members no rule explains, and the answer says so.
    assert.equal(kpa.tried.derivation.stopped_by, null);
    assert.equal(kpa.tried.derivation.places_tried_on_every_member, kpa.tried.derivation.places);
    assert.equal(kpa.tried.derivation.places, 65);
    assert.equal(kpa.trials, kpa.files.reduce((n: number, r: Doc) => n + r.trials, 0), "the derived trials are in the rows and in the total");
    assert.ok(kpa.recipe_file, "a rule that explains four members is a recipe");
    const recipe = JSON.parse(await readFile(join(cwd, kpa.recipe_file), "utf8")) as Doc;
    assert.equal(recipe.key.xor_hex, mask.toString("hex"));
    // The recipe decrypts every member, the three odd ones too (their type is not confirmed, and the answer is partial for it).
    const dec = answer(await job(DECRYPT, cwd, "j000002", { dir: "work/share", recipe_file: kpa.recipe_file }));
    assert.equal(dec.members.named, 7);
    for (const m of made) {
      const row = dec.files.find((r: Doc) => r.file.endsWith(`/${m.name}`));
      assert.ok((await readFile(join(cwd, row.output))).equals(m.plain), m.name);
    }
  }
  assert.deepEqual(results[0], results[1], "the verdicts do not follow the order of the names");
});

test("members that use another first block than the opened member are found by the hypothesis, and the recipe holds both variants", { timeout: 120_000 }, async () => {
  const cwd = await sandbox();
  const mask = randomBytes(32), nonce = randomBytes(12);
  const list: Array<[string, Buffer]> = [["a.png.locked", HEADS.png!], ["b.pdf.locked", HEADS.pdf!], ["c.jpg.locked", HEADS.jpg!], ["d.docx.locked", HEADS.docx!]];
  // Only the opened member starts at block 0: what opened it opens no other member, so the cheap first pass finds nothing.
  const made = await members(join(cwd, "work", "share"), list, mask, nonce, (name) => (name.startsWith("a.") ? 0 : 1));
  await writeFile(join(cwd, "work", "key.bin"), made[0]!.key);
  const kpa = answer(await job(KPA, cwd, "j000001", { dir: "work/share", key_sources: [{ file: "work/key.bin", offset: 0, length: 32 }], nonce_sources: [{ hex: nonce.toString("hex") }], ciphers: ["chacha20-ietf"] }));
  assert.equal(kpa.status, "complete", kpa.status_basis);
  assert.equal(kpa.outcome, "one_rule_explains_every_member", kpa.finding);
  assert.deepEqual(kpa.recipe.variants.map((v: Doc) => [v.cipher, v.counter, v.members]), [["chacha20-ietf", 1, 3], ["chacha20-ietf", 0, 1]]);
});

test("the derived trials count against max_trials and the clock: a bound that stops the hypothesis makes the answer partial and says what was not tried", { timeout: 180_000 }, async () => {
  const cwd = await sandbox();
  const nonce = randomBytes(12);
  const list: Array<[string, Buffer]> = [["a.png.locked", HEADS.png!], ["b.pdf.locked", HEADS.pdf!], ["c.jpg.locked", HEADS.jpg!], ["d.docx.locked", HEADS.docx!], ["e.png.locked", HEADS.png!]];
  const made = await members(join(cwd, "work", "share"), list, randomBytes(32), nonce);
  // No footer rule: every trailer but the opened member's is noise, so the hypothesis has every place to try on every member.
  for (const m of made.slice(1)) {
    const data = await readFile(join(cwd, "work", "share", m.name));
    randomBytes(32).copy(data, data.length - 32);
    await writeFile(join(cwd, "work", "share", m.name), data);
  }
  await writeFile(join(cwd, "work", "key.bin"), made[0]!.key);
  const nonces = Array.from({ length: 400 }, (_, i) => JSON.stringify({ finding_id: `F${String(i + 1).padStart(6, "0")}`, offset: 64 * i, kind: "chacha-state", layouts: { ietf: { counter: 0, nonce_hex: (i === 200 ? nonce : randomBytes(12)).toString("hex") } } }));
  await writeFile(join(cwd, "work", "nonces.jsonl"), nonces.join("\n") + "\n");
  const args = { dir: "work/share", key_sources: [{ file: "work/key.bin", offset: 0, length: 32 }], nonce_sources: [{ candidates: "work/nonces.jsonl" }], ciphers: ["chacha20-ietf"], counters: [0, 1, 2, 3] };
  // The sources' trials: 5 members x 400 nonces x 4 counters = 8000. The hypothesis needs 65 places x 4 members x 1600 more.
  const tight = answer(await job(KPA, cwd, "j000001", { ...args, max_trials: 20_000 }));
  assert.equal(tight.status, "partial");
  // A place is begun only when the trials it takes fit in what max_trials leaves (1.14.5: a place is tried whole or not at all): the
  // first pass is 65 places x 4 members (260), one place of the second pass is 4 members x 1599 other variants (6396), and the next
  // one's 6396 would pass the 20,000.
  assert.equal(tight.trials, 8000 + 260 + 6396, "not one trial past max_trials, and no place begun that would pass it");
  assert.equal(tight.tried.derivation.stopped_by, "max_trials");
  assert.equal(tight.tried.derivation.trials, 260 + 6396);
  assert.ok(tight.tried.derivation.places_tried_on_every_member < tight.tried.derivation.places);
  assert.match(tight.status_basis, /max_trials \(20000\) was reached while the footer hypothesis was being tried: \d+ of its 65 places/);
  assert.ok(tight.not_tried.some((l: string) => /^the footer hypothesis, in part: max_trials \(20000\) was reached/.test(l)), "not_tried says so");
  assert.equal(tight.outcome, "some_members_explained");
  for (const row of tight.files.filter((r: Doc) => r.verdict === "no_match")) assert.match(row.note, /footer hypothesis was stopped by max_trials before every place was tried on it/);
  // The clock: max_seconds holds while the hypothesis runs (it used to be read only between two skips).
  const started = Date.now();
  const timed = answer(await job(KPA, cwd, "j000002", { ...args, max_trials: 5_000_000, max_seconds: 3 }));
  const seconds = (Date.now() - started) / 1000;
  assert.equal(timed.status, "partial");
  assert.equal(timed.tried.derivation.stopped_by, "max_seconds");
  assert.match(timed.status_basis, /the time limit \(max_seconds 3\) was reached while the footer hypothesis was being tried/);
  assert.ok(seconds < 3 + 4, `the tool answered ${seconds.toFixed(1)} s after it started, with max_seconds 3`);
  // With room for all of it the answer is complete: every place on every member, and still no rule.
  const whole = answer(await job(KPA, cwd, "j000003", { ...args, counters: [0], nonce_sources: [{ hex: nonce.toString("hex") }] }));
  assert.equal(whole.status, "complete", whole.status_basis);
  assert.deepEqual([whole.tried.derivation.places_tried_on_every_member, whole.tried.derivation.stopped_by, whole.derived_rules.length], [65, null, 0]);
  assert.equal(whole.tried.derivation.trials, 65 * 4, "one variant, so the second pass has nothing more to try than the first did");
});

test("a key kept unmasked in the trailer: the answer does not say that the mask is all zero, the recipe file does", { timeout: 120_000 }, async () => {
  const cwd = await sandbox();
  const nonce = randomBytes(12);
  const list: Array<[string, Buffer]> = [["a.png.locked", HEADS.png!], ["b.pdf.locked", HEADS.pdf!], ["c.jpg.locked", HEADS.jpg!]];
  const made = await members(join(cwd, "work", "share"), list, Buffer.alloc(32), nonce);
  await writeFile(join(cwd, "work", "key.bin"), made[0]!.key);
  const run = await job(KPA, cwd, "j000001", { dir: "work/share", key_sources: [{ file: "work/key.bin", offset: 0, length: 32 }], nonce_sources: [{ hex: nonce.toString("hex") }] });
  const kpa = answer(run);
  assert.equal(kpa.outcome, "one_rule_explains_every_member", kpa.finding);
  assert.doesNotMatch(run.stdout, /mask_all_zero|\(all zero|stored unmasked|"key_mask_all_zero"/);
  assert.equal(kpa.derived_rules[0].rule, "derived_rules[0]: the last 32 bytes of each file XOR a 32-byte constant");
  const recipe = JSON.parse(await readFile(join(cwd, kpa.recipe_file), "utf8")) as Doc;
  assert.equal(recipe.key_mask_all_zero, true);
  assert.equal(recipe.key.xor_hex, "00".repeat(32));
});

// ---- stream_kpa_check and family_decrypt: which files are members, and how a recipe names them ----

test("a shared extension that is not lower case is the member suffix, with its case: a ransom note beside the members is not decrypted", { timeout: 120_000 }, async () => {
  const cwd = await sandbox();
  const mask = randomBytes(32), nonce = randomBytes(12);
  const dir = join(cwd, "work", "share");
  const made = await members(dir, [["a.png.LoCKed", HEADS.png!], ["b.pdf.LoCKed", HEADS.pdf!], ["c.jpg.LOCKED", HEADS.jpg!], ["d.docx.LoCKed", HEADS.docx!]], mask, nonce);
  await writeFile(join(dir, "RESTORE-FILES.txt"), "Your files are encrypted.\n".repeat(10));
  const tail = { key_sources: [{ slice: "tail", length: 32, xor: { hex: mask.toString("hex") } }], nonce_sources: [{ hex: nonce.toString("hex") }], ciphers: ["chacha20-ietf"] };
  const kpa = answer(await job(KPA, cwd, "j000001", { dir: "work/share", ...tail }));
  assert.equal(kpa.outcome, "one_rule_explains_every_member", kpa.finding);
  assert.equal(kpa.recipe.member_suffix, ".LoCKed", "compared in any case, written as most members write it");
  // dir and no glob: the files that carry the suffix, in any case. The note is not one of them.
  const dec = answer(await job(DECRYPT, cwd, "j000002", { dir: "work/share", recipe_file: kpa.recipe_file }));
  assert.equal(dec.status, "complete", dec.status_basis);
  assert.equal(dec.members.named, 4);
  for (const m of made) {
    const row = dec.files.find((r: Doc) => r.file.endsWith(`/${m.name}`));
    assert.equal(row.verdict, "decrypted, type confirmed", m.name);
    assert.ok((await readFile(join(cwd, row.output))).equals(m.plain), m.name);
  }
  // Named outright (files, or a glob that takes everything), the note is still not a member: it is listed, not turned into noise.
  for (const args of [{ files: ["work/share/RESTORE-FILES.txt", "work/share/a.png.LoCKed"] }, { dir: "work/share", glob: "*" }]) {
    const named = answer(await job(DECRYPT, cwd, "j000003", { ...args, recipe_file: kpa.recipe_file }));
    assert.equal(named.status, "partial");
    const note = named.files.find((r: Doc) => r.file.endsWith("RESTORE-FILES.txt"));
    assert.equal(note.verdict, "not decrypted");
    assert.match(note.failure, /not a member: its name does not end in the recipe's member_suffix/);
    assert.equal(note.output, null);
    assert.equal(named.members.not_decrypted_not_a_member, 1);
    assert.match(named.status_basis, /1 files named are not members and were not decrypted/);
  }
});

test("two members of one name in two directories are two entries of the recipe: each is decrypted with its own variant", { timeout: 120_000 }, async () => {
  const cwd = await sandbox();
  const mask = randomBytes(32), nonce = randomBytes(12);
  const list: Array<[string, Buffer]> = [["a.png.locked", HEADS.png!], ["b.pdf.locked", HEADS.pdf!]];
  const made: Array<Made & { sub: string }> = [];
  for (const [sub, counter] of [["d1", 0], ["d2", 1]] as const) {
    for (const m of await members(join(cwd, "work", "share", sub), list, mask, nonce, () => counter)) made.push({ ...m, sub });
  }
  const tail = { key_sources: [{ slice: "tail", length: 32, xor: { hex: mask.toString("hex") } }], nonce_sources: [{ hex: nonce.toString("hex") }], ciphers: ["chacha20-ietf"] };
  const kpa = answer(await job(KPA, cwd, "j000001", { dir: "work/share", recursive: true, ...tail }));
  assert.equal(kpa.outcome, "one_rule_explains_every_member", kpa.finding);
  const recipe = JSON.parse(await readFile(join(cwd, kpa.recipe_file), "utf8")) as Doc;
  assert.deepEqual(Object.keys(recipe.assignments).sort(), ["d1/a.png.locked", "d1/b.pdf.locked", "d2/a.png.locked", "d2/b.pdf.locked"]);
  assert.notEqual(recipe.assignments["d1/a.png.locked"], recipe.assignments["d2/a.png.locked"]);
  const dec = answer(await job(DECRYPT, cwd, "j000002", { dir: "work/share", recursive: true, recipe_file: kpa.recipe_file }));
  assert.equal(dec.status, "complete", dec.status_basis);
  for (const m of made) {
    const row = dec.files.find((r: Doc) => r.file.endsWith(`/${m.sub}/${m.name}`));
    assert.equal(row.counter, m.sub === "d1" ? 0 : 1);
    assert.equal(row.variant_chosen_by, "the recipe's assignment for this member");
    assert.ok((await readFile(join(cwd, row.output))).equals(m.plain), `${m.sub}/${m.name}`);
  }
  // Listed from one of the two directories, a name the recipe holds twice with two variants is not taken from it: the result decides.
  const one = answer(await job(DECRYPT, cwd, "j000003", { dir: "work/share/d2", recipe_file: kpa.recipe_file }));
  for (const m of made.filter((x) => x.sub === "d2")) {
    const row = one.files.find((r: Doc) => r.file.endsWith(`/${m.name}`));
    assert.match(row.variant_chosen_by, /the variant whose result starts with the bytes of the type in the name/);
    assert.ok((await readFile(join(cwd, row.output))).equals(m.plain), m.name);
  }
});

test("no trial is no negative: a cipher with no fitting nonce leaves its members not_tried, and a candidates file with no key says what it held", { timeout: 120_000 }, async () => {
  const cwd = await sandbox();
  const mask = randomBytes(32), nonce = randomBytes(12);
  await members(join(cwd, "work", "share"), [["a.png.locked", HEADS.png!], ["b.pdf.locked", HEADS.pdf!]], mask, nonce);
  const key = { slice: "tail", length: 32, xor: { hex: mask.toString("hex") } };
  // ChaCha20 (IETF) takes a 12-byte nonce and the call gives 8 bytes: nothing can be tried.
  const none = answer(await job(KPA, cwd, "j000001", { dir: "work/share", key_sources: [key], nonce_sources: [{ hex: "00".repeat(8) }], ciphers: ["chacha20-ietf"] }));
  assert.equal(none.status, "partial");
  assert.equal(none.outcome, "nothing_tried");
  assert.equal(none.trials, 0);
  assert.deepEqual(none.members.by_verdict, { not_tried: 2 });
  assert.ok(none.files.every((r: Doc) => r.verdict === "not_tried" && /no trial could be made on this member/.test(r.note)));
  assert.match(none.status_basis, /2 members that have a crib had no trial at all/);
  assert.deepEqual(none.tried.trials_by_cipher, { "chacha20-ietf": 0 });
  assert.ok(none.not_tried.some((l: string) => /^asked for and not tried, on any member: chacha20-ietf\./.test(l)));
  assert.equal(none.recipe, null);
  // The default ciphers: the ones the sources cannot feed are named, the others ran, and the right one matched.
  const mixed = answer(await job(KPA, cwd, "j000002", { dir: "work/share", key_sources: [key], nonce_sources: [{ hex: nonce.toString("hex") }] }));
  assert.equal(mixed.status, "complete", mixed.status_basis);
  assert.equal(mixed.outcome, "one_rule_explains_every_member");
  assert.deepEqual(mixed.tried.trials_by_cipher, { "chacha20-ietf": 4, "chacha20-original": 0, salsa20: 0, "aes-ctr": 4, rc4: 2, xor: 2 });
  assert.ok(mixed.not_tried.some((l: string) => /^asked for and not tried, on any member: chacha20-original, salsa20\./.test(l)));
  // A values file whose rows hold no key (permutations only): refused with what the file held, not as a missing parameter.
  await writeFile(join(cwd, "work", "perms.jsonl"), [JSON.stringify({ finding_id: "F000001", offset: 10, kind: "rc4-permutation", permutation_hex: "00" }), "not json", JSON.stringify({ finding_id: "F000002", offset: 20, kind: "rc4-permutation" })].join("\n") + "\n");
  const empty = answer(await job(KPA, cwd, "j000003", { dir: "work/share", key_sources: [{ candidates: "work/perms.jsonl" }] }), 1);
  assert.equal(empty.status, "failed");
  assert.match(empty.error, /^key_sources yields no key: key_sources\[0\] is a candidates file of 2 rows, 1 of them not usable[\s\S]*and 0 distinct keys/);
  assert.doesNotMatch(empty.error, /key_sources is required/);
  const missing = answer(await job(KPA, cwd, "j000004", { dir: "work/share" }), 1);
  assert.match(missing.error, /^key_sources is required/);
});

test("400 members with 64 descriptors: one member is open at a time; a name that is not ASCII is printed as given", { timeout: 180_000 }, async () => {
  const cwd = await sandbox();
  const mask = randomBytes(32), nonce = randomBytes(12);
  const list = Array.from({ length: 400 }, (_, i): [string, Buffer] => [`f${String(i).padStart(4, "0")}.png.locked`, HEADS.png!]);
  list.push(["ödeme-заказ-請求.pdf.locked", HEADS.pdf!]);
  await members(join(cwd, "work", "share"), list, mask, nonce, () => 0, 100);
  const out = join(cwd, "store", "jobs", "j000001", "out");
  await mkdir(out, { recursive: true });
  const args = { dir: "work/share", max_files: 500, limit: 500, key_sources: [{ slice: "tail", length: 32, xor: { hex: mask.toString("hex") } }], nonce_sources: [{ hex: nonce.toString("hex") }], ciphers: ["chacha20-ietf"] };
  const ran = await new Promise<Run>((resolve, reject) => {
    const child = spawn("bash", ["-c", 'ulimit -n 64; exec "$0" "$1"', PYTHON3, KPA], { cwd, env: { ...process.env, AGENT_ID: "s1", JOB_ID: "j000001", OUT: out, SECRET_OUTPUT: "1" } });
    const so: Buffer[] = [], se: Buffer[] = [];
    child.stdout.on("data", (c: Buffer) => so.push(c));
    child.stderr.on("data", (c: Buffer) => se.push(c));
    child.on("error", reject);
    child.on("close", (code) => resolve({ code, stdout: Buffer.concat(so).toString("utf8"), stderr: Buffer.concat(se).toString("utf8") }));
    child.stdin.end(JSON.stringify(args));
  });
  const kpa = answer(ran);
  assert.equal(kpa.status, "complete", kpa.status_basis);
  assert.deepEqual(kpa.members.by_verdict, { match: 401 });
  assert.equal(kpa.outcome, "one_rule_explains_every_member");
  assert.ok(kpa.files.some((r: Doc) => r.file === "work/share/ödeme-заказ-請求.pdf.locked"), "the path is the one given, not one with question marks");
  // family_decrypt prints it as given too, and writes under a safe name.
  const dec = answer(await job(DECRYPT, cwd, "j000002", { files: ["work/share/ödeme-заказ-請求.pdf.locked"], recipe_file: kpa.recipe_file }));
  assert.equal(dec.files[0].file, "work/share/ödeme-заказ-請求.pdf.locked");
  assert.equal(dec.files[0].verdict, "decrypted, type confirmed");
  assert.match(dec.files[0].output, /\/decrypted\/0001_[A-Za-z0-9._-]+\.pdf$/);
});

// ---- family_decrypt ----

test("family_decrypt refuses outside a secret-output job before it reads the recipe or lists a directory; a large header is hashed in pieces", { timeout: 120_000 }, async () => {
  const cwd = await sandbox();
  // Neither the recipe file nor the directory is there: the answer is the refusal, not what reading either would have said.
  for (const run of [await tool(DECRYPT, cwd, { dir: "work/nothing", recipe_file: "work/no-recipe.json" }), await job(DECRYPT, cwd, "j000001", { dir: "work/nothing", recipe_file: "work/no-recipe.json" }, false)]) {
    const refused = answer(run, 1);
    assert.match(refused.error, /refused outside a job run as secret output[\s\S]*Nothing was read and nothing was written/);
    assert.doesNotMatch(refused.error, /recipe_file|not a directory/);
    assert.equal(refused.written, false);
  }
  assert.match(answer(await job(DECRYPT, cwd, "j000002", { dir: "work/nothing", recipe_file: "work/no-recipe.json" }), 1).error, /recipe_file could not be read/);
  // A header of 3 MiB before the ciphertext and a trailer of 2 MiB after the key: the digest of the member as it was covers both.
  const key = randomBytes(32), nonce = randomBytes(12);
  const plain = Buffer.concat([HEADS.png!, randomBytes(5000)]);
  const member = Buffer.concat([randomBytes(3 << 20), chacha(key, nonce, plain), randomBytes(2 << 20)]);
  await mkdir(join(cwd, "work", "big"), { recursive: true });
  await writeFile(join(cwd, "work", "big", "a.png.locked"), member);
  const recipe = { recipe: "stream-family/1", key: { hex: key.toString("hex") }, variants: [{ cipher: "chacha20-ietf", counter: 0, nonce: { hex: nonce.toString("hex") } }], assignments: {}, header_bytes: 3 << 20, trailer_bytes: 2 << 20, member_suffix: ".locked" };
  const dec = answer(await job(DECRYPT, cwd, "j000003", { dir: "work/big", recipe }));
  assert.equal(dec.status, "complete", dec.status_basis);
  assert.equal(dec.files[0].sha256_ciphertext, sha(member));
  assert.ok((await readFile(join(cwd, dec.files[0].output))).equals(plain));
});

// ---- cipher_state_scan ----

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
const swapWords = (s: Buffer): Buffer => Buffer.concat(Array.from({ length: s.length / 4 }, (_, i) => Buffer.from(s.subarray(4 * i, 4 * i + 4)).reverse()));

/** A random key of `bytes` bytes whose schedule has a zero byte at `at` (counted from the end when negative). */
function keyWithZeroAt(bytes: number, at: number): Buffer {
  for (;;) {
    const key = randomBytes(bytes);
    const schedule = expandKey(key);
    if (schedule[at < 0 ? schedule.length + at : at] === 0) return key;
  }
}

test("an AES schedule that ends or begins in zero bytes among zero bytes is found; so is the schedule of the all-zero key between zero pages", { timeout: 300_000 }, async () => {
  assert.equal(expandKey(Buffer.from("2b7e151628aed2a6abf7158809cf4f3c", "hex")).subarray(160).toString("hex"), "d014f9a8c9ee2589e13f0cc8b6630ca6", "the test's own key expansion is FIPS-197's");
  const cwd = await sandbox();
  type Plant = { what: string; kind: string; key: Buffer; blob: Buffer; before: Buffer; after: Buffer; swapped?: boolean };
  const zeros = (n: number): Buffer => Buffer.alloc(n);
  const plants: Plant[] = [];
  for (const bytes of [16, 24, 32]) {
    const kind = `aes-${8 * bytes}-key-schedule`;
    const last = keyWithZeroAt(bytes, -1);
    // The case that was missed: the last byte of the schedule is 00 and at least 15 zero bytes follow it (the unused words of a key structure).
    plants.push({ what: `${kind}, last byte 00, 15 zero bytes after`, kind, key: last, blob: expandKey(last), before: randomBytes(64), after: Buffer.concat([zeros(15), Buffer.from([0x0a]), randomBytes(48)]) });
    plants.push({ what: `${kind}, last byte 00, 64 zero bytes after and before`, kind, key: last, blob: expandKey(last), before: zeros(64), after: zeros(64) });
    plants.push({ what: `${kind}, last byte 00, a zero page after`, kind, key: last, blob: expandKey(last), before: randomBytes(64), after: zeros(4096) });
    // The mirror: the first bytes of the schedule are zero and zero bytes stand before it.
    const first = Buffer.concat([zeros(3), randomBytes(bytes - 3)]);
    plants.push({ what: `${kind}, first three bytes 00, 15 zero bytes before`, kind, key: first, blob: expandKey(first), before: Buffer.concat([randomBytes(48), Buffer.from([0x77]), zeros(15)]), after: randomBytes(64) });
    plants.push({ what: `${kind}, first three bytes 00, a zero page before`, kind, key: first, blob: expandKey(first), before: zeros(4096), after: randomBytes(64) });
    // Byte-swapped words: the byte stored last is the first byte of the last word.
    const swap = keyWithZeroAt(bytes, -4);
    plants.push({ what: `${kind}, byte-swapped, stored last byte 00, zero bytes after`, kind, key: swap, blob: swapWords(expandKey(swap)), before: randomBytes(64), after: zeros(300), swapped: true });
    // A schedule that holds a run of zero bytes itself: the all-zero key, between zero pages.
    plants.push({ what: `${kind} of the all-zero key between zero pages`, kind, key: zeros(bytes), blob: expandKey(zeros(bytes)), before: zeros(4096), after: zeros(4096) });
  }
  const parts: Buffer[] = [randomBytes(1000)];
  const at: number[] = [];
  let size = 1000;
  for (const p of plants) {
    at.push(size + p.before.length);
    parts.push(p.before, p.blob, p.after, randomBytes(200));
    size += p.before.length + p.blob.length + p.after.length + 200;
  }
  await writeFile(join(cwd, "work", "proc.dmp"), Buffer.concat(parts));
  const run = await job(SCAN, cwd, "j000001", { file: "work/proc.dmp", look_for: ["aes-schedule"] });
  const scan = answer(run);
  assert.equal(scan.status, "complete", scan.status_basis);
  assert.equal(scan.control.passed, true);
  const found = new Map<number, Doc>(scan.hits.map((h: Doc) => [h.offset, h]));
  const values = (await readFile(join(cwd, scan.candidates.values_file), "utf8")).trim().split("\n").map((l) => JSON.parse(l) as Doc);
  plants.forEach((p, i) => {
    assert.equal(found.get(at[i]!)?.kind, p.kind, `${p.what}: not found at ${at[i]}`);
    assert.equal(found.get(at[i]!)!.word_order, p.swapped ? "byte-swapped words (a 32-bit big-endian load on a little-endian machine)" : "as FIPS-197 writes them", p.what);
    assert.equal(values.find((v) => v.offset === at[i])?.key_hex, p.key.toString("hex"), `${p.what}: its key is in the values file`);
  });
  assert.equal(scan.hits.length, plants.length, "and nothing else is reported");
  // What the answer says it does not find no longer names zero bytes, and the control plants these cases itself.
  assert.ok(!scan.not_looked_for.some((l: string) => /holds a run of 16 zero bytes/.test(l)));
  assert.ok(scan.not_looked_for.some((l: string) => /Zero bytes in or around a\s+schedule do not hide it/.test(l)));
  assert.match(scan.control.how, /a last or a first byte of zero among zero bytes[\s\S]*all-zero key\s+between zero pages/);
  const self = answer(await tool(SCAN, cwd, { self_test: true, look_for: ["aes-schedule"] }));
  assert.equal(self.self_test.passed, true);
  assert.ok(self.self_test.planted >= 30, `the control plants ${self.self_test.planted} schedules`);
  // A scanner that changes zero runs of the file before it searches (what the tool did) fails that control and answers nothing.
  const { runPatched } = await import("./ransomware-pack-harness.ts");
  const out = join(cwd, "store", "jobs", "j000002", "out");
  await mkdir(out, { recursive: true });
  const patch = "real = m.scan_buffer\nm.scan_buffer = lambda buf, own, shapes, emit, counts: real(buf.replace(bytes(16), b'\\xa5' * 16), own, shapes, emit, counts)";
  const broken = JSON.parse((await runPatched(SCAN, patch, JSON.stringify({ file: "work/proc.dmp", look_for: ["aes-schedule"] }), cwd, out, { SECRET_OUTPUT: "1" })).stdout) as Doc;
  assert.equal(broken.status, "failed");
  assert.match(broken.error, /the planted control failed/);
  assert.ok(broken.control.missed.length >= 4);
});

test("whether nonce bytes of a state are zero is in the values file and not in the answer; an S-box met by the permutation search alone is counted", { timeout: 120_000 }, async () => {
  const cwd = await sandbox();
  const key = randomBytes(32), nonce8 = randomBytes(8);
  // A ChaCha state whose bytes 52 to 56 are zero: four nonce bytes in the IETF layout, the counter's high word in the original one.
  const state = Buffer.concat([SIGMA, key, Buffer.from([1, 0, 0, 0]), Buffer.alloc(4), nonce8]);
  const data = randomBytes(300_000);
  state.copy(data, 5000);
  Buffer.from(SBOX).copy(data, 100_000);
  await writeFile(join(cwd, "work", "proc.dmp"), data);
  const run = await job(SCAN, cwd, "j000001", { file: "work/proc.dmp", look_for: ["chacha-salsa", "rc4"] });
  const scan = answer(run);
  assert.equal(scan.status, "complete", scan.status_basis);
  assert.deepEqual(scan.hits.map((h: Doc) => [h.kind, h.offset]), [["chacha-state", 5000]]);
  assert.doesNotMatch(run.stdout, /bytes_52_to_56_zero|52_to_56/);
  assert.deepEqual(Object.keys(scan.hits[0]).sort(), ["bytes", "candidate", "counter_32bit", "finding_id", "key_bytes", "key_distinct_byte_values", "key_shape", "kind", "matched", "offset", "values"]);
  const values = (await readFile(join(cwd, scan.candidates.values_file), "utf8")).trim().split("\n").map((l) => JSON.parse(l) as Doc);
  assert.equal(values[0]!.bytes_52_to_56_zero, true);
  assert.equal(values[0]!.layouts.ietf.nonce_hex, Buffer.concat([Buffer.alloc(4), nonce8]).toString("hex"));
  // The S-box is a permutation: without `tables` it is not a hit, and it is not dropped without a count either.
  assert.equal(scan.counts.aes_sbox_permutations, 1);
  const tables = answer(await job(SCAN, cwd, "j000002", { file: "work/proc.dmp", look_for: ["rc4", "tables"] }));
  assert.deepEqual(tables.hits.map((h: Doc) => [h.kind, h.matched, h.offset]), [["constant-table", "AES S-box", 100_000]]);
  assert.equal(tables.counts.aes_sbox_permutations, 1);
});

test("a tool-output that is a link is not written through: the list of all hits is not written, and the answer says so", { timeout: 120_000 }, async () => {
  const cwd = await sandbox();
  const outside = join(cwd, "outside");
  await mkdir(outside);
  const out = join(cwd, "store", "jobs", "j000001", "out");
  await mkdir(out, { recursive: true });
  await symlink(outside, join(out, "tool-output"));
  await writeFile(join(cwd, "work", "many.dmp"), Buffer.concat(Array.from({ length: 40 }, () => Buffer.concat([SIGMA, randomBytes(48), randomBytes(100)]))));
  const scan = answer(await job(SCAN, cwd, "j000001", { file: "work/many.dmp", limit: 5 }));
  assert.equal(scan.counts.hits, 40);
  assert.equal(scan.hits.length, 5);
  assert.equal(scan.status, "partial");
  assert.match(scan.status_basis, /the list of all hits could not be written \([\s\S]*tool-output is there and is not a directory of this run[\s\S]*\): only the first 5 are shown/);
  assert.equal(scan.all_hits, undefined);
  assert.deepEqual(await readdir(outside), [], "nothing was written through the link");
  // With a directory of its own the list is written.
  const good = answer(await job(SCAN, cwd, "j000002", { file: "work/many.dmp", limit: 5 }));
  assert.match(good.all_hits, /^store\/jobs\/j000002\/out\/tool-output\/cipher_state_scan-hits-[0-9a-f]{16}\.jsonl$/);
});

// ---- encrypted_survey 13: the census label moved, and its two readers take it ----

test("a census of encrypted_survey/5 (a tail measured, not printed) is read by encryption_extent and by ransomware_scope_report", { timeout: 120_000 }, async () => {
  const cwd = await sandbox();
  const dir = join(cwd, "work", "share");
  await mkdir(dir, { recursive: true });
  for (let i = 0; i < 3; i++) await writeFile(join(dir, `f${i}.pdf.locked`), randomBytes(20_000 + i));
  const SURVEY = join(PACK, "encrypted_survey", "run.py");
  const survey = answer(await tool(SURVEY, cwd, { root: "work/share" }));
  assert.equal(survey.parser, "encrypted_survey/5");
  const lines = (await readFile(join(cwd, survey.census.file), "utf8")).trim().split("\n").map((l) => JSON.parse(l) as Doc);
  assert.equal(lines.at(-1)!.parser, "encrypted_survey/5");
  assert.ok(lines.filter((r) => r.status === "candidate").every((r) => r.tail.bytes === 32 && !("tail_hex" in r)));
  const extent = answer(await tool(join(PACK, "encryption_extent", "run.py"), cwd, { policy: "sampling", census: survey.census.file }));
  assert.equal(extent.error, undefined, JSON.stringify(extent).slice(0, 400));
  assert.notEqual(extent.status, "failed");
  const report = answer(await tool(join(PACK, "ransomware_scope_report", "run.py"), cwd, { censuses: [{ host: "h1", file: survey.census.file }] }));
  assert.equal(report.error, undefined, JSON.stringify(report).slice(0, 400));
  assert.notEqual(report.status, "failed");
});
