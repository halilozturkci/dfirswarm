/**
 * chromium_logins and dpapi_masterkey: the saved logins of a Chromium-family profile, and the DPAPI steps that lead to its key.
 *
 * Every fixture is made here in the FORWARD direction, with node:crypto and never with the tools' own code: a master key file encrypted for a
 * chosen password and SID (PBKDF2-HMAC-SHA512, AES-256-CBC, the HMAC over the key), a DPAPI blob under that master key (the session key, the
 * padding, the signature), a Local State that holds the blob, and 'v10' values (AES-256-GCM). The tools then have to recover what was put in.
 * The readers' AES is their own (pure Python), so a fixture made with OpenSSL's is an independent check of it; where the host's Python has the
 * cryptography module the primitives are also compared with it on random inputs.
 *
 * What is NOT shown here: that a master key file made by Windows opens with its user's password. The layout of a real file was read by hand
 * (in the manifests); no real file with a known password was at hand.
 *
 * What is held: a known key decrypts and the tag is verified; a wrong key, password, SID or entropy is an answer (`decrypted: false`,
 * `verified: false`) and never an exception or a wrong value; no password, key or digest of one is in an answer or in a file that is not the
 * sealed values file; the tools refuse outside a secret-output job, except the self-test; wrong arguments and a stop get one JSON document.
 */
import assert from "node:assert/strict";
import { createCipheriv, createHash, createHmac, pbkdf2Sync, randomBytes } from "node:crypto";
import { chmodSync, existsSync, mkdirSync, readFileSync, readdirSync, statSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { test } from "node:test";
import { withCwd } from "./tool-library-harness.ts";
import { WIN, py, pythonCanImport } from "./windows-pack-harness.ts";
import { assertJsonAnswer, assertStopped, fuzzTool, manifestOf, runTool, stopAt, typeConfused, type StopSignal } from "./windows-tool-contract.ts";

type Answer = Record<string, any>; // eslint-disable-line @typescript-eslint/no-explicit-any
const SID = "S-1-5-21-1004336348-1177238915-682003330-1001";
const GUID = "3f2a9c10-77aa-4b1e-9d2c-5e6f7a8b9c0d";
const PASSWORD = "Tr0ub4dor&3 über";
const SECRETS = ["hunter2-first", "correct horse battery staple", "pässwörd-三"];
const u16 = (s: string): Buffer => Buffer.from(s, "utf16le");
const sha1 = (b: Buffer): Buffer => createHash("sha1").update(b).digest();
const hmac = (alg: string, key: Buffer, ...data: Buffer[]): Buffer => data.reduce((h, d) => h.update(d), createHmac(alg, key)).digest();

// --- the forward direction ------------------------------------------------------------------------------------------------------------------

function cbc(key: Buffer, iv: Buffer, clear: Buffer, pad: boolean): Buffer {
  const c = createCipheriv("aes-256-cbc", key, iv);
  c.setAutoPadding(pad);
  return Buffer.concat([c.update(clear), c.final()]);
}

/** The pre-key of a local account: HMAC-SHA1 over the SID in UTF-16LE with its terminator, keyed by SHA-1 of the password in UTF-16LE. */
const prekeySha1 = (password: string, sid = SID): Buffer => hmac("sha1", sha1(u16(password)), u16(sid + "\0"));
const prekeyNt = (nt: Buffer, sid = SID): Buffer => hmac("sha1", nt, u16(sid + "\0"));

type MkOptions = { rounds?: number; hashAlg?: number; cipherAlg?: number; guid?: string };

/** A master key file as Windows 10 lays it out: a 128-byte header, the master key block, a backup key block and a credential history link. */
function masterKeyFile(prekey: Buffer, masterKey: Buffer, o: MkOptions = {}): Buffer {
  const rounds = o.rounds ?? 4000;
  const salt = randomBytes(16);
  const hmacSalt = randomBytes(16);
  const mac = hmac("sha512", hmac("sha512", prekey, hmacSalt), masterKey);
  const derived = pbkdf2Sync(prekey, salt, Math.min(rounds, 20000), 48, "sha512");
  const encrypted = cbc(derived.subarray(0, 32), derived.subarray(32), Buffer.concat([hmacSalt, mac, masterKey]), false);
  const block = Buffer.alloc(32);
  block.writeUInt32LE(2, 0);
  salt.copy(block, 4);
  block.writeUInt32LE(rounds, 20);
  block.writeUInt32LE(o.hashAlg ?? 0x800e, 24);
  block.writeUInt32LE(o.cipherAlg ?? 0x6610, 28);
  const key = Buffer.concat([block, encrypted]);
  const backup = Buffer.concat([Buffer.from([2, 0, 0, 0]), randomBytes(140)]);
  const credhist = Buffer.concat([Buffer.from([3, 0, 0, 0]), randomBytes(16)]);
  const head = Buffer.alloc(128);
  head.writeUInt32LE(2, 0);
  u16(o.guid ?? GUID).copy(head, 12);
  head.writeUInt32LE(5, 92);
  head.writeBigUInt64LE(BigInt(key.length), 96);
  head.writeBigUInt64LE(BigInt(backup.length), 104);
  head.writeBigUInt64LE(BigInt(credhist.length), 112);
  return Buffer.concat([head, key, backup, credhist]);
}

function guidBytes(guid: string): Buffer {
  const h = guid.replaceAll("-", "");
  const b = Buffer.from(h, "hex");
  return Buffer.concat([Buffer.from(b.subarray(0, 4)).reverse(), Buffer.from(b.subarray(4, 6)).reverse(), Buffer.from(b.subarray(6, 8)).reverse(), b.subarray(8)]);
}

const u32 = (n: number): Buffer => {
  const b = Buffer.alloc(4);
  b.writeUInt32LE(n >>> 0, 0);
  return b;
};

/** A DPAPI blob (CryptProtectData's output) under a master key: SHA-512 and AES-256, the signature in the form Windows 7 and later write. */
function dpapiBlob(masterKey: Buffer, clear: Buffer, o: { entropy?: Buffer; guid?: string; hashAlg?: number; cipherAlg?: number; description?: string } = {}): Buffer {
  const keyHash = sha1(masterKey);
  const salt = randomBytes(32);
  const hmacKey = randomBytes(32);
  const entropy = o.entropy ?? Buffer.alloc(0);
  const session = hmac("sha512", keyHash, salt, entropy);
  const cipherText = cbc(session.subarray(0, 32), Buffer.alloc(16), clear, true);
  const description = u16((o.description ?? "Google Chrome") + "\0");
  const body = Buffer.concat([
    u32(1), guidBytes(o.guid ?? GUID), u32(0x10), u32(description.length), description, u32(o.cipherAlg ?? 0x6610), u32(256), u32(salt.length), salt, u32(0),
    u32(o.hashAlg ?? 0x800e), u32(512), u32(hmacKey.length), hmacKey, u32(cipherText.length), cipherText,
  ]);
  const signature = hmac("sha512", keyHash, hmacKey, entropy, body);
  return Buffer.concat([u32(1), Buffer.from("d08c9ddf0115d1118c7a00c04fc297eb", "hex"), body, u32(signature.length), signature]);
}

function v10(key: Buffer, clear: string | Buffer, prefix = "v10"): Buffer {
  const nonce = randomBytes(12);
  const c = createCipheriv("aes-256-gcm", key, nonce);
  const body = Buffer.concat([c.update(typeof clear === "string" ? Buffer.from(clear, "utf8") : clear), c.final()]);
  return Buffer.concat([Buffer.from(prefix, "latin1"), nonce, body, c.getAuthTag()]);
}

const localState = (blob: Buffer, more: Record<string, unknown> = {}): string =>
  JSON.stringify({ browser: { enabled_labs_experiments: [] }, os_crypt: { audit_enabled: true, encrypted_key: Buffer.concat([Buffer.from("DPAPI"), blob]).toString("base64"), ...more } });

type Login = { origin: string; username: string; value: Buffer; created?: bigint; lastUsed?: bigint; timesUsed?: number; never?: number };
const T0 = 13352846768131444n; // 2024-02-19T20:06:08.131444Z in microseconds since 1601

/** A Login Data as Chrome lays the table out (the columns this reader takes, and two it does not), written by SQLite itself. */
function loginData(path: string, rows: Login[], o: { table?: string; extra?: string } = {}): void {
  py(
    [
      "import os, sqlite3, sys, json",
      "os.path.exists(sys.argv[1]) and os.remove(sys.argv[1])",
      "c = sqlite3.connect(sys.argv[1])",
      "c.execute('CREATE TABLE meta(key LONGVARCHAR NOT NULL UNIQUE PRIMARY KEY, value LONGVARCHAR)')",
      `c.execute('CREATE TABLE ${o.table ?? "logins"} (origin_url VARCHAR NOT NULL, action_url VARCHAR, username_element VARCHAR, username_value VARCHAR, password_element VARCHAR, password_value BLOB, submit_element VARCHAR, signon_realm VARCHAR NOT NULL, date_created INTEGER NOT NULL, blacklisted_by_user INTEGER NOT NULL, scheme INTEGER NOT NULL, times_used INTEGER, date_last_used INTEGER NOT NULL DEFAULT 0, date_password_modified INTEGER NOT NULL DEFAULT 0, id INTEGER PRIMARY KEY AUTOINCREMENT)')`,
      "for r in json.loads(sys.argv[2]):",
      `    c.execute('INSERT INTO ${o.table ?? "logins"} (origin_url, action_url, username_value, password_value, signon_realm, date_created, blacklisted_by_user, scheme, times_used, date_last_used, date_password_modified) VALUES (?,?,?,?,?,?,?,0,?,?,?)', (r['origin'], r['origin'], r['username'], bytes.fromhex(r['value']), r['origin'], r['created'], r['never'], r['times'], r['last'], r['created']))`,
      o.extra ?? "",
      "c.commit(); c.close()",
    ].join("\n"),
    path,
    JSON.stringify(rows.map((r) => ({ origin: r.origin, username: r.username, value: r.value.toString("hex"), created: Number(r.created ?? T0), last: Number(r.lastUsed ?? 0n), times: r.timesUsed ?? 0, never: r.never ?? 0 }))),
  );
}

// --- running the tools as the job service runs them -----------------------------------------------------------------------------------------

let jobs = 0;
/** The environment of a secret-output job with a fresh $OUT. */
function secretJob(cwd: string): Record<string, string> {
  const id = `j${String(++jobs).padStart(6, "0")}`;
  const out = join(cwd, "store", "jobs", id, "out");
  mkdirSync(out, { recursive: true });
  return { JOB_ID: id, OUT: out, SECRET_OUTPUT: "1" };
}

function secretFile(cwd: string, rel: string, content: string | Buffer): string {
  mkdirSync(join(cwd, rel, ".."), { recursive: true });
  writeFileSync(join(cwd, rel), content);
  chmodSync(join(cwd, rel), 0o600);
  return rel;
}

async function call(tool: string, cwd: string, args: Record<string, unknown>, env: Record<string, string>): Promise<{ out: Answer; raw: string; exit: number | null }> {
  const run = await runTool(tool, cwd, args, env);
  return { out: assertJsonAnswer(run, `${tool} ${JSON.stringify(args).slice(0, 100)}`) as Answer, raw: run.stdout, exit: run.code };
}

const lines = (path: string): Answer[] => readFileSync(path, "utf8").split("\n").filter(Boolean).map((l) => JSON.parse(l) as Answer);

/** No secret, in any encoding the tools handle, and no digest-shaped run, in text that is not the sealed file. */
function assertNoSecret(text: string, secrets: Array<string | Buffer>, where: string): void {
  for (const s of secrets) {
    const b = typeof s === "string" ? Buffer.from(s, "utf8") : s;
    for (const shape of [b.toString("utf8"), b.toString("hex"), b.toString("base64"), JSON.stringify(b.toString("utf8")).slice(1, -1)]) {
      if (shape.length >= 6) assert.ok(!text.includes(shape), `${where} holds a secret (${shape.length} characters of it)`);
    }
  }
  assert.doesNotMatch(text, /\b[0-9a-f]{64,}\b/i, `${where} holds a 64-digit hexadecimal run (a key or a digest)`);
}

type Profile = { key: Buffer; masterKey: Buffer; dir: string; loginData: string; localState: string; protect: string };

/** A profile on disk: Protect/<SID>/<GUID> for PASSWORD, a Local State whose key is under that master key, and a Login Data of three logins. */
function profile(cwd: string, o: { password?: string; prekey?: Buffer; rows?: (key: Buffer, masterKey: Buffer) => Login[]; mk?: MkOptions } = {}): Profile {
  const key = randomBytes(32);
  const masterKey = randomBytes(64);
  const protect = `work/Protect/${SID}`;
  mkdirSync(join(cwd, protect), { recursive: true });
  writeFileSync(join(cwd, protect, GUID), masterKeyFile(o.prekey ?? prekeySha1(o.password ?? PASSWORD), masterKey, o.mk));
  writeFileSync(join(cwd, protect, "Preferred"), Buffer.alloc(24));
  mkdirSync(join(cwd, "work/User Data/Default"), { recursive: true });
  writeFileSync(join(cwd, "work/User Data/Local State"), localState(dpapiBlob(masterKey, key)));
  const rows = o.rows?.(key, masterKey) ?? [
    { origin: "https://mail.example.org/login?next=%2Finbox&sessionid=QUERYSECRET123#frag", username: "alice@example.org", value: v10(key, SECRETS[0]), lastUsed: T0 + 5_000_000n, timesUsed: 3 },
    { origin: "https://bank.example.com/", username: "alice", value: v10(key, SECRETS[1]) },
    { origin: "android://hash@com.example.app/", username: "älice", value: v10(key, SECRETS[2]) },
  ];
  loginData(join(cwd, "work/User Data/Default/Login Data"), rows);
  return { key, masterKey, dir: "work/User Data", loginData: "work/User Data/Default/Login Data", localState: "work/User Data/Local State", protect };
}

// --- the self-test, and the refusal outside a secret job --------------------------------------------------------------------------------------

for (const tool of ["chromium_logins", "dpapi_masterkey"]) {
  test(`${tool}: selftest alone runs anywhere and shows every known answer reproduced and every wrong key refused`, async () => {
    await withCwd(async (cwd) => {
      const before = (readdirSync(cwd, { recursive: true }) as string[]).sort();
      const { out, exit } = await call(tool, cwd, { selftest: true }, {});
      assert.equal(exit, 0);
      assert.equal(out.status, "complete");
      assert.equal(out.self_test.passed, true);
      assert.equal(out.self_test.checks.length, 8);
      assert.ok(out.self_test.checks.every((c: Answer) => c.passed === true));
      for (const name of [/FIPS 197/, /test case 14/, /test case 16/, /RFC 1320/, /master key from a password by its SHA-1/, /by its NT hash/, /DPAPI blob/, /Chromium v10/]) {
        assert.ok(out.self_test.checks.some((c: Answer) => name.test(c.name)), String(name));
      }
      assert.match(out.verification_note, /not against a master key/);
      assert.deepEqual((readdirSync(cwd, { recursive: true }) as string[]).sort(), before, "the self-test writes nothing");
    });
  });

  test(`${tool}: outside a job run as secret output every call but the self-test is refused as JSON before anything is read or made`, async () => {
    await withCwd(async (cwd) => {
      const p = profile(cwd);
      const args = tool === "chromium_logins" ? { login_data: p.loginData, key_file: secretFile(cwd, "work/k.bin", p.key) } : { masterkey: p.protect, empty_password: true };
      for (const env of [{}, { JOB_ID: "j1", OUT: join(cwd, "o1") }, { SECRET_OUTPUT: "1" }, { SECRET_OUTPUT: "true", JOB_ID: "j1", OUT: join(cwd, "o2") }] as Array<Record<string, string>>) {
        const { out, exit } = await call(tool, cwd, args, env);
        assert.notEqual(exit, 0);
        assert.equal(out.status, "failed");
        assert.match(out.error, /refused outside a job run as secret output/);
        assert.match(out.error, /Nothing was read and nothing was written/);
      }
      assert.equal(existsSync(join(cwd, "o1")), false);
      assert.equal(existsSync(join(cwd, "o2")), false);
    });
  });
}

// --- chromium_logins: the key in a file --------------------------------------------------------------------------------------------------------

test("chromium_logins with the profile key in a file decrypts every row with its tag verified; the answer holds rows and no password, the sealed file holds the values", async () => {
  await withCwd(async (cwd) => {
    const p = profile(cwd);
    for (const [form, content] of [["raw", p.key], ["hex", p.key.toString("hex") + "\n"], ["base64", "  " + p.key.toString("base64") + "\r\n"]] as Array<[string, Buffer | string]>) {
      const env = secretJob(cwd);
      const { out, raw, exit } = await call("chromium_logins", cwd, { login_data: p.loginData, key_file: secretFile(cwd, `work/key.${form}`, content) }, env);
      assert.equal(exit, 0, form);
      assert.equal(out.status, "complete", `${form}: ${out.status_basis}`);
      assert.match(out.status_basis, /every row of the logins table was read \(3\): 3 hold a password and each was decrypted with its tag or signature verified/);
      assert.deepEqual([out.every_row_read, out.rows_in_table, out.rows_read, out.passwords_present, out.decrypted, out.not_decrypted], [true, 3, 3, 3, 3, 0]);
      assert.deepEqual(out.schemes, { v10: 3 });
      assert.deepEqual(out.profile_key, { source: "key_file", obtained: true });
      assert.equal(out.self_test.passed, true);
      const [first, second, third] = out.rows as Answer[];
      assert.equal(first.origin, "https://mail.example.org/login", "the origin is shown without its query and fragment");
      assert.deepEqual(first.origin_left_out, { query_characters: "next=%2Finbox&sessionid=QUERYSECRET123".length, fragment_characters: 4 });
      assert.deepEqual([first.username, first.decrypted, first.scheme, first.password_present, first.times_used, first.never_save], ["alice@example.org", true, "v10", true, 3, false]);
      assert.deepEqual([first.created, first.created_raw], ["2024-02-19T20:06:08.131444Z", 13352846768131444]);
      assert.deepEqual([first.last_used, first.last_used_raw], ["2024-02-19T20:06:13.131444Z", 13352846773131444]);
      assert.deepEqual([second.last_used, second.last_used_raw], [null, 0], "a time of 0 is no time, and the raw value is kept");
      assert.equal(first.password_value_bytes, 3 + 12 + Buffer.byteLength(SECRETS[0]) + 16);
      assert.equal(third.origin, "android://com.example.app/");
      assert.deepEqual(third.origin_left_out, { user_info_characters: 4 });
      assert.equal(third.username, "älice");
      // The answer: no password, no key, nothing key-shaped; not even the query of an origin.
      assertNoSecret(raw, [...SECRETS, p.key, "QUERYSECRET123"], `the answer (${form})`);
      // The sealed file: the passwords, the whole URLs, mode 0600; a key that was handed in is not written again.
      const sealed = join(env.OUT, "chromium_logins-values.jsonl");
      assert.equal(statSync(sealed).mode & 0o777, 0o600);
      const values = lines(sealed);
      assert.deepEqual(values.map((v) => [v.kind, v.row, v.password, v.password_encoding]), SECRETS.map((s, i) => ["login", i + 1, s, "utf-8"]));
      assert.equal(values[0].origin_url, "https://mail.example.org/login?next=%2Finbox&sessionid=QUERYSECRET123#frag");
      assert.deepEqual(out.secret_values, { values_file: `store/jobs/${env.JOB_ID}/out/chromium_logins-values.jsonl`, written: 3, contains_secret_values: true, mode: "0600", format: "JSON Lines, one value per line with what it belongs to" });
      assert.deepEqual(readdirSync(env.OUT), ["chromium_logins-values.jsonl"], "three rows fit the inline page: no other file");
    }
  });
});

test("a wrong key is an answer, never an exception: every row says decrypted false and why, the status is partial, and no login is written", async () => {
  await withCwd(async (cwd) => {
    const p = profile(cwd);
    const wrong = Buffer.from(p.key);
    wrong[31] ^= 1;
    const env = secretJob(cwd);
    const { out, raw, exit } = await call("chromium_logins", cwd, { login_data: p.loginData, key_file: secretFile(cwd, "work/wrong.bin", wrong) }, env);
    assert.equal(exit, 0, "the reader ran: a wrong key is not a failure of the tool");
    assert.equal(out.status, "partial");
    assert.deepEqual([out.every_row_read, out.rows_read, out.decrypted, out.not_decrypted], [true, 3, 0, 3]);
    assert.match(out.status_basis, /3 of the 3 stored password\(s\) were not decrypted/);
    for (const row of out.rows as Answer[]) {
      assert.equal(row.decrypted, false);
      assert.match(row.why_not, /the tag did not verify under the profile key: a wrong key for this value, or a changed value/);
    }
    assert.deepEqual(Object.values(out.not_decrypted_by_reason), [3]);
    assert.equal(out.self_test.passed, true, "the negative counts because the reader reproduced its known answers first");
    assert.deepEqual(lines(join(env.OUT, "chromium_logins-values.jsonl")), []);
    assert.equal(out.secret_values.written, 0);
    assertNoSecret(raw, [...SECRETS, p.key, wrong], "the answer");
    // One changed byte of one stored value: that row alone is refused.
    const mixed = profile(cwd, { rows: (key) => [{ origin: "https://a.example/", username: "a", value: v10(key, SECRETS[0]) }, { origin: "https://b.example/", username: "b", value: (() => { const v = v10(key, SECRETS[1]); v[20] ^= 0x80; return v; })() }] });
    const two = await call("chromium_logins", cwd, { login_data: mixed.loginData, key_file: secretFile(cwd, "work/right.bin", mixed.key) }, secretJob(cwd));
    assert.deepEqual((two.out.rows as Answer[]).map((r) => r.decrypted), [true, false]);
    assert.equal(two.out.status, "partial");
  });
});

// --- the DPAPI route ---------------------------------------------------------------------------------------------------------------------------

test("the whole chain from a password: master key (HMAC verified), the profile key in Local State (signature verified), then every login", async () => {
  await withCwd(async (cwd) => {
    const p = profile(cwd);
    const env = secretJob(cwd);
    const password = secretFile(cwd, "work/secrets/password.txt", PASSWORD + "\n");
    const { out, raw, exit } = await call("chromium_logins", cwd, { login_data: p.loginData, local_state: p.localState, masterkey: [p.protect], password_file: password }, env);
    assert.equal(exit, 0);
    assert.equal(out.status, "complete", out.status_basis);
    assert.deepEqual([out.decrypted, out.sid, out.sid_from, out.secret_kind], [3, SID, "the name of the directory the master key file is in", "a password"]);
    assert.equal(out.profile_key.obtained, true);
    assert.equal(out.profile_key.local_state.masterkey_guid, GUID);
    assert.deepEqual([out.profile_key.local_state.hash_algorithm, out.profile_key.local_state.cipher_algorithm], ["SHA-512 (0x800E)", "AES-256 (0x6610)"]);
    const [mk] = out.masterkeys as Answer[];
    assert.deepEqual([mk.guid, mk.verified, mk.verified_with, mk.rounds, mk.supported, mk.backupkey_bytes, mk.credhist_bytes, mk.sizes_fit_file], [GUID, true, "the SHA-1 of the password", 4000, true, 144, 20, true]);
    const values = lines(join(env.OUT, "chromium_logins-values.jsonl"));
    assert.deepEqual([values[0].kind, values[0].key_hex], ["profile_key", p.key.toString("hex")], "a key this call opened is in the sealed file");
    assert.deepEqual(values.slice(1).map((v) => v.password), SECRETS);
    assertNoSecret(raw, [...SECRETS, p.key, p.masterKey, PASSWORD], "the answer");

    // The same in two jobs: dpapi_masterkey verifies and seals the key, chromium_logins takes the sealed file.
    const first = secretJob(cwd);
    const verified = await call("dpapi_masterkey", cwd, { masterkey: p.protect, password_file: password }, first);
    assert.equal(verified.out.status, "complete");
    assert.deepEqual([verified.out.verified_count, verified.out.masterkey_count], [1, 1]);
    assertNoSecret(verified.raw, [p.masterKey, PASSWORD], "the answer of dpapi_masterkey");
    const keys = join(first.OUT, "dpapi_masterkey-keys.jsonl");
    assert.equal(statSync(keys).mode & 0o777, 0o600);
    assert.deepEqual(lines(keys).map((k) => [k.kind, k.guid, k.sid, k.key_hex, k.verified_with]), [["masterkey", GUID, SID, p.masterKey.toString("hex"), "the SHA-1 of the password"]]);
    const chained = await call("chromium_logins", cwd, { login_data: p.loginData, local_state: p.localState, masterkey_keys_file: keys }, secretJob(cwd));
    assert.equal(chained.out.status, "complete", chained.out.status_basis);
    assert.equal(chained.out.decrypted, 3);
  });
});

test("a wrong password, a wrong SID and a key for another GUID are answers: verified false, the step that stopped is named, no row is decrypted", async () => {
  await withCwd(async (cwd) => {
    const p = profile(cwd);
    const wrong = secretFile(cwd, "work/wrong.txt", PASSWORD + "x");
    const right = secretFile(cwd, "work/right.txt", PASSWORD);
    const a = await call("chromium_logins", cwd, { login_data: p.loginData, local_state: p.localState, masterkey: p.protect, password_file: wrong }, secretJob(cwd));
    assert.equal(a.exit, 0);
    assert.equal(a.out.status, "partial");
    assert.deepEqual([a.out.masterkeys[0].verified, a.out.masterkeys[0].attempted, a.out.masterkeys[0].derivations_tried.length], [false, true, 3]);
    assert.equal(a.out.profile_key.obtained, false);
    assert.match(a.out.profile_key.why_not, new RegExp(`the profile key is under master key ${GUID}, and no verified key of that GUID is at hand`));
    assert.match(a.out.status_basis, /the profile key was not obtained: .*; none of the 1 master key file\(s\) verified with a password for this SID/);
    assert.ok((a.out.rows as Answer[]).every((r) => r.decrypted === false && r.why_not === "no profile key (profile_key.why_not)"));
    // The right password under another SID: the SID is part of the derivation.
    const b = await call("dpapi_masterkey", cwd, { masterkey: p.protect, sid: "S-1-5-21-1004336348-1177238915-682003330-1002", password_file: right }, secretJob(cwd));
    assert.deepEqual([b.out.status, b.out.verified_count, b.out.sid_from], ["complete", 0, "the sid argument"]);
    assert.match(b.out.status_basis, /0 of 1 master key file\(s\) verified .* not this secret for this SID/);
    assert.equal(b.out.secret_values.keys.written, 0);
    // The empty password, tried when it is said, and right when the key was made with it.
    const e = await call("dpapi_masterkey", cwd, { masterkey: p.protect, empty_password: true }, secretJob(cwd));
    assert.deepEqual([e.out.verified_count, e.out.secret_kind], [0, "an empty password"]);
    const none = profile(cwd, { password: "" });
    const f = await call("chromium_logins", cwd, { login_data: none.loginData, local_state: none.localState, masterkey: none.protect, empty_password: true }, secretJob(cwd));
    assert.equal(f.out.status, "complete", f.out.status_basis);
    assert.equal(f.out.decrypted, 3);
  });
});

test("a hash file opens the key by the derivation of its kind: the SHA-1 of the password, its NT hash, and the NT hash of a known password", async () => {
  await withCwd(async (cwd) => {
    const p = profile(cwd);
    const sha = sha1(u16(PASSWORD));
    for (const content of [sha, sha.toString("hex") + "\n"]) {
      const r = await call("dpapi_masterkey", cwd, { masterkey: join(p.protect, GUID), hash_file: secretFile(cwd, "work/sha1", content) }, secretJob(cwd));
      assert.deepEqual([r.out.verified_count, r.out.masterkeys[0].verified_with, r.out.secret_kind], [1, "the SHA-1 of the password", "the SHA-1 of the password"]);
      assertNoSecret(r.raw, [sha, p.masterKey], "the answer");
    }
    // A domain account: the pre-key is keyed by the NT hash. Any 16 bytes stand for one here; the hash of a real password is checked below.
    const nt = randomBytes(16);
    const domain = profile(cwd, { prekey: prekeyNt(nt) });
    const r = await call("chromium_logins", cwd, { login_data: domain.loginData, local_state: domain.localState, masterkey: domain.protect, hash_file: secretFile(cwd, "work/nt", nt.toString("hex")) }, secretJob(cwd));
    assert.equal(r.out.status, "complete", r.out.status_basis);
    assert.deepEqual([r.out.masterkeys[0].verified_with, r.out.secret_kind, r.out.decrypted], ["the NT hash of the password", "the NT hash of the password", 3]);
    // The NT hash of "password" is public (8846f7ea...): a key made from it opens with the password, through the reader's own MD4.
    const known = profile(cwd, { prekey: prekeyNt(Buffer.from("8846f7eaee8fb117ad06bdd830b7586c", "hex")) });
    const k = await call("dpapi_masterkey", cwd, { masterkey: known.protect, password_file: secretFile(cwd, "work/pw", "password\r\n") }, secretJob(cwd));
    assert.deepEqual([k.out.verified_count, k.out.masterkeys[0].verified_with], [1, "the NT hash of the password"]);
    assert.deepEqual(k.out.masterkeys[0].derivations_tried, ["the SHA-1 of the password", "the NT hash of the password"]);
    for (const bad of ["", "zz".repeat(20), "ab".repeat(19)]) {
      const refused = await call("dpapi_masterkey", cwd, { masterkey: p.protect, hash_file: secretFile(cwd, "work/bad", bad) }, secretJob(cwd));
      assert.equal(refused.out.status, "failed");
      assert.match(refused.out.error, /hash_file must hold a SHA-1 .* or an NT hash/);
    }
  });
});

test("the older schemes are told apart: a bare DPAPI blob is decrypted with its master key, a v20 value and an unknown one are named and not decrypted, an empty one holds no password", async () => {
  await withCwd(async (cwd) => {
    const p = profile(cwd, {
      rows: (key, masterKey) => [
        { origin: "https://old.example/", username: "legacy", value: dpapiBlob(masterKey, Buffer.from(SECRETS[0])) },
        { origin: "https://new.example/", username: "v20", value: Buffer.concat([Buffer.from("v20"), randomBytes(60)]) },
        { origin: "https://odd.example/", username: "odd", value: Buffer.from("plain-looking-bytes-that-are-no-scheme") },
        { origin: "https://never.example/", username: "", value: Buffer.alloc(0), never: 1 },
        { origin: "https://linux.example/", username: "v11", value: v10(key, SECRETS[1], "v11") },
        { origin: "https://short.example/", username: "short", value: Buffer.from("v10tooshort") },
      ],
    });
    const env = secretJob(cwd);
    const { out, raw } = await call("chromium_logins", cwd, { login_data: p.loginData, local_state: p.localState, masterkey: p.protect, password_file: secretFile(cwd, "work/pw", PASSWORD) }, env);
    assert.equal(out.status, "partial");
    const rows = out.rows as Answer[];
    assert.deepEqual(rows.map((r) => [r.scheme, r.decrypted]), [["dpapi", true], ["v20", false], ["unknown", false], ["empty", null], ["v11", true], ["v10", false]]);
    assert.match(rows[1].why_not, /a v20 value \(app-bound encryption/);
    assert.match(rows[2].why_not, /of no scheme this reader knows/);
    assert.deepEqual([rows[3].password_present, rows[3].never_save, rows[3].why_not], [false, true, undefined]);
    assert.deepEqual([out.passwords_present, out.decrypted, out.not_decrypted], [5, 2, 3]);
    assert.deepEqual(lines(join(env.OUT, "chromium_logins-values.jsonl")).filter((v) => v.kind === "login").map((v) => [v.scheme, v.password]), [["dpapi", SECRETS[0]], ["v11", SECRETS[1]]]);
    assertNoSecret(raw, [...SECRETS, p.key, p.masterKey], "the answer");
    // With the key in a file and no master key, the bare blob says which master key it needs.
    const keyOnly = await call("chromium_logins", cwd, { login_data: p.loginData, key_file: secretFile(cwd, "work/k", p.key) }, secretJob(cwd));
    assert.match(keyOnly.out.rows[0].why_not, new RegExp(`a DPAPI blob under master key ${GUID}, and no verified key of that GUID is at hand`));
  });
});

test("a master key or a blob of other algorithm ids, of a hostile round count or cut short is named and not attempted; nothing hangs", async () => {
  await withCwd(async (cwd) => {
    const p = profile(cwd);
    const pre = prekeySha1(PASSWORD);
    const dir = `work/keys/${SID}`;
    mkdirSync(join(cwd, dir), { recursive: true });
    const names = ["00000000-0000-4000-8000-000000000001", "00000000-0000-4000-8000-000000000002", "00000000-0000-4000-8000-000000000003", "00000000-0000-4000-8000-000000000004"];
    writeFileSync(join(cwd, dir, names[0]), masterKeyFile(pre, p.masterKey, { hashAlg: 0x8009, cipherAlg: 0x6603, guid: names[0] })); // what Windows 7 wrote: HMAC-SHA1 and 3DES
    writeFileSync(join(cwd, dir, names[1]), masterKeyFile(pre, p.masterKey, { rounds: 0xfffffff0, guid: names[1] }));
    writeFileSync(join(cwd, dir, names[2]), masterKeyFile(pre, p.masterKey, { guid: names[2] }).subarray(0, 200));
    writeFileSync(join(cwd, dir, names[3]), masterKeyFile(pre, p.masterKey, { guid: names[3] }));
    const started = Date.now();
    const { out, exit } = await call("dpapi_masterkey", cwd, { masterkey: dir, password_file: secretFile(cwd, "work/pw", PASSWORD) }, secretJob(cwd));
    assert.ok(Date.now() - started < 20_000, "a round count of four thousand million was not run");
    assert.equal(exit, 0);
    assert.equal(out.status, "partial");
    const mk = out.masterkeys as Answer[];
    assert.deepEqual(mk.map((m) => [m.attempted, m.verified]), [[false, false], [false, false], [false, false], [true, true]]);
    assert.match(mk[0].unsupported_why, /protected with HMAC \(SHA-1\) \(0x8009\) and 3DES \(0x6603\): this reader reads SHA-512 \(0x800E\) with AES-256 \(0x6610\) only/);
    assert.match(mk[1].unsupported_why, /declares 4294967280 PBKDF2 rounds: outside 1 to 1000000, it was not attempted/);
    assert.match(mk[2].error, /the header declares a master key block of 176 bytes in a file of 200/);
    assert.match(out.status_basis, /3 of the 4 master key file\(s\) were not tried .*1 of 4 master key file\(s\) verified/);
    // A blob of other ids.
    const blob = secretFile(cwd, "work/blob.bin", dpapiBlob(p.masterKey, Buffer.from("x"), { guid: names[3], cipherAlg: 0x6603 }));
    const b = await call("dpapi_masterkey", cwd, { masterkey: join(dir, names[3]), password_file: "work/pw", blob_file: blob }, secretJob(cwd));
    assert.equal(b.out.status, "partial");
    assert.deepEqual([b.out.blob.supported, b.out.blob.attempted, b.out.blob.decrypted], [false, false, false]);
    assert.match(b.out.blob.unsupported_why, /3DES \(0x6603\)/);
  });
});

// --- dpapi_masterkey: a blob --------------------------------------------------------------------------------------------------------------------

test("dpapi_masterkey decrypts a blob in each form it is kept in, only with its signature verified, and writes the clear text to the sealed file alone", async () => {
  await withCwd(async (cwd) => {
    const p = profile(cwd);
    const password = secretFile(cwd, "work/pw", PASSWORD);
    const clear = Buffer.from("wifi-passphrase é " + "z".repeat(40));
    const blob = dpapiBlob(p.masterKey, clear);
    const forms: Array<[string, Buffer | string, RegExp]> = [
      ["raw", blob, /^a raw DPAPI blob$/],
      ["prefixed", Buffer.concat([Buffer.from("DPAPI"), blob]), /^a raw DPAPI blob$/],
      ["base64", blob.toString("base64") + "\n", /^base64 of a DPAPI blob$/],
      ["local-state", localState(blob), /^os_crypt\.encrypted_key of a Chromium Local State$/],
    ];
    for (const [name, content, foundAs] of forms) {
      const env = secretJob(cwd);
      const { out, raw, exit } = await call("dpapi_masterkey", cwd, { masterkey: p.protect, password_file: password, blob_file: secretFile(cwd, `work/blob.${name}`, content) }, env);
      assert.equal(exit, 0, name);
      assert.equal(out.status, "complete", `${name}: ${out.status_basis}`);
      assert.match(out.blob.found_as, foundAs);
      assert.deepEqual([out.blob.decrypted, out.blob.attempted, out.blob.masterkey_guid, out.blob.plaintext_bytes, out.blob.masterkey_available], [true, true, GUID, clear.length, true]);
      assert.deepEqual(lines(join(env.OUT, "dpapi_masterkey-plaintext.jsonl")).map((r) => [r.kind, r.hex, r.utf8, r.bytes]), [["blob_plaintext", clear.toString("hex"), clear.toString("utf8"), clear.length]]);
      assertNoSecret(raw, [clear, p.masterKey, PASSWORD], `the answer (${name})`);
      assert.equal(out.contains_secret_values, true);
    }
    // With the keys of an earlier job, and with an entropy.
    const first = secretJob(cwd);
    await call("dpapi_masterkey", cwd, { masterkey: p.protect, password_file: password }, first);
    const keys = join(first.OUT, "dpapi_masterkey-keys.jsonl");
    const entropy = randomBytes(20);
    const salted = secretFile(cwd, "work/salted.bin", dpapiBlob(p.masterKey, clear, { entropy }));
    const without = await call("dpapi_masterkey", cwd, { keys_file: keys, blob_file: salted }, secretJob(cwd));
    assert.deepEqual([without.out.status, without.out.blob.attempted, without.out.blob.decrypted], ["complete", true, false]);
    assert.match(without.out.blob.why_not, /signature did not verify under the master key of its GUID \(a blob made with an optional entropy needs entropy_file\)/);
    assert.equal(without.out.secret_values.plaintext.written, 0);
    const withIt = await call("dpapi_masterkey", cwd, { keys_file: keys, blob_file: salted, entropy_file: secretFile(cwd, "work/entropy.bin", entropy) }, secretJob(cwd));
    assert.equal(withIt.out.blob.decrypted, true);
    // A blob that names a master key that was not verified; a changed blob; a file that holds none.
    const other = await call("dpapi_masterkey", cwd, { keys_file: keys, blob_file: secretFile(cwd, "work/other.bin", dpapiBlob(p.masterKey, clear, { guid: "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee" })) }, secretJob(cwd));
    assert.equal(other.out.status, "partial");
    assert.match(other.out.blob.why_not, /names master key aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee, and no verified key of that GUID is at hand/);
    const changed = Buffer.from(blob);
    changed[changed.length - 70] ^= 1;
    const tampered = await call("dpapi_masterkey", cwd, { keys_file: keys, blob_file: secretFile(cwd, "work/changed.bin", changed) }, secretJob(cwd));
    assert.deepEqual([tampered.out.blob.attempted, tampered.out.blob.decrypted], [true, false]);
    const cut = await call("dpapi_masterkey", cwd, { keys_file: keys, blob_file: secretFile(cwd, "work/cut.bin", blob.subarray(0, 120)) }, secretJob(cwd));
    assert.equal(cut.out.status, "partial");
    assert.match(cut.out.blob.error, /a length in the blob passes its end/);
    const nothing = await call("dpapi_masterkey", cwd, { keys_file: keys, blob_file: secretFile(cwd, "work/none.bin", "just some text") }, secretJob(cwd));
    assert.equal(nothing.out.status, "failed");
    assert.match(nothing.out.error, /blob_file holds no DPAPI blob/);
  });
});

// --- what the database can be -----------------------------------------------------------------------------------------------------------------------

test("a log beside the database, a file that is no database, a database without the table, and a view named logins are each said; none runs evidence SQL", async () => {
  await withCwd(async (cwd) => {
    const p = profile(cwd);
    const key = secretFile(cwd, "work/k", p.key);
    writeFileSync(join(cwd, p.loginData + "-wal"), randomBytes(4152));
    writeFileSync(join(cwd, p.loginData + "-journal"), Buffer.alloc(0));
    const beside = await call("chromium_logins", cwd, { login_data: p.loginData, key_file: key }, secretJob(cwd));
    assert.equal(beside.out.status, "partial", "rows in a log are not read");
    assert.equal(beside.out.decrypted, 3);
    assert.deepEqual(beside.out.sidecars_beside, [{ file: p.loginData + "-wal", bytes: 4152 }]);
    assert.deepEqual(beside.out.sidecars_looked_for, [p.loginData + "-wal", p.loginData + "-journal"]);
    assert.match(beside.out.status_basis, /1 file\(s\) SQLite keeps beside the database are there and not empty/);
    assert.ok(readFileSync(join(cwd, p.loginData + "-wal")).length === 4152, "the log is not touched");

    const text = secretFile(cwd, "work/notdb", "SQLite format 2 is not a thing\n".repeat(50));
    const env = secretJob(cwd);
    const notDb = await call("chromium_logins", cwd, { login_data: text, key_file: key }, env);
    assert.equal(notDb.out.status, "failed");
    assert.match(notDb.out.error, /login_data is not an SQLite database/);
    assert.deepEqual(readdirSync(env.OUT), [], "nothing is made for a file that is not read");

    loginData(join(cwd, "work/history.db"), [], { table: "urls" });
    const noTable = await call("chromium_logins", cwd, { login_data: "work/history.db", key_file: key }, secretJob(cwd));
    assert.equal(noTable.out.status, "failed");
    assert.match(noTable.out.error, /no table named logins/);

    // A view named logins over a table of the evidence's own, with a trigger: the reader takes a table only.
    loginData(join(cwd, "work/view.db"), [{ origin: "https://a.example/", username: "a", value: v10(p.key, SECRETS[0]) }], {
      table: "real_logins",
      extra: "c.execute('CREATE VIEW logins AS SELECT * FROM real_logins')",
    });
    const view = await call("chromium_logins", cwd, { login_data: "work/view.db", key_file: key }, secretJob(cwd));
    assert.equal(view.out.status, "failed");
    assert.match(view.out.error, /no table named logins/);

    // A table whose row count is large: the page is `limit` rows, every row is read and the whole list is a file with no password in it.
    const many = profile(cwd, { rows: (k) => Array.from({ length: 60 }, (_, i) => ({ origin: `https://site${i}.example/`, username: `user${i}`, value: v10(k, `${SECRETS[1]}-${i}`) })) });
    const envMany = secretJob(cwd);
    const paged = await call("chromium_logins", cwd, { login_data: many.loginData, key_file: secretFile(cwd, "work/k2", many.key), limit: 10 }, envMany);
    assert.equal(paged.out.status, "complete");
    assert.deepEqual([paged.out.rows.length, paged.out.row_count, paged.out.decrypted, paged.out.truncated], [10, 60, 60, true]);
    const listed = readFileSync(join(envMany.OUT, "tool-output", paged.out.all_results.split("/").pop()), "utf8");
    assert.equal(listed.trim().split("\n").length, 60);
    assertNoSecret(listed + paged.raw, [SECRETS[1], many.key], "the list of rows");
    assert.equal(lines(join(envMany.OUT, "chromium_logins-values.jsonl")).length, 60);
  });
});

// --- the contract -----------------------------------------------------------------------------------------------------------------------------------

test("a secret given as a value, two key sources at once, a values file already there, and a secret file that is a link are refused by name", async () => {
  await withCwd(async (cwd) => {
    const p = profile(cwd);
    const key = secretFile(cwd, "work/k", p.key);
    const pw = secretFile(cwd, "work/pw", PASSWORD);
    const cases: Array<[string, Record<string, unknown>, RegExp]> = [
      ["chromium_logins", { login_data: p.loginData, key_hex: p.key.toString("hex") }, /unknown argument\(s\): key_hex/],
      ["chromium_logins", { login_data: p.loginData, password: PASSWORD }, /unknown argument\(s\): password/],
      ["chromium_logins", { login_data: p.loginData, key_file: key, masterkey: p.protect, password_file: pw }, /give the profile key \(key_file\) or the DPAPI material that opens it .* not both/],
      ["chromium_logins", { login_data: p.loginData, local_state: p.localState, password_file: pw }, /a password, a hash or a SID was given without masterkey/],
      ["chromium_logins", { login_data: p.loginData, local_state: p.localState, masterkey: p.protect, password_file: pw, empty_password: true }, /name exactly one of password_file .* 2 were given/],
      ["chromium_logins", { login_data: p.loginData, local_state: p.localState, masterkey: p.protect }, /name exactly one of password_file .* none was given/],
      ["chromium_logins", { key_file: key }, /login_data is required/],
      ["dpapi_masterkey", { masterkey: p.protect, password_file: pw, sid: "not-a-sid" }, /sid must be a security identifier/],
      ["dpapi_masterkey", { masterkey: join(p.protect, "Preferred") + "x", password_file: pw, sid: SID }, /0 of 1|could not be opened/],
      ["dpapi_masterkey", { password_file: pw }, /name masterkey .* or keys_file/],
      ["dpapi_masterkey", { keys_file: key }, /keys_file is for decrypting a blob: name blob_file with it/],
      ["dpapi_masterkey", { masterkey: "work/User Data", password_file: pw, sid: SID }, /holds no file named by a GUID/],
    ];
    for (const [tool, args, expected] of cases) {
      const { out, raw } = await call(tool, cwd, args, secretJob(cwd));
      assert.match(String(out.error ?? out.status_basis) + JSON.stringify(out.masterkeys ?? ""), expected, `${tool} ${JSON.stringify(args).slice(0, 80)}`);
      assertNoSecret(raw, [p.key, PASSWORD, p.masterKey], "a refusal");
    }
    // The values file is never replaced: a second call into the same $OUT is refused by name, and the first file is as it was.
    const env = secretJob(cwd);
    await call("chromium_logins", cwd, { login_data: p.loginData, key_file: key }, env);
    const before = readFileSync(join(env.OUT, "chromium_logins-values.jsonl"));
    const again = await call("chromium_logins", cwd, { login_data: p.loginData, key_file: key }, env);
    assert.equal(again.out.status, "failed");
    assert.match(again.out.error, /the values file store\/jobs\/j\d+\/out\/chromium_logins-values\.jsonl is already there: nothing is replaced/);
    assert.ok(readFileSync(join(env.OUT, "chromium_logins-values.jsonl")).equals(before));
    // A link is not followed to a secret.
    py("import os, sys; os.symlink(sys.argv[1], sys.argv[2])", join(cwd, key), join(cwd, "work", "k.link"));
    const link = await call("chromium_logins", cwd, { login_data: p.loginData, key_file: "work/k.link" }, secretJob(cwd));
    assert.match(link.out.error, /key_file is a symbolic link/);
    const big = await call("chromium_logins", cwd, { login_data: p.loginData, key_file: secretFile(cwd, "work/big", randomBytes(5000)) }, secretJob(cwd));
    assert.match(big.out.error, /key_file is 5000 bytes, over the 4096 this tool reads for it/);
    const odd = await call("chromium_logins", cwd, { login_data: p.loginData, key_file: secretFile(cwd, "work/odd", "not a key") }, secretJob(cwd));
    assert.match(odd.out.error, /key_file must hold 32 bytes: raw, as 64 hexadecimal digits, or as base64/);
  });
});

for (const tool of ["chromium_logins", "dpapi_masterkey"]) {
  test(`${tool}: arguments of the wrong type get a JSON answer each, in a secret job, and a stop signal gets one JSON document`, async () => {
    await withCwd(async (cwd) => {
      const p = profile(cwd);
      const base = tool === "chromium_logins" ? { login_data: p.loginData, key_file: secretFile(cwd, "work/k", p.key) } : { masterkey: p.protect, password_file: secretFile(cwd, "work/pw", PASSWORD) };
      const seed = 20261113;
      // Each run gets a $OUT of its own (the values file is made exclusively), so the sets are run in turn through a wrapper environment per set.
      const sets = typeConfused(manifestOf(tool), 120, seed, base);
      for (let i = 0; i < sets.length; i += 6) {
        await Promise.all(sets.slice(i, i + 6).map(async (set, j) => {
          const run = await runTool(tool, cwd, set, secretJob(cwd));
          assertJsonAnswer(run, `seed ${seed}, set ${i + j}: ${JSON.stringify(set)}`.slice(0, 300));
        }));
      }
      await fuzzTool(tool, [[], 5, "x", null], seed, { cwd, env: secretJob(cwd) });
      for (const signal of ["SIGTERM", "SIGINT", "SIGHUP"] as StopSignal[]) {
        const early = assertStopped(await stopAt(tool, base, secretJob(cwd), "early", signal, { cwd }), signal);
        assert.equal(early.answered, true);
      }
    });
  });
}

// --- the shared text, the manifests, and a second implementation of the primitives -------------------------------------------------------------

test("the two tools carry the WINCRYPT and CREDENTIAL IO blocks byte for byte, start no program, and take no module outside the standard library", () => {
  const a = readFileSync(join(WIN, "chromium_logins", "run.py"), "utf8");
  const b = readFileSync(join(WIN, "dpapi_masterkey", "run.py"), "utf8");
  for (const [begin, end] of [["# BEGIN WINCRYPT", "# END WINCRYPT"], ["# BEGIN CREDENTIAL IO", "# END CREDENTIAL IO"]]) {
    const cut = (s: string): string => s.slice(s.indexOf(begin), s.indexOf(end));
    assert.ok(cut(a).length > 2000, `${begin} is there`);
    assert.equal(cut(a), cut(b), `${begin} is the same text in both tools`);
  }
  for (const text of [a, b]) {
    assert.doesNotMatch(text, /^\s*(?:import|from)\s+(?:cryptography|Crypto|Cryptodome|impacket|dpapick3|subprocess|socket)\b/m);
    assert.doesNotMatch(text, /os\.system|Popen/);
  }
});

test("the manifests declare every job secret, carry the three rules, say what is and is not verified, and name the script's digest", () => {
  for (const tool of ["chromium_logins", "dpapi_masterkey"]) {
    const manifest = JSON.parse(readFileSync(join(WIN, tool, "manifest.json"), "utf8"));
    assert.equal(manifest.secret_output, "required");
    assert.equal(manifest.sha256, createHash("sha256").update(readFileSync(join(WIN, tool, "run.py"))).digest("hex"));
    assert.match(manifest.description, /^SENSITIVE:/);
    assert.match(manifest.description, /a v10 secret needs the profile key/);
    assert.match(manifest.description, /look where the user keeps secrets \(notes, exports, password files, backups\) before attacking DPAPI/);
    assert.match(manifest.description, /a negative from your own crypto counts only after the tool's self-test passed/);
    assert.match(manifest.description, /no real master key was opened with its known password/);
    assert.match(manifest.description, /ONLY SHA-512 \(0x800E\) with AES-256 \(0x6610\) is read/);
    assert.deepEqual(manifest.requires, []);
    for (const name of ["password_file", "hash_file", "empty_password", "masterkey", "sid", "selftest"]) assert.ok(name in manifest.params, `${tool} takes ${name}`);
    assert.equal(manifest.params.empty_password.type, "boolean");
    for (const name of Object.keys(manifest.params)) assert.doesNotMatch(name, /^(password|key|hash|key_hex|secret)$/, "no parameter takes a secret as a value");
  }
});

test("the readers' own AES-CBC, AES-GCM and MD4 give what the cryptography module and OpenSSL give, on random inputs", { skip: pythonCanImport("cryptography") ? false : "the cryptography module is not installed on this host" }, () => {
  const out = py(
    [
      "import importlib.util, os, sys, json, hashlib",
      "from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes",
      "from cryptography.hazmat.primitives.ciphers.aead import AESGCM",
      "spec = importlib.util.spec_from_file_location('tool', sys.argv[1]); w = importlib.util.module_from_spec(spec); spec.loader.exec_module(w)",
      "bad = 0",
      "for n in range(200):",
      "    key, iv, data = os.urandom(32), os.urandom(16), os.urandom(16 * (1 + n % 9))",
      "    e = Cipher(algorithms.AES(key), modes.CBC(iv)).encryptor(); ct = e.update(data) + e.finalize()",
      "    bad += w.aes_cbc_decrypt(key, iv, ct) != data",
      "    nonce, clear, aad = os.urandom(12), os.urandom(n % 131), os.urandom(n % 7)",
      "    sealed = AESGCM(key).encrypt(nonce, clear, aad or None)",
      "    bad += w.aes_gcm_decrypt(key, nonce, sealed[:-16], sealed[-16:], aad) != clear",
      "    bad += w.aes_gcm_decrypt(key, nonce, sealed[:-16], sealed[-16:], aad + b'x') is not None",
      "    bad += w.chromium_decrypt(b'v10' + nonce + AESGCM(key).encrypt(nonce, clear, None), key) != clear",
      "rfc = {b'': '31d6cfe0d16ae931b73c59d7e0c089c0', b'a': 'bde52cb31de33e46245e05fbdbd6fb24', b'message digest': 'd9130a8164549fe818874806e1c7014b',",
      "       b'12345678901234567890123456789012345678901234567890123456789012345678901234567890': 'e33b4ddc9c38f2199c3e7b164fcc0536'}",
      "bad += sum(w.md4(k).hex() != v for k, v in rfc.items())",
      "print(json.dumps({'bad': bad, 'checks': [c['passed'] for c in w.wincrypt_selftest()]}))",
    ].join("\n"),
    join(WIN, "dpapi_masterkey", "run.py"),
  );
  const got = JSON.parse(out) as { bad: number; checks: boolean[] };
  assert.equal(got.bad, 0);
  assert.deepEqual(got.checks, Array(8).fill(true));
});
