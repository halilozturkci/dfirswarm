/**
 * keychain_open opens a macOS login or System keychain with the password a case supplies, and writes every item to a sealed file. Held here with a
 * stand-in reader (a Python module named chainbreaker with the reader's own API: `Chainbreaker(path, unlock_password=, unlock_file=)`, `.locked`, the
 * `dump_*` methods, records that carry `.password`, `.locked` and the reader's attribute names) behind a launcher in the form images/install.py writes, so
 * that every outcome can be driven, and with keychain files that are a signature and a description of what the stand-in should do:
 *   - the refusal outside a job run as secret output makes nothing, and so does every refusal of an input (a link, a mode other than 0600, a value in the
 *     arguments, a FIFO);
 *   - opened, partial, wrong secret, SystemKey, unsupported format (the Local Items store among them), damaged and truncated, the reader missing, an empty
 *     password file and a reader that cannot be imported each get their own outcome, and only `opened` is complete;
 *   - the clock ends a reader that does not end, and what it started; SIGTERM ends with one answer, exit 143, the whole lines kept, nothing left running;
 *   - a random password canary is not in the argument list or environment of the tool or of any process alive during the run, not in the answer, stderr,
 *     any file but the one sealed items file, and an item's value is in the items file only;
 *   - the items file is 0600, a rerun never replaces it, and the answer's size, lines and sha256 are the file's.
 * One real run on a keychain made with `security create-keychain` runs on macOS when the reader is installed, and is skipped elsewhere.
 */
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { createHash, randomBytes } from "node:crypto";
import { chmod, mkdir, readFile, readdir, stat, symlink, truncate, writeFile } from "node:fs/promises";
import { existsSync, readFileSync, readdirSync } from "node:fs";
import { join } from "node:path";
import { test } from "node:test";
import { withCwd } from "./tool-library-harness.ts";
import { parseSecretDeclaration } from "../scripts/output-hygiene.ts";
import { MAC, PYTHON, body, filesUnder, plainJob, runAndSignal, secretJob, tool } from "./macos-pack-harness.ts";
import type { Json, Run } from "./macos-pack-harness.ts";
import { NO_ADOPTION } from "./host-gates.ts";

const KEYCHAIN = join(MAC, "keychain_open", "run.py");
const sha = (data: Buffer | string): string => createHash("sha256").update(data).digest("hex");

// The stand-in reader. It follows the reader's API (module chainbreaker, class Chainbreaker, records with the reader's attribute names) and takes its
// behaviour from the JSON that follows the 'kych' signature in the keychain file.
const STANDIN = String.raw`
import json, os, signal, sys, time
open(os.path.join(os.path.dirname(os.path.abspath(__file__)), 'imported'), 'a').write('1')
LOCKED = '[Invalid Password / Keychain Locked]'


class Rec(object):
    def __init__(self, kind, spec):
        self.Created, self.LastModified = '20200101000000Z', '20200102000000Z'
        self.Account, self.Service, self.PrintName = spec.get('account'), spec.get('service'), spec.get('label')
        self.SSGP, self.DBKey, self.IV, self.Key = object(), b'k', b'iv', b'key'
        self.locked = spec.get('password') is None
        self._password = spec.get('password')
        self.password_b64_encoded = False
        self.kind = kind
        if kind == 'private_key':
            self.PrivateKey = spec.get('key') and spec['key'].encode()
            self.KeyClass = 'private'
        if kind == 'x509_certificate':
            self.Certificate = b'cert-bytes'
            self.PrintName = spec.get('label')

    @property
    def password(self):
        return LOCKED if self.locked else self._password


class Chainbreaker(object):
    KEYCHAIN_LOCKED_SIGNATURE = LOCKED

    def __init__(self, filepath, unlock_password=None, unlock_key=None, unlock_file=None):
        data = open(filepath, 'rb').read()
        if data[:4] != b'kych':
            raise ValueError('signature')
        self.spec = json.loads(data[4:].decode('utf-8') or '{}')
        if self.spec.get('raise'):
            raise IndexError('truncated')
        if self.spec.get('trace'):
            open(self.spec['trace'], 'a').write(json.dumps({'argv': sys.argv[:1], 'password_given': unlock_password is not None, 'key_file_given': bool(unlock_file)}) + '\n')
        ok = False
        if unlock_password is not None and unlock_password == self.spec.get('password'):
            ok = True
        if unlock_file and open(unlock_file, 'rb').read() == self.spec.get('system_key', '').encode():
            ok = True
        self.locked = not ok

    def _recs(self, name, kind):
        out = []
        for spec in self.spec.get('items', {}).get(name, []):
            out.append(Rec(kind, spec))
        if self.spec.get('mode') == 'rows_then_hang' and name == 'dump_generic_passwords':
            self._hang_after = True
        return out

    def _maybe_hang(self):
        mode = self.spec.get('mode')
        if mode in ('hang', 'rows_then_hang'):
            if self.spec.get('child'):
                import subprocess
                p = subprocess.Popen(['sleep', '300'])
                open(self.spec['child'], 'w').write(str(p.pid))
            if self.spec.get('ready'):
                open(self.spec['ready'], 'w').write('1')
            time.sleep(300)

    def dump_generic_passwords(self):
        if self.spec.get('mode') == 'hang':
            self._maybe_hang()
        return self._recs('dump_generic_passwords', 'generic_password')

    def dump_internet_passwords(self):
        if self.spec.get('mode') == 'rows_then_hang':
            self._maybe_hang()
        if self.spec.get('mode') == 'class_error':
            raise KeyError('table')
        return self._recs('dump_internet_passwords', 'internet_password')

    def dump_appleshare_passwords(self):
        return []

    def dump_x509_certificates(self):
        return self._recs('dump_x509_certificates', 'x509_certificate')

    def dump_public_keys(self):
        return []

    def dump_private_keys(self):
        return self._recs('dump_private_keys', 'private_key')
`;

type Reader = { path: string; dir: string };

/** A stand-in reader behind a launcher in the form images/install.py writes. Returns the PATH that finds it. */
async function standin(cwd: string, source: string = STANDIN): Promise<Reader> {
  const dir = join(cwd, "reader");
  const mod = join(dir, "mod");
  await mkdir(join(mod, "chainbreaker"), { recursive: true });
  await mkdir(join(dir, "bin"), { recursive: true });
  await writeFile(join(mod, "chainbreaker", "__init__.py"), source, "utf8");
  await writeFile(join(mod, "chainbreaker", "__main__.py"), "", "utf8");
  const launcher = join(dir, "bin", "chainbreaker");
  await writeFile(launcher, `#!/bin/sh\nexport PYTHONPATH="${mod}\${PYTHONPATH:+:$PYTHONPATH}"\nexec "${PYTHON}" "${join(mod, "chainbreaker", "__main__.py")}" "$@"\n`, "utf8");
  await chmod(launcher, 0o755);
  return { dir, path: `${join(dir, "bin")}:${process.env.PATH}` };
}

async function keychain(cwd: string, name: string, spec: Record<string, unknown> | null, raw?: Buffer): Promise<string> {
  const file = join(cwd, "work", name);
  await mkdir(join(cwd, "work"), { recursive: true });
  await writeFile(file, raw ?? Buffer.concat([Buffer.from("kych"), Buffer.from(JSON.stringify(spec ?? {}).padEnd(256))]));
  return file;
}

async function secretFile(cwd: string, name: string, text: string, mode = 0o600): Promise<string> {
  const file = join(cwd, "work", name);
  await mkdir(join(cwd, "work"), { recursive: true });
  await writeFile(file, text);
  await chmod(file, mode);
  return file;
}

const run = (cwd: string, reader: Reader | null, args: unknown, env: Record<string, string> = {}): Promise<Run> =>
  secretJob(KEYCHAIN, cwd, args, { ...(reader ? { PATH: reader.path } : {}), ...env });

function json(out: Run): Json {
  return body(out);
}

const ITEMS = {
  dump_generic_passwords: [{ account: "acct-one", service: "svc-one", label: "label-one", password: "value-one" }, { account: "acct-two", service: "svc-two", label: "label-two", password: "value-two" }],
  dump_internet_passwords: [{ account: "acct-net", service: "net.example", label: "net", password: "value-net" }],
  dump_x509_certificates: [{ label: "cert-label" }],
  dump_private_keys: [{ label: "key-label", key: "private-key-bytes" }],
};

async function itemsFile(cwd: string, name = "keychain-items.jsonl"): Promise<{ text: string; rows: Json[]; mode: number }> {
  const file = join(cwd, "out", name);
  const text = await readFile(file, "utf8");
  return { text, rows: text.split("\n").filter((l) => l).map((l) => JSON.parse(l) as Json), mode: (await stat(file)).mode & 0o777 };
}

async function outFiles(cwd: string): Promise<string[]> {
  return (await readdir(join(cwd, "out")).catch(() => [])).sort();
}

// ---- the manifest ---------------------------------------------------------------------------------------------------------------------------

test("the manifest declares secret_output required in a form the harness accepts, and says what the answer holds and withholds", async () => {
  const m = JSON.parse(await readFile(join(MAC, "keychain_open", "manifest.json"), "utf8")) as Json;
  assert.equal(m.secret_output, "required");
  const parsed = parseSecretDeclaration(m.secret_output, m.params, true);
  assert.equal(parsed.ok, true, JSON.stringify(parsed));
  assert.match(m.description, /SENSITIVE/);
  assert.deepEqual(Object.keys(m.params).sort(), ["max_seconds", "password_file", "path", "system_key"]);
  assert.ok(m.timeout_seconds > 90, "the tool's own limit (90) is below the manifest's timeout");
  assert.deepEqual(m.requires, ["chainbreaker"]);
  for (const outcome of ["opened", "partial", "wrong_secret", "unsupported_format", "damaged", "unavailable", "timed_out", "interrupted"]) assert.match(m.description, new RegExp(outcome), outcome);
});

// ---- the refusals make nothing --------------------------------------------------------------------------------------------------------------

test("a call that is not a secret_output job is refused as JSON before anything is read or made", async () => {
  await withCwd(async (cwd) => {
    const reader = await standin(cwd);
    const kc = await keychain(cwd, "login.keychain-db", { password: "pw", items: ITEMS });
    const pw = await secretFile(cwd, "pw.txt", "pw\n");
    const out = await plainJob(KEYCHAIN, cwd, { path: kc, password_file: pw }, { PATH: reader.path });
    assert.equal(out.code, 1);
    const a = json(out);
    assert.equal(a.status, "failed");
    assert.match(a.error, /secret output/);
    assert.deepEqual(await outFiles(cwd), [], "nothing was made");
    const bare = await tool(KEYCHAIN, cwd, { path: kc, password_file: pw }, { PATH: reader.path });
    assert.equal(bare.code, 1);
    assert.match(json(bare).error, /secret output/);
    const noStdin = await runAndSignal(KEYCHAIN, cwd, { path: kc, password_file: pw }, "SIGTERM", async () => false, { PATH: reader.path });
    assert.equal(json(noStdin).status, "failed");
  });
});

test("every refused input is JSON, names no path, and makes nothing", async () => {
  await withCwd(async (cwd) => {
    const reader = await standin(cwd);
    const kc = await keychain(cwd, "login.keychain-db", { password: "pw", items: ITEMS });
    const pw = await secretFile(cwd, "pw.txt", "pw\n");
    const loose = await secretFile(cwd, "loose.txt", "pw\n", 0o644);
    const empty = await secretFile(cwd, "empty.txt", "");
    const big = await secretFile(cwd, "big.txt", "x".repeat(5000));
    const link = join(cwd, "work", "link.txt");
    await symlink(pw, link);
    const klink = join(cwd, "work", "kc-link");
    await symlink(kc, klink);
    const huge = join(cwd, "work", "huge.keychain-db");
    await writeFile(huge, "kych");
    await truncate(huge, 300 << 20);
    const fifo = join(cwd, "work", "fifo");
    assert.equal(spawnSync("mkfifo", [fifo]).status, 0);
    const cases: [string, unknown, RegExp][] = [
      ["no path", { password_file: pw }, /path is required/],
      ["no secret", { path: kc }, /password_file or system_key is required/],
      ["a literal password", { path: kc, password: "hunter2-canary" }, /does not take/],
      ["a literal in password_file", { path: kc, password_file: 7 }, /file path/],
      ["a loose mode", { path: kc, password_file: loose }, /0600/],
      ["an empty password file", { path: kc, password_file: empty }, /empty/],
      ["an oversized password file", { path: kc, password_file: big }, /larger than/],
      ["a linked password file", { path: kc, password_file: link }, /symbolic link/],
      ["a linked keychain", { path: klink, password_file: pw }, /symbolic link/],
      ["a FIFO keychain", { path: fifo, password_file: pw }, /not a regular file/],
      ["a FIFO password file", { path: kc, password_file: fifo }, /not a regular file/],
      ["a missing keychain", { path: join(cwd, "work", "nope"), password_file: pw }, /could not be read/],
      ["a keychain too large to read whole", { path: huge, password_file: pw }, /larger than/],
      ["a bad clock", { path: kc, password_file: pw, max_seconds: 500 }, /max_seconds/],
      ["a zero clock", { path: kc, password_file: pw, max_seconds: 0 }, /max_seconds/],
    ];
    for (const [name, args, pattern] of cases) {
      const out = await run(cwd, reader, args);
      assert.equal(out.code, 1, name);
      const a = json(out);
      assert.equal(a.status, "failed", name);
      assert.match(a.error, pattern, name);
      assert.ok(!out.stdout.includes(cwd), `${name}: a path was printed`);
      assert.ok(!out.stdout.includes("hunter2-canary"), name);
    }
    assert.deepEqual(await outFiles(cwd), [], "no refusal made a file");
  });
});

// ---- the outcomes ---------------------------------------------------------------------------------------------------------------------------

test("an unlocked keychain is opened: complete, every item in a 0600 file, counts and the file's own size, lines and sha256 in the answer", { skip: NO_ADOPTION }, async () => {
  await withCwd(async (cwd) => {
    const reader = await standin(cwd);
    const kc = await keychain(cwd, "login.keychain-db", { password: "correct horse", items: ITEMS });
    const pw = await secretFile(cwd, "pw.txt", "correct horse\n");
    const out = await run(cwd, reader, { path: kc, password_file: pw });
    assert.equal(out.code, 0, out.stderr + out.stdout);
    const a = json(out);
    assert.equal(a.status, "complete", a.status_basis);
    assert.equal(a.outcome, "opened");
    assert.equal(a.keychain.format, "kych");
    assert.equal(a.records.records, 5);
    assert.equal(a.records.decrypted, 4);
    assert.equal(a.records.not_decrypted, 0);
    assert.equal(a.records.by_class.generic_password.records, 2);
    assert.equal(a.records.by_class.internet_password.records, 1);
    assert.equal(a.records.by_class.x509_certificate.records, 1);
    assert.equal(a.records.by_class.private_key.records, 1);
    assert.equal(a.records.by_class.generic_password.value_bytes, "value-one".length + "value-two".length);
    const f = await itemsFile(cwd);
    assert.equal(f.mode, 0o600);
    assert.equal(f.rows.length, 5);
    const first = f.rows[0];
    assert.equal(first.class, "generic_password");
    assert.equal(first.fields.Account, "acct-one");
    assert.equal(first.fields.Service, "svc-one");
    assert.equal(first.value, "value-one");
    assert.equal(first.value_encoding, "utf-8");
    assert.equal(first.fields.SSGP, undefined, "the reader's internal key material is not a field");
    assert.equal(first.fields.DBKey, undefined);
    assert.equal(f.rows.find((r) => r.class === "private_key")!.value_encoding, "base64");
    assert.equal(Buffer.from(f.rows.find((r) => r.class === "private_key")!.value, "base64").toString(), "private-key-bytes");
    assert.equal(a.items_file.bytes, Buffer.byteLength(f.text));
    assert.equal(a.items_file.lines, 5);
    assert.equal(a.items_file.sha256, sha(f.text));
    assert.equal(a.items_file.mode, "0600");
    assert.equal(a.items_file.file, "store/jobs/j-1/out/keychain-items.jsonl");
    for (const word of ["acct-one", "svc-one", "label-one", "value-one", "value-net", "private-key-bytes", "correct horse"]) assert.ok(!out.stdout.includes(word), `the answer holds ${word}`);
    assert.deepEqual(await outFiles(cwd), ["keychain-items.jsonl"], "no temporary is left");
  });
});

test("a SystemKey file opens System.keychain, with or without a password file", { skip: NO_ADOPTION }, async () => {
  await withCwd(async (cwd) => {
    const reader = await standin(cwd);
    const kc = await keychain(cwd, "System.keychain", { system_key: "system-key-bytes", items: { dump_generic_passwords: [{ account: "a", service: "s", password: "v" }] } });
    const key = await secretFile(cwd, "SystemKey", "system-key-bytes");
    const a = json(await run(cwd, reader, { path: kc, system_key: key }));
    assert.equal(a.status, "complete", a.status_basis);
    assert.deepEqual(a.secrets_given, { password: false, system_key: true });
    const wrong = await secretFile(cwd, "other", "not-the-key");
    const b = json(await run(cwd, reader, { path: kc, system_key: wrong }));
    assert.equal(b.outcome, "wrong_secret");
  });
});

test("a wrong password is wrong_secret, failed, and makes no items file", async () => {
  await withCwd(async (cwd) => {
    const reader = await standin(cwd);
    const kc = await keychain(cwd, "login.keychain-db", { password: "right", items: ITEMS });
    const pw = await secretFile(cwd, "pw.txt", "wrong\n");
    const out = await run(cwd, reader, { path: kc, password_file: pw });
    assert.equal(out.code, 1);
    const a = json(out);
    assert.equal(a.status, "failed");
    assert.equal(a.outcome, "wrong_secret");
    assert.match(a.reason, /not proof about the password/);
    assert.equal(a.items_file, undefined);
    assert.equal(a.records, undefined);
    assert.deepEqual(await outFiles(cwd), []);
  });
});

test("records that cannot be decrypted, or a class the reader fails on, make the answer partial, with null values in the file", async () => {
  await withCwd(async (cwd) => {
    const reader = await standin(cwd);
    const kc = await keychain(cwd, "login.keychain-db", {
      password: "pw",
      items: { dump_generic_passwords: [{ account: "a", service: "s", password: "v" }, { account: "b", service: "t", password: null }] },
    });
    const pw = await secretFile(cwd, "pw.txt", "pw");
    const a = json(await run(cwd, reader, { path: kc, password_file: pw }));
    assert.equal(a.status, "partial");
    assert.equal(a.outcome, "partial");
    assert.equal(a.records.not_decrypted, 1);
    assert.equal(a.records.decrypted, 1);
    const f = await itemsFile(cwd);
    assert.equal(f.rows.length, 2);
    assert.equal(f.rows[1].value, null);
    const kc2 = await keychain(cwd, "second.keychain-db", { password: "pw", mode: "class_error", items: ITEMS });
    const b = json(await run(cwd, reader, { path: kc2, password_file: pw }));
    assert.equal(b.status, "partial");
    assert.match(b.reason, /internet_password/);
    assert.equal(b.records.by_class.internet_password.error, "KeyError");
  });
});

test("the Local Items store, any other file, a truncated file and an unparseable one each get their own outcome, never complete, and the reader is not asked", async () => {
  await withCwd(async (cwd) => {
    const imported = join(cwd, "reader", "mod", "chainbreaker", "imported");
    const reader = await standin(cwd);
    const pw = await secretFile(cwd, "pw.txt", "pw");
    const sqlite = await keychain(cwd, "keychain-2.db", null, Buffer.concat([Buffer.from("SQLite format 3\0"), randomBytes(200)]));
    const a = json(await run(cwd, reader, { path: sqlite, password_file: pw }));
    assert.equal(a.outcome, "unsupported_format");
    assert.equal(a.status, "failed");
    assert.match(a.keychain.format, /Local Items/);
    assert.match(a.reason, /Local Items store/);
    const other = await keychain(cwd, "other.bin", null, randomBytes(300));
    const b = json(await run(cwd, reader, { path: other, password_file: pw }));
    assert.equal(b.outcome, "unsupported_format");
    assert.equal(b.keychain.format, "unknown");
    const tiny = await keychain(cwd, "tiny", null, Buffer.from("kyc"));
    const c = json(await run(cwd, reader, { path: tiny, password_file: pw }));
    assert.equal(c.outcome, "damaged");
    const empty = await keychain(cwd, "empty", null, Buffer.alloc(0));
    assert.equal(json(await run(cwd, reader, { path: empty, password_file: pw })).outcome, "damaged");
    assert.ok(!existsSync(imported), "the reader was not asked about the files that are not keychains");
    const cut = await keychain(cwd, "cut.keychain-db", { raise: true });
    const d = json(await run(cwd, reader, { path: cut, password_file: pw }));
    assert.equal(d.outcome, "damaged");
    assert.match(d.reason, /IndexError/);
    for (const x of [a, b, c, d]) {
      assert.notEqual(x.status, "complete");
      assert.equal(x.items_file, undefined);
    }
    assert.ok(existsSync(imported), "the reader is asked about a file that begins with kych");
    assert.deepEqual(await outFiles(cwd), []);
  });
});

test("a reader that is not installed, not importable, or a password file that is empty after its newline are told apart", async () => {
  await withCwd(async (cwd) => {
    const kc = await keychain(cwd, "login.keychain-db", { password: "pw", items: ITEMS });
    const pw = await secretFile(cwd, "pw.txt", "pw\n");
    const missing = await run(cwd, null, { path: kc, password_file: pw }, { PATH: "/usr/bin:/bin" });
    assert.equal(missing.code, 1);
    const m = json(missing);
    assert.equal(m.outcome, "unavailable");
    assert.equal(m.reader.found, false);
    const broken = await standin(cwd, "raise RuntimeError('no module')\n");
    const b = json(await run(cwd, broken, { path: kc, password_file: pw }));
    assert.equal(b.outcome, "unavailable");
    assert.match(b.reason, /RuntimeError/);
    const reader = await standin(cwd);
    const newline = await secretFile(cwd, "nl.txt", "\n");
    const n = json(await run(cwd, reader, { path: kc, password_file: newline }));
    assert.equal(n.outcome, "secret_unreadable");
    const bad = await secretFile(cwd, "bad.txt", "\xff\xfe");
    await writeFile(bad, Buffer.from([0xff, 0xfe, 0x80]));
    const u = json(await run(cwd, reader, { path: kc, password_file: bad }));
    assert.equal(u.outcome, "secret_unreadable");
    const odd = join(cwd, "odd");
    await mkdir(join(odd, "bin"), { recursive: true });
    await writeFile(join(odd, "bin", "chainbreaker"), "#!/bin/sh\necho hi\n");
    await chmod(join(odd, "bin", "chainbreaker"), 0o755);
    const o = json(await run(cwd, null, { path: kc, password_file: pw }, { PATH: `${join(odd, "bin")}:/usr/bin:/bin` }));
    assert.equal(o.outcome, "unavailable");
    assert.match(o.reason, /launcher/);
  });
});

// ---- the clock and the signals --------------------------------------------------------------------------------------------------------------

const alive = (pid: number): boolean => {
  try {
    process.kill(pid, 0);
    return true;
  } catch {
    return false;
  }
};

test("max_seconds ends a reader that does not end, and what it started, within 2 seconds of the limit", async () => {
  await withCwd(async (cwd) => {
    const reader = await standin(cwd);
    const child = join(cwd, "work", "child.pid");
    const kc = await keychain(cwd, "login.keychain-db", { password: "pw", mode: "hang", child, ready: join(cwd, "work", "ready"), items: ITEMS });
    const pw = await secretFile(cwd, "pw.txt", "pw");
    const began = Date.now();
    const out = await run(cwd, reader, { path: kc, password_file: pw, max_seconds: 2 });
    const took = (Date.now() - began) / 1000;
    const a = json(out);
    assert.equal(a.outcome, "timed_out");
    assert.equal(a.status, "failed");
    assert.ok(took < 2 + 2 + 1.5, `took ${took}s`);
    assert.ok(a.limits.seconds_used < 5, String(a.limits.seconds_used));
    const pid = Number(readFileSync(child, "utf8"));
    await new Promise((r) => setTimeout(r, 300));
    assert.ok(!alive(pid), "what the reader started is gone");
    assert.deepEqual(await outFiles(cwd), []);
  });
});

test("SIGTERM ends the reader and what it started, keeps the whole lines written, and answers once with exit 143", async () => {
  await withCwd(async (cwd) => {
    const reader = await standin(cwd);
    const child = join(cwd, "work", "child.pid");
    const ready = join(cwd, "work", "ready");
    const kc = await keychain(cwd, "login.keychain-db", { password: "pw", mode: "rows_then_hang", child, ready, items: ITEMS });
    const pw = await secretFile(cwd, "pw.txt", "pw");
    await mkdir(join(cwd, "out"), { recursive: true });
    const out = await runAndSignal(KEYCHAIN, cwd, { path: kc, password_file: pw }, "SIGTERM", async () => existsSync(ready), { JOB_ID: "j-1", OUT: join(cwd, "out"), SECRET_OUTPUT: "1" }, reader.path);
    assert.ok(out.signalled);
    assert.equal(out.code, 143, out.stderr + out.stdout);
    const a = json(out);
    assert.equal(a.interrupted, "SIGTERM");
    assert.equal(a.outcome, "interrupted");
    assert.equal(a.status, "partial", a.status_basis);
    const f = await itemsFile(cwd);
    assert.equal(f.rows.length, 2, "the two generic rows written before the hang are kept whole");
    assert.equal(a.items_file.lines, 2);
    assert.ok(f.text.endsWith("\n"));
    const pid = Number(readFileSync(child, "utf8"));
    await new Promise((r) => setTimeout(r, 300));
    assert.ok(!alive(pid), "what the reader started is gone");
    assert.deepEqual(await outFiles(cwd), ["keychain-items.jsonl"]);
  });
});

test("SIGTERM before any item is written answers failed with exit 143 and makes no file", async () => {
  await withCwd(async (cwd) => {
    const reader = await standin(cwd);
    const ready = join(cwd, "work", "ready");
    const kc = await keychain(cwd, "login.keychain-db", { password: "pw", mode: "hang", ready, items: ITEMS });
    const pw = await secretFile(cwd, "pw.txt", "pw");
    await mkdir(join(cwd, "out"), { recursive: true });
    for (const signal of ["SIGINT", "SIGHUP"] as const) {
      const out = await runAndSignal(KEYCHAIN, cwd, { path: kc, password_file: pw }, signal, async () => existsSync(ready), { JOB_ID: "j-1", OUT: join(cwd, "out"), SECRET_OUTPUT: "1" }, reader.path);
      assert.equal(out.code, 128 + (signal === "SIGINT" ? 2 : 1), out.stderr + out.stdout);
      const a = json(out);
      assert.equal(a.interrupted, signal);
      assert.equal(a.status, "failed");
      assert.deepEqual(await outFiles(cwd), []);
      await import("node:fs/promises").then((fs) => fs.rm(ready, { force: true }));
    }
  });
});

// ---- the password canary --------------------------------------------------------------------------------------------------------------------

function canary(): string {
  return "Pw-" + randomBytes(12).toString("hex");
}

/** The argument lists and environments of every process of this user while `probe` runs, joined: where a password on argv or in an environment would be. */
function processText(): string {
  let text = "";
  for (const pid of readdirSync("/proc").filter((p) => /^\d+$/.test(p))) {
    for (const name of ["cmdline", "environ"]) {
      try {
        text += readFileSync(`/proc/${pid}/${name}`, "latin1") + "\n";
      } catch {
        /* gone, or not ours */
      }
    }
  }
  return text;
}

test("a random password is in no argument list or environment while the reader runs, nor in the answer, stderr, a path, or any file but the one the caller gave", { skip: process.platform !== "linux" }, async () => {
  await withCwd(async (cwd) => {
    const reader = await standin(cwd);
    const password = canary();
    const ready = join(cwd, "work", "ready");
    const kc = await keychain(cwd, "login.keychain-db", { password, mode: "hang", ready, items: ITEMS, trace: join(cwd, "work", "trace.log") });
    const pw = await secretFile(cwd, "pw.txt", password + "\n");
    await mkdir(join(cwd, "out"), { recursive: true });
    let seen = "";
    const out = await runAndSignal(KEYCHAIN, cwd, { path: kc, password_file: pw, max_seconds: 30 }, "SIGTERM", async () => {
      if (!existsSync(ready)) return false;
      seen = processText();
      return true;
    }, { JOB_ID: "j-1", OUT: join(cwd, "out"), SECRET_OUTPUT: "1" }, reader.path);
    assert.ok(out.signalled);
    assert.ok(seen.includes("keychain_open") || seen.includes("run.py"), "the probe saw the tool's processes");
    assert.ok(seen.includes("-I"), "and the reader's process");
    assert.ok(!seen.includes(password), "the password is in the argument list or environment of a process alive during the run");
    assert.ok(!out.stdout.includes(password) && !out.stderr.includes(password));
    const trace = readFileSync(join(cwd, "work", "trace.log"), "utf8");
    assert.match(trace, /"password_given": true/);
    assert.ok(!trace.includes(password));
    for (const file of await filesUnder(cwd)) {
      if (file === pw) continue;
      assert.ok(!file.includes(password), file);
      if (file === kc) continue;
      assert.ok(!readFileSync(file).includes(password), `${file} holds the password`);
    }
  });
});

test("a random password canary is in none of the answers of the other outcomes either (wrong secret, partial, damaged, timed out)", async () => {
  await withCwd(async (cwd) => {
    const reader = await standin(cwd);
    const password = canary();
    const pw = await secretFile(cwd, "pw.txt", password);
    const specs: Record<string, unknown>[] = [
      { password: "other-" + canary(), items: ITEMS },
      { password, items: { dump_generic_passwords: [{ account: "a", service: "s", password: null }] } },
      { raise: true },
      { password, mode: "hang", items: ITEMS },
    ];
    for (const [i, spec] of specs.entries()) {
      const kc = await keychain(cwd, `k${i}.keychain-db`, spec);
      const out = await run(cwd, reader, { path: kc, password_file: pw, max_seconds: i === 3 ? 1 : 30 });
      assert.ok(!out.stdout.includes(password) && !out.stderr.includes(password), `case ${i}`);
    }
    for (const file of await filesUnder(cwd)) {
      if (file.endsWith("pw.txt") || file.includes("/work/k")) continue;
      assert.ok(!readFileSync(file).includes(password), file);
    }
  });
});

// ---- the items file is never replaced ------------------------------------------------------------------------------------------------------

test("a rerun with other items does not replace the earlier file, and a rerun with the same bytes names it again", async () => {
  await withCwd(async (cwd) => {
    const reader = await standin(cwd);
    const pw = await secretFile(cwd, "pw.txt", "pw");
    const big = await keychain(cwd, "a.keychain-db", { password: "pw", items: ITEMS });
    const small = await keychain(cwd, "b.keychain-db", { password: "pw", items: { dump_generic_passwords: [{ account: "a", service: "s", password: "v" }] } });
    const first = json(await run(cwd, reader, { path: big, password_file: pw }));
    const before = await readFile(join(cwd, "out", "keychain-items.jsonl"), "utf8");
    const second = json(await run(cwd, reader, { path: small, password_file: pw }));
    assert.equal(await readFile(join(cwd, "out", "keychain-items.jsonl"), "utf8"), before, "the larger earlier file is intact");
    assert.equal(second.items_file.file, "store/jobs/j-1/out/keychain-items-2.jsonl");
    assert.match(second.items_file.named_anew, /not replaced/);
    assert.equal(first.items_file.file, "store/jobs/j-1/out/keychain-items.jsonl");
    const again = json(await run(cwd, reader, { path: big, password_file: pw }));
    assert.equal(again.items_file.file, first.items_file.file);
    assert.deepEqual(await outFiles(cwd), ["keychain-items-2.jsonl", "keychain-items.jsonl"]);
    for (const name of await outFiles(cwd)) assert.equal((await stat(join(cwd, "out", name))).mode & 0o777, 0o600);
  });
});

test("an output directory that refuses the write is storage_refused, and says nothing about the keychain", async () => {
  await withCwd(async (cwd) => {
    if (process.getuid && process.getuid() === 0) return; // a directory mode does not stop root
    const reader = await standin(cwd);
    const pw = await secretFile(cwd, "pw.txt", "pw");
    const kc = await keychain(cwd, "a.keychain-db", { password: "pw", items: ITEMS });
    await mkdir(join(cwd, "out"), { recursive: true });
    await chmod(join(cwd, "out"), 0o500);
    try {
      const a = json(await run(cwd, reader, { path: kc, password_file: pw }));
      assert.equal(a.outcome, "storage_refused");
      assert.equal(a.status, "failed");
      assert.match(a.reason, /not about the keychain/);
    } finally {
      await chmod(join(cwd, "out"), 0o700);
    }
  });
});

// ---- one real run, on a Mac -----------------------------------------------------------------------------------------------------------------

const REAL = process.platform === "darwin" && spawnSync("sh", ["-c", "command -v chainbreaker >/dev/null && command -v security >/dev/null"]).status === 0;

test("a keychain made with `security create-keychain` in a temporary directory is opened with its password by the real reader", { skip: REAL ? false : "needs macOS with `security` and the chainbreaker reader" }, async () => {
  await withCwd(async (cwd) => {
    const password = canary();
    const value = canary();
    const kc = join(cwd, "work", "probe.keychain-db");
    await mkdir(join(cwd, "work"), { recursive: true });
    try {
      assert.equal(spawnSync("security", ["create-keychain", "-p", password, kc]).status, 0, "the keychain is made in the temporary directory and never added to the search list");
      assert.equal(spawnSync("security", ["add-generic-password", "-a", "acct", "-s", "svc", "-w", value, kc]).status, 0);
      const pw = await secretFile(cwd, "pw.txt", password);
      const out = await secretJob(KEYCHAIN, cwd, { path: kc, password_file: pw });
      const a = json(out);
      assert.equal(a.outcome, "opened", JSON.stringify(a));
      const f = await itemsFile(cwd);
      assert.ok(f.rows.some((r) => r.class === "generic_password" && r.value === value));
      assert.ok(!out.stdout.includes(value) && !out.stdout.includes(password));
      const wrong = await secretFile(cwd, "wrong.txt", canary());
      assert.equal(json(await secretJob(KEYCHAIN, cwd, { path: kc, password_file: wrong })).outcome, "wrong_secret");
    } finally {
      spawnSync("security", ["delete-keychain", kc]);
    }
  });
});
