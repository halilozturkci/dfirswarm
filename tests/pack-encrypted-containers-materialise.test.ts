/**
 * materialise_decrypted: decrypted evidence under $OUT from a sealed key reference. The Python readers (pybde, pyluksde, pyAesCrypt) are not
 * installed on every host, so the suite runs the tool against stand-in modules with the readers' documented calls (volume().open_file_object,
 * set_recovery_password / set_password / read_startup_key, unlock, get_size, read_buffer; pyAesCrypt.decryptStream): a stand-in keeps the
 * plaintext XORed with a constant and raises ValueError for a wrong key. They prove the tool's own behaviour (what it reads, what it writes
 * and where, what it never shows, how it ends), not any cryptography; the real modules are exercised only where they are importable.
 *
 * Held: refused as JSON before anything is read outside a secret_output job; the key reaches no command line (/proc/<pid>/cmdline and
 * environ are read while the tool runs), answer, key of the JSON, path, error text or file name, for canaries of many shapes, also when a
 * module's exception quotes the key; a wrong key leaves nothing; a container cut short or a volume that ends early is partial and kept as
 * an unverified 0600 .partial; the output budget; a key file that is a link, a pipe, a directory, world-readable, empty or too large is
 * refused; a rerun names the same result and replaces nothing; a stop leaves one document and the .partial file.
 */
import assert from "node:assert/strict";
import { createHash, randomBytes } from "node:crypto";
import { spawnSync } from "node:child_process";
import { chmod, mkdir, readFile, readdir, stat, symlink, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { test } from "node:test";
import { type Json, asJob, body, filesUnder, gone, pidFile, refused, startDetached, tool, withCwd } from "./pack-network-harness.ts";
import { ROOT } from "./tool-library-harness.ts";
import { NO_ADOPTION, NO_PROC } from "./host-gates.ts";

const SCRIPT = join(ROOT, "packs", "encrypted-containers", "tools", "materialise_decrypted", "run.py");
const XOR = 0x5a;
const xor = (b: Buffer): Buffer => Buffer.from(b.map((x) => x ^ XOR));
const sha = (b: Buffer): string => createHash("sha256").update(b).digest("hex");

// canaries of many shapes: none is a literal that looks like a secret in this file, each is built at run time
const hex = (n: number): string => randomBytes(n).toString("hex");
const SHAPES: Array<[string, () => string]> = [
  ["recovery password", () => Array.from({ length: 8 }, () => String(100000 + (randomBytes(3).readUIntBE(0, 3) % 900000))).join("-")],
  ["aws-shaped", () => "AK" + "IA" + hex(8).toUpperCase()],
  ["base64 of 32 bytes", () => randomBytes(32).toString("base64")],
  ["base64 of 20 bytes", () => randomBytes(20).toString("base64")],
  ["alnum 24", () => hex(12)],
  ["user-info", () => "us" + "er:" + hex(5) + "@host"],
];

/** The stand-in modules: the readers' documented calls over an XOR 'cipher'. Behaviour is chosen by STANDIN_MODE; the expected key is read from a file. */
const PYBDE = `
import os, signal, time
def get_version(): return "20240101"
def _expect(): return open(os.environ["STANDIN_EXPECT_FILE"]).read().strip()
class volume:
    def __init__(self): self.pw = None; self.fo = None
    def open_file_object(self, fo): self.fo = fo
    def set_recovery_password(self, p): self.pw = p
    set_password = set_recovery_password
    def read_startup_key(self, path): self.pw = open(path).read().strip()
    def unlock(self):
        m = os.environ.get("STANDIN_MODE")
        if m == "leak": raise ValueError("cannot unlock with " + str(self.pw))
        if os.environ.get("STANDIN_PID_FILE"): open(os.environ["STANDIN_PID_FILE"], "w").write(str(os.getpid()))
        if m == "segv_unlock": os.kill(os.getpid(), signal.SIGSEGV)
        if m in ("ignore_term", "fork_hang"): signal.signal(signal.SIGTERM, signal.SIG_IGN)
        if m == "fork_hang" or m == "fork_return":
            pid = os.fork()
            if pid == 0:
                signal.signal(signal.SIGTERM, signal.SIG_IGN)
                time.sleep(600)
                os._exit(0)
            open(os.environ["STANDIN_FORK_PID_FILE"], "w").write(str(pid))
        if m in ("hang_unlock", "ignore_term", "fork_hang"): time.sleep(600)
        return self.pw is None and os.environ.get("STANDIN_CLEAR") == "1" or self.pw == _expect()
    def get_size(self): return self.fo.get_size()
    def read_buffer(self, n):
        m = os.environ.get("STANDIN_MODE")
        self.calls = getattr(self, "calls", 0) + 1
        if m == "segv_read2" and self.calls == 2: os.kill(os.getpid(), signal.SIGSEGV)
        if m == "hang_read2" and self.calls == 2: time.sleep(600)
        if os.environ.get("STANDIN_MODE") == "slow": time.sleep(0.2)
        if os.environ.get("STANDIN_MODE") == "short":
            left = int(os.environ["STANDIN_SHORT_AT"]) - self.fo.tell()
            if left <= 0: return b""
            n = min(n, left)
        data = self.fo.read(n)
        return bytes(b ^ 0x5a for b in data)
    def close(self): pass
`;
const PYAES = `
import os, time
def get_version(): return "6.1.1"
def decryptStream(fin, fout, passw, bufferSize, inputLength):
    if os.environ.get("STANDIN_PID_FILE"): open(os.environ["STANDIN_PID_FILE"], "w").write(str(os.getpid()))
    if os.environ.get("STANDIN_MODE") == "leak": raise ValueError("Wrong password " + passw)
    if passw != open(os.environ["STANDIN_EXPECT_FILE"]).read().strip(): raise ValueError("Wrong password (or file is corrupted).")
    data = fin.read()
    body = data[5 + 2 + 16 + 48 + 32: len(data) - 33]
    m = data[-33]
    if m: body = body[:len(body) - (16 - m)]
    for i in range(0, len(body), 4096):
        if os.environ.get("STANDIN_MODE") == "slow": time.sleep(0.3)
        fout.write(bytes(b ^ 0x5a for b in body[i:i+4096]))
`;

async function mods(cwd: string): Promise<string> {
  const dir = join(cwd, "mods");
  await mkdir(dir, { recursive: true });
  await writeFile(join(dir, "pybde.py"), PYBDE);
  await writeFile(join(dir, "pyluksde.py"), PYBDE);
  await writeFile(join(dir, "pyAesCrypt.py"), PYAES);
  return dir;
}

/** An AES Crypt v2 container laid out as the format description says (header, extensions, IV, encrypted key, key HMAC, data, size byte, file HMAC), with a stand-in 'cipher'. */
function aesContainer(plain: Buffer): Buffer {
  const padded = Buffer.concat([plain, Buffer.alloc((16 - (plain.length % 16)) % 16)]);
  return Buffer.concat([Buffer.from("AES\x02\x00", "latin1"), Buffer.from([0, 0]), randomBytes(16), randomBytes(48), randomBytes(32), xor(padded), Buffer.from([plain.length % 16]), randomBytes(32)]);
}

const ntfsLike = (n: number): Buffer => {
  const b = Buffer.alloc(n, 0x41);
  b.write("NTFS    ", 3, "latin1");
  b[510] = 0x55;
  b[511] = 0xaa;
  return b;
};

async function key(cwd: string, name: string, text: string, mode = 0o600): Promise<string> {
  await writeFile(join(cwd, name), text + "\n", { mode });
  await chmod(join(cwd, name), mode);
  return name;
}

type Env = Record<string, string>;
async function run(cwd: string, args: Json, expect: string, env: Env = {}, bin?: string): Promise<{ code: number | null; stdout: string; stderr: string }> {
  await writeFile(join(cwd, "expect.txt"), expect, { mode: 0o600 });
  return asJob(SCRIPT, cwd, args, bin, { PYTHONPATH: await mods(cwd), STANDIN_EXPECT_FILE: join(cwd, "expect.txt"), ...env });
}
/** The provenance file an answer names (the digests live there: the shared output check replaces long hexadecimal runs in an answer). */
async function prov(cwd: string, a: Json): Promise<Json> {
  const name = String(a.output.provenance).split("/").pop() as string;
  assert.equal((await stat(join(cwd, "out", "materialised", name))).mode & 0o777, 0o600);
  return JSON.parse(await readFile(join(cwd, "out", "materialised", name), "utf8"));
}
const PROV = /\.provenance(-\d+)?\.json$/;
const materialised = (cwd: string): Promise<string[]> => readdir(join(cwd, "out", "materialised")).catch(() => []);

test("refused outside a secret_output job, before anything is read, its own stdin included", async () => {
  await withCwd(async (cwd) => {
    const canary = hex(12);
    for (const env of [{}, { JOB_ID: "j1" }, { JOB_ID: "j1", OUT: join(cwd, "out") }, { JOB_ID: "j1", OUT: join(cwd, "out"), SECRET_OUTPUT: "0" }] as Env[]) {
      const out = await tool(SCRIPT, cwd, "not json " + canary, env);
      const a = refused(out);
      assert.match(a.error, /refused outside a job run as secret output/);
      assert.ok(!out.stdout.includes(canary));
    }
    assert.deepEqual(await materialised(cwd), []);
  });
});

test("AES Crypt: decrypted to a 0600 file under the job's output, with provenance and nothing of the key in any channel", { skip: NO_ADOPTION }, async () => {
  await withCwd(async (cwd) => {
    for (const [shape, make] of SHAPES) {
      const secret = make();
      const plain = randomBytes(5000);
      await writeFile(join(cwd, "box.aes"), aesContainer(plain));
      await key(cwd, "key.txt", secret);
      const r = await run(cwd, { operation: "aescrypt_decrypt", source: "box.aes", key_ref: "key.txt" }, secret);
      const a = body(r);
      assert.equal(a.status, "complete", `${shape}: ${a.status_basis}`);
      assert.equal(a.container.version, 2);
      assert.equal(a.integrity.hmac_verified_by_module, true);
      assert.equal(a.output.bytes, 5000);
      const pv = await prov(cwd, a);
      assert.equal(pv.output.sha256, sha(plain));
      assert.equal(pv.evidence.sha256, sha(await readFile(join(cwd, "box.aes"))));
      assert.equal(pv.reader.module, "pyAesCrypt");
      assert.equal(pv.key.kind, "password");
      assert.equal(a.reader.module, "pyAesCrypt");
      const files = (await materialised(cwd)).filter((f) => !PROV.test(f));
      assert.equal(files.length, 1, JSON.stringify(files));
      assert.ok(!files[0].endsWith(".partial"));
      const path = join(cwd, "out", "materialised", files[0]);
      assert.equal((await stat(path)).mode & 0o777, 0o600);
      assert.deepEqual(await readFile(path), plain.subarray(0, 5000));
      for (const text of [r.stdout, r.stderr, ...(await filesUnder(join(cwd, "out"))), JSON.stringify(Object.keys(a))]) assert.ok(!text.includes(secret), `${shape} appears in an output channel`);
      await import("node:fs/promises").then((fs) => fs.rm(join(cwd, "out", "materialised"), { recursive: true, force: true }));
    }
  });
});

test("a wrong key leaves nothing; a module that quotes the key in its exception does not put it in the answer", async () => {
  await withCwd(async (cwd) => {
    await writeFile(join(cwd, "box.aes"), aesContainer(randomBytes(100)));
    const secret = SHAPES[0][1]();
    await key(cwd, "key.txt", secret);
    const wrong = body(await run(cwd, { operation: "aescrypt_decrypt", source: "box.aes", key_ref: "key.txt" }, "some other key"));
    assert.equal(wrong.status, "failed");
    assert.match(wrong.status_basis, /says nothing about whether the evidence can be opened/);
    assert.deepEqual(await materialised(cwd), []);
    for (const op of ["aescrypt_decrypt", "bitlocker_image"]) {
      await writeFile(join(cwd, "vol.bin"), ntfsLike(8192));
      const r = await run(cwd, { operation: op, source: op === "aescrypt_decrypt" ? "box.aes" : "vol.bin", key_ref: "key.txt", key_kind: op === "aescrypt_decrypt" ? "password" : "recovery_password" }, secret, { STANDIN_MODE: "leak" });
      const a = body(r);
      assert.equal(a.status, "failed", op);
      assert.match(a.status_basis, op === "aescrypt_decrypt" ? /did not decrypt the container/ : /raised ValueError; its message is not shown/);
      assert.ok(!r.stdout.includes(secret) && !r.stderr.includes(secret), op);
      assert.deepEqual(await materialised(cwd), [], op);
    }
  });
});

test("AES Crypt: a container cut short is partial and no plaintext is written", async () => {
  await withCwd(async (cwd) => {
    const secret = SHAPES[2][1]();
    const whole = aesContainer(randomBytes(4000));
    await writeFile(join(cwd, "cut.aes"), whole.subarray(0, whole.length - 20));
    await key(cwd, "key.txt", secret);
    const a = body(await run(cwd, { operation: "aescrypt_decrypt", source: "cut.aes", key_ref: "key.txt" }, secret));
    assert.equal(a.status, "partial");
    assert.match(a.status_basis, /cut copy/);
    assert.deepEqual(await materialised(cwd), []);
    await writeFile(join(cwd, "notaes"), "this is not an AES Crypt file at all");
    assert.match(body(await run(cwd, { operation: "aescrypt_decrypt", source: "notaes", key_ref: "key.txt" }, secret)).status_basis, /signature/);
  });
});

test("BitLocker: the volume at an offset is unlocked with a recovery password and written as a raw image, with the volume header check", { skip: NO_ADOPTION }, async () => {
  await withCwd(async (cwd) => {
    const secret = SHAPES[0][1]();
    const volume = ntfsLike(64 * 1024);
    await writeFile(join(cwd, "disk.img"), Buffer.concat([randomBytes(4096), xor(volume)]));
    await key(cwd, "rp.txt", secret);
    const r = await run(cwd, { operation: "bitlocker_image", source: "disk.img", key_ref: "rp.txt", key_kind: "recovery_password", offset: 4096 }, secret);
    const a = body(r);
    assert.equal(a.status, "complete", a.status_basis);
    assert.equal(a.offset_bytes, 4096);
    assert.equal(a.unlocked_bytes, 64 * 1024);
    assert.equal(a.integrity.volume_header, "NTFS");
    assert.equal((await prov(cwd, a)).output.sha256, sha(volume));
    assert.equal((await prov(cwd, a)).evidence.offset_bytes, 4096);
    assert.equal(a.key.kind, "recovery_password");
    assert.ok(!r.stdout.includes(secret));
    const [name] = (await materialised(cwd)).filter((f) => !PROV.test(f));
    assert.deepEqual(await readFile(join(cwd, "out", "materialised", name)), volume);
    // a rerun names the same result and replaces nothing
    const again = body(await run(cwd, { operation: "bitlocker_image", source: "disk.img", key_ref: "rp.txt", key_kind: "recovery_password", offset: 4096 }, secret));
    assert.equal(String(again.output.path).split("/").pop(), String(a.output.path).split("/").pop());
    assert.deepEqual((await materialised(cwd)).filter((f) => !PROV.test(f)), [name]);
    assert.equal((await materialised(cwd)).length, 2, "the provenance file is named again, not duplicated");
    // the clear key needs no key reference
    const clear = body(await run(cwd, { operation: "bitlocker_image", source: "disk.img", key_kind: "clear_key", offset: 4096 }, "unused", { STANDIN_CLEAR: "1" }));
    assert.equal(clear.status, "complete", clear.status_basis);
    // a wrong key
    const wrong = body(await run(cwd, { operation: "bitlocker_image", source: "disk.img", key_ref: "rp.txt", key_kind: "recovery_password", offset: 4096 }, "different"));
    assert.equal(wrong.status, "failed");
    assert.deepEqual((await materialised(cwd)).filter((f) => !PROV.test(f)), [name], "a wrong key leaves nothing new");
    // LUKS has the same shape through pyluksde
    const luks = body(await run(cwd, { operation: "luks_image", source: "disk.img", key_ref: "rp.txt", offset: 4096 }, secret));
    assert.equal(luks.reader.module, "pyluksde");
    assert.equal(luks.status, "complete", luks.status_basis);
  });
});

test("a volume that ends early, and the output budget, are partial and kept as an unverified 0600 .partial", async () => {
  await withCwd(async (cwd) => {
    const secret = SHAPES[3][1]();
    await writeFile(join(cwd, "disk.img"), xor(ntfsLike(64 * 1024)));
    await key(cwd, "rp.txt", secret);
    const cut = body(await run(cwd, { operation: "bitlocker_image", source: "disk.img", key_ref: "rp.txt", key_kind: "recovery_password" }, secret, { STANDIN_MODE: "short", STANDIN_SHORT_AT: "20000" }));
    assert.equal(cut.status, "partial");
    assert.match(cut.status_basis, /ended after \d+ of 65536 bytes/);
    assert.equal(cut.output.verified, false);
    const files = (await materialised(cwd)).filter((f) => !PROV.test(f));
    assert.equal(files.length, 1);
    assert.ok(files[0].endsWith(".partial"));
    assert.equal((await stat(join(cwd, "out", "materialised", files[0]))).mode & 0o777, 0o600);
    assert.equal((await prov(cwd, cut)).output.complete, false);
    const budget = body(await run(cwd, { operation: "bitlocker_image", source: "disk.img", key_ref: "rp.txt", key_kind: "recovery_password", max_output_bytes: 10000 }, secret));
    assert.equal(budget.status, "partial");
    assert.match(budget.status_basis, /output budget \(10000\)/);
    assert.equal(budget.output.bytes, 10000);
    assert.equal((await readdir(join(cwd, "out", "materialised"))).filter((f) => f.endsWith(".partial")).length, 2, "a second partial takes its own name");
    await writeFile(join(cwd, "box.aes"), aesContainer(randomBytes(3000)));
    const aesBudget = body(await run(cwd, { operation: "aescrypt_decrypt", source: "box.aes", key_ref: "rp.txt", max_output_bytes: 1 }, secret));
    assert.equal(aesBudget.status, "partial");
  });
});

test("a key reference that is a link, a pipe, a directory, world-readable, empty, too large or missing is refused as JSON, and a pipe does not hold the tool", async () => {
  await withCwd(async (cwd) => {
    const secret = SHAPES[1][1]();
    await writeFile(join(cwd, "box.aes"), aesContainer(randomBytes(100)));
    await key(cwd, "good.txt", secret);
    await symlink(join(cwd, "good.txt"), join(cwd, "link.txt"));
    await key(cwd, "open.txt", secret, 0o644);
    await key(cwd, "empty.txt", "", 0o600);
    await writeFile(join(cwd, "empty.txt"), "", { mode: 0o600 });
    await writeFile(join(cwd, "big.txt"), "a".repeat(5000), { mode: 0o600 });
    await mkdir(join(cwd, "dir"), { mode: 0o700 });
    assert.equal(spawnSync("mkfifo", ["-m", "600", join(cwd, "pipe.txt")]).status, 0);
    for (const [ref, why] of [["link.txt", /symbolic link/], ["open.txt", /mode 0600/], ["empty.txt", /empty/], ["big.txt", /larger than 4096/], ["dir", /not a regular file/], ["pipe.txt", /not a regular file/], ["missing.txt", /could not be read/]] as Array<[string, RegExp]>) {
      const started = Date.now();
      const r = await run(cwd, { operation: "aescrypt_decrypt", source: "box.aes", key_ref: ref }, secret);
      const a = refused(r);
      assert.match(a.error, why, ref);
      assert.ok(Date.now() - started < 15_000, ref);
      assert.ok(!r.stdout.includes(secret));
    }
    assert.deepEqual(await materialised(cwd), []);
  });
});

test("a module that is not installed answers unavailable, naming it, without reading the key reference", async () => {
  await withCwd(async (cwd) => {
    await writeFile(join(cwd, "box.aes"), aesContainer(randomBytes(100)));
    const r = await asJob(SCRIPT, cwd, { operation: "aescrypt_decrypt", source: "box.aes", key_ref: "does-not-exist.txt" }, undefined, { PYTHONPATH: "" });
    const a = body(r);
    assert.equal(a.status, "unavailable");
    assert.match(a.status_basis, /pyAesCrypt \(package pyAesCrypt\) is not importable, so nothing was read: the key file's bytes were not read/);
  });
});

test("hostile parameters are JSON refusals", async () => {
  await withCwd(async (cwd) => {
    await writeFile(join(cwd, "box.aes"), aesContainer(randomBytes(100)));
    await key(cwd, "k.txt", "x");
    const ok = { operation: "aescrypt_decrypt", source: "box.aes", key_ref: "k.txt" };
    for (const args of [{}, { ...ok, operation: "format_everything" }, { ...ok, operation: 5 }, { ...ok, source: 5 }, { ...ok, source: "a\u0000b" }, { ...ok, source: "\ud800" }, { ...ok, source: "x".repeat(5000) }, { ...ok, key_ref: ["k"] },
      { ...ok, key_kind: "recovery_password" }, { ...ok, offset: -1 }, { ...ok, offset: 10 ** 30 }, { ...ok, offset: 10 ** 9 }, { ...ok, max_output_bytes: 0 }, { ...ok, max_output_bytes: 10 ** 30 }, { ...ok, max_seconds: 0 }, { ...ok, max_seconds: "3" },
      { ...ok, hash_evidence: "yes" }, [], "x", 5, null]) {
      const r = await run(cwd, args as Json, "x");
      assert.equal(refused(r).status, "failed", JSON.stringify(args).slice(0, 80));
    }
    assert.equal(refused(await run(cwd, "[".repeat(300000) as unknown as Json, "x")).status, "failed");
    assert.deepEqual(await materialised(cwd), []);
  });
});

test("SIGTERM during the write: one document, exit 143, the .partial file left at 0600, and the key in neither the command line nor the environment of the running tool", { skip: NO_PROC }, async () => {
  await withCwd(async (cwd) => {
    const secret = SHAPES[0][1]();
    await writeFile(join(cwd, "disk.img"), xor(ntfsLike(8 * 1024 * 1024)));
    await key(cwd, "rp.txt", secret);
    await writeFile(join(cwd, "expect.txt"), secret, { mode: 0o600 });
    await mkdir(join(cwd, "out"), { recursive: true });
    const pidPath = join(cwd, "tool.pid");
    const run = startDetached(SCRIPT, cwd, { operation: "bitlocker_image", source: "disk.img", key_ref: "rp.txt", key_kind: "recovery_password" },
      { JOB_ID: "j1", OUT: join(cwd, "out"), SECRET_OUTPUT: "1", PYTHONPATH: await mods(cwd), STANDIN_EXPECT_FILE: join(cwd, "expect.txt"), STANDIN_MODE: "slow", STANDIN_PID_FILE: pidPath });
    const pid = await pidFile(pidPath);
    const cmdline = await readFile(`/proc/${pid}/cmdline`, "latin1");
    const environ = await readFile(`/proc/${pid}/environ`, "latin1");
    assert.ok(!cmdline.includes(secret), "the key is on the command line");
    assert.ok(!environ.includes(secret), "the key is in the environment");
    run.signal("SIGTERM");
    assert.equal(await run.closed, 143);
    assert.equal(run.stdout().trim().split("\n").filter(Boolean).length, 1);
    const a = JSON.parse(run.stdout());
    assert.equal(a.status, "failed");
    assert.equal(a.interrupted, true);
    assert.ok(!run.stdout().includes(secret));
    const files = await materialised(cwd);
    assert.equal(files.length, 1);
    assert.ok(files[0].endsWith(".partial"));
    assert.equal((await stat(join(cwd, "out", "materialised", files[0]))).mode & 0o777, 0o600);
    assert.ok(await gone(pid));
  });
});

// ---- the readers are native libraries: one that dies, hangs, forks or ignores a signal must not take the tool down ----

async function crash(cwd: string, mode: string, extra: Json = {}, env: Env = {}, size = 3 * 1024 * 1024): Promise<{ r: { code: number | null; stdout: string; stderr: string }; secret: string }> {
  const secret = SHAPES[0][1]();
  await writeFile(join(cwd, "disk.img"), xor(ntfsLike(size)));
  await key(cwd, "rp.txt", secret);
  const r = await run(cwd, { operation: "bitlocker_image", source: "disk.img", key_ref: "rp.txt", key_kind: "recovery_password", ...extra }, secret,
    { STANDIN_MODE: mode, STANDIN_PID_FILE: join(cwd, "reader.pid"), STANDIN_FORK_PID_FILE: join(cwd, "fork.pid"), ...env });
  return { r, secret };
}
const pidOf = async (p: string): Promise<number> => Number((await readFile(p, "utf8")).trim());

test("a reader that dies of SIGSEGV in unlock, or in its second read, is a JSON answer naming the signal, with no partial file left", async () => {
  for (const mode of ["segv_unlock", "segv_read2"]) {
    await withCwd(async (cwd) => {
      const { r, secret } = await crash(cwd, mode);
      assert.equal(r.code, 0, `${mode}: ${r.stderr.slice(0, 200)}`);
      assert.equal(r.stdout.trim().split("\n").length > 0, true);
      const a = body(r);
      assert.equal(a.status, "failed", mode);
      assert.match(a.status_basis, /signal 11 \(SIGSEGV\)/, mode);
      assert.notEqual(a.status, "complete");
      assert.equal(a.output, undefined, "no output is named");
      assert.deepEqual(await materialised(cwd), [], `${mode}: the .partial file is removed`);
      assert.ok(!r.stdout.includes(secret));
      assert.ok(await gone(await pidOf(join(cwd, "reader.pid"))));
    });
  }
});

test("a reader that hangs in a library call is ended at the tool's clock: before any output a failed answer, after some a partial that is kept and said to be unverified", async () => {
  await withCwd(async (cwd) => {
    const t0 = Date.now();
    const { r } = await crash(cwd, "hang_unlock", { max_seconds: 6 });
    assert.ok(Date.now() - t0 < 12000, "ended near the clock");
    const a = body(r);
    assert.equal(a.status, "failed");
    assert.match(a.status_basis, /did not return within the tool's time limit \(6 seconds\)/);
    assert.deepEqual(await materialised(cwd), []);
    assert.ok(await gone(await pidOf(join(cwd, "reader.pid"))));
  });
  await withCwd(async (cwd) => {
    const { r } = await crash(cwd, "hang_read2", { max_seconds: 6 });
    const a = body(r);
    assert.equal(a.status, "partial");
    assert.match(a.status_basis, /did not return within the tool's time limit/);
    assert.equal(a.output.verified, false);
    assert.equal(a.output.bytes, 1024 * 1024);
    const files = (await materialised(cwd)).filter((f) => !PROV.test(f));
    assert.equal(files.length, 1);
    assert.ok(files[0].endsWith(".partial"));
    assert.equal((await prov(cwd, a)).output.sha256, null);
    assert.ok(await gone(await pidOf(join(cwd, "reader.pid"))));
  });
});

test("a reader that forks: a sleeper it leaves behind is ended when it returns, and with it when it hangs and ignores SIGTERM", { skip: NO_ADOPTION }, async () => {
  await withCwd(async (cwd) => {
    // as a job runs it: the tool heads its own process group, so what the reader left behind is the tool's to end
    const secret = SHAPES[0][1]();
    await writeFile(join(cwd, "disk.img"), xor(ntfsLike(3 * 1024 * 1024)));
    await key(cwd, "rp.txt", secret);
    await writeFile(join(cwd, "expect.txt"), secret, { mode: 0o600 });
    await mkdir(join(cwd, "out"), { recursive: true });
    const proc = startDetached(SCRIPT, cwd, { operation: "bitlocker_image", source: "disk.img", key_ref: "rp.txt", key_kind: "recovery_password" },
      { JOB_ID: "j1", OUT: join(cwd, "out"), SECRET_OUTPUT: "1", PYTHONPATH: await mods(cwd), STANDIN_EXPECT_FILE: join(cwd, "expect.txt"), STANDIN_MODE: "fork_return",
        STANDIN_PID_FILE: join(cwd, "reader.pid"), STANDIN_FORK_PID_FILE: join(cwd, "fork.pid") });
    assert.equal(await proc.closed, 0);
    // the reader returned and left a sleeper holding the descriptors it inherited: the tool ends it, and the image is no longer a complete result (an unverified .partial)
    const left = JSON.parse(proc.stdout());
    assert.equal(left.status, "partial", left.status_basis);
    assert.ok(left.program_group.left_behind >= 1);
    assert.equal(left.output.verified, false);
    assert.ok(await gone(await pidOf(join(cwd, "fork.pid"))), "the forked sleeper outlived the tool");
  });
  await withCwd(async (cwd) => {
    const { r } = await crash(cwd, "fork_hang", { max_seconds: 6 });
    assert.equal(body(r).status, "failed");
    assert.ok(await gone(await pidOf(join(cwd, "fork.pid"))), "the forked sleeper outlived the tool");
    assert.ok(await gone(await pidOf(join(cwd, "reader.pid"))));
  });
});

test("SIGTERM to the tool while the reader ignores SIGTERM and hangs: one document, exit 143, no reader left", async () => {
  await withCwd(async (cwd) => {
    const secret = SHAPES[0][1]();
    await writeFile(join(cwd, "disk.img"), xor(ntfsLike(3 * 1024 * 1024)));
    await key(cwd, "rp.txt", secret);
    await writeFile(join(cwd, "expect.txt"), secret, { mode: 0o600 });
    await mkdir(join(cwd, "out"), { recursive: true });
    const pidPath = join(cwd, "reader.pid");
    const proc = startDetached(SCRIPT, cwd, { operation: "bitlocker_image", source: "disk.img", key_ref: "rp.txt", key_kind: "recovery_password" },
      { JOB_ID: "j1", OUT: join(cwd, "out"), SECRET_OUTPUT: "1", PYTHONPATH: await mods(cwd), STANDIN_EXPECT_FILE: join(cwd, "expect.txt"), STANDIN_MODE: "fork_hang",
        STANDIN_PID_FILE: pidPath, STANDIN_FORK_PID_FILE: join(cwd, "fork.pid") });
    const pid = await pidFile(pidPath);
    await pidFile(join(cwd, "fork.pid"));
    proc.signal("SIGTERM");
    proc.signal("SIGTERM");
    assert.equal(await proc.closed, 143);
    assert.equal(proc.stdout().trim().split("\n").filter(Boolean).length, 1, "exactly one document");
    assert.equal(JSON.parse(proc.stdout()).interrupted, true);
    assert.ok(await gone(pid));
    assert.ok(await gone(await pidOf(join(cwd, "fork.pid"))));
  });
});

test("the native modules are imported by the reader child only, never by the tool's own process", async () => {
  const text = await readFile(SCRIPT, "utf8");
  const code = text.replace(/^\s*#.*$/gm, "");
  const calls = [...code.matchAll(/importlib\.import_module\(/g)].length;
  assert.equal(calls, 2, "the probe and the work, both in reader_child");
  const child = code.slice(code.indexOf("def reader_child"), code.indexOf("def _run_child"));
  assert.equal([...child.matchAll(/importlib\.import_module\(/g)].length, 2);
  assert.doesNotMatch(code.slice(code.indexOf("def main()"), code.indexOf("READER_RESULT_MAX")), /import_module|\.unlock\(|read_buffer\(|decryptStream\(/);
});

test("the real pyAesCrypt round trip, where the module is importable", async (t) => {
  if (spawnSync("python3", ["-c", "import pyAesCrypt"]).status !== 0) return t.skip("pyAesCrypt is not importable on this host");
  await withCwd(async (cwd) => {
    const secret = hex(10);
    const plain = randomBytes(70000);
    await writeFile(join(cwd, "plain.bin"), plain);
    const py = `import pyAesCrypt,sys;pyAesCrypt.encryptFile("plain.bin","box.aes",sys.stdin.readline().strip(),65536)`;
    const enc = spawnSync("python3", ["-c", py], { cwd, input: secret + "\n" });
    assert.equal(enc.status, 0);
    await key(cwd, "key.txt", secret);
    const a = body(await asJob(SCRIPT, cwd, { operation: "aescrypt_decrypt", source: "box.aes", key_ref: "key.txt" }));
    assert.equal(a.status, "complete", a.status_basis);
    assert.equal((await prov(cwd, a)).output.sha256, sha(plain));
  });
});

test("the tool carries the shared blocks of its lineage byte for byte, STOP first, and starts nothing", async () => {
  const text = await readFile(SCRIPT, "utf8");
  const probe = await readFile(join(ROOT, "packs", "encrypted-containers", "tools", "archive_probe", "run.py"), "utf8");
  const cut = (t: string, n: string): string => t.slice(t.indexOf(`# BEGIN SHARED ${n}`), t.indexOf(`# END SHARED ${n}`));
  for (const n of ["STOP", "PLACE", "PAGE", "WITHHOLDING", "NAMES", "PROCESS"]) assert.equal(cut(text, n), cut(probe, n), n);
  for (const n of ["PLACE", "PAGE", "WITHHOLDING", "NAMES", "PROCESS"]) assert.ok(text.indexOf("# BEGIN SHARED STOP") < text.indexOf(`# BEGIN SHARED ${n}`), n);
  assert.doesNotMatch(text.replace(/^\s*#.*$/gm, "").replace(/"""[\s\S]*?"""/g, ""), /start_new_session|setsid|process_group/);
  const own = text.slice(text.indexOf("# END SHARED PROCESS"));
  const argvs = [...own.matchAll(/\[sys\.executable[^\]]*\]/g)].map((m) => m[0]);
  assert.deepEqual(argvs, ['[sys.executable, os.path.abspath(__file__), "--reader-child", mode]'], "the one program this tool starts is its own reader child, and no key is in its argument list");
  assert.doesNotMatch(own, /os\.system|os\.exec|shell=True/, "no other program is started: the key cannot reach a command line");
});
