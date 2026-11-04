/**
 * backup_decrypt (mobile-forensics): an encrypted iOS backup decrypted with iphone_backup_decrypt, from a password in a file.
 *
 * The real library is not installed on the machine that wrote this test and none was downloaded (the approval covers a pin by hashes, not
 * the package's bytes). Every test therefore runs the tool against a STAND-IN module named iphone_backup_decrypt, put first on PYTHONPATH,
 * that has the three documented calls the tool uses (EncryptedBackup(backup_directory=, passphrase=), save_manifest_file(path),
 * extract_file(relative_path=, domain_like=, output_filename=)) and a toy cipher (XOR with 0x5A) and password check (a SHA-256 stored in the
 * fixture). It quotes the password in the text of its exceptions on purpose, to show that the tool reports a class name only. What the
 * stand-in cannot show: that the real library has these signatures, how long its key derivation takes, or how it behaves on a real backup.
 * The fixtures follow the backup format (Manifest.db's Files table, the keyed archive in `file`, the plists, blobs in <xx>/<fileID>).
 *
 * To see that a test fails on code it was written against, point BACKUP_DECRYPT at a script that is not the tool (the tool is new in this
 * change, so on the base every test fails because the script does not exist).
 */
import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { createHash, randomBytes } from "node:crypto";
import { chmod, lstat, mkdir, readFile, readdir, stat, symlink, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { test } from "node:test";
import { ROOT, runPy, runPySnippet, withCwd } from "./tool-library-harness.ts";

const TOOL = process.env.BACKUP_DECRYPT ?? join(ROOT, "packs", "mobile-forensics", "tools", "backup_decrypt", "run.py");

type Run = { code: number | null; stdout: string; stderr: string };
type Row = { row: number; file_id: string | null; domain: string; relative_path: string; kind: string; manifest_size: number | null; outcome: string; decrypted_bytes?: number | null; backend_exception_class?: string };
type Answer = {
  status: string; status_basis: string; outcome: string; error?: string; interrupted?: string; written?: boolean;
  counts: Record<string, number>; rows: Row[]; problems: string[]; truncated: boolean;
  decrypted: { root: string; manifest: string; manifest_opens_as_sqlite: boolean; manifest_rows: number };
  pages: { rows: { rows: number; all_results: string } };
  backup_facts: Record<string, unknown>; unlock?: { stage: string; exception_class: string }; password_file?: { usable: boolean; why?: string };
};

const STANDIN = String.raw`
import hashlib, json, os, sqlite3, tempfile, time
def _x(b):
    return bytes(c ^ 0x5A for c in b)
class EncryptedBackup:
    def __init__(self, backup_directory=None, passphrase=None):
        self.dir = backup_directory
        self.pw = passphrase
        meta = json.load(open(os.path.join(backup_directory, "standin.json")))
        if hashlib.sha256(passphrase.encode()).hexdigest() != meta["sha"]:
            raise ValueError("Incorrect passphrase: " + passphrase)
        time.sleep(float(os.environ.get("STANDIN_OPEN_SLEEP", "0")))
        self.tmp = tempfile.NamedTemporaryFile(dir=tempfile.gettempdir(), delete=False)
        self.tmp.write(_x(open(os.path.join(self.dir, "Manifest.db"), "rb").read()))
        self.tmp.close()
    def save_manifest_file(self, output_filename="manifest.db"):
        with open(output_filename, "wb") as fh:
            fh.write(_x(open(os.path.join(self.dir, "Manifest.db"), "rb").read()))
    def extract_file(self, *, relative_path=None, domain_like=None, output_filename):
        time.sleep(float(os.environ.get("STANDIN_FILE_SLEEP", "0")))
        if "boom" in relative_path:
            raise RuntimeError("cannot decrypt, passphrase was " + self.pw)
        con = sqlite3.connect(self.tmp.name)
        row = con.execute("SELECT fileID FROM Files WHERE relativePath = ? AND domain LIKE ? AND flags = 1 LIMIT 1", (relative_path, domain_like)).fetchone()
        if row is None:
            raise KeyError("no such row")
        blob = open(os.path.join(self.dir, row[0][:2], row[0]), "rb").read()
        with open(output_filename, "wb") as fh:
            fh.write(_x(blob))
`;

/** An encrypted backup directory from a spec: the plain map is built, then the map and the blobs are XORed. */
const ENCBACKUP = String.raw`
import hashlib, json, os, plistlib, sqlite3, sys
dest = sys.argv[1]
spec = json.load(sys.stdin)
os.makedirs(dest, exist_ok=True)
def x(b): return bytes(c ^ 0x5A for c in b)
def archive(size):
    return plistlib.dumps({"$archiver": "NSKeyedArchiver", "$version": 100000, "$top": {"root": plistlib.UID(1)},
        "$objects": ["$null", {"Size": size, "Mode": 0o100644, "$class": plistlib.UID(2)}, {"$classname": "MBFile", "$classes": ["MBFile", "NSObject"]}]}, fmt=plistlib.FMT_BINARY)
plain = os.path.join(dest, "Manifest.plain")
con = sqlite3.connect(plain)
con.execute("CREATE TABLE Files (fileID TEXT PRIMARY KEY, domain TEXT, relativePath TEXT, flags INTEGER, file BLOB)")
for e in spec["entries"]:
    data = e["data"].encode() if "data" in e else bytes((i * 7 + 3) % 256 for i in range(e.get("size", 10)))
    con.execute("INSERT INTO Files VALUES (?,?,?,?,?)", (e["id"], e.get("domain", "HomeDomain"), e["path"], e.get("flags", 1), archive(e.get("msize", len(data)))))
    if e.get("flags", 1) == 1 and e.get("blob", "sharded") == "sharded":
        os.makedirs(os.path.join(dest, e["id"][:2]), exist_ok=True)
        with open(os.path.join(dest, e["id"][:2], e["id"]), "wb") as fh: fh.write(x(data))
con.commit(); con.close()
raw = open(plain, "rb").read(); os.unlink(plain)
open(os.path.join(dest, "Manifest.db"), "wb").write(raw if spec.get("plain_manifest") else x(raw))
body = {"Version": "10.0", "IsEncrypted": spec.get("encrypted", True)}
if not spec.get("no_keys"): body["BackupKeyBag"] = b"KB" * 40; body["ManifestKey"] = b"MK" * 20
with open(os.path.join(dest, "Manifest.plist"), "wb") as fh: plistlib.dump(body, fh)
json.dump({"sha": hashlib.sha256(spec["password"].encode()).hexdigest()}, open(os.path.join(dest, "standin.json"), "w"))
`;

const fid = (n: number, shard = "aa"): string => shard + n.toString(16).padStart(38, "0");

async function setup(cwd: string): Promise<string> {
  const dir = join(cwd, "standin", "iphone_backup_decrypt");
  await mkdir(dir, { recursive: true });
  await writeFile(join(dir, "__init__.py"), STANDIN, "utf8");
  return join(cwd, "standin");
}

async function backup(cwd: string, name: string, spec: Record<string, unknown>): Promise<string> {
  const dir = join(cwd, "work", name);
  const out = await runPySnippet(ENCBACKUP, [dir], spec);
  assert.equal(out.code, 0, out.stderr);
  return dir;
}

async function secretFile(cwd: string, name: string, text: string, mode = 0o600): Promise<string> {
  const path = join(cwd, "work", name);
  await writeFile(path, text, { mode });
  await chmod(path, mode);
  return path;
}

function canaryText(): string {
  return "Cn-" + randomBytes(12).toString("hex");
}

function env(cwd: string, out: string, more: Record<string, string> = {}, secret = true, backend = true): Record<string, string> {
  return { AGENT_ID: "s1", JOB_ID: "j-1", OUT: out, ...(secret ? { SECRET_OUTPUT: "1" } : {}), ...(backend ? { PYTHONPATH: join(cwd, "standin") } : {}), ...more };
}

async function job(cwd: string, args: unknown, name = "out", more: Record<string, string> = {}, secret = true, backend = true): Promise<Run> {
  await mkdir(join(cwd, name), { recursive: true });
  return runPy(TOOL, cwd, args, undefined, env(cwd, join(cwd, name), more, secret, backend));
}

function answer(out: Run, ok = true): Answer {
  assert.doesNotMatch(out.stderr, /Traceback/);
  if (ok) assert.equal(out.code, 0, out.stderr + out.stdout);
  else assert.notEqual(out.code, 0, out.stdout);
  return JSON.parse(out.stdout) as Answer;
}

async function walk(dir: string): Promise<string[]> {
  const found: string[] = [];
  const go = async (d: string): Promise<void> => {
    for (const e of await readdir(d, { withFileTypes: true })) {
      const p = join(d, e.name);
      found.push(p);
      if (e.isDirectory()) await go(p);
    }
  };
  await go(dir);
  return found;
}

async function sealedFiles(dir: string): Promise<string[]> {
  return (await walk(dir)).filter((p) => !p.endsWith("/decrypted") && !/\/(tool-output|backup_decrypt-[0-9a-f]+)$/.test(p));
}

const alive = (pid: number): boolean => { try { process.kill(pid, 0); return true; } catch { return false; } };

async function descendants(root: number): Promise<number[]> {
  const parent = new Map<number, number>();
  for (const name of await readdir("/proc")) {
    if (!/^\d+$/.test(name)) continue;
    try {
      const text = await readFile(`/proc/${name}/stat`, "utf8");
      const after = text.slice(text.lastIndexOf(")") + 2).split(" ");
      parent.set(Number(name), Number(after[1]));
    } catch { /* gone */ }
  }
  const found = new Set<number>([root]);
  for (let grew = true; grew;) {
    grew = false;
    for (const [pid, ppid] of parent) if (!found.has(pid) && found.has(ppid)) { found.add(pid); grew = true; }
  }
  return [...found];
}

const SPEC = (password: string, extra: Record<string, unknown> = {}): Record<string, unknown> => ({
  password,
  entries: [
    { id: fid(1), path: "Library/SMS/sms.db", data: "sms database bytes" },
    { id: fid(2), path: "Media/DCIM/IMG_0001.JPG", size: 3000, domain: "CameraRollDomain" },
    { id: fid(3), path: "Library", flags: 2, size: 0, blob: "none" },
    { id: fid(4), path: "Library/link", flags: 4, size: 0, blob: "none" },
  ],
  ...extra,
});

test("backup_decrypt decrypts a backup, verifies the lengths against the Manifest, and writes every file 0600 under its id", async () => {
  await withCwd(async (cwd) => {
    await setup(cwd);
    const password = canaryText();
    const dir = await backup(cwd, "b", SPEC(password));
    const ref = await secretFile(cwd, "pw.txt", password + "\n");
    const run = await job(cwd, { backup: dir, password_ref: ref });
    const a = answer(run);
    assert.equal(a.status, "complete", JSON.stringify(a.problems) + a.status_basis);
    assert.equal(a.outcome, "verified");
    assert.equal(a.decrypted.manifest_opens_as_sqlite, true);
    assert.deepEqual(a.counts, { decrypted_verified: 2, no_blob_expected: 2 });
    const root = join(cwd, "out", a.decrypted.root.split("/out/")[1]);
    const sms = join(root, fid(1).slice(0, 2), fid(1));
    assert.equal(await readFile(sms, "utf8"), "sms database bytes");
    assert.equal((await stat(sms)).mode & 0o777, 0o600);
    assert.equal((await stat(join(root, "Manifest.db"))).mode & 0o777, 0o600);
    assert.equal((await readFile(join(root, "Manifest.db"))).subarray(0, 15).toString(), "SQLite format 3");
    assert.match(await readFile(join(root, "DECRYPTED.json"), "utf8"), /backup directory \(Manifest\.plist is not carried over\)/);
    // The whole account is a result file with a line per row of the map.
    const lines = (await readFile(join(cwd, "out", a.pages.rows.all_results.split("/out/")[1]), "utf8")).trim().split("\n").map((l) => JSON.parse(l) as Row);
    assert.equal(lines.length, 4);
    assert.deepEqual(lines.map((l) => l.outcome), ["decrypted_verified", "decrypted_verified", "no_blob_expected", "no_blob_expected"]);
    // No working copy is left: the work directory (the library's temporary files and stages) is gone.
    assert.equal((await walk(join(cwd, "out"))).some((p) => p.endsWith("/work") || p.includes("/stage-") || p.endsWith("events.jsonl")), false);
    // The key material is a presence and a length, never a byte.
    assert.deepEqual(a.backup_facts.BackupKeyBag, { present: true, bytes: 80 });
    assert.doesNotMatch(run.stdout, /KBKB|MKMK|S0JL/);
  });
});

test("the password reaches no argv, environment, output channel, path or file, though the library quotes it in its exception text", async () => {
  await withCwd(async (cwd) => {
    await setup(cwd);
    const password = canaryText();
    const dir = await backup(cwd, "b", { ...SPEC(password), entries: [...(SPEC(password).entries as unknown[]), { id: fid(9), path: "Documents/boom.txt", data: "x" }] });
    const ref = await secretFile(cwd, "pw.txt", password);
    await mkdir(join(cwd, "out"), { recursive: true });
    const child = spawn("python3", [TOOL], { cwd, env: { ...process.env, ...env(cwd, join(cwd, "out"), { STANDIN_OPEN_SLEEP: "3" }) } });
    const out: Buffer[] = [];
    const err: Buffer[] = [];
    child.stdout.on("data", (c: Buffer) => out.push(c));
    child.stderr.on("data", (c: Buffer) => err.push(c));
    const exit = new Promise<number | null>((resolve) => child.on("close", resolve));
    child.stdin.end(JSON.stringify({ backup: dir, password_ref: ref }));
    const seen = new Set<string>();
    const channels: string[] = [];
    for (let i = 0; i < 25; i++) {
      await new Promise((r) => setTimeout(r, 100));
      for (const pid of await descendants(child.pid!)) {
        for (const f of ["cmdline", "environ"]) {
          try {
            const data = await readFile(`/proc/${pid}/${f}`);
            if (f === "cmdline") seen.add(data.toString("utf8").replace(/\0/g, " "));
            channels.push(`/proc/${pid}/${f}: ${data.includes(password) ? "CANARY" : "clean"}`);
          } catch { /* gone */ }
        }
      }
    }
    assert.equal(await exit, 0);
    assert.ok([...seen].some((c) => c.includes("--child")), `the child was sampled: ${[...seen].join(" | ")}`);
    assert.ok(channels.length >= 4);
    assert.deepEqual(channels.filter((c) => c.endsWith("CANARY")), []);
    const stdout = Buffer.concat(out).toString("utf8");
    const stderr = Buffer.concat(err).toString("utf8");
    assert.equal(stdout.includes(password) || stderr.includes(password), false);
    const a = JSON.parse(stdout) as Answer;
    assert.equal(a.status, "partial");
    assert.equal(a.counts.backend_error, 1, JSON.stringify(a.counts));
    const boom = a.rows.find((r) => r.outcome === "backend_error")!;
    assert.equal(boom.backend_exception_class, "RuntimeError");
    // Every path and every byte of every file under the output holds no canary.
    for (const p of await walk(join(cwd, "out"))) {
      assert.equal(p.includes(password), false, p);
      const info = await lstat(p);
      if (info.isFile()) assert.equal((await readFile(p)).includes(Buffer.from(password)), false, p);
    }
    // And the password file is as it was.
    assert.equal(await readFile(ref, "utf8"), password);
  });
});

test("a wrong password, a missing or unfit password file, an unsupported backup and a missing backend are told apart, and nothing is kept", async () => {
  await withCwd(async (cwd) => {
    await setup(cwd);
    const password = canaryText();
    const dir = await backup(cwd, "b", SPEC(password));
    const wrong = canaryText();
    const bad = answer(await job(cwd, { backup: dir, password_ref: await secretFile(cwd, "wrong.txt", wrong) }, "o1"), false);
    assert.equal(bad.outcome, "wrong_secret");
    assert.equal(bad.status, "failed");
    assert.equal(bad.unlock?.exception_class, "ValueError");
    assert.equal(JSON.stringify(bad).includes(wrong), false, "the library quotes the password; the answer does not");
    assert.deepEqual(await walk(join(cwd, "o1")), []);
    // The password file: each fault is secret_unavailable, before any child is started or after its own look.
    const link = join(cwd, "work", "link.txt");
    await symlink(await secretFile(cwd, "real.txt", password), link);
    await mkdir(join(cwd, "work", "adir"));
    const faults: [string, string][] = [
      [join(cwd, "work", "absent.txt"), "missing"],
      [await secretFile(cwd, "open.txt", password, 0o644), "mode_not_0600"],
      [await secretFile(cwd, "empty.txt", "", 0o600), "size_out_of_range"],
      [await secretFile(cwd, "big.txt", "p".repeat(4097), 0o600), "size_out_of_range"],
      [link, "a_link"],
      [join(cwd, "work", "adir"), "not_a_regular_file"],
    ];
    for (const [i, [ref, why]] of faults.entries()) {
      const r = answer(await job(cwd, { backup: dir, password_ref: ref }, `f${i}`), false);
      assert.equal(r.outcome, "secret_unavailable", why);
      assert.equal(r.password_file?.why, why);
      assert.deepEqual(await walk(join(cwd, `f${i}`)), []);
    }
    // A password that is not UTF-8 is found by the child, which reads it.
    const nonutf = join(cwd, "work", "nonutf.txt");
    await writeFile(nonutf, Buffer.from([0xff, 0xfe, 0x41]), { mode: 0o600 });
    const n = answer(await job(cwd, { backup: dir, password_ref: nonutf }, "fn"), false);
    assert.equal(n.outcome, "secret_unavailable");
    assert.equal(n.password_file?.why, "not_utf8");
    // Unsupported formats: nothing is attempted.
    const good = await secretFile(cwd, "good.txt", password);
    const shapes: [string, Record<string, unknown>, RegExp][] = [
      ["notenc", { encrypted: false }, /does not say IsEncrypted is true/],
      ["nokeys", { no_keys: true }, /holds no BackupKeyBag/],
      ["plaindb", { plain_manifest: true }, /plain SQLite file although/],
    ];
    for (const [name, extra, pattern] of shapes) {
      const d = await backup(cwd, name, SPEC(password, extra));
      const r = answer(await job(cwd, { backup: d, password_ref: good }, `u-${name}`), false);
      assert.equal(r.outcome, "unsupported_format", name);
      assert.match(r.status_basis, pattern, name);
      assert.deepEqual(await walk(join(cwd, `u-${name}`)), []);
    }
    // No Manifest.plist at all.
    const nomanifest = join(cwd, "work", "nomanifest");
    await mkdir(nomanifest);
    const m = answer(await job(cwd, { backup: nomanifest, password_ref: good }, "u-none"), false);
    assert.equal(m.outcome, "unsupported_format");
    // The library is not installed.
    const nb = answer(await job(cwd, { backup: dir, password_ref: good }, "nb", {}, true, false), false);
    assert.equal(nb.outcome, "backend_unavailable");
    assert.deepEqual(await walk(join(cwd, "nb")), []);
  });
});

test("the tool is refused outside a job and in a job that is not secret output, as JSON, before anything is made", async () => {
  await withCwd(async (cwd) => {
    await setup(cwd);
    const password = canaryText();
    const dir = await backup(cwd, "b", SPEC(password));
    const ref = await secretFile(cwd, "pw.txt", password);
    const outside = await runPy(TOOL, cwd, { backup: dir, password_ref: ref }, undefined, { AGENT_ID: "s1", PYTHONPATH: join(cwd, "standin") });
    assert.match(answer(outside, false).error ?? "", /refused outside a job/);
    const plain = answer(await job(cwd, { backup: dir, password_ref: ref }, "plain", {}, false), false);
    assert.match(plain.error ?? "", /not run as secret output/);
    assert.deepEqual(await walk(join(cwd, "plain")), []);
    assert.deepEqual(await readdir(join(cwd, "work")).then((n) => n.filter((x) => x.startsWith("backup_decrypt"))), []);
    const unknown = answer(await job(cwd, { backup: dir, password_ref: ref, password: "x" }, "unk"), false);
    assert.match(unknown.error ?? "", /no such argument/);
    assert.equal(JSON.stringify(unknown).includes("\"x\""), false);
  });
});

test("rows that are not decrypted and verified make the run partial and are told apart: a missing blob, a length that is not the Size, an ambiguous name, a hostile name and id", async () => {
  await withCwd(async (cwd) => {
    await setup(cwd);
    const password = canaryText();
    const dir = await backup(cwd, "b", {
      password,
      entries: [
        { id: fid(1), path: "ok.txt", data: "fine" },
        { id: fid(2), path: "gone.txt", data: "x", blob: "none" },
        { id: fid(3), path: "short.txt", data: "abcdef", msize: 99 },
        { id: fid(4), path: "same.txt", data: "one", domain: "AppDomain-Test" },
        { id: fid(5), path: "same.txt", data: "two", domain: "appdomain-test" },
        { id: fid(6), path: "wild.txt", data: "aaa", domain: "AppDomain-a_c" },
        { id: fid(7), path: "wild.txt", data: "bbb", domain: "AppDomain-abc" },
        { id: fid(8), path: "../../escape.txt", data: "hostile name", domain: "HomeDomain" },
        { id: "zz" + "0".repeat(38), path: "badid.txt", data: "x", blob: "none" },
      ],
    });
    const ref = await secretFile(cwd, "pw.txt", password);
    const a = answer(await job(cwd, { backup: dir, password_ref: ref }));
    assert.equal(a.status, "partial", a.status_basis);
    assert.equal(a.outcome, "partial");
    const by = (path: string, domain?: string): Row => a.rows.find((r) => r.relative_path === path && (domain === undefined || r.domain === domain))!;
    assert.equal(by("ok.txt").outcome, "decrypted_verified");
    assert.equal(by("gone.txt").outcome, "blob_missing");
    assert.equal(by("short.txt").outcome, "size_mismatch");
    assert.equal(by("same.txt", "AppDomain-Test").outcome, "ambiguous_selection");
    assert.equal(by("same.txt", "appdomain-test").outcome, "ambiguous_selection");
    assert.equal(by("wild.txt", "AppDomain-a_c").outcome, "ambiguous_selection");
    assert.equal(by("wild.txt", "AppDomain-abc").outcome, "ambiguous_selection");
    assert.equal(by("../../escape.txt").outcome, "decrypted_verified");
    assert.equal(a.rows.find((r) => r.relative_path === "badid.txt")!.outcome, "refused_id");
    // The hostile name wrote nowhere but under its id; nothing escaped the output directory.
    assert.equal((await readdir(join(cwd, "work"))).includes("escape.txt"), false);
    assert.equal((await readdir(cwd)).includes("escape.txt"), false);
    for (const p of await walk(join(cwd, "out"))) assert.equal(p.endsWith("escape.txt"), false, p);
  });
});

test("max_bytes and max_files are lossless limits: the rows past them are listed, and the run is partial", async () => {
  await withCwd(async (cwd) => {
    await setup(cwd);
    const password = canaryText();
    const dir = await backup(cwd, "b", { password, entries: [1, 2, 3, 4].map((n) => ({ id: fid(n), path: `f${n}.bin`, size: 1000 })) });
    const ref = await secretFile(cwd, "pw.txt", password);
    const bytes = answer(await job(cwd, { backup: dir, password_ref: ref, max_bytes: 2500 }, "ob"));
    assert.equal(bytes.status, "partial");
    assert.deepEqual(bytes.counts, { decrypted_verified: 2, not_copied_max_bytes: 2 });
    const files = answer(await job(cwd, { backup: dir, password_ref: ref, max_files: 1 }, "of"));
    assert.deepEqual(files.counts, { decrypted_verified: 1, not_attempted_max_files: 3 });
    // The inline page is a prefix; the whole account is the file.
    const small = answer(await job(cwd, { backup: dir, password_ref: ref, limit: 2 }, "ol"));
    assert.equal(small.rows.length, 2);
    assert.equal(small.truncated, true);
    assert.equal(small.pages.rows.rows, 4);
  });
});

test("the child is ended at the tool's own clock, a stop signal ends the tool and the child with one JSON, and four runs at once do not disturb each other", async () => {
  await withCwd(async (cwd) => {
    await setup(cwd);
    const password = canaryText();
    const dir = await backup(cwd, "b", SPEC(password));
    const ref = await secretFile(cwd, "pw.txt", password);
    // The key derivation takes longer than the clock: the child is killed, the run says so within the limit, and no process is left.
    const began = Date.now();
    const slow = answer(await job(cwd, { backup: dir, password_ref: ref, max_seconds: 5 }, "slow", { STANDIN_OPEN_SLEEP: "60" }), false);
    assert.ok(Date.now() - began < 20000, `took ${Date.now() - began} ms`);
    assert.equal(slow.outcome, "failed");
    assert.match(slow.status_basis, /child ended before the decrypted Manifest\.db was written/);
    // A stop signal while the child works.
    await mkdir(join(cwd, "stopped"), { recursive: true });
    const child = spawn("python3", [TOOL], { cwd, env: { ...process.env, ...env(cwd, join(cwd, "stopped"), { STANDIN_OPEN_SLEEP: "60" }) } });
    const out: Buffer[] = [];
    child.stdout.on("data", (c: Buffer) => out.push(c));
    const exit = new Promise<number | null>((resolve) => child.on("close", (code, signal) => resolve(code ?? (signal ? 128 + 99 : null))));
    child.stdin.end(JSON.stringify({ backup: dir, password_ref: ref }));
    let pids: number[] = [];
    for (let i = 0; i < 100 && pids.length < 2; i++) {
      await new Promise((r) => setTimeout(r, 100));
      pids = await descendants(child.pid!);
    }
    assert.ok(pids.length >= 2, "the child started");
    child.kill("SIGTERM");
    assert.equal(await exit, 143);
    const last = JSON.parse(Buffer.concat(out).toString("utf8")) as Answer;
    assert.equal(last.status, "failed");
    assert.equal(last.interrupted, "SIGTERM");
    await new Promise((r) => setTimeout(r, 300));
    for (const pid of pids) assert.equal(alive(pid), false, `process ${pid} is still running after the stop`);
    // Four at once.
    const runs = await Promise.all([0, 1, 2, 3].map((i) => job(cwd, { backup: dir, password_ref: ref }, `four-${i}`)));
    for (const r of runs) assert.equal(answer(r).status, "complete");
  });
});

test("a second run in the same output directory writes a directory of its own and replaces nothing", async () => {
  await withCwd(async (cwd) => {
    await setup(cwd);
    const password = canaryText();
    const dir = await backup(cwd, "b", SPEC(password));
    const ref = await secretFile(cwd, "pw.txt", password);
    const first = answer(await job(cwd, { backup: dir, password_ref: ref }));
    const before = new Map<string, string>();
    const digest = async (p: string): Promise<string> => createHash("sha256").update(await readFile(p)).digest("hex");
    for (const p of await walk(join(cwd, "out"))) if ((await lstat(p)).isFile()) before.set(p, await digest(p));
    const second = answer(await job(cwd, { backup: dir, password_ref: ref }));
    assert.notEqual(first.decrypted.root, second.decrypted.root);
    assert.notEqual(first.pages.rows.all_results, second.pages.rows.all_results);
    for (const [p, d] of before) assert.equal(await digest(p), d, `${p} was replaced`);
    //
    const target = join(cwd, "out", first.decrypted.root.split("/out/")[1], fid(1).slice(0, 2), fid(1));
    assert.equal((await stat(target)).mode & 0o777, 0o600);
  });
});
