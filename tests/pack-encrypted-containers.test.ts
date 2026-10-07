/**
 * The encrypted-containers pack's tools, against fixtures built by the test
 * from the documented formats and never from a tool's own output: a BitLocker
 * recovery password is eight groups of six digits, each a multiple of eleven
 * whose quotient fits sixteen bits; a LUKS1 header is the on-disk layout of
 * the LUKS1 specification (a 592-byte header: 208 bytes of fixed fields, then
 * eight key slots of 48 bytes); a LUKS2 header is cryptsetup's
 * `struct luks2_hdr_disk` (4096 bytes: label at 24, UUID at 168).
 *
 * recovery_key_scan is the reference implementation of the secret-safe output
 * pattern (docs/packs.md, "Secrets and sensitive output"): what it prints and
 * what it writes are checked here for a value, a fragment, a shape and a
 * digest, in the answer and in every file the answer names.
 */
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { chmod, mkdir, readFile, readdir, stat, symlink, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { test } from "node:test";
import { ROOT, runPy, runPySnippet, withCwd } from "./tool-library-harness.ts";

const ENC = join(ROOT, "packs", "encrypted-containers", "tools");
const SCAN = join(ENC, "recovery_key_scan", "run.py");
const AGENT = { AGENT_ID: "s1" };

type Run = { code: number | null; stdout: string; stderr: string };

async function tool(script: string, cwd: string, args: unknown, env: Record<string, string> = {}, bin?: string): Promise<Run> {
  return runPy(script, cwd, args, bin, { ...AGENT, ...env });
}

function body<T>(out: Run): T {
  assert.equal(out.code, 0, out.stderr + out.stdout);
  assert.doesNotMatch(out.stderr, /Traceback/);
  return JSON.parse(out.stdout) as T;
}

function refused(out: Run): { error: string } {
  assert.notEqual(out.code, 0, out.stdout);
  assert.doesNotMatch(out.stderr, /Traceback/);
  return JSON.parse(out.stdout) as { error: string };
}

// --- recovery_key_scan --------------------------------------------------------

// A BitLocker recovery password: eight groups of six digits, each a multiple of
// 11 whose quotient is below 65536 (so no group is above 720885).
const QUOTIENTS = [4103, 51234, 7, 65535, 12345, 999, 40000, 20202];
const GROUPS = QUOTIENTS.map((q) => String(q * 11).padStart(6, "0"));
const KEY = GROUPS.join("-");
// The same password with its third group no longer a multiple of 11.
const BAD_GROUPS = GROUPS.map((g, i) => (i === 2 ? "000078" : g));
const BAD_KEY = BAD_GROUPS.join("-");

test("the fixture is a well-formed recovery password by the format's own rule", () => {
  for (const q of QUOTIENTS) assert.ok(q >= 0 && q < 65536);
  for (const g of GROUPS) {
    assert.equal(g.length, 6);
    assert.equal(Number(g) % 11, 0);
    assert.ok(Number(g) / 11 < 65536);
  }
  assert.notEqual(Number(BAD_GROUPS[2]) % 11, 0);
});

type Finding = {
  finding_id: string;
  file: string;
  offset: number;
  length: number;
  kind: string;
  encoding?: string;
  groups_passing_check?: number;
  passes_structure_check?: boolean;
  duplicate_of?: string;
  key_type?: string;
  parser: string;
};
type Exception = { path: string; status: string; reason: string; error?: string; bytes?: number; bytes_read?: number; bytes_unread?: number };
type Page = { matched: number; returned: number; truncated: boolean; all_results?: string };
type Scan = {
  findings: Finding[];
  finding_count: number;
  recovery_passwords: { found: number; pass_structure_check: number };
  files_worth_opening: { file: string; why: string }[];
  exceptions: Exception[];
  coverage: Record<string, number | boolean>;
  pages: { findings: Page; files_worth_opening: Page; exceptions: Page };
  secret_values: { requested: boolean; written: number; values_file: string | null; contains_secret_values: boolean };
  truncated: boolean;
  parser: string;
};

/** Everything that must carry no secret: the answer, and each file it names. */
async function everythingPrinted(cwd: string, stdout: string): Promise<string> {
  const answer = JSON.parse(stdout) as Scan;
  let all = stdout;
  for (const page of Object.values(answer.pages ?? {})) {
    if (page.all_results) all += "\n" + (await readFile(join(cwd, page.all_results), "utf8"));
  }
  return all;
}

function assertNoSecret(printed: string): void {
  for (const g of [...GROUPS, ...BAD_GROUPS]) assert.ok(!printed.includes(g), `a group of the value (${g}) is in the output`);
  assert.doesNotMatch(printed, /[0-9a-f]{64}/i, "a 64-hex digest is in the output");
  assert.doesNotMatch(printed, /\*{3,}/, "a masked shape is in the output");
  assert.doesNotMatch(printed, /"shape"|sha256_of_value/);
  // Not a fragment of the value either: no run of eight digits of it, in either spelling.
  const digits = GROUPS.join("");
  for (let i = 0; i + 8 <= digits.length; i++) assert.ok(!printed.includes(digits.slice(i, i + 8)), "a run of the value's digits is in the output");
}

async function plant(cwd: string): Promise<void> {
  await mkdir(join(cwd, "work", "ev", "Users", "alice"), { recursive: true });
  // As Windows' "save a recovery key" writes it: UTF-16LE text with a byte-order mark.
  const note = `BitLocker Drive Encryption recovery key\r\n\r\nRecovery Key ID: 11111111-2222-3333-4444-555555555555\r\n\r\n${KEY}\r\n`;
  await writeFile(join(cwd, "work", "ev", "Users", "alice", "BitLocker Recovery Key 1111.txt"), Buffer.from("﻿" + note, "utf16le"));
  await writeFile(join(cwd, "work", "ev", "notes.txt"), `my notes\nthe key is ${KEY} (copied)\n`);
}

test("recovery_key_scan locates a recovery password without a value, a fragment, a shape or a digest", async () => {
  // It printed the first two digits of each group (sixteen characters of the
  // secret) and an unsalted sha256 of the whole value, in an ordinary answer.
  await withCwd(async (cwd) => {
    await plant(cwd);
    const out = await tool(SCAN, cwd, { path: "work/ev" });
    const scan = body<Scan>(out);
    assertNoSecret(await everythingPrinted(cwd, out.stdout));
    assert.equal(scan.finding_count, 2);
    assert.equal(scan.recovery_passwords.found, 2);
    assert.equal(scan.recovery_passwords.pass_structure_check, 2);
    const byEncoding = Object.fromEntries(scan.findings.map((f) => [f.encoding ?? "", f]));
    // The text file: after "my notes\nthe key is " (20 bytes).
    assert.equal(byEncoding["ASCII"].offset, "my notes\nthe key is ".length);
    assert.equal(byEncoding["ASCII"].length, 55);
    // The UTF-16LE file: the position of the first digit in the file's bytes.
    const head = "﻿BitLocker Drive Encryption recovery key\r\n\r\nRecovery Key ID: 11111111-2222-3333-4444-555555555555\r\n\r\n";
    assert.equal(byEncoding["UTF-16LE"].offset, head.length * 2);
    assert.equal(byEncoding["UTF-16LE"].length, 55);
    for (const f of scan.findings) {
      assert.equal(f.kind, "BitLocker recovery password");
      assert.equal(f.groups_passing_check, 8);
      assert.equal(f.passes_structure_check, true);
      assert.match(f.finding_id, /^F\d{6}$/);
      assert.match(f.parser, /^recovery_key_scan\//);
    }
    // Where it was found is the answer: file, and the same value twice is said without saying the value.
    assert.match(byEncoding["UTF-16LE"].file, /BitLocker Recovery Key 1111\.txt$/);
    assert.equal(byEncoding["UTF-16LE"].duplicate_of === byEncoding["ASCII"].finding_id || byEncoding["ASCII"].duplicate_of === byEncoding["UTF-16LE"].finding_id, true);
    assert.equal(scan.secret_values.requested, false);
    assert.equal(scan.secret_values.written, 0);
    assert.equal(scan.secret_values.values_file, null);
  });
});

test("recovery_key_scan says a group that fails the multiple-of-eleven check, and calls the result a structure check", async () => {
  await withCwd(async (cwd) => {
    await mkdir(join(cwd, "work", "ev"), { recursive: true });
    await writeFile(join(cwd, "work", "ev", "partial.txt"), `x ${BAD_KEY} y\n`);
    const out = await tool(SCAN, cwd, { path: "work/ev" });
    const scan = body<Scan>(out);
    assert.equal(scan.findings.length, 1);
    assert.equal(scan.findings[0].groups_passing_check, 7);
    assert.equal(scan.findings[0].passes_structure_check, false);
    assert.equal(scan.recovery_passwords.found, 1);
    assert.equal(scan.recovery_passwords.pass_structure_check, 0);
    assert.doesNotMatch(out.stdout, /"complete":/, "the old name claimed more than a structure check shows");
    assertNoSecret(out.stdout);
  });
});

test("recovery_key_scan writes values only on request, only in a job, only under $OUT, mode 0600", async () => {
  await withCwd(async (cwd) => {
    await plant(cwd);
    // Outside a job there is no sealed output: the request is refused and nothing is written.
    const direct = refused(await tool(SCAN, cwd, { path: "work/ev", write_values: true }));
    assert.match(direct.error, /write_values/);
    assert.match(direct.error, /secret_output/);
    assert.deepEqual(await readdir(join(cwd, "work")), ["ev"]);

    const outDir = join(cwd, "out");
    await mkdir(outDir);
    const job = { JOB_ID: "j000001", OUT: outDir };
    // In a job, without the flag: still no value anywhere.
    const quiet = await tool(SCAN, cwd, { path: "work/ev" }, job);
    assert.deepEqual((await readdir(outDir)).filter((n) => n.includes("password")), []);
    assertNoSecret(await everythingPrinted(outDir, quiet.stdout).catch(() => quiet.stdout));

    const loud = await tool(SCAN, cwd, { path: "work/ev", write_values: true }, job);
    const scan = body<Scan>(loud);
    assert.equal(scan.secret_values.requested, true);
    assert.equal(scan.secret_values.written, 2);
    assert.equal(scan.secret_values.contains_secret_values, true);
    assert.equal(scan.secret_values.values_file, "store/jobs/j000001/out/recovery-passwords.jsonl");
    // The answer names the file and holds no value; the file holds the value, canonical, once per finding.
    assertNoSecret(loud.stdout);
    const file = join(outDir, "recovery-passwords.jsonl");
    assert.equal((await stat(file)).mode & 0o777, 0o600);
    const rows = (await readFile(file, "utf8")).trimEnd().split("\n").map((l) => JSON.parse(l) as { finding_id: string; value: string; file: string; offset: number });
    assert.equal(rows.length, 2);
    for (const r of rows) assert.equal(r.value, KEY);
    assert.deepEqual(rows.map((r) => r.finding_id).sort(), scan.findings.map((f) => f.finding_id).sort());
    // Nothing else under $OUT carries it: the metadata page, if any, is clean.
    for (const name of await readdir(outDir, { recursive: true })) {
      if (name === "recovery-passwords.jsonl") continue;
      const path = join(outDir, name);
      if ((await stat(path)).isFile()) assertNoSecret(await readFile(path, "utf8"));
    }
  });
});

test("recovery_key_scan keeps a finding that straddles its read window, once", async () => {
  // Streaming reads 4 MiB at a time; a value across the seam is found once,
  // at its true offset, and one past the seam is not lost.
  await withCwd(async (cwd) => {
    await mkdir(join(cwd, "work", "ev"), { recursive: true });
    const window = 1 << 22;
    const blob = Buffer.alloc(window + (1 << 20), 0x20);
    blob.write(KEY, window - 20, "latin1");
    blob.write(KEY, window + 5000, "latin1");
    blob.write(KEY, blob.length - 55, "latin1");
    await writeFile(join(cwd, "work", "ev", "big.bin"), blob);
    const out = await tool(SCAN, cwd, { path: "work/ev", max_bytes_per_file: 16 << 20 });
    const scan = body<Scan>(out);
    assert.deepEqual(scan.findings.map((f) => f.offset), [window - 20, window + 5000, blob.length - 55]);
    assert.equal(scan.coverage.files_partial, 0);
    assertNoSecret(out.stdout);
  });
});

test("recovery_key_scan lists a file it could only read a prefix of, with the bytes it did not read", async () => {
  await withCwd(async (cwd) => {
    await mkdir(join(cwd, "work", "ev"), { recursive: true });
    const blob = Buffer.alloc(10_000, 0x20);
    blob.write(KEY, 9000, "latin1");
    await writeFile(join(cwd, "work", "ev", "tail.bin"), blob);
    const scan = body<Scan>(await tool(SCAN, cwd, { path: "work/ev", max_bytes_per_file: 4096 }));
    assert.equal(scan.finding_count, 0, "the value sits past the budget");
    assert.equal(scan.coverage.files_partial, 1);
    const partial = scan.exceptions.find((e) => e.status === "partial");
    assert.ok(partial, JSON.stringify(scan.exceptions));
    assert.equal(partial.bytes, 10_000);
    assert.equal(partial.bytes_read, 4096);
    assert.equal(partial.bytes_unread, 10_000 - 4096);
    assert.equal(scan.coverage.max_bytes_per_file, 4096);
    assert.equal(scan.coverage.bytes_unread_in_partial_files, 10_000 - 4096);
  });
});

// Reads that fail with EIO, wherever the tool runs: root reads a mode-000 file,
// so the failure is made by the interpreter, not by chmod. unreadable.bin fails
// to open; flaky.bin gives its first read and fails the next, part way through.
const EIO_SITE = String.raw`
import builtins, errno, os
_real = builtins.open
class _Flaky:
    def __init__(self, fh):
        self._fh, self._n = fh, 0
    def read(self, n=-1):
        self._n += 1
        if self._n > 1:
            raise OSError(errno.EIO, "Input/output error")
        return self._fh.read(n)
    def __enter__(self):
        return self
    def __exit__(self, *exc):
        self._fh.close()
def _open(file, *args, **kwargs):
    name = os.fsdecode(file) if isinstance(file, (str, bytes, os.PathLike)) else ""
    if name.endswith("unreadable.bin"):
        raise OSError(errno.EIO, "Input/output error", name)
    if name.endswith("flaky.bin"):
        return _Flaky(_real(file, *args, **kwargs))
    return _real(file, *args, **kwargs)
builtins.open = _open
`;

test("recovery_key_scan names a file it could not read, and does not count it as read", async () => {
  // A read failure returned no findings, and the file was still counted in
  // files_scanned: the answer said "searched, nothing" for a file it never read.
  await withCwd(async (cwd) => {
    await mkdir(join(cwd, "work", "ev"), { recursive: true });
    await mkdir(join(cwd, "pystub"), { recursive: true });
    await writeFile(join(cwd, "pystub", "sitecustomize.py"), EIO_SITE);
    await writeFile(join(cwd, "work", "ev", "readable.txt"), "nothing here\n");
    await writeFile(join(cwd, "work", "ev", "unreadable.bin"), `${KEY}\n`);
    const scan = body<Scan>(await tool(SCAN, cwd, { path: "work/ev" }, { PYTHONPATH: join(cwd, "pystub") }));
    assert.equal(scan.coverage.files_attempted, 2);
    assert.equal(scan.coverage.files_read, 1);
    assert.equal(scan.coverage.files_failed, 1);
    const failed = scan.exceptions.filter((e) => e.status === "failed");
    assert.equal(failed.length, 1);
    assert.match(failed[0].path, /unreadable\.bin$/);
    assert.match(failed[0].error ?? "", /Input\/output error|EIO|\[Errno 5\]/);
    assert.equal(scan.finding_count, 0);
  });
});

test("recovery_key_scan keeps what it found before a read failed part way, and still calls the file failed", async () => {
  await withCwd(async (cwd) => {
    await mkdir(join(cwd, "work", "ev"), { recursive: true });
    await mkdir(join(cwd, "pystub"), { recursive: true });
    await writeFile(join(cwd, "pystub", "sitecustomize.py"), EIO_SITE);
    const text = `first ${KEY} last\n`;
    await writeFile(join(cwd, "work", "ev", "flaky.bin"), text);
    const out = await tool(SCAN, cwd, { path: "work/ev" }, { PYTHONPATH: join(cwd, "pystub") });
    const scan = body<Scan>(out);
    assert.equal(scan.finding_count, 1, "the value in the part that was read is still reported");
    assert.equal(scan.coverage.files_failed, 1);
    assert.equal(scan.coverage.files_read, 0);
    const failed = scan.exceptions.filter((e) => e.status === "failed");
    assert.equal(failed.length, 1);
    assert.equal(failed[0].bytes_read, text.length);
    assertNoSecret(out.stdout);
  });
});

test("recovery_key_scan names a file whose permissions refuse the read (where the user is not root)", async (t) => {
  if (process.getuid?.() === 0) return t.skip("root reads a mode-000 file; the read failure is covered by the EIO case");
  await withCwd(async (cwd) => {
    await mkdir(join(cwd, "work", "ev", "locked"), { recursive: true });
    await writeFile(join(cwd, "work", "ev", "secret.txt"), `${KEY}\n`);
    await chmod(join(cwd, "work", "ev", "secret.txt"), 0o000);
    await writeFile(join(cwd, "work", "ev", "locked", "inside.txt"), `${KEY}\n`);
    await chmod(join(cwd, "work", "ev", "locked"), 0o000);
    try {
      const scan = body<Scan>(await tool(SCAN, cwd, { path: "work/ev" }));
      assert.equal(scan.coverage.files_failed, 1);
      assert.equal(scan.coverage.directories_failed, 1);
      assert.equal(scan.coverage.files_read, 0);
      assert.deepEqual(scan.exceptions.map((e) => e.status).sort(), ["failed", "failed"]);
    } finally {
      await chmod(join(cwd, "work", "ev", "locked"), 0o755);
      await chmod(join(cwd, "work", "ev", "secret.txt"), 0o644);
    }
  });
});

test("recovery_key_scan reads regular files only, follows no link, and reports what it skipped and why", async () => {
  await withCwd(async (cwd) => {
    await mkdir(join(cwd, "work", "ev", "proc"), { recursive: true });
    await mkdir(join(cwd, "work", "ev", "Users", "bob", "dev"), { recursive: true });
    await writeFile(join(cwd, "work", "ev", "proc", "hidden.txt"), `${KEY}\n`);
    await writeFile(join(cwd, "work", "ev", "Users", "bob", "dev", "kept.txt"), `${KEY}\n`);
    await mkdir(join(cwd, "work", "outside"), { recursive: true });
    await writeFile(join(cwd, "work", "outside", "linked.txt"), `${KEY}\n`);
    await symlink(join(cwd, "work", "outside", "linked.txt"), join(cwd, "work", "ev", "file-link.txt"));
    await symlink(join(cwd, "work", "outside"), join(cwd, "work", "ev", "dir-link"));
    const out = await tool(SCAN, cwd, { path: "work/ev" });
    const scan = body<Scan>(out);
    // The directory named dev two levels down is evidence; a root-level proc is not scanned, and is said so.
    assert.deepEqual(scan.findings.map((f) => f.file.replace(/^.*work\/ev\//, "")), ["Users/bob/dev/kept.txt"]);
    const skipped = scan.exceptions.filter((e) => e.status === "skipped").map((e) => e.path.replace(/^.*work\/ev\//, "")).sort();
    assert.deepEqual(skipped, ["dir-link", "file-link.txt", "proc"]);
    for (const e of scan.exceptions.filter((x) => x.status === "skipped")) assert.ok(e.reason.length > 10);
    assert.equal(scan.coverage.files_attempted, 1);
    assertNoSecret(out.stdout);
  });
});

test("recovery_key_scan pages its findings and keeps the whole of them, still without a value", async () => {
  await withCwd(async (cwd) => {
    await mkdir(join(cwd, "work", "ev"), { recursive: true });
    for (let i = 0; i < 5; i++) await writeFile(join(cwd, "work", "ev", `n${i}.txt`), `k ${KEY}\n`);
    const out = await tool(SCAN, cwd, { path: "work/ev", limit: 2 });
    const scan = body<Scan>(out);
    assert.equal(scan.finding_count, 5);
    assert.equal(scan.findings.length, 2);
    assert.equal(scan.truncated, true);
    assert.equal(scan.pages.findings.matched, 5);
    const whole = (await readFile(join(cwd, scan.pages.findings.all_results!), "utf8")).trimEnd().split("\n");
    assert.equal(whole.length, 5);
    assertNoSecret(await everythingPrinted(cwd, out.stdout));
  });
});

test("recovery_key_scan reports a private key by type and place, never its body", async () => {
  await withCwd(async (cwd) => {
    await mkdir(join(cwd, "work", "ev"), { recursive: true });
    const pem = "-----BEGIN OPENSSH PRIVATE KEY-----\nb3BlbnNzaC1rZXktdjEAAAAABG5vbmU=\n-----END OPENSSH PRIVATE KEY-----\n";
    await writeFile(join(cwd, "work", "ev", "id_ed25519"), pem);
    const out = await tool(SCAN, cwd, { path: "work/ev" });
    const scan = body<Scan>(out);
    assert.equal(scan.findings.length, 1);
    assert.equal(scan.findings[0].kind, "private key");
    assert.equal(scan.findings[0].key_type, "OPENSSH PRIVATE KEY");
    assert.equal(scan.findings[0].offset, 0);
    assert.ok(!out.stdout.includes("b3BlbnNzaC1rZXktdjEAAAAABG5vbmU="));
    assert.equal(scan.files_worth_opening.length, 1);
  });
});

test("recovery_key_scan refuses what it cannot answer for, loudly", async () => {
  await withCwd(async (cwd) => {
    assert.match(refused(await tool(SCAN, cwd, {})).error, /path is required/);
    assert.match(refused(await tool(SCAN, cwd, { path: "work/missing" })).error, /no such file or directory/);
    assert.match(refused(await tool(SCAN, cwd, { path: "work", max_bytes_per_file: 10 })).error, /at least 1024/);
    assert.match(refused(await tool(SCAN, cwd, { path: "work", limit: 0 })).error, /limit/);
    assert.match(refused(await tool(SCAN, cwd, { path: "work", write_values: "yes" })).error, /write_values/);
  });
});

// --- crypto_id ----------------------------------------------------------------

const ID = join(ENC, "crypto_id", "run.py");

function field(buf: Buffer, at: number, text: string, width: number): void {
  Buffer.from(text, "latin1").copy(buf, at, 0, width);
}

/** A LUKS1 header as the LUKS1 on-disk specification lays it out: 592 bytes. */
function luks1Header(): Buffer {
  const h = Buffer.alloc(592);
  Buffer.from("LUKS\xba\xbe", "latin1").copy(h, 0);
  h.writeUInt16BE(1, 6);
  field(h, 8, "aes", 32); // cipher name
  field(h, 40, "xts-plain64", 32); // cipher mode
  field(h, 72, "sha256", 32); // hash spec
  h.writeUInt32BE(4096, 104); // payload offset, in sectors
  h.writeUInt32BE(64, 108); // key bytes
  for (let i = 0; i < 20; i++) h[112 + i] = 0x11; // master key digest
  for (let i = 0; i < 32; i++) h[132 + i] = 0x22; // master key digest salt
  h.writeUInt32BE(77777, 164); // master key digest iterations
  field(h, 168, "2f4a8e0c-1b5d-4c3a-9e7f-0a1b2c3d4e5f", 40); // uuid
  // Eight key slots of 48 bytes: active, iterations, salt[32], key material offset, stripes.
  const slots = [
    { active: 0x00ac71f3, iterations: 111111, offset: 8, stripes: 4000 },
    { active: 0x00ac71f3, iterations: 222222, offset: 264, stripes: 4000 },
    { active: 0x0000dead, iterations: 0, offset: 520, stripes: 4000 },
    { active: 0x00ac71f3, iterations: 333333, offset: 776, stripes: 4000 },
    { active: 0x0000dead, iterations: 0, offset: 1032, stripes: 4000 },
    { active: 0x0000dead, iterations: 0, offset: 1288, stripes: 4000 },
    { active: 0x0000dead, iterations: 0, offset: 1544, stripes: 4000 },
    { active: 0x0000dead, iterations: 0, offset: 1800, stripes: 4000 },
  ];
  slots.forEach((s, i) => {
    const at = 208 + i * 48;
    h.writeUInt32BE(s.active, at);
    h.writeUInt32BE(s.iterations, at + 4);
    for (let b = 0; b < 32; b++) h[at + 8 + b] = 0xa0 + i; // a salt that is not a number anyone would mistake
    h.writeUInt32BE(s.offset, at + 40);
    h.writeUInt32BE(s.stripes, at + 44);
  });
  return h;
}

/** A LUKS2 binary header as cryptsetup's `struct luks2_hdr_disk` lays it out: 4096 bytes. */
function luks2Header(version = 2): Buffer {
  const h = Buffer.alloc(4096);
  Buffer.from("LUKS\xba\xbe", "latin1").copy(h, 0);
  h.writeUInt16BE(version, 6);
  h.writeBigUInt64BE(16384n, 8); // hdr_size, with the JSON area
  h.writeBigUInt64BE(7n, 16); // seqid
  field(h, 24, "label", 48);
  field(h, 72, "sha256", 32); // checksum_alg
  for (let i = 0; i < 64; i++) h[104 + i] = 0x5a; // salt
  field(h, 168, "9b1d6a32-4c5e-4f70-8a91-b2c3d4e5f607", 40); // uuid
  field(h, 208, "subsys", 48);
  h.writeBigUInt64BE(0n, 256); // hdr_offset
  return h;
}

type Id = Record<string, unknown> & {
  scheme: string;
  version?: number;
  uuid?: string;
  label?: string;
  key_slots?: { slot: number; state: string; iterations: number; key_material_offset_sectors: number; stripes: number }[];
  enabled_slots?: number;
  supported?: boolean;
  header_problem?: string;
  next_reader?: string;
  not_determined?: string[];
  head_hex?: string;
};

test("crypto_id reads each LUKS1 key slot from the specification's field offsets", async () => {
  // It read four adjacent integers from the start of each 48-byte slot, so
  // `stripes` was taken from inside the salt (4000 came back as 2694881440).
  await withCwd(async (cwd) => {
    await writeFile(join(cwd, "work", "luks1.img"), luks1Header());
    const out = body<Id>(await tool(ID, cwd, { path: "work/luks1.img" }));
    assert.equal(out.scheme, "LUKS1");
    assert.equal(out.uuid, "2f4a8e0c-1b5d-4c3a-9e7f-0a1b2c3d4e5f");
    assert.equal(out.cipher, "aes");
    assert.equal(out.cipher_mode, "xts-plain64");
    assert.equal(out.hash, "sha256");
    assert.equal(out.key_bytes, 64);
    assert.equal(out.enabled_slots, 3);
    const slots = out.key_slots!;
    assert.equal(slots.length, 8);
    assert.deepEqual(slots.map((s) => s.state), ["enabled", "enabled", "disabled", "enabled", "disabled", "disabled", "disabled", "disabled"]);
    assert.deepEqual(slots.map((s) => s.stripes), Array(8).fill(4000));
    assert.equal(out.payload_offset_sectors, 4096);
    assert.deepEqual(slots.map((s) => s.key_material_offset_sectors), [8, 264, 520, 776, 1032, 1288, 1544, 1800]);
    assert.deepEqual(slots.slice(0, 4).map((s) => s.iterations), [111111, 222222, 0, 333333]);
    assert.ok(out.next_reader && /cryptsetup/.test(out.next_reader));
    assert.ok(Array.isArray(out.not_determined) && out.not_determined.length > 0);
  });
});

test("crypto_id says a LUKS1 header cut short is cut short, and reads no slot table from it", async () => {
  await withCwd(async (cwd) => {
    await writeFile(join(cwd, "work", "cut.img"), luks1Header().subarray(0, 300));
    const out = body<Id>(await tool(ID, cwd, { path: "work/cut.img" }));
    assert.equal(out.scheme, "LUKS1");
    assert.match(out.header_problem ?? "", /300 of 592 bytes/);
    assert.equal(out.key_slots, undefined);
    assert.equal(out.enabled_slots, undefined);
    assert.ok(out.not_determined?.some((n) => /key slot/i.test(n)));
    // A file that ends inside the version field is named too, not a struct.error.
    await writeFile(join(cwd, "work", "stub.img"), Buffer.from("LUKS\xba\xbe\x00", "latin1"));
    const stub = body<Id>(await tool(ID, cwd, { path: "work/stub.img" }));
    assert.match(stub.header_problem ?? "", /7 bytes/);
  });
});

test("crypto_id reads the LUKS2 UUID from byte 168 and the label from byte 24", async () => {
  // It returned bytes 24-63, the label, as the UUID.
  await withCwd(async (cwd) => {
    await writeFile(join(cwd, "work", "luks2.img"), luks2Header());
    const out = body<Id>(await tool(ID, cwd, { path: "work/luks2.img" }));
    assert.equal(out.scheme, "LUKS2");
    assert.equal(out.uuid, "9b1d6a32-4c5e-4f70-8a91-b2c3d4e5f607");
    assert.equal(out.label, "label");
    assert.equal(out.header_size_bytes, 16384);
    assert.equal(out.sequence_id, 7);
    assert.equal(out.checksum_alg, "sha256");
    assert.equal(out.key_slots, undefined, "the keyslots are JSON after the binary header: not read here");
    assert.ok(out.not_determined?.some((n) => /keyslot/i.test(n)));
    assert.match(out.next_reader ?? "", /cryptsetup luksDump/);
  });
});

test("crypto_id does not read a LUKS version it does not handle as LUKS2", async () => {
  await withCwd(async (cwd) => {
    await writeFile(join(cwd, "work", "luks3.img"), luks2Header(3));
    const out = body<Id>(await tool(ID, cwd, { path: "work/luks3.img" }));
    assert.equal(out.supported, false);
    assert.equal(out.version, 3);
    assert.match(out.scheme, /unsupported/i);
    assert.equal(out.uuid, undefined);
    assert.equal(out.label, undefined);
  });
});

test("crypto_id prints no raw bytes unless asked, bounds its sample, and says what it did not determine", async () => {
  await withCwd(async (cwd) => {
    // A file that could be a key file: crypto_id must not echo its first bytes.
    const key = Buffer.from("00112233445566778899aabbccddeeff102132435465768798a9bacbdcedfe0f", "hex");
    await writeFile(join(cwd, "work", "key.bin"), Buffer.concat([key, Buffer.alloc(2048)]));
    const plain = await tool(ID, cwd, { path: "work/key.bin" });
    assert.ok(!plain.stdout.includes(key.subarray(0, 32).toString("hex")), "head_hex is opt-in");
    assert.equal(body<Id>(plain).head_hex, undefined);
    const asked = body<Id>(await tool(ID, cwd, { path: "work/key.bin", include_head_hex: true }));
    assert.equal(asked.head_hex, key.toString("hex"));
    assert.match(String(asked.head_hex_note), /key material/i);
    // The entropy sample has an upper bound as well as a lower one.
    assert.match(refused(await tool(ID, cwd, { path: "work/key.bin", entropy_sample: 1 << 30 })).error, /at most/);
    assert.match(refused(await tool(ID, cwd, { path: "work/key.bin", entropy_sample: 10 })).error, /at least/);
    // A file no branch matches is not called unencrypted.
    await writeFile(join(cwd, "work", "text.txt"), "just some text\n".repeat(100));
    const text = body<Id>(await tool(ID, cwd, { path: "work/text.txt" }));
    assert.doesNotMatch(text.scheme, /^not encrypted/);
    assert.ok(text.not_determined?.some((n) => /encrypted/i.test(n)));
  });
});

// --- archive_probe ------------------------------------------------------------

const PROBE = join(ENC, "archive_probe", "run.py");

type ZipEntry = { name: string; data?: Buffer; flags?: number; method?: number; extra?: Buffer };

const DOS_DATE = ((2026 - 1980) << 9) | (3 << 5) | 14; // 2026-03-14
const DOS_TIME = (9 << 11) | (30 << 5) | (44 / 2); // 09:30:44

/** A ZIP built from the APPNOTE's record layouts: local headers, central directory, End Of Central Directory. */
function buildZip(entries: ZipEntry[], opts: { prefix?: Buffer; comment?: Buffer } = {}): Buffer {
  const parts: Buffer[] = [];
  const central: Buffer[] = [];
  let at = 0;
  for (const e of entries) {
    const name = Buffer.from(e.name, "utf8");
    const data = e.data ?? Buffer.from("x");
    const extra = e.extra ?? Buffer.alloc(0);
    const local = Buffer.alloc(30);
    local.writeUInt32LE(0x04034b50, 0);
    local.writeUInt16LE(20, 4);
    local.writeUInt16LE(e.flags ?? 0, 6);
    local.writeUInt16LE(e.method ?? 0, 8);
    local.writeUInt16LE(DOS_TIME, 10);
    local.writeUInt16LE(DOS_DATE, 12);
    local.writeUInt32LE(data.length, 18);
    local.writeUInt32LE(data.length, 22);
    local.writeUInt16LE(name.length, 26);
    local.writeUInt16LE(extra.length, 28);
    const record = Buffer.concat([local, name, extra, data]);
    const c = Buffer.alloc(46);
    c.writeUInt32LE(0x02014b50, 0);
    c.writeUInt16LE(20, 4);
    c.writeUInt16LE(20, 6);
    c.writeUInt16LE(e.flags ?? 0, 8);
    c.writeUInt16LE(e.method ?? 0, 10);
    c.writeUInt16LE(DOS_TIME, 12);
    c.writeUInt16LE(DOS_DATE, 14);
    c.writeUInt32LE(data.length, 20);
    c.writeUInt32LE(data.length, 24);
    c.writeUInt16LE(name.length, 28);
    c.writeUInt16LE(extra.length, 30);
    c.writeUInt32LE(at, 42);
    central.push(Buffer.concat([c, name, extra]));
    parts.push(record);
    at += record.length;
  }
  const cd = Buffer.concat(central);
  const comment = opts.comment ?? Buffer.alloc(0);
  const eocd = Buffer.alloc(22);
  eocd.writeUInt32LE(0x06054b50, 0);
  eocd.writeUInt16LE(entries.length, 8);
  eocd.writeUInt16LE(entries.length, 10);
  eocd.writeUInt32LE(cd.length, 12);
  eocd.writeUInt32LE(at, 16);
  eocd.writeUInt16LE(comment.length, 20);
  return Buffer.concat([opts.prefix ?? Buffer.alloc(0), ...parts, cd, eocd, comment]);
}

function extraField(id: number, data: Buffer): Buffer {
  const h = Buffer.alloc(4);
  h.writeUInt16LE(id, 0);
  h.writeUInt16LE(data.length, 2);
  return Buffer.concat([h, data]);
}

const UNIX_TIME = Math.floor(Date.UTC(2026, 2, 14, 9, 30, 45) / 1000);
const NTFS_FILETIME = (BigInt(UNIX_TIME) + 11644473600n) * 10_000_000n + 1234567n;

function aesExtra(strength: number, version = 2): Buffer {
  const d = Buffer.alloc(7);
  d.writeUInt16LE(version, 0);
  d.write("AE", 2, "latin1");
  d[4] = strength;
  d.writeUInt16LE(8, 5);
  return extraField(0x9901, d);
}

function utExtra(): Buffer {
  const d = Buffer.alloc(5);
  d[0] = 1;
  d.writeInt32LE(UNIX_TIME, 1);
  return extraField(0x5455, d);
}

function ntfsExtra(): Buffer {
  const d = Buffer.alloc(32);
  d.writeUInt16LE(1, 4); // tag 1
  d.writeUInt16LE(24, 6);
  d.writeBigUInt64LE(NTFS_FILETIME, 8);
  d.writeBigUInt64LE(NTFS_FILETIME, 16);
  d.writeBigUInt64LE(NTFS_FILETIME, 24);
  return extraField(0x000a, d);
}

type Probe = Record<string, any>;

test("archive_probe reads a ZIP structurally: each member's scheme, the AES extra field, DOS time raw and unzoned", async () => {
  await withCwd(async (cwd) => {
    await writeFile(join(cwd, "work", "mixed.zip"), buildZip([
      { name: "plain.txt" },
      { name: "legacy.bin", flags: 0x0001, method: 8 },
      { name: "aes.bin", flags: 0x0001, method: 99, extra: aesExtra(3, 2) },
      { name: "aes128.bin", flags: 0x0001, method: 99, extra: aesExtra(1, 1) },
      { name: "strong.bin", flags: 0x0041, method: 8 },
      { name: "timed.txt", extra: Buffer.concat([utExtra(), ntfsExtra()]) },
      { name: "unix-time.txt", extra: utExtra() },
    ]));
    const out = body<Probe>(await tool(PROBE, cwd, { path: "work/mixed.zip" }));
    assert.equal(out.container, "ZIP");
    assert.equal(out.entry_count, 7);
    assert.equal(out.entry_count_matches_declared, true);
    assert.equal(out.encrypted_entries, 4);
    assert.equal(out.protected, true);
    const byName = Object.fromEntries((out.entries as Probe[]).map((e) => [e.name, e]));
    assert.equal(byName["plain.txt"].encrypted, false);
    assert.equal(byName["legacy.bin"].scheme, "ZipCrypto (legacy, weak)");
    assert.equal(byName["aes.bin"].scheme, "WinZip AES-256 (AE-2)");
    assert.deepEqual(byName["aes.bin"].aes, { ae_version: 2, strength_bits: 256, method: 8 });
    assert.equal(byName["aes128.bin"].scheme, "WinZip AES-128 (AE-1)");
    assert.equal(byName["strong.bin"].scheme, "strong encryption");
    // The DOS time is the archiving machine's local clock with no zone, and its raw words are kept.
    assert.equal(byName["plain.txt"].modified, "2026-03-14T09:30:44");
    assert.equal(byName["plain.txt"].timezone_unknown, true);
    assert.equal(byName["plain.txt"].modified_raw, `dos_date=0x${DOS_DATE.toString(16).padStart(4, "0")} dos_time=0x${DOS_TIME.toString(16).padStart(4, "0")}`);
    assert.equal(byName["plain.txt"].modified_utc, undefined);
    // A recorded UTC time is a separate field, with its source and resolution; NTFS keeps its 100 ns fraction.
    assert.equal(byName["unix-time.txt"].modified_utc, "2026-03-14T09:30:45Z");
    assert.match(byName["unix-time.txt"].modified_utc_source, /0x5455/);
    assert.equal(byName["timed.txt"].modified_utc, "2026-03-14T09:30:45.1234567Z");
    assert.match(byName["timed.txt"].modified_utc_source, /0x000a/);
    assert.match(out.time_note, /no zone/);
    assert.equal(out.entries[0].header_offset, 0);
  });
});

test("archive_probe reads an empty ZIP and a self-extracting ZIP, found from the end of the file", async () => {
  // It dispatched on a local file header at byte zero, so an empty archive
  // and any archive behind an executable stub were "not a container".
  await withCwd(async (cwd) => {
    const empty = Buffer.alloc(22);
    empty.writeUInt32LE(0x06054b50, 0);
    await writeFile(join(cwd, "work", "empty.zip"), empty);
    const e = body<Probe>(await tool(PROBE, cwd, { path: "work/empty.zip" }));
    assert.equal(e.container, "ZIP");
    assert.equal(e.entry_count, 0);
    assert.equal(e.protected, false);

    const stub = Buffer.concat([Buffer.from("MZ"), Buffer.alloc(4094, 0x90)]);
    await writeFile(join(cwd, "work", "sfx.exe"), buildZip([{ name: "inside.docx" }, { name: "locked.bin", flags: 1, method: 8 }], { prefix: stub }));
    const s = body<Probe>(await tool(PROBE, cwd, { path: "work/sfx.exe" }));
    assert.equal(s.container, "ZIP");
    assert.deepEqual((s.entries as Probe[]).map((x) => x.name), ["inside.docx", "locked.bin"]);
    assert.equal(s.protected, true);
  });
});

test("archive_probe does not load a central directory above its budget, and says what it did not list", async () => {
  await withCwd(async (cwd) => {
    const eocd = Buffer.alloc(22);
    eocd.writeUInt32LE(0x06054b50, 0);
    eocd.writeUInt16LE(0xfffe, 8);
    eocd.writeUInt16LE(0xfffe, 10);
    eocd.writeUInt32LE(1 << 30, 12); // a central directory of 1 GiB in a file of 22 bytes
    await writeFile(join(cwd, "work", "huge.zip"), eocd);
    const out = body<Probe>(await tool(PROBE, cwd, { path: "work/huge.zip" }));
    assert.equal(out.listing, "not attempted");
    assert.equal(out.partial, true);
    assert.equal(out.protected, null);
    assert.equal(out.central_directory_bytes, 1 << 30);
    assert.match(out.reason, /max_metadata_bytes/);
    // A truncated archive (no End Of Central Directory) is named, not "not a container".
    await writeFile(join(cwd, "work", "cut.zip"), buildZip([{ name: "a.txt" }]).subarray(0, 40));
    const cut = body<Probe>(await tool(PROBE, cwd, { path: "work/cut.zip" }));
    assert.equal(cut.container, "ZIP");
    assert.equal(cut.listing, "failed");
    assert.equal(cut.protected, null);
  });
});

const PDF_OLD_REVISION = [
  "%PDF-1.7\n",
  "1 0 obj\n<< /Type /Catalog >>\nendobj\n",
  "5 0 obj\n<< /Filter /Standard /V 2 /R 3 /P -44 >>\nendobj\n",
  "trailer\n<< /Root 1 0 R /Encrypt 5 0 R >>\nstartxref\n10\n%%EOF\n",
  // An incremental update: its trailer names no /Encrypt and a reader decides what that means.
  "trailer\n<< /Root 1 0 R /Prev 10 >>\nstartxref\n300\n%%EOF\n",
].join("");

test("archive_probe never turns a byte search over a PDF into a verdict", async () => {
  // It said "opens with nothing" for a PDF without the marker, "protected" for
  // one with the marker anywhere, and told the reader not to report a file that
  // opens with an empty password as protected: a file can be encrypted and
  // still open with an empty user password.
  await withCwd(async (cwd) => {
    await writeFile(join(cwd, "work", "revisions.pdf"), PDF_OLD_REVISION);
    const out = await tool(PROBE, cwd, { path: "work/revisions.pdf" });
    const probe = body<Probe>(out);
    assert.match(probe.protection, /^heuristic/);
    assert.equal(probe.protected, null);
    assert.equal(probe.encrypt_marker.found, true);
    assert.equal(probe.encrypt_marker.count, 1);
    assert.deepEqual(probe.encrypt_marker.first_offsets, [PDF_OLD_REVISION.indexOf("/Encrypt")]);
    assert.ok(probe.not_determined.some((n: string) => /current trailer/.test(n)));
    assert.match(probe.next_reader, /not available yet/);
    assert.doesNotMatch(out.stdout, /opens with nothing|not protected|not encrypted|do not report/i);
    // The first /V /R /P are offered only as unresolved hints.
    assert.equal(probe.unresolved_hints.r, 3);
    assert.match(probe.unresolved_hints.note, /not read through the trailer/);

    await writeFile(join(cwd, "work", "plain.pdf"), "%PDF-1.4\n1 0 obj\n<< /Type /Catalog >>\nendobj\ntrailer\n<< /Root 1 0 R >>\n%%EOF\n");
    const plain = await tool(PROBE, cwd, { path: "work/plain.pdf" });
    const p = body<Probe>(plain);
    assert.equal(p.encrypt_marker.found, false);
    assert.equal(p.protected, null, "no marker is not a finding that the file is unencrypted");
    assert.doesNotMatch(plain.stdout, /opens with nothing|not protected|not encrypted/i);

    // A marker in the trailer of a file past 8 MiB is found, with its offset.
    const big = Buffer.concat([Buffer.from("%PDF-1.7\n"), Buffer.alloc(9 * 1024 * 1024, 0x20), Buffer.from("\ntrailer\n<< /Encrypt 5 0 R >>\n%%EOF\n")]);
    await writeFile(join(cwd, "work", "big.pdf"), big);
    const b = body<Probe>(await tool(PROBE, cwd, { path: "work/big.pdf" }));
    assert.deepEqual(b.encrypt_marker.first_offsets, [big.indexOf("/Encrypt")]);
  });
});

const OLE_MAGIC = Buffer.from([0xd0, 0xcf, 0x11, 0xe0, 0xa1, 0xb1, 0x1a, 0xe1]);

test("archive_probe reports Office markers as markers, and never says a document is not encrypted", async () => {
  // It said "not encrypted" when no EncryptionInfo string was found, and a
  // binary Word file with legacy encryption has none. The "legacy" fixture is
  // NOT a real encrypted .doc: it is a compound-file header with the Word
  // stream names and no marker, so it proves the tool no longer turns the
  // absence of a marker into a verdict, and nothing about the binary format.
  // (A real FIB, with fEncrypted 0x0100 at FIB offset 0x0A, is for the structural reader.)
  await withCwd(async (cwd) => {
    const dirEntry = (name: string) => Buffer.concat([Buffer.from(name + "\u0000", "utf16le"), Buffer.alloc(64 - (name.length + 1) * 2)]);
    const noMarker = Buffer.concat([OLE_MAGIC, Buffer.alloc(504), dirEntry("WordDocument"), dirEntry("1Table")]);
    await writeFile(join(cwd, "work", "no-marker.doc"), noMarker);
    const out = await tool(PROBE, cwd, { path: "work/no-marker.doc" });
    const probe = body<Probe>(out);
    assert.equal(probe.container, "OLE compound file");
    assert.equal(probe.protected, null);
    assert.match(probe.protection, /^heuristic/);
    assert.deepEqual(probe.markers_found, []);
    assert.ok(probe.not_determined.some((n: string) => /binary Word, Excel and PowerPoint/.test(n)));
    assert.doesNotMatch(out.stdout, /this document is not encrypted|No EncryptionInfo stream/);
    assert.match(probe.note, /does not mean the document is not encrypted/);

    const modern = Buffer.concat([OLE_MAGIC, Buffer.alloc(504), dirEntry("EncryptionInfo"), dirEntry("EncryptedPackage")]);
    await writeFile(join(cwd, "work", "modern.docx"), modern);
    const m = body<Probe>(await tool(PROBE, cwd, { path: "work/modern.docx" }));
    assert.deepEqual(m.markers_found.map((x: Probe) => [x.name, x.encoding, x.first_offsets[0]]),
      [["EncryptionInfo", "UTF-16LE", 512], ["EncryptedPackage", "UTF-16LE", 576]]);
    assert.equal(m.protected, null, "a marker is a lead for a structural reader, not a verdict");
  });
});

test("archive_probe identifies a RAR and leaves its protection undetermined", async () => {
  await withCwd(async (cwd) => {
    await writeFile(join(cwd, "work", "a.rar"), Buffer.concat([Buffer.from([0x52, 0x61, 0x72, 0x21, 0x1a, 0x07, 0x01, 0x00]), Buffer.alloc(64)]));
    const out = await tool(PROBE, cwd, { path: "work/a.rar" });
    const probe = body<Probe>(out);
    assert.equal(probe.container, "RAR5");
    assert.equal(probe.protected, null);
    assert.equal(probe.listing, "not attempted");
    assert.doesNotMatch(out.stdout, /enough to verify a password/);
  });
});

test("archive_probe refuses a file that is no container without printing its bytes", async () => {
  await withCwd(async (cwd) => {
    await writeFile(join(cwd, "work", "key.bin"), Buffer.from("00112233445566778899aabbccddeeff", "hex"));
    const out = await tool(PROBE, cwd, { path: "work/key.bin" });
    const err = refused(out);
    assert.match(err.error, /not a container this tool reads/);
    assert.doesNotMatch(out.stdout, /00112233|head_hex/);
  });
});

// --- archive_probe: 7-Zip ------------------------------------------------------

// Real 7-Zip 26.00 archives (`7zz a`, -mhe=on for the header-encrypted one), and what `7zz l -slt -y -p<dummy>` printed for each.
const SEVEN = {
  none: {
    archive: "N3q8ryccAAQqIBjMhQAAAAAAAAAgAAAAAAAAAAwa/mQBACJhbHBoYSBjb250ZW50CmJyYXZvIGNvbnRlbnQgbG9uZ2VyCgAAAIEzB64P0Hif/J8/R0EFh4ajQDx9Fv5JCP11Nh2Qet7V2ytx1YB2ubBAsByu1ktrICmll2FWDKK4gAdOAWHa6KsOzwPr7CRChc52YS9079Rgw4FB2mMiFaIBIAAAFwYnAQleAAcLAQABIwMBAQVdABAAAAxuCgFo2ORNAAA=",
    stdout: "\n7-Zip (z) 26.00 (arm64) : Copyright (c) 1999-2026 Igor Pavlov : 2026-02-12\n 64-bit arm_v:8.5-A locale=C.UTF-8 Threads:16 OPEN_MAX:1048576, ASM\n\nScanning the drive for archives:\n1 file, 197 bytes (1 KiB)\n\nListing archive: none.7z\n\n--\nPath = none.7z\nType = 7z\nPhysical Size = 197\nHeaders Size = 158\nMethod = LZMA2:12\nSolid = +\nBlocks = 1\n\n----------\nPath = a.txt\nSize = 14\nPacked Size = 39\nModified = 2026-10-07 01:56:54.3793106\nAttributes = A -rw-r--r--\nCRC = DEA868DF\nEncrypted = -\nMethod = LZMA2:12\nBlock = 0\n\nPath = b b.txt\nSize = 21\nPacked Size = \nModified = 2026-10-07 01:56:54.3843867\nAttributes = A -rw-r--r--\nCRC = 7C874C5B\nEncrypted = -\nMethod = LZMA2:12\nBlock = 0\n\n",
    stderr: "",
    code: 0,
  },
  plain: {
    archive: "N3q8ryccAATC2VWuqgAAAAAAAAAhAAAAAAAAAMPoJob1ch0aXtgMq+vhRuz8luFWVWLSD54FFKqaXSxRFMerbK0NfTCZDA5ayNiYvRJzsvkAAIEzB64P0QDUPKCKabDjxAD69FhUvaOuLav8QBpoQK3j7DicVKAUgsIPSnIYO8SO8EV57iMcaFQLhoyXsSrC2KNNkQHo7n03rowtwinLyqJzarVHjUn4SvB+I+tk30FvZFC03gBBpprgcamc133Vl7YymHZgnQAAABcGMAEJegAHCwEAASMDAQEFXQAQAAAMgI4KAR1BaiUAAA==",
    stdout: "\n7-Zip (z) 26.00 (arm64) : Copyright (c) 1999-2026 Igor Pavlov : 2026-02-12\n 64-bit arm_v:8.5-A locale=C.UTF-8 Threads:16 OPEN_MAX:1048576, ASM\n\nScanning the drive for archives:\n1 file, 235 bytes (1 KiB)\n\nListing archive: plain.7z\n\n--\nPath = plain.7z\nType = 7z\nPhysical Size = 235\nHeaders Size = 187\nMethod = LZMA2:12 7zAES\nSolid = +\nBlocks = 1\n\n----------\nPath = a.txt\nSize = 14\nPacked Size = 48\nModified = 2026-10-07 01:56:54.3793106\nAttributes = A -rw-r--r--\nCRC = DEA868DF\nEncrypted = +\nMethod = LZMA2:12 7zAES:19\nBlock = 0\n\nPath = b b.txt\nSize = 21\nPacked Size = \nModified = 2026-10-07 01:56:54.3843867\nAttributes = A -rw-r--r--\nCRC = 7C874C5B\nEncrypted = +\nMethod = LZMA2:12 7zAES:19\nBlock = 0\n\n",
    stderr: "",
    code: 0,
  },
  hdr: {
    archive: "N3q8ryccAARMd/ycsAAAAAAAAAA9AAAAAAAAAHwzuGJJgg7Aqtf8mOXD8Es0DzqFsKWhqD1GF4KY8vXKdGs9zXEyU+d3AX4sKlDObdj4H3bu3dSI3IA5OJnm+HrPMureT2KT7/IXt9jEeiFbUiPpEqQEhf9EDmvWTdAKBNROWDrZlnktblzTeYpxE8kC7kQkkHpPvvq8d3GU/SyFY1lTRYm49yrzjw1Kmd4CWTASrQ66hfwulrHP/bgG53DcBNaYKnUP4aUmUy96siU29G11fhcGMAEJgIAABwsBAAIkBvEHARJTD0FjP7qaeY1bH7RuLJIUM24jAwEBBV0AEAAAAQAMeoCOCgG3zPbiAAA=",
    stdout: "\n7-Zip (z) 26.00 (arm64) : Copyright (c) 1999-2026 Igor Pavlov : 2026-02-12\n 64-bit arm_v:8.5-A locale=C.UTF-8 Threads:16 OPEN_MAX:1048576, ASM\n\nScanning the drive for archives:\n1 file, 269 bytes (1 KiB)\n\nListing archive: hdr.7z\n\n\nErrors: 1\n",
    stderr: "\nERROR: hdr.7z : Cannot open encrypted archive. Wrong password?\n\n\n",
    code: 2,
  },
} as const;

/** A 7z stand-in on PATH that replays what the real 7-Zip printed for the three archives, and records its arguments. */
async function sevenStub(bin: string): Promise<void> {
  for (const [name, v] of Object.entries(SEVEN)) {
    await writeFile(join(bin, `${name}.stdout`), v.stdout);
    await writeFile(join(bin, `${name}.stderr`), v.stderr);
  }
  const script = `#!/bin/sh
here="$(dirname "$0")"
printf '%s\\n' "$@" > "$here/7z-args.txt"
last=""
for a in "$@"; do last="$a"; done
name="$(basename "$last" .7z)"
case "$name" in
  none|plain|hdr)
    cat "$here/$name.stdout"
    cat "$here/$name.stderr" >&2
    case "$name" in hdr) exit 2 ;; *) exit 0 ;; esac ;;
  *)
    echo "ERROR: $last : Cannot open the file as archive" >&2
    echo "Errors: 1"
    exit 2 ;;
esac
`;
  await writeFile(join(bin, "7z"), script, "utf8");
  await chmod(join(bin, "7z"), 0o755);
}

/** A sitecustomize that makes shutil.which find no 7-Zip program, wherever the test runs. */
const NO_7Z_SITE = String.raw`
import shutil
_which = shutil.which
shutil.which = lambda cmd, *a, **k: None if str(cmd) in ("7z", "7zz", "7za") else _which(cmd, *a, **k)
`;

async function withoutSeven(cwd: string): Promise<Record<string, string>> {
  await mkdir(join(cwd, "nosite"), { recursive: true });
  await writeFile(join(cwd, "nosite", "sitecustomize.py"), NO_7Z_SITE);
  return { PYTHONPATH: join(cwd, "nosite") };
}

async function putSeven(cwd: string): Promise<void> {
  for (const [name, v] of Object.entries(SEVEN)) await writeFile(join(cwd, "work", `${name}.7z`), Buffer.from(v.archive, "base64"));
}

test("archive_probe lists a 7-Zip archive through 7z: members, each one's flag, header not encrypted", async () => {
  await withCwd(async (cwd, bin) => {
    await sevenStub(bin);
    await putSeven(cwd);
    const out = body<Probe>(await tool(PROBE, cwd, { path: "work/plain.7z" }, {}, bin));
    assert.equal(out.container, "7-Zip");
    assert.equal(out.listing.status, "listed");
    assert.equal(out.names_readable, true);
    assert.equal(out.header_encrypted, false);
    assert.equal(out.payload_encrypted, true);
    assert.equal(out.protected, true);
    assert.deepEqual((out.members as Probe[]).map((m) => [m.name, m.bytes, m.encrypted]), [["a.txt", 14, true], ["b b.txt", 21, true]]);
    assert.equal(out.members[0].timezone_unknown, true);
    assert.equal(out.members[0].modified_as_printed, "2026-10-07 01:56:54.3793106");
    // The structure of the real archive: start header and header checksums hold.
    assert.equal(out.start_header.crc_ok, true);
    assert.equal(out.start_header.header_crc_ok, true);
    // 7z was run without a password prompt and with a literal that is no secret.
    const args = (await readFile(join(bin, "7z-args.txt"), "utf8")).trimEnd().split("\n");
    assert.deepEqual(args.slice(0, 3), ["l", "-slt", "-y"]);
    assert.match(args[3], /^-pdfirswarm-no-password$/);
    assert.equal(args[4], "--");
    assert.equal(args[5], "work/plain.7z");

    const none = body<Probe>(await tool(PROBE, cwd, { path: "work/none.7z" }, {}, bin));
    assert.equal(none.payload_encrypted, false);
    assert.equal(none.protected, false);
    assert.equal(none.names_readable, true);
  });
});

test("archive_probe says a 7-Zip archive's header is encrypted when 7z cannot open it without a password", async () => {
  await withCwd(async (cwd, bin) => {
    await sevenStub(bin);
    await putSeven(cwd);
    const out = body<Probe>(await tool(PROBE, cwd, { path: "work/hdr.7z" }, {}, bin));
    assert.equal(out.listing.status, "header_encrypted");
    assert.equal(out.listing.exit_code, 2);
    assert.equal(out.header_encrypted, true);
    assert.equal(out.names_readable, false);
    assert.equal(out.protected, true);
    assert.equal(out.payload_encrypted, null, "whether the data is encrypted is not read from an unlistable archive");
    assert.equal(out.members, undefined);
  });
});

test("archive_probe keeps its byte search as a hint when 7z is absent, and gives no verdict from it", async () => {
  await withCwd(async (cwd) => {
    await putSeven(cwd);
    const env = await withoutSeven(cwd);
    const hdr = body<Probe>(await tool(PROBE, cwd, { path: "work/hdr.7z" }, env));
    assert.equal(hdr.listing.status, "unavailable");
    assert.equal(hdr.protected, null);
    assert.equal(hdr.names_readable, null);
    assert.match(hdr.protection, /^heuristic/);
    assert.equal(hdr.hints.header_kind, "encoded");
    assert.equal(hdr.hints.header_encrypted, true);
    // An archive whose data is encrypted behind a readable header shows no AES coder in the header's own
    // coder list: the hint says "no", and that is why it is only a hint.
    const plain = body<Probe>(await tool(PROBE, cwd, { path: "work/plain.7z" }, env));
    assert.equal(plain.hints.header_encrypted, false);
    assert.equal(plain.protected, null);
    assert.equal(plain.payload_encrypted, undefined);
    assert.match(plain.header_strings_note, /not a member list/);
  });
});

test("archive_probe reports 7z that fails on a file as a failed listing, never as a clean one", async () => {
  await withCwd(async (cwd, bin) => {
    await sevenStub(bin);
    const fake = Buffer.alloc(64);
    Buffer.from([0x37, 0x7a, 0xbc, 0xaf, 0x27, 0x1c, 0x00, 0x04]).copy(fake, 0);
    await writeFile(join(cwd, "work", "fake.7z"), fake);
    const out = body<Probe>(await tool(PROBE, cwd, { path: "work/fake.7z" }, {}, bin));
    assert.equal(out.listing.status, "failed");
    assert.equal(out.listing.exit_code, 2);
    assert.equal(out.protected, null);
    assert.equal(out.start_header.crc_ok, false, "the start header's checksum does not hold");
  });
});

test("archive_probe bounds what it searches in a 7-Zip header and names a header placed past the end", async () => {
  await withCwd(async (cwd) => {
    const env = await withoutSeven(cwd);
    const sevenZip = (header: Buffer): Buffer => {
      const packed = Buffer.from("packed-stream-bytes");
      const start = Buffer.alloc(32);
      Buffer.from([0x37, 0x7a, 0xbc, 0xaf, 0x27, 0x1c, 0x00, 0x04]).copy(start, 0);
      start.writeBigUInt64LE(BigInt(packed.length), 12);
      start.writeBigUInt64LE(BigInt(header.length), 20);
      return Buffer.concat([start, packed, header]);
    };
    const header = Buffer.concat([Buffer.from([0x01]), Buffer.alloc(20000, 0x41)]);
    await writeFile(join(cwd, "work", "big-header.7z"), sevenZip(header));
    const big = body<Probe>(await tool(PROBE, cwd, { path: "work/big-header.7z", max_metadata_bytes: 4096 }, env));
    assert.equal(big.start_header.header_bytes, header.length);
    assert.equal(big.start_header.search_truncated, true);
    assert.match(big.start_header.search_note, /first 4096/);
    const whole = sevenZip(header);
    await writeFile(join(cwd, "work", "short.7z"), whole.subarray(0, whole.length - 10));
    const short = body<Probe>(await tool(PROBE, cwd, { path: "work/short.7z" }, env));
    assert.match(short.header_problem, /past the end of the file/);
    assert.equal(short.names_readable, null);
    assert.equal(short.protected, null);
    assert.match(refused(await tool(PROBE, cwd, { path: "work/short.7z", max_metadata_bytes: 10 })).error, /at least 4096/);
  });
});

test("archive_probe agrees with a real 7-Zip on the three archives, where one is installed", async (t) => {
  // Only an upstream 7zz: a p7zip `7z` (which a CI image may carry) prints other messages, and
  // this test was captured against 7-Zip 26.00. The stub tests above cover the rest.
  const real = spawnSync("which", ["7zz"], { encoding: "utf8" }).stdout.trim();
  if (!real) return t.skip("no upstream 7zz on PATH; the stub replays what 7-Zip 26.00 printed");
  await withCwd(async (cwd, bin) => {
    await symlink(real, join(bin, "7z"));
    await putSeven(cwd);
    const got = async (name: string) => body<Probe>(await tool(PROBE, cwd, { path: `work/${name}.7z` }, {}, bin));
    const plain = await got("plain");
    assert.deepEqual([plain.listing.status, plain.header_encrypted, plain.payload_encrypted, plain.names_readable], ["listed", false, true, true]);
    const hdr = await got("hdr");
    assert.deepEqual([hdr.listing.status, hdr.header_encrypted, hdr.protected, hdr.names_readable], ["header_encrypted", true, true, false]);
    const none = await got("none");
    assert.deepEqual([none.listing.status, none.payload_encrypted, none.protected], ["listed", false, false]);
  });
});

// --- review follow-ups ---------------------------------------------------------

/** The rows of the file a page names: the whole result, in order. */
async function allRows<T>(cwd: string, page: Page): Promise<T[]> {
  assert.ok(page.all_results, "the output must name the file holding the whole result");
  const text = await readFile(join(cwd, page.all_results), "utf8");
  return text.trimEnd().split("\n").map((line) => JSON.parse(line) as T);
}

test("crypto_id does not read a file that merely starts with CS as Apple Core Storage", async () => {
  // It tested the first two bytes of the file, so any CSV or text file that
  // began with "CS" was called Core Storage. Only the signature at offset 88 counts.
  await withCwd(async (cwd) => {
    await writeFile(join(cwd, "work", "data.csv"), "CSV,name,value\n".repeat(200));
    await writeFile(join(cwd, "work", "cs-zeros.bin"), Buffer.concat([Buffer.from("CS"), Buffer.alloc(2000)]));
    for (const name of ["data.csv", "cs-zeros.bin"]) {
      const out = body<Id>(await tool(ID, cwd, { path: `work/${name}` }));
      assert.equal(out.scheme, "no scheme this tool recognises", name);
    }
    // A header with the signature at offset 88 is still read as Core Storage, and says where it saw it.
    const header = Buffer.alloc(4096);
    Buffer.from("CS", "latin1").copy(header, 88);
    await writeFile(join(cwd, "work", "cs.img"), header);
    const cs = body<Id>(await tool(ID, cwd, { path: "work/cs.img" }));
    assert.match(cs.scheme, /Core Storage/);
    assert.match(String(cs.basis), /Core Storage signature at offset 88/);
  });
});

test("crypto_id says an empty file is empty", async () => {
  await withCwd(async (cwd) => {
    await writeFile(join(cwd, "work", "empty.img"), "");
    assert.equal(refused(await tool(ID, cwd, { path: "work/empty.img" })).error, "the file is empty");
  });
});

const KEY_NAME = `${KEY}`;

test("recovery_key_scan withholds a path component shaped like a recovery password, wherever a path is printed", async () => {
  // A file or directory named after the key put the key into exceptions[].path,
  // findings[].file and the error answer, and into the digest naming the paging file.
  await withCwd(async (cwd) => {
    await mkdir(join(cwd, "work", "ev", KEY_NAME), { recursive: true });
    await mkdir(join(cwd, "pystub"), { recursive: true });
    await writeFile(join(cwd, "pystub", "sitecustomize.py"), EIO_SITE);
    await writeFile(join(cwd, "work", "ev", KEY_NAME, "inside.txt"), `the key ${KEY}\n`);
    await writeFile(join(cwd, "work", "ev", `key_${KEY}.txt`), "an ordinary note\n");
    await writeFile(join(cwd, "work", "ev", `${KEY}-unreadable.bin`), "x");
    await symlink(join(cwd, "work", "ev", "key_" + KEY + ".txt"), join(cwd, "work", "ev", `${KEY}.lnk`));
    const out = await tool(SCAN, cwd, { path: "work/ev", limit: 1 }, { PYTHONPATH: join(cwd, "pystub") });
    const scan = body<Scan & { paths_withheld: number; paths_note: string }>(out);
    assertNoSecret(await everythingPrinted(cwd, out.stdout));
    const WITHHELD = "<recovery-password-shaped name withheld>";
    assert.ok(out.stdout.includes(WITHHELD));
    // The unreadable file, the link, and the finding inside the directory named after the key.
    assert.equal(scan.paths_withheld, 3);
    assert.match(scan.paths_note, /withheld/);
    // The finding still says which file, with the rest of its path intact.
    assert.equal(scan.findings[0].file, `work/ev/${WITHHELD}/inside.txt`);
    // The paging file's name does not derive from the real path either.
    for (const page of Object.values(scan.pages)) {
      if (page.all_results) assert.ok(!page.all_results.includes(GROUPS[0]));
    }
    // The error answer for a path that is not there.
    const missing = await tool(SCAN, cwd, { path: `work/${KEY}` });
    const err = refused(missing) as { error: string; path: string };
    assert.equal(err.path, `work/${WITHHELD}`);
    assertNoSecret(missing.stdout);

    // The sealed values file, and only it, keeps the real path.
    const outDir = join(cwd, "out");
    await mkdir(outDir);
    const loud = await tool(SCAN, cwd, { path: "work/ev", write_values: true }, { JOB_ID: "j000002", OUT: outDir, PYTHONPATH: join(cwd, "pystub") });
    assertNoSecret(await everythingPrinted(cwd, loud.stdout).catch(() => loud.stdout));
    const rows = (await readFile(join(outDir, "recovery-passwords.jsonl"), "utf8")).trimEnd().split("\n").map((l) => JSON.parse(l) as { file: string });
    assert.ok(rows.some((r) => r.file.includes(KEY_NAME)), "the real path is in the sealed file");
  });
});

test("recovery_key_scan finds a value glued to a letter, an underscore or punctuation, and not one that continues a digit run", async () => {
  // It matched on \b, which is no boundary between an underscore or a letter
  // and a digit: "key_<value>" and "pw<value>" were not found.
  await withCwd(async (cwd) => {
    await mkdir(join(cwd, "work", "ev"), { recursive: true });
    await writeFile(join(cwd, "work", "ev", "glued.txt"), [`pw${KEY}x`, `key_${KEY}_end`, `(${KEY})`].join("\n") + "\n");
    await writeFile(join(cwd, "work", "ev", "digits.txt"), [`${KEY}7`, `7${KEY}`].join("\n") + "\n");
    const out = await tool(SCAN, cwd, { path: "work/ev" });
    const scan = body<Scan>(out);
    const byFile = (name: string) => scan.findings.filter((f) => f.file.endsWith(name));
    assert.equal(byFile("glued.txt").length, 3);
    assert.ok(byFile("glued.txt").every((f) => f.passes_structure_check && f.length === 55));
    assert.equal(byFile("digits.txt").length, 0, "a seventh digit makes the first or last group no group");
    assertNoSecret(out.stdout);
  });
});

test("recovery_key_scan opens its values file first: a file or link already there is refused by name, before any scan", async () => {
  // The file was created at the first value written, after the scan: a
  // pre-existing file or link made the tool fail at the end, or write through it.
  await withCwd(async (cwd) => {
    await plant(cwd);
    const outDir = join(cwd, "out");
    await mkdir(outDir);
    const job = { JOB_ID: "j000003", OUT: outDir };
    const target = join(outDir, "recovery-passwords.jsonl");
    await writeFile(target, "already here\n");
    const exists = refused(await tool(SCAN, cwd, { path: "work/ev", write_values: true }, job)) as { error: string };
    assert.match(exists.error, /^the values file already exists: /);
    assert.ok(exists.error.includes(target));
    assert.equal(await readFile(target, "utf8"), "already here\n");
    assert.deepEqual((await readdir(outDir)).sort(), ["recovery-passwords.jsonl"], "nothing was scanned or paged");

    // A link at that name, to a file outside $OUT, is refused and its target is not written.
    const outside = join(cwd, "outside.txt");
    await writeFile(outside, "outside\n");
    const out2 = join(cwd, "out2");
    await mkdir(out2);
    await symlink(outside, join(out2, "recovery-passwords.jsonl"));
    const linked = refused(await tool(SCAN, cwd, { path: "work/ev", write_values: true }, { JOB_ID: "j000004", OUT: out2 })) as { error: string };
    assert.match(linked.error, /^the values file already exists: /);
    assert.equal(await readFile(outside, "utf8"), "outside\n");
    // So is a dangling link.
    const out3 = join(cwd, "out3");
    await mkdir(out3);
    await symlink(join(cwd, "nowhere.txt"), join(out3, "recovery-passwords.jsonl"));
    refused(await tool(SCAN, cwd, { path: "work/ev", write_values: true }, { JOB_ID: "j000005", OUT: out3 }));
    assert.deepEqual(await readdir(cwd).then((n) => n.includes("nowhere.txt")), false);

    // Asked for and nothing found: an empty file, mode 0600, named, and written: 0.
    await mkdir(join(cwd, "work", "clean"), { recursive: true });
    await writeFile(join(cwd, "work", "clean", "a.txt"), "nothing\n");
    const out4 = join(cwd, "out4");
    await mkdir(out4);
    const none = body<Scan>(await tool(SCAN, cwd, { path: "work/clean", write_values: true }, { JOB_ID: "j000006", OUT: out4 }));
    assert.equal(none.secret_values.written, 0);
    assert.equal(none.secret_values.contains_secret_values, false);
    assert.equal(none.secret_values.values_file, "store/jobs/j000006/out/recovery-passwords.jsonl");
    const file = join(out4, "recovery-passwords.jsonl");
    assert.equal((await stat(file)).size, 0);
    assert.equal((await stat(file)).mode & 0o777, 0o600);
  });
});

test("archive_probe searches a PDF or an Office file whole, whatever max_metadata_bytes says, and says so", async () => {
  // max_metadata_bytes bounds what is loaded (a ZIP central directory, a 7-Zip
  // header). A PDF's marker sits in its trailer, at the end: bounding the
  // search by it would miss it. The search is a linear pass bounded by the timeout.
  await withCwd(async (cwd) => {
    const pdf = Buffer.concat([Buffer.from("%PDF-1.7\n"), Buffer.alloc(9 * 1024 * 1024, 0x20), Buffer.from("\ntrailer\n<< /Encrypt 5 0 R >>\n%%EOF\n")]);
    await writeFile(join(cwd, "work", "tail.pdf"), pdf);
    const p = body<Probe>(await tool(PROBE, cwd, { path: "work/tail.pdf", max_metadata_bytes: 4096 }));
    assert.deepEqual(p.encrypt_marker.first_offsets, [pdf.indexOf("/Encrypt")]);
    assert.equal(p.bytes_searched, pdf.length);
    assert.equal(p.search_complete, true);
    assert.match(p.search_note, /whole file/);
    const ole = Buffer.concat([OLE_MAGIC, Buffer.alloc(9 * 1024 * 1024), Buffer.from("EncryptedPackage", "utf16le")]);
    await writeFile(join(cwd, "work", "tail.docx"), ole);
    const o = body<Probe>(await tool(PROBE, cwd, { path: "work/tail.docx", max_metadata_bytes: 4096 }));
    assert.equal(o.markers_found[0].name, "EncryptedPackage");
    assert.equal(o.bytes_searched, ole.length);
    assert.equal(o.search_complete, true);
  });
});

test("archive_probe streams a 7-Zip header's printable strings in offset order, ASCII and UTF-16LE together, without holding them", async () => {
  // It collected every match of both patterns into lists (up to the 32 MiB
  // budget's worth of tuples) and sorted them before the first was written.
  await withCwd(async (cwd) => {
    await mkdir(join(cwd, "nosite"), { recursive: true });
    await writeFile(join(cwd, "nosite", "sitecustomize.py"), NO_7Z_SITE);
    // Two NULs after an ASCII run: a lone one would read as the first half of a UTF-16 pair.
    const unit = (i: number) => [Buffer.from(`ascii-${i}\u0000\u0000`, "latin1"), Buffer.from(`wide-${i}\u0000`, "utf16le")];
    const header = Buffer.concat([Buffer.from([0x01]), ...[0, 1, 2, 3, 4].flatMap(unit)]);
    const start = Buffer.alloc(32);
    Buffer.from([0x37, 0x7a, 0xbc, 0xaf, 0x27, 0x1c, 0x00, 0x04]).copy(start, 0);
    start.writeBigUInt64LE(0n, 12);
    start.writeBigUInt64LE(BigInt(header.length), 20);
    await writeFile(join(cwd, "work", "mixed.7z"), Buffer.concat([start, header]));
    const out = body<Probe>(await tool(PROBE, cwd, { path: "work/mixed.7z", limit: 2 }, { PYTHONPATH: join(cwd, "nosite") }));
    assert.equal(out.header_strings_hint_count, 10);
    assert.deepEqual(out.header_strings_hint, ["ascii-0", "wide-0"]);
    assert.deepEqual(await allRows<string>(cwd, out.header_strings_hint_page), [0, 1, 2, 3, 4].flatMap((i) => [`ascii-${i}`, `wide-${i}`]));
  });
});

const MEMORY_DRIVER = String.raw`
import json, os, resource, subprocess, sys
tool, cwd, path = sys.argv[1], sys.argv[2], sys.argv[3]
env = dict(os.environ, AGENT_ID="s1", PYTHONPATH=os.path.join(cwd, "nosite"))
p = subprocess.run([sys.executable, tool], input=json.dumps({"path": path, "limit": 3, "max_metadata_bytes": 33554432}),
                   capture_output=True, text=True, cwd=cwd, env=env)
rss = resource.getrusage(resource.RUSAGE_CHILDREN).ru_maxrss
if sys.platform != "darwin":
    rss *= 1024
out = json.loads(p.stdout)
print(json.dumps({"code": p.returncode, "rss_mib": rss / 2**20, "count": out.get("header_strings_hint_count")}))
`;

test("archive_probe keeps its memory flat over a 16 MiB 7-Zip header with two million strings", async () => {
  await withCwd(async (cwd) => {
    await mkdir(join(cwd, "nosite"), { recursive: true });
    await writeFile(join(cwd, "nosite", "sitecustomize.py"), NO_7Z_SITE);
    const header = Buffer.concat([Buffer.from([0x01]), Buffer.from("abcdefg\u0000".repeat(2_097_151), "latin1")]);
    const start = Buffer.alloc(32);
    Buffer.from([0x37, 0x7a, 0xbc, 0xaf, 0x27, 0x1c, 0x00, 0x04]).copy(start, 0);
    start.writeBigUInt64LE(BigInt(header.length), 20);
    await writeFile(join(cwd, "work", "big.7z"), Buffer.concat([start, header]));
    const run = await runPySnippet(MEMORY_DRIVER, [PROBE, cwd, "work/big.7z"], null);
    assert.equal(run.code, 0, run.stderr);
    const got = JSON.parse(run.stdout) as { code: number; rss_mib: number; count: number };
    assert.equal(got.code, 0);
    assert.equal(got.count, 2_097_151);
    assert.ok(got.rss_mib < 150, `peak ${got.rss_mib.toFixed(0)} MiB: the matches were held`);
  });
});

/** A sitecustomize for one condition: no 7-Zip program on PATH, and/or a zipfile.is_zipfile as strict as Python 3.14's. */
function siteFor(opts: { no7z?: boolean; strictIsZipfile?: boolean }): string {
  return [
    "import shutil, zipfile",
    opts.no7z ? '_w = shutil.which\nshutil.which = lambda c, *a, **k: None if str(c) in ("7z", "7zz", "7za") else _w(c, *a, **k)' : "",
    // Python 3.14 refuses an End Of Central Directory record whose directory does not fit the file; this is the extreme.
    opts.strictIsZipfile ? "zipfile.is_zipfile = lambda *a, **k: False" : "",
  ].join("\n") + "\n";
}

test("archive_probe answers a ZIP the same whether 7z is installed or not, and whether zipfile.is_zipfile is strict (Python 3.14) or not", async () => {
  // On a runner whose python3 is 3.14 the 22-byte file below was "failed": is_zipfile
  // said no to a record that declares a directory bigger than the file, and the tool
  // took its answer for "not a ZIP". The ZIP is recognised from its own end now.
  await withCwd(async (cwd, bin) => {
    await sevenStub(bin);
    const eocd = Buffer.alloc(22);
    eocd.writeUInt32LE(0x06054b50, 0);
    eocd.writeUInt16LE(0xfffe, 8);
    eocd.writeUInt16LE(0xfffe, 10);
    eocd.writeUInt32LE(1 << 30, 12);
    await writeFile(join(cwd, "work", "huge.zip"), eocd);
    const real = buildZip([{ name: "inside.docx" }, { name: "locked.bin", flags: 1, method: 8 }]);
    await writeFile(join(cwd, "work", "plain.zip"), real);
    await writeFile(join(cwd, "work", "sfx.exe"), buildZip([{ name: "inside.docx" }, { name: "locked.bin", flags: 1, method: 8 }], { prefix: Buffer.concat([Buffer.from("MZ"), Buffer.alloc(4094, 0x90)]) }));
    await writeFile(join(cwd, "work", "cut.zip"), real.subarray(0, 40));
    for (const [label, no7z] of [["7z stub present", false], ["7z absent", true]] as const) {
      for (const strictIsZipfile of [false, true]) {
        const where = `${label}, strict is_zipfile ${strictIsZipfile}`;
        await mkdir(join(cwd, "site"), { recursive: true });
        await writeFile(join(cwd, "site", "sitecustomize.py"), siteFor({ no7z, strictIsZipfile }));
        const env = { PYTHONPATH: join(cwd, "site") };
        const run = (name: string) => tool(PROBE, cwd, { path: `work/${name}` }, env, no7z ? undefined : bin).then(body<Probe>);
        const huge = await run("huge.zip");
        assert.equal(huge.listing, "not attempted", where);
        assert.equal(huge.partial, true, where);
        assert.equal(huge.container, "ZIP", where);
        assert.match(huge.reason, /max_metadata_bytes/, where);
        const plain = await run("plain.zip");
        assert.deepEqual([plain.container, plain.entry_count, plain.encrypted_entries, plain.protected], ["ZIP", 2, 1, true], where);
        const sfx = await run("sfx.exe");
        assert.deepEqual((sfx.entries as Probe[]).map((e) => e.name), ["inside.docx", "locked.bin"], where);
        const cut = await run("cut.zip");
        assert.deepEqual([cut.container, cut.listing, cut.protected], ["ZIP", "failed", null], where);
      }
    }
    // The 7z stand-in is never run for a ZIP: its argument record was not written.
    assert.equal(await stat(join(bin, "7z-args.txt")).then(() => true, () => false), false);
  });
});
