/**
 * encrypted-containers: the findings of the independent review of archive_probe, crypto_id and recovery_key_scan, one test each. Every
 * test here fails on the tools as they were; fixtures are built from the formats (APPNOTE record layouts, the LUKS on-disk layouts) and
 * canaries from pieces, never from a tool's own output.
 */
import assert from "node:assert/strict";
import { spawn, spawnSync } from "node:child_process";
import { chmod, mkdir, readFile, readdir, stat, symlink, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { test } from "node:test";
import { ROOT, runPy, runPySnippet, withCwd } from "./tool-library-harness.ts";

const ENC = join(ROOT, "packs", "encrypted-containers", "tools");
const SCAN = join(ENC, "recovery_key_scan", "run.py");
const PROBE = join(ENC, "archive_probe", "run.py");
const ID = join(ENC, "crypto_id", "run.py");
const AGENT = { AGENT_ID: "s1" };
const LINUX = process.platform === "linux";

type Run = { code: number | null; stdout: string; stderr: string };
type Json = Record<string, any>;

async function tool(script: string, cwd: string, args: unknown, env: Record<string, string> = {}, bin?: string): Promise<Run> {
  return runPy(script, cwd, args, bin, { ...AGENT, ...env });
}

function answer(out: Run, code = 0): Json {
  assert.equal(out.code, code, out.stderr + out.stdout);
  assert.doesNotMatch(out.stderr, /Traceback/);
  return JSON.parse(out.stdout) as Json;
}

function refused(out: Run): Json {
  assert.equal(out.code, 1, out.stdout);
  assert.doesNotMatch(out.stderr, /Traceback/);
  const got = JSON.parse(out.stdout) as Json;
  assert.equal(got.status, "failed");
  assert.ok(typeof got.status_basis === "string" && got.status_basis.length > 10);
  return got;
}

/** Run a tool, send it a signal when `ready` says so (or after `afterMs`), and say how it ended. */
async function signalled(script: string, cwd: string, args: unknown, env: Record<string, string>, signal: NodeJS.Signals, ready: () => Promise<boolean>, bin?: string): Promise<Run & { signal: NodeJS.Signals | null; pid: number }> {
  const e: Record<string, string | undefined> = { ...process.env, ...AGENT, ...env };
  if (bin) e.PATH = `${bin}:${e.PATH ?? ""}`;
  const child = spawn("python3", [script], { cwd, env: e });
  const stdout: Buffer[] = [];
  const stderr: Buffer[] = [];
  child.stdout.on("data", (c: Buffer) => stdout.push(c));
  child.stderr.on("data", (c: Buffer) => stderr.push(c));
  child.stdin.end(JSON.stringify(args));
  for (let i = 0; i < 200 && !(await ready()); i++) await new Promise((r) => setTimeout(r, 50));
  child.kill(signal);
  return new Promise((resolve) =>
    child.on("close", (code, sig) => resolve({ code, signal: sig, pid: child.pid ?? 0, stdout: Buffer.concat(stdout).toString("utf8"), stderr: Buffer.concat(stderr).toString("utf8") })),
  );
}

const exists = (path: string) => stat(path).then(() => true, () => false);
const alive = (pid: number) => { try { process.kill(pid, 0); return true; } catch { return false; } };

// --- fixtures --------------------------------------------------------------------------------------------------------------------

let seed = 7102;
function rnd(): number {
  seed = (seed * 1664525 + 1013904223) >>> 0;
  return seed / 2 ** 32;
}
const pick = (alphabet: string, n: number) => Array.from({ length: n }, () => alphabet[Math.floor(rnd() * alphabet.length)]).join("");
const DIGITS = "0123456789";
const ALNUM = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
/** A BitLocker recovery password: eight groups of six digits, each a multiple of 11 whose quotient is below 65536. */
const recoveryKey = () => Array.from({ length: 8 }, () => String(Math.floor(rnd() * 65536) * 11).padStart(6, "0")).join("-");
const awsKeyId = () => ["AK", "IA", pick("ABCDEFGHIJKLMNOPQRSTUVWXYZ234567", 16)].join("");
const passwordAssignment = () => ["pass", "word=", pick(ALNUM, 14)].join("");

const DOS_DATE = ((2026 - 1980) << 9) | (3 << 5) | 14;
const DOS_TIME = (9 << 11) | (30 << 5) | (44 / 2);

type ZipEntry = { name?: string; nameBytes?: Buffer; flags?: number; method?: number; extra?: Buffer };

function centralEntry(e: ZipEntry, at: number, sizes: [number, number, number] = [1, 1, 0]): Buffer {
  const name = e.nameBytes ?? Buffer.from(e.name ?? "a", "utf8");
  const extra = e.extra ?? Buffer.alloc(0);
  const c = Buffer.alloc(46);
  c.writeUInt32LE(0x02014b50, 0);
  c.writeUInt16LE(20, 4);
  c.writeUInt16LE(20, 6);
  c.writeUInt16LE(e.flags ?? 0, 8);
  c.writeUInt16LE(e.method ?? 0, 10);
  c.writeUInt16LE(DOS_TIME, 12);
  c.writeUInt16LE(DOS_DATE, 14);
  c.writeUInt32LE(sizes[0], 20);
  c.writeUInt32LE(sizes[1], 24);
  c.writeUInt16LE(name.length, 28);
  c.writeUInt16LE(extra.length, 30);
  c.writeUInt32LE(sizes[2] === 0 ? at : sizes[2], 42);
  return Buffer.concat([c, name, extra]);
}

/** A ZIP from the APPNOTE's record layouts. */
function buildZip(entries: ZipEntry[]): Buffer {
  const parts: Buffer[] = [];
  const central: Buffer[] = [];
  let at = 0;
  for (const e of entries) {
    const name = e.nameBytes ?? Buffer.from(e.name ?? "a", "utf8");
    const extra = e.extra ?? Buffer.alloc(0);
    const local = Buffer.alloc(30);
    local.writeUInt32LE(0x04034b50, 0);
    local.writeUInt16LE(20, 4);
    local.writeUInt16LE(e.flags ?? 0, 6);
    local.writeUInt16LE(e.method ?? 0, 8);
    local.writeUInt32LE(1, 18);
    local.writeUInt32LE(1, 22);
    local.writeUInt16LE(name.length, 26);
    local.writeUInt16LE(extra.length, 28);
    const record = Buffer.concat([local, name, extra, Buffer.from("x")]);
    central.push(centralEntry(e, at));
    parts.push(record);
    at += record.length;
  }
  const cd = Buffer.concat(central);
  const eocd = Buffer.alloc(22);
  eocd.writeUInt32LE(0x06054b50, 0);
  eocd.writeUInt16LE(entries.length, 8);
  eocd.writeUInt16LE(entries.length, 10);
  eocd.writeUInt32LE(cd.length, 12);
  eocd.writeUInt32LE(at, 16);
  return Buffer.concat([...parts, cd, eocd]);
}

/** The Zip64 end record (56 bytes), the locator (20) and an End record that says what `eocd` says. */
function zip64Tail(entries: bigint, cdBytes: bigint, cdOffset: bigint, eocd: { entries: number; bytes: number; offset: number }): Buffer {
  const rec = Buffer.alloc(56);
  rec.write("PK\x06\x06", 0, "latin1");
  rec.writeBigUInt64LE(44n, 4);
  rec.writeUInt16LE(45, 12);
  rec.writeUInt16LE(45, 14);
  rec.writeBigUInt64LE(entries, 24);
  rec.writeBigUInt64LE(entries, 32);
  rec.writeBigUInt64LE(cdBytes, 40);
  rec.writeBigUInt64LE(cdOffset, 48);
  const loc = Buffer.alloc(20);
  loc.write("PK\x06\x07", 0, "latin1");
  loc.writeBigUInt64LE(cdOffset + cdBytes, 8);
  loc.writeUInt32LE(1, 16);
  const end = Buffer.alloc(22);
  end.writeUInt32LE(0x06054b50, 0);
  end.writeUInt16LE(eocd.entries, 8);
  end.writeUInt16LE(eocd.entries, 10);
  end.writeUInt32LE(eocd.bytes, 12);
  end.writeUInt32LE(eocd.offset, 16);
  return Buffer.concat([rec, loc, end]);
}

/** A file whose End record says one 47-byte entry and whose Zip64 record says `n` of them. */
function lyingZip(n: number, declaredBytes?: bigint): Buffer {
  const entry = centralEntry({ name: "a" }, 0);
  assert.equal(entry.length, 47);
  const cd = Buffer.concat(Array.from({ length: n }, () => entry));
  return Buffer.concat([cd, zip64Tail(BigInt(n), declaredBytes ?? BigInt(cd.length), 0n, { entries: 1, bytes: 47, offset: 0 })]);
}

// --- archive_probe ----------------------------------------------------------------------------------------------------

test("archive_probe follows a Zip64 locator whatever the End record says, and refuses a directory over its bound", async () => {
  // The End record said "1 entry, 47 bytes"; the Zip64 record said 1,000. The tool read the End record only, found the bound kept, and
  // zipfile then loaded all of them: a 141 MB file with 3,000,000 entries took 16 CPU s and 1.1 GB. The locator is followed always.
  await withCwd(async (cwd) => {
    await writeFile(join(cwd, "work", "lie.zip"), lyingZip(1000));
    const small = answer(await tool(PROBE, cwd, { path: "work/lie.zip", max_metadata_bytes: 4096 }));
    assert.equal(small.listing, "not attempted");
    assert.equal(small.partial, true);
    assert.equal(small.entry_count_declared, 1000);
    assert.equal(small.central_directory_bytes, 47000);
    assert.equal(small.status, "partial");
    assert.match(small.reason, /max_metadata_bytes/);
    // Within the bound the directory is the Zip64 one and every entry is read.
    const all = answer(await tool(PROBE, cwd, { path: "work/lie.zip" }));
    assert.deepEqual([all.listing === undefined, all.entry_count, all.entry_count_declared, all.entry_count_matches_declared, all.zip64], [true, 1000, 1000, true, true]);
    // A directory declared larger than the file is refused whatever the bound.
    await writeFile(join(cwd, "work", "beyond.zip"), lyingZip(10, 5_000_000n));
    const beyond = answer(await tool(PROBE, cwd, { path: "work/beyond.zip" }));
    assert.equal(beyond.listing, "not attempted");
    assert.match(beyond.reason, /more than the file holds/);
    // More entries declared than the bound can hold at 46 bytes each, in a directory that is small.
    const many = lyingZip(10);
    many.writeBigUInt64LE(10_000_000n, many.length - 22 - 20 - 56 + 32);
    await writeFile(join(cwd, "work", "many.zip"), many);
    const tooMany = answer(await tool(PROBE, cwd, { path: "work/many.zip", max_metadata_bytes: 1 << 20 }));
    assert.equal(tooMany.listing, "not attempted");
    assert.match(tooMany.reason, /entries are declared/);
  });
});

const MEMORY_DRIVER = String.raw`
import json, resource, subprocess, sys
p = subprocess.run(["python3", sys.argv[1]], input=json.dumps({"path": sys.argv[2]}).encode(), capture_output=True, cwd=sys.argv[3], env={**__import__("os").environ, "AGENT_ID": "s1"})
rss = resource.getrusage(resource.RUSAGE_CHILDREN).ru_maxrss
rss = rss if sys.platform == "darwin" else rss * 1024
out = json.loads(p.stdout)
print(json.dumps({"code": p.returncode, "rss_mib": rss / 2**20, "listing": out.get("listing"), "count": out.get("entry_count")}))
`;

test("archive_probe does not load a 40 MB lying directory, and lists a large honest one in flat memory", async () => {
  await withCwd(async (cwd) => {
    await writeFile(join(cwd, "work", "lie40.zip"), lyingZip(850_000));
    const lie = await runPySnippet(MEMORY_DRIVER, [PROBE, join(cwd, "work", "lie40.zip"), cwd], null);
    assert.equal(lie.code, 0, lie.stderr);
    const got = JSON.parse(lie.stdout) as { code: number; rss_mib: number; listing: string };
    assert.deepEqual([got.code, got.listing], [0, "not attempted"]);
    assert.ok(got.rss_mib < 60, `peak ${got.rss_mib.toFixed(0)} MiB`);
    // 300,000 entries of an honest Zip64 directory (14 MB, inside the bound): every entry read, memory not following the directory.
    const entry = centralEntry({ name: "a" }, 0);
    const cd = Buffer.concat(Array.from({ length: 300_000 }, () => entry));
    await writeFile(join(cwd, "work", "honest.zip"), Buffer.concat([cd, zip64Tail(300_000n, BigInt(cd.length), 0n, { entries: 0xffff, bytes: 0xffffffff, offset: 0xffffffff })]));
    const honest = await runPySnippet(MEMORY_DRIVER, [PROBE, join(cwd, "work", "honest.zip"), cwd], null);
    const ok = JSON.parse(honest.stdout) as { rss_mib: number; count: number };
    assert.equal(ok.count, 300_000);
    assert.ok(ok.rss_mib < 100, `peak ${ok.rss_mib.toFixed(0)} MiB`);
  });
});

test("archive_probe reads a Zip64 directory whose End record holds the 0xFFFF markers, with the sizes of a Zip64 extra field", async () => {
  await withCwd(async (cwd) => {
    const z64 = Buffer.alloc(8 + 8 + 8);
    z64.writeBigUInt64LE(5_000_000_000n, 0); // uncompressed
    z64.writeBigUInt64LE(4_000_000_000n, 8); // compressed
    z64.writeBigUInt64LE(77n, 16); // local header offset
    const extra = Buffer.concat([Buffer.from([1, 0, 24, 0]), z64]);
    const entry = Buffer.concat([centralEntry({ name: "big.bin", extra }, 0, [0xffffffff, 0xffffffff, 0xffffffff])]);
    const tail = zip64Tail(1n, BigInt(entry.length), 0n, { entries: 0xffff, bytes: 0xffffffff, offset: 0xffffffff });
    await writeFile(join(cwd, "work", "z64.zip"), Buffer.concat([entry, tail]));
    const out = answer(await tool(PROBE, cwd, { path: "work/z64.zip" }));
    assert.equal(out.entry_count, 1);
    assert.deepEqual([out.entries[0].name, out.entries[0].bytes, out.entries[0].compressed, out.entries[0].header_offset], ["big.bin", 5_000_000_000, 4_000_000_000, 77]);
    assert.equal(out.status, "complete");
  });
});

// --- archive_probe ----------------------------------------------------------------------------------------------------

test("archive_probe lists the other members when one name is not valid UTF-8", async () => {
  await withCwd(async (cwd) => {
    const zip = buildZip([{ name: "secret.docx", flags: 0x0001 }, { nameBytes: Buffer.from([0xff, 0xfe, 0x62, 0x61, 0x64]), flags: 0x0800 }, { name: "plain.txt" }]);
    await writeFile(join(cwd, "work", "bad.zip"), zip);
    const run = await tool(PROBE, cwd, { path: "work/bad.zip" });
    const out = answer(run);
    assert.equal(out.listing, undefined);
    assert.deepEqual([out.entry_count, out.encrypted_entries, out.protected, out.names_readable], [3, 1, true, true]);
    assert.deepEqual(out.entries.map((e: Json) => e.encrypted), [true, false, false]);
    assert.equal(out.entries[1].name, "\udcff\udcfebad");
    assert.equal(out.entries[1].name_encoding, "UTF-8 (flag 0x800)");
    assert.match(out.status_basis, /every central directory entry/);
    // The answer is plain ASCII: a name that is not text is written escaped.
    assert.doesNotMatch(out.entries[1].name, /^[\x00-\x7f]*$/);
    assert.match(run.stdout, /^[\x00-\x7f]*$/);
  });
});

test("archive_probe withholds recovery-password, key-id and password shapes in member names, header strings, diagnostics and paths", async () => {
  await withCwd(async (cwd, bin) => {
    const key = recoveryKey();
    const aws = awsKeyId();
    const pw = passwordAssignment();
    const names = [`docs/${key}.txt`, `keys/${aws}.csv`, `${pw}.txt`, "docs/plain.txt"];
    await mkdir(join(cwd, "work", key), { recursive: true });
    await writeFile(join(cwd, "work", key, "names.zip"), buildZip(names.map((name) => ({ name }))));
    const out = await tool(PROBE, cwd, { path: `work/${key}/names.zip`, limit: 2 }, { JOB_ID: "j000001", OUT: join(cwd, "out") });
    const probe = answer(out);
    const everything = [out.stdout];
    for (const f of await readdir(join(cwd, "out", "tool-output")).catch(() => [] as string[])) everything.push(await readFile(join(cwd, "out", "tool-output", f), "utf8"));
    const printed = everything.join("\n");
    for (const secret of [key, aws, pw, pw.slice(9), ...key.split("-")]) assert.ok(!printed.includes(secret), `${secret.slice(0, 6)}... is printed`);
    assert.equal(probe.path, "work/<recovery-password-shaped name withheld>/names.zip");
    assert.ok(printed.includes("docs/plain.txt"));
    assert.ok(probe.names_withheld >= 3);
    assert.match(probe.names_note, /by shape/);

    // The same through 7z's listing and its diagnostics, and through the header strings kept as a hint when 7z is absent.
    await writeFile(join(bin, "7z"), `#!/bin/sh
printf 'Path = x.7z\\nType = 7z\\n\\n----------\\nPath = docs/${key}.txt\\nSize = 3\\nEncrypted = -\\n\\nPath = ${aws}\\nSize = 3\\nEncrypted = -\\n\\n'
echo "WARNING: ${pw} : something"
exit 1
`);
    await chmod(join(bin, "7z"), 0o755);
    const header = Buffer.concat([Buffer.from([0x01]), Buffer.from(`${pw}\u0000${aws}\u0000${key}\u0000`, "latin1")]);
    const start = Buffer.alloc(32);
    Buffer.from([0x37, 0x7a, 0xbc, 0xaf, 0x27, 0x1c, 0x00, 0x04]).copy(start, 0);
    start.writeBigUInt64LE(BigInt(header.length), 20);
    await writeFile(join(cwd, "work", "n.7z"), Buffer.concat([start, header]));
    const listed = await tool(PROBE, cwd, { path: "work/n.7z" }, {}, bin);
    answer(listed);
    for (const secret of [key, aws, pw]) assert.ok(!listed.stdout.includes(secret), "7z member names and diagnostics");
    await mkdir(join(cwd, "nosite"), { recursive: true });
    await writeFile(join(cwd, "nosite", "sitecustomize.py"), "import shutil\n_w = shutil.which\nshutil.which = lambda c, *a, **k: None if str(c) in ('7z','7zz','7za') else _w(c, *a, **k)\n");
    const hint = await tool(PROBE, cwd, { path: "work/n.7z" }, { PYTHONPATH: join(cwd, "nosite") });
    const hinted = answer(hint);
    for (const secret of [key, aws, pw]) assert.ok(!hint.stdout.includes(secret), "header strings");
    assert.ok(hinted.header_strings_hint.length >= 3);
  });
});

test("archive_probe answers carry status and status_basis, errors included", async () => {
  await withCwd(async (cwd) => {
    await writeFile(join(cwd, "work", "a.zip"), buildZip([{ name: "a.txt" }]));
    await writeFile(join(cwd, "work", "r.rar"), Buffer.concat([Buffer.from("Rar!\x1a\x07\x00", "latin1"), Buffer.alloc(40)]));
    await writeFile(join(cwd, "work", "d.pdf"), Buffer.from("%PDF-1.4\n/Encrypt 4 0 R\n"));
    await writeFile(join(cwd, "work", "junk.bin"), Buffer.from("not a container at all"));
    const zip = answer(await tool(PROBE, cwd, { path: "work/a.zip" }));
    assert.deepEqual([zip.status, typeof zip.status_basis], ["complete", "string"]);
    assert.equal(answer(await tool(PROBE, cwd, { path: "work/r.rar" })).status, "partial");
    const pdf = answer(await tool(PROBE, cwd, { path: "work/d.pdf" }));
    assert.deepEqual([pdf.status, pdf.protected], ["partial", null]);
    for (const args of [{ path: "work/junk.bin" }, { path: "work/missing.zip" }, { path: "work" }, { path: "work/a.zip", limit: 0 }, { path: "work/a.zip", max_seconds: 0 }, []]) refused(await tool(PROBE, cwd, args));
    assert.match(refused(await tool(PROBE, cwd, { path: "work" })).error, /is a directory/);
  });
});

test("archive_probe reports a file it cannot read as JSON, not a traceback", async (t) => {
  if (process.getuid?.() === 0) return t.skip("root reads any file");
  await withCwd(async (cwd) => {
    await writeFile(join(cwd, "work", "locked.zip"), buildZip([{ name: "a" }]));
    await chmod(join(cwd, "work", "locked.zip"), 0);
    const out = refused(await tool(PROBE, cwd, { path: "work/locked.zip" }));
    assert.match(out.error, /could not be read/);
    assert.match(out.error, /Permission/);
  });
});

test("recovery_key_scan survives a file name that is not UTF-8 in its paging and values files", async (t) => {
  if (!LINUX) return t.skip("a name that is not UTF-8 can only be made where the file system allows it (Linux)");
  await withCwd(async (cwd) => {
    const dir = Buffer.from(join(cwd, "work", "ev"));
    await mkdir(dir, { recursive: true });
    const odd = Buffer.concat([dir, Buffer.from("/"), Buffer.from([0xff, 0xfe]), Buffer.from("_recovery_key.txt")]);
    await writeFile(odd, `the key ${recoveryKey()}\n`);
    await writeFile(join(cwd, "work", "ev", "ok.txt"), `the key ${recoveryKey()}\n`);
    for (const args of [{ path: "work/ev", limit: 1 }, { path: "work/ev" }]) {
      const out = answer(await tool(SCAN, cwd, args));
      assert.equal(out.finding_count, 2);
    }
    const outDir = join(cwd, "out");
    await mkdir(outDir);
    const values = answer(await tool(SCAN, cwd, { path: "work/ev", write_values: true }, { JOB_ID: "j000009", OUT: outDir, SECRET_OUTPUT: "1" }));
    assert.equal(values.secret_values.written, 2);
    for (const line of (await readFile(join(outDir, "recovery-passwords.jsonl"), "utf8")).trimEnd().split("\n")) JSON.parse(line);
  });
});

// --- archive_probe ----------------------------------------------------------------------------------------------------

/** A 7z stand-in that records its pid and then waits: the tool is stopped while it runs. */
async function sleepingSeven(bin: string, cwd: string): Promise<string> {
  const pidFile = join(cwd, "seven.pid");
  await writeFile(join(bin, "7z"), `#!/bin/sh\necho $$ > "${pidFile}"\nexec sleep 60\n`);
  await chmod(join(bin, "7z"), 0o755);
  return pidFile;
}

const SEVEN_HEADER = (() => {
  const header = Buffer.concat([Buffer.from([0x01]), Buffer.from("abcdefg\u0000", "latin1")]);
  const start = Buffer.alloc(32);
  Buffer.from([0x37, 0x7a, 0xbc, 0xaf, 0x27, 0x1c, 0x00, 0x04]).copy(start, 0);
  start.writeBigUInt64LE(BigInt(header.length), 20);
  return Buffer.concat([start, header]);
})();

for (const [name, num] of [["SIGTERM", 15], ["SIGINT", 2], ["SIGHUP", 1]] as const) {
  test(`archive_probe stops on ${name} with one JSON answer, exit ${128 + num}, and ends the 7z it started`, async () => {
    await withCwd(async (cwd, bin) => {
      const pidFile = await sleepingSeven(bin, cwd);
      await writeFile(join(cwd, "work", "s.7z"), SEVEN_HEADER);
      const run = await signalled(PROBE, cwd, { path: "work/s.7z" }, {}, name, () => exists(pidFile), bin);
      assert.doesNotMatch(run.stderr, /Traceback/);
      assert.equal(run.code, 128 + num, run.stdout);
      const got = JSON.parse(run.stdout) as Json;
      assert.deepEqual([got.status, got.signal, got.path], ["interrupted", num, "work/s.7z"]);
      const child = Number((await readFile(pidFile, "utf8")).trim());
      await new Promise((r) => setTimeout(r, 300));
      assert.equal(alive(child), false, "the 7z child is still running");
    });
  });
}

test("archive_probe keeps its own clock: max_seconds ends a 7z that runs long, and the answer says so", async () => {
  await withCwd(async (cwd, bin) => {
    const pidFile = await sleepingSeven(bin, cwd);
    await writeFile(join(cwd, "work", "s.7z"), SEVEN_HEADER);
    const started = Date.now();
    const out = answer(await tool(PROBE, cwd, { path: "work/s.7z", max_seconds: 2 }, {}, bin));
    assert.ok(Date.now() - started < 8000, "the limit was not honoured");
    assert.equal(out.listing.status, "timed_out");
    assert.equal(out.status, "partial");
    assert.equal(out.max_seconds, 2);
    await new Promise((r) => setTimeout(r, 300));
    assert.equal(alive(Number((await readFile(pidFile, "utf8")).trim())), false);
  });
});

test("archive_probe's 7z does not outlive the tool when the tool is killed (Linux: PR_SET_PDEATHSIG)", async (t) => {
  if (!LINUX) return t.skip("the parent-death signal is Linux's");
  await withCwd(async (cwd, bin) => {
    const pidFile = await sleepingSeven(bin, cwd);
    await writeFile(join(cwd, "work", "s.7z"), SEVEN_HEADER);
    const run = await signalled(PROBE, cwd, { path: "work/s.7z" }, {}, "SIGKILL", () => exists(pidFile), bin);
    assert.equal(run.signal, "SIGKILL");
    await new Promise((r) => setTimeout(r, 500));
    assert.equal(alive(Number((await readFile(pidFile, "utf8")).trim())), false);
  });
});

test("archive_probe never replaces a result file that is there, and names the one it kept", async () => {
  await withCwd(async (cwd) => {
    await writeFile(join(cwd, "work", "many.zip"), buildZip(Array.from({ length: 6 }, (_, i) => ({ name: `m${i}.txt` }))));
    const first = answer(await tool(PROBE, cwd, { path: "work/many.zip", limit: 2 }));
    const kept = join(cwd, first.all_results);
    const bigger = (await readFile(kept, "utf8")) + (await readFile(kept, "utf8"));
    await writeFile(kept, bigger);
    const second = answer(await tool(PROBE, cwd, { path: "work/many.zip", limit: 2 }));
    assert.notEqual(second.all_results, first.all_results);
    assert.equal(await readFile(kept, "utf8"), bigger, "the earlier, larger file was replaced");
    assert.equal((await readFile(join(cwd, second.all_results), "utf8")).trimEnd().split("\n").length, 6);
    assert.deepEqual((await readdir(join(cwd, "work", "s1", "tool-output"))).filter((n) => n.startsWith(".")), []);
  });
});

// --- crypto_id ---------------------------------------------------------------------------------------------------------------------

function field(h: Buffer, at: number, text: string, width: number): void {
  Buffer.from(text, "latin1").copy(h, at, 0, width);
}

function luks2(label: string, subsystem: string, checksum = "sha256", uuid = "9b1d6a32-4c5e-4f70-8a91-b2c3d4e5f607"): Buffer {
  const h = Buffer.alloc(4096);
  Buffer.from("LUKS\xba\xbe", "latin1").copy(h, 0);
  h.writeUInt16BE(2, 6);
  h.writeBigUInt64BE(16384n, 8);
  h.writeBigUInt64BE(7n, 16);
  field(h, 24, label, 48);
  field(h, 72, checksum, 32);
  field(h, 168, uuid, 40);
  field(h, 208, subsystem, 48);
  return h;
}

function luks1(cipher: string, mode: string, hash: string, uuid: string): Buffer {
  const h = Buffer.alloc(592);
  Buffer.from("LUKS\xba\xbe", "latin1").copy(h, 0);
  h.writeUInt16BE(1, 6);
  field(h, 8, cipher, 32);
  field(h, 40, mode, 32);
  field(h, 72, hash, 32);
  h.writeUInt32BE(4096, 104);
  h.writeUInt32BE(64, 108);
  field(h, 168, uuid, 40);
  for (let i = 0; i < 8; i++) h.writeUInt32BE(0x0000dead, 208 + i * 48);
  return h;
}

test("crypto_id prints header text only when it is what the format says: closed lists, the UUID form, withheld free text", async () => {
  await withCwd(async (cwd) => {
    const key = recoveryKey().replaceAll("-", "");
    const pw = passwordAssignment();
    await writeFile(join(cwd, "work", "l2.img"), luks2(key, pw));
    const l2 = answer(await tool(ID, cwd, { path: "work/l2.img" }));
    for (const secret of [key, key.slice(0, 20), pw, pw.slice(9)]) assert.ok(!JSON.stringify(l2).includes(secret));
    assert.deepEqual([l2.scheme, l2.uuid, l2.checksum_alg, l2.status], ["LUKS2", "9b1d6a32-4c5e-4f70-8a91-b2c3d4e5f607", "sha256", "complete"]);
    assert.match(l2.label, /withheld/);
    assert.deepEqual(l2.header_fields_withheld, ["label", "subsystem"]);
    // Names that are not on the lists, and a UUID field that is not a UUID.
    const junk = pick(ALNUM, 24);
    await writeFile(join(cwd, "work", "l1.img"), luks1(junk, `xts-${pick(ALNUM, 12)}`, ["pass", "word=", pick(ALNUM, 10)].join(""), pick(ALNUM, 30)));
    const l1 = answer(await tool(ID, cwd, { path: "work/l1.img" }));
    assert.deepEqual([l1.cipher, l1.cipher_mode, l1.hash, l1.uuid], Array(4).fill("<unrecognised header text withheld>"));
    assert.ok(!JSON.stringify(l1).includes(junk));
    assert.deepEqual(l1.header_fields_withheld, ["cipher", "cipher_mode", "hash", "uuid"]);
    // The names cryptsetup writes are printed.
    for (const [cipher, mode, hash] of [["aes", "xts-plain64", "sha256"], ["twofish", "cbc-essiv:sha256", "sha512"], ["serpent", "xts-plain", "ripemd160"], ["aes", "cbc-essiv:sha3-256", "whirlpool"]]) {
      await writeFile(join(cwd, "work", "good.img"), luks1(cipher, mode, hash, "2f4a8e0c-1b5d-4c3a-9e7f-0a1b2c3d4e5f"));
      const good = answer(await tool(ID, cwd, { path: "work/good.img" }));
      assert.deepEqual([good.cipher, good.cipher_mode, good.hash, good.header_fields_withheld], [cipher, mode, hash, undefined]);
    }
  });
});

test("crypto_id answers carry status, say a cut header is partial, and fail as JSON", async (t) => {
  await withCwd(async (cwd) => {
    await writeFile(join(cwd, "work", "cut.img"), luks1("aes", "xts-plain64", "sha256", "2f4a8e0c-1b5d-4c3a-9e7f-0a1b2c3d4e5f").subarray(0, 300));
    const cut = answer(await tool(ID, cwd, { path: "work/cut.img" }));
    assert.deepEqual([cut.status, typeof cut.status_basis], ["partial", "string"]);
    await writeFile(join(cwd, "work", "plain.bin"), "just text\n".repeat(200));
    assert.equal(answer(await tool(ID, cwd, { path: "work/plain.bin" })).status, "complete");
    for (const args of [{ path: "work/nothing" }, { path: "work" }, { path: "work/plain.bin", offset: -1 }, { path: "work/plain.bin", entropy_sample: 1 }]) refused(await tool(ID, cwd, args));
    assert.match(refused(await tool(ID, cwd, { path: "work" })).error, /is a directory/);
    if (process.getuid?.() !== 0) {
      await writeFile(join(cwd, "work", "locked.bin"), "x".repeat(100));
      await chmod(join(cwd, "work", "locked.bin"), 0);
      assert.match(refused(await tool(ID, cwd, { path: "work/locked.bin" })).error, /could not be read/);
    } else t.diagnostic("root reads any file");
  });
});

/** A sitecustomize that makes opening a file slow, so a signal arrives while the tool is working. */
const SLOW_OPEN = String.raw`
import builtins, time
_open = builtins.open
def slow(file, mode="r", *a, **k):
    if "b" in mode and str(file).endswith(".bin"):
        time.sleep(30)
    return _open(file, mode, *a, **k)
builtins.open = slow
`;

for (const [name, num] of [["SIGTERM", 15], ["SIGINT", 2], ["SIGHUP", 1]] as const) {
  test(`crypto_id stops on ${name} with one JSON answer and exit ${128 + num}`, async () => {
    await withCwd(async (cwd) => {
      await writeFile(join(cwd, "work", "slow.bin"), "x".repeat(2048));
      await mkdir(join(cwd, "site"));
      await writeFile(join(cwd, "site", "sitecustomize.py"), SLOW_OPEN);
      const started = Date.now();
      const run = await signalled(ID, cwd, { path: "work/slow.bin" }, { PYTHONPATH: join(cwd, "site") }, name, async () => Date.now() - started > 700);
      assert.doesNotMatch(run.stderr, /Traceback/);
      assert.equal(run.code, 128 + num, run.stdout);
      assert.equal((JSON.parse(run.stdout) as Json).status, "interrupted");
    });
  });
}

// --- recovery_key_scan -------------------------------------------------------------------------------------------------------------

const BIG_PEM_TYPE = ["-----BEGIN ", "A".repeat(3 << 20), "PRIVATE KEY-----"].join("");

test("recovery_key_scan reports a private key's type from a short closed list, and echoes none of the file's text", async () => {
  await withCwd(async (cwd) => {
    await mkdir(join(cwd, "work", "ev"), { recursive: true });
    for (let i = 0; i < 6; i++) await writeFile(join(cwd, "work", "ev", `big${i}.txt`), BIG_PEM_TYPE);
    await writeFile(join(cwd, "work", "ev", "shout.txt"), "-----BEGIN SECRETKEYMATERIALQWERTYUIOPASDFGH PRIVATE KEY-----\n");
    await writeFile(join(cwd, "work", "ev", "rsa.pem"), "-----BEGIN RSA PRIVATE KEY-----\nAAAA\n");
    await writeFile(join(cwd, "work", "ev", "odd.pem"), "-----BEGIN FOO PRIVATE KEY-----\nAAAA\n");
    await writeFile(join(cwd, "work", "ev", "plain.pem"), "-----BEGIN PRIVATE KEY-----\nAAAA\n");
    const out = await tool(SCAN, cwd, { path: "work/ev" });
    const scan = answer(out);
    assert.ok(out.stdout.length < 20_000, `${out.stdout.length} characters of stdout`);
    const types = Object.fromEntries(scan.findings.map((f: Json) => [f.file.split("/").pop(), f.key_type]));
    assert.deepEqual(types, { "rsa.pem": "RSA PRIVATE KEY", "odd.pem": "other", "plain.pem": "PRIVATE KEY" });
    assert.doesNotMatch(out.stdout, /SECRETKEYMATERIAL|AAAAAAAA/);
  });
});

/** The patterns the scanner had before (a look-behind in front of the first group), as the oracle for the scanner that searches by dash. */
const ORACLE = String.raw`
import importlib.util, io, json, random, re, sys
spec = importlib.util.spec_from_file_location("rks", sys.argv[1]); mod = importlib.util.module_from_spec(spec); spec.loader.exec_module(mod)
OLD_ASCII = re.compile(rb"(?<![0-9])(\d{6})-(\d{6})-(\d{6})-(\d{6})-(\d{6})-(\d{6})-(\d{6})-(\d{6})(?![0-9])")
OLD_WIDE = re.compile(rb"(?<![0-9]\x00)" + rb"-\x00".join([rb"((?:[0-9]\x00){6})"] * 8) + rb"(?![0-9]\x00)")
def reference(window):
    found = []
    for rx, kind in ((OLD_ASCII, "ascii"), (OLD_WIDE, "UTF-16LE")):
        found += [(m.start(), kind, m.groups()) for m in rx.finditer(window)]
    return sorted(found)
rnd = random.Random(int(sys.argv[2]))
def grp(): return b"%06d" % rnd.randrange(10**6)
def key(n=8, sep=b"-"): return sep.join(grp() for _ in range(n))
def wide(b): return b"".join(bytes([c, 0]) for c in b)
def piece():
    k = rnd.randrange(11)
    if k == 0: return key()
    if k == 1: return wide(key())
    if k == 2: return key(rnd.choice([6, 7, 9, 10]))
    if k == 3: return b"%d" % rnd.randrange(10**rnd.randrange(1, 12)) + b"-" + key()
    if k == 4: return key() + b"-%06d" % rnd.randrange(10**6)
    if k == 5: return wide(key(rnd.choice([7, 9])))
    if k == 6: return b"-" * rnd.randrange(1, 40)
    if k == 7: return b"\x00" * rnd.randrange(1, 9)
    if k == 8: return bytes(rnd.randrange(256) for _ in range(rnd.randrange(1, 60)))
    if k == 9: return wide(b"%d-" % rnd.randrange(10**8)) + wide(key())
    return b"x" * rnd.randrange(1, 20)
bad = total = 0
for _ in range(int(sys.argv[3])):
    data = b"".join(piece() for _ in range(rnd.randrange(1, 30)))
    want = reference(data)
    got = sorted([(h.start(), "ascii", h.groups()) for h in mod.ascii_hits(data)] + [(h.start(), "UTF-16LE", h.groups()) for h in mod.utf16_hits(data)])
    total += len(want)
    bad += want != got
print(json.dumps({"bad": bad, "found": total}))
`;

test("recovery_key_scan finds exactly what the look-behind patterns found, searching by the dash", async () => {
  const run = await runPySnippet(ORACLE, [SCAN, "11", "400"], null);
  assert.equal(run.code, 0, run.stderr);
  const got = JSON.parse(run.stdout) as { bad: number; found: number };
  assert.equal(got.bad, 0);
  assert.ok(got.found > 500, `${got.found} findings compared`);
});

/** A sitecustomize with a clock that moves half a second every time the tool looks at it. */
const FAST_CLOCK = String.raw`
import time
_t = [0.0]
def monotonic():
    _t[0] += 0.5
    return _t[0]
time.monotonic = monotonic
`;

test("recovery_key_scan has its own clock: at max_seconds it stops, names every file and directory it did not read, and says partial", async () => {
  await withCwd(async (cwd) => {
    for (const d of ["a", "b", "c"]) {
      await mkdir(join(cwd, "work", "ev", d), { recursive: true });
      for (let i = 0; i < 10; i++) await writeFile(join(cwd, "work", "ev", d, `f${String(i).padStart(2, "0")}.txt`), `note ${i}\n`);
    }
    await writeFile(join(cwd, "work", "ev", "a", "f00.txt"), `the key ${recoveryKey()}\n`);
    await mkdir(join(cwd, "site"));
    await writeFile(join(cwd, "site", "sitecustomize.py"), FAST_CLOCK);
    const out = answer(await tool(SCAN, cwd, { path: "work/ev", max_seconds: 3, limit: 5 }, { PYTHONPATH: join(cwd, "site") }));
    assert.deepEqual([out.status, out.interrupted, out.truncated], ["partial", true, true]);
    assert.match(out.stopped_by, /time limit \(max_seconds 3\)/);
    assert.match(out.status_basis, /time limit/);
    assert.equal(out.finding_count, 1, "what was found before the stop is kept");
    const cover = out.coverage;
    assert.equal(cover.max_seconds, 3);
    assert.ok(cover.files_attempted >= 1 && cover.files_attempted < 30);
    // Every file is read, or listed as not started, or inside a directory listed as not entered: nothing is dropped quietly.
    const rows = (await readFile(join(cwd, out.pages.exceptions.all_results), "utf8")).trimEnd().split("\n").map((l) => JSON.parse(l) as Json);
    const notStarted = rows.filter((r) => r.status === "not started");
    const directories = notStarted.filter((r) => r.what === "directory");
    assert.equal(cover.directories_not_entered, directories.length);
    assert.equal(cover.files_attempted + (cover.entries_not_started), 10 * (3 - directories.length), "files read + files not started = files in the directories that were entered");
    assert.ok(notStarted.length >= 1);
  });
});

/** A sitecustomize that makes reading a .bin file slow: each read waits, so a signal arrives while the scan is running. */
const SLOW_READ = String.raw`
import builtins, time
_open = builtins.open
class Slow:
    def __init__(self, fh, pause): self._fh, self._pause = fh, pause
    def read(self, n=-1):
        time.sleep(self._pause); return self._fh.read(n)
    def __enter__(self): return self
    def __exit__(self, *a): self._fh.close()
    def __getattr__(self, name): return getattr(self._fh, name)
def slow(file, mode="r", *a, **k):
    fh = _open(file, mode, *a, **k)
    if "b" in mode and str(file).endswith(".bin"):
        import os
        return Slow(fh, float(os.environ.get("SLOW_PAUSE", "0.3")))
    return fh
builtins.open = slow
`;

async function slowTree(cwd: string, files = 8): Promise<Record<string, string>> {
  await mkdir(join(cwd, "work", "ev"), { recursive: true });
  for (let i = 0; i < files; i++) await writeFile(join(cwd, "work", "ev", `f${i}.bin`), `row ${i} ${recoveryKey()}\n`);
  await mkdir(join(cwd, "site"), { recursive: true });
  await writeFile(join(cwd, "site", "sitecustomize.py"), SLOW_READ);
  return { PYTHONPATH: join(cwd, "site") };
}

for (const [name, num] of [["SIGTERM", 15], ["SIGINT", 2], ["SIGHUP", 1]] as const) {
  test(`recovery_key_scan stops on ${name}: one partial JSON answer, exit ${128 + num}, a closed values file, no temporary file`, async () => {
    await withCwd(async (cwd) => {
      const env = await slowTree(cwd);
      const outDir = join(cwd, "out");
      await mkdir(outDir);
      const started = Date.now();
      const run = await signalled(SCAN, cwd, { path: "work/ev", write_values: true, limit: 2 }, { ...env, JOB_ID: "j000020", OUT: outDir, SECRET_OUTPUT: "1" }, name, async () => Date.now() - started > 900);
      assert.doesNotMatch(run.stderr, /Traceback/);
      assert.equal(run.code, 128 + num, run.stdout);
      const got = JSON.parse(run.stdout) as Json;
      assert.deepEqual([got.status, got.interrupted], ["partial", true]);
      assert.equal(got.stopped_by, `stopped by signal ${num}`);
      assert.ok(got.coverage.files_attempted >= 1 && got.coverage.entries_not_started >= 1);
      // The values file holds whole rows only, as many as the answer says.
      const lines = (await readFile(join(outDir, "recovery-passwords.jsonl"), "utf8")).trimEnd().split("\n").filter(Boolean);
      assert.equal(lines.length, got.secret_values.written);
      for (const line of lines) JSON.parse(line);
      const left = (await readdir(outDir, { recursive: true })).filter((n) => /(^|\/)\./.test(n));
      assert.deepEqual(left, [], "a temporary file was left in the sealed output");
    });
  });
}

test("recovery_key_scan stops hard when a read never returns: the temporary files go, the answer says interrupted", async () => {
  await withCwd(async (cwd) => {
    const env = await slowTree(cwd, 4);
    for (let i = 0; i < 6; i++) await writeFile(join(cwd, "work", "ev", `n${i}.txt`), `${recoveryKey()}\n`);
    const outDir = join(cwd, "out");
    await mkdir(outDir);
    const started = Date.now();
    const run = await signalled(SCAN, cwd, { path: "work/ev", limit: 1 }, { ...env, SLOW_PAUSE: "40", JOB_ID: "j000021", OUT: outDir }, "SIGTERM", async () => Date.now() - started > 900);
    assert.equal(run.code, 143, run.stdout + run.stderr);
    assert.equal((JSON.parse(run.stdout) as Json).status, "interrupted");
    assert.deepEqual((await readdir(outDir, { recursive: true })).filter((n) => /(^|\/)\./.test(n)), []);
  });
});

test("recovery_key_scan answers carry status and status_basis, and a clean tree is complete", async () => {
  await withCwd(async (cwd) => {
    await mkdir(join(cwd, "work", "ev"), { recursive: true });
    await writeFile(join(cwd, "work", "ev", "a.txt"), "nothing here\n");
    const clean = answer(await tool(SCAN, cwd, { path: "work/ev" }));
    assert.deepEqual([clean.status, clean.interrupted], ["complete", undefined]);
    await symlink(join(cwd, "work", "ev", "a.txt"), join(cwd, "work", "ev", "link.txt"));
    const withLink = answer(await tool(SCAN, cwd, { path: "work/ev" }));
    assert.equal(withLink.status, "partial");
    assert.match(withLink.status_basis, /entries skipped/);
    for (const args of [{ path: "work/none" }, { path: "work/ev", limit: 0 }, { path: "work/ev", max_seconds: 541 }, { path: "work/ev", max_seconds: "9" }, { path: "work/ev", write_values: "yes" }]) refused(await tool(SCAN, cwd, args));
  });
});

test("recovery_key_scan withholds identifier- and secret-shaped path components, as the names block says", async () => {
  await withCwd(async (cwd) => {
    const id = pick("0123456789abcdef", 32);
    const dec = pick(DIGITS, 12);
    const pw = passwordAssignment();
    await mkdir(join(cwd, "work", "ev", id), { recursive: true });
    await writeFile(join(cwd, "work", "ev", id, "bitlocker recovery key.txt"), `the key ${recoveryKey()}\n`);
    await writeFile(join(cwd, "work", "ev", `README_${dec}.txt`), "x\n");
    await writeFile(join(cwd, "work", "ev", `${pw}.pem`), "x\n");
    const out = await tool(SCAN, cwd, { path: "work/ev", limit: 1 });
    const scan = answer(out);
    let printed = out.stdout;
    for (const page of Object.values(scan.pages) as Json[]) if (page.all_results) printed += await readFile(join(cwd, page.all_results), "utf8");
    for (const secret of [id, dec, pw, pw.slice(9)]) assert.ok(!printed.includes(secret), `${secret.slice(0, 8)}... is printed`);
    assert.ok(printed.includes("<identifier-shaped text withheld>/bitlocker recovery key.txt"));
    assert.ok(scan.paths_withheld >= 3);
    assert.match(scan.paths_note, /by shape/);
  });
});

test("recovery_key_scan never replaces a paging file that is there with a smaller one", async () => {
  await withCwd(async (cwd) => {
    await mkdir(join(cwd, "work", "ev"), { recursive: true });
    for (let i = 0; i < 6; i++) await writeFile(join(cwd, "work", "ev", `n${i}.txt`), `${recoveryKey()}\n`);
    const first = answer(await tool(SCAN, cwd, { path: "work/ev", limit: 2 }));
    const kept = join(cwd, first.pages.findings.all_results);
    const before = await readFile(kept, "utf8");
    // The same call again leaves the same bytes under the same name; a smaller read leaves the earlier file as it was.
    const again = answer(await tool(SCAN, cwd, { path: "work/ev", limit: 2 }));
    assert.equal(again.pages.findings.all_results, first.pages.findings.all_results);
    await writeFile(kept, before + before);
    const smaller = answer(await tool(SCAN, cwd, { path: "work/ev", limit: 2 }));
    assert.notEqual(smaller.pages.findings.all_results, first.pages.findings.all_results);
    assert.equal(await readFile(kept, "utf8"), before + before);
  });
});

test("recovery_key_scan, with its first layer removed, is held by the output check on the paths it prints", async () => {
  await withCwd(async (cwd) => {
    const key = recoveryKey();
    await mkdir(join(cwd, "work", "ev", key), { recursive: true });
    await writeFile(join(cwd, "work", "ev", key, "a.txt"), `the key ${recoveryKey()}\n`);
    const driver = String.raw`
import io, json, os, sys
os.chdir(sys.argv[2])
src = open(sys.argv[1], encoding="utf-8").read()
ns = {"__name__": "tool"}
exec(compile(src, sys.argv[1], "exec"), ns)
ns["_judge"] = lambda t, whole: (t, False)          # the first layer is gone
sys.stdin = io.StringIO(json.dumps({"path": "work/ev"}))
ns["main"]()
`;
    const run = await runPySnippet(driver, [SCAN, cwd], null);
    assert.equal(run.code, 0, run.stderr + run.stdout);
    assert.ok(!run.stdout.includes(key.slice(0, 13)), "a recovery-password-shaped path was printed");
    const out = JSON.parse(run.stdout) as Json;
    assert.ok(out.output_check.replaced >= 1);
    assert.equal(out.status, "partial");
  });
});

const HUNT_SCAN = String.raw`
import importlib.util, json, re, sys, time
spec = importlib.util.spec_from_file_location("rks", sys.argv[1]); mod = importlib.util.module_from_spec(spec); spec.loader.exec_module(mod)
def w(s): return b"".join(bytes([c, 0]) for c in s)
def gens(n):
    yield b"-" * n
    yield b"-123456" * (n // 7)
    yield b"1234567-" * (n // 8)
    yield (b"123456-" * (n // 7))
    yield b"-\x00" * (n // 2)
    yield w(b"123456-") * (n // 14)
    yield b"0\x00" * (n // 2)
    yield b"-----BEGIN " * (n // 11)
    yield b"-----BEGIN " + b"AA " * (n // 3)
    yield b"-----BEGIN RSA " * (n // 15)
    yield b"1" * n
out = []
for n in (4096, 32768):
    worst = 0.0
    for g in gens(n):
        t0 = time.process_time()
        list(mod.ascii_hits(g)); list(mod.utf16_hits(g)); list(mod.PEM.finditer(g))
        worst = max(worst, time.process_time() - t0)
    out.append([n, round(worst, 3)])
print(json.dumps(out))
`;

test("the scanner's patterns are linear on 4,096 and 32,768 bytes of the shapes that make a search by dash work hardest", async () => {
  const run = await runPySnippet(HUNT_SCAN, [SCAN], null);
  assert.equal(run.code, 0, run.stderr);
  const rows = JSON.parse(run.stdout) as Array<[number, number]>;
  for (const [n, worst] of rows) assert.ok(worst < 1, `${n} bytes took ${worst} s`);
  assert.ok(rows[1][1] < Math.max(0.05, rows[0][1] * 30), "the time grows faster than the size");
});
