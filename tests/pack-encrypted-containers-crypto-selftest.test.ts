/**
 * crypto_selftest: the image's readers proved on synthetic samples. The samples the tool writes are checked here against the formats' own
 * layouts (the LUKS1 on-disk header, the LUKS2 header with its SHA-256 checksum, the BitLocker boot sector with its three metadata block
 * offsets, the Core Storage signature, the APFS container superblock with its Fletcher-64 object checksum, a ZIP with the WinZip AES
 * extra field 0x9901, a fixed VHD footer), never against the tool's own reading. The readers are stand-ins that look at the sample they are
 * given; a stand-in proves the tool's verdicts (parsed, not parsed, unavailable, timed out), not any real build. The real readers and
 * modules are used only where the host has them (t.skip otherwise).
 */
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { mkdir, readFile, readdir, symlink, writeFile } from "node:fs/promises";
import { spawnSync } from "node:child_process";
import { join } from "node:path";
import { test } from "node:test";
import { type Json, asJob, body, filesUnder, gone, pidFile, refused, startDetached, stub, withCwd } from "./pack-network-harness.ts";
import { ROOT } from "./tool-library-harness.ts";
import { CLEAN } from "./host-gates.ts";

const SCRIPT = join(ROOT, "packs", "encrypted-containers", "tools", "crypto_selftest", "run.py");
const SAMPLES = (cwd: string): string => join(cwd, "out", "tool-output", "crypto_selftest-samples");

/** A stand-in reader: succeeds with `marker` when the last argument is a file that starts with `magicHex` at `at`, else prints noise. */
const reader = (version: string, versionFlag: string, at: number, magicHex: string, marker: string): string => `#!/bin/sh
if [ "$1" = "${versionFlag}" ]; then echo "${version}"; exit 0; fi
for last; do :; done
got=$(dd if="$last" bs=1 skip=${at} count=${magicHex.length / 2} 2>/dev/null | od -An -tx1 | tr -d ' \\n')
if [ "$got" = "${magicHex}" ]; then printf '%s\\n' "${marker}"; exit 0; fi
echo "unreadable"; exit 0
`;

const ALL_READERS = async (bin: string): Promise<void> => {
  await stub(bin, "cryptsetup", `#!/bin/sh
if [ "$1" = "--version" ]; then echo "cryptsetup 2.6.1"; exit 0; fi
for last; do :; done
head=$(dd if="$last" bs=1 count=8 2>/dev/null | od -An -tx1 | tr -d ' \\n')
case "$head" in
  4c554b53babe0001) printf 'Version:       1\\nKey Slot 0: ENABLED\\n'; exit 0 ;;
  4c554b53babe0002) printf '{"keyslots":{"0":{}},"segments":{"0":{}}}'; exit 0 ;;
esac
echo bad; exit 0
`);
  await stub(bin, "bdeinfo", reader("bdeinfo 20221031", "-V", 3, "2d4656452d46532d", "Key protector 0:"));
  await stub(bin, "fvdeinfo", reader("fvdeinfo 20221030", "-V", 88, "4353", "Core Storage information:"));
  await stub(bin, "fsapfsinfo", reader("fsapfsinfo 20221031", "-V", 32, "4e585342", "Container information: number of volumes"));
};

test("every reader that parses the sample it should read is parsed, the others are not, and a missing one is unavailable and named", async () => {
  await withCwd(async (cwd, bin) => {
    await ALL_READERS(bin);
    await stub(bin, "fvdeinfo", `#!/bin/sh\nif [ "$1" = "-V" ]; then echo "fvdeinfo 20221030"; exit 0; fi\necho "no idea"; exit 0\n`);
    await stub(bin, "bdeinfo", `#!/bin/sh\nif [ "$1" = "-V" ]; then echo "bdeinfo 20221031"; exit 0; fi\necho "failed" >&2; exit 1\n`);
    const a = body(await asJob(SCRIPT, cwd, {}, bin, { PATH: `${bin}:/usr/bin:/bin` }));
    assert.equal(a.status, CLEAN, a.status_basis);   // (a host that cannot adopt orphans cannot show that the programs left none: partial, which the answer says)
    const pair = (program: string, format: RegExp): Json => a.records.find((r: Json) => r.kind === "pair" && r.program === program && format.test(r.format));
    assert.equal(pair("cryptsetup", /LUKS1/).result, "parsed");
    assert.equal(pair("cryptsetup", /LUKS2/).result, "parsed");
    assert.equal(pair("cryptsetup", /LUKS1/).version, "cryptsetup 2.6.1");
    assert.equal(pair("bdeinfo", /BitLocker/).result, "not parsed");
    assert.equal(pair("bdeinfo", /BitLocker/).exit_code, 1);
    assert.equal(pair("fvdeinfo", /Core/).result, "not parsed");
    assert.equal(pair("fsapfsinfo", /APFS/).result, "parsed");
    assert.equal(a.summary.parsed >= 3, true);
    // Hermetic: the tool looks on PATH and then in EXTRA_PATH (/usr/sbin:/sbin:/usr/local/sbin), and a runner may have a real
    // cryptsetup, bdeinfo or the like in any of them. So it runs from a copy whose EXTRA_PATH names an empty directory, with a
    // PATH that holds only the interpreter (a link to python3).
    const empty = join(cwd, "no-reader");
    const only = join(cwd, "python-only");
    await mkdir(empty, { recursive: true });
    await mkdir(only, { recursive: true });
    const py = spawnSync("python3", ["-c", "import sys; print(sys.executable)"], { encoding: "utf8" }).stdout.trim();
    assert.ok(py.startsWith("/"), "the interpreter is found");
    await symlink(py, join(only, "python3"));
    const source = await readFile(SCRIPT, "utf8");
    const line = 'EXTRA_PATH = "/usr/sbin:/sbin:/usr/local/sbin"';
    assert.equal(source.split(line).length, 2, "the tool names its extra search path once");
    const copy = join(cwd, "crypto_selftest_no_reader.py");
    await writeFile(copy, source.replace(line, `EXTRA_PATH = ${JSON.stringify(empty)}`));
    const missing = body(await asJob(copy, cwd, {}, undefined, { PATH: only }));
    for (const p of ["cryptsetup", "bdeinfo", "fvdeinfo", "fsapfsinfo"]) {
      const r = missing.records.find((x: Json) => x.program === p);
      assert.equal(r.result, "unavailable");
      assert.match(r.why, new RegExp(`${p} is not on PATH`));
    }
  });
});

test("a module that is not installed is named, not run, and never importable", async () => {
  await withCwd(async (cwd, bin) => {
    const a = body(await asJob(SCRIPT, cwd, {}, bin, { PATH: "/usr/bin:/bin" }));
    const mods = a.records.filter((r: Json) => r.kind === "module");
    assert.deepEqual(mods.map((m: Json) => m.module), ["pybde", "pyvhdi", "pyluksde", "pytsk3", "dfvfs", "pyAesCrypt"]);
    for (const m of mods) {
      if (m.importable) continue;
      assert.equal(m.open_test, "not run");
      assert.equal(m.version, null);
    }
    assert.equal(a.summary.modules, 6);
  });
});

test("the samples are the formats' headers: LUKS1 and LUKS2 (with a valid checksum), BitLocker, Core Storage, APFS (with a valid Fletcher-64), ZIP AES, VHD", async () => {
  await withCwd(async (cwd, bin) => {
    body(await asJob(SCRIPT, cwd, {}, bin));
    const dir = SAMPLES(cwd);
    const luks1 = await readFile(join(dir, "luks1.img"));
    assert.equal(luks1.subarray(0, 6).toString("latin1"), "LUKS\xba\xbe");
    assert.equal(luks1.readUInt16BE(6), 1);
    assert.equal(luks1.readUInt32BE(208), 0x00ac71f3);
    assert.equal(luks1.readUInt32BE(208 + 48), 0x0000dead);
    const luks2 = await readFile(join(dir, "luks2.img"));
    for (const [start, magic] of [[0, "LUKS\xba\xbe"], [16384, "SKUL\xba\xbe"]] as const) {
      const blk = Buffer.from(luks2.subarray(start, start + 16384));
      assert.equal(blk.subarray(0, 6).toString("latin1"), magic);
      assert.equal(blk.readUInt16BE(6), 2);
      assert.equal(blk.readBigUInt64BE(8), 16384n);
      const csum = Buffer.from(blk.subarray(448, 480));
      blk.fill(0, 448, 512);
      assert.deepEqual(createHash("sha256").update(blk).digest(), csum, "the header checksum covers the header with its checksum field zeroed");
      const json = JSON.parse(blk.subarray(4096).toString("utf8").replace(/\0+$/, "")) as Json;
      assert.equal(json.config.json_size, "12288");
      assert.equal(json.segments["0"].type, "crypt");
    }
    const bl = await readFile(join(dir, "bitlocker.img"));
    assert.equal(bl.subarray(3, 11).toString("latin1"), "-FVE-FS-");
    for (const i of [0, 1, 2]) assert.equal(bl.subarray(Number(bl.readBigUInt64LE(176 + 8 * i)), Number(bl.readBigUInt64LE(176 + 8 * i)) + 8).toString("latin1"), "-FVE-FS-");
    assert.equal((await readFile(join(dir, "corestorage.img"))).subarray(88, 90).toString("latin1"), "CS");
    const apfs = await readFile(join(dir, "apfs.img"));
    assert.equal(apfs.subarray(32, 36).toString("latin1"), "NXSB");
    assert.equal(apfs.readBigUInt64LE(1264), 4n);
    let s1 = 0n, s2 = 0n;
    const mod = 0xffffffffn;
    for (let i = 8; i < 4096; i += 4) { s1 = (s1 + BigInt(apfs.readUInt32LE(i))) % mod; s2 = (s2 + s1) % mod; }
    const c1 = mod - ((s1 + s2) % mod);
    const c2 = mod - ((s1 + c1) % mod);
    assert.equal(apfs.readBigUInt64LE(0), (c2 << 32n) | c1, "the object checksum is Fletcher-64 over the block without its first 8 bytes");
    const zip = await readFile(join(dir, "zip-aes.zip"));
    assert.equal(zip.readUInt32LE(0), 0x04034b50);
    assert.equal(zip.readUInt16LE(8), 99, "compression method 99 marks WinZip AES");
    assert.ok(zip.includes(Buffer.from([0x01, 0x99, 0x07, 0x00, 0x02, 0x00, 0x41, 0x45, 0x03, 0x00, 0x00])), "the 0x9901 extra field: AE-2, vendor AE, strength 3, method stored");
    assert.equal((await readFile(join(dir, "fixed.vhd"))).subarray(-512, -504).toString("latin1"), "conectix");
  });
});

test("run twice in one job: the same bytes keep their names, and a file already at a sample's name is never replaced", async () => {
  await withCwd(async (cwd, bin) => {
    const first = body(await asJob(SCRIPT, cwd, {}, bin));
    const before = await readdir(SAMPLES(cwd));
    const second = body(await asJob(SCRIPT, cwd, {}, bin));
    assert.deepEqual(await readdir(SAMPLES(cwd)), before, "a rerun adds no file");
    assert.deepEqual(second.samples, first.samples);
    await writeFile(join(SAMPLES(cwd), "luks1.img"), "someone else's file");
    const third = body(await asJob(SCRIPT, cwd, {}, bin));
    assert.equal(await readFile(join(SAMPLES(cwd), "luks1.img"), "utf8"), "someone else's file");
    assert.match(third.samples.luks1, /luks1-2\.img$/);
    assert.deepEqual((await filesUnder(join(cwd, "out"))).filter((f) => f.includes(".cs-")), [], "no temporary file is left");
  });
});

test("john: the helpers on PATH are listed by name with the banner, and nothing is run but john", async () => {
  await withCwd(async (cwd, bin) => {
    await stub(bin, "john", `#!/bin/sh\necho "John the Ripper 1.9.0-jumbo-1 [linux-gnu 64-bit x86_64]"\n`);
    await stub(bin, "zip2john", "echo ran > /tmp/zip2john-was-run\n");
    await stub(bin, "office2john.py", "echo ran > /tmp/zip2john-was-run\n");
    const a = body(await asJob(SCRIPT, cwd, {}, bin, { PATH: `${bin}:/usr/bin:/bin` }));
    assert.equal(a.john.john, true);
    assert.deepEqual(a.john.helpers_on_path, ["office2john.py", "zip2john"]);
    assert.equal(a.john.jumbo, true);
    assert.match(a.john.banner, /^John the Ripper 1\.9\.0-jumbo-1/);
    assert.equal(spawnSync("test", ["-e", "/tmp/zip2john-was-run"]).status, 1, "a helper was only listed");
  });
});

test("a reader that does not answer is timed out and ended, the answer is partial, and nothing is left running", async () => {
  await withCwd(async (cwd, bin) => {
    const pid = join(cwd, "r.pid");
    await ALL_READERS(bin);
    await stub(bin, "fsapfsinfo", `#!/bin/sh\nif [ "$1" = "-V" ]; then echo "fsapfsinfo 1"; exit 0; fi\necho $$ > "${pid}"\nsleep 120\n`);
    const started = Date.now();
    const a = body(await asJob(SCRIPT, cwd, { max_seconds: 6 }, bin, { PATH: `${bin}:/usr/bin:/bin` }));
    assert.ok(Date.now() - started < 30_000);
    assert.equal(a.status, "partial");
    assert.ok(await gone(await pidFile(pid)));
  });
});

test("SIGTERM during a reader: one document, exit 143, the reader gone, no temporary file", async () => {
  await withCwd(async (cwd, bin) => {
    const pid = join(cwd, "r.pid");
    await stub(bin, "bdeinfo", `#!/bin/sh\nif [ "$1" = "-V" ]; then echo "bdeinfo 1"; exit 0; fi\necho $$ > "${pid}"\nsleep 120\n`);
    await mkdir(join(cwd, "out"), { recursive: true });
    const run = startDetached(SCRIPT, cwd, {}, { JOB_ID: "j1", OUT: join(cwd, "out") }, bin);
    const r = await pidFile(pid);
    run.signal("SIGTERM");
    assert.equal(await run.closed, 143);
    assert.equal(run.stdout().trim().split("\n").filter(Boolean).length, 1);
    const a = JSON.parse(run.stdout());
    assert.equal(a.status, "failed");
    assert.equal(a.interrupted, true);
    assert.ok(await gone(r));
    assert.deepEqual((await filesUnder(join(cwd, "out"))).filter((f) => f.includes(".cs-")), []);
  });
});

test("hostile parameters are JSON refusals", async () => {
  await withCwd(async (cwd, bin) => {
    for (const args of [{ max_seconds: 0 }, { max_seconds: 10 ** 12 }, { max_seconds: "9" }, { max_seconds: true }, { limit: 0 }, { limit: 10 ** 9 }, { limit: [] }, [], "x", 3, null]) {
      const a = refused(await asJob(SCRIPT, cwd, args, bin));
      assert.equal(a.status, "failed", JSON.stringify(args));
    }
    assert.equal(refused(await asJob(SCRIPT, cwd, "[".repeat(300000), bin)).status, "failed");
  });
});

test("the real pyAesCrypt and pytsk3 are exercised where the host has them", async (t) => {
  const have = (m: string): boolean => spawnSync("python3", ["-c", `import ${m}`]).status === 0;
  if (!have("pyAesCrypt") && !have("pytsk3")) {
    t.skip("neither pyAesCrypt nor pytsk3 is importable on this host");
    return;
  }
  await withCwd(async (cwd, bin) => {
    const a = body(await asJob(SCRIPT, cwd, {}, bin));
    for (const m of ["pyAesCrypt", "pytsk3"]) {
      if (!have(m)) continue;
      const row = a.records.find((r: Json) => r.module === m);
      assert.equal(row.importable, true);
      assert.equal(row.open_test, "passed", JSON.stringify(row));
    }
  });
});

test("the tool carries the shared blocks of its lineage byte for byte, STOP first, and starts nothing in a session of its own", async () => {
  const text = await readFile(SCRIPT, "utf8");
  const probe = await readFile(join(ROOT, "packs", "encrypted-containers", "tools", "archive_probe", "run.py"), "utf8");
  const cut = (t: string, n: string): string => t.slice(t.indexOf(`# BEGIN SHARED ${n}`), t.indexOf(`# END SHARED ${n}`));
  for (const n of ["STOP", "PLACE", "PAGE", "WITHHOLDING", "NAMES", "PROCESS"]) assert.equal(cut(text, n), cut(probe, n), n);
  for (const n of ["PLACE", "PAGE", "WITHHOLDING", "NAMES", "PROCESS"]) assert.ok(text.indexOf("# BEGIN SHARED STOP") < text.indexOf(`# BEGIN SHARED ${n}`), n);
  assert.doesNotMatch(text.replace(/^\s*#.*$/gm, "").replace(/"""[\s\S]*?"""/g, ""), /start_new_session|setsid|process_group/);
});
