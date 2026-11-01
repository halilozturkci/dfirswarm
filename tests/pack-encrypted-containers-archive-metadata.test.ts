/**
 * archive_metadata: the protection of a 7-Zip or RAR archive, structurally and through 7z, and the listing of a ZIP; never an extraction.
 * RAR 4 and RAR 5 archives and the ZIP are built here from the formats' block layouts (the RAR 4 and RAR 5 technical notes: block header with
 * CRC, type, flags and size; RAR 5's variable-length integers), 7-Zip archives are made by the host's own 7z where it is installed (t.skip
 * otherwise), never by the tool under test. Held: header-encrypted against payload-encrypted 7-Zip, RAR 4 and RAR 5 headers (the
 * password flag, the archive encryption header, a file's encryption record), a set of volumes with a missing volume named, a zip-bomb shape
 * counted and nothing unpacked, 7z not installed named, a forged CRC or size partial, lossless paging, hostile parameters, special files
 * and a stop signal that leaves one document and no 7z.
 */
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { mkdir, readFile, readdir, symlink, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { test } from "node:test";
import { type Json, asJob, body, gone, pidFile, refused, startDetached, stub, withCwd } from "./pack-network-harness.ts";
import { ROOT } from "./tool-library-harness.ts";

const SCRIPT = join(ROOT, "packs", "encrypted-containers", "tools", "archive_metadata", "run.py");
const HAVE_7Z = spawnSync("sh", ["-c", "command -v 7z"]).status === 0;

function crc32(buf: Buffer): number {
  let c = ~0 >>> 0;
  for (const b of buf) {
    c ^= b;
    for (let k = 0; k < 8; k++) c = (c >>> 1) ^ (0xedb88320 & -(c & 1));
  }
  return ~c >>> 0;
}

// --- RAR 4 -------------------------------------------------------------------------------------------------------
const RAR4_SIG = Buffer.from("526172211a0700", "hex");
function rar4Block(type: number, flags: number, rest: Buffer): Buffer {
  const hdr = Buffer.alloc(7 + rest.length);
  hdr.writeUInt8(type, 2);
  hdr.writeUInt16LE(flags, 3);
  hdr.writeUInt16LE(hdr.length, 5);
  rest.copy(hdr, 7);
  hdr.writeUInt16LE(crc32(hdr.subarray(2)) & 0xffff, 0);
  return hdr;
}
const rar4Main = (flags = 0): Buffer => rar4Block(0x73, flags, Buffer.alloc(6));
function rar4File(name: string, packed: number, unpacked: number, flags = 0x8000): Buffer {
  const rest = Buffer.alloc(25 + name.length);
  rest.writeUInt32LE(packed, 0);
  rest.writeUInt32LE(unpacked, 4);
  rest.writeUInt8(3, 8);
  rest.writeUInt8(0x33, 18);
  rest.writeUInt16LE(name.length, 19);
  rest.write(name, 25, "latin1");
  return Buffer.concat([rar4Block(0x74, flags, rest), Buffer.alloc(packed, 0x41)]);
}
const rar4End = (flags = 0): Buffer => rar4Block(0x7b, flags, Buffer.alloc(0));

// --- RAR 5 -------------------------------------------------------------------------------------------------------
const RAR5_SIG = Buffer.from("526172211a070100", "hex");
function vint(n: number): Buffer {
  const out: number[] = [];
  do {
    let b = n & 0x7f;
    n = Math.floor(n / 128);
    if (n) b |= 0x80;
    out.push(b);
  } while (n);
  return Buffer.from(out);
}
function rar5Block(type: number, flags: number, fields: Buffer[], extra?: Buffer, data = 0): Buffer {
  const parts = [vint(type), vint(flags | (extra ? 1 : 0) | (data ? 2 : 0))];
  if (extra) parts.push(vint(extra.length));
  if (data) parts.push(vint(data));
  const body = Buffer.concat([...parts, ...fields, ...(extra ? [extra] : [])]);
  const sized = Buffer.concat([vint(body.length), body]);
  const crc = Buffer.alloc(4);
  crc.writeUInt32LE(crc32(sized));
  return Buffer.concat([crc, sized, Buffer.alloc(data, 0x42)]);
}
const rar5Main = (): Buffer => rar5Block(1, 0, [vint(0)]);
function rar5File(name: string, packed: number, unpacked: number, encrypted = false): Buffer {
  const extra = encrypted ? Buffer.concat([vint(3), vint(1), vint(0)]) : undefined;
  return rar5Block(2, 0, [vint(0), vint(unpacked), vint(0), vint(0), vint(3), vint(name.length), Buffer.from(name)], extra, packed);
}
const rar5End = (flags = 0): Buffer => rar5Block(5, 0, [vint(flags)]);

// --- ZIP ---------------------------------------------------------------------------------------------------------
function zip(entries: Array<{ name: string; packed: number; unpacked: number; aes?: boolean }>): Buffer {
  const locals: Buffer[] = [];
  const centrals: Buffer[] = [];
  let at = 0;
  for (const e of entries) {
    const name = Buffer.from(e.name);
    const extra = e.aes ? Buffer.from("01990700020041450300" + "00", "hex") : Buffer.alloc(0);
    const local = Buffer.alloc(30);
    local.writeUInt32LE(0x04034b50, 0);
    local.writeUInt16LE(51, 4);
    local.writeUInt16LE(e.aes ? 1 : 0, 6);
    local.writeUInt16LE(e.aes ? 99 : 8, 8);
    local.writeUInt32LE(e.packed, 18);
    local.writeUInt32LE(e.unpacked, 22);
    local.writeUInt16LE(name.length, 26);
    local.writeUInt16LE(extra.length, 28);
    const data = Buffer.alloc(e.packed, 0x43);
    const central = Buffer.alloc(46);
    central.writeUInt32LE(0x02014b50, 0);
    central.writeUInt16LE(51, 4);
    central.writeUInt16LE(51, 6);
    central.writeUInt16LE(e.aes ? 1 : 0, 8);
    central.writeUInt16LE(e.aes ? 99 : 8, 10);
    central.writeUInt32LE(e.packed, 20);
    central.writeUInt32LE(e.unpacked, 24);
    central.writeUInt16LE(name.length, 28);
    central.writeUInt16LE(extra.length, 30);
    central.writeUInt32LE(at, 42);
    const l = Buffer.concat([local, name, extra, data]);
    locals.push(l);
    centrals.push(Buffer.concat([central, name, extra]));
    at += l.length;
  }
  const cd = Buffer.concat(centrals);
  const eocd = Buffer.alloc(22);
  eocd.writeUInt32LE(0x06054b50, 0);
  eocd.writeUInt16LE(entries.length, 8);
  eocd.writeUInt16LE(entries.length, 10);
  eocd.writeUInt32LE(cd.length, 12);
  eocd.writeUInt32LE(at, 16);
  return Buffer.concat([...locals, cd, eocd]);
}

const call = (cwd: string, args: Json, bin?: string, env: Record<string, string> = {}): Promise<Json> => asJob(SCRIPT, cwd, args, bin, env).then(body);
const put = (cwd: string, name: string, data: Buffer | string): Promise<void> => writeFile(join(cwd, name), data);
function make7z(cwd: string, name: string, args: string[]): void {
  const r = spawnSync("7z", ["a", ...args, name, "a.txt"], { cwd, encoding: "utf8" });
  assert.equal(r.status, 0, r.stdout + r.stderr);
}

test("7-Zip: a payload-encrypted archive reads its names and flags the members; a header-encrypted one needs the password for the names", async (t) => {
  if (!HAVE_7Z) return t.skip("7z is not installed on this host");
  await withCwd(async (cwd) => {
    await put(cwd, "a.txt", "hello hello hello\n");
    make7z(cwd, "payload.7z", ["-p" + "x".repeat(3) + "yz"]);
    make7z(cwd, "header.7z", ["-p" + "x".repeat(3) + "yz", "-mhe=on"]);
    make7z(cwd, "plain.7z", []);
    const p = await call(cwd, { path: "payload.7z" });
    assert.equal(p.status, "complete", p.status_basis);
    assert.equal(p.format, "7z");
    assert.equal(p.protection.header_encrypted, false);
    assert.equal(p.protection.members_encrypted, 1);
    assert.equal(p.members_listed, true);
    assert.equal(p.records[0].encrypted, true);
    assert.equal(p.structural.start_header_crc_ok, true);
    assert.equal(p.structural.next_header_crc_ok, true);
    const h = await call(cwd, { path: "header.7z" });
    assert.equal(h.status, "complete", h.status_basis);
    assert.equal(h.protection.header_encrypted, true);
    assert.deepEqual(h.structural.header_coders, ["06f10701"]);
    assert.equal(h.members_listed, false);
    assert.equal(h.lister.status, "header_encrypted");
    const n = await call(cwd, { path: "plain.7z" });
    assert.equal(n.protection.members_encrypted, 0);
    assert.equal(n.protection.header_encrypted, false);
    assert.equal(n.lister.exit_code, 0);
  });
});

test("7-Zip: a forged start header, a cut copy and the first volume of a split set are partial, with the missing volume named", async (t) => {
  if (!HAVE_7Z) return t.skip("7z is not installed on this host");
  await withCwd(async (cwd) => {
    await put(cwd, "a.txt", "hello\n".repeat(100));
    make7z(cwd, "ok.7z", []);
    const good = await readFile(join(cwd, "ok.7z"));
    const forged = Buffer.from(good);
    forged[20] ^= 0xff;
    await put(cwd, "forged.7z", forged);
    const f = await call(cwd, { path: "forged.7z" });
    assert.equal(f.status, "partial");
    assert.equal(f.structural.start_header_crc_ok, false);
    const cut = good.subarray(0, good.length - 10);
    await put(cwd, "cut.7z", cut);
    const c = await call(cwd, { path: "cut.7z" });
    assert.equal(c.status, "partial");
    assert.match(c.status_basis, /past the end/);
    await put(cwd, "set.7z.001", cut);
    const s = await call(cwd, { path: "set.7z.001" });
    assert.equal(s.volumes.next_volume_expected, true);
    assert.equal(s.volumes.next_volume_name, "set.7z.002");
    assert.equal(s.volumes.next_volume_present, false);
    assert.equal(s.status, "partial");
    assert.match(s.inconsistencies.join(" "), /set\.7z\.002 is not beside this file/);
  });
});

test("RAR 4: the password flag, a file's encrypted flag, the CRC, the end block", async () => {
  await withCwd(async (cwd) => {
    await put(cwd, "ok.rar", Buffer.concat([RAR4_SIG, rar4Main(), rar4File("secret.txt", 16, 100, 0x8004), rar4File("open.txt", 8, 8), rar4End()]));
    const a = await call(cwd, { path: "ok.rar" });
    assert.equal(a.status, "complete", a.status_basis);
    assert.equal(a.format, "RAR4");
    assert.deepEqual(a.records.map((r: Json) => [r.name, r.encrypted, r.bytes, r.packed]), [["secret.txt", true, 100, 16], ["open.txt", false, 8, 8]]);
    assert.equal(a.structural.end_block, true);
    assert.equal(a.protection.header_encrypted, false);
    assert.equal(a.protection.members_encrypted, 1);
    await put(cwd, "hdr.rar", Buffer.concat([RAR4_SIG, rar4Main(0x80), Buffer.alloc(64, 0x99)]));
    const h = await call(cwd, { path: "hdr.rar" });
    assert.equal(h.status, "complete", h.status_basis);
    assert.equal(h.protection.header_encrypted, true);
    assert.equal(h.structural.headers_encrypted, true);
    const bad = Buffer.concat([RAR4_SIG, rar4Main(), rar4File("a", 4, 4), rar4End()]);
    bad[7 + 13 + 7 + 2] ^= 0x40;   // a byte of the file header's body
    await put(cwd, "bad.rar", bad);
    const b = await call(cwd, { path: "bad.rar" });
    assert.equal(b.status, "partial");
    assert.match(b.inconsistencies.join(" "), /fail their CRC/);
    await put(cwd, "cut.rar", Buffer.concat([RAR4_SIG, rar4Main(), rar4File("a", 4, 4)]));
    assert.equal((await call(cwd, { path: "cut.rar" })).status, "partial");
    await put(cwd, "trunc.rar", Buffer.concat([RAR4_SIG, rar4Main(), rar4File("a", 400, 4)]).subarray(0, 120));
    assert.equal((await call(cwd, { path: "trunc.rar" })).status, "partial");
  });
});

test("RAR 4 volumes: a set whose next volume is missing is named, and complete once it is there", async () => {
  await withCwd(async (cwd) => {
    await put(cwd, "a.part1.rar", Buffer.concat([RAR4_SIG, rar4Main(0x0101), rar4File("x.bin", 8, 100, 0x8002), rar4End(0x0001)]));
    const missing = await call(cwd, { path: "a.part1.rar" });
    assert.equal(missing.status, "partial");
    assert.equal(missing.volumes.next_volume_name, "a.part2.rar");
    assert.equal(missing.volumes.next_volume_present, false);
    await put(cwd, "a.part2.rar", Buffer.concat([RAR4_SIG, rar4Main(0x0101), rar4File("x.bin", 8, 100, 0x8001), rar4End()]));
    const there = await call(cwd, { path: "a.part1.rar" });
    assert.equal(there.volumes.next_volume_present, true);
    assert.equal(there.status, "complete", there.status_basis);
  });
});

test("RAR 5: the archive encryption header, a file's encryption record, the CRC32 of each header", async () => {
  await withCwd(async (cwd) => {
    await put(cwd, "ok.rar", Buffer.concat([RAR5_SIG, rar5Main(), rar5File("secret.txt", 16, 100, true), rar5File("open.txt", 8, 8), rar5End()]));
    const a = await call(cwd, { path: "ok.rar" });
    assert.equal(a.status, "complete", a.status_basis);
    assert.equal(a.format, "RAR5");
    assert.deepEqual(a.records.map((r: Json) => [r.name, r.encrypted, r.bytes, r.packed]), [["secret.txt", true, 100, 16], ["open.txt", false, 8, 8]]);
    await put(cwd, "hdr.rar", Buffer.concat([RAR5_SIG, rar5Block(4, 0, [vint(0), vint(15), Buffer.alloc(16), Buffer.alloc(1)]), Buffer.alloc(64, 0x77)]));
    const h = await call(cwd, { path: "hdr.rar" });
    assert.equal(h.status, "complete", h.status_basis);
    assert.equal(h.protection.header_encrypted, true);
    const bad = Buffer.concat([RAR5_SIG, rar5Main(), rar5File("a", 4, 4), rar5End()]);
    bad[8 + 4 + 8] ^= 0x20;
    await put(cwd, "bad.rar", bad);
    assert.equal((await call(cwd, { path: "bad.rar" })).status, "partial");
    await put(cwd, "vol.rar", Buffer.concat([RAR5_SIG, rar5Main(), rar5File("a", 4, 4), rar5End(1)]));
    const v = await call(cwd, { path: "vol.rar" });
    assert.equal(v.volumes.next_volume_expected, true);
    assert.equal(v.status, "partial");
  });
});

test("ZIP: listed through 7z with its AES method and encrypted flags, and the structure is named as archive_probe's", async (t) => {
  if (!HAVE_7Z) return t.skip("7z is not installed on this host");
  await withCwd(async (cwd) => {
    await put(cwd, "aes.zip", zip([{ name: "a.txt", packed: 40, unpacked: 6, aes: true }, { name: "b.txt", packed: 6, unpacked: 6 }]));
    const a = await call(cwd, { path: "aes.zip" });
    assert.equal(a.format, "ZIP");
    assert.equal(a.protection.members_encrypted, 1);
    assert.match(a.structural.structural_reader, /archive_probe reads the central directory/);
    assert.equal(a.records.find((r: Json) => r.name === "a.txt").encrypted, true);
  });
});

test("a zip-bomb shape is counted and nothing is unpacked: a member declared 4 GiB from 200 bytes", async (t) => {
  if (!HAVE_7Z) return t.skip("7z is not installed on this host");
  await withCwd(async (cwd) => {
    await put(cwd, "bomb.zip", zip([{ name: "big.bin", packed: 200, unpacked: 0xffffffff }]));
    const started = Date.now();
    const a = await call(cwd, { path: "bomb.zip" });
    assert.ok(Date.now() - started < 20_000);
    assert.equal(a.high_ratio_members_in_page, 1);
    assert.match(a.extraction_note, /Nothing is extracted/);
    assert.deepEqual((await readdir(cwd)).filter((f) => !["bomb.zip", "out", "bin", "inputs", "work"].includes(f)), [], "nothing is written beside the archive");
  });
});

test("7z not installed is named: a 7-Zip archive is partial with its headers read, a ZIP is unavailable, a RAR is read from its headers", async (t) => {
  if (!HAVE_7Z) return t.skip("7z is not installed on this host");
  await withCwd(async (cwd, bin) => {
    await put(cwd, "a.txt", "hello\n");
    make7z(cwd, "p.7z", ["-pabcdef"]);
    await put(cwd, "z.zip", zip([{ name: "a.txt", packed: 6, unpacked: 6 }]));
    await put(cwd, "r.rar", Buffer.concat([RAR4_SIG, rar4Main(), rar4File("a", 4, 4), rar4End()]));
    const py = spawnSync("sh", ["-c", "command -v python3"], { encoding: "utf8" }).stdout.trim();
    const only = join(cwd, "onlypy");
    await mkdir(only);
    await symlink(py, join(only, "python3"));
    const env = { PATH: only };
    const s = await call(cwd, { path: "p.7z" }, undefined, env);
    assert.equal(s.status, "partial");
    assert.match(s.status_basis, /7z is not on PATH/);
    assert.equal(s.structural.start_header_crc_ok, true);
    const z = await call(cwd, { path: "z.zip" }, undefined, env);
    assert.equal(z.status, "unavailable");
    assert.match(z.status_basis, /7z is not on PATH/);
    const r = await call(cwd, { path: "r.rar" }, undefined, env);
    assert.equal(r.status, "complete", r.status_basis);
    assert.equal(bin.length > 0, true);
  });
});

test("a RAR with a hundred thousand block headers is read in time, paged losslessly, and the whole is in the file", async () => {
  await withCwd(async (cwd) => {
    const files: Buffer[] = [];
    for (let i = 0; i < 100000; i++) files.push(rar4File("f" + i, 0, 0));
    await put(cwd, "many.rar", Buffer.concat([RAR4_SIG, rar4Main(), ...files, rar4End()]));
    const started = Date.now();
    const a = await call(cwd, { path: "many.rar", limit: 3 });
    assert.ok(Date.now() - started < 60_000, `${Date.now() - started} ms`);
    assert.equal(a.status, "complete", a.status_basis);
    assert.equal(a.returned, 3);
    assert.equal(a.matched, 100000);
    assert.equal(a.truncated, true);
    const whole = (await readdir(join(cwd, "out", "tool-output"))).find((f) => f.endsWith(".jsonl"));
    assert.ok(whole);
    assert.equal((await readFile(join(cwd, "out", "tool-output", whole as string), "utf8")).trim().split("\n").length, 100000);
  });
});

test("hostile parameters and special files are JSON refusals; a FIFO does not hold the tool", async () => {
  await withCwd(async (cwd) => {
    await put(cwd, "ok.rar", Buffer.concat([RAR4_SIG, rar4Main(), rar4End()]));
    await symlink(join(cwd, "ok.rar"), join(cwd, "link.rar"));
    assert.equal(spawnSync("mkfifo", [join(cwd, "pipe.rar")]).status, 0);
    await put(cwd, "empty.rar", "");
    await put(cwd, "text.rar", "this is not an archive");
    for (const args of [{}, { path: 5 }, { path: "" }, { path: "a\u0000b" }, { path: "x".repeat(5000) }, { path: "\ud800" }, { path: ["a"] }, { path: "ok.rar", limit: 0 }, { path: "ok.rar", limit: 10 ** 9 },
      { path: "ok.rar", max_seconds: 0 }, { path: "ok.rar", max_seconds: 10 ** 12 }, { path: "ok.rar", max_seconds: "1" }, [], "x", 5, null, { path: "link.rar" }, { path: "pipe.rar" }, { path: "." }, { path: "empty.rar" }, { path: "nothing.rar" }]) {
      const started = Date.now();
      const a = refused(await asJob(SCRIPT, cwd, args));
      assert.equal(a.status, "failed", JSON.stringify(args));
      assert.ok(Date.now() - started < 15_000, JSON.stringify(args));
    }
    assert.equal(refused(await asJob(SCRIPT, cwd, "[".repeat(300000))).status, "failed");
    const t = body(await asJob(SCRIPT, cwd, { path: "text.rar" }));
    assert.equal(t.supported, false);
    assert.equal(t.status, "partial");
  });
});

test("SIGTERM while 7z runs: one document, exit 143, 7z gone", async () => {
  await withCwd(async (cwd, bin) => {
    const pid = join(cwd, "z.pid");
    await stub(bin, "7z", `#!/bin/sh\necho $$ > "${pid}"\nsleep 120\n`);
    await put(cwd, "p.7z", Buffer.concat([Buffer.from("377abcaf271c0004", "hex"), Buffer.alloc(24)]));
    await mkdir(join(cwd, "out"), { recursive: true });
    const run = startDetached(SCRIPT, cwd, { path: "p.7z" }, { JOB_ID: "j1", OUT: join(cwd, "out") }, bin);
    const z = await pidFile(pid);
    run.signal("SIGTERM");
    assert.equal(await run.closed, 143);
    assert.equal(run.stdout().trim().split("\n").filter(Boolean).length, 1);
    assert.equal(JSON.parse(run.stdout()).interrupted, true);
    assert.ok(await gone(z));
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
