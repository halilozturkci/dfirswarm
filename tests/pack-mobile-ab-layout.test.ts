/**
 * ab_layout (mobile-forensics): an unencrypted Android backup mapped onto the layout ALEAPP reads, and called a derivative of an adb backup.
 *
 * The `.ab` fixtures are built from the format: the header `ANDROID BACKUP\n<version>\n<compressed>\n<encryption>\n` and a tar (ustar headers,
 * pax extended headers for long names) deflated with zlib. The members are named as AOSP's backup agent names them: `apps/<package>/_manifest`
 * and `apps/<package>/<domain>/<path>`. The domain tokens and their mapping are the table in the tool and its manifest; their basis is the
 * author's recollection of FullBackup's constants, which the manifest says and which has not been checked against the AOSP source.
 *
 * The tool is new in this change: on the base every test fails because the script does not exist.
 */
import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { createHash } from "node:crypto";
import { mkdir, readFile, readdir, stat, symlink, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { test } from "node:test";
import { deflateSync } from "node:zlib";
import { ROOT, runPy, withCwd } from "./tool-library-harness.ts";

const TOOL = process.env.AB_LAYOUT ?? join(ROOT, "packs", "mobile-forensics", "tools", "ab_layout", "run.py");
const MANIFEST = join(ROOT, "packs", "mobile-forensics", "tools", "ab_layout", "manifest.json");
const AGENT = { AGENT_ID: "s1" };

type Run = { code: number | null; stdout: string; stderr: string };
type Row = {
  member: string; member_b64: string | null; name_withheld: boolean; type: string; size: number; payload_offset: number; state: string; reason?: string;
  package?: string; domain?: string; derivative_path?: string; sha256?: string; name_collision?: { kind: string }[]; sqlite_companion?: string;
};
type Answer = {
  status: string; status_basis: string; kind: string; derivative_note: string; error?: string; interrupted?: string; copy_content: boolean;
  header: { version: number; compressed: boolean; encryption: string };
  payload: { stream: string; tar_end: string; bytes_decompressed: number; bytes_after_stream: number; lone_zero_blocks: number; bytes_after_tar_end: number | null };
  derivative: { root?: string; banner?: string; values_file?: string; values_written?: number; written?: boolean };
  counts: { members_read: number; extracted_files: number; extracted_bytes: number; states: Record<string, number>; name_collisions: number; names_withheld: number;
    sqlite_companions: number; sqlite_companions_without_base: number };
  packages: Record<string, number>; entries: Row[]; entry_count: number; collisions: unknown[]; collision_count: number; observations: string[]; problems: string[];
  pages: { entries: { rows: number; all_results: string } }; mapping: Record<string, { to: string }>;
};

// --- tar and .ab, from the formats ------------------------------------------------------------------------------------------------

const octal = (n: number, width: number): Buffer => Buffer.from(n.toString(8).padStart(width - 1, "0") + "\0", "latin1");
type Member = { name: string | Buffer; data?: Buffer; type?: string; link?: string; mode?: number; raw?: boolean; pax?: Record<string, string> };

function header(name: Buffer, size: number, type: string, link: string, mode: number, prefix = Buffer.alloc(0)): Buffer {
  const b = Buffer.alloc(512);
  name.copy(b, 0, 0, Math.min(100, name.length));
  octal(mode, 8).copy(b, 100);
  octal(0, 8).copy(b, 108);
  octal(0, 8).copy(b, 116);
  octal(size, 12).copy(b, 124);
  octal(1700000000, 12).copy(b, 136);
  b.fill(0x20, 148, 156);
  b.write(type, 156, "latin1");
  b.write(link, 157, "latin1");
  b.write("ustar\0", 257, "latin1");
  b.write("00", 263, "latin1");
  prefix.copy(b, 345);
  const sum = b.reduce((s, x) => s + x, 0);
  b.write(sum.toString(8).padStart(6, "0") + "\0 ", 148, "latin1");
  return b;
}
const pad = (data: Buffer): Buffer => Buffer.concat([data, Buffer.alloc((512 - (data.length % 512)) % 512)]);
function paxRecord(key: string, value: Buffer | string): Buffer {
  const v = Buffer.isBuffer(value) ? value : Buffer.from(value);
  const rest = Buffer.concat([Buffer.from(` ${key}=`), v, Buffer.from("\n")]);
  let len = rest.length + 1;
  while (String(len).length + rest.length !== len) len = String(len).length + rest.length;
  return Buffer.concat([Buffer.from(String(len)), rest]);
}
function tarMember(m: Member): Buffer {
  const name = Buffer.isBuffer(m.name) ? m.name : Buffer.from(m.name);
  const data = m.data ?? Buffer.alloc(0);
  const type = m.type ?? "0";
  const parts: Buffer[] = [];
  let short = name;
  if (m.pax || name.length > 100) {
    const records = Buffer.concat([...(name.length > 100 ? [paxRecord("path", name)] : []), ...Object.entries(m.pax ?? {}).map(([k, v]) => paxRecord(k, v))]);
    parts.push(header(Buffer.from("PaxHeader"), records.length, "x", "", 0o644), pad(records));
    short = name.subarray(0, 100);
  }
  parts.push(header(short, ["5", "1", "2", "3", "4", "6"].includes(type) ? 0 : data.length, type, m.link ?? "", m.mode ?? 0o644), pad(data));
  return Buffer.concat(parts);
}
function tar(members: Member[], end = true): Buffer {
  return Buffer.concat([...members.map(tarMember), ...(end ? [Buffer.alloc(1024)] : [])]);
}
function ab(payload: Buffer, opts: { version?: number; compressed?: boolean; encryption?: string; trailer?: Buffer } = {}): Buffer {
  const compressed = opts.compressed ?? true;
  return Buffer.concat([Buffer.from(`ANDROID BACKUP\n${opts.version ?? 5}\n${compressed ? 1 : 0}\n${opts.encryption ?? "none"}\n`), compressed ? deflateSync(payload) : payload, opts.trailer ?? Buffer.alloc(0)]);
}
const f = (s: string): Buffer => Buffer.from(s);

const PKG = "com.example.chat";
const APP: Member[] = [
  { name: `apps/${PKG}/_manifest`, data: f("manifest record") },
  { name: `apps/${PKG}/db/msgstore.db`, data: f("SQLite format 3 main") },
  { name: `apps/${PKG}/db/msgstore.db-wal`, data: f("wal bytes") },
  { name: `apps/${PKG}/db/msgstore.db-shm`, data: f("shm bytes") },
  { name: `apps/${PKG}/sp/prefs.xml`, data: f("<map/>") },
  { name: `apps/${PKG}/f/note.txt`, data: f("a note") },
  { name: `apps/${PKG}/r/misc.txt`, data: f("root file") },
  { name: `apps/${PKG}/d_db/protected.db`, data: f("device protected") },
  { name: `apps/${PKG}/a/base.apk`, data: f("apk bytes") },
  { name: `apps/${PKG}/ef/ext.txt`, data: f("external") },
  { name: `apps/${PKG}/db/`, type: "5" },
  { name: "shared/0/pic.jpg", data: f("jpg") },
];

// --- running ------------------------------------------------------------------------------------------------------------------------

function run(cwd: string, args: unknown, env: Record<string, string> = {}): Promise<Run> {
  return runPy(TOOL, cwd, args, undefined, { ...AGENT, ...env });
}
async function asJob(cwd: string, args: unknown, name = "out", job = "j-1", secret = true): Promise<Run> {
  await mkdir(join(cwd, name), { recursive: true });
  return run(cwd, args, { JOB_ID: job, OUT: join(cwd, name), ...(secret ? { SECRET_OUTPUT: "1" } : {}) });
}
function body(out: Run): Answer {
  assert.doesNotMatch(out.stderr, /Traceback/);
  assert.ok(out.code === 0, out.stderr + out.stdout);
  return JSON.parse(out.stdout) as Answer;
}
function failed(out: Run): Answer {
  assert.notEqual(out.code, 0, out.stdout);
  assert.doesNotMatch(out.stderr, /Traceback/);
  return JSON.parse(out.stdout) as Answer;
}
async function walkDir(dir: string): Promise<string[]> {
  const out: string[] = [];
  for (const e of await readdir(dir, { withFileTypes: true }).catch(() => [])) {
    const p = join(dir, e.name);
    if (e.isDirectory()) out.push(...(await walkDir(p)));
    else out.push(p);
  }
  return out.sort();
}
async function put(cwd: string, name: string, data: Buffer): Promise<string> {
  await mkdir(join(cwd, "work"), { recursive: true });
  const p = join(cwd, "work", name);
  await writeFile(p, data);
  return p;
}
const sha = (b: Buffer | string): string => createHash("sha256").update(b).digest("hex");
const DERIV = (cwd: string, out = "out"): string => join(cwd, out, "ab_layout", "derivative");

// --- tests -----------------------------------------------------------------------------------------------------------------------------

test("it maps apps/<package>/<domain>/... onto data/data/<package>/..., keeps _manifest and the SQLite companions, lists what it does not extract, and says what it is", async () => {
  await withCwd(async (cwd) => {
    const file = await put(cwd, "app.ab", ab(tar(APP)));
    const answer = body(await asJob(cwd, { path: file, copy_content: true }));
    assert.equal(answer.status, "complete", answer.status_basis);
    assert.equal(answer.kind, "derivative of an adb backup");
    assert.match(answer.derivative_note, /not a file-system acquisition/);
    assert.deepEqual(answer.header, { version: 5, compressed: true, encryption: "none" });
    assert.equal(answer.payload.stream, "reached");
    assert.equal(answer.payload.tar_end, "reached");
    const d = DERIV(cwd);
    const at = (p: string): Promise<string> => readFile(join(d, p), "utf8");
    assert.equal(await at(`data/data/${PKG}/databases/msgstore.db`), "SQLite format 3 main");
    assert.equal(await at(`data/data/${PKG}/databases/msgstore.db-wal`), "wal bytes");
    assert.equal(await at(`data/data/${PKG}/databases/msgstore.db-shm`), "shm bytes");
    assert.equal(await at(`data/data/${PKG}/shared_prefs/prefs.xml`), "<map/>");
    assert.equal(await at(`data/data/${PKG}/files/note.txt`), "a note");
    assert.equal(await at(`data/data/${PKG}/misc.txt`), "root file");
    assert.equal(await at(`data/user_de/0/${PKG}/databases/protected.db`), "device protected");
    assert.equal(await at(`ab_layout_meta/${PKG}/_manifest`), "manifest record");
    const banner = JSON.parse(await at("DERIVATIVE.json")) as { kind: string; is_not: string };
    assert.equal(banner.kind, "derivative of an adb backup");
    assert.match(banner.is_not, /not a file-system acquisition|a file-system acquisition/);
    // Not extracted: the APK, external storage, shared storage and the directory are listed with their state, and are nowhere in the tree.
    const states = Object.fromEntries(answer.entries.map((e) => [e.member, e.state]));
    assert.equal(states[`apps/${PKG}/a/base.apk`], "not_laid_out");
    assert.equal(states[`apps/${PKG}/ef/ext.txt`], "not_laid_out");
    assert.equal(states["shared/0/pic.jpg"], "shared_storage");
    assert.equal(states[`apps/${PKG}/db/`], "directory");
    const tree = (await walkDir(d)).map((p) => p.slice(d.length + 1));
    assert.ok(!tree.some((p) => /base\.apk|ext\.txt|pic\.jpg/.test(p)), tree.join(", "));
    // Provenance: the member as spelled, its exact bytes, its offset in the decompressed payload and its size, and the hash of what was written.
    const row = answer.entries.find((e) => e.member === `apps/${PKG}/db/msgstore.db`)!;
    assert.equal(Buffer.from(row.member_b64!, "base64").toString(), row.member);
    assert.equal(row.state, "extracted");
    assert.equal(row.sha256, sha("SQLite format 3 main"));
    assert.equal(row.size, 20);
    assert.equal(row.package, PKG);
    assert.equal(row.domain, "db");
    assert.equal(row.derivative_path, `data/data/${PKG}/databases/msgstore.db`);
    const plain = tar(APP);
    const offsets = answer.entries.map((e) => e.payload_offset);
    assert.equal(offsets[0], 0);
    assert.ok(offsets.every((o, i) => i === 0 || o > offsets[i - 1]));
    assert.ok(plain.length >= offsets[offsets.length - 1], "the offsets are positions in the decompressed payload");
    assert.equal(answer.counts.sqlite_companions, 2);
    assert.equal(answer.counts.sqlite_companions_without_base, 0);
    assert.equal(answer.entry_count, answer.counts.members_read);
    assert.equal((await readFile(join(cwd, "out", answer.pages.entries.all_results.split("/out/")[1]), "utf8")).split("\n").filter(Boolean).length, answer.entry_count);
  });
});

test("header versions 1 to 5 are read, compressed or not; 99 is unsupported and an encrypted payload is refused, with nothing but the header reported", async () => {
  await withCwd(async (cwd) => {
    for (const version of [1, 2, 3, 4, 5]) {
      for (const compressed of [true, false]) {
        const file = await put(cwd, `v${version}${compressed}.ab`, ab(tar(APP.slice(0, 3)), { version, compressed }));
        const a = body(await run(cwd, { path: file }));
        assert.equal(a.header.version, version);
        assert.equal(a.header.compressed, compressed);
        assert.equal(a.status, "complete", `${version} ${compressed}: ${a.status_basis}`);
      }
    }
    const v99 = failed(await run(cwd, { path: await put(cwd, "v99.ab", ab(tar(APP), { version: 99 })) }));
    assert.match(v99.error!, /header version 99 is not one this tool reads/);
    assert.equal(v99.header.version, 99);
    const aes = failed(await run(cwd, { path: await put(cwd, "aes.ab", Buffer.concat([Buffer.from("ANDROID BACKUP\n5\n1\nAES-256\n"), Buffer.from("a\nb\n10000\nc\nd\n"), Buffer.alloc(200, 9)])) }));
    assert.match(aes.error!, /encrypted \(AES-256\).*reads the header only, opens nothing and reads no password/);
    assert.match(failed(await run(cwd, { path: await put(cwd, "other.ab", f("not a backup at all")) })).error!, /does not start with 'ANDROID BACKUP'/);
    assert.match(failed(await run(cwd, { path: await put(cwd, "odd.ab", f("ANDROID BACKUP\nx\n1\nnone\nabc")) })).error!, /header lines are not/);
    // Whatever the header, nothing was written for a refusal.
    assert.deepEqual((await readdir(join(cwd, "work"))).filter((n) => !n.endsWith(".ab") && n !== "s1"), []);
  });
});

test("the mapping table in the manifest is the one the tool uses, with its basis and its caveat", async () => {
  const manifest = JSON.parse(await readFile(MANIFEST, "utf8")) as { description: string; secret_output: { when_args: string[] } };
  await withCwd(async (cwd) => {
    const a = body(await run(cwd, { path: await put(cwd, "m.ab", ab(tar(APP.slice(0, 2)))) }));
    for (const [token, entry] of Object.entries(a.mapping)) {
      assert.ok(manifest.description.includes("`" + token + "` -> " + entry.to), `the manifest states ${token} -> ${entry.to}`);
    }
    assert.equal(Object.keys(a.mapping).length, 12);
  });
  assert.match(manifest.description, /FullBackup/);
  assert.match(manifest.description, /not been checked against the AOSP source/);
  assert.deepEqual(manifest.secret_output.when_args, ["copy_content"]);
});

test("a stream that expands without end is bounded by the decompression budget and by the byte budget, and nothing huge is written", async () => {
  await withCwd(async (cwd) => {
    // A member that declares 4 TB and a payload of zeros: ~600 KB deflated, 600 MB inflated.
    const bomb = Buffer.concat([header(Buffer.from(`apps/${PKG}/f/bomb.bin`), 0, "0", "", 0o644), Buffer.alloc(600 << 20)]);
    const size = 4 * 2 ** 40;
    bomb.write(size.toString(8).padStart(11, "0") + "\0", 124, "latin1");
    bomb.fill(0x20, 148, 156);
    bomb.write((bomb.subarray(0, 512).reduce((s, x) => s + x, 0)).toString(8).padStart(6, "0") + "\0 ", 148, "latin1");
    const file = await put(cwd, "bomb.ab", ab(bomb));
    assert.ok((await stat(file)).size < 2 << 20, "the file is small");
    for (const copy of [false, true]) {
      const began = Date.now();
      const a = body(await asJob(cwd, { path: file, max_decompressed_bytes: 32 << 20, copy_content: copy }, copy ? "o2" : "o1", "j-1", copy));
      assert.equal(a.status, "partial");
      assert.ok(a.payload.bytes_decompressed <= (32 << 20) + (1 << 20), String(a.payload.bytes_decompressed));
      assert.match(a.status_basis, /decompression budget/);
      assert.ok(Date.now() - began < 30000);
    }
    assert.deepEqual((await walkDir(join(cwd, "o2"))).filter((p) => p.includes("/derivative/data/")), []);
    // max_bytes: a member bigger than what may be written is not started.
    const big = await put(cwd, "big.ab", ab(tar([{ name: `apps/${PKG}/f/a.bin`, data: Buffer.alloc(3000, 1) }, { name: `apps/${PKG}/f/b.bin`, data: Buffer.alloc(1000, 2) }])));
    const limited = body(await asJob(cwd, { path: big, copy_content: true, max_bytes: 3500 }, "o3"));
    assert.equal(limited.status, "partial");
    assert.deepEqual(limited.entries.map((e) => e.state), ["extracted", "not_extracted_max_bytes"]);
    assert.match(limited.status_basis, /max_bytes/);
    // max_members.
    const many = await put(cwd, "many.ab", ab(tar(Array.from({ length: 50 }, (_, i) => ({ name: `apps/${PKG}/f/${i}.txt`, data: f("x") })))));
    const capped = body(await run(cwd, { path: many, max_members: 10 }));
    assert.equal(capped.entry_count, 10);
    assert.equal(capped.status, "partial");
    assert.match(capped.status_basis, /max_members \(10\)/);
  });
});

test("hostile member names are rejected and listed, an odd name is a name, and nothing is written outside $OUT", async () => {
  await withCwd(async (cwd) => {
    const members: Member[] = [
      { name: `apps/${PKG}/f/../../../../escape1.txt`, data: f("x") },
      { name: `/etc/absolute.txt`, data: f("x") },
      { name: `apps/${PKG}/f//empty.txt`, data: f("x") },
      { name: `apps/${PKG}/f/./dot.txt`, data: f("x") },
      { name: `apps/../escape2.txt`, data: f("x") },
      { name: Buffer.from(`apps/${PKG}/f/with\0nul.txt`), data: f("x"), pax: { path: `apps/${PKG}/f/with\0nul.txt` } },
      { name: `apps/${PKG}/f/${"c".repeat(300)}`, data: f("x") },
      { name: `apps/${PKG}/f/${"d/".repeat(70)}x`, data: f("x") },
      { name: `apps/${PKG}/f/..config`, data: f("odd but fine") },
      { name: `apps/${PKG}/f/...`, data: f("three dots, a name") },
      { name: `apps/not a package/f/x`, data: f("x") },
      { name: `apps/${PKG}/zz/unknown.txt`, data: f("unknown domain") },
      { name: `elsewhere/x.txt`, data: f("x") },
      { name: `apps/${PKG}/f/fine.txt`, data: f("fine") },
    ];
    const file = await put(cwd, "hostile.ab", ab(tar(members)));
    const before = await walkDir(cwd);
    const a = body(await asJob(cwd, { path: file, copy_content: true }));
    const states = a.entries.map((e) => e.state);
    assert.equal(states.filter((s) => s === "rejected_name").length, 9, states.join(" "));
    assert.equal(a.counts.states.unknown_domain, 1);
    assert.equal(a.counts.states.outside_layout, 1);
    assert.equal(a.counts.states.extracted, 3);
    assert.equal(a.status, "partial");
    assert.equal(await readFile(join(DERIV(cwd), `data/data/${PKG}/files/..config`), "utf8"), "odd but fine");
    assert.equal(await readFile(join(DERIV(cwd), `data/data/${PKG}/files/...`), "utf8"), "three dots, a name");
    const after = (await walkDir(cwd)).filter((p) => !before.includes(p));
    for (const p of after) assert.ok(p.startsWith(join(cwd, "out")), `written outside $OUT: ${p}`);
    for (const e of a.entries.filter((r) => r.state === "rejected_name")) assert.ok(e.reason);
  });
});

test("duplicates, names that differ only in case, and a file and a directory on one name each get their own name; the collisions are listed", async () => {
  await withCwd(async (cwd) => {
    const members: Member[] = [
      { name: `apps/${PKG}/f/Note.txt`, data: f("first") },
      { name: `apps/${PKG}/f/Note.txt`, data: f("duplicate") },
      { name: `apps/${PKG}/f/NOTE.TXT`, data: f("upper") },
      { name: `apps/${PKG}/f/thing`, data: f("a file") },
      { name: `apps/${PKG}/f/thing/inside.txt`, data: f("below a file") },
    ];
    const a = body(await asJob(cwd, { path: await put(cwd, "dup.ab", ab(tar(members))), copy_content: true }));
    assert.equal(a.status, "complete", a.status_basis);
    const files = await walkDir(join(DERIV(cwd), "data", "data", PKG, "files"));
    assert.equal(files.length, 5);
    assert.deepEqual((await Promise.all(files.map((p) => readFile(p, "utf8")))).sort(), ["a file", "below a file", "duplicate", "first", "upper"]);
    assert.equal(a.entries[0].derivative_path, `data/data/${PKG}/files/Note.txt`);
    assert.ok(a.counts.name_collisions >= 3);
    assert.equal(a.collision_count, a.collisions.length);
    const kinds = new Set(a.entries.flatMap((e) => (e.name_collision ?? []).map((c) => c.kind)));
    assert.ok(kinds.has("duplicate_path") && kinds.has("case_fold") && kinds.has("file_vs_directory"), [...kinds].join(","));
  });
});

test("links, hard links, device nodes and FIFOs are listed and never created or followed", async () => {
  await withCwd(async (cwd) => {
    const outside = join(cwd, "outside.txt");
    await writeFile(outside, "outside");
    const members: Member[] = [
      { name: `apps/${PKG}/f/link`, type: "2", link: outside },
      { name: `apps/${PKG}/f/hard`, type: "1", link: `apps/${PKG}/f/real.txt` },
      { name: `apps/${PKG}/f/real.txt`, data: f("real") },
      { name: `apps/${PKG}/f/char`, type: "3" },
      { name: `apps/${PKG}/f/block`, type: "4" },
      { name: `apps/${PKG}/f/fifo`, type: "6" },
      { name: `apps/${PKG}/f/after.txt`, data: f("after") },
    ];
    const a = body(await asJob(cwd, { path: await put(cwd, "links.ab", ab(tar(members))), copy_content: true }));
    assert.deepEqual(a.entries.map((e) => e.state), ["symlink", "hardlink", "extracted", "character_device", "block_device", "fifo", "extracted"]);
    assert.equal(a.status, "complete", a.status_basis);
    assert.deepEqual((await readdir(join(DERIV(cwd), "data", "data", PKG, "files"))).sort(), ["after.txt", "real.txt"]);
    assert.equal(await readFile(outside, "utf8"), "outside");
  });
});

test("the end of the stream is verified: a missing end block, a lone zero block, data after the end, bytes after the zlib stream, a cut stream and a damaged one are each partial and said", async () => {
  await withCwd(async (cwd) => {
    const members = APP.slice(0, 3);
    const check = async (name: string, data: Buffer, pattern: RegExp, copy = false) => {
      const a = body(await asJob(cwd, { path: await put(cwd, name, data), copy_content: copy }, `o-${name}`, "j-1", copy));
      assert.equal(a.status, "partial", `${name}: ${a.status_basis}`);
      assert.match(a.status_basis, pattern, name);
      return a;
    };
    await check("noend.ab", ab(tar(members, false)), /two end blocks were not reached \(missing\)/);
    const lone = Buffer.concat([tarMember(members[0]), Buffer.alloc(512), tarMember(members[1]), Buffer.alloc(1024)]);
    const l = await check("lone.ab", ab(lone), /1 lone zero block/);
    assert.equal(l.payload.lone_zero_blocks, 1);
    assert.equal(l.counts.members_read, 2, "the member after the lone zero block is read");
    const after = await check("after.ab", ab(Buffer.concat([tar(members), Buffer.alloc(512), f("data after the end")])), /data follows the tar's end blocks/);
    assert.ok(after.payload.bytes_after_tar_end! > 0);
    const padded = body(await run(cwd, { path: await put(cwd, "padded.ab", ab(Buffer.concat([tar(members), Buffer.alloc(10240 - (tar(members).length % 10240))]))) }));
    assert.equal(padded.status, "complete", "zero padding after the end blocks is not data");
    const trailer = await check("trailer.ab", ab(tar(members), { trailer: f("second stream or padding") }), /byte\(s\) follow the end of the zlib stream/);
    assert.equal(trailer.payload.bytes_after_stream, 24);
    const whole = ab(tar([{ name: `apps/${PKG}/f/big.bin`, data: Buffer.alloc(2 << 20, 3) }, ...members]));
    const cut = await check("cut.ab", whole.subarray(0, whole.length - 400), /zlib stream ends before its end marker|payload ended inside|end blocks were not reached/);
    assert.ok(["truncated", "not_reached"].includes(cut.payload.tar_end));
    const damaged = Buffer.from(whole);
    damaged[Math.floor(damaged.length / 2)] ^= 0xff;
    damaged[Math.floor(damaged.length / 2) + 1] ^= 0xff;
    const dmg = body(await run(cwd, { path: await put(cwd, "damaged.ab", damaged) }));
    assert.equal(dmg.status, "partial");
    // A member cut in the middle is not under a final name.
    const half = ab(tar([{ name: `apps/${PKG}/f/half.bin`, data: Buffer.alloc(5000, 4) }], false).subarray(0, 512 + 2000));
    const h = body(await asJob(cwd, { path: await put(cwd, "half.ab", half), copy_content: true }, "o-half"));
    assert.equal(h.entries[0].state, "truncated_member");
    assert.deepEqual(await walkDir(join(DERIV(cwd, "o-half"), "data")), []);
    assert.deepEqual((await walkDir(join(cwd, "o-half"))).filter((p) => /\.ab-.*\.tmp$/.test(p)), []);
    // A header whose checksum does not hold stops the walk.
    const broken = tar(members);
    broken[512 * 2 + 3] ^= 0x41;
    broken[512 * 4 + 7] ^= 0x41;
    const b = body(await run(cwd, { path: await put(cwd, "badsum.ab", ab(broken)) }));
    assert.equal(b.status, "partial");
  });
});

test("copy_content is refused outside a job and in a job that is not secret output, before anything is made; a plan writes only the result file", async () => {
  await withCwd(async (cwd) => {
    const file = await put(cwd, "app.ab", ab(tar(APP)));
    assert.match(failed(await run(cwd, { path: file, copy_content: true })).error!, /copy_content is refused outside a job/);
    assert.match(failed(await asJob(cwd, { path: file, copy_content: true }, "out", "j-2", false)).error!, /SECRET_OUTPUT is not 1/);
    assert.deepEqual(await readdir(join(cwd, "out")), []);
    assert.deepEqual((await readdir(join(cwd, "work"))).sort(), ["app.ab"]);
    const plan = body(await run(cwd, { path: file }));
    assert.equal(plan.status, "complete");
    assert.match(plan.status_basis, /planned/);
    assert.equal(plan.derivative.written, false);
    assert.ok(plan.entries.filter((e) => e.state === "planned").length >= 8);
    const written = (await walkDir(join(cwd, "work", "s1"))).map((p) => p.slice(join(cwd, "work", "s1").length + 1));
    assert.equal(written.length, 1, written.join(", "));
    assert.match(written[0], /^tool-output\/ab_layout-[0-9a-f]{16}\.jsonl$/);
    assert.match(failed(await run(cwd, { path: file, password: "x" })).error!, /no such argument/);
    assert.match(failed(await run(cwd, { path: file, packages: ["not a package"] })).error!, /list of at most 1000 Android package names/);
    // The package filter.
    const two = await put(cwd, "two.ab", ab(tar([{ name: `apps/${PKG}/f/a.txt`, data: f("a") }, { name: "apps/com.other.app/f/b.txt", data: f("b") }])));
    const only = body(await run(cwd, { path: two, packages: ["com.other.app"] }));
    assert.deepEqual(only.entries.map((e) => e.state), ["not_selected", "planned"]);
  });
});

test("a second run in the same $OUT names identical files again and never replaces one: a changed member takes -2", async () => {
  await withCwd(async (cwd) => {
    const first = await put(cwd, "one.ab", ab(tar([{ name: `apps/${PKG}/f/a.txt`, data: f("version one, the longer text") }, { name: `apps/${PKG}/f/b.txt`, data: f("same") }])));
    body(await asJob(cwd, { path: first, copy_content: true }));
    body(await asJob(cwd, { path: first, copy_content: true }));
    const dir = join(DERIV(cwd), "data", "data", PKG, "files");
    assert.deepEqual((await readdir(dir)).sort(), ["a.txt", "b.txt"]);
    const changed = await put(cwd, "two.ab", ab(tar([{ name: `apps/${PKG}/f/a.txt`, data: f("v2") }, { name: `apps/${PKG}/f/b.txt`, data: f("same") }])));
    const third = body(await asJob(cwd, { path: changed, copy_content: true }));
    assert.deepEqual((await readdir(dir)).sort(), ["a-2.txt", "a.txt", "b.txt"]);
    assert.equal(await readFile(join(dir, "a.txt"), "utf8"), "version one, the longer text");
    assert.equal(third.entries[0].derivative_path, `data/data/${PKG}/files/a-2.txt`);
    assert.ok(third.entries[0].name_collision!.some((c) => c.kind === "name_taken_on_disk"));
    const names = await readdir(join(cwd, "out"));
    assert.equal(names.filter((n) => n.startsWith("ab-layout-values")).length, 3);
    assert.equal((await readdir(join(cwd, "out", "tool-output"))).filter((n) => n.endsWith(".jsonl")).length, 3);
  });
});

test("a member name shaped like a recovery password is withheld on every channel, a package named like one too; the real name is only in the 0600 values file", async () => {
  // 150 canaries from a seeded generator, eight groups of six digits: with none found on any channel, the rate of a leak is under 2.5 % at 95 %
  // confidence (the Wilson upper bound for 0 of 150).
  await withCwd(async (cwd) => {
    let x = 424242 >>> 0;
    const next = (): number => { x = (Math.imul(x, 1664525) + 1013904223) >>> 0; return x; };
    const keys = Array.from({ length: 150 }, () => Array.from({ length: 8 }, () => String(next() % 1000000).padStart(6, "0")).join("-"));
    const members: Member[] = keys.map((k, i) => (i % 3 === 0 ? { name: `apps/${PKG}/f/${k}.txt`, data: f(`n${i}`) }
      : i % 3 === 1 ? { name: `apps/${PKG}/db/${k}/inner.db`, data: f(`n${i}`) } : { name: `apps/${k}/f/n.txt`, data: f(`n${i}`) }));
    const r = await asJob(cwd, { path: await put(cwd, "keys.ab", ab(tar(members))), copy_content: true });
    const a = body(r);
    assert.equal(a.counts.names_withheld, 150);
    const values = join(cwd, "out", a.derivative.values_file!.split("/out/")[1]);
    const others = (await walkDir(join(cwd, "out"))).filter((p) => p !== values);
    const hay = [r.stdout, r.stderr, ...others, ...(await Promise.all(others.filter((p) => /\.jsonl?$/.test(p)).map((p) => readFile(p, "utf8"))))].join("\n");
    for (const k of keys) for (const probe of [k, k.replaceAll("-", ""), k.split("-").slice(0, 3).join("-")]) assert.ok(!hay.includes(probe), `a canary reached a channel: ${probe.slice(0, 8)}...`);
    assert.equal((await stat(values)).mode & 0o777, 0o600);
    const text = await readFile(values, "utf8");
    for (const k of keys) assert.ok(text.includes(k));
    assert.equal(a.counts.states.extracted, 150);
    // Selecting a package by a guessed key matches nothing: the name is matched as it is printed.
    const guess = body(await run(cwd, { path: join(cwd, "work", "keys.ab"), packages: [keys[2]] }));
    assert.ok(guess.entries.every((e) => e.state === "not_selected"));
  });
});

/** The tool with every read of the file delayed, so that an extraction takes as long as the test needs. */
const SLOW = String.raw`
import os, runpy, sys, time
delay = float(sys.argv[1])
real = os.pread
def slow(fd, n, off):
    if n >= 1 << 20:
        time.sleep(delay)
    return real(fd, n, off)
os.pread = slow
sys.argv = [sys.argv[2]]
import os as _os_for_exit; _os_for_exit._exit = lambda code: (_ for _ in ()).throw(SystemExit(code))   # the tool ends with os._exit after its answer; this wrapper has more to do after it (report the peak), so the exit is turned into the SystemExit the tool used to end with
runpy.run_path(sys.argv[0], run_name="__main__")
`;

function slowTool(cwd: string, args: unknown, delay: number, env: Record<string, string>): { child: ReturnType<typeof spawn>; done: Promise<Run> } {
  const child = spawn("python3", ["-c", SLOW, String(delay), TOOL], { cwd, env: { ...process.env, ...AGENT, ...env } });
  const out: Buffer[] = [], err: Buffer[] = [];
  child.stdout.on("data", (c: Buffer) => out.push(c));
  child.stderr.on("data", (c: Buffer) => err.push(c));
  child.stdin.on("error", () => {});
  child.stdin.end(JSON.stringify(args));
  return { child, done: new Promise<Run>((resolve) => child.on("close", (code) => resolve({ code, stdout: Buffer.concat(out).toString("utf8"), stderr: Buffer.concat(err).toString("utf8") }))) };
}

test("SIGTERM in the middle of an extraction ends with JSON and exit 143, with no temporary file and no half file under a final name; max_seconds ends it too", async () => {
  await withCwd(async (cwd) => {
    // Several 2 MiB members of data that does not compress, so that the file is read in pieces and the copy takes a while.
    let seed = 7;
    const noise = (n: number): Buffer => { const b = Buffer.alloc(n); for (let i = 0; i < n; i++) { seed = (Math.imul(seed, 1103515245) + 12345) >>> 0; b[i] = seed >>> 24; } return b; };
    const members = Array.from({ length: 6 }, (_, i) => ({ name: `apps/${PKG}/f/m${i}.bin`, data: noise(2 << 20) }));
    const file = await put(cwd, "slow.ab", ab(tar(members)));
    await mkdir(join(cwd, "out"), { recursive: true });
    const env = { JOB_ID: "j-1", OUT: join(cwd, "out"), SECRET_OUTPUT: "1" };
    const { child, done } = slowTool(cwd, { path: file, copy_content: true, max_seconds: 120 }, 0.4, env);
    const until = Date.now() + 25000;
    let seen = false;
    while (Date.now() < until && !seen) {
      seen = (await walkDir(join(cwd, "out"))).some((p) => /\/\.ab-[^/]*\.tmp$/.test(p));
      if (!seen) await new Promise((r) => setTimeout(r, 20));
    }
    assert.ok(seen, "an extraction was in progress");
    child.kill("SIGTERM");
    const r = await done;
    assert.equal(r.code, 143, r.stderr + r.stdout);
    assert.equal((JSON.parse(r.stdout) as Answer).interrupted, "SIGTERM");
    assert.doesNotMatch(r.stderr, /Traceback/);
    const left = await walkDir(join(cwd, "out"));
    assert.deepEqual(left.filter((p) => /\.ab-.*\.tmp$|\/\.ab_layout-/.test(p)), []);
    for (const p of left.filter((q) => q.includes("/files/m"))) assert.equal((await readFile(p)).length, 2 << 20, "a file under a final name is whole");
    // The clock: max_seconds ends the walk, the members not reached are listed, the answer is partial.
    const { done: done2 } = slowTool(cwd, { path: file, copy_content: true, max_seconds: 3 }, 0.4, { ...env, OUT: join(cwd, "out2") });
    await mkdir(join(cwd, "out2"), { recursive: true });
    const clock = body(await done2);
    assert.equal(clock.status, "partial");
    assert.match(clock.status_basis, /time limit stopped the walk/);
    assert.equal(clock.entry_count, clock.counts.members_read, "every member read has its line");
  });
});

test("a file system that refuses the write is write_failed on that member, never a fact about the backup", async () => {
  await withCwd(async (cwd) => {
    const file = await put(cwd, "big.ab", ab(tar([{ name: `apps/${PKG}/f/a.bin`, data: Buffer.alloc(9000, 1) }, { name: `apps/${PKG}/f/b.bin`, data: Buffer.alloc(100, 2) }])));
    const limited = await new Promise<Run>((resolve) => {
      const child = spawn("bash", ["-c", `ulimit -f 6; exec python3 -c 'import signal; signal.signal(signal.SIGXFSZ, signal.SIG_IGN); import runpy, sys; sys.argv=[sys.argv[1]]; runpy.run_path(sys.argv[0], run_name="__main__")' "${TOOL}"`],
        { cwd, env: { ...process.env, ...AGENT, JOB_ID: "j-2", OUT: join(cwd, "out2"), SECRET_OUTPUT: "1" } });
      const out: Buffer[] = [], err: Buffer[] = [];
      child.stdout.on("data", (c: Buffer) => out.push(c));
      child.stderr.on("data", (c: Buffer) => err.push(c));
      child.stdin.on("error", () => {});
      child.stdin.end(JSON.stringify({ path: file, copy_content: true }));
      child.on("close", (code) => resolve({ code, stdout: Buffer.concat(out).toString("utf8"), stderr: Buffer.concat(err).toString("utf8") }));
    });
    const a = JSON.parse(limited.stdout) as Answer;
    assert.equal(a.status, "partial", limited.stdout.slice(0, 600));
    assert.equal(a.entries[0].state, "write_failed", limited.stdout.slice(0, 600));
    assert.ok(a.entries[0].reason);
    assert.equal(a.entries[1].state, "not_attempted_write_stopped");
    assert.deepEqual((await walkDir(join(cwd, "out2"))).filter((p) => /\.ab-.*\.tmp$/.test(p)), []);
  });
});

test("a pax header gives a long name, and a hard link to it, a member size and a bad pax record are handled", async () => {
  await withCwd(async (cwd) => {
    const long = `apps/${PKG}/f/${"sub/".repeat(30)}file.txt`;
    const members: Member[] = [
      { name: long, data: f("long name") },
      { name: `apps/${PKG}/f/sized.txt`, data: f("abcdef"), pax: { size: "6" } },
      { name: `apps/${PKG}/f/ok.txt`, data: f("ok") },
    ];
    const a = body(await asJob(cwd, { path: await put(cwd, "pax.ab", ab(tar(members))), copy_content: true }));
    assert.equal(a.status, "complete", a.status_basis);
    assert.equal(a.entries[0].member, long);
    assert.equal(await readFile(join(DERIV(cwd), "data", "data", PKG, "files", ...("sub/".repeat(30) + "file.txt").split("/")), "utf8"), "long name");
    // A pax record that does not parse: said, the member keeps the name of its own header.
    const bad = Buffer.concat([header(Buffer.from("PaxHeader"), 9, "x", "", 0o644), pad(f("notvalid!")), tarMember({ name: `apps/${PKG}/f/after-bad-pax.txt`, data: f("z") }), Buffer.alloc(1024)]);
    const b = body(await run(cwd, { path: await put(cwd, "badpax.ab", ab(bad)) }));
    assert.ok(b.problems.some((p) => /pax header .* does not parse/.test(p)));
    assert.equal(b.status, "partial");
  });
});

test("a fuzz of 400 mutated backups always ends with JSON, no traceback and nothing outside $OUT", async () => {
  // At most 1,000 cases: seeded byte flips, truncations and length rewrites of a valid payload, before and after compression.
  await withCwd(async (cwd) => {
    let x = 17;
    const next = (n: number): number => { x = (Math.imul(x, 1103515245) + 12345) >>> 0; return x % n; };
    const seed = tar(APP);
    const before = await walkDir(cwd);
    for (let i = 0; i < 400; i++) {
      const payload = Buffer.from(seed);
      const kind = next(5);
      if (kind === 0) for (let k = 0; k < 1 + next(5); k++) payload[next(payload.length)] = next(256);
      else if (kind === 1) payload.fill(0, Math.max(512, next(payload.length)));
      else if (kind === 2) payload.write(String(next(1e11)).padStart(11, "0"), 124 + 512 * next(3), "latin1");
      else if (kind === 3) payload.fill(0x41, 512 * next(10), 512 * next(10) + 20);
      let file = ab(payload, { compressed: next(4) !== 0 });
      if (kind === 4) file = file.subarray(0, Math.max(30, next(file.length)));
      const r = await asJob(cwd, { path: await put(cwd, `fuzz${i % 20}.ab`, file), copy_content: true, max_seconds: 20 }, `out-fuzz${i % 5}`, "j-f");
      assert.doesNotMatch(r.stderr, /Traceback/, `case ${i}`);
      const a = JSON.parse(r.stdout) as Answer;
      assert.ok(["complete", "partial", "failed"].includes(a.status), `case ${i}: ${r.stdout.slice(0, 200)}`);
    }
    const stray = (await walkDir(cwd)).filter((p) => !before.includes(p) && !p.startsWith(join(cwd, "work")) && !/\/out-fuzz\d\//.test(p));
    assert.deepEqual(stray, []);
    // A link planted inside the output directory is not followed.
    await mkdir(join(cwd, "plant", "ab_layout"), { recursive: true });
    await mkdir(join(cwd, "target"), { recursive: true });
    await symlink(join(cwd, "target"), join(cwd, "plant", "ab_layout", "derivative"));
    const planted = failed(await asJob(cwd, { path: join(cwd, "work", "fuzz0.ab"), copy_content: true }, "plant", "j-p"));
    assert.match(planted.error!, /symbolic link|derivative directory could not be made/);
    assert.deepEqual(await readdir(join(cwd, "target")), []);
  });
});

// --- fix round 1: a pax sparse member is listed and never extracted; a planted link is refused ---------------------------------------------

test("a pax sparse member (GNU.sparse.* records on a plain-file typeflag) is listed as sparse_not_extracted, nothing of it is written, and the answer is partial", async () => {
  await withCwd(async (cwd) => {
    const sparse = { "GNU.sparse.major": "1", "GNU.sparse.minor": "0", "GNU.sparse.name": `apps/${PKG}/f/sp.bin`, "GNU.sparse.realsize": String(50 << 20) };
    const file = await put(cwd, "sparse.ab", ab(tar([
      { name: `apps/${PKG}/_manifest`, data: f("manifest record") },
      { name: `apps/${PKG}/f/GNUSparseFile.1/sp.bin`, data: f("1\n0\n0\n"), pax: { ...sparse, path: `apps/${PKG}/f/sp.bin` } },
      { name: `apps/${PKG}/f/after.txt`, data: f("after") },
    ])));
    const answer = body(await asJob(cwd, { path: file, copy_content: true }));
    const by = Object.fromEntries(answer.entries.map((e) => [e.member, e]));
    assert.equal(by[`apps/${PKG}/f/sp.bin`].state, "sparse_not_extracted", JSON.stringify(by));
    assert.equal(by[`apps/${PKG}/f/after.txt`].state, "extracted", "the member after it is not taken for sparse");
    assert.equal(answer.status, "partial", answer.status_basis);
    assert.deepEqual((await walkDir(DERIV(cwd))).filter((p) => /sp\.bin|GNUSparse/.test(p)), []);
  });
});

test("a tool-output directory that is a link planted in the output directory is refused as JSON, and nothing is written through it", async () => {
  await withCwd(async (cwd) => {
    const file = await put(cwd, "app.ab", ab(tar(APP)));
    await mkdir(join(cwd, "out"), { recursive: true });
    await mkdir(join(cwd, "elsewhere"), { recursive: true });
    await symlink(join(cwd, "elsewhere"), join(cwd, "out", "tool-output"));
    const answer = failed(await run(cwd, { path: file }, { JOB_ID: "j-1", OUT: join(cwd, "out") }));
    assert.match(answer.error ?? "", /tool-output/);
    assert.deepEqual(await readdir(join(cwd, "elsewhere")), []);
  });
});

test("an old GNU sparse header with a map extension block is passed over: the member is listed as sparse_not_extracted and the member after it is read from the right place", async () => {
  await withCwd(async (cwd) => {
    const data = f("0123456789");
    const head = Buffer.from(header(f(`apps/${PKG}/f/sp.bin`), data.length, "S", "", 0o644));
    head[482] = 1;                                   // isextended
    head.fill(0x20, 148, 156);
    head.write(head.reduce((s, x) => s + x, 0).toString(8).padStart(6, "0") + "\0 ", 148, "latin1");
    const map = Buffer.alloc(512);                   // one extension block; its own isextended byte (504) is 0
    // Data that reads as two zero blocks if it is taken for the next headers: a skip that lands on the map's blocks would end the tar early.
    const payload = Buffer.concat([tarMember({ name: `apps/${PKG}/_manifest`, data: f("m") }), head, map, pad(data), tarMember({ name: `apps/${PKG}/f/after.txt`, data: f("after") }), Buffer.alloc(1024)]);
    const file = await put(cwd, "gnu-sparse.ab", ab(payload));
    const answer = body(await asJob(cwd, { path: file, copy_content: true }));
    const by = Object.fromEntries(answer.entries.map((e) => [e.member, e]));
    assert.equal(by[`apps/${PKG}/f/sp.bin`].state, "sparse_not_extracted", JSON.stringify(by));
    assert.equal(by[`apps/${PKG}/f/after.txt`].state, "extracted", JSON.stringify(by));
    assert.equal(answer.payload.tar_end, "reached");
    assert.equal(answer.status, "partial");
  });
});
