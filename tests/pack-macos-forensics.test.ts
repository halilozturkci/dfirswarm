/**
 * The macOS pack's four tools, against fixtures the test builds from the
 * formats' own layouts and never from a tool's output.
 *
 * Binary property list (plist_read): Apple's CFBinaryPList layout. "bplist00",
 * then the objects (an ASCII string is 0x5N followed by N bytes, data 0x4N, an
 * integer 0x10 or 0x11 followed by 1 or 2 big-endian bytes, an array 0xAN with
 * N one-byte object refs, a dictionary 0xDN with N key refs and N value refs),
 * then the offset table, then a 32-byte trailer: 5 unused bytes, the sort
 * version, the size of an offset, the size of an object ref, the object count,
 * the top object and the offset table's offset (the last three big-endian
 * 8-byte integers).
 *
 * FSEvents (fsevents_parse): a record file is gzip, possibly several members end
 * to end, holding pages. A page is a 12-byte header (the magic "1SLD" or "2SLD",
 * four bytes of unknown, the page length as u32 little-endian, header included)
 * and then records to the end of the page: the path as NUL-terminated UTF-8, the
 * event id (u64), the flags (u32) and, in version 2 only, the node id (u64).
 *
 * plist_read follows the secret-safe output pattern of recovery_key_scan
 * (docs/packs.md, "Secrets and sensitive output"): what it prints and writes is
 * checked here for a value, a fragment, a digest and a head, in the answer and in
 * every file the answer names.
 */
import assert from "node:assert/strict";
import { spawn, spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import { chmod, mkdir, readFile, readdir, stat, symlink, writeFile } from "node:fs/promises";
import { gzipSync } from "node:zlib";
import { join } from "node:path";
import { test } from "node:test";
import { ROOT, runPy, runPySnippet, withCwd } from "./tool-library-harness.ts";

const MAC = join(ROOT, "packs", "macos-forensics", "tools");
const PLIST = join(MAC, "plist_read", "run.py");
const AGENT = { AGENT_ID: "s1" };

type Run = { code: number | null; stdout: string; stderr: string };

async function tool(script: string, cwd: string, args: unknown, env: Record<string, string> = {}, bin?: string): Promise<Run> {
  return runPy(script, cwd, args, bin, { ...AGENT, ...env });
}

/** The tool as a job runs it: JOB_ID and OUT set, OUT inside the run directory. */
async function asJob(script: string, cwd: string, args: unknown): Promise<Run> {
  await mkdir(join(cwd, "out"), { recursive: true });
  return tool(script, cwd, args, { JOB_ID: "j-1", OUT: join(cwd, "out") });
}

function body<T>(out: Run): T {
  assert.equal(out.code, 0, out.stderr + out.stdout);
  assert.doesNotMatch(out.stderr, /Traceback/);
  return JSON.parse(out.stdout) as T;
}

function refused(out: Run): { error: string; [key: string]: unknown } {
  assert.notEqual(out.code, 0, out.stdout);
  assert.doesNotMatch(out.stderr, /Traceback/);
  return JSON.parse(out.stdout) as { error: string };
}

const sha256 = (data: Buffer | string): string => createHash("sha256").update(data).digest("hex");

async function exists(path: string): Promise<boolean> {
  return stat(path).then(() => true, () => false);
}

/** Run a Python fixture builder; its argv follows the code. */
async function build(code: string, ...args: string[]): Promise<void> {
  const out = await runPySnippet(code, args, null);
  assert.equal(out.code, 0, out.stderr);
}

// --- plist_read -----------------------------------------------------------------

type PlistValue = string | number | Buffer | PlistValue[] | { [key: string]: PlistValue };

/** A binary property list from Apple's layout (see the header), small enough for one-byte refs. */
function bplist(root: { [key: string]: PlistValue }): Buffer {
  const objects: Buffer[] = [];
  const add = (b: Buffer): number => objects.push(b) - 1;
  const length = (marker: number, n: number): Buffer => {
    if (n < 15) return Buffer.from([marker | n]);
    return Buffer.concat([Buffer.from([marker | 0x0f]), n < 256 ? Buffer.from([0x10, n]) : Buffer.from([0x11, n >> 8, n & 0xff])]);
  };
  const put = (v: PlistValue): number => {
    if (typeof v === "string") return add(Buffer.concat([length(0x50, v.length), Buffer.from(v, "ascii")]));
    if (typeof v === "number") return add(v < 256 ? Buffer.from([0x10, v]) : Buffer.from([0x11, v >> 8, v & 0xff]));
    if (Buffer.isBuffer(v)) return add(Buffer.concat([length(0x40, v.length), v]));
    if (Array.isArray(v)) {
      const at = add(Buffer.alloc(0));
      const refs = v.map(put);
      objects[at] = Buffer.concat([length(0xa0, v.length), Buffer.from(refs)]);
      return at;
    }
    const at = add(Buffer.alloc(0));
    const keys = Object.keys(v).map((k) => put(k));
    const vals = Object.values(v).map(put);
    objects[at] = Buffer.concat([length(0xd0, keys.length), Buffer.from(keys), Buffer.from(vals)]);
    return at;
  };
  put(root);
  const header = Buffer.from("bplist00", "ascii");
  let offset = header.length;
  const offsets = objects.map((o) => {
    const at = offset;
    offset += o.length;
    return at;
  });
  const table = Buffer.concat(offsets.map((o) => Buffer.from([o >> 8, o & 0xff])));
  const trailer = Buffer.alloc(32);
  trailer[6] = 2; // bytes per offset
  trailer[7] = 1; // bytes per object ref
  trailer.writeBigUInt64BE(BigInt(objects.length), 8);
  trailer.writeBigUInt64BE(0n, 16); // the top object is the first one made
  trailer.writeBigUInt64BE(BigInt(offset), 24);
  return Buffer.concat([header, ...objects, table, trailer]);
}

// A salted-PBKDF2-shaped verifier, 64 bytes, every byte distinct so no run of it is a pattern a header or an
// ordinary word could hold. These are test bytes, not a credential of anything.
const VERIFIER = Buffer.from(Array.from({ length: 64 }, (_, i) => (i * 37 + 11) % 251));
const HINT = "my first dog and a number";

function accountPlist(): Buffer {
  return bplist({
    name: "alice",
    uid: 501,
    home: "/Users/alice",
    shell: "/bin/zsh",
    authentication_authority: [";ShadowHash;HASHLIST:<SALTED-SHA512-PBKDF2>", ";SecureToken;"],
    ShadowHashData: [VERIFIER],
    hint: HINT,
    jpegphoto: Buffer.from(Array.from({ length: 40 }, (_, i) => 200 - i)),
  });
}

type PlistRow = {
  file: string;
  parser?: string;
  status: string;
  encoding?: string;
  bytes?: number;
  extracted_file_mtime?: string;
  modified?: string;
  key?: string;
  keys?: string[];
  value?: Record<string, unknown>;
  error?: string;
  reason?: string;
  binary_values?: number;
  withheld_values?: number;
};
type PlistAnswer = {
  status: string;
  files: PlistRow[];
  file_count: number;
  found: number;
  complete_files: string | null;
  inline_limited: boolean;
  counts: { matched: number; parsed: number; failed: number; skipped_over_a_bound: number; not_attempted: number };
  first_problems?: Record<string, { file: string; why: string }[]>;
  walk: { links_not_followed: number; files_not_matched: number };
  secret_bearing: { binary_values_not_printed: number; withheld_by_key_name: number };
  secret_values: { requested: boolean; written: number; values_file: string | null; contains_secret_values: boolean };
};

/** Everything that must carry no secret: the answer and each file it names. */
async function printed(cwd: string, out: Run): Promise<string> {
  let all = out.stdout;
  const answer = JSON.parse(out.stdout) as PlistAnswer;
  if (answer.complete_files) all += "\n" + (await readFile(join(cwd, answer.complete_files), "utf8"));
  return all;
}

function assertNoVerifier(text: string): void {
  const b64 = VERIFIER.toString("base64");
  for (let i = 0; i + 16 <= b64.length; i += 4) assert.ok(!text.includes(b64.slice(i, i + 16)), "a run of the verifier's base64 is in the output");
  assert.ok(!text.includes(VERIFIER.toString("hex").slice(0, 16)), "the verifier's hex is in the output");
  assert.ok(!text.includes(sha256(VERIFIER)), "the verifier's sha256 is in the output");
  assert.doesNotMatch(text, /[0-9a-f]{64}/i, "a 64-hex digest is in the output");
  assert.doesNotMatch(text, /_sha256|_base64_head/);
  assert.ok(!text.includes(HINT), "the password hint is in the output");
}

test("the fixture is a binary property list by Apple's own layout", async () => {
  await withCwd(async (cwd) => {
    const file = join(cwd, "work", "alice.plist");
    await writeFile(file, accountPlist());
    // plistlib is the reference reader of the format here, not the tool under test.
    const code = `
import json, plistlib, sys
t = plistlib.load(open(sys.argv[1], "rb"))
print(json.dumps({"uid": t["uid"], "len": len(t["ShadowHashData"][0]), "hint": t["hint"], "keys": sorted(t)}))
`;
    const out = await runPySnippet(code, [file], null);
    assert.equal(out.code, 0, out.stderr);
    const got = JSON.parse(out.stdout) as { uid: number; len: number; hint: string; keys: string[] };
    assert.equal(got.uid, 501);
    assert.equal(got.len, 64);
    assert.equal(got.hint, HINT);
  });
});

test("plist_read prints no digest, head or verifier of an account plist, and says where the withheld values are", async () => {
  // It printed the sha256 of every binary value and a base64 head, and `max_blob: 0` still printed the digest.
  await withCwd(async (cwd) => {
    await writeFile(join(cwd, "work", "alice.plist"), accountPlist());
    for (const args of [{ path: "work/alice.plist" }, { path: "work/alice.plist", max_blob: 0 }, { path: "work/alice.plist", max_blob: 4096 }]) {
      const out = await tool(PLIST, cwd, args);
      const answer = body<PlistAnswer>(out);
      assertNoVerifier(await printed(cwd, out));
      const row = answer.files[0];
      assert.equal(row.status, "parsed");
      assert.equal(row.encoding, "binary");
      // The ordinary keys are there, in full.
      const value = row.value as Record<string, unknown>;
      assert.equal(value.name, "alice");
      assert.equal(value.uid, 501);
      assert.equal(value.home, "/Users/alice");
      assert.deepEqual(value.authentication_authority, [";ShadowHash;HASHLIST:<SALTED-SHA512-PBKDF2>", ";SecureToken;"]);
      // The verifier and the hint are locators: kind, length, a finding id.
      const shadow = value.ShadowHashData as { _withheld: string; _kind: string; _length: number; finding_id: string };
      assert.equal(shadow._kind, "array");
      assert.equal(shadow._length, 1);
      assert.match(shadow.finding_id, /^F\d{6}$/);
      const hint = value.hint as { _kind: string; _length: number };
      assert.equal(hint._kind, "string");
      assert.equal(hint._length, HINT.length);
      // An ordinary binary value is its length and kind, not a digest or a head.
      const photo = value.jpegphoto as { _binary_bytes: number; _kind: string; finding_id: string };
      assert.equal(photo._binary_bytes, 40);
      assert.equal(photo._kind, "data");
      assert.equal(row.withheld_values, 2);
      assert.equal(answer.secret_bearing.withheld_by_key_name, 2);
      assert.equal(answer.secret_values.requested, false);
      assert.equal(answer.secret_values.values_file, null);
    }
  });
});

test("plist_read returns only the keys a selection names, and withholds a secret-bearing key even when it is selected", async () => {
  await withCwd(async (cwd) => {
    await writeFile(join(cwd, "work", "alice.plist"), accountPlist());
    const uid = body<PlistAnswer>(await tool(PLIST, cwd, { path: "work/alice.plist", key: "uid" }));
    assert.equal(uid.files[0].key, "uid");
    assert.equal(uid.files[0].value, 501);
    assert.equal(uid.files[0].keys, undefined, "a selection lists no other key");
    for (const key of ["ShadowHashData", "ShadowHashData.0", "hint"]) {
      const out = await tool(PLIST, cwd, { path: "work/alice.plist", key });
      const answer = body<PlistAnswer>(out);
      assertNoVerifier(out.stdout);
      const value = answer.files[0].value as { _withheld?: string; finding_id?: string };
      assert.ok(value._withheld, `${key} was printed`);
      assert.match(value.finding_id ?? "", /^F\d{6}$/);
    }
  });
});

test("plist_read writes values only on write_values, only in a job, only to a private file under $OUT", async () => {
  await withCwd(async (cwd) => {
    await writeFile(join(cwd, "work", "alice.plist"), accountPlist());
    // Outside a job the request is refused and nothing is written.
    const outside = refused(await tool(PLIST, cwd, { path: "work/alice.plist", write_values: true }));
    assert.match(outside.error, /refused outside a job/);
    assert.deepEqual(await readdir(join(cwd, "work")), ["alice.plist"]);

    const run = await asJob(PLIST, cwd, { path: "work/alice.plist", write_values: true });
    const answer = body<PlistAnswer>(run);
    assertNoVerifier(await printed(cwd, run));
    assert.equal(answer.secret_values.requested, true);
    assert.equal(answer.secret_values.written, 3, "the verifier, the hint and the photo");
    assert.equal(answer.secret_values.contains_secret_values, true);
    assert.equal(answer.secret_values.values_file, "store/jobs/j-1/out/plist-values.jsonl");
    const file = join(cwd, "out", "plist-values.jsonl");
    assert.equal((await stat(file)).mode & 0o777, 0o600);
    const rows = (await readFile(file, "utf8")).trimEnd().split("\n").map((l) => JSON.parse(l) as { finding_id: string; file: string; key_path: string; kind: string; length: number; value: unknown });
    const byPath = Object.fromEntries(rows.map((r) => [r.key_path, r]));
    assert.deepEqual(Object.keys(byPath).sort(), ["ShadowHashData", "hint", "jpegphoto"]);
    assert.equal(byPath.hint.value, HINT);
    assert.equal(byPath.hint.file, "work/alice.plist");
    const shadow = byPath.ShadowHashData.value as [{ _base64: string; _bytes: number; _truncated: boolean }];
    assert.equal(shadow[0]._base64, VERIFIER.toString("base64"));
    assert.equal(shadow[0]._bytes, 64);
    assert.equal(shadow[0]._truncated, false);
    // The ids in the answer are the ids in the file.
    const row = answer.files[0].value as Record<string, { finding_id: string }>;
    assert.equal(byPath.ShadowHashData.finding_id, row.ShadowHashData.finding_id);
    assert.equal(byPath.jpegphoto.finding_id, row.jpegphoto.finding_id);

    // A file already at that name is refused by name, before anything is read, and not touched.
    await writeFile(join(cwd, "out", "plist-values.jsonl"), "keep\n");
    const again = refused(await asJob(PLIST, cwd, { path: "work/alice.plist", write_values: true }));
    assert.match(again.error, /values file already exists/);
    assert.equal(await readFile(join(cwd, "out", "plist-values.jsonl"), "utf8"), "keep\n");
  });
});

test("plist_read bounds a value written to the values file and says how much it left", async () => {
  await withCwd(async (cwd) => {
    await writeFile(join(cwd, "work", "alice.plist"), accountPlist());
    await asJob(PLIST, cwd, { path: "work/alice.plist", write_values: true, max_blob: 16 }).then((r) => body<PlistAnswer>(r));
    const rows = (await readFile(join(cwd, "out", "plist-values.jsonl"), "utf8")).trimEnd().split("\n").map((l) => JSON.parse(l) as { key_path: string; value: unknown });
    const shadow = (rows.find((r) => r.key_path === "ShadowHashData")?.value as [{ _base64: string; _bytes: number; _bytes_written: number; _truncated: boolean }])[0];
    assert.equal(shadow._bytes, 64);
    assert.equal(shadow._bytes_written, 16);
    assert.equal(shadow._truncated, true);
    assert.equal(shadow._base64, VERIFIER.subarray(0, 16).toString("base64"));
  });
});

test("plist_read labels the file time as the extracted copy's and does not overwrite an out_file", async () => {
  await withCwd(async (cwd) => {
    await writeFile(join(cwd, "work", "a.plist"), bplist({ name: "x" }));
    const answer = body<PlistAnswer>(await tool(PLIST, cwd, { path: "work/a.plist" }));
    assert.match(answer.files[0].extracted_file_mtime ?? "", /^\d{4}-\d\d-\d\dT.*Z$/);
    assert.equal(answer.files[0].modified, undefined);
    assert.equal(answer.files[0].parser, "plist_read/3");

    await writeFile(join(cwd, "work", "keep.jsonl"), "precious\n");
    const clash = refused(await tool(PLIST, cwd, { path: "work/a.plist", out_file: "work/keep.jsonl" }));
    assert.match(clash.error, /already exists/);
    assert.equal(await readFile(join(cwd, "work", "keep.jsonl"), "utf8"), "precious\n");
    // A dangling link at the name is refused too, and nothing is written through it.
    await symlink("not-there.jsonl", join(cwd, "work", "dangling.jsonl"));
    refused(await tool(PLIST, cwd, { path: "work/a.plist", out_file: "work/dangling.jsonl" }));
    assert.equal(await exists(join(cwd, "work", "not-there.jsonl")), false);
  });
});

test("plist_read keeps going past a file it cannot read, one it will not read, a link and a tree too deep, and says each", async () => {
  await withCwd(async (cwd) => {
    const dir = join(cwd, "work", "plists");
    await mkdir(join(dir, "sub"), { recursive: true });
    await writeFile(join(dir, "a-good.plist"), bplist({ name: "good", n: 1 }));
    await writeFile(join(dir, "b-corrupt.plist"), Buffer.concat([Buffer.from("bplist00"), Buffer.alloc(40, 0xff)]));
    // A plist nested 5000 arrays deep: the converter recursed on it until Python gave up, and took the sweep with it.
    const deep = `<?xml version="1.0" encoding="UTF-8"?><plist version="1.0">${"<array>".repeat(5000)}${"</array>".repeat(5000)}</plist>`;
    await writeFile(join(dir, "c-deep.plist"), deep);
    await writeFile(join(dir, "d-big.plist"), Buffer.alloc(250_000));
    await writeFile(join(dir, "sub", "e-also-good.btm"), bplist({ name: "also" }));
    await writeFile(join(dir, "notes.txt"), "not a plist");
    await writeFile(join(cwd, "work", "outside.plist"), bplist({ name: "outside" }));
    await symlink(join(cwd, "work", "outside.plist"), join(dir, "f-link.plist"));
    const out = await tool(PLIST, cwd, { path: "work/plists", max_file_bytes: 200_000, out_file: "work/all.jsonl" });
    const answer = body<PlistAnswer>(out);
    assert.equal(answer.status, "partial");
    assert.deepEqual(answer.counts, { matched: 5, parsed: 2, failed: 1, skipped_over_a_bound: 2, not_attempted: 0 });
    const byFile = Object.fromEntries(answer.files.map((r) => [r.file.split("/").pop(), r]));
    assert.equal(byFile["a-good.plist"].status, "parsed");
    assert.equal(byFile["b-corrupt.plist"].status, "failed");
    assert.match(byFile["b-corrupt.plist"].error ?? "", /\w/);
    assert.equal(byFile["c-deep.plist"].status, "skipped");
    assert.match(byFile["c-deep.plist"].reason ?? "", /max_depth/);
    assert.equal(byFile["d-big.plist"].status, "skipped");
    assert.match(byFile["d-big.plist"].reason ?? "", /max_file_bytes/);
    assert.equal(byFile["e-also-good.btm"].status, "parsed");
    assert.equal(byFile["f-link.plist"], undefined, "a link is not followed");
    assert.equal(answer.walk.links_not_followed, 1);
    assert.equal(answer.walk.files_not_matched, 1);
    assert.ok(answer.first_problems?.failed?.[0]?.file.endsWith("b-corrupt.plist"));
    // Every row is in the file as it was made, in path order.
    const rows = (await readFile(join(cwd, "work", "all.jsonl"), "utf8")).trimEnd().split("\n").map((l) => JSON.parse(l) as PlistRow);
    assert.equal(rows.length, answer.file_count);
    assert.deepEqual(rows.map((r) => r.file.split("/").pop()), ["a-good.plist", "b-corrupt.plist", "c-deep.plist", "d-big.plist", "e-also-good.btm"]);
  });
});

test("plist_read refuses over a node budget, names it, and still reads a selected part of that file", async () => {
  await withCwd(async (cwd) => {
    await build(
      `
import plistlib, sys
plistlib.dump({"small": {"a": 1}, "wide": list(range(5000))}, open(sys.argv[1], "wb"), fmt=plistlib.FMT_BINARY)
`,
      join(cwd, "work", "wide.plist"),
    );
    // Nothing parsed: the answer is whole, and the exit says so.
    const run = await tool(PLIST, cwd, { path: "work/wide.plist", max_nodes: 100 });
    assert.equal(run.code, 1);
    assert.doesNotMatch(run.stderr, /Traceback/);
    const whole = JSON.parse(run.stdout) as PlistAnswer;
    assert.equal(whole.status, "failed");
    assert.equal(whole.files[0].status, "skipped");
    assert.match(whole.files[0].reason ?? "", /max_nodes \(100\)/);
    const part = body<PlistAnswer>(await tool(PLIST, cwd, { path: "work/wide.plist", key: "small", max_nodes: 100 }));
    assert.equal(part.status, "complete");
    assert.deepEqual(part.files[0].value, { a: 1 });
  });
});

test("plist_read writes each file's row as it goes and stops at max_seconds with the rest counted, not dropped", async () => {
  // It parsed every file into memory before writing any, so an interrupted sweep left nothing.
  await withCwd(async (cwd) => {
    await build(
      `
import os, plistlib, sys
d = sys.argv[1]
os.makedirs(d)
for i in range(300):
    plistlib.dump({"n": i, "items": list(range(8000))}, open(os.path.join(d, "p%04d.plist" % i), "wb"), fmt=plistlib.FMT_BINARY)
`,
      join(cwd, "work", "many"),
    );
    const out = await tool(PLIST, cwd, { path: "work/many", max_seconds: 0.25, out_file: "work/many.jsonl", max_nodes: 100000 });
    const answer = body<PlistAnswer>(out);
    assert.equal(answer.status, "partial");
    assert.ok(answer.counts.parsed > 0 && answer.counts.parsed < 300, JSON.stringify(answer.counts));
    assert.equal(answer.counts.parsed + answer.counts.not_attempted, 300);
    assert.equal(answer.found, 300);
    assert.match(answer.first_problems?.not_attempted?.[0]?.why ?? "", /max_seconds/);
    const rows = (await readFile(join(cwd, "work", "many.jsonl"), "utf8")).trimEnd().split("\n");
    assert.equal(rows.length, answer.counts.parsed, "each parsed file is in the output file");
  });
});

test("plist_read pages a directory sweep losslessly when no out_file is named", async () => {
  await withCwd(async (cwd) => {
    await mkdir(join(cwd, "work", "p"), { recursive: true });
    for (let i = 0; i < 7; i++) await writeFile(join(cwd, "work", "p", `f${i}.plist`), bplist({ n: i }));
    const answer = body<PlistAnswer>(await tool(PLIST, cwd, { path: "work/p", limit: 3 }));
    assert.equal(answer.files.length, 3);
    assert.equal(answer.file_count, 7);
    assert.equal(answer.inline_limited, true);
    assert.match(answer.complete_files ?? "", /^work\/s1\/tool-output\/plist_read-.*\.jsonl$/);
    const rows = (await readFile(join(cwd, answer.complete_files as string), "utf8")).trimEnd().split("\n").map((l) => JSON.parse(l) as PlistRow);
    assert.deepEqual(rows.map((r) => (r.value as { n: number }).n), [0, 1, 2, 3, 4, 5, 6]);
  });
});

// --- fsevents_parse ---------------------------------------------------------------

const FS = join(MAC, "fsevents_parse", "run.py");
const CREATED = 0x01000000;
const REMOVED = 0x02000000;
const RENAMED = 0x08000000;
const FILE_EVENT = 0x00008000;

function fsRecord(path: string, id: bigint, flags: number, node?: bigint): Buffer {
  const fixed = Buffer.alloc(node === undefined ? 12 : 20);
  fixed.writeBigUInt64LE(id, 0);
  fixed.writeUInt32LE(flags >>> 0, 8);
  if (node !== undefined) fixed.writeBigUInt64LE(node, 12);
  return Buffer.concat([Buffer.from(path, "utf8"), Buffer.from([0]), fixed]);
}

/** A page: the 12-byte header, then the records. `length` overrides the declared page length. */
function fsPage(magic: string, records: Buffer[], length?: number): Buffer {
  const body = Buffer.concat(records);
  const header = Buffer.alloc(12);
  header.write(magic, 0, "latin1");
  header.writeUInt32LE(length ?? 12 + body.length, 8);
  return Buffer.concat([header, body]);
}

type FsAnswer = {
  status: string;
  files: number;
  gzip_files: number;
  records: { path: string; event_id: number; flags: string[]; flags_raw: number; flags_undecoded?: number; node_id: number | null; version: number; file: string; member: number | null; page_offset: number; record_offset: number; parser: string }[];
  record_count: number;
  records_before_filter: number;
  event_id_range: [number, number] | null;
  complete_records: string | null;
  files_by_state: { parsed: number; partial: number; empty: number; unsupported: number; failed: number };
  per_file: { file: string; state: string; magic_seen?: string; members?: { complete: number; truncated: number; failed: number }; expanded_bytes?: number; records?: number }[];
  log_identity: { file: string; bytes: number; uuid?: string; raw_hex?: string } | null;
  coverage: {
    members: { complete: number; truncated: number; failed: number };
    pages: { parsed: number; unsupported: number; invalid_length: number; truncated: number };
    records: { decoded: number; empty_path: number; incomplete: number };
    bytes_skipped: number;
  };
  problems: { file: string; kind: string; why: string; offset?: number; compressed_offset?: number; member?: number; magic?: string; bytes?: number }[];
  problems_total: number;
  filters: { flags_unknown?: string[] };
  note: string;
};

/** The answer whatever the exit code: a failed run still prints its whole answer. */
function fsAnswer(out: Run): FsAnswer {
  assert.doesNotMatch(out.stderr, /Traceback/);
  return JSON.parse(out.stdout) as FsAnswer;
}

async function fsDir(cwd: string, name: string, files: Record<string, Buffer>): Promise<string> {
  const dir = join(cwd, "work", name);
  await mkdir(dir, { recursive: true });
  for (const [file, bytes] of Object.entries(files)) await writeFile(join(dir, file), bytes);
  return `work/${name}`;
}

test("fsevents_parse reads version 1 and 2 pages across two gzip members and counts both", async () => {
  await withCwd(async (cwd) => {
    const m1 = gzipSync(fsPage("2SLD", [fsRecord("Users/a/payroll.xlsx", 1001n, CREATED | FILE_EVENT, 12n), fsRecord("Users/a/payroll.xlsx", 1042n, REMOVED | FILE_EVENT, 12n)]));
    const m2 = gzipSync(fsPage("1SLD", [fsRecord("tmp/x", 1100n, CREATED | FILE_EVENT)]));
    const dir = await fsDir(cwd, "ev", { "0000000000000fff": Buffer.concat([m1, m2]) });
    const answer = fsAnswer(await tool(FS, cwd, { path: dir }));
    assert.equal(answer.status, "complete");
    assert.equal(answer.record_count, 3);
    assert.deepEqual(answer.records.map((r) => [r.path, r.event_id, r.version, r.node_id]), [
      ["Users/a/payroll.xlsx", 1001, 2, 12], ["Users/a/payroll.xlsx", 1042, 2, 12], ["tmp/x", 1100, 1, null],
    ]);
    assert.deepEqual(answer.coverage.members, { complete: 2, truncated: 0, failed: 0 });
    assert.equal(answer.coverage.pages.parsed, 2);
    assert.deepEqual(answer.files_by_state, { parsed: 1, partial: 0, empty: 0, unsupported: 0, failed: 0 });
    assert.deepEqual(answer.records[0].member, 0);
    assert.equal(answer.records[2].member, 1);
    assert.equal(answer.records[0].page_offset, 0);
    assert.equal(answer.records[0].record_offset, 12);
    assert.equal(answer.records[0].parser, "fsevents_parse/3");
  });
});

test("fsevents_parse says a page of a version it does not read is unsupported, with the magic seen, and not an empty success", async () => {
  // A 3SLD file came back as no records and no problems.
  await withCwd(async (cwd) => {
    const dir = await fsDir(cwd, "ev3", { "0000000000000aaa": gzipSync(fsPage("3SLD", [fsRecord("a/b", 5n, CREATED, 1n)])) });
    const run = await tool(FS, cwd, { path: dir });
    const answer = fsAnswer(run);
    assert.equal(run.code, 1, "nothing was decoded, and the exit says so");
    assert.equal(answer.status, "unsupported");
    assert.deepEqual(answer.files_by_state, { parsed: 0, partial: 0, empty: 0, unsupported: 1, failed: 0 });
    assert.equal(answer.per_file[0].state, "unsupported");
    assert.equal(answer.per_file[0].magic_seen, "3SLD");
    assert.equal(answer.coverage.pages.unsupported, 1);
    assert.ok(answer.problems.some((p) => p.kind === "unsupported page magic" && p.magic === "3SLD"));
    assert.equal(answer.record_count, 0);
    // Mixed with a readable file the run is partial, and the readable file's records are there.
    const mixed = await fsDir(cwd, "evmixed", {
      "0000000000000aaa": gzipSync(fsPage("3SLD", [fsRecord("a/b", 5n, CREATED, 1n)])),
      "0000000000000bbb": gzipSync(fsPage("2SLD", [fsRecord("c/d", 9n, REMOVED, 2n)])),
    });
    const both = fsAnswer(await tool(FS, cwd, { path: mixed }));
    assert.equal(both.status, "partial");
    assert.equal(both.record_count, 1);
    assert.deepEqual(both.files_by_state, { parsed: 1, partial: 0, empty: 0, unsupported: 1, failed: 0 });
  });
});

test("fsevents_parse names a gzip member cut short, with its offset, and keeps the records before the cut", async () => {
  await withCwd(async (cwd) => {
    const records = Array.from({ length: 200 }, (_, i) => fsRecord(`Users/a/file-${i}`, BigInt(1000 + i), CREATED | FILE_EVENT, BigInt(i)));
    const whole = gzipSync(fsPage("2SLD", records));
    const cut = whole.subarray(0, whole.length - 40); // loses the end of the deflate stream and the gzip trailer
    const dir = await fsDir(cwd, "evcut", { "0000000000000ccc": cut });
    const answer = fsAnswer(await tool(FS, cwd, { path: dir }));
    assert.equal(answer.status, "partial");
    assert.deepEqual(answer.coverage.members, { complete: 0, truncated: 1, failed: 0 });
    const problem = answer.problems.find((p) => p.kind === "gzip member truncated");
    assert.ok(problem, JSON.stringify(answer.problems));
    assert.equal(problem.member, 0);
    assert.equal(problem.compressed_offset, 0);
    assert.ok(answer.record_count > 0 && answer.record_count < 200, `records kept before the cut: ${answer.record_count}`);
    assert.equal(answer.per_file[0].state, "partial");
    assert.ok(answer.problems.some((p) => p.kind === "page truncated"), "the page the cut ended was named");
  });
});

test("fsevents_parse names a deflate stream that does not decode, and reads the members before it", async () => {
  await withCwd(async (cwd) => {
    const good = gzipSync(fsPage("2SLD", [fsRecord("ok/one", 1n, CREATED, 1n)]));
    const second = Buffer.from(gzipSync(fsPage("2SLD", Array.from({ length: 300 }, (_, i) => fsRecord(`bad/${i}`, BigInt(10 + i), CREATED, 2n)))));
    for (let i = 20; i < 40; i++) second[i] = 0xff; // damage inside the deflate data, past the 10-byte gzip header
    const dir = await fsDir(cwd, "evbad", { "0000000000000ddd": Buffer.concat([good, second]) });
    const answer = fsAnswer(await tool(FS, cwd, { path: dir }));
    assert.equal(answer.status, "partial");
    assert.equal(answer.coverage.members.complete, 1);
    assert.equal(answer.coverage.members.failed, 1);
    const problem = answer.problems.find((p) => p.kind === "gzip member failed");
    assert.ok(problem, JSON.stringify(answer.problems));
    assert.equal(problem.member, 1);
    assert.equal(problem.compressed_offset, good.length);
    assert.ok(answer.records.some((r) => r.path === "ok/one"));
  });
});

test("fsevents_parse reports an invalid page length, bytes it could not place and an incomplete record, and reads on", async () => {
  // It clamped a bad page length to the rest of the data, skipped to the next magic without counting the bytes, and dropped an incomplete record.
  await withCwd(async (cwd) => {
    const bad = fsPage("2SLD", [fsRecord("lost/in/bad/page", 7n, CREATED, 1n)], 4); // a declared length below the header
    const junk = Buffer.from("not a page, forty-odd bytes of something else");
    const incomplete = Buffer.concat([Buffer.from("half/a/record"), Buffer.from([0]), Buffer.from([1, 2, 3, 4, 5])]);
    const good = fsPage("2SLD", [fsRecord("after/all/that", 99n, REMOVED, 9n), incomplete]);
    const dir = await fsDir(cwd, "evpages", { "0000000000000eee": gzipSync(Buffer.concat([bad, junk, good])) });
    const answer = fsAnswer(await tool(FS, cwd, { path: dir }));
    assert.equal(answer.status, "partial");
    assert.ok(answer.records.some((r) => r.path === "after/all/that" && r.event_id === 99));
    assert.equal(answer.coverage.pages.invalid_length, 1);
    assert.ok(answer.problems.some((p) => p.kind === "invalid page length" && p.offset === 0), JSON.stringify(answer.problems));
    assert.ok(answer.problems.some((p) => p.kind === "bytes not placed in a page" && (p.bytes ?? 0) > 0));
    assert.ok(answer.coverage.bytes_skipped > 0);
    assert.equal(answer.coverage.records.incomplete, 1);
    assert.ok(answer.problems.some((p) => p.kind === "incomplete record"));
  });
});

test("fsevents_parse names a file that is neither gzip nor a page, and a gzip file that decodes to nothing", async () => {
  await withCwd(async (cwd) => {
    const dir = await fsDir(cwd, "evodd", {
      "0000000000000111": Buffer.from("plain text, no magic anywhere\n"),
      "0000000000000222": gzipSync(Buffer.alloc(0)),
      "0000000000000333": Buffer.alloc(0),
    });
    const answer = fsAnswer(await tool(FS, cwd, { path: dir }));
    const byFile = Object.fromEntries(answer.per_file.map((f) => [f.file.split("/").pop(), f.state]));
    assert.equal(byFile["0000000000000111"], "unsupported");
    assert.equal(byFile["0000000000000222"], "empty");
    assert.equal(byFile["0000000000000333"], "empty");
    assert.equal(answer.record_count, 0);
    assert.notEqual(answer.status, "complete", "an unsupported file is not a complete examination");
  });
});

test("fsevents_parse bounds expansion, says so, and names where the whole is", async () => {
  await withCwd(async (cwd) => {
    // 64 MiB of zeros is 64 KiB of gzip. With a 1 MiB cap the tool stops and says what it left.
    const bomb = gzipSync(Buffer.concat([fsPage("2SLD", [fsRecord("a", 1n, CREATED, 1n)]), Buffer.alloc(64 << 20)]));
    const dir = await fsDir(cwd, "evbomb", { "0000000000000444": bomb });
    const answer = fsAnswer(await tool(FS, cwd, { path: dir, max_expanded_bytes: 1 << 20 }));
    assert.equal(answer.status, "partial");
    const problem = answer.problems.find((p) => p.kind === "expansion cap reached");
    assert.ok(problem, JSON.stringify(answer.problems));
    assert.match(problem.why, /1048576/);
    assert.match(problem.why, /0000000000000444/);
    assert.ok(answer.record_count >= 1);
  });
});

test("fsevents_parse records the log's identity from fseventsd-uuid, and a flag bit it has no name for", async () => {
  await withCwd(async (cwd) => {
    const uuid = "6F2D1C77-4B6E-4E0A-9C1E-0A1B2C3D4E5F";
    const dir = await fsDir(cwd, "evuuid", {
      "fseventsd-uuid": Buffer.from(uuid + "\n"),
      "0000000000000555": gzipSync(fsPage("2SLD", [fsRecord("p", 3n, CREATED | 0x00000100, 1n), fsRecord("q", 4n, RENAMED | FILE_EVENT, 2n)])),
    });
    const answer = fsAnswer(await tool(FS, cwd, { path: dir }));
    assert.equal(answer.files, 1, "the identity file is not a record file");
    assert.equal(answer.log_identity?.uuid, uuid);
    assert.match(answer.log_identity?.file ?? "", /fseventsd-uuid$/);
    const p = answer.records.find((r) => r.path === "p");
    assert.deepEqual(p?.flags, ["Created"]);
    assert.equal(p?.flags_undecoded, 0x100, "a bit with no name is reported, not dropped");
    assert.equal(answer.records.find((r) => r.path === "q")?.flags_undecoded, undefined);
    // The note says a renamed path took part in a rename; it no longer says it is a move.
    assert.doesNotMatch(answer.note, /is a move/);
    assert.match(answer.note, /rename/i);
    assert.match(answer.note, /pair/i);
  });
});

test("fsevents_parse names a flag filter it has no name for, and does not overwrite an out_file", async () => {
  await withCwd(async (cwd) => {
    const dir = await fsDir(cwd, "evflt", { "0000000000000666": gzipSync(fsPage("2SLD", [fsRecord("p", 3n, REMOVED, 1n)])) });
    const answer = fsAnswer(await tool(FS, cwd, { path: dir, flags: ["Removed", "Deleted"] }));
    assert.equal(answer.record_count, 1);
    assert.deepEqual(answer.filters.flags_unknown, ["Deleted"]);
    await writeFile(join(cwd, "work", "keep.jsonl"), "precious\n");
    const clash = refused(await tool(FS, cwd, { path: dir, out_file: "work/keep.jsonl" }));
    assert.match(clash.error, /already exists/);
    assert.equal(await readFile(join(cwd, "work", "keep.jsonl"), "utf8"), "precious\n");
  });
});

test("fsevents_parse pages records losslessly and writes each to out_file", async () => {
  await withCwd(async (cwd) => {
    const records = Array.from({ length: 25 }, (_, i) => fsRecord(`d/f${i}`, BigInt(100 + i), CREATED, BigInt(i)));
    const dir = await fsDir(cwd, "evpage", { "0000000000000777": gzipSync(fsPage("2SLD", records)) });
    const answer = fsAnswer(await tool(FS, cwd, { path: dir, limit: 10 }));
    assert.equal(answer.records.length, 10);
    assert.equal(answer.record_count, 25);
    assert.match(answer.complete_records ?? "", /^work\/s1\/tool-output\/.+\.jsonl$/);
    const rows = (await readFile(join(cwd, answer.complete_records as string), "utf8")).trimEnd().split("\n");
    assert.equal(rows.length, 25);
    const withFile = fsAnswer(await tool(FS, cwd, { path: dir, limit: 10, out_file: "work/fs.jsonl" }));
    assert.equal(withFile.complete_records, "work/fs.jsonl");
    assert.equal((await readFile(join(cwd, "work", "fs.jsonl"), "utf8")).trimEnd().split("\n").length, 25);
  });
});

// --- knowledgec_query -------------------------------------------------------------

const KC = join(MAC, "knowledgec_query", "run.py");

/**
 * A knowledgeC.db as Core Data lays it out: ZOBJECT with its typed value columns and two foreign keys,
 * ZSTRUCTUREDMETADATA (one column per metadata key the OS wrote) and ZSOURCE. The dates are Apple-epoch seconds.
 * Built with the sqlite3 library from DDL written by hand here.
 */
const KC_BUILD = `
import os, shutil, sqlite3, sys
target, mode = sys.argv[1], sys.argv[2]
con = sqlite3.connect(target)
if mode == "wal":
    con.execute("PRAGMA journal_mode=WAL")
    con.execute("PRAGMA wal_autocheckpoint=0")
con.executescript("""
CREATE TABLE ZSOURCE (Z_PK INTEGER PRIMARY KEY, Z_ENT INTEGER, Z_OPT INTEGER, ZBUNDLEID VARCHAR, ZDEVICEID VARCHAR, ZGROUPID VARCHAR, ZITEMID VARCHAR, ZSOURCEID VARCHAR);
CREATE TABLE ZSTRUCTUREDMETADATA (Z_PK INTEGER PRIMARY KEY, Z_ENT INTEGER, Z_OPT INTEGER,
  Z_DKSAFARIHISTORYMETADATAKEY__TITLE VARCHAR, Z_DKDIGITALHEALTHMETADATAKEY__WEBDOMAIN VARCHAR, Z_DKAPPLICATIONMETADATAKEY__LAUNCHREASON VARCHAR);
CREATE TABLE ZOBJECT (Z_PK INTEGER PRIMARY KEY, Z_ENT INTEGER, Z_OPT INTEGER, ZSECONDSFROMGMT INTEGER, ZSOURCE INTEGER, ZSTRUCTUREDMETADATA INTEGER,
  ZVALUEINTEGER INTEGER, ZVALUETYPECODE INTEGER, ZCREATIONDATE TIMESTAMP, ZENDDATE TIMESTAMP, ZSTARTDATE TIMESTAMP, ZUUID BLOB,
  ZVALUESTRING VARCHAR, ZVALUEDOUBLE FLOAT, ZSTREAMNAME VARCHAR);
INSERT INTO ZSOURCE VALUES (1, 4, 1, 'com.apple.Safari', 'DEVICE-ONE', 'grp', 'item', 'src');
INSERT INTO ZSOURCE VALUES (2, 4, 1, NULL, 'DEVICE-TWO', NULL, NULL, NULL);
INSERT INTO ZSTRUCTUREDMETADATA VALUES (1, 2, 1, 'Quarterly report', 'example.com', NULL);
INSERT INTO ZSTRUCTUREDMETADATA VALUES (2, 2, 1, NULL, NULL, 'user');
INSERT INTO ZOBJECT VALUES (1, 3, 1, 3600, 1, 2, NULL, NULL, 760000000.5, 760000060.25, 760000000.25, x'00112233445566778899aabbccddeeff', 'com.apple.Terminal', NULL, '/app/inFocus');
INSERT INTO ZOBJECT VALUES (2, 3, 1, 3600, 2, NULL, 1, 0, 760000100, 760000200, 760000100, NULL, NULL, NULL, '/display/isBacklit');
INSERT INTO ZOBJECT VALUES (3, 3, 1, 3600, 2, NULL, 0, 0, 760000300, 760000400, 760000300, NULL, NULL, NULL, '/display/isBacklit');
INSERT INTO ZOBJECT VALUES (4, 3, 1, 3600, 2, NULL, 1, 0, 760000500, 760000600, 760000500, NULL, NULL, NULL, '/device/isLocked');
INSERT INTO ZOBJECT VALUES (5, 3, 1, 3600, 1, 1, NULL, NULL, 760000700, 760000760, 760000700, NULL, 'https://example.com/a', NULL, '/safari/history');
INSERT INTO ZOBJECT VALUES (6, 3, 1, 3600, 1, NULL, NULL, NULL, 760000800, 760000860, 760000800, NULL, NULL, 3.5, '/app/webUsage');
""")
con.commit()
if mode == "wal":
    con.execute("PRAGMA wal_checkpoint(TRUNCATE)")
    # A row that exists only in the write-ahead log: committed, never checkpointed.
    con.execute("INSERT INTO ZOBJECT VALUES (7, 3, 1, 3600, 1, NULL, NULL, NULL, 760000900, 760000960, 760000900, NULL, 'com.walonly.app', NULL, '/app/inFocus')")
    con.commit()
    os.makedirs(sys.argv[3], exist_ok=True)
    shutil.copy(target, os.path.join(sys.argv[3], "knowledgeC.db"))
    shutil.copy(target + "-wal", os.path.join(sys.argv[3], "knowledgeC.db-wal"))
con.close()
`;

type KcEntry = {
  parser: string;
  z_pk: number;
  source_table: string;
  stream: string;
  value_string: string | null;
  value_integer: number | null;
  value_double: number | null;
  value_type_code: number | null;
  start_raw: number | null;
  end_raw: number | null;
  created_raw: number | null;
  start: string | null;
  end: string | null;
  created: string | null;
  duration_seconds: number | null;
  utc_offset_seconds: number | null;
  uuid: string | null;
  metadata?: Record<string, unknown>;
  source?: Record<string, unknown>;
  zobject_other?: Record<string, unknown>;
  value?: unknown;
};
type KcAnswer = {
  status: string;
  entries: KcEntry[];
  entry_count: number;
  complete_entries: string | null;
  inline_limited: boolean;
  problems: string[];
  filters_applied?: string[];
  filters_unapplied?: string[];
  schema: { tables: string[]; fingerprint: string; joins: { ZSTRUCTUREDMETADATA: boolean; ZSOURCE: boolean } };
  source_used: { database: string; staged: boolean; sidecars: Record<string, { bytes: number }>; wal?: { frames_valid?: number; frames_committed?: number }; wal_checkpoint?: { log: number; checkpointed: number } };
  streams: { stream: string; count: number; first_start_raw: number | null; last_start_raw: number | null }[];
  streams_total: number;
  streams_pages: { all_results?: string };
  parser: string;
  note: string;
};

async function kcDb(cwd: string, name: string, mode: "plain" | "wal" = "plain"): Promise<string> {
  const dir = join(cwd, "work");
  const live = join(dir, `${name}-live.db`);
  const out = await runPySnippet(KC_BUILD, [live, mode, join(dir, name)], null);
  assert.equal(out.code, 0, out.stderr);
  if (mode === "plain") {
    await mkdir(join(dir, name), { recursive: true });
    const { copyFile } = await import("node:fs/promises");
    await copyFile(live, join(dir, name, "knowledgeC.db"));
  }
  return `work/${name}/knowledgeC.db`;
}

test("knowledgec_query joins ZSTRUCTUREDMETADATA and ZSOURCE and exports the typed values, with the row it came from", async () => {
  // It read ZOBJECT only: the metadata and the source were never joined, ZVALUEINTEGER was never exported (so /device/isLocked
  // and /display/isBacklit could not be decoded) and the row id was discarded.
  await withCwd(async (cwd) => {
    const db = await kcDb(cwd, "plain");
    const answer = body<KcAnswer>(await tool(KC, cwd, { db }));
    assert.equal(answer.status, "complete");
    assert.equal(answer.entry_count, 6);
    const byPk = Object.fromEntries(answer.entries.map((e) => [e.z_pk, e]));
    const focus = byPk[1];
    assert.equal(focus.stream, "/app/inFocus");
    assert.equal(focus.value_string, "com.apple.Terminal");
    assert.equal(focus.source_table, "ZOBJECT");
    assert.equal(focus.parser, "knowledgec_query/3");
    assert.equal(focus.start_raw, 760000000.25);
    assert.equal(focus.start, "2025-01-31T07:06:40.250000Z");
    assert.equal(focus.end, "2025-01-31T07:07:40.250000Z");
    assert.equal(focus.duration_seconds, 60);
    assert.equal(focus.utc_offset_seconds, 3600);
    assert.equal(focus.uuid, "00112233445566778899aabbccddeeff");
    // The joined metadata: only the columns that are set, under their own names; the row's Z_PK with them.
    assert.deepEqual(focus.metadata, { Z_PK: 2, Z_ENT: 2, Z_OPT: 1, Z_DKAPPLICATIONMETADATAKEY__LAUNCHREASON: "user" });
    assert.equal((focus.source as Record<string, unknown>).ZDEVICEID, "DEVICE-ONE");
    assert.equal((focus.source as Record<string, unknown>).ZBUNDLEID, "com.apple.Safari");
    // The numeric state: lock and backlight values are integers, and a duration of use can be a double.
    assert.equal(byPk[2].value_integer, 1);
    assert.equal(byPk[3].value_integer, 0);
    assert.equal(byPk[4].stream, "/device/isLocked");
    assert.equal(byPk[4].value_integer, 1);
    assert.equal(byPk[2].value_type_code, 0);
    assert.equal(byPk[6].value_double, 3.5);
    assert.equal(byPk[5].value_string, "https://example.com/a");
    assert.equal((byPk[5].metadata as Record<string, unknown>).Z_DKSAFARIHISTORYMETADATAKEY__TITLE, "Quarterly report");
    assert.equal((byPk[5].metadata as Record<string, unknown>).Z_DKDIGITALHEALTHMETADATAKEY__WEBDOMAIN, "example.com");
    assert.equal((byPk[2].source as Record<string, unknown>).ZDEVICEID, "DEVICE-TWO");
    // No legacy `bundle` that was the value string again.
    assert.equal((byPk[1] as unknown as Record<string, unknown>).bundle, undefined);
    assert.deepEqual(answer.schema.joins, { ZSTRUCTUREDMETADATA: true, ZSOURCE: true });
    assert.match(answer.schema.fingerprint, /^[0-9a-f]{64}$/);
    assert.ok(answer.schema.tables.includes("ZOBJECT"));
  });
});

test("knowledgec_query reads a record that is only in the write-ahead log, from a read-only directory, and does not touch the evidence", async () => {
  // Opened mode=ro beside the evidence, it failed on a read-only directory with 'not a SQLite database', and in a writable one it created a -shm next to the evidence.
  await withCwd(async (cwd) => {
    const dir = join(cwd, "work", "walcase");
    await build(KC_BUILD, join(cwd, "work", "walcase-live.db"), "wal", dir);
    const names = await readdir(dir);
    assert.deepEqual(names.sort(), ["knowledgeC.db", "knowledgeC.db-wal"]);
    const before = await Promise.all(names.map(async (n) => sha256(await readFile(join(dir, n)))));
    const { chmod } = await import("node:fs/promises");
    await chmod(dir, 0o555);
    try {
      const answer = body<KcAnswer>(await tool(KC, cwd, { db: "work/walcase/knowledgeC.db" }));
      assert.equal(answer.entry_count, 7);
      assert.ok(answer.entries.some((e) => e.value_string === "com.walonly.app" && e.z_pk === 7), "the row only the WAL holds");
      assert.equal(answer.source_used.staged, true);
      assert.equal(answer.source_used.sidecars["-wal"].bytes > 0, true);
      assert.ok((answer.source_used.wal?.frames_committed ?? 0) > 0);
      assert.ok((answer.source_used.wal_checkpoint?.checkpointed ?? 0) > 0, "the frames SQLite applied are counted");
      assert.match(answer.note, /write-ahead log/i);
    } finally {
      await chmod(dir, 0o755);
    }
    assert.deepEqual((await readdir(dir)).sort(), names.sort(), "nothing was added beside the evidence");
    const after = await Promise.all(names.map(async (n) => sha256(await readFile(join(dir, n)))));
    assert.deepEqual(after, before);
    // No staged copy is left behind in work/.
    const left = await readdir(join(cwd, "work", "s1")).catch(() => [] as string[]);
    assert.deepEqual(left.filter((n) => n.startsWith("knowledgec-")), []);
    // As a job it stages under $OUT, and leaves nothing of it there: a sealed output holds no empty staging directory.
    const job = body<KcAnswer>(await asJob(KC, cwd, { db: "work/walcase/knowledgeC.db" }));
    assert.equal(job.entry_count, 7);
    assert.deepEqual(await readdir(join(cwd, "out")), []);
  });
});

test("knowledgec_query says it did not apply a time filter the database has no column for, and does not drop the filter silently", async () => {
  await withCwd(async (cwd) => {
    const db = join(cwd, "work", "nodate.db");
    await build(
      `
import sqlite3, sys
c = sqlite3.connect(sys.argv[1])
c.execute("CREATE TABLE ZOBJECT (Z_PK INTEGER PRIMARY KEY, ZSTREAMNAME VARCHAR, ZVALUESTRING VARCHAR)")
c.executemany("INSERT INTO ZOBJECT VALUES (?,?,?)", [(1, "/app/inFocus", "a"), (2, "/app/inFocus", "b")])
c.commit()
`,
      db,
    );
    const answer = body<KcAnswer>(await tool(KC, cwd, { db: "work/nodate.db", since: "2025-01-01T00:00:00Z" }));
    assert.deepEqual(answer.filters_unapplied, ["since"]);
    assert.equal(answer.entry_count, 2, "the rows are returned, and the answer says they are not filtered");
    assert.equal(answer.status, "partial");
    assert.deepEqual(answer.schema.joins, { ZSTRUCTUREDMETADATA: false, ZSOURCE: false });
    assert.equal(answer.entries[0].start, null);
    // With a date column the filter applies, and the answer says so.
    const real = await kcDb(cwd, "plain2");
    const win = body<KcAnswer>(await tool(KC, cwd, { db: real, since: "2025-01-31T07:08:10Z", until: "2025-01-31T07:15:50Z" }));
    assert.deepEqual(win.filters_applied, ["since", "until"]);
    assert.equal(win.filters_unapplied, undefined);
    assert.deepEqual(win.entries.map((e) => e.z_pk), [2, 3, 4]);
  });
});

test("knowledgec_query lists every stream in the database, not the thirty most numerous", async () => {
  await withCwd(async (cwd) => {
    const db = join(cwd, "work", "streams.db");
    await build(
      `
import sqlite3, sys
c = sqlite3.connect(sys.argv[1])
c.execute("CREATE TABLE ZOBJECT (Z_PK INTEGER PRIMARY KEY, ZSTREAMNAME VARCHAR, ZVALUESTRING VARCHAR, ZSTARTDATE TIMESTAMP)")
rows = []
pk = 0
for n in range(int(sys.argv[2])):
    for k in range(1 + n % 3):
        pk += 1
        rows.append((pk, "/stream/%03d" % n, "v", 700000000 + pk))
c.executemany("INSERT INTO ZOBJECT VALUES (?,?,?,?)", rows)
c.commit()
`,
      db,
      "40",
    );
    const answer = body<KcAnswer>(await tool(KC, cwd, { db: "work/streams.db" }));
    assert.equal(answer.streams_total, 40);
    assert.equal(answer.streams.length, 40);
    assert.deepEqual(answer.streams.map((s) => s.stream).sort(), Array.from({ length: 40 }, (_, i) => `/stream/${String(i).padStart(3, "0")}`));
    const first = answer.streams.find((s) => s.stream === "/stream/001");
    assert.equal(first?.count, 2);
    assert.equal(typeof first?.first_start_raw, "number");
    // Past the inline page the whole inventory is in a file the answer names.
    const many = join(cwd, "work", "streams250.db");
    await build(
      `
import sqlite3, sys
c = sqlite3.connect(sys.argv[1])
c.execute("CREATE TABLE ZOBJECT (Z_PK INTEGER PRIMARY KEY, ZSTREAMNAME VARCHAR, ZVALUESTRING VARCHAR, ZSTARTDATE TIMESTAMP)")
c.executemany("INSERT INTO ZOBJECT VALUES (?,?,?,?)", [(i + 1, "/s/%04d" % i, "v", 700000000 + i) for i in range(250)])
c.commit()
`,
      many,
    );
    const big = body<KcAnswer>(await tool(KC, cwd, { db: "work/streams250.db" }));
    assert.equal(big.streams_total, 250);
    assert.ok(big.streams_pages.all_results);
    const rows = (await readFile(join(cwd, big.streams_pages.all_results as string), "utf8")).trimEnd().split("\n");
    assert.equal(rows.length, 250);
  });
});

test("knowledgec_query writes every row to an out_file as it reads it, in start order with the row id as the tie-break, and does not overwrite", async () => {
  await withCwd(async (cwd) => {
    const db = join(cwd, "work", "ties.db");
    await build(
      `
import sqlite3, sys
c = sqlite3.connect(sys.argv[1])
c.execute("CREATE TABLE ZOBJECT (Z_PK INTEGER PRIMARY KEY, ZSTREAMNAME VARCHAR, ZVALUESTRING VARCHAR, ZSTARTDATE TIMESTAMP)")
# Three rows share one start; the physical order is not the key order.
c.executemany("INSERT INTO ZOBJECT VALUES (?,?,?,?)", [(30, "/s", "c", 700), (10, "/s", "a", 700), (20, "/s", "b", 700), (5, "/s", "z", 900)])
c.commit()
`,
      db,
    );
    const answer = body<KcAnswer>(await tool(KC, cwd, { db: "work/ties.db", limit: 2, out_file: "work/kc.jsonl" }));
    assert.equal(answer.entries.length, 2);
    assert.equal(answer.entry_count, 4);
    assert.equal(answer.inline_limited, true);
    assert.equal(answer.complete_entries, "work/kc.jsonl");
    const rows = (await readFile(join(cwd, "work", "kc.jsonl"), "utf8")).trimEnd().split("\n").map((l) => JSON.parse(l) as KcEntry);
    assert.deepEqual(rows.map((r) => r.z_pk), [10, 20, 30, 5]);
    const clash = refused(await tool(KC, cwd, { db: "work/ties.db", out_file: "work/kc.jsonl" }));
    assert.match(clash.error, /already exists/);
    // A path with characters a file: URI would end on is read as the file it names.
    await mkdir(join(cwd, "work", "odd#dir?x"), { recursive: true });
    const { copyFile } = await import("node:fs/promises");
    await copyFile(join(cwd, "work", "ties.db"), join(cwd, "work", "odd#dir?x", "knowledgeC.db"));
    const odd = body<KcAnswer>(await tool(KC, cwd, { db: "work/odd#dir?x/knowledgeC.db" }));
    assert.equal(odd.entry_count, 4);
  });
});

test("knowledgec_query keeps its answer valid JSON when a REAL is infinite", async () => {
  await withCwd(async (cwd) => {
    const db = join(cwd, "work", "inf.db");
    await build(
      `
import sqlite3, sys
c = sqlite3.connect(sys.argv[1])
c.execute("CREATE TABLE ZOBJECT (Z_PK INTEGER PRIMARY KEY, ZSTREAMNAME VARCHAR, ZVALUEDOUBLE FLOAT, ZSTARTDATE TIMESTAMP, ZENDDATE TIMESTAMP)")
c.execute("INSERT INTO ZOBJECT VALUES (1, '/s', 9e999, 700, 9e999)")
c.commit()
`,
      db,
    );
    const out = await tool(KC, cwd, { db: "work/inf.db" });
    assert.doesNotMatch(out.stdout, /\bInfinity\b/);
    const answer = body<KcAnswer>(out);
    assert.deepEqual(answer.entries[0].value_double, { _float: "inf" });
    assert.equal(answer.entries[0].duration_seconds, null);
    assert.equal(answer.entries[0].end, null);
    assert.equal(answer.status, "partial", "a time that could not be converted is said");
  });
});

/** Peak resident memory of a tool run in a process of its own, in MB (Linux reports KB, macOS bytes). */
async function peakRssMb(script: string, cwd: string, args: unknown): Promise<{ mb: number; stdout: string; code: number | null }> {
  const code = `
import resource, runpy, sys
sys.argv = [sys.argv[1]]
try:
    runpy.run_path(sys.argv[0], run_name="__main__")
finally:
    r = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
    sys.stderr.write("RSS_MB=%f\\n" % ((r / 1e6) if sys.platform == "darwin" else (r / 1e3)))
`;
  const out = await new Promise<Run>((resolve, reject) => {
    const child = spawn("python3", ["-c", code, script], { cwd, env: { ...process.env, ...AGENT } });
    const so: Buffer[] = [];
    const se: Buffer[] = [];
    child.stdout.on("data", (c: Buffer) => so.push(c));
    child.stderr.on("data", (c: Buffer) => se.push(c));
    child.on("error", reject);
    child.on("close", (c) => resolve({ code: c, stdout: Buffer.concat(so).toString("utf8"), stderr: Buffer.concat(se).toString("utf8") }));
    child.stdin.end(JSON.stringify(args));
  });
  const m = /RSS_MB=([0-9.]+)/.exec(out.stderr);
  assert.ok(m, out.stderr);
  return { mb: Number(m[1]), stdout: out.stdout, code: out.code };
}

test("knowledgec_query reads a large cell as its head and its length, not whole, and writes the whole only when asked", async () => {
  // A 300 MB zeroblob took 2.1 GB of memory, and a 50 MB TEXT value was printed inline.
  await withCwd(async (cwd) => {
    const db = join(cwd, "work", "big.db");
    await build(
      `
import sqlite3, sys
c = sqlite3.connect(sys.argv[1])
c.execute("CREATE TABLE ZOBJECT (Z_PK INTEGER PRIMARY KEY, ZSTREAMNAME VARCHAR, ZVALUESTRING VARCHAR, ZPAYLOAD BLOB, ZSTARTDATE TIMESTAMP)")
c.execute("INSERT INTO ZOBJECT VALUES (1, '/s', 'short', zeroblob(%s), 700)" % sys.argv[2])
c.execute("INSERT INTO ZOBJECT VALUES (2, '/s', ?, x'0102030405', 701)", ("t" * int(sys.argv[3]),))
c.commit()
`,
      db,
      "150000000",
      "20000000",
    );
    const run = await peakRssMb(KC, cwd, { db: "work/big.db" });
    assert.equal(run.code, 0);
    assert.ok(run.mb < 120, `peak memory ${run.mb} MB for a 150 MB cell and a 20 MB TEXT value`);
    assert.ok(run.stdout.length < 200_000, `the answer is ${run.stdout.length} bytes`);
    const answer = JSON.parse(run.stdout) as KcAnswer & { values: { truncated: number; exported: number } };
    const big = answer.entries[0].zobject_other as Record<string, { _blob_bytes: number; _base64: string; _truncated: boolean; _where: { table: string; column: string; rowid: number } }>;
    assert.equal(big.ZPAYLOAD._blob_bytes, 150_000_000);
    assert.equal(big.ZPAYLOAD._truncated, true);
    assert.equal(Buffer.from(big.ZPAYLOAD._base64, "base64").length, 4096);
    assert.deepEqual(big.ZPAYLOAD._where, { table: "ZOBJECT", column: "ZPAYLOAD", rowid: 1 });
    const text = answer.entries[1].value_string as unknown as { _text_head: string; _text_bytes: number; _truncated: boolean };
    assert.equal(text._text_bytes, 20_000_000);
    assert.equal(text._text_head.length, 4096);
    assert.equal(answer.values.truncated, 2);
    assert.equal(answer.values.exported, 0);
    assert.equal(answer.entries[1].zobject_other?.ZPAYLOAD !== undefined, true, "a small BLOB is whole");
    // Asked, the whole value is streamed to a file that the answer names, and nothing is cut.
    const exported = body<KcAnswer & { values: { exported: number; exported_bytes: number } }>(
      await tool(KC, cwd, { db: "work/big.db", stream: "/s", export_oversize: true, max_export_bytes: 200_000_000 }),
    );
    assert.equal(exported.values.exported, 2);
    const e1 = exported.entries[1].value_string as unknown as { _whole_value_file: string; _whole_value_bytes_written: number };
    assert.match(e1._whole_value_file, /^work\/s1\/tool-output\/knowledgec-values\/ZOBJECT\.ZVALUESTRING\.2\.txt$/);
    assert.equal(e1._whole_value_bytes_written, 20_000_000);
    assert.equal((await stat(join(cwd, e1._whole_value_file))).size, 20_000_000);
    assert.equal((await stat(join(cwd, e1._whole_value_file))).mode & 0o777, 0o600);
    // Over the export budget the value is not written, and the answer says so.
    const refusedExport = body<KcAnswer & { values: { exported: number } }>(
      await tool(KC, cwd, { db: "work/big.db", stream: "/s", export_oversize: true, max_export_bytes: 1000 }),
    );
    assert.equal(refusedExport.values.exported, 0);
    assert.equal(refusedExport.status, "partial");
    assert.ok(refusedExport.problems.some((p) => /max_export_bytes/.test(p)));
  });
});

test("knowledgec_query answers when a joined table's schema cannot be read or ZOBJECT has no stream column, and says what is missing", async () => {
  // PRAGMA table_info on a virtual table with a module that is not here, and a GROUP BY on a column that is not there, were tracebacks.
  await withCwd(async (cwd) => {
    const virt = join(cwd, "work", "virtual.db");
    await build(
      `
import sqlite3, sys
c = sqlite3.connect(sys.argv[1])
c.execute("CREATE TABLE ZOBJECT (Z_PK INTEGER PRIMARY KEY, ZSOURCE INTEGER, ZSTREAMNAME VARCHAR, ZVALUESTRING VARCHAR, ZSTARTDATE TIMESTAMP)")
c.execute("INSERT INTO ZOBJECT VALUES (1, 1, '/s', 'v', 700)")
c.commit()
c.execute("PRAGMA writable_schema=ON")
c.execute("INSERT INTO sqlite_master (type, name, tbl_name, rootpage, sql) VALUES ('table', 'ZSOURCE', 'ZSOURCE', 0, 'CREATE VIRTUAL TABLE ZSOURCE USING nosuchmodule(a)')")
c.execute("PRAGMA writable_schema=OFF")
c.commit()
`,
      virt,
    );
    const out = await tool(KC, cwd, { db: "work/virtual.db" });
    const answer = body<KcAnswer>(out);
    assert.equal(answer.status, "partial");
    assert.equal(answer.entry_count, 1);
    assert.equal(answer.schema.joins.ZSOURCE, false);
    assert.ok(answer.problems.some((p) => /schema of ZSOURCE could not be read/.test(p)), JSON.stringify(answer.problems));
    assert.ok(answer.problems.some((p) => /no such module/.test(p)));

    const nostream = join(cwd, "work", "nostream.db");
    await build(
      `
import sqlite3, sys
c = sqlite3.connect(sys.argv[1])
c.execute("CREATE TABLE ZOBJECT (Z_PK INTEGER PRIMARY KEY, ZVALUESTRING VARCHAR, ZSTARTDATE TIMESTAMP)")
c.execute("INSERT INTO ZOBJECT VALUES (1, 'v', 700)")
c.commit()
`,
      nostream,
    );
    const plainRun = body<KcAnswer>(await tool(KC, cwd, { db: "work/nostream.db" }));
    assert.equal(plainRun.status, "partial");
    assert.equal(plainRun.entry_count, 1);
    assert.equal(plainRun.streams_total, 0);
    assert.ok(plainRun.problems.some((p) => /no ZSTREAMNAME column/.test(p)));
    const filtered = body<KcAnswer>(await tool(KC, cwd, { db: "work/nostream.db", stream: "/app/%" }));
    assert.deepEqual(filtered.filters_unapplied, ["stream"]);
    assert.equal(filtered.entry_count, 1, "rows are returned, and the answer says they are not filtered by stream");
  });
});

test("knowledgec_query rolls back a hot journal in the private copy and says the main file's state changed there", async () => {
  // A rollback journal holds the old pages of a transaction that did not commit, not committed rows the main file lacks.
  await withCwd(async (cwd) => {
    const live = join(cwd, "work", "jlive.db");
    await build(KC_BUILD, live, "plain", join(cwd, "work", "unused"));
    const dir = join(cwd, "work", "jcase");
    await build(
      `
import os, shutil, sqlite3, sys
live, dest = sys.argv[1], sys.argv[2]
os.makedirs(dest)
c = sqlite3.connect(live, isolation_level=None)
c.execute("PRAGMA cache_size=10")
c.execute("BEGIN")
c.executemany("INSERT INTO ZOBJECT (Z_PK, Z_ENT, Z_OPT, ZSTREAMNAME, ZVALUESTRING, ZSTARTDATE) VALUES (?,3,1,'/x',?,760001000)",
              [(1000 + i, "uncommitted-%05d-" % i + "z" * 120) for i in range(20000)])
# The transaction is open: its pages have spilled into the database file, and the journal holds the originals.
shutil.copy(live, os.path.join(dest, "knowledgeC.db"))
shutil.copy(live + "-journal", os.path.join(dest, "knowledgeC.db-journal"))
c.execute("ROLLBACK")
c.close()
`,
      live,
      dir,
    );
    const before = await Promise.all((await readdir(dir)).map(async (n) => [n, sha256(await readFile(join(dir, n)))]));
    const answer = body<KcAnswer & { problems: string[] }>(await tool(KC, cwd, { db: "work/jcase/knowledgeC.db" }));
    assert.equal(answer.entry_count, 6, "the uncommitted rows are not in the result");
    const journal = (answer.source_used as unknown as { journal: { bytes: number; sha256: string; rollback_applied: boolean; journal_present_after_open: boolean; database_sha256_as_acquired: string; database_sha256_after_open: string } }).journal;
    assert.ok(journal.bytes > 0);
    assert.match(journal.sha256, /^[0-9a-f]{64}$/);
    assert.equal(journal.rollback_applied, true);
    assert.equal(journal.journal_present_after_open, false);
    assert.notEqual(journal.database_sha256_after_open, journal.database_sha256_as_acquired);
    assert.equal(answer.status, "partial");
    assert.ok(answer.problems.some((p) => /rolled back the uncommitted transaction/.test(p) && /changed in the copy/.test(p)), JSON.stringify(answer.problems));
    assert.doesNotMatch(answer.note, /journal.*committed rows/i);
    const after = await Promise.all((await readdir(dir)).map(async (n) => [n, sha256(await readFile(join(dir, n)))]));
    assert.deepEqual(after, before, "the evidence directory is as it was");
  });
});

test("knowledgec_query keeps a larger earlier result when a rerun of the same query finds fewer rows", async () => {
  await withCwd(async (cwd) => {
    const db = join(cwd, "work", "rerun.db");
    const make = `
import sqlite3, sys
c = sqlite3.connect(sys.argv[1])
c.execute("CREATE TABLE ZOBJECT (Z_PK INTEGER PRIMARY KEY, ZSTREAMNAME VARCHAR, ZVALUESTRING VARCHAR, ZSTARTDATE TIMESTAMP)")
c.executemany("INSERT INTO ZOBJECT VALUES (?,?,?,?)", [(i, "/s", "v%d" % i, 700 + i) for i in range(1, int(sys.argv[2]) + 1)])
c.commit()
`;
    await build(make, db, "10");
    const first = body<KcAnswer & { kept_earlier_larger_result?: string }>(await tool(KC, cwd, { db: "work/rerun.db", limit: 2 }));
    const firstFile = first.complete_entries as string;
    assert.equal((await readFile(join(cwd, firstFile), "utf8")).trimEnd().split("\n").length, 10);
    await build(`import os, sys\nos.unlink(sys.argv[1])`, db);
    await build(make, db, "4");
    const second = body<KcAnswer & { kept_earlier_larger_result?: string }>(await tool(KC, cwd, { db: "work/rerun.db", limit: 2 }));
    assert.notEqual(second.complete_entries, firstFile);
    assert.equal(second.kept_earlier_larger_result, firstFile);
    assert.equal((await readFile(join(cwd, firstFile), "utf8")).trimEnd().split("\n").length, 10, "the earlier, larger result is intact");
    assert.equal((await readFile(join(cwd, second.complete_entries as string), "utf8")).trimEnd().split("\n").length, 4);
  });
});

test("knowledgec_query refuses a file that is not a knowledgeC database, and says what it found", async () => {
  await withCwd(async (cwd) => {
    await writeFile(join(cwd, "work", "text.db"), "not a database at all, just text\n");
    assert.match(refused(await tool(KC, cwd, { db: "work/text.db" })).error, /not a SQLite database/);
    await build(`import sqlite3, sys\nc = sqlite3.connect(sys.argv[1]); c.execute("CREATE TABLE other (a)"); c.commit()`, join(cwd, "work", "other.db"));
    const other = refused(await tool(KC, cwd, { db: "work/other.db" }));
    assert.match(other.error, /no ZOBJECT/);
    assert.deepEqual(other.tables, ["other"]);
  });
});

// --- unified_log ------------------------------------------------------------------

const UL = join(MAC, "unified_log", "run.py");
const PYTHON = spawnSync("python3", ["-c", "import sys; print(sys.executable)"], { encoding: "utf8" }).stdout.trim();

type UlAnswer = {
  status: string;
  engine: string;
  exit_code: number | null;
  timed_out?: boolean;
  command: string;
  output: string | null;
  output_sha256: string | null;
  entry_count: number;
  entries: Record<string, unknown>[];
  entries_inline: number;
  unparsed_lines: number;
  records_without_entry_fields?: number;
  decoded_coverage: {
    lines: number;
    json_records: number;
    entry_records: number;
    unparsed_lines: number;
    records_without_entry_fields: number;
    support_files?: unknown;
  };
  stderr: string | null;
  stderr_bytes: number;
  reader: { path?: string; version?: string | null; platform?: string };
  staging?: { staged: boolean; files: number; bytes: number; sources: string[] } | null;
  timeout_seconds_used: number;
  timeout_clamped?: boolean;
  problems: string[];
};

/** A stand-in for unifiedlog_iterator that writes what ULI_MODE says, on a PATH that holds nothing else (a Mac's own /usr/bin/log would be chosen first). */
async function ulBin(cwd: string, apple = false): Promise<string> {
  const bin = join(cwd, "ulbin");
  await mkdir(bin, { recursive: true });
  await symlink(PYTHON, join(bin, "python3")).catch(() => undefined);
  const reader = `#!${PYTHON}
import json, os, sys, time
a = sys.argv[1:]
mode = os.environ.get("ULI_MODE", "rows")
if "--version" in a:
    print("unifiedlog_iterator 9.9.9-test")
    sys.exit(0)
def arg(flag):
    return a[a.index(flag) + 1]
def row(i):
    return json.dumps({"timestamp": "2026-02-14T09:30:%02d.000000+0000" % (i % 60), "eventMessage": "message %d" % i, "process": "sudo", "subsystem": "com.apple.test"})
if %s:
    # Apple's log: the stream goes to stdout.
    out = sys.stdout
else:
    if mode == "nofile":
        sys.exit(0)
    out = open(arg("--output"), "w")
if mode == "rows":
    for i in range(3):
        out.write(row(i) + "\\n")
elif mode == "big":
    for i in range(1000):
        out.write(("{not json " + str(i) if i in (600, 700, 800, 900, 999) else row(i)) + "\\n")
elif mode == "trailer":
    for i in range(3):
        out.write(row(i) + "\\n")
    out.write(json.dumps({"finished": 1, "count": 3}) + "\\n")
elif mode == "hang":
    for i in range(3):
        out.write(row(i) + "\\n")
    out.flush()
    time.sleep(60)
elif mode == "empty":
    pass
out.flush()
`;
  const target = join(bin, apple ? "log" : "unifiedlog_iterator");
  await writeFile(target, reader.replace("%s", apple ? "True" : "False"));
  await chmod(target, 0o755);
  return bin;
}

async function ul(cwd: string, bin: string, args: Record<string, unknown>, mode = "rows"): Promise<Run> {
  // Only the stand-in's bin on PATH.
  return runPy(UL, cwd, args, undefined, { ...AGENT, PATH: bin, ULI_MODE: mode });
}

async function logarchive(cwd: string, name = "x.logarchive"): Promise<string> {
  const dir = join(cwd, "work", name);
  await mkdir(join(dir, "timesync"), { recursive: true });
  await writeFile(join(dir, "timesync", "0000.timesync"), "");
  return `work/${name}`;
}

/** A copy of /private/var/db: diagnostics and uuidtext side by side. */
async function dbCopy(cwd: string, files: Record<string, string> = {}): Promise<string> {
  const root = join(cwd, "work", "vardb");
  await mkdir(join(root, "diagnostics", "timesync"), { recursive: true });
  await mkdir(join(root, "uuidtext", "0A"), { recursive: true });
  await writeFile(join(root, "diagnostics", "timesync", "0000.timesync"), "t");
  await writeFile(join(root, "uuidtext", "0A", "B"), "u");
  for (const [rel, content] of Object.entries(files)) {
    await mkdir(join(root, rel, ".."), { recursive: true });
    await writeFile(join(root, rel), content);
  }
  return "work/vardb";
}

test("unified_log is not complete when the reader exits 0 and wrote no output file", async () => {
  // It said status complete, entry_count 0, exit 0.
  await withCwd(async (cwd) => {
    const bin = await ulBin(cwd);
    const out = await ul(cwd, bin, { path: await logarchive(cwd), out_dir: "work/u1" }, "nofile");
    assert.equal(out.code, 1);
    const answer = JSON.parse(out.stdout) as UlAnswer;
    assert.equal(answer.status, "failed");
    assert.equal(answer.exit_code, 0, "the reader's own exit code is still said");
    assert.equal(answer.output_sha256, null);
    assert.ok(answer.problems.some((p) => /wrote no output file/.test(p)), JSON.stringify(answer.problems));
  });
});

test("unified_log counts the whole stream, not the preview: malformed lines after the inline page are counted", async () => {
  // The Apple branch stopped parsing once its inline preview was full, and the Linux branch never parsed.
  await withCwd(async (cwd) => {
    const bin = await ulBin(cwd);
    const out = await ul(cwd, bin, { path: await logarchive(cwd), out_dir: "work/u2", limit: 50 }, "big");
    const answer = JSON.parse(out.stdout) as UlAnswer;
    assert.equal(answer.unparsed_lines, 5);
    assert.equal(answer.entry_count, 995);
    assert.equal(answer.entries.length, 50);
    assert.equal(answer.decoded_coverage.lines, 1000);
    assert.equal(answer.decoded_coverage.entry_records, 995);
    assert.equal(answer.status, "partial", "malformed lines make the coverage partial though the reader exited 0");
    assert.equal(answer.exit_code, 0);
    assert.ok(answer.problems.some((p) => /5 line\(s\)/.test(p)));
    assert.equal(answer.entries[0].process, "sudo");
  });
});

test("unified_log keeps a record with none of an entry's fields apart from the entries, and says so", async () => {
  await withCwd(async (cwd) => {
    const bin = await ulBin(cwd);
    const answer = JSON.parse((await ul(cwd, bin, { path: await logarchive(cwd), out_dir: "work/u3" }, "trailer")).stdout) as UlAnswer;
    assert.equal(answer.entry_count, 3);
    assert.equal(answer.decoded_coverage.json_records, 4);
    assert.equal(answer.decoded_coverage.records_without_entry_fields, 1);
    assert.equal(answer.status, "complete");
    assert.ok(answer.problems.length === 0 || answer.problems.every((p) => !/failed/.test(p)));
  });
});

test("unified_log says an output with no entries is empty, not complete", async () => {
  await withCwd(async (cwd) => {
    const bin = await ulBin(cwd);
    const out = await ul(cwd, bin, { path: await logarchive(cwd), out_dir: "work/u4" }, "empty");
    const answer = JSON.parse(out.stdout) as UlAnswer;
    assert.equal(answer.status, "empty");
    assert.equal(answer.entry_count, 0);
    assert.ok(answer.problems.some((p) => /no entries/.test(p)));
  });
});

test("unified_log refuses a link in the tree it would stage, and names it", async () => {
  // copytree(symlinks=True) copied the link as it was and handed the reader a tree with a way out.
  await withCwd(async (cwd) => {
    const bin = await ulBin(cwd);
    const path = await dbCopy(cwd);
    await symlink("/etc", join(cwd, "work", "vardb", "uuidtext", "escape"));
    const out = await ul(cwd, bin, { path, out_dir: "work/u5" });
    assert.equal(out.code, 1);
    const err = JSON.parse(out.stdout) as { error: string; link?: string };
    assert.match(err.error, /link/);
    assert.match(String(err.link), /uuidtext\/escape$/);
    assert.equal(await exists(join(cwd, "work", "u5", ".logarchive-input")), false, "the staging was removed");
    assert.equal(await exists(join(cwd, "work", "u5", "unifiedlogs.jsonl")), false, "the reader did not run");
    // A link as the root of one of the two trees is refused too.
    const linked = await dbCopy(cwd);
    const { rm } = await import("node:fs/promises");
    await rm(join(cwd, "work", "vardb", "uuidtext", "escape"));
    await rm(join(cwd, "work", "vardb", "uuidtext"), { recursive: true });
    await symlink("/etc", join(cwd, "work", "vardb", "uuidtext"));
    const root = await ul(cwd, bin, { path: linked, out_dir: "work/u5b" });
    assert.equal(root.code, 1);
    assert.match((JSON.parse(root.stdout) as { error: string }).error, /itself a link/);
  });
});

test("unified_log refuses a member present in both trees with different bytes, and stages one that is identical", async () => {
  await withCwd(async (cwd) => {
    const bin = await ulBin(cwd);
    const path = await dbCopy(cwd);
    await mkdir(join(cwd, "work", "vardb", "diagnostics", "dup"), { recursive: true });
    await mkdir(join(cwd, "work", "vardb", "uuidtext", "dup"), { recursive: true });
    await writeFile(join(cwd, "work", "vardb", "diagnostics", "dup", "same"), "same");
    await writeFile(join(cwd, "work", "vardb", "uuidtext", "dup", "same"), "same");
    const ok = JSON.parse((await ul(cwd, bin, { path, out_dir: "work/u6a" })).stdout) as UlAnswer;
    assert.equal(ok.status, "complete");
    assert.equal(ok.staging?.staged, true);
    await writeFile(join(cwd, "work", "vardb", "uuidtext", "dup", "same"), "different");
    const out = await ul(cwd, bin, { path, out_dir: "work/u6b" });
    assert.equal(out.code, 1);
    const err = JSON.parse(out.stdout) as { error: string; conflicts?: string[] };
    assert.match(err.error, /both/);
    assert.deepEqual(err.conflicts, ["dup/same"]);
  });
});

test("unified_log bounds what it stages, refuses over the bound, and says how much it counted", async () => {
  await withCwd(async (cwd) => {
    const bin = await ulBin(cwd);
    const path = await dbCopy(cwd);
    const out = await ul(cwd, bin, { path, out_dir: "work/u7", max_stage_files: 1 });
    assert.equal(out.code, 1);
    const err = JSON.parse(out.stdout) as { error: string; files?: number; max_stage_files?: number };
    assert.match(err.error, /max_stage_files/);
    assert.equal(err.max_stage_files, 1);
    assert.ok((err.files ?? 0) >= 2);
    assert.equal(await exists(join(cwd, "work", "u7", ".logarchive-input")), false);
    const ok = JSON.parse((await ul(cwd, bin, { path, out_dir: "work/u7b" })).stdout) as UlAnswer;
    assert.equal(ok.staging?.files, 2);
    assert.equal(ok.staging?.bytes, 2);
  });
});

test("unified_log does not overwrite an earlier run's output: a directory that holds one is refused", async () => {
  await withCwd(async (cwd) => {
    const bin = await ulBin(cwd);
    const first = await ul(cwd, bin, { path: await logarchive(cwd), out_dir: "work/u8" });
    const kept = await readFile(join(cwd, "work", "u8", "unifiedlogs.jsonl"), "utf8");
    assert.equal(first.code, 0);
    const again = await ul(cwd, bin, { path: await logarchive(cwd), out_dir: "work/u8" }, "big");
    assert.equal(again.code, 1);
    assert.match((JSON.parse(again.stdout) as { error: string }).error, /already holds/);
    assert.equal(await readFile(join(cwd, "work", "u8", "unifiedlogs.jsonl"), "utf8"), kept);
  });
});

test("unified_log clamps the timeout to what the tool's own limit allows, and a reader that overruns it leaves a partial receipt", async () => {
  await withCwd(async (cwd) => {
    const bin = await ulBin(cwd);
    const clamped = JSON.parse((await ul(cwd, bin, { path: await logarchive(cwd), out_dir: "work/u9", timeout_seconds: 99999 })).stdout) as UlAnswer;
    assert.equal(clamped.timeout_clamped, true);
    assert.ok(clamped.timeout_seconds_used <= 1100, String(clamped.timeout_seconds_used));
    const out = await ul(cwd, bin, { path: await logarchive(cwd), out_dir: "work/u10", timeout_seconds: 2 }, "hang");
    assert.equal(out.code, 1);
    const answer = JSON.parse(out.stdout) as UlAnswer;
    assert.equal(answer.timed_out, true);
    assert.equal(answer.status, "partial");
    assert.equal(answer.entry_count, 3, "what the reader wrote before it was stopped is kept and counted");
    assert.ok(answer.output && (await exists(join(cwd, answer.output))));
  });
});

test("unified_log records the reader's version, and declares the reader it needs", async () => {
  await withCwd(async (cwd) => {
    const bin = await ulBin(cwd);
    const answer = JSON.parse((await ul(cwd, bin, { path: await logarchive(cwd), out_dir: "work/u11" })).stdout) as UlAnswer;
    assert.equal(answer.reader.version, "unifiedlog_iterator 9.9.9-test");
    assert.match(answer.reader.path ?? "", /unifiedlog_iterator$/);
    const manifest = JSON.parse(await readFile(join(MAC, "unified_log", "manifest.json"), "utf8")) as { requires?: string[]; use?: { extensions?: string[] } };
    assert.deepEqual(manifest.requires, ["unifiedlog_iterator"]);
    assert.ok(manifest.use?.extensions?.includes(".tracev3"));
  });
});

const NOT_ROOT = process.getuid?.() !== 0;

test("unified_log as a job writes only under $OUT: an out_dir outside it is refused with a reason, a read-only parent is a JSON error", async () => {
  // The manifest's own example, out_dir work/ulog, ended in a traceback in a job: work/ is read-only there, and the harness maps only work/<id>/ to $OUT.
  await withCwd(async (cwd) => {
    const bin = await ulBin(cwd);
    const archive = await logarchive(cwd);
    await mkdir(join(cwd, "out"), { recursive: true });
    const job = { JOB_ID: "j-1", OUT: join(cwd, "out") };
    const outside = await runPy(UL, cwd, { path: archive, out_dir: "work/ulog" }, undefined, { ...AGENT, ...job, PATH: bin, ULI_MODE: "rows" });
    assert.equal(outside.code, 1);
    assert.doesNotMatch(outside.stderr, /Traceback/);
    const refusal = JSON.parse(outside.stdout) as { error: string; out_dir: string; out: string };
    assert.match(refusal.error, /only under \$OUT/);
    assert.equal(refusal.out_dir, "work/ulog");
    assert.equal(await exists(join(cwd, "work", "ulog")), false);
    const inside = await runPy(UL, cwd, { path: archive, out_dir: "out/ulog" }, undefined, { ...AGENT, ...job, PATH: bin, ULI_MODE: "rows" });
    assert.equal(JSON.parse(inside.stdout).status, "complete");
    assert.ok(await exists(join(cwd, "out", "ulog", "unifiedlogs.jsonl")));
  });
});

test("unified_log says an out_dir it cannot create is a JSON error, not a traceback", { skip: !NOT_ROOT }, async () => {
  await withCwd(async (cwd) => {
    const bin = await ulBin(cwd);
    const archive = await logarchive(cwd);
    await mkdir(join(cwd, "work", "ro"));
    await chmod(join(cwd, "work", "ro"), 0o555);
    try {
      const out = await ul(cwd, bin, { path: archive, out_dir: "work/ro/u" });
      assert.equal(out.code, 1);
      assert.doesNotMatch(out.stderr, /Traceback/);
      const err = JSON.parse(out.stdout) as { error: string; out_dir: string; reason: string };
      assert.match(err.error, /out_dir could not be created/);
      assert.match(err.reason, /Permission/);
    } finally {
      await chmod(join(cwd, "work", "ro"), 0o755);
    }
  });
});

test("unified_log does not stage a tree with a directory it cannot read, and counts one it cannot read in the census", { skip: !NOT_ROOT }, async () => {
  // An unreadable uuidtext/0B was left out of the staging without a word, and the run was complete.
  await withCwd(async (cwd) => {
    const bin = await ulBin(cwd);
    const path = await dbCopy(cwd);
    const hidden = join(cwd, "work", "vardb", "uuidtext", "0B");
    await mkdir(hidden);
    await writeFile(join(hidden, "C"), "u2");
    await chmod(hidden, 0o000);
    try {
      const out = await ul(cwd, bin, { path, out_dir: "work/u12" });
      assert.equal(out.code, 1);
      assert.doesNotMatch(out.stderr, /Traceback/);
      const err = JSON.parse(out.stdout) as { error: string; directory: string; reason: string };
      assert.match(err.error, /could not be read/);
      assert.match(err.directory, /uuidtext\/0B$/);
      assert.match(err.reason, /Permission/);
      assert.equal(await exists(join(cwd, "work", "u12", ".logarchive-input")), false, "the staging was removed");
      assert.equal(await exists(join(cwd, "work", "u12", "unifiedlogs.jsonl")), false, "the reader did not run");
      // A .logarchive is not staged, so the census says what it could not read.
      const archive = await logarchive(cwd, "y.logarchive");
      const sub = join(cwd, archive, "0F");
      await mkdir(sub);
      await chmod(sub, 0o000);
      try {
        const census = JSON.parse((await ul(cwd, bin, { path: archive, out_dir: "work/u13" })).stdout) as UlAnswer & { warnings: string[] };
        const files = census.decoded_coverage.support_files as { directories_unreadable: number; first_directories_unreadable: { directory: string }[] };
        assert.equal(files.directories_unreadable, 1);
        assert.match(files.first_directories_unreadable[0].directory, /0F$/);
        assert.ok(census.warnings.some((w) => /could not be read/.test(w)), JSON.stringify(census.warnings));
      } finally {
        await chmod(sub, 0o755);
      }
    } finally {
      await chmod(hidden, 0o755);
    }
  });
});

test("unified_log does not stage a tree with a file it cannot read", { skip: !NOT_ROOT }, async () => {
  await withCwd(async (cwd) => {
    const bin = await ulBin(cwd);
    const path = await dbCopy(cwd, { "uuidtext/0A/locked": "secret-ish" });
    const locked = join(cwd, "work", "vardb", "uuidtext", "0A", "locked");
    await chmod(locked, 0o000);
    try {
      const out = await ul(cwd, bin, { path, out_dir: "work/u14" });
      assert.equal(out.code, 1);
      assert.doesNotMatch(out.stderr, /Traceback/);
      const err = JSON.parse(out.stdout) as { error: string; path: string };
      assert.match(err.error, /could not be copied/);
      assert.match(err.path, /locked$/);
      assert.equal(await exists(join(cwd, "work", "u14", ".logarchive-input")), false);
    } finally {
      await chmod(locked, 0o644);
    }
  });
});

test("unified_log with Apple's log counts the whole stream, not the preview (macOS only: the tool picks log only there)", { skip: process.platform !== "darwin" }, async () => {
  await withCwd(async (cwd) => {
    const bin = await ulBin(cwd, true);
    const out = await ul(cwd, bin, { path: await logarchive(cwd), out_dir: "work/ua", limit: 20 }, "big");
    const answer = JSON.parse(out.stdout) as UlAnswer;
    assert.equal(answer.engine, "log");
    assert.equal(answer.unparsed_lines, 5);
    assert.equal(answer.entry_count, 995);
    assert.equal(answer.entries.length, 20);
    assert.equal(answer.status, "partial");
  });
});

// --- paging: names that are not UTF-8, reruns, and the byte bound ----------------------------

/** Load a tool's run.py as a module (its main() is guarded) and run Python against its classes. */
const LOAD = `
import importlib.util, json, os, sys
def load(path):
    spec = importlib.util.spec_from_file_location("tool", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module
`;

test("the tools' paging and values writers hold a file name that is not UTF-8", async () => {
  // A name the filesystem gave as bytes that are not UTF-8 reaches Python as a lone surrogate; json.dumps(ensure_ascii=False)
  // then failed writing a UTF-8 file, in the middle of a run (a values file already created, 0600, was left half written).
  await withCwd(async (cwd) => {
    for (const name of ["plist_read", "fsevents_parse", "knowledgec_query"]) {
      const out = await runPySnippet(
        `${LOAD}
m = load(sys.argv[1])
os.chdir(sys.argv[2])
os.environ["AGENT_ID"] = "s1"
page = m.LosslessPage("t", ["k"], 1)
for i in range(3):
    page.add({"file": "bad\\udcff-%d.plist" % i, "n": i})
result = page.finish()
rows = [json.loads(line) for line in open(result["all_results"], encoding="utf-8")]
print(json.dumps({"n": len(rows), "back": rows[1]["file"] == "bad\\udcff-1.plist"}))
`,
        [join(MAC, name, "run.py"), cwd],
        null,
      );
      assert.equal(out.code, 0, `${name}: ${out.stderr}`);
      assert.deepEqual(JSON.parse(out.stdout), { n: 3, back: true }, name);
    }
    const values = await runPySnippet(
      `${LOAD}
m = load(sys.argv[1])
os.chdir(sys.argv[2])
os.environ["JOB_ID"] = "j-9"
os.environ["OUT"] = os.path.join(sys.argv[2], "out9")
v = m.SecretValues(True)
v.add("F000001", {"file": "dir/bad\\udcff.plist", "key_path": "k"}, "value")
v.close()
row = json.loads(open(os.path.join(sys.argv[2], "out9", "plist-values.jsonl"), encoding="utf-8").readline())
print(json.dumps({"file_back": row["file"] == "dir/bad\\udcff.plist", "value": row["value"]}))
`,
      [join(MAC, "plist_read", "run.py"), cwd],
      null,
    );
    assert.equal(values.code, 0, values.stderr);
    assert.deepEqual(JSON.parse(values.stdout), { file_back: true, value: "value" });
  });
});

test("plist_read reads a directory whose file name is not UTF-8 end to end", { skip: process.platform === "darwin" }, async () => {
  // APFS refuses such a name, so this runs where the filesystem takes bytes (Linux).
  await withCwd(async (cwd) => {
    const dir = join(cwd, "work", "badnames");
    await mkdir(dir, { recursive: true });
    const bad = Buffer.concat([Buffer.from(dir + "/"), Buffer.from([0x62, 0x61, 0x64, 0xff]), Buffer.from(".plist")]);
    await writeFile(bad, bplist({ name: "x", ShadowHashData: [VERIFIER] }));
    await mkdir(join(cwd, "out"), { recursive: true });
    const run = await tool(PLIST, cwd, { path: "work/badnames", write_values: true, limit: 1 }, { JOB_ID: "j-1", OUT: join(cwd, "out") });
    assert.equal(run.code, 0, run.stderr);
    assert.doesNotMatch(run.stderr, /Traceback/);
    const rows = (await readFile(join(cwd, "out", "plist-values.jsonl"), "utf8")).trimEnd().split("\n");
    assert.equal(rows.length, 1);
  });
});

test("plist_read keeps a larger earlier result when a rerun of the same sweep finds fewer files", async () => {
  // A rerun with a smaller max_seconds (or fewer files) replaced a complete page file with a partial one of the same name.
  await withCwd(async (cwd) => {
    const dir = join(cwd, "work", "p");
    await mkdir(dir, { recursive: true });
    for (let i = 0; i < 8; i++) await writeFile(join(dir, `f${i}.plist`), bplist({ n: i }));
    const first = body<PlistAnswer & { kept_earlier_larger_result?: string }>(await tool(PLIST, cwd, { path: "work/p", limit: 2 }));
    const firstFile = first.complete_files as string;
    assert.equal((await readFile(join(cwd, firstFile), "utf8")).trimEnd().split("\n").length, 8);
    const { rm } = await import("node:fs/promises");
    for (let i = 3; i < 8; i++) await rm(join(dir, `f${i}.plist`));
    const second = body<PlistAnswer & { kept_earlier_larger_result?: string }>(await tool(PLIST, cwd, { path: "work/p", limit: 2 }));
    assert.notEqual(second.complete_files, firstFile);
    assert.equal(second.kept_earlier_larger_result, firstFile);
    assert.equal((await readFile(join(cwd, firstFile), "utf8")).trimEnd().split("\n").length, 8, "the earlier, larger result is intact");
    assert.equal((await readFile(join(cwd, second.complete_files as string), "utf8")).trimEnd().split("\n").length, 3);
  });
});

test("plist_read bounds its inline answer by bytes and keeps the whole in a file it names", async () => {
  await withCwd(async (cwd) => {
    await mkdir(join(cwd, "work", "p"), { recursive: true });
    for (let i = 0; i < 4; i++) {
      await writeFile(join(cwd, "work", "p", `f${i}.plist`), bplist({ name: i === 1 ? "x".repeat(40000) : `n${i}` }));
    }
    const run = await tool(PLIST, cwd, { path: "work/p", max_inline_bytes: 20000 });
    const answer = body<PlistAnswer & { inline_bounded_by_bytes: boolean; inline_byte_limit: number }>(run);
    assert.equal(answer.inline_bounded_by_bytes, true);
    assert.equal(answer.inline_byte_limit, 20000);
    assert.deepEqual(answer.files.map((f) => f.file.split("/").pop()), ["f0.plist"], "the page is a prefix: the rows before the one that does not fit");
    assert.ok(run.stdout.length < 20000 + 6000, `the answer is ${run.stdout.length} bytes`);
    const rows = (await readFile(join(cwd, answer.complete_files as string), "utf8")).trimEnd().split("\n").map((l) => JSON.parse(l) as PlistRow);
    assert.equal(rows.length, 4);
    assert.equal(((rows[1].value as { name: string }).name).length, 40000);
  });
});

test("fsevents_parse bounds its inline answer by bytes, keeps the whole, and counts a zero tail as padding", async () => {
  // A 59 MB path record made a 62 MB answer: the page was bounded by a count of records, not by bytes.
  await withCwd(async (cwd) => {
    const giant = "g".repeat(3_000_000);
    const tail = Buffer.alloc(30);
    const dir = await fsDir(cwd, "evbytes", {
      "0000000000000aaa": gzipSync(Buffer.concat([fsPage("2SLD", [fsRecord("small/one", 1n, CREATED, 1n), fsRecord(giant, 2n, CREATED, 2n), fsRecord("small/two", 3n, CREATED, 3n), tail])])),
    });
    const run = await tool(FS, cwd, { path: dir });
    const answer = body<FsAnswer & { inline_bounded_by_bytes: boolean; inline_byte_limit: number }>(run);
    assert.ok(run.stdout.length < 400_000, `the answer is ${run.stdout.length} bytes`);
    assert.equal(answer.inline_bounded_by_bytes, true);
    assert.deepEqual(answer.records.map((r) => r.path), ["small/one"], "a prefix of the records: up to the one that does not fit");
    assert.equal(answer.record_count, 3);
    assert.equal(answer.coverage.records.decoded, 3);
    assert.equal(answer.coverage.records.empty_path, 0);
    assert.equal((answer.coverage as unknown as { padding_bytes: number }).padding_bytes, 30);
    const rows = (await readFile(join(cwd, answer.complete_records as string), "utf8")).trimEnd().split("\n").map((l) => JSON.parse(l) as { path: string });
    assert.deepEqual(rows.map((r) => r.path.length), [9, 3_000_000, 9]);
    // With an out_file the inline page is bounded the same way and the file holds every record.
    const withFile = body<FsAnswer & { inline_bounded_by_bytes: boolean }>(await tool(FS, cwd, { path: dir, out_file: "work/fsb.jsonl" }));
    assert.equal(withFile.inline_bounded_by_bytes, true);
    assert.equal(withFile.records.length, 1);
    assert.equal((await readFile(join(cwd, "work", "fsb.jsonl"), "utf8")).trimEnd().split("\n").length, 3);
  });
});

test("fsevents_parse keeps a larger earlier result when a rerun of the same directory finds fewer records", async () => {
  await withCwd(async (cwd) => {
    const many = Array.from({ length: 6 }, (_, i) => fsRecord(`d/f${i}`, BigInt(10 + i), CREATED, BigInt(i)));
    const dir = await fsDir(cwd, "evrerun", { "0000000000000abc": gzipSync(fsPage("2SLD", many)) });
    const first = body<FsAnswer & { kept_earlier_larger_result?: string }>(await tool(FS, cwd, { path: dir, limit: 2 }));
    const firstFile = first.complete_records as string;
    await writeFile(join(cwd, dir, "0000000000000abc"), gzipSync(fsPage("2SLD", many.slice(0, 3))));
    const second = body<FsAnswer & { kept_earlier_larger_result?: string }>(await tool(FS, cwd, { path: dir, limit: 2 }));
    assert.notEqual(second.complete_records, firstFile);
    assert.equal(second.kept_earlier_larger_result, firstFile);
    assert.equal((await readFile(join(cwd, firstFile), "utf8")).trimEnd().split("\n").length, 6);
    assert.equal((await readFile(join(cwd, second.complete_records as string), "utf8")).trimEnd().split("\n").length, 3);
  });
});
