/**
 * carve_handoff (memory-forensics): one hit of mem_carve made ready for its parser.
 *
 * The images are built here from the formats' own layouts (a registry hive's base block and bins, an event log file's header and chunks, a
 * Prefetch header, a SQLite header, a DOS/PE header), never from the tool's output, and the expected values are computed by the test
 * (checksums, offsets, digests). A test also holds the tool equal to mem_carve on the same image, field for field. Canaries are random
 * secret-shaped strings (tests/memory-f1-support.ts). Each case fails on the base code, where the tool is missing.
 */
import assert from "node:assert/strict";
import { spawn, spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import { mkdir, readFile, readdir, stat, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { test } from "node:test";
import { crc32 } from "node:zlib";
import { ROOT, withCwd } from "./tool-library-harness.ts";
import { CARVE, MEM, SHAPES, rng, runTool } from "./memory-f1-support.ts";

const HAND = join(MEM, "carve_handoff", "run.py");
const SECOND = 1000;
const sha = (b: Buffer): string => createHash("sha256").update(b).digest("hex");
type Answer = Record<string, any>;
const parse = (r: { stdout: string; stderr: string }): Answer => {
  assert.ok(!r.stderr.includes("Traceback"), r.stderr);
  return JSON.parse(r.stdout) as Answer;
};

// ---- the formats, from their layouts ----

/** A registry hive: base block (4096 bytes) and `bins` bins of `binSize` bytes. Checksum: the XOR of the first 127 dwords (0xFFFFFFFF -> 0xFFFFFFFE, 0 -> 1). */
function hive(opts: { bins?: number; binSize?: number; primary?: number; secondary?: number; breakAt?: number } = {}): Buffer {
  const bins = opts.bins ?? 3, binSize = opts.binSize ?? 4096;
  const out = Buffer.alloc(4096 + bins * binSize);
  out.write("regf", 0, "ascii");
  out.writeUInt32LE(opts.primary ?? 7, 4);
  out.writeUInt32LE(opts.secondary ?? 7, 8);
  out.writeUInt32LE(1, 0x14); out.writeUInt32LE(5, 0x18);
  out.writeUInt32LE(0x20, 0x24);
  out.writeUInt32LE(bins * binSize, 0x28);
  let x = 0;
  for (let i = 0; i < 127; i++) x = (x ^ out.readUInt32LE(i * 4)) >>> 0;
  out.writeUInt32LE(x === 0xffffffff ? 0xfffffffe : x === 0 ? 1 : x, 0x1fc);
  for (let i = 0; i < bins; i++) {
    const at = 4096 + i * binSize;
    if (opts.breakAt === i) continue;
    out.write("hbin", at, "ascii");
    out.writeUInt32LE(i * binSize, at + 4);
    out.writeUInt32LE(binSize, at + 8);
  }
  return out;
}

/** An event log file: 4096-byte file header declaring `chunks`, then chunks of 65536 bytes, each ElfChnk with header size 128 at 0x28 and its header CRC-32 at 0x7C. */
function evtx(chunks: number, bad: number | null = null, badCrc = false): Buffer {
  const out = Buffer.alloc(4096 + chunks * 65536);
  out.write("ElfFile\0", 0, "latin1");
  out.writeUInt32LE(128, 0x20); out.writeUInt16LE(3, 0x26); out.writeUInt16LE(chunks, 0x2a);
  for (let i = 0; i < chunks; i++) {
    if (bad === i) continue;
    const at = 4096 + i * 65536;
    out.write("ElfChnk\0", at, "latin1");
    out.writeUInt32LE(128, at + 0x28);
    const head = out.subarray(at, at + 0x200);
    const crc = crc32(Buffer.concat([head.subarray(0, 0x78), head.subarray(0x80, 0x200)]));
    out.writeUInt32LE(badCrc && i === 0 ? crc ^ 1 : crc, at + 0x7c);
  }
  return out;
}

/** A plain Prefetch record: version at 0, "SCCA" at 4, the file size at 0x0C. */
function scca(version: number, size: number): Buffer {
  const out = Buffer.alloc(size);
  out.writeUInt32LE(version, 0); out.write("SCCA", 4, "ascii"); out.writeUInt32LE(size, 0x0c);
  return out;
}

/** A SQLite database: header with page size 4096, `pages` pages, change counter equal to version-valid-for. */
function sqlite(pages: number, fileBytes = pages * 4096): Buffer {
  const out = Buffer.alloc(fileBytes);
  out.write("SQLite format 3\0", 0, "latin1");
  out.writeUInt16BE(4096, 16); out[18] = 1; out[19] = 1;
  out.writeUInt32BE(5, 24); out.writeUInt32BE(pages, 28); out.writeUInt32BE(5, 92);
  if (fileBytes > 100) out[100] = 13;
  return out;
}

/** A PE image header: "MZ\x90\0\x03", e_lfanew at 0x3C, "PE\0\0" there. */
function pe(): Buffer {
  const out = Buffer.alloc(1024);
  Buffer.from([0x4d, 0x5a, 0x90, 0x00, 0x03]).copy(out, 0);
  out.writeUInt32LE(0x80, 0x3c); out.write("PE\0\0", 0x80, "latin1");
  return out;
}

/** An image: filler, with each part placed at its offset. */
function image(size: number, parts: Array<[number, Buffer]>): Buffer {
  const out = Buffer.alloc(size, 0x00);
  for (const [at, b] of parts) b.copy(out, at);
  return out;
}

async function put(cwd: string, name: string, data: Buffer): Promise<string> {
  await writeFile(join(cwd, "inputs", name), data);
  return `inputs/${name}`;
}

const call = (cwd: string, args: Record<string, unknown>, env: Record<string, string> = {}, signal?: NodeJS.Signals, after = 0) =>
  runTool(HAND, cwd, args, env, undefined, signal, after);

async function secretJob(cwd: string, n = 1): Promise<{ env: Record<string, string>; out: string }> {
  const out = join(cwd, "job-out");
  await mkdir(out, { recursive: true });
  return { env: { JOB_ID: `job${n}`, OUT: out, SECRET_OUTPUT: "1" }, out };
}

test("Prefetch: the structure starts four bytes before SCCA when those bytes are a known version, and is not established otherwise", { timeout: 120 * SECOND }, async () => {
  await withCwd(async (cwd) => {
    const rec = scca(30, 0x200);
    const p = await put(cwd, "a.raw", image(0x8000, [[0x3000, rec]]));
    let out = parse(await call(cwd, { path: p, kind: "prefetch record", signature_offset: 0x3004, object_offset: 0x3000 }));
    assert.equal(out.object_offset, 0x3000);
    assert.equal(out.cut_from, 0x3000);
    assert.equal(out.page_aligned, true, "0x3000 is a multiple of 4096");
    assert.equal(out.object_offset_agrees, true);
    assert.equal(out.validation, "header plausible");
    assert.equal(out.declared_bytes, 0x200);
    assert.equal(out.requested_bytes, 1 << 17);
    assert.equal(out.available_bytes, 0x5000, "the file ends 0x5000 bytes after the structure");
    assert.equal(out.cut_complete, true);
    assert.equal(out.slice.sha256, sha(image(0x8000, [[0x3000, rec]]).subarray(0x3000, 0x8000)), "the digest is of the cut, computed by the test");
    assert.deepEqual(out.suggested_parsers.names, ["prefetch_mam"]);
    assert.equal(out.status, "complete");
    // the caller's start, if wrong, is said and never taken
    out = parse(await call(cwd, { path: p, kind: "prefetch record", signature_offset: 0x3004, object_offset: 0x3004 }));
    assert.equal(out.object_offset, 0x3000);
    assert.equal(out.object_offset_agrees, false);
    // four bytes that are not a Prefetch version: the start is not established, and the cut is from the signature
    const q = await put(cwd, "b.raw", image(0x8000, [[0x3000, (() => { const r = scca(99, 0x200); return r; })()]]));
    out = parse(await call(cwd, { path: q, kind: "prefetch record", signature_offset: 0x3004 }));
    assert.equal(out.object_offset, null);
    assert.equal(out.cut_from, 0x3004);
    assert.equal(out.validation, "unknown");
    // a signature at offset 0..3 has no four bytes before it
    const r = await put(cwd, "c.raw", Buffer.concat([Buffer.from("SCCA"), Buffer.alloc(4096)]));
    out = parse(await call(cwd, { path: r, kind: "prefetch record", signature_offset: 0 }));
    assert.equal(out.object_offset, null);
  });
});

test("registry hive: checksum, sequence numbers and the chain of bins; a break is fragmentation; a hive is never hashed and its bytes are written nowhere without write_values", { timeout: 120 * SECOND }, async () => {
  await withCwd(async (cwd) => {
    const h = hive();
    let out = parse(await call(cwd, { path: await put(cwd, "h.raw", image(1 << 20, [[0x10000, h]])), kind: "registry hive", signature_offset: 0x10000 }));
    assert.equal(out.validation, "header plausible");
    const byName = (o: Answer, n: string) => o.structure.checks.find((c: any) => c.name === n);
    assert.equal(byName(out, "base block checksum").result, "pass");
    assert.equal(byName(out, "sequence numbers").result, "pass");
    assert.equal(out.structure.fragmentation.state, "none seen");
    assert.equal(out.structure.fragmentation.bins_contiguous, 3);
    assert.equal(out.slice.sha256, null);
    assert.match(out.slice.sha256_withheld, /credential store/);
    assert.equal(out.slice.credential_possible, true);
    assert.equal(out.slice.written, false);
    assert.deepEqual(out.suggested_parsers.names, ["regkv"]);
    // a hive written to while it was copied: the sequence numbers differ
    out = parse(await call(cwd, { path: await put(cwd, "d.raw", image(1 << 20, [[0x10000, hive({ primary: 8, secondary: 7 })]])), kind: "registry hive", signature_offset: 0x10000 }));
    assert.equal(byName(out, "sequence numbers").result, "fail");
    assert.match(byName(out, "sequence numbers").detail, /transaction logs/);
    // a base block whose checksum is wrong
    const bad = hive(); bad[0x100] ^= 0xff;
    out = parse(await call(cwd, { path: await put(cwd, "e.raw", image(1 << 20, [[0x10000, bad]])), kind: "registry hive", signature_offset: 0x10000 }));
    assert.equal(byName(out, "base block checksum").result, "fail");
    // the second bin is not where the chain puts it: the pages are not adjacent
    out = parse(await call(cwd, { path: await put(cwd, "f.raw", image(1 << 20, [[0x10000, hive({ breakAt: 1 })]])), kind: "registry hive", signature_offset: 0x10000 }));
    assert.equal(out.structure.fragmentation.state, "break found");
    assert.equal(out.structure.fragmentation.break_at, 8192);
    assert.equal(out.structure.fragmentation.bins_contiguous, 1);
    assert.equal(out.structure.anomalies.rows.length, 1);
    assert.equal(out.status, "complete", "a break is a finding, not a failure of the tool");
    // examine_bytes ends the walk: partial, said
    const big = hive({ bins: 300 });
    out = parse(await call(cwd, { path: await put(cwd, "g.raw", image(3 << 20, [[0x1000, big]])), kind: "registry hive", signature_offset: 0x1000, examine_bytes: 1 << 20 }));
    assert.equal(out.structure.fragmentation.bins_contiguous, 255);
    assert.equal(out.structure.fragmentation.state, "not examined to the end");
    assert.equal(out.status, "partial");
    assert.match(out.status_basis, /examine_bytes/);
    // nothing was written anywhere
    assert.deepEqual(await readdir(join(cwd, "work")), []);
  });
});

test("event log file and chunk: each declared chunk must start with ElfChnk; a chunk's header CRC-32 is checked; the slice of this family is hashed", { timeout: 120 * SECOND }, async () => {
  await withCwd(async (cwd) => {
    const file = evtx(3);
    let out = parse(await call(cwd, { path: await put(cwd, "ev.raw", image(1 << 20, [[0x20000, file]])), kind: "event log file", signature_offset: 0x20000 }));
    assert.equal(out.validation, "header plausible");
    assert.equal(out.declared_bytes, 4096 + 3 * 65536);
    assert.equal(out.structure.fragmentation.state, "none seen");
    assert.equal(out.structure.fragmentation.chunks_contiguous, 3);
    const raw = image(1 << 20, [[0x20000, file]]);
    assert.equal(out.slice.sha256, sha(raw.subarray(0x20000, 0x20000 + out.available_bytes)));
    assert.deepEqual(out.suggested_parsers.names, ["evtx_carve"]);
    out = parse(await call(cwd, { path: await put(cwd, "ev2.raw", image(1 << 20, [[0x20000, evtx(3, 1)]])), kind: "event log file", signature_offset: 0x20000 }));
    assert.equal(out.structure.fragmentation.state, "break found");
    assert.equal(out.structure.fragmentation.chunks_contiguous, 1);
    assert.equal(out.structure.fragmentation.break_at, 4096 + 65536);
    // a chunk on its own
    const chunk = evtx(1).subarray(4096);
    out = parse(await call(cwd, { path: await put(cwd, "ck.raw", image(1 << 18, [[0x10000, chunk]])), kind: "event log chunk", signature_offset: 0x10000 }));
    assert.equal(out.structure.checks[0].result, "pass");
    assert.equal(out.declared_bytes, 65536);
    out = parse(await call(cwd, { path: await put(cwd, "ck2.raw", image(1 << 18, [[0x10000, evtx(1, null, true).subarray(4096)]])), kind: "event log chunk", signature_offset: 0x10000 }));
    assert.equal(out.structure.checks[0].result, "fail");
  });
});

test("SQLite, PE and a truncated hit: the header's own fields; the file ending first is truncated; other families are not checkable, which is not intact", { timeout: 120 * SECOND }, async () => {
  await withCwd(async (cwd) => {
    let out = parse(await call(cwd, { path: await put(cwd, "s.raw", image(1 << 18, [[0x4000, sqlite(4)]])), kind: "SQLite database", signature_offset: 0x4000 }));
    assert.equal(out.validation, "header plausible");
    assert.equal(out.declared_bytes, 4 * 4096);
    assert.equal(out.slice.sha256, null, "a database can be a credential store");
    assert.equal(out.structure.fragmentation.state, "not checkable");
    // the file ends inside the 100-byte header
    const tail = Buffer.concat([Buffer.alloc(1000), sqlite(1, 4096).subarray(0, 60)]);
    out = parse(await call(cwd, { path: await put(cwd, "t.raw", tail), kind: "SQLite database", signature_offset: 1000 }));
    assert.equal(out.validation, "truncated");
    // a header that declares more than the file holds
    out = parse(await call(cwd, { path: await put(cwd, "u.raw", image(0x6000, [[0x4000, sqlite(64, 0x2000)]])), kind: "SQLite database", signature_offset: 0x4000 }));
    assert.equal(out.validation, "truncated");
    assert.equal(out.cut_complete, false);
    assert.match(out.validation_detail, /the file ends/);
    // PE: the signature is MZ 90 00 03
    out = parse(await call(cwd, { path: await put(cwd, "p.raw", image(1 << 16, [[0x2000, pe()]])), kind: "PE header", signature_offset: 0x2000 }));
    assert.equal(out.validation, "header plausible");
    assert.equal(out.slice.credential_possible, false);
    assert.equal(out.structure.fragmentation.state, "not checkable");
    assert.deepEqual(out.suggested_parsers.names, []);
  });
});

test("the cut and the checks are mem_carve's: on one image every field of every hit of mem_carve is the tool's", { timeout: 180 * SECOND }, async () => {
  await withCwd(async (cwd) => {
    const parts: Array<[number, Buffer]> = [
      [0x01000, hive()], [0x08000, evtx(2)], [0x30000 - 0x2000, scca(26, 0x300)], [0x40000, sqlite(3)], [0x50000, pe()], [0x60010, scca(77, 0x300)],
      [0x70000, hive({ bins: 1 }).subarray(0, 100)], [0x7f000, sqlite(80, 0x1000)],
    ];
    const p = await put(cwd, "mix.raw", image(0x80000, parts));
    const carve = parse(await runTool(CARVE, cwd, { path: p, limit: 100 }));
    const hits: any[] = carve.hits;
    assert.ok(hits.length >= 7, `${hits.length} hits`);
    for (const hit of hits) {
      const out = parse(await call(cwd, { path: p, kind: hit.kind, signature_offset: hit.signature_offset, object_offset: hit.object_offset }));
      for (const field of ["object_offset", "page_aligned", "validation", "validation_detail", "declared_bytes", "requested_bytes", "available_bytes", "cut_complete"]) {
        assert.deepEqual(out[field], hit[field], `${hit.kind} at ${hit.signature_offset}: ${field}`);
      }
      if (hit.object_offset !== null) assert.equal(out.object_offset_agrees, true);
    }
  });
});

test("credential families: no hash and no bytes outside a secret job; write_values is refused outside a job and in one that is not secret output, before the image is opened; in a secret job the slice is a 0600 file and never in the answer", { timeout: 120 * SECOND }, async () => {
  await withCwd(async (cwd) => {
    const canary = SHAPES.ghp(rng(5));
    const body = hive();
    Buffer.from(canary).copy(body, 0x500);
    const p = await put(cwd, "c.raw", image(1 << 20, [[0x10000, body]]));
    const args = { path: p, kind: "registry hive", signature_offset: 0x10000 };
    // refusals: nothing is opened or written (the image does not even exist for the second call)
    for (const env of [{}, { JOB_ID: "j", OUT: join(cwd, "o") }]) {
      const out = parse(await call(cwd, { ...args, write_values: true }, env));
      assert.equal(out.status, "failed");
      assert.equal(out.write_values, "refused");
      assert.equal(out.written, false);
    }
    const none = parse(await call(cwd, { ...args, path: "inputs/absent.raw", write_values: true }));
    assert.equal(none.write_values, "refused", "decided before the image is looked at");
    assert.deepEqual(await readdir(join(cwd, "work")), []);
    // the secret job
    const { env, out: outDir } = await secretJob(cwd);
    const run = await call(cwd, { ...args, write_values: true }, env);
    const out = parse(run);
    assert.equal(out.status, "complete", out.status_basis);
    assert.equal(out.slice.written, true);
    assert.equal(out.slice.sha256, null, "a credential family is never hashed, written or not");
    assert.match(out.slice.file, /^store\/jobs\/job1\/out\/carve_handoff\/000000010000-registry_hive\.bin$/);
    assert.ok(!run.stdout.includes(canary));
    const file = join(outDir, "carve_handoff", "000000010000-registry_hive.bin");
    assert.equal((await stat(file)).mode & 0o777, 0o600);
    assert.equal((await stat(join(outDir, "carve_handoff"))).mode & 0o777, 0o700);
    const written = await readFile(file);
    assert.equal(written.length, out.available_bytes);
    assert.ok(written.includes(Buffer.from(canary)), "the bytes are in the file");
    assert.equal(out.secret_values.contains_secret_values, true);
    // a second run in the same job: an identical one names the same file; a different image takes the next free name; the first is not replaced
    assert.equal(parse(await call(cwd, { ...args, write_values: true }, env)).slice.file, out.slice.file);
    const other = Buffer.from(body); other[0x600] = 0x41;
    const p2 = await put(cwd, "c2.raw", image(1 << 20, [[0x10000, other]]));
    const again = parse(await call(cwd, { ...args, path: p2, write_values: true }, env));
    assert.match(again.slice.file, /000000010000-registry_hive-2\.bin$/);
    assert.deepEqual(await readFile(file), written);
    assert.deepEqual((await readdir(join(outDir, "carve_handoff"))).filter((n) => n.startsWith(".")), []);
    // a family that is not a credential store is hashed even when written
    const ev = await put(cwd, "ev.raw", image(1 << 20, [[0x20000, evtx(1)]]));
    const w = parse(await call(cwd, { path: ev, kind: "event log file", signature_offset: 0x20000, write_values: true }, env));
    assert.equal(w.slice.written, true);
    assert.equal(w.slice.sha256, sha(await readFile(join(outDir, "carve_handoff", "000000020000-event_log_file.bin"))));
  });
});

test("the downstream result is referenced, by path and size, only when it is a regular file under the run directory; it is not read", { timeout: 120 * SECOND }, async () => {
  await withCwd(async (cwd) => {
    const p = await put(cwd, "a.raw", image(0x8000, [[0x3000, scca(30, 0x200)]]));
    await writeFile(join(cwd, "inputs", "prefetch.json"), JSON.stringify({ rows: [1, 2, 3] }));
    const base = { path: p, kind: "prefetch record", signature_offset: 0x3004 };
    const out = parse(await call(cwd, { ...base, parser: "prefetch_mam", parser_result: "inputs/prefetch.json" }));
    assert.deepEqual({ ...out.downstream, result: undefined, note: undefined }, { parser: "prefetch_mam", result: undefined, bytes: 16, read: false, note: undefined });
    assert.equal(out.downstream.result, "inputs/prefetch.json");
    for (const bad of [{ parser: "prefetch_mam" }, { parser_result: "inputs/prefetch.json" }, { parser: "other", parser_result: "inputs/prefetch.json" },
      { parser: "regkv", parser_result: "/etc/passwd" }, { parser: "regkv", parser_result: "inputs" }, { parser: "regkv", parser_result: p }, { parser: "regkv", parser_result: "inputs/none.json" }]) {
      const r = parse(await call(cwd, { ...base, ...bad }));
      assert.equal(r.status, "failed", JSON.stringify(bad));
    }
    assert.equal(spawnSync("mkfifo", [join(cwd, "inputs", "fifo.json")]).status, 0);
    assert.equal(parse(await call(cwd, { ...base, parser: "regkv", parser_result: "inputs/fifo.json" })).status, "failed");
  });
});

test("a signature that is not at the offset, a FIFO, a missing or empty file, and hostile parameters give a JSON refusal, never a Traceback and never a hang", { timeout: 120 * SECOND }, async () => {
  await withCwd(async (cwd) => {
    const p = await put(cwd, "a.raw", image(0x8000, [[0x3000, scca(30, 0x200)]]));
    assert.equal(spawnSync("mkfifo", [join(cwd, "inputs", "pipe.raw")]).status, 0);
    await writeFile(join(cwd, "inputs", "empty.raw"), Buffer.alloc(0));
    const good = { path: p, kind: "prefetch record", signature_offset: 0x3004 };
    const bad: unknown[] = [
      {}, { ...good, path: "" }, { ...good, path: "inputs/a.raw\u0000" }, { ...good, path: "inputs/\ud800" }, { ...good, path: "inputs/pipe.raw" }, { ...good, path: "inputs" },
      { ...good, path: "inputs/none.raw" }, { ...good, path: "inputs/empty.raw" }, { ...good, kind: "registry hive" }, { ...good, kind: "nothing" }, { ...good, kind: 3 },
      { ...good, signature_offset: 0x3005 }, { ...good, signature_offset: 10 ** 30 }, { ...good, signature_offset: -1 }, { ...good, signature_offset: 1.5 },
      { ...good, signature_offset: true }, { ...good, signature_offset: "12" }, { ...good, signature_offset: 0x7fff }, { ...good, object_offset: -4 },
      { ...good, object_offset: "x" }, { ...good, write_values: "yes" }, { ...good, max_seconds: 1e999 }, { ...good, max_seconds: 10 ** 30 },
      { ...good, max_seconds: true }, { ...good, examine_bytes: 5 }, { ...good, examine_bytes: 10 ** 30 }, { ...good, surprise: 1 },
    ];
    for (const args of bad) {
      const t0 = Date.now();
      const run = await call(cwd, args as Record<string, unknown>);
      const out = parse(run);
      assert.equal(out.status, "failed", JSON.stringify(args).slice(0, 100));
      assert.ok(out.error && out.status_basis);
      assert.equal(run.code, 1);
      assert.ok(Date.now() - t0 < 10 * SECOND);
    }
    for (const raw of [Buffer.from("{"), Buffer.from("[".repeat(200000)), Buffer.from("{\"a\":".repeat(100000)), Buffer.from("[1]"), Buffer.from([0x7b, 0x22, 0xff, 0x22, 0x3a, 0x31, 0x7d])]) {
      const child = spawn("python3", [HAND], { cwd });
      let stdout = "", stderr = "";
      child.stdout.on("data", (c) => (stdout += c));
      child.stderr.on("data", (c) => (stderr += c));
      child.stdin.on("error", () => undefined);
      child.stdin.end(raw);
      const code = await new Promise<number | null>((r) => child.on("close", (c) => r(c)));
      assert.ok(!stderr.includes("Traceback"), stderr);
      assert.equal(JSON.parse(stdout).status, "failed");
      assert.equal(code, 1);
    }
  });
});

test("SIGTERM in the middle of a copy gives one document, exit 143, and names the slice file with a name ending in .partial; none is left under a hidden name; a second signal changes nothing", { timeout: 120 * SECOND }, async () => {
  await withCwd(async (cwd) => {
    const p = await put(cwd, "big.raw", image(70 << 20, [[0x1000, sqlite(1 << 14, 64 << 20)]]));
    const { env, out: outDir } = await secretJob(cwd);
    // the copy is slowed by the test's own patch of the reader, so the signal lands in it: the module is run as the harness would run it
    const code = [
      "import importlib.util, os, signal, sys, time",
      "spec = importlib.util.spec_from_file_location('t', sys.argv[1]); m = importlib.util.module_from_spec(spec); spec.loader.exec_module(m)",
      "calls = [0]; real = m.Image.read",
      "def slow(self, offset, length):",
      "    calls[0] += 1",
      "    if length >= m.BLOCK:",
      "        if calls[0] >= 6:",
      "            os.kill(os.getpid(), signal.SIGTERM); os.kill(os.getpid(), signal.SIGINT)",
      "            time.sleep(0.05)",
      "    return real(self, offset, length)",
      "m.Image.read = slow",
      "try:",
      "    m.run_guarded()",
      "except SystemExit as e:",
      "    sys.stdout.flush(); os._exit(e.code if isinstance(e.code, int) else 0)",
    ].join("\n");
    const child = spawn("python3", ["-c", code, HAND], { cwd, env: { ...process.env, ...env } });
    let stdout = "", stderr = "";
    child.stdout.on("data", (c) => (stdout += c));
    child.stderr.on("data", (c) => (stderr += c));
    child.stdin.end(JSON.stringify({ path: p, kind: "SQLite database", signature_offset: 0x1000, write_values: true }));
    const status = await new Promise<number | null>((r) => child.on("close", (c) => r(c)));
    assert.ok(!stderr.includes("Traceback"), stderr);
    assert.equal(status, 143);
    const out = JSON.parse(stdout);
    assert.equal(out.status, "failed");
    assert.equal(out.interrupted, true);
    assert.ok(out.kept_results.length === 1 && out.kept_results[0].endsWith(".partial"), JSON.stringify(out.kept_results));
    const names = await readdir(join(outDir, "carve_handoff"));
    assert.deepEqual(names.filter((n) => n.startsWith(".")), []);
    const partial = await readFile(join(outDir, "carve_handoff", out.kept_results[0].split("/").pop()));
    assert.ok(partial.length > 0 && partial.length < 64 << 20, `${partial.length} bytes`);
    assert.equal((await stat(join(outDir, "carve_handoff", out.kept_results[0].split("/").pop()))).mode & 0o777, 0o600);
  });
});

test("the manifest declares secret_output for write_values and says what the code does", async () => {
  const man = JSON.parse(await readFile(join(ROOT, "packs", "memory-forensics", "tools", "carve_handoff", "manifest.json"), "utf8")) as Record<string, any>;
  assert.deepEqual(man.secret_output, { when_args: ["write_values"] });
  assert.equal(man.params.write_values.type, "boolean");
  assert.equal(man.params.write_values.default, undefined);
  assert.equal(man.timeout_seconds, 300);
  assert.equal(man.needs, undefined);
  assert.deepEqual(Object.keys(man.params).sort(), ["examine_bytes", "kind", "max_seconds", "object_offset", "parser", "parser_result", "path", "signature_offset", "write_values"]);
  const script = await readFile(HAND, "utf8");
  assert.match(man.description, /default 120, at most 270/);
  assert.match(script, /DEFAULT_SECONDS, MAX_SECONDS, MIN_SECONDS = 120\.0, 270\.0, 5\.0/);
  assert.match(man.description, /default 64 MiB, at most 1 GiB/);
  assert.match(script, /DEFAULT_EXAMINE, MAX_EXAMINE = 64 << 20, 1 << 30/);
  assert.match(script, /^ANOMALIES_INLINE = 20$/m);
  assert.ok(man.description.includes("20 in the answer"));
  // the families whose slice is not hashed are the ones the manifest names
  for (const k of ["registry hive", "SQLite database", "binary property list"]) assert.ok(script.includes(`"${k}"`) && man.description.includes(k));
  assert.match(script, /CREDENTIAL_POSSIBLE = \("registry hive", "SQLite database", "binary property list"\)/);
  // it runs no program and imports no other tool
  assert.ok(!/subprocess|os\.system|Popen/.test(script));
  assert.ok(!/^\s*(import|from) (mem_carve|regkv|evtx_carve|mam_scan|prefetch_mam)/m.test(script) && !/windows-forensics\/tools/.test(script));
  // a random token placed in the image's path is not echoed (the backstop at the serialisation boundary)
  const r = rng(9);
  const token = SHAPES.ghp(r);
  await withCwd(async (cwd) => {
    await writeFile(join(cwd, "inputs", `mem_${token}.raw`), image(0x8000, [[0x3000, scca(30, 0x200)]]));
    const run = await call(cwd, { path: `inputs/mem_${token}.raw`, kind: "prefetch record", signature_offset: 0x3004 });
    assert.ok(!run.stdout.includes(token));
    assert.match(parse(run).path, /withheld \d+ characters/, "the path is judged like any string read from the evidence");
  });
});
