/**
 * minidump_map (memory-forensics): hostile parameters, stops and size.
 *
 *  - every parameter of the manifest, given a value of the wrong type, a NUL, a lone surrogate, 300 characters, a huge integer, a nested
 *    list, an object or null, in a sensible call of each of three views: the answer is one JSON document and no traceback (the cases of
 *    tests/tool-contract-hostile.test.ts, driven from this tool's manifest);
 *  - a stop signal while the tool waits for its arguments, in the middle of a search and in the middle of writing a module: one JSON
 *    document, exit 128 plus the signal, and no file left behind;
 *  - a 200 MB sparse dump is searched by `find` inside a time and a memory bound (the speed is printed), with a needle across the tool's
 *    8 MiB piece boundary, one across two adjacent ranges and one at the very end; and the tool's own clock ends a search of a 32 GiB sparse
 *    dump with a partial that says where to resume.
 */
import assert from "node:assert/strict";
import { spawn, spawnSync } from "node:child_process";
import { mkdir, mkdtemp, open, readdir, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { after, before, test } from "node:test";
import { PYTHON3 } from "./host-gates.ts";
import { bareDump, call, doc, encode, hex, scene, SCRIPT, TOOL_DIR } from "./pack-memory-minidump-support.ts";

let dir = "";
before(async () => {
  dir = await mkdtemp(join(tmpdir(), "minidump-bounds-"));
  await mkdir(join(dir, "inputs"), { recursive: true });
  await writeFile(join(dir, "inputs", "p64.dmp"), encode(scene(64, "Zq7Lm2Xc9Vb4Nn6Hj8Kd3Fg5Ws1T")).file);
});
after(async () => { await rm(dir, { recursive: true, force: true }); });

/** A sparse dump: a head and ranges that are holes, with `plants` written at offsets counted from the start of the memory. */
async function sparse(name: string, ranges: Array<{ va: bigint; size: number }>, plants: Array<{ at: number; data: Buffer }>, module?: { base: bigint; size: number; name: string }): Promise<{ path: string; memoryAt: number }> {
  const { head, memoryAt } = bareDump(ranges, module ? { module } : undefined);
  const total = memoryAt + ranges.reduce((n, x) => n + x.size, 0);
  const fh = await open(join(dir, "inputs", name), "w");
  try {
    await fh.truncate(total);
    await fh.write(head, 0, head.length, 0);
    for (const p of plants) await fh.write(p.data, 0, p.data.length, memoryAt + p.at);
  } finally {
    await fh.close();
  }
  return { path: `inputs/${name}`, memoryAt };
}

const nest = (n: number): unknown => (n === 0 ? [] : [nest(n - 1)]);
const HOSTILE: Array<[string, unknown]> = [
  ["a list", [1]], ["an object", { a: 1 }], ["a number", 5], ["a float", 1.5], ["true", true], ["null", null], ["the empty string", ""],
  ["a NUL", "a\u0000b"], ["a lone surrogate", "x\udcffy"], ["300 characters", "n".repeat(300)], ["a huge integer", 10 ** 30], ["a negative integer", -1],
  ["a nested list", nest(40)], ["a list of strings", ["a", "b"]], ["a dot-dot path", "../../x"], ["an absolute path", "/proc/self/mem"],
  ["a hex string", "0xffffffffffffffff"], ["a huge hex string", "0x" + "f".repeat(24)], ["zero", 0], ["2**64", 18446744073709551616],
];

test("every parameter, given a hostile value in a call of each view, ends in one JSON document and no traceback", { timeout: 900_000 }, async () => {
  const manifest = JSON.parse(await readFile(join(TOOL_DIR, "manifest.json"), "utf8")) as { params: Record<string, unknown> };
  const bases: Array<Record<string, unknown>> = [
    { path: "inputs/p64.dmp" },
    { path: "inputs/p64.dmp", view: "memory" },
    { path: "inputs/p64.dmp", view: "threads" },
    { path: "inputs/p64.dmp", view: "va", addresses: ["0x7ff6a1b20000"] },
    { path: "inputs/p64.dmp", view: "find", needle: "payload" },
    { path: "inputs/p64.dmp", view: "module", module: "payload.exe" },
    { path: "inputs/p64.dmp", view: "read", va: "0x7ff6a1b20000", length: 4096 },
  ];
  const work: Array<{ label: string; args: unknown }> = [];
  for (const base of bases) for (const param of Object.keys(manifest.params)) for (const [label, value] of HOSTILE) work.push({ label: `${base.view ?? "summary"} ${param}=${label}`, args: { ...base, [param]: value } });
  // and calls that are not an object at all, or name a parameter the tool does not have
  for (const raw of ["", "{", "[]", "null", "7", "\"x\"", "{\"path\": 1e999}", "[".repeat(100_000), JSON.stringify({ path: "inputs/p64.dmp", nosuch: 1 }), JSON.stringify({ path: "inputs/p64.dmp", view: "nosuch" })])
    work.push({ label: `raw ${raw.slice(0, 20)}`, args: raw });
  const failures: string[] = [];
  let next = 0;
  let answered = 0;
  await Promise.all(Array.from({ length: 8 }, async () => {
    while (next < work.length) {
      const w = work[next++];
      const run = await call(dir, w.args);
      try {
        const a = doc(run);
        if (!a || typeof a !== "object" || !["complete", "partial", "failed"].includes(a.status)) failures.push(`${w.label}: status ${a?.status}`);
        else if (/unexpected failure/.test(a.error ?? "")) failures.push(`${w.label}: ${a.error} at line ${a.line}`);
        else if (a.status === "failed" ? run.code !== 1 : run.code !== 0) failures.push(`${w.label}: status ${a.status} with exit ${run.code}`);
        else answered++;
      } catch (e) {
        failures.push(`${w.label}: ${(e as Error).message.slice(0, 200)} (exit ${run.code}, ${run.stdout.length} bytes)`);
      }
    }
  }));
  assert.deepEqual(failures.sort(), []);
  assert.ok(answered >= 3000, `${answered} cases`);
  // nothing was written anywhere by any of them (no job, so no write is allowed)
  assert.deepEqual((await readdir(dir)).sort(), ["inputs"]);
});

test("a stop signal while the tool waits for its arguments: one JSON document, exit 143, nothing read", async () => {
  for (const signal of ["SIGTERM", "SIGINT", "SIGHUP"] as const) {
    const child = spawn(PYTHON3, [SCRIPT], { cwd: dir, env: { ...process.env, PYTHONDONTWRITEBYTECODE: "1" } });
    let stdout = "";
    let stderr = "";
    child.stdout.on("data", (b: Buffer) => { stdout += b.toString("utf8"); });
    child.stderr.on("data", (b: Buffer) => { stderr += b.toString("utf8"); });
    const closed = new Promise<{ code: number | null; by: string | null }>((resolve) => child.on("close", (code, by) => resolve({ code, by })));
    await new Promise((r) => setTimeout(r, 1500));
    child.kill(signal);
    await new Promise((r) => setTimeout(r, 300));
    child.stdin.end();
    const end = await closed;
    const number = { SIGTERM: 15, SIGINT: 2, SIGHUP: 1 }[signal];
    assert.deepEqual([end.by, end.code], [null, 128 + number], `${signal}: ${stderr}`);
    const a = JSON.parse(stdout);
    assert.deepEqual([a.status, a.interrupted, a.signal], ["failed", true, number]);
    assert.doesNotMatch(stderr, /Traceback/);
  }
});

const GIB = 1024 * 1024 * 1024;
const MIB = 1024 * 1024;

test("a stop signal in the middle of a search and in the middle of writing a module: one document, exit 128 + signal, no file left", { timeout: 300_000 }, async () => {
  const base = 0x20000000000n;
  const big = await sparse("stop.dmp", [{ va: base, size: 24 * GIB }], [], { base, size: 448 * MIB, name: "C:\\big\\huge.dll" });
  // (1) a case-folding search of 24 GiB (a hole in a sparse file) takes far longer than the 400 ms after which the stop is sent
  const t0 = Date.now();
  const searching = await call(dir, { path: big.path, view: "find", needle: "NoSuchNeedleAnywhere", ignore_case: true }, {}, { signal: "SIGTERM", when: () => Date.now() - t0 > 400 });
  assert.deepEqual([searching.signal, searching.code], [null, 143], searching.stderr);
  const a = doc(searching);
  assert.deepEqual([a.status, a.interrupted, a.signal], ["failed", true, 15]);
  assert.ok(searching.ms < 10_000, `answered ${searching.ms} ms after the start`);
  // (2) the module is being written (its hidden file has grown past 16 MiB) when the stop arrives
  const out = join(dir, "out-stop");
  const hidden = async (): Promise<boolean> => {
    for (const name of await readdir(join(out, "minidump_map"))) {
      if (name.startsWith(".module-")) return (await (await open(join(out, "minidump_map", name), "r").then(async (fh) => { const st = await fh.stat(); await fh.close(); return st; })).size) > 16 * MIB;
    }
    return false;
  };
  for (const signal of ["SIGTERM", "SIGINT"] as const) {
    const writing = await call(dir, { path: big.path, view: "module", base: hex(base), write_values: true }, { JOB_ID: "j000042", OUT: out, SECRET_OUTPUT: "1" }, { signal, when: hidden });
    assert.deepEqual([writing.signal, writing.code], [null, 128 + (signal === "SIGTERM" ? 15 : 2)], writing.stderr);
    const b = doc(writing);
    assert.deepEqual([b.status, b.interrupted], ["failed", true]);
    assert.match(b.status_basis, /a file it was writing was removed/);
    assert.deepEqual(await readdir(join(out, "minidump_map")), [], "neither the hidden file nor a half image is left");
  }
});

test("find over a 200 MB sparse dump: every planted needle, inside a time and a memory bound", { timeout: 300_000 }, async () => {
  const a0 = 0x10000000000n, a2 = 0x30000000000n;
  const ranges = [{ va: a0, size: 100 * MIB }, { va: a0 + BigInt(100 * MIB), size: 60 * MIB }, { va: a2, size: 40 * MIB }];
  const needle = Buffer.from("expand 32-byte k", "latin1");
  const at = [12345, 8 * MIB - 5, 100 * MIB - 7, 130 * MIB, 200 * MIB - needle.length];   // plain; across the 8 MiB piece; across ranges 1 and 2; in range 2; the very end
  const big = await sparse("big.dmp", ranges, at.map((n) => ({ at: n, data: needle })));
  const vaOf = (n: number): bigint => (n < 160 * MIB ? a0 + BigInt(n) : a2 + BigInt(n - 160 * MIB));
  // run under a wrapper that reports the peak memory of the tool's process
  const wrapper = [
    "import json, resource, subprocess, sys, time",
    "t = time.monotonic()",
    "p = subprocess.run([sys.executable, sys.argv[1]], input=sys.argv[2].encode(), capture_output=True)",
    "peak = resource.getrusage(resource.RUSAGE_CHILDREN).ru_maxrss * (1 if sys.platform == 'darwin' else 1024)",
    "print(json.dumps({'peak': peak, 'seconds': time.monotonic() - t, 'code': p.returncode, 'stdout': p.stdout.decode(), 'stderr': p.stderr.decode()}))",
  ].join("\n");
  const measure = (args: Record<string, unknown>): { peak: number; seconds: number; answer: Record<string, any> } => {
    const ran = spawnSync(PYTHON3, ["-c", wrapper, SCRIPT, JSON.stringify(args)], { cwd: dir, encoding: "utf8", env: { ...process.env, PYTHONDONTWRITEBYTECODE: "1" }, maxBuffer: 1 << 26 });
    const got = JSON.parse(ran.stdout);
    assert.equal(got.code, 0, got.stderr);
    assert.doesNotMatch(got.stderr, /Traceback/);
    return { peak: got.peak, seconds: got.seconds, answer: JSON.parse(got.stdout) };
  };
  const exact = measure({ path: big.path, view: "find", needle_hex: needle.toString("hex") });
  assert.equal(exact.answer.status, "complete");
  assert.deepEqual(exact.answer.hits.map((h: any) => [h.va, h.file_offset]), at.map((n) => [hex(vaOf(n)), big.memoryAt + n]));
  assert.equal(exact.answer.searched.bytes, 200 * MIB);
  const text = measure({ path: big.path, view: "find", needle: "expand 32-byte k" });
  assert.deepEqual(text.answer.hits.map((h: any) => [h.va, h.form]), at.map((n) => [hex(vaOf(n)), "utf-8"]));
  const folded = measure({ path: big.path, view: "find", needle: "EXPAND 32-BYTE K", ignore_case: true, encodings: ["utf-8"] });
  assert.deepEqual(folded.answer.hits.map((h: any) => h.va), at.map((n) => hex(vaOf(n))));
  const rows = [["hex needle", exact], ["text needle, UTF-8 and UTF-16LE", text], ["text needle, ignore_case", folded]] as const;
  for (const [label, m] of rows) {
    console.log(`minidump_map find, 200 MB sparse dump, ${label}: ${m.seconds.toFixed(2)} s (${(200 / m.seconds).toFixed(0)} MB/s end to end, the tool's own figure ${m.answer.searched.megabytes_per_second} MB/s), peak memory ${(m.peak / MIB).toFixed(1)} MB`);
    assert.ok(m.peak < 128 * MIB, `${label}: peak memory ${(m.peak / MIB).toFixed(1)} MB for a 200 MB dump`);
  }
  assert.ok(exact.seconds < 20 && text.seconds < 30, `the exact searches took ${exact.seconds.toFixed(1)} s and ${text.seconds.toFixed(1)} s`);
  assert.ok(folded.seconds < 120, `the case-folding search took ${folded.seconds.toFixed(1)} s`);
});

test("a case-folding search of memory made of one letter, for a long needle of that letter, is linear (it took minutes a piece as a regular expression)", { timeout: 120_000 }, async () => {
  const base = 0x50000000000n;
  const size = 24 * MIB;
  const { head, memoryAt } = bareDump([{ va: base, size }]);
  const body = Buffer.alloc(size, 0x41);                              // 24 MiB of "A"
  body.write("aAaAb", size - 4096, "latin1");
  await writeFile(join(dir, "inputs", "letters.dmp"), Buffer.concat([head, body]));
  const t0 = Date.now();
  const none = doc(await call(dir, { path: "inputs/letters.dmp", view: "find", needle: "a".repeat(1000) + "c", ignore_case: true, encodings: ["utf-8"] }));
  assert.deepEqual([none.status, none.hits.length, none.searched.bytes], ["complete", 0, size]);
  const long = doc(await call(dir, { path: "inputs/letters.dmp", view: "find", needle: "a".repeat(1000) + "b", ignore_case: true, encodings: ["utf-8"] }));
  assert.deepEqual(long.hits.map((h: any) => h.file_offset), [memoryAt + size - 4096 + 4 - 1000], "the one place where a thousand letters are followed by b");
  const one = doc(await call(dir, { path: "inputs/letters.dmp", view: "find", needle: "A".repeat(200) + "B", ignore_case: true }));
  assert.deepEqual(one.hits.map((h: any) => [h.va, h.file_offset, h.form]), [[hex(base + BigInt(size - 4096 + 4 - 200)), memoryAt + size - 4096 + 4 - 200, "utf-8"]]);
  const wideNone = doc(await call(dir, { path: "inputs/letters.dmp", view: "find", needle: "a".repeat(500) + "b", ignore_case: true, encodings: ["utf-16le"] }));
  assert.deepEqual([wideNone.status, wideNone.hits.length], ["complete", 0]);
  assert.ok(Date.now() - t0 < 30_000, `the three searches took ${Date.now() - t0} ms`);
  // the exact rule still holds where a lowered copy would lie: U+4100 is not U+6100, though their high bytes are A and a
  const units = Buffer.alloc(64);
  for (let i = 0; i < 32; i++) units.writeUInt16LE(i === 20 ? 0x6100 : 0x4100, 2 * i);
  const two = bareDump([{ va: base, size: 64 }]);
  await writeFile(join(dir, "inputs", "units.dmp"), Buffer.concat([two.head, units]));
  const exact = doc(await call(dir, { path: "inputs/units.dmp", view: "find", needle: "\u6100", ignore_case: true, encodings: ["utf-16le"] }));
  assert.deepEqual(exact.hits.map((h: any) => h.va), [hex(base + 40n)], "only the unit that is U+6100, not the 31 that are U+4100");
});

test("the tool's own clock ends a search with a truthful partial and a resume address, and the resumed search goes on from there", { timeout: 300_000 }, async () => {
  const base = 0x40000000000n;
  const needle = Buffer.from("LateNeedle-0001", "latin1");
  const big = await sparse("clock.dmp", [{ va: base, size: 32 * GIB }], [{ at: 32 * GIB - 4096, data: needle }]);
  const first = doc(await call(dir, { path: big.path, view: "find", needle: "latenEEDLE-0001", ignore_case: true, encodings: ["utf-8"], max_seconds: 1 }));
  assert.equal(first.status, "partial");
  assert.match(first.status_basis, /max_seconds \(1\) was reached; memory from 0x[0-9a-f]+ on was not searched/);
  assert.deepEqual([first.hits.length, first.page.truncated, first.page.total], [0, true, null]);
  const resume = BigInt(first.page.resume_va);
  assert.ok(resume > base && resume < base + BigInt(32 * GIB), "the resume address is inside the range, past its start");
  assert.equal(first.searched.bytes, Number(resume - base), "what was searched is what lies below the resume address");
  // from near the end, an exact search finishes and finds the needle
  const rest = doc(await call(dir, { path: big.path, view: "find", needle: needle.toString("latin1"), va_start: hex(base + BigInt(32 * GIB - 64 * MIB)) }));
  assert.equal(rest.status, "complete");
  assert.deepEqual(rest.hits.map((h: any) => [h.va, h.file_offset]), [[hex(base + BigInt(32 * GIB - 4096)), big.memoryAt + 32 * GIB - 4096]]);
});

test("the clock is looked at inside a piece: memory made of places that pass the folded search and fail the exact rule ends at max_seconds, and the chain gives every hit", { timeout: 300_000 }, async () => {
  // U+0141 is the bytes 41 01 in UTF-16LE; lowered for the search it is 61 01, which is what this memory is made of, so every second byte
  // is a place the plain search finds and the exact rule refuses. A piece of 8 MiB of it took 14.6 s for a needle of 300 such letters,
  // with max_seconds 1, when the clock was looked at only between pieces.
  const base = 0x60000000000n;
  const size = 12 * MIB;
  const needle = "Ł".repeat(300);
  const body = Buffer.alloc(size);
  for (let i = 0; i < size; i += 2) { body[i] = 0x61; body[i + 1] = 0x01; }
  const at = [1000, 8 * MIB - 100, 11 * MIB + 2];                           // plain; across the 8 MiB piece; near the end
  for (const n of at) Buffer.from(needle, "utf16le").copy(body, n);
  const { head, memoryAt } = bareDump([{ va: base, size }]);
  await writeFile(join(dir, "inputs", "refused.dmp"), Buffer.concat([head, body]));
  const hits: string[] = [];
  let start = "0x0", calls = 0, searched = 0;
  for (;;) {
    const run = await call(dir, { path: "inputs/refused.dmp", view: "find", needle, ignore_case: true, encodings: ["utf-16le"], max_seconds: 1, va_start: start });
    const a = doc(run);
    calls++;
    assert.ok(run.ms < 8_000, `call ${calls} with max_seconds 1 took ${run.ms} ms`);
    hits.push(...a.hits.map((h: any) => h.va));
    assert.ok(a.hits.every((h: any) => h.file_offset === memoryAt + Number(BigInt(h.va) - base)));
    searched += a.searched.bytes;
    if (a.page.resume_va === null) { assert.equal(a.status, "complete"); break; }
    assert.equal(a.status, "partial");
    assert.match(a.status_basis, /max_seconds \(1\) was reached; memory from 0x[0-9a-f]+ on was not searched/);
    assert.ok(BigInt(a.page.resume_va) > BigInt(start), "each call gets further");
    start = a.page.resume_va;
    assert.ok(calls < 200);
  }
  assert.deepEqual(hits, at.map((n) => hex(base + BigInt(n))), "every hit once, the one across the piece boundary among them");
  assert.equal(searched, size, "the calls searched every byte once between them");
  assert.ok(calls > 1, "the search did not fit one second, so the clock was what ended a call");
});
