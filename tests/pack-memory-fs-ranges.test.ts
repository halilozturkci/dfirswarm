/**
 * mem_fs export names the ranges of each file it copies (PKG-HAR-18): a ranges file under $OUT/mem_fs/%ranges with the ranges read, the
 * ranges the mount did not give, the ranges not copied and the zero-filled pages (whole aligned 4096-byte pages of zeros), named in the
 * answer with its size and sha256. The engine is a stub on PATH; a read error and a file shorter than the size the mount reports are
 * stand-ins set by the sitecustomize of tests/memory-f1-support.ts; a full disk is a tmpfs of a few kilobytes (unshare -rm).
 * Every case here fails on the tool as it was before this change (no ranges file; a short file was exported as complete).
 */
import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { createHash } from "node:crypto";
import { mkdir, readFile, readdir, stat, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { test } from "node:test";
import { withCwd } from "./tool-library-harness.ts";
import { FS, fsStub, json, rng, runTool, shimDir } from "./memory-f1-support.ts";
import { NO_ADOPTION, NO_UNSHARE } from "./host-gates.ts";

const PAGE = 4096;
type Range = { kind: string; offset: number; length: number; why?: string; [k: string]: unknown };
type Info = {
  file: string; bytes: number | null; sha256: string | null; read_ranges: number; unavailable_ranges: number; not_copied_ranges: number;
  zero_filled_ranges: number; zero_filled_bytes: number; file_complete: boolean; problem: string | null;
};
type Item = { item_id: string; virtual_path: string; output?: string; bytes?: number; status: string; ranges?: Info };
type Fs = {
  status: string; status_basis: string; complete: boolean; secret_values?: { written: number }; items?: Item[]; counts?: Record<string, number>; note?: string;
  ranges?: Record<string, unknown> & { files: number; problems: number; zero_filled_ranges: number; zero_filled_means: string };
};

const jobDir = async (cwd: string, id = "j000043") => {
  const out = join(cwd, ".jobs", id);
  await mkdir(out, { recursive: true });
  return { out, job: { JOB_ID: id, OUT: out, SECRET_OUTPUT: "1" } };
};
const image = async (cwd: string) => writeFile(join(cwd, "inputs", "memory.raw"), Buffer.alloc(4096));
const args = (out: string, paths: string[], extra: Record<string, unknown> = {}) =>
  ({ path: "inputs/memory.raw", mount: join(out, "m"), mode: "export", write_values: true, paths, timeout_seconds: 60, ...extra });
const sidecar = async (out: string, rel: string) => {
  const bytes = await readFile(join(out, "mem_fs", "%ranges", `${rel}%.json`));
  return { bytes, rows: bytes.toString("utf8").trimEnd().split("\n").map((l) => JSON.parse(l) as Range) };
};
const kinds = (rows: Range[], kind: string) => rows.filter((r) => r.kind === kind).map((r) => [r.offset, r.length]);

/** Whole aligned pages of zeros, computed independently of the tool, joined into runs. */
function zeroRuns(data: Buffer): number[][] {
  const runs: number[][] = [];
  for (let off = 0; off + PAGE <= data.length; off += PAGE) {
    if (!data.subarray(off, off + PAGE).every((b) => b === 0)) continue;
    const last = runs[runs.length - 1];
    if (last && last[0] + last[1] === off) last[1] += PAGE; else runs.push([off, PAGE]);
  }
  return runs;
}
const filled = (pages: number, seed: number): Buffer => {
  const r = rng(seed);
  return Buffer.from(Array.from({ length: pages * PAGE }, () => 1 + Math.floor(r() * 255)));
};

test("a file with zero holes gets a ranges file naming the zero-filled pages and the bytes read, and the answer names it", async () => {
  await withCwd(async (cwd, bin) => {
    // pages 0-1 data, 2-3 zero, 4 data, 5 zero... a whole zero run, one lone zero page, and a 100-byte zero tail that is not a whole page
    const data = Buffer.concat([filled(2, 1), Buffer.alloc(2 * PAGE), filled(1, 2), Buffer.alloc(PAGE), filled(1, 3), Buffer.alloc(100)]);
    const env = await fsStub(cwd, bin, { tree: { "d/hole.bin": data, "sys/x": "" } });
    await image(cwd);
    const { out, job } = await jobDir(cwd);
    const run = json<Fs>(await runTool(FS, cwd, args(out, ["d/hole.bin"]), { ...env, ...job }, bin));
    assert.equal(run.status, "complete", run.status_basis);
    const item = run.items![0];
    assert.equal(item.status, "exported");
    const { bytes, rows } = await sidecar(out, "d/hole.bin");
    assert.deepEqual(kinds(rows, "zero_filled"), [[2 * PAGE, 2 * PAGE], [5 * PAGE, PAGE]]);
    assert.deepEqual(kinds(rows, "zero_filled"), zeroRuns(data));
    assert.deepEqual(kinds(rows, "read"), [[0, data.length]]);
    assert.deepEqual(kinds(rows, "unavailable"), []);
    assert.equal(rows[0].kind, "ranges");
    const summary = rows[rows.length - 1];
    assert.equal(summary.kind, "summary");
    assert.equal(summary.zero_filled_ranges, 2);
    assert.equal(summary.zero_filled_bytes, 3 * PAGE);
    assert.equal(summary.unjudged_tail_bytes, 100);
    // the answer names the sidecar with the size and sha256 of what is on disk, and a count of each class
    const info = item.ranges!;
    assert.equal(info.bytes, bytes.length);
    assert.equal(info.sha256, createHash("sha256").update(bytes).digest("hex"));
    assert.deepEqual([info.read_ranges, info.unavailable_ranges, info.not_copied_ranges, info.zero_filled_ranges, info.zero_filled_bytes], [1, 0, 0, 2, 3 * PAGE]);
    assert.equal(info.file_complete, true);
    assert.match(info.file, /\/mem_fs\/%ranges\/d\/hole\.bin%\.json$/);
    assert.equal(run.ranges?.files, 1);
    assert.match(run.ranges!.zero_filled_means, /not proof that data is missing/);
    assert.match(run.note!, /not proof that data is missing/);
    // the export itself is byte for byte and the manifest names the ranges file
    assert.ok((await readFile(join(out, "mem_fs", "d", "hole.bin"))).equals(data));
    const manifest = (await readFile(join(out, "mem_fs", "export-manifest.jsonl"), "utf8")).trimEnd().split("\n").map((l) => JSON.parse(l));
    assert.equal(manifest[0].ranges_file_sha256, info.sha256);
    assert.equal(((await stat(join(out, "mem_fs", "%ranges", "d", "hole.bin%.json"))).mode & 0o777), 0o600);
    assert.equal(run.secret_values?.written, 1, "the ranges file holds no value and is not counted as one");
  });
});

test("a file with no zero page has no zero-filled range, and a run that crosses the read chunk is one range", async () => {
  await withCwd(async (cwd, bin) => {
    const none = filled(8, 4);
    // 3 MiB: the zero run starts 8 KiB before the 1 MiB read boundary and ends 8 KiB after it; the third MiB has one zero page and a zero in a page of data
    const big = filled(768, 5);
    big.fill(0, (1 << 20) - 2 * PAGE, (1 << 20) + 2 * PAGE);
    big.fill(0, (2 << 20) + 3 * PAGE, (2 << 20) + 4 * PAGE);
    big[(2 << 20) + 9 * PAGE + 17] = 0;
    big.fill(0, (2 << 20) + 11 * PAGE + 1, (2 << 20) + 12 * PAGE); // a page of zeros but its first byte
    const env = await fsStub(cwd, bin, { tree: { "none.bin": none, "big.bin": big, "sys/x": "" } });
    await image(cwd);
    const { out, job } = await jobDir(cwd);
    const run = json<Fs>(await runTool(FS, cwd, args(out, ["none.bin", "big.bin"]), { ...env, ...job }, bin));
    assert.equal(run.status, "complete", run.status_basis);
    assert.equal(run.items![0].ranges!.zero_filled_ranges, 0);
    assert.deepEqual(kinds((await sidecar(out, "none.bin")).rows, "zero_filled"), []);
    const rows = (await sidecar(out, "big.bin")).rows;
    assert.deepEqual(kinds(rows, "zero_filled"), zeroRuns(big));
    assert.deepEqual(kinds(rows, "zero_filled").slice(0, 1), [[(1 << 20) - 2 * PAGE, 4 * PAGE]], "one range across the chunk boundary");
    assert.equal(kinds(rows, "zero_filled").length, 2);
  });
});

test("zero pages are found the same as an independent scan, on random holes", async () => {
  await withCwd(async (cwd, bin) => {
    const r = rng(99);
    const files: Record<string, Buffer> = { "sys/x": Buffer.alloc(0) };
    for (let n = 0; n < 4; n++) {
      const pages = 20 + Math.floor(r() * 300);
      const data = filled(pages, 10 + n);
      for (let h = 0; h < 10; h++) {
        const start = Math.floor(r() * pages) * PAGE, len = (1 + Math.floor(r() * 5)) * PAGE;
        data.fill(0, start, Math.min(start + len, data.length));
      }
      files[`r${n}.bin`] = Buffer.concat([data, Buffer.alloc(Math.floor(r() * PAGE))]);
    }
    const env = await fsStub(cwd, bin, { tree: files });
    await image(cwd);
    const { out, job } = await jobDir(cwd);
    const names = Object.keys(files).filter((k) => k.endsWith(".bin"));
    const run = json<Fs>(await runTool(FS, cwd, args(out, names), { ...env, ...job }, bin));
    assert.equal(run.status, "complete", run.status_basis);
    for (const name of names) assert.deepEqual(kinds((await sidecar(out, name)).rows, "zero_filled"), zeroRuns(files[name]), name);
  });
});

test("zero pages are found when the mount gives short reads that end inside a page", async () => {
  await withCwd(async (cwd, bin) => {
    const data = Buffer.concat([filled(1, 30), Buffer.alloc(3 * PAGE), filled(1, 31), Buffer.alloc(PAGE), Buffer.concat([Buffer.alloc(2500), filled(1, 33).subarray(0, PAGE - 2500)]), filled(2, 32), Buffer.alloc(2 * PAGE + 500)]);
    const env = await fsStub(cwd, bin, { tree: { "s.bin": data, "sys/x": "" } });
    await image(cwd);
    const shim = await shimDir(cwd);
    const { out, job } = await jobDir(cwd);
    for (const cap of ["1000", "4097", "6000", "1"]) {
      await mkdir(join(out, cap), { recursive: true });
      const run = json<Fs>(await runTool(FS, cwd, args(out, ["s.bin"], { mount: join(out, cap, "m") }),
        { ...env, ...job, JOB_ID: "j" + cap, OUT: join(out, cap), PYTHONPATH: shim, FAKE_ISMOUNT: "1", FAKE_SHORT_MATCH: "/s.bin", FAKE_SHORT_READ: cap }, bin));
      assert.equal(run.status, "complete", `${cap}: ${run.status_basis}`);
      assert.deepEqual(kinds((await sidecar(join(out, cap), "s.bin")).rows, "zero_filled"), zeroRuns(data), `read ${cap} bytes at a time`);
    }
  });
});

test("a read that fails with EIO at an injected offset gives an unavailable range, and the export is not complete", { skip: NO_ADOPTION }, async () => {
  await withCwd(async (cwd, bin) => {
    const data = filled(4, 6);
    const env = await fsStub(cwd, bin, { tree: { "d/eio.bin": data, "d/ok.bin": filled(2, 7), "sys/x": "" } });
    await image(cwd);
    const shim = await shimDir(cwd);
    const { out, job } = await jobDir(cwd);
    const run = json<Fs>(await runTool(FS, cwd, args(out, ["d/eio.bin", "d/ok.bin"]),
      { ...env, ...job, PYTHONPATH: shim, FAKE_ISMOUNT: "1", FAKE_EIO_MATCH: "/m/d/eio.bin", FAKE_EIO_AT: "6000" }, bin));
    assert.equal(run.status, "partial");
    assert.equal(run.complete, false);
    const [bad, good] = run.items!;
    assert.match(bad.status, /^failed: copying .*Input\/output error/);
    assert.equal(good.status, "exported");
    const rows = (await sidecar(out, "d/eio.bin")).rows;
    assert.deepEqual(kinds(rows, "read"), [[0, 6000]]);
    // the failing read asked for up to 1 MiB: the whole of it is listed, and the file is shorter than that
    assert.deepEqual(kinds(rows, "unavailable"), [[6000, data.length - 6000]]);
    assert.deepEqual(kinds(rows, "not_copied"), []);
    assert.match(String(rows.find((x) => x.kind === "unavailable")!.why), /read of up to 1048576 bytes at offset 6000 failed.*Input\/output error/);
    assert.equal(bad.ranges!.unavailable_ranges, 1);
    assert.equal(good.ranges!.unavailable_ranges, 0);
    assert.equal((await readFile(join(out, "mem_fs", "d", "eio.bin"))).length, 6000, "what was read is kept");
  });
});

test("a file that ends before the size the mount reports is partial with an unavailable range, never complete", async () => {
  await withCwd(async (cwd, bin) => {
    const data = filled(3, 8);
    const env = await fsStub(cwd, bin, { tree: { "d/short.bin": data, "sys/x": "" } });
    await image(cwd);
    const shim = await shimDir(cwd);
    const { out, job } = await jobDir(cwd);
    const run = json<Fs>(await runTool(FS, cwd, args(out, ["d/short.bin"]),
      { ...env, ...job, PYTHONPATH: shim, FAKE_ISMOUNT: "1", FAKE_LSTAT_MATCH: "/m/d/short.bin", FAKE_LSTAT_EXTRA: "8192" }, bin));
    assert.equal(run.status, "partial", run.status_basis);
    assert.equal(run.complete, false);
    assert.equal(run.counts?.partial, 1);
    assert.match(run.items![0].status, new RegExp(`^partial: the file ended at ${data.length} bytes and the mount reports ${data.length + 8192}`));
    const rows = (await sidecar(out, "d/short.bin")).rows;
    assert.deepEqual(kinds(rows, "unavailable"), [[data.length, 8192]]);
    assert.deepEqual(kinds(rows, "read"), [[0, data.length]]);
    assert.match(run.status_basis, /1 unavailable and 0 not copied range/);
  });
});

test("a ranges file that cannot be written whole is a problem of the file, named, and the answer is not complete", { skip: NO_UNSHARE }, async () => {
  await withCwd(async (cwd, bin) => {
    // 200 pages, every other one zero: about 100 runs of about 60 bytes each, more than the 4 KiB tmpfs the ranges directory is on
    const data = Buffer.concat(Array.from({ length: 200 }, (_, i) => (i % 2 ? Buffer.alloc(PAGE) : filled(1, 100 + i))));
    const env = await fsStub(cwd, bin, { tree: { "full.bin": data, "sys/x": "" } });
    await image(cwd);
    const { out, job } = await jobDir(cwd);
    await mkdir(join(out, "mem_fs", "%ranges"), { recursive: true, mode: 0o700 });
    const e: NodeJS.ProcessEnv = { ...process.env, AGENT_ID: "s1", ...env, ...job };
    e.PATH = `${bin}:${e.PATH ?? ""}`;
    const done = await new Promise<{ code: number | null; stdout: string }>((resolve, reject) => {
      const child = spawn("unshare", ["-rm", "sh", "-c", `mount -t tmpfs -o size=4k tmpfs "$OUT/mem_fs/%ranges" && exec python3 "${FS}"`], { cwd, env: e });
      let stdout = "";
      child.stdout.on("data", (c: Buffer) => { stdout += c.toString(); });
      child.on("error", reject);
      child.on("close", (code) => resolve({ code, stdout }));
      child.stdin.end(JSON.stringify(args(out, ["full.bin"])));
    });
    const run = JSON.parse(done.stdout) as Fs;
    assert.equal(run.items![0].status, "exported", "the memory was copied whole; the full disk is not a fact about it");
    assert.equal(run.counts?.exported, 1);
    assert.equal(run.items![0].ranges!.file_complete, false);
    assert.match(String(run.items![0].ranges!.problem), /could not be written whole.*(ENOSPC|No space)/);
    assert.equal(run.complete, false);
    assert.equal(run.ranges?.problems, 1);
    assert.match(run.status_basis, /ranges file\(s\) were not written whole/);
    assert.ok((await readFile(join(out, "mem_fs", "full.bin"))).equals(data));
  });
});

test("the ranges directory cannot be confused with an export, and a second export of the same name is refused without touching the first", async () => {
  await withCwd(async (cwd, bin) => {
    const env = await fsStub(cwd, bin, { tree: { "%ranges/x.json": "mine\n", "a.bin": filled(1, 20), "sys/x": "" } });
    await image(cwd);
    const { out, job } = await jobDir(cwd);
    const run = json<Fs>(await runTool(FS, cwd, args(out, ["%ranges/x.json", "a.bin", "a.bin"]), { ...env, ...job }, bin));
    assert.deepEqual(run.items!.map((i) => i.status.split(":")[0]), ["exported", "exported", "refused"]);
    assert.equal(await readFile(join(out, "mem_fs", "%25ranges", "x.json"), "utf8"), "mine\n");
    assert.deepEqual((await readdir(join(out, "mem_fs", "%ranges"))).sort(), ["%25ranges", "a.bin%.json"]);
    assert.equal(run.items![2].ranges, undefined, "a refused export has no ranges file");
  });
});

test("a stop in the middle of an export answers with one JSON, and the ranges file of the file being copied ends in its summary and names what was not copied", { skip: NO_UNSHARE }, async () => {
  await withCwd(async (cwd, bin) => {
    const data = Buffer.concat([filled(20, 40), Buffer.alloc(20 * PAGE), filled(20, 41)]);
    const env = await fsStub(cwd, bin, { tree: { "slow.bin": data, "sys/x": "" } });
    await image(cwd);
    const shim = await shimDir(cwd);
    const { out, job } = await jobDir(cwd);
    // one byte per read: the copy takes many seconds; the stop comes once the export file has some bytes
    const gate = async () => (await stat(join(out, "mem_fs", "slow.bin"))).size > 20000;
    const run = await runTool(FS, cwd, args(out, ["slow.bin"]),
      { ...env, ...job, PYTHONPATH: shim, FAKE_ISMOUNT: "1", FAKE_SHORT_MATCH: "/m/slow.bin", FAKE_SHORT_READ: "1" }, bin, "SIGTERM", 0, gate);
    assert.equal(run.code, 143, run.stderr);
    const answer = JSON.parse(run.stdout) as Fs & { interrupted?: boolean };
    assert.equal(answer.status, "interrupted");
    const item = answer.items![0];
    assert.match(item.status, /^partial: the call was stopped/);
    const { rows } = await sidecar(out, "slow.bin");
    assert.equal(rows[rows.length - 1].kind, "summary");
    const copied = (await readFile(join(out, "mem_fs", "slow.bin"))).length;
    assert.deepEqual(kinds(rows, "read"), [[0, copied]]);
    assert.deepEqual(kinds(rows, "not_copied"), [[copied, data.length - copied]]);
    assert.equal(item.ranges!.not_copied_ranges, 1);
    assert.equal(item.ranges!.sha256, createHash("sha256").update(await readFile(join(out, "mem_fs", "%ranges", "slow.bin%.json"))).digest("hex"));
  });
});

for (const [signal, number] of [["SIGTERM", 143], ["SIGINT", 130], ["SIGHUP", 129]] as const) {
  test(`${signal} in the middle of a copy of a large sparse file: the file is listed with a manifest row, and its ranges file is named and ends in its summary`, async () => {
    for (let round = 0; round < 4; round++) {
      await withCwd(async (cwd, bin) => {
        const env = await fsStub(cwd, bin, { tree: { "small.bin": filled(1, 50), "sys/x": "" }, sparse: { "d/huge.bin": 3 * 2 ** 30 } });
        await image(cwd);
        const { out, job } = await jobDir(cwd);
        const run = await runTool(FS, cwd, args(out, ["d/huge.bin", "small.bin"]), { ...env, ...job }, bin, signal, 2500);
        assert.equal(run.code, number, run.stderr);
        const answer = JSON.parse(run.stdout) as Fs & { unfinished?: unknown };
        assert.equal(answer.status, "interrupted");
        assert.equal(answer.unfinished, null, "the worker ended inside its grace period");
        assert.match(answer.status_basis, /kept and named/);
        const [huge, small] = answer.items!;
        assert.equal(huge.virtual_path, "d/huge.bin", JSON.stringify(answer.items));
        assert.match(huge.status, /^partial: the call was stopped/);
        assert.match(small.status, /^not attempted/);
        const disk = (await readFile(join(out, "mem_fs", "d", "huge.bin"))).length;
        assert.equal(huge.bytes, disk);
        const manifest = (await readFile(join(out, "mem_fs", "export-manifest.jsonl"), "utf8")).trimEnd().split("\n").map((l) => JSON.parse(l));
        assert.equal(manifest.length, 1);
        assert.equal(manifest[0].bytes, disk);
        const raw = await readFile(join(out, "mem_fs", "%ranges", "d", "huge.bin%.json"));
        assert.ok(raw.length > 0);
        const rows = raw.toString("utf8").trimEnd().split("\n").map((l) => JSON.parse(l) as Range);
        assert.equal(rows[rows.length - 1].kind, "summary");
        assert.deepEqual(kinds(rows, "not_copied"), [[disk, 3 * 2 ** 30 - disk]]);
        assert.equal(huge.ranges!.bytes, raw.length);
        assert.equal(huge.ranges!.sha256, createHash("sha256").update(raw).digest("hex"));
      });
    }
  });
}

test("ranges file names are prefix-free: exports a and a.json/b both get one", async () => {
  await withCwd(async (cwd, bin) => {
    const env = await fsStub(cwd, bin, { tree: { "a": "one\n", "a.json/b": "two\n", "sys/x": "" } });
    await image(cwd);
    const { out, job } = await jobDir(cwd);
    const run = json<Fs>(await runTool(FS, cwd, args(out, ["a", "a.json/b"]), { ...env, ...job }, bin));
    assert.equal(run.status, "complete", run.status_basis);
    assert.deepEqual((await sidecar(out, "a")).rows.at(-1)!.kind, "summary");
    assert.deepEqual((await sidecar(out, "a.json/b")).rows.at(-1)!.kind, "summary");
  });
});

test("a file longer than the mount reports is partial, naming both sizes", async () => {
  await withCwd(async (cwd, bin) => {
    const data = filled(3, 60);
    const env = await fsStub(cwd, bin, { tree: { "g.bin": data, "sys/x": "" } });
    await image(cwd);
    const shim = await shimDir(cwd);
    const { out, job } = await jobDir(cwd);
    const run = json<Fs>(await runTool(FS, cwd, args(out, ["g.bin"]),
      { ...env, ...job, PYTHONPATH: shim, FAKE_ISMOUNT: "1", FAKE_LSTAT_MATCH: "/m/g.bin", FAKE_LSTAT_EXTRA: "-4096" }, bin));
    assert.equal(run.status, "partial");
    assert.match(run.items![0].status, new RegExp(`^partial: the file gave ${data.length} bytes, 4096 more than the ${data.length - 4096} the mount reports`));
  });
});

test("when every ranges file is cut, the basis says the files were copied whole and the ranges files were not", { skip: NO_UNSHARE }, async () => {
  await withCwd(async (cwd, bin) => {
    const data = Buffer.concat(Array.from({ length: 200 }, (_, i) => (i % 2 ? Buffer.alloc(PAGE) : filled(1, 100 + i))));
    const env = await fsStub(cwd, bin, { tree: { "full.bin": data, "sys/x": "" } });
    await image(cwd);
    const { out, job } = await jobDir(cwd);
    await mkdir(join(out, "mem_fs", "%ranges"), { recursive: true, mode: 0o700 });
    const e: NodeJS.ProcessEnv = { ...process.env, AGENT_ID: "s1", ...env, ...job };
    e.PATH = `${bin}:${e.PATH ?? ""}`;
    const stdout = await new Promise<string>((resolve, reject) => {
      const child = spawn("unshare", ["-rm", "sh", "-c", `mount -t tmpfs -o size=4k tmpfs "$OUT/mem_fs/%ranges" && exec python3 "${FS}"`], { cwd, env: e });
      let s = "";
      child.stdout.on("data", (c: Buffer) => { s += c.toString(); });
      child.on("error", reject);
      child.on("close", () => resolve(s));
      child.stdin.end(JSON.stringify(args(out, ["full.bin"])));
    });
    const run = JSON.parse(stdout) as Fs;
    assert.match(run.status_basis, /^all 1 requested files were copied whole, but 1 ranges file\(s\) were not written whole/);
    assert.doesNotMatch(run.status_basis, /exported whole/);
  });
});
