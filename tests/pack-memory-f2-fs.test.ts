/**
 * mem_fs, after the second review of the memory-forensics pack: private parent directories, the answer's word on values written by
 * earlier calls of the job, a byte count and a digest that agree with a disk that fills, engine logs with a bound, and exception text
 * that quotes no path. The engine is a stub on PATH and the full disk is an RLIMIT_FSIZE set by a sitecustomize (tests/memory-f1-support.ts).
 * Every case here fails on the tool as it was at the head of the first fix round.
 */
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { mkdir, readFile, stat, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { test } from "node:test";
import { withCwd } from "./tool-library-harness.ts";
import { FS, fsStub, json, rng, runTool, shimDir } from "./memory-f1-support.ts";

type Item = { item_id: string; virtual_path: string; output?: string; bytes?: number; bytes_on_disk?: number; status: string };
type Fs = {
  status: string; status_basis: string; error?: string; items?: Item[]; counts?: Record<string, number>; phase?: string;
  secret_values?: { requested: boolean; written: number; contains_secret_values: boolean; earlier_calls_in_this_job_wrote_values: boolean; note?: string };
  logs?: { stdout: string; stderr: string; stdout_bytes: number; stderr_bytes: number; stdout_dropped_bytes: number; stderr_dropped_bytes: number; cap_bytes: number };
  engine_stderr?: { lines: string[] };
};
const jobDir = async (cwd: string, id = "j000042") => {
  const out = join(cwd, ".jobs", id);
  await mkdir(out, { recursive: true });
  return { out, job: { JOB_ID: id, OUT: out, SECRET_OUTPUT: "1" } };
};
const image = async (cwd: string) => writeFile(join(cwd, "inputs", "memory.raw"), Buffer.alloc(4096));
const rows = async (out: string) => (await readFile(join(out, "mem_fs", "export-manifest.jsonl"), "utf8")).trimEnd().split("\n").map((l) => JSON.parse(l) as Record<string, unknown>);
const pick = (r: () => number, alphabet: string, n: number): string => Array.from({ length: n }, () => alphabet[Math.floor(r() * alphabet.length)]).join("");

test("every directory mem_fs creates for an export is mode 0700, the parents of a nested name too (P3-1)", async () => {
  await withCwd(async (cwd, bin) => {
    const env = await fsStub(cwd, bin, { tree: { "proc/deep/a.txt": "alpha\n", "sys/x": "" } });
    await image(cwd);
    const { out, job } = await jobDir(cwd);
    const run = json<Fs>(await runTool(FS, cwd, { path: "inputs/memory.raw", mount: join(out, "m"), mode: "export", write_values: true, paths: ["proc/deep/a.txt"], timeout_seconds: 30 }, { ...env, ...job }, bin));
    assert.equal(run.counts?.exported, 1);
    for (const dir of ["mem_fs", "mem_fs/proc", "mem_fs/proc/deep"]) assert.equal((await stat(join(out, dir))).mode & 0o777, 0o700, dir);
    assert.equal((await stat(join(out, "mem_fs", "proc", "deep", "a.txt"))).mode & 0o777, 0o600);
  });
});

test("a call that asks for no values still says the job's output holds the values earlier calls wrote (P3-2)", async () => {
  await withCwd(async (cwd, bin) => {
    const env = await fsStub(cwd, bin, { tree: { "proc/a.txt": "alpha\n", "sys/x": "" } });
    await image(cwd);
    const { out, job } = await jobDir(cwd);
    const first = json<Fs>(await runTool(FS, cwd, { path: "inputs/memory.raw", mount: join(out, "m1"), mode: "export", write_values: true, paths: ["proc/a.txt"], timeout_seconds: 30 }, { ...env, ...job }, bin));
    assert.equal(first.secret_values?.earlier_calls_in_this_job_wrote_values, false);
    const list = json<Fs>(await runTool(FS, cwd, { path: "inputs/memory.raw", mount: join(out, "m2"), mode: "list", list: "proc", timeout_seconds: 30 }, { ...env, ...job }, bin));
    assert.equal(list.secret_values?.requested, false);
    assert.equal(list.secret_values?.written, 0);
    assert.equal(list.secret_values?.contains_secret_values, true, "this call wrote none; the output holds values");
    assert.equal(list.secret_values?.earlier_calls_in_this_job_wrote_values, true);
    assert.match(list.secret_values?.note as string, /earlier calls of this job/);
    // a job that never wrote a value says false
    const fresh = await jobDir(cwd, "j000043");
    const none = json<Fs>(await runTool(FS, cwd, { path: "inputs/memory.raw", mount: join(fresh.out, "m"), mode: "list", list: "proc", timeout_seconds: 30 }, { ...env, ...fresh.job }, bin));
    assert.equal(none.secret_values?.contains_secret_values, false);
    assert.equal(none.secret_values?.earlier_calls_in_this_job_wrote_values, false);
  });
});

test("when the disk fills, the byte count, the manifest digest and the file agree, and the status says what is on disk (P3-6)", async () => {
  await withCwd(async (cwd, bin) => {
    const data = Buffer.from(Array.from({ length: 3 << 20 }, (_, i) => (i * 7 + (i >> 8)) & 0xff));
    const env = await fsStub(cwd, bin, { tree: { "big/m.bin": data, "small/s.txt": "tiny\n", "sys/x": "" } });
    await image(cwd);
    const shim = await shimDir(cwd);
    const { out, job } = await jobDir(cwd);
    // files over 1,500,000 bytes cannot be written: the second megabyte is a short write and then EFBIG
    const run = json<Fs>(await runTool(FS, cwd, { path: "inputs/memory.raw", mount: join(out, "m"), mode: "export", write_values: true, paths: ["big/m.bin", "small/s.txt"], timeout_seconds: 60 },
      { ...env, ...job, PYTHONPATH: shim, FAKE_ISMOUNT: "1", FAKE_FSIZE: "1500000" }, bin));
    const [big, small] = run.items as Item[];
    assert.match(big.status, /^failed: copying /);
    const onDisk = await readFile(join(out, "mem_fs", "big", "m.bin"));
    assert.equal(onDisk.length, 1_500_000);
    assert.equal(big.bytes, onDisk.length, "the count is what the disk holds");
    assert.match(big.status, new RegExp(`${onDisk.length} bytes are on disk and kept`));
    assert.equal(small.status, "exported");
    const row = (await rows(out)).find((r) => r.virtual_path === "big/m.bin");
    assert.equal(row?.bytes, onDisk.length);
    assert.equal(row?.sha256, createHash("sha256").update(onDisk).digest("hex"), "the digest is of the bytes in the file");
    assert.equal(run.counts?.failed, 1);
  });
});

test("the engine's logs keep the first megabyte of each stream and count the rest (P3-9)", async () => {
  await withCwd(async (cwd, bin) => {
    const flood = 3 << 20;
    const env = await fsStub(cwd, bin, { tree: { "sys/x": "" }, mode: "exit", flood });
    await image(cwd);
    const out = json<Fs>(await runTool(FS, cwd, { path: "inputs/memory.raw", mount: "work/s1/m", mode: "list", timeout_seconds: 30 }, env, bin));
    assert.equal(out.status, "failed");
    const logs = out.logs!;
    assert.equal(logs.cap_bytes, 1 << 20);
    for (const side of ["stdout", "stderr"] as const) {
      const file = await stat(logs[side]);
      assert.ok(file.size <= 1 << 20, `${side} log is ${file.size} bytes`);
      assert.equal(file.mode & 0o777, 0o600);
      assert.equal(logs[`${side}_bytes`], file.size);
      assert.ok(logs[`${side}_dropped_bytes`] >= flood - (1 << 20) - 200, `${side}: ${logs[`${side}_dropped_bytes`]} bytes counted as dropped`);
    }
    assert.ok(out.engine_stderr!.lines.length > 0, "the first lines are still shown, judged");
  });
});

test("an error that quotes a path names none of the mounted tree's components (P3-9)", async () => {
  await withCwd(async (cwd, bin) => {
    // sixteen mixed characters: the name judge reads them as a token; the text judge, which starts at twenty, does not
    const piece = pick(rng(77), "abcdefghijklmnopqrstuvwxyz", 1) + "B3dE5gH7jK9mN2p";
    assert.equal(piece.length, 16);
    const env = await fsStub(cwd, bin, { tree: { [`${piece}/`]: "", "sys/x": "" }, links: [[`${piece}/loop`, `{mount}/${piece}/loop`]] });
    await image(cwd);
    const { out, job } = await jobDir(cwd);
    const run = await runTool(FS, cwd, { path: "inputs/memory.raw", mount: join(out, "m"), mode: "export", write_values: true, paths: [`${piece}/loop`], timeout_seconds: 30 }, { ...env, ...job }, bin);
    const answer = json<Fs>(run);
    assert.ok(!run.stdout.includes(piece), "the component is in the answer");
    // Python before 3.13 raises on a link loop while resolving the path (the error text is what must name no component); from 3.13 a
    // non-strict resolve no longer raises, the loop is not a regular file, and the item says so. Either way the answer names no component.
    const status = (answer.items as Item[])[0].status;
    if (answer.counts?.failed === 1) assert.match(status, /^failed: (RuntimeError: a symbolic link loop|OSError ELOOP)/);
    else {
      assert.equal(answer.counts?.not_exported, 1, `neither a failure nor a refusal to export: ${status}`);
      assert.equal(status, "not exported: not a regular file");
    }
    // and the same on a listing
    const listed = await runTool(FS, cwd, { path: "inputs/memory.raw", mount: join(out, "m2"), mode: "list", list: `${piece}/loop`, timeout_seconds: 30 }, { ...env, ...job }, bin);
    assert.ok(!listed.stdout.includes(piece), "the component is in the answer of a listing");
  });
});
