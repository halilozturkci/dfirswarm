/**
 * The memory tools when the disk fills while a result is being spilled to its file (a file-size limit makes the write short and then
 * EFBIG, the error a full disk gives as ENOSPC). Each tool is run end to end: whatever ends the call, the hidden temporary file of the
 * page (.<tool>-<hash>.jsonl-<hex>) must not be left behind. abort() had been repaired but only mem_carve called it on this path.
 */
import assert from "node:assert/strict";
import { mkdir, readdir, stat, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { test } from "node:test";
import { withCwd } from "./tool-library-harness.ts";
import { CARVE, FS, PROFILE, fsStub, json, runTool, shimDir } from "./memory-f1-support.ts";

type Answer = { status: string; error?: string };

const hidden = async (dir: string): Promise<string[]> => (await readdir(dir).catch(() => [] as string[])).filter((name) => name.startsWith(".mem_"));

const lime = (ranges: number): Buffer => {
  const parts: Buffer[] = [];
  for (let i = 0; i < ranges; i++) {
    const h = Buffer.alloc(32);
    h.write("EMiL", 0, "latin1");
    h.writeUInt32LE(1, 4);
    h.writeBigUInt64LE(BigInt(i), 8);
    h.writeBigUInt64LE(BigInt(i), 16);
    parts.push(h, Buffer.from([i & 0xff]));
  }
  return Buffer.concat(parts);
};

test("mem_profile: a disk that fills while the range list is spilled ends in a failed answer and leaves no hidden temporary file", async () => {
  await withCwd(async (cwd) => {
    await writeFile(join(cwd, "work", "l.lime"), lime(3000));
    const shim = await shimDir(cwd);
    const out = json<Answer>(await runTool(PROFILE, cwd, { path: "work/l.lime" }, { PYTHONPATH: shim, FAKE_FSIZE: "5000" }));
    assert.equal(out.status, "failed", JSON.stringify(out));
    assert.match(out.error ?? "", /unexpected failure|cannot be written|File too large|No space/);
    assert.deepEqual(await hidden(join(cwd, "work", "s1", "tool-output")), [], "a hidden temporary file was left");
  });
});

test("mem_carve: a disk that fills at the last flush of the spill ends in a failed answer and leaves no hidden temporary file", async () => {
  // The limit sits between what the sweep wrote while it ran and the end of the file, so the failure is in page.finish() (flush, fsync,
  // placing), which runs after the sweep's own clean-up has stopped looking at the page.
  const image = Buffer.alloc(300 * 8192, 0x41);
  for (let i = 0; i < 300; i++) {
    const head = Buffer.alloc(100);
    head.write("SQLite format 3\u0000", 0, "latin1");
    head.writeUInt16BE(4096, 16);
    head[18] = 1;
    head[19] = 1;
    head.writeUInt32BE(7, 24);
    head.writeUInt32BE(1, 28);
    head.writeUInt32BE(7, 92);
    head.copy(image, i * 8192);
  }
  const args = { path: "work/db.raw", limit: 1 };
  let whole = 0;
  await withCwd(async (cwd) => {
    await writeFile(join(cwd, "work", "db.raw"), image);
    const out = json<{ status: string; complete_results?: string }>(await runTool(CARVE, cwd, args));
    assert.equal(out.status, "complete", JSON.stringify(out));
    whole = (await stat(join(cwd, out.complete_results ?? "none"))).size;
  });
  assert.ok(whole > 8192 && whole % 8192 !== 0, `the spill is ${whole} bytes: it needs a last, partial buffer for this case`);
  await withCwd(async (cwd) => {
    await writeFile(join(cwd, "work", "db.raw"), image);
    const shim = await shimDir(cwd);
    const run = await runTool(CARVE, cwd, args, { PYTHONPATH: shim, FAKE_FSIZE: String(whole - 1) });
    const out = json<Answer & { status_basis?: string }>(run);
    assert.equal(out.status, "failed", JSON.stringify(out));
    assert.ok(out.status_basis, "no status_basis");
    assert.notEqual(run.code, 0);
    assert.deepEqual(await hidden(join(cwd, "work", "s1", "tool-output")), [], "a hidden temporary file was left");
  });
});

test("mem_fs: a disk that fills while a listing is spilled ends in a failed answer and leaves no hidden temporary file", async () => {
  await withCwd(async (cwd, bin) => {
    const tree: Record<string, string> = { "sys/x": "" };
    for (let i = 0; i < 600; i++) tree[`proc/file-with-a-long-enough-name-${String(i).padStart(4, "0")}.txt`] = "x";
    const env = await fsStub(cwd, bin, { tree });
    await writeFile(join(cwd, "inputs", "memory.raw"), Buffer.alloc(4096));
    await mkdir(join(cwd, "work", "s1"), { recursive: true });
    const shim = await shimDir(cwd);
    const out = json<Answer>(await runTool(FS, cwd, { path: "inputs/memory.raw", mount: "work/s1/m", mode: "list", list: "proc", timeout_seconds: 30 },
      { ...env, PYTHONPATH: shim, FAKE_ISMOUNT: "1", FAKE_FSIZE: "5000" }, bin));
    assert.equal(out.status, "failed", JSON.stringify(out));
    assert.deepEqual(await hidden(join(cwd, "work", "s1", "tool-output")), [], "a hidden temporary file was left");
  });
});
