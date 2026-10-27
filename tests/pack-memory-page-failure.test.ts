/**
 * The memory tools when the disk fills while a result is being spilled to its file (a file-size limit makes the write short and then
 * EFBIG, the error a full disk gives as ENOSPC). Each tool is run end to end: whatever ends the call, the hidden temporary file of the
 * page (.<tool>-<hash>.jsonl-<hex>) must not be left behind. abort() had been repaired but only mem_carve called it on this path.
 */
import assert from "node:assert/strict";
import { mkdir, readdir, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { test } from "node:test";
import { withCwd } from "./tool-library-harness.ts";
import { FS, PROFILE, fsStub, json, runTool, shimDir } from "./memory-f1-support.ts";

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
