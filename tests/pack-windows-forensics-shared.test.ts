/**
 * What the windows-forensics tools share: the paging block (`LosslessPage`) that keeps the whole of a result in a file when
 * the inline page is shorter. Its fixtures are $I records laid out as the format documents them (header, size, FILETIME,
 * character count, UTF-16LE path), small enough to need no builder from the main suite.
 */
import assert from "node:assert/strict";
import { chmod, mkdir, readFile, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { test } from "node:test";
import { withCwd } from "./tool-library-harness.ts";
import { body, failed, tool, u16z } from "./windows-pack-harness.ts";

function iRecord(path: string): Buffer {
  const text = u16z(path);
  const b = Buffer.alloc(0x1c + text.length);
  b.writeBigUInt64LE(2n, 0);
  b.writeBigUInt64LE(10n, 8);
  b.writeBigUInt64LE(133_500_000_000_000_001n, 0x10);
  b.writeUInt32LE(path.length + 1, 0x18);
  text.copy(b, 0x1c);
  return b;
}

async function bin(cwd: string, names: string[]): Promise<void> {
  const dir = join(cwd, "work", "recycle");
  await mkdir(dir, { recursive: true });
  for (const [i, name] of names.entries()) await writeFile(join(dir, name), iRecord(`C:\\Users\\x\\file${i}.txt`));
}

type Page = { entry_count: number; entries: unknown[]; truncated: boolean; all_results?: string };

test("a result longer than the inline page is kept whole in a file the answer names", async () => {
  await withCwd(async (cwd) => {
    await bin(cwd, ["$IAAAAAA.txt", "$IBBBBBB.txt", "$ICCCCCC.txt"]);
    const out = body<Page>(await tool("recyclebin_i", cwd, { path: "work/recycle", limit: 1 }));
    assert.equal(out.entries.length, 1);
    assert.equal(out.entry_count, 3);
    assert.equal(out.truncated, true);
    const lines = (await readFile(join(cwd, out.all_results!), "utf8")).trim().split("\n");
    assert.equal(lines.length, 3);
  });
});

test("a result that cannot be written is a JSON failure with a reason, not a traceback (a read-only work directory outside a job)", async (t) => {
  if (process.getuid && process.getuid() === 0) return t.skip("root writes a read-only directory");
  await withCwd(async (cwd) => {
    await bin(cwd, ["$IAAAAAA.txt", "$IBBBBBB.txt", "$ICCCCCC.txt"]);
    await chmod(join(cwd, "work"), 0o555);
    try {
      const out = failed(await tool("recyclebin_i", cwd, { path: "work/recycle", limit: 1 }));
      assert.match(out.error, /cannot be written to work\/s1\/tool-output\//);
      assert.match(out.error, /Permission denied|Read-only/i);
    } finally {
      await chmod(join(cwd, "work"), 0o755);
    }
  });
});

test("a file name that is not UTF-8 is kept in the whole result, escaped, and does not stop the writer", async (t) => {
  await withCwd(async (cwd) => {
    const dir = join(cwd, "work", "recycle");
    await mkdir(dir, { recursive: true });
    try {
      // A name with a byte that is not UTF-8: the host's file system may refuse it (macOS does).
      await writeFile(Buffer.concat([Buffer.from(dir + "/$I"), Buffer.from([0xff, 0xfe]), Buffer.from("zz.txt")]), iRecord("C:\\a.txt"));
    } catch {
      return t.skip("this file system refuses a name that is not UTF-8");
    }
    await writeFile(join(dir, "$IAAAAAA.txt"), iRecord("C:\\b.txt"));
    const out = body<Page>(await tool("recyclebin_i", cwd, { path: "work/recycle", limit: 1 }));
    assert.equal(out.entry_count, 2);
    const whole = await readFile(join(cwd, out.all_results!), "utf8");
    assert.equal(whole.trim().split("\n").length, 2);
    for (const line of whole.trim().split("\n")) JSON.parse(line);
  });
});
