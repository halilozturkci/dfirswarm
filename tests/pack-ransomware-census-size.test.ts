/**
 * ransomware-response: encrypted_survey's census costs bytes on disk per entry, and the manifest says how many, so that a caller can pick
 * `census: false` for a large tree. Nothing bounds the census but the clock (nothing is cut), so the figure is the only warning.
 *
 * - the manifest's `census` parameter states the figure (up to about 0.75 KB per entry, 73 MB per 100,000 files);
 * - on trees the test builds, the census file holds at most that many bytes per entry, and not so few that the figure has gone stale.
 */
import assert from "node:assert/strict";
import { randomBytes } from "node:crypto";
import { mkdir, readFile, stat, writeFile } from "node:fs/promises";
import { dirname, join } from "node:path";
import { test } from "node:test";
import { withCwd } from "./tool-library-harness.ts";
import { SURVEY, body, tool } from "./ransomware-pack-harness.ts";

/** The figure the manifest states, in bytes per entry. */
const STATED = 750;
/** Below this the figure would no longer be a fair warning (the measured rows are 0.4 to 0.5 KB with short names). */
const FLOOR = 300;

async function tree(cwd: string, nameLength: number): Promise<number> {
  const ev = join(cwd, "work", "ev");
  let files = 0;
  for (let d = 0; d < 10; d++) {
    const dir = join(ev, `${"d".repeat(nameLength)}${String(d).padStart(3, "0")}`, "sub");
    await mkdir(dir, { recursive: true });
    for (let i = 0; i < 20; i++) {
      // half of the files are candidates by name and by entropy, half ordinary text of low entropy
      const name = i % 2 ? `${"p".repeat(nameLength)}${i}.docx.locked` : `${"f".repeat(nameLength)}${i}.txt`;
      await writeFile(join(dir, name), i % 2 ? randomBytes(70000) : Buffer.from("plain text ".repeat(500)));
      files++;
    }
  }
  return files;
}

test("the manifest states the census's bytes per entry in the census parameter", async () => {
  const manifest = JSON.parse(await readFile(join(dirname(SURVEY), "manifest.json"), "utf8")) as { params: { census: { description: string } } };
  const text = manifest.params.census.description;
  assert.match(text, /up to about 0\.75 KB on disk per entry \(73 MB per 100,000 files/);
  assert.match(text, /choose false for a large tree/);
  assert.equal(STATED, 750, "the test and the manifest state one figure");
});

for (const length of [5, 40, 80]) {
  test(`the census of a tree with names of ${length} characters holds at most the stated bytes per entry`, async () => {
    await withCwd(async (cwd) => {
      const files = await tree(cwd, length);
      const answer = body<{ census: { file: string; rows: number } }>(await tool(SURVEY, cwd, { root: "work/ev", limit: 5 }));
      const size = (await stat(join(cwd, answer.census.file))).size;
      const lines = (await readFile(join(cwd, answer.census.file), "utf8")).trimEnd().split("\n");
      const entries = lines.length - 1; // the last line is the receipt
      assert.ok(entries >= files, `the census holds a row per file (${entries} of ${files})`);
      const perEntry = size / entries;
      assert.ok(perEntry <= STATED, `${perEntry.toFixed(0)} bytes per entry, over the ${STATED} the manifest states`);
      assert.ok(perEntry >= FLOOR, `${perEntry.toFixed(0)} bytes per entry: the stated figure is no longer a fair warning`);
    });
  });
}
