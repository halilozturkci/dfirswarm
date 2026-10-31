/**
 * ransomware-response: encrypted_survey's census costs bytes on disk per entry, and the manifest says how many, so that a caller can pick
 * `census: false` for a large tree. Nothing bounds the census but the clock (nothing is cut), so the figure is the only warning.
 *
 * A candidate's row is larger than an ordinary file's (it carries the entropy of three windows and the reasons), and every row grows with
 * the path, so the manifest states a range by kind of row, and a figure to plan with for a tree of candidates (the case the tool is for).
 *
 * - the manifest's `census` parameter states those figures;
 * - on trees the test builds, the census file holds no more bytes per entry than the manifest states, and not so few that a figure has
 *   gone stale: ordinary files, candidates with short paths, candidates under a long path.
 */
import assert from "node:assert/strict";
import { randomBytes } from "node:crypto";
import { mkdir, readFile, stat, writeFile } from "node:fs/promises";
import { dirname, join } from "node:path";
import { test } from "node:test";
import { withCwd } from "./tool-library-harness.ts";
import { SURVEY, body, tool } from "./ransomware-pack-harness.ts";

/** Bytes per entry, as the manifest states them: [floor, ceiling] for each kind of row. */
const ORDINARY = [250, 500] as const; // "0.3 to 0.5 KB per ordinary file"
const CANDIDATE_SHORT = [500, 800] as const; // "0.6 to 0.8 KB per candidate with short paths"
const CANDIDATE_LONG = [600, 1100] as const; // "up to about 1.1 KB per candidate under long paths"

type Kind = "ordinary" | "candidate";

/** `dirs` x 20 files of one kind; the directory and file names are `nameLength` characters plus a counter. Returns the file count. */
async function tree(cwd: string, kind: Kind, nameLength: number): Promise<number> {
  const ev = join(cwd, "work", "ev");
  let files = 0;
  for (let d = 0; d < 10; d++) {
    const dir = join(ev, `${"d".repeat(nameLength)}${String(d).padStart(3, "0")}`, "sub");
    await mkdir(dir, { recursive: true });
    for (let i = 0; i < 20; i++) {
      const name = kind === "candidate" ? `${"p".repeat(nameLength)}${i}.docx.locked` : `${"f".repeat(nameLength)}${i}.txt`;
      await writeFile(join(dir, name), kind === "candidate" ? randomBytes(5000) : Buffer.from("plain text ".repeat(500)));
      files++;
    }
  }
  return files;
}

async function bytesPerEntry(cwd: string, files: number): Promise<number> {
  const answer = body<{ census: { file: string } }>(await tool(SURVEY, cwd, { root: "work/ev", limit: 5 }));
  const size = (await stat(join(cwd, answer.census.file))).size;
  const lines = (await readFile(join(cwd, answer.census.file), "utf8")).trimEnd().split("\n");
  const entries = lines.length - 1; // the last line is the receipt
  assert.ok(entries >= files, `the census holds a row per file (${entries} of ${files})`);
  return size / entries;
}

test("the manifest states the census's bytes per entry by kind of row, and a figure to plan with, in the census parameter", async () => {
  const manifest = JSON.parse(await readFile(join(dirname(SURVEY), "manifest.json"), "utf8")) as { params: { census: { description: string } } };
  const text = manifest.params.census.description;
  assert.match(text, /about 0\.3 to 0\.5 KB on disk per ordinary file/);
  assert.match(text, /0\.6 to 0\.8 KB per candidate with short paths/);
  assert.match(text, /up to about 1\.1 KB per candidate under long paths/);
  assert.match(text, /plan for about 1 KB per entry on a tree of candidates \(about 100 MB per 100,000 files/);
  assert.match(text, /choose false for a large tree/);
  assert.doesNotMatch(text, /0\.75 KB/);
});

for (const [name, kind, length, [floor, ceiling]] of [
  ["ordinary files with short names", "ordinary", 5, ORDINARY],
  ["ordinary files with names of 80 characters", "ordinary", 80, ORDINARY],
  ["candidates with short names", "candidate", 5, CANDIDATE_SHORT],
  ["candidates under a path of about 150 characters", "candidate", 60, CANDIDATE_LONG],
] as const) {
  test(`the census of a tree of ${name} holds between ${floor} and ${ceiling} bytes per entry`, async () => {
    await withCwd(async (cwd) => {
      const files = await tree(cwd, kind, length);
      const perEntry = await bytesPerEntry(cwd, files);
      assert.ok(perEntry <= ceiling, `${perEntry.toFixed(0)} bytes per entry, over the ${ceiling} the manifest states`);
      assert.ok(perEntry >= floor, `${perEntry.toFixed(0)} bytes per entry, under ${floor}: the stated figure is no longer a fair warning`);
    });
  });
}
