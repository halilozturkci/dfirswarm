/**
 * triage-collection: the archive block (the bounded readers of a zip and of a tar, plain, gzip, bzip2 or xz, and the checks of how an archive
 * ended) is one text in the collection-intake recipe and in collection_timestamps, byte for byte, so that the fixes of the recipe's archive
 * readers (the compressed stream's CRC and length, a stream appended to the first, the 1 MiB bound on a metadata record) are the tool's too.
 */
import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import { join } from "node:path";
import { test } from "node:test";
import { TOOLS, TRIAGE } from "./pack-triage-harness.ts";

const BEGIN = "# ---- BEGIN ARCHIVE BLOCK";
const END = "# ---- END ARCHIVE BLOCK";
const RECIPE = join(TRIAGE, "recipes", "collection-intake", "run.py");
const TIMESTAMPS = join(TOOLS, "collection_timestamps", "run.py");

async function block(path: string): Promise<string> {
  const text = await readFile(path, "utf8");
  const start = text.indexOf(BEGIN);
  const end = text.indexOf(END);
  assert.ok(start >= 0 && end > start, `${path} carries the archive block`);
  assert.equal(text.indexOf(BEGIN, start + 1), -1, "once");
  return text.slice(start, text.indexOf("\n", end) + 1);
}

test("the recipe and collection_timestamps carry one archive block, byte for byte", async () => {
  const [a, b] = await Promise.all([RECIPE, TIMESTAMPS].map(block));
  assert.equal(a, b);
  assert.ok(a.length > 15000);
  for (const name of ["class TarStream", "class BoundedTarInfo", "def tar_end(", "def tar_end_problem(", "def zip_problem(", "def gz_header_length(", "def sniff(", "MAX_META = 1 << 20"]) {
    assert.ok(a.includes(name), `the block holds ${name}`);
  }
});

test("collection_timestamps opens a tar only through the block's bounded stream and header, never through bare tarfile", async () => {
  const text = await readFile(TIMESTAMPS, "utf8");
  const code = text.replace(/# ---- BEGIN ARCHIVE BLOCK[\s\S]*?# ---- END ARCHIVE BLOCK[^\n]*\n/, "");
  const opens = code.match(/tarfile\.open\([^)]*\)/g) ?? [];
  assert.equal(opens.length, 1);
  assert.match(opens[0], /fileobj=stream, mode="r\|", tarinfo=BoundedTarInfo/);
  assert.doesNotMatch(code, /extractall|\.extract\(|extractfile/);
});
