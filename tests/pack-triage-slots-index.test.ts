/**
 * triage-collection: every output slot of collection_index, driven end to end with random secret canaries (the plants, the contexts
 * and the scan are in pack-triage-slots-harness.ts; collection_id has its own file so each stays under Node 22's per-file limit).
 */
import assert from "node:assert/strict";
import { test } from "node:test";
import { INDEX, KAPE_COPY_HEADER, body, kapeCopyRow, put, tool, withCwd } from "./pack-triage-harness.ts";
import type { Json } from "./pack-triage-harness.ts";
import { N, drive, leaks } from "./pack-triage-slots-harness.ts";

const GHP = "ghp_Zq7SxkP2mN4vB8cR1tY6wL3hD9fJ5aG0eUiO";

test("collection_index: no output slot prints a planted secret, in a job or not, with limit 1 or the default", { timeout: 900_000 }, async () => {
  const { results, outcomes } = await drive("index", false);
  assert.ok(Object.keys(results).length >= 13, `every slot was planted (${Object.keys(results).length})`);
  for (const [slot, v] of Object.entries(results)) assert.ok(v.planted >= N, `${slot}: ${v.planted} plants`);
  assert.ok(outcomes.every((o) => o.code === 0), JSON.stringify(outcomes.filter((o) => o.code !== 0)));
  assert.deepEqual(leaks(results), []);
});

test("collection_index: with the sanitiser removed, the independent check at the boundary alone keeps every planted secret out of every channel", { timeout: 900_000 }, async () => {
  const { results } = await drive("index", true);
  assert.deepEqual(leaks(results), []);
});

test("collection_index: a copy log in a directory with a secret-shaped name is shown with a withheld directory and still maps its files", async () => {
  await withCwd(async (cwd) => {
    await put(cwd, `inputs/t/${GHP}/20260101_CopyLog.csv`, `${KAPE_COPY_HEADER}\n${kapeCopyRow("C:\\Users\\a\\x.txt", "D:\\kape\\C\\Users\\a\\x.txt")}\n`);
    await put(cwd, `inputs/t/${GHP}/C/Users/a/x.txt`, "x");
    const run = await tool(INDEX, cwd, { root: "inputs/t" });
    const out = body(run);
    assert.doesNotMatch(run.stdout, /Zq7SxkP2mN4vB8cR1tY6wL3hD9fJ5aG0eUiO/);
    const logs = out.source_paths.observed.logs;
    assert.equal(logs.length, 1);
    assert.match(logs[0].directory, /withheld/);
    assert.equal(logs[0]._dir, undefined, "the raw directory is private to the lookup");
    const mapped = out.entries.find((e: Json) => e.kind === "file" && /x\.txt/.test(e.in_collection));
    assert.equal(mapped.source_path_mapping, "observed");
    assert.equal(mapped.source_path_observed.path, "C:\\Users\\a\\x.txt");
  });
});
