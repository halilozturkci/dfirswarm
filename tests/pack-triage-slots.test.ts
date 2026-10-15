/**
 * triage-collection: every output slot of collection_id, driven end to end with random secret canaries (the plants, the contexts and
 * the scan are in pack-triage-slots-harness.ts; collection_index has its own file so each stays under Node 22's per-file limit).
 */
import assert from "node:assert/strict";
import { test } from "node:test";
import { ID, body, put, tool, veloLogRow, veloResultRow, veloUploadsRow, withCwd } from "./pack-triage-harness.ts";
import type { Json } from "./pack-triage-harness.ts";
import { N, drive, leaks } from "./pack-triage-slots-harness.ts";

const GHP = "ghp_Zq7SxkP2mN4vB8cR1tY6wL3hD9fJ5aG0eUiO";

test("collection_id: no output slot prints a planted secret, in a job or not, with limit 1 or the default", { timeout: 900_000 }, async () => {
  const { results, outcomes } = await drive("id", false);
  assert.ok(Object.keys(results).length >= 30, `every slot was planted (${Object.keys(results).length})`);
  for (const [slot, v] of Object.entries(results)) assert.ok(v.planted >= N, `${slot}: ${v.planted} plants`);
  assert.ok(outcomes.every((o) => o.code === 0), JSON.stringify(outcomes.filter((o) => o.code !== 0)));
  assert.deepEqual(leaks(results), []);
});

test("collection_id: with the sanitiser removed, the independent check at the boundary alone keeps every planted secret out of every channel", { timeout: 900_000 }, async () => {
  const { results } = await drive("id", true);
  assert.deepEqual(leaks(results), []);
});

test("collection_id: a log found inside collected data is named by a withheld path, and a log.json level is counted under its own word or under other", async () => {
  await withCwd(async (cwd) => {
    await put(cwd, `inputs/t/[root]/${GHP}/uac.log`, "x");
    await put(cwd, "inputs/t/v/uploads.json", veloUploadsRow("/C:/a") + "\n");
    await put(cwd, "inputs/t/v/results/Art.json", veloResultRow("/C:/a") + "\n");
    await put(cwd, "inputs/t/v/log.json", [veloLogRow("INFO", "a"), veloLogRow("info", "b"), veloLogRow(GHP, "c"), veloLogRow("ERROR", "d")].join("\n") + "\n");
    const run = await tool(ID, cwd, { root: "inputs/t" });
    const out = body(run);
    assert.doesNotMatch(run.stdout, /Zq7SxkP2mN4vB8cR1tY6wL3hD9fJ5aG0eUiO/);
    assert.equal(out.walk.logs_inside_collected_data_total, 1);
    assert.match(out.walk.logs_inside_collected_data[0], /withheld/);
    const velo = out.runs.find((r: Json) => r.collector === "Velociraptor").record;
    assert.deepEqual(velo.log_levels, { INFO: 2, other: 1, ERROR: 1 });
    assert.equal(velo.error_lines, 1);
  });
});
