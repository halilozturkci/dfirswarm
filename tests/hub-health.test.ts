/**
 * The hub's own health row and its early heap snapshot.
 */
import assert from "node:assert/strict";
import test from "node:test";
import { loopMonitor, sampleHealth, snapshotAt, snapshotDue } from "../scripts/hub-health.ts";

test("a health sample names the heap, the loop's delay, the host and what the hub holds", async () => {
  const loop = loopMonitor();
  await new Promise((r) => setTimeout(r, 60));
  const until = Date.now() + 120;
  while (Date.now() < until) { /* hold the loop: a timer due now fires late */ }
  await new Promise((r) => setTimeout(r, 60));
  const h = sampleHealth(loop.read(), { transfers: 3 });
  loop.stop();
  assert.ok(h.heap_used_mb > 0 && h.heap_limit_mb >= h.heap_used_mb);
  assert.ok(h.loop_max_ms >= 50, `the held loop shows in the sample (max ${h.loop_max_ms} ms)`);
  assert.ok(h.host_cpus >= 1 && h.host_total_mb > h.host_free_mb);
  assert.deepEqual(h.holds, { transfers: 3 });
  assert.ok(JSON.stringify(h).length < 600);
});

test("the snapshot is taken once, at 60% of the heap limit by default, while it can still be written", () => {
  assert.equal(snapshotAt({}), 0.6);
  assert.equal(snapshotAt({ SWARM_HUB_SNAPSHOT_AT: "0.4" }), 0.4);
  assert.equal(snapshotAt({ SWARM_HUB_SNAPSHOT_AT: "0" }), 0, "0 turns it off");
  assert.equal(snapshotAt({ SWARM_HUB_SNAPSHOT_AT: "7" }), 0.6);
  assert.equal(snapshotDue({ heap_used_mb: 2400, heap_limit_mb: 4288 }, false), false);
  assert.equal(snapshotDue({ heap_used_mb: 2600, heap_limit_mb: 4288 }, false), true);
  assert.equal(snapshotDue({ heap_used_mb: 4000, heap_limit_mb: 4288 }, true), false, "once");
  assert.equal(snapshotDue({ heap_used_mb: 4000, heap_limit_mb: 4288 }, false, 0), false);
});
