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

test("a supervised hub past its heap line ends for a restart only at a quiet moment", async () => {
  const { recycleAt, recycleDue } = await import("../scripts/hub-health.ts");
  assert.equal(recycleAt({}), 0.85);
  assert.equal(recycleAt({ SWARM_HUB_RECYCLE_AT: "0" }), 0);
  assert.equal(recycleAt({ SWARM_HUB_RECYCLE_AT: "2" }), 0.85);
  const high = { heap_used_mb: 7100, heap_limit_mb: 8192 };
  const quiet = { supervised: true, callsInFlight: 0, jobsBusy: 0 };
  assert.equal(recycleDue({ heap_used_mb: 6000, heap_limit_mb: 8192 }, quiet, 0.85).due, false);
  const due = recycleDue(high, quiet, 0.85);
  assert.equal(due.due, true);
  assert.match(due.why, /heap 7100 of 8192 MB, past 85%, with no call in flight and no job running/);
  assert.match(recycleDue(high, { ...quiet, supervised: false }, 0.85).why, /no keeper would start it again/);
  assert.match(recycleDue(high, { ...quiet, callsInFlight: 2 }, 0.85).why, /2 call\(s\) in flight/);
  assert.match(recycleDue(high, { ...quiet, jobsBusy: 1 }, 0.85).why, /1 job\(s\) running or waiting to be sealed/);
  assert.equal(recycleDue(high, quiet, 0).due, false, "0 turns it off");
});
