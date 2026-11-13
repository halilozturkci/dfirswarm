/**
 * The harness row of swarm.sh metrics: what the harness cost the seats.
 */
import assert from "node:assert/strict";
import test from "node:test";
import { frictionMetrics, frictionWords } from "../scripts/friction-metrics.ts";

const ev = (ts: string, agent: string, tool: string, args: Record<string, unknown> = {}, result: Record<string, unknown> = { ok: true }) => ({ ts, agent, tool, args, result }) as never;

test("refusals per accepted record, the waits of small jobs behind a seal, compactions per seat-hour and the hub's health", () => {
  const events = [
    ev("2026-01-01T00:00:00Z", "a0", "record"),
    ev("2026-01-01T00:01:00Z", "a0", "record", {}, { ok: false, reason: "evidence is required" }),
    ev("2026-01-01T00:02:00Z", "a0", "record", {}, { ok: false, reason: "Timed out waiting for locks/.table.lock" }),
    ev("2026-01-01T00:03:00Z", "a0", "record"),
    ev("2026-01-01T00:04:00Z", "a1", "attest", {}, { ok: false, reason: "x" }),
    ev("2026-01-01T00:05:00Z", "a1", "job_run", {}, { ok: false, reason: "give one" }),
    ev("2026-01-01T00:10:00Z", "a0", "compact_done"),
    ev("2026-01-01T00:20:00Z", "a0", "shell_timeout", { kind: "sleep_loop" }, { ok: false }),
    ev("2026-01-01T00:21:00Z", "a0", "shell_timeout", { tool: "bash" }),
    ev("2026-01-01T00:30:00Z", "system", "hub_health", {}, { ok: true, loop_p99_ms: 840, heap_used_mb: 3000, heap_limit_mb: 4000 }),
    ev("2026-01-01T00:31:00Z", "system", "hub_health", {}, { ok: true, loop_p99_ms: 12, heap_used_mb: 1000, heap_limit_mb: 4000 }),
    ev("2026-01-01T00:32:00Z", "system", "hub_call", { agent: "a0", fn: "answer_too_large" }, { ok: false }),
    ev("2026-01-01T00:40:00Z", "system", "seat_down", { agent: "a1" }),
    ev("2026-01-01T00:41:00Z", "system", "seat_relaunched", { agent: "a1" }),
    ev("2026-01-01T00:42:00Z", "system", "regroup", {}, { ok: true, kind: "platform" }),
    ev("2026-01-01T01:00:00Z", "a0", "bash"),
  ];
  const journal = [
    { type: "job_accepted", job: "j1", at: "2026-01-01T00:00:00Z" }, { type: "job_started", job: "j1", at: "2026-01-01T00:00:10Z" }, { type: "job_finished", job: "j1", at: "2026-01-01T00:10:00Z" }, { type: "job_committed", job: "j1", at: "2026-01-01T00:28:00Z", outputs: { files: 200000 } },
    { type: "job_accepted", job: "j2", at: "2026-01-01T00:11:00Z" }, { type: "job_started", job: "j2", at: "2026-01-01T00:11:01Z" }, { type: "job_finished", job: "j2", at: "2026-01-01T00:12:00Z" }, { type: "job_committed", job: "j2", at: "2026-01-01T00:28:02Z", outputs: { files: 0 } },
    { type: "job_accepted", job: "j3", at: "2026-01-01T00:29:00Z" }, { type: "job_started", job: "j3", at: "2026-01-01T00:29:00Z" }, { type: "job_finished", job: "j3", at: "2026-01-01T00:29:05Z" }, { type: "job_committed", job: "j3", at: "2026-01-01T00:29:06Z", outputs: { files: 3 } },
  ];
  const m = frictionMetrics(events, journal);
  assert.deepEqual(m.record, { accepted: 2, refused: 2, per_accepted: 1 });
  assert.deepEqual(m.attest, { accepted: 0, refused: 1 });
  assert.equal(m.job_run_refused, 1);
  assert.deepEqual(m.shell, { timeouts: 1, sleep_loops_refused: 1 });
  assert.equal(m.compactions.done, 1);
  assert.equal(m.compactions.per_seat_hour, 1, "one compaction over a0's hour (a1's minute adds little)");
  assert.equal(m.commit_wait.jobs, 3);
  assert.equal(m.commit_wait.max_s, 1080);
  assert.deepEqual([m.commit_wait.small_over_30s, m.commit_wait.small_job_seconds], [1, 962], "the empty job that waited 16 minutes behind the large one's seal");
  assert.deepEqual(m.hub, { samples: 2, loop_p99_max_ms: 840, heap_share_max: 0.75, memory_high: 0, restarts: 0, answers_too_large: 1, lock_timeouts: 1 });
  assert.deepEqual(m.seats, { down: 1, relaunched: 1, dead: 0, images_scaled: 0 });
  assert.equal(m.platform_stalls, 1);
  const words = frictionWords(m);
  assert.match(words, /record: 2 refused for 2 accepted \(1 per accepted\)/);
  assert.match(words, /1 small job\(s\) waited over 30 s \(962 job-seconds\)/);
  assert.match(words, /hub: loop p99 at most 840 ms, heap at most 75% of its limit/);
  assert.doesNotThrow(() => frictionWords(frictionMetrics([], [])));
});
