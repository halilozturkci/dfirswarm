/**
 * The skill metrics (scripts/skill-metrics.ts): loads and cards per seat, the
 * tool jobs a seat ran holding the note on that tool since its last
 * compaction, and loads again after a compaction.
 */
import assert from "node:assert/strict";
import { test } from "node:test";
import { skillMetrics, skillMetricsWords } from "../scripts/skill-metrics.ts";
import type * as P from "../extensions/protocol.ts";

const row = (agent: string, tool: string, args: Record<string, unknown>, result: Record<string, unknown> = { ok: true }) => ({ ts: "2026-11-13T00:00:00Z", agent, tool, args, result }) as unknown as P.SwarmEvent;

test("a tool job is covered when its seat loaded a note on that tool, or was shown its card, since its last compaction", () => {
  const events = [
    row("a0", "skill", { id: "INDEX" }),
    row("a0", "skill", { id: "base/evidence/ad1" }, { ok: false, error: "no such skill" }),
    row("a0", "skill", { id: "evidence/ad1" }, { ok: true, pack: "base", tools: ["ad1_extract", "catalog_search"] }),
    row("a0", "job_run", { tool: "ad1_extract" }),
    row("a0", "skill", { id: "evidence/ad1" }, { ok: true, already_loaded: true }),
    row("a0", "compact_done", { reason: "threshold" }),
    // After the compaction the body is gone: not covered, until a card or a load.
    row("a0", "job_run", { tool: "ad1_extract" }),
    row("a0", "skill_card", { tool: "ad1_extract", id: "evidence/ad1" }, { ok: true, pack: "base" }),
    row("a0", "job_run", { tool: "ad1_extract" }),
    row("a0", "skill", { id: "data/sqlite" }, { ok: true, tools: ["sqlite_query"] }),
    row("a1", "job_run", { tool: "regkv" }),
    row("a1", "skill_card", { tool: "bash", ids: ["x/y", "z/w"] }, { ok: true, listed: 2 }),
    row("a1", "job_run", { command: "ls" }),
  ];
  const m = skillMetrics(events);
  assert.equal(m.recorded, true);
  assert.deepEqual([m.loads, m.failed_loads, m.already_loaded, m.cards], [2, 1, 1, 2]);
  assert.deepEqual(m.seats.a0, { loads: 2, failed: 1, cards: 1, distinct: 2 });
  assert.deepEqual(m.seats.a1, { loads: 0, failed: 0, cards: 1, distinct: 0 });
  assert.deepEqual([m.tool_jobs, m.tool_jobs_covered, m.covered_share], [4, 2, 0.5]);
  assert.deepEqual(m.uncovered_by_tool, { ad1_extract: 1, regkv: 1 });
  assert.deepEqual([m.compactions_after_loads, m.reloaded_after_compaction], [1, 1]);
  assert.match(skillMetricsWords(m), /2 of 4 tool job\(s\) run by a seat holding a note on that tool \(50%\)/);
  assert.match(skillMetricsWords(skillMetrics([])), /^not recorded/);
});
