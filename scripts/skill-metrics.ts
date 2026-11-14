/**
 * What a run made of its packs' skills, from the trace (swarm.sh metrics):
 * the loads per seat, the cards shown with a tool's result, the share of
 * tool jobs a seat ran while holding a note on that tool, and how often a
 * seat loaded a note again after its context was compacted.
 *
 * The share is the measure of the skills experiment (one case: a seat
 * held the note on the tool it ran for 5 of 55 tool jobs on one run): a tool
 * job is a `job_run` that names a tool; it counts as covered when, before it,
 * the seat loaded a skill whose front matter lists that tool, or was shown
 * that skill's card, since its last compaction (a compaction drops a body
 * from the context; the card re-arms after one).
 */
import type * as P from "../extensions/protocol.ts";

export type SkillMetrics = {
  recorded: boolean;
  loads: number;
  failed_loads: number;
  already_loaded: number;
  cards: number;
  seats: Record<string, { loads: number; failed: number; cards: number; distinct: number }>;
  tool_jobs: number;
  tool_jobs_covered: number;
  /** tool_jobs_covered over tool_jobs, two decimals; null with no tool job. */
  covered_share: number | null;
  /** The tools whose jobs ran uncovered most, with how many. */
  uncovered_by_tool: Record<string, number>;
  /** Compactions of a seat that held a loaded note before it, and how many of those it loaded a note again after, before its next. */
  compactions_after_loads: number;
  reloaded_after_compaction: number;
};

type Row = { agent?: string; tool?: string; args?: Record<string, unknown>; result?: Record<string, unknown> };

const strings = (x: unknown): string[] => (Array.isArray(x) ? x.filter((y): y is string => typeof y === "string") : []);

export function skillMetrics(events: readonly P.SwarmEvent[]): SkillMetrics {
  const out: SkillMetrics = { recorded: false, loads: 0, failed_loads: 0, already_loaded: 0, cards: 0, seats: {}, tool_jobs: 0, tool_jobs_covered: 0, covered_share: null, uncovered_by_tool: {}, compactions_after_loads: 0, reloaded_after_compaction: 0 };
  // Per seat: the tools its loaded notes or cards name since its last compaction, the ids it loaded, and whether a compaction waits for a reload.
  const held = new Map<string, Set<string>>();
  const carded = new Map<string, Set<string>>();
  const ids = new Map<string, Set<string>>();
  const loadedSinceCompact = new Map<string, boolean>();
  const waiting = new Map<string, boolean>();
  const seat = (a: string) => (out.seats[a] ??= { loads: 0, failed: 0, cards: 0, distinct: 0 });
  for (const raw of events) {
    const r = raw as unknown as Row;
    const agent = typeof r.agent === "string" ? r.agent : "";
    if (!agent) continue;
    const res = r.result ?? {};
    if (r.tool === "skill") {
      out.recorded = true;
      const id = String(r.args?.id ?? "");
      if (id === "INDEX") continue;
      if (res.ok !== true) {
        out.failed_loads += 1;
        seat(agent).failed += 1;
        continue;
      }
      if (res.already_loaded) {
        out.already_loaded += 1;
        continue;
      }
      out.loads += 1;
      seat(agent).loads += 1;
      const mine = ids.get(agent) ?? new Set<string>();
      mine.add(id);
      ids.set(agent, mine);
      seat(agent).distinct = mine.size;
      const tools = held.get(agent) ?? new Set<string>();
      for (const t of strings(res.tools)) tools.add(t);
      held.set(agent, tools);
      loadedSinceCompact.set(agent, true);
      if (waiting.get(agent)) {
        out.reloaded_after_compaction += 1;
        waiting.set(agent, false);
      }
      continue;
    }
    if (r.tool === "skill_card") {
      out.recorded = true;
      out.cards += 1;
      seat(agent).cards += 1;
      const tool = String(r.args?.tool ?? "");
      // A card of one note (id) puts its rules beside the call; a list of notes names them only.
      if (tool && r.args?.id) {
        // A card is shown once in the run and its rules ride on every hand-off after: it covers the tool from then on.
        const tools = carded.get(agent) ?? new Set<string>();
        tools.add(tool);
        carded.set(agent, tools);
      }
      continue;
    }
    if (r.tool === "compact_done") {
      if (loadedSinceCompact.get(agent) || (ids.get(agent)?.size ?? 0) > 0) {
        out.compactions_after_loads += 1;
        waiting.set(agent, true);
      }
      held.set(agent, new Set());
      loadedSinceCompact.set(agent, false);
      continue;
    }
    if (r.tool === "job_run") {
      const tool = typeof r.args?.tool === "string" ? r.args.tool : "";
      if (!tool) continue;
      out.tool_jobs += 1;
      if (held.get(agent)?.has(tool) || carded.get(agent)?.has(tool)) out.tool_jobs_covered += 1;
      else out.uncovered_by_tool[tool] = (out.uncovered_by_tool[tool] ?? 0) + 1;
    }
  }
  if (out.tool_jobs) out.covered_share = Math.round((out.tool_jobs_covered / out.tool_jobs) * 100) / 100;
  out.uncovered_by_tool = Object.fromEntries(Object.entries(out.uncovered_by_tool).sort((a, b) => b[1] - a[1]));
  return out;
}

/** The metrics table's row. */
export function skillMetricsWords(s: SkillMetrics): string {
  if (!s.recorded && !s.tool_jobs) return "not recorded (no skill loads or cards on the trace)";
  const seats = Object.entries(s.seats).sort((a, b) => a[0].localeCompare(b[0]));
  const top = Object.entries(s.uncovered_by_tool).slice(0, 4).map(([t, n]) => `${t} ${n}`).join(", ");
  return (
    `${s.loads} load(s) (${s.failed_loads} failed, ${s.already_loaded} already held), ${s.cards} card(s); ` +
    `per seat: ${seats.map(([a, x]) => `${a} ${x.loads}/${x.distinct} distinct${x.cards ? `, ${x.cards} card(s)` : ""}`).join("; ") || "none"}; ` +
    `${s.tool_jobs_covered} of ${s.tool_jobs} tool job(s) run by a seat holding a note on that tool${s.covered_share === null ? "" : ` (${Math.round(s.covered_share * 100)}%)`}${top ? `; uncovered most: ${top}` : ""}; ` +
    `${s.reloaded_after_compaction} of ${s.compactions_after_loads} compaction(s) after a load followed by a load again`
  );
}
