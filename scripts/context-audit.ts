/**
 * The context history of a run, from its trace.
 *
 *   node --experimental-strip-types scripts/context-audit.ts <sandbox|events.jsonl> [--json]
 *   scripts/swarm.sh context <id> [--json]
 *
 * Every agent's context over time comes from the `context` rows the
 * self-compaction module writes at each turn end; the lines it crossed, the
 * holds, the notes, the compactions and their cost come from the
 * `compact_*` events. What this prints is what an operator needs to decide
 * whether the three lines suit the model: the peak, where the hand-offs
 * happened, what each summary cost and what it left behind, whether Pi's own
 * recovery ever had to step in, the largest single jump between two turns,
 * and how much of what the tools produced had to live in tool-output/
 * rather than in the model's view. The numbers are the record's, not an
 * estimate: a run without `context` rows (self-compaction off, or older than
 * the feature) says so instead of guessing.
 *
 * The skills a seat loaded are measured too (ui/src/lib/skill-metrics.ts, the
 * same code the console's Packs tab runs): whether its prompt carried the
 * index, how many bodies it loaded and what they cost in tokens, which of them
 * a later row names or uses (a proxy, labelled as one), which a compaction
 * took out of its context and whether it loaded them again.
 *
 * Pure on purpose: reads one file, prints Markdown (or JSON with --json).
 */
import { readFileSync, statSync } from "node:fs";
import { join } from "node:path";
import { skillUse, type RunSkills, type SeatSkills } from "../ui/src/lib/skill-metrics.ts";

type Row = { ts: string; agent: string; tool: string; args: Record<string, unknown>; result: Record<string, unknown> };

export type Crossing = { level: "notice" | "warning" | "forced"; ts: string; tokens: number | null; threshold: number | null; cycle: number };

export type Compaction = {
  ts: string;
  cycle: number;
  via: string;
  reason: string;
  tokens_before: number | null;
  /** From the row when Pi measured it, else the first `context` row after the compaction. */
  tokens_after: number | null;
  summary_tokens: number | null;
  summary_usd: number | null;
  summary_chars: number;
  summary_model: string | null;
  note_chars: number;
};

export type AgentAudit = {
  agent: string;
  model: string | null;
  window: number | null;
  ceiling: number | null;
  ceiling_reason: string | null;
  lines: { notice: number; warning: number; compact: number } | null;
  defaults: boolean | null;
  matched: Record<string, string>;
  summary_model: string | null;
  config_error: string | null;
  turns: number;
  peak: { tokens: number; ts: string; percent: number | null } | null;
  last: { tokens: number; ts: string } | null;
  /** The largest climb between two consecutive turns: the biggest single result. */
  largest_jump: { tokens: number; ts: string } | null;
  crossings: Crossing[];
  holds: number;
  notes_saved: number;
  notes_refused: Array<{ ts: string; reason: string }>;
  compactions: Compaction[];
  failures: Array<{ ts: string; stage: string; reason: string }>;
  /** Tool calls whose whole output lives under tool-output/, and the bytes there. */
  spilled: { calls: number; bytes: number };
  /** inbox/wait deliveries that held posts back for the next call. */
  pages_held: number;
  /** What the seat did with the run's skills; all zeros on a run with no pack. */
  skills: SeatSkills;
};

export type RunAudit = {
  source: string;
  rows: number;
  bad_lines: number;
  agents: AgentAudit[];
  totals: { compactions: number; hand_offs: number; pi_fallbacks: number; summary_usd: number; summary_tokens: number; holds: number; spilled_calls: number; spilled_bytes: number; pages_held: number };
  /** Skill use over the whole trace: per seat, per skill and in total. */
  skills: RunSkills;
  findings: string[];
};

function num(v: unknown): number | null {
  return typeof v === "number" && Number.isFinite(v) ? v : null;
}

function str(v: unknown): string | null {
  return typeof v === "string" && v ? v : null;
}

export function readRows(source: string): { rows: Row[]; bad: number; file: string } {
  let file = source;
  try {
    if (statSync(source).isDirectory()) {
      const candidates = [join(source, "traces", "events.jsonl"), join(source, "trace", "events.jsonl")];
      file = candidates.find((c) => {
        try {
          return statSync(c).isFile();
        } catch {
          return false;
        }
      }) ?? candidates[0]!;
    }
  } catch {
    // a missing path fails below with the read
  }
  const text = readFileSync(file, "utf8");
  const rows: Row[] = [];
  let bad = 0;
  for (const line of text.split("\n")) {
    if (!line.trim()) continue;
    try {
      const parsed = JSON.parse(line) as Partial<Row>;
      if (!parsed || typeof parsed.tool !== "string" || typeof parsed.agent !== "string") {
        bad += 1;
        continue;
      }
      // The host's clock where the collector stamped one (recv_ts): a guest's
      // own `ts` is its word, and a VM's clock can run apart from the host's.
      const when = typeof (parsed as { recv_ts?: unknown }).recv_ts === "string" && (parsed as { recv_ts: string }).recv_ts ? (parsed as { recv_ts: string }).recv_ts : String(parsed.ts ?? "");
      rows.push({ ts: when, agent: parsed.agent, tool: parsed.tool, args: (parsed.args ?? {}) as Record<string, unknown>, result: (parsed.result ?? {}) as Record<string, unknown> });
    } catch {
      bad += 1;
    }
  }
  return { rows, bad, file };
}

function emptyAgent(agent: string): AgentAudit {
  return {
    agent,
    model: null,
    window: null,
    ceiling: null,
    ceiling_reason: null,
    lines: null,
    defaults: null,
    matched: {},
    summary_model: null,
    config_error: null,
    turns: 0,
    peak: null,
    last: null,
    largest_jump: null,
    crossings: [],
    holds: 0,
    notes_saved: 0,
    notes_refused: [],
    compactions: [],
    failures: [],
    spilled: { calls: 0, bytes: 0 },
    pages_held: 0,
    skills: skillUse([], [agent]).seats[0]!,
  };
}

export function audit(rows: Row[], source: string, bad = 0): RunAudit {
  const byAgent = new Map<string, AgentAudit>();
  const previousTokens = new Map<string, number>();
  const pendingAfter = new Map<string, Compaction[]>();
  const get = (id: string) => {
    let a = byAgent.get(id);
    if (!a) {
      a = emptyAgent(id);
      byAgent.set(id, a);
    }
    return a;
  };

  for (const row of rows) {
    const a = get(row.agent);
    const r = row.result;
    switch (row.tool) {
      case "compact_config": {
        a.model = str(r.model);
        if (r.ok === true) {
          a.window = num(r.window);
          a.ceiling = num(r.ceiling);
          a.ceiling_reason = str(r.ceiling_reason);
          const notice = num(r.notice);
          const warning = num(r.warning);
          const compact = num(r.compact);
          a.lines = notice !== null && warning !== null && compact !== null ? { notice, warning, compact } : null;
          a.config_error = null;
        } else {
          a.config_error = str(r.reason) ?? "rejected";
        }
        a.defaults = typeof row.args.defaults === "boolean" ? row.args.defaults : null;
        a.matched = row.args.matched && typeof row.args.matched === "object" ? (row.args.matched as Record<string, string>) : {};
        a.summary_model = str(r.summary_model);
        break;
      }
      case "context": {
        const tokens = num(r.tokens);
        if (tokens === null) break;
        a.turns += 1;
        const ceiling = a.ceiling ?? num(r.ceiling);
        const percent = ceiling ? (tokens / ceiling) * 100 : null;
        if (!a.peak || tokens > a.peak.tokens) a.peak = { tokens, ts: row.ts, percent };
        a.last = { tokens, ts: row.ts };
        const prev = previousTokens.get(row.agent);
        if (prev !== undefined && tokens > prev && (!a.largest_jump || tokens - prev > a.largest_jump.tokens)) a.largest_jump = { tokens: tokens - prev, ts: row.ts };
        previousTokens.set(row.agent, tokens);
        const waiting = pendingAfter.get(row.agent);
        if (waiting?.length) {
          for (const c of waiting) if (c.tokens_after === null) c.tokens_after = tokens;
          pendingAfter.set(row.agent, []);
        }
        break;
      }
      case "compact_notice":
      case "compact_warning":
      case "compact_forced":
        a.crossings.push({ level: row.tool.replace("compact_", "") as Crossing["level"], ts: row.ts, tokens: num(r.tokens), threshold: num(r.threshold), cycle: num(r.cycle) ?? 0 });
        break;
      case "compact_hold":
        a.holds += 1;
        break;
      case "compact_note":
        if (r.ok === true) a.notes_saved += 1;
        else a.notes_refused.push({ ts: row.ts, reason: str(r.reason) ?? "refused" });
        break;
      case "compact_done": {
        const c: Compaction = {
          ts: row.ts,
          cycle: num(r.cycle) ?? 0,
          via: str(row.args.via) ?? "?",
          reason: str(row.args.reason) ?? "?",
          tokens_before: num(r.tokens_before),
          tokens_after: num(r.tokens_after),
          summary_tokens: num(r.summary_tokens),
          summary_usd: num(r.summary_usd),
          summary_chars: num(r.summary_chars) ?? 0,
          summary_model: str(r.summary_model),
          note_chars: num(r.note_chars) ?? 0,
        };
        a.compactions.push(c);
        // Pi has no measurement before the next call; the next context row is it.
        previousTokens.delete(row.agent);
        if (c.tokens_after === null) pendingAfter.set(row.agent, [...(pendingAfter.get(row.agent) ?? []), c]);
        break;
      }
      case "compact_failed":
        a.failures.push({ ts: row.ts, stage: str(row.args.stage) ?? "?", reason: str(r.reason) ?? "failed" });
        break;
      default: {
        const full = (r.full_output ?? r.full_text) as { bytes?: unknown } | undefined;
        if (full && typeof full === "object") {
          a.spilled.calls += 1;
          a.spilled.bytes += num(full.bytes) ?? 0;
        }
        if ((row.tool === "inbox" || row.tool === "wait") && (num(r.remaining) ?? 0) > 0) a.pages_held += 1;
      }
    }
  }

  // Seats only: the watchdog and the reaper write rows as "system" and have
  // no context of their own.
  const agents = [...byAgent.values()].filter((a) => a.turns > 0 || a.model !== null || a.config_error !== null).sort((x, y) => x.agent.localeCompare(y.agent));
  const totals = {
    compactions: 0,
    hand_offs: 0,
    pi_fallbacks: 0,
    summary_usd: 0,
    summary_tokens: 0,
    holds: 0,
    spilled_calls: 0,
    spilled_bytes: 0,
    pages_held: 0,
  };
  for (const a of agents) {
    totals.compactions += a.compactions.length;
    totals.hand_offs += a.compactions.filter((c) => c.via === "self").length;
    totals.pi_fallbacks += a.compactions.filter((c) => c.via !== "self").length;
    totals.summary_usd += a.compactions.reduce((s, c) => s + (c.summary_usd ?? 0), 0);
    totals.summary_tokens += a.compactions.reduce((s, c) => s + (c.summary_tokens ?? 0), 0);
    totals.holds += a.holds;
    totals.spilled_calls += a.spilled.calls;
    totals.spilled_bytes += a.spilled.bytes;
    totals.pages_held += a.pages_held;
  }
  totals.summary_usd = Number(totals.summary_usd.toFixed(4));
  // A run with self-compaction off has no seat rows of the audit's own: the skills' seats are then read from the trace.
  const skills = skillUse(rows, agents.length ? agents.map((a) => a.agent) : undefined);
  for (const a of agents) a.skills = skills.seats.find((s) => s.agent === a.agent) ?? a.skills;
  return { source, rows: rows.length, bad_lines: bad, agents, totals, skills, findings: findings(agents, totals, skills) };
}

/**
 * What the record says about the lines. Each finding is one sentence an
 * operator can act on; none is a verdict on the run.
 */
export function findings(agents: AgentAudit[], totals: RunAudit["totals"], skills?: RunSkills): string[] {
  const out: string[] = [];
  const measured = agents.filter((a) => a.turns > 0);
  if (measured.length === 0) {
    out.push("No `context` rows: self-compaction was off for this run, or the run predates the feature; nothing here is measured.");
    if (skills) out.push(...skillFindings(skills));
    return out;
  }
  for (const a of measured) {
    if (a.config_error) out.push(`${a.agent}: the lines were rejected (${a.config_error}); this seat ran with no lock and Pi's own compaction only.`);
  }
  const overflow = agents.flatMap((a) => a.compactions.filter((c) => c.via !== "self" && c.reason === "overflow").map((c) => ({ a, c })));
  for (const { a, c } of overflow) {
    out.push(`${a.agent}: the provider refused a request at ${fmt(c.tokens_before)} tokens and Pi's overflow recovery ran; the ceiling for ${a.model ?? "this model"} (${fmt(a.ceiling)}) is above what the provider accepts, and the compact line should come down.`);
  }
  const thresholdFallbacks = agents.flatMap((a) => a.compactions.filter((c) => c.via !== "self" && c.reason === "threshold").map((c) => ({ a, c })));
  for (const { a, c } of thresholdFallbacks) {
    out.push(`${a.agent}: Pi's own threshold compaction ran at ${fmt(c.tokens_before)} tokens with no note saved; the agent did not hand off in time, and the note it would have written is missing from that cycle.`);
  }
  const caught = agents.filter((a) => a.crossings.some((x) => x.level === "forced") && a.holds > 0);
  for (const a of caught) {
    out.push(`${a.agent}: reached the compact line and was held ${a.holds} time${a.holds === 1 ? "" : "s"} before handing off; the warning line did not get a hand-off on its own.`);
  }
  const listened = agents.filter((a) => a.crossings.some((x) => x.level === "warning") && !a.crossings.some((x) => x.level === "forced") && a.compactions.some((c) => c.via === "self"));
  for (const a of listened) {
    out.push(`${a.agent}: handed off between the warning and the compact line, as the prompts ask.`);
  }
  const early = agents.filter((a) => !a.crossings.some((x) => x.level === "notice") && a.compactions.some((c) => c.via === "self"));
  for (const a of early) {
    const first = a.compactions.find((c) => c.via === "self");
    out.push(`${a.agent}: handed off below the notice line, at ${fmt(first?.tokens_before ?? null)} tokens, on its own judgement.`);
  }
  const untouched = measured.filter((a) => a.crossings.length === 0 && a.compactions.length === 0);
  if (untouched.length === measured.length) {
    const peak = Math.max(...measured.map((a) => a.peak?.percent ?? 0));
    out.push(`No agent reached the notice line; the highest context was ${peak.toFixed(1)}% of the ceiling. The lines cost this run nothing and could sit lower without changing it.`);
  }
  const restartsHigh = agents.flatMap((a) => a.compactions.filter((c) => c.tokens_after !== null && a.lines && c.tokens_after > a.lines.compact * 0.5).map((c) => ({ a, c })));
  for (const { a, c } of restartsHigh) {
    out.push(`${a.agent}: after the cycle-${c.cycle} compaction the context restarted at ${fmt(c.tokens_after)} tokens, more than half the compact line; Pi's retained history (keepRecentTokens) or the summary itself is large for this model.`);
  }
  const jumps = agents.filter((a) => a.largest_jump && a.lines && a.largest_jump.tokens > (a.ceiling ?? 0) - a.lines.compact);
  for (const a of jumps) {
    out.push(`${a.agent}: one turn added ${fmt(a.largest_jump!.tokens)} tokens, more than the room between the compact line and the ceiling; a single result that size can overshoot the line.`);
  }
  if (totals.summary_usd > 0) {
    out.push(`Summaries: ${totals.compactions} (${totals.hand_offs} hand-off${totals.hand_offs === 1 ? "" : "s"}, ${totals.pi_fallbacks} by Pi's own recovery), ${fmt(totals.summary_tokens)} tokens, $${totals.summary_usd.toFixed(2)}.`);
  }
  if (totals.spilled_calls > 0) {
    out.push(`${totals.spilled_calls} tool call${totals.spilled_calls === 1 ? "" : "s"} produced more than the model received; the whole output, ${fmtBytes(totals.spilled_bytes)}, is under tool-output/ and named on each row.`);
  }
  if (totals.pages_held > 0) {
    out.push(`${totals.pages_held} inbox/wait deliver${totals.pages_held === 1 ? "y" : "ies"} held posts back for the next call; no post was cut.`);
  }
  if (skills) out.push(...skillFindings(skills));
  return out;
}

/** What the record says about the skills; empty for a run that carried none. */
export function skillFindings(skills: RunSkills): string[] {
  const t = skills.totals;
  const out: string[] = [];
  const touched = skills.seats.some((s) => s.index_source !== null) || t.loads > 0 || t.index_reads > 0 || t.failed > 0;
  if (!touched) return out;
  if (touched) {
    const missing = skills.seats.filter((s) => !s.index_in_prompt);
    const bySource = (source: string) => missing.filter((s) => s.index_source === source).map((s) => s.agent);
    const none = missing.filter((s) => s.index_source === null).map((s) => s.agent);
    if (!missing.length) out.push(`All ${t.seats} seats had the run's index in the prompt Pi keeps for every run.`);
    else {
      out.push(`${t.seats_with_index} of ${t.seats} seats had the run's index in the prompt Pi keeps for every run (the kickoff's .pi/APPEND_SYSTEM.md).`);
      if (none.length) out.push(`${none.join(", ")}: no \`skills_index\` row, so nothing says the packs' index reached ${none.length === 1 ? "that seat" : "those seats"}.`);
      if (bySource("extension").length) out.push(`${bySource("extension").join(", ")}: the prompt had no index, the extension added it to the first run's prompt, and a run a hand-off starts does not keep that.`);
      if (bySource("stale").length) out.push(`${bySource("stale").join(", ")}: the prompt carried an index written for other packs.`);
      if (bySource("none").length) out.push(`${bySource("none").join(", ")}: the packs listed no skill.`);
    }
  }
  out.push(
    `Skills: ${t.loads} bod${t.loads === 1 ? "y" : "ies"} loaded by ${t.seats_that_loaded} of ${t.seats} seats (${fmt(t.tokens_loaded)} tokens); ${t.seats - t.seats_that_loaded} seat${t.seats - t.seats_that_loaded === 1 ? "" : "s"} never loaded one.`,
  );
  if (t.loads > 0) {
    out.push(
      `Of those loads, ${t.referenced} show a later use (the skill named, or one of its tools called) and ${t.unused} show none (a proxy: a seat can apply a note without naming it); ${t.done} ${t.done === 1 ? "was" : "were"} marked done with skill_done.`,
    );
    const approximate = skills.seats.some((s) => s.loads > 0 && s.lost_basis === "compact_done");
    out.push(
      `${t.lost_at_compaction} loaded bod${t.lost_at_compaction === 1 ? "y" : "ies"} ${t.lost_at_compaction === 1 ? "was" : "were"} taken out of the seat's context by a compaction (the newest part of the history a compaction keeps is not counted); ${t.refetched} ${t.refetched === 1 ? "was" : "were"} loaded again.${approximate ? " For some seats the trace has no skills_compacted row, so every compaction is counted as taking every body loaded before it: an upper bound." : ""}`,
    );
    if (t.loads_without_tools > 0) {
      out.push(`${t.loads_without_tools} of the loads come from rows that carry no tools list (a trace from before the harness wrote it): only a mention of the skill's id can show their use, so "no trace of use" is an upper bound there.`);
    }
  }
  if (t.already_loaded > 0) out.push(`${t.already_loaded} call${t.already_loaded === 1 ? "" : "s"} asked for a body the seat already held and was told so instead of being sent it again.`);
  if (t.failed > 0) out.push(`${t.failed} skill call${t.failed === 1 ? "" : "s"} named no skill the packs carry.`);
  return out;
}

function fmt(n: number | null | undefined): string {
  return n === null || n === undefined ? "?" : n.toLocaleString("en-US");
}

function fmtBytes(n: number): string {
  if (n < 1024) return `${n} B`;
  if (n < 1024 * 1024) return `${(n / 1024).toFixed(1)} KB`;
  return `${(n / (1024 * 1024)).toFixed(1)} MB`;
}

function pct(tokens: number | null, ceiling: number | null): string {
  return tokens === null || !ceiling ? "" : ` (${((tokens / ceiling) * 100).toFixed(1)}%)`;
}

function clock(ts: string): string {
  const m = /T(\d\d:\d\d:\d\d)/.exec(ts);
  return m ? m[1]! : ts;
}

export function renderMarkdown(run: RunAudit): string {
  const lines: string[] = [];
  lines.push(`# Context history`);
  lines.push("");
  lines.push(`Source: \`${run.source}\` (${run.rows.toLocaleString("en-US")} rows${run.bad_lines ? `, ${run.bad_lines} unreadable` : ""})`);
  lines.push("");
  lines.push("| Agent | Model | Ceiling | Lines (notice / warning / compact) | Turns | Peak | Crossed | Holds | Hand-offs | Pi fallbacks | Summary cost |");
  lines.push("| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |");
  for (const a of run.agents) {
    const crossed = a.crossings.map((c) => c.level).filter((v, i, arr) => arr.indexOf(v) === i).join(", ") || "none";
    const cost = a.compactions.reduce((s, c) => s + (c.summary_usd ?? 0), 0);
    lines.push(
      `| ${a.agent} | ${a.model ?? "?"} | ${fmt(a.ceiling)} | ${a.lines ? `${fmt(a.lines.notice)} / ${fmt(a.lines.warning)} / ${fmt(a.lines.compact)}` : a.config_error ? "rejected" : "?"} | ${a.turns} | ${a.peak ? `${fmt(a.peak.tokens)}${pct(a.peak.tokens, a.ceiling)}` : "?"} | ${crossed} | ${a.holds} | ${a.compactions.filter((c) => c.via === "self").length} | ${a.compactions.filter((c) => c.via !== "self").length} | ${cost ? `$${cost.toFixed(2)}` : "—"} |`,
    );
  }
  lines.push("");
  const skillSeats = run.skills.seats.filter((s) => s.index_source !== null || s.loads > 0 || s.index_reads > 0 || s.failed > 0);
  if (skillSeats.length) {
    lines.push("## Skills");
    lines.push("");
    lines.push("| Agent | Index in prompt | Loads | Distinct | Tokens loaded | Used after load (proxy) | No trace of use | Done | Taken out by a compaction | Loaded again | Missed |");
    lines.push("| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |");
    for (const s of skillSeats) {
      const index = s.index_in_prompt ? `yes${s.index_tokens !== null ? ` (${fmt(s.index_tokens)} tokens)` : ""}` : s.index_source === "extension" ? "first run only (extension)" : s.index_source === "stale" ? "another pack set's" : s.index_source === "none" ? "no skills" : "no row";
      lines.push(`| ${s.agent} | ${index} | ${s.loads} | ${s.distinct} | ${fmt(s.tokens_loaded)} | ${s.referenced} | ${s.unused} | ${s.done} | ${s.lost_at_compaction} | ${s.refetched} | ${s.failed} |`);
    }
    lines.push("");
  }
  for (const a of run.agents) {
    if (a.crossings.length === 0 && a.compactions.length === 0 && a.failures.length === 0 && a.notes_refused.length === 0) continue;
    lines.push(`## ${a.agent}`);
    lines.push("");
    if (a.ceiling_reason) lines.push(`Ceiling ${fmt(a.ceiling)} of a ${fmt(a.window)}-token window: ${a.ceiling_reason}.${a.summary_model ? ` Summaries by ${a.summary_model}.` : ""}${Object.keys(a.matched).length ? ` Per-model lines applied: ${Object.entries(a.matched).map(([k, v]) => `${k}=${v}`).join(", ")}.` : ""}`);
    if (a.largest_jump) lines.push(`Largest climb in one turn: ${fmt(a.largest_jump.tokens)} tokens at ${clock(a.largest_jump.ts)}.`);
    lines.push("");
    const moments: Array<{ ts: string; text: string }> = [];
    for (const c of a.crossings) moments.push({ ts: c.ts, text: `crossed the ${c.level} line (${fmt(c.threshold)}) at ${fmt(c.tokens)} tokens${pct(c.tokens, a.ceiling)}, cycle ${c.cycle}` });
    for (const n of a.notes_refused) moments.push({ ts: n.ts, text: `note refused: ${n.reason}` });
    for (const c of a.compactions) {
      moments.push({
        ts: c.ts,
        text: `${c.via === "self" ? "hand-off" : `Pi's own ${c.reason} compaction`} (cycle ${c.cycle}): ${fmt(c.tokens_before)} → ${fmt(c.tokens_after)} tokens; summary ${fmt(c.summary_tokens)} tokens${c.summary_usd !== null ? ` ($${c.summary_usd.toFixed(3)})` : ""}, ${fmt(c.summary_chars)} chars${c.summary_model ? ` by ${c.summary_model}` : ""}${c.note_chars ? `; note ${fmt(c.note_chars)} chars` : "; no note"}`,
      });
    }
    for (const f of a.failures) moments.push({ ts: f.ts, text: `failed at ${f.stage}: ${f.reason}` });
    moments.sort((x, y) => x.ts.localeCompare(y.ts));
    for (const m of moments) lines.push(`- ${clock(m.ts)} ${m.text}`);
    if (a.holds) lines.push(`- ${a.holds} tool call${a.holds === 1 ? "" : "s"} held at the compact line`);
    lines.push("");
  }
  lines.push("## What the record says");
  lines.push("");
  for (const f of run.findings) lines.push(`- ${f}`);
  lines.push("");
  return lines.join("\n");
}

function main(argv: string[]): number {
  const args = argv.filter((a) => !a.startsWith("--"));
  const json = argv.includes("--json");
  const source = args[0];
  if (!source) {
    process.stderr.write("usage: context-audit.ts <sandbox|events.jsonl> [--json]\n");
    return 2;
  }
  let read: ReturnType<typeof readRows>;
  try {
    read = readRows(source);
  } catch (error) {
    process.stderr.write(`cannot read the trace: ${error instanceof Error ? error.message : String(error)}\n`);
    return 1;
  }
  const run = audit(read.rows, read.file, read.bad);
  process.stdout.write(json ? `${JSON.stringify(run, null, 2)}\n` : renderMarkdown(run));
  return 0;
}

if (process.argv[1] && /context-audit\.ts$/.test(process.argv[1])) {
  process.exitCode = main(process.argv.slice(2));
}
