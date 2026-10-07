/**
 * How a run used its skills, from the trace alone.
 *
 * Three rows carry it (extensions/skills.ts): `skills_index` when a seat's
 * prompt was built, `skill` for every call of the tool (a body, the index, a
 * miss, an answer that the body is already in context) and `skill_done` when a
 * seat said it was finished with one. `compact_done` marks a compaction. This
 * module is pure and has no DOM, so the context audit (scripts/context-audit.ts),
 * the console server (scripts/ui/model.ts) and the Packs tab share it.
 *
 * "Referenced after load" is a proxy, and says so wherever it is shown: a load
 * counts as used when a later row of the same seat names the skill (its id, as
 * `id` or `pack:id`, in a post, a command, a record or the seat's reasoning) or
 * calls a tool the skill's own front matter names. A seat can apply a note
 * without naming it, so "unused" means "no trace of use", not "not used".
 */

export type SkillTraceRow = { ts: string; agent: string; tool: string; args?: unknown; result?: unknown };

export type SkillLoadUse = {
  id: string;
  pack: string | null;
  ts: string;
  tokens: number;
  sha256: string | null;
  /** Named, or one of its tools called, by a later row of the same seat. */
  referenced: boolean;
  /** A compaction of the seat took the body out of its context (the kept tail is not counted as lost). */
  lost_at_compaction: boolean;
  /** The seat loaded it again after that compaction. */
  refetched: boolean;
  /** The seat marked it done. */
  done: boolean;
};

export type SeatSkills = {
  agent: string;
  /**
   * The seat's prompt carried this run's index whole, in Pi's own prompt (the
   * kickoff's file), which every run of the seat keeps: a `skills_index` row
   * says `source: prompt` and that it matches the packs. An index the
   * extension had to add (`extension`) lasts for the first run only, a stale
   * one is a different index, and neither counts.
   */
  index_in_prompt: boolean;
  /** Where the index came from, as the row says: prompt, extension, stale or none. */
  index_source: string | null;
  index_tokens: number | null;
  /** `skill()` with no id. */
  index_reads: number;
  /** Bodies delivered. */
  loads: number;
  distinct: number;
  /** Calls answered "already in your context". */
  already_loaded: number;
  /** Calls that found no skill. */
  failed: number;
  tokens_loaded: number;
  done: number;
  referenced: number;
  /** Loads with no trace of use afterwards. */
  unused: number;
  lost_at_compaction: number;
  refetched: number;
  compactions: number;
  /**
   * What `lost_at_compaction` rests on: `skills_compacted` rows (the harness
   * says which bodies each compaction took out and which it kept), the
   * seat's `compact_done` rows (an approximation: every compaction counts as
   * taking every body loaded before it), or nothing.
   */
  lost_basis: "skills_compacted" | "compact_done" | "none";
  /** Loads whose row carries no `tools` (a trace from before the harness wrote them): only a mention of the id can show their use. */
  loads_without_tools: number;
  detail: SkillLoadUse[];
};

export type SkillRollup = {
  /** `pack:id` (or the bare id when the row did not say the pack). */
  key: string;
  id: string;
  pack: string | null;
  loads: number;
  agents: string[];
  first: string;
  last: string;
  tokens: number;
};

export type RunSkills = {
  seats: SeatSkills[];
  by_skill: SkillRollup[];
  totals: {
    seats: number;
    seats_with_index: number;
    seats_that_loaded: number;
    loads: number;
    tokens_loaded: number;
    done: number;
    referenced: number;
    unused: number;
    lost_at_compaction: number;
    refetched: number;
    loads_without_tools: number;
    already_loaded: number;
    failed: number;
    index_reads: number;
  };
};

const BYTES_PER_TOKEN = 4.245;

function obj(v: unknown): Record<string, unknown> {
  return v && typeof v === "object" && !Array.isArray(v) ? (v as Record<string, unknown>) : {};
}

function num(v: unknown): number | null {
  return typeof v === "number" && Number.isFinite(v) ? v : null;
}

function str(v: unknown): string | null {
  return typeof v === "string" && v ? v : null;
}

function strings(v: unknown): string[] {
  return Array.isArray(v) ? v.filter((x): x is string => typeof x === "string" && x.length > 0) : [];
}

function escapeRegExp(s: string): string {
  return s.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

/** Rows that only describe the skill machinery or the gauge: a mention there is not use. */
const NOT_USE = new Set(["skill", "skill_done", "skills_index", "skills_compacted", "context"]);

type Load = SkillLoadUse & { at: number; tools: string[]; toolsKnown: boolean; turn: number | null; reload: boolean };

export function emptySeat(agent: string): SeatSkills {
  return {
    agent,
    index_in_prompt: false,
    index_source: null,
    index_tokens: null,
    index_reads: 0,
    loads: 0,
    distinct: 0,
    already_loaded: 0,
    failed: 0,
    tokens_loaded: 0,
    done: 0,
    referenced: 0,
    unused: 0,
    lost_at_compaction: 0,
    refetched: 0,
    compactions: 0,
    lost_basis: "none",
    loads_without_tools: 0,
    detail: [],
  };
}

/**
 * Every seat's skill use over the rows, in trace order. `seatIds` names the
 * seats the run had, so a seat that never touched a skill still counts (and is
 * the number that matters); without it, a seat is an agent that started, had a
 * context row, or touched a skill (the watchdog and the operator write rows too).
 */
export function skillUse(rows: readonly SkillTraceRow[], seatIds?: readonly string[]): RunSkills {
  const perAgent = new Map<string, { at: number; row: SkillTraceRow }[]>();
  rows.forEach((row, at) => {
    if (typeof row.agent !== "string" || !row.agent) return;
    const list = perAgent.get(row.agent) ?? [];
    list.push({ at, row });
    perAgent.set(row.agent, list);
  });

  const seats: SeatSkills[] = [];
  const rollup = new Map<string, SkillRollup & { agentSet: Set<string> }>();
  const isSeatRow = (r: SkillTraceRow) => r.tool === "agent_start" || r.tool === "context" || r.tool === "skills_index" || r.tool === "skill" || r.tool === "skill_done";
  const ids = seatIds ? [...new Set(seatIds)] : [...perAgent].filter(([, list]) => list.some(({ row }) => isSeatRow(row))).map(([agent]) => agent);

  for (const agent of ids) {
    const seat = emptySeat(agent);
    const mine = perAgent.get(agent) ?? [];
    const loads: Load[] = [];
    const compactionAts: number[] = [];
    // The harness's own account of each compaction: which bodies it took out (`pack:id|turn`).
    const compacted: { at: number; lost: Set<string> }[] = [];

    for (const { at, row } of mine) {
      const a = obj(row.args);
      const r = obj(row.result);
      if (row.tool === "skills_index") {
        seat.index_source = str(r.source);
        // A row without a source predates the field and says only whether the section was built.
        seat.index_in_prompt = r.ok !== false && (r.source === undefined || (r.source === "prompt" && r.matches_packs !== false));
        seat.index_tokens = num(r.section_tokens) ?? num(r.shown_tokens);
      } else if (row.tool === "skill") {
        const id = str(a.id);
        if (id === "INDEX") {
          seat.index_reads += 1;
        } else if (r.ok === false) {
          seat.failed += 1;
        } else if (r.already_loaded === true) {
          seat.already_loaded += 1;
        } else if (id) {
          const bytes = num(r.bytes);
          loads.push({
            id,
            pack: str(r.pack),
            ts: row.ts,
            tokens: num(r.tokens) ?? (bytes !== null ? Math.ceil(bytes / BYTES_PER_TOKEN) : 0),
            sha256: str(r.sha256),
            referenced: false,
            lost_at_compaction: false,
            refetched: false,
            done: false,
            at,
            tools: strings(r.tools),
            toolsKnown: Array.isArray(r.tools),
            turn: num(r.turn),
            reload: r.reload_after_compaction === true,
          });
        }
      } else if (row.tool === "skill_done") {
        if (r.ok !== false) {
          seat.done += 1;
          const id = str(a.id);
          const open = [...loads].reverse().find((l) => l.id === id && !l.done);
          if (open) open.done = true;
        }
      } else if (row.tool === "compact_done") {
        compactionAts.push(at);
      } else if (row.tool === "skills_compacted") {
        const lost = Array.isArray(r.lost) ? (r.lost as unknown[]).map((x) => obj(x)).filter((x) => typeof x.key === "string") : [];
        compacted.push({ at, lost: new Set(lost.map((x) => `${String(x.key)}|${String(num(x.turn) ?? "")}`)) });
      }
    }

    // Compactions: what each one took out, and whether the seat loaded it again.
    const keyOf = (l: Load) => `${l.pack ?? ""}:${l.id}`;
    const tookOut = (l: Load) => compacted.find((c) => c.at > l.at && c.lost.has(`${keyOf(l)}|${l.turn ?? ""}`));
    const exact = compacted.length > 0;
    for (const l of loads) {
      const when = exact ? tookOut(l)?.at : compactionAts.find((c) => c > l.at);
      if (when === undefined) continue;
      l.lost_at_compaction = true;
      l.refetched = loads.some((o) => keyOf(o) === keyOf(l) && o.at > when);
    }

    // The proxy: later rows of this seat that name the skill or call one of its tools.
    const hay = new Map<number, string>();
    const haystack = (at: number, row: SkillTraceRow): string => {
      let h = hay.get(at);
      if (h === undefined) {
        const r = obj(row.result);
        let args = "";
        try {
          args = JSON.stringify(row.args ?? {});
        } catch {
          args = "";
        }
        h = `${row.tool} ${args}${row.tool === "thinking" && typeof r.text === "string" ? ` ${r.text}` : ""}`;
        hay.set(at, h);
      }
      return h;
    };
    for (const l of loads) {
      const toolRes = l.tools.map((t) => ({ t, re: new RegExp(`(^|[^A-Za-z0-9_])${escapeRegExp(t)}([^A-Za-z0-9_]|$)`) }));
      for (const { at, row } of mine) {
        if (at <= l.at || NOT_USE.has(row.tool) || row.tool.startsWith("compact_")) continue;
        const h = haystack(at, row);
        if (h.includes(l.id) || toolRes.some(({ t, re }) => row.tool === t || re.test(h))) {
          l.referenced = true;
          break;
        }
      }
    }

    seat.loads = loads.length;
    seat.distinct = new Set(loads.map(keyOf)).size;
    seat.tokens_loaded = loads.reduce((sum, l) => sum + l.tokens, 0);
    seat.referenced = loads.filter((l) => l.referenced).length;
    seat.unused = loads.length - seat.referenced;
    seat.lost_at_compaction = loads.filter((l) => l.lost_at_compaction).length;
    // A load that came after a compaction took the same note out: the harness says so on the row
    // (`reload_after_compaction`), and the order of the rows says it for a trace that predates the flag.
    seat.refetched = loads.filter((l, i) => l.reload || loads.slice(0, i).some((o) => keyOf(o) === keyOf(l) && (exact ? compacted.some((c) => c.at > o.at && c.at < l.at && c.lost.has(`${keyOf(o)}|${o.turn ?? ""}`)) : compactionAts.some((c) => c > o.at && c < l.at)))).length;
    seat.compactions = compactionAts.length;
    seat.lost_basis = exact ? "skills_compacted" : compactionAts.length ? "compact_done" : "none";
    seat.loads_without_tools = loads.filter((l) => !l.toolsKnown).length;
    seat.detail = loads.map(({ at: _at, tools: _tools, toolsKnown: _known, turn: _turn, reload: _reload, ...rest }) => rest);
    seats.push(seat);

    for (const l of loads) {
      const key = l.pack ? `${l.pack}:${l.id}` : l.id;
      const row = rollup.get(key) ?? { key, id: l.id, pack: l.pack, loads: 0, agents: [], first: l.ts, last: l.ts, tokens: 0, agentSet: new Set<string>() };
      row.loads += 1;
      row.tokens += l.tokens;
      row.agentSet.add(agent);
      if (l.ts < row.first) row.first = l.ts;
      if (l.ts > row.last) row.last = l.ts;
      rollup.set(key, row);
    }
  }

  const by_skill = [...rollup.values()]
    .map(({ agentSet, ...row }) => ({ ...row, agents: [...agentSet].sort() }))
    .sort((x, y) => y.loads - x.loads || x.key.localeCompare(y.key));
  const sum = (pick: (s: SeatSkills) => number) => seats.reduce((n, s) => n + pick(s), 0);
  return {
    seats,
    by_skill,
    totals: {
      seats: seats.length,
      seats_with_index: seats.filter((s) => s.index_in_prompt).length,
      seats_that_loaded: seats.filter((s) => s.loads > 0).length,
      loads: sum((s) => s.loads),
      tokens_loaded: sum((s) => s.tokens_loaded),
      done: sum((s) => s.done),
      referenced: sum((s) => s.referenced),
      unused: sum((s) => s.unused),
      lost_at_compaction: sum((s) => s.lost_at_compaction),
      refetched: sum((s) => s.refetched),
      loads_without_tools: sum((s) => s.loads_without_tools),
      already_loaded: sum((s) => s.already_loaded),
      failed: sum((s) => s.failed),
      index_reads: sum((s) => s.index_reads),
    },
  };
}

/** True when the trace has any sign that the run carried packs: an index row, or a call of the tool. */
export function carriedSkills(rows: readonly SkillTraceRow[]): boolean {
  return rows.some((r) => r.tool === "skills_index" || r.tool === "skill");
}
