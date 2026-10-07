#!/usr/bin/env node
/**
 * The model provider's limit on every seat (docs/adr/0013, "The provider's
 * limit"). A subscription's usage limit refuses every seat at once, each
 * turn ending in an agent_error ("You have hit your ChatGPT usage limit (pro
 * plan). Try again in ~6904 min.", "Codex error: The usage limit has been
 * reached"). An until-solved run's watchdog then prompted every seat again,
 * half an hour apart, for days, every VM and the hub up, and the operator was
 * never told the run could not go on before a stated time.
 *
 * So the run pauses, whatever its stop policy, when every live seat's last
 * turn since the last lift ended in a provider error and every one of those
 * seats is itself limited: its error states a wait of half an hour or more,
 * or it was prompted again after its first error and refused again. One
 * seat's error never pauses the run, and neither does one seat's long wait
 * beside the others' passing errors. The harness tries again at the end the
 * provider named (below, `until`) or every half hour when none is known, and
 * the same rule pauses the run again if every seat is refused again.
 * Generic: nothing here names a provider; the only reading of the words is
 * the wait they state, and a seat's provider is the part of its model name
 * before the slash.
 *
 *   provider-limit.ts tick <sandbox> [--now ISO]
 *       the watchdog's pass: lift the pause when its try is due, or pause the
 *       run when the rule holds; one JSON line, {action: paused|lifted|none}
 *   provider-limit.ts wait <text> [--at ISO]
 *       the wait a provider's error text states, as JSON (null when none)
 */
import { existsSync } from "node:fs";
import { open, readFile } from "node:fs/promises";
import { join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import * as P from "../extensions/protocol.ts";

// --- the wait a provider's words state ------------------------------------------------------

/**
 * The longest wait read as one. Past it the words are not taken for a wait
 * (an epoch sent where seconds were meant, "Retry-After: 1727600000", read as
 * fifty years): the harness tries again every half hour instead, and the
 * words stay whole on the trace.
 */
export const PROVIDER_WAIT_MAX_MS = 30 * 86_400_000;

const UNITS: Array<[RegExp, number]> = [
  [/^(?:milliseconds?|msecs?|ms)$/i, 1],
  [/^(?:seconds?|secs?|s)$/i, 1_000],
  [/^(?:minutes?|mins?|m)$/i, 60_000],
  [/^(?:hours?|hrs?|h)$/i, 3_600_000],
  [/^(?:days?|d)$/i, 86_400_000],
];
const NUM = String.raw`\d+(?:\.\d+)?`;
const UNIT = "milliseconds?|msecs?|ms|seconds?|secs?|s|minutes?|mins?|m|hours?|hrs?|h|days?|d";
const PART = String.raw`${NUM}\s*(?:${UNIT})(?![a-z])`;
/** One duration: "~6904 min", "6m0s", "1 hour 30 minutes", "1h, 30m". */
const DURATION = String.raw`(?:about\s+|approximately\s+|approx\.?\s+|~\s*)?(${PART}(?:\s*(?:,|and)?\s*${PART})*)`;
/** A wait said as one: "try again in", "retry after", "resets in", "available again in", "wait for". */
const SAID = new RegExp(String.raw`(?:try(?:ing)?\s+again|retry(?:ing)?|resets?|available(?:\s+again)?|wait(?:ing)?|resumes?|lifts?)\b[^.;\n]{0,24}?\b(?:in|after|for)\s+${DURATION}`, "i");
/** A Retry-After-style number: seconds. */
const RETRY_AFTER = new RegExp(String.raw`retry[-_ ]?after["']?\s*[:=]?\s*(${NUM})(?!\s*[a-z%]|\d|\.\d)`, "i");
/** A time with its zone: "2026-09-30T12:00:00Z", "2026-09-30 12:00 UTC", "…+03:00". */
const ISO = /\b(\d{4}-\d{2}-\d{2})[T ](\d{2}:\d{2}(?::\d{2}(?:\.\d+)?)?)\s*(Z|UTC|[+-]\d{2}:?\d{2})\b/gi;
/** "in N minutes" with nothing before it that says a wait, the last resort. */
const BARE = new RegExp(String.raw`\b(?:in|after)\s+${DURATION}`, "i");

function durationMs(text: string): number | null {
  let total = 0;
  let any = false;
  for (const m of text.matchAll(new RegExp(String.raw`(${NUM})\s*(${UNIT})(?![a-z])`, "gi"))) {
    const unit = UNITS.find(([re]) => re.test(m[2]));
    if (!unit) return null;
    total += Number(m[1]) * unit[1];
    any = true;
  }
  return any && total > 0 ? Math.round(total) : null;
}

export type ProviderWait = { until: number; wait_ms: number; said: string };

/**
 * The wait a provider's error text states, from `at` (when the error was
 * recorded): "try again in ~N min", "in N minutes", "in N hours", "retry
 * after N seconds", a Retry-After number (seconds), or the first time with
 * its zone that is after `at`. The first of those forms the text holds, in
 * that order, of at most PROVIDER_WAIT_MAX_MS; null when it states none.
 */
export function parseProviderWait(text: string, at: number): ProviderWait | null {
  if (!text) return null;
  const take = (ms: number | null, said: string): ProviderWait | null => (ms && ms > 0 && ms <= PROVIDER_WAIT_MAX_MS ? { until: at + ms, wait_ms: ms, said } : null);
  const said = SAID.exec(text);
  const fromSaid = said ? take(durationMs(said[1]), said[0]) : null;
  if (fromSaid) return fromSaid;
  const header = RETRY_AFTER.exec(text);
  const fromHeader = header ? take(Math.round(Number(header[1]) * 1_000), header[0]) : null;
  if (fromHeader) return fromHeader;
  for (const iso of text.matchAll(ISO)) {
    const zone = /^utc$/i.test(iso[3]) ? "Z" : iso[3].toUpperCase().replace(/^([+-]\d{2})(\d{2})$/, "$1:$2");
    const t = Date.parse(`${iso[1]}T${iso[2]}${zone}`);
    if (!Number.isFinite(t) || t <= at) continue;
    const fromIso = take(t - at, iso[0]);
    if (fromIso) return fromIso;
  }
  const bare = BARE.exec(text);
  return bare ? take(durationMs(bare[1]), bare[0]) : null;
}

// --- the rule -------------------------------------------------------------------------------

/** One trace row as the rule reads it: who, what, when (the host's clock), and the fields it looks at. */
export type TraceRow = { agent: string; tool: string; at: number; args?: Record<string, unknown>; result?: Record<string, unknown> };

/**
 * Rows a seat's harness writes under the seat's id without the seat's model
 * having answered: a prompt arriving, its context gauge and thinking, tools
 * loading, the hub link's state, its own errors and caps, a pause's hold,
 * the compaction's bookkeeping, the hints it adds to a call. None of them is
 * a turn that went anywhere. tests/provider-pause.test.ts holds every row the
 * extension writes under a seat's id to this list, to a tool the seat calls,
 * or to a row written inside such a call.
 */
export const SEAT_HARNESS_ROWS: ReadonlySet<string> = new Set([
  "agent_start", "agent_stop", "hub_prompt", "hub_lost", "hub_lost_stop", "context", "thinking", "tool_loaded", "toolchain",
  "inputs_guard", "budget_precall_stop", "pause_hold", "run_paused", "harness_stop", "extension_error", "watch_truncated",
  "agent_cap_steer", "agent_cap_stop", "sentinel_nudge", "repeat_hint", "job_hint", "evidence_code", "forge_hint", "publish_needed", "skills_index", "skills_compacted",
  "self_compact", "compact_config", "compact_notice", "compact_warning", "compact_forced", "compact_hold",
  "compact_note", "compact_start", "compact_done", "compact_failed", "compact_stalled", "compact_held",
  // A ledger entry the harness authored while it made the seat's header (a person's hint as a hypothesis).
  "harness_record",
  // The model a provider said answered a message (a resolved alias, or a substitution): bookkeeping beside the thinking row.
  "model_reported",
]);

/**
 * How late a prompt's own row may land after the error its turn ended in: a
 * watchdog writes its nudge's row after the delivery returns, and in a host
 * run a limit's refusal can reach the trace first.
 */
export const PROMPT_ROW_LAG_MS = 5_000;

/** A prompt that reached the seat: the watchdog's nudge or wake, or the hub's delivery its extension recorded. */
function promptTo(row: TraceRow, id: string): boolean {
  if (row.agent === id) return row.tool === "hub_prompt" && row.result?.ok === true;
  return row.agent === "system" && (row.tool === "idle_nudge" || row.tool === "resume_wake") && row.args?.agent === id && row.result?.ok === true;
}

export type SeatLimit = {
  agent: string;
  /** Its last own row since the last lift is a provider error. */
  refused: boolean;
  /** Refused, and limited by its own evidence: a long stated wait, or refused again after a prompt. */
  limited: boolean;
  model: string | null;
  /** The provider's words on its last error, whole. */
  reason: string | null;
  /** Its provider errors in a row, and when the first and the last were recorded. */
  errors: number;
  first_at: number | null;
  last_at: number | null;
  /** Prompted again after its first error, and refused again after that prompt. */
  retried: boolean;
  /** When it last did anything but fail (0: never). */
  worked_at: number;
  /** The wait its errors state, from the last one that states one, while still ahead. */
  until: number | null;
  wait_ms: number | null;
  /** The lift's wake did not reach it, and nothing of its own is on the trace since. */
  unreached: boolean;
};

/** Where one seat stands: its provider errors in a row at the end of its trace, and what they said. */
export function seatLimit(rows: TraceRow[], id: string, since: number, now: number): SeatLimit {
  const own = rows.filter((r) => r.agent === id && !SEAT_HARNESS_ROWS.has(r.tool));
  let i = own.length - 1;
  while (i >= 0 && own[i].tool === "agent_error") i--;
  const streak = own.slice(i + 1);
  const last = streak.at(-1);
  const first = streak[0];
  const refused = Boolean(last && last === own.at(-1) && last.at > since);
  const reasonOf = (r: TraceRow) => String(r.result?.reason ?? "");
  let wait: ProviderWait | null = null;
  for (let k = streak.length - 1; k >= 0 && !wait; k--) wait = parseProviderWait(reasonOf(streak[k]), streak[k].at);
  const ahead = wait && wait.until > now ? wait : null;
  const retried = Boolean(first && last && streak.length > 1 && rows.some((r) => promptTo(r, id) && r.at > first.at && r.at <= last.at + PROMPT_ROW_LAG_MS));
  // A lift's wake that did not land (resume_wake ok: false), none that did,
  // and nothing of its own since the lift: a seat whose process is gone
  // before the reaper has said so.
  const wakes = rows.filter((r) => r.agent === "system" && r.tool === "resume_wake" && r.args?.agent === id && r.at > since);
  const unreached = since > 0 && wakes.some((r) => r.result?.ok === false) && !wakes.some((r) => r.result?.ok === true) && !rows.some((r) => r.agent === id && r.at > since);
  return {
    agent: id,
    refused,
    limited: refused && ((ahead?.wait_ms ?? 0) >= P.PROVIDER_LIMIT_LONG_MS || retried),
    model: last ? String(last.args?.model ?? "") || null : null,
    reason: last ? reasonOf(last) : null,
    errors: streak.length,
    first_at: first?.at ?? null,
    last_at: last?.at ?? null,
    retried,
    worked_at: i >= 0 ? own[i].at : 0,
    until: ahead?.until ?? null,
    wait_ms: ahead?.wait_ms ?? null,
    unreached,
  };
}

/** A seat's provider: its model's name before the slash; null when its model is not known. */
export function providerOf(model: string | null): string | null {
  const cut = model?.indexOf("/") ?? -1;
  return model && cut > 0 ? model.slice(0, cut) : null;
}

/**
 * The end the pause holds to, from the ends the limited seats were told.
 * Every seat on one provider: each uses the one credential the run's Pi
 * store (or the key the kickoff was given) holds for that provider, so its
 * limit is one limit, and the longest wait any of them was told is when it
 * has lifted; a try before it would only be refused. Seats on more than one provider (or one whose model is not
 * known): the earliest end, when each seat was told one, the first time any
 * of them can go on; otherwise none, and the harness tries every half hour.
 */
export function pauseUntil(seats: Array<Pick<SeatLimit, "model" | "until">>): number | null {
  if (!seats.length) return null;
  const providers = new Set(seats.map((s) => providerOf(s.model)));
  const ends = seats.map((s) => s.until).filter((u): u is number => u !== null);
  if (providers.size === 1 && !providers.has(null)) return ends.length ? Math.max(...ends) : null;
  return ends.length === seats.length ? Math.min(...ends) : null;
}

export type ProviderLimitVerdict = {
  pause: boolean;
  /** Why, or why not, in words. */
  why: string;
  seats: SeatLimit[];
  /** The seats the lift's wake did not reach, left out of the rule. */
  unreached: string[];
  /** The models refused, and their distinct error texts, whole, one a line. */
  models: string[];
  detail: string;
  /** The end the pause holds to (pauseUntil). */
  until: string | null;
  /** A seat worked since the last lift: a pause now begins a new spell. */
  worked_since: boolean;
};

/**
 * The rule. Paused when every live seat (not done, not dead, and reached by
 * the last lift's wake) has, as its last own row since the last lift
 * (`since`), a provider error, and every one of those seats is limited: its
 * errors state a wait of half an hour or more still ahead, or it was
 * prompted again after its first error and refused again. Pure: the rows are
 * the trace's, in order.
 */
export function providerLimitVerdict(rows: TraceRow[], live: string[], o: { since: number; now: number }): ProviderLimitVerdict {
  const all = live.map((id) => seatLimit(rows, id, o.since, o.now));
  const unreached = all.filter((s) => s.unreached).map((s) => s.agent);
  const seats = all.filter((s) => !s.unreached);
  const none = (why: string): ProviderLimitVerdict => ({ pause: false, why, seats, unreached, models: [], detail: "", until: null, worked_since: false });
  if (!seats.length) return none(all.length ? `no live seat was reached by the last lift's wake (${unreached.join(", ")})` : "no seat is live");
  const plural = (n: number, one: string, many: string) => (n === 1 ? one : many);
  const going = seats.filter((s) => !s.refused);
  if (going.length) return none(`${going.map((s) => s.agent).join(", ")} ${plural(going.length, "has", "have")} no provider error as the last turn since ${o.since ? new Date(o.since).toISOString() : "the start"}`);
  const passing = seats.filter((s) => !s.limited);
  if (passing.length) {
    return none(
      `every live seat's last turn ended in a provider error, but ${passing.map((s) => s.agent).join(", ")} ${plural(passing.length, "was", "were")} neither told to wait ${P.PROVIDER_LIMIT_LONG_MS / 60_000} minutes or more nor refused again after a prompt`,
    );
  }
  const long = seats.filter((s) => (s.wait_ms ?? 0) >= P.PROVIDER_LIMIT_LONG_MS);
  const until = pauseUntil(seats);
  const models = [...new Set(seats.map((s) => s.model).filter((m): m is string => Boolean(m)))];
  const detail = [...new Set(seats.map((s) => s.reason).filter((r): r is string => Boolean(r)))].join("\n");
  const retried = seats.filter((s) => s.retried && !long.includes(s));
  const why =
    "every live seat's last turn ended in a provider error, and each is limited: " +
    [...long.map((s) => `${s.agent} was told to wait ${Math.round(s.wait_ms! / 60_000)} minutes`), ...(retried.length ? [`${retried.map((s) => s.agent).join(", ")} ${plural(retried.length, "was", "were")} refused again after a prompt`] : [])].join("; ");
  return { pause: true, why, seats, unreached, models, detail, until: until === null ? null : new Date(until).toISOString(), worked_since: seats.some((s) => s.worked_at > o.since) };
}

// --- the trace, read from its end -----------------------------------------------------------

/** The trace's lines from the last to the first, split on newlines before decoding. */
async function* linesBackward(path: string, chunk: number): AsyncGenerator<string> {
  const fh = await open(path, "r").catch(() => null);
  if (!fh) return;
  try {
    let pos = (await fh.stat()).size;
    let carry = Buffer.alloc(0);
    while (pos > 0) {
      const len = Math.min(chunk, pos);
      pos -= len;
      const buf = Buffer.alloc(len);
      await fh.read(buf, 0, len, pos);
      const data = Buffer.concat([buf, carry]);
      let end = data.length;
      for (let i = data.length - 1; i >= 0; i--) {
        if (data[i] !== 0x0a) continue;
        if (end > i + 1) yield data.subarray(i + 1, end).toString("utf8");
        end = i;
      }
      carry = Buffer.from(data.subarray(0, end));
    }
    if (carry.length) yield carry.toString("utf8");
  } finally {
    await fh.close();
  }
}

/**
 * The rows the rule reads for these seats, in trace order: each seat's own,
 * and the prompts and wakes that reached it. Read from the end only as far
 * as needed: it stops at once when a seat's last own row is not a provider
 * error since `since` (unless the last lift's wake did not reach it), or
 * when a seat's start (agent_start) comes before any turn of its own
 * (neither leaves the run to pause); otherwise at the row before each seat's
 * errors in a row, or at its start. A line cut short (one still being
 * written) is passed over. The watchdog's nudges and wakes that the
 * collector did not take are in traces/system-spill.jsonl (scripts/lib/
 * trace.sh): they are read from there too, in their place by time.
 */
export async function readSeatRows(sandbox: string, seats: string[], since: number, o: { chunk?: number } = {}): Promise<TraceRow[]> {
  const want = new Set(seats);
  const seen = new Set<string>();
  const settled = new Set<string>();
  // Since the last lift: the wakes that reached a seat or did not, and any row of its own.
  const woke = new Set<string>();
  const missed = new Set<string>();
  const stirred = new Set<string>();
  const out: TraceRow[] = [];
  const spilled = await spilledPrompts(sandbox, want);
  for (const r of spilled) if (r.tool === "resume_wake" && r.at > since) (r.result?.ok === true ? woke : missed).add(String(r.args?.agent ?? ""));
  for await (const line of linesBackward(join(sandbox, P.EVENTS_REL), o.chunk ?? 256 * 1024)) {
    if (!line.trim()) continue;
    let e: { agent?: string; tool?: string; ts?: string; recv_ts?: string; args?: Record<string, unknown>; result?: Record<string, unknown> };
    try {
      e = JSON.parse(line);
    } catch {
      continue;
    }
    const agent = String(e.agent ?? "");
    const tool = String(e.tool ?? "");
    const about = agent === "system" ? String(e.args?.agent ?? "") : agent;
    if (!want.has(about)) continue;
    const at = Date.parse(e.recv_ts || e.ts || "");
    if (!Number.isFinite(at)) continue;
    out.push({ agent, tool, at, ...(e.args ? { args: e.args } : {}), ...(e.result && typeof e.result === "object" ? { result: e.result } : {}) });
    if (agent === "system") {
      if (tool === "resume_wake" && at > since) (e.result?.ok === true ? woke : missed).add(about);
      continue;
    }
    if (at > since) stirred.add(agent);
    if (tool === "agent_start") {
      // The seat's start: nothing older is its current run of errors, and a
      // seat with no turn of its own since cannot have been refused.
      if (!seen.has(agent)) break;
      settled.add(agent);
    } else if (SEAT_HARNESS_ROWS.has(tool)) {
      continue;
    } else if (!seen.has(agent)) {
      seen.add(agent);
      // Its last own row is not a provider error: nothing to pause.
      if (tool !== "agent_error") break;
      if (at <= since) {
        // Refused before the last lift, and nothing since: not refused now,
        // unless the lift's wake never reached it (seatLimit's unreached).
        if (!missed.has(agent) || woke.has(agent) || stirred.has(agent)) break;
        settled.add(agent);
      }
    } else if (tool !== "agent_error") {
      settled.add(agent);
    }
    if (settled.size === want.size) break;
  }
  const rows = out.reverse();
  for (const r of spilled) {
    let at = rows.length;
    while (at > 0 && rows[at - 1].at > r.at) at -= 1;
    rows.splice(at, 0, r);
  }
  return rows;
}

/** The watchdog's nudges and wakes about these seats that went to the system spill, oldest first. */
async function spilledPrompts(sandbox: string, want: Set<string>): Promise<TraceRow[]> {
  const text = await readFile(join(sandbox, P.SYSTEM_SPILL_REL), "utf8").catch(() => "");
  const rows: TraceRow[] = [];
  for (const line of text.split("\n")) {
    if (!line.trim()) continue;
    let e: { agent?: string; tool?: string; ts?: string; args?: Record<string, unknown>; result?: Record<string, unknown> };
    try {
      e = JSON.parse(line);
    } catch {
      continue;
    }
    if (e.agent !== "system" || (e.tool !== "idle_nudge" && e.tool !== "resume_wake") || !want.has(String(e.args?.agent ?? ""))) continue;
    const at = Date.parse(e.ts ?? "");
    if (!Number.isFinite(at)) continue;
    rows.push({ agent: "system", tool: e.tool, at, ...(e.args ? { args: e.args } : {}), ...(e.result && typeof e.result === "object" ? { result: e.result } : {}) });
  }
  return rows.sort((a, b) => a.at - b.at);
}

/** The seats still in the run: on the team, with no done or dead marker. */
export async function liveSeats(sandbox: string): Promise<string[]> {
  const team = await P.readTeam(sandbox).catch(() => null);
  return (team?.agents ?? []).map((a) => a.id).filter((id) => !existsSync(P.agentDonePath(sandbox, id)) && !existsSync(P.agentDeadPath(sandbox, id)));
}

// --- the watchdog's pass --------------------------------------------------------------------

export type ProviderLimitTick =
  | { action: "none"; why: string; retry_at?: string }
  | { action: "lifted"; pause: P.PauseRecord }
  | {
      action: "paused";
      pause: P.PauseRecord;
      spell: "new" | "continued";
      why: string;
      retry_at: string;
      unreached: string[];
      seats: Array<Pick<SeatLimit, "agent" | "model" | "errors" | "retried"> & { until: string | null }>;
    };

/**
 * One pass, as the idle watchdog makes it every interval: under a pause for
 * the provider's limit, lift it when its try is due; otherwise pause the run
 * when the rule holds. Both under the table lock (pauseRun re-reads the rule
 * there, liftProviderLimit the time and the run's end), so two watchdogs
 * never both act. A new spell is said on the board once; a pause that
 * follows the harness's own try, no seat having worked since, continues the
 * spell before it: not said again, not told again (the notice is claimed per
 * spell), and the try is not charged to the wall clock.
 */
export async function providerLimitTick(sandbox: string, now = Date.now()): Promise<ProviderLimitTick> {
  if ((await P.swarmDoneExists(sandbox)) || existsSync(join(sandbox, P.STOPPED_REL)) || existsSync(join(sandbox, P.ALL_DEAD_REL))) return { action: "none", why: "the run has ended" };
  const budget = await P.readBudget(sandbox).catch(() => null);
  if (!budget) return { action: "none", why: "budget.json does not read" };
  if (budget.paused) {
    if (budget.paused.reason !== "provider_limit") return { action: "none", why: `paused for ${P.pauseReasonWords(budget.paused)}` };
    const lifted = await P.liftProviderLimit(sandbox, now);
    if (lifted) return { action: "lifted", pause: lifted };
    return { action: "none", why: "paused for the model provider's limit", retry_at: new Date(P.providerLimitRetryAt(budget.paused)).toISOString() };
  }
  const live = await liveSeats(sandbox);
  const decide = async (b: P.BudgetRecord) => {
    const lastLift = b.pauses?.at(-1)?.resumed_at;
    const since = lastLift ? Date.parse(lastLift) || 0 : 0;
    return providerLimitVerdict(await readSeatRows(sandbox, live, since), live, { since, now });
  };
  const v = await decide(budget);
  if (!v.pause) return { action: "none", why: v.why };
  const before = budget.pauses?.at(-1);
  const spell = !v.worked_since && before?.reason === "provider_limit" && before.resumed_by === "harness" ? (before.since ?? before.at) : undefined;
  const p = await P.pauseRun(sandbox, "provider_limit", v.detail, now, {
    by: "harness",
    models: v.models,
    ...(v.until ? { until: v.until } : {}),
    ...(spell ? { since: spell } : {}),
    recheck: async (b) => (await decide(b)).pause,
  });
  if (!p.paused) return { action: "none", why: p.already ? "the run is paused already" : "a seat came back before the pause was written" };
  const pause = (await P.readBudget(sandbox)).paused!;
  if (!spell) await P.systemPost(sandbox, { tag: "stop", body: P.providerLimitPost(pause) }).catch(() => undefined);
  return {
    action: "paused",
    pause,
    spell: spell ? "continued" : "new",
    why: v.why,
    retry_at: new Date(P.providerLimitRetryAt(pause)).toISOString(),
    unreached: v.unreached,
    seats: v.seats.map((s) => ({ agent: s.agent, model: s.model, errors: s.errors, retried: s.retried, until: s.until ? new Date(s.until).toISOString() : null })),
  };
}

function opt(args: string[], name: string): string | undefined {
  const i = args.indexOf(name);
  return i >= 0 ? args[i + 1] : undefined;
}

async function main(argv: string[]): Promise<number> {
  const [cmd, arg, ...rest] = argv;
  const emit = (o: unknown) => process.stdout.write(`${JSON.stringify(o)}\n`);
  const at = (name: string): number => {
    const v = opt(rest, name);
    if (v === undefined) return Date.now();
    const t = Date.parse(v);
    if (!Number.isFinite(t)) throw new Error(`${name} takes an ISO time (got ${JSON.stringify(v)})`);
    return t;
  };
  try {
    if (cmd === "tick" && arg) {
      emit(await providerLimitTick(resolve(arg), at("--now")));
      return 0;
    }
    if (cmd === "wait" && arg !== undefined) {
      const from = at("--at");
      const w = parseProviderWait(arg, from);
      emit(w ? { until: new Date(w.until).toISOString(), wait_ms: w.wait_ms, said: w.said } : null);
      return 0;
    }
  } catch (err) {
    emit({ action: "none", why: (err as Error).message });
    return 1;
  }
  process.stderr.write("usage: provider-limit.ts tick <sandbox> [--now ISO] | wait <text> [--at ISO]\n");
  return 2;
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  process.exit(await main(process.argv.slice(2)));
}
