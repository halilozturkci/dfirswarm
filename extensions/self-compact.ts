/**
 * Self-compaction: the agent watches its own context and hands off to itself.
 *
 * What the reference build (disler/self-compact-pi-agent, MIT) does for one
 * interactive Pi, this module does for one swarm agent inside the swarm
 * extension: three thresholds resolved against an effective ceiling the
 * harness owns (`context-ceiling.ts`), a transient guidance message at each
 * level, a lock at the compact line that leaves only `self_compact`, `budget`
 * and `done`, a `self_compact(note_to_self)` tool that saves the note and ends
 * the run, a compaction with the harness's own summary prompt once the agent
 * is idle, and the note returned verbatim under a header of facts the harness
 * reads from files: the agent's name, its live claims, its unread posts, the
 * ledger, the sentinel, its spend.
 *
 * Where it departs from the reference, on purpose:
 * - Pi's own `overflow` and `threshold` compactions are not cancelled. In a
 *   swarm the call that would carry `self_compact` can itself be the one the
 *   provider refuses, and an agent with every compaction cancelled has no
 *   working call left. They run with our prompt, are recorded as fallbacks,
 *   and still deliver a saved note afterwards.
 * - A summary that fails twice falls back to Pi's own summarizer rather than
 *   holding the lock; a compaction that fails past its retries releases the
 *   lock. A locked agent nobody can unlock is a dead agent.
 * - Every crossing, hold, note, start, success and failure is a trace event,
 *   and one `context` row per turn gives the run its context time series.
 *
 * Pure threshold arithmetic and the ceiling table live in
 * `context-ceiling.ts`; this file is the Pi wiring.
 */
import { randomUUID } from "node:crypto";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import type { ExtensionAPI, ExtensionContext, SessionBeforeCompactEvent, SessionEntry } from "@earendil-works/pi-coding-agent";
import { convertToLlm, findCutPoint, serializeConversation, sessionEntryToContextMessages, SettingsManager } from "@earendil-works/pi-coding-agent";
import { Type } from "typebox";
import {
  KEEP_RECENT_TOKENS,
  LEVEL_ORDER,
  levelFor,
  resolveThresholds,
  specsForModel,
  type ResolvedThresholds,
  type SpecLists,
  type UsageLevel,
} from "./context-ceiling.ts";

export const SELF_COMPACT_TOOL = "self_compact";
/** customType of the message that returns the note (sent to the model). */
export const HANDOFF_TYPE = "self-compact-handoff";
/** customType of the transient guidance (never persisted). */
export const GUIDANCE_TYPE = "self-compact-guidance";
/** customType of the state snapshot entries (never sent to the model). */
export const STATE_TYPE = "self-compact-state";
export const NOTE_MAX_CHARS = 24_000;
/** What a locked agent may still call: the hand-off, its own gauge, and the exit. */
export const LOCK_ALLOWED_TOOLS = new Set([SELF_COMPACT_TOOL, "budget", "done"]);
const MAX_AUTO_RETRIES = 3;
const SUMMARY_ATTEMPTS = 2;
const SUMMARY_MAX_TOKENS = 8_192;

/** The events this module writes to the trace; all reserved in protocol.ts. */
export const SELF_COMPACT_EVENTS = [
  "context",
  "compact_notice",
  "compact_warning",
  "compact_forced",
  "compact_hold",
  "compact_note",
  "compact_start",
  "compact_done",
  "compact_failed",
  "compact_config",
] as const;

export const PROMPT_FILES = {
  notice: "compact-notice.md",
  warning: "compact-warning.md",
  forced: "compact-forced.md",
  summary: "compaction-summary.md",
} as const;

export type HandoffStatus = "pending" | "compacting" | "failed" | "ready" | "done";

export type Handoff = {
  id: string;
  note: string;
  status: HandoffStatus;
  attempts: number;
  savedAt: number;
  error?: string;
};

export type PersistedState = {
  version: 1;
  cycle: number;
  locked: boolean;
  handoff?: Handoff;
};

export function emptyState(): PersistedState {
  return { version: 1, cycle: 0, locked: false };
}

/** What the harness knows from files at hand-off time; the header of the returned note. */
export type HandoffFacts = {
  name?: string;
  doing?: string;
  claims: string[];
  unread: Record<string, number>;
  ledgerTotal: number;
  ledgerMine: number;
  sentinel: boolean;
  spentUsd: number;
  capUsd?: number;
};

export type SelfCompactDeps = {
  agentId: () => string;
  /** One trace line; the extension's own `logEvent`, so attribution and the collector are the same. */
  trace: (cwd: string, tool: string, args: Record<string, unknown>, result: unknown) => Promise<void>;
  handoffFacts: (cwd: string, agentId: string) => Promise<HandoffFacts>;
  /** Where the four prompt files live (the repo's `prompts/`). */
  promptsDir: string;
  /** An operator-supplied summary prompt file (SWARM_COMPACT_PROMPT), replacing `compaction-summary.md`. */
  summaryPromptPath?: string;
  /**
   * The model the summary call goes to (SWARM_COMPACT_MODEL, `provider/id`),
   * for a seat whose own model is expensive; the agent's own model when
   * unset or not in Pi's registry, and the trace says which.
   */
  summaryModel?: string;
  /** The three lines as lists: a seat value and per-model overrides each; resolved per seat against `ctx.model`. */
  specs: SpecLists;
  /** True when the kickoff set none of the three; a seat with no matching entry is on the defaults either way. */
  fromDefaults: boolean;
};

/** The model a summary call goes to, and why it is that one. */
export type SummaryModel = {
  model: ExtensionContext["model"];
  /** `provider/id`, or null when the session has no model at all. */
  name: string | null;
  source: "compact-model" | "agent-model";
  /** Set when `--compact-model` named a model Pi does not know; the seat fell back to its own. */
  problem?: string;
};

export type ContextView = {
  tokens: number | null;
  percent: number | null;
  window: number;
  ceiling: number;
  ceiling_reason: string;
  cached_tokens: number;
  level: UsageLevel;
  thresholds: { notice: number; warning: number; compact: number } | null;
  tokens_until_compact: number | null;
  tools_locked: boolean;
  pending_note: { status: HandoffStatus; chars: number } | null;
  cycle: number;
  settings_error: string | null;
};

export type SelfCompactHandle = {
  systemPromptLine: string;
  view(ctx: ExtensionContext): ContextView;
  /** The lock. Called from the extension's own `tool_call` hook after the sentinel check. */
  gate(event: { toolName: string; toolCallId?: string }, ctx: ExtensionContext): { block: true; reason: string; terminate?: boolean } | undefined;
  /** One `context` trace row and the level bookkeeping; called at every turn end. */
  onTurnEnd(ctx: ExtensionContext): Promise<void>;
  /** The per-agent fields the budget fold writes. */
  budgetFields(ctx: ExtensionContext): { context_ceiling: number; context_level: UsageLevel; context_locked: boolean; handoffs: number };
};

/** A minimal view of the session entries the recovery reducer reads (a subset of Pi's SessionEntry). */
type EntryLike = {
  type: string;
  customType?: string;
  data?: unknown;
  details?: unknown;
  message?: { role?: string; usage?: unknown; stopReason?: string };
};

function isState(entry: EntryLike): entry is EntryLike & { data: PersistedState } {
  return entry.type === "custom" && entry.customType === STATE_TYPE && (entry.data as PersistedState | undefined)?.version === 1;
}

/**
 * Rebuild the state from the branch (root to leaf): the latest snapshot wins,
 * then the branch says whether the hand-off already landed or was answered.
 * A swarm agent is never resumed by the harness today; the reducer is here
 * so a Pi restart inside a pane cannot lose a saved note.
 */
export function recoverState(entries: EntryLike[]): { state: PersistedState; journaledUnanswered: boolean; answered: boolean } {
  let state = emptyState();
  for (const entry of entries) if (isState(entry)) state = structuredClone(entry.data);
  const result = { state, journaledUnanswered: false, answered: false };
  const h = state.handoff;
  if (!h) return result;
  const handoffIndex = entries.findIndex(
    (e) => e.type === "custom_message" && e.customType === HANDOFF_TYPE && (e.details as { id?: string } | undefined)?.id === h.id,
  );
  if (handoffIndex !== -1) {
    const answered = entries.slice(handoffIndex + 1).some((e) => e.type === "message" && e.message?.role === "assistant");
    result.answered = answered;
    result.journaledUnanswered = !answered;
    if (h.status !== "done") state.handoff = { ...h, status: "ready" };
    return result;
  }
  if (h.status === "done") return result;
  const landed = entries.some((e) => e.type === "compaction" && (e.details as { handoffId?: string } | undefined)?.handoffId === h.id);
  if (landed || h.status === "ready") state.handoff = { ...h, status: "ready" };
  return result;
}

type UsageLike = { input?: number; output?: number; cacheRead?: number; cacheWrite?: number; totalTokens?: number };

/** Usage of the latest valid assistant message after the latest compaction. */
export function latestAssistantUsage(entries: EntryLike[]): UsageLike | undefined {
  let compactionIndex = -1;
  for (let i = entries.length - 1; i >= 0; i--) {
    if (entries[i]!.type === "compaction") {
      compactionIndex = i;
      break;
    }
  }
  for (let i = entries.length - 1; i > compactionIndex; i--) {
    const entry = entries[i]!;
    if (entry.type !== "message" || entry.message?.role !== "assistant") continue;
    const stop = entry.message.stopReason;
    if (stop === "aborted" || stop === "error") continue;
    const usage = entry.message.usage as UsageLike | undefined;
    if (!usage) continue;
    const total = usage.totalTokens || (usage.input ?? 0) + (usage.output ?? 0) + (usage.cacheRead ?? 0) + (usage.cacheWrite ?? 0);
    if (total > 0) return usage;
  }
  return undefined;
}

/**
 * True when a compaction of this branch would have at least one message to
 * summarize; false when Pi would answer "Nothing to compact" because the
 * whole session still fits inside keepRecentTokens. Locking an agent then
 * would strand it, so the module stays quiet instead.
 */
export function hasCompactionMaterial(entries: SessionEntry[], keepRecentTokens: number): boolean {
  if (entries.length === 0 || entries[entries.length - 1]!.type === "compaction") return false;
  let previous = -1;
  for (let i = entries.length - 1; i >= 0; i--) {
    if (entries[i]!.type === "compaction") {
      previous = i;
      break;
    }
  }
  let boundaryStart = 0;
  if (previous >= 0) {
    const firstKept = entries.findIndex((entry) => entry.id === (entries[previous] as { firstKeptEntryId?: string }).firstKeptEntryId);
    boundaryStart = firstKept >= 0 ? firstKept : previous + 1;
  }
  const cut = findCutPoint(entries, boundaryStart, entries.length, keepRecentTokens);
  const historyEnd = cut.isSplitTurn ? cut.turnStartIndex : cut.firstKeptEntryIndex;
  for (let i = boundaryStart; i < historyEnd; i++) {
    const entry = entries[i]!;
    if (entry.type !== "compaction" && sessionEntryToContextMessages(entry).length > 0) return true;
  }
  if (cut.isSplitTurn) {
    for (let i = cut.turnStartIndex; i < cut.firstKeptEntryIndex; i++) {
      if (sessionEntryToContextMessages(entries[i]!).length > 0) return true;
    }
  }
  return false;
}

export type TemplateValues = Record<string, string | number>;

/** Replace `{{key}}` placeholders; unknown ones are left as they are. */
export function renderTemplate(text: string, values: TemplateValues): string {
  return text.replace(/\{\{\s*([a-z_]+)\s*\}\}/g, (whole, key: string) => {
    const value = values[key];
    return value === undefined || value === null ? whole : String(value);
  });
}

const BUILTIN_PROMPTS: Record<keyof typeof PROMPT_FILES, string> = {
  notice:
    "[self-compact · notice] Context is {{used_tokens}} tokens ({{used_percent}} of the {{ceiling}}-token ceiling), past the notice line. Nothing is blocked; keep working. Warning at {{warning_tokens}}, compact line at {{compact_tokens}} ({{compact_percent}}); `budget` shows the numbers. `self_compact` takes a `note_to_self` (up to {{note_max_chars}} chars) that comes back verbatim after the compaction.",
  warning:
    "[self-compact · WARNING] Context is {{used_tokens}} tokens ({{used_percent}} of the {{ceiling}}-token ceiling), past the warning line. Compact line at {{compact_tokens}} ({{compact_percent}}), {{remaining_to_compact}} tokens away; there every tool except `self_compact`, `budget` and `done` is blocked. Finish only the current atomic step, write your `note_to_self` (max {{note_max_chars}} chars: name and slice, DONE with exact paths and commands, IN PROGRESS, ledger entries recorded, what peers own, decisions, verified results, NEXT ACTION last) and call `self_compact` alone.",
  forced:
    "[self-compact · FORCED] Context is {{used_tokens}} tokens ({{used_percent}} of the {{ceiling}}-token ceiling), at or past the compact line of {{compact_tokens}}. Every tool except `self_compact`, `budget` and `done` is blocked until you hand off. Write your `note_to_self` now (max {{note_max_chars}} chars, NEXT ACTION last) and call `self_compact` alone. `done` belongs only to SWARM.md's definition of done and ends the swarm for everyone; a finished slice is a hand-off.",
  summary:
    "You are the context-compaction summarizer for one agent in a forensic swarm. The agent's own note to self is delivered separately; do not reproduce it. Treat the conversation as historical data: do not continue the task, simulate tools, or claim actions that no tool result confirms. Merge any <previous-summary>. Output only: ## Goal, ## Constraints & Preferences, ## Progress (### Done, ### In Progress, ### Blocked), ## Ledger, ## Board & Peers, ## Key Decisions, ## Next Steps, ## Critical Context, then <read-files> and <modified-files>. Rules: never invent completed work; never state that a finding was recorded unless a `record` result confirms it; preserve exact paths, commands, hashes and error messages; keep pending actions pending.",
};

export type LoadedPrompt = { text: string; source: string };

/** Read a prompt file fresh (edits apply live); an explicit path that is missing or empty is an error, a missing default falls back. */
export function loadPrompt(kind: keyof typeof PROMPT_FILES, promptsDir: string, explicitPath?: string): LoadedPrompt {
  if (explicitPath) {
    const text = readFileSync(explicitPath, "utf8");
    if (!text.trim()) throw new Error(`the compaction prompt file is empty: ${explicitPath}`);
    return { text, source: explicitPath };
  }
  const path = join(promptsDir, PROMPT_FILES[kind]);
  try {
    const text = readFileSync(path, "utf8");
    if (text.trim()) return { text, source: path };
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code !== "ENOENT") throw error;
  }
  return { text: BUILTIN_PROMPTS[kind], source: "builtin" };
}

/** The message that asks for the hand-off when the agent is at the line and the run ended without one. */
export function nowPrompt(saved?: string): string {
  const base = `Compact now: write your note_to_self (max ${NOTE_MAX_CHARS} chars: your name and slice, DONE with exact paths and commands, IN PROGRESS, ledger entries recorded, what peers own, decisions, verified results, exact NEXT ACTION last) and call ${SELF_COMPACT_TOOL} as your only tool call. A finished slice is still a hand-off: done belongs only to SWARM.md's definition of done and ends the swarm for everyone.`;
  if (!saved) return base;
  return `${base}\n\nA note is already saved from a previous attempt. Pass it to ${SELF_COMPACT_TOOL} verbatim instead of inventing a new one. Saved note, verbatim:\n\n${saved}\n\n---\nCall ${SELF_COMPACT_TOOL} now with exactly that note.`;
}

/** The header the harness puts in front of the returned note. */
export function handoffHeader(agentId: string, cycle: number, facts: HandoffFacts, hadNote: boolean, reason: string): string {
  const who = facts.name ? `you are ${agentId} "${facts.name}"${facts.doing ? ` (${facts.doing})` : ""}` : `you are ${agentId}; you have not named yourself yet (call name)`;
  const claims = facts.claims.length ? facts.claims.join(", ") : "none";
  const unreadEntries = Object.entries(facts.unread).filter(([, n]) => n > 0);
  const unread = unreadEntries.length ? `${unreadEntries.map(([thread, n]) => `${n} in ${thread}`).join(", ")}. Call inbox before acting.` : "none.";
  const sentinel = facts.sentinel ? "PRESENT: the swarm is over, call done now" : "absent";
  const spend = facts.capUsd ? `$${facts.spentUsd.toFixed(2)} of the $${facts.capUsd} cap` : `$${facts.spentUsd.toFixed(2)}`;
  const lines = [
    `[self-compact · handoff] cycle ${cycle} · ${who}.`,
    `Your context was just compacted (${reason}). SWARM.md is unchanged; re-read it only if the summary above leaves the goal unclear.`,
    `Live claims: ${claims}.`,
    `Unread posts: ${unread}`,
    `Ledger: ${facts.ledgerTotal} entries, ${facts.ledgerMine} yours. Sentinel: ${sentinel}. Spend: ${spend}.`,
  ];
  // On run 6 all four agents answered this message, a few tool calls later,
  // with a status update to "the user" and ended their turns; three sat idle
  // for ten minutes until the watchdog spoke. The message has to say what
  // it is not.
  lines.push("This message is the harness, not a person: do not answer it with a status or a summary, and do not end your turn. Work on until SWARM.md's definition of done is met; when you are waiting on a peer, call wait and keep it open, because a turn that ends is not waiting and nothing prompts you again.");
  lines.push(hadNote ? "Your note follows verbatim; continue from its NEXT ACTION and never restart work it marks as done:\n---" : "No note was saved before this compaction (it was Pi's own recovery, not a hand-off). Read the summary above, call inbox, then continue.");
  return lines.join("\n");
}

function fmt(n: number): string {
  return n.toLocaleString("en-US");
}

function fmtPct(n: number | null | undefined): string {
  return n === null || n === undefined || !Number.isFinite(n) ? "?%" : `${n.toFixed(1)}%`;
}

function guidanceMessage(text: string) {
  return { role: "custom" as const, customType: GUIDANCE_TYPE, content: text, display: false, timestamp: Date.now() };
}

export function registerSelfCompact(pi: ExtensionAPI, deps: SelfCompactDeps): SelfCompactHandle {
  type Runtime = {
    thresholds?: ResolvedThresholds;
    configError?: string;
    usage: { tokens: number | null; percent: number | null; cachedTokens: number; window: number };
    level: UsageLevel;
    announcedLevel: UsageLevel;
    state: PersistedState;
    /** Bumps on every compaction and session start so per-epoch nudges re-arm. */
    epoch: number;
    compactionInFlight: boolean;
    lastCompactionError?: string;
    /** What the compaction that is running was for; filled by session_before_compact. */
    compactionReason?: string;
    retryTimer?: ReturnType<typeof setTimeout>;
    deliveryTimer?: ReturnType<typeof setTimeout>;
    recoveryTimer?: ReturnType<typeof setTimeout>;
    alive: boolean;
    nudgedEpoch: number;
    configTold: boolean;
    /** Where the summary call goes, decided with the thresholds and said on the config row. */
    summaryModel?: SummaryModel;
  };
  const R: Runtime = {
    usage: { tokens: null, percent: null, cachedTokens: 0, window: 0 },
    level: "unknown",
    announcedLevel: "idle",
    state: emptyState(),
    epoch: 0,
    compactionInFlight: false,
    alive: true,
    nudgedEpoch: -1,
    configTold: false,
  };

  const agentId = () => deps.agentId();
  const inert = (): string | undefined => R.configError;
  const handoff = (): Handoff | undefined => R.state.handoff;
  const activeHandoff = (): Handoff | undefined => {
    const h = R.state.handoff;
    return h && h.status !== "done" ? h : undefined;
  };
  const locked = (): boolean => R.state.locked;

  function save() {
    try {
      pi.appendEntry(STATE_TYPE, structuredClone(R.state));
    } catch {
      // the session may be shutting down; the state is also in memory
    }
  }

  function setLocked(value: boolean) {
    R.state.locked = value;
  }

  function clearTimers() {
    for (const key of ["retryTimer", "deliveryTimer", "recoveryTimer"] as const) {
      if (R[key]) clearTimeout(R[key]);
      R[key] = undefined;
    }
  }

  function deferInEpoch(key: "retryTimer" | "recoveryTimer", delayMs: number, fn: () => void) {
    if (R[key]) clearTimeout(R[key]);
    const epoch = R.epoch;
    R[key] = setTimeout(() => {
      R[key] = undefined;
      if (!R.alive || epoch !== R.epoch) return;
      fn();
    }, delayMs);
  }

  const trace = (cwd: string, tool: string, args: Record<string, unknown>, result: unknown) => deps.trace(cwd, tool, args, result).catch(() => undefined);

  /**
   * The model the summary call goes to: the operator's `--compact-model`
   * when Pi's registry knows it, else the agent's own, and the config row
   * says which and why. A wrong name must not cost the seat its compaction.
   */
  function summaryModelFor(ctx: ExtensionContext): SummaryModel {
    const own = ctx.model;
    const ownName = own ? `${own.provider}/${own.id}` : null;
    const wanted = deps.summaryModel?.trim();
    if (!wanted) return { model: own, name: ownName, source: "agent-model" };
    const slash = wanted.indexOf("/");
    let found: ExtensionContext["model"];
    try {
      found = slash > 0 ? ctx.modelRegistry.find(wanted.slice(0, slash), wanted.slice(slash + 1)) : undefined;
    } catch {
      found = undefined;
    }
    if (found) return { model: found, name: wanted, source: "compact-model" };
    return { model: own, name: ownName, source: "agent-model", problem: `the compaction model ${wanted} is not in Pi's registry; the summary goes to the agent's own model` };
  }

  function resolve(ctx: ExtensionContext) {
    const model = ctx.model ? `${ctx.model.provider}/${ctx.model.id}` : undefined;
    // The three lines this seat runs under: its model's overrides when the
    // operator wrote any, else the seat value, else the default.
    const seat = specsForModel(deps.specs, model);
    const fromDefaults = deps.fromDefaults || seat.fromDefaults;
    const result = resolveThresholds(seat.specs, model, ctx.model?.contextWindow, { fromDefaults, explicit: seat.explicit });
    if (result.ok) {
      R.thresholds = result.thresholds;
      R.configError = undefined;
    } else {
      R.thresholds = undefined;
      R.configError = result.error;
    }
    R.summaryModel = summaryModelFor(ctx);
    if (!R.configTold) {
      R.configTold = true;
      const t = R.thresholds;
      const s = R.summaryModel;
      const summary = { summary_model: s.name, summary_model_source: s.source, ...(s.problem ? { summary_model_problem: s.problem } : {}) };
      void trace(ctx.cwd, "compact_config", { notice_at: seat.specs.noticeAt, warn_at: seat.specs.warnAt, compact_at: seat.specs.compactAt, defaults: fromDefaults, matched: seat.matched, compact_model: deps.summaryModel ?? null }, result.ok && t
        ? { ok: true, model, window: t.declared, ceiling: t.ceiling, ceiling_reason: t.ceilingReason, notice: t.noticeTokens, warning: t.warnTokens, compact: t.compactTokens, cap: t.capTokens, clamped: t.clamped, notes: t.notes, ...summary }
        : { ok: false, model, reason: R.configError, ...summary });
    }
  }

  function snapshotUsage(ctx: ExtensionContext) {
    let usage: { tokens: number | null; contextWindow?: number; percent?: number | null } | undefined;
    try {
      usage = ctx.getContextUsage() as typeof usage;
    } catch {
      usage = undefined;
    }
    const window = usage?.contextWindow ?? ctx.model?.contextWindow ?? 0;
    const tokens = usage?.tokens ?? null;
    const ceiling = R.thresholds?.ceiling ?? window;
    const percent = tokens !== null && ceiling > 0 ? (tokens / ceiling) * 100 : null;
    let cachedTokens = 0;
    if (tokens !== null) {
      try {
        const last = latestAssistantUsage(ctx.sessionManager.getBranch() as unknown as EntryLike[]);
        cachedTokens = Math.min(tokens, last?.cacheRead ?? 0);
      } catch {
        cachedTokens = 0;
      }
    }
    R.usage = { tokens, percent, cachedTokens, window };
    R.level = R.thresholds ? levelFor(tokens, R.thresholds) : "unknown";
  }

  function templateValues(): TemplateValues {
    const t = R.thresholds;
    const u = R.usage;
    const tokens = u.tokens ?? 0;
    return {
      agent_id: agentId(),
      used_tokens: fmt(tokens),
      used_percent: fmtPct(u.percent),
      cached_tokens: fmt(u.cachedTokens),
      context_window: fmt(u.window),
      ceiling: fmt(t?.ceiling ?? u.window),
      notice_tokens: fmt(t?.noticeTokens ?? 0),
      warning_tokens: fmt(t?.warnTokens ?? 0),
      compact_tokens: fmt(t?.compactTokens ?? 0),
      compact_percent: fmtPct(t?.compactPct ?? null),
      remaining_to_compact: fmt(Math.max(0, (t?.compactTokens ?? 0) - tokens)),
      cycle: R.state.cycle,
      note_max_chars: NOTE_MAX_CHARS,
    };
  }

  function keepRecent(ctx: ExtensionContext): number {
    try {
      return SettingsManager.create(ctx.cwd).getCompactionKeepRecentTokens();
    } catch {
      return KEEP_RECENT_TOKENS;
    }
  }

  function compactable(ctx: ExtensionContext): boolean {
    try {
      return hasCompactionMaterial(ctx.sessionManager.getBranch(), keepRecent(ctx));
    } catch {
      return true;
    }
  }

  function renderGuidance(level: UsageLevel): string {
    const kind = level === "notice" ? "notice" : level === "warning" ? "warning" : "forced";
    let text: string;
    try {
      text = loadPrompt(kind, deps.promptsDir).text;
    } catch {
      text = BUILTIN_PROMPTS[kind];
    }
    return renderTemplate(text, templateValues());
  }

  /** Called whenever usage may have changed: records crossings and engages the lock. */
  async function trackLevel(ctx: ExtensionContext): Promise<void> {
    snapshotUsage(ctx);
    if (inert() || !R.thresholds) return;
    const level = R.level;
    if (level === "unknown" || level === "idle") return;
    if (level === "forced" && !locked() && !activeHandoff() && compactable(ctx)) {
      setLocked(true);
      save();
    }
    if (LEVEL_ORDER[level] > LEVEL_ORDER[R.announcedLevel]) {
      R.announcedLevel = level;
      await trace(ctx.cwd, `compact_${level === "notice" ? "notice" : level === "warning" ? "warning" : "forced"}`, { level }, {
        ok: true,
        tokens: R.usage.tokens,
        percent: R.usage.percent === null ? null : Number(R.usage.percent.toFixed(1)),
        ceiling: R.thresholds.ceiling,
        threshold: level === "notice" ? R.thresholds.noticeTokens : level === "warning" ? R.thresholds.warnTokens : R.thresholds.compactTokens,
        cycle: R.state.cycle,
        locked: locked(),
      });
    }
  }

  function guidanceText(ctx: ExtensionContext): string | undefined {
    if (inert() || !R.thresholds || activeHandoff()) return undefined;
    const level = locked() ? "forced" : R.level;
    if (level === "unknown" || level === "idle") return undefined;
    if (!compactable(ctx)) return undefined;
    return renderGuidance(level);
  }

  async function deliverHandoff(ctx: ExtensionContext, reason: string, hadNote: boolean) {
    const h = handoff();
    if (!R.alive) return;
    if (hadNote && (!h || h.status !== "ready")) return;
    if (hadNote && !ctx.isIdle()) {
      if (!R.deliveryTimer) {
        const epoch = R.epoch;
        R.deliveryTimer = setTimeout(() => {
          R.deliveryTimer = undefined;
          if (epoch === R.epoch) void deliverHandoff(ctx, reason, hadNote);
        }, 25);
      }
      return;
    }
    let facts: HandoffFacts;
    try {
      facts = await deps.handoffFacts(ctx.cwd, agentId());
    } catch {
      facts = { claims: [], unread: {}, ledgerTotal: 0, ledgerMine: 0, sentinel: false, spentUsd: 0 };
    }
    const header = handoffHeader(agentId(), R.state.cycle, facts, hadNote, reason);
    const content = hadNote && h ? `${header}\n${h.note}` : header;
    const details = { id: h?.id, cycle: R.state.cycle, note: hadNote ? h?.note : undefined, reason, facts };
    try {
      if (hadNote || ctx.isIdle()) {
        pi.sendMessage({ customType: HANDOFF_TYPE, content, display: true, details }, { triggerTurn: true });
      } else {
        pi.sendMessage({ customType: HANDOFF_TYPE, content, display: true, details }, { triggerTurn: true, deliverAs: "steer" });
      }
    } catch {
      // a dead session cannot take a message; the note is recovered on the next start
    }
  }

  function startCompaction(ctx: ExtensionContext, trigger: string) {
    const h = handoff();
    if (R.compactionInFlight || !h || (h.status !== "pending" && h.status !== "failed")) return;
    R.compactionInFlight = true;
    h.status = "compacting";
    save();
    void trace(ctx.cwd, "compact_start", { trigger }, { ok: true, tokens: R.usage.tokens, note_chars: h.note.length, cycle: R.state.cycle + 1, attempt: h.attempts + 1 });
    ctx.compact({
      onComplete: () => {
        R.compactionInFlight = false;
      },
      onError: () => {
        R.compactionInFlight = false;
      },
    });
  }

  function scheduleRetry(ctx: ExtensionContext) {
    const delay = 2_000 * Math.max(1, handoff()?.attempts ?? 1);
    deferInEpoch("retryTimer", delay, () => {
      if (handoff()?.status === "failed" && ctx.isIdle()) startCompaction(ctx, `auto-retry ${(handoff()?.attempts ?? 0) + 1}`);
    });
  }

  function contextView(ctx: ExtensionContext): ContextView {
    snapshotUsage(ctx);
    const t = R.thresholds;
    const u = R.usage;
    const h = activeHandoff();
    return {
      tokens: u.tokens,
      percent: u.percent === null ? null : Number(u.percent.toFixed(1)),
      window: u.window,
      ceiling: t?.ceiling ?? u.window,
      ceiling_reason: t?.ceilingReason ?? "",
      cached_tokens: u.cachedTokens,
      level: R.level,
      thresholds: t ? { notice: t.noticeTokens, warning: t.warnTokens, compact: t.compactTokens } : null,
      tokens_until_compact: t && u.tokens !== null ? Math.max(0, t.compactTokens - u.tokens) : null,
      tools_locked: locked(),
      pending_note: h ? { status: h.status, chars: h.note.length } : null,
      cycle: R.state.cycle,
      settings_error: inert() ?? null,
    };
  }

  // ----------------------------------------------------------------- the tool

  pi.registerTool({
    name: SELF_COMPACT_TOOL,
    label: "Self Compact",
    description:
      `Hand off to yourself across a context compaction. Provide note_to_self (1 to ${NOTE_MAX_CHARS} characters): what you call yourself and the slice you took, DONE work with exact file paths, commands and observed results, IN PROGRESS state, ledger entries you recorded (kind and seq), what peers own and what you are waiting on, key decisions, verified results marked verified, and the exact NEXT ACTION as the last line. Call it alone in a tool batch. The note is saved, this run ends, the context is compacted once you are idle, and the note is returned verbatim under a header with your live claims, unread posts and ledger totals. At the compact line every other tool except budget and done is blocked until this succeeds.`,
    promptSnippet: "Compact your own context: save a note_to_self, compaction runs when the turn ends, the note comes back verbatim",
    promptGuidelines: [
      `Use ${SELF_COMPACT_TOOL} alone in a tool batch when a [self-compact · …] message asks you to, or at a clean checkpoint when your context is high (budget shows the numbers).`,
      `A ${SELF_COMPACT_TOOL} note_to_self ends with the exact NEXT ACTION and never lists finished work as pending.`,
      `After a [self-compact · handoff] message, continue only the unfinished NEXT ACTION from your note. A finished slice is a post and, when the context is high, a hand-off; done belongs only to SWARM.md's definition of done and ends the swarm for everyone.`,
    ],
    parameters: Type.Object({
      note_to_self: Type.String({ description: `Your hand-off note (1-${NOTE_MAX_CHARS} chars). Ends with the exact NEXT ACTION.` }),
    }),
    async execute(_toolCallId, params, signal, _onUpdate, ctx) {
      const cwd = ctx.cwd;
      const refuse = async (reason: string, extra: Record<string, unknown> = {}) => {
        await trace(cwd, "compact_note", { chars: typeof params.note_to_self === "string" ? params.note_to_self.length : 0 }, { ok: false, reason, ...extra });
        throw new Error(reason);
      };
      if (signal?.aborted) return refuse("self-compaction cancelled before the note was saved.");
      const problem = inert();
      if (problem) return refuse(`self-compaction is off in this session because its settings were rejected: ${problem}`);
      const raw = typeof params.note_to_self === "string" ? params.note_to_self : "";
      if (raw.trim().length === 0) return refuse("note_to_self must not be blank. Write your name and slice, DONE work, IN PROGRESS state, ledger entries, decisions, verified results, and the NEXT ACTION.");
      if (raw.length > NOTE_MAX_CHARS) return refuse(`note_to_self exceeds ${NOTE_MAX_CHARS} characters (${raw.length}). Shorten it and call ${SELF_COMPACT_TOOL} again.`);
      const existing = activeHandoff();
      if (existing && (existing.status === "compacting" || existing.status === "ready")) return refuse("a compaction is already in progress for the saved note; stop and wait for the hand-off.");
      snapshotUsage(ctx);
      if (!compactable(ctx)) {
        const keep = keepRecent(ctx);
        return refuse(`nothing to compact yet: Pi keeps the newest ${fmt(keep)} tokens untouched and this session does not reach past them (context ${R.usage.tokens === null ? "?" : fmt(R.usage.tokens)} tokens, ${fmtPct(R.usage.percent)}). No note was saved and nothing is blocked. Keep working and call ${SELF_COMPACT_TOOL} later.`);
      }
      if (existing && existing.note.trim() !== raw.trim()) {
        return refuse(`a note is already saved (${existing.note.length} chars). Retry ${SELF_COMPACT_TOOL} with that saved note verbatim instead of a new one.`);
      }
      const note = existing ? existing.note : raw;
      R.state.handoff = { id: existing?.id ?? randomUUID(), note, status: "pending", attempts: 0, savedAt: Date.now() };
      R.lastCompactionError = undefined;
      setLocked(true);
      save();
      await trace(cwd, "compact_note", { chars: note.length }, {
        ok: true,
        tokens: R.usage.tokens,
        percent: R.usage.percent === null ? null : Number(R.usage.percent.toFixed(1)),
        level: R.level,
        cycle: R.state.cycle + 1,
        retry: Boolean(existing),
      });
      const at = R.usage.tokens === null ? "unknown usage" : `${fmt(R.usage.tokens)} tokens (${fmtPct(R.usage.percent)}), level ${R.level}`;
      return {
        content: [{ type: "text" as const, text: `Note saved (${note.length} chars) at ${at}. Every other tool is blocked until compaction succeeds. Stop now: compaction runs when this turn ends and your note will be returned verbatim.` }],
        details: { handoffId: R.state.handoff.id, noteChars: note.length, cycle: R.state.cycle + 1, usedTokens: R.usage.tokens, usedPercent: R.usage.percent, level: R.level },
        terminate: true as const,
      };
    },
  });

  // ---------------------------------------------------------------- the hooks

  const recover = async (event: { reason?: string }, ctx: ExtensionContext) => {
    clearTimers();
    R.alive = true;
    R.epoch += 1;
    R.announcedLevel = "idle";
    R.compactionInFlight = false;
    resolve(ctx);
    let recovered: ReturnType<typeof recoverState>;
    try {
      recovered = recoverState(ctx.sessionManager.getBranch() as unknown as EntryLike[]);
    } catch {
      recovered = { state: emptyState(), journaledUnanswered: false, answered: false };
    }
    R.state = recovered.state;
    const h = handoff();
    if (h && recovered.journaledUnanswered) {
      R.state.handoff = { ...h, status: "done" };
      setLocked(false);
      save();
      const cycle = R.state.cycle;
      deferInEpoch("recoveryTimer", 500, () => {
        if (!ctx.isIdle()) return;
        try {
          pi.sendMessage(
            { customType: HANDOFF_TYPE, content: `Continue from your saved note_to_self above (self-compact cycle ${cycle}). Perform only its unfinished NEXT ACTION.`, display: false, details: { id: h.id, cycle, resumed: true } },
            { triggerTurn: true },
          );
        } catch {
          // nothing to do: the session is gone
        }
      });
    } else if (h && h.status === "ready") {
      if (recovered.answered) {
        R.state.handoff = { ...h, status: "done" };
        setLocked(false);
        save();
      } else {
        setLocked(false);
        save();
        void deliverHandoff(ctx, `recovery after ${event.reason ?? "restart"}`, true);
      }
    } else if (h && (h.status === "pending" || h.status === "failed" || h.status === "compacting")) {
      R.state.handoff = { ...h, status: h.status === "compacting" ? "failed" : h.status, attempts: 0, error: h.status === "compacting" ? "compaction was interrupted (session restarted)" : h.error };
      setLocked(true);
      save();
      deferInEpoch("recoveryTimer", 500, () => {
        const current = handoff();
        if (current && (current.status === "pending" || current.status === "failed") && ctx.isIdle()) startCompaction(ctx, `recovery after ${event.reason ?? "restart"}`);
      });
    }
    await trackLevel(ctx);
  };

  pi.on("session_start", recover);
  pi.on("session_tree", async (_event, ctx) => recover({ reason: "tree" }, ctx));

  pi.on("session_shutdown", async () => {
    R.alive = false;
    R.epoch += 1;
    clearTimers();
  });

  pi.on("model_select", async (_event, ctx) => {
    resolve(ctx);
    await trackLevel(ctx);
  });

  pi.on("context", async (event, ctx) => {
    await trackLevel(ctx);
    const messages = event.messages.filter((message) => !(message.role === "custom" && (message as { customType?: string }).customType === GUIDANCE_TYPE));
    const text = guidanceText(ctx);
    if (text) messages.push(guidanceMessage(text));
    return { messages };
  });

  pi.on("message_end", async (event, ctx) => {
    if (event.message.role === "assistant") {
      await trackLevel(ctx);
      return;
    }
    if (event.message.role === "custom" && (event.message as { customType?: string }).customType === HANDOFF_TYPE) {
      const h = handoff();
      const id = ((event.message as { details?: { id?: string } }).details ?? {}).id;
      if (h && h.status === "ready" && h.id === id) {
        R.state.handoff = { ...h, status: "done" };
        setLocked(false);
        save();
      }
    }
  });

  pi.on("agent_end", async (_event, ctx) => {
    await trackLevel(ctx);
    if (inert() || activeHandoff() || R.nudgedEpoch === R.epoch) return;
    if (!locked() && R.level !== "warning" && R.level !== "forced") return;
    if (!compactable(ctx)) return;
    R.nudgedEpoch = R.epoch;
    try {
      pi.sendMessage({ customType: GUIDANCE_TYPE, content: nowPrompt(), display: false }, { triggerTurn: true, deliverAs: "followUp" });
    } catch {
      // the session is ending
    }
  });

  pi.on("agent_settled", async (_event, ctx) => {
    if (!R.alive) return;
    snapshotUsage(ctx);
    if (inert()) return;
    const h = handoff();
    if (!h || !ctx.isIdle()) return;
    if (h.status === "ready") void deliverHandoff(ctx, R.compactionReason ?? "hand-off", true);
    else if (h.status === "pending" || (h.status === "failed" && h.attempts < MAX_AUTO_RETRIES && R.lastCompactionError)) startCompaction(ctx, h.status === "pending" ? "agent idle" : "retry after failure");
  });

  /** Our summary, through the model registry with our prompt; Pi's own summarizer is the fallback. */
  async function generateSummary(event: SessionBeforeCompactEvent, ctx: ExtensionContext, prompt: LoadedPrompt) {
    const chosen = R.summaryModel ?? summaryModelFor(ctx);
    const model = chosen.model;
    if (!model) throw new Error("no model available for the compaction summary");
    const { messagesToSummarize, turnPrefixMessages, previousSummary } = event.preparation;
    const history = messagesToSummarize.length ? serializeConversation(convertToLlm(messagesToSummarize)) : "";
    const prefix = turnPrefixMessages.length ? serializeConversation(convertToLlm(turnPrefixMessages)) : "";
    const maxTokens = Math.min(SUMMARY_MAX_TOKENS, model.maxTokens || SUMMARY_MAX_TOKENS);
    const budgetChars = Math.max(8_000, ((model.contextWindow || 128_000) - maxTokens - 4_000) * 4 - prompt.text.length - 2_000);
    let truncated = false;
    const fit = (text: string, share: number) => {
      const budget = Math.floor(budgetChars * share);
      if (text.length <= budget) return text;
      truncated = true;
      return `[earlier conversation truncated to fit the summary budget]\n${text.slice(-budget)}`;
    };
    const parts = [
      "Summarize the supplied historical data. Do not continue the task, simulate tools, or claim actions without tool-result evidence. Keep pending actions pending.",
      history ? `<conversation>\n${fit(history, prefix ? 0.5 : 0.9)}\n</conversation>` : "",
      prefix ? `<turn-prefix>\n${fit(prefix, history ? 0.4 : 0.9)}\n</turn-prefix>` : "",
      previousSummary ? `<previous-summary>\n${previousSummary}\n</previous-summary>` : "",
      event.customInstructions ? `Additional summarization instructions from the operator: ${event.customInstructions}` : "",
    ].filter(Boolean);
    const response = await ctx.modelRegistry.complete(
      model,
      { systemPrompt: prompt.text, messages: [{ role: "user", content: [{ type: "text", text: parts.join("\n\n") }], timestamp: Date.now() }], tools: [] },
      { maxTokens, signal: event.signal, cacheRetention: "none", sessionId: randomUUID() } as never,
    );
    if (event.signal.aborted || response.stopReason === "aborted") throw new Error("compaction summary cancelled");
    if (response.stopReason === "error") throw new Error(response.errorMessage || "the summary call returned an error");
    const summary = response.content
      .filter((c): c is { type: "text"; text: string } => c.type === "text")
      .map((c) => c.text)
      .join("\n")
      .trim();
    if (!summary) throw new Error("the summary response was empty");
    return { summary, usage: response.usage, truncated, model: chosen.name, modelSource: chosen.source };
  }

  pi.on("session_before_compact", async (event, ctx) => {
    R.compactionReason = event.reason;
    R.lastCompactionError = undefined;
    const h = activeHandoff();
    if (event.reason !== "manual" && !h) {
      // Pi's own threshold or overflow path with no note saved: it runs, with
      // our prompt, and the trace says the fallback was needed.
      setLocked(true);
      save();
    }
    let prompt: LoadedPrompt;
    try {
      prompt = loadPrompt("summary", deps.promptsDir, deps.summaryPromptPath);
    } catch (error) {
      R.lastCompactionError = error instanceof Error ? error.message : String(error);
      await trace(ctx.cwd, "compact_failed", { stage: "prompt" }, { ok: false, reason: R.lastCompactionError, fallback: "pi-summary" });
      return undefined;
    }
    const { fileOps, firstKeptEntryId, tokensBefore } = event.preparation;
    let lastError = "unknown error";
    for (let attempt = 1; attempt <= SUMMARY_ATTEMPTS; attempt++) {
      if (event.signal.aborted) return { cancel: true };
      try {
        const { summary, usage, truncated, model, modelSource } = await generateSummary(event, ctx, prompt);
        return {
          compaction: {
            summary,
            firstKeptEntryId,
            tokensBefore,
            usage,
            details: {
              readFiles: [...fileOps.read],
              modifiedFiles: [...new Set([...fileOps.written, ...fileOps.edited])],
              handoffId: h?.id,
              selfCompact: { cycle: R.state.cycle + (h ? 1 : 0), reason: event.reason, promptSource: prompt.source, noteChars: h?.note.length ?? 0, truncatedInput: truncated, attempt, summaryModel: model, summaryModelSource: modelSource },
            },
          },
        };
      } catch (error) {
        lastError = error instanceof Error ? error.message : String(error);
        if (event.signal.aborted) return { cancel: true };
      }
    }
    R.lastCompactionError = `our summary failed after ${SUMMARY_ATTEMPTS} attempts: ${lastError}`;
    await trace(ctx.cwd, "compact_failed", { stage: "summary", attempts: SUMMARY_ATTEMPTS }, { ok: false, reason: R.lastCompactionError, fallback: "pi-summary" });
    return undefined;
  });

  pi.on("session_compact", async (event, ctx) => {
    R.epoch += 1;
    R.announcedLevel = "idle";
    R.compactionInFlight = false;
    const h = handoff();
    const entry = event.compactionEntry as { tokensBefore?: number; summary?: string; usage?: { totalTokens?: number; cost?: { total?: number } }; details?: { selfCompact?: { summaryModel?: string | null; summaryModelSource?: string } } };
    const summaryModel = entry.details?.selfCompact?.summaryModel ?? null;
    const summaryModelSource = entry.details?.selfCompact?.summaryModelSource ?? (event.fromExtension ? null : "pi-summary");
    const hadNote = Boolean(h && h.status !== "done");
    if (h && h.status !== "done") {
      R.state.cycle += 1;
      R.state.handoff = { ...h, status: "ready", error: undefined };
    }
    setLocked(false);
    save();
    snapshotUsage(ctx);
    await trace(ctx.cwd, "compact_done", { reason: event.reason, via: hadNote ? "self" : "pi" }, {
      ok: true,
      tokens_before: entry.tokensBefore ?? null,
      tokens_after: R.usage.tokens,
      summary_chars: entry.summary?.length ?? 0,
      summary_tokens: entry.usage?.totalTokens ?? null,
      summary_usd: entry.usage?.cost?.total ?? null,
      summary_model: summaryModel,
      summary_model_source: summaryModelSource,
      from_extension: event.fromExtension,
      cycle: R.state.cycle,
      note_chars: hadNote ? h?.note.length ?? 0 : 0,
    });
    void deliverHandoff(ctx, `${event.reason} compaction`, hadNote);
  });

  pi.on("session_compact_failed", async (event, ctx) => {
    R.compactionInFlight = false;
    if (!R.alive) return;
    const h = handoff();
    if (!h || (h.status !== "compacting" && h.status !== "pending")) {
      if (locked() && !activeHandoff()) {
        setLocked(false);
        save();
      }
      await trace(ctx.cwd, "compact_failed", { reason: event.reason, stage: "pi" }, { ok: false, reason: event.errorMessage ?? (event.aborted ? "compaction was cancelled" : "compaction failed"), aborted: event.aborted });
      return;
    }
    const error = R.lastCompactionError ?? event.errorMessage ?? (event.aborted ? "compaction was cancelled" : "compaction failed");
    R.state.handoff = { ...h, status: "failed", attempts: h.attempts + 1, error };
    const current = handoff()!;
    const canRetry = !event.aborted && current.attempts < MAX_AUTO_RETRIES;
    if (canRetry) {
      setLocked(true);
      save();
      await trace(ctx.cwd, "compact_failed", { reason: event.reason, stage: "compaction", attempt: current.attempts }, { ok: false, reason: error, retrying: true });
      scheduleRetry(ctx);
    } else {
      // Past the retries the lock is released: a locked agent nobody can
      // unlock is a dead agent. The note is kept, and the next compaction
      // that lands (Pi's own overflow path, or a later hand-off) delivers it.
      setLocked(false);
      save();
      await trace(ctx.cwd, "compact_failed", { reason: event.reason, stage: "compaction", attempt: current.attempts }, { ok: false, reason: error, retrying: false, lock_released: true });
    }
  });

  // --------------------------------------------------------------- the handle

  const systemPromptLine =
    `\n\nSelf-compaction is on. Your context has a ceiling for this model and three lines under it: a notice, a warning, and the compact line, where every tool except self_compact, budget and done is blocked. When you cross one you receive a transient [self-compact · …] message with the live numbers; budget shows them at any time. At the warning line finish only the current atomic step, then write your note_to_self and call self_compact alone. After a [self-compact · handoff] message, your own note is returned verbatim under a header with your live claims, unread posts and ledger totals: resume its NEXT ACTION without waiting for anyone and never restart work the note marks as done. The hand-off message is the harness, not a person: never answer it with a status and never end your turn on it; when you are waiting on a peer call wait and keep it open. done is not the end of a slice: it ends the swarm for everyone and belongs only to SWARM.md's definition of done.`;

  return {
    systemPromptLine,
    view: contextView,
    gate(event, ctx) {
      const problem = inert();
      if (problem) return undefined;
      if (event.toolName === SELF_COMPACT_TOOL) return undefined;
      // Whole-batch preflight: an ordinary tool before or after self_compact
      // in the same assistant message is blocked too, so the run ends here.
      try {
        const branch = ctx.sessionManager.getBranch();
        for (let i = branch.length - 1; i >= 0; i--) {
          const entry = branch[i]! as { type: string; message?: { role?: string; content?: Array<{ type: string; id?: string; name?: string; arguments?: Record<string, unknown> }> } };
          if (entry.type !== "message" || entry.message?.role !== "assistant") continue;
          const calls = (entry.message.content ?? []).filter((c) => c.type === "toolCall");
          const hasHandoff = calls.some((c) => c.name === SELF_COMPACT_TOOL && typeof c.arguments?.note_to_self === "string" && (c.arguments.note_to_self as string).trim().length > 0 && (c.arguments.note_to_self as string).length <= NOTE_MAX_CHARS);
          if (hasHandoff && calls.some((c) => c.id === event.toolCallId)) {
            return { block: true, terminate: true, reason: `Tool "${event.toolName}" is blocked by self-compact: ${SELF_COMPACT_TOOL} is in this tool batch, so the run must end here. Wait for the hand-off.` };
          }
          break;
        }
      } catch {
        // no branch to inspect: fall through to the lock
      }
      if (LOCK_ALLOWED_TOOLS.has(event.toolName)) return undefined;
      if (!locked()) return undefined;
      const h = handoff();
      const u = R.usage;
      const t = R.thresholds;
      const why =
        h && (h.status === "pending" || h.status === "compacting")
          ? `a ${SELF_COMPACT_TOOL} note is saved and compaction is ${h.status}`
          : h && h.status === "failed"
            ? `the last compaction failed (${h.error ?? "unknown error"}) and the saved note is kept`
            : `context is at ${fmtPct(u.percent)} of the ceiling (${u.tokens === null ? "?" : fmt(u.tokens)} tokens), at or above the compact line of ${t ? fmt(t.compactTokens) : "?"} tokens`;
      void trace(ctx.cwd, "compact_hold", { tool: event.toolName }, { ok: true, tokens: u.tokens, level: R.level, cycle: R.state.cycle, handoff: h?.status ?? "none" });
      return {
        block: true,
        reason: `Tool "${event.toolName}" is blocked by self-compact: ${why}. Every tool except ${SELF_COMPACT_TOOL}, budget and done is blocked until compaction succeeds. Write your note_to_self and call ${SELF_COMPACT_TOOL} now${h && h.status === "failed" ? ", passing the saved note verbatim" : ""}.`,
      };
    },
    async onTurnEnd(ctx) {
      await trackLevel(ctx);
      if (R.usage.tokens === null) return;
      await trace(ctx.cwd, "context", {}, {
        ok: true,
        tokens: R.usage.tokens,
        cached: R.usage.cachedTokens,
        window: R.usage.window,
        ceiling: R.thresholds?.ceiling ?? R.usage.window,
        percent: R.usage.percent === null ? null : Number(R.usage.percent.toFixed(1)),
        level: R.level,
        cycle: R.state.cycle,
        locked: locked(),
      });
    },
    budgetFields(ctx) {
      snapshotUsage(ctx);
      return { context_ceiling: R.thresholds?.ceiling ?? R.usage.window, context_level: R.level, context_locked: locked(), handoffs: R.state.cycle };
    },
  };
}
