/**
 * Pi extension: the swarm's tools and the harness's hooks.
 *
 * Official Pi APIs (https://pi.dev/docs/latest/extensions):
 *   - export default function (pi: ExtensionAPI)
 *   - pi.registerTool(...)
 *   - pi.on("tool_call") returning { block: true, reason }
 *   - execute() returning { terminate: true }
 *   - pi.on("before_agent_start") / session_shutdown
 *   - pi.on("turn_end") + ctx.sessionManager.getEntries() for live Usage
 *   - pi.sendUserMessage(..., { deliverAs: "steer" }) on cap hit
 *
 * Budget numbers match Pi footer / get_session_stats: Usage.cost.total and
 * input+output+cacheRead+cacheWrite (pi-coding-agent usage-totals.js).
 *
 * Everything the protocol does lives in `protocol.ts`; this file registers
 * the tools, wires the hooks and does the reporting. It is loaded by Pi's
 * own extension loader, and type-checked against Pi's own types: the package
 * is a pinned devDependency, so `npm run typecheck` sees this file. The
 * loader test (`tests/pi-load.test.ts`) is what proves it still loads.
 */

import type { ExtensionAPI, ExtensionContext } from "@earendil-works/pi-coding-agent";
import { execFile } from "node:child_process";
import { existsSync } from "node:fs";
import { chmod, readdir, readFile, rm, stat, writeFile } from "node:fs/promises";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { Type, type TSchema } from "typebox";
import { specsFromEnv } from "./context-ceiling.ts";
import { registerSelfCompact, type HandoffFacts, type SelfCompactHandle } from "./self-compact.ts";
import {
  type FinishLineRun,
  leadingCommand,
  isSharedScratch,
  agentDeadPath,
  agentDonePath,
  finishLineVerdict,
  runFinishLine,
  classifyTurnError,
  CAP_STEER,
  TOKEN_CAP_STEER,
  overCap,
  STOP_GRACE_MS,
  appendEvent,
  isBudgetUnreadable,
  reportBudgetUnreadable,
  budgetPressure,
  createContext,
  diffWatchedPaths,
  extractWritePath,
  inboxLogResult,
  keepToolOutputFromFile,
  toolOutputRel,
  type FullOutputRef,
  resolveAgentId,
  shortHash,
  stopNetguardSidecarIfOver,
  summarizeArgs,
  toolText,
  usageFromSessionEntries,
  runForgedTool,
  packSecretsFor,
  redactSecrets,
  healInputs,
  type InputsHeal,
  readInputsManifest,
  verifyInputs,
  INPUTS_DIR,
  agentPressure,
  modelPressure,
  LEDGER_KINDS,
  LEDGER_CONFIDENCE,
  LEDGER_MD,
  TOOLS_DIR,
  TOOL_TIMEOUT_DEFAULT_SECONDS,
  TOOL_TIMEOUT_MAX_SECONDS,
  toolTimeoutSeconds,
  isPeerForgedTool,
  type ForgedToolManifest,
  watchedPathHashes,
  BASH_WATCH_MAX_WORK_FILES,
  BASH_WATCH_MAX_DEPTH,
  WAIT_MAX_SECONDS,
  type BashWriteReport,
  type BudgetRecord,
  type SwarmContext,
  type WatchSnapshot,
  isOwnScratch,
  realPathKey,
  nudgePeerViaBroker,
  postSender,
} from "./protocol.ts";
// The board: protocol.ts on the host, the hub on the other side of a VM's wall (board.ts says why).
import {
  applySessionUsage,
  claimFile,
  clearStopSteer,
  fileDiff,
  guardWrite,
  harnessStop,
  listClaims,
  listFileHistory,
  listTeam,
  markDone,
  markStopSteer,
  postMessage,
  publishFile,
  readBudget,
  readBudgetLive,
  readBudgetStatus,
  readInbox,
  recordFileVersion,
  releaseAllOwned,
  releaseFile,
  restoreFileVersion,
  swarmDoneExists,
  systemPost,
  threadJoin,
  threadOpen,
  waitForSwarmChange,
  forgeTool,
  forgedToolSeal,
  listForgedTools,
  listLedger,
  recordEntry,
  heldBy,
  claimName,
  correctionsAfter,
  nameOf,
  readNames,
  updateToolchainRecord,
  boardSocket,
  openHubLink,
  type HubLink,
  jobSubmit,
  jobStatus,
  catalogRequest,
} from "./board.ts";
import { registerPlaywrightTool, runBrowserCheck } from "./playwright-tool.ts";
import { readToolchainAt, TOOLCHAIN_DIR } from "./toolchain.ts";
import { installChunkedEgress } from "./vm-egress.ts";

type ToolCtx = { cwd: string };

/** What the write probe at session start found in front of inputs/. */
let inputsEnforced: "kernel" | "mode" | "none" = "none";
/** A turn-end sweep of inputs/ is a stat per file; this many seconds apart is plenty for a background write. */
const INPUTS_SWEEP_INTERVAL_MS = 15_000;
let lastInputsSweepAt = 0;
/** How often a pane re-reads what is installed. An install is a rare event. */
const TOOLCHAIN_INTERVAL_MS = 30_000;
let lastToolchainAt = 0;

/** Tools this extension owns. Everything else is a Pi built-in we only trace. */
export const SWARM_TOOLS = new Set([
  "post",
  "inbox",
  "list_team",
  "budget",
  "claim_file",
  "release_file",
  "claims",
  "file_history",
  "file_restore",
  "file_diff",
  "thread_open",
  "thread_join",
  "wait",
  "done",
  "playwright",
  "browser_check",
  "make_tool",
  "tools",
  "tool_loaded",
  "inputs",
  "inputs_guard",
  "inputs_violation",
  "inputs_check",
  "record_violation",
  "record",
  "ledger",
  "sentinel_nudge",
  "forge_hint",
  "agent_cap_steer",
  "agent_cap_stop",
  // They write their own trace row too: without them here each call was
  // on the trace twice, once as itself and once as a generic tool row.
  "name",
  "publish_file",
  "skill",
  "self_compact",
  "job_run",
  "job_status",
  "catalog_request",
]);

/** A bash command run this many times by one agent earns a hint to forge a tool. */
const FORGE_HINT_AT = 8;
/** Command words that are the shell itself, not a tool: no hint for these. */
const FORGE_HINT_SKIP = new Set([
  "echo", "printf", "cat", "ls", "cd", "pwd", "head", "tail", "wc", "mkdir", "cp", "mv", "rm", "ln", "touch", "chmod",
  "test", "true", "false", "export", "set", "unset", "date", "sleep", "tee", "sort", "uniq", "cut", "tr", "find", "xargs",
  "env", "which", "type", "command", "grep", "egrep", "sed", "awk", "diff", "cmp", "file", "stat", "du", "df", "ps", "kill",
  "jq", "sha256sum", "shasum", "md5", "md5sum", "strings", "xxd", "hexdump", "od", "less", "more", "tar", "gzip", "unzip",
  "sh", "bash", "zsh", "for", "while", "if", "read", "exit", "return", "source", "eval", "exec", "time", "timeout", "nohup",
]);
/** Paths whose files are evidence to read, never programs to run. */
const QUARANTINE_PREFIXES = ["work/extracted/", "work/quarantine/"];

/** How often a process re-reads the budget outside `turn_end` to check the caps. */
const STOP_CHECK_INTERVAL_MS = 15_000;

/** Settle time before judging what a bash call changed, so a peer's own
 *  write has a moment to land its history revision and account for itself. */
const BASH_SETTLE_MS = 150;

/*
 * The trace keeps a model's reasoning and a tool's output whole. It kept 240
 * characters of reasoning once, then 2,000, and 2,000 of each result; every
 * limit was defended as "enough to read" and each one cut the part a reviewer
 * wanted — the sentence where an agent changed direction, the `InvalidTag`
 * inside a result that said `ok: true`. The context-growth study behind
 * self-compaction was impossible against a trace that kept 2,000 characters
 * of a 60,000-character result. The Pi session file is not shipped; the
 * trace is the record, so the record is whole. Line size is the collector's
 * problem (64 MB a line), not the record's.
 */

/** How long the growth check waits between its two stats of an unnamed changed file. */
const GROWTH_CHECK_MS = 250;

/** Whether a shell command names a path: the key, its basename or its directory. */
export function commandNamesPath(command: string, pathKey: string): boolean {
  if (!command) return false;
  const parts = pathKey.split("/");
  const base = parts[parts.length - 1] ?? pathKey;
  if (command.includes(pathKey) || (base && command.includes(base))) return true;
  // any directory above the file counts, down to but not including the
  // shared roots `work`, `work/extracted` and `work/quarantine`, which every
  // agent names all the time: `> work/out/$name`, `tsk_recover … work/extracted/mine/`
  const floor = parts[0] === "work" && SHARED_WORK_ROOTS.has(parts[1] ?? "") ? 3 : 2;
  for (let depth = parts.length - 1; depth >= floor; depth -= 1) {
    if (command.includes(parts.slice(0, depth).join("/"))) return true;
  }
  return false;
}

/** Directories under work/ that belong to everyone, not to the agent named after them. */
const SHARED_WORK_ROOTS = new Set(["extracted", "quarantine"]);

/**
 * work/<peer>/… or work/extracted/<peer>/… — a directory named after another
 * agent. With the team's ids known, only those count; without them, any
 * id-shaped name that is not the shared roots does.
 */
export function isPeersScratch(pathKey: string, agentId: string, peers?: ReadonlySet<string>): boolean {
  const m = /^work\/(?:(?:extracted|quarantine)\/)?([a-z][a-z0-9_-]{0,31})\//.exec(pathKey);
  if (!m) return false;
  const owner = m[1];
  if (owner === agentId || SHARED_WORK_ROOTS.has(owner)) return false;
  return peers ? peers.has(owner) : true;
}

export { leadingCommand } from "./protocol.ts";

/**
 * A shell command that took this long and left its whole output under
 * tool-output/ is not worth running again: the second run is told where the
 * first one's output is (SWARM_REPEAT_HINT_MIN_MS overrides, in ms).
 */
export const REPEAT_HINT_MIN_MS = 60_000;

export function repeatHintMinMs(env: NodeJS.ProcessEnv = process.env): number {
  const n = Number(env.SWARM_REPEAT_HINT_MIN_MS);
  return Number.isFinite(n) && n >= 0 && env.SWARM_REPEAT_HINT_MIN_MS !== "" && env.SWARM_REPEAT_HINT_MIN_MS !== undefined ? n : REPEAT_HINT_MIN_MS;
}

/** The same command, whatever its spacing: what the repeat hint compares. Not its meaning. */
export function normalizeShellCommand(command: string): string {
  return command.trim().replace(/\s+/g, " ");
}

/** A long shell call whose whole output was kept: how long it ran and where the output is. */
export type KeptRun = { ms: number; path: string };

/** What the second run of a long command is told, once, with its own output. */
export function repeatHintText(run: KeptRun): string {
  return `Note from the harness: this same command ran for ${Math.round(run.ms / 1000)} s earlier in this session, and its whole output is kept at ${run.path}. Next time, grep or read that file instead of running the command again.`;
}

function ctxFrom(cwd: string, agentId?: string): SwarmContext {
  return createContext(cwd, agentId ?? resolveAgentId());
}

/** What `inbox` and `wait` say when the page bound held posts back: nothing was cut, the rest is one call away. */
function pageNote(remaining: number, pageChars: number): string {
  return `${remaining} more unread post${remaining === 1 ? " was" : "s were"} held back to keep this delivery under ${pageChars.toLocaleString("en-US")} characters of post text; nothing was cut. Call inbox again for ${remaining === 1 ? "it" : "them"} (wait returns ${remaining === 1 ? "it" : "them"} at once too).`;
}

function okResult(payload: unknown, extra: { terminate?: true } = {}) {
  return {
    content: [{ type: "text" as const, text: toolText(payload) }],
    details: payload,
    ...extra,
  };
}

/** How long a VM's seat goes on without its hub: told after the first, stopped after the second. */
export const HUB_LOST_STEER_MS = 60_000;
export const HUB_LOST_STOP_MS = 4 * 60_000;
export type HubLostState = { since: number; told: boolean };

/**
 * One check of the hub from a VM's seat: back, it forgets; lost for a
 * minute, the agent is told once; lost for four, the seat is stopped. A seat
 * with no hub has no record and no brake, and does not go on as if it had.
 */
export function hubLostStep(state: HubLostState, ok: boolean, now: number): { state: HubLostState; steer: boolean; stop: boolean } {
  if (ok) return { state: { since: 0, told: false }, steer: false, stop: false };
  const since = state.since || now;
  const lost = now - since;
  const steer = lost >= HUB_LOST_STEER_MS && !state.told;
  return { state: { since, told: state.told || steer }, steer, stop: lost >= HUB_LOST_STOP_MS };
}

/**
 * Lines this process could put neither on the chain nor in its spill. The
 * tool call goes on — a record that cannot be written must not stop the
 * work — but the loss is not silent: the next line that is written says how
 * many went before it (custody adds them up), and the pane's stderr says so
 * at once. A loss at the very end of a run, with no later line, is what
 * custody's per-sender gaps and a missing last line are left to show.
 */
let traceLinesLost = 0;

/** How many trace lines were lost and not yet told on a later line (tests read it). */
export function traceLinesLostCount(): number {
  return traceLinesLost;
}

export async function logEvent(
  cwd: string,
  agentId: string,
  tool: string,
  args: Record<string, unknown>,
  result: unknown,
  durationMs?: number,
): Promise<void> {
  // Taken, not read: two lines written at once (a tool's call and its
  // result, parallel tools) must not both carry the same count, which
  // custody would add up twice.
  const lost = traceLinesLost;
  traceLinesLost = 0;
  try {
    await appendEvent(cwd, {
      agent: agentId || "unknown",
      tool,
      args: { ...summarizeArgs(args), ...(lost ? { trace_lines_lost_before: lost } : {}) },
      result:
        durationMs === undefined || result === null || typeof result !== "object"
          ? result
          : { ...(result as Record<string, unknown>), duration_ms: durationMs },
    });
  } catch (err) {
    // observability must not break the protocol, and must not go quiet
    // either: this line and the count it carried go to the next one.
    traceLinesLost += lost + 1;
    try {
      process.stderr.write(`dfirswarm: a trace line (${tool}) reached neither the collector nor the spill: ${err instanceof Error ? err.message : String(err)}\n`);
    } catch {
      // no stderr either
    }
  }
}

/** The session's entries, or null when there is no session to read or the read failed. */
function entriesFrom(ctx: { sessionManager?: { getEntries?: () => unknown[] } }): unknown[] | null {
  try {
    const entries = ctx.sessionManager?.getEntries?.();
    return Array.isArray(entries) ? entries : null;
  } catch {
    return null;
  }
}

export default function (pi: ExtensionAPI) {
  // In a VM, before Pi's first model call: a body to a host msb swaps a
  // credential in for goes chunked (vm-egress.ts says why).
  installChunkedEgress();
  let agentId = process.env.AGENT_ID?.trim() ?? "";
  /** Start times per tool call, so every trace row can carry its duration. */
  const toolStarts = new Map<string, number>();
  /** Watched-path snapshot taken before a bash call, keyed by tool call id. */
  const bashSnapshots = new Map<string, { at: number; snapshot: WatchSnapshot; command: string }>();
  /** Limits this process has already steered on; the clock itself is shared. */
  const steeredHere = new Set<string>();
  let capTimer: ReturnType<typeof setInterval> | null = null;
  /** The hub's link, when this agent lives in a microVM; null on the host. */
  let hubLink: HubLink | null = null;
  /** Forged tools: on when the spawner said so (see the block near the end). */
  const forging = process.env.SWARM_TOOL_FORGING === "1";
  /**
   * Self-compaction: on when the spawner said so (the kickoff default). The
   * module is registered at the end of this function, after `done`, so the
   * sentinel check in `tool_call` stays first; `selfCompact` is null until
   * then and whenever the option is off.
   */
  const selfCompactOn = process.env.SWARM_SELF_COMPACT === "1";
  let selfCompact: SelfCompactHandle | null = null;
  /** name → version:sha256 of the tool this session has registered. */
  const loadedTools = new Map<string, string>();
  /** Leading word of each bash command this agent ran, counted for the forge hint. */
  const bashCommandCounts = new Map<string, number>();
  const forgeHinted = new Set<string>();
  /** Long shell calls whose whole output is kept, by command (normalizeShellCommand), and the ones already pointed back. */
  const longRuns = new Map<string, KeptRun>();
  const repeatHinted = new Set<string>();
  /** When this agent was steered for its own cap, if it was. */
  let agentCapSteeredAt: number | null = null;
  /** The watch outgrowing work/ is said once per session, not per shell call. */
  let watchTruncatedTold = false;

  /**
   * The shell-write watch hashes at most BASH_WATCH_MAX_WORK_FILES files
   * under work/. Past that, a write to a file it left out is invisible, and
   * a promise the harness cannot keep has to be said out loud rather than
   * kept quiet: once, on the trace and on the board.
   */
  async function reportWatchTruncated(cwd: string): Promise<void> {
    if (watchTruncatedTold || !agentId) return;
    watchTruncatedTold = true;
    await logEvent(cwd, agentId, "watch_truncated", { max_files: BASH_WATCH_MAX_WORK_FILES, max_depth: BASH_WATCH_MAX_DEPTH }, { ok: true });
    await systemPost(cwd, {
      tag: "ask",
      to: agentId,
      body: `${agentId}: work/ now holds more files than the shell-write watch covers (${BASH_WATCH_MAX_WORK_FILES} files, ${BASH_WATCH_MAX_DEPTH} levels). A shell write to a file outside that set is not detected or snapshotted. Keep bulk extractions in few files under work/${agentId}/, and claim shared files before writing them.`,
    }).catch(() => undefined);
  }

  function steer(message: string): boolean {
    try {
      pi.sendUserMessage(message, { deliverAs: "steer" });
      return true;
    } catch {
      try {
        pi.sendUserMessage(message);
        return true;
      } catch {
        return false;
      }
    }
  }

  /**
   * Fold this agent's Pi usage into the shared budget, then enforce the two
   * caps. An agent that is over is steered to stop itself; if the swarm is
   * still over `STOP_GRACE_MS` after the steer, the harness sets the sentinel
   * itself. The kill switch has to live here, not in the prompt.
   */
  async function refreshBudget(
    cwd: string,
    ctx: {
      sessionManager?: { getEntries?: () => unknown[]; getSessionId?: () => string };
      shutdown?: () => void;
      getContextUsage?: () => { tokens: number | null; contextWindow: number } | undefined;
    },
  ): Promise<void> {
    if (!agentId) return;
    const entries = entriesFrom(ctx);
    if (!entries) {
      // No session to read, or the read threw: that is no report, not a
      // report of zero. Folding it would look like a new session and count
      // the old one twice on the next good read. Enforce from the file as it
      // stands instead.
      const budget = await readBudget(cwd).catch(() => null);
      if (budget) await enforceAllCaps(cwd, budget, ctx);
      return;
    }
    const slice = usageFromSessionEntries(entries);
    try {
      // Keys the fold per session, so a resumed or shared session replaces
      // its own entry rather than being added again (foldSessionSlice).
      const sessionId = ctx.sessionManager?.getSessionId?.();
      if (typeof sessionId === "string" && sessionId) slice.session_id = sessionId;
    } catch {
      // without it the fold falls back to watching for a counter that drops
    }
    try {
      const context = ctx.getContextUsage?.();
      if (context && typeof context.tokens === "number") {
        slice.context_tokens = context.tokens;
        slice.context_window = context.contextWindow;
      }
    } catch {
      // context usage is decoration, never a reason to skip the budget fold
    }
    if (selfCompact) {
      try {
        Object.assign(slice, selfCompact.budgetFields(ctx as unknown as ExtensionContext));
      } catch {
        // the level is decoration too
      }
    }
    let applied: Awaited<ReturnType<typeof applySessionUsage>>;
    try {
      applied = await applySessionUsage(cwd, agentId, slice);
    } catch (err) {
      // budget.json is there and does not parse: the fold was refused and the
      // file and the stop clock are as they were, since a fold over defaults
      // would have dropped every cap. Said once, on the board (the hub's, from
      // a VM). Any other failure is not this one and goes on as before.
      if (!isBudgetUnreadable(err)) throw err;
      await reportBudgetUnreadable(cwd, agentId, err instanceof Error ? err.message : String(err), systemPost);
      return;
    }
    lastStopCheck = Date.now();
    await enforceAllCaps(cwd, applied.budget, ctx);
  }

  async function enforceAllCaps(
    cwd: string,
    budget: BudgetRecord,
    ctx: { shutdown?: () => void },
  ): Promise<void> {
    // In a microVM the swarm's stop is the hub's, from outside: the clock
    // and the sentinel are not this process's to move, and the hub does not
    // take those calls from a VM (scripts/vm-hub.ts). This seat's own cap is
    // still its own to honour.
    if (!boardSocket()) await enforceStops(cwd, budget, ctx);
    await enforceAgentCap(cwd, budget, ctx);
  }

  /**
   * In a microVM the hub is the board, the trace's door and the stop. A hub
   * that cannot be reached leaves this seat with no record and no brake, so
   * it does not go on as if it had one: told once, then stopped, unless the
   * hub is back (the watchdog restarts it).
   */
  let hubLost: HubLostState = { since: 0, told: false };
  async function hubReachable(cwd: string, ctx: { shutdown?: () => void }, ok: boolean): Promise<void> {
    if (!boardSocket()) return;
    const step = hubLostStep(hubLost, ok, Date.now());
    hubLost = step.state;
    if (step.steer) {
      steer("The harness hub cannot be reached from this VM: nothing you post or record lands, and no cap is enforced. Stop tool calls and wait; if it is not back within three minutes this seat is stopped.");
      await logEvent(cwd, agentId, "hub_lost", {}, { since: new Date(hubLost.since).toISOString() }).catch(() => undefined);
    }
    if (step.stop && typeof ctx.shutdown === "function") {
      stoppedByHarness = "hub_unreachable";
      await logEvent(cwd, agentId, "hub_lost_stop", {}, { since: new Date(hubLost.since).toISOString() }).catch(() => undefined);
      ctx.shutdown();
    }
  }

  /**
   * The per-agent cap: one agent over its own budget is steered to finish and,
   * a grace period later, stopped by its own harness — the swarm goes on.
   * The per-model cap takes the same road: when this seat's model has spent
   * its ceiling across every agent running it, this seat is treated as over,
   * and the agents on other models are not.
   */
  async function enforceAgentCap(
    cwd: string,
    budget: BudgetRecord,
    ctx: { shutdown?: () => void },
  ): Promise<void> {
    if (!agentId) return;
    const mine = agentPressure(budget, agentId);
    const model = budget.agents[agentId]?.model;
    const group = modelPressure(budget, model);
    if (!mine.over && !group.over) {
      agentCapSteeredAt = null;
      return;
    }
    // A seat over its own cap is told so; one over its model's cap is told
    // which model and how many seats share the ceiling.
    const byModel = !mine.over;
    const spent = byModel ? group.spent_usd : mine.spent_usd;
    const cap = byModel ? group.cap_usd : mine.cap_usd;
    // A seat's own cap may be in tokens (a subscription team's): said in tokens.
    const byTokens = !byModel && mine.by === "tokens";
    const used = byTokens ? `${mine.tokens.toLocaleString("en-US")} of ${mine.cap_tokens.toLocaleString("en-US")} tokens` : `$${spent.toFixed(2)} of $${cap}`;
    const capArgs = byModel ? { cap_usd: cap, model } : byTokens ? { cap_tokens: mine.cap_tokens } : { cap_usd: cap };
    if (await swarmDoneExists(cwd)) return;
    if (agentCapSteeredAt === null) {
      agentCapSteeredAt = Date.now();
      const delivered = steer(
        byModel
          ? `The spend cap on ${model} is reached ($${spent.toFixed(2)} of $${cap} across its ${group.agents} agent${group.agents === 1 ? "" : "s"}). Post what you have to the board, then call done(reason=agent_cap). Do not start new work.`
          : `Your own cap is reached (${used}). Post what you have to the board, then call done(reason=agent_cap). Do not start new work.`,
      );
      await logEvent(cwd, agentId, "agent_cap_steer", capArgs, { spent_usd: spent, ...(byTokens ? { tokens: mine.tokens } : {}), delivered });
      await systemPost(cwd, {
        tag: "stop",
        to: agentId,
        body: byModel
          ? `${agentId} is on ${model}, whose cap is reached ($${spent.toFixed(2)} of $${cap} across its agents); it will post its findings and stop. The swarm continues.`
          : `${agentId} reached its own cap (${used}); it will post its findings and stop. The swarm continues.`,
      }).catch(() => undefined);
      return;
    }
    if (Date.now() - agentCapSteeredAt < STOP_GRACE_MS) return;
    const result = await markDone(ctxFrom(cwd, agentId), {
      reason: "agent_cap",
      outputFile: byModel ? `(stopped by the per-model cap on ${model})` : "(stopped by the per-agent cap)",
      createSentinel: false,
    }).catch(() => null);
    await logEvent(cwd, agentId, "agent_cap_stop", capArgs, { spent_usd: spent, created_sentinel: result?.created_sentinel ?? false });
    stoppedByHarness = "agent_cap";
    if (typeof ctx.shutdown === "function") ctx.shutdown();
  }

  /** Evidence pulled out of an image is for reading: no execute bit, ever. */
  async function quarantineIfExtracted(cwd: string, pathKey: string): Promise<void> {
    if (process.env.SWARM_QUARANTINE !== "1") return;
    if (!QUARANTINE_PREFIXES.some((p) => pathKey.startsWith(p))) return;
    try {
      const abs = join(cwd, pathKey);
      const info = await stat(abs);
      if (info.isFile() && info.mode & 0o111) await chmod(abs, info.mode & ~0o111);
    } catch {
      // the file may be gone already; the guard is best effort on top of the profile
    }
  }

  /**
   * The same command typed for the eighth time is a tool waiting to be
   * forged. One hint per command per agent, on the board, addressed to them.
   */
  async function forgeHint(cwd: string, command: unknown): Promise<void> {
    if (typeof command !== "string") return;
    const head = leadingCommand(command);
    if (!head || FORGE_HINT_SKIP.has(head)) return;
    const n = (bashCommandCounts.get(head) ?? 0) + 1;
    bashCommandCounts.set(head, n);
    if (n !== FORGE_HINT_AT || forgeHinted.has(head)) return;
    forgeHinted.add(head);
    await logEvent(cwd, agentId, "forge_hint", { command: head }, { runs: n });
    await systemPost(cwd, {
      tag: "ask",
      to: agentId,
      // What the hint used to leave out is why it is worth the minute it
      // costs. On the BelkaCTF #6 run five hints went unanswered for fifteen
      // minutes, and the first tool that did get written was then called 38
      // times — by peers as well as its author, and it outlives the run.
      body: `${agentId}: that is the ${n}th bash call starting with \`${head}\`. A tool forged with make_tool runs it by name with typed arguments, for you and for every peer from their next inbox or wait, and its calls land on the trace under its own name. It is also kept: the operator saves a run's tools with \`swarm.sh tools <id> --save\` and hands them to the next swarm with --tools-from, so the minute you spend on it is not spent again. Consider forging one.`,
    }).catch(() => undefined);
  }

  /**
   * Idle panes never make another tool call, so they never see the sentinel.
   * The agent whose done created it prompts every peer without a marker once
   * through Herdr; their next tool call is then stopped by the sentinel hook.
   */
  async function nudgePeers(cwd: string, why: string): Promise<void> {
    if (!process.env.SWARM_ID) return;
    const team = await listTeam(ctxFrom(cwd, agentId)).catch(() => null);
    if (!team) return;
    const peers: string[] = [];
    for (const a of team.agents) {
      if (a.id === agentId) continue;
      const marked = await stat(agentDonePath(cwd, a.id)).then(() => true).catch(() => false);
      const dead = await stat(agentDeadPath(cwd, a.id)).then(() => true).catch(() => false);
      if (!marked && !dead) peers.push(a.id);
    }
    if (!peers.length) return;
    const reached: string[] = [];
    for (const peer of peers) {
      // Through the broker, which runs outside the pane and owns the words.
      // This was `herdr agent prompt` from in here, and that needed Herdr's
      // control socket — unauthenticated, and a way out of the write guard
      // entirely (scripts/nudge-broker.mjs says how). The guard denies it
      // now; a pane can wake a peer and cannot tell it anything.
      if (await nudgePeerViaBroker(cwd, peer, "swarm_done", agentId)) reached.push(peer);
    }
    await logEvent(cwd, agentId, "sentinel_nudge", { peers, why }, { reached, missed: peers.filter((p) => !reached.includes(p)) });
  }

  /**
   * Act on the caps. Split out from the budget fold because `turn_end` is not
   * frequent enough on its own: an agent that is steered and then sits in a
   * long tool call would never reach the grace deadline.
   */
  async function enforceStops(
    cwd: string,
    budget: BudgetRecord,
    ctx: { shutdown?: () => void },
  ): Promise<void> {
    const pressure = budgetPressure(budget);
    if (!pressure.reason) {
      // Back under both limits (the operator raised the cap): drop the clock
      // so a later breach gets a fresh steer and a fresh grace period.
      if (budget.stop_steer_at) {
        await clearStopSteer(cwd).catch(() => undefined);
        steeredHere.clear();
      }
      return;
    }
    if (await swarmDoneExists(cwd)) return;

    const capHit = pressure.reason === "cap";
    // A free team is braked by tokens; say so, or an agent reads "$0 spent"
    // next to "cap hit" and concludes the harness is confused.
    const byTokens = capHit && overCap(budget).by === "tokens";
    const capLine = byTokens
      ? `Token cap reached: ${budget.tokens.toLocaleString("en-US")} of ${Number(budget.cap_tokens).toLocaleString("en-US")} tokens.`
      : `Spend cap reached: $${budget.spent_usd} of $${budget.cap_usd}.`;
    const message = capHit
      ? (byTokens ? TOKEN_CAP_STEER : CAP_STEER)
      : `Swarm wall clock hit (${pressure.elapsed_minutes} of ${budget.wall_clock_minutes} minutes). Call done with reason cannot_complete and stop. Do not start new work.`;

    // One clock for the whole swarm, so every agent measures the grace period
    // from the same instant and only one of them announces it.
    const marker = await markStopSteer(cwd, pressure.reason);
    if (!steeredHere.has(pressure.reason)) {
      steeredHere.add(pressure.reason);
      const delivered = steer(message);
      await logEvent(
        cwd,
        agentId,
        capHit ? "cap_steer" : "wall_steer",
        { hard_kill: budget.hard_kill },
        { reason: "cannot_complete", delivered },
      );
      if (marker.claimed) {
        await systemPost(cwd, {
          tag: "stop",
          body: capHit
            ? `${capLine} Finish what is in hand, then call done(reason=cannot_complete).`
            : `Wall clock reached: ${pressure.elapsed_minutes} of ${budget.wall_clock_minutes} minutes. Finish what is in hand, then call done(reason=cannot_complete).`,
        }).catch(() => undefined);
      }
      if ((budget.hard_kill || process.env.SWARM_HARD_KILL === "1") && typeof ctx.shutdown === "function") {
        stoppedByHarness = "hard_kill";
        ctx.shutdown();
      }
    }

    if (Date.now() - Date.parse(marker.at) < STOP_GRACE_MS) return;
    const stop = await harnessStop(
      cwd,
      pressure.reason,
      capHit
        ? (byTokens
            ? `Token cap ${Number(budget.cap_tokens).toLocaleString("en-US")} passed (${budget.tokens.toLocaleString("en-US")}) and agents did not stop within the grace period.`
            : `Spend cap $${budget.cap_usd} passed ($${budget.spent_usd}) and agents did not stop within the grace period.`)
        : `Wall clock ${budget.wall_clock_minutes} minutes passed and agents did not stop within the grace period.`,
      { verify: true },
    );
    if (stop.created) {
      await logEvent(cwd, agentId, "harness_stop", { reason: pressure.reason }, { created_sentinel: true });
      await systemPost(cwd, {
        tag: "stop",
        body: `Harness wrote done/SWARM_DONE (reason ${pressure.reason}). Call done and stop.`,
      }).catch(() => undefined);
      await nudgePeers(cwd, `harness stop, ${pressure.reason}`).catch(() => undefined);
    }
  }

  /**
   * Cheap cap check between turns. Reads budget.json at most this often per
   * process, so a long tool call still reaches the grace deadline without
   * every tool result paying for a file read.
   */
  let lastStopCheck = 0;
  async function maybeEnforceStops(cwd: string, ctx: { shutdown?: () => void }): Promise<void> {
    if (!agentId) return;
    if (Date.now() - lastStopCheck < STOP_CHECK_INTERVAL_MS) return;
    lastStopCheck = Date.now();
    const budget = await readBudgetLive(cwd).catch(() => null);
    await hubReachable(cwd, ctx, budget !== null);
    if (budget) await enforceAllCaps(cwd, budget, ctx).catch(() => undefined);
  }

  /**
   * `turn_end` and `tool_result` are both blocked while a long shell command
   * runs, so neither can be relied on to notice that the grace period expired.
   * A timer can.
   */
  function watchCaps(ctx: { cwd: string; shutdown?: () => void }): void {
    if (capTimer) return;
    capTimer = setInterval(() => {
      void (async () => {
        const budget = await readBudgetLive(ctx.cwd).catch(() => null);
        await hubReachable(ctx.cwd, ctx, budget !== null);
        if (budget) await enforceAllCaps(ctx.cwd, budget, ctx).catch(() => undefined);
      })();
    }, STOP_CHECK_INTERVAL_MS);
    capTimer.unref?.();
  }

  pi.on("session_start", async (_event, ctx) => {
    if (!agentId) {
      try {
        agentId = resolveAgentId();
      } catch {
        agentId = "";
      }
    }
    if (agentId && ctx.ui?.setStatus) {
      ctx.ui.setStatus("swarm", `swarm:${agentId}`);
    }
    await logEvent(ctx.cwd, agentId, "agent_start", {}, { ok: true });
    await logInputsGuard(ctx.cwd);
    watchCaps(ctx);
    // In a microVM the harness can neither type into this pane nor read its
    // screen — the pane runs `msb exec`, and Herdr sees only that. The hub
    // keeps a link instead: its prompts arrive here as user messages, and
    // this agent's working/idle state goes back up it (board.ts).
    const hubSocket = boardSocket();
    if (hubSocket && !hubLink) {
      const cwd = ctx.cwd;
      hubLink = openHubLink(hubSocket, (message) => {
        try {
          pi.sendUserMessage(message.text, { deliverAs: message.deliver ?? "followUp" });
        } catch {
          steer(message.text);
        }
        void logEvent(cwd, agentId, "hub_prompt", { kind: message.kind ?? "prompt" }, { ok: true });
      });
    }
  });

  pi.on("agent_start", async () => {
    hubLink?.state("working");
  });

  pi.on("agent_end", async () => {
    hubLink?.state("idle");
  });

  /**
   * What protects inputs/ in this pane, measured rather than assumed: a write
   * probe under inputs/ fails with EPERM under a kernel guard, with EACCES on
   * permission bits alone, and succeeds when nothing is in the way (the probe
   * is removed again). The trace line is what the console shows.
   */
  async function logInputsGuard(cwd: string): Promise<void> {
    const manifest = await readInputsManifest(cwd);
    if (!manifest) return;
    const probe = join(cwd, INPUTS_DIR, ".fsguard-probe");
    let enforced: "kernel" | "mode" | "none" = "none";
    try {
      await writeFile(probe, "probe\n");
      await rm(probe, { force: true }).catch(() => undefined);
    } catch (err) {
      const code = (err as NodeJS.ErrnoException).code;
      // EPERM is the seatbelt/mount-namespace refusal; EROFS is what a
      // read-only mount answers (a container's `:ro` bind, a read-only disk
      // image attached on the host). Both are the kernel saying no.
      //
      // EACCES is ambiguous and the answer depends on what is guarding this
      // pane. Landlock refuses with EACCES, not EPERM (measured on 6.8), so
      // under a Landlock-backed guard EACCES is the kernel; anywhere else it
      // is the permission bits, which the file's owner can take back. Reading
      // the mode the pane was actually started under is what makes the
      // difference legible — a pane that has no kernel guard cannot claim one
      // here, because the variable is set by the guard itself.
      const guardMode = process.env.SWARM_FSGUARD || "none";
      const landlockBacked = guardMode === "landlock" || guardMode === "linux";
      enforced = code === "EPERM" || code === "EROFS" || (landlockBacked && code === "EACCES")
        ? "kernel"
        : code === "EACCES"
          ? "mode"
          : "none";
    }
    inputsEnforced = enforced;
    await logEvent(cwd, agentId, "inputs_guard", { files: manifest.files.length }, {
      ok: true,
      mode: process.env.SWARM_FSGUARD || "none",
      enforced,
      guard: manifest.guard,
      enforce: manifest.enforce,
    });
    if (manifest.guard !== "none" && enforced !== "kernel") {
      // The kickoff set a kernel guard up and this pane did not get it (a
      // bash pane, a pre-set SWARM_FSGUARD, a Herdr that changed how it
      // starts pi). A trace line alone is easy to miss; the board is not.
      await systemPost(cwd, {
        tag: "veto",
        body: `INPUTS GUARD: pane ${agentId} is running without the kernel guard the kickoff set up (${manifest.guard}); measured: ${enforced}. In this pane inputs/ is protected by the tool guard and detect + heal only.`,
      }).catch(() => undefined);
    }
  }

  /**
   * Put inputs/ right if anything changed outside a tool call the harness
   * could bracket — a backgrounded shell, a process a forged tool left
   * behind. Runs at every turn end and before done; cheap (a stat per file)
   * when nothing changed, loud when something did.
   */
  async function sweepInputs(cwd: string, via: string): Promise<void> {
    lastInputsSweepAt = Date.now();
    const check = await verifyInputs(cwd).catch(() => null);
    if (!check || check.ok) return;
    const content = [...check.modified, ...check.missing, ...check.added];
    const held = (await readInputsManifest(cwd).catch(() => null))?.held;
    if (boardSocket() || held === "bind") {
      // Evidence held in place (a VM's read-only mount, or --inputs-bind):
      // there is no pristine copy to heal from, and nothing in this pane
      // wrote it. What the check sees changed is a change on the host, and
      // it is said as that — once per path — for the host's custody to
      // confirm or not.
      const fresh = content.filter((p) => {
        const last = metadataReportedAt.get(p) ?? 0;
        if (Date.now() - last < METADATA_QUIET_MS) return false;
        metadataReportedAt.set(p, Date.now());
        return true;
      });
      for (const path of fresh) {
        await logEvent(cwd, agentId, "inputs_violation", { tool: via, path }, { blocked: false, detected: true, kind: "content", via, healed: "none", held: held ?? "bind" });
      }
      if (fresh.length) {
        await systemPost(cwd, {
          tag: "veto",
          body: `INPUTS CHANGED: ${fresh.join(", ")} no longer match the manifest, seen from ${agentId}'s ${boardSocket() ? "VM" : "pane"}. The evidence is held in place, read-only to every agent, so this is a change on the host or in the source, not in any pane; there is no pristine copy to restore. Stop relying on those files and say so in the report; the host's custody check at stop is the verdict.`,
        }).catch(() => undefined);
      }
      return;
    }
    const healed = await healInputs(cwd, [...content, ...check.metadata]);
    const contentSet = new Set(content);
    for (const heal of healed) {
      const kind = contentSet.has(heal.path) ? "content" : "metadata";
      await logEvent(cwd, agentId, "inputs_violation", { tool: via, path: heal.path }, {
        blocked: false,
        detected: true,
        kind,
        via,
        healed: heal.action,
        ...(heal.error ? { error: heal.error } : {}),
      });
    }
    const say = (paths: InputsHeal[]) => paths.map((h) => `${h.path} (${h.action})`).join(", ");
    const contentHeals = healed.filter((h) => contentSet.has(h.path));
    if (contentHeals.length) {
      await systemPost(cwd, {
        tag: "veto",
        body: `INPUTS VIOLATION: the bytes of ${contentHeals.length === 1 ? "a file" : "files"} under inputs/ changed between tool calls in ${agentId}'s pane. Healed from the pristine copy: ${say(contentHeals)}. Never write under inputs/.`,
      }).catch(() => undefined);
    }
    // Metadata drift is the write bit coming back, not the evidence moving.
    // It is worth saying once per path; saying it on every sweep is how one
    // archived run put 374 identical vetoes on a board about two files whose
    // sha256 never changed.
    const metaHeals = healed.filter((h) => !contentSet.has(h.path));
    // On an attached image the device refuses every write, and macOS still
    // lets `chmod` report success against it (measured) — so a mode that
    // drifts there is a VFS artefact, not a risk, and there is no pristine
    // copy to put it back from. Record it, do not put it on the board.
    const attached = (await readInputsManifest(cwd).catch(() => null))?.guard === "image";
    const fresh = attached ? [] : metaHeals.filter((h) => {
      const last = metadataReportedAt.get(h.path) ?? 0;
      if (Date.now() - last < METADATA_QUIET_MS) return false;
      metadataReportedAt.set(h.path, Date.now());
      return true;
    });
    if (fresh.length) {
      const stuck = fresh.filter((h) => h.action === "failed");
      await systemPost(cwd, {
        tag: "hold",
        body:
          `INPUTS METADATA: the bytes under inputs/ are unchanged, but how ${fresh.length === 1 ? "a file is" : "files are"} held drifted (the write bit or a second hard link) in ${agentId}'s pane: ${say(fresh)}. ` +
          (stuck.length
            ? `The harness could not put ${stuck.length === 1 ? "it" : "them"} back — that needs the operator. `
            : "") +
          `This is not a change to the evidence; the integrity check still matches.`,
      }).catch(() => undefined);
    }
  }

  /**
   * Write down what this run has installed, from the packages' own metadata.
   *
   * Only runs where there is a toolchain to read, so a swarm without
   * `--allow-install` pays one failed `readdir` per turn. A package that
   * appears gets a trace line naming it with its version and the sha256 of
   * its own RECORD; the full inventory lives in `toolchain.json`, which is a
   * protected path.
   */
  async function snapshotToolchain(cwd: string): Promise<void> {
    if (process.env.SWARM_ALLOW_INSTALL !== "1") return;
    if (Date.now() - lastToolchainAt < TOOLCHAIN_INTERVAL_MS) return;
    lastToolchainAt = Date.now();
    try {
      // In a VM the prefix is the seat's own disk, which the host cannot
      // read: the inventory is taken here and sent to the hub.
      const { fresh } = boardSocket() && process.env.SWARM_TOOLCHAIN
        ? await updateToolchainRecord(cwd, { agent: agentId, inventory: await readToolchainAt(process.env.SWARM_TOOLCHAIN) })
        : await updateToolchainRecord(cwd);
      for (const pkg of fresh) {
        await logEvent(cwd, agentId, "toolchain", { name: pkg.name, version: pkg.version }, {
          ok: true,
          installer: pkg.installer,
          record_sha256: pkg.record_sha256,
          ...(pkg.source ? { source: pkg.source } : {}),
        });
      }
      if (fresh.length) {
        await systemPost(cwd, {
          tag: "result",
          body: `TOOLCHAIN: ${fresh.map((p) => `\`${p.name} ${p.version}\``).join(", ")} installed into ${TOOLCHAIN_DIR}/ by ${agentId}. Recorded in \`toolchain.json\` with the sha256 of each package's own RECORD; the report's custody section prints it.`,
        }).catch(() => undefined);
      }
    } catch {
      // an inventory that cannot be read must not end a turn
    }
  }

  pi.on("turn_end", async (_event, ctx) => {
    await snapshotToolchain(ctx.cwd);
    // Rate-limited: a 30-agent run with a large input set would otherwise
    // pay a tree walk on every turn of every agent. `done` sweeps regardless.
    if (Date.now() - lastInputsSweepAt < INPUTS_SWEEP_INTERVAL_MS) return;
    await sweepInputs(ctx.cwd, "sweep");
  });

  pi.on("before_agent_start", async (event, ctx) => {
    // Everything this handler adds — the id, the stop rule, the read-only
    // inputs, the naming ask — is lost if it throws, and Pi carries on with a
    // prompt that says none of it. That happened once and cost a whole run:
    // the agents never learned that inputs/ was read-only or that `done` ends
    // the swarm, and nothing failed. Now a failure is on the trace and on the
    // board, where the operator and the peers can see it.
    try {
      return await buildSystemPrompt(event, ctx);
    } catch (err) {
      const cwd = event.systemPromptOptions?.cwd ?? ctx.cwd;
      const reason = err instanceof Error ? err.message : String(err);
      await logEvent(cwd, agentId, "extension_error", { where: "before_agent_start" }, { ok: false, reason }).catch(() => undefined);
      await systemPost(cwd, {
        tag: "veto",
        body: `HARNESS FAULT: the extension could not build ${agentId}'s system prompt (${reason}). This agent is running without the harness's own instructions — the id, the stop rule, the read-only inputs and the naming ask. Tell the operator; do not treat the contract as optional.`,
      }).catch(() => undefined);
      return undefined;
    }
  });

  async function buildSystemPrompt(
    event: { systemPrompt: string; systemPromptOptions?: { cwd?: string } },
    ctx: { cwd: string },
  ): Promise<{ systemPrompt: string } | undefined> {
    const cwd = event.systemPromptOptions?.cwd ?? ctx.cwd;
    const idLine = agentId
      ? `Your assigned id is ${agentId}. Use it on every post and claim.`
      : "AGENT_ID is unset. Refuse to claim or post until the spawner sets it.";
    // Independent reads of the sandbox: issue them together.
    const [done, status, mine, inputs, onDisk] = await Promise.all([
      swarmDoneExists(cwd),
      readBudgetStatus(ctxFrom(cwd, agentId || "agent00")).catch(() => null),
      agentId ? nameOf(cwd, agentId).catch(() => undefined) : undefined,
      readInputsManifest(cwd),
      forging ? listForgedTools(cwd).catch(() => [] as ForgedToolManifest[]) : ([] as ForgedToolManifest[]),
    ]);
    const capLine =
      status?.over_budget
        ? `\n\nSwarm spend cap hit (spent_usd=${status.budget.spent_usd} cap_usd=${status.budget.cap_usd}). Call done(reason=cannot_complete) now.`
        : "";
    const stop = done
      ? `\n\n${idLine}\n\ndone/SWARM_DONE exists. Call done(reason, output_file) now and stop. Do not start new work.`
      : `\n\n${idLine}\n\nIf done/SWARM_DONE exists on this turn, call done and stop.`;
    let nameLine = "";
    if (agentId) {
      if (mine) {
        nameLine = `\n\nYou call yourself "${mine}". Change it with name() whenever what you are doing changes.`;
      } else {
        nameLine =
          "\n\nNobody has given you a job. Read the goal, see what your peers have taken, decide what you are going to do, and call name(name, doing) to say what to call you and what you are taking on. The board is where that is agreed.";
      }
    }
    let inputsLine = "";
    if (inputs) {
      const kb = Math.max(1, Math.round(inputs.bytes / 1024));
      const consequence = inputsEnforced === "kernel" ? "refused by the kernel" : "refused, or detected and undone";
      inputsLine =
        `\n\nRead-only inputs: ${inputs.files.length} file(s), ${kb} KB under inputs/ (from ${inputs.source || "the operator"}). ` +
        `Read them with read, grep or bash as much as you like. Never write, delete, move or chmod anything under inputs/: every such write is ${consequence} and announced on the board. ` +
        `Put every result in work/ (claim first); copy an input there if you need a version you can change. Call \`inputs\` to list them.`;
    }
    let forgeLine = "";
    if (forging) {
      const have = onDisk.length ? ` Forged so far: ${onDisk.map((m) => `${m.name} (by ${m.by}, v${m.version})`).join(", ")}.` : " Nothing has been forged yet.";
      forgeLine =
        "\n\nTool forging is on for this swarm. If the goal needs a tool nobody has — a parser, a checker, a converter — write it once with make_tool (python3, node or bash; the arguments arrive as one JSON object on stdin; print the result to stdout) and it becomes a real tool for every agent after their next inbox or wait. Call `tools` first to see what peers have forged. A forged tool runs in this directory with the same limits as bash; keep it small and free of network calls." +
        have;
    }
    // Static, so the prompt-cache prefix stays the same from one call to the next.
    const compactLine = selfCompact?.systemPromptLine ?? "";
    return { systemPrompt: `${event.systemPrompt}${stop}${capLine}${nameLine}${inputsLine}${forgeLine}${compactLine}` };
  }

  pi.on("turn_end", async (_event, ctx) => {
    // A tool call that is blocked, or cancelled before it runs, never reaches
    // tool_result, so its bookkeeping would sit in these maps for the life of
    // the process.
    const stale = Date.now() - 10 * 60_000;
    for (const [id, entry] of bashSnapshots) if (entry.at < stale) bashSnapshots.delete(id);
    for (const [id, startedAt] of toolStarts) if (startedAt < stale) toolStarts.delete(id);
    // The context row first, so the budget fold that follows carries the
    // level this turn ended at rather than the one before it.
    if (selfCompact) await selfCompact.onTurnEnd(ctx).catch(() => undefined);
    await refreshBudget(ctx.cwd, ctx);
    await reportProviderError(ctx);
  });

  /**
   * The finish line, run the way the console and the report run it: the
   * operator's checks from the registry, by scripts/await-done.sh. Null when
   * the runner itself could not answer; the verdict then proceeds unchecked.
   */
  /** The provider error this session has already reported, so it says it once. */
  let providerErrorTold = "";
  /** Set when the harness itself stops this agent, so the abort that follows is not blamed on the provider. */
  let stoppedByHarness: string | null = null;

  /**
   * The caps, before each model call. Spend is folded in at the end of a
   * turn and the stops were acted on at the next tool result or timer tick,
   * so a seat past its grace period, or one whose swarm the sentinel ended,
   * could still make the call it was about to. Here the caps are taken just
   * before the call (a first breach is steered as ever, and its grace period
   * runs), and a seat that is to stop is stopped before the call goes out:
   * the turn is aborted and the session shut down, with the same outcome as
   * the stop it replaces (its done file, its trace line) and a
   * `budget_precall_stop` line saying it was taken here.
   *
   * On the host this is the brake. In a microVM this hook runs in the guest,
   * under the agent's own root, and is advisory like the rest of the
   * extension: the hub's cap stop (scripts/vm-hub.ts, seatBackstop) and its
   * wall clock are the brakes the host holds.
   */
  let precallStopped = false;
  pi.on("context", async (_event, ctx) => {
    if (!agentId || precallStopped) return;
    // A VM whose hub is down has no budget or sentinel to read; the lost-hub
    // steer and stop (hubReachable) handle it, and a call must not wait out
    // two timeouts first.
    if (boardSocket() && hubLost.since) return;
    const cwd = ctx.cwd;
    // The short deadline: a dead link is replaced, not waited on for two minutes before every model call.
    const budget = await readBudgetLive(cwd).catch(() => null);
    if (budget) await enforceAllCaps(cwd, budget, ctx).catch(() => undefined);
    const sentinel = !stoppedByHarness && (await swarmDoneExists(cwd).catch(() => false));
    if (!stoppedByHarness && !sentinel) return;
    precallStopped = true;
    if (sentinel) {
      // As the tool-call hook does once the sentinel stands: this seat's
      // done file, its leases released, and the process ended.
      const result = await markDone(ctxFrom(cwd, agentId), { reason: "sentinel_present", outputFile: "(stopped after the sentinel)" }).catch(() => null);
      await logEvent(cwd, agentId, "agent_stop", { reason: "sentinel_present" }, { ok: true, via: "precall", created_sentinel: result?.created_sentinel ?? false }).catch(() => undefined);
      stoppedByHarness = "sentinel_present";
    }
    await logEvent(cwd, agentId, "budget_precall_stop", { reason: stoppedByHarness }, { ok: true, brake: boardSocket() ? "advisory (in the VM; the hub holds the brake)" : "host" }).catch(() => undefined);
    ctx.abort();
    ctx.shutdown();
  });

  /**
   * A turn that ends in a provider error ends the agent, and used to end it in
   * silence. On the BelkaCTF #6 run both DeepSeek agents stopped six seconds
   * apart on `402 Insufficient Balance`; the console counted them among the
   * working for the rest of the hour, the board said nothing, and the idle
   * watchdog spent its three nudges on retries that could only hit the same
   * 402. The error is the provider's own words — the agent cannot fix it and
   * neither can a peer, so it goes where the operator will see it.
   */
  async function reportProviderError(ctx: { cwd: string; sessionManager?: { getEntries?: () => unknown[] } }): Promise<void> {
    if (!agentId) return;
    const entries = entriesFrom(ctx) ?? [];
    let last: Record<string, unknown> | undefined;
    for (let i = entries.length - 1; i >= 0; i--) {
      const entry = entries[i] as Record<string, unknown> | undefined;
      const message = entry?.message as Record<string, unknown> | undefined;
      if (message && message.role === "assistant") { last = message; break; }
    }
    if (!last || last.stopReason !== "error") return;
    // Whole: a provider's error text is the evidence of why a turn died.
    const reason = String(last.errorMessage ?? "") || "the provider returned an error with no message";
    const model = [last.provider, last.model].filter(Boolean).join("/") || "its model";
    // The harness stopping this agent aborts its turn, and Pi files that abort as an
    // error. The stop is already in the trace under its own name; nothing to report.
    if (classifyTurnError(reason, stoppedByHarness, await swarmDoneExists(ctx.cwd)) === "harness") return;
    if (providerErrorTold === reason) return;
    providerErrorTold = reason;
    await logEvent(ctx.cwd, agentId, "agent_error", { model }, { ok: false, reason }).catch(() => undefined);
    await systemPost(ctx.cwd, {
      tag: "veto",
      body: `PROVIDER ERROR: ${agentId}'s turn on ${model} ended with: ${reason}. Nothing this agent or a peer does will change that — it is the provider answering, not the harness. Whatever ${agentId} had taken on is free; read the board, and if the work matters to the finish line, take it.`,
    }).catch(() => undefined);
  }

  /**
   * The closing line of an agent's trace: `session end` with what that agent
   * spent, which is the only per-agent total a reader gets without opening
   * budget.json.
   */
  async function logStop(cwd: string, via: string, reason?: string): Promise<void> {
    const slice = await readBudget(cwd)
      .then((budget) => budget.agents[agentId])
      .catch(() => undefined);
    await logEvent(cwd, agentId, "agent_stop", reason ? { reason } : {}, {
      ok: true,
      via,
      tokens: slice?.tokens ?? 0,
      spent_usd: slice?.spent_usd ?? 0,
      calls: slice?.calls ?? 0,
    });
  }

  pi.on("session_shutdown", async (_event, ctx) => {
    if (capTimer) {
      clearInterval(capTimer);
      capTimer = null;
    }
    if (agentId) {
      try {
        await refreshBudget(ctx.cwd, ctx);
        await releaseAllOwned(ctxFrom(ctx.cwd, agentId));
      } catch {
        // best-effort reap
      }
      await logStop(ctx.cwd, "shutdown");
      // The last agent out ends the egress proxy this swarm was given. A VM
      // has none: its pid file would name a process on the host.
      if (!boardSocket()) await stopNetguardSidecarIfOver(ctx.cwd).catch(() => false);
    }
    hubLink?.state("idle", "session ended");
    hubLink?.close();
    hubLink = null;
  });

  // Layer B: harness blocks edit/write without a live claim.
  pi.on("tool_call", async (event, ctx) => {
    const callId = (event as { toolCallId?: string }).toolCallId;
    if (callId) toolStarts.set(callId, Date.now());

    // Once the sentinel exists the run is over by definition, and the only
    // tool left to call is `done`. An agent that keeps going anyway — a model
    // that ignores the steer, or a `wait` loop that now returns instantly
    // because the sentinel is what it was waiting for — would burn a model
    // call per turn for as long as the pane lives. A live probe did exactly
    // that: 2.9k calls in thirty seconds after the harness stopped the swarm.
    // So the harness finishes the session on the agent's behalf: its .done
    // file, its leases released, and the process shut down.
    if (agentId && event.toolName !== "done" && (await swarmDoneExists(ctx.cwd))) {
      const result = await markDone(ctxFrom(ctx.cwd, agentId), {
        reason: "sentinel_present",
        outputFile: "(stopped after the sentinel)",
      }).catch(() => null);
      await logEvent(ctx.cwd, agentId, "agent_stop", { reason: "sentinel_present" }, {
        ok: true,
        via: "sentinel",
        tool: event.toolName,
        created_sentinel: result?.created_sentinel ?? false,
      });
      // Blocking alone is not enough: the block reason goes back to the model
      // as a tool result and a model that will not stop simply calls again —
      // a live probe reached 3k calls that way. `abort()` cancels the turn in
      // flight, so nothing is fed back; `shutdown()` then ends the process.
      // Order matters: a graceful shutdown queues behind the active stream.
      stoppedByHarness = "sentinel_present";
      ctx.abort();
      ctx.shutdown();
      return { block: true, reason: "done/SWARM_DONE exists: this session is over. The harness has recorded your exit." };
    }

    // The self-compaction lock: at the compact line, or while a note waits
    // for its compaction, everything but self_compact, budget and done is
    // refused with the reason. After the sentinel, before anything else.
    if (selfCompact) {
      const held = selfCompact.gate({ toolName: event.toolName, toolCallId: callId }, ctx);
      if (held) return held;
    }

    // `bash` can write any path and no hook can stop it mid-command, so take
    // a hash of everything worth noticing and compare after it runs.
    if (event.toolName === "bash" || event.toolName === "powershell") {
      if (callId) {
        try {
          const command = (event as { input?: { command?: unknown } }).input?.command;
          const snapshot = await watchedPathHashes(ctx.cwd, agentId);
          bashSnapshots.set(callId, { at: Date.now(), snapshot, command: typeof command === "string" ? command : "" });
          if (snapshot.truncated) await reportWatchTruncated(ctx.cwd);
        } catch {
          // a missed snapshot must not block the command
        }
      }
      if (forging && agentId) await forgeHint(ctx.cwd, (event as { input?: { command?: unknown } }).input?.command);
      return;
    }

    if (event.toolName !== "edit" && event.toolName !== "write") return;
    if (!agentId) {
      await logEvent(ctx.cwd, "unknown", "claim_violation", { tool: event.toolName }, {
        blocked: true,
        reason: "AGENT_ID unset",
      });
      return { block: true, reason: "claim violation: AGENT_ID unset" };
    }
    const path = extractWritePath(event.input as Record<string, unknown>);
    if (!path) {
      await logEvent(ctx.cwd, agentId, "claim_violation", { tool: event.toolName }, {
        blocked: true,
        reason: "edit/write missing path",
      });
      return { block: true, reason: "claim violation: edit/write missing path" };
    }
    if (boardSocket()) {
      // In a VM the shared part of work/ is read-only: a deliverable is put
      // there through publish_file. Said before the write fails with EROFS.
      const key = await realPathKey(ctx.cwd, path).catch(() => "");
      if (key.startsWith("work/") && !isOwnScratch(key, agentId) && !isSharedScratch(key)) {
        const reason = `${key} is in the shared part of work/, which is read-only in your VM. Write it under work/${agentId}/ and call publish_file(path, to: "${key}"); it is claimed for you and recorded.`;
        await logEvent(ctx.cwd, agentId, "publish_needed", { tool: event.toolName, path: key }, { blocked: true }).catch(() => undefined);
        return { block: true, reason };
      }
    }
    const guard = await guardWrite(ctxFrom(ctx.cwd, agentId), path);
    if (guard.ok && !guard.refreshed && isOwnScratch(guard.path, agentId)) {
      // The guard took the lease for the agent's own scratch directory; say so
      // on the trace the way a shell write's implicit claim is said.
      await logEvent(ctx.cwd, agentId, "claim_file", { path: guard.path, reason: "own scratch", implicit: true }, { ok: true, implicit: true, via: event.toolName });
    }
    if (!guard.ok && guard.inputs) {
      // A refused write to an input is its own kind of event: nothing to
      // restore, nobody to wait for, and the console counts it with the
      // healed shell writes under the inputs it belongs to.
      await logEvent(ctx.cwd, agentId, "inputs_violation", { tool: event.toolName, path: guard.path ?? path }, {
        blocked: true,
        detected: false,
        via: event.toolName,
        reason: guard.reason,
      });
      await systemPost(ctx.cwd, {
        tag: "veto",
        body: `BLOCKED: ${agentId} tried to ${event.toolName} \`${guard.path ?? path}\`, which is a read-only input. The file is unchanged. Copy it into work/ if you need a version you can change.`,
      }).catch(() => undefined);
      return { block: true, reason: guard.reason };
    }
    if (!guard.ok) {
      await logEvent(ctx.cwd, agentId, "claim_violation", { tool: event.toolName, path: guard.path ?? path }, {
        blocked: true,
        reason: guard.reason,
        owner: guard.owner,
        ...(guard.protected ? { protected: true } : {}),
      });
      // Peers only learn what the harness enforced if it says so on the board,
      // and the remedy differs: a held path frees up, a harness-owned one never
      // does. Telling an agent to "claim it" would send it round a loop.
      const why = guard.protected
        ? ", which the harness owns and nobody can claim"
        : guard.owner
          ? ` while ${guard.owner} holds the claim`
          : " without holding a claim";
      await systemPost(ctx.cwd, {
        tag: "veto",
        body: `BLOCKED: ${agentId} tried to ${event.toolName} \`${guard.path ?? path}\`${why}. The file is unchanged.`,
      }).catch(() => undefined);
      return { block: true, reason: guard.reason };
    }
    try {
      await recordFileVersion(ctx.cwd, path, agentId);
    } catch {
      // history must not block a legal write
    }
    return undefined;
  });

  /**
   * A change seen across this shell call is this agent's only when the
   * evidence says so. A peer's long-running shell job — `strings` over a
   * pagefile into its own work/<id>/ — grows a file for minutes, and every
   * bash call that overlaps it would otherwise be blamed for it (the mystery
   * case: one file, four agents reported in thirty seconds). A change under a
   * peer's scratch directory that the command never names is the peer's; a
   * change the command never names that is still growing when this call
   * ends is someone else's job in flight; what is left — named, or stable
   * and not under a peer's directory — is ours, including a script's own
   * output files.
   */
  async function attributeToThisCall(cwd: string, reports: BashWriteReport[], command: string): Promise<BashWriteReport[]> {
    const kept: BashWriteReport[] = [];
    for (const report of reports) {
      if (report.inputs || report.legitimate || commandNamesPath(command, report.path)) {
        kept.push(report);
        continue;
      }
      // A rewritten append-only record is never the harness's own doing: the
      // harness only ever appends to the ledger and the trace. Whoever shortened
      // one or changed its opening bytes did it from a shell, named or not, and
      // it is still growing by definition — so both of the tests below would
      // wrongly drop it.
      if (report.rewritten) {
        kept.push(report);
        continue;
      }
      // A harness file that changed without the command naming it is the
      // harness's own doing during this call: a peer's done writing the
      // sentinel, a peer's make_tool, the reaper. Inputs stay reported and
      // healed whatever named them.
      if (report.protected) continue;
      if (isPeersScratch(report.path, agentId, await teamIds(cwd))) continue;
      // A file that is gone when the call ends, unnamed by the command, was a
      // peer's move or rename; a file still growing is a peer's job in flight.
      const abs = join(cwd, report.path);
      if (!(await stat(abs).then(() => true).catch(() => false))) continue;
      if (await stillGrowing(abs)) continue;
      kept.push(report);
    }
    return kept;
  }

  /** The team's agent ids, read once; a team that cannot be read means "any id-shaped name". */
  let teamIdsCache: Set<string> | undefined;
  async function teamIds(cwd: string): Promise<Set<string> | undefined> {
    if (teamIdsCache) return teamIdsCache;
    const team = await listTeam(ctxFrom(cwd, agentId)).catch(() => null);
    if (!team) return undefined;
    teamIdsCache = new Set(team.agents.map((a) => a.id));
    return teamIdsCache;
  }

  /** Two stats a moment apart: a file another process is still writing moves between them. */
  async function stillGrowing(abs: string): Promise<boolean> {
    try {
      const a = await stat(abs);
      await new Promise((r) => setTimeout(r, GROWTH_CHECK_MS));
      const b = await stat(abs);
      return a.size !== b.size || a.mtimeMs !== b.mtimeMs;
    } catch {
      return false;
    }
  }

  /**
   * Report what a bash command changed under someone else's claim. The write
   * is not blocked (a shell command can touch anything, and guessing from the
   * command text both misses and false-positives); the change is snapshotted,
   * named on the board, and the decision is left to the claim's owner.
   */
  /**
   * Paths reported without a revision to point at, and when. A change the
   * harness could not snapshot is still a change worth naming once; naming it
   * on every call afterwards is noise the swarm pays to read.
   */
  /** `done` says "there are newer corrections" once; the second call is the agent's answer. */
  let doneRefusedOnce = false;
  const unrecordableReportedAt = new Map<string, number>();
  const UNRECORDABLE_QUIET_MS = 60_000;
  /** Metadata drift under inputs/, said once per path per quiet window. */
  const metadataReportedAt = new Map<string, number>();
  const METADATA_QUIET_MS = 10 * 60_000;
  /**
   * A CLAIM VIOLATION post per path per quiet window. Every write is still a
   * `claim_violation` row on the trace; what is held is the board post, which
   * every peer reads on its next `wait` or `inbox`. On the Linux run s3096 a
   * shell loop that appended to a peer's file produced 566 of them in
   * fourteen minutes, and two `wait` results of 578 posts each: a quarter of
   * a working context spent reading the same sentence. The next post for
   * the path says how many the window held.
   */
  const claimViolationPostedAt = new Map<string, number>();
  const claimViolationsHeld = new Map<string, number>();
  const CLAIM_VIOLATION_QUIET_MS = 60_000;

  async function reportBashWrites(cwd: string, reports: BashWriteReport[], via = "bash", before?: WatchSnapshot): Promise<void> {
    for (const report of reports) {
      // A path whose change could not be snapshotted has no revision to point
      // at, so the next call sees the same difference and reports it again:
      // the Azure run announced SRUDB.dat and Amcache.hve twice inside one
      // second. Say it once, then stay quiet about that path for a while.
      if (!report.inputs && !report.recoverable && !report.legitimate) {
        const last = unrecordableReportedAt.get(report.path) ?? 0;
        if (Date.now() - last < UNRECORDABLE_QUIET_MS) continue;
        unrecordableReportedAt.set(report.path, Date.now());
      }
      if (report.rewritten) {
        // The ledger and the trace are what the case rests on, and the harness
        // only ever appends to them. A shorter file, or one whose opening bytes
        // changed, was rewritten by a shell. There is no pristine copy to heal
        // from here, so the only honest thing is to say it happened, loudly and
        // to everyone.
        await logEvent(
          cwd,
          agentId,
          "record_violation",
          { tool: via, path: report.path },
          { blocked: false, detected: true, via, rewritten: true },
        );
        await systemPost(cwd, {
          tag: "veto",
          body: `RECORD REWRITTEN: ${agentId}'s ${via} call did not append to \`${report.path}\` — it shortened the file or changed bytes already written. That file is the record this case rests on and the harness only ever adds to it. Nothing can restore it. Say on the board what the command was, and never write to ledger/ or traces/ from a shell; use \`record\` to add a finding.`,
        }).catch(() => undefined);
        continue;
      }
      if (report.inputs) {
        // Inputs are never legitimately written: put the file back from the
        // pristine copy (or remove what was added) and say so.
        const [heal] = await healInputs(cwd, [report.path]);
        const action = heal?.action ?? "failed";
        await logEvent(
          cwd,
          agentId,
          "inputs_violation",
          { tool: via, path: report.path },
          { blocked: false, detected: true, via, healed: action, ...(heal?.error ? { error: heal.error } : {}) },
        );
        // Only a copied run has a pristine copy: evidence held in place, from an
        // image or in a VM has none to heal from, and saying one exists
        // would send the operator looking for it.
        const hasPristine = existsSync(join(cwd, ".inputs-pristine"));
        const outcome =
          action === "restored"
            ? "It was restored from the pristine copy."
            : action === "removed"
              ? "The new file was removed again."
              : hasPristine
                ? `It could NOT be healed (${heal?.error ?? "unknown error"}); the operator has the pristine copy under .inputs-pristine/.`
                : `It could NOT be healed: this run holds its evidence in place, with no pristine copy to restore from (${heal?.error ?? "no copy"}). The change stands; the host's custody check at stop names it.`;
        await systemPost(cwd, {
          tag: "veto",
          body: `INPUTS VIOLATION: ${agentId}'s ${via} call changed \`${report.path}\`, which is a read-only input. ${outcome} Never write under inputs/; copy the file into work/ if you need a version you can change.`,
        }).catch(() => undefined);
        continue;
      }
      // A peer's make_tool landing during this shell call looks like a shell
      // write under tools/: the manifest names its author and hashes its
      // script, so a forge that checks out is the harness's own write.
      if (report.protected && (await isPeerForgedTool(cwd, report.path, agentId, before))) continue;
      // The shared install area and the scratch dir are nobody's work product:
      // pip writes hundreds of files under work/.toolchain/ and a tool keeps
      // its cache there, and two agents installing at once are not in
      // conflict over the case. On run sb36f that was 442 "violations" over
      // pytz's zoneinfo. What was installed is still inventoried from
      // toolchain.json by the toolchain watch; the claim ledger stays out.
      if (isSharedScratch(report.path)) continue;
      // Snapshot first: the announcement promises the change is undoable.
      const version = await recordFileVersion(cwd, report.path, agentId).catch(() => null);
      await quarantineIfExtracted(cwd, report.path);
      // The writer's own directories need no lease: no peer may claim or
      // write there (peerHoleOf refuses it), so a claim protects nothing. On
      // the sixth CTF round one ileapp run in an agent's own directory was
      // 507 of 644 claim_file lines on the trace, each a lock file too.
      if (isOwnScratch(report.path, agentId)) continue;
      if (!report.legitimate && !report.protected && !report.owner) {
        // Nobody holds it: the shell writer gets the lease it did not ask for.
        // From here on a peer writing the same file is a real conflict, and
        // this file is that agent's to release — the protocol, not a notice.
        const implicit = await claimFile(ctxFrom(cwd, agentId), report.path, { reason: `${via} write`, implicit: true }).catch(() => null);
        if (implicit && implicit.ok) {
          await logEvent(cwd, agentId, "claim_file", { path: report.path, reason: `${via} write`, implicit: true }, {
            ok: true,
            implicit: true,
            via,
            expires_at: implicit.expires_at,
            ...(version ? { rev: version.rev, sha256: shortHash(version.sha256) } : {}),
          });
          continue;
        }
        // The lease was not ours to take: a peer claimed it in the meantime
        // (a real conflict, reported with that owner), or the path is gone
        // or unclaimable, which is nobody's violation.
        const holder = await heldBy(ctxFrom(cwd, agentId), report.path).catch(() => null);
        if (!holder || holder.owner === agentId) continue;
        report.owner = holder.owner;
        report.owner_reason = holder.reason;
      }
      if (report.legitimate) {
        if (version) {
          await logEvent(cwd, agentId, "file_history", { path: report.path, rev: version.rev, via: "bash" }, {
            ok: true,
            bytes: version.bytes,
            sha256: shortHash(version.sha256),
          });
        }
        continue;
      }
      const held = report.owner && report.owner !== agentId
        ? ` while ${report.owner} holds a live claim on it ("${report.owner_reason ?? ""}")`
        : report.protected
          ? " — a harness-owned path"
          : " without holding a claim on it";
      await logEvent(
        cwd,
        agentId,
        "claim_violation",
        { tool: via, path: report.path },
        {
          blocked: false,
          detected: true,
          via,
          owner: report.owner,
          protected: report.protected,
          rev: version?.rev ?? null,
          reason: `${via} write to ${report.path}${held}`,
        },
      );
      const recovery = report.recoverable
        ? `The previous revision is in file_history and can be put back with file_restore.`
        : `There is no earlier revision of this path to restore.`;
      const lastPosted = claimViolationPostedAt.get(report.path) ?? 0;
      if (Date.now() - lastPosted < CLAIM_VIOLATION_QUIET_MS) {
        claimViolationsHeld.set(report.path, (claimViolationsHeld.get(report.path) ?? 0) + 1);
        continue;
      }
      const repeats = claimViolationsHeld.get(report.path) ?? 0;
      claimViolationsHeld.delete(report.path);
      claimViolationPostedAt.set(report.path, Date.now());
      await systemPost(cwd, {
        tag: "veto",
        body: `CLAIM VIOLATION: ${agentId}'s ${via} call modified \`${report.path}\`${held}.${
          version ? ` The result was snapshotted as rev ${version.rev} (${shortHash(version.sha256)}).` : ""
        } ${recovery}${repeats ? ` (${repeats} more write${repeats === 1 ? "" : "s"} to this path since the last notice, each on the trace as claim_violation.)` : ""}`,
      }).catch(() => undefined);
    }
  }

  /**
   * What the call came back with, clipped.
   *
   * The trace recorded that a tool ran and whether it errored, and nothing
   * else: `{ok: true}`. So a reviewer could see that `icat` ran and not what
   * it produced, and on BelkaCTF #6 twenty-seven of twenty-eight forged
   * unlock calls returned `ok: true, exit_code: 0` with `InvalidTag` inside
   * the payload — twenty-seven successes to anyone reading the trace, and
   * twenty-seven failures to anyone reading the output. The full text stays
   * in the Pi session file; the opening belongs in the record that ships.
   */
  function resultPreview(event: unknown): Record<string, unknown> {
    const e = event as Record<string, unknown>;
    let text = "";
    for (const key of ["output", "content", "result", "text"]) {
      const value = e[key];
      if (typeof value === "string" && value) {
        text = value;
        break;
      }
      if (Array.isArray(value)) {
        const joined = value
          .map((block) => (block && typeof block === "object" ? String((block as { text?: unknown }).text ?? "") : String(block ?? "")))
          .filter(Boolean)
          .join("\n");
        if (joined) {
          text = joined;
          break;
        }
      }
      if (value && typeof value === "object") {
        try {
          const json = JSON.stringify(value);
          if (json && json !== "{}") {
            text = json;
            break;
          }
        } catch {
          // not serialisable; try the next key
        }
      }
    }
    if (!text) return {};
    // Whole. `output_chars` stays beside it so a reader can size a result
    // without measuring it, and so archived rows that carried a clipped
    // opening under the same key keep reading the same way.
    return { output: text, output_chars: text.length };
  }

  /**
   * What Pi's own tools say about the part the model did not see. `read`,
   * `grep`, `find` and `ls` show a slice of something that stays on disk,
   * and the trace records the numbers; `bash` spills its whole output to
   * the host's temp directory past 50 KB, and that file is moved into the
   * sandbox under tool-output/ so the record holds it and the model's
   * trailer names a path inside the run.
   */
  type PiTruncation = { truncated?: boolean; truncatedBy?: string | null; totalLines?: number; totalBytes?: number; outputLines?: number; outputBytes?: number };
  function viewOf(details: { truncation?: PiTruncation } | undefined): Record<string, unknown> | undefined {
    const t = details?.truncation;
    if (!t || !t.truncated) return undefined;
    return { truncated: true, by: t.truncatedBy ?? null, total_lines: t.totalLines ?? null, shown_lines: t.outputLines ?? null, total_bytes: t.totalBytes ?? null, shown_bytes: t.outputBytes ?? null };
  }

  pi.on("tool_result", async (event, ctx) => {
    const name = (event as { toolName?: string }).toolName ?? "";
    const callId = (event as { toolCallId?: string }).toolCallId;
    const startedAt = callId ? toolStarts.get(callId) : undefined;
    const durationMs = startedAt === undefined ? undefined : Date.now() - startedAt;
    if (callId) toolStarts.delete(callId);
    const isError = Boolean((event as { isError?: boolean }).isError);
    const input = (event as { input?: Record<string, unknown> }).input;
    const details = (event as { details?: { truncation?: PiTruncation; fullOutputPath?: string } }).details;

    let fullOutput: FullOutputRef | undefined;
    let fullOutputError: string | undefined;
    let content = (event as unknown as { content?: Array<Record<string, unknown>> }).content;
    let contentChanged = false;
    const hostSpill = details?.fullOutputPath;
    if ((name === "bash" || name === "powershell") && hostSpill && agentId) {
      try {
        fullOutput = await keepToolOutputFromFile(ctx.cwd, toolOutputRel(agentId, name, "out"), hostSpill);
        // The pane's TMPDIR is work/.tmp inside the sandbox, so Pi's spill
        // file was an agent write to the watcher: on run 6 one such file
        // became a claim violation against a peer. The record is under
        // tool-output/ now; the copy Pi left is redundant and goes.
        await rm(hostSpill, { force: true }).catch(() => undefined);
        if (Array.isArray(content)) {
          content = content.map((block) =>
            block && block.type === "text" && typeof block.text === "string" && block.text.includes(hostSpill)
              ? { ...block, text: block.text.split(hostSpill).join(fullOutput!.path) }
              : block,
          );
          contentChanged = true;
        }
      } catch (error) {
        fullOutputError = error instanceof Error ? error.message : String(error);
      }
    }
    // The same long command a second time: told, once, where the first
    // run's whole output is, with this run's result. Generic: any command
    // whose earlier run was long and whose output was kept whole.
    if ((name === "bash" || name === "powershell") && agentId && typeof input?.command === "string") {
      const key = normalizeShellCommand(input.command);
      const earlier = longRuns.get(key);
      if (earlier && !repeatHinted.has(key)) {
        repeatHinted.add(key);
        content = [...(Array.isArray(content) ? content : []), { type: "text", text: repeatHintText(earlier) }];
        contentChanged = true;
        await logEvent(ctx.cwd, agentId, "repeat_hint", { command: leadingCommand(input.command) ?? "" }, { ok: true, earlier_ms: earlier.ms, full_output: earlier.path }).catch(() => undefined);
      }
      if (fullOutput && !fullOutput.write_error && !isError && durationMs !== undefined && durationMs >= repeatHintMinMs()) {
        longRuns.set(key, { ms: durationMs, path: fullOutput.path });
      }
    }
    // Pi takes a tool's failure only from a throw: an `isError: true` in what
    // execute returns is dropped, so every refusal and every failed pack or
    // forged tool reached the model, and its session, as a success. Their
    // details say ok: false, and this is where the flag is set from them.
    const refused =
      !isError && name !== "bash" && name !== "powershell" && (details as { ok?: unknown } | undefined)?.ok === false;
    const override =
      contentChanged || refused
        ? ({ ...(contentChanged ? { content } : {}), ...(refused ? { isError: true } : {}) } as never)
        : undefined;

    if ((name === "bash" || name === "powershell") && callId) {
      const before = bashSnapshots.get(callId);
      bashSnapshots.delete(callId);
      if (before && agentId) {
        try {
          // Let a peer's concurrent legal write record its revision first, so
          // it accounts for itself instead of looking like our shell's doing.
          await new Promise((r) => setTimeout(r, BASH_SETTLE_MS));
          const reports = await attributeToThisCall(ctx.cwd, await diffWatchedPaths(ctx.cwd, before.snapshot, agentId, { listClaims, listFileHistory }), before.command);
          if (reports.length) await reportBashWrites(ctx.cwd, reports, "bash", before.snapshot);
        } catch {
          // detection is best-effort; never break the agent's turn
        }
      }
    }

    // Built-in tools log nothing of their own, so the trace would otherwise
    // skip the reads, shells and edits that make a run readable. The row
    // carries what the model received, whole; `view` when that was a slice
    // of something on disk; `full_output` when the whole output is a file
    // under tool-output/.
    if (!SWARM_TOOLS.has(name) && !loadedTools.has(name)) {
      const view = viewOf(details);
      await logEvent(
        ctx.cwd,
        agentId,
        name || "tool",
        input ?? {},
        {
          ok: !isError,
          ...resultPreview(contentChanged ? { ...(event as unknown as Record<string, unknown>), content } : event),
          ...(view ? { view } : {}),
          ...(fullOutput ? { full_output: fullOutput } : {}),
          ...(fullOutputError ? { full_output_error: fullOutputError, full_output_host_path: hostSpill } : {}),
        },
        durationMs,
      );
    }

    await maybeEnforceStops(ctx.cwd, ctx);

    if (name !== "edit" && name !== "write") return override;
    if (isError) return override;
    const path = extractWritePath(input);
    if (!path || !agentId) return override;
    try {
      const version = await recordFileVersion(ctx.cwd, path, agentId);
      if (version) {
        await logEvent(ctx.cwd, agentId, "file_history", { path, rev: version.rev }, {
          ok: true,
          bytes: version.bytes,
          sha256: shortHash(version.sha256),
        });
      }
    } catch {
      // ignore
    }
    return override;
  });

  /**
   * One line of the model's reasoning per message, shown in the trace next
   * to the tool calls; the full text stays in the Pi session file.
   */
  pi.on("message_end", async (event, ctx) => {
    if (!agentId) return;
    const message = (event as { message?: { role?: string; content?: unknown } }).message;
    if (!message || message.role !== "assistant" || !Array.isArray(message.content)) return;
    const thinking = message.content
      .filter((block): block is { type: string; thinking?: string } =>
        Boolean(block) && typeof block === "object" && (block as { type?: string }).type === "thinking",
      )
      .map((block) => (block.thinking ?? "").trim())
      .filter(Boolean)
      .join(" ");
    if (!thinking) return;
    await logEvent(ctx.cwd, agentId, "thinking", {}, { text: thinking, chars: thinking.length });
  });

  pi.registerTool({
    name: "post",
    label: "Post",
    description:
      "Append a new markdown post under threads/<thread>/. Never edit old posts. Default thread is main. Tags: intro, ask, claim, result, hold, veto, stop.",
    promptSnippet: "Post a new append-only message on the swarm board",
    promptGuidelines: [
      "Use post for new board messages. Do not edit files under threads/ with write/edit.",
    ],
    parameters: Type.Object({
      body: Type.String({ description: "Message body" }),
      tag: Type.String({
        description: "intro | ask | claim | result | hold | veto | stop",
      }),
      thread: Type.Optional(Type.String({ description: "Thread name, default main" })),
      to: Type.Optional(Type.String({ description: "Recipient id or all" })),
    }),
    async execute(_id, params, _signal, _onUpdate, toolCtx: ToolCtx) {
      const record = await postMessage(ctxFrom(toolCtx.cwd, agentId), {
        body: params.body,
        tag: params.tag,
        thread: params.thread,
        to: params.to,
      });
      const payload = { ok: true, id: record.id, path: record.path, tag: record.tag };
      await logEvent(toolCtx.cwd, agentId, "post", params, payload);
      return okResult(payload);
    },
  });

  pi.registerTool({
    name: "inbox",
    label: "Inbox",
    description:
      "Unread posts, then advance this worker's cursor. With no argument it covers the primary thread plus every thread you belong to; pass `thread` to read just one. Also reports whether done/SWARM_DONE exists.",
    promptSnippet: "Read new swarm board posts and the done sentinel",
    promptGuidelines: [
      "Use inbox before acting. If inbox reports swarm_done, call done and stop.",
    ],
    parameters: Type.Object({
      thread: Type.Optional(
        Type.String({ description: "Read only this thread instead of all your threads" }),
      ),
    }),
    async execute(_id, params, _signal, _onUpdate, toolCtx: ToolCtx) {
      const started = Date.now();
      const box = await readInbox(ctxFrom(toolCtx.cwd, agentId), {
        thread: params.thread,
      });
      const payload = {
        swarm_done: box.swarm_done,
        seen: box.seen,
        threads: box.threads,
        cursors: box.cursors,
        posts: box.posts.map((p) => ({
          id: p.id,
          thread: p.thread,
          from: postSender(p),
          ...(p.via ? { via: p.via } : {}),
          to: p.to,
          tag: p.tag,
          path: p.path,
          body: p.body,
        })),
        remaining: box.remaining,
        ...(box.remaining > 0 ? { note: pageNote(box.remaining, box.page_chars) } : {}),
      };
      await logEvent(
        toolCtx.cwd,
        agentId,
        "inbox",
        params,
        { ...inboxLogResult(box), threads: box.threads.join(",") },
        Date.now() - started,
      );
      return okResult({ ...payload, ...newToolsNote(await loadForgedTools(toolCtx.cwd)) });
    },
  });

  pi.registerTool({
    name: "list_team",
    label: "List team",
    description: "Read team.json. Lock owner ids come from this file, not callsigns.",
    promptSnippet: "List assigned swarm agent ids",
    promptGuidelines: ["Use list_team to learn peer ids before claiming."],
    parameters: Type.Object({}),
    async execute(_id, _params, _signal, _onUpdate, toolCtx: ToolCtx) {
      const team = await listTeam(ctxFrom(toolCtx.cwd, agentId));
      await logEvent(toolCtx.cwd, agentId, "list_team", {}, { n: team.n });
      return okResult(team);
    },
  });

  pi.registerTool({
    name: "budget",
    label: "Budget",
    description:
      "Read live swarm-level budget.json (cap, spend, tokens, calls). Numbers come from Pi session Usage, not a static file. On a team of local models `metered` is false: spend is not measured, the brake is `cap_tokens` and `remaining_tokens` is what is left.",
    promptSnippet: "Check remaining swarm spend (or tokens, on local models) and wall-clock budget",
    promptGuidelines: [
      "Use budget before starting a long slice. If over_budget or over_time, write done/SWARM_DONE with cannot_complete.",
      "If metered is false, $0 spent means nothing was charged, not that nothing happened; read remaining_tokens instead.",
    ],
    parameters: Type.Object({}),
    async execute(_id, _params, _signal, _onUpdate, toolCtx: ToolCtx) {
      const status = await readBudgetStatus(ctxFrom(toolCtx.cwd, agentId));
      // The agent's own gauge rides on the tool it already calls: tokens in
      // context, the ceiling, the level and the three lines, so it never has
      // to guess where it stands before a large read or a hand-off.
      let context: ReturnType<SelfCompactHandle["view"]> | undefined;
      if (selfCompact) {
        try {
          context = selfCompact.view(toolCtx as unknown as ExtensionContext);
        } catch {
          context = undefined;
        }
      }
      await logEvent(toolCtx.cwd, agentId, "budget", {}, {
        spent_usd: status.budget.spent_usd,
        tokens: status.tokens,
        calls: status.calls,
        over_budget: status.over_budget,
        metered: status.metered,
        ...(status.remaining_tokens === null ? {} : { remaining_tokens: status.remaining_tokens }),
        ...(context ? { context_tokens: context.tokens, context_level: context.level } : {}),
      });
      return okResult(context ? { ...status, context } : status);
    },
  });

  pi.registerTool({
    name: "claim_file",
    label: "Claim file",
    description:
      "Lease a sandbox-relative path for writing. Say why in `reason` — peers and violation reports quote it. The lease runs for `seconds` (default 120, max 600); re-call to renew. Another live owner returns a conflict: post about it and do other work. Harness-owned paths are refused.",
    promptSnippet: "Lease a path before edit/write, with a reason",
    promptGuidelines: [
      "Use claim_file before every edit or write, with a short reason. Renew by calling it again; release_file when the slice is done. On conflict, yield; do not overwrite.",
    ],
    parameters: Type.Object({
      path: Type.String({ description: "Sandbox-relative path to claim" }),
      reason: Type.String({ description: "What you are about to do with the path" }),
      seconds: Type.Optional(
        Type.Number({ description: "Lease length in seconds (default 120, max 600)" }),
      ),
    }),
    async execute(_id, params, _signal, _onUpdate, toolCtx: ToolCtx) {
      const result = await claimFile(ctxFrom(toolCtx.cwd, agentId), params.path, {
        reason: params.reason,
        seconds: params.seconds,
      });
      await logEvent(toolCtx.cwd, agentId, "claim_file", params, result);
      // Taking a file back from an agent that stopped is the swarm's business,
      // not a private transaction: say it where the peers and the stalled
      // agent's own next turn will see it.
      if (result.ok && result.taken_over_from) {
        await systemPost(toolCtx.cwd, {
          tag: "claim",
          body: `${agentId} has taken \`${result.path}\`: ${result.taken_over_from}'s claim on it had expired. ${result.taken_over_from}, if you are still on it, say so on the board before you write.`,
        }).catch(() => undefined);
      }
      return okResult(result);
    },
  });

  pi.registerTool({
    name: "release_file",
    label: "Release file",
    description: "Drop a claim you own. Other owners are refused.",
    promptSnippet: "Release a claimed path after the slice",
    promptGuidelines: ["Use release_file after you finish a claimed slice, then post a result."],
    parameters: Type.Object({
      path: Type.String({ description: "Sandbox-relative path to release" }),
    }),
    async execute(_id, params, _signal, _onUpdate, toolCtx: ToolCtx) {
      const result = await releaseFile(ctxFrom(toolCtx.cwd, agentId), params.path);
      await logEvent(toolCtx.cwd, agentId, "release_file", params, result);
      return okResult(result);
    },
  });

  pi.registerTool({
    name: "claims",
    label: "Claims",
    description:
      "Every live claim on the board: path, owner, why they took it, and how long is left. Read it before assuming a path is free.",
    promptSnippet: "See who currently holds which paths",
    promptGuidelines: ["Use claims to find an unclaimed slice instead of colliding on a held one."],
    parameters: Type.Object({}),
    async execute(_id, _params, _signal, _onUpdate, toolCtx: ToolCtx) {
      const started = Date.now();
      const live = await listClaims(toolCtx.cwd);
      const payload = { n: live.length, claims: live };
      await logEvent(toolCtx.cwd, agentId, "claims", {}, { n: live.length }, Date.now() - started);
      return okResult(payload);
    },
  });

  pi.registerTool({
    name: "file_diff",
    label: "File diff",
    description:
      "Unified diff of a work file between two revisions. `from` and `to` accept a revision number, a content hash (short or full, as file_history reports them), or `disk` for the bytes on disk right now. Defaults to the newest recorded revision against disk — which is how you find out whether someone changed a file under you.",
    promptSnippet: "Diff two revisions of a work file",
    promptGuidelines: [
      "Use file_diff before overwriting a shared artifact, and quote the resulting hash when you sign off on it.",
    ],
    parameters: Type.Object({
      path: Type.String({ description: "Sandbox-relative path" }),
      from: Type.Optional(Type.String({ description: "Revision number, content hash, or `disk`" })),
      to: Type.Optional(Type.String({ description: "Revision number, content hash, or `disk`" })),
    }),
    async execute(_id, params, _signal, _onUpdate, toolCtx: ToolCtx) {
      const started = Date.now();
      const result = await fileDiff(toolCtx.cwd, params.path, params.from, params.to);
      await logEvent(
        toolCtx.cwd,
        agentId,
        "file_diff",
        params,
        { identical: result.identical, added: result.added, removed: result.removed },
        Date.now() - started,
      );
      return okResult(result);
    },
  });

  pi.registerTool({
    name: "thread_open",
    label: "Open thread",
    description:
      "Start a side thread for one slice of the work and join it. Everyone still reads the primary thread; a side thread keeps a detailed back-and-forth out of everyone else's inbox.",
    promptSnippet: "Open a side thread for a slice",
    promptGuidelines: [
      "Open a thread when two or three of you need detail the rest do not; announce it on the primary thread so others can join.",
    ],
    parameters: Type.Object({
      name: Type.String({ description: "Thread name, [A-Za-z0-9_-]" }),
      purpose: Type.String({ description: "What the thread is for" }),
    }),
    async execute(_id, params, _signal, _onUpdate, toolCtx: ToolCtx) {
      const started = Date.now();
      const meta = await threadOpen(ctxFrom(toolCtx.cwd, agentId), {
        name: params.name,
        purpose: params.purpose,
      });
      await logEvent(
        toolCtx.cwd,
        agentId,
        "thread_open",
        params,
        { created: meta.created, members: meta.members.length },
        Date.now() - started,
      );
      return okResult(meta);
    },
  });

  pi.registerTool({
    name: "thread_join",
    label: "Join thread",
    description:
      "Subscribe to an existing thread so its posts reach your inbox. Posting to a thread joins it automatically; this is for reading along without posting.",
    promptSnippet: "Subscribe to a thread you want to follow",
    promptGuidelines: ["A reviewer should join the threads it intends to audit."],
    parameters: Type.Object({
      name: Type.String({ description: "Thread name" }),
    }),
    async execute(_id, params, _signal, _onUpdate, toolCtx: ToolCtx) {
      const started = Date.now();
      const meta = await threadJoin(ctxFrom(toolCtx.cwd, agentId), params.name);
      await logEvent(
        toolCtx.cwd,
        agentId,
        "thread_join",
        params,
        { members: meta.members.length },
        Date.now() - started,
      );
      return okResult(meta);
    },
  });

  pi.registerTool({
    name: "wait",
    label: "Wait",
    description:
      "Sleep until something happens: a new post for you (on main: to you, to all, or to no one on the team; in a side thread you are in: any post), done/SWARM_DONE appearing, or a claim of yours lapsing — whichever comes first, or the timeout. A main-thread post addressed only to other agents does not wake you; it stays unread and comes with the next delivery. Returns the unread posts. Use this instead of `bash sleep`: a shell sleep costs a full provider round every time you wake up, this one costs nothing.",
    promptSnippet: "Block until the board changes instead of polling",
    promptGuidelines: [
      "When you are waiting on a peer, call wait, not bash sleep. Do not poll the board in a loop.",
    ],
    parameters: Type.Object({
      seconds: Type.Optional(
        Type.Number({ description: `How long to wait at most (default 60, max ${WAIT_MAX_SECONDS})` }),
      ),
      every_post: Type.Optional(
        Type.Boolean({
          description:
            "true: wake on every new post, one addressed to another agent included — for a seat that follows the whole board (a critic, an integrator). Each wake-up is a model turn with your whole context.",
        }),
      ),
    }),
    async execute(_id, params, signal, _onUpdate, toolCtx: ToolCtx) {
      const started = Date.now();
      const ctx = ctxFrom(toolCtx.cwd, agentId);
      const result = await waitForSwarmChange(ctx, {
        seconds: params.seconds,
        signal: signal as AbortSignal | undefined,
        everyPost: params.every_post === true,
      });
      // Hand back what woke us, so the agent does not need a second call.
      const box = result.reason === "post" ? await readInbox(ctx) : null;
      const remaining = box?.remaining ?? 0;
      const payload = {
        ...result,
        swarm_done: box?.swarm_done ?? (await swarmDoneExists(toolCtx.cwd)),
        posts:
          box?.posts.map((p) => ({
            id: p.id,
            thread: p.thread,
            from: postSender(p),
            ...(p.via ? { via: p.via } : {}),
            to: p.to,
            tag: p.tag,
            body: p.body,
          })) ?? [],
        remaining,
        ...(box && remaining > 0 ? { note: pageNote(remaining, box.page_chars) } : {}),
      };
      await logEvent(
        toolCtx.cwd,
        agentId,
        "wait",
        params,
        {
          reason: result.reason,
          waited_ms: result.waited_ms,
          n: payload.posts.length,
          ...(result.passed ? { passed: result.passed } : {}),
          ...(box ? { from: box.posts.map((p) => postSender(p)), ids: box.posts.map((p) => p.id), remaining } : {}),
        },
        Date.now() - started,
      );
      return okResult({ ...payload, ...newToolsNote(await loadForgedTools(toolCtx.cwd)) });
    },
  });

  pi.registerTool({
    name: "file_history",
    label: "File history",
    description:
      "List prior versions of a sandbox file. Storage is local numbered copies under history/.",
    promptSnippet: "Inspect prior versions of a claimed work file",
    promptGuidelines: ["Use file_history before restoring a stomped artifact."],
    parameters: Type.Object({
      path: Type.String({ description: "Sandbox-relative path" }),
    }),
    async execute(_id, params, _signal, _onUpdate, toolCtx: ToolCtx) {
      const versions = await listFileHistory(toolCtx.cwd, params.path);
      await logEvent(toolCtx.cwd, agentId, "file_history", params, { n: versions.length });
      return okResult({ path: params.path, versions });
    },
  });

  pi.registerTool({
    name: "file_restore",
    label: "File restore",
    description:
      "Restore a path to a history revision. Requires a live claim. Records the current bytes first.",
    promptSnippet: "Restore a claimed file to a prior revision",
    promptGuidelines: ["Claim the path, then file_restore, then release."],
    parameters: Type.Object({
      path: Type.String({ description: "Sandbox-relative path" }),
      rev: Type.Number({ description: "Revision number from file_history" }),
    }),
    async execute(_id, params, _signal, _onUpdate, toolCtx: ToolCtx) {
      const result = await restoreFileVersion(ctxFrom(toolCtx.cwd, agentId), params.path, params.rev);
      await logEvent(toolCtx.cwd, agentId, "file_restore", params, result);
      return okResult(result);
    },
  });

  pi.registerTool({
    name: "publish_file",
    label: "Publish file",
    description:
      "Put a file of your own (under work/<your id>/) into the shared part of work/ — work/report.md, work/timeline.md, a shared CSV. The destination is claimed for you (refused when a peer holds it), the bytes are copied by the harness and the revision is recorded. In a microVM this is the only way a shared file is written; on the host it works the same.",
    promptSnippet: "Publish a file of your own into the shared work/ (claimed and recorded for you)",
    promptGuidelines: ["Write a shared deliverable under work/<your id>/ first, then publish_file it. To change a shared file, copy it into your directory, edit, publish."],
    parameters: Type.Object({
      path: Type.String({ description: "Your own file, under work/<your id>/" }),
      to: Type.Optional(Type.String({ description: "Where it goes under work/; default: work/<basename>" })),
    }),
    async execute(_id, params, _signal, _onUpdate, toolCtx: ToolCtx) {
      const result = await publishFile(ctxFrom(toolCtx.cwd, agentId), params.path, params.to);
      await logEvent(toolCtx.cwd, agentId, "publish_file", params, result);
      if (!result.ok) {
        return { content: [{ type: "text" as const, text: result.reason }], details: result, isError: true };
      }
      return okResult(result);
    },
  });

  // Tool jobs: work in throwaway worker VMs, sealed into store/ (job-service.ts).
  const jobDone = (state: unknown) => state === "committed" || state === "failed" || state === "cancelled";
  pi.registerTool({
    name: "job_run",
    label: "Run a job",
    description:
      "Run work in a throwaway worker VM of this run's image: evidence parsing, anything slow or heavy, and anything whose output you will cite or share. Quick looks stay in your own shell. " +
      "The worker sees inputs/, store/ (earlier jobs' outputs), catalog/ and tools/ read-only, your own work/<you>/ read-only when the job names it, no network unless network=allowlist, and writes only to $OUT. " +
      "What it writes there is sealed into store/jobs/<id>/out/ (read-only, hashed) and outlives the VM: any job or agent reads it there, and you cite it as job:<id>/<path>. " +
      "Give command (bash, run from the run's directory) or tool with args (a pack or forged tool; write {OUT}/<name> where it takes an output path). " +
      "A short job answers here; a longer one returns its id, and a post tagged result wakes your wait when it is done: do not poll job_status. A failed or timed-out job keeps what it wrote. " +
      "stdout comes back a page at a time; all of it is store/jobs/<id>/stdout.log.",
    parameters: Type.Object({
      command: Type.Optional(Type.String({ description: "Bash, run from the run's directory; $OUT is the job's own directory" })),
      tool: Type.Optional(Type.String({ description: "A pack or forged tool's name, instead of a command" })),
      args: Type.Optional(Type.Object({}, { additionalProperties: true, description: "The tool's arguments, as its manifest says" })),
      inputs: Type.Optional(Type.Array(Type.String(), { description: "What it reads, for the record: input:<path>, job:<id>, or all (default)" })),
      timeout_seconds: Type.Optional(Type.Integer({ description: "Stop it after this long (default 900, at most 14400)" })),
      network: Type.Optional(Type.Union([Type.Literal("off"), Type.Literal("allowlist")], { description: "off (default) or the run's allowlist" })),
      wait_seconds: Type.Optional(Type.Integer({ description: "How long to wait here for it (default 12, at most 100)" })),
    }),
    async execute(_id, params, signal, _onUpdate, toolCtx: ToolCtx) {
      const started = Date.now();
      if (Boolean(params.command) === Boolean(params.tool)) {
        const refused = { ok: false as const, reason: "give command or tool (with its args), one of them" };
        await logEvent(toolCtx.cwd, agentId, "job_run", params, refused, Date.now() - started);
        return { content: [{ type: "text" as const, text: refused.reason }], details: refused, isError: true };
      }
      const spec: Record<string, unknown> = {
        ...(params.command ? { command: params.command } : {}),
        ...(params.tool ? { tool: params.tool, args: params.args ?? {} } : {}),
        ...(params.inputs ? { inputs: params.inputs } : {}),
        ...(params.timeout_seconds ? { timeout_seconds: params.timeout_seconds } : {}),
        ...(params.network ? { network: params.network } : {}),
      };
      const sub = await jobSubmit(toolCtx.cwd, spec);
      if (!sub.ok || !sub.job) {
        const refused = { ok: false as const, reason: sub.reason ?? "the job was not accepted" };
        await logEvent(toolCtx.cwd, agentId, "job_run", params, refused, Date.now() - started);
        return { content: [{ type: "text" as const, text: refused.reason }], details: refused, isError: true };
      }
      const id = String(sub.job.job);
      const wait = Math.min(Math.max(params.wait_seconds ?? 12, 0), 100);
      const until = Date.now() + wait * 1000;
      let last: Awaited<ReturnType<typeof jobStatus>> = sub;
      while (!jobDone(last.job?.state) && Date.now() < until && !signal?.aborted) {
        await new Promise((r) => setTimeout(r, 1000));
        const st = await jobStatus(toolCtx.cwd, { job_id: id, limit: 8192, wait: Math.ceil((until - Date.now()) / 1000) + 5 }).catch(() => null);
        if (st?.ok) last = st;
      }
      const result = jobDone(last.job?.state)
        ? { ok: true, ...last.job, ...(last.stdout ? { stdout: last.stdout } : {}) }
        : { ok: true, job: id, state: last.job?.state, note: `still ${last.job?.state === "accepted" ? "queued" : "running"}; a post tagged result will say when it is done (your wait wakes on it)` };
      await logEvent(toolCtx.cwd, agentId, "job_run", params, { ok: true, job: id, state: (result as { state?: unknown }).state, status: (result as { status?: unknown }).status }, Date.now() - started);
      return okResult(result);
    },
  });

  pi.registerTool({
    name: "job_status",
    label: "Job status",
    description:
      "A job's state, the first files it wrote (every one is in its manifest), and a page of its stdout (offset for the next page). cancel=true stops a job of your own. Needed only for a job that outlived job_run's wait and whose post you have not seen, or to read more of its stdout.",
    parameters: Type.Object({
      job_id: Type.String({ description: "j000123" }),
      offset: Type.Optional(Type.Integer({ description: "Where in stdout to start (bytes); the answer gives the next" })),
      cancel: Type.Optional(Type.Boolean({ description: "Stop it (your own jobs only)" })),
    }),
    async execute(_id, params, _signal, _onUpdate, toolCtx: ToolCtx) {
      const started = Date.now();
      const st = await jobStatus(toolCtx.cwd, { job_id: params.job_id, ...(params.offset !== undefined ? { offset: params.offset } : {}), ...(params.cancel ? { cancel: true } : {}), limit: 16384 });
      await logEvent(toolCtx.cwd, agentId, "job_status", params, { ok: st.ok, state: st.job?.state, ...(st.ok ? {} : { reason: st.reason }) }, Date.now() - started);
      if (!st.ok) return { content: [{ type: "text" as const, text: st.reason ?? "no answer" }], details: st, isError: true };
      return okResult({ ok: true, ...st.job, ...(st.stdout ? { stdout: st.stdout } : {}) });
    },
  });

  pi.registerTool({
    name: "catalog_request",
    label: "Catalogue an object",
    description:
      "Ask the harness to catalogue an object: an archive, a disk or memory image a job extracted, or an input the kickoff did not catalogue. Its member list, file list or timeline joins the shared catalogue (catalog/gen/…, a new revision announced on the board, found with catalog_search). " +
      "target: a path under inputs/ or store/jobs/<id>/out/, or an input:/job: reference. recipe (optional): one of the run's recipes (computer-forensics-base/archive-members, …/disk-volumes, …/memory-windows) or tool:<name> for a forged tool that declares the recipe protocol; without it every recipe is asked whether it applies. The same recipe over the same object is done once for everyone.",
    parameters: Type.Object({
      target: Type.String({ description: "inputs/…, store/jobs/<id>/out/…, input:… or job:<id>/…" }),
      recipe: Type.Optional(Type.String({ description: "<pack>/<recipe> or tool:<name>; default: every recipe that applies" })),
      reason: Type.Optional(Type.String({ description: "Why, for the record" })),
    }),
    async execute(_id, params, _signal, _onUpdate, toolCtx: ToolCtx) {
      const started = Date.now();
      const r = await catalogRequest(toolCtx.cwd, { target: params.target, ...(params.recipe ? { recipe: params.recipe } : {}), ...(params.reason ? { reason: params.reason } : {}) });
      await logEvent(toolCtx.cwd, agentId, "catalog_request", params, { ok: r.ok, job: r.job?.job, ...(r.ok ? {} : { reason: r.reason }) }, Date.now() - started);
      if (!r.ok) return { content: [{ type: "text" as const, text: r.reason ?? "refused" }], details: r, isError: true };
      return okResult({ ok: true, ...r.job, note: "the result is posted to you when it is catalogued (your wait wakes on it)" });
    },
  });

  // Real headless Chromium; still gated by --playwright at kickoff (--tools).
  registerPlaywrightTool(pi, { getAgentId: () => agentId, logEvent });

  // Audit name: browser_check. Implementation stays in playwright-tool.ts.
  pi.registerTool({
    name: "browser_check",
    label: "Browser check",
    description:
      "Alias of playwright: headless Chromium check of a work/ HTML file or loopback URL. Off unless --playwright.",
    promptSnippet: "Render a work/ HTML file headlessly (browser_check)",
    promptGuidelines: [
      "Use browser_check or playwright to verify a rendered artifact. Same driver as playwright.",
    ],
    parameters: Type.Object({
      target: Type.String({ description: "Sandbox-relative HTML file or loopback URL" }),
      screenshot: Type.Optional(Type.Boolean()),
      note: Type.Optional(Type.String()),
    }),
    async execute(_id, params, _signal, _onUpdate, toolCtx: ToolCtx) {
      try {
        const result = await runBrowserCheck({
          sandboxRoot: toolCtx.cwd,
          agentId,
          target: params.target,
          screenshot: params.screenshot ?? true,
        });
        await logEvent(toolCtx.cwd, agentId, "browser_check", params, {
          ok: true,
          title: result.title,
          screenshot: result.screenshot,
          text_chars: result.text.length,
          ...(result.full_text ? { full_text: result.full_text } : {}),
        });
        return { content: [{ type: "text" as const, text: toolText(result) }], details: result };
      } catch (err) {
        await logEvent(toolCtx.cwd, agentId, "browser_check", params, {
          ok: false,
          error: (err as Error).message,
        });
        throw err;
      }
    },
  });


  // -------------------------------------------------------------------------
  // Packs. The index goes in front of an agent once; a body arrives only when the
  // agent asks for it, so a pack's method never sits in every prompt on every turn.
  const packDirs = (process.env.SWARM_PACK_DIRS || "").split(":").filter(Boolean);
  if (packDirs.length) {
    const skillPath = (id: string): string | null => {
      if (!/^[a-z0-9][a-z0-9_\/-]{0,127}$/.test(id) || id.includes("..")) return null;
      return id;
    };
    pi.registerTool({
      name: "skill",
      label: "Skill",
      description:
        "Method from the packs this run was started with. Call it with no id for the index: every skill, what it is for, and when to reach for it. Call it with an id for that skill's body. A body may name other skills under `needs`; fetch those the same way. Reading a skill is cheaper than rediscovering the method, and every fetch is on the trace.",
      promptSnippet: "Read a method note from an installed pack",
      promptGuidelines: [
        "Call skill() with no argument once, early, to see what method this run carries.",
        "Fetch a skill before working an artefact family you have not worked in this case.",
      ],
      parameters: Type.Object({
        id: Type.Optional(Type.String({ description: "Skill id, for example windows/execution/prefetch. Omit to list every skill." })),
      }),
      async execute(_id, params, _signal, _onUpdate, toolCtx: ToolCtx) {
        const started = Date.now();
        const wanted = typeof params?.id === "string" ? params.id.trim() : "";
        if (!wanted) {
          const parts: string[] = [];
          for (const dir of packDirs) {
            const idx = await readFile(join(dir, "skills", "INDEX.md"), "utf8").catch(() => "");
            if (idx) parts.push(idx.trim());
          }
          const body = parts.join("\n\n");
          await logEvent(toolCtx.cwd, agentId, "skill", { id: "INDEX" }, { ok: true, bytes: body.length }, Date.now() - started);
          return okResult({ ok: true, index: body || "the packs carry no skills" });
        }
        const safe = skillPath(wanted);
        if (!safe) {
          await logEvent(toolCtx.cwd, agentId, "skill", { id: wanted }, { ok: false, error: "bad id" }, Date.now() - started);
          return okResult({ ok: false, error: "A skill id is lower case, slash separated, and cannot climb out of the pack." });
        }
        for (const dir of packDirs) {
          const file = join(dir, "skills", `${safe}.md`);
          const body = await readFile(file, "utf8").catch(() => null);
          if (body !== null) {
            await logEvent(toolCtx.cwd, agentId, "skill", { id: safe }, { ok: true, bytes: body.length }, Date.now() - started);
            return okResult({ ok: true, id: safe, body });
          }
        }
        const known: string[] = [];
        for (const dir of packDirs) {
          const idx = await readFile(join(dir, "skills", "INDEX.md"), "utf8").catch(() => "");
          for (const line of idx.split("\n")) {
            const m = /^- `([^`]+)`/.exec(line.trim());
            if (m) known.push(m[1]);
          }
        }
        await logEvent(toolCtx.cwd, agentId, "skill", { id: safe }, { ok: false, error: "no such skill" }, Date.now() - started);
        return okResult({ ok: false, error: `No skill ${safe}. The packs carry: ${known.join(", ") || "none"}` });
      },
    });
  }

  // Forged tools. Off unless the spawner set SWARM_TOOL_FORGING=1, in which
  // case it also dropped Pi's --tools allowlist (that list filters by name, so
  // a tool registered at runtime would never make it through) and handed the
  // base list over in SWARM_TOOLS for this extension to enforce itself.
  // -------------------------------------------------------------------------
  const baseTools = (process.env.SWARM_TOOLS ?? "")
    .split(",")
    .map((t) => t.trim())
    .filter(Boolean);

  function forgedSchema(manifest: ForgedToolManifest) {
    const props: Record<string, TSchema> = {};
    for (const [key, p] of Object.entries(manifest.params)) {
      const meta = p.description ? { description: p.description } : {};
      let schema: TSchema;
      switch (p.type) {
        case "string":
          schema = p.enum ? Type.Union(p.enum.map((v) => Type.Literal(v)), meta) : Type.String(meta);
          break;
        case "number":
          schema = Type.Number(meta);
          break;
        case "integer":
          schema = Type.Integer(meta);
          break;
        case "boolean":
          schema = Type.Boolean(meta);
          break;
        case "array":
          schema = Type.Array(Type.Any(), meta);
          break;
        default:
          schema = Type.Object({}, { ...meta, additionalProperties: true });
      }
      props[key] = p.required ? schema : Type.Optional(schema);
    }
    return Type.Object(props);
  }

  function paramSummary(manifest: ForgedToolManifest): string {
    const parts = Object.entries(manifest.params).map(([k, p]) => `${k}${p.required ? "" : "?"}: ${p.type}`);
    return parts.length ? parts.join(", ") : "no params";
  }

  function registerForged(manifest: ForgedToolManifest): void {
    pi.registerTool({
      name: manifest.name,
      label: manifest.name,
      description: `${manifest.description} (forged by ${manifest.by}, v${manifest.version}, ${manifest.runtime}; runs in the sandbox with a ${toolTimeoutSeconds(manifest)}s timeout)${manifest.example ? ` Example: ${manifest.example}` : ""}`,
      promptSnippet: `${manifest.description} — forged by ${manifest.by}`,
      parameters: forgedSchema(manifest),
      async execute(_id, params, signal, _onUpdate, toolCtx: ToolCtx) {
        // A forged tool is a subprocess with the same reach as bash, so it
        // gets the same treatment: a snapshot of every watched path before,
        // a diff after, and the same reports (claims, harness files, inputs).
        const before = await watchedPathHashes(toolCtx.cwd, agentId).catch(() => null);
        // A pack tool gets its pack's secrets in its own environment; the
        // trace row below has their values replaced by their names.
        const secrets = await packSecretsFor(manifest);
        // In a VM the seal is the hub's word, read where the record is current.
        const sealed = boardSocket() ? await forgedToolSeal(toolCtx.cwd, manifest.name).catch(() => undefined) : undefined;
        const run = await runForgedTool(toolCtx.cwd, manifest, (params ?? {}) as Record<string, unknown>, {
          signal: signal as AbortSignal | undefined,
          agentId,
          env: secrets,
          ...(sealed ? { sealed } : {}),
        });
        if (before && agentId) {
          try {
            await new Promise((resolve) => setTimeout(resolve, BASH_SETTLE_MS));
            // The same attribution a shell call gets: a change this call's
            // arguments do not name, in a peer's own directory, is the peer's
            // concurrent work. Without it, every file a peer's parallel
            // icat_extract wrote showed up as this agent's claim violation
            // (six on the first microVM case run, and on host runs before it).
            const reports = await attributeToThisCall(
              toolCtx.cwd,
              await diffWatchedPaths(toolCtx.cwd, before, agentId, { listClaims, listFileHistory }),
              JSON.stringify(params ?? {}),
            );
            if (reports.length) await reportBashWrites(toolCtx.cwd, reports, manifest.name, before);
          } catch {
            // the run's own result still goes back; a missed diff is not a reason to fail it
          }
        }
        await logEvent(
          toolCtx.cwd,
          agentId,
          manifest.name,
          redactSecrets((params ?? {}) as Record<string, unknown>, secrets),
          redactSecrets({
            ok: run.ok,
            forged: true,
            by: manifest.by,
            version: manifest.version,
            exit_code: run.exit_code,
            timed_out: run.timed_out,
            truncated: run.truncated,
            bytes: Buffer.byteLength(run.stdout, "utf8"),
            // What the model received, whole; the trace used to carry the
            // byte count and nothing of the output, so twenty-seven forged
            // calls that failed inside their payload read as successes.
            output: run.stdout,
            output_chars: run.stdout.length,
            ...(run.full_output ? { full_output: run.full_output } : {}),
            ...(run.full_stderr ? { full_stderr: run.full_stderr } : {}),
            ...(run.ok ? {} : { error: run.stderr.trim() || `exit ${run.exit_code ?? "?"}` }),
            ...(Object.keys(secrets).length ? { secrets: Object.keys(secrets) } : {}),
          }, secrets),
          run.duration_ms,
        );
        if (Object.keys(secrets).length) {
          run.stdout = redactSecrets(run.stdout, secrets);
          run.stderr = redactSecrets(run.stderr, secrets);
        }
        if (run.ok) {
          return {
            content: [{ type: "text" as const, text: run.stdout || "(no output)" }],
            details: { ok: true, exit_code: run.exit_code, duration_ms: run.duration_ms, truncated: run.truncated, ...(run.full_output ? { full_output: run.full_output } : {}) },
          };
        }
        const why = run.timed_out ? `timed out after ${toolTimeoutSeconds(manifest)}s` : `exit ${run.exit_code ?? "?"}${run.signal ? ` (${run.signal})` : ""}`;
        return {
          content: [{ type: "text" as const, text: `${manifest.name} failed: ${why}\n${run.stderr.trim() || run.stdout.trim()}`.trim() }],
          details: { ok: false, exit_code: run.exit_code, duration_ms: run.duration_ms, timed_out: run.timed_out },
          isError: true,
        };
      },
    });
    loadedTools.set(manifest.name, `${manifest.version}:${manifest.sha256}`);
  }

  /**
   * Register every tool on disk this session has not seen, or has seen at an
   * older version. Called at the wake-up points — session start, inbox, wait,
   * turn end — so a peer's forge reaches everyone within one turn. Returns
   * what was new, for the caller to tell the model.
   */
  // Seeded tools — a pack's, or a library handed over with --tools-from —
  // are registered whether or not forging is on: the contract lists them as
  // ready, and a run with packs but no forging used to get none of them.
  // Without forging nothing can add a tool mid-run, so after the first load
  // the wake points have nothing to pick up.
  let seededLoaded = false;
  async function loadForgedTools(cwd: string): Promise<ForgedToolManifest[]> {
    if (!forging && seededLoaded) return [];
    seededLoaded = true;
    const fresh: ForgedToolManifest[] = [];
    for (const manifest of await listForgedTools(cwd).catch(() => [] as ForgedToolManifest[])) {
      const key = `${manifest.version}:${manifest.sha256}`;
      if (loadedTools.get(manifest.name) === key) continue;
      try {
        registerForged(manifest);
        fresh.push(manifest);
        await logEvent(cwd, agentId, "tool_loaded", { name: manifest.name, version: manifest.version, by: manifest.by }, { ok: true, forged: true });
      } catch (err) {
        await logEvent(cwd, agentId, "tool_loaded", { name: manifest.name, version: manifest.version, by: manifest.by }, { ok: false, error: (err as Error).message });
      }
    }
    return fresh;
  }

  function newToolsNote(fresh: ForgedToolManifest[]): Record<string, unknown> {
    if (!fresh.length) return {};
    return {
      new_tools: fresh.map((m) => ({ name: m.name, by: m.by, version: m.version, description: m.description, params: paramSummary(m) })),
      note: "These forged tools are now in your tool list. Call them directly.",
    };
  }

  if (!forging) {
    pi.on("session_start", async (_event, ctx) => {
      // swarm.sh named every seeded tool in --tools, so registering them is
      // all it takes for them to be in the list from the first turn.
      await loadForgedTools(ctx.cwd);
    });
  }

  if (forging) {
    pi.on("session_start", async (_event, ctx) => {
      // The allowlist swarm.sh used to pass on the command line, enforced here
      // instead, so tools registered later can join it.
      const active = [...new Set([...baseTools, "make_tool", "tools", ...loadedTools.keys()])];
      try {
        pi.setActiveTools(active);
      } catch {
        // an older Pi without setActiveTools keeps whatever --tools gave it
      }
      await loadForgedTools(ctx.cwd);
    });

    pi.on("turn_end", async (_event, ctx) => {
      await loadForgedTools(ctx.cwd);
    });

    pi.registerTool({
      name: "make_tool",
      label: "Make tool",
      description:
        "Write a tool the goal needs and nobody has — a parser, a checker, a converter — and hand it to the whole swarm. Give it a name, a one-line description, its params, a runtime (python3, node or bash) and the script. The script receives its arguments as ONE JSON object on stdin and must print its result to stdout; exit non-zero to fail. It lands in tools/<name>/ with your id on it, is announced on the board, and becomes a real tool for every agent after their next inbox or wait. Replacing a tool is allowed to its author, or to anyone once the author has stopped.",
      promptSnippet: "Write a tool the swarm lacks and share it with every peer",
      promptGuidelines: [
        "Call `tools` before make_tool: if a peer already forged what you need, use theirs.",
        "A forged tool runs in this directory as a subprocess with the same limits as bash. Keep it small, deterministic and free of network calls.",
      ],
      parameters: Type.Object({
        name: Type.String({ description: "Lower-case, [a-z][a-z0-9_]{2,31}; becomes the tool's name" }),
        description: Type.String({ description: "One line: what it does and what it returns" }),
        runtime: Type.Union([Type.Literal("python3"), Type.Literal("node"), Type.Literal("bash")]),
        script: Type.String({ description: "The whole script. Reads one JSON object from stdin, prints the result to stdout." }),
        params: Type.Optional(
          Type.Record(
            Type.String(),
            Type.Object({
              type: Type.Union([Type.Literal("string"), Type.Literal("number"), Type.Literal("integer"), Type.Literal("boolean"), Type.Literal("array"), Type.Literal("object")]),
              description: Type.Optional(Type.String()),
              required: Type.Optional(Type.Boolean()),
              enum: Type.Optional(Type.Array(Type.String())),
            }),
            { description: "The arguments the tool takes, by name" },
          ),
        ),
        timeout_seconds: Type.Optional(Type.Number({ description: `Kill the script after this long (default ${TOOL_TIMEOUT_DEFAULT_SECONDS}, max ${TOOL_TIMEOUT_MAX_SECONDS})` })),
        example: Type.Optional(Type.String({ description: "One example call, shown to peers" })),
        requires: Type.Optional(Type.Array(Type.String(), { description: "Programs the script calls (e.g. fls, yara), so a later case knows what its image must hold" })),
      }),
      async execute(_id, params, _signal, _onUpdate, toolCtx: ToolCtx) {
        const started = Date.now();
        const result = await forgeTool(ctxFrom(toolCtx.cwd, agentId), params);
        if (!result.ok) {
          // The refusal used to record the name and the runtime only, so a
          // trace line said `param "db" must match …` about params it did not
          // hold. The params it was asked for go in, the same as on the way
          // through.
          await logEvent(
            toolCtx.cwd,
            agentId,
            "make_tool",
            {
              name: params.name,
              runtime: params.runtime,
              params: Object.keys(params.params ?? {}).join(","),
              bytes: Buffer.byteLength(params.script ?? "", "utf8"),
            },
            { ok: false, error: result.reason },
            Date.now() - started,
          );
          return { content: [{ type: "text" as const, text: `make_tool refused: ${result.reason}` }], details: { ok: false, reason: result.reason }, isError: true };
        }
        const m = result.manifest;
        await logEvent(
          toolCtx.cwd,
          agentId,
          "make_tool",
          { name: m.name, runtime: m.runtime, params: Object.keys(m.params).join(","), bytes: Buffer.byteLength(params.script, "utf8") },
          { ok: true, forged: true, created: result.created, version: m.version, sha256: shortHash(m.sha256) },
          Date.now() - started,
        );
        await loadForgedTools(toolCtx.cwd);
        // The board is how peers learn; the harness posts on the author's behalf
        // so a tool never exists without an announcement.
        await postMessage(ctxFrom(toolCtx.cwd, agentId), {
          tag: "result",
          to: "all",
          body: `Forged tool \`${m.name}\` v${m.version} (${m.runtime}): ${m.description} Params: ${paramSummary(m)}.${m.example ? ` Example: ${m.example}` : ""} It is in your tool list after your next inbox or wait.`,
        }).catch(() => undefined);
        return okResult({ ok: true, name: m.name, version: m.version, created: result.created, sha256: shortHash(m.sha256), entry: `${TOOLS_DIR}/${m.name}/${m.entry}` });
      },
    });

    pi.registerTool({
      name: "tools",
      label: "Tools",
      description: "List the tools this swarm has forged: name, what it does, its params, who wrote it and which version. Also loads any you have not seen yet.",
      promptSnippet: "See the tools peers have forged",
      parameters: Type.Object({}),
      async execute(_id, _params, _signal, _onUpdate, toolCtx: ToolCtx) {
        const started = Date.now();
        const fresh = await loadForgedTools(toolCtx.cwd);
        const all = await listForgedTools(toolCtx.cwd);
        await logEvent(toolCtx.cwd, agentId, "tools", {}, { ok: true, n: all.length, loaded: fresh.length }, Date.now() - started);
        return okResult({
          forged: all.map((m) => ({ name: m.name, description: m.description, params: paramSummary(m), runtime: m.runtime, by: m.by, version: m.version, ...(m.example ? { example: m.example } : {}) })),
          ...newToolsNote(fresh),
          hint: all.length ? "Call a forged tool by its name, like any other tool." : "Nothing forged yet. make_tool writes one and shares it.",
        });
      },
    });
  }

  pi.registerTool({
    name: "name",
    label: "Name",
    description:
      "Say what to call you and what you are taking on. Nobody assigns work here: you read the goal, you see on the board what your peers have taken, you decide, and you say it with this. The name goes on every post you write and beside your id everywhere the run is read. Call it again whenever what you are doing changes. Two agents cannot answer to the same name.",
    promptSnippet: "Name yourself for the work you are taking on",
    promptGuidelines: [
      "Name yourself in your first turn, after reading the goal and the board, and say what you are taking on.",
      "Rename yourself when your work changes; the old name is replaced and the board is told.",
    ],
    parameters: Type.Object({
      name: Type.String({ description: "What to call you: a few words for the work you are taking on" }),
      doing: Type.Optional(Type.String({ description: "What you are taking on, in a sentence" })),
    }),
    async execute(_id, params, _signal, _onUpdate, toolCtx: ToolCtx) {
      const started = Date.now();
      const result = await claimName(toolCtx.cwd, agentId, params.name, params.doing);
      if (!result.ok) {
        await logEvent(toolCtx.cwd, agentId, "name", { name: params.name }, { ok: false, reason: result.error }, Date.now() - started);
        return { content: [{ type: "text" as const, text: `name refused: ${result.error}` }], details: { ok: false, reason: result.error }, isError: true };
      }
      await postMessage(ctxFrom(toolCtx.cwd, agentId), {
        tag: "intro",
        // Renaming yourself to the same name is how an agent says its work
        // moved on; announcing it as a rename reads as a mistake.
        body:
          result.previous && result.previous !== result.name
            ? `${agentId} is now "${result.name}" (was "${result.previous}")${params.doing ? `: ${params.doing}` : ""}`
            : result.previous
              ? `${agentId} ("${result.name}")${params.doing ? ` is now on: ${params.doing}` : " updated what it is doing"}`
              : `${agentId} is "${result.name}"${params.doing ? `: ${params.doing}` : ""}`,
      }).catch(() => undefined);
      await logEvent(
        toolCtx.cwd,
        agentId,
        "name",
        { name: result.name, doing: params.doing },
        { ok: true, previous: result.previous, peers: result.peers.length, overlaps: result.overlaps?.length ?? 0 },
        Date.now() - started,
      );
      return okResult({
        ok: true,
        name: result.name,
        ...(result.previous ? { previous: result.previous } : {}),
        peers: result.peers,
        ...(result.overlaps?.length
          ? {
              overlaps: result.overlaps,
              note: "Peers have said they are doing something close to this. Nobody will move you: settle it on the board, or take the ground nobody has.",
            }
          : {}),
      });
    },
  });

  pi.registerTool({
    name: "record",
    label: "Record",
    description:
      "Put a fact in the swarm's ledger with its provenance: kind event (a dated event for the timeline; ts required, ISO 8601 with its zone: Z when the source's time is UTC, or the offset the source records), ioc (an indicator: address, hash, file, account), finding (a conclusion) or absence (a search that found nothing, when that matters: value is what was looked for, source what was searched, evidence the query, the tool and its version, and the scope). Both source and evidence are required: where it was seen (a path, a log, a registry key) and how to check it (the command, the inode, the record id, the hash). An entry nobody can check is not a record. To correct an entry, yours or a peer's, record the corrected one with supersedes=<its seq>: nothing is deleted, and the newer entry is the correction. The harness renders ledger/ledger.md — timeline, indicators, findings, searches that found nothing — after every record; cite that file in the report.",
    promptSnippet: "Record a dated event, an indicator or a finding with its evidence",
    promptGuidelines: [
      "Record every dated event you establish as kind=event with ts in UTC; the timeline is built from them.",
      "Record indicators and findings as you confirm them, with the evidence that proves them.",
      "source and evidence are required on every record: where you saw it, and the command or id that lets somebody else see it too.",
      "A wrong entry is corrected, never deleted: record the right one with supersedes=<seq of the wrong one>.",
      "kind=absence is optional: record a search that found nothing only when the absence matters to the case, with the scope it holds for.",
    ],
    parameters: Type.Object({
      kind: Type.Union(LEDGER_KINDS.map((k) => Type.Literal(k)), { description: "event | ioc | finding | absence" }),
      value: Type.String({ description: "The event, indicator or finding, in one sentence; for absence, what was looked for" }),
      ts: Type.Optional(Type.String({ description: "The event's time, ISO 8601 with its zone: 2024-01-15T12:44:22Z, or 2024-01-15T15:44:22+03:00 as the source records it. A time without a zone is refused." })),
      source: Type.String({ description: "Where it was seen: a path, log, plugin, registry key. Required." }),
      evidence: Type.String({ description: "How to check it: command, inode, record id, hash. Required." }),
      confidence: Type.Optional(Type.Union(LEDGER_CONFIDENCE.map((c) => Type.Literal(c)))),
      supersedes: Type.Optional(Type.Number({ description: "The seq of an entry this one corrects. The older entry stays, marked superseded." })),
    }),
    async execute(_id, params, _signal, _onUpdate, toolCtx: ToolCtx) {
      const started = Date.now();
      const result = await recordEntry(ctxFrom(toolCtx.cwd, agentId), {
        kind: params.kind,
        value: params.value,
        ts: params.ts,
        source: params.source,
        evidence: params.evidence,
        confidence: params.confidence,
        ...(params.supersedes !== undefined ? { supersedes: params.supersedes } : {}),
      });
      if (!result.ok) {
        await logEvent(toolCtx.cwd, agentId, "record", { kind: params.kind }, { ok: false, reason: result.reason }, Date.now() - started);
        return { content: [{ type: "text" as const, text: `record refused: ${result.reason}` }], details: { ok: false, reason: result.reason }, isError: true };
      }
      // The entry's hash goes on the trace, which is anchored outside the
      // run: custody holds the ledger to it, so an entry deleted from the
      // tail, or one written into the file without this tool, is named.
      await logEvent(toolCtx.cwd, agentId, "record", { kind: params.kind, ts: params.ts, value: params.value, ...(result.entry.supersedes !== undefined ? { supersedes: result.entry.supersedes } : {}) }, { ok: true, seq: result.entry.seq, merged: result.merged, total: result.total, ...(result.entry.hash ? { hash: result.entry.hash } : {}) }, Date.now() - started);
      // A correction is said on the trace as itself, so a reader of the
      // record sees which entry stopped standing, when, and by whom.
      if (result.entry.supersedes !== undefined && !result.merged) {
        await logEvent(toolCtx.cwd, agentId, "ledger_superseded", { seq: result.entry.supersedes }, { ok: true, by_seq: result.entry.seq });
      }
      return okResult({ ok: true, seq: result.entry.seq, merged: result.merged, total: result.total, ...(result.entry.supersedes !== undefined ? { supersedes: result.entry.supersedes } : {}), rendered: LEDGER_MD });
    },
  });

  pi.registerTool({
    name: "ledger",
    label: "Ledger",
    description: "List the swarm's ledger: every event, indicator, finding and search that found nothing, recorded so far, with authors and evidence; a corrected entry carries superseded_by. Filter by kind; the rendered file is ledger/ledger.md.",
    promptSnippet: "See what the swarm has recorded so far",
    parameters: Type.Object({
      kind: Type.Optional(Type.String({ description: "event | ioc | finding | absence" })),
      limit: Type.Optional(Type.Number({ description: "Newest N entries (default 200)" })),
    }),
    async execute(_id, params, _signal, _onUpdate, toolCtx: ToolCtx) {
      const started = Date.now();
      const entries = await listLedger(toolCtx.cwd, params ?? {});
      await logEvent(toolCtx.cwd, agentId, "ledger", params ?? {}, { ok: true, n: entries.length }, Date.now() - started);
      return okResult({ entries, rendered: LEDGER_MD });
    },
  });

  pi.registerTool({
    name: "inputs",
    label: "Inputs",
    description:
      "List this swarm's read-only inputs: every file under inputs/ with its size and hash, where they came from, and what guards them. Read them with read, grep or bash; never write there.",
    promptSnippet: "See the read-only files the swarm was given",
    parameters: Type.Object({}),
    async execute(_id, _params, _signal, _onUpdate, toolCtx: ToolCtx) {
      const started = Date.now();
      const manifest = await readInputsManifest(toolCtx.cwd);
      if (!manifest) {
        await logEvent(toolCtx.cwd, agentId, "inputs", {}, { ok: true, inputs: false }, Date.now() - started);
        return okResult({ inputs: false, hint: "This swarm was given no read-only inputs. Everything you need is in the goal and on the board." });
      }
      await logEvent(toolCtx.cwd, agentId, "inputs", {}, { ok: true, inputs: true, n: manifest.files.length, bytes: manifest.bytes }, Date.now() - started);
      return okResult({
        inputs: true,
        source: manifest.source,
        count: manifest.files.length,
        bytes: manifest.bytes,
        files: manifest.files.map((f) => ({ path: f.path, bytes: f.bytes, sha256: f.sha256.slice(0, 12) })),
        guard: { requested: manifest.enforce, kickoff: manifest.guard, in_this_pane: inputsEnforced },
        rule: "Read only. Writes under inputs/ are refused or undone and announced; put results in work/, copying an input there if you need a version you can change.",
      });
    },
  });

  pi.registerTool({
    name: "done",
    label: "Done",
    description:
      "Write done/agents/<id>.done, create done/SWARM_DONE if missing (idempotent), drop this worker's locks, and terminate the session.",
    promptSnippet: "Stop this worker and signal the swarm sentinel",
    promptGuidelines: [
      "Use done when the definition of done is met and its checks pass, or when done/SWARM_DONE already exists. done ends the whole swarm, not your slice: a finished slice is posted to the board, not done. When the task is impossible or unsafe, call done with abandon: true and say why.",
    ],
    parameters: Type.Object({
      reason: Type.String({ description: "Why this worker is stopping" }),
      output_file: Type.String({
        description: "The artifact this swarm was asked to produce",
      }),
      abandon: Type.Optional(
        Type.Boolean({ description: "The finish line cannot be met: stop the swarm anyway. The sentinel and the board will say the run was abandoned." }),
      ),
    }),
    async execute(_id, params, _signal, _onUpdate, toolCtx: ToolCtx) {
      // A peer's correction that landed after the report was last written has
      // not reached it. Say so once and let the agent decide: fold it in, or
      // call done again and say on the board why it does not change anything.
      if (!doneRefusedOnce && !(await swarmDoneExists(toolCtx.cwd))) {
        const late = await correctionsAfter(toolCtx.cwd, params.output_file, agentId).catch(() => []);
        if (late.length) {
          doneRefusedOnce = true;
          const who = late.map((p) => `#${p.id} by ${p.from}`).join(", ");
          const reason = `${late.length} post(s) landed after \`${params.output_file}\` was last written: ${who}. Read them. Fold what belongs in, or call done again and say on the board why they do not change it.`;
          await logEvent(toolCtx.cwd, agentId, "done", params, { ok: false, reason, late: late.length });
          return {
            content: [{ type: "text" as const, text: reason }],
            details: { ok: false, reason, late },
            isError: true,
          };
        }
      }
      // Put inputs/ right and vouch for it: anything a background process
      // changed since the last tool call is healed and announced, then the
      // check is recorded, so an `ok: false` here means a heal failed, not
      // that nobody looked. This comes before the finish line because the
      // finish line may ask for it: a goal check that greps the trace for
      // `inputs_check` could never pass while the event landed after the
      // checks had run (run s57e9: 7 of 9, twice, then abandoned).
      await sweepInputs(toolCtx.cwd, "done");
      const inputsCheck = await verifyInputs(toolCtx.cwd).catch(() => null);
      if (inputsCheck) {
        // `content_ok` and `metadata` travel with it: the custody line a
        // report prints has to be able to say "the bytes are intact, the mode
        // drifted" rather than the single `ok: false` that made 374 permission
        // changes read as evidence tampering on one archived run.
        await logEvent(toolCtx.cwd, agentId, "inputs_check", {}, {
          ok: inputsCheck.ok,
          content_ok: inputsCheck.content_ok,
          checked: inputsCheck.checked,
          modified: inputsCheck.modified,
          metadata: inputsCheck.metadata,
          missing: inputsCheck.missing,
          added: inputsCheck.added,
          ...(inputsCheck.digest_mismatch.length ? { digest_mismatch: inputsCheck.digest_mismatch } : {}),
        });
      }
      // The finish line, before the sentinel: the operator's checks, run now.
      // A done that would end the swarm with them failing is refused and told
      // which check fails; an abandoned run says so in its reason.
      let reasonPrefix = "";
      if (!(await swarmDoneExists(toolCtx.cwd))) {
        const run = await runFinishLine(toolCtx.cwd).catch(() => null);
        const verdict = finishLineVerdict(run, params.abandon === true);
        await logEvent(toolCtx.cwd, agentId, "finish_line", { abandon: params.abandon === true }, {
          ok: verdict.proceed,
          total: run?.total ?? 0,
          passed: run?.passed ?? 0,
          ...(verdict.proceed ? (verdict.note ? { note: verdict.note } : {}) : { failing: verdict.failing }),
        }).catch(() => undefined);
        if (!verdict.proceed) {
          await logEvent(toolCtx.cwd, agentId, "done", params, { ok: false, reason: verdict.reason }).catch(() => undefined);
          return {
            content: [{ type: "text" as const, text: verdict.reason }],
            details: { ok: false, reason: verdict.reason, failing: verdict.failing, passed: run?.passed ?? 0, total: run?.total ?? 0 },
            isError: true,
          };
        }
        reasonPrefix = verdict.reasonPrefix ?? "";
      }
      const result = await markDone(ctxFrom(toolCtx.cwd, agentId), {
        reason: reasonPrefix + params.reason,
        outputFile: params.output_file,
      });
      await logEvent(toolCtx.cwd, agentId, "done", params, {
        reason: result.reason,
        output_file: result.output_file,
        created_sentinel: result.created_sentinel,
      });
      if (result.created_sentinel) {
        await systemPost(toolCtx.cwd, {
          tag: "stop",
          body: `done/SWARM_DONE written by ${agentId}: ${result.reason}. Output: \`${result.output_file}\`. Everyone else: call done and stop.`,
        }).catch(() => undefined);
        await nudgePeers(toolCtx.cwd, result.reason).catch(() => undefined);
      }
      await logStop(toolCtx.cwd, "done", result.reason);
      // `terminate` ends the session without a session_shutdown, so the
      // last agent out has to turn the proxy off from here.
      if (!boardSocket()) await stopNetguardSidecarIfOver(toolCtx.cwd).catch(() => false);
      return okResult(result, { terminate: true });
    },
  });

  /**
   * What the harness knows at hand-off time, from files rather than from the
   * model's memory: the header the returned note travels under. Every read is
   * best effort; a missing fact is left out, never invented.
   */
  async function handoffFacts(cwd: string, id: string): Promise<HandoffFacts> {
    const sctx = ctxFrom(cwd, id);
    const [claims, box, ledger, names, sentinel, status] = await Promise.all([
      listClaims(cwd).catch(() => []),
      readInbox(sctx, { markSeen: false }).catch(() => null),
      listLedger(cwd, { limit: 500 }).catch(() => []),
      readNames(cwd).catch(() => []),
      swarmDoneExists(cwd).catch(() => false),
      readBudgetStatus(sctx).catch(() => null),
    ]);
    const unread: Record<string, number> = {};
    for (const post of box?.posts ?? []) unread[post.thread] = (unread[post.thread] ?? 0) + 1;
    const me = names.find((n) => n.id === id);
    return {
      name: me?.name,
      doing: me?.doing,
      claims: claims.filter((c) => c.owner === id).map((c) => c.path),
      unread,
      ledgerTotal: ledger.length,
      ledgerMine: ledger.filter((e) => e.by === id || e.authors.includes(id)).length,
      sentinel,
      spentUsd: status?.this_agent?.spent_usd ?? 0,
      capUsd: status?.budget.cap_per_agent_usd ?? undefined,
    };
  }

  if (selfCompactOn) {
    const { specs, fromDefaults } = specsFromEnv();
    selfCompact = registerSelfCompact(pi, {
      agentId: () => agentId,
      trace: (cwd, tool, args, result) => logEvent(cwd, agentId, tool, args, result),
      handoffFacts,
      promptsDir: join(dirname(fileURLToPath(import.meta.url)), "..", "prompts"),
      summaryPromptPath: process.env.SWARM_COMPACT_PROMPT?.trim() || undefined,
      summaryModel: process.env.SWARM_COMPACT_MODEL?.trim() || undefined,
      specs,
      fromDefaults,
    });
  }
}
