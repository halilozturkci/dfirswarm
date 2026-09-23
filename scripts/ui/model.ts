/**
 * Read models for the web app. Everything here is derived from files the
 * spawner and extension already write under runs/<id>/. No new
 * on-disk protocol.
 */
import { existsSync } from "node:fs";
import { lstat, readdir, readFile, realpath, stat } from "node:fs/promises";
import { join, relative, resolve, sep } from "node:path";
import { artifactKind } from "../artifact-kind.ts";
import {
  LEDGER_MD,
  listForgedTools,
  readInputsManifest,
  readLedger,
  readNames,
  type ForgedToolManifest,
  type InputFile,
  type LedgerEntry,
  type NameRecord,
} from "../../extensions/protocol.ts";
import {
  listSwarmSummaries,
  loadRegistry,
  readSwarmDetail,
  readThreadPosts,
  type AgentView,
  type SwarmDetail,
  type SwarmSummary,
} from "../../extensions/observe.ts";
import { agentDeadPath, agentDonePath, readEventLog, type PostRecord, type SwarmEvent } from "../../extensions/protocol.ts";
import { isFailureEvent } from "../../ui/src/lib/event-taxonomy.ts";
import { countChecks } from "./goals.ts";

export type RegistryRun = {
  /** The packs this run carried, with the checksum of each manifest. */
  packs?: Array<{ id: string; version: string; manifest_sha256: string }>;
  id: string;
  label?: string;
  state?: string;
  sandbox?: string;
  n?: number;
  model?: string;
  cap_usd?: number;
  wall_clock_minutes?: number;
  hard_kill?: boolean;
  tool_forging?: boolean;
  /** The kickoff's self-compaction options; absent on runs older than the feature. */
  self_compact?: { enabled: boolean; notice_at: string; warn_at: string; compact_at: string; prompt: string | null; model?: string | null; set?: { notice_at: boolean; warn_at: boolean; compact_at: boolean } };
  /** How much post text one inbox/wait delivery carries; absent on runs older than the bound. */
  inbox_page_chars?: number;
  inputs?: { source: string; files: number; bytes: number; enforce: string; guard: string } | null;
  goal?: string;
  agents?: string[];
  started_at?: string;
  /** guarded · hosts · open · local (the local endpoints and nothing else). */
  net?: string;
  netguard?: boolean;
  /** netns (enforced) · proxy-only (advisory) · off — what the host could give, measured at kickoff. */
  netguard_mode?: string;
  /** seatbelt · mountns · none — where the panes could write. */
  write_guard?: string;
  /** "sealed", "open" or "unenforced": could a pane reach Herdr's control socket. */
  herdr_socket?: string;
  /** "read-only", "writable" or "not-applicable": could a pane drop code into Pi's extensions/. */
  pi_extensions?: string;
  /** What the host could enforce, probed at kickoff: seatbelt, userns, netns, pidns, landlock_abi, bwrap. */
  host_caps?: Record<string, unknown>;
  /** "token", "ancestry" or "token-exposed": how the collector decided whose line each one was. */
  attribution?: string;
  /** "kernel", "partial", "none" or "unmeasured": what the panes' own probes said the guard was. */
  write_guard_measured?: string;
  metered?: boolean;
  cap_tokens?: number | null;
  local_models?: string[];
  workspace_id?: string;
  workspace_ids?: string[];
  probe_agent?: string;
  tab_count?: number;
  split_failures?: number;
  extra_workspaces?: number;
};

export type SwarmRow = SwarmSummary & {
  started_at: string;
  elapsed_ms: number;
  finished_at: string | null;
  goal: string;
  wall_clock_minutes: number;
  /** False when no model on the team bills: spend is an exact zero and cap_tokens is the brake. */
  metered: boolean;
  cap_tokens: number;
  net: string;
  agents_total: number;
  agents_done: number;
  agents_dead: number;
  violations: number;
  /** The newest post on threads/main — what the swarm last said, for the list. */
  last_post: { from: string; tag: string; body: string; at: string | null } | null;
  /** How many `## Checks` the goal defines; the finish line's denominator. */
  checks_total: number;
  /** Threads on the board and posts across all of them, for the list. */
  threads_total: number;
  posts_total: number;
  /** running | done | stopped | prepared | unknown, derived from sentinel + registry */
  phase: SwarmPhase;
  /** Frontmatter `by` on done/SWARM_DONE, when the swarm is finished. */
  sentinel_by: string | null;
  /** budget.json stop_reason (cap / wall_clock), when the harness steered or stopped. */
  stop_reason: string | null;
  /** How many tools the run forged (directories under tools/ with a manifest): what --tools-from can seed. */
  tools_forged: number;
  /** The inputs directory the run was given, from inputs.json, or null: what a clean room is about. */
  inputs_source: string | null;
};

/** One post as a dot on a thread's pulse line: when, and who. */
export type ThreadDot = { at: string | null; from: string; tag: string };

/**
 * The swarm's activity over its lifetime, bucketed for the strip at the foot
 * of the page: messages (posts) against tool calls.
 */
export type ActivitySeries = {
  from: string | null;
  to: string | null;
  messages: number;
  tool_calls: number;
  buckets: Array<{ m: number; c: number }>;
};

/** Lifecycle and harness lines: not something an agent chose to call. */
export const LIFECYCLE_TOOLS = new Set(["agent_start", "agent_stop", "harness_stop", "cap_steer", "wall_steer", "claim_violation", "reap", "reaped", "thinking"]);

export function activitySeries(events: readonly SwarmEvent[], from: string | null, to: string | null, buckets = 96, now = Date.now()): ActivitySeries {
  const stamps = events.map((e) => Date.parse(e.ts)).filter((n) => Number.isFinite(n));
  const startMs = from && Number.isFinite(Date.parse(from)) ? Date.parse(from) : stamps.length ? Math.min(...stamps) : NaN;
  const endMs = to && Number.isFinite(Date.parse(to)) ? Date.parse(to) : stamps.length ? Math.max(now, ...stamps) : NaN;
  const series: ActivitySeries = {
    from: Number.isFinite(startMs) ? new Date(startMs).toISOString() : null,
    to: Number.isFinite(endMs) ? new Date(endMs).toISOString() : null,
    messages: 0,
    tool_calls: 0,
    buckets: Array.from({ length: buckets }, () => ({ m: 0, c: 0 })),
  };
  if (!Number.isFinite(startMs) || !Number.isFinite(endMs)) return series;
  const span = Math.max(1, endMs - startMs);
  for (const e of events) {
    const t = Date.parse(e.ts);
    if (!Number.isFinite(t)) continue;
    const idx = Math.min(buckets - 1, Math.max(0, Math.floor(((t - startMs) / span) * buckets)));
    if (e.tool === "post") {
      series.messages += 1;
      series.buckets[idx].m += 1;
    } else if (!LIFECYCLE_TOOLS.has(e.tool)) {
      series.tool_calls += 1;
      series.buckets[idx].c += 1;
    }
  }
  return series;
}

export type SwarmPhase = "running" | "done" | "stopped" | "prepared" | "unknown";

export type MarkerInfo = {
  reason?: string;
  at?: string;
  by?: string;
  output?: string;
  idle_seconds?: number;
  locks_released?: number;
};

export type AgentRow = AgentView & {
  callsign: string | null;
  spent_usd: number;
  tokens: number;
  calls: number;
  /** How full this agent's context is, from Pi's own estimate. */
  context_tokens: number;
  context_window: number;
  /** Self-compaction: the ceiling the lines are fractions of (0 when the run had none), the level, the lock. */
  context_ceiling: number;
  context_level: string;
  context_locked: boolean;
  /** Compactions Pi recorded, what they cost, the hand-offs alone, and when each compaction landed. */
  compactions: number;
  compaction_usd: number;
  handoffs: number;
  compaction_at: string[];
  posts: number;
  /** Posts by this agent per thread, for the agent card's THREADS list. */
  thread_posts: Record<string, number>;
  first_event_at: string | null;
  last_event_at: string | null;
  /** Calls that came back as a failure (ok:false, an error, a timeout, a blocked write), with when. */
  failures: number;
  failure_at: string[];
  marker_info: MarkerInfo | null;
};

export type WorkFile = {
  path: string;
  name: string;
  bytes: number;
  mtime: string;
  kind: "html" | "svg" | "image" | "text" | "json" | "binary";
  previewable: boolean;
};

export type ThreadRow = SwarmDetail["threads"][number] & {
  created_by: string | null;
  created_at: string | null;
  /** Every post as a dot, so the list can draw who spoke when. */
  activity: ThreadDot[];
};

export type TimedPost = PostRecord & { at: string | null };

export type SentinelInfo = {
  by?: string;
  output?: string;
  reason?: string;
  at?: string;
};

/** A forged tool with how the swarm has used it. */
/** The read-only inputs a swarm was given, with what the trace says about them. */
export type InputsView = {
  source: string;
  copied_at: string;
  files: InputFile[];
  bytes: number;
  /** What the operator asked for: auto | on | off. */
  enforce: string;
  /** What the kickoff could set up: seatbelt | mountns | none. */
  guard: string;
  /** What the panes measured at session start: kernel | mode | none, per agent. */
  enforced: Record<string, string>;
  violations: SwarmEvent[];
  /** The latest inputs_check line, if an agent has called done. */
  check: { ok: boolean; content_ok: boolean; checked: number; modified: string[]; metadata: string[]; missing: string[]; added: string[]; by: string; at: string } | null;
};

/** A pack as the run carried it: what the record says, plus the inventory read
 *  back from the installed pack so the console can show what went unused. */
export type PackView = {
  id: string;
  version: string;
  manifest_sha256: string;
  /** False when the pack has since been removed or replaced on this host. */
  installed: boolean;
  name: string;
  description: string;
  skills: Array<{ id: string; title: string; when: string }>;
  tools: string[];
};

export type ForgedToolRow = ForgedToolManifest & {
  calls: number;
  failures: number;
  users: string[];
  last_used_at: string | null;
};

export type SwarmView = Omit<SwarmDetail, "summary" | "agents" | "threads"> & {
  summary: SwarmRow;
  agents: AgentRow[];
  threads: ThreadRow[];
  /**
   * `goal` is the rendered SWARM.md the agents work from. This is the goal
   * document the operator submitted — the part worth carrying into the next
   * run or keeping in the library.
   */
  goal_document: string;
  registry: RegistryRun | null;
  work: WorkFile[];
  layout: Record<string, unknown> | null;
  violations: SwarmEvent[];
  sentinel_info: SentinelInfo | null;
  activity: ActivitySeries;
  /** Tools the agents forged, with usage from the event log. */
  tools: ForgedToolRow[];
  /** The packs this run carried, with everything each one holds, so the console
   *  can say what was consulted and what was carried and never opened. */
  packs: PackView[];
  /** The read-only inputs, or null when the swarm was given none. */
  inputs: InputsView | null;
  /** What the agents recorded with `record`: events, indicators, findings. */
  ledger: LedgerView;
  /** What each agent decided to call itself, in its own words. */
  names: NameRecord[];
};

/** ledger/entries.jsonl as the agents wrote it, and whether ledger.md exists. */
export type LedgerView = {
  entries: LedgerEntry[];
  /** True once the harness has rendered ledger/ledger.md. */
  rendered: boolean;
};

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null;
}

async function mtimeIso(path: string): Promise<string | null> {
  try {
    return (await stat(path)).mtime.toISOString();
  } catch {
    return null;
  }
}

async function exists(path: string): Promise<boolean> {
  try {
    await stat(path);
    return true;
  } catch {
    return false;
  }
}

function parseFrontMatter(text: string): Record<string, string> {
  const match = text.match(/^---\n([\s\S]*?)\n---/);
  if (!match) return {};
  const attrs: Record<string, string> = {};
  for (const line of match[1].split("\n")) {
    const idx = line.indexOf(":");
    if (idx === -1) continue;
    attrs[line.slice(0, idx).trim()] = line.slice(idx + 1).trim();
  }
  return attrs;
}

export function derivePhase(state: string, done: boolean): SwarmPhase {
  if (done) return "done";
  if (state === "running") return "running";
  if (state === "stopped") return "stopped";
  if (state === "prepared") return "prepared";
  return "unknown";
}

async function countMarkers(sandbox: string, ids: string[]): Promise<{ done: number; dead: number }> {
  let done = 0;
  let dead = 0;
  for (const id of ids) {
    if (await exists(agentDonePath(sandbox, id))) done += 1;
    else if (await exists(agentDeadPath(sandbox, id))) dead += 1;
  }
  return { done, dead };
}

/** The event log from the protocol's own cache: parsed once per change, shared, never mutated here. */
function readEvents(sandbox: string): Promise<readonly SwarmEvent[]> {
  return readEventLog(sandbox);
}

export async function findRun(runsDir: string, id: string): Promise<RegistryRun | null> {
  const runs = await loadRegistry(runsDir);
  const run = runs.find((r) => isRecord(r) && r.id === id);
  return run ? (run as RegistryRun) : null;
}

async function enrichSummary(
  runsDir: string,
  summary: SwarmSummary,
  runsById: Map<string, RegistryRun>,
  now: number,
): Promise<SwarmRow> {
  const run = runsById.get(summary.id);
  const sandbox = summary.sandbox;
  const toolsForged = await countForgedTools(sandbox);
  const inputsSource = (await readInputsManifest(sandbox).catch(() => null))?.source ?? null;
  const budgetRaw = await readFile(join(sandbox, "budget.json"), "utf8").catch(() => "{}");
  let started = run?.started_at ?? "";
  let wall = Number(run?.wall_clock_minutes) || 0;
  let metered = run?.metered !== false;
  let capTokens = Number(run?.cap_tokens) || 0;
  let stopReason: string | null = null;
  try {
    const budget = JSON.parse(budgetRaw) as {
      started_at?: string;
      wall_clock_minutes?: number;
      metered?: boolean;
      cap_tokens?: number;
      stop_reason?: string;
    };
    if (!started && budget.started_at) started = budget.started_at;
    if (!wall && budget.wall_clock_minutes) wall = Number(budget.wall_clock_minutes) || 0;
    if (budget.metered === false) metered = false;
    if (!capTokens && budget.cap_tokens) capTokens = Number(budget.cap_tokens) || 0;
    if (typeof budget.stop_reason === "string" && budget.stop_reason) stopReason = budget.stop_reason;
  } catch {
    // budget missing or torn
  }
  const finishedAt = summary.done ? await mtimeIso(join(sandbox, "done", "SWARM_DONE")) : null;
  const startMs = Date.parse(started);
  const endMs = finishedAt ? Date.parse(finishedAt) : now;
  const elapsed = Number.isFinite(startMs) ? Math.max(0, endMs - startMs) : 0;
  const ids = Array.isArray(run?.agents) ? run!.agents! : [];
  const markers = await countMarkers(sandbox, ids);
  const events = await readEvents(sandbox);
  const violations = events.filter((e) => e.tool === "claim_violation").length;
  const goalText = typeof run?.goal === "string" ? run.goal : "";
  const mainPosts = await readThreadPosts(sandbox, "main").catch(() => [] as PostRecord[]);
  const newest = mainPosts.length ? mainPosts[mainPosts.length - 1] : null;
  const threadNames = (await readdir(join(sandbox, "threads"), { withFileTypes: true }).catch(() => [])).filter((d) => d.isDirectory()).map((d) => d.name);
  let postsTotal = mainPosts.length;
  for (const name of threadNames) {
    if (name === "main") continue;
    postsTotal += (await readThreadPosts(sandbox, name).catch(() => [] as PostRecord[])).length;
  }
  const lastPost = newest
    ? {
        from: newest.from,
        tag: newest.tag,
        body: newest.body.length > 240 ? `${newest.body.slice(0, 239)}…` : newest.body,
        at: await mtimeIso(newest.path),
      }
    : null;
  let sentinelBy: string | null = null;
  if (summary.done) {
    const text = await readFile(join(sandbox, "done", "SWARM_DONE"), "utf8").catch(() => "");
    const fm = parseFrontMatter(text);
    if (fm.by) sentinelBy = fm.by;
    if (!stopReason && fm.reason) stopReason = fm.reason;
  }
  void runsDir;
  return {
    ...summary,
    started_at: started,
    elapsed_ms: elapsed,
    finished_at: finishedAt,
    goal: typeof run?.goal === "string" ? run.goal : "",
    wall_clock_minutes: wall,
    metered,
    cap_tokens: capTokens,
    net: typeof run?.net === "string" ? run.net : "guarded",
    agents_total: ids.length || summary.n,
    agents_done: markers.done,
    agents_dead: markers.dead,
    violations,
    last_post: lastPost,
    checks_total: countChecks(goalText),
    threads_total: threadNames.length,
    posts_total: postsTotal,
    phase: derivePhase(summary.state, summary.done),
    sentinel_by: sentinelBy,
    stop_reason: stopReason,
    tools_forged: toolsForged,
    inputs_source: inputsSource,
  };
}

export async function listSwarmRows(runsDir: string, now = Date.now()): Promise<SwarmRow[]> {
  const [summaries, runs] = await Promise.all([listSwarmSummaries(runsDir), loadRegistry(runsDir)]);
  const byId = new Map<string, RegistryRun>();
  for (const run of runs) {
    if (isRecord(run) && typeof run.id === "string") byId.set(run.id, run as RegistryRun);
  }
  const rows: SwarmRow[] = [];
  for (const s of summaries) rows.push(await enrichSummary(runsDir, s, byId, now));
  return rows;
}

export async function listWorkFiles(sandbox: string, maxDepth = 3): Promise<WorkFile[]> {
  const root = join(sandbox, "work");
  const out: WorkFile[] = [];
  async function walk(dir: string, depth: number) {
    const names = await readdir(dir, { withFileTypes: true }).catch(() => []);
    for (const entry of names) {
      if (entry.name === ".gitkeep") continue;
      const abs = join(dir, entry.name);
      if (entry.isDirectory()) {
        if (depth < maxDepth) await walk(abs, depth + 1);
        continue;
      }
      if (!entry.isFile()) continue;
      const info = await stat(abs).catch(() => null);
      if (!info) continue;
      const rel = relative(root, abs).split(sep).join("/");
      const kind = artifactKind(entry.name);
      out.push({
        path: `work/${rel}`,
        name: rel,
        bytes: info.size,
        mtime: info.mtime.toISOString(),
        kind,
        previewable: kind !== "binary",
      });
    }
  }
  await walk(root, 0);
  return out.sort((a, b) => a.name.localeCompare(b.name));
}

export type WorkFileError = { error: 400 | 404 | 409; message: string };

/**
 * Open a work/ artifact for the unauthenticated GET. Lexical escape is 400;
 * a missing file is 404; a symlink or a realpath outside work/ is 409 so a
 * pane's `ln -s /etc/passwd work/leak.txt` cannot be read from the console.
 */
export async function resolveWorkFile(sandbox: string, rel: string): Promise<string | WorkFileError> {
  return resolveSandboxFile(sandbox, "work", rel, "artifact");
}

/**
 * The whole output of a tool call, kept under tool-output/ when the model
 * received a prefix. Same checks as an artifact: the directory is written by
 * the harness, but a shell can plant a link there, and the route is open.
 */
export async function resolveToolOutputFile(sandbox: string, rel: string): Promise<string | WorkFileError> {
  return resolveSandboxFile(sandbox, "tool-output", rel, "tool output");
}

async function resolveSandboxFile(sandbox: string, dir: "work" | "tool-output", rel: string, what: string): Promise<string | WorkFileError> {
  const root = resolve(sandbox, dir);
  const lexical = resolve(root, rel);
  const back = relative(root, lexical);
  if (back === "" || back.startsWith("..") || back.split(sep).includes("..")) return { error: 400, message: `path escapes ${dir}/` };
  const st = await lstat(lexical).catch(() => null);
  if (!st) return { error: 404, message: `${what} not found` };
  if (st.isSymbolicLink()) return { error: 409, message: `${what} is a symlink` };
  if (!st.isFile()) return { error: 404, message: `${what} not found` };
  const real = await realpath(lexical).catch(() => null);
  const realSandbox = await realpath(sandbox).catch(() => resolve(sandbox));
  const realRoot = join(realSandbox, dir);
  if (!real || (real !== realRoot && !real.startsWith(`${realRoot}${sep}`))) {
    return { error: 409, message: `${what} is no longer a file inside ${dir}/` };
  }
  return real;
}

const CALLSIGN_PATTERNS = [
  /\b(?:call me|i am|i'm|this is|name(?: is)?:?)\s+["“']?([A-Z][A-Za-z0-9_-]{1,23})["”']?/i,
  /^["“']?([A-Z][A-Za-z0-9_-]{1,23})["”']?\s+(?:here|reporting|checking in)/i,
];

/**
 * Agents tend to name themselves in chat (Scout, Stitch...). The protocol has
 * no callsign field, so this is a heuristic read of the first `intro` post.
 */
export function deriveCallsign(posts: PostRecord[], agentId: string): string | null {
  const intro = posts.find((p) => p.from === agentId && p.tag === "intro");
  if (!intro) return null;
  const firstLine = intro.body.split("\n")[0]?.trim() ?? "";
  for (const re of CALLSIGN_PATTERNS) {
    const m = firstLine.match(re);
    if (m && m[1].toLowerCase() !== agentId.toLowerCase()) return m[1];
  }
  return null;
}

async function readMarkerInfo(sandbox: string, agent: AgentView): Promise<MarkerInfo | null> {
  const file =
    agent.marker === "done"
      ? agentDonePath(sandbox, agent.id)
      : agent.marker === "dead"
        ? agentDeadPath(sandbox, agent.id)
        : null;
  if (!file) return null;
  const text = await readFile(file, "utf8").catch(() => "");
  if (!text) return null;
  const fm = parseFrontMatter(text);
  const info: MarkerInfo = {};
  if (fm.reason) info.reason = fm.reason;
  if (fm.at) info.at = fm.at;
  if (fm.by) info.by = fm.by;
  if (fm.output) info.output = fm.output;
  if (fm.idle_seconds) info.idle_seconds = Number(fm.idle_seconds);
  if (fm.locks_released) info.locks_released = Number(fm.locks_released);
  return info;
}

/** Posts carry no timestamp in their frontmatter; the file mtime is the clock. */
export async function readTimedPosts(sandbox: string, thread: string): Promise<TimedPost[]> {
  const posts = await readThreadPosts(sandbox, thread);
  const out: TimedPost[] = [];
  for (const p of posts) out.push({ ...p, at: await mtimeIso(p.path) });
  return out;
}

/**
 * Every post the swarm wrote, across every thread, in time order.
 *
 * The swarm view ships each thread's `activity` — a timestamp, an author and
 * a tag per post — which is enough to draw a pulse line and nothing else.
 * Anything that reads what was actually said (who named whom, which files the
 * board argued about, where somebody said stop) needs the bodies, and they
 * are too heavy for a view re-read on every change. So they are their own
 * request, made once by the panel that wants them.
 */
export async function readAllPosts(sandbox: string): Promise<TimedPost[]> {
  const names = (await readdir(join(sandbox, "threads"), { withFileTypes: true }).catch(() => []))
    .filter((d) => d.isDirectory())
    .map((d) => d.name);
  const out: TimedPost[] = [];
  for (const name of names) out.push(...(await readTimedPosts(sandbox, name).catch(() => [])));
  // Posts are numbered per thread, so the id breaks a tie within one thread
  // and the clock orders the board as a whole.
  out.sort((a, b) => (a.at ?? "").localeCompare(b.at ?? "") || a.id - b.id);
  return out;
}

export async function readSwarmView(runsDir: string, id: string, traceLimit = 400): Promise<SwarmView | null> {
  const detail = await readSwarmDetail(runsDir, id, traceLimit);
  if (!detail) return null;
  const sandbox = detail.summary.sandbox;
  const run = await findRun(runsDir, id);
  // This swarm's row, enriched the way the list enriches every row — and only
  // this one. The detail view used to rebuild the whole fleet's rows to find
  // its own, which read every sandbox on disk on every request.
  const byId = new Map<string, RegistryRun>();
  if (run) byId.set(id, run);
  const summary = await enrichSummary(runsDir, detail.summary, byId, Date.now());

  const allPosts: TimedPost[] = [];
  const threads: ThreadRow[] = [];
  for (const t of detail.threads) {
    const posts = await readTimedPosts(sandbox, t.name);
    allPosts.push(...posts);
    threads.push({
      ...t,
      created_by: posts[0]?.from ?? null,
      created_at: posts[0]?.at ?? null,
      activity: posts.map((p) => ({ at: p.at, from: p.from, tag: p.tag })),
    });
  }
  // main first, then the busiest thread most recently: what the operator
  // wants to look at is what just moved.
  threads.sort((a, b) => (a.name === "main" ? -1 : b.name === "main" ? 1 : (b.last_at ?? "").localeCompare(a.last_at ?? "") || a.name.localeCompare(b.name)));

  let sentinelInfo: SentinelInfo | null = null;
  if (detail.sentinel) {
    const text = await readFile(join(sandbox, "done", "SWARM_DONE"), "utf8").catch(() => "");
    const fm = parseFrontMatter(text);
    sentinelInfo = { by: fm.by, output: fm.output, reason: fm.reason, at: fm.at };
  }
  const events = await readEvents(sandbox);
  const lastEventByAgent = new Map<string, string>();
  const firstEventByAgent = new Map<string, string>();
  const failuresByAgent = new Map<string, string[]>();
  const compactionsByAgent = new Map<string, string[]>();
  for (const e of events) {
    lastEventByAgent.set(e.agent, e.ts);
    if (!firstEventByAgent.has(e.agent)) firstEventByAgent.set(e.agent, e.ts);
    if (isFailureEvent(e)) (failuresByAgent.get(e.agent) ?? failuresByAgent.set(e.agent, []).get(e.agent)!).push(e.ts);
    if (e.tool === "compact_done") (compactionsByAgent.get(e.agent) ?? compactionsByAgent.set(e.agent, []).get(e.agent)!).push(e.ts);
  }

  const agents: AgentRow[] = [];
  for (const a of detail.agents) {
    const slice = detail.budget.agents[a.id];
    const threadPosts: Record<string, number> = {};
    for (const p of allPosts) if (p.from === a.id) threadPosts[p.thread] = (threadPosts[p.thread] ?? 0) + 1;
    const failureAt = failuresByAgent.get(a.id) ?? [];
    agents.push({
      ...a,
      callsign: deriveCallsign(allPosts, a.id),
      spent_usd: slice?.spent_usd ?? 0,
      tokens: slice?.tokens ?? 0,
      calls: slice?.calls ?? 0,
      context_tokens: slice?.context_tokens ?? 0,
      context_window: slice?.context_window ?? 0,
      context_ceiling: slice?.context_ceiling ?? 0,
      context_level: slice?.context_level ?? "",
      context_locked: slice?.context_locked === true,
      compactions: slice?.compactions ?? 0,
      compaction_usd: slice?.compaction_usd ?? 0,
      handoffs: slice?.handoffs ?? 0,
      compaction_at: compactionsByAgent.get(a.id) ?? [],
      posts: allPosts.filter((p) => p.from === a.id).length,
      thread_posts: threadPosts,
      first_event_at: firstEventByAgent.get(a.id) ?? null,
      last_event_at: lastEventByAgent.get(a.id) ?? null,
      failures: failureAt.length,
      failure_at: failureAt,
      marker_info: await readMarkerInfo(sandbox, a),
    });
  }

  const layoutRaw = await readFile(join(sandbox, "layout.json"), "utf8").catch(() => "");
  let layout: Record<string, unknown> | null = null;
  if (layoutRaw) {
    try {
      layout = JSON.parse(layoutRaw) as Record<string, unknown>;
    } catch {
      layout = null;
    }
  }

  return {
    ...detail,
    summary,
    agents,
    threads,
    // `goal` is the rendered SWARM.md the agents work from; this is the goal
    // document the operator submitted, which is the part worth carrying into
    // the next run or keeping in the library.
    goal_document: typeof run?.goal === "string" ? run.goal : "",
    registry: run,
    work: await listWorkFiles(sandbox),
    layout,
    violations: events.filter((e) => e.tool === "claim_violation"),
    sentinel_info: sentinelInfo,
    activity: activitySeries(events, summary.started_at || null, summary.finished_at),
    tools: await forgedToolRows(sandbox, events),
    packs: await packViews(run),
    inputs: await inputsView(sandbox, events),
    ledger: await ledgerView(sandbox),
    names: await readNames(sandbox).catch(() => []),
  };
}

/** The packs a run carried, joined with what each one holds on this host. */
export async function packViews(run: RegistryRun | null): Promise<PackView[]> {
  const listed = Array.isArray(run?.packs) ? run!.packs! : [];
  if (!listed.length) return [];
  const home = process.env.DFIRSWARM_HOME || join(process.env.HOME || "", ".dfirswarm");
  const out: PackView[] = [];
  for (const p of listed) {
    const dir = join(home, "packs", p.id);
    const view: PackView = {
      id: p.id, version: p.version, manifest_sha256: p.manifest_sha256,
      installed: false, name: p.id, description: "", skills: [], tools: [],
    };
    const manifest = await readFile(join(dir, "pack.json"), "utf8")
      .then((t) => JSON.parse(t) as Record<string, unknown>)
      .catch(() => null);
    if (manifest) {
      view.installed = true;
      if (typeof manifest.name === "string") view.name = manifest.name;
      if (typeof manifest.description === "string") view.description = manifest.description;
    }
    // The index is generated at seal time from every skill's own front matter,
    // so it is the pack's own statement of what it carries.
    const index = await readFile(join(dir, "skills", "INDEX.md"), "utf8").catch(() => "");
    for (const line of index.split("\n")) {
      const m = /^- `([^`]+)`\s+([^:]+):\s*(.*)$/.exec(line.trim());
      if (m) view.skills.push({ id: m[1], title: m[2].trim(), when: m[3].trim() });
    }
    const tools = await readdir(join(dir, "tools"), { withFileTypes: true }).catch(() => []);
    view.tools = tools.filter((d) => d.isDirectory()).map((d) => d.name).sort();
    out.push(view);
  }
  return out;
}

/** The ledger entries, oldest first, and whether the rendered file is there. */
export async function ledgerView(sandbox: string): Promise<LedgerView> {
  const entries = await readLedger(sandbox).catch(() => []);
  const rendered = await stat(join(sandbox, LEDGER_MD)).then((s) => s.isFile()).catch(() => false);
  return { entries, rendered };
}

/** inputs.json joined with the guard, violation and check lines from the trace. */
export async function inputsView(sandbox: string, events: readonly SwarmEvent[]): Promise<InputsView | null> {
  const manifest = await readInputsManifest(sandbox);
  if (!manifest) return null;
  const enforced: Record<string, string> = {};
  for (const e of events) {
    if (e.tool !== "inputs_guard") continue;
    const result = (e.result ?? {}) as { enforced?: unknown };
    if (typeof result.enforced === "string") enforced[e.agent] = result.enforced;
  }
  const checks = events.filter((e) => e.tool === "inputs_check");
  const last = checks.at(-1);
  const lastResult = (last?.result ?? {}) as {
    ok?: unknown;
    content_ok?: unknown;
    checked?: unknown;
    modified?: unknown;
    metadata?: unknown;
    missing?: unknown;
    added?: unknown;
  };
  const strings = (v: unknown): string[] => (Array.isArray(v) ? v.filter((x): x is string => typeof x === "string") : []);
  return {
    source: manifest.source,
    copied_at: manifest.copied_at,
    files: manifest.files,
    bytes: manifest.bytes,
    enforce: manifest.enforce,
    guard: manifest.guard,
    enforced,
    violations: events.filter((e) => e.tool === "inputs_violation"),
    check: last
      ? {
          ok: lastResult.ok === true,
          content_ok: lastResult.content_ok === undefined ? lastResult.ok === true : lastResult.content_ok === true,
          checked: Number(lastResult.checked) || 0,
          modified: strings(lastResult.modified),
          metadata: strings(lastResult.metadata),
          missing: strings(lastResult.missing),
          added: strings(lastResult.added),
          by: last.agent,
          at: last.ts,
        }
      : null,
  };
}

/** Manifests from tools/ joined with the calls the trace recorded under each name. */
export async function forgedToolRows(sandbox: string, events: readonly SwarmEvent[]): Promise<ForgedToolRow[]> {
  const manifests = await listForgedTools(sandbox).catch(() => [] as ForgedToolManifest[]);
  // One pass over the trace, grouped by tool, instead of one filter per manifest.
  const callsByTool = new Map<string, SwarmEvent[]>();
  for (const e of events) {
    if (!isRecord(e.result) || e.result.forged !== true) continue;
    const list = callsByTool.get(e.tool);
    if (list) list.push(e);
    else callsByTool.set(e.tool, [e]);
  }
  return manifests.map((m) => {
    const calls = callsByTool.get(m.name) ?? [];
    return {
      ...m,
      calls: calls.length,
      failures: calls.filter((e) => isRecord(e.result) && e.result.ok === false).length,
      users: [...new Set(calls.map((e) => e.agent))],
      last_used_at: calls.length ? calls[calls.length - 1].ts : null,
    };
  });
}

export type TraceQuery = {
  agent?: string;
  tool?: string;
  q?: string;
  limit?: number;
  order?: "asc" | "desc";
};

export type TracePage = {
  total: number;
  matched: number;
  events: SwarmEvent[];
  agents: string[];
  tools: string[];
  /** Lines and spend per agent over the whole trace, for the filter chips. */
  by_agent: Record<string, { events: number; spent_usd: number }>;
  /**
   * Lines per agent over the *filtered* set — who the matches belong to.
   *
   * `by_agent` deliberately counts the whole trace so the chips do not
   * flicker as a filter narrows. But a caller that asks "which agents
   * produced reasoning?" needs the other number, and answering it by
   * downloading every matching event is a megabyte of prose to count to
   * ten. With `limit=1` this field alone answers it.
   */
  matched_by_agent: Record<string, number>;
};

export async function queryTraces(sandbox: string, query: TraceQuery): Promise<TracePage> {
  const events = await readEvents(sandbox);
  const agents = [...new Set(events.map((e) => e.agent))].sort();
  const tools = [...new Set(events.map((e) => e.tool))].sort();
  const byAgent: TracePage["by_agent"] = {};
  for (const e of events) (byAgent[e.agent] ??= { events: 0, spent_usd: 0 }).events += 1;
  try {
    const budget = JSON.parse(await readFile(join(sandbox, "budget.json"), "utf8")) as { agents?: Record<string, { spent_usd?: number }> };
    for (const [id, slice] of Object.entries(budget.agents ?? {})) {
      if (byAgent[id]) byAgent[id].spent_usd = Number(slice?.spent_usd) || 0;
    }
  } catch {
    // no budget yet: chips show lines only
  }
  let out: readonly SwarmEvent[] = events;
  if (query.agent) out = out.filter((e) => e.agent === query.agent);
  if (query.tool) out = out.filter((e) => e.tool === query.tool);
  if (query.q) {
    const needle = query.q.toLowerCase();
    out = out.filter((e) => JSON.stringify(e).toLowerCase().includes(needle));
  }
  const matched = out.length;
  const matchedByAgent: Record<string, number> = {};
  for (const e of out) matchedByAgent[e.agent] = (matchedByAgent[e.agent] ?? 0) + 1;
  const limit = Math.min(Math.max(1, query.limit ?? 500), 5000);
  // `slice` copies, so the shared cached array is never reversed in place.
  const page = out.slice(-limit);
  return {
    total: events.length,
    matched,
    events: query.order === "desc" ? page.reverse() : page,
    agents,
    tools,
    by_agent: byAgent,
    matched_by_agent: matchedByAgent,
  };
}

/** Directories under tools/ that carry a manifest: the ones `swarm.sh tools --save` would keep. */
export async function countForgedTools(sandbox: string): Promise<number> {
  const dir = join(sandbox, "tools");
  const entries = await readdir(dir, { withFileTypes: true }).catch(() => []);
  let n = 0;
  for (const e of entries) if (e.isDirectory() && existsSync(join(dir, e.name, "manifest.json"))) n += 1;
  return n;
}
