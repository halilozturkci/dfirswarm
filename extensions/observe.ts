/**
 * Read-only swarm view for the LAN debugger.
 * Hierarchy: swarms → threads → agents → traces.
 * No new protocol — only files the spawner and extension already write.
 */
import { readdir, readFile, stat } from "node:fs/promises";
import { join } from "node:path";
import {
  listClaims,
  listFileHistory,
  readThreadMeta,
  normalizeBudget,
  readAgentMarker,
  readEventLog,
  readPost,
  swarmDoneExists,
  type AgentMarker,
  type BudgetRecord,
  type ClaimView,
  type FileVersion,
  type LockRecord,
  type PostRecord,
  type SwarmEvent,
  type TeamRecord,
} from "./protocol.ts";

export type SwarmSummary = {
  id: string;
  label: string;
  state: string;
  workspace_id: string;
  n: number;
  model: string;
  cap_usd: number;
  spent_usd: number;
  tokens: number;
  calls: number;
  sandbox: string;
  done: boolean;
};

/** Idle threads go dark after this long; 2 minutes is a local choice. */
export const DEFAULT_THREAD_DIM_MS = 2 * 60 * 1000;

export type ThreadSummary = {
  name: string;
  posts: number;
  last_from?: string;
  last_tag?: string;
  last_at?: string;
  idle_ms: number;
  dim: boolean;
  /** From threads/<name>/meta.json: who opened it, what for, who reads it. */
  purpose: string;
  opened_by: string | null;
  members: string[];
};

export type AgentView = {
  id: string;
  role: string;
  done: boolean;
  dead: boolean;
  stalled: boolean;
  marker: AgentMarker;
  claims: string[];
};

/** A live claim as the UI shows it: who, why, and how long is left. */
export type ClaimRow = ClaimView;

export type SwarmDetail = {
  summary: SwarmSummary;
  goal: string;
  team: TeamRecord;
  budget: BudgetRecord;
  threads: ThreadSummary[];
  agents: AgentView[];
  locks: LockRecord[];
  /** Live claims only, with the reason and the remaining lease. */
  claims: ClaimRow[];
  sentinel: boolean;
  traces: SwarmEvent[];
  history: Record<string, FileVersion[]>;
};

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null;
}

async function readJson<T>(path: string, fallback: T): Promise<T> {
  try {
    return JSON.parse(await readFile(path, "utf8")) as T;
  } catch {
    return fallback;
  }
}

/** Snapshot history of each top-level entry under work/, keyed by its path; entries with none are left out. */
export async function readHistory(sandbox: string): Promise<Record<string, FileVersion[]>> {
  const history: Record<string, FileVersion[]> = {};
  const workFiles = await readdir(join(sandbox, "work")).catch(() => []);
  for (const name of workFiles) {
    const rel = `work/${name}`;
    const versions = await listFileHistory(sandbox, rel);
    if (versions.length) history[rel] = versions;
  }
  return history;
}

export async function loadRegistry(runsDir: string): Promise<Record<string, unknown>[]> {
  const raw = await readJson<{ runs?: Record<string, unknown>[] }>(join(runsDir, "registry.json"), {
    runs: [],
  });
  return raw.runs ?? [];
}

/** One registry run as a summary: the registry's own fields plus the live budget and the sentinel. */
async function summaryOf(runsDir: string, run: Record<string, unknown>): Promise<SwarmSummary | null> {
  if (typeof run.id !== "string") return null;
  const sandbox = typeof run.sandbox === "string" ? run.sandbox : join(runsDir, run.id);
  const budget = normalizeBudget(await readJson(join(sandbox, "budget.json"), {}));
  return {
    id: run.id,
    label: typeof run.label === "string" ? run.label : run.id,
    state: typeof run.state === "string" ? run.state : "unknown",
    workspace_id: typeof run.workspace_id === "string" ? run.workspace_id : "",
    n: Number(run.n) || 0,
    model: typeof run.model === "string" ? run.model : "",
    cap_usd: budget.cap_usd,
    spent_usd: budget.spent_usd,
    tokens: budget.tokens,
    calls: budget.calls,
    sandbox,
    done: await swarmDoneExists(sandbox),
  };
}

export async function listSwarmSummaries(runsDir: string): Promise<SwarmSummary[]> {
  const runs = await loadRegistry(runsDir);
  const out: SwarmSummary[] = [];
  for (const run of runs) {
    if (!isRecord(run)) continue;
    const summary = await summaryOf(runsDir, run);
    if (summary) out.push(summary);
  }
  return out.reverse();
}

/**
 * A thread's posts, served from memory while the directory has not moved.
 * Posts are append-only files that land by rename, so the directory's mtime
 * changes whenever one arrives and the files themselves never change; an
 * entry is still dropped after a couple of seconds, so a host whose clock
 * is coarse cannot hide a post behind an identical timestamp for long. The
 * array is shared: callers read it and never change it.
 */
const threadPostsCache = new Map<string, { mtimeMs: number; ctimeMs: number; at: number; posts: readonly PostRecord[] }>();
const THREAD_POSTS_CACHE_MS = 2_000;
const THREAD_POSTS_CACHE_MAX = 256;

export async function readThreadPosts(sandbox: string, thread: string): Promise<readonly PostRecord[]> {
  const dir = join(sandbox, "threads", thread);
  const info = await stat(dir).catch(() => null);
  if (!info) {
    threadPostsCache.delete(dir);
    return [];
  }
  const hit = threadPostsCache.get(dir);
  if (hit && hit.mtimeMs === info.mtimeMs && hit.ctimeMs === info.ctimeMs && Date.now() - hit.at < THREAD_POSTS_CACHE_MS) return hit.posts;
  const names = await readdir(dir).catch(() => []);
  const files = names.filter((n) => /^\d{6}-.+\.md$/.test(n)).sort();
  const posts: PostRecord[] = [];
  for (const name of files) {
    posts.push(await readPost(join(dir, name)));
  }
  if (threadPostsCache.size >= THREAD_POSTS_CACHE_MAX) threadPostsCache.clear();
  threadPostsCache.set(dir, { mtimeMs: info.mtimeMs, ctimeMs: info.ctimeMs, at: Date.now(), posts });
  return posts;
}

export async function readSwarmDetail(
  runsDir: string,
  id: string,
  traceLimit = 200,
): Promise<SwarmDetail | null> {
  const runs = await loadRegistry(runsDir);
  const run = runs.find((r) => isRecord(r) && r.id === id);
  if (!run || !isRecord(run)) return null;
  const sandbox = typeof run.sandbox === "string" ? run.sandbox : join(runsDir, id);
  // This swarm's summary alone: the detail view used to build every swarm's
  // to find its own, which read every sandbox on disk per request.
  const summary = await summaryOf(runsDir, run);
  if (!summary) return null;

  const team = await readJson<TeamRecord>(join(sandbox, "team.json"), {
    swarm_id: id,
    n: 0,
    agents: [],
  });
  const budget = normalizeBudget(await readJson(join(sandbox, "budget.json"), {}));
  const goal = await readFile(join(sandbox, "SWARM.md"), "utf8").catch(() => "");

  const threadNames = await readdir(join(sandbox, "threads")).catch(() => []);
  const threads: ThreadSummary[] = [];
  const dimMs = Number(process.env.SWARM_THREAD_DIM_MS) || DEFAULT_THREAD_DIM_MS;
  for (const name of threadNames) {
    const posts = await readThreadPosts(sandbox, name);
    const last = posts.at(-1);
    let lastAt: string | undefined;
    let idleMs = 0;
    if (last?.path) {
      const st = await stat(last.path);
      lastAt = st.mtime.toISOString();
      idleMs = Date.now() - st.mtimeMs;
    }
    const tagDim = last?.tag === "hold" || last?.tag === "veto" || last?.tag === "stop";
    const meta = await readThreadMeta(sandbox, name);
    threads.push({
      name,
      posts: posts.length,
      last_from: last?.from,
      last_tag: last?.tag,
      last_at: lastAt,
      idle_ms: idleMs,
      dim: Boolean(tagDim || (last && idleMs >= dimMs)),
      purpose: meta?.purpose ?? "",
      opened_by: meta?.created_by ?? posts[0]?.from ?? null,
      members: meta?.members ?? [],
    });
  }

  const lockFiles = await readdir(join(sandbox, "locks")).catch(() => []);
  const locks: LockRecord[] = [];
  for (const name of lockFiles) {
    if (!name.endsWith(".json")) continue;
    locks.push(await readJson<LockRecord>(join(sandbox, "locks", name), {
      path: "",
      owner: "",
      reason: "",
      seconds: 0,
      claimed_at: "",
      expires_at: "",
    }));
  }

  const agents: AgentView[] = [];
  for (const a of team.agents ?? []) {
    const marker = await readAgentMarker(sandbox, a.id);
    agents.push({
      id: a.id,
      role: a.role,
      done: marker === "done",
      dead: marker === "dead",
      stalled: marker === "stalled",
      marker,
      claims: locks.filter((l) => l.owner === a.id).map((l) => l.path),
    });
  }

  const traces: SwarmEvent[] = (await readEventLog(sandbox)).slice(-traceLimit);

  const history = await readHistory(sandbox);

  return {
    summary,
    goal,
    team,
    budget,
    threads,
    agents,
    locks,
    claims: await listClaims(sandbox),
    sentinel: await swarmDoneExists(sandbox),
    traces,
    history,
  };
}
