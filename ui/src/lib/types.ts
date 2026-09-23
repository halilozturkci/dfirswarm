/** Wire types. Mirrors scripts/ui/model.ts + extensions/*.ts; keep in sync by hand. */

export type SwarmPhase = "running" | "done" | "stopped" | "prepared" | "unknown";
export type AgentMarker = "done" | "dead" | "stalled" | "active";
export type PostTag = "intro" | "ask" | "claim" | "result" | "hold" | "veto" | "stop";

export type SwarmRow = {
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
  started_at: string;
  elapsed_ms: number;
  finished_at: string | null;
  goal: string;
  wall_clock_minutes: number;
  /** False when no model on the team bills: spend is an exact zero and cap_tokens is the brake. */
  metered: boolean;
  cap_tokens: number;
  /** guarded · hosts · open · local */
  net: string;
  agents_total: number;
  agents_done: number;
  agents_dead: number;
  violations: number;
  /** The newest post on threads/main — what the swarm last said. */
  last_post: { from: string; tag: string; body: string; at: string | null } | null;
  /** How many `## Checks` the goal defines. */
  checks_total: number;
  /** Threads on the board and posts across all of them. */
  threads_total: number;
  posts_total: number;
  phase: SwarmPhase;
  /** Frontmatter `by` on done/SWARM_DONE, when the swarm is finished. */
  sentinel_by: string | null;
  /** budget.json stop_reason (cap / wall_clock), when the harness steered or stopped. */
  stop_reason: string | null;
  /** Tools the run forged and kept a manifest for: what a next swarm can start with. */
  tools_forged: number;
  /** The evidence directory the run was given, or null: what a clean room is about. */
  inputs_source: string | null;
};

/** One post as a dot on a thread's pulse line. */
export type ThreadDot = { at: string | null; from: string; tag: string };

/** Messages against tool calls over the swarm's lifetime, bucketed. */
export type ActivitySeries = {
  from: string | null;
  to: string | null;
  messages: number;
  tool_calls: number;
  buckets: Array<{ m: number; c: number }>;
};

export type ProviderReadiness = {
  /** `local`: a server on this machine or network that Pi will not list until models.json gives it a placeholder apiKey. */
  status: "ready" | "not_ready" | "invalid" | "unknown" | "local";
  /** Served from this machine or network: no key to log in with, no metered cost. */
  local?: boolean;
  base_url?: string;
  provider: string;
  auth_type?: string;
  reason?: string;
};

/** Which providers `pi auth check` says are usable, keyed by provider. */
export type ReadinessReport = { checked_at: string; providers: Record<string, ProviderReadiness> };

/** The goal's checks, run in the sandbox the way await-done.sh certifies a run. */
export type ChecksReport = {
  sentinel: boolean;
  source: "registry" | "sandbox contract" | null;
  total: number;
  passed: number;
  checks: Array<{ cmd: string; ok: boolean; ms: number; timed_out: boolean }>;
  error?: string;
};

export type ThreadRow = {
  name: string;
  posts: number;
  last_from?: string;
  last_tag?: string;
  last_at?: string;
  idle_ms: number;
  dim: boolean;
  created_by: string | null;
  created_at: string | null;
  purpose: string;
  opened_by: string | null;
  members: string[];
  activity: ThreadDot[];
};

export type MarkerInfo = {
  reason?: string;
  at?: string;
  by?: string;
  output?: string;
  idle_seconds?: number;
  locks_released?: number;
};

export type AgentRow = {
  id: string;
  role: string;
  done: boolean;
  dead: boolean;
  stalled: boolean;
  marker: AgentMarker;
  claims: string[];
  callsign: string | null;
  spent_usd: number;
  tokens: number;
  calls: number;
  context_tokens: number;
  context_window: number;
  /** The ceiling the self-compaction lines are fractions of; 0 when the run had none. */
  context_ceiling: number;
  /** idle · notice · warning · forced against that ceiling; "" when unknown. */
  context_level: string;
  /** True while every tool but self_compact, budget and done is refused. */
  context_locked: boolean;
  /** Compactions Pi recorded (hand-offs and its own fallbacks), what they cost, and the hand-offs alone. */
  compactions: number;
  compaction_usd: number;
  handoffs: number;
  /** When each compaction landed, for the ticks on the activity span. */
  compaction_at: string[];
  posts: number;
  thread_posts: Record<string, number>;
  first_event_at: string | null;
  last_event_at: string | null;
  failures: number;
  failure_at: string[];
  marker_info: MarkerInfo | null;
};

export type LockRecord = {
  path: string;
  owner: string;
  reason: string;
  seconds: number;
  claimed_at: string;
  expires_at: string;
};

/** A live claim: the lock plus how long is left on the lease. */
export type ClaimRow = LockRecord & { expires_in_seconds: number };

export type SwarmEvent = {
  ts: string;
  agent: string;
  tool: string;
  args: Record<string, unknown>;
  result: unknown;
};

export type AgentBudget = {
  /** The model this seat runs, as the kickoff wrote it; what a per-model cap is summed over. */
  model?: string;
  spent_usd: number;
  tokens: number;
  calls: number;
  input: number;
  output: number;
  cache_read: number;
  cache_write: number;
  /** Context occupancy from Pi's own estimate, when the agent has reported one. */
  context_tokens?: number;
  context_window?: number;
  /** Self-compaction: the ceiling the lines are fractions of, the level against it, the lock. */
  context_ceiling?: number;
  context_level?: string;
  context_locked?: boolean;
  /** Compactions Pi recorded in the session (hand-offs and its own fallbacks), and what they cost. */
  compactions?: number;
  compaction_tokens?: number;
  compaction_usd?: number;
  /** Hand-offs completed through self_compact: the note came back. */
  handoffs?: number;
};

/** The kickoff's self-compaction options, as the registry records them. Absent on runs older than the feature. */
export type SelfCompactOptions = {
  enabled: boolean;
  notice_at: string;
  warn_at: string;
  compact_at: string;
  prompt: string | null;
  /** The model every summary call goes to; null means each agent's own. Absent on runs older than the option. */
  model?: string | null;
  /** Which lines the operator set; an unset one is a default fitted to them per seat. Absent on older runs. */
  set?: { notice_at: boolean; warn_at: boolean; compact_at: boolean };
};

export type BudgetRecord = {
  cap_usd: number;
  spent_usd: number;
  tokens: number;
  calls: number;
  wall_clock_minutes: number;
  started_at: string;
  source: string;
  hard_kill: boolean;
  cap_steer_sent: boolean;
  /** Set once when the swarm is first steered to stop, and why. */
  stop_steer_at?: string;
  stop_reason?: "cap" | "wall_clock";
  /** Each agent's own cap, when the kickoff set one (--cap-per-agent). */
  cap_per_agent_usd?: number;
  /** A ceiling per model on what every agent running it spends together. */
  cap_per_model_usd?: Record<string, number>;
  /** False when no model on the team bills; the brake is then cap_tokens. */
  metered?: boolean;
  cap_tokens?: number;
  agents: Record<string, AgentBudget>;
};

export type FileVersion = {
  rev: number;
  ts: string;
  agent: string;
  path: string;
  bytes: number;
  sha256: string;
};

export type WorkFile = {
  path: string;
  name: string;
  bytes: number;
  mtime: string;
  kind: "html" | "svg" | "image" | "text" | "json" | "binary";
  previewable: boolean;
};

/** One file under work/, hashed. GET /api/swarms/:id/artifacts. */
export type ArtifactEntry = {
  path: string;
  bytes: number;
  mtime: string;
  sha256: string;
  kind: WorkFile["kind"];
  /** False for work/extracted and work/quarantine: hashed, never shipped. */
  packaged: boolean;
  revisions: number;
  last_written_by: string | null;
};

export type ArtifactIndex = {
  generated_at: string;
  files: ArtifactEntry[];
  bytes: number;
  packaged_bytes: number;
  unpackaged_dirs: string[];
  skipped: Array<{ path: string; reason: string }>;
};

/** One file of the handover. GET /api/swarms/:id/dossier. */
export type DossierFile = {
  name: string;
  description: string;
  present: boolean;
  reason?: string;
  bytes: number | null;
  sha256: string | null;
  type: string;
};

/**
 * The handover as one product: the report the tab frames, the artifact
 * index, and every downloadable file with the hash of the bytes it is.
 */
export type Dossier = {
  html: string;
  summary: string;
  artifactsJson: string;
  artifacts: ArtifactIndex;
  files: DossierFile[];
};

export type SentinelInfo = { by?: string; output?: string; reason?: string; at?: string };

export type SwarmView = {
  summary: SwarmRow;
  /** The rendered SWARM.md: the goal document plus the harness frame. */
  goal: string;
  /** Just the goal document the operator submitted, from the registry. */
  goal_document: string;
  team: { swarm_id: string; n: number; models?: string[]; agents: Array<{ id: string; role: string; model?: string }> };
  budget: BudgetRecord;
  threads: ThreadRow[];
  agents: AgentRow[];
  locks: LockRecord[];
  claims: ClaimRow[];
  sentinel: boolean;
  sentinel_info: SentinelInfo | null;
  traces: SwarmEvent[];
  history: Record<string, FileVersion[]>;
  registry: (Record<string, unknown> & { tool_forging?: boolean; self_compact?: SelfCompactOptions; inbox_page_chars?: number; inputs?: { source: string; files: number; bytes: number; enforce: string; guard: string } | null }) | null;
  work: WorkFile[];
  layout: Record<string, unknown> | null;
  violations: SwarmEvent[];
  activity: ActivitySeries;
  tools: ForgedTool[];
  /** The packs this run carried, each with everything it holds, so the console
   *  can say what the swarm consulted and what it carried and never opened. */
  packs: PackView[];
  /** The read-only inputs, or null when the swarm was given none. */
  inputs: InputsView | null;
  /** What the agents recorded with `record`: events, indicators, findings. */
  ledger: LedgerView;
  /** What each agent decided to call itself; nothing here was assigned. */
  names?: Array<{ id: string; name: string; doing?: string; at: string }>;
};

/** One `record` call, as the harness stored it in ledger/entries.jsonl. */
export type LedgerEntry = {
  seq: number;
  kind: "event" | "ioc" | "finding";
  /** ISO 8601 UTC for an event; absent for the other kinds. */
  ts?: string;
  value: string;
  /** Where it was seen: a path, a log, a plugin, a registry key. */
  source?: string;
  /** How to check it: the command, the inode, the record id, the hash. */
  evidence?: string;
  confidence?: "high" | "medium" | "low";
  by: string;
  authors: string[];
  at: string;
};

export type LedgerView = {
  entries: LedgerEntry[];
  /** True once the harness has rendered ledger/ledger.md. */
  rendered: boolean;
};

/** A file under inputs/ as the kickoff recorded it. */
export type InputFile = { path: string; bytes: number; sha256: string };

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
  /** What each pane measured at session start: kernel | mode | none. */
  enforced: Record<string, string>;
  violations: SwarmEvent[];
  check: { ok: boolean; content_ok: boolean; checked: number; modified: string[]; metadata: string[]; missing: string[]; added: string[]; by: string; at: string } | null;
};

/** A directory under one of the server's inputs roots that a kickoff may hand a swarm. `id` is what the kickoff sends. */
export type InputSet = { id: string; name: string; root: string; root_index: number; files: number; bytes: number; sample: string[]; images: string[] };

/** One place the server looks for sets: named when it started, or added from the form. */
export type InputsRoot = { path: string; source: "env" | "ui"; ok: boolean };

/** What `GET /api/inputs` answers. */
export type InputsLibrary = {
  configured: boolean;
  root: string | null;
  roots: InputsRoot[];
  sets: InputSet[];
  /** Whether this server takes a new root from the form (`swarm.sh ui --allow-inputs-root-from-ui`). */
  runtime_roots: boolean;
};

/** A tool an agent wrote with make_tool, as the server lists it with its usage. */
export type ForgedTool = {
  name: string;
  description: string;
  params: Record<string, { type: string; description?: string; required?: boolean; enum?: string[] }>;
  runtime: "python3" | "node" | "bash";
  entry: string;
  timeout_seconds: number;
  example?: string;
  by: string;
  at: string;
  version: number;
  sha256: string;
  /** The pack it came from, or absent when an agent forged it during the run. */
  pack?: string;
  calls: number;
  failures: number;
  users: string[];
  last_used_at: string | null;
};

/** A pack as a run carried it, joined with its inventory on this host. */
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

export type ForgedToolSource = { id: string; manifest: Omit<ForgedTool, "calls" | "failures" | "users" | "last_used_at">; script: string };

export type TimedPost = {
  id: number;
  thread: string;
  from: string;
  to: string;
  tag: PostTag;
  body: string;
  path: string;
  at: string | null;
  /** What the author calls itself, as the post recorded it. */
  name?: string;
};

export type TracePage = {
  total: number;
  matched: number;
  events: SwarmEvent[];
  agents: string[];
  tools: string[];
  by_agent: Record<string, { events: number; spent_usd: number }>;
  /** Lines per agent over the filtered set — who the matches belong to. */
  matched_by_agent: Record<string, number>;
};

export type Job = {
  id: string;
  kind: "start" | "stop" | "reap";
  argv: string[];
  status: "running" | "ok" | "failed";
  exit_code: number | null;
  stdout: string;
  stderr: string;
  started_at: string;
  finished_at: string | null;
  swarm_id: string | null;
};

export type LocalModel = { model: string; provider: string; base_url: string; has_key: boolean; metered: boolean };

export type ModelList = { source: "pi" | "static"; models: string[]; local?: LocalModel[] };

export type Health = {
  ok: boolean;
  runs_dir: string;
  /** True when start / stop / reap / restore need the server token. */
  auth: boolean;
  watching: boolean;
  sse_clients: number;
  jobs: number;
  /** How many times this process has run a swarm's finish line in the shell. */
  checks_runs: number;
  now: string;
};

/** What kind of thing moved under a sandbox; mirrors `ChangeKind` in `scripts/ui/watch.ts` (the suppressed kinds never reach a client). */
export type ChangeKind =
  | "registry"
  | "threads"
  | "locks"
  | "done"
  | "budget"
  | "events"
  | "history"
  | "work"
  | "team"
  | "tools"
  | "ledger"
  | "names"
  | "inputs"
  | "contract"
  | "other";

export type ChangeEvent = {
  swarm_ids: string[];
  kinds: string[];
  /** What moved, per swarm. Absent from a server that predates it: then every swarm named gets every kind. */
  by_swarm?: Record<string, string[]>;
  at: string;
  watching?: boolean;
};

/** A goal document in the library under `prompts/goals/`. */
export type GoalSummary = {
  name: string;
  title: string;
  bytes: number;
  updated_at: string;
  has_definition_of_done: boolean;
  checks: number;
};

export type GoalDocument = GoalSummary & { text: string };

/** One investigation in the library under `library/<category>/`, as the picker lists it. */
export type LibraryEntry = {
  id: string;
  category: string;
  slug: string;
  title: string;
  summary: string;
  evidence: string[];
  os: string;
  tags: string[];
  inputs: string;
  seats?: number;
  cap_usd?: number;
  wall_clock?: number;
  checks: number;
  has_definition_of_done: boolean;
  bytes: number;
  updated_at: string;
};

/** The entry with its goal document, metadata block already removed. */
export type LibraryDocument = LibraryEntry & { text: string };

/** The rendered SWARM.md a running swarm is working under. Read-only. */
export type SwarmContract = {
  id: string;
  text: string;
  bytes: number;
  updated_at: string;
};

/** What the panes may reach: the allowlist, the allowlist plus hosts, or everything. */
export type NetMode = "guarded" | "hosts" | "open" | "local";
