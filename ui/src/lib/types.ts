/** Wire types. Mirrors scripts/ui/model.ts + extensions/*.ts; keep in sync by hand. */
import type { VmTimeline } from "./vm-timeline.ts";

/**
 * `finish_failed`: the hub reached the end of a VM run and could not put its
 * VMs away. `stop_incomplete`: swarm.sh stop ran and a VM of the run was
 * still up after it.
 */
export type SwarmPhase = "running" | "done" | "stopped" | "prepared" | "failed" | "finish_failed" | "stop_incomplete" | "unknown";
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
  /** guarded · hosts · open · local for a host run; vm (each VM denies by default) · vm-open for a microVM run. */
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
  /** A VM run whose sentinel is written and whose VMs are not all put away yet (the hub waiting for its agents, or finishing). */
  finishing: boolean;
  /** Frontmatter `by` on done/SWARM_DONE, when the swarm is finished. */
  sentinel_by: string | null;
  /** budget.json stop_reason (cap / wall_clock), when the harness steered or stopped. */
  stop_reason: string | null;
  /** Tools the run forged and kept a manifest for: what a next swarm can start with. */
  tools_forged: number;
  /** The evidence directory the run was given, or null: what a clean room is about. */
  inputs_source: string | null;
  /** Where the agents ran; a record from before isolation was recorded is a host run. Absent from an older server. */
  isolation?: "microvm" | "host";
  /** The last custody verdict, or null before any stop or hub finish took one. */
  custody?: "clean" | "attention" | null;
  /** A legal hold, with its reason. */
  hold?: { reason: string | null; at: string | null } | null;
  /** A running VM run whose hub is down with nothing to bring it back. */
  hub_down?: boolean | null;
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
  /** The hosts a microVM would be told of for this provider; empty when none is known, or for a local server. */
  vm_hosts?: string[];
  /** What the microVM kickoff refuses about this provider; empty when it can go into a VM. */
  vm_blockers?: VmBlocker[];
};

/** One reason the microVM kickoff refuses a provider, and the form setting that lifts it (none for a provider that signs its own requests). */
export type VmBlocker = {
  kind: "oauth" | "signing" | "unknown_host";
  lifted_by?: "allow_oauth_in_vm" | "provider_hosts";
  reason: string;
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
  /** The sender's clock: in a VM, the guest's. */
  ts: string;
  /** The collector's clock, the host's, when the line reached it. */
  recv_ts?: string;
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
  /** What the seat's other Pi sessions spent; the counters above include it. */
  earlier_sessions?: SessionCounters;
  /** The Pi session the live counters come from, when Pi gave an id. */
  session_id?: string;
  /** Each session's last report, by session id; the counters above are their sum. */
  sessions?: Record<string, SessionCounters>;
};

/** A Pi session's counters as the budget fold carries them (see extensions/protocol.ts). */
export type SessionCounters = {
  spent_usd: number;
  tokens: number;
  calls: number;
  input: number;
  output: number;
  cache_read: number;
  cache_write: number;
  compactions?: number;
  compaction_tokens?: number;
  compaction_usd?: number;
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
  cap_per_agent_tokens?: number;
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

/** One agent's VM as the console shows it: its record, and the hub's live word on it. */
export type VmHealth = {
  agent: string;
  name: string | null;
  image: { ref: string | null; digest: string | null; expected: string | null };
  cpus: number | null;
  memory_mib: number | null;
  /** What the kickoff's probe found in the VM. */
  probe: { hub: boolean; floor: string | null; inputs: string | null; clock_skew_s: number | null; fuse: boolean | null; loop: boolean | null; missing: string[] };
  fit_warnings: string[];
  /** The hub's word on this agent and when it last heard from the VM; null when no hub answers. What a dead hub last wrote, when hub_alive is false. */
  live: { state: string; connected: boolean; since: string | null; last_seen: string | null; detail?: string | null } | null;
  /** Each isolation check the kickoff's probe made, by the kickoff's own rules. */
  probe_checks?: Array<{ check: string; want: string; got: string; ok: boolean; meaning?: string }>;
  /** The run's hub, the same on every VM: up and the author of the status shown; null when none is recorded (before kickoff started it, after stop). */
  hub_alive: boolean | null;
  hub_detail: string | null;
  /** ok; warn: down but being brought back, or ended by the stop; danger: down and nothing brings it back. */
  hub_tone: "ok" | "warn" | "danger" | null;
  /** The hub's keeper (hub-supervise.sh), which restarts a dead hub until the stop; null when none is recorded. */
  hub_keeper_alive: boolean | null;
  /** The run's stop has begun. */
  hub_stop_begun: boolean;
  /** The hub is putting the VMs away and taking custody (its status: finished, not yet finish_done). */
  hub_finishing: boolean;
  /** The hub finished the run and exited on its own: not a hub that is down. */
  hub_ended?: boolean;
  hub_restarts?: number;
  collector_restarts?: number;
  /** When the keeper gave up on a hub that kept dying at once, or null. */
  keeper_gave_up_at?: string | null;
  /** What the hub refused this seat, by call, with counts. */
  refusals?: Array<{ fn: string; count: number; last_error: string; last_at: string }>;
  /** When the hub stopped this seat at its own spend cap. */
  cap_stopped_at?: string | null;
  created_at?: string | null;
  max_duration_sec?: number | null;
  /** Seconds since the hub last wrote its status; it writes on changes, not on a clock. */
  hub_status_age_s: number | null;
  mounts: Array<{ host: string; guest: string; mode: string; noexec: boolean }>;
  /** deny (plus allow_hosts) or public (--no-netguard). */
  network: { default: string; allow_hosts: string[]; host_ports: number[] } | null;
  /** Credentials bound to this VM as placeholders, each with the only hosts it is swapped in for. */
  secrets: Array<{ name: string; hosts: string[] }>;
  /** Each pack's secrets and what the kickoff did with them: injected, withheld, exposed, not-set. */
  pack_secrets: Array<{ pack: string; names: string[]; mode: string }>;
  stopped_at: string | null;
  snapshot: "kept" | "not kept" | "failed" | null;
  /** The disk kept at stop, or why it was not. */
  snapshot_detail?: { path: string | null; bytes: number | null; sha256: string | null; integrity: boolean | null; error: string | null; retry_error: string | null } | null;
  /** Why the VM was kept rather than put away, in the finish's words. */
  kept?: string | null;
  /** What the finish did to msb's database: scrubbed, busy, no sqlite3, no database. */
  msb_db?: string | null;
  logs?: string | null;
  logs_not_kept?: string[];
  installed_outside: string[];
  runtime: string | null;
  runtime_changed: string | null;
};

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
  /** Why the trace could not be read, when it is there and could not be; null or absent otherwise. */
  trace_unreadable?: string | null;
  history: Record<string, FileVersion[]>;
  registry: (Record<string, unknown> & {
    tool_forging?: boolean;
    self_compact?: SelfCompactOptions;
    inbox_page_chars?: number;
    inputs?: { source: string; files: number; bytes: number; enforce: string; guard: string } | null;
    isolation?: { mode?: string; image?: string; image_digest?: string | null; cpus?: number; memory_mib?: number; disk_mib?: number; snapshot?: boolean; oauth_allowed?: boolean; snapshot_dir?: string | null };
    provenance?: RunProvenance;
    host_clock?: HostClock;
    custody_timeout_sec?: number | string;
    idle_nudge_sec?: number | string;
    vm_snapshot_dir?: string | null;
    disk_encryption?: string;
    hold?: { reason?: string | null; at?: string; by?: string } | boolean | null;
    notify?: string | boolean | null;
    ledger_from?: string | { run?: string; entries?: number; reviewed?: boolean } | null;
    synced_folder_allowed_by?: string | null;
    pack_secrets?: Record<string, { names?: string[]; mode?: string }>;
    netguard_mode?: string;
  }) | null;
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
  /** A microVM run's VMs; empty or absent for a host run. */
  vms?: VmHealth[];
  /** The run's life across its VMs over the whole trace; null for a host run. */
  vm_timeline?: VmTimeline | null;
  /** What the last custody check found (custody.json); null before a stop or the hub's finish took one. */
  custody?: CustodyView | null;
};

/** What produced the run, as the kickoff recorded it. */
export type RunProvenance = {
  harness_commit?: string;
  harness_dirty?: boolean;
  node_version?: string;
  pi_version?: string | null;
  pi_on_path?: string | null;
  msb_version?: string | null;
  image_digest?: string | null;
  os?: string;
  arch?: string;
};

/** The host's clock as the kickoff found it; the run's own processes run in UTC. */
export type HostClock = { tz?: string; abbreviation?: string; utc_offset?: string; synced?: boolean | null; source?: string | null; run_processes_tz?: string };

/** custody.json as the console shows it; `problems` empty is a clean verdict. */
export type CustodyView = {
  at: string | null;
  summary: string;
  verdict: "clean" | "attention";
  problems: string[];
  /** `skipped`: not re-read before custody's deadline; the verdict does not cover them. */
  evidence:
    | null
    | { unverifiable: string }
    | {
        files: number;
        bytes: number;
        unchanged: boolean;
        complete: boolean;
        changed: string[];
        missing: string[];
        added: string[];
        skipped: string[];
        unreadable?: string[];
        manifest_anchored: boolean | null;
        /** How many files each digest was compared on: sha256 decides; md5 and sha1 when the manifest carries them. */
        digests?: { sha256: number; md5: number; sha1: number } | null;
        checked?: { files: number; links: number; special: number } | null;
      };
  /** The artifact index custody wrote beside its verdict. */
  artifacts?: { files: number; bytes: number; skipped: number; index_sha256: string } | null;
  /** Whether custody.json is the verdict custody anchored outside the run, in words; null when there is nothing to check it against. */
  anchor?: string | null;
  sessions_not_files: string[];
  trace: { lines: number; intact: boolean; detail: string; unverified: number; disputed: number; spilled: number; lost: number; refused_spills: Array<{ path: string; why: string }> } | null;
  ledger: { entries: number; chained: number | null; intact: boolean; detail: string; missing_from_ledger: string[]; not_on_trace: number[] } | null;
  tool_outputs: { referenced: number; verified: number; missing: string[]; mismatched: string[]; refused: string[] } | null;
  vms: Array<{
    agent: string;
    record_sha256: string | null;
    stopped: boolean;
    kept: string | null;
    snapshot: string | null;
    image: string | null;
    expected_image: string | null;
    image_differs: boolean;
    /** `own_host`: the credential's own host (a failed request, not a leak); false or null: aimed elsewhere, or not known. */
    secret_violations: Array<{ at: string; env: string; host: string; method: string; path: string; action: string; location?: string; match_form?: string; own_host?: boolean | null }>;
    installed_outside: string[];
    installed_note: string | null;
    runtime_changed: string | null;
  }> | null;
  incomplete: string | null;
};

/** One `record` call, as the harness stored it in ledger/entries.jsonl. */
export type LedgerEntry = {
  seq: number;
  /** absence: a search that found nothing, valid only for its stated scope. */
  kind: "event" | "ioc" | "finding" | "absence";
  /** ISO 8601 UTC for an event; absent for the other kinds. */
  ts?: string;
  /** What the agent wrote for `ts` when it was not already the UTC value. */
  ts_raw?: string;
  /** The seq of the entry this one corrects; nothing is deleted. */
  supersedes?: number;
  /** This entry's own hash in the ledger's chain. */
  hash?: string;
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
export type InputFile = {
  path: string;
  bytes: number;
  sha256: string;
  md5?: string;
  sha1?: string;
  /** A name that is neither a file nor a link: a FIFO, a socket, a device. */
  special?: "fifo" | "socket" | "char" | "block";
  /** A symbolic link inside the evidence, recorded as the link it is: its target, never followed. */
  link?: string;
  /** A name whose bytes are not UTF-8: `path` is only for reading, this holds the bytes, base64. */
  path_b64?: string;
  link_b64?: string;
};

/** The read-only inputs a swarm was given, with what the trace says about them. */
export type InputsView = {
  source: string;
  /** copy, bind (in place) or image; null on an older manifest. */
  held?: string | null;
  /** In a VM run the evidence is a read-only, no-exec mount in every VM. */
  isolation?: "microvm" | "host";
  /** How the copy was checked against its source at the kickoff. */
  source_checked?: { by: string; files: number | null; mismatches: number | null; seconds: number | null; detail: string } | null;
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
  /** The server's OS: a disk image is attached with hdiutil, so only on darwin. Absent from an older server. */
  platform?: string;
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
  /**
   * A post from `system` sent by a seat's own harness code in its VM: the
   * seat's authority, not the harness's. The hub sets it; an agent cannot.
   */
  via?: string;
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
  /** Why the trace could not be read, when it is there and could not be; null or absent otherwise. */
  unreadable?: string | null;
  /** With `spilled`: each spill file read, or why not. Their lines are not on the chain. */
  spills?: Array<{ path: string; lines: number; why: string | null; writable_by: string }>;
};

export type Job = {
  id: string;
  kind: "start" | "stop" | "reap" | "hold" | "release" | "export" | "package" | "verify" | "purge" | "review";
  argv: string[];
  status: "running" | "ok" | "failed";
  exit_code: number | null;
  stdout: string;
  stderr: string;
  started_at: string;
  finished_at: string | null;
  swarm_id: string | null;
  /** An export's file, downloadable from /api/jobs/:id/download once the job is done. */
  output_file?: string;
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
  /** store/: the job service's journal and each job's sealed output. */
  | "store"
  /** A live VM run's hub wrote its status: the seats' states moved. */
  | "hub"
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

/** Can this host run the agents in microVMs. GET /api/vm/readiness. */
/** What `swarm.sh package` left in the run's sandbox. */
export type PackageInfo = {
  present: boolean;
  error: string | null;
  dir: string;
  made_at: string | null;
  files: number;
  manifest_sha256: string | null;
  signed: boolean;
  /** SIGNER.txt's lines: principal, examiner, key, signed_at, namespace. */
  signer: string[];
};

/** `swarm.sh image-for`: the image a kickoff with the chosen packs would boot, and why. */
export type ImagePreview = {
  ref: string | null;
  digest: string | null;
  profile: string | null;
  arch: string | null;
  packs: string[];
  pinned_by: string | null;
  reason: string | null;
  said: string[];
  error: string | null;
};

/** `swarm.sh start --check` with the form's options: exit 0 the start would go ahead, 2 it would be refused. Env values and the notify command are taken out. */
export type StartCheck = {
  exit: number;
  ok: boolean;
  blockers: string[];
  warnings: string[];
  said: string[];
  checked_at: string;
};

export type VmReadiness = {
  checked_at: string;
  ok: boolean;
  reasons: string[];
  warnings: string[];
  msb: { path: string; version: string; measured: string; matches: boolean } | null;
  doctor_output: string | null;
  image: { ref: string; present: boolean; digest: string | null } | null;
  capacity: { ok: boolean; blockers: string[]; warnings: string[]; host: { mem_mib: number; cpus: number } | null } | null;
  runs_dir: { path: string; synced: string | null };
};

/** One line of the operator's record. */
export type OperatorLine = { at: string; command: string; argv: string[]; os_user: string; host: string; via: string; chained: boolean };

/** GET /api/swarms/:id/operator: this run's lines of runs/operator-audit.jsonl, and its operator lines on the trace. */
export type OperatorAudit = {
  lines: OperatorLine[];
  intact: boolean;
  detail: string;
  trace: Array<{ at: string; tool: string; command: string; via: string; os_user: string; verified: boolean }>;
};

/** GET /api/swarms/:id/coverage: which inputs no command named; which ledger entries no call before them named the source of. */
export type Coverage = {
  unavailable: string | null;
  inputs: number;
  untouched: string[];
  touched: Record<string, number>;
  under_named_dir: Record<string, number>;
  calls_scanned: number;
  clipped_calls: number;
  grounding: Record<string, "grounded" | "not in the trace" | "not a path">;
};

export type ReviewAction = "accept" | "reject" | "amend" | "sign";

/** GET /api/swarms/:id/review: the examiner's decisions, kept outside the run and chained. */
export type ReviewState = {
  present: boolean;
  /** Why the review file was not read (a link, a FIFO, a directory in its place), or null. */
  error?: string | null;
  lines: Array<{ seq: number; at: string; examiner: string; os_user: string; host: string; action: ReviewAction; entry_seq: number | null; entry_hash: string | null; note: string | null; ledger_head: string | null; chained: boolean }>;
  chain: { intact: boolean; detail: string };
  by_entry: Record<string, { action: Exclude<ReviewAction, "sign">; examiner: string; at: string; note: string | null; entry_hash: string | null }>;
  signed: { examiner: string; at: string; ledger_head: string | null } | null;
};

/** What a job's sealed tree holds, as its job_committed line recorded it. */
export type StoreJobOutputs = { files: number; bytes: number; rejected: number; path: string; manifest_sha256: string };

/**
 * One tool job, folded from the job service's journal. `status` (and
 * `outcome`) is what the job did; `state` is where its record stands:
 * `committed` means its output was sealed into the store, whatever it did.
 */
export type StoreJobRow = {
  id: string;
  kind: string;
  /** The command's first line, the tool, the recipe, the import's source, or "detect pass"; the whole is in the record. */
  what: string;
  more_lines: number;
  target: string | null;
  requester: { agent: string; name: string | null; doing: string | null };
  state: "accepted" | "running" | "finished" | "fenced" | "committed" | "failed" | "cancelled" | string;
  status: "ok" | "failed" | "timed_out" | "cancelled" | "stopped" | "interrupted" | string | null;
  /** The status, or queued / running / not_run before or without one. */
  outcome: string;
  exit: number | null;
  reason: string | null;
  ran: boolean;
  attempts: number;
  accepted_at: string;
  started_at: string | null;
  finished_at: string | null;
  committed_at: string | null;
  duration_ms: number | null;
  create_ms: number | null;
  boot_retry: string | null;
  worker: string | null;
  worker_size: string | null;
  image: string | null;
  network: string | null;
  fenced: boolean | null;
  fence_error: string | null;
  outputs: StoreJobOutputs | null;
  kept_attempts: Array<StoreJobOutputs & { attempt: number; status: string | null; at: string }>;
  generation: string | null;
  generation_status: string | null;
  notified: Array<{ to: string; how: string; at: string }>;
  deduplicated: number;
  cancel_requested: string | null;
  parent: string | null;
  note: string | null;
};

/** GET /api/swarms/:id/jobs: a page of the run's tool jobs, totals over all of them, the run's own journal lines and custody's store line. */
export type StoreJobsView = {
  service: boolean;
  note: string | null;
  journal: {
    path: string;
    lines: number;
    bytes: number;
    intact: boolean;
    detail: string;
    head: string | null;
    anchor: "matches" | "behind" | "off the chain" | "missing";
    unparsed: number[];
    partial_tail_bytes: number;
  } | null;
  totals: {
    jobs: number;
    committed: number;
    by_state: Record<string, number>;
    by_outcome: Record<string, number>;
    files: number;
    bytes: number;
    rejected: number;
    generations: number;
    revisions: number;
    notes: number;
    degraded: number;
    recovered: number;
    deduplicated: number;
  };
  jobs: StoreJobRow[];
  page: { offset: number; limit: number; total: number; next: number | null; whole: string };
  /** Journal lines, whole: note, jobs_degraded, jobs_recovered, job_deduplicated, journal_repaired, anchor_*, detect_bounded. */
  events: Array<{ seq?: number; at?: string; type: string; job?: string; by?: unknown; text?: string; jobs?: string[]; error?: string; in_a_row?: number; notify?: boolean } & Record<string, unknown>>;
  custody: { at: string | null; line: string | null; journal_lines: number | null; journal_head: string | null } | null;
};

/** GET /api/swarms/:id/jobs/:job: one job's row, record, journal lines, a page of one sealed tree's manifest, and its logs. */
export type StoreJobDetail = {
  id: string;
  row: StoreJobRow;
  record: unknown;
  record_error: string | null;
  lines: Array<Record<string, unknown>>;
  trees: string[];
  manifest: {
    tree: string;
    path: string;
    present: boolean;
    error: string | null;
    sha256: string | null;
    matches_journal: boolean | null;
    sealed_at: string | null;
    totals: { files: number; bytes: number } | null;
    dirs: number;
    rejected: Array<{ path: string; kind: string; link?: string }>;
    files: Array<{ path: string; bytes: number; sha256: string; mode: string }>;
    page: { offset: number; limit: number; total: number; next: number | null };
  } | null;
  logs: Array<{ name: string; path: string; bytes: number | null; sha256: string | null; present: boolean; why: string | null }>;
};

/** GET /api/swarms/:id/jobs/:job/log/:name: a page of a job's log, by bytes, ending on a character boundary. */
export type StoreLogPage = { name: string; path: string; offset: number; bytes: number; total: number; text: string; next: number | null };

/** An installed pack as the kickoff form lists it. */
export type PackRow = { id: string; name: string; version: string; description: string; depends: string[]; secrets?: Array<{ name: string; title: string; required: boolean }> };
