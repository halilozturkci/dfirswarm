/**
 * The run's tool jobs, as the console reads them: store/journal.jsonl (the
 * job service's record, a hash-chained line for every step), each job's
 * projection (store/jobs/<id>/job.json), its manifest and its stdout and
 * stderr. Read-only: the hub is the store's one writer, and nothing here
 * writes.
 *
 * A job's outcome (the status and exit of what it ran) and its record's
 * state (accepted, running, fenced, committed…) are two things and are kept
 * apart: `committed` says the job's output was sealed into the store,
 * whatever the job did; a failed job's output is committed too.
 *
 * Nothing is cut. A list is paged with offset and limit, and the page says
 * how many there are and where the whole is; a log is paged by bytes, on a
 * character boundary, and served whole on its own route; every journal line
 * about a job comes back as it was written.
 */
import { lstat, readdir, realpath } from "node:fs/promises";
import { join, resolve } from "node:path";
import { sha256Hex, verifyJournalText, type Anchor, type Manifest } from "../evidence-store.ts";
import { openRegular, readRegularText } from "../regular-file.ts";

export const STORE_JOURNAL = "store/journal.jsonl";
export const STORE_JOB_ID = /^j\d{6}$/;
/** A job's logs as the service keeps them: its own, and an interrupted attempt's under that attempt's name. */
const LOG_NAME = /^(attempt-\d{1,3}-interrupted\.)?(stdout\.log|stderr\.log|pip-before\.txt|pip-after\.txt)$/;
/** Which of a job's sealed trees: its result (`out`), or an interrupted attempt's. */
const TREE_NAME = /^(out|attempt-\d{1,3}-interrupted)$/;
/** Far past any journal a run has written; above it the file is named and not read. */
const JOURNAL_MAX_BYTES = 512 * 1024 * 1024;
const RECORD_MAX_BYTES = 64 * 1024 * 1024;

export type StoreError = { error: 400 | 404 | 409; message: string };

export type StoreJobOutputs = { files: number; bytes: number; rejected: number; path: string; manifest_sha256: string };

export type StoreJobRow = {
  id: string;
  kind: string;
  /** The command's first line, the tool, the recipe, the import's source, or "detect pass". The whole is in the record. */
  what: string;
  /** Lines of the command past the first; 0 for anything else. */
  more_lines: number;
  /** A recipe's object, or how many objects a detect pass asked about. */
  target: string | null;
  requester: { agent: string; name: string | null; doing: string | null };
  /** The record's state, in the service's words: accepted (queued), running, finished, fenced, committed, failed (not run), cancelled. */
  state: string;
  /** What the job did: ok, failed, timed_out, cancelled, stopped, interrupted; null until it finished. */
  status: string | null;
  /** The status, or what stands for one: queued, running, not_run. */
  outcome: string;
  exit: number | null;
  reason: string | null;
  /** Whether a worker was started for it (a job refused at its script step never ran). */
  ran: boolean;
  attempts: number;
  accepted_at: string;
  started_at: string | null;
  finished_at: string | null;
  committed_at: string | null;
  duration_ms: number | null;
  /** From asking for the worker to its VM up. */
  create_ms: number | null;
  boot_retry: string | null;
  worker: string | null;
  worker_size: string | null;
  image: string | null;
  network: string | null;
  /** Whether msb said the worker was gone before its output was read; null before that step. */
  fenced: boolean | null;
  fence_error: string | null;
  outputs: StoreJobOutputs | null;
  /** An interrupted attempt's output, kept beside the result. */
  kept_attempts: Array<StoreJobOutputs & { attempt: number; status: string | null; at: string }>;
  generation: string | null;
  generation_status: string | null;
  notified: Array<{ to: string; how: string; at: string }>;
  /** How many later requests were answered with this job. */
  deduplicated: number;
  cancel_requested: string | null;
  parent: string | null;
  note: string | null;
};

export type StoreJournalState = {
  path: string;
  lines: number;
  bytes: number;
  intact: boolean;
  detail: string;
  head: string | null;
  anchor: "matches" | "behind" | "off the chain" | "missing";
  /** Line numbers (1-based) that are not JSON: named, never dropped silently. */
  unparsed: number[];
  /** A last line with no end yet: the hub writing it as this was read. */
  partial_tail_bytes: number;
};

export type StoreJobsTotals = {
  jobs: number;
  committed: number;
  by_state: Record<string, number>;
  by_outcome: Record<string, number>;
  /** Every sealed tree in the store, kept attempts included. */
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

export type StoreCustodyLine = {
  at: string | null;
  /** Custody's own words about the store, whole: the part of its summary that starts `store:`. */
  line: string | null;
  /** The journal as custody read it, to set beside the journal now (a note added after the run lengthens it). */
  journal_lines: number | null;
  journal_head: string | null;
};

export type StoreJobsView = {
  /** False when the run has no store/journal.jsonl: no job service ran. */
  service: boolean;
  /** Why there is nothing, or less than a whole journal, to show; null otherwise. */
  note: string | null;
  journal: StoreJournalState | null;
  totals: StoreJobsTotals;
  jobs: StoreJobRow[];
  page: { offset: number; limit: number; total: number; next: number | null; whole: string };
  /** The run's own lines, whole: examiner notes, the service's degraded and recovered notices, dedup answers, journal repairs. */
  events: Array<Record<string, unknown>>;
  custody: StoreCustodyLine | null;
};

export type StoreJobDetail = {
  id: string;
  row: StoreJobRow;
  /** store/jobs/<id>/job.json, whole, as the service projected it; the journal is the record. */
  record: unknown;
  record_error: string | null;
  /** Every journal line about this job, as written. */
  lines: Array<Record<string, unknown>>;
  /** The sealed trees the journal names for this job: `out`, and any kept attempt. */
  trees: string[];
  manifest: {
    tree: string;
    path: string;
    present: boolean;
    error: string | null;
    sha256: string | null;
    /** Whether the manifest's sha256 is the one its job_committed line recorded. */
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

export type StoreLogPage = { name: string; path: string; offset: number; bytes: number; total: number; text: string; next: number | null };

const EVENT_TYPES = new Set(["note", "jobs_degraded", "jobs_recovered", "job_deduplicated", "journal_repaired", "anchor_behind", "anchor_mismatch", "detect_bounded"]);

function str(v: unknown): string | null {
  return typeof v === "string" ? v : null;
}

function num(v: unknown): number | null {
  return typeof v === "number" && Number.isFinite(v) ? v : null;
}

function bounds(offset: number | undefined, limit: number | undefined, dflt: number, max: number): { offset: number; limit: number } {
  return { offset: Math.max(0, Math.floor(Number(offset) || 0)), limit: Math.min(max, Math.max(1, Math.floor(Number(limit) || dflt))) };
}

/**
 * A file under the run's sandbox as it is on disk: the resolved path must
 * be the path asked for, so no component on the way is a link. The store is
 * the hub's, but a shell in a host run could still plant one, and these
 * routes need no token.
 */
async function inSandbox(sandbox: string, rel: string): Promise<{ abs: string } | { why: string }> {
  const base = await realpath(sandbox).catch(() => resolve(sandbox));
  const abs = join(base, rel);
  try {
    const real = await realpath(abs);
    return real === abs ? { abs } : { why: "a link" };
  } catch (err) {
    const code = (err as NodeJS.ErrnoException).code;
    // A link to nothing is a link, not a missing file.
    if (code === "ENOENT" && (await lstat(abs).catch(() => null))?.isSymbolicLink()) return { why: "a link" };
    return { why: code === "ENOENT" || code === "ENOTDIR" ? "missing" : `unreadable (${code ?? "error"})` };
  }
}

async function readText(sandbox: string, rel: string, max: number): Promise<{ text: string } | { why: string }> {
  const at = await inSandbox(sandbox, rel);
  if ("why" in at) return at;
  return readRegularText(at.abs, max);
}

function describeWhat(spec: Record<string, unknown>): { what: string; more_lines: number; target: string | null } {
  const kind = str(spec.kind) ?? "?";
  if (kind === "command") {
    const lines = (str(spec.command) ?? "").split("\n").filter((l) => l.trim());
    return { what: lines[0] ?? "", more_lines: Math.max(0, lines.length - 1), target: null };
  }
  if (kind === "tool") return { what: str(spec.tool) ?? "?", more_lines: 0, target: null };
  if (kind === "import") return { what: str(spec.source) ?? "?", more_lines: 0, target: null };
  if (kind === "recipe") {
    const t = (spec.target ?? {}) as { name?: unknown; ref?: unknown; paths?: unknown };
    return { what: str(spec.recipe) ?? "?", more_lines: 0, target: str(t.name) ?? str(t.ref) ?? (Array.isArray(t.paths) ? String(t.paths[0] ?? "") : null) };
  }
  const targets = Array.isArray(spec.targets) ? spec.targets.length : 0;
  return { what: `detect pass${spec.trigger ? ` (${String(spec.trigger)})` : ""}`, more_lines: 0, target: `${targets} object${targets === 1 ? "" : "s"}` };
}

function outputsOf(v: unknown): StoreJobOutputs | null {
  if (!v || typeof v !== "object") return null;
  const o = v as Record<string, unknown>;
  return { files: num(o.files) ?? 0, bytes: num(o.bytes) ?? 0, rejected: num(o.rejected) ?? 0, path: str(o.path) ?? "", manifest_sha256: str(o.manifest_sha256) ?? "" };
}

type JournalRead = { state: StoreJournalState; lines: Array<Record<string, unknown>> };

/** The journal whole: every line that parses, the chain checked, the anchor beside the run compared. */
async function readJournal(sandbox: string): Promise<JournalRead | { why: string }> {
  // The anchor first: the hub moves it after each line, so read before the
  // journal it can only be level with it or behind, never ahead.
  let anchor: Anchor | null = null;
  const base = await realpath(sandbox).catch(() => resolve(sandbox));
  const anchorText = await readRegularText(`${base}.journal-anchor.json`, 64 * 1024);
  if ("text" in anchorText) {
    try {
      anchor = JSON.parse(anchorText.text) as Anchor;
    } catch {
      anchor = null;
    }
  }
  const read = await readText(sandbox, STORE_JOURNAL, JOURNAL_MAX_BYTES);
  if ("why" in read) return read;
  const text = read.text;
  // A live run: the hub may be half way through a line. What has no end
  // yet is not judged, and is said to be there.
  const end = text.lastIndexOf("\n") + 1;
  const whole = text.slice(0, end);
  const lines: Array<Record<string, unknown>> = [];
  const unparsed: number[] = [];
  whole.split("\n").forEach((raw, i) => {
    if (!raw) return;
    try {
      const line = JSON.parse(raw) as unknown;
      if (line && typeof line === "object" && !Array.isArray(line)) lines.push(line as Record<string, unknown>);
      else unparsed.push(i + 1);
    } catch {
      unparsed.push(i + 1);
    }
  });
  const checked = verifyJournalText(whole);
  const where: StoreJournalState["anchor"] = !anchor
    ? "missing"
    : anchor.head === checked.head && anchor.seq === checked.lines.length - 1
      ? "matches"
      : anchor.seq >= 0 && checked.hashes[anchor.seq] === anchor.head
        ? "behind"
        : "off the chain";
  return {
    lines,
    state: {
      path: STORE_JOURNAL,
      lines: lines.length,
      bytes: Buffer.byteLength(text),
      intact: !checked.error,
      detail: checked.error ? `${checked.error}; every line after it that parses is still shown` : "chain intact",
      head: checked.head,
      anchor: where,
      unparsed,
      partial_tail_bytes: Buffer.byteLength(text) - Buffer.byteLength(whole),
    },
  };
}

/** Each job's row, folded from its lines in the order they were written, and the run's own lines. */
function fold(lines: Array<Record<string, unknown>>): { rows: Map<string, StoreJobRow>; events: Array<Record<string, unknown>>; totals: StoreJobsTotals } {
  const rows = new Map<string, StoreJobRow>();
  const events: Array<Record<string, unknown>> = [];
  const totals: StoreJobsTotals = { jobs: 0, committed: 0, by_state: {}, by_outcome: {}, files: 0, bytes: 0, rejected: 0, generations: 0, revisions: 0, notes: 0, degraded: 0, recovered: 0, deduplicated: 0 };
  for (const l of lines) {
    const type = str(l.type) ?? "";
    const at = str(l.at) ?? "";
    const id = str(l.job) ?? "";
    if (EVENT_TYPES.has(type)) events.push(l);
    if (type === "note") totals.notes += 1;
    if (type === "jobs_degraded") totals.degraded += 1;
    if (type === "jobs_recovered") totals.recovered += 1;
    if (type === "revision_published") totals.revisions += 1;
    if (type === "generation_committed") totals.generations += 1;
    if (type === "job_committed") {
      const o = outputsOf(l.outputs);
      if (o) {
        totals.files += o.files;
        totals.bytes += o.bytes;
        totals.rejected += o.rejected;
      }
    }
    if (type === "job_accepted") {
      const spec = (l.spec ?? {}) as Record<string, unknown>;
      const who = (l.requester ?? {}) as Record<string, unknown>;
      rows.set(id, {
        id,
        kind: str(spec.kind) ?? "?",
        ...describeWhat(spec),
        requester: { agent: str(who.agent) ?? "?", name: str(who.name), doing: str(who.doing) },
        state: "accepted",
        status: null,
        outcome: "queued",
        exit: null,
        reason: null,
        ran: false,
        attempts: 1,
        accepted_at: at,
        started_at: null,
        finished_at: null,
        committed_at: null,
        duration_ms: null,
        create_ms: null,
        boot_retry: null,
        worker: null,
        worker_size: null,
        image: null,
        network: null,
        fenced: null,
        fence_error: null,
        outputs: null,
        kept_attempts: [],
        generation: null,
        generation_status: null,
        notified: [],
        deduplicated: 0,
        cancel_requested: null,
        parent: str(spec.parent),
        note: str(spec.note),
      });
      continue;
    }
    const j = rows.get(id);
    if (!j) continue;
    switch (type) {
      case "job_started":
        Object.assign(j, {
          state: "running",
          ran: true,
          attempts: num(l.attempt) ?? j.attempts,
          started_at: at,
          worker: str(l.worker),
          image: str(l.image),
          network: str(l.network),
          worker_size: num(l.cpus) !== null ? `${l.cpus} vCPU, ${l.memory_mib} MiB` : null,
        });
        break;
      case "job_finished":
        Object.assign(j, { state: "finished", status: str(l.status), exit: num(l.exit), reason: str(l.reason), finished_at: at, duration_ms: num(l.duration_ms), create_ms: num(l.create_ms), boot_retry: str(l.boot_retry) });
        break;
      case "job_fenced":
        j.fenced = l.fenced === true;
        j.fence_error = str(l.error);
        if (l.fenced === true && j.state === "finished") j.state = "fenced";
        break;
      case "job_committed": {
        const o = outputsOf(l.outputs);
        // An interrupted attempt's output is kept beside the result, under
        // that attempt's name; the job goes on to its next attempt.
        if (o && !o.path.endsWith("/out")) {
          j.kept_attempts.push({ ...o, attempt: num(l.attempt) ?? j.attempts, status: str(l.status), at });
          break;
        }
        Object.assign(j, { state: "committed", status: str(l.status) ?? j.status, exit: l.exit === undefined ? j.exit : num(l.exit), reason: str(l.reason) ?? j.reason, outputs: o, committed_at: at });
        break;
      }
      case "job_retried":
        Object.assign(j, { state: "accepted", attempts: num(l.attempt) ?? j.attempts + 1, status: null, exit: null, reason: null, finished_at: null, fenced: null, fence_error: null });
        break;
      case "job_failed":
        Object.assign(j, { state: "failed", reason: str(l.reason) });
        break;
      case "job_cancelled":
        Object.assign(j, { state: "cancelled", status: "cancelled", reason: str(l.reason) });
        break;
      case "job_cancel_requested":
        j.cancel_requested = str(l.by);
        break;
      case "generation_committed":
        j.generation = str(l.generation);
        j.generation_status = str(l.status);
        break;
      case "job_notified":
        j.notified.push({ to: str(l.to) ?? "?", how: str(l.how) ?? "?", at });
        break;
      case "job_deduplicated":
        j.deduplicated += 1;
        totals.deduplicated += 1;
        break;
      default:
        break;
    }
  }
  for (const j of rows.values()) {
    j.outcome = j.status ?? (j.state === "failed" ? "not_run" : j.state === "running" ? "running" : j.state === "accepted" ? "queued" : "pending");
    totals.jobs += 1;
    if (j.state === "committed") totals.committed += 1;
    totals.by_state[j.state] = (totals.by_state[j.state] ?? 0) + 1;
    totals.by_outcome[j.outcome] = (totals.by_outcome[j.outcome] ?? 0) + 1;
  }
  return { rows, events, totals };
}

/** Custody's store line, from custody.json as stop wrote it; null with no custody taken. */
async function custodyLine(sandbox: string): Promise<StoreCustodyLine | null> {
  const read = await readText(sandbox, "custody.json", 256 * 1024 * 1024);
  if ("why" in read) return null;
  let c: Record<string, unknown>;
  try {
    c = JSON.parse(read.text) as Record<string, unknown>;
  } catch {
    return null;
  }
  const store = (c.store ?? null) as { journal?: { lines?: unknown; head?: unknown } } | null;
  const line = typeof c.summary === "string" ? (c.summary.split(" · ").find((p) => p.startsWith("store: ")) ?? null) : null;
  return { at: str(c.at), line, journal_lines: num(store?.journal?.lines), journal_head: str(store?.journal?.head) };
}

function emptyTotals(): StoreJobsTotals {
  return fold([]).totals;
}

/** The run's jobs: a page of them, the totals over all of them, the run's own lines and custody's store line. */
export async function readStoreJobs(sandbox: string, q: { offset?: number; limit?: number } = {}): Promise<StoreJobsView> {
  const { offset, limit } = bounds(q.offset, q.limit, 200, 1000);
  const custody = await custodyLine(sandbox);
  const nothing = (service: boolean, note: string): StoreJobsView => ({ service, note, journal: null, totals: emptyTotals(), jobs: [], page: { offset, limit, total: 0, next: null, whole: STORE_JOURNAL }, events: [], custody });
  const journal = await readJournal(sandbox);
  if ("why" in journal) {
    return journal.why === "missing"
      ? nothing(false, `This run has no job service: there is no ${STORE_JOURNAL}, so its agents ran every tool in their own seats.`)
      : nothing(true, `${STORE_JOURNAL} was not read: ${journal.why}.`);
  }
  const { rows, events, totals } = fold(journal.lines);
  const all = [...rows.values()];
  const jobs = all.slice(offset, offset + limit);
  const partial = journal.state.partial_tail_bytes ? `the last ${journal.state.partial_tail_bytes} bytes of the journal are a line still being written, read on the next change` : null;
  const unparsed = journal.state.unparsed.length ? `${journal.state.unparsed.length} line(s) of the journal are not JSON (line ${journal.state.unparsed.join(", ")}): named here, in the file whole` : null;
  return {
    service: true,
    note: [unparsed, partial].filter(Boolean).join("; ") || null,
    journal: journal.state,
    totals,
    jobs,
    page: { offset, limit, total: all.length, next: offset + jobs.length < all.length ? offset + jobs.length : null, whole: STORE_JOURNAL },
    events,
    custody,
  };
}

/** One job: its row, its record, every journal line about it, a page of one sealed tree's manifest, and its logs. */
export async function readStoreJob(sandbox: string, id: string, q: { tree?: string; offset?: number; limit?: number } = {}): Promise<StoreJobDetail | StoreError> {
  if (!STORE_JOB_ID.test(id)) return { error: 400, message: "not a job id" };
  const journal = await readJournal(sandbox);
  if ("why" in journal) return { error: 404, message: journal.why === "missing" ? "this run has no job service" : `${STORE_JOURNAL} was not read: ${journal.why}` };
  const row = fold(journal.lines).rows.get(id);
  if (!row) return { error: 404, message: `no job ${id} in the journal` };
  const lines = journal.lines.filter((l) => l.job === id);
  const dir = `store/jobs/${id}`;

  let record: unknown = null;
  let recordError: string | null = null;
  const recordText = await readText(sandbox, `${dir}/job.json`, RECORD_MAX_BYTES);
  if ("why" in recordText) recordError = `job.json is ${recordText.why}`;
  else {
    try {
      record = JSON.parse(recordText.text);
    } catch {
      recordError = "job.json is not JSON";
    }
  }

  const trees = [...(row.outputs ? ["out"] : []), ...row.kept_attempts.map((a) => a.path.split("/").pop() ?? "")].filter((t) => TREE_NAME.test(t));
  const tree = q.tree ?? trees[0] ?? "out";
  if (!TREE_NAME.test(tree)) return { error: 400, message: "tree is out or attempt-<n>-interrupted" };
  const recorded = tree === "out" ? row.outputs : row.kept_attempts.find((a) => a.path.endsWith(`/${tree}`)) ?? null;
  const manifestRel = `${dir}/${tree === "out" ? "manifest.json" : `${tree}.manifest.json`}`;
  let manifest: StoreJobDetail["manifest"] = null;
  if (recorded || tree !== "out" || row.state === "committed") {
    const { offset, limit } = bounds(q.offset, q.limit, 200, 2000);
    const read = await readText(sandbox, manifestRel, RECORD_MAX_BYTES);
    const empty = { tree, path: manifestRel, sealed_at: null, totals: null, dirs: 0, rejected: [], files: [], page: { offset, limit, total: 0, next: null } };
    if ("why" in read) manifest = { ...empty, present: false, error: `the manifest is ${read.why}`, sha256: null, matches_journal: null };
    else {
      let m: Manifest | null = null;
      try {
        m = JSON.parse(read.text) as Manifest;
      } catch {
        m = null;
      }
      const sha = sha256Hex(read.text);
      if (!m || !Array.isArray(m.files)) manifest = { ...empty, present: true, error: "the manifest is not a manifest", sha256: sha, matches_journal: recorded ? recorded.manifest_sha256 === sha : null };
      else {
        const files = m.files.slice(offset, offset + limit).map((f) => ({ path: f.path, bytes: f.bytes, sha256: f.sha256, mode: f.mode }));
        manifest = {
          tree,
          path: manifestRel,
          present: true,
          error: null,
          sha256: sha,
          matches_journal: recorded ? recorded.manifest_sha256 === sha : null,
          sealed_at: m.sealed_at ?? null,
          totals: m.totals ?? null,
          dirs: Array.isArray(m.dirs) ? m.dirs.length : 0,
          rejected: (m.rejected ?? []).map((r) => ({ path: r.path, kind: r.kind, ...(r.link ? { link: r.link } : {}) })),
          files,
          page: { offset, limit, total: m.files.length, next: offset + files.length < m.files.length ? offset + files.length : null },
        };
      }
    }
  }

  // The logs the job left, with the sha256 its job_committed line recorded for each.
  const recordedLogs = new Map<string, string>();
  for (const l of lines) {
    if (l.type !== "job_committed" || !l.logs || typeof l.logs !== "object") continue;
    const where = outputsOf(l.outputs)?.path.split("/").pop() ?? "out";
    for (const [name, sha] of Object.entries(l.logs as Record<string, unknown>)) if (typeof sha === "string") recordedLogs.set(where === "out" ? name : `${where}.${name}`, sha);
  }
  const names = new Set(recordedLogs.keys());
  const at = await inSandbox(sandbox, dir);
  if ("abs" in at) for (const n of await readdir(at.abs).catch(() => [] as string[])) if (LOG_NAME.test(n)) names.add(n);
  const order = (n: string) => ["stdout.log", "stderr.log", "pip-before.txt", "pip-after.txt"].indexOf(n.replace(/^attempt-\d+-interrupted\./, "")) + (n.startsWith("attempt-") ? 10 : 0);
  const logs: StoreJobDetail["logs"] = [];
  for (const name of [...names].sort((a, b) => order(a) - order(b) || a.localeCompare(b))) {
    const file = await inSandbox(sandbox, `${dir}/${name}`);
    const st = "abs" in file ? await lstat(file.abs).catch(() => null) : null;
    const why = "why" in file ? file.why : !st ? "missing" : !st.isFile() ? "not a regular file" : null;
    logs.push({ name, path: `${dir}/${name}`, bytes: why ? null : st!.size, sha256: recordedLogs.get(name) ?? null, present: !why, why });
  }

  return { id, row, record, record_error: recordError, lines, trees, manifest, logs };
}

/** The path of one of a job's logs, for serving whole; refused when it is not one of the names the service writes, or not a regular file inside the store. */
export async function storeJobLogFile(sandbox: string, id: string, name: string): Promise<string | StoreError> {
  if (!STORE_JOB_ID.test(id)) return { error: 400, message: "not a job id" };
  if (!LOG_NAME.test(name)) return { error: 400, message: "a job's log is stdout.log, stderr.log, pip-before.txt or pip-after.txt, or an interrupted attempt's" };
  const at = await inSandbox(sandbox, `store/jobs/${id}/${name}`);
  if ("why" in at) return at.why === "missing" ? { error: 404, message: `job ${id} has no ${name}` } : { error: 409, message: `${name} is ${at.why}` };
  return at.abs;
}

/**
 * A page of one of a job's logs, by bytes. A page ends on a character
 * boundary, so a character is never split between two pages; `next` is
 * where the following one starts, and the whole is on the raw route.
 */
export async function readStoreJobLog(sandbox: string, id: string, name: string, q: { offset?: number; limit?: number } = {}): Promise<StoreLogPage | StoreError> {
  const abs = await storeJobLogFile(sandbox, id, name);
  if (typeof abs !== "string") return abs;
  const opened = await openRegular(abs);
  if ("why" in opened) return opened.why === "missing" ? { error: 404, message: `job ${id} has no ${name}` } : { error: 409, message: `${name} is ${opened.why}` };
  try {
    const { limit } = bounds(0, q.limit, 64 * 1024, 1024 * 1024);
    const total = opened.size;
    const offset = Math.min(Math.max(0, Math.floor(Number(q.offset) || 0)), total);
    const buf = Buffer.alloc(Math.min(Math.max(limit, 4), total - offset));
    const { bytesRead } = await opened.handle.read(buf, 0, buf.length, offset);
    let keep = bytesRead;
    if (offset + keep < total) keep = utf8Boundary(buf.subarray(0, keep));
    return { name, path: `store/jobs/${id}/${name}`, offset, bytes: keep, total, text: buf.subarray(0, keep).toString("utf8"), next: offset + keep < total ? offset + keep : null };
  } finally {
    await opened.handle.close();
  }
}

/** Where a buffer cut at its end stops being a whole UTF-8 character: the length that ends on a boundary. */
export function utf8Boundary(buf: Buffer): number {
  // Back over at most three continuation bytes to the lead byte of the last
  // character; if that character needs more bytes than are here, end before it.
  for (let i = buf.length - 1; i >= Math.max(0, buf.length - 4); i -= 1) {
    const b = buf[i];
    if ((b & 0xc0) === 0x80) continue;
    const need = b >= 0xf0 ? 4 : b >= 0xe0 ? 3 : b >= 0xc0 ? 2 : 1;
    // All there: keep everything. Cut short: end before it, unless it is all there is.
    return i + need <= buf.length ? buf.length : i > 0 ? i : buf.length;
  }
  return buf.length;
}
