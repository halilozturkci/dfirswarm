/**
 * What the harness cost a run's seats, from the trace and the store's
 * journal (swarm.sh metrics, the "Harness" row).
 *
 * Each figure here was worked out by hand in a post-mortem of eight runs
 * before it had a row: refused records per accepted one (0.83 in one run,
 * 0.05 in another, with the same rules), how long small jobs waited for a
 * large one's seal (109,054 job-seconds in one run), compactions per seat
 * hour, how late the hub's loop ran, answers too large to send, seats that
 * went down. A run that is slow for the harness's reasons now says so.
 */
import type * as P from "../extensions/protocol.ts";
import { digestHolds, sightingText, textHolds } from "../extensions/sighting.ts";

export type FrictionMetrics = {
  record: { accepted: number; refused: number; per_accepted: number | null };
  attest: { accepted: number; refused: number };
  job_run_refused: number;
  shell: { timeouts: number; sleep_loops_refused: number };
  compactions: { done: number; failed: number; per_seat_hour: number | null };
  /** Seconds from a job's end to its commit: every job, and the small ones (50 files or fewer) that waited over 30 s. */
  commit_wait: { jobs: number; median_s: number | null; p90_s: number | null; max_s: number | null; small_over_30s: number; small_job_seconds: number };
  /** Seconds from acceptance to start. */
  queue_wait: { median_s: number | null; p90_s: number | null; max_s: number | null };
  hub: { samples: number; loop_p99_max_ms: number | null; heap_share_max: number | null; memory_high: number; restarts: number; answers_too_large: number; lock_timeouts: number };
  seats: { down: number; relaunched: number; dead: number; images_scaled: number };
  platform_stalls: number;
  /** job_run's answers: their text, and the share the hints at admission (library, similar, coverage) took of it. */
  job_run_text: { answers: number; chars: number; hint_share: number | null };
  /** The largest answer a seat's tool call returned, in characters, and which tool; and empty compaction summaries. */
  largest_answer: { chars: number; tool: string | null };
  empty_summaries: number;
  /** Compactions whose row gives its summary's size (summary_chars): empty summaries are counted among these only. */
  summaries_sized: number;
  /** Seconds from a job's end (job_finished) to the first time a seat was told of it (job_notified: a post, or a job_run or job_status answer); jobs never told are counted apart. */
  delivery: { jobs: number; told: number; never_told: number; median_s: number | null; p90_s: number | null; max_s: number | null };
  /** Sealing a large extraction (LARGE_FILES output files or more): seconds from the job's fence (else its end) to its commit, and the largest such job's file count. */
  large_seal: { threshold_files: number; jobs: number; median_s: number | null; max_s: number | null; max_files: number | null };
  /** Records accepted after two or more refusals in a row of the same seat's record calls, and the longest such run of refusals (accepted or not). */
  refused_twice: { records: number; longest_run: number };
  /**
   * The library's text: the library hint in job_run's answers (library_chars) and the `tools` listings' answers
   * (answer_chars), as a share of job_run's answer text and of all the tool-answer text seats received. Not recorded
   * for a run whose rows carry neither figure.
   */
  library: { recorded: boolean; hint_chars: number; listing_chars: number; of_job_run: number | null; of_all: number | null; all_chars: number };
  /**
   * Seconds from a seat's last tool result before a model request to that request's start (the gateway's log: its
   * end less its duration), per request that followed a tool result. Null source: the run has no gateway log.
   */
  model_gap: { source: "model-gateway" | null; calls: number; median_s: number | null; p90_s: number | null; max_s: number | null };
  /** `wait` calls: all, and those that ended with nothing delivered (idle), their seconds, and the idle share of seat time. */
  idle_waits: { waits: number; idle: number; wait_s: number; idle_s: number; share_of_seat_time: number | null };
};

/** A job with this many output files or more is a large extraction (150,000 to 230,000 files in the runs that stalled the store). */
export const LARGE_FILES = 10_000;

/** A model request as the gateway logged it: its seat, when it started and when it ended (ms). */
export type ModelCall = { seat: string; start: number; end: number };

/** Rows a seat writes that are not a tool's result: the time a tool answered is not theirs. */
const NOT_A_RESULT = new Set(["thinking", "model_reported", "compact_done", "compact_failed", "compact_started", "self_compact_hint", "seat_down", "seat_relaunched", "seat_dead"]);

type Row = { ts?: string; at?: string; recv_ts?: string; agent?: string; tool?: string; args?: Record<string, unknown>; result?: Record<string, unknown> };
type JRow = { type?: string; at?: string; job?: string; outputs?: { files?: number } };

const pct = (xs: number[], p: number): number | null => {
  if (!xs.length) return null;
  const s = [...xs].sort((a, b) => a - b);
  return Math.round(s[Math.min(s.length - 1, Math.floor((p / 100) * s.length))]! * 10) / 10;
};
const t = (s: unknown): number | null => {
  const n = typeof s === "string" ? Date.parse(s) : NaN;
  return Number.isFinite(n) ? n : null;
};

export function frictionMetrics(events: readonly P.SwarmEvent[], journal: readonly Record<string, unknown>[] = [], o: { calls?: readonly ModelCall[] | null } = {}): FrictionMetrics {
  const m: FrictionMetrics = {
    record: { accepted: 0, refused: 0, per_accepted: null },
    attest: { accepted: 0, refused: 0 },
    job_run_refused: 0,
    shell: { timeouts: 0, sleep_loops_refused: 0 },
    compactions: { done: 0, failed: 0, per_seat_hour: null },
    commit_wait: { jobs: 0, median_s: null, p90_s: null, max_s: null, small_over_30s: 0, small_job_seconds: 0 },
    queue_wait: { median_s: null, p90_s: null, max_s: null },
    hub: { samples: 0, loop_p99_max_ms: null, heap_share_max: null, memory_high: 0, restarts: 0, answers_too_large: 0, lock_timeouts: 0 },
    seats: { down: 0, relaunched: 0, dead: 0, images_scaled: 0 },
    platform_stalls: 0,
    job_run_text: { answers: 0, chars: 0, hint_share: null },
    largest_answer: { chars: 0, tool: null },
    empty_summaries: 0,
    summaries_sized: 0,
    delivery: { jobs: 0, told: 0, never_told: 0, median_s: null, p90_s: null, max_s: null },
    large_seal: { threshold_files: LARGE_FILES, jobs: 0, median_s: null, max_s: null, max_files: null },
    refused_twice: { records: 0, longest_run: 0 },
    library: { recorded: false, hint_chars: 0, listing_chars: 0, of_job_run: null, of_all: null, all_chars: 0 },
    model_gap: { source: null, calls: 0, median_s: null, p90_s: null, max_s: null },
    idle_waits: { waits: 0, idle: 0, wait_s: 0, idle_s: 0, share_of_seat_time: null },
  };
  let hintChars = 0;
  const streak = new Map<string, number>();
  const resultsBySeat = new Map<string, number[]>();
  const first = new Map<string, number>();
  const last = new Map<string, number>();
  for (const raw of events) {
    const r = raw as unknown as Row;
    const at = t(r.recv_ts ?? r.ts ?? r.at);
    const ok = r.result?.ok !== false;
    if (r.agent && r.agent !== "system" && at !== null) {
      if (!first.has(r.agent)) first.set(r.agent, at);
      last.set(r.agent, at);
    }
    const text = JSON.stringify(r.result ?? {});
    // A row's own size stands for its answer's when the row carries no figure: the trace keeps a tool's result whole.
    const size = typeof r.result?.answer_chars === "number" ? (r.result.answer_chars as number) : text.length;
    if (r.agent && r.agent !== "system" && size > m.largest_answer.chars) m.largest_answer = { chars: size, tool: r.tool ?? null };
    if (r.agent && r.agent !== "system" && r.tool && !NOT_A_RESULT.has(r.tool)) {
      m.library.all_chars += typeof r.result?.output_chars === "number" ? (r.result.output_chars as number) : size;
      if (at !== null) resultsBySeat.set(r.agent, [...(resultsBySeat.get(r.agent) ?? []), at]);
    }
    if (/Timed out waiting for locks\//.test(text)) m.hub.lock_timeouts += 1;
    switch (r.tool) {
      case "record": {
        ok ? (m.record.accepted += 1) : (m.record.refused += 1);
        const seat = r.agent ?? "";
        const run = ok ? 0 : (streak.get(seat) ?? 0) + 1;
        if (ok && (streak.get(seat) ?? 0) >= 2) m.refused_twice.records += 1;
        m.refused_twice.longest_run = Math.max(m.refused_twice.longest_run, run);
        streak.set(seat, run);
        break;
      }
      case "attest": ok ? (m.attest.accepted += 1) : (m.attest.refused += 1); break;
      case "job_run":
        if (!ok && (r.result?.refused || r.result?.reason) && !r.result?.job) m.job_run_refused += 1;
        if (typeof r.result?.answer_chars === "number") {
          m.job_run_text.answers += 1;
          m.job_run_text.chars += r.result.answer_chars as number;
          hintChars += Number(r.result?.hint_chars ?? 0) || 0;
        }
        if (typeof r.result?.library_chars === "number") {
          m.library.recorded = true;
          m.library.hint_chars += r.result.library_chars as number;
        }
        break;
      case "tools":
        if (typeof r.result?.answer_chars === "number") {
          m.library.recorded = true;
          m.library.listing_chars += r.result.answer_chars as number;
        }
        break;
      case "wait": {
        m.idle_waits.waits += 1;
        const waited = Number(r.result?.waited_ms ?? r.result?.duration_ms ?? 0) / 1000 || 0;
        m.idle_waits.wait_s += waited;
        if (Number(r.result?.n ?? 0) === 0) {
          m.idle_waits.idle += 1;
          m.idle_waits.idle_s += waited;
        }
        break;
      }
      case "shell_timeout": r.args?.kind === "sleep_loop" ? (m.shell.sleep_loops_refused += 1) : (m.shell.timeouts += 1); break;
      case "compact_done":
        m.compactions.done += 1;
        if (typeof r.result?.summary_chars === "number") m.summaries_sized += 1;
        if (r.result?.summary_chars === 0) m.empty_summaries += 1;
        break;
      case "compact_failed": m.compactions.failed += 1; break;
      case "hub_health": {
        m.hub.samples += 1;
        const p99 = Number(r.result?.loop_p99_ms);
        if (Number.isFinite(p99)) m.hub.loop_p99_max_ms = Math.max(m.hub.loop_p99_max_ms ?? 0, p99);
        const share = Number(r.result?.heap_used_mb) / Number(r.result?.heap_limit_mb);
        if (Number.isFinite(share)) m.hub.heap_share_max = Math.max(m.hub.heap_share_max ?? 0, Math.round(share * 100) / 100);
        break;
      }
      case "hub_memory_high": m.hub.memory_high += 1; break;
      case "hub_restarted": m.hub.restarts += 1; break;
      case "hub_call": if (r.args?.fn === "answer_too_large") m.hub.answers_too_large += 1; break;
      case "seat_down": m.seats.down += 1; break;
      case "seat_relaunched": if (ok) m.seats.relaunched += 1; break;
      case "seat_dead": m.seats.dead += 1; break;
      case "image_scaled": m.seats.images_scaled += 1; break;
      case "regroup": if (r.result?.kind === "platform") m.platform_stalls += 1; break;
      default: break;
    }
  }
  if (m.job_run_text.chars) m.job_run_text.hint_share = Math.round((hintChars / m.job_run_text.chars) * 100) / 100;
  if (m.record.accepted) m.record.per_accepted = Math.round((m.record.refused / m.record.accepted) * 100) / 100;
  let seatHours = 0;
  for (const [a, f] of first) seatHours += Math.max(0, (last.get(a) ?? f) - f) / 3_600_000;
  if (seatHours > 0) m.compactions.per_seat_hour = Math.round((m.compactions.done / seatHours) * 10) / 10;
  m.idle_waits.wait_s = Math.round(m.idle_waits.wait_s);
  m.idle_waits.idle_s = Math.round(m.idle_waits.idle_s);
  if (seatHours > 0) m.idle_waits.share_of_seat_time = Math.round((m.idle_waits.idle_s / (seatHours * 3600)) * 100) / 100;
  if (m.library.recorded) {
    if (m.job_run_text.chars) m.library.of_job_run = Math.round((m.library.hint_chars / m.job_run_text.chars) * 100) / 100;
    if (m.library.all_chars) m.library.of_all = Math.round(((m.library.hint_chars + m.library.listing_chars) / m.library.all_chars) * 100) / 100;
  }
  // The gap before a model call: from the seat's last tool result after its previous call ended to this call's start.
  if (o.calls) {
    m.model_gap.source = "model-gateway";
    const gaps: number[] = [];
    const bySeat = new Map<string, ModelCall[]>();
    for (const c of o.calls) if (Number.isFinite(c.start) && Number.isFinite(c.end)) bySeat.set(c.seat, [...(bySeat.get(c.seat) ?? []), c]);
    for (const [seat, calls] of bySeat) {
      calls.sort((a, b) => a.start - b.start);
      const results = (resultsBySeat.get(seat) ?? []).sort((a, b) => a - b);
      let prevEnd = -Infinity;
      for (const c of calls) {
        let lastResult: number | null = null;
        for (const x of results) {
          if (x > c.start) break;
          if (x > prevEnd) lastResult = x;
        }
        if (lastResult !== null) gaps.push(Math.max(0, (c.start - lastResult) / 1000));
        prevEnd = Math.max(prevEnd, c.end);
      }
    }
    m.model_gap.calls = gaps.length;
    m.model_gap.median_s = pct(gaps, 50);
    m.model_gap.p90_s = pct(gaps, 90);
    m.model_gap.max_s = gaps.length ? Math.round(Math.max(...gaps) * 10) / 10 : null;
  }
  // The journal: accepted -> started -> finished -> committed, by job.
  const jobs = new Map<string, { accepted?: number; started?: number; finished?: number; fenced?: number; committed?: number; files?: number; told?: number }>();
  for (const raw of journal) {
    const j = raw as JRow;
    if (!j.job || !j.type) continue;
    const rec = jobs.get(j.job) ?? {};
    const at = t(j.at);
    if (at === null) continue;
    if (j.type === "job_accepted") rec.accepted ??= at;
    else if (j.type === "job_started") rec.started ??= at;
    else if (j.type === "job_finished") rec.finished = at;
    else if (j.type === "job_fenced" && (raw as { fenced?: unknown }).fenced === true) rec.fenced = at;
    else if (j.type === "job_notified") rec.told ??= at;
    else if (j.type === "job_committed") { rec.committed = at; rec.files = Number(j.outputs?.files ?? 0); }
    jobs.set(j.job, rec);
  }
  const commit: number[] = [];
  const queue: number[] = [];
  const told: number[] = [];
  const seal: number[] = [];
  for (const rec of jobs.values()) {
    if (rec.finished !== undefined && rec.committed !== undefined) {
      const s = Math.max(0, (rec.committed - rec.finished) / 1000);
      commit.push(s);
      if ((rec.files ?? 0) <= 50 && s > 30) { m.commit_wait.small_over_30s += 1; m.commit_wait.small_job_seconds += Math.round(s); }
    }
    if (rec.accepted !== undefined && rec.started !== undefined) queue.push(Math.max(0, (rec.started - rec.accepted) / 1000));
    if (rec.finished !== undefined) {
      m.delivery.jobs += 1;
      if (rec.told !== undefined) told.push(Math.max(0, (rec.told - rec.finished) / 1000));
      else m.delivery.never_told += 1;
    }
    if (rec.committed !== undefined && (rec.files ?? 0) >= LARGE_FILES) {
      const from = rec.fenced ?? rec.finished;
      if (from !== undefined) {
        seal.push(Math.max(0, (rec.committed - from) / 1000));
        m.large_seal.max_files = Math.max(m.large_seal.max_files ?? 0, rec.files ?? 0);
      }
    }
  }
  m.delivery.told = told.length;
  m.delivery.median_s = pct(told, 50); m.delivery.p90_s = pct(told, 90); m.delivery.max_s = told.length ? Math.round(Math.max(...told)) : null;
  m.large_seal.jobs = seal.length;
  m.large_seal.median_s = pct(seal, 50); m.large_seal.max_s = seal.length ? Math.round(Math.max(...seal)) : null;
  m.commit_wait.jobs = commit.length;
  m.commit_wait.median_s = pct(commit, 50); m.commit_wait.p90_s = pct(commit, 90); m.commit_wait.max_s = commit.length ? Math.round(Math.max(...commit)) : null;
  m.queue_wait = { median_s: pct(queue, 50), p90_s: pct(queue, 90), max_s: queue.length ? Math.round(Math.max(...queue)) : null };
  return m;
}

/** The metrics table's row. */
export function frictionWords(m: FrictionMetrics): string {
  const n = (x: number | null, unit = "") => (x === null ? "?" : `${x}${unit}`);
  return [
    `record: ${m.record.refused} refused for ${m.record.accepted} accepted (${n(m.record.per_accepted)} per accepted); attest: ${m.attest.refused} for ${m.attest.accepted}; job_run refused ${m.job_run_refused}`,
    `commit wait: median ${n(m.commit_wait.median_s, " s")}, p90 ${n(m.commit_wait.p90_s, " s")}, max ${n(m.commit_wait.max_s, " s")} over ${m.commit_wait.jobs} job(s); ${m.commit_wait.small_over_30s} small job(s) waited over 30 s (${m.commit_wait.small_job_seconds} job-seconds)`,
    `queue wait: median ${n(m.queue_wait.median_s, " s")}, p90 ${n(m.queue_wait.p90_s, " s")}, max ${n(m.queue_wait.max_s, " s")}`,
    `compactions: ${m.compactions.done} (${m.compactions.failed} failed, ${m.empty_summaries} with an empty summary), ${n(m.compactions.per_seat_hour)} per seat-hour`,
    `job_run answers: ${m.job_run_text.answers}, ${m.job_run_text.chars} characters, ${m.job_run_text.hint_share === null ? "?" : `${Math.round(m.job_run_text.hint_share * 100)}%`} of them hints at admission; largest answer ${m.largest_answer.chars} characters${m.largest_answer.tool ? ` (${m.largest_answer.tool})` : ""}`,
    `shell: ${m.shell.timeouts} stopped at the limit, ${m.shell.sleep_loops_refused} sleep loop(s) refused`,
    `hub: loop p99 at most ${n(m.hub.loop_p99_max_ms, " ms")}, heap at most ${m.hub.heap_share_max === null ? "?" : `${Math.round(m.hub.heap_share_max * 100)}%`} of its limit (${m.hub.samples} sample(s)), ${m.hub.memory_high} memory warning(s), ${m.hub.restarts} restart(s), ${m.hub.answers_too_large} answer(s) too large to send, ${m.hub.lock_timeouts} lock timeout(s)`,
    `seats: ${m.seats.down} down, ${m.seats.relaunched} started again, ${m.seats.dead} recorded dead; ${m.platform_stalls} platform stall(s) said`,
  ].join("; ");
}

// --- first sighting ---------------------------------------------------------------------------------

/**
 * An answer to look for, as metrics.ts reads it from the ledger: the keys its value is matched by (extensions/sighting.ts
 * answerKey; the pieces of a format of several, answerPieces), when its first record with that value was written, and by
 * whom. The keys are never written anywhere: the result says only when and in what kind of row.
 */
export type SightingAnswer = { section: string; id: string | null; answer: string; by: string; at: number | null; key: string | null; pieces: string[] | null };

export type SightingStatus = "seen" | "seen_in_pieces" | "seen_after" | "not_seen" | "not_matchable";

export type FirstSightingRow = {
  section: string;
  id: string | null;
  answer: string;
  status: SightingStatus;
  /** From the first row that held the value (for pieces, the row that held the last of them) to the answer's first record with it. */
  minutes: number | null;
  /** What kind of row first held it: file read, shell output, search, job_run answer, job_status answer, store_find result, tool result. */
  kind: string | null;
  /** Whether that row was the answering seat's own. */
  same_seat: boolean | null;
};

export type FirstSightings = {
  answers: FirstSightingRow[];
  seen: number;
  median_minutes: number | null;
  max_minutes: number | null;
  /** Job answers and store_find results on the trace with no text and no sighting digest (a run from before the digests): a value first seen there is not found. */
  rows_without_text: number;
  /** Rows whose digest was cut at its bound. */
  rows_cut: number;
};

/** The kind of a row that holds text, in words the table can print. */
function rowKind(tool: string): string {
  if (tool === "read") return "file read";
  if (tool === "bash" || tool === "powershell") return "shell output";
  if (tool === "grep" || tool === "find" || tool === "ls") return "search";
  if (tool === "job_run") return "job_run answer";
  if (tool === "job_status") return "job_status answer";
  if (tool === "store_find") return "store_find result";
  return "tool result";
}

const DIGEST_ROWS = new Set(["job_run", "job_status", "store_find"]);

/**
 * When each answer's value was first in front of a seat: the earliest trace row of a seat's tool result whose text
 * (kept whole) or sighting digest holds the value, at or before the answer's first record with it.
 */
export function firstSightings(events: readonly P.SwarmEvent[], answers: readonly SightingAnswer[]): FirstSightings {
  type Hit = { at: number; kind: string; agent: string };
  const firstOf = new Map<string, Hit>();
  const firstAfter = new Map<string, Hit>();
  const keys = new Set<string>();
  for (const a of answers) {
    if (a.key) keys.add(a.key);
    for (const p of a.pieces ?? []) keys.add(p);
  }
  // A key's first row at or before the latest answer that asks it; the earliest after, apart.
  const deadline = new Map<string, number>();
  for (const a of answers) {
    for (const k of [a.key, ...(a.pieces ?? [])]) if (k && a.at !== null) deadline.set(k, Math.max(deadline.get(k) ?? -Infinity, a.at));
  }
  let withoutText = 0;
  let cut = 0;
  const rows = [...events].map((e) => e as unknown as Row).filter((r) => r.agent && r.agent !== "system" && r.tool && r.result && typeof r.result === "object");
  rows.sort((a, b) => (t(a.recv_ts ?? a.ts ?? a.at) ?? 0) - (t(b.recv_ts ?? b.ts ?? b.at) ?? 0));
  for (const r of rows) {
    const at = t(r.recv_ts ?? r.ts ?? r.at);
    if (at === null) continue;
    const tool = r.tool!;
    const output = typeof r.result?.output === "string" ? (r.result.output as string) : null;
    const digest = r.result?.sighted;
    if (output === null && !digest) {
      if (DIGEST_ROWS.has(tool) && r.result?.ok !== false) withoutText += 1;
      continue;
    }
    if (digest && (digest as { cut?: unknown }).cut === true) cut += 1;
    if (!keys.size) continue;
    const text = output !== null ? sightingText(output) : null;
    for (const k of keys) {
      if (firstOf.has(k) && firstAfter.has(k)) continue;
      const held = (text !== null && textHolds(text, k)) || (digest ? digestHolds(digest, k) : false);
      if (!held) continue;
      const hit = { at, kind: rowKind(tool), agent: r.agent! };
      const due = deadline.get(k);
      if (due === undefined || at <= due) {
        if (!firstOf.has(k)) firstOf.set(k, hit);
      } else if (!firstAfter.has(k)) firstAfter.set(k, hit);
    }
  }
  const out: FirstSightingRow[] = [];
  for (const a of answers) {
    const base = { section: a.section, id: a.id, answer: a.answer };
    if ((!a.key && !a.pieces) || a.at === null) {
      out.push({ ...base, status: "not_matchable", minutes: null, kind: null, same_seat: null });
      continue;
    }
    const before = (k: string) => {
      const h = firstOf.get(k);
      return h && h.at <= a.at! ? h : undefined;
    };
    const whole = a.key ? before(a.key) : undefined;
    const parts = !whole && a.pieces ? a.pieces.map(before) : null;
    const hit = whole ?? (parts && parts.every(Boolean) ? parts.reduce((x, y) => (y!.at > x!.at ? y : x)) : undefined);
    if (hit) {
      out.push({ ...base, status: whole ? "seen" : "seen_in_pieces", minutes: Math.round(((a.at - hit.at) / 60000) * 10) / 10, kind: hit.kind, same_seat: hit.agent === a.by });
      continue;
    }
    const early = a.key ? firstOf.get(a.key) : undefined;
    const after = a.key ? (early && early.at > a.at ? early : firstAfter.get(a.key)) : undefined;
    out.push({ ...base, status: after ? "seen_after" : "not_seen", minutes: null, kind: after?.kind ?? null, same_seat: after ? after.agent === a.by : null });
  }
  const mins = out.filter((x) => x.minutes !== null).map((x) => x.minutes!);
  return { answers: out, seen: mins.length, median_minutes: pct(mins, 50), max_minutes: mins.length ? Math.max(...mins) : null, rows_without_text: withoutText, rows_cut: cut };
}
