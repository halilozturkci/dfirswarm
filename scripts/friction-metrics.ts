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
};

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

export function frictionMetrics(events: readonly P.SwarmEvent[], journal: readonly Record<string, unknown>[] = []): FrictionMetrics {
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
  };
  let hintChars = 0;
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
    if (/Timed out waiting for locks\//.test(text)) m.hub.lock_timeouts += 1;
    switch (r.tool) {
      case "record": ok ? (m.record.accepted += 1) : (m.record.refused += 1); break;
      case "attest": ok ? (m.attest.accepted += 1) : (m.attest.refused += 1); break;
      case "job_run":
        if (!ok && (r.result?.refused || r.result?.reason) && !r.result?.job) m.job_run_refused += 1;
        if (typeof r.result?.answer_chars === "number") {
          m.job_run_text.answers += 1;
          m.job_run_text.chars += r.result.answer_chars as number;
          hintChars += Number(r.result?.hint_chars ?? 0) || 0;
        }
        break;
      case "shell_timeout": r.args?.kind === "sleep_loop" ? (m.shell.sleep_loops_refused += 1) : (m.shell.timeouts += 1); break;
      case "compact_done":
        m.compactions.done += 1;
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
  // The journal: accepted -> started -> finished -> committed, by job.
  const jobs = new Map<string, { accepted?: number; started?: number; finished?: number; committed?: number; files?: number }>();
  for (const raw of journal) {
    const j = raw as JRow;
    if (!j.job || !j.type) continue;
    const rec = jobs.get(j.job) ?? {};
    const at = t(j.at);
    if (at === null) continue;
    if (j.type === "job_accepted") rec.accepted ??= at;
    else if (j.type === "job_started") rec.started ??= at;
    else if (j.type === "job_finished") rec.finished = at;
    else if (j.type === "job_committed") { rec.committed = at; rec.files = Number(j.outputs?.files ?? 0); }
    jobs.set(j.job, rec);
  }
  const commit: number[] = [];
  const queue: number[] = [];
  for (const rec of jobs.values()) {
    if (rec.finished !== undefined && rec.committed !== undefined) {
      const s = Math.max(0, (rec.committed - rec.finished) / 1000);
      commit.push(s);
      if ((rec.files ?? 0) <= 50 && s > 30) { m.commit_wait.small_over_30s += 1; m.commit_wait.small_job_seconds += Math.round(s); }
    }
    if (rec.accepted !== undefined && rec.started !== undefined) queue.push(Math.max(0, (rec.started - rec.accepted) / 1000));
  }
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
