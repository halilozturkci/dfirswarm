/**
 * What a running job is doing, seen from the host without reading it (B11).
 *
 * On c09 one job wrote its only output 40 s after it started and then
 * nothing moved for 22.6 minutes until its holder cancelled it; stdout and
 * stderr stayed empty throughout. Nobody could tell a quiet healthy job from
 * a stuck one: a single-pass tool reading a 5 GB image is silent and
 * I/O-bound for minutes too. So three signals, each metadata only:
 *
 * 1. the job's output directory ($OUT, host staging): how many files, how
 *    many bytes, the newest file's time and its name, sanitised; walked
 *    without following a link, and bounded (the bound is said);
 * 2. its stdout and stderr: their sizes and times;
 * 3. its CPU and I/O: msb's metrics for the worker VM when the host has
 *    them, else the worker's own heartbeat (/job/heartbeat, written every
 *    15 s by the worker script from /proc/stat and /proc/diskstats: the VM
 *    runs this one job, so the VM's counters are the job's).
 *
 * "Suspected stall" only when all three are still for the stall window
 * (SWARM_JOB_STALL_SEC, 600) and the job is not within two minutes of its
 * timeout; "unknown" when the CPU and I/O signal is missing, since silence
 * alone proves nothing. A measurement must be current: a heartbeat whose
 * stamp has not advanced for a minute of samples is no CPU signal, a last
 * sample older than two minutes says nothing now, and stillness is never
 * counted across a gap between samples. The files are not sealed and not citable until the
 * job commits; cancelling a job keeps what it wrote; nothing here cancels
 * anything. Samples are kept beside the job's staging on the host
 * (telemetry.jsonl), so a restarted service reads them where they were.
 * Nothing here knows a tool or a format.
 */
import type { Dirent } from "node:fs";
import { appendFile, lstat, readdir, readFile, stat } from "node:fs/promises";
import { join } from "node:path";
import { jobSensitivity, sizeBucket, type SensitivityJob } from "./output-hygiene.ts";

/** Entries walked in a job's output directory per sample: past it the count is a lower bound, and says so. */
export const OUT_WALK_MAX = 10_000;
/** A job within this long of its timeout is ending, not stalled. */
export const NEAR_TIMEOUT_MS = 2 * 60_000;
/**
 * The longest gap between two samples that stillness is counted across,
 * and the oldest a last sample may be to say anything now: four of the
 * service's half-minute samples missed. Past it the sampler is behind or
 * stopped, and silence between samples is not measured silence.
 */
export const SAMPLE_GAP_MS = 2 * 60_000;
/**
 * How long, in the host's samples, a heartbeat may read the same before it
 * is stale: four of the worker's 15 s beats missed. A heartbeat that stopped
 * changing is a loop that died, not a still job. Judged by the heartbeat's
 * own stamp not advancing across the host's samples, so a guest clock that
 * differs from the host's changes nothing.
 */
export const HEARTBEAT_STALE_MS = 60_000;

/** Whole seconds from the environment, in milliseconds, or the default. */
function envMs(name: string, dfltSec: number): number {
  const raw = process.env[name]?.trim();
  const n = raw && /^\d+$/.test(raw) ? Number(raw) : dfltSec;
  return n * 1000;
}

/** How long all three signals must stay still before a job shows as a suspected stall (SWARM_JOB_STALL_SEC, 600). */
export function stallMs(): number {
  return envMs("SWARM_JOB_STALL_SEC", 600);
}

/** A file name as it may be shown: control characters and anything unprintable replaced, never cut. */
export function sanitizeName(name: string): string {
  return [...name].map((ch) => (/[\p{Cc}\p{Cf}\p{Co}\p{Cs}]/u.test(ch) ? "?" : ch)).join("");
}

export type CpuSignal = { source: "msb" | "heartbeat"; cpu: number; io: number; at: number };

export type TelemetrySample = {
  at: number;
  out: { files: number; bytes: number; newest_ms: number | null; newest: string | null; bounded: boolean };
  stdout: { bytes: number; mtime_ms: number | null };
  stderr: { bytes: number; mtime_ms: number | null };
  cpu: CpuSignal | null;
};

/** The output directory's metadata: files, bytes, the newest file; no link followed, at most OUT_WALK_MAX entries. */
async function walkOut(dir: string): Promise<TelemetrySample["out"]> {
  let files = 0;
  let bytes = 0;
  let newest_ms: number | null = null;
  let newest: string | null = null;
  let seen = 0;
  const stack: string[] = [""];
  while (stack.length) {
    const rel = stack.pop()!;
    const entries = await readdir(join(dir, rel), { withFileTypes: true }).catch(() => [] as Dirent[]);
    for (const e of entries) {
      seen += 1;
      if (seen > OUT_WALK_MAX) return { files, bytes, newest_ms, newest, bounded: true };
      const path = rel ? `${rel}/${e.name}` : e.name;
      const st = await lstat(join(dir, path)).catch(() => null);
      if (!st) continue;
      if (st.isDirectory()) {
        stack.push(path);
        continue;
      }
      if (!st.isFile()) continue;
      files += 1;
      bytes += st.size;
      if (newest_ms === null || st.mtimeMs > newest_ms) {
        newest_ms = st.mtimeMs;
        newest = sanitizeName(path);
      }
    }
  }
  return { files, bytes, newest_ms, newest, bounded: false };
}

async function sizeOf(path: string): Promise<{ bytes: number; mtime_ms: number | null }> {
  const st = await stat(path).catch(() => null);
  return st ? { bytes: st.size, mtime_ms: st.mtimeMs } : { bytes: 0, mtime_ms: null };
}

/** The worker's heartbeat (/job/heartbeat): "<epoch s> <cpu jiffies> <io sectors>", or null. */
export async function readHeartbeat(ctlDir: string): Promise<CpuSignal | null> {
  const text = await readFile(join(ctlDir, "heartbeat"), "utf8").catch(() => "");
  const m = /^(\d+)\s+(\d+)\s+(\d+)\s*$/.exec(text.trim());
  if (!m) return null;
  return { source: "heartbeat", at: Number(m[1]) * 1000, cpu: Number(m[2]), io: Number(m[3]) };
}

/**
 * One sample of a running job, from its staging on the host: the output
 * directory, its logs, and its CPU and I/O (msb's metrics when given, else
 * the heartbeat).
 */
export async function sampleJob(staging: { out: string; ctl: string }, o: { metrics?: () => Promise<{ cpu_ns: number; io_bytes: number } | null>; now?: number } = {}): Promise<TelemetrySample> {
  const now = o.now ?? Date.now();
  const m = o.metrics ? await o.metrics().catch(() => null) : null;
  const cpu: CpuSignal | null = m ? { source: "msb", cpu: m.cpu_ns, io: m.io_bytes, at: now } : await readHeartbeat(staging.ctl);
  return {
    at: now,
    out: await walkOut(staging.out),
    stdout: await sizeOf(join(staging.ctl, "stdout.log")),
    stderr: await sizeOf(join(staging.ctl, "stderr.log")),
    cpu,
  };
}

/** Keep a sample beside the job's staging (metadata only), for the next reader and a restarted service. */
export async function keepSample(base: string, s: TelemetrySample): Promise<void> {
  await appendFile(join(base, "telemetry.jsonl"), `${JSON.stringify(s)}\n`, "utf8").catch(() => undefined);
}

export async function readSamples(base: string): Promise<TelemetrySample[]> {
  const text = await readFile(join(base, "telemetry.jsonl"), "utf8").catch(() => "");
  const out: TelemetrySample[] = [];
  for (const line of text.split("\n")) {
    if (!line.trim()) continue;
    try {
      out.push(JSON.parse(line) as TelemetrySample);
    } catch {
      // a torn line: skipped
    }
  }
  return out;
}

export type JobProgress = {
  state: "moving" | "quiet" | "suspected_stall" | "unknown";
  why: string;
  signals: {
    out: { files: number; bytes: number; newest: string | null; newest_at: string | null; bounded: boolean; still_ms: number | null };
    logs: { stdout_bytes: number; stderr_bytes: number; still_ms: number | null };
    cpu: { source: "msb" | "heartbeat" | null; still_ms: number | null };
  };
  running_ms: number;
  timeout_in_ms: number | null;
  /** Unsealed: nothing in the output directory can be cited until the job commits. */
  sealed: false;
  hint: string;
};

/**
 * What an agent is shown of a running job whose outputs are, or will be,
 * sensitive (docs/adr/0016): the verdict and the timing, which are what the
 * signals are for, and the sizes as the sealed answer gives them, a bucket
 * (output-hygiene.ts sizeBucket), never a count of bytes or files and never
 * the newest file's name or time. An output directory that holds 299 bytes
 * for the right guess and none for a wrong one is the bit the sealed answer
 * hides; the running one must not hand it out a few seconds earlier. The
 * verdict itself (`state`, `why`, the `still_ms` figures) is assessed from
 * the exact samples first.
 */
export type SensitiveProgress = Omit<JobProgress, "signals"> & {
  signals: {
    out: { size: string; still_ms: number | null };
    logs: { stdout_size: string; stderr_size: string; still_ms: number | null };
    cpu: JobProgress["signals"]["cpu"];
  };
  withheld: string;
};

/** A running job's progress as an agent is shown it when the job is sensitive: sizes by bucket, no file count, no newest file. */
export function sensitiveProgress(p: JobProgress): SensitiveProgress {
  const { signals, ...rest } = p;
  return {
    ...rest,
    signals: {
      out: { size: sizeBucket(signals.out.bytes), still_ms: signals.out.still_ms },
      logs: { stdout_size: sizeBucket(signals.logs.stdout_bytes), stderr_size: sizeBucket(signals.logs.stderr_bytes), still_ms: signals.logs.still_ms },
      cpu: signals.cpu,
    },
    withheld: "sensitive output: its exact sizes, its file count and its newest file are not shown here; the sealed manifest, custody and the report hold what it wrote",
  };
}

/**
 * Where a running job stands, from its samples: how long each signal has
 * been still (the first sample with the value it has now), and the verdict.
 */
export function assessJob(samples: TelemetrySample[], o: { started_at: string | undefined; timeout_seconds: number; now?: number }): JobProgress {
  const now = o.now ?? Date.now();
  const last = samples.at(-1);
  const started = o.started_at ? Date.parse(o.started_at) : NaN;
  const running = Number.isFinite(started) ? now - started : 0;
  const timeoutIn = Number.isFinite(started) ? started + o.timeout_seconds * 1000 - now : null;
  const hint = "Metadata only: the files are not sealed and not citable until the job commits. Cancelling it (job_status cancel: true) keeps what it wrote; nothing is cancelled for you.";
  const empty = { files: 0, bytes: 0, newest: null, newest_at: null, bounded: false, still_ms: null };
  if (!last) return { state: "unknown", why: "no sample of it yet", signals: { out: empty, logs: { stdout_bytes: 0, stderr_bytes: 0, still_ms: null }, cpu: { source: null, still_ms: null } }, running_ms: running, timeout_in_ms: timeoutIn, sealed: false, hint };
  // A CPU and I/O signal is current when msb gave it at the sample, or the
  // worker's heartbeat stamp advanced within HEARTBEAT_STALE_MS of the
  // host's samples: a heartbeat file that stopped changing is a loop that
  // died, never a still job. frozenFrom[i] is the first sample of the run
  // of samples whose heartbeat read the same as sample i's.
  const frozenFrom: number[] = [];
  for (let i = 0; i < samples.length; i++) {
    const x = samples[i]!;
    const prev = i > 0 ? samples[i - 1]! : null;
    const same = prev && x.cpu?.source === "heartbeat" && prev.cpu?.source === "heartbeat" && prev.cpu.at === x.cpu.at && x.at - prev.at <= SAMPLE_GAP_MS;
    frozenFrom.push(same ? frozenFrom[i - 1]! : i);
  }
  const currentAt = (i: number) => {
    const x = samples[i]!;
    return Boolean(x.cpu && (x.cpu.source === "msb" || x.at - samples[frozenFrom[i]!]!.at <= HEARTBEAT_STALE_MS));
  };
  const indexOf = new Map(samples.map((x, i) => [x, i] as const));
  const current = (x: TelemetrySample) => currentAt(indexOf.get(x) ?? samples.length - 1);
  // How long a signal has held the value it has now, over the samples kept:
  // never across a gap longer than SAMPLE_GAP_MS between two samples, which
  // is time nobody measured.
  const stillSince = (same: (a: TelemetrySample, b: TelemetrySample) => boolean): number | null => {
    let since = last.at;
    for (let i = samples.length - 2; i >= 0; i--) {
      if (samples[i + 1]!.at - samples[i]!.at > SAMPLE_GAP_MS || !same(samples[i]!, last)) break;
      since = samples[i]!.at;
    }
    return samples.length > 1 ? now - since : null;
  };
  const outStill = stillSince((a, b) => a.out.files === b.out.files && a.out.bytes === b.out.bytes && a.out.newest_ms === b.out.newest_ms);
  const logStill = stillSince((a, b) => a.stdout.bytes === b.stdout.bytes && a.stderr.bytes === b.stderr.bytes);
  const cpuStill = last.cpu && current(last) ? stillSince((a, b) => Boolean(current(a) && a.cpu && b.cpu && a.cpu.cpu === b.cpu.cpu && a.cpu.io === b.cpu.io)) : null;
  const signals = {
    out: { files: last.out.files, bytes: last.out.bytes, newest: last.out.newest, newest_at: last.out.newest_ms ? new Date(last.out.newest_ms).toISOString() : null, bounded: last.out.bounded, still_ms: outStill },
    logs: { stdout_bytes: last.stdout.bytes, stderr_bytes: last.stderr.bytes, still_ms: logStill },
    cpu: { source: last.cpu?.source ?? null, still_ms: cpuStill },
  };
  const base = { signals, running_ms: running, timeout_in_ms: timeoutIn, sealed: false as const, hint };
  // A measurement of now: the host sampled it lately.
  if (now - last.at > SAMPLE_GAP_MS) {
    return { state: "unknown", why: `it has not been sampled for ${Math.round((now - last.at) / 60_000)} min (the job service samples every half minute: its sampler is behind or stopped), so nothing says what it does now`, ...base };
  }
  if (last.cpu && !current(last)) {
    const from = samples[frozenFrom[samples.length - 1]!]!.at;
    return { state: "unknown", why: `its heartbeat has not been written since ${new Date(from).toISOString()} (the same stamp for ${Math.round((last.at - from) / 60_000)} min of samples): the CPU and I/O signal is stale, and silence alone proves nothing`, ...base };
  }
  const window = stallMs();
  const outMoved = outStill === null || outStill < window;
  const logsMoved = logStill === null || logStill < window;
  if (!last.cpu) {
    return { state: "unknown", why: `no CPU or I/O telemetry for it (neither msb's metrics nor the worker's heartbeat): silence alone proves nothing${!outMoved && !logsMoved ? `; its outputs and logs have not moved for ${Math.round(Math.min(outStill ?? 0, logStill ?? 0) / 60_000)} min` : ""}`, ...base };
  }
  const cpuMoved = cpuStill === null || cpuStill < window;
  if (outMoved || logsMoved) return { state: "moving", why: outMoved ? "its output directory is changing" : "its logs are growing", ...base };
  if (cpuMoved) return { state: "quiet", why: `its outputs and logs are still, and its CPU or I/O moves (${last.cpu.source}): working without writing yet (a single pass over a large object is silent for minutes)`, ...base };
  if (timeoutIn !== null && timeoutIn <= NEAR_TIMEOUT_MS) return { state: "quiet", why: `every signal is still, and its timeout is ${Math.max(0, Math.round(timeoutIn / 1000))} s away: it ends by itself`, ...base };
  return { state: "suspected_stall", why: `its outputs, its logs and its CPU and I/O (${last.cpu.source}) have all been still for ${Math.round(Math.min(outStill ?? 0, logStill ?? 0, cpuStill ?? 0) / 60_000)} min, and its timeout is ${timeoutIn === null ? "unknown" : `${Math.round(timeoutIn / 60_000)} min away`}`, ...base };
}

/** The heartbeat the worker script runs beside the job (every 15 s): the VM's own counters, the VM running this one job. */
export const HEARTBEAT_LINES = [
  "( while :; do",
  "  c=$(awk '/^cpu /{print $2+$3+$4+$7+$8+$9}' /proc/stat 2>/dev/null)",
  "  d=$(awk '{s+=$6+$10} END {print s+0}' /proc/diskstats 2>/dev/null)",
  '  echo "$(date +%s) ${c:-0} ${d:-0}" > /job/heartbeat.tmp 2>/dev/null && mv -f /job/heartbeat.tmp /job/heartbeat 2>/dev/null',
  "  sleep 15",
  // Its own stdio is nothing: a sleep left behind holds no pipe of the job's.
  "done ) </dev/null >/dev/null 2>&1 &",
  "DFIRSWARM_HEARTBEAT=$!",
];
export const HEARTBEAT_STOP = 'kill "$DFIRSWARM_HEARTBEAT" 2>/dev/null || true';

/**
 * A running job's progress read from disk, as the job service last sampled
 * it (the header, the regroup and the console read it here, never the job's
 * output): its record in store/jobs/<id>/job.json and the samples beside its
 * staging. Null when it is not running.
 */
export async function jobProgressOnDisk(sandbox: string, id: string, now = Date.now()): Promise<JobProgress | SensitiveProgress | null> {
  const { storePaths } = await import("./evidence-store.ts");
  const P = storePaths(sandbox);
  type OnDisk = { id?: string; state?: string; attempt?: number; started_at?: string; spec?: Record<string, unknown> & { timeout_seconds?: number }; scope?: { manifest?: string } };
  const job = await readFile(join(P.jobs, id, "job.json"), "utf8").then((t) => JSON.parse(t) as OnDisk).catch(() => null);
  if (!job || job.state !== "running") return null;
  const samples = await readSamples(join(P.staging, `${id}-${job.attempt ?? 1}`));
  const progress = assessJob(samples, { started_at: job.started_at, timeout_seconds: Number(job.spec?.timeout_seconds ?? 0), now });
  // What an agent is told of a job that is, or will be, sensitive is a bucket (the header and the regroup read it here).
  const sensitive = await jobSensitivity(sandbox, { id, spec: (job.spec ?? {}) as SensitivityJob["spec"], ...(job.scope ? { scope: job.scope } : {}) }, { running: true }).catch(() => ({ why: "derived" }));
  return sensitive ? sensitiveProgress(progress) : progress;
}

/** A job's progress in words, for a header or a regroup: its state, why, and what cancel does. */
export function progressWords(id: string, p: JobProgress | SensitiveProgress): string {
  const min = (ms: number | null) => (ms === null ? "?" : `${Math.round(ms / 60_000)} min`);
  const head = `${id} ${p.state === "suspected_stall" ? "SUSPECTED STALL" : p.state} (running ${min(p.running_ms)}${p.timeout_in_ms !== null ? `, its timeout in ${min(p.timeout_in_ms)}` : ""}): ${p.why}`;
  const tail = "Not sealed, not citable yet; cancel keeps what it wrote, and nothing cancels it for you";
  if ("withheld" in p) return `${head}; out ${p.signals.out.size} (sensitive: no byte count, no file count); stdout ${p.signals.logs.stdout_size}, stderr ${p.signals.logs.stderr_size}. ${tail}`;
  return `${head}; out ${p.signals.out.files}${p.signals.out.bounded ? "+" : ""} file(s), ${p.signals.out.bytes} bytes${p.signals.out.newest ? `, newest ${p.signals.out.newest}` : ""}; stdout ${p.signals.logs.stdout_bytes} B, stderr ${p.signals.logs.stderr_bytes} B. ${tail}`;
}
