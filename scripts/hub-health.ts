/**
 * What the hub writes about itself each minute, and when it takes a heap
 * snapshot.
 *
 * Three post-mortems could not separate causes because nothing recorded the
 * host or the hub while a run slowed: whether the shared machine or the
 * run's own sweeps made a hub slow, which structure filled a heap, how late
 * the event loop was. The snapshot Node writes at the heap limit was 0 bytes
 * on the run s17fdfe: the hub died while writing it. So the hub samples
 * itself and the host on the trace (hub_health), and takes its snapshot at
 * 60% of the limit, once, while it still can.
 */
import { cpus, freemem, loadavg, totalmem } from "node:os";
import { monitorEventLoopDelay } from "node:perf_hooks";
import v8 from "node:v8";

export type HubHealth = {
  rss_mb: number;
  heap_used_mb: number;
  heap_limit_mb: number;
  external_mb: number;
  /** The event loop's delay over the last sample period: how late a timer fired, in ms. */
  loop_p50_ms: number;
  loop_p99_ms: number;
  loop_max_ms: number;
  /** The host: load average over one minute, cores, memory free of total. */
  host_load1: number;
  host_cpus: number;
  host_free_mb: number;
  host_total_mb: number;
  /** Counts of the hub's own structures a caller names (transfers held, calls in flight, sweeps, jobs sealing…). */
  holds: Record<string, number>;
};

const mb = (x: number) => Math.round(x / 2 ** 20);

export function loopMonitor(): { read(): { p50: number; p99: number; max: number }; stop(): void } {
  const h = monitorEventLoopDelay({ resolution: 20 });
  h.enable();
  return {
    read() {
      const out = { p50: Math.round(h.percentile(50) / 1e6), p99: Math.round(h.percentile(99) / 1e6), max: Math.round(h.max / 1e6) };
      h.reset();
      return out;
    },
    stop: () => h.disable(),
  };
}

export function sampleHealth(loop: { p50: number; p99: number; max: number }, holds: Record<string, number> = {}): HubHealth {
  const m = process.memoryUsage();
  return {
    rss_mb: mb(m.rss),
    heap_used_mb: mb(m.heapUsed),
    heap_limit_mb: mb(v8.getHeapStatistics().heap_size_limit),
    external_mb: mb(m.external),
    loop_p50_ms: loop.p50,
    loop_p99_ms: loop.p99,
    loop_max_ms: loop.max,
    host_load1: Math.round(loadavg()[0]! * 100) / 100,
    host_cpus: cpus().length,
    host_free_mb: mb(freemem()),
    host_total_mb: mb(totalmem()),
    holds,
  };
}

/** The share of the heap limit at which the hub takes its one snapshot (SWARM_HUB_SNAPSHOT_AT, 0 for never). */
export function snapshotAt(env: NodeJS.ProcessEnv = process.env): number {
  const n = Number(env.SWARM_HUB_SNAPSHOT_AT);
  return env.SWARM_HUB_SNAPSHOT_AT !== undefined && Number.isFinite(n) && n >= 0 && n < 1 ? n : 0.6;
}

/** Whether a snapshot is due: the heap is past the line and none was taken yet. */
export function snapshotDue(h: { heap_used_mb: number; heap_limit_mb: number }, taken: boolean, at = snapshotAt()): boolean {
  return !taken && at > 0 && h.heap_limit_mb > 0 && h.heap_used_mb > at * h.heap_limit_mb;
}
