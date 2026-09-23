/**
 * File-system change bus for SSE. Watches the runs directory recursively and
 * coalesces bursts into one `change` event that names the swarms touched and,
 * per swarm, what kind of thing moved. Falls back to a slow poll when
 * recursive fs.watch is unavailable.
 *
 * Not every write in a sandbox is news. Pi appends to its session file on
 * every message, the netguard proxy logs every connection, the idle watchdog
 * writes its state every half minute, and every post or claim takes and
 * drops the lock-table mutex: none of that changes anything the console
 * shows, and together it was most of the events a running swarm produced.
 * Those kinds are classified and then dropped here, at the source, so
 * neither the clients nor the finish line's change stamp ever see them.
 */
import { watch, type FSWatcher } from "node:fs";
import { stat } from "node:fs/promises";
import { join, relative, sep } from "node:path";

export type ChangeKind =
  | "registry"
  | "threads"
  | "locks"
  | "done"
  | "budget"
  /** traces/events.jsonl: the event log the trace and the agents' marks read. */
  | "events"
  | "history"
  | "work"
  | "team"
  | "tools"
  | "ledger"
  | "names"
  | "inputs"
  /** SWARM.md, the rendered contract. */
  | "contract"
  | "other"
  // Never published: nothing the console shows comes from these.
  /** Pi's own session files under .pi-sessions/ and .pi/. */
  | "sessions"
  /** Everything else under traces/: the proxy log, the watchdog's log and state. */
  | "logs"
  /** The harness's bookkeeping: inbox cursors, the lock-table mutex, the pristine inputs, guard hooks, pids. */
  | "internal";

/** Kinds the bus classifies and then keeps to itself. */
export const SUPPRESSED_KINDS: ReadonlySet<ChangeKind> = new Set<ChangeKind>(["sessions", "logs", "internal"]);

export type ChangeEvent = {
  swarm_ids: string[];
  /** Every kind in the burst, across swarms (kept for older clients). */
  kinds: ChangeKind[];
  /** What moved, per swarm: the key a client scopes its refetches on. */
  by_swarm: Record<string, ChangeKind[]>;
  at: string;
  /** Whether the recursive fs.watch is attached (false while polling). */
  watching: boolean;
};

export type BusMessage =
  | { event: "change"; data: ChangeEvent }
  | { event: "job"; data: unknown }
  | { event: "hello"; data: { runs_dir: string; watching: boolean } };

type Listener = (msg: BusMessage) => void;

function kindOf(second: string, third: string): ChangeKind {
  switch (second) {
    case "threads":
      return "threads";
    case "locks":
      return third === ".table.lock" ? "internal" : "locks";
    case "done":
      return "done";
    case "budget.json":
      return "budget";
    case "traces":
      return third === "" || third === "events.jsonl" ? "events" : "logs";
    case "history":
      return "history";
    case "work":
      return "work";
    case "team.json":
      return "team";
    case "tools":
      return "tools";
    case "ledger":
      return "ledger";
    case "names.json":
      return "names";
    case "inputs":
    case "inputs.json":
      return "inputs";
    case "SWARM.md":
      return "contract";
    case ".pi-sessions":
    case ".pi":
      return "sessions";
    case "inbox":
    case ".inputs-pristine":
    case ".fsguard":
    case ".zsh":
    case ".bash":
    case "bin":
    case "package":
    case "netguard.pid":
    case "netguard.port":
    case "idle-nudge.pid":
      return "internal";
    default:
      return "other";
  }
}

export function classifyPath(runsDir: string, absOrRel: string): { swarmId: string | null; kind: ChangeKind } {
  const rel = absOrRel.startsWith(runsDir) ? relative(runsDir, absOrRel) : absOrRel;
  const parts = rel.split(sep).filter(Boolean);
  if (parts.length === 0) return { swarmId: null, kind: "other" };
  if (parts[0] === "registry.json") return { swarmId: null, kind: "registry" };
  return { swarmId: parts[0], kind: kindOf(parts[1] ?? "", parts[2] ?? "") };
}

export class ChangeBus {
  private listeners = new Set<Listener>();
  private watcher: FSWatcher | null = null;
  private pending: { ids: Set<string>; kinds: Set<ChangeKind>; bySwarm: Map<string, Set<ChangeKind>> } | null = null;
  private timer: NodeJS.Timeout | null = null;
  private pollTimer: NodeJS.Timeout | null = null;
  private retryTimer: NodeJS.Timeout | null = null;
  private closed = false;
  watching = false;
  private readonly runsDir: string;
  private readonly debounceMs: number;
  private readonly maxWaitMs: number;
  /** When the burst now pending began, so a steady stream of writes still flushes. */
  private burstStartedAt = 0;
  /** A counter per swarm, moved on every published touch: "has anything changed since?" without a clock. */
  private touchSeq = 0;
  private readonly touched = new Map<string, number>();
  /** Size and mtime of every path the watcher has reported, so a report that changed neither is dropped. */
  private readonly stamps = new Map<string, string>();
  private static readonly STAMPS_MAX = 20_000;

  /**
   * A burst ends `debounceMs` after its last event, not its first: the
   * filesystem delivers one logical write as several events spread over a
   * few hundred milliseconds (a temp file, a rename, a directory entry), and
   * a window anchored on the first event cut one post into three `change`
   * events on macOS. A burst is flushed after `maxWaitMs` regardless, so a
   * swarm that never stops writing still reaches the console once a second
   * rather than five times.
   */
  constructor(runsDir: string, debounceMs = 200, maxWaitMs = 1000) {
    this.runsDir = runsDir;
    this.debounceMs = debounceMs;
    this.maxWaitMs = Math.max(debounceMs, maxWaitMs);
  }

  subscribe(fn: Listener): () => void {
    this.listeners.add(fn);
    return () => {
      this.listeners.delete(fn);
    };
  }

  publish(msg: BusMessage): void {
    for (const fn of this.listeners) {
      try {
        fn(msg);
      } catch {
        // a broken client must not take the bus down
      }
    }
  }

  /**
   * The change stamp of a swarm: the same value back means nothing the
   * console could show has changed under it since. Zero for a swarm never
   * touched in this process.
   */
  lastTouched(swarmId: string): number {
    return this.touched.get(swarmId) ?? 0;
  }

  /**
   * A path the watcher reported. The filesystem reports more than changes:
   * macOS delivers a write as several notifications over a second or more,
   * and a sync client touching attributes afterwards reports the path again
   * with the same bytes in it. A report is a change only when the size or
   * the mtime moved since the last report of that path (a directory's mtime
   * moves when an entry is added or removed). Public so a test can drive it
   * without a real watcher.
   */
  async noteFsEvent(name: string): Promise<boolean> {
    const { swarmId, kind } = classifyPath(this.runsDir, name);
    if (SUPPRESSED_KINDS.has(kind)) return false;
    const abs = name.startsWith(this.runsDir) ? name : join(this.runsDir, name);
    const info = await stat(abs).catch(() => null);
    const stamp = info ? `${info.size}:${info.mtimeMs}` : "gone";
    if (this.stamps.get(abs) === stamp) return false;
    if (this.stamps.size >= ChangeBus.STAMPS_MAX) this.stamps.clear();
    this.stamps.set(abs, stamp);
    this.touch(swarmId, kind);
    return true;
  }

  /** Public so actions and tests can nudge clients without touching disk. */
  touch(swarmId: string | null, kind: ChangeKind): void {
    if (SUPPRESSED_KINDS.has(kind)) return;
    if (!this.pending) this.pending = { ids: new Set(), kinds: new Set(), bySwarm: new Map() };
    if (swarmId) {
      this.pending.ids.add(swarmId);
      this.touched.set(swarmId, ++this.touchSeq);
      const slot = this.pending.bySwarm.get(swarmId) ?? new Set<ChangeKind>();
      slot.add(kind);
      this.pending.bySwarm.set(swarmId, slot);
    }
    this.pending.kinds.add(kind);
    const now = Date.now();
    if (!this.timer) this.burstStartedAt = now;
    else clearTimeout(this.timer);
    const wait = Math.max(0, Math.min(this.debounceMs, this.burstStartedAt + this.maxWaitMs - now));
    this.timer = setTimeout(() => this.flush(), wait);
  }

  private flush(): void {
    this.timer = null;
    const p = this.pending;
    this.pending = null;
    if (!p) return;
    const bySwarm: Record<string, ChangeKind[]> = {};
    for (const id of [...p.bySwarm.keys()].sort()) bySwarm[id] = [...(p.bySwarm.get(id) ?? [])].sort();
    this.publish({
      event: "change",
      data: { swarm_ids: [...p.ids].sort(), kinds: [...p.kinds].sort(), by_swarm: bySwarm, at: new Date().toISOString(), watching: this.watching },
    });
  }

  async start(): Promise<void> {
    if (this.closed || this.watcher) return;
    const present = await stat(this.runsDir).then(() => true).catch(() => false);
    if (!present) {
      if (!this.retryTimer) {
        this.retryTimer = setTimeout(() => {
          this.retryTimer = null;
          void this.start();
        }, 2000);
      }
      return;
    }
    try {
      const watcher = watch(this.runsDir, { recursive: true, persistent: false }, (_type, filename) => {
        const name = typeof filename === "string" ? filename : filename ? Buffer.from(filename).toString("utf8") : "";
        if (!name) {
          this.touch(null, "other");
          return;
        }
        void this.noteFsEvent(name);
      });
      watcher.on("error", () => this.fallbackToPoll());
      watcher.on("close", () => {
        if (this.watcher === watcher) this.fallbackToPoll();
      });
      this.watcher = watcher;
      this.watching = true;
      this.touch(null, "registry");
    } catch {
      this.fallbackToPoll();
    }
  }

  /**
   * The watched directory may be recreated (fixture reseed, `rm -rf
   * runs`). Poll meanwhile and keep trying to re-attach the watcher.
   */
  private fallbackToPoll(): void {
    this.watcher?.close();
    this.watcher = null;
    this.watching = false;
    if (this.closed) return;
    this.touch(null, "other");
    if (!this.pollTimer) {
      this.pollTimer = setInterval(() => this.touch(null, "other"), 3000);
      this.pollTimer.unref();
    }
    if (!this.retryTimer) {
      this.retryTimer = setTimeout(() => {
        this.retryTimer = null;
        void this.start().then(() => {
          if (this.watching && this.pollTimer) {
            clearInterval(this.pollTimer);
            this.pollTimer = null;
          }
        });
      }, 2000);
    }
  }

  close(): void {
    this.closed = true;
    this.watcher?.close();
    this.watcher = null;
    if (this.timer) clearTimeout(this.timer);
    if (this.pollTimer) clearInterval(this.pollTimer);
    if (this.retryTimer) clearTimeout(this.retryTimer);
    this.listeners.clear();
  }
}
