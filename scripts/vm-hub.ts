#!/usr/bin/env node
/**
 * The host end of every agent's VM: the board's only writer, the trace's
 * door, the harness's voice, and the stop that does not depend on the agents.
 *
 * Between two microVMs a shared directory keeps none of the promises the
 * board is built on (spikes/microvm-smoke/shared-fs.sh measured it), so an
 * agent in a VM does not write the board. Its extension sends the call here
 * (extensions/board.ts), and this process runs the same `protocol.ts` against
 * the same files on the host, where there is one kernel and one writer.
 *
 * **Who is asking is the channel, not the message.** Each agent's VM has one
 * vsock port, and msb connects it to exactly one Unix socket here,
 * `<dir>/<agent>.sock`. A request that arrives on it is that agent's, and
 * every function that acts as someone is given that agent whatever the
 * request says. There is no token to steal: another VM cannot open this
 * agent's socket, and nothing in a request can change which socket it came
 * in on.
 *
 * **What an agent may ask for is an agent's business.** The agent table
 * holds the board functions a tool of the agent's calls. The harness's own
 * functions — the stop clock, the harness stop — are not in it: the
 * extension that used to call them runs inside the VM, where anything can
 * call anything, so in a VM they are this process's alone. Every path an
 * agent sends is resolved on the host without following a link the agent
 * planted (protocol.ts `openSandboxFile`), the sentinel is written only when
 * the operator's finish line passes here on the host, and a seat's spend
 * report may only grow.
 *
 * One socket carries four things, told apart by shape:
 *   - a trace line (an object with `tool` and `ts`), forwarded to the trace
 *     collector with this agent's token added, so the collector's own
 *     attribution, chain and anchor apply unchanged;
 *   - a nudge (`kind` and `peer`), the nudge broker's request, delivered here
 *     to the peer's link instead of through Herdr;
 *   - a board call (`t: "rpc"`);
 *   - the agent's link (`t: "hello"`), held open: the harness's prompts go
 *     down it, and the agent's working/idle state comes up it.
 *
 * No line either way is past P.WIRE_LINE_MAX: one write of about 262 KB
 * stalled msb's vsock path for good. Anything larger travels in parts of
 * P.TRANSFER_PART_BYTES, one at a time: a call's arguments (`t: "up"`, then
 * the call names its `argsUpload`), a trace line (`t: "up"`, then
 * `t: "trace"` names its `upload`), an answer or a prompt (announced with a
 * `download`, fetched with `t: "down"`). A line to a seat that would be past
 * the limit is refused by name instead of written.
 *
 * The admin socket, `<dir>/admin.sock`, is for the harness's own scripts on
 * the host (idle-nudge.sh, await-done.sh, swarm.sh): prompt an agent, read
 * who is working, tell the hub which Herdr pane is whose.
 *
 * And the stop. The extension in each VM steers its own seat as it does on
 * the host; this process enforces the swarm's wall clock from outside, where
 * an agent cannot reach, on a clock of its own, and the caps on the spend
 * each seat reports about itself (a seat's report is its own word, and may
 * only grow): past the limit plus the grace period it writes the sentinel
 * itself, and once the sentinel has stood for the grace period it puts the
 * VMs away, records the run as finished and takes custody.
 *
 *   node --experimental-strip-types scripts/vm-hub.ts <sandbox> --dir DIR
 *        [--run ID] [--vm-cli PATH] [--registry FILE] [--stop-cmd SWARM_SH]
 *        [--settle-ms N] [--forging] [--no-snapshot] [--quiet]
 *   node --experimental-strip-types scripts/vm-hub.ts --resume DIR
 *
 * One line of JSON on stdin: `{agents: [...], tokens: {<agent>: <token>},
 * seat_tokens: {<agent>: <token>}, collector: "<socket>"}`: `tokens` are
 * the collector's attribution tokens, which no VM ever sees; `seat_tokens`
 * are the hello tokens, one to each seat's VM, which the hub asks of every
 * connection on that seat's socket. Tokens reach this process the way they reach the
 * collector, on stdin, never argv. What was given is kept in the hub's own
 * directory (0700, on the host, in no VM) so that `--resume` can bring the
 * hub back after a crash with the same tokens and the same clock.
 */
import { execFile, execFileSync, spawn } from "node:child_process";
import { createHash, randomBytes, timingSafeEqual } from "node:crypto";
import { appendFileSync, chmodSync, closeSync, existsSync, lstatSync, mkdirSync, openSync, readFileSync, renameSync, rmSync, unlinkSync, writeFileSync, writeSync } from "node:fs";
import { stat } from "node:fs/promises";
import { connect, createServer, type Server, type Socket } from "node:net";
import { basename, dirname, join, relative, resolve } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import * as P from "../extensions/protocol.ts";
import * as T from "../extensions/toolchain.ts";
import { claimHolds, messageFor, resolvePeer } from "./nudge-broker.mjs";
import { GATEWAY_STATE_REL } from "./model-gateway.ts";
import { JobService } from "./job-service.ts";
import { destroyWorker, runWorker } from "./vm.ts";

/**
 * One line from a VM: a trace line keeps a tool's whole input and output
 * (nothing is cut), and a file a seat records or publishes travels in its
 * call, so a line may be large; past this it is not a line.
 */
const MAX_REQUEST_BYTES = 64_000_000;
/**
 * A board call that carries no file has no business being large: past this
 * it is refused. The calls that carry a file's bytes (FILE_FNS) and trace
 * lines keep MAX_REQUEST_BYTES.
 */
const RPC_LINE_MAX = 8_000_000;
/** The calls whose arguments carry a file's bytes. */
const FILE_FNS = new Set(["publishFile", "recordFileVersion", "fileDiff"]);
/**
 * Transfers: a call's arguments or a trace line uploaded in parts, or an
 * answer or a prompt kept to be fetched in parts, when any is past
 * P.TRANSFER_PART_BYTES (board.ts and protocol.ts send and fetch them one
 * part at a time). What one seat may hold here in them at once, how many at
 * once, and how long one may sit untouched. Uploads are few at once (a
 * connection sends one at a time); answers kept are as many as the calls
 * that may run at once (IN_FLIGHT_MAX), since with parts of 32 KiB an inbox
 * page or a diff is often one. A prompt is the hub's own words, not something
 * the seat asked it to keep, and does not count against these.
 */
const TRANSFER_SEAT_BYTES = 96 * 1024 * 1024;
const TRANSFER_SEAT_COUNT = 4;
const TRANSFER_IDLE_MS = 5 * 60_000;
/** The states a seat reports (the extension's), and how much text may go with one. */
const SEAT_STATES = new Set(["idle", "working", "blocked", "unknown"]);
const STATE_DETAIL_MAX = 200;
/** C0 and C1 control characters, ESC and DEL: what a terminal acts on rather than shows. */
const TERMINAL_CONTROLS = /[\u0000-\u001f\u007f-\u009f]/g;
/** The least time between two Herdr reports for one seat. */
const HERDR_REPORT_GAP_MS = 250;
/** Connections one seat may hold open at once: its link, its board calls, its trace, a few one-shot calls. */
const AGENT_CONNECTIONS_MAX = 16;
/**
 * What one seat may have held here at once, across all its connections: the
 * bytes of lines not yet whole, of lines waiting their turn, and of calls
 * queued or running (their arguments stay in memory until they answer).
 * Past it the seat's connections are paused until its calls drain; a line
 * not yet whole that alone passes it cuts its connection.
 */
const AGENT_BUFFER_MAX = 160_000_000;
/**
 * How fast a seat may add to what every peer reads: posts (and the harness
 * posts it sends), thread and name claims, and ledger records. A burst up to
 * the capacity goes through; past it, one more per 1/rate seconds.
 */
const RATE_LIMITS: Record<string, { bucket: string; capacity: number; perSecond: number }> = {
  postMessage: { bucket: "post", capacity: 40, perSecond: 0.5 },
  systemPost: { bucket: "post", capacity: 40, perSecond: 0.5 },
  threadOpen: { bucket: "post", capacity: 40, perSecond: 0.5 },
  claimName: { bucket: "post", capacity: 40, perSecond: 0.5 },
  recordEntry: { bucket: "ledger", capacity: 200, perSecond: 5 },
  // Each done that would end the swarm runs the operator's finish line on
  // the host: a few in a row, then one a minute.
  markDone: { bucket: "done", capacity: 3, perSecond: 1 / 60 },
};
/** A refusal repeated within this window is counted, not written again. */
const REFUSAL_WINDOW_MS = 60_000;
/** Request ids remembered, so a call sent again after a dropped link gets the first run's answer. */
const REPLIES_KEPT = 4096;
/** How long the operator's notify hook may run before it is killed. */
const NOTIFY_TIMEOUT_MS = 30_000;
/** This process's own trace lines: an id of its own and a count, as every sender's are. */
const HUB_SID = `hub-${randomBytes(6).toString("hex")}`;
/** How long a quiet non-link connection is kept. `wait` is a long call, not a quiet one. */
const IDLE_MS = 30_000;
/** How often the stop is checked from out here. */
const BACKSTOP_INTERVAL_MS = 15_000;
/** Lines a connection may have waiting before it is paused; resumed below the low mark. */
const PENDING_HIGH = 200;
const PENDING_LOW = 50;
/**
 * Board calls one agent may have running at once, and how many more may
 * wait for a turn. A burst past the first number queues (a VM recording
 * forty findings at once is a burst, not a flood); one past both is refused.
 */
const IN_FLIGHT_MAX = 64;
const QUEUE_MAX = 192;
/**
 * How long a file must have been left alone before a claim on it passes to
 * an agent in another VM. virtio-fs caches a file's size and existence for
 * five seconds in each guest (passthroughfs, CachePolicy::Auto, not
 * configurable in msb 0.7.2), so an agent that takes a file straight from a
 * peer could append at a size that is five seconds old and overwrite the
 * peer's last lines. Past this window every cached view of the file is newer
 * than the peer's last write.
 */
export const SETTLE_MS_DEFAULT = 6_000;

/** Calls the hub records on the trace when they succeed; every refusal is recorded. */
const AUDITED = new Set(["markDone", "forgeTool", "restoreFileVersion", "claimName", "threadOpen", "publishFile", "recordEntry"]);

/**
 * The job service's settings, from the kickoff: the image workers boot, how
 * many may run at once and with what, the run's allowlist for a job that
 * asks for network, and the pack directories whose tools and recipes jobs run.
 */
export type JobsConfig = {
  image: string;
  workers: number;
  cpus: number;
  memoryMib: number;
  allowHosts: string[];
  openNet: boolean;
  packDirs: string[];
  minFreeMb?: number;
  derived?: boolean;
};

export function parseJobsConfig(raw: unknown): JobsConfig | undefined {
  if (!isObject(raw) || typeof raw.image !== "string" || !raw.image) return undefined;
  const num = (v: unknown, dflt: number, min: number, max: number) => (typeof v === "number" && Number.isFinite(v) ? Math.min(Math.max(Math.floor(v), min), max) : dflt);
  const strings = (v: unknown) => (Array.isArray(v) ? v.filter((x): x is string => typeof x === "string" && x.length > 0) : []);
  return {
    image: raw.image,
    workers: num(raw.workers, 2, 1, 16),
    cpus: num(raw.cpus, 2, 1, 16),
    memoryMib: num(raw.memoryMib, 2048, 512, 65536),
    allowHosts: strings(raw.allowHosts),
    openNet: raw.openNet === true,
    packDirs: strings(raw.packDirs),
    ...(typeof raw.minFreeMb === "number" ? { minFreeMb: num(raw.minFreeMb, 4096, 0, 1 << 30) } : {}),
    ...(raw.derived === true ? { derived: true } : {}),
  };
}

export type HubConfig = {
  sandbox: string;
  /** The job service's settings; absent, the run has no job service (host runs, --no-jobs). */
  jobs?: JobsConfig;
  dir: string;
  agents: string[];
  tokens: Record<string, string>;
  /**
   * Each seat's hello token (the kickoff's `seat_tokens`), which that seat's
   * VM alone holds (SWARM_SEAT_TOKEN): every connection to a seat's socket
   * starts with it or is refused. Absent (an older kickoff), nothing is
   * asked; present, a seat with no entry is refused everything.
   */
  seatTokens?: Record<string, string>;
  collector: string;
  run?: string;
  vmCli?: string;
  /** The operator's registry, for the run's state once the hub has finished it. */
  registry?: string;
  settleMs?: number;
  quiet?: boolean;
  /** Tests turn the backstop off and drive it by hand. */
  backstop?: boolean;
  herdrBin?: string;
  /** Whether make_tool is allowed in this run: the hub refuses a forge otherwise. */
  forging?: boolean;
  /** Whether each VM's disk is kept when the hub puts the VMs away. */
  snapshot?: boolean;
  /** How long after a seat's done its VM is put away (tests shorten it). */
  seatLeaveMs?: number;
  /** A seat's byte budget here (AGENT_BUFFER_MAX; tests lower it). */
  bufferMax?: number;
  /** Custody's bound at finish, in seconds (else SWARM_CUSTODY_TIMEOUT, else 14400). */
  custodyTimeoutSec?: number;
  /** Answers kept for request-id resends, in memory and in replies.jsonl (REPLIES_KEPT; tests lower it). */
  repliesKept?: number;
  /** Bytes of file history one seat may have stored (historyQuotaBytes; tests lower it). */
  historyQuotaBytes?: number;
  /** How long a transfer may sit untouched before it is dropped (TRANSFER_IDLE_MS; tests lower it). */
  transferIdleMs?: number;
  /** The operator's swarm.sh: run as `stop <run> --after-hub` once the hub has finished the run. */
  stopCmd?: string;
};

type AgentState = { state: string; detail?: string; since: string; connected: boolean; last_seen?: string };
/** An upload being received, or an answer waiting to be fetched, for one seat on one connection. */
/** Words the hub puts in front of an agent on its link. */
type QueuedPrompt = { text: string; deliver?: string; kind?: string };
/** An upload being received, or an answer (or a prompt, `prompt`) kept to be fetched. */
type Transfer = { agent: string; kind: "up" | "down"; socket: Socket; size: number; parts: Buffer[]; got: number; data?: Buffer; at: number; prompt?: QueuedPrompt };

/** What survives a restart: the swarm's stop clock and what the hub already said. */
type HubState = {
  stop_steer?: { reason: P.StopReason; at: number } | null;
  done_since?: number;
  finished?: boolean;
  finish_done?: boolean;
  told?: string[];
  seat_steer?: Record<string, number>;
  /** Per seat that said done: when its VM is due to be put away. A restarted hub puts it away still. */
  seat_leave?: Record<string, number>;
  /** Per seat: the bytes of file history it has stored, against its quota. */
  history_bytes?: Record<string, number>;
};

/**
 * A Unix socket path the kernel will take: 104 bytes on macOS. The collector
 * binds inside the sandbox's traces/, which under a long home is past that
 * (measured: every line of a run went to the spill file), so a long path is
 * dialled relative to this process's directory, which main() sets to it.
 */
function reachable(path: string): string {
  if (Buffer.byteLength(path) <= 100) return path;
  const rel = relative(process.cwd(), path);
  return rel && rel.length < path.length ? rel : path;
}

/** `null` in a JSON array is how `undefined` travels; a default parameter needs it back. */
function revive(args: unknown): unknown[] {
  return Array.isArray(args) ? args.map((a) => (a === null ? undefined : a)) : [];
}

function isObject(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

/** The context levels a seat can be at (extensions/context-ceiling.ts). */
const CONTEXT_LEVELS = new Set(["unknown", "idle", "notice", "warning", "forced"]);
/** A Pi session id as a seat reports it (a UUID in practice): short, and nothing that could be a path or a key of another kind. */
const SESSION_ID = /^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/;

function finiteNonNegative(value: unknown): number {
  const n = typeof value === "number" ? value : Number(value);
  return Number.isFinite(n) && n >= 0 ? n : Number.NaN;
}

/**
 * One connection to the collector, kept, with the lines in flight answered
 * in order: the collector writes `{"ok":true}` per line, on the same socket.
 * A line that is not answered in time fails, and the connection is dropped
 * so the next line is not answered with this one's reply.
 */
export class CollectorLink {
  /**
   * One dial: its socket, the lines on it still waiting for an answer, and
   * what it has read. Kept per socket: a socket cut on a timeout closes a
   * moment later, and its close must fail its own lines only, not the ones
   * already sent on the next socket (whose answers would then be matched to
   * the wrong lines: one written line said lost, one refused said written).
   */
  private conn: { socket: Socket; waiting: Array<{ done: (ok: boolean) => void; timer: ReturnType<typeof setTimeout> }>; buffer: string } | null = null;
  private readonly path: string;
  private readonly timeoutMs: number;
  constructor(path: string, timeoutMs = 5000) {
    this.path = path;
    this.timeoutMs = timeoutMs;
  }

  private dial(): NonNullable<CollectorLink["conn"]> {
    const s = connect(reachable(this.path));
    const conn: NonNullable<CollectorLink["conn"]> = { socket: s, waiting: [], buffer: "" };
    s.setEncoding("utf8");
    s.on("data", (chunk: string) => {
      conn.buffer += chunk;
      let cut;
      while ((cut = conn.buffer.indexOf("\n")) >= 0) {
        const line = conn.buffer.slice(0, cut);
        conn.buffer = conn.buffer.slice(cut + 1);
        const head = conn.waiting.shift();
        if (!head) continue;
        clearTimeout(head.timer);
        let ok = false;
        try {
          ok = JSON.parse(line)?.ok === true;
        } catch {
          ok = false;
        }
        head.done(ok);
      }
    });
    const drop = () => {
      if (this.conn === conn) this.conn = null;
      conn.buffer = "";
      for (const w of conn.waiting.splice(0)) {
        clearTimeout(w.timer);
        w.done(false);
      }
    };
    s.on("error", drop);
    s.on("close", drop);
    return conn;
  }

  send(line: string): Promise<boolean> {
    return new Promise((done) => {
      if (!this.conn || this.conn.socket.destroyed) this.conn = this.dial();
      const conn = this.conn;
      const entry = {
        done,
        timer: setTimeout(() => {
          const i = conn.waiting.indexOf(entry);
          if (i >= 0) conn.waiting.splice(i, 1);
          done(false);
          // The answers after this one would be matched to the wrong lines:
          // this socket is done, and the next line dials a new one.
          if (this.conn === conn) this.conn = null;
          conn.socket.destroy();
        }, this.timeoutMs),
      };
      conn.waiting.push(entry);
      conn.socket.write(line, (err) => {
        if (err) {
          const i = conn.waiting.indexOf(entry);
          if (i >= 0) conn.waiting.splice(i, 1);
          clearTimeout(entry.timer);
          done(false);
        }
      });
    });
  }

  close(): void {
    this.conn?.socket.destroy();
    this.conn = null;
  }
}

/**
 * Every board function an agent in a VM may call, and what it is given.
 * `who` is the agent the channel belongs to; the first argument the agent
 * sent (its sandbox path, or its context) is never used — the hub's own
 * sandbox and the channel's agent replace it. A test holds this table to
 * REMOTE_FUNCTIONS in extensions/board.ts.
 */
export function boardTable(hub: {
  sandbox: string;
  settle: (who: string, rawPath: string) => Promise<void>;
  wrote: (who: string, rawPath: string) => void;
  forging?: boolean;
  /** Every seat of the run: whose own directories are whose. */
  ids?: string[];
  /** A seat said done: its VM can be put away before the swarm's. */
  seatDone?: (who: string) => void;
  /**
   * The per-seat file-history quota: whether `bytes` more may be stored for
   * `who`, what was stored, and what a seat past it is told. Absent, none.
   */
  history?: {
    allow: (who: string, bytes: number) => boolean;
    stored: (who: string, bytes: number) => void;
    refused: (who: string) => string;
  };
  /** Whether the model gateway meters this seat's spend on the host (foldGatewaySpend). */
  gatewaySeat?: (who: string) => boolean;
}) {
  const S = hub.sandbox;
  const ids = hub.ids ?? [];
  // A seat's own directories are the only ones a running seat can rearrange
  // (a directory swapped for a link between the hub's checks and its open
  // would read the operator's files), so the hub does not open a file there:
  // the seat sends the bytes with the call.
  const holeOf = async (raw: string) => {
    const key = await P.realPathKey(S, raw);
    return { key, owner: P.seatHoleOwner(key, ids) };
  };
  const as = (who: string): P.SwarmContext => ({ sandboxRoot: S, agentId: who });
  // One finish-line run on the host at a time: a done that arrives while
  // one runs gets that run's answer.
  let finishLine: Promise<Awaited<ReturnType<typeof P.runFinishLine>> | null> | null = null;
  type Call = (who: string, a: unknown[], signal: AbortSignal) => Promise<unknown>;
  const table: Record<string, Call> = {
    applySessionUsage: async (who, a) => {
      // A seat's report of its own spend may only grow: a VM that reported
      // less than before, or a number that is not one, is refused and the
      // row it had stays. The check is made under the table lock, against the
      // row the write replaces. Only the fields a budget row has are taken,
      // each checked for its kind: the seat's model is the kickoff's to set
      // (a seat that renamed its model would leave its model's cap), and a
      // key the row does not have would ride into budget.json, which every
      // seat and this process read on every fold. (What a seat reports at all
      // is still its own word; docs/adr/0009 says so, and the wall clock is
      // the brake that is not.)
      const raw = isObject(a[2]) ? (a[2] as Record<string, unknown>) : null;
      if (!raw) throw new Error("usage must be an object");
      const slice: Record<string, unknown> = {};
      for (const key of P.MONOTONIC_USAGE_KEYS) {
        const value = finiteNonNegative(raw[key] ?? 0);
        if (Number.isNaN(value)) throw new Error(`usage.${key} is not a non-negative number`);
        slice[key] = value;
      }
      for (const key of ["context_tokens", "context_window", "context_ceiling", "compactions", "compaction_tokens", "compaction_usd", "handoffs"]) {
        if (raw[key] === undefined || raw[key] === null) continue;
        const value = finiteNonNegative(raw[key]);
        if (Number.isNaN(value)) throw new Error(`usage.${key} is not a non-negative number`);
        slice[key] = value;
      }
      if (raw.context_level !== undefined && raw.context_level !== null) {
        if (typeof raw.context_level !== "string" || !CONTEXT_LEVELS.has(raw.context_level)) {
          throw new Error(`usage.context_level must be one of ${[...CONTEXT_LEVELS].join(", ")}`);
        }
        slice.context_level = raw.context_level;
      }
      if (raw.context_locked !== undefined && raw.context_locked !== null) {
        if (typeof raw.context_locked !== "boolean") throw new Error("usage.context_locked must be true or false");
        slice.context_locked = raw.context_locked;
      }
      // A seat the model gateway meters: its spend is the host's measure,
      // and its own report a cross-check that can only raise it. Each figure
      // is the larger of the two, so the report still lands (its context
      // fields with it) and never lowers what the host measured.
      if (hub.gatewaySeat?.(who)) {
        const row = (await P.readBudget(S).catch(() => null))?.agents[who];
        if (row) for (const key of P.MONOTONIC_USAGE_KEYS) slice[key] = Math.max(Number(slice[key] ?? 0), Number(row[key] ?? 0));
        slice.metered_by = "model-gateway";
      } else if (typeof raw.session_id === "string" && SESSION_ID.test(raw.session_id)) {
        // The Pi session the report is from: a seat whose Pi restarted in its
        // VM reports from zero under a new id, and the fold adds it to what
        // the seat had. Dropped here, every such report was refused as going
        // backwards. A gateway seat is metered whole by the host instead.
        slice.session_id = raw.session_id;
      }
      return P.applySessionUsage(S, who, slice as never, { monotonic: true });
    },
    claimFile: async (who, a) => {
      await hub.settle(who, String(a[1] ?? ""));
      return P.claimFile(as(who), String(a[1] ?? ""), (a[2] as P.ClaimOptions) ?? {});
    },
    claimName: (who, a) => P.claimName(S, who, String(a[2] ?? ""), a[3] as string | undefined),
    correctionsAfter: (who, a) => P.correctionsAfter(S, String(a[1] ?? ""), who),
    fileDiff: async (_who, a) => {
      const { key, owner } = await holeOf(String(a[1] ?? ""));
      const from = a[2] as number | string | undefined;
      const to = a[3] as number | string | undefined;
      if (!owner) return P.fileDiff(S, key, from, to);
      const wire = isObject(a[4]) ? a[4] : null;
      const disk = wire?.missing === true ? null : typeof wire?.disk_b64 === "string" ? Buffer.from(wire.disk_b64, "base64") : undefined;
      const needsDisk = from === undefined || to === undefined || P.isDiskRef(from) || P.isDiskRef(to);
      if (needsDisk && disk === undefined) throw new Error(`${key} is in ${owner}'s own directory, which the hub does not open: the bytes on disk come with the call`);
      if (disk && disk.byteLength > P.DIFF_MAX_BYTES) throw new Error(`${key} is too large to diff (${disk.byteLength} bytes; the limit is ${P.DIFF_MAX_BYTES})`);
      return P.fileDiff(S, key, from, to, { disk });
    },
    forgeTool: (who, a) => {
      if (!hub.forging) throw new Error("tool forging is off for this run (--allow-tool-forging); the hub does not forge");
      return P.forgeTool(as(who), a[1]);
    },
    forgedToolSeal: (_who, a) => P.forgedToolSeal(S, String(a[1] ?? "")),
    guardWrite: (who, a) => P.guardWrite(as(who), String(a[1] ?? "")),
    heldBy: (who, a) => P.heldBy(as(who), String(a[1] ?? "")),
    listClaims: () => P.listClaims(S),
    listFileHistory: (_who, a) => P.listFileHistory(S, String(a[1] ?? "")),
    listForgedTools: () => P.listForgedTools(S),
    listLedger: (_who, a) => P.listLedger(S, (a[1] as { kind?: string; limit?: number }) ?? {}),
    listTeam: (who) => P.listTeam(as(who)),
    markDone: async (who, a) => {
      // The sentinel ends every seat, so the finish line is run here, on the
      // host, by the harness, before it is written: what the agent's own
      // extension ran inside its VM is that VM's word. An abandoned run says
      // so in its reason and is not held to the checks; a seat leaving on its
      // own cap writes no sentinel and is not either.
      const args = (a[1] as { reason?: string; outputFile?: string; createSentinel?: boolean }) ?? {};
      const reason = String(args.reason ?? "");
      const endsSwarm = args.createSentinel !== false && reason !== "agent_cap" && !reason.startsWith("ABANDONED: ");
      if (endsSwarm && !(await P.swarmDoneExists(S))) {
        finishLine ??= P.runFinishLine(S)
          .catch(() => null)
          .finally(() => {
            finishLine = null;
          });
        const run = await finishLine;
        const verdict = P.finishLineVerdict(run, false);
        if (!verdict.proceed) throw new Error(`the harness re-ran the finish line on the host and it is not met: ${verdict.reason}`);
      }
      const done = await P.markDone(as(who), args as never);
      hub.seatDone?.(who);
      return done;
    },
    nameOf: (_who, a) => P.nameOf(S, String(a[1] ?? "")),
    postMessage: (who, a) => {
      // An agent's post is its own; `via` is the hub's to set.
      const { via: _via, ...args } = (a[1] as Record<string, unknown>) ?? {};
      return P.postMessage(as(who), args as never);
    },
    publishFile: async (who, a) => {
      const wire = isObject(a[3]) ? a[3] : null;
      if (typeof wire?.bytes_b64 !== "string") throw new Error("publish sends the file's bytes with the call: the hub does not open a file in a seat's own directory");
      const bytes = Buffer.from(wire.bytes_b64, "base64");
      if (bytes.byteLength > P.HISTORY_STORE_MAX_BYTES) throw new Error(`a VM publishes up to ${P.HISTORY_STORE_MAX_BYTES} bytes; this is ${bytes.byteLength}`);
      hub.wrote(who, String(a[2] ?? ""));
      return P.publishFile(as(who), String(a[1] ?? ""), a[2] as string | undefined, { bytes, ids });
    },
    readBudget: () => P.readBudget(S),
    readBudgetStatus: (who) => P.readBudgetStatus(as(who)),
    readInbox: (who, a) => P.readInbox(as(who), (a[1] as never) ?? {}),
    readNames: () => P.readNames(S),
    recordEntry: (who, a) => P.recordEntry(as(who), a[1] as never),
    recordFileVersion: async (who, a) => {
      const { key, owner } = await holeOf(String(a[1] ?? ""));
      if (owner && owner !== who) throw new Error(`${key} is ${owner}'s own directory; a seat records its own files`);
      // The harness's files (custody's verdicts, the trace spill, the budget)
      // have no revisions a seat puts its name on.
      if (P.isProtectedPath(key)) throw new Error(`harness-owned path: ${key}; a seat records its own files and the shared ones under work/`);
      hub.wrote(who, key);
      // Past the seat's history quota a revision is still recorded, by its
      // hash: the record stays whole, and the host's disk is not the seat's
      // to fill with copies.
      const counted = (rec: P.FileVersion | null) => {
        if (rec && rec.stored !== false) hub.history?.stored(who, rec.bytes);
        return rec;
      };
      const hashOnly = async (sha256: string, bytes: number) => {
        const rec = await P.recordFileVersion(S, key, who, { hashOnly: { sha256, bytes } });
        return rec ? { ...rec, not_stored: hub.history?.refused(who) } : rec;
      };
      if (!owner) {
        if (hub.history) {
          const size = await stat(join(S, key)).then((st) => st.size).catch(() => 0);
          if (!hub.history.allow(who, size)) {
            const h = await P.hashSandboxFile(S, key);
            if (h) return hashOnly(h.sha256, h.bytes);
          }
        }
        return counted(await P.recordFileVersion(S, key, who));
      }
      const wire = isObject(a[3]) ? a[3] : null;
      if (!wire) throw new Error(`${key} is in your own directory, which the hub does not open: its bytes come with the call`);
      if (wire.missing === true) return null;
      if (typeof wire.bytes_b64 === "string") {
        const bytes = Buffer.from(wire.bytes_b64, "base64");
        if (bytes.byteLength > P.HISTORY_STORE_MAX_BYTES) throw new Error(`past ${P.HISTORY_STORE_MAX_BYTES} bytes a revision is its hash: send hash_only`);
        if (hub.history && !hub.history.allow(who, bytes.byteLength)) return hashOnly(P.sha256Hex(bytes), bytes.byteLength);
        return counted(await P.recordFileVersion(S, key, who, { bytes }));
      }
      const h = isObject(wire.hash_only) ? wire.hash_only : null;
      const sha = typeof h?.sha256 === "string" && /^[0-9a-f]{64}$/.test(h.sha256) ? h.sha256 : null;
      const size = finiteNonNegative(h?.bytes);
      if (!sha || Number.isNaN(size)) throw new Error("hash_only needs a sha256 and a size");
      return P.recordFileVersion(S, key, who, { hashOnly: { sha256: sha, bytes: size } });
    },
    releaseAllOwned: (who) => P.releaseAllOwned(as(who)),
    releaseFile: (who, a) => P.releaseFile(as(who), String(a[1] ?? "")),
    restoreFileVersion: async (who, a) => {
      const { key, owner } = await holeOf(String(a[1] ?? ""));
      if (owner) {
        throw new Error(owner === who ? `${key} is in your own directory: file_restore restores it in your VM, not here` : `${key} is ${owner}'s own directory; a peer's scratch is theirs to write`);
      }
      hub.wrote(who, key);
      return P.restoreFileVersion(as(who), key, Number(a[2]));
    },
    swarmDoneExists: () => P.swarmDoneExists(S),
    systemPost: (who, a) => {
      // The harness's voice, sent from inside a VM: said by the harness code
      // in that agent's VM, and the post says which one.
      const args = (a[1] as Record<string, unknown>) ?? {};
      return P.systemPost(S, { ...(args as { tag: string; body: string }), via: who });
    },
    threadJoin: (who, a) => P.threadJoin(as(who), String(a[1] ?? "")),
    threadOpen: (who, a) => P.threadOpen(as(who), a[1] as never),
    updateToolchainRecord: (who, a) => T.updateToolchainRecord(S, isObject(a[1]) ? { agent: who, inventory: a[1] as never } : undefined),
    // Only how long: how often the hub polls is the hub's (a guest's
    // pollMs of 0 was a tight loop of readdir on the hub's one event loop).
    waitForSwarmChange: (who, a, signal) =>
      P.waitForSwarmChange(as(who), { seconds: Number((a[1] as { seconds?: unknown } | null)?.seconds) || undefined, signal }),
  };
  return table;
}

export class Hub {
  readonly cfg: HubConfig;
  readonly roster: string[];
  /** Tool jobs in worker VMs, and the catalogue they update (job-service.ts). */
  jobService?: JobService;
  private servers: Server[] = [];
  /** Every open connection, so stopping does not wait on a held one. */
  private sockets = new Set<Socket>();
  private links = new Map<string, Socket>();
  private queued = new Map<string, QueuedPrompt[]>();
  private status = new Map<string, AgentState>();
  private panes = new Map<string, string>();
  private told = new Set<string>();
  private lastWrite = new Map<string, { who: string; at: number }>();
  private inFlight = new Map<string, number>();
  private queue = new Map<string, Array<() => void>>();
  /** Per seat: connections open, and bytes buffered across them. */
  private conns = new Map<string, number>();
  /** A Herdr report running per seat, and the newest one waiting behind it. */
  private herdrBusy = new Set<string>();
  private herdrNext = new Map<string, string[]>();
  /** Bytes of lines not yet whole, per seat. */
  private buffered = new Map<string, number>();
  /** Bytes of whole lines waiting or running, per seat, until each is answered. */
  private held = new Map<string, number>();
  /** Each seat's connections paused on its byte budget, resumed as its calls drain. */
  private stalled = new Map<string, Set<() => void>>();
  /** Per seat and bucket: tokens left and when they were last topped up. */
  private buckets = new Map<string, { tokens: number; at: number }>();
  /** Per (seat, call, error): a refusal already written this window, and how many since. */
  private refusals = new Map<string, { since: number; count: number; last: string }>();
  /** Calls that came with a request id, by seat and id: a call sent again gets the first run's answer. */
  private replies = new Map<string, Promise<{ ok: boolean; result?: unknown; error?: string }>>();
  /** This process's count of its own trace lines. */
  private seq = 0;
  /** Seats whose VM is put away early, once they are done and the swarm is not. */
  private leaving = new Set<string>();
  /** When each leaving seat's VM is due to be put away (persisted: seat_leave). */
  private seatLeave = new Map<string, number>();
  /** Bytes of file history each seat has stored (persisted: history_bytes). */
  private historyBytes = new Map<string, number>();
  /** Lines in replies.jsonl, so it is cut back before it grows past twice what is kept. */
  private repliesLines = 0;
  /** Whether the operator's hook has heard the collector stopped taking the hub's lines. */
  private collectorDownTold = false;
  /** The seats the model gateway meters, from its state file at the last fold. */
  private gatewaySeats = new Set<string>();
  /** Uploads and downloads in progress, by seat, kind and id. */
  private transfers = new Map<string, Transfer>();
  private transferTimer: ReturnType<typeof setInterval> | null = null;
  /** The sockets a seat's VM holds, and whose: every line written on one is checked against P.WIRE_LINE_MAX. */
  private seatSockets = new WeakMap<Socket, string>();
  private table: ReturnType<typeof boardTable>;
  private backstopTimer: ReturnType<typeof setInterval> | null = null;
  private collector: CollectorLink;
  /** The swarm's stop clock, this process's own: no request can move it. */
  private stopSteer: { reason: P.StopReason; at: number } | null = null;
  /** Per seat: when it was told it is over its own cap. */
  private seatSteer = new Map<string, number>();
  private doneSince = 0;
  private finished = false;
  /** The finish is over: the VMs put away (or not) and custody taken. */
  private finishDone = false;
  private finishing: Promise<void> | null = null;

  constructor(cfg: HubConfig) {
    this.cfg = { ...cfg, sandbox: resolve(cfg.sandbox) };
    this.roster = [...cfg.agents];
    for (const id of this.roster) this.status.set(id, { state: "unknown", since: new Date().toISOString(), connected: false });
    this.table = boardTable({
      sandbox: this.cfg.sandbox,
      settle: (who, raw) => this.settle(who, raw),
      wrote: (who, raw) => this.noteWrite(who, raw),
      forging: cfg.forging === true,
      ids: this.roster,
      seatDone: (who) => this.seatLeft(who),
      history: {
        allow: (who, bytes) => (this.historyBytes.get(who) ?? 0) + bytes <= this.historyQuota(),
        stored: (who, bytes) => {
          this.historyBytes.set(who, (this.historyBytes.get(who) ?? 0) + bytes);
          this.saveState();
        },
        refused: (who) => this.historyRefused(who),
      },
      gatewaySeat: (who) => this.gatewaySeats.has(who),
    });
    this.collector = new CollectorLink(this.cfg.collector);
  }

  private log(line: string): void {
    if (!this.cfg.quiet) console.log(`vm-hub: ${line}`);
  }

  socketFor(agent: string): string {
    return join(this.cfg.dir, `${agent}.sock`);
  }

  adminSocket(): string {
    return join(this.cfg.dir, "admin.sock");
  }

  statusFile(): string {
    return join(this.cfg.dir, "status.json");
  }

  /** The hub's own trace lines that the collector did not take: on the host, in no VM. */
  spillFile(): string {
    return join(this.cfg.dir, "hub-spill.jsonl");
  }

  private stateFile(): string {
    return join(this.cfg.dir, "hub-state.json");
  }

  private repliesKept(): number {
    return this.cfg.repliesKept ?? REPLIES_KEPT;
  }

  /** replies.jsonl cut back to the answers kept: written aside and renamed in, whole or not at all. */
  private compactReplies(kept?: string[]): void {
    try {
      const lines = kept ?? readFileSync(this.repliesFile(), "utf8").split("\n").filter(Boolean).slice(-this.repliesKept());
      const tmp = `${this.repliesFile()}.tmp`;
      writeFileSync(tmp, lines.length ? `${lines.join("\n")}\n` : "", { mode: 0o600 });
      renameSync(tmp, this.repliesFile());
      this.repliesLines = lines.length;
    } catch {
      // the file keeps growing until the next try; memory has the window
    }
  }

  /**
   * Whether the operator gave this run a hook: `swarm.sh start --notify`
   * keeps it at <runs>/notify/<run>.cmd, outside the run. No hook, no call
   * and no line on the trace.
   */
  private notifyConfigured(): boolean {
    // The run's own registry first: its directory is where the kickoff kept the hook.
    const runsDir = this.cfg.registry ? dirname(resolve(this.cfg.registry)) : process.env.SWARM_RUNS_DIR || "";
    return Boolean(this.cfg.run && runsDir && existsSync(join(runsDir, "notify", `${this.cfg.run}.cmd`)));
  }

  private historyQuota(): number {
    return this.cfg.historyQuotaBytes ?? historyQuotaBytes();
  }

  /**
   * What a seat past its history quota is told, with the record of it: once
   * on the trace and once on the board, addressed to the seat, and on every
   * revision recorded by its hash alone.
   */
  private historyRefused(who: string): string {
    const used = this.historyBytes.get(who) ?? 0;
    const quota = this.historyQuota();
    const text = `not stored: ${who} has stored ${used} bytes of file history, and its quota is ${quota}; this revision is recorded by its hash, its bytes are not kept`;
    const mark = `history_quota:${who}`;
    if (!this.told.has(mark)) {
      this.told.add(mark);
      this.saveState();
      void this.event("history_quota", { agent: who }, { ok: true, used_bytes: used, quota_bytes: quota });
      void P.systemPost(this.cfg.sandbox, {
        tag: "ask",
        to: who,
        body: `${who}: your file history has reached its quota (${Math.round(quota / 1048576)} MiB). Every revision you write from now on is still recorded, by its hash, but its bytes are not kept, so file_restore and file_diff cannot use it. Keep large outputs as files under your own directory and record the small deliverables.`,
      }).catch(() => undefined);
    }
    return text;
  }

  /**
   * The operator's hook (`--notify`): scripts/notify.sh, beside the VM
   * manager the hub runs, with the sandbox, what happened and its details.
   * Started and let go, bounded: the hook may be slow or broken, and the hub
   * never waits on it. Said on the trace; no script, no hook.
   */
  private notify(what: string, detail: Record<string, unknown>): void {
    const script = join(dirname(this.cfg.vmCli ?? join(dirname(fileURLToPath(import.meta.url)), "vm.ts")), "notify.sh");
    if (!existsSync(script) || !this.notifyConfigured()) return;
    let started = false;
    try {
      const child = spawn("bash", [script, this.cfg.sandbox, what, JSON.stringify(detail)], { detached: true, stdio: "ignore", timeout: NOTIFY_TIMEOUT_MS });
      child.on("error", () => undefined);
      child.unref();
      started = true;
    } catch {
      started = false;
    }
    void this.event("notify", { event: what }, { ok: started });
  }

  /** The answers to calls that came with a request id: a restarted hub still knows it ran them. */
  private repliesFile(): string {
    return join(this.cfg.dir, "replies.jsonl");
  }

  async start(): Promise<void> {
    this.transferTimer = setInterval(() => this.sweepTransfers(), Math.max(1_000, Math.min(60_000, Math.floor((this.cfg.transferIdleMs ?? TRANSFER_IDLE_MS) / 2))));
    this.transferTimer.unref();
    // A Unix socket path the kernel takes is 103 bytes and its NUL (104 on
    // macOS): past it `listen` fails with a bare EINVAL, which said nothing
    // about why (measured: a 3-byte run id under macOS's TMPDIR made 105).
    for (const path of [...this.roster.map((a) => this.socketFor(a)), this.adminSocket()]) {
      const bytes = Buffer.byteLength(path);
      if (bytes > SOCKET_PATH_MAX) throw new SocketPathTooLong(path, bytes);
    }
    mkdirSync(this.cfg.dir, { recursive: true, mode: 0o700 });
    this.loadState();
    // A seat that said done before a restart still has its VM put away, at
    // the time it was due, not a grace period after the restart.
    for (const [agent, due] of this.seatLeave) this.armSeatLeave(agent, due);
    for (const agent of this.roster) {
      await this.listen(this.socketFor(agent), (socket) => this.serveAgent(agent, socket));
    }
    await this.listen(this.adminSocket(), (socket) => this.serveAdmin(socket));
    if (this.cfg.jobs && this.cfg.run) await this.startJobs(this.cfg.jobs, this.cfg.run);
    this.writeStatus();
    if (this.cfg.backstop !== false) {
      this.backstopTimer = setInterval(() => void this.backstop().catch(() => undefined), BACKSTOP_INTERVAL_MS);
    }
  }

  private loadState(): void {
    try {
      const all = readFileSync(this.repliesFile(), "utf8").split("\n").filter(Boolean);
      this.repliesLines = all.length;
      const lines = all.slice(-this.repliesKept());
      if (all.length > this.repliesKept()) this.compactReplies(lines);
      for (const line of lines) {
        try {
          const r = JSON.parse(line) as { key?: string; reply?: { ok: boolean; result?: unknown; error?: string } };
          if (typeof r.key === "string" && r.reply) this.replies.set(r.key, Promise.resolve(r.reply));
        } catch {
          // a torn last line
        }
      }
    } catch {
      // none yet
    }
    try {
      const raw = JSON.parse(readFileSync(this.stateFile(), "utf8")) as HubState;
      this.stopSteer = raw.stop_steer ?? null;
      this.doneSince = raw.done_since ?? 0;
      this.finished = raw.finished === true;
      this.finishDone = raw.finish_done === true;
      for (const t of raw.told ?? []) this.told.add(t);
      for (const [agent, at] of Object.entries(raw.seat_steer ?? {})) this.seatSteer.set(agent, at);
      for (const [agent, due] of Object.entries(raw.seat_leave ?? {})) if (this.roster.includes(agent) && Number.isFinite(due)) this.seatLeave.set(agent, due);
      for (const [agent, n] of Object.entries(raw.history_bytes ?? {})) if (Number.isFinite(n) && n >= 0) this.historyBytes.set(agent, n);
    } catch {
      // a first start
    }
  }

  private saveState(): void {
    const state: HubState = {
      stop_steer: this.stopSteer,
      done_since: this.doneSince,
      finished: this.finished,
      finish_done: this.finishDone,
      told: [...this.told],
      seat_steer: Object.fromEntries(this.seatSteer),
      seat_leave: Object.fromEntries(this.seatLeave),
      history_bytes: Object.fromEntries(this.historyBytes),
    };
    try {
      const tmp = `${this.stateFile()}.tmp`;
      writeFileSync(tmp, JSON.stringify(state), { mode: 0o600 });
      renameSync(tmp, this.stateFile());
    } catch {
      // the state is also in memory; a restart without it starts the clock again
    }
  }

  private listen(path: string, onSocket: (socket: Socket) => void): Promise<void> {
    return new Promise((resolveListen, reject) => {
      try {
        if (existsSync(path)) unlinkSync(path);
      } catch {
        // the bind says whether it matters
      }
      const server = createServer((socket) => {
        this.sockets.add(socket);
        socket.once("close", () => this.sockets.delete(socket));
        onSocket(socket);
      });
      server.on("error", reject);
      server.listen(path, () => {
        try {
          chmodSync(path, 0o600);
        } catch {
          // a platform that does not honour it; the directory is 0700
        }
        this.servers.push(server);
        resolveListen();
      });
    });
  }

  /**
   * The job service, started with the hub: it reads its journal, finishes
   * what a crash left half done, queues the kickoff's recipes and runs jobs.
   * Its posts are the harness's, tagged result, to the agent concerned or to
   * everyone; who asked is read from names.json at the moment it asks.
   */
  private async startJobs(jobs: JobsConfig, run: string): Promise<void> {
    const S = this.cfg.sandbox;
    this.jobService = new JobService({
      sandbox: S,
      run,
      ...(this.cfg.registry ? { registry: this.cfg.registry } : {}),
      image: jobs.image,
      workers: jobs.workers,
      workerCpus: jobs.cpus,
      workerMemoryMib: jobs.memoryMib,
      allowHosts: jobs.allowHosts,
      openNet: jobs.openNet,
      packDirs: jobs.packDirs,
      forging: this.cfg.forging === true,
      ...(jobs.minFreeMb !== undefined ? { minFreeMb: jobs.minFreeMb } : {}),
      ...(jobs.derived ? { derived: true } : {}),
      runWorker,
      destroyWorker,
      notify: async (to, body) => {
        await P.systemPost(S, { tag: "result", to, body });
      },
      identity: async (agent) => {
        const r = (await P.readNames(S).catch(() => [])).find((n) => n.id === agent);
        return { ...(r?.name ? { name: r.name } : {}), ...(r?.doing ? { doing: r.doing } : {}) };
      },
      log: (line) => this.log(line),
    });
    try {
      await this.jobService.start();
    } catch (err) {
      // A job service that cannot start leaves the board working: agents are
      // told by the job tools that there is none.
      this.log(`jobs: not started: ${(err as Error).message}`);
      this.jobService = undefined;
    }
  }

  async stop(): Promise<void> {
    await this.jobService?.stop("the hub is stopping").catch((err: Error) => this.log(`jobs: stop: ${err.message}`));
    if (this.backstopTimer) clearInterval(this.backstopTimer);
    if (this.transferTimer) clearInterval(this.transferTimer);
    for (const key of [...this.transfers.keys()]) this.dropTransfer(key, false);
    await this.flushRefusals().catch(() => undefined);
    for (const link of this.links.values()) link.destroy();
    this.links.clear();
    for (const socket of this.sockets) socket.destroy();
    this.sockets.clear();
    this.collector.close();
    await Promise.all(this.servers.map((s) => new Promise((r) => s.close(() => r(undefined)))));
    this.servers = [];
  }

  /**
   * Line-at-a-time reader; `onLine` returns true to keep the connection for
   * more. A connection that sends faster than its lines are handled is paused
   * until the backlog drains: one VM in a loop must not grow this process
   * until it dies and takes every peer's board with it.
   */
  private lines(socket: Socket, onLine: (line: string, keep: () => () => void) => Promise<boolean> | boolean, idle = true, agent?: string): void {
    let buffer = "";
    let busy = Promise.resolve(true);
    let pending = 0;
    // Two reasons to stop reading: too many lines waiting on this
    // connection, or too many bytes held for its seat across all of them.
    let pausedLines = false;
    let pausedBytes = false;
    const settle = () => {
      if (pausedLines || pausedBytes) socket.pause();
      else if (!socket.destroyed) socket.resume();
    };
    const unstall = () => {
      pausedBytes = false;
      settle();
    };
    // What this connection holds counts against its seat's budget, so one VM
    // opening every connection it may cannot hold a line the size of the
    // limit on each of them at once.
    const account = (delta: number) => {
      if (!agent) return 0;
      const now = Math.max(0, (this.buffered.get(agent) ?? 0) + delta);
      this.buffered.set(agent, now);
      return now;
    };
    socket.once("close", () => {
      account(-buffer.length);
      buffer = "";
      if (agent) this.stalled.get(agent)?.delete(unstall);
    });
    socket.setEncoding("utf8");
    if (idle) socket.setTimeout(IDLE_MS, () => socket.destroy());
    socket.on("error", () => undefined);
    socket.on("data", (chunk: string) => {
      buffer += chunk;
      const partial = account(chunk.length);
      const max = this.cfg.bufferMax ?? AGENT_BUFFER_MAX;
      if (buffer.length > MAX_REQUEST_BYTES || partial > max) {
        account(-buffer.length);
        buffer = "";
        socket.destroy();
        return;
      }
      let cut;
      while ((cut = buffer.indexOf("\n")) >= 0) {
        const line = buffer.slice(0, cut);
        buffer = buffer.slice(cut + 1);
        account(-(cut + 1));
        if (!line.trim()) continue;
        // A whole line stays counted until it is handled, or, when its
        // handler keeps it (a call that answers later), until it answers.
        const size = cut + 1;
        this.hold(agent, size);
        let kept = false;
        const keep = () => {
          kept = true;
          let released = false;
          return () => {
            if (released) return;
            released = true;
            this.hold(agent, -size);
          };
        };
        pending++;
        if (pending >= PENDING_HIGH && !pausedLines) {
          pausedLines = true;
          settle();
        }
        busy = busy
          .then((more) => (more ? onLine(line, keep) : false))
          .catch(() => false)
          .finally(() => {
            if (!kept) this.hold(agent, -size);
            pending--;
            if (pausedLines && pending <= PENDING_LOW) {
              pausedLines = false;
              settle();
            }
          });
      }
      // Held bytes drain as calls answer; until then this connection reads
      // no more. Bytes of lines not yet whole cannot drain while paused, so
      // they alone never pause a connection (they cut it, above).
      if (agent && !pausedBytes && (this.held.get(agent) ?? 0) > 0 && (this.buffered.get(agent) ?? 0) + (this.held.get(agent) ?? 0) > max) {
        pausedBytes = true;
        settle();
        const set = this.stalled.get(agent) ?? new Set();
        set.add(unstall);
        this.stalled.set(agent, set);
      }
    });
  }

  /** Bytes of whole lines held for `agent`: waiting, or kept by a call until it answers. */
  private hold(agent: string | undefined, delta: number): void {
    if (!agent) return;
    const now = Math.max(0, (this.held.get(agent) ?? 0) + delta);
    this.held.set(agent, now);
    if (delta >= 0) return;
    // Below a quarter of the budget the seat's paused connections read again.
    const stalled = this.stalled.get(agent);
    if (stalled?.size && now <= (this.cfg.bufferMax ?? AGENT_BUFFER_MAX) / 4) {
      this.stalled.delete(agent);
      for (const resume of stalled) resume();
    }
  }

  /** What a seat holds here now: lines not yet whole, and whole ones not yet answered. */
  heldBytes(agent: string): number {
    return (this.buffered.get(agent) ?? 0) + (this.held.get(agent) ?? 0);
  }

  /**
   * Drop a transfer: an upload's bytes stop counting against its seat. A
   * prompt not fetched whole goes again (`requeue`, unless it was fetched or
   * the hub is stopping): on the agent's link if a new one is up already,
   * else at the front of its queue, for the next hello. Nothing is cut, and
   * the words are not lost to a dropped link.
   */
  private dropTransfer(key: string, requeue = true): void {
    const t = this.transfers.get(key);
    if (!t) return;
    this.transfers.delete(key);
    if (t.kind === "up") this.hold(t.agent, -t.got);
    if (!t.prompt || !requeue) return;
    this.log(`${t.agent}: a prompt of ${t.size} bytes was not fetched whole; it goes again`);
    const link = this.links.get(t.agent);
    if (link && link !== t.socket && !link.destroyed) this.sendPrompt(t.agent, link, t.prompt);
    else this.queued.set(t.agent, [t.prompt, ...(this.queued.get(t.agent) ?? [])]);
  }

  /** Transfers untouched past the idle limit go, and so do a closed connection's. */
  private sweepTransfers(now = Date.now()): void {
    const idle = this.cfg.transferIdleMs ?? TRANSFER_IDLE_MS;
    // Newest first, so prompts put back keep their order at the front of the queue.
    for (const [key, t] of [...this.transfers].reverse()) {
      if (!t.socket.destroyed && now - t.at <= idle) continue;
      if (!t.socket.destroyed) void this.refused(t.agent, t.prompt ? "prompt" : t.kind === "up" ? "upload" : "download", `a transfer untouched for ${Math.round(idle / 1000)}s was dropped`);
      this.dropTransfer(key);
    }
  }

  /** What one seat holds in transfers now, prompts aside: uploads, answers kept, and their bytes. */
  private seatTransfers(agent: string): { uploads: number; answers: number; bytes: number } {
    let uploads = 0;
    let answers = 0;
    let bytes = 0;
    for (const t of this.transfers.values()) {
      if (t.agent !== agent || t.prompt) continue;
      if (t.kind === "up") uploads++;
      else answers++;
      bytes += t.kind === "up" ? t.size : (t.data?.length ?? 0);
    }
    return { uploads, answers, bytes };
  }

  /**
   * One part of a call's arguments, sent ahead of the call (board.ts): taken
   * in order and acknowledged, or refused by name and the upload dropped. Its
   * bytes count against the seat from the moment they arrive.
   */
  private uploadPart(agent: string, socket: Socket, msg: Record<string, unknown>): void {
    const id = typeof msg.id === "string" && msg.id.length > 0 && msg.id.length <= 128 ? msg.id : "";
    const key = `${agent}\u0000up\u0000${id}`;
    const refuse = (error: string) => {
      void this.refused(agent, "upload", error);
      if (id) this.dropTransfer(key);
      this.reply(socket, { t: "up", id, ok: false, error }, false);
    };
    if (!id) return refuse("an upload part needs an id");
    this.sweepTransfers();
    const { off, size } = msg;
    if (typeof off !== "number" || !Number.isInteger(off) || off < 0 || typeof size !== "number" || !Number.isInteger(size) || size <= 0) {
      return refuse("an upload part needs whole numbers off and size");
    }
    if (typeof msg.b64 !== "string") return refuse("an upload part carries its bytes as b64");
    let t = this.transfers.get(key);
    if (!t) {
      if (off !== 0) return refuse(`an upload starts at 0, not ${off}`);
      if (size > MAX_REQUEST_BYTES) return refuse(`an upload of ${size} bytes is past the ${MAX_REQUEST_BYTES}-byte limit for a call`);
      const seat = this.seatTransfers(agent);
      if (seat.uploads >= TRANSFER_SEAT_COUNT) return refuse(`more than ${TRANSFER_SEAT_COUNT} uploads at once`);
      if (seat.bytes + size > TRANSFER_SEAT_BYTES) return refuse(`${seat.bytes + size} bytes in transfers at once is past the ${TRANSFER_SEAT_BYTES}-byte limit for a seat`);
      t = { agent, kind: "up", socket, size, parts: [], got: 0, at: Date.now() };
      this.transfers.set(key, t);
    }
    if (t.socket !== socket) return refuse("an upload's parts come on the connection that started it");
    if (size !== t.size) return refuse(`an upload's size changed from ${t.size} to ${size}`);
    if (off !== t.got) return refuse(`an upload part at ${off} does not follow the ${t.got} bytes received`);
    const bytes = Buffer.from(msg.b64, "base64");
    if (!bytes.length || bytes.length > P.TRANSFER_PART_BYTES) return refuse(`an upload part of ${bytes.length} bytes: a part is 1 to ${P.TRANSFER_PART_BYTES} bytes`);
    if (t.got + bytes.length > t.size) return refuse(`an upload part past the ${t.size} bytes declared`);
    t.parts.push(bytes);
    t.got += bytes.length;
    t.at = Date.now();
    this.hold(agent, bytes.length);
    this.reply(socket, { t: "up", id, ok: true, got: t.got }, false);
  }

  /**
   * What an upload carried (a call's arguments, or a trace line), checked
   * whole (size, sha256, JSON), or why not. Taken, its bytes stay counted
   * until the call answers or the line is forwarded (`held`).
   */
  private takeUpload(agent: string, socket: Socket, spec: unknown): { args?: unknown; held: number; error?: string } {
    if (!isObject(spec) || typeof spec.id !== "string") return { held: 0, error: "a call or a trace line sent in parts names its upload by id" };
    const key = `${agent}\u0000up\u0000${spec.id}`;
    const t = this.transfers.get(key);
    if (!t || t.kind !== "up") return { held: 0, error: `no upload ${spec.id} on this connection` };
    this.transfers.delete(key);
    const fail = (error: string) => {
      this.hold(agent, -t.got);
      return { held: 0, error };
    };
    if (t.socket !== socket) return fail("an upload is used on the connection that sent it");
    if (t.got !== t.size || spec.size !== t.size) return fail(`an upload of ${t.got} bytes, declared ${t.size}, named as ${String(spec.size)}`);
    const whole = Buffer.concat(t.parts);
    if (typeof spec.sha256 !== "string" || createHash("sha256").update(whole).digest("hex") !== spec.sha256) {
      return fail("an upload whose bytes do not match its sha256");
    }
    try {
      return { args: JSON.parse(whole.toString("utf8")), held: t.got };
    } catch {
      return fail("an upload that is not JSON");
    }
  }

  /**
   * The answer to a held call: in its own line, or, past a part's size, kept
   * here and named, for board.ts to fetch in parts. A multi-megabyte line is
   * what stalled the vsock path; an answer (a restored file, a diff, a long
   * page) is not sent as one either.
   */
  private replyRpc(agent: string, socket: Socket, id: number, result: { ok: boolean; result?: unknown; error?: string }): void {
    const body = JSON.stringify(result);
    if (Buffer.byteLength(body) + 64 <= P.TRANSFER_PART_BYTES) {
      this.reply(socket, { t: "rpc", id, ...result }, false);
      return;
    }
    const data = Buffer.from(body, "utf8");
    this.sweepTransfers();
    const seat = this.seatTransfers(agent);
    if (seat.answers >= IN_FLIGHT_MAX || seat.bytes + data.length > TRANSFER_SEAT_BYTES) {
      const error = `an answer of ${data.length} bytes could not be kept to be fetched: ${seat.answers} answers and ${seat.bytes} bytes in transfers are held for this seat already`;
      void this.refused(agent, "download", error);
      this.reply(socket, { t: "rpc", id, ok: false, error }, false);
      return;
    }
    const download = randomBytes(12).toString("hex");
    this.transfers.set(`${agent}\u0000down\u0000${download}`, { agent, kind: "down", socket, size: data.length, parts: [], got: 0, data, at: Date.now() });
    this.reply(socket, { t: "rpc", id, ok: true, download: { id: download, size: data.length, sha256: createHash("sha256").update(data).digest("hex") } }, false);
  }

  /** One part of a kept answer or prompt, by offset; `done` drops it, fetched whole. */
  private downloadPart(agent: string, socket: Socket, msg: Record<string, unknown>): void {
    const id = typeof msg.id === "string" && msg.id.length <= 128 ? msg.id : "";
    const key = `${agent}\u0000down\u0000${id}`;
    if (msg.done === true) {
      if (this.transfers.get(key)?.socket === socket) this.dropTransfer(key, false);
      return;
    }
    const t = this.transfers.get(key);
    const refuse = (error: string) => {
      void this.refused(agent, "download", error);
      this.reply(socket, { t: "down", id, ok: false, error }, false);
    };
    if (!t || !t.data || t.socket !== socket) return refuse(`no answer ${id} is kept for this connection`);
    const off = msg.off;
    if (typeof off !== "number" || !Number.isInteger(off) || off < 0 || off >= t.data.length) return refuse(`a part at ${String(off)} is outside the ${t.data.length}-byte answer`);
    t.at = Date.now();
    this.reply(socket, { t: "down", id, ok: true, off, b64: t.data.subarray(off, off + P.TRANSFER_PART_BYTES).toString("base64") }, false);
  }

  private reply(socket: Socket, body: unknown, end: boolean): void {
    try {
      let text = `${JSON.stringify(body)}\n`;
      const agent = this.seatSockets.get(socket);
      if (agent !== undefined && Buffer.byteLength(text) > P.WIRE_LINE_MAX) {
        // Never written to a seat: one line this large stalls the VM's link
        // and every answer behind it. What goes instead says so, by name,
        // and carries only what names the answer it stands for.
        const error = new P.WireLineTooLarge(Buffer.byteLength(text), "an answer").message;
        void this.refused(agent, "reply", error);
        const b = isObject(body) ? body : {};
        const named = {
          ...(typeof b.t === "string" && b.t.length <= 16 ? { t: b.t } : {}),
          ...(typeof b.id === "number" || (typeof b.id === "string" && b.id.length <= 128) ? { id: b.id } : {}),
        };
        text = `${JSON.stringify({ ...named, ok: false, error })}\n`;
      }
      if (end) socket.end(text);
      else socket.write(text);
    } catch {
      // the caller hung up
    }
  }

  private serveAgent(agent: string, socket: Socket): void {
    const open = (this.conns.get(agent) ?? 0) + 1;
    if (open > AGENT_CONNECTIONS_MAX) {
      // Past the cap the connection is not served: a VM that opens
      // connections in a loop cannot take the hub's descriptors from its peers.
      socket.destroy();
      void this.refused(agent, "connect", `more than ${AGENT_CONNECTIONS_MAX} connections open`);
      return;
    }
    this.conns.set(agent, open);
    this.seatSockets.set(socket, agent);
    // Calls in flight on this connection, so a cancel or a hang-up ends them.
    const running = new Map<number, AbortController>();
    socket.once("close", () => {
      this.conns.set(agent, Math.max(0, (this.conns.get(agent) ?? 1) - 1));
      // Newest first, so prompts put back keep their order at the front of the queue.
      for (const [key, t] of [...this.transfers].reverse()) if (t.socket === socket) this.dropTransfer(key);
      for (const c of running.values()) c.abort();
      running.clear();
    });
    // A connection is the seat's only once it has shown the seat's token
    // (P.seatAuthLine): a hello carrying it, or an auth line before anything
    // else. Until then nothing on it is served, not even its state.
    let authed = this.cfg.seatTokens === undefined;
    this.lines(socket, async (line, keep) => {
      let msg: unknown;
      try {
        msg = JSON.parse(line);
      } catch {
        this.reply(socket, { ok: false, error: "not json" }, true);
        return false;
      }
      if (!isObject(msg)) {
        this.reply(socket, { ok: false, error: "not an object" }, true);
        return false;
      }
      if (!authed) {
        const expected = this.cfg.seatTokens?.[agent];
        if ((msg.t === "auth" || msg.t === "hello") && seatTokenMatches(expected, msg.token)) {
          authed = true;
          if (msg.t === "auth") return true;
        } else {
          // Never the token itself, on the trace or in the answer.
          const why = expected === undefined ? "this seat was given no token" : msg.token === undefined ? "no seat token" : "a wrong seat token";
          void this.refused(agent, "seat_auth", `connection refused: ${why}; a seat's socket serves only its own VM, which starts every connection with its seat token`);
          this.reply(socket, { ok: false, error: "this socket serves only its seat's VM: the connection did not start with the seat's token" }, true);
          return false;
        }
      } else if (msg.t === "auth") {
        return true;
      }
      const seen = this.status.get(agent);
      if (seen) seen.last_seen = new Date().toISOString();
      if (msg.t === "hello") {
        this.attachLink(agent, socket);
        return true;
      }
      if (msg.t === "state") {
        this.setState(agent, String(msg.state ?? "unknown"), typeof msg.detail === "string" ? msg.detail : undefined);
        return true;
      }
      if (msg.t === "up" || msg.t === "down") {
        // A transfer's part: the connection is held, as a call's is.
        socket.setTimeout(0);
        if (msg.t === "up") this.uploadPart(agent, socket, msg);
        else this.downloadPart(agent, socket, msg);
        return true;
      }
      if (msg.t === "trace") {
        // A trace line past a part's size, sent ahead in parts
        // (protocol.ts): forwarded whole, as the line it would have been.
        socket.setTimeout(0);
        const taken = this.takeUpload(agent, socket, msg.upload);
        try {
          const record = taken.args;
          const error = taken.error ?? (isObject(record) && typeof record.tool === "string" && typeof record.ts === "string" ? undefined : "an uploaded trace line that is not one");
          if (error) {
            void this.refused(agent, "trace", error);
            this.reply(socket, { ok: false, error }, false);
            return true;
          }
          const ok = await this.forwardTrace(agent, record as Record<string, unknown>);
          this.reply(socket, ok ? { ok: true } : { ok: false, error: "the collector did not take the line" }, false);
        } finally {
          if (taken.held) this.hold(agent, -taken.held);
        }
        return true;
      }
      if (msg.t === "rpc" && line.length > RPC_LINE_MAX && !FILE_FNS.has(String(msg.fn ?? ""))) {
        const error = `a ${String(msg.fn ?? "")} call of ${line.length} bytes is past the ${RPC_LINE_MAX}-byte limit for a call that carries no file`;
        void this.refused(agent, String(msg.fn ?? ""), error);
        const held = typeof msg.id === "number";
        this.reply(socket, held ? { t: "rpc", id: msg.id, ok: false, error } : { ok: false, error }, !held);
        return held;
      }
      // A call whose arguments came ahead in parts runs as if they had come
      // in its line: the same limits, dedupe and accounting.
      let args: unknown = msg.args;
      let uploaded = 0;
      if (msg.t === "rpc" && msg.argsUpload !== undefined) {
        const fn = String(msg.fn ?? "");
        const spec = isObject(msg.argsUpload) ? msg.argsUpload : {};
        const held = typeof msg.id === "number";
        const size = typeof spec.size === "number" ? spec.size : 0;
        const taken: { args?: unknown; held: number; error?: string } =
          size > RPC_LINE_MAX && !FILE_FNS.has(fn)
            ? (this.dropTransfer(`${agent}\u0000up\u0000${String(spec.id ?? "")}`),
              { held: 0, error: `a ${fn} call of ${size} bytes is past the ${RPC_LINE_MAX}-byte limit for a call that carries no file` })
            : this.takeUpload(agent, socket, msg.argsUpload);
        if (taken.error) {
          void this.refused(agent, fn, taken.error);
          this.reply(socket, held ? { t: "rpc", id: msg.id, ok: false, error: taken.error } : { ok: false, error: taken.error }, !held);
          return held;
        }
        args = taken.args;
        uploaded = taken.held;
      }
      if (msg.t === "rpc" && typeof msg.id === "number") {
        // Many calls on one held connection, each answered when it finishes:
        // a VM makes one connection for its board calls instead of one per
        // call, which under load the vsock path refused (measured: 20 of 80
        // concurrent one-shot calls never reached the host).
        socket.setTimeout(0);
        const id = msg.id;
        const controller = new AbortController();
        running.set(id, controller);
        // The call's arguments stay in memory until it answers: its line's
        // bytes stay counted against the seat until then.
        const release = keep();
        void this.slot(agent).then(async (got) => {
          if (!got) {
            running.delete(id);
            release();
            if (uploaded) this.hold(agent, -uploaded);
            this.reply(socket, { t: "rpc", id, ok: false, error: `too many board calls waiting (${IN_FLIGHT_MAX} running, ${QUEUE_MAX} queued); slow down` }, false);
            return;
          }
          try {
            const result = await this.callOnce(agent, String(msg.fn ?? ""), args, controller.signal, msg.rid);
            this.replyRpc(agent, socket, id, result);
          } finally {
            running.delete(id);
            release();
            if (uploaded) this.hold(agent, -uploaded);
            this.release(agent);
          }
        });
        return true;
      }
      if (msg.t === "cancel" && typeof msg.id === "number") {
        running.get(msg.id)?.abort();
        return true;
      }
      if (msg.t === "rpc") {
        // The one-shot form (the kickoff's probe uses it) takes a turn like
        // any other call: connections are capped, and so is what they run.
        const controller = new AbortController();
        socket.setTimeout(0);
        socket.once("close", () => controller.abort());
        if (!(await this.slot(agent))) {
          if (uploaded) this.hold(agent, -uploaded);
          this.reply(socket, { ok: false, error: `too many board calls waiting (${IN_FLIGHT_MAX} running, ${QUEUE_MAX} queued); slow down` }, true);
          return false;
        }
        try {
          const result = await this.callOnce(agent, String(msg.fn ?? ""), args, controller.signal, msg.rid);
          const size = Buffer.byteLength(JSON.stringify(result)) + 1;
          if (size > P.WIRE_LINE_MAX) {
            // The one-shot form ends with its answer and carries no parts.
            const error = `an answer of ${size} bytes is past the ${P.WIRE_LINE_MAX}-byte line limit of a VM's hub link, and the one-shot form carries no parts: make the call on a held connection (board.ts), which fetches a large answer in parts`;
            void this.refused(agent, String(msg.fn ?? ""), error);
            this.reply(socket, { ok: false, error }, true);
          } else {
            this.reply(socket, result, true);
          }
        } finally {
          if (uploaded) this.hold(agent, -uploaded);
          this.release(agent);
        }
        return false;
      }
      if (typeof msg.kind === "string" && "peer" in msg) {
        const result = await this.nudge(agent, msg.kind, msg.peer);
        this.reply(socket, result, true);
        return false;
      }
      if (typeof msg.tool === "string" && typeof msg.ts === "string") {
        socket.setTimeout(0);
        const ok = await this.forwardTrace(agent, msg);
        this.reply(socket, ok ? { ok: true } : { ok: false, error: "the collector did not take the line" }, false);
        return true;
      }
      this.reply(socket, { ok: false, error: "unknown message" }, true);
      return false;
    }, true, agent);
  }

  /** A turn to run a call as `agent`: now, later when one frees, or never. */
  private slot(agent: string): Promise<boolean> {
    const open = this.inFlight.get(agent) ?? 0;
    if (open < IN_FLIGHT_MAX) {
      this.inFlight.set(agent, open + 1);
      return Promise.resolve(true);
    }
    const waiting = this.queue.get(agent) ?? [];
    if (waiting.length >= QUEUE_MAX) return Promise.resolve(false);
    return new Promise((grant) => {
      waiting.push(() => grant(true));
      this.queue.set(agent, waiting);
    });
  }

  private release(agent: string): void {
    const next = this.queue.get(agent)?.shift();
    if (next) {
      next();
      return;
    }
    this.inFlight.set(agent, Math.max(0, (this.inFlight.get(agent) ?? 1) - 1));
  }

  /**
   * One board call, as `who`. Errors travel as the protocol's own message. A
   * seat the run has recorded dead is not served: its VM may still be up, and
   * a post from it would be a post from someone the record says is gone.
   * What the hub did as the harness's writer is on the trace: every call it
   * refused, and every one that changed what the run is (AUDITED).
   */
  /**
   * A call that came with a request id is run once: the same id again (a
   * seat's client resends a call whose answer a dropped link lost) gets the
   * first run's answer, from memory or from the hub's own file, and a failed
   * first run may be tried again.
   */
  callOnce(who: string, fn: string, args: unknown, signal?: AbortSignal, rid?: unknown): Promise<{ ok: boolean; result?: unknown; error?: string }> {
    if (typeof rid !== "string" || !rid || rid.length > 128) return this.call(who, fn, args, signal);
    const key = `${who}\u0000${fn}\u0000${rid}`;
    const known = this.replies.get(key);
    if (known) return known;
    const running = this.call(who, fn, args, signal).then((reply) => {
      if (!reply.ok) {
        this.replies.delete(key);
        return reply;
      }
      try {
        appendFileSync(this.repliesFile(), `${JSON.stringify({ key, reply })}\n`, { mode: 0o600 });
        this.repliesLines += 1;
        // Cut back to what is kept once it is twice that: a long run's file
        // stays bounded, and a restart still knows the same window of answers.
        if (this.repliesLines > 2 * this.repliesKept()) this.compactReplies();
      } catch {
        // memory still has it
      }
      return reply;
    });
    this.replies.set(key, running);
    while (this.replies.size > this.repliesKept()) {
      const oldest = this.replies.keys().next().value;
      if (oldest === undefined) break;
      this.replies.delete(oldest);
    }
    return running;
  }

  /** Whether `who` may make one more call of this kind now; refills by the clock. */
  private takeToken(who: string, fn: string, now = Date.now()): boolean {
    const limit = RATE_LIMITS[fn];
    if (!limit || who === "system") return true;
    const key = `${who}\u0000${limit.bucket}`;
    const b = this.buckets.get(key) ?? { tokens: limit.capacity, at: now };
    b.tokens = Math.min(limit.capacity, b.tokens + ((now - b.at) / 1000) * limit.perSecond);
    b.at = now;
    const ok = b.tokens >= 1;
    if (ok) b.tokens -= 1;
    this.buckets.set(key, b);
    return ok;
  }

  async call(who: string, fn: string, args: unknown, signal: AbortSignal = new AbortController().signal): Promise<{ ok: boolean; result?: unknown; error?: string }> {
    const handler = Object.prototype.hasOwnProperty.call(this.table, fn) ? this.table[fn] : undefined;
    if (!handler) return { ok: false, error: `${fn} is not a board function` };
    if (!this.takeToken(who, fn)) {
      const limit = RATE_LIMITS[fn];
      const pace = limit.perSecond >= 1 ? `${limit.perSecond} a second` : `one every ${Math.round(1 / limit.perSecond)} seconds`;
      const error = `slow down: ${fn} past ${limit.capacity} in a burst and ${pace} after; wait and send again`;
      void this.refused(who, fn, error);
      return { ok: false, error };
    }
    if (who !== "system" && existsSync(P.agentDeadPath(this.cfg.sandbox, who))) {
      const error = `${who} is recorded dead (done/agents/${who}.dead); the hub does not serve it`;
      void this.refused(who, fn, error);
      return { ok: false, error };
    }
    try {
      const result = await handler(who, revive(args), signal);
      if (AUDITED.has(fn)) void this.audit(who, fn, { ok: true, ...summarize(fn, result) });
      return { ok: true, result: result === undefined ? null : result };
    } catch (err) {
      const error = err instanceof Error ? err.message : String(err);
      void this.refused(who, fn, error);
      return { ok: false, error };
    }
  }

  private audit(who: string, fn: string, result: Record<string, unknown>): Promise<void> {
    return this.event("hub_call", { agent: who, fn }, result);
  }

  /**
   * A refusal on the record. The same refusal again within a minute is
   * counted, not written: a VM in a loop cannot grow the trace (or, with the
   * collector down, the hub's spill on the host) by a line a call. The count
   * goes on the next line written for it, and on the flush at the end.
   */
  private refused(who: string, fn: string, error: string, now = Date.now()): Promise<void> {
    const key = `${who}\u0000${fn}\u0000${error}`;
    const seen = this.refusals.get(key);
    if (seen && now - seen.since < REFUSAL_WINDOW_MS) {
      seen.count++;
      seen.last = new Date(now).toISOString();
      return Promise.resolve();
    }
    this.refusals.set(key, { since: now, count: 0, last: "" });
    const repeated = seen && seen.count ? { repeated_before: seen.count, repeated_until: seen.last } : {};
    return this.audit(who, fn, { ok: false, error, ...repeated });
  }

  /** The refusals counted and not yet written. */
  async flushRefusals(): Promise<void> {
    for (const [key, seen] of this.refusals) {
      if (!seen.count) continue;
      const [who, fn, error] = key.split("\u0000");
      await this.audit(who, fn, { ok: false, error, repeated: seen.count, repeated_until: seen.last });
      seen.count = 0;
    }
  }

  /** Write notes still resolving their path: settle waits for them, or a claim right after a write could miss it. */
  private notes = new Set<Promise<void>>();

  private noteWrite(who: string, raw: string): void {
    const note: Promise<void> = P.realPathKey(this.cfg.sandbox, raw)
      .then((key) => {
        this.lastWrite.set(key, { who, at: Date.now() });
      })
      .catch(() => undefined)
      .finally(() => this.notes.delete(note));
    this.notes.add(note);
  }

  /**
   * Hold a claim until the file has been still for the settle window, when
   * the last hand on it was someone else's. The caller's own writes are
   * coherent in its own VM and never wait.
   */
  async settle(who: string, raw: string): Promise<void> {
    const window = this.cfg.settleMs ?? SETTLE_MS_DEFAULT;
    if (window <= 0 || !raw) return;
    // Every write noted before this claim is known before it is judged.
    await Promise.all([...this.notes]);
    let key: string;
    try {
      key = await P.realPathKey(this.cfg.sandbox, raw);
    } catch {
      return;
    }
    const mtime = await stat(join(this.cfg.sandbox, key)).then((s) => s.mtimeMs).catch(() => 0);
    const last = this.lastWrite.get(key);
    if (last?.who === who && (!mtime || mtime <= last.at + 1000)) return;
    const touched = Math.max(mtime, last && last.who !== who ? last.at : 0);
    if (!touched) return;
    const wait = touched + window - Date.now();
    if (wait > 0) await new Promise((r) => setTimeout(r, Math.min(wait, window)));
  }

  private forwardTrace(agent: string, record: Record<string, unknown>): Promise<boolean> {
    const { token: _t, gate: _g, ...rest } = record;
    const token = this.cfg.tokens[agent];
    const line = `${JSON.stringify(token ? { ...rest, token } : rest)}\n`;
    return this.sendToCollector(line);
  }

  sendToCollector(line: string): Promise<boolean> {
    if (!this.cfg.collector) return Promise.resolve(false);
    return this.collector.send(line);
  }

  /**
   * The hub's own lines, as the harness (`system`). What the collector does
   * not take is kept in the hub's directory, on the host, where custody
   * counts it: the record that the harness stopped a run must not depend on
   * the collector being up at that moment.
   */
  async event(tool: string, args: Record<string, unknown>, result: Record<string, unknown>): Promise<void> {
    const record = { ts: new Date().toISOString(), agent: "system", tool, args, result, sid: HUB_SID, seq: ++this.seq };
    const token = this.cfg.tokens.system;
    const line = `${JSON.stringify(token ? { ...record, token } : record)}\n`;
    const ok = await this.sendToCollector(line);
    if (!ok) {
      try {
        appendFileSync(this.spillFile(), `${JSON.stringify(record)}\n`, { mode: 0o600 });
      } catch {
        this.log(`spill failed: ${tool}`);
      }
      // Once per hub: the collector stopped taking the hub's own lines. The
      // keeper brings a dead collector back; the operator hears of it now.
      if (!this.collectorDownTold && tool !== "notify") {
        this.collectorDownTold = true;
        this.notify("collector_unreachable", { first_line: tool });
      }
    }
  }

  private attachLink(agent: string, socket: Socket): void {
    const previous = this.links.get(agent);
    if (previous && previous !== socket) previous.destroy();
    this.links.set(agent, socket);
    socket.setTimeout(0);
    socket.setKeepAlive(true);
    const st = this.status.get(agent);
    if (st) st.connected = true;
    socket.once("close", () => {
      if (this.links.get(agent) === socket) {
        this.links.delete(agent);
        const now = this.status.get(agent);
        if (now) {
          now.connected = false;
          // A seat whose link went down mid-turn is not working, whatever it
          // last said: a crashed VM stayed "working" on the record, and the
          // watchdogs that ask before nudging or reaping left it alone.
          if (now.state === "working" || now.state === "blocked") {
            now.state = "gone";
            now.detail = "link lost";
            now.since = new Date().toISOString();
          }
        }
        this.writeStatus();
        void this.event("hub_link", { agent }, { up: false });
      }
    });
    this.writeStatus();
    const pending = this.queued.get(agent) ?? [];
    this.queued.delete(agent);
    for (const p of pending) this.sendPrompt(agent, socket, p);
    this.log(`${agent}: link up`);
    void this.event("hub_link", { agent }, { up: true });
  }

  /**
   * Words on a seat's link: in one line, or, past a part's size, kept here
   * and named, for the link (board.ts openHubLink) to fetch in parts. Nothing
   * is cut: a long brief arrives whole, or, if the link drops before it is
   * fetched, waits for the next hello (dropTransfer).
   */
  private sendPrompt(agent: string, link: Socket, message: QueuedPrompt): void {
    const line = { t: "prompt", ...message };
    if (Buffer.byteLength(JSON.stringify(line)) + 1 <= P.TRANSFER_PART_BYTES) {
      this.reply(link, line, false);
      return;
    }
    const data = Buffer.from(message.text, "utf8");
    const id = randomBytes(12).toString("hex");
    this.transfers.set(`${agent}\u0000down\u0000${id}`, { agent, kind: "down", socket: link, size: data.length, parts: [], got: 0, data, at: Date.now(), prompt: message });
    const { text: _text, ...named } = message;
    this.reply(link, { t: "prompt", ...named, download: { id, size: data.length, sha256: createHash("sha256").update(data).digest("hex") } }, false);
  }

  /**
   * Put words in front of an agent: they arrive as a user message through
   * the extension's `sendUserMessage`, which starts a turn when the agent is
   * idle. Queued, and delivered on the next hello, only when asked to be.
   */
  prompt(agent: string, text: string, options: { deliver?: "steer" | "followUp"; kind?: string; queue?: boolean } = {}): boolean {
    const link = this.links.get(agent);
    const message = { text, ...(options.deliver ? { deliver: options.deliver } : {}), ...(options.kind ? { kind: options.kind } : {}) };
    if (link && !link.destroyed) {
      this.sendPrompt(agent, link, message);
      return true;
    }
    if (options.queue) {
      const list = this.queued.get(agent) ?? [];
      list.push(message);
      this.queued.set(agent, list);
    }
    return false;
  }

  /** The nudge broker's request, answered here: same kinds, same words, same checks. */
  async nudge(from: string, kind: unknown, peer: unknown): Promise<{ ok: boolean; error?: string; repeat?: boolean }> {
    if (typeof kind !== "string" || typeof peer !== "string") return { ok: false, error: "kind and peer are names" };
    const message = messageFor(kind) as string;
    if (!message) return { ok: false, error: "unknown kind" };
    if (!claimHolds(this.cfg.sandbox, kind)) return { ok: false, error: "the run does not say that" };
    const check = resolvePeer(this.roster, peer, from) as { ok: boolean; error?: string };
    if (!check.ok) return { ok: false, error: check.error };
    const once = `${String(kind)}:${String(peer)}`;
    if (this.told.has(once)) return { ok: true, repeat: true };
    this.told.add(once);
    const ok = this.prompt(String(peer), message, { deliver: "steer", kind: String(kind) });
    if (!ok) this.told.delete(once);
    this.saveState();
    return { ok };
  }

  setState(agent: string, rawState: string, rawDetail?: string): void {
    const st = this.status.get(agent);
    if (!st) return;
    // The states the extension sends, and a short line of text without the
    // control characters a terminal acts on: both reach the operator's
    // Herdr and status.json, and a guest writes them.
    const state = SEAT_STATES.has(rawState) ? rawState : "unknown";
    let detail = rawDetail === undefined ? undefined : rawDetail.replace(TERMINAL_CONTROLS, "");
    if (detail !== undefined && detail.length > STATE_DETAIL_MAX) {
      void this.refused(agent, "state", `a state detail of ${detail.length} characters is past the ${STATE_DETAIL_MAX}-character limit; the state is kept without it`);
      detail = undefined;
    }
    // A state line that says what the last one said changes nothing: no
    // status write and no Herdr process, so a VM repeating itself in a loop
    // does not fork a process on the host per line.
    if (st.state === state && st.detail === detail) return;
    if (st.state !== state) st.since = new Date().toISOString();
    st.state = state;
    st.detail = detail;
    this.writeStatus();
    const pane = this.panes.get(agent);
    if (pane) {
      const args = ["pane", "report-agent", pane, "--source", "dfirswarm-vm", "--agent", "pi", "--state", state];
      if (detail) args.push("--message", detail);
      this.reportPane(agent, args);
    }
  }

  /**
   * One Herdr report per seat at a time, spaced out, and only the newest one
   * waiting: a VM that alternates its state in a loop forked a Herdr process
   * per line (measured: 400 lines, about 214 processes alive at once).
   */
  private reportPane(agent: string, args: string[]): void {
    if (this.herdrBusy.has(agent)) {
      this.herdrNext.set(agent, args);
      return;
    }
    this.herdrBusy.add(agent);
    execFile(this.cfg.herdrBin || process.env.HERDR_BIN || "herdr", args, { timeout: 5000 }, () => {
      const gap = setTimeout(() => {
        this.herdrBusy.delete(agent);
        const next = this.herdrNext.get(agent);
        if (next) {
          this.herdrNext.delete(agent);
          this.reportPane(agent, next);
        }
      }, HERDR_REPORT_GAP_MS);
      gap.unref?.();
    });
  }

  statusSnapshot(): Record<string, AgentState> {
    return Object.fromEntries(this.status);
  }

  private writeStatus(): void {
    try {
      const tmp = `${this.statusFile()}.tmp`;
      writeFileSync(tmp, `${JSON.stringify({ at: new Date().toISOString(), pid: process.pid, agents: this.statusSnapshot(), finished: this.finished, finish_done: this.finishDone }, null, 2)}\n`);
      renameSync(tmp, this.statusFile());
    } catch {
      // the admin socket answers the same question
    }
  }

  private serveAdmin(socket: Socket): void {
    this.lines(socket, async (line) => {
      let msg: Record<string, unknown>;
      try {
        msg = JSON.parse(line);
      } catch {
        this.reply(socket, { ok: false, error: "not json" }, true);
        return false;
      }
      switch (msg.op) {
        case "prompt": {
          const agent = String(msg.agent ?? "");
          if (!this.roster.includes(agent)) {
            this.reply(socket, { ok: false, error: "not in this run" }, true);
            return false;
          }
          const delivered = this.prompt(agent, String(msg.text ?? ""), {
            deliver: msg.deliver === "steer" ? "steer" : "followUp",
            kind: typeof msg.kind === "string" ? msg.kind : undefined,
            queue: msg.queue === true,
          });
          this.reply(socket, { ok: delivered, delivered }, true);
          return false;
        }
        case "status":
          this.reply(socket, { ok: true, agents: this.statusSnapshot(), finished: this.finished }, true);
          return false;
        case "panes":
          if (isObject(msg.panes)) {
            for (const [agent, pane] of Object.entries(msg.panes)) {
              if (this.roster.includes(agent) && typeof pane === "string") this.panes.set(agent, pane);
            }
          }
          this.reply(socket, { ok: true }, true);
          return false;
        case "call": {
          // The harness's own board calls from the host, as `system`: the
          // admin socket is the harness's, and it does not act as a seat.
          const result = await this.call("system", String(msg.fn ?? ""), msg.args);
          this.reply(socket, result, true);
          return false;
        }
        case "shutdown":
          this.reply(socket, { ok: true }, true);
          setTimeout(() => void this.stop().then(() => process.exit(0)), 50);
          return false;
        default:
          this.reply(socket, { ok: false, error: "unknown op" }, true);
          return false;
      }
    });
  }

  /**
   * The stop, enforced from outside every VM. The extensions steer and stop
   * as they do on the host; this is what happens when they cannot — a VM
   * wedged in a long command, an agent that never ends a turn. The grace
   * period is measured on this process's clock: the marker in budget.json is
   * for the record, not the decision.
   */
  async backstop(now = Date.now()): Promise<void> {
    const S = this.cfg.sandbox;
    if (!existsSync(S)) {
      await this.stop();
      process.exit(0);
    }
    const done = await P.swarmDoneExists(S);
    if (!done) {
      // The reaper found every seat done or dead and nobody wrote the
      // sentinel (done/ALL_AGENTS_DEAD): there is no one left to steer, and a
      // harness stop now would record the run as finished. The idle watchdog
      // stops for the same file.
      if (existsSync(join(S, P.ALL_DEAD_REL))) return;
      await this.foldGatewaySpend().catch((err: Error) => this.log(`gateway fold: ${err.message}`));
      const budget = await P.readBudget(S).catch(() => null);
      if (!budget) return;
      await this.seatBackstop(budget, now);
      const pressure = P.budgetPressure(budget, now);
      if (!pressure.reason) {
        if (this.stopSteer) {
          // Back under both limits (the operator raised the cap): a later
          // breach gets a fresh steer and a fresh grace period.
          this.stopSteer = null;
          await P.clearStopSteer(S).catch(() => undefined);
          this.saveState();
        }
        return;
      }
      if (!this.stopSteer) {
        this.stopSteer = { reason: pressure.reason, at: now };
        this.saveState();
        await P.markStopSteer(S, pressure.reason).catch(() => undefined);
        const text =
          pressure.reason === "cap"
            ? P.CAP_STEER
            : `Swarm wall clock hit (${pressure.elapsed_minutes} of ${budget.wall_clock_minutes} minutes). Call done with reason cannot_complete and stop. Do not start new work.`;
        for (const agent of this.roster) this.prompt(agent, text, { deliver: "steer", kind: "stop_steer" });
        await this.event(pressure.reason === "cap" ? "cap_steer" : "wall_steer", { via: "hub", reason: pressure.reason }, { ok: true });
      }
      if (now - this.stopSteer.at < P.STOP_GRACE_MS) return;
      const stop = await P.harnessStop(S, pressure.reason, `The hub stopped the swarm: ${pressure.reason} passed and the agents did not stop within the grace period.`, { verify: true });
      if (stop.created) {
        await this.event("harness_stop", { via: "hub", reason: pressure.reason }, { created_sentinel: true });
        this.notify(pressure.reason === "wall_clock" ? "wall_clock" : "budget_cap", { scope: "run", reason: pressure.reason });
        await P.systemPost(S, { tag: "stop", body: `Harness wrote done/SWARM_DONE (reason ${pressure.reason}). Call done and stop.` }).catch(() => undefined);
      }
      return;
    }
    if (!this.doneSince) {
      this.doneSince = now;
      this.saveState();
      for (const agent of this.roster) {
        if (existsSync(P.agentDonePath(S, agent)) || existsSync(P.agentDeadPath(S, agent))) continue;
        await this.nudge("", "swarm_done", agent);
      }
      return;
    }
    const allOut = this.roster.every((a) => existsSync(P.agentDonePath(S, a)) || existsSync(P.agentDeadPath(S, a)));
    if (this.finished && !this.finishDone && !this.finishing) {
      // A hub that died while finishing the run finishes it now: putting
      // the VMs away again skips what is already away, and custody is taken.
      this.finishing = this.finishVms(allOut);
      await this.finishing;
      return;
    }
    if (this.finished || (!allOut && now - this.doneSince < P.STOP_GRACE_MS)) return;
    this.finished = true;
    this.saveState();
    this.writeStatus();
    this.finishing = this.finishVms(allOut);
    await this.finishing;
  }

  /**
   * With the model gateway (`--model-gateway`), a fronted seat's spend is
   * measured on the host, off the provider's own answers, and kept in
   * traces/model-gateway.json, which no VM can write. On every tick it is
   * folded into budget.json, so every cap, steer and stop (this process's
   * and the extensions') reads the host's figure: each field is the larger
   * of the gateway's and the seat's own report, which stays a cross-check,
   * and the row says it was metered on the host. Without the gateway there
   * is no file and nothing changes.
   */
  async foldGatewaySpend(): Promise<void> {
    const S = this.cfg.sandbox;
    const file = join(S, GATEWAY_STATE_REL);
    let seats: Record<string, Record<string, unknown>>;
    try {
      if (!lstatSync(file).isFile()) return;
      const state = JSON.parse(readFileSync(file, "utf8")) as { seats?: unknown };
      if (!isObject(state.seats)) return;
      seats = state.seats as Record<string, Record<string, unknown>>;
    } catch {
      return;
    }
    const budget = await P.readBudget(S).catch(() => null);
    if (!budget) return;
    const n = (v: unknown) => (typeof v === "number" && Number.isFinite(v) && v >= 0 ? v : 0);
    for (const [seat, gw] of Object.entries(seats)) {
      if (!this.roster.includes(seat) || !isObject(gw)) continue;
      this.gatewaySeats.add(seat);
      const row = budget.agents[seat] ?? P.emptyAgentBudget();
      const next: P.AgentBudget = {
        ...row,
        spent_usd: Math.max(row.spent_usd, n(gw.spent_usd)),
        tokens: Math.max(row.tokens, n(gw.input) + n(gw.output) + n(gw.cache_read) + n(gw.cache_write)),
        calls: Math.max(row.calls, n(gw.calls)),
        input: Math.max(row.input, n(gw.input)),
        output: Math.max(row.output, n(gw.output)),
        cache_read: Math.max(row.cache_read, n(gw.cache_read)),
        cache_write: Math.max(row.cache_write, n(gw.cache_write)),
        metered_by: "model-gateway",
      };
      const same = row.metered_by === "model-gateway" && P.MONOTONIC_USAGE_KEYS.every((k) => Number(row[k]) === Number(next[k]));
      if (same) continue;
      await P.applySessionUsage(S, seat, next, { monotonic: true }).catch((err: Error) => this.log(`gateway fold ${seat}: ${err.message}`));
    }
  }

  /**
   * A seat over its own cap, or over its model's: told, and a grace period
   * later put away by the hub — its VM stopped and the seat recorded as done
   * on its own cap, the way its extension would have done from inside.
   */
  private async seatBackstop(budget: P.BudgetRecord, now: number): Promise<void> {
    const S = this.cfg.sandbox;
    for (const agent of this.roster) {
      if (existsSync(P.agentDonePath(S, agent)) || existsSync(P.agentDeadPath(S, agent))) continue;
      const mine = P.agentPressure(budget, agent);
      const group = P.modelPressure(budget, budget.agents[agent]?.model);
      if (!mine.over && !group.over) {
        if (this.seatSteer.delete(agent)) this.saveState();
        continue;
      }
      const told = this.seatSteer.get(agent);
      if (!told) {
        this.seatSteer.set(agent, now);
        this.saveState();
        const text = mine.over
          ? `You have reached your own cap (${mine.by === "tokens" ? `${mine.tokens.toLocaleString("en-US")} of ${mine.cap_tokens.toLocaleString("en-US")} tokens` : `$${mine.spent_usd.toFixed(2)} of $${mine.cap_usd}`}). Post your findings to the board now and call done with reason agent_cap. The swarm continues without you.`
          : `Your model has spent its ceiling across every seat running it. Post your findings to the board now and call done with reason agent_cap. The swarm continues without you.`;
        this.prompt(agent, text, { deliver: "steer", kind: "agent_cap_steer" });
        await this.event("agent_cap_steer", { via: "hub", agent }, { ok: true });
        continue;
      }
      if (now - told < P.STOP_GRACE_MS) continue;
      // The output names what stopped the seat, as its extension's own stop
      // does: done refuses an empty one, and a stop that wrote no marker
      // is said as failed and tried again on the next tick, not said done.
      const model = budget.agents[agent]?.model;
      const outputFile = mine.over ? "(stopped by the per-agent cap)" : `(stopped by the per-model cap on ${model ?? "its model"})`;
      const marked = await P.markDone({ sandboxRoot: S, agentId: agent }, { reason: "agent_cap", outputFile, createSentinel: false }).then(
        () => ({ ok: true as const }),
        (err: unknown) => ({ ok: false as const, error: err instanceof Error ? err.message : String(err) }),
      );
      await this.event("agent_cap_stop", { via: "hub", agent }, marked);
      if (!marked.ok) continue;
      this.notify("budget_cap", { scope: "seat", agent, by: mine.over ? "agent cap" : "model cap" });
      this.seatSteer.delete(agent);
      this.saveState();
      await this.finishOne(agent);
    }
  }

  private vmCliArgs(extra: string[]): string[] {
    const args = ["--experimental-strip-types", "--no-warnings", this.cfg.vmCli as string, "finish", "--run", this.cfg.run as string, "--sandbox", this.cfg.sandbox, ...extra];
    if (this.cfg.snapshot === false) args.push("--no-snapshot");
    // Only this registry's VMs: another registry's run can carry the same id.
    if (this.cfg.registry) args.push("--registry", this.cfg.registry);
    return args;
  }

  private runVmCli(args: string[], timeoutMs: number): Promise<{ ok: boolean; out: string; msbDb: Array<{ agent: string; name: string; msb_db: string }> }> {
    return new Promise((done) => {
      execFile(process.execPath, args, { timeout: timeoutMs, maxBuffer: 16 * 1024 * 1024 }, (err, stdout, stderr) => {
        const out = `${String(stdout).trim()} ${String(stderr).trim()}`.trim();
        done({ ok: !err, out: err ? `${err.message} ${out}`.trim() : out, msbDb: msbDbOutcomes(String(stdout)) });
      });
    });
  }

  /**
   * A seat that said done while the swarm goes on has nothing left to do in
   * its VM, which would otherwise hold its memory and cores until the last
   * seat finishes. Its VM is put away a grace period later (its last trace
   * lines and the answer to its done are through by then), unless the
   * swarm is finishing, which puts every VM away itself.
   */
  private seatLeft(agent: string): void {
    if (this.leaving.has(agent) || !this.cfg.vmCli || !this.cfg.run) return;
    const due = Date.now() + (this.cfg.seatLeaveMs ?? P.STOP_GRACE_MS);
    this.seatLeave.set(agent, due);
    this.saveState();
    this.armSeatLeave(agent, due);
  }

  /** Put a leaving seat's VM away at `due`; kept in the hub's state until it has been. */
  private armSeatLeave(agent: string, due: number): void {
    if (this.leaving.has(agent) || !this.cfg.vmCli || !this.cfg.run) return;
    this.leaving.add(agent);
    const timer = setTimeout(() => {
      void (async () => {
        if (this.finished || this.finishing || (await P.swarmDoneExists(this.cfg.sandbox))) return;
        await this.finishOne(agent);
      })()
        .catch(() => undefined)
        .finally(() => {
          this.seatLeave.delete(agent);
          this.saveState();
        });
    }, Math.max(0, due - Date.now()));
    timer.unref?.();
  }

  private async finishOne(agent: string): Promise<void> {
    if (!this.cfg.vmCli || !this.cfg.run) return;
    const r = await this.runVmCli(this.vmCliArgs(["--agent", agent]), 20 * 60_000);
    this.log(`finish ${agent}: ${r.ok ? "ok" : "failed"} ${r.out}`);
    await this.event("vm_finish", { via: "hub", agent }, { ok: r.ok, ...(r.ok ? {} : { error: r.out }), ...(r.msbDb.length ? { msb_db: r.msbDb } : {}) });
  }

  /**
   * Put this run's VMs away, through the VM manager, once; then say on the
   * record what happened, not what was about to. Each VM gets its own time,
   * the registry learns the run is finished, and custody is taken on the
   * host, so a run the hub ended does not wait for an operator's `stop` to
   * become a record.
   */
  private async finishVms(allOut: boolean): Promise<void> {
    if (!this.cfg.vmCli || !this.cfg.run) return;
    // Jobs first: a queued one is cancelled and a running worker removed,
    // each on the record, before the seats are put away.
    await this.jobService?.stop("the run is finishing").catch((err: Error) => this.log(`jobs: stop: ${err.message}`));
    const r = await this.runVmCli(this.vmCliArgs([]), (this.roster.length + 1) * 20 * 60_000);
    this.log(`finish: ${r.ok ? "ok" : "failed"} ${r.out}`);
    await this.event("vm_finish", { via: "hub", all_out: allOut }, { ok: r.ok, ...(r.ok ? {} : { error: r.out }), ...(r.msbDb.length ? { msb_db: r.msbDb } : {}) });
    if (this.cfg.registry) await updateRegistryState(this.cfg.registry, this.cfg.run, r.ok ? "finished" : "finish_failed").catch((err: Error) => this.log(`registry: ${err.message}`));
    this.notify(r.ok ? "finished" : "finish_failed", { all_out: allOut, ...(r.ok ? {} : { error: r.out }) });
    await this.flushRefusals().catch(() => undefined);
    this.copySpill();
    const custody = join(dirname(this.cfg.vmCli), "custody.ts");
    if (existsSync(custody)) {
      // The operator's bound on custody, as `swarm.sh stop --custody-timeout`
      // takes it (SWARM_CUSTODY_TIMEOUT), with the same five minutes past it
      // before the process is ended.
      const timeoutSec = this.cfg.custodyTimeoutSec ?? custodyTimeoutSec();
      const c = await new Promise<{ ok: boolean; out: string }>((done) => {
        execFile(process.execPath, ["--experimental-strip-types", "--no-warnings", custody, this.cfg.sandbox, "--run", this.cfg.run as string, "--timeout", String(timeoutSec)], { timeout: (timeoutSec + 300) * 1000, maxBuffer: 16 * 1024 * 1024 }, (err, stdout, stderr) => {
          done({ ok: !err, out: `${String(stdout).trim()} ${String(stderr).trim()}`.trim() });
        });
      });
      this.log(`custody: ${c.ok ? "ok" : "failed"} ${c.out}`);
      await this.event("custody", { via: "hub" }, { ok: c.ok, ...(c.ok ? {} : { error: c.out }) });
      this.copySpill();
    }
    this.finishDone = true;
    this.saveState();
    this.writeStatus();
    this.clearUp();
  }

  /**
   * What the run still holds once the hub has finished it — the panes, the
   * collector, the keep-awake, an attached evidence image, this hub — is the
   * operator's stop's to clear: it is run, detached, with custody already
   * taken, and the run keeps the state the hub recorded.
   */
  private clearUp(): void {
    if (!this.cfg.stopCmd || !this.cfg.run || !existsSync(this.cfg.stopCmd)) return;
    try {
      const child = spawn("bash", [this.cfg.stopCmd, "stop", this.cfg.run, "--after-hub"], {
        detached: true,
        stdio: ["ignore", "ignore", "ignore"],
        env: { ...process.env, ...(this.cfg.registry ? { SWARM_RUNS_DIR: dirname(resolve(this.cfg.registry)) } : {}) },
      });
      child.unref();
      void this.event("hub_clear_up", { via: "hub" }, { ok: true, pid: child.pid ?? null });
    } catch (err) {
      this.log(`clear-up failed: ${err instanceof Error ? err.message : err}`);
    }
  }

  /**
   * The hub's own lines the collector did not take, into the run, where
   * custody counts them: custody taken here must see them, not only the one
   * an operator's `stop` takes after copying them.
   */
  copySpill(): void {
    try {
      if (!existsSync(this.spillFile())) return;
      const to = join(this.cfg.sandbox, "traces", "hub-spill.jsonl");
      mkdirSync(dirname(to), { recursive: true });
      writeFileSync(to, readFileSync(this.spillFile()), { mode: 0o600 });
    } catch (err) {
      this.log(`spill copy failed: ${err instanceof Error ? err.message : err}`);
    }
  }
}

/** What of a call's result is worth a line on the trace. */
function summarize(fn: string, result: unknown): Record<string, unknown> {
  if (!isObject(result)) return {};
  switch (fn) {
    case "markDone":
      return { created_sentinel: result.created_sentinel === true, reason: result.reason };
    case "forgeTool":
      return { ok: result.ok, name: (result as { manifest?: { name?: string } }).manifest?.name ?? result.name };
    case "restoreFileVersion":
      return { path: result.path, rev: result.rev, ok: result.ok };
    case "claimName":
      return { name: result.name, ok: result.ok };
    case "threadOpen":
      return { thread: result.name ?? result.thread };
    case "publishFile":
      return { path: result.path, sha256: result.sha256, bytes: result.bytes };
    case "recordEntry": {
      // The ledger entry's hash, on the harness's own line: custody holds
      // the ledger to it.
      const entry = isObject(result.entry) ? result.entry : {};
      return { ok: result.ok, seq: entry.seq, merged: result.merged, ...(typeof entry.hash === "string" ? { hash: entry.hash } : {}) };
    }
    default:
      return {};
  }
}

/** The run's state in the operator's registry, under a lock swarm.sh shares. */
export async function updateRegistryState(registry: string, runId: string, state: string): Promise<void> {
  const lock = `${registry}.lock`;
  for (let i = 0; i < 100; i++) {
    try {
      mkdirSync(lock);
      break;
    } catch {
      // A lock older than a minute is a writer that died holding it, as
      // swarm.sh's registry_lock reads it: a stop killed mid-write must not
      // keep the hub from recording the run finished.
      const age = await stat(lock).then((st) => Date.now() - st.mtimeMs).catch(() => 0);
      if (age > 60_000) {
        rmSync(lock, { recursive: true, force: true });
        continue;
      }
      await new Promise((r) => setTimeout(r, 100));
      if (i === 99) throw new Error(`the registry is locked (${lock})`);
    }
  }
  try {
    const raw = JSON.parse(readFileSync(registry, "utf8")) as { runs?: Array<Record<string, unknown>> };
    const runs = Array.isArray(raw.runs) ? raw.runs : [];
    for (const r of runs) if (r.id === runId) r.state = state;
    const tmp = `${registry}.tmp`;
    writeFileSync(tmp, `${JSON.stringify({ ...raw, runs }, null, 2)}\n`);
    renameSync(tmp, registry);
  } finally {
    rmSync(lock, { recursive: true, force: true });
  }
}

async function readStdin(): Promise<string> {
  let input = "";
  process.stdin.setEncoding("utf8");
  for await (const chunk of process.stdin) input += chunk;
  return input;
}

type HubInput = {
  sandbox: string;
  jobs?: JobsConfig;
  dir: string;
  agents: string[];
  tokens: Record<string, string>;
  /** The kickoff's `seat_tokens`, kept here (0600, 0700 dir, no VM mounts it) so a resumed hub asks for the same ones. */
  seatTokens?: Record<string, string>;
  collector: string;
  run?: string;
  vmCli?: string;
  registry?: string;
  stopCmd?: string;
  settleMs?: number;
  forging: boolean;
  snapshot: boolean;
  quiet: boolean;
  /**
   * What the hub reads from its environment, kept so a hub the watchdog
   * brings back with --resume reads the same: the inbox page bound, and the
   * runs directory whose registry holds the operator's finish line.
   */
  env?: Record<string, string>;
};

/**
 * Whether `given` is the seat's token, compared in constant time. No token
 * issued, or none given, is never a match.
 */
export function seatTokenMatches(expected: string | undefined, given: unknown): boolean {
  if (typeof expected !== "string" || !expected || typeof given !== "string" || !given) return false;
  const a = Buffer.from(expected, "utf8");
  const b = Buffer.from(given, "utf8");
  return a.length === b.length && timingSafeEqual(a, b);
}

/** The kickoff's `seat_tokens`, kept only as agent id → non-empty string; absent stays absent. */
export function parseSeatTokens(raw: unknown): Record<string, string> | undefined {
  if (!isObject(raw)) return undefined;
  return Object.fromEntries(Object.entries(raw).filter(([k, v]) => /^[a-z][a-z0-9_-]{0,31}$/.test(k) && typeof v === "string" && v.length > 0 && v.length <= 256)) as Record<string, string>;
}

/** The environment a hub runs with that must survive a --resume. */
/** The longest Unix socket path, in bytes, that every platform the hub runs on binds (macOS: 104 with the NUL). */
export const SOCKET_PATH_MAX = 103;

/** A hub socket path past SOCKET_PATH_MAX: named, with the path and its length. */
export class SocketPathTooLong extends Error {
  readonly code = "ESOCKETPATH";
  readonly path: string;
  readonly bytes: number;
  constructor(path: string, bytes: number) {
    super(`the hub socket path ${path} is ${bytes} bytes, past the ${SOCKET_PATH_MAX} a Unix socket can take: start the hub in a shorter directory`);
    this.name = "SocketPathTooLong";
    this.path = path;
    this.bytes = bytes;
  }
}

/** Each removed VM's msb database outcome, from `vm.ts finish`'s JSON (FinishEntry.msb_db). */
export function msbDbOutcomes(stdout: string): Array<{ agent: string; name: string; msb_db: string }> {
  for (const line of stdout.split("\n").reverse()) {
    if (!line.trim().startsWith("{")) continue;
    try {
      const parsed = JSON.parse(line) as { vms?: Array<{ agent?: unknown; name?: unknown; msb_db?: unknown }> };
      if (!Array.isArray(parsed.vms)) continue;
      return parsed.vms
        .filter((v) => typeof v.msb_db === "string")
        .map((v) => ({ agent: String(v.agent ?? ""), name: String(v.name ?? ""), msb_db: v.msb_db as string }));
    } catch {
      // not the finish's line
    }
  }
  return [];
}

const KEPT_ENV = ["SWARM_INBOX_PAGE_CHARS", "SWARM_RUNS_DIR", "SWARM_VM_IMAGE_DIGEST", "SWARM_CUSTODY_TIMEOUT", "SWARM_HISTORY_QUOTA_MB", "SWARM_TRANSFER_PART_BYTES"];

/**
 * Bytes of file history one seat may have stored: SWARM_HISTORY_QUOTA_MB, else
 * 1 GiB. A revision is stored whole up to 32 MiB (HISTORY_STORE_MAX_BYTES)
 * and a deliverable is kilobytes to a few megabytes, so a gibibyte holds
 * thirty-two revisions at the largest and thousands of ordinary ones; past it
 * a revision is still recorded by its hash. What it bounds is one seat
 * writing copies onto the host's disk in a loop.
 */
export function historyQuotaBytes(env: NodeJS.ProcessEnv = process.env): number {
  const mb = Number(env.SWARM_HISTORY_QUOTA_MB);
  return Number.isFinite(mb) && mb > 0 ? Math.floor(mb * 1048576) : 1024 * 1048576;
}

/** Custody's bound when the hub takes it: the operator's SWARM_CUSTODY_TIMEOUT, else stop's default. */
export function custodyTimeoutSec(env: NodeJS.ProcessEnv = process.env): number {
  const n = Number(env.SWARM_CUSTODY_TIMEOUT);
  return Number.isInteger(n) && n > 0 ? n : 14400;
}

async function main(): Promise<void> {
  const args = process.argv.slice(2);
  const opt = (name: string) => {
    const i = args.indexOf(name);
    return i >= 0 ? args[i + 1] : undefined;
  };
  let input: HubInput;
  const resumeDir = opt("--resume");
  if (resumeDir) {
    // Back after a crash, with what the kickoff gave: the hub's directory is
    // the host's, 0700, and no VM mounts it.
    try {
      input = JSON.parse(readFileSync(join(resolve(resumeDir), "hub-input.json"), "utf8")) as HubInput;
    } catch (err) {
      console.error(`vm-hub: cannot resume from ${resumeDir}: ${err instanceof Error ? err.message : err}`);
      process.exit(2);
    }
  } else {
    const sandbox = resolve(args[0] ?? "");
    const dir = opt("--dir");
    if (!args[0] || !existsSync(sandbox) || !dir) {
      console.error("vm-hub: usage: vm-hub.ts <sandbox> --dir DIR [--run ID] [--vm-cli PATH] [--registry FILE] [--stop-cmd SWARM_SH] [--settle-ms N] [--forging] [--no-snapshot] [--quiet]  (stdin: {agents, tokens, seat_tokens, collector}) | --resume DIR");
      process.exit(2);
    }
    let parsed: { agents?: unknown; tokens?: unknown; seat_tokens?: unknown; collector?: unknown; jobs?: unknown };
    try {
      parsed = JSON.parse((await readStdin()).trim() || "{}");
    } catch (err) {
      console.error(`vm-hub: stdin is not JSON (${err instanceof Error ? err.message : err})`);
      process.exit(2);
    }
    const settle = opt("--settle-ms");
    input = {
      sandbox,
      dir: resolve(dir),
      agents: Array.isArray(parsed.agents) ? parsed.agents.filter((a): a is string => typeof a === "string" && /^[a-z][a-z0-9_-]{0,31}$/.test(a)) : [],
      tokens: isObject(parsed.tokens) ? (Object.fromEntries(Object.entries(parsed.tokens).filter(([, v]) => typeof v === "string")) as Record<string, string>) : {},
      ...(parsed.seat_tokens !== undefined ? { seatTokens: parseSeatTokens(parsed.seat_tokens) ?? {} } : {}),
      collector: typeof parsed.collector === "string" ? parsed.collector : join(sandbox, "traces", ".collector.sock"),
      ...(parseJobsConfig(parsed.jobs) ? { jobs: parseJobsConfig(parsed.jobs) } : {}),
      run: opt("--run"),
      vmCli: opt("--vm-cli") ?? join(dirname(fileURLToPath(import.meta.url)), "vm.ts"),
      registry: opt("--registry"),
      stopCmd: opt("--stop-cmd"),
      settleMs: settle !== undefined ? Number(settle) : undefined,
      forging: args.includes("--forging"),
      snapshot: !args.includes("--no-snapshot"),
      quiet: args.includes("--quiet"),
      env: Object.fromEntries(KEPT_ENV.filter((k) => process.env[k]).map((k) => [k, process.env[k] as string])),
    };
    // The finish line the hub re-runs before a sentinel is the operator's
    // copy in the registry, found through the runs directory: a sandbox
    // outside runs/ would otherwise be judged by its own SWARM.md.
    if (input.registry && !input.env?.SWARM_RUNS_DIR) input.env = { ...(input.env ?? {}), SWARM_RUNS_DIR: dirname(resolve(input.registry)) };
    mkdirSync(input.dir, { recursive: true, mode: 0o700 });
    writeFileSync(join(input.dir, "hub-input.json"), JSON.stringify(input), { mode: 0o600 });
  }
  for (const [k, v] of Object.entries(input.env ?? {})) if (KEPT_ENV.includes(k) && typeof v === "string") process.env[k] = v;
  // Beside the collector's socket, so a long sandbox path is dialled short.
  try {
    process.chdir(dirname(input.collector));
  } catch {
    // the collector may not be there; the forward says so line by line
  }
  // One hub per run: a second (a watchdog and the keeper both restarting a
  // hub that died) would take the first's sockets and run a second stop clock.
  const lockFile = join(input.dir, "hub.lock");
  if (!takeHubLock(lockFile, input.dir)) {
    console.error(`vm-hub: a hub for ${input.dir} is already running; not starting a second`);
    process.exit(0);
  }
  const hub = new Hub(input);
  await hub.start();
  console.error(`vm-hub: up${resumeDir ? " (resumed)" : ""}, ${input.agents.length} agent socket(s) in ${input.dir}`);
  const shutdown = () => void hub.stop().then(() => process.exit(0));
  process.on("SIGTERM", shutdown);
  // Not SIGINT: a run started from the console's terminal shares its process
  // group, and the operator's Ctrl-C there must not take the stop with it.
  process.on("SIGINT", () => undefined);
}

/**
 * Whether `pid` is a hub serving `dir`: alive, and its command line is this
 * script's with that directory. A bare pid alive is not enough: after a
 * crash the dead hub's pid can be any process of the user's, and a resumed
 * hub that took it for a live one exited, until the keeper gave up.
 */
export function isHubProcess(pid: number, dir: string): boolean {
  try {
    process.kill(pid, 0);
  } catch {
    return false;
  }
  let command: string;
  try {
    command = execFileSync("ps", ["-o", "command=", "-p", String(pid)], { encoding: "utf8", timeout: 5000 });
  } catch {
    // No answer from ps: a live pid is taken for the hub, as before.
    return true;
  }
  return command.includes("vm-hub") && command.includes(basename(dir));
}

/**
 * Take the run's hub lock: created exclusively, so two hubs starting at once
 * cannot both pass; one that names a process which is not a hub for this
 * directory is stale and is replaced.
 */
export function takeHubLock(lockFile: string, dir: string): boolean {
  for (let attempt = 0; attempt < 3; attempt++) {
    try {
      const fd = openSync(lockFile, "wx", 0o600);
      writeSync(fd, `${process.pid}\n`);
      closeSync(fd);
      return true;
    } catch (err) {
      if ((err as NodeJS.ErrnoException).code !== "EEXIST") throw err;
    }
    const other = Number.parseInt(readFileSync(lockFile, "utf8"), 10);
    if (other === process.pid) return true;
    if (Number.isInteger(other) && other > 0 && isHubProcess(other, dir)) return false;
    rmSync(lockFile, { force: true });
  }
  return false;
}

if (process.argv[1] && pathToFileURL(process.argv[1]).href === import.meta.url) {
  void main();
}
