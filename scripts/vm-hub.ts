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
 * who is working, tell the hub which Herdr pane is whose, and admit the
 * operator's acts on the question register (scripts/questions-cli.ts), so
 * the hub is that register's one writer while it runs.
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
import { appendFileSync, chmodSync, closeSync, createReadStream, existsSync, lstatSync, mkdirSync, openSync, readFileSync, realpathSync, renameSync, rmSync, unlinkSync, writeFileSync, writeSync } from "node:fs";
import { stat } from "node:fs/promises";
import { connect, createServer, type Server, type Socket } from "node:net";
import { basename, dirname, join, relative, resolve } from "node:path";
import { createInterface } from "node:readline";
import { fileURLToPath, pathToFileURL } from "node:url";
import * as P from "../extensions/protocol.ts";
import * as F from "../extensions/finish.ts";
import * as L from "../extensions/leads.ts";
import * as Q from "../extensions/questions.ts";
import * as T from "../extensions/toolchain.ts";
import { claimHolds, messageFor, resolvePeer } from "./nudge-broker.mjs";
import { GATEWAY_STATE_REL } from "./model-gateway.ts";
import { JobService, jobView, type JobSpec } from "./job-service.ts";
import { similarView } from "./job-reuse.ts";
import { bindJobGrants, checkJobGrants, fetchForSeat, netTick, netViewFor, requestAccess } from "./net-broker.ts";
import { readCasePolicy } from "./case-policy.ts";
import { resolveScope, scopeKindOf } from "./job-scope.ts";
import { commandNames, libraryHint } from "./library-hint.ts";
import { sensitiveIndex } from "./output-hygiene.ts";
import { ACCESS_RULES, apiPageHit, classifyTraceRow, type AccessHit } from "./sensitive-access.ts";

/** What a job tool is told in a run with no job service. */
/**
 * The library hint for a command job at its admission: the tools of the
 * run's library whose manifest `use` (or description) matches the files the
 * job declared, the ones its command already runs left out (library-hint.ts).
 */
async function admissionHint(S: string, spec: JobSpec): Promise<Awaited<ReturnType<typeof libraryHint>>> {
  const r = await resolveScope(S, spec.inputs, {});
  if (!r.ok) return null;
  return libraryHint(S, r.objects, { skip: (tool) => commandNames(spec.command ?? "", tool) });
}

const NO_JOBS = "this run has no job service (a host run, or --no-jobs): run the work in your own shell";

/** How long a record waits for the seal of a brain-side output it cites (an import job on the short lane). */
const SEAL_WAIT_SECONDS = 45;

/**
 * Every ref an entry or an act on the ledger carries, mapped: `refs`,
 * `attribution.basis_refs`, each alternative's `test_refs`, each
 * `qualifies[].ref` (a list given as text is split as the ledger splits it).
 */
function mapLedgerRefs(input: Record<string, unknown>, f: (ref: string) => string): Record<string, unknown> {
  const list = (v: unknown) => (Array.isArray(v) ? v.map(String) : typeof v === "string" ? v.split(/[\s,]+/) : null);
  const mapped = (v: unknown) => {
    const l = list(v);
    return l ? [...new Set(l.map((r) => r.trim()).filter(Boolean).map(f))] : v;
  };
  const out: Record<string, unknown> = { ...input };
  if (input.refs !== undefined) out.refs = mapped(input.refs);
  if (isObject(input.attribution) && (input.attribution as Record<string, unknown>).basis_refs !== undefined) out.attribution = { ...(input.attribution as Record<string, unknown>), basis_refs: mapped((input.attribution as Record<string, unknown>).basis_refs) };
  if (Array.isArray(input.alternatives)) out.alternatives = input.alternatives.map((x) => (isObject(x) && (x as Record<string, unknown>).test_refs !== undefined ? { ...(x as Record<string, unknown>), test_refs: mapped((x as Record<string, unknown>).test_refs) } : x));
  if (Array.isArray(input.qualifies)) out.qualifies = input.qualifies.map((x) => (isObject(x) && typeof (x as Record<string, unknown>).ref === "string" ? { ...(x as Record<string, unknown>), ref: f(String((x as Record<string, unknown>).ref).trim()) } : x));
  return out;
}

/**
 * An entry, or an attest or dispute, with every tool: and trace: ref it
 * carries sealed and replaced by the import it became (JobService.sealCited),
 * and a note per seal. The first that cannot be sealed refuses it with the
 * reason; without a job service there is nothing to seal with, and it is
 * refused so.
 */
export async function sealCitedRefs(svc: JobService | undefined, who: string, input: Record<string, unknown>): Promise<{ ok: true; input: Record<string, unknown>; notes: string[] } | { ok: false; reason: string }> {
  const cited = new Set<string>();
  mapLedgerRefs(input, (r) => {
    if (/^(tool|trace):/.test(r)) cited.add(r);
    return r;
  });
  if (!cited.size) return { ok: true, input, notes: [] };
  const first = [...cited][0];
  if (!svc) return { ok: false, reason: `${first}: a brain's own output is sealed by the job service before a record cites it, and ${NO_JOBS}; run the work as a job and cite job:<id>/<path>` };
  const notes: string[] = [];
  const replaced = new Map<string, string>();
  for (const ref of cited) {
    const r = await svc.sealCited(who, ref, { wait: SEAL_WAIT_SECONDS });
    if (!r.ok) return { ok: false, reason: r.reason };
    replaced.set(ref, r.import_ref);
    notes.push(`${ref} sealed as ${r.import_ref} (job ${r.job}), which it cites`);
  }
  return { ok: true, input: mapLedgerRefs(input, (r) => replaced.get(r) ?? r), notes };
}
import { destroyWorker, roomForWorker, runWorker, workerMetrics } from "./vm.ts";

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
  // The lead register grows as the ledger does: a burst, then a few a second.
  leadOpen: { bucket: "ledger", capacity: 200, perSecond: 5 },
  leadClaim: { bucket: "ledger", capacity: 200, perSecond: 5 },
  leadRelease: { bucket: "ledger", capacity: 200, perSecond: 5 },
  leadClose: { bucket: "ledger", capacity: 200, perSecond: 5 },
  leadLink: { bucket: "ledger", capacity: 200, perSecond: 5 },
  leadInterpret: { bucket: "ledger", capacity: 200, perSecond: 5 },
  leadReopen: { bucket: "ledger", capacity: 200, perSecond: 5 },
  routeReview: { bucket: "ledger", capacity: 200, perSecond: 5 },
  leadHandoff: { bucket: "ledger", capacity: 200, perSecond: 5 },
  leadConfirm: { bucket: "ledger", capacity: 200, perSecond: 5 },
  offerAnswer: { bucket: "ledger", capacity: 200, perSecond: 5 },
  // A done that is not the coordinator's is answered at once; the finish's acts are few.
  finishTurnFor: { bucket: "ledger", capacity: 200, perSecond: 5 },
  finishAct: { bucket: "ledger", capacity: 200, perSecond: 5 },
  // The question register grows as the leads do.
  questionOpen: { bucket: "ledger", capacity: 200, perSecond: 5 },
  questionAsk: { bucket: "ledger", capacity: 200, perSecond: 5 },
  premisePropose: { bucket: "ledger", capacity: 200, perSecond: 5 },
  attestEntry: { bucket: "ledger", capacity: 200, perSecond: 5 },
  disputeEntry: { bucket: "ledger", capacity: 200, perSecond: 5 },
  // Each done that would end the swarm runs the operator's finish line on
  // the host: a few in a row, then one a minute.
  markDone: { bucket: "done", capacity: 3, perSecond: 1 / 60 },
  runFinishLine: { bucket: "finish_line", capacity: 3, perSecond: 1 / 60 },
  // A job is a VM: a burst, then one every few seconds; the queue's own
  // per-agent limits hold what is accepted.
  jobSubmit: { bucket: "job", capacity: 20, perSecond: 0.2 },
  catalogRequest: { bucket: "job", capacity: 20, perSecond: 0.2 },
  // The dynamic network: a request is decided and recorded, a fetch leaves
  // the host; a few at once, then one every few seconds (the engine's own
  // quotas hold the rest).
  netRequest: { bucket: "net", capacity: 20, perSecond: 0.2 },
  netFetch: { bucket: "net", capacity: 20, perSecond: 0.2 },
};
/**
 * How recent a finish-line run markDone takes as its own: the seat's `done`
 * asked for it and calls markDone as soon as it passes.
 */
const FINISH_LINE_REUSE_MS = 30_000;
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

/**
 * Lines the hub writes for one seat and one sensitive job; the next says that
 * the rest are on the trace as the rows they come from, and writes no more.
 */
const ACCESS_BURST_MAX = 200;
/** The tools of a seat whose rows may name a sensitive output (scripts/sensitive-access.ts). */
const ACCESS_TOOLS = new Set(["read", "grep", "find", "ls", "bash", "powershell"]);
/** Where a row can name the store, the catalogue, a kept output or a job: the rest need no look at the journal. */
const ACCESS_PROBE = /store|catalog|tool-output|j\d{6}/;

/** Bytes of a job's output that an API answer carried to a seat. */
export type ApiPage = { fn: string; job: string; part: "stdout" | "stderr"; path: string; offset: number; bytes: number; total: number };

/** Calls the hub records on the trace when they succeed; every refusal is recorded. */
const AUDITED = new Set(["markDone", "runFinishLine", "forgeTool", "restoreFileVersion", "claimName", "threadOpen", "publishFile", "recordEntry", "attestEntry", "disputeEntry", "jobSubmit", "catalogRequest", "leadOpen", "leadClaim", "leadRelease", "leadClose", "leadLink", "leadInterpret", "leadReopen", "routeReview", "leadHandoff", "leadConfirm", "offerAnswer", "finishTurnFor", "finishAct", "questionOpen", "questionAsk", "premisePropose", "netRequest", "netFetch"]);

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
  /** The derived catalogue's ceiling of generations a run (the kickoff's --derived-limit; the job service's own default when absent). */
  derivedGenerations?: number;
  /** The run's job images by profile, and each pack's profile (the kickoff's). */
  images?: Record<string, string>;
  packProfiles?: Record<string, string>;
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
    // On unless the kickoff said off (--no-derived-catalog).
    derived: raw.derived !== false,
    ...(typeof raw.derivedGenerations === "number" && Number.isInteger(raw.derivedGenerations) && raw.derivedGenerations > 0 ? { derivedGenerations: raw.derivedGenerations } : {}),
    ...(isObject(raw.images) ? { images: Object.fromEntries(Object.entries(raw.images).filter(([k, v]) => /^[a-z0-9-]{1,32}$/.test(k) && typeof v === "string" && v.length > 0 && v.length < 512)) as Record<string, string> } : {}),
    ...(isObject(raw.packProfiles) ? { packProfiles: Object.fromEntries(Object.entries(raw.packProfiles).filter(([k, v]) => typeof k === "string" && typeof v === "string")) as Record<string, string> } : {}),
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
  /** The run's job service, when it has one. */
  jobs?: () => JobService | undefined;
  /** An API answer carried bytes of a job's output to a seat: the hub records it when the job is sensitive. */
  accessed?: (who: string, page: ApiPage) => Promise<void>;
  /** The hub's own directory (the fetch service's config and secret are there, in no VM). */
  dir?: string;
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
  // one runs gets that run's answer. A seat's `done` asks for the run first
  // (runFinishLine: its VM does not see the trace the checks read) and then
  // calls markDone; markDone takes that same run when it met the finish line
  // moments ago, so one done is one run of the operator's checks. Only the
  // seat's own run, only a passing one, and only while the state it was run
  // against still stands (P.stateRevision: the board, the ledger, the review
  // and the leads); a run that refused, or one the state moved past, is run
  // again. Each run carries the revision taken before it started.
  type FinishLine = { run: Awaited<ReturnType<typeof P.runFinishLine>> | null; revision: string };
  let finishLine: Promise<FinishLine> | null = null;
  const askedBy = new Map<string, FinishLine & { at: number }>();
  const revisionNow = async () => (await P.stateRevision(S).catch(() => ({ revision: "" }))).revision;
  // One check result per revision (A4): a run recorded against the
  // revision that still holds is taken, not run again, by whichever seat asks.
  const sharedFinishLine = (): Promise<FinishLine> =>
    (finishLine ??= (async () => {
      const revision = await revisionNow();
      const stored = await F.checkAt(S, revision).catch(() => null);
      if (stored?.run) return { run: stored.run as FinishLine["run"], revision };
      const run = await P.runFinishLine(S).catch(() => null);
      const untilSolved = (await P.readBudget(S).catch(() => null))?.until_solved === true;
      const v = P.finishLineVerdict(run, false, { untilSolved });
      if (run && !run.error) await F.recordCheck(S, "system", revision, v.proceed ? { proceed: true, outcome: v.outcome } : { proceed: false, reason: v.reason }, run).catch(() => undefined);
      return { run, revision };
    })().finally(() => {
      finishLine = null;
    }));
  // A job as the seat is shown it, and, when the answer carried bytes of the
  // job's output (a page of stdout, the tail of stderr), a note of that for
  // the access record. Whether the job is sensitive is for the hub to say.
  const shown = async (who: string, fn: string, job: Parameters<typeof jobView>[1], stdout?: { offset: number; bytes: number; total: number; path: string }) => {
    const view = await jobView(S, job);
    if (hub.accessed) {
      if (stdout) await hub.accessed(who, { fn, job: job.id, part: "stdout", path: stdout.path, offset: stdout.offset, bytes: stdout.bytes, total: stdout.total }).catch(() => undefined);
      const err = view.stderr as { tail?: string; bytes?: number } | undefined;
      if (err && typeof err.tail === "string") await hub.accessed(who, { fn, job: job.id, part: "stderr", path: `store/jobs/${job.id}/stderr.log`, offset: Math.max(0, (err.bytes ?? 0) - Buffer.byteLength(err.tail)), bytes: Buffer.byteLength(err.tail), total: err.bytes ?? 0 }).catch(() => undefined);
    }
    return view;
  };
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
    teamView: (who, a) => {
      const o = isObject(a[1]) ? a[1] : {};
      return P.teamView(as(who), {
        ...(typeof o.from === "string" ? { from: o.from } : {}),
        ...(typeof o.pageChars === "number" && Number.isFinite(o.pageChars) ? { pageChars: o.pageChars } : {}),
      });
    },
    markDone: async (who, a) => {
      // The sentinel ends every seat, so the finish line is run here, on the
      // host, by the harness, before it is written: the run the seat's own
      // done asked for moments ago (runFinishLine), when it met the finish
      // line, or a new one; a seat's VM runs none of it. An abandoned run says
      // so in its reason and is not held to the checks, but one seat's
      // abandon ends it only with a second's or with nobody else working
      // (P.abandonGate); a seat leaving on its own cap writes no sentinel and
      // is not held to them either.
      const { outcome: _saidOutcome, ...said } = (a[1] as { reason?: string; outputFile?: string; createSentinel?: boolean; outcome?: string }) ?? {};
      const args: { reason?: string; outputFile?: string; createSentinel?: boolean; outcome?: P.FinishOutcome } = said;
      let reason = String(args.reason ?? "");
      const endsSwarm = args.createSentinel !== false && reason !== "agent_cap" && !reason.startsWith(P.ABANDON_PREFIX);
      const untilSolved = (await P.readBudget(S).catch(() => null))?.until_solved === true;
      if (endsSwarm && !(await P.swarmDoneExists(S))) {
        const mine = askedBy.get(who);
        askedBy.delete(who);
        const now = await revisionNow();
        const recent = mine && Date.now() - mine.at <= FINISH_LINE_REUSE_MS && mine.revision === now && P.finishLineVerdict(mine.run, false, { untilSolved }).proceed ? mine : null;
        // The revision is checked again just before the sentinel: a run the
        // state moved under (a dispute, a new lead, an entry) is run again,
        // a bounded number of times, and a state that never holds still is a
        // refusal, not a sentinel written on a verdict it no longer matches.
        let line: FinishLine = recent ?? (await sharedFinishLine());
        let attempts = recent ? 0 : 1;
        while ((await revisionNow()) !== line.revision) {
          if (attempts >= P.FINISH_LINE_ATTEMPTS) throw new Error(P.FINISH_LINE_UNSETTLED);
          line = await sharedFinishLine();
          attempts += 1;
        }
        const run = line.run;
        const verdict = P.finishLineVerdict(run, false, { untilSolved });
        if (!verdict.proceed) throw new Error(`the harness ran the finish line on the host and it is not met: ${verdict.reason}`);
        // How the run ended is the hub's to say, from its own run: a seat's
        // word for it is dropped, and a finish line the host could not run
        // is said in the sentinel's reason whatever the seat wrote there.
        args.outcome = verdict.outcome;
        if (verdict.outcome === "verification_unavailable" && !reason.startsWith(P.VERIFICATION_UNAVAILABLE_PREFIX)) reason = P.VERIFICATION_UNAVAILABLE_PREFIX + reason;
        args.reason = reason;
        // Written only while the state that line was judged on holds, under
        // the registers' lock: a question admitted since refuses it.
        (args as { revision?: string }).revision = line.revision;
      }
      // An abandon one seat asks for while others work is a vote: the seat
      // stays, and markDone says so.
      const done = await P.markDone(as(who), args as never);
      if (done.terminate) hub.seatDone?.(who);
      return done;
    },
    nameOf: (_who, a) => P.nameOf(S, String(a[1] ?? "")),
    // The operator's finish line for a seat's `done`, answered whole (the
    // refusal is made from it in the seat, as on the host).
    runFinishLine: async (who) => {
      const line = await sharedFinishLine();
      askedBy.set(who, { ...line, at: Date.now() });
      return line.run;
    },
    // The lead register (extensions/leads.ts): who acts is the channel's seat.
    leadOpen: (who, a) => L.openLead(as(who), (isObject(a[1]) ? a[1] : {}) as L.LeadOpenInput),
    leadClaim: (who, a) => L.claimLead(as(who), a[1], (isObject(a[2]) ? a[2] : {}) as L.LeadClaimInput),
    leadRelease: (who, a) => L.releaseLead(as(who), a[1], (isObject(a[2]) ? a[2] : {}) as { why?: string; generation?: number }),
    leadClose: (who, a) => L.closeLead(as(who), a[1], (isObject(a[2]) ? a[2] : {}) as { disposition?: string; ref?: string; why?: string; generation?: number; ask?: unknown }),
    leadLink: (who, a) => L.linkLead(as(who), a[1], (isObject(a[2]) ? a[2] : {}) as { add?: string[]; remove?: string[]; routes?: unknown }),
    leadsView: (who, a) => {
      const o = isObject(a[1]) ? a[1] : {};
      return L.leadsView(as(who), { ...(typeof o.view === "string" ? { view: o.view } : {}), ...(typeof o.from === "string" ? { from: o.from } : {}), ...(typeof o.pageChars === "number" && Number.isFinite(o.pageChars) ? { pageChars: o.pageChars } : {}) });
    },
    leadsDigest: (who, a) => L.leadsDigest(as(who), { mark: isObject(a[1]) && a[1].mark === true }),
    leadInterpret: (who, a) => L.recordInterpretations(S, who, Number(a[1]), Array.isArray(a[2]) ? (a[2] as L.InterpretInput[]) : []),
    leadReopen: (who, a) => L.agentReopenLead(as(who), a[1], (isObject(a[2]) ? a[2] : {}) as { expected_revision?: unknown; why?: string; take?: boolean }),
    routeReview: (who, a) => L.routeReview(as(who), a[1], (isObject(a[2]) ? a[2] : {}) as { material?: unknown; why?: string; second_review_why?: string }),
    leadHandoff: (who, a) => L.handoffLead(as(who), a[1], (isObject(a[2]) ? a[2] : {}) as { why?: string; to?: string; generation?: number }),
    leadConfirm: (who, a) => {
      const input = (isObject(a[2]) ? a[2] : {}) as { expected_revision?: unknown; ref?: string; why?: string; batch?: string };
      // A batch of confirmations (one correction chain, one seat) is confirmed in one act.
      return input.batch ? L.confirmBatch(as(who), input.batch, input) : L.confirmLead(as(who), a[1], input);
    },
    offerAnswer: (who, a) => L.answerOffer(as(who), a[1], (isObject(a[2]) ? a[2] : {}) as { action?: string; why?: string }),
    finishTurnFor: (who, a) => F.finishTurnFor(as(who), (isObject(a[1]) ? a[1] : {}) as { output_file?: string }),
    finishAct: (who, a) => F.finishAct(as(who), (isObject(a[1]) ? a[1] : {}) as Parameters<typeof F.finishAct>[1]),
    // The question register (extensions/questions.ts): the seat is the channel's.
    questionOpen: (who, a) => Q.questionOpen(as(who), (isObject(a[1]) ? a[1] : {}) as Q.ActInput),
    questionAsk: (who, a) => Q.questionAsk(as(who), a[1], a[2], a[3]),
    premisePropose: (who, a) => Q.premisePropose(as(who), (isObject(a[1]) ? a[1] : {}) as { text?: string; locator?: string; why?: string; scope?: unknown }),
    questionsView: (who, a) => {
      const o = isObject(a[1]) ? a[1] : {};
      return Q.questionsView(as(who), { ...(typeof o.view === "string" ? { view: o.view } : {}), ...(typeof o.id === "string" ? { id: o.id } : {}), ...(typeof o.from === "string" ? { from: o.from } : {}), ...(typeof o.pageChars === "number" && Number.isFinite(o.pageChars) ? { pageChars: o.pageChars } : {}) });
    },
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
    recordEntry: async (who, a) => {
      // A brain's own output the entry cites (tool:<seat>/<file>, trace:<sha256>)
      // is sealed first, through the job service, and the entry cites the
      // import it became: the ledger never rests on a file a seat can still write.
      const input = isObject(a[1]) ? (a[1] as Record<string, unknown>) : {};
      const sealed = await sealCitedRefs(hub.jobs?.(), who, input);
      if (!sealed.ok) return { ok: false, reason: sealed.reason };
      const res = await P.recordEntry(as(who), sealed.input as never);
      // A correction may take the ground from under a closed lead: it reopens.
      if (res.ok && res.entry.supersedes !== undefined) await L.reopenOnLedger(S).catch(() => undefined);
      return res.ok && sealed.notes.length ? { ...res, note: [res.note, ...sealed.notes].filter(Boolean).join("; ") } : res;
    },
    // The acts on the ledger are the hub's to write, as its entries are.
    // An attest's or a dispute's refs are sealed the same way.
    attestEntry: async (who, a) => {
      const sealed = await sealCitedRefs(hub.jobs?.(), who, isObject(a[1]) ? (a[1] as Record<string, unknown>) : {});
      return sealed.ok ? P.attestEntry(as(who), sealed.input as never) : { ok: false, reason: sealed.reason };
    },
    disputeEntry: async (who, a) => {
      const sealed = await sealCitedRefs(hub.jobs?.(), who, isObject(a[1]) ? (a[1] as Record<string, unknown>) : {});
      if (!sealed.ok) return { ok: false, reason: sealed.reason };
      const res = await P.disputeEntry(as(who), sealed.input as never);
      if (res.ok) await L.reopenOnLedger(S).catch(() => undefined);
      return res;
    },
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
    // Tool jobs (job-service.ts): who asks is the socket's seat, never an argument.
    jobSubmit: async (who, a) => {
      const svc = hub.jobs?.();
      if (!svc) return { ok: false, reason: NO_JOBS };
      const raw = isObject(a[1]) ? (a[1] as Record<string, unknown>) : {};
      const spec: Partial<JobSpec> = {
        kind: typeof raw.import === "string" && raw.import ? "import" : typeof raw.tool === "string" && raw.tool ? "tool" : "command",
        ...(typeof raw.import === "string" ? { source: raw.import } : {}),
        ...(typeof raw.tool === "string" ? { tool: raw.tool } : {}),
        ...(isObject(raw.args) ? { args: raw.args as Record<string, unknown> } : {}),
        ...(typeof raw.command === "string" ? { command: raw.command } : {}),
        // As said: left out (every object, by default), ["all"], or a list, possibly empty (job-scope.ts).
        ...(Array.isArray(raw.inputs) ? { inputs: raw.inputs.map(String) } : typeof raw.inputs === "string" ? { inputs: [raw.inputs] } : {}),
        timeout_seconds: typeof raw.timeout_seconds === "number" ? raw.timeout_seconds : 900,
        network: raw.network === "allowlist" ? "allowlist" : "off",
        ...(typeof raw.note === "string" ? { note: raw.note } : {}),
        ...(typeof raw.profile === "string" && raw.profile ? { profile: raw.profile } : {}),
        ...(Array.isArray(raw.net_grants) && raw.net_grants.length ? { net_grants: raw.net_grants.map(String) } : {}),
        ...(raw.independent === true ? { independent: true } : {}),
        // Every output sensitive at seal time (docs/adr/0016); anything but a boolean is refused by the service.
        ...(raw.secret_output !== undefined ? { secret_output: raw.secret_output as boolean } : {}),
      };
      // A job run under a lead: the lead must be the seat's own, checked
      // before the job is accepted, and the job goes on the lead's record.
      const refusedLead = await L.jobLeadAllowed(S, who, raw.lead);
      if (refusedLead) return { ok: false, reason: refusedLead };
      // Network grants a seat gives its job: each its own, asked for a job, not yet bound.
      if (spec.net_grants?.length) {
        const refusedGrants = await checkJobGrants(S, who, spec.net_grants);
        if (refusedGrants) return { ok: false, reason: refusedGrants };
      }
      const r = await svc.submit(who, spec, { watch: typeof raw.wait === "number" ? raw.wait : 0 });
      if (!r.ok) return r;
      const attached = r.job.requester.agent === who ? await L.attachJob(S, who, r.job.id, raw.lead).catch(() => null) : null;
      // The coverage hint at admission (A1): who else works these questions or these objects now.
      const coverage = r.job.requester.agent === who ? await L.jobAdmissionHint(S, who, attached?.ok ? attached.lead : raw.lead, r.job.spec.inputs ?? []).catch(() => null) : null;
      // Library visibility (docs/adr/0016): a command job that declared what it
      // reads is told which library tools say they read that kind of file. A hint.
      const library = r.job.spec.kind === "command" && scopeKindOf(r.job.spec) === "declared" ? await admissionHint(S, r.job.spec).catch(() => null) : null;
      return {
        ok: true,
        job: await shown(who, "jobSubmit", r.job),
        ...(attached?.ok && attached.lead ? { lead: attached.lead } : {}),
        ...(coverage ? { coverage: { ...coverage, note: "a hint: another seat works the same questions or objects now; overlap is not identity, so read what they have (leads, list_team) before you duplicate it" } } : {}),
        // The reuse hint (ADR 0017): other seats' same operation over the same objects, under way or committed.
        ...similarView(r.job.id, r.similar ?? [], r.job.spec.independent === true, r.similar_recorded !== false),
        ...(library ? { library } : {}),
      };
    },
    jobStatus: async (who, a) => {
      const svc = hub.jobs?.();
      if (!svc) return { ok: false, reason: NO_JOBS };
      const raw = isObject(a[1]) ? (a[1] as Record<string, unknown>) : {};
      const r = await svc.status(who, String(raw.job_id ?? ""), {
        ...(typeof raw.offset === "number" ? { offset: raw.offset } : {}),
        ...(typeof raw.limit === "number" ? { limit: raw.limit } : {}),
        ...(raw.cancel === true ? { cancel: true } : {}),
        ...(typeof raw.wait === "number" ? { wait: raw.wait } : {}),
      });
      if (!r.ok) return r;
      return { ok: true, job: await shown(who, "jobStatus", r.job, r.stdout), ...(r.stdout ? { stdout: r.stdout } : {}), ...(r.progress ? { progress: r.progress } : {}) };
    },
    catalogRequest: async (who, a) => {
      const svc = hub.jobs?.();
      if (!svc) return { ok: false, reason: NO_JOBS };
      const raw = isObject(a[1]) ? (a[1] as Record<string, unknown>) : {};
      const r = await svc.catalogRequest(who, String(raw.target ?? ""), typeof raw.recipe === "string" && raw.recipe ? raw.recipe : undefined, typeof raw.reason === "string" ? raw.reason : undefined);
      return r.ok ? { ok: true, job: await shown(who, "catalogRequest", r.job) } : r;
    },
    // The dynamic network (net-broker.ts, docs/adr/0012): who asks is the
    // socket's seat; a request is decided on the host and recorded before it
    // is answered; a fetch goes to the fetch service as this seat.
    netRequest: async (who, a) => {
      const raw = isObject(a[1]) ? (a[1] as Record<string, unknown>) : {};
      return requestAccess(S, who, raw, { jobs: Boolean(hub.jobs?.()), post: (args) => P.systemPost(S, args) });
    },
    netFetch: async (who, a) => {
      if (!hub.dir) return { ok: false, grant: null, reason: "this hub has no directory for the fetch service", note: "" };
      const raw = isObject(a[1]) ? (a[1] as Record<string, unknown>) : {};
      return fetchForSeat(S, hub.dir, who, raw);
    },
    netView: async (who, a) => {
      const raw = isObject(a[1]) ? (a[1] as Record<string, unknown>) : {};
      return netViewFor(S, who, typeof raw.view === "string" ? raw.view : "summary");
    },
    systemPost: (who, a) => {
      // The harness's voice, sent from inside a VM: said by the harness code
      // in that agent's VM, and the post says which one.
      const args = (a[1] as Record<string, unknown>) ?? {};
      return P.systemPost(S, { ...(args as { tag: string; body: string }), via: who });
    },
    threadJoin: (who, a) => P.threadJoin(as(who), String(a[1] ?? "")),
    threadOpen: (who, a) => P.threadOpen(as(who), a[1] as never),
    updateToolchainRecord: (who, a) => T.updateToolchainRecord(S, isObject(a[1]) ? { agent: who, inventory: a[1] as never } : undefined),
    // How long, and whether every post wakes it (a critic's or an
    // integrator's every_post: dropped here, a VM seat that asked to follow
    // the whole board slept through every post addressed to a peer). How
    // often the hub polls is the hub's (a guest's pollMs of 0 was a tight
    // loop of readdir on the hub's one event loop).
    waitForSwarmChange: (who, a, signal) => {
      const o = isObject(a[1]) ? (a[1] as { seconds?: unknown; everyPost?: unknown }) : {};
      // The lead register's news for this seat wakes its wait too (leads.ts).
      return P.waitForSwarmChange(as(who), { seconds: Number(o.seconds) || undefined, signal, ...(o.everyPost === true ? { everyPost: true } : {}), extraWake: L.leadsWaitCheck(as(who)) });
    },
  };
  return table;
}

export class Hub {
  readonly cfg: HubConfig;
  readonly roster: string[];
  /** Tool jobs in worker VMs, and the catalogue they update (job-service.ts). */
  jobService?: JobService;
  /** Whether the job service offers new objects to the derived catalogue (the kickoff's --no-derived-catalog says no). */
  private jobsDerived = false;
  /** The operator requests' outbox, reconciled and delivered one round at a time. */
  private requestsFiring: Promise<unknown> = Promise.resolve();
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
  /** When the run was paused (budget.json paused.at), read on every tick; null while it runs. */
  pausedAt: string | null = null;
  /** Per seat: when it was told it is over its own cap. */
  private seatSteer = new Map<string, number>();
  private doneSince = 0;
  private finished = false;
  /** The finish is over: the VMs put away (or not) and custody taken. */
  private finishDone = false;
  private finishing: Promise<void> | null = null;
  /** Takes this hub's way of writing the harness's lines back (stop). */
  private untraceHarness: () => void;

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
      jobs: () => this.jobService,
      accessed: (who, page) => this.noteApiPage(who, page),
      dir: this.cfg.dir,
    });
    this.collector = new CollectorLink(this.cfg.collector);
    // A ledger entry the harness authors while this hub serves the run (an
    // addition's external entry, a capture's, a hint's hypothesis) goes on
    // the trace as the hub's own line, as a seat's record through the hub does.
    this.untraceHarness = P.useHarnessTrace((_root, line) => this.event(line.tool, line.args, line.result), this.cfg.sandbox);
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
    const runsDir = this.runsDir();
    return Boolean(this.cfg.run && runsDir && (existsSync(join(runsDir, "notify", `${this.cfg.run}.cmd`)) || existsSync(join(runsDir, "notify", `${this.cfg.run}.targets`))));
  }

  /** The operator's runs directory: the registry's, else SWARM_RUNS_DIR. */
  private runsDir(): string {
    return this.cfg.registry ? dirname(resolve(this.cfg.registry)) : process.env.SWARM_RUNS_DIR || "";
  }

  /**
   * The operator requests' outbox (extensions/requests.ts), fired by the hub
   * itself: after every act that may open one (a lead closed needs_operator,
   * a clarification, a network refusal), on every round, and at start, the
   * committed records are reconciled into requests and each new one is
   * handed, by its ids only, to the operator's notification targets. One
   * round at a time; a failure is logged and the next round tries again.
   */
  fireRequests(): Promise<unknown> {
    const next = this.requestsFiring
      .then(async () => {
        const R = await import("../extensions/requests.ts");
        const dir = this.runsDir();
        const r = await R.fireRequests(this.cfg.sandbox, dir ? { runsDir: dir } : {});
        for (const rid of r.notified) await this.event("request_notified", { request: rid }, { ok: true });
      })
      .catch((err: Error) => this.log(`requests: ${err.message}`));
    this.requestsFiring = next;
    return next;
  }

  /** How the hub commits an addition: its job service's journal (the journal's one writer) and catalogue, when it runs one. */
  private additionOptions(): { journal?: import("./evidence-store.ts").Journal; catalogueOn?: boolean; catalogue?: (target: string, note: string) => Promise<{ ok: boolean; job?: string; reason?: string }> } {
    const svc = this.jobService;
    if (!svc) return {};
    return {
      journal: svc.journal,
      catalogueOn: this.jobsDerived || existsSync(join(this.cfg.sandbox, "catalog")),
      catalogue: async (target: string, note: string) => {
        const r = await svc.catalogRequest("system", target, undefined, note);
        return r.ok ? { ok: true, job: r.job.id } : { ok: false, reason: r.reason };
      },
    };
  }

  /**
   * Additions committed and not applied (a process that died after the
   * commit): what follows from each, applied now, once (scripts/material.ts
   * reconcileAdditions). On every round, at start, and when the CLI asks.
   */
  private async reconcileAdditions(): Promise<unknown[]> {
    const M = await import("./material.ts");
    return M.reconcileAdditions(this.cfg.sandbox, this.additionOptions()).catch((err: Error) => {
      this.log(`additions: ${err.message}`);
      return [];
    });
  }

  /**
   * The reverse sweeps of evidence added late (extensions/store-sweep.ts): a
   * pass of each that is not done, started in this process's background and
   * never awaited, so neither an addition nor the round waits on it; what a
   * pass leaves is searched by the next round's pass. Nothing is read while
   * every addition on the store journal is known swept whole.
   */
  private continueReverseSweeps(): void {
    const imports = this.jobService?.journal.of("evidence_added").map((l) => String(l.import ?? ""));
    if (imports && !imports.length) return;
    void import("../extensions/store-sweep.ts")
      .then((SW) => SW.reverseSweepInBackground(this.cfg.sandbox, imports ? { imports } : {}))
      .catch((err: Error) => this.log(`reverse sweeps: ${err.message}`));
  }

  /**
   * The coverage records' sweeps recorded under an older version of the
   * sweep's rules, read again under this harness's when the hub starts (a
   * kickoff, or a resume on a newer harness): extensions/store-sweep.ts
   * rereadSweeps, in the background and once; a line already under the
   * current rules is left alone. Its trace line is the hub's own (the
   * harness trace this hub registered), its board post the harness's.
   */
  private async rereadSweeps(): Promise<void> {
    try {
      const SW = await import("../extensions/store-sweep.ts");
      const r = await SW.rereadSweeps(this.cfg.sandbox);
      if (r.records.length) this.log(`store sweeps: ${r.records.length} read again under the sweep's rules version ${r.rules}; ${r.cleared.length} hold(s) cleared, ${r.added.length} added`);
    } catch (err) {
      this.log(`store sweeps read again: ${(err as Error).message}`);
    }
  }

  /**
   * Evidence added while no hub ran, or before its catalogue could take it:
   * a detect pass over each file, once (the store journal's
   * evidence_catalogue_queued line says it was queued).
   */
  private async catalogueAddedEvidence(): Promise<void> {
    const svc = this.jobService;
    if (!svc || !(this.jobsDerived || existsSync(join(this.cfg.sandbox, "catalog")))) return;
    const queued = new Set(svc.journal.of("evidence_catalogue_queued").map((l) => String(l.import)));
    for (const l of svc.journal.of("evidence_added")) {
      const id = String(l.import ?? "");
      if (!id || queued.has(id)) continue;
      const jobs: string[] = [];
      const refused: string[] = [];
      for (const f of (l.files as Array<{ path: string }> | undefined) ?? []) {
        const r = await svc.catalogRequest("system", `import:${id}/${f.path}`, undefined, `evidence added: import:${id}`).catch((err: Error) => ({ ok: false as const, reason: err.message }));
        if (r.ok) jobs.push(r.job.id);
        else refused.push(`${f.path}: ${r.reason}`);
      }
      await svc.journal.append({ type: "evidence_catalogue_queued", import: id, jobs, ...(refused.length ? { refused } : {}) });
    }
  }

  /** What a round of preparation said it could not do, each said once (the hub's log). */
  private readonly preparationSaid = new Set<string>();

  /**
   * The sources' broad extractions (scripts/preparation.ts): the receipts the
   * jobs and leads call for, the offers due, the leads whose extraction
   * reached an outcome closed. On every round, and once the job service is
   * up; one round at a time.
   */
  private preparationRound: Promise<void> | null = null;
  private async reconcilePreparation(): Promise<void> {
    const svc = this.jobService;
    if (!svc) return;
    if (this.preparationRound) return this.preparationRound;
    this.preparationRound = (async () => {
      const PREP = await import("./preparation.ts");
      const r = await PREP.reconcilePreparation(svc, this.cfg.sandbox);
      for (const n of r.notes) {
        if (this.preparationSaid.has(n)) continue;
        this.preparationSaid.add(n);
        this.log(`preparation: ${n}`);
      }
      if (r.opened.length) this.log(`preparation: offered ${r.opened.join(", ")}`);
      if (r.closed.length) this.log(`preparation: closed ${r.closed.join(", ")} (their extraction reached an outcome)`);
    })()
      .catch((err: Error) => this.log(`preparation: ${err.message}`))
      .finally(() => {
        this.preparationRound = null;
      });
    return this.preparationRound;
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
      const dir = this.runsDir();
      const child = spawn("bash", [script, this.cfg.sandbox, what, JSON.stringify(detail)], { detached: true, stdio: "ignore", timeout: NOTIFY_TIMEOUT_MS, env: { ...process.env, ...(dir ? { SWARM_RUNS_DIR: dir } : {}) } });
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
    // What a crash left committed and not yet applied or delivered to the operator: now.
    void this.reconcileAdditions().then(() => {
      this.continueReverseSweeps();
      return this.fireRequests();
    });
    // The kickoff's broad extractions: receipts for what it queued, offers for the rest.
    void this.reconcilePreparation();
    // Sweep lines recorded under an older version of the sweep's rules (a run resumed on a newer harness): read again under this one's.
    void this.rereadSweeps();
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
    this.jobsDerived = jobs.derived === true;
    this.jobService = new JobService({
      sandbox: S,
      run,
      ...(this.cfg.registry ? { registry: this.cfg.registry } : {}),
      image: jobs.image,
      ...(jobs.images ? { images: jobs.images } : {}),
      ...(jobs.packProfiles ? { packProfiles: jobs.packProfiles } : {}),
      workers: jobs.workers,
      workerCpus: jobs.cpus,
      workerMemoryMib: jobs.memoryMib,
      allowHosts: jobs.allowHosts,
      openNet: jobs.openNet,
      packDirs: jobs.packDirs,
      forging: this.cfg.forging === true,
      ...(jobs.minFreeMb !== undefined ? { minFreeMb: jobs.minFreeMb } : {}),
      ...(jobs.derived ? { derived: true } : {}),
      ...(jobs.derivedGenerations ? { derivedLimits: { generationsMax: jobs.derivedGenerations } } : {}),
      runWorker,
      destroyWorker,
      // `swarm.sh stop` writes .stop in this directory before it puts the
      // seats away: from then on no worker is started behind it.
      holding: () => existsSync(join(this.cfg.dir, ".stop")),
      // A running worker's CPU and I/O for the job's progress (B11); its heartbeat when msb cannot say.
      metrics: (worker) => workerMetrics(worker),
      hostRoom: async (mib) => roomForWorker(mib),
      notify: async (to, body) => {
        await P.systemPost(S, { tag: "result", to, body });
      },
      identity: async (agent) => {
        const r = (await P.readNames(S).catch(() => [])).find((n) => n.id === agent);
        return { ...(r?.name ? { name: r.name } : {}), ...(r?.doing ? { doing: r.doing } : {}) };
      },
      log: (line) => this.log(line),
      // A job's network grants, bound to it when its worker is made (net-broker.ts).
      netAccess: (job) => bindJobGrants(S, this.cfg.dir, job.id, job.requester.agent, job.spec.net_grants ?? []),
      // The lead each job was run under, for the reuse hints (job-reuse.ts).
      leadsOf: async (ids) => {
        const jobLead = L.foldLeads((await L.readLeadEvents(S)).events).jobLead;
        return new Map(ids.flatMap((id) => (jobLead.has(id) ? [[id, jobLead.get(id)!] as [string, string]] : [])));
      },
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
    // Its link to the collector closes below: a harness line written after it goes the CLI's way.
    this.untraceHarness();
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
      // An act that may have opened an operator request: the hub delivers it now.
      if (fn === "leadClose" || fn === "questionAsk" || fn === "netRequest") void this.fireRequests();
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

  /** The seats and models a substitution was told to the operator for, so each is told once. */
  private substitutionsTold = new Set<string>();

  /**
   * What the access record keeps between lines: the seat rows
   * already noted (a row sent again is not written twice), how many lines each
   * seat and job has, and the copies of a read that were kept under
   * tool-output/. Read from the trace the first time a row needs them, so a
   * hub brought back after a crash goes on where the last left off.
   */
  private accessSeen = new Set<string>();
  private accessCount = new Map<string, number>();
  private accessCopies = new Map<string, string>();
  private accessLoaded: Promise<void> | null = null;
  /** One row at a time: the counts and the dedupe above are read and written in order. */
  private accessChain: Promise<void> = Promise.resolve();

  private forwardTrace(agent: string, record: Record<string, unknown>): Promise<boolean> {
    // A seat's extension saw the provider answer with a model other than
    // the one asked for (model_reported, substituted): the operator is told,
    // once a seat and model, by its ids; the board has the words already.
    if (record.tool === "model_reported" && isObject(record.result) && record.result.answered === "substituted") {
      const key = `${agent} ${String(isObject(record.args) ? record.args.reported ?? "" : "")}`;
      if (!this.substitutionsTold.has(key)) {
        this.substitutionsTold.add(key);
        this.notify("model_substitution", { agent });
      }
    }
    const { token: _t, gate: _g, ...rest } = record;
    const token = this.cfg.tokens[agent];
    const line = `${JSON.stringify(token ? { ...rest, token } : rest)}\n`;
    return this.sendToCollector(line).then(async (ok) => {
      // The seat's row first, then the hub's note of what it names: the note
      // follows its row on the chain. A row the collector did not take comes
      // again, and is noted then.
      if (ok) await this.noteSensitiveAccess(agent, record);
      return ok;
    });
  }

  /**
   * The seat's row, looked at for the sensitive outputs it names. Never in
   * the seat's way: nothing is held, changed or refused, and a failure here
   * is the hub's to log, not the seat's to meet.
   */
  private noteSensitiveAccess(seat: string, record: Record<string, unknown>): Promise<void> {
    const tool = typeof record.tool === "string" ? record.tool : "";
    if (!ACCESS_TOOLS.has(tool) || !isObject(record.args)) return Promise.resolve();
    const probe = tool === "bash" || tool === "powershell" ? record.args.command : ["path", "filePath", "file_path", "file"].map((k) => (record.args as Record<string, unknown>)[k]).find((v) => typeof v === "string" && v.trim()) ?? "";
    if (typeof probe !== "string" || (probe && !ACCESS_PROBE.test(probe))) return Promise.resolve();
    const next = this.accessChain.then(async () => {
      const ix = await sensitiveIndex(this.cfg.sandbox);
      await this.loadAccessHistory();
      if (!ix.jobs.size && !this.accessCopies.size) return;
      const hits = classifyTraceRow({ tool, args: record.args }, ix, { sandbox: this.cfg.sandbox, copies: this.accessCopies });
      const row = { sid: typeof record.sid === "string" ? record.sid : undefined, seq: typeof record.seq === "number" ? record.seq : undefined, ts: typeof record.ts === "string" ? record.ts : undefined, tool };
      const kept = isObject(record.result) && isObject(record.result.full_output) && typeof record.result.full_output.path === "string" ? record.result.full_output.path : undefined;
      for (const hit of hits) await this.writeAccess(seat, hit, { row, ...(kept ? { kept } : {}) });
    });
    this.accessChain = next.catch(() => undefined);
    return next.catch((err: Error) => this.log(`sensitive access: ${err.message}`));
  }

  /** An API answer carried bytes of a job's output to a seat: noted when the job is sensitive. */
  private noteApiPage(seat: string, page: ApiPage): Promise<void> {
    const next = this.accessChain.then(async () => {
      const ix = await sensitiveIndex(this.cfg.sandbox);
      if (!ix.jobs.has(page.job)) return;
      await this.loadAccessHistory();
      await this.writeAccess(seat, apiPageHit(page.job, page.part, page.path), { api: { fn: page.fn, offset: page.offset, bytes: page.bytes, total: page.total } });
    });
    this.accessChain = next.catch(() => undefined);
    return next.catch((err: Error) => this.log(`sensitive access: ${err.message}`));
  }

  /** Read the lines this hub (or the hub before it) wrote, once: what is seen, counted and kept. */
  private loadAccessHistory(): Promise<void> {
    return (this.accessLoaded ??= (async () => {
      for (const file of [join(this.cfg.sandbox, P.EVENTS_REL), this.spillFile()]) {
        if (!existsSync(file)) continue;
        const lines = createInterface({ input: createReadStream(file, { encoding: "utf8" }), crlfDelay: Infinity });
        for await (const line of lines) {
          if (!line.includes('"tool":"sensitive_access"')) continue;
          let r: unknown;
          try {
            r = JSON.parse(line);
          } catch {
            continue;
          }
          if (!isObject(r) || r.agent !== "system" || r.tool !== "sensitive_access" || !isObject(r.args)) continue;
          const a = r.args;
          const seat = String(a.seat ?? "");
          const on = isObject(a.on) ? a.on : {};
          const job = typeof on.job === "string" ? on.job : "*";
          if (isObject(a.tool_row)) this.accessSeen.add(`${seat}\0${String(a.tool_row.sid)}\0${String(a.tool_row.seq)}\0${job}\0${String(a.via)}`);
          const bucket = `${seat}\0${job}`;
          this.accessCount.set(bucket, Math.max(this.accessCount.get(bucket) ?? 0, isObject(a.burst) ? ACCESS_BURST_MAX + 1 : (this.accessCount.get(bucket) ?? 0) + 1));
          if (isObject(r.result) && typeof r.result.kept_as === "string" && typeof on.job === "string") this.accessCopies.set(r.result.kept_as, on.job);
        }
      }
    })().catch((err: Error) => this.log(`sensitive access: history: ${err.message}`)));
  }

  /**
   * One line of the access record, as the harness's own on the trace. It
   * names the seat, the way the harness came to see it (`via`), how sure it
   * is (`certainty`), the sensitive job and the part reached, and points to
   * the row it was made from; never the value, a digest, or a range of bytes.
   */
  private async writeAccess(seat: string, hit: AccessHit, from: { row?: { sid?: string; seq?: number; ts?: string; tool: string }; api?: Record<string, unknown>; kept?: string }): Promise<void> {
    const job = hit.job;
    const row = from.row;
    if (row?.sid !== undefined && row.seq !== undefined) {
      const key = `${seat}\0${row.sid}\0${row.seq}\0${job ?? "*"}\0${hit.via}`;
      if (this.accessSeen.has(key)) return;
      this.accessSeen.add(key);
    }
    const bucket = `${seat}\0${job ?? "*"}`;
    const n = this.accessCount.get(bucket) ?? 0;
    if (n > ACCESS_BURST_MAX) return;
    this.accessCount.set(bucket, n + 1);
    const ix = job ? await sensitiveIndex(this.cfg.sandbox) : null;
    const on = { job, ...(hit.candidates ? { candidates: hit.candidates } : {}), part: hit.part, ...(job ? { why: ix?.jobs.get(job)?.sensitivity.why } : {}), paths: hit.paths };
    if (n === ACCESS_BURST_MAX) {
      await this.event("sensitive_access", { rules: ACCESS_RULES, seat, via: hit.via, certainty: hit.certainty, on: { job, part: hit.part }, burst: { after: ACCESS_BURST_MAX, note: "this seat's further accesses to this job are on the trace as the rows they come from; no more lines are written for the pair" } }, { ok: true });
      return;
    }
    await this.event(
      "sensitive_access",
      {
        rules: ACCESS_RULES,
        seat,
        via: hit.via,
        certainty: hit.certainty,
        on,
        ...(row ? { tool_row: { agent: seat, ...(row.sid !== undefined ? { sid: row.sid } : {}), ...(row.seq !== undefined ? { seq: row.seq } : {}), ...(row.ts ? { ts: row.ts } : {}), tool: row.tool } } : {}),
        ...(from.api ? { api: from.api } : {}),
      },
      { ok: true, ...(from.kept ? { kept_as: from.kept } : {}) },
    );
    // A whole output kept under tool-output/ holds what the call read: a later
    // read of that copy is the same access, and is noted as a `copy`.
    if (from.kept && job) this.accessCopies.set(from.kept, job);
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
    // A paused run's seats are held idle: a prompt would start a turn whose
    // model call the gateway then refuses. Only the words about the pause
    // itself, and the operator's wake after an extension, go through.
    if (this.pausedAt && !["stop_steer", "resume", "paused"].includes(options.kind ?? "")) return false;
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
        case "material": {
          // Evidence or material added by the operator: the hub is the store
          // journal's one writer while it runs (scripts/material.ts).
          const real = (x: string) => {
            try {
              return realpathSync(x);
            } catch {
              return resolve(x);
            }
          };
          if (typeof msg.sandbox === "string" && real(msg.sandbox) !== real(this.cfg.sandbox)) {
            this.reply(socket, { ok: false, reason: "this hub serves another run" }, true);
            return false;
          }
          const M = await import("./material.ts");
          const request = (isObject(msg.request) ? msg.request : {}) as never;
          const result = await M.admitMaterial(this.cfg.sandbox, request, this.additionOptions()).catch((err: Error) => ({ ok: false, reason: err.message }));
          this.reply(socket, result, true);
          void this.fireRequests();
          return false;
        }
        case "material_reconcile": {
          // What a crash left committed and not applied (swarm.sh evidence <run> list asks): applied by the journal's one writer.
          const real = (x: string) => {
            try {
              return realpathSync(x);
            } catch {
              return resolve(x);
            }
          };
          if (typeof msg.sandbox === "string" && real(msg.sandbox) !== real(this.cfg.sandbox)) {
            this.reply(socket, { ok: false, reason: "this hub serves another run" }, true);
            return false;
          }
          const applied = await this.reconcileAdditions();
          this.reply(socket, { ok: true, applied }, true);
          return false;
        }
        case "request_act": {
          // The operator's act on a request, from the host's CLI and console: the hub admits it while it runs, as it admits the question register's acts.
          const real = (x: string) => {
            try {
              return realpathSync(x);
            } catch {
              return resolve(x);
            }
          };
          if (typeof msg.sandbox === "string" && real(msg.sandbox) !== real(this.cfg.sandbox)) {
            this.reply(socket, { ok: false, reason: "this hub serves another run" }, true);
            return false;
          }
          const RC = await import("./requests-cli.ts");
          const result = await RC.admitRequestAct(this.cfg.sandbox, msg.rid, (isObject(msg.act) ? msg.act : {}) as never).catch((err: Error) => ({ ok: false, reason: err.message }));
          this.reply(socket, result, true);
          void this.fireRequests();
          return false;
        }
        case "requests_fire": {
          await this.fireRequests();
          this.reply(socket, { ok: true }, true);
          return false;
        }
        case "question":
        case "question_direct":
        case "question_deliver": {
          // The operator's acts on the question register, from the host's CLI
          // and console: the hub admits them, so it is the register's one
          // writer while it runs. The admin socket is in the hub's own 0700
          // directory, the host account's and never a VM's; a request for
          // another run's sandbox is refused.
          const real = (x: string) => {
            try {
              return realpathSync(x);
            } catch {
              return resolve(x);
            }
          };
          if (typeof msg.sandbox === "string" && real(msg.sandbox) !== real(this.cfg.sandbox)) {
            this.reply(socket, { ok: false, reason: "this hub serves another run" }, true);
            return false;
          }
          const QC = await import("./questions-cli.ts");
          const request = (isObject(msg.request) ? msg.request : {}) as never;
          const result = await (msg.op === "question"
            ? QC.admitOperatorAct(this.cfg.sandbox, request)
            : msg.op === "question_direct"
              ? QC.admitDirective(this.cfg.sandbox, request)
              : Q.deliverPending(this.cfg.sandbox).then((delivered) => ({ ok: true, delivered }))
          ).catch((err: Error) => ({ ok: false, reason: err.message }));
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
    // Additions committed and not applied, then the operator requests' round: what is committed and not yet written or delivered.
    await this.reconcileAdditions();
    this.continueReverseSweeps();
    await this.fireRequests();
    await this.catalogueAddedEvidence().catch((err: Error) => this.log(`catalogue of added evidence: ${err.message}`));
    // The sources' broad extractions: receipts, offers and closes due since the last round.
    await this.reconcilePreparation();
    // The dynamic network's round: grants whose lead closed or whose job
    // ended revoked, captures put on the ledger, contamination recorded.
    if (readCasePolicy(S).network !== "closed") {
      const svc = this.jobService;
      await netTick(S, (job) => {
        const j = svc?.jobs.get(job);
        return !j || j.state === "committed" || j.state === "failed" || j.state === "cancelled";
      }).catch((err: Error) => this.log(`net: ${err.message}`));
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
      await this.tellTokenAlerts(budget);
      await this.seatBackstop(budget, now);
      // A paused run: no seat is prompted (prompt() holds them) until the pause's cause is gone or the operator stops it.
      this.pausedAt = budget.paused?.at ?? null;
      // The operator is told of a pause once, whoever wrote it (claimPauseNotice: the watchdog may tell it first);
      // a spell of the provider's limit once, whatever the harness's tries within it.
      if (budget.paused) await this.tellPause(budget.paused);
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
      if (P.isPaused(budget)) return;
      const policy = P.stopPolicyOf(budget);
      if (!this.stopSteer) {
        this.stopSteer = { reason: pressure.reason, at: now };
        this.saveState();
        await P.markStopSteer(S, pressure.reason).catch(() => undefined);
        // The words follow the stop policy: a pause is announced as a pause, a stop as a stop.
        const text = P.capSteerText(budget, pressure);
        for (const agent of this.roster) this.prompt(agent, text, { deliver: "steer", kind: "stop_steer" });
        await this.event(pressure.reason === "cap" ? "cap_steer" : "wall_steer", { via: "hub", reason: pressure.reason, policy }, { ok: true });
      }
      if (now - this.stopSteer.at < P.STOP_GRACE_MS) return;
      const acted = await P.capAct(S, pressure.reason, `The hub ${policy === "cap-pause" ? "paused" : "stopped"} the swarm: ${pressure.reason} passed and the grace period ended.`);
      if (acted.kind === "paused" && acted.created) {
        this.pausedAt = new Date(now).toISOString();
        await this.event("run_paused", { via: "hub", reason: pressure.reason }, { ok: true });
        const paused = (await P.readBudget(S).catch(() => null))?.paused;
        if (paused) await this.tellPause(paused);
        await P.systemPost(S, { tag: "stop", body: `The run is paused (${pressure.reason === "cap" ? "its cap" : "its wall clock"}): no model call goes out until the operator extends it (swarm.sh extend) or stops it (swarm.sh stop). What the run holds stays as it is.` }).catch(() => undefined);
      } else if (acted.kind === "stopped" && acted.created) {
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
   * The operator's token marks (`--token-alert`) the run has crossed: each
   * told once (claimTokenAlerts holds the claim on disk and says it on the
   * board), on the trace and to the notify hook. Advisory: nothing pauses or
   * stops for it, under any stop policy.
   */
  private async tellTokenAlerts(budget: P.BudgetRecord): Promise<void> {
    const told = await P.claimTokenAlerts(this.cfg.sandbox, budget).catch((err: Error) => {
      this.log(`token alerts: ${err.message}`);
      return [] as Array<{ mark: number; tokens: number }>;
    });
    for (const t of told) {
      await this.event("token_alert", { via: "hub", mark: t.mark }, { ok: true, tokens: t.tokens, ...(budget.cap_tokens ? { cap_tokens: budget.cap_tokens } : {}) });
      this.notify("token_alert", { mark: t.mark, tokens: t.tokens, ...(budget.cap_tokens ? { cap_tokens: budget.cap_tokens } : {}) });
    }
  }

  /** Tell the operator of a pause, when this process claims its notice (the same words the watchdog would use: pauseNotice). */
  private async tellPause(paused: P.PauseRecord): Promise<void> {
    if (!(await P.claimPauseNotice(this.cfg.sandbox, P.pauseNoticeKey(paused)).catch(() => false))) return;
    const notice = P.pauseNotice(paused);
    if (notice) this.notify("paused", notice);
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
      // Exit 4 is custody done, with a check that did not pass: a verdict, not a failure to take one.
      const c = await new Promise<{ ok: boolean; adverse: boolean; out: string }>((done) => {
        execFile(process.execPath, ["--experimental-strip-types", "--no-warnings", custody, this.cfg.sandbox, "--run", this.cfg.run as string, "--timeout", String(timeoutSec)], { timeout: (timeoutSec + 300) * 1000, maxBuffer: 16 * 1024 * 1024 }, (err, stdout, stderr) => {
          const code = (err as (Error & { code?: unknown }) | null)?.code;
          done({ ok: !err || code === 4, adverse: code === 4, out: `${String(stdout).trim()} ${String(stderr).trim()}`.trim() });
        });
      });
      this.log(`custody: ${c.ok ? (c.adverse ? "done, with checks that did not pass" : "ok") : "failed"} ${c.out}`);
      await this.event("custody", { via: "hub" }, { ok: c.ok, ...(c.adverse ? { adverse: true } : {}), ...(c.ok ? {} : { error: c.out }) });
      this.copySpill();
      // The machine's draft of the report, sealed beside the verdict
      // (scripts/release.ts draft): here, so a run the hub ended has it
      // without waiting for an operator's stop, which then finds it. Its
      // record is the release and its line in the anchor, not the trace:
      // nothing is added after custody's own closing lines.
      const release = join(dirname(this.cfg.vmCli), "release.ts");
      if (c.ok && existsSync(release)) {
        const r = await new Promise<{ ok: boolean; out: string }>((done) => {
          execFile(
            process.execPath,
            ["--experimental-strip-types", "--no-warnings", release, "draft", this.cfg.sandbox, "--run", this.cfg.run as string, ...(this.cfg.registry ? ["--runs", dirname(resolve(this.cfg.registry))] : []), "--quiet"],
            { timeout: 15 * 60_000, maxBuffer: 16 * 1024 * 1024 },
            (err, stdout, stderr) => done({ ok: !err, out: `${String(stdout).trim()} ${String(stderr).trim()}`.trim() }),
          );
        });
        this.log(`release: ${r.ok ? "the draft is sealed" : "the draft was not written"} ${r.out}`);
      }
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
      return { created_sentinel: result.created_sentinel === true, reason: result.reason, ...(result.terminate === false ? { refused: true, abandon: result.abandon } : {}) };
    case "runFinishLine": {
      // The host's own run of the operator's checks for a seat's done: the
      // seat's finish_line line is its VM's word, this one is the harness's.
      const failed = Array.isArray(result.checks) ? (result.checks as Array<{ cmd?: unknown; ok?: unknown }>).filter((c) => c.ok !== true).map((c) => String(c.cmd ?? "")) : [];
      const gate = isObject(result.gate) ? result.gate : null;
      const gateDefects = gate && Array.isArray(gate.defects) ? (gate.defects as Array<{ code?: unknown; lead?: unknown; job?: unknown }>).map((d) => [d.code, d.lead, d.job].filter(Boolean).join(" ")) : [];
      return { total: result.total, passed: result.passed, ...(failed.length ? { failing: failed } : {}), ...(result.error ? { error: result.error } : {}), ...(gateDefects.length ? { gate_defects: gateDefects } : {}), ...(gate && Array.isArray(gate.limited) && gate.limited.length ? { limited: gate.limited } : {}), ...(gate?.error ? { gate_error: gate.error } : {}) };
    }
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
      // A revision held while the finish is assembled is not a refusal: said as deferred.
      if (result.quiet === true) return { ok: true, deferred: result.deferred ?? true };
      return { ok: result.ok, seq: entry.seq, merged: result.merged, ...(typeof entry.hash === "string" ? { hash: entry.hash } : {}) };
    }
    case "attestEntry":
    case "disputeEntry": {
      // The act's line hash, on the harness's own line, as an entry's is.
      const line = isObject(result.line) ? result.line : {};
      return { ok: result.ok, seq: line.seq, act: line.act, appended: result.appended, ...(typeof line.hash === "string" ? { hash: line.hash } : {}), ...(typeof line.target === "string" ? { target: line.target } : {}) };
    }
    case "leadOpen":
    case "leadClaim":
    case "leadRelease":
    case "leadClose":
    case "leadLink":
    case "leadReopen":
    case "routeReview":
    case "leadHandoff":
    case "leadConfirm": {
      // The lead's id, state and holder as the call left them, on the
      // harness's own line beside the register's chained event.
      const lead = isObject(result.lead) ? result.lead : {};
      return { ok: result.ok, lead: lead.id, status: lead.status, holder: lead.holder, generation: lead.generation, ...(lead.disposition ? { disposition: lead.disposition, ref: lead.ref } : {}), ...(result.reclaimed_from ? { reclaimed_from: result.reclaimed_from } : {}), ...(result.woke ? { woke: result.woke } : {}), ...(Array.isArray(result.confirmed) ? { confirmed: result.confirmed } : {}), ...(result.deferred ? { deferred: true } : {}) };
    }
    case "leadInterpret":
      return { ok: result.ok, interprets: result.interprets };
    case "questionOpen":
    case "questionAsk":
      // The question's id, revision and scope, and the register event's hash, beside the chained event.
      return { ok: result.ok, q: result.q, rev: result.rev, ...(result.scope ? { scope: result.scope } : {}), ...(result.clarify ? { clarify: result.clarify } : {}), ...(typeof result.hash === "string" ? { hash: result.hash } : {}), ...(result.duplicate ? { duplicate: true } : {}) };
    case "premisePropose":
      // The premise's id, revision and class, and the register event's hash, beside the chained event.
      return { ok: result.ok, p: result.p, rev: result.rev, class: result.class, ...(typeof result.hash === "string" ? { hash: result.hash } : {}) };
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
