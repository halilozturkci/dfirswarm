/**
 * The board, on this machine or on the other side of a VM's wall.
 *
 * On the host every pane shares one kernel, so the protocol's mutexes — an
 * exclusive mkdir, a rename, an O_APPEND — mean what they say, and each pane
 * calls `protocol.ts` directly on the files.
 *
 * An agent in a microVM reaches those files through virtio-fs, and between
 * VMs virtio-fs keeps none of those promises (measured in
 * spikes/microvm-smoke/shared-fs.sh: an O_EXCL-guarded counter lost 494 of
 * 600 increments, O_APPEND lost 495 of 600 lines, a reader missed a renamed
 * file 999 times in 1,000). So in a VM nothing writes the board's files
 * itself: every function here that reads or changes shared state is sent to
 * the hub on the host (scripts/vm-hub.ts), which runs the same `protocol.ts`
 * against the same files as the only writer, with the caller decided by the
 * channel the request arrived on rather than by anything in it.
 *
 * Which of the two happens is decided per call by `SWARM_BOARD_SOCKET`: set,
 * the call goes to the hub; unset, it runs here. The names and signatures are
 * `protocol.ts`'s own, so the extension imports them from here instead and
 * does not change at a single call site.
 */

import { randomUUID } from "node:crypto";
import { readFile } from "node:fs/promises";
import { connect, type Socket } from "node:net";
import * as P from "./protocol.ts";
import * as T from "./toolchain.ts";

/** Where the hub listens, as the VM sees it; unset on the host. */
export function boardSocket(env: NodeJS.ProcessEnv = process.env): string {
  return env.SWARM_BOARD_SOCKET || "";
}

/** A call that has not answered in this long is not going to. */
const CALL_TIMEOUT_MS = 120_000;
/** One reply line, however large a result (an inbox page, a ledger) gets. */
const MAX_REPLY_BYTES = 256 * 1024 * 1024;
/** A part of a transfer the hub has not acknowledged in this long: the link is dead. */
const PART_TIMEOUT_MS = 30_000;

/** The hub said no, or could not be reached. The message is the hub's own. */
export class BoardError extends Error {
  readonly unreachable: boolean;
  constructor(message: string, unreachable = false) {
    super(message);
    this.name = "BoardError";
    this.unreachable = unreachable;
  }
}

/** A connect the bridge's queue turned away, or a bridge not up yet: nothing was sent. */
function refused(err: unknown): boolean {
  const code = (err as { code?: string } | null)?.code;
  return code === "EAGAIN" || code === "ECONNREFUSED" || code === "ENOENT";
}

/** A call waiting for its answer, on the link it was sent on. `answered` stops its clock once the hub has answered, even if the answer is still to be fetched. */
type Pending = { fn: string; socket: Socket; answered: () => void; resolve: (value: unknown) => void; reject: (err: Error) => void };

/** Calls that change the board, sent once more with the same request id when a link drops. */
const RETRIED = new Set(["postMessage", "systemPost", "recordEntry", "threadOpen", "claimName", "markDone", "publishFile", "forgeTool", "recordFileVersion", "jobSubmit", "catalogRequest", "jobStatus"]);

/** Timings a test shortens; the defaults are the run's. */
export type HubClientTimings = { partTimeoutMs?: number; writeStallMs?: number };
let clientTimings: HubClientTimings = {};
/** Set the transfer timings of connections opened from now on (tests). */
export function setHubClientTimings(timings: HubClientTimings): void {
  clientTimings = { ...timings };
}

/**
 * One held connection to the hub per process, carrying every board call:
 * each request has an id, each answer names it, and they come back in the
 * order they finish. A VM that opened a connection per call lost a quarter of
 * them under load — the vsock path refused 20 of 80 concurrent connects
 * (measured) — and a held connection is also what lets a `wait` be
 * cancelled without closing anything else.
 *
 * Nothing large goes as one line. A call whose request is past
 * P.TRANSFER_PART_BYTES (a file's bytes, recorded or published) is uploaded
 * first in parts, one part on the link at a time (P.TransferLane), and then
 * sent naming the upload; an answer past it is fetched the same way. One
 * write of about 262 KB stalled the vsock path for good, and the calls behind
 * it on the same connection (the liveness check among them) never reached
 * the hub; no line here is past P.WIRE_LINE_MAX, and one that would be is
 * refused by name instead. A link that stops carrying data is closed and
 * replaced: a call that timed out, a part not answered, or queued writes
 * that have not moved (P.watchWriteStall). The calls pending on it fail as
 * "link closed", and the ones that change the board are sent again with
 * their request id.
 */
class HubClient {
  private socket: Socket | null = null;
  private opening: Promise<Socket> | null = null;
  private pending = new Map<number, Pending>();
  private lanes = new WeakMap<Socket, P.TransferLane>();
  private next = 1;
  private buffer = "";
  private readonly path: string;

  constructor(path: string) {
    this.path = path;
  }

  private open(): Promise<Socket> {
    if (this.socket && !this.socket.destroyed) return Promise.resolve(this.socket);
    if (this.opening) return this.opening;
    this.opening = (async () => {
      const deadline = Date.now() + 10_000;
      for (let attempt = 0; ; attempt++) {
        try {
          const socket = await new Promise<Socket>((resolve, reject) => {
            const s = connect(this.path);
            s.once("connect", () => resolve(s));
            s.once("error", reject);
          });
          this.attach(socket);
          return socket;
        } catch (err) {
          if (!refused(err) || Date.now() > deadline) throw new BoardError(`the hub is unreachable: ${(err as Error).message}`, true);
          await new Promise((r) => setTimeout(r, Math.min(25 * 2 ** attempt, 500)));
        }
      }
    })().finally(() => {
      this.opening = null;
    });
    return this.opening;
  }

  private attach(socket: Socket): void {
    this.socket = socket;
    this.buffer = "";
    socket.setEncoding("utf8");
    socket.unref();
    P.watchWriteStall(socket, clientTimings.writeStallMs);
    const lane = new P.TransferLane(socket, clientTimings.partTimeoutMs ?? PART_TIMEOUT_MS, (message, lost) => new BoardError(message, lost));
    this.lanes.set(socket, lane);
    // The seat's token first, before any call: the hub serves nothing else
    // on a seat's socket until it has it (P.seatAuthLine).
    const auth = P.seatAuthLine();
    if (auth) socket.write(auth);
    socket.on("data", (chunk: string) => {
      this.buffer += chunk;
      if (this.buffer.length > MAX_REPLY_BYTES) {
        socket.destroy(new Error("an answer past the limit"));
        return;
      }
      let cut;
      while ((cut = this.buffer.indexOf("\n")) >= 0) {
        const line = this.buffer.slice(0, cut);
        this.buffer = this.buffer.slice(cut + 1);
        let msg: { t?: string; id?: number | string; ok?: boolean; result?: unknown; error?: string; download?: P.TransferRef };
        try {
          msg = JSON.parse(line);
        } catch {
          continue;
        }
        if (lane.take(msg as P.PartAnswer)) continue;
        const call = typeof msg.id === "number" ? this.pending.get(msg.id) : undefined;
        if (!call) continue;
        this.pending.delete(msg.id as number);
        call.answered();
        if (msg.download && typeof msg.download.id === "string") {
          // The answer is kept on the hub: fetched in parts, then settled as
          // if it had come in this line.
          void lane.download(msg.download).then(
            (bytes) => {
              let reply: { ok?: boolean; result?: unknown; error?: string };
              try {
                reply = JSON.parse(bytes.toString("utf8"));
              } catch {
                call.reject(new BoardError(`${call.fn}: the answer fetched in parts is not JSON`, true));
                return;
              }
              if (reply.ok) call.resolve(reply.result);
              else call.reject(new BoardError(reply.error || `${call.fn} failed on the hub`));
            },
            (err: Error) => call.reject(err),
          );
          continue;
        }
        if (msg.ok) call.resolve(msg.result);
        else call.reject(new BoardError(msg.error || `${call.fn} failed on the hub`));
      }
    });
    // Only this link's calls and parts: a link replaced while the old one
    // was still closing already carries calls of its own.
    const lost = () => {
      if (this.socket === socket) this.socket = null;
      for (const [id, call] of this.pending) {
        if (call.socket !== socket) continue;
        this.pending.delete(id);
        call.reject(new BoardError(`the hub link closed during ${call.fn}`, true));
      }
      lane.fail("the hub link closed during a transfer");
    };
    socket.on("close", lost);
    socket.on("error", () => undefined);
  }

  /** Close this link so the next call opens another: it stopped answering. */
  private drop(socket: Socket, why: string): void {
    if (!socket.destroyed) socket.destroy(new Error(why));
  }

  /**
   * A call that changes the board, sent again when the link closed before
   * its answer came: the same request id goes with it, and the hub answers a
   * request id it has already run with that run's answer. A reply lost on a
   * dropped link is otherwise a model's cue to post again, and the board
   * gets the post twice.
   */
  async call(fn: string, args: unknown[], options: { timeoutMs?: number; signal?: AbortSignal } = {}): Promise<unknown> {
    if (!RETRIED.has(fn)) return this.callOnce(fn, args, options);
    const rid = randomUUID();
    for (let attempt = 0; ; attempt++) {
      try {
        return await this.callOnce(fn, args, options, rid);
      } catch (err) {
        const lost = err instanceof BoardError && err.unreachable && /link closed/.test(err.message);
        if (!lost || attempt >= 3 || options.signal?.aborted) throw err;
        await new Promise((r) => setTimeout(r, 250 * (attempt + 1)));
      }
    }
  }

  private async callOnce(fn: string, args: unknown[], options: { timeoutMs?: number; signal?: AbortSignal }, rid?: string): Promise<unknown> {
    if (options.signal?.aborted) throw new BoardError("aborted");
    const socket = await this.open();
    const lane = this.lanes.get(socket);
    if (!lane) throw new BoardError(`the hub link closed during ${fn}`, true);
    const id = this.next++;
    const timeoutMs = options.timeoutMs ?? CALL_TIMEOUT_MS;
    const argsText = JSON.stringify(args.map((a) => (a === undefined ? null : a)));
    const head = `{"t":"rpc","id":${id},"fn":${JSON.stringify(fn)}${rid ? `,"rid":${JSON.stringify(rid)}` : ""}`;
    let line = `${head},"args":${argsText}}\n`;
    if (Buffer.byteLength(line) > P.TRANSFER_PART_BYTES) {
      const upload = await lane.upload(Buffer.from(argsText, "utf8"));
      line = `${head},"argsUpload":${JSON.stringify(upload)}}\n`;
    }
    // Refused here, by name, rather than written: a line this large would
    // stall the link and every call behind it.
    try {
      P.wireChecked(line, `a ${fn} call`);
    } catch (err) {
      throw new BoardError((err as Error).message);
    }
    if (socket.destroyed) throw new BoardError(`the hub link closed during ${fn}`, true);
    return new Promise((resolve, reject) => {
      const done = () => {
        clearTimeout(timer);
        options.signal?.removeEventListener("abort", onAbort);
      };
      const timer = setTimeout(() => {
        this.pending.delete(id);
        done();
        // No answer in time is a link that stopped carrying one: it is
        // closed, so the next call does not queue behind whatever holds it.
        this.drop(socket, `${fn} not answered`);
        reject(new BoardError(`the hub did not answer ${fn} within ${Math.round(timeoutMs / 1000)}s; the link closed and a new one opens`, true));
      }, timeoutMs);
      const onAbort = () => {
        this.pending.delete(id);
        done();
        try {
          socket.write(P.wireLine({ t: "cancel", id }));
        } catch {
          // the link is gone, and the call with it
        }
        reject(new BoardError("aborted"));
      };
      options.signal?.addEventListener("abort", onAbort);
      this.pending.set(id, {
        fn,
        socket,
        // Answered: an answer still to be fetched is timed by its parts.
        answered: () => clearTimeout(timer),
        resolve: (value) => {
          done();
          resolve(value);
        },
        reject: (err) => {
          done();
          reject(err);
        },
      });
      socket.write(line);
    });
  }

  close(): void {
    this.socket?.destroy();
    this.socket = null;
  }
}

const clients = new Map<string, HubClient>();

/**
 * One board call on the process's held connection to the hub at
 * `socketPath`. `undefined` arguments travel as null, and the hub turns them
 * back, so a default parameter still applies.
 */
export function callBoard(
  socketPath: string,
  fn: string,
  args: unknown[],
  options: { timeoutMs?: number; signal?: AbortSignal } = {},
): Promise<unknown> {
  let client = clients.get(socketPath);
  if (!client) {
    client = new HubClient(socketPath);
    clients.set(socketPath, client);
  }
  return client.call(fn, args, options);
}

/** Close every held connection (tests; a process that is about to exit). */
export function closeBoardClients(): void {
  for (const c of clients.values()) c.close();
  clients.clear();
}

// eslint-disable-next-line @typescript-eslint/no-explicit-any
type AnyFn = (...args: any[]) => Promise<any>;

function remote<F extends AnyFn>(name: string, local: F): F {
  return (async (...args: Parameters<F>) => {
    const socket = boardSocket();
    if (!socket) return local(...args);
    return callBoard(socket, name, args);
  }) as F;
}

/**
 * Every function the hub answers. The hub keeps its own table of the same
 * names (scripts/vm-hub.ts), and a test holds the two to each other.
 */
export const REMOTE_FUNCTIONS = [
  "applySessionUsage",
  "catalogRequest",
  "claimFile",
  "claimName",
  "correctionsAfter",
  "fileDiff",
  "forgeTool",
  "forgedToolSeal",
  "guardWrite",
  "heldBy",
  "jobStatus",
  "jobSubmit",
  "listClaims",
  "listFileHistory",
  "listForgedTools",
  "listLedger",
  "listTeam",
  "markDone",
  "nameOf",
  "postMessage",
  "publishFile",
  "readBudget",
  "readBudgetStatus",
  "readInbox",
  "readNames",
  "recordEntry",
  "recordFileVersion",
  "releaseAllOwned",
  "releaseFile",
  "restoreFileVersion",
  "swarmDoneExists",
  "systemPost",
  "threadJoin",
  "threadOpen",
  "updateToolchainRecord",
  "waitForSwarmChange",
] as const;

export const applySessionUsage = remote("applySessionUsage", P.applySessionUsage);

/**
 * Tool jobs, run by the hub's job service in worker VMs. A host run has no
 * hub and no job service: the local answer says so.
 */
type JobAnswer = { ok: boolean; reason?: string; job?: Record<string, unknown>; stdout?: { offset: number; bytes: number; total: number; text: string; next: number | null; path: string } };
const noJobService = async (): Promise<JobAnswer> => ({ ok: false, reason: "this run has no job service (a host run): run the work in your own shell" });
export const jobSubmit = remote("jobSubmit", noJobService as (sandboxRoot: string, spec: Record<string, unknown>) => Promise<JobAnswer>);
export const jobStatus = remote("jobStatus", noJobService as (sandboxRoot: string, o: Record<string, unknown>) => Promise<JobAnswer>);
export const catalogRequest = remote("catalogRequest", noJobService as (sandboxRoot: string, o: Record<string, unknown>) => Promise<JobAnswer>);
export const claimFile = remote("claimFile", P.claimFile);
export const claimName = remote("claimName", P.claimName);
/**
 * The harness's own: the swarm's stop clock and the harness stop. On the
 * host the extension runs them itself; in a VM they are the hub's alone
 * (scripts/vm-hub.ts), and the extension does not call them there.
 */
export const clearStopSteer = P.clearStopSteer;
export const correctionsAfter = remote("correctionsAfter", P.correctionsAfter);
/**
 * The bytes of a file in this seat's own directory, for the hub, which does
 * not open a file under a directory a running seat can rearrange (a
 * directory swapped for a link between its checks and its open would read
 * the operator's files). Past the store limit only the hash and size go;
 * `missing` when there is no such file. Undefined for a path outside this
 * seat's own directories: the hub reads those itself.
 */
export async function ownFileWire(
  sandboxRoot: string,
  rawPath: string,
  agentId: string,
  limit = P.HISTORY_STORE_MAX_BYTES,
): Promise<OwnFileWire | undefined> {
  // A path that leaves the run (a link out of it) is refused here as on the
  // host: the error is the protocol's own.
  const pathKey = await P.realPathKey(sandboxRoot, rawPath);
  if (!P.isOwnScratch(pathKey, agentId)) return undefined;
  try {
    const read = await P.readSandboxFile(sandboxRoot, pathKey, { maxBytes: limit });
    if (!read) return { missing: true };
    return { bytes_b64: read.bytes.toString("base64") };
  } catch (err) {
    if (!(err instanceof P.FileTooLarge)) throw err;
  }
  const hashed = await P.hashSandboxFile(sandboxRoot, pathKey);
  return hashed ? { hash_only: { sha256: hashed.sha256, bytes: hashed.bytes } } : { missing: true };
}

export type OwnFileWire = { bytes_b64?: string; hash_only?: { sha256: string; bytes: number }; missing?: true };

export const recordFileVersion: typeof P.recordFileVersion = async (sandboxRoot, rawPath, agentId, options = {}) => {
  const socket = boardSocket();
  if (!socket) return P.recordFileVersion(sandboxRoot, rawPath, agentId, options);
  const wire = options.bytes ? { bytes_b64: options.bytes.toString("base64") } : await ownFileWire(sandboxRoot, rawPath, agentId);
  return (await callBoard(socket, "recordFileVersion", [sandboxRoot, rawPath, agentId, wire ?? null])) as Awaited<ReturnType<typeof P.recordFileVersion>>;
};

/** What a VM may publish in one call: its bytes cross the hub link. */
export const PUBLISH_MAX_BYTES = P.HISTORY_STORE_MAX_BYTES;

export const publishFile: typeof P.publishFile = async (ctx, fromRaw, toRaw, options = {}) => {
  const socket = boardSocket();
  if (!socket) return P.publishFile(ctx, fromRaw, toRaw, options);
  let wire: OwnFileWire | undefined;
  try {
    wire = await ownFileWire(ctx.sandboxRoot, fromRaw, ctx.agentId, PUBLISH_MAX_BYTES);
  } catch (err) {
    return { ok: false, reason: (err as Error).message };
  }
  if (!wire) return { ok: false, reason: `publish takes a file of your own: ${fromRaw} is not under work/${ctx.agentId}/, work/extracted/${ctx.agentId}/ or work/quarantine/${ctx.agentId}/`, path: fromRaw };
  if (wire.missing) return { ok: false, reason: `no such file: ${fromRaw}`, path: fromRaw };
  if (wire.hash_only) {
    return { ok: false, reason: `${fromRaw} is ${wire.hash_only.bytes} bytes; a VM publishes up to ${PUBLISH_MAX_BYTES}. Leave it in your own directory and name its path in the report.`, path: fromRaw };
  }
  return (await callBoard(socket, "publishFile", [ctx, fromRaw, toRaw ?? null, wire])) as Awaited<ReturnType<typeof P.publishFile>>;
};

export const fileDiff: typeof P.fileDiff = async (sandboxRoot, rawPath, fromRef, toRef, options = {}) => {
  const socket = boardSocket();
  if (!socket) return P.fileDiff(sandboxRoot, rawPath, fromRef, toRef, options);
  // The bytes on disk go with the call whenever a side is the disk (the
  // default right side is): the hub uses them for a file in a seat's own
  // directory, which it does not open, and its own read for any other.
  let disk: { disk_b64?: string; missing?: true } | null = null;
  if (fromRef === undefined || toRef === undefined || P.isDiskRef(fromRef) || P.isDiskRef(toRef)) {
    try {
      const read = await P.readSandboxFile(sandboxRoot, rawPath, { maxBytes: P.DIFF_MAX_BYTES });
      disk = read ? { disk_b64: read.bytes.toString("base64") } : { missing: true };
    } catch (err) {
      if (err instanceof P.FileTooLarge) throw new Error(`${rawPath} is too large to diff (${err.size} bytes; the limit is ${P.DIFF_MAX_BYTES})`);
      throw err;
    }
  }
  return (await callBoard(socket, "fileDiff", [sandboxRoot, rawPath, fromRef ?? null, toRef ?? null, disk])) as Awaited<ReturnType<typeof P.fileDiff>>;
};

/**
 * A file of this seat's own is restored here, in its VM: the hub does not
 * write under a directory a running seat can rearrange, and a write made by
 * the host would meet this guest's cached view of the file for five seconds.
 * The revision's bytes are read from history/ on the run's floor and checked
 * against the hash the hub recorded, waiting out the same cache for a
 * revision recorded a moment ago. Anything else is the hub's to restore.
 */
export const restoreFileVersion: typeof P.restoreFileVersion = async (ctx, rawPath, rev) => {
  const socket = boardSocket();
  if (!socket) return P.restoreFileVersion(ctx, rawPath, rev);
  const pathKey = await P.realPathKey(ctx.sandboxRoot, rawPath);
  if (!P.isOwnScratch(pathKey, ctx.agentId)) {
    return (await callBoard(socket, "restoreFileVersion", [ctx, rawPath, rev])) as Awaited<ReturnType<typeof P.restoreFileVersion>>;
  }
  const guard = (await callBoard(socket, "guardWrite", [ctx, pathKey])) as P.GuardResult;
  if (!guard.ok) return { ok: false, path: pathKey, rev, reason: guard.reason };
  const versions = (await callBoard(socket, "listFileHistory", [ctx.sandboxRoot, pathKey])) as P.FileVersion[];
  const version = versions.find((v) => v.rev === rev);
  if (!version) return { ok: false, path: pathKey, rev, reason: `no history rev ${rev}` };
  if (version.stored === false) return { ok: false, path: pathKey, rev, reason: `${pathKey} rev ${rev} was recorded by its hash only; its bytes were not kept` };
  const src = P.historyRevisionPath(ctx.sandboxRoot, pathKey, rev);
  let bytes: Buffer | null = null;
  const deadline = Date.now() + P.GUEST_CACHE_WAIT_MS;
  for (;;) {
    const got = await readFile(src).catch(() => null);
    if (got && P.sha256Hex(got) === version.sha256) {
      bytes = got;
      break;
    }
    if (Date.now() > deadline) break;
    await new Promise((r) => setTimeout(r, 250));
  }
  if (!bytes) return { ok: false, path: pathKey, rev, reason: `rev ${rev} of ${pathKey} is not readable from history/ in this VM yet; try again in a few seconds` };
  await recordFileVersion(ctx.sandboxRoot, pathKey, ctx.agentId);
  try {
    await P.writeSandboxFile(ctx.sandboxRoot, pathKey, bytes);
  } catch (err) {
    return { ok: false, path: pathKey, rev, reason: (err as Error).message };
  }
  const landed = await recordFileVersion(ctx.sandboxRoot, pathKey, ctx.agentId, { bytes });
  return { ok: true, path: pathKey, rev, landed_rev: landed?.rev ?? null, sha256: version.sha256 };
};
export const forgeTool = remote("forgeTool", P.forgeTool);
export const forgedToolSeal = remote("forgedToolSeal", P.forgedToolSeal);
export const guardWrite = remote("guardWrite", P.guardWrite);
export const harnessStop = P.harnessStop;
export const heldBy = remote("heldBy", P.heldBy);
export const listClaims = remote("listClaims", P.listClaims);
export const listFileHistory = remote("listFileHistory", P.listFileHistory);
export const listForgedTools = remote("listForgedTools", P.listForgedTools);
export const listLedger = remote("listLedger", P.listLedger);
export const listTeam = remote("listTeam", P.listTeam);
export const markDone = remote("markDone", P.markDone);
export const markStopSteer = P.markStopSteer;
export const nameOf = remote("nameOf", P.nameOf);
export const postMessage = remote("postMessage", P.postMessage);
export const readBudget = remote("readBudget", P.readBudget);
/**
 * How long the liveness check waits for the hub. Past it the link is closed
 * and replaced (a timed-out call drops its link), well inside the minute
 * after which a seat is steered as cut off from the hub.
 */
export const LIVENESS_TIMEOUT_MS = 20_000;
/** The budget, read as the liveness check reads it: in a VM with a short deadline, so a dead link is found and replaced. */
export async function readBudgetLive(sandboxRoot: string): Promise<P.BudgetRecord> {
  const socket = boardSocket();
  if (!socket) return P.readBudget(sandboxRoot);
  return (await callBoard(socket, "readBudget", [sandboxRoot], { timeoutMs: LIVENESS_TIMEOUT_MS })) as P.BudgetRecord;
}
export const readBudgetStatus = remote("readBudgetStatus", P.readBudgetStatus);
export const readInbox = remote("readInbox", P.readInbox);
export const readNames = remote("readNames", P.readNames);
export const recordEntry = remote("recordEntry", P.recordEntry);
export const releaseAllOwned = remote("releaseAllOwned", P.releaseAllOwned);
export const releaseFile = remote("releaseFile", P.releaseFile);
export const swarmDoneExists = remote("swarmDoneExists", P.swarmDoneExists);
export const systemPost = remote("systemPost", P.systemPost);
export const threadJoin = remote("threadJoin", P.threadJoin);
export const threadOpen = remote("threadOpen", P.threadOpen);
export const updateToolchainRecord = remote("updateToolchainRecord", T.updateToolchainRecord);

/**
 * `wait` holds its call open for up to five minutes, and an AbortSignal does
 * not cross a socket: the signal closes the connection instead, and the hub
 * ends the wait it was running for it.
 */
export const waitForSwarmChange: typeof P.waitForSwarmChange = async (ctx, options = {}) => {
  const socket = boardSocket();
  if (!socket) return P.waitForSwarmChange(ctx, options);
  const { signal, ...rest } = options;
  const seconds = Math.min(Math.max(1, Math.round(rest.seconds ?? 60)), P.WAIT_MAX_SECONDS);
  const started = Date.now();
  try {
    return (await callBoard(socket, "waitForSwarmChange", [ctx, rest], {
      signal,
      timeoutMs: seconds * 1000 + 60_000,
    })) as P.WaitResult;
  } catch (err) {
    // What the local wait answers when it is aborted, so the caller cannot tell the two apart.
    if (signal?.aborted) return { reason: "timeout", waited_ms: Date.now() - started, detail: "Wait aborted." };
    throw err;
  }
};

/**
 * The harness's side of the conversation: what it tells this agent (a nudge,
 * the kickoff's follow-ups, a stop) and what this agent tells it (working or
 * idle). On the host that is Herdr, which types into the pane and reads the
 * screen; a VM's pane runs `msb exec`, which Herdr cannot see into, so the
 * hub keeps one connection per agent open for it.
 */
export type HubPrompt = { t: "prompt"; text: string; kind?: string; deliver?: "steer" | "followUp" };

export type HubLink = {
  state(state: "working" | "idle" | "blocked", detail?: string): void;
  close(): void;
};

export function openHubLink(
  socketPath: string,
  onPrompt: (prompt: HubPrompt) => void,
  options: { retryMs?: number } = {},
): HubLink {
  let socket: ReturnType<typeof connect> | null = null;
  let closed = false;
  let last: { state: string; detail?: string } | null = null;
  let timer: ReturnType<typeof setTimeout> | null = null;
  const retryMs = options.retryMs ?? 2000;
  // Prompts are handed on in the order they came: one being fetched in
  // parts holds back the ones behind it.
  let delivering: Promise<void> = Promise.resolve();
  let fetching = 0;
  const deliver = (prompt: HubPrompt) => {
    try {
      onPrompt(prompt);
    } catch {
      // the receiver's own failure; the link goes on
    }
  };

  const send = (body: unknown) => {
    try {
      if (socket && !socket.destroyed) socket.write(P.wireLine(body));
    } catch {
      // the next connection says it again
    }
  };

  const open = () => {
    if (closed) return;
    let buffer = "";
    const s = connect(socketPath);
    socket = s;
    s.setEncoding("utf8");
    P.watchWriteStall(s, clientTimings.writeStallMs);
    const lane = new P.TransferLane(s, clientTimings.partTimeoutMs ?? PART_TIMEOUT_MS);
    s.on("connect", () => {
      // The link says hello with the seat's token (SWARM_SEAT_TOKEN), which
      // the hub takes as this connection's authentication.
      const token = process.env.SWARM_SEAT_TOKEN;
      send(token ? { t: "hello", token } : { t: "hello" });
      if (last) send({ t: "state", ...last });
    });
    s.on("data", (chunk: string) => {
      buffer += chunk;
      let cut;
      while ((cut = buffer.indexOf("\n")) >= 0) {
        const line = buffer.slice(0, cut);
        buffer = buffer.slice(cut + 1);
        let message: (Partial<HubPrompt> & { download?: P.TransferRef }) | null;
        try {
          message = JSON.parse(line);
        } catch {
          continue;
        }
        if (lane.take(message as P.PartAnswer)) continue;
        if (!message || message.t !== "prompt") continue;
        const { download, ...words } = message;
        if (download && typeof download.id === "string") {
          // Words past a part's size are kept by the hub and fetched here in
          // parts. A link that drops first gets them again on its next hello.
          fetching++;
          delivering = delivering.then(async () => {
            try {
              const text = (await lane.download(download)).toString("utf8");
              deliver({ ...words, t: "prompt", text });
            } catch {
              s.destroy();
            } finally {
              fetching--;
            }
          });
          continue;
        }
        if (typeof words.text !== "string") continue;
        const prompt = words as HubPrompt;
        if (fetching === 0) deliver(prompt);
        else delivering = delivering.then(() => deliver(prompt));
      }
    });
    const again = () => {
      if (closed || timer) return;
      timer = setTimeout(() => {
        timer = null;
        open();
      }, retryMs);
      timer.unref?.();
    };
    s.on("error", again);
    s.on("close", () => {
      lane.fail("the hub link closed");
      again();
    });
    s.unref?.();
  };
  open();

  return {
    state(state, detail) {
      const next = { state, ...(detail ? { detail } : {}) };
      // Refused here, by name, rather than written past the line limit.
      P.wireLine({ t: "state", ...next }, "a state line");
      last = next;
      send({ t: "state", ...last });
    },
    close() {
      closed = true;
      if (timer) clearTimeout(timer);
      socket?.destroy();
    },
  };
}
