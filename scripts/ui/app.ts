/**
 * HTTP app for the swarm web UI: JSON API + SSE + static bundle.
 * node:http only, so `node --experimental-strip-types` runs it with zero deps.
 */
import { timingSafeEqual } from "node:crypto";
import { createReadStream, existsSync } from "node:fs";
import { execFile } from "node:child_process";
import { readFile, realpath, stat } from "node:fs/promises";
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
import { ActionRunner, checkReadiness, listModels, validateStart, type Job, type ModelList, type ReadinessReport } from "./actions.ts";
import { deleteGoal, GoalError, listGoals, readGoal, saveGoal } from "./goals.ts";
import { listLibrary, readLibraryEntry } from "./library.ts";
import { describeRoots, InputsError, listInputSets, parseInputsRoots, resolveInputImage, resolveInputSet, RootStore } from "./inputs.ts";
import { countForgedTools, findRun, listSwarmRows, listWorkFiles, queryTraces, readAllPosts, readSwarmView, readTimedPosts, resolveToolOutputFile, resolveWorkFile } from "./model.ts";
import { hashArtifacts } from "../artifacts.ts";
import { buildDossier } from "../dossier.ts";
import { renderReport } from "../report.ts";
import { summarize } from "../summary.ts";
import { readForgedTool, TOOL_NAME_RE } from "../../extensions/protocol.ts";
import { ChangeBus } from "./watch.ts";

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
   * stays open — the whole point of the app is that anyone on the LAN can
   * watch — but starting, stopping, reaping and restoring need it. Empty
   * disables the check, which is the old behaviour.
   */
  token?: string;
  distDir?: string;
  runner?: ActionRunner;
  bus?: ChangeBus;
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
};

export type UiApp = {
  server: Server;
  bus: ChangeBus;
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
async function sendFile(
  res: ServerResponse,
  abs: string,
  extraHeaders: Record<string, string> = {},
  download = false,
): Promise<void> {
  const info = await stat(abs);
  if (!info.isFile()) throw new HttpError(404, "not a file");
  const type = MIME[extname(abs).toLowerCase()] ?? "application/octet-stream";
  // Names under work/ come from evidence and can be in any script. Node
  // refuses a header value above U+00FF (and mangles some that pass), so the
  // quoted filename is an ASCII stand-in and the real name goes in the
  // RFC 5987 filename*, which browsers prefer when both are present.
  const name = basename(abs);
  const fallback = name.replace(/[^\x20-\x7e]|["\\]/g, "_");
  const encoded = encodeURIComponent(name).replace(/['()*]/g, (c) => `%${c.charCodeAt(0).toString(16).toUpperCase()}`);
  res.writeHead(200, {
    "content-type": type,
    "content-length": String(info.size),
    "cache-control": "no-store",
    "content-disposition": `${download ? "attachment" : "inline"}; filename="${fallback}"; filename*=UTF-8''${encoded}`,
    ...extraHeaders,
  });
  // The headers are out, so a file removed or made unreadable since the stat
  // can only cut the response short; without a listener the stream's error
  // is an uncaught exception and takes the whole console down with it.
  const stream = createReadStream(abs);
  stream.on("error", () => res.destroy());
  stream.pipe(res);
}

export function createUiApp(options: UiAppOptions): UiApp {
  const root = resolve(options.root);
  const runsDir = resolve(options.runsDir);
  const distDir = options.distDir ?? join(root, "ui", "dist");
  const bus = options.bus ?? new ChangeBus(runsDir);
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
  const token = options.token ?? process.env.SWARM_UI_TOKEN ?? "";
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
    };
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
   * anyone on the LAN can watch, and watching must not become a way to hammer
   * the host. A result stands for the TTL, and beyond it for as long as
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
    // Adding a root over the LAN is off unless the server was started with the flag; then it needs the token.
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

    if (path === "/api/swarms") {
      if (method === "GET") {
        json(res, 200, await listSwarmRows(runsDir));
        return;
      }
      if (method === "POST") {
        requireToken(req, url);
        const check = validateStart(await readBody(req));
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
        json(res, 202, runner.start(check.params));
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
            files: dossier.files,
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
              "sandbox allow-scripts; default-src 'none'; style-src 'unsafe-inline'; img-src data:; font-src data:; connect-src 'none'; form-action 'none'; base-uri 'none'",
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
        // shell planted under work/. This route is open to the LAN, so the
        // resolver refuses a link outright and confirms what is left really
        // lives under work/.
        const abs = await resolveWorkFile(sandbox, rel);
        if (typeof abs !== "string") throw new HttpError(abs.error, abs.message);
        // Artifacts are agent output. sandbox without allow-same-origin is an
        // opaque origin; connect-src 'none' stops fetch() even if a page had
        // CORS. Scripts still run so HTML canvases stay interactive.
        await sendFile(
          res,
          abs,
          {
            "content-security-policy":
              "sandbox allow-scripts; default-src 'none'; script-src 'unsafe-inline'; style-src 'unsafe-inline'; img-src data: blob:; font-src data:; connect-src 'none'; form-action 'none'; base-uri 'none'",
            "x-content-type-options": "nosniff",
          },
          url.searchParams.get("download") === "1",
        );
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
        json(res, 202, runner.stop(id));
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
    runner,
    async listen(port, host) {
      await bus.start();
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
