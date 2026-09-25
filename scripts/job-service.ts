/**
 * The job service: tool work run in throwaway worker VMs, its outputs sealed
 * into the store, the catalogue updated from recipe results. A module of the
 * hub, the one writer of a run's shared state.
 *
 * A job is a pack or forged tool with its arguments, a shell command, a
 * recipe over one object, or a detect pass (which recipes apply to which
 * objects). Every step is an event in the evidence-work journal before the
 * next one starts:
 *
 *   job_accepted → job_started → job_finished → job_fenced → job_committed
 *                                                          ↘ (recipe) generation_committed → revision_published
 *
 * `fenced` is written only once msb says the worker is gone: until then no
 * byte of its staging directory is read, so nothing it could still write is
 * sealed. A job that fails keeps what it wrote (committed with its status);
 * one interrupted by the hub's own death is retried once, and its first
 * attempt's output is kept beside the second's.
 *
 * Who asked is recorded as the agent's id with the name and doing it had
 * given itself at that moment: context, never authority. What a worker could
 * reach (its mounts, its network) is recorded as the job's accessible scope,
 * beside the scope the agent declared; what it actually read is not measured
 * and is said to be unknown.
 */
import { existsSync, statfsSync } from "node:fs";
import { chmod, copyFile, mkdir, open, readFile, readdir, rm, stat, writeFile } from "node:fs/promises";
import { dirname, join, resolve } from "node:path";
import { Journal, maybeCrash, publishGeneration, readManifest, resealMoved, sealTree, sha256Hex, storePaths, type JournalLine } from "./evidence-store.ts";
import type { Mount, WorkerSpec } from "./vm.ts";

export type JobKind = "tool" | "command" | "recipe" | "detect";

export type Target = { paths: string[]; name?: string; ref?: string };

export type JobSpec = {
  kind: JobKind;
  tool?: string;
  args?: Record<string, unknown>;
  command?: string;
  recipe?: string;
  target?: Target;
  /** detect: the objects to ask about, and which trigger's recipes to ask. */
  targets?: Target[];
  trigger?: "kickoff" | "derived" | "request";
  /** What the agent said the job reads: refs (input:…, job:…) or "all". */
  inputs: string[];
  /** The agent's own scratch, read-only, when the job needs a file from it. */
  scratch?: boolean;
  timeout_seconds: number;
  network: "off" | "allowlist";
  note?: string;
  parent?: string;
  alias?: string;
  experimental?: boolean;
};

export type Requester = { agent: string; name?: string; doing?: string };

export type JobState = "accepted" | "running" | "finished" | "fenced" | "committed" | "failed" | "cancelled";

export type JobRecord = {
  id: string;
  attempt: number;
  spec: JobSpec;
  requester: Requester;
  state: JobState;
  status?: "ok" | "failed" | "timed_out" | "cancelled" | "interrupted" | "stopped";
  reason?: string;
  accepted_at: string;
  started_at?: string;
  finished_at?: string;
  exit?: number | null;
  worker?: string;
  image?: string;
  image_digest?: string;
  tool_sha256?: string;
  accessible?: Array<{ path: string; access: string }>;
  network?: string;
  outputs?: { manifest_sha256: string; files: number; bytes: number; rejected: number; path: string };
  generation?: string;
  revision?: number;
  dedup_of?: string;
  /** A recipe job's identity (recipe, its sha256, the image, the target): the same key is the same result. */
  dedup_key?: string;
  cancel_requested?: string;
};

export type RecipeInfo = { id: string; dir: string; runtime: string; entry: string; sha256: string; seconds: number; auto: string[]; experimental?: boolean };

export type JobServiceOptions = {
  sandbox: string;
  run: string;
  registry?: string;
  image: string;
  workers: number;
  workerCpus: number;
  workerMemoryMib: number;
  allowHosts: string[];
  openNet: boolean;
  packDirs: string[];
  forging: boolean;
  perRequesterRunning?: number;
  perRequesterQueued?: number;
  minFreeMb?: number;
  /** Offer every committed file to the recipes whose trigger is "derived" (off until the first CTF round says it earns its cost). */
  derived?: boolean;
  runWorker: (spec: WorkerSpec) => Promise<{ code: number | null; digest?: string; error?: string; fenced: boolean; fence_error?: string }>;
  destroyWorker: (name: string) => Promise<{ ok: boolean; error?: string }>;
  notify: (to: string, body: string) => Promise<void>;
  identity: (agent: string) => Promise<{ name?: string; doing?: string }>;
  log?: (line: string) => void;
};

const JOB_ID = /^j\d{6}$/;
export const TIMEOUT_MAX_SECONDS = 4 * 3600;
const DETECT_FILES_MAX = 200;

function canonical(v: unknown): string {
  if (Array.isArray(v)) return `[${v.map(canonical).join(",")}]`;
  if (v && typeof v === "object") return `{${Object.keys(v as object).sort().map((k) => `${JSON.stringify(k)}:${canonical((v as Record<string, unknown>)[k])}`).join(",")}}`;
  return JSON.stringify(v);
}

/** Free megabytes on the file system holding `dir`, or its nearest parent that exists. */
function freeMb(dir: string): number | null {
  for (let d = resolve(dir); ; d = dirname(d)) {
    try {
      const s = statfsSync(d);
      return Math.floor((Number(s.bavail) * Number(s.bsize)) / (1024 * 1024));
    } catch {
      if (d === dirname(d)) return null;
    }
  }
}

function shQuote(s: string): string {
  return `'${s.replace(/'/g, `'\\''`)}'`;
}

export class JobService {
  readonly o: Required<Pick<JobServiceOptions, "perRequesterRunning" | "perRequesterQueued" | "minFreeMb" | "derived">> & JobServiceOptions;
  readonly S: string;
  journal!: Journal;
  readonly jobs = new Map<string, JobRecord>();
  private readonly queue: string[] = [];
  private readonly running = new Map<string, Promise<void>>();
  private readonly watchers = new Map<string, number>();
  private readonly delivered = new Set<string>();
  private readonly waitingForSpace = new Set<string>();
  private rotation = 0;
  private stopping = false;
  private timer: ReturnType<typeof setInterval> | undefined;
  /**
   * Every change to the store and the catalogue, one at a time: a
   * generation's id and a revision's number are counted from the journal,
   * and two commits in the same tick would otherwise take the same ones.
   */
  private chain: Promise<unknown> = Promise.resolve();
  private exclusive<T>(fn: () => Promise<T>): Promise<T> {
    const next = this.chain.then(fn);
    this.chain = next.catch(() => undefined);
    return next;
  }

  constructor(options: JobServiceOptions) {
    this.o = { perRequesterRunning: 2, perRequesterQueued: 8, minFreeMb: 4096, derived: false, ...options };
    this.S = resolve(options.sandbox);
  }

  private log(line: string): void {
    this.o.log?.(`jobs: ${line}`);
  }

  // --- start and recovery ---------------------------------------------------------

  /** Open the journal, rebuild every job from it, finish what a crash left half done, and start the queue. */
  async start(): Promise<void> {
    this.journal = await Journal.open(this.S);
    this.replay(this.journal.lines);
    await this.recover();
    await this.queueKickoffRecipes();
    let ticks = 0;
    this.timer = setInterval(() => {
      ticks += 1;
      void this.pump();
      if (ticks % 15 === 0) void this.sweep();
    }, 2000);
    this.timer.unref?.();
    void this.pump();
  }

  private replay(lines: JournalLine[]): void {
    for (const l of lines) {
      const id = String(l.job ?? "");
      const j = this.jobs.get(id);
      switch (l.type) {
        case "job_accepted":
          this.jobs.set(id, { id, attempt: 1, spec: l.spec as JobSpec, requester: l.requester as Requester, state: "accepted", accepted_at: l.at, ...(l.dedup_key ? { dedup_key: String(l.dedup_key) } : {}) });
          break;
        case "job_started":
          if (j) Object.assign(j, { state: "running", attempt: Number(l.attempt), started_at: l.at, worker: l.worker, image: l.image, tool_sha256: l.tool_sha256, accessible: l.accessible, network: l.network });
          break;
        case "job_finished":
          if (j) Object.assign(j, { state: "finished", exit: l.exit as number | null, finished_at: l.at, status: l.status, reason: l.reason });
          break;
        case "job_fenced":
          if (j && l.fenced) j.state = "fenced";
          break;
        case "job_committed":
          if (j) Object.assign(j, { state: "committed", status: l.status, outputs: l.outputs, image_digest: l.image_digest ?? j.image_digest });
          break;
        case "job_failed":
          if (j) Object.assign(j, { state: "failed", status: "failed", reason: l.reason });
          break;
        case "job_cancelled":
          if (j) Object.assign(j, { state: "cancelled", status: "cancelled", reason: l.reason });
          break;
        case "job_cancel_requested":
          if (j) j.cancel_requested = String(l.by);
          break;
        case "job_retried":
          if (j) Object.assign(j, { state: "accepted", attempt: Number(l.attempt) });
          break;
        case "generation_committed":
          if (j) j.generation = String(l.generation);
          break;
        case "job_notified":
          this.delivered.add(id);
          break;
        default:
          break;
      }
    }
    for (const j of this.jobs.values()) if (j.state === "accepted") this.queue.push(j.id);
  }

  /**
   * After a crash, each job half done is finished from where it stopped, in
   * the order the steps are written: a worker still up is removed first; a
   * fenced job is sealed; a tree already moved into the store is sealed where
   * it is; a committed recipe without its generation gets it; a finished job
   * nobody was told about is told.
   */
  private async recover(): Promise<void> {
    for (const j of [...this.jobs.values()]) {
      if (j.state === "running" || j.state === "finished") {
        const gone = await this.o.destroyWorker(j.worker ?? "");
        await this.journal.append({ type: "job_fenced", job: j.id, attempt: j.attempt, fenced: gone.ok, ...(gone.ok ? {} : { error: gone.error }) });
        if (!gone.ok) {
          this.log(`${j.id}: worker ${j.worker} still up after a restart: ${gone.error}`);
          continue;
        }
        if (j.state === "running") {
          // Interrupted by the hub's own death, not by the job. It runs once
          // more only when it cannot have reached anything outside its own
          // VM (a job with network may already have done what it does); its
          // output so far is kept, as that attempt's or as the job's result.
          const interrupted = { status: "interrupted" as const, exit: null, reason: "the hub stopped while it ran" };
          if (j.attempt < 2 && !j.cancel_requested && j.spec.network === "off") {
            await this.commit(j, interrupted, `attempt-${j.attempt}-interrupted`);
            await this.journal.append({ type: "job_retried", job: j.id, attempt: j.attempt + 1, why: "interrupted by the hub's restart" });
            Object.assign(j, { state: "accepted", attempt: j.attempt + 1 });
            delete j.outputs;
            this.queue.push(j.id);
          } else {
            await this.commit(j, interrupted);
          }
          continue;
        }
        j.state = "fenced";
      }
      if (j.state === "fenced") {
        await this.commit(j, { status: j.status ?? "ok", exit: j.exit ?? null, reason: j.reason });
        continue;
      }
      if (j.state === "committed" && j.spec.kind === "recipe" && !j.generation && j.status !== "cancelled") {
        await this.afterCommit(j);
      } else if ((j.state === "committed" || j.state === "failed") && !this.delivered.has(j.id)) {
        await this.tell(j);
      }
    }
  }

  // --- submission -----------------------------------------------------------------------

  /**
   * A new job id, taken without waiting on anything: two submissions in the
   * same tick each get their own (counted from the journal, they took the
   * same one before either acceptance was written).
   */
  private lastId = 0;
  private nextId(): string {
    this.lastId = Math.max(this.lastId, this.journal.of("job_accepted").length) + 1;
    return `j${String(this.lastId).padStart(6, "0")}`;
  }

  /** Where a recipe is: a pack's recipes/<name>, or a forged tool that declares the recipe protocol (experimental). */
  async recipe(id: string): Promise<RecipeInfo | null> {
    const m = /^([a-z0-9][a-z0-9-]*)\/([a-z0-9][a-z0-9-]*)$/.exec(id);
    if (m) {
      for (const pack of this.o.packDirs) {
        let pid = "";
        try {
          pid = (JSON.parse(await readFile(join(pack, "pack.json"), "utf8")) as { id?: string }).id ?? "";
        } catch {
          continue;
        }
        if (pid !== m[1]) continue;
        const dir = join(pack, "recipes", m[2]);
        try {
          const r = JSON.parse(await readFile(join(dir, "recipe.json"), "utf8")) as { runtime?: string; entry?: string; sha256?: string; limits?: { seconds?: number }; auto?: string[] };
          const entry = join(dir, String(r.entry ?? ""));
          const sha = sha256Hex(await readFile(entry));
          if (r.sha256 && r.sha256 !== sha) return null;
          return { id, dir, runtime: r.runtime === "python3" ? "python3" : "bash", entry, sha256: sha, seconds: Number(r.limits?.seconds ?? 900), auto: r.auto ?? [] };
        } catch {
          return null;
        }
      }
      return null;
    }
    // A forged tool whose manifest says `"recipe": true`: an experimental
    // recipe, run only when asked for, never by a trigger.
    if (/^tool:[a-z0-9_]+$/.test(id) && this.o.forging) {
      const name = id.slice(5);
      try {
        const man = JSON.parse(await readFile(join(this.S, "tools", name, "manifest.json"), "utf8")) as { recipe?: boolean; runtime?: string; entry?: string; sha256?: string; timeout_seconds?: number };
        if (man.recipe !== true) return null;
        const entry = join(this.S, "tools", name, String(man.entry ?? ""));
        const sha = sha256Hex(await readFile(entry));
        if (man.sha256 !== sha) return null;
        return { id, dir: join(this.S, "tools", name), runtime: man.runtime === "python3" ? "python3" : man.runtime === "node" ? "node" : "bash", entry, sha256: sha, seconds: Math.min(Number(man.timeout_seconds ?? 900), TIMEOUT_MAX_SECONDS), auto: [], experimental: true };
      } catch {
        return null;
      }
    }
    return null;
  }

  async allRecipes(trigger: "kickoff" | "derived" | "request"): Promise<RecipeInfo[]> {
    const out: RecipeInfo[] = [];
    for (const pack of this.o.packDirs) {
      let pid = "";
      try {
        pid = (JSON.parse(await readFile(join(pack, "pack.json"), "utf8")) as { id?: string }).id ?? "";
      } catch {
        continue;
      }
      let names: string[] = [];
      try {
        names = (await readdir(join(pack, "recipes"))).sort();
      } catch {
        continue;
      }
      for (const name of names) {
        const r = await this.recipe(`${pid}/${name}`);
        if (r && (trigger === "request" || r.auto.includes(trigger))) out.push(r);
      }
    }
    return out;
  }

  /** A pack or forged tool, sealed as its manifest says, and its arguments checked against the manifest's params. */
  private async toolCheck(name: string, args: Record<string, unknown>): Promise<{ ok: true; runtime: string; entry: string; sha256: string } | { ok: false; reason: string }> {
    if (!/^[a-z0-9_]{1,64}$/.test(name)) return { ok: false, reason: `${name} is not a tool name` };
    let man: { runtime?: string; entry?: string; sha256?: string; params?: Record<string, { type?: string; required?: boolean; enum?: string[] }> };
    try {
      man = JSON.parse(await readFile(join(this.S, "tools", name, "manifest.json"), "utf8"));
    } catch {
      return { ok: false, reason: `no tool ${name} in this run (tools/${name}/manifest.json)` };
    }
    const entry = join(this.S, "tools", name, String(man.entry ?? ""));
    let sha: string;
    try {
      sha = sha256Hex(await readFile(entry));
    } catch {
      return { ok: false, reason: `tool ${name}'s script cannot be read` };
    }
    if (man.sha256 !== sha) return { ok: false, reason: `tool ${name}'s script does not match its manifest's sha256` };
    for (const [key, p] of Object.entries(man.params ?? {})) {
      const v = args[key];
      if (v === undefined || v === null) {
        if (p.required) return { ok: false, reason: `tool ${name} needs ${key}` };
        continue;
      }
      const t = p.type ?? "string";
      const ok = t === "string" ? typeof v === "string" : t === "number" ? typeof v === "number" : t === "integer" ? Number.isInteger(v) : t === "boolean" ? typeof v === "boolean" : t === "array" ? Array.isArray(v) : t === "object" ? typeof v === "object" && !Array.isArray(v) : true;
      if (!ok) return { ok: false, reason: `tool ${name}: ${key} must be ${t === "integer" ? "an integer" : `a ${t}`}` };
      if (p.enum && !p.enum.includes(String(v))) return { ok: false, reason: `tool ${name}: ${key} must be one of ${p.enum.join(", ")}` };
    }
    for (const key of Object.keys(args)) if (!(key in (man.params ?? {}))) return { ok: false, reason: `tool ${name} takes no ${key}` };
    return { ok: true, runtime: man.runtime === "python3" ? "python3" : man.runtime === "node" ? "node" : "bash", entry, sha256: sha };
  }

  /**
   * Accept a job, durably, or refuse it with the reason. The answer comes
   * once the acceptance is on disk; the work comes after.
   */
  async submit(agent: string, raw: Partial<JobSpec>, o: { watch?: number } = {}): Promise<{ ok: true; job: JobRecord } | { ok: false; reason: string }> {
    if (this.stopping) return { ok: false, reason: "the run is stopping; no new jobs" };
    const spec = await this.normalise(raw);
    if ("reason" in spec) return { ok: false, reason: spec.reason };
    const queued = [...this.jobs.values()].filter((j) => j.requester.agent === agent && (j.state === "accepted" || j.state === "running"));
    if (agent !== "system" && queued.length >= this.o.perRequesterQueued) return { ok: false, reason: `you have ${queued.length} jobs queued or running, the most one agent may have; wait for one (job_status) or cancel one` };
    // The same recipe over the same object is the same result: answered
    // with the earlier job. Never a command, a tool or anything with network.
    const key = spec.kind === "recipe" ? await this.recipeKey(spec) : undefined;
    if (key) {
      const same = [...this.jobs.values()].find((j) => j.spec.kind === "recipe" && j.dedup_key === key && (j.state === "accepted" || j.state === "running" || j.state === "finished" || j.state === "fenced" || (j.state === "committed" && j.status === "ok")));
      if (same) return { ok: true, job: same };
    }
    const who: { name?: string; doing?: string } = agent === "system" ? { name: "harness" } : await this.o.identity(agent).catch(() => ({}));
    const requester: Requester = { agent, ...(who.name ? { name: who.name } : {}), ...(who.doing ? { doing: who.doing } : {}) };
    const id = this.nextId();
    await this.journal.append({ type: "job_accepted", job: id, spec, requester, ...(key ? { dedup_key: key } : {}) });
    maybeCrash("job:accepted");
    const job: JobRecord = { id, attempt: 1, spec, requester, state: "accepted", accepted_at: new Date().toISOString(), ...(key ? { dedup_key: key } : {}) };
    this.jobs.set(id, job);
    // The agent waits for it in job_run from this moment: a job that is done
    // before its first status call is answered there, not posted as well.
    if (o.watch && o.watch > 0) this.watchers.set(id, Date.now() + Math.min(o.watch, 120) * 1000);
    await this.project(job);
    this.queue.push(id);
    void this.pump();
    return { ok: true, job };
  }

  private async recipeKey(spec: JobSpec): Promise<string> {
    const r = spec.recipe ? await this.recipe(spec.recipe) : null;
    const hashes: string[] = [];
    for (const p of spec.target?.paths ?? []) {
      try {
        const st = await stat(p);
        hashes.push(`${p}:${st.size}:${st.mtimeMs}`);
      } catch {
        hashes.push(`${p}:missing`);
      }
    }
    return sha256Hex(canonical({ recipe: spec.recipe, sha: r?.sha256, image: this.o.image, target: hashes }));
  }

  private async normalise(raw: Partial<JobSpec>): Promise<JobSpec | { reason: string }> {
    const kind = raw.kind;
    if (kind !== "tool" && kind !== "command" && kind !== "recipe" && kind !== "detect") return { reason: "a job is a tool, a command, a recipe or a detect pass" };
    const timeout = Math.min(Math.max(Number(raw.timeout_seconds ?? 900) || 900, 10), TIMEOUT_MAX_SECONDS);
    const network = raw.network === "allowlist" ? "allowlist" : "off";
    const inputs = Array.isArray(raw.inputs) ? raw.inputs.map(String).slice(0, 256) : ["all"];
    const base = { kind, inputs, timeout_seconds: timeout, network, ...(raw.scratch ? { scratch: true } : {}), ...(raw.note ? { note: String(raw.note).slice(0, 2000) } : {}), ...(raw.parent ? { parent: String(raw.parent) } : {}) } as JobSpec;
    if (kind === "tool") {
      const args = raw.args && typeof raw.args === "object" && !Array.isArray(raw.args) ? raw.args : {};
      const checked = await this.toolCheck(String(raw.tool ?? ""), args);
      if (!checked.ok) return { reason: checked.reason };
      return { ...base, tool: String(raw.tool), args };
    }
    if (kind === "command") {
      const command = String(raw.command ?? "");
      if (!command.trim()) return { reason: "a command job needs its command" };
      if (Buffer.byteLength(command) > 64 * 1024) return { reason: "a command is at most 64 KB; put a longer script in your scratch and run it from there" };
      return { ...base, command };
    }
    if (kind === "recipe") {
      const r = raw.recipe ? await this.recipe(String(raw.recipe)) : null;
      if (!r) return { reason: `no recipe ${raw.recipe ?? "(none named)"} in this run's packs${this.o.forging ? " (a forged tool is named tool:<name> and must declare \"recipe\": true)" : ""}` };
      const target = raw.target;
      if (!target || !Array.isArray(target.paths) || !target.paths.length) return { reason: "a recipe job needs a target" };
      for (const p of target.paths) if (!this.insideRun(p)) return { reason: `${p} is not an object of this run` };
      return { ...base, recipe: r.id, target, timeout_seconds: Math.min(r.seconds, TIMEOUT_MAX_SECONDS), ...(raw.alias ? { alias: String(raw.alias) } : {}), ...(r.experimental ? { experimental: true } : {}) };
    }
    const targets = Array.isArray(raw.targets) ? raw.targets.filter((t) => t && Array.isArray(t.paths) && t.paths.every((p) => this.insideRun(p))) : [];
    if (!targets.length) return { reason: "a detect pass needs objects of this run" };
    return { ...base, targets: targets.slice(0, DETECT_FILES_MAX), trigger: raw.trigger === "derived" ? "derived" : raw.trigger === "kickoff" ? "kickoff" : "request" };
  }

  /** A path a job may be pointed at: under inputs/, store/ or the run's catalogue, never out of the run. */
  private insideRun(p: string): boolean {
    const r = resolve(p);
    return [join(this.S, "inputs"), join(this.S, "store", "jobs"), join(this.S, "store", "imports"), join(this.S, "catalog")].some((base) => r === base || r.startsWith(`${base}/`)) && !p.includes("\0");
  }

  // --- the queue ----------------------------------------------------------------------------

  private runningFor(agent: string): number {
    return [...this.jobs.values()].filter((j) => j.state === "running" && j.requester.agent === agent).length;
  }

  /** Start what may start: the run's worker limit, each agent's own limit, taken in turn, and free disk. */
  async pump(): Promise<void> {
    if (this.stopping) return;
    while (this.running.size < this.o.workers && this.queue.length) {
      const requesters = [...new Set(this.queue.map((id) => this.jobs.get(id)?.requester.agent ?? ""))];
      let picked: string | undefined;
      for (let k = 0; k < requesters.length && !picked; k += 1) {
        const agent = requesters[(this.rotation + k) % requesters.length];
        if (agent !== "system" && this.runningFor(agent) >= this.o.perRequesterRunning) continue;
        picked = this.queue.find((id) => this.jobs.get(id)?.requester.agent === agent);
      }
      if (!picked) return;
      this.rotation += 1;
      const free = freeMb(storePaths(this.S).staging);
      if (free !== null && free < this.o.minFreeMb) {
        if (!this.waitingForSpace.has(picked)) {
          this.waitingForSpace.add(picked);
          this.log(`${picked} waits: ${free} MB free where job outputs are kept, below ${this.o.minFreeMb} MB`);
        }
        return;
      }
      this.waitingForSpace.delete(picked);
      this.queue.splice(this.queue.indexOf(picked), 1);
      const job = this.jobs.get(picked)!;
      const p = this.execute(job).catch((err: Error) => this.log(`${job.id}: ${err.message}`)).finally(() => {
        this.running.delete(job.id);
        void this.pump();
      });
      this.running.set(job.id, p);
    }
  }

  // --- running one job -------------------------------------------------------------------------

  private staging(job: JobRecord): { base: string; out: string; ctl: string } {
    const base = join(storePaths(this.S).staging, `${job.id}-${job.attempt}`);
    return { base, out: join(base, "out"), ctl: join(base, "job") };
  }

  /** The guest path a job writes to, and the worker's mounts: exactly what it can reach, which is recorded. */
  private mounts(job: JobRecord, st: { out: string; ctl: string }): { mounts: Mount[]; accessible: Array<{ path: string; access: string }> } {
    const S = this.S;
    const mounts: Mount[] = [];
    const inputs = join(S, "inputs");
    if (existsSync(inputs)) mounts.push({ host: inputs, guest: inputs, readonly: true, noexec: true });
    for (const rel of ["store", "catalog", "tools"]) if (existsSync(join(S, rel))) mounts.push({ host: join(S, rel), guest: join(S, rel), readonly: true });
    for (const pack of this.o.packDirs) if (existsSync(pack)) mounts.push({ host: pack, guest: pack, readonly: true });
    // The agent's own holes, read-only, when the job names one: its scratch,
    // and what it extracted or quarantined (no-exec, as in its own VM).
    if (job.spec.scratch && job.requester.agent !== "system") {
      const who = job.requester.agent;
      for (const [rel, noexec] of [[join("work", who), false], [join("work", "extracted", who), true], [join("work", "quarantine", who), true]] as const) {
        if (existsSync(join(S, rel))) mounts.push({ host: join(S, rel), guest: join(S, rel), readonly: true, ...(noexec ? { noexec: true } : {}) });
      }
    }
    mounts.push({ host: st.out, guest: this.outPath(job), noexec: true });
    mounts.push({ host: st.ctl, guest: "/job", noexec: true });
    const accessible = mounts.map((m) => ({ path: m.guest ?? m.host, access: m.readonly ? "read-only" : "read-write" }));
    return { mounts, accessible };
  }

  outPath(job: JobRecord): string {
    return join(this.S, "work", ".jobs", job.id);
  }

  private async script(job: JobRecord, ctl: string): Promise<{ lines: string[]; tool_sha256?: string }> {
    const q = shQuote;
    const out = this.outPath(job);
    const box = job.spec.timeout_seconds;
    const run = (cmd: string) => [`timeout --kill-after=10 ${box} ${cmd} > /job/stdout.log 2> /job/stderr.log`, "echo $? > /job/exit"];
    const head = ["#!/bin/bash", "set -u", `cd ${q(this.S)} 2>/dev/null || cd /`, `export OUT=${q(out)}`];
    if (job.spec.kind === "tool") {
      const checked = await this.toolCheck(job.spec.tool ?? "", job.spec.args ?? {});
      if (!checked.ok) throw new Error(checked.reason);
      // A tool that writes files takes an output path: the agent cannot know
      // the job's directory before it is accepted, so {OUT} names it.
      const out = this.outPath(job);
      const sub = (v: unknown): unknown => (typeof v === "string" ? v.split("{OUT}").join(out) : Array.isArray(v) ? v.map(sub) : v && typeof v === "object" ? Object.fromEntries(Object.entries(v as Record<string, unknown>).map(([k, x]) => [k, sub(x)])) : v);
      await writeFile(join(ctl, "args.json"), JSON.stringify(sub(job.spec.args ?? {})));
      return { lines: [...head, ...run(`${checked.runtime} ${q(checked.entry)} < /job/args.json`)], tool_sha256: checked.sha256 };
    }
    if (job.spec.kind === "command") {
      await writeFile(join(ctl, "command.sh"), `${job.spec.command ?? ""}\n`);
      return { lines: [...head, ...run("bash /job/command.sh")] };
    }
    if (job.spec.kind === "recipe") {
      const r = await this.recipe(job.spec.recipe ?? "");
      if (!r) throw new Error(`recipe ${job.spec.recipe} is no longer what it was when accepted`);
      await writeFile(join(ctl, "target.json"), JSON.stringify(job.spec.target));
      return { lines: [...head, ...run(`${r.runtime} ${q(r.entry)} run --target /job/target.json --out "$OUT"`)], tool_sha256: r.sha256 };
    }
    // detect: every recipe of the trigger asked about every target; one line each.
    const recipes = await this.allRecipes(job.spec.trigger ?? "request");
    const rows: string[] = [];
    let i = 0;
    for (const t of job.spec.targets ?? []) {
      await writeFile(join(ctl, `target-${i}.json`), JSON.stringify(t));
      for (const r of recipes) rows.push([String(i), r.id, r.runtime, r.entry].join("\t"));
      i += 1;
    }
    await writeFile(join(ctl, "detect.tsv"), rows.length ? `${rows.join("\n")}\n` : "");
    return {
      lines: [
        ...head,
        ": > /job/stdout.log; : > /job/stderr.log",
        "while IFS=$'\\t' read -r i rid rt entry; do",
        "  [ -n \"$i\" ] || continue",
        // The detect step's own exit status: through a pipe it was tail's, and every recipe "applied".
        "  v=$(timeout 300 \"$rt\" \"$entry\" detect --target \"/job/target-$i.json\" 2>>/job/stderr.log); rc=$?",
        "  v=$(printf '%s' \"$v\" | tail -n 1)",
        "  printf '%s\\t%s\\t%s\\t%s\\n' \"$i\" \"$rid\" \"$rc\" \"$v\" >> \"$OUT/detect.tsv\"",
        "done < /job/detect.tsv",
        "echo 0 > /job/exit",
      ],
    };
  }

  private network(job: JobRecord): WorkerSpec["network"] {
    if (job.spec.network !== "allowlist") return { mode: "off" };
    if (this.o.openNet) return { mode: "public" };
    return this.o.allowHosts.length ? { mode: "hosts", hosts: this.o.allowHosts } : { mode: "off" };
  }

  private async execute(job: JobRecord): Promise<void> {
    if (job.cancel_requested) {
      await this.journal.append({ type: "job_cancelled", job: job.id, reason: `cancelled by ${job.cancel_requested} before it started` });
      Object.assign(job, { state: "cancelled", status: "cancelled" });
      await this.project(job);
      await this.tell(job);
      return;
    }
    const st = this.staging(job);
    await rm(st.base, { recursive: true, force: true });
    await mkdir(st.out, { recursive: true });
    await mkdir(st.ctl, { recursive: true });
    let script: { lines: string[]; tool_sha256?: string };
    try {
      script = await this.script(job, st.ctl);
    } catch (err) {
      await this.journal.append({ type: "job_failed", job: job.id, reason: (err as Error).message });
      Object.assign(job, { state: "failed", status: "failed", reason: (err as Error).message });
      await this.project(job);
      await this.tell(job);
      return;
    }
    await writeFile(join(st.ctl, "run.sh"), `${script.lines.join("\n")}\n`);
    const { mounts, accessible } = this.mounts(job, st);
    const network = this.network(job);
    const worker = `dfs-${this.o.run}-job-${job.id}-${job.attempt}`;
    const netText = network.mode === "off" ? "none" : network.mode === "public" ? "every public host" : `the run's allowlist (${network.hosts.join(", ")})`;
    await this.journal.append({ type: "job_started", job: job.id, attempt: job.attempt, worker, image: this.o.image, ...(script.tool_sha256 ? { tool_sha256: script.tool_sha256 } : {}), declared: job.spec.inputs, accessible, observed: "unknown", network: netText, cpus: this.o.workerCpus, memory_mib: this.o.workerMemoryMib });
    Object.assign(job, { state: "running", worker, started_at: new Date().toISOString(), image: this.o.image, accessible, network: netText, ...(script.tool_sha256 ? { tool_sha256: script.tool_sha256 } : {}) });
    await this.project(job);
    maybeCrash("job:started");
    const started = Date.now();
    const guard = setInterval(() => void this.watchDisk(job, worker), 15_000);
    guard.unref?.();
    let result: Awaited<ReturnType<JobServiceOptions["runWorker"]>>;
    try {
      result = await this.o.runWorker({
        name: worker,
        image: this.o.image,
        run: this.o.run,
        job: job.id,
        attempt: job.attempt,
        ...(this.o.registry ? { registry: this.o.registry } : {}),
        cpus: this.o.workerCpus,
        memoryMib: this.o.workerMemoryMib,
        maxDurationSec: job.spec.timeout_seconds + 120,
        workdir: this.S,
        mounts,
        env: { JOB_ID: job.id, OUT: this.outPath(job), AGENT_ID: job.requester.agent, SWARM_SANDBOX: this.S, TZ: "UTC", LANG: "C.UTF-8", PYTHONDONTWRITEBYTECODE: "1", NO_COLOR: "1" },
        network,
        command: ["bash", "/job/run.sh"],
      });
    } finally {
      clearInterval(guard);
    }
    maybeCrash("job:ran");
    let exit: number | null = null;
    try {
      exit = Number((await readFile(join(st.ctl, "exit"), "utf8")).trim());
      if (!Number.isFinite(exit)) exit = null;
    } catch {
      exit = null;
    }
    const cancelled = job.cancel_requested ? `cancelled by ${job.cancel_requested}` : undefined;
    const stopped = (job as JobRecord & { stopped?: string }).stopped;
    const status: NonNullable<JobRecord["status"]> = cancelled ? "cancelled" : stopped ? "stopped" : exit === 124 || exit === 137 ? "timed_out" : exit === 0 ? "ok" : "failed";
    const reason = cancelled ?? stopped ?? (exit === 124 || exit === 137 ? `stopped at its limit of ${job.spec.timeout_seconds}s` : exit === null ? result.error ?? "the worker did not report an exit status" : exit !== 0 ? `exit ${exit}` : undefined);
    await this.journal.append({ type: "job_finished", job: job.id, attempt: job.attempt, exit, status, ...(reason ? { reason } : {}), duration_ms: Date.now() - started, ...(result.digest ? { image_digest: result.digest } : {}) });
    Object.assign(job, { state: "finished", exit, status, reason, finished_at: new Date().toISOString(), ...(result.digest ? { image_digest: result.digest } : {}) });
    await this.journal.append({ type: "job_fenced", job: job.id, attempt: job.attempt, fenced: result.fenced, ...(result.fence_error ? { error: result.fence_error } : {}) });
    if (!result.fenced) {
      // Never sealed while a VM that could write to it may still be up; the
      // backstop tries to remove it again, and recovery seals it after.
      this.log(`${job.id}: worker ${worker} not confirmed gone: ${result.fence_error}`);
      await this.project(job);
      return;
    }
    job.state = "fenced";
    maybeCrash("job:fenced");
    await this.commit(job, { status, exit, reason });
  }

  private async watchDisk(job: JobRecord, worker: string): Promise<void> {
    const free = freeMb(storePaths(this.S).staging);
    if (free === null || free >= Math.floor(this.o.minFreeMb / 4)) return;
    (job as JobRecord & { stopped?: string }).stopped = `stopped: the host's free space fell to ${free} MB`;
    await this.o.destroyWorker(worker).catch(() => undefined);
  }

  /**
   * Seal what the job wrote into the store and record it. `where` names the
   * directory under store/jobs/<id>/: `out` for the job's result, or an
   * interrupted attempt's own name.
   */
  private async commit(job: JobRecord, r: { status: NonNullable<JobRecord["status"]>; exit: number | null; reason?: string }, where = "out"): Promise<void> {
    const recorded = await this.exclusive(() => this.sealAndRecord(job, r, where));
    if (recorded) await this.afterCommit(job);
  }

  private async sealAndRecord(job: JobRecord, r: { status: NonNullable<JobRecord["status"]>; exit: number | null; reason?: string }, where: string): Promise<boolean> {
    const P = storePaths(this.S);
    const st = this.staging(job);
    const jobDir = join(P.jobs, job.id);
    const dest = join(jobDir, where);
    await mkdir(jobDir, { recursive: true });
    let sealed: { manifest: { totals: { files: number; bytes: number }; rejected: unknown[] }; manifestSha256: string };
    const manifestPath = join(jobDir, where === "out" ? "manifest.json" : `${where}.manifest.json`);
    // Where a crash stopped decides the step: moved but not sealed is sealed
    // in place; sealed but not recorded is read back; not moved is sealed now.
    const done = existsSync(manifestPath) ? await readManifest(manifestPath) : null;
    if (existsSync(dest) && done) {
      sealed = { manifest: done.manifest, manifestSha256: done.sha256 };
    } else if (existsSync(dest)) {
      sealed = await resealMoved(this.S, dest, job.id, job.attempt, manifestPath);
    } else {
      await mkdir(st.out, { recursive: true });
      sealed = await sealTree(this.S, st.out, dest, job.id, job.attempt, manifestPath);
    }
    // The job's own words, whole: stdout and stderr beside its outputs.
    const logs: Record<string, string> = {};
    for (const name of ["stdout.log", "stderr.log"]) {
      const from = join(st.ctl, name);
      const to = join(jobDir, where === "out" ? name : `${where}.${name}`);
      if (existsSync(from) && !existsSync(to)) {
        await copyFile(from, to);
        await chmod(to, 0o444);
      }
      if (existsSync(to)) logs[name] = sha256Hex(await readFile(to));
    }
    maybeCrash("job:sealed");
    const outputs = { manifest_sha256: sealed.manifestSha256, files: sealed.manifest.totals.files, bytes: sealed.manifest.totals.bytes, rejected: sealed.manifest.rejected.length, path: `store/jobs/${job.id}/${where}` };
    await this.journal.append({ type: "job_committed", job: job.id, attempt: job.attempt, status: r.status, exit: r.exit, ...(r.reason ? { reason: r.reason } : {}), outputs, logs, ...(job.image_digest ? { image_digest: job.image_digest } : {}) });
    await rm(st.base, { recursive: true, force: true }).catch(() => undefined);
    if (where !== "out") return false;
    Object.assign(job, { state: "committed", status: r.status, outputs });
    await this.project(job);
    maybeCrash("job:committed");
    return true;
  }

  /** A recipe's result becomes a generation; any job's files are offered to the derived recipes; then the requester is told. */
  private async afterCommit(job: JobRecord): Promise<void> {
    if (job.spec.kind === "recipe" && (job.status === "ok" || job.status === "failed" || job.status === "timed_out")) {
      const r = await this.recipe(job.spec.recipe ?? "");
      const { generation, revision } = await this.exclusive(() => publishGeneration(this.journal, {
        job: job.id,
        recipe: job.spec.recipe ?? "",
        recipe_sha256: r?.sha256 ?? job.tool_sha256 ?? "",
        target: job.spec.target ?? { paths: [] },
        ...(job.spec.experimental ? { experimental: true } : {}),
        ...(job.spec.parent ? { parent: job.spec.parent } : {}),
        ...(job.spec.alias ? { alias: job.spec.alias } : {}),
      }));
      Object.assign(job, { generation: generation.id, revision });
      await this.project(job);
      // The kickoff's catalogue is everyone's news; a derived one is told to
      // whoever made the object; a requested one to whoever asked (below).
      const to = job.requester.agent !== "system" ? null : job.spec.parent ? this.originOf(job.spec.parent) : "all";
      if (to) await this.o.notify(to, `Catalogue revision ${revision}: ${generation.id} ${generation.recipe} over ${generation.target.name ?? generation.target.ref ?? "an object"} — ${generation.status}${generation.experimental ? " (experimental recipe)" : ""}. Files: catalog/gen/${generation.id}/${generation.alias ? ` (also ${generation.alias}/)` : ""}; index: catalog/revisions/${revision}/index.md.`).catch(() => undefined);
    }
    if (job.spec.kind === "detect" && job.status === "ok") await this.fromDetect(job);
    if (this.o.derived && (job.spec.kind === "tool" || job.spec.kind === "command") && job.status === "ok") await this.deriveFrom(job);
    await this.tell(job);
  }

  /** The agent at the root of a chain of jobs (a derived detect and recipe run as the harness), or null. */
  private originOf(id: string): string | null {
    let j = this.jobs.get(id);
    for (let hops = 0; j && hops < 10; hops += 1) {
      if (j.requester.agent !== "system") return j.requester.agent;
      j = j.spec.parent ? this.jobs.get(j.spec.parent) : undefined;
    }
    return null;
  }

  /** The files a tool or command job produced, offered to the recipes whose trigger is "derived", one detect pass for all of them. */
  private async deriveFrom(job: JobRecord): Promise<void> {
    const derived = await this.allRecipes("derived");
    if (!derived.length) return;
    const m = await readManifest(join(storePaths(this.S).jobs, job.id, "manifest.json"));
    if (!m || !m.manifest.files.length) return;
    const files = m.manifest.files.filter((f) => f.bytes >= 512);
    const targets = files.slice(0, DETECT_FILES_MAX).map((f) => ({
      paths: [join(this.S, "store", "jobs", job.id, "out", Buffer.from(f.path_b64, "base64").toString("utf8"))],
      name: `job:${job.id}/${f.path}`,
      ref: `job:${job.id}/${f.path}`,
    }));
    if (!targets.length) return;
    const left = files.length - targets.length;
    const sub = await this.submit("system", { kind: "detect", targets, trigger: "derived", inputs: [`job:${job.id}`], timeout_seconds: 1800, network: "off", parent: job.id, note: left > 0 ? `${left} more file(s) of job ${job.id} were not offered to the recipes (the first ${DETECT_FILES_MAX} were); catalog_request any of them` : undefined });
    if (sub.ok && left > 0) await this.journal.append({ type: "detect_bounded", job: job.id, offered: targets.length, not_offered: left });
  }

  /** A detect pass's answers: every recipe that applies runs as a recipe job, whose parent is the job that made the object. */
  private async fromDetect(job: JobRecord): Promise<void> {
    let text = "";
    try {
      text = await readFile(join(storePaths(this.S).jobs, job.id, "out", "detect.tsv"), "utf8");
    } catch {
      return;
    }
    const targets = job.spec.targets ?? [];
    let applied = 0;
    for (const line of text.split("\n")) {
      const [i, rid, rc] = line.split("\t");
      if (rc !== "0" || !rid) continue;
      const t = targets[Number(i)];
      if (!t) continue;
      applied += 1;
      await this.submit(job.requester.agent === "system" ? "system" : job.requester.agent, { kind: "recipe", recipe: rid, target: t, inputs: [t.ref ?? "all"], timeout_seconds: 900, network: "off", parent: job.spec.parent ?? job.id });
    }
    if (!applied && job.requester.agent !== "system") {
      const whys = text.split("\n").filter(Boolean).map((l) => l.split("\t")).map(([, rid, , v]) => {
        try {
          return `${rid}: ${(JSON.parse(v) as { why?: string }).why ?? "does not apply"}`;
        } catch {
          return `${rid}: does not apply`;
        }
      });
      this.delivered.add(job.id);
      await this.journal.append({ type: "job_notified", job: job.id, to: job.requester.agent, how: "post" });
      await this.o.notify(job.requester.agent, `No recipe of this run catalogues ${targets.map((t) => t.name ?? t.ref).join(", ")} (job ${job.id}): ${whys.join("; ") || "none was asked"}. Open it with a job_run command; a forged tool that declares "recipe": true can be named as recipe=tool:<name>.`).catch(() => undefined);
    }
  }

  /** The kickoff's plan: every recipe the census found applies, run once the hub is up. */
  private async queueKickoffRecipes(): Promise<void> {
    if (this.journal.of("kickoff_queued").length) return;
    let plan: Array<{ recipe: string; target: Target; alias?: string; input: string }> = [];
    try {
      plan = (JSON.parse(await readFile(join(this.S, "catalog", "plan.json"), "utf8")) as { recipes?: typeof plan }).recipes ?? [];
    } catch {
      plan = [];
    }
    const ids: string[] = [];
    for (const p of plan) {
      const r = await this.submit("system", { kind: "recipe", recipe: p.recipe, target: p.target, alias: p.alias, inputs: [p.target.ref ?? "all"], timeout_seconds: 900, network: "allowlist", note: `kickoff: ${p.input}` });
      if (r.ok) ids.push(r.job.id);
      else this.log(`kickoff recipe ${p.recipe} over ${p.input} refused: ${r.reason}`);
    }
    await this.journal.append({ type: "kickoff_queued", jobs: ids });
  }

  /**
   * An agent asks for an object to be catalogued: with a recipe named, that
   * recipe runs over it; without, a detect pass asks every recipe of the
   * run whether it applies, and each that does runs as the agent's own job.
   */
  async catalogRequest(agent: string, target: string, recipe?: string, reason?: string): Promise<{ ok: true; job: JobRecord } | { ok: false; reason: string }> {
    const t = await resolveTarget(this.S, target, this.journal);
    if ("reason" in t) return { ok: false, reason: t.reason };
    const note = reason ? String(reason).slice(0, 2000) : undefined;
    if (recipe) return this.submit(agent, { kind: "recipe", recipe, target: t, inputs: [t.ref ?? "all"], timeout_seconds: 900, network: "off", ...(note ? { note } : {}) });
    return this.submit(agent, { kind: "detect", targets: [t], trigger: "request", inputs: [t.ref ?? "all"], timeout_seconds: 900, network: "off", ...(note ? { note } : {}) });
  }

  // --- what agents see ---------------------------------------------------------------------------

  /** A job's state for its requester (or anyone: jobs are the run's, not private), with a page of its stdout. */
  async status(agent: string, id: string, o: { offset?: number; limit?: number; cancel?: boolean; wait?: number } = {}): Promise<{ ok: true; job: JobRecord; stdout?: { offset: number; bytes: number; total: number; text: string; next: number | null; path: string } } | { ok: false; reason: string }> {
    if (!JOB_ID.test(id)) return { ok: false, reason: `${id} is not a job id` };
    const job = this.jobs.get(id);
    if (!job) return { ok: false, reason: `no job ${id}` };
    if (o.cancel) {
      if (job.requester.agent !== agent && agent !== "system") return { ok: false, reason: `job ${id} is ${job.requester.agent}'s; only it can cancel it` };
      if (job.state === "accepted" || job.state === "running") {
        job.cancel_requested = agent;
        await this.journal.append({ type: "job_cancel_requested", job: id, by: agent });
        if (job.state === "accepted") {
          this.queue.splice(this.queue.indexOf(id), 1);
          await this.journal.append({ type: "job_cancelled", job: id, reason: `cancelled by ${agent} before it started` });
          Object.assign(job, { state: "cancelled", status: "cancelled" });
          await this.project(job);
        } else if (job.worker) {
          await this.o.destroyWorker(job.worker).catch(() => undefined);
        }
      }
    }
    if (o.wait && o.wait > 0) this.watchers.set(id, Date.now() + Math.min(o.wait, 120) * 1000);
    const terminal = job.state === "committed" || job.state === "failed" || job.state === "cancelled";
    let stdout: { offset: number; bytes: number; total: number; text: string; next: number | null; path: string } | undefined;
    if (job.state === "committed") {
      const path = join(storePaths(this.S).jobs, id, "stdout.log");
      try {
        const total = (await stat(path)).size;
        const offset = Math.max(0, Math.min(Number(o.offset ?? 0) || 0, total));
        const limit = Math.max(1, Math.min(Number(o.limit ?? 16384) || 16384, 262144));
        const fh = await open(path, "r");
        const buf = Buffer.alloc(Math.min(limit, total - offset));
        await fh.read(buf, 0, buf.length, offset);
        await fh.close();
        const next = offset + buf.length < total ? offset + buf.length : null;
        stdout = { offset, bytes: buf.length, total, text: buf.toString("utf8"), next, path: `store/jobs/${id}/stdout.log` };
        await this.journal.append({ type: "job_returned", job: id, to: agent, stdout_offset: offset, stdout_bytes: buf.length });
      } catch {
        stdout = undefined;
      }
    }
    if (terminal && agent === job.requester.agent && !this.delivered.has(id)) {
      this.delivered.add(id);
      await this.journal.append({ type: "job_notified", job: id, to: agent, how: "status" });
    }
    return { ok: true, job, ...(stdout ? { stdout } : {}) };
  }

  /**
   * Tell the requester a job is done: skipped when it is waiting on the job
   * in a job_run call, which answers it; a post when not, or when its wait
   * ended without the answer.
   */
  private async tell(job: JobRecord): Promise<void> {
    // A detect pass is the service's step: its recipes' results are what the agent is told.
    if (this.delivered.has(job.id) || job.requester.agent === "system" || (job.spec.kind === "detect" && job.status === "ok")) return;
    const until = this.watchers.get(job.id) ?? 0;
    if (Date.now() < until) {
      setTimeout(() => void this.tell(job), until - Date.now() + 3000).unref?.();
      return;
    }
    this.delivered.add(job.id);
    await this.journal.append({ type: "job_notified", job: job.id, to: job.requester.agent, how: "post" });
    await this.o.notify(job.requester.agent, describe(job)).catch(() => undefined);
  }

  /** A readable copy of the job's state beside its outputs; the journal is the record. */
  private async project(job: JobRecord): Promise<void> {
    const dir = join(storePaths(this.S).jobs, job.id);
    await mkdir(dir, { recursive: true });
    const path = join(dir, "job.json");
    await chmod(path, 0o644).catch(() => undefined);
    await writeFile(path, `${JSON.stringify(job, null, 2)}\n`);
    await chmod(path, 0o444).catch(() => undefined);
  }

  // --- stopping -----------------------------------------------------------------------------------

  /** The run is ending: queued jobs are cancelled, running workers removed, and each recorded. */
  async stop(reason: string): Promise<void> {
    this.stopping = true;
    if (this.timer) clearInterval(this.timer);
    for (const id of [...this.queue]) {
      const j = this.jobs.get(id);
      if (!j) continue;
      await this.journal.append({ type: "job_cancelled", job: id, reason });
      Object.assign(j, { state: "cancelled", status: "cancelled", reason });
      await this.project(j);
    }
    this.queue.length = 0;
    for (const j of this.jobs.values()) {
      if (j.state === "running" && j.worker) {
        j.cancel_requested = "the harness";
        await this.o.destroyWorker(j.worker).catch(() => undefined);
      }
    }
    await Promise.allSettled([...this.running.values()]);
  }

  /** Backstop: a worker that did not go when its job ended is asked to go again. */
  async sweep(): Promise<void> {
    for (const j of this.jobs.values()) {
      if (j.state !== "finished" || !j.worker) continue;
      const gone = await this.o.destroyWorker(j.worker);
      if (!gone.ok) continue;
      await this.journal.append({ type: "job_fenced", job: j.id, attempt: j.attempt, fenced: true, late: true });
      j.state = "fenced";
      await this.commit(j, { status: j.status ?? "ok", exit: j.exit ?? null, reason: j.reason });
    }
  }
}

/** One post, for the agent that asked. */
export function describe(job: JobRecord): string {
  const what = job.spec.kind === "tool" ? `tool ${job.spec.tool}` : job.spec.kind === "command" ? "command" : job.spec.kind === "recipe" ? `recipe ${job.spec.recipe}` : "detect pass";
  if (job.state === "failed") return `Job ${job.id} (${what}) was not run: ${job.reason}.`;
  if (job.state === "cancelled") return `Job ${job.id} (${what}) was cancelled${job.reason ? `: ${job.reason}` : ""}.`;
  const o = job.outputs;
  const files = o ? `${o.files} file(s), ${o.bytes} bytes in ${o.path}/${o.rejected ? ` (${o.rejected} link(s) or special file(s) left out, named in its manifest)` : ""}` : "no output";
  const head = job.status === "ok" ? "done" : `${job.status}${job.reason ? ` (${job.reason})` : ""}`;
  return `Job ${job.id} (${what}) ${head}: ${files}; stdout and stderr whole in store/jobs/${job.id}/. job_status ${job.id} for the details; cite its files as job:${job.id}/<path>.${job.generation ? ` Catalogued as ${job.generation}.` : ""}`;
}


/**
 * A job as an agent is shown it: its state, and when it is done the first
 * files it wrote (every one is in its manifest, named), the tail of stderr
 * when it failed (all of it is in stderr.log, named), and how to cite it.
 */
export async function jobView(S: string, job: JobRecord, o: { files?: number } = {}): Promise<Record<string, unknown>> {
  const view: Record<string, unknown> = {
    job: job.id,
    state: job.state,
    ...(job.status ? { status: job.status } : {}),
    ...(job.reason ? { reason: job.reason } : {}),
    kind: job.spec.kind,
    ...(job.spec.tool ? { tool: job.spec.tool } : {}),
    ...(job.spec.recipe ? { recipe: job.spec.recipe } : {}),
    requester: job.requester.agent,
    ...(job.exit !== undefined ? { exit: job.exit } : {}),
    ...(job.generation ? { generation: job.generation, revision: job.revision } : {}),
  };
  if (job.state !== "committed" || !job.outputs) return view;
  const dir = join(storePaths(S).jobs, job.id);
  const m = await readManifest(join(dir, "manifest.json"));
  const shown = o.files ?? 20;
  view.outputs = {
    path: job.outputs.path,
    files: job.outputs.files,
    bytes: job.outputs.bytes,
    ...(m ? { list: m.manifest.files.slice(0, shown).map((f) => ({ path: f.path, bytes: f.bytes, sha256: f.sha256 })) } : {}),
    ...(m && m.manifest.files.length > shown ? { more: `${m.manifest.files.length - shown} more, every one in store/jobs/${job.id}/manifest.json` } : {}),
    ...(m && m.manifest.rejected.length ? { left_out: m.manifest.rejected.map((r) => `${r.path} (${r.kind})`) } : {}),
    manifest: `store/jobs/${job.id}/manifest.json`,
  };
  if (job.status !== "ok") {
    try {
      const err = await readFile(join(dir, "stderr.log"));
      const tail = err.subarray(Math.max(0, err.length - 2048));
      view.stderr = { tail: tail.toString("utf8"), bytes: err.length, ...(err.length > tail.length ? { whole: `store/jobs/${job.id}/stderr.log` } : {}) };
    } catch {
      // no stderr
    }
  }
  view.cite = `job:${job.id}/<path>`;
  return view;
}

/**
 * What an agent names as an object — a path under the run (inputs/…,
 * store/jobs/<id>/out/…, catalog/…) or a reference (input:…, job:<id>/…) —
 * as the target a recipe is given: its path, the rest of its segment set
 * when the journal records one, its name and its reference. Anything
 * outside the run is refused.
 */
export async function resolveTarget(S: string, text: string, journal?: Journal): Promise<Target | { reason: string }> {
  const t = text.trim();
  let rel = t;
  let ref = "";
  const m = /^(input|job|import):(.+)$/.exec(t);
  if (m) {
    if (m[1] === "input") rel = m[2].startsWith("inputs/") ? m[2] : `inputs/${m[2]}`;
    else {
      const slash = m[2].indexOf("/");
      if (slash < 0) return { reason: `${t} names a job, not a file of it: ${m[1]}:<id>/<path>` };
      rel = `store/${m[1] === "job" ? "jobs" : "imports"}/${m[2].slice(0, slash)}/out/${m[2].slice(slash + 1)}`;
    }
    ref = t;
  }
  const abs = resolve(S, rel);
  const bases = [join(S, "inputs"), join(S, "store", "jobs"), join(S, "store", "imports"), join(S, "catalog")];
  if (!bases.some((b) => abs.startsWith(`${b}/`)) || t.includes("\0")) return { reason: `${t} is not an object of this run: name a path under inputs/, store/ or catalog/, or an input:/job: reference` };
  try {
    const st = await stat(abs);
    if (!st.isFile()) return { reason: `${t} is not a file` };
  } catch {
    return { reason: `${t} does not exist` };
  }
  const relToS = abs.slice(S.length + 1);
  if (!ref) {
    const jm = /^store\/jobs\/(j\d{6})\/out\/(.+)$/.exec(relToS);
    ref = relToS.startsWith("inputs/") ? `input:${relToS.slice(7)}` : jm ? `job:${jm[1]}/${jm[2]}` : relToS;
  }
  const paths = [abs];
  const collection = journal?.of("input_collection").find((l) => l.input === relToS);
  if (collection && Array.isArray(collection.members)) for (const p of (collection.members as string[]).slice(1)) paths.push(join(S, p));
  return { paths, name: relToS, ref };
}
