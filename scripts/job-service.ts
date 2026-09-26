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
import { chmod, copyFile, lstat, mkdir, open, readFile, readdir, rm, stat, writeFile } from "node:fs/promises";
import { dirname, join, resolve } from "node:path";
import { Journal, maybeCrash, publishGeneration, publishRevision, readManifest, resealMoved, sealTree, sha256File, sha256Hex, storePaths, type JournalLine } from "./evidence-store.ts";
import type { Mount, WorkerSpec } from "./vm.ts";

export type JobKind = "tool" | "command" | "recipe" | "detect" | "import";

/** An import hashes its source before and after the copy up to this size; above it, size and mtime only. */
export const IMPORT_HASH_BOUND = 2 * 1024 * 1024 * 1024;

/**
 * What an import runs in its worker: each regular file under the source
 * copied into $OUT (links and special files named and left out), hashed
 * before and after the copy (up to the bound) and compared with the copy.
 * The source was live, and its producer was not stopped: the record says
 * so, and a file that changed while it was copied fails the import (exit 3).
 */
const IMPORT_SCRIPT = `import hashlib, json, os, shutil, stat, sys
S, rel, bound = sys.argv[1], sys.argv[2], int(sys.argv[3])
out = os.environ["OUT"]
src = os.path.join(S, rel)
def sha(p):
    h = hashlib.sha256()
    with open(p, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()
rows, changed = [], []
def one(path, name):
    a = os.lstat(path)
    if not stat.S_ISREG(a.st_mode):
        rows.append({"path": name, "left_out": "not a regular file"})
        return
    before = sha(path) if a.st_size <= bound else None
    dst = os.path.join(out, name)
    os.makedirs(os.path.dirname(dst) or out, exist_ok=True)
    shutil.copyfile(path, dst, follow_symlinks=False)
    copied = sha(dst)
    b = os.lstat(path)
    after = sha(path) if b.st_size <= bound else None
    still = (a.st_size, a.st_mtime_ns) == (b.st_size, b.st_mtime_ns) and (before is None or before == after == copied)
    rows.append({"path": name, "bytes": os.path.getsize(dst), "sha256": copied, "hashed_before_and_after": before is not None, "unchanged_while_copied": still})
    if not still:
        changed.append(name)
top = os.path.basename(rel.rstrip("/"))
if os.path.isdir(src) and not os.path.islink(src):
    for root, dirs, files in os.walk(src, followlinks=False):
        for d in [d for d in dirs if os.path.islink(os.path.join(root, d))]:
            rows.append({"path": os.path.join(top, os.path.relpath(os.path.join(root, d), src)), "left_out": "a link"})
        dirs[:] = sorted(d for d in dirs if not os.path.islink(os.path.join(root, d)))
        for f in sorted(files):
            p = os.path.join(root, f)
            one(p, os.path.join(top, os.path.relpath(p, src)))
else:
    one(src, top)
print(json.dumps({"import": rel, "copied_live": True, "producer_fenced": False, "files": rows, "changed_while_copied": changed}, indent=1))
sys.exit(3 if changed else 0)
`;

/** sha256: the object's content, when it is one file of the store (a derived or requested target). */
export type Target = { paths: string[]; name?: string; ref?: string; sha256?: string };

export type JobSpec = {
  kind: JobKind;
  tool?: string;
  args?: Record<string, unknown>;
  command?: string;
  recipe?: string;
  target?: Target;
  /** detect: the objects to ask about, and which trigger's recipes to ask. */
  targets?: Target[];
  /** detect: only these (target index, recipe) pairs, when a derived pass names them; else every recipe of the trigger on every target. */
  pairs?: Array<{ t: number; recipe: string }>;
  trigger?: "kickoff" | "derived" | "request";
  /** What the agent said the job reads: refs (input:…, job:…) or "all". */
  inputs: string[];
  /** The agent's own scratch, read-only, when the job needs a file from it. */
  scratch?: boolean;
  /** import: the file or directory under work/ or tool-output/ to copy into the store as it is now. */
  source?: string;
  timeout_seconds: number;
  network: "off" | "allowlist";
  note?: string;
  parent?: string;
  alias?: string;
  experimental?: boolean;
  /** The job image to run in, by profile (disk, memory, mobile, …), when the run declares job images; else the run's worker image. */
  profile?: string;
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
  worker_size?: string;
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

/**
 * minBytes, suffixes and magic: what the recipe says it is worth being
 * offered (recipe.json min_bytes, suffixes, and magic, bytes at an offset),
 * so the harness picks no file by its own measure and knows no format: it
 * compares what the recipe wrote.
 */
export type RecipeInfo = { id: string; dir: string; runtime: string; entry: string; sha256: string; seconds: number; auto: string[]; experimental?: boolean; minBytes?: number; suffixes?: string[]; magic?: Array<{ offset: number; bytes: Buffer }> };

/** The requester the derived catalogue's work runs as: the lowest lane. */
export const DERIVED = "derived";

/**
 * The derived catalogue's limits (decided with Fable and Codex after the
 * BelkaCTF #6 trial, where a cap of 20 passes went on noise in three
 * minutes): pairs a pass, a rolling budget of worker-seconds, and two
 * ceilings a run. At a limit nothing is dropped: the rest waits, named.
 */
export type DerivedLimits = { pairsPerPass: number; windowMs: number; windowSeconds: number; generationsMax: number; outputBytesMax: number; retries: number };
/**
 * The ceilings count what the catalogue costs, generations and their bytes,
 * not objects asked about: replayed over the BelkaCTF #6 trial, 477 gzip
 * media blobs a job extracted would have spent a 400-object ceiling before
 * the decrypted vault came, 21 minutes in. Asking is bounded by the rolling
 * worker-seconds budget alone.
 */
export const DERIVED_LIMITS: DerivedLimits = { pairsPerPass: 32, windowMs: 10 * 60 * 1000, windowSeconds: 300, generationsMax: 50, outputBytesMax: 2 * 1024 * 1024 * 1024, retries: 1 };

/** An object offered to the derived recipes: one file of the store, by content, and the recipes whose prefilter it met. */
type Candidate = { sha256: string; job: string; path: string; bytes: number; recipes: string[]; tries: number; parent_status: string };

export type JobServiceOptions = {
  sandbox: string;
  run: string;
  registry?: string;
  /** The worker image a job runs in when nothing names another: the one that holds every pack of the run. */
  image: string;
  /**
   * The run's job images, by profile (images/profiles.json): a job names one
   * with `profile`, a pack tool or a recipe runs in its pack's (packProfiles).
   * The agents' own VMs boot the base: the programs are here.
   */
  images?: Record<string, string>;
  /** Each pack's profile, from the kickoff (images/recipe.py profile-for). */
  packProfiles?: Record<string, string>;
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
  /** Offer what jobs make to the recipes whose trigger is "derived" (on by default in a run: --no-derived-catalog turns it off). */
  derived?: boolean;
  derivedLimits?: Partial<DerivedLimits>;
  runWorker: (spec: WorkerSpec) => Promise<{ code: number | null; digest?: string; error?: string; fenced: boolean; fence_error?: string; boot_retry?: string; create_ms?: number }>;
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
  /** Agents whose request was answered with another's job still under way: told too, once it is done (job → agent → end of its wait). */
  private readonly alsoTell = new Map<string, Map<string, number>>();
  private readonly waitingForSpace = new Set<string>();
  private rotation = 0;
  private stopping = false;
  /** Jobs in a row that ran in no worker, and whether the agents were told. */
  private unrun = 0;
  private degraded = false;
  /** The derived catalogue: every object by content, what waits, what it has spent, what it has said. */
  private readonly derivedKnown = new Map<string, "offered" | "answered" | "catalogued" | "unanswered">();
  private derivedPending: Candidate[] = [];
  private readonly derivedTries = new Map<string, number>();
  /** Derived passes whose answers are read (a detect_answered line). */
  private readonly derivedProcessed = new Set<string>();
  private draining = false;
  /** Jobs whose files were offered (a derived_offered line), so recovery offers each once. */
  private readonly derivedOfferedJobs = new Set<string>();
  private derivedSpent: Array<{ at: number; s: number }> = [];
  private derivedObjects = 0;
  private derivedOutputBytes = 0;
  private readonly derivedSaid = new Set<string>();
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
    // The images jobs may run in, on the record before any job does: custody
    // holds each job's image to them.
    if (this.o.images && Object.keys(this.o.images).length) {
      const declared = { default: this.o.image, images: this.o.images, pack_profiles: this.o.packProfiles ?? {} };
      const last = this.journal.of("job_images").at(-1);
      if (!last || JSON.stringify({ default: last.default, images: last.images, pack_profiles: last.pack_profiles }) !== JSON.stringify(declared)) await this.journal.append({ type: "job_images", ...declared });
    }
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
          if (j) Object.assign(j, { state: "running", attempt: Number(l.attempt), started_at: l.at, worker: l.worker, image: l.image, tool_sha256: l.tool_sha256, accessible: l.accessible, network: l.network, ...(l.cpus ? { worker_size: `${l.cpus} vCPU, ${l.memory_mib} MiB` } : {}) });
          break;
        case "job_finished":
          if (j) Object.assign(j, { state: "finished", exit: l.exit as number | null, finished_at: l.at, status: l.status, reason: l.reason });
          if (j?.requester.agent === DERIVED) this.derivedSpent.push({ at: Date.parse(String(l.at)), s: Number(l.duration_ms ?? 0) / 1000 });
          break;
        case "job_fenced":
          if (j && l.fenced) j.state = "fenced";
          break;
        case "job_committed":
          if (j) Object.assign(j, { state: "committed", status: l.status, outputs: l.outputs, image_digest: l.image_digest ?? j.image_digest });
          if (j?.requester.agent === DERIVED && j.spec.kind === "recipe") this.derivedOutputBytes += Number((l.outputs as { bytes?: number } | undefined)?.bytes ?? 0);
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
        case "generation_committed": {
          if (j) j.generation = String(l.generation);
          const sha = (l.target as Target | undefined)?.sha256;
          if (sha) this.derivedKnown.set(sha, "catalogued");
          break;
        }
        case "derived_offered":
          this.derivedOfferedJobs.add(id);
          for (const o of (l.offered as Array<{ sha256: string; path: string; bytes: number; recipes: string[] }> | undefined) ?? []) {
            if (this.derivedKnown.has(o.sha256)) continue;
            this.derivedKnown.set(o.sha256, "offered");
            this.derivedPending.push({ sha256: o.sha256, job: id, path: o.path, bytes: o.bytes, recipes: o.recipes, tries: 0, parent_status: String(l.parent_status ?? "") });
          }
          break;
        case "detect_answered":
          this.derivedProcessed.add(id);
          for (const r of (l.rows as Array<{ sha256: string }> | undefined) ?? []) if (this.derivedKnown.get(r.sha256) !== "catalogued") this.derivedKnown.set(r.sha256, "answered");
          for (const u of (l.unanswered as Array<{ sha256: string }> | undefined) ?? []) this.derivedTries.set(u.sha256, (this.derivedTries.get(u.sha256) ?? 0) + 1);
          break;
        case "detect_unanswered":
          this.derivedKnown.set(String(l.sha256), "unanswered");
          break;
        case "derived_bounded":
        case "derived_deferred":
          this.derivedSaid.add(`${l.type}:${l.bound}`);
          break;
        case "job_notified":
          this.delivered.add(j && l.to && l.to !== j.requester.agent ? `${id}@${l.to}` : id);
          break;
        case "job_deduplicated":
          if (j && l.notify) this.also(id, String((l.by as Requester | undefined)?.agent ?? ""), 0);
          break;
        default:
          break;
      }
    }
    for (const j of this.jobs.values()) if (j.state === "accepted") this.queue.push(j.id);
    // What waits: offered, not answered, and not in a derived pass that is
    // still to finish (recovery finishes those, and reads their answers).
    const inFlight = new Set<string>();
    for (const j of this.jobs.values()) {
      if (j.requester.agent !== DERIVED || j.spec.kind !== "detect") continue;
      this.derivedObjects += j.spec.targets?.length ?? 0;
      if (!this.derivedProcessed.has(j.id) && j.state !== "failed" && j.state !== "cancelled") for (const t of j.spec.targets ?? []) if (t.sha256) inFlight.add(t.sha256);
    }
    this.derivedPending = this.derivedPending
      .filter((c) => this.derivedKnown.get(c.sha256) === "offered" && !inFlight.has(c.sha256))
      .map((c) => ({ ...c, tries: this.derivedTries.get(c.sha256) ?? 0 }));
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
      // The derived catalogue: a pass committed and not read, a job's files never offered.
      if (j.state === "committed" && j.spec.kind === "detect" && j.requester.agent === DERIVED && !this.derivedProcessed.has(j.id)) await this.fromDetect(j);
      if ((j.state === "failed" || j.state === "cancelled") && j.spec.kind === "detect" && j.requester.agent === DERIVED && !this.derivedProcessed.has(j.id)) await this.derivedReturn(j, []);
      if (this.o.derived && j.state === "committed" && (j.spec.kind === "tool" || j.spec.kind === "command" || j.spec.kind === "import") && !this.derivedOfferedJobs.has(j.id)) await this.offerFrom(j);
      if (j.state === "committed" && j.spec.kind === "recipe" && !j.generation && j.status !== "cancelled") {
        await this.afterCommit(j);
      } else if ((j.state === "committed" || j.state === "failed") && (!this.delivered.has(j.id) || this.alsoTell.has(j.id))) {
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
          const r = JSON.parse(await readFile(join(dir, "recipe.json"), "utf8")) as { runtime?: string; entry?: string; sha256?: string; limits?: { seconds?: number }; auto?: string[]; min_bytes?: number; suffixes?: string[]; magic?: Array<{ offset?: number; hex?: string }> };
          const entry = join(dir, String(r.entry ?? ""));
          const sha = sha256Hex(await readFile(entry));
          if (r.sha256 && r.sha256 !== sha) return null;
          return { id, dir, runtime: r.runtime === "python3" ? "python3" : "bash", entry, sha256: sha, seconds: Number(r.limits?.seconds ?? 900), auto: r.auto ?? [], minBytes: Number(r.min_bytes ?? 0) || 0, ...(Array.isArray(r.suffixes) ? { suffixes: r.suffixes.map((x) => String(x).toLowerCase()) } : {}), ...(Array.isArray(r.magic) ? { magic: r.magic.filter((m) => Number.isInteger(m.offset) && /^([0-9a-f]{2})+$/i.test(m.hex ?? "")).map((m) => ({ offset: Number(m.offset), bytes: Buffer.from(String(m.hex), "hex") })) } : {}) };
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
    if (agent !== "system" && agent !== DERIVED && queued.length >= this.o.perRequesterQueued) return { ok: false, reason: `you have ${queued.length} jobs queued or running, the most one agent may have; wait for one (job_status) or cancel one` };
    // The same recipe over the same object is the same result: answered
    // with the earlier job. Never a command, a tool or anything with network.
    const key = spec.kind === "recipe" ? await this.recipeKey(spec) : undefined;
    if (key) {
      const same = [...this.jobs.values()].find((j) => j.spec.kind === "recipe" && j.dedup_key === key && (j.state === "accepted" || j.state === "running" || j.state === "finished" || j.state === "fenced" || (j.state === "committed" && j.status === "ok")));
      if (same) {
        // On the record: who else asked, and whether it is to be told when
        // the job is done (it is still under way, and not its own).
        const open = same.state !== "committed";
        const notify = open && agent !== same.requester.agent && agent !== "system";
        await this.journal.append({ type: "job_deduplicated", job: same.id, by: await this.requesterOf(agent), dedup_key: key, notify });
        if (notify) this.also(same.id, agent, o.watch && o.watch > 0 ? Date.now() + Math.min(o.watch, 120) * 1000 : 0);
        return { ok: true, job: same };
      }
    }
    const requester = await this.requesterOf(agent);
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

  /**
   * The image a job runs in: the profile it names; a pack tool's or a
   * recipe's own pack's profile (a recipe may name one in recipe.json); else
   * the run's worker image. Nothing here knows what a profile holds.
   */
  async imageFor(spec: JobSpec): Promise<{ profile: string | null; ref: string }> {
    const images = this.o.images ?? {};
    const byProfile = (p: string | undefined | null) => (p && images[p] ? { profile: p, ref: images[p] } : null);
    if (spec.profile) return byProfile(spec.profile) ?? { profile: null, ref: this.o.image };
    if (spec.kind === "tool" && spec.tool) {
      const man = await readFile(join(this.S, "tools", spec.tool, "manifest.json"), "utf8").then((t) => JSON.parse(t) as { pack?: string; profile?: string }).catch(() => null);
      const hit = byProfile(man?.profile) ?? byProfile(man?.pack ? this.o.packProfiles?.[man.pack] : null);
      if (hit) return hit;
    }
    if (spec.kind === "recipe" && spec.recipe && !spec.recipe.startsWith("tool:")) {
      const r = await this.recipe(spec.recipe).catch(() => null);
      const declared = r ? await readFile(join(r.dir, "recipe.json"), "utf8").then((t) => (JSON.parse(t) as { profile?: string }).profile).catch(() => undefined) : undefined;
      const hit = byProfile(declared) ?? byProfile(this.o.packProfiles?.[spec.recipe.split("/")[0]]);
      if (hit) return hit;
    }
    return { profile: null, ref: this.o.image };
  }

  private async recipeKey(spec: JobSpec): Promise<string> {
    const r = spec.recipe ? await this.recipe(spec.recipe) : null;
    // An object of the store is itself by content, wherever it sits (the
    // same vault image extracted twice is one object); an input by its stat.
    const image = (await this.imageFor(spec)).ref;
    if (spec.target?.sha256) return sha256Hex(canonical({ recipe: spec.recipe, sha: r?.sha256, image, content: spec.target.sha256 }));
    const hashes: string[] = [];
    for (const p of spec.target?.paths ?? []) {
      try {
        const st = await stat(p);
        hashes.push(`${p}:${st.size}:${st.mtimeMs}`);
      } catch {
        hashes.push(`${p}:missing`);
      }
    }
    return sha256Hex(canonical({ recipe: spec.recipe, sha: r?.sha256, image, target: hashes }));
  }

  private async normalise(raw: Partial<JobSpec>): Promise<JobSpec | { reason: string }> {
    const kind = raw.kind;
    if (kind !== "tool" && kind !== "command" && kind !== "recipe" && kind !== "detect" && kind !== "import") return { reason: "a job is a tool, a command, a recipe, a detect pass or an import" };
    const timeout = Math.min(Math.max(Number(raw.timeout_seconds ?? 900) || 900, 10), TIMEOUT_MAX_SECONDS);
    const network = raw.network === "allowlist" ? "allowlist" : "off";
    const inputs = Array.isArray(raw.inputs) ? raw.inputs.map(String).slice(0, 256) : ["all"];
    // A job image by profile: one the run declared, a pack's id for its
    // pack's image (agents named packs as profiles on the first basic-flow
    // round), or refused with the images the run has and the packs in each.
    let profile = typeof raw.profile === "string" && raw.profile.trim() ? raw.profile.trim() : undefined;
    const images = this.o.images ?? {};
    if (profile && !images[profile] && this.o.packProfiles?.[profile] && images[this.o.packProfiles[profile]]) profile = this.o.packProfiles[profile];
    if (profile && !images[profile]) {
      const have = Object.keys(images);
      const packsOf = (p: string) => Object.entries(this.o.packProfiles ?? {}).filter(([, q]) => q === p).map(([pack]) => pack).sort();
      const listing = have.map((p) => (packsOf(p).length ? `${p} (the packs ${packsOf(p).join(", ")})` : p)).join("; ");
      return { reason: have.length ? `no job image "${profile}" in this run: ${listing}; a pack's name also picks its image (or leave profile out for the run's worker image)` : `this run declared no job images: leave profile out (every job runs in ${this.o.image})` };
    }
    const base = { kind, inputs, timeout_seconds: timeout, network, ...(raw.scratch ? { scratch: true } : {}), ...(raw.note ? { note: String(raw.note) } : {}), ...(raw.parent ? { parent: String(raw.parent) } : {}), ...(profile ? { profile } : {}) } as JobSpec;
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
    if (kind === "import") {
      // A file an agent made in its VM, sealed as it is now: work/ or
      // tool-output/ only, named from the run's directory, never out of it.
      const source = String(raw.source ?? "").trim().replace(/^\.\//, "").replace(/\/+$/, "");
      if (!/^(work|tool-output)\/./.test(source) || source.split("/").includes("..") || source.includes("\0")) return { reason: "an import names a file or directory under work/ or tool-output/, from the run's directory" };
      const abs = join(this.S, source);
      const st = await lstat(abs).catch(() => null);
      if (!st) return { reason: `${source} does not exist` };
      if (!st.isFile() && !st.isDirectory()) return { reason: `${source} is not a regular file or a directory (a link is not followed)` };
      return { ...base, kind: "import", source, inputs: [source], network: "off" };
    }
    if (kind === "recipe") {
      const r = raw.recipe ? await this.recipe(String(raw.recipe)) : null;
      if (!r) return { reason: `no recipe ${raw.recipe ?? "(none named)"} in this run's packs${this.o.forging ? " (a forged tool is named tool:<name> and must declare \"recipe\": true)" : ""}` };
      const target = raw.target;
      if (!target || !Array.isArray(target.paths) || !target.paths.length) return { reason: "a recipe job needs a target" };
      for (const p of target.paths) if (!this.insideRun(p)) return { reason: `${p} is not an object of this run` };
      return { ...base, recipe: r.id, target, timeout_seconds: Math.min(r.seconds, TIMEOUT_MAX_SECONDS), ...(raw.alias ? { alias: String(raw.alias) } : {}), ...(r.experimental ? { experimental: true } : {}) };
    }
    const targets = Array.isArray(raw.targets) ? raw.targets.filter((t) => t && Array.isArray(t.paths) && t.paths.every((p) => this.insideRun(p))).map((t) => ({ paths: t.paths, ...(t.name ? { name: String(t.name) } : {}), ...(t.ref ? { ref: String(t.ref) } : {}), ...(t.sha256 && /^[0-9a-f]{64}$/.test(t.sha256) ? { sha256: t.sha256 } : {}) })) : [];
    if (!targets.length) return { reason: "a detect pass needs objects of this run" };
    const kept = targets.slice(0, DETECT_FILES_MAX);
    const pairs = Array.isArray(raw.pairs) ? raw.pairs.filter((q) => q && Number.isInteger(q.t) && q.t >= 0 && q.t < kept.length && typeof q.recipe === "string").map((q) => ({ t: q.t, recipe: q.recipe })) : undefined;
    return { ...base, targets: kept, ...(pairs?.length ? { pairs } : {}), trigger: raw.trigger === "derived" ? "derived" : raw.trigger === "kickoff" ? "kickoff" : "request" };
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
    await this.maybeDrainDerived();
    while (this.running.size < this.o.workers && this.queue.length) {
      const requesters = [...new Set(this.queue.map((id) => this.jobs.get(id)?.requester.agent ?? ""))];
      // The derived catalogue's work is the lowest lane: one at a time,
      // started only when no other job waits, and only within its budget.
      const othersWaiting = this.queue.some((id) => this.jobs.get(id)?.requester.agent !== DERIVED);
      let picked: string | undefined;
      for (let k = 0; k < requesters.length && !picked; k += 1) {
        const agent = requesters[(this.rotation + k) % requesters.length];
        if (agent === DERIVED && (othersWaiting || this.runningFor(DERIVED) >= 1 || !(await this.derivedMayRun()))) continue;
        if (agent !== "system" && agent !== DERIVED && this.runningFor(agent) >= this.o.perRequesterRunning) continue;
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

  /**
   * The worker's mounts: what its brain sees, read-only — the evidence,
   * store/, catalog/, tools/, the packs, all of work/ (every agent's live
   * scratch and the shared files; the extracted and quarantined corners
   * no-exec) and tool-output/ — and its own $OUT, the one writable place,
   * outside work/. Never the board, the inbox, the ledger, the sessions or
   * the budget. Exactly this list is recorded as the job's accessible scope.
   */
  private mounts(job: JobRecord, st: { out: string; ctl: string }): { mounts: Mount[]; accessible: Array<{ path: string; access: string }> } {
    const S = this.S;
    const mounts: Array<Mount & { note?: string }> = [];
    const inputs = join(S, "inputs");
    if (existsSync(inputs)) mounts.push({ host: inputs, guest: inputs, readonly: true, noexec: true });
    for (const rel of ["store", "catalog", "tools", "tool-output"]) if (existsSync(join(S, rel))) mounts.push({ host: join(S, rel), guest: join(S, rel), readonly: true });
    if (existsSync(join(S, "work"))) {
      mounts.push({ host: join(S, "work"), guest: join(S, "work"), readonly: true, note: "every agent's live scratch and the shared files: they may change while the job runs" });
      for (const corner of ["extracted", "quarantine"]) if (existsSync(join(S, "work", corner))) mounts.push({ host: join(S, "work", corner), guest: join(S, "work", corner), readonly: true, noexec: true });
    }
    for (const pack of this.o.packDirs) if (existsSync(pack)) mounts.push({ host: pack, guest: pack, readonly: true });
    mounts.push({ host: st.out, guest: this.outPath(job), noexec: true });
    mounts.push({ host: st.ctl, guest: "/job", noexec: true });
    const accessible = mounts.map((m) => ({ path: m.guest ?? m.host, access: `${m.readonly ? "read-only" : "read-write"}${m.noexec ? ", no-exec" : ""}${m.note ? `; ${m.note}` : ""}` }));
    return { mounts: mounts.map(({ note: _note, ...m }) => m), accessible };
  }

  /** Where a job writes, in its VM: its own directory in the run, outside work/ (which it sees read-only). */
  outPath(job: JobRecord): string {
    return join(this.S, ".jobs", job.id);
  }

  private async script(job: JobRecord, ctl: string): Promise<{ lines: string[]; tool_sha256?: string }> {
    const q = shQuote;
    const out = this.outPath(job);
    const box = job.spec.timeout_seconds;
    // A job with network may install what it needs for itself: what pip
    // holds before and after is kept with its logs, so the record says what
    // the job ran with beyond the image.
    const pip = job.spec.network === "allowlist" ? ["python3 -m pip list --format=freeze > /job/pip-before.txt 2>/dev/null || true"] : [];
    const pipAfter = job.spec.network === "allowlist" ? ["python3 -m pip list --format=freeze > /job/pip-after.txt 2>/dev/null || true"] : [];
    const run = (cmd: string) => [...pip, `timeout --kill-after=10 ${box} ${cmd} > /job/stdout.log 2> /job/stderr.log`, "echo $? > /job/exit", ...pipAfter];
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
    if (job.spec.kind === "import") {
      await writeFile(join(ctl, "import.py"), IMPORT_SCRIPT);
      return { lines: [...head, ...run(`python3 /job/import.py ${q(this.S)} ${q(job.spec.source ?? "")} ${IMPORT_HASH_BOUND}`)] };
    }
    if (job.spec.kind === "recipe") {
      const r = await this.recipe(job.spec.recipe ?? "");
      if (!r) throw new Error(`recipe ${job.spec.recipe} is no longer what it was when accepted`);
      await writeFile(join(ctl, "target.json"), JSON.stringify(job.spec.target));
      return { lines: [...head, ...run(`${r.runtime} ${q(r.entry)} run --target /job/target.json --out "$OUT"`)], tool_sha256: r.sha256 };
    }
    // detect: every recipe of the trigger asked about every target, or, for
    // a derived pass, the pairs whose prefilter matched; one line each.
    const recipes = await this.allRecipes(job.spec.trigger ?? "request");
    const byId = new Map(recipes.map((r) => [r.id, r]));
    const rows: string[] = [];
    let i = 0;
    for (const t of job.spec.targets ?? []) {
      await writeFile(join(ctl, `target-${i}.json`), JSON.stringify(t));
      const asked = job.spec.pairs ? job.spec.pairs.filter((q) => q.t === i).map((q) => byId.get(q.recipe)).filter((r): r is RecipeInfo => Boolean(r)) : recipes;
      for (const r of asked) rows.push([String(i), r.id, r.runtime, r.entry].join("\t"));
      i += 1;
    }
    await writeFile(join(ctl, "detect.tsv"), rows.length ? `${rows.join("\n")}\n` : "");
    return {
      lines: [
        ...head,
        ": > /job/stdout.log; : > /job/stderr.log",
        "mkdir -p \"$OUT/probes\"",
        "while IFS=$'\\t' read -r i rid rt entry; do",
        "  [ -n \"$i\" ] || continue",
        // Each probe's whole output kept (the answer is its last line); the
        // detect step's own exit status, not a pipe's.
        "  p=\"$OUT/probes/$i-$(printf '%s' \"$rid\" | tr '/:' '__')\"",
        "  timeout 300 \"$rt\" \"$entry\" detect --target \"/job/target-$i.json\" > \"$p.out\" 2> \"$p.err\"; rc=$?",
        "  [ -s \"$p.err\" ] || rm -f \"$p.err\"",
        "  v=$(tail -n 1 \"$p.out\")",
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
    const chosen = await this.imageFor(job.spec);
    const network = this.network(job);
    const worker = `dfs-${this.o.run}-job-${job.id}-${job.attempt}`;
    const netText = network.mode === "off" ? "none" : network.mode === "public" ? "every public host" : `the run's allowlist (${network.hosts.join(", ")})`;
    await this.journal.append({ type: "job_started", job: job.id, attempt: job.attempt, worker, image: chosen.ref, ...(chosen.profile ? { profile: chosen.profile } : {}), ...(script.tool_sha256 ? { tool_sha256: script.tool_sha256 } : {}), declared: job.spec.inputs, accessible, observed: "unknown", network: netText, cpus: this.o.workerCpus, memory_mib: this.o.workerMemoryMib });
    Object.assign(job, { state: "running", worker, worker_size: `${this.o.workerCpus} vCPU, ${this.o.workerMemoryMib} MiB`, started_at: new Date().toISOString(), image: chosen.ref, accessible, network: netText, ...(script.tool_sha256 ? { tool_sha256: script.tool_sha256 } : {}) });
    await this.project(job);
    maybeCrash("job:started");
    const started = Date.now();
    const guard = setInterval(() => void this.watchDisk(job, worker), 15_000);
    guard.unref?.();
    let result: Awaited<ReturnType<JobServiceOptions["runWorker"]>>;
    try {
      result = await this.o.runWorker({
        name: worker,
        image: chosen.ref,
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
    const reason =
      cancelled ??
      stopped ??
      (exit === 124 || exit === 137
        ? `stopped at its limit of ${job.spec.timeout_seconds}s`
        : exit === null
          ? result.error ?? "the worker did not report an exit status"
          : job.spec.kind === "import" && exit === 3
            ? "the source changed while it was copied (stdout.log names each file): import it again once it is still"
            : exit !== 0
              ? `exit ${exit}`
              : undefined);
    if (job.requester.agent === DERIVED) this.derivedSpent.push({ at: Date.now(), s: (Date.now() - started) / 1000 });
    await this.journal.append({ type: "job_finished", job: job.id, attempt: job.attempt, exit, status, ...(reason ? { reason } : {}), duration_ms: Date.now() - started, ...(result.digest ? { image_digest: result.digest } : {}), ...(result.boot_retry ? { boot_retry: result.boot_retry } : {}), ...(result.create_ms !== undefined ? { create_ms: result.create_ms } : {}) });
    Object.assign(job, { state: "finished", exit, status, reason, finished_at: new Date().toISOString(), ...(result.digest ? { image_digest: result.digest } : {}) });
    await this.workerHealth(job, exit === null && !cancelled && !stopped ? (result.error ?? "the worker did not report an exit status") : null);
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

  /**
   * Workers that cannot run are the service's trouble, not the job's. On Ali
   * Hadi #10 three agents found out one by one that none would start. After
   * three jobs in a row with no worker every agent is told once, and again
   * when one runs.
   */
  private async workerHealth(job: JobRecord, error: string | null): Promise<void> {
    if (error === null) {
      this.unrun = 0;
      if (!this.degraded) return;
      this.degraded = false;
      await this.journal.append({ type: "jobs_recovered", job: job.id });
      await this.o.notify("all", `Tool jobs run again: ${job.id} ran in a worker.`).catch(() => undefined);
      return;
    }
    this.unrun += 1;
    if (this.unrun < 3 || this.degraded) return;
    this.degraded = true;
    await this.journal.append({ type: "jobs_degraded", job: job.id, in_a_row: this.unrun, error });
    this.log(`workers are not running: ${this.unrun} jobs in a row (${error})`);
    await this.o.notify("all", `Tool jobs are not running: the last ${this.unrun} could not run in a worker (${error}). Until the job service says they run again, do that work in your own VM; jobs submitted meanwhile are still tried.`).catch(() => undefined);
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
    for (const name of ["stdout.log", "stderr.log", "pip-before.txt", "pip-after.txt"]) {
      const from = join(st.ctl, name);
      const to = join(jobDir, where === "out" ? name : `${where}.${name}`);
      if (existsSync(from) && !existsSync(to)) {
        await copyFile(from, to);
        await chmod(to, 0o444);
      }
      // Streamed: a job that prints gigabytes leaves a log of gigabytes.
      if (existsSync(to)) logs[name] = await sha256File(to);
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

  /**
   * A recipe's result becomes a generation, told by what asked for it; a
   * job that makes files offers them to the derived recipes, whatever its
   * status; a detect pass's answers are read whatever its status; then the
   * requester is told.
   */
  private async afterCommit(job: JobRecord): Promise<void> {
    if (job.spec.kind === "recipe" && (job.status === "ok" || job.status === "failed" || job.status === "timed_out")) {
      const r = await this.recipe(job.spec.recipe ?? "");
      const trigger = job.requester.agent === "system" ? "kickoff" : job.requester.agent === DERIVED ? "derived" : "request";
      const parentStatus = job.spec.parent ? this.jobs.get(job.spec.parent)?.status : undefined;
      const { generation, revision } = await this.exclusive(() => publishGeneration(this.journal, {
        job: job.id,
        recipe: job.spec.recipe ?? "",
        recipe_sha256: r?.sha256 ?? job.tool_sha256 ?? "",
        target: job.spec.target ?? { paths: [] },
        trigger,
        ...(parentStatus ? { parent_status: parentStatus } : {}),
        ...(job.spec.experimental ? { experimental: true } : {}),
        ...(job.spec.parent ? { parent: job.spec.parent } : {}),
        ...(job.spec.alias ? { alias: job.spec.alias } : {}),
      }));
      Object.assign(job, { generation: generation.id, revision });
      await this.project(job);
      if (job.spec.target?.sha256) this.derivedKnown.set(job.spec.target.sha256, "catalogued");
      if (trigger === "derived") this.derivedOutputBytes += job.outputs?.bytes ?? 0;
      const where = `Files: catalog/gen/${generation.id}/${generation.alias ? ` (also ${generation.alias}/)` : ""}; index: catalog/revisions/${revision}/index.md.`;
      const what = `${generation.id} ${generation.recipe} over ${generation.target.name ?? generation.target.ref ?? "an object"}`;
      if (trigger === "kickoff") {
        await this.o.notify("all", `Catalogue revision ${revision}: ${what} — ${generation.status}${generation.experimental ? " (experimental recipe)" : ""}. ${where}`).catch(() => undefined);
      } else if (trigger === "derived") {
        // A complete catalogue of something a job made is everyone's news;
        // a partial or failed one is its maker's, with the recipe's reasons.
        const maker = job.spec.parent ? this.originOf(job.spec.parent) : null;
        if (generation.status === "complete") {
          await this.o.notify("all", `Catalogue revision ${revision}: ${what}, made by job ${job.spec.parent ?? "?"}${maker ? ` (${maker})` : ""} and catalogued on its own — complete. ${where}`).catch(() => undefined);
        } else if (maker) {
          const cov = generation.coverage as { errors?: unknown[]; limits_hit?: unknown[]; why?: string } | null;
          const why = [...(cov?.errors ?? []), ...(cov?.limits_hit ?? []), ...(cov?.why ? [cov.why] : [])].map(String);
          await this.o.notify(maker, `Catalogue revision ${revision}: ${what}, made by your job ${job.spec.parent}, is ${generation.status}${why.length ? `: ${why.join("; ")}` : ""}. ${where} When a readable form of it appears in a job's output, it is offered to the recipes again.`).catch(() => undefined);
        }
      }
      if (generation.status === "complete") await this.relateReadable(generation);
    }
    if (job.spec.kind === "detect") await this.fromDetect(job);
    if (this.o.derived && (job.spec.kind === "tool" || job.spec.kind === "command" || job.spec.kind === "import")) await this.offerFrom(job);
    await this.tell(job);
    void this.pump();
  }

  /** The agent at the root of a chain of jobs (a derived detect and recipe run as the harness), or null. */
  private originOf(id: string): string | null {
    let j = this.jobs.get(id);
    for (let hops = 0; j && hops < 10; hops += 1) {
      if (j.requester.agent !== "system" && j.requester.agent !== DERIVED) return j.requester.agent;
      j = j.spec.parent ? this.jobs.get(j.spec.parent) : undefined;
    }
    return null;
  }

  /** Each derived recipe's own measure: its smallest object, and when it names any, a name ending or bytes at an offset. */
  private async derivedRecipesFor(path: string, bytes: number, head: () => Promise<Buffer>, derived: RecipeInfo[]): Promise<string[]> {
    const out: string[] = [];
    let first: Buffer | null = null;
    for (const r of derived) {
      if (bytes < (r.minBytes ?? 0)) continue;
      if (!r.suffixes?.length && !r.magic?.length) {
        out.push(r.id);
        continue;
      }
      if (r.suffixes?.some((x) => path.toLowerCase().endsWith(x))) {
        out.push(r.id);
        continue;
      }
      if (r.magic?.length) {
        first ??= await head();
        const f = first;
        if (r.magic.some((g) => f.length >= g.offset + g.bytes.length && f.subarray(g.offset, g.offset + g.bytes.length).equals(g.bytes))) out.push(r.id);
      }
    }
    return out;
  }

  /**
   * What a job made, offered to the derived recipes by content: each file a
   * derived recipe's own measure takes, once per sha256 in the run (an input,
   * an earlier offer or a catalogued object is skipped, named), queued to
   * wait for the lowest lane. A tool, command or import job, whatever its
   * status: a failed job's files are kept, and may be what matters.
   */
  private async offerFrom(job: JobRecord): Promise<void> {
    if (this.derivedOfferedJobs.has(job.id)) return;
    const derived = await this.allRecipes("derived");
    if (!derived.length) return;
    const m = await readManifest(join(storePaths(this.S).jobs, job.id, "manifest.json"));
    if (!m || !m.manifest.files.length) return;
    const reach = Math.min(Math.max(0, ...derived.flatMap((r) => (r.magic ?? []).map((g) => g.offset + g.bytes.length))), 1 << 20);
    const out = join(storePaths(this.S).jobs, job.id, "out");
    const inputsSha = await this.inputShas();
    const offered: Array<{ sha256: string; path: string; bytes: number; recipes: string[] }> = [];
    const skipped: Array<{ sha256: string; path: string; same_as: string }> = [];
    const seen = new Set<string>();
    let filtered = 0;
    for (const f of m.manifest.files) {
      const name = Buffer.from(f.path_b64, "base64").toString("utf8");
      const head = async (): Promise<Buffer> => {
        if (!reach) return Buffer.alloc(0);
        const fh = await open(join(out, name), "r").catch(() => null);
        if (!fh) return Buffer.alloc(0);
        try {
          const buf = Buffer.alloc(reach);
          const { bytesRead } = await fh.read(buf, 0, reach, 0);
          return buf.subarray(0, bytesRead);
        } finally {
          await fh.close();
        }
      };
      const recipes = await this.derivedRecipesFor(f.path, f.bytes, head, derived);
      if (!recipes.length) {
        filtered += 1;
        continue;
      }
      if (seen.has(f.sha256)) continue;
      seen.add(f.sha256);
      const known = inputsSha.get(f.sha256) ?? (this.derivedKnown.has(f.sha256) ? `${this.derivedKnown.get(f.sha256)} earlier` : undefined);
      if (known) {
        skipped.push({ sha256: f.sha256, path: f.path, same_as: known });
        continue;
      }
      offered.push({ sha256: f.sha256, path: f.path, bytes: f.bytes, recipes });
    }
    if (!offered.length && !skipped.length) return;
    this.derivedOfferedJobs.add(job.id);
    await this.journal.append({ type: "derived_offered", job: job.id, parent_status: job.status ?? job.state, offered, skipped, filtered });
    for (const o of offered) {
      this.derivedKnown.set(o.sha256, "offered");
      this.derivedPending.push({ ...o, job: job.id, tries: 0, parent_status: job.status ?? job.state });
    }
  }

  private inputShaCache: Map<string, string> | null = null;
  /** The run's inputs by content: a job's copy of an input is not a new object. */
  private async inputShas(): Promise<Map<string, string>> {
    if (this.inputShaCache) return this.inputShaCache;
    const m = new Map<string, string>();
    try {
      const inputs = JSON.parse(await readFile(join(this.S, "inputs.json"), "utf8")) as { files?: Array<{ path: string; sha256?: string }> };
      for (const f of inputs.files ?? []) if (f.sha256) m.set(f.sha256, `input:${f.path.replace(/^inputs\//, "")}`);
    } catch {
      // no inputs.json: nothing to skip by
    }
    this.inputShaCache = m;
    return m;
  }

  private limits(): DerivedLimits {
    return { ...DERIVED_LIMITS, ...(this.o.derivedLimits ?? {}) };
  }

  /** Worker-seconds the derived lane spent in the rolling window. */
  private derivedWindowSpent(now = Date.now()): number {
    const L = this.limits();
    this.derivedSpent = this.derivedSpent.filter((x) => now - x.at < L.windowMs);
    return this.derivedSpent.reduce((a, x) => a + x.s, 0);
  }

  /**
   * Whether the derived lane may start work now: within its rolling budget
   * (else it waits, said once each time it starts to wait) and under the
   * run's ceilings (else it stops, said once to everyone, nothing dropped:
   * what waits stays named in the journal's derived_offered lines).
   */
  private async derivedMayRun(): Promise<boolean> {
    const L = this.limits();
    const made = this.journal.of("generation_committed").filter((l) => l.trigger === "derived").length;
    const bound = made >= L.generationsMax ? { bound: "generations", spent: made, cap: L.generationsMax } : this.derivedOutputBytes >= L.outputBytesMax ? { bound: "output_bytes", spent: this.derivedOutputBytes, cap: L.outputBytesMax } : null;
    if (bound) {
      if (!this.derivedSaid.has(`derived_bounded:${bound.bound}`)) {
        this.derivedSaid.add(`derived_bounded:${bound.bound}`);
        const queued = this.queue.filter((id) => this.jobs.get(id)?.requester.agent === DERIVED).length;
        await this.journal.append({ type: "derived_bounded", ...bound, pending: this.derivedPending.length, queued });
        await this.o.notify("all", `The derived catalogue has reached its ${bound.bound === "generations" ? `${bound.cap} generations` : `${bound.cap} bytes of output`} for this run: ${this.derivedPending.length} object(s) that jobs made stay offered and not asked about, and ${queued} of its jobs stay queued (each named in the journal). catalog_request any object to have it catalogued.`).catch(() => undefined);
      }
      return false;
    }
    const spent = this.derivedWindowSpent();
    if (spent >= L.windowSeconds) {
      if (!this.derivedSaid.has("derived_deferred:worker_seconds")) {
        this.derivedSaid.add("derived_deferred:worker_seconds");
        await this.journal.append({ type: "derived_deferred", bound: "worker_seconds", spent: Math.round(spent), cap: L.windowSeconds, window_s: L.windowMs / 1000, pending: this.derivedPending.length });
      }
      return false;
    }
    this.derivedSaid.delete("derived_deferred:worker_seconds");
    return true;
  }

  /**
   * Start a derived pass when the lane is free: the largest waiting objects
   * first (a cap lands on small noise, never on a disk), up to the pass's
   * pairs, as the lowest lane's job.
   */
  private async maybeDrainDerived(): Promise<void> {
    if (!this.o.derived || this.stopping || !this.derivedPending.length || this.draining) return;
    const busy = [...this.jobs.values()].some((j) => j.requester.agent === DERIVED && (j.state === "accepted" || j.state === "running" || j.state === "finished" || j.state === "fenced"));
    if (busy || !(await this.derivedMayRun())) return;
    this.draining = true;
    try {
      const L = this.limits();
      this.derivedPending.sort((a, b) => b.bytes - a.bytes);
      const take: Candidate[] = [];
      let pairs = 0;
      while (this.derivedPending.length && (pairs === 0 || pairs + this.derivedPending[0].recipes.length <= L.pairsPerPass) && take.length < DETECT_FILES_MAX) {
        const c = this.derivedPending.shift()!;
        take.push(c);
        pairs += c.recipes.length;
      }
      if (!take.length) return;
      const S = this.S;
      const targets: Target[] = take.map((c) => ({ paths: [join(S, "store", "jobs", c.job, "out", c.path)], name: `job:${c.job}/${c.path}`, ref: `job:${c.job}/${c.path}`, sha256: c.sha256 }));
      const r = await this.submit(DERIVED, {
        kind: "detect",
        targets,
        pairs: take.flatMap((c, t) => c.recipes.map((recipe) => ({ t, recipe }))),
        trigger: "derived",
        inputs: [...new Set(take.map((c) => `job:${c.job}`))],
        timeout_seconds: 1800,
        network: "off",
      });
      if (r.ok) this.derivedObjects += take.length;
      else this.derivedPending.unshift(...take);
    } finally {
      this.draining = false;
    }
  }

  /**
   * A detect pass's answers, read whatever the pass's status (a pass that
   * timed out keeps what it answered): every recipe that applies runs as a
   * recipe job over the object, with the job that made it as its parent.
   * For a derived pass, every answer is journalled; a pair it did not answer
   * waits once more, then is named unanswered.
   */
  private async fromDetect(job: JobRecord): Promise<void> {
    if (job.state === "failed" || job.state === "cancelled" && !job.outputs) {
      if (job.requester.agent === DERIVED && !this.derivedProcessed.has(job.id)) await this.derivedReturn(job, []);
      return;
    }
    let text = "";
    try {
      text = await readFile(join(storePaths(this.S).jobs, job.id, "out", "detect.tsv"), "utf8");
    } catch {
      text = "";
    }
    const targets = job.spec.targets ?? [];
    const answered: Array<{ t: number; recipe: string; rc: string; why: string }> = [];
    for (const line of text.split("\n")) {
      const [i, rid, rc, v] = line.split("\t");
      if (!rid || !targets[Number(i)]) continue;
      let why = "";
      try {
        why = String((JSON.parse(v ?? "") as { why?: string }).why ?? "");
      } catch {
        why = "";
      }
      answered.push({ t: Number(i), recipe: rid, rc, why });
    }
    const derivedPass = job.requester.agent === DERIVED;
    if (derivedPass && this.derivedProcessed.has(job.id)) return;
    let applied = 0;
    for (const a of answered) {
      if (a.rc !== "0") continue;
      const t = targets[a.t];
      applied += 1;
      // Its parent is the job that made the object (a derived target names it).
      const maker = derivedPass ? /^job:(j\d{6})\//.exec(t.ref ?? "")?.[1] : undefined;
      const r = await this.submit(derivedPass ? DERIVED : job.requester.agent === "system" ? "system" : job.requester.agent, { kind: "recipe", recipe: a.recipe, target: t, inputs: [t.ref ?? "all"], timeout_seconds: 900, network: "allowlist", parent: maker ?? job.spec.parent ?? job.id });
      // Already catalogued over the same bytes: the agent who asked is told
      // where, since no job of its own will report.
      if (!derivedPass && r.ok && r.job.state === "committed" && job.requester.agent !== "system") {
        const g = this.journal.of("generation_committed").find((l) => l.job === r.job.id);
        await this.journal.append({ type: "job_notified", job: r.job.id, to: job.requester.agent, how: "post" });
        await this.o
          .notify(job.requester.agent, `${a.recipe} over ${t.name ?? t.ref} is already catalogued, by content: ${g ? `generation ${g.generation} (catalog/gen/${g.generation}/), ` : ""}job ${r.job.id}. catalog_search reads it; nothing was run again.`)
          .catch(() => undefined);
      }
    }
    if (derivedPass) {
      await this.derivedReturn(job, answered);
      return;
    }
    if (!applied && job.requester.agent !== "system") {
      const whys = answered.map((a) => `${a.recipe}: ${a.why || "does not apply"}`);
      this.delivered.add(job.id);
      await this.journal.append({ type: "job_notified", job: job.id, to: job.requester.agent, how: "post" });
      await this.o.notify(job.requester.agent, `No recipe of this run catalogues ${targets.map((t) => t.name ?? t.ref).join(", ")} (job ${job.id}): ${whys.join("; ") || "none was asked"}. Open it with a job_run command; a forged tool that declares "recipe": true can be named as recipe=tool:<name>.`).catch(() => undefined);
    }
  }

  /** A derived pass's answers on the record, and what it did not answer back in the queue (once), or named. */
  private async derivedReturn(job: JobRecord, answered: Array<{ t: number; recipe: string; rc: string; why: string }>): Promise<void> {
    const targets = job.spec.targets ?? [];
    const got = new Set(answered.map((a) => `${a.t}\u0000${a.recipe}`));
    const missing = new Map<number, string[]>();
    for (const q of job.spec.pairs ?? []) if (!got.has(`${q.t}\u0000${q.recipe}`)) missing.set(q.t, [...(missing.get(q.t) ?? []), q.recipe]);
    const rows = answered.map((a) => ({ sha256: targets[a.t]?.sha256 ?? "", ref: targets[a.t]?.ref ?? "", recipe: a.recipe, applies: a.rc === "0", rc: a.rc, why: a.why }));
    const unanswered = [...missing].map(([t, recipes]) => ({ sha256: targets[t]?.sha256 ?? "", ref: targets[t]?.ref ?? "", recipes }));
    this.derivedProcessed.add(job.id);
    await this.journal.append({ type: "detect_answered", job: job.id, status: job.status ?? job.state, rows, unanswered });
    for (const r of rows) if (r.sha256 && this.derivedKnown.get(r.sha256) !== "catalogued") this.derivedKnown.set(r.sha256, "answered");
    const L = this.limits();
    for (const u of unanswered) {
      const tries = (this.derivedTries.get(u.sha256) ?? 0) + 1;
      this.derivedTries.set(u.sha256, tries);
      const m = /^job:(j\d{6})\/(.*)$/s.exec(u.ref);
      if (tries <= L.retries && m) {
        this.derivedPending.push({ sha256: u.sha256, job: m[1], path: m[2], bytes: this.bytesOf(m[1], m[2]), recipes: u.recipes, tries, parent_status: this.jobs.get(m[1])?.status ?? "" });
      } else {
        this.derivedKnown.set(u.sha256, "unanswered");
        await this.journal.append({ type: "detect_unanswered", sha256: u.sha256, ref: u.ref, recipes: u.recipes, tries });
      }
    }
  }

  private bytesOf(job: string, path: string): number {
    const j = this.jobs.get(job);
    const f = (j?.outputs as { list?: Array<{ path: string; bytes: number }> } | undefined)?.list?.find((x) => x.path === path);
    return f?.bytes ?? 0;
  }

  /**
   * A complete generation over an object a job made from another object
   * that has a partial generation (the decrypted volume of an encrypted
   * container): the partial one is linked to its readable form, within
   * three jobs of lineage (declared inputs and store/jobs/<id> paths named
   * in a command). Nothing is called wrong: both stay.
   */
  private async relateReadable(g: { id: string; recipe: string; target: { ref?: string; paths?: string[] } }): Promise<void> {
    const maker = /^job:(j\d{6})\//.exec(g.target.ref ?? "")?.[1] ?? /store\/jobs\/(j\d{6})\//.exec((g.target.paths ?? [])[0] ?? "")?.[1];
    if (!maker) return;
    // Up to three hops back, by the jobs each one names and by the files it
    // names in them: the same bytes are often remade under another job (run
    // s8c228e decrypted a vault.raw another job had also made, byte for byte,
    // so the partial catalogue was over a job that was no ancestor).
    const ancestors = new Set<string>();
    const shas = new Set<string>();
    let frontier = [maker];
    for (let hop = 0; hop < 3 && frontier.length; hop += 1) {
      const next: string[] = [];
      for (const id of frontier) {
        const j = this.jobs.get(id);
        if (!j) continue;
        const named: Array<[string, string | undefined]> = [
          ...(j.spec.inputs ?? []).map((x) => /^job:(j\d{6})(?:\/(.+))?$/.exec(x)).map((m) => (m ? ([m[1], m[2]] as [string, string | undefined]) : null)),
          ...[...String(j.spec.command ?? "").matchAll(/store\/jobs\/(j\d{6})\/(?:out\/([^\s'"`;|&)<>]+))?/g)].map((m) => [m[1], m[2]] as [string, string | undefined]),
        ].filter((x): x is [string, string | undefined] => x !== null && x[0] !== id);
        for (const [a, path] of named) {
          for (const sha of await this.shasOf(a, path)) shas.add(sha);
          if (!ancestors.has(a)) {
            ancestors.add(a);
            next.push(a);
          }
        }
      }
      frontier = next;
    }
    if (!ancestors.size) return;
    const partials = this.journal.of("generation_committed").filter((l) => l.recipe === g.recipe && l.status !== "complete" && l.generation !== g.id).filter((l) => {
      const t = l.target as Target | undefined;
      const from = /^job:(j\d{6})\//.exec(t?.ref ?? "")?.[1] ?? /store\/jobs\/(j\d{6})\//.exec((t?.paths ?? [])[0] ?? "")?.[1];
      return (from !== undefined && ancestors.has(from)) || (typeof t?.sha256 === "string" && shas.has(t.sha256));
    });
    const already = new Set(this.journal.of("generation_related").map((l) => `${l.generation}>${l.readable}`));
    let wrote = false;
    for (const p of partials) {
      if (already.has(`${p.generation}>${g.id}`)) continue;
      await this.journal.append({ type: "generation_related", generation: p.generation, readable: g.id, relation: "readable form", via: maker });
      wrote = true;
    }
    if (wrote) await this.exclusive(() => publishRevision(this.journal));
  }

  /** The sha256 of a job's file as its manifest has it, or of every file when no path is named. */
  private async shasOf(job: string, path?: string): Promise<string[]> {
    const m = await readManifest(join(storePaths(this.S).jobs, job, "manifest.json")).catch(() => null);
    if (!m) return [];
    return m.manifest.files.filter((f) => path === undefined || f.path === path).map((f) => f.sha256);
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
    } else if (agent !== job.requester.agent && this.alsoTell.get(id)?.has(agent)) {
      if (o.wait && o.wait > 0) this.also(id, agent, Date.now() + Math.min(o.wait, 120) * 1000);
      if (terminal && !this.delivered.has(`${id}@${agent}`)) {
        this.delivered.add(`${id}@${agent}`);
        await this.journal.append({ type: "job_notified", job: id, to: agent, how: "status" });
      }
    }
    return { ok: true, job, ...(stdout ? { stdout } : {}) };
  }

  private async requesterOf(agent: string): Promise<Requester> {
    const who: { name?: string; doing?: string } = agent === "system" ? { name: "harness" } : agent === DERIVED ? { name: "derived catalogue" } : await this.o.identity(agent).catch(() => ({}));
    return { agent, ...(who.name ? { name: who.name } : {}), ...(who.doing ? { doing: who.doing } : {}) };
  }

  private also(job: string, agent: string, until: number): void {
    if (!agent) return;
    const m = this.alsoTell.get(job) ?? new Map<string, number>();
    m.set(agent, Math.max(until, m.get(agent) ?? 0));
    this.alsoTell.set(job, m);
  }

  /** The others who asked for the same job are told as its requester is: after their own wait. */
  private async tellAlso(job: JobRecord): Promise<void> {
    for (const [agent, until] of this.alsoTell.get(job.id) ?? []) {
      const key = `${job.id}@${agent}`;
      if (this.delivered.has(key)) continue;
      if (Date.now() < until) {
        setTimeout(() => void this.tellAlso(job), until - Date.now() + 3000).unref?.();
        continue;
      }
      this.delivered.add(key);
      await this.journal.append({ type: "job_notified", job: job.id, to: agent, how: "post" });
      await this.o.notify(agent, describe(job)).catch(() => undefined);
    }
  }

  /**
   * Tell the requester a job is done: skipped when it is waiting on the job
   * in a job_run call, which answers it; a post when not, or when its wait
   * ended without the answer.
   */
  private async tell(job: JobRecord): Promise<void> {
    await this.tellAlso(job);
    // A detect pass is the service's step: its recipes' results are what the agent is told.
    if (this.delivered.has(job.id) || job.requester.agent === "system" || job.requester.agent === DERIVED || (job.spec.kind === "detect" && job.status === "ok")) return;
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
  const what = job.spec.kind === "tool" ? `tool ${job.spec.tool}` : job.spec.kind === "command" ? "command" : job.spec.kind === "recipe" ? `recipe ${job.spec.recipe}` : job.spec.kind === "import" ? `import of ${job.spec.source}, copied live from where it was` : "detect pass";
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
    ...(job.worker_size ? { worker: job.worker_size } : {}),
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
  // stderr is shown whatever the exit status: a command that swallowed its
  // failures still exits 0, and what it said on stderr is how that shows.
  try {
    const err = await readFile(join(dir, "stderr.log"));
    if (err.length) {
      const room = job.status === "ok" ? 1024 : 2048;
      const tail = err.subarray(Math.max(0, err.length - room));
      view.stderr = { tail: tail.toString("utf8"), bytes: err.length, ...(err.length > tail.length ? { whole: `store/jobs/${job.id}/stderr.log` } : {}) };
    }
  } catch {
    // no stderr
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
  // An object of the store is named by its content too, as its manifest has
  // it, so a recipe asked for it dedups with one already run over the same
  // bytes (run s8c228e: an agent's request catalogued the decrypted vault a
  // second time, 13 s after the derived catalogue had).
  const om = /^store\/(jobs|imports)\/([^/]+)\/out\/(.+)$/.exec(relToS);
  const sha256 = om ? (await readManifest(join(S, "store", om[1], om[2], "manifest.json")))?.manifest.files.find((f) => f.path === om[3])?.sha256 : undefined;
  return { paths, name: relToS, ref, ...(sha256 ? { sha256 } : {}) };
}
