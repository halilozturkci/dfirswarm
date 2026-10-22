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
 * given itself at that moment: context, never authority. A job that declares
 * what it reads is given only that (job-scope.ts: a view the hub builds for
 * it); one that declares nothing, or `all`, sees every object of the run, and
 * the record says which. What a worker could reach (its mounts, its network)
 * is recorded as the job's accessible scope, beside the scope the agent
 * declared and what that expanded to; what it actually read within that is
 * not measured and is said to be unknown.
 *
 * A brain's own output a finding cites (`tool:<seat>/<file>`, a whole output
 * the harness kept; `trace:<sha256>`, one line of the trace) is sealed here:
 * found on the trace (evidence-store.ts traceOrigin), snapshotted by the hub
 * at an import job's start and held to the trace's digest there, sealed like
 * any import, and published as `import:<id>/<file>` with its trace provenance.
 */
import { createHash } from "node:crypto";
import { constants, existsSync, lstatSync, readdirSync, readFileSync, realpathSync } from "node:fs";
import { chmod, copyFile, link, lstat, mkdir, open, readFile, readdir, rm, stat, writeFile } from "node:fs/promises";
import { join, resolve } from "node:path";
import { hubAlive, hubProcessFor, Journal, maybeCrash, publishGeneration, publishRevision, readManifest, resealMoved, sealTree, sha256File, sha256Hex, storePaths, traceLineBytes, traceOrigin, type JournalLine, type Manifest, type TraceOrigin } from "./evidence-store.ts";
import { chooseImage, readImageRecords, type ImageChoice, type ImageRecord } from "./image-choice.ts";
import { buildView, declaredScope, dropProjected, freeMb, PROJECTED_DIR, resolveScope, ScopeError, scopeKindOf, scopeManifestText, VIEW_DIR, type ScopeKind, type ScopeObject, type ViewEntry } from "./job-scope.ts";
import { CANARY_NAME, OBSERVE_GUEST, observedRun, observeWanted, readObservation } from "./job-observe.ts";
import { assessJob, HEARTBEAT_LINES, HEARTBEAT_STOP, keepSample, readSamples, sampleJob, type JobProgress } from "./job-telemetry.ts";
import type { Mount, WorkerSpec } from "./vm.ts";
import { jobNetworkHosts } from "./net-grants.ts";
import { indexOutputs, objectsMatch, opMatch, rankSimilar, reuseOf, sameAsOf, sameAsView, type Reuse, type SameAs, type Similar } from "./job-reuse.ts";
import { declaredSecretOutput, jobSensitivity, parseSecretDeclaration, recipeSecretRefusal, sensitiveIndex, targetPaths, type SecretDeclaration, type Sensitivity } from "./output-hygiene.ts";
import { execRefused, execRefusedWords, type ExecRefused } from "./job-exec-refused.ts";
import { writeRefused, writeRefusedWords, type WriteRefused } from "./job-write-refused.ts";

export type JobKind = "tool" | "command" | "recipe" | "detect" | "import";

/**
 * A job an agent declares short: its own limit is at most this many seconds,
 * and it is killed there (timeout(1) in its worker, the VM's own limit two
 * minutes later), so the worker kept for short jobs cannot be held by a long
 * job that claimed otherwise.
 */
export const SHORT_JOB_SECONDS = 120;

/**
 * From this many workers one is kept for short jobs. With two, keeping one
 * halves what the longer ones have: replayed over the arrivals and run times
 * of the three latest runs (s306463, s2a59b2, s6895a8), two workers with one
 * kept put the longer jobs' p95 wait at 354-1951 s, against 71-210 s with
 * none kept.
 */
export const SHORT_LANE_FROM_WORKERS = 3;

/**
 * The lane a job waits in. An agent's short job may take any free worker,
 * the one kept for short jobs too, so a quick look never waits behind long
 * parses; an agent's other jobs and the kickoff's recipes take the rest; the
 * derived catalogue's work is the lowest lane (one at a time, only when no
 * other job waits, within its budget). Neither the kickoff's recipes nor the
 * derived catalogue ever take the worker kept for short jobs.
 */
export type Lane = "short" | "general" | "kickoff" | "derived";

/** An import hashes its source before and after the copy up to this size; above it, size and mtime only. */
export const IMPORT_HASH_BOUND = 2 * 1024 * 1024 * 1024;

/**
 * What an import runs in its worker: each regular file under the source
 * copied into $OUT (links and special files named and left out), hashed
 * before and after the copy (up to the bound) and compared with the copy.
 * An import's scope is its source: what the worker copies is the snapshot
 * the hub took of it at the job's start (cloned or copied from a descriptor,
 * and hashed; job-scope.ts), not the live file, and the record says so. Its
 * producer was not stopped. A file that changed while it was copied fails
 * the import (exit 3).
 */
const IMPORT_SCRIPT = `import hashlib, json, os, shutil, stat, sys
S, rel, bound = sys.argv[1], sys.argv[2], int(sys.argv[3])
mode = sys.argv[4] if len(sys.argv) > 4 else "live"
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
print(json.dumps({"import": rel, "copied_live": mode == "live", **({"copied_from": "the snapshot the hub took at the job's start (its sha256 in the job's scope manifest)"} if mode == "snapshot" else {}), "producer_fenced": False, "files": rows, "changed_while_copied": changed}, indent=1))
sys.exit(3 if changed else 0)
`;

/**
 * What a job with network grants runs to use one (docs/adr/0012): one call
 * to the fetch service on the host, as this job, for one grant. The request
 * is the grant's own; the body comes back and is written where the job says
 * (the capture is sealed in the store either way), the answer's other
 * fields to stderr. Exit 0 when the body was delivered.
 *
 *   python3 /job/net_fetch.py N-<k> [--out FILE]
 */
export const NET_FETCH_SCRIPT = `import base64, json, os, sys, urllib.request, urllib.error
args = sys.argv[1:]
if not args:
    sys.exit("usage: net_fetch.py N-<k> [--out FILE]")
grant, out = args[0], None
if "--out" in args:
    out = args[args.index("--out") + 1]
req = urllib.request.Request(os.environ["SWARM_NET_URL"], data=json.dumps({"grant": grant}).encode(), method="POST",
    headers={"content-type": "application/json", "authorization": "Bearer " + os.environ["SWARM_NET_TOKEN"], "x-dfirswarm-principal": os.environ["SWARM_NET_PRINCIPAL"]})
opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
try:
    raw = opener.open(req, timeout=180).read()
except urllib.error.HTTPError as e:
    raw = e.read()
answer = json.loads(raw.decode("utf-8"))
body = answer.pop("body_b64", None)
sys.stderr.write(json.dumps(answer, indent=1) + "\\n")
if body is not None:
    data = base64.b64decode(body)
    if out:
        with open(out, "wb") as f:
            f.write(data)
    else:
        sys.stdout.buffer.write(data)
sys.exit(0 if answer.get("delivered") else 1)
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
  /**
   * What the agent said the job reads, as said: refs and run paths (input:…,
   * job:…, work/…), ["all"], or nothing (left out: [] with scope default-all).
   */
  inputs: string[];
  /** declared (enforced), all (said) or default-all (nothing said; a job from before scopes). */
  scope?: ScopeKind;
  /** The hub's own seal of a brain-side output a record cited: set by sealCited, never by an agent. */
  seal?: SealSpec;
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
  /**
   * The network grants its requester gave it (N-<k>, each asked for a job:
   * docs/adr/0012): bound to this job when its worker is made, which then
   * reaches the fetch service on the host and nothing else of it.
   */
  net_grants?: string[];
  /**
   * An intended reproduction of work another seat did (docs/adr/0017): a
   * command or a tool only. Recorded, and counted apart by the metrics; the
   * similar jobs are still named.
   */
  independent?: boolean;
  /**
   * Every output this job seals is sensitive (docs/adr/0016): its result
   * may hold a secret. Said by the agent, or declared by the tool's manifest
   * (secret_output_by); the harness never reads the bytes to decide. The
   * job's process is told with SECRET_OUTPUT=1.
   */
  secret_output?: boolean;
  /** The tool's manifest declared this job secret output (a "secret_output" key it reads: output-hygiene.ts parseSecretDeclaration), whether or not the agent said so. */
  secret_output_by?: "tool_manifest";
};

export type Requester = { agent: string; name?: string; doing?: string };

/** A brain-side output being sealed: the ref, the trace line and digest it is held to, and where it came from. */
export type SealSpec = { kind: "tool" | "trace"; ref: string; digest: string; line_sha256: string; path?: string; origin: TraceOrigin };

/** What a job's scope was, on its record: which kind, and for a declared one what it resolved to and where the manifest is. */
export type JobScope = {
  kind: ScopeKind;
  objects?: number;
  files?: number;
  bound?: number;
  manifest?: string;
  manifest_sha256?: string;
  /**
   * A job that declared no scope (it could read every object) and whose command, arguments, source or targets name a
   * sensitive job: the job ran, the dependency was recorded here when it started, and what it seals is sensitive
   * (docs/adr/0016). `matched` is what the text held of the job: its store path, else its id.
   */
  auto_declared?: Array<{ from: string; how: "named_in_text"; matched: string }>;
  /** A job that declared no scope: the sensitive jobs that were sealed when it started, which its mounts let it read. Not a record that it did. */
  could_read_sensitive?: string[];
};

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
  scope?: JobScope;
  network?: string;
  outputs?: { manifest_sha256: string; files: number; bytes: number; rejected: number; path: string };
  generation?: string;
  revision?: number;
  dedup_of?: string;
  /** A recipe job's identity (recipe, its sha256, the image, the target): the same key is the same result. */
  dedup_key?: string;
  /**
   * A command's or a tool's objects by digest and its operation, for the
   * reuse hints (job-reuse.ts, docs/adr/0017): never used to merge.
   */
  reuse?: Reuse;
  /** Its outputs that are an earlier job's, byte for byte (the job_same_as line). */
  same_as?: SameAs[];
  cancel_requested?: string;
  lane?: Lane;
  image_choice?: ImageChoice;
  /**
   * A program the job ran is not in its image (B17): exit 127, or the
   * shell's "command not found" on its stderr. The profile and image it ran
   * in, for the images' upkeep; generic, never a tool's own message.
   */
  program_missing?: { program: string | null; profile: string | null; image: string };
  /**
   * A write its worker refused (job-write-refused.ts): it ended non-zero and
   * its stdout, stderr or a stderr file it kept says "Read-only file system",
   * or "Permission denied" on a path outside what it may write. Its reason
   * says so, names $OUT, and says what to do; generic, never a tool's own.
   */
  write_refused?: WriteRefused;
  /**
   * A program its worker could not execute (job-exec-refused.ts): exit 126,
   * with the shell's line that names the program when there is one, the
   * loader's refusal to map a segment, or a denied existing file under a
   * read-only mount. Its reason says so and, by where the program stands,
   * what to do: a copy run from an executable directory inside the job for a
   * supplied program, the operator's tool-supply for evidence; generic, never
   * a tool's own.
   */
  exec_refused?: ExecRefused;
  /** Its outputs are sensitive, decided when they were sealed (output-hygiene.ts): run with secret_output, or made from a sensitive output. */
  sensitive?: Sensitivity;
  /** Derived and known when the job started: what it declared, or its text, already reaches a sensitive output (job_started's `sensitive_at_start`; the seal decides again, from what it read). */
  sensitive_at_start?: Sensitivity;
};

/**
 * minBytes, suffixes and magic: what the recipe says it is worth being
 * offered (recipe.json min_bytes, suffixes, and magic, bytes at an offset),
 * so the harness picks no file by its own measure and knows no format: it
 * compares what the recipe wrote. purpose, capability, exclusions and
 * unavailable: what the pack declares the recipe prepares
 * (extensions/preparation.ts): an inventory, or a broad extraction of a
 * whole source into a searchable form, the capability it prepares (its id
 * when none is named), what it does not hold, and, for one the job images
 * cannot run, why (it is never run, and each source it applies to has its
 * preparation declined with that why).
 */
export type RecipeInfo = {
  id: string;
  dir: string;
  runtime: string;
  entry: string;
  sha256: string;
  seconds: number;
  auto: string[];
  experimental?: boolean;
  minBytes?: number;
  suffixes?: string[];
  magic?: Array<{ offset: number; bytes: Buffer }>;
  version?: string;
  description?: string;
  purpose?: "inventory" | "broad_extraction";
  capability?: string;
  exclusions?: string[];
  unavailable?: string;
  /** Why the recipe is never run: it carries a secret_output declaration, which only tool jobs honour (recipeSecretRefusal). */
  refused?: string;
};

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

/**
 * What a recipe's coverage says the images lack to read its object
 * (`missing: [{kind, what}]`, the recipe's own words), one sentence each.
 */
export function missingOf(coverage: unknown): string[] {
  const m = (coverage && typeof coverage === "object" ? (coverage as { missing?: unknown }).missing : undefined) as unknown;
  if (!Array.isArray(m)) return [];
  return m.map((x) => (x && typeof x === "object" ? String((x as { what?: unknown }).what ?? "").trim() : "")).filter(Boolean);
}

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
  /**
   * Whether this host has room now for one more worker of this much memory:
   * asked before each worker starts, since several runs may share a host and
   * the kickoff fitted this run's workers only once. No room, the job waits
   * (said on the journal), and is asked again. Absent, there is always room.
   */
  hostRoom?: (memoryMib: number) => Promise<{ ok: boolean; available_mib: number | null; needed_mib: number }>;
  destroyWorker: (name: string) => Promise<{ ok: boolean; error?: string }>;
  /**
   * Whether a stop of the run is under way (the hub's `.stop`, which
   * `swarm.sh stop` writes before it puts the seats away): no new worker is
   * started and no new job accepted from then on, so the stop is not raced
   * by a worker started behind it. What waits in the queue is cancelled on
   * the record by the service's own stop.
   */
  holding?: () => boolean;
  /**
   * The service's stop asks again, this many times with this long between,
   * for each worker not confirmed gone when its job ended, and seals it once
   * it is gone (default 3 tries, 2 s apart).
   */
  stopFence?: { tries: number; waitMs: number };
  /**
   * A running worker's CPU and I/O counters (msb's metrics for its VM),
   * when the host has them; absent or null, the worker's own heartbeat is
   * read instead (job-telemetry.ts).
   */
  metrics?: (worker: string) => Promise<{ cpu_ns: number; io_bytes: number } | null>;
  notify: (to: string, body: string) => Promise<void>;
  identity: (agent: string) => Promise<{ name?: string; doing?: string }>;
  log?: (line: string) => void;
  /**
   * A job's network grants bound to it, and how its worker reaches the fetch
   * service: the host port and the job's own token in its environment
   * (net-broker.ts bindJobGrants). Absent, the run has no fetch service and
   * a job given grants is not run.
   */
  netAccess?: (job: JobRecord) => Promise<{ ok: true; port: number; env: Record<string, string> } | { ok: false; reason: string }>;
  /** The lead each of these jobs was run under (the lead register's), for the reuse hints; absent, none is named. */
  leadsOf?: (jobs: string[]) => Promise<Map<string, string>>;
};

const JOB_ID = /^j\d{6}$/;
export const TIMEOUT_MAX_SECONDS = 4 * 3600;
const DETECT_FILES_MAX = 200;

function canonical(v: unknown): string {
  if (Array.isArray(v)) return `[${v.map(canonical).join(",")}]`;
  if (v && typeof v === "object") return `{${Object.keys(v as object).sort().map((k) => `${JSON.stringify(k)}:${canonical((v as Record<string, unknown>)[k])}`).join(",")}}`;
  return JSON.stringify(v);
}

function shQuote(s: string): string {
  return `'${s.replace(/'/g, `'\\''`)}'`;
}

/**
 * The directories of several evidence sets held in place, resolved: each
 * set inputs.json names whose inputs/<name> is a link. Empty for one set
 * (inputs/ is itself the link, or the copy) and for a copy of several. The
 * manifest, which can be hundreds of megabytes, is read only when a link at
 * the top of inputs/ may be a set.
 */
export function boundInputSets(S: string): string[] {
  const top = join(S, "inputs");
  try {
    if (lstatSync(top).isSymbolicLink() || !readdirSync(top, { withFileTypes: true }).some((e) => e.isSymbolicLink())) return [];
  } catch {
    return [];
  }
  let sets: unknown;
  try {
    sets = (JSON.parse(readFileSync(join(S, "inputs.json"), "utf8")) as { sets?: unknown }).sets;
  } catch {
    return [];
  }
  const out: string[] = [];
  for (const set of Array.isArray(sets) ? sets : []) {
    const name = set && typeof set === "object" ? (set as { name?: unknown }).name : undefined;
    if (typeof name !== "string" || !name || name.includes("/") || name === "." || name === "..") continue;
    const link = join(S, "inputs", name);
    try {
      if (lstatSync(link).isSymbolicLink()) out.push(realpathSync(link));
    } catch {
      // A set whose link leads nowhere is not mounted; the job sees it missing.
    }
  }
  return out;
}

export class JobService {
  readonly o: Required<Pick<JobServiceOptions, "perRequesterRunning" | "perRequesterQueued" | "minFreeMb" | "derived">> & JobServiceOptions;
  readonly S: string;
  /** Several sets held in place: their directories, read once (the sets do not change during a run). */
  private boundSets?: string[];
  journal!: Journal;
  readonly jobs = new Map<string, JobRecord>();
  private readonly queue: string[] = [];
  private readonly running = new Map<string, Promise<void>>();
  private readonly watchers = new Map<string, number>();
  private readonly delivered = new Set<string>();
  /** Agents whose request was answered with another's job still under way: told too, once it is done (job → agent → end of its wait). */
  private readonly alsoTell = new Map<string, Map<string, number>>();
  private readonly waitingForSpace = new Set<string>();
  /** Jobs waiting for room on the host, and since when. */
  private readonly waitingForHost = new Map<string, number>();
  private rotation = 0;
  private stopping = false;
  /** Sealing what a stop left, with no hub and nobody to tell (sealLeft). */
  private afterRun = false;
  /** One pump at a time: a call while one runs asks it to go round again. */
  private pumping = false;
  private pumpAgain = false;
  /** The run's job images as their own records have them, read once. */
  private imageRecords: Promise<ImageRecord[]> | null = null;
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
    this.indexOutputsInBackground();
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
      // Each running job sampled every half minute (B11): how long each signal has been still is read from these.
      if (ticks % 15 === 7) void this.sampleRunning().catch(() => undefined);
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
          this.jobs.set(id, { id, attempt: 1, spec: l.spec as JobSpec, requester: l.requester as Requester, state: "accepted", accepted_at: l.at, ...(l.dedup_key ? { dedup_key: String(l.dedup_key) } : {}), ...(l.reuse ? { reuse: l.reuse as Reuse } : {}) });
          break;
        case "job_same_as":
          if (j) j.same_as = l.same_as as SameAs[];
          break;
        case "job_started":
          if (j) Object.assign(j, { state: "running", attempt: Number(l.attempt), started_at: l.at, worker: l.worker, image: l.image, tool_sha256: l.tool_sha256, accessible: l.accessible, network: l.network, ...(l.scope ? { scope: l.scope as JobScope } : {}), ...(l.sensitive_at_start ? { sensitive_at_start: l.sensitive_at_start as Sensitivity } : {}), ...(l.cpus ? { worker_size: `${l.cpus} vCPU, ${l.memory_mib} MiB` } : {}), ...(l.lane ? { lane: l.lane as Lane } : {}), ...(l.image_choice ? { image_choice: l.image_choice as ImageChoice } : {}) });
          break;
        case "job_finished":
          if (j) Object.assign(j, { state: "finished", exit: l.exit as number | null, finished_at: l.at, status: l.status, reason: l.reason });
          if (j?.requester.agent === DERIVED) this.derivedSpent.push({ at: Date.parse(String(l.at)), s: Number(l.duration_ms ?? 0) / 1000 });
          break;
        case "job_fenced":
          if (j && l.fenced) j.state = "fenced";
          break;
        case "job_committed":
          if (j) Object.assign(j, { state: "committed", status: l.status, outputs: l.outputs, image_digest: l.image_digest ?? j.image_digest, ...(l.sensitive ? { sensitive: l.sensitive as Sensitivity } : {}) });
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
          if (j.attempt < 2 && !j.cancel_requested && j.spec.network === "off" && !j.spec.net_grants?.length) {
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
      if (j.state === "committed" && j.spec.seal) await this.publishSeal(j);
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
          const r = JSON.parse(await readFile(join(dir, "recipe.json"), "utf8")) as { runtime?: string; entry?: string; sha256?: string; limits?: { seconds?: number }; auto?: string[]; min_bytes?: number; suffixes?: string[]; magic?: Array<{ offset?: number; hex?: string }>; version?: string; description?: string; purpose?: string; capability?: string; exclusions?: unknown[]; unavailable?: string; secret_output?: unknown };
          const entry = join(dir, String(r.entry ?? ""));
          const sha = sha256Hex(await readFile(entry));
          if (r.sha256 && r.sha256 !== sha) return null;
          const broad = r.purpose === "broad_extraction";
          const unavailable = typeof r.unavailable === "string" && r.unavailable.trim() ? r.unavailable.trim() : undefined;
          const refused = recipeSecretRefusal(id, Object.hasOwn(r, "secret_output"));
          return {
            id,
            dir,
            runtime: r.runtime === "python3" ? "python3" : "bash",
            entry,
            sha256: sha,
            seconds: Number(r.limits?.seconds ?? 900),
            // A recipe the images cannot run, or that carries a declaration it cannot honour, is never triggered.
            auto: unavailable || refused ? [] : (r.auto ?? []),
            ...(refused ? { refused } : {}),
            minBytes: Number(r.min_bytes ?? 0) || 0,
            ...(Array.isArray(r.suffixes) ? { suffixes: r.suffixes.map((x) => String(x).toLowerCase()) } : {}),
            ...(Array.isArray(r.magic) ? { magic: r.magic.filter((m) => Number.isInteger(m.offset) && /^([0-9a-f]{2})+$/i.test(m.hex ?? "")).map((m) => ({ offset: Number(m.offset), bytes: Buffer.from(String(m.hex), "hex") })) } : {}),
            ...(r.version ? { version: String(r.version) } : {}),
            ...(r.description ? { description: String(r.description) } : {}),
            purpose: broad ? "broad_extraction" : "inventory",
            ...(broad ? { capability: String(r.capability ?? "").trim() || id, exclusions: Array.isArray(r.exclusions) ? r.exclusions.map(String) : [] } : {}),
            ...(unavailable ? { unavailable } : {}),
          };
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
        const man = JSON.parse(await readFile(join(this.S, "tools", name, "manifest.json"), "utf8")) as { recipe?: boolean; runtime?: string; entry?: string; sha256?: string; timeout_seconds?: number; secret_output?: unknown };
        if (man.recipe !== true) return null;
        const entry = join(this.S, "tools", name, String(man.entry ?? ""));
        const sha = sha256Hex(await readFile(entry));
        if (man.sha256 !== sha) return null;
        const refused = recipeSecretRefusal(id, Object.hasOwn(man, "secret_output"));
        return { id, dir: join(this.S, "tools", name), runtime: man.runtime === "python3" ? "python3" : man.runtime === "node" ? "node" : "bash", entry, sha256: sha, seconds: Math.min(Number(man.timeout_seconds ?? 900), TIMEOUT_MAX_SECONDS), auto: [], experimental: true, ...(refused ? { refused } : {}) };
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
        if (r && !r.refused && (trigger === "request" || r.auto.includes(trigger))) out.push(r);
      }
    }
    return out;
  }

  /** A pack or forged tool, sealed as its manifest says, and its arguments checked against the manifest's params. */
  private async toolCheck(name: string, args: Record<string, unknown>): Promise<{ ok: true; runtime: string; entry: string; sha256: string; secret: boolean } | { ok: false; reason: string }> {
    if (!/^[a-z0-9_]{1,64}$/.test(name)) return { ok: false, reason: `${name} is not a tool name` };
    let man: { runtime?: string; entry?: string; sha256?: string; secret_output?: unknown; params?: Record<string, { type?: string; required?: boolean; enum?: string[] }> };
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
      // A parameter that is not an object (null, a number, a list) cannot be read: refused, never a TypeError out of submit.
      if (!p || typeof p !== "object" || Array.isArray(p)) return { ok: false, reason: `tool ${name}: its manifest's parameter ${key} is not an object` };
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
    for (const key of Object.keys(args)) if (!Object.hasOwn(man.params ?? {}, key)) return { ok: false, reason: `tool ${name} takes no ${key}` };
    // Its manifest's word on secret output (a job of the tool is run as the
    // agent's secret_output would run it): read here, from the manifest this
    // job runs, and refused when it is not understood.
    const declared = parseSecretDeclaration(man.secret_output, man.params, Object.hasOwn(man, "secret_output"));
    if (!declared.ok) return { ok: false, reason: `tool ${name}: ${declared.reason}` };
    const secret = declaredSecretOutput(declared.declaration as SecretDeclaration | null, args);
    return { ok: true, runtime: man.runtime === "python3" ? "python3" : man.runtime === "node" ? "node" : "bash", entry, sha256: sha, secret };
  }

  /**
   * Accept a job, durably, or refuse it with the reason. The answer comes
   * once the acceptance is on disk; the work comes after.
   */
  async submit(agent: string, raw: Partial<JobSpec>, o: { watch?: number; seal?: SealSpec } = {}): Promise<{ ok: true; job: JobRecord; similar?: Similar[]; similar_recorded?: boolean } | { ok: false; reason: string }> {
    if (this.stopping || this.held()) return { ok: false, reason: "the run is stopping; no new jobs" };
    // A seal comes only from sealCited, never in what an agent sends.
    const { seal: _seal, scope: _scope, ...asked } = raw;
    const spec = await this.normalise(asked, o.seal);
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
    // A command or a tool is never merged (docs/adr/0017): what it reads, by
    // digest, and what it runs are kept, and the jobs of other seats that do
    // the same over the same objects are named to its requester.
    const reuse = !key ? await reuseOf(this.S, spec, { collections: this.collections(), targets: targetPaths(spec) }).catch(() => null) : null;
    await this.journal.append({ type: "job_accepted", job: id, spec, requester, ...(key ? { dedup_key: key } : {}), ...(reuse ? { reuse } : {}) });
    maybeCrash("job:accepted");
    const job: JobRecord = { id, attempt: 1, spec, requester, state: "accepted", accepted_at: new Date().toISOString(), ...(key ? { dedup_key: key } : {}), ...(reuse ? { reuse } : {}) };
    this.jobs.set(id, job);
    // The agent waits for it in job_run from this moment: a job that is done
    // before its first status call is answered there, not posted as well.
    if (o.watch && o.watch > 0) this.watchers.set(id, Date.now() + Math.min(o.watch, 120) * 1000);
    await this.project(job);
    this.queue.push(id);
    void this.pump();
    // The hint, once the job is registered and queued: it never holds the job up.
    const similar = reuse ? await this.similarTo(job, reuse).catch(() => []) : [];
    let recorded = true;
    if (similar.length) {
      await this.journal.append({ type: "job_similar", job: id, by: requester, ...(spec.independent ? { independent: true } : {}), similar }).catch((err) => {
        recorded = false;
        this.log(`${id}: the job_similar line was not written: ${(err as Error).message}`);
      });
    }
    return { ok: true, job, ...(similar.length ? { similar, similar_recorded: recorded } : {}) };
  }

  /**
   * The jobs of other seats, under way or committed, that read some of the
   * same objects by digest with the same tool or the same leading command
   * (job-reuse.ts), ranked, each with its lead and what it made so far.
   */
  private async similarTo(job: JobRecord, reuse: Reuse): Promise<Similar[]> {
    if (job.requester.agent === "system" || job.requester.agent === DERIVED) return [];
    const found: Array<Omit<Similar, "lead">> = [];
    for (const j of this.jobs.values()) {
      if (j.id === job.id || !j.reuse || j.requester.agent === job.requester.agent || j.requester.agent === "system" || j.requester.agent === DERIVED) continue;
      if (j.state === "failed" || j.state === "cancelled" || (j.state === "committed" && j.status === "cancelled")) continue;
      const match = opMatch(job.spec, j.spec, reuse.op, j.reuse.op);
      if (!match) continue;
      const objects = objectsMatch(reuse.objects, j.reuse.objects);
      if (!objects) continue;
      found.push({
        job: j.id,
        seat: j.requester.agent,
        ...(j.requester.name ? { name: j.requester.name } : {}),
        state: j.state,
        ...(j.status ? { status: j.status } : {}),
        ...(j.outputs ? { outputs: { files: j.outputs.files, bytes: j.outputs.bytes, path: j.outputs.path } } : {}),
        ...(j.sensitive ? { sensitive: true as const } : {}),
        ...objects,
        match,
        op: j.reuse.op,
        ...(j.spec.independent ? { independent: true as const } : {}),
      });
    }
    if (!found.length) return [];
    const leads = this.o.leadsOf ? await this.o.leadsOf(found.map((f) => f.job)).catch(() => new Map<string, string>()) : new Map<string, string>();
    return rankSimilar(found.map((f) => ({ ...f, lead: leads.get(f.job) ?? null })));
  }

  /**
   * The image a job runs in, and why: the profile it names; a pack tool's or
   * a recipe's own pack's profile (a recipe may name one in recipe.json); for
   * a command or an import that names none, the smallest job image whose own
   * record holds every program it runs (scripts/image-choice.ts); else the
   * run's worker image. Nothing here knows what a profile holds.
   */
  async imageFor(spec: JobSpec): Promise<{ profile: string | null; ref: string; choice: ImageChoice }> {
    const images = this.o.images ?? {};
    const byProfile = (p: string | undefined | null) => (p && images[p] ? { profile: p, ref: images[p] } : null);
    const dflt = { profile: null, ref: this.o.image };
    if (spec.profile) {
      const hit = byProfile(spec.profile);
      return hit ? { ...hit, choice: { how: "named", why: `the job named the profile ${spec.profile}` } } : { profile: null, ref: this.o.image, choice: { how: "default", why: "the run declared no job images" } };
    }
    if (spec.kind === "tool" && spec.tool) {
      const man = await readFile(join(this.S, "tools", spec.tool, "manifest.json"), "utf8").then((t) => JSON.parse(t) as { pack?: string; profile?: string }).catch(() => null);
      const own = byProfile(man?.profile);
      if (own) return { ...own, choice: { how: "pack", why: `the tool's manifest names the profile ${own.profile}` } };
      const hit = byProfile(man?.pack ? this.o.packProfiles?.[man.pack] : null);
      if (hit) return { ...hit, choice: { how: "pack", why: `the tool's pack ${man?.pack} runs in ${hit.profile}` } };
    }
    if (spec.kind === "recipe" && spec.recipe && !spec.recipe.startsWith("tool:")) {
      const r = await this.recipe(spec.recipe).catch(() => null);
      const declared = r ? await readFile(join(r.dir, "recipe.json"), "utf8").then((t) => (JSON.parse(t) as { profile?: string }).profile).catch(() => undefined) : undefined;
      const own = byProfile(declared);
      if (own) return { ...own, choice: { how: "pack", why: `the recipe names the profile ${own.profile}` } };
      const pack = spec.recipe.split("/")[0];
      const hit = byProfile(this.o.packProfiles?.[pack]);
      if (hit) return { ...hit, choice: { how: "pack", why: `the recipe's pack ${pack} runs in ${hit.profile}` } };
    }
    if (!Object.keys(images).length) return { ...dflt, choice: { how: "default", why: "the run declared no job images" } };
    // What the job runs, as text: a command's own, an import's copy script.
    const text = spec.kind === "command" ? (spec.command ?? "") : spec.kind === "import" ? "python3 /job/import.py" : null;
    if (text === null) {
      const why = spec.kind === "detect" ? "a detect pass asks the recipes of every pack" : spec.kind === "tool" ? "the tool's pack, if it has one, has no job image of its own" : spec.recipe?.startsWith("tool:") ? "a forged tool's recipe, of no pack" : "the recipe's pack has no job image of its own";
      return { ...dflt, choice: { how: "default", why } };
    }
    this.imageRecords ??= readImageRecords(this.S, images);
    return chooseImage(text, await this.imageRecords, dflt);
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

  /**
   * A job as accepted, or refused with the reason. What it reads is kept as
   * said (left out, all, or a list); a list is resolved here, and one entry
   * that does not resolve refuses the job: a scope is never widened to fit.
   */
  private async normalise(raw: Partial<JobSpec>, seal?: SealSpec): Promise<JobSpec | { reason: string }> {
    const spec = await this.normaliseKind(raw, seal);
    if ("reason" in spec) return spec;
    if (spec.scope === "declared" && !spec.seal) {
      const r = await resolveScope(this.S, spec.inputs, { collections: this.collections(), targets: targetPaths(spec) });
      if (!r.ok) return { reason: `${r.reason}. A job reads only what it declares: name the evidence as input:<path> (a directory as input:<dir>/), a job's output as job:<id>[/<path>], a file of yours as work/<you>/<file>, or inputs: ["all"] for everything` };
    }
    return spec;
  }

  private async normaliseKind(raw: Partial<JobSpec>, seal?: SealSpec): Promise<JobSpec | { reason: string }> {
    const kind = raw.kind;
    if (kind !== "tool" && kind !== "command" && kind !== "recipe" && kind !== "detect" && kind !== "import") return { reason: "a job is a tool, a command, a recipe, a detect pass or an import" };
    const timeout = Math.min(Math.max(Number(raw.timeout_seconds ?? 900) || 900, 10), TIMEOUT_MAX_SECONDS);
    const network = raw.network === "allowlist" ? "allowlist" : "off";
    // Left out, all, or a list: kept apart in the spec and on the journal.
    const declared = declaredScope(raw.inputs);
    if ("reason" in declared) return { reason: declared.reason };
    const inputs = declared.inputs;
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
    // Network grants go with a command or a tool (a job whose code makes the request); at most eight.
    const grants = Array.isArray(raw.net_grants) ? [...new Set(raw.net_grants.map((g) => String(g).trim().toUpperCase()))].filter(Boolean) : [];
    if (grants.length && kind !== "command" && kind !== "tool") return { reason: "network grants go with a command or a tool job" };
    if (grants.some((g) => !/^N-[1-9]\d{0,6}$/.test(g)) || grants.length > 8) return { reason: "net_grants names up to 8 grants, N-<k>" };
    if (raw.secret_output !== undefined && typeof raw.secret_output !== "boolean") return { reason: "secret_output is true or false" };
    const base = { kind, inputs, scope: declared.kind, timeout_seconds: timeout, network, ...(raw.scratch ? { scratch: true } : {}), ...(raw.note ? { note: String(raw.note) } : {}), ...(raw.parent ? { parent: String(raw.parent) } : {}), ...(profile ? { profile } : {}), ...(grants.length ? { net_grants: grants } : {}), ...(raw.independent === true && (kind === "command" || kind === "tool") ? { independent: true } : {}), ...(raw.secret_output === true ? { secret_output: true } : {}) } as JobSpec;
    if (kind === "tool") {
      const args = raw.args && typeof raw.args === "object" && !Array.isArray(raw.args) ? raw.args : {};
      const checked = await this.toolCheck(String(raw.tool ?? ""), args);
      if (!checked.ok) return { reason: checked.reason };
      // The tool's manifest says this job is secret output: so it is, whatever the agent said (false included).
      if (checked.secret) return { ...base, secret_output: true, secret_output_by: "tool_manifest", tool: String(raw.tool), args };
      return { ...base, tool: String(raw.tool), args };
    }
    if (kind === "command") {
      const command = String(raw.command ?? "");
      if (!command.trim()) return { reason: "a command job needs its command" };
      if (Buffer.byteLength(command) > 64 * 1024) return { reason: "a command is at most 64 KB; put a longer script in your scratch and run it from there" };
      return { ...base, command };
    }
    if (kind === "import") {
      if (seal) {
        // The hub's own seal of a cited brain-side output: the kept file, or
        // the trace line written into the job's view; a short job, no network.
        const source = seal.kind === "tool" ? String(seal.path ?? "") : `traces/trace-${seal.line_sha256}.json`;
        if (seal.kind === "tool" && !/^tool-output\/[a-z][a-z0-9_-]{0,31}\/./.test(source)) return { reason: `${seal.ref}: not a kept output under tool-output/<seat>/` };
        return { ...base, kind: "import", source, inputs: seal.kind === "tool" ? [source] : [], scope: "declared", network: "off", timeout_seconds: SHORT_JOB_SECONDS, seal };
      }
      // A file an agent made in its VM, sealed as it is now: work/ or
      // tool-output/ only, named from the run's directory, never out of it.
      // Its scope is its source, snapshotted by the hub at the job's start.
      const source = String(raw.source ?? "").trim().replace(/^\.\//, "").replace(/\/+$/, "");
      if (!/^(work|tool-output)\/./.test(source) || source.split("/").includes("..") || source.includes("\0")) return { reason: "an import names a file or directory under work/ or tool-output/, from the run's directory" };
      const abs = join(this.S, source);
      const st = await lstat(abs).catch(() => null);
      if (!st) return { reason: `${source} does not exist` };
      if (!st.isFile() && !st.isDirectory()) return { reason: `${source} is not a regular file or a directory (a link is not followed)` };
      return { ...base, kind: "import", source, inputs: [source], scope: "declared", network: "off" };
    }
    if (kind === "recipe") {
      const r = raw.recipe ? await this.recipe(String(raw.recipe)) : null;
      if (!r) return { reason: `no recipe ${raw.recipe ?? "(none named)"} in this run's packs${this.o.forging ? " (a forged tool is named tool:<name> and must declare \"recipe\": true)" : ""}` };
      if (r.refused) return { reason: r.refused };
      if (r.unavailable) return { reason: `${r.id} is declared by its pack but cannot run in this run's job images: ${r.unavailable}. Its preparation of each source it applies to is recorded declined with that why; read the source with the tools the images hold` };
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

  /** The lane a job waits in (see Lane). */
  laneOf(job: JobRecord): Lane {
    if (job.requester.agent === DERIVED) return "derived";
    if (job.requester.agent === "system") return "kickoff";
    return job.spec.timeout_seconds <= SHORT_JOB_SECONDS ? "short" : "general";
  }

  /** Workers kept for short jobs: one, from SHORT_LANE_FROM_WORKERS workers. */
  shortSlots(): number {
    return this.o.workers >= SHORT_LANE_FROM_WORKERS ? 1 : 0;
  }

  /**
   * Whether a queued job may take a free worker now. Counted over the jobs
   * the queue has handed a worker and that are not done (this.running), not
   * over those whose job_started line is written: a job picked a moment ago
   * is still "accepted" until then, and counting by state let the derived
   * lane run two recipes at once past its ceiling (tests/derived-catalog's
   * ceiling test, which timed out on a Linux runner) and let one agent take
   * more workers than its own limit.
   */
  private startable(job: JobRecord): boolean {
    const lane = this.laneOf(job);
    const running = [...this.running.keys()].map((id) => this.jobs.get(id)).filter((j): j is JobRecord => Boolean(j));
    const short = running.filter((j) => this.laneOf(j) === "short").length;
    // The worker kept for short jobs is never a longer one's, even when idle.
    if (lane !== "short" && running.length - short >= this.o.workers - this.shortSlots()) return false;
    if (lane === "derived") return !running.some((j) => this.laneOf(j) === "derived");
    if (lane === "kickoff") return true;
    // Each agent so many at once in each lane: its own long parses do not hold back its quick look.
    return running.filter((j) => j.requester.agent === job.requester.agent && (this.laneOf(j) === "short") === (lane === "short")).length < this.o.perRequesterRunning;
  }

  /**
   * Start what may start: the run's worker limit, the worker kept for short
   * jobs, each agent's own limit, agents taken in turn, free disk, and room
   * on the host. One pump at a time: its checks and its start are one step.
   */
  async pump(): Promise<void> {
    if (this.stopping || this.held()) return;
    if (this.pumping) {
      this.pumpAgain = true;
      return;
    }
    this.pumping = true;
    try {
      do {
        this.pumpAgain = false;
        await this.pumpOnce();
      } while (this.pumpAgain && !this.stopping);
    } finally {
      this.pumping = false;
    }
  }

  /**
   * Whether a stop is under way (the `holding` option): said once in the
   * log, and from then on no worker is started. A check that throws is
   * taken as no stop.
   */
  private holdSaid = false;
  private held(): boolean {
    let h = false;
    try {
      h = this.o.holding?.() === true;
    } catch {
      h = false;
    }
    if (h && !this.holdSaid) {
      this.holdSaid = true;
      this.log(`a stop is under way: no new worker is started (${this.queue.length} queued)`);
    }
    return h;
  }

  private async pumpOnce(): Promise<void> {
    await this.maybeDrainDerived();
    while (!this.stopping && !this.held() && this.running.size < this.o.workers && this.queue.length) {
      const requesters = [...new Set(this.queue.map((id) => this.jobs.get(id)?.requester.agent ?? ""))];
      // The derived catalogue's work is the lowest lane: one at a time,
      // started only when no other job waits, and only within its budget.
      const othersWaiting = this.queue.some((id) => this.jobs.get(id)?.requester.agent !== DERIVED);
      let picked: string | undefined;
      for (let k = 0; k < requesters.length && !picked; k += 1) {
        const agent = requesters[(this.rotation + k) % requesters.length];
        // Its oldest job that may start: a short one is not held behind its own long one.
        const next = this.queue.find((id) => {
          const j = this.jobs.get(id);
          return j !== undefined && j.requester.agent === agent && this.startable(j);
        });
        if (!next) continue;
        if (agent === DERIVED && (othersWaiting || !(await this.derivedMayRun()))) continue;
        // A cancel while the budget was read takes it out of the queue.
        if (this.queue.includes(next)) picked = next;
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
      if (this.o.hostRoom) {
        const room = await this.o.hostRoom(this.o.workerMemoryMib).catch(() => null);
        if (room && !room.ok) {
          if (!this.waitingForHost.has(picked)) {
            this.waitingForHost.set(picked, Date.now());
            this.log(`${picked} waits: ${room.available_mib ?? "?"} MiB available on this host, ${room.needed_mib} MiB needed to start a worker beside what runs`);
            await this.journal.append({ type: "job_waits_for_host", job: picked, available_mib: room.available_mib, needed_mib: room.needed_mib, worker_memory_mib: this.o.workerMemoryMib });
          }
          return;
        }
        if (!this.queue.includes(picked)) continue;
      }
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

  /** The input_collection lines of the store: each input's segment set, as the census recorded it. */
  private collections(): string[][] {
    return this.journal.of("input_collection").map((l) => [String(l.input), ...((l.members as string[] | undefined) ?? [])]);
  }

  /**
   * What a job's worker is given. A declared scope: the view the hub builds
   * for it (job-scope.ts) — only what it declared, at the paths its brain
   * sees them — with the reviewed code (tools/, the packs), its own $OUT and
   * the control directory. Otherwise the broad view jobs always had (below),
   * recorded as such. Throws a ScopeError when a declared object cannot be
   * given: the job then does not run.
   */
  private async placement(job: JobRecord, st: { base: string; out: string; ctl: string }, observe = false): Promise<{ mounts: Mount[]; accessible: Array<{ path: string; access: string }>; manifest: Record<string, unknown> | null; view: { objects: number; files: number; bound: number } | null }> {
    const kind = scopeKindOf(job.spec);
    const tail: Array<Mount & { note?: string }> = [];
    for (const pack of this.o.packDirs) if (existsSync(pack)) tail.push({ host: pack, guest: pack, readonly: true });
    tail.push({ host: st.out, guest: this.outPath(job), noexec: true });
    tail.push({ host: st.ctl, guest: "/job", noexec: true });
    const accessOf = (list: Array<Mount & { note?: string }>) => list.map((m) => ({ path: m.guest ?? m.host, access: `${m.readonly ? "read-only" : "read-write"}${m.noexec ? ", no-exec" : ""}${m.note ? `; ${m.note}` : ""}` }));
    const strip = (list: Array<Mount & { note?: string }>) => list.map(({ note: _note, ...m }) => m);
    if (kind !== "declared") {
      const all = [...this.broadMounts(), ...tail];
      return { mounts: strip(all), accessible: accessOf(all), manifest: null, view: null };
    }
    const resolved = await resolveScope(this.S, job.spec.inputs, { collections: this.collections(), targets: targetPaths(job.spec) });
    if (!resolved.ok) throw new ScopeError(resolved.reason);
    // A trace line being sealed is written into the view by the hub, from the chained trace.
    const extra: Array<{ path: string; bytes: Buffer; ref: string }> = [];
    if (job.spec.seal?.kind === "trace") {
      const bytes = await traceLineBytes(this.S, job.spec.seal.line_sha256);
      if (!bytes) throw new ScopeError(`${job.spec.seal.ref}: the trace no longer holds that line`);
      extra.push({ path: job.spec.source ?? "", bytes, ref: job.spec.seal.ref });
    }
    // EXPERIMENTAL: a file the job's user reads before and after its command, which the collector must see.
    if (observe) extra.push({ path: CANARY_NAME, bytes: Buffer.from(`${job.id}.${job.attempt}.${Math.random().toString(36).slice(2)}\n`), ref: "the observation's canary" });
    const view = await buildView(resolved.objects, { S: this.S, root: join(st.base, VIEW_DIR), projected: join(storePaths(this.S).staging, PROJECTED_DIR), guestOut: this.outPath(job), minFreeMb: Math.floor(this.o.minFreeMb / 4), extra });
    // A seal: what the job copies is what the trace recorded, or it does not run.
    if (job.spec.seal) {
      const e = view.entries.find((x) => x.path === job.spec.source);
      if (!e || e.sha256 !== job.spec.seal.digest) throw new ScopeError(`${job.spec.seal.ref}: ${job.spec.source} reads as sha256 ${e?.sha256?.slice(0, 16) ?? "?"}…, not the ${job.spec.seal.digest.slice(0, 16)}… the trace recorded (line ${job.spec.seal.line_sha256.slice(0, 12)}…): it changed since, and what the trace saw is gone. Run the work again as a job (job_run) and cite job:<id>/<path>`);
    }
    const all = [...view.mounts, ...tail];
    const files = view.entries.filter((e) => e.how !== "bound" && e.how !== "left out").length;
    const bound = view.entries.filter((e) => e.how === "bound").length;
    const manifest = {
      v: 1,
      job: job.id,
      attempt: job.attempt,
      kind,
      declared: job.spec.inputs,
      expanded: resolved.objects satisfies ScopeObject[],
      accessible: view.entries satisfies ViewEntry[],
      mounts: accessOf(all),
      observed: "not observed: the reads within this scope are not recorded",
    };
    return { mounts: strip(all), accessible: accessOf(all), manifest, view: { objects: resolved.objects.length, files, bound } };
  }

  /**
   * The broad view, for a job that declared nothing or `all`: what its brain
   * sees, read-only — the evidence, store/, catalog/, tools/, all of work/
   * (every agent's live scratch and the shared files; the extracted and
   * quarantined corners no-exec) and tool-output/ — beside the packs and its
   * own $OUT, the one writable place, outside work/. Never the board, the
   * inbox, the ledger, the sessions or the budget.
   */
  private broadMounts(): Array<Mount & { note?: string }> {
    const S = this.S;
    const mounts: Array<Mount & { note?: string }> = [];
    const inputs = join(S, "inputs");
    if (existsSync(inputs)) {
      mounts.push({ host: inputs, guest: inputs, readonly: true, noexec: true });
      // Several sets held in place: inputs/ holds a link per set, and each
      // set's directory is mounted at its own path, where its link leads, as
      // in the agents' VMs.
      this.boundSets ??= boundInputSets(S);
      for (const dir of this.boundSets) mounts.push({ host: dir, guest: dir, readonly: true, noexec: true });
    }
    for (const rel of ["store", "catalog", "tools", "tool-output"]) if (existsSync(join(S, rel))) mounts.push({ host: join(S, rel), guest: join(S, rel), readonly: true });
    if (existsSync(join(S, "work"))) {
      mounts.push({ host: join(S, "work"), guest: join(S, "work"), readonly: true, note: "every agent's live scratch and the shared files: they may change while the job runs" });
      for (const corner of ["extracted", "quarantine"]) if (existsSync(join(S, "work", corner))) mounts.push({ host: join(S, "work", corner), guest: join(S, "work", corner), readonly: true, noexec: true });
    }
    return mounts;
  }

  /** Where a job writes, in its VM: its own directory in the run, outside work/ (which it sees read-only). */
  outPath(job: JobRecord): string {
    return join(this.S, ".jobs", job.id);
  }

  private async script(job: JobRecord, ctl: string, observe: { mounts: string[]; canary: string } | null = null): Promise<{ lines: string[]; tool_sha256?: string }> {
    const q = shQuote;
    const out = this.outPath(job);
    const box = job.spec.timeout_seconds;
    // A job with network may install what it needs for itself: what pip
    // holds before and after is kept with its logs, so the record says what
    // the job ran with beyond the image.
    const pip = job.spec.network === "allowlist" ? ["python3 -m pip list --format=freeze > /job/pip-before.txt 2>/dev/null || true"] : [];
    const pipAfter = job.spec.network === "allowlist" ? ["python3 -m pip list --format=freeze > /job/pip-after.txt 2>/dev/null || true"] : [];
    // EXPERIMENTAL (SWARM_JOB_OBSERVE=fanotify-experimental, a declared scope only): the command as an unprivileged user, a collector watching the view's mounts.
    // A heartbeat beside the command (job-telemetry.ts): the VM's CPU and I/O counters every 15 s, for the host to read while it runs.
    const run = (cmd: string) =>
      observe
        ? [...pip, ...HEARTBEAT_LINES, ...observedRun({ mounts: observe.mounts, canary: observe.canary, cmd: `timeout --kill-after=10 ${box} ${cmd} > /job/stdout.log 2> /job/stderr.log` }), HEARTBEAT_STOP, ...pipAfter]
        : [...pip, ...HEARTBEAT_LINES, `timeout --kill-after=10 ${box} ${cmd} > /job/stdout.log 2> /job/stderr.log`, "echo $? > /job/exit", HEARTBEAT_STOP, ...pipAfter];
    // SECRET_OUTPUT=1 for a job run as secret output (the agent's flag, or its tool's manifest), so a tool can refuse a values mode in a job that is not; unset for any other, whatever the image carries.
    const head = ["#!/bin/bash", "set -u", `cd ${q(this.S)} 2>/dev/null || cd /`, `export OUT=${q(out)}`, job.spec.secret_output === true ? "export SECRET_OUTPUT=1" : "unset SECRET_OUTPUT"];
    if (job.spec.kind === "tool") {
      const checked = await this.toolCheck(job.spec.tool ?? "", job.spec.args ?? {});
      if (!checked.ok) throw new Error(checked.reason);
      // The manifest now declares what the job's spec, taken at acceptance, does not carry: not run unsealed.
      if (checked.secret && job.spec.secret_output !== true) throw new Error(`tool ${job.spec.tool}: its manifest declares this job secret output, but the job was accepted without that (the manifest changed since); ask for it again`);
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
      return { lines: [...head, ...run(`python3 /job/import.py ${q(this.S)} ${q(job.spec.source ?? "")} ${IMPORT_HASH_BOUND} ${scopeKindOf(job.spec) === "declared" ? "snapshot" : "live"}`)] };
    }
    if (job.spec.kind === "recipe") {
      const r = await this.recipe(job.spec.recipe ?? "");
      if (!r) throw new Error(`recipe ${job.spec.recipe} is no longer what it was when accepted`);
      // The manifest or recipe.json may carry the key now, though it did not when the job was accepted: not run.
      if (r.refused) throw new Error(r.refused);
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
    // The kickoff's allowlist, and every host the operator allowed since
    // (swarm.sh lead <run> note L-n TEXT --allow-host HOST): an agent's own
    // VM keeps the network it booted with, and a job's worker is made new,
    // so this is where a host allowed while the run goes on is reached.
    // The operator's socket grants (tier 2) for this job's requester decide
    // (net-grants.ts jobNetworkHosts): a host the operator took back is not
    // given to a new worker in any spelling, and a note's host line counts
    // only where no grant was ever made for that host.
    const hosts = jobNetworkHosts(this.S, this.o.allowHosts, job.requester.agent);
    return hosts.length ? { mode: "hosts", hosts } : { mode: "off" };
  }

  /**
   * The worker a job runs in, as a spec: its control scripts written under
   * `base`, its mounts (the view of a declared scope, built at `base`/view,
   * or the broad view), its image (the one it is recorded to have run in, or
   * the one chosen for it now), its network and its limits. A function of
   * the recorded job and a staging directory, so a rerun builds the same
   * worker the job had: `base` must be outside every VM's reach, as the job
   * service's own staging is. Throws a ScopeError when a declared object
   * cannot be given.
   */
  async workerSpecFor(job: JobRecord, base: string = this.staging(job).base): Promise<WorkerPlan> {
    const st = { base, out: join(base, "out"), ctl: join(base, "job") };
    await mkdir(st.out, { recursive: true });
    await mkdir(st.ctl, { recursive: true });
    const observe = this.observing(job);
    const placed = await this.placement(job, st, observe);
    // Observed: the collector's script beside the job's, its own mount, and the view's evidence-bearing mounts to watch.
    let watch: { mounts: string[]; canary: string } | null = null;
    if (observe) {
      await writeFile(join(st.ctl, "observe.py"), await readFile(new URL("./job-observe.py", import.meta.url)));
      await mkdir(join(st.base, "observe"), { recursive: true, mode: 0o700 });
      placed.mounts.push({ host: join(st.base, "observe"), guest: OBSERVE_GUEST, noexec: true });
      placed.accessible.push({ path: OBSERVE_GUEST, access: "read-write, no-exec; the experimental collector's log, root's alone in the worker" });
      watch = { mounts: placed.mounts.filter((m) => m.readonly && (m.guest ?? m.host).startsWith(this.S) && (m.view || m.expect)).map((m) => m.guest ?? m.host), canary: join(this.S, CANARY_NAME) };
    }
    const script = await this.script(job, st.ctl, watch);
    await writeFile(join(st.ctl, "run.sh"), `${script.lines.join("\n")}\n`);
    // A job that ran keeps its image (a retry, a rerun); a new one is placed by its spec.
    const chosen = job.image ? { profile: null, ref: job.image, choice: job.image_choice ?? { how: "default" as const, why: "the image it is recorded to have run in" } } : await this.imageFor(job.spec);
    const network = this.network(job);
    // Its network grants: bound to it, and the fetch service's port and the
    // job's own token given to its worker. A job that cannot have them is not run.
    let net: { port: number; env: Record<string, string> } | null = null;
    if (job.spec.net_grants?.length) {
      if (!this.o.netAccess) throw new Error(`not run: this run has no fetch service for its network grants (${job.spec.net_grants.join(", ")})`);
      const acc = await this.o.netAccess(job);
      if (!acc.ok) throw new Error(`not run: its network grants: ${acc.reason}`);
      net = { port: acc.port, env: acc.env };
      await writeFile(join(st.ctl, "net_fetch.py"), NET_FETCH_SCRIPT);
    }
    const spec: WorkerSpec = {
      name: `dfs-${this.o.run}-job-${job.id}-${job.attempt}`,
      image: chosen.ref,
      run: this.o.run,
      job: job.id,
      attempt: job.attempt,
      ...(this.o.registry ? { registry: this.o.registry } : {}),
      cpus: this.o.workerCpus,
      memoryMib: this.o.workerMemoryMib,
      maxDurationSec: job.spec.timeout_seconds + 120,
      workdir: this.S,
      mounts: placed.mounts,
      env: { JOB_ID: job.id, OUT: this.outPath(job), AGENT_ID: job.requester.agent, SWARM_SANDBOX: this.S, TZ: "UTC", LANG: "C.UTF-8", PYTHONDONTWRITEBYTECODE: "1", NO_COLOR: "1", ...(job.spec.secret_output === true ? { SECRET_OUTPUT: "1" } : {}), ...(net?.env ?? {}) },
      network,
      ...(net ? { hostPorts: [net.port] } : {}),
      command: ["bash", "/job/run.sh"],
    };
    return { spec, accessible: placed.accessible, manifest: placed.manifest, view: placed.view, chosen, script };
  }

  /**
   * Whether this job's reads are observed: EXPERIMENTAL and untested in a
   * worker VM, off unless SWARM_JOB_OBSERVE=fanotify-experimental, and only
   * over a declared scope (a detect pass runs its probes in its own loop).
   */
  private observing(job: JobRecord): boolean {
    return observeWanted() && scopeKindOf(job.spec) === "declared" && job.spec.kind !== "detect";
  }

  /**
   * EXPERIMENTAL: the collector's log read after the worker is gone, kept
   * whole beside the job's record with what it says (complete, partial or
   * unknown, and why), on the journal as job_observed. job_started keeps
   * `observed: "unknown"`: this is a prototype's word, not custody's.
   */
  private async readObserved(job: JobRecord, base: string): Promise<void> {
    const dir = join(base, "observe");
    const text = await readFile(join(dir, "events.jsonl"), "utf8").catch(() => null);
    const key = await readFile(join(dir, "key"), "utf8").catch(() => null);
    // The declared scope as the view gave it (the job's scope manifest): every object, at its path in the worker.
    const manifest = job.scope?.manifest ? await readFile(join(this.S, job.scope.manifest), "utf8").then((t) => JSON.parse(t) as { accessible?: Array<{ path: string; left_out?: string }> }).catch(() => null) : null;
    const scope = (manifest?.accessible ?? []).filter((e) => !e.left_out).map((e) => join(this.S, e.path.replace(/\/$/, "")));
    const seen = readObservation(text, key, { scope, canary: join(this.S, CANARY_NAME) });
    const jobDir = join(storePaths(this.S).jobs, job.id);
    const logRel = `store/jobs/${job.id}/observe.${job.attempt}.jsonl`;
    const readRel = `store/jobs/${job.id}/observed.${job.attempt}.json`;
    await mkdir(jobDir, { recursive: true });
    if (text !== null) await writeFile(join(this.S, logRel), text, { mode: 0o444 });
    const summary = `${JSON.stringify({ experimental: true, ...seen }, null, 2)}\n`;
    await writeFile(join(this.S, readRel), summary, { mode: 0o444 });
    await this.journal.append({ type: "job_observed", job: job.id, attempt: job.attempt, experimental: true, status: seen.status, reasons: seen.reasons, opened: seen.opened.length, escapes: seen.escapes.length, overflow: seen.overflow, ...(text !== null ? { log: logRel, log_sha256: sha256Hex(text) } : {}), read: readRel, read_sha256: sha256Hex(summary) });
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
    let plan: WorkerPlan;
    try {
      plan = await this.workerSpecFor(job, st.base);
    } catch (err) {
      // Not run: a script that cannot be written, or a declared object that cannot be given (the reason says which).
      const reason = err instanceof ScopeError ? `not run: ${err.message}` : (err as Error).message;
      await this.journal.append({ type: "job_failed", job: job.id, reason });
      Object.assign(job, { state: "failed", status: "failed", reason });
      await this.project(job);
      await this.tell(job);
      await rm(st.base, { recursive: true, force: true }).catch(() => undefined);
      return;
    }
    const { spec: workerSpec, accessible, chosen, script } = plan;
    const worker = workerSpec.name;
    const network = workerSpec.network;
    const netText = `${network.mode === "off" ? "none" : network.mode === "public" ? "every public host" : `the run's allowlist (${network.hosts.join(", ")})`}${workerSpec.hostPorts?.length ? `; the fetch service on this host for its grants ${job.spec.net_grants?.join(", ")}, each request exactly as granted` : ""}`;
    // The declared scope's manifest beside the job's record, its sha256 on job_started.
    const scope: JobScope = { kind: scopeKindOf(job.spec) };
    if (plan.manifest) {
      const rel = `store/jobs/${job.id}/scope.${job.attempt}.json`;
      const text = scopeManifestText(plan.manifest);
      await mkdir(join(this.S, "store", "jobs", job.id), { recursive: true });
      await chmod(join(this.S, rel), 0o644).catch(() => undefined);
      await writeFile(join(this.S, rel), text);
      await chmod(join(this.S, rel), 0o444).catch(() => undefined);
      Object.assign(scope, plan.view ?? {}, { manifest: rel, manifest_sha256: sha256Hex(text) });
    }
    // Why it is sensitive, if it already is (docs/adr/0016): what it declared, or for a job with no scope what its text names.
    // The job runs either way; this records the dependency and what it could read, and nothing is refused or hidden.
    const atStart = await this.sensitiveAtStart(job, scope);
    // Which lane it took, how it came to its image, and how long it waited for room on the host.
    const lane = this.laneOf(job);
    const since = this.waitingForHost.get(job.id);
    this.waitingForHost.delete(job.id);
    const hostWait = since !== undefined ? { host_wait_ms: Date.now() - since } : {};
    const imageChoice = Object.keys(this.o.images ?? {}).length ? { image_choice: chosen.choice } : {};
    await this.journal.append({ type: "job_started", job: job.id, attempt: job.attempt, worker, image: chosen.ref, ...(chosen.profile ? { profile: chosen.profile } : {}), ...imageChoice, lane, ...hostWait, ...(script.tool_sha256 ? { tool_sha256: script.tool_sha256 } : {}), declared: job.spec.inputs, scope, ...(atStart ? { sensitive_at_start: atStart } : {}), accessible, observed: "unknown", network: netText, cpus: this.o.workerCpus, memory_mib: this.o.workerMemoryMib });
    Object.assign(job, { state: "running", worker, worker_size: `${this.o.workerCpus} vCPU, ${this.o.workerMemoryMib} MiB`, started_at: new Date().toISOString(), image: chosen.ref, lane, ...imageChoice, accessible, scope, ...(atStart ? { sensitive_at_start: atStart } : {}), network: netText, ...(script.tool_sha256 ? { tool_sha256: script.tool_sha256 } : {}) });
    await this.project(job);
    maybeCrash("job:started");
    const started = Date.now();
    const guard = setInterval(() => void this.watchDisk(job, worker), 15_000);
    guard.unref?.();
    let result: Awaited<ReturnType<JobServiceOptions["runWorker"]>>;
    try {
      result = await this.o.runWorker(workerSpec);
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
    const failed = !cancelled && !stopped && exit !== null && exit !== 0 && exit !== 124 && exit !== 137;
    // A program its worker could not execute: nothing runs where it stands in
    // store/, work/extracted/, inputs/ or $OUT (job-exec-refused.ts). Read
    // first: the loader's refusal to map a segment ends in exit 127, which is
    // no program missing from the image.
    const unexecuted = failed ? await execRefused({ ctl: st.ctl, out: st.out, cwd: this.S, exit }).catch(() => null) : null;
    if (unexecuted) {
      job.exec_refused = unexecuted;
      await this.journal.append({ type: "job_exec_refused", job: job.id, attempt: job.attempt, exit, ...unexecuted });
    }
    // A program its image does not hold (B17): exit 127, or the shell's own words for it.
    const missing = !cancelled && !stopped && !unexecuted && exit !== 0 ? await programMissing(st.ctl, exit) : null;
    if (missing) {
      job.program_missing = { program: missing, profile: chosen.profile ?? job.spec.profile ?? null, image: chosen.ref };
      await this.journal.append({ type: "job_program_missing", job: job.id, attempt: job.attempt, exit, ...job.program_missing });
    }
    // A write its worker refused: the run is read-only there, only $OUT (and
    // its control directory) writable, as the worker and the host name them.
    const writable = [...new Set([this.outPath(job), st.out, st.ctl, ...accessible.filter((a) => a.access.startsWith("read-write")).map((a) => a.path)])];
    const refused = failed && !unexecuted && !missing ? await writeRefused({ ctl: st.ctl, out: st.out, cwd: this.S, writable }).catch(() => null) : null;
    if (refused) {
      job.write_refused = refused;
      await this.journal.append({ type: "job_write_refused", job: job.id, attempt: job.attempt, exit, ...refused });
    }
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
            : unexecuted
              ? `exit ${exit}: ${execRefusedWords(unexecuted, { job: job.id, out: this.outPath(job), cwd: this.S })}`
              : missing
                ? `exit ${exit}: a program it runs is not in its image${job.program_missing?.profile ? ` (profile ${job.program_missing.profile})` : ""}: ${missing === "?" ? "exit 127" : missing}`
                : refused
                  ? `exit ${exit}: ${writeRefusedWords(refused, { job: job.id, out: this.outPath(job) })}`
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
    if (this.observing(job)) await this.readObserved(job, st.base).catch((err: Error) => this.log(`${job.id}: its observation could not be read: ${err.message}`));
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
    if (!recorded) return;
    // The hint is written outside the store's one-at-a-time section: it never holds a commit up.
    if (job.same_as?.length) await this.writeSameAs(job);
    await this.afterCommit(job);
  }

  private async sealAndRecord(job: JobRecord, r: { status: NonNullable<JobRecord["status"]>; exit: number | null; reason?: string }, where: string): Promise<boolean> {
    const P = storePaths(this.S);
    const st = this.staging(job);
    const jobDir = join(P.jobs, job.id);
    const dest = join(jobDir, where);
    await mkdir(jobDir, { recursive: true });
    let sealed: { manifest: Manifest; manifestSha256: string };
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
    // Sensitive at seal time (docs/adr/0016): run with secret_output, or made from a sensitive output.
    const sensitive = await this.sensitivityOf(job, sealed.manifest.files).catch((err: Error) => {
      this.log(`${job.id}: its sensitivity could not be decided (${err.message}); sealed as sensitive`);
      return { why: "derived" as const, from: [], note: `its sensitivity could not be decided when it was sealed (${err.message}): held sensitive` };
    });
    await this.journal.append({ type: "job_committed", job: job.id, attempt: job.attempt, status: r.status, exit: r.exit, ...(r.reason ? { reason: r.reason } : {}), outputs, logs, ...(job.image_digest ? { image_digest: job.image_digest } : {}), ...(sensitive ? { sensitive } : {}) });
    await rm(st.base, { recursive: true, force: true }).catch(() => undefined);
    if (where !== "out") return false;
    // In memory only, before the record says committed (whoever reads the
    // job then reads its hint too): no read, no write, no wait here. The
    // sensitivity above never waits on that index: it read the sensitive
    // jobs' own manifests before job_committed was written.
    this.sameAsAtCommit(job, sealed.manifest.files ?? []);
    Object.assign(job, { state: "committed", status: r.status, outputs, ...(sensitive ? { sensitive } : {}) });
    await this.project(job);
    maybeCrash("job:committed");
    return true;
  }

  /**
   * Every committed job's output by content, the first job to write given
   * bytes keeping them. Built once from the manifests, off the commit path
   * (indexOutputsInBackground); null until it is.
   */
  private outputIndex: Map<string, { job: string; file: string }> | null = null;
  /** Jobs committed while the index was being built, in commit order: their same_as is said once it is. */
  private sameAsPending: Array<{ job: JobRecord; files: Manifest["files"] }> = [];

  /**
   * The index of every earlier job's output, read from the manifests of the
   * jobs the journal says were committed, one at a time, in the background:
   * a slow or unreadable manifest delays only the hints of the jobs committed
   * meanwhile, never a commit. Those are then answered in order.
   */
  private indexOutputsInBackground(): void {
    const ids = this.journal.of("job_committed").filter((l) => (l.outputs as { path?: string } | undefined)?.path === `store/jobs/${String(l.job ?? "")}/out`).map((l) => String(l.job));
    void (async () => {
      const index = new Map<string, { job: string; file: string }>();
      for (const id of ids) {
        const m = await readManifest(join(storePaths(this.S).jobs, id, "manifest.json")).catch(() => null);
        if (m) indexOutputs(index, id, m.manifest.files);
      }
      this.outputIndex = index;
      const pending = this.sameAsPending.splice(0);
      for (const p of pending) {
        this.sameAsAtCommit(p.job, p.files);
        if (p.job.same_as?.length) {
          await this.writeSameAs(p.job);
          await this.project(p.job).catch(() => undefined);
        }
      }
    })().catch((err) => this.log(`the output index for same_as was not built: ${(err as Error).message}`));
  }

  /**
   * Which of a committed job's files are an earlier job's output byte for
   * byte (docs/adr/0017), set on its record from the index in memory, or
   * left for the index to answer when it is still being built. A hint: the
   * files are sealed and cited as the job's own either way.
   */
  private sameAsAtCommit(job: JobRecord, files: Manifest["files"]): void {
    if (!this.outputIndex) {
      this.sameAsPending.push({ job, files });
      return;
    }
    const same = sameAsOf(job.id, files, this.outputIndex);
    indexOutputs(this.outputIndex, job.id, files);
    if (same.length) job.same_as = same;
  }

  /** The job_same_as line; a failure to write it is logged, never raised. */
  private async writeSameAs(job: JobRecord): Promise<void> {
    await this.journal.append({ type: "job_same_as", job: job.id, same_as: job.same_as ?? [] }).catch((err) => this.log(`${job.id}: the job_same_as line was not written: ${(err as Error).message}`));
  }

  /**
   * Whether what a job sealed is sensitive (docs/adr/0016): it was run with
   * secret_output, or it read a sensitive output. What it read is what it
   * declared (resolved again now: a sealed output does not change), by path,
   * by digest, or a catalogue generation a sensitive job made; a job that
   * declared no scope could read everything, so it is held to what its
   * command, arguments, source and targets name; and a file it sealed that is
   * byte for byte what a sensitive job wrote is sensitive whatever it read.
   * Null when none of these.
   */
  private async sensitivityOf(job: JobRecord, outputs: ReadonlyArray<{ sha256: string; path?: string }> = []): Promise<Sensitivity | null> {
    return jobSensitivity(this.S, job, { outputs });
  }

  /**
   * What a job that is starting already reaches (output-hygiene.ts
   * jobSensitivity, running): sets `auto_declared` and `could_read_sensitive`
   * on its scope when it declared none, and returns its derived sensitivity
   * for the journal's `sensitive_at_start`. A sensitivity that cannot be read
   * records nothing here: the seal decides it again and holds the output
   * sensitive if it cannot.
   */
  private async sensitiveAtStart(job: JobRecord, scope: JobScope): Promise<Sensitivity | null> {
    try {
      // Asked as if the job were not secret_output itself: a job that is also reads sensitive outputs, and the record says so.
      const sens = await jobSensitivity(this.S, { id: job.id, spec: { ...job.spec, secret_output: undefined, secret_output_by: undefined }, scope: { manifest: scope.manifest } }, { running: true });
      if (!scope.manifest) {
        const named = (sens?.because ?? []).filter((b) => b.how === "named_in_text");
        if (named.length) scope.auto_declared = named.map((b) => ({ from: b.from, how: "named_in_text" as const, matched: b.object }));
        const could = [...(await sensitiveIndex(this.S)).jobs.keys()].filter((id) => id !== job.id).sort();
        if (could.length) scope.could_read_sensitive = could;
      }
      return sens && !job.spec.secret_output ? sens : null;
    } catch (err) {
      this.log(`${job.id}: what it reaches of the sensitive outputs could not be read when it started (${(err as Error).message}); the seal decides`);
      return null;
    }
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
        ...(job.sensitive ? { sensitive: true } : {}),
      }));
      Object.assign(job, { generation: generation.id, revision });
      await this.project(job);
      if (job.spec.target?.sha256) this.derivedKnown.set(job.spec.target.sha256, "catalogued");
      if (trigger === "derived") this.derivedOutputBytes += job.outputs?.bytes ?? 0;
      const where = `Files: catalog/gen/${generation.id}/${generation.alias ? ` (also ${generation.alias}/)` : ""}; index: catalog/revisions/${revision}/index.md.`;
      const what = `${generation.id} ${generation.recipe} over ${generation.target.name ?? generation.target.ref ?? "an object"}`;
      // What the recipe says the run's images lack to read the object (a
      // kernel's symbol table), in its own words: said in the post, plainly,
      // to whoever the post goes to. A sensitive generation's detail is withheld.
      const lacks = generation.sensitive ? [] : missingOf(generation.coverage);
      const lackNote = lacks.length ? ` Missing from the images: ${lacks.join("; ")}.` : "";
      if (trigger === "kickoff") {
        await this.o.notify("all", `Catalogue revision ${revision}: ${what} — ${generation.status}${generation.experimental ? " (experimental recipe)" : ""}.${lackNote} ${where}`).catch(() => undefined);
      } else if (trigger === "derived") {
        // A complete catalogue of something a job made is everyone's news;
        // a partial or failed one is its maker's, with the recipe's reasons.
        const maker = job.spec.parent ? this.originOf(job.spec.parent) : null;
        if (generation.status === "complete") {
          await this.o.notify("all", `Catalogue revision ${revision}: ${what}, made by job ${job.spec.parent ?? "?"}${maker ? ` (${maker})` : ""} and catalogued on its own — complete.${lackNote} ${where}`).catch(() => undefined);
        } else if (maker) {
          const cov = generation.coverage as { errors?: unknown[]; limits_hit?: unknown[]; why?: string } | null;
          // A sensitive generation's coverage detail may carry the secret: the notification says it is withheld, never the reasons.
          const why = generation.sensitive ? [] : [...(cov?.errors ?? []), ...(cov?.limits_hit ?? []), ...(cov?.why ? [cov.why] : [])].map(String);
          await this.o.notify(maker, `Catalogue revision ${revision}: ${what}, made by your job ${job.spec.parent}, is ${generation.status}${why.length ? `: ${why.join("; ")}` : generation.sensitive ? " (its coverage detail is withheld: a sensitive output)" : ""}.${lackNote} ${where} When a readable form of it appears in a job's output, it is offered to the recipes again.`).catch(() => undefined);
        }
      }
      if (generation.status === "complete") await this.relateReadable(generation);
    }
    if (job.spec.kind === "detect") await this.fromDetect(job);
    if (job.spec.seal) await this.publishSeal(job);
    if (this.o.derived && (job.spec.kind === "tool" || job.spec.kind === "command" || job.spec.kind === "import")) await this.offerFrom(job);
    await this.tell(job);
    void this.pump();
  }

  // --- a brain's own output, sealed when a record cites it ----------------------------------------

  /** The import a tool:/trace: ref was sealed as, from the journal, the last one. */
  private sealedRef(ref: string): { import: string; job: string } | null {
    const l = this.journal.of("brain_output_sealed").filter((x) => x.ref === ref).at(-1);
    return l ? { import: String(l.import), job: String(l.job) } : null;
  }

  /**
   * Seal a brain-side output a record cites, and say which import to cite:
   * `tool:<seat>/<file>` (a whole output kept under tool-output/<seat>/) or
   * `trace:<sha256>` (one line of the trace). Found on the trace; a kept file
   * is hashed now and refused at once when it no longer matches the digest the
   * trace recorded. Then an import job (short, no network) whose view holds
   * the hub's snapshot of it, checked against the digest again at its start,
   * so what is sealed is what the trace saw, whatever the file does meanwhile;
   * published as `import:<job>/<file>` with its trace provenance. The same ref
   * is sealed once: a second record gets the same import, and one asked while
   * the first seal runs waits for it. Waits up to `wait` seconds; past that
   * the answer names the job, whose post says when it is done.
   */
  async sealCited(agent: string, ref: string, o: { wait?: number } = {}): Promise<{ ok: true; ref: string; import_ref: string; job: string } | { ok: false; reason: string }> {
    const r = ref.trim();
    const done = this.sealedRef(r);
    if (done) return { ok: true, ref: r, import_ref: done.import, job: done.job };
    const found = await traceOrigin(this.S, r);
    if (!found.ok) return { ok: false, reason: found.reason };
    const origin = found.origin;
    if (origin.kind === "tool" && origin.path) {
      const now = await hashNoFollow(join(this.S, origin.path));
      const gone = "what the trace saw is gone: run the work again as a job (job_run) and cite job:<id>/<path>";
      if ("reason" in now) return { ok: false, reason: `${r}: ${origin.path} ${now.reason}; ${gone}` };
      if (now.sha256 !== origin.digest) return { ok: false, reason: `${r}: ${origin.path} reads now as sha256 ${now.sha256.slice(0, 16)}…, not the ${origin.digest.slice(0, 16)}… the trace recorded (line ${origin.line_sha256.slice(0, 12)}…): it changed since, and ${gone}` };
    }
    const failed = (j: JobRecord) => j.state === "failed" || j.state === "cancelled" || (j.state === "committed" && j.status !== "ok");
    let job = [...this.jobs.values()].find((j) => j.spec.seal?.ref === r && j.spec.seal.digest === origin.digest && !failed(j));
    if (!job) {
      const seal: SealSpec = { kind: origin.kind, ref: r, digest: origin.digest, line_sha256: origin.line_sha256, ...(origin.path ? { path: origin.path } : {}), origin };
      const sub = await this.submit(agent, { kind: "import", note: `the seal of ${r}, which a record cites` }, { seal, watch: Math.min(Math.max(o.wait ?? 45, 0), 120) });
      if (!sub.ok) return sub;
      job = sub.job;
    }
    const until = Date.now() + Math.min(Math.max(o.wait ?? 45, 0), 120) * 1000;
    for (;;) {
      const s = this.sealedRef(r);
      if (s) return { ok: true, ref: r, import_ref: s.import, job: s.job };
      const j = this.jobs.get(job.id) ?? job;
      const refused = this.journal.of("brain_output_refused").find((l) => l.job === j.id);
      if (refused) return { ok: false, reason: `${r} could not be sealed: ${String(refused.why)}` };
      if (failed(j)) return { ok: false, reason: `${r} could not be sealed: job ${j.id} ${j.status ?? j.state}${j.reason ? ` (${j.reason})` : ""}` };
      if (Date.now() >= until) return { ok: false, reason: `${r} is being sealed as job ${j.id} (${j.state === "accepted" ? "queued" : j.state}): record again once it is done (a post says so), and the record cites it as import:${j.id}/<name>` };
      await new Promise((res) => setTimeout(res, 200));
    }
  }

  /**
   * A committed seal, published: store/imports/<job>/ holds the sealed file
   * (a link to the store's bytes), the job's manifest (the same bytes) and
   * import.json (the ref, the digest, the trace provenance, the mapping);
   * then a brain_output_sealed line. The sealed file must be the digest the
   * trace recorded, else a brain_output_refused line says why.
   */
  private async publishSeal(job: JobRecord): Promise<void> {
    const seal = job.spec.seal;
    if (!seal || job.state !== "committed" || job.status !== "ok") return;
    if (this.journal.of("brain_output_sealed").some((l) => l.job === job.id) || this.journal.of("brain_output_refused").some((l) => l.job === job.id)) return;
    await this.exclusive(async () => {
      const P = storePaths(this.S);
      const found = await readManifest(join(P.jobs, job.id, "manifest.json"));
      const file = found?.manifest.files.find((f) => f.sha256 === seal.digest);
      if (!found || !file) {
        await this.journal.append({ type: "brain_output_refused", job: job.id, ref: seal.ref, why: `job ${job.id}'s sealed output holds no file of sha256 ${seal.digest.slice(0, 16)}…, the digest the trace recorded` });
        return;
      }
      const dir = join(P.imports, job.id);
      // A publication a crash left half done is made again from the store.
      if (existsSync(dir)) {
        for (const d of [dir, join(dir, "out")]) await chmod(d, 0o755).catch(() => undefined);
        await rm(dir, { recursive: true, force: true });
      }
      await mkdir(join(dir, "out"), { recursive: true });
      const name = Buffer.from(file.path_b64, "base64");
      const from = Buffer.concat([Buffer.from(`${join(P.jobs, job.id, "out")}/`), name]);
      const to = Buffer.concat([Buffer.from(`${join(dir, "out")}/`), name]);
      await link(from, to).catch(async () => copyFile(from, to));
      await copyFile(join(P.jobs, job.id, "manifest.json"), join(dir, "manifest.json"));
      const importRef = `import:${job.id}/${file.path}`;
      const record = { v: 1, ref: seal.ref, import: importRef, job: job.id, digest: seal.digest, bytes: file.bytes, trace_line: seal.line_sha256, trace: seal.origin, how: "the kept bytes, snapshotted by the hub at the import job's start and held there to the digest the trace recorded; sealed like any import" };
      const text = `${JSON.stringify(record, null, 2)}\n`;
      await writeFile(join(dir, "import.json"), text);
      for (const f of ["manifest.json", "import.json"]) await chmod(join(dir, f), 0o444).catch(() => undefined);
      await chmod(join(dir, "out"), 0o555).catch(() => undefined);
      await chmod(dir, 0o555).catch(() => undefined);
      const manifestSha = (await readManifest(join(dir, "manifest.json")))?.sha256 ?? "";
      await this.journal.append({ type: "brain_output_sealed", job: job.id, ref: seal.ref, import: importRef, digest: seal.digest, trace_line: seal.line_sha256, seat: seal.origin.seat, tool: seal.origin.tool, manifest_sha256: manifestSha, import_json_sha256: sha256Hex(text) });
    });
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
    const unasked: string[] = [];
    for (const a of answered) {
      if (a.rc !== "0") continue;
      const t = targets[a.t];
      applied += 1;
      // A broad extraction its pack does not mark auto, or one the images
      // cannot run, is not run unasked: the hub offers the one as a lead and
      // declines the other with the pack's why (scripts/preparation.ts).
      if (!derivedPass) {
        const info = await this.recipe(a.recipe).catch(() => null);
        if (info && (info.unavailable || (info.purpose === "broad_extraction" && !info.auto.length))) {
          unasked.push(`${a.recipe} over ${t.name ?? t.ref ?? "the object"}${info.unavailable ? ` (declared, and it cannot run in this run's images: ${info.unavailable})` : ""}`);
          continue;
        }
      }
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
    if (unasked.length && job.requester.agent !== "system") {
      await this.journal.append({ type: "job_notified", job: job.id, to: job.requester.agent, how: "post" });
      await this.o.notify(job.requester.agent, `A broad extraction applies and is not run unasked (job ${job.id}): ${unasked.join("; ")}. One that can run is started with catalog_request target=<ref> recipe=<id> when the case needs it.`).catch(() => undefined);
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
    // A recipe the plan names that the service refuses is named with why, on the record: a broad extraction refused here is declined with that why (scripts/preparation.ts).
    const refused: Array<{ recipe: string; input: string; reason: string }> = [];
    for (const p of plan) {
      const r = await this.submit("system", { kind: "recipe", recipe: p.recipe, target: p.target, alias: p.alias, inputs: [p.target.ref ?? "all"], timeout_seconds: 900, network: "allowlist", note: `kickoff: ${p.input}` });
      if (r.ok) ids.push(r.job.id);
      else {
        refused.push({ recipe: p.recipe, input: p.input, reason: r.reason });
        this.log(`kickoff recipe ${p.recipe} over ${p.input} refused: ${r.reason}`);
      }
    }
    await this.journal.append({ type: "kickoff_queued", jobs: ids, ...(refused.length ? { refused } : {}) });
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

  /**
   * What a running job is doing, from the host (B11): a sample now (its
   * output directory's metadata, its logs' sizes, its CPU and I/O from
   * msb's metrics or its heartbeat), kept beside its staging, and the
   * verdict over the samples kept. Null when it is not running.
   */
  async progress(id: string): Promise<JobProgress | null> {
    const job = this.jobs.get(id);
    if (!job || job.state !== "running") return null;
    const st = this.staging(job);
    const worker = job.worker;
    const metrics = worker && this.o.metrics ? () => this.o.metrics!(worker) : undefined;
    const s = await sampleJob({ out: st.out, ctl: st.ctl }, { ...(metrics ? { metrics } : {}) }).catch(() => null);
    if (s) await keepSample(st.base, s);
    return assessJob(await readSamples(st.base), { started_at: job.started_at, timeout_seconds: job.spec.timeout_seconds });
  }

  /** Every running job sampled (the service's own clock), so the samples say how long each signal has been still. */
  async sampleRunning(): Promise<void> {
    for (const j of this.jobs.values()) if (j.state === "running") await this.progress(j.id).catch(() => null);
  }

  /** A job's state for its requester (or anyone: jobs are the run's, not private), with a page of its stdout. */
  async status(agent: string, id: string, o: { offset?: number; limit?: number; cancel?: boolean; wait?: number } = {}): Promise<{ ok: true; job: JobRecord; stdout?: { offset: number; bytes: number; total: number; text: string; next: number | null; path: string }; progress?: JobProgress } | { ok: false; reason: string }> {
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
          this.waitingForHost.delete(id);
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
    const progress = job.state === "running" ? await this.progress(id).catch(() => null) : null;
    return { ok: true, job, ...(stdout ? { stdout } : {}), ...(progress ? { progress } : {}) };
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
    if (this.afterRun) return;
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
    // After the run (sealLeft) nobody is there to be told: the job stays
    // untold on the record, and a resume's recovery tells it.
    if (this.afterRun) return;
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
    await this.fenceLeft(this.o.stopFence ?? { tries: 3, waitMs: 2000 });
    await dropProjected(storePaths(this.S).staging);
  }

  /**
   * Every job whose worker was not confirmed gone, sealed once it is, or
   * accounted for on the journal: the backstop run once more as the service
   * stops, `tries` times with `waitMs` between. On the Breadcrumbs run a
   * stop's removal of a worker and the job's own raced, msb could not say
   * whether the worker was gone, and the hub went with the job's staging
   * directory unsealed and nothing on the record but that one fence.
   *
   * A job still `running` here ended without its `job_finished` (its run
   * threw): sealed as cancelled when the stop asked for that, else stopped.
   * A `fenced` one whose commit failed is committed. One whose worker still
   * is not confirmed gone is never read: a `job_unsealed` line names its
   * staging directory and why, and `swarm.sh stop` seals it once the run's
   * VMs are gone (sealLeft).
   */
  private async fenceLeft(o: { tries: number; waitMs: number }, only?: ReadonlySet<string>, when = "when the job service stopped"): Promise<void> {
    for (const j of [...this.jobs.values()]) {
      if (this.running.has(j.id) || (only && !only.has(j.id))) continue;
      if (!((j.state === "finished" || j.state === "running") && j.worker) && j.state !== "fenced") continue;
      if (j.state !== "fenced") {
        let gone = false;
        let why = "";
        for (let k = 0; k < Math.max(1, o.tries) && !gone; k += 1) {
          if (k) await new Promise((r) => setTimeout(r, o.waitMs));
          const r = await this.o.destroyWorker(j.worker!).catch((err: Error) => ({ ok: false, error: err.message }));
          gone = r.ok;
          why = r.error ?? "no reason given";
        }
        if (!gone) {
          await this.journal.append({ type: "job_unsealed", job: j.id, attempt: j.attempt, staging: `${j.id}-${j.attempt}`, why: `its worker ${j.worker} was not confirmed gone ${when}: ${why}` });
          this.log(`${j.id}: left unsealed, its worker ${j.worker} not confirmed gone: ${why}`);
          continue;
        }
        await this.journal.append({ type: "job_fenced", job: j.id, attempt: j.attempt, fenced: true, late: true, by: "stop" });
        if (j.state === "running") Object.assign(j, { status: j.cancel_requested ? "cancelled" : "stopped", reason: j.cancel_requested ? `cancelled by ${j.cancel_requested}` : "the run was stopped while it ran", exit: null });
        j.state = "fenced";
      }
      await this.commit(j, { status: j.status ?? "ok", exit: j.exit ?? null, reason: j.reason }).catch((err: Error) => this.log(`${j.id}: not sealed at stop: ${err.message}`));
    }
  }

  /**
   * After the run, with no hub: what a stop left unsealed, sealed or said.
   * The journal is read as the service reads it at start, nothing is queued
   * and no worker is made; each job a staging directory belongs to that was
   * started and never committed has its worker asked to go once more (the
   * caller's destroyWorker, msb's own answer), and is sealed when it is gone
   * (`job_fenced` with `by: "stop"`, then its commit, as recovery would) or
   * accounted for with a `job_unsealed` line when it is not. A staging
   * directory no such job owns is named and left as it is. Only with no hub
   * running: the hub is the store's writer while it runs.
   */
  async sealLeft(): Promise<{ sealed: Array<{ staging: string; job: string; status: string }>; left: Array<{ staging: string; why: string }> }> {
    // The hub is the store's writer while it lives: by hub.pid, and by its
    // command line when hub.pid is gone (a stop that gave up waiting for it).
    const hub = hubAlive(this.S) ?? hubProcessFor(this.S);
    if (hub) throw new Error(`the run's hub (pid ${hub}) is still up, and it is the store's writer while it runs: nothing is sealed beside it. Once it has gone (or after \`kill ${hub}\` if it hangs), run swarm.sh stop for this run again: it seals what is left`);
    this.stopping = true;
    this.afterRun = true;
    this.journal = await Journal.open(this.S);
    this.replay(this.journal.lines);
    const P = storePaths(this.S);
    const names = (await readdir(P.staging).catch(() => [] as string[])).filter((n) => !n.startsWith(".")).sort();
    const sealed: Array<{ staging: string; job: string; status: string }> = [];
    const left: Array<{ staging: string; why: string }> = [];
    const owned = new Map<string, string>();
    for (const name of names) {
      const m = /^(j\d{6})-(\d+)$/.exec(name);
      const j = m ? this.jobs.get(m[1]) : undefined;
      if (!m || !j || j.attempt !== Number(m[2])) {
        left.push({ staging: name, why: m ? (j ? `attempt ${m[2]} of ${m[1]} is not the attempt the journal has (${j.attempt})` : `no job ${m[1]} on the journal`) : "not a job's staging directory" });
        continue;
      }
      if (j.state !== "running" && j.state !== "finished" && j.state !== "fenced") {
        left.push({ staging: name, why: `${j.id} is ${j.state} on the journal: nothing of it is left to seal` });
        continue;
      }
      owned.set(j.id, name);
    }
    // Once each: destroyWorker already asks msb three times.
    await this.fenceLeft({ tries: 1, waitMs: 0 }, new Set(owned.keys()), "after the run");
    for (const [id, name] of owned) {
      const after = this.jobs.get(id)!;
      if (after.state === "committed") sealed.push({ staging: name, job: id, status: after.status ?? "ok" });
      else left.push({ staging: name, why: this.journal.of("job_unsealed").filter((l) => l.job === id).map((l) => String(l.why)).at(-1) ?? `${id} is ${after.state}` });
    }
    await dropProjected(P.staging);
    return { sealed, left: left.sort((a, b) => a.staging.localeCompare(b.staging)) };
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

/**
 * What a stop left unsealed, sealed after the run (JobService.sealLeft),
 * with msb's own answer for each worker (vm.ts destroyWorker): `vm.ts
 * seal-left --sandbox DIR`, which `swarm.sh stop` runs once the hub has
 * gone. Nothing is made, queued or posted.
 */
export async function sealLeftStaging(sandbox: string, destroyWorker: JobServiceOptions["destroyWorker"], log?: (line: string) => void): Promise<Awaited<ReturnType<JobService["sealLeft"]>>> {
  const svc = new JobService({
    sandbox,
    run: "",
    image: "",
    workers: 0,
    workerCpus: 1,
    workerMemoryMib: 0,
    allowHosts: [],
    openNet: false,
    packDirs: [],
    forging: false,
    runWorker: async () => ({ code: null, fenced: false, error: "no worker is made after the run" }),
    destroyWorker,
    notify: async () => undefined,
    identity: async () => ({}),
    ...(log ? { log } : {}),
  });
  return svc.sealLeft();
}

/**
 * The program a failed job's image did not hold (B17), from the generic
 * signs only: a shell's own diagnostic on its stderr (bash's "X: command
 * not found", zsh's "command not found: X", and dash's "sh: 1: X: not
 * found" with the shell's exit 127; the name sanitised), or exit 127 with
 * no name ("?"). An application's own "X: not found" (a file, an object it
 * looked for) is no missing program: null, as when there is neither.
 */
export async function programMissing(ctl: string, exit: number | null): Promise<string | null> {
  const err = await readFile(join(ctl, "stderr.log")).catch(() => Buffer.alloc(0));
  const text = err.subarray(Math.max(0, err.length - 65536)).toString("utf8");
  // zsh first: its "zsh: command not found: X" would otherwise read as a program named "zsh".
  const zsh = /(?:^|\n)[^\n]*?: command not found: ([A-Za-z0-9_.+-]{1,64})/.exec(text);
  if (zsh) return zsh[1]!;
  const bash = /(?:^|\n)(?:[^\n]*?: )?(?:line \d+: )?([A-Za-z0-9_.+-]{1,64}): command not found/.exec(text);
  if (bash) return bash[1]!;
  if (exit !== 127) return null;
  const dash = /(?:^|\n)[^\n:]*: \d+: ([A-Za-z0-9_.+-]{1,64}): not found/.exec(text);
  return dash ? dash[1]! : "?";
}

/** One post, for the agent that asked. */
export function describe(job: JobRecord): string {
  const what = job.spec.kind === "tool" ? `tool ${job.spec.tool}` : job.spec.kind === "command" ? "command" : job.spec.kind === "recipe" ? `recipe ${job.spec.recipe}` : job.spec.seal ? `the seal of ${job.spec.seal.ref}` : job.spec.kind === "import" ? `import of ${job.spec.source}${scopeKindOf(job.spec) === "declared" ? ", from the snapshot the hub took at its start" : ", copied live from where it was"}` : "detect pass";
  if (job.state === "failed") return `Job ${job.id} (${what}) was not run: ${job.reason}.`;
  if (job.state === "cancelled") return `Job ${job.id} (${what}) was cancelled${job.reason ? `: ${job.reason}` : ""}.`;
  const o = job.outputs;
  const files = o ? `${o.files} file(s), ${o.bytes} bytes in ${o.path}/${o.rejected ? ` (${o.rejected} link(s) or special file(s) left out, named in its manifest)` : ""}` : "no output";
  const head = job.status === "ok" ? "done" : `${job.status}${job.reason ? ` (${job.reason})` : ""}`;
  const cite = job.spec.seal && job.status === "ok" ? `record again citing ${job.spec.seal.ref}: it resolves to import:${job.id}/<name>` : `cite its files as job:${job.id}/<path>`;
  const same = job.same_as?.length ? ` ${job.same_as.length} of its files are an earlier job's output byte for byte (job_status ${job.id} names them).` : "";
  return `Job ${job.id} (${what}) ${head}: ${files}; stdout and stderr whole in store/jobs/${job.id}/. job_status ${job.id} for the details; ${cite}.${job.generation ? ` Catalogued as ${job.generation}.` : ""}${same}${job.sensitive ? ` ${sensitiveWords(job)}` : ""}`;
}

/** What a sensitive job's outputs mean for whoever uses them, in one sentence. */
export function sensitiveWords(job: Pick<JobRecord, "id" | "sensitive">): string {
  if (!job.sensitive) return "";
  return `Its outputs are sensitive (${job.sensitive.why === "secret_output" ? `it ran with secret_output${job.sensitive.declared === "tool_manifest" ? ", which the tool's manifest declares" : ""}` : `made from the sensitive output of ${job.sensitive.from.join(", ")}`}): an entry citing them is recorded sensitive, a job reading them seals sensitive output too, and a redacted package withholds them. Say what they show without the value.`;
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
    // Where it ran and why, and the lane it took: a job that names no profile is placed by the images' records.
    ...(job.image ? { image: job.image } : {}),
    ...(job.image_choice ? { image_why: job.image_choice.why } : {}),
    ...(job.lane ? { lane: job.lane } : {}),
    // What it could read: its declared scope (enforced; its manifest names every object), or every object of the run.
    scope: job.scope?.kind ?? scopeKindOf(job.spec),
    ...(scopeKindOf(job.spec) === "declared" ? { declared: job.spec.inputs } : {}),
    ...(job.scope?.manifest ? { scope_manifest: job.scope.manifest } : {}),
    ...(job.generation ? { generation: job.generation, revision: job.revision } : {}),
    ...(job.program_missing ? { program_missing: { ...job.program_missing, note: "the image of its profile does not hold it: run it in a profile that does, install it if the job may, or tell the operator (the console lists these for the images' upkeep)" } } : {}),
    ...(job.spec.independent ? { independent: true } : {}),
    ...(job.spec.secret_output ? { secret_output: true } : {}),
    ...(job.spec.secret_output_by ? { secret_output_by: job.spec.secret_output_by } : {}),
    ...(job.sensitive ? { sensitive: sensitiveWords(job) } : {}),
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
  Object.assign(view, sameAsView(job.id, job.same_as ?? []));
  view.cite = `job:${job.id}/<path>`;
  return view;
}

/** What workerSpecFor gives: the worker's spec, what it could reach, a declared scope's manifest, and how the image was chosen. */
export type WorkerPlan = {
  spec: WorkerSpec;
  accessible: Array<{ path: string; access: string }>;
  manifest: Record<string, unknown> | null;
  view: { objects: number; files: number; bound: number } | null;
  chosen: { profile: string | null; ref: string; choice: ImageChoice };
  script: { lines: string[]; tool_sha256?: string };
};

export { targetPaths };

/** A file's sha256 read through a descriptor that does not follow a link; a link, a special file or nothing is said. */
async function hashNoFollow(path: string): Promise<{ sha256: string } | { reason: string }> {
  let fh;
  try {
    fh = await open(path, constants.O_RDONLY | constants.O_NOFOLLOW);
  } catch (err) {
    const code = (err as NodeJS.ErrnoException).code;
    return { reason: code === "ENOENT" ? "is no longer there" : code === "ELOOP" ? "is a link now" : `cannot be read (${code ?? "error"})` };
  }
  try {
    if (!(await fh.stat()).isFile()) return { reason: "is not a regular file" };
    const h = createHash("sha256");
    const buf = Buffer.alloc(1 << 20);
    for (let pos = 0; ; ) {
      const { bytesRead } = await fh.read(buf, 0, buf.length, pos);
      if (!bytesRead) break;
      h.update(buf.subarray(0, bytesRead));
      pos += bytesRead;
    }
    return { sha256: h.digest("hex") };
  } finally {
    await fh.close();
  }
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
