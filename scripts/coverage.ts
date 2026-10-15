/**
 * What the trace says the agents named, and what it never named.
 *
 *   node --experimental-strip-types scripts/coverage.ts <sandbox> [--json]
 *
 * Two questions, both answered from the chained trace and nothing else:
 *
 *   - Coverage: which evidence files (inputs.json, names compared as the
 *     manifest holds them, `path_b64` honoured) no command on the trace
 *     named. "Untouched" means exactly that and no more: no call's arguments
 *     named the file. A job request (`job_run`, `catalog_request`) names a
 *     file when its command or tool arguments carry the path or its `inputs`
 *     list declares it (`input:<name>`); `inputs: ["all"]` and a job's status
 *     call name nothing. A file a command named, or a job was given, was not
 *     necessarily examined, and a file read through a directory walk, a glob
 *     or an archive is not named at all (nor is a further segment of a split
 *     image a job read from its first); the directories a command named are
 *     counted beside it so a reader can see that.
 *   - Grounding: for each ledger entry whose `source` names a path, whether
 *     any call before the entry was recorded named that path. An entry whose
 *     source no earlier call named is "not in the trace": its source may
 *     still be right (a path inside an image the tools reached by inode), but
 *     the trace does not show the swarm reading it. A path that may lie
 *     inside an input is also grounded when the entry cites (`refs`) a job,
 *     started before it, that declared an evidence input (itself or through
 *     the output of the jobs it declared; `store/jobs/<id>/job.json`, scope
 *     `declared`). That says the job was given the input, and counts apart
 *     (`grounded_via_job`): nothing says the path was read.
 *
 * Generic on purpose: the harness knows its own tools (it leaves out the
 * board, the ledger and the other messaging calls, which name paths without
 * reading them) and nothing about any forensic tool. A path is matched in a
 * call's arguments wherever it appears, in any of the forms an agent writes
 * it: under `inputs/`, from the sandbox's absolute path or the guest's
 * `/…/inputs/…`, quoted or not, and relative to inputs/ as a bare name.
 */
import { readFile, readdir } from "node:fs/promises";
import { join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import {
  SYSTEM_AGENT,
  TOOL_RESERVED_NAMES,
  hostTime,
  readEventLogChecked,
  readLedger,
  type LedgerEntry,
  type SwarmEvent,
} from "../extensions/protocol.ts";
import { eachInputsFile } from "./custody.ts";

/** The harness's own tools that act on files; every other reserved name is messaging or a harness event. */
const FILE_TOOLS = new Set(["read", "bash", "edit", "write", "grep", "find", "ls", "powershell", "playwright", "browser_check"]);

/**
 * The job tools whose arguments name what a worker VM is to read: a job's
 * command, its tool's arguments and the inputs it declares, or the target a
 * catalogue request points at. `job_status` carries a job id and nothing else.
 */
const JOB_TOOLS = new Set(["job_run", "catalog_request"]);

/** A call an agent made to reach something: a file tool, a job, or a tool a pack or an agent brought. */
export function isCommand(e: SwarmEvent): boolean {
  if (!e || typeof e.tool !== "string" || e.agent === SYSTEM_AGENT) return false;
  return FILE_TOOLS.has(e.tool) || JOB_TOOLS.has(e.tool) || !TOOL_RESERVED_NAMES.has(e.tool);
}

/** Every string in a call's arguments, however deep. */
export function argStrings(value: unknown, out: string[] = [], depth = 0): string[] {
  if (depth > 8) return out;
  if (typeof value === "string") out.push(value);
  else if (Array.isArray(value)) for (const v of value) argStrings(v, out, depth + 1);
  else if (value && typeof value === "object") for (const v of Object.values(value as Record<string, unknown>)) argStrings(v, out, depth + 1);
  return out;
}

/** An argument the trace kept cut short: older runs clipped them at 80 characters and marked the cut. */
function clipped(s: string): boolean {
  return s.length >= 80 && s.length <= 84 && (s.endsWith("...") || s.endsWith("…"));
}

const DELIM = /[\s"'`;|&<>()=,]/;
const TRAILING = /[.,:;)\]}]+$/;
const GLOB = /[*?[]/;

/**
 * The names a string gives under `inputs/`: at every occurrence, the rest of
 * the token it sits in, up to the closing quote when the token was quoted,
 * with shell-escaped spaces read as spaces.
 */
export function namesUnderInputs(s: string): string[] {
  const out: string[] = [];
  let from = 0;
  for (;;) {
    const i = s.indexOf("inputs/", from);
    if (i < 0) break;
    from = i + 7;
    // The token's start, to learn whether it was quoted.
    let j = i - 1;
    while (j >= 0 && !DELIM.test(s[j])) j -= 1;
    const quote = j >= 0 && (s[j] === '"' || s[j] === "'" || s[j] === "`") ? s[j] : null;
    let end = i + 7;
    if (quote) {
      const close = s.indexOf(quote, end);
      end = close < 0 ? s.length : close;
    } else {
      while (end < s.length) {
        if (s[end] === "\\" && s[end + 1] === " ") {
          end += 2;
          continue;
        }
        if (DELIM.test(s[end])) break;
        end += 1;
      }
    }
    out.push(s.slice(i + 7, end).replace(/\\ /g, " "));
  }
  return out;
}

/**
 * The name a job's input declaration gives (`input:<name>`, as `job_run`'s
 * `inputs` list and `catalog_request`'s target write it), relative to
 * `inputs/`. The whole of the string is the reference: an `input:` inside a
 * command is prose, not a declaration. `input:` alone, or `input:inputs/`,
 * names the directory.
 */
export function declaredInput(s: string): string[] {
  const m = /^input:(.*)$/s.exec(s.trim());
  if (!m) return [];
  const rel = m[1].replace(/^\/+/, "").replace(/^inputs(\/|$)/, "");
  return [rel];
}

export type CoverageReport = {
  /** Why nothing could be said: no manifest, or a trace that could not be read. */
  unavailable: string | null;
  /** Names the manifest lists. */
  inputs: number;
  /** The manifest's paths no command named, in manifest order. */
  untouched: string[];
  /** Manifest path → how many commands named it. */
  touched: Record<string, number>;
  /** Untouched manifest path → how many commands named a directory above it (a walk may have read it). */
  under_named_dir: Record<string, number>;
  /** The calls matched against. */
  calls_scanned: number;
  /** Calls the trace kept cut short: a name past the cut is not seen. */
  clipped_calls: number;
  /** Ledger seq → grounded · not in the trace · not a path. */
  grounding: Record<string, Grounding>;
  /** Of the grounded entries, the seqs no call named the source of, grounded only through a job the entry cites that declared an evidence input. */
  grounded_via_job: string[];
};

export type Grounding = "grounded" | "not in the trace" | "not a path";

/**
 * The paths a ledger entry's source names, as written, backslashes read as
 * slashes. A token counts when it is rooted (`/`, `./`, `~/`, a drive
 * letter, one of the run's own directories), has two slashes or more, or
 * ends in a file name with an extension; prose like "TCP/IP", a URL and a
 * registry key are not paths.
 */
export function pathTokens(source: string): string[] {
  const out: string[] = [];
  for (const raw of source.split(/[\s,;()[\]{}<>"'`|]+/)) {
    let t = raw.replace(/[.:!?]+$/, "");
    if (!t || t.includes("://")) continue;
    // A registry key names a key in a hive, not a file.
    if (/^HK(LM|CU|U|CR|CC|EY_)\b/i.test(t)) continue;
    t = t.replace(/\\/g, "/");
    const slashes = (t.match(/\//g) ?? []).length;
    const last = t.split("/").filter(Boolean).at(-1) ?? "";
    const hasExt = /^[^/]{2,}\.[A-Za-z][A-Za-z0-9]{0,7}$/.test(last);
    const rooted = /^(\/|\.\/|~\/|[A-Za-z]:\/|(inputs|work|catalog|tool-output)\/)/.test(t);
    if (slashes === 0 ? hasExt : rooted || hasExt || slashes >= 2) out.push(t);
  }
  return out;
}

const WORDISH = /[a-z0-9_.-]/;

/** `needle` in `hay` as a whole name: not inside a longer one on either side. */
export function containsName(hay: string, needle: string): boolean {
  if (!needle) return false;
  let from = 0;
  for (;;) {
    const i = hay.indexOf(needle, from);
    if (i < 0) return false;
    const before = i > 0 ? hay[i - 1] : "";
    const after = hay[i + needle.length] ?? "";
    const okBefore = needle.startsWith("/") || !before || !WORDISH.test(before);
    const okAfter = !after || !WORDISH.test(after);
    if (okBefore && okAfter) return true;
    from = i + 1;
  }
}

type Call = { at: number; text: string };

/**
 * What a job's record says it was to read: when its worker started, the
 * evidence it declared (`input:<name>` or a path under `inputs/`, as names
 * relative to `inputs/`; only a job whose scope was enforced, `declared`,
 * says anything of the kind) and the jobs whose output it declared
 * (`job:<id>[/…]`). A scope of `all` or none names nothing.
 */
export type JobDeclaration = { at: number; inputs: string[]; from: string[] };

/** The jobs of a run, by id, from `store/jobs/<id>/job.json`; a record that cannot be read is left out. */
export async function readJobDeclarations(sandboxArg: string): Promise<Map<string, JobDeclaration>> {
  const dir = join(resolve(sandboxArg), "store", "jobs");
  const out = new Map<string, JobDeclaration>();
  const ids = await readdir(dir).catch(() => [] as string[]);
  for (let i = 0; i < ids.length; i += 32) {
    await Promise.all(
      ids.slice(i, i + 32).map(async (id) => {
        const rec = await readFile(join(dir, id, "job.json"), "utf8")
          .then((t) => JSON.parse(t) as { id?: unknown; started_at?: unknown; accepted_at?: unknown; spec?: { scope?: unknown; inputs?: unknown } })
          .catch(() => null);
        if (!rec || typeof rec !== "object" || !rec.spec || typeof rec.id !== "string") return;
        const said = Array.isArray(rec.spec.inputs) ? rec.spec.inputs.filter((x): x is string => typeof x === "string") : [];
        const declared = rec.spec.scope === "declared";
        const inputs: string[] = [];
        const from: string[] = [];
        for (const ref of declared ? said : []) {
          const t = ref.trim();
          const job = /^job:([a-z0-9-]+)(?:\/|$)/.exec(t);
          if (job) from.push(job[1]);
          else if (t.startsWith("input:")) inputs.push(...declaredInput(t));
          else if (t === "inputs" || t.startsWith("inputs/")) inputs.push(t.replace(/^inputs\/?/, ""));
        }
        out.set(rec.id, { at: Date.parse(String(rec.started_at ?? rec.accepted_at ?? "")), inputs, from });
      }),
    );
  }
  return out;
}

/** The ids of the jobs an entry cites: its `refs` of the form `job:<id>[/…]`. */
function citedJobs(entry: LedgerEntry): string[] {
  const out: string[] = [];
  for (const ref of Array.isArray(entry.refs) ? entry.refs : []) {
    const m = typeof ref === "string" ? /^job:([a-z0-9-]+)(?:\/|$)/.exec(ref.trim()) : null;
    if (m) out.push(m[1]);
  }
  return out;
}

/**
 * Whether a job, started by `until`, declared evidence: itself, or through
 * the output of a job it declared (and so on, back to a job that did).
 */
function declaredEvidence(jobs: ReadonlyMap<string, JobDeclaration>, id: string, until: number, seen = new Set<string>()): boolean {
  if (seen.has(id)) return false;
  seen.add(id);
  const j = jobs.get(id);
  if (!j || (Number.isFinite(until) && Number.isFinite(j.at) && j.at > until)) return false;
  return j.inputs.length > 0 || j.from.some((f) => declaredEvidence(jobs, f, until, seen));
}

/** A path token the run itself holds (a job's output or log, the agents' work, the catalogue): not a path inside an input. */
function runsOwn(token: string): boolean {
  return /^(\.\/)?(work|store|catalog|tool-output)\//.test(token) || /^(job|import|member):/i.test(token) || /(^|\/)j\d{6}(\/|$)/.test(token);
}

export type GroundingDetail = {
  grounding: Record<string, Grounding>;
  /** Ledger seq of the entries grounded only through a job the entry cites, none of the trace's calls having named the source. */
  via_job: string[];
};

/**
 * Whether each entry's source was named by a call before the entry was
 * recorded: its full path, or its last component when that is three
 * characters or more. Case is ignored, as the file systems the evidence
 * comes from mostly ignore it.
 *
 * With the run's jobs (`readJobDeclarations`) there is a second way, for a
 * path that may lie inside an input the call arguments do not name (a member
 * of an image a tool extracted whole): the entry cites (`refs`) a job that
 * started before it and declared an evidence input, itself or through the
 * output of the jobs it declared. That says a job was given the input, and
 * nothing of what it read within it. A path of the run's own (a job's
 * output or log, the agents' work, the catalogue) is not a path inside an
 * input and gets only the first way.
 */
export function groundingDetail(ledger: readonly LedgerEntry[], events: readonly SwarmEvent[], jobs?: ReadonlyMap<string, JobDeclaration>): GroundingDetail {
  const calls: Call[] = events
    .filter(isCommand)
    .map((e) => ({ at: Date.parse(hostTime(e)), text: argStrings(e.args).join("\n").toLowerCase() }))
    .sort((a, b) => (Number.isFinite(a.at) ? a.at : 0) - (Number.isFinite(b.at) ? b.at : 0));
  const out: Record<string, Grounding> = {};
  const viaJob: string[] = [];
  for (const entry of ledger) {
    const tokens = pathTokens(entry.source ?? "");
    if (!tokens.length) {
      out[String(entry.seq)] = "not a path";
      continue;
    }
    const until = Date.parse(entry.at ?? "");
    const needles = tokens.flatMap((t) => {
      const lower = t.toLowerCase();
      const last = lower.split("/").filter(Boolean).at(-1) ?? "";
      return last.length >= 3 && last !== lower ? [lower, last] : [lower];
    });
    let found = false;
    for (const c of calls) {
      if (Number.isFinite(until) && Number.isFinite(c.at) && c.at > until) break;
      if (needles.some((n) => containsName(c.text, n))) {
        found = true;
        break;
      }
    }
    if (!found && jobs?.size && tokens.some((t) => !runsOwn(t)) && citedJobs(entry).some((id) => declaredEvidence(jobs, id, until))) {
      found = true;
      viaJob.push(String(entry.seq));
    }
    out[String(entry.seq)] = found ? "grounded" : "not in the trace";
  }
  return { grounding: out, via_job: viaJob };
}

/** `groundingDetail`'s answer alone, for a caller that does not say how an entry was grounded. */
export function groundingOf(ledger: readonly LedgerEntry[], events: readonly SwarmEvent[], jobs?: ReadonlyMap<string, JobDeclaration>): Record<string, Grounding> {
  return groundingDetail(ledger, events, jobs).grounding;
}

/**
 * Coverage over a run: the manifest streamed, the trace's calls matched
 * against it. `events` and `ledger` are the caller's when it already holds
 * them (the report does); otherwise they are read here.
 */
export async function coverageOf(
  sandboxArg: string,
  given: { events?: readonly SwarmEvent[]; ledger?: readonly LedgerEntry[]; traceUnreadable?: string | null } = {},
): Promise<CoverageReport> {
  const sandbox = resolve(sandboxArg);
  const empty = (why: string | null): CoverageReport => ({
    unavailable: why,
    inputs: 0,
    untouched: [],
    touched: {},
    under_named_dir: {},
    calls_scanned: 0,
    clipped_calls: 0,
    grounding: {},
    grounded_via_job: [],
  });
  let events = given.events;
  let traceUnreadable = given.traceUnreadable ?? null;
  if (!events) {
    const read = await readEventLogChecked(sandbox);
    events = read.events;
    traceUnreadable = read.unreadable;
  }
  if (traceUnreadable) return empty(`the trace could not be read (${traceUnreadable})`);
  const ledger = given.ledger ?? (await readLedger(sandbox));
  const { grounding, via_job: viaJob } = groundingDetail(ledger, events, await readJobDeclarations(sandbox));

  // The manifest: each name under inputs/ in the forms an argument can carry
  // it (as written, and case-folded), and every directory above a name.
  const paths: string[] = [];
  const exact = new Map<string, number>();
  const folded = new Map<string, number[]>();
  const dirs = new Set<string>([""]);
  const listed = await eachInputsFile(sandbox, ({ path, rel }) => {
    const idx = paths.length;
    paths.push(path);
    for (const form of new Set([path.startsWith("inputs/") ? path.slice(7) : path, rel.toString("utf8")])) {
      if (!exact.has(form)) exact.set(form, idx);
      const low = form.toLowerCase();
      const list = folded.get(low);
      if (list) list.push(idx);
      else folded.set(low, [idx]);
      const parts = form.split("/");
      for (let k = 1; k < parts.length; k++) dirs.add(parts.slice(0, k).join("/"));
    }
  });
  if ("why" in listed) {
    const report = empty(listed.why === "missing" ? "no evidence manifest (inputs.json)" : `inputs.json is ${listed.why}`);
    report.grounding = grounding;
    report.grounded_via_job = viaJob;
    return report;
  }
  const foldedDirs = new Set([...dirs].map((d) => d.toLowerCase()));

  const counts = new Array<number>(paths.length).fill(0);
  const dirCounts = new Map<string, number>();
  let scanned = 0;
  let clippedCalls = 0;
  const lookup = (name: string): number[] => {
    const hit = exact.get(name);
    if (hit !== undefined) return [hit];
    return folded.get(name.toLowerCase()) ?? [];
  };
  for (const e of events) {
    if (!isCommand(e)) continue;
    scanned += 1;
    const strings = argStrings(e.args);
    if (strings.some(clipped)) clippedCalls += 1;
    const named = new Set<number>();
    const namedDirs = new Set<string>();
    const consider = (candidate: string) => {
      let c = candidate.replace(/\/+$/, "");
      // A pattern names the directory it walks, not a file.
      if (GLOB.test(c)) {
        const cut = c.split("/");
        const first = cut.findIndex((seg) => GLOB.test(seg));
        const dir = cut.slice(0, first).join("/");
        if (foldedDirs.has(dir.toLowerCase())) namedDirs.add(dir.toLowerCase());
        return;
      }
      for (let tries = 0; tries < 4; tries++) {
        const hits = lookup(c);
        if (hits.length) {
          for (const h of hits) named.add(h);
          return;
        }
        if (foldedDirs.has(c.toLowerCase())) {
          namedDirs.add(c.toLowerCase());
          return;
        }
        const trimmed = c.replace(TRAILING, "").replace(/\/+$/, "");
        if (trimmed === c) return;
        c = trimmed;
      }
    };
    for (const s of strings) {
      for (const candidate of declaredInput(s)) consider(candidate);
      for (const candidate of namesUnderInputs(s)) consider(candidate);
      // A bare name relative to inputs/, as a command run from inside it gives it.
      for (const token of s.split(/[\s"'`;|&<>()=,]+/)) {
        const t = token.replace(/^\.\//, "");
        if (!t || t.startsWith("/") || t.startsWith("inputs/")) continue;
        const hit = exact.get(t);
        if (hit !== undefined) named.add(hit);
      }
    }
    for (const h of named) counts[h] += 1;
    for (const d of namedDirs) dirCounts.set(d, (dirCounts.get(d) ?? 0) + 1);
  }

  const touched: Record<string, number> = {};
  const untouched: string[] = [];
  const underNamedDir: Record<string, number> = {};
  paths.forEach((path, i) => {
    if (counts[i] > 0) {
      touched[path] = counts[i];
      return;
    }
    untouched.push(path);
    const rel = (path.startsWith("inputs/") ? path.slice(7) : path).toLowerCase();
    const parts = rel.split("/");
    let viaDir = 0;
    for (let k = 0; k < parts.length; k++) viaDir += dirCounts.get(parts.slice(0, k).join("/")) ?? 0;
    if (viaDir) underNamedDir[path] = viaDir;
  });
  return {
    unavailable: null,
    inputs: paths.length,
    untouched,
    touched,
    under_named_dir: underNamedDir,
    calls_scanned: scanned,
    clipped_calls: clippedCalls,
    grounding,
    grounded_via_job: viaJob,
  };
}

/** The coverage in the words the report and the summary use: what no command named, and no more. */
export function coverageLine(c: CoverageReport): string {
  if (c.unavailable) return `not computed: ${c.unavailable}`;
  if (!c.inputs) return "no evidence files listed";
  const walked = Object.keys(c.under_named_dir).length;
  return `${c.untouched.length} of ${c.inputs} evidence file${c.inputs === 1 ? "" : "s"} named by no command or job request on the trace (${c.calls_scanned} call${c.calls_scanned === 1 ? "" : "s"} matched)${
    walked ? `; ${walked} of those ${walked === 1 ? "sits" : "sit"} under a directory a command named, which a walk may have read` : ""
  }${c.clipped_calls ? `; ${c.clipped_calls} call${c.clipped_calls === 1 ? " was" : "s were"} kept cut short by the trace, and a name past the cut is not seen` : ""}. A file a command named, or a job request listed as an input, was not necessarily examined.`;
}

if (process.argv[1] && resolve(process.argv[1]) === resolve(fileURLToPath(import.meta.url))) {
  const args = process.argv.slice(2);
  const sandbox = args.find((a) => !a.startsWith("--"));
  if (!sandbox) {
    console.error("Usage: coverage.ts <sandbox> [--json]");
    process.exit(2);
  }
  const c = await coverageOf(sandbox);
  if (args.includes("--json")) {
    process.stdout.write(`${JSON.stringify(c, null, 2)}\n`);
  } else {
    process.stdout.write(`Coverage: ${coverageLine(c)}\n`);
    for (const p of c.untouched) process.stdout.write(`  untouched  ${p}${c.under_named_dir[p] ? `  (under a directory named by ${c.under_named_dir[p]} call${c.under_named_dir[p] === 1 ? "" : "s"})` : ""}\n`);
    const ungrounded = Object.entries(c.grounding).filter(([, g]) => g === "not in the trace");
    process.stdout.write(`Grounding: ${ungrounded.length} ledger entr${ungrounded.length === 1 ? "y's" : "ies'"} source named by no earlier call, nor by a job the entry cites that was given an evidence input${ungrounded.length ? `: ${ungrounded.map(([s]) => `E-${s}`).join(", ")}` : ""}\n`);
    if (c.grounded_via_job.length) process.stdout.write(`  ${c.grounded_via_job.length} grounded only through a job the entry cites: ${c.grounded_via_job.map((s) => `E-${s}`).join(", ")}\n`);
  }
  process.exit(c.unavailable && !Object.keys(c.grounding).length ? 1 : 0);
}
