/**
 * Output hygiene (docs/adr/0016): which sealed job outputs are sensitive,
 * and what follows from that for the jobs that read them, the ledger entries
 * that cite them and a package that hands them over.
 *
 * A job run with `secret_output: true` (one whose output may hold a secret:
 * a key, a credential or a decrypted value the evidence holds) has every
 * output marked sensitive when it is sealed, whatever it wrote: the harness does not read
 * the bytes to decide. A job that reads such an output (it declared it, by
 * path or digest, or a catalogue generation made from it; or, with no scope
 * declared, its command names the job) is sealed sensitive too, as derived,
 * with the jobs it was made from. A ledger entry whose refs reach a
 * sensitive output is recorded sensitive (protocol.ts appendLedgerEntry), so
 * the run's sensitivity rules (B9, redaction) hold its words from then on.
 *
 * The package side reads the same records: every sensitive output (and its
 * job's stdout and stderr) is withheld from a redacted package whole, named
 * with its sha256, and the whole package is scanned for what should not be
 * in it, the small text outputs of sensitive jobs included.
 *
 * A tool's manifest may declare it too (`secret_output`, below): a job of
 * such a tool is run as if the agent had said so, so the protection does not
 * rest on an agent remembering a skill's sentence.
 *
 * Nothing here knows a tool or a format: sensitivity comes from what the
 * agent declared, what a tool's manifest declared and what the job service
 * recorded, and is matched by path, digest and job id.
 */
import { readdir, readFile, stat } from "node:fs/promises";
import { join, resolve } from "node:path";

/**
 * The six ways a job comes to be made from a sensitive output, as
 * `derivedFrom` tells them apart: it declared a file of the sensitive job
 * (`declared`), or bytes with that job's digest wherever they sat
 * (`digest`), or a catalogue generation (`generation`) or alias (`alias`) it
 * made; it declared no scope and its command, arguments, source or targets
 * name the job (`named_in_text`); or a file it sealed is byte for byte one
 * the sensitive job wrote (`same_bytes`).
 */
export type BecauseHow = "declared" | "digest" | "generation" | "alias" | "named_in_text" | "same_bytes";

/**
 * One reason a job is made from a sensitive output: the sensitive job
 * (`from`), the way (`how`) and what matched (`object`): the path its scope
 * manifest names, the store path (or the id) its text held, or its own sealed
 * file for `same_bytes`. A job id and a path; never a value or a digest.
 */
export type Because = { from: string; how: BecauseHow; object: string };

export type Sensitivity = {
  /** secret_output: the job was run so; derived: made from a sensitive output. */
  why: "secret_output" | "derived";
  /** The sensitive jobs it was made from (derived). */
  from: string[];
  note: string;
  /** secret_output only: the tool's manifest declared it (the agent's flag was not needed). */
  declared?: "tool_manifest";
  /** derived only: why, for each sensitive job and each way it applies (absent on a record from before this field). */
  because?: Because[];
};

/** A sealed output file, as its job's manifest lists it. */
export type OutputFile = { path: string; sha256: string; bytes: number };

export type SensitiveJob = { id: string; sensitivity: Sensitivity; status: string | null; files: OutputFile[]; logs: string[] };

export type SensitiveIndex = {
  jobs: Map<string, SensitiveJob>;
  /** Every sensitive output file's sha256, to the job that sealed it. */
  digests: Map<string, string>;
  /** Every byte a sensitive job wrote, by sha256 (its outputs and its stdout, stderr and pip logs), to the job: what a copy anywhere in the run is matched by. */
  content: Map<string, string>;
  /** A catalogue generation's job, and an alias's, from the journal: for resolving a catalog/ path to a sensitive job without reading each record. */
  genJob: Map<string, string>;
  aliasJob: Map<string, string>;
};

/** A job's sensitivity for its own spec: secret_output, or null (derived sensitivity is decided at seal, from what it read). */
export function ownSensitivity(spec: { secret_output?: unknown; secret_output_by?: unknown }): Sensitivity | null {
  if (spec.secret_output !== true) return null;
  return spec.secret_output_by === "tool_manifest"
    ? { why: "secret_output", from: [], note: "run with secret_output, as the tool's manifest declares: every output it sealed is sensitive", declared: "tool_manifest" }
    : { why: "secret_output", from: [], note: "run with secret_output: every output it sealed is sensitive" };
}

/**
 * What a tool's manifest says about its jobs' secret output, one key,
 * `secret_output`:
 *
 *   "required"                      every job of the tool is secret output
 *   { "when_args": ["a", "b"] }     a job is secret output when any of these
 *                                   arguments is set (the tool's secret mode,
 *                                   such as a flag that writes values to a file)
 *
 * A name in `when_args` is one of the tool's own `params`, declared
 * `type: "boolean"` with no `default` other than false (absent, null or false;
 * the harness applies no defaults, so a flag that is on unless the caller says
 * otherwise would never be seen as set; and a boolean is the one type whose "set" nobody can read two ways).
 * Left out, the tool declares nothing and the agent's flag decides, as before.
 * A declaration that is not one of these is not guessed at: the job is refused
 * with the reason, because ignoring it would drop the protection the author
 * asked for. Pure; it reads one key and knows no tool.
 *
 * Applies to `kind: tool` jobs only: a recipe (a pack's, or a forged tool that
 * declares the recipe protocol) cannot honour it and a recipe that carries the
 * key is refused (recipeSecretRefusal).
 */
export type SecretDeclaration = { mode: "required" } | { mode: "when_args"; args: string[] };

export function parseSecretDeclaration(raw: unknown, params: Record<string, unknown> | undefined, present: boolean): { ok: true; declaration: SecretDeclaration | null } | { ok: false; reason: string } {
  if (!present) return { ok: true, declaration: null };
  if (raw === "required") return { ok: true, declaration: { mode: "required" } };
  const bad = (why: string) => ({ ok: false as const, reason: `its manifest's secret_output is not understood (${why}); it is "required", or { "when_args": [parameter names] }` });
  if (typeof raw !== "object" || raw === null || Array.isArray(raw)) return bad("not \"required\" and not an object");
  const keys = Object.keys(raw);
  if (keys.length !== 1 || keys[0] !== "when_args") return bad("an object takes when_args and nothing else");
  const args = (raw as { when_args: unknown }).when_args;
  if (!Array.isArray(args) || !args.length || args.length > 16 || args.some((a) => typeof a !== "string" || !a)) return bad("when_args is a list of one to sixteen parameter names");
  const seen = new Set<string>();
  for (const a of args as string[]) {
    if (seen.has(a)) return bad(`${a} is named twice`);
    seen.add(a);
    if (!params || typeof params !== "object" || Array.isArray(params)) return bad("the tool's params is not an object");
    if (!Object.hasOwn(params, a)) return bad(`${a} is not a parameter of the tool`);
    const p = (params as Record<string, unknown>)[a];
    if (typeof p !== "object" || p === null || Array.isArray(p) || (p as { type?: unknown }).type !== "boolean") return bad(`${a} is not declared type "boolean"`);
    // A default is allowed only when absent, null or false: the one rule scripts/pack.sh applies too, in terms no language reads two ways ([] and {} are truthy in JS, falsy in Python).
    const dflt = (p as { default?: unknown }).default;
    if (dflt !== undefined && dflt !== null && dflt !== false) return bad(`${a} has a default other than false, and the harness applies no defaults`);
  }
  return { ok: true, declaration: { mode: "when_args", args: args as string[] } };
}

/**
 * Whether an argument is set, read to fail closed: anything but undefined, null
 * and false counts (0, "", [] and {} too). A declaration over-sealing a job is
 * harmless; one that under-seals leaks. Declared parameters are booleans, so
 * the other values do not reach a job today.
 */
export function argIsSet(v: unknown): boolean {
  return v !== undefined && v !== null && v !== false;
}

/**
 * Why a recipe cannot run when its manifest or recipe.json carries a
 * `secret_output` key, or null. The declaration applies to `kind: tool` jobs;
 * a recipe job is never run as secret output by it, so the key is refused
 * rather than ignored (ignoring it would drop the protection its author asked for).
 */
export function recipeSecretRefusal(id: string, present: boolean): string | null {
  return present ? `${id} carries a secret_output declaration, which applies to tool jobs only (job_run kind: tool) and cannot be honoured by a recipe job; the recipe is not run` : null;
}

/** Whether a tool's declaration makes a job with these arguments secret output. */
export function declaredSecretOutput(declaration: SecretDeclaration | null, args: Record<string, unknown>): boolean {
  if (!declaration) return false;
  return declaration.mode === "required" || declaration.args.some((a) => Object.hasOwn(args, a) && argIsSet(args[a]));
}

/** What `derivedFrom` reads: the objects the job's scope manifest names (null for a broad-scope job), its text, and how a sensitive output is recognised. */
export type DerivedInput = {
  /** The scope manifest's accessible files and expanded objects, each with the digest the snapshot hashed where it has one; null for a broad-scope job. */
  objects: Array<{ path: string; sha256?: string }> | null;
  text: string;
  sensitive: ReadonlySet<string>;
  /** A digest of any byte a sensitive job wrote (its output or a log), to the job. */
  contentJob: (sha256: string) => string | null;
  generationJob: (generation: string) => string | null;
  aliasJob: (alias: string) => string | null;
};

/**
 * Why a job was made from each sensitive job it was made from, from what it
 * actually read (the executed snapshot, not a scope resolved anew): each
 * object of its scope manifest that is a sensitive job's output — declared
 * by its path under store/jobs/<id>/, by the digest the snapshot hashed (a
 * work copy of a sensitive output has the same bytes and so the same digest,
 * wherever it sits), or by a catalogue generation or alias a sensitive job
 * made — and, for a job that declared no scope (it could read every object),
 * each sensitive job its command, arguments, source or targets name by id or
 * by its store path. One entry per sensitive job and way, the first object
 * that matched; sorted by job, then by way. Pure.
 */
export function derivedBecause(o: DerivedInput): Because[] {
  const out = new Map<string, Because>();
  const add = (from: string | null, how: BecauseHow, object: string) => {
    if (from && o.sensitive.has(from) && !out.has(`${from}\0${how}`)) out.set(`${from}\0${how}`, { from, how, object });
  };
  for (const x of o.objects ?? []) {
    const declaredJob = /^store\/jobs\/([a-z0-9-]{1,64})(?:\/|$)/.exec(x.path)?.[1] ?? null;
    // The bytes it read, wherever they came from (a work copy of a sensitive output is the same digest).
    const sha = (x.sha256 ?? /^store\/blobs\/([0-9a-f]{64})$/.exec(x.path)?.[1])?.toLowerCase();
    const byDigest = sha ? o.contentJob(sha) : null;
    // A file of the job itself, declared by path, is `declared`; its digest says the same thing a second time.
    if (byDigest && byDigest !== declaredJob) add(byDigest, "digest", x.path);
    add(declaredJob, "declared", x.path);
    const gen = /^catalog\/gen\/([a-z0-9-]+)(?:\/|$)/.exec(x.path)?.[1];
    if (gen) add(o.generationJob(gen), "generation", x.path);
    const alias = /^catalog\/([A-Za-z0-9._-]+)(?:\/|$)/.exec(x.path)?.[1];
    if (alias && alias !== "gen" && alias !== "revisions") add(o.aliasJob(alias), "alias", x.path);
  }
  if (o.objects === null) {
    for (const id of o.sensitive) {
      const word = id.replace(/[.*+?^${}()|[\]\\-]/g, "\\$&");
      const re = new RegExp(`(?<![A-Za-z0-9_-])${word}(?![A-Za-z0-9_-])`);
      if (!re.test(o.text)) continue;
      // What the text held of it: its store path where it names one, else the id.
      const path = new RegExp(`store/jobs/${word}(?![A-Za-z0-9_-])[^\\s"'\`;|&<>()]*`).exec(o.text)?.[0];
      add(id, "named_in_text", path ?? id);
    }
  }
  return [...out.values()].sort((a, b) => (a.from < b.from ? -1 : a.from > b.from ? 1 : a.how < b.how ? -1 : a.how > b.how ? 1 : 0));
}

/** The sensitive jobs a job was made from (`derivedBecause`, one id each), sorted. */
export function derivedFrom(o: DerivedInput): string[] {
  return [...new Set(derivedBecause(o).map((b) => b.from))].sort();
}

/** The files a job's scope manifest names it read, each with the digest the snapshot hashed (a work copy carries the sensitive output's digest). Null when the job declared no scope. */
export async function snapshotObjects(sandbox: string, scopeManifest: string | undefined): Promise<Array<{ path: string; sha256?: string }> | null> {
  if (!scopeManifest) return null;
  const m = await readJson<{ scope?: string; accessible?: Array<{ path?: string; sha256?: string }>; expanded?: Array<{ path?: string; sha256?: string }> }>(join(resolve(sandbox), scopeManifest));
  if (!m) return null;
  const out: Array<{ path: string; sha256?: string }> = [];
  for (const x of [...(m.accessible ?? []), ...(m.expanded ?? [])]) if (typeof x.path === "string") out.push({ path: x.path, ...(typeof x.sha256 === "string" ? { sha256: x.sha256 } : {}) });
  return out;
}

export function derivedSensitivity(from: string[], because: Because[] = []): Sensitivity | null {
  return from.length ? { why: "derived", from, note: `made from the sensitive output of ${from.join(", ")}: every output it sealed is sensitive`, ...(because.length ? { because } : {}) } : null;
}

/** A recipe's or a detect pass's target paths: part of its scope, whatever it declared. */
export function targetPaths(spec: { target?: { paths?: string[] }; targets?: Array<{ paths?: string[] }> }): string[] {
  return [...(spec.target?.paths ?? []), ...(spec.targets ?? []).flatMap((t) => t.paths ?? [])];
}

/** What decides a job's sensitivity: its spec, and the scope manifest its start recorded. */
export type SensitivityJob = {
  id: string;
  spec: {
    secret_output?: unknown;
    secret_output_by?: unknown;
    command?: string;
    args?: unknown;
    source?: string;
    inputs?: readonly string[];
    target?: { paths?: string[] };
    targets?: Array<{ paths?: string[] }>;
  };
  scope?: { manifest?: string };
};

/**
 * Whether what a job seals is sensitive (docs/adr/0016), and why: it was run
 * with secret_output, or it read a sensitive output. What it read is what it
 * declared (resolved again now: a sealed output does not change), by path,
 * by digest, or a catalogue generation or alias a sensitive job made; a job
 * that declared no scope could read everything, so it is held to what its
 * command, arguments, source and targets name; and a file it sealed that is
 * byte for byte what a sensitive job wrote (`outputs`) is sensitive whatever
 * it read. A derived answer carries `because` (`derivedBecause`). Null when
 * none of these.
 *
 * `running: true` asks it of a job that has not sealed yet (nothing to read
 * `outputs` from): the scope manifest its start recorded is there, and what
 * it declares to read counts as named, so the answer is the one the seal
 * will give except for a file that turns out to be a sensitive output's
 * bytes.
 */
export async function jobSensitivity(sandbox: string, job: SensitivityJob, o: { outputs?: ReadonlyArray<{ sha256: string; path?: string }>; running?: boolean } = {}): Promise<Sensitivity | null> {
  const own = ownSensitivity(job.spec);
  if (own) return own;
  // Every job the run holds sensitive so far, from the journal (the record), by their outputs' and logs' digests.
  const index = await sensitiveIndex(sandbox);
  const sensitive = new Set([...index.jobs.keys()].filter((id) => id !== job.id));
  if (!sensitive.size) return null;
  // What the job actually read: its scope manifest's snapshot (each file's digest hashed at the job's start), not a scope resolved anew.
  const objects = await snapshotObjects(sandbox, job.scope?.manifest);
  const text = [job.spec.command ?? "", job.spec.args ? JSON.stringify(job.spec.args) : "", job.spec.source ?? "", ...targetPaths(job.spec), ...(o.running ? (job.spec.inputs ?? []) : [])].join("\n");
  const because = derivedBecause({
    objects,
    text,
    sensitive,
    contentJob: (sha) => (index.content.get(sha) === job.id ? null : index.content.get(sha) ?? null),
    generationJob: (gen) => index.genJob.get(gen) ?? null,
    aliasJob: (alias) => index.aliasJob.get(alias) ?? null,
  });
  // A file it sealed that is byte for byte what a sensitive job wrote (what
  // same_as names, ADR 0017) holds what that output holds, however it was
  // made. Read from the journal's sensitive jobs and their manifests (the
  // index above, the empty file excluded), never from the same_as index,
  // which may still be building: the sensitivity is decided before
  // job_committed is written.
  for (const f of o.outputs ?? []) {
    const from = index.content.get(f.sha256) ?? null;
    if (from && from !== job.id) because.push({ from, how: "same_bytes", object: f.path ?? "" });
  }
  const seen = new Set<string>();
  const kept = because.filter((b) => (seen.has(`${b.from}\0${b.how}`) ? false : (seen.add(`${b.from}\0${b.how}`), true)));
  kept.sort((a, b) => (a.from < b.from ? -1 : a.from > b.from ? 1 : a.how < b.how ? -1 : a.how > b.how ? 1 : 0));
  return derivedSensitivity([...new Set(kept.map((b) => b.from))].sort(), kept);
}

async function readJson<T>(path: string): Promise<T | null> {
  try {
    return JSON.parse(await readFile(path, "utf8")) as T;
  } catch {
    return null;
  }
}

let cache: { key: string; index: SensitiveIndex } | null = null;

/**
 * The run's sensitive outputs, from the store's journal (every
 * job_committed line that says it is sensitive) and each such job's
 * manifest. Read again whenever the journal changes.
 */
export async function sensitiveIndex(sandbox: string): Promise<SensitiveIndex> {
  const S = resolve(sandbox);
  const journal = join(S, "store", "journal.jsonl");
  const st = await stat(journal).catch(() => null);
  const key = `${journal}:${st?.size ?? 0}:${st?.mtimeMs ?? 0}`;
  if (cache?.key === key) return cache.index;
  const jobs = new Map<string, SensitiveJob>();
  const digests = new Map<string, string>();
  const content = new Map<string, string>();
  const genJob = new Map<string, string>();
  const aliasJob = new Map<string, string>();
  const logsOf = new Map<string, string[]>();
  const text = st ? await readFile(journal, "utf8").catch(() => "") : "";
  // A store with no journal (a run copied without it, a hand-made fixture): the jobs' own records say it.
  if (!st) {
    for (const id of await projectedSensitive(S)) {
      const j = await readJson<{ status?: string; sensitive?: Sensitivity; logs?: Record<string, string> }>(join(S, "store", "jobs", id, "job.json"));
      if (j?.sensitive) {
        jobs.set(id, { id, sensitivity: j.sensitive, status: j.status ?? null, files: [], logs: [] });
        if (j.logs) logsOf.set(id, Object.values(j.logs).filter((h) => /^[0-9a-f]{64}$/.test(h)));
      }
    }
  }
  for (const line of text.split("\n")) {
    if (!line.trim()) continue;
    let l: { type?: string; job?: string; status?: string; sensitive?: Sensitivity; generation?: string; alias?: string; logs?: Record<string, string> };
    try {
      l = JSON.parse(line) as typeof l;
    } catch {
      continue;
    }
    if (!l || typeof l !== "object") continue;
    if (l.type === "generation_committed" && l.generation && l.job) {
      genJob.set(String(l.generation), String(l.job));
      if (l.alias) aliasJob.set(String(l.alias).replace(/^catalog\//, "").replace(/\/$/, ""), String(l.job));
    }
    // A line that is not a job id and a record is not read (a hand-made or damaged journal reaches the paths below).
    if (l.type !== "job_committed" || typeof l.job !== "string" || !/^[a-z0-9-]{1,64}$/.test(l.job) || !l.sensitive || typeof l.sensitive !== "object") continue;
    jobs.set(l.job, { id: l.job, sensitivity: l.sensitive, status: l.status ?? null, files: [], logs: [] });
    if (l.logs) logsOf.set(l.job, Object.values(l.logs).filter((h) => /^[0-9a-f]{64}$/.test(h)));
  }
  // The empty file's digest is not a mark: it says nothing, and every empty
  // file of the run would match it (a sensitive job's empty log among them).
  const EMPTY = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
  for (const j of jobs.values()) {
    const m = await readJson<{ files?: Array<{ path?: string; sha256?: string; bytes?: number }> }>(join(S, "store", "jobs", j.id, "manifest.json"));
    j.files = (Array.isArray(m?.files) ? m.files.filter((f) => f && typeof f === "object") : []).map((f) => ({ path: String(f.path ?? ""), sha256: String(f.sha256 ?? ""), bytes: Number(f.bytes) || 0 }));
    j.logs = logsOf.get(j.id) ?? [];
    for (const f of j.files) if (/^[0-9a-f]{64}$/.test(f.sha256) && f.sha256 !== EMPTY && !digests.has(f.sha256)) digests.set(f.sha256, j.id);
    for (const sha of [...j.files.map((f) => f.sha256), ...j.logs]) if (/^[0-9a-f]{64}$/.test(sha) && sha !== EMPTY && !content.has(sha)) content.set(sha, j.id);
  }
  const index = { jobs, digests, content, genJob, aliasJob };
  cache = { key, index };
  return index;
}

/** The job a catalogue generation was made by (catalog/gen/<gen>/generation.json), or null. */
export async function generationJob(sandbox: string, gen: string): Promise<string | null> {
  if (!/^[a-z0-9-]+$/.test(gen)) return null;
  const g = await readJson<{ job?: unknown }>(join(resolve(sandbox), "catalog", "gen", gen, "generation.json"));
  return typeof g?.job === "string" ? g.job : null;
}

/** A ref that reaches a sensitive output: which ref, which job, and why that job's outputs are sensitive. */
export type SensitiveRef = { ref: string; job: string; why: Sensitivity["why"] };

/**
 * Which of an entry's refs reach a sensitive output: a job's file or its
 * logs (job:<id>…), a sealed file by digest (sha256:<hex>), or a member of a
 * catalogue generation a sensitive job made (member:<gen>#<n>).
 */
export async function sensitiveRefs(sandbox: string, refs: readonly string[]): Promise<SensitiveRef[]> {
  if (!refs.length) return [];
  const index = await sensitiveIndex(sandbox);
  if (!index.jobs.size) return [];
  const out: SensitiveRef[] = [];
  for (const ref of refs) {
    const r = ref.trim();
    let job: string | null = null;
    const j = /^job:([a-z0-9-]{1,64})(?:\/|$)/.exec(r)?.[1];
    if (j) job = j;
    const sha = /^sha256:([0-9a-fA-F]{64})$/.exec(r)?.[1]?.toLowerCase();
    if (sha) job = index.content.get(sha) ?? null;
    const gen = /^member:([a-z0-9-]+)#\d+$/.exec(r)?.[1];
    if (gen) job = index.genJob.get(gen) ?? (await generationJob(sandbox, gen));
    const hit = job ? index.jobs.get(job) : undefined;
    if (hit) out.push({ ref: r, job: hit.id, why: hit.sensitivity.why });
  }
  return out;
}

/**
 * Every ledger entry that is sensitive, and why: marked so by its author (or
 * by the harness when it cited a sensitive output), or citing a sensitive
 * output while not marked (an entry recorded before the harness marked such
 * entries): the second kind is named, so a package treats it as marked.
 */
export async function sensitiveEntries(sandbox: string, entries: ReadonlyArray<{ seq: number; sensitive?: boolean; refs?: string[] }>): Promise<Map<number, string>> {
  const out = new Map<number, string>();
  for (const e of entries) {
    if (e.sensitive) {
      out.set(e.seq, "marked sensitive");
      continue;
    }
    const hits = await sensitiveRefs(sandbox, e.refs ?? []);
    if (hits.length) out.set(e.seq, `cites sensitive output (${hits.map((h) => `${h.ref}: job ${h.job}, ${h.why === "secret_output" ? "secret_output" : "derived"}`).join("; ")})`);
  }
  return out;
}

/** The largest sensitive output whose whole text is a scan word: a recovered secret is one short file, not a report. */
export const OUTPUT_WORD_MAX_BYTES = 256;

/**
 * Whether a small output's whole text is a word the scan looks for: one
 * line, and shaped like a secret rather than a status (six characters or
 * more with a digit or a sign in it, or ten or more of anything), so a
 * result file that says "none" or "success" does not take every such word
 * out of a package.
 */
export function secretShaped(text: string): boolean {
  if (!text || /[\r\n]/.test(text)) return false;
  return (text.length >= 6 && /[^\p{L}\s]/u.test(text)) || text.length >= 10;
}

/**
 * What a manifest-wide scan looks for beside the ledger's sensitive words:
 * the whole text of each small sensitive output (a file of at most 256 bytes
 * with no NUL, trimmed, secret-shaped), with the job it came from. Its sha256
 * names it in any report of a hit, never its text.
 */
export async function outputWords(sandbox: string): Promise<Array<{ token: string; job: string; path: string }>> {
  const S = resolve(sandbox);
  const index = await sensitiveIndex(S);
  const out: Array<{ token: string; job: string; path: string }> = [];
  for (const j of index.jobs.values()) {
    for (const f of j.files) {
      if (f.bytes > OUTPUT_WORD_MAX_BYTES) continue;
      const bytes = await readFile(join(S, "store", "jobs", j.id, "out", f.path)).catch(() => null);
      if (!bytes || bytes.includes(0)) continue;
      const token = bytes.toString("utf8").trim();
      if (secretShaped(token) && !out.some((x) => x.token === token)) out.push({ token, job: j.id, path: f.path });
    }
  }
  return out;
}

/** Every sensitive job's directory entries a package lays out (store/jobs/<id>/…): its outputs and its logs, withheld whole. */
export function withheldPaths(index: SensitiveIndex): Array<{ job: string; rel: RegExp; why: string }> {
  return [...index.jobs.values()].map((j) => ({
    job: j.id,
    rel: new RegExp(`^store/jobs/${j.id}/(out/.+|stdout\\.log|stderr\\.log|[^/]+\\.stdout\\.log|[^/]+\\.stderr\\.log)$`),
    why: j.sensitivity.why === "secret_output" ? `job ${j.id} ran with secret_output` : `job ${j.id} was made from the sensitive output of ${j.sensitivity.from.join(", ")}`,
  }));
}

/**
 * Which job wrote the bytes a citation names, and that job's status, so a
 * partial output (a cancelled or stopped job's) is recognised however it is
 * cited (docs/adr/0016): a `job:<id>/<path>` by the file's own digest, so a
 * later job's byte-identical copy resolves to the job that wrote it first; a
 * bare `sha256:<hex>`; a `member:<gen>#<n>` through its generation. Built
 * once from the store: every job's status, and a map from each output
 * digest to the earliest job that wrote it (a cancelled producer wins over
 * a later copy, so its partial status is not lost).
 */
export async function producerIndex(sandbox: string): Promise<{ producerOf: (ref: string) => { job: string; status: string } | null }> {
  const S = resolve(sandbox);
  const dir = join(S, "store", "jobs");
  const status = new Map<string, string>();
  const fileDigest = new Map<string, string>(); // job/path (relative to out/) -> sha256
  const digestJob = new Map<string, string>(); // sha256 -> job that wrote it
  const partial: string[] = [];
  const ids = (await readdir(dir).catch(() => [] as string[])).filter((n) => /^[a-z0-9-]{1,64}$/.test(n)).sort();
  for (const id of ids) {
    const j = await readJson<{ status?: string }>(join(dir, id, "job.json"));
    if (j?.status) status.set(id, j.status);
    if (j?.status && (j.status === "cancelled" || j.status === "stopped")) partial.push(id);
  }
  // A partial producer's digests first, so a later copy of the same bytes resolves to it.
  const order = [...partial, ...ids.filter((id) => !partial.includes(id))];
  for (const id of order) {
    const m = await readJson<{ files?: Array<{ path?: string; sha256?: string }> }>(join(dir, id, "manifest.json"));
    for (const f of m?.files ?? []) {
      const sha = String(f.sha256 ?? "");
      if (/^[0-9a-f]{64}$/.test(sha)) {
        fileDigest.set(`${id}/${String(f.path ?? "")}`, sha);
        if (!digestJob.has(sha)) digestJob.set(sha, id);
      }
    }
  }
  const genJob = new Map<string, string>();
  const journal = await readFile(join(S, "store", "journal.jsonl"), "utf8").catch(() => "");
  for (const line of journal.split("\n")) {
    if (!line.includes("generation_committed")) continue;
    try {
      const l = JSON.parse(line) as { type?: string; generation?: string; job?: string };
      if (l.type === "generation_committed" && l.generation && l.job) genJob.set(String(l.generation), String(l.job));
    } catch {
      // the journal's own check names it
    }
  }
  const of = (job: string | null): { job: string; status: string } | null => (job && status.has(job) ? { job, status: status.get(job)! } : null);
  return {
    producerOf: (ref: string) => {
      const r = ref.trim();
      const jobRef = /^job:([a-z0-9-]{1,64})\/(.+)$/.exec(r) ?? /^job:([a-z0-9-]{1,64})$/.exec(r);
      if (jobRef) {
        const id = jobRef[1];
        const rel = (jobRef[2] ?? "").replace(/^out\//, "");
        // The bytes it names: the file's digest resolves to whatever job wrote them first (a partial producer wins).
        const sha = rel ? fileDigest.get(`${id}/${rel}`) ?? fileDigest.get(`${id}/out/${rel}`) : undefined;
        return of((sha && digestJob.get(sha)) ?? id);
      }
      const sha = /^sha256:([0-9a-fA-F]{64})$/.exec(r)?.[1]?.toLowerCase();
      if (sha) return of(digestJob.get(sha) ?? null);
      const gen = /^member:([a-z0-9-]+)#\d+$/.exec(r)?.[1];
      if (gen) return of(genJob.get(gen) ?? null);
      return null;
    },
  };
}

/** The job ids under store/jobs whose job.json says they are sensitive (the projection; the journal is the record). */
export async function projectedSensitive(sandbox: string): Promise<string[]> {
  const dir = join(resolve(sandbox), "store", "jobs");
  const out: string[] = [];
  for (const id of (await readdir(dir).catch(() => [] as string[])).sort()) {
    const j = await readJson<{ sensitive?: unknown }>(join(dir, id, "job.json"));
    if (j?.sensitive) out.push(id);
  }
  return out;
}
