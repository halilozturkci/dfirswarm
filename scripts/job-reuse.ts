/**
 * Reuse hints (docs/adr/0017): the work another seat already did, said when
 * a job is accepted, and the outputs that are byte for byte an earlier
 * job's, said when it is committed. Nothing is merged here: a hint names the
 * other job and its outputs, and the job runs as asked. Only a typed recipe
 * over the same object is answered with the earlier job (job-service.ts
 * recipeKey), because its identity is the recipe's own.
 *
 * What a job does is read at the level duplication happens, object ×
 * operation (the shadow key this replaces hashed the whole spec, timeout and
 * wording included, and matched none of 393, 127 and 190 keyed jobs in the
 * last CTF round):
 * - its objects: the declared scope as resolved (job-scope.ts), each file by
 *   its sha256 and each directory of the evidence, the store or the
 *   catalogue by its path (neither changes during a run). An agent's own
 *   work/ or tool-output/ file is live, and not known by its digest until
 *   the job starts: it is left out. A job that declares nothing, or `all`,
 *   has no objects to compare, and is never similar;
 * - its operation: a tool job's tool, a command's leading command word
 *   (protocol.ts leadingCommand), and whether the text or the arguments are
 *   the same, byte for byte.
 *
 * Only digests, paths and command words are read: no format, no tool's
 * output, nothing a program printed.
 */
import { leadingCommand } from "../extensions/protocol.ts";
import { resolveScope } from "./job-scope.ts";
import type { Manifest } from "./evidence-store.ts";

/** One object a job reads: a file by content (and where it sits), or a directory of the run by its path. */
export type ReuseObject = { path: string; sha256?: string; dir?: true };

/** A job's reuse identity, kept on its job_accepted line. `op` is tool:<name> or command:<word>; null when a command has no readable leading word. */
export type Reuse = { op: string | null; objects: ReuseObject[] };

/** What a similar job is, as the new job's requester is told it and the journal keeps it. */
export type Similar = {
  job: string;
  seat: string;
  name?: string;
  state: string;
  status?: string;
  outputs?: { files: number; bytes: number; path: string };
  /** Its outputs are sensitive (docs/adr/0016). Said; nothing about the other job is withheld. */
  sensitive?: true;
  lead: string | null;
  /** same: the same objects; overlap: some of them (shared says how many of the new job's). */
  objects: "same" | "overlap";
  shared: number;
  /** What the operation has in common: the same command or the same tool and arguments, or only the leading word or the tool. */
  match: "same command" | "same leading command" | "same tool and arguments" | "same tool";
  op: string | null;
  independent?: true;
};

/** An earlier job's output a committed job's file equals, byte for byte. */
export type SameAs = { path: string; sha256: string; bytes: number; job: string; file: string };

/** How many similar jobs a job_run answer shows; the rest are on the job_similar line, every one, and the answer says so. */
export const SIMILAR_SHOWN = 8;
/** How many same_as files a job's view shows; the rest are on the job_same_as line, every one. */
export const SAME_AS_SHOWN = 20;

type Spec = { kind: string; tool?: string; args?: Record<string, unknown>; command?: string; scope?: string; inputs: string[]; seal?: unknown };

function canonical(v: unknown): string {
  if (Array.isArray(v)) return `[${v.map(canonical).join(",")}]`;
  if (v && typeof v === "object") return `{${Object.keys(v as object).sort().map((k) => `${JSON.stringify(k)}:${canonical((v as Record<string, unknown>)[k])}`).join(",")}}`;
  return JSON.stringify(v);
}

/** A job's operation: the tool it runs, or its command's leading word. */
export function opOf(spec: Pick<Spec, "kind" | "tool" | "command">): string | null {
  if (spec.kind === "tool" && spec.tool) return `tool:${spec.tool}`;
  if (spec.kind === "command") {
    const word = leadingCommand(spec.command ?? "");
    return word ? `command:${word}` : null;
  }
  return null;
}

/**
 * The reuse identity of a tool or command job that declared what it reads,
 * or null: a recipe, a detect pass, an import, a seal, a job over everything,
 * or a declaration that does not resolve (it is refused elsewhere).
 */
export async function reuseOf(S: string, spec: Spec, o: { collections?: string[][]; targets?: string[] } = {}): Promise<Reuse | null> {
  if (spec.kind !== "command" && spec.kind !== "tool") return null;
  if (spec.scope !== "declared" || spec.seal || spec.inputs.includes("all")) return null;
  const r = await resolveScope(S, spec.inputs, o);
  if (!r.ok) return null;
  const seen = new Set<string>();
  const objects: ReuseObject[] = [];
  for (const x of r.objects) {
    if (x.area === "work") continue;
    const obj: ReuseObject = x.shape === "dir" ? { path: x.path.replace(/\/+$/, ""), dir: true } : { path: x.path, ...(x.sha256 ? { sha256: x.sha256 } : {}) };
    const k = keyOf(obj);
    if (seen.has(k)) continue;
    seen.add(k);
    objects.push(obj);
  }
  objects.sort((a, b) => keyOf(a).localeCompare(keyOf(b)));
  return { op: opOf(spec), objects };
}

/** An object's identity: a file by its content (by its path only when the record has no digest), a directory by its path. */
export function keyOf(o: ReuseObject): string {
  return o.dir ? `dir:${o.path}` : o.sha256 ? `sha256:${o.sha256}` : `path:${o.path}`;
}

function inside(child: ReuseObject, parent: ReuseObject): boolean {
  return Boolean(parent.dir) && child.path.startsWith(`${parent.path}/`);
}

/**
 * Whether two jobs read the same objects: `same` when their identities are
 * the same set, `overlap` when some object of the new job is one of the
 * other's (or lies in a directory of it, or holds one), null when none is.
 * `shared` counts the new job's objects the other also reads.
 */
export function objectsMatch(mine: ReuseObject[], theirs: ReuseObject[]): { objects: "same" | "overlap"; shared: number } | null {
  if (!mine.length || !theirs.length) return null;
  const keys = new Set(theirs.map(keyOf));
  const shared = mine.filter((m) => keys.has(keyOf(m)) || theirs.some((t) => inside(m, t) || inside(t, m))).length;
  if (!shared) return null;
  const same = mine.length === theirs.length && mine.every((m) => keys.has(keyOf(m)));
  return { objects: same ? "same" : "overlap", shared };
}

/** Whether two jobs do the same operation, and how closely; null when they do not. */
export function opMatch(mine: Spec, theirs: Spec, mineOp: string | null, theirOp: string | null): Similar["match"] | null {
  if (mine.kind === "command" && theirs.kind === "command") {
    if ((mine.command ?? "") === (theirs.command ?? "")) return "same command";
    return mineOp && mineOp === theirOp ? "same leading command" : null;
  }
  if (mine.kind === "tool" && theirs.kind === "tool" && mine.tool && mine.tool === theirs.tool) {
    return canonical(mine.args ?? {}) === canonical(theirs.args ?? {}) ? "same tool and arguments" : "same tool";
  }
  return null;
}

const CLOSE: Record<Similar["match"], number> = { "same command": 0, "same tool and arguments": 0, "same leading command": 1, "same tool": 1 };

/** Similar jobs in the order they are worth reading: the same operation first, then the same objects, then done and sound, then the newest. */
export function rankSimilar(list: Similar[]): Similar[] {
  const done = (s: Similar) => (s.state === "committed" && s.status === "ok" ? 0 : s.state === "committed" ? 2 : 1);
  return [...list].sort((a, b) => CLOSE[a.match] - CLOSE[b.match] || (a.objects === "same" ? 0 : 1) - (b.objects === "same" ? 0 : 1) || done(a) - done(b) || b.job.localeCompare(a.job));
}

/**
 * What a job_run answer carries: the similar jobs worth reading, at most
 * SIMILAR_SHOWN (the rest counted, and named where every one is), and one
 * sentence on what to do with them. Nothing when there are none. When the
 * job_similar line could not be written (`recorded` false), nothing names
 * the rest, so every one is in the answer.
 */
export function similarView(job: string, similar: Similar[], independent: boolean, recorded = true): Record<string, unknown> {
  if (!similar.length) return {};
  const shown = recorded ? similar.slice(0, SIMILAR_SHOWN) : similar;
  const rest = similar.length - shown.length;
  const note = independent
    ? `Recorded as an independent reproduction: other seats ran the same work over the same objects (${shown.map((s) => s.job).join(", ")}${rest ? ", …" : ""}). Keep your result apart from theirs until yours is in, then compare.`
    : `Other seats ran the same work over the same objects: read their outputs (job:<id>/<path>) before you rely on a second run. This job runs as asked (job_status cancel=true stops it); when a second run is the point, say independent: true.`;
  return { similar: shown, ...(rest ? { similar_more: `${rest} more, every one on the job_similar line for ${job} in store/journal.jsonl` } : {}), similar_note: note };
}

/**
 * The files of a job's manifest that are an earlier job's output byte for
 * byte, by sha256, against `index` (sha256 → the first job output with those
 * bytes). An empty file is the same as every other empty file and says
 * nothing: it is left out.
 */
export function sameAsOf(job: string, files: Manifest["files"], index: Map<string, { job: string; file: string }>): SameAs[] {
  const out: SameAs[] = [];
  for (const f of files) {
    if (!f.bytes) continue;
    const hit = index.get(f.sha256);
    if (!hit || hit.job === job) continue;
    out.push({ path: f.path, sha256: f.sha256, bytes: f.bytes, job: hit.job, file: hit.file });
  }
  return out;
}

/** Adds a committed job's files to the index; the first job to have written given bytes keeps them. */
export function indexOutputs(index: Map<string, { job: string; file: string }>, job: string, files: Manifest["files"]): void {
  for (const f of files) if (f.bytes && !index.has(f.sha256)) index.set(f.sha256, { job, file: f.path });
}

/** A job view's same_as: at most SAME_AS_SHOWN files, the rest counted and named where every one is. */
export function sameAsView(job: string, same: SameAs[]): Record<string, unknown> {
  if (!same.length) return {};
  const shown = same.slice(0, SAME_AS_SHOWN);
  const rest = same.length - shown.length;
  return {
    same_as: shown.map((s) => ({ path: s.path, bytes: s.bytes, same_as: `job:${s.job}/${s.file}` })),
    ...(rest ? { same_as_more: `${rest} more, every one on the job_same_as line for ${job} in store/journal.jsonl` } : {}),
  };
}
