/**
 * The access record (docs/adr/0018): who reached a sensitive output, joined
 * from the chains the run already writes, by one reader.
 *
 * There is no register of its own. Four places already hold the facts, each
 * in a chain that custody seals:
 *
 *   - the store's journal: `job_started.scope.auto_declared` and
 *     `job_committed.sensitive.because`, the jobs that took a sensitive
 *     output as an input and the way the harness found it;
 *   - the trace: the hub's own `sensitive_access` lines (SensitiveAccessArgs
 *     below), written for a seat's read of a sensitive output and for a page
 *     of a job's output an API call returned;
 *   - the ledger: an entry that cites a sensitive output;
 *   - the operator's audit (`runs/operator-audit.jsonl`): the console's
 *     `console_view` lines.
 *
 * The reader keeps three kinds of evidence apart, because they are three
 * different things (`EvidenceKind`): a link the harness verified (a declared
 * or added input of a job), a read the harness observed (a path or command
 * that names the output), and what an agent says it did (a ledger entry).
 * "Opened the container" is only ever the third. A tool, a format or a
 * program is named nowhere in it, and a value, a digest of one or a range of
 * its bytes is in no record this module reads or builds.
 *
 * The record is a lower bound (`LOWER_BOUND_SENTENCE`). It does not look at
 * what an agent printed, copied or wrote: ADR 0018 decision 6.
 *
 * Reading is read-only and never fails: a chain file that is missing is
 * empty, one that cannot be read, a line that is not JSON or not the shape
 * is a problem line on the result and the rest is read.
 *
 * The first half is the rules that decide, from one trace row of a seat and
 * the run's sensitive jobs, which outputs the call names (`classifyTraceRow`):
 * pure, and the one place they are written, for the hub that records the
 * lines and for the reader that checks them.
 *
 *   node --experimental-strip-types scripts/sensitive-access.ts <run-dir> [--json] [--derive]
 *        [--runs-dir DIR] [--run-id ID] [--job jN] [--seat NAME] [--verify]
 */
import { createReadStream } from "node:fs";
import { lstat, readFile } from "node:fs/promises";
import { basename, dirname, isAbsolute, join, posix, relative, resolve } from "node:path";
import { createInterface } from "node:readline";
import { fileURLToPath } from "node:url";
import { sensitiveIndex, sensitiveRefs, type BecauseHow, type SensitiveIndex } from "./output-hygiene.ts";

/** The sentence the report's section, custody and the command line end with, exactly (ADR 0018 decision 10). */
export const LOWER_BOUND_SENTENCE =
  "Reads through a computed path, through a copy that was not a recorded page, or by a program that opened it by a name the command does not hold are not seen. This list is a lower bound.";

/** What the record does not hold, said once beside the sentence above. */
export const HARNESS_READS_SENTENCE = "The harness's own reads (store sweeps, location checks, custody, the report) are not agent access and are not listed.";

// --- the rules: which outputs one trace row of a seat names -------------------------

/** The version of the matching below; a line carries it, so a later reader knows which rules made it. */
export const ACCESS_RULES = 1;

/** How the harness came to see the access: a path a tool was given, text a command held, a page an API call returned. */
export type AccessVia = "path" | "text" | "api_page";

/**
 * How sure it is. `certain`: bytes of the output were returned to the seat
 * (an API page). `path`: a read tool's path lies in the output. `text`: a
 * command's text names it. `maybe`: a command walks a root that holds it.
 */
export type AccessCertainty = "certain" | "path" | "text" | "maybe";

/** The part of a sensitive job's output that was reached. */
export type AccessPart = "out" | "log" | "blob" | "catalog" | "copy" | "stdout" | "stderr" | "run";

export type AccessHit = {
  /** The sensitive job; null for a reach that cannot be pinned to one (`candidates` then lists the ones it could hold). */
  job: string | null;
  candidates?: string[];
  via: AccessVia;
  certainty: AccessCertainty;
  part: AccessPart;
  /** What matched, from the run's directory: the path as the call named it (a blob by the part alone). */
  paths: string[];
};

/** The sensitive jobs of the run and how their bytes are recognised (output-hygiene `sensitiveIndex`). */
export type AccessIndex = Pick<SensitiveIndex, "jobs" | "content" | "genJob" | "aliasJob">;

/** A kept copy of an earlier access: the path it was kept as, to the sensitive job it holds. */
export type KeptCopies = ReadonlyMap<string, string>;

/** The tools whose argument is a path they read from. */
const PATH_TOOLS = new Set(["read", "grep", "find", "ls"]);
const SHELL_TOOLS = new Set(["bash", "powershell"]);

/** A job's files that say nothing of its content: its record, its manifest and its scope. */
const METADATA = /^(?:job|manifest|scope[\w.-]*|[\w.-]*\.manifest)\.json$/;
const PIPS = /^(?:[\w.-]+\.)?(?:stdout\.log|stderr\.log|pip-before\.txt|pip-after\.txt)$/;

/** The path a read tool was given: the fields the write guard looks for, in the same order. */
function toolPath(args: Record<string, unknown>): string | undefined {
  for (const key of ["path", "filePath", "file_path", "file"]) {
    const v = args[key];
    if (typeof v === "string" && v.trim()) return v;
  }
  return undefined;
}

/** A path named from the run's directory, or null when it points outside it. Collapses `.` and `..`. */
export function runRelative(sandbox: string, raw: string): string | null {
  const text = raw.trim();
  if (!text || text.includes("\0")) return null;
  const rel = isAbsolute(text) ? relative(sandbox, text) : text;
  if (isAbsolute(rel)) return null;
  const clean = posix.normalize(rel.split("\\").join("/")).replace(/\/+$/, "");
  if (clean === ".." || clean.startsWith("../")) return null;
  return clean === "." ? "" : clean;
}

/** One path, from the run's directory, to the sensitive job whose output it lies in; null when it lies in none. */
function pathJob(rel: string, ix: AccessIndex, copies: KeptCopies): { job: string; part: AccessPart; walk: boolean } | null {
  const job = /^store\/jobs\/([A-Za-z0-9_-]+)(?:\/(.*))?$/.exec(rel);
  if (job) {
    const [, id, rest = ""] = job;
    if (!ix.jobs.has(id)) return null;
    if (!rest) return { job: id, part: "out", walk: true };
    if (METADATA.test(rest)) return null;
    if (rest === "out" || rest.startsWith("out/")) return { job: id, part: "out", walk: false };
    // Another attempt's output sits beside it as `<attempt>.out/…`.
    if (/^[\w.-]+\.out(?:\/|$)/.test(rest)) return { job: id, part: "out", walk: false };
    return PIPS.test(rest) ? { job: id, part: "log", walk: false } : null;
  }
  const blob = /^store\/blobs\/([0-9a-f]{64})$/.exec(rel);
  if (blob) {
    const id = ix.content.get(blob[1]);
    return id && ix.jobs.has(id) ? { job: id, part: "blob", walk: false } : null;
  }
  const gen = /^catalog\/gen\/([a-z0-9-]+)(?:\/|$)/.exec(rel);
  if (gen) {
    const id = ix.genJob.get(gen[1]);
    return id && ix.jobs.has(id) ? { job: id, part: "catalog", walk: false } : null;
  }
  const alias = /^catalog\/([A-Za-z0-9._-]+)(?:\/|$)/.exec(rel);
  if (alias && alias[1] !== "gen" && alias[1] !== "revisions") {
    const id = ix.aliasJob.get(alias[1]);
    return id && ix.jobs.has(id) ? { job: id, part: "catalog", walk: false } : null;
  }
  for (const [kept, id] of copies) if (rel === kept || rel.startsWith(`${kept}/`)) return { job: id, part: "copy", walk: false };
  return null;
}

/** A path as it goes in a record: a blob is named by its part alone, since its name is the digest of its bytes. */
function shownPath(rel: string, part: AccessPart): string {
  return part === "blob" ? "store/blobs" : rel;
}

/** Whether a path is a root above many jobs' outputs: the store, its jobs or its blobs. */
function isRoot(rel: string): boolean {
  return rel === "store" || rel === "store/jobs" || rel === "store/blobs" || rel === "catalog" || rel === "catalog/gen";
}

function addHit(hits: Map<string, AccessHit>, job: string, part: AccessPart, via: AccessVia, certainty: AccessCertainty, path: string): void {
  const have = hits.get(job);
  if (!have) hits.set(job, { job, via, certainty, part, paths: [path] });
  else if (!have.paths.includes(path)) have.paths.push(path);
}

/** A glob over one path segment as the source of a regular expression: `*`, `?`, `[…]` and `{a,b}`. */
function globSource(seg: string): string {
  let out = "";
  for (let i = 0; i < seg.length; i += 1) {
    const c = seg[i];
    if (c === "*") out += "[^/]*";
    else if (c === "?") out += "[^/]";
    else if (c === "{") {
      const end = seg.indexOf("}", i);
      if (end < 0) out += "\\{";
      else {
        out += `(?:${seg.slice(i + 1, end).split(",").map(globSource).join("|")})`;
        i = end;
      }
    } else if (c === "[") {
      const end = seg.indexOf("]", i + 2);
      if (end < 0) out += "\\[";
      else {
        out += `[${seg.slice(i + 1, end).replace(/\\/g, "\\\\")}]`;
        i = end;
      }
    } else out += c.replace(/[.+^$()|\]\\}]/g, "\\$&");
  }
  return out;
}

/** A glob over one path segment as a regular expression; null for a segment that holds none. */
function segmentGlob(seg: string): RegExp | null {
  if (!/[*?[{]/.test(seg)) return null;
  try {
    return new RegExp(`^${globSource(seg)}$`);
  } catch {
    return null;
  }
}

/** The commands that read what they are given; a root or a glob named to anything else is not a reach. */
const READERS = /(?:^|[\s;&|(`'"=])(?:grep|egrep|fgrep|rg|ag|ack|find|tree|du|cat|head|tail|less|more|xargs|cp|rsync|tar|zip|7z|strings|xxd|hexdump|od|sort|sed|awk|wc|file|ls\s+-\w*R)\b/;
/** The ones that walk a directory they are given, which is what makes a bare `store` a root and not a word. */
const WALKERS = /(?:^|[\s;&|(`'"=])(?:grep\s+-\w*[rR]|grep\s+--recursive|egrep\s+-\w*[rR]|rg|ag|ack|find|tree|du|ls\s+-\w*R)\b/;
/** A word of a command: quotes and a leading `./` taken off. */
const SHELL_WORD = /[^\s"'`;|&<>()=]+/g;

function shellHits(cmd: string, sandbox: string, ix: AccessIndex, copies: KeptCopies): AccessHit[] {
  const hits = new Map<string, AccessHit>();
  const sensitive = [...ix.jobs.keys()];
  const rootReach = new Set<string>();

  // The paths the command holds, relative to the run when they lie in it.
  const words = new Set<string>();
  for (const m of cmd.matchAll(SHELL_WORD)) words.add(m[0]);
  // A path may also be joined to a prefix (`--path=store/…`, `$S/store/…`): search the text for the store's own names.
  const texts = new Set<string>();
  for (const m of cmd.matchAll(/(?:store\/(?:jobs|blobs)(?:\/[^\s"'`;|&<>()]*)?|catalog\/[^\s"'`;|&<>()]*|tool-output\/[^\s"'`;|&<>()]*)/g)) texts.add(m[0]);
  for (const t of texts) words.add(t);

  for (const w of words) {
    // The path of a word, in the run's directory; a word that is only part of one (`$S/store/jobs/j1/out/x`) is searched for the store's names.
    const rels = new Set<string>();
    const direct = runRelative(sandbox, w);
    if (direct !== null) rels.add(direct);
    const at = /(?:^|\/)((?:store\/(?:jobs|blobs)|catalog|tool-output)(?:\/.*)?)$/.exec(w);
    if (at) rels.add(posix.normalize(at[1]).replace(/\/+$/, ""));
    for (const rel of rels) {
      const found = pathJob(rel, ix, copies);
      if (found) {
        addHit(hits, found.job, found.part, "text", "text", shownPath(rel, found.part));
        continue;
      }
      if (isRoot(rel)) {
        // `store/jobs` is a directory of jobs whatever reads it; a bare `store` or `catalog` is a word unless something walks it.
        if (rel.includes("/") || WALKERS.test(cmd)) rootReach.add("*");
        continue;
      }
      // A glob over the jobs: store/jobs/j0000*/out/…
      const g = /^store\/jobs\/([^/]*[*?[{][^/]*)(?:\/.*)?$/.exec(rel);
      const re = g ? segmentGlob(g[1]) : null;
      if (re) {
        for (const id of sensitive) if (re.test(id)) rootReach.add(id);
        continue;
      }
      if (/^store\/(?:\*+|\*\/.*)$/.test(rel)) rootReach.add("*");
    }
  }

  // A job id the command holds on its own, with no path: it names the job.
  for (const m of cmd.matchAll(/(?<![A-Za-z0-9_-])j\d{6,}(?![A-Za-z0-9_-])/g)) {
    if (ix.jobs.has(m[0]) && !hits.has(m[0])) addHit(hits, m[0], "run", "text", "text", m[0]);
  }

  const out = [...hits.values()].sort((a, b) => (a.job! < b.job! ? -1 : a.job! > b.job! ? 1 : 0));
  // A root or a glob: only a command that reads or walks what it is given could reach the outputs under it.
  if (rootReach.size && (READERS.test(cmd) || WALKERS.test(cmd))) {
    const all = rootReach.has("*");
    const candidates = (all ? sensitive : [...rootReach]).filter((id) => !hits.has(id)).sort();
    if (candidates.length) out.push({ job: null, candidates, via: "text", certainty: "maybe", part: "run", paths: [] });
  }
  return out;
}

/**
 * The sensitive outputs one seat trace row names: for `read`, `grep`, `find`
 * and `ls`, the path the tool was given; for `bash` and `powershell`, the
 * command text. At most one entry per sensitive job, and one more for the
 * outputs a walked root could hold (`job: null`). Empty when the call names
 * none, or the run has no sensitive output.
 */
export function classifyTraceRow(row: { tool?: unknown; args?: unknown }, ix: AccessIndex, o: { sandbox: string; copies?: KeptCopies }): AccessHit[] {
  if (!ix.jobs.size && !(o.copies && o.copies.size)) return [];
  const tool = typeof row.tool === "string" ? row.tool : "";
  const args = row.args && typeof row.args === "object" ? (row.args as Record<string, unknown>) : {};
  const copies = o.copies ?? new Map<string, string>();
  if (SHELL_TOOLS.has(tool)) {
    return typeof args.command === "string" ? shellHits(args.command, o.sandbox, ix, copies) : [];
  }
  if (!PATH_TOOLS.has(tool)) return [];
  const raw = toolPath(args);
  // A search with no path searches the run's directory, where the tool is started.
  const rel = raw === undefined ? (tool === "grep" ? "" : null) : runRelative(o.sandbox, raw);
  if (rel === null) return [];
  const found = pathJob(rel, ix, copies);
  if (found) {
    // The job's own directory: a search walks it and reads its output; a read or a listing of it names files and holds none.
    if (found.walk && tool !== "grep") return [];
    return [{ job: found.job, via: "path", certainty: "path", part: found.part, paths: [shownPath(rel, found.part)] }];
  }
  // A root above many jobs, searched: it could read any of their outputs.
  if (tool === "grep" && (isRoot(rel) || rel === "")) {
    const candidates = [...ix.jobs.keys()].sort();
    return candidates.length ? [{ job: null, candidates, via: "path", certainty: "maybe", part: "run", paths: [rel] }] : [];
  }
  return [];
}

/**
 * A page of a sensitive job's output that an API answer returned to a seat:
 * certain, since the bytes were in the answer.
 */
export function apiPageHit(job: string, part: "stdout" | "stderr", path: string): AccessHit {
  return { job, via: "api_page", certainty: "certain", part, paths: [path] };
}

// --- the hub's line ---------------------------------------------------------------

export type SensitiveWhy = "secret_output" | "derived";

/** How the reader names an access: the hub's three ways, and the three the other chains give. */
export type AccessEventVia = AccessVia | "declared_input" | "auto_declared" | "cited" | "operator_view";

/** How the harness came to know of an access. Three, and kept apart. */
export type EvidenceKind =
  /** A link the harness verified: a job took the output as a declared input, or the harness added it for a job that named it. */
  | "harness_verified_link"
  /** A read the harness observed: a path or command that names the output, a page returned to a seat, a console view. */
  | "harness_observed_read"
  /** What an agent says it did: a ledger entry that cites the output. */
  | "agent_claim";

/**
 * The hub's line on the trace (the tool name `sensitive_access`, `agent` "system"),
 * its `args`: one for a seat's row that names a sensitive job's output, one
 * for a page of a job's output an API answer returned to a seat. The line
 * follows its row on the chain and points back at it (`tool_row`); it holds a
 * job, a part and the paths as the call named them, never a value, a digest of
 * one or a range of its bytes (a blob is named by its part alone). Its
 * `result` is `{ok: true, kept_as?}`: `kept_as` is the `tool-output/` file the
 * whole output was kept as, which a later read of the copy is noted against.
 * After 200 lines for one seat and one job the next carries `burst` and no
 * more are written: the rest are on the trace as the rows they come from.
 */
export type SensitiveAccessArgs = {
  /** ACCESS_RULES when the line was written. */
  rules: number;
  /** The seat whose socket the row or call came in on, whatever the row claims. */
  seat: string;
  via: AccessVia;
  certainty: AccessCertainty;
  on: {
    /** The sensitive job reached; null for a possible reach (`certainty: "maybe"`), where `candidates` lists the ones it could be. */
    job: string | null;
    candidates?: string[];
    part: AccessPart;
    why?: SensitiveWhy;
    paths?: string[];
  };
  /** The seat row the line was made from; a row sent again is noted once. */
  tool_row?: { agent: string; sid?: string; seq?: number; ts?: string; tool: string };
  /** An API page: which call, and which bytes of the log it returned. */
  api?: { fn: string; offset: number; bytes: number; total: number };
  burst?: { after: number; note: string };
};

export type SensitiveAccessResult = { ok: true; kept_as?: string };

const isRec = (v: unknown): v is Record<string, unknown> => typeof v === "object" && v !== null && !Array.isArray(v);
const str = (v: unknown): string | null => (typeof v === "string" ? v : null);
const num = (v: unknown): number | null => (typeof v === "number" && Number.isFinite(v) ? v : null);
const ID = /^[a-z0-9-]{1,64}$/;

const CERTAINTIES: readonly AccessCertainty[] = ["certain", "path", "text", "maybe"];
const VIAS: readonly AccessVia[] = ["path", "text", "api_page"];
const PARTS: readonly AccessPart[] = ["out", "log", "blob", "catalog", "copy", "stdout", "stderr", "run"];
const HOWS: readonly BecauseHow[] = ["declared", "digest", "generation", "alias", "named_in_text", "same_bytes"];

/** A line's `args`, read back, or why they are not the hub's. */
export function parseSensitiveAccessArgs(v: unknown): { ok: true; args: SensitiveAccessArgs } | { ok: false; why: string } {
  if (!isRec(v)) return { ok: false, why: "args is not an object" };
  const rules = num(v.rules);
  const seat = str(v.seat);
  const via = VIAS.find((x) => x === v.via);
  const certainty = CERTAINTIES.find((x) => x === v.certainty);
  if (rules === null) return { ok: false, why: "no rules version" };
  if (!seat) return { ok: false, why: "no seat" };
  if (!via) return { ok: false, why: `via ${JSON.stringify(v.via)} is not one of ${VIAS.join(", ")}` };
  if (!certainty) return { ok: false, why: `certainty ${JSON.stringify(v.certainty)} is not one of ${CERTAINTIES.join(", ")}` };
  const on = v.on;
  if (!isRec(on)) return { ok: false, why: "no `on`" };
  const job = on.job === null ? null : str(on.job);
  if (job !== null && !ID.test(job)) return { ok: false, why: "`on.job` is not a job id" };
  const part = PARTS.find((x) => x === on.part);
  if (!part) return { ok: false, why: `part ${JSON.stringify(on.part)} is not one of ${PARTS.join(", ")}` };
  const strings = (x: unknown): string[] | undefined => (Array.isArray(x) ? x.filter((y): y is string => typeof y === "string") : undefined);
  const candidates = strings(on.candidates)?.filter((x) => ID.test(x));
  const paths = strings(on.paths);
  let tool_row: SensitiveAccessArgs["tool_row"];
  if (v.tool_row !== undefined) {
    const r = v.tool_row;
    const agent = isRec(r) ? str(r.agent) : null;
    const tool = isRec(r) ? str(r.tool) : null;
    if (!isRec(r) || !agent || !tool) return { ok: false, why: "tool_row lacks agent or tool" };
    tool_row = { agent, tool, ...(typeof r.sid === "string" ? { sid: r.sid } : {}), ...(num(r.seq) !== null ? { seq: num(r.seq) as number } : {}), ...(typeof r.ts === "string" ? { ts: r.ts } : {}) };
  }
  const api = isRec(v.api) && str(v.api.fn) ? { fn: v.api.fn as string, offset: num(v.api.offset) ?? 0, bytes: num(v.api.bytes) ?? 0, total: num(v.api.total) ?? 0 } : undefined;
  const burst = isRec(v.burst) ? { after: num(v.burst.after) ?? 0, note: str(v.burst.note) ?? "" } : undefined;
  return {
    ok: true,
    args: {
      rules,
      seat,
      via,
      certainty,
      on: { job, part, ...(candidates ? { candidates } : {}), ...(on.why === "secret_output" || on.why === "derived" ? { why: on.why } : {}), ...(paths ? { paths } : {}) },
      ...(tool_row ? { tool_row } : {}),
      ...(api ? { api } : {}),
      ...(burst ? { burst } : {}),
    },
  };
}

/**
 * The args of the hub's line for one hit of one seat row, as the hub writes
 * them: the one place the line is made. `why` is the sensitive job's, from the
 * index; `row` the seat's row (`sid` and `seq` are how a row sent again is
 * noticed).
 */
export function accessLineArgs(seat: string, hit: AccessHit, o: { why?: SensitiveWhy; row?: { sid?: string; seq?: number; ts?: string; tool: string }; api?: SensitiveAccessArgs["api"] } = {}): SensitiveAccessArgs {
  return {
    rules: ACCESS_RULES,
    seat,
    via: hit.via,
    certainty: hit.certainty,
    on: { job: hit.job, ...(hit.candidates ? { candidates: hit.candidates } : {}), part: hit.part, ...(o.why ? { why: o.why } : {}), paths: hit.paths },
    ...(o.row ? { tool_row: { agent: seat, ...(o.row.sid !== undefined ? { sid: o.row.sid } : {}), ...(o.row.seq !== undefined ? { seq: o.row.seq } : {}), ...(o.row.ts ? { ts: o.row.ts } : {}), tool: o.row.tool } } : {}),
    ...(o.api ? { api: o.api } : {}),
  };
}

// --- the record -------------------------------------------------------------------

export type AccessEvent = {
  /** Where it is: `trace:L<line>`, `journal:<seq>`, `ledger:E-<seq>`, `operator-audit:L<line>`. */
  ref: string;
  /** ISO time of the line that holds it, when it has one. */
  at: string | null;
  source: "trace" | "journal" | "ledger" | "operator_audit";
  via: AccessEventVia;
  evidence: EvidenceKind;
  certainty: AccessCertainty;
  /** The sensitive job whose output was reached; null for a possible reach, where `maybe_jobs` lists them. */
  job: string | null;
  maybe_jobs?: string[];
  /** The seat that read, the seat that requested the job that took the output, the ledger entry's author. Null for the operator. */
  seat: string | null;
  /** The job that took the output as an input (declared_input, auto_declared). */
  by_job?: string;
  /** declared_input, auto_declared: the way the harness found the dependency. Null on a record from before the field. */
  how?: BecauseHow | null;
  part?: AccessPart | null;
  /** The paths the record holds: as the call named them, the path a job's text held, the ref a ledger entry cited. Never a value. */
  paths: string[];
  /** The seat row the hub's line was made from. */
  tool_row?: NonNullable<SensitiveAccessArgs["tool_row"]>;
  api?: SensitiveAccessArgs["api"];
  /** The `tool-output/` file the whole output was kept as. */
  kept_as?: string | null;
  /** The line says the seat and the job have more accesses than it wrote lines for. */
  burst?: boolean;
  /** ledger: the entry. */
  entry?: number;
  /** operator_audit: OS user and host. */
  operator?: string;
  /** The rules the hub's line was written under. */
  rules?: number;
  /** false for an event derived now from the trace by `accessRecord(..., {derive: true})`; true for what a chain holds. */
  recorded: boolean;
  /** A word about the row, where the record cannot say more (the way is not recorded; the line is from older rules). */
  note?: string;
};

/** One sensitive job, as the journal holds it. */
export type SensitiveJobInfo = {
  id: string;
  why: SensitiveWhy;
  /** The sensitive jobs it was made from (derived). */
  from: string[];
  declared: "tool_manifest" | null;
  /** The seat that requested it, from `job_accepted`. */
  seat: string | null;
  kind: string | null;
  accepted_at: string | null;
  committed_at: string | null;
};

/** A job as `job_accepted` holds it: who asked and when. Every job, sensitive or not. */
export type Request = { job: string; seat: string | null; at: string | null; kind: string | null };

/** A job with no declared scope: the sensitive jobs its mounts let it read when it started. Not a read. */
export type Reach = { job: string; seat: string | null; at: string | null; could_read: string[] };

export type Problem = { file: string; line: number | null; why: string };

export type AccessRecord = {
  rules: number;
  sandbox: string;
  events: AccessEvent[];
  jobs: SensitiveJobInfo[];
  /** Every job of the run, as it was asked for (what a seat asked for after it read an output). */
  requests: Request[];
  reach: Reach[];
  problems: Problem[];
  /** How many problems there were, including those past the ones kept. */
  problems_total: number;
  /** Ledger entries marked sensitive that cite no sensitive output (a flag, not an access). */
  ledger_marked_only: number;
  /** Which files were read: false for one that is not there. */
  sources: { trace: boolean; journal: boolean; ledger: boolean; operator_audit: boolean };
  derived: boolean;
  lower_bound: string;
  not_listed: string;
};

const PROBLEMS_KEPT = 200;

type Sink = { add: (file: string, line: number | null, why: string) => void };

/**
 * Each line of a JSON-lines file that is an object, one at a time (a trace
 * can be larger than a string holds). A file that is not there is `false`,
 * one that is a link, not a regular file or unreadable is a problem, a line
 * that is not a JSON object is a problem and the next is read.
 */
async function eachJsonLine(file: string, label: string, sink: Sink, each: (rec: Record<string, unknown>, line: number) => void): Promise<boolean> {
  const st = await lstat(file).catch((err: NodeJS.ErrnoException) => (err.code === "ENOENT" || err.code === "ENOTDIR" ? null : err));
  if (st === null) return false;
  if (st instanceof Error) {
    sink.add(label, null, `unreadable (${(st as NodeJS.ErrnoException).code ?? st.message})`);
    return false;
  }
  if (st.isSymbolicLink()) {
    sink.add(label, null, "a link, not the file");
    return false;
  }
  if (!st.isFile()) {
    sink.add(label, null, "not a regular file");
    return false;
  }
  try {
    const lines = createInterface({ input: createReadStream(file, { encoding: "utf8" }), crlfDelay: Infinity });
    let n = 0;
    for await (const raw of lines) {
      n += 1;
      if (!raw.trim()) continue;
      let v: unknown;
      try {
        v = JSON.parse(raw);
      } catch {
        sink.add(label, n, "not JSON");
        continue;
      }
      if (!isRec(v)) {
        sink.add(label, n, "not a JSON object");
        continue;
      }
      try {
        each(v, n);
      } catch (err) {
        sink.add(label, n, `not read (${(err as Error).message})`);
      }
    }
  } catch (err) {
    sink.add(label, null, `read stopped (${(err as NodeJS.ErrnoException).code ?? (err as Error).message})`);
  }
  return true;
}

const rowKey = (agent: string, sid: string | undefined, seq: number | undefined): string => `${agent}\0${sid ?? ""}\0${seq ?? ""}`;
/** Where a row can name the store, the catalogue, a kept output or a job: the rest need no look. */
const PROBE = /store|catalog|tool-output|j\d{6}/;

type SeatRow = { key: string; line: number; at: string | null; seat: string; tool: string; sid?: string; seq?: number; args: Record<string, unknown>; hits: AccessHit[] };
type Scan = { recorded: AccessEvent[]; rows: SeatRow[]; found: boolean };

/** The path a trace row's `full_output` names (a whole output kept under tool-output/), when it names one. */
function keptPath(result: unknown): string | null {
  if (!isRec(result)) return null;
  const f = result.full_output;
  return isRec(f) && typeof f.path === "string" ? f.path : typeof f === "string" ? f : null;
}

/**
 * The trace: the hub's lines as events, and every seat row the rules read,
 * classified now, in order, with the kept copies the lines (and the rows
 * before) leave: a read of a copy is the same access.
 */
async function scanTrace(S: string, index: SensitiveIndex, sink: Sink): Promise<Scan> {
  const recorded: AccessEvent[] = [];
  const rows: SeatRow[] = [];
  const copies = new Map<string, string>();
  const found = await eachJsonLine(join(S, "traces", "events.jsonl"), "traces/events.jsonl", sink, (rec, line) => {
    const tool = str(rec.tool);
    const agent = str(rec.agent);
    const at = str(rec.recv_ts) || str(rec.ts) || null;
    if (tool === "sensitive_access" && agent === "system") {
      const parsed = parseSensitiveAccessArgs(rec.args);
      if (!parsed.ok) {
        sink.add("traces/events.jsonl", line, `a sensitive_access line is not read (${parsed.why})`);
        return;
      }
      const a = parsed.args;
      const kept = isRec(rec.result) ? str(rec.result.kept_as) : null;
      recorded.push({
        ref: `trace:L${line}`,
        at,
        source: "trace",
        via: a.via,
        evidence: "harness_observed_read",
        certainty: a.certainty,
        job: a.on.job,
        ...(a.on.candidates ? { maybe_jobs: a.on.candidates } : {}),
        seat: a.seat,
        part: a.on.part,
        paths: a.on.paths ?? [],
        ...(a.tool_row ? { tool_row: a.tool_row } : {}),
        ...(a.api ? { api: a.api } : {}),
        kept_as: kept,
        ...(a.burst ? { burst: true, note: a.burst.note } : {}),
        rules: a.rules,
        recorded: true,
        ...(a.rules !== ACCESS_RULES ? { note: `written under rules ${a.rules}; this reader is at ${ACCESS_RULES}` } : {}),
      });
      if (kept && a.on.job) copies.set(kept, a.on.job);
      return;
    }
    if (!agent || agent === "system" || !tool || !isRec(rec.args)) return;
    const hits = classifyTraceRow({ tool, args: rec.args }, index, { sandbox: S, copies });
    const kept = keptPath(rec.result);
    if (kept) for (const h of hits) if (h.job) copies.set(kept, h.job);
    const sid = str(rec.sid) ?? undefined;
    const seq = num(rec.seq) ?? undefined;
    // A row is kept for the check against a line when it could be named by one (it mentions a store, a catalogue, a kept output or a job).
    if (hits.length || PROBE.test(JSON.stringify(rec.args))) rows.push({ key: rowKey(agent, sid, seq), line, at, seat: agent, tool, ...(sid ? { sid } : {}), ...(seq !== undefined ? { seq } : {}), args: rec.args, hits });
  });
  return { recorded, rows, found };
}

function becauseOf(v: unknown): Array<{ from: string; how: BecauseHow; object: string }> | undefined {
  if (!Array.isArray(v)) return undefined;
  const out: Array<{ from: string; how: BecauseHow; object: string }> = [];
  for (const b of v) {
    if (!isRec(b)) continue;
    const from = str(b.from);
    const how = HOWS.find((h) => h === b.how);
    if (!from || !ID.test(from) || !how) continue;
    out.push({ from, how, object: str(b.object) ?? "" });
  }
  return out;
}

const emptyIndex = (): SensitiveIndex => ({ jobs: new Map(), digests: new Map(), content: new Map(), genJob: new Map(), aliasJob: new Map() });

/**
 * The access record of a run: every access the chains hold, joined, in time
 * order. Reads `traces/events.jsonl`, `store/journal.jsonl`,
 * `ledger/entries.jsonl` and, beside the run, `operator-audit.jsonl`; writes
 * nothing. With `derive`, a seat row the rules read now and no line records
 * is added, `recorded: false`: for a run that predates the hub's lines.
 */
export async function accessRecord(sandboxArg: string, opts: { runsDir?: string; runId?: string; derive?: boolean } = {}): Promise<AccessRecord> {
  const S = resolve(sandboxArg);
  const problems: Problem[] = [];
  let total = 0;
  const sink: Sink = {
    add: (file, line, why) => {
      total += 1;
      if (problems.length < PROBLEMS_KEPT) problems.push({ file, line, why });
    },
  };
  const sources = { trace: false, journal: false, ledger: false, operator_audit: false };
  const events: AccessEvent[] = [];
  const jobs: SensitiveJobInfo[] = [];
  const reach: Reach[] = [];
  let ledgerMarkedOnly = 0;

  let index = emptyIndex();
  try {
    index = await sensitiveIndex(S);
  } catch (err) {
    sink.add("store/journal.jsonl", null, `the sensitive jobs could not be read (${(err as Error).message})`);
  }

  // The journal: who requested each job, what each job that declared no scope could read, and why a job is sensitive.
  const accepted = new Map<string, { seat: string | null; at: string | null; kind: string | null }>();
  const committed = new Map<string, { at: string | null; seq: number | null }>();
  const linkSeen = new Set<string>();
  const linkPairs = new Set<string>();
  sources.journal = await eachJsonLine(join(S, "store", "journal.jsonl"), "store/journal.jsonl", sink, (rec, line) => {
    const type = str(rec.type);
    const job = str(rec.job);
    if (!type || !job || !ID.test(job)) return;
    const at = str(rec.at);
    const seq = num(rec.seq) ?? line - 1;
    const link = (ev: AccessEvent) => events.push(ev);
    if (type === "job_accepted") {
      const requester = isRec(rec.requester) ? str(rec.requester.agent) : null;
      accepted.set(job, { seat: requester, at, kind: isRec(rec.spec) ? str(rec.spec.kind) : null });
    } else if (type === "job_started" && isRec(rec.scope)) {
      const seat = accepted.get(job)?.seat ?? null;
      if (Array.isArray(rec.scope.auto_declared)) {
        for (const a of rec.scope.auto_declared) {
          if (!isRec(a)) continue;
          const from = str(a.from);
          if (!from || !ID.test(from)) continue;
          const key = `${job}\0${from}\0named_in_text`;
          if (linkSeen.has(key)) continue;
          linkSeen.add(key);
          linkPairs.add(`${job}\0${from}`);
          link({ ref: `journal:${seq}`, at, source: "journal", via: "auto_declared", evidence: "harness_verified_link", certainty: "text", job: from, seat, by_job: job, how: "named_in_text", paths: str(a.matched) ? [a.matched as string] : [], recorded: true });
        }
      }
      if (Array.isArray(rec.scope.could_read_sensitive)) {
        const could = rec.scope.could_read_sensitive.filter((x): x is string => typeof x === "string" && ID.test(x));
        if (could.length) reach.push({ job, seat, at, could_read: could });
      }
    } else if (type === "job_committed") {
      committed.set(job, { at, seq });
      const sens = isRec(rec.sensitive) ? rec.sensitive : null;
      const because = sens ? becauseOf(sens.because) : undefined;
      const seat = accepted.get(job)?.seat ?? null;
      for (const b of because ?? []) {
        const key = `${job}\0${b.from}\0${b.how}`;
        if (linkSeen.has(key)) continue;
        linkSeen.add(key);
        linkPairs.add(`${job}\0${b.from}`);
        const auto = b.how === "named_in_text";
        link({ ref: `journal:${seq}`, at, source: "journal", via: auto ? "auto_declared" : "declared_input", evidence: "harness_verified_link", certainty: auto ? "text" : "certain", job: b.from, seat, by_job: job, how: b.how, paths: b.object ? [b.object] : [], recorded: true });
      }
    }
  });

  // The sensitive jobs and, for a derived one with no `because` (a record from before the field), the link without its way.
  for (const j of [...index.jobs.values()].sort((a, b) => (a.id < b.id ? -1 : 1))) {
    const s = j.sensitivity as unknown as Record<string, unknown> | null;
    const why: SensitiveWhy = isRec(s) && s.why === "secret_output" ? "secret_output" : "derived";
    const from = isRec(s) && Array.isArray(s.from) ? s.from.filter((x): x is string => typeof x === "string" && ID.test(x)) : [];
    const acc = accepted.get(j.id);
    jobs.push({ id: j.id, why, from, declared: isRec(s) && s.declared === "tool_manifest" ? "tool_manifest" : null, seat: acc?.seat ?? null, kind: acc?.kind ?? null, accepted_at: acc?.at ?? null, committed_at: committed.get(j.id)?.at ?? null });
    if (why === "derived" && !(isRec(s) && Array.isArray(s.because) && s.because.length > 0)) {
      for (const f of from) {
        if (linkPairs.has(`${j.id}\0${f}`)) continue;
        linkPairs.add(`${j.id}\0${f}`);
        const c = committed.get(j.id);
        events.push({ ref: c?.seq != null ? `journal:${c.seq}` : `store/jobs/${j.id}/job.json`, at: c?.at ?? null, source: "journal", via: "declared_input", evidence: "harness_verified_link", certainty: "certain", job: f, seat: acc?.seat ?? null, by_job: j.id, how: null, paths: [], recorded: true, note: "the way is not recorded (a record from before the field)" });
      }
    }
  }

  // The trace.
  const trace = await scanTrace(S, index, sink);
  sources.trace = trace.found;
  for (const e of trace.recorded) events.push(e);
  if (opts.derive) {
    const have = new Set(trace.recorded.filter((e) => e.tool_row).map((e) => `${rowKey((e.tool_row as { agent: string }).agent, e.tool_row?.sid, e.tool_row?.seq)}\0${e.job ?? "*"}`));
    const burst = new Set(trace.recorded.filter((e) => e.burst).map((e) => `${e.seat}\0${e.job ?? "*"}`));
    for (const r of trace.rows) {
      for (const h of r.hits) {
        if (have.has(`${r.key}\0${h.job ?? "*"}`) || burst.has(`${r.seat}\0${h.job ?? "*"}`)) continue;
        events.push({
          ref: `trace:L${r.line}`,
          at: r.at,
          source: "trace",
          via: h.via,
          evidence: "harness_observed_read",
          certainty: h.certainty,
          job: h.job,
          ...(h.candidates ? { maybe_jobs: h.candidates } : {}),
          seat: r.seat,
          part: h.part,
          paths: h.paths,
          tool_row: { agent: r.seat, ...(r.sid ? { sid: r.sid } : {}), ...(r.seq !== undefined ? { seq: r.seq } : {}), tool: r.tool },
          rules: ACCESS_RULES,
          recorded: false,
          note: "derived now from the trace by the rules; no line of the hub records it",
        });
      }
    }
  }

  // The ledger: an entry that cites a sensitive output is the agent's claim.
  sources.ledger = await (async () => {
    const entries: Array<{ seq: number; by: string | null; at: string | null; refs: string[]; sensitive: boolean }> = [];
    const found = await eachJsonLine(join(S, "ledger", "entries.jsonl"), "ledger/entries.jsonl", sink, (rec) => {
      const seq = num(rec.seq);
      if (seq === null) throw new Error("no seq");
      entries.push({ seq, by: str(rec.by), at: str(rec.at) ?? str(rec.ts), refs: Array.isArray(rec.refs) ? rec.refs.filter((x): x is string => typeof x === "string") : [], sensitive: rec.sensitive === true });
    });
    for (const e of entries) {
      let hits: Awaited<ReturnType<typeof sensitiveRefs>> = [];
      try {
        hits = await sensitiveRefs(S, e.refs);
      } catch (err) {
        sink.add("ledger/entries.jsonl", null, `E-${e.seq}: its refs could not be matched (${(err as Error).message})`);
      }
      for (const h of hits) events.push({ ref: `ledger:E-${e.seq}`, at: e.at, source: "ledger", via: "cited", evidence: "agent_claim", certainty: "certain", job: h.job, seat: e.by, paths: [h.ref], entry: e.seq, recorded: true });
      if (!hits.length && e.sensitive) ledgerMarkedOnly += 1;
    }
    return found;
  })();

  // The operator's console views.
  const runsDir = opts.runsDir ?? process.env.SWARM_RUNS_DIR ?? dirname(S);
  let runId = opts.runId ?? "";
  if (!runId) {
    try {
      const team = JSON.parse(await readFile(join(S, "team.json"), "utf8")) as unknown;
      runId = isRec(team) && typeof team.swarm_id === "string" ? team.swarm_id : "";
    } catch {
      runId = "";
    }
  }
  if (!runId) runId = basename(S);
  sources.operator_audit = await eachJsonLine(join(runsDir, "operator-audit.jsonl"), "operator-audit.jsonl", sink, (rec, line) => {
    if (rec.command !== "console_view") return;
    const argv = Array.isArray(rec.argv) ? rec.argv.map(String) : [];
    const cwd = str(rec.cwd) ?? "";
    if (!argv.includes(runId) && !cwd.startsWith(S)) return;
    const d = isRec(rec.detail) ? rec.detail : rec;
    const job = str(d.job);
    if (!job || !ID.test(job)) {
      sink.add("operator-audit.jsonl", line, "a console_view line names no job");
      return;
    }
    events.push({ ref: `operator-audit:L${line}`, at: str(rec.at), source: "operator_audit", via: "operator_view", evidence: "harness_observed_read", certainty: "certain", job, seat: null, paths: str(d.path) ? [d.path as string] : [], operator: `${str(rec.os_user) ?? "?"}@${str(rec.host) ?? "?"}`, recorded: true });
  });

  const order = new Map(events.map((e, i) => [e, i]));
  events.sort((a, b) => {
    if (a.at && b.at && a.at !== b.at) return a.at < b.at ? -1 : 1;
    if (!a.at !== !b.at) return a.at ? -1 : 1;
    return (order.get(a) ?? 0) - (order.get(b) ?? 0);
  });

  const requests = [...accepted].map(([job, a]) => ({ job, seat: a.seat, at: a.at, kind: a.kind }));
  return { rules: ACCESS_RULES, sandbox: S, events, jobs, requests, reach, problems, problems_total: total, ledger_marked_only: ledgerMarkedOnly, sources, derived: opts.derive === true, lower_bound: LOWER_BOUND_SENTENCE, not_listed: HARNESS_READS_SENTENCE };
}

// --- verification: record against the trace ----------------------------------------

export type AccessVerification = {
  rules: number;
  /** Rule versions the recorded lines were written under that are not this reader's. */
  rules_changed: number[];
  /** A recorded line whose tool row is not on the trace, or whose row the rules do not read as naming that job (FAIL in custody). */
  orphan: AccessEvent[];
  /** A seat row the rules read as a path or text access that no line records (WARN: the hub was down, or the rules moved). */
  unrecorded: Array<{ line: number; seat: string; tool: string; job: string | null; via: AccessVia; certainty: AccessCertainty }>;
  /** The same tool row recorded twice for the same job and way. */
  duplicate: AccessEvent[];
  ok: boolean;
};

/**
 * The recorded lines held to the trace they came from, and the trace held
 * to the lines: each `sensitive_access` line points at a tool row that is
 * on the trace and that the rules read as naming its job; each row the rules
 * read as a path or text access has a line (unless the seat and the job
 * reached the burst limit, where the line says the rest are on the trace).
 * When the lines were written under other rules the difference is told as
 * `rules_changed`, not as orphan or missing. Possible reaches (`maybe`) and
 * API pages are not held to a row.
 */
export async function verifyAccess(sandboxArg: string): Promise<AccessVerification> {
  const S = resolve(sandboxArg);
  const sink: Sink = { add: () => undefined };
  let index = emptyIndex();
  try {
    index = await sensitiveIndex(S);
  } catch {
    // the record names it
  }
  const scan = await scanTrace(S, index, sink);
  const byKey = new Map(scan.rows.map((r) => [r.key, r]));
  const changed = [...new Set(scan.recorded.map((e) => e.rules ?? 0).filter((v) => v !== ACCESS_RULES))].sort((a, b) => a - b);
  const orphan: AccessEvent[] = [];
  const duplicate: AccessEvent[] = [];
  const seen = new Set<string>();
  const recordedKeys = new Set<string>();
  const burst = new Set<string>();
  for (const e of scan.recorded) {
    if (e.burst) {
      burst.add(`${e.seat}\0${e.job ?? "*"}`);
      continue;
    }
    const t = e.tool_row;
    if (!t) continue;
    const key = rowKey(t.agent, t.sid, t.seq);
    const dup = `${key}\0${e.job ?? "*"}\0${e.via}`;
    if (seen.has(dup)) duplicate.push(e);
    seen.add(dup);
    recordedKeys.add(`${key}\0${e.job ?? "*"}`);
    const row = byKey.get(key);
    if (!row || !row.hits.some((h) => h.job === e.job)) orphan.push(e);
  }
  const unrecorded: AccessVerification["unrecorded"] = [];
  for (const r of scan.rows) {
    for (const h of r.hits) {
      if (h.certainty === "maybe" || recordedKeys.has(`${r.key}\0${h.job ?? "*"}`) || burst.has(`${r.seat}\0${h.job ?? "*"}`)) continue;
      unrecorded.push({ line: r.line, seat: r.seat, tool: r.tool, job: h.job, via: h.via, certainty: h.certainty });
    }
  }
  const moved = changed.length > 0;
  return { rules: ACCESS_RULES, rules_changed: changed, orphan: moved ? [] : orphan, unrecorded: moved ? [] : unrecorded, duplicate, ok: !moved && !orphan.length && !unrecorded.length && !duplicate.length };
}

// --- provenance ------------------------------------------------------------------

/** A job that took a sensitive output as an input, and the verified link that says so. */
export type ProvenanceChild = { link: AccessEvent; node: ProvenanceNode; /** Already shown elsewhere in the chain (or past the depth limit): this one stands for it and is not opened again. */ repeated: boolean };

export type ProvenanceNode = {
  job: string;
  why: SensitiveWhy | null;
  seat: string | null;
  kind: string | null;
  declared: "tool_manifest" | null;
  /** harness_verified_link: the jobs that took this job's output as an input. */
  used_by: ProvenanceChild[];
  /** harness_observed_read: seats that read it, the console's views. */
  observed: AccessEvent[];
  /** agent_claim: ledger entries that cite it. */
  claims: AccessEvent[];
  /** Jobs that could have read it (no declared scope) and did not say. Reach, not a read. */
  could_be_read_by: string[];
  /** An inference, not a record: later jobs of a seat that read it, which declared no link to it. */
  later_jobs_of_readers: Array<{ seat: string; job: string; at: string | null }>;
  /** The jobs it was made from are not among the sensitive jobs the record holds. */
  source_unknown: boolean;
};

export type Provenance = { roots: ProvenanceNode[]; evidence_kinds: readonly EvidenceKind[]; lower_bound: string };

const MAX_DEPTH = 300;
const EVIDENCE_KINDS: readonly EvidenceKind[] = ["harness_verified_link", "harness_observed_read", "agent_claim"];

/**
 * The chains of use of each sensitive output: from a root (a job run as
 * secret output) to the jobs made from it and theirs, each with its three
 * kinds of evidence apart. A job made from two is shown under both, opened
 * once. A derived job none of whose sources is among the record's jobs is a
 * root of its own, `source_unknown`. Pure.
 */
export function provenance(rec: AccessRecord): Provenance {
  const info = new Map(rec.jobs.map((j) => [j.id, j]));
  const bySource = new Map<string, AccessEvent[]>();
  const observed = new Map<string, AccessEvent[]>();
  const claims = new Map<string, AccessEvent[]>();
  const push = (m: Map<string, AccessEvent[]>, k: string, e: AccessEvent) => (m.has(k) ? m.get(k)!.push(e) : m.set(k, [e]));
  for (const e of rec.events) {
    if (!e.job) {
      for (const j of e.maybe_jobs ?? []) push(observed, j, e);
      continue;
    }
    if (e.evidence === "harness_verified_link" && e.by_job) push(bySource, e.job, e);
    else if (e.evidence === "harness_observed_read") push(observed, e.job, e);
    else if (e.evidence === "agent_claim") push(claims, e.job, e);
  }
  const could = new Map<string, string[]>();
  for (const r of rec.reach) for (const j of r.could_read) (could.get(j) ?? could.set(j, []).get(j)!).push(r.job);
  const opened = new Set<string>();

  const shallow = (id: string): ProvenanceNode => {
    const j = info.get(id);
    return { job: id, why: j?.why ?? null, seat: j?.seat ?? null, kind: j?.kind ?? null, declared: j?.declared ?? null, used_by: [], observed: [], claims: [], could_be_read_by: [], later_jobs_of_readers: [], source_unknown: false };
  };
  const build = (id: string, linked: Set<string>, depth = 0): ProvenanceNode => {
    const j = info.get(id);
    const reads = observed.get(id) ?? [];
    const kids: ProvenanceChild[] = [];
    const node: ProvenanceNode = {
      job: id,
      why: j?.why ?? null,
      seat: j?.seat ?? null,
      kind: j?.kind ?? null,
      declared: j?.declared ?? null,
      used_by: kids,
      observed: reads,
      claims: claims.get(id) ?? [],
      could_be_read_by: [...new Set(could.get(id) ?? [])].sort(),
      later_jobs_of_readers: [],
      source_unknown: j?.why === "derived" && !j.from.some((f) => info.has(f)),
    };
    opened.add(id);
    for (const link of bySource.get(id) ?? []) {
      const child = link.by_job as string;
      linked.add(child);
      // A chain deeper than the limit (a damaged journal) is not opened further; the child stands for itself.
      if (opened.has(child) || depth >= MAX_DEPTH) {
        kids.push({ link, node: shallow(child), repeated: true });
        continue;
      }
      kids.push({ link, node: build(child, linked, depth + 1), repeated: false });
    }
    // Later jobs of a seat that read it (a harness-observed read of the trace), which no verified link ties to it.
    const readers = new Map<string, string>();
    for (const e of reads) if (e.seat && e.at && e.source === "trace" && e.via !== "api_page" && (!readers.has(e.seat) || e.at < readers.get(e.seat)!)) readers.set(e.seat, e.at);
    const later: ProvenanceNode["later_jobs_of_readers"] = [];
    for (const [seat, from] of readers) {
      for (const k of rec.requests) {
        if (k.seat !== seat || k.job === id || linked.has(k.job) || !k.at || k.at <= from) continue;
        later.push({ seat, job: k.job, at: k.at });
      }
    }
    node.later_jobs_of_readers = later;
    return node;
  };
  const roots: ProvenanceNode[] = [];
  for (const j of rec.jobs) if ((j.why === "secret_output" || !j.from.some((f) => info.has(f))) && !opened.has(j.id)) roots.push(build(j.id, new Set()));
  // A cycle among derived jobs (a damaged journal) is opened from its first member, so nothing is left out.
  for (const j of rec.jobs) if (!opened.has(j.id)) roots.push(build(j.id, new Set()));
  return { roots, evidence_kinds: EVIDENCE_KINDS, lower_bound: LOWER_BOUND_SENTENCE };
}

// --- words -----------------------------------------------------------------------

const CERT_WORD: Record<AccessCertainty, string> = { certain: "certain", path: "a named path", text: "text that names it", maybe: "a possible reach" };

function when(at: string | null): string {
  return at ? at.replace("T", " ").replace(/\.\d+Z$|Z$/, "") : "no time";
}

function eventLine(e: AccessEvent): string {
  const tag = e.evidence === "harness_verified_link" ? "harness verified" : e.evidence === "harness_observed_read" ? "harness observed" : "agent claim";
  const who = e.seat ?? (e.operator ? `operator ${e.operator}` : "?");
  const first = e.paths[0] ?? "";
  const what =
    e.via === "declared_input" || e.via === "auto_declared"
      ? `job ${e.by_job} took it as an input${e.how ? ` (${e.how.replace(/_/g, " ")})` : ""}${first ? `: ${first}` : ""}`
      : e.via === "cited"
        ? `E-${e.entry} cites ${first}`
        : e.via === "operator_view"
          ? `console view${first ? ` of ${first}` : ""}`
          : e.via === "api_page"
            ? `a page of its ${e.part ?? "log"} was returned${e.api ? ` (${e.api.bytes} bytes from ${e.api.offset} of ${e.api.total})` : ""}`
            : e.burst
              ? "further accesses by this seat are on the trace as the rows they come from"
              : e.certainty === "maybe"
                ? `${e.tool_row?.tool ?? "a command"} could reach it: ${first || "a root it walks"}`
                : e.part === "copy"
                  ? `${e.tool_row?.tool ?? "read"} a kept copy of an earlier read: ${first}`
                  : `${e.tool_row?.tool ?? "read"} ${first}`;
  return `${who}: ${what}  ${when(e.at)}  [${tag}, ${CERT_WORD[e.certainty]}${e.recorded ? "" : ", derived now"}]`;
}

/** The record as text: the events in time order, the chains of use, the problems, and the sentence that says what the list is. */
export function renderAccess(rec: AccessRecord, prov: Provenance = provenance(rec)): string {
  const out: string[] = [];
  out.push(`Access to sensitive outputs: ${rec.events.length} event${rec.events.length === 1 ? "" : "s"} on ${rec.jobs.length} sensitive job${rec.jobs.length === 1 ? "" : "s"}${rec.derived ? " (seat reads derived now from the trace)" : ""}`);
  if (!rec.jobs.length) out.push("  No job of the run is sensitive.");
  const show = (n: ProvenanceNode, depth: number, via?: AccessEvent) => {
    const pad = "  ".repeat(depth + 1);
    const head = n.why === "secret_output" ? `secret_output${n.declared ? " (tool manifest)" : ""}` : n.why === "derived" ? "derived" : "not in the record";
    out.push(`${pad}${via ? "used by " : ""}${n.job}${n.kind ? `  ${n.kind}` : ""}${n.seat ? `  ${n.seat}` : ""}  ${head}${n.source_unknown ? "  (its sources are not among the sensitive jobs of the record)" : ""}`);
    if (via) out.push(`${pad}  link: ${eventLine(via)}`);
    for (const e of n.observed) out.push(`${pad}  read:  ${eventLine(e)}`);
    for (const e of n.claims) out.push(`${pad}  claim: ${eventLine(e)}`);
    if (n.could_be_read_by.length) out.push(`${pad}  could have been read (no declared scope; not a read) by: ${n.could_be_read_by.join(", ")}`);
    for (const l of n.later_jobs_of_readers) out.push(`${pad}  inference, not a record: ${l.seat} requested ${l.job} later (${when(l.at)}) and declared no link to it`);
    for (const c of n.used_by) {
      if (c.repeated) out.push(`${pad}  used by ${c.node.job}  (shown elsewhere)\n${pad}    link: ${eventLine(c.link)}`);
      else show(c.node, depth + 1, c.link);
    }
  };
  for (const r of prov.roots) show(r, 0);
  // What a chain holds of a job the journal does not show as sensitive (a record kept without its journal, a damaged one): said, not dropped.
  const known = new Set(rec.jobs.map((j) => j.id));
  const loose = rec.events.filter((e) => (e.job ? !known.has(e.job) : !(e.maybe_jobs ?? []).some((j) => known.has(j))));
  if (loose.length) {
    out.push("  Not under a sensitive job of this record:");
    for (const e of loose) out.push(`    ${e.job ?? "a possible reach"}: ${eventLine(e)}`);
  }
  if (rec.ledger_marked_only) out.push(`  ${rec.ledger_marked_only} ledger entr${rec.ledger_marked_only === 1 ? "y is" : "ies are"} marked sensitive and cite no sensitive output.`);
  if (rec.problems_total) {
    out.push(`Not read (${rec.problems_total}):`);
    for (const p of rec.problems) out.push(`  ${p.file}${p.line ? `:${p.line}` : ""}: ${p.why}`);
    if (rec.problems_total > rec.problems.length) out.push(`  and ${rec.problems_total - rec.problems.length} more`);
  }
  out.push(rec.not_listed, rec.lower_bound);
  return `${out.join("\n")}\n`;
}

// --- command line ----------------------------------------------------------------

/** The record narrowed to one job and/or one seat (the events that touch it; the reach it names). */
export function narrow(rec: AccessRecord, o: { job?: string; seat?: string }): AccessRecord {
  if (!o.job && !o.seat) return rec;
  const keep = (e: AccessEvent) => (!o.job || e.job === o.job || e.by_job === o.job || (e.maybe_jobs ?? []).includes(o.job)) && (!o.seat || e.seat === o.seat);
  return { ...rec, events: rec.events.filter(keep), reach: o.job ? rec.reach.filter((r) => r.job === o.job || r.could_read.includes(o.job as string)) : rec.reach };
}

async function main(argv: string[]): Promise<number> {
  const flag = (name: string): string | undefined => {
    const i = argv.indexOf(name);
    return i >= 0 ? argv[i + 1] : undefined;
  };
  const valueFlags = new Set(["--runs-dir", "--run-id", "--job", "--seat"]);
  const positional = argv.filter((a, i) => !a.startsWith("--") && !valueFlags.has(argv[i - 1] ?? ""));
  const dir = positional[0];
  if (!dir) {
    console.error("Usage: sensitive-access.ts <run-dir> [--json] [--derive] [--verify] [--runs-dir DIR] [--run-id ID] [--job jN] [--seat NAME]");
    return 2;
  }
  const st = await lstat(resolve(dir)).catch(() => null);
  if (!st?.isDirectory()) {
    console.error(`sensitive-access: ${dir} is not a directory`);
    return 1;
  }
  const opts = { runsDir: flag("--runs-dir"), runId: flag("--run-id"), derive: argv.includes("--derive") };
  const rec = narrow(await accessRecord(dir, opts), { job: flag("--job"), seat: flag("--seat") });
  const prov = provenance(rec);
  const ver = argv.includes("--verify") ? await verifyAccess(dir) : null;
  if (argv.includes("--json")) {
    process.stdout.write(`${JSON.stringify({ record: rec, provenance: prov, ...(ver ? { verification: ver } : {}) }, null, 2)}\n`);
    return 0;
  }
  process.stdout.write(renderAccess(rec, prov));
  if (ver) {
    process.stdout.write(
      `Verification against the trace: ${ver.ok ? "the lines and the rows agree" : "differences"}` +
        `${ver.rules_changed.length ? `; the lines were written under rules ${ver.rules_changed.join(", ")} and this is ${ver.rules}` : ""}` +
        `${ver.orphan.length ? `; ${ver.orphan.length} line(s) point at a row that is not on the trace or that the rules do not read as naming their job` : ""}` +
        `${ver.unrecorded.length ? `; ${ver.unrecorded.length} row(s) the rules read have no line` : ""}` +
        `${ver.duplicate.length ? `; ${ver.duplicate.length} line(s) repeat a row` : ""}\n`,
    );
  }
  return 0;
}

if (process.argv[1] && resolve(process.argv[1]) === resolve(fileURLToPath(import.meta.url))) {
  process.exit(await main(process.argv.slice(2)).catch((err) => {
    console.error(`sensitive-access: ${(err as Error).message}`);
    return 1;
  }));
}
