/**
 * The store sweep (docs/adr/0013, "After the round-13 scoring"): a negative
 * is checked against everything the run already holds, not only against the
 * sources its coverage record names.
 *
 * On the round-13 scoring runs, five answers were written not determinable
 * while the row that answered two of them sat in a parser export the run
 * itself had made half an hour before; each passed a review, because the
 * reviews checked the answer against its coverage record's two or three
 * sources, never against the store. A coverage record now names what a hit
 * would contain (`looked_for`: literal strings), and the hub searches every
 * output the run holds for them when the record is written: every sealed
 * job output and job log, every import (evidence added late included: an
 * import is an output the run holds), every capture, every whole output the
 * harness kept under tool-output/. Not the input images: the coverage record
 * is where they are searched. Bytes and strings only, case-insensitive for
 * ASCII, in UTF-8 and in UTF-16LE, every file streamed whole: no format
 * parser and no per-tool code (the harness stays tool-agnostic). A budget of
 * bytes and time bounds a sweep; what it did not reach is named, and the
 * sweep is partial, never clean.
 *
 * The record is immutable and the sweep is not instant, so the result is a
 * line of its own in ledger/sweeps.jsonl, chained like the attestations and
 * bound to the coverage record by its hash. A record with looked_for and no
 * sweep line is pending. The gate (protocol.ts ledgerGate) reads them.
 *
 * The same bytes under several names are one object: a file the harness
 * kept under tool-output/ and the import it was sealed as are one, so a
 * record that names either names both (the run sd0e59d held three
 * negatives on kept outputs whose sealed imports their records named).
 *
 * The rules change, and a recorded line keeps what it was written under
 * (docs/adr/0013, "Re-reading after a rules change"): each line names the
 * version of the sweep's rules it was written by (`rules`; a line with none
 * is older than any versioned one). When the hub starts, and at the answers
 * check and the finish gate, a record whose latest line is older than this
 * harness's rules is read again under them (rereadSweeps): its hits sorted
 * anew from what the line recorded, nothing searched, or, where a change
 * needs bytes the line did not record, its record searched again within
 * the sweep's budget. The result is a line of its own on the chain
 * (`reread`), the trace gets a line and the board one post.
 *
 * Echoes (docs/adr/0013, "Echoes: authored, not derived"): a hit in an
 * object whose every name was made by a command or a job that read nothing
 * of the run but its own registers (the ledger, the board, SWARM.md, the
 * trace…) and named objects this sweep found the same string in, and whose
 * own words name the string or that read registers alone, or kept by the
 * harness from a seat's own model words outside any tool call (a
 * compaction summary), holds the string by construction: it is the run's
 * words, or a named hit's again, not new evidence. It is named on the line
 * (`echoes`, with what made each name) and holds nothing. One whose maker
 * read such named objects, and whose words do not name the string, is said
 * among the named hits, with what it read. A maker that read anything else
 * (an input, which the sweep never reads, included), or whose reads cannot
 * be told (a command that names no path, a job that saw everything),
 * leaves the hit standing. The makers come from the trace (the line that
 * kept the file) and the jobs' own records: refs and words only, no parser.
 *
 * The reverse sweep (docs/adr/0013, "Late evidence: the reverse sweep and
 * the delta"): when evidence is added, the new import's files, and only
 * they, are searched for the looked_for strings of every coverage record
 * standing then, and each hit is bound to the records whose strings it
 * holds. Its lines (version 2, `of: "import"`) are on the same chain, bound
 * to the addition's external entry by its hash. It runs after the
 * addition commits, never inside it: in the background of the hub's round,
 * or as a detached step when no hub runs, a pass at a time within a budget
 * of its own (reverseSweepBudget); what a pass leaves (`left`) is named on
 * its line and searched by the next pass, at the next round, until nothing
 * is left (the Fable review of the limits branch, P2-4). Each pass's hits
 * are delivered on the board when it completes, and to the re-examination
 * of the questions those records name (the stale answer's words, a
 * warning); they hold nothing by themselves.
 */
import { spawn } from "node:child_process";
import { createHash } from "node:crypto";
import { createReadStream } from "node:fs";
import { appendFile, lstat, mkdir, readdir, readFile, realpath } from "node:fs/promises";
import { join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import type { LedgerEntry } from "./protocol.ts";

export const LEDGER_SWEEPS = "ledger/sweeps.jsonl";
/** A looked_for string: at least this long (a shorter one matches everything), at most this long, at most this many. */
export const SWEEP_TERM_MIN = 3;
export const SWEEP_TERM_MAX = 200;
export const SWEEP_MAX_TERMS = 20;
/** The budget a sweep may spend, from the environment; past it the sweep is partial and names what it did not search. */
export function sweepBudget(env: NodeJS.ProcessEnv = process.env): { maxBytes: number; maxMs: number } {
  const num = (k: string, d: number) => {
    const v = Number(env[k]);
    return Number.isFinite(v) && v > 0 ? v : d;
  };
  return { maxBytes: num("SWARM_SWEEP_MAX_BYTES", 16 * 1024 ** 3), maxMs: num("SWARM_SWEEP_MAX_SEC", 1800) * 1000 };
}
/**
 * The budget one pass of a reverse sweep may spend: small, since it runs
 * beside the run's work; what it leaves is searched by the next pass.
 */
export function reverseSweepBudget(env: NodeJS.ProcessEnv = process.env): { maxBytes: number; maxMs: number } {
  const num = (k: string, d: number) => {
    const v = Number(env[k]);
    return Number.isFinite(v) && v > 0 ? v : d;
  };
  return { maxBytes: num("SWARM_REVERSE_SWEEP_MAX_BYTES", 2 * 1024 ** 3), maxMs: num("SWARM_REVERSE_SWEEP_MAX_SEC", 120) * 1000 };
}
/** A pending sweep older than this is taken to have been lost with its process, and is run again by whoever reads the gate. */
export function sweepOrphanMs(env: NodeJS.ProcessEnv = process.env): number {
  const v = Number(env.SWARM_SWEEP_ORPHAN_SEC);
  return (Number.isFinite(v) && v >= 0 ? v : 120) * 1000;
}

export type SweepHit = {
  /** The object it was found in (job:<id>/<path>, import:<id>/<path>, net:<k>/<n>/<file>, tool:<seat>/<file>). */
  ref: string;
  term: string;
  count: number;
  /** The byte offset of the first occurrence, in the object's own bytes. */
  first_offset: number;
  encodings: Array<"utf-8" | "utf-16le">;
  /** Other objects that hold the same bytes (one blob, several names). */
  also?: string[];
  /** What made each name of the object, when that is why the hit holds nothing (an echo, or a reading of objects the record names). */
  origins?: HitOrigin[];
};
/**
 * What made one name of a hit object, and why that makes the hit the run's
 * own words or a reading of what the record names (docs/adr/0013, "Echoes:
 * authored, not derived"). `by` is the maker: `trace:<sha256>` (the trace
 * line that kept a file under tool-output/), `job:<id>` (a job), or
 * `trace-spill` (the trace itself, spilled under a seat's tool-output/).
 * - `searched`: its maker's own words (a command, a tool's arguments, a
 *   job's command or arguments, the run's paths they name aside) name the
 *   string, and it read nothing of the run but what is accounted for
 *   (`reads`; a job by its declared inputs, a command by the paths its
 *   words name): the output holds the string because the search asked for
 *   it. A search that read evidence the record does not name, or an input
 *   (which the sweep never reads), is no echo: its matches are the miss
 *   the sweep is for.
 * - `registers`: its maker read the run's own registers and harness files
 *   and no other path of the run (RUN_REGISTERS): the run's words about the
 *   case, not evidence of it.
 * - `harness`: the harness kept it from a seat's own model words outside
 *   any tool call (HARNESS_KEEPERS: a compaction summary).
 * - `named_sources`: its maker read only what is accounted for, at least
 *   one object (`reads`): their hits are said already.
 * Accounted for: a register, or an object the record names in which the
 * same sweep found the same string (a named hit says it). An input is never
 * accounted for: the sweep does not read the images, so what is made from
 * one is the only place its rows show (the round-13 export).
 */
export type HitOrigin = { name: string; by: string; why: "searched" | "registers" | "harness" | "named_sources"; reads?: string[] };
export type SweepState = "clean" | "hits" | "partial";

/**
 * A change of the sweep's rules (docs/adr/0013, "Re-reading after a rules
 * change"): its version, since when, what changed, and whether a line
 * written before it can be read again from what it recorded (`bytes`
 * false: its hits sorted anew, nothing searched) or needs bytes it did not
 * record (`bytes` true: its record is searched again, within the sweep's
 * budget).
 */
export type SweepRuleChange = { version: number; since: string; what: string; bytes: boolean };
/**
 * The sweep's rules, by version, oldest first. A line with no version was
 * written before versions were recorded and is older than any versioned
 * one. A change of what a hit is, or where it goes, adds a version here;
 * a hub that starts, and the answers check, read every record's latest
 * line from before it again (rereadSweeps).
 */
export const SWEEP_RULE_CHANGES: readonly SweepRuleChange[] = [
  {
    version: 1,
    since: "2026-09-30",
    what: "the same bytes under several names are one object (a kept output and the import it was sealed as), and a hit in an object made from the run's own words is an echo, holding nothing",
    bytes: false,
  },
  {
    version: 2,
    since: "2026-11-13",
    what: "a whole output kept by one of the harness's tools that read the registers alone (REGISTER_READERS: ledger, leads, questions) is an echo, whatever its arguments name",
    bytes: false,
  },
];
/** This harness's version of the sweep's rules: written on every coverage record's sweep line. */
export const SWEEP_RULES: number = SWEEP_RULE_CHANGES.at(-1)!.version;
/** The version of the sweep's rules a line was written under: 0 when it records none (older than any versioned one). */
export function sweepRulesOf(s: { rules?: unknown }): number {
  return typeof s.rules === "number" && Number.isFinite(s.rules) ? s.rules : 0;
}
/**
 * What a line that read an earlier one again says of it: the version that
 * line was written under (null: it recorded none), why (the rules
 * changed), the hash of the line read again (`of`), when it was read
 * again, and how: `read` (its hits sorted anew from what it recorded,
 * nothing searched; the line's `started_at` and `at` stay the search's),
 * or `searched` (a change needed bytes it did not record: the record was
 * searched again, and the times are that search's).
 */
export type SweepReread = { from_version: number | null; reason: "rules changed"; of: string; at: string; how: "read" | "searched" };

export type SweepRecord = {
  v: 1;
  /** The coverage record's seq and hash. */
  seq: number;
  target: string;
  /** The version of the sweep's rules it was written, or read again, under (SWEEP_RULES). Absent on a line from before 2026-09-30, which is older than any versioned one. */
  rules?: number;
  /** On a line that read the record's earlier one again after the rules changed (rereadSweeps). */
  reread?: SweepReread;
  state: SweepState;
  terms: string[];
  searched: { objects: number; bytes: number };
  /** In objects the record does not name (its refs, or the outputs among its result_refs): these hold the negative. */
  hits: SweepHit[];
  /** In objects the record names already, or whose every name was made from objects it names in which this sweep found the string (`origins`): said, never holding; a reviewer checks the answer accounts for them. */
  named_hits: SweepHit[];
  /** Echoes: in objects the record does not name whose every name was made from the run's own words (a command that read only registers, a summary the harness kept, a search for the string over what is accounted for; `origins` says which and by what): said, never holding. Absent on a line from before 2026-09-30. */
  echoes?: SweepHit[];
  /** What the budget did not reach, each named with why. */
  unsearched: Array<{ ref: string; why: string }>;
  started_at: string;
  at: string;
  prev?: string;
  hash?: string;
};

/** A hit of the reverse sweep: bound to the coverage records whose looked_for holds its string (by seq). */
export type ImportSweepHit = SweepHit & { bears_on: number[] };
/**
 * A pass of the reverse sweep of an addition (version 2, `of: "import"`):
 * the addition's external entry (seq, and hash as `target`), its import,
 * each coverage record standing at the addition with looked_for (its seq,
 * hash, questions and strings), and what the objects this pass searched
 * hold of them. `unsearched` names every object of the import not searched
 * yet, each with why; those the pass's budget left carry `left` and are
 * searched by the next pass, whose line names this one's hash in
 * `continues` and its number in `pass` (both only on a continuation). An
 * addition's sweep is the union of its passes (importSweepWhole).
 */
export type ImportSweepRecord = {
  v: 2;
  of: "import";
  seq: number;
  target: string;
  import: string;
  records: Array<{ seq: number; target: string; questions: string[]; terms: string[] }>;
  state: SweepState;
  terms: string[];
  searched: { objects: number; bytes: number };
  hits: ImportSweepHit[];
  unsearched: Array<{ ref: string; why: string; left?: true }>;
  started_at: string;
  at: string;
  pass?: number;
  continues?: string;
  prev?: string;
  hash?: string;
};
/** Any line of ledger/sweeps.jsonl: a coverage record's sweep, or an addition's reverse sweep. */
export type AnySweepLine = SweepRecord | ImportSweepRecord;

/**
 * One object a sweep reads. Its path is its directory (one string, shared by
 * every file of a job or an import) and its name under it, joined only when
 * it is read (objectPath): on the run s082123's store, 212,722 objects held
 * as whole paths took 260 MB of a sweep's 330 MB, and the hub, running
 * several sweeps at once, ran out of heap at 3.5 GB.
 */
type SweepObject = { ref: string; dir: string; name: string; bytes: number; key: string; mtimeMs?: number };
const objectPath = (x: Pick<SweepObject, "dir" | "name">): string => (x.name ? join(x.dir, x.name) : x.dir);

/** The sha256 of a file known by its inode, by its inode, size and time: a kept output or a job's log is written once. */
const contentHashes = new Map<string, string>();
async function contentKey(x: SweepObject): Promise<string | null> {
  const stamp = `${x.key}:${x.bytes}:${x.mtimeMs ?? 0}`;
  const had = contentHashes.get(stamp);
  if (had) return had;
  try {
    const h = createHash("sha256");
    for await (const chunk of createReadStream(objectPath(x))) h.update(chunk as Buffer);
    const key = `sha256:${h.digest("hex")}`;
    contentHashes.set(stamp, key);
    return key;
  } catch {
    return null;
  }
}

/**
 * Every output the run holds that is not an input image, sorted by ref; the
 * same bytes under several names share a key. A sealed object is known by
 * the sha256 its manifest gives; a file the harness kept under tool-output/
 * and a job's log by their inode, and by their content when another object
 * has their size: a kept output and the import it was sealed as are one
 * object (the run sd0e59d's records named the import, and the kept file
 * went on holding their negatives).
 */
export function sweepObjects(sandboxRoot: string): Promise<SweepObject[]> {
  // Sweeps that start while a listing is being made share it: one list in memory, not one per sweep (the hub runs a sweep per coverage
  // record, in the background, and a reread or a finish gate runs more). A listing is never reused once it is done: a sweep that starts
  // after it sees what was sealed since.
  const key = resolve(sandboxRoot);
  let p = listing.get(key);
  if (!p) {
    p = listSweepObjects(sandboxRoot).finally(() => listing.delete(key));
    listing.set(key, p);
  }
  return p;
}
const listing = new Map<string, Promise<SweepObject[]>>();

async function listSweepObjects(sandboxRoot: string): Promise<SweepObject[]> {
  const out: SweepObject[] = [];
  const dirs = async (p: string) => (await readdir(p, { withFileTypes: true }).catch(() => [])).filter((d) => d.isDirectory()).map((d) => d.name);
  const manifestFiles = async (dir: string): Promise<Array<{ path: string; sha256: string; bytes: number }> | null> => {
    try {
      const m = JSON.parse(await readFile(join(dir, "manifest.json"), "utf8")) as { files?: Array<{ path: string; sha256: string; bytes: number }> };
      return m.files ?? [];
    } catch {
      return null;
    }
  };
  const fileKey = async (path: string): Promise<{ key: string; bytes: number; mtimeMs: number } | null> => {
    const st = await lstat(path).catch(() => null);
    return st?.isFile() ? { key: `ino:${st.dev}:${st.ino}`, bytes: st.size, mtimeMs: st.mtimeMs } : null;
  };
  // Sealed job outputs, and each job's logs (stdout.log is what job_status pages).
  const jobs = join(sandboxRoot, "store", "jobs");
  for (const id of (await dirs(jobs)).sort()) {
    const files = await manifestFiles(join(jobs, id));
    if (!files) continue;
    const dir = join(jobs, id, "out");
    for (const f of files) out.push({ ref: `job:${id}/${f.path}`, dir, name: f.path, bytes: f.bytes, key: `sha256:${f.sha256}` });
    for (const log of ["stdout.log", "stderr.log"]) {
      const k = await fileKey(join(jobs, id, log));
      if (k && k.bytes) out.push({ ref: `job:${id}/${log}`, dir: join(jobs, id), name: log, ...k });
    }
  }
  // Imports: evidence added late, supplied material, a brain's sealed output.
  const imports = join(sandboxRoot, "store", "imports");
  for (const id of (await dirs(imports)).sort()) {
    const dir = join(imports, id, "out");
    for (const f of (await manifestFiles(join(imports, id))) ?? []) out.push({ ref: `import:${id}/${f.path}`, dir, name: f.path, bytes: f.bytes, key: `sha256:${f.sha256}` });
  }
  // Captures the fetch service sealed.
  const net = join(sandboxRoot, "store", "net");
  for (const k of (await dirs(net)).sort()) {
    for (const n of (await dirs(join(net, k))).sort()) {
      const dir = join(net, k, n);
      for (const f of (await manifestFiles(dir)) ?? []) out.push({ ref: `net:${k}/${n}/${f.path}`, dir, name: f.path, bytes: f.bytes, key: `sha256:${f.sha256}` });
    }
  }
  // The whole outputs the harness kept under tool-output/<seat>/.
  const tools = join(sandboxRoot, "tool-output");
  for (const seat of (await dirs(tools)).sort()) {
    const walk = async (dir: string, rel: string): Promise<void> => {
      for (const d of (await readdir(dir, { withFileTypes: true }).catch(() => [])).sort((a, b) => a.name.localeCompare(b.name))) {
        const p = join(dir, d.name);
        const r = rel ? `${rel}/${d.name}` : d.name;
        if (d.isDirectory()) await walk(p, r);
        else if (d.isFile()) {
          const k = await fileKey(p);
          if (k) out.push({ ref: `tool:${seat}/${r}`, dir: p, name: "", ...k });
        }
      }
    };
    await walk(join(tools, seat), "");
  }
  // Known by its inode and the same size as another object: known by its content, so the same bytes are one object whatever named them.
  const sizes = new Map<number, number>();
  for (const x of out) sizes.set(x.bytes, (sizes.get(x.bytes) ?? 0) + 1);
  for (const x of out) {
    if (!x.key.startsWith("ino:") || (sizes.get(x.bytes) ?? 0) < 2) continue;
    const key = await contentKey(x);
    if (key) x.key = key;
  }
  return out.sort((a, b) => a.ref.localeCompare(b.ref));
}

/** ASCII letters folded to lower case, in a copy: the case-insensitive part of the byte search. */
function fold(b: Buffer): Buffer {
  const out = Buffer.from(b);
  for (let i = 0; i < out.length; i++) {
    const c = out[i]!;
    if (c >= 0x41 && c <= 0x5a) out[i] = c + 0x20;
  }
  return out;
}

type Pattern = { term: number; enc: "utf-8" | "utf-16le"; bytes: Buffer };

/** Each term in UTF-8 and UTF-16LE, as given, lower-cased and upper-cased (for letters outside ASCII), folded, each once. */
function patterns(terms: string[]): Pattern[] {
  const out: Pattern[] = [];
  terms.forEach((t, i) => {
    for (const v of new Set([t, t.toLowerCase(), t.toUpperCase()])) {
      for (const enc of ["utf-8", "utf-16le"] as const) {
        const bytes = fold(Buffer.from(v, enc === "utf-8" ? "utf8" : "utf16le"));
        if (!out.some((p) => p.term === i && p.enc === enc && p.bytes.equals(bytes))) out.push({ term: i, enc, bytes });
      }
    }
  });
  return out;
}

/** Count each pattern in one file, streamed whole: the count and the first offset of each term, by encoding. */
async function searchFile(path: string, pats: Pattern[]): Promise<Map<number, { count: number; first: number; encodings: Set<"utf-8" | "utf-16le"> }>> {
  const found = new Map<number, { count: number; first: number; encodings: Set<"utf-8" | "utf-16le"> }>();
  const keep = Math.max(0, ...pats.map((p) => p.bytes.length)) - 1;
  let tail = Buffer.alloc(0);
  let base = 0;
  for await (const raw of createReadStream(path, { highWaterMark: 1024 * 1024 })) {
    const chunk = fold(raw as Buffer);
    const buf = tail.length ? Buffer.concat([tail, chunk]) : chunk;
    for (const p of pats) {
      let i = buf.indexOf(p.bytes);
      while (i >= 0) {
        // A match that lies wholly in the carried tail was counted with the chunk before.
        if (i + p.bytes.length > tail.length) {
          const at = base - tail.length + i;
          const f = found.get(p.term) ?? { count: 0, first: at, encodings: new Set() };
          f.count += 1;
          f.first = Math.min(f.first, at);
          f.encodings.add(p.enc);
          found.set(p.term, f);
        }
        i = buf.indexOf(p.bytes, i + 1);
      }
    }
    base += chunk.length;
    tail = keep > 0 ? Buffer.from(buf.subarray(Math.max(0, buf.length - keep))) : Buffer.alloc(0);
  }
  return found;
}

/** Whether a coverage record's refs name an object: the ref itself, a directory of it (job:<id>, job:<id>/<dir>), or its bytes by sha256. */
export function refsName(refs: readonly string[], ref: string, key?: string): boolean {
  const want = normRef(ref);
  return refs.some((r) => {
    const n = normRef(r);
    return n === want || want.startsWith(`${n}/`) || (key?.startsWith("sha256:") && n === key);
  });
}

/** An object an earlier sweep found a record's strings in, that a coverage record now names with no entry among its results saying what it showed. */
export type UnexaminedHit = {
  /** The object, as the earlier sweep named it. */
  ref: string;
  /** Other names of the same bytes. */
  also: string[];
  /** The strings found in it. */
  terms: string[];
  /** The coverage record whose sweep first found it, and when that sweep ended. */
  found_by: number;
  found_at: string;
};

/** The kinds of entry that say what an object showed: a finding, an event, a search that found nothing in it, or a limitation on it. */
export const INTERPRETING_KINDS: ReadonlySet<string> = new Set(["finding", "event", "absence", "limitation"]);

/**
 * The objects a coverage record names that the sweep of an earlier coverage
 * record for one of its questions found hits in, with no entry among its
 * results that says what each showed. Naming a hit is not examining it (the
 * run sb1b3c8 cleared sweep_hits by naming up to 66 hit objects in a
 * revised record's refs, with nothing recorded about any of them): an
 * object that moves from hits into a record is cited in its result_refs by
 * an entry that interprets it, a finding, an event, an absence or a
 * limitation that stands, names the object itself in its refs (not a
 * directory that holds it), and was written after the sweep that found it.
 * One entry per object, or one absence whose refs list several. Object refs
 * and times only: no content is read or judged.
 */
export function unexaminedHits(cov: LedgerEntry, entries: readonly LedgerEntry[], sweeps: readonly SweepRecord[], replaced: ReadonlyMap<number, number>): UnexaminedHit[] {
  // A question's id as protocol.ts sectionKey reads it: Q-19 is 19.
  const qkey = (x: string) => String(x ?? "").trim().replace(/^question:/i, "").replace(/^q-?(?=\d)/i, "");
  const questions = new Set((cov.answers ?? []).map(qkey));
  const found = new Map<string, UnexaminedHit>();
  for (const e of entries) {
    if (e.kind !== "coverage" || e.seq >= cov.seq || !e.hash || !(e.answers ?? []).some((a) => questions.has(qkey(a)))) continue;
    // Its sweep as the gate reads it: the latest line for it (a replay's --resweep adds one).
    for (const sw of [sweepOf(e, sweeps)].filter((x): x is SweepRecord => Boolean(x))) {
      for (const h of sw.hits) {
        const was = found.get(h.ref);
        const earlier = !was || Date.parse(sw.at) < Date.parse(was.found_at);
        found.set(h.ref, {
          ref: h.ref,
          also: [...new Set([...(was?.also ?? []), ...(h.also ?? [])])],
          terms: [...new Set([...(was?.terms ?? []), h.term])],
          found_by: earlier ? e.seq : was!.found_by,
          found_at: earlier ? sw.at : was!.found_at,
        });
      }
    }
  }
  if (!found.size) return [];
  const names = [...(cov.refs ?? []), ...(cov.result_refs ?? []).filter((r) => !/^E-\d+$/.test(r))];
  const bySeq = new Map(entries.map((e) => [e.seq, e]));
  const results = (cov.result_refs ?? [])
    .filter((r) => /^E-\d+$/.test(r))
    .map((r) => bySeq.get(Number(r.slice(2))))
    .filter((e): e is LedgerEntry => Boolean(e) && !replaced.has((e as LedgerEntry).seq) && INTERPRETING_KINDS.has((e as LedgerEntry).kind));
  const out: UnexaminedHit[] = [];
  for (const h of [...found.values()].sort((a, b) => a.ref.localeCompare(b.ref))) {
    const all = [h.ref, ...h.also];
    if (!all.some((n) => refsName(names, n))) continue;
    const wanted = new Set(all.map(normRef));
    const examined = results.some((e) => Date.parse(e.at) >= Date.parse(h.found_at) && (e.refs ?? []).some((r) => wanted.has(normRef(r))));
    if (!examined) out.push(h);
  }
  return out;
}

/** An object ref as the sweep compares it: job:<id>/out/x is job:<id>/x, no trailing slash. */
function normRef(r: string): string {
  return r.trim().replace(/^(job|import):([^/]+)\/out\//, "$1:$2/").replace(/\/+$/, "");
}

// --- echoes: authored, not derived ----------------------------------------------------------------

/**
 * The run's own registers and harness files (docs/adr/0013, "Echoes:
 * authored, not derived"): what the run says about the case, written by its
 * seats, its operator and the harness, never evidence of it. A command that
 * read these and no other path of the run made the run's words again.
 */
export const RUN_REGISTERS: readonly string[] = ["ledger/", "leads/", "questions/", "requests/", "threads/", "board/", "inbox/", "traces/", "done/", "locks/", "SWARM.md", "operator-requests.jsonl", "team.json", "names.json", "budget.json", "layout.json"];

/**
 * The harness's own trace events that keep a file under tool-output/ from a
 * seat's model words outside any tool call: the self-compaction's
 * (extensions/self-compact.ts SELF_COMPACT_EVENTS; a stopped summary is kept
 * by compact_failed). Named, so an event not here that keeps a file is read
 * as a tool call's and its hits hold (tests/store-sweep-echoes.test.ts keeps
 * the two lists the same).
 */
export const HARNESS_KEEPERS: ReadonlySet<string> = new Set(["context", "compact_notice", "compact_warning", "compact_forced", "compact_hold", "compact_note", "compact_start", "compact_done", "compact_failed", "compact_stalled", "compact_config"]);

/**
 * The harness's own seat tools that read the run's registers and nothing
 * else: the ledger tool's page of entries, the leads and questions views. A
 * whole output one of them kept under tool-output/ is the registers' words
 * again, whatever its arguments name (they name no path: `{limit: 12}`), so
 * it is an echo. Without this a seat that read the ledger after recording
 * an answer made a new hit for the answer's own strings each time, and the
 * coverage record that had to name it made the next (the run sf4406b: one
 * question's answer written 18 times in an hour). A tool not here that
 * keeps a file is read by what its arguments name (tests keep each a name
 * no seat's tool can take).
 */
export const REGISTER_READERS: ReadonlySet<string> = new Set(["ledger", "leads", "questions"]);

/** The trace spilled under a seat's tool-output/ when its collector could not be reached (protocol.ts traceSpillRel): the trace itself. */
const TRACE_SPILL = "trace-spill.jsonl";

/** Every string in a tool call's arguments, at any depth (not the keys). */
function stringsIn(v: unknown, depth = 0): string[] {
  if (typeof v === "string") return [v];
  if (!v || typeof v !== "object" || depth > 8) return [];
  return (Array.isArray(v) ? v : Object.values(v as Record<string, unknown>)).flatMap((x) => stringsIn(x, depth + 1));
}

/**
 * The paths a maker's own words name (docs/adr/0013, "Echoes: authored, not
 * derived"), token by token, after the run's absolute paths (`roots`), $PWD
 * and ./ are taken off: a token that begins with one of the run's own
 * top-level names and a slash, a top-level file's name, or a top-level
 * directory's name quoted whole, as the run path it is; and, as a path
 * outside what the run's layout says (read as unnamed evidence), the run's
 * root (`.`, `*`), a parent (`..`), a hidden entry at the root, a path
 * through a variable, and an absolute path elsewhere (/dev/null and the
 * standard streams aside). Words, not a parser: a path the command builds
 * while it runs is not seen, which is why a maker that names no path is
 * never read as having read nothing. `text` is the words with the run
 * paths blanked, for the string's own test.
 */
export function runPathsIn(words: string, top: ReadonlySet<string>, roots: readonly string[] = []): { text: string; paths: string[] } {
  let w = words;
  // `cd <run root>` (or pushd), with no slash after it, only moves to where the run's own paths are read from: it names nothing (the run sf4406b's
  // seats ran `cd /…/runs/sf4406b && grep … ledger/ledger.md`, and the bare root read as a path elsewhere). A bare root anywhere else still is one.
  const esc = (x: string) => x.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
  for (const r of roots) if (r && r !== "/") w = w.replace(new RegExp(`\\b(cd|pushd)\\s+(["']?)${esc(r.replace(/\/+$/, ""))}\\/?\\2(?=[\\s;&|)]|$)`, "g"), "$1 ");
  for (const r of roots) if (r && r !== "/") w = w.split(`${r.replace(/\/+$/, "")}/`).join("");
  w = w.replace(/\$\{?PWD\}?\/|\$\(pwd\)\//g, "");
  const paths: string[] = [];
  let text = "";
  let last = 0;
  for (const m of w.matchAll(/[^\s'"`;|&<>(){}[\],=]+/g)) {
    const raw = m[0];
    const at = m.index ?? 0;
    const t = raw.replace(/^(?:\.\/)+/, "");
    let path: string | null = null;
    if (/^(?:\.{1,2}|\*|\.\.\/.*|\*\/.*)$/.test(t) || (raw.startsWith("./") && !t)) path = t || ".";
    else if (/^\/[A-Za-z0-9_.~-]/.test(t) || /^~(?:\/|$)/.test(t) || /^[a-z][a-z0-9+.-]*:\/\//i.test(t)) path = /^\/dev\/(?:null|stdin|stdout|stderr|fd\/\d+)$/.test(t) ? null : t;
    else if (/^\.[A-Za-z0-9_-][^/]*\//.test(t) || /^\$[A-Za-z_{(].*\//.test(t)) path = t;
    else {
      const first = t.split("/")[0]!;
      if (top.has(first)) {
        const q = w[at - 1];
        const quoted = (q === "'" || q === '"') && w[at + raw.length] === q;
        // A directory's bare name is a word as often as a path: read as one only quoted whole ('inputs').
        if (t.includes("/") || first.includes(".")) path = t;
        else if (quoted) path = `${t}/`;
        if (path) {
          text += `${w.slice(last, at)} `;
          last = at + raw.length;
        }
      }
    }
    if (path) paths.push(path);
  }
  return { text: text + w.slice(last), paths };
}

/** A path of the run as what it names: a register, an object by its ref, or another path of the run (null). */
function pathNames(p: string): { register: true } | { ref: string } | null {
  const clean = p.replace(/\/{2,}/g, "/");
  if (clean.split("/").some((s) => s === "..")) return null;
  for (const r of RUN_REGISTERS) if (r.endsWith("/") ? clean === r.slice(0, -1) || clean.startsWith(r) : clean === r) return { register: true };
  let m: RegExpExecArray | null;
  if ((m = /^inputs\/(.+)$/.exec(clean))) return { ref: `input:${m[1]}` };
  if ((m = /^store\/(jobs|imports)\/([^/]+)(?:\/(.*))?$/.exec(clean))) {
    const rest = (m[3] ?? "").replace(/^out(?:\/|$)/, "").replace(/\/+$/, "");
    return { ref: `${m[1] === "jobs" ? "job" : "import"}:${m[2]}${rest ? `/${rest}` : ""}` };
  }
  if ((m = /^store\/net\/([^/]+\/[^/]+(?:\/.+)?)$/.exec(clean))) return { ref: `net:${m[1]!.replace(/\/+$/, "")}` };
  if ((m = /^store\/blobs\/([0-9a-f]{64})$/.exec(clean))) return { ref: `sha256:${m[1]}` };
  if ((m = /^tool-output\/([^/]+)\/(.+)$/.exec(clean))) return { ref: `tool:${m[1]}/${m[2]}` };
  return null;
}

/** Whether words name a string, as the sweep folds case; a backslash before punctuation (a pattern's escape) read as nothing. */
function namesTerm(words: string, term: string): boolean {
  const t = term.toLowerCase();
  const l = words.toLowerCase();
  return l.includes(t) || l.replace(/\\(?=[^A-Za-z0-9\s])/g, "").includes(t);
}

type JobSpec = { kind?: string; command?: string; tool?: string; args?: unknown; inputs?: string[]; scope?: string; network?: string; seal?: { ref?: string } };

/**
 * What made each name of a hit object, for a coverage record whose objects
 * are `refs` (docs/adr/0013, "Echoes: authored, not derived"): a function of
 * the object's names and a string, null when any name was made by something
 * that is neither an echo of the string nor a reading of what the record
 * names (its hit holds). What it reads it reads once, when first asked: the
 * trace's kept outputs (keptOutputOrigins), the jobs' records, the seals of
 * the seats' own outputs, the run's top-level names.
 */
export function hitOrigins(sandboxRoot: string, refs: readonly string[]): (names: readonly string[], term: string, said: (ref: string, term: string) => boolean) => Promise<HitOrigin[] | null> {
  const S = resolve(sandboxRoot);
  const canon = refs.map((r) => r.trim().replace(/^input:inputs\//, "input:"));
  const named = (ref: string) => refsName(canon, ref);
  let kept: Promise<Map<string, { line_sha256: string; tool: string; args: unknown }>> | null = null;
  let seals: Promise<Map<string, string>> | null = null;
  let top: Promise<{ names: Set<string>; roots: string[] }> | null = null;
  const jobs = new Map<string, Promise<JobSpec | null>>();
  const ES = () => import("../scripts/evidence-store.ts");
  const keptOf = () => (kept ??= ES().then((m) => m.keptOutputOrigins(S)).catch(() => new Map()));
  // A seat's own output sealed: its import and the import job's output are its bytes, made as it was.
  const sealsOf = () => (seals ??= ES().then(async (m) => new Map((await m.brainOutputSeals(S)).map((x) => [normRef(x.import), x.ref] as [string, string]))).catch(() => new Map<string, string>()));
  const topOf = () => (top ??= (async () => ({ names: new Set((await readdir(S).catch(() => [] as string[])).filter((n) => !n.startsWith("."))), roots: [...new Set([S, await realpath(S).catch(() => S)])] }))());
  const jobOf = (id: string) => {
    let p = jobs.get(id);
    if (!p) {
      p = readFile(join(S, "store", "jobs", id, "job.json"), "utf8")
        .then((t) => {
          const j = JSON.parse(t) as { state?: string; spec?: JobSpec };
          return j.state === "committed" ? (j.spec ?? null) : null;
        })
        .catch(() => null);
      jobs.set(id, p);
    }
    return p;
  };
  // What a maker read, accounted for: a register, or an object the record names in which this sweep found the string (its hit said already). An input is never swept: what is made from it is the only place its rows show.
  const accounted = (ref: string, term: string, said: (ref: string, term: string) => boolean) => named(ref) && said(ref, term);
  // The paths a maker's words name, each accounted for; null when any is not, or none is named.
  const readsOf = async (words: string, term: string, said: (ref: string, term: string) => boolean): Promise<{ text: string; verdict: { why: "registers" } | { why: "named_sources"; reads: string[] } | null }> => {
    const t = await topOf();
    const { text, paths } = runPathsIn(words, t.names, t.roots);
    if (!paths.length) return { text, verdict: null };
    const reads: string[] = [];
    for (const p of paths) {
      const k = pathNames(p);
      if (!k || ("ref" in k && !accounted(k.ref, term, said))) return { text, verdict: null };
      if ("ref" in k && !reads.includes(k.ref)) reads.push(k.ref);
    }
    return { text, verdict: reads.length ? { why: "named_sources", reads } : { why: "registers" } };
  };
  const originOf = async (name: string, term: string, said: (ref: string, term: string) => boolean, depth = 0): Promise<HitOrigin | null> => {
    if (depth > 3) return null;
    const n = normRef(name);
    let m: RegExpExecArray | null;
    if ((m = /^tool:([^/]+)\/(.+)$/.exec(n))) {
      if (m[2] === TRACE_SPILL) return { name, by: "trace-spill", why: "registers" };
      const line = (await keptOf()).get(`tool-output/${m[1]}/${m[2]}`);
      if (!line) return null;
      const by = `trace:${line.line_sha256}`;
      if (HARNESS_KEEPERS.has(line.tool)) return { name, by, why: "harness" };
      if (REGISTER_READERS.has(line.tool)) return { name, by, why: "registers" };
      // What a command read is what its words name: nothing it names, or anything but registers and objects the record names, and the hit stands.
      const { text, verdict } = await readsOf(stringsIn(line.args).join("\n"), term, said);
      if (!verdict) return null;
      if (namesTerm(text, term)) return { name, by, why: "searched", ...(verdict.why === "named_sources" ? { reads: verdict.reads } : {}) };
      return { name, by, ...verdict };
    }
    if ((m = /^trace:([0-9a-f]{64})$/.exec(n))) return { name, by: n, why: "registers" };
    if ((m = /^import:([^/]+)\/.+$/.exec(n))) {
      const origin = (await sealsOf()).get(n);
      const o = origin ? await originOf(origin, term, said, depth + 1) : null;
      return o ? { ...o, name } : null;
    }
    if ((m = /^job:([^/]+)(?:\/.*)?$/.exec(n))) {
      const spec = await jobOf(m[1]!);
      if (!spec) return null;
      const by = `job:${m[1]}`;
      if (spec.kind === "import" && spec.seal?.ref) {
        const o = await originOf(spec.seal.ref, term, said, depth + 1);
        return o ? { ...o, name } : null;
      }
      // What a job read is what it declared, and nothing else: each an object the record names, and no network. A job that saw everything (inputs left out, or all) read unnamed evidence.
      if (spec.kind !== "command" && spec.kind !== "tool") return null;
      if (spec.scope !== "declared" || (spec.network ?? "off") !== "off") return null;
      const reads: string[] = [];
      for (const d of spec.inputs ?? []) {
        const t = d.trim();
        const ref = /^[a-z0-9]+:/.test(t) ? t.replace(/^input:inputs\//, "input:") : (pathNames(t) as { ref?: string } | null)?.ref;
        if (!ref || !accounted(ref, term, said)) return null;
        if (!reads.includes(ref)) reads.push(ref);
      }
      const { text } = runPathsIn((await ES()).jobOwnWords(spec), (await topOf()).names);
      if (namesTerm(text, term)) return { name, by, why: "searched", ...(reads.length ? { reads } : {}) };
      return reads.length ? { name, by, why: "named_sources", reads } : null;
    }
    return null;
  };
  return async (names, term, said) => {
    const out: HitOrigin[] = [];
    for (const name of names) {
      const o = await originOf(name, term, said);
      if (!o) return null;
      out.push(o);
    }
    return out.length ? out : null;
  };
}

/**
 * What a sweep found in the objects the record names, as a test: whether it
 * found `term` in the object `ref` names (any name of its bytes; a
 * directory, in any object under it). A maker that read such an object
 * made again what the named hit says already.
 */
function saidIn(named: readonly SweepHit[]): (ref: string, term: string) => boolean {
  const found = new Map<string, Set<string>>();
  for (const h of named) {
    for (const n of [h.ref, ...(h.also ?? [])]) {
      const k = normRef(n);
      found.set(k, (found.get(k) ?? new Set()).add(h.term.toLowerCase()));
    }
  }
  return (ref, term) => {
    const r = normRef(ref);
    const t = term.toLowerCase();
    for (const [k, terms] of found) if ((k === r || k.startsWith(`${r}/`)) && terms.has(t)) return true;
    return false;
  };
}

/** Whether a hit's makers make it an echo (every name the run's own words), not a reading of named objects. */
export function isEcho(origins: readonly HitOrigin[]): boolean {
  return origins.length > 0 && origins.every((o) => o.why !== "named_sources");
}

/** Search every output the run holds for a coverage record's looked_for strings. Pure over the store; `now` and the budget are the caller's (tests fix them). */
export async function computeSweep(sandboxRoot: string, cov: Pick<LedgerEntry, "seq" | "hash" | "refs" | "result_refs" | "looked_for">, o: { maxBytes?: number; maxMs?: number; now?: () => number } = {}): Promise<Omit<SweepRecord, "prev" | "hash">> {
  const now = o.now ?? Date.now;
  const budget = { ...sweepBudget(), ...(o.maxBytes !== undefined ? { maxBytes: o.maxBytes } : {}), ...(o.maxMs !== undefined ? { maxMs: o.maxMs } : {}) };
  const started = now();
  const terms = [...(cov.looked_for ?? [])];
  const pats = patterns(terms);
  // What the record names: the objects it searched, and the outputs its search produced (a search's own
  // output echoes what it looked for; it was read as the search's result). A hit there is said, never holding.
  const refs = recordObjects(cov);
  const objects = await sweepObjects(sandboxRoot);
  // The same bytes under several names are read once; a group is named when any of its names is.
  const groups = new Map<string, SweepObject[]>();
  for (const x of objects) groups.set(x.key, [...(groups.get(x.key) ?? []), x]);
  const origins = hitOrigins(sandboxRoot, refs);
  const hits: SweepHit[] = [];
  const namedHits: SweepHit[] = [];
  const echoes: SweepHit[] = [];
  const unnamed: Array<{ hit: SweepHit; names: string[] }> = [];
  const unsearched: SweepRecord["unsearched"] = [];
  let searchedObjects = 0;
  let searchedBytes = 0;
  for (const [key, group] of groups) {
    const first = group[0]!;
    if (now() - started > budget.maxMs) {
      for (const g of group) unsearched.push({ ref: g.ref, why: `the sweep's time budget (${Math.round(budget.maxMs / 1000)} s, SWARM_SWEEP_MAX_SEC) ran out before it` });
      continue;
    }
    if (searchedBytes + first.bytes > budget.maxBytes) {
      for (const g of group) unsearched.push({ ref: g.ref, why: `its ${first.bytes} bytes would pass the sweep's byte budget (${budget.maxBytes}, SWARM_SWEEP_MAX_BYTES; ${searchedBytes} searched)` });
      continue;
    }
    let found: Awaited<ReturnType<typeof searchFile>>;
    try {
      found = await searchFile(objectPath(first), pats);
    } catch (err) {
      for (const g of group) unsearched.push({ ref: g.ref, why: `it could not be read (${(err as Error).message})` });
      continue;
    }
    searchedObjects += group.length;
    searchedBytes += first.bytes;
    const named = group.some((g) => refsName(refs, g.ref, key));
    for (const [t, f] of [...found.entries()].sort((a, b) => a[0] - b[0])) {
      const hit: SweepHit = { ref: first.ref, term: terms[t]!, count: f.count, first_offset: f.first, encodings: [...f.encodings].sort(), ...(group.length > 1 ? { also: group.slice(1).map((g) => g.ref) } : {}) };
      if (named) namedHits.push(hit);
      else unnamed.push({ hit, names: group.map((g) => g.ref) });
    }
  }
  // Not named: an echo, or said among the named hits, when what made every name of it says so (hitOrigins), read against what this sweep found in the objects the record names; else a hit.
  const said = saidIn(namedHits);
  for (const { hit, names } of unnamed) {
    const made = await origins(names, hit.term, said);
    if (!made) hits.push(hit);
    else (isEcho(made) ? echoes : namedHits).push({ ...hit, origins: made });
  }
  const state: SweepState = hits.length ? "hits" : unsearched.length ? "partial" : "clean";
  return { v: 1, seq: cov.seq, target: cov.hash ?? "", rules: SWEEP_RULES, state, terms, searched: { objects: searchedObjects, bytes: searchedBytes }, hits, named_hits: namedHits, echoes, unsearched, started_at: new Date(started).toISOString(), at: new Date(now()).toISOString() };
}

/** The objects a coverage record names: its refs, and the outputs among its result_refs (a search's own output echoes what it looked for). */
function recordObjects(cov: Pick<LedgerEntry, "refs" | "result_refs">): string[] {
  return [...(cov.refs ?? []), ...(cov.result_refs ?? []).filter((r) => !/^E-\d+$/.test(r))];
}

/**
 * A recorded sweep's hits read again by this harness (rereadSweeps, and
 * scripts/replay.ts --resweep): each hit's object as the store names it
 * now (every name of its bytes), named when the record names any of them,
 * an echo or said among the named hits when what made each name says so
 * (hitOrigins), a hit otherwise. The line's other fields are its own: what
 * it searched, what it did not, and when; the rules are this harness's.
 * Nothing is searched again.
 */
export async function resplitSweep(sandboxRoot: string, cov: Pick<LedgerEntry, "refs" | "result_refs">, line: SweepRecord): Promise<Omit<SweepRecord, "prev" | "hash">> {
  const refs = recordObjects(cov);
  const objects = await sweepObjects(sandboxRoot);
  const keyOf = new Map(objects.map((x) => [x.ref, x.key]));
  const origins = hitOrigins(sandboxRoot, refs);
  const hits: SweepHit[] = [];
  const namedHits = [...line.named_hits];
  const echoes = [...(line.echoes ?? [])];
  const said = saidIn(line.named_hits.filter((h) => !h.origins?.length));
  for (const h of line.hits) {
    const was = [h.ref, ...(h.also ?? [])];
    const keys = new Set(was.map((n) => keyOf.get(n)).filter((k): k is string => Boolean(k)));
    const names = [...new Set([...was, ...objects.filter((x) => keys.has(x.key)).map((x) => x.ref)])];
    const hit: SweepHit = { ...h, ...(names.length > 1 ? { also: names.filter((n) => n !== h.ref) } : {}) };
    if (names.some((n) => refsName(refs, n, keyOf.get(n)))) {
      namedHits.push(hit);
      continue;
    }
    const made = await origins(names, h.term, said);
    if (!made) hits.push(hit);
    else (isEcho(made) ? echoes : namedHits).push({ ...hit, origins: made });
  }
  const { prev: _p, hash: _h, reread: _r, ...rest } = line;
  return { ...rest, rules: SWEEP_RULES, state: hits.length ? "hits" : line.unsearched.length ? "partial" : "clean", hits, named_hits: namedHits, echoes };
}

/** A sweep line's hash: over the previous line's and its own fields, canonical. */
export function sweepHash(s: AnySweepLine, prev: string): string {
  const { prev: _p, hash: _h, ...core } = s;
  return createHash("sha256").update(`${prev}\n${JSON.stringify(sortKeys(core))}`).digest("hex");
}
function sortKeys(v: unknown): unknown {
  if (Array.isArray(v)) return v.map(sortKeys);
  if (v && typeof v === "object") return Object.fromEntries(Object.keys(v as Record<string, unknown>).sort().map((k) => [k, sortKeys((v as Record<string, unknown>)[k])]));
  return v;
}

/** Every line of ledger/sweeps.jsonl, in order. */
async function readSweepLines(sandboxRoot: string): Promise<AnySweepLine[]> {
  const text = await readFile(join(sandboxRoot, LEDGER_SWEEPS), "utf8").catch(() => "");
  const out: AnySweepLine[] = [];
  for (const line of text.split("\n")) {
    if (!line.trim()) continue;
    try {
      out.push(JSON.parse(line) as AnySweepLine);
    } catch {
      // a torn line is the chain check's to name
    }
  }
  return out;
}

/** The coverage records' sweeps (version 1 lines): what the gate holds a negative to. */
export async function readSweeps(sandboxRoot: string): Promise<SweepRecord[]> {
  return (await readSweepLines(sandboxRoot)).filter((s): s is SweepRecord => s.v === 1);
}

/** The additions' reverse sweeps (version 2 lines, of: "import"). */
export async function readImportSweeps(sandboxRoot: string): Promise<ImportSweepRecord[]> {
  return (await readSweepLines(sandboxRoot)).filter((s): s is ImportSweepRecord => s.v === 2 && (s as ImportSweepRecord).of === "import");
}

/** The sweeps' chain: every line's hash recomputed over its fields and chained to the one before; the head is the last line's hash. */
export function verifySweepChain(text: string): { ok: boolean; total: number; broken_at: number | null; reason: string | null; head: string | null } {
  let last = "genesis";
  let total = 0;
  for (const line of text.split("\n")) {
    if (!line.trim()) continue;
    total += 1;
    let s: AnySweepLine;
    try {
      s = JSON.parse(line) as AnySweepLine;
    } catch {
      return { ok: false, total, broken_at: total, reason: "not json", head: null };
    }
    if (s.v !== 1 && !(s.v === 2 && (s as ImportSweepRecord).of === "import")) return { ok: false, total, broken_at: total, reason: `a sweep of version ${JSON.stringify(s.v)}${s.v === 2 ? ` of ${JSON.stringify((s as { of?: unknown }).of)}` : ""}, which this harness does not know`, head: null };
    if (s.prev !== last) return { ok: false, total, broken_at: total, reason: "prev does not name the line before it", head: null };
    if (s.hash !== sweepHash(s, last)) return { ok: false, total, broken_at: total, reason: "the line was rewritten", head: null };
    last = s.hash;
  }
  return { ok: true, total, broken_at: null, reason: null, head: total ? last : null };
}

/** The sweep recorded for a coverage record, by its hash: the latest line, or null (pending, when the record names looked_for). */
export function sweepOf(c: Pick<LedgerEntry, "hash">, sweeps: readonly SweepRecord[]): SweepRecord | null {
  return sweeps.filter((s) => s.target === c.hash).at(-1) ?? null;
}

/** A hit in words, with what made its object when that is why it holds nothing. */
export function hitWords(h: SweepHit): string {
  return `"${h.term}" in ${h.ref}${h.also?.length ? ` (the same bytes as ${h.also.join(", ")})` : ""}, ${h.count} time${h.count === 1 ? "" : "s"}, first at byte ${h.first_offset}${h.encodings.includes("utf-16le") ? ` (${h.encodings.join(" and ")})` : ""}${h.origins?.length ? ` [${originWords(h.origins)}]` : ""}`;
}

/** What made a hit's object, in words: each maker once. */
export function originWords(origins: readonly HitOrigin[]): string {
  const seen = new Map<string, HitOrigin>();
  for (const o of origins) if (!seen.has(`${o.by}\u0000${o.why}`)) seen.set(`${o.by}\u0000${o.why}`, o);
  return [...seen.values()]
    .map((o) =>
      o.why === "searched"
        ? `made by ${o.by}, whose own words name the string: an echo of the search`
        : o.why === "registers"
          ? `made by ${o.by} from the run's own registers: the run's words, not evidence`
          : o.why === "harness"
            ? `kept by the harness from a seat's own words (${o.by}): not evidence`
            : `made by ${o.by} from ${(o.reads ?? []).join(", ")}, which the record names`,
    )
    .join("; ");
}

/** A line that read an earlier one again, in words: under which rules, from which, and how. */
export function rereadWords(s: Pick<SweepRecord, "reread" | "rules">): string {
  const r = s.reread;
  if (!r) return "";
  const from = r.from_version === null ? "a line that recorded no rules version" : `rules version ${r.from_version}`;
  return `read again at ${r.at} under the sweep's rules version ${sweepRulesOf(s)}, from ${from} (the rules changed): ${r.how === "searched" ? "the record searched again, since the change needs bytes the earlier line did not record" : "its hits sorted anew from what the earlier line recorded, nothing searched again"}`;
}

/** A sweep in words, for the ledger's rendering, the report and the review offer. */
export function sweepWords(s: SweepRecord | null, c: Pick<LedgerEntry, "looked_for">): string {
  if (!c.looked_for?.length) return "no store sweep (no looked_for strings)";
  if (!s) return "store sweep pending";
  const head = `store sweep ${s.state}: ${s.searched.objects} object(s), ${s.searched.bytes} bytes searched for ${s.terms.map((t) => `"${t}"`).join(", ")}`;
  return [
    head,
    s.reread ? rereadWords(s) : "",
    s.hits.length ? `found outside the record's objects: ${s.hits.map(hitWords).join("; ")}` : "",
    s.named_hits.length ? `found in objects the record names (does the answer account for them?): ${s.named_hits.map(hitWords).join("; ")}` : "",
    s.echoes?.length ? `echoes, holding nothing (is each only the run's own words?): ${s.echoes.map(hitWords).join("; ")}` : "",
    s.unsearched.length ? `not searched: ${s.unsearched.map((u) => `${u.ref} (${u.why})`).join("; ")}` : "",
  ]
    .filter(Boolean)
    .join("; ");
}

const inflight = new Map<string, Promise<SweepRecord | null>>();

/**
 * Run a coverage record's sweep and record it, once per record: a sweep
 * already recorded, or running in this process, is not run again. Written
 * under the sweeps' lock, chained. Errors are the result's (null), never
 * thrown: the record stands and its sweep stays pending, to be run again.
 */
export function startSweep(sandboxRoot: string, cov: LedgerEntry, o: { maxBytes?: number; maxMs?: number } = {}): Promise<SweepRecord | null> {
  if (!cov.looked_for?.length || !cov.hash) return Promise.resolve(null);
  const key = `${sandboxRoot}\u0000${cov.hash}`;
  const running = inflight.get(key);
  if (running) return running;
  const p = (async (): Promise<SweepRecord | null> => {
    if (sweepOf(cov, await readSweeps(sandboxRoot))) return sweepOf(cov, await readSweeps(sandboxRoot));
    const result = await computeSweep(sandboxRoot, cov, o);
    const P = await import("./protocol.ts");
    const line = await P.withNamedLock(sandboxRoot, "sweeps", async () => {
      const text = await readFile(join(sandboxRoot, LEDGER_SWEEPS), "utf8").catch(() => "");
      const existing = (await readSweeps(sandboxRoot)).filter((s) => s.target === cov.hash).at(-1);
      if (existing) return existing;
      const lines = text.split("\n").filter((l) => l.trim());
      const prev = lines.length ? ((JSON.parse(lines.at(-1)!) as SweepRecord).hash ?? "genesis") : "genesis";
      const rec: SweepRecord = { ...result, prev };
      rec.hash = sweepHash(rec, prev);
      await mkdir(join(sandboxRoot, "ledger"), { recursive: true });
      await appendFile(join(sandboxRoot, LEDGER_SWEEPS), `${JSON.stringify(rec)}\n`, "utf8");
      return rec;
    });
    await P.renderLedger(sandboxRoot).catch(() => undefined);
    return line;
  })()
    .catch(() => null)
    .finally(() => inflight.delete(key));
  inflight.set(key, p);
  return p;
}

/** Every sweep running in this process for a run, settled: the coverage records', a pass reading them again after a rules change, and a background round of the reverse sweeps. */
export async function awaitSweeps(sandboxRoot: string): Promise<void> {
  await Promise.all([...inflight.entries()].filter(([k]) => k.startsWith(`${sandboxRoot}\u0000`)).map(([, p]) => p));
  await rereadInflight.get(resolve(sandboxRoot))?.catch(() => null);
  await backgroundRounds.get(resolve(sandboxRoot));
  await Promise.all([...importInflight.entries()].filter(([k]) => k.startsWith(`${sandboxRoot}\u0000`)).map(([, p]) => p.catch(() => null)));
}

/**
 * The sweeps still pending on standing coverage records, run: those running
 * in this process are awaited, and those whose record is older than the
 * orphan bound (lost with the process that began them) are run here; then
 * every record's latest line written under an older version of the sweep's
 * rules is read again under this harness's (rereadSweeps; idempotent: a
 * line already under them is left alone), so a run with no hub (a host
 * run) is read again too. The finish gate and the answers check call it
 * before they read the gate. Returns how many sweeps it ran or read again.
 */
export async function reconcileSweeps(sandboxRoot: string, o: { orphanMs?: number; maxBytes?: number; maxMs?: number; now?: number } = {}): Promise<number> {
  const P = await import("./protocol.ts");
  const entries = await P.readLedger(sandboxRoot).catch(() => [] as LedgerEntry[]);
  const replaced = P.supersededBy(entries);
  const sweeps = await readSweeps(sandboxRoot);
  const orphan = o.orphanMs ?? sweepOrphanMs();
  const now = o.now ?? Date.now();
  let ran = 0;
  for (const c of entries) {
    if (c.kind !== "coverage" || replaced.has(c.seq) || !c.looked_for?.length || sweepOf(c, sweeps)) continue;
    const key = `${sandboxRoot}\u0000${c.hash}`;
    if (!inflight.has(key) && now - Date.parse(c.at) < orphan) continue;
    await startSweep(sandboxRoot, c, o);
    ran += 1;
  }
  const reread = await rereadSweeps(sandboxRoot, { ...(o.maxBytes !== undefined ? { maxBytes: o.maxBytes } : {}), ...(o.maxMs !== undefined ? { maxMs: o.maxMs } : {}) }).catch(() => null);
  return ran + (reread?.records.length ?? 0);
}

// --- a line read again after the sweep's rules changed ---------------------------------------------

/** A hold of the store sweep on a question's standing answer, as the gate names it: the section, the answer, the code, and the coverage record it is on. */
export type SweepHoldKey = { section: string; answer: number; code: "sweep_pending" | "sweep_hits" | "sweep_partial"; coverage: number };

/** A hold in words: `question:2 (answer E-137): sweep_hits on E-111`. */
export function holdKeyWords(h: SweepHoldKey): string {
  return `${h.section} (answer E-${h.answer}): ${h.code} on E-${h.coverage}`;
}

/**
 * The store sweep's holds on the run's standing answers over `sweeps`, as
 * the gate reads them: each question's standing answer (the first that no
 * correction replaced, as ledgerGate takes it) through protocol.ts
 * sweepHolds, with the question's materiality as the answers check reads
 * it (check-answers.ts sectionBars: a goal's question, or one the register
 * does not hold, is material). Read from the question register, never
 * through check-answers.ts, whose CLI calls this before it has finished
 * loading. Sorted.
 */
export async function sweepHoldKeys(sandboxRoot: string, entries: readonly LedgerEntry[], sweeps: readonly SweepRecord[]): Promise<SweepHoldKey[]> {
  const P = await import("./protocol.ts");
  const disputes = await P.readDisputes(sandboxRoot).catch(() => []);
  const snap = await import("./questions.ts").then((Q) => Q.questionsSnapshot(sandboxRoot)).catch(() => null);
  const goal = new Set((snap?.goal.questions ?? []).map((x) => P.sectionKey(x)));
  const bars = (id: string) => {
    const key = P.sectionKey(id);
    const q = snap?.bySection.get(key);
    return { material: goal.has(key) || !q ? true : q.materiality === "material" };
  };
  const all = entries as LedgerEntry[];
  const replaced = P.supersededBy(all);
  const standing = new Map<string, LedgerEntry>();
  for (const e of all) if (e.kind === "answer" && e.section?.startsWith("question:") && !replaced.has(e.seq) && !standing.has(e.section)) standing.set(e.section, e);
  const out: SweepHoldKey[] = [];
  for (const [section, a] of standing) {
    const material = bars(P.sectionAnswersId(section)).material;
    for (const h of P.sweepHolds(a, all, sweeps, disputes, material)) out.push({ section, answer: a.seq, code: h.code, coverage: h.coverage.seq });
  }
  return out.sort((x, y) => x.section.localeCompare(y.section, undefined, { numeric: true }) || x.coverage - y.coverage || x.code.localeCompare(y.code));
}

/** A coverage record whose latest sweep line was read again: its seq, the version that line was written under (null: none), how, the line read again (`of`) and the line written (`line`), and its hits, named hits and echoes before and after. */
export type RereadRecord = {
  seq: number;
  from_version: number | null;
  how: "read" | "searched";
  of: string;
  line: string;
  hits: [number, number];
  named: [number, number];
  echoes: [number, number];
};
/** A pass of rereadSweeps: the rules version read under, each record read again, and the gate's sweep holds the pass cleared and added. */
export type RereadResult = { rules: number; records: RereadRecord[]; cleared: SweepHoldKey[]; added: SweepHoldKey[] };

const rereadInflight = new Map<string, Promise<RereadResult>>();

/**
 * The coverage records' sweeps recorded under an older version of the
 * sweep's rules, read again under this harness's (docs/adr/0013,
 * "Re-reading after a rules change"). Each record whose latest line (the
 * one the gate reads) was written under a version before the current one,
 * or under none, gets one line on the chain with this harness's `rules`
 * and `reread` ({from_version, reason: "rules changed", of, at, how}). Its
 * hits are sorted anew from what the line recorded (resplitSweep), nothing
 * searched; where a change since its version needs bytes the line did not
 * record (SWEEP_RULE_CHANGES, `bytes`), or the line lacks what a re-read
 * needs, its record is searched again (computeSweep), within the sweep's
 * budget. Every such record is read again, a corrected one too: the gate
 * reads an earlier record's line for the objects a later one names
 * (unexaminedHits). A line already under the current rules is left alone,
 * so a second pass writes nothing: the hub runs one when it starts (a
 * kickoff or a resume), the answers check and the finish gate as a step of
 * reconcileSweeps. The lines are written under the sweeps' lock; a record
 * whose latest line changed meanwhile (another process read it again
 * first) is left to that line, and one that could not be read again stays
 * as it was, for the next pass. When it wrote a line, the trace gets one
 * (`sweep_reread`) and the board one post: how many records were read
 * again and which of the gate's sweep holds changed. One pass at a time
 * per run in this process; `changes` and `now` are the caller's (tests
 * give them).
 */
export function rereadSweeps(sandboxRoot: string, o: { maxBytes?: number; maxMs?: number; changes?: readonly SweepRuleChange[]; now?: () => number } = {}): Promise<RereadResult> {
  const S = resolve(sandboxRoot);
  const running = rereadInflight.get(S);
  if (running) return running;
  const p = rereadPass(S, o).finally(() => rereadInflight.delete(S));
  rereadInflight.set(S, p);
  return p;
}

async function rereadPass(S: string, o: { maxBytes?: number; maxMs?: number; changes?: readonly SweepRuleChange[]; now?: () => number }): Promise<RereadResult> {
  const changes = o.changes ?? SWEEP_RULE_CHANGES;
  const current = changes.at(-1)?.version ?? 0;
  const now = o.now ?? Date.now;
  const result: RereadResult = { rules: current, records: [], cleared: [], added: [] };
  const P = await import("./protocol.ts");
  const entries = await P.readLedger(S).catch(() => [] as LedgerEntry[]);
  const sweeps = await readSweeps(S);
  const due: Array<{ e: LedgerEntry; line: SweepRecord }> = [];
  for (const e of entries) {
    if (e.kind !== "coverage" || !e.hash) continue;
    const line = sweepOf(e, sweeps);
    if (line && sweepRulesOf(line) < current) due.push({ e, line });
  }
  if (!due.length) return result;
  const before = await sweepHoldKeys(S, entries, sweeps).catch(() => [] as SweepHoldKey[]);
  const made: Array<{ e: LedgerEntry; line: SweepRecord; next: Omit<SweepRecord, "prev" | "hash"> }> = [];
  for (const { e, line } of due) {
    const from = sweepRulesOf(line);
    const whole = Array.isArray(line.hits) && Array.isArray(line.named_hits) && Array.isArray(line.unsearched);
    const how: SweepReread["how"] = whole && !changes.some((c) => c.version > from && c.bytes) ? "read" : "searched";
    let r: Omit<SweepRecord, "prev" | "hash">;
    try {
      r = how === "read" ? await resplitSweep(S, e, line) : await computeSweep(S, e, { ...(o.maxBytes !== undefined ? { maxBytes: o.maxBytes } : {}), ...(o.maxMs !== undefined ? { maxMs: o.maxMs } : {}), ...(o.now ? { now: o.now } : {}) });
    } catch {
      // Not read again: its line stands as it was, and the next pass tries again.
      continue;
    }
    const reread: SweepReread = { from_version: typeof line.rules === "number" ? line.rules : null, reason: "rules changed", of: line.hash ?? "", at: new Date(now()).toISOString(), how };
    made.push({ e, line, next: { ...r, rules: current, reread } });
  }
  if (!made.length) return result;
  const written = await P.withNamedLock(S, "sweeps", async () => {
    const latest = await readSweeps(S);
    const text = await readFile(join(S, LEDGER_SWEEPS), "utf8").catch(() => "");
    const lines = text.split("\n").filter((l) => l.trim());
    let prev = lines.length ? ((JSON.parse(lines.at(-1)!) as AnySweepLine).hash ?? "genesis") : "genesis";
    const out: Array<{ m: (typeof made)[number]; rec: SweepRecord }> = [];
    let body = "";
    for (const m of made) {
      // Read again, or swept anew, by another process first: its line stands.
      if (sweepOf(m.e, latest)?.hash !== m.line.hash) continue;
      const rec: SweepRecord = { ...m.next, prev };
      rec.hash = sweepHash(rec, prev);
      prev = rec.hash;
      body += `${JSON.stringify(rec)}\n`;
      out.push({ m, rec });
    }
    if (body) {
      await mkdir(join(S, "ledger"), { recursive: true });
      await appendFile(join(S, LEDGER_SWEEPS), body, "utf8");
    }
    return out;
  });
  if (!written.length) return result;
  await P.renderLedger(S).catch(() => undefined);
  const after = await sweepHoldKeys(S, entries, await readSweeps(S)).catch(() => [] as SweepHoldKey[]);
  const key = (h: SweepHoldKey) => `${h.section}\u0000${h.answer}\u0000${h.code}\u0000${h.coverage}`;
  const had = new Set(before.map(key));
  const has = new Set(after.map(key));
  result.cleared = before.filter((h) => !has.has(key(h)));
  result.added = after.filter((h) => !had.has(key(h)));
  const count = (xs: unknown) => (Array.isArray(xs) ? xs.length : 0);
  result.records = written.map(({ m, rec }) => ({
    seq: m.e.seq,
    from_version: rec.reread!.from_version,
    how: rec.reread!.how,
    of: rec.reread!.of,
    line: rec.hash!,
    hits: [count(m.line.hits), rec.hits.length],
    named: [count(m.line.named_hits), rec.named_hits.length],
    echoes: [count(m.line.echoes), rec.echoes?.length ?? 0],
  }));
  await P.traceHarnessLine(S, {
    tool: "sweep_reread",
    args: { rules: current, reason: "rules changed" },
    result: {
      ok: true,
      records: result.records.length,
      read: result.records.filter((r) => r.how === "read").length,
      searched: result.records.filter((r) => r.how === "searched").length,
      lines: result.records.map((r) => ({ seq: r.seq, from_version: r.from_version, how: r.how, of: r.of, hash: r.line, hits: r.hits, named: r.named, echoes: r.echoes })),
      holds_cleared: result.cleared,
      holds_added: result.added,
    },
  });
  await P.systemPost(S, { tag: "result", key: `sweep-reread:${current}:${result.records[0]!.line}`, body: rereadPostWords(result, changes) }).catch(() => undefined);
  return result;
}

/** A pass of rereadSweeps, as its board post says it: what changed in the rules, how many records were read again and how, what moved, and which holds changed. */
export function rereadPostWords(r: RereadResult, changes: readonly SweepRuleChange[] = SWEEP_RULE_CHANGES): string {
  const oldest = Math.min(...r.records.map((x) => x.from_version ?? 0));
  const since = changes.filter((c) => c.version > oldest && c.version <= r.rules);
  const read = r.records.filter((x) => x.how === "read").length;
  const searched = r.records.length - read;
  const moved = r.records.filter((x) => x.hits[0] !== x.hits[1] || x.named[0] !== x.named[1] || x.echoes[0] !== x.echoes[1]);
  const sum = (f: (x: RereadRecord) => number) => r.records.reduce((n, x) => n + f(x), 0);
  const plural = (n: number, one: string, many = `${one}s`) => `${n} ${n === 1 ? one : many}`;
  return [
    `STORE SWEEPS READ AGAIN: the sweep's rules changed since ${plural(r.records.length, "coverage record")} (${r.records.map((x) => `E-${x.seq}`).join(", ")}) had ${r.records.length === 1 ? "its" : "their"} sweep recorded${since.length ? ` (${since.map((c) => `version ${c.version}, ${c.since}: ${c.what}`).join("; ")})` : ""}. Each was read again under this harness's rules (version ${r.rules}), a line of its own on ledger/sweeps.jsonl with \`reread\`: ${[read ? `${read} from what ${read === 1 ? "its line" : "their lines"} recorded, nothing searched again` : "", searched ? `${searched} searched again, the change needing bytes ${searched === 1 ? "its line" : "their lines"} did not record` : ""].filter(Boolean).join("; ")}.`,
    moved.length ? `In ${plural(moved.length, "record")} what the sweep found moved: ${sum((x) => x.hits[0])} hit(s) became ${sum((x) => x.hits[1])}, named hits ${sum((x) => x.named[0])} became ${sum((x) => x.named[1])}, echoes ${sum((x) => x.echoes[0])} became ${sum((x) => x.echoes[1])}.` : "In none did what the sweep found move.",
    r.cleared.length || r.added.length
      ? `The gate's holds that changed: ${[...r.cleared.map((h) => `${holdKeyWords(h)} cleared`), ...r.added.map((h) => `${holdKeyWords(h)} now held`)].join("; ")}.`
      : "No hold of the gate changed.",
  ].join(" ");
}

// --- the reverse sweep: an addition's files against every standing looked_for -----------------

/** A question's key as protocol.ts sectionKey reads it: question:Q-19, Q-19 and 19 are 19. */
function questionKey(x: string): string {
  return String(x ?? "").trim().replace(/^question:/i, "").replace(/^q-?(?=\d)/i, "");
}

/**
 * The coverage records standing at an addition that name what a hit would
 * contain: recorded before the addition's external entry (`seq`), not
 * corrected by then, with looked_for. Read by seqs alone, so a
 * reconciliation long after finds the same ones.
 */
export function recordsStandingAt(entries: readonly LedgerEntry[], seq: number): LedgerEntry[] {
  const before = entries.filter((e) => e.seq < seq);
  const corrected = new Set(before.filter((e) => typeof e.supersedes === "number").map((e) => e.supersedes as number));
  return before.filter((e) => e.kind === "coverage" && !corrected.has(e.seq) && Boolean(e.looked_for?.length) && Boolean(e.hash));
}

/**
 * Search an addition's import, and only it, for the looked_for strings of
 * `records` (the coverage records standing at the addition), each object
 * streamed whole once, as the store sweep reads one: bytes and strings
 * only, in UTF-8 and UTF-16LE, ASCII case folded. Each hit names the
 * records whose strings it holds (`bears_on`). A budget of bytes and time
 * bounds it; what it did not reach is named, and it is partial. Pure over
 * the store; `now` and the budget are the caller's (tests fix them).
 */
export async function computeImportSweep(sandboxRoot: string, addition: { seq: number; hash: string; import: string }, records: readonly LedgerEntry[], o: { maxBytes?: number; maxMs?: number; now?: () => number; only?: readonly string[] } = {}): Promise<Omit<ImportSweepRecord, "prev" | "hash">> {
  const now = o.now ?? Date.now;
  const budget = { ...sweepBudget(), ...(o.maxBytes !== undefined ? { maxBytes: o.maxBytes } : {}), ...(o.maxMs !== undefined ? { maxMs: o.maxMs } : {}) };
  const started = now();
  // Each string once, whatever case the records wrote it in; bound to every record that looked for it.
  const terms: string[] = [];
  const byTerm = new Map<string, number[]>();
  for (const c of records) {
    for (const t of c.looked_for ?? []) {
      const k = t.toLowerCase();
      if (!byTerm.has(k)) {
        byTerm.set(k, []);
        terms.push(t);
      }
      const on = byTerm.get(k)!;
      if (!on.includes(c.seq)) on.push(c.seq);
    }
  }
  const pats = patterns(terms);
  // The import's files, or those a previous pass left (`only`).
  const objects = terms.length ? (await sweepObjects(sandboxRoot)).filter((x) => x.ref.startsWith(`import:${addition.import}/`) && (!o.only || o.only.includes(x.ref))) : [];
  const groups = new Map<string, SweepObject[]>();
  for (const x of objects) groups.set(x.key, [...(groups.get(x.key) ?? []), x]);
  const hits: ImportSweepHit[] = [];
  const unsearched: ImportSweepRecord["unsearched"] = [];
  let searchedObjects = 0;
  let searchedBytes = 0;
  for (const [, group] of groups) {
    const first = group[0]!;
    if (now() - started > budget.maxMs) {
      for (const g of group) unsearched.push({ ref: g.ref, why: `this pass's time budget (${Math.round(budget.maxMs / 1000)} s, SWARM_REVERSE_SWEEP_MAX_SEC) ran out before it: the next pass searches it`, left: true });
      continue;
    }
    // An object larger than the store sweep's own byte budget is named and not searched, as the store sweep names one; any other is searched, by a pass of its own when it is larger than a pass's budget, never left forever.
    if (first.bytes > sweepBudget().maxBytes) {
      for (const g of group) unsearched.push({ ref: g.ref, why: `its ${first.bytes} bytes are over the store sweep's byte budget (${sweepBudget().maxBytes}, SWARM_SWEEP_MAX_BYTES): not searched` });
      continue;
    }
    if (searchedBytes + first.bytes > budget.maxBytes && searchedObjects > 0) {
      for (const g of group) unsearched.push({ ref: g.ref, why: `its ${first.bytes} bytes would pass this pass's byte budget (${budget.maxBytes}, SWARM_REVERSE_SWEEP_MAX_BYTES; ${searchedBytes} searched): the next pass searches it`, left: true });
      continue;
    }
    let found: Awaited<ReturnType<typeof searchFile>>;
    try {
      found = await searchFile(objectPath(first), pats);
    } catch (err) {
      for (const g of group) unsearched.push({ ref: g.ref, why: `it could not be read (${(err as Error).message})` });
      continue;
    }
    searchedObjects += group.length;
    searchedBytes += first.bytes;
    for (const [t, f] of [...found.entries()].sort((a, b) => a[0] - b[0])) {
      const term = terms[t]!;
      hits.push({ ref: first.ref, term, count: f.count, first_offset: f.first, encodings: [...f.encodings].sort(), ...(group.length > 1 ? { also: group.slice(1).map((g) => g.ref) } : {}), bears_on: [...(byTerm.get(term.toLowerCase()) ?? [])].sort((a, b) => a - b) });
    }
  }
  const state: SweepState = hits.length ? "hits" : unsearched.length ? "partial" : "clean";
  return {
    v: 2,
    of: "import",
    seq: addition.seq,
    target: addition.hash,
    import: addition.import,
    records: records.map((c) => ({ seq: c.seq, target: c.hash ?? "", questions: [...new Set((c.answers ?? []).map(questionKey))], terms: [...(c.looked_for ?? [])] })),
    state,
    terms,
    searched: { objects: searchedObjects, bytes: searchedBytes },
    hits,
    unsearched,
    started_at: new Date(started).toISOString(),
    at: new Date(now()).toISOString(),
  };
}

/** An addition's reverse sweep, by its external entry's hash: the line, or null. */
export function importSweepOf(target: string, sweeps: readonly ImportSweepRecord[]): ImportSweepRecord | null {
  return sweeps.filter((s) => s.target === target).at(-1) ?? null;
}

const importInflight = new Map<string, Promise<ImportSweepRecord>>();

/** An addition's reverse sweep as a whole: its passes in order, every hit, what was searched, and what is not searched yet (its last pass's `unsearched`). */
export type ImportSweepWhole = { passes: ImportSweepRecord[]; latest: ImportSweepRecord; state: SweepState; searched: { objects: number; bytes: number }; hits: ImportSweepHit[]; unsearched: ImportSweepRecord["unsearched"]; left: string[] };

/** The passes of an addition's reverse sweep, by its external entry's hash, as one; null when none is recorded. */
export function importSweepWhole(target: string, sweeps: readonly ImportSweepRecord[]): ImportSweepWhole | null {
  const passes = sweeps.filter((s) => s.target === target);
  const latest = passes.at(-1);
  if (!latest) return null;
  const hits = passes.flatMap((s) => s.hits);
  const left = latest.unsearched.filter((u) => u.left).map((u) => u.ref);
  return {
    passes,
    latest,
    state: hits.length ? "hits" : latest.unsearched.length ? "partial" : "clean",
    searched: { objects: passes.reduce((n, s) => n + s.searched.objects, 0), bytes: passes.reduce((n, s) => n + s.searched.bytes, 0) },
    hits,
    unsearched: latest.unsearched,
    left,
  };
}

/**
 * Run one pass of an addition's reverse sweep and record it: the first
 * over every file of the import, a continuation over what the last pass
 * left, within `o`'s budget (the reverse sweep's own, reverseSweepBudget,
 * by default). A sweep with nothing left is not run again, and a pass
 * running in this process is not started twice. Written under the sweeps'
 * lock, chained; a pass that finds another process recorded the same step
 * first keeps that one. The coverage records searched for are those
 * standing at the addition (recordsStandingAt), read from `entries`.
 * Returns the line (this pass's, or the last one when nothing is left).
 * Throws what went wrong: the next round runs it again.
 */
export function startImportSweep(sandboxRoot: string, addition: { seq: number; hash: string; import: string }, entries: readonly LedgerEntry[], o: { maxBytes?: number; maxMs?: number } = {}): Promise<ImportSweepRecord> {
  const key = `${sandboxRoot}\u0000${addition.hash}`;
  const running = importInflight.get(key);
  if (running) return running;
  const p = (async (): Promise<ImportSweepRecord> => {
    const had = importSweepWhole(addition.hash, await readImportSweeps(sandboxRoot));
    if (had && !had.left.length) return had.latest;
    const budget = { ...reverseSweepBudget(), ...o };
    const result = await computeImportSweep(sandboxRoot, addition, recordsStandingAt(entries, addition.seq), { ...budget, ...(had ? { only: had.left } : {}) });
    // What earlier passes could not read is named on every later line, until it is searched.
    const carried = had ? had.unsearched.filter((u) => !u.left && !result.unsearched.some((x) => x.ref === u.ref)) : [];
    const pass: Omit<ImportSweepRecord, "prev" | "hash"> = { ...result, unsearched: [...result.unsearched, ...carried], state: result.hits.length ? "hits" : result.unsearched.length || carried.length ? "partial" : "clean", ...(had ? { pass: had.passes.length + 1, continues: had.latest.hash } : {}) };
    const P = await import("./protocol.ts");
    const line = await P.withNamedLock(sandboxRoot, "sweeps", async () => {
      const now = importSweepWhole(addition.hash, await readImportSweeps(sandboxRoot));
      // Another process recorded this step first: its line stands.
      if ((now?.latest.hash ?? null) !== (had?.latest.hash ?? null)) return now!.latest;
      const text = await readFile(join(sandboxRoot, LEDGER_SWEEPS), "utf8").catch(() => "");
      const lines = text.split("\n").filter((l) => l.trim());
      const prev = lines.length ? ((JSON.parse(lines.at(-1)!) as AnySweepLine).hash ?? "genesis") : "genesis";
      const rec: ImportSweepRecord = { ...pass, prev };
      rec.hash = sweepHash(rec, prev);
      await mkdir(join(sandboxRoot, "ledger"), { recursive: true });
      await appendFile(join(sandboxRoot, LEDGER_SWEEPS), `${JSON.stringify(rec)}\n`, "utf8");
      return rec;
    });
    await P.renderLedger(sandboxRoot).catch(() => undefined);
    return line;
  })().finally(() => importInflight.delete(key));
  importInflight.set(key, p);
  return p;
}

/** The evidence additions whose reverse sweep is not done: none recorded yet, or its last pass left objects unsearched. Oldest first. */
export async function pendingImportSweeps(sandboxRoot: string, entries?: readonly LedgerEntry[]): Promise<Array<{ seq: number; hash: string; import: string }>> {
  const P = await import("./protocol.ts");
  const all = entries ?? (await P.readLedger(sandboxRoot).catch(() => [] as LedgerEntry[]));
  const lines = await readImportSweeps(sandboxRoot);
  const bySeq = new Map(all.map((e) => [e.seq, e]));
  const out: Array<{ seq: number; hash: string; import: string }> = [];
  for (const x of P.evidenceAdditions(all as LedgerEntry[])) {
    const hash = bySeq.get(x.seq)?.hash;
    if (!hash) continue;
    const whole = importSweepWhole(hash, lines);
    if (!whole || whole.left.length) out.push({ seq: x.seq, hash, import: x.import });
  }
  return out;
}

/**
 * A round of the reverse sweeps: one pass of each addition's that is not
 * done, oldest first, each delivered on the board when it completes (its
 * hits, and what the next pass searches). Nothing once the run has ended.
 * Returns the passes it recorded.
 */
export async function reverseSweepRound(sandboxRoot: string, o: { maxBytes?: number; maxMs?: number } = {}): Promise<ImportSweepRecord[]> {
  const P = await import("./protocol.ts");
  if ((await P.runOutcome(sandboxRoot).catch(() => ({ outcome: null }))).outcome) return [];
  const entries = await P.readLedger(sandboxRoot).catch(() => [] as LedgerEntry[]);
  const out: ImportSweepRecord[] = [];
  for (const a of await pendingImportSweeps(sandboxRoot, entries)) {
    const before = importSweepWhole(a.hash, await readImportSweeps(sandboxRoot))?.latest.hash ?? null;
    const line = await startImportSweep(sandboxRoot, a, entries, o).catch(() => null);
    if (!line || line.hash === before) continue;
    out.push(line);
    await P.systemPost(sandboxRoot, { tag: "ask", key: `reverse-sweep:${a.import}:${line.pass ?? 1}`, body: reverseSweepPostWords(line) }).catch(() => undefined);
  }
  return out;
}

/** A pass of the reverse sweep, as its board post says it: what it searched and found, and what the next pass searches. */
export function reverseSweepPostWords(line: ImportSweepRecord): string {
  const left = line.unsearched.filter((u) => u.left);
  return [
    `REVERSE SWEEP of import:${line.import} (evidence added as E-${line.seq})${line.pass ? `, pass ${line.pass}` : ""}: ${importSweepWords(line)}.`,
    line.hits.length ? "A hit is a string a coverage record looked for, found in the new files: weigh it for its question, recording what the object shows with a delta; it holds nothing by itself." : "",
    left.length ? `The next pass searches the ${left.length} object(s) this one left (${left.map((u) => u.ref).join(", ")}), at the hub's next round; its hits follow here.` : `The reverse sweep of import:${line.import} is complete.`,
  ].filter(Boolean).join(" ");
}

const backgroundRounds = new Map<string, Promise<ImportSweepRecord[]>>();
/** The additions this process has found swept whole, by run: a round is not read again for them. */
const sweptWhole = new Map<string, Set<string>>();

/**
 * A round of the reverse sweeps started in this process's background, and
 * not awaited: none while one runs, none when every addition `imports`
 * names (the store journal's) is known swept whole here. awaitSweeps waits
 * for it.
 */
export function reverseSweepInBackground(sandboxRoot: string, o: { maxBytes?: number; maxMs?: number; imports?: readonly string[] } = {}): Promise<ImportSweepRecord[]> {
  const S = resolve(sandboxRoot);
  const running = backgroundRounds.get(S);
  if (running) return running;
  const done = sweptWhole.get(S);
  if (o.imports && done && o.imports.every((i) => done.has(i))) return Promise.resolve([]);
  const p = (async () => {
    const lines = await reverseSweepRound(S, o);
    const P = await import("./protocol.ts");
    const pending = new Set((await pendingImportSweeps(S)).map((x) => x.import));
    const all = P.evidenceAdditions(await P.readLedger(S).catch(() => [] as LedgerEntry[])).map((x) => x.import);
    sweptWhole.set(S, new Set(all.filter((i) => !pending.has(i))));
    return lines;
  })()
    .catch(() => [] as ImportSweepRecord[])
    .finally(() => backgroundRounds.delete(S));
  backgroundRounds.set(S, p);
  return p;
}

/**
 * The reverse sweeps run as a step of their own, detached from the process
 * that asks (the CLI's evidence add, which exits when the addition is
 * committed): scripts/reverse-sweep.ts, which runs rounds until nothing is
 * left or the run ends, under a lock of its own so that two such steps
 * never run at once (runReverseSweeps).
 */
export function detachReverseSweeps(sandboxRoot: string): void {
  const child = spawn(process.execPath, ["--experimental-strip-types", "--no-warnings", fileURLToPath(new URL("../scripts/reverse-sweep.ts", import.meta.url)), resolve(sandboxRoot)], { detached: true, stdio: "ignore", env: process.env });
  child.on("error", () => undefined);
  child.unref();
}

/**
 * Rounds of the reverse sweeps until nothing is left, the run ends, or a
 * round records nothing (a pass that failed: the next reconciliation runs
 * it again), under the run's reverse-sweep lock: a second such step waits
 * for the lock's bound and gives up. The detached step's body.
 */
export async function runReverseSweeps(sandboxRoot: string, o: { maxBytes?: number; maxMs?: number } = {}): Promise<number> {
  const P = await import("./protocol.ts");
  let passes = 0;
  await P.withNamedLock(resolve(sandboxRoot), "reverse-sweep", async () => {
    for (;;) {
      const recorded = await reverseSweepRound(sandboxRoot, o);
      passes += recorded.length;
      if (!recorded.length || !(await pendingImportSweeps(sandboxRoot)).length) break;
    }
  }).catch(() => undefined);
  return passes;
}

/** A reverse sweep's hit on a question: the sweep, the hit, and the question's coverage records it bears on. */
export type ImportHitOn = { sweep: ImportSweepRecord; hit: ImportSweepHit; records: number[] };

/** The reverse sweeps' hits that bear on a question (`id`, its section key): those in strings a coverage record naming it looked for. */
export function importHitsFor(id: string, sweeps: readonly ImportSweepRecord[]): ImportHitOn[] {
  const want = questionKey(id);
  const out: ImportHitOn[] = [];
  for (const s of sweeps) {
    const mine = new Set(s.records.filter((r) => r.questions.includes(want)).map((r) => r.seq));
    if (!mine.size) continue;
    for (const h of s.hits) {
      const records = h.bears_on.filter((n) => mine.has(n));
      if (records.length) out.push({ sweep: s, hit: h, records });
    }
  }
  return out;
}

/** A reverse sweep's hit in words, with the records whose strings it holds. */
export function importHitWords(x: ImportHitOn): string {
  return `${hitWords(x.hit)} (${x.records.map((n) => `E-${n}`).join(", ")}'s looked_for)`;
}

/**
 * Whether an object a reverse sweep found a hit in is examined for an
 * answer: an entry the answer reaches (`reach`, its seqs), that stands,
 * was recorded after the addition's entry, and names the object itself in
 * its refs (not the import or a directory that holds it). Refs and seqs
 * only: nothing is read of what the entry says.
 */
export function importHitExamined(x: ImportHitOn, reach: ReadonlySet<number>, bySeq: ReadonlyMap<number, LedgerEntry>, replaced: ReadonlyMap<number, number>): boolean {
  const wanted = new Set([x.hit.ref, ...(x.hit.also ?? [])].map(normRef));
  for (const n of reach) {
    const e = bySeq.get(n);
    if (!e || replaced.has(n) || e.seq <= x.sweep.seq || e.kind === "answer" || e.kind === "coverage") continue;
    if ((e.refs ?? []).some((r) => wanted.has(normRef(r)))) return true;
  }
  return false;
}

/** A reverse sweep in words, by question, for the addition's board post and the operator's reply: what it searched for, and each hit with the questions it bears on. */
export function importSweepWords(s: ImportSweepRecord): string {
  if (!s.records.length) return `no coverage record standing at the addition names looked_for strings: nothing to search import:${s.import} for`;
  const head = `import:${s.import} searched for the ${s.terms.length} string(s) of ${s.records.length} standing coverage record(s): ${s.searched.objects} object(s), ${s.searched.bytes} bytes`;
  const questions = [...new Set(s.records.flatMap((r) => (r.questions.length ? r.questions : [""])))];
  const found: string[] = [];
  for (const q of questions) {
    const hs = q ? importHitsFor(q, [s]) : s.hits.map((hit) => ({ sweep: s, hit, records: hit.bears_on.filter((n) => s.records.some((r) => r.seq === n && !r.questions.length)) })).filter((x) => x.records.length);
    if (hs.length) found.push(`${!q ? "no question named" : /^\d+$/.test(q) ? `Q-${q}` : q}: ${hs.map(importHitWords).join("; ")}`);
  }
  return [head, found.length ? `found: ${found.join(" | ")}` : "found none of them", s.unsearched.length ? `not searched: ${s.unsearched.map((u) => `${u.ref} (${u.why})`).join("; ")}` : ""].filter(Boolean).join("; ");
}
