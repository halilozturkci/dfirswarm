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
 * parser and no per-tool code (the harness stays tool-agnostic).
 *
 * The record is immutable and the sweep is not instant, so the result is a
 * line of its own in ledger/sweeps.jsonl, chained like the attestations and
 * bound to the coverage record by its hash. A record with looked_for and no
 * sweep line is pending. The gate (protocol.ts ledgerGate) reads them.
 *
 * Passes (one case, the runs D, E1 and s17fdfe): the search runs in a
 * process of its own (scripts/sweep-pass.ts), one pass at a time for a run,
 * and a pass serves every coverage record waiting when it starts: the store
 * is listed once and each object read once, for the union of their strings
 * (runSweepPass). What each object holds of each string is kept under
 * ledger/sweeps/cache/ (SweepResults), so a later pass reads an object only
 * for strings it has no result for. A budget of bytes read and of time
 * bounds a pass, not a sweep: what a pass's budget ended before is left to
 * the next, which starts by itself and continues the line (`pass`,
 * `continues`; each line says the union so far), until the record's line
 * is clean or names hits. An object larger than a pass's byte budget, or
 * one that cannot be read, is named, and the sweep stays partial. What a
 * line did not search is a summary on it (`unsearched_all`: how many, by
 * reason and by directory) with the first few named, and the whole list a
 * file under ledger/sweeps/ that the line names by sha256
 * (unsearchedRows reads it); a line is never as long as its store. What a
 * line found is bounded the same way when it is long (`hits_all`, the
 * lists whole in ledger/sweeps/hits-<sha256>.jsonl, boundHits), and read
 * whole again from that file by whoever reads the line (hydrateHits). The
 * file's lines are read once by a process and kept, bounded
 * (loadSweepFile), and an append is chained from the head it holds.
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
 * each pass searched in a process of its own (scripts/reverse-sweep-pass.ts)
 * with what each object holds kept between passes, or as a detached step
 * when no hub runs, a pass at a time within a budget of its own
 * (reverseSweepBudget); what a pass leaves (`left`) is named on
 * its line and searched by the next pass, at the next round, until nothing
 * is left (the Fable review of the limits branch, P2-4). Each pass's hits
 * are delivered on the board when it completes, and to the re-examination
 * of the questions those records name (the stale answer's words, a
 * warning); they hold nothing by themselves.
 */
import { spawn } from "node:child_process";
import { createHash } from "node:crypto";
import { closeSync, createReadStream, lstatSync, openSync, readSync } from "node:fs";
import { appendFile, lstat, mkdir, open, readdir, readFile, realpath, rename, rm, stat, writeFile } from "node:fs/promises";
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
  {
    version: 3,
    since: "2026-11-13",
    what: "a maker that read a whole job (job:<id>) or a directory of one read what is accounted for when the record names an object under it holding the string and no object under it holds the string unnamed",
    bytes: false,
  },
  {
    version: 4,
    since: "2026-11-13",
    what: "what a sweep did not search is a summary on its line (how many, by reason and by directory, a few names), the whole list in a file beside the ledger that the line names by sha256; a sweep its budget ended goes on in later passes over what was left, each a line continuing the last",
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
  /**
   * What the sweep did not search, each named with why: the whole list when
   * `unsearched_all` is absent (at most SWEEP_UNSEARCHED_INLINE objects),
   * else the first few of it (SWEEP_UNSEARCHED_SAMPLE), the summary and the
   * file of the whole list being `unsearched_all`'s. Empty when everything
   * was searched; never empty when something was not.
   */
  unsearched: Array<{ ref: string; why: string }>;
  /** The summary of a list too long for the line, and the file that holds it whole (unsearchedRows reads it). */
  unsearched_all?: UnsearchedSummary;
  /**
   * When what the sweep found is longer than a line holds: the summary, and
   * the file that holds `hits`, `named_hits` and `echoes` whole; the three
   * lists on the written line are then the first few of each. The line as
   * this process reads it (readSweeps) holds the lists whole again, read from
   * that file and held to its sha256 (hydrateHits).
   */
  hits_all?: HitsSummary;
  started_at: string;
  at: string;
  /** On a line that continues an earlier pass of the same record's sweep: its number (the first pass is 1 and says nothing), and the hash of the line it continues. Its hits and what it searched are the union of the passes so far; `unsearched` is what is still not searched. */
  pass?: number;
  continues?: string;
  prev?: string;
  hash?: string;
};

/** Why an object was not searched: the pass's time or byte budget ended before it (a later pass searches it), it is larger than a pass's byte budget, or it could not be read; `other` on a line from before 2026-11-13 whose words are none of these. */
export type UnsearchedCode = "time" | "bytes" | "too_large" | "unreadable" | "other";
/** The reasons a later pass takes up by itself. */
export const UNSEARCHED_LEFT: ReadonlySet<UnsearchedCode> = new Set(["time", "bytes"]);
/** A list of unsearched objects no longer than this is whole on its line. */
export const SWEEP_UNSEARCHED_INLINE = 50;
/** How many of a longer list the line names. */
export const SWEEP_UNSEARCHED_SAMPLE = 12;
/** How many directories a summary counts by; the rest are one row, `(other)`. */
export const SWEEP_UNSEARCHED_PREFIXES = 24;
/** Where the whole lists are kept: beside the ledger, one file per list, named by its sha256. */
export const LEDGER_SWEEP_LISTS = "ledger/sweeps";
/**
 * What a sweep did not search, when the list is too long for its line
 * (the run s17fdfe wrote 97,000 to 193,000 rows a line, 33 to 51 MB each):
 * how many, how many of them a later pass searches (`left`), the count by
 * reason (largest first, each with its words) and by directory (the first
 * directory under a job, an import, a capture or a seat's kept outputs;
 * the SWEEP_UNSEARCHED_PREFIXES largest, the rest as `(other)`), and the
 * file that holds the whole list: its path under the run, its sha256 and
 * its rows, one JSON object a line, `{"ref", "why"}` with `why` an
 * UnsearchedCode (and `detail`, the object's own words, on one that could
 * not be read).
 * `file` is absent only on a line read from before 2026-11-13, whose whole
 * list is in the line itself (unsearchedRows reads it from there).
 */
export type UnsearchedSummary = {
  total: number;
  left: number;
  by_reason: Array<{ code: UnsearchedCode; count: number; why: string }>;
  by_prefix: Array<{ prefix: string; count: number }>;
  file?: { path: string; sha256: string; rows: number };
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
  /** As a coverage record's sweep names them (SweepRecord.unsearched): whole, or the first few with `unsearched_all`. */
  unsearched: Array<{ ref: string; why: string; left?: true }>;
  unsearched_all?: UnsearchedSummary;
  /** As a coverage record's sweep has it (SweepRecord.hits_all): the summary and the file of a list of hits too long for the line. */
  hits_all?: HitsSummary;
  started_at: string;
  at: string;
  pass?: number;
  continues?: string;
  prev?: string;
  hash?: string;
};
/**
 * What a sweep found, when it is too long for its line (the runs of
 * one case held up to 920 hits a line): how many in all and in each list
 * (`counts`), by string and by directory (the SWEEP_HITS_KEYS largest, the
 * rest as one row `(other)`), each row with how many of them hold
 * (`hits`, the list a gate holds a negative to) and how many in all
 * (`count`), and the file that holds every list whole: its path under the
 * run, its sha256 and its rows, one JSON object a line, the hit with the
 * list it is in (`{"list": "hits" | "named_hits" | "echoes", ...hit}`), the
 * lists in that order.
 */
export type HitsSummary = {
  total: number;
  counts: { hits: number; named_hits: number; echoes: number };
  by_term: Array<{ term: string; hits: number; count: number }>;
  by_prefix: Array<{ prefix: string; hits: number; count: number }>;
  file: { path: string; sha256: string; rows: number };
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
export function hitOrigins(sandboxRoot: string, refs: readonly string[]): (names: readonly string[], term: string, said: (ref: string, term: string) => boolean, open?: (ref: string, term: string) => boolean) => Promise<HitOrigin[] | null> {
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
  // A maker that read a whole job (job:<id>) or a directory of one, which the record does not name as such, read what is accounted for when
  // the record names an object under it that holds the string and no object under it holds the string unnamed (`open`): every place the
  // string is in what it read is then said. One object under it holding the string unnamed, or not known, and the hit stands.
  let openOf: (ref: string, term: string) => boolean = () => true;
  const accounted = (ref: string, term: string, said: (ref: string, term: string) => boolean) => said(ref, term) && (named(ref) || !openOf(ref, term));
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
  return async (names, term, said, open) => {
    openOf = open ?? (() => true);
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

/**
 * Whether the sweep found a string in an object under `ref` (the object, or
 * one under it as a directory) that the record does not name: a hit not yet
 * judged, by any of its names. What a maker read under such a ref is not
 * accounted for by the record's named hits alone.
 */
function openIn(unnamed: ReadonlyArray<{ term: string; names: readonly string[] }>): (ref: string, term: string) => boolean {
  return (ref, term) => {
    const r = normRef(ref);
    const t = term.toLowerCase();
    return unnamed.some((u) => u.term.toLowerCase() === t && u.names.some((n) => {
      const k = normRef(n);
      return k === r || k.startsWith(`${r}/`);
    }));
  };
}

/** Whether a hit's makers make it an echo (every name the run's own words), not a reading of named objects. */
export function isEcho(origins: readonly HitOrigin[]): boolean {
  return origins.length > 0 && origins.every((o) => o.why !== "named_sources");
}

// --- what a sweep did not search: a summary on the line, the whole list beside the ledger ----------

/** One unsearched object as the whole list holds it: its ref, why by code, and in words; `detail` is its own words where they say more than its reason's (the error of one that could not be read). */
export type UnsearchedRow = { ref: string; code: UnsearchedCode; why: string; detail?: string };

/** The reason an older line's words give (a line from before 2026-11-13 says each object's reason in a sentence, and nothing else). */
export function unsearchedCodeOf(why: string): UnsearchedCode {
  if (/by themselves|are over the store sweep's byte budget/.test(why)) return "too_large";
  if (/time budget/.test(why)) return "time";
  if (/would pass (?:the sweep's|this pass's) byte budget/.test(why)) return "bytes";
  if (/could not be read|no longer in the store/.test(why)) return "unreadable";
  return "other";
}

/** A reason in words, for every object it holds of a summary. */
function reasonWords(code: UnsearchedCode): string {
  return code === "time"
    ? "the pass's time budget (SWARM_SWEEP_MAX_SEC) ran out before them: the next pass searches them"
    : code === "bytes"
      ? "they would pass the pass's byte budget (SWARM_SWEEP_MAX_BYTES): the next pass searches them"
      : code === "too_large"
        ? "each is larger than a pass's byte budget (SWARM_SWEEP_MAX_BYTES): no pass searches them"
        : code === "unreadable"
          ? "they could not be read"
          : "";
}

/** The directory an object is counted under: the first directory below its job, import, capture or seat (job:<id>/<dir>), or that itself for a file at its top. */
export function unsearchedPrefix(ref: string): string {
  const colon = ref.indexOf(":");
  if (colon < 0) return ref;
  const segs = ref.slice(colon + 1).split("/");
  const base = ref.startsWith("net:") ? 2 : 1;
  return `${ref.slice(0, colon + 1)}${segs.slice(0, segs.length > base + 1 ? base + 1 : base).join("/")}`;
}

/** How many objects a sweep line did not search. */
export function unsearchedTotal(s: Pick<AnySweepLine, "unsearched" | "unsearched_all"> | null | undefined): number {
  return s ? (s.unsearched_all?.total ?? s.unsearched?.length ?? 0) : 0;
}

/** How many of them a later pass searches by itself: those a pass's budget ended before. */
export function unsearchedLeft(s: Pick<AnySweepLine, "unsearched" | "unsearched_all"> | null | undefined): number {
  if (!s) return 0;
  if (s.unsearched_all) return s.unsearched_all.left;
  return (s.unsearched ?? []).filter((u) => (u as { left?: true }).left || UNSEARCHED_LEFT.has(unsearchedCodeOf(u.why))).length;
}

/**
 * The list of what a sweep did not search, as it is made: counted by
 * reason and by directory, its first rows kept for the line, and, once it
 * is longer than a line holds (SWEEP_UNSEARCHED_INLINE), written row by
 * row to a file under ledger/sweeps/ named by its sha256. With no run
 * (`root` null) it only counts: a line from before 2026-11-13 read into
 * memory, whose whole list stays in the line.
 */
class UnsearchedList {
  total = 0;
  left = 0;
  private reasons = new Map<UnsearchedCode, { count: number; why: string }>();
  private prefixes = new Map<string, number>();
  private head: Array<{ ref: string; code: UnsearchedCode; why: string; detail?: string; left?: true }> = [];
  private pending: string[] = [];
  private pendingBytes = 0;
  private hash = createHash("sha256");
  private tmp: string | null = null;
  private fh: Awaited<ReturnType<typeof open>> | null = null;
  private root: string | null;
  private flagLeft: boolean;
  constructor(root: string | null, o: { flagLeft?: boolean } = {}) {
    this.root = root;
    this.flagLeft = o.flagLeft ?? false;
  }
  /** More rows are waiting than a caller should let pile up: `await drain()`. */
  get full(): boolean {
    return this.pendingBytes > 1024 * 1024;
  }
  add(ref: string, code: UnsearchedCode, why: string | (() => string), detail?: string, flag?: boolean): void {
    this.total += 1;
    const isLeft = UNSEARCHED_LEFT.has(code);
    if (isLeft) this.left += 1;
    const r = this.reasons.get(code);
    if (r) r.count += 1;
    else this.reasons.set(code, { count: 1, why: reasonWords(code) || (typeof why === "function" ? why() : why) });
    const p = unsearchedPrefix(ref);
    this.prefixes.set(p, (this.prefixes.get(p) ?? 0) + 1);
    if (this.head.length <= SWEEP_UNSEARCHED_INLINE) this.head.push({ ref, code, why: typeof why === "function" ? why() : why, ...(detail !== undefined ? { detail } : {}), ...((flag ?? (isLeft && this.flagLeft)) ? { left: true as const } : {}) });
    if (!this.root) return;
    if (this.total === SWEEP_UNSEARCHED_INLINE + 1) for (const h of this.head) this.row(h.ref, h.code, h.detail);
    else if (this.total > SWEEP_UNSEARCHED_INLINE + 1) this.row(ref, code, detail);
  }
  private row(ref: string, code: UnsearchedCode, detail?: string): void {
    const line = `${JSON.stringify({ ref, why: code, ...(detail !== undefined ? { detail } : {}) })}\n`;
    this.pending.push(line);
    this.pendingBytes += line.length;
  }
  async drain(): Promise<void> {
    if (!this.pending.length || !this.root) return;
    const body = Buffer.from(this.pending.join(""), "utf8");
    this.pending = [];
    this.pendingBytes = 0;
    if (!this.fh) {
      const dir = join(this.root, LEDGER_SWEEP_LISTS);
      await mkdir(dir, { recursive: true });
      this.tmp = join(dir, `.unsearched-${process.pid}-${Math.random().toString(16).slice(2)}.tmp`);
      this.fh = await open(this.tmp, "w");
    }
    this.hash.update(body);
    await this.fh.write(body);
  }
  /** The line's two fields without a file: the list whole, or its first rows and the summary. */
  summary(file?: UnsearchedSummary["file"]): { unsearched: Array<{ ref: string; why: string; left?: true }>; unsearched_all?: UnsearchedSummary } {
    const said = (h: (typeof this.head)[number]) => ({ ref: h.ref, why: h.why, ...(h.left ? { left: true as const } : {}) });
    if (this.total <= SWEEP_UNSEARCHED_INLINE) return { unsearched: this.head.map(said) };
    // The line names a few, within a bound of bytes: a ref is a path, and a path can be long.
    const sample: Array<ReturnType<typeof said>> = [];
    let bytes = 0;
    for (const h of this.head) {
      if (sample.length >= SWEEP_UNSEARCHED_SAMPLE) break;
      bytes += Buffer.byteLength(h.ref) + Buffer.byteLength(h.why);
      if (sample.length && bytes > 8192) break;
      sample.push(said(h));
    }
    const prefixes = [...this.prefixes.entries()].sort((a, b) => b[1] - a[1] || a[0].localeCompare(b[0]));
    const top = prefixes.slice(0, SWEEP_UNSEARCHED_PREFIXES).map(([prefix, count]) => ({ prefix, count }));
    const rest = prefixes.slice(SWEEP_UNSEARCHED_PREFIXES).reduce((n, [, c]) => n + c, 0);
    return {
      unsearched: sample,
      unsearched_all: {
        total: this.total,
        left: this.left,
        by_reason: [...this.reasons.entries()].sort((a, b) => b[1].count - a[1].count || a[0].localeCompare(b[0])).map(([code, r]) => ({ code, count: r.count, why: r.why })),
        by_prefix: rest ? [...top, { prefix: "(other)", count: rest }] : top,
        ...(file ? { file } : {}),
      },
    };
  }
  /** The line's two fields, the whole list closed in its file under its sha256 when it is longer than the line holds. */
  async finish(): Promise<{ unsearched: Array<{ ref: string; why: string; left?: true }>; unsearched_all?: UnsearchedSummary }> {
    if (this.total <= SWEEP_UNSEARCHED_INLINE || !this.root) return this.summary();
    await this.drain();
    await this.fh!.close();
    this.fh = null;
    const sha256 = this.hash.digest("hex");
    const path = `${LEDGER_SWEEP_LISTS}/unsearched-${sha256}.jsonl`;
    // Named by what it holds: the same list again is the same file.
    await rename(this.tmp!, join(this.root, path));
    this.tmp = null;
    return this.summary({ path, sha256, rows: this.total });
  }
  /** A list given up before it was finished: its file is taken away. */
  async abandon(): Promise<void> {
    await this.fh?.close().catch(() => undefined);
    if (this.tmp) await rm(this.tmp, { force: true }).catch(() => undefined);
  }
}

/**
 * The elements of a JSON array in `buf`, from the byte after its `[`: each
 * element's bytes (objects and arrays; a line's `unsearched` holds objects
 * only), found from quote to quote, never parsed here. Returns the index
 * after the array's `]`. A line of 51 MB is read this way in its buffer:
 * parsed whole it was 621 MB of heap for the run s17fdfe's seven lines.
 */
function* arrayElements(buf: Buffer, from: number): Generator<[number, number], number> {
  let pos = from;
  let depth = 0;
  let start = -1;
  for (;;) {
    const q = buf.indexOf(0x22, pos);
    const stop = q < 0 ? buf.length : q;
    for (let i = pos; i < stop; i++) {
      const c = buf[i]!;
      if (c === 0x7b || c === 0x5b) {
        if (depth === 0) start = i;
        depth += 1;
      } else if (c === 0x7d || c === 0x5d) {
        if (depth === 0) return i + 1;
        depth -= 1;
        if (depth === 0) yield [start, i + 1];
      }
    }
    if (q < 0 || depth === 0) throw new Error("not an array of objects");
    let c = q;
    for (;;) {
      c = buf.indexOf(0x22, c + 1);
      if (c < 0) throw new Error("a string with no end");
      let slashes = 0;
      for (let k = c - 1; buf[k] === 0x5c; k--) slashes += 1;
      if (slashes % 2 === 0) break;
    }
    pos = c + 1;
  }
}

const UNSEARCHED_KEY = Buffer.from('"unsearched":[');

/** The rows of the `unsearched` array of a line's bytes, parsed a batch at a time; returns the index after the array. Throws when the line holds none. */
function* unsearchedOfLine(buf: Buffer): Generator<{ ref: string; why: string; left?: true }, number> {
  const at = buf.indexOf(UNSEARCHED_KEY);
  if (at < 0) throw new Error("the line has no unsearched list");
  const it = arrayElements(buf, at + UNSEARCHED_KEY.length);
  let first = -1;
  let last = -1;
  const flush = function* (): Generator<{ ref: string; why: string; left?: true }> {
    if (first < 0) return;
    yield* JSON.parse(`[${buf.toString("utf8", first, last)}]`) as Array<{ ref: string; why: string; left?: true }>;
    first = -1;
  };
  for (;;) {
    const n = it.next();
    if (n.done) {
      yield* flush();
      return n.value;
    }
    if (first < 0) first = n.value[0];
    last = n.value[1];
    if (last - first > 256 * 1024) yield* flush();
  }
}

/** A line larger than this is read in its buffer, its unsearched list never parsed whole. */
const SWEEP_BIG_LINE = 1024 * 1024;

/** A row's reason as its line says it: `left` on a reverse sweep's row is a pass's budget. */
function rowCode(u: { why: string; left?: true }): UnsearchedCode {
  const code = unsearchedCodeOf(u.why);
  return u.left && !UNSEARCHED_LEFT.has(code) ? "bytes" : code;
}

/**
 * One line of ledger/sweeps.jsonl as this process holds it: bounded. A
 * line that carries its unsearched list whole and long (written before
 * 2026-11-13) is held as its summary and its first rows; `legacy` says the
 * whole list is in the line's own bytes (unsearchedRows reads it there).
 */
function parseSweepLine(buf: Buffer): { line: AnySweepLine; legacy: boolean } {
  let list = new UnsearchedList(null);
  let line: AnySweepLine | null = null;
  const at = buf.length > SWEEP_BIG_LINE ? buf.indexOf(UNSEARCHED_KEY) : -1;
  if (at >= 0) {
    try {
      const it = unsearchedOfLine(buf);
      let end = -1;
      for (;;) {
        const n = it.next();
        if (n.done) {
          end = n.value;
          break;
        }
        list.add(n.value.ref, rowCode(n.value), n.value.why, undefined, Boolean(n.value.left));
      }
      line = JSON.parse(`${buf.toString("utf8", 0, at)}"unsearched":[]${buf.toString("utf8", end)}`) as AnySweepLine;
    } catch {
      // Not the shape the scan reads: parsed whole, as any line is.
      line = null;
      list = new UnsearchedList(null);
    }
  }
  if (!line) {
    line = JSON.parse(buf.toString("utf8")) as AnySweepLine;
    if (line.unsearched_all || !Array.isArray(line.unsearched) || line.unsearched.length <= SWEEP_UNSEARCHED_INLINE) return { line, legacy: false };
    for (const u of line.unsearched) list.add(u.ref, rowCode(u), u.why, undefined, Boolean((u as { left?: true }).left));
  }
  const s = list.summary();
  line.unsearched = s.unsearched;
  // A line of this harness's that is long for another reason names its file already.
  if (line.unsearched_all || !s.unsearched_all) return { line, legacy: false };
  line.unsearched_all = s.unsearched_all;
  return { line, legacy: true };
}

// --- the sweeps file in memory -------------------------------------------------------------------

/**
 * ledger/sweeps.jsonl as this process read it: its lines, bounded
 * (parseSweepLine), the chain's head, and where each line that carries its
 * list whole lies in the file. Kept while the file is as it was (its
 * inode, size and time); a file that grew is read from where the last read
 * ended when its first new line continues the head, and whole otherwise.
 * The run s17fdfe's hub parsed 280 MB at each of fourteen call sites, with
 * nothing kept between them, and the append read the file again for the
 * head.
 */
type SweepFile = { cached: boolean; dev: number; ino: number; size: number; mtimeMs: number; parsedTo: number; lines: AnySweepLine[]; head: string; legacy: Map<string, { offset: number; length: number }>; v1?: SweepRecord[]; v2?: ImportSweepRecord[] };
const sweepFiles = new Map<string, SweepFile>();
const sweepLoads = new Map<string, Promise<SweepFile>>();
const emptySweepFile = (): SweepFile => ({ cached: false, dev: 0, ino: 0, size: 0, mtimeMs: 0, parsedTo: 0, lines: [], head: "genesis", legacy: new Map() });

/** The lines between two offsets of the file, each parsed as it completes; a torn line is the chain check's to name. */
async function parseSweepRange(file: string, start: number, end: number, into: SweepFile): Promise<void> {
  if (end <= start) return;
  let parts: Buffer[] = [];
  let lineAt = start;
  let at = start;
  const take = (buf: Buffer, offset: number, complete: boolean) => {
    if (buf.length && buf.toString("latin1", 0, Math.min(buf.length, 64)).trim()) {
      try {
        const { line, legacy } = parseSweepLine(buf);
        into.lines.push(line);
        if (typeof line.hash === "string") into.head = line.hash;
        if (legacy && line.hash) into.legacy.set(line.hash, { offset, length: buf.length });
      } catch {
        if (!complete) return;
      }
    }
    into.parsedTo = offset + buf.length + (complete ? 1 : 0);
  };
  for await (const raw of createReadStream(file, { start, end: end - 1, highWaterMark: 4 * 1024 * 1024 })) {
    const chunk = raw as Buffer;
    let from = 0;
    for (;;) {
      const nl = chunk.indexOf(0x0a, from);
      if (nl < 0) break;
      const piece = chunk.subarray(from, nl);
      const buf = parts.length ? Buffer.concat([...parts, piece]) : piece;
      parts = [];
      take(buf, lineAt, true);
      lineAt = at + nl + 1;
      from = nl + 1;
    }
    if (from < chunk.length) parts.push(chunk.subarray(from));
    at += chunk.length;
  }
  // A last line with no newline: read when it parses (a file written by hand), left to the next read when it is torn.
  if (parts.length) take(Buffer.concat(parts), lineAt, false);
}

/** Lines as written, held as this process holds them: what each found whole again where its line names a file of hits (hydrateHits). */
async function hydrateLines(sandboxRoot: string, lines: AnySweepLine[]): Promise<void> {
  for (let i = 0; i < lines.length; i++) lines[i] = await hydrateHits(sandboxRoot, lines[i]!);
}

/** The sweeps file, read once and kept while it does not change under this process. */
function loadSweepFile(sandboxRoot: string): Promise<SweepFile> {
  const key = resolve(sandboxRoot);
  const running = sweepLoads.get(key);
  if (running) return running;
  const p = (async (): Promise<SweepFile> => {
    const file = join(sandboxRoot, LEDGER_SWEEPS);
    const st = await stat(file).catch(() => null);
    if (!st) {
      sweepFiles.delete(key);
      return emptySweepFile();
    }
    if (!st.isFile()) {
      // Not a regular file (a test holds a render at a pipe): read as it comes, nothing kept.
      const out = emptySweepFile();
      for (const l of (await readFile(file, "utf8")).split("\n")) {
        if (!l.trim()) continue;
        try {
          out.lines.push(parseSweepLine(Buffer.from(l, "utf8")).line);
          out.head = out.lines.at(-1)!.hash ?? out.head;
        } catch {
          // a torn line is the chain check's to name
        }
      }
      await hydrateLines(sandboxRoot, out.lines);
      return out;
    }
    const had = sweepFiles.get(key);
    const same = had && had.dev === st.dev && had.ino === st.ino;
    if (had && same && had.size === st.size && had.mtimeMs === st.mtimeMs) return had;
    if (had && same && st.size > had.size && had.parsedTo === had.size) {
      // Grown: the lines after the last one read, when the first of them continues the chain's head.
      const tail = emptySweepFile();
      await parseSweepRange(file, had.parsedTo, st.size, tail);
      await hydrateLines(sandboxRoot, tail.lines);
      if (tail.lines.length && tail.lines[0]!.prev === had.head) {
        had.lines.push(...tail.lines);
        for (const [h, at] of tail.legacy) had.legacy.set(h, at);
        Object.assign(had, { head: tail.head, size: st.size, mtimeMs: st.mtimeMs, parsedTo: tail.parsedTo, v1: undefined, v2: undefined });
        return had;
      }
    }
    const fresh = emptySweepFile();
    await parseSweepRange(file, 0, st.size, fresh);
    await hydrateLines(sandboxRoot, fresh.lines);
    Object.assign(fresh, { cached: true, dev: st.dev, ino: st.ino, size: st.size, mtimeMs: st.mtimeMs });
    sweepFiles.set(key, fresh);
    return fresh;
  })().finally(() => sweepLoads.delete(key));
  sweepLoads.set(key, p);
  return p;
}

/**
 * Lines appended to ledger/sweeps.jsonl under the sweeps' lock, chained
 * from the head this process holds (read again only when the file changed
 * under it), and added to what it holds: nothing is read back. `make` is
 * given the lines as they stand under the lock and says what to append, as
 * this process holds them (their lists whole); what is written of each is
 * the form boundHits or hydrateHits registered for it, made here only for a
 * line no caller made ready (its file of hits is then written under the
 * lock). Returns the lines as held, each with its hash.
 */
async function appendSweepLines<T extends AnySweepLine>(sandboxRoot: string, make: (lines: readonly AnySweepLine[]) => Array<Omit<T, "prev" | "hash">> | Promise<Array<Omit<T, "prev" | "hash">>>): Promise<T[]> {
  const P = await import("./protocol.ts");
  return P.withNamedLock(sandboxRoot, "sweeps", async () => {
    const state = await loadSweepFile(sandboxRoot);
    const next = await make(state.lines);
    if (!next.length) return [];
    let prev = state.head;
    let body = "";
    const out: T[] = [];
    for (const n of next) {
      let held = n as Omit<AnySweepLine, "prev" | "hash">;
      let written = writtenForms.get(held) as typeof held | undefined;
      if (!written) {
        held = await boundHits(sandboxRoot, held as Unchained<SweepRecord> | Unchained<ImportSweepRecord>);
        written = writtenForms.get(held) as typeof held;
      }
      const rec = { ...written, prev } as unknown as T;
      rec.hash = sweepHash(rec, prev);
      prev = rec.hash;
      body += `${JSON.stringify(rec)}\n`;
      const kept = { ...held, prev: rec.prev, hash: rec.hash } as unknown as T;
      writtenForms.set(kept, rec);
      out.push(kept);
    }
    const file = join(sandboxRoot, LEDGER_SWEEPS);
    await mkdir(join(sandboxRoot, "ledger"), { recursive: true });
    await appendFile(file, body, "utf8");
    const st = await stat(file).catch(() => null);
    if (state.cached && sweepFiles.get(resolve(sandboxRoot)) === state && st && st.ino === state.ino && state.parsedTo === state.size && st.size === state.size + Buffer.byteLength(body)) {
      state.lines.push(...out);
      Object.assign(state, { head: prev, size: st.size, mtimeMs: st.mtimeMs, parsedTo: st.size, v1: undefined, v2: undefined });
    } else sweepFiles.delete(resolve(sandboxRoot));
    return out;
  });
}

/**
 * Every object a sweep line did not search, one at a time: the line's own
 * rows when it holds the list whole, its file's when it names one (the
 * rows counted and their sha256 checked as the last is read: a file that
 * is not the one the line names throws), and, for a line from before
 * 2026-11-13, the list in the line's own bytes in ledger/sweeps.jsonl.
 * A later pass and the reverse sweep's next pass read what was left here.
 */
export async function* unsearchedRows(sandboxRoot: string, s: Pick<AnySweepLine, "unsearched" | "unsearched_all" | "hash">): AsyncGenerator<UnsearchedRow> {
  const all = s.unsearched_all;
  if (!all) {
    for (const u of s.unsearched ?? []) yield { ref: u.ref, code: rowCode(u), why: u.why };
    return;
  }
  if (all.file) {
    const words = new Map(all.by_reason.map((r) => [r.code, r.why]));
    const hash = createHash("sha256");
    let rows = 0;
    let rest = "";
    const say = (l: string): UnsearchedRow => {
      const r = JSON.parse(l) as { ref: string; why: UnsearchedCode; detail?: string };
      rows += 1;
      return { ref: r.ref, code: r.why, why: r.detail ?? words.get(r.why) ?? r.why, ...(r.detail !== undefined ? { detail: r.detail } : {}) };
    };
    for await (const chunk of createReadStream(join(sandboxRoot, all.file.path), { highWaterMark: 1024 * 1024 })) {
      hash.update(chunk as Buffer);
      const text = rest + (chunk as Buffer).toString("utf8");
      const lines = text.split("\n");
      rest = lines.pop() ?? "";
      for (const l of lines) if (l) yield say(l);
    }
    if (rest) yield say(rest);
    if (rows !== all.file.rows || hash.digest("hex") !== all.file.sha256) throw new Error(`${all.file.path} is not the list its sweep line names (${all.file.rows} rows, sha256 ${all.file.sha256})`);
    return;
  }
  const at = s.hash ? (await loadSweepFile(sandboxRoot)).legacy.get(s.hash) : undefined;
  if (!at) throw new Error("the sweep line's whole list is neither in a file it names nor in ledger/sweeps.jsonl");
  const fh = await open(join(sandboxRoot, LEDGER_SWEEPS), "r");
  let buf: Buffer;
  try {
    buf = Buffer.alloc(at.length);
    await fh.read(buf, 0, at.length, at.offset);
  } finally {
    await fh.close();
  }
  for (const u of unsearchedOfLine(buf)) yield { ref: u.ref, code: rowCode(u), why: u.why };
}

/** What a line did not search, in words, bounded: the list when it is short, else the counts by reason and by directory, a few names, and the file that holds the whole list. */
export function unsearchedWords(s: Pick<AnySweepLine, "unsearched" | "unsearched_all">): string {
  const all = s.unsearched_all;
  if (!all) return s.unsearched.map((u) => `${u.ref} (${u.why})`).join("; ");
  const names = s.unsearched.slice(0, 5).map((u) => clipWords(u.ref, 200));
  return clipWords(
    [
      `${all.total} object(s)${all.left ? `, ${all.left === all.total ? "all" : all.left} of them left to the next pass` : ""}`,
      `by reason: ${all.by_reason.map((r) => `${r.count} ${r.code}${r.why ? ` (${clipWords(r.why, 200)})` : ""}`).join("; ")}`,
      `by directory: ${all.by_prefix.slice(0, 8).map((p) => `${clipWords(p.prefix, 120)} ${p.count}`).join(", ")}${all.by_prefix.length > 8 ? `, and ${all.by_prefix.length - 8} more` : ""}`,
      `the first: ${names.join(", ")}`,
      all.file ? `the whole list: ${all.file.path} (${all.file.rows} rows, sha256 ${all.file.sha256})` : "the whole list: in the sweep's own line of ledger/sweeps.jsonl",
    ].join("; "),
    2400,
  );
}

/** Words cut to a bound of bytes, saying so: nothing a sweep says is longer than a few KB. */
function clipWords(text: string, max: number): string {
  if (Buffer.byteLength(text) <= max) return text;
  let cut = text.slice(0, max);
  while (Buffer.byteLength(cut) > max - 6) cut = cut.slice(0, Math.max(0, cut.length - Math.max(1, Math.ceil((Buffer.byteLength(cut) - (max - 6)) / 4))));
  return `${cut} […]`;
}

/** The first `n` of a list in words, and how many more there are, and where each is. */
function someWords<T>(xs: readonly T[], n: number, say: (x: T) => string, more = "more", where = "ledger/sweeps.jsonl"): string {
  return xs.length <= n ? xs.map(say).join("; ") : `${xs.slice(0, n).map(say).join("; ")}; and ${xs.length - n} ${more} (${where} holds each)`;
}

// --- what a sweep found: whole on a short line, else a summary on it and the lists beside the ledger ----------

/** What a sweep found (hits, named hits and echoes together) is whole on its line when it is no more than this many rows, and SWEEP_HITS_INLINE_BYTES. */
export const SWEEP_HITS_INLINE = 50;
const SWEEP_HITS_INLINE_BYTES = 24 * 1024;
/** How many of each list a longer line names (within SWEEP_HITS_SAMPLE_BYTES a list, a hit at most 2 KB). */
export const SWEEP_HITS_SAMPLE = 12;
const SWEEP_HITS_SAMPLE_BYTES = 4 * 1024;
/** How many strings and directories a summary of hits counts by; the rest are one row, `(other)`. */
export const SWEEP_HITS_KEYS = 24;
const HIT_LISTS = ["hits", "named_hits", "echoes"] as const;
type HitListName = (typeof HIT_LISTS)[number];
/** A side file a sweep line names: what it did not search, or what it found; its name is its sha256. */
export const SWEEP_SIDE_FILE = /^ledger\/sweeps\/(unsearched|hits)-([0-9a-f]{64})\.jsonl$/;

/** A side file as a line of the sweeps file names it: its path under the run, its sha256 and rows, and which list it holds. */
export type SweepSideFile = { path: string; sha256: string; rows: number | null; of: "unsearched" | "hits" };

/**
 * The side files the lines of a sweeps file name (`unsearched_all.file`,
 * `hits_all.file`), each once, in the order first named; read from the
 * text, a line at a time, as custody and a package's verify read the
 * chain. A line that does not parse is the chain check's finding, not this
 * one's; a redacted line names none.
 */
export function sweepSideFiles(text: string): SweepSideFile[] {
  const out = new Map<string, SweepSideFile>();
  for (const line of text.split("\n")) {
    if (!line.includes('"unsearched_all"') && !line.includes('"hits_all"')) continue;
    let o: { unsearched_all?: { file?: { path?: unknown; sha256?: unknown; rows?: unknown } }; hits_all?: { file?: { path?: unknown; sha256?: unknown; rows?: unknown } } };
    try {
      o = JSON.parse(line);
    } catch {
      continue;
    }
    for (const [of, f] of [["unsearched", o.unsearched_all?.file], ["hits", o.hits_all?.file]] as const) {
      if (!f || typeof f.path !== "string" || typeof f.sha256 !== "string" || out.has(f.path)) continue;
      out.set(f.path, { path: f.path, sha256: f.sha256, rows: typeof f.rows === "number" ? f.rows : null, of });
    }
  }
  return [...out.values()];
}

/**
 * Each side file held to what its line names: a path of the form
 * ledger/sweeps/<list>-<sha256>.jsonl whose name is the sha256 it names
 * and holds the list it is named for, a regular file where `at` puts it
 * (the run: under the run; a package: ledger-sweeps/<name>), whose bytes
 * hash to that sha256. Returns how many were named and each that is not as
 * named, in words.
 */
export function checkSweepSideFiles(files: readonly SweepSideFile[], at: (path: string) => string): { named: number; bad: string[] } {
  const bad: string[] = [];
  for (const f of files) {
    const m = SWEEP_SIDE_FILE.exec(f.path);
    if (!m || m[1] !== f.of || m[2] !== f.sha256) {
      bad.push(`${f.path.slice(0, 120)}: not a side list's path`);
      continue;
    }
    const abs = at(f.path);
    let regular = false;
    try {
      regular = lstatSync(abs).isFile();
    } catch {
      regular = false;
    }
    if (!regular) {
      bad.push(`${f.path}: missing`);
      continue;
    }
    const h = createHash("sha256");
    let fd: number | null = null;
    try {
      fd = openSync(abs, "r");
      const buf = Buffer.alloc(1024 * 1024);
      for (let n = readSync(fd, buf, 0, buf.length, null); n > 0; n = readSync(fd, buf, 0, buf.length, null)) h.update(buf.subarray(0, n));
    } catch {
      // Unreadable: its hash is not the one named.
    } finally {
      if (fd !== null) closeSync(fd);
    }
    if (h.digest("hex") !== f.sha256) bad.push(`${f.path}: its bytes are not the ${f.sha256.slice(0, 12)}… its line names`);
  }
  return { named: files.length, bad };
}

type Unchained<L> = Omit<L, "prev" | "hash">;
/**
 * The line as it is written, by the line as this process holds it (its
 * lists whole): set where either is made (boundHits, hydrateHits), read
 * where a line is chained (appendSweepLines), so that the chain hashes what
 * the file holds.
 */
const writtenForms = new WeakMap<object, object>();
/** Lines held whose file of hits is missing or not the one the line names: their lists are the line's few and a row that says so. */
const hitsUnreadable = new WeakSet<object>();

function listsOf(line: object): Array<[HitListName, SweepHit[]]> {
  const l = line as Record<string, unknown>;
  return HIT_LISTS.filter((k) => Array.isArray(l[k])).map((k) => [k, l[k] as SweepHit[]]);
}

/** Whether a line this process holds has what its sweep found whole: false when the file of hits its line names could not be read as named (its lists are then the line's few, and a row naming the file). */
export function hitsReadWhole(line: object): boolean {
  return !hitsUnreadable.has(line);
}

/** A hit made short for a line's few: eight of its other names, four of its makers with eight reads each. */
function shortHit<H extends SweepHit>(h: H): H {
  return {
    ...h,
    ...(h.also && h.also.length > 8 ? { also: h.also.slice(0, 8) } : {}),
    ...(h.origins?.length ? { origins: h.origins.slice(0, 4).map((o) => ({ ...o, ...(o.reads && o.reads.length > 8 ? { reads: o.reads.slice(0, 8) } : {}) })) } : {}),
  };
}

/** The first few of a list, within a bound of bytes: at most SWEEP_HITS_SAMPLE, none over 2 KB (made short first), and one at least when one fits. */
function hitSample<H extends SweepHit>(xs: readonly H[]): H[] {
  const out: H[] = [];
  let left = SWEEP_HITS_SAMPLE_BYTES;
  for (const h of xs) {
    if (out.length >= SWEEP_HITS_SAMPLE) break;
    let x = h;
    let b = Buffer.byteLength(JSON.stringify(x));
    if (b > 2048) {
      x = shortHit(h);
      b = Buffer.byteLength(JSON.stringify(x));
    }
    if (b > 2048 || b > left) break;
    out.push(x);
    left -= b;
  }
  return out;
}

/** Counts by key, the largest `n` first, the rest as one row. */
function topCounts<K extends string>(m: Map<string, { hits: number; count: number }>, key: K): Array<Record<K, string> & { hits: number; count: number }> {
  const all = [...m.entries()].sort((a, b) => b[1].count - a[1].count || a[0].localeCompare(b[0]));
  const row = (k: string, v: { hits: number; count: number }) => ({ [key]: k, hits: v.hits, count: v.count }) as Record<K, string> & { hits: number; count: number };
  const top = all.slice(0, SWEEP_HITS_KEYS).map(([k, v]) => row(k, v));
  const rest = all.slice(SWEEP_HITS_KEYS).reduce((n, [, v]) => ({ hits: n.hits + v.hits, count: n.count + v.count }), { hits: 0, count: 0 });
  return rest.count ? [...top, row("(other)", rest)] : top;
}

/**
 * A line made ready to be written: when what it found is longer than a line
 * holds (SWEEP_HITS_INLINE rows, SWEEP_HITS_INLINE_BYTES), every list is
 * written whole to a file under ledger/sweeps/ named by its sha256
 * (`hits-<sha256>.jsonl`), and the line written names it (`hits_all`) and
 * keeps the first few of each list. Returns the line as this process holds
 * it, its lists whole and `hits_all` beside them; what is written is
 * registered for appendSweepLines. A `hits_all` the line came with (read
 * from an older line) is made again. Called before the sweeps' lock is
 * taken, so that the lock is held for the append alone.
 */
export async function boundHits<L extends Unchained<SweepRecord> | Unchained<ImportSweepRecord>>(root: string, whole: L): Promise<L> {
  const { hits_all: _old, ...line } = whole as L & { hits_all?: HitsSummary };
  const lists = listsOf(line);
  const total = lists.reduce((n, [, xs]) => n + xs.length, 0);
  if (total <= SWEEP_HITS_INLINE && Buffer.byteLength(JSON.stringify(lists.map(([, xs]) => xs))) <= SWEEP_HITS_INLINE_BYTES) {
    writtenForms.set(line, line);
    return line as unknown as L;
  }
  const dir = join(root, LEDGER_SWEEP_LISTS);
  await mkdir(dir, { recursive: true });
  const tmp = join(dir, `.hits-${process.pid}-${Math.random().toString(16).slice(2)}.tmp`);
  const fh = await open(tmp, "w");
  const hash = createHash("sha256");
  const terms = new Map<string, { hits: number; count: number }>();
  const prefixes = new Map<string, { hits: number; count: number }>();
  const tally = (m: typeof terms, k: string, holds: boolean) => {
    const v = m.get(k) ?? { hits: 0, count: 0 };
    v.count += 1;
    if (holds) v.hits += 1;
    m.set(k, v);
  };
  let rows = 0;
  try {
    let pending: string[] = [];
    let size = 0;
    const flush = async () => {
      if (!pending.length) return;
      const body = Buffer.from(pending.join(""), "utf8");
      pending = [];
      size = 0;
      hash.update(body);
      await fh.write(body);
    };
    for (const [list, xs] of lists) {
      for (const h of xs) {
        const row = `${JSON.stringify({ list, ...h })}\n`;
        pending.push(row);
        size += row.length;
        rows += 1;
        tally(terms, h.term, list === "hits");
        tally(prefixes, unsearchedPrefix(h.ref), list === "hits");
        if (size > 1024 * 1024) await flush();
      }
    }
    await flush();
    await fh.close();
  } catch (err) {
    await fh.close().catch(() => undefined);
    await rm(tmp, { force: true }).catch(() => undefined);
    throw err;
  }
  const sha256 = hash.digest("hex");
  const path = `${LEDGER_SWEEP_LISTS}/hits-${sha256}.jsonl`;
  // Named by what it holds: the same lists again are the same file.
  await rename(tmp, join(root, path));
  const count = (k: HitListName) => lists.find(([n]) => n === k)?.[1].length ?? 0;
  const summary: HitsSummary = {
    total,
    counts: { hits: count("hits"), named_hits: count("named_hits"), echoes: count("echoes") },
    by_term: topCounts(terms, "term"),
    by_prefix: topCounts(prefixes, "prefix"),
    file: { path, sha256, rows },
  };
  const written = { ...line, ...Object.fromEntries(lists.map(([k, xs]) => [k, hitSample(xs)])), hits_all: summary };
  const held = { ...line, hits_all: summary };
  writtenForms.set(held, written);
  return held as unknown as L;
}

/** A line as it is written (boundHits), for a process that hands its lines to another (scripts/sweep-pass.ts, scripts/reverse-sweep-pass.ts): what it found in a file when it is long. */
export async function sweepLineAsWritten<L extends Unchained<SweepRecord> | Unchained<ImportSweepRecord>>(root: string, line: L): Promise<L> {
  return writtenForms.get(await boundHits(root, line)) as L;
}

/**
 * A written line as this process holds it: what it found whole again, read
 * from the file its `hits_all` names, the rows counted and their sha256
 * checked. A file that is missing or not the one the line names is not
 * trusted for a row: the lists are the line's few, and each list with more
 * than those gets a row whose object is the file and what is missing of it
 * (on a reverse sweep, bearing on every record it searched for), so that a
 * hit the line names is never taken for examined because its list could not
 * be read (hitsReadWhole says so). A line that names no file is as written.
 */
export async function hydrateHits<L extends object>(root: string, written: L): Promise<L> {
  const all = (written as { hits_all?: HitsSummary }).hits_all;
  if (!all?.file) {
    writtenForms.set(written, written);
    return written;
  }
  const got: Record<HitListName, SweepHit[]> = { hits: [], named_hits: [], echoes: [] };
  const name = SWEEP_SIDE_FILE.exec(all.file.path);
  let whole = Boolean(name && name[1] === "hits" && name[2] === all.file.sha256);
  if (whole) {
    try {
      const hash = createHash("sha256");
      let rows = 0;
      let rest = Buffer.alloc(0);
      const take = (b: Buffer) => {
        if (!b.length) return;
        const { list, ...h } = JSON.parse(b.toString("utf8")) as SweepHit & { list: HitListName };
        if (!HIT_LISTS.includes(list)) throw new Error(`a row of no list (${String(list)})`);
        got[list].push(h);
        rows += 1;
      };
      for await (const raw of createReadStream(join(root, all.file.path), { highWaterMark: 1024 * 1024 })) {
        const chunk = raw as Buffer;
        hash.update(chunk);
        const buf = rest.length ? Buffer.concat([rest, chunk]) : chunk;
        let from = 0;
        for (let nl = buf.indexOf(0x0a, from); nl >= 0; nl = buf.indexOf(0x0a, from)) {
          take(buf.subarray(from, nl));
          from = nl + 1;
        }
        rest = Buffer.from(buf.subarray(from));
      }
      take(rest);
      whole = rows === all.file.rows && hash.digest("hex") === all.file.sha256;
    } catch {
      whole = false;
    }
  }
  let held: L;
  if (whole) held = { ...written, ...Object.fromEntries(listsOf(written).map(([k]) => [k, got[k]])) };
  else {
    const records = (written as { records?: Array<{ seq: number }> }).records;
    const terms = (written as { terms?: string[] }).terms ?? [];
    const lists = listsOf(written).map(([k, xs]): [HitListName, SweepHit[]] => {
      const missing = (all.counts?.[k] ?? 0) - xs.length;
      if (missing <= 0) return [k, xs];
      const row: SweepHit & { bears_on?: number[] } = {
        ref: `${all.file.path} (missing, or not the list its line names: ${missing} of the line's ${all.counts[k]} ${k === "hits" ? "hit(s)" : k === "named_hits" ? "named hit(s)" : "echo(es)"} not read)`,
        term: terms[0] ?? "",
        count: 0,
        first_offset: 0,
        encodings: [],
        ...(records ? { bears_on: records.map((r) => r.seq) } : {}),
      };
      return [k, [...xs, row]];
    });
    held = { ...written, ...Object.fromEntries(lists) };
    hitsUnreadable.add(held);
  }
  writtenForms.set(held, written);
  return held;
}

// --- what each object holds of each string, kept between passes -----------------------------------

/** What one object holds of one string: null when it holds none. */
type Found = { count: number; first: number; encodings: Array<"utf-8" | "utf-16le"> };

type TermResults = { file: string; bits: Uint8Array; hits: Map<number, Found>; hitsSize: number; fresh: Array<[number, Found | null]>; known: boolean };

/** Where the results are kept: beside the whole lists, under a name that changes when the search does. */
export const SWEEP_RESULTS_DIR = `${LEDGER_SWEEP_LISTS}/cache/v1`;

/** How often a pass writes the results it has so far, so that one that dies loses little. */
function sweepCacheFlushMs(env: NodeJS.ProcessEnv = process.env): number {
  const v = Number(env.SWARM_SWEEP_CACHE_FLUSH_MS);
  return Number.isFinite(v) && v >= 0 ? v : 5000;
}

/** An object's name in the results: its sha256 when a manifest gives it or its content was read, else its inode with its size and time (written once, but never trusted past a change). */
function resultKey(x: SweepObject): string {
  return x.key.startsWith("sha256:") ? x.key : `${x.key}:${x.bytes}:${x.mtimeMs ?? 0}`;
}

/**
 * The results of the search, by object and string, kept under the run
 * (SWEEP_RESULTS_DIR): a pass reads an object only for the strings it has
 * no result for, so eight coverage records over one store read it once,
 * and a second record with the same strings reads nothing (the run E1
 * read 86.6 GB in seven sweeps of one 12 GB store). An object is a line of
 * `keys` (its number is the line's); a string is three files named by its
 * sha256: `.term` (the string), `.bits` (one bit an object: searched) and
 * `.hits` (a row an object that holds it: number, count, first offset,
 * encodings). Written under a lock of its own, each writer taking in what
 * another wrote first; a file that does not read is as if nothing were
 * kept. Results, not evidence: a line of ledger/sweeps.jsonl never rests
 * on this alone being kept, since a pass that finds none here searches.
 */
class SweepResults {
  private ids = new Map<string, number>();
  private keysSize = 0;
  private count = 0;
  private terms = new Map<string, TermResults>();
  private unnumbered = new Map<string, Map<string, Found | null>>();
  private dirty = false;
  private lastFlush = Date.now();
  private dir: string;
  private root: string | null;
  private constructor(root: string | null) {
    this.root = root;
    this.dir = root ? join(root, SWEEP_RESULTS_DIR) : "";
  }
  /** The results kept for `terms`, read; with no run (`root` null) nothing is kept past the pass. */
  static async open(root: string | null, terms: readonly string[]): Promise<SweepResults> {
    const r = new SweepResults(root);
    for (const t of terms) r.terms.set(t, { file: createHash("sha256").update(t).digest("hex").slice(0, 32), bits: new Uint8Array(0), hits: new Map(), hitsSize: 0, fresh: [], known: false });
    // A writer killed in its write leaves the lock until it is stale: waited for, a few times, before the pass goes on with nothing kept (it then searches, and writes what it finds when the lock is free).
    for (let i = 0; root && i < 3; i++) {
      if (await r.locked(() => r.takeIn()).then(() => true, () => false)) break;
    }
    return r;
  }
  private async locked<T>(fn: () => Promise<T>): Promise<T> {
    const P = await import("./protocol.ts");
    return P.withNamedLock(this.root!, "sweep-results", fn);
  }
  /**
   * What is on disk and not yet in memory: the keys after the last one
   * read (a key's number is its line's), each string's bits (or-ed in) and
   * the hit rows after the last read. Returns the files that end in a row
   * with no newline (a writer died in it): the next writer ends it first.
   */
  private async takeIn(): Promise<string[]> {
    const torn: string[] = [];
    const keys = await readFrom(join(this.dir, "keys"), this.keysSize);
    if (keys) {
      const text = keys.toString("utf8");
      const whole = text.slice(0, text.lastIndexOf("\n") + 1);
      if (whole.length < text.length) torn.push("keys");
      for (const k of whole.split("\n").slice(0, -1)) this.ids.set(k, this.count++);
      this.keysSize += Buffer.byteLength(whole);
    }
    for (const t of this.terms.values()) {
      const bits = await readFile(join(this.dir, `${t.file}.bits`)).catch(() => null);
      if (bits) {
        t.known = true;
        if (bits.length > t.bits.length) {
          const grown = new Uint8Array(bits.length);
          grown.set(t.bits);
          t.bits = grown;
        }
        for (let i = 0; i < bits.length; i++) t.bits[i]! |= bits[i]!;
      }
      const rows = await readFrom(join(this.dir, `${t.file}.hits`), t.hitsSize);
      if (rows) {
        const text = rows.toString("utf8");
        const whole = text.slice(0, text.lastIndexOf("\n") + 1);
        if (whole.length < text.length) torn.push(`${t.file}.hits`);
        for (const l of whole.split("\n")) {
          if (!l) continue;
          try {
            const [id, count, first, enc] = JSON.parse(l) as [number, number, number, number];
            t.hits.set(id, { count, first, encodings: [...(enc & 1 ? (["utf-8"] as const) : []), ...(enc & 2 ? (["utf-16le"] as const) : [])] });
          } catch {
            // a torn row: its object's bit is not set either, and it is searched again
          }
        }
        t.hitsSize += Buffer.byteLength(whole);
      }
    }
    return torn;
  }
  /** What `key` holds of `term`: undefined when it was not searched for it. */
  get(key: string, term: string): Found | null | undefined {
    const id = this.ids.get(key);
    if (id === undefined) return this.unnumbered.get(key)?.get(term);
    const t = this.terms.get(term);
    if (!t || !(t.bits[id >> 3]! & (1 << (id & 7)))) return undefined;
    return t.hits.get(id) ?? null;
  }
  set(key: string, term: string, found: Found | null): void {
    this.dirty = true;
    const id = this.ids.get(key);
    if (id === undefined) {
      let m = this.unnumbered.get(key);
      if (!m) this.unnumbered.set(key, (m = new Map()));
      m.set(term, found);
      return;
    }
    this.mark(this.terms.get(term)!, id, found);
  }
  private mark(t: TermResults, id: number, found: Found | null): void {
    if (id >> 3 >= t.bits.length) {
      const grown = new Uint8Array(Math.max((id >> 3) + 1, t.bits.length * 2, 1024));
      grown.set(t.bits);
      t.bits = grown;
    }
    t.bits[id >> 3]! |= 1 << (id & 7);
    if (found) t.hits.set(id, found);
    t.fresh.push([id, found]);
  }
  /** Written when enough time has passed since the last write. */
  async maybeFlush(): Promise<void> {
    if (this.root && this.dirty && Date.now() - this.lastFlush >= sweepCacheFlushMs()) await this.flush();
  }
  /** Everything found since the last write, written: new objects numbered after those another writer numbered first, hit rows appended, then the bits. Never throws: the pass's lines do not wait on it. */
  async flush(): Promise<void> {
    this.lastFlush = Date.now();
    if (!this.root || !this.dirty) return;
    this.dirty = false;
    await this.locked(async () => {
      await mkdir(this.dir, { recursive: true });
      const torn = await this.takeIn();
      if (torn.length) {
        for (const f of torn) await appendFile(join(this.dir, f), "\n", "utf8");
        await this.takeIn();
      }
      let keys = "";
      for (const [key, results] of this.unnumbered) {
        let id = this.ids.get(key);
        if (id === undefined) {
          id = this.count++;
          this.ids.set(key, id);
          keys += `${key}\n`;
        }
        for (const [term, found] of results) this.mark(this.terms.get(term)!, id, found);
      }
      this.unnumbered.clear();
      if (keys) {
        await appendFile(join(this.dir, "keys"), keys, "utf8");
        this.keysSize += Buffer.byteLength(keys);
      }
      for (const [term, t] of this.terms) {
        if (!t.fresh.length) continue;
        if (!t.known) {
          await writeFile(join(this.dir, `${t.file}.term`), JSON.stringify(term), "utf8");
          t.known = true;
        }
        const rows = t.fresh.filter(([, f]) => f).map(([id, f]) => `${JSON.stringify([id, f!.count, f!.first, (f!.encodings.includes("utf-8") ? 1 : 0) | (f!.encodings.includes("utf-16le") ? 2 : 0)])}\n`).join("");
        if (rows) {
          await appendFile(join(this.dir, `${t.file}.hits`), rows, "utf8");
          t.hitsSize += Buffer.byteLength(rows);
        }
        t.fresh = [];
        const tmp = join(this.dir, `.${t.file}.${process.pid}.bits`);
        await writeFile(tmp, t.bits);
        await rename(tmp, join(this.dir, `${t.file}.bits`));
      }
    }).catch(() => {
      this.dirty = true;
    });
  }
}

/** A file's bytes from an offset on; null when it is not there or holds no more. */
async function readFrom(path: string, offset: number): Promise<Buffer | null> {
  const fh = await open(path, "r").catch(() => null);
  if (!fh) return null;
  try {
    const size = (await fh.stat()).size;
    if (size <= offset) return null;
    const buf = Buffer.alloc(size - offset);
    await fh.read(buf, 0, buf.length, offset);
    return buf;
  } finally {
    await fh.close();
  }
}

// --- a pass: every waiting record's strings, each object read once ---------------------------------

/** A coverage record as a pass reads it. */
export type SweepCoverage = Pick<LedgerEntry, "seq" | "hash" | "refs" | "result_refs" | "looked_for">;
/** What a pass did: the records it served, the objects it read (each once, for every string it had no result for) and their bytes, the objects whose results were all kept already, and how long it took. */
export type SweepPassStats = { records: number; objects: number; reads: number; bytes_read: number; from_results: number; ms: number };
export type SweepPassResult = { lines: Array<Omit<SweepRecord, "prev" | "hash">>; stats: SweepPassStats };

const WHY = { none: 0, time: 1, bytes: 2, too_large: 3, unreadable: 4 } as const;
const WHY_CODE: readonly UnsearchedCode[] = ["other", "time", "bytes", "too_large", "unreadable"];

/**
 * One pass of the store sweep for several coverage records at once: every
 * output the run holds is listed once and each object is read once, for
 * the union of the strings the records that still need it look for and
 * that no kept result answers (SweepResults); what it holds is then
 * attributed to each record by its own strings and sorted by its own
 * objects (named, an echo, a hit). A record with a `prior` line continues
 * it: only what that line left unsearched is searched (unsearchedRows),
 * and the line this pass makes says the union: every hit so far, what was
 * searched in all its passes, what is still not searched. A budget of
 * bytes read and of time bounds the pass, not a record: what it ends
 * before is `left` to the next pass; an object larger than the byte
 * budget by itself is searched by no pass, and one that cannot be read is
 * named. Pure over the store but for what it keeps (the results when
 * `results` is not false, and a list too long for its line, in its file);
 * `now` and the budget are the caller's (tests fix them).
 */
export async function runSweepPass(sandboxRoot: string, records: ReadonlyArray<{ cov: SweepCoverage; prior?: SweepRecord | null }>, o: { maxBytes?: number; maxMs?: number; now?: () => number; results?: boolean } = {}): Promise<SweepPassResult> {
  const now = o.now ?? Date.now;
  const budget = { ...sweepBudget(), ...(o.maxBytes !== undefined ? { maxBytes: o.maxBytes } : {}), ...(o.maxMs !== undefined ? { maxMs: o.maxMs } : {}) };
  const started = now();
  const wall = Date.now();
  const objects = await sweepObjects(sandboxRoot);
  // The same bytes under several names are read once; a group is named when any of its names is.
  const groups: SweepObject[][] = [];
  const byKey = new Map<string, number>();
  const byRef = new Map<string, number>();
  for (const x of objects) {
    let g = byKey.get(x.key);
    if (g === undefined) {
      g = groups.length;
      groups.push([]);
      byKey.set(x.key, g);
    }
    groups[g]!.push(x);
    byRef.set(x.ref, g);
  }
  type Raw = { g: number; ref: string; also: string[]; term: number; found: Found };
  const works = [] as Array<{ cov: SweepCoverage; prior: SweepRecord | null; known: SweepRecord | null; terms: string[]; need: Uint8Array; why: Uint8Array; detail: Map<number, string>; gone: UnsearchedRow[]; raw: Raw[]; objects: number; bytes: number }>;
  for (const r of records) {
    const prior = r.prior ?? null;
    // A line whose file of hits could not be read is continued by searching everything again: what its passes found is not known.
    const known = prior && hitsReadWhole(prior) ? prior : null;
    const terms = [...(r.cov.looked_for ?? [])];
    const w = { cov: r.cov, prior, known, terms, need: new Uint8Array(groups.length).fill(known ? 0 : 1), why: new Uint8Array(groups.length), detail: new Map<number, string>(), gone: [] as UnsearchedRow[], raw: [] as Raw[], objects: 0, bytes: 0 };
    if (known) {
      // What the line it continues left, and what that line could not read (tried again: the reason may have passed).
      for await (const row of unsearchedRows(sandboxRoot, known)) {
        const g = byRef.get(row.ref);
        if (g === undefined) w.gone.push({ ref: row.ref, code: "unreadable", why: "it is no longer in the store's listing", detail: "it is no longer in the store's listing" });
        else w.need[g] = 1;
      }
      // What its passes found so far, by the names the store gives each object now.
      for (const h of [...known.hits, ...known.named_hits, ...(known.echoes ?? [])]) {
        const t = terms.indexOf(h.term);
        if (t < 0) continue;
        const g = byRef.get(h.ref) ?? -1;
        const names = g >= 0 ? groups[g]!.map((x) => x.ref) : [h.ref, ...(h.also ?? [])];
        w.raw.push({ g, ref: names[0]!, also: names.slice(1), term: t, found: { count: h.count, first: h.first_offset, encodings: [...h.encodings] } });
      }
    }
    works.push(w);
  }
  const allTerms = [...new Set(works.flatMap((w) => w.terms))];
  const results = await SweepResults.open(o.results === false ? null : sandboxRoot, allTerms);
  const patternsOf = new Map<string, Pattern[]>();
  let reads = 0;
  let bytesRead = 0;
  let fromResults = 0;
  let tried = 0;
  for (let g = 0; g < groups.length; g++) {
    const wanting = works.filter((w) => w.need[g]);
    if (!wanting.length) continue;
    const group = groups[g]!;
    const first = group[0]!;
    const key = resultKey(first);
    const missing: string[] = [];
    for (const w of wanting) for (const t of w.terms) if (results.get(key, t) === undefined && !missing.includes(t)) missing.push(t);
    if (missing.length) {
      let why: number = WHY.none;
      let detail: string | undefined;
      // The first object a pass reads is read whatever the listing cost: every pass gets somewhere.
      if (tried > 0 && now() - started > budget.maxMs) why = WHY.time;
      else if (first.bytes > budget.maxBytes) why = WHY.too_large;
      else if (bytesRead + first.bytes > budget.maxBytes) why = WHY.bytes;
      else {
        tried += 1;
        try {
          const id = missing.join("\u0000");
          let pats = patternsOf.get(id);
          if (!pats) patternsOf.set(id, (pats = patterns(missing)));
          const found = await searchFile(objectPath(first), pats);
          reads += 1;
          bytesRead += first.bytes;
          missing.forEach((t, i) => {
            const f = found.get(i);
            results.set(key, t, f ? { count: f.count, first: f.first, encodings: [...f.encodings].sort() } : null);
          });
        } catch (err) {
          why = WHY.unreadable;
          detail = (err as Error).message;
        }
      }
      if (why) {
        for (const w of wanting) {
          w.why[g] = why;
          if (detail !== undefined) w.detail.set(g, detail);
        }
        continue;
      }
      await results.maybeFlush();
    } else fromResults += 1;
    for (const w of wanting) {
      w.objects += group.length;
      w.bytes += first.bytes;
      w.terms.forEach((t, i) => {
        const f = results.get(key, t);
        if (f) w.raw.push({ g, ref: first.ref, also: group.slice(1).map((x) => x.ref), term: i, found: f });
      });
    }
  }
  await results.flush();
  const at = now();
  const lines: SweepPassResult["lines"] = [];
  for (const w of works) {
    // What the record names: the objects it searched, and the outputs its search produced (a search's own
    // output echoes what it looked for; it was read as the search's result). A hit there is said, never holding.
    const refs = recordObjects(w.cov);
    const origins = hitOrigins(sandboxRoot, refs);
    const hits: SweepHit[] = [];
    const namedHits: SweepHit[] = [];
    const echoes: SweepHit[] = [];
    const unnamed: Array<{ hit: SweepHit; names: string[] }> = [];
    w.raw.sort((a, b) => a.ref.localeCompare(b.ref) || a.term - b.term);
    for (const r of w.raw) {
      const names = [r.ref, ...r.also];
      const hit: SweepHit = { ref: r.ref, term: w.terms[r.term]!, count: r.found.count, first_offset: r.found.first, encodings: [...r.found.encodings].sort(), ...(r.also.length ? { also: r.also } : {}) };
      if (names.some((n) => refsName(refs, n, r.g >= 0 ? groups[r.g]![0]!.key : undefined))) namedHits.push(hit);
      else unnamed.push({ hit, names });
    }
    // Not named: an echo, or said among the named hits, when what made every name of it says so (hitOrigins), read against what this sweep found in the objects the record names; else a hit.
    const said = saidIn(namedHits);
    const open = openIn(unnamed.map((u) => ({ term: u.hit.term, names: u.names })));
    for (const { hit, names } of unnamed) {
      const made = await origins(names, hit.term, said, open);
      if (!made) hits.push(hit);
      else (isEcho(made) ? echoes : namedHits).push({ ...hit, origins: made });
    }
    const list = new UnsearchedList(sandboxRoot);
    try {
      for (let g = 0; g < groups.length; g++) {
        const code = w.why[g]!;
        if (!code) continue;
        const first = groups[g]![0]!;
        const words =
          code === WHY.time
            ? () => `the sweep's time budget (${Math.round(budget.maxMs / 1000)} s, SWARM_SWEEP_MAX_SEC) ran out before it: the next pass searches it`
            : code === WHY.bytes
              ? () => `its ${first.bytes} bytes would pass the sweep's byte budget (${budget.maxBytes}, SWARM_SWEEP_MAX_BYTES; ${bytesRead} read in this pass): the next pass searches it`
              : code === WHY.too_large
                ? () => `its ${first.bytes} bytes would pass the sweep's byte budget (${budget.maxBytes}, SWARM_SWEEP_MAX_BYTES) by themselves: no pass searches it`
                : () => `it could not be read (${w.detail.get(g) ?? ""})`;
        for (const x of groups[g]!) list.add(x.ref, WHY_CODE[code]!, words, code === WHY.unreadable ? words() : undefined);
        if (list.full) await list.drain();
      }
      for (const row of w.gone) list.add(row.ref, row.code, row.why, row.detail);
      const left = await list.finish();
      const p = w.prior;
      lines.push({
        v: 1,
        seq: w.cov.seq,
        target: w.cov.hash ?? "",
        rules: SWEEP_RULES,
        state: hits.length ? "hits" : list.total ? "partial" : "clean",
        terms: w.terms,
        searched: { objects: (w.known?.searched.objects ?? 0) + w.objects, bytes: (w.known?.searched.bytes ?? 0) + w.bytes },
        hits,
        named_hits: namedHits,
        echoes,
        unsearched: left.unsearched.map(({ ref, why }) => ({ ref, why })),
        ...(left.unsearched_all ? { unsearched_all: left.unsearched_all } : {}),
        started_at: new Date(started).toISOString(),
        at: new Date(at).toISOString(),
        ...(p ? { pass: (p.pass ?? 1) + 1, continues: p.hash ?? "" } : {}),
      });
    } catch (err) {
      await list.abandon();
      throw err;
    }
  }
  return { lines, stats: { records: works.length, objects: objects.length, reads, bytes_read: bytesRead, from_results: fromResults, ms: Date.now() - wall } };
}

/**
 * Search every output the run holds for one coverage record's looked_for
 * strings, in this process and with no result kept or read: a pass of one
 * (runSweepPass), as a line read again under rules that need the bytes
 * runs it. The hub's own sweeps go through startSweep, off its loop.
 */
export async function computeSweep(sandboxRoot: string, cov: SweepCoverage, o: { maxBytes?: number; maxMs?: number; now?: () => number } = {}): Promise<Omit<SweepRecord, "prev" | "hash">> {
  return (await runSweepPass(sandboxRoot, [{ cov }], { ...o, results: false })).lines[0]!;
}

/**
 * A pass for the coverage records `covs` as the sweeps file has them now:
 * one with no line is searched whole, one whose latest line left objects
 * to a next pass continues it, one that is done is left out. What the
 * child process runs (scripts/sweep-pass.ts), and what runs here when a
 * child cannot (SWARM_SWEEP_INPROCESS=1).
 */
export async function sweepPassFor(sandboxRoot: string, covs: readonly SweepCoverage[], o: { maxBytes?: number; maxMs?: number } = {}): Promise<SweepPassResult> {
  const sweeps = await readSweeps(sandboxRoot);
  const records: Array<{ cov: SweepCoverage; prior: SweepRecord | null }> = [];
  for (const cov of covs) {
    const prior = sweepOf(cov, sweeps);
    if (prior && !unsearchedLeft(prior)) continue;
    records.push({ cov, prior });
  }
  if (!records.length) return { lines: [], stats: { records: 0, objects: 0, reads: 0, bytes_read: 0, from_results: 0, ms: 0 } };
  return runSweepPass(sandboxRoot, records, o);
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
 * Nothing is searched again. A list of unsearched objects the line held
 * whole and long is written to its file (ledger/sweeps/) and named.
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
  const open = openIn(line.hits.map((h) => ({ term: h.term, names: [h.ref, ...(h.also ?? [])] })));
  for (const h of line.hits) {
    const was = [h.ref, ...(h.also ?? [])];
    const keys = new Set(was.map((n) => keyOf.get(n)).filter((k): k is string => Boolean(k)));
    const names = [...new Set([...was, ...objects.filter((x) => keys.has(x.key)).map((x) => x.ref)])];
    const hit: SweepHit = { ...h, ...(names.length > 1 ? { also: names.filter((n) => n !== h.ref) } : {}) };
    if (names.some((n) => refsName(refs, n, keyOf.get(n)))) {
      namedHits.push(hit);
      continue;
    }
    const made = await origins(names, h.term, said, open);
    if (!made) hits.push(hit);
    else (isEcho(made) ? echoes : namedHits).push({ ...hit, origins: made });
  }
  // What it found is said again whole; boundHits makes its summary and file when the line is written.
  const { prev: _p, hash: _h, reread: _r, hits_all: _ha, ...rest } = line;
  // A line from before 2026-11-13 holds its long list of unsearched objects in itself: the line that reads it again names it in a file, as every line now does.
  let list: Partial<Pick<SweepRecord, "unsearched" | "unsearched_all">> = {};
  if (line.unsearched_all && !line.unsearched_all.file) {
    const whole = new UnsearchedList(sandboxRoot);
    try {
      for await (const row of unsearchedRows(sandboxRoot, line)) {
        whole.add(row.ref, row.code, row.why, row.code === "other" || row.code === "unreadable" ? row.why : undefined);
        if (whole.full) await whole.drain();
      }
      const done = await whole.finish();
      list = { unsearched: done.unsearched.map(({ ref, why }) => ({ ref, why })), ...(done.unsearched_all ? { unsearched_all: done.unsearched_all } : {}) };
    } catch (err) {
      await whole.abandon();
      throw err;
    }
  }
  return { ...rest, ...list, rules: SWEEP_RULES, state: hits.length ? "hits" : unsearchedTotal(line) ? "partial" : "clean", hits, named_hits: namedHits, echoes };
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

/** The coverage records' sweeps (version 1 lines): what the gate holds a negative to. Each bounded: a list of unsearched objects too long for a line is its summary and its first rows (unsearchedRows reads it whole). Read from the file once and kept while it does not change (loadSweepFile). */
export async function readSweeps(sandboxRoot: string): Promise<SweepRecord[]> {
  const f = await loadSweepFile(sandboxRoot);
  return [...(f.v1 ??= f.lines.filter((s): s is SweepRecord => s.v === 1))];
}

/** The additions' reverse sweeps (version 2 lines, of: "import"). */
export async function readImportSweeps(sandboxRoot: string): Promise<ImportSweepRecord[]> {
  const f = await loadSweepFile(sandboxRoot);
  return [...(f.v2 ??= f.lines.filter((s): s is ImportSweepRecord => s.v === 2 && (s as ImportSweepRecord).of === "import"))];
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
  return `"${h.term}" in ${h.ref}${h.also?.length ? ` (the same bytes as ${h.also.length > 8 ? `${h.also.slice(0, 8).join(", ")} and ${h.also.length - 8} more` : h.also.join(", ")})` : ""}, ${h.count} time${h.count === 1 ? "" : "s"}, first at byte ${h.first_offset}${h.encodings.includes("utf-16le") ? ` (${h.encodings.join(" and ")})` : ""}${h.origins?.length ? ` [${originWords(h.origins)}]` : ""}`;
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

/** How many hits of one kind a sweep's words name; the rest are counted. */
const SWEEP_WORDS_HITS = 12;
/** No words made from a sweep are longer than this many bytes: the ledger's rendering, a gate item and a review offer carry them. */
export const SWEEP_WORDS_MAX = 4000;

/**
 * A sweep in words, for the ledger's rendering, the report and the review
 * offer: bounded (SWEEP_WORDS_MAX). The first hits of each kind are named
 * and the rest counted, and what was not searched is its list when that is
 * short, else its summary and the file that holds the list
 * (unsearchedWords): the run s17fdfe's ledger.md was 265 MB of one
 * sentence an unsearched object.
 */
export function sweepWords(s: SweepRecord | null, c: Pick<LedgerEntry, "looked_for">): string {
  if (!c.looked_for?.length) return "no store sweep (no looked_for strings)";
  if (!s) return "store sweep pending";
  const head = `store sweep ${s.state}: ${s.searched.objects} object(s), ${s.searched.bytes} bytes searched for ${s.terms.map((t) => `"${t}"`).join(", ")}${s.pass ? ` in ${s.pass} passes` : ""}`;
  const left = unsearchedLeft(s);
  const where = s.hits_all?.file ? s.hits_all.file.path : undefined;
  return clipWords(
    [
      head,
      s.reread ? rereadWords(s) : "",
      s.hits.length ? `found outside the record's objects: ${someWords(s.hits, SWEEP_WORDS_HITS, hitWords, "more", where)}` : "",
      s.named_hits.length ? `found in objects the record names (does the answer account for them?): ${someWords(s.named_hits, SWEEP_WORDS_HITS, hitWords, "more", where)}` : "",
      s.echoes?.length ? `echoes, holding nothing (is each only the run's own words?): ${someWords(s.echoes, SWEEP_WORDS_HITS, hitWords, "more", where)}` : "",
      unsearchedTotal(s) ? `not searched${left ? " yet (the next pass goes on with what was left)" : ""}: ${unsearchedWords(s)}` : "",
    ]
      .filter(Boolean)
      .join("; "),
    SWEEP_WORDS_MAX,
  );
}

/** How long a pass waits for more coverage records before it starts: those recorded in a burst are served by one pass. */
export function sweepSettleMs(env: NodeJS.ProcessEnv = process.env): number {
  const v = Number(env.SWARM_SWEEP_SETTLE_MS);
  return Number.isFinite(v) && v >= 0 ? v : 300;
}

/** The passes this process ran, by run, newest last (the last 50): what each read. */
const passLog = new Map<string, SweepPassStats[]>();
/** What each pass this process ran for a run read (the last 50, oldest first). */
export function sweepPasses(sandboxRoot: string): SweepPassStats[] {
  return [...(passLog.get(resolve(sandboxRoot)) ?? [])];
}

/**
 * A pass run off this process's loop: a child process (scripts/sweep-pass.ts)
 * that is given the records and the budget, searches, keeps its results
 * and the long lists, and answers with the lines, bounded, for this
 * process to chain. The run D's hub held twelve sweeps of 212,000 objects
 * in its own loop when it died. With SWARM_SWEEP_INPROCESS=1 the pass runs
 * here (a host with no second process to give).
 */
async function execSweepPass(sandboxRoot: string, covs: readonly SweepCoverage[], budget: { maxBytes: number; maxMs: number }): Promise<SweepPassResult> {
  if (process.env.SWARM_SWEEP_INPROCESS === "1") return sweepPassFor(sandboxRoot, covs, budget);
  const request = JSON.stringify({ sandbox: resolve(sandboxRoot), budget, records: covs.map((c) => ({ seq: c.seq, hash: c.hash, refs: c.refs ?? [], result_refs: c.result_refs ?? [], looked_for: c.looked_for ?? [] })) });
  return new Promise<SweepPassResult>((done, fail) => {
    const child = spawn(process.execPath, ["--experimental-strip-types", "--no-warnings", fileURLToPath(new URL("../scripts/sweep-pass.ts", import.meta.url))], { stdio: ["pipe", "pipe", "pipe"], env: process.env });
    const out: Buffer[] = [];
    let err = "";
    child.stdout.on("data", (c: Buffer) => out.push(c));
    child.stderr.on("data", (c: Buffer) => {
      if (err.length < 4096) err += c.toString("utf8");
    });
    child.on("error", fail);
    child.on("close", (code, signal) => {
      if (code !== 0) return fail(new Error(`the sweep pass ended ${signal ? `on ${signal}` : `with status ${code}`}${err.trim() ? `: ${err.trim().slice(0, 1000)}` : ""}`));
      try {
        done(JSON.parse(Buffer.concat(out).toString("utf8")) as SweepPassResult);
      } catch (e) {
        fail(e as Error);
      }
    });
    child.stdin.on("error", () => undefined);
    child.stdin.end(request);
  });
}

type Waiting = { cov: LedgerEntry; resolve: (line: SweepRecord | null) => void };
type PassQueue = { waiting: Map<string, Waiting>; running: Promise<void> | null; timer: ReturnType<typeof setTimeout> | null; budget: { maxBytes?: number; maxMs?: number } };
const passQueues = new Map<string, PassQueue>();
const inflight = new Map<string, Promise<SweepRecord | null>>();

function startPassSoon(sandboxRoot: string, q: PassQueue, ms: number): void {
  if (q.running || q.timer) return;
  q.timer = setTimeout(() => {
    q.timer = null;
    q.running = passRound(sandboxRoot, q)
      .catch(() => undefined)
      .finally(() => {
        q.running = null;
        if (q.waiting.size) startPassSoon(sandboxRoot, q, 0);
        // A budget a caller gave is its sweeps' own: gone when none of them waits.
        else q.budget = {};
      });
  }, ms);
}

/**
 * One pass for every record waiting when it starts, and their lines: each
 * chained under the sweeps' lock unless another process recorded that step
 * first (the record's latest line is no longer the one the pass
 * continued). A record whose line left objects to a next pass, and whose
 * pass got somewhere, waits again: the next pass starts when this one
 * ends, until nothing is left. Its promise settles with its last line.
 */
async function passRound(sandboxRoot: string, q: PassQueue): Promise<void> {
  const batch = [...q.waiting.entries()];
  q.waiting.clear();
  const open = new Map(batch);
  const settle = (hash: string, line: SweepRecord | null) => {
    const w = open.get(hash);
    if (!w) return;
    open.delete(hash);
    w.resolve(line);
  };
  try {
    const before = await readSweeps(sandboxRoot);
    const todo: Array<{ hash: string; w: Waiting; prior: SweepRecord | null }> = [];
    for (const [hash, w] of batch) {
      const prior = sweepOf(w.cov, before);
      if (prior && !unsearchedLeft(prior)) settle(hash, prior);
      else todo.push({ hash, w, prior });
    }
    if (!todo.length) return;
    const result = await execSweepPass(sandboxRoot, todo.map((t) => t.w.cov), { ...sweepBudget(), ...q.budget });
    const log = passLog.get(resolve(sandboxRoot)) ?? [];
    log.push(result.stats);
    passLog.set(resolve(sandboxRoot), log.slice(-50));
    // As this process holds them: a line the pass wrote its file of hits for is read whole from it, any other made ready; outside the lock.
    const ready = await Promise.all(result.lines.map((l) => (l.hits_all ? hydrateHits(sandboxRoot, l) : boundHits(sandboxRoot, l))));
    const written = await appendSweepLines<SweepRecord>(sandboxRoot, (lines) => {
      const v1 = lines.filter((s): s is SweepRecord => s.v === 1);
      // Recorded by another process first: its line stands.
      return ready.filter((l) => (sweepOf({ hash: l.target }, v1)?.hash ?? null) === (l.continues ?? null));
    });
    const P = await import("./protocol.ts");
    await P.renderLedger(sandboxRoot).catch(() => undefined);
    const after = await readSweeps(sandboxRoot);
    for (const t of todo) {
      const mine = written.find((l) => l.target === t.hash);
      const got = mine && (mine.searched.objects > (t.prior?.searched.objects ?? 0) || unsearchedTotal(mine) < unsearchedTotal(t.prior));
      if (mine && got && unsearchedLeft(mine)) {
        open.delete(t.hash);
        q.waiting.set(t.hash, t.w);
      } else settle(t.hash, sweepOf(t.w.cov, after));
    }
  } finally {
    // What went wrong is the result's (null): the record stands, its sweep stays as it was, to be run again.
    for (const hash of [...open.keys()]) settle(hash, null);
  }
}

/**
 * Run a coverage record's sweep and record it, once per record: a sweep
 * already recorded with nothing left to a next pass, or waiting or running
 * in this process, is not started again. One pass at a time for a run,
 * off this process's loop (execSweepPass): it serves every record waiting
 * when it starts, so records written in a burst are one reading of the
 * store, and a record whose pass the budget ended is continued by the
 * next, until its line is clean or names hits, or names only what no pass
 * can search. The promise settles with the record's last line. Errors are
 * the result's (null), never thrown: the record stands and its sweep stays
 * pending, to be run again.
 */
export function startSweep(sandboxRoot: string, cov: LedgerEntry, o: { maxBytes?: number; maxMs?: number } = {}): Promise<SweepRecord | null> {
  if (!cov.looked_for?.length || !cov.hash) return Promise.resolve(null);
  const key = `${sandboxRoot}\u0000${cov.hash}`;
  const running = inflight.get(key);
  if (running) return running;
  const root = resolve(sandboxRoot);
  let q = passQueues.get(root);
  if (!q) passQueues.set(root, (q = { waiting: new Map(), running: null, timer: null, budget: {} }));
  if (o.maxBytes !== undefined) q.budget.maxBytes = o.maxBytes;
  if (o.maxMs !== undefined) q.budget.maxMs = o.maxMs;
  let resolveIt!: (line: SweepRecord | null) => void;
  const p = new Promise<SweepRecord | null>((r) => (resolveIt = r)).finally(() => inflight.delete(key));
  inflight.set(key, p);
  q.waiting.set(cov.hash, { cov, resolve: resolveIt });
  startPassSoon(sandboxRoot, q, sweepSettleMs());
  return p;
}

/** Every sweep running in this process for a run, settled: the coverage records', a pass reading them again after a rules change, and a background round of the reverse sweeps. */
export async function awaitSweeps(sandboxRoot: string): Promise<void> {
  await Promise.all([...inflight.entries()].filter(([k]) => k.startsWith(`${sandboxRoot}\u0000`)).map(([, p]) => p));
  await rereadInflight.get(resolve(sandboxRoot))?.catch(() => null);
  await backgroundRounds.get(resolve(sandboxRoot));
  await Promise.all([...importInflight.entries()].filter(([k]) => k.startsWith(`${sandboxRoot}\u0000`)).map(([, p]) => p.catch(() => null)));
  await Promise.all([...inflight.entries()].filter(([k]) => k.startsWith(`${sandboxRoot}\u0000`)).map(([, p]) => p));
}

/**
 * The sweeps of standing coverage records that are not done, started, and
 * not waited for: a record with no line (its sweep lost with the process
 * that began it) and one whose latest line left objects to a next pass
 * that no process is running. `orphanMs` is how old the record, or that
 * line, must be before it is taken to be nobody's (0: at once, as a hub
 * that starts takes them: nothing of an earlier hub's is still running).
 * Returns the sweeps it started or found running here.
 */
export async function startPendingSweeps(sandboxRoot: string, o: { orphanMs?: number; maxBytes?: number; maxMs?: number; now?: number } = {}): Promise<Array<Promise<SweepRecord | null>>> {
  const P = await import("./protocol.ts");
  const entries = await P.readLedger(sandboxRoot).catch(() => [] as LedgerEntry[]);
  const replaced = P.supersededBy(entries);
  const sweeps = await readSweeps(sandboxRoot);
  const orphan = o.orphanMs ?? sweepOrphanMs();
  const now = o.now ?? Date.now();
  const budget = { ...(o.maxBytes !== undefined ? { maxBytes: o.maxBytes } : {}), ...(o.maxMs !== undefined ? { maxMs: o.maxMs } : {}) };
  const out: Array<Promise<SweepRecord | null>> = [];
  for (const c of entries) {
    if (c.kind !== "coverage" || replaced.has(c.seq) || !c.looked_for?.length || !c.hash) continue;
    const line = sweepOf(c, sweeps);
    if (line && !unsearchedLeft(line)) continue;
    const running = inflight.get(`${sandboxRoot}\u0000${c.hash}`);
    if (running) out.push(running);
    else if (now - Date.parse(line?.at ?? c.at) >= orphan) out.push(startSweep(sandboxRoot, c, budget));
  }
  return out;
}

/**
 * What a hub does with the sweeps when it starts (a kickoff, or a resume
 * after it died): every standing coverage record with no sweep line, or
 * with a line whose pass the budget ended, gets its pass now, in the
 * background (the run D's four lost sweeps ran 85 to 89 minutes after
 * their records, when the finish gate asked). Returns how many it started.
 */
export async function reconcileSweepsAtStart(sandboxRoot: string): Promise<number> {
  return (await startPendingSweeps(sandboxRoot, { orphanMs: 0 }).catch(() => [])).length;
}

/**
 * The sweeps still pending on standing coverage records, run: those running
 * in this process are awaited, and those whose record is older than the
 * orphan bound (lost with the process that began them), or whose latest
 * line left objects to a next pass nobody is running, are run here to
 * their end; then every record's latest line written under an older
 * version of the sweep's rules is read again under this harness's
 * (rereadSweeps; idempotent: a line already under them is left alone), so
 * a run with no hub (a host run) is read again too, and what a line read
 * again left to a next pass is searched. The finish gate and the answers
 * check call it before they read the gate. Returns how many sweeps it ran
 * or read again.
 */
export async function reconcileSweeps(sandboxRoot: string, o: { orphanMs?: number; maxBytes?: number; maxMs?: number; now?: number } = {}): Promise<number> {
  let ran = (await Promise.all(await startPendingSweeps(sandboxRoot, o))).length;
  const reread = await rereadSweeps(sandboxRoot, { ...(o.maxBytes !== undefined ? { maxBytes: o.maxBytes } : {}), ...(o.maxMs !== undefined ? { maxMs: o.maxMs } : {}) }).catch(() => null);
  if (reread?.records.length) ran += (await Promise.all(await startPendingSweeps(sandboxRoot, o))).length;
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
  const attests = await P.readAttestations(sandboxRoot).catch(() => []);
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
    for (const h of P.sweepHolds(a, all, sweeps, disputes, material, attests)) out.push({ section, answer: a.seq, code: h.code, coverage: h.coverage.seq });
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
    const whole = Array.isArray(line.hits) && Array.isArray(line.named_hits) && Array.isArray(line.unsearched) && hitsReadWhole(line);
    const how: SweepReread["how"] = whole && !changes.some((c) => c.version > from && c.bytes) ? "read" : "searched";
    let r: Omit<SweepRecord, "prev" | "hash">;
    try {
      r = how === "read" ? await resplitSweep(S, e, line) : await computeSweep(S, e, { ...(o.maxBytes !== undefined ? { maxBytes: o.maxBytes } : {}), ...(o.maxMs !== undefined ? { maxMs: o.maxMs } : {}), ...(o.now ? { now: o.now } : {}) });
    } catch {
      // Not read again: its line stands as it was, and the next pass tries again.
      continue;
    }
    const reread: SweepReread = { from_version: typeof line.rules === "number" ? line.rules : null, reason: "rules changed", of: line.hash ?? "", at: new Date(now()).toISOString(), how };
    // Its file of hits written now, outside the sweeps' lock.
    made.push({ e, line, next: await boundHits(S, { ...r, rules: current, reread }) });
  }
  if (!made.length) return result;
  const kept: typeof made = [];
  const recs = await appendSweepLines<SweepRecord>(S, (lines) => {
    const latest = lines.filter((s): s is SweepRecord => s.v === 1);
    // Read again, or swept anew, by another process first: its line stands.
    for (const m of made) if (sweepOf(m.e, latest)?.hash === m.line.hash) kept.push(m);
    return kept.map((m) => m.next);
  });
  const written = recs.map((rec, i) => ({ m: kept[i]!, rec }));
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
export async function computeImportSweep(sandboxRoot: string, addition: { seq: number; hash: string; import: string }, records: readonly LedgerEntry[], o: { maxBytes?: number; maxMs?: number; now?: () => number; only?: readonly string[] | ReadonlySet<string>; carried?: readonly UnsearchedRow[] } = {}): Promise<Omit<ImportSweepRecord, "prev" | "hash">> {
  return (await importSweepPass(sandboxRoot, addition, records, { ...o, results: false })).line;
}

/** What a pass of a reverse sweep did: the objects of the store it listed, those of the import it was to search, the objects it read and their bytes, those whose results were all kept already, how long it took, and the process it ran in. */
export type ReverseSweepStats = { import: string; listed: number; objects: number; reads: number; bytes_read: number; from_results: number; ms: number; pid: number };

/**
 * computeImportSweep, with what each object holds of each string kept
 * between passes when `results` is not false (SweepResults, as the store
 * sweep keeps them): an object whose results are all kept is not read
 * again, so a pass that died, or one started again after a restart, reads
 * only what no pass got to. The line is the same either way: an object
 * answered from the results passes the same budget checks, and counts as
 * searched, as one read.
 */
async function importSweepPass(sandboxRoot: string, addition: { seq: number; hash: string; import: string }, records: readonly LedgerEntry[], o: { maxBytes?: number; maxMs?: number; now?: () => number; only?: readonly string[] | ReadonlySet<string>; carried?: readonly UnsearchedRow[]; results?: boolean } = {}): Promise<{ line: Omit<ImportSweepRecord, "prev" | "hash">; stats: ReverseSweepStats }> {
  const wall = Date.now();
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
  const only = o.only ? (o.only instanceof Set ? (o.only as ReadonlySet<string>) : new Set(o.only as readonly string[])) : null;
  const listed = terms.length ? await sweepObjects(sandboxRoot) : [];
  const objects = listed.filter((x) => x.ref.startsWith(`import:${addition.import}/`) && (!only || only.has(x.ref)));
  const groups = new Map<string, SweepObject[]>();
  for (const x of objects) groups.set(x.key, [...(groups.get(x.key) ?? []), x]);
  const hits: ImportSweepHit[] = [];
  // What is not searched: whole on the line when short, else its summary there and the list in its file (UnsearchedList).
  const unsearched = new UnsearchedList(sandboxRoot, { flagLeft: true });
  let searchedObjects = 0;
  let searchedBytes = 0;
  const results = o.results === false || !terms.length ? null : await SweepResults.open(sandboxRoot, terms);
  let reads = 0;
  let bytesRead = 0;
  let fromResults = 0;
  try {
    for (const [, group] of groups) {
      const first = group[0]!;
      if (unsearched.full) await unsearched.drain();
      if (now() - started > budget.maxMs) {
        for (const g of group) unsearched.add(g.ref, "time", `this pass's time budget (${Math.round(budget.maxMs / 1000)} s, SWARM_REVERSE_SWEEP_MAX_SEC) ran out before it: the next pass searches it`);
        continue;
      }
      // An object larger than the store sweep's own byte budget is named and not searched, as the store sweep names one; any other is searched, by a pass of its own when it is larger than a pass's budget, never left forever.
      if (first.bytes > sweepBudget().maxBytes) {
        for (const g of group) unsearched.add(g.ref, "too_large", `its ${first.bytes} bytes are over the store sweep's byte budget (${sweepBudget().maxBytes}, SWARM_SWEEP_MAX_BYTES): not searched`);
        continue;
      }
      if (searchedBytes + first.bytes > budget.maxBytes && searchedObjects > 0) {
        for (const g of group) unsearched.add(g.ref, "bytes", `its ${first.bytes} bytes would pass this pass's byte budget (${budget.maxBytes}, SWARM_REVERSE_SWEEP_MAX_BYTES; ${searchedBytes} searched): the next pass searches it`);
        continue;
      }
      let found: Map<number, { count: number; first: number; encodings: Iterable<"utf-8" | "utf-16le"> }>;
      const key = resultKey(first);
      // The strings no kept result answers for this object: read for those alone.
      const missing = results ? terms.map((t, i) => [t, i] as const).filter(([t]) => results.get(key, t) === undefined) : terms.map((t, i) => [t, i] as const);
      try {
        const read = missing.length ? await searchFile(objectPath(first), missing.length === terms.length ? pats : patterns(missing.map(([t]) => t))) : new Map<number, { count: number; first: number; encodings: Set<"utf-8" | "utf-16le"> }>();
        if (missing.length) {
          reads += 1;
          bytesRead += first.bytes;
        } else fromResults += 1;
        if (results) {
          missing.forEach(([t], j) => {
            const f = read.get(j);
            results.set(key, t, f ? { count: f.count, first: f.first, encodings: [...f.encodings].sort() } : null);
          });
          await results.maybeFlush();
          found = new Map();
          terms.forEach((t, i) => {
            const f = results.get(key, t);
            if (f) found.set(i, f);
          });
        } else found = read;
      } catch (err) {
        const words = `it could not be read (${(err as Error).message})`;
        for (const g of group) unsearched.add(g.ref, "unreadable", words, words);
        continue;
      }
      searchedObjects += group.length;
      searchedBytes += first.bytes;
      for (const [t, f] of [...found.entries()].sort((a, b) => a[0] - b[0])) {
        const term = terms[t]!;
        hits.push({ ref: first.ref, term, count: f.count, first_offset: f.first, encodings: [...f.encodings].sort(), ...(group.length > 1 ? { also: group.slice(1).map((g) => g.ref) } : {}), bears_on: [...(byTerm.get(term.toLowerCase()) ?? [])].sort((a, b) => a - b) });
      }
    }
    // What earlier passes could not read is named on every later line, until it is searched.
    for (const row of o.carried ?? []) {
      unsearched.add(row.ref, row.code, row.why, row.detail ?? (row.code === "other" || row.code === "unreadable" ? row.why : undefined));
      if (unsearched.full) await unsearched.drain();
    }
  } catch (err) {
    await unsearched.abandon();
    await results?.flush();
    throw err;
  }
  await results?.flush();
  const total = unsearched.total;
  const left = await unsearched.finish();
  const state: SweepState = hits.length ? "hits" : total ? "partial" : "clean";
  const line: Omit<ImportSweepRecord, "prev" | "hash"> = {
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
    unsearched: left.unsearched,
    ...(left.unsearched_all ? { unsearched_all: left.unsearched_all } : {}),
    started_at: new Date(started).toISOString(),
    at: new Date(now()).toISOString(),
  };
  return { line, stats: { import: addition.import, listed: listed.length, objects: objects.length, reads, bytes_read: bytesRead, from_results: fromResults, ms: Date.now() - wall, pid: process.pid } };
}

/** An addition's reverse sweep, by its external entry's hash: the line, or null. */
export function importSweepOf(target: string, sweeps: readonly ImportSweepRecord[]): ImportSweepRecord | null {
  return sweeps.filter((s) => s.target === target).at(-1) ?? null;
}

const importInflight = new Map<string, Promise<ImportSweepRecord>>();

/** An addition's reverse sweep as a whole: its passes in order, every hit, what was searched, and what is not searched yet (its last pass's `unsearched`). */
export type ImportSweepWhole = {
  passes: ImportSweepRecord[];
  latest: ImportSweepRecord;
  state: SweepState;
  searched: { objects: number; bytes: number };
  hits: ImportSweepHit[];
  /** The last pass's rows as its line names them: all of them, or the first few of a long list (`unsearched_total` is how many there are). */
  unsearched: ImportSweepRecord["unsearched"];
  unsearched_total: number;
  /** The objects the next pass searches, as the line names them (all, or the first few), and how many there are. */
  left: string[];
  left_total: number;
};

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
    state: hits.length ? "hits" : unsearchedTotal(latest) ? "partial" : "clean",
    searched: { objects: passes.reduce((n, s) => n + s.searched.objects, 0), bytes: passes.reduce((n, s) => n + s.searched.bytes, 0) },
    hits,
    unsearched: latest.unsearched,
    unsearched_total: unsearchedTotal(latest),
    left,
    left_total: unsearchedLeft(latest),
  };
}

/**
 * The next pass of an addition's reverse sweep, searched and not recorded:
 * the first over every file of the import, a continuation over what the
 * last pass left (read as a stream from its line, or from the file it
 * names), what earlier passes could not read named again, within `budget`.
 * The coverage records searched for are those standing at the addition
 * (recordsStandingAt), from `entries` or the ledger. What each object holds
 * of each string is kept (importSweepPass), so a pass started again after
 * a restart reads only what no pass got to. `line` is null when the sweep
 * has nothing left; `continues` is the hash of the line it continues (null
 * for a first pass), for the asker to chain it only when that is still the
 * latest. What the child process runs (scripts/reverse-sweep-pass.ts), and
 * what runs here when no child is wanted.
 */
export async function reverseSweepPassFor(sandboxRoot: string, addition: { seq: number; hash: string; import: string }, budget: { maxBytes?: number; maxMs?: number }, entries?: readonly LedgerEntry[]): Promise<{ line: Omit<ImportSweepRecord, "prev" | "hash"> | null; continues: string | null; stats: ReverseSweepStats | null }> {
  const had = importSweepWhole(addition.hash, await readImportSweeps(sandboxRoot));
  if (had && !had.left_total) return { line: null, continues: had.latest.hash ?? null, stats: null };
  const P = await import("./protocol.ts");
  const all = entries ?? (await P.readLedger(sandboxRoot));
  // What the last pass left is what this one searches; what earlier passes could not read is named on every later line, until it is searched.
  let only: Set<string> | undefined;
  const carried: UnsearchedRow[] = [];
  if (had) {
    only = new Set();
    for await (const row of unsearchedRows(sandboxRoot, had.latest)) {
      if (UNSEARCHED_LEFT.has(row.code)) only.add(row.ref);
      else carried.push(row);
    }
  }
  const { line, stats } = await importSweepPass(sandboxRoot, addition, recordsStandingAt(all, addition.seq), { ...budget, ...(only ? { only, carried } : {}) });
  return { line: { ...line, ...(had ? { pass: had.passes.length + 1, continues: had.latest.hash } : {}) }, continues: had?.latest.hash ?? null, stats };
}

/** The reverse sweep passes this process asked for, by run (the last 50, oldest first): what each read, and in which process. */
const reversePassLog = new Map<string, ReverseSweepStats[]>();
export function reverseSweepPasses(sandboxRoot: string): ReverseSweepStats[] {
  return [...(reversePassLog.get(resolve(sandboxRoot)) ?? [])];
}

/**
 * A pass of a reverse sweep run off this process's loop: a child process
 * (scripts/reverse-sweep-pass.ts) that lists the store, reads what the last
 * pass left, searches, keeps its results and the long lists under
 * ledger/sweeps/, and answers with the line as it is written, for this
 * process to chain. A hub's loop otherwise held the listing of the whole
 * store (212,000 objects on the run D), the stream of what the last pass
 * left and the search of every object of the import. With
 * SWARM_SWEEP_INPROCESS=1 the pass runs here.
 */
async function execReverseSweepPass(sandboxRoot: string, addition: { seq: number; hash: string; import: string }, budget: { maxBytes?: number; maxMs?: number }): Promise<Awaited<ReturnType<typeof reverseSweepPassFor>>> {
  const request = JSON.stringify({ sandbox: resolve(sandboxRoot), addition, budget });
  return new Promise((done, fail) => {
    const child = spawn(process.execPath, ["--experimental-strip-types", "--no-warnings", fileURLToPath(new URL("../scripts/reverse-sweep-pass.ts", import.meta.url))], { stdio: ["pipe", "pipe", "pipe"], env: process.env });
    const out: Buffer[] = [];
    let err = "";
    child.stdout.on("data", (c: Buffer) => out.push(c));
    child.stderr.on("data", (c: Buffer) => {
      if (err.length < 4096) err += c.toString("utf8");
    });
    child.on("error", fail);
    child.on("close", (code, signal) => {
      if (code !== 0) return fail(new Error(`the reverse sweep's pass ended ${signal ? `on ${signal}` : `with status ${code}`}${err.trim() ? `: ${err.trim().slice(0, 1000)}` : ""}`));
      try {
        done(JSON.parse(Buffer.concat(out).toString("utf8")));
      } catch (e) {
        fail(e as Error);
      }
    });
    child.stdin.on("error", () => undefined);
    child.stdin.end(request);
  });
}

/**
 * Run one pass of an addition's reverse sweep and record it: the first
 * over every file of the import, a continuation over what the last pass
 * left, within `o`'s budget (the reverse sweep's own, reverseSweepBudget,
 * by default). A sweep with nothing left is not run again, and a pass
 * running in this process is not started twice. The search runs in a
 * process of its own (execReverseSweepPass) unless `inProcess` (a step
 * that is itself off every hub's loop, scripts/reverse-sweep.ts) or
 * SWARM_SWEEP_INPROCESS=1; this process only chains the line it answers,
 * under the sweeps' lock; a pass that finds another process recorded the
 * same step first keeps that one. The coverage records searched for are
 * those standing at the addition (recordsStandingAt): from `entries` in
 * this process, from the ledger in the child (an addition's standing
 * records are read by seqs alone, so both find the same). Returns the line
 * (this pass's, or the last one when nothing is left). Throws what went
 * wrong: the next round runs it again.
 */
export function startImportSweep(sandboxRoot: string, addition: { seq: number; hash: string; import: string }, entries: readonly LedgerEntry[], o: { maxBytes?: number; maxMs?: number; inProcess?: boolean } = {}): Promise<ImportSweepRecord> {
  const key = `${sandboxRoot}\u0000${addition.hash}`;
  const running = importInflight.get(key);
  if (running) return running;
  const p = (async (): Promise<ImportSweepRecord> => {
    const had = importSweepWhole(addition.hash, await readImportSweeps(sandboxRoot));
    if (had && !had.left_total) return had.latest;
    const budget = { ...reverseSweepBudget(), ...(o.maxBytes !== undefined ? { maxBytes: o.maxBytes } : {}), ...(o.maxMs !== undefined ? { maxMs: o.maxMs } : {}) };
    const here = o.inProcess || process.env.SWARM_SWEEP_INPROCESS === "1";
    const r = here ? await reverseSweepPassFor(sandboxRoot, addition, budget, entries) : await execReverseSweepPass(sandboxRoot, addition, budget);
    if (r.stats) {
      const log = reversePassLog.get(resolve(sandboxRoot)) ?? [];
      log.push(r.stats);
      reversePassLog.set(resolve(sandboxRoot), log.slice(-50));
    }
    let line: ImportSweepRecord | null = null;
    if (r.line) {
      // As this process holds it, made ready outside the lock: what it found read whole from its file, or its file written.
      const pass = r.line.hits_all ? await hydrateHits(sandboxRoot, r.line) : await boundHits(sandboxRoot, r.line);
      const written = await appendSweepLines<ImportSweepRecord>(sandboxRoot, (lines) => {
        const now = importSweepWhole(addition.hash, lines.filter((s): s is ImportSweepRecord => s.v === 2 && (s as ImportSweepRecord).of === "import"));
        // Another process recorded this step first: its line stands.
        if ((now?.latest.hash ?? null) !== r.continues) {
          line = now!.latest;
          return [];
        }
        return [pass];
      });
      line = written[0] ?? line;
    } else line = importSweepWhole(addition.hash, await readImportSweeps(sandboxRoot))?.latest ?? null;
    if (!line) throw new Error("the reverse sweep's pass was not recorded");
    const P = await import("./protocol.ts");
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
    if (!whole || whole.left_total) out.push({ seq: x.seq, hash, import: x.import });
  }
  return out;
}

/**
 * A round of the reverse sweeps: one pass of each addition's that is not
 * done, oldest first, each delivered on the board when it completes (its
 * hits, and what the next pass searches). Nothing once the run has ended.
 * Returns the passes it recorded.
 */
export async function reverseSweepRound(sandboxRoot: string, o: { maxBytes?: number; maxMs?: number; inProcess?: boolean } = {}): Promise<ImportSweepRecord[]> {
  const P = await import("./protocol.ts");
  if ((await P.runOutcome(sandboxRoot).catch(() => ({ outcome: null }))).outcome) return [];
  const entries = await P.readLedger(sandboxRoot).catch(() => [] as LedgerEntry[]);
  const out: ImportSweepRecord[] = [];
  for (const a of await pendingImportSweeps(sandboxRoot, entries)) {
    const before = importSweepWhole(a.hash, await readImportSweeps(sandboxRoot))?.latest.hash ?? null;
    const line = await startImportSweep(sandboxRoot, a, entries, { ...(o.maxBytes !== undefined ? { maxBytes: o.maxBytes } : {}), ...(o.maxMs !== undefined ? { maxMs: o.maxMs } : {}), ...(o.inProcess ? { inProcess: true } : {}) }).catch(() => null);
    if (!line || line.hash === before) continue;
    out.push(line);
    await P.systemPost(sandboxRoot, { tag: "ask", key: `reverse-sweep:${a.import}:${line.pass ?? 1}`, body: reverseSweepPostWords(line) }).catch(() => undefined);
  }
  return out;
}

/** A pass of the reverse sweep, as its board post says it: what it searched and found, and what the next pass searches. */
export function reverseSweepPostWords(line: ImportSweepRecord): string {
  const left = unsearchedLeft(line);
  const names = line.unsearched.filter((u) => u.left).map((u) => u.ref).slice(0, SWEEP_UNSEARCHED_SAMPLE);
  return [
    `REVERSE SWEEP of import:${line.import} (evidence added as E-${line.seq})${line.pass ? `, pass ${line.pass}` : ""}: ${importSweepWords(line)}.`,
    line.hits.length ? "A hit is a string a coverage record looked for, found in the new files: weigh it for its question, recording what the object shows with a delta; it holds nothing by itself." : "",
    left ? `The next pass searches the ${left} object(s) this one left (${names.join(", ")}${left > names.length ? `, and ${left - names.length} more` : ""}), at the hub's next round; its hits follow here.` : `The reverse sweep of import:${line.import} is complete.`,
  ].filter(Boolean).join(" ");
}

const backgroundRounds = new Map<string, Promise<ImportSweepRecord[]>>();
/** When this process last looked for coverage sweeps nobody is running, by run. */
const pendingLooked = new Map<string, number>();
/** The additions this process has found swept whole, by run: a round is not read again for them. */
const sweptWhole = new Map<string, Set<string>>();

/**
 * A round of the reverse sweeps started in this process's background, and
 * not awaited: none while one runs, none when every addition `imports`
 * names (the store journal's) is known swept whole here. awaitSweeps waits
 * for it. The coverage records' own sweeps that nobody is running are
 * started from here too (startPendingSweeps), so a sweep lost with a hub
 * is run within its orphan bound of the next hub's rounds, not at the
 * finish gate.
 */
export function reverseSweepInBackground(sandboxRoot: string, o: { maxBytes?: number; maxMs?: number; imports?: readonly string[] } = {}): Promise<ImportSweepRecord[]> {
  const S = resolve(sandboxRoot);
  // The hub's round is also where a coverage record's sweep that nobody is running is taken up (lost with a process, or left by a pass's budget): looked for at most once a minute, started and not waited for.
  if (Date.now() - (pendingLooked.get(S) ?? 0) >= 60_000) {
    pendingLooked.set(S, Date.now());
    void startPendingSweeps(S).catch(() => []);
  }
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
      // This step is a process of its own, off every hub's loop: its passes run in it.
      const recorded = await reverseSweepRound(sandboxRoot, { ...o, inProcess: true });
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
    if (hs.length) found.push(`${!q ? "no question named" : /^\d+$/.test(q) ? `Q-${q}` : q}: ${someWords(hs, SWEEP_WORDS_HITS, importHitWords, "more", s.hits_all?.file?.path)}`);
  }
  return clipWords([head, found.length ? `found: ${found.join(" | ")}` : "found none of them", unsearchedTotal(s) ? `not searched: ${unsearchedWords(s)}` : ""].filter(Boolean).join("; "), SWEEP_WORDS_MAX);
}
