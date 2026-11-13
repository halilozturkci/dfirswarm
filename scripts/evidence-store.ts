/**
 * The evidence-work store: what tool jobs produce, kept independent of where
 * they ran, and the journal that says how every object came to be.
 *
 *   <sandbox>/store/journal.jsonl         every evidence-work event, hash-chained
 *   <sandbox>.journal-anchor.json         the chain's head, out of every VM's reach
 *   <sandbox>/store/jobs/<id>/out/…       a job's committed outputs, read-only
 *   <sandbox>/store/jobs/<id>/manifest.json   every file: name bytes, size, sha256
 *   <sandbox>/store/jobs/<id>/manifest.head.json, manifest.index.tsv
 *                                         made from a large manifest, to find one file in it (manifest-index.ts)
 *   <sandbox>/store/jobs/<id>/.seal-out/  a seal's own record while it runs (sealDirOf)
 *   <sandbox>/store/blobs/<sha256>        each file's bytes once (hard links)
 *   <sandbox>/store/imports/<id>/…        a brain's own output a finding cited (tool:, trace:), sealed by
 *                                         an import job and published here with its trace provenance
 *   <sandbox>/catalog/gen/<gen>/          a recipe's committed result (a generation)
 *   <sandbox>/catalog/revisions/<n>/      the catalogue's index as of revision n
 *   <sandbox>.staging/<id>/               a running job's writable directory
 *
 * One writer at a time: the kickoff before the hub exists, the hub after.
 * Nothing here parses a forensic format: recipes and tools do that in their
 * VMs; this file moves, hashes, links and records.
 *
 *   node scripts/evidence-store.ts init <sandbox>      revision 0 from the census
 *   node scripts/evidence-store.ts verify <sandbox>    the journal against its anchor
 *   node scripts/evidence-store.ts note <sandbox> --by NAME --text TEXT [--job ID]...
 *                                                      an examiner's note on the record, after the run
 */
import { execFileSync } from "node:child_process";
import { createHash } from "node:crypto";
import { createReadStream, existsSync, readFileSync, realpathSync, type Stats } from "node:fs";
import { chmod, copyFile, link, lstat, mkdir, open, readdir, readFile, readlink, rename, rm, stat, truncate, unlink, writeFile } from "node:fs/promises";
import { availableParallelism } from "node:os";
import { basename, dirname, join, relative, resolve } from "node:path";
import { Worker } from "node:worker_threads";
import { buildIndex, INDEX_MIN_BYTES, manifestView, writeIndex, type IndexedFile, type ManifestView } from "./manifest-index.ts";
import { SEAL_RECORD_BYTES, type SealWorkerData, type SealWorkerDone, type SealWorkerTask } from "./seal-worker.ts";
import { jsonlLines, jsonlRecords } from "../extensions/jsonl-lines.ts";
import { fileURLToPath } from "node:url";

export const STORE_REL = "store";
export const JOURNAL_REL = "store/journal.jsonl";

export function storePaths(sandbox: string) {
  const S = resolve(sandbox);
  return {
    root: join(S, STORE_REL),
    journal: join(S, JOURNAL_REL),
    jobs: join(S, STORE_REL, "jobs"),
    blobs: join(S, STORE_REL, "blobs"),
    imports: join(S, STORE_REL, "imports"),
    anchor: `${S}.journal-anchor.json`,
    staging: `${S}.staging`,
    gen: join(S, "catalog", "gen"),
    revisions: join(S, "catalog", "revisions"),
  };
}

export function sha256Hex(data: Buffer | string): string {
  return createHash("sha256").update(data).digest("hex");
}

/** A file's sha256, read as a stream: never the whole file in memory. */
export async function sha256File(path: string | Buffer): Promise<string> {
  const h = createHash("sha256");
  await new Promise<void>((ok, fail) => {
    createReadStream(path).on("data", (c) => h.update(c)).on("end", () => ok()).on("error", fail);
  });
  return h.digest("hex");
}

/** A name for a reader: one line, nothing hidden; the bytes are kept beside it in base64. */
export function shownName(raw: Buffer): string {
  let text: string | null;
  try {
    text = new TextDecoder("utf-8", { fatal: true }).decode(raw);
  } catch {
    text = null;
  }
  if (text === null) {
    // Not UTF-8: printable ASCII as itself, every other byte as \xNN.
    let out = "";
    for (const b of raw) out += b === 0x5c ? "\\\\" : b >= 0x20 && b < 0x7f ? String.fromCharCode(b) : `\\x${b.toString(16).padStart(2, "0")}`;
    return out;
  }
  let out = "";
  for (const ch of text) {
    const c = ch.codePointAt(0) ?? 0;
    if (ch === "\\") out += "\\\\";
    else if (ch === "\t") out += "\\t";
    else if (ch === "\n") out += "\\n";
    else if (ch === "\r") out += "\\r";
    else if (c < 0x20 || c === 0x7f) out += `\\x${c.toString(16).padStart(2, "0")}`;
    else out += ch;
  }
  return out;
}

async function writeDurable(path: string, text: string, mode = 0o644): Promise<void> {
  const tmp = join(dirname(path), `.${basename(path)}.${process.pid}.${Math.random().toString(36).slice(2)}.tmp`);
  const fh = await open(tmp, "w", mode);
  try {
    await fh.writeFile(text, "utf8");
    await fh.sync();
  } finally {
    await fh.close();
  }
  await rename(tmp, path);
}

// --- the journal ---------------------------------------------------------------

export type JournalEvent = { type: string } & Record<string, unknown>;
export type JournalLine = JournalEvent & { v: 1; seq: number; at: string; prev: string | null };
export type Anchor = { head: string | null; seq: number; at: string };

/** Read a journal's text: the lines that chain, and where the chain first fails. */
export function verifyJournalText(text: string): { lines: JournalLine[]; goodBytes: number; head: string | null; hashes: string[]; error?: string } {
  const lines: JournalLine[] = [];
  const hashes: string[] = [];
  let prev: string | null = null;
  let offset = 0;
  const cut = (error: string) => ({ lines, goodBytes: Buffer.byteLength(text.slice(0, offset)), head: prev, hashes, error });
  while (offset < text.length) {
    const nl = text.indexOf("\n", offset);
    if (nl < 0) return cut(`line ${lines.length + 1} has no end (a write cut short)`);
    const raw = text.slice(offset, nl);
    let line: JournalLine;
    try {
      line = JSON.parse(raw) as JournalLine;
    } catch {
      return cut(`line ${lines.length + 1} is not JSON`);
    }
    if (line.prev !== prev) return cut(`line ${lines.length + 1} does not chain to the line before`);
    if (line.seq !== lines.length) return cut(`line ${lines.length + 1} has seq ${line.seq}`);
    lines.push(line);
    prev = sha256Hex(raw);
    hashes.push(prev);
    offset = nl + 1;
  }
  return { lines, goodBytes: Buffer.byteLength(text), head: prev, hashes };
}

export class Journal {
  readonly sandbox: string;
  readonly path: string;
  readonly anchorPath: string;
  lines: JournalLine[] = [];
  private head: string | null = null;
  private tail: Promise<unknown> = Promise.resolve();

  private constructor(sandbox: string) {
    this.sandbox = resolve(sandbox);
    this.path = storePaths(sandbox).journal;
    this.anchorPath = storePaths(sandbox).anchor;
  }

  /**
   * Open (or start) a run's journal. A last line cut short by a crash is kept
   * byte for byte in store/journal.torn-<n>.bin, the journal is cut back to
   * the last whole line and the repair is itself an event; an anchor that
   * disagrees with the journal is recorded, not fatal: custody reads both.
   */
  static async open(sandbox: string): Promise<Journal> {
    const j = new Journal(sandbox);
    await mkdir(dirname(j.path), { recursive: true });
    const text = existsSync(j.path) ? await readFile(j.path, "utf8") : "";
    const checked = verifyJournalText(text);
    j.lines = checked.lines;
    j.head = checked.head;
    // The anchor is compared with what the journal holds before anything
    // here writes: a disagreement is what custody has to read.
    const anchor = j.readAnchor();
    const mismatch = anchor && (anchor.head !== j.head || anchor.seq !== j.lines.length - 1);
    let repair: JournalEvent | null = null;
    if (checked.error) {
      const all = Buffer.from(text, "utf8");
      const dropped = all.subarray(checked.goodBytes);
      const saved = join(dirname(j.path), `journal.torn-${Date.now()}.bin`);
      await writeFile(saved, dropped);
      const fh = await open(j.path, "r+");
      try {
        await fh.truncate(checked.goodBytes);
        await fh.sync();
      } finally {
        await fh.close();
      }
      repair = { type: "journal_repaired", why: checked.error, kept_lines: checked.lines.length, dropped_bytes: dropped.length, dropped_sha256: sha256Hex(dropped), saved_as: relative(j.sandbox, saved) };
    }
    if (mismatch && anchor) {
      // A crash between a line's fsync and the anchor's move leaves the
      // anchor on the chain, behind it: that is recovery, not tampering.
      const onChain = anchor.seq >= 0 && anchor.seq < checked.hashes.length && checked.hashes[anchor.seq] === anchor.head;
      await j.append({ type: onChain ? "anchor_behind" : "anchor_mismatch", anchor_head: anchor.head, anchor_seq: anchor.seq, journal_head: checked.head, journal_seq: checked.lines.length - 1 });
    }
    if (repair) await j.append(repair);
    return j;
  }

  readAnchor(): Anchor | null {
    try {
      return JSON.parse(readFileSync(this.anchorPath, "utf8")) as Anchor;
    } catch {
      return null;
    }
  }

  get seq(): number {
    return this.lines.length - 1;
  }

  /** Append one event, durably: the line is on disk (fsync) before the anchor moves, and both before this resolves. */
  append(event: JournalEvent): Promise<JournalLine> {
    const next = this.tail.then(async () => {
      const line = { v: 1, seq: this.lines.length, at: new Date().toISOString(), ...event, prev: this.head } as JournalLine;
      const raw = JSON.stringify(line);
      const fh = await open(this.path, "a");
      try {
        await fh.write(`${raw}\n`);
        await fh.sync();
      } finally {
        await fh.close();
      }
      this.lines.push(line);
      this.head = sha256Hex(raw);
      maybeCrash(`journal:${event.type}`);
      await writeDurable(this.anchorPath, `${JSON.stringify({ head: this.head, seq: line.seq, at: line.at } satisfies Anchor)}\n`, 0o444).catch(async () => {
        // A read-only anchor from the last write: replace it.
        await chmod(this.anchorPath, 0o644).catch(() => undefined);
        await writeDurable(this.anchorPath, `${JSON.stringify({ head: this.head, seq: line.seq, at: line.at } satisfies Anchor)}\n`, 0o444);
      });
      return line;
    });
    this.tail = next.catch(() => undefined);
    return next;
  }

  of(type: string): JournalLine[] {
    return this.lines.filter((l) => l.type === type);
  }
}

/** Tests only: stop the process at a named step, as a crash would. */
export function maybeCrash(step: string): void {
  const at = process.env.SWARM_JOB_CRASH_AT;
  if (at && (at === step || (at.endsWith("*") && step.startsWith(at.slice(0, -1))))) {
    process.stderr.write(`crash injected at ${step}\n`);
    process.exit(99);
  }
}

// --- sealing a job's output ------------------------------------------------------

export type ManifestFile = { path: string; path_b64: string; bytes: number; sha256: string; mode: string };
export type ManifestRejected = { path: string; path_b64: string; kind: string; link_b64?: string; link?: string };
export type Manifest = {
  v: 1;
  job: string;
  attempt: number;
  sealed_at: string;
  files: ManifestFile[];
  dirs: Array<{ path: string; path_b64: string }>;
  rejected: ManifestRejected[];
  totals: { files: number; bytes: number };
  copied?: true;
};

type Walked = { rel: Buffer; kind: "file" | "dir" | "reject"; how?: string; link?: Buffer; bytes?: number; mode?: number };

function joinB(a: Buffer, b: Buffer): Buffer {
  return a.length ? Buffer.concat([a, Buffer.from("/"), b]) : b;
}

/** Every entry under `root`, by lstat, never following a link. */
async function walk(root: string): Promise<Walked[]> {
  const out: Walked[] = [];
  const rootB = Buffer.from(root);
  const visit = async (rel: Buffer) => {
    const here = rel.length ? Buffer.concat([rootB, Buffer.from("/"), rel]) : rootB;
    // A tool running as root in its VM can leave a directory mode 000:
    // the host owns it, so it is opened up rather than left unread.
    await chmod(here, 0o755).catch(() => undefined);
    let names: Buffer[];
    try {
      names = (await readdir(here, { encoding: "buffer" })).sort(Buffer.compare);
    } catch (err) {
      if (rel.length) out.push({ rel, kind: "reject", how: `unreadable directory (${(err as NodeJS.ErrnoException).code ?? "error"})` });
      else throw err;
      return;
    }
    // Each name's lstat, a few at a time; what they found is read in the names' order.
    const stats: Array<Stats | null> = [];
    for (let i = 0; i < names.length; i += 32) {
      stats.push(...(await Promise.all(names.slice(i, i + 32).map((name) => lstat(Buffer.concat([rootB, Buffer.from("/"), joinB(rel, name)])).catch(() => null)))));
    }
    for (let i = 0; i < names.length; i += 1) {
      const r = joinB(rel, names[i]);
      const full = Buffer.concat([rootB, Buffer.from("/"), r]);
      const st = stats[i];
      if (!st) {
        out.push({ rel: r, kind: "reject", how: "vanished while read" });
        continue;
      }
      if (st.isDirectory()) {
        out.push({ rel: r, kind: "dir" });
        await visit(r);
      } else if (st.isFile()) {
        out.push({ rel: r, kind: "file", bytes: st.size, mode: st.mode & 0o7777 });
      } else {
        const how = st.isSymbolicLink() ? "symlink" : st.isFIFO() ? "fifo" : st.isSocket() ? "socket" : st.isCharacterDevice() ? "char device" : st.isBlockDevice() ? "block device" : "other";
        out.push({ rel: r, kind: "reject", how, link: st.isSymbolicLink() ? await readlink(full, { encoding: "buffer" }) : undefined });
      }
    }
  };
  await visit(Buffer.alloc(0));
  return out;
}

async function copyTree(from: string, to: string, entries: Walked[]): Promise<void> {
  await mkdir(to, { recursive: true });
  for (const e of entries) {
    const src = Buffer.concat([Buffer.from(from), Buffer.from("/"), e.rel]);
    const dst = Buffer.concat([Buffer.from(to), Buffer.from("/"), e.rel]);
    if (e.kind === "dir") await mkdir(dst, { recursive: true });
    // copyFile, not a read into memory: a job's file may be larger than the hub's heap.
    else if (e.kind === "file") await copyFile(src, dst);
  }
}

/** How far a seal has got: what a job's status can show while its output is hashed. */
export type SealProgress = {
  job: string;
  /** walk: the tree is being listed; move: into the store; hash: files_done of files_total; manifest: written and indexed; done. */
  phase: "walk" | "move" | "hash" | "manifest" | "done";
  files_done: number;
  files_total: number;
  bytes_done: number;
  bytes_total: number;
  /** Files an earlier, interrupted seal had hashed: taken from its record, not hashed again (counted in files_done). */
  resumed_files: number;
  /** Worker threads hashing (0: in this thread, a small tree). */
  workers: number;
  started_at: string;
  at: string;
};

export type SealOptions = {
  /** Called at each phase and a few times a second while hashing. */
  onProgress?: (p: SealProgress) => void;
  /** Worker threads to hash in; 0 hashes in this thread, one file after another. Default: the processors less one, at most SEAL_WORKERS_MAX. */
  workers?: number;
};

export type Sealed = {
  manifest: Manifest;
  manifestSha256: string;
  /** What this seal did: files hashed now, files taken from an interrupted seal's record, threads, time. */
  seal: { files: number; hashed: number; resumed: number; workers: number; ms: number };
};

export const SEAL_WORKERS_MAX = 8;
/** A tree smaller than both is hashed where the seal runs: starting threads would take longer. */
export const SEAL_POOL_MIN_FILES = 256;
export const SEAL_POOL_MIN_BYTES = 64 * 1024 * 1024;
/** What one worker is handed at a time. */
const SEAL_BATCH_FILES = 64;
const SEAL_BATCH_BYTES = 32 * 1024 * 1024;

/**
 * Where a seal keeps its own record while it runs, beside the tree it seals
 * and gone when the manifest is written:
 *
 *   plan.json       the job, the attempt, a digest of the walk, what was left out (links, devices) before it was removed
 *   modes.bin       each file's mode as the job left it (u16le, in walk order): the seal makes files read-only as it goes
 *   w<k>.log        worker k's finished files (seal-worker.ts), what a seal that is run again does not hash again
 *   progress.json   SealProgress, rewritten about twice a second (readSealProgress)
 */
export function sealDirOf(dest: string): string {
  return join(dirname(dest), `.seal-${basename(dest)}`);
}

/** How far the seal of `dest` has got, from its record; null when none is running (or it runs in one thread: a small tree). */
export async function readSealProgress(dest: string): Promise<SealProgress | null> {
  try {
    return JSON.parse(await readFile(join(sealDirOf(dest), "progress.json"), "utf8")) as SealProgress;
  } catch {
    return null;
  }
}

type SealPlan = { v: 1; job: string; attempt: number; walk_sha256: string; files: number; bytes: number; copied: boolean; staging: string; moved: boolean; rejected: ManifestRejected[] };

/**
 * What a worker thread is started with: only the flags that say how a file
 * of this repository is loaded. A process started by a test runner or with
 * a string to run (node -e) carries flags a thread refuses, and they are
 * not handed on.
 */
const WORKER_ARGV = (() => {
  const out: string[] = [];
  const argv = process.execArgv;
  for (let i = 0; i < argv.length; i += 1) {
    const a = argv[i];
    if (/^--(experimental-strip-types|experimental-transform-types|no-warnings)$/.test(a)) out.push(a);
    else if (/^(--import|--loader|--experimental-loader|--conditions|-C|-r|--require)$/.test(a) && i + 1 < argv.length) out.push(a, argv[(i += 1)]);
    else if (/^--(import|loader|experimental-loader|conditions|require)=/.test(a)) out.push(a);
  }
  return out;
})();

const breathe = () => new Promise<void>((ok) => setImmediate(ok));

/** What a walk found, as one digest: the names, kinds and sizes a seal run again must find the same. */
async function walkDigest(kept: Walked[]): Promise<string> {
  const h = createHash("sha256");
  for (let i = 0; i < kept.length; i += 1) {
    const e = kept[i];
    h.update(e.kind === "dir" ? "d" : "f");
    h.update(e.rel);
    h.update(`\0${e.kind === "file" ? e.bytes : ""}\n`);
    if (i % 4096 === 4095) await breathe();
  }
  return h.digest("hex");
}

async function readPlan(dir: string, job: string, attempt: number): Promise<SealPlan | null> {
  try {
    const p = JSON.parse(await readFile(join(dir, "plan.json"), "utf8")) as SealPlan;
    return p && p.v === 1 && p.job === job && p.attempt === attempt && Array.isArray(p.rejected) ? p : null;
  } catch {
    return null;
  }
}

async function writePlan(dir: string, plan: SealPlan, kept: Walked[] | null): Promise<void> {
  await mkdir(dir, { recursive: true });
  if (kept) {
    const files = kept.filter((x) => x.kind === "file");
    const modes = Buffer.alloc(files.length * 2);
    for (let i = 0; i < files.length; i += 1) modes.writeUInt16LE((files[i].mode ?? 0o644) & 0xffff, i * 2);
    await writeFile(join(dir, "modes.bin"), modes);
  }
  // Renamed into place: a plan is whole or it is not there.
  const tmp = join(dir, `.plan.${process.pid}.tmp`);
  await writeFile(tmp, `${JSON.stringify(plan)}\n`);
  await rename(tmp, join(dir, "plan.json"));
}

async function readModes(dir: string, files: number): Promise<Buffer | null> {
  const b = await readFile(join(dir, "modes.bin")).catch(() => null);
  return b && b.length === files * 2 ? b : null;
}

function rejectedOf(e: Walked): ManifestRejected {
  return { path: shownName(e.rel), path_b64: e.rel.toString("base64"), kind: e.how ?? "other", ...(e.link ? { link_b64: e.link.toString("base64"), link: shownName(e.link) } : {}) };
}

/** What an interrupted seal left out and removed, then what this walk found: each name once. */
function mergeRejected(before: ManifestRejected[], now: ManifestRejected[]): ManifestRejected[] {
  const seen = new Set(before.map((r) => r.path_b64));
  return [...before, ...now.filter((r) => !seen.has(r.path_b64))];
}

async function removeRejected(root: string, entries: Walked[]): Promise<void> {
  for (const e of entries) {
    if (e.kind !== "reject") continue;
    const p = Buffer.concat([Buffer.from(root), Buffer.from("/"), e.rel]);
    if (e.how?.startsWith("unreadable directory")) await rm(p, { recursive: true, force: true }).catch(() => undefined);
    else await unlink(p).catch(() => undefined);
  }
}

/** A manifest written as JSON.stringify writes it, a piece at a time: a tree of 200,000 files is over 100 MB of it. */
async function writeManifest(path: string, manifest: Manifest): Promise<string> {
  const h = createHash("sha256");
  const tmp = join(dirname(path), `.${basename(path)}.${process.pid}.${Math.random().toString(36).slice(2)}.tmp`);
  const fh = await open(tmp, "w", 0o444);
  try {
    let part = "";
    const flush = async () => {
      if (!part) return;
      h.update(part, "utf8");
      await fh.write(part, null, "utf8");
      part = "";
    };
    let first = true;
    for (const [key, value] of Object.entries(manifest)) {
      if (value === undefined) continue;
      part += `${first ? "{" : ","}${JSON.stringify(key)}:`;
      first = false;
      if (Array.isArray(value)) {
        part += "[";
        for (let i = 0; i < value.length; i += 1) {
          part += (i ? "," : "") + JSON.stringify(value[i]);
          if (part.length >= 1 << 20) await flush();
        }
        part += "]";
      } else part += JSON.stringify(value);
    }
    part += `${first ? "{" : ""}}\n`;
    await flush();
    await fh.sync();
  } finally {
    await fh.close();
  }
  await rename(tmp, path);
  return h.digest("hex");
}

/** Make a large manifest's head and index in a thread of its own (seal-worker.ts). */
function indexInWorker(manifestPath: string): Promise<void> {
  return new Promise<void>((ok, fail) => {
    const w = new Worker(new URL("./seal-worker.ts", import.meta.url), { execArgv: WORKER_ARGV, workerData: { seal_worker: true, blobs: "", log: "", tmp: join(dirname(manifestPath), `.index-${process.pid}.tmp`) } satisfies SealWorkerData });
    const end = (err?: Error) => {
      void w.terminate();
      if (err) fail(err);
      else ok();
    };
    w.once("message", (m: SealWorkerDone) => end(m.error ? new Error(m.error) : undefined));
    w.once("error", end);
    w.once("exit", () => end(new Error("the index worker stopped")));
    w.postMessage({ op: "index", id: 0, manifestPath } satisfies SealWorkerTask);
  });
}

/**
 * Hash, link and record a tree that is in the store already: the part of a
 * seal after the move, and all of one that is run again. `plan` and the
 * modes are on disk in sealDirOf(dest); what the worker logs there say was
 * hashed by an interrupted seal is not hashed again.
 */
async function sealMoved(sandbox: string, dest: string, kept: Walked[], plan: SealPlan, modes: Buffer, manifestPath: string, opts: SealOptions, progress: SealProgress, started: number): Promise<Sealed> {
  const P = storePaths(sandbox);
  const dir = sealDirOf(dest);
  await mkdir(P.blobs, { recursive: true });
  const fileEntries = kept.filter((x) => x.kind === "file");
  const N = fileEntries.length;
  const shaOf: Array<string | null> = new Array<string | null>(N).fill(null);
  const sizeOf = new Float64Array(N);
  const failed = new Map<number, string>();
  const done = new Uint8Array(N);
  // What an interrupted seal finished: a record whose place and size are a file of this walk.
  let resumed = 0;
  let resumedBytes = 0;
  for (const name of (await readdir(dir).catch(() => [] as string[])).filter((n) => /^w\d+\.log$/.test(n)).sort()) {
    const log = join(dir, name);
    const b = await readFile(log).catch(() => Buffer.alloc(0));
    const whole = Math.floor(b.length / SEAL_RECORD_BYTES);
    for (let i = 0; i < whole; i += 1) {
      const at = i * SEAL_RECORD_BYTES;
      const ord = b.readUInt32LE(at);
      const size = b.readDoubleLE(at + 4);
      if (ord >= N || done[ord] || fileEntries[ord].bytes !== size) continue;
      done[ord] = 1;
      shaOf[ord] = b.toString("hex", at + 12, at + 44);
      sizeOf[ord] = size;
      resumed += 1;
      resumedBytes += size;
    }
    // A record cut short by the kill: the next one must start on a boundary.
    if (b.length % SEAL_RECORD_BYTES) await truncate(log, whole * SEAL_RECORD_BYTES).catch(() => undefined);
  }
  const pending: number[] = [];
  let pendingBytes = 0;
  for (let ord = 0; ord < N; ord += 1) {
    if (done[ord]) continue;
    pending.push(ord);
    pendingBytes += fileEntries[ord].bytes ?? 0;
  }
  const want = opts.workers ?? Math.min(SEAL_WORKERS_MAX, Math.max(1, availableParallelism() - 1));
  let width = want > 0 && (pending.length >= SEAL_POOL_MIN_FILES || pendingBytes >= SEAL_POOL_MIN_BYTES) ? Math.max(1, Math.min(Math.floor(want), Math.ceil(pending.length / SEAL_BATCH_FILES))) : 0;
  // Where a thread cannot be started the files are hashed here: a seal does not fail for the want of one.
  let workers: Worker[] = [];
  try {
    for (let k = 0; k < width; k += 1) workers.push(new Worker(new URL("./seal-worker.ts", import.meta.url), { execArgv: WORKER_ARGV, workerData: { seal_worker: true, blobs: P.blobs, log: join(dir, `w${k}.log`), tmp: join(dir, `t${k}`) } satisfies SealWorkerData }));
  } catch {
    await Promise.all(workers.map((w) => w.terminate()));
    workers = [];
    width = 0;
  }
  Object.assign(progress, { phase: "hash", files_total: N, bytes_total: plan.bytes, files_done: resumed, bytes_done: resumedBytes, resumed_files: resumed, workers: width });
  // The readable record of how far it is: one write at a time, the last one awaited before the directory goes.
  let lastTold = 0;
  let writing: Promise<void> | null = null;
  const tell = (force = false) => {
    const now = Date.now();
    if (!force && now - lastTold < 200) return;
    lastTold = now;
    progress.at = new Date(now).toISOString();
    opts.onProgress?.({ ...progress });
    if (width && !writing) {
      const tmp = join(dir, ".progress.tmp");
      writing = writeFile(tmp, `${JSON.stringify(progress)}\n`)
        .then(() => rename(tmp, join(dir, "progress.json")))
        .catch(() => undefined)
        .finally(() => {
          writing = null;
        });
    }
  };
  tell(true);
  const full = (ord: number) => Buffer.concat([Buffer.from(dest), Buffer.from("/"), fileEntries[ord].rel]);
  /** One file after another, in this thread: a small tree, or what the threads left when one of them failed. */
  const inThread = async (list: number[]) => {
    const tmp = join(dir, "t-main");
    for (const ord of list) {
      const p = full(ord);
      await chmod(p, 0o644).catch(() => undefined);
      let sha: string;
      try {
        sha = await sha256File(p);
      } catch (err) {
        failed.set(ord, (err as NodeJS.ErrnoException).code ?? "error");
        continue;
      }
      const st = await stat(p);
      await chmod(p, 0o444);
      const blob = join(P.blobs, sha);
      try {
        await link(p, blob);
      } catch (err) {
        if ((err as NodeJS.ErrnoException).code === "EEXIST") {
          // The same bytes are already kept (by an earlier file, or by another seal a moment ago):
          // this occurrence becomes a link to them, put in place by a rename so the name is never missing.
          try {
            const keptBlob = await stat(blob);
            if (keptBlob.size === st.size && keptBlob.ino !== st.ino) {
              await unlink(tmp).catch(() => undefined);
              await link(blob, tmp);
              await rename(tmp, p);
            }
          } catch {
            // A blob with no room for another link: the occurrence stays its own copy.
            await unlink(tmp).catch(() => undefined);
          }
        }
        // A file system without hard links keeps the occurrence as its own copy.
      }
      shaOf[ord] = sha;
      sizeOf[ord] = st.size;
      progress.files_done += 1;
      progress.bytes_done += st.size;
      tell();
    }
  };
  if (width === 0) await inThread(pending);
  else {
    let cursor = 0;
    let batches = 0;
    const next = (): SealWorkerTask | null => {
      if (cursor >= pending.length) return null;
      const rels: string[] = [];
      const ords: number[] = [];
      for (let bytes = 0; cursor < pending.length && rels.length < SEAL_BATCH_FILES && (bytes < SEAL_BATCH_BYTES || !rels.length); cursor += 1) {
        const ord = pending[cursor];
        rels.push(fileEntries[ord].rel.toString("latin1"));
        ords.push(ord);
        bytes += fileEntries[ord].bytes ?? 0;
      }
      batches += 1;
      return { op: "hash", id: batches, root: dest, rels, ords };
    };
    let over = false;
    let broken = false;
    // Tests only: SWARM_JOB_CRASH_AT=seal:hashed:<n> stops the process once n files are hashed.
    const crashAt = Number(/^seal:hashed:(\d+)$/.exec(process.env.SWARM_JOB_CRASH_AT ?? "")?.[1] ?? 0);
    try {
      await new Promise<void>((ok, fail) => {
        let active = 0;
        const give = (w: Worker) => {
          const task = next();
          if (!task) {
            if (!active) ok();
            return;
          }
          active += 1;
          w.postMessage(task);
        };
        for (const w of workers) {
          w.on("message", (m: SealWorkerDone) => {
            if (m.error || !m.done) return fail(new Error(`the seal of ${dest} failed: ${m.error ?? "a worker answered nothing"}`));
            for (const [ord, sha, x] of m.done) {
              if (sha === null) failed.set(ord, String(x));
              else {
                shaOf[ord] = sha;
                sizeOf[ord] = Number(x);
                progress.bytes_done += Number(x);
              }
              progress.files_done += 1;
            }
            active -= 1;
            tell();
            if (crashAt && progress.files_done >= crashAt) maybeCrash(`seal:hashed:${crashAt}`);
            give(w);
          });
          w.on("error", (err) => fail(new Error(`the seal of ${dest} failed: ${err.message}`)));
          w.on("exit", (code) => {
            if (!over) fail(new Error(`the seal of ${dest} failed: a worker stopped (exit ${code})`));
          });
          give(w);
        }
      });
    } catch {
      // A thread failed (it could not load, or it died): what the threads did not finish is hashed here,
      // and an error that is the tree's own is met again, and thrown, there.
      broken = true;
    } finally {
      over = true;
      await Promise.all(workers.map((w) => w.terminate()));
    }
    if (broken) await inThread(pending.filter((ord) => shaOf[ord] === null && !failed.has(ord)));
  }
  // The manifest's lists, in the order the tree was walked.
  const files: ManifestFile[] = [];
  const dirs: Array<{ path: string; path_b64: string }> = [];
  const rejected = [...plan.rejected];
  let total = 0;
  let ord = 0;
  for (let i = 0; i < kept.length; i += 1) {
    const e = kept[i];
    if (i % 2048 === 2047) await breathe();
    if (e.kind === "dir") {
      dirs.push({ path: shownName(e.rel), path_b64: e.rel.toString("base64") });
      continue;
    }
    const at = ord;
    ord += 1;
    const sha = shaOf[at];
    if (sha === null) {
      rejected.push({ path: shownName(e.rel), path_b64: e.rel.toString("base64"), kind: `unreadable file (${failed.get(at) ?? "error"})` });
      continue;
    }
    files.push({ path: shownName(e.rel), path_b64: e.rel.toString("base64"), bytes: sizeOf[at], sha256: sha, mode: modes.readUInt16LE(at * 2).toString(8) });
    total += sizeOf[at];
  }
  progress.phase = "manifest";
  tell(true);
  // Directories read-only from the deepest up.
  for (const e of [...kept].filter((x) => x.kind === "dir").reverse()) {
    await chmod(Buffer.concat([Buffer.from(dest), Buffer.from("/"), e.rel]), 0o555).catch(() => undefined);
  }
  await chmod(dest, 0o555);
  const manifest: Manifest = {
    v: 1,
    job: plan.job,
    attempt: plan.attempt,
    sealed_at: new Date().toISOString(),
    files,
    dirs,
    rejected,
    totals: { files: files.length, bytes: total },
    ...(plan.copied ? { copied: true as const } : {}),
  };
  // Compact, and written a piece at a time: the same bytes JSON.stringify gives.
  const manifestSha256 = await writeManifest(manifestPath, manifest);
  // Its head and index (manifest-index.ts), where it is large enough to have them: made from the manifest,
  // and made again by whoever finds them missing.
  try {
    const st = await stat(manifestPath);
    if (st.size >= INDEX_MIN_BYTES) {
      if (width) await indexInWorker(manifestPath);
      else await writeIndex(manifestPath, buildIndex(manifest, { sha256: manifestSha256, bytes: st.size, mtime_ms: st.mtimeMs }));
    }
  } catch {
    // made when first asked for
  }
  if (plan.copied && plan.staging) await rm(plan.staging, { recursive: true, force: true }).catch(() => undefined);
  if (writing) await writing;
  await rm(dir, { recursive: true, force: true }).catch(() => undefined);
  progress.phase = "done";
  progress.at = new Date().toISOString();
  opts.onProgress?.({ ...progress });
  return { manifest, manifestSha256, seal: { files: N, hashed: pending.length, resumed, workers: width, ms: Date.now() - started } };
}

function sealProgress(job: string): SealProgress {
  const at = new Date().toISOString();
  return { job, phase: "walk", files_done: 0, files_total: 0, bytes_done: 0, bytes_total: 0, resumed_files: 0, workers: 0, started_at: at, at };
}

/**
 * Seal a fenced job's staging directory into the store: links, devices,
 * FIFOs and sockets are recorded and left out (never followed); the tree is
 * moved (renamed, or copied when staging is on another file system) to
 * `dest`, every file hashed there — after its producer is gone, never live —
 * made read-only, and hard-linked to store/blobs/<sha256> so the same bytes
 * are kept once however many jobs produce them. The manifest names every
 * file by its exact bytes and a readable form, in the order the tree was
 * walked, whatever order the files were hashed in.
 *
 * A tree of any size is hashed in worker threads (seal-worker.ts), so the
 * process that seals keeps answering; a seal that is killed leaves its
 * record beside the tree (sealDirOf), and `resealMoved` goes on from it.
 */
export async function sealTree(sandbox: string, staging: string, dest: string, job: string, attempt: number, manifestPath = join(dirname(dest), "manifest.json"), opts: SealOptions = {}): Promise<Sealed> {
  const started = Date.now();
  const rootSt = await lstat(staging).catch(() => null);
  if (!rootSt || !rootSt.isDirectory()) throw new Error(`the staging directory ${staging} is not a directory`);
  const progress = sealProgress(job);
  opts.onProgress?.({ ...progress });
  const entries = await walk(staging);
  await mkdir(dirname(dest), { recursive: true });
  if (existsSync(dest)) throw new Error(`${dest} exists already`);
  const kept = entries.filter((x) => x.kind !== "reject");
  const files = kept.filter((x) => x.kind === "file");
  const dir = sealDirOf(dest);
  const walked = await walkDigest(kept);
  // A seal of this tree that stopped before the move: what it left out is in its plan, and gone from the tree.
  let before = await readPlan(dir, job, attempt);
  if (before && (before.walk_sha256 !== walked || !(await readModes(dir, files.length)))) before = null;
  if (!before) await rm(dir, { recursive: true, force: true });
  const copied = (await stat(staging)).dev !== (await stat(dirname(dest))).dev;
  const plan: SealPlan = { v: 1, job, attempt, walk_sha256: walked, files: files.length, bytes: files.reduce((a, e) => a + (e.bytes ?? 0), 0), copied, staging: resolve(staging), moved: false, rejected: mergeRejected(before?.rejected ?? [], entries.filter((x) => x.kind === "reject").map(rejectedOf)) };
  // The plan first: what is removed next is on record before it is gone.
  await writePlan(dir, plan, before ? null : kept);
  await removeRejected(staging, entries);
  Object.assign(progress, { phase: "move", files_total: plan.files, bytes_total: plan.bytes });
  opts.onProgress?.({ ...progress });
  if (copied) await copyTree(staging, dest, kept);
  else await rename(staging, dest);
  plan.moved = true;
  await writePlan(dir, plan, null);
  maybeCrash("seal:moved");
  const modes = (await readModes(dir, files.length)) ?? Buffer.alloc(files.length * 2);
  return sealMoved(sandbox, dest, kept, plan, modes, manifestPath, opts, progress, started);
}

/**
 * A tree already moved into the store (a crash after the move): seal it
 * where it stands. With the interrupted seal's record beside it, only the
 * files that seal had not finished are hashed, and the manifest is the one
 * it would have written; without one (a seal from before the record
 * existed) every file is hashed, and a file's mode is what it has now.
 */
export async function resealMoved(sandbox: string, dest: string, job: string, attempt: number, manifestPath = join(dirname(dest), "manifest.json"), opts: SealOptions = {}): Promise<Sealed> {
  const started = Date.now();
  const dir = sealDirOf(dest);
  const before = await readPlan(dir, job, attempt);
  if (before && before.copied && !before.moved && before.staging && existsSync(before.staging)) {
    // A copy cut short: the store holds part of the tree, and the whole of it is still where it was.
    await rm(dest, { recursive: true, force: true });
    return sealTree(sandbox, before.staging, dest, job, attempt, manifestPath, opts);
  }
  const progress = sealProgress(job);
  opts.onProgress?.({ ...progress });
  // The walk opens every directory up again; the files are opened up as they are hashed.
  const entries = await walk(dest);
  await removeRejected(dest, entries);
  const kept = entries.filter((x) => x.kind !== "reject");
  const files = kept.filter((x) => x.kind === "file");
  const walked = await walkDigest(kept);
  const found = entries.filter((x) => x.kind === "reject").map(rejectedOf);
  let plan: SealPlan;
  let modes = before && before.walk_sha256 === walked ? await readModes(dir, files.length) : null;
  if (before && modes) {
    plan = { ...before, moved: true, rejected: mergeRejected(before.rejected, found) };
    await writePlan(dir, plan, null);
  } else {
    // Nothing to go on from: every file again, the modes as they are now.
    const keep = before ? { rejected: before.rejected, copied: before.copied, staging: before.staging } : { rejected: [], copied: false, staging: "" };
    await rm(dir, { recursive: true, force: true });
    plan = { v: 1, job, attempt, walk_sha256: walked, files: files.length, bytes: files.reduce((a, e) => a + (e.bytes ?? 0), 0), copied: keep.copied, staging: keep.staging, moved: true, rejected: mergeRejected(keep.rejected, found) };
    await writePlan(dir, plan, kept);
    modes = (await readModes(dir, files.length)) ?? Buffer.alloc(files.length * 2);
  }
  return sealMoved(sandbox, dest, kept, plan, modes, manifestPath, opts, progress, started);
}

export async function readManifest(path: string): Promise<{ manifest: Manifest; sha256: string } | null> {
  try {
    const text = await readFile(path, "utf8");
    return { manifest: JSON.parse(text) as Manifest, sha256: sha256Hex(text) };
  } catch {
    return null;
  }
}

/**
 * A sealed manifest asked a file or a directory at a time, from its head
 * and index (manifest-index.ts) and never the manifest whole: what a ref, a
 * declared input and a job's status need. What verifies a store reads the
 * manifest itself (`readManifest`).
 */
export function manifestOf(manifestPath: string): Promise<ManifestView | null> {
  return manifestView(manifestPath, indexInWorker);
}

/**
 * The file of a sealed manifest a name names: its shown path, or its name's
 * bytes read as UTF-8 (the two differ where a name holds a backslash or a
 * control character); the earliest in the manifest when several do.
 */
export async function manifestFile(manifestPath: string, view: ManifestView, names: readonly string[]): Promise<IndexedFile | null> {
  const hit = await view.file(names.flatMap((w) => [w, shownName(Buffer.from(w, "utf8"))]));
  if (hit || !view.head.odd_names || !names.some((w) => w.includes("�"))) return hit;
  // A name that is not UTF-8, cited as UTF-8 reads it: only the manifest holds its bytes.
  const whole = await readManifest(manifestPath);
  const n = whole ? whole.manifest.files.findIndex((x) => names.some((w) => x.path === w || Buffer.from(x.path_b64, "base64").toString("utf8") === w)) : -1;
  return whole && n >= 0 ? { ...whole.manifest.files[n], n } : null;
}

/**
 * The files of a sealed manifest whose names are nearest to one that is not
 * in it: those with the same last name anywhere in the tree and those in the
 * same directory, by edit distance. Read from the index as a stream.
 */
export async function manifestNearNames(manifestPath: string, want: string, n = 5): Promise<string[]> {
  const view = await manifestOf(manifestPath);
  if (!view) return [];
  const base = (x: string) => x.slice(x.lastIndexOf("/") + 1).toLowerCase();
  const wantBase = base(want);
  const wantDir = want.includes("/") ? want.slice(0, want.lastIndexOf("/") + 1).toLowerCase() : "";
  const same: string[] = [];
  const beside: string[] = [];
  for await (const rows of view.files()) for (const f of rows) {
    const b = base(f.path);
    if (b === wantBase) {
      if (same.length < 200) same.push(f.path);
    } else if (beside.length < 500 && f.path.length - b.length === wantDir.length && f.path.slice(0, wantDir.length).toLowerCase() === wantDir) beside.push(f.path);
  }
  const dist = (a: string, b: string) => {
    a = a.slice(-200);
    b = b.slice(-200);
    let row = Array.from({ length: b.length + 1 }, (_, i) => i);
    for (let i = 1; i <= a.length; i += 1) {
      const next = [i];
      for (let j = 1; j <= b.length; j += 1) next.push(Math.min(row[j] + 1, next[j - 1] + 1, row[j - 1] + (a[i - 1] === b[j - 1] ? 0 : 1)));
      row = next;
    }
    return row[b.length];
  };
  const w = want.toLowerCase();
  return [...same.map((x) => ({ x, d: dist(x.toLowerCase(), w) })), ...beside.map((x) => ({ x, d: 1000 + dist(x.toLowerCase(), w) }))]
    .sort((a, b) => a.d - b.d)
    .slice(0, n)
    .map((r) => r.x);
}

// --- object references -------------------------------------------------------------

export type Resolved =
  | {
      ok: true;
      ref: string;
      kind: "input" | "job" | "import" | "member" | "sha256" | "unresolved" | "tool" | "trace" | "net";
      sha256?: string;
      bytes?: number;
      path?: string;
      why?: string;
      status?: string;
      /** tool: and trace: once sealed: the import the record cites, and the trace line it was sealed against. */
      import_ref?: string;
      trace_line?: string;
    }
  | { ok: false; ref: string; reason: string };

/** What resolveRef may check besides existence: the bytes, against what was sealed. */
export type ResolveOptions = { verify?: boolean; committedLogs?: Map<string, Record<string, string>> };

/** Each committed job's log hashes, from its job_committed line. */
export async function committedLogHashes(sandbox: string): Promise<Map<string, Record<string, string>>> {
  const out = new Map<string, Record<string, string>>();
  const text = await readFile(storePaths(resolve(sandbox)).journal, "utf8").catch(() => "");
  for (const line of text.split("\n")) {
    if (!line.includes('"job_committed"')) continue;
    try {
      const l = JSON.parse(line) as { type?: string; job?: string; logs?: Record<string, string> };
      if (l.type === "job_committed" && l.job && l.logs) out.set(l.job, l.logs);
    } catch {
      // a torn line is the journal check's to name
    }
  }
  return out;
}

async function jobStatus(dir: string): Promise<string | undefined> {
  try {
    return (JSON.parse(await readFile(join(dir, "job.json"), "utf8")) as { status?: string }).status;
  } catch {
    return undefined;
  }
}

/**
 * What an object reference names, checked against the run's records:
 * `input:<path under inputs/>` (inputs.json), `job:<id>/<path>` and
 * `import:<id>/<path>` (their sealed manifests), `member:<generation>#<n>`
 * (a generation's member list), `sha256:<hex>` (the store or the inputs),
 * `unresolved:<why>` (said, not resolved), and a brain's own output:
 * `tool:<seat>/<file>` (a whole output the harness kept under
 * tool-output/<seat>/, by the trace line that recorded it) and
 * `trace:<sha256>` (one line of the trace, by its hash). Those two resolve
 * once sealed (the hub seals them when a record cites them; see
 * traceOrigin): to the import they were sealed as. `net:<k>/<n>[/<file>]` is
 * a capture the fetch service sealed (docs/adr/0012): external material,
 * by its own manifest.
 */
export async function resolveRef(sandbox: string, ref: string, opts: ResolveOptions = {}): Promise<Resolved> {
  const S = resolve(sandbox);
  const P = storePaths(S);
  const m = /^([a-z0-9]+):(.*)$/s.exec(ref.trim());
  if (!m) return { ok: false, ref, reason: "a reference is kind:value (input:, job:, import:, member:, sha256:, net:, tool:, trace:, unresolved:)" };
  const [, kind, value] = m;
  if (kind === "tool" || kind === "trace") {
    const sealed = await sealedBrainOutput(S, ref.trim());
    if (sealed) {
      const imp = await resolveRef(S, sealed.import, opts);
      return imp.ok ? { ...imp, ref, kind, import_ref: sealed.import, trace_line: sealed.trace_line } : { ok: false, ref, reason: `${ref} was sealed as ${sealed.import}, which does not resolve: ${imp.reason}` };
    }
    const origin = await traceOrigin(S, ref.trim());
    if (!origin.ok) return { ok: false, ref, reason: origin.reason };
    return { ok: false, ref, reason: `${ref} is on the trace (line ${origin.origin.line_sha256.slice(0, 12)}…) and not sealed: the hub seals it as an import when a record in a run with tool jobs cites it; where no job service runs, run the work again as a job and cite job:<id>/<path>` };
  }
  if (kind === "unresolved") {
    return value.trim() ? { ok: true, ref, kind: "unresolved", why: value.trim() } : { ok: false, ref, reason: "unresolved: needs the why" };
  }
  if (kind === "input") {
    try {
      const inputs = JSON.parse(await readFile(join(S, "inputs.json"), "utf8")) as { files?: Array<{ path: string; sha256?: string; bytes?: number }> };
      const want = value.startsWith("inputs/") ? value : `inputs/${value}`;
      const f = (inputs.files ?? []).find((x) => x.path === want);
      return f ? { ok: true, ref, kind: "input", sha256: f.sha256, bytes: f.bytes, path: f.path } : { ok: false, ref, reason: `${want} is not in inputs.json` };
    } catch {
      return { ok: false, ref, reason: "inputs.json cannot be read" };
    }
  }
  if (kind === "job" || kind === "import") {
    const slash = value.indexOf("/");
    const id = slash < 0 ? value : value.slice(0, slash);
    const rel = slash < 0 ? "" : value.slice(slash + 1);
    if (!/^[a-z0-9-]{1,64}$/.test(id)) return { ok: false, ref, reason: `${id} is not a ${kind} id` };
    // Asked of the manifest's head and index: a manifest of 200,000 files is not read for one of them.
    const manifestPath = join(kind === "job" ? P.jobs : P.imports, id, "manifest.json");
    const found = await manifestOf(manifestPath);
    if (!found) {
      // A job that ran and waits for its seal is not a job that left nothing: say which, so the seat waits instead of re-running it.
      const state = kind === "job" ? await readFile(join(P.jobs, id, "job.json"), "utf8").then((t) => String((JSON.parse(t) as { state?: unknown }).state ?? "")).catch(() => "") : "";
      const waits = state === "finished" || state === "fenced" ? `: it has finished and its output is waiting to be sealed into the store (state ${state}); cite it again after its result post` : state === "running" || state === "accepted" ? `: it has not finished (state ${state})` : "";
      return { ok: false, ref, reason: `${kind} ${id} has no sealed manifest${waits}` };
    }
    const base = `${kind === "job" ? "store/jobs" : "store/imports"}/${id}`;
    // A job's own outcome travels with what it left: a failed job's kept output is citable, and said to be.
    const status = kind === "job" ? await jobStatus(join(P.jobs, id)) : undefined;
    const st0 = status ? { status } : {};
    if (!rel) return { ok: true, ref, kind, path: `${base}/out`, bytes: found.head.totals.bytes, ...st0 };
    // A job's logs are sealed beside its output (their sha256 in its
    // job_committed line): stdout.log, stderr.log and pip's lists.
    if (kind === "job" && /^(stdout\.log|stderr\.log|pip-before\.txt|pip-after\.txt)$/.test(rel)) {
      const abs = join(P.jobs, id, rel);
      const st = await lstat(abs).catch(() => null);
      if (!st?.isFile()) return { ok: false, ref, reason: `job ${id} has no ${rel}` };
      const sha = await sha256File(abs);
      if (opts.verify) {
        const sealed = (opts.committedLogs ?? (await committedLogHashes(S))).get(id)?.[rel];
        if (sealed && sealed !== sha) return { ok: false, ref, reason: `job ${id}'s ${rel} changed since it was sealed (${sha.slice(0, 12)}…, sealed ${sealed.slice(0, 12)}…)` };
      }
      return { ok: true, ref, kind, sha256: sha, bytes: st.size, path: `${base}/${rel}`, ...st0 };
    }
    // The path as the store shows it (out/…) is the same file.
    const want = rel.startsWith("out/") ? [rel, rel.slice(4)] : [rel];
    const f = await manifestFile(manifestPath, found, want);
    return f ? { ok: true, ref, kind, sha256: f.sha256, bytes: f.bytes, path: `${base}/out/${f.path}`, ...st0 } : { ok: false, ref, reason: `${rel} is not in ${kind} ${id}'s manifest` };
  }
  if (kind === "net") {
    const nm = /^([1-9]\d{0,6})\/([1-9]\d{0,6})(?:\/(.+))?$/.exec(value);
    if (!nm) return { ok: false, ref, reason: "net:<k>/<n>, or net:<k>/<n>/<file> (body, request.json, response.json, capture.json)" };
    const base = `${STORE_REL}/net/${nm[1]}/${nm[2]}`;
    const found = await readManifest(join(S, base, "manifest.json"));
    if (!found) return { ok: false, ref, reason: `no capture ${nm[1]}/${nm[2]} is sealed (store/net/${nm[1]}/${nm[2]})` };
    if (!nm[3]) return { ok: true, ref, kind: "net", path: base, bytes: found.manifest.totals.bytes };
    const f = found.manifest.files.find((x) => x.path === nm[3]);
    if (!f) return { ok: false, ref, reason: `capture ${nm[1]}/${nm[2]} has no ${nm[3]} (it has ${found.manifest.files.map((x) => x.path).join(", ")})` };
    if (opts.verify) {
      const sha = await sha256File(join(S, base, f.path)).catch(() => null);
      if (sha !== f.sha256) return { ok: false, ref, reason: `${base}/${f.path} is not what was sealed` };
    }
    return { ok: true, ref, kind: "net", sha256: f.sha256, bytes: f.bytes, path: `${base}/${f.path}` };
  }
  if (kind === "member") {
    const mm = /^([a-z0-9-]+)#(\d+)$/.exec(value);
    if (!mm) return { ok: false, ref, reason: "member:<generation>#<n>" };
    const tsv = join(P.gen, mm[1], "members.tsv");
    if (!existsSync(tsv)) return { ok: false, ref, reason: `generation ${mm[1]} has no member list` };
    // Read as it streams, stopping at the row: a phone's list is millions of lines.
    // (The rows hold names from the evidence, which can hold U+2028: the LF-only reader, not readline.)
    const found = await (async () => {
      try {
        for await (const l of jsonlLines(createReadStream(tsv))) if (l.startsWith(`${mm[2]}\t`)) return true;
        return false;
      } catch {
        return false;
      }
    })();
    return found ? { ok: true, ref, kind: "member", path: `catalog/gen/${mm[1]}/members.tsv#${mm[2]}` } : { ok: false, ref, reason: `no member ${mm[2]} in generation ${mm[1]}` };
  }
  if (kind === "sha256") {
    if (!/^[0-9a-f]{64}$/.test(value)) return { ok: false, ref, reason: "sha256: takes 64 hex digits" };
    if (existsSync(join(P.blobs, value))) {
      // Found by name; with verify, by content too: a blob is its hash.
      if (opts.verify) {
        const sha = await sha256File(join(P.blobs, value));
        if (sha !== value) return { ok: false, ref, reason: `store/blobs/${value.slice(0, 12)}… does not hash to its name (${sha.slice(0, 12)}…)` };
      }
      return { ok: true, ref, kind: "sha256", sha256: value, path: `store/blobs/${value}` };
    }
    try {
      const inputs = JSON.parse(await readFile(join(S, "inputs.json"), "utf8")) as { files?: Array<{ path: string; sha256?: string }> };
      const f = (inputs.files ?? []).find((x) => x.sha256 === value);
      if (f) return { ok: true, ref, kind: "sha256", sha256: value, path: f.path };
    } catch {
      // no inputs
    }
    return { ok: false, ref, reason: "no stored object or input has that sha256" };
  }
  return { ok: false, ref, reason: `${kind}: is not a kind of reference` };
}

// --- a brain's own output: tool: and trace: --------------------------------------------

export const TRACE_REL = "traces/events.jsonl";

/** Where one brain-side output came from, as the trace recorded it. */
export type TraceOrigin = {
  ref: string;
  kind: "tool" | "trace";
  /** The sha256 of the trace line that recorded it (the next line's `prev` names it, or the trace's anchor). */
  line_sha256: string;
  /** The seat that made the call, as the collector attributed the line (never a claim). */
  seat: string;
  tool: string;
  args: unknown;
  /** The sender's clock and the collector's. */
  ts: string | null;
  recv_ts: string | null;
  /** The line's own sender id and count. */
  sid: string | null;
  seq: number | null;
  /** The tool's sha256 where the line records one; a built-in tool has none, and none is invented. */
  tool_sha256: string | null;
  /** The kept bytes: tool-output/<seat>/<file> for tool:; the line itself for trace:. */
  path: string | null;
  /** Which field of the line's result named the kept file (full_output, full_stderr, …). */
  field: string | null;
  /** sha256 and size of the kept bytes, as the trace recorded them. */
  digest: string;
  bytes: number;
};

const SEAT = /^[a-z][a-z0-9_-]{0,31}$/;

/** Every object under a line's result shaped like a kept output: a path, its sha256, its size. */
function keptOutputs(v: unknown, at = "result", depth = 0): Array<{ field: string; path: string; sha256: string; bytes: number }> {
  if (!v || typeof v !== "object" || depth > 5) return [];
  const o = v as Record<string, unknown>;
  const out: Array<{ field: string; path: string; sha256: string; bytes: number }> = [];
  if (typeof o.path === "string" && typeof o.sha256 === "string" && /^[0-9a-f]{64}$/.test(o.sha256) && typeof o.bytes === "number" && o.write_error === undefined) out.push({ field: at, path: o.path, sha256: o.sha256, bytes: o.bytes });
  for (const [k, x] of Object.entries(o)) if (x && typeof x === "object") out.push(...keptOutputs(x, `${at}.${k}`, depth + 1));
  return out;
}

/** The trace's anchor head, when the run has one beside it. */
function traceAnchorHead(S: string): { head: string | null; prev_head: string | null } | null {
  try {
    const a = JSON.parse(readFileSync(`${S}.trace-anchor.json`, "utf8")) as { head?: string; prev_head?: string };
    return { head: typeof a.head === "string" ? a.head : null, prev_head: typeof a.prev_head === "string" ? a.prev_head : null };
  } catch {
    return null;
  }
}

/**
 * Find a `tool:` or `trace:` ref's origin on the trace (traces/events.jsonl,
 * the collector's chained record; never a spill, which a seat can write):
 * - `tool:<seat>/<file>`: the line, attributed to that seat by the collector,
 *   whose result names tool-output/<seat>/<file> as a kept output with its
 *   sha256 and size.
 * - `trace:<sha256>`: the line whose bytes hash to it; its kept bytes are the
 *   line itself.
 * The line must be on the chain: the next line names it as its `prev`, or,
 * the last, the trace's anchor does. Nothing is sealed here.
 */
export async function traceOrigin(sandbox: string, ref: string): Promise<{ ok: true; origin: TraceOrigin } | { ok: false; reason: string }> {
  const S = resolve(sandbox);
  const m = /^(tool|trace):(.*)$/s.exec(ref.trim());
  if (!m) return { ok: false, reason: `${ref}: tool:<seat>/<file> or trace:<sha256>` };
  const [, kind, value] = m;
  let want = "";
  let seatWanted = "";
  if (kind === "tool") {
    const slash = value.indexOf("/");
    seatWanted = slash < 0 ? "" : value.slice(0, slash);
    const file = slash < 0 ? "" : value.slice(slash + 1);
    if (!SEAT.test(seatWanted) || !file || file.includes("\0") || file.startsWith("/") || file.split("/").some((s) => s === "" || s === "." || s === "..")) return { ok: false, reason: `${ref}: tool:<seat>/<file under tool-output/<seat>/>` };
    want = `tool-output/${seatWanted}/${file}`;
  } else if (!/^[0-9a-f]{64}$/.test(value)) {
    return { ok: false, reason: `${ref}: trace:<the sha256 of one line of traces/events.jsonl>` };
  }
  const file = join(S, TRACE_REL);
  if (!existsSync(file)) return { ok: false, reason: `${ref}: the run has no trace (${TRACE_REL}) to resolve it against` };
  type Hit = { line: string; hash: string; record: Record<string, unknown>; kept?: { field: string; path: string; sha256: string; bytes: number } };
  let pending: Hit | null = null;
  let confirmed: Hit | null = null;
  const refusals: string[] = [];
  const rl = jsonlLines(createReadStream(file));
  for await (const line of rl) {
    if (!line) continue;
    if (pending) {
      // On the chain: this line names the one before it.
      if (lineParent(line) === pending.hash) {
        confirmed = pending;
        break;
      }
      refusals.push(`the line ${pending.hash.slice(0, 12)}… is not what the next line names as its parent (the trace was changed there)`);
      pending = null;
    }
    if (kind === "tool" && !line.includes(want)) continue;
    const hash = sha256Hex(line);
    if (kind === "trace" && hash !== value) continue;
    let record: Record<string, unknown>;
    try {
      record = JSON.parse(line) as Record<string, unknown>;
    } catch {
      continue;
    }
    if (kind === "tool") {
      if (record.agent !== seatWanted || record.agent_unverified || record.claimed_agent !== undefined) {
        refusals.push(`a line naming ${want} is not attributed to ${seatWanted} by the collector`);
        continue;
      }
      const kept = keptOutputs(record.result).find((k) => k.path === want);
      if (!kept) continue;
      pending = { line, hash, record, kept };
    } else {
      pending = { line, hash, record };
    }
  }
  if (!confirmed && pending) {
    // The last line: the trace's anchor names it.
    const anchor = traceAnchorHead(S);
    if (anchor && (anchor.head === pending.hash || anchor.prev_head === pending.hash)) confirmed = pending;
    else refusals.push(anchor ? `the line ${pending.hash.slice(0, 12)}… is the trace's last and its anchor names another` : `the line ${pending.hash.slice(0, 12)}… is the trace's last, and the run has no trace anchor to hold it to: cite it once another line follows`);
  }
  if (!confirmed) {
    const why = refusals.length ? `: ${refusals.join("; ")}` : kind === "tool" ? `: no line of the trace, attributed to ${seatWanted}, records ${want} as a kept output with its sha256` : ": no line of the trace hashes to it";
    return { ok: false, reason: `${ref} does not resolve against the trace${why}. What the trace did not capture cannot be sealed: run the work again as a job (job_run) and cite job:<id>/<path>` };
  }
  const r = confirmed.record;
  const args = r.args ?? null;
  const result = (r.result ?? {}) as Record<string, unknown>;
  const shaOf = (x: unknown) => (typeof x === "string" && /^[0-9a-f]{64}$/.test(x) ? x : null);
  const toolSha = shaOf(result.tool_sha256) ?? shaOf((args as Record<string, unknown> | null)?.tool_sha256) ?? null;
  return {
    ok: true,
    origin: {
      ref: ref.trim(),
      kind: kind as "tool" | "trace",
      line_sha256: confirmed.hash,
      seat: String(r.agent ?? ""),
      tool: String(r.tool ?? ""),
      args,
      ts: typeof r.ts === "string" ? r.ts : null,
      recv_ts: typeof r.recv_ts === "string" ? r.recv_ts : null,
      sid: typeof r.sid === "string" ? r.sid : null,
      seq: typeof r.seq === "number" ? r.seq : null,
      tool_sha256: toolSha,
      path: confirmed.kept?.path ?? null,
      field: confirmed.kept?.field ?? null,
      digest: confirmed.kept?.sha256 ?? confirmed.hash,
      bytes: confirmed.kept?.bytes ?? Buffer.byteLength(confirmed.line),
    },
  };
}

/** One line of the trace by its sha256, as its bytes (no newline): what a trace: seal copies. */
export async function traceLineBytes(sandbox: string, sha256: string): Promise<Buffer | null> {
  const file = join(resolve(sandbox), TRACE_REL);
  if (!existsSync(file)) return null;
  // The record's own bytes, split at LF only: a record that holds U+2028 or U+2029 is found whole, and a CR before the LF is part of it.
  for await (const record of jsonlRecords(createReadStream(file))) {
    if (record.length > 0 && sha256Hex(record.bytes) === sha256) return Buffer.from(record.bytes);
  }
  return null;
}

/** A brain-side output already sealed: the journal's brain_output_sealed line for the ref. */
export async function sealedBrainOutput(sandbox: string, ref: string): Promise<{ import: string; job: string; digest: string; trace_line: string } | null> {
  const text = await readFile(storePaths(resolve(sandbox)).journal, "utf8").catch(() => "");
  let hit: { import: string; job: string; digest: string; trace_line: string } | null = null;
  for (const line of text.split("\n")) {
    if (!line.includes('"brain_output_sealed"')) continue;
    try {
      const l = JSON.parse(line) as { type?: string; ref?: string; import?: string; job?: string; digest?: string; trace_line?: string };
      if (l.type === "brain_output_sealed" && l.ref === ref && l.import) hit = { import: l.import, job: String(l.job ?? ""), digest: String(l.digest ?? ""), trace_line: String(l.trace_line ?? "") };
    } catch {
      // a torn line is the journal check's to name
    }
  }
  return hit;
}

/** Every brain-side output sealed, as the journal's brain_output_sealed lines name them: the ref, the import it became and the import job. */
export async function brainOutputSeals(sandbox: string): Promise<Array<{ ref: string; import: string; job: string }>> {
  const text = await readFile(storePaths(resolve(sandbox)).journal, "utf8").catch(() => "");
  const out: Array<{ ref: string; import: string; job: string }> = [];
  for (const line of text.split("\n")) {
    if (!line.includes('"brain_output_sealed"')) continue;
    try {
      const l = JSON.parse(line) as { type?: string; ref?: string; import?: string; job?: string };
      if (l.type === "brain_output_sealed" && l.ref && l.import) out.push({ ref: l.ref, import: l.import, job: String(l.job ?? "") });
    } catch {
      // a torn line is the journal check's to name
    }
  }
  return out;
}

/**
 * A job's own words: its command, its tool and its arguments, as one
 * lower-cased text. A value they name was written by whoever asked for the
 * job, not derived by it: authored, not derived (the network's evidence
 * check, net-broker.ts; the store sweep's echoes, store-sweep.ts).
 */
export function jobOwnWords(spec: { command?: string; tool?: string; args?: unknown } | undefined): string {
  return [spec?.command ?? "", spec?.tool ?? "", JSON.stringify(spec?.args ?? {})].join("\n").toLowerCase();
}

/** The parent a trace line names (its `prev`), read from its end where the collector writes it. */
function lineParent(line: string): string {
  return (
    /"prev":"([0-9a-f]{64})"/.exec(line.slice(-100))?.[1] ??
    (() => {
      try {
        return String((JSON.parse(line) as { prev?: unknown }).prev ?? "");
      } catch {
        return "";
      }
    })()
  );
}

/** The line of the trace that kept a file under tool-output/: the file, the line's sha256, its seat, tool and arguments. */
export type KeptOutputOrigin = { path: string; line_sha256: string; seat: string; tool: string; args: unknown };

/**
 * The line of the trace that kept each file under tool-output/, in one pass
 * (traceOrigin's rules, for every file at once): a line whose result names
 * the file as a kept output with its sha256 and size, attributed by the
 * collector to the seat whose directory holds it (never a claim), and on the
 * chain (the next line names it as its parent, or, the last, the trace's
 * anchor does). The first such line for a file is its origin; a file no line
 * keeps is not in the map. `wanted` limits it to those paths.
 */
export async function keptOutputOrigins(sandbox: string, wanted?: ReadonlySet<string>): Promise<Map<string, KeptOutputOrigin>> {
  const S = resolve(sandbox);
  const out = new Map<string, KeptOutputOrigin>();
  const file = join(S, TRACE_REL);
  if (!existsSync(file)) return out;
  let pending: { hash: string; origins: KeptOutputOrigin[] } | null = null;
  const confirm = (p: { origins: KeptOutputOrigin[] }) => {
    for (const o of p.origins) if (!out.has(o.path)) out.set(o.path, o);
  };
  const rl = jsonlLines(createReadStream(file));
  for await (const line of rl) {
    if (!line) continue;
    if (pending) {
      if (lineParent(line) === pending.hash) confirm(pending);
      pending = null;
    }
    if (!line.includes('"tool-output/')) continue;
    let record: Record<string, unknown>;
    try {
      record = JSON.parse(line) as Record<string, unknown>;
    } catch {
      continue;
    }
    const seat = typeof record.agent === "string" ? record.agent : "";
    if (!SEAT.test(seat) || record.agent_unverified || record.claimed_agent !== undefined) continue;
    const mine = (p: string) => p.startsWith(`tool-output/${seat}/`) && !p.includes("\0") && p.split("/").every((s) => s !== "" && s !== "." && s !== "..");
    const kept = keptOutputs(record.result).filter((k) => mine(k.path) && (!wanted || wanted.has(k.path)) && !out.has(k.path));
    if (!kept.length) continue;
    const hash = sha256Hex(line);
    pending = { hash, origins: kept.map((k) => ({ path: k.path, line_sha256: hash, seat, tool: String(record.tool ?? ""), args: record.args ?? null })) };
  }
  if (pending) {
    const anchor = traceAnchorHead(S);
    if (anchor && (anchor.head === pending.hash || anchor.prev_head === pending.hash)) confirm(pending);
  }
  return out;
}

// --- catalogue generations and revisions ---------------------------------------------

export type Generation = {
  id: string;
  job: string;
  recipe: string;
  recipe_sha256: string;
  /** sha256: the target's content, when it is one object of the store (a derived or requested one). */
  target: { name?: string; ref?: string; paths?: string[]; sha256?: string };
  status: string;
  coverage: Record<string, unknown> | null;
  experimental: boolean;
  parent?: string;
  alias?: string;
  /** What asked for it: the kickoff's plan, the derived catalogue, or an agent's catalog_request; and the status of the job that made its object. */
  trigger?: "kickoff" | "derived" | "request";
  parent_status?: string;
  /** The recipe read a sensitive output: this generation's coverage detail is withheld, and its files are named by their digest (docs/adr/0016). */
  sensitive?: boolean;
  /** What the harness did not read of the recipe's own record, and where the whole is. */
  notes?: string[];
  files: Array<{ path: string; what: string; rows: number | null; bytes: number }>;
  at: string;
};

async function linkFarm(from: string, to: string): Promise<void> {
  const entries = await walk(from);
  await mkdir(to, { recursive: true });
  for (const e of entries) {
    const src = Buffer.concat([Buffer.from(from), Buffer.from("/"), e.rel]);
    const dst = Buffer.concat([Buffer.from(to), Buffer.from("/"), e.rel]);
    if (e.kind === "dir") await mkdir(dst, { recursive: true });
    else if (e.kind === "file") await link(src, dst).catch(async () => copyFile(src, dst));
  }
  for (const e of [...entries].filter((x) => x.kind === "dir").reverse()) await chmod(Buffer.concat([Buffer.from(to), Buffer.from("/"), e.rel]), 0o555).catch(() => undefined);
}

async function rowsOf(path: string): Promise<number | null> {
  // Counted as it streams by: a body file of a large disk is hundreds of MB.
  return new Promise((ok) => {
    let n = 0;
    createReadStream(path)
      .on("data", (chunk) => {
        const b = chunk as Buffer;
        for (let i = b.indexOf(10); i !== -1; i = b.indexOf(10, i + 1)) n += 1;
      })
      .on("end", () => ok(n))
      .on("error", () => ok(null));
  });
}

/**
 * A recipe job's committed output becomes a generation: catalog/gen/<gen>/
 * holds the same files (hard links), generation.json says which recipe
 * (and its sha256) catalogued which target from which job, with what
 * coverage; a kickoff generation is also linked at its compatibility path
 * (catalog/<slug>/) when nothing is there yet. Then a new revision.
 */
/** The most of a recipe's coverage.json and index.tsv the harness reads; a larger one is named, kept whole. */
export const RECIPE_RECORD_MAX_BYTES = 4 * 1024 * 1024;

export async function publishGeneration(
  journal: Journal,
  g: { job: string; recipe: string; recipe_sha256: string; target: Generation["target"]; experimental?: boolean; parent?: string; alias?: string; trigger?: Generation["trigger"]; parent_status?: string; sensitive?: boolean },
): Promise<{ generation: Generation; revision: number }> {
  const S = journal.sandbox;
  const P = storePaths(S);
  const n = journal.of("generation_committed").length + 1;
  const id = `g${String(n).padStart(4, "0")}`;
  const out = join(P.jobs, g.job, "out");
  const dir = join(P.gen, id);
  await mkdir(P.gen, { recursive: true });
  await linkFarm(out, dir);
  // What a worker wrote names files for the host to read: only those the
  // job's sealed manifest lists, as regular files under its out/, are read
  // (a path in index.tsv climbing out of the store, or naming a FIFO, was
  // stat'ed and read by the hub before: Codex, 2026-09-26).
  const sealed = await readManifest(join(P.jobs, g.job, "manifest.json"));
  const listed = new Map((sealed?.manifest.files ?? []).map((f) => [f.path, f]));
  const notes: string[] = [];
  const readRecord = async (name: string): Promise<string | null> => {
    const f = listed.get(name);
    if (!f) return null;
    if (f.bytes > RECIPE_RECORD_MAX_BYTES) {
      notes.push(`${name} is ${f.bytes} bytes, more than the ${RECIPE_RECORD_MAX_BYTES} the harness reads; it is whole at catalog/gen/${id}/${name}`);
      return null;
    }
    const st = await lstat(join(out, name)).catch(() => null);
    return st?.isFile() ? readFile(join(out, name), "utf8").catch(() => null) : null;
  };
  let coverage: Record<string, unknown> | null = null;
  try {
    const text = await readRecord("coverage.json");
    coverage = text === null ? null : (JSON.parse(text) as Record<string, unknown>);
  } catch {
    coverage = null;
  }
  // A generation of a sensitive output is sensitive too: the recipe read
  // secret bytes, and its coverage's covered/not_covered, errors and
  // explanations may carry them. The record keeps only the status and says
  // the rest is withheld; its linked files carry the sensitive digests and
  // are withheld from a package by those (docs/adr/0016).
  if (g.sensitive && coverage) coverage = { status: coverage.status ?? "unknown", withheld: "this generation is of a sensitive output; its coverage detail is not recorded here" };
  const files: Generation["files"] = [];
  const index = await readRecord("index.tsv");
  for (const line of (index ?? "").split("\n")) {
    const [f, ...what] = line.split("\t");
    if (!f) continue;
    const entry = listed.get(f);
    if (!entry) {
      notes.push(`index.tsv names ${JSON.stringify(f)}, which is not a file of job ${g.job}'s sealed output: not read`);
      continue;
    }
    const p = join(out, f);
    const st = await lstat(p).catch(() => null);
    if (!st?.isFile()) continue;
    // A sensitive generation's file descriptions can carry the secret; the bytes are named by their digest, withheld from a package.
    files.push({ path: `catalog/gen/${id}/${f}`, what: g.sensitive ? "withheld: a sensitive output" : what.join("\t"), rows: g.sensitive ? null : await rowsOf(p), bytes: st.size });
  }
  let alias: string | undefined;
  if (g.alias && /^catalog\/[A-Za-z0-9._-]+$/.test(g.alias) && !existsSync(join(S, g.alias))) {
    await linkFarm(out, join(S, g.alias));
    alias = g.alias;
  }
  const generation: Generation = {
    id,
    job: g.job,
    recipe: g.recipe,
    recipe_sha256: g.recipe_sha256,
    target: g.target,
    status: String(coverage?.status ?? "unknown"),
    coverage,
    experimental: Boolean(g.experimental),
    ...(g.parent ? { parent: g.parent } : {}),
    ...(alias ? { alias } : {}),
    ...(g.trigger ? { trigger: g.trigger } : {}),
    ...(g.parent_status ? { parent_status: g.parent_status } : {}),
    ...(g.sensitive ? { sensitive: true } : {}),
    ...(notes.length ? { notes } : {}),
    files,
    at: new Date().toISOString(),
  };
  await chmod(dir, 0o755).catch(() => undefined);
  await writeDurable(join(dir, "generation.json"), `${JSON.stringify(generation, null, 2)}\n`, 0o444);
  await chmod(dir, 0o555).catch(() => undefined);
  await journal.append({ type: "generation_committed", generation: id, job: g.job, recipe: g.recipe, recipe_sha256: g.recipe_sha256, target: g.target, status: generation.status, experimental: generation.experimental, ...(alias ? { alias } : {}), ...(g.trigger ? { trigger: g.trigger } : {}), ...(g.parent_status ? { parent_status: g.parent_status } : {}) });
  maybeCrash("generation:committed");
  const revision = await publishRevision(journal);
  return { generation, revision };
}

/** The catalogue as of now, as a new numbered revision: a new directory, never a renamed pointer. */
export async function publishRevision(journal: Journal): Promise<number> {
  const S = journal.sandbox;
  const P = storePaths(S);
  const n = journal.of("revision_published").length;
  const dir = join(P.revisions, String(n));
  await mkdir(dir, { recursive: true });
  // A partial generation whose object has a readable form catalogued since
  // (the decrypted volume of an encrypted one): said beside it.
  const readable = new Map<string, string>();
  for (const r of journal.of("generation_related")) readable.set(String(r.generation), String(r.readable));
  const generations: Array<Generation & { readable_form?: string }> = [];
  for (const ev of journal.of("generation_committed")) {
    try {
      const g = JSON.parse(await readFile(join(P.gen, String(ev.generation), "generation.json"), "utf8")) as Generation;
      generations.push({ ...g, ...(readable.has(g.id) ? { readable_form: readable.get(g.id) } : {}) });
    } catch {
      // a generation whose record is gone is named by the journal alone
    }
  }
  const census = existsSync(join(S, "catalog", "coverage.tsv")) ? sha256Hex(readFileSync(join(S, "catalog", "coverage.tsv"))) : null;
  const index = { revision: n, at: new Date().toISOString(), census: { path: "catalog/coverage.tsv", sha256: census }, generations };
  const md: string[] = [`# Evidence catalogue, revision ${n}`, "", `The kickoff's census is \`catalog/coverage.tsv\`; each generation below is one recipe's result over one object. A newer revision, when there is one, has everything this one has.`, ""];
  if (!generations.length) md.push("No generation yet.");
  for (const g of generations) {
    md.push(`## ${g.id}: ${g.recipe} over ${g.target.name ?? g.target.ref ?? "?"} — ${g.status}${g.experimental ? " (experimental recipe)" : ""}`, "");
    md.push(`Job ${g.job}${g.parent ? `, triggered by job ${g.parent}` : ""}${g.trigger ? ` (${g.trigger})` : ""}; recipe sha256 ${g.recipe_sha256.slice(0, 16)}…${g.alias ? `; also at \`${g.alias}/\`` : ""}.`, "");
    if (g.readable_form) md.push(`A readable form of this object is catalogued as ${g.readable_form}.`, "");
    const cov = g.coverage as { covered?: string; not_covered?: string; errors?: unknown[]; limits_hit?: unknown[] } | null;
    if (cov?.covered) md.push(`Covered: ${cov.covered}. Not covered: ${cov.not_covered ?? "not said"}.`, "");
    for (const e of [...(cov?.errors ?? []), ...(cov?.limits_hit ?? [])]) md.push(`- ${String(e)}`);
    if (g.files.length) {
      md.push("", "| File | What | Rows | Bytes |", "| --- | --- | --- | --- |");
      for (const f of g.files) md.push(`| \`${f.path}\` | ${f.what} | ${f.rows ?? "?"} | ${f.bytes} |`);
    }
    md.push("");
  }
  const indexText = `${JSON.stringify(index, null, 2)}\n`;
  const mdText = `${md.join("\n")}\n`;
  await writeDurable(join(dir, "index.json"), indexText, 0o444);
  await writeDurable(join(dir, "index.md"), mdText, 0o444);
  const manifest = { revision: n, files: { "index.json": sha256Hex(indexText), "index.md": sha256Hex(mdText) } };
  const manifestText = `${JSON.stringify(manifest, null, 2)}\n`;
  // Written last: a revision directory with its MANIFEST is complete.
  await writeDurable(join(dir, "MANIFEST.json"), manifestText, 0o444);
  await chmod(dir, 0o555).catch(() => undefined);
  await journal.append({ type: "revision_published", revision: n, generations: generations.length, manifest_sha256: sha256Hex(manifestText) });
  return n;
}

/**
 * Revision 0, at kickoff: the store, the journal's first events (the census,
 * the inputs and their segment sets as the plan gives them) and an empty
 * catalogue revision the kickoff generations will follow.
 */
export async function initStore(sandbox: string): Promise<Journal> {
  const S = resolve(sandbox);
  const P = storePaths(S);
  for (const d of [P.root, P.jobs, P.blobs, P.imports, P.gen, P.revisions]) await mkdir(d, { recursive: true });
  await mkdir(P.staging, { recursive: true, mode: 0o700 });
  const journal = await Journal.open(S);
  if (journal.lines.length) return journal;
  const file = (rel: string) => (existsSync(join(S, rel)) ? sha256Hex(readFileSync(join(S, rel))) : null);
  let plan: Array<{ input: string; target?: { paths?: string[] } }> = [];
  let sets: Array<{ input?: string; members?: string[] }> = [];
  try {
    const parsed = JSON.parse(readFileSync(join(S, "catalog", "plan.json"), "utf8")) as { recipes?: typeof plan; collections?: typeof sets };
    plan = parsed.recipes ?? [];
    sets = Array.isArray(parsed.collections) ? parsed.collections : [];
  } catch {
    plan = [];
  }
  const collections = new Map<string, string[]>();
  for (const r of plan) {
    const paths = (r.target?.paths ?? []).map((p) => relative(S, p));
    if (paths.length > 1) collections.set(r.input, paths);
  }
  // Every segment set the census saw, planned or not: a job that declares one
  // segment is given the rest (job-scope.ts), by this record, not a guess.
  for (const c of sets) {
    const members = (c.members ?? []).filter((x) => typeof x === "string" && x.startsWith("inputs/"));
    if (typeof c.input === "string" && members.length > 1 && !collections.has(c.input)) collections.set(c.input, members);
  }
  await journal.append({ type: "store_opened", inputs_sha256: file("inputs.json"), census_sha256: file("catalog/coverage.tsv"), plan_sha256: file("catalog/plan.json") });
  for (const [input, paths] of collections) await journal.append({ type: "input_collection", input, members: paths });
  await publishRevision(journal);
  return journal;
}

/** What custody checks of the store, and what it found. */
export type StoreCheck = {
  journal: { lines: number; intact: boolean; detail: string; head: string | null; anchor: "matches" | "behind" | "off the chain" | "missing"; repaired: number; anchor_behind: number; anchor_mismatch: number };
  jobs: number;
  committed: number;
  outputs: { files: number; verified: number; mismatched: string[]; missing: string[] };
  manifests_missing: string[];
  staging_left: string[];
  /** Why each staging directory left was not sealed, from the journal's `job_unsealed` lines (the last for each). */
  staging_why?: Record<string, string>;
  generations: number;
  revisions: number;
  /**
   * The standing findings (a corrected one counts as its correction) and
   * what they rest on: structured refs, resolved again now (those that no
   * longer resolve named; those that say only why none can be named, named),
   * a path of the run's objects in the prose only, or nothing at all (an
   * audit gap). Each list holds seqs.
   */
  findings: { total: number; structured: number; refs_invalid: number[]; unresolved_only: number[]; path_only: number[]; without_refs: number[]; on_failed_jobs?: number[]; contradictions?: Array<{ from: number; to: number }>; sensitive?: number[]; hypotheses?: number; limitations?: number };
  /** Each committed job's logs against the hashes its job_committed line sealed. */
  logs?: { checked: number; mismatched: string[]; missing: string[] };
  /** Why the ledger could not be read for the findings, when it could not (not the same as no ledger). */
  ledger_unreadable?: string | null;
  /**
   * What each job was given and could reach, and whether what it read is
   * known: the store records declared and accessible; observed is unknown
   * unless a tool reports it. `scopes` counts the jobs by scope: declared
   * (enforced: the worker had a view of what it named), all (said) and
   * default (nothing said, or a job from before scopes were enforced: every
   * object of the run in reach). `manifests` are the declared jobs' scope
   * manifests held to the sha256 their job_started line carries.
   */
  access?: { jobs: number; declared: number; observed_unknown: number; scopes?: { declared: number; all: number; default_all: number }; manifests?: { verified: number; mismatched: string[] } };
  /** A brain's own outputs a finding cited, sealed as imports: each import's manifest and files held to its journal line. */
  imports?: { sealed: number; verified: number; mismatched: string[] };
  /** The job images the run declared (job_images), each job held to them, and each image name to the digests it booted. */
  images?: { declared: string[]; jobs: number; undeclared: string[]; digests: Record<string, string[]> };
  /** Notes an examiner added to the record after the run (evidence-store.ts note), and the times the job service told the agents that workers were not running. */
  notes: number;
  degraded: number;
  /** Each revision's MANIFEST.json and its index files, and each generation.json, held to the journal's lines. */
  catalogue: { revisions_verified: number; revisions_mismatched: string[]; generations_verified: number; generations_mismatched: string[] };
  /** The derived catalogue, from its journal lines: objects offered and skipped, answered, catalogued, left unanswered, and each limit it met. */
  derived: { offered: number; skipped: number; detected: number; applied: number; undetermined: number; catalogued: number; partial: number; unanswered: number; deferred: number; bounded: string[] };
};

/** Every regular file under a directory, links and specials left out. */
async function walkFiles(dir: string): Promise<string[]> {
  const out: string[] = [];
  for (const d of await readdir(dir, { withFileTypes: true }).catch(() => [])) {
    const p = join(dir, d.name);
    if (d.isDirectory()) out.push(...(await walkFiles(p)));
    else if (d.isFile()) out.push(p);
  }
  return out;
}

/**
 * Custody's look at the store: the journal's chain and its anchor, every
 * committed job's files hashed again against its manifest, and any staging
 * directory left (a job that never finished sealing). `before` stops the
 * re-hashing at custody's deadline; what was not reached is not claimed.
 */
export async function checkStore(sandbox: string, before = Infinity): Promise<StoreCheck | null> {
  const S = resolve(sandbox);
  const P = storePaths(S);
  if (!existsSync(P.journal)) return null;
  const text = await readFile(P.journal, "utf8");
  const checked = verifyJournalText(text);
  let anchor: Anchor | null = null;
  try {
    anchor = JSON.parse(await readFile(P.anchor, "utf8")) as Anchor;
  } catch {
    anchor = null;
  }
  const where = !anchor ? "missing" : anchor.head === checked.head && anchor.seq === checked.lines.length - 1 ? "matches" : anchor.seq >= 0 && checked.hashes[anchor.seq] === anchor.head ? "behind" : "off the chain";
  const count = (t: string) => checked.lines.filter((l) => l.type === t).length;
  const committed = checked.lines.filter((l) => l.type === "job_committed");
  const out: StoreCheck = {
    journal: { lines: checked.lines.length, intact: !checked.error, detail: checked.error ?? "chain intact", head: checked.head, anchor: where, repaired: count("journal_repaired"), anchor_behind: count("anchor_behind"), anchor_mismatch: count("anchor_mismatch") },
    jobs: count("job_accepted"),
    committed: committed.length,
    outputs: { files: 0, verified: 0, mismatched: [], missing: [] },
    manifests_missing: [],
    staging_left: [],
    generations: count("generation_committed"),
    revisions: count("revision_published"),
    findings: { total: 0, structured: 0, refs_invalid: [], unresolved_only: [], path_only: [], without_refs: [] },
    notes: count("note"),
    degraded: count("jobs_degraded"),
    catalogue: { revisions_verified: 0, revisions_mismatched: [], generations_verified: 0, generations_mismatched: [] },
    derived: { offered: 0, skipped: 0, detected: 0, applied: 0, undetermined: 0, catalogued: 0, partial: 0, unanswered: count("detect_unanswered"), deferred: count("derived_deferred"), bounded: [] },
  };
  for (const l of checked.lines) {
    if (l.type === "derived_offered") {
      out.derived.offered += ((l.offered as unknown[]) ?? []).length;
      out.derived.skipped += ((l.skipped as unknown[]) ?? []).length;
    } else if (l.type === "detect_answered") {
      const rows = (l.rows as Array<{ applies?: boolean | "unknown" }>) ?? [];
      out.derived.detected += rows.length;
      out.derived.applied += rows.filter((r) => r.applies === true).length;
      out.derived.undetermined += rows.filter((r) => r.applies === "unknown").length;
    } else if (l.type === "generation_committed" && l.trigger === "derived") {
      if (l.status === "complete") out.derived.catalogued += 1;
      else out.derived.partial += 1;
    } else if (l.type === "derived_bounded") {
      out.derived.bounded.push(String(l.bound));
    }
  }
  // The catalogue as published, held to the journal: a revision's manifest
  // and its two index files by hash, a generation's record by what it says.
  for (const l of checked.lines) {
    if (l.type === "revision_published") {
      const dir = join(P.revisions, String(l.revision));
      try {
        const text = await readFile(join(dir, "MANIFEST.json"), "utf8");
        const man = JSON.parse(text) as { files?: Record<string, string> };
        const ok = sha256Hex(text) === l.manifest_sha256 && Object.entries(man.files ?? {}).every(([f, h]) => existsSync(join(dir, f)) && sha256Hex(readFileSync(join(dir, f))) === h);
        if (ok) out.catalogue.revisions_verified += 1;
        else out.catalogue.revisions_mismatched.push(`revision ${l.revision}`);
      } catch {
        out.catalogue.revisions_mismatched.push(`revision ${l.revision} (unreadable)`);
      }
    } else if (l.type === "generation_committed") {
      try {
        const gdir = join(P.gen, String(l.generation));
        const g = JSON.parse(await readFile(join(gdir, "generation.json"), "utf8")) as Record<string, unknown> & { id?: string; target?: Record<string, unknown> };
        // Every field the journal line and the record both carry, not four of them.
        const differs: string[] = [];
        if (g.id !== l.generation) differs.push("id");
        for (const k of ["job", "recipe", "recipe_sha256", "status", "experimental", "trigger", "parent_status"]) {
          if (l[k] !== undefined && g[k] !== undefined && JSON.stringify(g[k]) !== JSON.stringify(l[k])) differs.push(k);
        }
        const lt = (l.target ?? {}) as Record<string, unknown>;
        for (const k of ["ref", "name", "sha256", "paths"]) {
          if (lt[k] !== undefined && g.target?.[k] !== undefined && JSON.stringify(g.target[k]) !== JSON.stringify(lt[k])) differs.push(`target.${k}`);
        }
        // Each file the generation publishes, against the sealed output of the job that made it.
        if (Date.now() <= before && typeof l.job === "string") {
          const sealed = await readManifest(join(P.jobs, l.job, "manifest.json"));
          const byPath = new Map((sealed?.manifest.files ?? []).map((f) => [f.path, f.sha256]));
          for (const f of await walkFiles(gdir)) {
            const rel = relative(gdir, f);
            if (rel === "generation.json") continue;
            const want = byPath.get(rel);
            if (want && (await sha256File(f)) !== want) differs.push(`${rel} differs from job ${l.job}'s sealed output`);
          }
        }
        if (!differs.length) out.catalogue.generations_verified += 1;
        else out.catalogue.generations_mismatched.push(`${l.generation} (${differs.join(", ")})`);
      } catch {
        out.catalogue.generations_mismatched.push(`${l.generation} (unreadable)`);
      }
    }
  }
  // Each job's sealed logs, against the hashes its commit recorded.
  out.logs = { checked: 0, mismatched: [], missing: [] };
  for (const c of committed) {
    if (Date.now() > before) break;
    for (const [name, want] of Object.entries((c.logs ?? {}) as Record<string, string>)) {
      const f = join(P.jobs, String(c.job), name);
      try {
        const got = await sha256File(f);
        out.logs.checked += 1;
        if (got !== want) out.logs.mismatched.push(`${c.job}/${name}`);
      } catch {
        out.logs.missing.push(`${c.job}/${name}`);
      }
    }
  }
  // What each job declared and could reach; what it read is not observed by the harness.
  const started = checked.lines.filter((l) => l.type === "job_started");
  // The images jobs ran in, held to the ones the run declared before any job ran.
  const declaredLine = checked.lines.filter((l) => l.type === "job_images").at(-1);
  if (declaredLine) {
    const declared = [...new Set([String(declaredLine.default ?? ""), ...Object.values((declaredLine.images ?? {}) as Record<string, string>)].filter(Boolean))].sort();
    const imageOf = new Map(started.map((l) => [String(l.job), String(l.image ?? "")]));
    const digests: Record<string, Set<string>> = {};
    for (const c of committed) {
      const img = imageOf.get(String(c.job));
      if (img && typeof c.image_digest === "string") (digests[img] ??= new Set()).add(c.image_digest);
    }
    out.images = {
      declared,
      jobs: started.length,
      undeclared: started.filter((l) => !declared.includes(String(l.image ?? ""))).map((l) => String(l.job)),
      digests: Object.fromEntries(Object.entries(digests).map(([k, v]) => [k, [...v].sort()])),
    };
  }
  const kindOf = (l: JournalLine) => String((l.scope as { kind?: string } | undefined)?.kind ?? "default-all");
  const manifests = { verified: 0, mismatched: [] as string[] };
  for (const l of started) {
    const sc = l.scope as { kind?: string; manifest?: string; manifest_sha256?: string } | undefined;
    if (sc?.kind !== "declared" || !sc.manifest) continue;
    const got = await readFile(join(S, sc.manifest)).then((b) => sha256Hex(b)).catch(() => null);
    if (got && got === sc.manifest_sha256) manifests.verified += 1;
    else manifests.mismatched.push(`${l.job} (${sc.manifest}${got ? "" : ", missing"})`);
  }
  out.access = {
    jobs: started.length,
    declared: started.filter((l) => Array.isArray(l.declared) && (l.declared as unknown[]).length > 0).length,
    observed_unknown: started.filter((l) => l.observed === "unknown" || l.observed === undefined).length,
    scopes: { declared: started.filter((l) => kindOf(l) === "declared").length, all: started.filter((l) => kindOf(l) === "all").length, default_all: started.filter((l) => kindOf(l) === "default-all").length },
    manifests,
  };
  // A brain's own outputs sealed as imports, and evidence and material added
  // from outside (docs/adr/0014): the manifest by its hash, each file by its manifest.
  const sealedLines = checked.lines.filter((l) => l.type === "brain_output_sealed" || l.type === "evidence_added" || l.type === "material_added");
  if (sealedLines.length) {
    out.imports = { sealed: sealedLines.length, verified: 0, mismatched: [] };
    for (const l of sealedLines) {
      const dir = join(P.imports, String(l.type === "brain_output_sealed" ? l.job : l.import));
      const m = await readManifest(join(dir, "manifest.json"));
      let good = Boolean(m) && m!.sha256 === l.manifest_sha256;
      for (const f of m?.manifest.files ?? []) {
        if (!good || Date.now() > before) break;
        const got = await sha256File(Buffer.concat([Buffer.from(join(dir, "out")), Buffer.from("/"), Buffer.from(f.path_b64, "base64")])).catch(() => null);
        if (got !== f.sha256) good = false;
      }
      if (good && l.type !== "brain_output_sealed" && typeof l.material_json_sha256 === "string") {
        const rec = await readFile(join(dir, "material.json")).catch(() => null);
        if (!rec || sha256Hex(rec) !== l.material_json_sha256) good = false;
      }
      if (good) out.imports.verified += 1;
      else out.imports.mismatched.push(l.type === "brain_output_sealed" ? `${l.import} (store/imports/${l.job})` : `import:${l.import} (store/imports/${l.import}, ${l.type === "evidence_added" ? "evidence added" : "material supplied"})`);
    }
  }
  let ledgerText: string | null = null;
  try {
    ledgerText = await readFile(join(S, "ledger", "entries.jsonl"), "utf8");
    out.ledger_unreadable = null;
  } catch (err) {
    // No ledger is not an unreadable one: said apart.
    const code = (err as NodeJS.ErrnoException).code;
    out.ledger_unreadable = code === "ENOENT" ? null : `the ledger is unreadable (${code ?? "error"})`;
  }
  if (ledgerText !== null) {
    type E = { seq?: number; kind?: string; source?: string; evidence?: string; supersedes?: number; refs?: string[]; rel?: Array<{ to: number; kind: string }>; sensitive?: boolean };
    const entries: E[] = [];
    for (const line of ledgerText.split("\n")) {
      if (!line.trim()) continue;
      try {
        entries.push(JSON.parse(line) as E);
      } catch {
        out.ledger_unreadable = "a line of the ledger is not JSON (the ledger check names it)";
      }
    }
    const replaced = new Set(entries.map((e) => e.supersedes).filter((n): n is number => typeof n === "number"));
    const logs = await committedLogHashes(S);
    out.findings.on_failed_jobs = [];
    out.findings.sensitive = entries.filter((e) => e.sensitive && !replaced.has(Number(e.seq))).map((e) => Number(e.seq));
    out.findings.hypotheses = entries.filter((e) => e.kind === "hypothesis" && !replaced.has(Number(e.seq))).length;
    out.findings.limitations = entries.filter((e) => e.kind === "limitation" && !replaced.has(Number(e.seq))).length;
    out.findings.contradictions = entries.flatMap((e) => (replaced.has(Number(e.seq)) ? [] : (e.rel ?? []).filter((r) => r.kind === "contradicts" && !replaced.has(r.to)).map((r) => ({ from: Number(e.seq), to: r.to }))));
    for (const e of entries) {
      if (e.kind !== "finding" || replaced.has(Number(e.seq))) continue;
      out.findings.total += 1;
      const seq = Number(e.seq);
      if (e.refs?.length) {
        out.findings.structured += 1;
        let bad = false;
        let failed = false;
        // Resolved against the store's bytes: a job log against its sealed hash, a blob against its name.
        for (const r of e.refs) {
          const got = await resolveRef(S, r, { verify: true, committedLogs: logs });
          if (!got.ok) bad = true;
          else if (got.status && got.status !== "ok") failed = true;
        }
        if (failed) out.findings.on_failed_jobs.push(seq);
        if (bad) out.findings.refs_invalid.push(seq);
        else if (e.refs.every((r) => r.startsWith("unresolved:"))) out.findings.unresolved_only.push(seq);
        continue;
      }
      // A reference (job:, input:, …) or a path of the run's own objects
      // (inputs/…, store/jobs/<id>/…, catalog/gen/<g>/…) in the prose: it
      // names what the finding rests on, unchecked; prose alone does not.
      const cited = `${e.source ?? ""} ${e.evidence ?? ""}`;
      if (/\b(job|input|import|member|sha256):[^\s,;)]+/.test(cited) || /(^|[\s`'"(])(inputs\/\S+|store\/jobs\/j\d{6}\S*|catalog\/gen\/g\d{4}\S*)/.test(cited)) out.findings.path_only.push(seq);
      else out.findings.without_refs.push(seq);
    }
  }
  for (const c of committed) {
    const rel = String((c.outputs as { path?: string } | undefined)?.path ?? "");
    if (!rel) continue;
    const dir = join(S, rel);
    const manifestPath = rel.endsWith("/out") ? join(dirname(dir), "manifest.json") : join(dirname(dir), `${basename(dir)}.manifest.json`);
    const m = await readManifest(manifestPath);
    if (!m) {
      out.manifests_missing.push(rel);
      continue;
    }
    if (m.sha256 !== (c.outputs as { manifest_sha256?: string }).manifest_sha256) out.outputs.mismatched.push(`${relative(S, manifestPath)} (the manifest itself)`);
    for (const f of m.manifest.files) {
      out.outputs.files += 1;
      if (Date.now() > before) continue;
      const p = Buffer.concat([Buffer.from(dir), Buffer.from("/"), Buffer.from(f.path_b64, "base64")]);
      try {
        if ((await sha256File(p)) === f.sha256) out.outputs.verified += 1;
        else out.outputs.mismatched.push(`${rel}/${f.path}`);
      } catch {
        out.outputs.missing.push(`${rel}/${f.path}`);
      }
    }
  }
  try {
    // A dot name there is the job service's own (the run's copies of inputs a file system could not clone), not a job's.
    out.staging_left = (await readdir(P.staging)).filter((n) => !n.startsWith(".")).sort();
  } catch {
    out.staging_left = [];
  }
  if (out.staging_left.length) {
    // Each one's account, when the job service gave one: why it was not sealed.
    const why: Record<string, string> = {};
    for (const l of checked.lines) if (l.type === "job_unsealed" && typeof l.staging === "string" && out.staging_left.includes(l.staging)) why[l.staging] = String(l.why ?? "");
    if (Object.keys(why).length) out.staging_why = why;
  }
  return out;
}

/** The pid in the run's hub.pid when that process is alive: the store's writer while the run runs; null when there is none. */
export function hubAlive(sandbox: string): number | null {
  const pidFile = join(resolve(sandbox), "hub.pid");
  if (!existsSync(pidFile)) return null;
  const pid = Number(readFileSync(pidFile, "utf8").trim());
  try {
    return Number.isInteger(pid) && pid > 0 && process.kill(pid, 0) ? pid : null;
  } catch {
    return null;
  }
}

/**
 * A live hub process for this run, by its command line rather than by
 * hub.pid: `vm-hub.ts <sandbox> --dir DIR` (a kickoff's) or `vm-hub.ts
 * --resume DIR` (its keeper's), DIR's `sandbox` file naming this run. A
 * stop that gave up waiting for its hub used to drop hub.pid and the hub's
 * directory, and a second stop then took the store for its own while that
 * hub might still write it. The pid, or null when none is found. A failed
 * process lookup throws: it cannot establish that the writer has gone.
 */
export function hubProcessFor(sandbox: string): number | null {
  const S = resolve(sandbox);
  let real = S;
  try {
    real = realpathSync(S);
  } catch {
    // a sandbox that is gone has no hub to find by its path
  }
  let out = "";
  try {
    out = execFileSync("ps", ["-e", "-ww", "-o", "pid=,args="], { encoding: "utf8", timeout: 15_000, maxBuffer: 64 * 1024 * 1024 });
  } catch {
    throw new Error("could not check whether the run's hub is up (ps failed)");
  }
  const names = (dir: string): boolean => {
    try {
      const named = readFileSync(join(dir, "sandbox"), "utf8").trim();
      return named === real || named === S;
    } catch {
      return false;
    }
  };
  for (const line of out.split("\n")) {
    const m = /^\s*(\d+)\s+(.*)$/.exec(line);
    if (!m || Number(m[1]) === process.pid || !/vm-hub\.ts\b/.test(m[2]!)) continue;
    const args = m[2]!;
    const dir = /--(?:dir|resume) (\S+)/.exec(args)?.[1];
    if (args.includes(` ${S} `) || args.includes(` ${real} `) || args.endsWith(` ${S}`) || args.endsWith(` ${real}`) || (dir && names(dir))) return Number(m[1]);
  }
  return null;
}

/**
 * An examiner's note appended to a run's journal: a correction or an
 * observation about the record, attributed and chained like every other
 * line, never an edit of one. Only with no hub running, the store's writer
 * during a run.
 */
export async function appendNote(sandbox: string, note: { by: string; text: string; jobs?: string[] }): Promise<number> {
  if (!note.by.trim() || !note.text.trim()) throw new Error("a note needs --by and --text");
  const pid = hubAlive(sandbox);
  if (pid) throw new Error(`the run's hub (pid ${pid}) is the store's writer while it runs: add the note after the run`);
  const j = await Journal.open(sandbox);
  await j.append({ type: "note", by: note.by, text: note.text, ...(note.jobs?.length ? { jobs: note.jobs } : {}) });
  return j.seq;
}

async function main(argv: string[]): Promise<number> {
  const [cmd, sandbox] = argv;
  if (!cmd || !sandbox) {
    process.stderr.write("usage: evidence-store.ts init|verify|note <sandbox>\n");
    return 2;
  }
  if (cmd === "note") {
    const opt = (name: string) => {
      const i = argv.indexOf(name);
      return i >= 0 ? argv[i + 1] : undefined;
    };
    const jobs = argv.flatMap((a, i) => (a === "--job" && argv[i + 1] ? [argv[i + 1]] : []));
    const seq = await appendNote(sandbox, { by: opt("--by") ?? "", text: opt("--text") ?? "", jobs });
    process.stdout.write(`${JSON.stringify({ ok: true, seq })}\n`);
    return 0;
  }
  if (cmd === "init") {
    const j = await initStore(sandbox);
    process.stdout.write(`${JSON.stringify({ ok: true, journal: relative(resolve(sandbox), j.path), seq: j.seq })}\n`);
    return 0;
  }
  if (cmd === "verify") {
    const P = storePaths(sandbox);
    const text = existsSync(P.journal) ? await readFile(P.journal, "utf8") : "";
    const checked = verifyJournalText(text);
    let anchor: Anchor | null = null;
    try {
      anchor = JSON.parse(await readFile(P.anchor, "utf8")) as Anchor;
    } catch {
      anchor = null;
    }
    const lastRaw = checked.lines.length ? text.slice(0, checked.goodBytes).trimEnd().split("\n").pop() ?? "" : "";
    const head = lastRaw ? sha256Hex(lastRaw) : null;
    const ok = !checked.error && (!anchor || (anchor.head === head && anchor.seq === checked.lines.length - 1));
    process.stdout.write(`${JSON.stringify({ ok, lines: checked.lines.length, head, anchor, error: checked.error ?? null })}\n`);
    return ok ? 0 : 1;
  }
  process.stderr.write(`unknown command ${cmd}\n`);
  return 2;
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  main(process.argv.slice(2)).then((code) => process.exit(code), (err: Error) => {
    process.stderr.write(`${err.message}\n`);
    process.exit(1);
  });
}
