/**
 * The evidence-work store: what tool jobs produce, kept independent of where
 * they ran, and the journal that says how every object came to be.
 *
 *   <sandbox>/store/journal.jsonl         every evidence-work event, hash-chained
 *   <sandbox>.journal-anchor.json         the chain's head, out of every VM's reach
 *   <sandbox>/store/jobs/<id>/out/…       a job's committed outputs, read-only
 *   <sandbox>/store/jobs/<id>/manifest.json   every file: name bytes, size, sha256
 *   <sandbox>/store/blobs/<sha256>        each file's bytes once (hard links)
 *   <sandbox>/store/imports/<id>/…        a brain's own file brought in
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
import { createHash } from "node:crypto";
import { createReadStream, existsSync, readFileSync } from "node:fs";
import { chmod, copyFile, link, lstat, mkdir, open, readdir, readFile, readlink, rename, rm, stat, unlink, writeFile } from "node:fs/promises";
import { basename, dirname, join, relative, resolve } from "node:path";
import { createInterface } from "node:readline";
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
    for (const name of names) {
      const r = joinB(rel, name);
      const full = Buffer.concat([rootB, Buffer.from("/"), r]);
      const st = await lstat(full).catch(() => null);
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

/**
 * Seal a fenced job's staging directory into the store: links, devices,
 * FIFOs and sockets are recorded and left out (never followed); the tree is
 * moved (renamed, or copied when staging is on another file system) to
 * `dest`, every file hashed there — after its producer is gone, never live —
 * made read-only, and hard-linked to store/blobs/<sha256> so the same bytes
 * are kept once however many jobs produce them. The manifest names every
 * file by its exact bytes and a readable form.
 */
export async function sealTree(sandbox: string, staging: string, dest: string, job: string, attempt: number, manifestPath = join(dirname(dest), "manifest.json")): Promise<{ manifest: Manifest; manifestSha256: string }> {
  const P = storePaths(sandbox);
  const rootSt = await lstat(staging).catch(() => null);
  if (!rootSt || !rootSt.isDirectory()) throw new Error(`the staging directory ${staging} is not a directory`);
  const entries = await walk(staging);
  const rejected: ManifestRejected[] = [];
  for (const e of entries.filter((x) => x.kind === "reject")) {
    rejected.push({ path: shownName(e.rel), path_b64: e.rel.toString("base64"), kind: e.how ?? "other", ...(e.link ? { link_b64: e.link.toString("base64"), link: shownName(e.link) } : {}) });
    const p = Buffer.concat([Buffer.from(staging), Buffer.from("/"), e.rel]);
    if (e.how?.startsWith("unreadable directory")) await rm(p, { recursive: true, force: true }).catch(() => undefined);
    else await unlink(p).catch(() => undefined);
  }
  const kept = entries.filter((x) => x.kind !== "reject");
  await mkdir(dirname(dest), { recursive: true });
  let copied = false;
  const stagingDev = (await stat(staging)).dev;
  const destDev = (await stat(dirname(dest))).dev;
  if (existsSync(dest)) throw new Error(`${dest} exists already`);
  if (stagingDev === destDev) {
    await rename(staging, dest);
  } else {
    await copyTree(staging, dest, kept);
    copied = true;
  }
  maybeCrash("seal:moved");
  await mkdir(P.blobs, { recursive: true });
  const files: ManifestFile[] = [];
  const dirs: Array<{ path: string; path_b64: string }> = [];
  let total = 0;
  for (const e of kept) {
    const full = Buffer.concat([Buffer.from(dest), Buffer.from("/"), e.rel]);
    if (e.kind === "dir") {
      dirs.push({ path: shownName(e.rel), path_b64: e.rel.toString("base64") });
      continue;
    }
    await chmod(full, 0o644).catch(() => undefined);
    let sha: string;
    try {
      sha = await sha256File(full);
    } catch (err) {
      rejected.push({ path: shownName(e.rel), path_b64: e.rel.toString("base64"), kind: `unreadable file (${(err as NodeJS.ErrnoException).code ?? "error"})` });
      continue;
    }
    const st = await stat(full);
    await chmod(full, 0o444);
    const blob = join(P.blobs, sha);
    try {
      if (existsSync(blob)) {
        // The same bytes are already kept: this occurrence becomes a link to them.
        if ((await stat(blob)).size === st.size && (await stat(blob)).ino !== st.ino) {
          await unlink(full);
          await link(blob, full);
        }
      } else {
        await link(full, blob);
      }
    } catch {
      // A file system without hard links keeps the occurrence as its own copy.
    }
    files.push({ path: shownName(e.rel), path_b64: e.rel.toString("base64"), bytes: st.size, sha256: sha, mode: (e.mode ?? 0o644).toString(8) });
    total += st.size;
  }
  // Directories read-only from the deepest up.
  for (const e of [...kept].filter((x) => x.kind === "dir").reverse()) {
    await chmod(Buffer.concat([Buffer.from(dest), Buffer.from("/"), e.rel]), 0o555).catch(() => undefined);
  }
  await chmod(dest, 0o555);
  const manifest: Manifest = {
    v: 1,
    job,
    attempt,
    sealed_at: new Date().toISOString(),
    files,
    dirs,
    rejected,
    totals: { files: files.length, bytes: total },
    ...(copied ? { copied: true as const } : {}),
  };
  // Compact: a materialised tree of a hundred thousand files is read back
  // whenever one of them is cited.
  const text = `${JSON.stringify(manifest)}\n`;
  await writeDurable(manifestPath, text, 0o444);
  if (copied) await rm(staging, { recursive: true, force: true }).catch(() => undefined);
  return { manifest, manifestSha256: sha256Hex(text) };
}

/** A tree already moved into the store (a crash after the move): hash it again and write its manifest. */
export async function resealMoved(sandbox: string, dest: string, job: string, attempt: number, manifestPath = join(dirname(dest), "manifest.json")): Promise<{ manifest: Manifest; manifestSha256: string }> {
  // Make it writable again so the same seal can run over it in place.
  const entries = await walk(dest);
  await chmod(dest, 0o755).catch(() => undefined);
  for (const e of entries) await chmod(Buffer.concat([Buffer.from(dest), Buffer.from("/"), e.rel]), e.kind === "dir" ? 0o755 : 0o644).catch(() => undefined);
  const tmp = `${dest}.reseal`;
  await rename(dest, tmp);
  return sealTree(sandbox, tmp, dest, job, attempt, manifestPath);
}

export async function readManifest(path: string): Promise<{ manifest: Manifest; sha256: string } | null> {
  try {
    const text = await readFile(path, "utf8");
    return { manifest: JSON.parse(text) as Manifest, sha256: sha256Hex(text) };
  } catch {
    return null;
  }
}

// --- object references -------------------------------------------------------------

export type Resolved =
  | { ok: true; ref: string; kind: "input" | "job" | "import" | "member" | "sha256" | "unresolved"; sha256?: string; bytes?: number; path?: string; why?: string; status?: string }
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
 * `unresolved:<why>` (said, not resolved).
 */
export async function resolveRef(sandbox: string, ref: string, opts: ResolveOptions = {}): Promise<Resolved> {
  const S = resolve(sandbox);
  const P = storePaths(S);
  const m = /^([a-z0-9]+):(.*)$/s.exec(ref.trim());
  if (!m) return { ok: false, ref, reason: "a reference is kind:value (input:, job:, import:, member:, sha256:, unresolved:)" };
  const [, kind, value] = m;
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
    const found = await readManifest(join(kind === "job" ? P.jobs : P.imports, id, "manifest.json"));
    if (!found) return { ok: false, ref, reason: `${kind} ${id} has no sealed manifest` };
    const base = `${kind === "job" ? "store/jobs" : "store/imports"}/${id}`;
    // A job's own outcome travels with what it left: a failed job's kept output is citable, and said to be.
    const status = kind === "job" ? await jobStatus(join(P.jobs, id)) : undefined;
    const st0 = status ? { status } : {};
    if (!rel) return { ok: true, ref, kind, path: `${base}/out`, bytes: found.manifest.totals.bytes, ...st0 };
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
    const f = found.manifest.files.find((x) => want.some((w) => x.path === w || Buffer.from(x.path_b64, "base64").toString("utf8") === w));
    return f ? { ok: true, ref, kind, sha256: f.sha256, bytes: f.bytes, path: `${base}/out/${f.path}`, ...st0 } : { ok: false, ref, reason: `${rel} is not in ${kind} ${id}'s manifest` };
  }
  if (kind === "member") {
    const mm = /^([a-z0-9-]+)#(\d+)$/.exec(value);
    if (!mm) return { ok: false, ref, reason: "member:<generation>#<n>" };
    const tsv = join(P.gen, mm[1], "members.tsv");
    if (!existsSync(tsv)) return { ok: false, ref, reason: `generation ${mm[1]} has no member list` };
    // Read as it streams, stopping at the row: a phone's list is millions of lines.
    const found = await new Promise<boolean>((done) => {
      const rl = createInterface({ input: createReadStream(tsv), crlfDelay: Infinity });
      let hit = false;
      rl.on("line", (l) => {
        if (!hit && l.startsWith(`${mm[2]}\t`)) {
          hit = true;
          rl.close();
        }
      });
      rl.on("close", () => done(hit));
      rl.on("error", () => done(false));
    });
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
  g: { job: string; recipe: string; recipe_sha256: string; target: Generation["target"]; experimental?: boolean; parent?: string; alias?: string; trigger?: Generation["trigger"]; parent_status?: string },
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
    files.push({ path: `catalog/gen/${id}/${f}`, what: what.join("\t"), rows: await rowsOf(p), bytes: st.size });
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
  try {
    plan = (JSON.parse(readFileSync(join(S, "catalog", "plan.json"), "utf8")) as { recipes?: typeof plan }).recipes ?? [];
  } catch {
    plan = [];
  }
  const collections = new Map<string, string[]>();
  for (const r of plan) {
    const paths = (r.target?.paths ?? []).map((p) => relative(S, p));
    if (paths.length > 1) collections.set(r.input, paths);
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
  /** What each job was given and could reach, and whether what it read is known: the store records declared and accessible; observed is unknown unless a tool reports it. */
  access?: { jobs: number; declared: number; observed_unknown: number };
  /** Notes an examiner added to the record after the run (evidence-store.ts note), and the times the job service told the agents that workers were not running. */
  notes: number;
  degraded: number;
  /** Each revision's MANIFEST.json and its index files, and each generation.json, held to the journal's lines. */
  catalogue: { revisions_verified: number; revisions_mismatched: string[]; generations_verified: number; generations_mismatched: string[] };
  /** The derived catalogue, from its journal lines: objects offered and skipped, answered, catalogued, left unanswered, and each limit it met. */
  derived: { offered: number; skipped: number; detected: number; applied: number; catalogued: number; partial: number; unanswered: number; deferred: number; bounded: string[] };
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
    derived: { offered: 0, skipped: 0, detected: 0, applied: 0, catalogued: 0, partial: 0, unanswered: count("detect_unanswered"), deferred: count("derived_deferred"), bounded: [] },
  };
  for (const l of checked.lines) {
    if (l.type === "derived_offered") {
      out.derived.offered += ((l.offered as unknown[]) ?? []).length;
      out.derived.skipped += ((l.skipped as unknown[]) ?? []).length;
    } else if (l.type === "detect_answered") {
      const rows = (l.rows as Array<{ applies?: boolean }>) ?? [];
      out.derived.detected += rows.length;
      out.derived.applied += rows.filter((r) => r.applies).length;
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
  out.access = { jobs: started.length, declared: started.filter((l) => Array.isArray(l.declared) && (l.declared as unknown[]).length > 0).length, observed_unknown: started.filter((l) => l.observed === "unknown" || l.observed === undefined).length };
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
    out.staging_left = (await readdir(P.staging)).sort();
  } catch {
    out.staging_left = [];
  }
  return out;
}

/**
 * An examiner's note appended to a run's journal: a correction or an
 * observation about the record, attributed and chained like every other
 * line, never an edit of one. Only with no hub running, the store's writer
 * during a run.
 */
export async function appendNote(sandbox: string, note: { by: string; text: string; jobs?: string[] }): Promise<number> {
  if (!note.by.trim() || !note.text.trim()) throw new Error("a note needs --by and --text");
  const pidFile = join(resolve(sandbox), "hub.pid");
  if (existsSync(pidFile)) {
    const pid = Number(readFileSync(pidFile, "utf8").trim());
    let alive = false;
    try {
      alive = Number.isInteger(pid) && pid > 0 && process.kill(pid, 0);
    } catch {
      alive = false;
    }
    if (alive) throw new Error(`the run's hub (pid ${pid}) is the store's writer while it runs: add the note after the run`);
  }
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
