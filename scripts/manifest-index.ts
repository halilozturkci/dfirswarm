/**
 * A sealed manifest's head and index: what answers "is this file in that
 * job's output, and what is its sha256" without reading the manifest.
 *
 *   <dir>/manifest.json         the record (evidence-store.ts sealTree); custody reads it whole
 *   <dir>/manifest.head.json    its sha256, size and totals, the tree's top-level entries, its first files
 *   <dir>/manifest.index.tsv    one line per file and per directory, sorted by name, searched by bisection
 *
 * The two files beside the manifest are made from it, at seal time and
 * again whenever they are missing or older than it (a store sealed before
 * they existed, a store copied elsewhere); a small manifest (under
 * INDEX_MIN_BYTES) has neither and is read whole. They are a way to find a line of
 * the manifest quickly, never the record: nothing that verifies a store
 * reads them, and a head that does not name the manifest that is there (by
 * size and time) is thrown away.
 *
 * The index, one line each, LF-ended, sorted by its first field as
 * JavaScript compares strings:
 *
 *   <path>\t<sha256>\t<bytes>\t<n>[\t<path_b64>]    a file; n is its place in the manifest's `files`;
 *                                                  path_b64 only where the name's bytes are not the path's
 *   <prefix>/\td\t<bytes>\t<files>                  every file whose path starts with <prefix>/
 *
 * A path is a manifest's shown name (no tab, no line break), so a tab ends
 * it. Nothing here needs the store: the hashing workers load this file too.
 */
import { createHash } from "node:crypto";
import { createReadStream } from "node:fs";
import { open, readFile, rename, stat, unlink, writeFile, type FileHandle } from "node:fs/promises";
import { basename, dirname, join } from "node:path";

/** The parts of a manifest the index is made from (evidence-store.ts `Manifest`). */
export type IndexedManifest = {
  job?: string;
  attempt?: number;
  sealed_at?: string;
  files: Array<{ path: string; path_b64: string; bytes: number; sha256: string }>;
  dirs?: Array<{ path: string }>;
  rejected?: unknown[];
  totals?: { files: number; bytes: number };
  copied?: true;
};

export type ManifestHead = {
  v: 1;
  /** The manifest this was made from: its sha256, and the size and time it is recognised by. */
  manifest: { sha256: string; bytes: number; mtime_ms: number };
  job: string;
  attempt: number;
  sealed_at: string;
  totals: { files: number; bytes: number };
  dirs: number;
  rejected: number;
  copied?: true;
  /** The tree's top-level entries, by name; at most TOP_MAX, `top_more` says how many are not listed. */
  top: Array<{ name: string; kind: "file" | "dir"; files: number; bytes: number }>;
  top_more: number;
  /** The manifest's first files, in its own order (the order the tree was walked in). */
  first: Array<{ path: string; bytes: number; sha256: string }>;
  /** Files whose name is not UTF-8: such a name read as UTF-8 is not in the index. */
  odd_names: number;
  index: { bytes: number; lines: number };
};

export type IndexedFile = { path: string; path_b64: string; sha256: string; bytes: number; n: number };
/** A file as the stream of the whole index gives it: `path_b64` only where the name's bytes are not the path's. */
export type IndexedRow = Omit<IndexedFile, "path_b64"> & { path_b64?: string };

/** A sealed manifest, asked one line at a time. */
export type ManifestView = {
  head: ManifestHead;
  /** The file one of these paths names (a manifest's shown path, exactly); the earliest in the manifest when several do. */
  file(paths: readonly string[]): Promise<IndexedFile | null>;
  /** Every file under a directory, counted: null when no file's path starts with `<rel>/`. */
  dir(rel: string): Promise<{ files: number; bytes: number } | null>;
  /** Every file, sorted by path, read as a stream and handed on a piece of the index at a time. */
  files(): AsyncGenerator<IndexedRow[]>;
};

export const TOP_MAX = 200;
export const FIRST_MAX = 50;
/** A manifest smaller than this has no head and no index: it is read whole, which costs less than keeping two more files right. */
export const INDEX_MIN_BYTES = 256 * 1024;
/** A manifest larger than this is indexed in a worker thread, not where it is asked for. */
export const INLINE_BUILD_MAX_BYTES = 4 * 1024 * 1024;

/** What the index read from disk, for a test to hold it to. */
export const indexStats = { reads: 0, bytes: 0, builds: 0 };

export function headPath(manifestPath: string): string {
  return join(dirname(manifestPath), `${basename(manifestPath).replace(/\.json$/, "")}.head.json`);
}

export function indexPath(manifestPath: string): string {
  return join(dirname(manifestPath), `${basename(manifestPath).replace(/\.json$/, "")}.index.tsv`);
}

/**
 * The head and the index of a manifest, from its parsed form. Throws when a
 * path could not be a line's first field (a tab or a line break in it, which
 * a sealed manifest never has): such a manifest is answered from memory.
 */
export function buildIndex(manifest: IndexedManifest, of: { sha256: string; bytes: number; mtime_ms: number }): { head: ManifestHead; index: string } {
  const files = Array.isArray(manifest.files) ? manifest.files : [];
  const lines: string[] = [];
  const under = new Map<string, { files: number; bytes: number }>();
  const topFiles: ManifestHead["top"] = [];
  let odd = 0;
  let total = 0;
  for (let n = 0; n < files.length; n += 1) {
    const f = files[n];
    if (typeof f?.path !== "string" || typeof f.sha256 !== "string" || /[\t\n\r]/.test(f.path) || f.path === "" || f.path.endsWith("/")) throw new Error(`file ${n} has no indexable path`);
    const bytes = Number(f.bytes) || 0;
    total += bytes;
    const raw = Buffer.from(String(f.path_b64 ?? ""), "base64");
    const plain = raw.toString("utf8") === f.path;
    if (!plain && !Buffer.from(raw.toString("utf8"), "utf8").equals(raw)) odd += 1;
    lines.push(`${f.path}\t${f.sha256}\t${bytes}\t${n}${plain ? "" : `\t${raw.toString("base64")}`}`);
    let at = f.path.indexOf("/");
    if (at < 0) topFiles.push({ name: f.path, kind: "file", files: 1, bytes });
    for (; at >= 0; at = f.path.indexOf("/", at + 1)) {
      const prefix = f.path.slice(0, at + 1);
      const sum = under.get(prefix);
      if (sum) {
        sum.files += 1;
        sum.bytes += bytes;
      } else under.set(prefix, { files: 1, bytes });
    }
  }
  const top = [...topFiles];
  for (const [prefix, sum] of under) {
    lines.push(`${prefix}\td\t${sum.bytes}\t${sum.files}`);
    if (prefix.indexOf("/") === prefix.length - 1) top.push({ name: prefix.slice(0, -1), kind: "dir", files: sum.files, bytes: sum.bytes });
  }
  // A top-level directory with no file under it is still an entry of the tree.
  for (const d of manifest.dirs ?? []) if (typeof d?.path === "string" && !d.path.includes("/") && !under.has(`${d.path}/`)) top.push({ name: d.path, kind: "dir", files: 0, bytes: 0 });
  top.sort((a, b) => (a.name < b.name ? -1 : a.name > b.name ? 1 : 0));
  // A tab sorts before every character a path holds, so sorting the lines sorts them by path.
  lines.sort();
  const index = lines.length ? `${lines.join("\n")}\n` : "";
  const head: ManifestHead = {
    v: 1,
    manifest: of,
    job: String(manifest.job ?? ""),
    attempt: Number(manifest.attempt) || 0,
    sealed_at: String(manifest.sealed_at ?? ""),
    totals: { files: Number(manifest.totals?.files ?? files.length), bytes: Number(manifest.totals?.bytes ?? total) },
    dirs: manifest.dirs?.length ?? 0,
    rejected: manifest.rejected?.length ?? 0,
    ...(manifest.copied ? { copied: true as const } : {}),
    top: top.slice(0, TOP_MAX),
    top_more: Math.max(0, top.length - TOP_MAX),
    first: files.slice(0, FIRST_MAX).map((f) => ({ path: f.path, bytes: Number(f.bytes) || 0, sha256: f.sha256 })),
    odd_names: odd,
    index: { bytes: Buffer.byteLength(index), lines: lines.length },
  };
  return { head, index };
}

async function writeBeside(path: string, text: string): Promise<void> {
  const tmp = join(dirname(path), `.${basename(path)}.${process.pid}.${Math.random().toString(36).slice(2)}.tmp`);
  try {
    await writeFile(tmp, text, { mode: 0o444 });
    await rename(tmp, path);
  } catch (err) {
    await unlink(tmp).catch(() => undefined);
    throw err;
  }
}

/** Write a manifest's head and index beside it: the index first, so a head that is there names an index that is. */
export async function writeIndex(manifestPath: string, built: { head: ManifestHead; index: string }): Promise<void> {
  await writeBeside(indexPath(manifestPath), built.index);
  await writeBeside(headPath(manifestPath), `${JSON.stringify(built.head)}\n`);
}

/** Read a manifest whole and write its head and index (a worker thread's job when the manifest is large). */
export async function indexManifestFile(manifestPath: string): Promise<{ head: ManifestHead; index: string }> {
  const st = await stat(manifestPath);
  const text = await readFile(manifestPath);
  const built = buildIndex(JSON.parse(text.toString("utf8")) as IndexedManifest, { sha256: createHash("sha256").update(text).digest("hex"), bytes: st.size, mtime_ms: st.mtimeMs });
  indexStats.builds += 1;
  await writeIndex(manifestPath, built);
  return built;
}

function parseLine(line: string): IndexedRow | { dir: string; files: number; bytes: number } | null {
  const p = line.split("\t");
  if (p.length < 4) return null;
  if (p[1] === "d") return { dir: p[0], bytes: Number(p[2]), files: Number(p[3]) };
  return p.length > 4 ? { path: p[0], sha256: p[1], bytes: Number(p[2]), n: Number(p[3]), path_b64: p[4] } : { path: p[0], sha256: p[1], bytes: Number(p[2]), n: Number(p[3]) };
}

const BLOCK = 4096;
/** A range this small is read whole and searched line by line. */
const SCAN = 8192;

/** The line whose first field is `key`, found by bisection over the file's bytes: a few blocks read, never the file. */
async function findLine(fh: FileHandle, size: number, key: string): Promise<string | null> {
  const blocks = new Map<number, Buffer>();
  const block = async (i: number): Promise<Buffer> => {
    let b = blocks.get(i);
    if (!b) {
      b = Buffer.allocUnsafe(Math.min(BLOCK, size - i * BLOCK));
      const { bytesRead } = await fh.read(b, 0, b.length, i * BLOCK);
      indexStats.reads += 1;
      indexStats.bytes += bytesRead;
      if (bytesRead < b.length) b = b.subarray(0, bytesRead);
      blocks.set(i, b);
    }
    return b;
  };
  /** The first line break at or after `pos`, or -1. */
  const breakFrom = async (pos: number): Promise<number> => {
    for (let i = Math.floor(pos / BLOCK); i * BLOCK < size; i += 1) {
      const b = await block(i);
      const at = b.indexOf(0x0a, Math.max(0, pos - i * BLOCK));
      if (at >= 0) return i * BLOCK + at;
      if (!b.length) break;
    }
    return -1;
  };
  const bytes = async (from: number, to: number): Promise<Buffer> => {
    const parts: Buffer[] = [];
    for (let i = Math.floor(from / BLOCK); i * BLOCK < to; i += 1) {
      const b = await block(i);
      parts.push(b.subarray(Math.max(0, from - i * BLOCK), Math.min(b.length, to - i * BLOCK)));
    }
    return parts.length === 1 ? parts[0] : Buffer.concat(parts);
  };
  /** The line that starts at `start`: its text and where the next one starts. */
  const lineAt = async (start: number): Promise<{ text: string; next: number }> => {
    const nl = await breakFrom(start);
    const end = nl < 0 ? size : nl;
    return { text: (await bytes(start, end)).toString("utf8"), next: end + 1 };
  };
  const keyOf = (text: string) => {
    const tab = text.indexOf("\t");
    return tab < 0 ? text : text.slice(0, tab);
  };
  // The line sought starts in [lo, hi); lo is always the start of a line.
  let lo = 0;
  let hi = size;
  while (hi - lo > SCAN) {
    const mid = lo + ((hi - lo) >> 1);
    const nl = await breakFrom(mid);
    // No line starts after mid and before hi: what is left starts at or before mid.
    if (nl < 0 || nl + 1 >= hi) {
      hi = mid + 1;
      continue;
    }
    const line = await lineAt(nl + 1);
    const k = keyOf(line.text);
    if (k === key) return line.text;
    if (k < key) lo = line.next;
    else hi = nl + 1;
  }
  for (let at = lo; at < hi && at < size; ) {
    const line = await lineAt(at);
    const k = keyOf(line.text);
    if (k === key) return line.text;
    if (k > key) return null;
    at = line.next;
  }
  return null;
}

function fileView(manifestPath: string, head: ManifestHead): ManifestView {
  const ix = indexPath(manifestPath);
  const lookup = async (keys: readonly string[]): Promise<string[]> => {
    if (!head.index.bytes) return [];
    const fh = await open(ix, "r");
    try {
      const out: string[] = [];
      for (const key of keys) {
        const line = /[\t\n\r]/.test(key) || key === "" ? null : await findLine(fh, head.index.bytes, key);
        if (line !== null) out.push(line);
      }
      return out;
    } finally {
      await fh.close();
    }
  };
  return {
    head,
    async file(paths) {
      let best: IndexedRow | null = null;
      for (const line of await lookup([...new Set(paths)].filter((p) => !p.endsWith("/")))) {
        const f = parseLine(line);
        if (f && "path" in f && (!best || f.n < best.n)) best = f;
      }
      return best ? { ...best, path_b64: best.path_b64 ?? Buffer.from(best.path, "utf8").toString("base64") } : null;
    },
    async dir(rel) {
      const d = (await lookup([`${rel.replace(/\/+$/, "")}/`])).map(parseLine)[0];
      return d && "dir" in d ? { files: d.files, bytes: d.bytes } : null;
    },
    async *files() {
      if (!head.index.bytes) return;
      let rest = "";
      for await (const chunk of createReadStream(ix, { encoding: "utf8", highWaterMark: 1 << 20 })) {
        const text = rest + (chunk as string);
        const rows: IndexedRow[] = [];
        let at = 0;
        for (let nl = text.indexOf("\n", at); nl >= 0; nl = text.indexOf("\n", at)) {
          const f = parseLine(text.slice(at, nl));
          if (f && "path" in f) rows.push(f);
          at = nl + 1;
        }
        rest = text.slice(at);
        if (rows.length) yield rows;
      }
    },
  };
}

/** The same answers from a manifest held in memory: where no index can be written or the manifest cannot have one. */
export function memoryView(manifest: IndexedManifest, of: { sha256: string; bytes: number; mtime_ms: number }): ManifestView {
  // A manifest some other hand wrote may hold anything in `files`: what is not a file with a path is not one.
  const all = Array.isArray(manifest.files) ? manifest.files : [];
  const rows: IndexedFile[] = [];
  for (let n = 0; n < all.length; n += 1) {
    const f = all[n];
    if (f && typeof f === "object" && typeof f.path === "string") rows.push({ path: f.path, path_b64: String(f.path_b64 ?? Buffer.from(f.path, "utf8").toString("base64")), sha256: String(f.sha256 ?? ""), bytes: Number(f.bytes) || 0, n });
  }
  let head: ManifestHead;
  try {
    head = buildIndex(manifest, of).head;
  } catch {
    head = { v: 1, manifest: of, job: String(manifest.job ?? ""), attempt: Number(manifest.attempt) || 0, sealed_at: String(manifest.sealed_at ?? ""), totals: { files: Number(manifest.totals?.files ?? rows.length), bytes: Number(manifest.totals?.bytes ?? rows.reduce((a, f) => a + f.bytes, 0)) }, dirs: manifest.dirs?.length ?? 0, rejected: manifest.rejected?.length ?? 0, top: [], top_more: 0, first: rows.slice(0, FIRST_MAX).map((f) => ({ path: f.path, bytes: f.bytes, sha256: f.sha256 })), odd_names: rows.length, index: { bytes: 0, lines: 0 } };
  }
  return {
    head,
    async file(paths) {
      return rows.find((f) => paths.includes(f.path)) ?? null;
    },
    async dir(rel) {
      const prefix = `${rel.replace(/\/+$/, "")}/`;
      const inside = rows.filter((f) => f.path.startsWith(prefix));
      return inside.length ? { files: inside.length, bytes: inside.reduce((a, f) => a + f.bytes, 0) } : null;
    },
    async *files() {
      if (rows.length) yield [...rows].sort((a, b) => (a.path < b.path ? -1 : a.path > b.path ? 1 : 0));
    },
  };
}

const heads = new Map<string, ManifestHead>();
const HEADS_MAX = 256;
const building = new Map<string, Promise<ManifestView | null>>();

/** A head that names the manifest that is there now, and an index of the size it says; else null. */
async function currentHead(manifestPath: string, st: { size: number; mtimeMs: number }): Promise<ManifestHead | null> {
  const fits = (h: ManifestHead | undefined | null): h is ManifestHead => Boolean(h && h.v === 1 && h.manifest?.bytes === st.size && h.manifest.mtime_ms === st.mtimeMs && typeof h.index?.bytes === "number");
  const kept = heads.get(manifestPath);
  let head: ManifestHead | null = fits(kept) ? kept : null;
  if (!head) {
    try {
      const text = await readFile(headPath(manifestPath), "utf8");
      indexStats.reads += 1;
      indexStats.bytes += Buffer.byteLength(text);
      const read = JSON.parse(text) as ManifestHead;
      head = fits(read) ? read : null;
    } catch {
      head = null;
    }
  }
  if (!head) {
    heads.delete(manifestPath);
    return null;
  }
  const ix = await stat(indexPath(manifestPath)).catch(() => null);
  if (!ix || ix.size !== head.index.bytes) {
    heads.delete(manifestPath);
    return null;
  }
  if (heads.size >= HEADS_MAX && !heads.has(manifestPath)) heads.delete(heads.keys().next().value as string);
  heads.set(manifestPath, head);
  return head;
}

/** Tests only: forget every head held in memory. */
export function forgetHeads(): void {
  heads.clear();
}

/**
 * A sealed manifest, to be asked a file or a directory at a time: from its
 * head and index where they are current, made now where they are not (in a
 * worker thread when the manifest is large; `inWorker` runs it), and from
 * the manifest in memory where they cannot be written. Null when there is
 * no manifest, or it is not one.
 */
export async function manifestView(manifestPath: string, inWorker?: (manifestPath: string) => Promise<void>): Promise<ManifestView | null> {
  const st = await stat(manifestPath).catch(() => null);
  if (!st?.isFile()) return null;
  if (st.size < INDEX_MIN_BYTES) {
    try {
      const text = await readFile(manifestPath);
      const manifest = JSON.parse(text.toString("utf8")) as IndexedManifest;
      if (!manifest || typeof manifest !== "object" || !Array.isArray(manifest.files)) return null;
      return memoryView(manifest, { sha256: createHash("sha256").update(text).digest("hex"), bytes: st.size, mtime_ms: st.mtimeMs });
    } catch {
      return null;
    }
  }
  const head = await currentHead(manifestPath, st);
  if (head) return fileView(manifestPath, head);
  const key = `${manifestPath}:${st.size}:${st.mtimeMs}`;
  let making = building.get(key);
  if (!making) {
    making = (async (): Promise<ManifestView | null> => {
      if (inWorker && st.size > INLINE_BUILD_MAX_BYTES) {
        try {
          await inWorker(manifestPath);
          const made = await currentHead(manifestPath, st);
          if (made) return fileView(manifestPath, made);
        } catch {
          // read here instead
        }
      }
      let text: Buffer;
      let manifest: IndexedManifest;
      try {
        text = await readFile(manifestPath);
        manifest = JSON.parse(text.toString("utf8")) as IndexedManifest;
        if (!manifest || typeof manifest !== "object" || !Array.isArray(manifest.files)) return null;
      } catch {
        return null;
      }
      const of = { sha256: createHash("sha256").update(text).digest("hex"), bytes: st.size, mtime_ms: st.mtimeMs };
      try {
        const built = buildIndex(manifest, of);
        indexStats.builds += 1;
        await writeIndex(manifestPath, built);
        heads.set(manifestPath, built.head);
        return fileView(manifestPath, built.head);
      } catch {
        // A store that cannot be written to (a package, a read-only copy), or a manifest no index can hold.
        return memoryView(manifest, of);
      }
    })().finally(() => building.delete(key));
    building.set(key, making);
  }
  return making;
}
