/**
 * A job's declared scope, enforced (ADR 0010, "A job sees what it declared").
 *
 * An agent says what a job reads (`inputs`). Left out, the job sees every
 * object of the run, as jobs always did, and the record says it was the
 * default (`default-all`); `["all"]` is the same view, said (`all`); a list,
 * empty or not, is the job's declared scope (`declared`), and its worker is
 * given that and nothing else: a view the hub builds for the job outside
 * every VM's reach, holding the declared objects at the paths its brain sees
 * them, with what they need beside them (the rest of a segment set, as the
 * census recorded it: nothing here knows a format), the reviewed code
 * (tools/, the packs), and its own $OUT and control directory. A declaration
 * that does not resolve refuses the job with the reason: there is no broad
 * fallback.
 *
 * How an object gets into a view, by what it is:
 * - The evidence: a declared directory is bound whole, read-only and
 *   no-exec, and so is an evidence set, or any directory of it, whose every
 *   name inputs.json lists is in the scope (the common case: a set of one
 *   image, or of one image's segments; nothing beside them is shown). Only
 *   a scope that covers part of one is given file by file: each file cloned
 *   from a descriptor (APFS clonefile, a reflink), or, where the file system
 *   cannot clone, linked from one copy the hub made for the run and checked
 *   against inputs.json. Never a hard link to the evidence itself: its link
 *   count and ctime are the examiner's, and the inputs guard counts a second
 *   name as a change.
 * - The store and the catalogue (sealed, read-only): a job's whole output or a
 *   generation is bound; a file is linked, cloned or copied.
 * - A work file (an agent's live scratch, tool-output/): opened without
 *   following a link, cloned or copied from that descriptor, the path checked
 *   to still name the same file afterwards, and hashed: a snapshot the job
 *   reads while the live file goes on changing. Never a hard link.
 *
 * What was declared, what it expanded to and what the worker could reach are
 * recorded apart (the job's scope manifest, its sha256 on job_started).
 */
import { spawn } from "node:child_process";
import { createHash, randomBytes } from "node:crypto";
import { constants, statfsSync } from "node:fs";
import { chmod, link, lstat, mkdir, open, readdir, readFile, realpath, rename, rm, stat, writeFile, type FileHandle } from "node:fs/promises";
import { dirname, join, relative, resolve } from "node:path";
import { manifestFile, manifestOf, readManifest, storePaths } from "./evidence-store.ts";
import type { Mount } from "./vm.ts";

/** declared: the worker sees what the job named; all: everything, said; default-all: everything, because nothing was said. */
export type ScopeKind = "declared" | "all" | "default-all";

/** The most objects one job may name; past it, name the directory or the job output that holds them. */
export const SCOPE_DECLARED_MAX = 256;

/**
 * Directories bound whole into one worker (each is a share of its own). Past
 * it a declared directory of the store is linked in file by file; one of the
 * evidence is refused, since copying a disk image per job is not an option.
 */
export const SCOPE_DIR_BINDS_MAX = 8;

/** Where a view is built beside a job's staging directory. */
export const VIEW_DIR = "view";

/** The run's one copy of an input that cannot be cloned, under the staging root (a dot name: not a job's). */
export const PROJECTED_DIR = ".projected";

/** A refusal: said to the agent, or recorded as the reason the job did not run. */
export class ScopeError extends Error {}

/**
 * What `inputs` says, kept apart: left out, `["all"]`, or a list of what the
 * job reads (possibly empty). Refused when it is none of the three.
 */
export function declaredScope(raw: unknown): { kind: ScopeKind; inputs: string[] } | { reason: string } {
  if (raw === undefined || raw === null) return { kind: "default-all", inputs: [] };
  const list = Array.isArray(raw) ? raw.map((x) => String(x).trim()) : typeof raw === "string" ? [raw.trim()] : null;
  if (!list) return { reason: 'inputs is the list of what the job reads (input:<path>, job:<id>[/<path>], work/<path>, …), or ["all"]' };
  if (list.some((x) => !x)) return { reason: "inputs names an empty entry" };
  if (list.length === 1 && list[0] === "all") return { kind: "all", inputs: ["all"] };
  if (list.includes("all")) return { reason: 'all stands alone: every object of the run (inputs: ["all"]), or the list of what the job reads' };
  if (list.length > SCOPE_DECLARED_MAX) return { reason: `inputs names ${list.length} objects, more than ${SCOPE_DECLARED_MAX}: declare the directory or the job output that holds them` };
  return { kind: "declared", inputs: list };
}

/** A job's scope as its spec records it; a job accepted before scopes were kept apart saw everything. */
export function scopeKindOf(spec: { scope?: ScopeKind }): ScopeKind {
  return spec.scope === "declared" || spec.scope === "all" ? spec.scope : "default-all";
}

// --- resolution -------------------------------------------------------------------------

export type ScopeArea = "inputs" | "store" | "catalog" | "work";

/** One object in a job's scope, as declared or as expanded from a declaration. */
export type ScopeObject = {
  /** How the job named it, or the declaration it was expanded from. */
  ref: string;
  /** Run-relative, readable: the worker sees it at <run>/<path>, where its brain sees it. */
  path: string;
  /** The name's bytes, base64, when they are not UTF-8 (as inputs.json and the manifests keep them). */
  path_b64?: string;
  area: ScopeArea;
  shape: "file" | "dir";
  /** declared, a recipe's target, or what it was expanded from and why. */
  from: string;
  /** As the record has it: inputs.json, the store's manifest. A work file is hashed when snapshotted. */
  sha256?: string;
  bytes?: number;
  /** A directory: how many files the record lists under it. */
  files?: number;
};

type InputRow = { path: string; path_b64?: string; sha256?: string; bytes?: number; link?: string; special?: string };
type InputsIndex = { key: string; rows: Map<string, InputRow>; sorted: string[]; sets: string[]; collections: string[][] };

let inputsCache: InputsIndex | null = null;

/**
 * inputs.json, indexed once while it does not change (a triage set's manifest
 * is hundreds of megabytes): every name by its path, the paths in order for a
 * directory's prefix, the sets and any collections it records.
 */
async function inputsIndex(S: string): Promise<InputsIndex> {
  const file = join(S, "inputs.json");
  const st = await stat(file).catch(() => null);
  const key = st ? `${file}:${st.size}:${st.mtimeMs}` : `${file}:none`;
  if (inputsCache?.key === key) return inputsCache;
  let parsed: { files?: InputRow[]; sets?: Array<{ name?: unknown }>; collections?: unknown } = {};
  if (st) {
    try {
      parsed = JSON.parse(await readFile(file, "utf8")) as typeof parsed;
    } catch {
      throw new ScopeError("inputs.json cannot be read: no input can be given to a job alone");
    }
  }
  const rows = new Map<string, InputRow>();
  for (const f of parsed.files ?? []) if (f && typeof f.path === "string") rows.set(f.path, f);
  const sets = (Array.isArray(parsed.sets) ? parsed.sets : []).map((s) => (s && typeof s.name === "string" ? s.name : "")).filter((n) => n && !n.includes("/") && n !== "." && n !== "..");
  // A collection inputs.json records itself: [{members}] or [[…]].
  const collections: string[][] = [];
  for (const c of Array.isArray(parsed.collections) ? parsed.collections : []) {
    const members = Array.isArray(c) ? c : c && typeof c === "object" && Array.isArray((c as { members?: unknown }).members) ? (c as { members: unknown[] }).members : [];
    const list = members.filter((m): m is string => typeof m === "string");
    if (list.length > 1) collections.push(list);
  }
  inputsCache = { key, rows, sorted: [...rows.keys()].sort(), sets, collections };
  return inputsCache;
}

/** The first index in a sorted list at or after `prefix`. */
function lowerBound(sorted: string[], prefix: string): number {
  let lo = 0;
  let hi = sorted.length;
  while (lo < hi) {
    const mid = (lo + hi) >> 1;
    if (sorted[mid] < prefix) lo = mid + 1;
    else hi = mid;
  }
  return lo;
}

/** Every path of a sorted list under a directory, in order. */
function under(sorted: string[], dir: string): string[] {
  const prefix = `${dir}/`;
  const out: string[] = [];
  for (let i = lowerBound(sorted, prefix); i < sorted.length && sorted[i].startsWith(prefix); i += 1) out.push(sorted[i]);
  return out;
}

type Located = { ref: string; area: ScopeArea; path: string; dir: boolean; sha?: string };

/**
 * Where a declaration points, by its words alone: `input:<path>`,
 * `job:<id>[/<path>]` (its whole output, a file or a directory of it, or its
 * sealed logs), `import:<id>[/<path>]`, `member:<generation>#<n>` (the
 * generation), `sha256:<hex>` (an input or a stored object by content), or a
 * path from the run's directory under inputs/, store/, catalog/, work/ or
 * tool-output/. A trailing slash names a directory.
 */
export function locate(text: string): Located | { reason: string } {
  const t = text.trim();
  if (t.includes("\0")) return { reason: `${JSON.stringify(t)} has a NUL byte` };
  let path: string;
  let dir = false;
  const m = /^([a-z0-9]+):(.*)$/s.exec(t);
  if (m) {
    const [, kind, v] = m;
    if (kind === "input") {
      const p = v.replace(/^\/+/, "");
      path = p === "" || p === "inputs" || p === "inputs/" ? "inputs/" : p.startsWith("inputs/") ? p : `inputs/${p}`;
    } else if (kind === "job" || kind === "import") {
      const slash = v.indexOf("/");
      const id = slash < 0 ? v : v.slice(0, slash);
      const rel = slash < 0 ? "" : v.slice(slash + 1);
      if (!/^[a-z0-9-]{1,64}$/.test(id)) return { reason: `${t}: ${id} is not a ${kind} id` };
      const base = `store/${kind === "job" ? "jobs" : "imports"}/${id}`;
      if (!rel || rel === "out" || rel === "out/") path = `${base}/out/`;
      else if (kind === "job" && /^(stdout\.log|stderr\.log|pip-before\.txt|pip-after\.txt)$/.test(rel)) path = `${base}/${rel}`;
      else path = `${base}/out/${rel.startsWith("out/") ? rel.slice(4) : rel}`;
    } else if (kind === "member") {
      const mm = /^([a-z0-9-]+)#\d+$/.exec(v);
      if (!mm) return { reason: `${t}: member:<generation>#<n>` };
      path = `catalog/gen/${mm[1]}/`;
    } else if (kind === "net") {
      // A capture the fetch service sealed: the whole of it, or one file.
      const nm = /^([1-9]\d{0,6})\/([1-9]\d{0,6})(?:\/(.+))?$/.exec(v);
      if (!nm) return { reason: `${t}: net:<k>/<n>[/<file>]` };
      path = nm[3] ? `store/net/${nm[1]}/${nm[2]}/${nm[3]}` : `store/net/${nm[1]}/${nm[2]}/`;
    } else if (kind === "sha256") {
      if (!/^[0-9a-f]{64}$/.test(v)) return { reason: `${t}: sha256: takes 64 hex digits` };
      return { ref: t, area: "store", path: `store/blobs/${v}`, dir: false, sha: v };
    } else {
      return { reason: `${t}: a job reads input:, job:, import:, member:, sha256: or net: objects, or a path under inputs/, store/, catalog/, work/ or tool-output/` };
    }
  } else {
    if (t.startsWith("/")) return { reason: `${t}: name it from the run's directory (inputs/…, store/…, catalog/…, work/…, tool-output/…)` };
    path = t.replace(/^(\.\/)+/, "");
    if (path === "inputs") path = "inputs/";
  }
  if (path.endsWith("/")) {
    dir = true;
    path = path.replace(/\/+$/, "");
  }
  const segs = path.split("/");
  if (segs.some((s) => s === "" || s === "." || s === "..")) return { reason: `${t}: a path with no empty, . or .. part` };
  const area: ScopeArea | null =
    segs[0] === "inputs" ? "inputs" : segs[0] === "store" && ["jobs", "imports", "blobs", "net"].includes(segs[1] ?? "") && segs.length >= 3 ? "store" : segs[0] === "catalog" ? "catalog" : (segs[0] === "work" || segs[0] === "tool-output") && segs.length >= 2 ? "work" : null;
  if (!area) return { reason: `${t}: a job reads the evidence (input:<path>), the store (job:<id>[/<path>], import:…, sha256:…), the catalogue (member:…, catalog/…) or a file or directory under work/<…> or tool-output/<…>` };
  return { ref: t, area, path, dir };
}

/** The run's evidence roots, resolved: inputs/ itself and each set held in place where its link leads. */
async function inputRoots(S: string, sets: string[]): Promise<string[]> {
  const roots: string[] = [];
  const top = await realpath(join(S, "inputs")).catch(() => null);
  if (top) roots.push(top);
  for (const name of sets) {
    const r = await realpath(join(S, "inputs", name)).catch(() => null);
    if (r && !roots.includes(r)) roots.push(r);
  }
  return roots;
}

function within(p: string, roots: string[]): boolean {
  return roots.some((r) => p === r || p.startsWith(`${r}/`));
}

/**
 * The directory a path's parents resolve to must be where the names say: a
 * link anywhere on the way (work/a1/sub -> /Users/…) would take the hub
 * somewhere no job may read.
 */
async function parentsAreDirect(S: string, rel: string): Promise<boolean> {
  const realS = await realpath(S);
  const parent = dirname(rel);
  const got = await realpath(join(S, parent)).catch(() => null);
  return got === (parent === "." ? realS : join(realS, parent));
}

/**
 * What a job's declarations name, resolved against the run's records: each
 * object with what inputs.json or the store says of it, the rest of an
 * input's segment set (from the store's `input_collection` lines, the
 * census's record, and any collection inputs.json lists), and a recipe's
 * target paths. The first declaration that does not resolve refuses the
 * whole: a scope is what was said, never more.
 */
export async function resolveScope(S: string, declared: string[], o: { collections?: string[][]; targets?: string[] } = {}): Promise<{ ok: true; objects: ScopeObject[] } | { ok: false; reason: string }> {
  try {
    return { ok: true, objects: await resolveObjects(resolve(S), declared, o) };
  } catch (err) {
    if (err instanceof ScopeError) return { ok: false, reason: err.message };
    throw err;
  }
}

async function resolveObjects(S: string, declared: string[], o: { collections?: string[][]; targets?: string[] }): Promise<ScopeObject[]> {
  const P = storePaths(S);
  const out = new Map<string, ScopeObject>();
  const add = (x: ScopeObject) => {
    if (!out.has(x.path)) out.set(x.path, x);
  };
  const wanted: Array<{ text: string; from: string }> = declared.map((text) => ({ text, from: "declared" }));
  for (const abs of o.targets ?? []) {
    const rel = relative(S, resolve(abs));
    if (rel.startsWith("..") || rel === "") throw new ScopeError(`the target ${abs} is not an object of this run`);
    wanted.push({ text: rel, from: "the recipe's target" });
  }
  let index: InputsIndex | null = null;
  const inputs = async () => (index ??= await inputsIndex(S));
  for (const w of wanted) {
    const at = locate(w.text);
    if ("reason" in at) throw new ScopeError(at.reason);
    if (at.area === "inputs") {
      const ix = await inputs();
      // The whole of the evidence: each set, where there are several.
      if (at.path === "inputs") {
        if (ix.sets.length) {
          for (const name of ix.sets) {
            const files = under(ix.sorted, `inputs/${name}`);
            add({ ref: at.ref, path: `inputs/${name}`, area: "inputs", shape: "dir", from: w.from === "declared" ? `every set of ${at.ref}` : w.from, files: files.length, bytes: files.reduce((a, p) => a + Number(ix.rows.get(p)?.bytes ?? 0), 0) });
          }
        } else {
          add({ ref: at.ref, path: "inputs", area: "inputs", shape: "dir", from: w.from, files: ix.sorted.length, bytes: ix.sorted.reduce((a, p) => a + Number(ix.rows.get(p)?.bytes ?? 0), 0) });
        }
        continue;
      }
      const row = at.dir ? undefined : ix.rows.get(at.path);
      if (row) {
        if (row.link !== undefined) throw new ScopeError(`${at.ref} is a link in the evidence (to ${row.link}): declare what it names`);
        if (row.special) throw new ScopeError(`${at.ref} is a ${row.special} in the evidence, not a file`);
        add({ ref: at.ref, path: at.path, ...(row.path_b64 ? { path_b64: row.path_b64 } : {}), area: "inputs", shape: "file", from: w.from, ...(row.sha256 ? { sha256: row.sha256 } : {}), bytes: Number(row.bytes ?? 0) });
        continue;
      }
      const files = under(ix.sorted, at.path);
      if (files.length) {
        add({ ref: at.ref, path: at.path, area: "inputs", shape: "dir", from: w.from, files: files.length, bytes: files.reduce((a, p) => a + Number(ix.rows.get(p)?.bytes ?? 0), 0) });
        continue;
      }
      const base = at.path.slice(at.path.lastIndexOf("/") + 1).toLowerCase();
      const near = ix.sorted.filter((p) => p.slice(p.lastIndexOf("/") + 1).toLowerCase() === base).slice(0, 5);
      throw new ScopeError(`${at.ref}: ${at.path} is not in inputs.json${near.length ? ` (the same name: ${near.map((p) => `input:${p.slice(7)}`).join(", ")})` : ""}`);
    }
    if (at.area === "store") {
      if (at.sha) {
        // By content: the evidence first (a job's copy of an input is the input), then the store's blobs.
        const ix = await inputs();
        const hit = ix.sorted.find((p) => ix.rows.get(p)?.sha256 === at.sha);
        if (hit) {
          const row = ix.rows.get(hit)!;
          add({ ref: at.ref, path: hit, ...(row.path_b64 ? { path_b64: row.path_b64 } : {}), area: "inputs", shape: "file", from: w.from, sha256: at.sha, bytes: Number(row.bytes ?? 0) });
          continue;
        }
        const st = await lstat(join(P.blobs, at.sha)).catch(() => null);
        if (!st?.isFile()) throw new ScopeError(`${at.ref}: no stored object or input has that sha256`);
        add({ ref: at.ref, path: at.path, area: "store", shape: "file", from: w.from, sha256: at.sha, bytes: st.size });
        continue;
      }
      const segs = at.path.split("/");
      if (segs[1] === "blobs") {
        const sha = segs[2] ?? "";
        const st = /^[0-9a-f]{64}$/.test(sha) && segs.length === 3 ? await lstat(join(P.blobs, sha)).catch(() => null) : null;
        if (!st?.isFile()) throw new ScopeError(`${at.ref}: not a stored object (store/blobs/<sha256>)`);
        add({ ref: at.ref, path: at.path, area: "store", shape: "file", from: w.from, sha256: sha, bytes: st.size });
        continue;
      }
      if (segs[1] === "net") {
        // A sealed capture (store/net/<k>/<n>/), by its own manifest.
        const base = segs.slice(0, 4).join("/");
        const found = segs.length >= 4 ? await readManifest(join(S, base, "manifest.json")) : null;
        if (!found) throw new ScopeError(`${at.ref}: no capture is sealed at ${base}`);
        if (segs.length === 4) {
          add({ ref: at.ref, path: base, area: "store", shape: "dir", from: w.from, files: found.manifest.totals.files, bytes: found.manifest.totals.bytes });
          continue;
        }
        const file = found.manifest.files.find((f) => f.path === segs.slice(4).join("/"));
        if (!file || at.dir) throw new ScopeError(`${at.ref}: the capture at ${base} has no ${segs.slice(4).join("/")}`);
        add({ ref: at.ref, path: `${base}/${file.path}`, area: "store", shape: "file", from: w.from, sha256: file.sha256, bytes: file.bytes });
        continue;
      }
      const kind = segs[1] as "jobs" | "imports";
      const id = segs[2];
      // Asked of the manifest's head and index (manifest-index.ts), never the manifest whole.
      const manifestPath = join(kind === "jobs" ? P.jobs : P.imports, id, "manifest.json");
      const found = await manifestOf(manifestPath);
      if (!found) throw new ScopeError(`${at.ref}: ${kind === "jobs" ? "job" : "import"} ${id} has no sealed output${kind === "jobs" ? " (not committed yet)" : ""}`);
      const base = `store/${kind}/${id}`;
      if (segs.length === 4 && segs[3] !== "out") {
        const st = await lstat(join(S, at.path)).catch(() => null);
        if (!st?.isFile()) throw new ScopeError(`${at.ref}: ${kind === "jobs" ? "job" : "import"} ${id} has no ${segs[3]}`);
        add({ ref: at.ref, path: at.path, area: "store", shape: "file", from: w.from, bytes: st.size });
        continue;
      }
      if (segs[3] !== "out") throw new ScopeError(`${at.ref}: a job's files are under ${base}/out/`);
      const rel = segs.slice(4).join("/");
      if (!rel) {
        add({ ref: at.ref, path: `${base}/out`, area: "store", shape: "dir", from: w.from, files: found.head.totals.files, bytes: found.head.totals.bytes });
        continue;
      }
      const file = at.dir ? null : await manifestFile(manifestPath, found, [rel]);
      if (file) {
        const utf8 = Buffer.from(file.path_b64, "base64").toString("utf8") === file.path;
        add({ ref: at.ref, path: `${base}/out/${file.path}`, ...(utf8 ? {} : { path_b64: Buffer.concat([Buffer.from(`${base}/out/`), Buffer.from(file.path_b64, "base64")]).toString("base64") }), area: "store", shape: "file", from: w.from, sha256: file.sha256, bytes: file.bytes });
        continue;
      }
      const inside = await found.dir(rel);
      if (!inside) throw new ScopeError(`${at.ref}: ${rel} is not in ${kind === "jobs" ? "job" : "import"} ${id}'s manifest`);
      add({ ref: at.ref, path: `${base}/out/${rel}`, area: "store", shape: "dir", from: w.from, files: inside.files, bytes: inside.bytes });
      continue;
    }
    // The catalogue and the agents' work: what is there now, by lstat, a link neither followed nor taken.
    const abs = join(S, at.path);
    if (!(await parentsAreDirect(S, at.path))) throw new ScopeError(`${at.ref}: a link on the way to ${at.path}: name the file where it is`);
    const st = await lstat(abs).catch(() => null);
    if (!st) throw new ScopeError(`${at.ref}: ${at.path} does not exist`);
    if (st.isSymbolicLink()) throw new ScopeError(`${at.ref}: ${at.path} is a link: name the file it names`);
    if (st.isDirectory()) {
      add({ ref: at.ref, path: at.path, area: at.area, shape: "dir", from: w.from });
      continue;
    }
    if (!st.isFile() || at.dir) throw new ScopeError(`${at.ref}: ${at.path} is not a regular file or a directory`);
    add({ ref: at.ref, path: at.path, area: at.area, shape: "file", from: w.from, bytes: st.size, ...(at.area === "catalog" ? await catalogSha(S, at.path) : {}) });
  }
  // The rest of an input's set, as the census recorded it (and inputs.json, when it lists collections).
  const groups = [...(o.collections ?? [])];
  if ([...out.values()].some((x) => x.area === "inputs")) groups.push(...(await inputs()).collections);
  if (groups.length) {
    const ix = await inputs();
    for (const x of [...out.values()]) {
      if (x.area !== "inputs" || x.shape !== "file") continue;
      for (const g of groups) {
        if (!g.includes(x.path)) continue;
        for (const member of g) {
          if (out.has(member)) continue;
          const row = ix.rows.get(member);
          if (!row || row.link !== undefined || row.special) throw new ScopeError(`${x.ref}: its set, as the census recorded it, names ${member}, which inputs.json does not list as a file`);
          add({ ref: `input:${member.slice(7)}`, path: member, ...(row.path_b64 ? { path_b64: row.path_b64 } : {}), area: "inputs", shape: "file", from: `the set of ${x.ref}, as the census recorded it`, ...(row.sha256 ? { sha256: row.sha256 } : {}), bytes: Number(row.bytes ?? 0) });
        }
      }
    }
  }
  return [...out.values()];
}

/** A generation's file by the sealed manifest of the job that made it, when it is one. */
async function catalogSha(S: string, rel: string): Promise<{ sha256?: string }> {
  const m = /^catalog\/gen\/([a-z0-9-]+)\/(.+)$/.exec(rel);
  if (!m) return {};
  try {
    const g = JSON.parse(await readFile(join(S, "catalog", "gen", m[1], "generation.json"), "utf8")) as { job?: string };
    const found = g.job ? await manifestOf(join(storePaths(S).jobs, g.job, "manifest.json")) : null;
    const f = await found?.file([m[2]]);
    return f ? { sha256: f.sha256 } : {};
  } catch {
    return {};
  }
}

// --- the view -------------------------------------------------------------------------------

/** What one entry of a view is, and how it got there. */
export type ViewEntry = {
  path: string;
  ref: string;
  how: "bound" | "clone" | "link" | "copy" | "the run's copy, linked" | "written by the hub" | "left out";
  sha256?: string;
  bytes?: number;
  /** Where the sha256 comes from: this job's own snapshot, or the record it was checked against. */
  hashed?: "at the job's start" | "inputs.json" | "the store's manifest" | "its name";
  files?: number;
  /** A name under a declared directory of the agents' work that is not a regular file: named, not given. */
  left_out?: string;
  /** Why a directory the job did not name is bound whole: every name under it is in the scope. */
  why?: string;
};

export type View = {
  root: string;
  /** The worker's mounts for the view: the view at the run's path, its no-exec corners, the directories bound whole, tools/. */
  mounts: Array<Mount & { note?: string }>;
  entries: ViewEntry[];
};

export type ViewOptions = {
  /** The run, resolved. */
  S: string;
  /** Where to build it: beside the job's staging directory, outside every VM's reach. */
  root: string;
  /** The run's one copy of an input that cannot be cloned. */
  projected: string;
  /** $OUT's path in the worker: a mountpoint inside the view. */
  guestOut: string;
  minFreeMb: number;
  /** Files the hub writes into the view itself (a trace line being sealed): run-relative path and bytes. */
  extra?: Array<{ path: string; bytes: Buffer; ref: string }>;
};

/** Free megabytes on the file system holding `dir`, or its nearest parent that exists. */
export function freeMb(dir: string): number | null {
  for (let d = resolve(dir); ; d = dirname(d)) {
    try {
      const s = statfsSync(d);
      return Math.floor((Number(s.bavail) * Number(s.bsize)) / (1024 * 1024));
    } catch {
      if (d === dirname(d)) return null;
    }
  }
}

function room(where: string, bytes: number, minFreeMb: number, what: string): void {
  const free = freeMb(where);
  if (free !== null && free - Math.ceil(bytes / (1024 * 1024)) < minFreeMb) throw new ScopeError(`no room to give this job ${what} (${bytes} bytes): ${free} MB free where views are built, ${minFreeMb} MB kept free`);
}

/**
 * A run-relative name as the host's path: from its bytes when inputs.json or
 * the manifest kept them (a name that is not UTF-8), else from its text.
 */
function hostPath(base: string, x: { path: string; path_b64?: string }): string | Buffer {
  return x.path_b64 ? Buffer.concat([Buffer.from(`${base}/`), Buffer.from(x.path_b64, "base64")]) : join(base, x.path);
}

/** The directory a path is in, kept as bytes when the path is. */
function parentOf(p: string | Buffer): string | Buffer {
  if (typeof p === "string") return dirname(p);
  const cut = p.lastIndexOf(0x2f);
  return cut > 0 ? p.subarray(0, cut) : Buffer.from("/");
}

async function sha256Of(path: string | Buffer): Promise<string> {
  const h = createHash("sha256");
  const fh = await open(path, "r");
  try {
    const buf = Buffer.alloc(1 << 20);
    for (;;) {
      const { bytesRead } = await fh.read(buf, 0, buf.length, null);
      if (!bytesRead) break;
      h.update(buf.subarray(0, bytesRead));
    }
  } finally {
    await fh.close();
  }
  return h.digest("hex");
}

/** Copy from an open descriptor, from its start, hashing as it goes. */
async function copyFromFd(src: FileHandle, dest: string | Buffer): Promise<{ sha256: string; bytes: number }> {
  const h = createHash("sha256");
  const out = await open(dest, "wx", 0o600);
  let bytes = 0;
  try {
    const buf = Buffer.alloc(1 << 20);
    for (let pos = 0; ; ) {
      const { bytesRead } = await src.read(buf, 0, buf.length, pos);
      if (!bytesRead) break;
      h.update(buf.subarray(0, bytesRead));
      await out.write(buf, 0, bytesRead);
      pos += bytesRead;
      bytes += bytesRead;
    }
  } finally {
    await out.close();
  }
  return { sha256: h.digest("hex"), bytes };
}

/**
 * Clone each open descriptor to its destination, copy-on-write, in one
 * process: macOS fclonefileat(2), Linux's FICLONE ioctl. From the descriptor,
 * not the path, so what is cloned is what was opened and checked. A file
 * system that cannot clone (or two different ones) answers with its errno,
 * and the caller falls back.
 */
const CLONE_PY = `import ctypes, json, os, sys
libc = ctypes.CDLL(None, use_errno=True)
out = []
for fd, dst in json.loads(sys.stdin.read()):
    e = 0
    if sys.platform == "darwin":
        if libc.fclonefileat(ctypes.c_int(fd), ctypes.c_int(-2), os.fsencode(dst), ctypes.c_uint32(0)) != 0:
            e = ctypes.get_errno() or 1
    else:
        import fcntl
        try:
            t = os.open(dst, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            try:
                fcntl.ioctl(t, 0x40049409, fd)
            finally:
                os.close(t)
        except OSError as x:
            e = x.errno or 1
            try:
                os.unlink(dst)
            except OSError:
                pass
    out.append(e)
print(json.dumps(out))
`;

/** How many descriptors one clone process is handed. */
const CLONE_BATCH = 200;

/** Whether cloning is to be tried at all (tests turn it off to take the fallbacks). */
function cloneWanted(): boolean {
  return process.env.SWARM_VIEW_NO_CLONE !== "1";
}

async function cloneFds(pairs: Array<{ fd: number; dest: string | Buffer }>): Promise<number[]> {
  const results = pairs.map(() => 45);
  if (!cloneWanted()) return results;
  // A name that is not UTF-8 is not handed over as text (it would not be its bytes there): it is copied.
  const asked = pairs.map((p, k) => ({ ...p, k })).filter((p): p is { fd: number; dest: string; k: number } => typeof p.dest === "string");
  for (let i = 0; i < asked.length; i += CLONE_BATCH) {
    const batch = asked.slice(i, i + CLONE_BATCH);
    // The descriptors are handed to the child as its 3, 4, …: nothing is opened by name there.
    const stdio: Array<"pipe" | number> = ["pipe", "pipe", "pipe", ...batch.map((p) => p.fd)];
    const list = batch.map((p, k) => [3 + k, p.dest]);
    const answer = await new Promise<number[] | null>((done) => {
      const child = spawn("python3", ["-c", CLONE_PY], { stdio });
      let text = "";
      child.stdout?.setEncoding("utf8").on("data", (c: string) => {
        text += c;
      });
      child.on("error", () => done(null));
      child.on("close", () => {
        try {
          const got = JSON.parse(text) as number[];
          done(Array.isArray(got) && got.length === batch.length ? got : null);
        } catch {
          done(null);
        }
      });
      child.stdin?.end(JSON.stringify(list));
    });
    batch.forEach((p, k) => {
      results[p.k] = answer ? answer[k] : 1;
    });
  }
  return results;
}

type Pending = {
  entry: ViewEntry;
  area: ScopeArea;
  fh: FileHandle;
  /** The descriptor's stat when opened: the path must still name this file, unchanged, afterwards. */
  st: import("node:fs").Stats;
  /** The path as the hub named it (for the check afterwards) and where it goes in the view. */
  lexical: string | Buffer;
  dest: string | Buffer;
  bytes: number;
  sha256?: string;
};

/**
 * Build a job's view: every object of its resolved scope at its run path
 * under `root`, and the mounts that give it to the worker. Directories first
 * (a file inside one bound is already there), then files, cloned in one
 * batch, each falling back by what it is. Throws a ScopeError with the
 * reason when an object cannot be given: the job then does not run.
 */
export async function buildView(objects: ScopeObject[], o: ViewOptions): Promise<View> {
  const S = o.S;
  const V = o.root;
  await rm(V, { recursive: true, force: true });
  await mkdir(V, { recursive: true, mode: 0o700 });
  const realS = await realpath(S);
  const ix = objects.some((x) => x.area === "inputs") ? await inputsIndex(S) : null;
  const roots = ix ? await inputRoots(S, ix.sets) : [];
  const sealedRoots = [await realpath(join(S, "store")).catch(() => join(realS, "store")), await realpath(join(S, "catalog")).catch(() => join(realS, "catalog"))];
  const mounts: Array<Mount & { note?: string }> = [];
  const entries: ViewEntry[] = [];
  const covered: string[] = [];
  const isCovered = (p: string) => covered.some((c) => p === c || p.startsWith(`${c}/`));
  let binds = 0;
  const pending: Pending[] = [];
  const devIno = async (p: string) => {
    const st = await lstat(p);
    return { dev: st.dev, ino: st.ino };
  };

  /** A directory bound whole: resolved, inside the roots it belongs to, a directory. */
  const bind = async (x: ScopeObject) => {
    const real = await realpath(hostPath(S, x)).catch(() => null);
    const ok = real !== null && (x.area === "inputs" ? within(real.toString(), roots) : within(real.toString(), sealedRoots));
    const st = ok ? await lstat(real!).catch(() => null) : null;
    if (!ok || !st?.isDirectory()) throw new ScopeError(`${x.ref}: ${x.path} does not lead to a directory of the run's ${x.area === "inputs" ? "evidence" : x.area}`);
    await mkdir(hostPath(V, x), { recursive: true });
    mounts.push({ host: real!.toString(), guest: join(S, x.path), readonly: true, ...(x.area === "inputs" ? { noexec: true } : {}), expect: await devIno(real!.toString()) });
    entries.push({ path: `${x.path}/`, ref: x.ref, how: "bound", ...(x.files !== undefined ? { files: x.files } : {}), ...(x.bytes !== undefined ? { bytes: x.bytes } : {}) });
    binds += 1;
  };

  /** A file opened for the view: without following a link, a regular file. */
  const openFile = async (x: { path: string; path_b64?: string; ref: string }, base: string, area: ScopeArea): Promise<Pending> => {
    const lexical = hostPath(base, x);
    let fh: FileHandle;
    try {
      fh = await open(lexical, constants.O_RDONLY | constants.O_NOFOLLOW);
    } catch (err) {
      throw new ScopeError(`${x.ref}: ${x.path} cannot be opened (${(err as NodeJS.ErrnoException).code ?? "error"}${(err as NodeJS.ErrnoException).code === "ELOOP" ? ": a link" : ""})`);
    }
    const st = await fh.stat();
    if (!st.isFile()) {
      await fh.close();
      throw new ScopeError(`${x.ref}: ${x.path} is not a regular file`);
    }
    const dest = hostPath(V, x);
    await mkdir(parentOf(dest), { recursive: true });
    return { entry: { path: x.path, ref: x.ref, how: "copy" }, area, fh, st, lexical, dest, bytes: st.size };
  };

  // An evidence set, or a directory of it, whose every name is in the scope
  // is bound whole rather than given file by file (while the binds last).
  const whole = ix ? coveredDirs(objects, ix, SCOPE_DIR_BINDS_MAX - objects.filter((x) => x.shape === "dir" && x.area !== "work").length) : [];
  for (const d of whole) {
    if (isCovered(d.path)) continue;
    covered.push(d.path);
    await bind(d);
    entries[entries.length - 1].why = d.from;
  }
  // Directories, the shallowest first.
  for (const d of objects.filter((x) => x.shape === "dir").sort((a, b) => a.path.length - b.path.length)) {
    if (isCovered(d.path)) continue;
    covered.push(d.path);
    if (d.area === "work") {
      // Live: every regular file under it snapshotted, a link or special file named and left out.
      for (const w of await walkWork(S, d.path)) {
        if (w.left_out) {
          entries.push({ path: w.path, ref: d.ref, how: "left out", left_out: w.left_out });
          continue;
        }
        pending.push(await openFile({ path: w.path, ref: d.ref }, S, "work"));
      }
      continue;
    }
    if (binds < SCOPE_DIR_BINDS_MAX) {
      await bind(d);
      continue;
    }
    if (d.area === "inputs") throw new ScopeError(`${d.ref}: a job is given at most ${SCOPE_DIR_BINDS_MAX} directories whole; declare fewer, or the directory that holds them`);
    // The store's and the catalogue's past the count: linked in, file by file.
    for (const w of await walkWork(S, d.path)) {
      if (w.left_out) continue;
      pending.push(await openFile({ path: w.path, ref: d.ref }, S, d.area));
    }
  }
  // Files not under a directory already given.
  for (const f of objects.filter((x) => x.shape === "file")) {
    if (isCovered(f.path)) continue;
    covered.push(f.path);
    if (f.area === "inputs") {
      // By where its name resolves: inside the evidence (a set's link is followed, nothing else).
      const real = await realpath(hostPath(S, f)).catch(() => null);
      if (!real || !within(real.toString(), roots)) throw new ScopeError(`${f.ref}: ${f.path} does not lead to a file of the run's evidence`);
      const p = await openFile({ path: f.path, ...(f.path_b64 ? { path_b64: f.path_b64 } : {}), ref: f.ref }, S, "inputs");
      p.lexical = real;
      p.sha256 = f.sha256;
      pending.push(p);
      continue;
    }
    if (f.area === "store" || f.area === "catalog") {
      const real = await realpath(hostPath(S, f)).catch(() => null);
      if (!real || !within(real.toString(), sealedRoots)) throw new ScopeError(`${f.ref}: ${f.path} does not lead to a file of the run's ${f.area}`);
      const p = await openFile({ path: f.path, ...(f.path_b64 ? { path_b64: f.path_b64 } : {}), ref: f.ref }, S, f.area);
      p.sha256 = f.sha256;
      pending.push(p);
      continue;
    }
    pending.push(await openFile({ path: f.path, ref: f.ref }, S, "work"));
  }
  try {
    await place(pending, o);
  } finally {
    for (const p of pending) await p.fh.close().catch(() => undefined);
  }
  for (const p of pending) entries.push(p.entry);
  for (const x of o.extra ?? []) {
    const dest = join(V, x.path);
    await mkdir(dirname(dest), { recursive: true });
    await writeFile(dest, x.bytes, { mode: 0o444, flag: "wx" });
    entries.push({ path: x.path, ref: x.ref, how: "written by the hub", sha256: createHash("sha256").update(x.bytes).digest("hex"), bytes: x.bytes.length, hashed: "at the job's start" });
  }
  // Mountpoints for what is mounted inside the view: tools/ and $OUT.
  const toolsDir = join(S, "tools");
  if (await lstat(toolsDir).then((st) => st.isDirectory()).catch(() => false)) {
    await mkdir(join(V, "tools"), { recursive: true });
    mounts.push({ host: toolsDir, guest: toolsDir, readonly: true, note: "the run's tools: code, each sealed by its manifest's sha256" });
  }
  const outRel = relative(S, o.guestOut);
  if (!outRel.startsWith("..")) await mkdir(join(V, outRel), { recursive: true });
  // The view itself at the run's path, its evidence and its extracted and quarantined corners no-exec.
  const own: Array<Mount & { note?: string }> = [{ host: V, guest: S, readonly: true, view: true, expect: await devIno(V), note: "this job's view: only what it declared" }];
  if (!mounts.some((m) => m.guest === join(S, "inputs")) && (await lstat(join(V, "inputs")).catch(() => null))?.isDirectory()) own.push({ host: join(V, "inputs"), guest: join(S, "inputs"), readonly: true, noexec: true, view: true, expect: await devIno(join(V, "inputs")) });
  for (const corner of ["extracted", "quarantine"]) {
    const dir = join(V, "work", corner);
    if ((await lstat(dir).catch(() => null))?.isDirectory()) own.push({ host: dir, guest: join(S, "work", corner), readonly: true, noexec: true, view: true, expect: await devIno(dir) });
  }
  // Parents before children: a share is mounted on a directory its parent share holds.
  const all = [...own, ...mounts].map((m, i) => ({ m, i })).sort((a, b) => depth(a.m.guest ?? a.m.host) - depth(b.m.guest ?? b.m.host) || a.i - b.i).map((x) => x.m);
  return { root: V, mounts: all, entries };
}

function depth(p: string): number {
  return p.split("/").filter(Boolean).length;
}

/**
 * The directories of the evidence whose every name inputs.json lists under
 * them is a file in the scope (declared, or the rest of a declared file's
 * set): the highest such, at most `room` of them, as directory objects. A
 * link or a special file under one is a name no job can declare, so a
 * directory holding one is never bound this way. With several sets inputs/
 * itself holds only their links, and is never one: each set is.
 */
function coveredDirs(objects: ScopeObject[], ix: InputsIndex, room: number): ScopeObject[] {
  const files = objects.filter((x) => x.area === "inputs" && x.shape === "file");
  if (!files.length || room <= 0) return [];
  const inScope = new Set(files.map((x) => x.path));
  const declaredDirs = objects.filter((x) => x.area === "inputs" && x.shape === "dir").map((x) => x.path);
  const given = (p: string) => inScope.has(p) || declaredDirs.some((d) => p.startsWith(`${d}/`));
  const candidates = new Set<string>();
  for (const f of files) {
    for (let d = f.path.slice(0, f.path.lastIndexOf("/")); d.includes("/") || d === "inputs"; d = d.slice(0, Math.max(d.lastIndexOf("/"), 0))) {
      if (!(d === "inputs" && ix.sets.length)) candidates.add(d);
      if (d === "inputs") break;
    }
  }
  const picked: ScopeObject[] = [];
  for (const d of [...candidates].sort((a, b) => depth(a) - depth(b) || (a < b ? -1 : 1))) {
    if (picked.length >= room) break;
    if (picked.some((p) => d.startsWith(`${p.path}/`))) continue;
    const names = under(ix.sorted, d);
    const plain = names.every((p) => {
      const row = ix.rows.get(p);
      return row && row.link === undefined && !row.special && given(p);
    });
    if (!names.length || !plain) continue;
    const bytes = names.reduce((a, p) => a + Number(ix.rows.get(p)?.bytes ?? 0), 0);
    const set = d === "inputs" || (ix.sets.length > 0 && depth(d) === 2) ? "the evidence set" : "the directory";
    picked.push({ ref: `input:${d === "inputs" ? "" : `${d.slice(7)}/`}`, path: d, area: "inputs", shape: "dir", from: `every file of ${set} ${d}/ is in the scope (${names.length} file(s)): bound whole, not given file by file`, files: names.length, bytes });
  }
  return picked;
}

/**
 * Put every opened file into the view by what it is. Clones first, in one
 * batch; then, for what did not clone, the evidence from the run's own
 * checked copy, the sealed store by a link or a copy, and a work file by a
 * copy from its descriptor. Afterwards each path must still name the file
 * that was opened (same device and inode) and that file must not have
 * changed while it was read: else a work file is refused as changing.
 */
async function place(pending: Pending[], o: ViewOptions): Promise<void> {
  const cloned = await cloneFds(pending.map((p) => ({ fd: p.fh.fd, dest: p.dest })));
  for (let k = 0; k < pending.length; k += 1) {
    const p = pending[k];
    if (cloned[k] === 0) {
      p.entry.how = "clone";
    } else if (p.area === "inputs" && !p.sha256) {
      // inputs.json names no sha256 for it (a manifest from before, or a test's): copied for this job alone, and hashed.
      room(o.root, p.bytes, o.minFreeMb, p.entry.path);
      const c = await copyFromFd(p.fh, p.dest);
      p.entry.how = "copy";
      p.sha256 = c.sha256;
      p.entry.hashed = "at the job's start";
    } else if (p.area === "inputs") {
      const cache = await projectedCopy(p, o);
      if (await link(cache, p.dest).then(() => true).catch(() => false)) {
        p.entry.how = "the run's copy, linked";
      } else {
        // No hard links where views are built: the run's checked copy, copied.
        room(o.root, p.bytes, o.minFreeMb, p.entry.path);
        const from = await open(cache, "r");
        try {
          await copyFromFd(from, p.dest);
        } finally {
          await from.close();
        }
        p.entry.how = "copy";
      }
    } else if (p.area === "store" || p.area === "catalog") {
      const linked = await link(p.lexical, p.dest).then(() => true).catch(() => false);
      if (linked) {
        // A link names whatever the path named at that moment: it must be the file that was opened.
        const got = await lstat(p.dest);
        if (got.dev !== p.st.dev || got.ino !== p.st.ino) {
          await rm(p.dest, { force: true });
          throw new ScopeError(`${p.entry.ref}: ${p.entry.path} changed while it was given to the job`);
        }
        p.entry.how = "link";
      } else {
        room(o.root, p.bytes, o.minFreeMb, p.entry.path);
        const c = await copyFromFd(p.fh, p.dest);
        p.entry.how = "copy";
        if (!p.sha256) p.sha256 = c.sha256;
      }
    } else {
      room(o.root, p.bytes, o.minFreeMb, p.entry.path);
      const c = await copyFromFd(p.fh, p.dest);
      p.entry.how = "copy";
      p.sha256 = c.sha256;
      p.entry.hashed = "at the job's start";
    }
    // The path still names the file that was opened, and it did not change
    // while it was read. A work file's ctime too (its owner can set mtime
    // back; not ctime); a sealed file's ctime moves when another job's view
    // links it, which is not a change of its bytes.
    const now = await lstat(p.lexical).catch(() => null);
    const after = await p.fh.stat();
    if (!now || now.dev !== p.st.dev || now.ino !== p.st.ino || after.size !== p.st.size || after.mtimeMs !== p.st.mtimeMs || (p.area === "work" && after.ctimeMs !== p.st.ctimeMs)) {
      throw new ScopeError(`${p.entry.ref}: ${p.entry.path} changed while it was given to the job (a file still being written, or replaced): run the job again once it is still`);
    }
    if (p.area === "work") {
      // A work file is what the job reads: its snapshot hashed, whatever the live file does next.
      if (p.entry.how === "clone") p.sha256 = await sha256Of(p.dest);
      p.entry.hashed = "at the job's start";
    } else if (p.entry.hashed) {
      // hashed already, as it was copied
    } else if (p.sha256) {
      p.entry.hashed = p.area === "inputs" ? "inputs.json" : /^store\/blobs\//.test(p.entry.path) ? "its name" : "the store's manifest";
    } else {
      p.sha256 = await sha256Of(p.dest);
      p.entry.hashed = "at the job's start";
    }
    if (p.entry.how !== "link" && p.entry.how !== "the run's copy, linked") await chmod(p.dest, 0o444).catch(() => undefined);
    p.entry.sha256 = p.sha256;
    p.entry.bytes = p.bytes;
  }
}

/** One copy per input per run, made once, checked against inputs.json, shared by link with every view that needs it. */
const projecting = new Map<string, Promise<string>>();

async function projectedCopy(p: Pending, o: ViewOptions): Promise<string> {
  const sha = p.sha256;
  if (!sha || !/^[0-9a-f]{64}$/.test(sha)) throw new ScopeError(`${p.entry.ref}: inputs.json has no sha256 for ${p.entry.path}, and this file system cannot clone it: declare its directory, or all`);
  const cache = join(o.projected, sha);
  const made = await stat(cache).catch(() => null);
  if (made?.isFile() && made.size === p.bytes) return cache;
  const inFlight = projecting.get(cache);
  if (inFlight) return inFlight;
  const job = (async () => {
    await mkdir(o.projected, { recursive: true, mode: 0o700 });
    room(o.projected, p.bytes, o.minFreeMb, `a copy of ${p.entry.path} (this file system cannot clone it)`);
    const tmp = `${cache}.${randomBytes(4).toString("hex")}.tmp`;
    try {
      const c = await copyFromFd(p.fh, tmp);
      if (c.sha256 !== sha) throw new ScopeError(`${p.entry.ref}: ${p.entry.path} reads now as sha256 ${c.sha256.slice(0, 16)}…, not the ${sha.slice(0, 16)}… inputs.json records: not given to a job (custody names it)`);
      await chmod(tmp, 0o444);
      await rename(tmp, cache);
      return cache;
    } finally {
      await rm(tmp, { force: true }).catch(() => undefined);
    }
  })();
  projecting.set(cache, job);
  try {
    return await job;
  } finally {
    projecting.delete(cache);
  }
}

/**
 * Every name under a run directory, by lstat: regular files to give,
 * anything else named and left out (a link, a special file, and a name that
 * is not UTF-8, which the view would not keep as its bytes).
 */
async function walkWork(S: string, rel: string): Promise<Array<{ path: string; left_out?: string }>> {
  const out: Array<{ path: string; left_out?: string }> = [];
  const visit = async (r: string) => {
    let raw: Buffer[];
    try {
      raw = (await readdir(join(S, r), { encoding: "buffer" })).sort(Buffer.compare);
    } catch (err) {
      out.push({ path: r, left_out: `unreadable directory (${(err as NodeJS.ErrnoException).code ?? "error"})` });
      return;
    }
    for (const bytes of raw) {
      const name = bytes.toString("utf8");
      const p = `${r}/${name}`;
      if (!Buffer.from(name, "utf8").equals(bytes)) {
        out.push({ path: p, left_out: "a name that is not UTF-8" });
        continue;
      }
      const st = await lstat(join(S, p)).catch(() => null);
      if (!st) out.push({ path: p, left_out: "vanished while read" });
      else if (st.isDirectory()) await visit(p);
      else if (st.isFile()) out.push({ path: p });
      else out.push({ path: p, left_out: st.isSymbolicLink() ? "a link" : "a special file" });
    }
  };
  await visit(rel);
  return out;
}

/** The canonical bytes of a scope manifest (sorted keys): its sha256 goes on job_started. */
export function scopeManifestText(m: Record<string, unknown>): string {
  const canonical = (v: unknown): string => {
    if (Array.isArray(v)) return `[${v.map(canonical).join(",")}]`;
    if (v && typeof v === "object") return `{${Object.keys(v as object).sort().map((k) => `${JSON.stringify(k)}:${canonical((v as Record<string, unknown>)[k])}`).join(",")}}`;
    return JSON.stringify(v);
  };
  return `${canonical(m)}\n`;
}

/** Remove the run's copies of inputs (the run is ending; a later job makes them again). */
export async function dropProjected(stagingRoot: string): Promise<void> {
  const dir = join(stagingRoot, PROJECTED_DIR);
  for (const f of await readdir(dir).catch(() => [])) await chmod(join(dir, f), 0o644).catch(() => undefined);
  await rm(dir, { recursive: true, force: true }).catch(() => undefined);
}

/** Tests only: forget the cached inputs.json index. */
export function forgetInputsIndex(): void {
  inputsCache = null;
}

/** Every name in a built view, in order (tests read what a job would see). */
export async function viewFiles(root: string): Promise<string[]> {
  const out: string[] = [];
  const visit = async (r: string) => {
    for (const name of (await readdir(join(root, r)).catch(() => [])).sort()) {
      const p = r ? `${r}/${name}` : name;
      const st = await lstat(join(root, p)).catch(() => null);
      if (st?.isDirectory()) await visit(p);
      else if (st) out.push(p);
    }
  };
  await visit("");
  return out;
}

