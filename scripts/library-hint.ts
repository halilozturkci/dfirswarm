/**
 * Library visibility (B20, docs/adr/0016): at a job's admission, the tools
 * of the run's library whose manifest says they read the kind of file the
 * job declared, offered as a hint in the admission's answer. Never a rule:
 * the job runs as asked.
 *
 * In the BelkaCTF #6 round the library held mobile-oriented tools that no
 * agent used; the agents wrote their own parsers for the same databases,
 * one command job at a time. Whether that is good or bad is a calibration
 * question; that the tools were there and unseen is not.
 *
 * Nothing here knows a format. A manifest may say what it reads in `use`:
 * `extensions` (".evtx"), `magic` (bytes at an offset, as hex) and `names`
 * (a file's own name, `*` for any run of characters: "History", "$J").
 * Each declared input is matched against every manifest by its extension,
 * its first bytes and its name; a manifest that says nothing in `use` is
 * matched by its description naming the input's extension as a word. The
 * harness compares what the manifests wrote, as it does a recipe's
 * prefilter.
 */
import { lstat, open, readdir, readFile, realpath, stat } from "node:fs/promises";
import { basename, join, resolve } from "node:path";

/** What a tool's manifest says it reads. */
export type ToolUse = { extensions?: string[]; magic?: Array<{ offset: number; hex: string }>; names?: string[] };

type Manifest = { name?: string; description?: string; use?: ToolUse; example?: string };

/** One declared input a tool matched, and how. */
export type HintMatch = { input: string; by: "extension" | "magic" | "name" | "description"; what: string };

export type LibraryHint = { tool: string; description: string; matched: HintMatch[]; example?: string };

/** How many of a job's input files are looked at: each directory is listed, and files beyond this are counted, not read. */
export const HINT_FILES_MAX = 256;
/** How many bytes of a file's head are read for a manifest's magic. */
export const HINT_HEAD_MAX = 4096;

export const HINT_NOTE =
  "A hint, not a rule: tools in this run's library whose manifest says they read these inputs (by extension, first bytes or name). Run one as job_run tool=<name> with its args (tools lists them) instead of writing a parser; each was written by an agent in an earlier case and folded in after review, so read what it does before you rest a finding on it.";

/** An input's extension, lower case, without the dot: none for a name with no dot, a leading dot only, or a long tail. */
export function extensionOf(path: string): string | null {
  const name = basename(path);
  const i = name.lastIndexOf(".");
  if (i <= 0 || i === name.length - 1) return null;
  const ext = name.slice(i + 1).toLowerCase();
  return ext.length <= 12 && /^[a-z0-9_-]+$/.test(ext) ? ext : null;
}

const norm = (e: string) => e.trim().toLowerCase().replace(/^\./, "");

function globRe(pattern: string): RegExp {
  return new RegExp(`^${pattern.split("*").map((p) => p.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")).join(".*")}$`, "i");
}

function hexBytes(hex: string): Buffer | null {
  const h = hex.replace(/\s+/g, "").toLowerCase();
  return /^([0-9a-f]{2})+$/.test(h) ? Buffer.from(h, "hex") : null;
}

/**
 * Which tools match one file: by the manifest's `use` (extension, magic,
 * name), or, for a manifest with no `use`, by its description naming the
 * extension as a word of its own (not a part of a path or a longer word).
 * Pure: `head` is the file's first bytes, or null when it was not read.
 */
export function matchTool(m: Manifest, file: { input: string; path: string; head: Buffer | null }): HintMatch[] {
  const out: HintMatch[] = [];
  const ext = extensionOf(file.path);
  const use = m.use && typeof m.use === "object" ? m.use : null;
  if (use) {
    if (ext && (use.extensions ?? []).map(norm).includes(ext)) out.push({ input: file.input, by: "extension", what: `.${ext}` });
    for (const g of use.magic ?? []) {
      const want = hexBytes(String(g.hex ?? ""));
      const at = Number(g.offset) || 0;
      if (!want || !file.head || at < 0 || at + want.length > file.head.length) continue;
      if (file.head.subarray(at, at + want.length).equals(want)) {
        out.push({ input: file.input, by: "magic", what: `${want.toString("hex")} at offset ${at}` });
        break;
      }
    }
    const name = basename(file.path);
    const hit = (use.names ?? []).find((n) => globRe(String(n)).test(name));
    if (hit) out.push({ input: file.input, by: "name", what: String(hit) });
    return out;
  }
  if (ext && ext.length >= 3 && /[a-z]/.test(ext) && new RegExp(`(?<![\\w./\\\\-])${ext}(?![\\w-])`, "i").test(m.description ?? "")) out.push({ input: file.input, by: "description", what: `its description names ${ext.toUpperCase()}` });
  return out;
}

/** The tools of a run's library (tools/<name>/manifest.json), by name. */
export async function readToolManifests(sandbox: string): Promise<Manifest[]> {
  const dir = join(resolve(sandbox), "tools");
  const out: Manifest[] = [];
  for (const name of (await readdir(dir).catch(() => [] as string[])).sort()) {
    try {
      const m = JSON.parse(await readFile(join(dir, name, "manifest.json"), "utf8")) as Manifest;
      if (m && typeof m === "object") out.push({ ...m, name: typeof m.name === "string" ? m.name : name });
    } catch {
      // a tool without a readable manifest is not offered
    }
  }
  return out;
}

async function headOf(path: string, bytes: number): Promise<Buffer | null> {
  try {
    const real = await realpath(path);
    const st = await lstat(real);
    if (!st.isFile()) return null;
    const fh = await open(real, "r");
    try {
      const buf = Buffer.alloc(Math.min(bytes, st.size));
      const { bytesRead } = await fh.read(buf, 0, buf.length, 0);
      return buf.subarray(0, bytesRead);
    } finally {
      await fh.close();
    }
  } catch {
    return null;
  }
}

/** A scope object as job-scope.ts resolves it: enough of it to name its files. */
export type HintObject = { ref: string; path: string; area: string; shape: "file" | "dir" };

/**
 * inputs.json's file paths, parsed once and cached against its size and
 * mtime, so a run of directory hints at admission does not re-read and
 * re-parse a manifest that may be hundreds of megabytes (docs/adr/0016).
 */
let inputsPathsCache: { key: string; paths: string[] } | null = null;
async function inputsPaths(S: string): Promise<string[]> {
  const file = join(S, "inputs.json");
  const st = await stat(file).catch(() => null);
  const key = st ? `${file}:${st.size}:${st.mtimeMs}` : `${file}:none`;
  if (inputsPathsCache?.key === key) return inputsPathsCache.paths;
  const paths = await readFile(file, "utf8")
    .then((t) => ((JSON.parse(t) as { files?: Array<{ path?: string; link?: string; special?: string }> }).files ?? []).filter((f) => typeof f.path === "string" && !f.link && !f.special).map((f) => String(f.path)))
    .catch(() => []);
  inputsPathsCache = { key, paths };
  return paths;
}

/**
 * The files a job's declared objects hold, up to the bound: a file as it is;
 * a directory's files from the record that lists them (inputs.json cached, a
 * job's or an import's manifest), else as the directory holds them now. The
 * hint reads a bounded head of at most HINT_FILES_MAX files; the total is the
 * full count, so the job is told how much its objects hold.
 */
async function filesOf(S: string, objects: HintObject[]): Promise<{ files: Array<{ input: string; path: string }>; total: number }> {
  const files: Array<{ input: string; path: string }> = [];
  let total = 0;
  const push = (input: string, path: string) => {
    total += 1;
    if (files.length < HINT_FILES_MAX) files.push({ input, path });
  };
  for (const o of objects) {
    if (o.shape === "file") {
      push(o.ref, o.path);
      continue;
    }
    if (o.area === "inputs") {
      const inputs = await inputsPaths(S);
      for (const p of inputs) if (p.startsWith(`${o.path}/`) || o.path === "inputs") push(`input:${p.replace(/^inputs\//, "")}`, p);
      continue;
    }
    const store = /^store\/(jobs|imports)\/([^/]+)\/out(?:\/(.*))?$/.exec(o.path);
    if (store) {
      const m = await readFile(join(S, "store", store[1], store[2], "manifest.json"), "utf8").then((t) => JSON.parse(t) as { files?: Array<{ path?: string }> }).catch(() => null);
      const under = store[3] ? `${store[3]}/` : "";
      for (const f of m?.files ?? []) if (typeof f.path === "string" && f.path.startsWith(under)) push(`${store[1] === "jobs" ? "job" : "import"}:${store[2]}/${f.path}`, `store/${store[1]}/${store[2]}/out/${f.path}`);
      continue;
    }
    // The catalogue and the agents' work: one level, as it stands.
    for (const name of (await readdir(join(S, o.path)).catch(() => [] as string[])).sort()) push(`${o.path}/${name}`, `${o.path}/${name}`);
  }
  return { files, total };
}

/** How long the library hint may take before it gives what it has (a hint is not worth holding a job's admission). */
export const HINT_DEADLINE_MS = 250;

/** Forget the cached inputs.json (for a test that changes it in place). */
export function forgetInputsPaths(): void {
  inputsPathsCache = null;
}

/**
 * The hint for a job's declared objects: every tool of the run's library
 * that matches one of their files, with what it matched and how, or null
 * when none does. `skip` names tools the job already runs (its command
 * names them): they are not offered to it again.
 */
export async function libraryHint(sandbox: string, objects: HintObject[], o: { skip?: (tool: string) => boolean; deadlineMs?: number } = {}): Promise<{ note: string; tools: LibraryHint[]; examined: number; of: number } | null> {
  const S = resolve(sandbox);
  const deadline = Date.now() + (o.deadlineMs ?? HINT_DEADLINE_MS);
  const manifests = (await readToolManifests(S)).filter((m) => !o.skip?.(String(m.name)));
  if (!manifests.length || !objects.length) return null;
  const { files, total } = await filesOf(S, objects);
  const headBytes = Math.min(HINT_HEAD_MAX, Math.max(0, ...manifests.flatMap((m) => (m.use?.magic ?? []).map((g) => (Number(g.offset) || 0) + (hexBytes(String(g.hex ?? ""))?.length ?? 0)))));
  const tools: LibraryHint[] = [];
  const heads = new Map<string, Buffer | null>();
  // The hint is worth having but not worth holding the job: past its deadline it gives what it has matched so far.
  for (const m of manifests) {
    if (Date.now() >= deadline) break;
    const matched: HintMatch[] = [];
    for (const f of files) {
      if (headBytes && m.use?.magic?.length && !heads.has(f.path)) heads.set(f.path, await headOf(join(S, f.path), headBytes));
      matched.push(...matchTool(m, { ...f, head: heads.get(f.path) ?? null }));
    }
    if (matched.length) tools.push({ tool: String(m.name), description: String(m.description ?? ""), matched, ...(m.example ? { example: m.example } : {}) });
  }
  return tools.length ? { note: HINT_NOTE, tools, examined: files.length, of: total } : null;
}

/** Whether a command already runs a tool: it names the tool's directory, or the tool by its name as a word. */
export function commandNames(command: string, tool: string): boolean {
  return command.includes(`tools/${tool}/`) || new RegExp(`(?<![\\w-])${tool.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")}(?![\\w-])`).test(command);
}

/** How many tools one admission answer names, and how long before a seat is told of the same tool again. */
export const HINT_TOOLS_MAX = 3;
export const HINT_REPEAT_MS = 30 * 60 * 1000;

/** The hint as an answer carries it: a tool is one line, with one input it matched and how many more. */
export type ShortHint = { note: string; tools: Array<{ tool: string; about: string; matched: HintMatch; more_inputs: number }>; more_tools: number; examined: number; of: number };

/** A description's first sentence, bounded: what a tool is for in one line. */
export function oneLine(description: string, max = 160): string {
  const first = description.replace(/\s+/g, " ").trim().split(/(?<=[.:;])\s/)[0] ?? "";
  return first.length > max ? `${first.slice(0, max - 1)}…` : first;
}

/**
 * The hint bounded for an answer (the runs sf4406b and s68ce47: the whole hint was three quarters of all job_run result
 * text, 12 M characters in one run, and a hinted tool was run 4 times in 237). A tool matched only by its description
 * naming an extension is left out (every extraction writes a .json); at most HINT_TOOLS_MAX tools, the ones that
 * matched the most inputs first; each as its name, one line, one matched input and a count of the rest. `seen` (tool to
 * the time it was last named to this seat) keeps a tool from being named again within HINT_REPEAT_MS; it is updated.
 * Null when nothing is left to say.
 */
export function shortHint(full: Awaited<ReturnType<typeof libraryHint>>, seen?: Map<string, number>, now = Date.now()): ShortHint | null {
  if (!full) return null;
  const fresh = full.tools
    .map((t) => ({ t, own: t.matched.filter((m) => m.by !== "description") }))
    .filter((x) => x.own.length && !(seen && now - (seen.get(x.t.tool) ?? -Infinity) < HINT_REPEAT_MS))
    .sort((a, b) => new Set(b.own.map((m) => m.input)).size - new Set(a.own.map((m) => m.input)).size || a.t.tool.localeCompare(b.t.tool));
  if (!fresh.length) return null;
  const said = fresh.slice(0, HINT_TOOLS_MAX);
  for (const x of said) seen?.set(x.t.tool, now);
  return {
    note: "A hint, not a rule: library tools whose manifest says they read these inputs. Run one as job_run tool=<name> (tools(name) gives its arguments) instead of writing a parser.",
    tools: said.map((x) => ({ tool: x.t.tool, about: oneLine(x.t.description), matched: x.own[0]!, more_inputs: new Set(x.own.map((m) => m.input)).size - 1 })),
    more_tools: fresh.length - said.length,
    examined: full.examined,
    of: full.of,
  };
}
