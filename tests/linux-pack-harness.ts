/**
 * Helpers the Linux pack's tool suites share: running a pack tool as a call and as a job (JOB_ID and OUT set,
 * the way the job service runs it), reading the rows an answer pages, and finding where a planted secret ended up.
 * Each suite builds its own fixtures from the formats' layouts and never from a tool's output.
 */
import assert from "node:assert/strict";
import { chmod, mkdir, readFile, readdir, stat, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { ROOT, runPy } from "./tool-library-harness.ts";
export { withCwd } from "./tool-library-harness.ts";

const LINUX = join(ROOT, "packs", "linux-forensics");
export const TOOLS = join(LINUX, "tools");
export const AUTH = join(TOOLS, "auth_log", "run.py");
export const UTMP = join(TOOLS, "utmp_parse", "run.py");
export const JOURNAL = join(TOOLS, "journal_export", "run.py");
export const CRON = join(TOOLS, "cron_dump", "run.py");
export const SHELL = join(TOOLS, "shell_history", "run.py");
export const TRIAGE = join(TOOLS, "linux_triage", "run.py");
export const RECIPE = join(LINUX, "recipes", "linux-target", "run.py");
export const AGENT = { AGENT_ID: "s1" };
export const IS_ROOT = typeof process.getuid === "function" && process.getuid() === 0;

export type Run = { code: number | null; stdout: string; stderr: string };
export type Page = { matched: number; returned: number; truncated: boolean; all_results?: string };
// eslint-disable-next-line @typescript-eslint/no-explicit-any
export type Json = any;

export async function tool(script: string, cwd: string, args: unknown, env: Record<string, string> = {}, bin?: string): Promise<Run> {
  return runPy(script, cwd, args, bin, { ...AGENT, ...env });
}

let jobs = 0;
/** The tool as a job runs it: JOB_ID and OUT set, OUT inside the run directory (`out`, or the directory named). */
export async function asJob(script: string, cwd: string, args: unknown, bin?: string, env: Record<string, string> = {}, outName = "out"): Promise<Run> {
  await mkdir(join(cwd, outName), { recursive: true });
  jobs += 1;
  return tool(script, cwd, args, { JOB_ID: `j${String(jobs).padStart(6, "0")}`, OUT: join(cwd, outName), ...env }, bin);
}

export function body(out: Run): Json {
  assert.equal(out.code, 0, out.stderr + out.stdout);
  assert.doesNotMatch(out.stderr, /Traceback/);
  return JSON.parse(out.stdout);
}

export function refused(out: Run): Json {
  assert.notEqual(out.code, 0, out.stdout);
  assert.doesNotMatch(out.stderr, /Traceback/);
  return JSON.parse(out.stdout);
}

export async function exists(path: string): Promise<boolean> {
  return stat(path).then(() => true, () => false);
}

/** Every file under a directory, relative to it. */
export async function filesUnder(dir: string): Promise<string[]> {
  const out: string[] = [];
  const walk = async (d: string, prefix: string): Promise<void> => {
    for (const e of await readdir(d, { withFileTypes: true }).catch(() => [])) {
      if (e.isDirectory()) await walk(join(d, e.name), `${prefix}${e.name}/`);
      else out.push(`${prefix}${e.name}`);
    }
  };
  await walk(dir, "");
  return out.sort();
}

/**
 * The rows of a list an answer pages: the inline page, or the whole in the file the page names. A job's paging file is
 * named store/jobs/<id>/out/..., which a test run finds under `outDir`.
 */
export async function rowsOf(cwd: string, out: Json, key = "records", outDir = "out"): Promise<Json[]> {
  const page: Page | undefined = out.pages?.[key];
  if (page?.all_results) {
    const real = page.all_results.replace(/^store\/jobs\/[^/]+\/out\//, `${outDir}/`);
    const text = await readFile(join(cwd, real), "utf8");
    return text.trimEnd().split("\n").filter(Boolean).map((l) => JSON.parse(l));
  }
  return out[key] ?? [];
}

/**
 * Everything a call left where an agent reads it, as one string: the answer, every job output directory
 * (`out*`) and the agent's own tool-output pages (`work/s1`). The fixtures under `work/` are the evidence
 * and are meant to hold the planted secret, so they are not scanned.
 */
export async function everythingBut(cwd: string, answer: string, skip: string[]): Promise<string> {
  const parts = [answer];
  const roots = (await readdir(cwd)).filter((d) => d.startsWith("out")).concat(["work/s1"]);
  for (const root of roots) {
    for (const f of await filesUnder(join(cwd, root))) {
      if (skip.includes(`${root}/${f}`)) continue;
      parts.push(await readFile(join(cwd, root, f), "utf8").catch(() => ""));
    }
  }
  return parts.join("\n");
}

export function lines(...ls: string[]): string {
  return ls.join("\n") + "\n";
}

export async function put(root: string, rel: string, text: string | Buffer, mode?: number): Promise<void> {
  const full = join(root, rel);
  await mkdir(join(full, ".."), { recursive: true });
  await writeFile(full, text);
  if (mode !== undefined) await chmod(full, mode);
}
