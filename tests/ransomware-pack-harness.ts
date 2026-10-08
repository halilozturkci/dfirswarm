/**
 * What the ransomware-response pack's tool suites share: how a tool is run (as a
 * subprocess, from a working directory, with an agent id), how its answer is
 * read, and a way to make a read fail with EIO wherever the suite runs.
 */
import assert from "node:assert/strict";
import { readFile, readdir, stat } from "node:fs/promises";
import { join } from "node:path";
import { ROOT, runPy } from "./tool-library-harness.ts";

export const PACK = join(ROOT, "packs", "ransomware-response", "tools");
export const NOTES = join(PACK, "ransom_note_scan", "run.py");
export const SURVEY = join(PACK, "encrypted_survey", "run.py");
const AGENT = { AGENT_ID: "s1" };

export type Run = { code: number | null; stdout: string; stderr: string };
export type Page = { matched: number; returned: number; truncated: boolean; all_results?: string };

export async function tool(script: string, cwd: string, args: unknown, env: Record<string, string> = {}): Promise<Run> {
  return runPy(script, cwd, args, undefined, { ...AGENT, ...env });
}

export function body<T>(out: Run): T {
  assert.equal(out.code, 0, out.stderr + out.stdout);
  assert.doesNotMatch(out.stderr, /Traceback/);
  return JSON.parse(out.stdout) as T;
}

export function refused(out: Run): { error: string } {
  assert.notEqual(out.code, 0, out.stdout);
  assert.doesNotMatch(out.stderr, /Traceback/);
  return JSON.parse(out.stdout) as { error: string };
}

export async function exists(path: string): Promise<boolean> {
  return stat(path).then(() => true, () => false);
}

/** Every regular file under a directory, as text, keyed by its path relative to it. */
export async function filesUnder(dir: string): Promise<Record<string, string>> {
  const out: Record<string, string> = {};
  if (!(await exists(dir))) return out;
  for (const name of await readdir(dir, { recursive: true })) {
    const path = join(dir, name);
    if ((await stat(path)).isFile()) out[name] = await readFile(path, "utf8");
  }
  return out;
}

/** The rows of the file a page names: the whole result, in order. */
export async function allRows<T>(cwd: string, page: Page): Promise<T[]> {
  assert.ok(page.all_results, "the output must name the file holding the whole result");
  const text = await readFile(join(cwd, page.all_results), "utf8");
  return text.trimEnd().split("\n").map((line) => JSON.parse(line) as T);
}

// Reads that fail with EIO wherever the tool runs (root reads a mode-000 file, so
// the failure is made by the interpreter): a file named *unreadable* fails to
// open, in either of the ways a tool opens one.
export const EIO_SITE = String.raw`
import builtins, errno, os
_real_open, _real_os_open = builtins.open, os.open
def _fails(file):
    name = os.fsdecode(file) if isinstance(file, (str, bytes, os.PathLike)) else ""
    return "unreadable" in os.path.basename(name)
def _open(file, *args, **kwargs):
    if _fails(file):
        raise OSError(errno.EIO, "Input/output error", os.fsdecode(file))
    return _real_open(file, *args, **kwargs)
def _os_open(path, *args, **kwargs):
    if _fails(path):
        raise OSError(errno.EIO, "Input/output error", os.fsdecode(path))
    return _real_os_open(path, *args, **kwargs)
builtins.open = _open
os.open = _os_open
`;
