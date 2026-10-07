/**
 * Helpers the windows-forensics pack's suites share: how a tool is run (against the pack's own tools, or against a copy of
 * them when WINDOWS_PACK_TOOLS names one, to see a test fail on the code it was written against), how its answer is read, and the
 * stand-ins for what a host may lack.
 */
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { chmod, mkdir, readdir, stat, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { ROOT, runPy } from "./tool-library-harness.ts";

/**
 * These tests run the tools against the real libraries they import. A host that does not have a library (CI installs only
 * the apt packages, the images install the pip ones) skips them with the reason; everything else in this file uses stand-ins.
 */
export const pythonCanImport = (module: string): boolean => spawnSync("python3", ["-c", "import " + module], { stdio: "ignore" }).status === 0;
export const REGIPY = pythonCanImport("regipy.registry") ? false : "regipy is not installed on this host";
export const DISSECT = pythonCanImport("dissect.util.compression.lzxpress_huffman") ? false : "dissect.util is not installed on this host";

export const WIN = process.env.WINDOWS_PACK_TOOLS ?? join(ROOT, "packs", "windows-forensics", "tools");
export const AGENT = { AGENT_ID: "s1" };

export type Run = { code: number | null; stdout: string; stderr: string };

export async function tool(name: string, cwd: string, args: unknown, env: Record<string, string> = {}, bin?: string): Promise<Run> {
  return runPy(join(WIN, name, "run.py"), cwd, args, bin, { ...AGENT, ...env });
}

export function body<T>(out: Run): T {
  assert.equal(out.code, 0, out.stderr + out.stdout);
  assert.doesNotMatch(out.stderr, /Traceback/);
  return JSON.parse(out.stdout) as T;
}

/** A refusal or a failure: a non-zero exit and a JSON answer with an `error`. */
export function failed(out: Run): { error: string; [key: string]: unknown } {
  assert.notEqual(out.code, 0, out.stdout);
  assert.doesNotMatch(out.stderr, /Traceback/);
  return JSON.parse(out.stdout) as { error: string };
}

export async function exists(path: string): Promise<boolean> {
  return stat(path).then(() => true, () => false);
}

export async function stub(bin: string, name: string, script: string): Promise<void> {
  await mkdir(bin, { recursive: true });
  const path = join(bin, name);
  await writeFile(path, `#!/bin/sh\n${script}\n`, "utf8");
  await chmod(path, 0o755);
}

/** Run python3 with code, for fixtures a Buffer is awkward for. */
export function py(code: string, ...args: string[]): string {
  const out = spawnSync("python3", ["-c", code, ...args], { encoding: "utf8" });
  assert.equal(out.status, 0, out.stderr);
  return out.stdout;
}

export const u16 = (text: string): Buffer => Buffer.from(text, "utf16le");
export const asciiz = (text: string): Buffer => Buffer.concat([Buffer.from(text, "latin1"), Buffer.from([0])]);
export const u16z = (text: string): Buffer => Buffer.concat([u16(text), Buffer.from([0, 0])]);

export async function stubModule(cwd: string, files: Record<string, string>): Promise<Record<string, string>> {
  const dir = join(cwd, "pystub");
  for (const [name, text] of Object.entries(files)) {
    await mkdir(join(dir, name, ".."), { recursive: true });
    await writeFile(join(dir, name), text, "utf8");
  }
  return { PYTHONPATH: dir };
}

export async function everyFileUnder(dir: string): Promise<string[]> {
  const out: string[] = [];
  for (const entry of await readdir(dir, { withFileTypes: true })) {
    const full = join(dir, entry.name);
    if (entry.isDirectory()) out.push(...(await everyFileUnder(full)));
    else out.push(full);
  }
  return out;
}
