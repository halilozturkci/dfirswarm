/**
 * Spawn helpers for the tool-library suites. The library tools are
 * standalone directories, so the tests drive them as subprocesses with a
 * stub `icat` on PATH.
 */
import { spawn } from "node:child_process";
import { PYTHON3 } from "./host-gates.ts";
import type { Writable } from "node:stream";
import { chmod, mkdir, mkdtemp, realpath, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

export const ROOT = join(dirname(fileURLToPath(import.meta.url)), "..");
export const LIB = join(ROOT, "tool-library");

/**
 * Write the JSON stdin of a child and close it. A child that exits without reading its stdin (a fixture builder run
 * through `runPySnippet`) is not an error of the harness: without a listener the EPIPE of a loaded runner would surface
 * as an uncaught exception that kills the whole test file. `undefined` is no stdin at all (the pipe is closed with no
 * bytes); `null` is the JSON document `null` for a tool, which the tools' own tests send on purpose, and no stdin for
 * a snippet (`noneForNull`), which is how a builder that reads nothing is called.
 */
/** Whether an error of a child's stdin only means the child exited without reading it (the only error the helpers ignore). */
export function childGone(err: { code?: string }): boolean {
  return err.code === "EPIPE" || err.code === "ERR_STREAM_DESTROYED";
}

function feedStdin(stream: Writable | null, stdin: unknown, noneForNull = false): void {
  if (!stream) return;
  stream.on("error", (err: NodeJS.ErrnoException) => {
    if (!childGone(err)) throw err; // any other failure of the write surfaces (an uncaught exception fails the test file)
  });
  if (stdin === undefined || (noneForNull && stdin === null)) stream.end();
  else stream.end(JSON.stringify(stdin));
}

export async function runPy(
  script: string,
  cwd: string,
  stdin: unknown,
  extraPath?: string,
  extraEnv?: Record<string, string>,
): Promise<{ code: number | null; stdout: string; stderr: string }> {
  const env = { ...process.env, ...extraEnv };
  if (extraPath) env.PATH = `${extraPath}:${env.PATH ?? ""}`;
  return new Promise((resolve, reject) => {
    const child = spawn(PYTHON3, [script], { cwd, env });
    const stdout: Buffer[] = [];
    const stderr: Buffer[] = [];
    child.stdout.on("data", (c: Buffer) => stdout.push(c));
    child.stderr.on("data", (c: Buffer) => stderr.push(c));
    child.on("error", reject);
    child.on("close", (code) =>
      resolve({
        code,
        stdout: Buffer.concat(stdout).toString("utf8"),
        stderr: Buffer.concat(stderr).toString("utf8"),
      }),
    );
    feedStdin(child.stdin, stdin);
  });
}

export async function runSh(
  script: string,
  cwd: string,
  stdin: unknown,
  extraPath?: string,
): Promise<{ code: number | null; stdout: string; stderr: string }> {
  const env = { ...process.env };
  if (extraPath) env.PATH = `${extraPath}:${env.PATH ?? ""}`;
  return new Promise((resolve, reject) => {
    const child = spawn("bash", [script], { cwd, env });
    const stdout: Buffer[] = [];
    const stderr: Buffer[] = [];
    child.stdout.on("data", (c: Buffer) => stdout.push(c));
    child.stderr.on("data", (c: Buffer) => stderr.push(c));
    child.on("error", reject);
    child.on("close", (code) =>
      resolve({
        code,
        stdout: Buffer.concat(stdout).toString("utf8"),
        stderr: Buffer.concat(stderr).toString("utf8"),
      }),
    );
    feedStdin(child.stdin, stdin);
  });
}

export async function runPySnippet(
  code: string,
  args: string[],
  stdin: unknown,
): Promise<{ code: number | null; stdout: string; stderr: string }> {
  return new Promise((resolve, reject) => {
    const child = spawn(PYTHON3, ["-c", code, ...args]);
    const stdout: Buffer[] = [];
    const stderr: Buffer[] = [];
    child.stdout.on("data", (c: Buffer) => stdout.push(c));
    child.stderr.on("data", (c: Buffer) => stderr.push(c));
    child.on("error", reject);
    child.on("close", (code) =>
      resolve({
        code,
        stdout: Buffer.concat(stdout).toString("utf8"),
        stderr: Buffer.concat(stderr).toString("utf8"),
      }),
    );
    feedStdin(child.stdin, stdin, true);
  });
}

export async function withCwd(fn: (cwd: string, bin: string) => Promise<void>): Promise<void> {
  // The real path: on macOS tmpdir() is /var/folders/..., and /var is a link to /private/var. A tool that refuses a link in its output path
  // (ab_layout, backup_materialise) or prints a path it resolved (heic_inspect, marshal_inspect) then disagrees with the name the test holds.
  const cwd = await realpath(await mkdtemp(join(tmpdir(), "lib-eval-")));
  const bin = join(cwd, "bin");
  try {
    await mkdir(bin, { recursive: true });
    await mkdir(join(cwd, "work"), { recursive: true });
    await mkdir(join(cwd, "inputs"), { recursive: true });
    await writeFile(join(cwd, "inputs", "AF-Case2.E01"), "img\n", "utf8");
    await writeFile(join(cwd, "inputs", "Webserver.E01"), "img\n", "utf8");
    const icat = join(bin, "icat");
    await writeFile(
      icat,
      `#!/bin/sh
printf '%s\\n' "$@" > "${cwd}/icat-args.txt"
printf 'extracted-bytes'
`,
      "utf8",
    );
    await chmod(icat, 0o755);
    await fn(cwd, bin);
  } finally {
    await rm(cwd, { recursive: true, force: true });
  }
}

export async function failingStub(bin: string, name: string, message: string): Promise<void> {
  const path = join(bin, name);
  await writeFile(path, `#!/bin/sh\necho "${message}" >&2\nexit 1\n`, "utf8");
  await chmod(path, 0o755);
}
