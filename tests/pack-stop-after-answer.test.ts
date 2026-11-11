/**
 * Every tool and recipe of every pack: a stop signal that lands once the answer has begun does not kill the call by the signal's default action,
 * does not start a second document, and does not put a traceback on standard error; and a write the file system refuses does not either.
 *
 * The interpreter's own teardown resets the signal handlers to their defaults before it frees what the call held; a SIGINT/SIGTERM/SIGHUP that
 * lands there ended a process with no exit code (killed by the signal) with its whole answer already printed (macOS CI: pcap_summary, doc_structure).
 * A handler that raises (keychain_open's Interrupted), run after the answer had been printed, wrote a second document, or a traceback from inside
 * the ending (every CI job of #245; here only with the tool and the test on one CPU, where the reader of the pipe runs before the writer goes on).
 * Every script now carries the SHARED LEAVE block: the first write to standard output holds the stop signals for good, and the call ends with
 * `_leave()` (flush, the atexit hooks, os._exit with the call's own code), never through the teardown. This file runs each script for real
 * (a tool with arguments `{}`, a recipe with `detect` on a target that does not exist: each answers with a complete document) and
 *
 * - sends each of the three signals as soon as a complete JSON document has been read from standard output (twice each);
 * - runs it under tests/stop-after-answer-inject.py, which sends the signal from inside the process the moment its first write has gone out,
 *   the moment a loaded runner reaches only by luck (the test sends one from outside as well, for the tools that write with os.write);
 * - runs it with a file-size limit of 40 bytes, SIGXFSZ ignored, and PYTHONDEVMODE=1 (Python 3.11 and 3.12 report an error of a file closed by
 *   the garbage collector only in development mode; 3.14 always does, and the hosted Mac's shell suite met it: archive_extract);
 *
 * and in each case the answer is ONE document, no traceback is on standard error, nothing is killed by a signal, and the exit status is the
 * call's own (0, 1 or 2) or 128 + the signal. A static case pins the block and the ending in every script. (The network tools have a deeper case
 * of their own in pack-network-stop-after-answer.test.ts, with a success for the three summary tools.)
 */
import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { mkdtempSync, readFileSync, readdirSync, rmSync, statSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "node:test";
import { PYTHON3 } from "./host-gates.ts";
import { ROOT } from "./tool-library-harness.ts";

const SIGNALS = [["SIGTERM", 15], ["SIGINT", 2], ["SIGHUP", 1]] as const;
const ROUNDS = 2;
const INJECT = join(ROOT, "tests", "stop-after-answer-inject.py");
const TARGET = JSON.stringify({ paths: ["/nonexistent/stop-after-answer/target.bin"], name: "target.bin" });
const LIMITED = "import os, resource, signal, sys; resource.setrlimit(resource.RLIMIT_FSIZE, (40, 40)); signal.signal(signal.SIGXFSZ, signal.SIG_IGN); os.execv(sys.executable, [sys.executable] + sys.argv[1:])";

type Script = { name: string; script: string; argv: string[]; recipe: boolean };
const scripts: Script[] = [];
for (const pack of readdirSync(join(ROOT, "packs")).sort()) {
  for (const kind of ["tools", "recipes"] as const) {
    const dir = join(ROOT, "packs", pack, kind);
    try {
      if (!statSync(dir).isDirectory()) continue;
    } catch {
      continue;
    }
    for (const entry of readdirSync(dir).sort()) {
      const script = join(dir, entry, "run.py");
      try {
        statSync(script);
      } catch {
        continue;                                // not a Python tool or recipe (a recipe may be run.sh)
      }
      const recipe = kind === "recipes";
      scripts.push({ name: `${pack}/${kind === "tools" ? "" : "recipes/"}${entry}`, script, argv: recipe ? ["detect", "--target", TARGET] : [], recipe });
    }
  }
}

function whole(text: string): boolean {
  try {
    JSON.parse(text);
    return true;
  } catch {
    return false;
  }
}

type Ran = { code: number | null; by: string | null; stdout: string; stderr: string; answered: boolean };
type How = { signal?: NodeJS.Signals; inject?: boolean; limited?: boolean };

function run(s: Script, cwd: string, how: How): Promise<Ran> {
  const argv = how.inject ? [INJECT, s.script, ...s.argv] : how.limited ? ["-c", LIMITED, s.script, ...s.argv] : [s.script, ...s.argv];
  const env: NodeJS.ProcessEnv = { ...process.env, AGENT_ID: "s1" };
  for (const k of ["JOB_ID", "OUT", "SECRET_OUTPUT"]) delete env[k];
  if (how.inject && how.signal) env.INJECT_SIGNAL = how.signal;
  if (how.limited) env.PYTHONDEVMODE = "1";
  const child = spawn(PYTHON3, argv, { cwd, env, detached: true, stdio: ["pipe", "pipe", "pipe"] });
  let stdout = "";
  let stderr = "";
  let answered = false;
  child.stdout.on("data", (b: Buffer) => {
    stdout += b.toString("utf8");
    if (!answered && whole(stdout)) {
      answered = true;
      if (how.signal) {
        try {
          child.kill(how.signal);                // the moment the answer has been read
        } catch {
          /* gone */
        }
      }
    }
  });
  child.stderr.on("data", (b: Buffer) => { stderr += b.toString("utf8"); });
  child.stdin.on("error", () => undefined);
  child.stdin.end(s.recipe ? "" : "{}");
  return new Promise((resolve) => {
    const timer = setTimeout(() => { try { process.kill(-(child.pid as number), "SIGKILL"); } catch { /* gone */ } }, 60_000);
    child.on("close", (code, by) => { clearTimeout(timer); resolve({ code, by, stdout, stderr, answered: answered || whole(stdout) }); });
  });
}

/** What is wrong with one run, or null. */
function judge(r: Ran, number: number | null): string | null {
  if (!r.answered) return `no document (exit ${r.code}, ${r.stdout.length} bytes${r.stderr ? `, ${r.stderr.trim().split("\n").pop()?.slice(0, 160)}` : ""})`;
  if (r.by !== null || r.code === null) return `killed by ${r.by}`;
  if (/Traceback/.test(r.stderr)) return `traceback ${r.stderr.slice(-600)}`;
  if (!whole(r.stdout)) return `more than one document: ${r.stdout.slice(0, 300)}`;
  if (![0, 1, 2, ...(number === null ? [] : [128 + number])].includes(r.code)) return `exit ${r.code}`;
  return null;
}

/** Every script through `cases` (four at a time), the problems sorted. */
async function sweep(cases: Array<{ label: string; how: How; number: number | null }>): Promise<string[]> {
  const bad: string[] = [];
  const cwd = mkdtempSync(join(tmpdir(), "stop-after-"));
  try {
    const queue = scripts.slice();
    const worker = async (): Promise<void> => {
      for (let s = queue.shift(); s; s = queue.shift()) {
        for (const c of cases) {
          const why = judge(await run(s, cwd, c.how), c.number);
          if (why) bad.push(`${s.name} ${c.label}: ${why}`);
        }
      }
    };
    await Promise.all([worker(), worker(), worker(), worker()]);
  } finally {
    rmSync(cwd, { recursive: true, force: true });
  }
  return bad.sort();
}

test(`every tool and recipe of every pack carries the SHARED LEAVE block and ends with its own exit, not through the interpreter's teardown (static)`, () => {
  const missing: string[] = [];
  for (const { name, script } of scripts) {
    const text = readFileSync(script, "utf8");
    const block = text.includes("# BEGIN SHARED LEAVE\n") && text.includes("\n# END SHARED LEAVE\n") && /def _leave\(code\):[\s\S]*os\._exit\(code\)/.test(text);
    const main = text.slice(text.indexOf('if __name__ == "__main__":'));
    const guarded = /\n    _leave\(exit_code\)\n$/.test(main);
    // (four computer-forensics-base scripts have no __main__ guard: they run top to bottom, and every one of their ways out is _leave(...))
    const flat = !text.includes('if __name__ == "__main__":') && !/\n\s*sys\.exit\(/.test(text);
    if (!block || !(guarded || flat)) missing.push(name);
  }
  assert.deepEqual(missing, []);
  assert.ok(scripts.filter((s) => !s.recipe).length >= 140, `${scripts.length} scripts`);
  assert.ok(scripts.filter((s) => s.recipe).length >= 16, `${scripts.filter((s) => s.recipe).length} recipes`);
});

test(`a stop signal sent the moment the answer was read kills no tool or recipe by the signal (0 of ${ROUNDS * SIGNALS.length} per script), and the answer stays one document`, { timeout: 1_700_000 }, async () => {
  const cases = [];
  for (let round = 0; round < ROUNDS; round++) for (const [signal, number] of SIGNALS) cases.push({ label: signal, how: { signal }, number });
  assert.deepEqual(await sweep(cases), []);
});

test("a stop signal sent from inside the process the moment its first write to standard output has gone out (and again from outside when the document is read): one document, no traceback, not killed", { timeout: 1_700_000 }, async () => {
  assert.deepEqual(await sweep(SIGNALS.map(([signal, number]) => ({ label: `${signal} injected`, how: { signal, inject: true }, number }))), []);
});

test("under a file-size limit of 40 bytes, SIGXFSZ ignored and Python's development mode (which reports what 3.14 reports): one document, no traceback", { timeout: 1_700_000 }, async () => {
  assert.deepEqual(await sweep([{ label: "limit 40", how: { limited: true }, number: null }]), []);
});
