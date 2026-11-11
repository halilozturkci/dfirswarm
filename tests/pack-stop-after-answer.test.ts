/**
 * Every tool of every pack: a stop signal that lands the moment the answer has been read does not kill the call by the signal's default action.
 *
 * The interpreter's own teardown resets the signal handlers to their defaults before it frees what the call held; a SIGINT/SIGTERM/SIGHUP that
 * lands there ended a process with no exit code (killed by the signal) with its whole answer already printed (macOS CI: pcap_summary, doc_structure).
 * Every tool now ends with `_leave()` (flush, run the atexit hooks the interpreter would have run, os._exit with the call's own code), or, in the
 * memory pack, with its own os._exit. This file runs each tool for real (arguments `{}`: the refusal is a complete document) and sends each of the
 * three signals as soon as a complete JSON document has been read from standard output: 0 of N may die by the signal, the answer stays ONE
 * document, and the exit status is the call's own (0, 1 or 2) or 128 + the signal. A static case pins the ending in every script. (The network
 * tools have a deeper case of their own in pack-network-stop-after-answer.test.ts, with a success for the three summary tools.)
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

const scripts: Array<[string, string]> = [];
for (const pack of readdirSync(join(ROOT, "packs")).sort()) {
  const tools = join(ROOT, "packs", pack, "tools");
  try {
    if (!statSync(tools).isDirectory()) continue;
  } catch {
    continue;
  }
  for (const tool of readdirSync(tools).sort()) {
    const script = join(tools, tool, "run.py");
    try {
      statSync(script);
      scripts.push([`${pack}/${tool}`, script]);
    } catch {
      /* not a tool */
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

function runThenSignal(script: string, cwd: string, signal: NodeJS.Signals): Promise<Ran> {
  const child = spawn(PYTHON3, [script], { cwd, env: { ...process.env, AGENT_ID: "s1" }, detached: true, stdio: ["pipe", "pipe", "pipe"] });
  let stdout = "";
  let stderr = "";
  let answered = false;
  child.stdout.on("data", (b: Buffer) => {
    stdout += b.toString("utf8");
    if (!answered && whole(stdout)) {
      answered = true;
      try {
        child.kill(signal);                      // the moment the answer has been read
      } catch {
        /* gone */
      }
    }
  });
  child.stderr.on("data", (b: Buffer) => { stderr += b.toString("utf8"); });
  child.stdin.on("error", () => undefined);
  child.stdin.end("{}");
  return new Promise((resolve) => {
    const timer = setTimeout(() => { try { process.kill(-(child.pid as number), "SIGKILL"); } catch { /* gone */ } }, 60_000);
    child.on("close", (code, by) => { clearTimeout(timer); resolve({ code, by, stdout, stderr, answered }); });
  });
}

test(`every tool of every pack ends with its own exit, not through the interpreter's teardown (static)`, () => {
  const missing: string[] = [];
  for (const [name, script] of scripts) {
    const text = readFileSync(script, "utf8");
    const main = text.slice(text.indexOf('if __name__ == "__main__":'));
    const guarded = /\n    _leave\(exit_code\)\n$/.test(main) && /def _leave\(code\):[\s\S]*os\._exit\(code\)/.test(text);
    // (four computer-forensics-base scripts have no __main__ guard: they run top to bottom, and every one of their ways out is _leave(...))
    const flat = !text.includes('if __name__ == "__main__":') && /def _leave\(code\):[\s\S]*os\._exit\(code\)/.test(text) && !/\n\s*sys\.exit\(/.test(text);
    if (!guarded && !flat && !/os\._exit\(/.test(main)) missing.push(name);
  }
  assert.deepEqual(missing, []);
  assert.ok(scripts.length >= 140, `${scripts.length} tools`);
});

test(`a stop signal sent the moment the answer was read kills no tool by the signal (0 of ${ROUNDS * SIGNALS.length} per tool), and the answer stays one document`, { timeout: 1_700_000 }, async () => {
  const bad: string[] = [];
  const cwd = mkdtempSync(join(tmpdir(), "stop-after-"));
  try {
    const queue = scripts.slice();
    const worker = async (): Promise<void> => {
      for (let item = queue.shift(); item; item = queue.shift()) {
        const [name, script] = item;
        for (let round = 0; round < ROUNDS; round++) {
          for (const [signal, number] of SIGNALS) {
            const run = await runThenSignal(script, cwd, signal);
            const where = `${name} ${signal}`;
            if (!run.answered) { bad.push(`${where}: no document (exit ${run.code}, ${run.stdout.length} bytes${run.stderr ? `, ${run.stderr.trim().split("\n").pop()?.slice(0, 120)}` : ""})`); continue; }
            if (run.by !== null || run.code === null) { bad.push(`${where}: killed by ${run.by}`); continue; }
            if (/Traceback/.test(run.stderr)) { bad.push(`${where}: traceback ${run.stderr.slice(-400)}`); continue; }
            if (!whole(run.stdout)) { bad.push(`${where}: more than one document`); continue; }
            if (![0, 1, 2, 128 + number].includes(run.code)) bad.push(`${where}: exit ${run.code}`);
          }
        }
      }
    };
    await Promise.all([worker(), worker(), worker(), worker()]);
  } finally {
    rmSync(cwd, { recursive: true, force: true });
  }
  assert.deepEqual(bad.sort(), []);
});