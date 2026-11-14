/**
 * Hostile parameters, driven from the manifests: for every parameter of a tool, a value of the wrong type, a string with a NUL, a lone surrogate, a name of
 * 300 characters, a huge integer, a nested list, an object and null, each in place of the parameter's value in an otherwise sensible call. The answer to
 * every one of them is a JSON document on stdout and no traceback on stderr, in time (a refusal, or an answer: both are fine; a crash with no JSON is not).
 * At most 1,000 cases per tool. The tools held are the twelve computer-forensics-base tools whose refusals carry the status pair, and their twins.
 */
import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { mkdir, mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "node:test";
import { ROOT } from "./tool-library-harness.ts";

const TOOLS = ["ad1_extract", "archive_extract", "chunk_needles", "feature_scan", "file_type", "icat_extract", "image_layout", "ioc_scan", "sig_carve", "sqlite_snapshot", "timeline_super", "timestamp_decode"];
const LIMIT_MS = 20_000;
const MAX_CASES = 1000;

type Param = { type?: string; required?: boolean };

const nest = (n: number): unknown => (n === 0 ? [] : [nest(n - 1)]);
const HOSTILE: Array<[string, unknown]> = [
  ["a list", [1]], ["an object", { a: 1 }], ["a number", 5], ["a float", 1.5], ["true", true], ["null", null], ["the empty string", ""],
  ["a NUL", "a\u0000b"], ["a lone surrogate", "x\udcffy"], ["300 characters", "n".repeat(300)], ["a huge integer", 10 ** 30], ["a negative integer", -1],
  ["a nested list", nest(40)], ["a list of strings", ["a", "b"]], ["a dot-dot path", "../../x"], ["an absolute path", "/proc/self/mem"],
];

function run(script: string, cwd: string, args: unknown): Promise<{ stdout: string; stderr: string; killed: boolean }> {
  return new Promise((resolve) => {
    const child = spawn("python3", [script], { cwd, env: { ...process.env, AGENT_ID: "s1" } });
    const out: Buffer[] = [];
    const err: Buffer[] = [];
    let killed = false;
    const timer = setTimeout(() => {
      killed = true;
      child.kill("SIGKILL");
    }, LIMIT_MS);
    child.stdout.on("data", (c: Buffer) => out.push(c));
    child.stderr.on("data", (c: Buffer) => err.push(c));
    child.on("error", () => undefined);
    child.on("close", () => {
      clearTimeout(timer);
      resolve({ stdout: Buffer.concat(out).toString("utf8"), stderr: Buffer.concat(err).toString("utf8"), killed });
    });
    child.stdin.on("error", () => undefined);
    child.stdin.end(typeof args === "string" ? args : JSON.stringify(args));
  });
}

/** Why an answer is a crash, or null. */
export function crash(r: { stdout: string; stderr: string; killed: boolean }): string | null {
  if (r.killed) return `no answer in ${LIMIT_MS / 1000} s`;
  if (/Traceback/.test(r.stderr)) return `a traceback: ${r.stderr.trim().split("\n").pop()?.slice(0, 120)}`;
  const text = r.stdout.trim();
  if (!text) return "no JSON on stdout";
  try {
    const doc = JSON.parse(text);
    if (!doc || typeof doc !== "object" || Array.isArray(doc)) return "stdout is not a JSON object";
  } catch {
    return "stdout is not one JSON document";
  }
  return null;
}

test("every parameter of each base tool, given a hostile value, ends in a JSON answer and no traceback", { timeout: 900_000 }, async () => {
  // The run's root is three levels inside the test's own tree, so a dot-dot path lands in it and not on whatever the
  // host keeps two levels above its temp directory (on macOS a directory of a million files, which no tool lists in 20 s).
  const top = await mkdtemp(join(tmpdir(), "hostile-"));
  const dir = join(top, "a", "b", "run");
  const failures: string[] = [];
  let cases = 0;
  try {
    await mkdir(join(dir, "work"), { recursive: true });
    await mkdir(join(dir, "inputs"), { recursive: true });
    await writeFile(join(dir, "work", "f.bin"), Buffer.concat([Buffer.from("MZ"), Buffer.alloc(600, 7), Buffer.from("PK\x03\x04", "latin1"), Buffer.alloc(600)]));
    const work: Array<{ tool: string; script: string; base: Record<string, unknown>; param: string; label: string; value: unknown }> = [];
    for (const tool of TOOLS) {
      const manifest = JSON.parse(await readFile(join(ROOT, "packs", "computer-forensics-base", "tools", tool, "manifest.json"), "utf8")) as { params: Record<string, Param> };
      const base: Record<string, unknown> = {};
      for (const [name, p] of Object.entries(manifest.params)) {
        if (!p.required) continue;
        base[name] = p.type === "integer" ? 1 : p.type === "boolean" ? false : p.type === "array" ? ["x"] : /out|output|dir/.test(name) ? `work/${tool}-out` : /needles|pattern|value|sig|inode/.test(name) ? (name === "inode" ? "5" : name === "value" ? "1700000000" : "needle") : "work/f.bin";
      }
      const names = Object.keys(manifest.params);
      let n = 0;
      for (const param of names) {
        for (const [label, value] of HOSTILE) {
          if (n++ >= MAX_CASES) break;
          work.push({ tool, script: join(ROOT, "packs", "computer-forensics-base", "tools", tool, "run.py"), base, param, label, value });
        }
      }
    }
    let next = 0;
    await Promise.all(Array.from({ length: 8 }, async () => {
      while (next < work.length) {
        const w = work[next++];
        cases++;
        const args = { ...w.base, [w.param]: w.value };
        const r = await run(w.script, dir, args);
        const why = crash(r);
        if (why) failures.push(`${w.tool} ${w.param}=${w.label}: ${why}`);
      }
    }));
  } finally {
    await rm(top, { recursive: true, force: true });
  }
  assert.ok(cases >= 500, `${cases} cases`);
  assert.deepEqual(failures.sort(), []);
});

test("the crash check finds a traceback, no JSON, a hang, and takes a JSON refusal", () => {
  assert.match(crash({ stdout: "", stderr: "Traceback (most recent call last):\nTypeError: x", killed: false }) ?? "", /traceback/);
  assert.equal(crash({ stdout: "", stderr: "", killed: false }), "no JSON on stdout");
  assert.match(crash({ stdout: "{}", stderr: "", killed: true }) ?? "", /no answer/);
  assert.equal(crash({ stdout: '{"status":"failed"}', stderr: "", killed: false }), null);
  assert.equal(crash({ stdout: "[1]", stderr: "", killed: false }), "stdout is not a JSON object");
});
