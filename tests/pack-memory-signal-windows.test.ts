/**
 * A stop (SIGTERM) delivered at each point of the end of a memory tool: the hidden temporary file just created, the final name taken but
 * not yet filled, the file moved onto its name, the rows placed, the answer printed. Whatever the point, the tool ends with ONE JSON
 * answer whose status is "complete" (the work was done: the final named output) or "interrupted" (a clearly partial answer that names the
 * whole kept file), never with a hidden temporary name in the answer, a second document, an empty stray file, or a file no answer names.
 *
 * A timer finds these points only by luck (mem_carve's SIGTERM test failed on a runner when the stop landed in the second of them), so
 * tests/memory-signal-inject.py sends the signal at the point itself. Every case here fails on the tools as they were on main
 * (MEM_TOOLS_DIR points the suite at a checkout of them).
 */
import assert from "node:assert/strict";
import { readFile, readdir, realpath, stat, writeFile } from "node:fs/promises";
import { basename, join, resolve } from "node:path";
import { test } from "node:test";
import { ROOT, withCwd } from "./tool-library-harness.ts";
import { CARVE, FS, PROFILE, fsStub, runTool } from "./memory-f1-support.ts";

const INJECT = join(ROOT, "tests", "memory-signal-inject.py");
const POINTS = ["after_tmp_open", "before_replace", "after_replace", "after_finish", "after_answer"] as const;
type Answer = Record<string, any>;

/** The JSON documents in a text: top-level objects, found by their braces (a string's braces do not count). */
function documents(text: string): Answer[] {
  const found: Answer[] = [];
  let depth = 0, from = -1, inString = false, escaped = false;
  for (let i = 0; i < text.length; i++) {
    const c = text[i];
    if (inString) { if (escaped) escaped = false; else if (c === "\\") escaped = true; else if (c === '"') inString = false; continue; }
    if (c === '"') inString = true;
    else if (c === "{") { if (depth++ === 0) from = i; }
    else if (c === "}" && --depth === 0) found.push(JSON.parse(text.slice(from, i + 1)));
  }
  assert.equal(depth, 0, `the output ends inside a document: ${text.slice(-200)}`);
  return found;
}

/** Every file name an answer gives, wherever the tool puts it. */
function names(answer: Answer): string[] {
  const out: string[] = [];
  const walk = (value: unknown, key = ""): void => {
    if (typeof value === "string" && ["partial_results", "complete_results", "all_results", "ranges_all"].includes(key)) out.push(value);
    else if (Array.isArray(value)) for (const v of value) { if (key === "kept_results" && typeof v === "string") out.push(v); else walk(v, key); }
    else if (value && typeof value === "object") for (const [k, v] of Object.entries(value)) walk(v, k);
  };
  walk(answer);
  return out;
}

async function files(dir: string): Promise<string[]> {
  const out: string[] = [];
  for (const entry of await readdir(dir, { withFileTypes: true })) {
    if (entry.isDirectory()) out.push(...(await files(join(dir, entry.name))));
    else out.push(join(dir, entry.name));
  }
  return out;
}

const rowCount = async (path: string): Promise<number> => (await readFile(path, "utf8")).split("\n").filter(Boolean).length;

/** Run the tool with the stop at `point` and hold the answer, the exit status and the files left to the rules above. */
async function stopAt(tool: string, point: string, cwd: string, args: unknown, env: Record<string, string>, bin: string | undefined, total: number, ignore: (file: string) => boolean): Promise<Answer> {
  const run = await runTool(INJECT, cwd, args, { ...env, INJECT_TOOL: tool, INJECT_POINT: point }, bin);
  const label = `${basename(join(tool, ".."))} at ${point}`;
  assert.doesNotMatch(run.stderr, /Traceback/, `${label}: ${run.stderr}`);
  const docs = documents(run.stdout);
  assert.equal(docs.length, 1, `${label}: ${docs.length} documents on stdout: ${docs.map((d) => d.status).join(", ")}`);
  const answer = docs[0];
  assert.ok(["complete", "interrupted"].includes(answer.status), `${label}: status ${answer.status}`);
  assert.equal(run.code, answer.status === "complete" ? 0 : 143, `${label}: exit status`);
  const named: string[] = [];
  for (const n of names(answer)) named.push(await realpath(resolve(cwd, n)).catch(() => resolve(cwd, n)));
  for (const n of named) {
    assert.ok(!basename(n).startsWith("."), `${label}: the answer names a hidden file, ${n}`);
    assert.ok((await stat(n).catch(() => null)) !== null, `${label}: the answer names ${n}, which is not there`);
  }
  const left = (await files(join(cwd, "work"))).filter((f) => !ignore(f));
  for (const f of left) {
    const real = await realpath(f);
    assert.ok(!basename(f).startsWith("."), `${label}: a hidden file is left, ${f}`);
    assert.ok(named.includes(real), `${label}: ${f} is left and no answer names it`);
    const rows = await rowCount(f);
    // a stop before the first hit keeps an empty file, named, and the answer counts no hit
    if (rows === 0) assert.ok(answer.status === "interrupted" && answer.hit_count_so_far === 0, `${label}: ${f} is empty`);
    if (answer.status === "complete") assert.equal(rows, total, `${label}: the named file holds ${rows} rows of ${total}`);
  }
  return answer;
}

const dense = (count: number): Buffer => {
  const blob = Buffer.alloc(count * 16);
  for (let i = 0; i < count; i++) blob.write("regf", i * 16, "latin1");
  return blob;
};

for (const [mode, extra] of [["a results_to", { results_to: "work/s1/sig.jsonl" }], ["no results_to (the tool's own file)", {}]] as const) {
  test(`mem_carve stop at each point of its ending with ${mode}: one answer, no hidden name, no stray file`, async () => {
    for (const point of POINTS) {
      await withCwd(async (cwd) => {
        await writeFile(join(cwd, "work", "d.raw"), dense(3000));
        const answer = await stopAt(CARVE, point, cwd, { path: "work/d.raw", limit: 10, ...extra }, {}, undefined, 3000, (f) => f === join(cwd, "work", "d.raw"));
        if (answer.status === "complete") assert.equal(answer.hit_count, 3000);
        else assert.equal(answer.hit_count_so_far, await rowCount(resolve(cwd, answer.partial_results)));
      });
    }
  });
}

test("mem_profile stop at each point of the end of its range list: one answer, no hidden name, a finished list is named", async () => {
  for (const point of POINTS) {
    await withCwd(async (cwd) => {
      const lime = Buffer.concat(Array.from({ length: 3000 }, (_, i) => {
        const head = Buffer.alloc(32);
        head.writeUInt32LE(0x4c694d45, 0); head.writeUInt32LE(1, 4); head.writeBigUInt64LE(BigInt(i) * 0x1000n, 8); head.writeBigUInt64LE(BigInt(i) * 0x1000n, 16);
        return Buffer.concat([head, Buffer.from("x")]);
      }));
      await writeFile(join(cwd, "work", "l.lime"), lime);
      await stopAt(PROFILE, point, cwd, { path: "work/l.lime" }, {}, undefined, 3000, (f) => f === join(cwd, "work", "l.lime"));
    });
  }
});

test("mem_fs stop at each point of the end of its listing: one answer, no hidden name, a finished list is named", async () => {
  for (const point of POINTS) {
    await withCwd(async (cwd, bin) => {
      const tree: Record<string, string> = { "sys/x": "" };
      for (let i = 0; i < 400; i++) tree[`proc/f${String(i).padStart(4, "0")}.txt`] = "x";
      const env = await fsStub(cwd, bin, { tree });
      await writeFile(join(cwd, "inputs", "memory.raw"), Buffer.alloc(4096));
      // the engine's own logs are kept by design and named in logs; the image is the evidence
      const answer = await stopAt(FS, point, cwd, { path: "inputs/memory.raw", mount: "work/s1/m", mode: "list", list: "proc", limit: 10, timeout_seconds: 30 }, env, bin, 400, (f) => /\.memprocfs-.*\.log$/.test(f));
      if (answer.status === "complete") assert.equal(answer.entry_count, 400);
    });
  }
});
