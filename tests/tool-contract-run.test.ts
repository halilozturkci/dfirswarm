/**
 * Two repo-wide checks that run every bundled tool (packs/*\/tools/*) against the tool contract (docs/packs.md, section 8):
 *
 *  3. The status pair. Given `{}`, and given a path that is not there in an empty directory, a tool answers JSON whose `status` is complete, partial or
 *     failed and whose `status_basis` is not empty. A tool that answers nothing, or something else, fails.
 *  4. Names that are not UTF-8 (Linux only: other file systems refuse the name). Given a file named with the byte 0xff, and given a directory named so, a
 *     tool answers one JSON document that is strict UTF-8, and every JSON Lines file it left behind parses, row by row.
 *
 * Each run is in an empty temporary directory, with AGENT_ID=s1, and ends in SIGKILL after 20 seconds. tests/tool-contract-allowed.json names every current
 * failure with the item or package that removes it; it may only shrink (a failure with no entry fails, and so does an entry that no longer fails).
 * The recipes are not run here: they need the programs they drive and take their input from the harness, not from stdin.
 */
import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { mkdir, mkdtemp, readdir, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { test } from "node:test";
import { fileURLToPath } from "node:url";

const ROOT = join(dirname(fileURLToPath(import.meta.url)), "..");
const LIMIT_MS = 20_000;
const CONCURRENT = 8;

type Param = { type?: string; required?: boolean };
type Manifest = { name: string; version: number; params?: Record<string, Param> };
type Tool = { id: string; dir: string; manifest: Manifest };
type Entry = { tool: string; item: string; why: string };

async function bundledTools(): Promise<Tool[]> {
  const out: Tool[] = [];
  const packs = join(ROOT, "packs");
  for (const pack of (await readdir(packs)).sort()) {
    const tools = join(packs, pack, "tools");
    for (const name of await readdir(tools).catch(() => [] as string[])) {
      const manifest = await readFile(join(tools, name, "manifest.json"), "utf8").then((t) => JSON.parse(t) as Manifest, () => null);
      if (manifest) out.push({ id: `${pack}/${name}`, dir: join(tools, name), manifest });
    }
  }
  return out.sort((a, b) => a.id.localeCompare(b.id));
}

async function allowed(name: string): Promise<Entry[]> {
  const all = JSON.parse(await readFile(join(ROOT, "tests", "tool-contract-allowed.json"), "utf8")) as Record<string, Entry[]>;
  const list = all[name];
  assert.ok(Array.isArray(list), `tests/tool-contract-allowed.json has no list "${name}"`);
  for (const e of list) assert.ok(e.tool && e.item && e.why && !/\n/.test(e.why), `${name}: an entry needs tool, item and a one-line why: ${JSON.stringify(e)}`);
  assert.equal(new Set(list.map((e) => e.tool)).size, list.length, `${name}: a tool twice`);
  return list;
}

function settle(name: string, failures: Map<string, string>, list: Entry[]): void {
  const known = new Set(list.map((e) => e.tool));
  const fresh = [...failures].filter(([tool]) => !known.has(tool)).map(([tool, why]) => `  ${tool}: ${why}`);
  assert.equal(fresh.length, 0, `${name}: ${fresh.length} tool(s) fail with no entry in tests/tool-contract-allowed.json (fix the tool, or add an entry naming the item that will):\n${fresh.join("\n")}`);
  const stale = list.filter((e) => !failures.has(e.tool)).map((e) => `  ${e.tool} (${e.item})`);
  assert.equal(stale.length, 0, `${name}: ${stale.length} entr(ies) of tests/tool-contract-allowed.json no longer fail, remove them:\n${stale.join("\n")}`);
}

type Run = { code: number | null; stdout: Buffer; stderr: string; killed: boolean };

function run(tool: Tool, cwd: string, params: unknown): Promise<Run> {
  return new Promise((resolve) => {
    const child = spawn("python3", [join(tool.dir, "run.py")], { cwd, env: { ...process.env, AGENT_ID: "s1" }, stdio: ["pipe", "pipe", "pipe"] });
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
    child.on("close", (code) => {
      clearTimeout(timer);
      resolve({ code, stdout: Buffer.concat(out), stderr: Buffer.concat(err).toString("utf8"), killed });
    });
    child.stdin.on("error", () => undefined);
    child.stdin.end(JSON.stringify(params));
  });
}

/** Run `fn` over `items`, `CONCURRENT` at a time. */
async function pool<T>(items: T[], fn: (item: T) => Promise<void>): Promise<void> {
  let next = 0;
  await Promise.all(Array.from({ length: CONCURRENT }, async () => {
    while (next < items.length) await fn(items[next++]);
  }));
}

async function inEmptyDir<T>(fn: (cwd: string) => Promise<T>): Promise<T> {
  const cwd = await mkdtemp(join(tmpdir(), "tool-contract-"));
  try {
    return await fn(cwd);
  } finally {
    await rm(cwd, { recursive: true, force: true });
  }
}

/** The first required parameter that names a path, else the first parameter that does (a name read from the manifest, not a list of tools). */
const PATHISH = /^(path|root|image|source|db_path|db|hive|file|dir|directory|input|archive|pcap|log|logfile|evidence)$/;
export function pathParam(manifest: Manifest): string | null {
  const params = Object.entries(manifest.params ?? {}).filter(([, p]) => p?.type === "string");
  return (params.find(([k, p]) => p.required && PATHISH.test(k)) ?? params.find(([k]) => PATHISH.test(k)))?.[0] ?? null;
}

// ---- 3. the status pair ---------------------------------------------------------------------------------------------------------------------

/** Why an answer is not a status pair, or null. */
export function statusFailure(r: Run): string | null {
  if (r.killed) return `no answer in ${LIMIT_MS / 1000} s`;
  const text = r.stdout.toString("utf8").trim();
  if (!text) return `no JSON on stdout (exit ${r.code})${/Traceback/.test(r.stderr) ? ", a traceback on stderr" : ""}`;
  let doc: unknown;
  try {
    doc = JSON.parse(text);
  } catch {
    return `stdout is not one JSON document (exit ${r.code})`;
  }
  if (!doc || typeof doc !== "object" || Array.isArray(doc)) return "the answer is not a JSON object";
  const { status, status_basis: basis } = doc as { status?: unknown; status_basis?: unknown };
  if (status !== "complete" && status !== "partial" && status !== "failed") return `status is ${JSON.stringify(status)}`;
  if (typeof basis !== "string" || !basis.trim()) return "status_basis is missing or empty";
  return null;
}

test("every tool, given {} and given a missing path, answers JSON with a status and a status_basis", { timeout: 900_000 }, async () => {
  const tools = await bundledTools();
  assert.ok(tools.length >= 80, `${tools.length} tools found`);
  const failures = new Map<string, string>();
  let runs = 0;
  await pool(tools, async (tool) => {
    const missing = pathParam(tool.manifest);
    const cases: [string, unknown][] = [["{}", {}]];
    if (missing) cases.push([`${missing}: a path that is not there`, { [missing]: "work/does-not-exist-s1" }]);
    for (const [label, params] of cases) {
      const r = await inEmptyDir((cwd) => run(tool, cwd, params));
      runs++;
      const why = statusFailure(r);
      if (why && !failures.has(tool.id)) failures.set(tool.id, `given ${label}: ${why}`);
    }
  });
  assert.ok(runs >= tools.length, `${runs} runs`);
  settle("status_pair", failures, await allowed("status_pair"));
});

test("the status check finds an answer without a status, with an empty basis, with no JSON, and takes a good one", () => {
  const answer = (text: string, code = 0): Run => ({ code, stdout: Buffer.from(text), stderr: "", killed: false });
  assert.equal(statusFailure(answer('{"status":"failed","status_basis":"no path"}', 1)), null);
  assert.equal(statusFailure(answer('{"status":"partial","status_basis":"x"}')), null);
  assert.match(statusFailure(answer('{"error":"no path"}', 1)) ?? "", /status is undefined/);
  assert.match(statusFailure(answer('{"status":"complete","status_basis":""}')) ?? "", /status_basis/);
  assert.match(statusFailure(answer('{"status":"ok","status_basis":"x"}')) ?? "", /status is "ok"/);
  assert.match(statusFailure(answer("")) ?? "", /no JSON/);
  assert.match(statusFailure(answer("not json", 1)) ?? "", /not one JSON document/);
  assert.match(statusFailure({ ...answer(""), killed: true }) ?? "", /no answer/);
});

// ---- 4. names that are not UTF-8 -------------------------------------------------------------------------------------------------------------

/** The JSON Lines files under `dir` with a row that does not parse, or null when every row parses. */
export async function brokenRows(dir: string): Promise<string | null> {
  for (const e of await readdir(dir, { withFileTypes: true, recursive: true }).catch(() => [])) {
    if (!e.isFile() || !/\.(jsonl|ndjson)$/.test(e.name)) continue;
    const lines = (await readFile(join(e.parentPath, e.name), "utf8").catch(() => "")).split("\n");
    for (let i = 0; i < lines.length; i++) {
      if (!lines[i].trim()) continue;
      try {
        JSON.parse(lines[i]);
      } catch {
        return `${e.name}: row ${i + 1} does not parse`;
      }
    }
  }
  return null;
}

/** Why a run given a non-UTF-8 name is not one UTF-8 JSON answer with whole paging files, or null. */
export async function nameFailure(r: Run, cwd: string): Promise<string | null> {
  if (r.killed) return `no answer in ${LIMIT_MS / 1000} s`;
  if (!r.stdout.length) return `no JSON on stdout (exit ${r.code})${/Traceback/.test(r.stderr) ? ", a traceback on stderr" : ""}`;
  let text: string;
  try {
    text = new TextDecoder("utf-8", { fatal: true }).decode(r.stdout);
  } catch {
    return "stdout is not UTF-8";
  }
  try {
    JSON.parse(text);
  } catch {
    return "stdout is not one JSON document";
  }
  const broken = await brokenRows(cwd);
  return broken ? `a paging file is left with a row that does not parse (${broken})` : null;
}

const NAME = Buffer.concat([Buffer.from("name-"), Buffer.from([0xff]), Buffer.from(".bin")]);

test("every tool that takes a path, given a file and given a directory named with the byte 0xff, answers one UTF-8 JSON document and leaves paging files whose rows all parse", { timeout: 900_000, skip: process.platform !== "linux" ? "only Linux file systems take a name that is not UTF-8" : false }, async () => {
  const tools = (await bundledTools()).filter((t) => pathParam(t.manifest));
  assert.ok(tools.length >= 60, `${tools.length} tools take a path`);
  const failures = new Map<string, string>();
  await pool(tools, async (tool) => {
    const param = pathParam(tool.manifest) as string;
    for (const kind of ["file", "directory"]) {
      const why = await inEmptyDir(async (cwd) => {
        const target = Buffer.concat([Buffer.from(cwd + "/"), NAME]);
        if (kind === "file") await writeFile(target, Buffer.from("not an artefact\n"));
        else {
          await mkdir(target);
          await writeFile(Buffer.concat([target, Buffer.from("/inner.bin")]), Buffer.from("not an artefact\n"));
        }
        // the name reaches a tool as JSON does: a byte that is not UTF-8 is a lone surrogate (Python's surrogateescape reads it back as the byte)
        const r = await run(tool, cwd, { [param]: "name-\udcff.bin" });
        return nameFailure(r, cwd);
      });
      if (why && !failures.has(tool.id)) failures.set(tool.id, `given a ${kind}: ${why}`);
    }
  });
  settle("non_utf8_name", failures, await allowed("non_utf8_name"));
});

test("the name check finds an answer that is not UTF-8, a torn paging row, and no JSON", async () => {
  await inEmptyDir(async (cwd) => {
    const ok = (text: string | Buffer): Run => ({ code: 0, stdout: Buffer.from(text), stderr: "", killed: false });
    assert.equal(await nameFailure(ok('{"status":"failed"}'), cwd), null);
    assert.match((await nameFailure(ok(Buffer.concat([Buffer.from('{"a":"'), Buffer.from([0xff]), Buffer.from('"}')])), cwd)) ?? "", /not UTF-8/);
    assert.match((await nameFailure(ok(""), cwd)) ?? "", /no JSON/);
    await writeFile(join(cwd, "rows.jsonl"), '{"a":1}\n{"a":2\n');
    assert.match((await nameFailure(ok('{"status":"failed"}'), cwd)) ?? "", /row 2 does not parse/);
  });
});
