/**
 * ransomware-response: the rows a table shows inline stop at about 512 KiB as well as at `limit`, in ransom_note_scan and
 * encrypted_survey. A `limit` of 1,000,000 over 100,000 rows used to put every row in the answer, which was then judged, serialised and
 * read back, so the run overran its max_seconds and its memory grew with the table. The cut is lossless: every row is in the paging file
 * the table names. The trees are made here (100,000 files each) from the names the tools document; nothing is a tool's own output.
 *
 * The two pack-local LosslessPage classes are the same text (the size bound is copied, not rewritten); a test holds them equal.
 */
import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { mkdir, readFile, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { test } from "node:test";
import { runPySnippet, withCwd } from "./tool-library-harness.ts";
import { NOTES, SURVEY } from "./ransomware-pack-harness.ts";

const FILES = 100_000;
const SECONDS = 30;
/** The peak resident set the bounded tools stay under over this tree, in MiB. Measured over the same tree and `limit` 1,000,000 (Linux,
 * Python 3.12): the fixed ransom_note_scan 43 MiB and 0.64 MB of stdout in 9.3 s, encrypted_survey 29 MiB and 0.66 MB in 5.1 s; the
 * tools as they were: 445 MiB and 65 MB in 10.1 s, 349 MiB and 51 MB in 5.6 s (every row held in the answer, then serialised). */
const RSS_MIB_BOUND = 150;

/** Make `count` files in directories of 1,000, named by `name(i)`, each holding `body`. */
async function tree(root: string, count: number, name: (i: number) => string, body: string): Promise<void> {
  for (let d = 0; d * 1000 < count; d++) {
    const dir = join(root, `d${String(d).padStart(4, "0")}`);
    await mkdir(dir, { recursive: true });
    const writes: Promise<void>[] = [];
    for (let i = d * 1000; i < Math.min(count, (d + 1) * 1000); i++) writes.push(writeFile(join(dir, name(i)), body));
    await Promise.all(writes);
  }
}

type Measured = { code: number | null; elapsed: number; rssMiB: number; stdout: string; stderr: string };

/** Run a tool with its arguments on stdin, from `cwd`, through a small parent that reports the child's peak resident set. */
function measure(script: string, cwd: string, args: unknown): Promise<Measured> {
  const driver = String.raw`
import json, resource, subprocess, sys, time
t = time.monotonic()
p = subprocess.run([sys.executable, sys.argv[1]], input=sys.stdin.buffer.read(), capture_output=True)
rss = resource.getrusage(resource.RUSAGE_CHILDREN).ru_maxrss
rss = rss / (1024 * 1024) if sys.platform == "darwin" else rss / 1024
sys.stdout.write(json.dumps({"code": p.returncode, "elapsed": time.monotonic() - t, "rssMiB": rss, "stdout": p.stdout.decode("utf-8", "replace"), "stderr": p.stderr.decode("utf-8", "replace")}))
`;
  return new Promise((resolve, reject) => {
    const child = spawn("python3", ["-c", driver, script], { cwd, env: { ...process.env, AGENT_ID: "s1" } });
    const out: Buffer[] = [];
    const timer = setTimeout(() => child.kill("SIGKILL"), 300_000);
    child.stdout.on("data", (c: Buffer) => out.push(c));
    child.on("error", reject);
    child.on("close", () => {
      clearTimeout(timer);
      try {
        resolve(JSON.parse(Buffer.concat(out).toString("utf8")) as Measured);
      } catch (e) {
        reject(e);
      }
    });
    child.stdin.end(JSON.stringify(args));
  });
}

type Json = Record<string, any>; // eslint-disable-line @typescript-eslint/no-explicit-any

async function check(script: string, cwd: string, root: string, table: string): Promise<void> {
  const run = await measure(script, cwd, { root, limit: 1_000_000, max_seconds: SECONDS });
  assert.doesNotMatch(run.stderr, /Traceback/);
  const answer = JSON.parse(run.stdout) as Json;
  assert.ok(answer.status, "one JSON answer with a status");
  assert.ok(run.elapsed < SECONDS + 2, `ended in ${run.elapsed.toFixed(1)} s, over max_seconds + 2`);
  const page = answer.pages[table] as Json;
  assert.ok(page.matched >= FILES / 2, `${table}: ${page.matched} rows matched`);
  assert.equal(typeof page.inline_cut_by_size, "string", `${table}: the cut by size is named`);
  assert.match(page.inline_cut_by_size, /512|524288/);
  assert.ok(page.returned < page.matched && page.returned < 1_000_000, `${table}: the rows shown inline are cut (${page.returned} of ${page.matched})`);
  assert.equal(page.truncated, true);
  assert.ok(page.all_results, `${table}: the whole table is named`);
  const lines = (await readFile(join(cwd, page.all_results), "utf8")).trimEnd().split("\n");
  assert.equal(lines.length, page.matched, `${table}: every row is in the paging file`);
  assert.ok(run.rssMiB < RSS_MIB_BOUND, `peak resident set ${run.rssMiB.toFixed(0)} MiB, over the ${RSS_MIB_BOUND} MiB bound`);
  assert.ok(run.stdout.length < 4_000_000, `${run.stdout.length} bytes of stdout`);
}

test("ransom_note_scan: 100,000 note-named files with limit 1,000,000 end within max_seconds + 2 s, cut the inline rows by size and keep every row in the paging file", { timeout: 600_000 }, async () => {
  await withCwd(async (cwd) => {
    const root = join(cwd, "work", "ev");
    await tree(root, FILES, (i) => `README_decrypt_${String(i).padStart(6, "0")}.txt`, "Your files are encrypted. Contact us.\n");
    await check(NOTES, cwd, "work/ev", "notes");
  });
});

test("encrypted_survey: 100,000 candidate files with limit 1,000,000 end within max_seconds + 2 s, cut the inline rows by size and keep every row in the paging file", { timeout: 600_000 }, async () => {
  await withCwd(async (cwd) => {
    const root = join(cwd, "work", "ev");
    await tree(root, FILES, (i) => `report_${String(i).padStart(6, "0")}.docx.locked`, "x\n");
    const run = await measure(SURVEY, cwd, { root: "work/ev", limit: 1_000_000, max_seconds: SECONDS });
    assert.doesNotMatch(run.stderr, /Traceback/);
    const answer = JSON.parse(run.stdout) as Json;
    assert.ok(answer.status, "one JSON answer with a status");
    assert.ok(run.elapsed < SECONDS + 2, `ended in ${run.elapsed.toFixed(1)} s, over max_seconds + 2`);
    const tables = Object.entries(answer.pages as Json).filter(([, p]) => (p as Json).inline_cut_by_size);
    assert.ok(tables.length >= 1, `a table is cut by size: ${Object.keys(answer.pages).join(", ")}`);
    for (const [name, p] of tables) {
      const page = p as Json;
      assert.ok(page.all_results, `${name}: the whole table is named`);
      const lines = (await readFile(join(cwd, page.all_results), "utf8")).trimEnd().split("\n");
      assert.equal(lines.length, page.matched, `${name}: every row is in the paging file`);
      assert.ok(page.returned < page.matched, `${name}: the inline rows are cut`);
    }
    assert.ok(run.rssMiB < RSS_MIB_BOUND, `peak resident set ${run.rssMiB.toFixed(0)} MiB, over the ${RSS_MIB_BOUND} MiB bound`);
  });
});

test("the two LosslessPage classes of the pack are the same text", async () => {
  const code = String.raw`
import ast, sys
def cls(path):
    src = open(path, encoding="utf-8").read()
    for node in ast.parse(src).body:
        if isinstance(node, ast.ClassDef) and node.name == "LosslessPage":
            return ast.get_source_segment(src, node)
    raise SystemExit("no LosslessPage in " + path)
a, b = cls(sys.argv[1]), cls(sys.argv[2])
if a != b:
    import difflib
    sys.exit("\n".join(difflib.unified_diff(a.splitlines(), b.splitlines(), "ransom_note_scan", "encrypted_survey", lineterm="")))
print("equal")
`;
  const out = await runPySnippet(code, [NOTES, SURVEY], "");
  assert.equal(out.code, 0, out.stderr + out.stdout);
  assert.match(out.stdout, /equal/);
});
