/**
 * The console and the access record (docs/adr/0018, decision 3): the jobs list shows a badge on a sensitive job ("sensitive · N seats read ·
 * M jobs used") and a job's page lists its readers and the jobs made from it, all from the access record; and each time the console serves a
 * sensitive job's log, it first appends a `console_view` line to runs/operator-audit.jsonl in the shape the reader accepts, written by
 * swarm.sh (the one writer, under its lock and its `prev` chain), and serves nothing when the line did not land.
 */
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { spawnSync } from "node:child_process";
import { mkdir, mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { after, before, test } from "node:test";
import { createUiApp, type UiApp } from "../scripts/ui/app.ts";
import { accessRecord } from "../scripts/sensitive-access.ts";
import type { StoreJobDetail, StoreJobsView } from "../scripts/ui/store-jobs.ts";
import { fixtureFiles, writeFiles } from "./sensitive-access-fixture.ts";

const ROOT = join(import.meta.dirname, "..");
const sha = (s: string) => createHash("sha256").update(s).digest("hex");

let runsDir: string;
let S: string;
let app: UiApp;
let base: string;

async function get(path: string): Promise<{ status: number; text: string; body: any }> {
  const res = await fetch(`${base}${path}`);
  const text = await res.text();
  let body: unknown = text;
  try {
    body = JSON.parse(text);
  } catch {
    // plain text
  }
  return { status: res.status, text, body };
}

const auditLines = async () => (await readFile(join(runsDir, "operator-audit.jsonl"), "utf8")).split("\n").filter(Boolean);
const views = async () => (await auditLines()).map((l) => JSON.parse(l) as Record<string, any>).filter((r) => r.command === "console_view");

before(async () => {
  runsDir = await mkdtemp(join(tmpdir(), "console-view-"));
  const files = fixtureFiles();
  // The jobs' logs, and the audit the way the CLI chains it: each line's prev the sha256 of the line before.
  for (const id of ["j000001", "j000010", "j000034"]) files[`run1/store/jobs/${id}/stdout.log`] = `${id} printed this\n`;
  const first = JSON.stringify({ at: "2026-10-21T14:30:00.000Z", command: "start", argv: ["run1"], cwd: "/x", os_user: "examiner", host: "h1", via: "cli", prev: null });
  const second = JSON.stringify({ at: "2026-10-21T14:31:00.000Z", command: "console_view", argv: ["run1"], cwd: "/x", os_user: "examiner", host: "h1", via: "console", detail: { job: "j000001", path: "values.jsonl" }, prev: sha(first) });
  files["operator-audit.jsonl"] = `${first}\n${second}\n`;
  S = await writeFiles(runsDir, files);
  await writeFile(join(runsDir, "registry.json"), `${JSON.stringify({ runs: [{ id: "run1", sandbox: S, state: "stopped" }] })}\n`);
  app = createUiApp({
    root: ROOT,
    runsDir,
    distDir: join(runsDir, "no-dist"),
    models: async () => ({ source: "static", models: ["solo/model"] }),
    readiness: async () => ({ checked_at: "2026-10-21T00:00:00.000Z", providers: {} }),
    liveHubDirs: async () => [],
    heartbeatMs: 200,
  });
  const { port } = await app.listen(0, "127.0.0.1");
  base = `http://127.0.0.1:${port}`;
});

after(async () => {
  await app?.close();
  await rm(runsDir, { recursive: true, force: true });
});

test("the jobs list badges a sensitive job with how many seats read it and how many jobs used it, and no other", async () => {
  const { status, body } = await get("/api/swarms/run1/jobs");
  assert.equal(status, 200);
  const v = body as StoreJobsView;
  const by = new Map(v.jobs.map((j) => [j.id, j.sensitive]));
  assert.equal(by.get("j000001")?.badge, "sensitive · 1 seat read · 2 jobs used");
  assert.deepEqual([by.get("j000001")?.why, by.get("j000001")?.seats_read, by.get("j000001")?.jobs_used], ["secret_output", 1, 2]);
  assert.equal(by.get("j000034")?.badge, "sensitive · 0 seats read · 1 job used", "a derived job is sensitive too; the read of its output the hub did not record is not counted");
  assert.equal(by.get("j000010") ?? null, null, "a job that is not sensitive has none");
});

test("a sensitive job's page lists its readers, the jobs made from it, the entries that cite it and the views, and says the list is a lower bound", async () => {
  const { status, body } = await get("/api/swarms/run1/jobs/j000001");
  assert.equal(status, 200);
  const a = (body as StoreJobDetail).access as NonNullable<StoreJobDetail["access"]>;
  assert.deepEqual(a.readers.map((r) => [r.seat, r.reads, r.certainty]), [["agent-2", 1, "path"]]);
  assert.deepEqual(a.dependents.map((d) => [d.job, d.how]), [["j000034", "declared"], ["j000037", "named_in_text"]]);
  assert.deepEqual(a.cited_by, [57]);
  assert.ok(a.console_views >= 1);
  assert.match(a.lower_bound, /This list is a lower bound\.$/);
  assert.equal(((await get("/api/swarms/run1/jobs/j000060")).body as StoreJobDetail).access, null, "no access section on a job that is not sensitive");
});

test("serving a sensitive job's log appends a console_view line first, in the shape the reader takes, chained under the writer's lock", async () => {
  const before = await auditLines();
  const page = await get("/api/swarms/run1/jobs/j000001/log/stdout.log");
  assert.equal(page.status, 200);
  assert.equal(page.body.text, "j000001 printed this\n");
  const raw = await get("/api/swarms/run1/jobs/j000001/log/stdout.log?raw=1");
  assert.equal(raw.status, 200);
  assert.equal(raw.text, "j000001 printed this\n");
  const after = await auditLines();
  assert.equal(after.length, before.length + 2, "one line for each time it was served");
  for (const [i, line] of after.slice(before.length).entries()) {
    const r = JSON.parse(line) as Record<string, any>;
    assert.equal(r.command, "console_view");
    assert.deepEqual(r.argv, ["run1"], "the run id is in argv");
    assert.deepEqual(r.detail, { job: "j000001", path: "store/jobs/j000001/stdout.log" }, "a job and a path, never a value");
    assert.equal(r.via, "console");
    assert.ok(r.os_user && r.host && r.at && typeof r.cwd === "string");
    assert.equal(r.prev, sha(after[before.length + i - 1]), "chained to the line before, as operator_audit chains it");
  }
  // The reader takes them: two more console views of j000001 than before, by the operator, never as an agent's read.
  const rec = await accessRecord(S, { runsDir, runId: "run1" });
  const ops = rec.events.filter((e) => e.source === "operator_audit" && e.job === "j000001");
  assert.equal(ops.length, 3);
  assert.ok(ops.every((e) => e.evidence === "harness_observed_read" && e.via === "operator_view" && e.seat === null && e.operator?.includes("@")));
  assert.deepEqual(rec.problems, []);
  // The chain holds across the whole file.
  const all = await auditLines();
  for (let i = 1; i < all.length; i += 1) assert.equal(JSON.parse(all[i]).prev, sha(all[i - 1]), `line ${i + 1} names the line before it`);
});

test("a log of a job that is not sensitive, or that is not there, adds no line", async () => {
  const n = (await auditLines()).length;
  assert.equal((await get("/api/swarms/run1/jobs/j000010/log/stdout.log")).status, 200);
  assert.equal((await get("/api/swarms/run1/jobs/j000010/log/stdout.log?raw=1")).status, 200);
  assert.equal((await get("/api/swarms/run1/jobs/j000001/log/stderr.log")).status, 404, "a log the job does not have");
  assert.equal((await get("/api/swarms/run1/jobs/j000001/log/other.txt")).status, 400);
  assert.equal((await auditLines()).length, n);
});

test("concurrent views each leave their own line and the chain holds", async () => {
  const n = (await auditLines()).length;
  const answers = await Promise.all(Array.from({ length: 6 }, (_, i) => get(`/api/swarms/run1/jobs/${i % 2 ? "j000001" : "j000034"}/log/stdout.log?offset=${i}`)));
  assert.ok(answers.every((a) => a.status === 200));
  const all = await auditLines();
  assert.equal(all.length, n + 6);
  for (let i = 1; i < all.length; i += 1) assert.equal(JSON.parse(all[i]).prev, sha(all[i - 1]));
});

test("when the line cannot be written nothing is served: a view is never unrecorded", async () => {
  const file = join(runsDir, "operator-audit.jsonl");
  const saved = await readFile(file, "utf8");
  await rm(file);
  await mkdir(file); // a directory where the audit should be
  try {
    const refused = await get("/api/swarms/run1/jobs/j000001/log/stdout.log?raw=1");
    assert.equal(refused.status, 503);
    assert.doesNotMatch(refused.text, /printed this/);
    assert.match(refused.text, /could not be recorded on the operator's audit/);
    assert.equal((await get("/api/swarms/run1/jobs/j000010/log/stdout.log")).status, 200, "a job that is not sensitive is still served");
  } finally {
    await rm(file, { recursive: true, force: true });
    await writeFile(file, saved);
  }
});

test("swarm.sh console-view is not a command of the operator's: it refuses arguments that are not a run, a job and a path", () => {
  const run = (...a: string[]) => spawnSync("bash", [join(ROOT, "scripts", "swarm.sh"), "console-view", ...a], { encoding: "utf8", env: { ...process.env, SWARM_RUNS_DIR: runsDir, SWARM_OPERATOR_VIA: "console" } });
  assert.equal(run().status, 2);
  assert.equal(run("run1", "J 1", "p").status, 2);
  assert.equal(run("run 1", "j000001", "p").status, 2);
  assert.equal(run("run1", "j000001", "").status, 2);
  assert.equal(run("run1", "j000001", "a\nb").status, 2);
});
