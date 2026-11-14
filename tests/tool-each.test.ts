/**
 * A directory given to a one-file reader (IMPROVEMENT-PLAN-2 D4): the job
 * service runs the tool once per file the manifest says it reads, each run
 * with its own output directory, under one clock, and the job's answer is
 * complete only when every run was. A directory with none of its files,
 * too many, or more entries than can be listed is refused before the job
 * runs; a parameter whose description takes a directory is left alone.
 */
import test from "node:test";
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { existsSync, mkdirSync, mkdtempSync, readFileSync, symlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { JobService, describe } from "../scripts/job-service.ts";
import { storePaths } from "../scripts/evidence-store.ts";
import { EACH_MAX, eachOf, oneFileParams } from "../scripts/tool-each.ts";
import { listInputs, localWorker } from "./job-service-worker.ts";

const ROOT = join(import.meta.dirname, "..");
const CFB = join(ROOT, "packs", "computer-forensics-base");

function sandbox(): string {
  const S = join(mkdtempSync(join(tmpdir(), "each-")), "run");
  for (const d of ["inputs", "tools", "catalog", "work/a1"]) mkdirSync(join(S, d), { recursive: true });
  writeFileSync(join(S, "inputs.json"), JSON.stringify({ files: [] }));
  return S;
}

function tool(S: string, name: string, body: string, params: Record<string, unknown>, extra: Record<string, unknown> = {}): void {
  mkdirSync(join(S, "tools", name), { recursive: true });
  writeFileSync(join(S, "tools", name, "run.py"), body);
  const sha = createHash("sha256").update(body).digest("hex");
  writeFileSync(join(S, "tools", name, "manifest.json"), JSON.stringify({ name, description: "t", params, runtime: "python3", entry: "run.py", timeout_seconds: 60, by: "t", at: "t", version: 1, sha256: sha, ...extra }));
}

function service(S: string) {
  return new JobService({
    sandbox: S,
    run: "s000000",
    image: "img:test",
    workers: 2,
    workerCpus: 1,
    workerMemoryMib: 512,
    allowHosts: [],
    openNet: false,
    packDirs: [CFB],
    forging: true,
    minFreeMb: 1,
    runWorker: localWorker(),
    destroyWorker: async () => ({ ok: true }),
    notify: async () => {},
    identity: async (agent) => ({ name: agent, doing: "t" }),
  });
}

async function until(svc: JobService, id: string, ms = 30000) {
  const end = Date.now() + ms;
  for (;;) {
    const j = svc.jobs.get(id);
    if (j && ["committed", "failed", "cancelled"].includes(j.state)) return j;
    if (Date.now() > end) throw new Error(`job ${id} is ${j?.state} after ${ms} ms`);
    await new Promise((r) => setTimeout(r, 50));
  }
}

// Reads one file: writes what it read to $OUT/read.txt; "fail" in a file exits 2, "half" answers partial, "slow" sleeps.
const READER = [
  "import json,os,sys,time",
  "d=json.load(sys.stdin)",
  "t=open(d['path']).read()",
  "if 'slow' in t:",
  "    os.system('sleep 30 & echo $! > ' + os.path.join(os.environ['OUT'], 'grandchild.pid'))",
  "    time.sleep(30)",
  "if 'fail' in t: sys.exit(2)",
  "open(os.path.join(os.environ['OUT'],'read.txt'),'w').write(t)",
  "print(json.dumps({'status': 'partial' if 'half' in t else 'complete', 'path': d['path']}))",
  "",
].join("\n");
const PARAMS = { path: { type: "string", required: true, description: "The log file to read" } };
const USE = { use: { extensions: [".lg"], names: ["main.log"] } };

test("which parameters take one file: a path-like name whose description does not take a directory", () => {
  assert.deepEqual(oneFileParams({ path: { description: "The EVTX file" }, hive: { description: "Path to the hive" }, out_dir: { description: "x" }, image: { description: "An image, or a directory to walk" }, limit: { type: "integer" } }), ["path", "hive"]);
});

test("a directory given to a one-file reader runs it once per file it reads, each in its own output directory, and says complete only when every run was", async () => {
  const S = sandbox();
  mkdirSync(join(S, "inputs", "logs", "sub"), { recursive: true });
  writeFileSync(join(S, "inputs", "logs", "a.lg"), "alpha");
  writeFileSync(join(S, "inputs", "logs", "main.log"), "beta");
  writeFileSync(join(S, "inputs", "logs", "notes.txt"), "not read");
  writeFileSync(join(S, "inputs", "logs", "sub", "c.LG"), "gamma");
  symlinkSync("/etc/hosts", join(S, "inputs", "logs", "link.lg"));
  listInputs(S);
  tool(S, "reader", READER, PARAMS, USE);
  const svc = service(S);
  await svc.start();
  const r = await svc.submit("a1", { kind: "tool", tool: "reader", args: { path: "input:logs" }, inputs: ["all"] });
  assert.ok(r.ok, !r.ok ? r.reason : "");
  assert.deepEqual(r.job.spec.each, { param: "path", directory: "inputs/logs", files: ["inputs/logs/a.lg", "inputs/logs/main.log", "inputs/logs/sub/c.LG"] }, "the files it reads, in name order; the link and the other file are not");
  const job = await until(svc, r.job.id);
  assert.equal(job.status, "ok");
  const dir = join(storePaths(S).jobs, job.id);
  const answer = JSON.parse(readFileSync(join(dir, "stdout.log"), "utf8"));
  assert.equal(answer.status, "complete");
  assert.deepEqual(answer.each, { param: "path", directory: "inputs/logs", files: 3, ran: 3 });
  assert.deepEqual(answer.runs.map((x: { file: string; out: string; exit: number }) => [x.file, x.out, x.exit]), [["inputs/logs/a.lg", "each/1", 0], ["inputs/logs/main.log", "each/2", 0], ["inputs/logs/sub/c.LG", "each/3", 0]]);
  assert.equal(readFileSync(join(dir, "out", "each", "2", "read.txt"), "utf8"), "beta", "each run wrote to its own output directory");
  assert.equal(answer.runs[0].result.path, "inputs/logs/a.lg", "a small answer is carried in the job's answer");
  assert.match(describe(job), /path named the directory inputs\/logs, so the tool was run once for each of the 3 file\(s\)/);
  await svc.stop("test over");
});

test("a run that fails or answers partial makes the job's answer partial, and the reason names the file", async () => {
  const S = sandbox();
  mkdirSync(join(S, "inputs", "logs"), { recursive: true });
  writeFileSync(join(S, "inputs", "logs", "a.lg"), "fail");
  writeFileSync(join(S, "inputs", "logs", "b.lg"), "half");
  writeFileSync(join(S, "inputs", "logs", "c.lg"), "fine");
  listInputs(S);
  tool(S, "reader", READER, PARAMS, USE);
  const svc = service(S);
  await svc.start();
  const r = await svc.submit("a1", { kind: "tool", tool: "reader", args: { path: "inputs/logs" }, inputs: ["all"] });
  assert.ok(r.ok, !r.ok ? r.reason : "");
  const job = await until(svc, r.job.id);
  const answer = JSON.parse(readFileSync(join(storePaths(S).jobs, job.id, "stdout.log"), "utf8"));
  assert.equal(answer.status, "partial");
  assert.deepEqual(answer.status_basis, ["inputs/logs/a.lg: exit 2", "inputs/logs/b.lg: its answer is not complete"]);
  assert.deepEqual(answer.runs.map((x: { settled: boolean }) => x.settled), [false, false, true]);
  await svc.stop("test over");
});

test("the clock of the job ends the run in progress with its own session, names what was not run, and answers within the job's limit", async () => {
  const S = sandbox();
  mkdirSync(join(S, "inputs", "logs"), { recursive: true });
  writeFileSync(join(S, "inputs", "logs", "a.lg"), "fine");
  writeFileSync(join(S, "inputs", "logs", "b.lg"), "slow");
  writeFileSync(join(S, "inputs", "logs", "c.lg"), "fine");
  listInputs(S);
  tool(S, "reader", READER, PARAMS, USE);
  const svc = service(S);
  await svc.start();
  const t0 = Date.now();
  const r = await svc.submit("a1", { kind: "tool", tool: "reader", args: { path: "inputs/logs" }, inputs: ["all"], timeout_seconds: 10 });
  assert.ok(r.ok, !r.ok ? r.reason : "");
  const job = await until(svc, r.job.id);
  assert.ok(Date.now() - t0 < 10000, `answered within the job's 10 s limit (${Date.now() - t0} ms)`);
  const dir = join(storePaths(S).jobs, job.id);
  const answer = JSON.parse(readFileSync(join(dir, "stdout.log"), "utf8"));
  assert.equal(answer.status, "partial");
  assert.deepEqual(answer.not_run, ["inputs/logs/c.lg"]);
  assert.equal(answer.runs[1].stopped_by, "clock");
  const pidFile = join(dir, "out", "each", "2", "grandchild.pid");
  if (existsSync(pidFile)) {
    const pid = Number(readFileSync(pidFile, "utf8"));
    let alive = true;
    try {
      process.kill(pid, 0);
    } catch {
      alive = false;
    }
    assert.equal(alive, false, "the run's own session was ended, its child too");
  }
  await svc.stop("test over");
});

test("a directory with none of its files, more than EACH_MAX of them, or a parameter that takes a directory", () => {
  const S = sandbox();
  mkdirSync(join(S, "inputs", "none"), { recursive: true });
  writeFileSync(join(S, "inputs", "none", "x.txt"), "x");
  const man = { params: PARAMS, ...USE };
  const none = eachOf(S, "reader", { path: "inputs/none" }, man);
  assert.equal(none.ok, false);
  assert.match(!none.ok ? none.reason : "", /which holds no file its manifest says it reads .*give path the file itself/);
  mkdirSync(join(S, "inputs", "many"), { recursive: true });
  for (let i = 0; i <= EACH_MAX; i += 1) writeFileSync(join(S, "inputs", "many", `f${i}.lg`), "x");
  const many = eachOf(S, "reader", { path: "inputs/many" }, man);
  assert.equal(many.ok, false);
  assert.match(!many.ok ? many.reason : "", new RegExp(`holds ${EACH_MAX + 1} files it reads.*at most ${EACH_MAX}`));
  const walks = eachOf(S, "reader", { path: "inputs/many" }, { params: { path: { description: "A file, or a directory to walk" } }, ...USE });
  assert.deepEqual(walks, { ok: true, each: null }, "a tool that takes a directory is given it");
  const file = eachOf(S, "reader", { path: "inputs/many/f1.lg" }, man);
  assert.deepEqual(file, { ok: true, each: null }, "a file is a file");
  const outside = eachOf(S, "reader", { path: "/etc" }, man);
  assert.deepEqual(outside, { ok: true, each: null }, "a path outside the run is the tool's to refuse");
});
