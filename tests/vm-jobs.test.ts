/**
 * The job service with real worker VMs (msb): what a worker can and cannot
 * reach, a recipe's result as a catalogue generation, one job's output read
 * by two others at once, a hub that dies with a worker up or while one is
 * being made, a job cancelled while its worker is made, and a finish that
 * finds one. Needs a host that boots microVMs and an image with python3
 * (VM_TEST_IMAGE; default dfirswarm-base:dev-<arch>); skipped otherwise,
 * failed instead when DFIRSWARM_VM_TESTS=1.
 */
import assert from "node:assert/strict";
import { execFileSync, spawn } from "node:child_process";
import { existsSync, readFileSync } from "node:fs";
import { mkdir, mkdtemp, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { after, before, test } from "node:test";
import { fileURLToPath } from "node:url";
import { JobService, type JobRecord } from "../scripts/job-service.ts";
import { destroyWorker, finishRun, imageCatalog, msbBinary, probeHost, runWorker } from "../scripts/vm.ts";
import { initStore, storePaths } from "../scripts/evidence-store.ts";

const ROOT = join(dirname(fileURLToPath(import.meta.url)), "..");
const ARCH = process.arch === "arm64" ? "arm64" : "amd64";
const IMAGE = process.env.VM_TEST_IMAGE || `dfirswarm-base:dev-${ARCH}`;
const REQUIRED = process.env.DFIRSWARM_VM_TESTS === "1";
const CFB = join(ROOT, "packs", "computer-forensics-base");
let skip: string | false = false;
const runs: string[] = [];

before(async () => {
  const probe = await probeHost(IMAGE).catch((err: Error) => ({ ok: false, reasons: [err.message], image_present: false }));
  if (!probe.ok || !probe.image_present) {
    skip = `this host cannot run the VM job tests (${probe.ok ? `no image ${IMAGE}` : (probe as { reasons: string[] }).reasons.join("; ")})`;
    if (REQUIRED) throw new Error(skip);
  }
});

after(async () => {
  // Nothing of these tests is left in msb.
  for (const run of runs) {
    const list = execFileSync(msbBinary(), ["list", "--format", "json"], { encoding: "utf8" });
    for (const name of (JSON.parse(list || "[]") as Array<{ name: string }>).map((v) => v.name).filter((n) => n.startsWith(`dfs-${run}-`))) await destroyWorker(name);
  }
});

function workerNames(run: string): string[] {
  const list = execFileSync(msbBinary(), ["list", "--format", "json"], { encoding: "utf8" });
  return (JSON.parse(list || "[]") as Array<{ name: string }>).map((v) => v.name).filter((n) => n.startsWith(`dfs-${run}-job-`));
}

async function sandbox(): Promise<{ S: string; run: string }> {
  const base = await mkdtemp(join(tmpdir(), "vmjobs-"));
  const run = `vj${Math.random().toString(36).slice(2, 8)}`;
  runs.push(run);
  const S = join(base, "runs", run);
  for (const d of ["inputs", "tools", "catalog", "threads/main", "work/a1", "work/extracted"]) await mkdir(join(S, d), { recursive: true });
  await writeFile(join(S, "work", "a1", "mine.txt"), "an agent's note");
  await writeFile(join(S, "work", "extracted", "run.sh"), "#!/bin/sh\necho ran\n", { mode: 0o755 });
  await writeFile(join(S, "threads", "main", "000001-a1.md"), "a board post\n");
  execFileSync("python3", ["-c", "import zipfile,sys\nwith zipfile.ZipFile(sys.argv[1],'w') as z:\n  z.writestr('docs/secret.txt','the key is 1234')", join(S, "inputs", "case.zip")]);
  await writeFile(join(S, "inputs.json"), JSON.stringify({ files: [{ path: "inputs/case.zip" }] }));
  return { S, run };
}

function service(S: string, run: string, posts: Array<[string, string]> = []) {
  return new JobService({
    sandbox: S,
    run,
    image: IMAGE,
    workers: 3,
    workerCpus: 1,
    workerMemoryMib: 1024,
    allowHosts: [],
    openNet: false,
    packDirs: [CFB],
    forging: false,
    minFreeMb: 64,
    runWorker,
    destroyWorker,
    notify: async (to, body) => {
      posts.push([to, body]);
    },
    identity: async () => ({ name: "tester" }),
  });
}

async function until(svc: JobService, id: string, ms = 240_000): Promise<JobRecord> {
  const end = Date.now() + ms;
  for (;;) {
    const j = svc.jobs.get(id)!;
    if (["committed", "failed", "cancelled"].includes(j.state)) return j;
    if (Date.now() > end) throw new Error(`job ${id} is ${j.state} after ${ms} ms`);
    await new Promise((r) => setTimeout(r, 250));
  }
}

test("a worker reaches only what it was given: no network, no credential, nothing writable but $OUT, no board", async (t) => {
  if (skip) return t.skip(skip);
  const { S, run } = await sandbox();
  const svc = service(S, run);
  await svc.start();
  const probe = [
    `(python3 -c "import urllib.request; urllib.request.urlopen('https://example.org', timeout=5)" >/dev/null 2>&1 && echo net-open || echo net-closed) > "$OUT/net.txt"`,
    `(env | grep -iE 'api_key|apikey|token|oauth|secret|password' || true) > "$OUT/env.txt"`,
    `for p in "$SWARM_SANDBOX/inputs/x" "$SWARM_SANDBOX/store/x" "$SWARM_SANDBOX/catalog/x" "$SWARM_SANDBOX/tools/x" "$SWARM_SANDBOX/work/x" "$SWARM_SANDBOX/work/a1/x" "$SWARM_SANDBOX/work/extracted/x"; do (touch "$p" 2>/dev/null && echo "WROTE $p" || echo "refused $p"); done > "$OUT/writes.txt"`,
    `cat "$SWARM_SANDBOX/work/a1/mine.txt" > "$OUT/peer.txt" 2>&1`,
    `(printf '#!/bin/sh\necho ran\n' > /tmp/x.sh; cp /tmp/x.sh "$OUT/x.sh" 2>/dev/null; chmod +x "$OUT/x.sh" 2>/dev/null; "$SWARM_SANDBOX/work/extracted/run.sh" 2>/dev/null && echo EXEC || echo noexec) > "$OUT/exec.txt"`,
    `(ls "$SWARM_SANDBOX/threads" >/dev/null 2>&1 && echo board-visible || echo board-not-mounted) > "$OUT/board.txt"`,
    `cat "$SWARM_SANDBOX/inputs.json" >/dev/null 2>&1 && echo floor-visible > "$OUT/floor.txt" || echo floor-not-mounted > "$OUT/floor.txt"`,
    `echo ok > "$OUT/own.txt"`,
  ].join("\n");
  const r = await svc.submit("a1", { kind: "command", command: probe, inputs: ["all"] });
  assert.ok(r.ok, !r.ok ? r.reason : "");
  const job = await until(svc, r.job.id);
  assert.equal(job.status, "ok", JSON.stringify(job));
  const out = join(storePaths(S).jobs, job.id, "out");
  const read = (f: string) => readFileSync(join(out, f), "utf8").trim();
  assert.equal(read("net.txt"), "net-closed");
  assert.equal(read("env.txt"), "", "no credential in a worker's environment");
  assert.doesNotMatch(read("writes.txt"), /WROTE/, read("writes.txt"));
  assert.equal(read("board.txt"), "board-not-mounted");
  assert.equal(read("floor.txt"), "floor-not-mounted", "the run's own records are not a worker's to read");
  assert.equal(read("own.txt"), "ok");
  assert.equal(read("peer.txt"), "an agent's note", "all of work/ is readable, as it is to the agents");
  assert.equal(read("exec.txt"), "noexec", "what was extracted cannot run");
  assert.deepEqual(workerNames(run), [], "the worker is gone");
  await svc.stop("over");
});

test("a recipe job in a worker catalogues an input; one job's tree is read by two others at once", async (t) => {
  if (skip) return t.skip(skip);
  const { S, run } = await sandbox();
  const posts: Array<[string, string]> = [];
  const svc = service(S, run, posts);
  await svc.start();
  const r = await svc.submit("a1", { kind: "recipe", recipe: "computer-forensics-base/archive-members", target: { paths: [join(S, "inputs", "case.zip")], name: "inputs/case.zip", ref: "input:case.zip" }, inputs: ["input:case.zip"] });
  assert.ok(r.ok, !r.ok ? r.reason : "");
  const recipe = await until(svc, r.job.id);
  assert.equal(recipe.status, "ok", JSON.stringify(recipe));
  const end = Date.now() + 30_000;
  while (!recipe.generation && Date.now() < end) await new Promise((res) => setTimeout(res, 200));
  assert.match(readFileSync(join(S, "catalog", "gen", String(recipe.generation), "members.tsv"), "utf8"), /docs\/secret\.txt/);
  // Materialise once: the member extracted into a tree.
  const a = await svc.submit("a1", { kind: "command", command: `cd "$OUT" && python3 -c "import zipfile; zipfile.ZipFile('$SWARM_SANDBOX/inputs/case.zip').extractall('tree')"`, inputs: ["input:case.zip"] });
  assert.ok(a.ok);
  const made = await until(svc, a.job.id);
  assert.equal(made.status, "ok");
  // Share: two jobs read it at the same time, each in its own VM.
  const read = (n: string) => svc.submit(n, { kind: "command", command: `cat "$SWARM_SANDBOX/store/jobs/${made.id}/out/tree/docs/secret.txt" > "$OUT/seen.txt"`, inputs: [`job:${made.id}`] });
  const [b, c] = await Promise.all([read("a1"), read("a2")]);
  assert.ok(b.ok && c.ok);
  const [jb, jc] = await Promise.all([until(svc, b.job.id), until(svc, c.job.id)]);
  for (const j of [jb, jc]) assert.equal(readFileSync(join(storePaths(S).jobs, j.id, "out", "seen.txt"), "utf8"), "the key is 1234");
  const overlap = Date.parse(jb.started_at!) < Date.parse(jc.finished_at!) && Date.parse(jc.started_at!) < Date.parse(jb.finished_at!);
  assert.ok(overlap, "the two readers ran at the same time");
  assert.deepEqual(workerNames(run), []);
  await svc.stop("over");
});

test("a hub that dies with a worker up: the next one removes it and keeps the attempt; a finish removes a worker left up", async (t) => {
  if (skip) return t.skip(skip);
  const { S, run } = await sandbox();
  const code = `
import { JobService } from ${JSON.stringify(join(ROOT, "scripts", "job-service.ts"))};
import { runWorker, destroyWorker } from ${JSON.stringify(join(ROOT, "scripts", "vm.ts"))};
const svc = new JobService({ sandbox: ${JSON.stringify(S)}, run: ${JSON.stringify(run)}, image: ${JSON.stringify(IMAGE)}, workers: 1, workerCpus: 1, workerMemoryMib: 1024, allowHosts: [], openNet: false, packDirs: [], forging: false, minFreeMb: 64, runWorker, destroyWorker, notify: async () => {}, identity: async () => ({}) });
await svc.start();
await svc.submit("a1", { kind: "command", command: "echo started > \\"$OUT/s.txt\\"; sleep 300", inputs: [], network: "allowlist" });
await new Promise(() => {});
`;
  const child = spawn(process.execPath, ["--experimental-strip-types", "--input-type=module", "-e", code], { stdio: "ignore" });
  const end = Date.now() + 120_000;
  while (!workerNames(run).length && Date.now() < end) await new Promise((r) => setTimeout(r, 500));
  assert.equal(workerNames(run).length, 1, "the worker is up");
  await new Promise((r) => setTimeout(r, 2000));
  child.kill("SIGKILL");
  const svc = service(S, run);
  await svc.start();
  const job = svc.jobs.get("j000001")!;
  assert.equal(job.state, "committed");
  assert.equal(job.status, "interrupted", "a job with network is not run again on its own");
  assert.deepEqual(workerNames(run), [], "the dead hub's worker was removed before its output was sealed");
  assert.equal(readFileSync(join(storePaths(S).jobs, "j000001", "out", "s.txt"), "utf8"), "started\n", "what it wrote before is kept");
  // A worker the service does not know about (its hub gone for good) is removed by the run's finish.
  const orphan = runWorker({ name: `dfs-${run}-job-j999999-1`, image: IMAGE, run, job: "j999999", attempt: 1, cpus: 1, memoryMib: 512, maxDurationSec: 600, workdir: "/", mounts: [], env: {}, network: { mode: "off" }, command: ["sleep", "300"] });
  const until2 = Date.now() + 120_000;
  while (!workerNames(run).length && Date.now() < until2) await new Promise((r) => setTimeout(r, 500));
  const done = await finishRun(run, S, { snapshot: false });
  assert.ok(done.some((e) => e.agent === "job-j999999" && !e.error), JSON.stringify(done));
  await orphan;
  assert.deepEqual(workerNames(run), []);
  assert.ok(!existsSync(join(`${S}.vm-snapshots`, "job-j999999.msb")), "a worker is never snapshotted as a seat");
  await svc.stop("over");
});

/** Processes still making or running a worker of this run (runWorker's children). */
function makers(run: string): string[] {
  return execFileSync("ps", ["-e", "-ww", "-o", "args="], { encoding: "utf8" }).split("\n").filter((l) => l.includes(`worker-once --name dfs-${run}-job-`));
}

test("a job cancelled while its worker is being made, and a hub that dies while one is: no VM and no maker left, each attempt on the record", async (t) => {
  if (skip) return t.skip(skip);
  const { S, run } = await sandbox();
  const svc = service(S, run);
  await svc.start();
  // Cancelled the moment it is running: its maker has just been started.
  const r = await svc.submit("a1", { kind: "command", command: "echo ran > \"$OUT/x\"", inputs: [] });
  assert.ok(r.ok);
  const end = Date.now() + 30_000;
  while (svc.jobs.get(r.job.id)!.state === "accepted" && Date.now() < end) await new Promise((res) => setTimeout(res, 5));
  await svc.status("a1", r.job.id, { cancel: true });
  const cancelled = await until(svc, r.job.id);
  assert.equal(cancelled.status, "cancelled");
  const journal = () => readFileSync(storePaths(S).journal, "utf8").trim().split("\n").map((l) => JSON.parse(l) as Record<string, unknown>);
  assert.ok(journal().some((l) => l.type === "job_fenced" && l.job === r.job.id && l.fenced === true), "fenced before it was sealed");
  assert.deepEqual(workerNames(run), [], "no VM left");
  assert.deepEqual(makers(run), [], "no maker left");
  await svc.stop("over");

  // A hub killed just after it recorded a job as started (its worker being made).
  const code = `
import { JobService } from ${JSON.stringify(join(ROOT, "scripts", "job-service.ts"))};
import { runWorker, destroyWorker } from ${JSON.stringify(join(ROOT, "scripts", "vm.ts"))};
const svc = new JobService({ sandbox: ${JSON.stringify(S)}, run: ${JSON.stringify(run)}, image: ${JSON.stringify(IMAGE)}, workers: 1, workerCpus: 1, workerMemoryMib: 1024, allowHosts: [], openNet: false, packDirs: [], forging: false, minFreeMb: 64, runWorker, destroyWorker, notify: async () => {}, identity: async () => ({}) });
await svc.start();
await svc.submit("a1", { kind: "command", command: "echo ok > \\"$OUT/ok.txt\\"", inputs: [] });
await new Promise(() => {});
`;
  const child = spawn(process.execPath, ["--experimental-strip-types", "--input-type=module", "-e", code], { stdio: "ignore" });
  const id = "j000002";
  const end2 = Date.now() + 60_000;
  while (!journal().some((l) => l.type === "job_started" && l.job === id) && Date.now() < end2) await new Promise((res) => setTimeout(res, 5));
  child.kill("SIGKILL");
  const svc2 = service(S, run);
  await svc2.start();
  const job = await until(svc2, id);
  assert.equal(job.status, "ok", "a job with no network is run once more after its hub died");
  assert.equal(job.attempt, 2);
  assert.ok(journal().some((l) => l.type === "job_retried" && l.job === id));
  assert.equal(readFileSync(join(storePaths(S).jobs, id, "out", "ok.txt"), "utf8"), "ok\n");
  const settle = Date.now() + 10_000;
  while (makers(run).length && Date.now() < settle) await new Promise((res) => setTimeout(res, 250));
  assert.deepEqual(makers(run), [], "the dead hub's maker is gone");
  assert.deepEqual(workerNames(run), [], "and so is any VM it made");
  await svc2.stop("over");
});

test("the kickoff's flow without agents: the catalog VM plans from the packs' recipes, the job service runs them, the catalogue grows", async (t) => {
  if (skip) return t.skip(skip);
  const { S, run } = await sandbox();
  // The census in its own VM, with the pack's recipes mounted: planned, not run.
  const census = await imageCatalog(IMAGE, S, [join(S, "inputs")], { memoryMib: 1024, planOnly: true, packDirs: [CFB], run });
  assert.equal(census.code, 0, census.output);
  const plan = JSON.parse(readFileSync(join(S, "catalog", "plan.json"), "utf8")).recipes as Array<{ recipe: string; input: string }>;
  assert.deepEqual(plan.map((p) => [p.recipe, p.input]), [["computer-forensics-base/archive-members", "inputs/case.zip"]], "the VM saw the pack's recipes");
  assert.match(readFileSync(join(S, "catalog", "coverage.tsv"), "utf8"), /inputs\/case\.zip\t\d+\tplanned\t/);
  await initStore(S);
  const posts: Array<[string, string]> = [];
  const svc = service(S, run, posts);
  await svc.start();
  const id = [...svc.jobs.keys()][0];
  assert.ok(id, "the plan's recipe was queued");
  const job = await until(svc, id);
  const end = Date.now() + 60_000;
  while (!posts.some(([to]) => to === "all") && Date.now() < end) await new Promise((r) => setTimeout(r, 250));
  assert.equal(job.requester.agent, "system");
  assert.match(readFileSync(join(S, "catalog", "case.zip", "members.tsv"), "utf8"), /docs\/secret\.txt/, "at its compatibility path too");
  assert.ok(existsSync(join(S, "catalog", "revisions", "1", "MANIFEST.json")));
  assert.ok(posts.some(([to, body]) => to === "all" && /^Catalogue revision 1: g0001 computer-forensics-base\/archive-members over inputs\/case\.zip — complete/.test(body)), JSON.stringify(posts));
  await svc.stop("over");
});
