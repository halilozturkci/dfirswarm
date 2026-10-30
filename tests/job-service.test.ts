/**
 * The job service, with the worker VM replaced by a stand-in that runs the
 * job's own run.sh on this machine (its /job and $OUT mapped to the host
 * directories the VM would have mounted): acceptance before work, the
 * journal's order, sealing, failures kept, cancellation, fencing, the
 * catalogue's generations, the lanes and limits of the queue, room on the
 * host, and recovery after a crash at each durable step.
 */
import test from "node:test";
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { existsSync, mkdirSync, mkdtempSync, readFileSync, realpathSync, symlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { createHash } from "node:crypto";
import { boundInputSets, copyInputsManifest, DERIVED, JOB_INPUTS_MANIFEST, JOB_INPUTS_MANIFEST_MAX, JobService, missingOf, SHORT_JOB_SECONDS, type JobServiceOptions } from "../scripts/job-service.ts";
import { storePaths, verifyJournalText } from "../scripts/evidence-store.ts";
import { listInputs, localWorker, mountedWorker } from "./job-service-worker.ts";
import type { WorkerSpec } from "../scripts/vm.ts";

const ROOT = join(import.meta.dirname, "..");
const CFB = join(ROOT, "packs", "computer-forensics-base");

function sandbox(): string {
  const S = join(mkdtempSync(join(tmpdir(), "jobs-")), "run");
  mkdirSync(join(S, "inputs"), { recursive: true });
  mkdirSync(join(S, "tools"), { recursive: true });
  mkdirSync(join(S, "catalog"), { recursive: true });
  mkdirSync(join(S, "work", "a1"), { recursive: true });
  writeFileSync(join(S, "inputs.json"), JSON.stringify({ files: [] }));
  return S;
}

function tool(S: string, name: string, body: string, params: Record<string, unknown>): void {
  mkdirSync(join(S, "tools", name), { recursive: true });
  writeFileSync(join(S, "tools", name, "run.py"), body);
  const sha = createHash("sha256").update(body).digest("hex");
  writeFileSync(join(S, "tools", name, "manifest.json"), JSON.stringify({ name, description: "t", params, runtime: "python3", entry: "run.py", timeout_seconds: 60, by: "t", at: "t", version: 1, sha256: sha }));
}

function service(S: string, extra: Partial<JobServiceOptions> = {}) {
  const posts: Array<[string, string]> = [];
  const destroyed: string[] = [];
  const svc = new JobService({
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
    destroyWorker: async (name) => {
      destroyed.push(name);
      return { ok: true };
    },
    notify: async (to, body) => {
      posts.push([to, body]);
    },
    identity: async (agent) => ({ name: `${agent} the examiner`, doing: "the timeline" }),
    ...extra,
  });
  return { svc, posts, destroyed };
}

/** Until `ok` holds, polling. */
async function eventually(ok: () => boolean, what: string, ms = 20000): Promise<void> {
  const end = Date.now() + ms;
  while (!ok()) {
    if (Date.now() > end) throw new Error(`not within ${ms} ms: ${what}`);
    await new Promise((r) => setTimeout(r, 50));
  }
}

async function until(svc: JobService, id: string, states = ["committed", "failed", "cancelled"], ms = 20000) {
  const end = Date.now() + ms;
  for (;;) {
    const j = svc.jobs.get(id);
    if (j && states.includes(j.state)) return j;
    if (Date.now() > end) throw new Error(`job ${id} is ${j?.state} after ${ms} ms`);
    await new Promise((r) => setTimeout(r, 50));
  }
}

test("a command job is accepted before it runs, its output sealed and every step journalled in order", async () => {
  const S = sandbox();
  const { svc, posts, destroyed } = service(S);
  await svc.start();
  const r = await svc.submit("a1", { kind: "command", command: "echo hello; mkdir -p \"$OUT/d\"; printf data > \"$OUT/d/f.txt\"; ln -s /etc/passwd \"$OUT/l\"", inputs: ["all"] });
  assert.ok(r.ok, !r.ok ? r.reason : "");
  const job = await until(svc, r.job.id);
  assert.equal(job.status, "ok");
  assert.deepEqual(job.requester, { agent: "a1", name: "a1 the examiner", doing: "the timeline" }, "who asked, with what it called itself then");
  const P = storePaths(S);
  const manifest = JSON.parse(readFileSync(join(P.jobs, job.id, "manifest.json"), "utf8"));
  assert.deepEqual(manifest.files.map((f: { path: string }) => f.path), ["d/f.txt"]);
  assert.deepEqual(manifest.rejected.map((x: { kind: string }) => x.kind), ["symlink"]);
  assert.equal(readFileSync(join(P.jobs, job.id, "stdout.log"), "utf8"), "hello\n");
  const lines = verifyJournalText(readFileSync(P.journal, "utf8"));
  assert.equal(lines.error, undefined);
  const mine = lines.lines.filter((l) => l.job === job.id).map((l) => l.type);
  assert.deepEqual(mine.slice(0, 5), ["job_accepted", "job_started", "job_finished", "job_fenced", "job_committed"]);
  const started = lines.lines.find((l) => l.type === "job_started" && l.job === job.id)!;
  assert.deepEqual(started.declared, ["all"]);
  assert.equal(started.observed, "unknown", "what the job read is not measured, and says so");
  const acc = started.accessible as Array<{ path: string; access: string }>;
  assert.ok(acc.some((a) => a.path === join(S, "inputs") && a.access === "read-only, no-exec"), `the accessible scope names the evidence, read-only and no-exec: ${JSON.stringify(acc)}`);
  assert.ok(acc.some((a) => a.path === join(S, "work") && a.access.startsWith("read-only;") && a.access.includes("may change")), "all of work/, read-only, said to be live");
  assert.ok(acc.some((a) => a.path === join(S, ".jobs", job.id) && a.access === "read-write, no-exec"), "its own $OUT, the one writable place");
  // By the run's own directories, not by a word in a path (the harness's checkout may be named anything).
  assert.ok(!acc.some((a) => a.path.startsWith(`${S}/`) && /^(threads|inbox|ledger|\.pi-sessions)(\/|$)/.test(a.path.slice(S.length + 1))), "never the board, the ledger or the sessions");
  assert.equal(started.network, "none");
  assert.ok(destroyed.length === 0 || destroyed.every((n) => n.startsWith("dfs-")));
  await eventually(() => posts.length > 0, "the requester is told");
  await new Promise((res) => setTimeout(res, 200));
  assert.equal(posts.length, 1, "the requester is told once");
  assert.match(posts[0][1], new RegExp(`Job ${job.id} \\(command\\) done: 1 file\\(s\\)`));
  assert.ok(existsSync(join(P.jobs, job.id, "job.json")));
  await svc.stop("test over");
});

test("several sets held in place: each set's directory is in a job's reach where its link leads, read-only and no-exec", async () => {
  const S = sandbox();
  const ev = mkdtempSync(join(tmpdir(), "jobs-sets-"));
  mkdirSync(join(ev, "laptop"));
  mkdirSync(join(ev, "phone"));
  writeFileSync(join(ev, "phone", "sms.db"), "sqlite");
  symlinkSync(join(ev, "laptop"), join(S, "inputs", "laptop"));
  symlinkSync(join(ev, "phone"), join(S, "inputs", "phone"));
  // Only a set the manifest names, whose link is there, and whose name is one directory.
  writeFileSync(join(S, "inputs.json"), JSON.stringify({ files: [], sets: [{ name: "laptop" }, { name: "phone" }, { name: "../etc" }, { name: "gone" }] }));
  const sets = [realpathSync(join(ev, "laptop")), realpathSync(join(ev, "phone"))];
  assert.deepEqual(boundInputSets(S), sets);
  const { svc } = service(S);
  await svc.start();
  const r = await svc.submit("a1", { kind: "command", command: "cat inputs/phone/sms.db", inputs: ["all"] });
  assert.ok(r.ok, !r.ok ? r.reason : "");
  const job = await until(svc, r.job.id);
  assert.equal(job.status, "ok");
  assert.equal(readFileSync(join(storePaths(S).jobs, job.id, "stdout.log"), "utf8"), "sqlite");
  const started = verifyJournalText(readFileSync(storePaths(S).journal, "utf8")).lines.find((l) => l.type === "job_started" && l.job === job.id)!;
  const acc = started.accessible as Array<{ path: string; access: string }>;
  for (const path of [join(S, "inputs"), ...sets]) {
    assert.ok(acc.some((a) => a.path === path && a.access === "read-only, no-exec"), `${path} is not in the job's reach, read-only and no-exec: ${JSON.stringify(acc)}`);
  }
  await svc.stop("test over");
  // One set, or a copy: nothing beyond inputs/ itself.
  writeFileSync(join(S, "inputs.json"), JSON.stringify({ files: [] }));
  assert.deepEqual(boundInputSets(S), []);
});

test("a pack or forged tool runs sealed, its arguments checked against its manifest, {OUT} naming the job's directory", async () => {
  const S = sandbox();
  tool(S, "writer", "import json,sys,os\nd=json.load(sys.stdin)\nos.makedirs(os.path.dirname(d['output']), exist_ok=True)\nopen(d['output'],'w').write(d['text'])\nprint(json.dumps({'ok': True}))\n", { output: { type: "string", required: true }, text: { type: "string", required: true } });
  const { svc } = service(S);
  await svc.start();
  const refused = async (args: Record<string, unknown>, why: RegExp) => {
    const r = await svc.submit("a1", { kind: "tool", tool: "writer", args, inputs: [] });
    assert.equal(r.ok, false);
    assert.match(!r.ok ? r.reason : "", why);
  };
  await refused({ text: "x" }, /needs output/);
  await refused({ output: "{OUT}/a", text: 5 }, /text must be a string/);
  await refused({ output: "{OUT}/a", text: "x", extra: 1 }, /takes no extra/);
  writeFileSync(join(S, "inputs", "x"), "evidence");
  listInputs(S);
  const r = await svc.submit("a1", { kind: "tool", tool: "writer", args: { output: "{OUT}/sub/result.txt", text: "carved" }, inputs: ["input:x"] });
  assert.ok(r.ok, !r.ok ? r.reason : "");
  const job = await until(svc, r.job.id);
  assert.equal(job.status, "ok");
  assert.equal(readFileSync(join(storePaths(S).jobs, job.id, "out", "sub", "result.txt"), "utf8"), "carved");
  assert.equal(job.tool_sha256?.length, 64, "the tool's sha256 is on the record");
  writeFileSync(join(S, "tools", "writer", "run.py"), "print('changed')\n");
  await refused({ output: "{OUT}/a", text: "x" }, /does not match its manifest's sha256/);
  await svc.stop("test over");
});

test("a failed job keeps what it wrote, a timed-out one says so, and a peer cannot cancel someone else's job", async () => {
  const S = sandbox();
  const { svc, posts } = service(S, { workers: 1 });
  await svc.start();
  const bad = await svc.submit("a1", { kind: "command", command: "printf partial > \"$OUT/p.txt\"; echo boom >&2; exit 3", inputs: [] });
  assert.ok(bad.ok);
  const b = await until(svc, bad.job.id);
  assert.equal(b.status, "failed");
  assert.equal(b.outputs?.files, 1, "a failed job's output is committed, not dropped");
  assert.equal(readFileSync(join(storePaths(S).jobs, bad.job.id, "stderr.log"), "utf8"), "boom\n");
  const slow = await svc.submit("a1", { kind: "command", command: "exit 124", inputs: [] });
  assert.ok(slow.ok);
  assert.equal((await until(svc, slow.job.id)).status, "timed_out");
  // A queued job: the worker is busy with a long one.
  const long = await svc.submit("a1", { kind: "command", command: "sleep 1", inputs: [] });
  const queued = await svc.submit("a1", { kind: "command", command: "echo never", inputs: [] });
  assert.ok(long.ok && queued.ok);
  const other = await svc.status("a2", queued.job.id, { cancel: true });
  assert.equal(other.ok, false, "only the requester cancels");
  const mine = await svc.status("a1", queued.job.id, { cancel: true });
  assert.ok(mine.ok);
  assert.equal(mine.ok && mine.job.state, "cancelled", "the answer to the cancel says so");
  assert.equal((await until(svc, queued.job.id)).state, "cancelled");
  await until(svc, long.job.id);
  assert.ok(!posts.some(([, body]) => body.includes(`Job ${queued.job.id} `)), "the agent that cancelled it is not told again by post");
  await svc.stop("test over");
});

test("submissions in the same tick each get a job id of their own", async () => {
  const S = sandbox();
  const { svc } = service(S, { workers: 4 });
  await svc.start();
  const rs = await Promise.all(["a1", "a2", "a3", "a4", "a1", "a2"].map((a) => svc.submit(a, { kind: "command", command: "true", inputs: [] })));
  const ids = rs.map((r) => (r.ok ? r.job.id : "refused"));
  assert.equal(new Set(ids).size, ids.length, `distinct ids: ${ids.join(", ")}`);
  for (const id of ids) await until(svc, id);
  await svc.stop("over");
});

test("a job its agent waits for from submission is answered in the call, not posted as well", async () => {
  const S = sandbox();
  const { svc, posts } = service(S);
  await svc.start();
  const r = await svc.submit("a1", { kind: "command", command: "echo quick", inputs: [] }, { watch: 10 });
  assert.ok(r.ok);
  await until(svc, r.job.id);
  const st = await svc.status("a1", r.job.id, {});
  assert.ok(st.ok && st.job.state === "committed");
  await new Promise((res) => setTimeout(res, 300));
  assert.equal(posts.length, 0, "no post for a job answered where the agent waited");
  await svc.stop("over");
});

test("an agent may queue so many jobs and no more; the harness's own are not counted", async () => {
  const S = sandbox();
  const { svc } = service(S, { workers: 1, perRequesterQueued: 2, runWorker: async () => { await new Promise((r) => setTimeout(r, 300)); return { code: 0, fenced: true }; } });
  await svc.start();
  assert.ok((await svc.submit("a1", { kind: "command", command: "true", inputs: [] })).ok);
  assert.ok((await svc.submit("a1", { kind: "command", command: "true", inputs: [] })).ok);
  const third = await svc.submit("a1", { kind: "command", command: "true", inputs: [] });
  assert.equal(third.ok, false);
  assert.match(!third.ok ? third.reason : "", /the most one agent may have/);
  assert.ok((await svc.submit("a2", { kind: "command", command: "true", inputs: [] })).ok, "another agent is not held back");
  await svc.stop("test over");
});

test("a worker not confirmed gone is not sealed; the backstop seals it once it is", async () => {
  const S = sandbox();
  let gone = false;
  const { svc } = service(S, { runWorker: localWorker([], { fenced: () => false }), destroyWorker: async () => ({ ok: gone, ...(gone ? {} : { error: "still there" }) }) });
  await svc.start();
  const r = await svc.submit("a1", { kind: "command", command: "printf x > \"$OUT/x\"", inputs: [] });
  assert.ok(r.ok);
  await until(svc, r.job.id, ["finished"]);
  await new Promise((res) => setTimeout(res, 200));
  assert.equal(svc.jobs.get(r.job.id)!.state, "finished", "not sealed while the worker may still write");
  assert.ok(!existsSync(join(storePaths(S).jobs, r.job.id, "out")));
  gone = true;
  await svc.sweep();
  assert.equal((await until(svc, r.job.id)).status, "ok");
  await svc.stop("test over");
});

test("three jobs in a row that ran in no worker are told to every agent once, and so is the next that runs", async () => {
  const S = sandbox();
  let broken = true;
  const real = localWorker();
  const { svc, posts } = service(S, {
    workers: 1,
    runWorker: async (spec) => (broken ? { code: null, error: "[BootStart] failed to start: insert run: FOREIGN KEY constraint failed", fenced: true } : real(spec)),
  });
  await svc.start();
  const ids: string[] = [];
  for (let i = 0; i < 4; i += 1) {
    const r = await svc.submit("a1", { kind: "command", command: "true", inputs: [] });
    assert.ok(r.ok);
    ids.push(r.job.id);
    await until(svc, r.job.id);
  }
  const told = () => posts.filter(([to, b]) => to === "all" && b.startsWith("Tool jobs are not running"));
  assert.equal(told().length, 1, `once, not per job: ${JSON.stringify(posts)}`);
  assert.match(told()[0][1], /the last 3 could not run in a worker \(\[BootStart\].*FOREIGN KEY/);
  assert.match(told()[0][1], /do that work in your own VM/);
  broken = false;
  const ok = await svc.submit("a1", { kind: "command", command: "true", inputs: [] });
  assert.ok(ok.ok);
  assert.equal((await until(svc, ok.job.id)).status, "ok");
  await eventually(() => posts.some(([to, b]) => to === "all" && b === `Tool jobs run again: ${ok.job.id} ran in a worker.`), "the recovery is told");
  const types = verifyJournalText(readFileSync(storePaths(S).journal, "utf8")).lines.map((l) => l.type);
  assert.equal(types.filter((t) => t === "jobs_degraded").length, 1);
  assert.equal(types.filter((t) => t === "jobs_recovered").length, 1);
  await svc.stop("test over");
});

test("an import seals an agent's own file or directory as it is now, links left out, and refuses what is not under work/ or tool-output/", async () => {
  const S = sandbox();
  const { svc } = service(S, { runWorker: mountedWorker() });
  await svc.start();
  mkdirSync(join(S, "work", "a1", "vdi", "deep"), { recursive: true });
  writeFileSync(join(S, "work", "a1", "runlist.tsv"), "run\tlcn\n0\t9884700\n");
  writeFileSync(join(S, "work", "a1", "vdi", "header.bin"), "VDI");
  writeFileSync(join(S, "work", "a1", "vdi", "deep", "map.json"), "{}");
  spawnSync("ln", ["-s", "/etc/passwd", join(S, "work", "a1", "vdi", "link")]);
  const one = await svc.submit("a1", { kind: "import", source: "work/a1/runlist.tsv" });
  assert.ok(one.ok, !one.ok ? one.reason : "");
  const j1 = await until(svc, one.job.id);
  assert.equal(j1.status, "ok", j1.reason);
  assert.equal(readFileSync(join(storePaths(S).jobs, j1.id, "out", "runlist.tsv"), "utf8"), "run\tlcn\n0\t9884700\n");
  const rec = JSON.parse(readFileSync(join(storePaths(S).jobs, j1.id, "stdout.log"), "utf8"));
  assert.equal(rec.copied_live, false, "copied from the hub's snapshot, not the live file");
  assert.match(rec.copied_from, /snapshot the hub took at the job's start/);
  assert.equal(rec.producer_fenced, false, "the record says its producer was not stopped");
  assert.equal(rec.files[0].unchanged_while_copied, true);
  assert.equal(rec.files[0].hashed_before_and_after, true);
  assert.equal(rec.files[0].sha256, createHash("sha256").update("run\tlcn\n0\t9884700\n").digest("hex"));
  const dir = await svc.submit("a1", { kind: "import", source: "./work/a1/vdi/" });
  assert.ok(dir.ok);
  const j2 = await until(svc, dir.job.id);
  assert.equal(j2.status, "ok", j2.reason);
  const rec2 = JSON.parse(readFileSync(join(storePaths(S).jobs, j2.id, "stdout.log"), "utf8"));
  assert.deepEqual(rec2.files.map((f: { path: string }) => f.path).sort(), ["vdi/deep/map.json", "vdi/header.bin"]);
  // The link never reached the snapshot: the job's scope manifest names it, left out, never followed.
  const manifest = JSON.parse(readFileSync(join(storePaths(S).jobs, j2.id, "scope.1.json"), "utf8"));
  assert.equal(manifest.accessible.find((e: { path: string }) => e.path === "work/a1/vdi/link")?.left_out, "a link", "a link is named and left out, never followed");
  assert.ok(existsSync(join(storePaths(S).jobs, j2.id, "out", "vdi", "deep", "map.json")));
  for (const bad of ["inputs/case.zip", "work/../inputs.json", "/etc/passwd", "work/a1/nothing.txt", "store/jobs"]) {
    const r = await svc.submit("a1", { kind: "import", source: bad });
    assert.equal(r.ok, false, bad);
  }
  await svc.stop("test over");
});

test("a recipe job becomes a catalogue generation and revision; the same recipe over the same object is the same job, on the record, and both askers are told", async () => {
  const S = sandbox();
  spawnSync("python3", ["-c", "import tarfile,io,sys\nwith tarfile.open(sys.argv[1],'w') as t:\n  i=tarfile.TarInfo('private/sms.db'); d=b'SQLite format 3\\0'+b'x'*1000; i.size=len(d); t.addfile(i,io.BytesIO(d))", join(S, "inputs", "phone.tar")]);
  listInputs(S);
  const { svc, posts } = service(S);
  await svc.start();
  const target = { paths: [join(S, "inputs", "phone.tar")], name: "inputs/phone.tar", ref: "input:phone.tar" };
  const r = await svc.submit("a1", { kind: "recipe", recipe: "computer-forensics-base/archive-members", target, inputs: ["input:phone.tar"] });
  assert.ok(r.ok, !r.ok ? r.reason : "");
  const again = await svc.submit("a2", { kind: "recipe", recipe: "computer-forensics-base/archive-members", target, inputs: ["input:phone.tar"] });
  assert.ok(again.ok);
  assert.equal(again.job.id, r.job.id, "answered with the earlier job");
  const job = await until(svc, r.job.id);
  const lines = () => verifyJournalText(readFileSync(storePaths(S).journal, "utf8")).lines;
  const dedup = lines().filter((l) => l.type === "job_deduplicated");
  assert.equal(dedup.length, 1, "the second request is on the record");
  assert.equal(dedup[0].job, r.job.id);
  assert.equal((dedup[0].by as { agent: string }).agent, "a2");
  assert.equal(dedup[0].notify, true, "asked while the job was under way: to be told");
  await eventually(() => ["a1", "a2"].every((a) => posts.some(([to, b]) => to === a && b.startsWith(`Job ${r.job.id} (recipe`))), `both askers are told: ${JSON.stringify(posts)}`);
  const late = await svc.submit("a2", { kind: "recipe", recipe: "computer-forensics-base/archive-members", target, inputs: ["input:phone.tar"] });
  assert.equal(late.ok && late.job.id, r.job.id);
  assert.equal(lines().filter((l) => l.type === "job_deduplicated").at(-1)!.notify, false, "asked once it was done: answered in the call, not posted");
  await eventually(() => Boolean(job.generation), "the recipe's generation is published after its commit");
  assert.equal(job.generation, "g0001");
  const gen = JSON.parse(readFileSync(join(S, "catalog", "gen", "g0001", "generation.json"), "utf8"));
  assert.equal(gen.status, "complete");
  assert.match(readFileSync(join(S, "catalog", "gen", "g0001", "members.tsv"), "utf8"), /private\/sms\.db/);
  assert.ok(existsSync(join(S, "catalog", "revisions", String(job.revision), "MANIFEST.json")));
  const unknown = await svc.submit("a1", { kind: "recipe", recipe: "computer-forensics-base/nope", target, inputs: [] });
  assert.equal(unknown.ok, false);
  const outside = await svc.submit("a1", { kind: "recipe", recipe: "computer-forensics-base/archive-members", target: { paths: ["/etc/passwd"] }, inputs: [] });
  assert.equal(outside.ok, false, "a target outside the run is refused");
  await svc.stop("test over");
});

test("two recipe jobs committing at once take distinct generations and revisions", async () => {
  const S = sandbox();
  for (const n of ["a", "b", "c"]) spawnSync("python3", ["-c", "import zipfile,sys\nwith zipfile.ZipFile(sys.argv[1],'w') as z: z.writestr('x.txt','x'*100)", join(S, "inputs", `${n}.zip`)]);
  listInputs(S);
  const { svc } = service(S, { workers: 3 });
  await svc.start();
  const ids: string[] = [];
  for (const n of ["a", "b", "c"]) {
    const r = await svc.submit("a1", { kind: "recipe", recipe: "computer-forensics-base/archive-members", target: { paths: [join(S, "inputs", `${n}.zip`)], name: `inputs/${n}.zip`, ref: `input:${n}.zip` }, inputs: [] });
    assert.ok(r.ok);
    ids.push(r.job.id);
  }
  for (const id of ids) await until(svc, id);
  await eventually(() => ids.every((id) => Boolean(svc.jobs.get(id)!.generation)), "every job has its generation");
  const gens = ids.map((id) => svc.jobs.get(id)!.generation);
  assert.equal(new Set(gens).size, 3, `distinct generations: ${gens.join(", ")}`);
  const revs = ids.map((id) => svc.jobs.get(id)!.revision);
  assert.equal(new Set(revs).size, 3, `distinct revisions: ${revs.join(", ")}`);
  for (const g of gens) {
    const gen = JSON.parse(readFileSync(join(S, "catalog", "gen", String(g), "generation.json"), "utf8"));
    assert.equal(readFileSync(join(S, "catalog", "gen", String(g), "members.tsv"), "utf8").split("\n").length, 3, `${g} holds one archive's members, not a merge: ${gen.target.name}`);
  }
  await svc.stop("over");
});

test("a job service built without the derived catalogue offers no committed file to the recipes (tests/derived-catalog.test.ts has it on)", async () => {
  const S = sandbox();
  const { svc } = service(S);
  await svc.start();
  const r = await svc.submit("a1", { kind: "command", command: `python3 -c "import tarfile,io\nwith tarfile.open('$OUT/inner.tar','w') as t:\n  i=tarfile.TarInfo('a.txt'); d=b'x'*2000; i.size=len(d); t.addfile(i,io.BytesIO(d))"`, inputs: [] });
  assert.ok(r.ok);
  await until(svc, r.job.id);
  await new Promise((res) => setTimeout(res, 500));
  assert.equal(svc.jobs.size, 1, "no detect pass was queued");
  await svc.stop("over");
});

test("a job with network interrupted by a restart is not run again on its own", async () => {
  const S = sandbox();
  const code = `
import { JobService } from ${JSON.stringify(join(ROOT, "scripts", "job-service.ts"))};
import { localWorker } from ${JSON.stringify(join(ROOT, "tests", "job-service-worker.ts"))};
const svc = new JobService({ sandbox: ${JSON.stringify(S)}, run: "s000000", image: "img:test", workers: 1, workerCpus: 1, workerMemoryMib: 512, allowHosts: ["example.org"], openNet: false, packDirs: [], forging: false, minFreeMb: 1,
  runWorker: localWorker(), destroyWorker: async () => ({ ok: true }), notify: async () => {}, identity: async () => ({}) });
await svc.start();
await svc.submit("a1", { kind: "command", command: "true", inputs: [], network: "allowlist" });
await new Promise((r) => setTimeout(r, 20000));
`;
  const c = spawnSync(process.execPath, ["--experimental-strip-types", "--input-type=module", "-e", code], { encoding: "utf8", env: { ...process.env, SWARM_JOB_CRASH_AT: "job:started" }, timeout: 30000 });
  assert.equal(c.status, 99, c.stderr);
  const { svc } = service(S, { packDirs: [] });
  await svc.start();
  const job = svc.jobs.get("j000001")!;
  assert.equal(job.state, "committed");
  assert.equal(job.status, "interrupted", "kept as interrupted, not retried");
  await svc.stop("over");
});

test("the kickoff's plan is queued once, however often the service starts", async () => {
  const S = sandbox();
  spawnSync("python3", ["-c", "import zipfile,sys\nwith zipfile.ZipFile(sys.argv[1],'w') as z: z.writestr('x.txt','x'*100)", join(S, "inputs", "a.zip")]);
  listInputs(S);
  writeFileSync(join(S, "catalog", "plan.json"), JSON.stringify({ recipes: [{ input: "inputs/a.zip", recipe: "computer-forensics-base/archive-members", target: { paths: [join(S, "inputs", "a.zip")], name: "inputs/a.zip", ref: "input:a.zip" }, alias: "catalog/a.zip" }] }));
  const first = service(S);
  await first.svc.start();
  const ids = [...first.svc.jobs.keys()];
  assert.equal(ids.length, 1);
  await until(first.svc, ids[0]);
  await eventually(() => existsSync(join(S, "catalog", "a.zip", "members.tsv")), "linked at its compatibility path too");
  await eventually(() => first.posts.some(([to, body]) => to === "all" && body.startsWith("Catalogue revision")), "the kickoff's catalogue is everyone's news");
  await first.svc.stop("restart");
  const second = service(S);
  await second.svc.start();
  assert.equal(second.svc.jobs.size, 1, "not queued again");
  await second.svc.stop("over");
});

test("with too little free disk a job waits in the queue rather than start", async () => {
  const S = sandbox();
  const lines: string[] = [];
  const { svc } = service(S, { minFreeMb: 1e12, log: (l) => lines.push(l) });
  await svc.start();
  const r = await svc.submit("a1", { kind: "command", command: "true", inputs: [] });
  assert.ok(r.ok);
  await new Promise((res) => setTimeout(res, 300));
  assert.equal(svc.jobs.get(r.job.id)!.state, "accepted");
  assert.ok(lines.some((l) => l.includes("waits") && l.includes("MB free")));
  await svc.stop("over");
  assert.equal(svc.jobs.get(r.job.id)!.state, "cancelled", "stopping the run cancels what is queued, on the record");
});

/**
 * A worker whose jobs are held until let go: one whose command says `hold`
 * waits for `release()`, any other answers at once. It writes the job's exit
 * status as run.sh would, and counts what runs at once, by requester.
 */
function heldWorker() {
  let release!: () => void;
  const held = new Promise<void>((r) => {
    release = r;
  });
  const live = new Map<string, number>();
  const most = new Map<string, number>();
  const scripts: string[] = [];
  const runWorker = async (spec: WorkerSpec) => {
    const ctl = spec.mounts.find((m) => m.guest === "/job")!.host;
    const who = String(spec.env.AGENT_ID);
    live.set(who, (live.get(who) ?? 0) + 1);
    most.set(who, Math.max(most.get(who) ?? 0, live.get(who)!));
    scripts.push(readFileSync(join(ctl, "run.sh"), "utf8"));
    if (existsSync(join(ctl, "command.sh")) && readFileSync(join(ctl, "command.sh"), "utf8").includes("hold")) await held;
    writeFileSync(join(ctl, "exit"), "0\n");
    live.set(who, live.get(who)! - 1);
    return { code: 0, fenced: true };
  };
  return { runWorker, release, most, scripts };
}

test("the queue counts the jobs it has handed a worker, not only those whose start is written: an agent gets its own limit and the derived lane one job", async () => {
  // Every job queued first (too little disk), then the queue let go at once:
  // a job picked a moment ago is still "accepted" until its job_started line
  // is written, and counting by that state started them all (the derived
  // ceiling test that timed out on a Linux runner ran two recipes at once).
  const S = sandbox();
  const w = heldWorker();
  const { svc } = service(S, { workers: 4, perRequesterRunning: 2, minFreeMb: 1e12, runWorker: w.runWorker });
  await svc.start();
  const mine = await Promise.all([1, 2, 3].map(() => svc.submit("a1", { kind: "command", command: "hold", inputs: [] })));
  assert.ok(mine.every((r) => r.ok));
  svc.o.minFreeMb = 1;
  await svc.pump();
  await eventually(() => (w.most.get("a1") ?? 0) >= 2, "a1's first two run");
  await new Promise((res) => setTimeout(res, 300));
  assert.equal(w.most.get("a1"), 2, "no more than its own limit at once");
  w.release();
  for (const r of mine) await until(svc, r.ok ? r.job.id : "");
  await svc.stop("over");
  const S2 = sandbox();
  const w2 = heldWorker();
  const two = service(S2, { workers: 4, minFreeMb: 1e12, runWorker: w2.runWorker });
  await two.svc.start();
  const derived = await Promise.all([1, 2].map(() => two.svc.submit(DERIVED, { kind: "command", command: "hold", inputs: [] })));
  two.svc.o.minFreeMb = 1;
  await two.svc.pump();
  await eventually(() => (w2.most.get(DERIVED) ?? 0) >= 1, "the derived lane's first runs");
  await new Promise((res) => setTimeout(res, 300));
  assert.equal(w2.most.get(DERIVED), 1, "the derived lane runs one job at a time");
  w2.release();
  for (const r of derived) await until(two.svc, r.ok ? r.job.id : "");
  await two.svc.stop("over");
});

test("a long job on every general worker does not delay a short one; the worker kept for short jobs is never a longer job's, the kickoff's or the derived catalogue's", async () => {
  const S = sandbox();
  const w = heldWorker();
  const { svc } = service(S, { workers: 3, runWorker: w.runWorker });
  await svc.start();
  assert.equal(svc.shortSlots(), 1, "three workers: one kept for short jobs");
  const long1 = await svc.submit("a1", { kind: "command", command: "hold 1", inputs: [] });
  const long2 = await svc.submit("a2", { kind: "command", command: "hold 2", inputs: [] });
  assert.ok(long1.ok && long2.ok);
  await until(svc, long1.job.id, ["running"]);
  await until(svc, long2.job.id, ["running"]);
  // Every general worker is taken: a longer job, the kickoff's (whatever its
  // limit) and the derived catalogue's wait, the kept worker idle.
  const long3 = await svc.submit("a3", { kind: "command", command: "hold 3", inputs: [], timeout_seconds: SHORT_JOB_SECONDS + 1 });
  const kickoff = await svc.submit("system", { kind: "command", command: "hold k", inputs: [], timeout_seconds: 60 });
  const derived = await svc.submit(DERIVED, { kind: "command", command: "hold d", inputs: [], timeout_seconds: 60 });
  assert.ok(long3.ok && kickoff.ok && derived.ok);
  await new Promise((res) => setTimeout(res, 300));
  for (const r of [long3, kickoff, derived]) assert.equal(svc.jobs.get(r.job.id)!.state, "accepted", `${r.job.id} waits`);
  // a1's quick look runs now, beside its own long parse.
  const quick = await svc.submit("a1", { kind: "command", command: "echo quick", inputs: [], timeout_seconds: SHORT_JOB_SECONDS });
  assert.ok(quick.ok);
  const q = await until(svc, quick.job.id);
  assert.equal(q.status, "ok");
  assert.equal(svc.jobs.get(long1.job.id)!.state, "running", "done while the long ones still run");
  assert.ok(w.scripts.some((t) => t.includes(`timeout --kill-after=10 ${SHORT_JOB_SECONDS} bash /job/command.sh`)), "a short job is killed at its own limit, so the kept worker is not held longer");
  w.release();
  for (const r of [long1, long2, long3, kickoff, derived]) await until(svc, r.job.id);
  const lane = new Map(verifyJournalText(readFileSync(storePaths(S).journal, "utf8")).lines.filter((l) => l.type === "job_started").map((l) => [String(l.job), l.lane]));
  assert.deepEqual([long1, long2, long3, kickoff, derived, quick].map((r) => lane.get(r.job.id)), ["general", "general", "general", "kickoff", "derived", "short"], "each job_started names its lane");
  await svc.stop("over");
  // Two workers: none is kept, and two long jobs run at once.
  const S2 = sandbox();
  const w2 = heldWorker();
  const two = service(S2, { workers: 2, runWorker: w2.runWorker });
  await two.svc.start();
  assert.equal(two.svc.shortSlots(), 0);
  const a = await two.svc.submit("a1", { kind: "command", command: "hold a", inputs: [] });
  const b = await two.svc.submit("a2", { kind: "command", command: "hold b", inputs: [] });
  assert.ok(a.ok && b.ok);
  await until(two.svc, a.job.id, ["running"]);
  await until(two.svc, b.job.id, ["running"]);
  w2.release();
  for (const r of [a, b]) await until(two.svc, r.job.id);
  await two.svc.stop("over");
});

test("a job that sees all of inputs/ gets a copy of the run's inputs.json, named by SWARM_INPUTS_MANIFEST; a declared scope gets none", async () => {
  // The first microVM case run's check_inputs job: the broad view shares inputs/, store/ and the rest, a share is a
  // directory, and the run's inputs.json was not there.
  const S = sandbox();
  writeFileSync(join(S, "inputs.json"), JSON.stringify({ files: [{ path: "inputs/x", bytes: 1, sha256: "ab".repeat(32) }] }));
  const seen: Array<{ env: Record<string, string>; copy: string | null }> = [];
  const { svc } = service(S, {
    runWorker: async (spec: WorkerSpec) => {
      const ctl = spec.mounts.find((m) => m.guest === "/job")!.host;
      const copy = existsSync(join(ctl, "inputs.json")) ? readFileSync(join(ctl, "inputs.json"), "utf8") : null;
      seen.push({ env: spec.env, copy });
      writeFileSync(join(ctl, "inputs.json"), "a job may write its copy");
      writeFileSync(join(ctl, "exit"), "0\n");
      return { code: 0, fenced: true };
    },
  });
  await svc.start();
  const broad = await svc.submit("a1", { kind: "command", command: "true", inputs: ["all"] });
  assert.ok(broad.ok);
  const done = await until(svc, broad.job.id);
  assert.equal(seen[0]!.env.SWARM_INPUTS_MANIFEST, JOB_INPUTS_MANIFEST);
  assert.equal(seen[0]!.copy, readFileSync(join(S, "inputs.json"), "utf8"), "the copy is the run's inputs.json as it is");
  assert.ok((done.accessible ?? []).some((a: { path: string }) => a.path === JOB_INPUTS_MANIFEST), "the record says the job had it");
  assert.match(readFileSync(join(S, "inputs.json"), "utf8"), /inputs\/x/, "what the job wrote into its copy is not the run's");
  const declared = await svc.submit("a1", { kind: "command", command: "true", inputs: [] });
  assert.ok(declared.ok);
  await until(svc, declared.job.id);
  assert.equal(seen[1]!.env.SWARM_INPUTS_MANIFEST, undefined);
  assert.equal(seen[1]!.copy, null);
  await svc.stop("over");
  // Past the bound nothing is copied.
  const big = sandbox();
  writeFileSync(join(big, "inputs.json"), Buffer.alloc(JOB_INPUTS_MANIFEST_MAX + 1, 0x20));
  const ctl = mkdtempSync(join(tmpdir(), "ctl-"));
  assert.equal(await copyInputsManifest(big, ctl), false);
  assert.equal(existsSync(join(ctl, "inputs.json")), false);
});

test("whole-source work holds every worker but one: with two, an agent's job runs beside the kickoff's recipe, and the derived catalogue's waits", async () => {
  // The first microVM case run: the kickoff's linux-target and a disk-timeline an agent asked for held both workers, and
  // the agents' jobs waited up to 505 s.
  const S = sandbox();
  const w = heldWorker();
  const { svc } = service(S, { workers: 2, runWorker: w.runWorker });
  await svc.start();
  assert.equal(svc.heavySlots(), 1, "two workers: whole-source work holds one");
  assert.equal(svc.heavy({ requester: { agent: "a1" }, spec: { kind: "recipe", timeout_seconds: 14400 } } as never), true, "a recipe an agent asked for is whole-source work");
  assert.equal(svc.heavy({ requester: { agent: "a1" }, spec: { kind: "command", timeout_seconds: 14400 } } as never), false, "an agent's long command is not: its limit is not its run time");
  const kickoff = await svc.submit("system", { kind: "command", command: "hold k", inputs: [] });
  assert.ok(kickoff.ok);
  await until(svc, kickoff.job.id, ["running"]);
  // A second worker is free, and the kickoff's next recipe and the derived catalogue's work still wait for the first.
  const kickoff2 = await svc.submit("system", { kind: "command", command: "hold k2", inputs: [] });
  const derived = await svc.submit(DERIVED, { kind: "command", command: "hold d", inputs: [], timeout_seconds: 60 });
  assert.ok(derived.ok && kickoff2.ok);
  await new Promise((res) => setTimeout(res, 300));
  for (const r of [derived, kickoff2]) assert.equal(svc.jobs.get(r.job.id)!.state, "accepted", `${r.job.id} waits for the whole-source worker`);
  const mine = await svc.submit("a1", { kind: "command", command: "hold a", inputs: [] });
  assert.ok(mine.ok);
  await until(svc, mine.job.id, ["running"]);
  w.release();
  for (const r of [kickoff, kickoff2, derived, mine]) await until(svc, r.job.id);
  await svc.stop("over");
  // Four workers, one kept for short jobs: whole-source work holds two.
  const four = service(sandbox(), { workers: 4, runWorker: heldWorker().runWorker });
  assert.equal(four.svc.heavySlots(), 2);
  assert.equal(service(sandbox(), { workers: 1, runWorker: heldWorker().runWorker }).svc.heavySlots(), 1, "one worker: it is the only one there is");
});

test("without room on the host a job waits, said once on the journal, and starts when there is room, its wait on job_started", async () => {
  const S = sandbox();
  let room = false;
  const asked: number[] = [];
  const { svc } = service(S, {
    workerMemoryMib: 2048,
    hostRoom: async (mib) => {
      asked.push(mib);
      return { ok: room, available_mib: room ? 65536 : 1024, needed_mib: mib + 4096 };
    },
  });
  await svc.start();
  const r = await svc.submit("a1", { kind: "command", command: "true", inputs: [] });
  assert.ok(r.ok);
  await eventually(() => asked.length >= 2, "asked again");
  assert.equal(svc.jobs.get(r.job.id)!.state, "accepted", "it waits rather than fail");
  const journal = () => verifyJournalText(readFileSync(storePaths(S).journal, "utf8")).lines;
  const waits = journal().filter((l) => l.type === "job_waits_for_host");
  assert.equal(waits.length, 1, "said once, however often it is asked");
  assert.deepEqual([waits[0].job, waits[0].available_mib, waits[0].needed_mib, waits[0].worker_memory_mib], [r.job.id, 1024, 6144, 2048]);
  room = true;
  assert.equal((await until(svc, r.job.id)).status, "ok");
  const started = journal().find((l) => l.type === "job_started" && l.job === r.job.id)!;
  assert.ok(Number(started.host_wait_ms) > 0, `the wait is on its start: ${JSON.stringify(started)}`);
  await svc.stop("over");
});

/** Start the service in a child process that dies at `step`, then recover in this one. */
function crashAt(S: string, step: string, command: string): void {
  const code = `
import { JobService } from ${JSON.stringify(join(ROOT, "scripts", "job-service.ts"))};
import { localWorker } from ${JSON.stringify(join(ROOT, "tests", "job-service-worker.ts"))};
const svc = new JobService({ sandbox: ${JSON.stringify(S)}, run: "s000000", image: "img:test", workers: 1, workerCpus: 1, workerMemoryMib: 512, allowHosts: [], openNet: false, packDirs: [], forging: false, minFreeMb: 1,
  runWorker: localWorker(), destroyWorker: async () => ({ ok: true }), notify: async () => {}, identity: async () => ({}) });
await svc.start();
await svc.submit("a1", { kind: "command", command: ${JSON.stringify(command)}, inputs: [] });
await new Promise((r) => setTimeout(r, 20000));
`;
  const r = spawnSync(process.execPath, ["--experimental-strip-types", "--input-type=module", "-e", code], { encoding: "utf8", env: { ...process.env, SWARM_JOB_CRASH_AT: step }, timeout: 30000 });
  assert.equal(r.status, 99, `the child should die at ${step}: ${r.stderr}`);
}

for (const [step, expect] of [
  ["job:accepted", "a job accepted and never started runs after the restart"],
  ["job:started", "a job interrupted while it ran keeps that attempt's output and runs again"],
  ["job:fenced", "a job fenced but not sealed is sealed after the restart"],
  ["seal:moved", "a job whose output was moved but not sealed is sealed where it is"],
  ["job:sealed", "a job sealed but not recorded is recorded"],
] as const) {
  test(`recovery: ${expect}`, async () => {
    const S = sandbox();
    crashAt(S, step, "printf result > \"$OUT/r.txt\"");
    const { svc } = service(S, { packDirs: [] });
    await svc.start();
    const job = await until(svc, "j000001");
    assert.equal(job.status, "ok", `${step}: ${JSON.stringify(job)}`);
    assert.equal(readFileSync(join(storePaths(S).jobs, "j000001", "out", "r.txt"), "utf8"), "result");
    const text = readFileSync(storePaths(S).journal, "utf8");
    assert.equal(verifyJournalText(text).error, undefined, "the journal still chains");
    const types = verifyJournalText(text).lines.filter((l) => l.job === "j000001").map((l) => l.type);
    assert.equal(types.filter((t) => t === "job_committed").length, step === "job:started" ? 2 : 1, `${step}: ${types.join(",")}`);
    if (step === "job:started") {
      assert.ok(types.includes("job_retried"));
      assert.ok(existsSync(join(storePaths(S).jobs, "j000001", "attempt-1-interrupted.manifest.json")), "the interrupted attempt's output is kept beside the retry's");
    }
    await svc.stop("over");
  });
}


test("a recipe's coverage says what the images lack, in its own words, and nothing else is taken for it", () => {
  assert.deepEqual(missingOf({ status: "complete", missing: [{ kind: "symbols", what: "the symbol table of kernel K" }, { kind: "symbols" }, "x", null] }), ["the symbol table of kernel K"]);
  assert.deepEqual(missingOf({ status: "complete" }), []);
  assert.deepEqual(missingOf(null), []);
  assert.deepEqual(missingOf({ missing: "not a list" }), []);
});
