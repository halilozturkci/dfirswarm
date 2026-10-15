/**
 * What a stop does to the job service's work (scripts/job-service.ts). On
 * the Breadcrumbs run a job's worker was started while `swarm.sh stop` put
 * the seats away; the stop's removal of that worker and the job's own raced,
 * msb could not say whether the worker was gone, and the hub went with the
 * job's staging directory unsealed and nothing on the record but that one
 * fence. Here, with a stand-in worker:
 *
 * - once a stop is under way (the hub's `.stop`) no new worker is started
 *   and no new job accepted, and what waits is cancelled on the record;
 * - the service's own stop asks again for a worker not confirmed gone and
 *   seals its job once it is (`job_fenced` by the stop);
 * - one still not confirmed gone is accounted for (`job_unsealed`, with its
 *   staging directory and why), custody names it with that why, and
 *   `vm.ts seal-left` seals it after the run once msb says it is gone;
 * - a job the hub left running is sealed as stopped; a staging directory no
 *   job owns is named and left as it is; nothing is sealed while a hub runs,
 *   found by hub.pid or, when a stop that gave up on it dropped that, by its
 *   own command line.
 */
import test from "node:test";
import assert from "node:assert/strict";
import { existsSync, mkdirSync, mkdtempSync, readFileSync, realpathSync, writeFileSync } from "node:fs";
import { spawn, spawnSync } from "node:child_process";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { JobService, sealLeftStaging as sealLeftStagingOnce, type JobServiceOptions } from "../scripts/job-service.ts";
import { checkStore, storePaths, verifyJournalText } from "../scripts/evidence-store.ts";
import { localWorker } from "./job-service-worker.ts";
import type { WorkerSpec } from "../scripts/vm.ts";

const ROOT = join(import.meta.dirname, "..");
const CFB = join(ROOT, "packs", "computer-forensics-base");

/**
 * seal-left looks for a hub process with `ps` (bounded at 15 seconds) and refuses with "(ps failed)" when the listing did not come
 * back, which a machine under a whole suite's load can cause. That refusal is about the listing, not about the hub or the run:
 * nothing has been read or sealed when it comes. This asks again (at most five times) when, and only when, that is the refusal;
 * every other answer, refusals included, is returned as it is.
 */
async function sealLeftStaging(...args: Parameters<typeof sealLeftStagingOnce>): ReturnType<typeof sealLeftStagingOnce> {
  for (let tries = 1; ; tries++) {
    try {
      return await sealLeftStagingOnce(...args);
    } catch (e) {
      if (!/\(ps failed\)/.test(String((e as Error).message)) || tries >= 5) throw e;
    }
  }
}

function sandbox(): string {
  const S = join(mkdtempSync(join(tmpdir(), "stop-seal-")), "run");
  for (const d of ["inputs", "tools", "catalog", "work/a1"]) mkdirSync(join(S, d), { recursive: true });
  writeFileSync(join(S, "inputs.json"), JSON.stringify({ files: [] }));
  return S;
}

function service(S: string, extra: Partial<JobServiceOptions> = {}) {
  const posts: Array<[string, string]> = [];
  const svc = new JobService({
    sandbox: S,
    run: "s000000",
    image: "img:test",
    workers: 1,
    workerCpus: 1,
    workerMemoryMib: 512,
    allowHosts: [],
    openNet: false,
    packDirs: [CFB],
    forging: false,
    minFreeMb: 1,
    runWorker: localWorker(),
    destroyWorker: async () => ({ ok: true }),
    notify: async (to, body) => {
      posts.push([to, body]);
    },
    identity: async () => ({}),
    ...extra,
  });
  return { svc, posts };
}

async function until(svc: JobService, id: string, states: string[], ms = 60000) {
  const end = Date.now() + ms;
  for (;;) {
    const j = svc.jobs.get(id);
    if (j && states.includes(j.state)) return j;
    if (Date.now() > end) throw new Error(`job ${id} is ${j?.state} after ${ms} ms`);
    await new Promise((r) => setTimeout(r, 50));
  }
}

const journal = (S: string) => verifyJournalText(readFileSync(storePaths(S).journal, "utf8"));
const staged = (S: string, name: string) => existsSync(join(storePaths(S).staging, name));

test("once a stop is under way no new worker is started and no job accepted; what waits is cancelled on the record", async () => {
  const S = sandbox();
  let holding = false;
  const { svc } = service(S, { holding: () => holding });
  await svc.start();
  const a = await svc.submit("a1", { kind: "command", command: "sleep 0.5; printf a > \"$OUT/a\"", inputs: [] });
  const b = await svc.submit("a1", { kind: "command", command: "printf b > \"$OUT/b\"", inputs: [] });
  assert.ok(a.ok && b.ok);
  await until(svc, a.job.id, ["running"]);
  holding = true;
  await until(svc, a.job.id, ["committed"]);
  // Past the queue's own two-second tick: still waiting, never started.
  await new Promise((r) => setTimeout(r, 2500));
  assert.equal(svc.jobs.get(b.job.id)!.state, "accepted", "the queued job is not started behind the stop");
  const refused = await svc.submit("a1", { kind: "command", command: "true", inputs: [] });
  assert.equal(refused.ok, false);
  assert.match(!refused.ok ? refused.reason : "", /stopping/);
  await svc.stop("the run is stopping");
  const lines = journal(S).lines;
  assert.ok(!lines.some((l) => l.type === "job_started" && l.job === b.job.id), "no worker for it");
  assert.ok(lines.some((l) => l.type === "job_cancelled" && l.job === b.job.id && l.reason === "the run is stopping"), "cancelled on the record");
});

test("a worker not confirmed gone when its job ended is asked again by the stop, and its job sealed once it is", async () => {
  const S = sandbox();
  let gone = false;
  const { svc } = service(S, { runWorker: localWorker([], { fenced: () => false }), destroyWorker: async () => (gone ? { ok: true } : { ok: false, error: "msb could not say whether it is gone: exit 1" }), stopFence: { tries: 2, waitMs: 10 } });
  await svc.start();
  const r = await svc.submit("a1", { kind: "command", command: "printf x > \"$OUT/x\"", inputs: [] });
  assert.ok(r.ok);
  await until(svc, r.job.id, ["finished"]);
  assert.ok(staged(S, `${r.job.id}-1`), "left in staging while the worker may still write");
  gone = true;
  await svc.stop("the run is stopping");
  assert.equal(svc.jobs.get(r.job.id)!.state, "committed");
  assert.ok(!staged(S, `${r.job.id}-1`), "its staging is sealed into the store");
  const fence = journal(S).lines.filter((l) => l.type === "job_fenced" && l.job === r.job.id).at(-1)!;
  assert.deepEqual([fence.fenced, fence.late, fence.by], [true, true, "stop"]);
  assert.equal(readFileSync(join(storePaths(S).jobs, r.job.id, "out", "x"), "utf8"), "x");
  assert.deepEqual((await checkStore(S))!.staging_left, []);
});

test("one still not confirmed gone is accounted for on the journal, custody says why, and seal-left seals it once it is gone", async () => {
  const S = sandbox();
  const { svc } = service(S, { runWorker: localWorker([], { fenced: () => false }), destroyWorker: async () => ({ ok: false, error: "msb could not say whether it is gone: exit 1" }), stopFence: { tries: 2, waitMs: 10 } });
  await svc.start();
  const r = await svc.submit("a1", { kind: "command", command: "printf partial > \"$OUT/p\"", inputs: [] });
  assert.ok(r.ok);
  await until(svc, r.job.id, ["finished"]);
  await svc.stop("the run is stopping");
  const name = `${r.job.id}-1`;
  assert.ok(staged(S, name), "never read while its worker may be up");
  const unsealed = journal(S).lines.filter((l) => l.type === "job_unsealed");
  assert.equal(unsealed.length, 1);
  assert.equal(unsealed[0]!.staging, name);
  assert.match(String(unsealed[0]!.why), /not confirmed gone when the job service stopped: msb could not say/);
  const before = (await checkStore(S))!;
  assert.deepEqual(before.staging_left, [name]);
  assert.match(before.staging_why?.[name] ?? "", /not confirmed gone/);
  // After the run: nothing is sealed while a hub is the store's writer.
  writeFileSync(join(S, "hub.pid"), `${process.pid}\n`);
  await assert.rejects(sealLeftStaging(S, async () => ({ ok: true })), /store's writer/);
  writeFileSync(join(S, "hub.pid"), "999999999\n");
  const asked: string[] = [];
  const out = await sealLeftStaging(S, async (w) => {
    asked.push(w);
    return { ok: true };
  });
  assert.deepEqual(out, { sealed: [{ staging: name, job: r.job.id, status: "ok" }], left: [] });
  assert.deepEqual(asked, [svc.jobs.get(r.job.id)!.worker], "msb asked once more for that worker");
  assert.ok(!staged(S, name));
  const after = journal(S);
  assert.equal(after.error, undefined, "the journal's chain holds");
  const mine = after.lines.filter((l) => l.job === r.job.id).map((l) => `${l.type}${l.by ? `:${l.by}` : ""}`);
  assert.deepEqual(mine.slice(-3), ["job_unsealed", "job_fenced:stop", "job_committed"]);
  assert.ok(!after.lines.some((l) => l.type === "job_notified" && l.job === r.job.id), "nobody is told after the run: a resume's recovery tells");
  assert.equal(JSON.parse(readFileSync(join(storePaths(S).jobs, r.job.id, "job.json"), "utf8")).state, "committed");
  const st = (await checkStore(S))!;
  assert.deepEqual(st.staging_left, []);
  assert.equal(st.outputs.mismatched.length, 0);
});

test("a job the hub left running is sealed as stopped once its worker is gone; a staging directory no job owns is named and left", async () => {
  const S = sandbox();
  // A worker that writes and never comes back: the hub went while it ran.
  const hanging = async (spec: WorkerSpec) => {
    const out = spec.mounts.find((m) => m.host.includes(".staging/") && m.host.endsWith("/out"))!.host;
    writeFileSync(join(out, "half"), "written before the hub went");
    return new Promise<never>(() => undefined);
  };
  const { svc } = service(S, { runWorker: hanging as JobServiceOptions["runWorker"] });
  await svc.start();
  const r = await svc.submit("a1", { kind: "command", command: "true", inputs: [] });
  assert.ok(r.ok);
  await until(svc, r.job.id, ["running"]);
  for (let i = 0; i < 100 && !existsSync(join(storePaths(S).staging, `${r.job.id}-1`, "out", "half")); i += 1) await new Promise((res) => setTimeout(res, 20));
  mkdirSync(join(storePaths(S).staging, "j999999-1", "out"), { recursive: true });
  const out = await sealLeftStaging(S, async () => ({ ok: true }));
  assert.deepEqual(out.sealed, [{ staging: `${r.job.id}-1`, job: r.job.id, status: "stopped" }]);
  assert.deepEqual(out.left, [{ staging: "j999999-1", why: "no job j999999 on the journal" }]);
  assert.ok(staged(S, "j999999-1"), "not ours to touch");
  const committed = journal(S).lines.filter((l) => l.type === "job_committed" && l.job === r.job.id).at(-1)!;
  assert.equal(committed.status, "stopped");
  assert.equal(committed.reason, "the run was stopped while it ran");
  assert.equal(readFileSync(join(storePaths(S).jobs, r.job.id, "out", "half"), "utf8"), "written before the hub went");
});

test("seal-left finds a hub still up by its command line when hub.pid is gone, and seals nothing beside it", async () => {
  const S = sandbox();
  const { svc } = service(S, { runWorker: localWorker([], { fenced: () => false }), destroyWorker: async () => ({ ok: false, error: "msb could not say" }), stopFence: { tries: 1, waitMs: 0 } });
  await svc.start();
  const r = await svc.submit("a1", { kind: "command", command: "printf p > \"$OUT/p\"", inputs: [] });
  assert.ok(r.ok);
  await until(svc, r.job.id, ["finished"]);
  await svc.stop("the run is stopping");
  const D = mkdtempSync(join(tmpdir(), "dfs-hubdir-"));
  writeFileSync(join(D, "sandbox"), `${realpathSync(S)}\n`);
  // A kickoff's hub, then a keeper's: no hub.pid either time.
  for (const args of [["vm-hub.ts", S, "--dir", D], ["vm-hub.ts", "--resume", D]]) {
    const hub = spawn(process.execPath, ["-e", "setInterval(() => {}, 1000)", ...args], { stdio: "ignore" });
    try {
      // Until `ps` shows the hub's command line (a spawned process is its parent's image until its exec): the lookup this case is
      // about reads that line, and a loaded machine takes longer than any fixed time to get there.
      for (let i = 0; i < 1200 && !spawnSync("ps", ["-ww", "-o", "args=", "-p", String(hub.pid)], { encoding: "utf8" }).stdout.includes("vm-hub.ts"); i++) await new Promise((res) => setTimeout(res, 50));
      await assert.rejects(sealLeftStaging(S, async () => ({ ok: true })), new RegExp(`hub \\(pid ${hub.pid}\\) is still up.*run swarm.sh stop for this run again`));
      assert.ok(staged(S, `${r.job.id}-1`), "left as it is beside a live hub");
    } finally {
      hub.kill("SIGKILL");
      await new Promise((res) => hub.on("exit", res));
    }
  }
  const out = await sealLeftStaging(S, async () => ({ ok: true }));
  assert.deepEqual(out.sealed.map((x) => x.staging), [`${r.job.id}-1`], "sealed once the hub has gone");
});
