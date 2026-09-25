/**
 * The hub's job routes (jobSubmit, jobStatus, catalogRequest) over a job
 * service whose workers are the local stand-in: who asks is the seat the
 * call came in on, an agent's own scratch is mounted when its command names
 * it, a target is resolved to an object of the run or refused, and a
 * request with no recipe finds the ones that apply.
 */
import test from "node:test";
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { mkdirSync, mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { boardTable } from "../scripts/vm-hub.ts";
import { JobService, resolveTarget } from "../scripts/job-service.ts";
import { localWorker } from "./job-service-worker.ts";
import type { WorkerSpec } from "../scripts/vm.ts";

const ROOT = join(import.meta.dirname, "..");

function rig(withJobs = true) {
  const S = join(mkdtempSync(join(tmpdir(), "hubjobs-")), "run");
  for (const d of ["inputs", "tools", "catalog", "work/a1", "work/a2"]) mkdirSync(join(S, d), { recursive: true });
  writeFileSync(join(S, "inputs.json"), JSON.stringify({ files: [] }));
  writeFileSync(join(S, "work", "a1", "notes.txt"), "mine\n");
  spawnSync("python3", ["-c", "import zipfile,sys\nwith zipfile.ZipFile(sys.argv[1],'w') as z: z.writestr('k.txt','key')", join(S, "inputs", "a.zip")]);
  const specs: WorkerSpec[] = [];
  const posts: Array<[string, string]> = [];
  const svc = new JobService({
    sandbox: S, run: "s000000", image: "img:test", workers: 2, workerCpus: 1, workerMemoryMib: 512, allowHosts: [], openNet: false,
    packDirs: [join(ROOT, "packs", "computer-forensics-base")], forging: false, minFreeMb: 1,
    runWorker: localWorker(specs), destroyWorker: async () => ({ ok: true }),
    notify: async (to, body) => { posts.push([to, body]); }, identity: async (a) => ({ name: `${a}-name` }),
  });
  const table = boardTable({ sandbox: S, settle: async () => undefined, wrote: () => undefined, ids: ["a1", "a2"], ...(withJobs ? { jobs: () => svc } : {}) });
  const call = (who: string, fn: string, arg: unknown) => (table as Record<string, (w: string, a: unknown[], s: AbortSignal) => Promise<unknown>>)[fn](who, [S, arg], new AbortController().signal) as Promise<Record<string, any>>;
  return { S, svc, call, specs, posts };
}

async function done(call: (who: string, fn: string, arg: unknown) => Promise<Record<string, any>>, who: string, id: string) {
  for (let i = 0; i < 400; i += 1) {
    const r = await call(who, "jobStatus", { job_id: id });
    if (["committed", "failed", "cancelled"].includes(r.job?.state)) return r;
    await new Promise((res) => setTimeout(res, 50));
  }
  throw new Error(`${id} never finished`);
}

test("with no job service the routes say so", async () => {
  const { call } = rig(false);
  for (const fn of ["jobSubmit", "jobStatus", "catalogRequest"]) {
    const r = await call("a1", fn, {});
    assert.equal(r.ok, false);
    assert.match(r.reason, /no job service/);
  }
});

test("a job is the calling seat's; a command naming its own scratch gets it read-only; status pages stdout and only the owner cancels", async () => {
  const { svc, call, specs } = rig();
  await svc.start();
  const r = await call("a1", "jobSubmit", { command: "cat work/a1/notes.txt; echo out > \"$OUT/o.txt\"", requester: "a2" });
  assert.equal(r.ok, true, JSON.stringify(r));
  assert.equal(r.job.requester, "a1", "the seat the call came in on, whatever the arguments say");
  const st = await done(call, "a1", r.job.job);
  assert.equal(st.job.status, "ok");
  assert.equal(st.stdout.text, "mine\n");
  assert.equal(st.job.outputs.list[0].path, "o.txt");
  assert.equal(st.job.cite, `job:${r.job.job}/<path>`);
  const scratch = specs[0].mounts.find((m) => m.guest?.endsWith("/work/a1"));
  assert.ok(scratch?.readonly, "its own scratch, read-only, because the command names it");
  const other = await call("a2", "jobSubmit", { command: "true" });
  assert.equal(specs.length, 1);
  assert.equal(other.ok, true);
  await done(call, "a2", other.job.job);
  assert.ok(!specs[1].mounts.some((m) => /\/work\/a\d$/.test(m.guest ?? "")), "a job that does not name a scratch gets none");
  const long = await call("a1", "jobSubmit", { command: "sleep 2" });
  const refused = await call("a2", "jobStatus", { job_id: long.job.job, cancel: true });
  assert.equal(refused.ok, false);
  await svc.stop("over");
});

test("catalogRequest resolves the target, refuses what is not the run's, and without a recipe finds those that apply", async () => {
  const { S, svc, call, posts } = rig();
  await svc.start();
  for (const bad of ["/etc/passwd", "../outside", "inputs/../../x", "job:j000001", "input:none.zip"]) {
    const r = await call("a1", "catalogRequest", { target: bad });
    assert.equal(r.ok, false, `${bad}: ${JSON.stringify(r)}`);
  }
  const t = await resolveTarget(S, "input:a.zip");
  assert.ok(!("reason" in t) && t.name === "inputs/a.zip" && t.ref === "input:a.zip");
  const r = await call("a1", "catalogRequest", { target: "inputs/a.zip", reason: "the key is in there" });
  assert.equal(r.ok, true, JSON.stringify(r));
  assert.equal(r.job.kind, "detect");
  // The detect pass hands the zip to the archive recipe, as a1's own job.
  for (let i = 0; i < 400 && !posts.some(([to, b]) => to === "a1" && /Catalogued as g0001/.test(b)); i += 1) await new Promise((res) => setTimeout(res, 50));
  assert.ok(posts.some(([to, b]) => to === "a1" && /recipe computer-forensics-base\/archive-members\) done/.test(b) && /Catalogued as g0001/.test(b)), JSON.stringify(posts));
  // Nothing applies: said so.
  writeFileSync(join(S, "inputs", "plain.txt"), "just text, nothing to catalogue here\n".repeat(10));
  const none = await call("a1", "catalogRequest", { target: "inputs/plain.txt" });
  assert.equal(none.ok, true);
  for (let i = 0; i < 400 && !posts.some(([, b]) => b.startsWith("No recipe of this run catalogues inputs/plain.txt")); i += 1) await new Promise((res) => setTimeout(res, 50));
  assert.ok(posts.some(([to, b]) => to === "a1" && b.startsWith("No recipe of this run catalogues inputs/plain.txt")), JSON.stringify(posts));
  await svc.stop("over");
});
