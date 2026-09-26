/**
 * The run's job images: the agents' own VMs boot the base, and the forensic
 * programs are in an image per profile. A job names one with `profile`; a
 * pack tool runs in its pack's, a recipe in its pack's (or the one its
 * recipe.json names); anything else in the image that holds every pack. The
 * images are declared on the journal before any job runs, and custody holds
 * each job to them. The worker is the local stand-in, which records the image
 * it was asked to boot.
 */
import test from "node:test";
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { mkdirSync, mkdtempSync, readFileSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { JobService, type JobRecord, type JobServiceOptions } from "../scripts/job-service.ts";
import { checkStore, storePaths, verifyJournalText } from "../scripts/evidence-store.ts";
import { localWorker } from "./job-service-worker.ts";
import type { WorkerSpec } from "../scripts/vm.ts";

const ROOT = join(import.meta.dirname, "..");
const CFB = join(ROOT, "packs", "computer-forensics-base");
const IMAGES = { full: "dfirswarm-full:dev", disk: "dfirswarm-disk:dev", memory: "dfirswarm-memory:dev", mobile: "dfirswarm-mobile:dev" };

function sandbox(): string {
  const S = join(mkdtempSync(join(tmpdir(), "jobprof-")), "run");
  for (const d of ["inputs", "tools", "catalog", "work/a1"]) mkdirSync(join(S, d), { recursive: true });
  writeFileSync(join(S, "inputs.json"), JSON.stringify({ files: [] }));
  return S;
}

function service(S: string, extra: Partial<JobServiceOptions> = {}) {
  const booted: string[] = [];
  const worker = localWorker();
  const svc = new JobService({
    sandbox: S, run: "s000000", image: IMAGES.full, images: IMAGES,
    packProfiles: { "computer-forensics-base": "disk", "memory-forensics": "memory", "mobile-forensics": "mobile" },
    workers: 2, workerCpus: 1, workerMemoryMib: 512, allowHosts: [], openNet: false, packDirs: [CFB], forging: true, minFreeMb: 1, derived: false,
    runWorker: (spec: WorkerSpec) => {
      booted.push(spec.image);
      return worker(spec);
    },
    destroyWorker: async () => ({ ok: true }),
    notify: async () => undefined,
    identity: async (a) => ({ name: `${a}-name` }),
    ...extra,
  });
  return { svc, booted };
}

async function until(svc: JobService, id: string): Promise<JobRecord> {
  const end = Date.now() + 30000;
  while (!["committed", "failed", "cancelled"].includes(svc.jobs.get(id)?.state ?? "")) {
    if (Date.now() > end) throw new Error(`job ${id} not done`);
    await new Promise((r) => setTimeout(r, 50));
  }
  return svc.jobs.get(id)!;
}

const journal = (S: string) => verifyJournalText(readFileSync(storePaths(S).journal, "utf8")).lines;

test("a job runs in the image its profile names, a pack tool in its pack's, anything else in the one holding every pack", async () => {
  const S = sandbox();
  // A pack tool, seeded with its pack's name as the kickoff seeds one.
  const body = "import json,sys\nprint(json.dumps({'ok': True}))\n";
  mkdirSync(join(S, "tools", "segb_dump"), { recursive: true });
  writeFileSync(join(S, "tools", "segb_dump", "run.py"), body);
  writeFileSync(join(S, "tools", "segb_dump", "manifest.json"), JSON.stringify({ name: "segb_dump", description: "t", params: {}, runtime: "python3", entry: "run.py", timeout_seconds: 60, by: "t", at: "t", version: 1, sha256: createHash("sha256").update(body).digest("hex"), pack: "mobile-forensics" }));
  const { svc, booted } = service(S);
  await svc.start();
  const mem = await svc.submit("a1", { kind: "command", command: "echo vol", inputs: [], profile: "memory" });
  const plain = await svc.submit("a1", { kind: "command", command: "echo hi", inputs: [] });
  const tool = await svc.submit("a1", { kind: "tool", tool: "segb_dump", args: {}, inputs: [] });
  assert.ok(mem.ok && plain.ok && tool.ok);
  for (const r of [mem, plain, tool]) await until(svc, r.ok ? r.job.id : "");
  const started = new Map(journal(S).filter((l) => l.type === "job_started").map((l) => [String(l.job), l]));
  assert.equal(started.get(mem.ok ? mem.job.id : "")?.image, IMAGES.memory);
  assert.equal(started.get(mem.ok ? mem.job.id : "")?.profile, "memory");
  assert.equal(started.get(plain.ok ? plain.job.id : "")?.image, IMAGES.full, "no profile: the image that holds every pack");
  assert.equal(started.get(tool.ok ? tool.job.id : "")?.image, IMAGES.mobile, "a pack tool: its pack's image");
  assert.deepEqual([...booted].sort(), [IMAGES.full, IMAGES.memory, IMAGES.mobile].sort(), "each worker booted the image on its record");
  // The images were on the journal before any job ran.
  const lines = journal(S);
  const declared = lines.findIndex((l) => l.type === "job_images");
  assert.ok(declared >= 0 && declared < lines.findIndex((l) => l.type === "job_started"));
  assert.deepEqual(lines[declared].images, IMAGES);
  // Custody holds each job to them.
  const st = await checkStore(S);
  assert.deepEqual(st?.images?.undeclared, []);
  assert.deepEqual(st?.images?.declared, Object.values(IMAGES).sort());
  await svc.stop("over");
});

test("a profile the run did not declare is refused with the ones it has; with no job images, any profile is", async () => {
  const S = sandbox();
  const { svc } = service(S);
  await svc.start();
  const r = await svc.submit("a1", { kind: "command", command: "true", inputs: [], profile: "network" });
  assert.equal(r.ok, false);
  assert.match(!r.ok ? r.reason : "", /no job image "network" in this run: full; disk \(the packs computer-forensics-base\); memory \(the packs memory-forensics\); mobile \(the packs mobile-forensics\)/);
  // A pack's id picks its pack's image: agents named packs as profiles.
  const byPack = await svc.submit("a1", { kind: "command", command: "true", inputs: [], profile: "mobile-forensics" });
  assert.ok(byPack.ok, !byPack.ok ? byPack.reason : "");
  const done = await until(svc, byPack.ok ? byPack.job.id : "");
  assert.equal(done.spec.profile, "mobile");
  assert.equal(journal(S).find((l) => l.type === "job_started" && l.job === done.id)?.image, IMAGES.mobile);
  await svc.stop("over");
  const S2 = sandbox();
  const { svc: plain } = service(S2, { images: undefined, packProfiles: undefined });
  await plain.start();
  const r2 = await plain.submit("a1", { kind: "command", command: "true", inputs: [], profile: "disk" });
  assert.match(!r2.ok ? r2.reason : "", /declared no job images: leave profile out/);
  assert.equal(journal(S2).some((l) => l.type === "job_images"), false, "nothing declared when there is nothing to declare");
  await plain.stop("over");
});

test("a recipe runs in its pack's image, or in the one its recipe.json names", async () => {
  const S = sandbox();
  const { svc } = service(S);
  await svc.start();
  assert.deepEqual(await svc.imageFor({ kind: "recipe", recipe: "computer-forensics-base/archive-members", inputs: [], timeout_seconds: 60, network: "off" }), { profile: "disk", ref: IMAGES.disk });
  assert.deepEqual(await svc.imageFor({ kind: "detect", inputs: [], timeout_seconds: 60, network: "off" }), { profile: null, ref: IMAGES.full }, "a detect pass asks every recipe: the image that holds every pack");
  await svc.stop("over");
});
