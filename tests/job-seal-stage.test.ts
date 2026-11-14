/**
 * What the seal stage and its neighbours say and bound (scripts/job-service.ts),
 * with the worker VM replaced by the stand-in of tests/job-service-worker.ts
 * and the seal by one this file holds or fails:
 *
 * - a job being sealed says how far its seal is, in the seal's own count;
 * - a seal that fails is tried again a bounded number of times, says so to
 *   whoever waits, and after the last try the job ends failed and its
 *   requester is told; a stop does not wait for a try, and leaves the job
 *   for the seal after the run;
 * - a status call reads a large manifest's head, never the manifest;
 * - a derived_offered line past a few rows is counts, a sample and a side
 *   file a restart reads what waits from;
 * - a call joined to a job under way is not counted against its seat's queue;
 * - a job marked sensitive file by file says which files.
 */
import test from "node:test";
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { chmodSync, existsSync, mkdirSync, mkdtempSync, readFileSync, statSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, JobService, jobView, OFFERED_SHOWN, sealLeftStaging, sensitiveWords, type JobRecord, type JobServiceOptions } from "../scripts/job-service.ts";
import { sealTree, storePaths, verifyJournalText, type JournalLine, type SealProgress } from "../scripts/evidence-store.ts";
import { INDEX_MIN_BYTES } from "../scripts/manifest-index.ts";
import { listInputs, localWorker } from "./job-service-worker.ts";

const ROOT = join(import.meta.dirname, "..");
const CFB = join(ROOT, "packs", "computer-forensics-base");

function sandbox(inputs?: Array<{ path: string; sha256: string }>): string {
  const S = join(mkdtempSync(join(tmpdir(), "sealstage-")), "run");
  for (const d of ["inputs", "tools", "catalog", "work/a1"]) mkdirSync(join(S, d), { recursive: true });
  writeFileSync(join(S, "inputs", "image.bin"), "an image\n".repeat(40));
  if (inputs) writeFileSync(join(S, "inputs.json"), JSON.stringify({ files: inputs }));
  else listInputs(S);
  return S;
}

function tool(S: string, name: string, body: string, params: Record<string, unknown>): void {
  mkdirSync(join(S, "tools", name), { recursive: true });
  writeFileSync(join(S, "tools", name, "run.py"), body);
  writeFileSync(join(S, "tools", name, "manifest.json"), JSON.stringify({ name, description: "t", params, runtime: "python3", entry: "run.py", timeout_seconds: 60, by: "t", at: "t", version: 1, sha256: createHash("sha256").update(body).digest("hex") }));
}

function service(S: string, extra: Partial<JobServiceOptions> = {}) {
  const posts: Array<[string, string]> = [];
  const logs: string[] = [];
  const svc = new JobService({
    sandbox: S, run: "s000000", image: "img:test", workers: 2, workerCpus: 1, workerMemoryMib: 512, allowHosts: [], openNet: false,
    packDirs: [], forging: true, minFreeMb: 1,
    runWorker: localWorker(), destroyWorker: async () => ({ ok: true }),
    notify: async (to, body) => { posts.push([to, body]); }, identity: async (a) => ({ name: `${a}-name` }),
    log: (line: string) => { logs.push(line); },
    ...extra,
  });
  return { svc, posts, logs };
}

const journal = (S: string): JournalLine[] => {
  const checked = verifyJournalText(readFileSync(storePaths(S).journal, "utf8"));
  assert.equal(checked.error, undefined, "the journal chains");
  return checked.lines;
};
const sleep = (ms: number) => new Promise<void>((r) => setTimeout(r, ms));

async function eventually(ok: () => boolean, what: string, ms = 30000): Promise<void> {
  const end = Date.now() + ms;
  while (!ok()) {
    if (Date.now() > end) throw new Error(`not within ${ms} ms: ${what}`);
    await sleep(25);
  }
}

async function until(svc: JobService, id: string, states = ["committed", "failed", "cancelled"], ms = 30000): Promise<JobRecord> {
  await eventually(() => states.includes(svc.jobs.get(id)?.state ?? ""), `job ${id} is ${states.join(" or ")}`, ms);
  return svc.jobs.get(id)!;
}

function ok<T extends { ok: boolean }>(r: T): Extract<T, { ok: true }> {
  assert.ok(r.ok, JSON.stringify(r));
  return r as Extract<T, { ok: true }>;
}

test("a job being sealed says how far its seal is, in the seal's own count: listed, N of M files hashed, the manifest being written", async () => {
  const S = sandbox();
  let step: (p: Partial<SealProgress>) => void = () => undefined;
  let release: () => void = () => undefined;
  const held = new Promise<void>((res) => {
    release = res;
  });
  let entered = false;
  const { svc } = service(S, {
    sealTree: async (sandboxDir, staging, dest, job, attempt, manifestPath, opts) => {
      step = (p) => opts?.onProgress?.({ job, phase: "hash", files_done: 0, files_total: 0, bytes_done: 0, bytes_total: 0, resumed_files: 0, workers: 0, started_at: "", at: "", ...p });
      entered = true;
      await held;
      return sealTree(sandboxDir, staging, dest, job, attempt, manifestPath);
    },
  });
  await svc.start();
  const a = ok(await svc.submit("a1", { kind: "command", command: "printf a > \"$OUT/a\"", inputs: [] }));
  await eventually(() => entered, "its seal started");
  const job = svc.jobs.get(a.job.id)!;
  assert.equal(job.state, "fenced");
  step({ phase: "walk" });
  assert.match(svc.waitWords(job) ?? "", /^finished \(exit 0\) at \S+, being sealed into the store now \(its files are being listed\)\. Its output cannot be cited or read as job:j000001\/\.\.\. until then/);
  step({ phase: "hash", files_done: 1200, files_total: 201202 });
  const words = svc.waitWords(job) ?? "";
  assert.match(words, /^finished \(exit 0\) at \S+, being sealed into the store now \(1200 of 201202 files hashed\)\. /);
  assert.match(words, /running it again or cancelling it gains nothing\. A post tagged result says when it is sealed$/);
  assert.equal((await jobView(S, job, { waiting: words })).waiting, words, "job_status and job_run show the same words");
  step({ phase: "manifest", files_done: 201202, files_total: 201202 });
  assert.match(svc.waitWords(job) ?? "", /being sealed into the store now \(all 201202 files hashed, its manifest is being written\)\. /);
  release();
  const done = await until(svc, a.job.id);
  assert.equal(done.state, "committed");
  assert.equal(svc.waitWords(done), undefined);
  await svc.stop("over");
});

test("a seal that fails is tried again with a wait, says so to whoever waits, and the job is committed by the try that works", async () => {
  const S = sandbox();
  let calls = 0;
  const { svc, posts } = service(S, {
    sealRetry: { tries: 3, waitMs: 400 },
    sealTree: async (sandboxDir, staging, dest, job, attempt, manifestPath) => {
      if (job === "j000001") calls += 1;
      if (job === "j000001" && calls <= 2) throw new Error(`ENOSPC: no space left on device (try ${calls})`);
      return sealTree(sandboxDir, staging, dest, job, attempt, manifestPath);
    },
  });
  await svc.start();
  const a = ok(await svc.submit("a1", { kind: "command", command: "printf a > \"$OUT/a\"", inputs: [] }));
  await eventually(() => journal(S).some((l) => l.type === "job_seal_failed"), "the first failure is on the record");
  const job = svc.jobs.get(a.job.id)!;
  assert.equal(job.state, "fenced", "it is not failed, and not committed");
  assert.match(svc.waitWords(job) ?? "", /^finished \(exit 0\) at \S+, not yet sealed into the store\. Its seal failed once \(ENOSPC: no space left on device \(try 1\)\) and is tried again at \d{4}-\S+Z, try 2 of 3; if the last try fails the job ends failed and you are told\. Its output cannot be cited/);
  // A job behind it is sealed meanwhile: a seal that waits for its next try holds no sealer.
  const b = ok(await svc.submit("a2", { kind: "command", command: "printf b > \"$OUT/b\"", inputs: [] }));
  await until(svc, b.job.id);
  assert.equal(svc.jobs.get(a.job.id)!.state, "fenced", "the later job is committed while the first waits for its next try");
  const done = await until(svc, a.job.id);
  assert.deepEqual([done.state, done.status], ["committed", "ok"]);
  assert.equal(readFileSync(join(storePaths(S).jobs, a.job.id, "out", "a"), "utf8"), "a");
  const lines = journal(S);
  const failures = lines.filter((l) => l.type === "job_seal_failed" && l.job === a.job.id);
  assert.deepEqual(failures.map((l) => [l.try, l.of, l.retry_in_ms]), [[1, 3, 400], [2, 3, 1600]], "each failure, and the wait before the next try: four times as long each time");
  assert.equal(lines.filter((l) => l.type === "job_committed" && l.job === a.job.id).length, 1);
  assert.ok(!lines.some((l) => l.type === "job_failed"));
  await eventually(() => posts.some(([to, body]) => to === "a1" && body.startsWith(`Job ${a.job.id} (command) done`)), "its requester is told it is done");
  await svc.stop("over");
});

test("a seal that fails every try ends the job failed with the reason, tells its requester and whoever joined it, and keeps what it wrote; a restart reads it failed", async () => {
  const S = sandbox();
  tool(S, "extract_all", "import os,sys\nopen(os.path.join(os.environ['OUT'],'tree.txt'),'w').write('x')\n", { output: { type: "string" } });
  const { svc, posts } = service(S, {
    sealRetry: { tries: 2, waitMs: 50 },
    sealTree: async () => {
      throw new Error("EIO: i/o error, read");
    },
  });
  await svc.start();
  const call = { kind: "tool" as const, tool: "extract_all", args: { output: "{OUT}" }, inputs: ["input:image.bin"] };
  const a = ok(await svc.submit("a1", call));
  const joined = ok(await svc.submit("a2", call));
  assert.equal(joined.job.id, a.job.id);
  const done = await until(svc, a.job.id);
  assert.deepEqual([done.state, done.status], ["failed", "failed"]);
  assert.match(done.reason ?? "", /^its output could not be sealed into the store after 2 tries \(EIO: i\/o error, read\); it ran \(exit 0\), and what it wrote is kept unsealed in store\/staging\/j000001-1\/ or store\/jobs\/j000001\/out\/ and cannot be cited\./);
  assert.deepEqual(done.seal_failed, { tries: 2, error: "EIO: i/o error, read", staging: "store/staging/j000001-1", ran: { status: "ok", exit: 0 } });
  assert.ok(existsSync(join(storePaths(S).staging, "j000001-1", "out", "tree.txt")), "what it wrote is not removed");
  const lines = journal(S);
  assert.deepEqual(lines.filter((l) => l.job === a.job.id && ["job_seal_failed", "job_failed", "job_committed"].includes(l.type)).map((l) => l.type), ["job_seal_failed", "job_seal_failed", "job_failed"]);
  await eventually(() => ["a1", "a2"].every((seat) => posts.some(([to, body]) => to === seat && body.startsWith(`Job ${a.job.id} (tool extract_all) failed: its output could not be sealed into the store after 2 tries`))), `both are told: ${JSON.stringify(posts)}`);
  assert.equal(describe(done), posts.find(([to]) => to === "a1")![1]);
  assert.equal(svc.waitWords(done), undefined, "it waits for nothing");
  assert.deepEqual((await jobView(S, done)).seal_failed, done.seal_failed);
  // The same call again is a new job: a failed one is never joined.
  const again = ok(await svc.submit("a3", call));
  assert.notEqual(again.job.id, a.job.id);
  await until(svc, again.job.id);
  await svc.stop("over");
  const back = service(S).svc;
  await back.start();
  assert.deepEqual([back.jobs.get(a.job.id)?.state, back.jobs.get(a.job.id)?.seal_failed?.tries], ["failed", 2]);
  await back.stop("over");
});

test("a stop does not wait for a seal's next try: the job stays fenced, is not said failed, and the seal after the run seals it", async () => {
  const S = sandbox();
  let broken = true;
  const failing: JobServiceOptions["sealTree"] = async (sandboxDir, staging, dest, job, attempt, manifestPath) => {
    if (broken) throw new Error("EIO: i/o error, read");
    return sealTree(sandboxDir, staging, dest, job, attempt, manifestPath);
  };
  const { svc, posts } = service(S, { sealRetry: { tries: 3, waitMs: 600_000 }, sealTree: failing });
  await svc.start();
  const a = ok(await svc.submit("a1", { kind: "command", command: "printf a > \"$OUT/a\"", inputs: [] }));
  await eventually(() => journal(S).some((l) => l.type === "job_seal_failed"), "the first failure");
  const asked = Date.now();
  await svc.stop("the run is stopping");
  assert.ok(Date.now() - asked < 5000, `the stop took ${Date.now() - asked} ms, not the ten minutes of the wait`);
  assert.equal(svc.jobs.get(a.job.id)!.state, "fenced");
  assert.ok(!journal(S).some((l) => l.type === "job_failed" || l.type === "job_committed"));
  assert.ok(!posts.some(([, body]) => /could not be sealed/.test(body)));
  // After the run, with the cause gone: what the stop left is sealed (swarm.sh stop).
  broken = false;
  const out = await sealLeftStaging(S, async () => ({ ok: true }));
  assert.deepEqual(out, { sealed: [{ staging: "j000001-1", job: a.job.id, status: "ok" }], left: [] });
  assert.equal(readFileSync(join(storePaths(S).jobs, a.job.id, "out", "a"), "utf8"), "a");
});

test("a status call of a job with a large manifest reads its head: the first files, the top of its tree and the manifest's sha256, as the manifest has them", async () => {
  const S = sandbox();
  const { svc } = service(S);
  await svc.start();
  const write = "python3 -c \"import os\nfor i in range(2400):\n  d=os.environ['OUT']+'/Users/someone/AppData/Local/a-long-directory-name/%02d'%(i%40); os.makedirs(d,exist_ok=True); open(d+'/file-%05d.dat'%i,'w').write('content %05d'%i)\nopen(os.environ['OUT']+'/summary.txt','w').write('s')\"";
  const a = ok(await svc.submit("a1", { kind: "command", command: write, inputs: [] }));
  const done = await until(svc, a.job.id, undefined, 120000);
  const manifestPath = join(storePaths(S).jobs, a.job.id, "manifest.json");
  assert.ok(statSync(manifestPath).size > INDEX_MIN_BYTES, "a manifest large enough to have a head");
  const text = readFileSync(manifestPath, "utf8");
  const manifest = JSON.parse(text) as { files: Array<{ path: string; bytes: number; sha256: string }> };
  const view = (await jobView(S, done)).outputs as { files: number; list: Array<{ path: string; bytes: number; sha256: string }>; more: string; top: unknown[]; manifest_sha256: string };
  assert.equal(view.files, 2401);
  assert.deepEqual(view.list, manifest.files.slice(0, 20).map((f) => ({ path: f.path, bytes: f.bytes, sha256: f.sha256 })), "the manifest's own first files, in its order");
  assert.equal(view.more, `2381 more, every one in store/jobs/${a.job.id}/manifest.json`);
  assert.deepEqual(view.top, [{ dir: "Users/", files: 2400, bytes: 2400 * 13 }, { file: "summary.txt", bytes: 1 }]);
  assert.equal(view.manifest_sha256, createHash("sha256").update(text).digest("hex"));
  assert.equal(view.manifest_sha256, done.outputs?.manifest_sha256);
  await svc.stop("over");
});

test("a derived_offered line past a few rows is counts, the first few and a side file held to its sha256; a restart reads what waits from the file, and offers the job again when the file is not the one the line names", async () => {
  // 300 files a recipe's measure takes that are the run's inputs by content (skipped, each named), and three that are new (offered).
  const bytesOf = (i: number) => `PK\u0003\u0004 not a zip, only its first bytes: object ${String(i).padStart(4, "0")}`;
  const inputs = Array.from({ length: 300 }, (_, i) => ({ path: `inputs/set/member-with-a-long-name-${String(i).padStart(4, "0")}.zip`, sha256: createHash("sha256").update(bytesOf(i)).digest("hex") }));
  const S = sandbox(inputs);
  const command = "python3 -c \"import os\nfor i in range(303):\n  open(os.environ['OUT']+'/copy-%04d.zip'%i,'w').write('PK\\x03\\x04 not a zip, only its first bytes: object %04d'%i)\"";
  // The lane has no budget in this service: what is offered waits.
  const { svc } = service(S, { packDirs: [CFB], derived: true, derivedLimits: { windowSeconds: 0 } });
  await svc.start();
  const a = ok(await svc.submit("a1", { kind: "command", command, inputs: [] }));
  await until(svc, a.job.id);
  await eventually(() => journal(S).some((l) => l.type === "derived_offered"), "the offer is on the record");
  const line = journal(S).find((l) => l.type === "derived_offered")!;
  const raw = readFileSync(storePaths(S).journal, "utf8").split("\n")[line.seq];
  assert.ok(Buffer.byteLength(raw) < 4096, `the line is ${Buffer.byteLength(raw)} bytes, whatever the job made`);
  assert.deepEqual([line.offered_total, line.skipped_total, line.filtered, line.list], [3, 300, 0, `store/jobs/${a.job.id}/derived_offered.json`]);
  assert.equal((line.offered as unknown[]).length, 3);
  assert.equal((line.skipped as unknown[]).length, OFFERED_SHOWN, "the first few of what was skipped");
  const sidePath = join(S, String(line.list));
  const side = readFileSync(sidePath, "utf8");
  assert.equal(createHash("sha256").update(side).digest("hex"), line.list_sha256, "the side file is held to the line");
  const doc = JSON.parse(side) as { job: string; offered: Array<{ path: string; sha256: string }>; skipped: Array<{ path: string; same_as: string }> };
  assert.deepEqual([doc.job, doc.offered.length, doc.skipped.length], [a.job.id, 3, 300]);
  assert.deepEqual(doc.offered.map((o) => o.path), ["copy-0300.zip", "copy-0301.zip", "copy-0302.zip"]);
  assert.deepEqual(doc.skipped[0], { sha256: inputs[0].sha256, path: "copy-0000.zip", same_as: "input:set/member-with-a-long-name-0000.zip" });
  assert.ok(![...svc.jobs.values()].some((j) => j.spec.kind === "detect"), "nothing of the lane ran");
  await svc.stop("over");
  // A restart with a budget: what waited is asked about, read from the side file, and the job is not offered again.
  const second = service(S, { packDirs: [CFB], derived: true });
  await second.svc.start();
  await eventually(() => [...second.svc.jobs.values()].some((j) => j.spec.kind === "detect" && doc.offered.every((o) => j.spec.targets?.some((t) => t.sha256 === o.sha256))), "the three that waited are asked about");
  await eventually(() => journal(S).some((l) => l.type === "detect_answered"), "the pass is read");
  assert.equal(journal(S).filter((l) => l.type === "derived_offered").length, 1, "offered once");
  await second.svc.stop("over");
  // The side file rewritten: it is not believed, and the job's files are offered again from its manifest.
  chmodSync(sidePath, 0o644);
  writeFileSync(sidePath, side.replace("copy-0300.zip", "copy-9999.zip"));
  const third = service(S, { packDirs: [CFB], derived: true, derivedLimits: { windowSeconds: 0 } });
  await third.svc.start();
  await eventually(() => journal(S).filter((l) => l.type === "derived_offered").length === 2, "offered again");
  assert.ok(third.logs.some((l) => /derived_offered\.json is not there or is not the file its derived_offered line names/.test(l)), third.logs.join("\n"));
  const again = journal(S).filter((l) => l.type === "derived_offered")[1];
  assert.equal(createHash("sha256").update(readFileSync(sidePath, "utf8")).digest("hex"), again.list_sha256, "and the file is the new line's");
  await third.svc.stop("over");
});

test("a call joined to a job under way is not counted against its seat's queue: the join is looked for first, and a call of its own is still refused at the limit", async () => {
  const S = sandbox();
  tool(S, "extract_all", "import os,sys\nopen(os.path.join(os.environ['OUT'],'tree.txt'),'w').write('x')\n", { output: { type: "string" } });
  let release: () => void = () => undefined;
  const held = new Promise<void>((res) => {
    release = res;
  });
  const real = localWorker();
  const { svc } = service(S, {
    perRequesterQueued: 1,
    runWorker: async (spec) => {
      await held;
      return real(spec);
    },
  });
  await svc.start();
  const call = { kind: "tool" as const, tool: "extract_all", args: { output: "{OUT}" }, inputs: ["input:image.bin"] };
  const first = ok(await svc.submit("a2", call));
  // a3 has one job of its own, the most it may have.
  const own = ok(await svc.submit("a3", { kind: "command", command: "true", inputs: [] }));
  const refused = await svc.submit("a3", { kind: "command", command: "printf x", inputs: [] });
  assert.ok(!refused.ok && /^you have 1 jobs queued or running, the most one agent may have/.test(refused.reason), JSON.stringify(refused));
  const joined = ok(await svc.submit("a3", call));
  assert.equal(joined.job.id, first.job.id, "the identical call is answered with the job under way");
  assert.match(joined.joined?.note ?? "", /^Not run again: a2-name \(a2\) asked for the same call/);
  // And the seat that asked for it first, at its own limit, is answered with its own job.
  const mine = ok(await svc.submit("a2", call));
  assert.equal(mine.job.id, first.job.id);
  assert.match(mine.joined?.note ?? "", /^Not run again: you asked for the same call/);
  release();
  for (const id of [first.job.id, own.job.id]) await until(svc, id);
  assert.equal(journal(S).filter((l) => l.type === "job_accepted").length, 2);
  await svc.stop("over");
});

test("a job marked sensitive file by file says which files are sensitive and that the rest is not; one sensitive whole says all of it is", async () => {
  const whole = sensitiveWords({ id: "j000009", sensitive: { why: "derived", from: ["j000003"], note: "made from the sensitive output of j000003: every output it sealed is sensitive" } });
  assert.match(whole, /^Its outputs are sensitive \(made from the sensitive output of j000003\): an entry citing them is recorded sensitive/);
  const one = sensitiveWords({ id: "j000009", sensitive: { why: "derived", from: ["j000003"], note: "n", files: ["tree/Users/x/vault.kdbx"] } });
  assert.equal(one, "1 of its output files is sensitive (out/tree/Users/x/vault.kdbx): byte for byte the sensitive output of j000003. An entry citing that file, or the job's whole output, is recorded sensitive, a job reading it seals sensitive output too, and a redacted package withholds it; the rest of what it sealed, and its logs, are not sensitive. Say what that file shows without the value.");
  assert.doesNotMatch(one, /Its outputs are sensitive/);
  const many = sensitiveWords({ id: "j000009", sensitive: { why: "derived", from: ["j000003", "j000004"], note: "n", files: ["a", "b", "c", "d", "e"] } });
  assert.match(many, /^5 of its output files are sensitive \(out\/a, out\/b, out\/c, and 2 more: its job_committed line names every one\): byte for byte the sensitive output of j000003, j000004\. An entry citing one of those files, or the job's whole output, is recorded sensitive/);
  assert.match(many, /the rest of what it sealed, and its logs, are not sensitive\. Say what those files show without the value\.$/);
  // An empty list is not a mark file by file.
  assert.match(sensitiveWords({ id: "j000009", sensitive: { why: "derived", from: ["j000003"], note: "n", files: [] } }), /^Its outputs are sensitive/);
  assert.equal(sensitiveWords({ id: "j000009" }), "");
  // What a seat is shown of the job names the files too.
  const S = sandbox();
  const job = { id: "j000009", attempt: 1, spec: { kind: "command", command: "true", inputs: [], timeout_seconds: 60, network: "off" }, requester: { agent: "a1" }, state: "finished", accepted_at: "t", sensitive: { why: "derived", from: ["j000003"], note: "n", files: ["tree/Users/x/vault.kdbx"] } } as unknown as JobRecord;
  const view = await jobView(S, job);
  assert.deepEqual(view.sensitive_files, ["out/tree/Users/x/vault.kdbx"]);
  assert.equal(view.sensitive, one);
});

test("the metrics and the console read a job_same_as line's count and bytes, not its list: 60 same files of a side file are 60, wholly; and a joined tool call is counted apart from a merged recipe", async () => {
  const S = sandbox();
  tool(S, "extract_all", "import os,sys\nopen(os.path.join(os.environ['OUT'],'tree.txt'),'w').write('x')\n", { output: { type: "string" } });
  const { svc } = service(S);
  await svc.start();
  const write = "python3 -c \"import os\nfor i in range(60):\n  open(os.environ['OUT']+'/file-%03d.dat'%i,'w').write('content %03d'%i)\"";
  const first = ok(await svc.submit("a1", { kind: "command", command: write, inputs: [] }));
  await until(svc, first.job.id);
  // The same 60 files and an empty one: wholly an earlier job's, though the line's count is not every file it sealed.
  const second = ok(await svc.submit("a2", { kind: "command", command: `${write}; : > "$OUT/empty"`, inputs: [] }));
  await until(svc, second.job.id);
  // 60 of 61 files that are not empty: not wholly.
  const third = ok(await svc.submit("a3", { kind: "command", command: `${write}; printf own > "$OUT/own.txt"`, inputs: [] }));
  await until(svc, third.job.id);
  await eventually(() => journal(S).filter((l) => l.type === "job_same_as").length === 2, "both job_same_as lines");
  const call = { kind: "tool" as const, tool: "extract_all", args: { output: "{OUT}" }, inputs: ["input:image.bin"] };
  const t1 = ok(await svc.submit("a1", call));
  await until(svc, t1.job.id);
  assert.equal(ok(await svc.submit("a2", call)).job.id, t1.job.id);
  await svc.stop("over");
  const line = journal(S).find((l) => l.type === "job_same_as" && l.job === second.job.id)!;
  assert.ok((line.same_as as unknown[]).length < 60 && line.files === 60 && typeof line.list === "string", "the line holds a few and the count; the list is the side file");
  const { measureRun } = await import("../scripts/metrics.ts");
  const d = (await measureRun(S)).duplicates;
  assert.deepEqual(d.same_as, { jobs: [second.job.id, third.job.id], files: 120, bytes: 120 * 11, whole: [second.job.id] });
  assert.deepEqual([d.recipe_merged, d.tool_joined], [0, 1]);
  const { readStoreJobs } = await import("../scripts/ui/store-jobs.ts");
  const row = (await readStoreJobs(S)).jobs.find((j) => j.id === second.job.id)!;
  assert.deepEqual(row.same_as_total, { files: 60, bytes: 60 * 11, list: `store/jobs/${second.job.id}/same_as.jsonl`, list_sha256: line.list_sha256, jobs: [{ job: first.job.id, files: 60, bytes: 60 * 11 }] });
  assert.equal(row.same_as.length, (line.same_as as unknown[]).length, "the row carries the line's own entries, not the list");
  assert.equal((await readStoreJobs(S)).jobs.find((j) => j.id === first.job.id)!.same_as_total, null);
});
