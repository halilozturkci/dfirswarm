/**
 * The derived catalogue, on by default (decided after the BelkaCTF #6 trial
 * with Fable and Codex): what jobs make is offered to the derived recipes by
 * content, in the lowest lane, the largest objects first, within a rolling
 * budget and two ceilings, nothing dropped; a pass's answers are read
 * whatever its status; a restart rebuilds what waits; a complete catalogue
 * of a readable form is linked to the partial one. The worker is the local
 * stand-in (tests/job-service-worker.ts).
 */
import test from "node:test";
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { chmodSync, existsSync, mkdirSync, mkdtempSync, readFileSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { DERIVED, JobService, type DerivedLimits, type JobRecord, type JobServiceOptions } from "../scripts/job-service.ts";
import { checkStore, storePaths, verifyJournalText, type JournalLine } from "../scripts/evidence-store.ts";
import { localWorker } from "./job-service-worker.ts";
import type { WorkerSpec } from "../scripts/vm.ts";

const ROOT = join(import.meta.dirname, "..");
const CFB = join(ROOT, "packs", "computer-forensics-base");

function sandbox(inputs: Array<{ path: string; sha256: string }> = []): string {
  const S = join(mkdtempSync(join(tmpdir(), "derived-")), "run");
  for (const d of ["inputs", "tools", "catalog", "work/a1"]) mkdirSync(join(S, d), { recursive: true });
  writeFileSync(join(S, "inputs.json"), JSON.stringify({ files: inputs }));
  return S;
}

function service(S: string, limits: Partial<DerivedLimits> = {}, extra: Partial<JobServiceOptions> = {}) {
  const posts: Array<[string, string]> = [];
  const svc = new JobService({
    sandbox: S, run: "s000000", image: "img:test", workers: 2, workerCpus: 1, workerMemoryMib: 512, allowHosts: [], openNet: false,
    packDirs: [CFB], forging: false, minFreeMb: 1, derived: true, derivedLimits: limits,
    runWorker: localWorker(), destroyWorker: async () => ({ ok: true }),
    notify: async (to, body) => { posts.push([to, body]); }, identity: async (a) => ({ name: `${a}-name` }),
    ...extra,
  });
  return { svc, posts };
}

const lines = (S: string): JournalLine[] => verifyJournalText(readFileSync(storePaths(S).journal, "utf8")).lines;
const of = (S: string, type: string) => lines(S).filter((l) => l.type === type);

async function eventually(ok: () => boolean, what: string, ms = 30000): Promise<void> {
  const end = Date.now() + ms;
  while (!ok()) {
    if (Date.now() > end) throw new Error(`not within ${ms} ms: ${what}`);
    await new Promise((r) => setTimeout(r, 50));
  }
}

async function until(svc: JobService, id: string): Promise<JobRecord> {
  await eventually(() => ["committed", "failed", "cancelled"].includes(svc.jobs.get(id)?.state ?? ""), `job ${id} done`);
  return svc.jobs.get(id)!;
}

function zipCommand(files: Array<[string, number]>): string {
  const body = files.map(([f, n], i) => `with zipfile.ZipFile('$OUT/${f}','w') as z: z.writestr('m.txt', ('y${i}-'*${n}))`).join("\n");
  return `python3 - <<'PY'\nimport zipfile\n${body.replaceAll("$OUT", "' + __import__('os').environ['OUT'] + '")}\nPY`;
}

function tarCommand(file: string, cut = false): string {
  return `python3 - <<'PY'\nimport tarfile,io,os\np=os.environ['OUT']+'/${file}'\nwith tarfile.open(p,'w') as t:\n  for k in range(3):\n    i=tarfile.TarInfo('f%d.txt'%k); d=b'x'*4000; i.size=len(d); t.addfile(i,io.BytesIO(d))\n${cut ? "b=open(p,'rb').read(); open(p,'wb').write(b[:6000])\n" : ""}PY`;
}

test("a tar a job makes is offered by content, detected and catalogued in the derived lane, and a complete catalogue is told to all", async () => {
  const S = sandbox();
  const { svc, posts } = service(S);
  await svc.start();
  const r = await svc.submit("a1", { kind: "command", command: tarCommand("inner.tar"), inputs: [] });
  assert.ok(r.ok);
  await until(svc, r.job.id);
  await eventually(() => of(S, "generation_committed").length > 0, "a generation");
  const gen = of(S, "generation_committed")[0];
  assert.equal(gen.trigger, "derived");
  assert.equal((gen.target as { ref: string }).ref, `job:${r.job.id}/inner.tar`);
  assert.match(String((gen.target as { sha256?: string }).sha256), /^[0-9a-f]{64}$/, "the object is on the record by content");
  const recipeJob = svc.jobs.get(String(gen.job))!;
  assert.equal(recipeJob.requester.agent, DERIVED, "the derived lane runs it");
  assert.equal(recipeJob.spec.parent, r.job.id, "its parent is the job that made the object");
  assert.equal(recipeJob.spec.network, "allowlist", "a derived recipe gets the run's allowlist, as the kickoff's do");
  const detect = [...svc.jobs.values()].find((j) => j.spec.kind === "detect")!;
  assert.equal(detect.requester.agent, DERIVED);
  assert.deepEqual(detect.spec.pairs, [{ t: 0, recipe: "computer-forensics-base/archive-members" }], "only the recipes whose prefilter matched are asked");
  assert.ok(existsSync(join(storePaths(S).jobs, detect.id, "out", "probes", "0-computer-forensics-base_archive-members.out")), "each probe's whole output is kept");
  await eventually(() => posts.some(([to, b]) => to === "all" && /catalogued on its own — complete/.test(b)), `told to all: ${JSON.stringify(posts)}`);
  await svc.stop("over");
});

test("offers are by content: small and plain files are not offered, a zip with no name ending is, the same bytes again and a copy of an input are skipped, named", async () => {
  const inputZip = spawnSync("python3", ["-c", "import zipfile,io,sys,hashlib\nb=io.BytesIO()\nwith zipfile.ZipFile(b,'w') as z: z.writestr('k.txt','input')\nopen(sys.argv[1],'wb').write(b.getvalue())\nprint(hashlib.sha256(b.getvalue()).hexdigest())", join(tmpdir(), `in-${process.pid}.zip`)], { encoding: "utf8" }).stdout.trim();
  const S = sandbox([{ path: "inputs/in.zip", sha256: inputZip }]);
  writeFileSync(join(S, "inputs", "in.zip"), readFileSync(join(tmpdir(), `in-${process.pid}.zip`)));
  const { svc } = service(S);
  await svc.start();
  const a = await svc.submit("a1", { kind: "command", command: `printf hi > "$OUT/tiny.bin"; head -c 5000 /dev/zero | tr '\\0' a > "$OUT/notes.txt"; cp inputs/in.zip "$OUT/copy-of-input"; ${zipCommand([["blob", 100]]).replace("'$OUT/blob'", "os.environ['OUT']+'/blob'")}`, inputs: [] });
  assert.ok(a.ok);
  await until(svc, a.job.id);
  await eventually(() => of(S, "derived_offered").length === 1, "the first offer");
  const first = of(S, "derived_offered")[0] as JournalLine & { offered: Array<{ path: string; recipes: string[] }>; skipped: Array<{ path: string; same_as: string }>; filtered: number };
  assert.deepEqual(first.offered.map((o) => o.path), ["blob"], "the zip is offered by its magic, with no name ending");
  assert.deepEqual(first.offered[0].recipes, ["computer-forensics-base/archive-members"]);
  assert.deepEqual(first.skipped.map((x) => [x.path, x.same_as]), [["copy-of-input", "input:in.zip"]], "a copy of an input is not a new object");
  assert.equal(first.filtered, 2, "tiny.bin and notes.txt meet no recipe's measure");
  const b = await svc.submit("a1", { kind: "command", command: `cp store/jobs/${a.job.id}/out/blob "$OUT/same-bytes.zip"`, inputs: [] });
  await until(svc, b.ok ? b.job.id : "");
  await eventually(() => of(S, "derived_offered").length === 2, "the second offer");
  const second = of(S, "derived_offered")[1] as JournalLine & { offered: unknown[]; skipped: Array<{ path: string; same_as: string }> };
  assert.equal(second.offered.length, 0);
  assert.match(second.skipped[0].same_as, /^(offered|answered|catalogued) earlier$/, "the same bytes from another job are the same object");
  await svc.stop("over");
});

test("the largest objects go first, so many pairs a pass, and nothing offered is dropped", async () => {
  const S = sandbox();
  const { svc } = service(S, { pairsPerPass: 4 });
  await svc.start();
  const files: Array<[string, number]> = Array.from({ length: 10 }, (_, i) => [`f${i}.zip`, 50 + i * 400]);
  const r = await svc.submit("a1", { kind: "command", command: zipCommand(files).replaceAll("'$OUT/", "os.environ['OUT']+'/"), inputs: [] });
  assert.ok(r.ok);
  await until(svc, r.job.id);
  await eventually(() => of(S, "detect_answered").reduce((n, l) => n + ((l.rows as unknown[]) ?? []).length, 0) === 10, "every object answered", 60000);
  const passes = of(S, "detect_answered");
  assert.equal(passes.length, 3, "10 objects at 4 pairs a pass");
  const firstRefs = (passes[0].rows as Array<{ ref: string }>).map((x) => x.ref);
  assert.deepEqual(firstRefs.sort(), ["f6.zip", "f7.zip", "f8.zip", "f9.zip"].map((f) => `job:${r.job.id}/${f}`).sort(), "the largest first");
  await svc.stop("over");
});

test("a pass that stopped keeps the answers it gave; what it did not answer waits once more, then is named unanswered", async () => {
  const S = sandbox();
  const local = localWorker();
  // A derived pass that never answers for b.zip, and is stopped at its limit.
  const runWorker = async (spec: WorkerSpec) => {
    const r = await local(spec);
    const ctl = spec.mounts.find((m) => m.guest === "/job")!.host;
    const out = spec.mounts.find((m) => m.host.includes(".staging/") && m.host.endsWith("/out"))!.host;
    if (existsSync(join(ctl, "detect.tsv")) && existsSync(join(out, "detect.tsv"))) {
      const b = [0, 1, 2].find((i) => existsSync(join(ctl, `target-${i}.json`)) && readFileSync(join(ctl, `target-${i}.json`), "utf8").includes("b.zip"));
      const kept = readFileSync(join(out, "detect.tsv"), "utf8").split("\n").filter((l) => l && !l.startsWith(`${b}\t`));
      writeFileSync(join(out, "detect.tsv"), kept.length ? `${kept.join("\n")}\n` : "");
      writeFileSync(join(ctl, "exit"), "124\n");
    }
    return r;
  };
  const { svc } = service(S, {}, { runWorker });
  await svc.start();
  const r = await svc.submit("a1", { kind: "command", command: zipCommand([["a.zip", 900], ["b.zip", 500]]).replaceAll("'$OUT/", "os.environ['OUT']+'/"), inputs: [] });
  await until(svc, r.ok ? r.job.id : "");
  await eventually(() => of(S, "detect_unanswered").length === 1, "the pair left twice is named", 60000);
  const passes = of(S, "detect_answered");
  assert.equal(passes[0].status, "timed_out", "the pass stopped at its limit");
  assert.equal((passes[0].rows as unknown[]).length, 1, "and what it answered is read");
  assert.equal(passes.length, 2, "b.zip was asked once more, alone");
  assert.equal((passes[0].unanswered as unknown[]).length, 1);
  assert.equal(of(S, "detect_unanswered")[0].ref, `job:${r.ok ? r.job.id : ""}/b.zip`, "the one never answered, asked twice, named");
  await eventually(() => of(S, "generation_committed").length === 1, "the answered one is catalogued");
  await svc.stop("over");
});

test("the derived lane waits while an agent's job waits, and runs one job at a time", async () => {
  const S = sandbox();
  const { svc } = service(S, {}, { workers: 1 });
  await svc.start();
  const maker = await svc.submit("a1", { kind: "command", command: tarCommand("t.tar"), inputs: [] });
  const busy = await svc.submit("a1", { kind: "command", command: "sleep 1", inputs: [] });
  assert.ok(maker.ok && busy.ok);
  const b = await until(svc, busy.job.id);
  await eventually(() => [...svc.jobs.values()].some((j) => j.spec.kind === "detect" && j.state === "committed"), "the pass ran");
  const detect = [...svc.jobs.values()].find((j) => j.spec.kind === "detect")!;
  assert.ok(Date.parse(detect.started_at!) >= Date.parse(b.finished_at!), "the pass started after the agent's waiting job");
  await svc.stop("over");
});

test("at the run's generations ceiling the lane stops, says so to all once, and keeps what waits named", async () => {
  const S = sandbox();
  const { svc, posts } = service(S, { generationsMax: 1 });
  await svc.start();
  const r = await svc.submit("a1", { kind: "command", command: zipCommand([["a.zip", 900], ["b.zip", 500]]).replaceAll("'$OUT/", "os.environ['OUT']+'/"), inputs: [] });
  await until(svc, r.ok ? r.job.id : "");
  await eventually(() => of(S, "generation_committed").length === 1, "one generation");
  // The next object is asked about only once the lane may run again: it may not.
  const later = await svc.submit("a1", { kind: "command", command: tarCommand("later.tar"), inputs: [] });
  await until(svc, later.ok ? later.job.id : "");
  await eventually(() => of(S, "derived_bounded").length === 1, "the ceiling is journalled");
  const bounded = of(S, "derived_bounded")[0];
  assert.deepEqual([bounded.bound, bounded.spent, bounded.cap], ["generations", 1, 1]);
  assert.ok(Number(bounded.pending) + Number(bounded.queued) >= 1, `what waits is counted: ${JSON.stringify(bounded)}`);
  await eventually(() => posts.filter(([to, b]) => to === "all" && b.startsWith("The derived catalogue has reached its 1 generations")).length === 1, "told to all");
  await new Promise((res) => setTimeout(res, 300));
  assert.equal(of(S, "derived_bounded").length, 1, "once");
  assert.equal(of(S, "generation_committed").length, 1, "and no more generations");
  await svc.stop("over");
});

test("the rolling budget defers the lane, said, and it resumes when the window has room; a restart rebuilds what waits", async () => {
  const S = sandbox();
  // No budget at all: the offer waits.
  const first = service(S, { windowSeconds: 0 });
  await first.svc.start();
  const r = await first.svc.submit("a1", { kind: "command", command: tarCommand("x.tar"), inputs: [] });
  await until(first.svc, r.ok ? r.job.id : "");
  await eventually(() => of(S, "derived_deferred").length === 1, "the wait is journalled");
  assert.equal(of(S, "detect_answered").length, 0);
  await first.svc.stop("over");
  // A new service with a budget: what waited is rebuilt from the journal and done.
  const second = service(S);
  await second.svc.start();
  await eventually(() => of(S, "generation_committed").length === 1, "catalogued after the restart");
  assert.equal(of(S, "derived_offered").length, 1, "offered once, not again on restart");
  await second.svc.stop("over");
});

test("a complete catalogue of an object made from one with a partial catalogue is linked to it as its readable form", async () => {
  const S = sandbox();
  const { svc } = service(S);
  await svc.start();
  const cut = await svc.submit("a1", { kind: "command", command: tarCommand("cut.tar", true), inputs: [] });
  await until(svc, cut.ok ? cut.job.id : "");
  await eventually(() => of(S, "generation_committed").length === 1, "the partial one");
  const partial = of(S, "generation_committed")[0];
  assert.equal(partial.status, "partial");
  const whole = await svc.submit("a1", { kind: "command", command: `test -s store/jobs/${cut.ok ? cut.job.id : ""}/out/cut.tar && ${tarCommand("whole.tar")}`, inputs: [] });
  await until(svc, whole.ok ? whole.job.id : "");
  await eventually(() => of(S, "generation_related").length === 1, "the link");
  const rel = of(S, "generation_related")[0];
  assert.equal(rel.generation, partial.generation);
  assert.equal(rel.readable, of(S, "generation_committed")[1].generation);
  // The link is published as a revision of its own, just after the line.
  const readableIn = () => {
    const revs = of(S, "revision_published");
    const index = JSON.parse(readFileSync(join(S, "catalog", "revisions", String(revs.at(-1)!.revision), "index.json"), "utf8")) as { generations: Array<{ id: string; readable_form?: string }> };
    return index.generations.find((g) => g.id === partial.generation)?.readable_form;
  };
  await eventually(() => readableIn() === rel.readable, "the revision index says so");
  await svc.stop("over");
});

test("the readable link follows content: the same bytes remade under another job still lead back to the partial catalogue", async () => {
  const S = sandbox();
  const { svc } = service(S);
  await svc.start();
  const first = await svc.submit("a1", { kind: "command", command: tarCommand("cut.tar", true), inputs: [] });
  await until(svc, first.ok ? first.job.id : "");
  await eventually(() => of(S, "generation_committed").length === 1, "the partial one");
  const partial = of(S, "generation_committed")[0];
  // Another agent makes the same bytes without naming the first job (run s8c228e: two jobs made one vault.raw).
  const again = await svc.submit("a1", { kind: "command", command: tarCommand("cut.tar", true), inputs: [] });
  await until(svc, again.ok ? again.job.id : "");
  await eventually(() => of(S, "derived_offered").length === 2, "the second offer");
  assert.equal((of(S, "derived_offered")[1].skipped as unknown[]).length, 1, "known by content, not catalogued twice");
  const whole = await svc.submit("a1", { kind: "command", command: `test -s store/jobs/${again.ok ? again.job.id : ""}/out/cut.tar && ${tarCommand("whole.tar")}`, inputs: [] });
  await until(svc, whole.ok ? whole.job.id : "");
  await eventually(() => of(S, "generation_related").length === 1, "the link, by content");
  assert.equal(of(S, "generation_related")[0].generation, partial.generation);
  await svc.stop("over");
});

test("an agent asking for an object the derived catalogue already has is told where it is, and nothing runs again", async () => {
  const S = sandbox();
  const { svc, posts } = service(S);
  await svc.start();
  const r = await svc.submit("a1", { kind: "command", command: tarCommand("inner.tar"), inputs: [] });
  await until(svc, r.ok ? r.job.id : "");
  await eventually(() => of(S, "generation_committed").length === 1, "the derived catalogue");
  const gen = of(S, "generation_committed")[0];
  // Run s8c228e: the request came 9 s after the derived catalogue and made a second one.
  const asked = await svc.catalogRequest("a2", `job:${r.ok ? r.job.id : ""}/inner.tar`, undefined, "index it for everyone");
  assert.ok(asked.ok);
  await eventually(() => posts.some(([to, body]) => to === "a2" && /already catalogued/.test(body)), "a2 is told");
  const told = posts.find(([to, body]) => to === "a2" && /already catalogued/.test(body))![1];
  assert.match(told, new RegExp(String(gen.generation)));
  assert.equal(of(S, "job_deduplicated").length, 1);
  assert.equal(of(S, "generation_committed").length, 1, "not catalogued twice");
  await svc.stop("over");
});

test("the files of a failed job and of an import are offered too; with the derived catalogue off, nothing is", async () => {
  const S = sandbox();
  const { svc } = service(S);
  await svc.start();
  const failed = await svc.submit("a1", { kind: "command", command: `${tarCommand("f.tar")}\nexit 1`, inputs: [] });
  await until(svc, failed.ok ? failed.job.id : "");
  mkdirSync(join(S, "work", "a1"), { recursive: true });
  spawnSync("python3", ["-c", "import tarfile,io,sys\nwith tarfile.open(sys.argv[1],'w') as t:\n  i=tarfile.TarInfo('a.txt'); d=b'q'*3000; i.size=len(d); t.addfile(i,io.BytesIO(d))", join(S, "work", "a1", "mine.tar")]);
  const imp = await svc.submit("a1", { kind: "import", source: "work/a1/mine.tar" });
  await until(svc, imp.ok ? imp.job.id : "");
  await eventually(() => of(S, "derived_offered").length === 2, "both offered");
  const [a, b] = of(S, "derived_offered");
  assert.equal(a.parent_status, "failed");
  assert.equal(b.job, imp.ok ? imp.job.id : "");
  await svc.stop("over");
  const S2 = sandbox();
  const off = service(S2, {}, { derived: false });
  await off.svc.start();
  const r = await off.svc.submit("a1", { kind: "command", command: tarCommand("t.tar"), inputs: [] });
  await until(off.svc, r.ok ? r.job.id : "");
  await new Promise((res) => setTimeout(res, 300));
  assert.equal(existsSync(storePaths(S2).journal) ? of(S2, "derived_offered").length : 0, 0);
  await off.svc.stop("over");
});

test("custody sums the derived catalogue from its journal lines and holds every revision and generation to the journal", async () => {
  const S = sandbox();
  const { svc } = service(S);
  await svc.start();
  const r = await svc.submit("a1", { kind: "command", command: tarCommand("c.tar"), inputs: [] });
  await until(svc, r.ok ? r.job.id : "");
  await eventually(() => of(S, "generation_committed").length === 1 && of(S, "revision_published").length >= 1, "catalogued and published");
  await svc.stop("over");
  let c = (await checkStore(S))!;
  assert.deepEqual([c.derived.offered, c.derived.skipped, c.derived.detected, c.derived.applied, c.derived.catalogued, c.derived.partial, c.derived.unanswered], [1, 0, 1, 1, 1, 0, 0]);
  assert.equal(c.catalogue.revisions_mismatched.length, 0);
  assert.equal(c.catalogue.generations_verified, 1);
  // A revision's index changed after it was published is named.
  const last = of(S, "revision_published").at(-1)!.revision;
  const dir = join(S, "catalog", "revisions", String(last));
  chmodSync(dir, 0o755);
  chmodSync(join(dir, "index.md"), 0o644);
  writeFileSync(join(dir, "index.md"), "rewritten\n");
  c = (await checkStore(S))!;
  assert.deepEqual(c.catalogue.revisions_mismatched, [`revision ${last}`]);
});
