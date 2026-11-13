/**
 * Reuse hints (scripts/job-reuse.ts, docs/adr/0017): at acceptance, the
 * jobs of other seats doing the same tool or leading command over some of
 * the same objects by digest are named with their lead, state and outputs
 * (`similar`, a job_similar line); an intended reproduction says
 * `independent: true` and is recorded as one; at commit, the files that are
 * an earlier job's output byte for byte are named (`same_as`, a job_same_as
 * line). Nothing is merged, and a restarted service keeps both.
 */
import test from "node:test";
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { mkdirSync, mkdtempSync, readFileSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { JobService, describe, jobView, type JobRecord } from "../scripts/job-service.ts";
import { objectsMatch, opMatch, opOf, rankSimilar, sameAsOf, sameAsView, SAME_AS_SHOWN, similarView, SIMILAR_SHOWN, type Similar } from "../scripts/job-reuse.ts";
import { storePaths } from "../scripts/evidence-store.ts";
import { listInputs, localWorker } from "./job-service-worker.ts";

const ROOT = join(import.meta.dirname, "..");

function sandbox(): string {
  const S = join(mkdtempSync(join(tmpdir(), "reuse-")), "run");
  for (const d of ["inputs/logs", "tools", "catalog", "work/a1", "work/a2", "leads"]) mkdirSync(join(S, d), { recursive: true });
  writeFileSync(join(S, "inputs", "disk.img"), "disk bytes\n".repeat(50));
  writeFileSync(join(S, "inputs", "notes.txt"), "a note\n");
  writeFileSync(join(S, "inputs", "logs", "auth.log"), "a log line\n");
  listInputs(S);
  const body = "import json,sys\nd=json.load(sys.stdin)\nopen(d['output'],'w').write(d['text'])\n";
  mkdirSync(join(S, "tools", "writer"), { recursive: true });
  writeFileSync(join(S, "tools", "writer", "run.py"), body);
  writeFileSync(join(S, "tools", "writer", "manifest.json"), JSON.stringify({ name: "writer", description: "t", params: { output: { type: "string", required: true }, text: { type: "string", required: true } }, runtime: "python3", entry: "run.py", timeout_seconds: 60, by: "t", at: "t", version: 1, sha256: createHash("sha256").update(body).digest("hex") }));
  return S;
}

function service(S: string, leads: Map<string, string> = new Map()) {
  const posts: Array<[string, string]> = [];
  const svc = new JobService({
    sandbox: S, run: "s000000", image: "img:test", workers: 2, workerCpus: 1, workerMemoryMib: 512, allowHosts: [], openNet: false,
    packDirs: [join(ROOT, "packs", "computer-forensics-base")], forging: true, minFreeMb: 1,
    runWorker: localWorker(), destroyWorker: async () => ({ ok: true }),
    notify: async (to, body) => { posts.push([to, body]); }, identity: async (a) => ({ name: `${a}-name` }),
    leadsOf: async (ids) => new Map(ids.filter((id) => leads.has(id)).map((id) => [id, leads.get(id)!])),
  });
  return { svc, posts };
}

async function until(svc: JobService, id: string): Promise<JobRecord> {
  for (let i = 0; i < 400; i += 1) {
    const j = svc.jobs.get(id);
    if (j && (j.state === "committed" || j.state === "failed" || j.state === "cancelled")) return j;
    await new Promise((r) => setTimeout(r, 50));
  }
  throw new Error(`${id} never finished`);
}

const journal = (S: string) => readFileSync(storePaths(S).journal, "utf8").trim().split("\n").map((l) => JSON.parse(l) as Record<string, unknown>);

function ok<T extends { ok: boolean }>(r: T): Extract<T, { ok: true }> {
  assert.ok(r.ok, JSON.stringify(r));
  return r as Extract<T, { ok: true }>;
}

test("an operation is the tool or the leading command word; objects match by digest, by a directory that holds them, or not at all", () => {
  assert.equal(opOf({ kind: "tool", tool: "writer" }), "tool:writer");
  assert.equal(opOf({ kind: "command", command: "cd /tmp && LC_ALL=C strings -n 8 inputs/disk.img" }), "command:strings");
  assert.equal(opOf({ kind: "command", command: "/usr/bin/fls -r inputs/disk.img" }), "command:fls");
  assert.equal(opOf({ kind: "command", command: "$(echo x)" }), null, "no readable word, no operation");
  assert.equal(opOf({ kind: "recipe" }), null);
  const disk = { path: "inputs/disk.img", sha256: "a".repeat(64) };
  const copy = { path: "store/jobs/j000009/out/disk.img", sha256: "a".repeat(64) };
  const log = { path: "inputs/logs/auth.log", sha256: "b".repeat(64) };
  const logs = { path: "inputs/logs", dir: true as const };
  assert.deepEqual(objectsMatch([disk], [copy]), { objects: "same", shared: 1 }, "the same bytes wherever they sit");
  assert.deepEqual(objectsMatch([disk, log], [disk]), { objects: "overlap", shared: 1 });
  assert.deepEqual(objectsMatch([log], [logs]), { objects: "overlap", shared: 1 }, "a file in a directory the other read");
  assert.deepEqual(objectsMatch([logs], [log]), { objects: "overlap", shared: 1 }, "a directory that holds the other's file");
  assert.equal(objectsMatch([disk], [log]), null);
  assert.equal(objectsMatch([], [disk]), null, "no objects, nothing to compare");
  const cmd = (command: string) => ({ kind: "command", command, inputs: [] });
  assert.equal(opMatch(cmd("strings -n 8 x"), cmd("strings -n 8 x"), "command:strings", "command:strings"), "same command");
  assert.equal(opMatch(cmd("strings -a x"), cmd("strings -n 8 x"), "command:strings", "command:strings"), "same leading command");
  assert.equal(opMatch(cmd("fls x"), cmd("strings x"), "command:fls", "command:strings"), null);
  const tl = (args: Record<string, unknown>) => ({ kind: "tool", tool: "writer", args, inputs: [] });
  assert.equal(opMatch(tl({ a: 1, b: 2 }), tl({ b: 2, a: 1 }), "tool:writer", "tool:writer"), "same tool and arguments");
  assert.equal(opMatch(tl({ a: 1 }), tl({ a: 2 }), "tool:writer", "tool:writer"), "same tool");
  assert.equal(opMatch(tl({}), cmd("writer"), "tool:writer", "command:writer"), null, "a tool is not a command of its name");
});

test("similar jobs are ranked and bounded without loss: the closest first, the rest counted and named on the journal", () => {
  const s = (job: string, match: Similar["match"], objects: Similar["objects"], state = "committed", status = "ok"): Similar => ({ job, seat: "a2", state, status, lead: null, objects, shared: 1, match, op: "command:x" });
  const ranked = rankSimilar([s("j000001", "same leading command", "overlap"), s("j000002", "same command", "overlap"), s("j000003", "same leading command", "same"), s("j000004", "same command", "same", "running", ""), s("j000005", "same command", "same")]);
  assert.deepEqual(ranked.map((x) => x.job), ["j000005", "j000004", "j000002", "j000003", "j000001"]);
  const many = Array.from({ length: SIMILAR_SHOWN + 3 }, (_, i) => s(`j${String(i + 1).padStart(6, "0")}`, "same command", "same"));
  const view = similarView("j000100", many, false);
  assert.equal((view.similar as Similar[]).length, SIMILAR_SHOWN);
  assert.equal(view.similar_more, `3 more, every one on the job_similar line for j000100 in store/journal.jsonl`);
  assert.match(String(view.similar_note), /independent: true/);
  assert.match(String(similarView("j000100", many.slice(0, 1), true).similar_note), /independent reproduction/);
  assert.deepEqual(similarView("j000100", [], false), {}, "nothing similar, nothing said");
  const index = new Map([["c".repeat(64), { job: "j000001", file: "a.txt" }]]);
  const files = [
    { path: "copy.txt", path_b64: "", sha256: "c".repeat(64), bytes: 5, mode: 0 },
    { path: "empty.txt", path_b64: "", sha256: "e".repeat(64), bytes: 0, mode: 0 },
    { path: "new.txt", path_b64: "", sha256: "d".repeat(64), bytes: 5, mode: 0 },
  ] as never;
  assert.deepEqual(sameAsOf("j000002", files, index), [{ path: "copy.txt", sha256: "c".repeat(64), bytes: 5, job: "j000001", file: "a.txt" }]);
  assert.deepEqual(sameAsOf("j000001", files, index), [], "a job is not the same as itself");
  const long = Array.from({ length: SAME_AS_SHOWN + 2 }, (_, i) => ({ path: `f${i}`, sha256: "c".repeat(64), bytes: 1, job: "j000001", file: "a.txt" }));
  const sv = sameAsView("j000002", long);
  assert.equal((sv.same_as as unknown[]).length, SAME_AS_SHOWN);
  assert.equal(sv.same_as_more, "2 more, every one on the job_same_as line for j000002 in store/journal.jsonl");
});

test("at acceptance, another seat's job over the same objects with the same command word is named with its lead, state and outputs; nothing is merged", async () => {
  const S = sandbox();
  const leads = new Map<string, string>();
  const { svc } = service(S, leads);
  await svc.start();
  const first = ok(await svc.submit("a2", { kind: "command", command: "strings -n 8 inputs/disk.img > \"$OUT/strings.txt\"", inputs: ["input:disk.img"] }));
  leads.set(first.job.id, "L-4");
  assert.equal(first.similar, undefined);
  await until(svc, first.job.id);
  const second = ok(await svc.submit("a1", { kind: "command", command: "strings -a inputs/disk.img | head", inputs: ["input:disk.img"] }));
  assert.equal(second.similar?.length, 1);
  const sim = second.similar![0];
  assert.deepEqual([sim.job, sim.seat, sim.name, sim.lead, sim.state, sim.status, sim.match, sim.objects, sim.op], [first.job.id, "a2", "a2-name", "L-4", "committed", "ok", "same leading command", "same", "command:strings"]);
  assert.equal(sim.outputs?.path, `store/jobs/${first.job.id}/out`);
  assert.notEqual(second.job.id, first.job.id, "the job is its own, and runs");
  const line = journal(S).find((l) => l.type === "job_similar" && l.job === second.job.id)!;
  assert.deepEqual((line.similar as Similar[]).map((x) => x.job), [first.job.id]);
  assert.equal((line.by as { agent: string }).agent, "a1");
  const accepted = journal(S).find((l) => l.type === "job_accepted" && l.job === second.job.id)!;
  assert.deepEqual(accepted.reuse, { op: "command:strings", objects: [{ path: "inputs/disk.img", sha256: createHash("sha256").update("disk bytes\n".repeat(50)).digest("hex") }] });
  // A different word, or a disjoint object, is not similar; a wider scope overlaps.
  assert.equal(ok(await svc.submit("a1", { kind: "command", command: "fls inputs/disk.img", inputs: ["input:disk.img"] })).similar, undefined);
  assert.equal(ok(await svc.submit("a1", { kind: "command", command: "strings inputs/notes.txt", inputs: ["input:notes.txt"] })).similar, undefined);
  const wide = ok(await svc.submit("a1", { kind: "command", command: "strings inputs/disk.img inputs/notes.txt", inputs: ["input:disk.img", "input:notes.txt"] }));
  assert.deepEqual(wide.similar?.map((x) => [x.job, x.objects, x.shared]), [[first.job.id, "overlap", 1]]);
  // A directory scope and a file inside it.
  ok(await svc.submit("a2", { kind: "command", command: "grep -r fail inputs/logs", inputs: ["input:logs/"] }));
  const inDir = ok(await svc.submit("a1", { kind: "command", command: "grep fail inputs/logs/auth.log", inputs: ["input:logs/auth.log"] }));
  assert.equal(inDir.similar?.[0]?.objects, "overlap");
  await svc.stop("over");
});

test("tools match by name, with the same arguments ranked first; independent: true is recorded, still shown, and kept on the view", async () => {
  const S = sandbox();
  const { svc } = service(S);
  await svc.start();
  const a = ok(await svc.submit("a2", { kind: "tool", tool: "writer", args: { output: "{OUT}/w.txt", text: "one" }, inputs: ["input:notes.txt"] }));
  const b = ok(await svc.submit("a3", { kind: "tool", tool: "writer", args: { output: "{OUT}/w.txt", text: "two" }, inputs: ["input:notes.txt"] }));
  assert.deepEqual(b.similar?.map((x) => x.match), ["same tool"]);
  const c = ok(await svc.submit("a1", { kind: "tool", tool: "writer", args: { output: "{OUT}/w.txt", text: "one" }, inputs: ["input:notes.txt"], independent: true }));
  assert.deepEqual(c.similar?.map((x) => [x.job, x.match]), [[a.job.id, "same tool and arguments"], [b.job.id, "same tool"]]);
  assert.equal(c.job.spec.independent, true);
  const line = journal(S).find((l) => l.type === "job_similar" && l.job === c.job.id)!;
  assert.equal(line.independent, true, "the reproduction is said on the journal");
  assert.equal((journal(S).find((l) => l.type === "job_accepted" && l.job === c.job.id)!.spec as { independent?: boolean }).independent, true);
  assert.match(String(similarView(c.job.id, c.similar!, true).similar_note), /independent reproduction/);
  // Other arguments: the identical call would be answered with the job under way (tests/job-stages.test.ts), and say nothing of the others.
  const d = ok(await svc.submit("a4", { kind: "tool", tool: "writer", args: { output: "{OUT}/w.txt", text: "three" }, inputs: ["input:notes.txt"] }));
  assert.equal(d.similar?.find((x) => x.job === c.job.id)?.independent, true, "a reproduction is named as one to the next seat");
  assert.equal((await jobView(S, c.job)).independent, true);
  // Only a command or a tool is a reproduction: an import says nothing of it.
  writeFileSync(join(S, "work", "a1", "n.txt"), "n\n");
  const imp = ok(await svc.submit("a1", { kind: "import", source: "work/a1/n.txt", independent: true }));
  assert.equal(imp.job.spec.independent, undefined);
  for (const j of [a, b, c, d, imp]) await until(svc, j.job.id);
  await svc.stop("over");
});

test("at commit, files that are an earlier job's output byte for byte are named (never an empty one), on the view, the post and the journal, and kept across a restart", async () => {
  const S = sandbox();
  const { svc } = service(S);
  await svc.start();
  const first = ok(await svc.submit("a1", { kind: "command", command: "printf 'the same bytes' > \"$OUT/x.txt\"; : > \"$OUT/empty\"", inputs: [] }));
  await until(svc, first.job.id);
  const second = ok(await svc.submit("a2", { kind: "command", command: "printf 'the same bytes' > \"$OUT/y.txt\"; printf 'new' > \"$OUT/z.txt\"; : > \"$OUT/empty\"", inputs: [], timeout_seconds: 30 }));
  const done = await until(svc, second.job.id);
  assert.deepEqual(done.same_as?.map((s) => [s.path, s.job, s.file]), [["y.txt", first.job.id, "x.txt"]]);
  const view = await jobView(S, done);
  assert.deepEqual(view.same_as, [{ path: "y.txt", bytes: 14, same_as: `job:${first.job.id}/x.txt` }]);
  assert.match(describe(done), /1 of its files are an earlier job's output byte for byte/);
  // The hint is written after the commit, outside the store's one-at-a-time
  // section (it never holds a commit up): the committed state can be seen
  // a moment before its line is on the journal.
  let line: Record<string, unknown> | undefined;
  for (let i = 0; i < 100 && !line; i += 1) {
    line = journal(S).find((l) => l.type === "job_same_as" && l.job === second.job.id);
    if (!line) await new Promise((r) => setTimeout(r, 50));
  }
  assert.ok(line, "the job_same_as line is on the journal");
  assert.deepEqual(line.same_as, done.same_as);
  assert.equal(journal(S).filter((l) => l.type === "job_same_as").length, 1, "the first job and the empty files say nothing");
  await svc.stop("over");
  // A restarted service reads both back, and builds its index from the manifests.
  const again = service(S).svc;
  await again.start();
  assert.deepEqual(again.jobs.get(second.job.id)?.same_as, done.same_as);
  assert.equal(again.jobs.get(second.job.id)?.reuse?.op, "command:printf");
  const third = ok(await again.submit("a3", { kind: "command", command: "printf 'new' > \"$OUT/again.txt\"", inputs: [] }));
  const t = await until(again, third.job.id);
  assert.deepEqual(t.same_as?.map((s) => [s.path, s.job, s.file]), [["again.txt", second.job.id, "z.txt"]]);
  await again.stop("over");
});
