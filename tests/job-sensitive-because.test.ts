/**
 * Why a job is sensitive is on the record (docs/adr/0016, docs/protocol.md "Reports, sensitive outputs"):
 *
 * - `job_committed.sensitive.because` names, for a derived job, each sensitive job and the way (`declared`, `digest`,
 *   `generation`, `alias`, `named_in_text`, `same_bytes`) with the path that matched;
 * - a job that declared no scope and names a sensitive job RUNS: `job_started.scope.auto_declared` records the
 *   dependency, `scope.could_read_sensitive` the sensitive jobs its mounts let it read, `sensitive_at_start` that it is
 *   already derived; nothing is refused and nothing is hidden;
 * - `jobSensitivity(running)` gives the answer a job that has not sealed yet will get;
 * - a `similar` entry says when the other job's outputs are sensitive.
 */
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { mkdir, mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { after, test } from "node:test";
import * as P from "../extensions/protocol.ts";
import { storePaths } from "../scripts/evidence-store.ts";
import { JobService, type JobRecord } from "../scripts/job-service.ts";
import { derivedBecause, derivedFrom, jobSensitivity } from "../scripts/output-hygiene.ts";
import { listInputs, localWorker } from "./job-service-worker.ts";

const ROOT = join(import.meta.dirname, "..");
const dirs: string[] = [];
after(async () => {
  for (const d of dirs) {
    spawnSync("chmod", ["-R", "u+w", d]);
    await rm(d, { recursive: true, force: true });
  }
});

/** A value a job writes and the run treats as secret: a placeholder, never a real credential. */
const VALUE = "TOKEN-sample-7f3a91";

async function run() {
  const base = await mkdtemp(join(tmpdir(), "because-"));
  dirs.push(base);
  const S = join(base, "run");
  await P.initSandbox(S, { swarmId: "sbec", agentIds: ["a1", "a2"] });
  for (const d of ["inputs", "tools", "catalog", "work/a1", "work/a2"]) await mkdir(join(S, d), { recursive: true });
  await writeFile(join(S, "inputs", "notes.txt"), "a note\n");
  listInputs(S);
  const svc = new JobService({
    sandbox: S, run: "sbec", image: "img:test", workers: 2, workerCpus: 1, workerMemoryMib: 512, allowHosts: [], openNet: false,
    packDirs: [join(ROOT, "packs", "computer-forensics-base")], forging: false, minFreeMb: 1,
    runWorker: localWorker(), destroyWorker: async () => ({ ok: true }), notify: async () => undefined, identity: async (a) => ({ name: a }),
  });
  await svc.start();
  return { S, svc };
}

async function until(svc: JobService, id: string): Promise<JobRecord> {
  for (let i = 0; i < 1200; i += 1) {
    const j = svc.jobs.get(id);
    if (j && ["committed", "failed", "cancelled"].includes(j.state)) return j;
    await new Promise((r) => setTimeout(r, 50));
  }
  throw new Error(`${id} did not finish`);
}

async function submitted(svc: JobService, who: string, spec: Record<string, unknown>) {
  const r = await svc.submit(who, { kind: "command", timeout_seconds: 60, network: "off", ...spec } as never);
  assert.ok(r.ok, !r.ok ? r.reason : "");
  return { job: await until(svc, r.job.id), answer: r };
}

/** A journal line of a job, waited for: job_committed may land just after the job reads committed. */
async function line(S: string, type: string, job: string): Promise<Record<string, any>> {
  for (let i = 0; i < 200; i++) {
    const journal = await readFile(storePaths(S).journal, "utf8").catch(() => "");
    const found = journal.split("\n").filter(Boolean).map((l) => JSON.parse(l)).find((l) => l.type === type && l.job === job);
    if (found) return found;
    await new Promise((r) => setTimeout(r, 10));
  }
  throw new Error(`no ${type} line for ${job}`);
}

test("the six ways a job is made from a sensitive output are told apart, with the path that matched; j3 is not j30", () => {
  const sensitive = new Set(["j000003"]);
  const SHA = "a".repeat(64);
  const at = (objects: Array<{ path: string; sha256?: string }> | null, text = "") => derivedBecause({ objects, text, sensitive, contentJob: (s) => (s === SHA ? "j000003" : null), generationJob: (g) => (g === "g000002" ? "j000003" : null), aliasJob: (a) => (a === "vault" ? "j000003" : null) });
  assert.deepEqual(at([{ path: "store/jobs/j000003/out/x" }]), [{ from: "j000003", how: "declared", object: "store/jobs/j000003/out/x" }]);
  assert.deepEqual(at([{ path: "store/jobs/j000003/out/x", sha256: SHA }]).map((b) => b.how), ["declared"], "a file declared by its path is not also told as its digest");
  assert.deepEqual(at([{ path: "inputs/disk.E01", sha256: SHA }]), [{ from: "j000003", how: "digest", object: "inputs/disk.E01" }], "the same bytes, wherever they sit");
  assert.deepEqual(at([{ path: `store/blobs/${SHA}` }]).map((b) => b.how), ["digest"]);
  assert.deepEqual(at([{ path: "catalog/gen/g000002/members.tsv" }]), [{ from: "j000003", how: "generation", object: "catalog/gen/g000002/members.tsv" }]);
  assert.deepEqual(at([{ path: "catalog/vault/filelist.txt" }]), [{ from: "j000003", how: "alias", object: "catalog/vault/filelist.txt" }]);
  assert.deepEqual(at(null, "python3 read.py store/jobs/j000003/out/key --all > o.txt"), [{ from: "j000003", how: "named_in_text", object: "store/jobs/j000003/out/key" }], "the store path the text held");
  assert.deepEqual(at(null, "echo j000003"), [{ from: "j000003", how: "named_in_text", object: "j000003" }], "the id, when the text names no path");
  assert.deepEqual(at(null, "echo j0000031 store/jobs/j0000031/out/x"), [], "an id inside a longer id is not the job");
  assert.deepEqual(at([{ path: "inputs/x" }], "echo j000003"), [], "a declared scope is held to what it declared, not to its words");
  // Several ways for one job are all said, once each; derivedFrom still gives the ids.
  const both = at([{ path: "store/jobs/j000003/out/x" }, { path: "catalog/vault/f", sha256: SHA }]);
  assert.deepEqual(both.map((b) => [b.from, b.how]), [["j000003", "alias"], ["j000003", "declared"], ["j000003", "digest"]]);
  assert.deepEqual(derivedFrom({ objects: [{ path: "store/jobs/j000003/out/x" }, { path: "inputs/d", sha256: SHA }], text: "", sensitive, contentJob: (s) => (s === SHA ? "j000003" : null), generationJob: () => null, aliasJob: () => null }), ["j000003"]);
});

test("a job with no scope that names a sensitive job's output RUNS; the dependency is recorded when it starts and why when it seals", async () => {
  const { S, svc } = await run();
  const { job: secret } = await submitted(svc, "a1", { command: `printf '%s' '${VALUE}' > "$OUT/value.txt"`, inputs: [], secret_output: true });
  assert.equal(secret.sensitive?.why, "secret_output");
  assert.equal(secret.sensitive?.because, undefined, "a secret_output job is not derived: nothing to give a reason for");

  const { job, answer } = await submitted(svc, "a2", { command: `wc -c store/jobs/${secret.id}/out/value.txt > "$OUT/count.txt"`, inputs: ["all"] });
  assert.equal(job.status, "ok", "it ran: nothing was refused");
  assert.ok(answer.ok);
  assert.equal(job.outputs?.files, 1);
  // At the seal: why it is sensitive.
  assert.deepEqual(job.sensitive?.because, [{ from: secret.id, how: "named_in_text", object: `store/jobs/${secret.id}/out/value.txt` }]);
  const committed = await line(S, "job_committed", job.id);
  assert.deepEqual(committed.sensitive.because, [{ from: secret.id, how: "named_in_text", object: `store/jobs/${secret.id}/out/value.txt` }]);
  assert.deepEqual([committed.sensitive.why, committed.sensitive.from], ["derived", [secret.id]]);
  // At the start: the dependency auto-declared, the sensitive outputs it could read, and that it was derived from the start.
  const started = await line(S, "job_started", job.id);
  assert.deepEqual(started.scope.auto_declared, [{ from: secret.id, how: "named_in_text", matched: `store/jobs/${secret.id}/out/value.txt` }]);
  assert.deepEqual(started.scope.could_read_sensitive, [secret.id]);
  assert.equal(started.scope.kind, "all");
  assert.deepEqual([started.sensitive_at_start.why, started.sensitive_at_start.from], ["derived", [secret.id]]);
  // The job's projection says the same, and a restarted service reads it back from the journal.
  const proj = JSON.parse(await readFile(join(storePaths(S).jobs, job.id, "job.json"), "utf8")) as JobRecord;
  assert.deepEqual(proj.scope?.auto_declared, started.scope.auto_declared);
  assert.deepEqual(proj.sensitive?.because, job.sensitive?.because);
  await svc.stop("test over");
});

test("a job that names nothing sensitive is not sensitive and has no reason; with no scope it records which sensitive outputs it could read", async () => {
  const { S, svc } = await run();
  // Before any sensitive job exists there is nothing to list.
  const { job: early } = await submitted(svc, "a2", { command: `echo early > "$OUT/e.txt"`, inputs: ["all"] });
  const earlyStart = await line(S, "job_started", early.id);
  assert.equal(earlyStart.scope.could_read_sensitive, undefined);
  assert.equal(earlyStart.scope.auto_declared, undefined);
  assert.equal(earlyStart.sensitive_at_start, undefined);

  const { job: secret } = await submitted(svc, "a1", { command: `printf '%s' '${VALUE}' > "$OUT/value.txt"`, inputs: [], secret_output: true });
  const { job: other } = await submitted(svc, "a2", { command: `echo unrelated > "$OUT/u.txt"`, inputs: ["all"] });
  assert.equal(other.sensitive, undefined);
  assert.equal((await line(S, "job_committed", other.id)).sensitive, undefined);
  const started = await line(S, "job_started", other.id);
  assert.deepEqual(started.scope.could_read_sensitive, [secret.id], "maybe: its mounts let it read the sensitive output; it named nothing");
  assert.equal(started.scope.auto_declared, undefined);
  assert.equal(started.sensitive_at_start, undefined);

  // A job on a declared scope reads what it declared: it could read no more, and the list is not written.
  const { job: declared } = await submitted(svc, "a2", { command: `cat inputs/notes.txt > "$OUT/n.txt"`, inputs: ["input:notes.txt"] });
  const dStart = await line(S, "job_started", declared.id);
  assert.equal(dStart.scope.kind, "declared");
  assert.equal(dStart.scope.could_read_sensitive, undefined);
  assert.equal(dStart.scope.auto_declared, undefined);
  await svc.stop("test over");
});

test("a declared scope is `declared`, a work copy is `digest`, the same bytes written by another job are `same_bytes`, and a chain carries", async () => {
  const { S, svc } = await run();
  const { job: secret } = await submitted(svc, "a1", { command: `printf '%s' '${VALUE}' > "$OUT/value.txt"`, inputs: [], secret_output: true });
  const byPath = (await submitted(svc, "a2", { command: `echo d > "$OUT/d.txt"`, inputs: [`job:${secret.id}/value.txt`] })).job;
  assert.deepEqual(byPath.sensitive?.because, [{ from: secret.id, how: "declared", object: `store/jobs/${secret.id}/out/value.txt` }]);
  const dStart = await line(S, "job_started", byPath.id);
  assert.equal(dStart.scope.auto_declared, undefined, "a declared dependency is declared, not auto-declared");
  assert.deepEqual([dStart.sensitive_at_start.why, dStart.sensitive_at_start.because[0].how], ["derived", "declared"], "derived from its start");

  await writeFile(join(S, "work", "a1", "notes.bin"), VALUE);
  const byCopy = (await submitted(svc, "a2", { command: `wc -c work/a1/notes.bin > "$OUT/n.txt"`, inputs: ["work/a1/notes.bin"] })).job;
  assert.deepEqual(byCopy.sensitive?.because, [{ from: secret.id, how: "digest", object: "work/a1/notes.bin" }]);

  const same = (await submitted(svc, "a2", { command: `printf '%s' '${VALUE}' > "$OUT/copy.txt"`, inputs: [] })).job;
  assert.deepEqual(same.sensitive?.because, [{ from: secret.id, how: "same_bytes", object: "copy.txt" }], "its own sealed file, byte for byte what the sensitive job wrote");
  assert.equal((await line(S, "job_started", same.id)).sensitive_at_start, undefined, "nothing but the bytes made it derived: not known until it sealed");

  const chained = (await submitted(svc, "a1", { command: `echo again > "$OUT/a.txt"`, inputs: [`job:${byPath.id}`] })).job;
  assert.deepEqual(chained.sensitive?.because?.map((b) => [b.from, b.how]), [[byPath.id, "declared"]]);
  await svc.stop("test over");
});

test("a job that is both secret_output and names a sensitive job keeps its own sensitivity and still records the dependency", async () => {
  const { S, svc } = await run();
  const { job: secret } = await submitted(svc, "a1", { command: `printf '%s' '${VALUE}' > "$OUT/value.txt"`, inputs: [], secret_output: true });
  const { job } = await submitted(svc, "a2", { command: `wc -c store/jobs/${secret.id}/out/value.txt > "$OUT/c.txt"`, inputs: ["all"], secret_output: true });
  assert.equal(job.sensitive?.why, "secret_output");
  const started = await line(S, "job_started", job.id);
  assert.deepEqual(started.scope.auto_declared?.map((a: { from: string }) => a.from), [secret.id]);
  assert.equal(started.sensitive_at_start, undefined, "its sensitivity is its own, not derived");
  await svc.stop("test over");
});

test("jobSensitivity(running) gives the answer a job that has not sealed will get, from what it declared or its text", async () => {
  const { S, svc } = await run();
  const { job: secret } = await submitted(svc, "a1", { command: `printf '%s' '${VALUE}' > "$OUT/value.txt"`, inputs: [], secret_output: true });
  await svc.stop("test over");
  const spec = (s: Record<string, unknown>) => ({ id: "j999999", spec: s as never });
  // No scope manifest yet: what it declared counts as named, but only while it is running.
  assert.equal(await jobSensitivity(S, spec({ command: "true", inputs: [`job:${secret.id}/value.txt`] })), null);
  const running = await jobSensitivity(S, spec({ command: "true", inputs: [`job:${secret.id}/value.txt`] }), { running: true });
  assert.deepEqual([running?.why, running?.from, running?.because?.[0]?.how], ["derived", [secret.id], "named_in_text"]);
  assert.equal(await jobSensitivity(S, spec({ command: "true", inputs: ["input:notes.txt"] }), { running: true }), null);
  // Its own flag first.
  assert.equal((await jobSensitivity(S, spec({ command: "true", secret_output: true }), { running: true }))?.why, "secret_output");
  // A file it sealed that is the sensitive output's bytes: only with `outputs`, which a running job has none of.
  const files = JSON.parse(await readFile(join(storePaths(S).jobs, secret.id, "manifest.json"), "utf8")).files as Array<{ sha256: string }>;
  assert.equal(await jobSensitivity(S, spec({ command: "true", inputs: [] }), { running: true }), null);
  assert.deepEqual((await jobSensitivity(S, spec({ command: "true", inputs: [] }), { outputs: [{ sha256: files[0].sha256, path: "x.txt" }] }))?.because, [{ from: secret.id, how: "same_bytes", object: "x.txt" }]);
});

test("a similar job's entry says when its outputs are sensitive; the sizes and names are as for any other", async () => {
  const { svc } = await run();
  // Not byte for byte the input: a job that read bytes a sensitive job wrote is itself derived, and the plain case below must stay plain.
  const cmd = `cat inputs/notes.txt > "$OUT/o.txt"; echo extra >> "$OUT/o.txt"`;
  const first = await submitted(svc, "a2", { command: cmd, inputs: ["input:notes.txt"], secret_output: true });
  assert.equal(first.job.sensitive?.why, "secret_output");
  const second = await submitted(svc, "a1", { command: cmd, inputs: ["input:notes.txt"] });
  assert.equal(second.answer.ok && second.answer.similar?.length, 1);
  const sim = second.answer.ok ? second.answer.similar![0] : null;
  assert.equal(sim?.job, first.job.id);
  assert.equal(sim?.sensitive, true);
  assert.deepEqual(sim?.outputs, { files: 1, bytes: 13, path: `store/jobs/${first.job.id}/out` }, "nothing about the other job is withheld");
  // And the plain case: a similar job that is not sensitive says nothing of it.
  const third = await submitted(svc, "a2", { command: `cat inputs/notes.txt | wc -c > "$OUT/p.txt"`, inputs: ["input:notes.txt"] });
  const fourth = await submitted(svc, "a1", { command: `cat inputs/notes.txt | head > "$OUT/q.txt"`, inputs: ["input:notes.txt"] });
  const plain = fourth.answer.ok ? fourth.answer.similar?.find((s) => s.job === third.job.id) : null;
  assert.ok(plain, "the plain job is similar");
  assert.equal(plain.sensitive, undefined);
  await svc.stop("test over");
});
