/**
 * The cloud pack's three tools take `write_values`, which writes the originals of what they withheld to a 0600 file under
 * $OUT. Each manifest declares `"secret_output": {"when_args": ["write_values"]}`, so the job service runs a job with that
 * argument as secret output whether or not the agent set the flag: the file is sealed sensitive, a redacted package
 * withholds it, and a read of it is recorded as a read of sensitive output. The tool, in turn, writes nothing in a run
 * whose SECRET_OUTPUT is not 1 (tests/pack-cloud-shared.test.ts holds that refusal for a direct run; this suite holds the
 * harness side, modelled on tests/secret-output-declaration.test.ts).
 */
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { existsSync } from "node:fs";
import { mkdir, mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { after, test } from "node:test";
import * as P from "../extensions/protocol.ts";
import { storePaths } from "../scripts/evidence-store.ts";
import { describe, JobService, jobView } from "../scripts/job-service.ts";
import { redactPackage } from "../scripts/package-tools.ts";
import { localWorker } from "./job-service-worker.ts";
import type { WorkerSpec } from "../scripts/vm.ts";
import { ALICE, ct, trail } from "./cloud-pack-harness.ts";

const ROOT = join(import.meta.dirname, "..");
const CLOUD = join(ROOT, "packs", "cloud-forensics");
/** A value a run withholds and the job treats as secret: a placeholder, never a real credential. */
const SECRET = "Hunter2-correct-horse-9";

const dirs: string[] = [];
after(async () => {
  for (const d of dirs) {
    spawnSync("chmod", ["-R", "u+w", d]);
    await rm(d, { recursive: true, force: true });
  }
});

async function make() {
  const base = await mkdtemp(join(tmpdir(), "cloudsec-"));
  dirs.push(base);
  const S = join(base, "run");
  await P.initSandbox(S, { swarmId: "cloudsec", agentIds: ["a1", "a2"] });
  for (const d of ["inputs", "tools", "catalog", "work/a1"]) await mkdir(join(S, d), { recursive: true });
  await writeFile(join(S, "inputs.json"), JSON.stringify({ files: [] }));
  const workers: WorkerSpec[] = [];
  const svc = new JobService({
    sandbox: S, run: "cloudsec", image: "img:test", workers: 2, workerCpus: 1, workerMemoryMib: 512, allowHosts: [], openNet: false,
    packDirs: [CLOUD], forging: true, minFreeMb: 1,
    runWorker: localWorker(workers), destroyWorker: async () => ({ ok: true }), notify: async () => undefined, identity: async (a) => ({ name: a }),
  });
  await svc.start();
  return { S, base, svc, workers };
}

async function until(svc: JobService, id: string) {
  for (let i = 0; i < 1200; i += 1) {
    const j = svc.jobs.get(id);
    if (j && ["committed", "failed", "cancelled"].includes(j.state)) return j;
    await new Promise((r) => setTimeout(r, 50));
  }
  throw new Error(`${id} did not finish`);
}

async function submitted(svc: JobService, who: string, spec: Record<string, unknown>) {
  const r = await svc.submit(who, { kind: "tool", timeout_seconds: 120, network: "off", inputs: [], ...spec } as never);
  assert.ok(r.ok, !r.ok ? r.reason : "");
  return until(svc, r.job.id);
}

const outFile = (S: string, job: string, name: string) => readFile(join(storePaths(S).jobs, job, "out", name), "utf8");

/** One tool, the evidence it reads (laid out as the provider's export is), and the file its values go to. */
const CASES: Array<[string, string, string, string]> = [
  ["cloudtrail_parse", "cloudtrail-values.jsonl", "ev.json", trail(ct({ eventID: "g-0", eventSource: "s3.amazonaws.com", eventName: "GetObject", userIdentity: ALICE, requestParameters: { password: SECRET } }))],
  ["signin_analyse", "signin-values.jsonl", "ev.json", JSON.stringify({ value: [{ id: "g-0", createdDateTime: "2026-02-14T09:00:00Z", userPrincipalName: "alice@example.org", userId: "id-1", status: { errorCode: 0 }, password: SECRET }] })],
  ["ual_parse", "ual-values.jsonl", "ev.json", JSON.stringify([{ Id: "u-0", Operation: "Send", UserId: "alice@example.org", CreationTime: "2026-02-14T09:00:00Z", Password: SECRET }])],
];

for (const [name, valuesName, file, evidence] of CASES) {
  test(`${name}: a job with write_values is secret output without the agent's flag: sealed sensitive, a redacted package withholds the values file, a plain job is ordinary`, async () => {
    const { S, svc, base, workers } = await make();
    const manifest = JSON.parse(await readFile(join(CLOUD, "tools", name, "manifest.json"), "utf8"));
    assert.deepEqual(manifest.secret_output, { when_args: ["write_values"] });
    spawnSync("cp", ["-R", join(CLOUD, "tools", name), join(S, "tools", name)]);
    await writeFile(join(S, "work", "a1", file), evidence);
    const rel = `work/a1/${file}`;

    const job = await submitted(svc, "a1", { tool: name, args: { path: rel, write_values: true }, inputs: undefined });
    const log = await readFile(join(storePaths(S).jobs, job.id, "stdout.log"), "utf8");
    assert.equal(job.status, "ok", log);
    assert.equal(job.spec.secret_output, true, "the spec records what the job was run as");
    assert.equal(job.spec.secret_output_by, "tool_manifest");
    assert.equal(job.sensitive?.why, "secret_output");
    assert.equal(job.sensitive?.declared, "tool_manifest");
    assert.equal((await jobView(S, job)).secret_output_by, "tool_manifest");
    assert.match(describe(job), /Its outputs are sensitive \(it ran with secret_output, which the tool's manifest declares\)/);
    assert.equal(workers.find((w) => w.job === job.id)?.env.SECRET_OUTPUT, "1", "the process was told it is a secret job");
    assert.ok((await outFile(S, job.id, valuesName)).includes(SECRET), "the values file holds the original");
    assert.ok(!log.includes(SECRET), "the answer carries no value");

    // The agent saying false does not turn it off.
    const denied = await submitted(svc, "a1", { tool: name, args: { path: rel, write_values: true }, secret_output: false, inputs: undefined });
    assert.equal(denied.sensitive?.why, "secret_output");
    assert.ok((await outFile(S, denied.id, valuesName)).includes(SECRET));

    // A job that reads the values file is derived sensitive, and an entry citing it is recorded sensitive.
    const reader = await submitted(svc, "a2", { kind: "command", command: `wc -c < store/jobs/${job.id}/out/${valuesName} > "$OUT/n.txt"`, inputs: [`job:${job.id}/${valuesName}`] });
    assert.deepEqual([reader.sensitive?.why, reader.sensitive?.from], ["derived", [job.id]]);
    const rec = await P.recordEntry({ sandboxRoot: S, agentId: "a1" }, { kind: "finding", basis: "observed", confidence: "medium", indicates: "What the observation shows, and the step to it.", confidence_why: "Read directly from the object it cites.", value: "The tool wrote a value", source: "the job's output", evidence: "the job", refs: [`job:${job.id}/${valuesName}`] });
    assert.ok(rec.ok, (rec as { reason?: string }).reason);
    assert.equal((rec as { entry: P.LedgerEntry }).entry.sensitive, true);

    // Without write_values the job is an ordinary job and its process is not told otherwise.
    const plain = await submitted(svc, "a1", { tool: name, args: { path: rel }, inputs: undefined });
    assert.equal(plain.status, "ok");
    assert.equal(plain.sensitive, undefined, "an ordinary read is an ordinary job");
    assert.equal(plain.spec.secret_output, undefined);
    assert.equal(workers.find((w) => w.job === plain.id)?.env.SECRET_OUTPUT, undefined);
    assert.equal(existsSync(join(storePaths(S).jobs, plain.id, "out", valuesName)), false, "no values file in an ordinary job");

    // Run by hand in a command job without the flag: no variable, so the tool refuses, as JSON, and writes nothing.
    const args = JSON.stringify({ path: rel, write_values: true });
    const hand = await submitted(svc, "a1", { kind: "command", command: `printf '%s' '${args}' | python3 tools/${name}/run.py > "$OUT/answer.json"; true`, inputs: undefined });
    const answer = JSON.parse(await outFile(S, hand.id, "answer.json"));
    assert.equal(answer.status, "failed");
    assert.deepEqual([answer.write_values, answer.written], ["refused", false]);
    assert.match(answer.error, /not run as secret output/);
    assert.equal(existsSync(join(storePaths(S).jobs, hand.id, "out", valuesName)), false, "nothing was written");
    assert.equal(hand.sensitive, undefined);

    // A redacted package withholds the values file whole.
    await svc.stop("test over");
    const pkg = join(base, "pkg");
    await mkdir(join(pkg, "store", "jobs", job.id, "out"), { recursive: true });
    for (const f of ["job.json", "manifest.json", "stdout.log"]) await writeFile(join(pkg, "store", "jobs", job.id, f), await readFile(join(storePaths(S).jobs, job.id, f)));
    await writeFile(join(pkg, "store", "jobs", job.id, "out", valuesName), SECRET);
    await redactPackage(S, pkg, { leaks: "list" });
    assert.ok(!(await readFile(join(pkg, "store", "jobs", job.id, "out", valuesName), "utf8")).includes(SECRET), "the value is not in the redacted package");
  });
}
