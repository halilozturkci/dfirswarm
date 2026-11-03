/**
 * virtualization-backup-forensics: the three tools refuse `write_text` unless they run with SECRET_OUTPUT=1, and their
 * manifests declare `"secret_output": {"when_args": ["write_text"]}`, so the job service makes a job with `write_text`
 * true secret output by itself (secret_output_by: tool_manifest), whether or not the agent said so. The route is the job
 * service's own, as tests/secret-output-declaration.test.ts asks it: a real job per tool, no flag from the agent. The
 * inputs are synthetic and tiny: this test holds the classification, not the tools' reading.
 */
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { mkdir, mkdtemp, readFile, readdir, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { after, test } from "node:test";
import * as P from "../extensions/protocol.ts";
import { declaredSecretOutput, parseSecretDeclaration } from "../scripts/output-hygiene.ts";
import { storePaths } from "../scripts/evidence-store.ts";
import { describe, JobService } from "../scripts/job-service.ts";
import { localWorker } from "./job-service-worker.ts";
import type { WorkerSpec } from "../scripts/vm.ts";

const ROOT = join(import.meta.dirname, "..");
const PACK = join(ROOT, "packs", "virtualization-backup-forensics");
const TOOLS: Array<[string, Record<string, unknown>]> = [
  ["backup_audit_normalise", { path: "work/a1/in/tasks/index", format: "pve_task_index" }],
  ["snapshot_chain_check", { root: "work/a1/in" }],
  ["virtualization_inventory", { root: "work/a1/in" }],
];

const dirs: string[] = [];
after(async () => {
  for (const d of dirs) {
    spawnSync("chmod", ["-R", "u+w", d]);
    await rm(d, { recursive: true, force: true });
  }
});

async function make() {
  const base = await mkdtemp(join(tmpdir(), "virtsecret-"));
  dirs.push(base);
  const S = join(base, "run");
  await P.initSandbox(S, { swarmId: "virtsec", agentIds: ["a1", "a2"] });
  for (const d of ["inputs", "tools", "catalog", "work/a1/in/tasks"]) await mkdir(join(S, d), { recursive: true });
  await writeFile(join(S, "inputs.json"), JSON.stringify({ files: [] }));
  // One task line in the published Proxmox UPID layout (UPID:node:pid:pstart:starttime:type:id:user:), no end field.
  await writeFile(join(S, "work/a1/in/tasks/index"), "UPID:pve1:00000B73:0000D2F0:65539A80:vzdump::root@pam:\n");
  for (const [name] of TOOLS) spawnSync("cp", ["-R", join(PACK, "tools", name), join(S, "tools", name)]);
  const workers: WorkerSpec[] = [];
  const svc = new JobService({
    sandbox: S, run: "virtsec", image: "img:test", workers: 2, workerCpus: 1, workerMemoryMib: 512, allowHosts: [], openNet: false,
    packDirs: [PACK], forging: true, minFreeMb: 1,
    runWorker: localWorker(workers), destroyWorker: async () => ({ ok: true }), notify: async () => undefined, identity: async (a) => ({ name: a }),
  });
  await svc.start();
  return { S, svc };
}

async function submitted(svc: JobService, spec: Record<string, unknown>) {
  const r = await svc.submit("a1", { kind: "tool", timeout_seconds: 60, network: "off", inputs: [], ...spec } as never);
  assert.ok(r.ok, !r.ok ? r.reason : "");
  for (let i = 0; i < 1200; i += 1) {
    const j = svc.jobs.get(r.job.id);
    if (j && ["committed", "failed", "cancelled"].includes(j.state)) return j;
    await new Promise((x) => setTimeout(x, 50));
  }
  throw new Error(`${r.job.id} did not finish`);
}

for (const [name, args] of TOOLS) {
  test(`${name}: the manifest declares write_text as secret output`, async () => {
    const manifest = JSON.parse(await readFile(join(PACK, "tools", name, "manifest.json"), "utf8"));
    assert.deepEqual(manifest.secret_output, { when_args: ["write_text"] });
    assert.equal(manifest.params.write_text.type, "boolean");
    assert.equal(manifest.params.write_text.default, undefined, "the seal needs a boolean with no default other than false");
    const parsed = parseSecretDeclaration(manifest.secret_output, manifest.params, "secret_output" in manifest);
    assert.ok(parsed.ok, parsed.ok ? "" : parsed.reason);
    assert.equal(declaredSecretOutput(parsed.declaration, { write_text: true }), true);
    assert.equal(declaredSecretOutput(parsed.declaration, { write_text: false }), false);
    assert.equal(declaredSecretOutput(parsed.declaration, {}), false);
  });

  test(`${name}: a job with write_text true is secret by the manifest, with no flag from the agent; one without is an ordinary job`, async () => {
    const { S, svc } = await make();
    const asked = await submitted(svc, { tool: name, args: { ...args, write_text: true } });
    assert.equal(asked.spec.secret_output, true, "the job service ran it as secret output");
    assert.equal(asked.spec.secret_output_by, "tool_manifest", "and says the manifest made it so");
    assert.equal(asked.sensitive?.why, "secret_output");
    assert.equal(asked.sensitive?.declared, "tool_manifest");
    assert.match(describe(asked), /which the tool's manifest declares/);
    const stdout = await readFile(join(storePaths(S).jobs, asked.id, "stdout.log"), "utf8");
    assert.doesNotMatch(stdout, /SECRET_OUTPUT|not run as secret output/, "the tool did not refuse: it ran with SECRET_OUTPUT=1");
    assert.notEqual(JSON.parse(stdout).write_text, "refused");

    const plain = await submitted(svc, { tool: name, args: { ...args } });
    assert.equal(plain.spec.secret_output, undefined);
    assert.equal(plain.sensitive, undefined, "an ordinary read is an ordinary job");
    const off = await submitted(svc, { tool: name, args: { ...args, write_text: false } });
    assert.equal(off.sensitive, undefined, "write_text false is not a values mode");
    assert.deepEqual(await readdir(join(storePaths(S).jobs, plain.id, "out")).catch(() => []), await readdir(join(storePaths(S).jobs, off.id, "out")).catch(() => []));
    await svc.stop("test over");
  });
}
