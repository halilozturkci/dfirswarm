/**
 * A job runs a program the operator supplied (import:mat-<n>) by naming it in
 * programs (scripts/job-service.ts programLines): it is copied into an
 * executable directory in the worker, its bin/ put on PATH and its lib/ on
 * LD_LIBRARY_PATH. Nothing runs where it stands in store/ (sealed 0444) or in
 * $OUT (no-exec): on the run sf4406b a seat copied ffmpeg and zbarimg into
 * $OUT, every call was refused and the job ended 0. Only supplied programs, only
 * for a command or a tool, and each is added to a declared scope.
 */
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { chmodSync, mkdirSync, mkdtempSync, writeFileSync } from "node:fs";
import { rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { after, test } from "node:test";
import { sealTree, storePaths } from "../scripts/evidence-store.ts";
import { JobService, programLines } from "../scripts/job-service.ts";
import { localWorker } from "./job-service-worker.ts";

const dirs: string[] = [];
after(async () => {
  for (const d of dirs) {
    spawnSync("chmod", ["-R", "u+w", d]);
    await rm(d, { recursive: true, force: true });
  }
});

test("the lines: one executable directory, each program's bin/ on PATH and lib/ on LD_LIBRARY_PATH, none for a job that names none", () => {
  assert.deepEqual(programLines([], "/run/store/imports"), []);
  const lines = programLines(["mat-0002"], "/run/store/imports").join("\n");
  assert.match(lines, /^PROGRAMS="\$\(mktemp -d \/tmp\/programs\.XXXXXX\)"/);
  assert.match(lines, /cp -R '\/run\/store\/imports\/mat-0002\/out'\/\. "\$PROGRAMS"\/'mat-0002'\//);
  assert.match(lines, /-name bin -o -name sbin/);
  assert.match(lines, /-name lib -o -name lib64 -o -name '\*-linux-gnu'/);
});

test("through the service: a supplied program sealed 0444 runs when the job names it in programs, with its library found; refused otherwise, and named", async () => {
  const S = join(mkdtempSync(join(tmpdir(), "job-programs-")), "run");
  dirs.push(join(S, ".."));
  for (const d of ["inputs", "tools", "catalog", "work/a1", "store/imports", "staging/bin", "staging/lib", "store/imports/ev-0001/out"]) mkdirSync(join(S, d), { recursive: true });
  writeFileSync(join(S, "inputs.json"), JSON.stringify({ files: [] }));
  // A program and the library it reads, sealed as tool-supply seals them: no execute bit.
  writeFileSync(join(S, "staging/bin/greet"), '#!/bin/sh\necho "hello from $(cat "$(dirname "$0")/../lib/word.txt") ld=${LD_LIBRARY_PATH:+set}"\n', { mode: 0o755 });
  writeFileSync(join(S, "staging/lib/word.txt"), "the supply\n");
  await sealTree(S, join(S, "staging"), join(storePaths(S).imports, "mat-0001", "out"), "mat-0001", 1);
  writeFileSync(join(S, "store/imports/ev-0001/out/e"), "evidence\n");
  chmodSync(join(S, "store/imports/ev-0001/out/e"), 0o444);
  const svc = new JobService({ sandbox: S, run: "s000000", image: "img:test", workers: 1, workerCpus: 1, workerMemoryMib: 512, allowHosts: [], openNet: false, packDirs: [], forging: false, minFreeMb: 1, runWorker: localWorker(), destroyWorker: async () => ({ ok: true }), notify: async () => undefined, identity: async () => ({}) });
  await svc.start();
  const run = async (spec: Record<string, unknown>) => {
    const r = await svc.submit("a1", { kind: "command", inputs: ["all"], ...spec } as never);
    if (!r.ok) return { refused: r.reason };
    const end = Date.now() + 20_000;
    let job = svc.jobs.get(r.job.id)!;
    while (!["committed", "failed", "cancelled"].includes(job.state) && Date.now() < end) {
      await new Promise((res) => setTimeout(res, 50));
      job = svc.jobs.get(r.job.id)!;
    }
    return { job };
  };
  const ran = await run({ command: "greet", programs: ["import:mat-0001/"] });
  assert.ok(ran.job, ran.refused);
  assert.equal(ran.job!.status, "ok", ran.job!.reason);
  assert.deepEqual(ran.job!.spec.programs, ["import:mat-0001"]);
  const out = spawnSync("cat", [join(S, "store", "jobs", ran.job!.id, "stdout.log")], { encoding: "utf8" }).stdout;
  assert.equal(out.trim(), "hello from the supply ld=set");
  // A declared scope is given the program too.
  const scoped = await run({ command: "greet", programs: ["import:mat-0001"], inputs: [] });
  assert.equal(scoped.job?.status, "ok", scoped.refused ?? scoped.job?.reason);
  assert.deepEqual(scoped.job!.spec.inputs, ["import:mat-0001"]);
  // Without it, the sealed file does not run where it stands.
  const bare = await run({ command: `${join(S, "store/imports/mat-0001/out/bin/greet")}` });
  assert.equal(bare.job?.status, "failed");
  assert.match(bare.job?.reason ?? "", /could not be executed/);
  // Only supplied programs, only a command or a tool.
  assert.match((await run({ command: "x", programs: ["import:ev-0001"] })).refused ?? "", /names programs the operator supplied, as import:mat-<n>/);
  assert.match((await run({ command: "x", programs: ["import:mat-0009"] })).refused ?? "", /no supplied program import:mat-0009/);
  assert.match((await run({ command: "x", programs: ["job:j000001"] })).refused ?? "", /is not one/);
  assert.match((await run({ command: "x", programs: "import:mat-0001" })).refused ?? "", /a list of supplied programs/);
  await svc.stop?.();
});
