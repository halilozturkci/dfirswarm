/**
 * What an agent is shown of a sensitive job while it RUNS and in the places
 * the sealed answer does not cover (docs/adr/0016, docs/packs.md "Secrets and
 * sensitive output").
 *
 * The sealed answer gives a size bucket for a sensitive job's outputs
 * (tests/job-service-sensitive-size.test.ts). job_status on a job that has not
 * sealed yet sampled the output directory and returned its exact bytes, its
 * file count and its newest file, and the logs' byte counts: the size the
 * sealed answer hides, a few seconds earlier. A job made from a sensitive
 * output is sensitive only when it seals, so its running answer is held to
 * the same rule from the start. The host keeps the exact samples: the verdict
 * (moving, quiet, suspected stall) is assessed from them.
 *
 * The worker is an async stand-in (tests/job-service-worker.ts): the tool
 * writes its files, signals that it has, and waits for the test to let it go.
 */
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { spawnSync } from "node:child_process";
import { existsSync } from "node:fs";
import { mkdir, mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { after, test } from "node:test";
import * as P from "../extensions/protocol.ts";
import { JobService, jobView, type JobRecord } from "../scripts/job-service.ts";
import { jobProgressOnDisk, progressWords } from "../scripts/job-telemetry.ts";
import { sizeBucket } from "../scripts/output-hygiene.ts";
import { asyncLocalWorker } from "./job-service-worker.ts";

const ROOT = join(import.meta.dirname, "..");
const BASE = join(ROOT, "packs", "computer-forensics-base");

const dirs: string[] = [];
after(async () => {
  for (const d of dirs) {
    spawnSync("chmod", ["-R", "u+w", d]);
    await rm(d, { recursive: true, force: true });
  }
});

/** Writes a values file of `size` bytes, a log of `err` bytes on stderr, says it is ready and waits for the gate. */
const LIVE = [
  "import json, os, sys, time",
  "a = json.load(sys.stdin)",
  "out = os.environ['OUT']",
  "with open(os.path.join(out, 'values.jsonl'), 'w') as f:",
  "    f.write('v' * int(a.get('size', 0)))",
  "if a.get('err'):",
  "    sys.stderr.write('e' * int(a['err']))",
  "    sys.stderr.flush()",
  "open(a['ready'], 'w').write('1')",
  "while not os.path.exists(a['gate']):",
  "    time.sleep(0.05)",
  "print(json.dumps({'ok': True}))",
  "",
].join("\n");

async function make(secret: boolean) {
  const base = await mkdtemp(join(tmpdir(), "senslive-"));
  dirs.push(base);
  const S = join(base, "run");
  await P.initSandbox(S, { swarmId: "slive", agentIds: ["a1", "a2"] });
  for (const d of ["inputs", "tools", "catalog", "work/a1"]) await mkdir(join(S, d), { recursive: true });
  await writeFile(join(S, "inputs.json"), JSON.stringify({ files: [] }));
  await mkdir(join(S, "tools", "live"), { recursive: true });
  await writeFile(join(S, "tools", "live", "run.py"), LIVE);
  await writeFile(
    join(S, "tools", "live", "manifest.json"),
    JSON.stringify({
      name: "live",
      description: "A probe.",
      params: { size: { type: "number" }, err: { type: "number" }, ready: { type: "string" }, gate: { type: "string" } },
      runtime: "python3",
      entry: "run.py",
      timeout_seconds: 60,
      by: "t",
      at: "t",
      version: 1,
      sha256: createHash("sha256").update(LIVE).digest("hex"),
      ...(secret ? { secret_output: "required" } : {}),
    }),
  );
  const svc = new JobService({
    sandbox: S, run: "slive", image: "img:test", workers: 2, workerCpus: 1, workerMemoryMib: 512, allowHosts: [], openNet: false,
    packDirs: [BASE], forging: true, minFreeMb: 1,
    runWorker: asyncLocalWorker(), destroyWorker: async () => ({ ok: true }),
    notify: async () => undefined, identity: async (a) => ({ name: a }),
  });
  await svc.start();
  return { base, S, svc };
}

async function eventually(ok: () => boolean, what: string, ms = 20000): Promise<void> {
  const end = Date.now() + ms;
  while (!ok()) {
    if (Date.now() > end) throw new Error(`not within ${ms} ms: ${what}`);
    await new Promise((r) => setTimeout(r, 25));
  }
}

async function committed(svc: JobService, id: string): Promise<JobRecord> {
  await eventually(() => ["committed", "failed", "cancelled"].includes(svc.jobs.get(id)?.state ?? ""), `${id} finished`);
  return svc.jobs.get(id)!;
}

/** What vm-hub's jobStatus gives a seat for a job: jobView, a page of stdout, the progress of a running job. */
async function hubStatus(S: string, svc: JobService, who: string, id: string): Promise<Record<string, unknown>> {
  const r = await svc.status(who, id, {});
  if (!r.ok) return { ok: false, reason: r.reason };
  return { ok: true, job: await jobView(S, r.job), ...(r.stdout ? { stdout: r.stdout } : {}), ...(r.progress ? { progress: r.progress } : {}) };
}

/** Every key of a value, nested. */
function keys(v: unknown, into = new Set<string>()): Set<string> {
  if (Array.isArray(v)) for (const x of v) keys(x, into);
  else if (v && typeof v === "object") for (const [k, x] of Object.entries(v)) (into.add(k), keys(x, into));
  return into;
}

/** The answer as text, with what differs between two runs of the same thing (ids, times, durations) made equal. */
function text(v: unknown, ids: string[]): string {
  let s = JSON.stringify(v);
  for (const id of ids) s = s.split(id).join("<job>");
  return s
    .replace(/"(started_at|finished_at|accepted_at|newest_at)":"[^"]*"/g, '"$1":"T"')
    .replace(/"(running_ms|timeout_in_ms|still_ms)":(?:null|-?\d+)/g, '"$1":N')
    .replace(/\/[^"\s]*?senslive-[A-Za-z0-9]+/g, "/TMP");
}

type Run = { id: string; mid: Array<Record<string, unknown>>; exact: Awaited<ReturnType<JobService["progress"]>>; disk: unknown; words: string | null };

/** Runs the tool with a values file of `size` bytes and a stderr of `err`, asks about it while it runs, then lets it go. */
async function runLive(secret: boolean, size: number, err: number): Promise<Run & { S: string; svc: JobService; final: JobRecord }> {
  const { base, S, svc } = await make(secret);
  const ready = join(base, "ready");
  const gate = join(base, "gate");
  const r = await svc.submit("a1", { kind: "tool", tool: "live", args: { size, err, ready, gate }, timeout_seconds: 60, network: "off", inputs: [] } as never);
  assert.ok(r.ok, !r.ok ? r.reason : "");
  const id = r.job.id;
  await eventually(() => existsSync(ready), "the tool wrote its files");
  assert.equal(svc.jobs.get(id)?.state, "running");
  let mid: Array<Record<string, unknown>>;
  let exact: Awaited<ReturnType<JobService["progress"]>>;
  let onDisk: Awaited<ReturnType<typeof jobProgressOnDisk>>;
  try {
    mid = [await hubStatus(S, svc, "a1", id), await hubStatus(S, svc, "a2", id)];
    exact = await svc.progress(id);
    onDisk = await jobProgressOnDisk(S, id);
  } finally {
    await writeFile(gate, "go");
  }
  const final = await committed(svc, id);
  return { id, mid, exact, disk: onDisk, words: onDisk ? progressWords(id, onDisk) : null, S, svc, final };
}

test("job_status on a RUNNING sensitive job gives the same answer whatever the output's size: no byte count, no file count, no newest file, no log byte counts", async () => {
  const runs: Array<Awaited<ReturnType<typeof runLive>>> = [];
  for (const size of [0, 299, 70000]) runs.push(await runLive(true, size, size));
  const shown = runs.map((r) => r.mid.map((m) => text(m, [r.id])));
  assert.equal(shown[0].length, 2);
  for (let i = 1; i < runs.length; i++) assert.deepEqual(shown[i], shown[0], "the answers at 0, 299 and 70,000 bytes are the same words");
  for (const r of runs) {
    for (const m of r.mid) {
      assert.equal(m.ok, true);
      const progress = m.progress as Record<string, unknown>;
      assert.ok(progress, "a running job's answer carries its progress");
      const k = keys(progress);
      for (const gone of ["bytes", "files", "newest", "newest_at", "stdout_bytes", "stderr_bytes", "bounded"]) assert.equal(k.has(gone), false, `no ${gone} in a sensitive job's progress`);
      const signals = progress.signals as { out: { size: string }; logs: { stdout_size: string; stderr_size: string } };
      assert.equal(signals.out.size, "under 1 MiB");
      assert.equal(signals.logs.stderr_size, "under 1 MiB");
      assert.match(String(progress.withheld), /sensitive output/);
      for (const n of ["299", "70000", "values.jsonl"]) assert.equal(JSON.stringify(m).includes(n), false, `${n} is not in the answer`);
    }
    // The header's and the regroup's words are held to it too.
    assert.ok(r.words);
    assert.doesNotMatch(r.words!, /\d+ bytes|file\(s\)|newest|values\.jsonl|\d+ B\b/);
    assert.equal(keys(r.disk).has("bytes"), false);
  }
  assert.equal(runs[0].words!.split(runs[0].id).join("<job>"), runs[2].words!.split(runs[2].id).join("<job>"));
  // The host keeps the exact samples: the verdict is assessed from them, and they say what the job wrote.
  for (const [i, size] of [0, 299, 70000].entries()) {
    const exact = runs[i].exact!;
    assert.equal(exact.signals.out.bytes, size, "the sample on the host is exact");
    assert.equal(exact.signals.out.files, 1);
    assert.equal(exact.signals.out.newest, "values.jsonl");
    assert.equal(exact.signals.logs.stderr_bytes, size);
    const shownState = (runs[i].mid[0].progress as { state: string; why: string });
    assert.equal(shownState.state, exact.state, "the verdict is the exact sample's");
    assert.equal(shownState.why, exact.why);
  }
  // The sealed record has the exact size, as before.
  const last = runs[2];
  assert.equal(last.final.outputs?.bytes, 70000);
  for (const r of runs) await r.svc.stop("test over");
});

test("a running job that is not sensitive is shown as before: the exact bytes, files, newest file and log counts", async () => {
  const r = await runLive(false, 299, 5);
  const progress = r.mid[0].progress as { signals: { out: { files: number; bytes: number; newest: string | null; newest_at: string | null; bounded: boolean }; logs: { stdout_bytes: number; stderr_bytes: number } }; withheld?: string };
  assert.equal(progress.signals.out.bytes, 299);
  assert.equal(progress.signals.out.files, 1);
  assert.equal(progress.signals.out.newest, "values.jsonl");
  assert.equal(typeof progress.signals.out.newest_at, "string");
  assert.equal(progress.signals.out.bounded, false);
  assert.equal(progress.signals.logs.stderr_bytes, 5);
  assert.equal(progress.withheld, undefined);
  assert.match(r.words!, /out 1 file\(s\), 299 bytes, newest values\.jsonl; stdout \d+ B, stderr 5 B\./);
  await r.svc.stop("test over");
});

test("a job that reads a sensitive output is held sensitive from the start: its running answer carries no size either", async () => {
  const { base, S, svc } = await make(true);
  const secret = await svc.submit("a1", { kind: "command", command: `printf 'token=ZZ' > "$OUT/s.txt"`, secret_output: true, timeout_seconds: 60, network: "off", inputs: [] } as never);
  assert.ok(secret.ok);
  await committed(svc, secret.job.id);
  const answers: string[] = [];
  const gates: string[] = [];
  try {
  for (const size of [0, 70000]) {
    const ready = join(base, `ready-${size}`);
    const gate = join(base, `gate-${size}`);
    gates.push(gate);
    const d = await svc.submit("a2", {
      kind: "command",
      command: `head -c ${size} /dev/zero > "$OUT/z.bin"; cp store/jobs/${secret.job.id}/out/s.txt "$OUT/copy.txt"; : > '${ready}'; while [ ! -e '${gate}' ]; do sleep 0.05; done`,
      inputs: [`job:${secret.job.id}/s.txt`],
      timeout_seconds: 60,
      network: "off",
    } as never);
    assert.ok(d.ok, !d.ok ? d.reason : "");
    await eventually(() => existsSync(ready), "the derived job wrote its files");
    assert.equal(svc.jobs.get(d.job.id)?.state, "running");
    assert.equal(svc.jobs.get(d.job.id)?.sensitive, undefined, "sensitivity is decided at the seal, as before");
    const mid = await hubStatus(S, svc, "a2", d.job.id);
    const exact = await svc.progress(d.job.id);
    const onDisk = await jobProgressOnDisk(S, d.job.id);
    answers.push(text(mid, [d.job.id]));
    const progress = mid.progress as Record<string, unknown>;
    assert.ok(progress);
    assert.match(String(progress.withheld), /sensitive output/);
    for (const gone of ["bytes", "files", "newest", "newest_at", "stdout_bytes", "stderr_bytes"]) assert.equal(keys(progress).has(gone), false, `no ${gone}`);
    assert.equal(keys(onDisk).has("bytes"), false, "nor in the words of the header and the regroup");
    assert.equal(exact!.signals.out.bytes, size + 8, "the host's sample is exact");
    await writeFile(gate, "go");
    const done = await committed(svc, d.job.id);
    assert.equal(done.sensitive?.why, "derived", "and it seals sensitive, as the running answer treated it");
  }
  assert.equal(answers[0], answers[1], "a running derived job is the same words at 0 and 70,000 bytes");
  } finally {
    for (const g of gates) await writeFile(g, "go");
    await svc.stop("test over");
  }
});

test("a job that reads nothing sensitive is exact while it runs, even when the run holds a sensitive job", async () => {
  const { base, S, svc } = await make(true);
  const secret = await svc.submit("a1", { kind: "command", command: `printf 'token=ZZ' > "$OUT/s.txt"`, secret_output: true, timeout_seconds: 60, network: "off", inputs: [] } as never);
  assert.ok(secret.ok);
  await committed(svc, secret.job.id);
  const ready = join(base, "ready");
  const gate = join(base, "gate");
  const d = await svc.submit("a2", { kind: "command", command: `head -c 1234 /dev/zero > "$OUT/z.bin"; : > '${ready}'; while [ ! -e '${gate}' ]; do sleep 0.05; done`, inputs: [], timeout_seconds: 60, network: "off" } as never);
  assert.ok(d.ok);
  await eventually(() => existsSync(ready), "the job wrote its file");
  try {
    const mid = await hubStatus(S, svc, "a2", d.job.id);
    assert.equal((mid.progress as { signals: { out: { bytes: number } } }).signals.out.bytes, 1234);
  } finally {
    await writeFile(gate, "go");
  }
  const done = await committed(svc, d.job.id);
  assert.equal(done.sensitive, undefined);
  await svc.stop("test over");
});

test("a sensitive job's stderr length beyond its tail is a bucket; a job that is not sensitive keeps the count", async () => {
  const sens = await runLive(true, 3, 5000);
  const plain = await runLive(false, 3, 5000);
  const sv = await jobView(sens.S, sens.final);
  const pv = await jobView(plain.S, plain.final);
  const se = sv.stderr as Record<string, unknown>;
  const pe = pv.stderr as Record<string, unknown>;
  assert.equal(se.size, "under 1 MiB");
  assert.equal("bytes" in se, false);
  assert.equal(String(se.tail).length, 1024, "the tail is shown whole");
  assert.equal(se.whole, `store/jobs/${sens.id}/stderr.log`);
  assert.equal(pe.bytes, 5000);
  assert.equal("size" in pe, false);
  await sens.svc.stop("test over");
  await plain.svc.stop("test over");
});

test("the size bucket does not loop or throw on a size that is not a number of bytes", () => {
  assert.equal(sizeBucket(Number.POSITIVE_INFINITY), "1 PiB or more");
  assert.equal(sizeBucket(1e300), "1 PiB or more");
  assert.equal(sizeBucket(2 ** 50), "1 PiB or more");
  assert.equal(sizeBucket(2 ** 50 - 1), "536870912 MiB to under 1073741824 MiB");
  assert.equal(sizeBucket(Number.NEGATIVE_INFINITY), "under 1 MiB");
  assert.equal(sizeBucket(Number.NaN), "under 1 MiB");
  assert.equal(sizeBucket(-5), "under 1 MiB");
});
