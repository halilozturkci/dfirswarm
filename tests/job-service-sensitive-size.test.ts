/**
 * The size and digest of a sensitive output are not shown to the agent
 * (docs/adr/0016, docs/packs.md "Secrets and sensitive output").
 *
 * A tool that writes a values file only under a withheld condition (a
 * `contains` filter over text the answer does not show) tells one bit per
 * call through the file's size, and its sha256 confirms a guess. The job
 * service shows the requesting agent what a sensitive job sealed by name and
 * a size bucket only: no byte count, no sha256, no "same bytes as" naming.
 * The sealed manifest, the journal and the store check keep both exactly.
 */
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { spawnSync } from "node:child_process";
import { mkdir, mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { after, test } from "node:test";
import * as P from "../extensions/protocol.ts";
import { checkStore, readManifest, storePaths } from "../scripts/evidence-store.ts";
import { describe, JobService, jobView, type JobRecord } from "../scripts/job-service.ts";
import { sameAsView, similarView, type SameAs, type Similar } from "../scripts/job-reuse.ts";
import { sizeBucket } from "../scripts/output-hygiene.ts";
import { localWorker } from "./job-service-worker.ts";

const ROOT = join(import.meta.dirname, "..");
const BASE = join(ROOT, "packs", "computer-forensics-base");

const dirs: string[] = [];
after(async () => {
  for (const d of dirs) {
    spawnSync("chmod", ["-R", "u+w", d]);
    await rm(d, { recursive: true, force: true });
  }
});

/** The text a tool withholds; the guess is a fragment of it. A placeholder, never a real credential. */
const HIDDEN = "token=Zq7Kp2mR9xT4 end";
/** What the values file holds for a matching guess: a row that is 299 bytes long. */
const ROW = `{"finding_id":1,"file":"a.db","offset":4096,"value":"${"v".repeat(243)}"}\n`;

/** A tool that writes its values file only for a guess that is part of the hidden text (the oracle in the review of the sqlite_freespace filter). */
const ORACLE = [
  "import json, os, sys",
  "a = json.load(sys.stdin)",
  `hidden = ${JSON.stringify(HIDDEN)}`,
  `row = ${JSON.stringify(ROW)}`,
  "out = os.environ['OUT']",
  "if a.get('write_values') and os.environ.get('SECRET_OUTPUT') == '1':",
  "    with open(os.path.join(out, 'values.jsonl'), 'w') as f:",
  "        f.write(row if a.get('contains', '') in hidden else '')",
  "print(json.dumps({'ok': True, 'contains_secret_values': True}))",
  "",
].join("\n");

async function make() {
  const base = await mkdtemp(join(tmpdir(), "sensize-"));
  dirs.push(base);
  const S = join(base, "run");
  await P.initSandbox(S, { swarmId: "ssize", agentIds: ["a1", "a2"] });
  for (const d of ["inputs", "tools", "catalog", "work/a1"]) await mkdir(join(S, d), { recursive: true });
  await writeFile(join(S, "inputs.json"), JSON.stringify({ files: [] }));
  await mkdir(join(S, "tools", "oracle"), { recursive: true });
  await writeFile(join(S, "tools", "oracle", "run.py"), ORACLE);
  await writeFile(
    join(S, "tools", "oracle", "manifest.json"),
    JSON.stringify({
      name: "oracle",
      description: "A probe.",
      params: { write_values: { type: "boolean" }, contains: { type: "string" } },
      runtime: "python3",
      entry: "run.py",
      timeout_seconds: 60,
      by: "t",
      at: "t",
      version: 1,
      sha256: createHash("sha256").update(ORACLE).digest("hex"),
      secret_output: { when_args: ["write_values"] },
    }),
  );
  const svc = new JobService({
    sandbox: S, run: "ssize", image: "img:test", workers: 2, workerCpus: 1, workerMemoryMib: 512, allowHosts: [], openNet: false,
    packDirs: [BASE], forging: true, minFreeMb: 1,
    runWorker: localWorker(), destroyWorker: async () => ({ ok: true }),
    notify: async () => undefined, identity: async (a) => ({ name: a }),
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

async function submitted(svc: JobService, who: string, spec: Record<string, unknown>): Promise<JobRecord> {
  const r = await svc.submit(who, { kind: "tool", timeout_seconds: 60, network: "off", inputs: [], ...spec } as never);
  assert.ok(r.ok, !r.ok ? r.reason : "");
  return until(svc, r.job.id);
}

const sha = (s: string) => createHash("sha256").update(s).digest("hex");

/** The job's committed line on the journal, waited for: it may land just after the job reads committed. */
async function committedLine(S: string, job: string): Promise<Record<string, unknown>> {
  for (let i = 0; i < 200; i++) {
    const text = await readFile(storePaths(S).journal, "utf8").catch(() => "");
    const line = text.split("\n").filter(Boolean).map((l) => JSON.parse(l)).find((l) => l.type === "job_committed" && l.job === job);
    if (line) return line;
    await new Promise((r) => setTimeout(r, 10));
  }
  throw new Error(`no job_committed line for ${job}`);
}

/** The manifest, waited for the same way. */
async function manifestOf(S: string, job: string) {
  for (let i = 0; i < 200; i++) {
    const m = await readManifest(join(storePaths(S).jobs, job, "manifest.json"));
    if (m) return m;
    await new Promise((r) => setTimeout(r, 10));
  }
  throw new Error(`no manifest for ${job}`);
}

/** Every key of a value, nested. */
function keys(v: unknown, into = new Set<string>()): Set<string> {
  if (Array.isArray(v)) for (const x of v) keys(x, into);
  else if (v && typeof v === "object") for (const [k, x] of Object.entries(v)) (into.add(k), keys(x, into));
  return into;
}

test("a right guess and a wrong guess look the same to the agent: no byte count, no sha256, one size bucket", async () => {
  const { S, svc } = await make();
  const right = await submitted(svc, "a1", { tool: "oracle", args: { write_values: true, contains: "Zq7K" } });
  const wrong = await submitted(svc, "a1", { tool: "oracle", args: { write_values: true, contains: "Zq7J" } });
  assert.equal(right.sensitive?.why, "secret_output");
  assert.equal(right.sensitive?.declared, "tool_manifest");
  // The files differ exactly, as sealed: 299 bytes against none.
  const rmf = await manifestOf(S, right.id);
  const wm = await manifestOf(S, wrong.id);
  assert.equal(rmf.manifest.files[0].bytes, ROW.length);
  assert.equal(ROW.length, 299);
  assert.equal(wm.manifest.files[0].bytes, 0);

  const rv = await jobView(S, right);
  const wv = await jobView(S, wrong);
  const shown = (v: Record<string, unknown>, id: string) => JSON.stringify(v).split(id).join("<job>");
  assert.equal(shown(rv, right.id), shown(wv, wrong.id), "the two answers are the same words");
  for (const v of [rv, wv]) {
    const k = keys(v);
    assert.equal(k.has("bytes"), false, "no byte count in the answer");
    assert.equal(k.has("sha256"), false, "no digest in the answer");
    assert.equal(k.has("same_as"), false);
    const outputs = v.outputs as { size: string; list: Array<Record<string, unknown>>; files: number; path: string; withheld: string };
    assert.equal(outputs.size, "under 1 MiB");
    assert.deepEqual(outputs.list.map((f) => Object.keys(f).sort()), [["path", "size"]]);
    assert.equal(outputs.list[0].size, "under 1 MiB");
    assert.equal(outputs.files, 1);
    assert.match(outputs.withheld, /exact sizes and sha256 are not shown/);
    assert.match(String(v.sensitive), /Its outputs are sensitive/);
  }
  // Not in the text of the answer either: neither the size nor a digest of either file.
  for (const text of [JSON.stringify(rv), JSON.stringify(wv), describe(right), describe(wrong)]) {
    assert.doesNotMatch(text, /\b299\b/);
    assert.equal(text.includes(sha(ROW)), false);
    assert.equal(text.includes(sha("")), false);
    assert.equal(text.includes(rmf.sha256), false, "nor the manifest's digest");
  }
  // The post to the requester says the same, in words.
  assert.equal(describe(right).split(right.id).join("<job>"), describe(wrong).split(wrong.id).join("<job>"));
  assert.match(describe(right), /1 file\(s\), sealed, size under 1 MiB in store\/jobs\//);
  assert.doesNotMatch(describe(right), /\d+ bytes/);
  await svc.stop("test over");
});

test("the sealed manifest, the journal and the store check keep the exact size and digest", async () => {
  const { S, svc } = await make();
  const right = await submitted(svc, "a1", { tool: "oracle", args: { write_values: true, contains: "Zq7K" } });
  const wrong = await submitted(svc, "a1", { tool: "oracle", args: { write_values: true, contains: "Zq7J" } });
  for (const [job, row] of [[right, ROW], [wrong, ""]] as const) {
    const m = await manifestOf(S, job.id);
    assert.deepEqual([m.manifest.files[0].path, m.manifest.files[0].bytes, m.manifest.files[0].sha256], ["values.jsonl", row.length, sha(row)]);
    assert.equal(m.manifest.totals.bytes, row.length);
    const line = await committedLine(S, job.id);
    const outputs = line.outputs as { bytes: number; files: number; manifest_sha256: string };
    assert.equal(outputs.bytes, row.length, "the journal line keeps the total");
    assert.equal(outputs.manifest_sha256, m.sha256);
    assert.equal(job.outputs?.bytes, row.length, "and so does the job's own record");
    const stored = JSON.parse(await readFile(join(storePaths(S).jobs, job.id, "job.json"), "utf8"));
    assert.equal(stored.outputs.bytes, row.length);
  }
  // Custody re-hashes every sealed file against its manifest: the exact digests are what it holds them to.
  const check = await checkStore(S);
  assert.ok(check);
  assert.equal(check.outputs.mismatched.length, 0);
  assert.equal(check.outputs.missing.length, 0);
  assert.ok(check.outputs.verified >= 2);
  await svc.stop("test over");
});

test("a job derived from a sensitive output, and a file of 1.5 MiB, are shown by bucket", async () => {
  const { S, svc } = await make();
  const secret = await submitted(svc, "a1", { kind: "command", command: `head -c 1572864 /dev/zero > "$OUT/big.bin"; printf x > "$OUT/small.bin"`, secret_output: true });
  const v = await jobView(S, secret);
  const outputs = v.outputs as { size: string; list: Array<{ path: string; size: string }> };
  assert.equal(outputs.size, "1 MiB to under 2 MiB");
  assert.deepEqual(outputs.list.map((f) => [f.path, f.size]), [["big.bin", "1 MiB to under 2 MiB"], ["small.bin", "under 1 MiB"]]);
  assert.equal(keys(v).has("sha256"), false);
  const derived = await submitted(svc, "a2", { kind: "command", command: `printf 'abc' > "$OUT/d.txt"`, inputs: [`job:${secret.id}/small.bin`] });
  assert.equal(derived.sensitive?.why, "derived");
  const dv = await jobView(S, derived);
  assert.equal(keys(dv).has("bytes"), false);
  assert.equal(keys(dv).has("sha256"), false);
  assert.equal((dv.outputs as { size: string }).size, "under 1 MiB");
  assert.doesNotMatch(describe(derived), /\d+ bytes/);
  assert.equal((await manifestOf(S, derived.id)).manifest.files[0].bytes, 3, "sealed exactly");
  await svc.stop("test over");
});

test("a job that is not sensitive is shown as before: exact bytes and sha256, same_as and its words", async () => {
  const { S, svc } = await make();
  const plain = await submitted(svc, "a1", { kind: "command", command: `printf 'hello' > "$OUT/h.txt"` });
  assert.equal(plain.sensitive, undefined);
  const v = await jobView(S, plain);
  const outputs = v.outputs as { bytes: number; size?: string; withheld?: string; list: Array<Record<string, unknown>> };
  assert.equal(outputs.bytes, 5);
  assert.equal(outputs.size, undefined);
  assert.equal(outputs.withheld, undefined);
  assert.deepEqual(outputs.list, [{ path: "h.txt", bytes: 5, sha256: sha("hello") }]);
  assert.match(describe(plain), /1 file\(s\), 5 bytes in store\/jobs\//);
  // same_as is shown for it, with its bytes.
  const same: SameAs[] = [{ path: "h.txt", sha256: sha("hello"), bytes: 5, job: "j000001", file: "h.txt" }];
  plain.same_as = same;
  assert.deepEqual((await jobView(S, plain)).same_as, [{ path: "h.txt", bytes: 5, same_as: "job:j000001/h.txt" }]);
  assert.match(describe(plain), /1 of its files are an earlier job's output byte for byte/);
  await svc.stop("test over");
});

test("a sensitive job is not told which earlier output its file equals byte for byte", async () => {
  const { S, svc } = await make();
  const secret = await submitted(svc, "a1", { kind: "command", command: `printf 'hello' > "$OUT/h.txt"`, secret_output: true });
  secret.same_as = [{ path: "h.txt", sha256: sha("hello"), bytes: 5, job: "j000099", file: "h.txt" }];
  const v = await jobView(S, secret);
  assert.equal("same_as" in v, false);
  assert.equal("same_as_more" in v, false);
  assert.doesNotMatch(describe(secret), /byte for byte/);
  await svc.stop("test over");
});

test("another seat's reuse hint shows a sensitive job's outputs by bucket; the journal's similar line keeps the size", () => {
  const base = { seat: "a1", state: "committed", status: "ok", lead: null, objects: "same", shared: 1, match: "same tool", op: "tool:oracle" } as const;
  const plain: Similar = { ...base, job: "j000001", outputs: { files: 1, bytes: 299, path: "store/jobs/j000001/out" } };
  const secret: Similar = { ...base, job: "j000002", outputs: { files: 1, bytes: 299, path: "store/jobs/j000002/out" }, sensitive: true };
  const told = (similarView("j000003", [plain, secret], false).similar as Array<{ job: string; outputs: Record<string, unknown> }>);
  assert.deepEqual(told[0].outputs, { files: 1, bytes: 299, path: "store/jobs/j000001/out" });
  assert.deepEqual(told[1].outputs, { files: 1, path: "store/jobs/j000002/out", size: "under 1 MiB" });
  assert.equal(JSON.stringify(told[1]).includes("299"), false);
  // The record is the Similar itself, untouched by the view.
  assert.equal(secret.outputs?.bytes, 299);
  assert.deepEqual(sameAsView("j000003", []), {});
});

test("the size bucket: a megabyte floor, then powers of two; nothing under it tells empty from small", () => {
  const MIB = 1024 * 1024;
  assert.equal(sizeBucket(0), "under 1 MiB");
  assert.equal(sizeBucket(1), "under 1 MiB");
  assert.equal(sizeBucket(299), "under 1 MiB");
  assert.equal(sizeBucket(MIB - 1), "under 1 MiB");
  assert.equal(sizeBucket(MIB), "1 MiB to under 2 MiB");
  assert.equal(sizeBucket(2 * MIB - 1), "1 MiB to under 2 MiB");
  assert.equal(sizeBucket(2 * MIB), "2 MiB to under 4 MiB");
  assert.equal(sizeBucket(5 * MIB), "4 MiB to under 8 MiB");
  assert.equal(sizeBucket(3 * 1024 * MIB), "2048 MiB to under 4096 MiB");
  assert.equal(sizeBucket(Number.NaN), "under 1 MiB");
});
