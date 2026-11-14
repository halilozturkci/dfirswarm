/**
 * The run's sensitive index (scripts/output-hygiene.ts sensitiveIndex), and
 * what `same_bytes` marks: the index is brought up to date from the lines
 * the journal gained, never read again from its start; a job whose tree
 * shares one file with a secret_output job has that file marked and no
 * other, and nothing spreads from the rest of its tree.
 */
import test from "node:test";
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { appendFileSync, mkdirSync, mkdtempSync, rmSync, statSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { Journal, sealTree, storePaths, type Manifest } from "../scripts/evidence-store.ts";
import { indexManifestFile } from "../scripts/manifest-index.ts";
import { jobSensitivity, ownSensitivity, sensitiveIndex, sensitiveIndexStats, sensitiveRefs, withheldPaths, type Sensitivity } from "../scripts/output-hygiene.ts";

const bases: string[] = [];
test.after(() => {
  for (const b of bases) {
    spawnSync("chmod", ["-R", "u+w", b]);
    rmSync(b, { recursive: true, force: true });
  }
});

async function run(): Promise<{ b: string; S: string; journal: Journal }> {
  const b = mkdtempSync(join(tmpdir(), "sensitive-index-"));
  bases.push(b);
  const S = join(b, "run");
  mkdirSync(S, { recursive: true });
  return { b, S, journal: await Journal.open(S) };
}

/** Seal a tree as a job and decide its sensitivity as the job service does at the seal, then commit it. */
async function commit(o: { b: string; S: string; journal: Journal }, id: string, files: Record<string, string>, spec: Record<string, unknown> = { command: "walk" }, scopeManifest?: string): Promise<{ manifest: Manifest; sensitive: Sensitivity | null }> {
  const staging = join(o.b, `staging-${id}`);
  for (const [path, text] of Object.entries(files)) {
    mkdirSync(join(staging, path, ".."), { recursive: true });
    writeFileSync(join(staging, path), text);
  }
  const { manifest } = await sealTree(o.S, staging, join(storePaths(o.S).jobs, id, "out"), id, 1);
  const sensitive = await jobSensitivity(o.S, { id, spec, ...(scopeManifest ? { scope: { manifest: scopeManifest } } : {}) }, { outputs: manifest.files });
  await o.journal.append({ type: "job_committed", job: id, attempt: 1, status: "ok", logs: {}, ...(sensitive ? { sensitive } : {}) });
  return { manifest, sensitive };
}

test("a tree that shares one file with a secret_output job has that file marked, and only it; nothing spreads from the rest of the tree", async () => {
  const o = await run();
  const secret: Record<string, string> = {};
  for (let i = 0; i < 37; i += 1) secret[`keys/k${i}.txt`] = `recovered value ${i}`;
  secret["Users/Duke/Bookmarks"] = "{ the bookmarks }";
  const first = await commit(o, "j000023", secret, { command: "extract", secret_output: true });
  assert.equal(first.sensitive?.why, "secret_output");

  // A walk of the whole disk: 300 files of its own, and the bookmarks file, byte for byte.
  const walk: Record<string, string> = { "tree/Users/Duke/AppData/Bookmarks": "{ the bookmarks }", "tree/$Bitmap": "the bitmap" };
  for (let i = 0; i < 300; i += 1) walk[`tree/d${i % 10}/f${i}.bin`] = `walked ${i}`;
  const second = await commit(o, "j000008", walk);
  assert.deepEqual(second.sensitive?.files, ["tree/Users/Duke/AppData/Bookmarks"]);
  assert.deepEqual(second.sensitive?.because, [{ from: "j000023", how: "same_bytes", object: "tree/Users/Duke/AppData/Bookmarks" }]);
  assert.match(second.sensitive?.note ?? "", /^1 of the files it sealed is byte for byte the sensitive output of j000023: that file is sensitive, the rest of what it sealed is not$/);

  // A third job that shares another file with the walk is not made sensitive by it.
  const third = await commit(o, "j000011", { "tree/$Bitmap": "the bitmap", "other.txt": "its own" });
  assert.equal(third.sensitive, null);
  // Nor is one that declares a file of the walk that is not the marked one; one that declares the marked file is, whole.
  mkdirSync(join(o.S, "store", "scopes"), { recursive: true });
  writeFileSync(join(o.S, "store", "scopes", "a.json"), JSON.stringify({ accessible: [{ path: "store/jobs/j000008/out/tree/d1/f1.bin" }, { path: "store/jobs/j000008/out/tree/d2" }] }));
  writeFileSync(join(o.S, "store", "scopes", "b.json"), JSON.stringify({ accessible: [{ path: "store/jobs/j000008/out/tree/Users/Duke" }] }));
  assert.equal((await commit(o, "j000012", { "r.txt": "read a plain file" }, { command: "x" }, "store/scopes/a.json")).sensitive, null);
  const reader = await commit(o, "j000013", { "r.txt": "read the bookmarks" }, { command: "x" }, "store/scopes/b.json");
  assert.deepEqual([reader.sensitive?.from, reader.sensitive?.files, reader.sensitive?.because?.map((x) => x.how)], [["j000008"], undefined, ["declared"]]);

  const index = await sensitiveIndex(o.S);
  assert.deepEqual([...index.jobs.keys()], ["j000023", "j000008", "j000013"]);
  const marked = index.jobs.get("j000008")!;
  assert.deepEqual([marked.partial, marked.files.map((f) => f.path), marked.logs], [true, ["tree/Users/Duke/AppData/Bookmarks"], []]);
  assert.equal(index.jobs.get("j000023")!.files.length, 38);
  assert.equal(index.jobs.get("j000023")!.partial, undefined);
  assert.equal(index.content.get(second.manifest.files.find((f) => f.path === "tree/$Bitmap")!.sha256), undefined, "the walk's other files are not sensitive content");

  // A ledger entry's refs: the marked file and the whole output reach it, another file of the walk does not.
  const hits = await sensitiveRefs(o.S, ["job:j000008/tree/Users/Duke/AppData/Bookmarks", "job:j000008/out/tree/Users/Duke/AppData/Bookmarks", "job:j000008", "job:j000008/tree/d1/f1.bin", "job:j000008/stdout.log", "job:j000023/keys/k1.txt", "job:j000011/other.txt"]);
  assert.deepEqual(hits.map((h) => h.ref), ["job:j000008/tree/Users/Duke/AppData/Bookmarks", "job:j000008/out/tree/Users/Duke/AppData/Bookmarks", "job:j000008", "job:j000023/keys/k1.txt"]);
  // A package withholds that file of the walk, and every file and log of the secret job.
  const rules = withheldPaths(index);
  const withheld = (p: string) => rules.some((r) => r.rel.test(p));
  assert.deepEqual(["store/jobs/j000008/out/tree/Users/Duke/AppData/Bookmarks", "store/jobs/j000008/out/tree/d1/f1.bin", "store/jobs/j000008/out/tree/$Bitmap", "store/jobs/j000008/stdout.log", "store/jobs/j000023/out/keys/k3.txt", "store/jobs/j000023/stdout.log"].map(withheld), [true, false, false, false, true, true]);
});

test("the index is brought up to date from what the journal gained: a sensitive commit of 20,000 files is taken in once, and the next decision takes under 50 ms", async (t) => {
  const o = await run();
  await commit(o, "j000001", { "k.txt": "a recovered value" }, { command: "extract", secret_output: true });
  await sensitiveIndex(o.S);
  const rebuilds = sensitiveIndexStats.rebuilds;

  // Lines that are not sensitive commits, one of them megabytes long: read past, not parsed, the journal not read again.
  const before = { ...sensitiveIndexStats };
  const size0 = statSync(storePaths(o.S).journal).size;
  await o.journal.append({ type: "job_same_as", job: "j000001", same: Array.from({ length: 40000 }, (_, i) => ({ path: `tree/some/long/path/of/a/file-${i}.dat`, as: `job:j000000/tree/some/long/path/of/a/file-${i}.dat` })) });
  for (let i = 0; i < 50; i += 1) await o.journal.append({ type: "job_started", job: `j1${String(i).padStart(5, "0")}`, attempt: 1 });
  let at = performance.now();
  const same = await sensitiveIndex(o.S);
  const pastMs = performance.now() - at;
  assert.deepEqual([...same.jobs.keys()], ["j000001"]);
  assert.equal(sensitiveIndexStats.rebuilds, rebuilds);
  assert.equal(sensitiveIndexStats.journal_bytes - before.journal_bytes, statSync(storePaths(o.S).journal).size - size0, "only the lines it gained");
  assert.equal(sensitiveIndexStats.manifests, before.manifests);

  // A sensitive job of 20,000 files, sealed (its manifest and its index, as a seal leaves them) and committed.
  const dir = join(storePaths(o.S).jobs, "j000002");
  mkdirSync(dir, { recursive: true });
  const files = Array.from({ length: 20000 }, (_, i) => {
    const path = `tree/Users/u${i % 20}/AppData/d${i % 300}/secret-${i}.bin`;
    return { path, path_b64: Buffer.from(path).toString("base64"), bytes: 100 + i, sha256: (i + 1).toString(16).padStart(64, "0"), mode: "644" };
  });
  writeFileSync(join(dir, "manifest.json"), `${JSON.stringify({ v: 1, job: "j000002", attempt: 1, sealed_at: "2026-11-13T00:00:00.000Z", files, dirs: [], rejected: [], totals: { files: files.length, bytes: 0 } })}\n`);
  await indexManifestFile(join(dir, "manifest.json"));
  await o.journal.append({ type: "job_committed", job: "j000002", attempt: 1, status: "ok", logs: {}, sensitive: ownSensitivity({ secret_output: true }) });
  // What JobService.record does after it writes a sensitive job_committed line: the commit is taken in then, its manifest read once.
  at = performance.now();
  await sensitiveIndex(o.S);
  const takenInMs = performance.now() - at;
  assert.equal(sensitiveIndexStats.manifests, before.manifests + 1, "the commit's own manifest, once");

  // The next job's decision: it sealed one file that is one of the 20,000.
  at = performance.now();
  const next = await jobSensitivity(o.S, { id: "j000003", spec: { command: "copy" } }, { outputs: [{ sha256: files[12345].sha256, path: "copied.bin" }, { sha256: "f".repeat(64), path: "own.bin" }] });
  const firstMs = performance.now() - at;
  at = performance.now();
  const again = await jobSensitivity(o.S, { id: "j000004", spec: { command: "other" } }, { outputs: [{ sha256: "e".repeat(64), path: "own.bin" }] });
  const secondMs = performance.now() - at;
  t.diagnostic(`past a ${((statSync(storePaths(o.S).journal).size - size0) / 1e6).toFixed(1)} MB of other lines in ${pastMs.toFixed(1)} ms; a 20,000-file sensitive commit taken in in ${takenInMs.toFixed(1)} ms, the decision after it ${firstMs.toFixed(2)} ms, the one after that ${secondMs.toFixed(2)} ms`);
  assert.deepEqual(next?.files, ["copied.bin"]);
  assert.deepEqual(next?.from, ["j000002"]);
  assert.equal(again, null);
  assert.equal(sensitiveIndexStats.rebuilds, rebuilds, "never read again from its start");
  assert.equal((await sensitiveIndex(o.S)).jobs.get("j000002")!.files.length, 20000);
  assert.ok(firstMs < 50, `the decision after the commit took ${firstMs.toFixed(1)} ms`);
  assert.ok(secondMs < 50);

  // A journal that is not the one the index was built from is read from its start.
  appendFileSync(storePaths(o.S).journal, "");
  writeFileSync(storePaths(o.S).journal, `${JSON.stringify({ type: "job_committed", job: "j000009", sensitive: { why: "secret_output", from: [], note: "n" } })}\n`);
  assert.deepEqual([...(await sensitiveIndex(o.S)).jobs.keys()], ["j000009"]);
  assert.equal(sensitiveIndexStats.rebuilds, rebuilds + 1);
});

test("a sensitive commit of 200,000 files is taken in when it is committed, as the job service does: the decision after it takes under 50 ms", async (t) => {
  const o = await run();
  await commit(o, "j000001", { "k.txt": "a recovered value" }, { command: "extract", secret_output: true });
  await sensitiveIndex(o.S);
  const dir = join(storePaths(o.S).jobs, "j000002");
  mkdirSync(dir, { recursive: true });
  const files = Array.from({ length: 200000 }, (_, i) => {
    const path = `tree/Users/u${i % 20}/AppData/d${i % 300}/secret-${i}.bin`;
    return { path, path_b64: Buffer.from(path).toString("base64"), bytes: 100 + i, sha256: (i + 1).toString(16).padStart(64, "0"), mode: "644" };
  });
  writeFileSync(join(dir, "manifest.json"), `${JSON.stringify({ v: 1, job: "j000002", attempt: 1, sealed_at: "2026-11-13T00:00:00.000Z", files, dirs: [], rejected: [], totals: { files: files.length, bytes: 0 } })}\n`);
  await indexManifestFile(join(dir, "manifest.json"));
  await o.journal.append({ type: "job_committed", job: "j000002", attempt: 1, status: "ok", logs: {}, sensitive: ownSensitivity({ secret_output: true }) });

  // What JobService.record does after it writes a sensitive job_committed line.
  let at = performance.now();
  await sensitiveIndex(o.S);
  const takenInMs = performance.now() - at;
  at = performance.now();
  const next = await jobSensitivity(o.S, { id: "j000003", spec: { command: "copy" } }, { outputs: [{ sha256: files[123456].sha256, path: "copied.bin" }, { sha256: "f".repeat(64), path: "own.bin" }] });
  const decisionMs = performance.now() - at;
  t.diagnostic(`a 200,000-file sensitive commit taken in at its commit in ${takenInMs.toFixed(0)} ms; the decision after it ${decisionMs.toFixed(2)} ms`);
  assert.deepEqual(next?.files, ["copied.bin"]);
  assert.equal((await sensitiveIndex(o.S)).jobs.get("j000002")!.files.length, 200000);
  assert.ok(decisionMs < 50, `the decision after the commit took ${decisionMs.toFixed(1)} ms`);
});
