/**
 * A sealed manifest's head and index (scripts/manifest-index.ts): a ref, a
 * declared input and a directory are answered from a few blocks of the
 * index, never the manifest; the answers are the manifest's own; an index
 * that is missing or older than its manifest is made again; a store that
 * cannot be written to is answered from memory; a small manifest has no
 * index at all.
 *
 * The large case is a manifest of 200,000 files written by hand (no tree
 * behind it): what is measured is the reading.
 */
import test from "node:test";
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { chmodSync, existsSync, mkdirSync, mkdtempSync, readdirSync, rmSync, statSync, unlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import v8 from "node:v8";
import vm from "node:vm";
import { manifestNearNames, manifestOf, resolveRef, sealTree, storePaths, type Manifest } from "../scripts/evidence-store.ts";
import { resolveScope } from "../scripts/job-scope.ts";
import { forgetHeads, headPath, indexPath, indexStats } from "../scripts/manifest-index.ts";
import { checkRefs } from "../extensions/ledger-rules.ts";

const bases: string[] = [];
test.after(() => {
  for (const b of bases) {
    spawnSync("chmod", ["-R", "u+w", b]);
    rmSync(b, { recursive: true, force: true });
  }
});

v8.setFlagsFromString("--expose-gc");
const gc = vm.runInNewContext("gc") as () => void;

const FILES = 200000;
const sha = (i: number) => i.toString(16).padStart(64, "0");
const pathOf = (i: number) => `tree/Users/u${i % 50}/AppData/Local/d${i % 997}/file-${i}.dat`;

/** A store with one job whose manifest names 200,000 files, two of them with names that are not their paths. */
function large(): { S: string; manifestPath: string; under: Map<string, { files: number; bytes: number }> } {
  const b = mkdtempSync(join(tmpdir(), "manifest-index-"));
  bases.push(b);
  const S = join(b, "run");
  const dir = join(storePaths(S).jobs, "j000001");
  mkdirSync(dir, { recursive: true });
  const files: Manifest["files"] = [];
  const under = new Map<string, { files: number; bytes: number }>();
  let bytes = 0;
  for (let i = 0; i < FILES; i += 1) {
    const path = pathOf(i);
    files.push({ path, path_b64: Buffer.from(path).toString("base64"), bytes: i + 1, sha256: sha(i), mode: "644" });
    bytes += i + 1;
    const u = `tree/Users/u${i % 50}`;
    const sum = under.get(u) ?? { files: 0, bytes: 0 };
    sum.files += 1;
    sum.bytes += i + 1;
    under.set(u, sum);
  }
  // A backslash in a name is shown doubled; a byte that is not UTF-8 is shown as \xNN.
  files.push({ path: "tree/odd\\\\name.txt", path_b64: Buffer.from("tree/odd\\name.txt").toString("base64"), bytes: 3, sha256: "a".repeat(64), mode: "644" });
  files.push({ path: "tree/\\xff.bin", path_b64: Buffer.concat([Buffer.from("tree/"), Buffer.from([0xff]), Buffer.from(".bin")]).toString("base64"), bytes: 4, sha256: "b".repeat(64), mode: "644" });
  const manifest: Manifest = { v: 1, job: "j000001", attempt: 1, sealed_at: "2026-11-13T00:00:00.000Z", files, dirs: [{ path: "tree", path_b64: "dHJlZQ==" }], rejected: [], totals: { files: files.length, bytes: bytes + 7 } };
  const manifestPath = join(dir, "manifest.json");
  writeFileSync(manifestPath, `${JSON.stringify(manifest)}\n`);
  return { S, manifestPath, under };
}

test("with a manifest of 200,000 files a ref is resolved from under 1 MB of the index in under 20 ms, and a hundred of them leave the heap where it was", async (t) => {
  const { S, manifestPath, under } = large();
  const mb = (statSync(manifestPath).size / 1e6).toFixed(1);
  // A store sealed before the index existed: the first question makes it (in a thread of its own), and is answered.
  let at = performance.now();
  const missing = await resolveRef(S, "job:j000001/x/y");
  const builtMs = performance.now() - at;
  assert.deepEqual(missing, { ok: false, ref: "job:j000001/x/y", reason: "x/y is not in job j000001's manifest" });
  assert.ok(existsSync(headPath(manifestPath)) && existsSync(indexPath(manifestPath)));
  assert.ok(statSync(headPath(manifestPath)).size < 64 * 1024, "the head is small");

  // Cold in this process (no head in memory), then warm.
  forgetHeads();
  Object.assign(indexStats, { reads: 0, bytes: 0, builds: 0 });
  const cold = await resolveRef(S, `job:j000001/${pathOf(123456)}`);
  assert.deepEqual(cold, { ok: true, ref: `job:j000001/${pathOf(123456)}`, kind: "job", sha256: sha(123456), bytes: 123457, path: `store/jobs/j000001/out/${pathOf(123456)}` });
  const coldBytes = indexStats.bytes;
  assert.ok(coldBytes < 1024 * 1024, `${coldBytes} bytes read for the first ref`);
  gc();
  const heap0 = process.memoryUsage().heapUsed;
  const times: number[] = [];
  let most = 0;
  for (let k = 0; k < 100; k += 1) {
    const i = (k * 7919 + 13) % FILES;
    const before = indexStats.bytes;
    at = performance.now();
    const r = k % 10 === 9 ? await resolveRef(S, "job:j000001/x/y") : await resolveRef(S, `job:j000001/${k % 2 ? "out/" : ""}${pathOf(i)}`);
    times.push(performance.now() - at);
    most = Math.max(most, indexStats.bytes - before);
    if (k % 10 === 9) assert.ok(!r.ok);
    else assert.ok(r.ok && r.sha256 === sha(i) && r.bytes === i + 1 && r.path === `store/jobs/j000001/out/${pathOf(i)}`, pathOf(i));
  }
  gc();
  const grown = process.memoryUsage().heapUsed - heap0;
  times.sort((a, b) => a - b);
  t.diagnostic(`manifest ${mb} MB, index ${(statSync(indexPath(manifestPath)).size / 1e6).toFixed(1)} MB, made in ${Math.round(builtMs)} ms; a ref: ${coldBytes} bytes read cold, at most ${most} warm; median ${times[50].toFixed(2)} ms, slowest ${times[99].toFixed(2)} ms; heap ${(grown / 1e6).toFixed(1)} MB after 100`);
  assert.equal(indexStats.builds, 0, "made once");
  assert.ok(most < 1024 * 1024);
  assert.ok(times[50] < 20, `a ref took ${times[50].toFixed(1)} ms (median of 100)`);
  assert.ok(grown < 20 * 1024 * 1024, `the heap grew ${(grown / 1e6).toFixed(1)} MB over 100 refs`);

  // The whole output, a directory and a file as a job declares them: the head and the index's directory lines.
  const whole = await resolveRef(S, "job:j000001");
  assert.ok(whole.ok && whole.bytes === (FILES * (FILES + 1)) / 2 + 7);
  const scope = await resolveScope(S, ["job:j000001/tree/Users/u7", `job:j000001/${pathOf(7)}`, "job:j000001"]);
  assert.ok(scope.ok, (scope as { reason?: string }).reason);
  const objects = (scope as { objects: Array<{ path: string; shape: string; files?: number; bytes?: number; sha256?: string }> }).objects;
  assert.deepEqual(objects.map((o) => [o.path, o.shape, o.files, o.bytes, o.sha256]), [
    ["store/jobs/j000001/out/tree/Users/u7", "dir", under.get("tree/Users/u7")!.files, under.get("tree/Users/u7")!.bytes, undefined],
    [`store/jobs/j000001/out/${pathOf(7)}`, "file", undefined, 8, sha(7)],
    ["store/jobs/j000001/out", "dir", FILES + 2, (FILES * (FILES + 1)) / 2 + 7, undefined],
  ]);
  const gone = await resolveScope(S, ["job:j000001/tree/Users/u7x"]);
  assert.ok(!gone.ok && /tree\/Users\/u7x is not in job j000001's manifest/.test(gone.reason));
  const view = (await manifestOf(manifestPath))!;
  assert.deepEqual(view.head.top, [{ name: "tree", kind: "dir", files: FILES + 2, bytes: (FILES * (FILES + 1)) / 2 + 7 }]);
  assert.deepEqual(view.head.first[0], { path: pathOf(0), bytes: 1, sha256: sha(0) });
  assert.equal(view.head.odd_names, 1);
  assert.equal(await view.dir("tree/Users/u7/AppData/Local/d7/file-7.dat"), null, "a file is not a directory");

  // A name as its bytes read, where that is not the path the manifest shows.
  const odd = await resolveRef(S, "job:j000001/tree/odd\\name.txt");
  assert.ok(odd.ok && odd.sha256 === "a".repeat(64) && odd.path === "store/jobs/j000001/out/tree/odd\\\\name.txt");
  const shown = await resolveRef(S, "job:j000001/tree/odd\\\\name.txt");
  assert.ok(shown.ok && shown.sha256 === "a".repeat(64));
  const notUtf8 = await resolveRef(S, "job:j000001/tree/�.bin");
  assert.ok(notUtf8.ok && notUtf8.sha256 === "b".repeat(64), "found in the manifest itself, which alone holds the bytes");

  // A typo: the names nearest to it, read from the index.
  at = performance.now();
  const near = await manifestNearNames(manifestPath, "tree/Users/u7/AppData/Local/d7/fiel-7.dat");
  t.diagnostic(`nearest names over ${FILES} files in ${Math.round(performance.now() - at)} ms`);
  assert.equal(near[0], pathOf(7));
  assert.ok(near.length > 1 && near.every((p) => p.startsWith("tree/Users/u7/AppData/Local/d7/")));
  assert.equal((await manifestNearNames(manifestPath, "tree/Users/u8/AppData/Local/d7/file-7.dat"))[0], pathOf(7), "the same last name elsewhere in the tree");

  // A manifest that is not the one the head names: the index is made again from it.
  const changed = JSON.stringify({ v: 1, job: "j000001", attempt: 1, sealed_at: "2026-11-13T00:00:01.000Z", files: Array.from({ length: 3000 }, (_, i) => ({ path: `n/f${i}`, path_b64: Buffer.from(`n/f${i}`).toString("base64"), bytes: 2, sha256: sha(i + 5), mode: "644" })), dirs: [], rejected: [], totals: { files: 3000, bytes: 6000 } });
  writeFileSync(manifestPath, `${changed}\n`);
  const after = await resolveRef(S, "job:j000001/n/f2999");
  assert.ok(after.ok && after.sha256 === sha(3004));
  assert.ok(!(await resolveRef(S, `job:j000001/${pathOf(7)}`)).ok);
  assert.equal(indexStats.builds, 1);

  // A store that cannot be written to and has no index: answered from the manifest, nothing left beside it.
  unlinkSync(headPath(manifestPath));
  unlinkSync(indexPath(manifestPath));
  forgetHeads();
  chmodSync(join(storePaths(S).jobs, "j000001"), 0o555);
  try {
    const ro = await resolveRef(S, "job:j000001/n/f17");
    assert.ok(ro.ok && ro.sha256 === sha(22));
    assert.deepEqual(readdirSync(join(storePaths(S).jobs, "j000001")), ["manifest.json"]);
  } finally {
    chmodSync(join(storePaths(S).jobs, "j000001"), 0o755);
  }
});

test("a small manifest has no index and is read whole; the refusal of a typo still names the nearest", async () => {
  const b = mkdtempSync(join(tmpdir(), "manifest-index-small-"));
  bases.push(b);
  const S = join(b, "run");
  mkdirSync(join(b, "staging", "report"), { recursive: true });
  writeFileSync(join(b, "staging", "report", "out.txt"), "the result");
  writeFileSync(join(b, "staging", "report", "rows.csv"), "a,b\n");
  await sealTree(S, join(b, "staging"), join(storePaths(S).jobs, "j000001", "out"), "j000001", 1);
  assert.deepEqual(readdirSync(join(storePaths(S).jobs, "j000001")).sort(), ["manifest.json", "out"]);
  const ok = await resolveRef(S, "job:j000001/report/out.txt");
  assert.ok(ok.ok && ok.bytes === 10);
  assert.ok((await resolveRef(S, "job:j000001/out/report/out.txt")).ok);
  const typo = await checkRefs(S, ["job:j000001/report/out.tx"]);
  assert.ok(!typo.ok && /is not in job j000001's manifest; nearest: job:j000001\/report\/out\.txt/.test(typo.reason), (typo as { reason: string }).reason);
  assert.deepEqual(await manifestNearNames(join(storePaths(S).jobs, "j000001", "manifest.json"), "report/out.tx"), ["report/out.txt", "report/rows.csv"]);
  const scope = await resolveScope(S, ["job:j000001/report"]);
  assert.ok(scope.ok && scope.objects[0].files === 2 && scope.objects[0].bytes === 14);
  assert.deepEqual(readdirSync(join(storePaths(S).jobs, "j000001")).sort(), ["manifest.json", "out"], "nothing was written beside it");
});
