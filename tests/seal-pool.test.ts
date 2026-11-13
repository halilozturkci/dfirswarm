/**
 * Sealing a large tree (evidence-store.ts sealTree, seal-worker.ts): the
 * files are hashed in worker threads and the manifest is the one the
 * one-thread seal writes, byte for byte; the sealing process keeps its
 * timers; a seal that is killed goes on from its record and hashes only
 * what it had not finished; two seals that keep the same bytes at the same
 * moment both end with one blob.
 *
 * The first test prints what it measured (files per second each way, the
 * ratio, the longest a timer was late), so a run says how the machine did.
 */
import test from "node:test";
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { chmodSync, existsSync, mkdirSync, mkdtempSync, readdirSync, readFileSync, rmSync, statSync, symlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { resealMoved, resolveRef, sealDirOf, sealTree, storePaths, type SealProgress } from "../scripts/evidence-store.ts";
import { headPath, indexPath } from "../scripts/manifest-index.ts";

const STORE = join(import.meta.dirname, "..", "scripts", "evidence-store.ts");
const FILES = 20000;
const bases: string[] = [];

test.after(() => {
  for (const b of bases) {
    spawnSync("chmod", ["-R", "u+w", b]);
    rmSync(b, { recursive: true, force: true });
  }
});

function base(): string {
  const b = mkdtempSync(join(tmpdir(), "seal-pool-"));
  bases.push(b);
  return b;
}

/**
 * The same tree every time: `files` small files in directories of a
 * hundred, every tenth one bytes another file has, two with modes of their
 * own, a name with a backslash and one outside ASCII, an empty directory
 * and a link (which a seal leaves out and records).
 */
function tree(root: string, files = FILES): void {
  for (let i = 0; i < files; i += 1) {
    const d = join(root, `d${String(Math.floor(i / 100)).padStart(3, "0")}`);
    if (i % 100 === 0) mkdirSync(d, { recursive: true });
    const bytes = i % 10 === 9 ? Buffer.alloc(300, i % 7) : Buffer.concat([Buffer.from(`file ${i}\n`), Buffer.alloc(500, i % 251)]);
    writeFileSync(join(d, `f${i}.bin`), bytes);
  }
  writeFileSync(join(root, "d000", "back\\slash.txt"), "a name with a backslash");
  writeFileSync(join(root, "d000", "çağrı.txt"), "a name outside ASCII");
  writeFileSync(join(root, "d000", "empty"), "");
  chmodSync(join(root, "d000", "f0.bin"), 0o600);
  chmodSync(join(root, "d000", "f1.bin"), 0o755);
  mkdirSync(join(root, "nothing-here"));
  symlinkSync("/etc/hosts", join(root, "d000", "link"));
}

const sealedAt = (text: string) => text.replace(/"sealed_at":"[^"]+"/, '"sealed_at":"-"');

test("a large tree is hashed in worker threads: the same manifest as one thread writes, several times sooner, and the process keeps its timers", async (t) => {
  const b = base();
  const one = join(b, "one");
  const pool = join(b, "pool");
  tree(join(one, "staging"));
  tree(join(pool, "staging"));
  // One thread, one file after another: the seal as it was.
  let at = Date.now();
  const first = await sealTree(one, join(one, "staging"), join(storePaths(one).jobs, "j1", "out"), "j1", 1, undefined, { workers: 0 });
  const oneMs = Date.now() - at;
  assert.equal(first.seal.workers, 0);
  // The pool, with a timer running beside it.
  let late = 0;
  let last = performance.now();
  const timer = setInterval(() => {
    const now = performance.now();
    late = Math.max(late, now - last - 20);
    last = now;
  }, 20);
  const seen: SealProgress[] = [];
  at = Date.now();
  const second = await sealTree(pool, join(pool, "staging"), join(storePaths(pool).jobs, "j1", "out"), "j1", 1, undefined, { onProgress: (p) => seen.push(p) });
  const poolMs = Date.now() - at;
  clearInterval(timer);
  const total = FILES + 3;
  t.diagnostic(`${total} files: one thread ${oneMs} ms (${Math.round((total * 1000) / oneMs)} files/s), ${second.seal.workers} workers ${poolMs} ms (${Math.round((total * 1000) / poolMs)} files/s), ${(oneMs / poolMs).toFixed(1)} times sooner; a 20 ms timer was at most ${Math.round(late)} ms late`);
  assert.ok(second.seal.workers >= 1, "hashed in worker threads");
  assert.equal(second.seal.hashed, total);

  // The manifest: the same bytes, in the order the tree is walked.
  const a = readFileSync(join(storePaths(one).jobs, "j1", "manifest.json"), "utf8");
  const c = readFileSync(join(storePaths(pool).jobs, "j1", "manifest.json"), "utf8");
  assert.equal(sealedAt(c), sealedAt(a));
  assert.equal(c, `${JSON.stringify(second.manifest)}\n`, "written a piece at a time, the bytes JSON.stringify gives");
  assert.equal(second.manifest.totals.files, total);
  assert.deepEqual(second.manifest.rejected.map((r) => [r.path, r.kind, r.link]), [["d000/link", "symlink", "/etc/hosts"]]);
  assert.equal(second.manifest.files.find((f) => f.path === "d000/f0.bin")?.mode, "600");
  assert.equal(second.manifest.files.find((f) => f.path === "d000/f1.bin")?.mode, "755");
  assert.ok(second.manifest.files.some((f) => f.path === "d000/back\\\\slash.txt"));
  assert.ok(second.manifest.dirs.some((d) => d.path === "nothing-here"));

  // The tree: read-only, each file's bytes kept once.
  const out = join(storePaths(pool).jobs, "j1", "out");
  assert.equal(statSync(join(out, "d000", "f0.bin")).mode & 0o777, 0o444);
  assert.equal(statSync(join(out, "d000")).mode & 0o777, 0o555);
  const blob = (sha: string) => statSync(join(storePaths(pool).blobs, sha)).ino;
  for (const f of [second.manifest.files[0], second.manifest.files[9], second.manifest.files[19], second.manifest.files[total - 1]]) assert.equal(statSync(join(out, f.path.replace("\\\\", "\\"))).ino, blob(f.sha256), `${f.path} is its blob`);
  assert.equal(new Set(second.manifest.files.map((f) => f.sha256)).size, readdirSync(storePaths(pool).blobs).length, "one blob for each content");
  // Its record is gone, its head and index are there, and a ref resolves from them.
  assert.ok(!existsSync(sealDirOf(out)));
  assert.ok(existsSync(headPath(join(storePaths(pool).jobs, "j1", "manifest.json"))) && existsSync(indexPath(join(storePaths(pool).jobs, "j1", "manifest.json"))));
  const r = await resolveRef(pool, "job:j1/d199/f19999.bin");
  assert.ok(r.ok && r.sha256 === second.manifest.files.find((f) => f.path === "d199/f19999.bin")?.sha256);

  // What it told: every phase, the count never falling, all of it at the end.
  assert.deepEqual([...new Set(seen.map((p) => p.phase))], ["walk", "move", "hash", "manifest", "done"]);
  assert.ok(seen.every((p, i) => i === 0 || p.files_done >= seen[i - 1].files_done));
  assert.equal(seen.at(-1)?.files_done, total);
  assert.equal(seen.at(-1)?.bytes_done, second.manifest.totals.bytes);
  assert.ok(seen.filter((p) => p.phase === "hash").length >= 3, "told while hashing, not only at the ends");

  assert.ok(late < 500, `a timer in the sealing process was ${Math.round(late)} ms late`);
  // How many times sooner depends on the file system: each file is one link into store/blobs, and where
  // that link is slow and one at a time for the whole volume (APFS: about 0.15 ms each, measured 3 to 3.5
  // times sooner over 20,003 files) it is most of what is left. Held here to half as long again, on a loaded machine too; the line above says what it was.
  assert.ok(oneMs / poolMs >= 1.5, `the pool sealed ${(oneMs / poolMs).toFixed(1)} times sooner than one thread (${oneMs} ms, ${poolMs} ms)`);
});

test("a seal killed three quarters of the way goes on from its record: the files it had not finished are hashed, and the manifest is the one it would have written", async (t) => {
  const b = base();
  const S = join(b, "run");
  const whole = join(b, "whole");
  tree(join(S, "staging"));
  tree(join(whole, "staging"));
  const dest = join(storePaths(S).jobs, "j1", "out");
  const stopAt = Math.floor(FILES * 0.75);
  const script = `import { sealTree } from ${JSON.stringify(STORE)}; await sealTree(${JSON.stringify(S)}, ${JSON.stringify(join(S, "staging"))}, ${JSON.stringify(dest)}, "j1", 1, undefined, { workers: 4 });`;
  const r = spawnSync(process.execPath, ["--experimental-strip-types", "--input-type=module", "-e", script], { encoding: "utf8", env: { ...process.env, SWARM_JOB_CRASH_AT: `seal:hashed:${stopAt}` } });
  assert.equal(r.status, 99, r.stderr);
  assert.ok(existsSync(dest) && !existsSync(join(storePaths(S).jobs, "j1", "manifest.json")), "moved, not sealed");
  const progress = JSON.parse(readFileSync(join(sealDirOf(dest), "progress.json"), "utf8")) as SealProgress;
  assert.equal(progress.phase, "hash");
  assert.equal(progress.files_total, FILES + 3);
  const again = await resealMoved(S, dest, "j1", 1, undefined, { workers: 4 });
  t.diagnostic(`killed at ${stopAt} of ${FILES + 3}: ${again.seal.resumed} taken from the record, ${again.seal.hashed} hashed again`);
  assert.ok(again.seal.resumed >= stopAt, `${again.seal.resumed} files were not hashed again`);
  assert.ok(again.seal.hashed <= FILES + 3 - stopAt + 4, `${again.seal.hashed} files hashed after the kill: at most the quarter left and the one each worker was on`);
  assert.equal(again.seal.resumed + again.seal.hashed, FILES + 3);
  // The manifest an uninterrupted seal of the same tree writes: the modes the job left, the link it left out.
  const full = await sealTree(whole, join(whole, "staging"), join(storePaths(whole).jobs, "j1", "out"), "j1", 1);
  assert.equal(sealedAt(readFileSync(join(storePaths(S).jobs, "j1", "manifest.json"), "utf8")), sealedAt(readFileSync(join(storePaths(whole).jobs, "j1", "manifest.json"), "utf8")));
  assert.equal(again.manifest.rejected.length, 1);
  assert.ok(!existsSync(sealDirOf(dest)));
  // Every file is what its manifest says, the resumed ones too.
  const { createHash } = await import("node:crypto");
  for (const f of again.manifest.files.filter((_, i) => i % 997 === 0)) assert.equal(createHash("sha256").update(readFileSync(join(dest, Buffer.from(f.path_b64, "base64").toString()))).digest("hex"), f.sha256, f.path);
});

test("a tree moved by a seal that left no record is sealed whole, where it stands", async () => {
  const b = base();
  const S = join(b, "run");
  tree(join(S, "staging"), 300);
  const dest = join(storePaths(S).jobs, "j1", "out");
  const script = `import { sealTree } from ${JSON.stringify(STORE)}; await sealTree(${JSON.stringify(S)}, ${JSON.stringify(join(S, "staging"))}, ${JSON.stringify(dest)}, "j1", 1);`;
  const r = spawnSync(process.execPath, ["--experimental-strip-types", "--input-type=module", "-e", script], { encoding: "utf8", env: { ...process.env, SWARM_JOB_CRASH_AT: "seal:moved" } });
  assert.equal(r.status, 99, r.stderr);
  rmSync(sealDirOf(dest), { recursive: true, force: true });
  const again = await resealMoved(S, dest, "j1", 1);
  assert.equal(again.seal.resumed, 0);
  assert.equal(again.manifest.totals.files, 303);
  assert.ok(!existsSync(`${dest}.reseal`) && !existsSync(sealDirOf(dest)));
});

test("two seals that keep the same bytes at the same moment both end, with one blob and every file a link to it", async () => {
  const b = base();
  const S = join(b, "run");
  tree(join(S, "s1"), 1500);
  tree(join(S, "s2"), 1500);
  const [x, y] = await Promise.all([
    sealTree(S, join(S, "s1"), join(storePaths(S).jobs, "j1", "out"), "j1", 1, undefined, { workers: 3 }),
    sealTree(S, join(S, "s2"), join(storePaths(S).jobs, "j2", "out"), "j2", 1, undefined, { workers: 3 }),
  ]);
  assert.deepEqual(x.manifest.files.map((f) => [f.path, f.sha256]), y.manifest.files.map((f) => [f.path, f.sha256]));
  assert.equal(readdirSync(storePaths(S).blobs).length, new Set(x.manifest.files.map((f) => f.sha256)).size);
  for (const f of x.manifest.files) {
    const ino = statSync(join(storePaths(S).blobs, f.sha256)).ino;
    const rel = Buffer.from(f.path_b64, "base64").toString();
    assert.equal(statSync(join(storePaths(S).jobs, "j1", "out", rel)).ino, ino, `j1 ${f.path}`);
    assert.equal(statSync(join(storePaths(S).jobs, "j2", "out", rel)).ino, ino, `j2 ${f.path}`);
  }
});
