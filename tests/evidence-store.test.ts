/**
 * The evidence-work store: the journal (chained, durable, repaired and
 * checked against its anchor), sealing a job's output (links and devices
 * left out, names kept as bytes, files read-only and stored once), object
 * references, and catalogue generations and revisions.
 */
import test from "node:test";
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { existsSync, mkdtempSync, readFileSync, statSync } from "node:fs";
import { appendFile, mkdir, readFile, readdir, rm, symlink, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { Journal, initStore, publishGeneration, resealMoved, resolveRef, sealTree, storePaths, verifyJournalText } from "../scripts/evidence-store.ts";

const STORE = join(import.meta.dirname, "..", "scripts", "evidence-store.ts");

function sandbox(): string {
  const S = join(mkdtempSync(join(tmpdir(), "evstore-")), "run");
  return S;
}

test("the journal chains every line, fsyncs it, moves its anchor, and a reopen continues the chain", async () => {
  const S = sandbox();
  await mkdir(S, { recursive: true });
  const j = await Journal.open(S);
  await j.append({ type: "a", n: 1 });
  await j.append({ type: "b", n: 2 });
  const text = await readFile(storePaths(S).journal, "utf8");
  const checked = verifyJournalText(text);
  assert.equal(checked.error, undefined);
  assert.equal(checked.lines.length, 2);
  const anchor = JSON.parse(readFileSync(storePaths(S).anchor, "utf8"));
  assert.equal(anchor.head, checked.head);
  assert.equal(anchor.seq, 1);
  const again = await Journal.open(S);
  await again.append({ type: "c" });
  const after = verifyJournalText(await readFile(storePaths(S).journal, "utf8"));
  assert.equal(after.error, undefined);
  assert.deepEqual(after.lines.map((l) => l.type), ["a", "b", "c"], "no repair and no mismatch on a clean reopen");
  const v = spawnSync(process.execPath, ["--experimental-strip-types", STORE, "verify", S], { encoding: "utf8" });
  assert.equal(v.status, 0, v.stdout + v.stderr);
});

test("a line cut short by a crash is kept byte for byte, the journal cut back, and the repair recorded", async () => {
  const S = sandbox();
  await mkdir(S, { recursive: true });
  const j = await Journal.open(S);
  await j.append({ type: "a" });
  await appendFile(storePaths(S).journal, '{"v":1,"seq":1,"at":"x","type":"half');
  const reopened = await Journal.open(S);
  const types = reopened.lines.map((l) => l.type);
  assert.deepEqual(types, ["a", "anchor_mismatch", "journal_repaired"].filter((t) => t !== "anchor_mismatch" || types.includes("anchor_mismatch")));
  const repair = reopened.of("journal_repaired")[0];
  assert.ok(repair, "the repair is an event");
  const saved = join(S, String(repair.saved_as));
  assert.equal(readFileSync(saved, "utf8"), '{"v":1,"seq":1,"at":"x","type":"half', "the cut bytes are kept, not dropped");
  assert.equal(verifyJournalText(await readFile(storePaths(S).journal, "utf8")).error, undefined, "the journal chains again");
});

test("an anchor that disagrees with the journal is recorded when the journal is opened", async () => {
  const S = sandbox();
  await mkdir(S, { recursive: true });
  const j = await Journal.open(S);
  await j.append({ type: "a" });
  await rm(storePaths(S).anchor, { force: true });
  await writeFile(storePaths(S).anchor, JSON.stringify({ head: "f".repeat(64), seq: 7, at: "then" }));
  const reopened = await Journal.open(S);
  const m = reopened.of("anchor_mismatch")[0];
  assert.ok(m, "the mismatch is an event");
  assert.equal(m.anchor_seq, 7);
  assert.equal(m.journal_seq, 0);
});

test("sealing leaves out links, FIFOs and sockets, keeps names as bytes, makes everything read-only and stores the same bytes once", async () => {
  const S = sandbox();
  await mkdir(S, { recursive: true });
  const P = storePaths(S);
  const staging = join(P.staging, "j1", "out");
  await mkdir(join(staging, "sub"), { recursive: true });
  await writeFile(join(staging, "a.txt"), "same bytes");
  await writeFile(join(staging, "sub", "two\nlines.txt"), "x");
  // APFS refuses a name that is not UTF-8 (EILSEQ), so a worker on a Mac
  // cannot make one; on Linux it can, and the manifest keeps its bytes.
  let badName = true;
  await writeFile(Buffer.concat([Buffer.from(staging + "/bad-"), Buffer.from([0xff, 0xfe])]), "not utf-8").catch((err: NodeJS.ErrnoException) => {
    if (err.code !== "EILSEQ") throw err;
    badName = false;
  });
  await symlink("/etc/passwd", join(staging, "link"));
  spawnSync("mkfifo", [join(staging, "fifo")]);
  const dest = join(P.jobs, "j1", "out");
  const { manifest, manifestSha256 } = await sealTree(S, staging, dest, "j1", 1);
  assert.equal(manifestSha256.length, 64);
  assert.deepEqual(manifest.files.map((f) => f.path).sort(), ["a.txt", ...(badName ? ["bad-\\xff\\xfe"] : []), "sub/two\\nlines.txt"]);
  if (badName) {
    const bad = manifest.files.find((f) => f.path.startsWith("bad-"))!;
    assert.deepEqual(Buffer.from(bad.path_b64, "base64"), Buffer.from([0x62, 0x61, 0x64, 0x2d, 0xff, 0xfe]), "the exact name bytes are kept");
  }
  assert.equal(Buffer.from(manifest.files.find((f) => f.path.startsWith("sub/"))!.path_b64, "base64").toString(), "sub/two\nlines.txt");
  assert.deepEqual(manifest.rejected.map((r) => [r.path, r.kind]).sort(), [["fifo", "fifo"], ["link", "symlink"]]);
  assert.equal(manifest.rejected.find((r) => r.kind === "symlink")!.link, "/etc/passwd");
  assert.ok(!existsSync(join(dest, "link")) && !existsSync(join(dest, "fifo")), "a link or a FIFO never reaches the store");
  assert.equal(statSync(join(dest, "a.txt")).mode & 0o777, 0o444);
  assert.equal(statSync(dest).mode & 0o777, 0o555);
  const a = manifest.files.find((f) => f.path === "a.txt")!;
  assert.equal(statSync(join(P.blobs, a.sha256)).ino, statSync(join(dest, "a.txt")).ino, "the file is its blob");
  // A second job with the same bytes: the same blob, one copy on disk.
  const staging2 = join(P.staging, "j2", "out");
  await mkdir(staging2, { recursive: true });
  await writeFile(join(staging2, "copy.txt"), "same bytes");
  await sealTree(S, staging2, join(P.jobs, "j2", "out"), "j2", 1);
  assert.equal(statSync(join(P.jobs, "j2", "out", "copy.txt")).ino, statSync(join(P.blobs, a.sha256)).ino, "bytes are stored once");
  assert.ok(existsSync(join(P.jobs, "j1", "manifest.json")));
});

test("a crash after the move is recovered by sealing the moved tree again", async () => {
  const S = sandbox();
  await mkdir(S, { recursive: true });
  const P = storePaths(S);
  const staging = join(P.staging, "j9", "out");
  await mkdir(staging, { recursive: true });
  await writeFile(join(staging, "r.txt"), "result");
  const dest = join(P.jobs, "j9", "out");
  const script = `import { sealTree } from ${JSON.stringify(STORE)}; await sealTree(${JSON.stringify(S)}, ${JSON.stringify(staging)}, ${JSON.stringify(dest)}, "j9", 1);`;
  const r = spawnSync(process.execPath, ["--experimental-strip-types", "--input-type=module", "-e", script], { encoding: "utf8", env: { ...process.env, SWARM_JOB_CRASH_AT: "seal:moved" } });
  assert.equal(r.status, 99, r.stderr);
  assert.ok(existsSync(dest) && !existsSync(join(P.jobs, "j9", "manifest.json")), "moved, not yet sealed");
  const { manifest } = await resealMoved(S, dest, "j9", 1);
  assert.deepEqual(manifest.files.map((f) => f.path), ["r.txt"]);
  assert.ok(existsSync(join(P.jobs, "j9", "manifest.json")));
});

test("object references resolve against inputs.json, sealed manifests, member lists and the store", async () => {
  const S = sandbox();
  await mkdir(S, { recursive: true });
  const P = storePaths(S);
  await writeFile(join(S, "inputs.json"), JSON.stringify({ files: [{ path: "inputs/disk.E01", sha256: "a".repeat(64), bytes: 10 }] }));
  const staging = join(P.staging, "j3", "out");
  await mkdir(staging, { recursive: true });
  await writeFile(join(staging, "sms.db"), "SQLite");
  const { manifest } = await sealTree(S, staging, join(P.jobs, "j3", "out"), "j3", 1);
  const sha = manifest.files[0].sha256;
  await mkdir(join(P.gen, "g0001"), { recursive: true });
  await writeFile(join(P.gen, "g0001", "members.tsv"), "n\ttype\n0\tfile\n1\tfile\n");
  const ok = async (ref: string) => {
    const r = await resolveRef(S, ref);
    assert.ok(r.ok, `${ref}: ${!r.ok ? r.reason : ""}`);
    return r;
  };
  assert.equal((await ok("input:disk.E01")).sha256, "a".repeat(64));
  assert.equal((await ok("input:inputs/disk.E01")).kind, "input");
  assert.equal((await ok("job:j3/sms.db")).sha256, sha);
  assert.equal((await ok(`sha256:${sha}`)).path, `store/blobs/${sha}`);
  assert.equal((await ok("member:g0001#1")).kind, "member");
  assert.equal((await ok("unresolved:the file was carved by hand")).kind, "unresolved");
  for (const bad of ["input:nope.E01", "job:j3/other", "job:../x/y", "member:g0001#9", "sha256:1234", "unresolved:", "http:x", "no-colon"]) {
    const r = await resolveRef(S, bad);
    assert.equal(r.ok, false, `${bad} should not resolve`);
  }
});

test("a recipe job's output becomes a generation, linked at its compatibility path, and each change a new revision", async () => {
  const S = sandbox();
  await mkdir(join(S, "catalog"), { recursive: true });
  await writeFile(join(S, "catalog", "coverage.tsv"), "input\tbytes\tstatus\twhy\n");
  await writeFile(join(S, "catalog", "plan.json"), JSON.stringify({ recipes: [{ input: "inputs/d.E01", target: { paths: [join(S, "inputs/d.E01"), join(S, "inputs/d.E02")] } }] }));
  const j = await initStore(S);
  assert.deepEqual(j.lines.map((l) => l.type), ["store_opened", "input_collection", "revision_published"]);
  assert.deepEqual(j.of("input_collection")[0].members, ["inputs/d.E01", "inputs/d.E02"], "a segment set is recorded as one ordered collection");
  assert.ok(existsSync(join(S, "catalog", "revisions", "0", "MANIFEST.json")));
  const P = storePaths(S);
  const staging = join(P.staging, "j4", "out");
  await mkdir(join(staging, "p0"), { recursive: true });
  await writeFile(join(staging, "p0", "filelist.txt"), "r/r 5: a\nr/r 6: b\n");
  await writeFile(join(staging, "index.tsv"), "p0/filelist.txt\tpath list\n");
  await writeFile(join(staging, "coverage.json"), JSON.stringify({ status: "complete", covered: "one volume", not_covered: "contents" }));
  await sealTree(S, staging, join(P.jobs, "j4", "out"), "j4", 1);
  const { generation, revision } = await publishGeneration(j, { job: "j4", recipe: "computer-forensics-base/disk-volumes", recipe_sha256: "b".repeat(64), target: { name: "inputs/d.E01", ref: "input:d.E01" }, alias: "catalog/d.E01" });
  assert.equal(generation.id, "g0001");
  assert.equal(revision, 1);
  assert.equal(generation.status, "complete");
  assert.deepEqual(generation.files, [{ path: "catalog/gen/g0001/p0/filelist.txt", what: "path list", rows: 2, bytes: 18 }]);
  assert.equal(readFileSync(join(S, "catalog", "d.E01", "p0", "filelist.txt"), "utf8"), "r/r 5: a\nr/r 6: b\n", "the kickoff path still holds the file list");
  const index = JSON.parse(readFileSync(join(S, "catalog", "revisions", "1", "index.json"), "utf8"));
  assert.deepEqual(index.generations.map((g: { id: string }) => g.id), ["g0001"]);
  assert.deepEqual((await readdir(join(S, "catalog", "revisions"))).sort(), ["0", "1"], "a revision is a new directory, never a renamed pointer");
  assert.match(readFileSync(join(S, "catalog", "revisions", "1", "index.md"), "utf8"), /g0001: computer-forensics-base\/disk-volumes over inputs\/d.E01 — complete/);
});
