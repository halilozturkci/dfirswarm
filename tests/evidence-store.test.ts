/**
 * The evidence-work store: the journal (chained, durable, repaired and
 * checked against its anchor), sealing a job's output (links and devices
 * left out, names kept as bytes, files read-only and stored once), object
 * references, and catalogue generations and revisions.
 */
import test from "node:test";
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import { existsSync, mkdtempSync, readFileSync, statSync } from "node:fs";
import { appendFile, mkdir, readFile, readdir, rm, symlink, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { Journal, appendNote, checkStore, initStore, publishGeneration, resealMoved, resolveRef, sealTree, storePaths, verifyJournalText } from "../scripts/evidence-store.ts";
import { chmodSync, writeFileSync } from "node:fs";

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

test("custody's look at the store: the chain and its anchor, every committed file against its manifest, staging left", async () => {
  const S = sandbox();
  await mkdir(S, { recursive: true });
  const P = storePaths(S);
  const j = await Journal.open(S);
  const staging = join(P.staging, "j000001-1", "out");
  await mkdir(staging, { recursive: true });
  await writeFile(join(staging, "a.txt"), "alpha");
  await writeFile(join(staging, "b.txt"), "beta");
  const { manifestSha256 } = await sealTree(S, staging, join(P.jobs, "j000001", "out"), "j000001", 1);
  await rm(join(P.staging, "j000001-1"), { recursive: true, force: true });
  await j.append({ type: "job_accepted", job: "j000001" });
  await j.append({ type: "job_committed", job: "j000001", outputs: { path: "store/jobs/j000001/out", manifest_sha256: manifestSha256 } });
  let c = await checkStore(S);
  assert.ok(c);
  assert.equal(c!.journal.intact, true);
  assert.equal(c!.journal.anchor, "matches");
  assert.deepEqual([c!.jobs, c!.committed, c!.outputs.files, c!.outputs.verified], [1, 1, 2, 2]);
  // A sealed file changed afterwards, and a job's staging left behind.
  const b = join(P.jobs, "j000001", "out", "b.txt");
  chmodSync(join(P.jobs, "j000001", "out"), 0o755);
  chmodSync(b, 0o644);
  writeFileSync(b, "BETA");
  await mkdir(join(P.staging, "j000002-1"), { recursive: true });
  c = await checkStore(S);
  assert.deepEqual(c!.outputs.mismatched, ["store/jobs/j000001/out/b.txt"]);
  assert.deepEqual(c!.staging_left, ["j000002-1"]);
  // The anchor one line behind (a crash between the two writes) is told apart from one off the chain.
  const lines = readFileSync(P.journal, "utf8").trimEnd().split("\n");
  const behind = createHashHex(lines[lines.length - 2]);
  await rm(P.anchor, { force: true });
  await writeFile(P.anchor, JSON.stringify({ head: behind, seq: lines.length - 2, at: "x" }));
  assert.equal((await checkStore(S))!.journal.anchor, "behind");
  await rm(P.anchor, { force: true });
  await writeFile(P.anchor, JSON.stringify({ head: "0".repeat(64), seq: 0, at: "x" }));
  assert.equal((await checkStore(S))!.journal.anchor, "off the chain");
  await mkdir(join(S, "ledger"), { recursive: true });
  await writeFile(join(S, "ledger", "entries.jsonl"), [
    { seq: 1, kind: "finding", source: "job:j000001/a.txt", evidence: "x" },
    { seq: 2, kind: "finding", source: "my notes", evidence: "I looked" },
    { seq: 3, kind: "event", source: "nothing" },
    { seq: 4, kind: "finding", source: "inputs", evidence: "sha256:" + "a".repeat(64) },
    { seq: 5, kind: "finding", source: "inputs/AF-Case2.E01 inode 126755", evidence: "icat" },
    { seq: 6, kind: "finding", source: "the image", evidence: "read store/jobs/j000012/out/sms.db" },
    { seq: 7, kind: "finding", source: "x", evidence: "y", refs: ["job:j000404/gone.txt"] },
    { seq: 8, kind: "finding", source: "x", evidence: "y", refs: ["unresolved:the page was only on screen"] },
    { seq: 9, kind: "finding", source: "x", evidence: "y" },
    { seq: 10, kind: "finding", source: "x", evidence: "y", refs: ["unresolved:checked later"], supersedes: 9 },
  ].map((e) => JSON.stringify(e)).join("\n") + "\n");
  assert.deepEqual((await checkStore(S))!.findings, { total: 8, structured: 3, refs_invalid: [7], unresolved_only: [8, 10], path_only: [1, 4, 5, 6], without_refs: [2], on_failed_jobs: [], sensitive: [], hypotheses: 0, limitations: 0, contradictions: [] }, "standing findings only (#9 is corrected by #10); refs resolved again; a path in prose counted apart; one that cites nothing named; none on a failed job, none sensitive, no hypotheses, limitations or contradictions");
});

function createHashHex(text: string): string {
  return createHash("sha256").update(text).digest("hex");
}

test("an examiner's note is chained onto the journal after the run, attributed, and refused while the hub runs", async () => {
  const S = sandbox();
  const j = await Journal.open(S);
  await j.append({ type: "job_fenced", job: "j000001", attempt: 1, fenced: true });
  await writeFile(join(S, "hub.pid"), `${process.pid}\n`);
  await assert.rejects(appendNote(S, { by: "examiner", text: "x" }), /hub \(pid \d+\) is the store's writer/);
  await writeFile(join(S, "hub.pid"), "999999999\n");
  const r = spawnSync(process.execPath, ["--experimental-strip-types", "--no-warnings", STORE, "note", S, "--by", "Claude (examiner)", "--text", "j000001's fence was false: msb listed the worker later.", "--job", "j000001"], { encoding: "utf8" });
  assert.equal(r.status, 0, r.stderr);
  const lines = verifyJournalText(readFileSync(storePaths(S).journal, "utf8"));
  assert.equal(lines.error, undefined);
  const note = lines.lines.at(-1)!;
  assert.deepEqual([note.type, note.by, note.jobs], ["note", "Claude (examiner)", ["j000001"]]);
  assert.equal(JSON.parse(spawnSync(process.execPath, ["--experimental-strip-types", "--no-warnings", STORE, "verify", S], { encoding: "utf8" }).stdout).ok, true, "the anchor moved with it");
  await assert.rejects(appendNote(S, { by: "", text: "x" }), /needs --by and --text/);
  const c = await checkStore(S);
  assert.equal(c!.notes, 1, "custody counts the notes on the record");
  assert.equal(c!.journal.intact, true);
});

test("a generation reads only the files of its job's sealed output: an index.tsv row that climbs out is named, not read", async () => {
  const S = sandbox();
  const journal = await initStore(S);
  const staging = join(S, "..", `stage-${Math.random()}`);
  await mkdir(staging, { recursive: true });
  await writeFile(join(staging, "coverage.json"), JSON.stringify({ status: "complete" }));
  await writeFile(join(staging, "list.tsv"), "a\nb\n");
  await writeFile(join(staging, "index.tsv"), "list.tsv\tthe list\n../../../../../../etc/passwd\tnot ours\nmissing.tsv\tnot there\n");
  await sealTree(S, staging, join(storePaths(S).jobs, "j000001", "out"), "j000001", 1);
  const { generation } = await publishGeneration(journal, { job: "j000001", recipe: "p/r", recipe_sha256: "x", target: { name: "obj", sha256: "a".repeat(64) }, trigger: "derived", parent_status: "failed" });
  assert.equal(generation.status, "complete");
  assert.deepEqual(generation.files.map((f) => [f.path, f.rows]), [[`catalog/gen/${generation.id}/list.tsv`, 2]]);
  assert.ok(generation.notes?.some((n) => n.includes('"../../../../../../etc/passwd", which is not a file of job j000001\'s sealed output: not read')), JSON.stringify(generation.notes));
  assert.equal(generation.trigger, "derived");
  assert.equal(generation.parent_status, "failed");
  const line = journal.of("generation_committed").at(-1)!;
  assert.equal((line.target as { sha256?: string }).sha256, "a".repeat(64), "the target's content is on the record");
  assert.equal(line.trigger, "derived");
});
