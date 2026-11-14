/**
 * A package made with --redact holds none of what a sensitive ledger entry
 * says, nor the objects it cites, and every chain it carries still walks:
 * a redacted line keeps its own hash, which the next line names. The
 * package's verify re-walks the trace, the ledger, its attestations and the
 * journal against the custody verdict's seal, recomputing every entry's core
 * a redaction left readable; holds every packaged work/ file to the index
 * custody sealed; walks the examiner's review; and fails on a part that is
 * missing and not declared absent.
 */
import test, { after } from "node:test";
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { spawnSync } from "node:child_process";
import { appendFileSync } from "node:fs";
import { chmod, cp, mkdir, mkdtemp, readFile, readdir, rm, stat, symlink, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { disputeEntry, initSandbox, recordEntry, type LedgerEntry } from "../extensions/protocol.ts";
import { copySweepLists, hygieneReport, ledgerChain, makeDigestReplacer, packSessions, redactPackage, type Replaced, SESSIONS_ARCHIVE, SESSIONS_MANIFEST, type SessionsManifest, verifyPackage, verifySessions, writeComponents } from "../scripts/package-tools.ts";
import { takeCustody } from "../scripts/custody.ts";
import { T, fixtureFiles, hubLine, jl, traceRow, writeFiles } from "./sensitive-access-fixture.ts";
import { sealTree, storePaths } from "../scripts/evidence-store.ts";
import { appendReview } from "../scripts/review.ts";

const dirs: string[] = [];
after(async () => {
  // A sealed job output is read-only, as the store leaves it.
  for (const d of dirs) {
    spawnSync("chmod", ["-R", "u+w", d]);
    await rm(d, { recursive: true, force: true });
  }
});
const sha = (s: string | Buffer) => createHash("sha256").update(s).digest("hex");
const SECRET = "123456-654321-111222-333444-555666-777888-999000-121212";

function chained(objs: unknown[]): string {
  let prev = "";
  let out = "";
  for (const o of objs) {
    const line = JSON.stringify({ ...(o as Record<string, unknown>), prev });
    out += `${line}\n`;
    prev = sha(line);
  }
  return out;
}

async function packaged(): Promise<{ root: string; pkg: string }> {
  const root = await mkdtemp(join(tmpdir(), "pkg-tools-"));
  dirs.push(root);
  await initSandbox(root, { reset: true, agentIds: ["a0", "a1"] });
  const a0 = { sandboxRoot: root, agentId: "a0" };
  await recordEntry(a0, { kind: "finding", value: "The laptop was imaged on 2024-04-05", source: "E01 header", evidence: "ewfinfo", basis: "observed", confidence: "high", indicates: "The acquisition is dated.", confidence_why: "The E01 header records it." });
  await recordEntry(a0, { kind: "ioc", value: `BitLocker recovery key ${SECRET}`, source: "notes app", evidence: "sqlite3 NoteStore row 11", sensitive: true });
  await recordEntry({ sandboxRoot: root, agentId: "a1" }, { kind: "ioc", value: `BitLocker recovery key ${SECRET}`, source: "notes app", evidence: "sqlite3 NoteStore row 11", sensitive: true });
  await recordEntry(a0, { kind: "event", ts: "2024-04-05T10:00:00Z", value: "The volume was unlocked", source: "System.evtx", evidence: "event 24577" });
  const pkg = join(root, "package");
  await mkdir(join(pkg, "trace"), { recursive: true });
  await mkdir(join(pkg, "board"), { recursive: true });
  await mkdir(join(pkg, "store", "jobs", "j000001"), { recursive: true });
  await cp(join(root, "ledger", "entries.jsonl"), join(pkg, "ledger.jsonl"));
  await cp(join(root, "ledger", "attestations.jsonl"), join(pkg, "ledger-attestations.jsonl"));
  await cp(join(root, "ledger", "ledger.md"), join(pkg, "ledger.md"));
  const trace = chained([
    { ts: "t", agent: "a0", tool: "bash", args: { command: "sqlite3 NoteStore.sqlite" }, result: { ok: true } },
    { ts: "t", agent: "a0", tool: "record", args: { kind: "ioc", value: `BitLocker recovery key ${SECRET}` }, result: { ok: true } },
    { ts: "t", agent: "a1", tool: "post", args: { body: "the vault opens" }, result: { ok: true } },
  ]);
  await writeFile(join(pkg, "trace", "events.jsonl"), trace);
  await writeFile(join(pkg, "board", "main.md"), `a0: the key is ${SECRET}\n`);
  await writeFile(join(pkg, "store", "jobs", "j000001", "stdout.log"), `recovery key: ${SECRET}\n`);
  // The store's journal, chained: one line's command carries the key.
  let prev: string | null = null;
  let journal = "";
  for (const [i, l] of [{ type: "store_opened" }, { type: "job_accepted", job: "j000001", spec: { kind: "command", command: `pybde --key ${SECRET}` } }, { type: "job_committed", job: "j000001" }].entries()) {
    const raw = JSON.stringify({ v: 1, seq: i, at: "t", ...l, prev });
    journal += `${raw}\n`;
    prev = sha(raw);
  }
  await writeFile(join(pkg, "store", "journal.jsonl"), journal);
  const lines = trace.trim().split("\n");
  await writeFile(join(pkg, "custody.json"), JSON.stringify({ seal: { trace: { lines: 3, last_line_sha256: sha(lines[2]) } } }));
  writeComponents(root, pkg);
  return { root, pkg };
}

test("a redacted package holds none of a sensitive entry's words, and its chains still walk", async () => {
  const { root, pkg } = await packaged();
  // The job log is cited by the sensitive entry through its refs in a real run; here it carries the words.
  const r = await redactPackage(root, pkg);
  assert.equal(r.entries, 1, "a1 recorded the same entry word for word: an attestation, not a second entry");
  assert.equal(r.lines, 4, "one ledger entry, the attestation of it (an act on a sensitive entry), one trace line and one journal line");
  assert.deepEqual(r.leaks, [], "nothing of it is left anywhere in the package");
  for (const f of ["ledger.jsonl", "trace/events.jsonl", "board/main.md", "store/jobs/j000001/stdout.log", "ledger.md", "store/journal.jsonl"]) {
    assert.doesNotMatch(await readFile(join(pkg, f), "utf8"), new RegExp(SECRET), `${f} holds no secret`);
  }
  const log = await readFile(join(pkg, "REDACTIONS.txt"), "utf8");
  assert.match(log, /1 ledger entry was marked sensitive \(seq 2\)/);
  assert.match(log, /[0-9a-f]{64}  [0-9a-f]{64}  trace\/events\.jsonl  1 line\(s\)/);
  const v = verifyPackage(pkg);
  assert.equal(v.ok, true, v.lines.join("\n"));
  assert.match(v.lines.join("\n"), /Trace:        3 lines, chain intact, 1 redacted \(their hashes kept\); the 3 lines the verdict sealed are there, 0 after/);
  assert.match(v.lines.join("\n"), /Ledger:       3 entries, chain intact, 1 redacted/);
  assert.match(v.lines.join("\n"), /Attestations: 1 lines, chain intact, 1 redacted \(their hashes kept\)/);
  assert.match(v.lines.join("\n"), /Journal:      3 lines, chain intact, 1 redacted/);
  assert.match(v.lines.join("\n"), /Redacted:     this package was made with --redact \(REDACTIONS\.txt\); REDACTIONS\.json records what \d+ redaction\(s\) replaced \(the sha256 of each original, why, which entry\); the leak scan after it found nothing over \d+ file\(s\)/);
});

test("the package's verify finds a chain edited after it was packaged, and a trace that is not the one sealed", async () => {
  const { pkg } = await packaged();
  assert.equal(verifyPackage(pkg).ok, true);
  const ledger = await readFile(join(pkg, "ledger.jsonl"), "utf8");
  await writeFile(join(pkg, "ledger.jsonl"), ledger.replace("imaged on 2024-04-05", "imaged on 2024-04-06"));
  const v = verifyPackage(pkg);
  assert.equal(v.ok, false);
  assert.match(v.lines.join("\n"), /Ledger:       broken at entry 1/);
  await writeFile(join(pkg, "ledger.jsonl"), ledger);
  const trace = await readFile(join(pkg, "trace", "events.jsonl"), "utf8");
  await writeFile(join(pkg, "trace", "events.jsonl"), trace.split("\n").slice(0, 2).join("\n") + "\n");
  const w = verifyPackage(pkg);
  assert.equal(w.ok, false);
  assert.match(w.lines.join("\n"), /THE SEALED LINE IS NOT THE ONE THE VERDICT NAMES/);
  assert.ok((await readdir(pkg)).length > 0);
});

test("after a redaction every readable entry's core is recomputed: one rewritten after the redacted entry is found", async () => {
  const { root, pkg } = await packaged();
  await redactPackage(root, pkg);
  assert.equal(verifyPackage(pkg).ok, true);
  // Entry 3 comes after the redacted entry 2: its prev and hash kept, its words changed.
  const ledger = await readFile(join(pkg, "ledger.jsonl"), "utf8");
  await writeFile(join(pkg, "ledger.jsonl"), ledger.replace("The volume was unlocked", "The volume was never unlocked"));
  const v = verifyPackage(pkg);
  assert.equal(v.ok, false);
  assert.match(v.lines.join("\n"), /Ledger:       broken at entry 3 \(the entry's core was rewritten\)/);
  assert.equal(ledgerChain(ledger).ok, true);
});

test("a part the verdict sealed, or one the package lists as present, cannot be taken out: missing and not declared absent fails", async () => {
  const { pkg } = await packaged();
  const components = JSON.parse(await readFile(join(pkg, "COMPONENTS.json"), "utf8")) as { components: Array<{ path: string; present: boolean; reason?: string }> };
  assert.deepEqual(components.components.find((c) => c.path === "trace/custody-anchor.json"), { path: "trace/custody-anchor.json", what: "the verdict's anchor, kept outside the run", present: false, reason: "the kickoff wrote no custody anchor for this run" });
  assert.match(verifyPackage(pkg).lines.join("\n"), /Absent:       .*trace\/custody-anchor\.json: the kickoff wrote no custody anchor for this run/);
  // The verdict taken out: the list says it is there.
  const custody = await readFile(join(pkg, "custody.json"), "utf8");
  await rm(join(pkg, "custody.json"));
  let v = verifyPackage(pkg);
  assert.equal(v.ok, false);
  assert.match(v.lines.join("\n"), /Components:   MISSING, AND NOT DECLARED ABSENT OR AGAINST THE SEAL: custody\.json \(declared present\)/);
  // With no list at all (an older package), a core part missing is not declared absent.
  await rm(join(pkg, "COMPONENTS.json"));
  v = verifyPackage(pkg);
  assert.equal(v.ok, false);
  assert.match(v.lines.join("\n"), /custody\.json \(not declared absent\)/);
  // The trace taken out of a package whose verdict sealed it, and declared absent: against the seal, it fails.
  await writeFile(join(pkg, "custody.json"), custody);
  await rm(join(pkg, "trace", "events.jsonl"));
  writeComponents(join(pkg, "no-such-run"), pkg);
  v = verifyPackage(pkg);
  assert.equal(v.ok, false);
  assert.match(v.lines.join("\n"), /trace\/events\.jsonl \(the verdict sealed 3 trace lines; declared absent: the run has no trace\)/);
});

test("a package carries the store sweeps' side lists (what a sweep did not search, what it found) and its verify holds each to the sha256 its line names; a line redacted for a word past its first few hits takes its side lists with it", async () => {
  const { root, pkg } = await packaged();
  // A job of 60 files that hold the string, the last of them named with a sensitive entry's words; and 80 objects too large for a pass.
  const hitDir = join(root, "store", "jobs", "j000010");
  const files: Array<{ path: string; sha256: string; bytes: number }> = [];
  for (let i = 0; i < 60; i++) {
    const path = i === 59 ? `export/zz-${SECRET}.txt` : `export/row-${String(i).padStart(3, "0")}.txt`;
    const body = `row ${i}: mallory\n`;
    await mkdir(join(hitDir, "out", "export"), { recursive: true });
    await writeFile(join(hitDir, "out", path), body);
    files.push({ path, sha256: sha(body), bytes: body.length });
  }
  await writeFile(join(hitDir, "manifest.json"), JSON.stringify({ files }));
  await writeFile(join(hitDir, "job.json"), JSON.stringify({ id: "j000010", state: "committed", status: "ok", exit: 0, spec: { kind: "command", scope: "declared", inputs: ["input:disk.E01"], command: "export" } }));
  await mkdir(join(root, "store", "jobs", "j000011", "out"), { recursive: true });
  await writeFile(join(root, "store", "jobs", "j000011", "manifest.json"), JSON.stringify({ files: Array.from({ length: 80 }, (_, i) => ({ path: `big/${i}.bin`, sha256: sha(`big ${i}`), bytes: 64 * 1024 * 1024 })) }));
  const SW = await import("../extensions/store-sweep.ts");
  process.env.SWARM_SWEEP_MAX_BYTES = String(32 * 1024 * 1024);
  try {
    const line = await SW.startSweep(root, { seq: 99, hash: sha("coverage 99"), kind: "coverage", refs: ["input:disk.E01"], result_refs: [], looked_for: ["mallory"], at: new Date().toISOString() } as unknown as LedgerEntry);
    assert.deepEqual([line?.hits.length, SW.unsearchedTotal(line)], [60, 80]);
  } finally {
    delete process.env.SWARM_SWEEP_MAX_BYTES;
  }
  const text = await readFile(join(root, "ledger", "sweeps.jsonl"), "utf8");
  assert.doesNotMatch(text, new RegExp(SECRET), "the line names its first few hits, not the last");
  await cp(join(root, "ledger", "sweeps.jsonl"), join(pkg, "ledger-sweeps.jsonl"));
  // As swarm.sh package copies them.
  const copied = spawnSync(process.execPath, ["--experimental-strip-types", "--no-warnings", join(import.meta.dirname, "..", "scripts", "package-tools.ts"), "sweep-lists", root, pkg], { encoding: "utf8" });
  assert.equal(copied.status, 0, copied.stderr);
  assert.deepEqual(JSON.parse(copied.stdout), { named: 2, copied: 2, missing: [] });
  const names = (await readdir(join(pkg, "ledger-sweeps"))).sort();
  assert.equal(names.length, 2);
  assert.match(names.join(" "), /^hits-[0-9a-f]{64}\.jsonl unsearched-[0-9a-f]{64}\.jsonl$/);
  writeComponents(root, pkg);
  let v = verifyPackage(pkg);
  assert.equal(v.ok, true, v.lines.join("\n"));
  assert.match(v.lines.join("\n"), /Sweep lists:  2 side list\(s\) named by the sweep lines, each in ledger-sweeps\/ as its line names it/);
  // A side list changed after it was packaged, or taken out, is named and fails the package.
  const hitsFile = join(pkg, "ledger-sweeps", names[0]!);
  const kept = await readFile(hitsFile);
  await writeFile(hitsFile, kept.toString("utf8").replace("row-000", "row-999"));
  v = verifyPackage(pkg);
  assert.equal(v.ok, false);
  assert.match(v.lines.join("\n"), new RegExp(`Sweep lists:  2 side list\\(s\\) named by the sweep lines, 1 NOT AS NAMED in ledger-sweeps/ \\(ledger/sweeps/${names[0]}: its bytes are not the`));
  await rm(hitsFile);
  assert.match(verifyPackage(pkg).lines.join("\n"), new RegExp(`ledger/sweeps/${names[0]}: missing`));
  await writeFile(hitsFile, kept);
  // A package from before the side lists were carried says so and is not failed for them.
  const components = JSON.parse(await readFile(join(pkg, "COMPONENTS.json"), "utf8")) as { components: Array<{ path: string }> };
  const withList = JSON.stringify(components);
  await writeFile(join(pkg, "COMPONENTS.json"), JSON.stringify({ ...components, components: components.components.filter((c) => c.path !== "ledger-sweeps") }));
  await rm(join(pkg, "ledger-sweeps"), { recursive: true });
  v = verifyPackage(pkg);
  assert.equal(v.ok, true, v.lines.join("\n"));
  assert.match(v.lines.join("\n"), /Sweep lists:  2 side list\(s\) named by the sweep lines, not carried \(a package from before 2026-11-14/);
  await writeFile(join(pkg, "COMPONENTS.json"), withList);
  assert.equal(copySweepLists(root, pkg).copied, 2);
  // Redacted: the sensitive words stand in the hits' file only, past the line's first few; the line is redacted for them, and its side lists withheld with it.
  const r = await redactPackage(root, pkg);
  assert.deepEqual(r.leaks, [], "nothing of it is left anywhere in the package");
  const sweepsAfter = await readFile(join(pkg, "ledger-sweeps.jsonl"), "utf8");
  assert.match(sweepsAfter, /"redacted":true/);
  assert.doesNotMatch(sweepsAfter, /hits_all/);
  for (const n of names) {
    const body = await readFile(join(pkg, "ledger-sweeps", n), "utf8");
    assert.doesNotMatch(body, new RegExp(SECRET));
    assert.match(body, /withheld with them/);
  }
  const json = JSON.parse(await readFile(join(pkg, "REDACTIONS.json"), "utf8")) as { changes: Array<{ path: string; why: string }> };
  assert.ok(json.changes.some((c) => c.path === "ledger-sweeps.jsonl" && /side list/.test(c.why)), JSON.stringify(json.changes.map((c) => [c.path, c.why])));
  assert.deepEqual(json.changes.filter((c) => c.path.startsWith("ledger-sweeps/")).length, 2);
  v = verifyPackage(pkg);
  assert.equal(v.ok, true, v.lines.join("\n"));
  assert.match(v.lines.join("\n"), /Sweeps:       1 lines, chain intact, 1 redacted \(their hashes kept\)/);
  assert.doesNotMatch(v.lines.join("\n"), /Sweep lists:/, "a redacted line names no side list to hold");
});

/** A run with custody taken and an examiner's sign-off, packaged as swarm.sh package lays it out. */
async function sealedPackage(o: { dispute?: boolean; leads?: boolean; questions?: boolean } = {}): Promise<{ root: string; runs: string; pkg: string }> {
  const runs = await mkdtemp(join(tmpdir(), "pkg-sealed-"));
  dirs.push(runs);
  const root = join(runs, "sp001");
  await initSandbox(root, { reset: true, swarmId: "sp001", agentIds: ["a0"] });
  // A finding as ledger version 4 takes one; refused, the ledger stays empty and there is nothing to sign.
  const r = await recordEntry({ sandboxRoot: root, agentId: "a0" }, { kind: "finding", value: "The laptop was imaged on 2024-04-05", source: "E01 header", evidence: "ewfinfo", basis: "observed", confidence: "high", indicates: "The image is of the laptop as it stood that day.", confidence_why: "The acquisition header, read directly." });
  if (!r.ok) throw new Error(r.reason);
  await mkdir(join(root, "work", "a0"), { recursive: true });
  await writeFile(join(root, "work", "report.md"), "# Report\n\nImaged on 2024-04-05 [#1].\n");
  await writeFile(join(root, "work", "a0", "big.bin"), Buffer.concat([Buffer.from([0]), Buffer.alloc(16, 1)]));
  await writeFile(join(runs, "registry.json"), JSON.stringify({ runs: [{ id: "sp001", sandbox: root }] }));
  if (o.dispute) {
    const d = await disputeEntry({ sandboxRoot: root, agentId: "a1" }, { seq: 1, why: "the header date is the imager's clock, not checked" });
    assert.equal(d.ok, true, JSON.stringify(d));
  }
  if (o.leads) {
    const L = await import("../extensions/leads.ts");
    const opened = await L.openLead({ sandboxRoot: root, agentId: "a0" }, { title: "Check the imager's clock", why: "The date rests on it", take: true });
    assert.equal(opened.ok, true, JSON.stringify(opened));
    const closed = await L.closeLead({ sandboxRoot: root, agentId: "a0" }, "L-1", { disposition: "resolved", ref: "E-1" });
    assert.equal(closed.ok, true, JSON.stringify(closed));
  }
  if (o.questions) {
    const Q = await import("../extensions/questions.ts");
    const asked = await Q.act(root, { kind: "human", role: "operator", person: "tester@lab", enrolled: false, os_user: "tester", host: "lab", via: "cli", identity: "claimed" }, "open", { text: "Was the imager's clock checked against a reference?", why: "The date rests on it" });
    assert.equal(asked.ok, true, JSON.stringify(asked));
  }
  await takeCustody(root, { runsDir: runs });
  await appendReview(runs, "sp001", root, { action: "sign", examiner: "H. Examiner" });
  const pkg = join(root, "package");
  await mkdir(join(pkg, "work"), { recursive: true });
  await mkdir(join(pkg, "trace"), { recursive: true });
  await cp(join(root, "work", "report.md"), join(pkg, "work", "report.md"));
  // The binary is left in the sandbox, named with its sha256, as package leaves a large one.
  await writeFile(join(pkg, "LEFT-BEHIND.txt"), `Left in the sandbox\n\n${sha(await readFile(join(root, "work", "a0", "big.bin")))}            17  work/a0/big.bin\n`);
  await cp(join(root, "custody.json"), join(pkg, "custody.json"));
  await cp(`${root}.custody-anchor.json`, join(pkg, "trace", "custody-anchor.json"));
  await cp(join(root, "artifacts.json"), join(pkg, "artifacts.sealed.json"));
  await cp(join(root, "ledger", "entries.jsonl"), join(pkg, "ledger.jsonl"));
  await cp(join(root, "traces", "events.jsonl"), join(pkg, "trace", "events.jsonl"));
  await cp(join(runs, "reviews", "sp001.jsonl"), join(pkg, "review.jsonl"));
  if (o.dispute) await cp(join(root, "ledger", "disputes.jsonl"), join(pkg, "ledger-disputes.jsonl"));
  if (o.leads) {
    await cp(join(root, "leads", "leads.jsonl"), join(pkg, "leads.jsonl"));
    await cp(join(root, "leads", "leads.md"), join(pkg, "leads.md"));
  }
  if (o.questions) {
    await cp(join(root, "questions", "questions.jsonl"), join(pkg, "questions.jsonl"));
    await cp(join(root, "questions", "questions.md"), join(pkg, "questions.md"));
  }
  writeComponents(root, pkg);
  return { root, runs, pkg };
}

test("every packaged work/ file is held to the index custody sealed, and that index to the verdict and its anchor", async () => {
  const { pkg } = await sealedPackage();
  let v = verifyPackage(pkg);
  assert.equal(v.ok, true, v.lines.join("\n"));
  assert.match(v.lines.join("\n"), /Work files:   every packaged work\/ file is the one custody sealed: 1 as sealed, 1 left in the sandbox with the sealed sha256 \(LEFT-BEHIND\.txt\); the index is the one the verdict and the anchor name/);
  // A packaged report edited after the stop, and a file that was never sealed.
  const report = await readFile(join(pkg, "work", "report.md"), "utf8");
  await writeFile(join(pkg, "work", "report.md"), `${report}Added later.\n`);
  await writeFile(join(pkg, "work", "late.md"), "late\n");
  v = verifyPackage(pkg);
  assert.equal(v.ok, false);
  assert.match(v.lines.join("\n"), /Work files:   NOT AS SEALED: 1 CHANGED \(work\/report\.md\); 1 NOT IN THE SEALED INDEX \(work\/late\.md\)/);
  await writeFile(join(pkg, "work", "report.md"), report);
  await rm(join(pkg, "work", "late.md"));
  // The sealed index replaced by one that fits the files: it is not the one the verdict names.
  const index = await readFile(join(pkg, "artifacts.sealed.json"), "utf8");
  await writeFile(join(pkg, "artifacts.sealed.json"), index.replace(/"generated_at": "[^"]+"/, '"generated_at": "2030-01-01T00:00:00.000Z"'));
  v = verifyPackage(pkg);
  assert.equal(v.ok, false);
  assert.match(v.lines.join("\n"), /Sealed index: artifacts\.sealed\.json IS NOT THE INDEX THE VERDICT NAMES/);
});

test("the examiner's review travels with the package: its chain is walked and its sign-off said against the ledger and the report there", async () => {
  const { pkg } = await sealedPackage();
  let v = verifyPackage(pkg);
  assert.match(v.lines.join("\n"), /Review:       1 act\(s\), chain intact; signed by H\. Examiner at \S+ over this ledger and this work\/report\.md/);
  // A line put in that does not follow the one before it.
  const review = await readFile(join(pkg, "review.jsonl"), "utf8");
  await writeFile(join(pkg, "review.jsonl"), `${review}${JSON.stringify({ v: 1, seq: 2, action: "accept", entry_seq: 1, prev: "0".repeat(64) })}\n`);
  v = verifyPackage(pkg);
  assert.equal(v.ok, false);
  assert.match(v.lines.join("\n"), /Review:       CHAIN BROKEN \(line 2 does not follow the line before it\)/);
});

test("the agents' disputes travel with the package: their chain is walked and held to the head the verdict sealed", async () => {
  const { pkg } = await sealedPackage({ dispute: true });
  let v = verifyPackage(pkg);
  assert.equal(v.ok, true, v.lines.join("\n"));
  assert.match(v.lines.join("\n"), /Disputes:     1 lines, chain intact; head sealed/);
  const components = JSON.parse(await readFile(join(pkg, "COMPONENTS.json"), "utf8")) as { components: Array<{ path: string; present: boolean }> };
  assert.equal(components.components.find((c) => c.path === "ledger-disputes.jsonl")?.present, true);
  // A dispute's words rewritten: the chain breaks.
  const text = await readFile(join(pkg, "ledger-disputes.jsonl"), "utf8");
  await writeFile(join(pkg, "ledger-disputes.jsonl"), text.replace("not checked", "checked"));
  v = verifyPackage(pkg);
  assert.equal(v.ok, false);
  assert.match(v.lines.join("\n"), /Disputes:     CHAIN BROKEN at line 1 \(the line was rewritten\)/);
  // Taken out, and still declared present: named.
  await rm(join(pkg, "ledger-disputes.jsonl"));
  v = verifyPackage(pkg);
  assert.equal(v.ok, false);
  assert.match(v.lines.join("\n"), /ledger-disputes\.jsonl \(declared present\)/);
});

test("the lead register travels with the package, unsigned: its chain is walked and held to the head the verdict sealed", async () => {
  const { pkg } = await sealedPackage({ leads: true });
  let v = verifyPackage(pkg);
  assert.equal(v.ok, true, v.lines.join("\n"));
  assert.match(v.lines.join("\n"), /Leads:        2 events, chain intact; head sealed/);
  const components = JSON.parse(await readFile(join(pkg, "COMPONENTS.json"), "utf8")) as { components: Array<{ path: string; present: boolean }> };
  assert.equal(components.components.find((c) => c.path === "leads.jsonl")?.present, true);
  assert.equal(components.components.find((c) => c.path === "leads.md")?.present, true);
  // An event's words rewritten: the chain breaks.
  const text = await readFile(join(pkg, "leads.jsonl"), "utf8");
  await writeFile(join(pkg, "leads.jsonl"), text.replace("imager's clock", "imager's name"));
  v = verifyPackage(pkg);
  assert.equal(v.ok, false);
  assert.match(v.lines.join("\n"), /Leads:        CHAIN BROKEN at line 1 \(the line was rewritten\)/);
  // Taken out, and the verdict sealed it: named.
  await rm(join(pkg, "leads.jsonl"));
  v = verifyPackage(pkg);
  assert.equal(v.ok, false);
  assert.match(v.lines.join("\n"), /leads\.jsonl \(declared present\)/);
});

test("the question register travels with the package: its chain is walked and held to the head the verdict sealed", async () => {
  const { pkg } = await sealedPackage({ questions: true });
  let v = verifyPackage(pkg);
  assert.equal(v.ok, true, v.lines.join("\n"));
  assert.match(v.lines.join("\n"), /Questions:    \d+ events, chain intact; head sealed/);
  const components = JSON.parse(await readFile(join(pkg, "COMPONENTS.json"), "utf8")) as { components: Array<{ path: string; present: boolean }> };
  assert.equal(components.components.find((c) => c.path === "questions.jsonl")?.present, true);
  assert.equal(components.components.find((c) => c.path === "questions.md")?.present, true);
  const text = await readFile(join(pkg, "questions.jsonl"), "utf8");
  await writeFile(join(pkg, "questions.jsonl"), text.replace("against a reference", "against the wall clock"));
  v = verifyPackage(pkg);
  assert.equal(v.ok, false);
  assert.match(v.lines.join("\n"), /Questions:    CHAIN BROKEN at line \d+ \(the line was rewritten\)/);
  await rm(join(pkg, "questions.jsonl"));
  v = verifyPackage(pkg);
  assert.equal(v.ok, false);
  assert.match(v.lines.join("\n"), /questions\.jsonl \(declared present\)/);
});

// --- the sessions component (swarm.sh package --with-sessions) -------------------------------------

/** A sandbox whose ledger holds one sensitive entry (SECRET), with sessions of two seats under .pi-sessions/, and an empty package directory. */
async function withSessions(): Promise<{ root: string; pkg: string }> {
  const root = await mkdtemp(join(tmpdir(), "pkg-sessions-"));
  dirs.push(root);
  await initSandbox(root, { reset: true, agentIds: ["a0", "a1"] });
  await recordEntry({ sandboxRoot: root, agentId: "a0" }, { kind: "ioc", value: `BitLocker recovery key ${SECRET}`, source: "notes app", evidence: "sqlite3 NoteStore row 11", sensitive: true });
  await mkdir(join(root, ".pi-sessions", "a0"), { recursive: true });
  await mkdir(join(root, ".pi-sessions", "a1"), { recursive: true });
  await writeFile(join(root, ".pi-sessions", "a0", "s1.jsonl"), `${JSON.stringify({ role: "tool", text: `the key is ${SECRET}` })}\n${JSON.stringify({ role: "assistant", text: "nothing sensitive here" })}\n`);
  await writeFile(join(root, ".pi-sessions", "a1", "s2.jsonl"), `${JSON.stringify({ role: "assistant", text: "a second seat's session, nothing sensitive" })}\n`);
  const pkg = join(root, "package");
  await mkdir(pkg, { recursive: true });
  return { root, pkg };
}

/** The archive's members extracted into a fresh directory with the host's tar. */
async function extracted(pkg: string): Promise<string> {
  const into = await mkdtemp(join(tmpdir(), "pkg-sessions-x-"));
  dirs.push(into);
  const r = spawnSync("tar", ["-xzf", join(pkg, SESSIONS_ARCHIVE), "-C", into]);
  assert.equal(r.status, 0, String(r.stderr));
  return into;
}

test("the sessions component carries each seat's session masked, in one archive with a manifest; verify holds both", async () => {
  const { root, pkg } = await withSessions();
  const r = await packSessions(root, pkg);
  assert.equal(r.files, 2);
  assert.ok(r.masked >= 1, "the sensitive value was masked");
  const manifest = JSON.parse(await readFile(join(pkg, SESSIONS_MANIFEST), "utf8")) as SessionsManifest;
  assert.equal(manifest.archive.sha256, sha(await readFile(join(pkg, SESSIONS_ARCHIVE))));
  assert.deepEqual(manifest.files.map((f) => f.restore_to), [".pi-sessions/a0/s1.jsonl", ".pi-sessions/a1/s2.jsonl"]);
  const s1 = manifest.files[0]!;
  assert.equal(s1.sha256_before, sha(await readFile(join(root, ".pi-sessions", "a0", "s1.jsonl"))), "the hash before masking is the file as copied");
  assert.notEqual(s1.sha256_after, s1.sha256_before);
  assert.equal(manifest.files[1]!.masked, 0);
  assert.ok(!(await readFile(join(pkg, SESSIONS_MANIFEST), "utf8")).includes(SECRET));
  const into = await extracted(pkg);
  const text = await readFile(join(into, ".pi-sessions", "a0", "s1.jsonl"), "utf8");
  assert.ok(!text.includes(SECRET), "the value is gone from the member");
  assert.match(text, /hidden-[0-9a-f]{24}/, "its keyed id stands in its place");
  assert.equal(sha(await readFile(join(into, ".pi-sessions", "a0", "s1.jsonl"))), s1.sha256_after);
  const sidecar = JSON.parse(await readFile(`${pkg}.sessions.private.json`, "utf8")) as { map: Record<string, unknown> };
  assert.ok(Object.keys(sidecar.map).some((k) => k.startsWith("hidden-")), "the id map is in the private sidecar, outside the package");
  const v = verifySessions(pkg);
  assert.ok(v.lines.some((l) => /^Sessions: +2 file\(s\) in sessions\/sessions\.tar\.gz/.test(l) && /match the manifest/.test(l)), v.lines.join("\n"));
  assert.equal(v.ok, true, v.lines.join("\n"));
  // The session in the run is copied, never edited.
  assert.ok((await readFile(join(root, ".pi-sessions", "a0", "s1.jsonl"), "utf8")).includes(SECRET));
});

test("verify names a tampered member, a missing member and a member the manifest lacks", async () => {
  const { root, pkg } = await withSessions();
  await packSessions(root, pkg);
  const manifestPath = join(pkg, SESSIONS_MANIFEST);
  const original = await readFile(join(pkg, SESSIONS_ARCHIVE));
  // Rebuild the archive after changing the extracted tree, and point the manifest at the new archive, so only a member can be the difference.
  const rebuild = async (change: (dir: string) => Promise<void>): Promise<string[]> => {
    const into = await extracted(pkg);
    await change(into);
    const made = spawnSync("tar", ["-czf", join(pkg, SESSIONS_ARCHIVE), "-C", into, ".pi-sessions"]);
    assert.equal(made.status, 0, String(made.stderr));
    const m = JSON.parse(await readFile(manifestPath, "utf8")) as SessionsManifest;
    m.archive.sha256 = sha(await readFile(join(pkg, SESSIONS_ARCHIVE)));
    await writeFile(manifestPath, JSON.stringify(m));
    return verifySessions(pkg).lines.filter((l) => l.startsWith("Sessions:"));
  };
  const pristine = await readFile(manifestPath, "utf8");
  const reset = async () => {
    await writeFile(join(pkg, SESSIONS_ARCHIVE), original);
    await writeFile(manifestPath, pristine);
  };
  const tampered = await rebuild(async (d) => writeFile(join(d, ".pi-sessions", "a1", "s2.jsonl"), "changed after packaging\n"));
  assert.ok(tampered.some((l) => /member \.pi-sessions\/a1\/s2\.jsonl DIFFERS FROM THE MANIFEST/.test(l)), tampered.join("\n"));
  assert.equal(verifySessions(pkg).ok, false);
  await reset();
  const missing = await rebuild(async (d) => rm(join(d, ".pi-sessions", "a0", "s1.jsonl")));
  assert.ok(missing.some((l) => /member \.pi-sessions\/a0\/s1\.jsonl IS MISSING from the archive/.test(l)), missing.join("\n"));
  await reset();
  const extra = await rebuild(async (d) => writeFile(join(d, ".pi-sessions", "a1", "s3.jsonl"), "slipped in\n"));
  assert.ok(extra.some((l) => /member \.pi-sessions\/a1\/s3\.jsonl IS IN THE ARCHIVE AND NOT IN THE MANIFEST/.test(l)), extra.join("\n"));
  await reset();
  // The archive itself edited: its sha256 no longer matches the manifest.
  await writeFile(join(pkg, SESSIONS_ARCHIVE), Buffer.concat([original, Buffer.from([0])]));
  const edited = verifySessions(pkg);
  assert.ok(edited.lines.some((l) => /sessions\.tar\.gz DOES NOT MATCH ITS MANIFEST/.test(l)), edited.lines.join("\n"));
  assert.equal(edited.ok, false);
  await reset();
  assert.equal(verifySessions(pkg).ok, true);
  // A package made with --redact never holds the component.
  await writeFile(join(pkg, "REDACTIONS.txt"), "Redactions\n");
  const disclosed = verifySessions(pkg);
  assert.equal(disclosed.ok, false);
  assert.ok(disclosed.lines.some((l) => /MADE WITH --redact AND HOLDS SESSIONS/.test(l)), disclosed.lines.join("\n"));
});

test("a session file that grows during the copy is named with both sizes; a link and a FIFO are never followed", async () => {
  const { root, pkg } = await withSessions();
  const outside = join(root, "..", `outside-${sha(root).slice(0, 8)}.txt`);
  dirs.push(outside);
  await writeFile(outside, `the operator's own file with ${SECRET}\n`);
  await symlink(outside, join(root, ".pi-sessions", "a0", "link.jsonl"));
  assert.equal(spawnSync("mkfifo", [join(root, ".pi-sessions", "a1", "pipe")]).status, 0);
  const before = (await stat(join(root, ".pi-sessions", "a1", "s2.jsonl"))).size;
  const r = await packSessions(root, pkg, { afterListed: () => appendFileSync(join(root, ".pi-sessions", "a1", "s2.jsonl"), "{\"role\":\"assistant\",\"text\":\"written during the copy\"}\n") });
  assert.equal(r.changed, 1);
  const grown = r.changed_files[0]!;
  assert.equal(grown.path, ".pi-sessions/a1/s2.jsonl");
  assert.equal(grown.listed_bytes, before);
  assert.ok(grown.copied_bytes > before, "the copied size is the larger one");
  const manifest = JSON.parse(await readFile(join(pkg, SESSIONS_MANIFEST), "utf8")) as SessionsManifest;
  assert.deepEqual(manifest.skipped.map((s) => s.path).sort(), [".pi-sessions/a0/link.jsonl", ".pi-sessions/a1/pipe"]);
  assert.match(manifest.skipped.find((s) => s.path.endsWith("link.jsonl"))!.why, /symbolic link: never followed/);
  const into = await extracted(pkg);
  const members = (await readdir(join(into, ".pi-sessions"), { recursive: true })).filter((m) => !m.endsWith("a0") && !m.endsWith("a1")).sort();
  assert.deepEqual(members, ["a0/s1.jsonl", "a1/s2.jsonl"]);
  assert.ok(!(await readFile(join(pkg, SESSIONS_ARCHIVE))).includes(Buffer.from("operator's own file")), "nothing was read through the link");
  assert.equal(verifySessions(pkg).ok, true);
});

test("a value in a JSON escape, in UTF-16 text and in a session file's name is masked too", async () => {
  const { root, pkg } = await withSessions();
  const dir = join(root, ".pi-sessions", "a0");
  // A dash of the value as a unicode escape (U+002D): no byte search of the plain value finds it.
  const escaped = SECRET.replace("-", String.fromCharCode(92) + "u002d");
  await writeFile(join(dir, "escaped.jsonl"), `{"role":"tool","text":"read ${escaped} from the note"}\n`);
  await writeFile(join(dir, "utf16.txt"), Buffer.concat([Buffer.from([0xff, 0xfe]), Buffer.from(`key ${SECRET}\n`, "utf16le")]));
  await writeFile(join(dir, `name-${SECRET}.txt`), "a file named after the value\n");
  const r = await packSessions(root, pkg);
  assert.equal(r.files, 5);
  const manifest = JSON.parse(await readFile(join(pkg, SESSIONS_MANIFEST), "utf8")) as SessionsManifest;
  assert.ok(!JSON.stringify(manifest).includes(SECRET), "the manifest names no value");
  assert.ok(manifest.files.some((f) => f.name_masked && /^\.pi-sessions\/a0\/name-hidden-[0-9a-f]{24}\.txt$/.test(f.path)), "the name is masked");
  const into = await extracted(pkg);
  for (const m of await readdir(join(into, ".pi-sessions", "a0"))) {
    const bytes = await readFile(join(into, ".pi-sessions", "a0", m));
    assert.ok(!bytes.includes(Buffer.from(SECRET, "utf8")), `${m} holds the value`);
    assert.ok(!bytes.includes(Buffer.from(SECRET, "utf16le")), `${m} holds the value in UTF-16`);
    assert.ok(!bytes.toString("utf8").includes(escaped), `${m} holds the escaped value`);
  }
  assert.ok((await readFile(join(into, ".pi-sessions", "a0", "utf16.txt"))).subarray(0, 2).equals(Buffer.from([0xff, 0xfe])), "the BOM stays");
  const escapedLine = await readFile(join(into, ".pi-sessions", "a0", "escaped.jsonl"), "utf8");
  assert.match(escapedLine, /hidden-[0-9a-f]{24}/);
  JSON.parse(escapedLine.trim());
  assert.equal(verifySessions(pkg).ok, true);
});

// --- redaction on sealed copies, directory citations and many digests ----------------------------------

test("a package that holds a read-only (0444) sealed log of a sensitive job redacts and verifies, and the run's own log keeps its mode", async () => {
  const { root, pkg } = await packaged();
  // The run's sealed original and the package's copy of it, both as the store leaves them: read-only.
  await mkdir(join(root, "store", "jobs", "j000001"), { recursive: true });
  const original = join(root, "store", "jobs", "j000001", "stdout.log");
  await writeFile(original, `recovery key: ${SECRET}\n`);
  await chmod(original, 0o444);
  const copy = join(pkg, "store", "jobs", "j000001", "stdout.log");
  await chmod(copy, 0o444);
  const r = await redactPackage(root, pkg);
  assert.deepEqual(r.leaks, []);
  assert.doesNotMatch(await readFile(copy, "utf8"), new RegExp(SECRET));
  assert.equal((await stat(copy)).mode & 0o777, 0o644, "the redacted copy is the copy's mode with the owner's write bit");
  assert.equal((await stat(original)).mode & 0o777, 0o444, "the run's sealed original keeps its mode");
  assert.match(await readFile(original, "utf8"), new RegExp(SECRET), "and its bytes");
  assert.deepEqual((await readdir(join(pkg, "store", "jobs", "j000001"))).filter((n) => n.includes(".tmp-")), [], "no temporary file is left");
  const v = verifyPackage(pkg);
  assert.equal(v.ok, true, v.lines.join("\n"));
});

/** A sandbox whose sensitive entry cites a directory of a sealed job's output, and a package --with-outputs that holds the files under it. */
async function citingDirectory(): Promise<{ root: string; pkg: string; dir: string }> {
  const root = await mkdtemp(join(tmpdir(), "pkg-cite-"));
  dirs.push(root);
  await initSandbox(root, { reset: true, agentIds: ["a0"] });
  const staging = join(root, "..", `staging-${sha(root).slice(0, 8)}`);
  dirs.push(staging);
  await mkdir(join(staging, "archive", "contact"), { recursive: true });
  await writeFile(join(staging, "archive", "contact", "a.txt"), "Joe Doe, 12 Elm Street\n");
  await writeFile(join(staging, "archive", "contact", "b.txt"), "Jane Roe, 3 Oak Avenue\n");
  await sealTree(root, staging, join(storePaths(root).jobs, "j000001", "out"), "j000001", 1);
  await writeFile(join(storePaths(root).jobs, "j000001", "job.json"), JSON.stringify({ id: "j000001", state: "committed", requester: { agent: "a0" }, status: "ok", exit: 0, spec: { kind: "command", scope: "all", command: "export" } }));
  // A ref names an object of the job's manifest, so a directory is not recorded as one: the entry cites a file, and the line is then written as citing the directory
  // (the ledger is read raw here, as redaction reads it), the shape a run packaged with its outputs can hold.
  const e = await recordEntry({ sandboxRoot: root, agentId: "a0" }, { kind: "ioc", value: "the contact archive", source: "the export", evidence: "a listing", sensitive: true, refs: ["job:j000001/archive/contact/a.txt"] });
  assert.ok(e.ok, JSON.stringify(e));
  const entries = join(root, "ledger", "entries.jsonl");
  await writeFile(entries, (await readFile(entries, "utf8")).replace("job:j000001/archive/contact/a.txt", "job:j000001/archive/contact/"));
  const pkg = join(root, "package");
  const out = join(pkg, "store", "jobs", "j000001", "out", "archive", "contact");
  await mkdir(out, { recursive: true });
  await mkdir(join(out, "nested"), { recursive: true });
  await writeFile(join(out, "a.txt"), "Joe Doe, 12 Elm Street\n");
  await writeFile(join(out, "b.txt"), "Jane Roe, 3 Oak Avenue\n");
  await writeFile(join(out, "nested", "c.txt"), "a third record\n");
  await writeFile(join(pkg, "ledger.jsonl"), await readFile(join(root, "ledger", "entries.jsonl")));
  return { root, pkg, dir: out };
}

test("a sensitive entry that cites a job's output directory has every file under it withheld, each by its keyed id; a symlink there is refused and named", async () => {
  const { root, pkg, dir } = await citingDirectory();
  const r = await redactPackage(root, pkg);
  for (const f of ["a.txt", "b.txt", join("nested", "c.txt")]) {
    const text = await readFile(join(dir, f), "utf8");
    assert.match(text, /cited by a sensitive ledger entry \(E-1\); matched hidden-[0-9a-f]{24}/, f);
    assert.doesNotMatch(text, /Elm Street|Oak Avenue|third record/, f);
  }
  const ids = new Set((await Promise.all(["a.txt", "b.txt"].map((f) => readFile(join(dir, f), "utf8")))).map((x) => /matched (hidden-[0-9a-f]{24})/.exec(x)![1]));
  assert.equal(ids.size, 2, "each file has its own id");
  // A link under the cited directory is not followed: the redaction is refused, naming it.
  const again = await citingDirectory();
  await symlink("/etc/hostname", join(again.dir, "link.txt"));
  await assert.rejects(redactPackage(again.root, again.pkg), /cites store\/jobs\/j000001\/out\/archive\/contact, which holds store\/jobs\/j000001\/out\/archive\/contact\/link\.txt: a symbolic link; redaction refuses it and does not follow it/);
});

test("makeDigestReplacer gives the old function's output on small inputs, and 50,000 digests over 20 MB take little CPU time", () => {
  const hex = (n: number) => createHash("sha256").update(`digest-${n}`).digest("hex");
  /** The function this replaced, kept as the oracle: once per digest, over the whole text. */
  const oldReplace = (list: string[], hide: (sha: string) => string, text: string, replaced: Replaced[]): string => {
    let t = text;
    for (const sha of list) {
      if (!t.includes(sha)) continue;
      const id = hide(sha);
      const count = t.split(sha).length - 1;
      t = t.split(sha).join(id);
      replaced.push({ what: "text", entry: null, sha256_of_original: id, count, why: "the digest of a sensitive output" });
    }
    return t;
  };
  const small = Array.from({ length: 40 }, (_, i) => hex(i));
  const hide = (sha: string) => `hidden-${sha.slice(0, 24)}`;
  const a = small[3]!;
  const b = small[7]!;
  const corpus = [
    "",
    "no digest here",
    `one ${a} two`,
    `${a}${a}`,
    `${a} and ${b} and ${a}`,
    `line one ${a}\nline two ${b}\n{"sha":"${a}","other":"${hex(500)}"}`,
    `${a.toUpperCase()} upper case is not a sensitive digest as written`,
    `${hex(500)} not sensitive, ${b} sensitive`,
    // Overlapping runs: a digest inside a longer hex run, two digests back to back, a digest preceded and followed by hex.
    `ab${a}cd`,
    `${a}${b}`,
    `${a}${a.slice(0, 20)}`,
    `${b.slice(40)}${a}${b.slice(0, 40)}`,
    `${small.join("")}`,
    `x ${small.join(" ")} y`,
  ];
  for (const text of corpus) {
    const wantRecords: Replaced[] = [];
    const gotRecords: Replaced[] = [];
    const want = oldReplace(small, hide, text, wantRecords);
    const r = makeDigestReplacer(small, hide);
    const got = r.replace(text, gotRecords);
    assert.equal(got, want, JSON.stringify(text.slice(0, 60)));
    assert.deepEqual(gotRecords, wantRecords, JSON.stringify(text.slice(0, 60)));
    assert.equal(r.holds(text), small.some((d) => text.includes(d)), JSON.stringify(text.slice(0, 60)));
  }
  // 50,000 digests over a 20 MB text: process CPU time, not wall clock, with a wide bound. The old function does 50,000 passes over the text.
  const many = Array.from({ length: 50_000 }, (_, i) => hex(100_000 + i));
  const chunk = `${"a line of an ordinary report with a few words and no digest in it ".repeat(20)}\n${many[12_345]} ${hex(7)}\n`;
  const text = chunk.repeat(Math.ceil((20 * 1024 * 1024) / chunk.length));
  const replacer = makeDigestReplacer(many, (sha) => `hidden-${sha.slice(0, 24)}`);
  const before = process.cpuUsage();
  const records: Replaced[] = [];
  const out = replacer.replace(text, records);
  const used = process.cpuUsage(before);
  const cpuSeconds = (used.user + used.system) / 1e6;
  assert.ok(!out.includes(many[12_345]!), "the digest is replaced everywhere");
  assert.equal(records.length, 1);
  assert.ok(cpuSeconds < 20, `${cpuSeconds.toFixed(2)} CPU seconds for 50,000 digests over ${(text.length / 1048576).toFixed(1)} MB`);
});

test("HYGIENE.json carries the access record as whole counts {roots, readers, edges, maybe}: no seat, job or path is named in it", async () => {
  const base = await mkdtemp(join(tmpdir(), "hygiene-access-"));
  dirs.push(base);
  const S = await writeFiles(base, fixtureFiles());
  const pkg = join(base, "pkg");
  await mkdir(pkg, { recursive: true });
  await hygieneReport(S, pkg);
  const hyg = JSON.parse(await readFile(join(pkg, "HYGIENE.json"), "utf8")) as { access: Record<string, number> };
  // j000001 is the one root; agent-2 the one seat the hub's line shows reading; three jobs took an output as an input;
  // two jobs declared no scope and could read 2 and 4 of the outputs: six possible reaches, none of them a read.
  assert.deepEqual(hyg.access, { roots: 1, readers: 1, edges: 3, maybe: 6, marked_trace_lines: 0, marked_kept_copies: 0 });
  assert.doesNotMatch(JSON.stringify(hyg.access), /agent-|j0000|store\//, "counts only");
});

// --- --redact replaces the trace lines the access record marks (PKG-ACC-04) ---------------------------------------

/** A run whose ledger holds no sensitive entry (so no word is looked for), with a package made of its trace and a kept output. */
async function markedRun(o: { sensitive?: boolean } = {}): Promise<{ S: string; pkg: string; lines: string[]; kept: string }> {
  const base = await mkdtemp(join(tmpdir(), "redact-marks-"));
  dirs.push(base);
  const kept = "tool-output/agent-2/bash-1.out";
  const trace = [
    traceRow("agent-2", 1, "bash", { command: "cat store/jobs/j000001/out/values.jsonl" }, T(10), { ok: true, full_output: { path: kept } }),
    hubLine(T(10, 1), "agent-2", { job: "j000001", via: "text", certainty: "text", part: "out", paths: ["store/jobs/j000001/out/values.jsonl"] }, { sid: "sid-agent-2", seq: 1, tool: "bash" }, { kept_as: kept }),
    traceRow("agent-3", 2, "bash", { command: "cat store/jobs/*/out/*" }, T(11)),
    traceRow("agent-3", 3, "bash", { command: "ls inputs" }, T(12)),
    traceRow("agent-2", 4, "read", { path: "store/jobs/j000010/out/x" }, T(13)),
  ];
  // A run with no sensitive output has no line of the hub on its trace.
  const files = fixtureFiles({ trace: o.sensitive === false ? trace.filter((l) => (l as { tool?: string }).tool !== "sensitive_access") : trace, ledger: [] });
  if (o.sensitive === false) {
    files["run1/store/journal.jsonl"] = jl({ v: 1, seq: 0, at: T(0), type: "job_accepted", job: "j000010", spec: { kind: "command" }, requester: { agent: "agent-2" } });
    delete files["run1/store/jobs/j000001/manifest.json"];
  }
  const S = await writeFiles(base, files);
  const pkg = join(base, "pkg");
  await mkdir(join(pkg, "trace"), { recursive: true });
  await mkdir(join(pkg, "tool-output", "agent-2"), { recursive: true });
  await writeFile(join(pkg, "trace", "events.jsonl"), files["run1/traces/events.jsonl"]);
  await writeFile(join(pkg, kept), "the whole output a seat's command returned\n");
  return { S, pkg, lines: files["run1/traces/events.jsonl"].trim().split("\n"), kept };
}

test("--redact replaces the trace lines the access record marks (the possible reaches and the commands that name an output included) and the whole copy kept of the read; the rest stays", async () => {
  const { S, pkg, lines, kept } = await markedRun();
  const r = await redactPackage(S, pkg, { leaks: "list" });
  const out = (await readFile(join(pkg, "trace", "events.jsonl"), "utf8")).trim().split("\n");
  assert.equal(out.length, lines.length, "no line is dropped");
  assert.deepEqual(JSON.parse(out[0]), { redacted: true, line_sha256: sha(lines[0]) }, "the seat's tool result that named the output is replaced by the hash of the line");
  assert.equal(out[1], lines[1], "the hub's own line names a job and a path, never a value: it stays");
  assert.deepEqual(JSON.parse(out[2]), { redacted: true, line_sha256: sha(lines[2]) }, "a command that walks a root which holds it is marked too");
  assert.deepEqual([out[3], out[4]], [lines[3], lines[4]], "a call that names nothing sensitive stays");
  assert.equal(r.lines, 2);
  // The whole copy kept of the read is replaced by a stub that names a keyed id, not the digest.
  const stub = await readFile(join(pkg, kept), "utf8");
  assert.match(stub, /^\[redacted: marked sensitive\]: a whole output kept from a seat's read of a sensitive output \(the access record marks it\); matched hidden-[0-9a-f]{24}/);
  assert.doesNotMatch(stub, /[0-9a-f]{64}|seat's command returned/);
  // The chain still reads: a redacted line stands for the line it replaced, by its hash.
  const chain = out.map((l) => JSON.parse(l) as { redacted?: boolean; line_sha256?: string });
  assert.deepEqual(chain.map((c, i) => (c.redacted ? c.line_sha256 : sha(out[i]))), [sha(lines[0]), sha(lines[1]), sha(lines[2]), sha(lines[3]), sha(lines[4])]);
});

test("without --redact nothing changes, and HYGIENE.json counts the lines the record marks and advises --redact", async () => {
  const { S, pkg, lines } = await markedRun();
  await hygieneReport(S, pkg);
  assert.equal(await readFile(join(pkg, "trace", "events.jsonl"), "utf8"), `${lines.join("\n")}\n`, "the trace is as it was");
  const hyg = JSON.parse(await readFile(join(pkg, "HYGIENE.json"), "utf8")) as { access: { marked_trace_lines: number; marked_kept_copies: number; advice?: string } };
  assert.equal(hyg.access.marked_trace_lines, 2);
  assert.equal(hyg.access.marked_kept_copies, 1);
  assert.match(hyg.access.advice ?? "", /2 trace line\(s\) of seats' tool results and 1 kept whole output\(s\).* a package made with --redact replaces them/);
});

test("a run with no sensitive output marks nothing: the trace of its package is not touched", async () => {
  const { S, pkg, lines } = await markedRun({ sensitive: false });
  const before = await readFile(join(pkg, "trace", "events.jsonl"), "utf8");
  const r = await redactPackage(S, pkg, { leaks: "list" });
  assert.equal(r.lines, 0);
  assert.equal(await readFile(join(pkg, "trace", "events.jsonl"), "utf8"), before);
  assert.equal(before, `${lines.join("\n")}\n`);
});
