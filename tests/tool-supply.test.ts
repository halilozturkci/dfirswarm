/**
 * Supplying a tool to a running run (`swarm.sh tool-supply`,
 * scripts/material.ts `tool`): a program no image holds, handed over by the
 * operator with where it came from, how it was built and the hashes that were
 * checked, sealed as material of class operator_supplied, on the ledger with
 * that provenance in the chained core, and told to the seats with the way to
 * run it (nothing sealed in the store can be executed where it stands).
 * The case policy's rules for material are kept: every preset admits it,
 * a class the policy says `none` for does not, and what rests on it is
 * flagged with its class.
 */
import assert from "node:assert/strict";
import { spawn, spawnSync } from "node:child_process";
import { createServer } from "node:net";
import { createHash } from "node:crypto";
import { chmod, mkdir, mkdtemp, readdir, readFile, rm, stat, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { after, test } from "node:test";
import * as L from "../extensions/leads.ts";
import * as P from "../extensions/protocol.ts";
import * as Q from "../extensions/questions.ts";
import { resolveCasePolicy, type CasePolicy } from "../scripts/case-policy.ts";
import { checkLedgerAnswers } from "../scripts/check-answers.ts";
import { admitMaterial, listMaterial, type MaterialRequest } from "../scripts/material.ts";
import { Journal, sealTree, storePaths } from "../scripts/evidence-store.ts";
import { externalLineage } from "../scripts/net-broker.ts";

const ROOT = resolve(import.meta.dirname, "..");
const dirs: string[] = [];
after(async () => {
  // The store's sealed imports are read-only: made writable again to be removed.
  for (const d of dirs) {
    spawnSync("chmod", ["-R", "u+w", d]);
    await rm(d, { recursive: true, force: true });
  }
});

const sha = (b: string | Buffer) => createHash("sha256").update(b).digest("hex");
const policyOf = (flags: Record<string, string>): CasePolicy => {
  const r = resolveCasePolicy({ flags, goal: {}, isolation: "microvm" });
  assert.ok(r.ok, JSON.stringify(r));
  return (r as { policy: CasePolicy }).policy;
};
const GOAL = ["## Goal", "", "Examine the memory image.", "", "### Questions", "", "1. Which program held a key?", "", "## Objectives", "", "- O-1: Find it.", "", "## Definition of done", "", "d", "", "## Checks", "", '- `node x "$SWARM_HARNESS/scripts/check-answers.ts" --sections 1,summary,narrative`', ""].join("\n");

async function run(flags: Record<string, string> = {}) {
  const base = await mkdtemp(join(tmpdir(), "toolsupply-"));
  dirs.push(base);
  const S = join(base, "run");
  await P.initSandbox(S, { swarmId: "c1", agentIds: ["a0", "a1"], capUsd: 5, wallClockMinutes: 30, goal: GOAL });
  await mkdir(join(S, "network"), { recursive: true });
  await writeFile(join(S, "network", "policy.json"), JSON.stringify(policyOf(flags)));
  await Q.seedRegister(S);
  return { S, base, a0: { sandboxRoot: S, agentId: "a0" }, a1: { sandboxRoot: S, agentId: "a1" } };
}

/** A program as an operator has it on their machine: an executable file. */
async function program(base: string, name = "detector", body = "#!/bin/sh\necho scanning\n"): Promise<{ path: string; sha256: string }> {
  const dir = join(base, "supply");
  await mkdir(dir, { recursive: true });
  const path = join(dir, name);
  await writeFile(path, body);
  await chmod(path, 0o755);
  return { path, sha256: sha(body) };
}

const WHO = "ana (analyst, enrolled, claimed)";
const req = (path: string, tool: NonNullable<MaterialRequest["tool"]>, more: Partial<MaterialRequest> = {}): MaterialRequest => ({ mode: "material", path, why: "a scanner for a file format the images lack", supplied_by: WHO, via: "cli", tool, ...more });
const added = (r: Record<string, unknown> & { ok: boolean }): Record<string, unknown> => {
  assert.equal(r.ok, true, String(r.reason ?? ""));
  return r;
};
const refused = (r: { ok: boolean }, re: RegExp) => {
  assert.equal(r.ok, false, "expected a refusal");
  assert.match((r as unknown as { reason: string }).reason, re);
};
const posts = async (S: string) => Promise.all((await readdir(join(S, "threads", "main"))).filter((n) => n.endsWith("-system.md")).map((n) => readFile(join(S, "threads", "main", n), "utf8")));

test("a supplied tool is sealed as operator-supplied material with its provenance: on the journal, on the ledger in the chained core, in the record, and told to the seats with the way to run it", async () => {
  const { S, base, a0 } = await run();
  // The request that asked for it, and its lead.
  ok(await L.openLead(a0, { title: "Find the key schedules", why: "Q1 wants the program that held the key", answers: ["1"], take: true }));
  const asked = ok(await L.closeLead(a0, "L-1", { disposition: "needs_operator", ref: "no image holds a scanner for this file format" }));
  assert.equal(asked.request?.id, "R-1");
  const p = await program(base);
  const source = `the vendor's source archive 1.0 (sha256 ${"ab".repeat(32)}), checked against the vendor's signed release notes`;
  const built = "make in a clean debian:bookworm-slim container for linux/arm64";
  const r = added(await admitMaterial(S, req(p.path, { source, built, sha256: [p.sha256], for: ["R-1"] })));
  assert.equal(r.import, "mat-0001");
  assert.equal(r.class, "operator_supplied");
  assert.deepEqual(r.tool, { source, built, checked: [p.sha256], for: ["R-1", "L-1"] }, "the request's own lead is named beside it");
  assert.equal(r.complete, true);
  // In the store: sealed, one file, the bytes as supplied, read-only and not executable (a sealed file never is).
  const sealed = join(S, "store", "imports", "mat-0001", "out", "detector");
  assert.equal(sha(await readFile(sealed)), p.sha256);
  assert.equal((await stat(sealed)).mode & 0o111, 0, "a sealed file has no execute bit");
  // The record, whole.
  const rec = JSON.parse(await readFile(join(S, "store", "imports", "mat-0001", "material.json"), "utf8"));
  assert.deepEqual(rec.tool, { source, built, checked: [p.sha256], for: ["R-1", "L-1"] });
  assert.equal(rec.mode, "material");
  assert.equal(rec.class, "operator_supplied");
  assert.equal(rec.why, "a scanner for a file format the images lack");
  // On the store journal.
  const journal = (await readFile(join(S, "store", "journal.jsonl"), "utf8")).trim().split("\n").map((l) => JSON.parse(l));
  assert.ok(journal.some((l) => l.type === "material_added" && l.import === "mat-0001" && l.files[0].sha256 === p.sha256));
  assert.ok(journal.some((l) => l.type === "addition_applied" && l.import === "mat-0001"));
  // On the ledger: external, operator supplied, the provenance in the chained core.
  const ext = (await P.readLedger(S)).find((e) => e.kind === "external")!;
  assert.equal(ext.source_class, "operator_supplied");
  assert.deepEqual(ext.refs, ["import:mat-0001/detector"]);
  assert.match(ext.value, /^Tool supplied \(operator_supplied\): 1 file\(s\) as import:mat-0001: a scanner for a file format the images lack$/);
  assert.match(String(ext.source), /^swarm\.sh tool-supply add, by ana/);
  assert.deepEqual(ext.provenance?.tool, { source, built, checked: [p.sha256], for: ["R-1", "L-1"] });
  assert.equal(ext.provenance?.sha256, p.sha256);
  assert.match(String(ext.provenance?.permitted_use), /^reference: /);
  // A provenance rewritten after the fact is a broken chain.
  const entries = await readFile(join(S, P.LEDGER_ENTRIES), "utf8");
  assert.equal(P.verifyLedgerChain(entries).ok, true);
  assert.equal(P.verifyLedgerChain(entries.replace("make in a clean debian", "make in a clean ubuntu")).ok, false, "the tool's provenance is part of the entry's hash");
  // Told to the seats: where it came from as the operator states it, what the harness checked, and how to run it.
  const post = (await posts(S)).find((x) => /TOOL SUPPLIED/.test(x))!;
  assert.match(post, /key: addition:mat-0001/);
  assert.match(post, /TOOL SUPPLIED as import:mat-0001 \(operator_supplied; use: reference: /);
  assert.ok(post.includes(`detector (${(await stat(sealed)).size} bytes, sha256 ${p.sha256})`));
  assert.ok(post.includes(`Where it came from, as the operator states it: ${source}.`));
  assert.ok(post.includes(`How it was built, as the operator states it: ${built}.`));
  assert.ok(post.includes(`Hashes the operator gave, each checked against the bytes sealed: ${p.sha256}.`));
  assert.match(post, /It was supplied for R-1, L-1\./);
  assert.match(post, /the harness vouches for the bytes only/);
  assert.match(post, /Test it on input whose answer you know before you rely on it/);
  // The way to run it: named in a job's programs, which copies it into an executable directory in the worker.
  assert.match(post, /job_run with programs \["import:mat-0001"\] \(and inputs \["import:mat-0001\/detector"\] when you declare them\)/);
  assert.match(post, /Nothing in the store or in a job's \$OUT can be executed where it stands \(sealed files have no execute bit, \$OUT is no-exec\)/);
  assert.match(post, /its bin\/ on PATH and its lib\/ on LD_LIBRARY_PATH \(\$PROGRAMS names the directory\), and your command calls it by name/);
  assert.match(post, /cites the job and import:mat-0001\/detector, and says what the tool is/);
  // Listed as material, with what was said of it.
  const listed = (await listMaterial(S)).find((m) => m.import === "mat-0001")!;
  assert.deepEqual((listed.tool as { checked: string[] }).checked, [p.sha256]);
  assert.equal(listed.applied, true);
});

test("a finding that cites the supplied tool is flagged with its class, as material is", async () => {
  const { S, base, a0 } = await run();
  const p = await program(base);
  added(await admitMaterial(S, req(p.path, { source: "built by the operator from a public source tree" })));
  const f = ok(await P.recordEntry(a0, { kind: "finding", basis: "observed", confidence: "high", indicates: "What the observation shows, and the step to it.", confidence_why: "Read directly from the object it cites.", value: "The detector is the program the operator supplied", source: "the supplied tool", evidence: "its bytes", refs: ["import:mat-0001/detector"], answers: ["1"] } as P.LedgerInput));
  ok(await P.recordEntry(a0, { kind: "answer", result: "established", confidence: "high", confidence_why: "The finding is read from the object.", alternatives_open: "none remains open", would_change: "a record that disagrees", section: "question:1", value: "The supplied program", reasoning: `E-${f.entry.seq} shows it` } as unknown as P.LedgerInput));
  const lin = await externalLineage(S);
  assert.deepEqual(lin.classes.get(f.entry.seq), ["operator_supplied"]);
  const check = await checkLedgerAnswers(S, ["question:1"]);
  assert.deepEqual(check.external["question:1"]?.classes, ["operator_supplied"]);
});

test("every preset admits a tool, as they admit material; a policy that says operator_supplied=none for it refuses it before anything is sealed, because nothing could be recorded on its output", async () => {
  for (const preset of ["standard", "live_adversary", "internal", "ctf"]) {
    const { S, base } = await run({ policy: preset });
    const p = await program(base);
    const r = added(await admitMaterial(S, req(p.path, { source: "the operator's build" })));
    assert.equal(r.import, "mat-0001", `${preset} admits it`);
  }
  const { S, base } = await run({ material_use: "operator_supplied=none" });
  const p = await program(base);
  refused(await admitMaterial(S, req(p.path, { source: "the operator's build" })), /case policy standard does not let a record cite or rest on material of class operator_supplied \(material_use operator_supplied=none\): a tool supplied under it could be run but nothing recorded on its output could be kept; nothing was added/);
  assert.deepEqual(await readdir(join(S, "store", "imports")).catch(() => []), [], "nothing was sealed, and no id was reserved");
  // Plain material under the same policy is still kept on the record, as it always was.
  const memo = join(base, "memo.txt");
  await writeFile(memo, "a note\n");
  added(await admitMaterial(S, { mode: "material", path: memo, why: "a note", supplied_by: WHO, via: "cli" }));
});

test("a tool says where it came from, and what it says is held: the source is required, a hash given must be one of the files supplied, a request or lead must exist, nothing is cut", async () => {
  const { S, base, a0 } = await run();
  const p = await program(base);
  refused(await admitMaterial(S, req(p.path, { source: "" })), /says where the tool came from/);
  refused(await admitMaterial(S, req(p.path, { source: "   " })), /says where the tool came from/);
  refused(await admitMaterial(S, req(p.path, { source: "x".repeat(4001) })), /--source is at most 4000 characters: nothing is cut/);
  refused(await admitMaterial(S, req(p.path, { source: "s", built: "x".repeat(4001) })), /--built is at most 4000 characters: nothing is cut/);
  refused(await admitMaterial(S, req(p.path, { source: "s", sha256: ["abc"] })), /--sha256 is a file's sha256, 64 hex characters \(got "abc"\)/);
  refused(await admitMaterial(S, req(p.path, { source: "s", sha256: ["0".repeat(64)] })), new RegExp(`the hash 0{64} is none of the supplied files' sha256 \\(detector is ${p.sha256}\\): a hash of anything else, a source archive or a signed index, goes in --source or --built; nothing was added`));
  refused(await admitMaterial(S, req(p.path, { source: "s", for: ["R-9"] })), /R-9 is not a request of this run/);
  refused(await admitMaterial(S, req(p.path, { source: "s", for: ["L-9"] })), /L-9 is not a lead of this run/);
  refused(await admitMaterial(S, req(p.path, { source: "s", for: ["Q-1"] })), /--for names a request or a lead, R-<n> or L-<n> \(got "Q-1"\)/);
  refused(await admitMaterial(S, { ...req(p.path, { source: "s" }), mode: "evidence" }), /a tool is supplied as material/);
  refused(await admitMaterial(S, { ...req(p.path, { source: "s" }), cls: "case_material" }), /a tool is operator-supplied material: --class is not for it/);
  refused(await admitMaterial(S, req(join(S, "SWARM.md"), { source: "s" })), /inside the run/);
  refused(await admitMaterial(S, { ...req(p.path, { source: "s" }), why: "" }), /says why/);
  assert.deepEqual(await readdir(join(S, "store", "imports")).catch(() => []), [], "every refusal left nothing behind");
  void a0;
  // What is said is kept whole, however long it is up to the limit, in the record and on the ledger.
  const long = `${"a".repeat(3990)} end`;
  const ok1 = added(await admitMaterial(S, req(p.path, { source: long, built: long })));
  const ext = (await P.readLedger(S)).find((e) => e.kind === "external")!;
  assert.equal((ext.provenance?.tool as { source: string }).source, long);
  assert.equal((ext.provenance?.tool as { built: string }).built, long);
  assert.equal((ok1.tool as { source: string }).source, long);
  // No build stated: said so, not invented.
  const q = await program(base, "other", "#!/bin/sh\necho other\n");
  const r2 = added(await admitMaterial(S, req(q.path, { source: "a vendor's release page" })));
  assert.equal((r2.tool as { built?: string }).built, undefined);
  const post = (await posts(S)).find((x) => /import:mat-0002/.test(x))!;
  assert.match(post, /How it was built: not stated by the operator\./);
  assert.match(post, /Hashes the operator gave: none; the harness holds the bytes to the sha256 each had before it was copied\./);
});

test("a directory is a tool too: a program and the libraries it loads are sealed together, each hash checked against its own file", async () => {
  const { S, base } = await run();
  const dir = join(base, "bundle");
  await mkdir(join(dir, "lib"), { recursive: true });
  await writeFile(join(dir, "prog"), "#!/bin/sh\necho prog\n");
  await writeFile(join(dir, "lib", "libx.so.1"), "library bytes\n");
  const progSha = sha("#!/bin/sh\necho prog\n");
  const libSha = sha("library bytes\n");
  refused(await admitMaterial(S, req(dir, { source: "s", sha256: [sha("elsewhere")] })), /is none of the supplied files' sha256/);
  const r = added(await admitMaterial(S, req(dir, { source: "an extracted package", sha256: [progSha, libSha, progSha] })));
  assert.deepEqual((r.tool as { checked: string[] }).checked, [progSha, libSha], "a hash named twice is checked and kept once");
  assert.deepEqual((r.files as Array<{ path: string }>).map((f) => f.path).sort(), ["lib/libx.so.1", "prog"]);
  const post = (await posts(S)).find((x) => /TOOL SUPPLIED/.test(x))!;
  assert.match(post, /job_run with programs \["import:mat-0001"\] \(and inputs \["import:mat-0001"\] when you declare them\)/);
  assert.ok(post.includes(`prog (20 bytes, sha256 ${progSha})`) && post.includes(`lib/libx.so.1 (14 bytes, sha256 ${libSha})`));
});

test("what rests on the output of a job that ran the supplied tool is marked operator_supplied through the lineage: the job's file, the finding that cites it, the answer", async () => {
  const { S, base, a0 } = await run();
  const p = await program(base);
  added(await admitMaterial(S, req(p.path, { source: "built by the operator from a public source tree" })));
  // A committed job that declared the tool among its inputs, and the file it wrote.
  const stg = join(base, "job-out");
  await mkdir(stg, { recursive: true });
  await writeFile(join(stg, "found.txt"), "three candidates\n");
  await sealTree(S, stg, join(storePaths(S).jobs, "j000001", "out"), "j000001", 1);
  await writeFile(join(storePaths(S).jobs, "j000001", "job.json"), JSON.stringify({ id: "j000001", state: "committed", requester: { agent: "a0" }, status: "ok", exit: 0, spec: { kind: "command", scope: "declared", inputs: ["import:mat-0001/detector"], command: "run the tool" } }));
  await (await Journal.open(S)).append({ type: "job_started", job: "j000001", attempt: 1, declared: ["import:mat-0001/detector"], scope: { kind: "declared" } });
  const f = ok(await P.recordEntry(a0, { kind: "finding", basis: "observed", confidence: "high", indicates: "What the observation shows, and the step to it.", confidence_why: "Read directly from the object it cites.", value: "The tool reports three candidates", source: "the job's output", evidence: "found.txt", refs: ["job:j000001/found.txt"], answers: ["1"] } as P.LedgerInput));
  ok(await P.recordEntry(a0, { kind: "answer", result: "established", confidence: "high", confidence_why: "The finding is read from the object.", alternatives_open: "none remains open", would_change: "a record that disagrees", section: "question:1", value: "Three candidates", reasoning: `E-${f.entry.seq} shows it` } as unknown as P.LedgerInput));
  const lin = await externalLineage(S);
  assert.deepEqual(lin.classes.get(f.entry.seq), ["operator_supplied"], "the finding that cites the job's file rests on the supplied tool");
  assert.ok((lin.jobs.get("j000001") ?? []).some((v) => v.startsWith("import:mat-0001")), "the job is tainted by the import it read");
  const check = await checkLedgerAnswers(S, ["question:1"]);
  assert.deepEqual(check.external["question:1"]?.classes, ["operator_supplied"]);
});

test("a directory is sealed whole, so hidden files in it are refused and a path that holds the run is refused; a file named directly is its own choice", async () => {
  const { S, base } = await run();
  const dir = join(base, "bundle2");
  await mkdir(join(dir, ".git"), { recursive: true });
  await writeFile(join(dir, "prog"), "#!/bin/sh\necho prog\n");
  await writeFile(join(dir, ".env"), "TOKEN=abc\n");
  await writeFile(join(dir, ".git", "config"), "[remote]\n");
  refused(await admitMaterial(S, req(dir, { source: "s" })), /holds hidden files or directories \(\.env, \.git\/config\): a directory supplied as a tool is sealed whole and every seat reads all of it, so a \.env, a \.git\/config or a \.netrc would go with it; remove them or give the files themselves; nothing was added/);
  assert.deepEqual(await readdir(join(S, "store", "imports")).catch(() => []), [], "nothing was sealed");
  // Plain material is unchanged: a directory with a hidden file is sealed as it always was.
  added(await admitMaterial(S, { mode: "material", path: dir, why: "a bundle", supplied_by: WHO, via: "cli" }));
  // A hidden file given as the file itself is the operator's choice.
  const lone = join(base, ".tool");
  await writeFile(lone, "#!/bin/sh\n");
  added(await admitMaterial(S, req(lone, { source: "s" })));
  // The run's parent holds the run: every run beside it would be copied.
  refused(await admitMaterial(S, req(dirname(S), { source: "s" })), /holds the run \(.*\): adding it would copy the run, and every run beside it if it is the runs directory; give the files themselves/);
  refused(await admitMaterial(S, { mode: "material", path: dirname(S), why: "all", supplied_by: WHO, via: "cli" }), /holds the run/);
  refused(await admitMaterial(S, { mode: "evidence", path: dirname(S), why: "all", supplied_by: WHO, via: "cli" }), /holds the run|admits no evidence/);
});

test("the command line holds the policy's rule, the statements, the hashes and the directory's hidden files before it hands the act to a hub, which may be older than this checkout and apply none of them", async () => {
  const out = await mkdtemp("/tmp/tsc.");
  dirs.push(out);
  const S = join(out, "run");
  await P.initSandbox(S, { swarmId: "c1", agentIds: ["a0"], capUsd: 5, wallClockMinutes: 30, goal: GOAL });
  await mkdir(join(S, "network"), { recursive: true });
  await writeFile(join(S, "network", "policy.json"), JSON.stringify(policyOf({})));
  const p = await program(out);
  // A hub from an older harness: it takes any act, says ok, and records nothing of a tool.
  const received: Array<Record<string, unknown>> = [];
  const sock = join(out, "h.sock");
  const hub = createServer((c) => {
    let buf = "";
    c.on("data", (d) => {
      buf += String(d);
      if (!buf.includes("\n")) return;
      received.push(JSON.parse(buf.split("\n")[0]!) as Record<string, unknown>);
      c.end(`${JSON.stringify({ ok: true, import: "mat-0001", mode: "material", class: "operator_supplied", files: [], manifest_sha256: "m", journal_seq: 1, entry: 1, permitted_use: "reference", complete: true })}\n`);
    });
  });
  await new Promise<void>((done) => hub.listen(sock, done));
  const cli = (args: string[]) =>
    new Promise<{ ok: boolean; reason?: string }>((done) => {
      const c = spawn("node", ["--experimental-strip-types", "--no-warnings", join(ROOT, "scripts", "material.ts"), "tool-add", S, ...args, "--hub-admin", sock], { env: { ...process.env, SWARM_RUNS_DIR: join(out, "runs") } });
      let text = "";
      c.stdout.on("data", (d) => (text += String(d)));
      c.on("close", () => done(JSON.parse(text.trim().split("\n").at(-1) ?? "{}")));
    });
  try {
    // Refused by the command line: the hub is never asked.
    assert.match((await cli([p.path, "--why", "a tool", "--source", "s", "--sha256", "0".repeat(64)])).reason ?? "", /is none of the supplied files' sha256/);
    assert.match((await cli([p.path, "--why", "a tool"])).reason ?? "", /says where the tool came from/);
    assert.match((await cli([p.path, "--why", "a tool", "--source", "s", "--sha256", "abc"])).reason ?? "", /64 hex characters/);
    const dir = join(out, "bundle3");
    await mkdir(dir, { recursive: true });
    await writeFile(join(dir, ".netrc"), "machine x\n");
    await writeFile(join(dir, "prog"), "x\n");
    assert.match((await cli([dir, "--why", "a tool", "--source", "s"])).reason ?? "", /holds hidden files or directories \(\.netrc\)/);
    await writeFile(join(S, "network", "policy.json"), JSON.stringify(policyOf({ material_use: "operator_supplied=none" })));
    assert.match((await cli([p.path, "--why", "a tool", "--source", "s"])).reason ?? "", /material_use operator_supplied=none/);
    assert.equal(received.length, 0, "no refused act reached the hub");
    // A good one is handed over, with the tool in it (an old hub ignores it; the shell reply says so).
    await writeFile(join(S, "network", "policy.json"), JSON.stringify(policyOf({})));
    const good = await cli([p.path, "--why", "a tool", "--source", "s", "--sha256", p.sha256]);
    assert.equal(good.ok, true);
    assert.equal(received.length, 1);
    const sent = received[0]!.request as { tool?: { source?: string; sha256?: string[] } };
    assert.deepEqual([sent.tool?.source, sent.tool?.sha256], ["s", [p.sha256]]);
  } finally {
    hub.close();
  }
});

function ok<T extends { ok: boolean }>(r: T): Extract<T, { ok: true }> {
  assert.equal(r.ok, true, (r as unknown as { reason?: string }).reason);
  return r as Extract<T, { ok: true }>;
}
