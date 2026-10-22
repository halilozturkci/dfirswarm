/**
 * The access record (docs/adr/0018, scripts/sensitive-access.ts): one reader
 * joins the store's journal, the hub's lines on the trace, the ledger and the
 * operator's audit, keeps a harness-verified link, a harness-observed read
 * and an agent's claim apart, and ends with the fixed lower-bound sentence.
 * The cases use hand-made run directories (a journal, a trace, a ledger and
 * an audit written as the run writes them) and, once, the job service's own
 * journal, so the shapes the reader holds are the service's.
 */
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { mkdir, mkdtemp, readFile, rm, symlink, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { after, test } from "node:test";
import * as P from "../extensions/protocol.ts";
import { JobService, type JobRecord } from "../scripts/job-service.ts";
import { sensitiveIndex } from "../scripts/output-hygiene.ts";
import {
  ACCESS_RULES,
  HARNESS_READS_SENTENCE,
  LOWER_BOUND_SENTENCE,
  apiPageHit,
  classifyTraceRow,
  accessRecord,
  parseSensitiveAccessArgs,
  provenance,
  renderAccess,
  verifyAccess,
  type AccessEvent,
  type AccessHit,
} from "../scripts/sensitive-access.ts";
import { listInputs, localWorker } from "./job-service-worker.ts";
import { KEY, READ_HIT, T, VALUES, fixtureFiles, hubLine, jl, sha, tempBase, traceRow, writeFiles, type Extra } from "./sensitive-access-fixture.ts";

const ROOT = join(import.meta.dirname, "..");
const SCRIPT = join(ROOT, "scripts", "sensitive-access.ts");
const dirs: string[] = [];
after(async () => {
  for (const d of dirs) {
    spawnSync("chmod", ["-R", "u+w", d]);
    await rm(d, { recursive: true, force: true });
  }
});

type Fixture = { base: string; S: string };

async function fixture(extra: Extra = {}): Promise<Fixture> {
  const base = await tempBase("access-");
  dirs.push(base);
  return { base, S: await writeFiles(base, fixtureFiles(extra)) };
}

const by = (events: AccessEvent[], via: string) => events.filter((e) => e.via === via);

test("the reader joins the four chains and keeps the three kinds of evidence apart", async () => {
  const { S } = await fixture();
  const rec = await accessRecord(S);
  assert.deepEqual(rec.problems, []);
  assert.deepEqual(rec.sources, { trace: true, journal: true, ledger: true, operator_audit: true });
  assert.equal(rec.lower_bound, LOWER_BOUND_SENTENCE);
  // Harness-verified links, from the journal: one declared, one added by the harness (named in text), one by digest.
  const links = rec.events.filter((e) => e.evidence === "harness_verified_link");
  assert.deepEqual(links.map((e) => [e.by_job, e.job, e.via, e.how, e.certainty, e.seat]).sort(), [
    ["j000034", "j000001", "declared_input", "declared", "certain", "agent-3"],
    ["j000037", "j000001", "auto_declared", "named_in_text", "text", "agent-4"],
    ["j000040", "j000034", "declared_input", "digest", "certain", "agent-3"],
  ]);
  assert.equal(links.length, 3, "the dependency of j000037 is on job_started and on job_committed: one link, not two");
  // Harness-observed reads: the hub's line, and the operator's console view of this run (not of another).
  const obs = rec.events.filter((e) => e.evidence === "harness_observed_read");
  assert.deepEqual(obs.map((e) => [e.source, e.via, e.job, e.seat ?? e.operator, e.certainty]), [
    ["trace", "path", "j000001", "agent-2", "path"],
    ["operator_audit", "operator_view", "j000001", "examiner@h1", "certain"],
  ]);
  // An agent's claim: the ledger entry that cites j000001 and j000034; the entry that cites no sensitive output is a flag, not an access.
  const claims = rec.events.filter((e) => e.evidence === "agent_claim");
  assert.deepEqual(claims.map((e) => [e.entry, e.job, e.seat, e.paths]).sort(), [[57, "j000001", "agent-3", ["job:j000001/values.jsonl"]], [57, "j000034", "agent-3", ["job:j000034/decrypted/key.bin"]]]);
  assert.equal(rec.ledger_marked_only, 1);
  // What a job with no scope could read is not a read and not a link.
  assert.deepEqual(rec.reach.map((r) => [r.job, r.could_read]), [["j000037", ["j000001", "j000034"]], ["j000060", ["j000001", "j000034", "j000037", "j000040"]]]);
  assert.ok(rec.events.every((e) => e.recorded));
  // In time order.
  const times = rec.events.map((e) => e.at ?? "");
  assert.deepEqual(times, [...times].sort());
  assert.deepEqual(rec.jobs.map((j) => [j.id, j.why, j.seat, j.kind]), [["j000001", "secret_output", "agent-2", "tool"], ["j000034", "derived", "agent-3", "command"], ["j000037", "derived", "agent-4", "command"], ["j000040", "derived", "agent-3", "command"]]);
});

test("the provenance chain says 'took it as an input' from the journal, 'read it' from the trace and 'opened the container' only as an agent's claim", async () => {
  const { S } = await fixture();
  const rec = await accessRecord(S);
  const prov = provenance(rec);
  assert.equal(prov.roots.length, 1);
  const [j000001] = prov.roots;
  assert.deepEqual([j000001.job, j000001.why, j000001.seat], ["j000001", "secret_output", "agent-2"]);
  assert.deepEqual(j000001.observed.map((e) => e.evidence), ["harness_observed_read", "harness_observed_read"]);
  assert.deepEqual(j000001.claims.map((e) => [e.evidence, e.entry]), [["agent_claim", 57]]);
  assert.deepEqual(j000001.used_by.map((c) => [c.node.job, c.link.evidence, c.link.via]), [["j000034", "harness_verified_link", "declared_input"], ["j000037", "harness_verified_link", "auto_declared"]]);
  const j000034 = j000001.used_by[0].node;
  assert.deepEqual(j000034.used_by.map((c) => [c.node.job, c.link.how]), [["j000040", "digest"]]);
  assert.deepEqual(j000034.claims.map((e) => e.entry), [57], "the claim sits under the job whose output it cites");
  assert.deepEqual(j000001.could_be_read_by, ["j000037", "j000060"]);
  assert.deepEqual(prov.evidence_kinds, ["harness_verified_link", "harness_observed_read", "agent_claim"]);
  // No claim, link or read is ever turned into another kind.
  for (const e of [...j000001.observed, ...j000001.claims, ...j000001.used_by.map((c) => c.link)]) assert.equal(e.evidence, ({ cited: "agent_claim", operator_view: "harness_observed_read", path: "harness_observed_read", text: "harness_observed_read", api_page: "harness_observed_read", declared_input: "harness_verified_link", auto_declared: "harness_verified_link" } as Record<string, string>)[e.via]);
  const text = renderAccess(rec, prov);
  assert.match(text, /\[agent claim, certain\]/);
  assert.match(text, /\[harness verified, certain\]/);
  assert.match(text, /\[harness observed, a named path\]/);
  assert.match(text, /could have been read \(no declared scope; not a read\) by: j000037, j000060/);
  assert.ok(text.endsWith(`${HARNESS_READS_SENTENCE}\n${LOWER_BOUND_SENTENCE}\n`), "the fixed sentence closes the list");
  assert.doesNotMatch(text, new RegExp(`${VALUES}|${KEY}`), "no digest of a sensitive file is in the list");
});

test("a seat that read an output and then asked for a job that declared no link to it is listed as an inference, not as a link", async () => {
  const { S } = await fixture();
  const prov = provenance(await accessRecord(S));
  // agent-2 read j000001 at 14:10:01; its j000060 was accepted at 14:20 and declared nothing; agent-3's jobs are linked or by another seat.
  assert.deepEqual(prov.roots[0].later_jobs_of_readers.map((l) => [l.seat, l.job]), [["agent-2", "j000060"]]);
  assert.match(renderAccess(await accessRecord(S)), /inference, not a record: agent-2 requested j000060/);
});

test("the lower-bound sentence is the one of ADR 0018, word for word, and the documentation holds it", async () => {
  assert.equal(LOWER_BOUND_SENTENCE, "Reads through a computed path, through a copy that was not a recorded page, or by a program that opened it by a name the command does not hold are not seen. This list is a lower bound.");
  assert.ok((await readFile(join(ROOT, "docs", "protocol.md"), "utf8")).includes(LOWER_BOUND_SENTENCE));
});

test("the rules: a path, a command, a glob, a blob, a kept copy; j000001 is not j0000010; manifest.json is not content", async () => {
  const { S } = await fixture();
  const index = await sensitiveIndex(S);
  const at = (rel: string) => join(S, rel);
  const c = (tool: string, args: Record<string, unknown>, copies?: ReadonlyMap<string, string>) =>
    classifyTraceRow({ tool, args }, index, { sandbox: S, copies }).map((h) => [h.via, h.certainty, h.job, h.part, h.paths.join()]);
  // The read tools: a named path, relative to the run or absolute inside it.
  assert.deepEqual(c("read", { path: "store/jobs/j000001/out/values.jsonl" }), [["path", "path", "j000001", "out", "store/jobs/j000001/out/values.jsonl"]]);
  assert.deepEqual(c("read", { filePath: at("store/jobs/j000001/out/values.jsonl") }), [["path", "path", "j000001", "out", "store/jobs/j000001/out/values.jsonl"]], "an absolute path, a field by another name");
  assert.deepEqual(c("ls", { path: "store/jobs/j000034/out/decrypted" }), [["path", "path", "j000034", "out", "store/jobs/j000034/out/decrypted"]]);
  assert.deepEqual(c("read", { path: "store/jobs/j000001/stdout.log" }), [["path", "path", "j000001", "log", "store/jobs/j000001/stdout.log"]]);
  assert.deepEqual(c("grep", { pattern: "x", path: "store/jobs/j000001" }), [["path", "path", "j000001", "out", "store/jobs/j000001"]], "a search over the job's directory reads what is in it");
  assert.deepEqual(c("ls", { path: "store/jobs/j000001" }), [], "a listing of the directory names files and holds none");
  // j000001 is not j0000010; a job that is not sensitive gives nothing.
  assert.deepEqual(c("read", { path: "store/jobs/j000010/out/x" }), []);
  assert.deepEqual(c("read", { path: "store/jobs/j0000010/out/x" }), []);
  assert.deepEqual(c("read", { path: "store/jobs/j000050/out/x" }), []);
  assert.deepEqual(c("read", { path: "mystore/jobs/j000001/out/x" }), []);
  assert.deepEqual(c("read", { path: "/elsewhere/store/jobs/j000001/out/x" }), [], "a path outside the run is not the run's store");
  // The records about a job are not its content.
  assert.deepEqual(c("read", { path: "store/jobs/j000001/manifest.json" }), []);
  assert.deepEqual(c("read", { path: "store/jobs/j000001/job.json" }), []);
  // A command: the text names it.
  assert.deepEqual(c("bash", { command: "cat store/jobs/j000001/out/values.jsonl | head -3" }), [["text", "text", "j000001", "out", "store/jobs/j000001/out/values.jsonl"]]);
  assert.deepEqual(c("bash", { command: `head -1 ${at("store/jobs/j000001/out/values.jsonl")}; ls store/jobs/j000010/out` }).map((x) => x[2]), ["j000001"]);
  assert.deepEqual(c("powershell", { command: "Get-Content store/jobs/j000001/out/values.jsonl" }).map((x) => [x[0], x[2]]), [["text", "j000001"]]);
  assert.deepEqual(c("bash", { command: "echo j000034" }), [["text", "text", "j000034", "run", "j000034"]], "the job id as a word of its own");
  assert.deepEqual(c("bash", { command: "echo j0000345 xj000034 j000034x" }), [], "an id inside another word is not the job");
  assert.deepEqual(c("bash", { command: "cat store/jobs/j000010/out/x inputs/notes.txt" }), []);
  // A blob is named by its part: its name is the digest of its bytes, and the line does not hold it.
  assert.deepEqual(c("bash", { command: `sha256sum store/blobs/${VALUES}` }), [["text", "text", "j000001", "blob", "store/blobs"]]);
  assert.deepEqual(c("read", { path: `store/blobs/${KEY}` }), [["path", "path", "j000034", "blob", "store/blobs"]]);
  assert.deepEqual(c("bash", { command: `sha256sum store/blobs/${sha("something else")}` }), []);
  // A glob or a walk is a possible reach, listing the sensitive jobs that existed.
  const maybe = (tool: string, args: Record<string, unknown>) => classifyTraceRow({ tool, args }, index, { sandbox: S }).map((h) => [h.via, h.certainty, h.job, h.candidates]);
  const all = ["j000001", "j000034", "j000037", "j000040"];
  assert.deepEqual(maybe("bash", { command: "cat store/jobs/*/out/*" }), [["text", "maybe", null, all]]);
  assert.deepEqual(maybe("bash", { command: "find store -type f -exec cat {} +" }), [["text", "maybe", null, all]]);
  assert.deepEqual(maybe("bash", { command: "grep -r secret store/jobs" }), [["text", "maybe", null, all]]);
  assert.deepEqual(maybe("grep", { pattern: "x", path: "store" }), [["path", "maybe", null, all]]);
  assert.deepEqual(maybe("bash", { command: "cat store/jobs/j00003*/out/key" }), [["text", "maybe", null, ["j000034", "j000037"]]], "a glob reaches the sensitive jobs it matches");
  assert.deepEqual(maybe("ls", { path: "store/jobs" }), [], "a listing of names alone is not a walk of the content");
  assert.deepEqual(maybe("bash", { command: "ls store" }), [], "no walker, no root reached");
  assert.deepEqual(maybe("bash", { command: "echo the store is open" }), []);
  // A tool the rules do not read, a row without a command, a run with no sensitive job.
  assert.deepEqual(c("edit", { path: "store/jobs/j000001/out/values.jsonl" }), []);
  assert.deepEqual(c("bash", {}), []);
  assert.deepEqual(classifyTraceRow({ tool: "read", args: { path: "store/jobs/j000001/out/x" } }, { jobs: new Map(), content: new Map(), genJob: new Map(), aliasJob: new Map() }, { sandbox: S }), []);
  // A kept copy of an earlier access is read as a copy; any other page is any other page.
  const copies = new Map([["tool-output/agent-2/bash-1.out", "j000001"]]);
  assert.deepEqual(c("read", { path: "tool-output/agent-2/bash-1.out" }, copies), [["path", "path", "j000001", "copy", "tool-output/agent-2/bash-1.out"]]);
  assert.deepEqual(c("read", { path: "tool-output/agent-2/other.out" }, copies), []);
  assert.deepEqual(c("read", { path: "tool-output/agent-2/bash-1.out" }), []);
  // An API page is certain: the bytes were in the answer.
  assert.deepEqual(apiPageHit("j000001", "stdout", "store/jobs/j000001/stdout.log"), { job: "j000001", via: "api_page", certainty: "certain", part: "stdout", paths: ["store/jobs/j000001/stdout.log"] });
});

test("a catalogue generation or alias a sensitive job made is its output too", async () => {
  const { S } = await fixture();
  await writeFile(join(S, "store", "journal.jsonl"), `${await readFile(join(S, "store", "journal.jsonl"), "utf8")}${jl({ v: 1, seq: 13, at: T(23), type: "generation_committed", generation: "g000002", job: "j000001", alias: "catalog/vault/" })}`);
  const index = await sensitiveIndex(S);
  const c = (command: string) => classifyTraceRow({ tool: "bash", args: { command } }, index, { sandbox: S }).map((h) => [h.job, h.part]);
  assert.deepEqual(c("cat catalog/gen/g000002/members.tsv"), [["j000001", "catalog"]]);
  assert.deepEqual(c("cat catalog/vault/filelist.txt"), [["j000001", "catalog"]]);
  assert.deepEqual(c("cat catalog/gen/g000009/members.tsv catalog/revisions/r1"), []);
});

test("without --derive only what the chains hold; with it, a seat row the rules read and no line records is added and marked as derived", async () => {
  const kept = { path: "tool-output/agent-2/bash-1.out", bytes: 412 };
  const { S } = await fixture({
    trace: [
      traceRow("agent-2", 1, "bash", { command: "cat store/jobs/j000001/out/values.jsonl" }, T(10), { ok: true, full_output: kept }),
      traceRow("agent-5", 1, "read", { path: "tool-output/agent-2/bash-1.out" }, T(11)),
      traceRow("agent-2", 2, "bash", { command: "cat store/jobs/*/out/*" }, T(12)),
    ],
  });
  const plain = await accessRecord(S);
  assert.deepEqual(plain.events.filter((e) => e.source === "trace"), [], "no line of the hub: nothing recorded");
  const rec = await accessRecord(S, { derive: true });
  const derived = rec.events.filter((e) => e.source === "trace");
  assert.deepEqual(derived.map((e) => [e.seat, e.via, e.certainty, e.job, e.part, e.recorded]), [
    ["agent-2", "text", "text", "j000001", "out", false],
    ["agent-5", "path", "path", "j000001", "copy", false],
    ["agent-2", "text", "maybe", null, "run", false],
  ]);
  assert.deepEqual(derived[2].maybe_jobs, ["j000001", "j000034", "j000037", "j000040"]);
  assert.ok(derived.every((e) => e.rules === ACCESS_RULES && /derived now/.test(e.note ?? "")));
  // The possible reach appears under every job it lists, as a possibility.
  const prov = provenance(rec);
  assert.ok(prov.roots[0].observed.some((e) => e.certainty === "maybe" && e.job === null));
  // A row a line records is not derived a second time.
  const both = await fixture({ trace: [traceRow("agent-2", 1, "read", { path: "store/jobs/j000001/out/values.jsonl" }, T(10)), hubLine(T(10, 1), "agent-2", READ_HIT, { sid: "sid-agent-2", seq: 1, tool: "read" })] });
  assert.deepEqual((await accessRecord(both.S, { derive: true })).events.filter((e) => e.source === "trace").map((e) => e.recorded), [true]);
  // A seat and a job at the burst limit: the line says the rest are on the trace, and the rest are not derived as missing.
  const burst = { ...hubLine(T(10, 2), "agent-2", READ_HIT, undefined), args: { rules: ACCESS_RULES, seat: "agent-2", via: "path", certainty: "path", on: { job: "j000001", part: "out" }, burst: { after: 200, note: "the rest are on the trace" } } };
  const limited = await fixture({ trace: [traceRow("agent-2", 1, "read", { path: "store/jobs/j000001/out/values.jsonl" }, T(10)), burst] });
  assert.deepEqual((await accessRecord(limited.S, { derive: true })).events.filter((e) => e.source === "trace").map((e) => [e.burst, e.recorded]), [[true, true]]);
  assert.equal((await verifyAccess(limited.S)).ok, true);
});

test("a line the hub wrote and the row it was made from are held to each other; a rules change is told as such", async () => {
  const row = traceRow("agent-2", 7, "bash", { command: "cat store/jobs/j000001/out/values.jsonl" }, T(10));
  const hit: AccessHit = { job: "j000001", via: "text", certainty: "text", part: "out", paths: ["store/jobs/j000001/out/values.jsonl"] };
  const line = (ts = T(10, 1), o: { rules?: number } = {}) => hubLine(ts, "agent-2", hit, { sid: "sid-agent-2", seq: 7, tool: "bash" }, o);
  const ok = await fixture({ trace: [row, line()] });
  assert.equal((await verifyAccess(ok.S)).ok, true);
  assert.equal((await accessRecord(ok.S)).events.filter((e) => e.source === "trace").length, 1);

  const missing = await fixture({ trace: [row] });
  const v1 = await verifyAccess(missing.S);
  assert.deepEqual(v1.unrecorded.map((u) => [u.line, u.seat, u.job, u.via]), [[1, "agent-2", "j000001", "text"]], "the hub was down, or the rules moved: a warning");
  assert.equal(v1.ok, false);

  const noRow = await fixture({ trace: [line()] });
  assert.equal((await verifyAccess(noRow.S)).orphan.length, 1, "a line whose tool row is not on the trace is an orphan");

  const wrong = await fixture({ trace: [{ ...row, args: { command: "ls inputs" } }, line()] });
  assert.equal((await verifyAccess(wrong.S)).orphan.length, 1, "a line whose row the rules do not read as naming its job is an orphan");

  const twice = await fixture({ trace: [row, line(), line(T(10, 2))] });
  assert.equal((await verifyAccess(twice.S)).duplicate.length, 1, "the same row is never written twice");

  const old = await fixture({ trace: [row, line(T(10, 1), { rules: 0 })] });
  const v3 = await verifyAccess(old.S);
  assert.deepEqual(v3.rules_changed, [0]);
  assert.deepEqual([v3.orphan.length, v3.unrecorded.length], [0, 0], "lines of older rules are kept as written; the difference is told as a rules change");
  assert.match((await accessRecord(old.S)).events.find((e) => e.source === "trace")?.note ?? "", /written under rules 0/);

  // An API page has no seat row to be held to.
  const page = await fixture({ trace: [hubLine(T(10), "agent-2", apiPageHit("j000001", "stdout", "store/jobs/j000001/stdout.log"), undefined, { api: { fn: "jobStatus", offset: 0, bytes: 412, total: 412 } })] });
  assert.equal((await verifyAccess(page.S)).ok, true);
  const ev = (await accessRecord(page.S)).events.find((e) => e.via === "api_page");
  assert.deepEqual([ev?.certainty, ev?.part, ev?.api?.bytes, ev?.evidence], ["certain", "stdout", 412, "harness_observed_read"]);
});

test("a line is read the way the hub makes it: a malformed one is a problem, not an event", async () => {
  const good = hubLine(T(1), "a", READ_HIT, { sid: "s", seq: 1, tool: "read" }).args as Record<string, any>;
  assert.equal(parseSensitiveAccessArgs(good).ok, true);
  assert.equal(parseSensitiveAccessArgs({ ...good, via: "bash" }).ok, false);
  assert.equal(parseSensitiveAccessArgs({ ...good, certainty: "sure" }).ok, false);
  assert.equal(parseSensitiveAccessArgs({ ...good, tool_row: null }).ok, false);
  assert.equal(parseSensitiveAccessArgs({ ...good, on: { ...good.on, job: "../x" } }).ok, false);
  assert.equal(parseSensitiveAccessArgs({ ...good, on: { ...good.on, part: "everything" } }).ok, false);
  assert.equal(parseSensitiveAccessArgs([]).ok, false);
  const { S } = await fixture({ trace: [{ ts: T(1), agent: "system", tool: "sensitive_access", args: { ...good, via: "nonsense" }, result: {} }] });
  const rec = await accessRecord(S);
  assert.deepEqual(rec.events.filter((e) => e.source === "trace"), []);
  assert.match(rec.problems.map((p) => p.why).join("|"), /sensitive_access line is not read \(via "nonsense"/);
});

test("a chain file that is missing, torn, a link or a directory gives a partial record and a problem line, and the rest is read", async () => {
  const { S } = await fixture();
  const events = join(S, "traces", "events.jsonl");
  await writeFile(events, `${await readFile(events, "utf8")}{"ts":"x","agent":"agent-2","tool":"re\nnot json\n[1,2]\n`);
  const rec = await accessRecord(S);
  assert.deepEqual(rec.problems.map((p) => [p.file, p.why]), [["traces/events.jsonl", "not JSON"], ["traces/events.jsonl", "not JSON"], ["traces/events.jsonl", "not a JSON object"]]);
  assert.deepEqual(rec.problems.map((p) => p.line), [5, 6, 7]);
  assert.equal(rec.events.filter((e) => e.source === "trace").length, 1, "the lines before the damage are read");
  // Missing files are empty, not a problem; a run with no chain at all is an empty record.
  const empty = await accessRecord(join(S, "no-such-run"));
  assert.deepEqual([empty.events, empty.jobs, empty.problems], [[], [], []]);
  // A link where the file should be.
  const other = await fixture({ skip: ["trace", "ledger"] });
  await mkdir(join(other.S, "traces"), { recursive: true });
  await writeFile(join(other.base, "real.jsonl"), "{}\n");
  await symlink(join(other.base, "real.jsonl"), join(other.S, "traces", "events.jsonl"));
  await mkdir(join(other.S, "ledger", "entries.jsonl"), { recursive: true });
  const r2 = await accessRecord(other.S);
  assert.deepEqual(r2.problems.map((p) => [p.file, p.why]), [["traces/events.jsonl", "a link, not the file"], ["ledger/entries.jsonl", "not a regular file"]]);
  assert.equal(r2.events.filter((e) => e.evidence === "harness_verified_link").length, 3, "the journal is still read");
});

test("a record from before `because` still shows the link, without its way", async () => {
  const { S } = await fixture();
  const j = join(S, "store", "journal.jsonl");
  const text = (await readFile(j, "utf8")).split("\n").filter(Boolean).map((l) => JSON.parse(l) as Record<string, any>);
  for (const l of text) if (l.sensitive?.because) delete l.sensitive.because;
  await writeFile(j, jl(...text));
  const rec = await accessRecord(S);
  const links = rec.events.filter((e) => e.evidence === "harness_verified_link").sort((a, b) => ((a.by_job ?? "") < (b.by_job ?? "") ? -1 : 1));
  // j000037's dependency stays from job_started; j000034 and j000040 have no way on the record.
  assert.deepEqual(links.map((e) => [e.by_job, e.job, e.how]), [["j000034", "j000001", null], ["j000037", "j000001", "named_in_text"], ["j000040", "j000034", null]]);
  assert.match(links[0].note ?? "", /the way is not recorded/);
});

test("the store's sensitive index reads past a journal line or a manifest that is not the shape (it threw on them)", async () => {
  const { S } = await fixture();
  const j = join(S, "store", "journal.jsonl");
  await writeFile(j, `${await readFile(j, "utf8")}${["null", "[]", "5", JSON.stringify({ type: "job_committed", job: { x: 1 }, sensitive: { why: "derived" } }), JSON.stringify({ type: "job_committed", job: "../../x", sensitive: { why: "derived" } }), JSON.stringify({ type: "job_committed", job: "j000099", sensitive: "yes" })].join("\n")}\n`);
  await writeFile(join(S, "store", "jobs", "j000001", "manifest.json"), JSON.stringify({ files: 5 }));
  await writeFile(join(S, "store", "jobs", "j000034", "manifest.json"), JSON.stringify({ files: [null, 3, { path: "k", sha256: KEY, bytes: 1 }] }));
  const index = await sensitiveIndex(S);
  assert.deepEqual([...index.jobs.keys()].sort(), ["j000001", "j000034", "j000037", "j000040"]);
  assert.equal(index.content.get(KEY), "j000034");
  assert.equal((await accessRecord(S)).jobs.length, 4);
});

test("what a chain holds of a job the journal does not show as sensitive is said, not dropped", async () => {
  const { S } = await fixture({ skip: ["journal"] });
  const rec = await accessRecord(S);
  assert.deepEqual(rec.jobs, []);
  assert.ok(rec.events.length >= 2, "the hub's line and the console view are still events");
  const text = renderAccess(rec);
  assert.match(text, /Not under a sensitive job of this record:/);
  assert.match(text, /j000001: agent-2: read store\/jobs\/j000001\/out\/values.jsonl/);
  assert.ok(text.endsWith(`${LOWER_BOUND_SENTENCE}\n`));
});

test("the command line: text ends with the fixed sentence, --json is the record and the chains, a missing directory is told", async () => {
  const { S } = await fixture();
  const run = (...args: string[]) => spawnSync(process.execPath, ["--experimental-strip-types", "--no-warnings", SCRIPT, ...args], { encoding: "utf8" });
  const text = run(S);
  assert.equal(text.status, 0, text.stderr);
  assert.ok(text.stdout.endsWith(`${LOWER_BOUND_SENTENCE}\n`));
  assert.match(text.stdout, /Access to sensitive outputs: 7 events on 4 sensitive jobs/);
  assert.match(text.stdout, /j000001 {2}tool {2}agent-2 {2}secret_output/);
  assert.match(text.stdout, /used by j000034/);
  const json = run(S, "--json");
  assert.equal(json.status, 0, json.stderr);
  const out = JSON.parse(json.stdout) as { record: { events: unknown[]; lower_bound: string }; provenance: { roots: Array<{ job: string }> } };
  assert.equal(out.record.events.length, 7);
  assert.equal(out.record.lower_bound, LOWER_BOUND_SENTENCE);
  assert.deepEqual(out.provenance.roots.map((r) => r.job), ["j000001"]);
  const job = JSON.parse(run(S, "--json", "--job", "j000034").stdout) as { record: { events: Array<{ job: string; by_job?: string }> } };
  assert.ok(job.record.events.length && job.record.events.every((e) => e.job === "j000034" || e.by_job === "j000034"));
  const seat = JSON.parse(run(S, "--json", "--seat", "agent-3").stdout) as { record: { events: Array<{ seat: string }> } };
  assert.ok(seat.record.events.length && seat.record.events.every((e) => e.seat === "agent-3"));
  const ver = run(S, "--verify");
  assert.match(ver.stdout, /Verification against the trace: differences; 1 row\(s\) the rules read have no line/, "agent-3's ls of j000034 has no line of the hub");
  const row = traceRow("agent-2", 1, "read", { path: "store/jobs/j000001/out/values.jsonl" }, T(10));
  const line = hubLine(T(10, 1), "agent-2", READ_HIT, { sid: "sid-agent-2", seq: 1, tool: "read" });
  const agreed = await fixture({ trace: [row, line] });
  assert.match(run(agreed.S, "--verify").stdout, /Verification against the trace: the lines and the rows agree/);
  assert.equal(run().status, 2);
  const bad = run(join(S, "nope"));
  assert.equal(bad.status, 1);
  assert.match(bad.stderr, /is not a directory/);
  // An operator's audit beside a run directory elsewhere.
  const moved = run(S, "--json", "--runs-dir", join(S, "no-audit"));
  assert.equal((JSON.parse(moved.stdout) as { record: { sources: { operator_audit: boolean } } }).record.sources.operator_audit, false);
});

test("the job service's own journal is read: a declared job, a job that named one, a chain, and what a scope-less job could read", async () => {
  const base = await mkdtemp(join(tmpdir(), "access-svc-"));
  dirs.push(base);
  const S = join(base, "sacc");
  await P.initSandbox(S, { swarmId: "sacc", agentIds: ["a1", "a2"] });
  for (const d of ["inputs", "tools", "catalog", "work/a1", "work/a2"]) await mkdir(join(S, d), { recursive: true });
  await writeFile(join(S, "inputs", "notes.txt"), "a note\n");
  listInputs(S);
  const svc = new JobService({
    sandbox: S, run: "sacc", image: "img:test", workers: 2, workerCpus: 1, workerMemoryMib: 512, allowHosts: [], openNet: false,
    packDirs: [join(ROOT, "packs", "computer-forensics-base")], forging: false, minFreeMb: 1,
    runWorker: localWorker(), destroyWorker: async () => ({ ok: true }), notify: async () => undefined, identity: async (a) => ({ name: a }),
  });
  await svc.start();
  const submit = async (who: string, spec: Record<string, unknown>): Promise<JobRecord> => {
    const r = await svc.submit(who, { kind: "command", timeout_seconds: 60, network: "off", ...spec } as never);
    assert.ok(r.ok, !r.ok ? r.reason : "");
    for (let i = 0; i < 1200; i += 1) {
      const j = svc.jobs.get(r.job.id);
      if (j && ["committed", "failed", "cancelled"].includes(j.state)) return j;
      await new Promise((res) => setTimeout(res, 50));
    }
    throw new Error("a job did not finish");
  };
  const secret = await submit("a1", { command: `printf '%s' 'TOKEN-sample-7f3a91' > "$OUT/value.txt"`, inputs: [], secret_output: true });
  const declared = await submit("a2", { command: `echo d > "$OUT/d.txt"`, inputs: [`job:${secret.id}/value.txt`] });
  const named = await submit("a2", { command: `wc -c store/jobs/${secret.id}/out/value.txt > "$OUT/c.txt"`, inputs: ["all"] });
  const chained = await submit("a1", { command: `echo again > "$OUT/a.txt"`, inputs: [`job:${declared.id}`] });
  const plain = await submit("a2", { command: `echo plain > "$OUT/p.txt"`, inputs: ["all"] });
  await svc.stop("test over");
  // The trace and the ledger the hub and the agents would have written.
  await mkdir(join(S, "traces"), { recursive: true });
  await writeFile(join(S, "traces", "events.jsonl"), jl({ ts: T(1), agent: "a1", tool: "bash", args: { command: `cat store/jobs/${secret.id}/out/value.txt` }, result: { ok: true }, sid: "s", seq: 1 }));
  await mkdir(join(S, "ledger"), { recursive: true });
  await writeFile(join(S, "ledger", "entries.jsonl"), jl({ v: 4, seq: 1, kind: "finding", value: "v", refs: [`job:${chained.id}/a.txt`], by: "a1", at: T(3) }));

  const rec = await accessRecord(S, { derive: true, runsDir: base });
  assert.deepEqual(rec.problems, []);
  const links = rec.events.filter((e) => e.evidence === "harness_verified_link").map((e) => [e.by_job, e.job, e.via, e.how, e.certainty]).sort();
  assert.deepEqual(links, [
    [chained.id, declared.id, "declared_input", "declared", "certain"],
    [declared.id, secret.id, "declared_input", "declared", "certain"],
    [named.id, secret.id, "auto_declared", "named_in_text", "text"],
  ].sort());
  assert.deepEqual(rec.reach.map((r) => [r.job, r.could_read]).filter(([j]) => j === plain.id), [[plain.id, [secret.id, declared.id, named.id, chained.id].sort()]]);
  assert.ok(rec.reach.some((r) => r.job === named.id && r.could_read.includes(secret.id)));
  assert.deepEqual(rec.events.filter((e) => e.source === "trace").map((e) => [e.seat, e.via, e.job, e.recorded]), [["a1", "text", secret.id, false]]);
  assert.deepEqual(rec.events.filter((e) => e.evidence === "agent_claim").map((e) => [e.entry, e.job, e.seat]), [[1, chained.id, "a1"]]);
  const prov = provenance(rec);
  assert.deepEqual(prov.roots.map((r) => r.job), [secret.id]);
  assert.deepEqual(prov.roots[0].used_by.map((c) => c.node.job).sort(), [declared.id, named.id].sort());
  assert.equal(prov.roots[0].used_by.find((c) => c.node.job === declared.id)?.node.used_by[0].node.job, chained.id);
  assert.equal(prov.roots[0].used_by.find((c) => c.node.job === declared.id)?.node.used_by[0].node.claims.length, 1);
});
