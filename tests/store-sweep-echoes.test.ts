/**
 * The store sweep's echoes (docs/adr/0013, "Echoes: authored, not
 * derived"): a hit in an object whose every name was made from the run's
 * own words (a command that read only the registers, a compaction summary
 * the harness kept) or by a search that asked for the string and read only
 * named objects the sweep found it in is named on the sweep as an echo and
 * holds nothing; a hit whose maker read evidence the record does not name,
 * an input, or paths that cannot be told still holds; a kept output and
 * the import it was sealed as are one object; a recorded sweep read again
 * (replay --resweep) moves what this harness would. Synthetic runs only.
 */
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import { existsSync } from "node:fs";
import { appendFile, mkdir, readFile, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { test } from "node:test";
import * as P from "../extensions/protocol.ts";
import * as L from "../extensions/leads.ts";
import { SELF_COMPACT_EVENTS } from "../extensions/self-compact.ts";
import * as SW from "../extensions/store-sweep.ts";
import { checkLedgerAnswers } from "../scripts/check-answers.ts";
import { sealTree, storePaths } from "../scripts/evidence-store.ts";
import { measureRun } from "../scripts/metrics.ts";
import type { Replay } from "../scripts/replay.ts";
import { A, coverage, F, ok, planned, rec, REVIEW, run } from "./negative-bar-fixture.ts";

const sha = (s: string | Buffer) => createHash("sha256").update(s).digest("hex");

/** Lines appended to the run's trace as the collector writes them: each chained to the one before by its sha256. Returns each line's sha256. */
async function traceLines(S: string, records: Array<Record<string, unknown>>): Promise<string[]> {
  const file = join(S, "traces", "events.jsonl");
  await mkdir(join(S, "traces"), { recursive: true });
  const had = existsSync(file) ? (await readFile(file, "utf8")).split("\n").filter(Boolean) : [];
  let prev: string | null = had.length ? sha(had.at(-1)!) : null;
  const out: string[] = [];
  for (const r of records) {
    const line = JSON.stringify({ ts: "2026-09-30T08:00:00.000Z", sid: "s1", ...r, recv_ts: "2026-09-30T08:00:00.100Z", prev });
    await appendFile(file, `${line}\n`);
    prev = sha(line);
    out.push(prev);
  }
  return out;
}

/** A whole output the harness kept under tool-output/<seat>/, and the trace line that kept it (then a line after it, which puts it on the chain). Returns its tool: ref and the line's sha256. */
async function kept(S: string, seat: string, file: string, body: string, line: { tool: string; args: Record<string, unknown>; agent?: string }, o: { follow?: boolean } = {}): Promise<{ ref: string; line: string }> {
  const rel = `tool-output/${seat}/${file}`;
  await mkdir(join(S, "tool-output", seat), { recursive: true });
  await writeFile(join(S, rel), body);
  const [h] = await traceLines(S, [
    { agent: line.agent ?? seat, tool: line.tool, args: line.args, result: { ok: true, output: "(prefix)", full_output: { path: rel, bytes: Buffer.byteLength(body), lines: body.split("\n").length - 1, sha256: sha(body) } } },
    ...(o.follow === false ? [] : [{ agent: seat, tool: "ls", args: {}, result: { ok: true } }]),
  ]);
  return { ref: `tool:${seat}/${file}`, line: h! };
}

/** A committed job whose one output holds `body`, made as `spec` says. */
async function jobWith(S: string, id: string, file: string, body: string, spec: Record<string, unknown>): Promise<void> {
  const staging = join(S, "..", `staging-${id}-${Math.random().toString(16).slice(2)}`);
  await mkdir(staging, { recursive: true });
  await writeFile(join(staging, file), body);
  await sealTree(S, staging, join(storePaths(S).jobs, id, "out"), id, 1);
  await writeFile(join(storePaths(S).jobs, id, "job.json"), JSON.stringify({ id, state: "committed", requester: { agent: "a0" }, status: "ok", exit: 0, spec }));
}

const attested = async (c: { sandboxRoot: string; agentId: string }, input: P.LedgerActInput) => {
  const r = await P.attestEntry(c, input);
  assert.ok(r.ok && (r as { line: unknown }).line, JSON.stringify(r));
};
const codes = (r: Awaited<ReturnType<typeof checkLedgerAnswers>>, section: string) => r.defects.filter((d) => d.section === section).map((d) => d.code);
const PY_LEDGER = "python3 - <<'PY'\nimport json\nfor l in open('ledger/entries.jsonl'):\n    r = json.loads(l)\n    print(r['seq'], r.get('value'))\nPY";

test("an echo is not held: an output made from the run's registers, a summary the harness kept from a seat's words, and a search over a named object the sweep found the string in are named as echoes; the review offer, ledger.md and the metrics say them", async () => {
  const { S, a0, a1, a2, a3 } = await run();
  await jobWith(S, "j000007", "export.csv", "time,user\n09:58,alice\n", { kind: "command", scope: "declared", inputs: ["input:disk.E01"], command: "export" });
  // The ledger dumped by a seat's own script: the run's words about alice, not evidence of her.
  const dump = await kept(S, "a1", "20260930080000000-bash-aaaa.out.log", "12 a note that alice was looked for\n13 none found\n", { tool: "bash", args: { command: PY_LEDGER, timeout: 60 } });
  // A compaction summary the harness kept from the seat's model: its own words.
  const summary = await kept(S, "a2", "20260930080100000-compact_summary-bbbb.text.log", "## Where I am\nsearching the disk for alice; nothing yet\n", { tool: "compact_failed", args: { stage: "summary", attempt: 1 } });
  // A search for the string over a named object the sweep finds it in: its matches say again what the named hit says.
  const grep = await kept(S, "a3", "20260930080200000-bash-cccc.out.log", "store/jobs/j000007/out/export.csv:09:58,alice\n", { tool: "bash", args: { command: "grep -Hi 'alice' store/jobs/j000007/out/export.csv" } });
  // The trace spilled under a seat's tool-output/ (a microVM seat that could not reach its collector): the trace itself.
  await writeFile(join(S, "tool-output", "a3", "trace-spill.jsonl"), `${JSON.stringify({ agent: "a3", tool: "bash", args: { command: "grep -ri alice inputs/" } })}\n`);
  const spill = "tool:a3/trace-spill.jsonl";
  await planned(a0, "2");
  const abs = ok(await rec(a0, { kind: "absence", value: "a remote tool", source: "the disk", evidence: "a search", refs: ["job:j000001/hits.txt"], answers: ["2"] })).entry;
  const cov = ok(await rec(a0, coverage("2", ["input:disk.E01", "job:j000007"], [`E-${abs.seq}`, "job:j000001/hits.txt"], { looked_for: ["alice"] }))).entry;
  const ans = ok(await rec(a1, { kind: "answer", section: "question:2", value: "No evidence of a remote tool was found on the disk", reasoning: `E-${cov.seq}`, ...A, result: "bounded_negative" })).entry;
  await SW.awaitSweeps(S);
  const sw = SW.sweepOf(cov, await SW.readSweeps(S))!;
  assert.equal(sw.state, "clean", JSON.stringify(sw.hits));
  assert.deepEqual(sw.hits, []);
  assert.deepEqual(sw.named_hits.map((h) => h.ref), ["job:j000007/export.csv"]);
  assert.deepEqual(sw.echoes!.map((h) => h.ref).sort(), [dump.ref, summary.ref, grep.ref, spill].sort());
  const why = (ref: string) => sw.echoes!.find((h) => h.ref === ref)!.origins!;
  assert.deepEqual(why(dump.ref), [{ name: dump.ref, by: `trace:${dump.line}`, why: "registers" }]);
  assert.deepEqual(why(summary.ref), [{ name: summary.ref, by: `trace:${summary.line}`, why: "harness" }]);
  assert.deepEqual(why(grep.ref), [{ name: grep.ref, by: `trace:${grep.line}`, why: "searched", reads: ["job:j000007/export.csv"] }]);
  assert.deepEqual(why(spill), [{ name: spill, by: "trace-spill", why: "registers" }]);
  assert.equal(SW.verifySweepChain(await readFile(join(S, SW.LEDGER_SWEEPS), "utf8")).ok, true);
  // Said, where the record is read and where it is reviewed.
  const words = SW.sweepWords(sw, cov);
  assert.match(words, /echoes, holding nothing \(is each only the run's own words\?\): .*from the run's own registers: the run's words, not evidence/);
  assert.match(words, /kept by the harness from a seat's own words/);
  assert.match(words, /whose own words name the string: an echo of the search/);
  // The sweep's own render of ledger.md can be overtaken by one that began before its line was written (two renders write the same file, the later write
  // wins); render once more from what is on disk, which is what this reads.
  await P.renderLedger(S);
  assert.match(await readFile(join(S, P.LEDGER_MD), "utf8"), /store sweep clean: .*echoes, holding nothing/);
  await L.leadsDigest(a3);
  const snap = await L.leadsSnapshot(S);
  const offer = snap.state.reviewOffers.get(`E-${ans.seq}`)?.at(-1);
  assert.ok(offer, "the negative's review is offered");
  assert.match(L.reviewOfferText(`E-${ans.seq}`, offer!, snap), new RegExp(`echoes, holding nothing .*${dump.ref.replace(/[.*+?^${}()|[\]\\/]/g, "\\$&")}`));
  // Reviewed, and nothing holds.
  await attested({ sandboxRoot: S, agentId: offer!.to }, { seq: cov.seq, how: "ran the search again", review: REVIEW });
  const r = await checkLedgerAnswers(S, ["2"], ["2"]);
  assert.deepEqual(codes(r, "question:2"), [], r.lines.join("\n"));
  assert.equal(r.dispositions["question:2"], "bounded_negative");
  const m = await measureRun(S);
  assert.deepEqual([m.sweeps.with_hits, m.sweeps.hit_objects, m.sweeps.echoes], [0, 0, 4]);
});

test("a hit still holds when what made it read evidence the record does not name, an input (which the sweep never reads), a path it cannot tell or none, or when no attributed line on the chain kept it", async () => {
  const { S, a0, a1, a2 } = await run();
  const made: Record<string, string> = {};
  // A search over an input the record does not name: its matches are the miss the sweep is for.
  made.unnamed = (await kept(S, "a1", "20260930081000000-bash-dddd.out.log", "b.log:alice logged on at 09:58\n", { tool: "bash", args: { command: "grep -i alice inputs/logs/b.log" } })).ref;
  // A search over an input the record names: the sweep never reads the image, so this is the only place its rows show (the round-13 export).
  made.namedInput = (await kept(S, "a1", "20260930081100000-bash-eeee.out.log", "disk:alice in a registry hive\n", { tool: "bash", args: { command: "strings -a inputs/disk.E01 | grep -i alice" } })).ref;
  // A search that names no path: what it read cannot be told.
  made.noPath = (await kept(S, "a1", "20260930081200000-bash-ffff.out.log", "./notes:alice?\n", { tool: "bash", args: { command: "rg -i alice" } })).ref;
  // The registers and a seat's own file: the file is not a register.
  made.mixed = (await kept(S, "a2", "20260930081300000-bash-gggg.out.log", "alice, from the notes and the ledger\n", { tool: "bash", args: { command: `${PY_LEDGER}\ncat work/a2/notes.txt` } })).ref;
  // The registers and a path outside the run.
  made.outside = (await kept(S, "a2", "20260930081400000-bash-hhhh.out.log", "alice, from the ledger and a copy in /tmp\n", { tool: "bash", args: { command: "cat ledger/entries.jsonl /tmp/copy.txt" } })).ref;
  // A line another seat wrote about this seat's file: not attributed to the seat whose directory holds it.
  made.otherSeat = (await kept(S, "a1", "20260930081500000-bash-iiii.out.log", "alice, said by a peer\n", { tool: "bash", agent: "a2", args: { command: "cat ledger/entries.jsonl" } })).ref;
  // The trace's last line, with no anchor to hold it: not on the chain yet.
  made.unchained = (await kept(S, "a1", "20260930081600000-bash-jjjj.out.log", "alice, the last line\n", { tool: "bash", args: { command: "cat ledger/entries.jsonl" } }, { follow: false })).ref;
  await planned(a0, "2");
  const abs = ok(await rec(a0, { kind: "absence", value: "a remote tool", source: "the disk", evidence: "a search", refs: ["job:j000001/hits.txt"], answers: ["2"] })).entry;
  const cov = ok(await rec(a0, coverage("2", ["input:disk.E01"], [`E-${abs.seq}`, "job:j000001/hits.txt"], { looked_for: ["alice"] }))).entry;
  ok(await rec(a1, { kind: "answer", section: "question:2", value: "No evidence of a remote tool was found on the disk", reasoning: `E-${cov.seq}`, ...A, result: "bounded_negative" }));
  await SW.awaitSweeps(S);
  const sw = SW.sweepOf(cov, await SW.readSweeps(S))!;
  assert.equal(sw.state, "hits");
  assert.deepEqual(sw.hits.map((h) => h.ref).sort(), Object.values(made).sort());
  assert.deepEqual(sw.echoes, [], "none of them is an echo");
  assert.ok(sw.hits.every((h) => !h.origins), "a hit that holds carries no makers");
  await attested(a2, { seq: cov.seq, how: "ran the search again", review: REVIEW });
  const r = await checkLedgerAnswers(S, ["2"], ["2"]);
  assert.deepEqual(codes(r, "question:2"), ["sweep_hits"], r.lines.join("\n"));
});

test("a job whose own command names the string is an echo when it read only named objects the sweep found the string in; one that read an input, saw everything or reached the network holds; one that names nothing is said among the named hits", async () => {
  const { S, a0, a1, a2 } = await run();
  await jobWith(S, "j000007", "export.csv", "time,user\n09:58,alice\n", { kind: "command", scope: "declared", inputs: ["input:disk.E01"], command: "export" });
  const grep = (inputs: string[], o: Record<string, unknown> = {}) => ({ kind: "command", scope: "declared", inputs, network: "off", command: "grep -Hi alice \"$IN\"/* > \"$OUT/hits.txt\"", ...o });
  await jobWith(S, "j000008", "hits.txt", "export.csv:09:58,alice\n", grep(["job:j000007/export.csv"]));
  await jobWith(S, "j000009", "hits.txt", "b.log:alice logged on\n", grep(["input:logs/b.log"]));
  await jobWith(S, "j000010", "hits.txt", "anywhere:alice\n", grep(["all"], { scope: "all" }));
  await jobWith(S, "j000011", "hits.txt", "export.csv and the web:alice\n", grep(["job:j000007/export.csv"], { network: "allowlist" }));
  await jobWith(S, "j000012", "summary.txt", "users seen: alice (1)\n", { kind: "command", scope: "declared", inputs: ["job:j000007/export.csv"], network: "off", command: "python3 summarise.py" });
  await jobWith(S, "j000013", "hits.txt", "export.csv, whole:alice\n", grep(["input:disk.E01"]));
  await planned(a0, "2");
  const abs = ok(await rec(a0, { kind: "absence", value: "a remote tool", source: "the disk", evidence: "a search", refs: ["job:j000001/hits.txt"], answers: ["2"] })).entry;
  const cov = ok(await rec(a0, coverage("2", ["input:disk.E01", "job:j000007"], [`E-${abs.seq}`, "job:j000001/hits.txt"], { looked_for: ["alice"] }))).entry;
  ok(await rec(a1, { kind: "answer", section: "question:2", value: "No evidence of a remote tool was found on the disk", reasoning: `E-${cov.seq}`, ...A, result: "bounded_negative" }));
  await SW.awaitSweeps(S);
  const sw = SW.sweepOf(cov, await SW.readSweeps(S))!;
  assert.deepEqual(sw.echoes!.map((h) => [h.ref, h.origins]), [["job:j000008/hits.txt", [{ name: "job:j000008/hits.txt", by: "job:j000008", why: "searched", reads: ["job:j000007/export.csv"] }]]]);
  assert.deepEqual(sw.hits.map((h) => h.ref), ["job:j000009/hits.txt", "job:j000010/hits.txt", "job:j000011/hits.txt", "job:j000013/hits.txt"], "an input, everything, the network, or a named input the sweep never reads");
  assert.deepEqual(sw.named_hits.map((h) => [h.ref, h.origins?.map((o) => o.why) ?? null]), [["job:j000007/export.csv", null], ["job:j000012/summary.txt", ["named_sources"]]]);
  assert.match(SW.sweepWords(sw, cov), /"alice" in job:j000012\/summary\.txt, .*\[made by job:j000012 from job:j000007\/export\.csv, which the record names\]/);
  await attested(a2, { seq: cov.seq, how: "ran the search again", review: REVIEW });
  const r = await checkLedgerAnswers(S, ["2"], ["2"]);
  assert.deepEqual(codes(r, "question:2"), ["sweep_hits"]);
  const d = r.defects.find((x) => x.code === "sweep_hits")!;
  assert.doesNotMatch(d.what, /j000008|j000012/, "the echo and the named reading hold nothing");
});

test("a kept output and the import it was sealed as are one object: a record that names the import names the kept file (the run sd0e59d), and a recorded sweep read again says so", async () => {
  const { S, a0, a1, a2 } = await run();
  const file = "20260930082000000-bash-kkkk.out.log";
  const body = "a.log: alice logged on at 09:58 from ws-11\n";
  const k = await kept(S, "a1", file, body, { tool: "bash", args: { command: "strings -a inputs/logs/a.log" } });
  // Sealed when a record cited it: an import job whose output holds the kept bytes, published as an import, and the journal's line.
  const staging = join(S, "..", `staging-seal-${Math.random().toString(16).slice(2)}`);
  await mkdir(staging, { recursive: true });
  await writeFile(join(staging, file), body);
  await sealTree(S, staging, join(storePaths(S).jobs, "j000020", "out"), "j000020", 1);
  await writeFile(join(storePaths(S).jobs, "j000020", "job.json"), JSON.stringify({ id: "j000020", state: "committed", status: "ok", requester: { agent: "a1" }, spec: { kind: "import", scope: "declared", inputs: [`tool-output/a1/${file}`], seal: { ref: k.ref } } }));
  const staging2 = join(S, "..", `staging-seal2-${Math.random().toString(16).slice(2)}`);
  await mkdir(staging2, { recursive: true });
  await writeFile(join(staging2, file), body);
  await sealTree(S, staging2, join(storePaths(S).imports, "j000020", "out"), "j000020", 1);
  await planned(a0, "2");
  const abs = ok(await rec(a0, { kind: "absence", value: "a remote tool", source: "the disk", evidence: "a search", refs: ["job:j000001/hits.txt"], answers: ["2"] })).entry;
  const cov = ok(await rec(a0, coverage("2", ["input:disk.E01"], [`E-${abs.seq}`, "job:j000001/hits.txt"], { looked_for: ["alice"] }))).entry;
  let ans = ok(await rec(a1, { kind: "answer", section: "question:2", value: "No evidence of a remote tool was found on the disk", reasoning: `E-${cov.seq}`, ...A, result: "bounded_negative" })).entry;
  await SW.awaitSweeps(S);
  const sw = SW.sweepOf(cov, await SW.readSweeps(S))!;
  // One object under three names: a dump of an input the record does not name, so it holds.
  assert.deepEqual(sw.hits.map((h) => [h.ref, h.also]), [[`import:j000020/${file}`, [`job:j000020/${file}`, k.ref]]]);
  // What the kept output showed, after the sweep, and the record revised to name the import: the kept file is named with it.
  const seen = ok(await rec(a0, { kind: "finding", ...F, value: "the alice in the strings is another host's user", source: "the strings", evidence: "line 1", refs: [`import:j000020/${file}`], answers: ["2"] })).entry;
  const cov2 = ok(await rec(a0, coverage("2", ["input:disk.E01", `import:j000020/${file}`], [`E-${abs.seq}`, "job:j000001/hits.txt", `E-${seen.seq}`], { looked_for: ["alice"], supersedes: cov.seq }))).entry;
  ans = ok(await rec(a1, { kind: "answer", section: "question:2", value: "No evidence of a remote tool was found on the disk or the strings", reasoning: `E-${cov2.seq}`, ...A, result: "bounded_negative", supersedes: ans.seq })).entry;
  await SW.awaitSweeps(S);
  const sw2 = SW.sweepOf(cov2, await SW.readSweeps(S))!;
  assert.equal(sw2.state, "clean");
  assert.deepEqual(sw2.named_hits.map((h) => [h.ref, h.also]), [[`import:j000020/${file}`, [`job:j000020/${file}`, k.ref]]]);
  await attested(a2, { seq: cov2.seq, how: "read the strings", review: REVIEW, second_review_why: "the revised record names what the sweep found" });
  const r = await checkLedgerAnswers(S, ["2"], ["2"]);
  assert.deepEqual(codes(r, "question:2"), [], r.lines.join("\n"));
  // A sweep recorded before the kept file was known by its content named it alone: read again, the record's import names it.
  const before: SW.SweepRecord = { ...sw2, hits: [{ ref: k.ref, term: "alice", count: 1, first_offset: 6, encodings: ["utf-8"] }], named_hits: [], echoes: undefined, state: "hits" };
  delete (before as Partial<SW.SweepRecord>).echoes;
  const again = await SW.resplitSweep(S, cov2, before);
  assert.deepEqual([again.state, again.hits.length, again.named_hits.map((h) => h.ref)], ["clean", 0, [k.ref]]);
  assert.deepEqual(again.named_hits[0]!.also?.sort(), [`import:j000020/${file}`, `job:j000020/${file}`].sort());
});

test("the run paths a maker's words name, and the harness's own events that keep a seat's words", () => {
  const top = new Set(["inputs", "store", "work", "ledger", "tool-output", "SWARM.md", "traces"]);
  const root = "/runs/s1";
  const at = (w: string) => SW.runPathsIn(w, top, [root]).paths;
  assert.deepEqual(at("grep -i alice inputs/logs/b.log ./ledger/entries.jsonl"), ["inputs/logs/b.log", "ledger/entries.jsonl"]);
  assert.deepEqual(at(`python3 -c "open('${root}/store/jobs/j1/out/x.csv')"`), ["store/jobs/j1/out/x.csv"], "the run's absolute path is the run");
  assert.deepEqual(at("cat $PWD/SWARM.md"), ["SWARM.md"]);
  assert.deepEqual(at("for f in a b; do echo $f; done"), [], "a word the layout shares, unquoted and bare, is a word");
  assert.deepEqual(at("os.walk('inputs')"), ["inputs/"], "a directory's name quoted whole is the directory");
  assert.deepEqual(at("grep -r alice ."), ["."], "the root: read as unnamed evidence");
  assert.deepEqual(at("cat /tmp/x 2>/dev/null"), ["/tmp/x"], "a path elsewhere; the standard streams aside");
  assert.deepEqual(at("curl https://example.org/x"), ["https://example.org/x"]);
  assert.deepEqual(at("cat $OUT/x ../other/y"), ["$OUT/x", "../other/y"]);
  assert.equal(SW.runPathsIn("grep -i alice inputs/users/alice/ntuser.dat", top).text.includes("alice/ntuser"), false, "the paths are blanked for the string's own test");
  assert.match(SW.runPathsIn("grep -i alice inputs/users/alice/ntuser.dat", top).text, /grep -i alice/);
  // The self-compaction's events are the harness's keepers of a seat's own words, all of them and nothing else.
  assert.deepEqual([...SW.HARNESS_KEEPERS].sort(), [...SELF_COMPACT_EVENTS].sort());
  for (const e of SW.HARNESS_KEEPERS) assert.ok(P.TOOL_RESERVED_NAMES.has(e), `${e} is a reserved name: no seat's tool can take it`);
});

test("replay --resweep reads a recorded sweep again: the hit an older harness held on a kept output whose sealed import the record names moves to the named hits, on a synthetic line in the copy, the run untouched; without it, the checkout's answers check reads the line again, recorded under older rules", async () => {
  const { S, a0, a1, a2 } = await run();
  const file = "20260930083000000-bash-mmmm.out.log";
  const body = "a.log: alice again, from ws-12\n";
  const k = await kept(S, "a1", file, body, { tool: "bash", args: { command: "strings -a inputs/logs/a.log" } });
  for (const [dir, spec] of [[storePaths(S).jobs, true], [storePaths(S).imports, false]] as const) {
    const staging = join(S, "..", `staging-${Math.random().toString(16).slice(2)}`);
    await mkdir(staging, { recursive: true });
    await writeFile(join(staging, file), body);
    await sealTree(S, staging, join(dir, "j000021", "out"), "j000021", 1);
    if (spec) await writeFile(join(dir, "j000021", "job.json"), JSON.stringify({ id: "j000021", state: "committed", status: "ok", requester: { agent: "a1" }, spec: { kind: "import", scope: "declared", inputs: [`tool-output/a1/${file}`], seal: { ref: k.ref } } }));
  }
  await planned(a0, "2");
  const abs = ok(await rec(a0, { kind: "absence", value: "a remote tool", source: "the disk", evidence: "a search", refs: ["job:j000001/hits.txt"], answers: ["2"] })).entry;
  const seen = ok(await rec(a0, { kind: "finding", ...F, value: "the alice in the strings is another host's user", source: "the strings", evidence: "line 1", refs: [`import:j000021/${file}`], answers: ["2"] })).entry;
  const cov = ok(await rec(a0, coverage("2", ["input:disk.E01", `import:j000021/${file}`], [`E-${abs.seq}`, "job:j000001/hits.txt", `E-${seen.seq}`], { looked_for: ["alice"] }))).entry;
  ok(await rec(a1, { kind: "answer", section: "question:2", value: "No evidence of a remote tool was found on the disk or the strings", reasoning: `E-${cov.seq}`, ...A, result: "bounded_negative" }));
  await SW.awaitSweeps(S);
  // The line an older harness recorded: the kept file known by its inode, a hit of its own, and no rules version.
  const now = SW.sweepOf(cov, await SW.readSweeps(S))!;
  const { prev: _p, hash: _h, echoes: _e, rules: _r, ...core } = now;
  const old: Record<string, unknown> & { hash?: string } = { ...core, state: "hits", hits: [{ ref: k.ref, term: "alice", count: 1, first_offset: 6, encodings: ["utf-8"] }], named_hits: now.named_hits.filter((h) => !h.also?.includes(k.ref)).map((h) => ({ ...h, also: h.also?.filter((n) => n !== k.ref) })), prev: "genesis" };
  old.hash = SW.sweepHash(old as unknown as SW.SweepRecord, "genesis");
  await writeFile(join(S, SW.LEDGER_SWEEPS), `${JSON.stringify(old)}\n`);
  await attested(a2, { seq: cov.seq, how: "read the strings", review: REVIEW });
  assert.deepEqual(codes(await checkLedgerAnswers(S, ["2"], ["2"]), "question:2"), ["sweep_hits"], "held as the older harness held it");
  const before = await readFile(join(S, SW.LEDGER_SWEEPS), "utf8");
  const replay = (args: string[]) => JSON.parse(spawnSync(process.execPath, ["--experimental-strip-types", "--no-warnings", join(import.meta.dirname, "..", "scripts", "replay.ts"), S, "--json", ...args], { encoding: "utf8", maxBuffer: 1 << 26 }).stdout) as Replay;
  const q2 = (r: Replay) => r.evaluations[0]!.projection!.questions.find((q) => q.section === "question:2")!;
  // The checkout's answers check reads the line, recorded under no rules version, again under its own (store-sweep.ts rereadSweeps), in the copy.
  const as = replay([]);
  assert.deepEqual(q2(as).check?.defects, [], "read again by the answers check: the record names the import");
  assert.deepEqual(as.evaluations[0]!.projection!.store_sweeps, { records: 1, swept: 1, resplit: 0, reread: 1, hits: 0, named: now.named_hits.length, echoes: 0, with_hits: 0 });
  const again = replay(["--resweep"]);
  assert.deepEqual(again.resplit, { records: 1, moved: 1, to_named: 1, to_echoes: 0, hits_before: 1, hits_after: 0 });
  assert.deepEqual(q2(again).check?.defects, [], "the record names the import: the kept file is the same object");
  assert.equal(again.evaluations[0]!.projection!.store_sweeps?.resplit, 1);
  assert.equal(again.evaluations[0]!.projection!.store_sweeps?.reread, 0, "the synthetic line is under this checkout's rules: the answers check leaves it alone");
  assert.equal(again.unchanged, true);
  assert.equal(await readFile(join(S, SW.LEDGER_SWEEPS), "utf8"), before, "the run's own sweeps are untouched");
});
