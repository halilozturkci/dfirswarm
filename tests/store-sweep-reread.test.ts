/**
 * A store sweep read again after the sweep's rules changed (docs/adr/0013,
 * "Re-reading after a rules change"): each line names the rules version it
 * was written under, and a record whose latest line is older (or names
 * none) is read again under the current rules when the hub starts, at the
 * answers check and at the finish gate: a line of its own on the chain
 * (`reread`), a trace line and one board post. A line under the current
 * rules is left alone; the chain verifies, and an earlier seal holds as a
 * prefix; a replay of a run stopped on the older harness shows its holds
 * clearing under the step. The run sd0e59d, when its directory is given
 * (SWARM_SD0E59D), is replayed as of its resume. Synthetic runs otherwise.
 */
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import { existsSync } from "node:fs";
import { appendFile, cp, lstat, mkdir, mkdtemp, readdir, readFile, rm, writeFile } from "node:fs/promises";
import { createServer, type Server } from "node:net";
import { tmpdir } from "node:os";
import { basename, join } from "node:path";
import { after, test } from "node:test";
import * as P from "../extensions/protocol.ts";
import * as SW from "../extensions/store-sweep.ts";
import { checkLedgerAnswers } from "../scripts/check-answers.ts";
import { CHAINED_REGISTERS } from "../scripts/chained-registers.ts";
import { sealPrefix, takeCustody } from "../scripts/custody.ts";
import { sealTree, storePaths } from "../scripts/evidence-store.ts";
import type { Replay } from "../scripts/replay.ts";
import { LEFT_OUT } from "../scripts/replay.ts";
import { Hub } from "../scripts/vm-hub.ts";
import { A, coverage, dirs, F, ok, planned, rec, REVIEW, run } from "./negative-bar-fixture.ts";

const HERE = import.meta.dirname;
const sha = (s: string | Buffer) => createHash("sha256").update(s).digest("hex");
const cleanups: Array<() => Promise<unknown>> = [];
after(async () => {
  for (const c of cleanups.reverse()) await c().catch(() => undefined);
});

/** Poll until the condition holds. */
async function until(cond: () => boolean | Promise<boolean>, what: string, ms = 10_000): Promise<void> {
  const end = Date.now() + ms;
  while (!(await cond())) {
    if (Date.now() > end) throw new Error(`timed out waiting: ${what}`);
    await new Promise((r) => setTimeout(r, 20));
  }
}

/** Lines appended to the run's trace as the collector writes them, each chained to the one before by its sha256. Returns each line's sha256. */
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

/** A whole output the harness kept under tool-output/<seat>/, the trace line that kept it, and a line after it (which puts it on the chain). */
async function kept(S: string, seat: string, file: string, body: string, line: { tool: string; args: Record<string, unknown> }): Promise<string> {
  const rel = `tool-output/${seat}/${file}`;
  await mkdir(join(S, "tool-output", seat), { recursive: true });
  await writeFile(join(S, rel), body);
  await traceLines(S, [
    { agent: seat, tool: line.tool, args: line.args, result: { ok: true, output: "(prefix)", full_output: { path: rel, bytes: Buffer.byteLength(body), lines: body.split("\n").length - 1, sha256: sha(body) } } },
    { agent: seat, tool: "ls", args: {}, result: { ok: true } },
  ]);
  return `tool:${seat}/${file}`;
}

/** A kept output sealed as an import (the import job's output and the import it published), as a record citing it seals it. */
async function sealed(S: string, seat: string, id: string, file: string, body: string, command: string): Promise<{ tool: string; imp: string; job: string }> {
  const tool = await kept(S, seat, file, body, { tool: "bash", args: { command } });
  for (const [dir, spec] of [[storePaths(S).jobs, true], [storePaths(S).imports, false]] as const) {
    const staging = join(S, "..", `staging-${id}-${Math.random().toString(16).slice(2)}`);
    await mkdir(staging, { recursive: true });
    await writeFile(join(staging, file), body);
    await sealTree(S, staging, join(dir, id, "out"), id, 1);
    if (spec) await writeFile(join(dir, id, "job.json"), JSON.stringify({ id, state: "committed", status: "ok", requester: { agent: seat }, spec: { kind: "import", scope: "declared", inputs: [`tool-output/${seat}/${file}`], seal: { ref: tool } } }));
  }
  return { tool, imp: `import:${id}/${file}`, job: `job:${id}/${file}` };
}

/** A hit as an older harness recorded it: an object's own name, no makers. */
function oldHit(h: SW.SweepHit, ref: string, also?: string[]): SW.SweepHit {
  return { ref, term: h.term, count: h.count, first_offset: h.first_offset, encodings: h.encodings, ...(also?.length ? { also } : {}) };
}

/**
 * The run sd0e59d's shape, stopped on the harness before the rules version
 * (synthetic): three questions whose standing negatives rest on coverage
 * records whose recorded sweeps hold them (sweep_hits). Question 2's
 * revised record names the import a kept output was sealed as, and its
 * earlier record's sweep found the kept file; question 5's hit is a seat's
 * dump of the ledger; question 6's the self-compaction's summary. Every
 * sweep line is as the older harness wrote it: a kept file known by its
 * inode alone, no echoes, no rules version.
 */
async function olderRun() {
  const r = await run();
  const { S, a0, a1, a2 } = r;
  const file = "20260930090000000-bash-aaaa.out.log";
  const k = await sealed(S, "a1", "j000030", file, "a.log: alice logged on at 09:58 from ws-11\n", "strings -a inputs/logs/a.log");
  const dump = await kept(S, "a1", "20260930090100000-bash-bbbb.out.log", "12 bob was looked for\n13 none found\n", { tool: "bash", args: { command: "python3 - <<'PY'\nfor l in open('ledger/entries.jsonl'):\n    print(l)\nPY" } });
  const summary = await kept(S, "a2", "20260930090200000-compact_summary-cccc.text.log", "## Where I am\nsearching the disk for carol; nothing yet\n", { tool: "compact_failed", args: { stage: "summary", attempt: 1 } });
  for (const q of ["2", "5", "6"]) await planned(a0, q);
  const abs = ok(await rec(a0, { kind: "absence", value: "a remote tool", source: "the disk", evidence: "a search", refs: ["job:j000001/hits.txt"], answers: ["2", "5", "6"] })).entry;
  // Question 2: a record that did not name the kept output, then one revised to name its sealed import, with what it showed.
  const cov1 = ok(await rec(a0, coverage("2", ["input:disk.E01"], [`E-${abs.seq}`, "job:j000001/hits.txt"], { looked_for: ["alice"] }))).entry;
  await SW.awaitSweeps(S);
  const seen = ok(await rec(a0, { kind: "finding", ...F, value: "the alice in the strings is another host's user", source: "the strings", evidence: "line 1", refs: [k.imp], answers: ["2"] })).entry;
  const cov2 = ok(await rec(a0, coverage("2", ["input:disk.E01", k.imp], [`E-${abs.seq}`, "job:j000001/hits.txt", `E-${seen.seq}`], { looked_for: ["alice"], supersedes: cov1.seq }))).entry;
  const cov5 = ok(await rec(a0, coverage("5", ["input:disk.E01"], [`E-${abs.seq}`, "job:j000001/hits.txt"], { looked_for: ["bob"] }))).entry;
  const cov6 = ok(await rec(a0, coverage("6", ["input:disk.E01"], [`E-${abs.seq}`, "job:j000001/hits.txt"], { looked_for: ["carol"] }))).entry;
  await SW.awaitSweeps(S);
  const answers: Record<string, P.LedgerEntry> = {};
  for (const [q, c] of [["2", cov2], ["5", cov5], ["6", cov6]] as const) {
    answers[q] = ok(await rec(a1, { kind: "answer", section: `question:${q}`, value: `No evidence for question ${q} was found on the disk`, reasoning: `E-${c.seq}`, ...A, result: "bounded_negative" })).entry;
    const r2 = await P.attestEntry(a2, { seq: c.seq, how: "ran the search again", review: REVIEW, ...(c.seq === cov2.seq ? { second_review_why: "the revised record names what the sweep found" } : {}) });
    assert.ok(r2.ok, JSON.stringify(r2));
  }
  // The lines as this harness recorded them, then as the older one would have.
  const now = await SW.readSweeps(S);
  const of = (c: P.LedgerEntry) => SW.sweepOf(c, now)!;
  const find = (line: SW.SweepRecord, ref: string) => [...line.hits, ...line.named_hits, ...(line.echoes ?? [])].find((h) => [h.ref, ...(h.also ?? [])].includes(ref))!;
  const older = (line: SW.SweepRecord, o: { hits: SW.SweepHit[]; named?: SW.SweepHit[] }): SW.SweepRecord => {
    const { prev: _p, hash: _h, rules: _r, echoes: _e, ...core } = line;
    return { ...core, state: o.hits.length ? "hits" : "clean", hits: o.hits, named_hits: o.named ?? [] };
  };
  const lines: SW.SweepRecord[] = [
    older(of(cov1), { hits: [oldHit(find(of(cov1), k.imp), k.imp, [k.job]), oldHit(find(of(cov1), k.tool), k.tool)] }),
    older(of(cov2), { hits: [oldHit(find(of(cov2), k.tool), k.tool)], named: [oldHit(find(of(cov2), k.imp), k.imp, [k.job])] }),
    older(of(cov5), { hits: [oldHit(find(of(cov5), dump), dump)] }),
    older(of(cov6), { hits: [oldHit(find(of(cov6), summary), summary)] }),
  ];
  let prev = "genesis";
  let text = "";
  for (const l of lines) {
    l.prev = prev;
    l.hash = SW.sweepHash(l, prev);
    prev = l.hash;
    text += `${JSON.stringify(l)}\n`;
  }
  await writeFile(join(S, SW.LEDGER_SWEEPS), text);
  await P.renderLedger(S);
  return { ...r, k, dump, summary, cov1, cov2, cov5, cov6, answers, lines };
}

/** The sweep holds' codes the answers check names on a question. */
const codes = (r: Awaited<ReturnType<typeof checkLedgerAnswers>>, section: string) => r.defects.filter((d) => d.section === section).map((d) => d.code);
const posts = async (S: string) => Promise.all((await readdir(join(S, "threads", "main")).catch(() => [] as string[])).filter((n) => n.endsWith("-system.md")).map((n) => readFile(join(S, "threads", "main", n), "utf8")));
const rereadPosts = async (S: string) => (await posts(S)).filter((p) => /STORE SWEEPS READ AGAIN/.test(p));

/** A hub over the run, as a kickoff or a resume starts one, with a stand-in collector; its lines, and what stops it. */
async function hubOver(S: string): Promise<{ hub: Hub; lines: Array<Record<string, unknown>>; stop: () => Promise<void> }> {
  const dir = await mkdtemp(join(tmpdir(), "dfr-"));
  const lines: Array<Record<string, unknown>> = [];
  const socket = join(dir, "col.sock");
  const collector: Server = createServer((s) => {
    let buffer = "";
    s.setEncoding("utf8");
    s.on("data", (chunk: string) => {
      buffer += chunk;
      let cut;
      while ((cut = buffer.indexOf("\n")) >= 0) {
        lines.push(JSON.parse(buffer.slice(0, cut)));
        buffer = buffer.slice(cut + 1);
        s.write('{"ok":true}\n');
      }
    });
    s.on("error", () => undefined);
  });
  await new Promise<void>((r) => collector.listen(socket, () => r()));
  const agents = ["a0", "a1", "a2", "a3"];
  const hub = new Hub({ sandbox: S, dir, agents, tokens: Object.fromEntries([...agents.map((a) => [a, `token-${a}`]), ["system", "token-system"]]), collector: socket, backstop: false, quiet: true, settleMs: 0, herdrBin: "/usr/bin/false" });
  await hub.start();
  let stopped = false;
  const stop = async () => {
    if (stopped) return;
    stopped = true;
    await hub.stop().catch(() => undefined);
    collector.close();
    await rm(dir, { recursive: true, force: true });
  };
  cleanups.push(stop);
  return { hub, lines, stop };
}

test("a sweep line recorded under an older version of the sweep's rules is read again when the hub starts: the hold on a kept output whose sealed import the record names clears, and so do those on echoes; the trace gets a line and the board one post; a second start reads nothing", async () => {
  const o = await olderRun();
  const { S } = o;
  const held = await checkLedgerAnswers(S, ["2", "5", "6"], ["2"]);
  for (const q of ["2", "5", "6"]) assert.ok(codes(held, `question:${q}`).includes("sweep_hits"), `question ${q} is held as the older harness held it: ${held.lines.join("\n")}`);
  const before = await readFile(join(S, SW.LEDGER_SWEEPS), "utf8");

  const h = await hubOver(S);
  await until(async () => (await rereadPosts(S)).length > 0 && h.lines.some((l) => l.tool === "sweep_reread"), "the hub's reread");
  await SW.awaitSweeps(S);
  const all = (await readFile(join(S, SW.LEDGER_SWEEPS), "utf8")).split("\n").filter(Boolean).map((l) => JSON.parse(l) as SW.SweepRecord);
  assert.equal(all.length, 8, "one line for each record read again");
  assert.ok((await readFile(join(S, SW.LEDGER_SWEEPS), "utf8")).startsWith(before), "appended: the older lines stand as they were");
  const again = all.slice(4);
  assert.deepEqual(
    again.map((l) => [l.seq, l.rules, l.reread]),
    o.lines.map((l) => [l.seq, SW.SWEEP_RULES, { from_version: null, reason: "rules changed", of: l.hash, at: again.find((x) => x.seq === l.seq)!.reread!.at, how: "read" }]),
  );
  assert.deepEqual(again.map((l) => [l.started_at, l.at]), o.lines.map((l) => [l.started_at, l.at]), "a re-read keeps its search's times: nothing was searched again");
  const by = (c: P.LedgerEntry) => again.find((l) => l.seq === c.seq)!;
  // Question 2: the kept file is the import the revised record names; the earlier record's hit is on it too, and what it showed is among the revised record's results.
  assert.deepEqual([by(o.cov2).state, by(o.cov2).hits], ["clean", []]);
  assert.deepEqual(by(o.cov2).named_hits.map((h) => [h.ref, [...(h.also ?? [])].sort()]), [[o.k.imp, [o.k.job]], [o.k.tool, [o.k.imp, o.k.job].sort()]]);
  assert.deepEqual(by(o.cov1).hits.map((h) => h.ref).sort(), [o.k.imp, o.k.tool].sort(), "the earlier record does not name the import: its hits stay, each now with every name of its bytes");
  // Questions 5 and 6: echoes.
  assert.deepEqual([by(o.cov5).state, by(o.cov5).echoes!.map((h) => [h.ref, h.origins!.map((x) => x.why)])], ["clean", [[o.dump, ["registers"]]]]);
  assert.deepEqual([by(o.cov6).state, by(o.cov6).echoes!.map((h) => [h.ref, h.origins!.map((x) => x.why)])], ["clean", [[o.summary, ["harness"]]]]);
  assert.match(SW.sweepWords(by(o.cov5), o.cov5), /read again at .* under the sweep's rules version \d+, from a line that recorded no rules version \(the rules changed\): its hits sorted anew from what the earlier line recorded, nothing searched again/);
  // The sweep's own render of ledger.md can be overtaken by one that began before its line was written (two renders write the same file, the later write
  // wins); render once more from what is on disk, which is what this reads.
  await P.renderLedger(S);
  assert.match(await readFile(join(S, P.LEDGER_MD), "utf8"), /read again at .* under the sweep's rules version/);

  const cleared = await checkLedgerAnswers(S, ["2", "5", "6"], ["2"]);
  for (const q of ["2", "5", "6"]) assert.ok(!codes(cleared, `question:${q}`).includes("sweep_hits"), `question ${q} clears: ${cleared.lines.join("\n")}`);
  // The trace's line: the hub's own, with each line written and the holds that changed.
  const line = h.lines.find((l) => l.tool === "sweep_reread")!;
  assert.equal(line.agent, "system");
  assert.equal(line.token, "token-system", "the hub's own line, as the harness");
  const result = line.result as { records: number; read: number; searched: number; lines: Array<{ seq: number; from_version: number | null; how: string; of: string; hash: string }>; holds_cleared: SW.SweepHoldKey[]; holds_added: SW.SweepHoldKey[] };
  assert.deepEqual([result.records, result.read, result.searched], [4, 4, 0]);
  assert.deepEqual(result.lines.map((x) => [x.seq, x.from_version, x.how, x.of, x.hash]), again.map((l) => [l.seq, null, "read", l.reread!.of, l.hash]));
  const want = [
    { section: "question:2", answer: o.answers["2"]!.seq, code: "sweep_hits", coverage: o.cov2.seq },
    { section: "question:5", answer: o.answers["5"]!.seq, code: "sweep_hits", coverage: o.cov5.seq },
    { section: "question:6", answer: o.answers["6"]!.seq, code: "sweep_hits", coverage: o.cov6.seq },
  ];
  assert.deepEqual(result.holds_cleared, want);
  assert.deepEqual(result.holds_added, []);
  // One post: how many records were read again, and which holds changed.
  const said = await rereadPosts(S);
  assert.equal(said.length, 1);
  assert.match(said[0]!, new RegExp(`the sweep's rules changed since 4 coverage records \\(E-${o.cov1.seq}, E-${o.cov2.seq}, E-${o.cov5.seq}, E-${o.cov6.seq}\\) had their sweep recorded \\(version 1, 2026-09-30: the same bytes under several names are one object`));
  assert.match(said[0]!, /Each was read again under this harness's rules \(version \d+\)/);
  assert.match(said[0]!, /In 3 records what the sweep found moved: 5 hit\(s\) became 2, named hits 1 became 2, echoes 0 became 2\./);
  assert.match(said[0]!, /4 from what their lines recorded, nothing searched again/);
  assert.match(said[0]!, new RegExp(`question:2 \\(answer E-${o.answers["2"]!.seq}\\): sweep_hits on E-${o.cov2.seq} cleared; question:5 .*sweep_hits on E-${o.cov5.seq} cleared; question:6 .*sweep_hits on E-${o.cov6.seq} cleared`));
  await h.stop();

  // A resume on the same harness: every record's latest line is under its rules, and nothing is read again.
  const after1 = await readFile(join(S, SW.LEDGER_SWEEPS), "utf8");
  const h2 = await hubOver(S);
  await new Promise((r) => setTimeout(r, 300));
  await SW.awaitSweeps(S);
  assert.equal(await readFile(join(S, SW.LEDGER_SWEEPS), "utf8"), after1);
  assert.equal(h2.lines.filter((l) => l.tool === "sweep_reread").length, 0);
  assert.equal((await rereadPosts(S)).length, 1);
  await h2.stop();
});

test("a line already under the current rules is left alone, holding or not: the hub's start and the answers check write no line, no trace line and no post", async () => {
  const { S, a0, a1, a2 } = await run();
  await kept(S, "a1", "20260930091000000-bash-dddd.out.log", "b.log:alice logged on at 09:58\n", { tool: "bash", args: { command: "grep -i alice inputs/logs/b.log" } });
  await planned(a0, "2");
  const abs = ok(await rec(a0, { kind: "absence", value: "a remote tool", source: "the disk", evidence: "a search", refs: ["job:j000001/hits.txt"], answers: ["2"] })).entry;
  const cov = ok(await rec(a0, coverage("2", ["input:disk.E01"], [`E-${abs.seq}`, "job:j000001/hits.txt"], { looked_for: ["alice"] }))).entry;
  ok(await rec(a1, { kind: "answer", section: "question:2", value: "No evidence of a remote tool was found on the disk", reasoning: `E-${cov.seq}`, ...A, result: "bounded_negative" }));
  await SW.awaitSweeps(S);
  const line = SW.sweepOf(cov, await SW.readSweeps(S))!;
  assert.equal(line.rules, SW.SWEEP_RULES, "a sweep names the rules it was written under");
  assert.equal(line.reread, undefined);
  assert.equal(line.state, "hits", "a search of evidence the record does not name: it holds");
  const r2 = await P.attestEntry(a2, { seq: cov.seq, how: "ran the search again", review: REVIEW });
  assert.ok(r2.ok);
  const before = await readFile(join(S, SW.LEDGER_SWEEPS), "utf8");
  assert.deepEqual(await SW.rereadSweeps(S), { rules: SW.SWEEP_RULES, records: [], cleared: [], added: [] });
  assert.equal(await SW.reconcileSweeps(S), 0);
  const h = await hubOver(S);
  await new Promise((r) => setTimeout(r, 300));
  await SW.awaitSweeps(S);
  assert.equal(await readFile(join(S, SW.LEDGER_SWEEPS), "utf8"), before);
  assert.equal(h.lines.filter((l) => l.tool === "sweep_reread").length, 0);
  assert.deepEqual(await rereadPosts(S), []);
  assert.deepEqual(codes(await checkLedgerAnswers(S, ["2"], ["2"]), "question:2"), ["sweep_hits"], "it holds as it did");
  await h.stop();
});

test("with no hub, the answers check reads the older lines again as a step of its own, once: the chain verifies and an earlier custody seal holds as a prefix", async () => {
  const o = await olderRun();
  const { S } = o;
  // What custody sealed before the run was resumed on this harness.
  const custody = await takeCustody(S, { readOnly: true, timeoutSec: 120 });
  assert.deepEqual(custody.seal.sweeps, { lines: 4, head: o.lines.at(-1)!.hash });
  const cli = (): { status: number | null; out: string; err: string } => {
    const r = spawnSync(process.execPath, ["--experimental-strip-types", "--no-warnings", join(HERE, "..", "scripts", "check-answers.ts"), "--sandbox", S, "--sections", "2,5,6", "--existence", "2"], { encoding: "utf8", env: Object.fromEntries(Object.entries(process.env).filter(([k]) => !k.startsWith("SWARM_"))) });
    return { status: r.status, out: r.stdout, err: r.stderr };
  };
  const first = cli();
  assert.match(first.out, /CHECK_ANSWERS_JSON /, `the check ran to its end: ${first.err}`);
  const cleared = await checkLedgerAnswers(S, ["2", "5", "6"], ["2"]);
  for (const q of ["2", "5", "6"]) assert.ok(!codes(cleared, `question:${q}`).includes("sweep_hits"), `question ${q} clears: ${first.err}`);
  const text = await readFile(join(S, SW.LEDGER_SWEEPS), "utf8");
  const v = SW.verifySweepChain(text);
  assert.deepEqual([v.ok, v.total], [true, 8]);
  assert.deepEqual(text.split("\n").filter(Boolean).slice(4).map((l) => (JSON.parse(l) as SW.SweepRecord).reread?.of), o.lines.map((l) => l.hash), "each names the line it read again");
  // The trace line of a process with no collector to reach goes to the harness's spill, as trace_emit writes one.
  const spill = (await readFile(join(S, P.SYSTEM_SPILL_REL), "utf8")).split("\n").filter(Boolean).map((l) => JSON.parse(l) as { agent: string; tool: string; result: { records: number; holds_cleared: unknown[] } });
  assert.deepEqual(spill.filter((l) => l.tool === "sweep_reread").map((l) => [l.agent, l.result.records, l.result.holds_cleared.length]), [["system", 4, 3]]);
  assert.equal((await rereadPosts(S)).length, 1);
  // The seal taken before holds the run now as a prefix: what the re-read wrote is appended.
  const read = async (rel: string) => readFile(join(S, rel), "utf8").catch(() => "");
  const now = { trace: await read("traces/events.jsonl"), ledger: await read("ledger/entries.jsonl"), attestations: await read("ledger/attestations.jsonl"), disputes: await read("ledger/disputes.jsonl"), leads: await read("leads/leads.jsonl"), questions: await read("questions/questions.jsonl"), grants: await read("network/grants.jsonl"), fetches: await read("network/fetches.jsonl"), sweeps: text, journal: existsSync(join(S, "store", "journal.jsonl")) ? await read("store/journal.jsonl") : null, gateway: null };
  const held = sealPrefix(custody.seal, now);
  assert.equal(held.ok, true, held.broken.join("; "));
  assert.ok(held.held.includes("the store sweeps (4)"), held.held.join("; "));
  // Once: the second check reads nothing again.
  const second = cli();
  assert.match(second.out, /CHECK_ANSWERS_JSON /, second.err);
  assert.equal(await readFile(join(S, SW.LEDGER_SWEEPS), "utf8"), text);
  assert.equal((await rereadPosts(S)).length, 1);
});

test("where a change of the rules needs bytes a line did not record, its record is searched again, within the sweep's budget", async () => {
  const o = await olderRun();
  const { S } = o;
  const changes: SW.SweepRuleChange[] = [...SW.SWEEP_RULE_CHANGES, { version: SW.SWEEP_RULES + 1, since: "2026-10-01", what: "a test change the recorded hits cannot answer", bytes: true }];
  const at = Date.parse("2026-10-01T10:00:00.000Z");
  const r = await SW.rereadSweeps(S, { changes, maxBytes: 1, now: () => at });
  assert.deepEqual(r.records.map((x) => [x.seq, x.from_version, x.how]), o.lines.map((l) => [l.seq, null, "searched"]));
  const again = (await SW.readSweeps(S)).slice(4);
  assert.ok(again.every((l) => l.rules === SW.SWEEP_RULES + 1 && l.reread?.how === "searched" && l.at === "2026-10-01T10:00:00.000Z"), "a new search: its own times");
  assert.ok(again.every((l) => l.state === "partial" && l.unsearched.length > 0 && /SWARM_SWEEP_MAX_BYTES/.test(l.unsearched[0]!.why)), "the sweep's budget bounds it: what it did not reach is named");
  assert.match(SW.rereadPostWords(r, changes), /4 searched again, the change needing bytes their lines did not record/);
  // Once: the next pass under the same rules reads nothing, and a harness whose rules are older than a line's leaves it alone too.
  assert.deepEqual((await SW.rereadSweeps(S, { changes })).records, []);
  assert.deepEqual((await SW.rereadSweeps(S)).records, [], "a line under a later version than this harness's is not older");
});

test("a replay of a run stopped on the older harness, as of before its seats record again: the three sweep_hits holds clear under the answers check's re-read, in the copy; the run untouched", async () => {
  const o = await olderRun();
  const { S } = o;
  const before = await readFile(join(S, SW.LEDGER_SWEEPS), "utf8");
  const out = spawnSync(process.execPath, ["--experimental-strip-types", "--no-warnings", join(HERE, "..", "scripts", "replay.ts"), S, "--json"], { encoding: "utf8", maxBuffer: 1 << 26 });
  const replay = JSON.parse(out.stdout) as Replay;
  const p = replay.evaluations[0]!.projection!;
  assert.deepEqual(p.errors, []);
  for (const q of ["2", "5", "6"]) assert.ok(!p.questions.find((x) => x.section === `question:${q}`)!.check!.defects.includes("sweep_hits"), `question ${q}`);
  assert.deepEqual(p.store_sweeps, { records: 4, swept: 4, resplit: 0, reread: 4, hits: 2, named: 2, echoes: 2, with_hits: 1 });
  assert.equal(replay.unchanged, true);
  assert.equal(await readFile(join(S, SW.LEDGER_SWEEPS), "utf8"), before, "the run's own sweeps are untouched");
  assert.deepEqual(codes(await checkLedgerAnswers(S, ["2"], ["2"]), "question:2").filter((c) => c === "sweep_hits"), ["sweep_hits"], "and the run itself still holds until a hub or its answers check reads it again");
});

/**
 * A copy of a run, cut as of a moment: every chained register a prefix of
 * the lines written until then (a line's `reread.at`, `at` or `ts`), the
 * rest of the run as it is, less what replay leaves out. Read only.
 */
async function cutRun(src: string, until: number, dest: string): Promise<void> {
  await cp(src, dest, {
    recursive: true,
    filter: async (p) => {
      const rel = p.slice(src.length + 1);
      if (rel && Object.hasOwn(LEFT_OUT, rel.split("/")[0]!)) return false;
      const st = await lstat(p).catch(() => null);
      return Boolean(st && (st.isFile() || st.isDirectory()));
    },
  });
  for (const r of CHAINED_REGISTERS) {
    const file = join(dest, r.rel);
    if (!existsSync(file)) continue;
    const keep: string[] = [];
    for (const line of (await readFile(file, "utf8")).split("\n").filter((l) => l.trim())) {
      let row: Record<string, unknown>;
      try {
        row = JSON.parse(line) as Record<string, unknown>;
      } catch {
        break;
      }
      const reread = row.reread as { at?: unknown } | undefined;
      const t = Date.parse(String(reread?.at ?? row.at ?? row.ts ?? ""));
      if (t > until) break;
      keep.push(line);
    }
    await writeFile(file, keep.length ? `${keep.join("\n")}\n` : "");
  }
}

test("the run sd0e59d, replayed as of its resume on the older harness's lines (before its seats recorded again): its three sweep_hits holds, on E-111, E-118 and E-129, clear under the answers check's re-read", { skip: !process.env.SWARM_SD0E59D && "SWARM_SD0E59D names no copy of the run" }, async () => {
  const src = process.env.SWARM_SD0E59D!;
  const trace = await readFile(join(src, "traces", "events.jsonl"), "utf8");
  const resumed = trace.split("\n").find((l) => l.includes('"tool":"run_resumed"'));
  assert.ok(resumed, "the run was resumed");
  const at = Date.parse((JSON.parse(resumed!) as { ts: string }).ts);
  const base = await mkdtemp(join(tmpdir(), "sd0e59d-"));
  dirs.push(base);
  const S = join(base, basename(src));
  await cutRun(src, at, S);
  // As the older harness left it: every line of the sweeps without a rules version, and three holds.
  const lines = await SW.readSweeps(S);
  assert.ok(lines.every((l) => l.rules === undefined));
  const entries = await P.readLedger(S);
  const holds = (await SW.sweepHoldKeys(S, entries, lines)).filter((h) => h.code === "sweep_hits");
  assert.deepEqual([...new Set(holds.map((h) => h.coverage))].sort((a, b) => a - b), [111, 118, 129], "held on E-111, E-118 and E-129");
  const out = spawnSync(process.execPath, ["--experimental-strip-types", "--no-warnings", join(HERE, "..", "scripts", "replay.ts"), S, "--json"], { encoding: "utf8", maxBuffer: 1 << 28 });
  const replay = JSON.parse(out.stdout) as Replay;
  const p = replay.evaluations[0]!.projection!;
  for (const h of holds) assert.ok(!p.questions.find((x) => x.section === h.section)!.check!.defects.includes("sweep_hits"), `${h.section} (E-${h.coverage}) clears`);
  assert.equal(p.store_sweeps?.reread, p.store_sweeps?.swept, "every recorded sweep was read again under this harness's rules");
  assert.equal(replay.unchanged, true);
});
