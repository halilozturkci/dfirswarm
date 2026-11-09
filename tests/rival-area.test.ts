/**
 * A locator is not coverage (docs/adr/0013): an established attest of an
 * answer to a material question that locates a value in the sealed bytes
 * is recorded best_candidate (rival_area_uncovered) unless, for each input
 * the located object was read from, a standing coverage record for the
 * question names that input, says every area searched or not applicable,
 * and cites a job over it among its results. A located object that traces
 * to no input, and a partial answer, are not held. The metrics count the
 * caps and each area's not_applicable.
 */
import assert from "node:assert/strict";
import { mkdir, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { test } from "node:test";
import * as P from "../extensions/protocol.ts";
import { measureRun, metricsText } from "../scripts/metrics.ts";
import { sealTree, storePaths } from "../scripts/evidence-store.ts";
import { A, coverage, ESTABLISHED, F, ok, planned, rec, run, SOURCE_FIRST } from "./negative-bar-fixture.ts";

const HIGH = { ...A, confidence: "high" } as const;
const { discriminator: _d, derivation: _v, ...BARE } = ESTABLISHED.answer_review;
const ALL = { allocated: "searched", deleted: "searched", unallocated: "searched", slack: "searched", secondary: "not_applicable" } as const;

/** A job whose one output holds `bytes`, sealed, over `inputs` (declared), or over everything. */
async function sealed(S: string, id: string, file: string, bytes: Buffer, inputs: string[] | "all" = ["input:disk.E01"]): Promise<void> {
  const staging = join(S, "..", `staging-${id}`);
  await mkdir(staging, { recursive: true });
  await writeFile(join(staging, file), bytes);
  await sealTree(S, staging, join(storePaths(S).jobs, id, "out"), id, 1);
  const spec = inputs === "all" ? { kind: "command", scope: "all", command: "strings" } : { kind: "command", scope: "declared", inputs, command: "strings" };
  await writeFile(join(storePaths(S).jobs, id, "job.json"), JSON.stringify({ id, state: "committed", requester: { agent: "a0" }, status: "ok", exit: 0, spec }));
}

const attest = async (c: { sandboxRoot: string; agentId: string }, input: Record<string, unknown>) => {
  const r = await P.attestEntry(c, input as unknown as P.LedgerActInput);
  assert.ok(r.ok && (r as { line?: unknown }).line, JSON.stringify(r));
  return r as { ok: true; line: P.LedgerAttestation; note?: string };
};

/** Question `q` answered `result` on a finding over `ref`, by a1; and a review that locates `value` in `ref`. */
async function located(c: Awaited<ReturnType<typeof run>>, q: string, ref: string, value: string, body: Buffer, result = "established") {
  await planned(c.a0, q);
  const f = ok(await rec(c.a0, { kind: "finding", ...F, value: `${value} is in the notes`, source: "the notes", evidence: "its live text", refs: [ref], answers: [q] })).entry;
  const lim = result === "partial" ? ok(await rec(c.a0, { kind: "limitation", value: "The notes' earlier version is not read", source: "the notes", evidence: "time", reason: "not_examined", answers: [q] })).entry.seq : null;
  const a = ok(await rec(c.a1, { kind: "answer", section: `question:${q}`, value, reasoning: `E-${f.seq}`, ...HIGH, result, ...(lim ? { confidence: "medium", parts: [{ id: "who", part: "whom", status: "established", refs: [`E-${f.seq}`] }, { id: "when", part: "when", status: "open", open_by: `E-${lim}` }] } : {}) })).entry;
  const review = { ...BARE, discriminator: SOURCE_FIRST.discriminator, reproduced_at: [{ ref, offset: body.indexOf(value), value }], ...(lim ? { parts: [{ id: "who", part: "whom", established: true, why: "the notes" }, { id: "when", part: "when", established: false, why: "not read" }] } : {}) };
  return { a, review };
}

test("a located value whose disk no coverage record covers where a rival could live is recorded a best candidate, saying which input and what is missing, and how to fix it", async () => {
  const c = await run();
  const body = Buffer.from("notes: send the list to Joe Doe\n");
  await sealed(c.S, "j000020", "notes.txt", body);
  const { a, review } = await located(c, "1", "job:j000020/notes.txt", "Joe Doe", body);
  const first = await attest(c.a2, { seq: a.seq, how: "read the live notes", strength: "established", answer_review: review });
  assert.equal(first.line.strength, "best_candidate");
  assert.match(first.line.capped!.join("\n"), /^a locator is not coverage: the value was read from input:disk\.E01, and no standing coverage record for question:1 names it$/m);
  assert.match(first.note ?? "", /a located value proves the value is there, not that it is the answer: record kind=coverage for the question over the source the value was read from/);
  // A coverage record over the disk that skips slack: still a best candidate, and it says which area.
  const skipped = ok(await rec(c.a0, coverage("1", ["input:disk.E01"], ["job:j000020/notes.txt"], { areas: { ...ALL, slack: "skipped" }, skipped: "slack: not carved" }))).entry.seq;
  const second = await attest(c.a3, { seq: a.seq, how: "read the live notes", strength: "established", answer_review: review });
  assert.equal(second.line.strength, "best_candidate");
  assert.match(second.line.capped!.join("\n"), new RegExp(`its coverage record E-${skipped} does not say every area \\{allocated, deleted, unallocated, slack, secondary\\} searched or not applicable \\(slack skipped\\)`));
  // Every area searched, but its results cite no job over the disk: still held.
  await sealed(c.S, "j000021", "log-hits.txt", Buffer.from("nothing\n"), ["input:logs/a.log"]);
  const offDisk = ok(await rec(c.a0, coverage("1", ["input:disk.E01"], ["job:j000021/log-hits.txt"], { areas: ALL, supersedes: skipped }))).entry.seq;
  const third = await attest(c.a0, { seq: a.seq, how: "read the live notes again", strength: "established", answer_review: { ...review, inference: "the notes name the recipient, read again after the coverage" } });
  assert.match(third.line.capped!.join("\n"), new RegExp(`its coverage record E-${offDisk} cites no job over it among its result_refs`));
  // A search of the disk's other areas, cited: established.
  await sealed(c.S, "j000022", "slack.txt", Buffer.from("no other name\n"));
  ok(await rec(c.a0, coverage("1", ["input:disk.E01"], ["job:j000022/slack.txt"], { areas: ALL, supersedes: offDisk })));
  // A seat's later review counts when it now holds established what its earlier one held a best candidate.
  const fourth = await attest(c.a2, { seq: a.seq, how: "read the live notes, and the carve of the disk's slack", strength: "established", answer_review: { ...review, inference: "the notes name the recipient, and the disk's other areas name no other" } });
  assert.equal(fourth.line.strength, "established", fourth.note);
  assert.equal(fourth.line.capped, undefined);
  assert.deepEqual(await P.rivalAreasUncovered(c.S, a, ["job:j000020/notes.txt"], await P.readLedger(c.S)), []);
  // Counted: the caps, and each area's not_applicable.
  const m = await measureRun(c.S);
  assert.equal(m.review_caps?.rival_area_uncovered, 3);
  assert.equal(m.coverage.areas_not_applicable?.secondary, 1);
  assert.match(metricsText(m), /Rival areas:? +3 established attest\(s\) capped because a located value's input was not covered where a rival could live; not_applicable per area across standing coverage records: .*secondary 1/);
});

test("a located object that traces to no input is not held, a coverage record for another question covers nothing, and a partial answer is never capped for it", async () => {
  const c = await run();
  const body = Buffer.from("owner: Joe Doe\n");
  // A job that read everything traces to no one input: not held.
  await sealed(c.S, "j000030", "all.txt", body, "all");
  const one = await located(c, "1", "job:j000030/all.txt", "Joe Doe", body);
  const free = await attest(c.a2, { seq: one.a.seq, how: "read the output", strength: "established", answer_review: one.review });
  assert.equal(free.line.strength, "established", free.note);
  // Another question's coverage does not cover question 2's value.
  await sealed(c.S, "j000031", "notes.txt", body);
  ok(await rec(c.a0, coverage("1", ["input:disk.E01"], ["job:j000031/notes.txt"], { areas: ALL })));
  const two = await located(c, "2", "job:j000031/notes.txt", "Joe Doe", body);
  const held = await attest(c.a2, { seq: two.a.seq, how: "read the notes", strength: "established", answer_review: two.review });
  assert.match(held.line.capped!.join("\n"), /no standing coverage record for question:2 names it/);
  // A partial answer's review with a locator: checked, never capped for it.
  const three = await located(c, "3", "job:j000031/notes.txt", "Joe Doe", body, "partial");
  const part = await attest(c.a2, { seq: three.a.seq, how: "read the notes", strength: "established", answer_review: three.review });
  assert.equal(part.line.capped, undefined);
});

test("the rival-area check runs for every review: a locator, a derivation, both or neither gives the same answer the same verdict", async () => {
  const c = await run();
  const body = Buffer.from("notes: send the list to Joe Doe\n");
  await sealed(c.S, "j000040", "notes.txt", body);
  const ref = "job:j000040/notes.txt";
  const value = "Joe Doe";
  const variants: Array<[string, (b: typeof BARE) => Record<string, unknown>]> = [
    ["locator only", (b) => ({ ...b, discriminator: SOURCE_FIRST.discriminator, reproduced_at: [{ ref, offset: body.indexOf(value), value }] })],
    ["derivation only", (b) => ({ ...b, discriminator: SOURCE_FIRST.discriminator, derivation: SOURCE_FIRST.derivation })],
    ["locator and derivation", (b) => ({ ...b, discriminator: SOURCE_FIRST.discriminator, derivation: SOURCE_FIRST.derivation, reproduced_at: [{ ref, offset: body.indexOf(value), value }] })],
    ["neither", (b) => ({ ...b, discriminator: SOURCE_FIRST.discriminator })],
  ];
  const answers: number[] = [];
  for (const [i, [name, review]] of variants.entries()) {
    const q = String(i + 1);
    await planned(c.a0, q);
    const f = ok(await rec(c.a0, { kind: "finding", ...F, value: `${value} is in the notes`, source: "the notes", evidence: "its live text", refs: [ref], answers: [q] })).entry;
    const a = ok(await rec(c.a1, { kind: "answer", section: `question:${q}`, value, reasoning: `E-${f.seq}`, ...HIGH, result: "established" })).entry;
    answers.push(a.seq);
    const capped = await attest(c.a2, { seq: a.seq, how: `read the live notes (${name})`, strength: "established", answer_review: review(BARE) });
    assert.equal(capped.line.strength, "best_candidate", name);
    assert.match(capped.line.capped!.join("\n"), new RegExp(`no standing coverage record for question:${q} names it`), name);
  }
  // A coverage record that names the input, searches every area and cites a job over it: none is capped, whatever the review gives.
  await sealed(c.S, "j000041", "slack.txt", Buffer.from("no other name\n"));
  for (const [i, [name, review]] of variants.entries()) {
    const q = String(i + 1);
    ok(await rec(c.a0, coverage(q, ["input:disk.E01"], ["job:j000041/slack.txt"], { areas: ALL })));
    const held = await attest(c.a3, { seq: answers[i], how: `read the live notes and the carve of the slack (${name})`, strength: "established", answer_review: review(BARE) });
    assert.equal(held.line.strength, "established", `${name}: ${held.note}`);
    assert.equal(held.line.capped, undefined, name);
  }
});
