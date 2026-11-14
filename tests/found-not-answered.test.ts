/**
 * A value known is not an answer: findings that answer a question no answer
 * entry answers yet are said to the lead's holder, then to everyone.
 */
import assert from "node:assert/strict";
import test from "node:test";
import { FOUND_ANYONE_ANSWERS_MS, FOUND_NOT_ANSWERED_MS, foundNotAnswered, foundNotAnsweredLine } from "../extensions/leads.ts";

const T0 = Date.parse("2026-01-01T00:00:00Z");
const entry = (seq: number, kind: string, minutesAgo: number, extra: Record<string, unknown> = {}) => ({ seq, kind, by: "s06", at: new Date(T0 - minutesAgo * 60_000).toISOString(), ...extra }) as never;
const snapOf = (entries: unknown[], answered: string[], leads: Array<{ id: string; holder: string | null; answers: string[]; closed?: boolean }>, replaced: Array<[number, number]> = []) =>
  ({ ledger: { entries, bySeq: new Map(), replaced: new Map(replaced), disputed: new Set() }, answered: new Set(answered), state: { leads: new Map(leads.map((l) => [l.id, l])) } }) as never;

test("a finding that answers an unanswered question is said after ten minutes, and anyone may answer after twenty (s5d814f, question 5: 58 minutes)", () => {
  const snap = snapOf(
    [entry(229, "finding", 58, { answers: ["5"] }), entry(230, "finding", 4, { answers: ["question:6"] }), entry(231, "finding", 30, { answers: ["2"] }), entry(232, "finding", 15, { answers: "9" }), entry(240, "finding", 90, { answers: ["8"] }), entry(241, "event", 90, { answers: ["10"] })],
    ["2"],
    [{ id: "L-3", holder: "s05", answers: ["5", "6"] }, { id: "L-9", holder: "s02", answers: ["question:9"] }, { id: "L-1", holder: "s01", answers: ["8"], closed: true }],
    [[240, 250]],
  );
  const items = foundNotAnswered(snap, T0);
  assert.deepEqual(items.map((x) => [x.question, x.finding, x.minutes, x.lead, x.holder, x.anyone]), [["5", 229, 58, "L-3", "s05", true], ["9", 232, 15, "L-9", "s02", false]]);
  assert.ok(FOUND_NOT_ANSWERED_MS < FOUND_ANYONE_ANSWERS_MS);
  const holder = foundNotAnsweredLine(items, "s05")!;
  assert.match(holder, /^Found but not answered .*question:5 \(finding E-229 by s06, 58 min ago; you hold its lead: record the answer now\)/);
  const finder = foundNotAnsweredLine(items, "s06")!;
  assert.match(finder, /question:5 .*s05 holds its lead and has not answered: whoever can cite E-229 records the answer now, the holder included/);
  assert.match(finder, /question:9 .*s02 holds its lead and is asked to record the answer/);
  assert.equal(foundNotAnsweredLine([], "s05"), null);
  assert.deepEqual(foundNotAnswered(snapOf([entry(1, "finding", 3, { answers: ["1"] })], [], []), T0), [], "a fresh finding is not said yet");
});

test("--seed-leads: one open, unheld lead for each question no lead answers; --lead-max-questions bounds a lead's width", async () => {
  const { mkdtempSync, writeFileSync } = await import("node:fs");
  const { tmpdir } = await import("node:os");
  const { join } = await import("node:path");
  const P = await import("../extensions/protocol.ts");
  const L = await import("../extensions/leads.ts");
  const S = mkdtempSync(join(tmpdir(), "seed-leads-"));
  await P.initSandbox(S, { reset: true, agentIds: ["a0", "a1"] });
  writeFileSync(join(S, "SWARM.md"), ["## Goal", "", "Examine the host.", "", "### Questions", "", "1. What is the host name?", "2. When did it run?", "3. Which file?", "", "## Definition of done", "", "d", "", "## Checks", "", '- `node x "$SWARM_HARNESS/scripts/check-answers.ts" --sections 1,2,3`', ""].join("\n"));
  const mine = await L.openLead({ sandboxRoot: S, agentId: "a0" }, { title: "Host name", why: "q1", answers: ["1"], take: true });
  assert.ok(mine.ok);
  const seeded = await L.seedQuestionLeads(S);
  assert.equal(seeded.opened.length, 2, JSON.stringify(seeded));
  const snap = await L.leadsSnapshot(S);
  const made = seeded.opened.map((id) => snap.state.leads.get(id)!);
  assert.deepEqual(made.map((l) => [l.holder, l.answers]), [[null, ["2"]], [null, ["3"]]]);
  assert.ok(made.every((l) => /^Answer question [23]/.test(l.title)));
  assert.deepEqual((await L.seedQuestionLeads(S)).opened, [], "seeding again opens nothing");
  assert.equal(L.leadMaxAnswers({}), 8);
  assert.equal(L.leadMaxAnswers({ SWARM_LEAD_MAX_QUESTIONS: "3" }), 3);
  assert.equal(L.leadMaxAnswers({ SWARM_LEAD_MAX_QUESTIONS: "40" }), 8);
  process.env.SWARM_LEAD_MAX_QUESTIONS = "1";
  try {
    const wide = await L.openLead({ sandboxRoot: S, agentId: "a1" }, { title: "Two at once", why: "x", answers: ["2", "3"] });
    assert.ok(!wide.ok && /a lead names at most 1 questions: open one lead for each part of the work/.test(wide.reason), JSON.stringify(wide));
  } finally {
    delete process.env.SWARM_LEAD_MAX_QUESTIONS;
  }
});
