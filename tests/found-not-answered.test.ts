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
