/**
 * A read made before every model call is served within its deadline: a hub
 * that is held for seconds costs a seat the deadline, not the hold.
 */
import assert from "node:assert/strict";
import test from "node:test";
import { lastKnown } from "../extensions/last-known.ts";
import { factsWithin, HANDOFF_FACTS_MS } from "../extensions/self-compact.ts";

const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));

test("with the hub held ten seconds, a read answers within its deadline on the last value, and the newer value arrives for a later call", async () => {
  const lk = lastKnown<number>(50);
  assert.equal(await lk.read(async () => 1), 1, "a first read is waited for whole");
  let release!: (v: number) => void;
  const held = new Promise<number>((r) => (release = r));
  const t0 = Date.now();
  const gaps: number[] = [];
  for (let i = 0; i < 5; i += 1) {
    const s = Date.now();
    assert.equal(await lk.read(() => held), 1, "the last value the hub gave");
    gaps.push(Date.now() - s);
  }
  assert.ok(Math.max(...gaps) < 300, `each read took at most ${Math.max(...gaps)} ms`);
  assert.ok(Date.now() - t0 < 1500);
  assert.equal(lk.stale(), 5);
  release(2);
  await sleep(10);
  assert.equal(await lk.read(async () => 3), 3, "once the held read has ended, the next one is a new read");
  assert.ok((lk.age() ?? 1e9) < 1000);
});

test("only one read flies at a time; a first read that fails throws, a later failing one gives the last value", async () => {
  const lk = lastKnown<string>(30);
  await assert.rejects(lk.read(async () => { throw new Error("hub down"); }), /hub down/);
  let calls = 0;
  const slow = async () => { calls += 1; await sleep(80); return "a"; };
  const [x, y] = await Promise.all([lk.read(slow), lk.read(slow)]);
  assert.deepEqual([x, y], ["a", "a"]);
  assert.equal(calls, 1, "two callers share the one read");
  assert.equal(await lk.read(async () => { throw new Error("hub down again"); }), "a");
  assert.equal(lk.age() !== null, true);
});

test("a hand-off does not wait for a hub that is held: past its bound the facts are unknown, and a hub that answers in time is used", async () => {
  const known = { claims: [], unread: { main: 2 }, ledgerTotal: 9, ledgerMine: 3, sentinel: false, spentUsd: 0 };
  assert.deepEqual(await factsWithin(async () => known, 50), known);
  const t0 = Date.now();
  const late = await factsWithin(() => new Promise((r) => setTimeout(() => r(known), 2000)), 50);
  assert.ok(Date.now() - t0 < 500, `the hand-off waited ${Date.now() - t0} ms`);
  assert.equal(late.unknown, true);
  assert.equal((await factsWithin(async () => { throw new Error("hub down"); }, 50)).unknown, true);
  assert.ok(HANDOFF_FACTS_MS <= 5000, "a hand-off is at most five seconds behind its compaction");
});
