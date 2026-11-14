/**
 * Coordination of the work (Plan 3, WP4; docs/adr/0015): the coverage check
 * at open and claim, staggered first choices and stable names (A1); the
 * hand-off, prerequisites with their product, parked leads and blocked
 * holders counted idle (A2); offers from delivery, declined, lapsed,
 * invalidated, restart-safe, skipping seats that cannot take them, a reopen
 * offered to the previous holder, and a superseded closure confirmed or
 * reopened, never re-pointed (A3); one mechanism for leads and questions.
 * Concurrency: two seats racing for an offered lead, two waits electing at
 * once, a restart in the middle of an offer, and a compacting seat.
 */
import assert from "node:assert/strict";
import { mkdirSync, writeFileSync } from "node:fs";
import { appendFile, mkdir, mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { after, test } from "node:test";
import * as P from "../extensions/protocol.ts";
import * as L from "../extensions/leads.ts";
import * as O from "../extensions/offers.ts";
import * as Q from "../extensions/questions.ts";

const dirs: string[] = [];
after(async () => {
  for (const d of dirs) await rm(d, { recursive: true, force: true });
});

const F = { basis: "observed", confidence: "high", indicates: "What the observation shows, and the step to it.", confidence_why: "Read directly from the object it cites." } as const;

const GOAL = ["## Goal", "", "Examine it.", "", "### Questions", "", "1. Who?", "2. What?", "3. When?", "", "## Checks", "", '- `node x "$SWARM_HARNESS/scripts/check-answers.ts" --sections 1,2,3`', ""].join("\n");

async function run(agents = ["a0", "a1", "a2", "a3"]) {
  const base = await mkdtemp(join(tmpdir(), "coordination-"));
  dirs.push(base);
  const S = join(base, "run");
  await P.initSandbox(S, { swarmId: "c1", agentIds: agents, capUsd: 5, wallClockMinutes: 30, goal: GOAL });
  const ctx = (id: string) => ({ sandboxRoot: S, agentId: id });
  return { S, ctx, a0: ctx("a0"), a1: ctx("a1"), a2: ctx("a2"), a3: ctx("a3") };
}

async function traceRow(S: string, agent: string, tool: string, at: Date = new Date()): Promise<void> {
  await appendFile(join(S, P.EVENTS_REL), `${JSON.stringify({ ts: at.toISOString(), recv_ts: at.toISOString(), agent, tool, args: {}, result: { ok: true } })}\n`);
}

/** A seat waiting since `min` minutes ago. */
async function idleFor(S: string, agent: string, min: number): Promise<void> {
  const at = new Date(Date.now() - min * 60_000).toISOString();
  await mkdir(join(S, "inbox", agent), { recursive: true });
  await writeFile(join(S, "inbox", agent, "waiting.json"), JSON.stringify({ since: at, started_at: at }));
}

const ok = <T extends { ok: boolean }>(r: T): Extract<T, { ok: true }> => {
  assert.equal(r.ok, true, (r as unknown as { reason?: string }).reason);
  return r as Extract<T, { ok: true }>;
};
const refused = (r: { ok: boolean }, re: RegExp) => {
  assert.equal(r.ok, false, "expected a refusal");
  assert.match((r as unknown as { reason: string }).reason, re);
};

/** Run `fn` with offers of `sec` seconds (and parking after `park`), restoring the environment after. */
async function withTimings<T>(o: { offer?: number; max?: number; park?: number }, fn: () => Promise<T>): Promise<T> {
  const was = { offer: process.env.SWARM_OFFER_SEC, max: process.env.SWARM_OFFER_MAX_SEC, park: process.env.SWARM_LEAD_PARK_SEC };
  if (o.offer !== undefined) process.env.SWARM_OFFER_SEC = String(o.offer);
  if (o.max !== undefined) process.env.SWARM_OFFER_MAX_SEC = String(o.max);
  if (o.park !== undefined) process.env.SWARM_LEAD_PARK_SEC = String(o.park);
  try {
    return await fn();
  } finally {
    for (const [k, v] of [["SWARM_OFFER_SEC", was.offer], ["SWARM_OFFER_MAX_SEC", was.max], ["SWARM_LEAD_PARK_SEC", was.park]] as const) {
      if (v === undefined) delete process.env[k];
      else process.env[k] = v;
    }
  }
}

test("offers: first claim for 60 s from delivery within an age bound; accepted, declined, lapsed and invalidated as the state machine says", () => {
  const at = "2026-09-28T10:00:00.000Z";
  const t0 = Date.parse(at);
  const o: O.Offer = { seq: 5, at, to: "a1", rev: 3, reason: "wake", seen_at: null, declined: null, accepted: null, lapsed_at: null };
  assert.equal(O.offerStatus(o, t0 + 1000, 3).state, "pending");
  assert.equal(O.offerStatus(o, t0 + O.offerMaxAgeMs(), 3).state, "lapsed", "undelivered, it lapses at its age bound");
  const seen = { ...o, seen_at: new Date(t0 + 30_000).toISOString() };
  assert.deepEqual([O.offerStatus(seen, t0 + 60_000, 3).state, O.offerStatus(seen, t0 + 89_000, 3).state, O.offerStatus(seen, t0 + 90_000, 3).state], ["live", "live", "lapsed"], "60 s from delivery");
  const late = { ...o, seen_at: new Date(t0 + O.offerMaxAgeMs() - 10_000).toISOString() };
  assert.equal(O.offerStatus(late, t0 + O.offerMaxAgeMs(), 3).state, "lapsed", "never past its age bound");
  assert.equal(O.offerStatus(seen, t0 + 40_000, 4).state, "invalidated", "a revision since invalidates it");
  assert.equal(O.offerStatus({ ...seen, declined: { at, why: "busy" } }, t0 + 40_000, 3).state, "declined");
  assert.equal(O.offerStatus({ ...seen, accepted: { at } }, t0 + 40_000, 3).state, "accepted");
  assert.equal(O.reservingOffer([o, { ...seen, seq: 6, to: "a2" }], t0 + 40_000, 3)?.to, "a2", "the newest offer that holds it");
});

test("A1: a take on questions another seat's held lead covers is opened unheld and names the holder; overlap with why holds it; a claim is held to the same", async () => {
  const { a0, a1, a2 } = await run();
  const held = ok(await L.openLead(a0, { title: "Who logged on", why: "q1", answers: ["1"], take: true, objects: ["input:disk.E01"] })).lead;
  const second = ok(await L.openLead(a1, { title: "Who logged on, from the log", why: "q1", answers: ["Q-1"], take: true, objects: ["input:disk.E01"] }));
  assert.deepEqual([second.lead.holder, second.lead.status, second.coverage?.held], [null, "open", false]);
  assert.match(second.coverage!.why, new RegExp(`question:1 is covered by ${held.id} \\(a0, since .*\\): ${second.lead.id} is open, unheld, as a second route`));
  assert.deepEqual(second.coverage!.objects, [`${held.id} (a0) names input:disk.E01 too`], "objects are a hint, never load-bearing");
  assert.deepEqual(second.lead.covered_by, [held.id]);
  assert.equal(second.offered_to, undefined, "a second route left for its opener is not offered to an idle seat");
  // Held on purpose: a second route, said so.
  refused(await L.openLead(a2, { title: "x", why: "y", answers: ["1"], take: true, overlap: "same" }), /overlap is second_route or verification/);
  refused(await L.openLead(a2, { title: "x", why: "y", answers: ["1"], take: true, overlap: "verification" }), /overlap_why is required/);
  const third = ok(await L.openLead(a2, { title: "Verify who, from memory", why: "q1", answers: ["1"], take: true, overlap: "verification", overlap_why: "the memory image, independently of the disk" }));
  assert.deepEqual([third.lead.holder, third.lead.overlap?.kind], ["a2", "verification"]);
  // A claim of the unheld second route meets the same check.
  refused(await L.claimLead(a1, second.lead.id), new RegExp(`question:1 is covered by ${held.id} \\(a0.*claim ${second.lead.id} only as a second route or a verification`));
  const claimed = ok(await L.claimLead(a1, second.lead.id, { overlap: "second_route", overlap_why: "the security log, where a0 reads the registry" }));
  assert.equal(claimed.lead.holder, "a1");
  assert.equal(claimed.coverage?.held, true);
  // No overlap when the questions differ.
  const other = ok(await L.openLead(a1, { title: "When", why: "q3", answers: ["3"], take: true }));
  assert.deepEqual([other.lead.holder, other.coverage], ["a1", undefined]);
});

test("A1: staggered first choices wait for the seat before, or its 20 s, skip a dead seat, stop at the global bound, and carry the coverage then", async () => {
  const { S, a0 } = await run();
  const budget = JSON.parse(await readFile(join(S, "budget.json"), "utf8")) as Record<string, unknown>;
  const start = Date.parse(String(budget.started_at));
  await writeFile(join(S, "budget.json"), JSON.stringify({ ...budget, coordination: { first_choice_stagger_sec: 20, first_choice_bound_sec: 90 } }));
  // A clock the test moves: seat a2 waits for a0 and a1 (each within 20 s of its own turn).
  let clock = start + 1_000;
  const sleeps: number[] = [];
  const opts = { now: () => clock, sleep: async (ms: number) => { sleeps.push(ms); clock += ms; } };
  const a2 = await L.admitFirstChoice(S, "a2", opts);
  assert.ok(a2);
  assert.equal(a2!.order, 2);
  assert.equal(a2!.turn_at, new Date(start + 40_000).toISOString(), "a0 and a1 chose nothing: 20 s each");
  // a0 chooses: its first choice is recorded; a1's turn comes at once, not 20 s later.
  ok(await L.openLead(a0, { title: "Who", why: "q1", answers: ["1"], take: true }));
  clock = start + 5_000;
  const a1 = await L.admitFirstChoice(S, "a1", opts);
  assert.ok(a1);
  assert.equal(Date.parse(a1!.turn_at) <= clock, true, "a0 chose: a1 goes");
  assert.deepEqual(a1!.coverage.held.map((h) => [h.lead, h.holder, h.answers]), [["L-1", "a0", ["1"]]], "the admission carries the register as it stands");
  assert.equal(await L.admitFirstChoice(S, "a0", opts), null, "a seat that chose has no first choice left");
  // A dead seat is skipped; the bound caps every wait.
  await mkdir(join(S, "done", "agents"), { recursive: true });
  await writeFile(join(S, "done", "agents", "a1.dead"), "x");
  clock = start + 1_000;
  const a3 = await L.admitFirstChoice(S, "a3", opts);
  const chose = Date.parse((await L.leadsSnapshot(S)).state.events[0].at);
  assert.equal(a3!.turn_at, new Date(Math.max(chose, start) + 20_000).toISOString(), "a0 chose, a1 is dead: a3 waits only for a2's 20 s");
  clock = start + 95_000;
  assert.equal(await L.admitFirstChoice(S, "a3", opts), null, "past the global bound nobody waits");
  // With no stagger at kickoff nobody waits at all.
  await writeFile(join(S, "budget.json"), JSON.stringify(budget));
  assert.equal(await L.admitFirstChoice(S, "a2"), null);
});

test("A1: a seat's name is stable, and its label follows the lead it holds", async () => {
  const { S, a0, a1 } = await run();
  ok(await P.claimName(S, "a1", "disk reader", "the disk"));
  const renamed = await P.claimName(S, "a1", "mail reader", "the mail store");
  assert.ok(renamed.ok && renamed.name === "disk reader" && renamed.asked === "mail reader");
  ok(await L.openLead(a1, { title: "Read the mail store", why: "q2", answers: ["2"], take: true }));
  const view = await P.teamView(a0);
  const peer = view.peers.find((p) => p.id === "a1")!;
  assert.equal(peer.name, "disk reader");
  assert.equal(peer.label, 'disk reader (a1) on L-1 "Read the mail store"');
  assert.deepEqual(peer.holds, [{ id: "L-1", title: "Read the mail store", status: "active" }]);
  assert.equal(view.peers.find((p) => p.id === "a2")!.label, "a2, holding no lead");
});

test("A2: a prerequisite opened and linked in one act, with its product; dependency outcomes are satisfied, failed, invalidated or withdrawn, never met by a removal", async () => {
  const { S, a0, a1, a2 } = await run();
  await traceRow(S, "a0", "bash");
  const consumer = ok(await L.openLead(a0, { title: "Decrypt the message", why: "q2", answers: ["2"], take: true })).lead;
  refused(await L.openLead(a1, { title: "Find the key", why: "for L-1", consumer: consumer.id }), /held by a0; its needs are its holder's to revise/);
  refused(await L.openLead(a0, { title: "Find the key", why: "for L-1", inputs: ["input:missing.bin"] }), /inputs: /);
  const pre = ok(await L.openLead(a0, { title: "Find the key", why: "the message is encrypted", consumer: consumer.id, product: "the key, as a file", acceptance: "it opens the header", next_action: "search the notes app for a 32-byte string" }));
  assert.equal(pre.consumer, consumer.id);
  assert.equal(pre.lead.origin, `prerequisite of ${consumer.id}`);
  assert.deepEqual([pre.lead.product, pre.lead.acceptance, pre.lead.next_action], ["the key, as a file", "it opens the header", "search the notes app for a 32-byte string"]);
  let snap = await L.leadsSnapshot(S);
  let c = L.viewLead(snap.state.leads.get(consumer.id)!, snap);
  assert.deepEqual(c.needs.map((n) => [n.need, n.met, n.outcome]), [[`${pre.lead.id}:resolved`, false, "pending"]]);
  // The producer delivers, with its product's refs.
  ok(await L.claimLead(a1, pre.lead.id));
  const key = ok(await P.recordEntry(a1, { kind: "finding", ...F, value: "The key is in a note", source: "notes", evidence: "row 3", refs: ["unresolved:fixture"] }) as never) as unknown as { entry: P.LedgerEntry };
  refused(await L.closeLead(a1, pre.lead.id, { disposition: "resolved", ref: `E-${key.entry.seq}`, result_refs: ["E-99"] }), /result_refs: E-99 is not in the ledger/);
  const closed = ok(await L.closeLead(a1, pre.lead.id, { disposition: "resolved", ref: `E-${key.entry.seq}`, result_refs: [`E-${key.entry.seq}`] })).lead;
  assert.deepEqual(closed.result_refs, [`E-${key.entry.seq}`]);
  snap = await L.leadsSnapshot(S);
  c = L.viewLead(snap.state.leads.get(consumer.id)!, snap);
  assert.deepEqual(c.needs.map((n) => n.outcome), ["satisfied"]);
  // Reopened: what met the need no longer stands.
  const pv = snap.state.leads.get(pre.lead.id)!;
  ok(await L.agentReopenLead(a2, pre.lead.id, { expected_revision: pv.rev, why: "the key opens only the first part" }));
  snap = await L.leadsSnapshot(S);
  assert.deepEqual(L.viewLead(snap.state.leads.get(consumer.id)!, snap).needs.map((n) => n.outcome), ["invalidated"]);
  // Failed: the producer ends otherwise.
  ok(await L.claimLead(a1, pre.lead.id));
  const lim = ok(await P.recordEntry(a1, { kind: "limitation", value: "No key opens the rest", source: "notes", evidence: "tried all", reason: "failed" }) as never) as unknown as { entry: P.LedgerEntry };
  ok(await L.closeLead(a1, pre.lead.id, { disposition: "infeasible", ref: `E-${lim.entry.seq}` }));
  snap = await L.leadsSnapshot(S);
  assert.deepEqual(L.viewLead(snap.state.leads.get(consumer.id)!, snap).needs.map((n) => n.outcome), ["failed"]);
  // Withdrawn, with its reason: never read as met.
  const dropped = ok(await L.linkLead(a0, consumer.id, { remove: [`${pre.lead.id}:resolved`], why: "the message is also in clear in the backup" })).lead;
  assert.deepEqual([dropped.needs.length, dropped.dropped?.[0]?.why], [0, "the message is also in clear in the backup"]);
});

test("A2: a hand-off offers the lead to the seat it names (never one that cannot take it) or to the seat idle longest", async () => {
  const { S, a0, a1, a2, a3 } = await run();
  await traceRow(S, "a0", "bash");
  const l = ok(await L.openLead(a0, { title: "Carve the pagefile", why: "q3", answers: ["3"], take: true })).lead;
  refused(await L.handoffLead(a1, l.id, { why: "x" }), /held by a0.*only its holder can hand over it/);
  refused(await L.handoffLead(a0, l.id, { why: "" }), /why is required/);
  refused(await L.handoffLead(a0, l.id, { why: "x", to: "a0" }), /a hand-off is to another seat/);
  await mkdir(join(S, "done", "agents"), { recursive: true });
  await writeFile(join(S, "done", "agents", "a3.dead"), "x");
  refused(await L.handoffLead(a0, l.id, { why: "x", to: "a3" }), /a3 is marked dead/);
  // A compacting seat cannot take it either.
  await traceRow(S, "a2", "compact_start");
  refused(await L.handoffLead(a0, l.id, { why: "x", to: "a2" }), /a2 is compacting its context/);
  const h = ok(await L.handoffLead(a0, l.id, { why: "the pagefile is 8 GB and I have the registry; next: run the carver over it", to: "a1" }));
  assert.deepEqual([h.lead.holder, h.offered_to, h.lead.offered?.to, h.lead.offered?.reason], [null, "a1", "a1", "handoff"]);
  // Reserved for a1: a peer's claim is refused, a1's accepts it.
  refused(await L.claimLead(a2, l.id), /is offered to a1 \(handed over by a0\), who has first claim/);
  const took = ok(await L.claimLead(a1, l.id));
  assert.equal(took.lead.holder, "a1");
  const snap = await L.leadsSnapshot(S);
  const o = snap.state.leads.get(l.id)!.offers.at(-1)!;
  assert.ok(o.accepted, "the claim accepted the offer");
  // Left to nobody: the seat idle longest.
  await idleFor(S, "a0", 5);
  const h2 = ok(await L.handoffLead(a1, l.id, { why: "back to a0, who knows the registry" }));
  assert.equal(h2.offered_to, "a0");
  void a3;
});

test("A2: a lead parked in a busy holder's hands is offered to an idle seat; the holder keeps it by acting, or the idle seat takes it over", async () => {
  await withTimings({ park: 1 }, async () => {
    const { S, a0, a1, a2 } = await run();
    await traceRow(S, "a0", "bash");
    const l = ok(await L.openLead(a0, { title: "Read the browser history", why: "q2", answers: ["2"], take: true })).lead;
    await new Promise((r) => setTimeout(r, 1_200));
    // a0 works on another lead: the positive evidence that L-1 lies idle in busy hands.
    const other = ok(await L.openLead(a0, { title: "Walk the registry", why: "q1", take: true })).lead;
    await traceRow(S, "a0", "bash");
    let snap = await L.leadsSnapshot(S);
    const parked = await L.parkedLeads(S, snap);
    assert.deepEqual(parked.map((p) => [p.lead, p.holder]), [[l.id, "a0"]]);
    assert.match((await L.leadsDigest(a2, { mark: false })).text, new RegExp(`Parked \\(held, no job and no act on it .*\\): ${l.id} \\(a0, `));
    // The idle seat's wait is offered it.
    await idleFor(S, "a1", 5);
    const text = await L.leadsWaitCheck(a1)();
    assert.match(text ?? "", new RegExp(`${l.id} \\("Read the browser history"\\) is parked in a0's hands .* offered to you`));
    snap = await L.leadsSnapshot(S);
    const offer = snap.state.leads.get(l.id)!.offers.at(-1)!;
    assert.deepEqual([offer.to, offer.reason, offer.from], ["a1", "parked", "a0"]);
    // The holder is told, and keeps it by claiming it again: the offer ends.
    const holderNotices = await L.leadsDigest(a0, { mark: false });
    assert.ok(holderNotices.notices.some((n) => n.kind === "parked" && n.lead === l.id), JSON.stringify(holderNotices.notices));
    const kept = ok(await L.claimLead(a0, l.id));
    assert.equal(kept.kept, true);
    refused(await L.claimLead(a1, l.id), /is held by a0/);
    // Parked again, offered again, and this time taken over at once.
    await new Promise((r) => setTimeout(r, 1_200));
    ok(await L.linkLead(a0, other.id, { routes: [{ source: "input:disk.E01", method: "the SYSTEM hive" }] }));
    await traceRow(S, "a0", "bash");
    await L.leadsDigest(a1, { mark: true });
    assert.match((await L.leadsWaitCheck(a1)()) ?? "", new RegExp(`${l.id} .* is parked in a0's hands`));
    const taken = ok(await L.claimLead(a1, l.id));
    assert.deepEqual([taken.lead.holder, taken.reclaimed_from], ["a1", "a0"]);
    snap = await L.leadsSnapshot(S);
    assert.equal(snap.state.events.filter((e) => e.ev === "claim" && e.lead === l.id).at(-1)!.cause, "parked");
  });
});

test("A2: a seat whose held leads are all blocked counts as idle for offers", async () => {
  const { S, a0, a1 } = await run();
  await traceRow(S, "a1", "bash");
  const producer = ok(await L.openLead(a1, { title: "Unlock the volume", why: "q1", take: true })).lead;
  ok(await L.openLead(a0, { title: "Read inside the volume", why: "q1", needs: [producer.id], take: true }));
  await idleFor(S, "a0", 5);
  const snap = await L.leadsSnapshot(S);
  const idle = await L.idleSeats(S, snap.state, snap.ledger, snap.jobs);
  assert.ok(idle.some((x) => x.agent === "a0"), "its only lead waits on a need: it can take other work");
  const opened = ok(await L.openLead(a1, { title: "Walk the second profile", why: "q2" }));
  assert.equal(opened.offered_to, "a0");
});

test("A3: two seats racing for an offered lead: only the seat it is offered to gets it; a decline passes it on; a lapse and a revision end it", async () => {
  await withTimings({ offer: 1, max: 5 }, async () => {
    const { S, a0, a1, a2 } = await run();
    await idleFor(S, "a1", 9);
    await idleFor(S, "a2", 3);
    const l = ok(await L.openLead(a0, { title: "Read the prefetch folder", why: "q3" }));
    assert.equal(l.offered_to, "a1");
    // A peer's claim first is refused, naming the offer.
    refused(await L.claimLead(a2, l.lead.id), /offered to a1 \(woken for it\)/);
    // Both at once: whichever takes the lock first, only a1 gets it; a2 is refused by the offer or by a1's hold.
    const [r1, r2] = await Promise.all([L.claimLead(a2, l.lead.id), L.claimLead(a1, l.lead.id)]);
    assert.equal(r1.ok, false);
    assert.match((r1 as { reason: string }).reason, /offered to a1 \(woken for it\)|is held by a1/);
    assert.equal(r2.ok, true);
    assert.equal((await L.leadsSnapshot(S)).state.events.filter((e) => e.ev === "claim" && e.lead === l.lead.id).length, 1, "one claim, the offered seat's");
    // Released: offered again; declined, the next idle seat is offered it.
    ok(await L.releaseLead(a1, l.lead.id, { why: "a2 knows prefetch better" }));
    await idleFor(S, "a1", 10);
    const offeredTo = async () => (await L.leadsSnapshot(S)).state.leads.get(l.lead.id)!.offers.at(-1)!;
    assert.match((await L.leadsWaitCheck(a1)()) ?? "", /offered to you/);
    assert.equal((await offeredTo()).to, "a1");
    refused(await L.answerLeadOffer(a2, l.lead.id, { action: "decline", why: "x" }), /no offer of L-1 stands for you/);
    refused(await L.answerLeadOffer(a1, l.lead.id, { action: "decline" }), /why is required/);
    ok(await L.answerLeadOffer(a1, l.lead.id, { action: "decline", why: "I hold the registry work" }));
    await idleFor(S, "a2", 8);
    assert.match((await L.leadsWaitCheck(a2)()) ?? "", /offered to you/);
    assert.equal((await offeredTo()).to, "a2", "a1 declined: a2 next");
    assert.equal(await L.leadsWaitCheck(a1)(), null, "a1 is not offered it again at this revision");
    // Lapsed after its window from delivery: anyone may claim it.
    await new Promise((r) => setTimeout(r, 1_200));
    const snap = await L.leadsSnapshot(S);
    const o = snap.state.leads.get(l.lead.id)!.offers.at(-1)!;
    assert.equal(O.offerStatus(o, Date.now(), snap.state.leads.get(l.lead.id)!.rev).state, "lapsed");
    // A revision invalidates an offer: a route added to the lead while it is offered.
    await idleFor(S, "a3", 20);
    const l2 = ok(await L.openLead(a0, { title: "Read the shimcache", why: "q3" }));
    assert.equal(l2.offered_to, "a3");
    ok(await L.linkLead(a0, l2.lead.id, { routes: [{ source: "input:disk.E01", method: "parse the SYSTEM hive" }] }));
    const s2 = await L.leadsSnapshot(S);
    const o2 = s2.state.leads.get(l2.lead.id)!.offers.at(-1)!;
    assert.equal(O.offerStatus(o2, Date.now(), s2.state.leads.get(l2.lead.id)!.rev).state, "invalidated");
    ok(await L.claimLead(a2, l2.lead.id));
  });
});

test("A3: two waits electing at once make one offer; an offer survives a restart of the process that made it", async () => {
  const { S, a0, a1, a2, ctx } = await run(["a0", "a1", "a2", "a3", "a4"]);
  await idleFor(S, "a1", 9);
  await idleFor(S, "a2", 9);
  // An open lead whose offer was never written (the hub died after the open).
  await mkdir(join(S, "leads"), { recursive: true });
  const text = await readFile(join(S, L.LEADS_LOG), "utf8").catch(() => "");
  const last = text.trim() ? (JSON.parse(text.trim().split("\n").at(-1)!) as L.LeadEvent) : null;
  const draft = { v: 1 as const, seq: (last?.seq ?? 0) + 1, at: new Date().toISOString(), by: "a0", ev: "open" as const, lead: "L-1", title: "Read the jump lists", why: "q3", origin: "lead_open by a0", needs: [], answers: [], material: true, generation: 0, prev: last?.hash ?? "genesis" };
  await appendFile(join(S, L.LEADS_LOG), `${JSON.stringify({ ...draft, hash: L.leadEventHash(draft as unknown as L.LeadEvent, last?.hash ?? "genesis") })}\n`);
  const [w1, w2] = await Promise.all([L.leadsWaitCheck(a1)(), L.leadsWaitCheck(a2)()]);
  const snap = await L.leadsSnapshot(S);
  const offers = snap.state.events.filter((e) => e.ev === "offer" && e.lead === "L-1");
  assert.equal(offers.length, 1, "one offer, however many waits elect at once");
  assert.equal([w1, w2].filter((w) => /offered to you/.test(w ?? "")).length, 1);
  const to = offers[0].to!;
  // A fresh process (the hub restarted) reads the offer where it was: it still holds the lead.
  const fresh = (await import(`../extensions/leads.ts?restart=${Date.now()}`)) as typeof L;
  const other = to === "a1" ? "a2" : "a1";
  const r = await fresh.claimLead(ctx(other), "L-1");
  assert.equal(r.ok, false);
  assert.match((r as { reason: string }).reason, new RegExp(`offered to ${to}`));
  ok(await fresh.claimLead(ctx(to), "L-1"));
  void a0;
});

test("A3: a reopen after the operator's note is offered to the previous holder first; nobody else is woken meanwhile", async () => {
  const { S, a1, a2 } = await run();
  await traceRow(S, "a1", "bash");
  const l = ok(await L.openLead(a1, { title: "Fetch the pasted key", why: "q2", answers: ["2"], take: true })).lead;
  ok(await L.closeLead(a1, l.id, { disposition: "needs_operator", ref: "allow the paste host so a job can fetch the key" }));
  await idleFor(S, "a2", 20);
  const noted = ok(await L.noteLead(S, l.id, "Allowed", { allowHost: "paste.example.org" }));
  assert.deepEqual([noted.reopened, noted.lead.offered?.to, noted.lead.offered?.reason], [true, "a1", "reopen"]);
  refused(await L.claimLead(a2, l.id), /offered to a1 \(reopened after the operator's note, to its previous holder first\)/);
  assert.equal(await L.leadsWaitCheck(a2)(), null, "the idle seat is not woken while the previous holder has it");
  ok(await L.claimLead(a1, l.id));
});

test("A3: a superseded closure is offered to its closer to confirm on what stands, by revision; a stranger, a wrong revision or a dead closer do not confirm it", async () => {
  const { S, a0, a1, a2 } = await run();
  await traceRow(S, "a1", "bash");
  const l = ok(await L.openLead(a1, { title: "Which account ran it", why: "q1", answers: ["1"], take: true })).lead;
  const f = ok(await P.recordEntry(a1, { kind: "finding", ...F, value: "Account bob ran it", source: "prefetch", evidence: "row 1", refs: ["unresolved:fixture"] }) as never) as unknown as { entry: P.LedgerEntry };
  ok(await L.closeLead(a1, l.id, { disposition: "resolved", ref: `E-${f.entry.seq}` }));
  const fix = ok(await P.recordEntry(a0, { kind: "finding", ...F, value: "Account bob ran it, from the console", source: "prefetch", evidence: "row 1 and the session", refs: ["unresolved:fixture"], supersedes: f.entry.seq, because: "the session says where" }) as never) as unknown as { entry: P.LedgerEntry };
  assert.deepEqual(await L.reopenOnLedger(S), []);
  let lv = (await L.leadsSnapshot(S)).state.leads.get(l.id)!;
  assert.ok(lv.confirm);
  refused(await L.confirmLead(a2, l.id, { expected_revision: lv.rev, why: "it holds" }), /its closer/);
  refused(await L.confirmLead(a1, l.id, { expected_revision: lv.rev - 1, why: "it holds" }), /is at revision/);
  refused(await L.confirmLead(a1, l.id, { expected_revision: lv.rev }), /why is required/);
  const confirmed = ok(await L.confirmLead(a1, l.id, { expected_revision: lv.rev, why: "the correction adds where; who ran it is unchanged" }));
  assert.equal(confirmed.lead.ref, `E-${fix.entry.seq}`, "confirmed on the correction, by the closer's act");
  assert.deepEqual(confirmed.lead.confirmed?.map((c) => [c.by, c.from, c.to]), [["a1", `E-${f.entry.seq}`, `E-${fix.entry.seq}`]]);
  assert.equal(confirmed.lead.confirm, undefined);
  // A dead closer: reopened at once, nobody to confirm it.
  const l2 = ok(await L.openLead(a1, { title: "When did it run", why: "q3", answers: ["3"], take: true })).lead;
  const g = ok(await P.recordEntry(a1, { kind: "finding", ...F, value: "At ten", source: "prefetch", evidence: "row 2", refs: ["unresolved:fixture"] }) as never) as unknown as { entry: P.LedgerEntry };
  ok(await L.closeLead(a1, l2.id, { disposition: "resolved", ref: `E-${g.entry.seq}` }));
  await mkdir(join(S, "done", "agents"), { recursive: true });
  await writeFile(join(S, "done", "agents", "a1.dead"), "x");
  ok(await P.recordEntry(a0, { kind: "finding", ...F, value: "At ten past ten", source: "prefetch", evidence: "row 2, UTC", refs: ["unresolved:fixture"], supersedes: g.entry.seq, because: "the clock was local" }) as never);
  assert.deepEqual(await L.reopenOnLedger(S), [l2.id]);
  lv = (await L.leadsSnapshot(S)).state.leads.get(l2.id)!;
  assert.equal(lv.closed, null);
});

test("one offer mechanism: a question offered to its suggested seat counts its minute from delivery; declined, it passes on; a seat holding a lead offer is offered nothing more", async () => {
  await withTimings({ offer: 1, max: 5 }, async () => {
    const { S, a0, a1, a2, a3 } = await run();
    const operator: Q.Actor = { kind: "human", role: "operator", person: "ops@lab", enrolled: false, os_user: "ops", host: "lab", via: "cli", identity: "claimed" };
    await idleFor(S, "a1", 4);
    await idleFor(S, "a2", 9);
    await idleFor(S, "a3", 6);
    // a2 is offered a lead first: one offer at a time.
    const lead = ok(await L.openLead(a0, { title: "Read the prefetch folder", why: "q3" }));
    assert.equal(lead.offered_to, "a2");
    const q = ok(await Q.act(S, operator, "open", { text: "Was the archive mailed?", why: "the client says so", suggested_to: "a1" })).q!;
    await Q.deliverPending(S);
    let qs = await Q.questionsSnapshot(S);
    let o = qs.state.questions.get(q)!.offers.at(-1)!;
    assert.deepEqual([o.to, o.first, o.seen_at], ["a1", true, null]);
    assert.ok(Q.reservingQuestionOffer(qs.state.questions.get(q)!, Date.now() + 3_000), "undelivered, it holds up to its age bound");
    // Delivered through a1's wait: its window runs from here.
    assert.match((await L.leadsWaitCheck(a1)()) ?? "", new RegExp(`${q} is offered to you first`));
    qs = await Q.questionsSnapshot(S);
    o = qs.state.questions.get(q)!.offers.at(-1)!;
    assert.ok(o.seen_at, "the delivery is on the record");
    // Declined: the next seat, at once; a2 holds a lead offer, so a3.
    refused(await Q.answerQuestionOffer(a2, q, { action: "decline", why: "x" }), /no offer of .* stands for you/);
    refused(await Q.answerQuestionOffer(a1, q, { action: "decline" }), /why is required/);
    ok(await Q.answerQuestionOffer(a1, q, { action: "decline", why: "I hold the disk" }));
    assert.equal(await Q.electQuestionOffer(a2), null, "a seat with a lead offer standing is offered nothing more");
    const pooled = await Q.electQuestionOffer(a3);
    assert.equal(pooled?.q.id, q);
    assert.equal(pooled?.offer.to, "a3");
    // Accepted, it holds the question for another window while the seat opens its lead; a peer's take meanwhile is unheld.
    const acc = ok(await Q.answerQuestionOffer(a3, q, { action: "accept" }));
    assert.ok(acc.until);
    const early = ok(await L.openLead(a1, { title: "Search the mail", why: q, answers: [q], take: true, proposition: "it was mailed", negation: "it was not mailed", routes: [{ source: "input:disk.E01", method: "the mail store" }] }));
    assert.equal(early.lead.holder, null);
    assert.match(early.coverage?.reserved ?? "", new RegExp(`${q} is offered to a3`));
    // The peer's claim is refused while a3 holds the question; a3's own claim takes the lead (framed at its open already).
    refused(await L.claimLead(a1, early.lead.id), new RegExp(`serves ${q}, which is offered to a3`));
    const took = ok(await L.claimLead(a3, early.lead.id));
    assert.equal(took.lead.holder, "a3");
    // Lapsed after its window: nobody holds it for anyone.
    await new Promise((r) => setTimeout(r, 1_300));
    assert.equal(Q.reservingQuestionOffer((await Q.questionsSnapshot(S)).state.questions.get(q)!, Date.now()), null);
  });
});

test("A1: a heavy job's admission is told who else works its questions or its declared objects now; a hint, never a refusal", async () => {
  const { S, a0, a1 } = await run();
  await traceRow(S, "a0", "bash");
  ok(await L.openLead(a0, { title: "Who logged on", why: "q1", answers: ["1"], take: true, objects: ["input:disk.E01"] }));
  const mine = ok(await L.openLead(a1, { title: "Who logged on, from memory", why: "q1", answers: ["1"], take: true, overlap: "verification", overlap_why: "memory, independently" })).lead;
  const dir = join(S, "store", "jobs", "j000001");
  await mkdir(dir, { recursive: true });
  await writeFile(join(dir, "job.json"), JSON.stringify({ id: "j000001", state: "running", requester: { agent: "a0" }, spec: { kind: "command", scope: "declared", inputs: ["input:disk.E01"], command: "carve" } }));
  const hint = await L.jobAdmissionHint(S, "a1", mine.id, ["input:disk.E01"]);
  assert.ok(hint);
  assert.deepEqual(hint!.overlaps.map((o) => [o.lead, o.holder]), [["L-1", "a0"]]);
  assert.deepEqual(hint!.objects, ["L-1 (a0) names input:disk.E01 too"]);
  assert.deepEqual(hint!.jobs, ["j000001 (a0, running) declared input:disk.E01 too"]);
  assert.equal(await L.jobAdmissionHint(S, "a1", mine.id, ["input:other.bin"]).then((h) => h?.objects.length ?? 0), 0);
});

test("what coordination adds is shown whole: leads.md and the operator's list name the offer that holds a lead, its product contract and a dropped need, and the list the finish", async () => {
  const { S, a0 } = await run();
  await traceRow(S, "a0", "bash");
  const l = ok(await L.openLead(a0, { title: "Carve the pagefile", why: "q3", answers: ["3"], take: true, product: "the carved strings, one file", acceptance: "every hit with its offset", next_action: "grep the strings for the key" })).lead;
  const producer = ok(await L.openLead(a0, { title: "Unlock the volume", why: "q3", material: false })).lead;
  ok(await L.linkLead(a0, l.id, { add: [producer.id] }));
  ok(await L.linkLead(a0, l.id, { remove: [`${producer.id}:resolved`], why: "the pagefile is outside the volume" }));
  await idleFor(S, "a1", 5);
  ok(await L.handoffLead(a0, l.id, { why: "the registry is mine; next: run the carver", to: "a1" }));
  const md = await readFile(join(S, L.LEADS_MD), "utf8");
  assert.match(md, /- Offered to a1 \(handoff, from a0\), first claim until .* \(at revision \d+\)/);
  assert.match(md, /- Product: the carved strings, one file; accepted when: every hit with its offset/);
  assert.match(md, /- Next action once accepted: grep the strings for the key/);
  assert.match(md, new RegExp(`- Need dropped at .* by a0: ${producer.id}:resolved \\(withdrawn, never met: the pagefile is outside the volume\\)`));
  const { listText } = await import("../scripts/leads-cli.ts");
  const text = await listText(S);
  assert.match(text, /offered to a1 \(handoff, from a0\), first claim until/);
  assert.match(text, /product: the carved strings, one file; accepted when: every hit with its offset; then: grep the strings for the key/);
  assert.match(text, new RegExp(`need ${producer.id}:resolved dropped by a0: the pagefile is outside the volume`));
  assert.match(text, /^Finish: not ready \(\d+\); nobody coordinates it yet: the first prepare or done takes it\.$/m);
  assert.match(text, new RegExp(`^  holds it: ${l.id} "Carve the pagefile" is open`, "m"));
});

test("compaction: a compacting seat is offered nothing: a reopen after the operator's note is not held for it, a question suggested to it goes to an idle seat; a closure of its superseded waits for it, bounded (the c10 pilot)", async () => {
  const { S, a0, a1, a2, ctx } = await run();
  const operator: Q.Actor = { kind: "human", role: "operator", person: "ops@lab", enrolled: false, os_user: "ops", host: "lab", via: "cli", identity: "claimed" };
  await traceRow(S, "a1", "bash");
  const asked = ok(await L.openLead(a1, { title: "Fetch the pasted key", why: "q2", answers: ["2"], take: true })).lead;
  ok(await L.closeLead(a1, asked.id, { disposition: "needs_operator", ref: "allow the paste host so a job can fetch the key" }));
  const closed = ok(await L.openLead(a1, { title: "Which account ran it", why: "q1", answers: ["1"], take: true })).lead;
  const f = ok(await P.recordEntry(a1, { kind: "finding", ...F, value: "Account bob ran it", source: "prefetch", evidence: "row 1", refs: ["unresolved:fixture"] }) as never) as unknown as { entry: P.LedgerEntry };
  ok(await L.closeLead(a1, closed.id, { disposition: "resolved", ref: `E-${f.entry.seq}` }));
  // a1 compacts its context: it takes no prompt until it is through.
  await traceRow(S, "a1", "compact_start");
  await idleFor(S, "a2", 10);
  const noted = ok(await L.noteLead(S, asked.id, "Allowed", { allowHost: "paste.example.org" }));
  assert.deepEqual([noted.reopened, noted.lead.offered], [true, undefined], "not held for a compacting previous holder");
  ok(await L.claimLead(a2, asked.id));
  ok(await P.recordEntry(a0, { kind: "finding", ...F, value: "Account bob ran it, from the console", source: "prefetch", evidence: "row 1 and the session", refs: ["unresolved:fixture"], supersedes: f.entry.seq, because: "the session says where" }) as never);
  // Compacting is away for a while, not gone (the c10 pilot's L-17): the confirmation is offered and waits for it, never re-pointed.
  assert.deepEqual(await L.reopenOnLedger(S), [], "held for its compacting closer");
  const held = (await L.leadsSnapshot(S)).state.leads.get(closed.id)!;
  assert.deepEqual([Boolean(held.closed), held.confirm ? held.offers.find((x) => x.seq === held.confirm!.offer)?.to : null], [true, "a1"]);
  await idleFor(S, "a3", 7);
  const q = ok(await Q.act(S, operator, "open", { text: "Was the archive mailed?", why: "the client says so", suggested_to: "a1" })).q!;
  await Q.deliverPending(S);
  const o = (await Q.questionsSnapshot(S)).state.questions.get(q)!.offers.at(-1)!;
  assert.deepEqual([o.to, o.first], ["a3", false], "the suggested seat is compacting: the idle seat is offered it");
  // Its compaction over, a1 can be offered work again.
  await traceRow(S, "a1", "compact_done");
  assert.equal((await L.seatAvailable(S, "a1")).available, true);
  void ctx;
});

test("the header says how many seats work now, and what each of the others is", async () => {
  const { S } = await run();
  const now = new Date();
  await traceRow(S, "a1", "bash", new Date(now.getTime() - 40 * 60_000));
  await traceRow(S, "a0", "bash", now);
  await traceRow(S, "a2", "wait", now); // waiting is not work
  mkdirSync(join(S, "done", "agents"), { recursive: true });
  writeFileSync(join(S, "done", "agents", "a3.done"), "");
  const line = await L.seatsWorkingLine(S, await L.leadsSnapshot(S), now.getTime());
  assert.match(line ?? "", /^Seats working: 1 of 4 \(/);
  assert.match(line!, /a1 silent \d+\+? min/);
  assert.match(line!, /a2 silent/);
  assert.match(line!, /a3 done/);
  assert.ok(line!.length < 300);
});
