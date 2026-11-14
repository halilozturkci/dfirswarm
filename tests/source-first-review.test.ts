/**
 * A source-first review (docs/adr/0015, "A source-first review"): an
 * established attest of an answer that claims established, on a material
 * question, names the strongest rival and the test that separates it
 * (answer_review.discriminator), and says where it read each value it
 * vouches for (reproduced_at, which the hub reads at the offset in UTF-8
 * and UTF-16LE) or how it was derived (derivation). What it lacks is
 * recorded best_candidate, the reason in `capped`, and the reply says how to
 * fix it. A partial answer's review is checked and never capped for it. The
 * review offer leads with the question, its scope and its sources, and a
 * review goes first to a seat of another model family.
 */
import assert from "node:assert/strict";
import { mkdir, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { test } from "node:test";
import * as L from "../extensions/leads.ts";
import * as O from "../extensions/offers.ts";
import * as P from "../extensions/protocol.ts";
import { checkLedgerAnswers } from "../scripts/check-answers.ts";
import { measureRun, metricsText } from "../scripts/metrics.ts";
import { sealTree, storePaths } from "../scripts/evidence-store.ts";
import { A, coverage, ESTABLISHED, F, ok, planned, rec, refused, REVIEW, run, SOURCE_FIRST } from "./negative-bar-fixture.ts";

const HIGH = { ...A, confidence: "high" } as const;
/** The review part by part, as every established review since B2 gives it: no discriminator, no locator, no derivation. */
const { discriminator: _d, derivation: _v, ...BARE } = ESTABLISHED.answer_review;

/** A job whose one output holds `bytes`, sealed, as the job service leaves one. */
async function sealed(S: string, id: string, file: string, bytes: Buffer, spec: Record<string, unknown> = { kind: "command", scope: "declared", inputs: ["input:disk.E01"], command: "strings" }): Promise<void> {
  const staging = join(S, "..", `staging-${id}`);
  await mkdir(staging, { recursive: true });
  await writeFile(join(staging, file), bytes);
  await sealTree(S, staging, join(storePaths(S).jobs, id, "out"), id, 1);
  await writeFile(join(storePaths(S).jobs, id, "job.json"), JSON.stringify({ id, state: "committed", requester: { agent: "a0" }, status: "ok", exit: 0, spec }));
}

const attest = async (c: { sandboxRoot: string; agentId: string }, input: Record<string, unknown>) => {
  const r = await P.attestEntry(c, input as unknown as P.LedgerActInput);
  assert.ok(r.ok, (r as { reason?: string }).reason);
  assert.ok((r as { line?: unknown }).line, JSON.stringify(r));
  return r as { ok: true; line: P.LedgerAttestation; appended: boolean; note?: string };
};

/** Every area of the disk searched for question 1: a locator is not coverage (docs/adr/0013), and these tests are about the locator. */
const ALL_AREAS = { allocated: "searched", deleted: "searched", unallocated: "searched", slack: "searched", secondary: "not_applicable" } as const;

/** Question 1 answered established on a finding over `ref`, by a1, with the disk it was read from covered where a rival value could live. */
async function established(c: Awaited<ReturnType<typeof run>>, ref: string, value: string) {
  await planned(c.a0, "1");
  ok(await rec(c.a0, coverage("1", ["input:disk.E01"], [ref], { areas: ALL_AREAS })));
  const f = ok(await rec(c.a0, { kind: "finding", ...F, value: `${value} is in the export`, source: "the export", evidence: "its second row", refs: [ref], answers: ["1"] })).entry;
  return ok(await rec(c.a1, { kind: "answer", section: "question:1", value, reasoning: `E-${f.seq}`, ...HIGH, result: "established" })).entry;
}

test("a locator the hub finds at its offset holds an established review; one that is not there records a best candidate that says where the value is, and the seat's review at the right offset is its review", async () => {
  const c = await run();
  const body = Buffer.from("time,user\n09:58,alice\n");
  await sealed(c.S, "j000010", "export.csv", body);
  const at = body.indexOf("alice");
  const ans = await established(c, "job:j000010/export.csv", "alice, at 09:58");
  const review = (offset: number) => ({ ...BARE, discriminator: SOURCE_FIRST.discriminator, reproduced_at: [{ ref: "job:j000010/export.csv", offset, value: "alice" }] });
  // Two bytes off: recorded a best candidate, the reason in capped, and the reply says where it is and how to fix it.
  const off = await attest(c.a2, { seq: ans.seq, how: "read the export's second row", strength: "established", answer_review: review(at + 2) });
  assert.equal(off.line.strength, "best_candidate");
  assert.match(off.line.capped!.join("\n"), new RegExp(`reproduced_at\\[0\\] \\(job:j000010/export\\.csv at ${at + 2}\\) does not verify: the value is not at offset ${at + 2} of job:j000010/export\\.csv in UTF-8 or UTF-16LE: it begins at offset ${at} \\(utf-8\\), 2 bytes before`));
  assert.match(off.note ?? "", /you attested it established, and it is recorded as a best candidate/);
  assert.match(off.note ?? "", new RegExp(P.REVIEW_CAP_FIX.locator_unverified.slice(0, 60).replace(/[.*+?^${}()|[\]\\]/g, "\\$&")));
  assert.match(off.note ?? "", /Attest again with them: your later attest is then your review/);
  assert.equal(P.heldAsBestCandidate(ans, P.answerReviews(ans, await P.readAttestations(c.S))), true, "a best candidate, held so");
  // At the offset: established, and the answer is no longer held.
  const right = await attest(c.a2, { seq: ans.seq, how: "read the export's second row at its offset", strength: "established", answer_review: review(at) });
  assert.equal(right.line.strength, "established");
  assert.equal(right.line.capped, undefined);
  assert.deepEqual(right.line.answer_review?.reproduced_at, [{ ref: "job:j000010/export.csv", offset: at, value: "alice" }], "kept in the chained attestation");
  assert.equal(P.heldAsBestCandidate(ans, P.answerReviews(ans, await P.readAttestations(c.S))), false);
  assert.equal(P.verifyAttestationChain(await (await import("node:fs/promises")).readFile(join(c.S, P.LEDGER_ATTESTATIONS), "utf8")).ok, true);
  assert.match(P.answerReviewWords(right.line.answer_review!), new RegExp(`the strongest rival: .*; read at: job:j000010/export\\.csv byte ${at} \\("alice"\\)`));
  // A value that is at its offset and that neither the answer nor anything it rests on states vouches for nothing: an occurrence of anything is not a locator (the Fable review of the limits branch, P2-2).
  const elsewhere = await attest(c.a3, { seq: ans.seq, how: "read the export's header", strength: "established", answer_review: { ...BARE, discriminator: SOURCE_FIRST.discriminator, reproduced_at: [{ ref: "job:j000010/export.csv", offset: 0, value: "time,user" }] } });
  assert.equal(elsewhere.line.strength, "best_candidate");
  assert.match(elsewhere.line.capped!.join("\n"), /reproduced_at\[0\] \(job:j000010\/export\.csv at 0\) does not verify: the value "time,user" is not among the words of the answer \(its value and reasoning\) nor of any entry it rests on \(its support, and what those cite\): a locator vouches for a value the answer or its chain states\. A value given there in another form \(a converted time, a decoded field\) is vouched for by derivation \{job, inputs\}/);
  const short = await P.checkLocator(c.S, { ref: "job:j000010/export.csv", offset: at, value: "al" }, "alice, at 09:58");
  assert.match((short as { why: string }).why, /is under 3 characters: too short to vouch for what the answer rests on/);
});

test("a locator vouches for a supporting observation: a value a cited finding states verifies, though the answer's own words do not state it; one nothing in the chain states does not", async () => {
  const c = await run();
  const body = Buffer.from("user=alice host=ws-17 tty=pts/3\n");
  await sealed(c.S, "j000012", "auth.log", body);
  await planned(c.a0, "1");
  ok(await rec(c.a0, coverage("1", ["input:disk.E01"], ["job:j000012/auth.log"], { areas: ALL_AREAS })));
  // The finding says where the logon came from; the answer names only the account.
  const f = ok(await rec(c.a0, { kind: "finding", ...F, value: "alice logged on from ws-17", source: "the auth log", evidence: "its first line", refs: ["job:j000012/auth.log"], answers: ["1"] })).entry;
  const ans = ok(await rec(c.a1, { kind: "answer", section: "question:1", value: "alice", reasoning: `E-${f.seq}`, ...HIGH, result: "established" })).entry;
  const review = (offset: number, value: string) => ({ ...BARE, discriminator: SOURCE_FIRST.discriminator, reproduced_at: [{ ref: "job:j000012/auth.log", offset, value }] });
  const chained = await attest(c.a2, { seq: ans.seq, how: "read the auth log's first line", strength: "established", answer_review: review(body.indexOf("ws-17"), "ws-17") });
  assert.equal(chained.line.strength, "established", chained.note);
  assert.equal(chained.line.capped, undefined);
  const nowhere = await attest(c.a3, { seq: ans.seq, how: "read the auth log's first line", strength: "established", answer_review: review(body.indexOf("pts/3"), "pts/3") });
  assert.equal(nowhere.line.strength, "best_candidate");
  assert.match(nowhere.line.capped!.join("\n"), /the value "pts\/3" is not among the words of the answer \(its value and reasoning\) nor of any entry it rests on/);
  // Read back by length: the same words.
  const byLength = await P.checkLocator(c.S, { ref: "job:j000012/auth.log", offset: body.indexOf("ws-17"), length: 5 }, "alice", P.chainWords(ans, await P.readLedger(c.S)));
  assert.equal(byLength.ok, true, JSON.stringify(byLength));
});

test("a value in UTF-16LE is found at its offset, in either case, and a length alone is read back and found in the answer's words", async () => {
  const c = await run();
  const body = Buffer.concat([Buffer.from([0x4d, 0x5a, 0x90, 0x00]), Buffer.from("Bob-Laptop", "utf16le"), Buffer.from([0, 0])]);
  await sealed(c.S, "j000011", "strings.bin", body);
  const ans = await established(c, "job:j000011/strings.bin", "bob-laptop");
  const direct = await P.checkLocator(c.S, { ref: "job:j000011/strings.bin", offset: 4, value: "BOB-LAPTOP" }, "bob-laptop");
  assert.deepEqual(direct, { ok: true, ref: "job:j000011/strings.bin", offset: 4, encoding: "utf-16le" });
  const byLength = await P.checkLocator(c.S, { ref: "job:j000011/strings.bin", offset: 4, length: 20 }, "the host is bob-laptop");
  assert.equal(byLength.ok, true, JSON.stringify(byLength));
  assert.equal((byLength as { encoding: string }).encoding, "utf-16le");
  const notSaid = await P.checkLocator(c.S, { ref: "job:j000011/strings.bin", offset: 4, length: 20 }, "another host");
  assert.equal(notSaid.ok, false);
  assert.match((notSaid as { why: string }).why, /read as utf-16le text neither the answer nor an entry it rests on states: give value/);
  const r = await attest(c.a2, { seq: ans.seq, how: "read the strings of the binary", strength: "established", answer_review: { ...BARE, discriminator: SOURCE_FIRST.discriminator, reproduced_at: [{ ref: "job:j000011/strings.bin", offset: 4, value: "bob-laptop" }] } });
  assert.equal(r.line.strength, "established", r.note);
  // A locator into nothing the run sealed is refused by nothing and verifies nothing.
  const gone = await P.checkLocator(c.S, { ref: "job:j000099/x.txt", offset: 0, value: "x" }, "x");
  assert.match((gone as { why: string }).why, /job:j000099\/x\.txt does not resolve to a sealed object of this run/);
  const dir = await P.checkLocator(c.S, { ref: "job:j000011", offset: 0, value: "x" }, "x");
  assert.match((dir as { why: string }).why, /is a directory: a locator names one file in it/);
});

test("a derived value is vouched for by its derivation: a job that ran to its end over what it declared; one over an undeclared object, or a failed job, records a best candidate", async () => {
  const c = await run();
  const ans = await established(c, "job:j000001/hits.txt", "12:44:22 UTC, converted from the local time");
  const review = (derivation: Record<string, unknown>) => ({ ...BARE, discriminator: SOURCE_FIRST.discriminator, derivation });
  const undeclared = await attest(c.a2, { seq: ans.seq, how: "converted the local time", strength: "established", answer_review: review({ job: "j000001", inputs: ["input:logs/a.log"] }) });
  assert.equal(undeclared.line.strength, "best_candidate");
  assert.match(undeclared.line.capped!.join("\n"), /the derivation does not resolve: job j000001 did not declare input:logs\/a\.log among what it reads \(it declared input:disk\.E01\)/);
  const failed = await attest(c.a3, { seq: ans.seq, how: "converted the local time", strength: "established", answer_review: review({ job: "job:j000004", inputs: ["input:disk.E01"] }) });
  assert.match(failed.line.capped!.join("\n"), /job j000004 ended failed: a derivation is a job that ran to its end/);
  const good = await attest(c.a2, { seq: ans.seq, how: "converted the local time with job j000001", strength: "established", answer_review: review({ job: "j000001", inputs: ["input:disk.E01"] }) });
  assert.equal(good.line.strength, "established", good.note);
  assert.deepEqual(good.line.answer_review?.derivation, { job: "j000001", inputs: ["input:disk.E01"] });
});

test("an established review with no discriminator, or one that says nothing, is recorded a best candidate with each reason and how to fix it; one with neither a locator nor a derivation is warned, never capped; its refs must be in the run", async () => {
  const c = await run();
  const ans = await established(c, "job:j000001/hits.txt", "alice");
  const none = await attest(c.a2, { seq: ans.seq, how: "read the row", strength: "established", answer_review: BARE });
  assert.equal(none.line.strength, "best_candidate");
  assert.equal(none.line.capped!.length, 1, none.line.capped!.join("\n"));
  assert.match(none.line.capped![0]!, /^the review names no discriminator: the strongest rival and a test that separates it from the answer/);
  assert.ok(none.note?.includes(P.REVIEW_CAP_FIX.no_discriminator), none.note);
  assert.ok(none.note?.includes(`Warned, not capped: the review vouches for no value by bytes or by derivation`), none.note);
  assert.ok(none.note?.includes(P.REVIEW_UNLOCATED_FIX), none.note);
  assert.match(none.note ?? "", /Until then question:1 is not established by it, and the finish line says so/);
  // A discriminator and neither a locator nor a derivation (an inference over several entries): recorded established, and warned where the decision is made (the Fable review of the limits branch, P2-3).
  const unlocated = await attest(c.a0, { seq: ans.seq, how: "weighed the rows against the rival", strength: "established", answer_review: { ...BARE, discriminator: SOURCE_FIRST.discriminator } });
  assert.equal(unlocated.line.strength, "established", unlocated.note);
  assert.equal(unlocated.line.capped, undefined);
  assert.deepEqual((unlocated as { warned?: string[] }).warned, ["no_locator_or_derivation"]);
  const checked = await checkLedgerAnswers(c.S, ["1"]);
  assert.equal(checked.dispositions["question:1"], "established", checked.lines.join("\n"));
  const w = checked.warnings.filter((x) => /is held established by a0 on a review that vouches for no value by bytes or by derivation/.test(x));
  assert.equal(w.length, 1, checked.warnings.join("\n"));
  assert.ok(w[0]!.includes(P.REVIEW_UNLOCATED_FIX), w[0]);
  // A placeholder is none.
  const filler = await attest(c.a3, { seq: ans.seq, how: "read the row", strength: "established", answer_review: { ...BARE, discriminator: { rival: "none", test: "n/a", favours_if: "n/a", outcome: "none", refs: ["job:j000001/hits.txt"] }, derivation: SOURCE_FIRST.derivation } });
  assert.equal(filler.line.strength, "best_candidate");
  assert.match(filler.line.capped!.join("\n"), /the review's discriminator says nothing a reader can weigh/);
  // Its refs: an entry the ledger holds, an object the run holds.
  refused(await P.attestEntry(c.a2, { seq: ans.seq, how: "x", strength: "established", answer_review: { ...BARE, discriminator: { ...SOURCE_FIRST.discriminator, refs: ["E-999"] }, derivation: SOURCE_FIRST.derivation } } as unknown as P.LedgerActInput), /answer_review\.discriminator\.refs names E-999: there is no entry #999 in the ledger/);
  refused(await P.attestEntry(c.a2, { seq: ans.seq, how: "x", strength: "established", answer_review: { ...BARE, discriminator: { ...SOURCE_FIRST.discriminator, refs: ["job:j000001/hit.txt"] }, derivation: SOURCE_FIRST.derivation } } as unknown as P.LedgerActInput), /answer_review\.discriminator\.refs: ref "job:j000001\/hit\.txt" does not resolve.*nearest: job:j000001\/hits\.txt/);
  refused(await P.attestEntry(c.a2, { seq: ans.seq, how: "x", strength: "established", answer_review: { ...BARE, discriminator: { ...SOURCE_FIRST.discriminator, refs: [] } } } as unknown as P.LedgerActInput), /answer_review\.discriminator\.refs names the observation or the job the outcome rests on, at least one/);
  // Never the answer itself, nor only the entries it cites: the test rests on what it read or showed (the Fable review of the limits branch, P3-7).
  refused(await P.attestEntry(c.a2, { seq: ans.seq, how: "x", strength: "established", answer_review: { ...BARE, discriminator: { ...SOURCE_FIRST.discriminator, refs: [`E-${ans.seq}`] }, derivation: SOURCE_FIRST.derivation } } as unknown as P.LedgerActInput), new RegExp(`answer_review\\.discriminator\\.refs names E-${ans.seq}, the answer under review: a discriminator rests on an observation or a job, not the answer`));
  const own = (ans.support ?? []).map((x) => `E-${x.seq}`);
  refused(await P.attestEntry(c.a2, { seq: ans.seq, how: "x", strength: "established", answer_review: { ...BARE, discriminator: { ...SOURCE_FIRST.discriminator, refs: own }, derivation: SOURCE_FIRST.derivation } } as unknown as P.LedgerActInput), new RegExp(`answer_review\\.discriminator\\.refs names only ${own.join(", ")}, which #${ans.seq} cites already`));
  assert.ok((await P.attestEntry(c.a2, { seq: ans.seq, how: "x", strength: "best_candidate", answer_review: { ...BARE, discriminator: { ...SOURCE_FIRST.discriminator, refs: [...own, "job:j000001/hits.txt"] } } } as unknown as P.LedgerActInput)).ok, "what the answer cites beside the job the test read is its own observation");
  refused(await P.attestEntry(c.a2, { seq: ans.seq, how: "x", strength: "established", answer_review: { ...BARE, reproduced_at: [{ ref: "job:j000001/hits.txt", offset: 0 }] } } as unknown as P.LedgerActInput), /reproduced_at\[0\] names the value it vouches for \(value, as it is in the object\) or how many bytes hold it/);
  refused(await P.attestEntry(c.a2, { seq: ans.seq, how: "x", strength: "established", answer_review: { ...BARE, reproduced_at: [{ ref: "job:j000001/hits.txt", offset: -1, value: "x" }] } } as unknown as P.LedgerActInput), /reproduced_at\[0\]\.offset is the byte offset/);
  refused(await P.attestEntry(c.a2, { seq: ans.seq, how: "x", strength: "established", answer_review: { ...BARE, derivation: { job: "a shell", inputs: ["input:disk.E01"] } } } as unknown as P.LedgerActInput), /answer_review\.derivation\.job names a job, j<id> or job:<id>/);
  // The full review stands.
  const full = await attest(c.a2, { seq: ans.seq, how: "read the row", strength: "established", answer_review: { ...BARE, ...SOURCE_FIRST } });
  assert.equal(full.line.strength, "established", full.note);
});

test("the rule is an established claim's on a material question: a best candidate review, a partial answer's review and a question not material are not capped for it, and a partial answer's locator that does not verify is said", async () => {
  const c = await run();
  const ans = await established(c, "job:j000001/hits.txt", "alice");
  const bc = await attest(c.a2, { seq: ans.seq, how: "read the row", strength: "best_candidate", answer_review: BARE });
  assert.equal(bc.line.capped, undefined, "a best candidate asked for is not capped again");
  const rule = await P.reviewEvidenceCaps(c.S, ans, BARE as unknown as P.AnswerReview, { material: false });
  assert.deepEqual(rule.caps, [], "not material: nothing capped");
  // A partial answer: its parts as ever; a locator that misses is said, and nothing is capped for it.
  await planned(c.a0, "3");
  const f = ok(await rec(c.a0, { kind: "finding", ...F, value: "a file was deleted at 09:14", source: "the log", evidence: "line 1", refs: ["job:j000001/hits.txt"], answers: ["3"] })).entry;
  const lim = ok(await rec(c.a0, { kind: "limitation", value: "The log keeps no file name", source: "the log", evidence: "its fields", reason: "unavailable", answers: ["3"] })).entry;
  const part = ok(await rec(c.a1, { kind: "answer", section: "question:3", value: "A file, deleted at 09:14; its name is not established", reasoning: `E-${f.seq} (job j000001's hits); the name is open (E-${lim.seq})`, ...A, limitations: [lim.seq], result: "partial", parts: [{ id: "when", part: "when it was deleted", status: "established", refs: [`E-${f.seq}`] }, { id: "which", part: "which file", status: "open", open_by: `E-${lim.seq}` }] })).entry;
  const pr = await attest(c.a3, { seq: part.seq, how: "read line 1", strength: "established", answer_review: { ...BARE, parts: [{ part: "when", established: true, why: "line 1" }, { part: "which file", established: false, why: "no name kept", declared_open: `E-${lim.seq}` }], reproduced_at: [{ ref: "job:j000001/hits.txt", offset: 3, value: "j000001" }] } });
  assert.equal(pr.line.strength, "established", "partial is a disposition: nothing capped");
  assert.equal(pr.line.capped, undefined);
  assert.match(pr.note ?? "", /Not verified \(said: it caps only an established review of an answer that claims established\): job:j000001\/hits\.txt at 3: the value is not at offset 3/);
});

test("what a cap costs is measured: an answer that claimed established, recorded partial after a capped attest of it, is counted in the metrics with the seats that capped it", async () => {
  const c = await run();
  const ans = await established(c, "job:j000001/hits.txt", "alice");
  const capped = await attest(c.a2, { seq: ans.seq, how: "read the row", strength: "established", answer_review: BARE });
  assert.equal(capped.line.strength, "best_candidate");
  const lim = ok(await rec(c.a0, { kind: "limitation", value: "The export keeps no second source for the account", source: "the export", evidence: "its fields", reason: "unavailable", answers: ["1"] })).entry;
  const f = (ans.support ?? [])[0]!.seq;
  ok(await rec(c.a1, { kind: "answer", section: "question:1", value: "alice; the account's owner is not established", reasoning: `E-${f}; the owner is open (E-${lim.seq})`, ...A, limitations: [lim.seq], result: "partial", parts: [{ id: "who", part: "which account", status: "established", refs: [`E-${f}`] }, { id: "owner", part: "whose account", status: "open", open_by: `E-${lim.seq}` }], supersedes: ans.seq }));
  const m = await measureRun(c.S);
  assert.deepEqual(m.reversals.partial_after_cap, [{ section: "1", from: `E-${ans.seq}`, to: `E-${ans.seq + 2}`, capped_by: ["a2"] }]);
  assert.match(metricsText(m), /1 established answer\(s\) recorded partial after a capped attest \(question:1 E-\d+ to E-\d+, capped by a2\)/);
});

test("the review offer leads with the question, its scope and its original sources, the answer linked by its seq and never quoted; it goes first to a seat of another model family, a preference only", async () => {
  const c = await run();
  await planned(c.a0, "2");
  const abs = ok(await rec(c.a0, { kind: "absence", value: "a remote tool", source: "inputs/disk.E01", evidence: "a search", refs: ["job:j000001/hits.txt"], control: { ref: "job:j000001/hits.txt", found: "the same search finds a planted row" }, answers: ["2"] })).entry;
  const cov = ok(await rec(c.a0, coverage("2", ["job:j000001"], [`E-${abs.seq}`, "job:j000001/hits.txt"]))).entry;
  const ans = ok(await rec(c.a1, { kind: "answer", section: "question:2", value: "No evidence of a remote tool was found on the disk", reasoning: `E-${cov.seq}`, ...A, result: "bounded_negative" })).entry;
  // a2 has worked the question (the most relevant by the old order); a3 is of another model family than a0 and a1.
  ok(await rec(c.a2, { kind: "finding", ...F, value: "the disk holds a user profile", source: "the disk", evidence: "a listing", refs: ["job:j000001/hits.txt"], answers: ["2"] }));
  const team = await P.readTeam(c.S);
  const models: Record<string, string> = { a0: "openai-codex/gpt-6-sol", a1: "openai-codex/gpt-6-sol-latest", a2: "openai-codex/gpt-6-sol", a3: "anthropic/claude-opus-5-5" };
  await writeFile(join(c.S, "team.json"), `${JSON.stringify({ ...team, agents: team.agents.map((a) => ({ ...a, model: models[a.id] })) }, null, 2)}\n`);
  assert.equal(L.modelFamily("openai-codex/gpt-6-sol-latest"), L.modelFamily("gpt-6-sol"), "a route and a release tag are not a family");
  assert.equal(await L.offerReviews(c.S), 1);
  const snap = await L.leadsSnapshot(c.S);
  const offer = O.reservingOffer(snap.state.reviewOffers.get(`E-${ans.seq}`) ?? [], Date.now(), 1)!;
  assert.equal(offer.to, "a3", "another model family first");
  const packet = await L.reviewPacketWords(c.S, snap, ans.seq);
  assert.match(String(packet), /^Review it source-first\. The question: Q-2, revision 1: "Was a remote tool installed\?"\. Its scope: a material question; it asks whether something exists\. The original sources its answer's coverage and cited entries lead back to: input:disk\.E01\. Read the question against those sources before the answer under review/);
  assert.match(String(packet), new RegExp(`The answer under review is linked, not quoted: E-${ans.seq} in ledger/ledger\\.md; its coverage E-${cov.seq}\\.$`));
  const text = L.reviewOfferText(`E-${ans.seq}`, offer, snap, [], null, packet);
  assert.ok(text.startsWith(String(packet)), "the question and the sources come first");
  assert.ok(!text.includes(ans.value), "the answer's words are not in the offer");
  // Delivered so: the seat's header leads with it.
  const digest = await L.leadsDigest(c.a3);
  const notice = digest.notices.find((n) => n.kind === "review_offer");
  assert.ok(notice?.text.startsWith("Review it source-first. The question: Q-2"), notice?.text);
  // One family: offered as before, by relevance.
  const d = await run();
  await planned(d.a0, "2");
  const abs2 = ok(await rec(d.a0, { kind: "absence", value: "a remote tool", source: "inputs/disk.E01", evidence: "a search", refs: ["job:j000001/hits.txt"], control: { ref: "job:j000001/hits.txt", found: "the same search finds a planted row" }, answers: ["2"] })).entry;
  const cov2 = ok(await rec(d.a0, coverage("2", ["input:disk.E01"], [`E-${abs2.seq}`, "job:j000001/hits.txt"]))).entry;
  const ans2 = ok(await rec(d.a1, { kind: "answer", section: "question:2", value: "No evidence of a remote tool was found on the disk", reasoning: `E-${cov2.seq}`, ...A, result: "bounded_negative" })).entry;
  ok(await rec(d.a3, { kind: "finding", ...F, value: "the disk holds a user profile", source: "the disk", evidence: "a listing", refs: ["job:j000001/hits.txt"], answers: ["2"] }));
  assert.equal(await L.offerReviews(d.S), 1);
  const o2 = O.reservingOffer((await L.leadsSnapshot(d.S)).state.reviewOffers.get(`E-${ans2.seq}`) ?? [], Date.now(), 1)!;
  assert.equal(o2.to, "a3", "no models known: the most relevant, as before");
  await attest(d.a3, { seq: cov2.seq, how: "ran the search again", review: REVIEW });
});
