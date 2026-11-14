/**
 * `record` and `attest` check the whole entry and answer once (the review of
 * the Batman III runs, S-01): on the run sf4406b the open-weight seats had
 * 353 of 776 `record` calls refused, one rule a refusal, and one coverage
 * record took eight refusals in 190 s (seat 05, session lines 784-800). Here:
 * every defect comes back in one refusal, each with what to send; what was
 * plainly meant is taken and said; a missing or misspelt field is answered by
 * the tool's own check and never by an echo of the call.
 */
import assert from "node:assert/strict";
import { test } from "node:test";
import { Type } from "typebox";
import * as P from "../extensions/protocol.ts";
import { A, ESTABLISHED, F, coverage, covers, ok, planned, rec, refused, run } from "./negative-bar-fixture.ts";

type Refusal = { ok: false; reason: string; defects?: string[] };
const no = (r: { ok: boolean }): Refusal => {
  assert.equal(r.ok, false, "expected a refusal");
  return r as Refusal;
};

test("every defect of an entry is named in one refusal, with what to send, and the corrected call is taken", async () => {
  const c = await run();
  // A finding short of four required fields, with a ref that does not resolve, a ref that names an entry, a field of another kind and a link to nothing.
  const r = no(await rec(c.a0, { kind: "finding", value: "alice logged on at 09:14", source: "the log", evidence: "line 12", refs: ["job:j000001/hitz.txt", "E-3"], section: "question:1", rel: [{ to: 99, kind: "supports" }] }));
  assert.match(r.reason, /^8 things to fix, every one named here, so one more call is enough \(fix them all, then record once\)\. A finding also needs basis, confidence, indicates, confidence_why\./);
  assert.equal(r.defects?.length, 8, r.reason);
  for (const must of [
    /ref "job:j000001\/hitz\.txt" does not resolve: hitz\.txt is not in job j000001's manifest; nearest: job:j000001\/hits\.txt/,
    /ref "E-3" names a ledger entry, and refs takes the run's objects .*link the entry with rel \[\{to: 3, kind: "supports"/,
    /section is an answer's: record kind=answer with its section to answer a question/,
    /a finding says whether it was seen in the evidence or reasoned from it: basis observed or inferred/,
    /a finding says how sure: confidence high, medium or low/,
    /indicates is required on a finding/,
    /confidence_why is required on a finding/,
    /rel names #99: there is no entry #99 in the ledger/,
  ]) assert.match(r.reason, must);
  // What a ref is, is said once however many refs are wrong.
  assert.equal(r.reason.split("A ref names an object of this run").length - 1, 1);
  // The corrected call: every defect fixed, one more call.
  const fixed = ok(await rec(c.a0, { kind: "finding", ...F, value: "alice logged on at 09:14", source: "the log", evidence: "line 12", refs: ["job:j000001/hits.txt"], answers: ["1"] }));
  assert.equal(fixed.entry.seq, 1);
  // One defect is still said as it always was: no count, no list.
  assert.equal(no(await rec(c.a0, { kind: "finding", ...F, value: "x", source: "s", evidence: "e", status: "open" })).reason, "status is a hypothesis's: open, supported or refuted");
});

test("the coverage record that took eight refusals on the run sf4406b takes two calls: the kind is taken from its fields and every other defect is named at once", async () => {
  const c = await run();
  await planned(c.a0, "2");
  const absence = ok(await rec(c.a0, { kind: "absence", value: "a remote tool", source: "inputs/disk.E01", evidence: "a search", refs: ["job:j000001/hits.txt"], control: { ref: "job:j000001/hits.txt", found: "the same search finds a planted row" }, answers: ["2"] })).entry;
  const first = ok(await rec(c.a0, coverage("2", ["input:disk.E01"], [`E-${absence.seq}`, "job:j000001/hits.txt"]))).entry;
  const cov = ok(await rec(c.a0, coverage("2", ["input:disk.E01"], [`E-${absence.seq}`, "job:j000001/hits.txt"], { supersedes: first.seq, settings: "the same query, case-insensitive" }))).entry;
  const answer = ok(await rec(c.a1, { kind: "answer", section: "question:2", value: "No evidence of a remote tool was found on the disk", reasoning: `E-${cov.seq} over E-${absence.seq}`, ...A, result: "bounded_negative" })).entry;
  // As the seat sent it: no kind, time_range, failures and alternatives left out, the answer and a superseded record among its results.
  const { kind: _kind, time_range: _t, failures: _f, alternatives: _a, ...sent } = coverage("2", ["input:disk.E01"], [`E-${answer.seq}`, `E-${first.seq}`, `E-${absence.seq}`], { supersedes: cov.seq }) as Record<string, unknown>;
  const r = no(await rec(c.a0, sent));
  assert.equal(r.defects?.length, 3, r.reason);
  assert.match(r.reason, /^3 things to fix, every one named here.* A coverage record also needs time_range, failures, alternatives\./);
  assert.match(r.reason, /time_range is required on a coverage record/);
  assert.match(r.reason, /failures is required on a coverage record \("none" when nothing was, with how that is known\)/);
  assert.match(r.reason, /alternatives is required: the explanations or routes still open, or none and why/);
  // What the seat met in three more calls is taken and said: an answer and a corrected coverage record among the results are left out, the absence stays.
  assert.match(r.reason, /Taken as meant, nothing to change there: kind was left out: taken as coverage, the one kind these fields allow/);
  assert.match(r.reason, new RegExp(`result_refs E-${answer.seq} is an answer, which no search produces: left out; result_refs E-${first.seq}, now E-${cov.seq}, is a coverage record, which no search produces: left out`));
  // The second call, with what the refusal named and nothing else changed: recorded.
  const again = ok(await rec(c.a0, { ...sent, time_range: "2026-01-01 to 2026-01-31", failures: "none: the job exited 0", alternatives: "none still open" }));
  assert.deepEqual(again.entry.result_refs, [`E-${absence.seq}`]);
  assert.equal(again.entry.kind, "coverage");
  assert.match(again.note ?? "", /kind was left out: taken as coverage/);
  // A record whose every result is an answer is told what a result is, and what the answer itself rests on.
  const only = no(await rec(c.a0, coverage("2", ["input:disk.E01"], [`E-${answer.seq}`], { supersedes: again.entry.seq })));
  assert.match(only.reason, new RegExp(`result_refs names E-${answer.seq}, a answer: a search's results are what it found or failed to \\(absences, limitations, findings, events\\); leave E-${answer.seq} out`));
  // A result that was corrected is the entry that stands.
  const absence2 = ok(await rec(c.a0, { kind: "absence", value: "a remote tool or its service", source: "inputs/disk.E01", evidence: "a search", refs: ["job:j000001/hits.txt"], control: { ref: "job:j000001/hits.txt", found: "the same search finds a planted row" }, answers: ["2"], supersedes: absence.seq })).entry;
  const carried = ok(await rec(c.a0, coverage("2", ["input:disk.E01"], [`E-${absence.seq}`], { supersedes: again.entry.seq })));
  assert.deepEqual(carried.entry.result_refs, [`E-${absence2.seq}`]);
  assert.match(carried.note ?? "", new RegExp(`result_refs E-${absence.seq} was corrected by #${absence2.seq}: taken as E-${absence2.seq}, the entry that stands`));
});

test("what is plainly meant is taken and said: a ref as the shell shows it, a section id in the seats' spellings, the one kind the fields allow, a second answer from the seat whose answer stands", async () => {
  const c = await run();
  await planned(c.a0, "1");
  // No kind: indicates is a finding's and no other kind's.
  const f = ok(await rec(c.a0, { ...F, value: "alice logged on at 09:14", source: "the log", evidence: "line 12", refs: ["job:j000001/out/hits.txt", "store/jobs/j000002/out/hits.txt", "inputs/disk.E01"], answers: ["question:1"] }));
  assert.equal(f.entry.kind, "finding");
  assert.deepEqual(f.entry.refs, ["job:j000001/hits.txt", "job:j000002/hits.txt", "input:disk.E01"]);
  assert.deepEqual(f.entry.answers, ["1"]);
  for (const must of [/kind was left out: taken as finding, the one kind these fields allow/, /ref "job:j000001\/out\/hits\.txt" taken as job:j000001\/hits\.txt: a ref has no out\/ and no store path/, /ref "store\/jobs\/j000002\/out\/hits\.txt" taken as job:j000002\/hits\.txt/, /ref "inputs\/disk\.E01" taken as input:disk\.E01/, /answers "question:1" taken as "1": answers takes the id alone/]) assert.match(f.note ?? "", must);
  // A limitation by its reason, an absence by its completion.
  assert.equal(ok(await rec(c.a0, { value: "The second volume was not opened", source: "the disk", evidence: "no key", reason: "unavailable" })).entry.kind, "limitation");
  assert.deepEqual(P.kindsFitting({ value: "v", source: "s", evidence: "e", completion: "partial" }), ["absence"]);
  assert.deepEqual(P.kindsFitting({ section: "question:1", value: "v", reasoning: "E-1", result: "established" }), ["answer"]);
  assert.deepEqual(P.kindsFitting({ value: "v", refs: ["input:x"], answers: ["1"], time_range: "t", result_refs: ["E-1"] }), ["coverage"]);
  // Several kinds fit: asked, with the kinds that do, and the rest of the entry checked all the same.
  const asked = no(await rec(c.a0, { value: "a second logon", source: "the log", refs: ["job:j000001/nope.txt"] }));
  assert.match(asked.reason, /kind is required: one of event, ioc, finding, absence, hypothesis, limitation, answer, coverage\. The fields sent fit ioc, finding, absence, hypothesis, limitation: say which\. The rest was checked as a finding/);
  assert.match(asked.reason, /evidence is required/);
  assert.match(asked.reason, /ref "job:j000001\/nope\.txt" does not resolve/);
  // The same seat answers a question it has answered: the revision of its answer, said.
  const a1 = ok(await rec(c.a1, { kind: "answer", section: "question:1", value: "alice", reasoning: `E-${f.entry.seq}`, ...A, result: "established" })).entry;
  const a2 = ok(await rec(c.a1, { kind: "answer", section: "question:1", value: "alice, at 09:14", reasoning: `E-${f.entry.seq}`, ...A, result: "established", answers: ["1"] }));
  assert.equal(a2.entry.supersedes, a1.seq);
  assert.match(a2.note ?? "", new RegExp(`question:1 is answered by your #${a1.seq} already: taken as its revision \\(supersedes=${a1.seq}\\)`));
  assert.match(a2.note ?? "", /answers is left out: on an answer the section names the question \(question:1\)/);
  // The same words again are the answer that stands, as they always were.
  const same = ok(await rec(c.a1, { kind: "answer", section: "question:1", value: "alice, at 09:14", reasoning: `E-${f.entry.seq}`, ...A, result: "established" }));
  assert.equal(same.merged, true);
  assert.equal(same.entry.seq, a2.entry.seq);
  // A correction that names an entry corrected already is the correction of the entry that stands at the end of that chain.
  const i1 = ok(await rec(c.a0, { kind: "ioc", value: "203.0.113.9", source: "the proxy log", evidence: "line 4" })).entry;
  const i2 = ok(await rec(c.a0, { kind: "ioc", value: "203.0.113.10", source: "the proxy log", evidence: "line 4", supersedes: i1.seq })).entry;
  const i3 = ok(await rec(c.a0, { kind: "ioc", value: "203.0.113.11", source: "the proxy log", evidence: "line 4, read again", supersedes: `E-${i1.seq}` }));
  assert.equal(i3.entry.supersedes, i2.seq);
  assert.match(i3.note ?? "", new RegExp(`#${i1.seq} is already superseded: taken as the correction of #${i2.seq}, the entry that stands at the end of its corrections`));
  // Another seat's second answer is not taken for a revision: it is told which answer stands.
  refused(await rec(c.a2, { kind: "answer", section: "question:1", value: "bob", reasoning: `E-${f.entry.seq}`, ...A, result: "established" }), new RegExp(`question:1 is answered by #${a2.entry.seq} already: one answer stands for a section; to revise it, record this with supersedes=${a2.entry.seq}`));
});

test("a failed job's output: the refusal writes the qualifies to send, a why given for the job is the why of its refs, and one that qualifies nothing is left out", async () => {
  const c = await run();
  const base = { kind: "finding", ...F, value: "the listing names the tool", source: "the listing", evidence: "row 9", refs: ["job:j000004/hits.txt", "job:j000001/hits.txt"] };
  const r = no(await rec(c.a0, base));
  assert.match(r.reason, /this finding rests on the kept output of a job that did not succeed \(job:j000004\/hits\.txt: failed\): say in qualifies \[\{ref, why\}\] why those bytes are still usable, or cite the output of a job that worked\. To keep it, add qualifies: \[\{ref: "job:j000004\/hits\.txt", why: "<why its bytes are still usable>"\}\] \(a row that names a job, job:<id>, covers every ref of the entry from it\)/);
  // The job, in either spelling: the why of the entry's ref from it.
  for (const ref of ["job:j000004", "j000004", "job:j000004/out/hits.txt", "job:j000004/another-file.txt"]) {
    const q = ok(await rec(c.a0, { ...base, value: `the listing names the tool (${ref})`, qualifies: [{ ref, why: "the rows were written before the job failed" }] }));
    assert.deepEqual(q.entry.qualifies, [{ ref: "job:j000004/hits.txt", why: "the rows were written before the job failed" }], ref);
  }
  // Something that is no job of the entry's: named, with the ref to use.
  refused(await rec(c.a0, { ...base, qualifies: [{ ref: "input:disk.E01", why: "w" }] }), /qualifies names "input:disk\.E01", which is not one of the entry's refs: use exactly job:j000004\/hits\.txt, as refs has it/);
  // A why on a ref whose job succeeded, or on a job the entry does not cite, qualifies nothing and is left out; what does need one is still named.
  const left = no(await rec(c.a0, { ...base, qualifies: [{ ref: "job:j000001/hits.txt", why: "w" }, { ref: "job:j000002", why: "w" }] }));
  assert.match(left.reason, /^this finding rests on the kept output of a job that did not succeed/);
  assert.match(left.reason, /Taken as meant, nothing to change there: qualifies on job:j000001\/hits\.txt is left out: its job succeeded, and qualifies is only for the output of a job that did not; qualifies on job:j000002 is left out: no ref of the entry from a job that failed is from that job/);
  // A ref that does not resolve hides its job's status: said with it, so the corrected call carries the qualifies too.
  refused(await rec(c.a0, { ...base, refs: ["job:j000004/hitz.txt"] }), /ref "job:j000004\/hitz\.txt" does not resolve.*job j000004 did not succeed \(failed\): once its ref is right, the finding also says why those bytes are still usable, qualifies: \[\{ref: "job:j000004", why:/);
});

test("the fields of a fact on an answer: all of them named, with the two calls to make, in order", async () => {
  const c = await run();
  await planned(c.a0, "1");
  const r = no(await rec(c.a1, { kind: "answer", section: "question:1", value: "alice", reasoning: "the log shows it", ...A, result: "established", refs: ["job:j000001/hits.txt"], basis: "observed", indicates: "alice was at the console", answers: ["2"] }));
  assert.match(r.reason, /refs, answers, basis, indicates are not an answer's: an answer rests on ledger entries it cites as E-<seq>; record the fact itself as a finding, an event or an indicator first\. Two calls, in this order: \(1\) record_finding \(record with kind=finding\) with the fact and those fields, and answers: \["1"\]; its reply gives the entry's seq, E-<n>\. \(2\) this answer again without refs, answers, basis, indicates, citing E-<n> in reasoning\. If the fact is on the ledger already, send only the second call, citing its E-<seq>/);
  // The same refusal names what the ledger shows too: the answer cites nothing that stands for its question.
  assert.match(r.reason, /an answer to question:1 rests on at least one standing finding, search, limitation or coverage record recorded with answers=\["1"\] and cited as E-<seq> \(the answer cites no standing entry\); none is on the ledger yet: record it first \(record_finding with answers: \["1"\]\), then this answer citing it/);
  // The two calls, as it says.
  const f = ok(await rec(c.a0, { kind: "finding", ...F, value: "alice logged on at 09:14", source: "the log", evidence: "line 12", refs: ["job:j000001/hits.txt"], answers: ["1"] })).entry;
  ok(await rec(c.a1, { kind: "answer", section: "question:1", value: "alice", reasoning: `E-${f.seq} shows it`, ...A, result: "established" }));
});

test("attest names every defect of a review at once, takes the entry that stands when its correction concludes the same, and weighs a part without the id an answer with no parts cannot hold", async () => {
  const c = await run();
  await planned(c.a0, "1");
  const f = ok(await rec(c.a0, { kind: "finding", ...F, value: "alice logged on at 09:14", source: "the log", evidence: "line 12", refs: ["job:j000001/hits.txt"], answers: ["1"] })).entry;
  await covers(c.a0, "1");
  const a = ok(await rec(c.a1, { kind: "answer", section: "question:1", value: "alice", reasoning: `E-${f.seq}`, ...A, confidence: "high", result: "established" })).entry;
  // A review short of five fields, with an object where an entry is asked: one refusal.
  const r = await P.attestEntry(c.a2, { seq: a.seq, how: "", strength: "sure", answer_review: { reproduced: "re-read line 12", alternatives: [{ explanation: "bob at the same console", why: "bob had logged off", evidence: ["job:j000001/hits.txt"] }] } });
  assert.equal(r.ok, false);
  const reason = (r as { reason: string }).reason;
  assert.match(reason, /^\d+ things to fix, every one named here/);
  for (const must of [/how is required/, /strength is established or best_candidate \(got "sure"\)/, /answer_review\.read is required/, /answer_review\.link is required: what ties the artefact the answer cites to what the question asks, apart from the value re-deriving/, /answer_review\.inference is required/, /answer_review\.parts names each part the question asks/, /answer_review\.other_family is \{checked: true\|false, text\}/, /answer_review\.alternatives\[\]\.evidence names entries as E-<seq> \(got "job:j000001\/hits\.txt"\).*is an object: it goes in the attest's refs \(or in discriminator\.refs\), and here goes the E-<seq> of the entry that says what it shows/]) assert.match(reason, must);
  // A link that says only that the value re-derives says nothing of the artefact.
  refused(await P.attestEntry(c.a2, { seq: a.seq, how: "re-read", ...ESTABLISHED, answer_review: { ...ESTABLISHED.answer_review, link: "the value re-derives" } }), /answer_review\.link says what ties the cited artefact to the question, and "the value re-derives" says only that the value re-derives/);
  // The answer is recorded again with the same conclusion (its reasoning reworded): an attest of the one it corrects is the attest of the one that stands.
  const a2 = ok(await rec(c.a1, { kind: "answer", section: "question:1", value: "alice", reasoning: `The log's line 12 shows it (E-${f.seq})`, ...A, confidence: "high", result: "established", supersedes: a.seq })).entry;
  const att = await P.attestEntry(c.a2, { seq: a.seq, how: "re-read line 12 from job:j000001", refs: ["job:j000001/out/hits.txt"], ...ESTABLISHED, answer_review: { ...ESTABLISHED.answer_review, parts: [{ id: "who", part: "who logged on", established: true, why: "line 12 names her" }] } });
  assert.ok(att.ok, (att as { reason?: string }).reason);
  const line = (att as { line: P.LedgerAttestation }).line;
  assert.equal(line.seq, a2.seq);
  assert.deepEqual(line.refs, ["job:j000001/hits.txt"]);
  assert.equal(line.answer_review?.link, ESTABLISHED.answer_review.link);
  assert.equal(line.answer_review?.parts[0]?.id, undefined);
  const note = String((att as { note?: string }).note);
  assert.match(note, new RegExp(`#${a.seq} was corrected by #${a2.seq}, which concludes the same: your attest is recorded on #${a2.seq}, the entry that stands`));
  assert.match(note, new RegExp(`#${a2.seq} carries no parts, so the ids in answer_review\\.parts \\(who\\) name nothing`));
  assert.match(note, /ref "job:j000001\/out\/hits\.txt" taken as job:j000001\/hits\.txt/);
  // A correction that concludes something else is still refused, with the entry that stands.
  const a3 = ok(await rec(c.a1, { kind: "answer", section: "question:1", value: "alice and bob", reasoning: `E-${f.seq}`, ...A, confidence: "high", result: "established", supersedes: a2.seq })).entry;
  refused(await P.attestEntry(c.a3, { seq: a2.seq, how: "re-read", ...ESTABLISHED }), new RegExp(`#${a2.seq} is superseded by #${a3.seq}: attest the entry that stands; #${a3.seq} concludes something else than #${a2.seq} did`));
});

test("a field left out or misspelt is answered by the tool's own check: the arguments pass Pi's schema with what was sent kept beside them, and come back as sent", () => {
  const schema = Type.Object({
    kind: Type.Union([Type.Literal("finding"), Type.Literal("absence")]),
    value: Type.String(),
    confidence: Type.Optional(Type.Union([Type.Literal("high"), Type.Literal("low")])),
    refs: Type.Optional(Type.Array(Type.String())),
    detection_opportunity: Type.Optional(Type.Object({ trace_expected: Type.Union([Type.Literal("yes"), Type.Literal("no")]), why: Type.String() })),
    supersedes: Type.Optional(Type.Number()),
  });
  // A call that fits is the call, untouched.
  const fits = { kind: "finding", value: "v", refs: ["input:x"] };
  assert.equal(P.argsForValidator(schema, fits), fits);
  assert.equal(P.argsAsSent(fits), fits);
  // kind left out, an enum misspelt, a list sent as a string, an object short of a field, a number as words, an optional sent null.
  const sent = { value: "v", confidence: "certain", refs: "input:x, input:y", detection_opportunity: { trace_expected: "yes" }, supersedes: "12", extra: null as unknown };
  const prepared = P.argsForValidator(schema, sent) as Record<string, unknown>;
  assert.equal(prepared.kind, "finding", "a placeholder the schema takes, where the required field was left out");
  for (const k of ["confidence", "refs", "detection_opportunity", "supersedes"]) assert.equal(k in prepared, false, `${k} is set aside: the schema would refuse it`);
  assert.deepEqual(prepared[P.ARGS_AS_SENT], { missing: ["kind"], unfit: { confidence: "certain", refs: "input:x, input:y", detection_opportunity: { trace_expected: "yes" }, supersedes: "12" } });
  // What the tool reads is what the model sent: no placeholder, nothing lost.
  const back = P.argsAsSent(prepared);
  assert.deepEqual(back, { value: "v", confidence: "certain", refs: "input:x, input:y", detection_opportunity: { trace_expected: "yes" }, supersedes: "12", extra: null });
  // No arguments at all (a broken call) is every required field left out.
  assert.deepEqual((P.argsForValidator(schema, undefined) as Record<string, unknown>)[P.ARGS_AS_SENT], { missing: ["kind", "value"], unfit: {} });
});
