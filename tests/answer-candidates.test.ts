/**
 * Candidates, carriers and decoys as checks (plan item B4, the review of the
 * Batman III runs): a lower confidence or an objection never rewrites an
 * answer's value; a dispute about a reading adds a candidate; only a record
 * that names a machine check removes one; an answer that chose among N
 * carriers is settled only on a carrier table with N rows; and a payload that
 * declares itself fake is a decoy candidate, never on its own the answer.
 */
import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import { join } from "node:path";
import { test } from "node:test";
import * as P from "../extensions/protocol.ts";
import { answerWords } from "../scripts/report-body.ts";
import { b9SensitiveValues, sensitiveTokens } from "../extensions/sensitive.ts";
import { A, F, ok, planned, rec, refused, run } from "./negative-bar-fixture.ts";

const MD5 = "5f4dcc3b5aa765d61d8327deb882cf99";
const OTHER = "7c6a180b36896a0a8c02787eeafb0e4c";
const GOAL = [
  "## Goal",
  "",
  "Examine the host.",
  "",
  "### Questions",
  "",
  "1. What is the hidden text in the AVI file? Format: *md5(text)*",
  "2. Which QR symbol on the desktop carries the flag?",
  "3. What is the flag in the archive?",
  "",
  "## Definition of done",
  "",
  "d",
  "",
  "## Checks",
  "",
  '- `node x "$SWARM_HARNESS/scripts/check-answers.ts" --sections 1,2,3`',
  "",
].join("\n");

const answer = (section: string, value: string, reasoning: string, o: Record<string, unknown> = {}) => ({ kind: "answer", section: `question:${section}`, value, reasoning, ...A, confidence: "high", result: "established", ...o });
type Row = NonNullable<P.LedgerEntry["candidates"]>[number];
const rowsOf = (e: P.LedgerEntry) => (e.candidates ?? []).map((r: Row) => [r.value, r.state, r.by ?? null]);

async function fixture() {
  const c = await run({ goal: GOAL });
  const f: Record<string, number> = {};
  for (const q of ["1", "2", "3"]) {
    await planned(c.a0, q);
    f[q] = ok(await rec(c.a0, { kind: "finding", ...F, value: `what question ${q} asks, read from the disk: ${MD5}`, source: "the disk", evidence: "a row", refs: ["job:j000001/hits.txt"], answers: [q] })).entry.seq;
  }
  return { c, f };
}

test("an objection leaves value as it was and adds its reading as a candidate; a lower confidence keeps the asked string", async () => {
  const { c, f } = await fixture();
  const first = ok(await rec(c.a1, answer("1", MD5, `E-${f["1"]} shows it`))).entry;
  // The critic reads one glyph otherwise: a dispute with its reading. The answer's value is not touched.
  const d = await P.disputeEntry(c.a2, { seq: first.seq, why: "one glyph of the overlay reads as an uppercase I, not a lower-case l", reading: OTHER });
  assert.ok(d.ok, (d as { reason?: string }).reason);
  assert.equal((d as { line: P.LedgerDispute }).line.reading, OTHER);
  // A reading is a dispute's, not a withdrawal's, and only of an answer's or a finding's value.
  assert.equal((await P.disputeEntry(c.a2, { seq: first.seq, why: "w", withdraw: true, reading: OTHER })).ok, false);
  const lim = ok(await rec(c.a0, { kind: "limitation", value: "One glyph of the overlay could be l or I", source: "the AVI overlay", evidence: "the font was not identified", reason: "partial", answers: ["1"] })).entry.seq;
  assert.match(((await P.disputeEntry(c.a2, { seq: lim, why: "w", reading: OTHER })) as { reason: string }).reason, /reading is the value as you read it, a candidate beside an answer's or a finding's value; #\d+ is a limitation/);
  // The ledger a seat reads back shows the reading, beside the value and on the dispute.
  const md = await readFile(join(c.S, P.LEDGER_MD), "utf8");
  assert.match(md, new RegExp(`#${first.seq}\\*\\* question:1 \\(established\\): ${MD5} — candidates: ${OTHER} \\(open: the reading a2's dispute gives\\)`));
  assert.match(md, new RegExp(`disputed by a2: one glyph[^\\]]*\\(reads it as: ${OTHER}\\)`));
  // The run s68ce47's E-262: the critic's doubt turned the asked string into a sentence. Refused, as before.
  refused(await rec(c.a1, answer("1", `The best-supported candidate is ${MD5}, but one glyph is open.`, `E-${f["1"]}; E-${lim}`, { confidence: "low", supersedes: first.seq })), /also changes its value, which was in the asked format/);
  // The revision as the rule asks: the asked string stays, at low confidence; the reading is carried as a candidate, and nothing is said to remain open while it is.
  refused(await rec(c.a1, answer("1", MD5, `E-${f["1"]}; E-${lim}`, { confidence: "low", supersedes: first.seq })), new RegExp(`alternatives_open says nothing remains open, and this answer holds a candidate no check has ruled out \\("${OTHER}"\\)`));
  const kept = ok(await rec(c.a1, answer("1", MD5, `E-${f["1"]}; E-${lim}`, { confidence: "low", supersedes: first.seq, alternatives_open: `the reading ${OTHER} is open until the font is identified` })));
  assert.equal(kept.entry.value, MD5);
  assert.equal(kept.entry.confidence, "low");
  assert.deepEqual(rowsOf(kept.entry), [[OTHER, "open", null]]);
  assert.match(kept.note ?? "", new RegExp(`candidates carried from #${first.seq}: ${OTHER} \\(open: the reading a2's dispute of #${first.seq} gives\\)`));
  // A revision that leaves the row out does not drop it: the hub carries it.
  const again = ok(await rec(c.a1, answer("1", MD5, `E-${f["1"]}; E-${lim}, read again`, { confidence: "low", supersedes: kept.entry.seq, alternatives_open: "the other reading is open" })));
  assert.deepEqual(rowsOf(again.entry), [[OTHER, "open", null]]);
  // The report words the candidate beside the value.
  assert.equal(answerWords(again.entry), `${MD5}\n\nCandidates still open: ${OTHER} (the reading a2's dispute of #${first.seq} gives).`);
  // The chain verifies with the rows in the core, and the disputes' chain with the reading in it.
  assert.equal(P.verifyLedgerChain(await readFile(join(c.S, P.LEDGER_ENTRIES), "utf8")).ok, true);
  assert.equal(P.verifyDisputeChain(await readFile(join(c.S, P.LEDGER_DISPUTES), "utf8")).ok, true);
});

test("a lowered revision that changes the value of a question with no Format line keeps the earlier value as a candidate", async () => {
  const { c, f } = await fixture();
  const first = ok(await rec(c.a1, answer("3", "FLAG{alpha}", `E-${f["3"]} shows it`))).entry;
  const r = ok(await rec(c.a1, answer("3", "FLAG{beta}", `E-${f["3"]} read again`, { confidence: "low", supersedes: first.seq, alternatives_open: "FLAG{alpha} is still open" })));
  assert.deepEqual(rowsOf(r.entry), [["FLAG{alpha}", "open", null]]);
  // A correction that lowers nothing and answers no objection is a correction: nothing is carried.
  const fresh = ok(await rec(c.a2, answer("2", "qr1.png", `E-${f["2"]}`))).entry;
  const fixed = ok(await rec(c.a2, answer("2", "qr2.png", `E-${f["2"]}`, { supersedes: fresh.seq })));
  assert.equal(fixed.entry.candidates, undefined);
});

test("a candidate leaves only as ruled_out with a machine check, and the removal names that check", async () => {
  const { c, f } = await fixture();
  const lim = ok(await rec(c.a0, { kind: "limitation", value: "One glyph of the overlay could be l or I", source: "the AVI overlay", evidence: "the font was not identified", reason: "partial", answers: ["1"] })).entry.seq;
  const argued = ok(await rec(c.a0, { kind: "finding", ...F, basis: "inferred", alternatives_none_why: "an argument, nothing tested", value: "The other reading is less likely", source: "the analyst", evidence: "an argument about letter shapes", refs: ["input:disk.E01"], answers: ["1"] })).entry.seq;
  const check = ok(await rec(c.a0, { kind: "finding", ...F, value: `The overlay's font renders the glyph as a lower-case l: the text hashes to ${MD5}`, source: "the AVI overlay", evidence: "the font's glyph table against the frame's pixels", refs: ["job:j000002/hits.txt"], answers: ["1"] })).entry.seq;
  const first = ok(await rec(c.a1, answer("1", MD5, `E-${f["1"]}; E-${lim}`, { candidates: [{ value: OTHER, why: "one glyph may be an uppercase I" }], alternatives_open: "the other reading is open" }))).entry;
  assert.deepEqual(rowsOf(first), [[OTHER, "open", null]]);
  const out = (by?: string) => ({ candidates: [{ value: OTHER, state: "ruled_out", why: "the font settles the glyph", ...(by ? { by } : {}) }] });
  // No check, an argument, a limitation, a failed job: each refused, all in one refusal.
  refused(await rec(c.a1, answer("1", MD5, `E-${f["1"]}`, { supersedes: first.seq, ...out() })), /candidate "7c6a180b36896a0a8c02787eeafb0e4c" is ruled_out with no check: by names the job/);
  refused(await rec(c.a1, answer("1", MD5, `E-${f["1"]}`, { supersedes: first.seq, ...out(`E-${argued}`) })), new RegExp(`is ruled out by E-${argued}, which is not a machine check: E-${argued} rests on no job's result \\(no job:<id>/<path> in its refs, no control run\\): it is a reading or an argument, which adds a candidate and removes none`));
  refused(await rec(c.a1, answer("1", MD5, `E-${f["1"]}`, { supersedes: first.seq, ...out(`E-${lim}`) })), new RegExp(`E-${lim} is a limitation: a check that rules a candidate out is a job's result`));
  refused(await rec(c.a1, answer("1", MD5, `E-${f["1"]}`, { supersedes: first.seq, ...out("job:j000004/hits.txt") })), /job:j000004\/hits\.txt is the output of a job that did not succeed \(failed\): its result excludes nothing/);
  // A check that rests on a job's result rules it out, and the row names it.
  const settled = ok(await rec(c.a1, answer("1", MD5, `E-${f["1"]}; E-${check}`, { supersedes: first.seq, ...out(`E-${check}`), alternatives_open: "none open: the font settles the glyph" })));
  assert.deepEqual(rowsOf(settled.entry), [[OTHER, "ruled_out", `E-${check}`]]);
  // A job ref is a check too; a later revision that leaves the row out keeps the ruled-out row, with its check.
  const later = ok(await rec(c.a1, answer("1", MD5, `E-${f["1"]}; E-${check} again`, { supersedes: settled.entry.seq })));
  assert.deepEqual(rowsOf(later.entry), [[OTHER, "ruled_out", `E-${check}`]]);
  assert.match(answerWords(later.entry), new RegExp(`Ruled out by a check: ${OTHER} \\(by E-${check}: the font settles the glyph\\)\\.`));
  // A value changed on a machine check carries the earlier value, ruled out by that check.
  const changed = ok(await rec(c.a1, answer("1", OTHER, `E-${check}`, { confidence: "medium", supersedes: later.entry.seq, value_changed_because: `E-${check} identifies the glyph`, candidates: [{ value: OTHER, state: "open", why: "reopened" }] })));
  assert.deepEqual(rowsOf(changed.entry).find((r) => r[0] === MD5), [MD5, "ruled_out", `E-${check}`]);
});

test("a finding's candidates are carried by its correction, a dispute's reading with them", async () => {
  const { c } = await fixture();
  const one = ok(await rec(c.a0, { kind: "finding", ...F, value: "The note on the desktop holds a password", source: "the desktop", evidence: "a row", refs: ["job:j000001/hits.txt"], answers: ["3"], candidates: [{ value: "hunter2", why: "the note's first line" }] })).entry;
  const d = await P.disputeEntry(c.a1, { seq: one.seq, why: "the last glyph is a Z", reading: "hunterZ" });
  assert.ok(d.ok);
  const fixed = ok(await rec(c.a0, { kind: "finding", ...F, value: "The note on the desktop holds a password, read again", source: "the desktop", evidence: "a row", refs: ["job:j000001/hits.txt"], answers: ["3"], supersedes: one.seq }));
  assert.deepEqual(rowsOf(fixed.entry), [["hunter2", "open", null], ["hunterZ", "open", null]]);
  assert.match(fixed.note ?? "", new RegExp(`candidates carried from #${one.seq}: hunter2 \\(open: the note's first line\\); hunterZ \\(open: the reading a1's dispute of #${one.seq} gives\\)`));
  // Only a finding and an answer take candidates.
  refused(await rec(c.a0, { kind: "limitation", value: "x", source: "s", evidence: "e", reason: "partial", candidates: [{ value: "a", why: "b" }] }), /candidates is an answer's or a finding's/);
  // A sensitive finding's candidates are sensitive values too.
  const s = ok(await rec(c.a0, { kind: "finding", ...F, value: "The vault password is noted", source: "the desktop", evidence: "a row", refs: ["job:j000001/hits.txt"], answers: ["3"], sensitive: true, candidates: [{ value: "Qx7!secretpass", why: "the second line" }] })).entry;
  const entries = await P.readLedger(c.S);
  assert.ok(sensitiveTokens(entries).some((t) => t.token === "Qx7!secretpass" && t.seq === s.seq));
  assert.ok(b9SensitiveValues(entries).some((t) => t.token === "Qx7!secretpass" && t.exact));
});

test("an answer that chose among N carriers holds until the carrier table has N rows, at record and at the finish gate", async () => {
  const { c, f } = await fixture();
  const names = ["qr1.png", "qr2.png", "qr3.png", "qr4.png"];
  const rowsFor = (n: number) => names.slice(0, n).map((carrier) => ({ carrier, state: "decoded", why: "decodes to a string that is not the flag" }));
  const table = async (n: number, supersedes?: number) => ok(await rec(c.a0, { kind: "finding", ...F, value: `${n} QR symbols were decoded on the desktop`, source: "the desktop", evidence: "each decoded in turn", refs: ["job:j000001/hits.txt"], answers: ["2"], carriers: rowsFor(n), ...(supersedes ? { supersedes } : {}) })).entry;
  // No table at all: nothing settles the choice.
  refused(await rec(c.a1, answer("2", "qr1.png", `E-${f["2"]}`, { carrier_names: names, alternatives_open: "the others were decoded" })), /this answer names 4 carriers \(carrier_names\) and it cites no carrier table, so none of them has a row \(qr1\.png, qr2\.png, qr3\.png, qr4\.png\): it cannot be recorded established until each carrier has a row/);
  const t3 = await table(3);
  refused(await rec(c.a1, answer("2", "qr1.png", `E-${t3.seq}; E-${f["2"]}`, { carrier_names: names, alternatives_open: "the others were decoded" })), new RegExp(`this answer names 4 carriers \\(carrier_names\\) and the carrier table it cites \\(E-${t3.seq}\\) has no row for 1 of them \\(qr4\\.png\\): it cannot be recorded established`));
  // Nothing open is refused on a partial answer too.
  const lim = ok(await rec(c.a0, { kind: "limitation", value: "qr4.png is not decoded", source: "the desktop", evidence: "not rendered", reason: "partial", answers: ["2"] })).entry.seq;
  const parts = [{ id: "symbol", part: "the symbol", status: "established", refs: [`E-${t3.seq}`] }, { id: "rest", part: "the fourth symbol", status: "open", open_by: `E-${lim}` }];
  refused(await rec(c.a1, answer("2", "qr1.png", `E-${t3.seq}; E-${f["2"]}; E-${lim}`, { result: "partial", parts, carrier_names: names, alternatives_open: "No material candidate remains open" })), /nothing can be said to remain open until each carrier has a row/);
  // Partial, naming what is open: the table allows it.
  ok(await rec(c.a2, answer("2", "qr1.png", `E-${t3.seq}; E-${f["2"]}; E-${lim}`, { result: "partial", parts, carrier_names: names, alternatives_open: "qr4.png is not decoded" })));
  // Four rows for four carriers: settled.
  const t4 = await table(4, t3.seq);
  const standing = (await P.readLedger(c.S)).find((e) => e.kind === "answer" && e.section === "question:2")!;
  const settled = ok(await rec(c.a2, answer("2", "qr1.png", `E-${t4.seq}; E-${f["2"]}`, { supersedes: standing.seq, carrier_names: names, alternatives_open: "none open: every symbol was decoded" })));
  assert.deepEqual(settled.entry.carrier_names, names);
  const gate = async () => P.ledgerGate({ entries: await P.readLedger(c.S), attestations: await P.readAttestations(c.S), disputes: await P.readDisputes(c.S), sections: ["2"] });
  assert.deepEqual((await gate()).defects.filter((d) => d.code === "carriers_incomplete"), []);
  // The table corrected to fewer rows: the gate holds the answer, and says which carrier has no row.
  await table(2, t4.seq);
  const held = (await gate()).defects.filter((d) => d.code === "carriers_incomplete");
  assert.equal(held.length, 1);
  assert.match(held[0]!.what, new RegExp(`answer #${settled.entry.seq} \\(question:2\\) names 4 carriers and is established, while the carrier tables it rests on \\(E-\\d+\\) have no row for 2 of them \\(qr3\\.png, qr4\\.png\\)`));
  assert.ok((await gate()).open.some((d) => d.code === "carriers_incomplete"), "it holds the finish line");
});

test("a payload that declares itself fake is a decoy candidate: never the sole support of value without a machine check", async () => {
  const { c } = await fixture();
  const decoy = ok(await rec(c.a0, { kind: "finding", ...F, value: "The archive's readme holds FLAG{sample}", source: "archive/readme.txt", evidence: "a row", refs: ["job:j000001/hits.txt"], answers: ["3"], decoy: "the readme says: this is a sample flag for testing" })).entry;
  assert.equal(decoy.decoy, "the readme says: this is a sample flag for testing");
  // Words that say so without the mark are said to the recorder.
  const unmarked = ok(await rec(c.a0, { kind: "finding", ...F, value: "The config holds a fake flag FLAG{nope}", source: "config.ini", evidence: "a row", refs: ["job:j000001/hits.txt"], answers: ["3"] }));
  assert.match(unmarked.note ?? "", /its words say the payload declares itself fake, a test or a sample: if it does, record it again with decoy/);
  refused(await rec(c.a1, answer("3", "FLAG{sample}", `E-${decoy.seq}`)), new RegExp(`every finding this answer cites for its question is marked decoy \\(E-${decoy.seq}: the readme says: this is a sample flag for testing\\): a payload that declares itself fake, a test or a vendor's sample cannot be the sole support of value`));
  // A candidate row marked decoy is not the value either.
  const real = ok(await rec(c.a0, { kind: "finding", ...F, value: "The archive's payload decrypts to FLAG{real}", source: "archive/payload.bin", evidence: "decrypted", refs: ["job:j000002/hits.txt"], answers: ["3"] })).entry.seq;
  refused(await rec(c.a1, answer("3", "FLAG{sample}", `E-${real}; E-${decoy.seq}`, { candidates: [{ value: "FLAG{sample}", state: "decoy", why: "the readme calls it a sample" }] })), /value is a candidate marked decoy \(in this answer's candidates: the readme calls it a sample\)/);
  // decoy_check names a machine check, or it does not hold.
  refused(await rec(c.a1, answer("3", "FLAG{sample}", `E-${decoy.seq}`, { decoy_check: { by: "the analyst's view", why: "it looks right" } })), /decoy_check\.by is not a machine check: "the analyst's view" is not a check/);
  const ch = ok(await rec(c.a1, answer("3", "FLAG{sample}", `E-${decoy.seq}`, { decoy_check: { by: "job:j000002/hits.txt", why: "the challenge server accepts it" } })));
  assert.deepEqual(ch.entry.decoy_check, { by: "job:j000002/hits.txt", why: "the challenge server accepts it" });
  // The case's own data beside the decoy: the answer stands on it, the decoy a candidate.
  const other = await run({ goal: GOAL });
  await planned(other.a0, "3");
  const d2 = ok(await rec(other.a0, { kind: "finding", ...F, value: "The readme holds FLAG{sample}", source: "readme", evidence: "a row", refs: ["job:j000001/hits.txt"], answers: ["3"], decoy: "it calls itself a sample" })).entry.seq;
  const r2 = ok(await rec(other.a0, { kind: "finding", ...F, value: "The payload decrypts to FLAG{real}", source: "payload", evidence: "decrypted", refs: ["job:j000002/hits.txt"], answers: ["3"] })).entry.seq;
  ok(await rec(other.a1, answer("3", "FLAG{real}", `E-${r2}; E-${d2} is a decoy`, { candidates: [{ value: "FLAG{sample}", state: "decoy", why: "the readme calls it a sample" }] })));
  const md = await readFile(join(other.S, P.LEDGER_MD), "utf8");
  assert.match(md, /DECOY \(declares itself so: it calls itself a sample\)/);
  assert.match(md, /candidates: FLAG\{sample\} \(decoy: the readme calls it a sample\)/);
});
