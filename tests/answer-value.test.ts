/**
 * The answer in two fields, and what a review may change of it (the review
 * of the Batman III runs, I-02, I-04, I-08 and S-13).
 *
 * `value` is the asked string alone and `qualifier` what qualifies it: on
 * the run s082123 five right answers of eleven were sentences in the ledger
 * while the report held the exact strings. The format check reads the first
 * line of `value` only, asks nothing of an answer that found nothing or of a
 * part declared open, and is not said twice for the same first line. A drop
 * in confidence or a dispute changes confidence, result and parts, never the
 * asked string: three right answers were turned into sentences after their
 * critic doubted them (s68ce47 E-253 to E-262, s530aa4 E-260 to E-267). And
 * "nothing remains open" is held to the carrier table the answer cites.
 */
import assert from "node:assert/strict";
import { test } from "node:test";
import * as P from "../extensions/protocol.ts";
import { formatMiss, knownPart, looksLikeSentence, questionFormat } from "../extensions/answer-format.ts";
import { A, F, coverage, ok, planned, rec, refused, run } from "./negative-bar-fixture.ts";

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
  "2. What is the password noted down of the site and what is stored in the site? Format: *md5(password)_md5(data-in-the-site)*",
  "3. What is the PC name and timezone? Format: *PC-name_Time-Zone-info*",
  "4. What is the name and hash of the initial infection file? Format: *Name_md5(file)*",
  "",
  "## Definition of done",
  "",
  "d",
  "",
  "## Checks",
  "",
  '- `node x "$SWARM_HARNESS/scripts/check-answers.ts" --sections 1,2,3,4`',
  "",
].join("\n");

const HIGH = { ...A, confidence: "high" } as const;
const answer = (section: string, value: string, reasoning: string, o: Record<string, unknown> = {}) => ({ kind: "answer", section: `question:${section}`, value, reasoning, ...HIGH, result: "established", ...o });
const formatNotes = (note: string | undefined) => (note ?? "").split("asks for its answer in the format").length - 1;

async function withFindings() {
  const c = await run({ goal: GOAL });
  const f: Record<string, number> = {};
  for (const q of ["1", "2", "3", "4"]) {
    await planned(c.a0, q);
    f[q] = ok(await rec(c.a0, { kind: "finding", ...F, value: `what question ${q} asks, read from the disk: ${MD5}`, source: "the disk", evidence: "a row", refs: ["job:j000001/hits.txt"], answers: [q] })).entry.seq;
  }
  return { c, f };
}

test("value is the asked string and qualifier what qualifies it: a sentence in value gets one note, the bare string none, and the note is not repeated for the same first line", async () => {
  const { c, f } = await withFindings();
  // A sentence: recorded as written, told once what the first line is to be.
  const prose = ok(await rec(c.a1, answer("1", `The hidden text hashes to ${MD5} (E-${f["1"]}).`, `E-${f["1"]}`)));
  assert.equal(formatNotes(prose.note), 1, prose.note);
  assert.match(prose.note ?? "", /question:1 asks for its answer in the format md5\(text\) \(a hash as its hex digits\), and the value's first line is not in it\. It looks like: <32 hex digits> Recorded as written; record it again with supersedes, value exactly in that form and nothing else \(no sentence, no label, no second candidate\), and the words that go with it in qualifier/);
  // The same first line again (the reasoning reworded): not told again.
  const again = ok(await rec(c.a1, answer("1", `The hidden text hashes to ${MD5} (E-${f["1"]}).`, `E-${f["1"]} shows it`)));
  assert.equal(formatNotes(again.note), 0, again.note);
  // The asked string alone, with its words in qualifier: no note, both recorded.
  const bare = ok(await rec(c.a1, answer("1", MD5, `E-${f["1"]} shows it, read twice`, { qualifier: "read from the overlay at frame 10; the lowercase l is the one glyph that could be an I" })));
  assert.equal(formatNotes(bare.note), 0, bare.note);
  assert.equal(bare.entry.value, MD5);
  assert.equal((bare.entry as P.LedgerEntry & P.AnswerExtras).qualifier, "read from the overlay at frame 10; the lowercase l is the one glyph that could be an I");
  // A second digest on the first line of an md5 answer is a second candidate, not the answer.
  const two = ok(await rec(c.a1, answer("4", `invoice.docm_${MD5} or invoice.docm_${OTHER}`, `E-${f["4"]}`)));
  assert.match(two.note ?? "", /question:4 asks for its answer in the format Name_md5\(file\).*the value's first line holds 2 digests where the format asks 1: one answer is graded, so the first line holds one, and a second candidate goes in qualifier/);
  // A sentence passes a format of free text by its separator alone: said too.
  const pc = ok(await rec(c.a1, answer("3", "The PC name is DESKTOP-EXAMPLE1 and the time zone is Fiji_Standard Time", `E-${f["3"]}`)));
  assert.equal(formatNotes(pc.note), 1, pc.note);
  assert.equal(formatNotes(ok(await rec(c.a1, answer("3", "DESKTOP-EXAMPLE1_Fiji Standard Time", `E-${f["3"]} gives both`))).note), 0);
  // The qualifier's tokens are held to the cited entries as the value's are, and a qualifier is a question's answer's.
  refused(await rec(c.a1, { kind: "answer", section: "summary", value: "what happened", reasoning: `E-${f["1"]}`, qualifier: "a candidate" }), /qualifier is a question's answer's/);
  refused(await rec(c.a0, { kind: "finding", ...F, value: "x", source: "s", evidence: "e", qualifier: "q" }), /qualifier is an answer's/);
});

test("nothing is asked of a part declared open, of an empty value, or of an answer that found nothing; an established answer is asked for the whole", async () => {
  const { c, f } = await withFindings();
  const lim = ok(await rec(c.a0, { kind: "limitation", value: "The site's stored data was not recovered", source: "the browser profile", evidence: "the login data is encrypted with a key the image does not hold", reason: "unavailable", answers: ["2"] })).entry.seq;
  const parts = [
    { id: "password", part: "the password noted down", status: "established", refs: [`E-${f["2"]}`] },
    { id: "data", part: "what is stored in the site", status: "open", open_by: `E-${lim}` },
  ];
  const partial = { result: "partial", confidence: "medium", parts };
  // The half that is known, in its piece of the format: no note (the old check sent six on this answer, and one seat then invented the other half).
  const half = ok(await rec(c.a1, answer("2", MD5, `E-${f["2"]} gives the password; the stored data is open (E-${lim})`, { ...partial, qualifier: "md5 of the password only; what the site stores is open" })));
  assert.equal(formatNotes(half.note), 0, half.note);
  // No value at all, the qualifier saying what is known: taken, no note.
  const empty = ok(await rec(c.a1, answer("2", "", `E-${f["2"]} gives a candidate password; the stored data is open (E-${lim})`, { ...partial, qualifier: `candidate password digest ${MD5}; the stored data is open` })));
  assert.equal(empty.entry.value, "");
  assert.equal(formatNotes(empty.note), 0, empty.note);
  // A sentence on the open answer is still told once, and only for the piece it has.
  const prose = ok(await rec(c.a1, answer("2", `The password hashes to ${MD5} and the site data is unknown`, `E-${f["2"]}; open: E-${lim}`, partial)));
  assert.equal(formatNotes(prose.note), 1, prose.note);
  assert.match(prose.note ?? "", /This answer declares a part open, so nothing is asked for that part: record it again with supersedes, value holding only the piece of the format that is established, alone \(or value empty\), and everything else in qualifier\. This note is not a reason to guess the open part/);
  // An empty value is an established answer's defect, and a qualifier does not stand in for it.
  refused(await rec(c.a1, answer("1", "", `E-${f["1"]}`, { qualifier: "a candidate" })), /value is required: the answer itself, as the reader is to be told it \(it may be empty only on an answer that is not established, whose qualifier says what is known and what is open\)/);
  // An answer that found nothing has no asked string: no note (a negative question 11 drew two on the run s01a4f4).
  const absence = ok(await rec(c.a0, { kind: "absence", value: "text in any frame of the AVI", source: "the AVI", evidence: "every frame rendered and read", refs: ["job:j000001/hits.txt"], control: { ref: "job:j000001/hits.txt", found: "the same rendering shows a planted caption" }, answers: ["1"] })).entry.seq;
  const cov = ok(await rec(c.a0, coverage("1", ["input:disk.E01"], [`E-${absence}`, "job:j000001/hits.txt"]))).entry.seq;
  const negative = ok(await rec(c.a2, answer("1", "No evidence of hidden text was found in the AVI's frames", `E-${cov} over E-${absence}`, { result: "bounded_negative", confidence: "medium" })));
  assert.equal(formatNotes(negative.note), 0, negative.note);
});

test("the format's own readers: a sentence, a known piece, an extra digest", () => {
  const q7 = "What is the password and the data? Format: *md5(password)_md5(data-in-the-site)*";
  const f = questionFormat(q7)!;
  assert.equal(f.pieces.length, 2);
  assert.equal(knownPart(f, MD5), true, "one hash of the two");
  assert.equal(knownPart(f, `${MD5}_${OTHER}`), false, "the whole is not a part");
  assert.equal(knownPart(f, `the password is ${MD5}`), false);
  assert.ok(formatMiss(q7, MD5), "an established answer gives both");
  assert.equal(formatMiss(q7, MD5, { open: true }), null);
  assert.equal(formatMiss(q7, "", { open: true }), null);
  assert.equal(formatMiss(q7, `${MD5}_${OTHER}`), null);
  assert.equal(formatMiss(q7, `${MD5}_${OTHER} ${MD5}`)?.extra_digests, 3);
  const name = "Format: *Name_md5(file)*";
  assert.equal(knownPart(questionFormat(name)!, "invoice.docm"), true);
  assert.equal(formatMiss(name, `invoice.docm_${MD5}`), null);
  assert.equal(formatMiss(name, `Strongest current candidate: invoice.docm_${MD5}; the retained evidence has not yet established that it delivered the bytes.`)?.seen_elsewhere, false);
  for (const [line, is] of [["DESKTOP-EXAMPLE1_Fiji Standard Time", false], ["The PC name is FOO and the zone is BAR_BAZ", true], ["A 22-character overlay is visible.", true], ["mssetup.exe", false]] as const) assert.equal(looksLikeSentence(line), is, line);
});

test("a drop in confidence or a dispute changes confidence and result, never the asked string; a candidate is not removed by argument", async () => {
  const { c, f } = await withFindings();
  const first = ok(await rec(c.a1, answer("1", MD5, `E-${f["1"]} shows it`))).entry;
  const lim = ok(await rec(c.a0, { kind: "limitation", value: "One glyph of the overlay could be l or I", source: "the AVI overlay", evidence: "the font was not identified", reason: "partial", answers: ["1"] })).entry.seq;
  const parts = [
    { id: "overlay", part: "the AVI holds visible text", status: "established", refs: [`E-${f["1"]}`] },
    { id: "exact", part: "its exact transcription and MD5", status: "open", open_by: `E-${lim}` },
  ];
  const lowered = { result: "partial", confidence: "medium", parts, supersedes: first.seq, because: "the critic holds one glyph open" };
  // What the run s68ce47 recorded as E-262: the digest gone into a sentence, on the critic's doubt.
  const prose = await rec(c.a1, answer("1", `A 22-character overlay is visible. The best-supported no-newline MD5 candidate is ${MD5}, but the exact mapping remains open.`, `E-${f["1"]}; E-${lim}`, lowered));
  refused(prose, new RegExp(`this revision lowers the result of #${first.seq} \\(established to partial\\) and also changes its value, which was in the asked format \\("${MD5}"\\): a drop in confidence or a dispute changes confidence, result and parts, never the value\\. Record it again with value "${MD5}" unchanged and the doubt in qualifier`));
  // The same revision as the rule asks it: the asked string stands, at the lower confidence, the doubt beside it.
  const kept = ok(await rec(c.a1, answer("1", MD5, `E-${f["1"]}; E-${lim}`, { ...lowered, qualifier: `best-supported candidate; the other reading gives ${OTHER}` }))).entry as P.LedgerEntry & P.AnswerExtras;
  assert.equal(kept.value, MD5);
  assert.equal(kept.result, "partial");
  assert.equal(kept.confidence, "medium");
  // A candidate the answer held is not dropped by a later revision without a check that rules it out.
  const drop = await rec(c.a1, answer("1", MD5, `E-${f["1"]}; E-${lim}, argued again`, { ...lowered, supersedes: kept.seq, qualifier: "best-supported candidate" }));
  refused(drop, new RegExp(`this revision drops a candidate #${kept.seq} held \\(${OTHER}\\): a dispute about a reading adds a candidate and only a check that rules one out removes it\\. Keep it in qualifier`));
  // The value itself is wrong: said, with the entry that shows it.
  refused(await rec(c.a1, answer("1", OTHER, `E-${f["1"]}; E-${lim}`, { ...lowered, supersedes: kept.seq, value_changed_because: "the critic prefers the other reading" })), /value_changed_because names the entry that shows the earlier value wrong, as E-<seq> \(it names none\): a doubt alone changes confidence or result, not the value/);
  const check = ok(await rec(c.a0, { kind: "finding", ...F, value: `The overlay's font renders the glyph as an uppercase I: the text hashes to ${OTHER}`, source: "the AVI overlay", evidence: "the font's glyph table against the frame's pixels", refs: ["job:j000002/hits.txt"], answers: ["1"] })).entry.seq;
  const changed = ok(await rec(c.a1, answer("1", OTHER, `E-${check} settles the glyph (E-${f["1"]} read it as l)`, { confidence: "medium", supersedes: kept.seq, value_changed_because: `E-${check} identifies the glyph by the font's own table`, qualifier: `the earlier reading gave ${MD5}` }))).entry as P.LedgerEntry & P.AnswerExtras;
  assert.equal(changed.value, OTHER);
  assert.equal(changed.value_changed_because, `E-${check} identifies the glyph by the font's own table`);
  // A revision that raises nothing and lowers nothing may reword freely; one without supersedes has nothing to say of a change.
  refused(await rec(c.a2, answer("4", `invoice.docm_${MD5}`, `E-${f["4"]}`, { value_changed_because: `E-${check}` })), /value_changed_because says why a revision changes the asked string: it comes with supersedes/);
});

test("nothing remains open is held to the carrier table: a row not examined, or a carrier with no row, refuses it", async () => {
  const { c, f } = await withFindings();
  const carriers = (states: Array<[string, P.CarrierRow["state"]]>) => states.map(([carrier, state]) => ({ carrier, state, why: state === "decoded" ? "decodes to a string that is not the answer" : state === "undecodable" ? "the symbol is cut: no decoder reads it" : "not rendered yet" }));
  const table = async (states: Array<[string, P.CarrierRow["state"]]>, supersedes?: number) => ok(await rec(c.a0, { kind: "finding", ...F, value: `${states.length} QR symbols were found on the desktop: ${MD5}`, source: "the desktop", evidence: "each decoded in turn", refs: ["job:j000001/hits.txt"], answers: ["1"], carriers: carriers(states), ...(supersedes ? { supersedes } : {}) })).entry;
  refused(await rec(c.a0, { kind: "finding", ...F, value: "x", source: "s", evidence: "e", carriers: [{ carrier: "a.png", state: "skipped", why: "w" }] }), /a carrier's state must be one of decoded, undecodable, not_examined/);
  refused(await rec(c.a0, { kind: "limitation", value: "x", source: "s", evidence: "e", reason: "partial", carriers: [{ carrier: "a.png", state: "decoded", why: "w" }] }), /carriers is a finding's/);
  const t1 = await table([["qr1.png", "decoded"], ["qr2.png", "decoded"], ["qr3.png", "not_examined"]]);
  assert.deepEqual((t1 as P.LedgerEntry & { carriers: P.CarrierRow[] }).carriers.map((r) => r.state), ["decoded", "decoded", "not_examined"]);
  const all = { alternatives_open: "No material candidate remains open: every symbol was decoded" };
  refused(await rec(c.a1, answer("1", MD5, `E-${t1.seq} lists the symbols; E-${f["1"]}`, all)), new RegExp(`alternatives_open says nothing remains open, and E-${t1.seq}'s carrier table has 1 not examined \\(qr3\\.png\\): examine it and record the table again, or say in alternatives_open which carrier is open`));
  // Saying what is open is an answer the table allows.
  ok(await rec(c.a1, answer("1", MD5, `E-${t1.seq} lists the symbols; E-${f["1"]}`, { alternatives_open: "qr3.png is not decoded yet and could carry another text" })));
  // A coverage record over four objects beside a table of three rows: a carrier has no row.
  const t2 = await table([["qr1.png", "decoded"], ["qr2.png", "decoded"], ["qr3.png", "undecodable"]], t1.seq);
  const cov = ok(await rec(c.a0, coverage("1", ["input:disk.E01", "input:logs/a.log", "input:logs/b.log", "job:j000001"], [`E-${t2.seq}`, "job:j000001/hits.txt"]))).entry.seq;
  refused(await rec(c.a1, answer("1", MD5, `E-${t2.seq} lists the symbols, searched for in E-${cov}; E-${f["1"]}`, all)), new RegExp(`alternatives_open says nothing remains open, and the coverage record E-${cov} names 4 objects where the carrier table cited has 3 rows`));
  const t3 = await table([["qr1.png", "decoded"], ["qr2.png", "decoded"], ["qr3.png", "undecodable"], ["qr4.png", "decoded"]], t2.seq);
  const held = ok(await rec(c.a1, answer("1", MD5, `E-${t3.seq} lists the symbols, searched for in E-${cov}; E-${f["1"]}`, all)));
  assert.equal(held.entry.alternatives_open, all.alternatives_open);
  // An answer that cites no table is not held: nothing on the record says it chose among carriers.
  ok(await rec(c.a2, answer("4", `invoice.docm_${MD5}`, `E-${f["4"]}`, { alternatives_open: "none open" })));
});
