/**
 * What a negative rests on (the review of the Batman III runs, I-22 and
 * I-07): a negative from the seat's own scanner names its control run, since
 * a search that could not have matched reads the same as one that found
 * nothing (the run sf4406b's E-87, "0 hits over 111.7 M key offsets" where a
 * state was there, gave a wrong answer two seats attested); a negative about
 * pictures holds for the pictures read, and the sheets of the cited job its
 * recorder was never handed hold the answer that rests on it (the run
 * s01a4f4's E-252, high after 3 of 11 sheets); and a finding at high
 * confidence that later entries stand on and nobody reviewed is said (that
 * run's E-81 fixed the team's search for 115 minutes).
 */
import assert from "node:assert/strict";
import { appendFile, mkdir, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { test } from "node:test";
import * as P from "../extensions/protocol.ts";
import { sealTree, storePaths } from "../scripts/evidence-store.ts";
import { A, F, job, ok, planned, rec, refused, run } from "./negative-bar-fixture.ts";

type Negative = P.LedgerEntry & P.NegativeFields;

/** A job whose output is a set of files, as an ffmpeg tile job leaves its sheets. */
async function jobWith(S: string, id: string, files: string[], record: Record<string, unknown>): Promise<void> {
  const staging = join(S, "..", `staging-${id}-${Math.random().toString(16).slice(2)}`);
  for (const f of files) {
    await mkdir(join(staging, f, ".."), { recursive: true });
    await writeFile(join(staging, f), `${id} ${f}\n`);
  }
  await sealTree(S, staging, join(storePaths(S).jobs, id, "out"), id, 1);
  await writeFile(join(storePaths(S).jobs, id, "job.json"), JSON.stringify({ id, state: "committed", requester: { agent: "a0" }, status: "ok", exit: 0, ...record }));
}

/** A `read` of a file under the store, as the extension traces it. */
async function traceRead(S: string, agent: string, path: string, okRead = true): Promise<void> {
  await mkdir(join(S, "traces"), { recursive: true });
  await appendFile(join(S, P.EVENTS_REL), `${JSON.stringify({ ts: new Date().toISOString(), agent, tool: "read", args: { path }, result: { ok: okRead, output: "Read image file [image/png]" } })}\n`);
}

test("a negative from the seat's own scanner names its control run; a pack tool that ended ok, a failed search and a reading are not held to one", async () => {
  const c = await run();
  await job(c.S, "j000020", "report.json", { spec: { kind: "tool", tool: "chunk_needles", inputs: ["input:disk.E01"] } });
  await job(c.S, "j000021", "control.txt", { spec: { kind: "command", inputs: ["input:disk.E01"], command: "the same scan over a copy with a planted key" } });
  const absence = { kind: "absence", value: "a live cipher state in the process dump", source: "inputs/disk.E01", evidence: "a sweep of every offset for the state's layout", refs: ["job:j000001/hits.txt"] };
  // The output of a command job, no control: refused, with what a control is.
  refused(await rec(c.a0, absence), /^this absence rests on your own scanner \(job:j000001\/hits\.txt: the output of a command job, not of a pack tool that reports what it covered\), and a search that could not have matched reads the same as one that found nothing: name its control in control: \{ref: "job:<id>\/stdout\.log", found: "<what it found>"\}, a job in which the same scanner, with the same pattern and layout, found a planted or known value/);
  // A finding that reports a search's empty result is one too; a reading is not.
  refused(await rec(c.a0, { kind: "finding", ...F, value: "The sweep returned 0 hits over 111.7 M key offsets: no live state is in the dump", source: "the dump", evidence: "the sweep", refs: ["job:j000001/hits.txt"] }), /^this negative finding rests on your own scanner/);
  assert.equal(P.searchNegative("finding", "No copy of the key was found in the hives"), true);
  assert.equal(P.searchNegative("finding", "Nothing of note in the unrelated output"), false);
  assert.equal(P.searchNegative("finding", "The service was installed at 09:14"), false);
  ok(await rec(c.a0, { kind: "finding", ...F, value: "Nothing of note in the unrelated output", source: "the job's output", evidence: "cat", refs: ["job:j000001/hits.txt"] }));
  // What a control is: a job's output and what the scanner found in it; a run that worked.
  refused(await rec(c.a0, { ...absence, control: { ref: "job:j000021/control.txt" } }), /control is \{ref, found\}: the job in which the same scanner found a planted or known value/);
  refused(await rec(c.a0, { ...absence, control: { ref: "input:disk.E01", found: "the key" } }), /control\.ref names a job's output .*"input:disk\.E01" is not one/);
  refused(await rec(c.a0, { ...absence, control: { ref: "job:j000004/hits.txt", found: "the key" } }), /control\.ref names job:j000004\/hits\.txt, whose job failed: a control is a run that worked and found the planted value/);
  refused(await rec(c.a0, { ...absence, control: { ref: "job:j000021/nope.txt", found: "the key" } }), /control\.ref: ref "job:j000021\/nope\.txt" does not resolve/);
  const held = ok(await rec(c.a0, { ...absence, control: { ref: "job:j000021/out/control.txt", found: "the planted state at offset 4096, by the same layout" } })).entry as Negative;
  assert.deepEqual(held.control, [{ ref: "job:j000021/control.txt", found: "the planted state at offset 4096, by the same layout" }]);
  // A pack tool that ended ok reports what it covered: no control asked. A search recorded as failed claims nothing.
  ok(await rec(c.a0, { ...absence, value: "the needle in any chunk", refs: ["job:j000020/report.json"] }));
  ok(await rec(c.a0, { ...absence, value: "a live cipher state (the sweep died)", completion: "failed" }));
  // control is a negative's: a fact that is none does not take it.
  refused(await rec(c.a1, { kind: "answer", section: "question:1", value: "x", reasoning: "E-1", ...A, result: "established", control: { ref: "job:j000021/control.txt", found: "f" } }), /control is not an answer's/);
});

test("a negative about pictures lists the images read, and the sheets of the cited job its recorder was not handed hold the answer that rests on it until they are read", async () => {
  const c = await run();
  const sheets = Array.from({ length: 11 }, (_, i) => `m/m${String(i + 1).padStart(2, "0")}.png`);
  await jobWith(c.S, "j000030", [...sheets, "edge.txt"], { spec: { kind: "command", inputs: ["input:disk.E01"], command: "ffmpeg … tile=5x4 m/m%02d.png" } });
  for (const s of sheets.slice(0, 3)) await traceRead(c.S, "a0", `store/jobs/j000030/out/${s}`);
  // Another seat's read is not the recorder's, and a read that failed handed nothing.
  await traceRead(c.S, "a1", "store/jobs/j000030/out/m/m04.png");
  await traceRead(c.S, "a0", "store/jobs/j000030/out/m/m05.png", false);
  await planned(c.a0, "1");
  const finding = { kind: "finding", ...F, value: "None of the one-per-second frames of the clip shows burned-in text", source: "job:j000030/m/", evidence: "read by eye, 5x4 tiles", refs: ["job:j000030/m/m01.png"], answers: ["1"] };
  const r = ok(await rec(c.a0, { ...finding, images_read: ["job:j000030/m/m01.png", "job:j000030/m/m09.png"] }));
  const e = r.entry as Negative;
  assert.deepEqual(e.images_read, ["job:j000030/m/m01.png", "job:j000030/m/m02.png", "job:j000030/m/m03.png"], "what the trace shows the recorder was handed, whatever it listed");
  assert.deepEqual(e.images_unread, [{ job: "j000030", dir: "m", total: 11, unread: sheets.slice(3).map((s) => s) }]);
  assert.match(r.note ?? "", /images_read names job:j000030\/m\/m09\.png, which the trace does not show you were handed by read: left out of images_read/);
  assert.match(r.note ?? "", /a negative about pictures holds for the pictures read, and the trace shows you were not handed 8 of the 11 images of job:j000030\/m \(m04\.png, m05\.png, m06\.png, m07\.png, m08\.png, m09\.png, m10\.png, m11\.png\): recorded with them named \(images_unread\), and an answer that cites this entry is held \(negative_images_unread\) until you read them and record it again with supersedes/);
  // The answer that rests on it is held, with the sheets named.
  const a = ok(await rec(c.a1, { kind: "answer", section: "question:1", value: "No text is shown in the clip's frames", reasoning: `E-${e.seq}`, ...A, result: "partial", parts: [{ id: "frames", part: "the sampled frames", status: "established", refs: [`E-${e.seq}`] }, { id: "rest", part: "the frames between the samples", status: "open", open_by: await planned(c.a1, "1") }] })).entry;
  const gate = async () => P.ledgerGate({ entries: await P.readLedger(c.S), attestations: await P.readAttestations(c.S), disputes: await P.readDisputes(c.S), sections: ["1"] });
  let held = (await gate()).defects.filter((d) => d.code === "negative_images_unread");
  assert.equal(held.length, 1);
  assert.deepEqual(held[0]!.seqs, [a.seq, e.seq]);
  assert.match(held[0]!.what, new RegExp(`answer #${a.seq} \\(question:1\\) rests on E-${e.seq}, a negative about pictures recorded with 8 of the 11 images of job:j000030/m \\(m04\\.png, .*m11\\.png\\) never handed to its recorder`));
  assert.ok((await gate()).open.some((d) => d.code === "negative_images_unread"), "it holds the finish line");
  // The sheets are read and the entry recorded again: nothing is unread, and the hold goes with the answer's next record.
  for (const s of sheets.slice(3)) await traceRead(c.S, "a0", `store/jobs/j000030/out/${s}`);
  const again = ok(await rec(c.a0, { ...finding, value: "None of the 11 sheets of one-per-second frames of the clip shows burned-in text", supersedes: e.seq })).entry as Negative;
  assert.equal(again.images_unread, undefined);
  assert.equal(again.images_read?.length, 11);
  ok(await rec(c.a1, { kind: "answer", section: "question:1", value: "No text is shown in the clip's frames", reasoning: `E-${again.seq}`, ...A, result: "partial", parts: [{ id: "frames", part: "the sampled frames", status: "established", refs: [`E-${again.seq}`] }, { id: "rest", part: "the frames between the samples", status: "open", open_by: "L-1" }], supersedes: a.seq }));
  held = (await gate()).defects.filter((d) => d.code === "negative_images_unread");
  assert.deepEqual(held, []);
  // A positive finding over one image is no negative: nothing is listed, nothing held; images_read is a negative's.
  const seen = ok(await rec(c.a0, { kind: "finding", ...F, value: "The caption on sheet 6 reads a 22-character string", source: "job:j000030/m/m06.png", evidence: "read by eye", refs: ["job:j000030/m/m06.png"] })).entry as Negative;
  assert.equal(seen.images_unread, undefined);
  refused(await rec(c.a0, { kind: "finding", ...F, value: "The caption on sheet 6 reads a 22-character string, twice", source: "s", evidence: "e", images_read: ["job:j000030/m/m06.png"] }), /images_read is a negative's/);
});

test("a finding at high confidence that five later entries stand on and nobody reviewed is warned of, and no longer once another seat attests or disputes it", async () => {
  const c = await run();
  await planned(c.a0, "1");
  const premise = ok(await rec(c.a0, { kind: "finding", ...F, value: "The key and the nonce are runtime-only values", source: "the disassembly", evidence: "lines 640-680", refs: ["job:j000001/hits.txt"], answers: ["1"] })).entry;
  const medium = ok(await rec(c.a0, { kind: "finding", ...F, confidence: "medium", value: "The note names no key", source: "the note", evidence: "read whole", refs: ["job:j000001/hits.txt"] })).entry;
  const citers: number[] = [];
  for (let i = 0; i < 4; i += 1) citers.push(ok(await rec(i % 2 ? c.a1 : c.a2, { kind: "finding", ...F, confidence: "medium", value: `Search design ${i}: memory only, since E-${premise.seq} rules the binary out (and E-${medium.seq})`, source: "the plan", evidence: `follows E-${premise.seq}`, refs: ["job:j000002/hits.txt"] })).entry.seq);
  assert.deepEqual(P.premisesUnreviewed(await P.readLedger(c.S), await P.readAttestations(c.S), []), [], `four citers are under the bar of ${P.PREMISE_CITERS_MIN}`);
  citers.push(ok(await rec(c.a1, { kind: "limitation", value: "The binary was not searched for the nonce", source: "mssetup.exe", evidence: "ruled out by the finding", reason: "not_examined", rel: [{ to: premise.seq, kind: "derived_from" }] })).entry.seq);
  const found = P.premisesUnreviewed(await P.readLedger(c.S), await P.readAttestations(c.S), []);
  assert.deepEqual(found.map((p) => [p.entry.seq, p.citers]), [[premise.seq, citers]], "the high one, not the medium one the same entries cite");
  const gate = async () => P.ledgerGate({ entries: await P.readLedger(c.S), attestations: await P.readAttestations(c.S), disputes: await P.readDisputes(c.S), sections: ["1"] });
  const w = (await gate()).warnings.filter((x) => x.code === "premise_unreviewed");
  assert.equal(w.length, 1);
  assert.equal(w[0]!.section, "question:1");
  assert.match(P.warningWords(w[0]!), new RegExp(`E-${premise.seq} \\(a finding at high confidence, recorded by a0, reviewed by nobody\\) is what ${citers.map((n) => `E-${n}`).join(", ")} rest on.*a seat other than a0 re-derives E-${premise.seq} from its refs and attests it, or disputes it with what it found`));
  assert.equal((await gate()).open.some((d) => (d.code as string) === "premise_unreviewed"), false, "a warning: it holds nothing");
  // Another seat's attest is a review: nothing to warn of.
  assert.ok((await P.attestEntry(c.a3, { seq: premise.seq, how: "re-read lines 640-680 of the disassembly from job:j000001", refs: ["job:j000001/hits.txt"] })).ok);
  assert.deepEqual((await gate()).warnings.filter((x) => x.code === "premise_unreviewed"), []);
});
