/**
 * The report's body (scripts/report-body.ts), held to the ledger version 4
 * fixture (tests/fixtures/ledger-v4): a small run whose ledger holds every
 * kind of entry and act, with a legacy prefix, a superseded answer, a
 * dispute, a failed job, an import and a defect a limitation names.
 *
 * What is pinned: every section is there and in order; each answer block runs
 * its steps in the fixed order; the answer shown is the one that stands; each
 * chip is where the fixture says it belongs and nowhere it does not;
 * corroboration is counted by evidence object; nothing a run wrote becomes
 * markup; the Markdown carries the same; nothing is cut; the DRAFT mark goes
 * only when a release v1 is said to exist; an old run renders as what it is.
 */
import assert from "node:assert/strict";
import { cp, mkdir, mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { after, test } from "node:test";
import { humanReviewFrom, parseGoal, renderReportBody, renderReportBodyMarkdown, reportBodyDocument, type HumanReview } from "../scripts/report-body.ts";
import type { ReviewState } from "../scripts/report.ts";

const ROOT = join(dirname(fileURLToPath(import.meta.url)), "..");
const FIXTURE = join(ROOT, "tests", "fixtures", "ledger-v4");
const scratch: string[] = [];
after(async () => {
  for (const d of scratch) await rm(d, { recursive: true, force: true });
});

async function tempDir(): Promise<string> {
  const d = await mkdtemp(join(tmpdir(), "report-body-"));
  scratch.push(d);
  return d;
}

/** A copy of the fixture run, with whatever extra files a test gives it. */
async function fixtureCopy(extra: Record<string, string> = {}): Promise<string> {
  const d = join(await tempDir(), "run");
  await cp(FIXTURE, d, { recursive: true });
  for (const [rel, text] of Object.entries(extra)) {
    await mkdir(dirname(join(d, rel)), { recursive: true });
    await writeFile(join(d, rel), text);
  }
  return d;
}

/** A run written by hand: entries (unchained, as a pre-chain ledger's are), jobs, and any files. */
async function handRun(o: { entries: Array<Record<string, unknown>>; jobs?: Record<string, Record<string, unknown>>; files?: Record<string, string> }): Promise<string> {
  const d = join(await tempDir(), "run");
  await mkdir(join(d, "ledger"), { recursive: true });
  await writeFile(join(d, "ledger", "entries.jsonl"), o.entries.map((e) => JSON.stringify(e)).join("\n") + "\n");
  for (const [id, job] of Object.entries(o.jobs ?? {})) {
    await mkdir(join(d, "store", "jobs", id), { recursive: true });
    await writeFile(join(d, "store", "jobs", id, "job.json"), JSON.stringify({ id, ...job }));
  }
  for (const [rel, text] of Object.entries(o.files ?? {})) {
    await mkdir(dirname(join(d, rel)), { recursive: true });
    await writeFile(join(d, rel), text);
  }
  return d;
}

/** The HTML from an anchor id to the next element with one of the given ids (or the end). */
function slice(html: string, id: string, next?: string): string {
  const start = html.indexOf(`id="${id}"`);
  assert.ok(start >= 0, `no element with id ${id}`);
  const end = next ? html.indexOf(`id="${next}"`, start) : -1;
  return html.slice(start, end > start ? end : undefined);
}

/** The Markdown under one heading, to the next heading of the same level or above. */
function mdSlice(md: string, heading: string): string {
  const start = md.indexOf(`\n${heading}`);
  assert.ok(start >= 0, `no heading ${heading}`);
  const level = /^#+/.exec(heading)?.[0].length ?? 2;
  const rest = md.slice(start + 1);
  const next = rest.slice(1).search(new RegExp(`\\n#{1,${level}} `));
  return next >= 0 ? rest.slice(0, next + 1) : rest;
}

/** Markdown with its fenced blocks and code spans taken out: what a renderer would read as markup. */
function outsideCode(md: string): string {
  return md.replace(/^(`{3,})[^\n]*\n[\s\S]*?^\1[ \t]*$/gm, "").replace(/(`+)(?:(?!\1)[\s\S])+?\1/g, "");
}

const STEPS = ["How it was obtained", "What it indicates", "Why this confidence", "What else could explain it", "Contrary evidence", "Limitations", "What would change it", "Exhibits"];

test("every section is there, in order, in the HTML and the Markdown", async () => {
  const body = await renderReportBody(FIXTURE);
  const ids = ["s1", "s2", "s3", "s4", "s5", "s6", "s7", "s8", "s9", "s10", "sA", "sB", "sC"];
  assert.deepEqual(body.sections.map((s) => s.id), ids);
  let at = -1;
  for (const id of ids) {
    const i = body.html.indexOf(`<section id="${id}"`);
    assert.ok(i > at, `section ${id} out of order`);
    at = i;
  }
  const titles = ["1. Summary for decision makers", "2. Request, scope and questions", "3. Evidence and its handling", "4. Method and roles", "5. Answers", "6. What happened", "7. Conclusions and opinions", "8. Limitations, negative findings and open questions", "9. Recommendations", "10. Review and adoption", "Appendix A: Exhibits", "Appendix B: Jobs and their method records", "Appendix C: The swarm's working report"];
  const md = await renderReportBodyMarkdown(FIXTURE);
  at = -1;
  for (const t of titles) {
    const i = md.indexOf(`\n## ${t}`);
    assert.ok(i > at, `Markdown section ${t} missing or out of order`);
    at = i;
  }
  // Every exhibit a section links to exists: no dangling E-<seq>.
  for (const m of body.html.matchAll(/href="#e-(\d+)"/g)) assert.ok(body.html.includes(`id="e-${m[1]}"`), `a link to E-${m[1]}, which has no exhibit`);
  for (const m of body.html.matchAll(/href="#(q-[^"]+|job-[^"]+)"/g)) assert.ok(body.html.includes(`id="${m[1]}"`), `a link to #${m[1]}, which is not there`);
});

test("each answer block leads with the answer and runs its steps in the fixed order", async () => {
  const html = (await renderReportBody(FIXTURE)).html;
  for (const [q, next] of [["q-1", "q-2"], ["q-2", "q-3"], ["q-3", "s6"]]) {
    const block = slice(html, q, next);
    const lead = block.indexOf("Answer</span>");
    assert.ok(lead > 0, `${q}: no answer lead`);
    let at = lead;
    for (const step of STEPS) {
      const i = block.indexOf(`<h4>${step}</h4>`);
      assert.ok(i > at, `${q}: "${step}" missing or out of order`);
      at = i;
    }
  }
  const md = await renderReportBodyMarkdown(FIXTURE);
  const q1 = mdSlice(md, "### Question 1");
  let at = q1.indexOf("**Answer**");
  assert.ok(at > 0);
  for (const step of STEPS) {
    const i = q1.indexOf(`#### ${step}`);
    assert.ok(i > at, `Markdown: "${step}" missing or out of order`);
    at = i;
  }
});

test("the answer shown for each section is the one that stands; a superseded one is history", async () => {
  const gate = JSON.parse(await readFile(join(FIXTURE, "gate.json"), "utf8")) as { answers: Record<string, number> };
  const html = (await renderReportBody(FIXTURE)).html;
  for (const [q, next, section] of [["q-1", "q-2", "question:1"], ["q-2", "q-3", "question:2"], ["q-3", "s6", "question:3"]]) {
    assert.match(slice(html, q, next), new RegExp(`<a href="#e-${gate.answers[section]}">E-${gate.answers[section]}</a>, recorded by`));
  }
  const q2 = slice(html, "q-2", "q-3");
  assert.match(q2, /At least one command ran through the shell/);
  // E-15, the answer the dispute brought down, is not shown as the answer.
  assert.doesNotMatch(q2, /Commands were run through the shell for about two minutes/);
  assert.match(q2, /it replaces <a href="#e-15">E-15<\/a> \(superseded: <a href="#e-6">E-6<\/a> was disputed/);
  const e15 = slice(html, "e-15", "e-16");
  assert.match(e15, /chip-brick">superseded by E-19</);
  // The narrative: E-20 stands, E-18 is history.
  const s6 = slice(html, "s6", "s7");
  assert.match(s6, /<a href="#e-20">E-20<\/a>, recorded by a3/);
  assert.match(s6, /disputed as commands/);
  assert.match(s6, /it replaces <a href="#e-18">E-18<\/a>/);
  // A superseded finding cited with its correction is history, not support.
  const q3 = slice(html, "q-3", "s6");
  assert.match(q3, /cites 1 superseded entry for their history/);
  assert.match(q3, /History only<\/dt><dd>superseded by <a href="#e-9">E-9<\/a>/);
});

test("chips: disputed, qualified, legacy, superseded, unsupported tokens, attested — each where it belongs", async () => {
  const html = (await renderReportBody(FIXTURE)).html;
  const chips = (id: string, next: string) => [...slice(html, id, next).split("<dl>")[0].matchAll(/class="chip chip-\w+">([^<]+)</g)].map((m) => m[1]);
  // E-6 is disputed, and why is shown.
  assert.ok(chips("e-6", "e-7").includes("disputed"));
  assert.match(slice(html, "e-6", "e-7"), /Disputed<\/dt><dd>by a2 at [^:]+:\d\d:[\d.]+Z: response sizes alone do not show execution/);
  // E-9's dispute was withdrawn: not disputed now, the history kept.
  assert.ok(!chips("e-9", "e-13").includes("disputed"));
  assert.match(slice(html, "e-9", "e-13"), /Dispute withdrawn<\/dt><dd>a0 disputed it \(the import was copied live and may be incomplete\) and withdrew/);
  // E-7 rests on a job that timed out and says why its bytes hold.
  assert.ok(chips("e-7", "e-8").includes("qualified (failed job)"));
  assert.match(slice(html, "e-7", "e-8"), /job j000002 ended timed_out/);
  // E-2 is a version 3 finding: no interpretation was recorded; E-5 (version 4) has one.
  assert.ok(chips("e-2", "e-5").includes("interpretation not recorded"));
  assert.ok(!chips("e-5", "e-6").includes("interpretation not recorded"));
  assert.match(slice(html, "e-5", "e-6"), /class="v-interpretation">The shell arrived through the site/);
  // Superseded, and by what.
  assert.ok(chips("e-8", "e-9").includes("superseded by E-9"));
  assert.ok(!chips("e-9", "e-13").some((c) => c.startsWith("superseded")));
  // Unsupported tokens, with the tokens listed.
  assert.ok(chips("e-16", "e-17").includes("unsupported tokens"));
  assert.match(slice(html, "e-16", "e-17"), /<code>0123456789abcdef0123456789abcdef<\/code>/);
  assert.match(slice(html, "e-15", "e-16"), /<code>\/var\/www<\/code>/);
  assert.match(slice(html, "q-3", "s6"), /Unsupported tokens: <\/strong>.*<code>0123456789abcdef0123456789abcdef<\/code>/);
  // Attested (an agent) and reviewed (a human) are two chips, never one.
  assert.ok(chips("e-5", "e-6").includes("attested by a2"));
  assert.ok(chips("e-5", "e-6").includes("not independently reviewed"));
  assert.ok(chips("e-6", "e-7").includes("not attested"));
  // The co-author of a version 1 attestation is not a check.
  assert.match(slice(html, "e-3", "e-10"), /Also recorded by<\/dt><dd>a1, word for word, at [^:]+:\d\d:[\d.]+Z: a second author, not a check/);
  // The summary no longer stands on its support, and the limitation that names that is shown.
  assert.ok(chips("e-17", "e-18").includes("no longer stands on its support"));
  assert.match(slice(html, "s1", "s2"), /It no longer stands on its support: <\/strong>it rests on <a href="#e-15">E-15<\/a>, superseded by #19.*A limitation names this \(<a href="#e-21">E-21<\/a>\)/);
  assert.match(slice(html, "s8", "s9"), /answer #17 \(summary\) no longer stands on its support.*Named by <a href="#e-21">E-21<\/a>/);
  // Answers are opinions; findings are observed or inferred.
  assert.ok(chips("e-14", "e-15").includes("opinion"));
  assert.ok(chips("e-6", "e-7").includes("inferred"));
  assert.ok(!chips("e-6", "e-7").includes("opinion"));
});

test("corroboration is counted by evidence object, not by ref or job", async () => {
  const html = (await renderReportBody(FIXTURE)).html;
  // Question 1 rests on the E01 (through job j000001) and the access log: two groups.
  assert.match(slice(html, "q-1", "q-2"), /2 corroboration groups by evidence object\./);
  // E-5 cites both; E-7 one job over the E01; E-6 the log alone.
  assert.match(slice(html, "e-5", "e-6"), /2 corroboration groups by evidence object\./);
  assert.match(slice(html, "e-7", "e-8"), /1 corroboration group by evidence object: every ref traces to one source \(single-source\)/);
  // The import's file was made by an agent: its origin is not recorded.
  assert.match(slice(html, "e-9", "e-13"), /chip-saffron">origin not recorded</);
  // The summary reaches through its answers: the E01 (two jobs, one source), the log, the import.
  const e17 = slice(html, "e-17", "e-18");
  assert.match(e17, /3 corroboration groups/);
  assert.match(e17, /inputs\/web\.E01 — <a href="#e-4">E-4<\/a>, <a href="#e-5">E-5<\/a>, <a href="#e-7">E-7<\/a> \(job:j000001\/fls\.txt, job:j000002\/partial\.txt\)/);

  // Two jobs over one E01 are one source; a job with scope all is its own, of unknown independence.
  const run = await handRun({
    jobs: {
      j000001: { spec: { kind: "command", inputs: ["input:disk.E01"], command: "a" }, status: "ok" },
      j000002: { spec: { kind: "command", inputs: ["input:inputs/disk.E01"], command: "b" }, status: "ok" },
      j000003: { spec: { kind: "command", inputs: ["all"], command: "c" }, status: "ok" },
      j000004: { spec: { kind: "command", inputs: ["job:j000001"], command: "d" }, status: "ok" },
    },
    entries: [
      { v: 4, seq: 1, kind: "finding", value: "two jobs, one image", refs: ["job:j000001/a.txt", "job:j000002/b.txt"], basis: "observed", confidence: "high", indicates: "x", confidence_why: "y", by: "a0", authors: ["a0"], at: "2026-01-01T00:00:00Z" },
      { v: 4, seq: 2, kind: "finding", value: "a job with scope all", refs: ["job:j000003/c.txt", "input:disk.E01"], basis: "observed", confidence: "high", indicates: "x", confidence_why: "y", by: "a0", authors: ["a0"], at: "2026-01-01T00:00:01Z" },
      { v: 4, seq: 3, kind: "finding", value: "a job over a job over the image", refs: ["job:j000004/d.txt", "input:disk.E01"], basis: "observed", confidence: "high", indicates: "x", confidence_why: "y", by: "a0", authors: ["a0"], at: "2026-01-01T00:00:02Z" },
    ],
  });
  const h = (await renderReportBody(run)).html;
  assert.match(slice(h, "e-1", "e-2"), /1 corroboration group by evidence object/);
  assert.match(slice(h, "e-1", "e-2"), /chip-saffron">single-source</);
  assert.match(slice(h, "e-2", "e-3"), /2 corroboration groups/);
  assert.match(slice(h, "e-2", "e-3"), /chip-saffron">independence unknown</);
  assert.match(slice(h, "e-2", "e-3"), /job j000003 declared scope all: it could read every input, so its independence is unknown/);
  assert.match(slice(h, "e-3", "sB"), /1 corroboration group by evidence object/);
});

test("nothing a run wrote becomes markup", async () => {
  const evil = `<script>alert(1)</script><img src=x onerror="alert(2)"> & "quotes" ' E-1 E-999 \`code\` <a href="javascript:x">y</a>`;
  const run = await handRun({
    files: {
      "SWARM.md": `# Swarm contract\n\nCase \`${evil}\` · examiner x\n\n## Goal\n\n${evil}\n\n### Questions the report has to answer\n\n1. ${evil}\n2. Recommend what to do. ${evil}\n\n## Caps\n\n- Spend: ${evil}\n`,
      "names.json": JSON.stringify({ names: [{ id: "a0", name: evil, doing: evil, at: "2026-01-01T00:00:00Z" }] }),
      "team.json": JSON.stringify({ swarm_id: evil, agents: [{ id: "a0", model: evil }] }),
      "inputs.json": JSON.stringify({ source: evil, files: [{ path: `inputs/${evil}`, sha256: "a".repeat(64), bytes: 1 }] }),
      "work/report.md": `# ${evil}\n\n${evil}\n\n| a | b |\n| - | - |\n| ${evil} | x |\n`,
    },
    jobs: { j000001: { spec: { kind: "command", inputs: [`input:${evil}`], command: evil, network: evil }, status: evil, image: evil, image_digest: evil, requester: { agent: evil, doing: evil } } },
    entries: [
      { v: 4, seq: 1, kind: "finding", value: evil, source: evil, evidence: evil, refs: ["job:j000001/x", evil], basis: "inferred", confidence: "low", indicates: evil, confidence_why: evil, alternatives: [{ explanation: evil, status: "open", why: evil, test_refs: [evil] }], answers: ["1", evil], by: "a0", authors: ["a0"], at: evil, qualifies: [{ ref: evil, why: evil }] },
      { v: 4, seq: 2, kind: "event", ts: "2026-01-01T00:00:00Z", ts_raw: evil, clock: evil, precision: "second", value: evil, source: evil, by: "a0", authors: ["a0"], at: evil },
      { v: 4, seq: 3, kind: "answer", section: `question:${evil}`, value: evil, reasoning: `${evil} E-1`, confidence: "low", confidence_why: evil, alternatives_open: evil, would_change: evil, support: [{ seq: 1, hash: evil }], unsupported_tokens: [evil], by: "a0", authors: ["a0"], at: evil },
      { v: 4, seq: 4, kind: "answer", section: "summary", value: evil, reasoning: evil, support: [{ seq: 3, hash: evil }], by: "a0", authors: ["a0"], at: evil },
    ],
  });
  const body = await renderReportBody(run);
  const page = reportBodyDocument(body);
  // Every tag in the page is one the renderer writes, with only its own attributes.
  for (const [tag] of page.matchAll(/<[^>]+>/g)) {
    assert.match(
      tag,
      /^<\/?(?:!doctype html|html|meta|title|style|body|main|nav|section|div|span|p|h[1-6]|ul|ol|li|dl|dt|dd|table|thead|tbody|tr|th|td|pre|code|strong|em|a|br|blockquote|hr)(?:\s+(?:class|id|href|aria-hidden|aria-label|lang|charset|name|content)="[^"<>]*")*>$/i,
      `the page holds ${tag}`,
    );
    for (const href of tag.matchAll(/href="([^"]*)"/g)) assert.ok(href[1].startsWith("#"), `a link out of the page: ${href[1]}`);
  }
  assert.doesNotMatch(page, /<script|<img|javascript:x">/i);
  assert.match(page, /&lt;script&gt;alert\(1\)&lt;\/script&gt;/);
  // E-1 exists and is linked; E-999 does not, and is left as text.
  assert.match(body.html, /<a href="#e-1">E-1<\/a>/);
  assert.doesNotMatch(body.html, /href="#e-999"/);
  // In the Markdown, HTML stays inert: outside code it is escaped, inside code it is text.
  const md = await renderReportBodyMarkdown(run);
  assert.doesNotMatch(outsideCode(md), /<script|<img|<a href/i);
  assert.match(md, /&lt;script>alert\(1\)&lt;\/script>/);
});

test("the Markdown carries the body: sections, answers, chips as code spans, exhibits, the working report fenced", async () => {
  const run = await fixtureCopy({ "work/report.md": "# The swarm's own words\n\n## 1. Something\n\nA claim the ledger does not hold.\n" });
  const md = await renderReportBodyMarkdown(run);
  assert.match(md, /^# DRAFT — /);
  assert.match(md, /### Question 2 `answered`/);
  assert.match(md, /> At least one command ran through the shell/);
  assert.match(md, /`single-source`/);
  assert.match(md, /`qualified \(failed job\)`/);
  assert.match(md, /`interpretation not recorded`/);
  assert.match(md, /`superseded by E-19`/);
  assert.match(md, /#### E-16 `answer`/);
  assert.match(md, /`0123456789abcdef0123456789abcdef`/);
  assert.match(md, /- \*\*Confidence:\*\* high: Two independent authoritative records/);
  // Emphasis closes before its trailing space, or a renderer leaves the stars.
  assert.doesNotMatch(md, /\*\*[^*\n]*\s\*\*\S/);
  const c = md.slice(md.indexOf("\n## Appendix C: The swarm's working report"));
  assert.match(c, /The agents' working document\./);
  assert.match(c, /```\n# The swarm's own words\n\n## 1\. Something\n\nA claim the ledger does not hold\.\n\n```/);
  // Its headings stay inside the fence: the body's outline is the body's.
  assert.equal((md.match(/^## 1\. /gm) ?? []).length, 2);
});

test("nothing is cut: a long value, reasoning, command and working report arrive whole", async () => {
  const long = (tag: string, n: number) => `${tag}-start ${"abcdefghij ".repeat(Math.ceil(n / 11))}${tag}-end`;
  const value = long("value", 5_000);
  const reasoning = `${long("reasoning", 20_000)} E-1`;
  const command = long("command", 10_000);
  const report = long("report", 100_000);
  const run = await handRun({
    files: { "work/report.md": report, "SWARM.md": `## Goal\n\nThe request.\n\n### Questions\n\n1. ${long("question", 3_000)}\n` },
    jobs: { j000001: { spec: { kind: "command", inputs: ["input:x"], command }, status: "ok" } },
    entries: [
      { v: 4, seq: 1, kind: "finding", value, refs: ["job:j000001/o"], basis: "observed", confidence: "high", indicates: long("indicates", 1_500), confidence_why: "w", answers: ["1"], by: "a0", authors: ["a0"], at: "2026-01-01T00:00:00Z" },
      { v: 4, seq: 2, kind: "answer", section: "question:1", value: long("answer", 2_000), reasoning, confidence: "high", confidence_why: "w", alternatives_open: "none", would_change: "x", support: [{ seq: 1, hash: "h" }], by: "a1", authors: ["a1"], at: "2026-01-01T00:00:01Z" },
    ],
  });
  const html = (await renderReportBody(run)).html;
  const md = await renderReportBodyMarkdown(run);
  for (const text of [value, reasoning.replace(" E-1", ""), command, report, long("indicates", 1_500), long("answer", 2_000), long("question", 3_000)]) {
    assert.ok(html.includes(text), `HTML lost part of ${text.slice(0, 12)}`);
    assert.ok(md.includes(text), `Markdown lost part of ${text.slice(0, 12)}`);
  }
  assert.doesNotMatch(html, /…/);
});

test("DRAFT on every render until the caller says a release v1 exists", async () => {
  const draft = await renderReportBody(FIXTURE);
  assert.equal(draft.draft, true);
  assert.match(draft.html, /<div class="draft-mark" aria-hidden="true">DRAFT<\/div>/);
  assert.match(draft.html, /Release<\/dt><dd>draft: no release v1 exists/);
  assert.match(reportBodyDocument(draft), /<title>DRAFT — /);
  for (const release of [null, { version: 0 }]) assert.equal((await renderReportBody(FIXTURE, { release })).draft, true);
  const v1 = await renderReportBody(FIXTURE, { release: { version: 1, at: "2026-10-01T00:00:00Z" } });
  assert.equal(v1.draft, false);
  assert.doesNotMatch(v1.html, /draft-mark|DRAFT\./);
  assert.match(v1.html, /Release<\/dt><dd>release v1, 2026-10-01T00:00:00Z/);
  assert.doesNotMatch(await renderReportBodyMarkdown(FIXTURE, { release: { version: 2 } }), /DRAFT/);
});

test("review: said plainly when no human reviewed it; an examiner's word is the examiner's, never an agent's", async () => {
  const none = (await renderReportBody(FIXTURE)).html;
  assert.match(slice(none, "s10", "sA"), /No human has reviewed this report\. /);
  assert.match(slice(none, "s4", "s5"), /No human checked any of it/);
  const review: HumanReview = {
    examiner: { name: "E. Xaminer", organisation: "Lab" },
    entries: new Map([[14, { action: "accept", by: "E. Xaminer", at: "2026-10-01T00:00:00Z", note: "re-checked the $MFT row" }]]),
    signed: { by: "E. Xaminer", at: "2026-10-01T01:00:00Z" },
  };
  const html = (await renderReportBody(FIXTURE, { review })).html;
  assert.doesNotMatch(slice(html, "s10", "sA"), /No human has reviewed this report/);
  assert.match(slice(html, "s10", "sA"), /Examiner<\/dt><dd>E\. Xaminer, Lab/);
  assert.match(slice(html, "e-14", "e-15"), /chip-moss">accepted by E\. Xaminer \(examiner\)</);
  // Question 1 was accepted; question 2 is still the swarm's alone, attested or not.
  assert.doesNotMatch(slice(html, "e-14", "e-15").split("<dl>")[0], /not independently reviewed/);
  assert.match(slice(html, "e-19", "e-20").split("<dl>")[0], /attested by a2<\/span> <span class="chip chip-none">not independently reviewed/);
});

test("an old run renders as what it is: no structured answers, interpretation not recorded, the working report labelled", async () => {
  const run = await handRun({
    files: {
      "SWARM.md": "# Swarm contract\n\nCase `c0` · examiner x\n\n## Goal\n\nFind out what happened.\n\n### Questions the report has to answer\n\n1. How did they get in?\n2. What did they take?\n\n## Definition of done\n\n`work/report.md` exists.\n",
      "work/report.md": "# Report\n\n## 1. How\n\nThrough the VPN (#1).\n",
    },
    entries: [
      { v: 3, seq: 1, kind: "finding", value: "A VPN login from a new country", source: "vpn.log", evidence: "line 9", confidence: "high", refs: ["input:vpn.log"], answers: ["1"], by: "a0", authors: ["a0"], at: "2026-01-01T00:00:00Z" },
      { v: 3, seq: 2, kind: "event", ts: "2026-01-01T00:00:00Z", value: "login", source: "vpn.log", precision: "second", by: "a0", authors: ["a0"], at: "2026-01-01T00:00:01Z" },
    ],
  });
  const html = (await renderReportBody(run)).html;
  assert.match(slice(html, "s1", "s2"), /This run predates structured answers \(ledger version 4\)/);
  assert.match(slice(html, "s1", "s2"), /chip-none">no structured answer</);
  assert.match(slice(html, "q-1", "q-2"), /1 entry names this question/);
  assert.match(slice(html, "q-1", "q-2"), /chip-none">interpretation not recorded</);
  assert.match(slice(html, "q-2", "s6"), /No finding, event or search names this question/);
  assert.match(slice(html, "e-1", "e-2"), /Interpretation<\/dt><dd><span class="chip chip-none">interpretation not recorded<\/span> this finding was recorded before findings said what they indicate/);
  const c = slice(html, "sC");
  assert.match(c, /predates structured answers \(ledger version 4\): the answers it gives exist only in this working report, which the ledger does not check/);
  assert.match(c, /The agents' working document\. <\/strong>Reproduced verbatim from work\/report\.md \(sha256 [0-9a-f]{64}\)\. It carries no evidentiary authority/);
  assert.match(c, /Through the VPN \(#1\)\./);
  // No answers, so no gate: the ledger's defects are not invented for it.
  assert.doesNotMatch(html, /Defects left in the ledger/);
});

test("the goal: its request, its numbered questions with their continuation lines, its caps, whether it asks for recommendations", () => {
  const g = parseGoal(
    [
      "# Swarm contract",
      "",
      "Case `c1` · examiner someone",
      "",
      "## Goal",
      "",
      "A host was compromised.",
      "",
      "### Questions the report has to answer",
      "",
      "1. How was access gained? State the hypothesis",
      "   and the evidence.",
      "2) Can this host be cleaned or recovered, and what would it take?",
      "",
      "   Name what must be rotated.",
      "",
      "Answer them in order.",
      "",
      "### Ground rules",
      "",
      "1. Not a question.",
      "",
      "```",
      "## Not a heading",
      "```",
      "",
      "## Caps",
      "",
      "- Spend: $30",
      "- Wall clock: 90 minutes",
    ].join("\n"),
  );
  assert.equal(g.caseLine, "Case `c1` · examiner someone");
  assert.equal(g.request, "A host was compromised.");
  assert.deepEqual(g.questions, [
    { id: "1", text: "How was access gained? State the hypothesis and the evidence." },
    { id: "2", text: "Can this host be cleaned or recovered, and what would it take? Name what must be rotated." },
  ]);
  assert.deepEqual(g.caps, ["Spend: $30", "Wall clock: 90 minutes"]);
  assert.deepEqual(g.recommendations, ["2"]);
  assert.equal(parseGoal("## Goal\n\nJust look.\n").recommendations, null);
});

test("a goal's questions and a recommendation question reach §2, §5 and §9", async () => {
  const run = await fixtureCopy({
    "SWARM.md": "# Swarm contract\n\nCase `web-1` · examiner x\n\n## Goal\n\nA web server was breached.\n\n### Questions the report has to answer\n\n1. How did the intruder get in?\n2. What did they run?\n3. What did they take? Recommend what to rotate.\n4. Who were they?\n",
  });
  const body = await renderReportBody(run);
  assert.equal(body.title, "web-1 — Forensic report, run run");
  const html = body.html;
  assert.match(slice(html, "s2", "s3"), /Question 1\. <\/strong>How did the intruder get in\?/);
  assert.match(slice(html, "q-1", "q-2"), /Question 1: How did the intruder get in\?/);
  // Question 4 has no answer, and the report says so where a reader looks.
  assert.match(slice(html, "q-4", "s6"), /No answer was recorded for this question\./);
  assert.match(slice(html, "s1", "s2"), /Question 4<\/a><\/td><td><span class="chip chip-brick">not answered</);
  assert.match(slice(html, "s8", "s9"), /Question 4<\/a>: <span class="chip chip-brick">not answered<\/span>/);
  assert.match(slice(html, "s8", "s9"), /question:4 has no answer\. What would repair it/);
  assert.match(slice(html, "s9", "s10"), /The goal asks for recommendations in Question 3\./);
  assert.match(slice(html, "s9", "s10"), /Data was staged in \/tmp\/www\.tgz/);
});

test("report.ts's review state maps onto the body's without either importing the other", async () => {
  const state: ReviewState = {
    lines: 2,
    chain: { ok: true },
    byEntry: new Map([[16, { v: 1, seq: 1, at: "2026-10-01T00:00:00Z", examiner: "E. Xaminer", os_user: "e", host: "h", action: "reject", entry_seq: 16, note: "the proxy log is not the only way out", prev: null }]]),
    signed: { v: 1, seq: 2, at: "2026-10-01T01:00:00Z", examiner: "E. Xaminer", os_user: "e", host: "h", action: "sign", ledger_head: "abc", prev: "x" },
    head: "abc",
  };
  const review = humanReviewFrom(state);
  assert.deepEqual(review?.signed, { by: "E. Xaminer", at: "2026-10-01T01:00:00Z", ledger_head: "abc" });
  const html = (await renderReportBody(FIXTURE, { review })).html;
  assert.match(slice(html, "e-16", "e-17"), /chip-brick">rejected by E\. Xaminer \(examiner\)</);
  assert.match(slice(html, "q-3", "s6"), /The examiner's word: rejected by E\. Xaminer \(examiner\): the proxy log is not the only way out\./);
  assert.deepEqual(humanReviewFrom({ byEntry: new Map(), signed: null, unreadable: "a link, not a file" }), { unreadable: "a link, not a file" });
  assert.equal(humanReviewFrom(null), null);
});

test("the gate holds the run to the goal's questions; a section only an entry names is shown, not demanded", async () => {
  const run = await fixtureCopy({ "SWARM.md": "## Goal\n\nLook.\n\n### Questions\n\n1. One?\n2. Two?\n3. Three?\n" });
  const entries = (await readFile(join(run, "ledger", "entries.jsonl"), "utf8")).trimEnd().split("\n");
  const extra = { ...JSON.parse(entries[1]), seq: 22, answers: ["side-note"], prev: undefined, hash: undefined };
  await writeFile(join(run, "ledger", "entries.jsonl"), `${[...entries, JSON.stringify(extra)].join("\n")}\n`);
  const html = (await renderReportBody(run)).html;
  assert.match(slice(html, "q-side-note", "s6"), /No answer was recorded for this question\./);
  assert.doesNotMatch(slice(html, "s8", "s9"), /question:side-note has no answer/);
});

test("the caller's trace grounding reaches the exhibit; the cover's facts are counted", async () => {
  const body = await renderReportBody(FIXTURE, { grounding: { "5": "grounded", "6": "not in the trace" } });
  assert.deepEqual(body.facts, { questions: 3, answered: 3, hasAnswers: true, entries: 21 });
  assert.match(slice(body.html, "e-6", "e-7"), /chip-saffron">not grounded in the trace</);
  assert.match(slice(body.html, "e-6", "e-7"), /Grounding<\/dt><dd>NOT GROUNDED IN THE TRACE/);
  assert.match(slice(body.html, "e-5", "e-6"), /Grounding<\/dt><dd>a call before this entry was recorded named its source/);
  assert.doesNotMatch(slice(body.html, "e-5", "e-6"), /not grounded in the trace/);
});
