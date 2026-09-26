/**
 * The report. Two things are being pinned here.
 *
 * One: the Markdown renderer really does handle what the delivered reports
 * contain. The corpus under docs/use-cases is the fixture — eighteen reports
 * written by swarms on real cases — and every one of them has to survive the
 * round trip with its headings, tables and code spans intact and nothing of
 * it escaping as raw HTML.
 *
 * Two: the citation lint is the corrected rule, not the one the improvement
 * plan wrote. B10 said a section must cite a path under inputs/, catalog/ or
 * work/; applied to these reports it rejects most of their sections, because
 * a forensic citation is usually an inode, a record id or a registry key.
 */
import assert from "node:assert/strict";
import { mkdir, mkdtemp, readdir, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { test } from "node:test";
import { chainLine, escapeHtml, gatewayLine, gatewayRecordOf, heldRows, hostClockLine, hostEvidenceLine, lintReport, markdownToHtml, renderReport, reproducibilityLine, sourceCheckedLine, vmRows, vmSpendNote } from "../scripts/report.ts";
import { summarize } from "../scripts/summary.ts";
import { takeCustody } from "../scripts/custody.ts";
import { recordEntry, createContext, initSandbox } from "../extensions/protocol.ts";
import { containsName, coverageLine, coverageOf, namesUnderInputs, pathTokens } from "../scripts/coverage.ts";
import { csvCell, ledgerCsv, ledgerTimesketch } from "../scripts/export.ts";
import { parseAnswers, patternOf, scoreRun, scoreText } from "../scripts/score.ts";
import { execFileSync } from "node:child_process";

const ROOT = join(dirname(fileURLToPath(import.meta.url)), "..");
const CASES = join(ROOT, "docs", "use-cases");

async function deliveredReports(): Promise<Array<{ name: string; text: string }>> {
  const out: Array<{ name: string; text: string }> = [];
  async function walk(dir: string, depth: number): Promise<void> {
    if (depth > 3) return;
    for (const entry of await readdir(dir, { withFileTypes: true }).catch(() => [])) {
      const abs = join(dir, entry.name);
      if (entry.isDirectory()) await walk(abs, depth + 1);
      else if (entry.isFile() && entry.name === "report.md") out.push({ name: abs.slice(CASES.length + 1), text: await readFile(abs, "utf8") });
    }
  }
  await walk(CASES, 0);
  return out.sort((a, b) => a.name.localeCompare(b.name));
}

test("every delivered report survives the renderer with nothing escaping as HTML", async () => {
  const reports = await deliveredReports();
  assert.ok(reports.length >= 15, `expected the delivered corpus, got ${reports.length}`);
  for (const { name, text } of reports) {
    const html = markdownToHtml(text);
    assert.ok(html.length > 0, `${name} rendered to nothing`);

    // Nothing in the source may become markup. Rather than hunting for the
    // dangerous forms one at a time — a search that reports `OnTop = False`
    // inside a registry dump as an event handler — enumerate every tag the
    // output contains: the renderer emits a fixed vocabulary and exactly one
    // attribute, so anything else came from the document.
    for (const [tag] of html.matchAll(/<[^>]+>/g)) {
      assert.match(
        tag,
        /^<\/?(?:h[1-6]|p|ul|ol|li|table|thead|tbody|tr|th|td|pre|code|strong|em|blockquote|hr)>$|^<span class="url">$/,
        `${name} produced ${tag}`,
      );
    }

    // Every heading in the source reaches the output as a heading — and a `#`
    // line inside a fence is a shell comment, not a heading, which is why
    // this counts fences rather than hash marks.
    let inFence = false;
    let headings = 0;
    for (const line of text.split("\n")) {
      if (/^```/.test(line)) {
        inFence = !inFence;
        continue;
      }
      if (!inFence && /^#{1,6}\s+\S/.test(line)) headings++;
    }
    const rendered = (html.match(/<h[1-6]>/g) ?? []).length;
    assert.equal(rendered, headings, `${name}: ${headings} headings in, ${rendered} out`);
  }
});

/**
 * A report published as measured rather than as an exemplar, with what it
 * fails on written down.
 *
 * Run 4 is the first run on a Linux server: four agents on a small model,
 * where the earlier runs of that case had seven on large ones. Three of its
 * eight sections cite nothing checkable. The file is what the swarm wrote and
 * is not edited — a report in this repository is evidence of a run, not a
 * model answer — so the lint records the shortfall by name and asserts its
 * size, which is stricter than an exemption: the report may not quietly get
 * worse, and if someone "fixes" the artifact the test says so too.
 */
const AS_MEASURED: Record<string, number> = {
  "dfir-web-server-case/run-4-linux/report.md": 3,
};

test("the citation lint is the corrected rule, and the delivered reports pass it", async () => {
  const reports = await deliveredReports();
  const failures: string[] = [];
  for (const { name, text } of reports) {
    const findings = lintReport(text);
    const allowed = AS_MEASURED[name];
    if (allowed !== undefined) {
      assert.equal(findings.length, allowed, `${name} is published as measured with ${allowed} uncited sections, found ${findings.length}: ${findings.map((f) => f.section).join("; ")}`);
      continue;
    }
    if (findings.length) failures.push(`${name}: ${findings.map((f) => f.section).join("; ")}`);
  }
  assert.deepEqual(failures, [], "every numbered section in the corpus cites something checkable");

  // And the rule still catches a section that cites nothing.
  const bare = lintReport("## 1. What happened\n\nSomebody got in and took the files.\n");
  assert.equal(bare.length, 1);
  assert.match(bare[0].section, /^1\. What happened/);

  // Each accepted form on its own: a code span, an exhibit, an inode, a
  // record id and a registry key.
  for (const body of [
    "The shell is at `c:\\\\inetpub\\\\cmd.aspx`.",
    "See E-14.",
    "MFT inode 126755 carries it.",
    "Record 33194-128-4 holds the data.",
    "HKLM\\\\SYSTEM\\\\CurrentControlSet\\\\Services was changed.",
  ]) {
    assert.deepEqual(lintReport(`## 2. Finding\n\n${body}\n`), [], `should accept: ${body}`);
  }
});

test("the renderer handles the vocabulary, and nothing more", () => {
  const html = markdownToHtml(
    [
      "# Title",
      "",
      "A paragraph with `code`, **bold** and *italic*.",
      "",
      "- one",
      "- two that wraps onto",
      "  a second line",
      "",
      "1. first",
      "2. second",
      "",
      "| A | B |",
      "| --- | --- |",
      "| 1 | 2 |",
      "",
      "> quoted",
      "",
      "```",
      "raw <not> markup",
      "```",
      "",
      "---",
    ].join("\n"),
  );
  assert.match(html, /<h1>Title<\/h1>/);
  assert.match(html, /<code>code<\/code>/);
  assert.match(html, /<strong>bold<\/strong>/);
  assert.match(html, /<em>italic<\/em>/);
  // A soft-wrapped bullet stays inside its item: the tail of a sentence
  // becoming a paragraph outside the list is how a caveat reads as a claim.
  assert.match(html, /<li>two that wraps onto a second line<\/li>/);
  assert.match(html, /<ol>\s*<li>first<\/li>/);
  assert.match(html, /<th>A<\/th><th>B<\/th>/);
  assert.match(html, /<blockquote>/);
  assert.match(html, /<pre><code>raw &lt;not&gt; markup<\/code><\/pre>/);
  assert.match(html, /<hr>/);
});

test("a code span is not reinterpreted as markup", () => {
  const html = markdownToHtml("Use `a **b** c` and `<script>`.");
  assert.match(html, /<code>a \*\*b\*\* c<\/code>/, "markup inside a code span stays literal");
  assert.match(html, /<code>&lt;script&gt;<\/code>/);
  assert.doesNotMatch(html, /<strong>/);
});

test("escapeHtml covers the five characters that matter", () => {
  assert.equal(escapeHtml(`<a href="x">&'`), "&lt;a href=&quot;x&quot;&gt;&amp;'");
});

async function sandboxWithLedger(): Promise<string> {
  const root = await mkdtemp(join(tmpdir(), "report-"));
  await initSandbox(root, { reset: true, swarmId: "sr001", agentIds: ["sr00100", "sr00101"], capUsd: 5, wallClockMinutes: 30, goal: "Establish how the host was compromised." });
  const a = createContext(root, "sr00100");
  for (const entry of [
    { kind: "event", ts: "2026-02-11T02:57:12Z", value: "First request from 203.0.113.24", source: "inputs/u_ex.log", evidence: "line 4418" },
    { kind: "event", ts: "2026-02-11T02:57:52Z", value: "upload.aspx written", source: "MFT", evidence: "inode 33194-128-4" },
    { kind: "ioc", value: "203.0.113.24", source: "inputs/u_ex.log", evidence: "40 requests", confidence: "high" },
    { kind: "finding", value: "Entry was an unauthenticated upload", source: "work/notes.md", evidence: "no 4624 before 02:57:12", confidence: "medium" },
  ] as const) {
    const r = await recordEntry(a, entry);
    if (!r.ok) throw new Error(r.reason);
  }
  await mkdir(join(root, "work"), { recursive: true });
  await writeFile(join(root, "work", "report.md"), "## 1. Entry\n\nThrough `upload.aspx`, inode 33194-128-4.\n", "utf8");
  return root;
}

test("the report is one self-contained file that cites the ledger's own sequence", async () => {
  const root = await sandboxWithLedger();
  try {
    const html = await renderReport(root, { runsDir: join(root, ".."), caseId: "CASE-2026-004", examiner: "H. Ozturkci", now: "2026-02-12T09:00:00.000Z" });

    // A run with no VMs recorded is a host run and says it was unisolated.
    assert.match(html, /host, unisolated: every agent was a process on this machine/);

    // Self-contained: nothing is fetched. The one <style> is inline, the mark
    // is an inline <svg>, and there is no <img>, <link> or <script>.
    assert.doesNotMatch(html, /<script/i);
    assert.doesNotMatch(html, /<link\b/i);
    assert.doesNotMatch(html, /<img\b/i);
    assert.doesNotMatch(html, /\bsrc\s*=\s*["']https?:/i);
    assert.doesNotMatch(html, /@import/i);
    assert.match(html, /<svg[^>]*viewBox="0 0 64 64"/, "the mark is inlined, not linked");

    assert.match(html, /CASE-2026-004/);
    assert.match(html, /H\. Ozturkci/);
    assert.match(html, /2026-02-12T09:00:00\.000Z/, "generated_at is fixed, so two renders match");

    // Exhibit numbers are the ledger's seq, so the console, ledger.jsonl and
    // this document all name the same row.
    assert.match(html, /E-1/);
    assert.match(html, /E-4/);
    // The section head is a number beside the title, not "4." inside it.
    assert.match(html, /<span class="n">4<\/span><h2>Indicators and findings<\/h2>/);
    // The cover carries the numbers a reader needs before the fold.
    assert.match(html, /class="scorecard"/, "the cover has its scorecard");
    assert.match(html, /class="tl"/, "the timeline is a rail, not a five-column table");
    assert.match(html, /class="verdict /, "the findings are verdict cards");
    assert.match(html, /203\.0\.113\.24/);
    assert.match(html, /inode 33194-128-4/);

    // The swarm's own report is reproduced, with its headings demoted so the
    // document keeps one outline.
    assert.match(html, /The swarm's own report \(report\.md\)/);
    assert.match(html, /<h4>1\. Entry<\/h4>/);

    // Two renders with the same `now` are byte-identical.
    const again = await renderReport(root, { runsDir: join(root, ".."), caseId: "CASE-2026-004", examiner: "H. Ozturkci", now: "2026-02-12T09:00:00.000Z" });
    assert.equal(again, html);
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test("a run with nothing recorded says so instead of printing empty sections", async () => {
  const root = await mkdtemp(join(tmpdir(), "report-empty-"));
  try {
    await initSandbox(root, { reset: true, swarmId: "sr002", agentIds: ["sr00200"], capUsd: 1, wallClockMinutes: 5, goal: "Nothing happened here." });
    const html = await renderReport(root, { runsDir: join(root, ".."), now: "2026-02-12T09:00:00.000Z" });
    assert.match(html, /recorded no findings/i);
    assert.match(html, /no timeline/i);
    assert.match(html, /was given no read-only inputs/i);
    // And it says why the document has no conclusions, in the limitations.
    assert.match(html, /did not finish/);
    assert.match(html, /No findings were recorded/);
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test("a run whose every agent died is reported as a failure, not as finished", async () => {
  const root = await mkdtemp(join(tmpdir(), "report-dead-"));
  try {
    await initSandbox(root, { reset: true, swarmId: "sr003", agentIds: ["sr00300"], capUsd: 1, wallClockMinutes: 5, goal: "Nobody finished." });
    await mkdir(join(root, "done"), { recursive: true });
    await writeFile(join(root, "done", "ALL_AGENTS_DEAD"), "---\nby: reaper\nreason: all_agents_dead\nagents_dead: sr00300\nat: 2026-02-12T08:00:00Z\n---\n\nx\n", "utf8");
    const html = await renderReport(root, { runsDir: join(root, ".."), now: "2026-02-12T09:00:00.000Z" });
    assert.match(html, /every agent died/);
    assert.doesNotMatch(html, />finished</);
    assert.match(html, /The swarm did not finish: every agent died/);
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test("the print stylesheet keeps the rules that decide whether the PDF is usable", async () => {
  const root = await sandboxWithLedger();
  try {
    const html = await renderReport(root, { runsDir: join(root, ".."), now: "2026-02-12T09:00:00.000Z" });
    const print = html.slice(html.indexOf("@media print"));
    // Each of these exists because of something that breaks without it.
    assert.match(print, /@page\s*\{[^}]*size:\s*A4/, "the page box");
    assert.match(print, /thead\s*\{\s*display:\s*table-header-group/, "a long timeline repeats its column headers");
    assert.match(print, /\.exhibit[^{]*\{[^}]*break-inside:\s*avoid-page/, "an exhibit is never split");
    assert.match(print, /orphans:\s*3;\s*widows:\s*3/, "no stranded single lines");
    assert.match(print, /break-after:\s*avoid-page/, "a heading never ends a page");
    assert.match(print, /print-color-adjust:\s*exact/, "chips keep their ground");
    // A 64-character hash has to be breakable or it overflows the column.
    assert.match(html, /\.hash\s*\{[^}]*word-break:\s*break-all/);
    // And the document does not claim page numbers it cannot compute.
    assert.match(html, /Section numbers, not page numbers/);
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test("the evidence row says only what the host re-read: yes, NO, or not fully re-hashed", () => {
  const at = "2026-09-24T10:00:00.000Z";
  assert.equal(hostEvidenceLine(null, at), null, "no custody of the evidence, no host line");
  assert.match(hostEvidenceLine({ unverifiable: "no manifest" }, at) ?? "", /^UNVERIFIABLE by the host — no manifest$/);
  assert.equal(
    hostEvidenceLine({ files: 3, unchanged: true, complete: true, changed: [], missing: [], added: [], skipped: [], manifest_anchored: true, checked: { files: 2, links: 1, special: 0 } }, at),
    `yes — re-hashed in full by the host at ${at} (3 files; 1 link checked by target), manifest anchored`,
  );
  // A custody that ran out of time before some files found nothing changed in
  // the rest: not "NO — 0 changed", which reads as evidence that changed.
  const partial = hostEvidenceLine({ files: 3, unchanged: false, complete: false, changed: [], missing: [], added: [], skipped: ["inputs/big.raw"], manifest_anchored: null }, at) ?? "";
  assert.match(partial, /^NOT FULLY RE-HASHED — 2 of 3 files checked unchanged by the host at .*, 1 not re-read before custody's deadline, manifest not anchored \(the kickoff recorded no hash of it\); the rest are not covered$/);
  assert.doesNotMatch(partial, /^NO —/);
  assert.match(hostEvidenceLine({ files: 3, unchanged: false, changed: ["inputs/a"], missing: [], added: [], skipped: ["inputs/b"], manifest_anchored: true }, at) ?? "", /^NO — the host's re-hash found 1 changed, 0 missing, 0 added; 1 not re-read/);
  assert.match(hostEvidenceLine({ files: 1, unchanged: true, changed: [], missing: [], added: [], skipped: [], manifest_anchored: null }, at) ?? "", /manifest not anchored/, "the yes says when the manifest was not anchored");
});

test("the trace line puts a broken chain first, even when nothing is left of the trace", () => {
  assert.match(chainLine({ ok: false, chained: 0, total: 0, broken_at: 0, reason: "shortened" }, true), /^BROKEN at line 0 of 0 — the record is shorter than the anchor says it was/);
  assert.equal(chainLine({ ok: true, chained: 0, total: 0 }), "no trace");
});

test("the provenance and host-clock rows say what the kickoff recorded, and nothing when it recorded nothing", () => {
  assert.equal(reproducibilityLine(null, ["m"]), null);
  assert.equal(reproducibilityLine({ state: "running" }, []), null);
  const line = reproducibilityLine({ provenance: { harness_commit: "abc123def456", harness_dirty: true, pi_version: "0.87.0", node_version: "v24.13.1", msb_version: "0.7.2" }, isolation: { image_digest: "sha256:aa" } }, ["openai/gpt-5.4"]) ?? "";
  assert.match(line, /^harness commit abc123def456 with local changes; Pi 0\.87\.0; Node v24\.13\.1; msb 0\.7\.2; image sha256:aa; models openai\/gpt-5\.4\./);
  assert.match(line, /not deterministic/);
  assert.match(reproducibilityLine({ harness_commit: "abc" }, []) ?? "", /^harness commit abc\./, "top-level fields are read too");
  assert.equal(hostClockLine(null), null);
  assert.equal(hostClockLine({ host_clock: { tz: "Europe/Istanbul", utc_offset: "+03:00", synced: true, source: "timedatectl" } }), "time zone Europe/Istanbul (UTC+03:00); clock synchronised: yes (timedatectl). The harness stamps its own times in UTC.");
  assert.match(hostClockLine({ host_tz: "UTC" }) ?? "", /^time zone UTC; clock synchronised: not known/);
});

test("the report discloses the AI, names each exhibit's model and hash, lists forged tools as unvalidated, and holds custody.json to its anchor", async () => {
  const root = await sandboxWithLedger();
  try {
    await writeFile(
      join(root, "traces", "events.jsonl"),
      `${JSON.stringify({ ts: "2026-02-11T03:00:00Z", agent: "sr00100", tool: "make_tool", args: { name: "evtx_grep", runtime: "python3" }, result: { ok: true, sha256: "e".repeat(64) } })}\n${JSON.stringify({ ts: "2026-02-11T03:01:00Z", agent: "sr00101", tool: "evtx_grep", args: {}, result: { ok: true } })}\n`,
      { flag: "a" },
    );
    const team = JSON.parse(await readFile(join(root, "team.json"), "utf8")) as { agents: Array<{ id: string; model?: string }> };
    team.agents = team.agents.map((a) => ({ ...a, model: "openai/gpt-5.4" }));
    await writeFile(join(root, "team.json"), JSON.stringify(team));
    let html = await renderReport(root, { runsDir: join(root, ".."), now: "2026-02-12T09:00:00.000Z" });
    assert.match(html, /<dt>Prepared by<\/dt><dd>an AI agent swarm \(2 agents\); its findings are the agents' conclusions until an examiner reviews them<\/dd>/);
    assert.match(html, /Prepared by an AI agent swarm\. The findings are the agents' conclusions/);
    assert.match(html, /not deterministic/);
    assert.match(html, /<dt>Model<\/dt><dd>openai\/gpt-5\.4<\/dd>/);
    assert.match(html, /<dt>Entry hash<\/dt><dd class="hash">[0-9a-f]{64}<\/dd>/);
    assert.match(html, /<code>evtx_grep<\/code> by sr00100 \(python3\), called 1 time, sha256 <span class="hash">e{64}<\/span>/);
    assert.match(html, /not independently validated/);
    // custody.json, then edited after the stop.
    const anchorFile = `${root}.custody-anchor.json`;
    try {
      await takeCustody(root);
      html = await renderReport(root, { runsDir: join(root, ".."), now: "2026-02-12T09:00:00.000Z" });
      assert.match(html, /which matches the verdict anchored outside the run/);
      const text = await readFile(join(root, "custody.json"), "utf8");
      await writeFile(join(root, "custody.json"), text.replace(/"summary": "[^"]*"/, '"summary": "evidence unchanged (edited)"'));
      html = await renderReport(root, { runsDir: join(root, ".."), now: "2026-02-12T09:00:00.000Z" });
      assert.match(html, /which DOES NOT MATCH the verdict anchored outside the run/);
    } finally {
      await rm(anchorFile, { force: true });
    }
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test("operator actions from another shell are worded as the operator's, not as lines no pane accounts for", () => {
  const line = chainLine({ ok: true, chained: 5, total: 5, unverified: 3 }, true, true, 2);
  assert.match(line, /2 operator action\(s\) run from a shell outside the run .* runs\/operator-audit\.jsonl/);
  assert.match(line, /1 line\(s\) could not be attributed to a pane/);
  assert.doesNotMatch(chainLine({ ok: true, chained: 2, total: 2, unverified: 1 }, true, true, 1), /could not be attributed/);
});

test("the copy's check against its source is said for exactly what it was: names, kinds and sizes, not content", () => {
  assert.equal(sourceCheckedLine(undefined), null);
  assert.equal(sourceCheckedLine("names, kinds and sizes"), "the copy was checked against its source at kickoff by names, kinds and sizes, not by content (the source itself was not hashed)");
  assert.match(sourceCheckedLine("MISMATCH") ?? "", /did NOT match its source/);
});

test("a removed VM whose finish could not clear msb's database is named", () => {
  const rows = vmRows([
    { agent: "a0", msb_db: "busy" },
    { agent: "a1", msb_db: "scrubbed" },
    { agent: "a2", msb_db: "no database" },
  ]);
  assert.match(rows.find(([k]) => k === "VM a0")?.[1] ?? "", /msb's database NOT cleared after removal \(busy\): a secret's value may remain in msb's database/);
  assert.match(rows.find(([k]) => k === "VM a1")?.[1] ?? "", /msb's database cleared of it after removal/);
  assert.equal(rows.find(([k]) => k === "Secrets in msb's database")?.[1], "NOT CLEARED after removing a0 (busy): a secret's value may remain in msb's database on the host");
});

test("sha1 and md5 stand beside sha256 where the evidence is listed, with the source check; an unreadable trace is not no trace", async () => {
  const root = await sandboxWithLedger();
  try {
    await mkdir(join(root, "inputs"), { recursive: true });
    await writeFile(join(root, "inputs", "a.txt"), "a");
    await writeFile(
      join(root, "inputs.json"),
      JSON.stringify({ source: "/ev", copied_at: "t", held: "copy", files: [{ path: "inputs/a.txt", bytes: 1, sha256: "a".repeat(64), sha1: "b".repeat(40), md5: "c".repeat(32) }], bytes: 1, enforce: "auto", guard: "none", source_checked: "names, kinds and sizes" }),
    );
    let html = await renderReport(root, { runsDir: join(root, ".."), now: "2026-02-12T09:00:00.000Z" });
    assert.match(html, /<th>sha1<\/th><th>md5<\/th>/);
    assert.match(html, new RegExp(`<td class="hash">${"b".repeat(40)}</td><td class="hash">${"c".repeat(32)}</td>`));
    assert.match(html, /checked against its source at kickoff by names, kinds and sizes, not by content/);
    const summary = await summarize(root, { runsDir: join(root, "..") });
    assert.match(summary, /\| Input \| Bytes \| SHA-256 \| SHA-1 \| MD5 \|/);
    assert.match(summary, /not by content/);
    // The trace replaced by a directory: there, and not read.
    await rm(join(root, "traces", "events.jsonl"), { force: true });
    await mkdir(join(root, "traces", "events.jsonl"));
    html = await renderReport(root, { runsDir: join(root, ".."), now: "2026-02-12T09:00:00.000Z" });
    assert.match(html, /NOT READ HERE: the trace could not be read by this report \(not a regular file\)/);
    assert.match(await summarize(root, { runsDir: join(root, "..") }), /The trace is there and could not be read \(not a regular file\)/);
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

// ---------------------------------------------------------------------------
// Coverage and grounding (scripts/coverage.ts): generic path matching over
// any call's arguments; "untouched" means no command named it, and no more.
// ---------------------------------------------------------------------------

async function coverageSandbox(): Promise<string> {
  const root = await mkdtemp(join(tmpdir(), "coverage-"));
  await mkdir(join(root, "traces"), { recursive: true });
  await mkdir(join(root, "ledger"), { recursive: true });
  const raw = Buffer.concat([Buffer.from("inputs/caf"), Buffer.from([0xe9]), Buffer.from(".txt")]);
  await writeFile(
    join(root, "inputs.json"),
    JSON.stringify({
      source: "/ev",
      copied_at: "t",
      held: "copy",
      files: [
        { path: "inputs/notes.txt", bytes: 6, sha256: "a".repeat(64) },
        { path: "inputs/mail/a.bin", bytes: 10, sha256: "b".repeat(64) },
        { path: "inputs/mail/b.bin", bytes: 10, sha256: "c".repeat(64) },
        { path: "inputs/My Docs/x.doc", bytes: 1, sha256: "d".repeat(64) },
        { path: "inputs/deep/z.log", bytes: 1, sha256: "e".repeat(64) },
        { path: "inputs/caf?.txt", path_b64: raw.toString("base64"), bytes: 1, sha256: "f".repeat(64) },
      ],
      bytes: 29,
      enforce: "auto",
      guard: "none",
    }),
  );
  const line = (ts: string, agent: string, tool: string, args: Record<string, unknown>) => JSON.stringify({ ts, agent, tool, args, result: { ok: true } });
  await writeFile(
    join(root, "traces", "events.jsonl"),
    [
      line("2026-01-01T00:00:01Z", "s100", "bash", { command: `strings ${root}/inputs/notes.txt | head` }),
      line("2026-01-01T00:00:02Z", "s100", "bash", { command: 'cat "inputs/My Docs/x.doc"; ls inputs/mail/*.bin' }),
      // A post names a path without reading it; the harness's own lines are not commands.
      line("2026-01-01T00:00:03Z", "s101", "post", { body: "look at inputs/deep/z.log" }),
      line("2026-01-01T00:00:04Z", "s101", "read", { path: "/guest/run/inputs/mail/a.bin" }),
      line("2026-01-01T00:00:05Z", "system", "inputs_check", { path: "inputs/mail/b.bin" }),
      line("2026-01-01T00:00:06Z", "s101", "evtx_dump", { file: "inputs/caf\ufffd.txt" }),
      line("2026-01-01T00:00:07Z", "s100", "bash", { command: "regripper -r work/s100/SAM -p samparse" }),
    ].join("\n") + "\n",
  );
  const entry = (seq: number, source: string, at: string) => JSON.stringify({ v: 2, seq, kind: "finding", value: `v${seq}`, source, evidence: "e", by: "s100", authors: ["s100"], at });
  await writeFile(
    join(root, "ledger", "entries.jsonl"),
    [
      entry(1, "inputs/notes.txt line 3", "2026-01-01T00:00:10Z"),
      entry(2, "C:\\Windows\\System32\\config\\SAM", "2026-01-01T00:00:10Z"),
      entry(3, "memory strings, TCP/IP stack", "2026-01-01T00:00:10Z"),
      // Recorded before the call that read its source: not grounded.
      entry(4, "inputs/mail/a.bin", "2026-01-01T00:00:03Z"),
      entry(5, "HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run", "2026-01-01T00:00:10Z"),
      entry(6, "work/s101/never-read.csv", "2026-01-01T00:00:10Z"),
    ].join("\n") + "\n",
  );
  return root;
}

test("coverage names what no command on the trace named, in any form a path is written, and leaves posts and harness lines out", async () => {
  const root = await coverageSandbox();
  try {
    const c = await coverageOf(root);
    assert.equal(c.unavailable, null);
    assert.equal(c.inputs, 6);
    assert.deepEqual(c.untouched, ["inputs/mail/b.bin", "inputs/deep/z.log"]);
    assert.deepEqual(c.touched, { "inputs/notes.txt": 1, "inputs/mail/a.bin": 1, "inputs/My Docs/x.doc": 1, "inputs/caf?.txt": 1 });
    // A glob names the directory it walks: said beside the file, never as touched.
    assert.deepEqual(c.under_named_dir, { "inputs/mail/b.bin": 1 });
    assert.equal(c.calls_scanned, 5, "the post and the harness's own line are not commands");
    assert.match(coverageLine(c), /^2 of 6 evidence files named by no command on the trace \(5 calls matched\); 1 of those sits under a directory a command named, which a walk may have read\. A file a command named was not necessarily examined\.$/);
    assert.deepEqual(namesUnderInputs('x "inputs/a b/c.txt" inputs/d\\ e.txt inputs/f.txt;'), ["a b/c.txt", "d e.txt", "f.txt"]);
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test("grounding says whether a call before the entry named its source, and never counts prose, a URL or a registry key as a path", async () => {
  const root = await coverageSandbox();
  try {
    assert.deepEqual(pathTokens("memory strings, TCP/IP stack"), []);
    assert.deepEqual(pathTokens("HKLM\\Software\\Run"), []);
    assert.deepEqual(pathTokens("see https://x.example/a.txt"), []);
    assert.deepEqual(pathTokens("Security.evtx record 4624."), ["Security.evtx"]);
    assert.deepEqual(pathTokens("C:\\Windows\\System32\\config\\SAM"), ["C:/Windows/System32/config/SAM"]);
    const c = await coverageOf(root);
    assert.deepEqual(c.grounding, {
      "1": "grounded",
      // Its last component, SAM, was named by the regripper call.
      "2": "grounded",
      "3": "not a path",
      "4": "not in the trace",
      "5": "not a path",
      "6": "not in the trace",
    });
    assert.equal(containsName("cat samples/sam.log", "sam"), false, "a name inside a longer one is not the name");
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test("the ledger exports to CSV and to Timesketch whole, quoted, with corrections, reviews and grounding, and a formula cannot run", async () => {
  const root = await coverageSandbox();
  try {
    const ledger = [
      { v: 2 as const, seq: 1, kind: "event" as const, ts: "2026-01-01T00:00:00.000Z", ts_raw: "2026-01-01T03:00:00+03:00", value: 'Said "hello", then left\nsecond line', source: "inputs/notes.txt", evidence: "=HYPERLINK(\"http://x\")", confidence: "high" as const, by: "s100", authors: ["s100", "s101"], at: "2026-01-01T00:00:10Z", hash: "h1" },
      { v: 2 as const, seq: 2, kind: "finding" as const, value: "-corrected", source: "inputs/notes.txt", evidence: "e", by: "s100", authors: ["s100"], at: "2026-01-01T00:00:11Z", supersedes: 1, hash: "h2", scope: "allocated only" },
    ];
    const csv = ledgerCsv(ledger as never, { review: new Map([[1, "accepted by H at t"]]), grounding: { "1": "grounded", "2": "not in the trace" } });
    const [header, ...rows] = csv.split("\r\n");
    assert.equal(header, "seq,kind,ts,ts_raw,precision,clock,value,source,evidence,confidence,status,reason,completion,basis,answers,rel,attribution,locators,sensitive,by,authors,at,v,supersedes,because,prev,hash,scope,superseded_by,review,grounding");
    assert.match(rows.join("\r\n"), /^1,event,2026-01-01T00:00:00\.000Z,2026-01-01T03:00:00\+03:00,,,"Said ""hello"", then left\nsecond line",inputs\/notes\.txt,"'=HYPERLINK\(""http:\/\/x""\)",high,,,,,,,,,,s100,s100;s101,2026-01-01T00:00:10Z,2,,,,h1,,2,accepted by H at t,grounded$/m);
    assert.match(csv, /\r\n2,finding,,,,,'-corrected,inputs\/notes\.txt,e,,,,,,,,,,,s100,s100,2026-01-01T00:00:11Z,2,1,,,h2,allocated only,,not reviewed,not in the trace\r\n$/);
    // A sensitive entry is exported with its words replaced, its hash kept; the clock is the time's description.
    const secret = [{ v: 3 as const, seq: 3, kind: "event" as const, ts: "2026-01-01T00:00:00.000Z", clock: "NTFS $SI created", value: "the key is 1234", source: "notes", evidence: "cat", sensitive: true, by: "s100", authors: ["s100"], at: "t", hash: "h3" }];
    const red = ledgerCsv(secret as never, { redact: true });
    assert.doesNotMatch(red, /1234/);
    assert.match(red, /\[redacted: marked sensitive\].*h3/);
    assert.match(ledgerTimesketch(secret as never), /,NTFS \$SI created,event,/);
    const ts = ledgerTimesketch(ledger as never);
    assert.match(ts, /^message,datetime,timestamp_desc,kind,source,evidence,confidence,by,seq,hash,superseded_by,review\r\n/);
    assert.match(ts, /,2026-01-01T00:00:00\.000Z,"Event time, as recorded in the ledger",event,/);
    assert.match(ts, /'-corrected,2026-01-01T00:00:11\.000Z,Recorded in the ledger,finding,/);
    assert.equal(csvCell("@SUM(A1)"), "'@SUM(A1)");
    assert.equal(csvCell(7), "7");
    // The CLI writes where --out says, and reads the run's own ledger and trace.
    const out = join(root, "..", `${root.split("/").pop()}.export.csv`);
    try {
      execFileSync(process.execPath, ["--experimental-strip-types", "--no-warnings", join(ROOT, "scripts", "export.ts"), root, "--format", "csv", "--out", out]);
      const written = await readFile(out, "utf8");
      assert.equal(written.split("\r\n").length - 2, 6, "every ledger entry is exported");
      assert.match(written, /,not in the trace\r\n$/);
    } finally {
      await rm(out, { force: true });
    }
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

/** Every file under a directory, with its size and mtime: what a read-only check must leave as it found it. */
async function snapshotTree(dir: string): Promise<Record<string, string>> {
  const out: Record<string, string> = {};
  const { lstat } = await import("node:fs/promises");
  async function walk(d: string): Promise<void> {
    for (const e of await readdir(d, { withFileTypes: true }).catch(() => [])) {
      const p = join(d, e.name);
      const s = await lstat(p);
      out[p] = `${s.size}:${s.mtimeMs}`;
      if (e.isDirectory()) await walk(p);
    }
  }
  await walk(dir);
  return out;
}

test("the accuracy check prints found, not found and contradicted, and writes nothing anywhere", async () => {
  const runs = await mkdtemp(join(tmpdir(), "score-runs-"));
  const root = join(runs, "s1");
  try {
    await mkdir(join(root, "work", "s100"), { recursive: true });
    await mkdir(join(root, "ledger"), { recursive: true });
    await mkdir(join(root, "done"), { recursive: true });
    await writeFile(join(runs, "registry.json"), JSON.stringify({ runs: [{ id: "s1", sandbox: root }] }));
    await writeFile(join(root, "done", "SWARM_DONE"), "---\nby: s100\noutput: work/final.md\n---\n");
    await writeFile(join(root, "work", "final.md"), "# Findings\n\nThe attacker used PuTTY over SSH.\nNot WinSCP.\n");
    await writeFile(join(root, "work", "timeline.csv"), "t,what\n1,logon from 203.0.113.24\n");
    await writeFile(join(root, "work", "s100", "scratch.txt"), "mimikatz in my notes only\n");
    await writeFile(join(root, "ledger", "entries.jsonl"), `${JSON.stringify({ v: 2, seq: 1, kind: "ioc", value: "C2 at 203.0.113.24", source: "s", evidence: "e", by: "s100", authors: ["s100"], at: "t" })}\n`);
    const answers = join(runs, "answers.json");
    await writeFile(
      answers,
      JSON.stringify([
        { id: "q1", question: "Which client?", accept: ["putty"] },
        { id: "q2", question: "C2 address?", accept: ["/203\\.0\\.113\\.2[0-9]/"] },
        { id: "q3", question: "Credential tool?", accept: ["mimikatz"] },
        { id: "q4", question: "Transfer tool?", accept: ["putty"], reject: ["winscp"] },
      ]),
    );
    const result = await scoreRun(root, parseAnswers(await readFile(answers, "utf8")));
    assert.deepEqual(result.results.map((r) => [r.id, r.verdict]), [["q1", "found"], ["q2", "found"], ["q3", "not found"], ["q4", "contradicted"]]);
    assert.ok(result.results[0].found.some((p) => p.where === "the report work/final.md:3"));
    assert.ok(result.results[1].found.some((p) => p.where === "ledger E-1") && result.results[1].found.some((p) => p.where === "work/timeline.csv:2"));
    assert.match(scoreText(result), /2 found, 1 not found, 1 contradicted, of 4\.\nNothing was written: this check is not recorded anywhere\.\n$/);
    assert.equal(patternOf("/a.c/gi").flags, "i", "a global flag would carry position between lines");
    assert.throws(() => parseAnswers('[{"id":"x"}]'), /no accept list/);
    // Run as the operator runs it: nothing in the run, the registry or anywhere under runs/ changes.
    const before = await snapshotTree(runs);
    const printed = execFileSync(process.execPath, ["--experimental-strip-types", "--no-warnings", join(ROOT, "scripts", "score.ts"), root, "--answers", answers], { encoding: "utf8" });
    assert.match(printed, /^q1  FOUND  Which client\?/m);
    assert.deepEqual(await snapshotTree(runs), before, "the check wrote or touched something");
  } finally {
    await rm(runs, { recursive: true, force: true });
  }
});

test("the report shows searches that found nothing, corrections, grounding, coverage and the examiner's signed review, and holds the signature to the ledger's head", async () => {
  const root = await sandboxWithLedger();
  const runs = await mkdtemp(join(tmpdir(), "report-runs-"));
  try {
    const a = createContext(root, "sr00100");
    // A trace that names one input and never the other.
    await writeFile(
      join(root, "traces", "events.jsonl"),
      `${JSON.stringify({ ts: "2026-02-11T02:59:00Z", agent: "sr00100", tool: "bash", args: { command: "grep -n 203.0.113.24 inputs/u_ex.log" }, result: { ok: true } })}\n`,
      { flag: "a" },
    );
    await mkdir(join(root, "inputs"), { recursive: true });
    await writeFile(
      join(root, "inputs.json"),
      JSON.stringify({
        source: "/ev",
        copied_at: "t",
        held: "copy",
        files: [
          { path: "inputs/u_ex.log", bytes: 1, sha256: "a".repeat(64) },
          { path: "inputs/Security.evtx", bytes: 1, sha256: "b".repeat(64) },
        ],
        bytes: 2,
        enforce: "auto",
        guard: "none",
        source_checked: { by: "content", files: 2, mismatches: 0, seconds: 3 },
      }),
    );
    for (const entry of [
      { kind: "absence", value: "No RDP logon (4624 type 10)", source: "inputs/Security.evtx", evidence: "evtx query event id 4624 LogonType 10, tool 1.5, allocated records only" },
      { kind: "finding", value: "Entry was an authenticated upload", source: "work/notes.md", evidence: "a 4624 at 02:57:10", confidence: "medium", supersedes: 4 },
    ]) {
      const r = await recordEntry(a, entry as never);
      if (!r.ok) throw new Error(r.reason);
    }
    await writeFile(
      join(runs, "registry.json"),
      JSON.stringify({ runs: [{ id: "sr001", sandbox: root, disk_encryption: "off", hold: { reason: "litigation", at: "2026-02-12T00:00:00Z", by: "counsel" }, notify: true, allow_root: true }] }),
    );
    const { appendReview } = await import("../scripts/review.ts");
    await appendReview(runs, "sr001", root, { action: "accept", examiner: "H. Examiner", entry_seq: 3 });
    await appendReview(runs, "sr001", root, { action: "reject", examiner: "H. Examiner", entry_seq: 4, note: "not supported by the logon record" });
    await appendReview(runs, "sr001", root, { action: "sign", examiner: "H. Examiner" });
    let html = await renderReport(root, { runsDir: runs, now: "2026-02-12T09:00:00.000Z" });
    assert.match(html, /Searched and not found \(1\)/);
    assert.match(html, /valid only for the stated scope/);
    assert.match(html, /id="e-4">[\s\S]*?superseded by E-6/);
    assert.match(html, /<dt>Corrects<\/dt><dd><a href="#e-4">E-4<\/a>/);
    assert.match(html, /id="e-4">[\s\S]*?NOT GROUNDED IN THE TRACE: no call before this entry was recorded named its source/);
    assert.match(html, /id="e-3">[\s\S]*?<dt>Grounding<\/dt><dd>a call before this entry named its source<\/dd>/);
    assert.match(html, /<th class="num">Named by<\/th>/);
    assert.match(html, /Named by no command: <code>inputs\/Security\.evtx<\/code>/);
    assert.match(html, /checked against its source at kickoff by content: 2 files hashed again from the source, 0 mismatches \(3 s\)/);
    assert.match(html, /id="e-3">[\s\S]*?<dt>Examiner review<\/dt><dd>accepted by H\. Examiner at /);
    assert.match(html, /id="e-4">[\s\S]*?<dt>Examiner review<\/dt><dd>REJECTED by H\. Examiner at [^:]+:\d\d:[^:]+: not supported by the logon record<\/dd>/);
    assert.match(html, /<td>Examiner review<\/td><td class="">1 accepted, 1 rejected, 0 amended, 4 of 6 entries not reviewed; signed by H\. Examiner at \S+ over ledger head [0-9a-f]{64} \(the ledger's current head\); the review file's chain verifies<\/td>/);
    assert.match(html, /<dt>Prepared by<\/dt><dd>an AI agent swarm \(2 agents\); reviewed and signed by H\. Examiner at /);
    assert.match(html, /<td>Disk encryption<\/td><td class="">OFF where the run is kept/);
    assert.match(html, /<td>Legal hold<\/td><td class="">held: litigation, by counsel, at 2026-02-12T00:00:00Z<\/td>/);
    assert.match(html, /<td>Notify hook<\/td><td class="">set \(its command is not recorded\)<\/td>/);
    assert.match(html, /<td>Started as root<\/td>/);
    // An entry recorded after the signature: the signature no longer covers the ledger.
    const late = await recordEntry(a, { kind: "ioc", value: "198.51.100.7", source: "inputs/u_ex.log", evidence: "line 9000", confidence: "low" });
    if (!late.ok) throw new Error(late.reason);
    html = await renderReport(root, { runsDir: runs, now: "2026-02-12T09:00:00.000Z" });
    assert.match(html, /NOT the ledger's current head/);
    const summary = await summarize(root, { runsDir: runs });
    assert.match(summary, /^- Examiner review: 1 accepted, 1 rejected, 0 amended, 5 of 7 entries not reviewed; signed by H\. Examiner/m);
    assert.match(summary, /^- Disk encryption: OFF/m);
    assert.match(summary, /1 searched and not found \(valid only for the scope each states\)/);
    assert.match(summary, /1 corrected by a later entry, kept as recorded: E-4 by E-6\./);
    assert.match(summary, /^Grounding: \d+ entr(y's|ies') source named by no call before the entry was recorded \(.*E-4.*\)\./m);
    assert.match(summary, /^Coverage: 1 of 2 evidence files named by no command on the trace/m);
    // A review file edited by hand no longer verifies.
    const file = join(runs, "reviews", "sr001.jsonl");
    const text = await readFile(file, "utf8");
    await writeFile(file, text.replace("not supported by the logon record", "supported after all"));
    html = await renderReport(root, { runsDir: runs, now: "2026-02-12T09:00:00.000Z" });
    assert.match(html, /the review file's chain is BROKEN/);
  } finally {
    await rm(root, { recursive: true, force: true });
    await rm(runs, { recursive: true, force: true });
  }
});

test("the copy's content check against its source is said with its counts", () => {
  assert.equal(
    sourceCheckedLine({ by: "content", files: 1200, mismatches: 2, seconds: 61.4 }),
    "the copy was checked against its source at kickoff by content: 1200 files hashed again from the source, 2 MISMATCHES (61 s)",
  );
  assert.equal(sourceCheckedLine({ by: "content", files: 1, mismatches: 0 }), "the copy was checked against its source at kickoff by content: 1 file hashed again from the source, 0 mismatches");
  assert.equal(sourceCheckedLine({ by: "names" }), null);
  assert.deepEqual(heldRows({ hold: null, notify: false, disk_encryption: "unknown" }), [
    ["Disk encryption", "not known where the run is kept"],
    ["Legal hold", "not held"],
    ["Notify hook", "none"],
  ]);
  assert.deepEqual(heldRows({ state: "purged" }), [["Legal hold", "the run was PURGED"]]);
});

test("VM spend is the seats' word without the model gateway and the host's with it, naming the providers it did not front", async () => {
  // Wording unchanged without the gateway; nothing for a host run.
  assert.equal(vmSpendNote({ isolation: { mode: "microvm" } }, null), " (as each VM reported its own spend; the host did not meter it)");
  assert.equal(vmSpendNote({ isolation: { mode: "host" } }, null), "");
  assert.equal(vmSpendNote({ isolation: { mode: "microvm", model_gateway: { on: false } } }, null), " (as each VM reported its own spend; the host did not meter it)");
  const fronted = { isolation: { mode: "microvm", model_gateway: { on: true, port: 4100, providers: ["openai", "anthropic"], declined: [] } } };
  assert.equal(vmSpendNote(fronted, { spent_usd: 1.5, seats: { a0: { calls: 3 } } }), " (metered on the host by the model gateway)");
  const partly = { isolation: { mode: "microvm", model_gateway: { on: true, port: 4100, providers: ["openai"], declined: [{ provider: "openrouter", reason: "no usage in its answers" }] } } };
  assert.equal(
    vmSpendNote(partly, { spent_usd: 1, seats: { a0: { calls: 3, unpriced_calls: 2 } } }),
    " (metered on the host by the model gateway for openai; openrouter was not fronted, and that spend is what each VM reported; 2 calls the gateway could not price)",
  );
  assert.equal(
    gatewayLine(gatewayRecordOf(partly)!, { spent_usd: 1.25, seats: { a1: { calls: 2, refused: 1 }, a0: { calls: 3, refused: 0, unpriced_calls: 1 } } }, { lines: 6, intact: true, detail: "6 lines, chain intact" }),
    "on for openai; $1.25 metered on the host across 5 calls; not fronted, so seat-reported: openrouter (no usage in its answers); calls refused by the gateway: a1 1; 1 call it could not price; its log: 6 lines, chain intact (custody)",
  );
  assert.match(gatewayLine(gatewayRecordOf(fronted)!, null, null), /its totals were not found .*; its log was not checked by custody$/);
  assert.match(gatewayLine(gatewayRecordOf(fronted)!, {}, { lines: 2, intact: false, detail: "chain broken at line 2 (prev does not name the line before it)" }), /its log: CHAIN BROKEN \(chain broken at line 2/);
  assert.equal(gatewayRecordOf({ isolation: { mode: "microvm" } }), null);

  // In the report and the summary of a VM run that used it.
  const root = await sandboxWithLedger();
  const runs = await mkdtemp(join(tmpdir(), "report-gw-"));
  try {
    await writeFile(join(runs, "registry.json"), JSON.stringify({ runs: [{ id: "sr001", sandbox: root, cap_usd: 5, ...partly }] }));
    await writeFile(join(root, "traces", "model-gateway.json"), JSON.stringify({ v: 1, run: "sr001", spent_usd: 1.25, updated_at: "t", seats: { sr00100: { calls: 4, refused: 2, spent_usd: 1.25, unpriced_calls: 0, input: 1, output: 1, cache_read: 0, cache_write: 0 } } }));
    const html = await renderReport(root, { runsDir: runs, now: "2026-02-12T09:00:00.000Z" });
    assert.match(html, /cap \(metered on the host by the model gateway for openai; openrouter was not fronted, and that spend is what each VM reported\)/);
    assert.doesNotMatch(html, /the host did not meter it/);
    assert.match(html, /<td>Model gateway<\/td><td class="">on for openai; \$1\.25 metered on the host across 4 calls; not fronted, so seat-reported: openrouter \(no usage in its answers\); calls refused by the gateway: sr00100 2; its log was not checked by custody<\/td>/);
    const summary = await summarize(root, { runsDir: runs });
    assert.match(summary, /^- Isolation: one microVM per agent; spend metered on the host by the model gateway for openai; openrouter was not fronted, and that spend is what each VM reported$/m);
    assert.match(summary, /^- Model gateway: on for openai; \$1\.25 metered on the host; openrouter as reported by the seats$/m);
  } finally {
    await rm(root, { recursive: true, force: true });
    await rm(runs, { recursive: true, force: true });
  }
});

/** A report with a crowded exhibit, a long artifact path and a chip in the last column, for the layout checks. */
async function layoutSandbox(runs: string): Promise<string> {
  const root = join(runs, "sl001");
  await mkdir(root);
  await initSandbox(root, { reset: true, swarmId: "sl001", agentIds: ["sl00100"], capUsd: 5, wallClockMinutes: 30, goal: "g" });
  await writeFile(join(runs, "registry.json"), JSON.stringify({ runs: [{ id: "sl001", sandbox: root }] }));
  await mkdir(join(root, "work", "extracted", "sl00100", "a", "very", "deep", "folder"), { recursive: true });
  await writeFile(join(root, "work", "timeline_of_everything_the_swarm_found_on_the_host.csv"), "x\n");
  await writeFile(join(root, "work", "extracted", "sl00100", "a", "very", "deep", "folder", "carved-record-000123456.bin"), "y");
  const a = createContext(root, "sl00100");
  for (const entry of [
    { kind: "finding", value: "v", source: "inputs/never-read/Security.evtx", evidence: "e", confidence: "high" },
    { kind: "finding", value: "w", source: "inputs/never-read/Security.evtx", evidence: "e", confidence: "medium", supersedes: 1 },
  ]) {
    const r = await recordEntry(a, entry as never);
    if (!r.ok) throw new Error(r.reason);
  }
  return root;
}

test("each exhibit shows the examiner's standing on it, reviewed or not, and an unreadable review is never 'not reviewed'", async () => {
  const runs = await mkdtemp(join(tmpdir(), "report-review-"));
  try {
    const root = await layoutSandbox(runs);
    // No review at all: every exhibit says so, on its head and in its rows.
    let html = await renderReport(root, { runsDir: runs, now: "2026-02-12T09:00:00.000Z" });
    assert.equal((html.match(/<span class="chip chip-none">not reviewed<\/span>/g) ?? []).length, 2);
    assert.equal((html.match(/<dt>Examiner review<\/dt><dd>not reviewed by an examiner<\/dd>/g) ?? []).length, 2);
    // Reviewed: the chip carries the standing.
    const { appendReview } = await import("../scripts/review.ts");
    await appendReview(runs, "sl001", root, { action: "reject", examiner: "H. Examiner", entry_seq: 1, note: "no" });
    await appendReview(runs, "sl001", root, { action: "accept", examiner: "H. Examiner", entry_seq: 2 });
    html = await renderReport(root, { runsDir: runs, now: "2026-02-12T09:00:00.000Z" });
    assert.match(html, /id="e-1">[\s\S]*?<span class="chip chip-brick">rejected by the examiner<\/span>/);
    assert.match(html, /id="e-2">[\s\S]*?<span class="chip chip-moss">accepted by the examiner<\/span>/);
    // A link in the review's place: said as unreadable, never as not reviewed.
    const file = join(runs, "reviews", "sl001.jsonl");
    await rm(file);
    await writeFile(join(runs, "elsewhere.jsonl"), "");
    const { symlink } = await import("node:fs/promises");
    await symlink(join(runs, "elsewhere.jsonl"), file);
    html = await renderReport(root, { runsDir: runs, now: "2026-02-12T09:00:00.000Z" });
    assert.match(html, /<td>Examiner review<\/td><td class="">the examiner's review could not be read: a link/);
    assert.match(html, /<span class="chip chip-brick">review unreadable<\/span>/);
    assert.doesNotMatch(html, /not reviewed by an examiner/);
    assert.match(await summarize(root, { runsDir: runs }), /^- Examiner review: the examiner's review could not be read: a link/m);
  } finally {
    await rm(runs, { recursive: true, force: true });
  }
});

test("the artifact and hand-over tables give their last column room, and a chip in a cell or an exhibit's head wraps", async () => {
  const runs = await mkdtemp(join(tmpdir(), "report-layout-"));
  try {
    const root = await layoutSandbox(runs);
    const html = await renderReport(root, { runsDir: runs, now: "2026-02-12T09:00:00.000Z", handover: [{ name: "custody.json", description: "The host's verdict.", present: false, reason: "not written for this run", bytes: null, sha256: null }] });
    assert.match(html, /<table class="artifacts"><thead><tr><th>Path<\/th>/);
    assert.match(html, /table\.artifacts th:nth-child\(4\) \{ width: 16%; \}/);
    assert.match(html, /td \.chip, \.exhibit \.chips \.chip \{ white-space: normal; \}/);
    assert.match(html, /\.exhibit \.chips \{[^}]*flex-wrap: wrap;/);
    assert.match(html, /<h3>Files handed over with this report \(1\)<\/h3>[\s\S]*<table class="handover">[\s\S]*absent: not written for this run/);
  } finally {
    await rm(runs, { recursive: true, force: true });
  }
});

test("rendered in a browser, no table and no exhibit head overflows, on a phone, in a narrow pane or on an A4 page", async (t) => {
  let pw: typeof import("playwright");
  let browser: import("playwright").Browser;
  try {
    pw = await import("playwright");
    browser = await pw.chromium.launch({ headless: true, ...(process.env.BROWSER_CHECK_EXECUTABLE ? { executablePath: process.env.BROWSER_CHECK_EXECUTABLE } : {}) });
  } catch (err) {
    t.skip(`playwright/chromium unavailable: ${(err as Error).message.split("\n")[0]}`);
    return;
  }
  const runs = await mkdtemp(join(tmpdir(), "report-browser-"));
  try {
    const root = await layoutSandbox(runs);
    const { appendReview } = await import("../scripts/review.ts");
    await appendReview(runs, "sl001", root, { action: "reject", examiner: "H. Examiner", entry_seq: 1, note: "no" });
    const { buildDossier } = await import("../scripts/dossier.ts");
    const html = (await buildDossier(root, { runsDir: runs, now: "2026-02-12T09:00:00.000Z" })).reportHtml;
    for (const [width, media] of [[390, "screen"], [560, "screen"], [673, "print"], [794, "print"], [1200, "screen"]] as const) {
      const page = await browser.newPage({ viewport: { width, height: 1000 } });
      await page.emulateMedia({ media });
      await page.setContent(html);
      const overflow = await page.evaluate(() => {
        const out: string[] = [];
        for (const el of document.querySelectorAll("table, td, th, .exhibit .head")) {
          const e = el as HTMLElement;
          if (e.scrollWidth > e.clientWidth + 1) out.push(`${e.tagName.toLowerCase()} "${(e.textContent ?? "").slice(0, 40)}" ${e.scrollWidth}>${e.clientWidth}`);
        }
        return out;
      });
      assert.deepEqual(overflow, [], `overflow at ${width}px (${media})`);
      // The standing is on the rejected exhibit, in its visible text.
      const text = await page.evaluate(() => (document.getElementById("e-1") as HTMLElement).innerText.toLowerCase());
      assert.match(text, /rejected by the examiner/);
      await page.close();
    }
  } finally {
    await browser.close();
    await rm(runs, { recursive: true, force: true });
  }
});

test("a long line of table or link punctuation renders in linear time", () => {
  // Each of these used to be scanned once per starting position, and the
  // report and the artifact preview both render whatever markdown work/
  // holds. At these sizes the old scans took 2.6 to 11 s each where this was
  // measured, and the linear ones a millisecond, so a second's bound tells
  // the two apart on a slow machine too.
  const lines = {
    pipes: `| a | b |\n${"|".repeat(100_000)}x`,
    cells: `| a | b |\n${"| -".repeat(35_000)}x`,
    brackets: "[".repeat(100_000),
    links: "[a](".repeat(40_000),
  };
  for (const [name, md] of Object.entries(lines)) {
    const started = performance.now();
    markdownToHtml(md);
    const ms = performance.now() - started;
    assert.ok(ms < 1_000, `${name}: ${Math.round(ms)} ms`);
  }
  // What the rewrite must still do: a divider is recognised with or without
  // outer pipes and alignment colons, a pipe-free rule is not a divider, and
  // a link keeps its label and shows its target.
  assert.match(markdownToHtml("| A | B |\n|:---|---:|\n| 1 | 2 |"), /<th>A<\/th><th>B<\/th>/);
  assert.match(markdownToHtml("A | B\n--- | ---\n1 | 2"), /<th>A<\/th><th>B<\/th>/);
  assert.doesNotMatch(markdownToHtml("A | B\n---\n"), /<table>/);
  assert.doesNotMatch(markdownToHtml("| A | B |\n|---|x|\n"), /<table>/);
  assert.match(markdownToHtml("See [the log](https://example.org/a) now."), /See the log <span class="url">\(https:\/\/example\.org\/a\)<\/span> now\./);
});
