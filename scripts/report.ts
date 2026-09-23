#!/usr/bin/env node
/**
 * The report: one HTML file an examiner can hand to somebody else.
 *
 *   node --experimental-strip-types scripts/report.ts <sandbox> [--lint]
 *   swarm.sh report <id> [--pdf]     (same thing, by run id)
 *
 * Self-contained on purpose. No stylesheet, no script, no font and no image
 * is fetched from anywhere: the file is read in a room that may have no
 * network, years after the run, and a report whose layout depends on a CDN
 * being up is a report that will one day render as a wall of unstyled text.
 * That is also why the type is system stacks rather than the console's web
 * fonts — embedding them would be megabytes of base64 in every report, and
 * the document is designed to read correctly in Georgia and Menlo.
 *
 * The print stylesheet controls what it can control and does not pretend to
 * control the rest. Page size, margins, `break-inside: avoid` on exhibits and
 * rows, repeating table headers and widow/orphan limits all work. Running
 * headers and page numbers do not: `@page` margin boxes are unimplemented in
 * Chrome, and a `position: fixed` element — the usual workaround — is
 * anchored to the first page there and lands on top of the content of every
 * page after it. So `--pdf` lets the browser draw the page numbers, and the
 * document asks to be cited by section rather than by page.
 *
 * There is no Markdown library. Reading the fifteen delivered reports in
 * docs/use-cases showed that none of them contains an image, a link or raw
 * HTML: headings, paragraphs, lists, tables, code spans and fences is the
 * whole vocabulary, and `markdownToHtml` below covers it in about a hundred
 * lines. The repo has one runtime dependency and this is not a reason for a
 * second one.
 *
 * Every ledger entry already carries a stable `seq`, so an exhibit number is
 * `E-<seq>` and the console, the ledger and this document cite the same
 * thing.
 */
import { readFile, stat } from "node:fs/promises";
import { basename, dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import {
  EVENTS_REL,
  readNames,
  verifyEventChain,
  type AgentBudget,
  type LedgerEntry,
} from "../extensions/protocol.ts";
import { hashArtifacts, type ArtifactIndex } from "./artifacts.ts";
import { loadRunContext, readJsonFile } from "./run-record.ts";

const ROOT = join(dirname(fileURLToPath(import.meta.url)), "..");

export type ReportOptions = {
  runsDir?: string;
  /** Overrides the registry's case id and examiner, for a one-off render. */
  caseId?: string;
  examiner?: string;
  /** The organisation the report is issued by. Free, and it belongs here. */
  organisation?: string;
  /** Fixes `generated_at` so two renders of one run are byte-identical. */
  now?: string;
  /** Skip a second walk of work/ when the caller already hashed it. */
  artifacts?: ArtifactIndex;
};

// ---------------------------------------------------------------------------
// Markdown
// ---------------------------------------------------------------------------

export { escapeHtml, markdownToHtml } from "../ui/src/lib/markdown.ts";
import { escapeHtml, inline, markdownToHtml } from "../ui/src/lib/markdown.ts";

/** One numbered section of a swarm's report that cites nothing checkable. */
export type LintFinding = { section: string; reason: string };

/**
 * Does each numbered section cite something a reader can check?
 *
 * `docs/improvement-plan.md` B10 wrote this rule as "every `## N.` section
 * cites at least one path under inputs/, catalog/ or work/". Applied to the
 * fifteen delivered reports it rejects 57 of their 103 sections, because a
 * forensic citation is usually not a path: it is an inode, a record id, an
 * event id or a registry key. The rule below accepts any of those — a code
 * span, a ledger seq, or an identifier that looks like one — and all fifteen
 * pass. It warns and never fails: a report linter that blocks delivery is a
 * linter operators turn off.
 */
export function lintReport(markdown: string): LintFinding[] {
  const findings: LintFinding[] = [];
  const lines = markdown.replace(/\r\n?/g, "\n").split("\n");
  let current: string | null = null;
  let body: string[] = [];
  const check = () => {
    if (current === null) return;
    const text = body.join("\n");
    const cites =
      /`[^`]+`/.test(text) ||
      /\bE-\d+\b/.test(text) ||
      /\b(?:inode|seq|record|entry|event ?id|offset|cluster|sector|lba)\b\s*#?\s*\d/i.test(text) ||
      /\b\d{4,}-\d{1,3}(?:-\d{1,3})?\b/.test(text) ||
      /\bHK(?:LM|CU|CR|U|CC)\\/i.test(text);
    if (!cites) findings.push({ section: current, reason: "no code span, exhibit number, inode, record id or registry key" });
    body = [];
  };
  for (const line of lines) {
    const heading = /^##\s+(\d+[.)]?\s+.*)$/.exec(line);
    if (heading) {
      check();
      current = heading[1].trim();
      continue;
    }
    if (current !== null) body.push(line);
  }
  check();
  return findings;
}

// ---------------------------------------------------------------------------
// Reading the sandbox
// ---------------------------------------------------------------------------

function parseFrontMatter(text: string): Record<string, string> {
  const out: Record<string, string> = {};
  const block = /^---\n([\s\S]*?)\n---/.exec(text);
  for (const line of (block ? block[1] : text).split("\n")) {
    const m = /^([a-z_]+):\s*(.*)$/i.exec(line.trim());
    if (m) out[m[1]] = m[2].trim();
  }
  return out;
}

function usd(n: number): string {
  return `$${n.toFixed(2)}`;
}

function bytesHuman(n: number): string {
  if (!Number.isFinite(n)) return "—";
  const units = ["B", "KB", "MB", "GB", "TB"];
  let value = n;
  let i = 0;
  while (value >= 1024 && i < units.length - 1) {
    value /= 1024;
    i++;
  }
  return `${i === 0 ? value : value.toFixed(1)} ${units[i]}`;
}

function durationHuman(ms: number): string {
  if (!Number.isFinite(ms) || ms < 0) return "—";
  const minutes = Math.floor(ms / 60_000);
  const hours = Math.floor(minutes / 60);
  return hours ? `${hours} h ${minutes % 60} min` : `${minutes} min`;
}

// ---------------------------------------------------------------------------
// The document
// ---------------------------------------------------------------------------

/**
 * The print stylesheet is the part that decides whether the PDF is usable.
 * Every rule here exists because of something that breaks without it: a
 * 64-character hash overflowing an A4 column, an exhibit split across a page
 * boundary, a forty-row timeline whose column headers appear once, a heading
 * stranded at the foot of a page.
 */
const STYLE = `
:root {
  --paper: #ffffff; --paper-2: #f6f3ec; --paper-3: #efebe1; --card: #fffdf9;
  --ink: #171615; --ink-2: #4f4c46; --ink-3: #726d64;
  --line: #e2ddd1; --line-2: #cbc5b6; --rule: #171615;
  --kelp: #0e7c7b; --kelp-soft: #dcefee; --kelp-ink: #0a5d5c;
  --saffron: #c9822a; --saffron-soft: #fbebd3; --saffron-ink: #8a540a;
  --brick: #b23a48; --brick-soft: #f5dade; --brick-ink: #8b2532;
  --slate: #3e5c76; --slate-soft: #dce4ec; --slate-ink: #2c4660;
  --moss: #4c7a34; --moss-soft: #e1edd8; --moss-ink: #2f5a1c;
  --sans: "IBM Plex Sans", ui-sans-serif, system-ui, -apple-system, "Segoe UI", Helvetica, Arial, sans-serif;
  --serif: "Instrument Serif", Georgia, "Times New Roman", serif;
  --mono: "IBM Plex Mono", ui-monospace, SFMono-Regular, Menlo, Consolas, monospace;
}
* { box-sizing: border-box; }
html { -webkit-text-size-adjust: 100%; }
body { margin: 0; background: var(--paper-2); color: var(--ink); font: 10.5pt/1.6 var(--sans); }
main { max-width: 54rem; margin: 0 auto; padding: 0 0 4rem; background: var(--paper); box-shadow: 0 0 0 1px var(--line); }
section, .cover, .toc, footer { padding-left: clamp(1.25rem, 5vw, 3.25rem); padding-right: clamp(1.25rem, 5vw, 3.25rem); }

h1, h2, h3, h4 { font-family: var(--serif); font-weight: 400; line-height: 1.12; margin: 0 0 .5em; }
h1 { font-size: clamp(2.2rem, 6vw, 3.1rem); letter-spacing: -.01em; }
h2 { font-size: 1.6rem; margin: 0 0 1rem; }
h3 { font-size: 1.12rem; margin: 2em 0 .6em; }
h4 { font-size: .95rem; font-family: var(--sans); font-weight: 650; letter-spacing: .01em; margin: 1.6em 0 .4em; }
p, li { margin: .55em 0; }
ul, ol { padding-left: 1.3em; }
a { color: var(--kelp-ink); }
code { font-family: var(--mono); font-size: .86em; background: var(--paper-2); padding: .1em .32em; border-radius: 3px; overflow-wrap: anywhere; }
pre { background: var(--paper-2); border: 1px solid var(--line); border-radius: 8px; padding: .75rem .95rem; overflow-x: auto; }
pre code { background: none; padding: 0; font-size: .82em; }
blockquote { margin: .8em 0; padding: .1em 0 .1em 1rem; border-left: 3px solid var(--line-2); color: var(--ink-2); }
hr { border: 0; border-top: 1px solid var(--line); margin: 2em 0; }
.url { color: var(--ink-3); font-family: var(--mono); font-size: .8em; }
.lede { font-size: 1.02rem; color: var(--ink-2); max-width: 42em; }

/* Every table has to fit the page: a 64-character hash in a five-column row
   used to push the whole table past the paper. Fixed layout plus breaking
   inside the cell is what keeps it inside. */
table { border-collapse: collapse; width: 100%; table-layout: fixed; margin: 1.1em 0; font-size: .92em; }
th, td { text-align: left; padding: .45rem .6rem; border-bottom: 1px solid var(--line); vertical-align: top; overflow-wrap: anywhere; }
thead th { border-bottom: 1px solid var(--line-2); }
th { font-family: var(--sans); font-size: .68rem; letter-spacing: .07em; text-transform: uppercase; color: var(--ink-3); font-weight: 650; }
tbody tr:last-child td { border-bottom: 0; }
td.num, th.num, .tabular { font-variant-numeric: tabular-nums; }
th.num, td.num { text-align: right; }
.hash { font-family: var(--mono); font-size: .76em; overflow-wrap: anywhere; word-break: break-all; color: var(--ink-2); line-height: 1.45; }
.when { font-variant-numeric: tabular-nums; white-space: nowrap; }
.when .t { display: block; color: var(--ink-2); font-size: .92em; }

/* --- cover ---------------------------------------------------------------- */
.cover { padding-top: 3rem; padding-bottom: 2.25rem; border-bottom: 2px solid var(--rule); }
.cover .mark { display: flex; align-items: center; gap: .7rem; color: var(--ink); }
.cover .mark svg { width: 30px; height: 30px; }
.cover .wordmark { font-family: var(--serif); font-style: italic; font-size: 1.05rem; }
.cover .kicker { margin: 2.6rem 0 .5rem; font-size: .7rem; letter-spacing: .18em; text-transform: uppercase; color: var(--ink-3); }
.cover h1 { margin: 0; }
.cover .case-line { display: flex; flex-wrap: wrap; align-items: baseline; gap: .6rem; margin: .7rem 0 0; font-size: 1.15rem; color: var(--ink-2); }
.cover .case-line strong { font-weight: 650; color: var(--ink); }
.scorecard { display: grid; grid-template-columns: repeat(auto-fit, minmax(7.5rem, 1fr)); gap: 1px; margin: 2rem 0 1.75rem; background: var(--line); border: 1px solid var(--line); border-radius: 10px; overflow: hidden; }
.scorecard .cell { background: var(--card); padding: .7rem .85rem; }
.scorecard .k { font-size: .62rem; letter-spacing: .11em; text-transform: uppercase; color: var(--ink-3); }
.scorecard .v { font-family: var(--serif); font-size: 1.55rem; line-height: 1.1; margin-top: .15rem; font-variant-numeric: tabular-nums; }
.scorecard .s { font-size: .74rem; color: var(--ink-3); margin-top: .1rem; }
.facts { display: grid; grid-template-columns: auto minmax(0, 1fr); gap: .35rem 1.4rem; font-size: .92em; }
.facts dt { font-size: .66rem; letter-spacing: .08em; text-transform: uppercase; color: var(--ink-3); padding-top: .3em; }
.facts dd { margin: 0; }

/* --- chips ---------------------------------------------------------------- */
.chip { display: inline-block; border-radius: 999px; padding: .1em .6em; font-size: .7rem; font-weight: 650; letter-spacing: .02em; line-height: 1.6; white-space: nowrap; vertical-align: .08em; }
.chip-kelp { background: var(--kelp-soft); color: var(--kelp-ink); }
.chip-saffron { background: var(--saffron-soft); color: var(--saffron-ink); }
.chip-brick { background: var(--brick-soft); color: var(--brick-ink); }
.chip-slate { background: var(--slate-soft); color: var(--slate-ink); }
.chip-moss { background: var(--moss-soft); color: var(--moss-ink); }
.chip-none { background: var(--paper-3); color: var(--ink-2); }

/* --- contents ------------------------------------------------------------- */
.toc { padding-top: 2rem; padding-bottom: 1.5rem; border-bottom: 1px solid var(--line); }
.toc h2 { font-size: 1.05rem; font-family: var(--sans); font-weight: 650; letter-spacing: .01em; }
.toc ol { list-style: none; padding: 0; margin: 0; display: grid; grid-template-columns: repeat(auto-fit, minmax(15rem, 1fr)); gap: 0 2rem; }
.toc li { border-bottom: 1px solid var(--line); padding: .45em 0; display: grid; grid-template-columns: 1.6rem 1fr; align-items: baseline; }
.toc .n { font-family: var(--mono); font-size: .78rem; color: var(--ink-3); }
.toc a { text-decoration: none; color: var(--ink); }
.toc a:hover { text-decoration: underline; }
.toc .desc { grid-column: 2; font-size: .76rem; color: var(--ink-3); }

/* --- sections ------------------------------------------------------------- */
section { padding-top: 2.5rem; }
.sec-head { display: flex; align-items: baseline; gap: .8rem; border-bottom: 1px solid var(--rule); padding-bottom: .55rem; margin-bottom: 1.2rem; }
.sec-head .n { font-family: var(--mono); font-size: .8rem; color: var(--ink-3); padding-top: .2rem; }
.sec-head h2 { margin: 0; }
.sec-head .count { margin-left: auto; font-size: .72rem; letter-spacing: .06em; text-transform: uppercase; color: var(--ink-3); white-space: nowrap; }

/* --- the summary ---------------------------------------------------------- */
.verdicts { display: flex; flex-direction: column; gap: .5rem; margin: 1rem 0; }
.verdict { display: grid; grid-template-columns: 3.1rem minmax(0, 1fr); gap: .9rem; align-items: start; padding: .7rem .9rem .7rem .75rem; border: 1px solid var(--line); border-left: 3px solid var(--kelp); border-radius: 8px; background: var(--card); }
.verdict.c-medium { border-left-color: var(--saffron); }
.verdict.c-low { border-left-color: var(--line-2); }
.verdict .no { font-family: var(--mono); font-size: .74rem; color: var(--ink-3); padding-top: .18rem; }
.verdict .claim { font-size: .98rem; line-height: 1.45; }
.verdict .meta { font-size: .78rem; color: var(--ink-3); margin-top: .3rem; }
.group-head { display: flex; align-items: baseline; gap: .55rem; margin: 1.6rem 0 .3rem; }
.group-head .t { font-size: .72rem; letter-spacing: .1em; text-transform: uppercase; color: var(--ink-3); }
.group-head .rule { flex: 1; border-bottom: 1px solid var(--line); transform: translateY(-.25em); }

/* --- the timeline --------------------------------------------------------- */
/* A five-column table of long forensic strings cannot be made to fit a page.
   The same rows as a rail: the stamp on the left, the claim and its citation
   stacked on the right, nothing to scroll sideways for. */
.tl { margin: 1.2rem 0 0; border-left: 1px solid var(--line-2); padding-left: 0; list-style: none; }
.tl li { position: relative; padding: 0 0 1.15rem 1.4rem; }
.tl li::before { content: ""; position: absolute; left: -4.5px; top: .55rem; width: 8px; height: 8px; border-radius: 50%; background: var(--slate); box-shadow: 0 0 0 3px var(--paper); }
.tl .stamp { display: flex; flex-wrap: wrap; align-items: baseline; gap: .5rem; font-variant-numeric: tabular-nums; font-size: .78rem; color: var(--ink-3); }
.tl .stamp .date { font-weight: 650; color: var(--ink-2); }
.tl .stamp .no { font-family: var(--mono); }
.tl .what { margin: .15rem 0 .25rem; line-height: 1.45; }
.tl dl { display: grid; grid-template-columns: 4.6rem minmax(0, 1fr); gap: .1rem .7rem; margin: 0; font-size: .8rem; }
.tl dt { color: var(--ink-3); }
.tl dd { margin: 0; color: var(--ink-2); overflow-wrap: anywhere; }

/* --- exhibits ------------------------------------------------------------- */
.exhibit { border: 1px solid var(--line); border-left: 3px solid var(--slate); border-radius: 8px; background: var(--card); padding: .75rem .95rem; margin: .6rem 0; }
.exhibit .head { display: flex; flex-wrap: wrap; align-items: baseline; gap: .5rem; }
.exhibit .no { font-family: var(--mono); font-size: .74rem; color: var(--ink-3); font-weight: 650; }
.exhibit .chips { margin-left: auto; display: flex; gap: .35rem; }
.exhibit .value { margin: .35rem 0 .5rem; font-size: .98rem; line-height: 1.45; }
.exhibit dl { display: grid; grid-template-columns: 5.4rem minmax(0, 1fr); gap: .18rem .8rem; margin: 0; font-size: .82em; }
.exhibit dt { color: var(--ink-3); }
.exhibit dd { margin: 0; overflow-wrap: anywhere; color: var(--ink-2); }
.exhibit-ioc { border-left-color: var(--saffron); }
.exhibit-finding { border-left-color: var(--kelp); }

/* --- spend ---------------------------------------------------------------- */
.bars { margin: 1rem 0; display: flex; flex-direction: column; gap: .45rem; }
.bar { display: grid; grid-template-columns: minmax(6rem, 11rem) minmax(0, 1fr) 4.5rem; align-items: center; gap: .7rem; font-size: .82rem; }
.bar .track { height: 7px; background: var(--paper-3); border-radius: 999px; overflow: hidden; }
.bar .fill { height: 100%; background: var(--slate); border-radius: 999px; }
.bar .v { text-align: right; font-variant-numeric: tabular-nums; color: var(--ink-2); }
.bar .name { font-family: var(--mono); font-size: .74rem; overflow-wrap: anywhere; }

.note { background: var(--paper-2); border: 1px solid var(--line); border-radius: 8px; padding: .7rem .95rem; font-size: .9em; color: var(--ink-2); }
.note strong { color: var(--ink); }
.embedded { border: 1px solid var(--line); border-radius: 8px; padding: .3rem 1.1rem 1.1rem; background: var(--card); margin-top: 1rem; }
.embedded h3 { margin-top: 1.4em; }
footer { margin-top: 3rem; padding-top: 1.1rem; border-top: 1px solid var(--line); font-size: .8em; color: var(--ink-3); }
footer p { max-width: 44em; }

@media (max-width: 34rem) {
  .verdict { grid-template-columns: minmax(0, 1fr); gap: .25rem; }
  .exhibit dl, .tl dl { grid-template-columns: minmax(0, 1fr); }
  .exhibit dt, .tl dt { font-size: .68rem; letter-spacing: .06em; text-transform: uppercase; margin-top: .3rem; }
  .bar { grid-template-columns: minmax(0, 1fr) 4rem; }
  .bar .track { grid-column: 1 / -1; }
}

@media print {
  /* The page box: A4 with a running header and a page counter. Chrome only
     honours the margin boxes when it is driving the print itself, so a
     browser "Save as PDF" may draw its own header instead; that is stated
     in the document rather than silently different. */
  @page { size: A4; margin: 15mm 16mm; }
  @page :first { margin-top: 12mm; }

  html, body { background: #fff; }
  body { font-size: 9.3pt; line-height: 1.5; }
  main { max-width: none; margin: 0; padding: 0; box-shadow: none; }
  section, .cover, .toc, footer { padding-left: 0; padding-right: 0; }

  /* The cover is a page of its own, and the contents follow it. */
  .cover { min-height: 0; padding-top: 0; break-after: page; page-break-after: always; }
  .cover h1 { font-size: 2.6rem; }
  .toc { break-after: page; page-break-after: always; }
  section { padding-top: 0; margin-top: 1.4rem; }

  /* Nothing a reader has to follow should be cut in half. */
  h1, h2, h3, h4, .sec-head { break-after: avoid-page; page-break-after: avoid; }
  .exhibit, .verdict, .tl li, tr, pre, blockquote, .note, .scorecard { break-inside: avoid-page; page-break-inside: avoid; }
  p, li { orphans: 3; widows: 3; }

  /* A forty-row table runs over several pages; its column headers have to be
     on every one of them. */
  thead { display: table-header-group; }
  tfoot { display: table-footer-group; }

  /* Chips, rails and bars carry meaning, so their ground has to survive the
     printer's "background graphics off" default where the browser allows it. */
  .chip, .scorecard, .verdict, .exhibit, .note, .bar .fill, .bar .track, .tl li::before {
    -webkit-print-color-adjust: exact; print-color-adjust: exact;
  }

  .page-break { break-before: page; page-break-before: always; }
  .screen-only { display: none !important; }
}
`;

/** An ISO stamp that fits a narrow column: date, then time beneath it. */
function whenCell(ts: string): string {
  const m = /^(\d{4}-\d{2}-\d{2})T(\d{2}:\d{2}:\d{2})/.exec(ts);
  if (!m) return `<span class="when">${escapeHtml(ts)}</span>`;
  return `<span class="when">${m[1]}<span class="t">${m[2]}Z</span></span>`;
}

function chip(text: string, tone: "kelp" | "saffron" | "brick" | "slate" | "moss" | "none"): string {
  return `<span class="chip chip-${tone}">${escapeHtml(text)}</span>`;
}

/** One dated event on the timeline rail: stamp, claim, then its citation. */
function timelineRow(entry: LedgerEntry): string {
  const m = /^(\d{4}-\d{2}-\d{2})T(\d{2}:\d{2}:\d{2})/.exec(entry.ts ?? "");
  const stamp = m
    ? `<span class="date">${m[1]}</span><span>${m[2]}Z</span>`
    : `<span class="date">${escapeHtml(entry.ts ?? "undated")}</span>`;
  const rows: string[] = [];
  if (entry.source) rows.push(`<dt>Source</dt><dd>${inline(entry.source)}</dd>`);
  if (entry.evidence) rows.push(`<dt>Evidence</dt><dd>${inline(entry.evidence)}</dd>`);
  return `<li>
  <div class="stamp">${stamp}<span class="no">E-${entry.seq}</span></div>
  <div class="what">${inline(entry.value)}</div>
  ${rows.length ? `<dl>${rows.join("")}</dl>` : ""}
</li>`;
}

/**
 * The findings as verdict cards, grouped by how sure the swarm said it was.
 * A numbered list of forty-word sentences is the one shape a reader cannot
 * scan, and confidence is the first thing they need: what this run stands
 * behind, and what it is only offering.
 */
function verdictGroups(findings: LedgerEntry[]): string {
  const order: Array<{ key: string; label: string; cls: string }> = [
    { key: "high", label: "High confidence", cls: "c-high" },
    { key: "medium", label: "Medium confidence", cls: "c-medium" },
    { key: "low", label: "Low confidence — offered as hypotheses", cls: "c-low" },
    { key: "", label: "Recorded without a confidence", cls: "c-low" },
  ];
  const out: string[] = [];
  for (const group of order) {
    const rows = findings.filter((f) => (f.confidence ?? "") === group.key);
    if (!rows.length) continue;
    const cards = rows
      .slice()
      .reverse()
      .map((f) => {
        const source = f.source ? inline(f.source) : f.evidence ? inline(f.evidence) : "";
        return `<div class="verdict ${group.cls}">
  <span class="no">E-${f.seq}</span>
  <div>
    <div class="claim">${inline(f.value)}</div>
    ${source ? `<div class="meta">${source}</div>` : ""}
  </div>
</div>`;
      })
      .join("");
    out.push(`<div class="group-head"><span class="t">${escapeHtml(group.label)}</span><span class="rule"></span><span class="t">${rows.length}</span></div>
<div class="verdicts">${cards}</div>`);
  }
  return out.join("\n");
}

function exhibitCard(entry: LedgerEntry): string {
  const tone = entry.kind === "ioc" ? "ioc" : entry.kind === "finding" ? "finding" : "event";
  const rows: string[] = [];
  if (entry.ts) rows.push(`<dt>When</dt><dd>${whenCell(entry.ts)}</dd>`);
  rows.push(`<dt>Source</dt><dd>${inline(entry.source ?? "—")}</dd>`);
  rows.push(`<dt>Evidence</dt><dd>${inline(entry.evidence ?? "—")}</dd>`);
  rows.push(`<dt>Recorded by</dt><dd class="hash">${escapeHtml(entry.authors.join(", "))}</dd>`);
  const confidence = entry.confidence
    ? ` ${chip(entry.confidence, entry.confidence === "high" ? "moss" : entry.confidence === "medium" ? "saffron" : "none")}`
    : "";
  return `<div class="exhibit exhibit-${tone}">
  <div class="head"><span class="no">E-${entry.seq}</span><span class="chips">${chip(entry.kind, entry.kind === "ioc" ? "saffron" : entry.kind === "finding" ? "kelp" : "slate")}${confidence}</span></div>
  <p class="value">${inline(entry.value)}</p>
  <dl>${rows.join("")}</dl>
</div>`;
}

type Section = { n: number; title: string; html: string; breakBefore?: boolean; count?: string };

/**
 * How firmly the egress allowlist was held, in the report's own words.
 *
 * `netns` is the kernel refusing a route; `proxy-only` is an environment
 * variable that a raw socket ignores. A custody section that prints the
 * allowlist without printing which of the two was in force is telling half
 * a fact in a document somebody will be cross-examined on.
 */
/**
 * Hosts in the proxy log, with how often, most-refused first.
 *
 * The harness's own startup telemetry is dropped: `pi.dev` is 130 of the 172
 * refusals on a ten-agent run and no agent ever asked for it, so leaving it
 * in buries the one line that matters.
 */
export function countHosts(log: string, verb: "ALLOW" | "DENY"): Array<[string, number]> {
  const counts = new Map<string, number>();
  for (const match of log.matchAll(new RegExp(`${verb} connect ([^\\s:]+)`, "g"))) {
    const host = match[1];
    if (host === "pi.dev") continue;
    counts.set(host, (counts.get(host) ?? 0) + 1);
  }
  return [...counts.entries()].sort((a, b) => b[1] - a[1] || a[0].localeCompare(b[0]));
}

/** Where the panes could write, for the custody section. */
export function writeGuardLine(mode: string | undefined): string {
  switch (mode) {
    case "seatbelt":
      return "enforced (seatbelt: the panes could write inside this run and Pi's agent directory, and nowhere else)";
    case "linux":
      return "enforced (Landlock inside a user namespace: the panes could write inside this run and Pi's agent directory, and nowhere else)";
    case "landlock":
      return "enforced (Landlock, no namespace: the panes could write inside this run and Pi's agent directory, and nowhere else)";
    case "mountns":
      return "enforced (bubblewrap: a read-only root with this run and Pi's agent directory bound back writable)";
    case "none":
      return "NONE — a pane could write anywhere this user can, including outside the run";
    default:
      return "not recorded (this run predates the field)";
  }
}

/**
 * Whether a pane could reach the terminal multiplexer's control socket.
 *
 * It matters to custody because that socket authenticates nobody: anything
 * that can open it can start a process outside the write guard, type into
 * another agent's terminal, or report a lifecycle state for a pane that is
 * not its own. A run where it was open has a weaker record than one where it
 * was not, and the report should not make the reader go and find that out.
 */
export function herdrSocketLine(state: string | undefined): string {
  switch (state) {
    case "sealed":
      return "denied to the panes (seatbelt)";
    case "masked":
      return "hidden from the panes (an empty tmpfs over the socket's directory in their mount namespace)";
    case "open":
      return "REACHABLE — --no-seal-herdr was passed; a pane could start a process outside the write guard";
    case "unenforced":
      // Not always the host's fault: `--no-write-guard` turns the whole
      // profile off, and a run with nothing to point the rule at emits none
      // either. The custody line should say what is true — the socket was
      // reachable — and not guess which of the three it was.
      return "REACHABLE — no deny was applied (this host's guard cannot mask a socket, as Landlock alone cannot; or the write guard was off; or there was no socket path to deny)";
    default:
      return "not recorded (this run predates the field)";
  }
}

/**
 * Whether a pane could drop code into Pi's `extensions/`, which every later
 * Pi run on the machine would load. Seatbelt and the namespace modes carve
 * it read-only inside the writable agent directory; Landlock alone cannot
 * express "read-only inside writable", and the record says so.
 */
export function piExtensionsLine(state: string | undefined): string {
  switch (state) {
    case "read-only":
      return "read-only to the panes";
    case "writable":
      return "WRITABLE — this host's guard cannot carve a read-only directory out of a writable one; a dropped extension would load in later runs";
    case "not-applicable":
      return "no write guard on this run";
    default:
      return "not recorded (this run predates the field)";
  }
}

/**
 * How the collector decided whose line each one was. On macOS the token in
 * a pane's environment is a secret, so the token decides. On Linux every
 * pane of one uid can read a peer's environment, so a gate in front of the
 * collector decides from the kernel's SO_PEERCRED and the process tree, and
 * the collector counts a token only on a line the gate vouched for.
 */
export function attributionLine(state: string | undefined): string {
  switch (state) {
    case "token":
      return "by token (the token lives in the pane's environment, which no other process on this host can read)";
    case "ancestry":
      return "by process ancestry (the gate reads the sender's pid from the kernel and walks up to the pane; a token alone does not attribute)";
    case "token-exposed":
      return "BY TOKEN, EXPOSED — this host lets a pane read a peer's environment and the gate was not running; a line could carry a peer's token";
    default:
      return "not recorded (this run predates the field)";
  }
}

/**
 * Whether the anchor, which lives beside the run and outside it, was past a
 * pane's reach. Every write allowlist puts it there: seatbelt, Landlock (with
 * or without the namespace), and the namespace mode when bubblewrap made the
 * root read-only. The namespace mode without bubblewrap has no allowlist,
 * and its dry run says so; then the anchor was as writable as the trace.
 */
export function anchorGuarded(writeGuard: string | undefined, hostCaps: Record<string, unknown> | undefined): boolean {
  switch (writeGuard) {
    case "seatbelt":
    case "linux":
    case "landlock":
      return true;
    case "mountns":
      return hostCaps?.bwrap === true;
    default:
      return false;
  }
}

/**
 * What the panes' own probes said, beside what the kickoff built. A guard the
 * host can enforce is not a guard the panes got: the hook rides on the pane's
 * shell, and a login shell that is neither zsh nor bash never reads it.
 */
export function measuredGuardLine(state: string | undefined): string {
  switch (state) {
    case "kernel":
      return "every pane measured it at the kernel";
    case "partial":
      return "SOME PANES UNGUARDED — the hook reached only part of the team; the rest could write anywhere";
    case "none":
      return "NO PANE MEASURED IT — the guard was built and never reached a pane; treat this run as unguarded";
    case "unmeasured":
      return "not measured (no pane reported a probe in time)";
    case "not-applicable":
      return "no write guard on this run";
    default:
      return "not recorded (this run predates the field)";
  }
}

/** What the trace's hash chain says, for the custody section. */
export function chainLine(
  chain: {
    ok: boolean;
    chained: number;
    total: number;
    broken_at?: number;
    reason?: string;
    unverified?: number;
    disputed?: number;
  },
  anchored = false,
  guarded = true,
): string {
  if (!chain.total) return "no trace";
  // The failure verdict comes first. A file with every `prev` stripped has no
  // chain *and* contradicts the anchor; reported the other way round, the
  // most complete rewrite possible printed as "this run had no trace
  // collector" — the one sentence that tells the reader to stop worrying.
  if (!chain.ok) {
    const what =
      chain.reason === "appended"
        ? "a line was added by something other than the harness"
        : chain.reason === "shortened"
          ? "the record is shorter than the anchor says it was"
          : chain.reason === "head"
            ? "the record does not end where the anchor says it ends"
            : "the record was edited after it was written";
    return `BROKEN at line ${chain.broken_at} of ${chain.total} — ${what}`;
  }
  if (!chain.chained) return `${chain.total} lines, not chained (this run had no trace collector)`;
  const notes: string[] = [];
  // Both are ordinary in an older run and a finding in a current one, so they
  // are stated rather than folded into "intact".
  if (chain.disputed) notes.push(`${chain.disputed} line(s) claimed another agent's name`);
  if (chain.unverified) notes.push(`${chain.unverified} line(s) could not be attributed to a pane`);
  // Without the anchor, "intact" means the file agrees with itself — which a
  // wholesale rewrite also manages. Saying so is the difference between a
  // custody line a reader can rely on and one that sounds like it.
  if (!anchored) notes.push("no anchor was found, so a wholesale rewrite would not be visible here");
  // The anchor is only out of reach because the write guard puts it there.
  // On a host with no guard it sits in a directory the panes can write, and
  // then it proves what they allowed it to prove.
  else if (!guarded) notes.push("the anchor was writable by the panes on this host, so it settles less than it looks");
  return `intact: ${chain.chained} of ${chain.total} lines hash-chained${notes.length ? ` — ${notes.join("; ")}` : ""}`;
}

export function egressLine(mode: string | undefined): string {
  switch (mode) {
    case "netns":
      return "enforced (network namespace: a connection outside the allowlist has no route)";
    case "proxy-only":
      return "ADVISORY (proxy environment only: it holds for anything that reads HTTP(S)_PROXY, not for a raw socket)";
    case "off":
      return "none (netguard was off for this run)";
    default:
      return "not recorded (this run predates the field)";
  }
}

export async function renderReport(sandboxArg: string, options: ReportOptions = {}): Promise<string> {
  const { sandbox, run, team, budget, events, sentinel, ledger, inputs } = await loadRunContext(sandboxArg, {
    runsDir: options.runsDir,
    parseSentinel: parseFrontMatter,
  });
  // The manifest says what was copied; the trace says what each pane measured
  // and what the final check found. The console joins them the same way in
  // `inputsView`, and the report must not state a guard the panes did not
  // report.
  const enforced: Record<string, string> = {};
  for (const e of events) {
    if (e.tool !== "inputs_guard") continue;
    const r = (e.result ?? {}) as { enforced?: unknown };
    if (typeof r.enforced === "string") enforced[e.agent] = r.enforced;
  }
  const lastCheck = events.filter((e) => e.tool === "inputs_check").at(-1);
  const checkResult = (lastCheck?.result ?? {}) as {
    ok?: unknown;
    content_ok?: unknown;
    checked?: unknown;
    modified?: unknown;
    metadata?: unknown;
    missing?: unknown;
    added?: unknown;
  };
  const strings = (v: unknown): string[] => (Array.isArray(v) ? v.filter((x): x is string => typeof x === "string") : []);
  const inputsCheck = lastCheck
    ? {
        ok: checkResult.ok === true,
        // An older run has no `content_ok`; then `ok` is the only answer there is.
        content_ok: checkResult.content_ok === undefined ? checkResult.ok === true : checkResult.content_ok === true,
        checked: Number(checkResult.checked) || 0,
        modified: strings(checkResult.modified),
        metadata: strings(checkResult.metadata),
        missing: strings(checkResult.missing),
        added: strings(checkResult.added),
        by: lastCheck.agent,
        at: lastCheck.ts,
      }
    : null;
  const toolbox = await readJsonFile<{ preset?: string; present?: Array<{ name: string; version?: string }>; missing?: Array<{ name: string }> }>(join(sandbox, "toolbox.json"));
  // What the run installed for itself, from the packages' own dist-info. A
  // report that cites a finding produced by a library has to be able to name
  // the library's version; before this it could not.
  // The trace's hash chain, when a collector wrote it. A run whose lines name
  // their parents can say more than "the file grew".
  // The anchor lives beside the registry, outside the sandbox: a trace
  // rewritten from its first line carries a chain that verifies against
  // itself, and only the anchor remembers how long the record was.
  const anchor = await readJsonFile<{ lines?: number; head?: string; prev_head?: string; pending?: boolean }>(
    join(dirname(sandbox), `${basename(sandbox)}.trace-anchor.json`),
  );
  const anchorPoint =
    typeof anchor?.lines === "number" && typeof anchor?.head === "string"
      ? { lines: anchor.lines, head: anchor.head, prev_head: anchor.prev_head, pending: anchor.pending }
      : null;
  const chain = verifyEventChain(await readFile(join(sandbox, EVENTS_REL), "utf8").catch(() => ""), anchorPoint);
  const toolchain = await readJsonFile<{ packages?: Array<{ name: string; version: string; record_sha256?: string }> }>(join(sandbox, "toolchain.json"));
  const artifacts = options.artifacts ?? (await hashArtifacts(sandbox));
  const version = (await readJsonFile<{ version?: string }>(join(ROOT, "package.json")))?.version ?? "0.0.0";
  const mark = await readFile(join(ROOT, "brand", "mark-mono.svg"), "utf8").catch(() => "");
  // What this run could reach, for the custody record. `netguard.allow` is the
  // kickoff's own statement of it; teardown used to delete that file with the
  // pid and the port, so a report written after `swarm.sh stop` said "not
  // recorded" about a run whose allowlist had been enforced throughout. The
  // file is kept now, and where an older run has lost it the proxy's log still
  // names every host it let through — a weaker source, and said to be one.
  const allowHosts = (await readFile(join(sandbox, "netguard.allow"), "utf8").catch(() => "")).trim();
  const netguardLog = await readFile(join(sandbox, "traces", "netguard.log"), "utf8").catch(() => "");
  const allowFromLog = allowHosts
    ? []
    : [
        ...new Set(
          (netguardLog.match(/ALLOW connect ([^\s]+)/g) ?? []).map((m) =>
            m.replace("ALLOW connect ", ""),
          ),
        ),
      ].sort();
  // What the run tried to reach and could not. On BelkaCTF #6 that list held
  // `bit.ly` — an agent resolving a shortened link it had read inside the
  // seized phone. A custody section that prints only what was allowed cannot
  // show the reader that it happened.
  const deniedHosts = countHosts(netguardLog, "DENY");
  const names = await readNames(sandbox).catch(() => []);
  const chosen = new Map(names.map((n) => [n.id, n.doing ? `${n.name} — ${n.doing}` : n.name]));

  const id = run?.id ?? team.swarm_id ?? "";
  const caseId = options.caseId ?? run?.case_id ?? "";
  const examiner = options.examiner ?? run?.examiner ?? "";
  const startedAt = budget?.started_at ?? run?.started_at ?? events[0]?.ts ?? "";
  const endedAt = sentinel?.at ?? events.at(-1)?.ts ?? "";
  const durationMs = startedAt && endedAt ? Date.parse(endedAt) - Date.parse(startedAt) : Number.NaN;
  const generatedAt = options.now ?? new Date().toISOString();
  const unmetered = budget?.metered === false;

  const timeline = ledger.filter((e) => e.kind === "event").sort((a, b) => (a.ts ?? "").localeCompare(b.ts ?? "") || a.seq - b.seq);
  const iocs = ledger.filter((e) => e.kind === "ioc");
  const findings = ledger.filter((e) => e.kind === "finding");

  const sections: Section[] = [];

  // --- 1. Summary of findings ---------------------------------------------
  sections.push({
    n: 1,
    title: "Summary of findings",
    count: findings.length ? `${findings.length} recorded` : "none recorded",
    html: findings.length
      ? `<p class="lede">What the swarm concluded, strongest first. Each card carries the exhibit number its full entry has in §4, and the source it rests on. A claim with no evidence line is a claim this document does not stand behind.</p>
${verdictGroups(findings)}`
      : `<div class="note">The swarm recorded no findings. That is not the same as finding nothing: it means nothing was written to the ledger with <code>record</code>, so this report has no conclusions to carry. §7 says what was and was not covered.</div>`,
  });

  // --- 2. Scope and evidence ----------------------------------------------
  const guardWord = (g: string) => (g === "kernel" ? "kernel" : g === "mode" ? "permission bits" : "detect + heal");
  const enforcedSeen = Object.values(enforced);
  const evidenceRows = (inputs?.files ?? [])
    .map(
      (f) =>
        `<tr><td><code>${escapeHtml(f.path)}</code></td><td class="num">${escapeHtml(bytesHuman(f.bytes))}</td><td class="hash">${escapeHtml(f.sha256)}</td></tr>`,
    )
    .join("");
  sections.push({
    n: 2,
    title: "Scope and evidence",
    count: inputs ? `${inputs.files.length} file${inputs.files.length === 1 ? "" : "s"} · ${bytesHuman(inputs.bytes ?? 0)}` : "none given",
    html: inputs
      ? `<p>Copied from <code>${escapeHtml(inputs.source || "the operator")}</code> at ${escapeHtml(inputs.copied_at || "—")} into <code>inputs/</code>, which no agent may write. The harness refuses <code>write</code>, <code>edit</code> and <code>claim_file</code> on it, restores a shell write from a pristine copy, and where the host allows it runs each pane with <code>inputs/</code> read-only at the kernel.</p>
<p>Guard requested <code>${escapeHtml(inputs.enforce || "auto")}</code>, set up as <code>${escapeHtml(inputs.guard || "none")}</code>; measured per pane: ${
          enforcedSeen.length
            ? Object.entries(enforced)
                .map(([agent, g]) => `${escapeHtml(agent)} ${chip(guardWord(g), g === "kernel" ? "moss" : g === "mode" ? "saffron" : "brick")}`)
                .join(" ")
            : "no pane reported"
        }.</p>
<table><thead><tr><th>File</th><th class="num">Size</th><th>sha256 at kickoff</th></tr></thead><tbody>${evidenceRows}</tbody></table>
<p>${(inputs.files ?? []).length} file${(inputs.files ?? []).length === 1 ? "" : "s"}, ${escapeHtml(bytesHuman(inputs.bytes ?? 0))} in total.</p>`
      : `<div class="note">This run was given no read-only inputs. Whatever the agents examined, they reached some other way, and this report cannot state a hash for it.</div>`,
  });

  // --- 3. Timeline ---------------------------------------------------------
  sections.push({
    n: 3,
    title: "Timeline",
    count: timeline.length ? `${timeline.length} event${timeline.length === 1 ? "" : "s"}` : "none",
    breakBefore: true,
    html: timeline.length
      ? `<p class="lede">${timeline.length} dated event${timeline.length === 1 ? "" : "s"}, in time order, every timestamp UTC. The exhibit number is the ledger's own sequence, so the console, <code>ledger.jsonl</code> and this rail all name the same row.</p>
<ol class="tl">${timeline.map(timelineRow).join("")}</ol>`
      : `<div class="note">No dated events were recorded, so this report has no timeline.</div>`,
  });

  // --- 4. Indicators and findings -----------------------------------------
  sections.push({
    n: 4,
    title: "Indicators and findings",
    count: `${iocs.length} indicator${iocs.length === 1 ? "" : "s"} · ${findings.length} finding${findings.length === 1 ? "" : "s"}`,
    html:
      (iocs.length
        ? `<h3>Indicators (${iocs.length})</h3>${iocs.map(exhibitCard).join("")}`
        : `<h3>Indicators</h3><div class="note">None recorded.</div>`) +
      (findings.length
        ? `<h3>Findings (${findings.length})</h3>${findings.map(exhibitCard).join("")}`
        : `<h3>Findings</h3><div class="note">None recorded.</div>`),
  });

  // --- 5. Method -----------------------------------------------------------
  const anyNamed = team.agents.some((a) => chosen.has(a.id));
  // Each model's cap against what its agents spent together.
  const modelCaps = Object.entries(budget?.cap_per_model_usd ?? run?.cap_per_model_usd ?? {})
    .filter(([, cap]) => Number(cap) > 0)
    .sort((x, y) => x[0].localeCompare(y[0]))
    .map(([model, cap]) => {
      const spent = team.agents
        .filter((a) => (a.model ?? run?.model) === model)
        .reduce((sum, a) => sum + (budget?.agents[a.id]?.spent_usd ?? 0), 0);
      return `<code>${escapeHtml(model)}</code> ${escapeHtml(usd(spent))} of ${escapeHtml(usd(Number(cap)))}${spent >= Number(cap) ? " (over)" : ""}`;
    });
  // Context against the self-compaction ceiling when the run had one, else
  // against Pi's declared window; compactions as hand-offs, with every
  // compaction Pi recorded in brackets when the two differ.
  const anyContext = team.agents.some((a) => (budget?.agents[a.id]?.context_tokens ?? 0) > 0);
  const contextCell = (b: AgentBudget | undefined) => {
    const ctx = b?.context_tokens ?? 0;
    const against = b?.context_ceiling || b?.context_window || 0;
    if (!ctx || !against) return "—";
    return `${ctx.toLocaleString("en-US")} <span class="muted">(${Math.round((ctx / against) * 100)}%${b?.context_ceiling ? " of ceiling" : ""})</span>`;
  };
  const compactCell = (b: AgentBudget | undefined) => {
    const handoffs = b?.handoffs ?? 0;
    const all = b?.compactions ?? 0;
    if (!handoffs && !all) return "—";
    return `${handoffs}${all !== handoffs ? ` (${all})` : ""}${b?.compaction_usd ? ` <span class="muted">${escapeHtml(usd(b.compaction_usd))}</span>` : ""}`;
  };
  const teamRows = team.agents
    .map((a) => {
      const b = budget?.agents[a.id];
      const name = anyNamed ? `<td>${escapeHtml(chosen.get(a.id) ?? "—")}</td>` : "";
      const context = anyContext ? `<td class="num">${contextCell(b)}</td><td class="num">${compactCell(b)}</td>` : "";
      return `<tr><td class="hash">${escapeHtml(a.id)}</td>${name}<td>${escapeHtml(a.model ?? run?.model ?? "—")}</td><td class="num">${unmetered ? "free" : usd(b?.spent_usd ?? 0)}</td><td class="num">${b?.calls ?? 0}</td><td class="num">${(b?.tokens ?? 0).toLocaleString("en-US")}</td>${context}</tr>`;
    })
    .join("");
  const contextHeaders = anyContext ? `<th class="num">Context</th><th class="num">Compactions</th>` : "";
  sections.push({
    n: 5,
    title: "Method",
    html: `<p>${team.n} peer agent${team.n === 1 ? "" : "s"} shared one sandbox and coordinated through an append-only file board. Nobody planned, nobody was assigned a seat, and no agent could direct another.${anyNamed ? ' The "Calls itself" column is what each one decided to be, in its own words, after reading the goal.' : ""}</p>
<table><thead><tr><th>Agent</th>${anyNamed ? "<th>Calls itself</th>" : ""}<th>Model</th><th class="num">Spent</th><th class="num">Calls</th><th class="num">Tokens</th>${contextHeaders}</tr></thead><tbody>${teamRows}</tbody></table>
<p>
  ${unmetered ? "Unmetered (local models)." : `${escapeHtml(usd(budget?.spent_usd ?? 0))} of a ${escapeHtml(usd(run?.cap_usd ?? budget?.cap_usd ?? 0))} cap`},
  ${(budget?.tokens ?? 0).toLocaleString("en-US")} tokens, ${events.length.toLocaleString("en-US")} tool calls in ${escapeHtml(durationHuman(durationMs))}.
  ${run?.wall_clock_minutes ? `Wall-clock cap ${run.wall_clock_minutes} min.` : ""}
  ${run?.cap_per_agent_usd ? `Per-agent cap ${escapeHtml(usd(run.cap_per_agent_usd))}.` : ""}
  ${modelCaps.length ? `Per-model caps: ${modelCaps.join("; ")}.` : ""}
</p>
${
  toolbox
    ? `<p>Toolbox <code>${escapeHtml(toolbox.preset ?? "off")}</code>: ${(toolbox.present ?? []).length} tool${(toolbox.present ?? []).length === 1 ? "" : "s"} present${(toolbox.missing ?? []).length ? `, ${(toolbox.missing ?? []).length} missing (${(toolbox.missing ?? []).map((m) => escapeHtml(m.name)).join(", ")})` : ""}.</p>`
    : ""
}`,
  });

  // --- 6. Artifacts --------------------------------------------------------
  const artifactRows = artifacts.files
    .map(
      (f) =>
        `<tr><td><code>${escapeHtml(f.path)}</code></td><td class="num">${escapeHtml(bytesHuman(f.bytes))}</td><td class="hash">${escapeHtml(f.sha256)}</td><td>${f.packaged ? chip("packaged", "moss") : chip("in the sandbox", "saffron")}</td></tr>`,
    )
    .join("");
  sections.push({
    n: 6,
    title: "Artifacts produced",
    count: artifacts.files.length ? `${artifacts.files.length} file${artifacts.files.length === 1 ? "" : "s"}` : "none",
    html: artifacts.files.length
      ? `<table><thead><tr><th>Path</th><th class="num">Size</th><th>sha256</th><th>Where</th></tr></thead><tbody>${artifactRows}</tbody></table>
<p>${artifacts.files.length} file${artifacts.files.length === 1 ? "" : "s"}, ${escapeHtml(bytesHuman(artifacts.bytes))} in total; ${escapeHtml(bytesHuman(artifacts.packaged_bytes))} of that travels with the package.</p>
${
  artifacts.files.some((f) => !f.packaged)
    ? `<div class="note">Files marked <strong>in the sandbox</strong> are under ${artifacts.unpackaged_dirs.map((d) => `<code>work/${escapeHtml(d)}/</code>`).join(" and ")}. That material came out of the evidence and may be live, so the package does not carry it. It is hashed here, which is what lets a reader verify a copy obtained another way.</div>`
    : ""
}
${artifacts.skipped.length ? `<p>Not hashed: ${artifacts.skipped.map((s) => `<code>${escapeHtml(s.path)}</code> (${escapeHtml(s.reason)})`).join(", ")}.</p>` : ""}`
      : `<div class="note">Nothing under <code>work/</code>.</div>`,
  });

  // --- 7. Limitations ------------------------------------------------------
  const capHit = (budget?.spent_usd ?? 0) > 0 && (run?.cap_usd ?? 0) > 0 && (budget?.spent_usd ?? 0) >= (run?.cap_usd ?? 0) * 0.98;
  const limits: string[] = [];
  if (!sentinel) limits.push("The swarm did not finish: there is no <code>done/SWARM_DONE</code>, so no agent stated that the definition of done was met.");
  if (capHit) limits.push(`Spend reached the cap (${escapeHtml(usd(budget?.spent_usd ?? 0))} of ${escapeHtml(usd(run?.cap_usd ?? 0))}). Work stopped because of the budget, not because the questions were answered.`);
  if (!findings.length) limits.push("No findings were recorded, so nothing in this report is stated as a conclusion.");
  if (!inputs) limits.push("No read-only inputs were given, so no evidence hash is stated.");
  const refusals = events.filter((e) => e.result && typeof e.result === "object" && (e.result as { ok?: boolean }).ok === false);
  if (refusals.length) limits.push(`${refusals.length} tool call${refusals.length === 1 ? "" : "s"} failed or were refused during the run; they are in <code>trace/events.jsonl</code>.`);
  limits.push("This document reports what the swarm recorded. An artefact nobody opened is not evidence of absence, and the trace is the record of what was actually read.");
  sections.push({
    n: 7,
    title: "Limitations",
    html: `<ul>${limits.map((l) => `<li>${l}</li>`).join("")}</ul>`,
  });

  // --- 8. Chain of custody -------------------------------------------------
  const custody: Array<[string, string]> = [
    ["Case", caseId || "—"],
    ["Examiner", examiner || "—"],
    ["Tool", `DFIR Swarm ${version}`],
    ["Run", id || "—"],
    ["Started", startedAt || "—"],
    ["Ended", endedAt || "—"],
    ["Sandbox", sandbox],
    ["Evidence", inputs ? `${inputs.files.length} file(s), ${bytesHuman(inputs.bytes ?? 0)}, from ${inputs.source || "the operator"}` : "none given"],
    [
      "Evidence intact at the end",
      !inputsCheck
        ? "not checked"
        : inputsCheck.ok
          ? `yes, ${inputsCheck.checked} checked by ${inputsCheck.by} at ${inputsCheck.at}`
          : inputsCheck.content_ok
            ? `bytes intact (${inputsCheck.checked} checked by ${inputsCheck.by} at ${inputsCheck.at}); ${inputsCheck.metadata.length} file(s) drifted in mode or link count only`
            : `NO — ${inputsCheck.modified.length} modified, ${inputsCheck.missing.length} missing, ${inputsCheck.added.length} added`,
    ],
    [
      "Network",
      allowHosts
        ? `netguard allowlist: ${allowHosts.split("\n").filter(Boolean).join(", ")}`
        : allowFromLog.length
          ? `netguard allowlist not kept; the proxy log shows it allowed ${allowFromLog.join(", ")}`
          : "netguard allowlist not recorded",
    ],
    // What the allowlist was is half the custody line; whether the host could
    // hold it is the other half, and the record used to carry only the first.
    ["Egress enforcement", egressLine(run?.netguard === false ? "off" : (run?.netguard_mode as string | undefined))],
    ["Write guard", writeGuardLine(run?.write_guard as string | undefined)],
    ["Terminal socket", herdrSocketLine(run?.herdr_socket as string | undefined)],
    ["Pi extensions", piExtensionsLine(run?.pi_extensions as string | undefined)],
    ["Attribution", attributionLine(run?.attribution as string | undefined)],
    ["Guard measured", measuredGuardLine(run?.write_guard_measured as string | undefined)],
    [
      "Trace integrity",
      chainLine(chain, Boolean(anchorPoint), anchorGuarded(run?.write_guard as string | undefined, run?.host_caps as Record<string, unknown> | undefined)),
    ],
    [
      "Egress refused",
      deniedHosts.length
        ? deniedHosts.map(([host, n]) => `${host}${n > 1 ? ` (${n})` : ""}`).join(", ")
        : "nothing was refused",
    ],
    [
      "Installed during the run",
      toolchain?.packages?.length
        ? toolchain.packages.map((p) => `${p.name} ${p.version}${p.record_sha256 ? ` (${p.record_sha256.slice(0, 12)})` : ""}`).join(", ")
        : "nothing",
    ],
    ["Ledger", `${ledger.length} entries (${timeline.length} events, ${iocs.length} indicators, ${findings.length} findings)`],
    ["Trace", `${events.length} tool calls`],
  ];
  sections.push({
    n: 8,
    title: "Chain of custody",
    html: `<table><thead><tr><th>Item</th><th>Recorded</th></tr></thead><tbody>${custody
      .map(([k, v]) => `<tr><td>${escapeHtml(k)}</td><td class="${k.startsWith("Sandbox") ? "hash" : ""}">${escapeHtml(v)}</td></tr>`)
      .join("")}</tbody></table>`,
  });

  // --- 9. The swarm's own report ------------------------------------------
  const own = await (async () => {
    for (const candidate of [sentinel?.output, "work/report.md", "work/notes.md"]) {
      if (!candidate || !candidate.startsWith("work/") || !candidate.endsWith(".md")) continue;
      const text = await readFile(join(sandbox, candidate), "utf8").catch(() => null);
      if (text && text.trim()) return { path: candidate, text };
    }
    return null;
  })();
  if (own) {
    sections.push({
      n: 9,
      title: `The swarm's own report (${basename(own.path)})`,
      breakBefore: true,
      html: `<p>Reproduced verbatim from <code>${escapeHtml(own.path)}</code>, sha256 <span class="hash">${escapeHtml(artifacts.files.find((f) => f.path === own.path)?.sha256 ?? "not hashed")}</span>. Its headings are demoted so this document keeps one outline; nothing else is changed.</p>
<div class="embedded">${markdownToHtml(own.text, 2)}</div>`,
    });
  }

  const SECTION_DESC: Record<number, string> = {
    1: "what the run concluded, by confidence",
    2: "what it was given, and the hash of each file",
    3: "every dated event, in order",
    4: "the exhibits those conclusions rest on",
    5: "who ran it, on what, for how much",
    6: "what the run produced, hashed",
    7: "what this document does not claim",
    8: "the custody record",
    9: "the swarm's own words, verbatim",
  };
  const toc = sections
    .map(
      (s) =>
        `<li><span class="n">${s.n}</span><a href="#s${s.n}">${escapeHtml(s.title)}</a>${SECTION_DESC[s.n] ? `<span class="desc">${escapeHtml(SECTION_DESC[s.n])}</span>` : ""}</li>`,
    )
    .join("");
  // The cover's scorecard: the six numbers a reader wants before they decide
  // how much of the rest to read.
  const scoreCells: Array<[string, string, string]> = [
    [String(findings.length), "Findings", `${findings.filter((f) => f.confidence === "high").length} at high confidence`],
    [String(iocs.length), "Indicators", "recorded with their source"],
    [String(timeline.length), "Dated events", "on the timeline"],
    [inputs ? String(inputs.files.length) : "0", "Evidence files", inputs ? bytesHuman(inputs.bytes ?? 0) : "none given"],
    [durationHuman(durationMs), "Elapsed", `${team.n} agent${team.n === 1 ? "" : "s"}`],
    [unmetered ? "free" : usd(budget?.spent_usd ?? 0), "Spend", unmetered ? "local models" : `of ${usd(run?.cap_usd ?? budget?.cap_usd ?? 0)} cap`],
  ];
  const scorecard = `<div class="scorecard">${scoreCells
    .map(([v, k, sub]) => `<div class="cell"><div class="k">${escapeHtml(k)}</div><div class="v">${escapeHtml(v)}</div><div class="s">${escapeHtml(sub)}</div></div>`)
    .join("")}</div>`;
  const title = `${caseId ? `${caseId} — ` : ""}DFIR Swarm report${id ? ` ${id}` : ""}`;
  // One sentence under the case number: what a reader learns before the fold.
  const highCount = findings.filter((f) => f.confidence === "high").length;
  const headline = findings.length
    ? `${findings.length} finding${findings.length === 1 ? "" : "s"}${highCount ? `, ${highCount} at high confidence` : ""}`
    : "no findings recorded";
  const stateChip = sentinel ? chip("finished", "moss") : run?.state === "stopped" ? chip("stopped", "brick") : chip("did not finish", "saffron");

  return `<!doctype html>
<html lang="en">
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>${escapeHtml(title)}</title>
<meta name="generator" content="DFIR Swarm ${escapeHtml(version)}">
<meta name="dcterms.created" content="${escapeHtml(generatedAt)}">
<style>${STYLE}</style>
<body>
<main>
  <header class="cover">
    <div class="mark">${mark}<span class="wordmark">DFIR Swarm</span></div>
    <p class="kicker">${escapeHtml(options.organisation || "Forensic report")}</p>
    <h1>${escapeHtml(caseId || run?.label || id || "Untitled case")}</h1>
    <p class="case-line"><strong>${escapeHtml(headline)}</strong> ${stateChip}</p>
    ${scorecard}
    <dl class="facts">
      <dt>Examiner</dt><dd>${escapeHtml(examiner || "—")}</dd>
      <dt>Run</dt><dd class="hash">${escapeHtml(id || "—")}</dd>
      <dt>Period</dt><dd class="tabular">${escapeHtml(startedAt || "—")} → ${escapeHtml(endedAt || "—")}</dd>
      <dt>Tool</dt><dd>DFIR Swarm ${escapeHtml(version)}</dd>
      <dt>Generated</dt><dd class="tabular">${escapeHtml(generatedAt)}</dd>
    </dl>
  </header>

  <nav class="toc" aria-label="Contents">
    <h2>Contents</h2>
    <ol>${toc}</ol>
    <p class="note">Section numbers, not page numbers: the pagination belongs to whatever prints this file, and a number this document computed itself would be wrong in every engine but one. <code>swarm.sh report &lt;id&gt; --pdf</code> prints it through a browser, which numbers the pages in the footer and puts this document's title and the print date at the top of each one.</p>
  </nav>

${sections
    .map(
      (s) => `  <section id="s${s.n}"${s.breakBefore ? ' class="page-break"' : ""}>
    <div class="sec-head"><span class="n">${s.n}</span><h2>${escapeHtml(s.title)}</h2>${s.count ? `<span class="count">${escapeHtml(s.count)}</span>` : ""}</div>
${s.html}
  </section>`,
    )
    .join("\n\n")}

  <footer>
    <p>Produced by DFIR Swarm ${escapeHtml(version)} from the run's own files. This document is self-contained: it fetches no stylesheet, script, font or image, so it renders the same on a machine with no network. The evidence hashes above are the ones recorded at kickoff; the artifact hashes are of the files as they stood when this was generated.</p>
    <p>DFIR Swarm is free software under the GNU Affero General Public License v3 or later. The name and the wordmark are not covered by that licence.</p>
  </footer>
</main>
</body>
</html>
`;
}

// ---------------------------------------------------------------------------

if (process.argv[1] && resolve(process.argv[1]) === resolve(fileURLToPath(import.meta.url))) {
  const args = process.argv.slice(2);
  const sandbox = args.find((a) => !a.startsWith("--"));
  if (!sandbox) {
    console.error("Usage: report.ts <sandbox> [--lint]");
    process.exit(2);
  }
  if (args.includes("--lint")) {
    const output = (await readFile(join(resolve(sandbox), "work", "report.md"), "utf8").catch(() => "")) || "";
    if (!output.trim()) {
      console.error("No work/report.md to lint.");
      process.exit(1);
    }
    const findings = lintReport(output);
    for (const f of findings) console.error(`warn: ${f.section}: ${f.reason}`);
    console.error(findings.length ? `${findings.length} section(s) cite nothing checkable.` : "Every numbered section cites something checkable.");
    process.exit(0);
  }
  await stat(sandbox).catch(() => {
    console.error(`No such sandbox: ${sandbox}`);
    process.exit(1);
  });
  process.stdout.write(await renderReport(sandbox));
}
