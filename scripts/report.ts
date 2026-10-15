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
import { readdir, readFile, stat } from "node:fs/promises";
import { basename, dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import {
  EVENTS_REL,
  claimKey,
  hostTime,
  readNames,
  eventChainVerifier,
  readSandboxFile,
  supersededBy,
  type AgentBudget,
  type LedgerEntry,
} from "../extensions/protocol.ts";
import { createHash } from "node:crypto";
import { hashArtifacts, type ArtifactIndex } from "./artifacts.ts";
import { GROUNDED_VIA_JOB, humanReviewFrom, renderReportBody, type HumanReview } from "./report-body.ts";
import { custodyAnchorPath, manifestMeta, sealedIndex, verdictAnchorLine, verdictAnchorState } from "./custody.ts";
import { hashRegularFile, openRegular, readRegularText } from "./regular-file.ts";
import { createInterface } from "node:readline";
import { loadRunContext, readJsonFile } from "./run-record.ts";
import { coverageLine, coverageOf, type CoverageReport, type Grounding } from "./coverage.ts";
import { ReviewFileError, dispositionsHead, isSandboxPath, ledgerHead, readReviews, reviewState, signoffCoverage, technicalReviewsOf, verifyReviewChain, type ReviewLine, type TechnicalReview } from "./review.ts";
import { bodyRelease, readReleases } from "./release-record.ts";

const ROOT = join(dirname(fileURLToPath(import.meta.url)), "..");

/**
 * The release a rendering is for (scripts/release.ts): which version, a
 * machine's draft or an examiner's adoption, when, and who seals it.
 */
export type RenderRelease = {
  version: number;
  state: "draft" | "adopted";
  at: string;
  examiner?: { id: string; name: string; organisation: string; competence: string; fingerprint: string } | null;
  machine?: { fingerprint: string } | null;
  /** What the examiner did with the conclusions, counted, and who checked the methods. */
  adoption?: { adopted: number; qualified: number; withdrawn: number; inconclusive: number; not_adopted: number; scope: "answers" | "report"; technical: string[] } | null;
};

export type ReportOptions = {
  runsDir?: string;
  /**
   * The release this rendering is for. A draft, or no release at all,
   * carries the DRAFT mark, decided now, when the bytes are rendered; a
   * release an examiner adopts renders its own final bytes without it.
   * Absent, the run's releases are read to say which one, if any, is the
   * adopted report, and that this rendering is not it.
   */
  release?: RenderRelease | null;
  /** Overrides the registry's case id and examiner, for a one-off render. */
  caseId?: string;
  examiner?: string;
  /** The organisation the report is issued by. Free, and it belongs here. */
  organisation?: string;
  /** Fixes `generated_at` so two renders of one run are byte-identical. */
  now?: string;
  /** Skip a second walk of work/ when the caller already hashed it. */
  artifacts?: ArtifactIndex;
  /** The examiner's review, when the caller already read it; read from the runs directory otherwise. */
  review?: ReviewState | null;
  /**
   * The files handed over with this report (the dossier's court set), each
   * with its size and sha256 or why it is absent: printed in the custody
   * section so the paper copy names what came with it.
   */
  handover?: Array<{ name: string; description: string; present: boolean; reason?: string; bytes: number | null; sha256: string | null }>;
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

export function parseFrontMatter(text: string): Record<string, string> {
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
section, .cover, .toc, .preamble, footer { padding-left: clamp(1.25rem, 5vw, 3.25rem); padding-right: clamp(1.25rem, 5vw, 3.25rem); }

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
/* In a table cell or an exhibit's head a chip may wrap: a nowrap chip wider
   than its column was cut off at the table's edge, on a phone and in the
   console's narrow report pane. */
td .chip, .exhibit .chips .chip { white-space: normal; }
/* The artifact and hand-over tables: room for the path and the hash, and a
   last column wide enough for its chip or its reason. */
table.artifacts th:nth-child(1) { width: 36%; }
table.artifacts th:nth-child(2) { width: 11%; }
table.artifacts th:nth-child(3) { width: 37%; }
table.artifacts th:nth-child(4) { width: 16%; }
table.handover th:nth-child(1) { width: 22%; }
table.handover th:nth-child(2) { width: 10%; }
table.handover th:nth-child(3) { width: 33%; }
table.handover th:nth-child(4) { width: 35%; }

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
.exhibit .chips { margin-left: auto; display: flex; flex-wrap: wrap; justify-content: flex-end; gap: .35rem; }
.exhibit .value { margin: .35rem 0 .5rem; font-size: .98rem; line-height: 1.45; }
.exhibit dl { display: grid; grid-template-columns: 5.4rem minmax(0, 1fr); gap: .18rem .8rem; margin: 0; font-size: .82em; }
.exhibit dt { color: var(--ink-3); }
.exhibit dd { margin: 0; overflow-wrap: anywhere; color: var(--ink-2); }
.exhibit-ioc { border-left-color: var(--saffron); }
.exhibit-finding { border-left-color: var(--kelp); }
.exhibit-absence { border-left-style: dashed; }
.exhibit-hypothesis { border-left-style: dotted; }
.exhibit-limitation { border-left-color: var(--brick); border-left-style: dashed; }

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
.watermark { position: fixed; top: 40%; left: 0; right: 0; text-align: center; font: 700 110pt/1 var(--sans); letter-spacing: .12em; color: rgba(178, 58, 72, .10); transform: rotate(-28deg); pointer-events: none; z-index: 0; }
.release-banner { margin: 1.4rem 0 0; padding: .6rem .85rem; border: 2px solid var(--brick); background: var(--brick-soft); color: var(--brick-ink); font-weight: 600; }
.release-banner.adopted { border-color: var(--moss); background: var(--moss-soft); color: var(--moss-ink); }
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
  section, .cover, .toc, .preamble, footer { padding-left: 0; padding-right: 0; }

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

function chip(text: string, tone: "kelp" | "saffron" | "brick" | "slate" | "moss" | "none"): string {
  return `<span class="chip chip-${tone}">${escapeHtml(text)}</span>`;
}

/** A section as the document prints it: the body's (1 to 10, appendices A to C), then custody (D) and the artifacts (E). */
type Section = { id: string; n: string; title: string; desc?: string; html: string; breakBefore?: boolean; count?: string };

/** An examiner's review of a run, as the report reads it (scripts/review.ts keeps the file). */
export type ReviewState = {
  lines: number;
  /** Whether the review file's own chain holds, and where it does not. */
  chain: { ok: boolean; reason?: string | null };
  /** The examiner's latest word on each entry. */
  byEntry: Map<number, ReviewLine>;
  /** The last signature, over the ledger head it names. */
  signed: ReviewLine | null;
  /** The ledger's head now, to hold the signature to: the last chain hash, or file:<sha256>. */
  head: string;
  /** The sha256 of the report the sign-off names, as it is now: null when it is gone; undefined when there is no sign-off or it names none. */
  reportNow?: string | null;
  /** Why the review file could not be read (a link, not a regular file): said as that, never as "not reviewed". */
  unreadable?: string;
  /** The last technical reviewer's record: who, on what competence, what was checked. */
  technical?: { name: string; competence?: string; checked?: string } | null;
  /** Every technical review, each with where it stands against the run as it is now (review.ts technicalReviewsOf). */
  technicals?: TechnicalReview[];
};

/**
 * The examiner's review of run `id`, from `<runs>/reviews/<id>.jsonl`, with
 * its chain checked and the ledger's current head beside it; null when there
 * is none.
 */
export async function readReviewState(runsDir: string, id: string, sandbox: string, ledger: readonly LedgerEntry[], upTo?: number): Promise<ReviewState | null> {
  if (!id) return null;
  let lines: Awaited<ReturnType<typeof readReviews>>;
  try {
    lines = await readReviews(runsDir, id);
    // A release renders the review as it bound it: its first lines only.
    if (upTo !== undefined) lines = lines.slice(0, upTo);
  } catch (err) {
    if (!(err instanceof ReviewFileError)) throw err;
    return { lines: 0, chain: { ok: false, reason: err.why }, byEntry: new Map(), signed: null, head: "", unreadable: err.why };
  }
  if (!lines.length) return null;
  const parsed = lines.filter((l) => typeof (l as ReviewLine).action === "string") as ReviewLine[];
  const { entries, signed } = reviewState(parsed);
  const digest = await hashRegularFile(join(sandbox, "ledger", "entries.jsonl"));
  const fileSha = digest && "sha256" in digest ? digest.sha256 : "";
  const head = ledgerHead(ledger.map((e) => ({ ...(e as object), text: "" })) as Parameters<typeof ledgerHead>[0], fileSha);
  // The report the sign-off is over, hashed as it is now.
  let reportNow: string | null | undefined;
  if (signed?.report_path && isSandboxPath(signed.report_path)) {
    const r = await hashRegularFile(join(sandbox, signed.report_path));
    reportNow = r && "sha256" in r ? r.sha256 : null;
  }
  const tr = [...parsed].reverse().find((l) => l.action === "technical_review" && l.reviewer);
  // Every technical review, held to the run as it stands: the report's five wordings.
  const custody = await hashRegularFile(join(sandbox, "custody.json"));
  const report = await hashRegularFile(join(sandbox, "work", "report.md"));
  const technicals = technicalReviewsOf(lines as Array<ReviewLine & { text: string }>, { report_sha256: report && "sha256" in report ? report.sha256 : null, ledger_head: head || null, custody_sha256: custody && "sha256" in custody ? custody.sha256 : null, dispositions_head: dispositionsHead(parsed) });
  return { lines: lines.length, chain: verifyReviewChain(lines), byEntry: entries, signed, head, reportNow, technical: tr?.reviewer ? { name: tr.reviewer.name, competence: tr.reviewer.competence, ...(tr.methods_checked ? { checked: tr.methods_checked } : {}) } : null, technicals };
}

/**
 * Whether the examiner's sign-off covers this run as it stands: the
 * review's chain holds, and the ledger's head and the report's hash are the
 * ones signed. Only then does the report say "reviewed and signed".
 */
export function signoffCurrent(state: ReviewState | null): boolean {
  if (!state?.signed || state.unreadable) return false;
  return signoffCoverage(state.signed, { chainOk: state.chain.ok, ledgerHead: state.head || null, reportSha: state.reportNow }).current;
}

/** What a sign-off that does not cover the run as it stands is over, in words. */
export function signoffScope(state: ReviewState): string {
  const s = state.signed as ReviewLine;
  const c = signoffCoverage(s, { chainOk: state.chain.ok, ledgerHead: state.head || null, reportSha: state.reportNow });
  const parts: string[] = [];
  if (!state.chain.ok) parts.push("its review file's chain is broken, so what it says is not held to anything");
  if (c.ledger === false) parts.push(`it is over an earlier ledger (head ${s.ledger_head}), and entries were recorded after it`);
  if (!s.report_sha256) parts.push("it names no report");
  else if (c.report === false) parts.push(`it is over ${s.report_path ?? "a report"} as it was (sha256 ${s.report_sha256}), and ${state.reportNow ? `that file is now ${state.reportNow}` : "that file is gone"}`);
  return parts.join("; ");
}

/**
 * The examiner's review as the report's body takes it, with whether the
 * sign-off covers the run as it stands: the report and the run summary pass
 * the same, so their counts of what was adopted agree.
 */
export function bodyReview(review: ReviewState | null, examiner?: { name: string; organisation?: string; competence?: string } | null): HumanReview | null {
  const current = review?.signed && !review.unreadable ? signoffCurrent(review) : null;
  const h = humanReviewFrom(review, examiner ? { name: examiner.name, ...(examiner.organisation ? { organisation: examiner.organisation } : {}) } : null, review && current !== null ? { current, ...(current ? {} : { scope: signoffScope(review) }) } : undefined);
  if (!h) return h;
  // The adopting examiner's competence, and the technical reviewer, when there are.
  return {
    ...h,
    ...(examiner?.competence && h.examiner ? { examiner: { ...h.examiner, competence: examiner.competence } } : {}),
    ...(review?.technical ? { technicalReviewer: review.technical } : {}),
    ...(review && !review.unreadable ? { technicalReviews: (review.technicals ?? []).map((t) => ({ name: t.reviewer.name, organisation: t.reviewer.organisation, competence: t.reviewer.competence, checked: t.methods_checked, outcome: t.outcome ?? null, reviewed_at: t.reviewed_at ?? null, disagreements: t.disagreements ?? [], words: t.words ?? "" })) } : {}),
  };
}

/** The examiner's standing on one entry, in the words of its exhibit. */
export function reviewStatusOf(state: ReviewState | null, entry: LedgerEntry): string {
  if (!state) return "not reviewed by an examiner";
  if (state.unreadable) return `the examiner's review could not be read (${state.unreadable})`;
  const l = state.byEntry.get(entry.seq);
  if (!l) return "not reviewed";
  const verb = l.action === "accept" ? "accepted" : l.action === "reject" ? "REJECTED" : "amended";
  const other = l.entry_hash && entry.hash && l.entry_hash !== entry.hash ? `; reviewed against entry hash ${l.entry_hash}, which is not this entry's` : "";
  return `${verb} by ${l.examiner} at ${l.at}${l.note ? `: ${l.note}` : ""}${other}`;
}

/** The report's "Examiner review" row. */
export function reviewLine(state: ReviewState | null, ledger: readonly LedgerEntry[]): string {
  if (state?.unreadable) return `the examiner's review could not be read: ${state.unreadable} (reviews/<run>.jsonl beside the registry); nothing here says whether it was reviewed`;
  if (!state || !state.lines) return "not reviewed by an examiner: every finding here is the agents' conclusion";
  const counts = { accept: 0, reject: 0, amend: 0 };
  for (const l of state.byEntry.values()) if (l.action in counts) counts[l.action as "accept" | "reject" | "amend"] += 1;
  // A review names the entry's hash as it was reviewed; one that no longer
  // matches was a review of a different entry.
  const stale = ledger.filter((e) => {
    const l = state.byEntry.get(e.seq);
    return Boolean(l?.entry_hash && e.hash && l.entry_hash !== e.hash);
  }).length;
  const reviewed = `${counts.accept} accepted, ${counts.reject} rejected, ${counts.amend} amended, ${ledger.length - state.byEntry.size} of ${ledger.length} entries not reviewed${stale ? `; ${stale} reviewed against an entry hash that is not the entry's now` : ""}`;
  const chain = state.chain.ok ? "the review file's chain verifies" : `the review file's chain is BROKEN${state.chain.reason ? ` (${state.chain.reason})` : ""}`;
  const head = state.head;
  const sign = state.signed
    ? `signed by ${state.signed.examiner} at ${state.signed.at} over ledger head ${state.signed.ledger_head ?? "not named"}${
        state.signed.ledger_head && head ? (state.signed.ledger_head === head ? " (the ledger's current head)" : ` — NOT the ledger's current head (${head}): entries were recorded after the signature`) : ""
      }${
        !state.signed.report_sha256
          ? " and over no report"
          : ` and ${state.signed.report_path ?? "the report"} sha256 ${state.signed.report_sha256}${state.reportNow === undefined ? "" : state.reportNow === state.signed.report_sha256 ? " (the report as it is)" : ` — NOT the report as it is (${state.reportNow ?? "gone"}): it changed after the signature`}`
      }`
    : "not signed";
  return `${reviewed}; ${sign}; ${chain}`;
}

/**
 * The swarm's report held to the index custody sealed at stop: the sha256 of
 * the bytes this document reproduces, labelled as that, and whether they are
 * the ones sealed. A report changed after the stop says CHANGED SINCE
 * CUSTODY with the sealed hash, rather than today's hash standing in for the
 * record's.
 */
export async function ownReportSeal(sandbox: string, path: string, sha256: string, custody: { at?: string; artifacts?: { index_sha256?: string } | null } | null, anchored: string | null | undefined): Promise<string> {
  const now = `Its sha256 as reproduced here: ${sha256}`;
  if (!custody) return `${now}; not sealed: no custody was taken (swarm.sh stop takes it).`;
  const when = custody.at ?? "stop";
  const idx = await sealedIndex(sandbox, custody, anchored);
  if (idx.state === "not sealed") return `${now}; not held to a seal: ${idx.why}.`;
  if (idx.state === "differs") return `${now}; NOT HELD TO THE SEAL: ${idx.why}.`;
  const sealed = (idx.index.files ?? []).find((f) => f.path === path);
  if (!sealed) return `${now}. NOT SEALED: the index custody sealed at ${when} has no ${path}; it was written after the stop.`;
  return sealed.sha256 === sha256
    ? `${now}, the bytes custody sealed at ${when} (artifacts.json).`
    : `${now}. CHANGED SINCE CUSTODY: custody sealed ${path} at ${when} with sha256 ${sealed.sha256}; these are not those bytes.`;
}

/** The run's model gateway as the kickoff recorded it (`isolation.model_gateway`); null when it had none. */
export type GatewayRecord = { providers: string[]; declined: Array<{ provider: string; reason: string }> };

export function gatewayRecordOf(run: Record<string, unknown> | null | undefined): GatewayRecord | null {
  const iso = run?.isolation && typeof run.isolation === "object" ? (run.isolation as { model_gateway?: unknown }) : null;
  const g = iso?.model_gateway && typeof iso.model_gateway === "object" ? (iso.model_gateway as { on?: unknown; providers?: unknown; declined?: unknown }) : null;
  if (!g || g.on !== true) return null;
  const providers = Array.isArray(g.providers) ? g.providers.filter((p): p is string => typeof p === "string") : [];
  const declined = Array.isArray(g.declined)
    ? g.declined.flatMap((d) => (d && typeof d === "object" && typeof (d as { provider?: unknown }).provider === "string" ? [{ provider: (d as { provider: string }).provider, reason: String((d as { reason?: unknown }).reason ?? "") }] : []))
    : [];
  return { providers, declined };
}

/** The gateway's own totals (traces/model-gateway.json), as far as the report needs them. */
export type GatewayTotals = { spent_usd?: number; seats?: Record<string, { calls?: number; refused?: number; spent_usd?: number; unpriced_calls?: number }> };

/**
 * Whose word a VM run's spend is. Without the gateway, each seat's own
 * report (the wording is unchanged); with it, the host's meter, for the
 * providers it fronted, and each seat's report for the ones it did not.
 * Empty for a host run.
 */
export function vmSpendNote(run: Record<string, unknown> | null | undefined, totals: GatewayTotals | null): string {
  const iso = run?.isolation as { mode?: unknown } | undefined;
  if (iso?.mode !== "microvm") return "";
  const gw = gatewayRecordOf(run);
  if (!gw) return " (as each VM reported its own spend; the host did not meter it)";
  const unpriced = Object.values(totals?.seats ?? {}).reduce((n, t) => n + (Number(t?.unpriced_calls) || 0), 0);
  const unpricedNote = unpriced ? `; ${unpriced} call${unpriced === 1 ? "" : "s"} the gateway could not price` : "";
  if (!gw.declined.length) return ` (metered on the host by the model gateway${unpricedNote})`;
  return ` (metered on the host by the model gateway for ${gw.providers.join(", ") || "no provider"}; ${gw.declined.map((d) => d.provider).join(", ")} ${gw.declined.length === 1 ? "was" : "were"} not fronted, and that spend is what each VM reported${unpricedNote})`;
}

/** The custody row for the gateway: what it fronted, what it metered and refused, and custody's word on its log. */
export function gatewayLine(gw: GatewayRecord, totals: GatewayTotals | null, log: { lines: number; intact: boolean; detail: string; refused?: string } | null | undefined): string {
  const seats = Object.entries(totals?.seats ?? {}).sort(([a], [b]) => (a < b ? -1 : a > b ? 1 : 0));
  const calls = seats.reduce((n, [, t]) => n + (Number(t?.calls) || 0), 0);
  const refused = seats.filter(([, t]) => Number(t?.refused) > 0).map(([id, t]) => `${id} ${t?.refused}`);
  const unpriced = seats.reduce((n, [, t]) => n + (Number(t?.unpriced_calls) || 0), 0);
  const parts = [
    `on for ${gw.providers.join(", ") || "no provider"}`,
    totals ? `${usd(Number(totals.spent_usd) || 0)} metered on the host across ${calls} call${calls === 1 ? "" : "s"}` : "its totals were not found (traces/model-gateway.json)",
    ...(gw.declined.length ? [`not fronted, so seat-reported: ${gw.declined.map((d) => `${d.provider}${d.reason ? ` (${d.reason})` : ""}`).join(", ")}`] : []),
    ...(refused.length ? [`calls refused by the gateway: ${refused.join(", ")}`] : []),
    ...(unpriced ? [`${unpriced} call${unpriced === 1 ? "" : "s"} it could not price`] : []),
    log ? `its log: ${log.refused ? log.detail : log.intact ? `${log.lines} lines, chain intact (custody)` : `CHAIN BROKEN (${log.detail})`}` : "its log was not checked by custody",
  ];
  return parts.join("; ");
}

/**
 * What the kickoff recorded about how the run was held that a custody
 * record should carry: the disk's encryption, a legal hold, a notify hook
 * (whether one was set; the command itself is never recorded, since it may
 * carry a token), how a synced folder was allowed, an earlier run's ledger
 * handed in as hypotheses, and a run started as root.
 */
export function heldRows(run: Record<string, unknown> | null | undefined): Array<[string, string]> {
  if (!run) return [];
  const rows: Array<[string, string]> = [];
  const enc = run.disk_encryption;
  if (enc === "on" || enc === "off" || enc === "unknown") {
    rows.push(["Disk encryption", enc === "on" ? "on, where the run is kept" : enc === "off" ? "OFF where the run is kept: the evidence copy and the record sit on an unencrypted disk" : "not known where the run is kept"]);
  }
  if ("hold" in run || run.state === "purged") {
    const h = run.hold && typeof run.hold === "object" ? (run.hold as { reason?: unknown; at?: unknown; by?: unknown }) : null;
    rows.push([
      "Legal hold",
      run.state === "purged"
        ? "the run was PURGED"
        : h
          ? `held${typeof h.reason === "string" && h.reason ? `: ${h.reason}` : ""}${typeof h.by === "string" ? `, by ${h.by}` : ""}${typeof h.at === "string" ? `, at ${h.at}` : ""}`
          : "not held",
    ]);
  }
  if (typeof run.notify === "boolean") rows.push(["Notify hook", run.notify ? "set (its command is not recorded)" : "none"]);
  if (run.synced_folder_allowed_by === "flag" || run.synced_folder_allowed_by === "marker") {
    rows.push(["Synced folder", `the run's files sit in a synced folder, allowed by ${run.synced_folder_allowed_by === "flag" ? "--allow-synced-folder" : "a marker in the folder"}: copies may leave this machine`]);
  }
  if (run.ledger_from && typeof run.ledger_from === "object") {
    const l = run.ledger_from as { run?: unknown; entries?: unknown; reviewed?: unknown };
    rows.push(["Prior ledger", `${Number(l.entries) || 0} entr${Number(l.entries) === 1 ? "y" : "ies"} from run ${String(l.run ?? "?")}${l.reviewed === true ? " (reviewed ones only)" : ""}, handed in as hypotheses to re-derive, not as evidence`]);
  }
  if (run.allow_root === true) rows.push(["Started as root", "yes, allowed by --allow-root"]);
  return rows;
}

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
    case "microvm":
      return "enforced (microVM: each agent could write only its own work/<id>/, work/extracted/<id>/, work/quarantine/<id>/, tool-output/<id>/ and Pi session; the rest of the run was read-only in its VM, shared files and the board were written by the hub on the host, and of the host the VM was given only what its record lists as mounted, all read-only: the harness code, the packs, the evidence, the run)";
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
    case "unreachable":
      return "out of reach: the agents ran in microVMs, and no host socket but each one's own hub link was in its VM";
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
    case "channel":
      return "by channel (each agent's VM reached the hub on its own vsock port, and the hub named the sender from the port a line came in on; no agent held a token)";
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
    case "microvm":
      // Beside the run on the host, and the host was not in any VM.
      return true;
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
    case "microvm":
      return "every agent's VM was probed at kickoff (vm/<id>.json): the run's floor read-only, its own directories writable, the evidence read-only, the hub reachable";
    default:
      return "not recorded (this run predates the field)";
  }
}

/** What the trace's hash chain says, for the custody section. */
/**
 * What the run tried to reach and was refused. "Nothing was refused" is a
 * claim only a log can back: without one the line used to say it anyway, and
 * a run whose egress was enforced by something that keeps no log (or not
 * enforced at all) read as if it had been watched and was clean.
 */
export function egressRefusedLine(
  denied: Array<[string, number]>,
  logPresent: boolean,
  run: { netguard?: unknown; netguard_mode?: unknown; isolation?: { mode?: string } } | null | undefined,
  secretViolations: string[] = [],
  ownHostStops: string[] = [],
): string {
  if (denied.length) return denied.map(([host, n]) => `${host}${n > 1 ? ` (${n})` : ""}`).join(", ");
  if (logPresent) return "nothing was refused";
  if (run?.isolation?.mode === "microvm") {
    // The one refusal msb writes down is a credential's placeholder aimed at
    // a host it is not bound to; custody read those from each VM's log. A
    // stop on the credential's own host is told apart: no leak, a failed
    // request (msb 0.7.2 reads a body starting with % or \u that way).
    const own = ownHostStops.length
      ? `; msb also stopped ${ownHostStops.length} request${ownHostStops.length === 1 ? "" : "s"} to a credential's own host on a placeholder it found outside the headers (not a leak; each request failed): ${ownHostStops.join("; ")}`
      : "";
    const stopped = (secretViolations.length
      ? `; msb stopped ${secretViolations.length} credential placeholder${secretViolations.length === 1 ? "" : "s"} aimed at a host not its own: ${secretViolations.join("; ")}`
      : "; msb stopped no credential placeholder on its way to another host") + own;
    if (run.netguard_mode === "microvm-open") return `not observable, and the network was open (--no-netguard): each VM could reach every public host${stopped}`;
    return `not observable: each agent's microVM refused everything outside its rules, and that refusal leaves no log${stopped}`;
  }
  if (run?.netguard === false) return "not observable: no egress control was running";
  return "not observable: no netguard log was kept";
}

type CustodyStops = { vms?: Array<{ agent?: string; secret_violations?: Array<{ env?: string; host?: string; method?: string; path?: string; location?: string; own_host?: boolean | null }> }> | null } | null | undefined;

function stopLines(custody: CustodyStops, own: boolean): string[] {
  return (custody?.vms ?? []).flatMap((v) =>
    (v.secret_violations ?? [])
      .filter((x) => (x.own_host === true) === own)
      .map((x) => `${v.agent ?? "?"} ${x.env ?? ""} → ${x.host ?? ""} ${x.method ?? ""} ${x.path ?? ""}${x.location ? ` (${x.location})` : ""}`.replace(/\s+/g, " ").trim()),
  );
}

/** Each placeholder msb stopped on its way to a host not its own (or not known to be), as custody read it from the VMs' logs. */
export function custodyViolations(custody: CustodyStops): string[] {
  return stopLines(custody, false);
}

/** Each request msb stopped on the credential's own host: a failed call, not a leak. */
export function custodyOwnHostStops(custody: CustodyStops): string[] {
  return stopLines(custody, true);
}

/**
 * Where the evidence went. Every byte an agent reads is sent to its model's
 * provider; on BelkaCTF #6 that included a BitLocker recovery key, sent to
 * four providers. That is a case-acceptance decision, and this line is what
 * lets a reader check it was made.
 */
export function providersLine(run: { providers?: unknown } | null | undefined): string {
  const list = Array.isArray(run?.providers)
    ? (run!.providers as Array<{ model?: string; hosts?: string[]; local?: boolean }>)
    : [];
  if (!list.length) return "not recorded";
  return list
    .map((p) => {
      const where = p.local ? "this machine (local model)" : p.hosts?.length ? p.hosts.join(", ") : "its provider (host not recorded)";
      return `${p.model ?? "?"}${(p as { role?: string }).role === "summary" ? " (the summary model self-compaction hands contexts to)" : ""} → ${where}`;
    })
    .join("; ");
}

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
  operatorActions = 0,
  harnessFromShell = 0,
): string {
  // The failure verdict comes first — before "no trace" as well. A file
  // with every `prev` stripped has no chain *and* contradicts the anchor;
  // reported the other way round, the most complete rewrite possible printed
  // as "this run had no trace collector" — the one sentence that tells the
  // reader to stop worrying. A trace emptied while its anchor names lines is
  // the same case with nothing left.
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
  if (!chain.total) return "no trace";
  if (!chain.chained) return `${chain.total} lines, not chained (this run had no trace collector)`;
  const notes: string[] = [];
  // Both are ordinary in an older run and a finding in a current one, so they
  // are stated rather than folded into "intact".
  if (chain.disputed) notes.push(`${chain.disputed} line(s) claimed another agent's name`);
  const unattributed = Math.max(0, (chain.unverified ?? 0) - operatorActions - harnessFromShell);
  if (operatorActions) notes.push(`${operatorActions} operator action(s) run from a shell outside the run (stop, reap, say), recorded as the operator's and also on runs/operator-audit.jsonl`);
  if (harnessFromShell) notes.push(`${harnessFromShell} ledger entr${harnessFromShell === 1 ? "y" : "ies"} the harness recorded from the operator's shell (evidence or material added with no hub running), each line carrying its entry's hash`);
  if (unattributed) notes.push(`${unattributed} line(s) could not be attributed to a pane`);
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

/**
 * How the copy was held to its source at kickoff, as the manifest says: by
 * name, kind and size, never by content — the source is not hashed. Null
 * when the manifest says nothing (evidence used in place, an older run).
 */
export function sourceCheckedLine(sourceChecked: unknown): string | null {
  // The content check: every copied file's source hashed again and compared
  // with the manifest's sha256.
  if (sourceChecked && typeof sourceChecked === "object") {
    const c = sourceChecked as { by?: unknown; files?: unknown; mismatches?: unknown; seconds?: unknown };
    if (c.by !== "content") return null;
    const files = Number(c.files) || 0;
    const mismatches = Number(c.mismatches) || 0;
    const secs = Number(c.seconds);
    return `the copy was checked against its source at kickoff by content: ${files} file${files === 1 ? "" : "s"} hashed again from the source, ${mismatches ? `${mismatches} MISMATCH${mismatches === 1 ? "" : "ES"}` : "0 mismatches"}${Number.isFinite(secs) && secs > 0 ? ` (${Math.round(secs)} s)` : ""}`;
  }
  if (typeof sourceChecked !== "string" || !sourceChecked) return null;
  if (sourceChecked === "MISMATCH") return "the copy did NOT match its source by name, kind and size at kickoff";
  return `the copy was checked against its source at kickoff by ${sourceChecked}, not by content (the source itself was not hashed)`;
}

type HostInputs = {
  unverifiable?: unknown;
  unchanged?: boolean;
  files?: number;
  changed?: unknown[];
  missing?: unknown[];
  added?: unknown[];
  skipped?: unknown[];
  unreadable?: unknown[];
  manifest_anchored?: boolean | null;
  checked?: { files?: number; links?: number; special?: number };
  digests_compared?: { md5?: number; sha1?: number };
};

/**
 * The host's re-hash of the evidence, as the custody row says it. Only what
 * was read again is called intact: a custody that ran out of time before
 * some files found nothing changed in the rest, which is not a "yes" and was
 * printed as "NO — 0 changed, 0 missing, 0 added", as if the evidence had
 * changed. Null when custody did not look at the evidence at all.
 */
export function hostEvidenceLine(inputs: unknown, at: string | undefined): string | null {
  if (!inputs || typeof inputs !== "object") return null;
  const i = inputs as HostInputs;
  if (typeof i.unverifiable === "string") return `UNVERIFIABLE by the host — ${i.unverifiable}`;
  const n = (v?: unknown[]) => (Array.isArray(v) ? v.length : 0);
  const manifest =
    i.manifest_anchored === true ? ", manifest anchored" : i.manifest_anchored === false ? "" : ", manifest not anchored (the kickoff recorded no hash of it)";
  const notRead = `${n(i.skipped) ? `, ${n(i.skipped)} not re-read before custody's deadline` : ""}${n(i.unreadable) ? `, ${n(i.unreadable)} unreadable by the host` : ""}`;
  if (n(i.changed) || n(i.missing) || n(i.added) || i.manifest_anchored === false) {
    return `NO — the host's re-hash found ${n(i.changed)} changed, ${n(i.missing)} missing, ${n(i.added)} added${i.manifest_anchored === false ? "; the manifest was rewritten" : ""}${notRead ? `;${notRead.slice(1)}` : ""}`;
  }
  const files = i.files ?? 0;
  if (i.unchanged) {
    const how = [
      `${files} file${files === 1 ? "" : "s"}`,
      ...(i.checked?.links ? [`${i.checked.links} link${i.checked.links === 1 ? "" : "s"} checked by target`] : []),
      ...(i.checked?.special ? [`${i.checked.special} special file${i.checked.special === 1 ? "" : "s"} checked by kind`] : []),
      ...(i.digests_compared?.md5 || i.digests_compared?.sha1 ? ["md5 and sha1 compared beside sha256"] : []),
    ];
    return `yes — re-hashed in full by the host at ${at ?? "?"} (${how.join("; ")})${manifest}`;
  }
  return `NOT FULLY RE-HASHED — ${files - n(i.skipped) - n(i.unreadable)} of ${files} files checked unchanged by the host at ${at ?? "?"}${notRead}${manifest}; the rest are not covered`;
}

/**
 * What a reader needs to say which software produced this run: the
 * harness's commit (and whether it had local changes), the versions of Pi,
 * Node and msb, the image digest and the models. Read from the registry,
 * where the kickoff records them; null when it recorded none of them.
 */
export function reproducibilityLine(run: Record<string, unknown> | null | undefined, models: string[]): string | null {
  const nested = run?.provenance && typeof run.provenance === "object" ? (run.provenance as Record<string, unknown>) : {};
  const str = (k: string): string | null => {
    const v = nested[k] ?? run?.[k];
    return typeof v === "string" && v.trim() ? v.trim() : null;
  };
  const commit = str("harness_commit");
  const dirty = nested.harness_dirty === true || run?.harness_dirty === true;
  const pi = str("pi_version");
  const node = str("node_version");
  const msb = str("msb_version");
  const image = str("image_digest") ?? ((run?.isolation as { image_digest?: unknown } | undefined)?.image_digest as string | undefined) ?? null;
  if (!commit && !pi && !node && !msb) return null;
  const parts = [
    commit ? `harness commit ${commit}${dirty ? " with local changes" : ""}` : "harness commit not recorded",
    ...(pi ? [`Pi ${pi}`] : []),
    ...(node ? [`Node ${node}`] : []),
    ...(msb ? [`msb ${msb}`] : []),
    ...(image ? [`image ${image}`] : []),
    ...(models.length ? [`models ${models.join(", ")}`] : []),
  ];
  return `${parts.join("; ")}. The models' outputs are not deterministic: the trace, the kept tool outputs and the sealed sessions are the reproducible record, not a re-run.`;
}

/** The examiner host's clock, as the kickoff recorded it; null when it recorded nothing. */
export function hostClockLine(run: Record<string, unknown> | null | undefined): string | null {
  const c = run?.host_clock && typeof run.host_clock === "object" ? (run.host_clock as { tz?: unknown; utc_offset?: unknown; synced?: unknown; source?: unknown }) : null;
  const tz = typeof c?.tz === "string" ? c.tz : typeof run?.host_tz === "string" ? (run.host_tz as string) : null;
  if (!c && !tz) return null;
  const synced = c?.synced === true ? "yes" : c?.synced === false ? "NO" : "not known";
  return `time zone ${tz ?? "not recorded"}${typeof c?.utc_offset === "string" ? ` (UTC${c.utc_offset})` : ""}; clock synchronised: ${synced}${typeof c?.source === "string" ? ` (${c.source})` : ""}. The harness stamps its own times in UTC.`;
}

export function egressLine(mode: string | undefined): string {
  switch (mode) {
    case "netns":
      return "enforced (network namespace: a connection outside the allowlist has no route)";
    case "proxy-only":
      return "ADVISORY (proxy environment only: it holds for anything that reads HTTP(S)_PROXY, not for a raw socket)";
    case "off":
      return "none (netguard was off for this run)";
    case "microvm":
      return "enforced (microVM network policy on the host: deny by default, each VM's allowed hosts only; a denied name does not resolve and a hard-coded address has no route)";
    case "microvm-open":
      return "OPEN (--no-netguard: each microVM could reach every public host; its secrets still went only to their own hosts)";
    default:
      return "not recorded (this run predates the field)";
  }
}

/**
 * How the evidence reached the agents: copied into the run, used in place
 * behind a host guard, or mounted read-only into each agent's microVM.
 * Several sets are each named, at inputs/<name>/, with where it came from.
 */
export function evidenceArrival(inputs: { source?: string; copied_at?: string; guard?: string; held?: string; bound?: boolean; sets?: Array<{ path?: string; source?: string; files?: number }> }): string {
  const source = inputs.sets?.length
    ? `${inputs.sets.length} sets (${inputs.sets.map((set) => `<code>${escapeHtml(set.source || "the operator")}</code> as <code>${escapeHtml(set.path ?? "inputs/?")}/</code>, ${set.files ?? 0} file${set.files === 1 ? "" : "s"}`).join("; ")})`
    : `<code>${escapeHtml(inputs.source || "the operator")}</code>`;
  const at = escapeHtml(inputs.copied_at || "—");
  if (inputs.guard === "microvm" && inputs.held === "copy") {
    return `<p>Copied from ${source} at ${at} into <code>inputs/</code>, read-only, as a second layer (<code>--inputs-copy</code>): each agent's microVM had the copy mounted read-only, and the host refused every write through that mount.</p>`;
  }
  if (inputs.guard === "microvm") {
    return `<p>Used in place from ${source} (manifest taken ${at}), with no copy: each agent's microVM had it mounted read-only as <code>inputs/</code>, and the host refused every write through that mount. The harness also refuses <code>write</code>, <code>edit</code> and <code>claim_file</code> on it. The source itself stayed as writable on the host as it was; the host's custody check at stop is what says it did not change.</p>`;
  }
  if (inputs.held === "image") {
    return `<p>Attached from ${source} (manifest taken ${at}) as a read-only disk image at <code>inputs/</code>: the device refused every write. There is no pristine copy, and nothing to restore from.</p>`;
  }
  if (inputs.held === "bind" || inputs.bound) {
    return `<p>Used in place from ${source} (manifest taken ${at}), with no copy: <code>inputs/</code> linked to it, and the kernel held the source read-only in every pane. The harness refuses <code>write</code>, <code>edit</code> and <code>claim_file</code> on it.</p>`;
  }
  return `<p>Copied from ${source} at ${at} into <code>inputs/</code>, which no agent may write. The harness refuses <code>write</code>, <code>edit</code> and <code>claim_file</code> on it, restores a shell write from a pristine copy, and where the host allows it runs each pane with <code>inputs/</code> read-only at the kernel.</p>`;
}

/** Where the evidence came from, in words: its source, or each set's at inputs/<name>/. */
export function evidenceFrom(inputs: { source?: string; sets?: Array<{ path?: string; source?: string; files?: number }> }): string {
  if (!inputs.sets?.length) return `from ${inputs.source || "the operator"}`;
  return `in ${inputs.sets.length} sets: ${inputs.sets.map((set) => `${set.path ?? "inputs/?"}/ from ${set.source || "the operator"} (${set.files ?? 0} file${set.files === 1 ? "" : "s"})`).join("; ")}`;
}

/** What the VM manager recorded about one agent's VM (scripts/vm.ts, vm/<id>.json). */
export type VmRecordView = {
  agent: string;
  name?: string;
  runtime?: { name?: string; version?: string };
  image?: {
    ref?: string;
    manifest_digest?: string | null;
    expected_digest?: string;
    /** The image's own record, /etc/dfirswarm/image.json, as the VM's probe read it. */
    description?: { profile?: string; pack_versions?: Record<string, { version?: string }>; redistributable?: boolean; nonredistributable?: string[]; downloads?: Record<string, { version?: string }> } | null;
  };
  cpus?: number;
  memory_mib?: number;
  mounts?: Array<{ host?: string; guest?: string; mode?: string; noexec?: boolean }>;
  network?: { default?: string; allow_hosts?: string[]; host_ports?: number[] };
  secrets?: Array<{ name?: string; hosts?: string[] }>;
  snapshot?: { path?: string; sha256?: string; bytes?: number } | { error?: string };
  created_at?: string;
  stopped_at?: string;
  /** What the VM held at stop that its image did not (scripts/vm.ts INVENTORY_SCRIPT). */
  installed_outside_image?: { baseline?: boolean; apt?: Record<string, string>; venv?: Record<string, string>; error?: string };
  /** What the finish that removed the VM did to msb's database: scrubbed, busy, no sqlite3, no database. */
  msb_db?: string;
};

/**
 * The custody rows a microVM run adds: what the agents ran in, and each
 * agent's VM as the host recorded it. Whole — a reader checking a digest or
 * a mount needs all of it.
 */
export function vmRows(records: VmRecordView[]): Array<[string, string]> {
  if (!records.length) return [];
  const first = records[0];
  const images = [...new Set(records.map((r) => `${r.image?.ref ?? "?"} (${r.image?.manifest_digest ?? "digest not recorded"})`))];
  const rows: Array<[string, string]> = [
    ["Isolation", `one microVM per agent (${first.runtime?.name ?? "microsandbox"} ${first.runtime?.version ?? ""}`.trimEnd() + `), image ${images.join("; ")}`],
  ];
  // Every VM booted the digest the kickoff resolved, or it is said which did not.
  const expected = first.image?.expected_digest;
  if (expected) {
    const off = records.filter((r) => r.image?.manifest_digest && r.image.manifest_digest !== expected);
    rows.push(["Image digest", off.length ? `DIFFERS: ${off.map((r) => `${r.agent} booted ${r.image?.manifest_digest}`).join("; ")}; the run resolved ${expected}` : `every VM booted ${expected}, resolved once at kickoff`]);
  }
  const desc = first.image?.description;
  if (desc && typeof desc === "object") {
    const packs = Object.entries(desc.pack_versions ?? {}).map(([id, v]) => `${id} ${v.version ?? "?"}`).join(", ");
    const downloads = Object.entries(desc.downloads ?? {}).map(([n, v]) => `${n} ${v.version ?? "?"}`).join(", ");
    rows.push([
      "Image record",
      `profile ${desc.profile ?? "?"}; built from ${packs || "no recorded pack versions"}${downloads ? `; pinned downloads ${downloads}` : ""}; ${
        desc.redistributable === false ? `NOT for redistribution (${(desc.nonredistributable ?? []).length} programs; see /etc/dfirswarm/NOTICE in the image)` : desc.redistributable === true ? "redistributable" : "redistribution not recorded"
      }`,
    ]);
  }
  for (const r of records) {
    const writable = (r.mounts ?? []).filter((m) => m.mode === "rw").map((m) => `${m.guest ?? m.host}${m.noexec ? " (no-exec)" : ""}`);
    const net = r.network?.default === "public"
      ? "every public host (--no-netguard)"
      : [...(r.network?.allow_hosts ?? []).map((h) => (/:\d+$/.test(h) && !h.endsWith("]") ? h : `${h}:443`)), ...(r.network?.host_ports ?? []).map((p) => `the host gateway :${p}`)].join(", ") || "nothing";
    const secrets = (r.secrets ?? []).map((s) => `${s.name ?? "?"} → ${(s.hosts ?? []).join(", ")}`).join("; ") || "none";
    const snap = !r.snapshot
      ? "not kept"
      : "error" in r.snapshot && r.snapshot.error
        ? `NOT KEPT — ${r.snapshot.error}`
        : `kept, sha256 ${(r.snapshot as { sha256?: string }).sha256 ?? "?"} (${(r.snapshot as { path?: string }).path ?? "?"})`;
    const inv = r.installed_outside_image;
    const added = inv && !inv.error ? [...Object.entries(inv.apt ?? {}).map(([k, v]) => `apt ${k} ${v}`), ...Object.entries(inv.venv ?? {}).map(([k, v]) => `venv ${k} ${v}`)] : [];
    const installed = !inv
      ? "not inventoried"
      : inv.error
        ? `not inventoried (${inv.error})`
        : added.length
          ? `INSTALLED OUTSIDE THE IMAGE: ${added.join(", ")}`
          : inv.baseline === false
            ? "nothing in the image's venv; apt not comparable (the image records no full package list)"
            : "nothing outside the image";
    rows.push([
      `VM ${r.agent}`,
      `${r.name ?? "?"}: ${r.cpus ?? "?"} vCPU, ${r.memory_mib ?? "?"} MiB; writable: ${writable.join(", ") || "nothing"}; everything else mounted read-only; could reach: ${net}; secrets swapped in on the way out: ${secrets}; installed at stop: ${installed}; disk at stop: ${snap}${
        r.msb_db === "scrubbed"
          ? "; msb's database cleared of it after removal"
          : r.msb_db && r.msb_db !== "no database"
            ? `; msb's database NOT cleared after removal (${r.msb_db}): a secret's value may remain in msb's database`
            : ""
      }`,
    ]);
  }
  // msb keeps a live VM's secret values in its database; a finish that
  // removed VMs rewrites it without them. Where it could not, it is said once
  // more on its own line, since a reader scanning for secrets looks here.
  const unscrubbed = records.filter((r) => r.msb_db && r.msb_db !== "scrubbed" && r.msb_db !== "no database");
  if (unscrubbed.length) rows.push(["Secrets in msb's database", `NOT CLEARED after removing ${unscrubbed.map((r) => `${r.agent} (${r.msb_db})`).join(", ")}: a secret's value may remain in msb's database on the host`]);
  return rows;
}

async function readVmRecords(sandbox: string): Promise<VmRecordView[]> {
  const dir = join(sandbox, "vm");
  const out: VmRecordView[] = [];
  for (const name of (await readdir(dir).catch(() => [])).filter((n) => n.endsWith(".json")).sort()) {
    const rec = await readJsonFile<VmRecordView>(join(dir, name));
    if (rec?.agent) out.push(rec);
  }
  return out;
}

/** The trace's chain, read a line at a time from a regular file; why it was not read, when it is there and could not be. */
async function streamedChain(file: string, anchor: Parameters<typeof eventChainVerifier>[0]): Promise<{ chain: ReturnType<ReturnType<typeof eventChainVerifier>["finish"]>; unread: string | null }> {
  const verifier = eventChainVerifier(anchor);
  const opened = await openRegular(file);
  if ("why" in opened) return { chain: verifier.finish(), unread: opened.why === "missing" ? null : opened.why };
  try {
    const rl = createInterface({ input: opened.handle.createReadStream({ autoClose: false, encoding: "utf8" }), crlfDelay: Infinity });
    for await (const line of rl) verifier.push(line);
  } catch (err) {
    return { chain: verifier.finish(), unread: `unreadable (${(err as NodeJS.ErrnoException).code ?? (err as Error).message})` };
  } finally {
    await opened.handle.close();
  }
  return { chain: verifier.finish(), unread: null };
}

export async function renderReport(sandboxArg: string, options: ReportOptions = {}): Promise<string> {
  const { sandbox, runsDir, run, team, budget, events, trace_unreadable, sentinel, allDead, ledger, inputs } = await loadRunContext(sandboxArg, {
    runsDir: options.runsDir,
    parseSentinel: parseFrontMatter,
  });
  const vmRecords = await readVmRecords(sandbox);
  const hostCustody = await readJsonFile<{
    summary?: string;
    at?: string;
    inputs?: unknown;
    run?: string | null;
    vms?: Array<{ agent?: string; secret_violations?: Array<{ env?: string; host?: string; method?: string; path?: string; location?: string; own_host?: boolean | null }> }> | null;
    model_gateway?: { lines: number; intact: boolean; detail: string; refused?: string } | null;
    checks?: Array<{ name: string; status: string; reason?: string; expected?: number; checked?: number }>;
    artifacts?: { files?: number; index_sha256?: string } | null;
    seal?: { trace?: { lines?: number; last_line_sha256?: string | null }; ledger?: { entries?: number; head?: string | null }; attestations?: { lines?: number; head?: string | null }; disputes?: { lines?: number; head?: string | null }; journal?: { lines?: number; head?: string | null } | null };
    acquisition?: { source: string | null; source_sha256: string | null; given: number; matched: number; mismatched: string[]; not_compared: string[] } | null;
    operator?: { lines: number; intact: boolean; detail: string; trace_actions: number; matched: number; unmatched: unknown[] } | null;
    models?: { team: Array<{ agent: string; model: string | null }>; gateway_answered: string[] | null };
    time_reference?: { url: string; offset_ms: number | null; precision_ms: number; error?: string } | null;
    timing?: { total_ms: number; evidence_bytes: number; evidence_mb_per_s: number | null };
  }>(join(sandbox, "custody.json"));
  // The anchor outside the run: the kickoff's reference clock, and the last verdict's signature and timestamp.
  const custodyAnchorFile = await readJsonFile<{ time_reference?: { url?: string; offset_ms?: number | null; precision_ms?: number; error?: string } | null; custody?: Array<{ artifacts_sha256?: string | null; signature?: { file?: string; key?: string | null; error?: string }; timestamp?: { authority?: string; gen_time?: string | null; error?: string; signature?: { verified?: boolean | null; ca?: string | null; detail?: string } } }> }>(custodyAnchorPath(sandbox));
  const lastAnchored = custodyAnchorFile?.custody?.at(-1);
  // The operator's own actions on this run, from the audit beside the registry.
  const operatorActs = await (async () => {
    const read = await readRegularText(join(runsDir, "operator-audit.jsonl"), 256 * 1024 * 1024);
    if (!("text" in read)) return [] as Array<{ at: string; command: string; os_user: string; host: string; via: string }>;
    const runId = String(run?.id ?? team.swarm_id ?? "");
    return read.text
      .split("\n")
      .filter(Boolean)
      .map((l) => {
        try {
          return JSON.parse(l) as { at?: string; command?: string; argv?: unknown[]; os_user?: string; host?: string; via?: string; cwd?: string };
        } catch {
          return null;
        }
      })
      .filter((o): o is NonNullable<typeof o> => Boolean(o) && ((o?.argv ?? []).map(String).includes(runId) || String(o?.cwd ?? "").startsWith(sandbox)))
      .map((o) => ({ at: String(o.at ?? ""), command: String(o.command ?? ""), os_user: String(o.os_user ?? ""), host: String(o.host ?? ""), via: String(o.via ?? "") }));
  })();
  // The model gateway's totals, host-written beside the trace, when the run had one.
  const gatewayTotals = await (async (): Promise<GatewayTotals | null> => {
    const read = await readRegularText(join(sandbox, "traces", "model-gateway.json"), 64 * 1024 * 1024);
    if (!("text" in read)) return null;
    try {
      return JSON.parse(read.text) as GatewayTotals;
    } catch {
      return null;
    }
  })();
  // Whether that custody.json is the verdict custody anchored outside the run.
  const custodyAnchor = hostCustody ? await verdictAnchorState(sandbox) : null;
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
  // The chain, a line at a time, so a trace of any size is checked. A trace
  // that is there and cannot be read (a link, not a regular file, an open
  // that failed) is said as such: read as empty, it printed as "no trace"
  // or as a trace cut short, neither of which is what happened.
  const streamed = await streamedChain(join(sandbox, EVENTS_REL), anchorPoint);
  const chain = streamed.chain;
  const traceUnread = trace_unreadable ?? streamed.unread;
  // Operator actions run from a shell outside the run (stop, reap, say)
  // reach the collector with no pane's token: that is who they are, not a
  // line nobody can account for. Each is also on runs/operator-audit.jsonl.
  const operatorActions = events.filter((e) => e.tool === "operator_action" && (e as { agent_unverified?: unknown }).agent_unverified === true).length;
  // A ledger entry the harness recorded in the operator's CLI (no hub to write it) carries no pane's token either: the harness's, not a line nobody can account for.
  const harnessFromShell = events.filter((e) => e.tool === "harness_record" && e.agent === "system" && (e as { agent_unverified?: unknown }).agent_unverified === true).length;
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
  // Null when there is no log: "nothing was refused" needs one behind it.
  const netguardLog = await readFile(join(sandbox, "traces", "netguard.log"), "utf8").catch(() => null);
  const allowFromLog = allowHosts
    ? []
    : [
        ...new Set(
          ((netguardLog ?? "").match(/ALLOW connect ([^\s]+)/g) ?? []).map((m) =>
            m.replace("ALLOW connect ", ""),
          ),
        ),
      ].sort();
  // What the run tried to reach and could not. On BelkaCTF #6 that list held
  // `bit.ly` — an agent resolving a shortened link it had read inside the
  // seized phone. A custody section that prints only what was allowed cannot
  // show the reader that it happened.
  const deniedHosts = countHosts(netguardLog ?? "", "DENY");
  const names = await readNames(sandbox).catch(() => []);
  const chosen = new Map(names.map((n) => [n.id, n.doing ? `${n.name} — ${n.doing}` : n.name]));

  const id = run?.id ?? team.swarm_id ?? "";
  // The examiner's review, kept beside the registry where no agent writes.
  const review: ReviewState | null = options.review !== undefined ? options.review : await readReviewState(runsDir, id, sandbox, ledger);
  // Which model each agent ran on, for the exhibits and the provenance row.
  const models = [...new Set(team.agents.map((a) => a.model ?? run?.model).filter((m): m is string => Boolean(m)))].sort();
  const provenance = reproducibilityLine(run as Record<string, unknown> | null, models);
  const runRecord = run as Record<string, unknown> | null;
  const commit = (() => {
    const nested = runRecord?.provenance && typeof runRecord.provenance === "object" ? (runRecord.provenance as Record<string, unknown>) : {};
    const c = nested.harness_commit ?? runRecord?.harness_commit;
    const dirty = nested.harness_dirty === true || runRecord?.harness_dirty === true;
    return typeof c === "string" && c ? ` (commit ${c.slice(0, 12)}${dirty ? ", with local changes" : ""})` : "";
  })();
  const caseId = options.caseId ?? run?.case_id ?? "";
  // What the kickoff was told about who ran the run: its words, never taken for an enrolled examiner's.
  const examiner = options.examiner ?? run?.examiner ?? "";
  // The run's releases, and the one this rendering is for: a machine's draft
  // and an examiner's adoption are kept apart in every line below.
  const releases = readReleases(sandbox);
  const forRelease = options.release ?? null;
  // The release state the body and the summary take (release-record.ts bodyRelease): this release's own, or the run's latest.
  const rel = bodyRelease(sandbox, forRelease);
  const adoptedHere = forRelease && forRelease.state === "adopted" && forRelease.version >= 1 ? forRelease : null;
  // Only the releases before this one: what a release says of the others never depends on what came after it.
  const earlier = forRelease ? releases.filter((r) => r.version < forRelease.version) : releases;
  const adoptedElsewhere = [...earlier].reverse().find((r) => r.record?.state === "adopted") ?? null;
  // A fresh rendering of a run whose latest release is adopted is not DRAFT (plan: the mark stands until release v1), and says it is not the signed bytes.
  const releasedRun = !forRelease && rel.release?.state === "adopted" ? rel.latest : null;
  const draftMark = !adoptedHere && !releasedRun;
  const adopter = adoptedHere?.examiner ?? null;
  const releaseBanner = adoptedHere
    ? `Release v${adoptedHere.version}, adopted by ${adopter?.name ?? "the examiner"}${adopter?.organisation ? ` (${adopter.organisation})` : ""} at ${adoptedHere.at}, and signed with the key ${adopter?.fingerprint ?? "named in release.json"} (the signature is beside these bytes: release/v${adoptedHere.version}/${adopter?.fingerprint?.startsWith("X509-SHA256:") ? "release.json.p7s, an e-signature whose certificate travels inside it" : "release.json.sig"}). The conclusions the examiner adopted are the examiner's; every other one is the agents'.`
    : forRelease
      ? `DRAFT: release v${forRelease.version}, sealed at ${forRelease.at} by this install's machine key${forRelease.machine?.fingerprint ? ` (${forRelease.machine.fingerprint})` : ""} when custody was taken. The machine key is not an examiner: no one has adopted this report, and every conclusion in it is the agents'.`
      : releasedRun
        ? `NOT THE SIGNED BYTES: a fresh rendering of the run as it stands. The report ${releasedRun.record?.signer.examiner?.name ?? "an examiner"} adopted is release v${releasedRun.version} (release/v${releasedRun.version}/report.html, sha256 ${releasedRun.record?.report.html.sha256 ?? "?"}), signed with their key; what changed since is not adopted until a release says so.`
      : adoptedElsewhere
        ? `DRAFT: NOT THE ADOPTED REPORT. This is a fresh rendering of the run as it stands; the report ${adoptedElsewhere.record?.signer.examiner?.name ?? "an examiner"} adopted is release v${adoptedElsewhere.version} (release/v${adoptedElsewhere.version}/report.html, sha256 ${adoptedElsewhere.record?.report.html.sha256 ?? "?"}), signed with their key, and a later release is a machine's draft.`
        : "DRAFT: no examiner has adopted this report. It is a rendering of the run's record as it stands, and every conclusion in it is the agents'.";
  const releaseRow = [
    ...earlier.map((r) => (r.record ? `v${r.version} ${r.record.state === "adopted" ? `adopted by ${r.record.signer.examiner?.name ?? "?"} (examiner's key ${r.record.signer.fingerprint})` : `draft sealed by the machine key (${r.record.signer.fingerprint}), adopted by no one`}, ${r.record.at}, release.json sha256 ${r.sha256}` : `v${r.version}: ${r.error ?? "unreadable"}`)),
    ...(forRelease ? [`this document is v${forRelease.version}: its own hash cannot be inside it, and release/v${forRelease.version}/release.json binds it`] : []),
  ].join("; ") || "none: no release was sealed (custody at stop writes v0; swarm.sh releases <id> --draft writes one for a run that has a verdict)";
  const startedAt = budget?.started_at ?? run?.started_at ?? events[0]?.ts ?? "";
  // The host's clock, where the collector stamped one: a guest's own `ts` is its word.
  const endedAt = sentinel?.at ?? (events.length ? hostTime(events.at(-1) as { ts: string; recv_ts?: string }) : "");
  const durationMs = startedAt && endedAt ? Date.parse(endedAt) - Date.parse(startedAt) : Number.NaN;
  const generatedAt = options.now ?? new Date().toISOString();
  const unmetered = budget?.metered === false;

  const timeline = ledger.filter((e) => e.kind === "event").sort((a, b) => (a.ts ?? "").localeCompare(b.ts ?? "") || a.seq - b.seq);
  const iocs = ledger.filter((e) => e.kind === "ioc");
  const findings = ledger.filter((e) => e.kind === "finding");
  // Searches that found nothing, as the agents recorded them.
  const absences = ledger.filter((e) => (e.kind as string) === "absence");
  // Corrections: the corrected entry stays as it was recorded, marked.
  const correctedBy = supersededBy(ledger);
  const sensitive = ledger.filter((e) => e.sensitive && !correctedBy.has(e.seq));
  // What the trace shows the swarm naming, and whether it shows each
  // exhibit's source being read before the exhibit was recorded: the body
  // shows the grounding on each exhibit.
  const coverage: CoverageReport = await coverageOf(sandbox, { events, ledger, traceUnreadable: traceUnread });
  const ungrounded = ledger.filter((e) => coverage.grounding[String(e.seq)] === "not in the trace");

  // --- The evidence (the body's §3) ---------------------------------------
  const guardWord = (g: string) => (g === "kernel" ? "kernel" : g === "mode" ? "permission bits" : "detect + heal");
  const enforcedSeen = Object.values(enforced);
  // The digests an imager's log and an opposing expert's tools carry, beside
  // sha256, when the kickoff took them.
  const fileDigests = (f: unknown) => f as { md5?: string; sha1?: string };
  const withSha1 = (inputs?.files ?? []).some((f) => typeof fileDigests(f).sha1 === "string");
  const withMd5 = (inputs?.files ?? []).some((f) => typeof fileDigests(f).md5 === "string");
  // The imager's own digests, when the operator gave them at kickoff: which file each matched.
  const acquired = new Map<string, string[]>();
  for (const e of ((inputs as { acquisition?: { entries?: Array<{ path: string; algo: string }> } } | null)?.acquisition?.entries ?? [])) acquired.set(e.path, [...(acquired.get(e.path) ?? []), e.algo]);
  const withAcq = acquired.size > 0;
  // How many commands on the trace named each file; "—" is a file no command named.
  const withCoverage = !coverage.unavailable && coverage.inputs > 0;
  const namedCell = (path: string) => {
    if (!withCoverage) return "";
    const n = coverage.touched[path] ?? 0;
    const walked = coverage.under_named_dir[path] ?? 0;
    return `<td class="num">${n ? String(n) : walked ? `— <span class="muted">(directory named ${walked}×)</span>` : "—"}</td>`;
  };
  const evidenceRows = (inputs?.files ?? [])
    .map(
      (f) =>
        `<tr><td><code>${escapeHtml(f.path)}</code></td><td class="num">${escapeHtml(bytesHuman(f.bytes))}</td><td class="hash">${escapeHtml(f.sha256)}</td>${withSha1 ? `<td class="hash">${escapeHtml(fileDigests(f).sha1 ?? "—")}</td>` : ""}${withMd5 ? `<td class="hash">${escapeHtml(fileDigests(f).md5 ?? "—")}</td>` : ""}${withAcq ? `<td>${escapeHtml(acquired.get(f.path)?.join(", ") ?? "—")}</td>` : ""}${namedCell(f.path)}</tr>`,
    )
    .join("");
  const coverageHtml = inputs
    ? `<h3>Coverage, from the trace</h3>
<p>${escapeHtml(coverageLine(coverage))}${withCoverage ? " The table's last column counts the calls that named each file." : ""}</p>${
        withCoverage && coverage.untouched.length
          ? `<p>Named by no command or job request: ${coverage.untouched.map((p) => `<code>${escapeHtml(p)}</code>`).join(", ")}.</p>`
          : ""
      }`
    : "";
  const manifest = inputs ? await manifestMeta(sandbox) : null;
  const sourceCheck = sourceCheckedLine(manifest?.source_checked);
  // How the evidence reached the agents, the guard each pane measured, every
  // file with its hashes and how often the trace named it: in the body's §3,
  // in place of its own table.
  const evidenceHtml = inputs
    ? `${evidenceArrival(inputs as Parameters<typeof evidenceArrival>[0])}
<p>Guard requested <code>${escapeHtml(inputs.enforce || "auto")}</code>, set up as <code>${escapeHtml(inputs.guard || "none")}</code>; measured per pane: ${
          enforcedSeen.length
            ? Object.entries(enforced)
                .map(([agent, g]) => `${escapeHtml(agent)} ${chip(guardWord(g), g === "kernel" ? "moss" : g === "mode" ? "saffron" : "brick")}`)
                .join(" ")
            : "no pane reported"
        }.</p>
<table><thead><tr><th>File</th><th class="num">Size</th><th>sha256 at kickoff</th>${withSha1 ? "<th>sha1</th>" : ""}${withMd5 ? "<th>md5</th>" : ""}${withAcq ? "<th>Acquisition hash</th>" : ""}${withCoverage ? '<th class="num">Named by</th>' : ""}</tr></thead><tbody>${evidenceRows}</tbody></table>
<p>${(inputs.files ?? []).length} file${(inputs.files ?? []).length === 1 ? "" : "s"}, ${escapeHtml(bytesHuman(inputs.bytes ?? 0))} in total.${sourceCheck ? ` ${escapeHtml(sourceCheck)}` : ""}</p>
${coverageHtml}`
    : undefined;

  // --- Spend, calls and context (the body's §4) --------------------------
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
  // Tools the agents wrote for themselves: code nobody reviewed, which a
  // finding may rest on. Named with who wrote it, how often it ran, and its
  // hash where the trace kept one.
  const forged = events.filter((e) => e.tool === "make_tool" && (e.result as { ok?: unknown } | undefined)?.ok === true);
  const forgedHtml = forged.length
    ? `<p>Tools the agents forged during the run with <code>make_tool</code>, <strong>not independently validated</strong>: ${forged
        .map((e) => {
          const name = String((e.args as { name?: unknown } | undefined)?.name ?? "?");
          const calls = events.filter((x) => x.tool === name).length;
          const sha = (e.result as { sha256?: unknown } | undefined)?.sha256;
          const runtime = (e.args as { runtime?: unknown } | undefined)?.runtime;
          return `<code>${escapeHtml(name)}</code> by ${escapeHtml(e.agent)}${typeof runtime === "string" ? ` (${escapeHtml(runtime)})` : ""}, called ${calls} time${calls === 1 ? "" : "s"}${typeof sha === "string" ? `, sha256 <span class="hash">${escapeHtml(sha)}</span>` : ""}`;
        })
        .join("; ")}. A finding that rests on one of them rests on code the swarm wrote and no one reviewed.</p>`
    : "";
  const methodHtml = `<h3>Spend, calls and context</h3>
${anyNamed ? '<p class="lede">The "Calls itself" column is what each agent decided to be, in its own words, after reading the goal.</p>' : ""}
<table><thead><tr><th>Agent</th>${anyNamed ? "<th>Calls itself</th>" : ""}<th>Model</th><th class="num">Spent</th><th class="num">Calls</th><th class="num">Tokens</th>${contextHeaders}</tr></thead><tbody>${teamRows}</tbody></table>
<p>
  ${unmetered ? "Unmetered (local models)." : `${escapeHtml(usd(budget?.spent_usd ?? 0))} of a ${escapeHtml(usd(run?.cap_usd ?? budget?.cap_usd ?? 0))} cap${escapeHtml(vmSpendNote(runRecord, gatewayTotals))}`},
  ${(budget?.tokens ?? 0).toLocaleString("en-US")} tokens, ${events.length.toLocaleString("en-US")} tool calls in ${escapeHtml(durationHuman(durationMs))}.
  ${run?.wall_clock_minutes ? `Wall-clock cap ${run.wall_clock_minutes} min.` : ""}
  ${run?.cap_per_agent_usd ? `Per-agent cap ${escapeHtml(usd(run.cap_per_agent_usd))}.` : ""}
  ${modelCaps.length ? `Per-model caps: ${modelCaps.join("; ")}.` : ""}
</p>
${
  toolbox
    ? `<p>Toolbox <code>${escapeHtml(toolbox.preset ?? "off")}</code>: ${(toolbox.present ?? []).length} tool${(toolbox.present ?? []).length === 1 ? "" : "s"} present${(toolbox.missing ?? []).length ? `, ${(toolbox.missing ?? []).length} missing (${(toolbox.missing ?? []).map((m) => escapeHtml(m.name)).join(", ")})` : ""}.</p>`
    : ""
}
${forgedHtml}`;

  // --- Appendix E: artifacts ----------------------------------------------
  const artifactRows = artifacts.files
    .map(
      (f) =>
        `<tr><td><code>${escapeHtml(f.path)}</code></td><td class="num">${escapeHtml(bytesHuman(f.bytes))}</td><td class="hash">${escapeHtml(f.sha256)}</td><td>${f.packaged ? chip("packaged", "moss") : chip("in the sandbox", "saffron")}</td></tr>`,
    )
    .join("");
  const artifactsSection: Section = {
    id: "sE",
    n: "E",
    title: "Appendix E: Artifacts produced",
    desc: "what the run produced, hashed",
    count: artifacts.files.length ? `${artifacts.files.length} file${artifacts.files.length === 1 ? "" : "s"}` : "none",
    html: artifacts.files.length
      ? `<table class="artifacts"><thead><tr><th>Path</th><th class="num">Size</th><th>sha256</th><th>Where</th></tr></thead><tbody>${artifactRows}</tbody></table>
<p>${artifacts.files.length} file${artifacts.files.length === 1 ? "" : "s"}, ${escapeHtml(bytesHuman(artifacts.bytes))} in total; ${escapeHtml(bytesHuman(artifacts.packaged_bytes))} of that travels with the package.</p>
${
  artifacts.files.some((f) => !f.packaged)
    ? `<div class="note">Files marked <strong>in the sandbox</strong> are under ${artifacts.unpackaged_dirs.map((d) => `<code>work/${escapeHtml(d)}/</code>`).join(" and ")}. That material came out of the evidence and may be live, so the package does not carry it. It is hashed here, which is what lets a reader verify a copy obtained another way.</div>`
    : ""
}
${artifacts.skipped.length ? `<p>Not hashed: ${artifacts.skipped.map((s) => `<code>${escapeHtml(s.path)}</code> (${escapeHtml(s.reason)})`).join(", ")}.</p>` : ""}`
      : `<div class="note">Nothing under <code>work/</code>.</div>`,
  };

  // --- The limits of this run (in the body's §8) --------------------------
  const capHit = (budget?.spent_usd ?? 0) > 0 && (run?.cap_usd ?? 0) > 0 && (budget?.spent_usd ?? 0) >= (run?.cap_usd ?? 0) * 0.98;
  const limits: string[] = [];
  // Whose conclusions these are, first: a reader deciding what to rely on
  // needs to know an AI swarm wrote them before anything else.
  limits.push(
    review?.unreadable
      ? `Prepared by an AI agent swarm. The examiner's review could not be read (${escapeHtml(review.unreadable)}), so this document cannot say whether any finding was reviewed.`
      : review && review.signed && signoffCurrent(review)
      ? `Prepared by an AI agent swarm and reviewed by an examiner: ${escapeHtml(reviewLine(review, ledger))}. An entry the examiner did not review is still the agents' conclusion.`
      : review && review.signed
      ? `Prepared by an AI agent swarm. An examiner signed off, and the sign-off does not cover this run as it stands: ${escapeHtml(signoffScope(review))}. What changed since is the agents' conclusion (${escapeHtml(reviewLine(review, ledger))}).`
      : review && review.lines
        ? `Prepared by an AI agent swarm. An examiner has reviewed some entries and has not signed the review (${escapeHtml(reviewLine(review, ledger))}); an entry not reviewed is the agents' conclusion.`
        : "Prepared by an AI agent swarm. The findings are the agents' conclusions, each recorded with the source it rests on; none is an examiner's opinion until an examiner has reviewed it.",
  );
  limits.push("The models' output is not deterministic: running the case again would not give the same words. The reproducible record is the trace, the kept tool outputs and the sealed sessions, not a re-run.");
  if (forged.length) limits.push(`${forged.length} tool${forged.length === 1 ? " was" : "s were"} written by the agents during the run and not independently validated (§4).`);
  if (!sentinel && allDead) limits.push(`The swarm did not finish: every agent died${allDead.at ? ` (recorded by the reaper at ${escapeHtml(allDead.at)})` : ""} before any stated that the definition of done was met.`);
  else if (!sentinel) limits.push("The swarm did not finish: there is no <code>done/SWARM_DONE</code>, so no agent stated that the definition of done was met.");
  if (capHit) limits.push(`Spend reached the cap (${escapeHtml(usd(budget?.spent_usd ?? 0))} of ${escapeHtml(usd(run?.cap_usd ?? 0))}). Work stopped because of the budget, not because the questions were answered.`);
  if (!findings.length) limits.push("No findings were recorded, so nothing in this report is stated as a conclusion.");
  if (!inputs) limits.push("No read-only inputs were given, so no evidence hash is stated.");
  if (withCoverage && coverage.untouched.length) limits.push(`${coverage.untouched.length} of ${coverage.inputs} evidence file${coverage.inputs === 1 ? " was" : "s were"} named by no command or job request on the trace (§3). An artefact nobody opened is not evidence of absence.`);
  if (ungrounded.length) limits.push(`${ungrounded.length} ledger entr${ungrounded.length === 1 ? "y's" : "ies'"} source${ungrounded.length === 1 ? " was" : "s were"} named by no call before the entry was recorded, nor by a job the entry cites that was given an evidence input (marked on each in Appendix A).`);
  const refusals = events.filter((e) => e.result && typeof e.result === "object" && (e.result as { ok?: boolean }).ok === false);
  if (refusals.length) limits.push(`${refusals.length} tool call${refusals.length === 1 ? "" : "s"} failed or were refused during the run; they are in <code>trace/events.jsonl</code>.`);
  limits.push("This document reports what the swarm recorded. An artefact nobody opened is not evidence of absence, and the trace is the record of what was actually read.");
  const limitsHtml = `<ul>${limits.map((l) => `<li>${l}</li>`).join("")}</ul>${
    ungrounded.length
      ? `<p>${ungrounded.length} entr${ungrounded.length === 1 ? "y is" : "ies are"} marked <strong>not grounded in the trace</strong>: no call before ${ungrounded.length === 1 ? "it" : "each"} was recorded named its source. The source may still be right (a path inside an image a tool reached by inode, say), but the trace does not show the swarm reading it.</p>`
      : ""
  }${
    sensitive.length
      ? `<h3>Sensitive material</h3><p>${sensitive.length} standing entr${sensitive.length === 1 ? "y is" : "ies are"} marked sensitive: ${sensitive.map((e) => `<a href="#e-${e.seq}">E-${e.seq}</a>`).join(", ")}. The objects they cite (${[...new Set(sensitive.flatMap((e) => e.refs ?? []))].map((r) => `<code>${escapeHtml(r)}</code>`).join(", ") || "none named"}) are replaced by their hashes in a package made with <code>--redact</code>.</p>`
      : ""
  }`;

  // --- Appendix D: chain of custody --------------------------------------
  // What a court reads first: each check's status, what was sealed, how to check it again.
  const checksRow = hostCustody?.checks?.length
    ? hostCustody.checks.map((c) => `${c.name}: ${c.status.replace("_", " ")}${c.reason ? ` (${c.reason})` : ""}${c.expected !== undefined ? ` [${c.checked ?? 0} of ${c.expected}]` : ""}`).join("; ")
    : null;
  const sealRow = hostCustody?.seal
    ? `trace ${hostCustody.seal.trace?.lines ?? 0} lines (the last line's sha256 ${hostCustody.seal.trace?.last_line_sha256 ?? "none"}); ledger ${hostCustody.seal.ledger?.entries ?? 0} entries, head ${hostCustody.seal.ledger?.head ?? "none"}${hostCustody.seal.attestations?.lines ? `; attestations ${hostCustody.seal.attestations.lines} lines, head ${hostCustody.seal.attestations.head}` : ""}${hostCustody.seal.disputes?.lines ? `; disputes ${hostCustody.seal.disputes.lines} lines, head ${hostCustody.seal.disputes.head}` : ""}${hostCustody.seal.journal ? `; store journal ${hostCustody.seal.journal.lines} lines, head ${hostCustody.seal.journal.head}` : ""}`
    : null;
  const acquisitionRow = hostCustody?.acquisition
    ? hostCustody.acquisition.mismatched.length
      ? `DOES NOT MATCH: ${hostCustody.acquisition.mismatched.join(", ")} (of ${hostCustody.acquisition.given} given in ${hostCustody.acquisition.source ?? "the file given"})`
      : `${hostCustody.acquisition.matched} of ${hostCustody.acquisition.given} digests from ${hostCustody.acquisition.source ?? "the file given"} (sha256 ${hostCustody.acquisition.source_sha256 ?? "not recorded"}) match the evidence as re-hashed${hostCustody.acquisition.not_compared.length ? `; ${hostCustody.acquisition.not_compared.length} not compared` : ""}`
    : hostCustody
      ? "not given at kickoff (--inputs-hashes): \"intact\" above means unchanged since the kickoff hashed it, not against the imager's own numbers"
      : null;
  const signatureRow = lastAnchored?.signature
    ? lastAnchored.signature.error
      ? `NOT SIGNED: ${lastAnchored.signature.error}`
      : `custody.json.sig, ssh key ${lastAnchored.signature.key ?? "(fingerprint not recorded)"}, namespace dfirswarm-custody`
    : "custody.json is not signed (--custody-sign-key)";
  const timestampRow = lastAnchored?.timestamp
    ? lastAnchored.timestamp.error
      ? `NOT TIMESTAMPED: ${lastAnchored.timestamp.error}`
      : `custody.json.tsr from ${lastAnchored.timestamp.authority}, ${lastAnchored.timestamp.gen_time ?? "time not read"} (RFC 3161; ${
          lastAnchored.timestamp.signature?.verified === true
            ? `its signature verified against ${lastAnchored.timestamp.signature.ca ?? "the authority's CA"} when custody took it (openssl ts -verify)`
            : lastAnchored.timestamp.signature?.verified === false
              ? `ITS SIGNATURE DID NOT VERIFY against ${lastAnchored.timestamp.signature.ca ?? "the CA named"}: ${lastAnchored.timestamp.signature.detail ?? "no detail"}`
              : `imprint only: its signature was not verified${lastAnchored.timestamp.signature?.detail && lastAnchored.timestamp.signature.ca ? ` (${lastAnchored.timestamp.signature.detail})` : " (no CA named: --custody-timestamp-ca)"}; to check it: openssl ts -verify -in custody.json.tsr -data custody.json -CAfile <the authority's CA>, or swarm.sh custody-verify --tsa-ca FILE`
        })`
    : "no trusted timestamp (--custody-timestamp-url)";
  const clockRef = (r: { url?: string; offset_ms?: number | null; precision_ms?: number; error?: string } | null | undefined, when: string) =>
    r ? (r.offset_ms === null || r.offset_ms === undefined ? `${when}: ${r.url} not read (${r.error ?? "no answer"})` : `${when}: the host ${r.offset_ms >= 0 ? "behind" : "ahead of"} ${r.url} by ${Math.abs(r.offset_ms)} ms (± ${r.precision_ms ?? 1000} ms)`) : null;
  const referenceRow = [clockRef(custodyAnchorFile?.time_reference, "at kickoff"), clockRef(hostCustody?.time_reference, "at custody")].filter(Boolean).join("; ") || "no reference clock named (--time-reference)";
  const modelsRow = hostCustody?.models
    ? `${[...new Set(hostCustody.models.team.map((m) => m.model ?? "not recorded"))].join(", ")} (as given to the agents)${hostCustody.models.gateway_answered ? `; the gateway saw ${hostCustody.models.gateway_answered.join(", ") || "none"} answer` : "; no host-side record of the model ids that answered (no model gateway)"}`
    : null;
  const custody: Array<[string, string]> = [
    ["Case", caseId || "—"],
    ["Examiner", examiner || "—"],
    ["Tool", `DFIR Swarm ${version}${commit}`],
    ...(provenance ? ([["Reproducibility", provenance]] as Array<[string, string]>) : []),
    ...(hostClockLine(runRecord) ? ([["Host clock", hostClockLine(runRecord) as string]] as Array<[string, string]>) : []),
    ["Run", id || "—"],
    ["Started", startedAt || "—"],
    ["Ended", endedAt || "—"],
    ["Sandbox", sandbox],
    ["Evidence", inputs ? `${inputs.files.length} file(s), ${bytesHuman(inputs.bytes ?? 0)}, ${evidenceFrom(inputs)}${sourceCheck ? `; ${sourceCheck}` : ""}` : "none given"],
    [
      "Evidence intact at the end",
      // The host's own re-hash, when the stop took one, is the verdict; an
      // agent's check is the agent's word and is said as such beside it.
      hostEvidenceLine(hostCustody?.inputs, hostCustody?.at) !== null
        ? (hostEvidenceLine(hostCustody?.inputs, hostCustody?.at) as string) +
            (inputsCheck ? `; the agents' own last check (${inputsCheck.by}, ${inputsCheck.at}) said ${inputsCheck.ok ? "intact" : "changed"}` : "")
          : hostCustody && hostCustody.inputs === null
            ? `no evidence to check: the host's custody (${hostCustody.at ?? "time not recorded"}) found none given to this run`
          : !inputsCheck
            ? "not checked (no host custody was taken; an agent's check is absent too)"
            : inputsCheck.ok
              ? `an agent's word only: ${inputsCheck.checked} checked by ${inputsCheck.by} at ${inputsCheck.at}; no host custody was taken (swarm.sh stop takes it)`
              : inputsCheck.content_ok
                ? `an agent's word only: bytes intact (${inputsCheck.checked} checked by ${inputsCheck.by} at ${inputsCheck.at}); ${inputsCheck.metadata.length} file(s) drifted in mode or link count only`
                : `an agent's word only: NO — ${inputsCheck.modified.length} modified, ${inputsCheck.missing.length} missing, ${inputsCheck.added.length} added`,
    ],
    [
      "Network",
      vmRecords.length && (run?.netguard_mode === "microvm-open" || vmRecords.some((r) => r.network?.default === "public"))
        ? "each agent's VM, OPEN (--no-netguard): every public host; each credential still only to its own host"
        : vmRecords.length
        ? `each agent's VM, deny by default: ${[...new Set(vmRecords.flatMap((r) => r.network?.default === "public" ? ["every public host"] : [...(r.network?.allow_hosts ?? []), ...(r.network?.host_ports ?? []).map((p) => `host gateway :${p}`)]))].join(", ") || "nothing"}`
        : allowHosts
        ? `netguard allowlist: ${allowHosts.split("\n").filter(Boolean).join(", ")}`
        : allowFromLog.length
          ? `netguard allowlist not kept; the proxy log shows it allowed ${allowFromLog.join(", ")}`
          : "netguard allowlist not recorded",
    ],
    // What the allowlist was is half the custody line; whether the host could
    // hold it is the other half, and the record used to carry only the first.
    ["Egress enforcement", egressLine(run?.netguard === false && !String(run?.netguard_mode ?? "").startsWith("microvm") ? "off" : (run?.netguard_mode as string | undefined))],
    ["Write guard", writeGuardLine(run?.write_guard as string | undefined)],
    ["Terminal socket", herdrSocketLine(run?.herdr_socket as string | undefined)],
    ["Pi extensions", piExtensionsLine(run?.pi_extensions as string | undefined)],
    ["Attribution", attributionLine(run?.attribution as string | undefined)],
    ["Guard measured", measuredGuardLine(run?.write_guard_measured as string | undefined)],
    ...vmRows(vmRecords),
    // A host run says so beside the VM rows it does not have: every agent
    // was a process on this machine, and a record with no isolation field is
    // an old host run.
    ...(run?.isolation?.mode === "microvm" ? [] : [["Isolation", "host, unisolated: every agent was a process on this machine (--isolation host); the host guards above are what held it"] as [string, string]]),
    [
      "Trace integrity",
      traceUnread
        ? `NOT READ HERE: the trace could not be read by this report (${traceUnread}); the host's custody check streams it, and its verdict is below`
        : chainLine(chain, Boolean(anchorPoint), anchorGuarded(run?.write_guard as string | undefined, run?.host_caps as Record<string, unknown> | undefined), operatorActions, harnessFromShell),
    ],
    ["Egress refused", egressRefusedLine(deniedHosts, netguardLog !== null, run, custodyViolations(hostCustody), custodyOwnHostStops(hostCustody))],
    ["Content sent to", providersLine(run)],
    [
      "Installed during the run",
      toolchain?.packages?.length
        ? toolchain.packages.map((p) => `${p.name} ${p.version}${p.record_sha256 ? ` (${p.record_sha256.slice(0, 12)})` : ""}`).join(", ")
        : "nothing",
    ],
    ["Ledger", `${ledger.length} entries (${timeline.length} events, ${iocs.length} indicators, ${findings.length} findings${absences.length ? `, ${absences.length} searched and not found` : ""}${correctedBy.size ? `; ${correctedBy.size} corrected by a later entry, kept as recorded` : ""})`],
    ["Examiner review", reviewLine(review, ledger)],
    ["Releases", releaseRow],
    ...(gatewayRecordOf(runRecord) ? ([["Model gateway", gatewayLine(gatewayRecordOf(runRecord) as GatewayRecord, gatewayTotals, hostCustody?.model_gateway)]] as Array<[string, string]>) : []),
    ["Coverage", coverageLine(coverage)],
    [
      "Grounding",
      coverage.unavailable
        ? `not computed: ${coverage.unavailable}`
        : `${ledger.length - ungrounded.length - Object.values(coverage.grounding).filter((g) => g === "not a path").length} entr${ledger.length === 1 ? "y" : "ies"} with a source a call named before it was recorded${coverage.grounded_via_job.length ? `, or (${coverage.grounded_via_job.length} of them) a job the entry cites was given an evidence input before it` : ""}; ${ungrounded.length} not grounded in the trace${ungrounded.length ? ` (${ungrounded.map((e) => `E-${e.seq}`).join(", ")})` : ""}; ${Object.values(coverage.grounding).filter((g) => g === "not a path").length} whose source names no path`,
    ],
    ...heldRows(runRecord),
    [
      "Host custody check",
      hostCustody?.summary
        ? `${hostCustody.summary} (taken on the host after the run, ${hostCustody.at ?? "time not recorded"}; custody.json${custodyAnchor && custodyAnchor.state !== "no verdict" ? `, which ${verdictAnchorLine(custodyAnchor)}` : ""})`
        : "not taken (swarm.sh stop takes it)",
    ],
    ["Trace", traceUnread ? `not read here (${traceUnread})` : `${events.length} tool calls`],
    ...(checksRow ? ([["Custody checks", checksRow]] as Array<[string, string]>) : []),
    ...(sealRow ? ([["Sealed", sealRow]] as Array<[string, string]>) : []),
    ...(acquisitionRow ? ([["Acquisition hashes", acquisitionRow]] as Array<[string, string]>) : []),
    ...(hostCustody?.operator ? ([["Operator audit", hostCustody.operator.intact ? `${hostCustody.operator.detail}; ${hostCustody.operator.matched} of ${hostCustody.operator.trace_actions} operator line(s) on the trace are on it` : `CHAIN BROKEN: ${hostCustody.operator.detail}`]] as Array<[string, string]>) : []),
    ["Verdict signature", signatureRow],
    ["Trusted timestamp", timestampRow],
    ["Reference clock", referenceRow],
    ...(modelsRow ? ([["Models", modelsRow]] as Array<[string, string]>) : []),
    ...(hostCustody?.timing ? ([["Custody's cost", `${Math.round(hostCustody.timing.total_ms / 1000)} s; ${bytesHuman(hostCustody.timing.evidence_bytes)} of evidence re-read${hostCustody.timing.evidence_mb_per_s ? ` at ${hostCustody.timing.evidence_mb_per_s} MB/s` : ""}`]] as Array<[string, string]>) : []),
    ["What the anchors are", "files of the operator's own account beside the run: they hold the agents to account, and a signature and a trusted timestamp hold the verdict itself; they do not hold the operator's account to account"],
    ["Check it again", `swarm.sh custody-verify ${id || "<id>"} (writes nothing in the run: every check, the sealed prefix and the lines after it, every chain's sealed length and head, every work file against the index custody sealed, the signature and the timestamp token, its signature too with --tsa-ca FILE); a package: swarm.sh verify <package> --allowed-signers FILE`],
  ];
  const operatorHtml = operatorActs.length
    ? `<h3>The operator's actions on this run (${operatorActs.length})</h3>
<p>From <code>operator-audit.jsonl</code> beside the registry, chained, where no agent writes: who ran which command, from which host, and how.</p>
<table><thead><tr><th>When (UTC)</th><th>Command</th><th>OS user</th><th>Host</th><th>Via</th></tr></thead><tbody>${operatorActs
        .map((a) => `<tr><td class="tabular">${escapeHtml(a.at)}</td><td>${escapeHtml(a.command)}</td><td>${escapeHtml(a.os_user)}</td><td>${escapeHtml(a.host)}</td><td>${escapeHtml(a.via)}</td></tr>`)
        .join("")}</tbody></table>`
    : "";
  const handover = options.handover ?? [];
  const handoverHtml = handover.length
    ? `<h3>Files handed over with this report (${handover.length})</h3>
<p>What a court or a counterparty receives beside this document, as the dossier read each file when it generated this report: its size and sha256, or why it is absent. This report is not in the list, since its own hash cannot be inside it; <code>court-set.json</code> carries it.</p>
<table class="handover"><thead><tr><th>File</th><th class="num">Size</th><th>sha256</th><th>Contents</th></tr></thead><tbody>${handover
        .map(
          (f) =>
            `<tr><td><code>${escapeHtml(f.name)}</code></td><td class="num">${f.present && f.bytes !== null ? escapeHtml(bytesHuman(f.bytes)) : "—"}</td><td class="hash">${f.present && f.sha256 ? escapeHtml(f.sha256) : escapeHtml(`absent: ${f.reason ?? "not there"}`)}</td><td>${escapeHtml(f.description)}</td></tr>`,
        )
        .join("")}</tbody></table>`
    : "";
  const custodySection: Section = {
    id: "sD",
    n: "D",
    title: "Appendix D: Chain of custody",
    desc: "the custody record, and how to check it again",
    breakBefore: true,
    html: `<table><thead><tr><th>Item</th><th>Recorded</th></tr></thead><tbody>${custody
      .map(([k, v]) => `<tr><td>${escapeHtml(k)}</td><td class="${k.startsWith("Sandbox") || k === "Sealed" ? "hash" : ""}">${escapeHtml(v)}</td></tr>`)
      .join("")}</tbody></table>${operatorHtml}${handoverHtml}`,
  };

  // --- The body: the answers and what they rest on (scripts/report-body.ts)
  // The swarm's own report, as the sentinel names it: the body reproduces it
  // in its Appendix C, labelled with what custody says of those bytes.
  const own = await (async () => {
    for (const candidate of [sentinel?.output, "work/report.md", "work/notes.md"]) {
      if (!candidate || !candidate.endsWith(".md")) continue;
      // The sentinel's output is an agent's word: a path that leaves the run
      // (`work/../..`) or a link an agent planted is not read into a report
      // that leaves the building.
      let key: string;
      try {
        key = claimKey(sandbox, candidate);
      } catch {
        continue;
      }
      if (!key.startsWith("work/")) continue;
      const read = await readSandboxFile(sandbox, key, { maxBytes: 16 * 1024 * 1024 }).catch(() => null);
      const text = read ? read.bytes.toString("utf8") : null;
      // The hash of the bytes reproduced here, not of a read made before them.
      if (text && text.trim() && read) return { path: key, text, sha256: createHash("sha256").update(read.bytes).digest("hex") };
    }
    return null;
  })();
  const body = await renderReportBody(sandbox, {
    review: bodyReview(review, rel.examiner),
    release: rel.release,
    grounding: { ...coverage.grounding, ...Object.fromEntries(coverage.grounded_via_job.map((seq) => [seq, GROUNDED_VIA_JOB])) },
    ...(run?.model ? { defaultModel: run.model } : {}),
    workingReport: own ? { path: own.path, text: own.text, seal: await ownReportSeal(sandbox, own.path, own.sha256, hostCustody, lastAnchored?.artifacts_sha256) } : null,
    html: { ...(evidenceHtml ? { evidence: evidenceHtml } : {}), method: methodHtml, limits: limitsHtml },
    // The release this rendering is for, or the run's latest (bodyRelease):
    // a draft unless an examiner adopted it; a release renders its own final bytes.
  });
  // The body's sections and its appendices A to C, then this report's D and E, then the body's later appendices (F: the registers), in their letters' order.
  const bodySection = (b: (typeof body.sections)[number]): Section => ({ id: b.id, n: b.n, title: /^[A-Z]$/.test(b.n) ? `Appendix ${b.n}: ${b.title}` : b.title, desc: b.desc, ...(b.count ? { count: b.count } : {}), html: b.html, ...(b.n === "A" || b.n === "C" || b.n === "F" ? { breakBefore: true } : {}) });
  const sections: Section[] = [
    ...body.sections.filter((b) => !/^[F-Z]$/.test(b.n)).map(bodySection),
    custodySection,
    artifactsSection,
    ...body.sections.filter((b) => /^[F-Z]$/.test(b.n)).map(bodySection),
  ];

  const toc = sections
    // A section's number in the margin; an appendix says its letter in its title, once.
    .map((s) => `<li><span class="n">${/^\d+$/.test(s.n) ? escapeHtml(s.n) : ""}</span><a href="#${s.id}">${escapeHtml(s.title)}</a>${s.desc ? `<span class="desc">${escapeHtml(s.desc)}</span>` : ""}</li>`)
    .join("");
  // The cover's scorecard: the six numbers a reader wants before they decide
  // how much of the rest to read.
  const scoreCells: Array<[string, string, string]> = [
    body.facts.questions
      ? [`${body.facts.answered} of ${body.facts.questions}`, "Questions answered", body.facts.hasAnswers ? `${body.facts.adopted} adopted by the examiner` : "no answer in the ledger"]
      : [String(findings.length), "Findings", `${findings.filter((f) => f.confidence === "high").length} at high confidence`],
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
  const headline = body.facts.hasAnswers
    ? `${body.facts.answered} of ${body.facts.questions} question${body.facts.questions === 1 ? "" : "s"} answered`
    : findings.length
      ? `${findings.length} finding${findings.length === 1 ? "" : "s"}${highCount ? `, ${highCount} at high confidence` : ""}`
      : "no findings recorded";
  const stateChip = sentinel ? chip("finished", "moss") : allDead ? chip("every agent died", "brick") : run?.state === "stopped" ? chip("stopped", "brick") : chip("did not finish", "saffron");

  return `<!doctype html>
<html lang="en">
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>${escapeHtml(`${body.draft ? "DRAFT — " : ""}${title}`)}</title>
<meta name="generator" content="DFIR Swarm ${escapeHtml(version)}">
<meta name="dcterms.created" content="${escapeHtml(generatedAt)}">
<meta name="dfirswarm.release" content="${escapeHtml(adoptedHere ? `v${adoptedHere.version} adopted` : forRelease ? `v${forRelease.version} draft` : "none: a draft rendering")}">
<style>${STYLE}${body.style}</style>
<body>
${draftMark ? '<div class="watermark" aria-hidden="true">DRAFT</div>\n' : ""}<main>
  <header class="cover">
    <div class="mark">${mark}<span class="wordmark">DFIR Swarm</span></div>
    <p class="kicker">${escapeHtml(options.organisation || "Forensic report")}</p>
    <h1>${escapeHtml(caseId || run?.label || id || "Untitled case")}</h1>
    <p class="case-line"><strong>${escapeHtml(headline)}</strong> ${stateChip}${body.draft ? ` ${chip("draft", "brick")}` : ""}</p>
    <p class="release-banner${adoptedHere ? " adopted" : ""}">${escapeHtml(releaseBanner)}</p>
    ${scorecard}
    <dl class="facts">
      <dt>Examiner</dt><dd>${escapeHtml(adopter ? `${adopter.name}, ${adopter.organisation}: ${adopter.competence} (enrolled on this install; key ${adopter.fingerprint})` : adoptedElsewhere ? `none for this rendering; release v${adoptedElsewhere.version} is adopted by ${adoptedElsewhere.record?.signer.examiner?.name ?? "an examiner"}` : "none: no enrolled examiner has adopted this report")}</dd>
      ${examiner ? `<dt>Run by</dt><dd>${escapeHtml(`${examiner} (as the kickoff recorded who ran it; not an enrolled examiner, and not a signature)`)}</dd>` : ""}
      <dt>Release</dt><dd>${escapeHtml(adoptedHere ? `v${adoptedHere.version}, adopted ${adoptedHere.at}${adoptedHere.adoption ? adoptedHere.adoption.scope === "answers" ? `: ${adoptedHere.adoption.adopted} conclusion(s) adopted, ${adoptedHere.adoption.qualified} qualified, ${adoptedHere.adoption.withdrawn} withdrawn, ${adoptedHere.adoption.inconclusive} rendered inconclusive, ${adoptedHere.adoption.not_adopted} not adopted (the agents')` : ": the report as a whole (a ledger with no answer entries)" : ""}${adoptedHere.adoption?.technical.length ? `; methods checked by ${adoptedHere.adoption.technical.join("; ")}` : ""}` : forRelease ? `v${forRelease.version}, a draft sealed by the machine at ${forRelease.at}` : "none: a rendering, not a release")}</dd>
      <dt>Run</dt><dd class="hash">${escapeHtml(id || "—")}</dd>
      <dt>Period</dt><dd class="tabular">${escapeHtml(startedAt || "—")} → ${escapeHtml(endedAt || "—")}</dd>
      <dt>Tool</dt><dd>DFIR Swarm ${escapeHtml(version)}${escapeHtml(commit)}</dd>
      <dt>Prepared by</dt><dd>an AI agent swarm (${team.n} agent${team.n === 1 ? "" : "s"}); ${
        adoptedHere
          ? `adopted by ${escapeHtml(adopter?.name ?? "the examiner")} in release v${adoptedHere.version}: the conclusions the examiner adopted or qualified are the examiner's, and every other one is the agents' conclusion, not adopted`
          : review && review.signed && signoffCurrent(review)
          ? `reviewed and signed by ${escapeHtml(review.signed.examiner)} at ${escapeHtml(review.signed.at)}, over this ledger and this report`
          : review && review.signed && !review.unreadable
            ? `signed off by ${escapeHtml(review.signed.examiner)} at ${escapeHtml(review.signed.at)}, and NOT OVER THIS RUN AS IT STANDS: ${escapeHtml(signoffScope(review))}`
            : "its findings are the agents' conclusions until an examiner reviews them"
      }</dd>
      <dt>Generated</dt><dd class="tabular">${escapeHtml(generatedAt)}</dd>
    </dl>
  </header>

  <nav class="toc" aria-label="Contents">
    <h2>Contents</h2>
    <ol>${toc}</ol>
    <p class="note">Section numbers, not page numbers: the pagination belongs to whatever prints this file, and a number this document computed itself would be wrong in every engine but one. <code>swarm.sh report &lt;id&gt; --pdf</code> prints it through a browser, which numbers the pages in the footer and puts this document's title and the print date at the top of each one.</p>
  </nav>

${body.preamble}

${sections
    .map(
      (s) => `  <section id="${s.id}"${s.breakBefore ? ' class="page-break"' : ""}>
    <div class="sec-head">${/^\d+$/.test(s.n) ? `<span class="n">${escapeHtml(s.n)}</span>` : ""}<h2>${escapeHtml(s.title)}</h2>${s.count ? `<span class="count">${escapeHtml(s.count)}</span>` : ""}</div>
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
