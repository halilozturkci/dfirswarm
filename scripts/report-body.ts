#!/usr/bin/env node
/**
 * The report's body: what the run found, told to the person who has to act
 * on it.
 *
 *   node --experimental-strip-types scripts/report-body.ts <sandbox> [--md]
 *
 * The report used to carry the agents' own `work/report.md` verbatim, which
 * is the one document of a run nothing checks: an agent can write any
 * sentence into it. From ledger version 4 the swarm's answers are ledger
 * entries (`kind=answer`) that cite, by hash, the entries they rest on, and a
 * finding says what its observation indicates and why that confidence. This
 * module renders those as the body. Each question gets one fixed block that
 * leads with the answer in plain words and then says how it was obtained,
 * what it indicates, why that confidence, what else could explain it, what
 * speaks against it, what bounds it and what would change it, each step
 * citing its exhibits. The working report moves to an appendix, labelled as
 * the agents' working document, with no evidentiary authority.
 *
 * Three voices are kept apart on the page, because a reader weighing a
 * report has to know which sentences were seen in the evidence and which
 * were reasoned from it: an observation (upright, a plain rule), an
 * interpretation (italic, a dotted rule) and an opinion (boxed). What this
 * module computes itself, such as the corroboration groups, is said to be
 * computed and set apart once more.
 *
 * Every status a reader needs is a chip, and chips are never conflated:
 * single-source (every ref traces to one evidence object), not attested (no
 * agent other than its author re-derived it) and not independently reviewed
 * (no human checked it) are three different facts. An agent's act is never
 * called peer review.
 *
 * Nothing is cut: every string is rendered whole, a 20,000-character
 * reasoning included. The HTML follows report.ts: self-contained, escaped,
 * system fonts, a print stylesheet, `E-<seq>` as the exhibit anchor. The
 * Markdown rendering carries the same content for a reader without a
 * browser, or a model.
 *
 * Every render carries a DRAFT watermark unless the caller says a release v1
 * exists. The watermark is decided when the bytes are rendered, so a release
 * renders its own final bytes rather than editing a draft's.
 */
import { createHash } from "node:crypto";
import { readdir, readFile, stat } from "node:fs/promises";
import { basename, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import type { OperatorRequest } from "../extensions/requests.ts";
import {
  answerProblems,
  attestationAct,
  ledgerGate,
  ledgerHash,
  ledgerMethods,
  limitationCites,
  listForgedTools,
  negativeReview,
  openContradictions,
  partialOutputCites,
  readAttestations,
  readDisputes,
  readInputsManifest,
  readLedger,
  readNames,
  readSandboxFile,
  sectionAnswersId,
  sectionKey,
  standingContradictions,
  standingDisputes,
  supersededBy,
  verifyAttestationChain,
  verifyDisputeChain,
  verifyLedgerChain,
  answerReviews,
  answerPartsStanding,
  heldAsBestCandidate,
  recordedConfidence,
  confidenceWords,
  type ForgedToolManifest,
  type InputsManifest,
  type LedgerAttestation,
  type LedgerDispute,
  type LedgerEdge,
  type LedgerEntry,
  type LedgerGate,
  type LedgerMethod,
  type NameRecord,
  type RecordedConfidence,
} from "../extensions/protocol.ts";
import { escapeHtml, markdownToHtml } from "../ui/src/lib/markdown.ts";
import { readSweeps, sweepOf, sweepWords, type SweepRecord } from "../extensions/store-sweep.ts";
import { answerResult, resultWords, reviewWords as negativeReviewWords, NEGATIVE_RESULTS } from "../extensions/negative-bar.ts";
import { sectionBars } from "./check-answers.ts";
import { leadsSnapshot, rankedLeads, viewLead, type LeadEvent, type LeadView, type LeadsSnapshot } from "../extensions/leads.ts";
import { originWords, premiseViews, presumptionsOf, questionViews, type PremiseView, type QuestionEvent, type QuestionView, type QuestionsSnapshot } from "../extensions/questions.ts";
import { classWords, partialPlainWords, partsSummaryWords, presumptionWords, scopeWords, type PartsStanding, type Presumption } from "../extensions/premises.ts";
import { questionCost, tokensWords, type QuestionCost } from "./question-cost.ts";
import { FINISH_LOG, readFinish, type FinishState } from "../extensions/finish.ts";
import { evidenceCodeRun, onlyOwnOutputs, ownJobOutputs, ownWords, type EvidenceCode } from "../extensions/evidence-code.ts";

/** An entry's grounding when no call named its source and a job it cites was given an evidence input (report.ts maps coverage.ts onto it). */
export const GROUNDED_VIA_JOB = "grounded through a job";

// ---------------------------------------------------------------------------
// Options
// ---------------------------------------------------------------------------

/**
 * The release this render is for (release-record.ts bodyRelease). Version 1
 * or later that an examiner adopted is a release; anything else, a machine's
 * draft included, is a draft.
 */
export type ReportRelease = { version: number; at?: string; state?: "draft" | "adopted" };

/**
 * A human's review of the run, as the caller read it (report.ts keeps the
 * examiner's review file and maps it into this). Agent acts never go here:
 * they are the ledger's attestations and disputes.
 */
export type HumanReview = {
  examiner?: { name: string; organisation?: string; competence?: string } | null;
  /** A second human who checked the methods, when there was one (the latest). */
  technicalReviewer?: { name: string; competence?: string; checked?: string } | null;
  /**
   * Every technical review, in order, each with where it stands in one of the
   * five wordings (review.ts technicalWords): signed by the reviewer; recorded
   * by the examiner, not signed by the reviewer; countersigned after a
   * release; signed (or recorded) over an earlier state, not current. None at
   * all reads "No technical review".
   */
  technicalReviews?: Array<{ name: string; organisation?: string | null; competence?: string; checked?: string; outcome?: string | null; reviewed_at?: string | null; disagreements?: string[]; words: string }>;
  /** The examiner's latest word on an entry, by seq. */
  entries?: Map<number, { action: string; by: string; at: string; note?: string; entry_hash?: string }>;
  /**
   * The sign-off, and whether it covers the run as it stands (the ledger's
   * head and the report's hash the ones signed); `scope` says what it is
   * over when it does not. Only a current sign-off reads "signed".
   */
  signed?: { by: string; at: string; ledger_head?: string; current?: boolean; scope?: string } | null;
  /** Why the review could not be read: said as that, never as "not reviewed". */
  unreadable?: string;
};

/**
 * report.ts's examiner review, as this module takes it: the review file's
 * lines, the latest word on each entry and the signature. Structural, so
 * report.ts passes its own ReviewState without either module importing the
 * other.
 */
export function humanReviewFrom(
  state: { byEntry: Map<number, { action: string; examiner: string; at: string; note?: string; entry_hash?: string }>; signed: { examiner: string; at: string; ledger_head?: string } | null; unreadable?: string } | null,
  examiner?: { name: string; organisation?: string } | null,
  /** Whether the sign-off covers the run as it stands (report.ts: signoffCurrent, signoffScope). */
  signoff?: { current: boolean; scope?: string },
): HumanReview | null {
  if (!state) return examiner ? { examiner } : null;
  if (state.unreadable) return { unreadable: state.unreadable };
  return {
    ...(examiner || state.signed ? { examiner: examiner ?? { name: (state.signed as { examiner: string }).examiner } } : {}),
    entries: new Map([...state.byEntry].map(([seq, l]) => [seq, { action: l.action, by: l.examiner, at: l.at, ...(l.note ? { note: l.note } : {}), ...(l.entry_hash ? { entry_hash: l.entry_hash } : {}) }])),
    signed: state.signed ? { by: state.signed.examiner, at: state.signed.at, ...(state.signed.ledger_head ? { ledger_head: state.signed.ledger_head } : {}), ...(signoff ? { current: signoff.current, ...(signoff.scope ? { scope: signoff.scope } : {}) } : {}) } : null,
  };
}

export type ReportBodyOptions = {
  release?: ReportRelease | null;
  review?: HumanReview | null;
  /** The goal's questions, when the caller knows them better than SWARM.md says. */
  questions?: Array<{ id: string; text: string }>;
  /**
   * The working report for Appendix C; read from work/report.md when not
   * given, none when null. `seal` is what custody says of those bytes (report.ts:
   * ownReportSeal), said in place of the body's own hash line.
   */
  workingReport?: { path: string; text: string; seal?: string } | null;
  /**
   * HTML a caller that knows more of the run adds to the HTML body (never
   * to the Markdown): `evidence` in place of §3's file table (report.ts's,
   * with the per-pane guard and what the trace named), `method` at the end of
   * §4's account of the swarm (spend, calls, context, the tools the trace
   * shows forged; the body's own list of forged tools is then left out),
   * `limits` in §8 (the run's own limits). The caller escapes what it writes.
   */
  html?: { evidence?: string; method?: string; limits?: string };
  /**
   * Whether the trace shows each entry's source being read before the entry
   * was recorded, by seq (report.ts computes it: coverage.ts's grounding).
   * The body does not read the trace itself.
   */
  grounding?: Record<string, string>;
  /** The run's model, for an agent team.json names without one (report.ts: the registry's). */
  defaultModel?: string;
};

// ---------------------------------------------------------------------------
// The goal
// ---------------------------------------------------------------------------

export type GoalQuestion = { id: string; text: string };

export type Goal = {
  /** The line under the contract's title: the case, the examiner. */
  caseLine: string;
  /** The goal's own words before its first sub-heading: what was asked. */
  request: string;
  questions: GoalQuestion[];
  /** The contract's caps, one line each. */
  caps: string[];
  /**
   * Whether the goal asks for recommendations, and how it says so: a
   * `## Recommendations` section (or a `### Recommendations` sub-heading of
   * its goal) is the marker, and its text what is asked; failing one,
   * wording that asks for them in the request or a question. `questions`
   * are the question ids whose wording asks for them. Null when it does not.
   */
  recommendations: { marker: "section" | "wording"; text: string; questions: string[]; request: boolean } | null;
};

const RECOMMEND = /\b(recommend\w*|remediat\w*|mitigat\w*|what would it take)\b/i;

/** A Markdown document's `## ` sections, by heading, fences skipped. */
function h2Sections(text: string): { before: string[]; sections: Map<string, string[]> } {
  const before: string[] = [];
  const sections = new Map<string, string[]>();
  let current: string[] | null = null;
  let fenced = false;
  for (const line of text.split("\n")) {
    if (/^\s*(```|~~~)/.test(line)) fenced = !fenced;
    const h = fenced ? null : /^##\s+(.+?)\s*$/.exec(line);
    if (h && !line.startsWith("###")) {
      current = [];
      if (!sections.has(h[1])) sections.set(h[1], current);
      continue;
    }
    (current ?? before).push(line);
  }
  return { before, sections };
}

/**
 * What the goal asked, from the rendered contract (SWARM.md): the request in
 * the goal's own words, its numbered questions (under a `### ` heading that
 * names questions), the caps, and whether it asks for recommendations.
 * Nothing here knows a case: a goal without numbered questions has none.
 */
export function parseGoal(swarmMd: string): Goal {
  const { before, sections } = h2Sections(swarmMd.replace(/\r\n?/g, "\n"));
  const caseLine = before
    .filter((l) => !/^#\s/.test(l))
    .join("\n")
    .trim();
  const goal = sections.get("Goal") ?? [];
  const request: string[] = [];
  const questionLines: string[] = [];
  const recommendLines: string[] = [];
  let sub: string | null = null;
  for (const line of goal) {
    const h = /^###\s+(.+?)\s*$/.exec(line);
    if (h) {
      sub = h[1];
      continue;
    }
    if (sub === null) request.push(line);
    else if (/^recommendations?$/i.test(sub)) recommendLines.push(line);
    else if (/question/i.test(sub)) questionLines.push(line);
  }
  // A numbered item, with its indented continuation lines; after a blank
  // line, an unindented line that is not an item ends the list.
  const questions: GoalQuestion[] = [];
  let cur: { id: string; parts: string[] } | null = null;
  let blank = false;
  const flush = () => {
    if (cur) questions.push({ id: cur.id, text: cur.parts.join(" ").replace(/\s+/g, " ").trim() });
    cur = null;
  };
  for (const line of questionLines) {
    const m = /^\s{0,3}(\d+(?:\.\d+)*)[.)]\s+(.*)$/.exec(line);
    if (m) {
      flush();
      cur = { id: m[1], parts: [m[2]] };
      blank = false;
      continue;
    }
    if (!line.trim()) {
      blank = true;
      continue;
    }
    if (cur && (!blank || /^\s/.test(line))) {
      cur.parts.push(line.trim());
      blank = false;
      continue;
    }
    flush();
  }
  flush();
  const caps = (sections.get("Caps") ?? []).map((l) => /^\s*-\s+(.*)$/.exec(l)?.[1]?.trim()).filter((l): l is string => Boolean(l));
  const requestText = request.join("\n").trim();
  const section = [...sections.entries()].find(([h]) => /^recommendations?$/i.test(h.trim()))?.[1];
  const marked = section ?? (recommendLines.length ? recommendLines : null);
  const byWording = questions.filter((q) => RECOMMEND.test(q.text)).map((q) => q.id);
  const inRequest = RECOMMEND.test(requestText);
  const recommendations = marked
    ? { marker: "section" as const, text: marked.join("\n").trim(), questions: byWording, request: inRequest }
    : byWording.length || inRequest
      ? { marker: "wording" as const, text: "", questions: byWording, request: inRequest }
      : null;
  return { caseLine, request: requestText, questions, caps, recommendations };
}

// ---------------------------------------------------------------------------
// Reading the run
// ---------------------------------------------------------------------------

type JobRecord = {
  id: string;
  spec: {
    kind?: string;
    inputs?: unknown;
    command?: string;
    tool?: string;
    args?: unknown;
    recipe?: string;
    target?: { ref?: string; name?: string };
    targets?: Array<{ ref?: string; name?: string }>;
    source?: string;
    network?: string;
    profile?: string;
    timeout_seconds?: number;
    note?: string;
    parent?: string;
  };
  requester?: { agent?: string; name?: string; doing?: string };
  status?: string;
  exit?: number | null;
  reason?: string;
  image?: string;
  image_digest?: string;
  tool_sha256?: string;
  /** The sealed output as its manifest lists it; null when there is no manifest. */
  outputs: Array<{ path: string; bytes: number; sha256: string }> | null;
};

type CustodyView = {
  at?: string;
  summary?: string;
  inputs?: { unchanged?: boolean; files?: number; changed?: unknown[]; missing?: unknown[]; added?: unknown[]; skipped?: unknown[]; unreadable?: unknown[]; checked?: { files?: number } } | null;
  acquisition?: { source: string | null; given: number; matched: number; mismatched: string[]; not_compared: string[] } | null;
};

/** A question of the report: its section key, its words, whether the goal asked it, and its register id when the register holds it. */
type Question = { id: string; text: string | null; fromGoal: boolean; reg?: string };

type Chain = { ok: boolean; total: number; broken_at: number | null; reason: string | null };

type Run = {
  sandbox: string;
  runId: string;
  caseId: string;
  goal: Goal | null;
  questions: Question[];
  entries: LedgerEntry[];
  bySeq: Map<number, LedgerEntry>;
  replaced: Map<number, number>;
  attestations: LedgerAttestation[];
  disputes: LedgerDispute[];
  standingD: LedgerDispute[];
  /** The store sweeps of the coverage records (ledger/sweeps.jsonl, extensions/store-sweep.ts). */
  sweeps: SweepRecord[];
  jobs: Map<string, JobRecord>;
  generations: Map<string, string | null>;
  inputs: InputsManifest | null;
  acquisitionGiven: Array<{ path?: string; algo?: string }>;
  custody: CustodyView | null;
  team: Array<{ id: string; model?: string }>;
  names: NameRecord[];
  forged: ForgedToolManifest[];
  working: { path: string; text: string; sha256: string; seal?: string } | { path: string; error: string } | null;
  html: { evidence?: string; method?: string; limits?: string };
  /**
   * What the ledger can hold: answers (it has some); no answers yet from a
   * run whose ledger is version 4; a ledger that predates answers; nothing.
   */
  era: "answers" | "no answers" | "predates" | "empty";
  chains: { ledger: Chain & { chained: number }; attestations: Chain; disputes: Chain };
  review: HumanReview | null;
  grounding: Record<string, string>;
  release: ReportRelease | null;
  draft: boolean;
  hasAnswers: boolean;
  gate: LedgerGate | null;
  problems: Map<number, string[]>;
  failed: Map<number, Array<{ ref: string; job: string; status: string }>>;
  /** Methods for entries that carry none (before version 4), read from the job records now. */
  derivedMethods: Map<number, LedgerMethod[]>;
  /** The lead register (extensions/leads.ts): every lead as it stands, and whether its chain holds; null when the run opened none. */
  leads: { views: LeadView[]; chain: { ok: boolean; broken_at: number | null; reason: string | null }; events: number } | null;
  /** Every lead event, in order: the full register's appendix and the question chains read them. */
  leadEvents: LeadEvent[];
  /**
   * The question register (extensions/questions.ts) as it stands: every
   * question's view (origin, revisions, scope, clarifications, acceptance,
   * leads), its events, and whether its chain holds; derived from the goal,
   * without a write, for a run that never wrote it. Null when it could not be
   * read.
   */
  register: { snap: QuestionsSnapshot; views: QuestionView[]; byId: Map<string, QuestionView>; bySection: Map<string, QuestionView>; events: QuestionEvent[]; persisted: number } | null;
  /** What each question cost in tokens, apportioned by the leads held (scripts/question-cost.ts). */
  cost: QuestionCost | null;
  /** The finish register (leads/finish.jsonl, docs/adr/0015): the coordinator's lease, readiness, the checks, the report's review. Null for a run without one. */
  finish: FinishState | null;
  /** What the negative bar holds each question to: material, and whether it asks whether something exists (the registers'). */
  bar: (id: string) => { material: boolean; existence: boolean };
  /**
   * The case contract (docs/adr/0014): which entries rest on material from
   * outside the original evidence and its classes (net-broker.ts
   * externalLineage), the operator requests, the material added, and what
   * the case policy says of more evidence. Empty for a run before it.
   */
  contract: {
    external: { entries: Map<number, string[]>; classes: Map<number, string[]>; jobs: Map<string, string[]> } | null;
    requests: OperatorRequest[];
    material: Array<Record<string, unknown>>;
    more_evidence: string | null;
  };
};

async function readJson<T>(file: string): Promise<T | null> {
  try {
    return JSON.parse(await readFile(file, "utf8")) as T;
  } catch {
    return null;
  }
}

async function readJobs(sandbox: string): Promise<Map<string, JobRecord>> {
  const dir = join(sandbox, "store", "jobs");
  const out = new Map<string, JobRecord>();
  const ids = (await readdir(dir).catch(() => [] as string[])).filter((n) => /^[a-z0-9-]{1,64}$/.test(n)).sort();
  for (const id of ids) {
    const job = await readJson<Omit<JobRecord, "outputs" | "id"> & { spec?: JobRecord["spec"] }>(join(dir, id, "job.json"));
    if (!job) continue;
    const manifest = await readJson<{ files?: Array<{ path?: unknown; bytes?: unknown; sha256?: unknown }> }>(join(dir, id, "manifest.json"));
    out.set(id, {
      id,
      spec: job.spec ?? {},
      ...(job.requester ? { requester: job.requester } : {}),
      ...(job.status !== undefined ? { status: job.status } : {}),
      ...(job.exit !== undefined ? { exit: job.exit } : {}),
      ...(job.reason !== undefined ? { reason: job.reason } : {}),
      ...(job.image !== undefined ? { image: job.image } : {}),
      ...(job.image_digest !== undefined ? { image_digest: job.image_digest } : {}),
      ...(job.tool_sha256 !== undefined ? { tool_sha256: job.tool_sha256 } : {}),
      outputs: manifest ? (manifest.files ?? []).map((f) => ({ path: String(f.path ?? ""), bytes: Number(f.bytes) || 0, sha256: String(f.sha256 ?? "") })) : null,
    });
  }
  return out;
}

const numericAware = (a: string, b: string): number => {
  const pa = a.split(/[.]/);
  const pb = b.split(/[.]/);
  for (let i = 0; i < Math.max(pa.length, pb.length); i += 1) {
    const x = pa[i] ?? "";
    const y = pb[i] ?? "";
    const nx = /^\d+$/.test(x) ? Number(x) : NaN;
    const ny = /^\d+$/.test(y) ? Number(y) : NaN;
    if (!Number.isNaN(nx) && !Number.isNaN(ny) && nx !== ny) return nx - ny;
    if (Number.isNaN(nx) !== Number.isNaN(ny)) return Number.isNaN(nx) ? 1 : -1;
    if (x !== y) return x.localeCompare(y);
  }
  return 0;
};

const entryHash = (e: LedgerEntry): string => e.hash ?? ledgerHash(e, "genesis");

async function loadRun(sandboxArg: string, opts: ReportBodyOptions): Promise<Run> {
  const sandbox = resolve(sandboxArg);
  const swarmMd = await readFile(join(sandbox, "SWARM.md"), "utf8").catch(() => null);
  const goal = swarmMd === null ? null : parseGoal(swarmMd);
  const entries = await readLedger(sandbox);
  const bySeq = new Map(entries.map((e) => [e.seq, e]));
  const replaced = supersededBy(entries);
  const attestations = await readAttestations(sandbox);
  const disputes = await readDisputes(sandbox);
  const jobs = await readJobs(sandbox);
  const inputs = await readInputsManifest(sandbox);
  const inputsRaw = await readJson<{ acquisition?: { entries?: Array<{ path?: string; algo?: string }> } }>(join(sandbox, "inputs.json"));
  const custody = await readJson<CustodyView>(join(sandbox, "custody.json"));
  const teamRaw = await readJson<{ swarm_id?: string; agents?: Array<{ id?: unknown; model?: unknown }> }>(join(sandbox, "team.json"));
  const team = (teamRaw?.agents ?? []).filter((a) => typeof a?.id === "string").map((a) => ({ id: String(a.id), ...(typeof a.model === "string" ? { model: a.model } : opts.defaultModel ? { model: opts.defaultModel } : {}) }));
  const names = await readNames(sandbox).catch(() => []);
  const forged = (await listForgedTools(sandbox).catch(() => [])).filter((t) => !t.pack);

  // The catalogue generations member: refs name, each to the job that listed it.
  const generations = new Map<string, string | null>();
  for (const e of entries) {
    for (const ref of e.refs ?? []) {
      const gen = /^member:([a-z0-9-]+)#\d+$/.exec(ref)?.[1];
      if (gen && !generations.has(gen)) generations.set(gen, (await readJson<{ job?: string }>(join(sandbox, "catalog", "gen", gen, "generation.json")))?.job ?? null);
    }
  }

  // Which entries rest on the kept output of a job that did not end ok, and
  // which of those the entry does not qualify itself.
  const failed = new Map<number, Array<{ ref: string; job: string; status: string }>>();
  const unqualified = new Map<number, string[]>();
  for (const e of entries) {
    const bad = (e.refs ?? []).flatMap((ref) => {
      const id = /^job:([^/]+)\//.exec(ref)?.[1];
      const job = id ? jobs.get(id) : undefined;
      return job && job.status && job.status !== "ok" ? [{ ref, job: job.id, status: job.status }] : [];
    });
    if (!bad.length) continue;
    failed.set(e.seq, bad);
    const left = bad.filter((b) => !(e.qualifies ?? []).some((q) => q.ref === b.ref)).map((b) => `${b.ref} (job ${b.status})`);
    if (left.length) unqualified.set(e.seq, left);
  }

  // A method for each entry written before the hub wrote one: read from the
  // job records now, and said to be so wherever it is shown.
  const derivedMethods = new Map<number, LedgerMethod[]>();
  for (const e of entries) {
    if (e.method?.length || !e.refs?.length) continue;
    const got = await ledgerMethods(sandbox, e.refs).catch(() => []);
    if (got.length) derivedMethods.set(e.seq, got);
  }

  // The questions: the goal's, then any section an answer or an entry names.
  const questions = new Map<string, Question>();
  for (const q of opts.questions ?? goal?.questions ?? []) questions.set(sectionKey(q.id), { id: sectionKey(q.id), text: q.text, fromGoal: true });
  // A goal with a Recommendations section asks for them as it asks a question: answered as the section "recommendations".
  if (goal?.recommendations?.marker === "section") questions.set("recommendations", { id: "recommendations", text: "what the goal's Recommendations section asks (quoted in §9)", fromGoal: true });
  // The question register, read with the leads (both derived without a write for a run that never wrote them).
  const ls: LeadsSnapshot | null = await leadsSnapshot(sandbox).catch(() => null);
  const register: Run["register"] = ls?.questions
    ? (() => {
        const views = questionViews({ questions: ls.questions, leads: ls.state, ledger: ls.ledger, attestations });
        // The events on disk; any after them are the goal's seed, derived when this is read and never written (their times are the reading's).
        const head = ls.questions.state.chain.head;
        const persisted = head ? ls.questions.state.events.findIndex((e) => e.hash === head) + 1 : 0;
        return { snap: ls.questions, views, byId: new Map(views.map((v) => [v.id, v])), bySection: new Map(views.map((v) => [sectionKey(v.section), v])), events: ls.questions.state.events, persisted };
      })()
    : null;
  for (const [key, q] of questions) {
    const v = register?.bySection.get(key);
    if (v) questions.set(key, { ...q, reg: v.id });
  }
  // A person's or an agent's question in scope is the run's to answer, as the goal's are.
  for (const v of register?.views ?? []) {
    const key = sectionKey(v.section);
    if (v.origin.kind === "goal" || v.scope !== "in_scope" || v.withdrawn || questions.has(key)) continue;
    questions.set(key, { id: key, text: v.text, fromGoal: false, reg: v.id });
  }
  for (const e of entries) {
    const ids = [...(e.kind === "answer" && e.section?.startsWith("question:") ? [sectionAnswersId(e.section)] : []), ...(e.answers ?? [])].map(sectionKey).filter(Boolean);
    for (const id of ids) if (!questions.has(id)) questions.set(id, { id, text: register?.bySection.get(id)?.text ?? null, fromGoal: false, ...(register?.bySection.get(id) ? { reg: register.bySection.get(id)!.id } : {}) });
  }
  const hasAnswers = entries.some((e) => e.kind === "answer");
  // The sections the gate holds the run to: the goal's questions when it numbers them, else every one named;
  // and every material question the register holds in scope beyond the goal's (the finish line's, ADR 0011).
  const asked = [...questions.values()].filter((q) => q.fromGoal);
  const held = (register?.views ?? []).filter((v) => v.origin.kind !== "goal" && v.scope === "in_scope" && !v.withdrawn && !v.after_done && v.materiality === "material").map((v) => `question:${sectionKey(v.section)}`);
  const sections = [...new Set([...(asked.length ? asked : [...questions.values()]).map((q) => `question:${q.id}`), ...(asked.length ? held : []), "summary", "narrative"])];
  const problems = answerProblems(entries, disputes, unqualified);
  const bar = await sectionBars(sandbox).catch(() => (() => ({ material: true, existence: false })) as (id: string) => { material: boolean; existence: boolean });
  const { producerOf } = await (await import("./output-hygiene.ts")).producerIndex(sandbox).catch(() => ({ producerOf: () => null as null }));
  const sweeps = await readSweeps(sandbox).catch(() => [] as SweepRecord[]);
  const preparation = hasAnswers ? await import("../extensions/preparation.ts").then((PR) => PR.preparationFacts(sandbox, entries)).catch(() => undefined) : undefined;
  const premises = register?.snap.state.premises;
  const presumes = ls ? presumptionsOf(ls.questions, ls.state) : new Map<string, Presumption>();
  const gate = hasAnswers ? ledgerGate({ entries, attestations, disputes, sections, failed: unqualified, bar, partial: partialOutputCites(entries, producerOf), sweeps, ...(preparation ? { preparation } : {}), ...(premises?.size ? { premises } : {}), ...(presumes.size ? { presumes } : {}) }) : null;

  const text = async (rel: string) => (await readFile(join(sandbox, rel), "utf8").catch(() => ""));
  const ledgerChain = verifyLedgerChain(await text("ledger/entries.jsonl"));
  const chains = { ledger: ledgerChain, attestations: verifyAttestationChain(await text("ledger/attestations.jsonl")), disputes: verifyDisputeChain(await text("ledger/disputes.jsonl")) };

  const working = await (async (): Promise<Run["working"]> => {
    if (opts.workingReport === null) return null;
    if (opts.workingReport) return { path: opts.workingReport.path, text: opts.workingReport.text, sha256: createHash("sha256").update(opts.workingReport.text).digest("hex"), ...(opts.workingReport.seal ? { seal: opts.workingReport.seal } : {}) };
    try {
      const read = await readSandboxFile(sandbox, "work/report.md", { maxBytes: 64 * 1024 * 1024 });
      if (!read) return null;
      return { path: read.pathKey, text: read.bytes.toString("utf8"), sha256: createHash("sha256").update(read.bytes).digest("hex") };
    } catch (err) {
      return { path: "work/report.md", error: (err as Error).message };
    }
  })();

  const cost = ls
    ? await questionCost(sandbox, ls.state.events, (lead) => (ls.state.leads.get(lead)?.answers ?? []).map((a) => register?.bySection.get(sectionKey(a))?.id ?? `question:${sectionKey(a)}`), {
        // What a call made holding no lead named, keyed as the leads' questions are.
        questionKey: (raw) => {
          const t = raw.trim();
          if (/^Q-\d+$/i.test(t)) return register?.byId.get(`Q-${Number(t.slice(2))}`)?.id ?? null;
          const sec = sectionKey(t.replace(/^question:/i, ""));
          return sec ? (register?.bySection.get(sec)?.id ?? `question:${sec}`) : null;
        },
      }).catch(() => null)
    : null;
  const caseId = /Case\s+`([^`]+)`/.exec(goal?.caseLine ?? "")?.[1] ?? "";
  const release = opts.release ?? null;
  // The case contract: external lineage, the operator requests, the material added, the policy's word on more evidence.
  const contract: Run["contract"] = await (async () => {
    const { externalLineage } = await import("./net-broker.ts");
    const lin = await externalLineage(sandbox).catch(() => null);
    const R = await import("../extensions/requests.ts");
    const rs = await R.requestsSnapshot(sandbox).catch(() => null);
    const { listMaterial } = await import("./material.ts");
    const material = await listMaterial(sandbox).catch(() => [] as Array<Record<string, unknown>>);
    const policy = await readJson<{ more_evidence?: string }>(join(sandbox, "network", "policy.json"));
    return {
      external: lin && (lin.entries.size || lin.jobs.size) ? { entries: lin.entries, classes: lin.classes, jobs: lin.jobs } : null,
      requests: rs ? R.requestList(rs) : [],
      material,
      more_evidence: typeof policy?.more_evidence === "string" ? policy.more_evidence : null,
    };
  })();
  return {
    sandbox,
    runId: teamRaw?.swarm_id ?? basename(sandbox),
    caseId,
    goal,
    questions: [...questions.values()].sort((a, b) => numericAware(a.id, b.id)),
    entries,
    bySeq,
    replaced,
    attestations,
    disputes,
    standingD: standingDisputes(disputes),
    sweeps,
    jobs,
    generations,
    inputs,
    acquisitionGiven: inputsRaw?.acquisition?.entries ?? [],
    custody,
    team,
    names,
    forged,
    working,
    html: opts.html ?? {},
    era: hasAnswers ? "answers" : !entries.length ? "empty" : entries.some((e) => (e.v ?? 1) >= 4) ? "no answers" : "predates",
    chains,
    review: opts.review ?? null,
    grounding: opts.grounding ?? {},
    release,
    draft: !(release && Number(release.version) >= 1 && release.state !== "draft"),
    hasAnswers,
    gate,
    problems,
    failed,
    derivedMethods,
    bar,
    leads: ls && ls.state.events.length ? { views: rankedLeads(ls), chain: ls.state.chain, events: ls.state.events.length } : null,
    leadEvents: ls?.state.events ?? [],
    register,
    cost,
    contract,
    finish: (await stat(join(sandbox, FINISH_LOG)).catch(() => null)) ? await readFinish(sandbox).catch(() => null) : null,
  };
}

// ---------------------------------------------------------------------------
// Corroboration: which evidence objects an entry's refs come from
// ---------------------------------------------------------------------------

/**
 * What a ref's bytes were made from, as evidence objects: the run's inputs by
 * path, or an object whose origin the run did not record, said as such.
 * Two jobs over one disk image are one source: a job: ref is followed to the
 * inputs its job declared, and a job over another job's output to that
 * job's. A job that declared no scope, or the legacy `all`, could have read
 * any input, so it is its own object and its independence is unknown.
 */
type Origin = { keys: string[]; unknown: Unknown[] };
/** Why a source's independence is unknown (it could have read anything), or its origin (what it was made from is not recorded). */
type Unknown = { kind: "independence" | "origin"; text: string };

const inputKey = (p: string) => `input:${p.replace(/^\.?\//, "").replace(/^inputs\//, "")}`;

function pathOrigin(p: string, run: Run, seen: Set<string>): Origin {
  const path = p.replace(/^\.\//, "");
  if (path.startsWith("inputs/")) return { keys: [inputKey(path)], unknown: [] };
  const jobDir = /^store\/jobs\/([^/]+)/.exec(path)?.[1];
  if (jobDir) return jobOrigin(jobDir, run, seen);
  const cat = /^catalog\/([^/]+)\//.exec(path)?.[1];
  if (cat && run.inputs?.files.some((f) => f.path === `inputs/${cat}`)) return { keys: [inputKey(cat)], unknown: [] };
  if (path.startsWith("work/")) return { keys: [`work:${path}`], unknown: [{ kind: "origin", text: `${path} is a file an agent made: what it was made from is not recorded` }] };
  return { keys: [`path:${path}`], unknown: [{ kind: "origin", text: `${path}: where it came from is not traced here` }] };
}

function jobOrigin(id: string, run: Run, seen: Set<string>): Origin {
  if (seen.has(id)) return { keys: [], unknown: [] };
  seen.add(id);
  const job = run.jobs.get(id);
  if (!job) return { keys: [`job:${id}`], unknown: [{ kind: "independence", text: `job ${id} has no record: what it read is unknown` }] };
  const declared = Array.isArray(job.spec.inputs) ? job.spec.inputs.map(String) : [];
  const out: Origin = { keys: [], unknown: [] };
  const add = (o: Origin) => {
    out.keys.push(...o.keys);
    out.unknown.push(...o.unknown);
  };
  if (!declared.length) add({ keys: [`all:${id}`], unknown: [{ kind: "independence", text: `job ${id} declared no scope: it could read every input, so its independence is unknown` }] });
  for (const x of declared) {
    if (x === "all") add({ keys: [`all:${id}`], unknown: [{ kind: "independence", text: `job ${id} declared scope all: it could read every input, so its independence is unknown` }] });
    else if (x.startsWith("input:")) add({ keys: [inputKey(x.slice(6))], unknown: [] });
    else if (x.startsWith("job:")) add(jobOrigin(x.slice(4).split("/")[0], run, seen));
    else add(pathOrigin(x, run, seen));
  }
  return out;
}

function refOrigin(ref: string, run: Run): Origin {
  const m = /^([a-z0-9]+):(.*)$/s.exec(ref);
  if (!m) return pathOrigin(ref, run, new Set());
  const [, kind, value] = m;
  switch (kind) {
    case "input":
      return { keys: [inputKey(value)], unknown: [] };
    case "job":
      return jobOrigin(value.split("/")[0], run, new Set());
    case "import": {
      const id = value.split("/")[0];
      // Evidence or material added from outside, with its provenance on record (docs/adr/0014).
      const m = run.contract.material.find((x) => x.import === id);
      if (m) return { keys: [`import:${id}`], unknown: [] };
      return { keys: [`import:${id}`], unknown: [{ kind: "origin", text: `import ${id} was brought into the store: what it was made from is not recorded` }] };
    }
    case "member": {
      const gen = /^([a-z0-9-]+)#\d+$/.exec(value)?.[1] ?? value;
      const job = run.generations.get(gen);
      return job ? jobOrigin(job, run, new Set()) : { keys: [`member:${gen}`], unknown: [{ kind: "origin", text: `catalogue generation ${gen}: its job is not recorded` }] };
    }
    case "sha256":
      return { keys: [`sha256:${value.toLowerCase()}`], unknown: [] };
    case "unresolved":
      return { keys: [], unknown: [{ kind: "origin", text: `a ref that did not resolve (${value})` }] };
    default:
      return { keys: [ref], unknown: [{ kind: "origin", text: `${ref}: an object of a kind this report does not trace` }] };
  }
}

export type CorroborationGroup = {
  /** The evidence objects, as keys: input:<path>, all:<job>, work:<path>, import:<id>, sha256:<hex>… */
  objects: string[];
  refs: string[];
  seqs: number[];
  /** Why the group's independence or origin is not known, when it is not. */
  unknown: Unknown[];
};

/**
 * Refs grouped by the evidence objects they come from: two refs that share
 * an object are one group, however they were reached. A group is a
 * provenance group, not proof of independence: two inputs may still copy one
 * another, and that is the confidence reasoning's to weigh.
 */
export function groupByOrigin(items: Array<{ ref: string; seq: number; origin: Origin }>): CorroborationGroup[] {
  const parent = items.map((_, i) => i);
  const find = (i: number): number => (parent[i] === i ? i : (parent[i] = find(parent[i])));
  const owner = new Map<string, number>();
  items.forEach((it, i) => {
    for (const k of it.origin.keys) {
      const j = owner.get(k);
      if (j === undefined) owner.set(k, i);
      else parent[find(i)] = find(j);
    }
  });
  const groups = new Map<number, CorroborationGroup>();
  items.forEach((it, i) => {
    if (!it.origin.keys.length) return;
    const root = find(i);
    const g = groups.get(root) ?? { objects: [], refs: [], seqs: [], unknown: [] };
    for (const k of it.origin.keys) if (!g.objects.includes(k)) g.objects.push(k);
    if (!g.refs.includes(it.ref)) g.refs.push(it.ref);
    if (!g.seqs.includes(it.seq)) g.seqs.push(it.seq);
    for (const u of it.origin.unknown) if (!g.unknown.some((x) => x.text === u.text)) g.unknown.push(u);
    groups.set(root, g);
  });
  return [...groups.values()].map((g) => ({ ...g, objects: g.objects.sort(), seqs: g.seqs.sort((a, b) => a - b) })).sort((a, b) => a.objects[0].localeCompare(b.objects[0]));
}

/** The entries an entry's support comes down to: itself, or for an answer the standing entries it cites, answers followed. */
function supportLeaves(e: LedgerEntry, run: Run, seen = new Set<number>()): LedgerEntry[] {
  if (seen.has(e.seq)) return [];
  seen.add(e.seq);
  if (e.kind !== "answer") return [e];
  const out: LedgerEntry[] = [];
  for (const edge of e.support ?? []) {
    const t = run.bySeq.get(edge.seq);
    // A superseded entry explains history; it supports nothing.
    if (!t || run.replaced.has(t.seq)) continue;
    out.push(...supportLeaves(t, run, seen));
  }
  return out;
}

function groupsOf(e: LedgerEntry, run: Run): CorroborationGroup[] {
  const items = supportLeaves(e, run).flatMap((x) => (x.refs ?? []).map((ref) => ({ ref, seq: x.seq, origin: refOrigin(ref, run) })));
  return groupByOrigin(items);
}

function objectLabel(key: string): string {
  const i = key.indexOf(":");
  const kind = key.slice(0, i);
  const value = key.slice(i + 1);
  switch (kind) {
    case "input":
      return `inputs/${value}`;
    case "all":
      return `whatever job ${value} read (it declared no narrower scope)`;
    case "work":
      return `${value} (a file an agent made)`;
    case "import":
      return `import ${value}`;
    case "sha256":
      return `the object with sha256 ${value}`;
    case "job":
      return `job ${value} (no record)`;
    case "member":
      return `catalogue generation ${value}`;
    default:
      return value;
  }
}

// ---------------------------------------------------------------------------
// The page model: blocks both renderings share
// ---------------------------------------------------------------------------

type Tone = "kelp" | "saffron" | "brick" | "slate" | "moss" | "none";
export type Chip = { text: string; tone: Tone };
/**
 * A run of text. A string is words from the run (an agent's, the goal's or
 * this module's): escaped, its code spans kept, each E-<seq> linked to its
 * exhibit. The rest are code, bold, a link to an exhibit or an anchor, and a
 * chip.
 */
type Span = string | { code: string } | { b: string } | { e: number } | { a: string; text: string } | { chip: Chip } | { plain: string };
type Voice = "fact" | "interpretation" | "opinion" | "computed";
type Row = { label: string; s: Span[]; voice?: Voice };
type Block =
  | { k: "p"; s: Span[]; lede?: boolean }
  | { k: "note"; s: Span[]; draft?: boolean }
  | { k: "h"; level: 3 | 4; text: string; id?: string; chips?: Chip[] }
  | { k: "list"; items: Span[][]; ordered?: boolean }
  | { k: "rows"; rows: Row[] }
  | { k: "table"; head: string[]; rows: Span[][][]; cls?: string }
  | { k: "voice"; voice: Voice; label: string; s: Span[]; chips?: Chip[] }
  | { k: "cite"; seq: number; head: Span[]; chips: Chip[]; rows: Row[] }
  | { k: "timeline"; rows: Array<{ seq: number; when: string; what: Span[]; meta: string }> }
  | { k: "details"; summary: string; body: Block[] }
  /** HTML a caller wrote and escaped itself (ReportBodyOptions.html): in the HTML only. */
  | { k: "html"; html: string }
  | { k: "md"; text: string }
  | { k: "verbatim"; text: string }
  | { k: "box"; cls: string; id?: string; level: 3 | 4; title: Span[]; chips: Chip[]; body: Block[] };

export type BodySection = { id: string; n: string; title: string; desc: string; count?: string; blocks: Block[] };

const VOICE_LABEL: Record<Voice, string> = { fact: "Observed", interpretation: "Interpretation", opinion: "Opinion", computed: "Computed by this report" };

const plural = (n: number, one: string, many = `${one}s`) => `${n} ${n === 1 ? one : many}`;

// ---------------------------------------------------------------------------
// Entry state and chips
// ---------------------------------------------------------------------------

type EntryState = {
  hash: string;
  supersededBy: number | undefined;
  /** v2 attest acts on this entry's hash by an agent that is not its author. */
  attests: LedgerAttestation[];
  /** Attest acts by one of its own authors: listed, never counted as a check. */
  selfAttests: LedgerAttestation[];
  /** Version 1 attestations: a second agent recorded the same words (co-authorship, not a check). */
  sameContent: LedgerAttestation[];
  disputes: LedgerDispute[];
  withdrawn: Array<{ dispute: LedgerDispute; withdrawal: LedgerDispute }>;
  failed: Array<{ ref: string; job: string; status: string }>;
  groups: CorroborationGroup[];
  problems: string[];
  review: { action: string; by: string; at: string; note?: string; entry_hash?: string } | null;
  /** The trace's word on the entry's source, when the caller gave it. */
  grounding: string | undefined;
  /** Why the examiner's review could not be read, when it could not. */
  reviewUnreadable: string | undefined;
  /** The classes of material from outside the original evidence the entry rests on, when it rests on any (docs/adr/0014). */
  external: string[] | null;
  /** Its confidence as stated and as the run records it (recordedConfidence: a high stands only on an established answer another seat attested established, naming the alternatives it weighed). */
  confidence: RecordedConfidence;
};

function stateOf(e: LedgerEntry, run: Run, memo: Map<number, EntryState>): EntryState {
  const hit = memo.get(e.seq);
  if (hit) return hit;
  const hash = entryHash(e);
  const acts = run.attestations.filter((a) => (attestationAct(a) === "attest" ? a.target === hash : a.seq === e.seq));
  const attest = acts.filter((a) => attestationAct(a) === "attest");
  const withdrawn: EntryState["withdrawn"] = [];
  const raised: LedgerDispute[] = [];
  for (const d of run.disputes.filter((x) => x.target === hash)) {
    if (d.act === "dispute") raised.push(d);
    else {
      const i = raised.map((r) => r.by).lastIndexOf(d.by);
      if (i >= 0) withdrawn.push({ dispute: raised.splice(i, 1)[0], withdrawal: d });
    }
  }
  const s: EntryState = {
    hash,
    supersededBy: run.replaced.get(e.seq),
    attests: attest.filter((a) => !e.authors.includes(a.by) && a.by !== e.by),
    selfAttests: attest.filter((a) => e.authors.includes(a.by) || a.by === e.by),
    sameContent: acts.filter((a) => attestationAct(a) === "same_content"),
    disputes: run.standingD.filter((d) => d.target === hash),
    withdrawn,
    failed: run.failed.get(e.seq) ?? [],
    groups: e.kind === "answer" || e.kind === "finding" || e.kind === "absence" ? groupsOf(e, run) : [],
    problems: run.problems.get(e.seq) ?? [],
    review: run.review?.entries?.get(e.seq) ?? null,
    grounding: run.grounding[String(e.seq)],
    reviewUnreadable: run.review?.unreadable,
    external: run.contract.external?.entries.has(e.seq) ? (run.contract.external.classes.get(e.seq) ?? []) : null,
    confidence: recordedConfidence(e, run.attestations),
  };
  memo.set(e.seq, s);
  return s;
}

/** A count of entries of a kind, in words: "2 searches that found nothing". */
const KIND_PLURAL: Record<string, string> = { event: "events", ioc: "indicators", finding: "findings", absence: "searches that found nothing", hypothesis: "hypotheses", limitation: "limitations", answer: "answers", coverage: "coverage records" };
const kindCount = (kind: string, n: number) => `${n} ${n === 1 ? (kind === "absence" ? "search that found nothing" : (KIND_LABEL[kind] ?? kind)) : (KIND_PLURAL[kind] ?? `${kind}s`)}`;

const KIND_LABEL: Record<string, string> = { event: "event", ioc: "indicator", finding: "finding", absence: "searched, not found", hypothesis: "hypothesis", limitation: "limitation", answer: "answer", coverage: "coverage record" };
const KIND_TONE: Record<string, Tone> = { ioc: "saffron", finding: "kelp", event: "slate", absence: "slate", hypothesis: "none", limitation: "brick", answer: "moss", coverage: "slate" };

const interpretationMissing = (e: LedgerEntry) => e.kind === "finding" && !e.indicates && (e.v ?? 1) < 4;

/**
 * The chips of an entry, in a fixed order: what it is, how it was reached,
 * how sure, how many sources, who checked it, and what stands against it.
 */
function chipsOf(e: LedgerEntry, s: EntryState): Chip[] {
  const out: Chip[] = [{ text: KIND_LABEL[e.kind] ?? e.kind, tone: KIND_TONE[e.kind] ?? "slate" }];
  if (e.kind === "answer") out.push({ text: "opinion", tone: "saffron" });
  if (e.kind === "hypothesis") out.push({ text: `${e.status ?? "open"}: not a finding`, tone: e.status === "refuted" ? "brick" : "none" });
  if (e.basis === "observed") out.push({ text: "observed", tone: "slate" });
  if (e.basis === "inferred") out.push({ text: "inferred", tone: "saffron" });
  const conf = s.confidence.recorded;
  if (conf) out.push({ text: `${conf} confidence${s.confidence.legacy ? " (as declared)" : s.confidence.stated !== conf ? ` (stated ${s.confidence.stated})` : ""}`, tone: conf === "high" ? "moss" : conf === "medium" ? "saffron" : "none" });
  if (e.inconclusive) out.push({ text: "inconclusive", tone: "saffron" });
  if (interpretationMissing(e)) out.push({ text: "interpretation not recorded", tone: "none" });
  if (e.kind === "finding" || e.kind === "answer" || e.kind === "absence") {
    if (s.groups.length === 1) out.push({ text: "single-source", tone: "saffron" });
    else if (!s.groups.length) out.push({ text: "rests on no object of the run", tone: "brick" });
    if (s.groups.some((g) => g.unknown.some((u) => u.kind === "independence"))) out.push({ text: "independence unknown", tone: "saffron" });
    if (s.groups.some((g) => g.unknown.some((u) => u.kind === "origin"))) out.push({ text: "origin not recorded", tone: "saffron" });
  }
  if (s.failed.length) out.push(s.failed.every((f) => (e.qualifies ?? []).some((q) => q.ref === f.ref)) ? { text: "qualified (failed job)", tone: "saffron" } : { text: "from a failed job, not qualified", tone: "brick" });
  if (s.grounding === "not in the trace") out.push({ text: "not grounded in the trace", tone: "saffron" });
  if (s.external && e.kind !== "external") out.push({ text: `rests on external material${s.external.length ? ` (${s.external.map((c) => c.replace(/_/g, " ")).join(", ")})` : ""}`, tone: "saffron" });
  if (s.disputes.length) out.push({ text: "disputed", tone: "brick" });
  if (s.supersededBy !== undefined) out.push({ text: `superseded by E-${s.supersededBy}`, tone: "brick" });
  if (s.problems.length) out.push({ text: "no longer stands on its support", tone: "brick" });
  if (e.unsupported_tokens?.length) out.push({ text: "unsupported tokens", tone: "brick" });
  if (e.kind === "finding" || e.kind === "answer") {
    out.push(s.attests.length ? { text: `attested by ${[...new Set(s.attests.map((a) => a.by))].join(", ")}`, tone: "kelp" } : { text: "not attested", tone: "none" });
    out.push(reviewChip(s.review, s.reviewUnreadable));
  }
  return out;
}

/** The examiner's standing on an entry, as a chip: a human's word, never an agent's. */
function reviewChip(r: EntryState["review"], unreadable?: string): Chip {
  if (unreadable) return { text: "review unreadable", tone: "brick" };
  if (!r) return { text: "not independently reviewed", tone: "none" };
  if (r.action === "accept") return { text: "accepted by the examiner", tone: "moss" };
  if (r.action === "adopt") return { text: "adopted by the examiner", tone: "moss" };
  if (r.action === "qualify") return { text: "adopted with a qualification", tone: "saffron" };
  if (r.action === "inconclusive") return { text: "inconclusive (the examiner)", tone: "saffron" };
  if (r.action === "reject") return { text: "rejected by the examiner", tone: "brick" };
  return { text: `${r.action === "amend" ? "amended" : r.action} by the examiner`, tone: "saffron" };
}

/** The examiner's standing on an entry, in words (report.ts's reviewStatusOf): who, when, what, and against which hash. */
function reviewWords(run: Run, s: EntryState): string {
  if (run.review?.unreadable) return `the examiner's review could not be read (${run.review.unreadable})`;
  if (!run.review) return "not reviewed by an examiner";
  const r = s.review;
  if (!r) return "not reviewed";
  const verb = r.action === "accept" ? "accepted" : r.action === "adopt" ? "adopted" : r.action === "qualify" ? "adopted with a qualification" : r.action === "inconclusive" ? "rendered inconclusive" : r.action === "reject" ? "REJECTED" : r.action === "amend" ? "amended" : r.action;
  const other = r.entry_hash && r.entry_hash !== s.hash ? `; reviewed against entry hash ${r.entry_hash}, which is not this entry's` : "";
  return `${verb} by ${r.by} at ${r.at}${r.note ? `: ${r.note}` : ""}${other}`;
}

// ---------------------------------------------------------------------------
// Pieces the sections share
// ---------------------------------------------------------------------------

function whenText(e: LedgerEntry): string {
  if (!e.ts) return "undated";
  if (e.precision === "date") return `${e.ts.slice(0, 10)} (date only)`;
  const m = /^(\d{4}-\d{2}-\d{2})T(\d{2}:\d{2}:\d{2})(\.\d+)?/.exec(e.ts);
  if (!m) return e.ts;
  return `${m[1]} ${m[2]}${e.precision === "subsecond" && m[3] ? m[3] : ""}Z`;
}

/** The time as the source gave it, when that is not the UTC value stored. */
function givenTime(e: LedgerEntry): string | null {
  const raw = e.ts_raw?.trim();
  if (!raw || raw === e.ts || /[Zz]$/.test(raw)) return null;
  if (e.precision === "date" && raw === (e.ts ?? "").slice(0, 10)) return null;
  return raw;
}

/** One method record as a line: what ran, where, how it ended, what it declared it would read. */
function methodSpans(m: LedgerMethod): Span[] {
  const str = (v: unknown) => (v === undefined || v === null ? "unknown" : typeof v === "string" ? v : JSON.stringify(v));
  const out: Span[] = [];
  const who = m.job ? `job ${str(m.job)}` : m.import ? `import ${str(m.import)}` : "";
  if (m.record) return [`${who ? `${who}: ` : ""}${str(m.record)}`];
  if (m.kind === "import" || m.source !== undefined) {
    out.push(`${who ? `${who}: ` : ""}import of `, { code: str(m.source ?? "unknown") }, `, ${str(m.produced_by ?? "its producer not recorded")}${m.copied_live ? "; copied while the file was live" : ""}`);
  } else if (m.tool !== undefined) {
    out.push(`${who}: tool `, { code: str(m.tool) }, ` (sha256 ${str(m.tool_sha256)}, version ${str(m.tool_version)}) with arguments `, { code: JSON.stringify(m.args ?? {}) });
  } else if (m.recipe !== undefined) {
    out.push(`${who}: recipe `, { code: str(m.recipe) }, ` (sha256 ${str(m.recipe_sha256)}) on ${str(m.target)}`);
  } else if (m.command !== undefined) {
    out.push(`${who}: command `, { code: str(m.command) });
  } else if (Array.isArray(m.targets)) {
    out.push(`${who}: detection over ${(m.targets as unknown[]).map(str).join(", ")}`);
  } else out.push(`${who}: ${str(m.job_kind ?? m.kind)}`);
  const scope = Array.isArray(m.declared_scope) ? (m.declared_scope as unknown[]).map(str).join(", ") : str(m.declared_scope);
  out.push(`; in ${str(m.image)} (${str(m.image_digest)})${m.profile ? `, profile ${str(m.profile)}` : ""}; ended ${str(m.status)}${m.exit !== undefined ? ` (exit ${str(m.exit)})` : ""}; declared scope ${scope}; network ${str(m.network)}`);
  return out;
}

/**
 * One method record as a short line under a citation: which job, what kind
 * of work, where, how it ended, what it declared it would read. The command
 * or the arguments, whole, are in Appendix B (linked), and the record itself
 * in the entry's exhibit: a citation repeated under several answers does not
 * repeat a forty-line script each time.
 */
function methodBrief(m: LedgerMethod, run: Run): Span[] {
  const str = (v: unknown) => (v === undefined || v === null ? "unknown" : typeof v === "string" ? v : JSON.stringify(v));
  if (m.record) return [`${m.job ? `job ${str(m.job)}: ` : ""}${str(m.record)}`];
  const job = typeof m.job === "string" ? m.job : null;
  const what =
    m.kind === "import" || m.source !== undefined
      ? `an import of ${str(m.source ?? "unknown")} (${str(m.produced_by ?? "its producer not recorded")})`
      : m.tool !== undefined
        ? `tool ${str(m.tool)}, sha256 ${str(m.tool_sha256)}`
        : m.recipe !== undefined
          ? `recipe ${str(m.recipe)} on ${str(m.target)}`
          : m.command !== undefined
            ? "a shell command"
            : str(m.job_kind ?? m.kind);
  const scope = Array.isArray(m.declared_scope) ? (m.declared_scope as unknown[]).map(str).join(", ") : str(m.declared_scope);
  return [
    ...(job ? [run.jobs.has(job) ? ({ a: `#job-${job}`, text: `job ${job}` } as Span) : `job ${job}`] : m.import ? [`import ${str(m.import)}`] : []),
    `: ${what}${job && run.jobs.has(job) ? " (whole in Appendix B)" : ""}, in ${str(m.image)} (${str(m.image_digest)}); ended ${str(m.status)}; declared scope ${scope}; network ${str(m.network)}`,
  ];
}

function methodsOf(e: LedgerEntry, run: Run): { records: LedgerMethod[]; bound: boolean } {
  if (e.method?.length) return { records: e.method, bound: true };
  return { records: run.derivedMethods.get(e.seq) ?? [], bound: false };
}

/** How the objects an entry rests on were made: bound in the entry (version 4), or read from the job records now and said to be so. */
function methodRows(e: LedgerEntry, run: Run, full = false): Row[] {
  const { records, bound } = methodsOf(e, run);
  if (!records.length) return [];
  return records.map((m, i) => ({
    label: i === 0 ? (bound ? "Made by" : "Made by (job record)") : "",
    s: full ? methodSpans(m) : methodBrief(m, run),
  }));
}

function groupItems(groups: CorroborationGroup[]): Span[][] {
  return groups.map((g) => [
    g.objects.map(objectLabel).join(" + "),
    " — ",
    ...g.seqs.flatMap((n, i): Span[] => (i ? [", ", { e: n }] : [{ e: n }])),
    ` (${g.refs.map((r) => r).join(", ")})`,
    ...(g.unknown.length ? [`; ${g.unknown.map((u) => u.text).join("; ")}`] : []),
  ]);
}

function groupsSentence(groups: CorroborationGroup[]): string {
  if (!groups.length) return "0 corroboration groups: no ref names an object of the run.";
  return `${plural(groups.length, "corroboration group")} by evidence object${groups.length === 1 ? ": every ref traces to one source (single-source)" : ""}.`;
}

/** How an entry came to be, in a few words: seen, reasoned, searched, bounded, or an answer. */
function basisWords(e: LedgerEntry, run: Run): string {
  if (run.replaced.has(e.seq)) return "superseded: history only";
  if (e.kind === "answer") return `the answer to ${sectionName(e.section)}`;
  if (e.kind === "absence") return "a search that found nothing";
  if (e.kind === "limitation") return "a limitation";
  if (e.kind === "hypothesis") return "a hypothesis";
  if (e.basis === "observed") return "observed";
  if (e.basis === "inferred") return "inferred";
  return (e.v ?? 1) < 4 ? "recorded before the basis was kept" : "basis not given";
}

/** An entry, one line: its number, kind and basis, then its words. */
function citeHead(e: LedgerEntry): Span[] {
  return [{ e: e.seq }, ` · ${KIND_LABEL[e.kind] ?? e.kind}${e.kind === "answer" ? ` (${sectionName(e.section)})` : ""}: `, e.value];
}

function sectionName(section: string | undefined): string {
  if (!section) return "no section";
  if (section === "summary" || section === "narrative") return `the ${section}`;
  const id = sectionAnswersId(section);
  return /^\d/.test(id) ? `question ${id}` : `section ${id}`;
}

const questionAnchor = (id: string) => `q-${id.replace(/[^A-Za-z0-9._-]/g, "_")}`;

/** An entry cited by an answer: its words, then where it was seen, how, and by what; `brief`, its words and chips alone. */
function citeBlock(e: LedgerEntry, run: Run, memo: Map<number, EntryState>, extra: Row[] = [], brief = false): Block {
  const s = stateOf(e, run, memo);
  if (brief) return { k: "cite", seq: e.seq, head: citeHead(e), chips: chipsOf(e, s), rows: extra };
  const rows: Row[] = [];
  if (e.ts) rows.push({ label: "When", s: [`${whenText(e)}${e.clock ? `; clock: ${e.clock}` : ""}${e.precision && e.precision !== "date" ? `; precision: ${e.precision}` : ""}`] });
  if (e.source) rows.push({ label: "Where", s: [e.source] });
  if (e.evidence) rows.push({ label: "How", s: [e.evidence] });
  rows.push(...methodRows(e, run));
  if (e.locators?.length) rows.push({ label: "Located at", s: e.locators.flatMap((l, i): Span[] => [...(i ? ["; "] : []), { code: l.ref }, ` ${l.at}`]) });
  if (e.refs?.length && !methodsOf(e, run).records.length) rows.push({ label: "Rests on", s: e.refs.flatMap((r, i): Span[] => [...(i ? [", "] : []), { code: r }]) });
  rows.push(...extra);
  return { k: "cite", seq: e.seq, head: citeHead(e), chips: chipsOf(e, s), rows };
}

// ---------------------------------------------------------------------------
// The sections
// ---------------------------------------------------------------------------

function standingAnswer(run: Run, section: string): LedgerEntry | null {
  return run.entries.filter((e) => e.kind === "answer" && e.section === section && !run.replaced.has(e.seq)).at(-1) ?? null;
}

function answerHistory(run: Run, section: string): LedgerEntry[] {
  return run.entries.filter((e) => e.kind === "answer" && e.section === section);
}

/** A question's status in a few words, with the chips that say why. */
function questionStatus_(q: Question, run: Run, memo: Map<number, EntryState>): { status: Chip; answer: LedgerEntry | null; chips: Chip[] } {
  const a = standingAnswer(run, `question:${q.id}`);
  if (!a) return { status: run.era === "predates" ? { text: "no structured answer", tone: "none" } : { text: "not answered", tone: "brick" }, answer: null, chips: [] };
  const s = stateOf(a, run, memo);
  const result = answerResult(a);
  const negative = result && NEGATIVE_RESULTS.has(result) ? negativeReview(a, run.entries, run.attestations, run.disputes) : null;
  const status: Chip = s.problems.length
    ? { text: "no longer stands on its support", tone: "brick" }
    : s.disputes.length
      ? { text: "disputed", tone: "brick" }
      : negative && !negative.reviewed && run.bar(q.id).material
        ? { text: "negative (unreviewed)", tone: "brick" }
        : a.inconclusive || result === "not_determinable"
          ? { text: result ? "not determinable" : "inconclusive", tone: "saffron" }
          : result === "bounded_negative"
            ? { text: "no evidence found (bounded negative)", tone: "saffron" }
            : result === "partial" || result === "out_of_scope"
              ? { text: resultWords(result), tone: "saffron" }
              : result === "premise_not_supported"
                ? { text: "premise not supported", tone: "moss" }
                : { text: "answered", tone: "moss" };
  return { status, answer: a, chips: chipsOf(a, s).filter((c) => c.text !== "answer" && c.text !== "opinion" && c.text !== status.text) };
}

function legendBlocks(run: Run): Block[] {
  return [
    ...(run.draft
      ? [
          {
            k: "note",
            draft: true,
            s: [
              { b: "DRAFT." },
              ` No release v1 exists for this run: this is a working render of what the ledger holds now, not an adopted report.${run.review?.signed || run.review?.entries?.size || run.review?.unreadable ? "" : " No human has reviewed it."}`,
            ],
          } as Block,
        ]
      : []),
    { k: "h", level: 3, text: "How to read this report" },
    {
      k: "p",
      s: [
        "Each answer in §5 leads with the answer in plain words, then says how it was obtained, what it indicates, why that confidence, what else could explain it, what speaks against it, what limits it and what would change it; the technical detail follows, and every claim cites an exhibit by its number (an E and the entry's number in the ledger), whole in Appendix A. Four kinds of sentence are set apart:",
      ],
    },
    {
      k: "rows",
      rows: [
        { label: "Observed", voice: "fact", s: ["what an agent saw in the evidence, with where and how."] },
        { label: "Interpretation", voice: "interpretation", s: ["what an agent says the observation means, and the step from one to the other."] },
        { label: "Opinion", voice: "opinion", s: ["a conclusion the swarm draws from several entries: an answer, a summary, a significance."] },
        { label: "Computed", voice: "computed", s: ["what this report worked out from the ledger itself, such as how many independent-looking sources an answer has."] },
      ],
    },
    {
      k: "list",
      items: [
        [{ chip: { text: "observed", tone: "slate" } }, " ", { chip: { text: "inferred", tone: "saffron" } }, " seen in the evidence, or reasoned from it."],
        [{ chip: { text: "single-source", tone: "saffron" } }, " every object the entry rests on comes from one evidence object: three outputs of one disk image are one source."],
        [{ chip: { text: "independence unknown", tone: "saffron" } }, " ", { chip: { text: "origin not recorded", tone: "saffron" } }, " a job that could read every input rests on whatever it read; a file an agent made, or imported, has no recorded origin."],
        [{ chip: { text: "not attested", tone: "none" } }, " no agent other than its author re-derived it from the sealed objects."],
        [{ chip: { text: "not independently reviewed", tone: "none" } }, " no human has checked it. An agent's attestation is not peer review."],
        [{ chip: { text: "disputed", tone: "brick" } }, " an agent says why it does not hold, and has not withdrawn that."],
        [{ chip: { text: "qualified (failed job)", tone: "saffron" } }, " it rests on the kept output of a job that did not succeed, and says why those bytes still hold."],
        [{ chip: { text: "superseded", tone: "brick" } }, " a later entry corrects it; it is kept as it was recorded and supports nothing."],
        [{ chip: { text: "unsupported tokens", tone: "brick" } }, " a hash, path, time, address or account in an answer that none of the entries it cites holds."],
        [{ chip: { text: "interpretation not recorded", tone: "none" } }, " the finding was recorded before findings said what they indicate."],
      ],
    },
  ];
}

function summarySection(run: Run, memo: Map<number, EntryState>): BodySection {
  const blocks: Block[] = [];
  const summary = standingAnswer(run, "summary");
  if (summary) {
    const s = stateOf(summary, run, memo);
    blocks.push({ k: "voice", voice: "opinion", label: "Summary", s: [summary.value], chips: chipsOf(summary, s).filter((c) => c.text !== "answer") });
    if (summary.confidence) blocks.push({ k: "p", s: [{ b: `Confidence ${summary.confidence}. ` }, summary.confidence_why ?? "The reason was not recorded."] });
    blocks.push({ k: "voice", voice: "interpretation", label: "The author's reasoning", s: [summary.reasoning ?? ""] });
    if (s.problems.length) blocks.push(problemNote(summary, s, run));
    if (summary.unsupported_tokens?.length) blocks.push(tokensNote(summary));
  } else if (run.hasAnswers) {
    blocks.push({ k: "note", s: ["The swarm recorded no summary. The status of each question follows; the answers are in §5."] });
  } else if (run.era === "empty") {
    blocks.push({ k: "note", s: ["The swarm recorded no findings and no answers: nothing was written to the ledger, so this report has no conclusions to carry. That is not the same as finding nothing; §8 says what limited the run."] });
  } else if (run.era === "no answers") {
    blocks.push({ k: "note", s: ["The swarm recorded no answers: the ledger holds what it found (Appendix A), and no answer to any question drawn from it. Its working report (Appendix C) is its prose, which the ledger does not check."] });
  } else {
    blocks.push({
      k: "note",
      s: [
        "This run predates structured answers (ledger version 4): the swarm's conclusions exist only in its working report (Appendix C), which the ledger does not check. What follows is what the ledger holds for each question.",
      ],
    });
  }
  const chains = chainQuestions(run);
  if (chains.length) {
    // One screen: each question's standing, who asked it, its answer by number, its leads, its acceptance and its cost; the words are in §2 and §5.
    blocks.push({ k: "h", level: 3, text: "Each question" });
    blocks.push({
      k: "table",
      cls: "status",
      head: ["Question", "Status", "Asked by", "Answer", "Leads", "Accepted", "Tokens"],
      rows: chains.map((c): Span[][] => {
        const st = chainStatus(c, run, memo);
        const g = groupOf(c);
        const state: Chip | null = g === "proposed" || g === "excluded" || g === "withdrawn" ? { text: g === "proposed" ? "proposed, not admitted" : g, tone: g === "withdrawn" ? "brick" : "saffron" } : null;
        const leads = leadsFor(run, c.key);
        const tally = new Map<string, number>();
        for (const l of leads) tally.set(l.disposition ?? l.status, (tally.get(l.disposition ?? l.status) ?? 0) + 1);
        const named = st.answer ? [] : run.entries.filter((e) => !run.replaced.has(e.seq) && (e.answers ?? []).some((x) => sectionKey(x) === c.key));
        const ans = st.answer ? answerResult(st.answer) : null;
        // A partial answer's parts (docs/adr/0013, "What the report shows of an answer's parts"): the plain line, and beside the label when every asked part is established.
        const standing = st.answer && ans === "partial" ? partsOf(st.answer, run) : null;
        const plain = partialPlainWords(ans, standing);
        return [
          [c.q ? { a: `#${questionAnchor(c.q.id)}`, text: questionName(c.q) } : { a: `#${chainAnchor(chainName(c))}`, text: chainName(c) }],
          [{ chip: state ?? st.status }, ...(plain && !state ? [` ${plain}`] : []), ...(c.v?.answer?.stale ? [" ", { chip: { text: "stale", tone: "brick" } } as Span] : []), ...(c.v?.must_establish?.required ? [" ", { chip: { text: "must be established", tone: "saffron" } } as Span] : [])],
          [...(c.v ? [`${c.v.id} · `] : []), ...askerSpans(c.v, c.q)],
          st.answer ? [{ e: st.answer.seq }, ` ${ans ? resultWords(ans) : st.answer.inconclusive ? "inconclusive" : "no result stated"}`, ...(standing ? [`. ${partsSummaryWords(standing)}`] : [])] : named.length ? [`none; ${plural(named.length, "entry", "entries")}: `, ...named.flatMap((e, i): Span[] => [...(i ? [", " as Span] : []), { e: e.seq }])] : ["none"],
          [leads.length ? `${leads.length}: ${[...tally].map(([k, n]) => `${n} ${k}`).join(", ")}` : "0"],
          [c.v?.accepted ? `${c.v.accepted.as === "bounded" ? "bounded" : "not determinable"}${c.v.accepted.stands ? "" : " (lifted)"}` : "—"],
          [run.cost && run.cost.source !== "none" ? `${(run.cost.shown.byQuestion.get(costKey(c)) ?? 0).toLocaleString("en-US")}${run.cost.source === "trace" ? " (est.)" : ""}` : "—"],
        ];
      }),
    });
    blocks.push({ k: "p", s: ["Each question's chain (who asked it, every revision, the leads that worked it, the result, the acceptance and how the tokens are counted) is in ", { a: "#chains", text: "§2" }, "; each answer, with how it was reached, in §5; the whole register in Appendix F."] });
    const held = mustEstablishWords(chains.map((c) => c.v).filter((v): v is QuestionView => Boolean(v)));
    if (held) blocks.push({ k: "p", s: held });
  }
  const narrative = standingAnswer(run, "narrative");
  if (narrative) blocks.push({ k: "p", s: ["What happened, in order, is in §6 (", { e: narrative.seq }, ")."] });
  blocks.push({ k: "p", s: [reviewSentence(run)] });
  return { id: "s1", n: "1", title: "Summary for decision makers", desc: "the answer in brief, and where each question stands", blocks };
}

/**
 * What the run was held to (docs/adr/0013, "A question that must be
 * established"): each question required, by whom and why, and each
 * requirement released, by whom, when and why. Null when the run required
 * nothing.
 */
export function mustEstablishWords(views: readonly QuestionView[]): Span[] | null {
  const required = views.filter((v) => v.must_establish?.required);
  const released = views.filter((v) => v.must_establish && !v.must_establish.required);
  if (!required.length && !released.length) return null;
  const out: Span[] = [{ b: "Must be established. " }];
  if (required.length) {
    out.push(`${required.length === 1 ? "This question was" : "These questions were"} required to be established: only an answer that answers ${required.length === 1 ? "it" : "each"} ends the run on it, or the operator's acceptance of its limits. `);
    out.push(required.map((v) => `${v.id} (required by ${originWords(v.must_establish!.origin)}${v.must_establish!.why ? `: ${v.must_establish!.why}` : ""})`).join("; "));
    out.push(released.length ? ". " : ".");
  } else out.push("No question is required to be established now. ");
  if (released.length) {
    out.push(`The requirement was released on ${released.length === 1 ? "one question" : `${released.length} questions`}: `);
    out.push(released.map((v) => `${v.id}, by ${originWords(v.must_establish!.origin)} at ${v.must_establish!.at}${v.must_establish!.why ? ` (${v.must_establish!.why})` : ""}`).join("; "));
    out.push(".");
  }
  return out;
}

function questionName(q: Question): string {
  return /^\d/.test(q.id) ? `Question ${q.id}` : /^recommendations?$/i.test(q.id) ? "Recommendations" : `Section ${q.id}`;
}

function reviewSentence(run: Run): string {
  const r = run.review;
  if (r?.unreadable) return `Prepared by an AI agent swarm. The examiner's review could not be read (${r.unreadable}), so this document cannot say whether anything in it was reviewed.`;
  if (r?.signed && r.signed.current === false) return `Prepared by an AI agent swarm. An examiner signed off (${r.signed.by}, ${r.signed.at}), and the sign-off does not cover this run as it stands${r.signed.scope ? `: ${r.signed.scope}` : ""}. What changed since is the swarm's (§10).`;
  if (r?.signed) return `Prepared by an AI agent swarm and signed by ${r.signed.by} at ${r.signed.at}; §10 says what the examiner adopted. An answer the examiner did not review is still the swarm's.`;
  if (r?.entries?.size) return "Prepared by an AI agent swarm. An examiner has reviewed some entries and has not signed; §10 says which. An entry not reviewed is the swarm's.";
  return "Prepared by an AI agent swarm. No human has reviewed it: every answer here is the swarm's until an examiner adopts it (§10).";
}

function problemNote(a: LedgerEntry, s: EntryState, run: Run): Block {
  const named = run.entries.filter((l) => l.kind === "limitation" && !run.replaced.has(l.seq) && limitationCites(l).has(a.seq));
  return {
    k: "note",
    s: [
      { b: "It no longer stands on its support: " },
      s.problems.join("; "),
      ". ",
      ...(named.length
        ? ["A limitation names this (", ...named.flatMap((l, i): Span[] => [...(i ? [", "] : []), { e: l.seq }]), "): ", named.map((l) => l.value).join("; "), ". A limitation lets the run end; it does not make the answer supported."]
        : ["No limitation names it."]),
    ],
  };
}

function tokensNote(a: LedgerEntry): Block {
  return {
    k: "note",
    s: [
      { b: "Unsupported tokens: " },
      "these specifics in the answer are in none of the entries it cites: ",
      ...(a.unsupported_tokens ?? []).flatMap((t, i): Span[] => [...(i ? [", "] : []), { code: t }]),
      ". The check finds omissions, not entailment: a token found is not a token proved.",
    ],
  };
}

function requestSection(run: Run, memo: Map<number, EntryState>): BodySection {
  const blocks: Block[] = [];
  const g = run.goal;
  if (g) {
    if (g.caseLine) blocks.push({ k: "p", s: [g.caseLine] });
    blocks.push({ k: "p", lede: true, s: ["What was asked, in the goal's own words (from SWARM.md):"] });
    blocks.push({ k: "md", text: g.request || "(the goal states no request before its questions)" });
  } else {
    blocks.push({ k: "note", s: ["The run's goal (SWARM.md) was not found in the sandbox: the questions below are the sections the ledger's answers and entries name, without the goal's wording."] });
  }
  blocks.push({ k: "h", level: 3, text: "The questions" });
  if (run.questions.length) {
    blocks.push({
      k: "list",
      items: run.questions.map((q) => [{ b: `${questionName(q)}. ` }, q.text ?? (q.fromGoal ? "" : "not among the goal's numbered questions: a section the ledger names"), " — ", { a: `#${questionAnchor(q.id)}`, text: "answer in §5" }]),
    });
  } else blocks.push({ k: "note", s: ["The goal numbers no questions, and no entry names one."] });
  if (g?.caps.length) {
    blocks.push({ k: "h", level: 3, text: "The limits the run worked within" });
    blocks.push({ k: "list", items: g.caps.map((c) => [c]) });
  }
  // Each question, from who asked it to what it cost (docs/adr/0016): before the evidence and the method, as the first layer; the whole register is Appendix F.
  blocks.push(...chainBlocks(run, memo));
  return { id: "s2", n: "2", title: "Request, scope and questions", desc: "what was asked, by whom, and how each question was examined", blocks };
}

// ---------------------------------------------------------------------------
// The questions one by one (§2), and the whole register (Appendix F)
// ---------------------------------------------------------------------------

const chainAnchor = (id: string) => `qc-${id.replace(/[^A-Za-z0-9._-]/g, "_")}`;

/** A question the chains show: its register view when the register holds it, and the report's own record of it when the report asks it. */
type ChainQ = { key: string; q: Question | null; v: QuestionView | null };

/** Every question, once: the register's (a person's first, then the goal's, then the agents'), then any the report asks that the register does not hold. */
function chainQuestions(run: Run): ChainQ[] {
  const out: ChainQ[] = [];
  const seen = new Set<string>();
  for (const v of run.register?.views ?? []) {
    const key = sectionKey(v.section);
    out.push({ key, q: run.questions.find((x) => x.id === key) ?? null, v });
    seen.add(key);
  }
  for (const q of run.questions) if (!seen.has(q.id)) out.push({ key: q.id, q, v: null });
  return out;
}

type ChainGroup = "original" | "asked" | "emergent" | "proposed" | "excluded" | "withdrawn";

function groupOf(c: ChainQ): ChainGroup {
  if (c.v?.withdrawn) return "withdrawn";
  if (c.v?.scope === "excluded") return "excluded";
  if (c.v?.scope === "proposed") return "proposed";
  if (c.v ? c.v.origin.kind === "goal" : c.q?.fromGoal) return "original";
  if (c.v && ["analyst", "reviewer", "observer"].includes(c.v.origin.kind)) return "asked";
  return "emergent";
}

const chainName = (c: ChainQ) => c.v?.id ?? (c.q ? questionName(c.q) : c.key);

/** Where a question stands, as §1 and §5 say it; a question the report does not ask is read from its section all the same. */
function chainStatus(c: ChainQ, run: Run, memo: Map<number, EntryState>): { status: Chip; answer: LedgerEntry | null } {
  const st = questionStatus_(c.q ?? { id: c.key, text: c.v?.text ?? null, fromGoal: false }, run, memo);
  return { status: st.status, answer: st.answer };
}

/** The settled standings: an answer that answers the question, or says its premise is not supported. */
const SETTLED = new Set(["answered", "premise not supported"]);

/** Who asked, in a few words: the goal, an agent and the entry it came from, or a person with their role, claimed or signed. */
function askerSpans(v: QuestionView | null, q: Question | null): Span[] {
  if (!v) return [q?.fromGoal ? "the goal (the register holds no record of it)" : "a section the ledger names (the register holds no record of it)"];
  const o = v.origin;
  if (o.kind === "goal") return ["the goal"];
  if (o.kind === "agent") {
    const src = /^E-(\d+)$/.exec(o.source_entry ?? "")?.[1];
    return [`agent ${o.agent ?? "?"}`, ...(src ? [", from ", { e: Number(src) } as Span] : o.source_entry ? [`, from ${o.source_entry}`] : [])];
  }
  return [originWords(o)];
}

/** The key each question is costed under (question-cost.ts's questionsOf): its register id, else its section. */
const costKey = (c: ChainQ) => c.v?.id ?? `question:${c.key}`;

/** Tokens given to a question, and its share of the run's, as whole numbers that conserve the total. */
function costWords(run: Run, c: ChainQ): string {
  const cost = run.cost;
  if (!cost || cost.source === "none") return "not known (no token record)";
  const n = cost.shown.byQuestion.get(costKey(c)) ?? 0;
  const pct = cost.shown.total ? ` (${((n / cost.shown.total) * 100).toFixed(1)}% of the run's ${tokensWords(cost.shown.total)})` : "";
  return `${tokensWords(n)}${pct}${cost.source === "trace" ? ", estimated" : ""}`;
}

/** The leads that work a question: every lead naming its section. */
function leadsFor(run: Run, key: string): LeadView[] {
  return (run.leads?.views ?? []).filter((l) => l.answers.some((a) => sectionKey(a) === key)).sort((a, b) => a.opened_at.localeCompare(b.opened_at) || a.id.localeCompare(b.id));
}

/** Who held a lead, in order, from its events: each claim (or an open taken at once) with the seat and when. */
function holdersOf(run: Run, lead: string): string[] {
  return run.leadEvents.filter((e) => e.lead === lead && ((e.ev === "open" && e.holder) || e.ev === "claim")).map((e) => `${e.holder ?? e.by} from ${e.at}`);
}

/** Whether a drop or a deferral was reviewed: by an agent other than the one who closed it, attesting or disputing the entry it cites. */
function dropReview(run: Run, x: LeadView): Span[] {
  if (!x.disposition || !DROPS.has(x.disposition)) return [];
  const m = x.ref ? /^E-(\d+)$/.exec(x.ref) : null;
  if (!m) return [" Review: not reviewable by an attestation (", x.disposition === "duplicate" ? "a duplicate cites a lead" : "an operator request cites no entry", ")."];
  const e = run.bySeq.get(Number(m[1]));
  if (!e) return [" Review: the entry it cites is not in the ledger."];
  const target = e.hash ?? ledgerHash(e, "genesis");
  const att = run.attestations.filter((a) => attestationAct(a) === "attest" && a.target === target && a.by !== x.closed_by && !e.authors.includes(a.by)).map((a) => a.by);
  const dis = run.disputes.filter((d) => d.act === "dispute" && d.target === target).map((d) => d.by);
  if (!att.length && !dis.length) return [" Review: ", { b: "not reviewed" }, ": no agent other than the one who closed it attested or disputed what it cites."];
  return [` Review: ${[att.length ? `attested by ${[...new Set(att)].join(", ")}` : "", dis.length ? `disputed by ${[...new Set(dis)].join(", ")}` : ""].filter(Boolean).join("; ")}.`];
}

/**
 * What coordination did with a lead (docs/adr/0015), from its events: each
 * offer (why it was made, to whom, and what became of it: accepted by the
 * claim that names it, declined, lapsed, taken by another seat, or still
 * open), each hand-off, and a parked lead taken over.
 */
export function leadCoordination(events: readonly LeadEvent[], lead: string): string[] {
  const ev = events.filter((e) => e.lead === lead);
  const out: string[] = [];
  for (const [i, e] of ev.entries()) {
    if (e.ev === "handoff") out.push(`handed off by ${e.by} at ${e.at}${e.to ? ` to ${e.to}` : ""}${e.why ? ` (${e.why})` : ""}`);
    else if (e.ev === "claim" && e.cause === "parked") out.push(`taken over from ${e.from ?? "its holder"} by ${e.holder ?? e.by} at ${e.at}, parked (held with no act while its holder worked elsewhere)`);
    else if ((e.ev as string) === "offer") {
      let outcome = "still open when the run ended";
      for (const x of ev.slice(i + 1)) {
        if ((x.ev === "claim" || (x.ev as string) === "confirm") && x.offer === e.seq) outcome = `accepted by ${x.holder ?? x.by} at ${x.at}`;
        else if ((x.ev as string) === "offer_decline" && x.offer === e.seq) outcome = `declined at ${x.at}${x.why ? ` (${x.why})` : ""}`;
        else if ((x.ev as string) === "offer_lapse" && x.offer === e.seq) outcome = `lapsed at ${x.at}${x.why ? ` (${x.why})` : ""}`;
        else if (x.ev === "claim") outcome = `taken by ${x.holder ?? x.by} at ${x.at}, not by the offer`;
        else continue;
        break;
      }
      out.push(`offered to ${e.to ?? "?"} at ${e.at} (${e.reason ?? "wake"}${e.from ? `, from ${e.from}` : ""}): ${outcome}`);
    }
  }
  return out;
}

/** One lead, whole: what it was for, its plan, its jobs, how it ended and on what, whether that was reviewed, and what happened to it since. */
function leadLineOf(run: Run, x: LeadView): Span[] {
  const m = x.ref ? /^E-(\d+)$/.exec(x.ref) : null;
  const ended: Span[] = x.disposition
    ? [` Ended ${x.disposition}`, ...(x.closed_by ? [` (${x.closed_by})`] : []), ": ", ...(m ? [{ e: Number(m[1]) } as Span] : [x.ref ?? ""]), x.close_why ? ` (${x.close_why})` : "", "."]
    : [` Not ended: ${x.status}${x.holder ? `, held by ${x.holder}` : ", held by nobody"}${x.needs.some((n) => !n.met) ? `, waiting on ${x.needs.filter((n) => !n.met).map((n) => n.need).join(", ")}` : ""}${x.material ? "" : " (not material)"}.`];
  const reopened: Span[] = x.reopened.length ? [` Reopened ${plural(x.reopened.length, "time")}: ${x.reopened.map((r) => `${r.cause}, ${r.why}`).join("; ")}.`] : [];
  const notes: Span[] = x.notes.length ? [` The operator: ${x.notes.map((n) => `${n.text}${n.allow_host ? ` (allowed ${n.allow_host})` : ""}`).join("; ")}.`] : [];
  const routes: Span[] = x.routes?.length ? [` Routes planned: ${x.routes.map((r) => `${r.source} (${r.method})`).join("; ")}.`] : [];
  const notExamined: Span[] = x.not_examined?.length ? [` Planned, not examined at its close: ${x.not_examined.map((r) => `${r.source} (${r.method}): ${r.why}`).join("; ")}.`] : [];
  const quick: Span[] = x.quick_negative ? [{ b: " Quick negative:" }, ` closed ${Math.round(x.quick_negative.held_ms / 1000)} s after it was taken, on ${plural(x.quick_negative.jobs, "job")} over ${plural(x.quick_negative.objects, "object")}; a cue for review, not a refusal.`] : [];
  // The product contract a prerequisite delivers (A2), and what it delivered at its close.
  const product: Span[] = x.product ? [` Product: ${x.product}${x.acceptance ? `; accepted when: ${x.acceptance}` : ""}${x.next_action ? `; next: ${x.next_action}` : ""}.`, ...(x.result_refs?.length ? [" Delivered: ", ...x.result_refs.flatMap((r, i): Span[] => [...(i ? [", "] : []), /^E-\d+$/.test(r) ? { e: Number(r.slice(2)) } : { code: r }]), "."] : [])] : [];
  // A limiting close reviewed by another seat (B3/A4): whether the route it could not take still matters.
  const reviews: Span[] = x.route_reviews?.length ? [` Route reviewed: ${x.route_reviews.map((r) => `by ${r.by} at ${r.at}, ${r.material ? "still material" : "no longer material"}: ${r.why}`).join("; ")}.`] : [];
  const confirm: Span[] = [...(x.confirmed?.length ? [` Closure confirmed: ${x.confirmed.map((c) => `by ${c.by} at ${c.at} (from ${c.from} to ${c.to}): ${c.why}`).join("; ")}.`] : []), ...(x.confirm ? [{ b: " Closure waiting for its closer's confirmation" } as Span, `: it was closed on ${x.confirm.ref_was}, superseded since${x.confirm.head ? ` (the entry that stands: ${x.confirm.head})` : ""}.`] : [])];
  const coordination = leadCoordination(run.leadEvents, x.id);
  const coord: Span[] = coordination.length ? [` Coordination: ${coordination.join("; ")}.`] : [];
  return [{ b: `${x.id} ` }, x.title, `: ${x.why}${/[.!?]$/.test(x.why) ? "" : "."}`, ...routes, ...product, ...(x.jobs.length ? [` Jobs: ${x.jobs.join(", ")}.`] : []), ...ended, ...notExamined, ...quick, ...dropReview(run, x), ...reviews, ...confirm, ...reopened, ...notes, ...coord];
}

/** The provenance of a question's attachment: the material it was sealed as, or the external entry that recorded it, or none named. */
function attachmentSpans(run: Run, qid: string, ref: string): Span[] {
  const imp = /^import:([a-z]+-\d+)/.exec(ref)?.[1];
  const m = imp ? run.contract.material.find((x) => x.import === imp) : undefined;
  if (m) {
    const files = (m.files as Array<{ path: string; sha256: string }> | undefined) ?? [];
    return [{ code: ref }, `: ${String(m.class ?? "material").replace(/_/g, " ")}, supplied by ${String(m.supplied_by ?? "?")} at ${String(m.at ?? "?")} from ${String(m.from ?? "?")}; permitted use ${String(m.permitted_use ?? "?")}; ${files.map((f) => `${f.path} sha256 ${f.sha256}`).join(", ") || "no file listed"}; why: ${String(m.why ?? "")}`];
  }
  const e = run.entries.find((x) => x.kind === "external" && (x.provenance as Record<string, unknown> | undefined)?.question === qid && x.value.includes(ref));
  if (e?.provenance) return [{ code: ref }, `: recorded as external material (`, { e: e.seq }, `), supplied by ${e.provenance.supplied_by} at ${e.provenance.at} from ${e.provenance.from}${e.provenance.sha256 ? `, sha256 ${e.provenance.sha256}` : ""}; permitted use ${e.provenance.permitted_use}`];
  return [{ code: ref }, ": an object of the run; no supplied material names it"];
}

/** One question's chain: who asked it and why, every revision, what came with it, the proposition tested, the leads, the result, the acceptance and the cost. */
function chainBlock(c: ChainQ, run: Run, memo: Map<number, EntryState>, limits: LedgerEntry[]): Block {
  const v = c.v;
  const st = chainStatus(c, run, memo);
  // A question not in the run's work (proposed, excluded, withdrawn) says where it stands; its answer's standing only when it has one.
  const outside = ["proposed", "excluded", "withdrawn"].includes(groupOf(c));
  const rows: Row[] = [];
  rows.push({ label: "Asked by", s: askerSpans(v, c.q) });
  // A goal question the register never wrote: derived from the goal as this is read, so it has no time of its own.
  const derived = Boolean(v && run.register && v.revisions[0] && v.revisions[0].seq > run.register.persisted);
  const when = (at: string) => (derived ? "the goal's (derived, never written)" : at);
  if (v) {
    rows.push({ label: "When", s: [derived ? "the goal's question: the register never wrote it, and it is read from the goal as this is rendered" : `${v.opened_at}${v.opened_by && v.opened_by !== "system" ? ` (recorded by ${v.opened_by})` : ""}`] });
    rows.push({ label: "Why", s: [v.why || (v.origin.kind === "goal" ? "the goal asks it" : "not given")] });
    const objective = v.objective ? run.register?.snap.state.objectives.get(v.objective) : null;
    if (v.objective || v.parent) rows.push({ label: "Under", s: [[v.objective ? `objective ${v.objective}${objective?.text ? `: ${objective.text}` : ""}` : "", v.parent ? `question ${v.parent}` : ""].filter(Boolean).join("; ")] });
    rows.push({ label: "Weight", s: [`${v.materiality}; priority ${v.priority}${v.priority_reason ? ` (${v.priority_reason})` : ""}${v.expects ? `; expects ${v.expects}` : ""}${v.deadline ? `; deadline ${v.deadline}` : ""}${v.suggested_to ? `; suggested to ${v.suggested_to}` : ""}`] });
    for (const r of v.revisions) rows.push({ label: r === v.revisions[0] ? "Revisions" : "", s: [`r${r.rev}, ${when(r.at)}, by ${originWords(r.origin)}${r.why ? ` (${r.why})` : ""}: `, { b: r.text }] });
    if (v.neutral) rows.push({ label: "Neutral formulation", s: [`${v.neutral.text} (by ${originWords(v.neutral.origin)} at ${v.neutral.at}, for r${v.neutral.rev})`] });
    if (v.leading_forms.length) rows.push({ label: "Leading form", s: [`worded as a conclusion to reach (${v.leading_forms.join(", ")}): flagged for the critic, tested as a proposition`] });
    for (const [i, s] of v.scope_history.entries()) {
      const who = s.origin ? originWords(s.origin) : "";
      rows.push({ label: i ? "" : "Scope", s: [`${s.scope.replace(/_/g, " ")} at ${i ? s.at : when(s.at)}${who && !s.why.includes(who) ? ` by ${who}` : ""}${s.why ? `: ${s.why}` : ""}`] });
    }
    const hypotheses = v.delivered.flatMap((d) => d.hypotheses);
    for (const [i, h] of v.hints.entries()) rows.push({ label: i ? "" : "Hints", s: [{ code: h.ref }, h.value ? ` — says: ${h.value}` : "", ...(h.value && hypotheses.length ? [" (recorded as a hypothesis in the asker's name: ", ...hypotheses.flatMap((n, j): Span[] => [...(j ? [", "] : []), { e: n }]), ")"] : [])] });
    for (const [i, a] of v.attachments.entries()) rows.push({ label: i ? "" : "Attachments", s: attachmentSpans(run, v.id, a) });
    for (const [i, cl] of v.clarifications.entries()) rows.push({ label: i ? "" : "Clarifications", s: [`${cl.id}: ${cl.by} asked ${cl.to ? `${cl.to} ` : ""}at ${cl.at}: ${cl.what}. `, cl.answer ? `Answered by ${cl.answer.origin ? originWords(cl.answer.origin) : cl.answer.by} at ${cl.answer.at}: ${cl.answer.text}` : { b: "Not answered." }] });
    if (v.signed.length) rows.push({ label: "Signed", s: [v.signed.map((x) => `event ${x.act_seq} by ${x.person} (key ${x.fingerprint})`).join("; ")] });
    // Its offers to a seat (docs/adr/0015), as the register wrote them: when each reached its seat, and whether it was taken.
    for (const [i, o] of v.offers.entries()) rows.push({ label: i ? "" : "Offered", s: [`to ${o.to} at ${o.at} for r${o.rev}${o.first ? " (the suggested seat first)" : ""}${o.why ? `, ${o.why}` : ""}: ${o.accepted ? `accepted at ${o.accepted.at}` : o.declined ? `declined at ${o.declined.at}${o.declined.why ? ` (${o.declined.why})` : ""}` : o.seen_at ? `seen at ${o.seen_at}, not taken up` : "not seen by its seat"}`] });
    for (const [i, ev] of v.evidence.entries()) rows.push({ label: i ? "" : "Evidence added", s: [`import:${ev.import} at ${ev.at}${ev.request ? ` for ${ev.request}` : ""}${ev.inventory_rev !== null ? `, inventory revision ${ev.inventory_rev}` : ""}: what was concluded before it is recorded again`] });
    if (v.withdrawn) rows.push({ label: "Withdrawn", s: [`by ${originWords(v.withdrawn.origin)} at ${v.withdrawn.at}: ${v.withdrawn.why}`] });
    if (v.after_done) rows.push({ label: "After the done", s: ["asked after the run's done: a follow-up a resume takes up"] });
  } else if (c.q?.text) rows.push({ label: "Question", s: [c.q.text] });
  const leads = leadsFor(run, c.key);
  // The proposition tested: the first lead under the question that stated one.
  const framed = leads.find((l) => l.proposition);
  rows.push({ label: "Proposition tested", s: framed ? [`${framed.proposition}; its negation: ${framed.negation ?? "not stated"} (${framed.id})`] : [v && ["analyst", "reviewer", "observer"].includes(v.origin.kind) ? "no lead stated one (a person's question is tested as a proposition and its negation)" : "none stated: the question was worked as asked"] });
  // What the question takes as happened (docs/adr/0011, "What a question presumes"): its answer tests it first.
  if (v?.presumption) rows.push({ label: "Presumes", s: [`${presumptionWords(v.presumption)}: its answer tests that premise first, against "the question's premise is not supported"`] });
  const body: Block[] = [{ k: "rows", rows }];
  // The leads: whole, except the negatives and the duplicates, counted here and listed whole in Appendix F.
  const negatives = leads.filter((l) => l.disposition === "negative");
  const duplicates = leads.filter((l) => l.disposition === "duplicate");
  const shown = leads.filter((l) => l.disposition !== "negative" && l.disposition !== "duplicate");
  body.push({ k: "p", s: [{ b: `Leads (${leads.length})` }] });
  if (!leads.length) body.push({ k: "p", s: ["No lead names this question."] });
  if (shown.length) body.push({ k: "list", items: shown.map((x) => [...leadLineOf(run, x), ...(holdersOf(run, x.id).length ? [` Held by ${holdersOf(run, x.id).join("; ")}.`] : [])]) });
  if (negatives.length) {
    const quick = negatives.filter((l) => l.quick_negative).length;
    const unreviewed = negatives.filter((l) => dropReview(run, l).some((sp) => typeof sp === "object" && "b" in sp && sp.b === "not reviewed")).length;
    body.push({ k: "p", s: [`${plural(negatives.length, "lead")} closed negative (${quick} quick, ${unreviewed} not reviewed by another agent): `, ...negatives.flatMap((l, i): Span[] => [...(i ? [", "] : []), { a: `#reg-${l.id}`, text: l.id }]), ", each whole in Appendix F."] });
  }
  if (duplicates.length) body.push({ k: "note", s: [`Duplicates: ${duplicates.map((l) => `${l.id} (of ${l.ref ?? "?"}${l.closed_by ? `, closed by ${l.closed_by}` : ""})`).join("; ")}. Listed whole in Appendix F.`] });
  // Coverage records that name it: what a negative was searched over, as the hub found it, and who reviewed it.
  const cov = run.entries.filter((e) => e.kind === "coverage" && !run.replaced.has(e.seq) && (e.answers ?? []).some((a) => sectionKey(a) === c.key));
  if (cov.length) {
    body.push({ k: "p", s: [{ b: "Coverage" }] });
    body.push({ k: "list", items: cov.map((e): Span[] => {
      const r = negativeReview(e, run.entries, run.attestations, run.disputes);
      return [{ e: e.seq }, `: ${e.value}; over ${coverageScope(e) || "no object named"}; coverage ${e.coverage ?? "not computed"} (computed by the hub)${e.not_examined?.length ? `; ${plural(e.not_examined.length, "planned route")} not examined` : ""}; ${r.reviewed ? `reviewed by ${r.by.join(", ")}` : "not reviewed by another seat"}.`];
    }) });
  }
  // The result, with what speaks against it.
  body.push({ k: "p", s: [{ b: "Result" }] });
  const a = st.answer;
  if (!a) body.push({ k: "p", s: outside ? ["No answer: it was not the run's work."] : [{ chip: st.status }, " No standing answer."] });
  else {
    const result = answerResult(a);
    const contrary = a.contrary ?? [];
    body.push({
      k: "p",
      s: [
        { chip: st.status },
        ` ${result ? resultWords(result) : a.inconclusive ? "inconclusive" : "answered (recorded before results)"}: `,
        { e: a.seq },
        ...(c.q ? [" (", { a: `#${questionAnchor(c.q.id)}`, text: "§5" } as Span, ")"] : []),
        ". ",
        contrary.length ? "Contrary evidence: " : a.contrary_none_why ? `Nothing recorded against it, and why: ${a.contrary_none_why}` : "No contrary evidence recorded.",
        ...contrary.flatMap((x, i): Span[] => [...(i ? [", "] : []), { e: x.seq }]),
        contrary.length ? "." : "",
        ...(v?.answer?.stale ? [" ", { b: `Stale: ${v.answer.stale_why === "evidence" ? "evidence arrived for the question after it was recorded" : `it answers r${v.answer.question_rev}, and the question stands at r${v.rev}`}.` } as Span] : []),
      ],
    });
    // Its parts, part by part (docs/adr/0013, "What the report shows of an answer's parts").
    body.push(...chainPartsBlocks(a, run));
    // The test of what it presumes (docs/adr/0011, "What a question presumes").
    body.push(...premiseTestBlocks(a, v, run));
    // How strongly other seats hold it (B2): established, or a best candidate only, and what capped it.
    // Held a best candidate only when it claims established (heldAsBestCandidate, the test the finish reads).
    const reviews = answerReviews(a, run.attestations);
    if (reviews.length) {
      body.push({ k: "p", s: [{ b: "Reviewed" }, `: ${reviews.map((x) => `by ${x.by} at ${x.at}, ${x.strength === "best_candidate" ? "a best candidate" : "established"}${x.capped?.length ? ` (capped: ${x.capped.join("; ")})` : ""}`).join("; ")}.`, ...(heldAsBestCandidate(a, reviews) ? [" ", { b: "A best candidate, not established: every review holds it so, and the run is examination-limited on it." } as Span] : [])] });
    }
  }
  // The operator's acceptance of what is left.
  if (v?.accepted) body.push({ k: "p", s: [{ b: "Accepted " }, `as ${v.accepted.as === "bounded" ? "a bounded examination" : "not determinable"} by ${originWords(v.accepted.origin)} at ${v.accepted.at} (r${v.accepted.rev}${v.accepted.answer ? `, the answer ${v.accepted.answer}` : ""}): ${v.accepted.why}. ${v.accepted.stands ? "It stands: the run is examination-limited, never completed on it." : "It no longer stands: the question, its answer or its evidence moved since."}`] });
  // The gaps that bound it.
  const gaps = gapsOf(run, limits).filter((g) => g.questions.some((x) => sectionKey(x) === c.key || x === v?.id));
  if (gaps.length) {
    body.push({ k: "p", s: [{ b: "Evidence gaps" }] });
    body.push({ k: "list", items: gaps.map((g): Span[] => [`${g.cls}: ${g.what}. Record: ${g.record}. Consequence: ${g.consequence}.`]) });
  }
  body.push({ k: "p", s: [{ b: "Cost: " }, `${costWords(run, c)}${leads.length && run.cost && run.cost.source !== "none" ? `; by lead: ${leads.map((l) => `${l.id} ${tokensWords(run.cost?.shown.byLead.get(l.id) ?? 0)}`).join(", ")}` : ""}.`] });
  const chips: Chip[] = [{ text: v ? v.origin.kind : c.q?.fromGoal ? "goal" : "section", tone: "slate" }, ...(v && v.scope !== "in_scope" ? [{ text: v.scope.replace(/_/g, " "), tone: "saffron" } as Chip] : []), ...(v?.withdrawn ? [{ text: "withdrawn", tone: "brick" } as Chip] : []), ...(outside && !st.answer ? [] : [st.status])];
  return { k: "box", cls: "answer chain", id: chainAnchor(chainName(c)), level: 4, title: [{ plain: `${chainName(c)} · ` }, v?.text ?? c.q?.text ?? "(no words recorded)"], chips, body };
}

/** Why each group of questions matters to a reader, in one paragraph. */
const GROUP_WHY: Record<ChainGroup, { title: string; why: string }> = {
  original: { title: "Original questions (the goal's)", why: "What the goal asked. The report answers each or says why it cannot; the finish line held the run to them." },
  asked: { title: "Asked during the run", why: "Questions a person put while the swarm worked, each on the record with who asked it (claimed or signed), every revision and clarification. A person's question is a proposition to test, never a conclusion to confirm; its authority carries no evidential weight." },
  emergent: { title: "Emergent questions (found in the evidence)", why: "Questions an agent found in the evidence, each with the entry that raised it, in scope because it sits under an objective or a question in scope. They are where the examination went beyond what was asked." },
  proposed: { title: "Proposed, not admitted", why: "Questions outside the declared objectives, waiting for the operator's triage: nobody examined them as the run's work. They may hold what the case needs; the report says nothing of their answers." },
  excluded: { title: "Excluded", why: "Questions the operator or an examiner put out of scope, with why: set aside, not answered. A reader who needs one knows it was not examined." },
  withdrawn: { title: "Withdrawn", why: "Questions their asker or the operator withdrew, with why. Their leads closed withdrawn; what they found stays in the ledger." },
};

/** §2's questions, one by one, grouped by where they came from and where they stand, then the ones left unresolved. */
function chainBlocks(run: Run, memo: Map<number, EntryState>): Block[] {
  const blocks: Block[] = [{ k: "h", level: 3, text: "How each question was examined", id: "chains" }];
  const all = chainQuestions(run);
  if (!all.length) {
    blocks.push({ k: "p", s: ["No question was asked or named: there is nothing to follow from question to answer."] });
    return blocks;
  }
  const reg = run.register;
  const counts = new Map<string, number>();
  for (const c of all) counts.set(c.v?.origin.kind ?? (c.q?.fromGoal ? "goal" : "section"), (counts.get(c.v?.origin.kind ?? (c.q?.fromGoal ? "goal" : "section")) ?? 0) + 1);
  blocks.push({
    k: "p",
    s: [
      `${plural(all.length, "question")}: ${[...counts].map(([k, n]) => `${n} ${k === "goal" ? "from the goal" : k === "agent" ? "from agents" : k === "section" ? "named only by the ledger" : `from ${k}s`}`).join(", ")}. `,
      reg ? `The question register (questions/questions.jsonl, ${plural(reg.events.length, "event")}${reg.snap.seeded ? "" : ", the goal's seed read from the goal, never written"}; chain ${reg.snap.state.chain.ok ? "intact" : `BROKEN at line ${reg.snap.state.chain.broken_at}: ${reg.snap.state.chain.reason}`}) keeps each one's asker, revisions, scope and acts; every event is in Appendix F. ` : "The question register could not be read: each question is shown from the goal and the ledger alone. ",
      "Each chain runs from who asked to what it cost: the asker, why, every verbatim revision, what came with it, the proposition tested, the leads that worked it (a negative lead counted here and listed whole in Appendix F), the result and what speaks against it, the operator's acceptance, the gaps that bound it, and its tokens.",
    ],
  });
  blocks.push({ k: "p", s: [{ b: "How the cost is counted. " }, run.cost?.method ?? "No token record could be read.", ...(run.cost && run.cost.source !== "none" ? [` Of the run's ${tokensWords(run.cost.shown.total)}, ${tokensWords([...run.cost.shown.byQuestion.values()].reduce((x, y) => x + y, 0))} went to questions (${tokensWords(run.cost.shown.named)} of it given to what a call made holding no lead named: a review, a record, an act on a lead), ${tokensWords(run.cost.shown.noQuestion)} to leads that name no question, ${tokensWords(run.cost.shown.run)} to the finish and the report's writing, ${tokensWords([...run.cost.shown.unheld.values()].reduce((x, y) => x + y, 0))} to calls made while the seat held no lead and named nothing (${[...run.cost.shown.unheldByKind].map(([k, n]) => `${k} ${tokensWords(n)}`).join(", ") || "none"}; by seat: ${[...run.cost.shown.unheld].map(([seat, n]) => `${seat} ${tokensWords(n)}`).join(", ") || "none"})${run.cost.shown.noTrace.size ? `, and ${tokensWords([...run.cost.shown.noTrace.values()].reduce((x, y) => x + y, 0))} a seat spent that the trace could not place (${[...run.cost.shown.noTrace].map(([seat, n]) => `${seat} ${tokensWords(n)}`).join(", ")})` : ""}.`] : [])] });
  const limits = run.entries.filter((e) => e.kind === "limitation" && !run.replaced.has(e.seq));
  for (const g of ["original", "asked", "emergent", "proposed", "excluded", "withdrawn"] as ChainGroup[]) {
    const list = all.filter((c) => groupOf(c) === g);
    if (!list.length) continue;
    blocks.push({ k: "h", level: 3, text: `${GROUP_WHY[g].title} (${list.length})` });
    blocks.push({ k: "p", s: [GROUP_WHY[g].why] });
    for (const c of list) blocks.push(chainBlock(c, run, memo, limits));
  }
  // What the examination leaves open: a question in scope with no answer that settles it.
  const open = all.filter((c) => ["original", "asked", "emergent"].includes(groupOf(c))).map((c) => ({ c, st: chainStatus(c, run, memo) })).filter(({ c, st }) => !SETTLED.has(st.status.text) || c.v?.answer?.stale || c.v?.after_done);
  blocks.push({ k: "h", level: 3, text: `Unresolved (${open.length})`, id: "unresolved" });
  blocks.push({ k: "p", s: ["Questions in scope that no answer settles: none standing, one that is negative, not determinable, partial, disputed, unreviewed or stale, or one asked after the run's done. The report's conclusions do not cover them; each says what would."] });
  if (open.length) {
    blocks.push({
      k: "list",
      items: open.map(({ c, st }): Span[] => {
        const would = st.answer?.would_change;
        const limitsFor = limits.filter((l) => (l.answers ?? []).some((x) => sectionKey(x) === c.key));
        return [
          { a: `#${chainAnchor(chainName(c))}`, text: chainName(c) },
          ": ",
          { chip: st.status },
          c.v?.answer?.stale ? " (stale)" : "",
          c.v?.after_done ? " (asked after the run's done)" : "",
          c.v?.accepted?.stands ? ` Accepted by the operator as ${c.v.accepted.as === "bounded" ? "a bounded examination" : "not determinable"}: the run is examination-limited on it.` : "",
          " What would settle it: ",
          would ? would : limitsFor.length ? `what the limitations recorded for it name (${limitsFor.map((l) => `E-${l.seq}`).join(", ")})` : "the record does not say.",
        ];
      }),
    });
  } else blocks.push({ k: "p", s: ["None: every question in scope has a standing answer that settles it."] });
  return blocks;
}

/**
 * Appendix F: the whole register, every event a reviewable one. Each
 * question event (who, when, what, and the act whole) in the chain's order;
 * each lead's events, and every close with who closed it, what it cites and
 * whether another agent reviewed that; the negatives and the duplicates the
 * body counts, whole.
 */
/** One lead-register event, whole and lossless: its heading, then every field it carries as its JSON, so nothing (an interpretation's `rest`, an acquisition `ask`) is dropped. */
function eventSpans(e: LeadEvent): Span[] {
  const { seq, at, by, ev, lead, prev: _p, hash: _h, ...fields } = e as LeadEvent & Record<string, unknown>;
  const head = `${seq} · ${at} · ${by} · ${ev}${lead ? ` · ${lead}` : ""}`;
  const rest = Object.keys(fields).length ? [" ", { code: JSON.stringify(fields) } as Span] : [];
  return [head, ...rest];
}

function registerSection(run: Run): BodySection {
  const blocks: Block[] = [];
  blocks.push({ k: "p", lede: true, s: ["The question and lead registers as the harness kept them, whole: every event with its seq, time and author, and every disposition with what it rests on and whether an agent other than the one who made it reviewed it. The body counts the negative and duplicate leads; they are here in full."] });
  const reg = run.register;
  blocks.push({ k: "h", level: 3, text: "The question register" });
  if (!reg || !reg.events.length) blocks.push({ k: "p", s: ["No question event was recorded or derived."] });
  else {
    blocks.push({ k: "p", s: [`${plural(reg.events.length, "event")}${reg.snap.seeded ? "" : " (the goal's seed derived from the goal, not written: a run from before the register, or one nothing wrote to)"}; chain ${reg.snap.state.chain.ok ? `intact, head ${reg.snap.state.chain.head ?? "none"}` : `BROKEN at line ${reg.snap.state.chain.broken_at}: ${reg.snap.state.chain.reason}`}.`] });
    blocks.push({
      k: "table",
      cls: "register",
      head: ["Seq", "When", "Who", "Event", "What"],
      rows: reg.events.map((e): Span[][] => [
        [String(e.seq)],
        [e.seq > reg.persisted ? "derived from the goal, not written" : e.at],
        [e.origin ? originWords(e.origin) : e.by],
        [`${e.ev}${e.q ? ` ${e.q}` : ""}${e.rev !== undefined ? ` r${e.rev}` : ""}`],
        [{ code: JSON.stringify({ ...(e.act ? { act: e.act } : {}), ...(e.decided ? { decided: e.decided } : {}), ...Object.fromEntries(Object.entries(e).filter(([k]) => !["v", "seq", "at", "by", "ev", "q", "rev", "act", "decided", "origin", "prev", "hash"].includes(k))) }) }],
      ]),
    });
  }
  blocks.push({ k: "h", level: 3, text: "The lead register" });
  const views = new Map((run.leads?.views ?? []).map((l) => [l.id, l]));
  if (!run.leadEvents.length) blocks.push({ k: "p", s: ["No lead was opened."] });
  else {
    blocks.push({ k: "p", s: [`${plural(views.size, "lead")}, ${plural(run.leadEvents.length, "event")}; chain ${run.leads?.chain.ok ? "intact" : `BROKEN at line ${run.leads?.chain.broken_at}: ${run.leads?.chain.reason}`}.`] });
    for (const id of [...views.keys()].sort((a, b) => Number(a.slice(2)) - Number(b.slice(2)))) {
      const x = views.get(id) as LeadView;
      const events = run.leadEvents.filter((e) => e.lead === id);
      blocks.push({
        k: "box",
        cls: "exhibit lead",
        id: `reg-${id}`,
        level: 4,
        title: [{ plain: `${id} · ` }, x.title],
        chips: [{ text: x.disposition ?? x.status, tone: x.disposition === "negative" ? "saffron" : x.disposition ? "slate" : "moss" }, ...(x.quick_negative ? [{ text: "quick negative", tone: "saffron" } as Chip] : [])],
        body: [
          { k: "p", s: [...leadLineOf(run, x), ` For ${x.answers.length ? x.answers.join(", ") : "no question"}; opened by ${x.opened_by} at ${x.opened_at}${x.origin ? ` from ${x.origin}` : ""}.`, ...(x.proposition ? [` Proposition: ${x.proposition}; negation: ${x.negation ?? "not stated"}.`] : []), ...(x.product ? [` Product: ${x.product}; acceptance: ${x.acceptance ?? "not stated"}.`] : [])] },
          { k: "list", items: events.map(eventSpans) },
        ],
      });
    }
    // Events tied to no lead (an interpretation of a job's output, above all): they carry how the rest of the output was treated, and are lost if only per-lead events are shown.
    const noLead = run.leadEvents.filter((e) => !e.lead);
    if (noLead.length) {
      blocks.push({ k: "h", level: 4, text: `Events not tied to a lead (${noLead.length})` });
      blocks.push({ k: "list", items: noLead.map(eventSpans) });
    }
    const negatives = [...views.values()].filter((x) => x.disposition === "negative");
    const duplicates = [...views.values()].filter((x) => x.disposition === "duplicate");
    blocks.push({ k: "h", level: 3, text: `Negative leads (${negatives.length})` });
    if (negatives.length) blocks.push({ k: "list", items: negatives.map((x) => leadLineOf(run, x)) });
    else blocks.push({ k: "p", s: ["None."] });
    blocks.push({ k: "h", level: 3, text: `Duplicate leads (${duplicates.length})` });
    if (duplicates.length) blocks.push({ k: "list", items: duplicates.map((x) => leadLineOf(run, x)) });
    else blocks.push({ k: "p", s: ["None."] });
  }
  // The finish (docs/adr/0015): who coordinated it, when the registers said it was ready, what each check said, and the report's review.
  blocks.push({ k: "h", level: 3, text: "The finish" });
  const fin = run.finish;
  if (!fin || !fin.events.length) blocks.push({ k: "p", s: ["No finish register: a run from before one seat coordinated the finish, or one no seat called done in."] });
  else {
    blocks.push({ k: "p", s: [`${plural(fin.events.length, "event")} in leads/finish.jsonl; chain ${fin.chain.ok ? `intact, head ${fin.chain.head ?? "none"}` : `BROKEN at line ${fin.chain.broken_at}: ${fin.chain.reason}`}. ${fin.lease ? `The coordinator at the end: ${fin.lease.holder} (generation ${fin.lease.generation}, since ${fin.lease.at}${fin.lease.from ? `, taken over from ${fin.lease.from}` : ""}): ${fin.lease.why}${fin.lease.report ? `; the report it finished on: ${fin.lease.report}` : ""}.` : "No seat held the coordinator's lease."}`] });
    blocks.push({
      k: "list",
      items: fin.events.map((e): Span[] => {
        const x = e as unknown as Record<string, unknown>;
        const what =
          e.ev === "lease" ? `lease to ${String(x.holder)} (generation ${String(x.generation ?? "?")})${x.from ? ` from ${String(x.from)}` : ""}${x.segment ? `, segment ${String(x.segment)}` : ""}${Array.isArray(x.carried) && x.carried.length ? `, carrying ${(x.carried as Array<{ id?: unknown }>).map((c) => `post #${String(c.id)}`).join(", ")} from before the resume` : ""}${x.why ? `: ${String(x.why)}` : ""}`
          : e.ev === "prepare" ? `the finish prepared at generation ${String(x.generation ?? "?")} on ${String(x.report ?? "the report")} ${String(x.digest ?? "").slice(0, 12)}: ${x.ready ? "ready" : "not ready"} by the registers, ${Array.isArray(x.late) ? x.late.length : 0} item(s) late against it${Array.isArray(x.late) && x.late.length ? ` (${(x.late as Array<{ kind?: unknown; id?: unknown }>).map((l) => (l.kind === "post" ? `post #${String(l.id)}` : `objection ${String(l.id)}`)).join(", ")})` : ""}`
          : e.ev === "readiness" ? `${x.ready ? "ready" : "not ready"} at revision ${String(x.revision ?? "").slice(0, 12)}${Array.isArray(x.items) && x.items.length ? `: ${(x.items as string[]).join("; ")}` : ""}`
          : e.ev === "check" ? `the finish line at revision ${String(x.revision ?? "").slice(0, 12)}: ${x.proceed ? "proceed" : "refused"}${x.outcome ? ` (${String(x.outcome)})` : ""}${x.reason ? `: ${String(x.reason)}` : ""}`
          : e.ev === "ack" ? `${x.verdict === "objection" ? "objection" : "no objection"} to the report ${String(x.digest ?? "").slice(0, 12)}${x.sections && typeof x.sections === "object" && !x.whole ? `, sections ${Object.keys(x.sections as object).join(", ")}` : ""}${x.why ? `: ${String(x.why)}` : ""}`
          : e.ev === "carry" ? `the reviews of earlier versions weighed for ${String(x.report ?? "the report")} ${String(x.digest ?? "").slice(0, 12)}: ${Array.isArray(x.kept) && x.kept.length ? `carried over, their sections unchanged: ${(x.kept as Array<{ by?: unknown; acks?: unknown[]; sections?: unknown[] }>).map((k) => `${String(k.by)} (ack ${(k.acks ?? []).map(String).join(", ")}; ${(k.sections ?? []).map(String).join(", ")})`).join("; ")}` : "none carried over"}${Array.isArray(x.reasked) && x.reasked.length ? `; asked again: ${(x.reasked as Array<{ by?: unknown; changed?: unknown[]; removed?: unknown[] }>).map((k) => `${String(k.by)} (${[...(k.changed ?? []).map(String), ...(k.removed ?? []).map((r) => `${String(r)} removed`)].join(", ")})`).join("; ")}` : ""}`
          : e.ev === "resolve" ? `resolved ${x.post !== undefined ? `post #${String(x.post)}` : `ack ${String(x.ack)}`} as ${String(x.how)}${x.batch ? ` (batch ${String(x.batch)})` : ""}${x.why ? `: ${String(x.why)}` : ""}`
          : JSON.stringify(Object.fromEntries(Object.entries(x).filter(([k]) => !["v", "seq", "at", "by", "ev", "prev", "hash", "run"].includes(k))));
        return [`${e.seq} · ${e.at} · ${e.by} · ${e.ev}: ${what}`];
      }),
    });
  }
  return { id: "sF", n: "F", title: "The question and lead registers", desc: "every question and lead event, every disposition reviewable", count: `${plural(run.register?.events.length ?? 0, "question event")}, ${plural(run.leadEvents.length, "lead event")}`, blocks };
}

function evidenceSection(run: Run): BodySection {
  const blocks: Block[] = [];
  const inputs = run.inputs;
  if (run.html.evidence) {
    blocks.push({ k: "html", html: run.html.evidence });
  } else if (inputs && inputs.files.length) {
    const withSha1 = inputs.files.some((f) => f.sha1);
    const withMd5 = inputs.files.some((f) => f.md5);
    blocks.push({
      k: "p",
      lede: true,
      s: [`${plural(inputs.files.length, "evidence file")}, ${bytesHuman(inputs.bytes || inputs.files.reduce((n, f) => n + f.bytes, 0))} in total${inputs.source ? `, from ${inputs.source}` : ""}${inputs.copied_at ? `, recorded when the run began (${inputs.copied_at})` : ", recorded when the run began"}. Each hash below was taken then.`],
    });
    blocks.push({
      k: "table",
      cls: "evidence",
      head: ["File", "Size", "sha256", ...(withSha1 ? ["sha1"] : []), ...(withMd5 ? ["md5"] : [])],
      rows: inputs.files.map((f) => [[{ code: f.path }], [bytesHuman(f.bytes)], [{ code: f.sha256 }], ...(withSha1 ? [[f.sha1 ? { code: f.sha1 } : "—"] as Span[]] : []), ...(withMd5 ? [[f.md5 ? { code: f.md5 } : "—"] as Span[]] : [])]),
    });
    blocks.push({ k: "p", s: [heldSentence(inputs)] });
  } else {
    blocks.push({ k: "note", s: ["This run was given no read-only inputs: whatever the agents examined, they reached some other way, and no evidence hash can be stated for it."] });
  }
  blocks.push({ k: "h", level: 3, text: "Acquisition" });
  blocks.push({ k: "p", s: [acquisitionSentence(run)] });
  // What entered the run after its kickoff (docs/adr/0014): each addition sealed in the store with its provenance.
  const added = run.contract.material.filter((m) => m.mode === "evidence");
  const supplied = run.contract.material.filter((m) => m.mode === "material");
  if (added.length) {
    blocks.push({ k: "h", level: 3, text: "Evidence added during the run" });
    blocks.push({ k: "p", s: ["Each addition is an inventory revision: copied, held to the sha256 its source had, sealed in the store and recorded on the ledger as external material (acquired evidence). Every seat's VM mounts the run's directory read-only and live, so each addition was readable there (store/imports/<id>/out/) as soon as it was sealed, as it was through jobs; a finding cites it as import:<id>/<file> however it was read, and what it is (its class, who supplied it, when) is its ledger entry's."] });
    blocks.push({
      k: "table",
      cls: "evidence",
      head: ["Import", "Revision", "File", "Size", "sha256", "For", "Supplied by", "Why"],
      rows: added.flatMap((m) => ((m.files as Array<{ path: string; bytes: number; sha256: string }> | undefined) ?? []).map((f): Span[][] => [[{ code: `import:${String(m.import)}` }], [String(m.inventory_rev ?? "")], [{ code: f.path }], [bytesHuman(f.bytes)], [{ code: f.sha256 }], [String(m.request ?? "")], [String(m.supplied_by ?? "")], [String(m.why ?? "")]])),
    });
  }
  if (supplied.length) {
    blocks.push({ k: "h", level: 3, text: "Material supplied by the operator" });
    blocks.push({ k: "p", s: ["Supplied material is not evidence of the events: it proves nothing by itself, and what rests on it is marked in §5."] });
    blocks.push({
      k: "table",
      cls: "evidence",
      head: ["Import", "Class", "File", "sha256", "Use", "Supplied by", "Why"],
      rows: supplied.flatMap((m) => ((m.files as Array<{ path: string; bytes: number; sha256: string }> | undefined) ?? []).map((f): Span[][] => [[{ code: `import:${String(m.import)}` }], [String(m.class ?? "").replace(/_/g, " ")], [{ code: f.path }], [{ code: f.sha256 }], [String(m.permitted_use ?? "")], [String(m.supplied_by ?? "")], [String(m.why ?? "")]])),
    });
  }
  blocks.push({ k: "h", level: 3, text: "At the end of the run" });
  blocks.push({ k: "p", s: [custodySentence(run.custody)] });
  if (run.custody?.summary) blocks.push({ k: "p", s: [{ b: "The host's custody check, in its own words (custody.json): " }, run.custody.summary] });
  blocks.push({ k: "h", level: 3, text: "How jobs read it" });
  blocks.push({
    k: "p",
    s: [
      run.jobs.size
        ? `${plural(run.jobs.size, "job")} ran in worker VMs with the evidence mounted read-only; each declared the objects it would read (Appendix B). A method record says what ran, where and how it ended: it describes recorded execution, not which bytes a tool actually read, and what the run did not record stays "unknown". From ledger version 4 the record is written into each entry and its hash; for an entry recorded before that, this report reads the job's record when it renders and says so ("job record"): that one is not bound in the entry's hash.`
        : "No job ran in a worker VM: the agents read the evidence themselves, and the ledger's evidence lines say how.",
    ],
  });
  blocks.push({ k: "h", level: 3, text: "The record" });
  const c = run.chains;
  blocks.push({
    k: "list",
    items: [
      [`The ledger (ledger/entries.jsonl): ${ledgerChainWords(c.ledger)}.`],
      [`The attestations (ledger/attestations.jsonl): ${c.attestations.total ? (c.attestations.ok ? `${c.attestations.total} lines, the chain intact` : `BROKEN at line ${c.attestations.broken_at}: ${c.attestations.reason}`) : "none"}.`],
      [`The disputes (ledger/disputes.jsonl): ${c.disputes.total ? (c.disputes.ok ? `${c.disputes.total} lines, the chain intact` : `BROKEN at line ${c.disputes.broken_at}: ${c.disputes.reason}`) : "none"}.`],
    ],
  });
  return { id: "s3", n: "3", title: "Evidence and its handling", desc: "what was examined, its hashes, and how it was held", count: inputs ? plural(inputs.files.length, "file") : "none given", blocks };
}

function ledgerChainWords(c: Chain & { chained: number }): string {
  if (!c.ok) return `BROKEN at line ${c.broken_at} of ${c.total}: ${c.reason}`;
  if (!c.total) return "empty";
  if (!c.chained) return `${plural(c.total, "entry", "entries")}, none hash-chained (written before the ledger was chained): nothing here shows it unchanged`;
  if (c.chained < c.total) return `${plural(c.total, "entry", "entries")}: the first ${c.total - c.chained} written before the ledger was chained, the other ${c.chained} hash-chained, the chain intact`;
  return `${plural(c.total, "entry", "entries")}, all hash-chained, the chain intact`;
}

function heldSentence(inputs: InputsManifest & { held?: string }): string {
  const guard = inputs.guard;
  const held = inputs.held;
  if (guard === "microvm" && held === "copy") return "It was copied into the run and mounted read-only into each agent's microVM; the host refused every write through that mount.";
  if (guard === "microvm") return "It was used in place, with no copy: each agent's microVM had it mounted read-only, and the host refused every write through that mount.";
  if (held === "image") return "It was attached as a read-only disk image: the device refused every write.";
  if (held === "bind") return "It was used in place, with no copy; the kernel held it read-only in every pane.";
  if (guard && guard !== "none") return `It was copied into inputs/, which no agent may write (guard: ${guard}).`;
  return "How it was held during the run is not recorded in its manifest.";
}

function acquisitionSentence(run: Run): string {
  const acq = run.custody?.acquisition;
  if (acq) {
    if (acq.mismatched.length) return `The acquisition digests DO NOT MATCH: ${acq.mismatched.join(", ")} (of ${acq.given} given in ${acq.source ?? "the file given"}). The copy examined is not shown to be the copy acquired.`;
    return `${acq.matched} of ${acq.given} digests from the acquisition record (${acq.source ?? "the file given"}) match the evidence as the host re-hashed it${acq.not_compared.length ? `; ${acq.not_compared.length} not compared (${acq.not_compared.join(", ")})` : ""}.`;
  }
  if (run.acquisitionGiven.length) return `The operator gave ${plural(run.acquisitionGiven.length, "acquisition digest")} at kickoff (${[...new Set(run.acquisitionGiven.map((a) => a.algo ?? "?"))].join(", ")}); no custody check has compared them with the evidence yet.`;
  return "Acquisition record: not provided. The hashes above were taken when the run began, not when the evidence was acquired: nothing in this report ties the copy examined to the original acquisition, so the evidence's continuity before the run rests on the word of whoever supplied it.";
}

function custodySentence(c: CustodyView | null): string {
  if (!c) return "No host custody was taken (swarm.sh stop takes it): nothing here says the evidence was unchanged at the end of the run.";
  const at = c.at ?? "time not recorded";
  const i = c.inputs;
  if (i === null) return `The host's custody check (${at}) found no evidence given to this run.`;
  if (!i) return `The host's custody check (${at}) did not re-hash the evidence.`;
  const n = (v?: unknown[]) => (Array.isArray(v) ? v.length : 0);
  if (n(i.changed) || n(i.missing) || n(i.added)) return `At the end the host's re-hash found ${n(i.changed)} changed, ${n(i.missing)} missing and ${n(i.added)} added (custody.json, ${at}).`;
  if (i.unchanged) return `At the end the host re-hashed every file in full and found it unchanged since the run began (custody.json, ${at}).`;
  const files = Number(i.files) || 0;
  return `At the end the host re-hashed ${files - n(i.skipped) - n(i.unreadable)} of ${files} files and found them unchanged; ${n(i.skipped)} were not re-read before custody's deadline and ${n(i.unreadable)} could not be read, so those are not covered (custody.json, ${at}).`;
}

/** The dispositions that drop or defer work: a critic reviews each, by attesting or disputing what it cites. */
const DROPS = new Set(["negative", "duplicate", "deferred", "infeasible", "needs_operator"]);

/**
 * How the investigation proceeded: each finding, the leads it opened, and
 * how each lead ended, from the lead register. A lead's origin is the entry
 * (or the agent) that opened it and its disposition cites what it rests on,
 * so the chain reads finding, lead, disposition, the finding that closed it,
 * the leads that one opened. A drop or a deferral says whether an agent other
 * than the one who closed it reviewed the entry it cites; an agent's review
 * is still not a human's.
 */
function proceededBlocks(run: Run): Block[] {
  const blocks: Block[] = [{ k: "h", level: 3, text: "How the investigation proceeded", id: "proceeded" }];
  const leads = run.leads;
  if (!leads) {
    blocks.push({ k: "p", s: ["The swarm opened no lead: the order of its work is in the trace and the board, not in a register of what was found to follow."] });
    return blocks;
  }
  blocks.push({
    k: "p",
    s: [
      `${plural(leads.views.length, "lead")} in the register (`,
      { code: "leads/leads.md" },
      `, ${plural(leads.events, "event")}, chain ${leads.chain.ok ? "intact" : `BROKEN at line ${leads.chain.broken_at}: ${leads.chain.reason}`}). `,
      "A lead is work an agent found had to be followed; the harness kept who held it and how it ended, and assigned none of it. Each finding is listed with the leads it opened, then how each ended and what that rests on. A lead closed negative is counted here and listed whole in Appendix F, and so is a duplicate.",
    ],
  });
  const reviewOf = (x: LeadView): Span[] => dropReview(run, x);
  // The negatives and the duplicates are counted where they fall; Appendix F has each whole.
  const folded = (x: LeadView) => x.disposition === "negative" || x.disposition === "duplicate";
  const foldNote = (list: LeadView[]): Block[] => {
    const neg = list.filter((x) => x.disposition === "negative");
    const dup = list.filter((x) => x.disposition === "duplicate");
    const out: Block[] = [];
    if (neg.length) out.push({ k: "p", s: [`and ${plural(neg.length, "lead")} closed negative (${neg.filter((x) => x.quick_negative).length} quick): `, ...neg.flatMap((x, i): Span[] => [...(i ? [", "] : []), { a: `#reg-${x.id}`, text: x.id }]), ", in Appendix F."] });
    if (dup.length) out.push({ k: "note", s: [`Duplicates: ${dup.map((x) => `${x.id} (of ${x.ref ?? "?"})`).join("; ")}; in Appendix F.`] });
    return out;
  };
  // Grouped by where each lead came from: a finding first, in ledger order, then the leads an agent opened on its own.
  const byOrigin = new Map<string, LeadView[]>();
  for (const x of [...leads.views].sort((a, b) => a.opened_at.localeCompare(b.opened_at) || a.id.localeCompare(b.id))) {
    const key = /^E-\d+$/.test(x.origin) ? x.origin : "";
    byOrigin.set(key, [...(byOrigin.get(key) ?? []), x]);
  }
  const fromEntries = [...byOrigin.keys()].filter(Boolean).sort((a, b) => Number(a.slice(2)) - Number(b.slice(2)));
  for (const origin of fromEntries) {
    const seq = Number(origin.slice(2));
    const e = run.bySeq.get(seq);
    const list = byOrigin.get(origin) ?? [];
    blocks.push({ k: "p", s: [{ e: seq }, e ? ` (${e.kind}): ${e.value}` : " (not in the ledger)", " opened:"] });
    if (list.some((x) => !folded(x))) blocks.push({ k: "list", items: list.filter((x) => !folded(x)).map((x) => leadLineOf(run, x)) });
    blocks.push(...foldNote(list));
  }
  const own = byOrigin.get("") ?? [];
  if (own.length) {
    blocks.push({ k: "p", s: [fromEntries.length ? "Opened by an agent, not from a recorded finding:" : "Every lead was opened by an agent, not from a recorded finding:"] });
    if (own.some((x) => !folded(x))) blocks.push({ k: "list", items: own.filter((x) => !folded(x)).map((x) => [...leadLineOf(run, x), ` (${x.origin})`]) });
    blocks.push(...foldNote(own));
  }
  const drops = leads.views.filter((x) => x.disposition && DROPS.has(x.disposition));
  const unreviewed = drops.filter((x) => reviewOf(x).some((sp) => typeof sp === "object" && "b" in sp && sp.b === "not reviewed"));
  if (drops.length) blocks.push({ k: "p", s: [`${plural(drops.length, "lead")} dropped or deferred; ${unreviewed.length ? `${unreviewed.length} of them not reviewed by an agent other than the one who closed it (${unreviewed.map((x) => x.id).join(", ")})` : "each reviewed by another agent"}.`] });
  return blocks;
}

function methodSection(run: Run): BodySection {
  const blocks: Block[] = [];
  const agents = new Map<string, { model?: string }>();
  for (const a of run.team) agents.set(a.id, { ...(a.model ? { model: a.model } : {}) });
  for (const e of run.entries) for (const a of e.authors) if (!agents.has(a)) agents.set(a, {});
  for (const a of [...run.attestations, ...run.disputes]) if (!agents.has(a.by)) agents.set(a.by, {});
  const name = new Map(run.names.map((n) => [n.id, n]));
  const recorded = (id: string) => {
    const by = run.entries.filter((e) => e.by === id);
    const kinds = new Map<string, number>();
    for (const e of by) kinds.set(e.kind, (kinds.get(e.kind) ?? 0) + 1);
    return [...kinds.entries()].map(([k, n]) => kindCount(k, n)).join(", ") || "nothing";
  };
  const acts = (id: string) => {
    const at = run.attestations.filter((a) => a.by === id && attestationAct(a) === "attest").length;
    const dp = run.disputes.filter((d) => d.by === id && d.act === "dispute").length;
    return [at ? plural(at, "attestation") : "", dp ? plural(dp, "dispute") : ""].filter(Boolean).join(", ") || "none";
  };
  const authors = [...new Set(run.entries.filter((e) => e.kind === "answer").map((e) => e.by))];
  const critics = [...new Set([...run.attestations.filter((a) => attestationAct(a) === "attest").map((a) => a.by), ...run.disputes.filter((d) => d.act === "dispute").map((d) => d.by)])];
  const finders = [...new Set(run.entries.filter((e) => e.kind !== "answer").map((e) => e.by))];
  blocks.push({
    k: "p",
    lede: true,
    s: [
      `${agents.size === 1 ? "1 AI agent worked the case" : `${agents.size} AI agents worked the case as peers`}. Nobody assigned the work: each read the goal, chose its part and said so (below). What they established went into a hash-chained ledger as it was found, each entry with where it was seen and how; the answers in §5 are entries of that ledger, citing by hash the entries they rest on.`,
    ],
  });
  blocks.push({
    k: "rows",
    rows: [
      { label: "Recorded findings, events, searches and limitations", s: [finders.join(", ") || "nobody"] },
      { label: "Wrote the answers", s: [authors.join(", ") || "nobody (no answer is recorded)"] },
      { label: "Re-derived or disputed", s: [critics.join(", ") || "nobody"] },
      ...(authors.some((a) => critics.includes(a)) ? [{ label: "Note", s: [`${authors.filter((a) => critics.includes(a)).join(", ")} both wrote answers and acted as a critic; no agent's act on its own answer counts as a check.`] } as Row] : []),
    ],
  });
  blocks.push({
    k: "table",
    cls: "agents",
    head: ["Agent", "Calls itself", "Said it was doing", "Model", "Recorded", "Acts"],
    rows: [...agents.entries()].map(([id, a]) => [[{ code: id }], [name.get(id)?.name ?? "—"], [name.get(id)?.doing ?? "—"], [a.model ?? "not recorded"], [recorded(id)], [acts(id)]]),
  });

  if (run.html.method) blocks.push({ k: "html", html: run.html.method });

  // Jobs, images and tools.
  blocks.push({ k: "h", level: 3, text: "Jobs, images and tools" });
  if (run.jobs.size) {
    const count = (f: (j: JobRecord) => string) => {
      const m = new Map<string, number>();
      for (const j of run.jobs.values()) m.set(f(j), (m.get(f(j)) ?? 0) + 1);
      return [...m.entries()].sort((a, b) => b[1] - a[1] || a[0].localeCompare(b[0])).map(([k, n]) => `${n} ${k}`).join(", ");
    };
    blocks.push({ k: "p", s: [`${plural(run.jobs.size, "job")}: ${count((j) => j.spec.kind ?? "unknown kind")}; ended ${count((j) => j.status ?? "unknown")}.`] });
    const images = new Map<string, number>();
    for (const j of run.jobs.values()) {
      const k = `${j.image ?? "image not recorded"}\u0000${j.image_digest ?? "digest not recorded"}`;
      images.set(k, (images.get(k) ?? 0) + 1);
    }
    blocks.push({ k: "table", cls: "images", head: ["Image", "Digest", "Jobs"], rows: [...images.entries()].map(([k, n]) => [[{ code: k.split("\u0000")[0] }], [{ code: k.split("\u0000")[1] }], [String(n)]]) });
    const scope = (j: JobRecord) => {
      const d = Array.isArray(j.spec.inputs) ? j.spec.inputs.map(String) : [];
      return !d.length ? "recorded no scope" : d.includes("all") ? "declared scope all (could read every input)" : "named their inputs";
    };
    blocks.push({ k: "p", s: [`Declared scope, by job: ${count(scope)}. A job that could read every input is counted as its own source, of unknown independence.`] });
    const tools = new Map<string, Set<string>>();
    const recipes = new Set<string>();
    let commands = 0;
    for (const j of run.jobs.values()) {
      if (j.spec.kind === "tool" && j.spec.tool) tools.set(j.spec.tool, new Set([...(tools.get(j.spec.tool) ?? []), j.tool_sha256 ?? "sha256 not recorded"]));
      if (j.spec.kind === "recipe" && j.spec.recipe) recipes.add(j.spec.recipe);
      if (j.spec.kind === "command") commands += 1;
    }
    const lines: Span[][] = [];
    if (tools.size) lines.push(["Pack tools run as jobs: ", ...[...tools.entries()].flatMap(([t, shas], i): Span[] => [...(i ? ["; "] : []), { code: t }, ` (sha256 ${[...shas].join(", ")})`])]);
    if (recipes.size) lines.push(["Catalogue recipes: ", ...[...recipes].flatMap((r, i): Span[] => [...(i ? [", "] : []), { code: r }])]);
    if (commands) lines.push([`${plural(commands, "shell command job")}: each command is in Appendix B, whole.`]);
    if (lines.length) blocks.push({ k: "list", items: lines });
  } else blocks.push({ k: "p", s: ["No job ran in a worker VM."] });
  if (run.forged.length && !run.html.method) {
    blocks.push({
      k: "p",
      s: [
        "Tools the agents wrote for themselves during the run, not independently validated: ",
        ...run.forged.flatMap((t, i): Span[] => [...(i ? ["; "] : []), { code: t.name }, ` by ${t.by} (${t.runtime}, sha256 ${t.sha256})`]),
        ". A finding that rests on one rests on code the swarm wrote and no one reviewed.",
      ],
    });
  }

  blocks.push({ k: "h", level: 3, text: "How corroboration is counted" });
  blocks.push({
    k: "voice",
    voice: "computed",
    label: VOICE_LABEL.computed,
    s: [
      "Each ref an entry rests on is traced to the evidence objects it came from: an input by its path; a job's output to the inputs that job declared (and a job over another job's output to that job's); an import or an agent's own file to itself, its origin not recorded. Refs that share an object are one corroboration group: two outputs of one disk image are one source. A group is a provenance group, not proof of independence: two different logs may still copy one another, and a job that declared scope all is its own group of unknown independence.",
    ],
  });

  blocks.push(...proceededBlocks(run));

  // What agents checked, and what humans did.
  blocks.push({ k: "h", level: 3, text: "What an agent checked" });
  const attests = run.attestations.filter((a) => attestationAct(a) === "attest");
  const coauthors = run.attestations.filter((a) => attestationAct(a) === "same_content");
  const items: Span[][] = [
    ...attests.map((a): Span[] => [`${a.by} attested `, { e: a.seq }, `${a.how ? `: ${a.how}` : ""}${a.refs?.length ? ` (from ${a.refs.join(", ")})` : ""}${run.bySeq.get(a.seq)?.authors.includes(a.by) ? " — its own entry: not a check" : ""}`]),
    ...run.disputes.map((d): Span[] => [`${d.by} ${d.act === "dispute" ? "disputed" : "withdrew its dispute of"} `, { e: d.seq }, `: ${d.why}${d.refs?.length ? ` (from ${d.refs.join(", ")})` : ""}`]),
    ...coauthors.map((a): Span[] => [`${a.by} recorded `, { e: a.seq }, " word for word: a second author, not a check"]),
  ];
  if (items.length) {
    blocks.push({ k: "list", items });
    blocks.push({ k: "p", s: ["An attestation is an agent re-deriving another agent's work from the sealed objects. It is not peer review and not independent: the agents share a run, an instruction and often a model."] });
  } else blocks.push({ k: "p", s: ["No agent attested or disputed anything: every entry is its author's word alone."] });
  blocks.push({ k: "h", level: 3, text: "What a human checked" });
  blocks.push({ k: "p", s: [humanChecked(run)] });
  return { id: "s4", n: "4", title: "Method and roles", desc: "who did what, with which tools, and who checked it", blocks };
}

function humanChecked(run: Run): string {
  const r = run.review;
  if (r?.unreadable) return `The examiner's review could not be read (${r.unreadable}).`;
  const n = r?.entries?.size ?? 0;
  const parts: string[] = [];
  if (r?.examiner) parts.push(`Examiner: ${r.examiner.name}${r.examiner.organisation ? `, ${r.examiner.organisation}` : ""}.`);
  if (n) parts.push(`${plural(n, "entry", "entries")} reviewed by the examiner (§10).`);
  if (r?.technicalReviews?.length) {
    for (const t of r.technicalReviews) parts.push(`Technical review by ${t.name}${t.checked ? `, who checked ${t.checked}` : ""}${t.outcome ? ` (${t.outcome}${t.reviewed_at ? `, ${t.reviewed_at}` : ""})` : ""}: ${t.words}.${t.disagreements?.length ? ` Disagreements: ${t.disagreements.join("; ")}.` : ""}`);
  } else if (r?.technicalReviewer) parts.push(`Technical reviewer: ${r.technicalReviewer.name}${r.technicalReviewer.checked ? `, who checked ${r.technicalReviewer.checked}` : ""}.`);
  else if (r && !r.unreadable) parts.push("No technical review.");
  if (r?.signed) parts.push(r.signed.current === false ? `Signed off by ${r.signed.by} at ${r.signed.at}, and NOT OVER THIS RUN AS IT STANDS${r.signed.scope ? `: ${r.signed.scope}` : ""}.` : `Signed by ${r.signed.by} at ${r.signed.at}.`);
  if (!n && !r?.signed) return `No human checked any of it: no examiner review is recorded for this run.${r?.examiner ? ` The examiner named for the case is ${r.examiner.name}${r.examiner.organisation ? `, ${r.examiner.organisation}` : ""}.` : ""}`;
  return parts.join(" ");
}

/** How a late delta that neither supports nor contradicts the answer reads in its chain. */
const LATE_DELTA_WORDS: Readonly<Record<string, string>> = {
  irrelevant: "irrelevant to it within its scope",
  inconclusive: "inconclusive: it cannot say how the new evidence bears on it",
  adds_part: "it adds a part the answer left open",
};

const STEPS = ["How it was obtained", "What it indicates", "Why this confidence", "What else could explain it", "Contrary evidence", "Limitations", "What would change it", "Exhibits"] as const;

function answerSectionOf(run: Run, memo: Map<number, EntryState>): BodySection {
  const blocks: Block[] = [];
  if (!run.questions.length) blocks.push({ k: "note", s: ["No question is named by the goal or by any entry."] });
  if (!run.hasAnswers && run.questions.length) {
    blocks.push({
      k: "note",
      s: [
        `${run.era === "predates" ? "This run predates structured answers (ledger version 4)." : "The swarm recorded no answers."} For each question below, the ledger holds only the entries that name it; the swarm's prose is in its working report (Appendix C), which the ledger does not check.`,
      ],
    });
  }
  blocks.push(...premisesTable(run));
  for (const q of run.questions) blocks.push(questionBlock(q, run, memo));
  return { id: "s5", n: "5", title: "Answers", desc: "each question: the answer, how it was reached, how sure", count: run.hasAnswers ? `${run.questions.filter((q) => standingAnswer(run, `question:${q.id}`)).length} of ${run.questions.length} answered` : "no structured answers", blocks };
}

function questionBlock(q: Question, run: Run, memo: Map<number, EntryState>): Block {
  const a = standingAnswer(run, `question:${q.id}`);
  const title: Span[] = [`${questionName(q)}${q.text ? `: ${q.text}` : ""}`];
  if (!a) return { k: "box", cls: "answer unanswered", id: questionAnchor(q.id), level: 3, title, chips: [questionStatus_(q, run, memo).status], body: unansweredBody(q, run, memo) };
  const s = stateOf(a, run, memo);
  const body: Block[] = [];
  const history = answerHistory(run, `question:${q.id}`).filter((x) => x.seq !== a.seq);
  // A negative is stated as the harness makes it from its coverage record,
  // what was not found where, unless the answer earned the stronger words;
  // the agents' own words follow it, whole, and marked as theirs.
  const bounded = boundedConclusion(a, q, run);
  // A partial answer leads with its parts in a plain line (docs/adr/0013, "What the report shows of an answer's parts"); one without rows reads as before.
  body.push(...partialLeadBlocks(a, run));
  body.push({ k: "voice", voice: "opinion", label: a.inconclusive ? "Answer (inconclusive)" : "Answer", s: [bounded ?? a.value], chips: chipsOf(a, s).filter((c) => c.text !== "answer") });
  if (bounded) body.push({ k: "p", s: [`As the agents worded it (not the conclusion: the bar for saying more is not met): ${a.value}`] });
  body.push(...resultBlocks(a, q, run));
  body.push(...partsBlocks(a, q, run));
  body.push(...premiseBlocks(a, run));
  body.push(...premiseTestBlocks(a, q.reg ? (run.register?.byId.get(q.reg) ?? null) : null, run));
  body.push({
    k: "p",
    s: [
      { e: a.seq },
      `, recorded by ${a.authors.join(", ")} at ${a.at}${history.length ? "; it replaces " : ""}`,
      ...history.flatMap((h, i): Span[] => [...(i ? [", "] : []), { e: h.seq }]),
      history.length ? ` (superseded${a.because ? `: ${a.because}` : ""}; kept in Appendix A)` : "",
      ".",
    ],
  });
  body.push(...downgradeBlocks(a, run));
  body.push(...answerSteps(a, s, run, memo));
  return { k: "box", cls: "answer", id: questionAnchor(q.id), level: 3, title, chips: [questionStatus_(q, run, memo).status], body };
}

/** The premise register, read from the question chain with the ledger beside it; none on a run from before it. */
function premisesOf(run: Run): PremiseView[] {
  const snap = run.register?.snap;
  if (!snap?.state.premises.size) return [];
  return premiseViews({ questions: snap, ledger: { entries: run.entries, replaced: run.replaced } as never });
}

/**
 * The premises the case took (docs/adr/0011, "Premises"): each whole, its
 * class (a given, a supplied assertion, a proposition under test), its
 * revision, where its words stand, its scope, who designated it, and the
 * answers that cite it. Nothing on a run with none.
 */
function premisesTable(run: Run): Block[] {
  const premises = premisesOf(run);
  if (!premises.length) return [];
  return [
    { k: "h", level: 3, text: "The premises the examination took" },
    { k: "p", s: ["A given was designated by the operator (the goal or the register) and is not proved again; a supplied assertion is assumed as asserted, not as established; a proposition under test (an agent's, not admitted) is assumed only conditionally. Each answer below says which premises it rests on and how."] },
    {
      k: "table",
      cls: "premises",
      head: ["Premise", "Class", "Words (verbatim)", "Where", "Scope", "Designated by", "Cited by"],
      rows: premises.map((p): Span[][] => [
        [`${p.id} (revision ${p.rev})${p.withdrawn ? ", withdrawn" : ""}`],
        [classWords(p.class)],
        [p.text],
        [p.locator || "not said"],
        [scopeWords(p.scope)],
        [p.author],
        p.cited_by.length ? p.cited_by.flatMap((c, i): Span[] => [i ? "; " : "", { e: c.answer }, ` ${c.conditional ? "assuming it" : c.stance}${c.current ? "" : ` (revision ${c.rev})`}`]) : ["no standing answer"],
      ]),
    },
  ];
}

/** An entry, a request or a lead, as a span: an entry is linked to its exhibit. */
function refSpan(r: string): Span {
  return /^E-\d+$/.test(r) ? { e: Number(r.slice(2)) } : { code: r };
}

/**
 * An answer's claim and open-part rows (docs/adr/0013, "Claim and open-part
 * rows"), against the question's revision it answers, and each part a
 * review says the answer leaves out. Nothing on an answer without them.
 */
function partsBlocks(a: LedgerEntry, q: Question, run: Run): Block[] {
  const out: Block[] = [];
  const standing = partsOf(a, run);
  if (standing) {
    const v = q.reg ? run.register?.byId.get(q.reg) : undefined;
    const asked = v?.revisions.find((r) => r.rev === (a.question_rev ?? 1))?.text ?? q.text;
    out.push({ k: "p", s: [`Part by part, as the answer reads revision ${a.question_rev ?? 1} of the question${asked ? ` ("${asked}")` : ""}:`] });
    out.push({
      k: "table",
      cls: "parts",
      head: ["Part", "What it asks", "Status", "Rests on, or what bounds it"],
      // A review's not_asked mark beside the part it marks: a limitation, not an open part; the answer stands as recorded.
      rows: standing.rows.map((p): Span[][] => [[p.id], [p.part], [p.status === "limited" ? "at the limit of the evidence" : p.status, ...notAskedSpans(p.not_asked_by)], partRefSpans(p)]),
    });
  }
  const omitted = answerReviews(a, run.attestations).flatMap((x) => (x.answer_review?.parts ?? []).filter((p) => p.missing).map((p) => ({ by: x.by, part: p.part, why: p.why })));
  if (omitted.length) out.push({ k: "note", s: [`A review says the answer leaves out ${omitted.length === 1 ? "a part" : "parts"} of the question: ${omitted.map((x) => `"${x.part}" (${x.by}: ${x.why})`).join("; ")}. It stays here until the answer is recorded again with ${omitted.length === 1 ? "it" : "them"}.`] });
  // A part a review says the question does not ask (not_asked) that names none of the answer's rows (or an answer without rows): said apart, never dropped.
  const unasked = standing
    ? standing.unmatched.map((m) => ({ by: m.by, id: m.id, part: m.part, why: m.why }))
    : answerReviews(a, run.attestations).flatMap((x) => (x.answer_review?.parts ?? []).filter((p) => p.not_asked).map((p) => ({ by: x.by, id: p.id, part: p.part, why: p.why })));
  if (unasked.length) out.push({ k: "note", s: [`A review says ${unasked.length === 1 ? "a part" : "parts"} the answer holds ${unasked.length === 1 ? "is" : "are"} outside what the question asks: ${unasked.map((x) => `${x.id ? `${x.id} ` : ""}"${x.part}" (${x.by}: ${x.why})`).join("; ")}. Such a part is a limitation, not an open part; the answer stands as recorded.`] });
  return out;
}

/** The reviews that mark a part not asked by the question, beside it. */
function notAskedSpans(by: PartsStanding["rows"][number]["not_asked_by"]): Span[] {
  return by.length ? [`; not asked by the question, as ${by.length === 1 ? "a review marks it" : "reviews mark it"}: ${by.map((x) => `${x.by} (${x.why})`).join("; ")}`] : [];
}

/** What a part rests on; or what bounds it, or shows it is at the limit of the evidence (and whether another seat reviewed that), and what it rests on so far. */
function partRefSpans(p: PartsStanding["rows"][number]): Span[] {
  if (p.status === "established") return (p.refs ?? []).flatMap((r, i): Span[] => [i ? ", " : "", refSpan(r)]);
  const soFar: Span[] = p.refs?.length ? [" (so far ", ...p.refs.flatMap((r, i): Span[] => [i ? ", " : "", refSpan(r)]), ")"] : [];
  if (p.status === "limited") return [refSpan(p.limited_by ?? "?"), p.bound ? (p.bound.reviewed ? `, reviewed by ${p.bound.by.join(", ")}` : `, not yet reviewed by another seat (${p.bound.why ?? "no review"})`) : "", ...soFar];
  return [refSpan(p.open_by ?? "?"), ...soFar];
}

/** An answer's parts as its reviews weigh them, with each limited part's bound and whether another seat reviewed it. */
function partsOf(a: LedgerEntry, run: Run): PartsStanding | null {
  return answerPartsStanding(a, run.attestations, { entries: run.entries, disputes: run.disputes });
}


/**
 * The plain line a partial answer leads with (docs/adr/0013, "What the
 * report shows of an answer's parts"): how many of the parts the question
 * asks are established, how many are open and how many of those a review
 * marks not asked; and, when every asked part is established, that it is,
 * beside the label, which is the recorder's and unchanged. A part held at
 * the limit of the evidence is counted apart ("A part at the limit of the
 * evidence"). Nothing on an answer without rows, or one that is not partial.
 */
function partialLeadBlocks(a: LedgerEntry, run: Run): Block[] {
  if (answerResult(a) !== "partial") return [];
  const s = partsOf(a, run);
  if (!s) return [];
  const plain = partialPlainWords("partial", s);
  return [{ k: "p", s: [{ b: partsSummaryWords(s) }, ...(plain ? [` Partial as recorded, and ${plain}.`] : [])] }];
}

/**
 * The test of what a question presumes (docs/adr/0011, "What a question
 * presumes"): what it presumes, then each test on the record (the answer's
 * own, each review's), what it showed and on what; for an established or
 * partial answer with none, that none is recorded. Nothing on a question
 * that presumes nothing, unless the answer carries a test of its own.
 */
function premiseTestBlocks(a: LedgerEntry, v: QuestionView | null, run: Run): Block[] {
  const tests = [...(a.premise_tested ? [{ who: `the answer (${a.authors.join(", ")})`, t: a.premise_tested }] : []), ...answerReviews(a, run.attestations).flatMap((x) => (x.answer_review?.premise_tested ? [{ who: `${x.by}'s review`, t: x.answer_review.premise_tested }] : []))];
  const p = v?.presumption ?? null;
  if (!p && !tests.length) return [];
  const result = answerResult(a);
  return [
    {
      k: "p",
      s: [
        { b: "Premise tested" },
        p ? `: the question presumes ${presumptionWords(p)}. ` : ": ",
        ...(tests.length
          ? tests.flatMap((x, i): Span[] => [i ? "; " : "", `by ${x.who}, against "the question's premise is not supported": ${x.t.outcome} (`, ...x.t.refs.flatMap((r, j): Span[] => [j ? ", " : "", refSpan(r)]), ")"])
          : [result === "established" || result === "partial" || result === null ? "No test of that premise is on the record: neither the answer nor a review of it tests whether it happened." : "No test of that premise is on the record."]),
        tests.length ? "." : "",
      ],
    },
  ];
}

/** An answer's parts in its §2 chain: a partial answer's plain line, then each part, established on what it rests on or open with what bounds it, with the reviews that mark it not asked. Nothing on an answer without rows. */
function chainPartsBlocks(a: LedgerEntry, run: Run): Block[] {
  const s = partsOf(a, run);
  if (!s) return [];
  const partial = answerResult(a) === "partial";
  const plain = partialPlainWords(answerResult(a), s);
  return [
    { k: "p", s: [{ b: "Parts" }, ...(partial ? [`: ${partsSummaryWords(s)}${plain ? ` Partial as recorded, and ${plain}.` : ""}`] : [])] },
    { k: "list", items: s.rows.map((p): Span[] => [{ code: p.id }, ` ${p.part}: ${p.status === "established" ? "established on " : p.status === "limited" ? "at the limit of the evidence, shown by " : "open, bounded by "}`, ...partRefSpans(p), ...notAskedSpans(p.not_asked_by)]) },
  ];
}

/**
 * The premises an answer cites, each with its stance: what it assumes (a
 * conditional assumption said as "assuming P-n": the answer holds only if
 * the premise does), what it supports or contradicts and on which entries,
 * what it leaves unresolved. Nothing on an answer that cites none.
 */
function premiseBlocks(a: LedgerEntry, run: Run): Block[] {
  if (!a.premises?.length) return [];
  const reg = run.register?.snap.state.premises;
  return [
    {
      k: "rows",
      rows: a.premises.map((c): Row => {
        const p = reg?.get(c.id);
        const words = p ? `"${p.revisions.find((r) => r.rev === c.rev)?.text ?? p.text}" (${classWords(p.class)})` : "";
        const refs = (c.refs ?? []).flatMap((r, i): Span[] => [i ? ", " : "", refSpan(r)]);
        const how =
          c.stance === "assumed"
            ? c.conditional
              ? `assuming ${c.id}: the answer holds only if it does`
              : p?.class === "supplied_assertion"
                ? `rests on it as asserted (${p.locator}), not as established`
                : "rests on it as given"
            : c.stance === "supported"
              ? "the evidence supports it, on "
              : c.stance === "contradicted"
                ? refs.length
                  ? "the evidence contradicts it, on "
                  : "the answer says the evidence contradicts it (no finding named)"
                : "unresolved: the evidence does not settle it";
        return { label: `${c.id} (revision ${c.rev})`, s: [`${words ? `${words}: ` : ""}${how}`, ...(c.stance === "supported" || (c.stance === "contradicted" && refs.length) ? refs : []), ...(c.scope ? [` (for ${scopeWords(c.scope)})`] : [])] };
      }),
    },
  ];
}

/**
 * Each downgrade in a question's answer chain (an answer moved from
 * established or partial to not determinable or a bounded negative): the
 * earlier answer, the disputes raised on it, and the counter-evidence the
 * downgrade names. A reader sees why the answer went down, never only that
 * it did.
 */
function downgradeBlocks(a: LedgerEntry, run: Run): Block[] {
  const out: Block[] = [];
  let cur: LedgerEntry | undefined = a;
  while (cur) {
    const prev: LedgerEntry | undefined = cur.supersedes !== undefined ? run.bySeq.get(cur.supersedes) : undefined;
    if (cur.downgrade && prev) {
      const hash = entryHash(prev);
      const raised = run.disputes.filter((d) => d.act === "dispute" && d.target === hash);
      out.push({
        k: "rows",
        rows: [
          { label: "Downgraded", s: [{ e: cur.seq }, ` moved the answer from ${resultWords(answerResult(prev))} (`, { e: prev.seq }, `) to ${resultWords(answerResult(cur))}`] },
          { label: "Counter-evidence", s: [...cur.downgrade.evidence.flatMap((r, i): Span[] => [...(i ? [", "] : []), /^E-\d+$/.test(r) ? { e: Number(r.slice(2)) } : { code: r }]), `: ${cur.downgrade.why}`] },
          { label: "Disputes of the earlier answer", s: [raised.length ? raised.map((d) => `${d.by}: ${d.why}`).join("; ") : "none"] },
        ],
      });
    }
    cur = prev?.kind === "answer" ? prev : undefined;
  }
  return out;
}

/**
 * What an answer's result says, and for a negative what it rests on (the
 * negative bar): its coverage records, each as the hub found it, the
 * planned routes nothing examined, and who reviewed it. A bounded negative
 * reads "No evidence of <the proposition> was found in <the objects and the
 * time range>"; "it did not happen" is kept for an answer that earned it
 * (an existence question, a complete coverage record, a trace expected).
 */
/** A proposition as the object of a sentence: its closing stop dropped, a leading article lowercased. */
function propositionWords(value: string): string {
  return value.trim().replace(/\.$/, "").replace(/^(A|An|The) /, (x) => x.toLowerCase());
}

/** The coverage records an answer rests on that stand, and what they searched. */
function standingCoverage(a: LedgerEntry, run: Run): LedgerEntry[] {
  return (a.support ?? []).map((x) => run.bySeq.get(x.seq)).filter((e): e is LedgerEntry => e?.kind === "coverage" && !run.replaced.has(e.seq));
}

const coverageScope = (c: LedgerEntry) => `${(c.refs ?? []).join(", ")}${c.time_range ? `, ${c.time_range}` : ""}`;

/**
 * A negative's conclusion as the report states it: made from the coverage
 * records it rests on (their propositions and their scope), never from the
 * agents' words, which no phrase list can hold to the bar. Null for an
 * answer that is not a negative, and for a bounded negative that earned
 * "it did not happen" (an existence question, a complete coverage record
 * that says the event would have left a trace, asserts_absence).
 */
function boundedConclusion(a: LedgerEntry, q: Question, run: Run): string | null {
  const result = answerResult(a);
  if (!result || !NEGATIVE_RESULTS.has(result)) return null;
  const cov = standingCoverage(a, run);
  const earned = result === "bounded_negative" && a.asserts_absence === true && run.bar(q.id).existence && cov.some((c) => c.coverage === "complete" && c.detection_opportunity?.trace_expected === "yes");
  if (earned) return null;
  const what = cov.map((c) => propositionWords(c.value)).join("; ");
  const where = cov.map(coverageScope).join("; ");
  if (result === "bounded_negative") return cov.length ? `No evidence that ${what} was found in ${where}.` : "No evidence was found; the answer names no coverage record, so what was searched is not stated.";
  return cov.length ? `It cannot be determined from ${where} whether ${what}.` : "It cannot be determined from the evidence examined; the answer names no coverage record, so what was examined is not stated.";
}

function resultBlocks(a: LedgerEntry, q: Question, run: Run): Block[] {
  const result = answerResult(a);
  if (!result) return [{ k: "note", s: ["The answer states no result: it was recorded before results were, and reads as it always did."] }];
  const out: Block[] = [];
  const cov = standingCoverage(a, run);
  const scope = coverageScope;
  const earned = a.asserts_absence === true && run.bar(q.id).existence && cov.some((c) => c.coverage === "complete" && c.detection_opportunity?.trace_expected === "yes");
  if (result === "bounded_negative") {
    out.push({
      k: "p",
      s: earned
        ? [`Result: it did not happen, as the answer says. The bar for saying so is met: the question asks whether it exists, `, ...cov.filter((c) => c.coverage === "complete").flatMap((c, i): Span[] => [i ? ", " : "", { e: c.seq }]), " is complete, and says the event would have left a trace there."]
        : cov.length
          ? [`Result: no evidence that ${cov.map((c) => propositionWords(c.value)).join("; ")} was found in ${cov.map(scope).join("; ")}. This is a bounded negative: it says what was not found where, not that it did not happen.`]
          : ["Result: a bounded negative (no evidence found), with no coverage record naming its scope."],
    });
  } else out.push({ k: "p", s: [`Result: ${resultWords(result)}.`] });
  for (const c of cov) {
    out.push({
      k: "rows",
      rows: [
        { label: "Coverage record", s: [{ e: c.seq }, `: ${c.value}`] },
        { label: "Objects and time", s: [scope(c)] },
        { label: "Method", s: [`${c.search_method ?? ""} (${c.settings ?? ""})`] },
        { label: "Covered, skipped, failed", s: [`${c.coverage_actual ?? ""}; skipped: ${c.skipped ?? ""}; failures: ${c.failures ?? ""}`] },
        { label: "Detection opportunity", s: [`trace expected ${c.detection_opportunity?.trace_expected ?? "?"}: ${c.detection_opportunity?.why ?? ""}`] },
        { label: "Alternatives open", s: [c.alternatives_open ?? ""] },
        { label: "Computed by the hub", s: [`coverage ${c.coverage ?? "not computed"}${c.coverage_detail?.why.length ? `: ${c.coverage_detail.why.join("; ")}` : ""}${c.coverage_detail?.jobs.length ? ` (jobs ${c.coverage_detail.jobs.join(", ")})` : ""}`] },
        ...(c.not_examined?.length ? [{ label: "Planned, not examined", s: [c.not_examined.map((r) => `${r.source} (${r.method}): ${r.why}`).join("; ")] }] : []),
        ...(c.looked_for?.length
          ? [{ label: "Looked for", s: [c.looked_for.map((t) => `"${t}"`).join(", ")] } as Row, { label: "Store sweep (by the hub)", s: [sweepWords(sweepOf({ hash: entryHash(c) }, run.sweeps), c)] } as Row]
          : c.looked_for_none_why
            ? [{ label: "Looked for", s: [`no literal form: ${c.looked_for_none_why}`] } as Row]
            : []),
      ],
    });
  }
  if (NEGATIVE_RESULTS.has(result)) {
    const r = negativeReview(a, run.entries, run.attestations, run.disputes);
    out.push(
      r.reviewed
        ? { k: "p", s: [`Reviewed by ${r.by.join(", ")}: ${r.reviews.map((x) => negativeReviewWords(x.review)).join(" / ")}.`] }
        : { k: "note", s: [run.bar(q.id).material ? "Negative (unreviewed): no seat other than its authors has reviewed it; the finish line held the run for it." : "Not reviewed by another seat (a background question: the finish line does not wait for it)."] },
    );
  }
  return out;
}

/** The fixed block after the answer: eight steps, always in this order, each saying so when it has nothing. */
function answerSteps(a: LedgerEntry, s: EntryState, run: Run, memo: Map<number, EntryState>): Block[] {
  const out: Block[] = [];
  const support = (a.support ?? []).map((x) => run.bySeq.get(x.seq)).filter((x): x is LedgerEntry => Boolean(x));
  const standing = support.filter((e) => !run.replaced.has(e.seq));
  const history = support.filter((e) => run.replaced.has(e.seq));
  const qualified = new Map((a.qualifies ?? []).map((q) => [Number(q.ref.replace(/^E-/i, "")), q.why]));
  const edgeNote = (edge: LedgerEdge | undefined, e: LedgerEntry): Row[] => (edge && edge.hash !== entryHash(e) ? [{ label: "Cited hash", s: [`${edge.hash}, which is not this entry's: the answer cites another version of it`] }] : []);

  // 1. How it was obtained.
  out.push({ k: "h", level: 4, text: STEPS[0] });
  const tally = new Map<string, number>();
  for (const e of standing) tally.set(basisWords(e, run), (tally.get(basisWords(e, run)) ?? 0) + 1);
  out.push({
    k: "p",
    s: [`It rests on ${plural(standing.length, "entry", "entries")}${standing.length ? `: ${[...tally.entries()].map(([k, n]) => `${n} ${k}`).join(", ")}` : ""}.${history.length ? ` It also cites ${plural(history.length, "superseded entry", "superseded entries")} for their history, each with its correction; those support nothing.` : ""}`],
  });
  for (const e of standing) {
    const extra: Row[] = [...edgeNote(a.support?.find((x) => x.seq === e.seq), e)];
    if (qualified.has(e.seq)) extra.push({ label: "Cited with", s: [`a qualification: ${qualified.get(e.seq)}`] });
    if (e.kind === "answer") extra.push({ label: "Its own block", s: [e.section?.startsWith("question:") ? { a: `#${questionAnchor(sectionAnswersId(e.section))}`, text: `§5, ${sectionName(e.section)}` } : `§${e.section === "narrative" ? "6" : "1"}`] });
    out.push(citeBlock(e, run, memo, extra));
  }
  for (const e of history) out.push(citeBlock(e, run, memo, [{ label: "History only", s: ["superseded by ", { e: stateOf(e, run, memo).supersededBy as number }, "; cited for what it said, not as support"] }]));

  // 2. What it indicates.
  out.push({ k: "h", level: 4, text: STEPS[1] });
  out.push({ k: "voice", voice: "interpretation", label: "The author's reasoning", s: [a.reasoning ?? "(no reasoning recorded)"] });
  const findings = standing.filter((e) => e.kind === "finding");
  if (findings.length) {
    out.push({
      k: "list",
      items: findings.map((e): Span[] => [{ e: e.seq }, interpretationMissing(e) ? " — " : " indicates: ", interpretationMissing(e) ? { chip: { text: "interpretation not recorded", tone: "none" } } : e.indicates ?? "(no interpretation recorded)", ...(e.significance ? [` Its finder's view of what it means for the case: ${e.significance}`] : [])]),
    });
  }

  // 3. Why this confidence.
  out.push({ k: "h", level: 4, text: STEPS[2] });
  out.push({ k: "p", s: s.confidence.recorded ? [{ b: `Confidence ${s.confidence.recorded}. ` }, ...(s.confidence.legacy ? [`As its author declared it: the answer was recorded before the run recorded confidence (a high kept only on an established answer attested established with its alternatives), so it is shown as declared. `] : s.confidence.stated !== s.confidence.recorded ? [`Its author stated ${s.confidence.stated}; the run records ${s.confidence.recorded}: ${s.confidence.why}. `] : []), a.confidence_why ?? "The author gave no reason."] : ["The author gave no confidence."] });
  out.push({ k: "voice", voice: "computed", label: VOICE_LABEL.computed, s: [groupsSentence(s.groups)] });
  if (s.groups.length) out.push({ k: "list", items: groupItems(s.groups) });
  const rated = standing.filter((e) => e.confidence);
  if (rated.length) out.push({ k: "list", items: rated.map((e): Span[] => [{ e: e.seq }, ` ${e.confidence}: `, e.confidence_why ?? (e.kind === "answer" ? "see its own block" : "the finder gave no reason (recorded before findings said why)")]) });
  out.push({
    k: "list",
    items: [
      [s.attests.length ? s.attests.map((x) => `Attested by ${x.by}${x.how ? `: ${x.how}` : ""}.`).join(" ") : "Not attested: no agent other than its author re-derived what it rests on."],
      [s.review || s.reviewUnreadable ? `The examiner's word: ${reviewWords(run, s)}.` : "Not independently reviewed: no human has checked it."],
    ],
  });

  // 4. What else could explain it.
  out.push({ k: "h", level: 4, text: STEPS[3] });
  out.push({ k: "p", s: [{ b: "Still open, as the author sees it: " }, a.alternatives_open ?? "not recorded."] });
  const alts: Span[][] = [];
  for (const e of [...standing, ...history].filter((x) => x.kind === "finding")) {
    for (const alt of e.alternatives ?? []) alts.push([{ e: e.seq }, `: ${alt.explanation} — ${alt.status === "rejected" ? "rejected" : "still open"}: ${alt.why}${alt.test_refs?.length ? ` (tested with ${alt.test_refs.join(", ")})` : ""}`]);
    if (e.alternatives_none_why) alts.push([{ e: e.seq }, `: no alternative considered — ${e.alternatives_none_why}`]);
    if (e.basis === "inferred" && !e.alternatives?.length && !e.alternatives_none_why) alts.push([{ e: e.seq }, ": inferred, and no alternative was recorded"]);
  }
  if (alts.length) out.push({ k: "list", items: alts });

  // 5. Contrary evidence.
  out.push({ k: "h", level: 4, text: STEPS[4] });
  const contrary = (a.contrary ?? []).map((x) => run.bySeq.get(x.seq)).filter((x): x is LedgerEntry => Boolean(x));
  const supportSeqs = new Set(support.map((e) => e.seq));
  const againstSupport = standingContradictions(run.entries).filter((c) => (supportSeqs.has(c.from) || supportSeqs.has(c.to)) && !contrary.some((x) => x.seq === c.from || x.seq === c.to));
  const disputedSupport = standing.filter((e) => stateOf(e, run, memo).disputes.length);
  if (!contrary.length && !againstSupport.length && !disputedSupport.length && !s.disputes.length) out.push({ k: "p", s: ["None recorded. That is what the ledger holds, not proof that none exists."] });
  for (const e of contrary) out.push(citeBlock(e, run, memo, [...edgeNote(a.contrary?.find((x) => x.seq === e.seq), e), ...(e.indicates ? [{ label: "Indicates", voice: "interpretation", s: [e.indicates] } as Row] : [])]));
  for (const c of againstSupport) out.push({ k: "p", s: [{ e: c.from }, " contradicts ", { e: c.to }, "; both stand, and the answer does not cite the contradiction as contrary evidence."] });
  for (const e of disputedSupport) {
    for (const d of stateOf(e, run, memo).disputes) out.push({ k: "p", s: [{ e: e.seq }, ` is disputed by ${d.by}: ${d.why}. `, qualified.has(e.seq) ? `The answer cites it qualified: ${qualified.get(e.seq)}.` : "The answer does not qualify it."] });
  }
  for (const d of s.disputes) out.push({ k: "p", s: [{ b: "The answer itself is disputed " }, `by ${d.by}: ${d.why}.`] });
  // Evidence added late and weighed against the answer by a delta that neither supports nor contradicts it (docs/adr/0013, "Late evidence: the reverse sweep and the delta"): said, so an "irrelevant" or an "inconclusive" is read where the answer is (the Fable review of the limits branch, P3-1).
  const weighed = run.entries
    .filter((e) => !run.replaced.has(e.seq))
    .flatMap((e) => (e.rel ?? []).filter((r) => LATE_DELTA_WORDS[r.kind] && run.bySeq.get(r.to)?.kind === "answer" && run.bySeq.get(r.to)?.section === a.section).map((r) => ({ e, r })));
  if (weighed.length) {
    out.push({ k: "p", s: ["Evidence added late, weighed against the answer, neither supporting nor contradicting it:"] });
    out.push({ k: "list", items: weighed.map(({ e, r }): Span[] => [{ e: e.seq }, ` on `, { e: r.to }, `: ${LATE_DELTA_WORDS[r.kind]}${e.value ? ` (${e.value})` : ""}`]) });
  }

  // 6. Limitations.
  out.push({ k: "h", level: 4, text: STEPS[5] });
  const cited = (a.limitations ?? []).map((x) => run.bySeq.get(x.seq)).filter((x): x is LedgerEntry => Boolean(x));
  const id = a.section?.startsWith("question:") ? sectionAnswersId(a.section) : null;
  const alsoLimits = run.entries.filter(
    (l) => l.kind === "limitation" && !run.replaced.has(l.seq) && !cited.some((c) => c.seq === l.seq) && (((id !== null) && (l.answers ?? []).some((x) => sectionKey(x) === id)) || [...limitationCites(l)].some((n) => supportSeqs.has(n) || n === a.seq)),
  );
  let any = false;
  for (const l of cited) {
    out.push(citeBlock(l, run, memo, [{ label: "Reason", s: [(l.reason ?? "not given").replace(/_/g, " ")] }]));
    any = true;
  }
  for (const l of alsoLimits) {
    out.push(citeBlock(l, run, memo, [{ label: "Reason", s: [(l.reason ?? "not given").replace(/_/g, " ")] }, { label: "Note", s: ["recorded for this question or what it rests on; the answer does not cite it"] }]));
    any = true;
  }
  const failedSupport = standing.filter((e) => stateOf(e, run, memo).failed.length);
  for (const e of failedSupport) {
    const st = stateOf(e, run, memo);
    out.push({
      k: "p",
      s: [
        { e: e.seq },
        ` rests on the kept output of a job that did not succeed (${st.failed.map((f) => `${f.ref}: job ${f.status}`).join("; ")}). `,
        (e.qualifies ?? []).length ? `Why those bytes still hold, as its finder says: ${(e.qualifies ?? []).map((q) => `${q.ref}: ${q.why}`).join("; ")}.` : "Its finder does not say why those bytes still hold.",
        " Such output can support a qualified positive, never a claim that something is absent.",
      ],
    });
    any = true;
  }
  if (a.unsupported_tokens?.length) {
    out.push(tokensNote(a));
    any = true;
  }
  if (s.problems.length) {
    out.push(problemNote(a, s, run));
    any = true;
  }
  if (!any) out.push({ k: "p", s: ["None recorded for this answer."] });

  // 7. What would change it.
  out.push({ k: "h", level: 4, text: STEPS[6] });
  out.push({ k: "p", s: [a.would_change ?? "Not recorded."] });

  // 8. Exhibits.
  out.push({ k: "h", level: 4, text: STEPS[7] });
  const all = [a, ...support, ...contrary, ...cited, ...alsoLimits];
  const seen = new Set<number>();
  const listed = all.filter((e) => (seen.has(e.seq) ? false : (seen.add(e.seq), true)));
  const notCited = id === null ? [] : run.entries.filter((e) => !seen.has(e.seq) && !run.replaced.has(e.seq) && e.kind !== "answer" && (e.answers ?? []).some((x) => sectionKey(x) === id));
  out.push({ k: "list", items: listed.map((e): Span[] => citeHead(e)) });
  if (notCited.length) out.push({ k: "p", s: ["Also recorded for this question, not cited by the answer: ", ...notCited.flatMap((e, i): Span[] => [...(i ? [", "] : []), { e: e.seq }]), "."] });
  return out;
}

function unansweredBody(q: Question, run: Run, memo: Map<number, EntryState>): Block[] {
  const out: Block[] = [];
  out.push({ k: "note", s: [run.era === "predates" ? "No structured answer: the run predates answers in the ledger." : "No answer was recorded for this question."] });
  const named = run.entries.filter((e) => !run.replaced.has(e.seq) && e.kind !== "answer" && (e.answers ?? []).some((x) => sectionKey(x) === q.id));
  const limits = named.filter((e) => e.kind === "limitation");
  const rest = named.filter((e) => e.kind !== "limitation");
  out.push({ k: "h", level: 4, text: "What the ledger holds for it" });
  if (rest.length) {
    out.push({ k: "p", s: [`${plural(rest.length, "entry", "entries")} ${rest.length === 1 ? "names" : "name"} this question; ${rest.length === 1 ? "it is" : "each is"} whole in Appendix A.`] });
    for (const e of rest) out.push(citeBlock(e, run, memo, e.indicates ? [{ label: "Indicates", voice: "interpretation", s: [e.indicates] }] : [], true));
  }
  else out.push({ k: "p", s: ["No finding, event or search names this question."] });
  out.push({ k: "h", level: 4, text: "Limitations" });
  if (limits.length) for (const l of limits) out.push(citeBlock(l, run, memo, [{ label: "Reason", s: [(l.reason ?? "not given").replace(/_/g, " ")] }], true));
  else out.push({ k: "p", s: ["None recorded for this question."] });
  out.push({ k: "h", level: 4, text: "What would answer it" });
  out.push({ k: "p", s: [limits.length ? "The limitations above say what was not available or not examined; that is what would answer it." : "The ledger does not say."] });
  return out;
}

function narrativeSection(run: Run, memo: Map<number, EntryState>): BodySection {
  const blocks: Block[] = [];
  const n = standingAnswer(run, "narrative");
  if (n) {
    const s = stateOf(n, run, memo);
    const history = answerHistory(run, "narrative").filter((x) => x.seq !== n.seq);
    blocks.push({ k: "voice", voice: "opinion", label: "What happened, as the swarm tells it", s: [n.value], chips: chipsOf(n, s).filter((c) => c.text !== "answer") });
    blocks.push({ k: "voice", voice: "interpretation", label: "In order, with its exhibits", s: [n.reasoning ?? ""] });
    blocks.push({ k: "p", s: [{ e: n.seq }, `, recorded by ${n.authors.join(", ")} at ${n.at}${history.length ? "; it replaces " : ""}`, ...history.flatMap((h, i): Span[] => [...(i ? [", "] : []), { e: h.seq }]), history.length ? ` (superseded${n.because ? `: ${n.because}` : ""})` : "", "."] });
    if ((n.qualifies ?? []).length) blocks.push({ k: "list", items: (n.qualifies ?? []).map((q): Span[] => [`${q.ref} is cited qualified: ${q.why}`]) });
    if (s.problems.length) blocks.push(problemNote(n, s, run));
    if (n.unsupported_tokens?.length) blocks.push(tokensNote(n));
    blocks.push({ k: "voice", voice: "computed", label: VOICE_LABEL.computed, s: [groupsSentence(s.groups)] });
  } else {
    blocks.push({ k: "note", s: [run.era === "predates" ? "This run predates structured answers: the timeline below is the ledger's dated events, in order." : "No narrative answer was recorded: the timeline below is the ledger's dated events, in order, without the swarm's account of them."] });
  }
  const events = run.entries.filter((e) => e.kind === "event").sort((a, b) => (a.ts ?? "").localeCompare(b.ts ?? "") || a.seq - b.seq);
  blocks.push({ k: "h", level: 3, text: "Timeline" });
  if (events.length) {
    // A rail rather than a table: a four-column table of long forensic
    // strings does not fit a phone or an A4 column (report.ts's timeline).
    blocks.push({
      k: "timeline",
      rows: events.map((e) => {
        const s = stateOf(e, run, memo);
        const given = givenTime(e);
        return {
          seq: e.seq,
          when: `${whenText(e)}${given ? ` (as given: ${given})` : ""}`,
          what: [e.value, ...(s.supersededBy !== undefined ? [" ", { chip: { text: `superseded by E-${s.supersededBy}`, tone: "brick" } } as Span] : []), ...(e.basis ? [" ", { chip: { text: e.basis, tone: e.basis === "observed" ? "slate" : "saffron" } } as Span] : [])],
          meta: `clock: ${e.clock ?? "not recorded"}; precision: ${e.precision ?? "not recorded"}`,
        };
      }),
    });
  } else blocks.push({ k: "p", s: ["No dated events were recorded, so this report has no timeline."] });
  blocks.push({ k: "h", level: 3, text: "Clocks and precision" });
  blocks.push({ k: "voice", voice: "computed", label: VOICE_LABEL.computed, s: [clockParagraph(events)] });
  return { id: "s6", n: "6", title: "What happened", desc: "the swarm's account, the timeline, and how far its times can be trusted", count: plural(events.length, "event"), blocks };
}

function clockParagraph(events: LedgerEntry[]): string {
  if (!events.length) return "With no dated events, there are no clocks to weigh.";
  const tally = (f: (e: LedgerEntry) => string) => {
    const m = new Map<string, number>();
    for (const e of events) m.set(f(e), (m.get(f(e)) ?? 0) + 1);
    return [...m.entries()].sort((a, b) => b[1] - a[1] || a[0].localeCompare(b[0])).map(([k, n]) => `${k} (${n})`).join(", ");
  };
  const converted = events.filter((e) => givenTime(e) !== null).length;
  const dated = events.filter((e) => e.ts).sort((a, b) => (a.ts ?? "").localeCompare(b.ts ?? ""));
  return [
    `${plural(events.length, "dated event")}${dated.length ? `, from ${whenText(dated[0])} to ${whenText(dated.at(-1) as LedgerEntry)}` : ""}.`,
    `Clocks named: ${tally((e) => e.clock ?? "not recorded")}.`,
    `Precision: ${tally((e) => e.precision ?? "not recorded")}.`,
    converted ? `${plural(converted, "time was", "times were")} given with an offset or a zone and converted to UTC; the source's own words are shown beside ${converted === 1 ? "it" : "them"}.` : "",
    "Every time is in UTC as the ledger holds it, and is no more precise than its precision says: a date alone is a day, not midnight.",
    "Times read from different clocks are compared here as they were recorded: nothing in the ledger says those clocks agreed with each other, so an order between events from different clocks closer than their clocks' possible drift is not established.",
  ]
    .filter(Boolean)
    .join(" ");
}

function conclusionsSection(run: Run, memo: Map<number, EntryState>): BodySection {
  const blocks: Block[] = [];
  blocks.push({ k: "p", lede: true, s: ["What follows are opinions: conclusions the swarm drew from the entries they cite, not observations. Each is given with its basis, so a reader can weigh the one against the other."] });
  const answers = [...run.questions.map((q) => ({ label: questionName(q), a: standingAnswer(run, `question:${q.id}`) })), { label: "Summary", a: standingAnswer(run, "summary") }].filter((x): x is { label: string; a: LedgerEntry } => Boolean(x.a));
  for (const { label, a } of answers) {
    const s = stateOf(a, run, memo);
    const basis = (a.support ?? []).map((x) => run.bySeq.get(x.seq)).filter((x): x is LedgerEntry => Boolean(x));
    blocks.push({ k: "voice", voice: "opinion", label, s: [a.value], chips: chipsOf(a, s).filter((c) => c.text !== "answer" && c.text !== "opinion") });
    blocks.push({
      k: "p",
      s: [
        "Basis: ",
        ...basis.flatMap((e, i): Span[] => [
          ...(i ? ["; "] : []),
          { e: e.seq },
          ` (${e.kind === "answer" || e.kind === "absence" || e.kind === "limitation" ? basisWords(e, run) : `${KIND_LABEL[e.kind] ?? e.kind}, ${basisWords(e, run)}`})`,
        ]),
        basis.length ? "." : "no entry.",
        s.confidence.recorded ? ` Confidence ${confidenceWords(s.confidence)}${a.confidence_why ? `: ${a.confidence_why}` : "."}` : "",
      ],
    });
  }
  if (!answers.length) blocks.push({ k: "note", s: [run.hasAnswers || run.era !== "predates" ? "No question has a standing answer, so the swarm offers no conclusion here." : "This run predates structured answers: its conclusions are in the working report (Appendix C), without the ledger's check."] });
  const significant = run.entries.filter((e) => e.significance && !run.replaced.has(e.seq));
  if (significant.length) {
    blocks.push({ k: "h", level: 3, text: "What finders said their findings mean for the case" });
    for (const e of significant) blocks.push({ k: "voice", voice: "opinion", label: `E-${e.seq}`, s: [e.significance ?? ""] });
  }
  const hypotheses = run.entries.filter((e) => e.kind === "hypothesis" && !run.replaced.has(e.seq));
  if (hypotheses.length) {
    blocks.push({ k: "h", level: 3, text: "Hypotheses" });
    blocks.push({ k: "p", s: ["Propositions the swarm put under test, with the status it last gave each. A hypothesis is not a finding, and a supported one is an assessment."] });
    for (const e of hypotheses) blocks.push(citeBlock(e, run, memo, e.rel?.length ? [{ label: "Related", s: e.rel.flatMap((r, i): Span[] => [...(i ? [", "] : []), `${r.kind.replace(/_/g, " ")} `, { e: r.to }]) }] : []));
  }
  return { id: "s7", n: "7", title: "Conclusions and opinions", desc: "the swarm's conclusions, marked as opinion, with their basis", blocks };
}

/** The five kinds of evidence gap a reader is told apart (docs/adr/0014). */
export type GapClass = "never collected" | "unavailable" | "inaccessible" | "unexamined" | "inconclusive";

/** One evidence gap, generated from the records: what, why, which questions, what it bounds, and what would close it. */
export type EvidenceGap = { cls: GapClass; what: string; source: string; questions: string[]; record: string; consequence: string; next: string };

/**
 * The evidence gaps, generated from the records and never written by hand:
 * acquisition requests that were declined, are still open, or found the
 * source unavailable; evidence that arrived and that no job read;
 * limitations by their reason (unavailable; failed: inaccessible;
 * not_examined, excluded, partial: unexamined); coverage records that are
 * partial or name planned routes nothing examined; answers that are not
 * determinable. A gap bounds what an answer can say; it is never a finding
 * that the thing is absent.
 */
export function gapsOf(run: Run, limits: LedgerEntry[]): EvidenceGap[] {
  const out: EvidenceGap[] = [];
  const qs = (list: string[] | undefined) => [...new Set((list ?? []).map((x) => sectionKey(x)).filter(Boolean))].map((x) => (/^\d+$/.test(x) ? `Q-${x}` : x));
  for (const r of run.contract.requests.filter((x) => x.kind === "acquisition")) {
    const what = r.ask ? `${r.ask.source} (${r.ask.where})` : String(r.line.request ?? "");
    const would = r.ask?.expected_value ?? "";
    const questions = r.questions;
    const base = { what, source: r.rid, questions };
    if (r.stage === "declined") out.push({ ...base, cls: "never collected", record: `${r.rid}, declined by ${r.closed?.by ?? r.stages.at(-1)?.by ?? "the operator"}${r.closed?.cause === "case_policy" ? " (the case policy admits no further evidence)" : ""}`, consequence: `the answers to ${questions.join(", ") || "the questions it bears on"} rest on the evidence the run had; what it would have established (${would || "not said"}) is not known`, next: r.ask?.authority_needed ? `collect it with ${r.ask.authority_needed}, in a run whose policy admits it` : "collect it, in a run whose policy admits it" });
    else if (r.stage === "unavailable") out.push({ ...base, cls: "unavailable", record: `${r.rid}: ${r.closed?.text ?? "unavailable"}`, consequence: `what it would have established (${would || "not said"}) cannot be established from it`, next: "look for a secondary source of the same facts" });
    else if (r.stage === "requested" || r.stage === "authorised" || r.stage === "collecting") out.push({ ...base, cls: "never collected", record: `${r.rid}, still ${r.stage} when this was rendered`, consequence: `the answers to ${questions.join(", ") || "the questions it bears on"} were given without it`, next: `supply it (swarm.sh evidence <run> add PATH --for ${r.rid}) or say it is unavailable` });
    else if (r.stage === "received" || r.stage === "validated") {
      const imp = r.stages.find((x) => x.import)?.import;
      const read = imp ? [...(run.contract.external?.jobs.entries() ?? [])].some(([, via]) => via.some((v) => v.startsWith(`import:${imp}`) && !v.includes("broad scope"))) : false;
      if (imp && !read) out.push({ ...base, cls: "unexamined", record: `${r.rid}, received as import:${imp}; no job declared it as an input`, consequence: "it arrived and nothing shows it was read", next: `run a job over import:${imp}` });
    }
  }
  // Evidence added without a request, and not read by any job.
  for (const m of run.contract.material.filter((x) => x.mode === "evidence" && !x.request)) {
    const imp = String(m.import);
    const read = [...(run.contract.external?.jobs.entries() ?? [])].some(([, via]) => via.some((v) => v.startsWith(`import:${imp}`) && !v.includes("broad scope")));
    if (!read) out.push({ cls: "unexamined", what: `import:${imp} (${String(m.why ?? "")})`, source: `import:${imp}`, questions: (m.questions as string[] | undefined) ?? [], record: `added by ${String(m.supplied_by ?? "the operator")} at ${String(m.at ?? "")}; no job declared it as an input`, consequence: "it arrived and nothing shows it was read", next: `run a job over import:${imp}` });
  }
  const byReason: Record<string, GapClass> = { unavailable: "unavailable", failed: "inaccessible", not_examined: "unexamined", excluded: "unexamined", partial: "unexamined" };
  for (const l of limits) {
    const cls = byReason[l.reason ?? ""];
    if (!cls) continue;
    const names = /\bR-\d+\b/.exec(`${l.value}\n${l.source ?? ""}\n${l.evidence ?? ""}`)?.[0];
    out.push({ cls, what: l.value, source: `E-${l.seq}`, questions: qs(l.answers), record: `limitation E-${l.seq} (${(l.reason ?? "").replace(/_/g, " ")})${names ? `, naming ${names}` : ""}`, consequence: l.reason === "partial" ? "the part not examined bounds what was found" : "what it would have shown is not known", next: l.reason === "failed" ? "another method or tool to read it" : l.reason === "unavailable" ? "a secondary source" : "examine it" });
  }
  for (const c of run.entries.filter((e) => e.kind === "coverage" && !run.replaced.has(e.seq))) {
    if (c.coverage === "partial") out.push({ cls: "unexamined", what: `objects the search of E-${c.seq} named and its jobs were not given${c.coverage_detail?.why?.length ? `: ${c.coverage_detail.why.join("; ")}` : ""}`, source: `E-${c.seq}`, questions: qs(c.answers), record: `coverage record E-${c.seq}, coverage partial (computed by the hub)`, consequence: "the negative holds over the part searched only", next: "give a job every object the record names" });
    for (const r of c.not_examined ?? []) out.push({ cls: "unexamined", what: `${r.source} (${r.method})`, source: `E-${c.seq}`, questions: qs(c.answers), record: `a planned route of coverage record E-${c.seq} nothing examined: ${r.why}`, consequence: "the route planned before the search was not taken", next: "examine the route, or say why it no longer matters" });
  }
  for (const a of run.entries.filter((e) => e.kind === "answer" && !run.replaced.has(e.seq) && (e.result === "not_determinable" || (e.inconclusive && !e.result)))) {
    out.push({ cls: "inconclusive", what: a.value, source: `E-${a.seq}`, questions: qs([sectionAnswersId(a.section ?? "")]), record: `answer E-${a.seq}, not determinable`, consequence: "the question stays open", next: a.would_change ? a.would_change : "what would settle it is not recorded" });
  }
  return out;
}

function evidenceGaps(run: Run, limits: LedgerEntry[]): Block[] {
  const gaps = gapsOf(run, limits);
  const blocks: Block[] = [{ k: "h", level: 3, text: "Evidence gaps and acquisition requests" }];
  blocks.push({ k: "p", s: [`Generated from the records (acquisition requests, limitations, coverage records and answers), never written by hand. A gap bounds what an answer can say; it is never a finding that something is absent. ${run.contract.more_evidence ? `The case policy said of more evidence: ${run.contract.more_evidence}${run.contract.more_evidence === "no" ? " (an acquisition was answered at once, \"no additional input under this case policy\")" : ""}.` : ""}`] });
  const acq = run.contract.requests.filter((r) => r.kind === "acquisition");
  if (acq.length) {
    blocks.push({
      k: "table",
      cls: "gaps",
      head: ["Request", "Source", "Questions", "Would establish", "Urgency", "Stage", "Outcome"],
      rows: acq.map((r): Span[][] => [[r.rid], [r.ask ? `${r.ask.source} (${r.ask.where})` : String(r.line.request ?? "")], [r.questions.join(", ")], [r.ask?.expected_value ?? ""], [r.ask?.urgency ?? ""], [r.stage ?? ""], [r.closed ? `${r.closed.ev} by ${r.closed.by}: ${r.closed.text}` : r.state]]),
    });
  } else blocks.push({ k: "p", s: ["No acquisition was requested."] });
  if (gaps.length) {
    for (const cls of ["never collected", "unavailable", "inaccessible", "unexamined", "inconclusive"] as GapClass[]) {
      const list = gaps.filter((g) => g.cls === cls);
      if (!list.length) continue;
      blocks.push({ k: "h", level: 4, text: `${cls[0].toUpperCase()}${cls.slice(1)} (${list.length})` });
      blocks.push({ k: "list", items: list.map((g): Span[] => [{ b: `${g.what}.` }, ` Record: ${g.record}.${g.questions.length ? ` Questions: ${g.questions.join(", ")}.` : ""} Consequence: ${g.consequence}. Next step: ${g.next}.`]) });
    }
  } else blocks.push({ k: "p", s: ["No gap is recorded: no acquisition was declined or left open, no limitation names an unavailable, inaccessible or unexamined source, and no answer is not determinable. That is what the records say, not a statement that the examination had no limits."] });
  return blocks;
}

function limitsSection(run: Run, memo: Map<number, EntryState>): BodySection {
  const blocks: Block[] = [];
  const out = (e: LedgerEntry, extra: Row[]) => blocks.push(citeBlock(e, run, memo, extra));
  const limits = run.entries.filter((e) => e.kind === "limitation" && !run.replaced.has(e.seq));
  blocks.push({ k: "h", level: 3, text: "Limitations recorded" });
  if (limits.length) {
    for (const l of limits) {
      const bounds = run.entries.filter((a) => a.kind === "answer" && (a.limitations ?? []).some((x) => x.seq === l.seq)).map((a) => a.seq);
      const names = [...limitationCites(l)];
      out(l, [
        { label: "Reason", s: [(l.reason ?? "not given").replace(/_/g, " ")] },
        ...(l.answers?.length ? [{ label: "For", s: [l.answers.map((x) => `question ${sectionKey(x)}`).join(", ")] } as Row] : []),
        ...(names.length ? [{ label: "Names", s: names.flatMap((n, i): Span[] => [...(i ? [", "] : []), { e: n }]) } as Row] : []),
        ...(bounds.length ? [{ label: "Bounds", s: bounds.flatMap((n, i): Span[] => [...(i ? [", "] : []), { e: n }]) } as Row] : []),
      ]);
    }
  } else blocks.push({ k: "p", s: ["The swarm recorded none. That is not a statement that the examination had no limits."] });

  // The store sweeps (extensions/store-sweep.ts): each negative checked against every output the run held.
  const swept = run.entries.filter((e) => e.kind === "coverage" && e.looked_for?.length);
  if (swept.length) {
    const recs = swept.map((c) => ({ c, sw: sweepOf({ hash: entryHash(c) }, run.sweeps) }));
    const withHits = recs.filter((x) => x.sw?.hits.length);
    const withEchoes = recs.filter((x) => !x.sw?.hits.length && x.sw?.echoes?.length);
    const released = withHits.filter((x) => {
      const next = run.replaced.get(x.c.seq);
      const n = next !== undefined ? run.bySeq.get(next) : undefined;
      const sw = n ? sweepOf({ hash: entryHash(n) }, run.sweeps) : null;
      return Boolean(sw && !sw.hits.length && !sw.unsearched.length);
    });
    blocks.push({ k: "h", level: 3, text: "Store sweeps" });
    blocks.push({
      k: "p",
      s: [
        `${plural(swept.length, "coverage record")} named what a hit would contain, and the hub searched every output the run held for it (job outputs and logs, imports, captures, the agents' kept tool outputs): ${recs.filter((x) => x.sw).length} swept, ${recs.filter((x) => !x.sw).length} pending, ${withHits.length} with hits in objects the record did not name, ${recs.filter((x) => x.sw?.unsearched.length).length} partial; ${released.length} of the records with hits were revised to name what the sweep found, and their sweep is clean.${withEchoes.length ? ` ${plural(withEchoes.length, "record")} found its strings only in echoes (an output made from the run's own words, or by a search that asked for the string and read nothing the record does not name): named below, holding nothing.` : ""}`,
      ],
    });
    if (withHits.length || withEchoes.length) blocks.push({ k: "list", items: [...withHits, ...withEchoes].map((x): Span[] => [{ e: x.c.seq }, `: ${sweepWords(x.sw, x.c)}`, run.replaced.has(x.c.seq) ? " (revised)" : ""]) });
  }

  blocks.push({ k: "h", level: 3, text: "Searched and not found" });
  const absences = run.entries.filter((e) => e.kind === "absence");
  blocks.push({ k: "p", s: ["Each is valid only for the stated scope: what was searched, where, and how. Not found by that search is not absent from the evidence."] });
  if (absences.length) {
    for (const e of absences) out(e, [{ label: "Search", s: [e.completion === "complete" ? "complete over its stated scope" : `${e.completion ?? "completion not recorded"}: holds for the part searched only`] }]);
  } else blocks.push({ k: "p", s: ["No search that found nothing was recorded."] });

  blocks.push({ k: "h", level: 3, text: "Questions not answered" });
  const open: Span[][] = [];
  for (const q of run.questions) {
    const st = questionStatus_(q, run, memo);
    if (st.status.text === "answered") continue;
    const limitsFor = limits.filter((l) => (l.answers ?? []).some((x) => sectionKey(x) === q.id));
    const would = st.answer?.would_change;
    open.push([
      { a: `#${questionAnchor(q.id)}`, text: questionName(q) },
      ": ",
      { chip: st.status },
      st.answer ? " — its answer, " : " — ",
      ...(st.answer ? [{ e: st.answer.seq } as Span, ". "] : []),
      "What would answer it: ",
      would ? would : limitsFor.length ? `what the limitations recorded for it name (${limitsFor.map((l) => `E-${l.seq}`).join(", ")}): ${limitsFor.map((l) => l.value).join("; ")}` : run.hasAnswers ? "the ledger does not say." : "not recorded (the run predates structured answers; see the working report).",
    ]);
  }
  if (open.length) blocks.push({ k: "list", items: open });
  else blocks.push({ k: "p", s: [run.questions.length ? "Every question has a standing answer." : "No question was named."] });

  blocks.push(...evidenceGaps(run, limits));

  // Contradictions that stand, whether or not the run has answers to weigh them.
  const contradictions = standingContradictions(run.entries);
  if (contradictions.length) {
    const openOnes = new Set(openContradictions(run.entries).map((c) => `${c.from}:${c.to}`));
    blocks.push({ k: "h", level: 3, text: "Contradictions that stand" });
    blocks.push({
      k: "p",
      s: [
        `${plural(contradictions.length, "standing contradiction")}: `,
        ...contradictions.flatMap((c, i): Span[] => [...(i ? ["; "] : []), { e: c.from }, " contradicts ", { e: c.to }, openOnes.has(`${c.from}:${c.to}`) ? "" : " (weighed in an answer or named by a limitation)"]),
        ". Both entries of each stand; neither was corrected.",
      ],
    });
  }

  if (run.gate) {
    blocks.push({ k: "h", level: 3, text: "Defects left in the ledger" });
    const g = run.gate;
    if (g.defects.length) {
      blocks.push({ k: "p", s: ["Mechanical defects the ledger gate found, each with what would resolve it. A limitation that names a defect lets the run end; it does not resolve the defect."] });
      blocks.push({
        k: "list",
        items: g.defects.map((d): Span[] => [d.what, ". ", { b: "What would resolve it: " }, resolveWords(d), " ", d.named_by.length ? "Named by " : "No limitation names it.", ...d.named_by.flatMap((n, i): Span[] => [...(i ? [", "] : []), { e: n }]), d.named_by.length ? "." : ""]),
      });
    } else blocks.push({ k: "p", s: ["None: every section has a standing answer resting on standing support, and every answer has a critic's act."] });
    const tokens = Object.entries(g.unsupported);
    if (tokens.length) blocks.push({ k: "list", items: tokens.map(([seq, t]): Span[] => [{ e: Number(seq) }, " states ", ...t.flatMap((x, i): Span[] => [...(i ? [", "] : []), { code: x }]), ", in none of the entries it cites."]) });
  }

  if (run.html.limits) blocks.push({ k: "h", level: 3, text: "The limits of this run" }, { k: "html", html: run.html.limits });
  blocks.push({ k: "h", level: 3, text: "What this report does not claim" });
  blocks.push({
    k: "list",
    items: [
      ["It was prepared by an AI agent swarm. The models' output is not deterministic: running the case again would not give the same words; the reproducible record is the ledger, the sealed job outputs and the trace."],
      ["A method record says what ran and how it ended, not which bytes a tool read."],
      ["A corroboration group is a provenance group, not proof of independence."],
      ["An agent's attestation is not peer review, and no answer is an examiner's opinion until an examiner adopts it."],
      ["An artefact nobody opened is not evidence of absence."],
    ],
  });
  return { id: "s8", n: "8", title: "Limitations, negative findings and open questions", desc: "what could not be established, what was searched and not found, what is still open", blocks };
}

/**
 * What would resolve a defect the ledger gate found, for a reader of the
 * report. The gate's own `fix` is written for the agents (which tool, which
 * field) and stays in its refusal; this says the same to a person. An
 * unsupported answer is resolved by repairing its support, withdrawing it or
 * declaring it inconclusive, never by a limitation or an examiner's waiver.
 */
function resolveWords(d: LedgerGate["defects"][number]): string {
  const where = d.section ? sectionName(d.section) : "the answer";
  switch (d.code) {
    case "no_answer":
      return `an answer to ${where} resting on the entries that bear on it, or, if the evidence cannot answer it, a statement of why (a limitation), which leaves the question open.`;
    case "answer_support":
      return `the answer recorded again on what stands now (the correction of what it cited, or a stated reason why a disputed or failed-job entry still supports it), or the answer withdrawn or declared inconclusive. Until then it is not supported.`;
    case "answer_disputed":
      return `the dispute answered: the answer recorded again on what stands, or the dispute withdrawn by the agent that raised it, with its reason. Otherwise an examiner decides between them.`;
    case "no_critic_act":
      return `an agent other than its author re-deriving what the answer rests on from the sealed objects and recording that it holds, or why not. Even then no human has reviewed it.`;
    case "open_contradiction":
      return `the wrong one of the two entries corrected, or both weighed in an answer (one as contrary evidence), or a limitation naming both.`;
    case "partial_output":
      return `the entry recorded again saying how it treats the output of a job that was stopped before its end (what that part still shows, and why), or resting instead on a job that ran to its end. A limitation does not resolve it.`;
    case "evidence_stale":
      return `${where} examined against the evidence added after its search: a new search record that covers it (or says why it cannot bear on the question), checked by another agent, and the answer recorded again on it, or on what the new evidence shows. A limitation does not resolve it.`;
    case "sweep_pending":
      return `the hub's search of everything the run holds for what ${where}'s search looked for, run to its end. A limitation does not resolve it.`;
    case "sweep_hits":
      return `each object the store sweep found what was looked for in examined, and the search record for ${where} recorded again naming it with what it showed, or the answer revised on what those objects show. A limitation does not resolve it.`;
    case "sweep_partial":
      return `the store sweep run again within a larger budget over what it left unsearched, or the question's limits accepted by the operator.`;
    case "preparation_pending":
      return `the broad extraction of the source ${where}'s negative claims absence over (a parse of the whole source that a pack declares) run to an outcome: produced, partial, failed or declined, each on the record with what it does not hold; or the question's limits accepted by the operator.`;
    case "premise_inconsistent":
      return `the two answers reconciled on the record, neither side forced: one answer revised, the finding that rebuts the premise named in the contradiction (the premise then goes to the operator as a dispute), either answer's scope narrowed so the two no longer overlap, or one answer made conditional on the premise ("assuming P-n").`;
    case "completeness_uncovered":
      return `a search record for ${where} that says what was searched and which parts of the stored data it reached (live, deleted, unallocated, slack, secondary copies), and the answer recorded again on it. A question that asks for every item is not answered by the items found alone.`;
    default:
      return d.fix;
  }
}

function recommendationsSection(run: Run, memo: Map<number, EntryState>): BodySection {
  const blocks: Block[] = [];
  const asks = run.goal?.recommendations ?? null;
  if (!asks) {
    blocks.push({ k: "p", s: ["The goal did not ask for recommendations, and none are made."] });
    return { id: "s9", n: "9", title: "Recommendations", desc: "what the swarm recommends, when the goal asked", blocks };
  }
  // Where the answers are: a section the swarm answered as "recommendations",
  // and the questions whose wording asks for them.
  const own = run.questions.find((q) => /^recommendations?$/i.test(q.id));
  const qs = [...(own ? [own] : []), ...run.questions.filter((q) => asks.questions.includes(q.id))];
  if (asks.marker === "section") {
    blocks.push({ k: "p", lede: true, s: ["The goal asks for recommendations in a section of its own. What it asks, in its own words:"] });
    blocks.push({ k: "md", text: asks.text || "(the section is empty)" });
  } else {
    blocks.push({ k: "p", lede: true, s: [`The goal's wording asks for recommendations${asks.request ? " in its request" : ""}${asks.questions.length ? `${asks.request ? " and" : ""} in ${run.questions.filter((q) => asks.questions.includes(q.id)).map(questionName).join(", ")}` : ""} (it has no Recommendations section; this is read from its words).`] });
  }
  if (qs.length) blocks.push({ k: "p", s: ["They are opinions, resting on the findings the answers cite."] });
  for (const q of qs) {
    const a = standingAnswer(run, `question:${q.id}`);
    if (a) blocks.push({ k: "voice", voice: "opinion", label: questionName(q), s: [a.value, " (", { e: a.seq }, "; its basis in ", { a: `#${questionAnchor(q.id)}`, text: "§5" }, ")"], chips: chipsOf(a, stateOf(a, run, memo)).filter((c) => c.text !== "answer" && c.text !== "opinion") });
    else blocks.push({ k: "note", s: [`${questionName(q)} has no standing answer: no recommendation is made for it.`] });
  }
  if (!qs.length) blocks.push({ k: "note", s: ["No answer in the ledger holds them (an answer recorded for the section \"recommendations\", or for a question that asks for them): none are made here."] });
  return { id: "s9", n: "9", title: "Recommendations", desc: "what the swarm recommends, when the goal asked", blocks };
}

function reviewSection(run: Run, memo: Map<number, EntryState>): BodySection {
  const blocks: Block[] = [];
  const r = run.review;
  const reviewed = r?.entries?.size ?? 0;
  if (r?.unreadable) blocks.push({ k: "note", s: [`The examiner's review could not be read: ${r.unreadable}. Nothing here says whether anything was reviewed.`] });
  else if (!r || (!reviewed && !r.signed)) {
    blocks.push({
      k: "note",
      s: [
        { b: "No human has reviewed this report. " },
        "It was prepared by an AI agent swarm. The attestations in §4 are agents re-deriving agents' work, not independent review. Until an examiner adopts each answer, every answer here is the swarm's.",
      ],
    });
  }
  const answers = run.entries.filter((e) => e.kind === "answer" && !run.replaced.has(e.seq));
  if (reviewed) {
    blocks.push({
      k: "table",
      head: ["Answer", "Examiner's word"],
      rows: answers.map((a) => {
        const st = stateOf(a, run, memo);
        return [[{ e: a.seq }, ` ${sectionName(a.section)}`], [reviewWords(run, st)]];
      }),
    });
  }
  blocks.push({
    k: "rows",
    rows: [
      { label: "Examiner", s: [r?.examiner ? `${r.examiner.name}${r.examiner.organisation ? `, ${r.examiner.organisation}` : ""}${r.examiner.competence ? ` — ${r.examiner.competence}` : ""}` : "not recorded"] },
      {
        label: "Technical review",
        s: [
          r?.technicalReviews?.length
            ? r.technicalReviews.map((t) => `${t.name}${t.competence ? ` — ${t.competence}` : ""}${t.checked ? `; checked ${t.checked}` : ""}${t.outcome ? `; ${t.outcome}` : ""}: ${t.words}`).join(". ")
            : r?.technicalReviewer
              ? `${r.technicalReviewer.name}${r.technicalReviewer.competence ? ` — ${r.technicalReviewer.competence}` : ""}${r.technicalReviewer.checked ? `; checked ${r.technicalReviewer.checked}` : ""}`
              : "No technical review",
        ],
      },
      { label: "Signed", s: [r?.signed ? `by ${r.signed.by} at ${r.signed.at}${r.signed.ledger_head ? `, over ledger head ${r.signed.ledger_head}` : ""}${r.signed.current === false ? `; NOT OVER THIS RUN AS IT STANDS${r.signed.scope ? `: ${r.signed.scope}` : ""}` : r.signed.current ? "; over this ledger and this report" : ""}` : "not signed"] },
      { label: "Release", s: [run.draft ? (run.release ? `release v${run.release.version}, a draft sealed by the machine${run.release.at ? ` at ${run.release.at}` : ""}: adopted by no one` : "draft: no release v1 exists") : `release v${run.release?.version}${run.release?.at ? `, ${run.release.at}` : ""}`] },
    ],
  });
  return { id: "s10", n: "10", title: "Review and adoption", desc: "who reviewed it, what they adopted, and the release", blocks };
}

function exhibitsSection(run: Run, memo: Map<number, EntryState>): BodySection {
  const blocks: Block[] = [];
  blocks.push({ k: "p", lede: true, s: ["Every entry of the ledger, whole, grouped by kind and in the order it was recorded. A corrected entry stays as it was recorded, marked; an exhibit's number is its ledger seq, so the console, ledger.jsonl and this document name the same row."] });
  const groups: Array<[string, string]> = [
    ["answer", "Answers"],
    ["finding", "Findings"],
    ["event", "Events"],
    ["ioc", "Indicators"],
    ["absence", "Searched and not found"],
    ["hypothesis", "Hypotheses"],
    ["limitation", "Limitations"],
  ];
  const known = new Set(groups.map((g) => g[0]));
  for (const [kind, title] of [...groups, ["other", "Other entries"] as [string, string]]) {
    const rows = run.entries.filter((e) => (kind === "other" ? !known.has(e.kind) : e.kind === kind));
    if (!rows.length) continue;
    blocks.push({ k: "h", level: 3, text: `${title} (${rows.length})` });
    for (const e of rows) blocks.push(exhibitBox(e, run, memo));
  }
  if (!run.entries.length) blocks.push({ k: "note", s: ["The ledger is empty."] });
  return { id: "sA", n: "A", title: "Exhibits", desc: "every ledger entry, whole", count: plural(run.entries.length, "entry", "entries"), blocks };
}

function exhibitBox(e: LedgerEntry, run: Run, memo: Map<number, EntryState>): Block {
  const s = stateOf(e, run, memo);
  const rows: Row[] = [];
  const valueLabel = e.kind === "answer" ? "Answer" : e.basis === "observed" ? "Observation" : e.basis === "inferred" ? "Claim (inferred)" : "Recorded";
  rows.push({ label: valueLabel, voice: e.kind === "answer" ? "opinion" : e.basis === "inferred" ? undefined : "fact", s: [e.value] });
  if (e.kind === "answer") {
    rows.push({ label: "Section", s: [sectionName(e.section)] });
    rows.push({ label: "Reasoning", voice: "interpretation", s: [e.reasoning ?? ""] });
    const edges = (label: string, list?: LedgerEdge[]) => (list?.length ? [{ label, s: list.flatMap((x, i): Span[] => [...(i ? ["; "] : []), { e: x.seq }, ` (hash ${x.hash})`]) } as Row] : []);
    rows.push(...edges("Rests on", e.support), ...edges("Contrary", e.contrary), ...edges("Bounded by", e.limitations));
    if (e.alternatives_open) rows.push({ label: "Still open", s: [e.alternatives_open] });
    if (e.would_change) rows.push({ label: "Would change it", s: [e.would_change] });
  }
  if (e.indicates) rows.push({ label: "Interpretation", voice: "interpretation", s: [e.indicates] });
  else if (interpretationMissing(e)) rows.push({ label: "Interpretation", s: [{ chip: { text: "interpretation not recorded", tone: "none" } }, " this finding was recorded before findings said what they indicate"] });
  if (e.significance) rows.push({ label: "Significance", voice: "opinion", s: [e.significance] });
  if (e.confidence) rows.push({ label: "Confidence", s: [`${confidenceWords(s.confidence)}${e.confidence_why ? `: ${e.confidence_why}` : ""}`] });
  for (const alt of e.alternatives ?? []) rows.push({ label: alt.status === "rejected" ? "Rejected" : "Still open", s: [`${alt.explanation}: ${alt.why}${alt.test_refs?.length ? ` (tested with ${alt.test_refs.join(", ")})` : ""}`] });
  if (e.alternatives_none_why) rows.push({ label: "No alternative", s: [e.alternatives_none_why] });
  if (e.status) rows.push({ label: "Status", s: [e.kind === "hypothesis" ? `${e.status}: a proposition under test, not a finding` : e.status] });
  if (e.reason) rows.push({ label: "Why not established", s: [e.reason.replace(/_/g, " ")] });
  if (e.completion) rows.push({ label: "Search", s: [e.completion === "complete" ? "complete over its stated scope" : `${e.completion}: holds for the part searched only`] });
  if (e.answers?.length) rows.push({ label: "For", s: [e.answers.map((x) => `question ${sectionKey(x)}`).join(", ")] });
  if (e.ts) rows.push({ label: "When", s: [`${whenText(e)}${givenTime(e) ? ` (as given: ${givenTime(e)})` : ""}${e.clock ? `; clock: ${e.clock}` : ""}${e.precision && e.precision !== "date" ? `; precision: ${e.precision}` : ""}`] });
  if (e.source) rows.push({ label: "Where", s: [e.source] });
  if (e.evidence) rows.push({ label: "How", s: [e.evidence] });
  if (e.refs?.length) rows.push({ label: "Rests on", s: e.refs.flatMap((r, i): Span[] => [...(i ? [", "] : []), { code: r }]) });
  else if (e.kind === "finding") rows.push({ label: "Rests on", s: ["no object of the run named (no refs)"] });
  if (e.locators?.length) rows.push({ label: "Located at", s: e.locators.flatMap((l, i): Span[] => [...(i ? ["; "] : []), { code: l.ref }, ` ${l.at}`]) });
  rows.push(...methodRows(e, run, true));
  const { records, bound } = methodsOf(e, run);
  for (const m of records) rows.push({ label: bound ? "Method record" : "Job record (not in the entry's hash)", s: [{ code: JSON.stringify(m) }] });
  if (e.kind === "finding" || e.kind === "absence" || e.kind === "answer") {
    rows.push({ label: "Corroboration", voice: "computed", s: [groupsSentence(s.groups)] });
    for (const g of groupItems(s.groups)) rows.push({ label: "", voice: "computed", s: g });
  }
  for (const q of e.qualifies ?? []) rows.push({ label: "Qualifies", s: [`${q.ref}: ${q.why}`] });
  if (s.failed.length) rows.push({ label: "Failed job", s: [s.failed.map((f) => `${f.ref}: job ${f.job} ended ${f.status}`).join("; ")] });
  if (e.unsupported_tokens?.length) rows.push({ label: "Unsupported tokens", s: ["in none of the cited entries: ", ...e.unsupported_tokens.flatMap((t, i): Span[] => [...(i ? [", "] : []), { code: t }])] });
  if (s.problems.length) rows.push({ label: "Support", s: [`no longer stands on it: ${s.problems.join("; ")}`] });
  if (e.rel?.length) rows.push({ label: "Related", s: e.rel.flatMap((r, i): Span[] => [...(i ? [", "] : []), `${r.kind.replace(/_/g, " ")} `, { e: r.to }]) });
  if (e.attribution) rows.push({ label: "Attributed to", s: [`${e.attribution.subject} (${e.attribution.subject_type})${e.attribution.basis_refs?.length ? `, on ${e.attribution.basis_refs.join(", ")}` : ""}`] });
  if (e.supersedes !== undefined) rows.push({ label: "Corrects", s: [{ e: e.supersedes }, `, which stays in the ledger as it was recorded${e.because ? `, because ${e.because}` : ""}`] });
  if (s.supersededBy !== undefined) rows.push({ label: "Superseded by", s: [{ e: s.supersededBy }, ": this entry is shown as it was recorded and supports nothing"] });
  for (const a of s.attests) rows.push({ label: "Attested", s: [`by ${a.by} at ${a.at}${a.how ? `: ${a.how}` : ""}${a.refs?.length ? ` (from ${a.refs.join(", ")})` : ""}`] });
  for (const a of s.selfAttests) rows.push({ label: "Own attestation", s: [`by ${a.by}, one of its authors: not a check`] });
  for (const a of s.sameContent) rows.push({ label: "Also recorded by", s: [`${a.by}, word for word, at ${a.at}: a second author, not a check`] });
  for (const d of s.disputes) rows.push({ label: "Disputed", s: [`by ${d.by} at ${d.at}: ${d.why}${d.refs?.length ? ` (from ${d.refs.join(", ")})` : ""}`] });
  for (const w of s.withdrawn) rows.push({ label: "Dispute withdrawn", s: [`${w.dispute.by} disputed it (${w.dispute.why}) and withdrew at ${w.withdrawal.at}: ${w.withdrawal.why}`] });
  if (s.grounding === "not in the trace") rows.push({ label: "Grounding", s: ["NOT GROUNDED IN THE TRACE: no call before this entry was recorded named its source, and no job it cites was given an evidence input"] });
  else if (s.grounding === "grounded") rows.push({ label: "Grounding", s: ["a call before this entry named its source"] });
  else if (s.grounding === GROUNDED_VIA_JOB) rows.push({ label: "Grounding", s: ["no call named its source; a job this entry cites was given an evidence input before it was recorded, which says the job was given the input and not that it read this path"] });
  rows.push({ label: "Examiner review", s: [reviewWords(run, s)] });
  if (e.sensitive) rows.push({ label: "Sensitive", s: ["it, or what it cites, holds a credential, a key or personal data"] });
  rows.push({ label: "Recorded by", s: [e.authors.join(", ")] });
  const models = [...new Set(e.authors.map((id) => run.team.find((t) => t.id === id)?.model).filter((m): m is string => Boolean(m)))];
  if (models.length) rows.push({ label: "Model", s: [models.join(", ")] });
  rows.push({ label: "Recorded at", s: [e.at] });
  rows.push({ label: "Ledger version", s: [`${e.v ?? 1}${e.hash ? "" : ", not chained"}`] });
  if (e.hash) rows.push({ label: "Entry hash", s: [{ code: e.hash }] });
  return { k: "box", cls: `exhibit exhibit-${e.kind}`, id: `e-${e.seq}`, level: 4, title: [{ plain: `E-${e.seq}` }], chips: chipsOf(e, s), body: [{ k: "rows", rows }] };
}

function jobsSection(run: Run): BodySection {
  const blocks: Block[] = [];
  // Which entries rest on each job: a job: ref, or a method record (a
  // member: ref reaches the job that listed the catalogue).
  const citedBy = new Map<string, number[]>();
  for (const e of run.entries) {
    const ids = [...(e.refs ?? []).map((ref) => /^job:([^/]+)/.exec(ref)?.[1]), ...methodsOf(e, run).records.map((m) => (typeof m.job === "string" ? m.job : undefined))];
    for (const id of ids) if (id) citedBy.set(id, [...new Set([...(citedBy.get(id) ?? []), e.seq])]);
  }
  const uncited: Block[] = [];
  blocks.push({ k: "p", lede: true, s: ["Every job the run's job service ran, from its record (store/jobs/<id>/job.json) and the manifest of its sealed output. A method record describes recorded execution, not proven reads."] });
  if (!run.jobs.size) blocks.push({ k: "note", s: ["No job ran."] });
  const cited = [...run.jobs.keys()].filter((id) => citedBy.has(id)).length;
  if (run.jobs.size) blocks.push({ k: "p", s: [`${plural(cited, "job")} ${cited === 1 ? "is" : "are"} cited by an entry and ${cited === 1 ? "comes" : "come"} first; the ${plural(run.jobs.size - cited, "job")} no entry cites follow, whole, in a group a browser shows collapsed (open it to read them; a printout shows the group's count only).`] });
  // Code recovered from the evidence, run or evaluated by a job's command (extensions/evidence-code.ts), read from its words; an output of the same seat's own command job is said apart (its own code, or code that job recovered).
  const codeOf = (j: JobRecord): EvidenceCode | null => {
    const x = j.spec.command !== undefined ? evidenceCodeRun(j.spec.command, Array.isArray(j.spec.inputs) ? j.spec.inputs : []) : null;
    if (!x) return null;
    const own = j.requester?.agent ? ownJobOutputs(x, j.requester.agent, (id) => run.jobs.get(id) ?? null) : { paths: [], jobs: [] };
    return own.paths.length ? { ...x, own } : x;
  };
  const codes = new Map([...run.jobs.values()].map((j) => [j.id, codeOf(j)] as const).filter((x): x is readonly [string, EvidenceCode] => x[1] !== null));
  const fromEvidence = [...codes].filter(([, x]) => !onlyOwnOutputs(x)).map(([id]) => id);
  const fromOwn = [...codes].filter(([, x]) => onlyOwnOutputs(x)).map(([id]) => id);
  if (codes.size) blocks.push({ k: "note", s: [[fromEvidence.length ? `${plural(fromEvidence.length, "job")} may have executed code recovered from the evidence (its command runs, or evaluates, code from the evidence, an extraction or a job's output; read from the command's words): ${fromEvidence.join(", ")}. What comes out of the evidence is read, never run, and a no-exec mount does not stop an interpreter reading it: what rests on these jobs rests on that code's behaviour.` : "", fromOwn.length ? `${plural(fromOwn.length, "job")} ran or evaluated only an output of a command job its own seat asked for: ${fromOwn.join(", ")}. Code the seat wrote there itself is not the evidence's; code that job recovered from the evidence is: the seat says which.` : ""].filter(Boolean).join(" ")] });
  for (const j of run.jobs.values()) {
    const sp = j.spec;
    const rows: Row[] = [];
    rows.push({ label: "Kind", s: [`${sp.kind ?? "unknown"}${sp.profile ? `, profile ${sp.profile}` : ""}`] });
    rows.push({ label: "Ended", s: [`${j.status ?? "unknown"}${j.exit !== undefined ? ` (exit ${j.exit === null ? "none" : j.exit})` : ""}${j.reason ? `: ${j.reason}` : ""}`] });
    if (j.requester) rows.push({ label: "Asked for by", s: [`${j.requester.agent ?? "?"}${j.requester.name ? ` (${j.requester.name})` : ""}${j.requester.doing ? `, doing: ${j.requester.doing}` : ""}`] });
    rows.push({ label: "Image", s: [{ code: j.image ?? "not recorded" }, " ", { code: j.image_digest ?? "digest not recorded" }] });
    if (sp.command !== undefined) rows.push({ label: "Command", s: [{ code: sp.command }] });
    if (sp.tool !== undefined) rows.push({ label: "Tool", s: [{ code: sp.tool }, ` sha256 ${j.tool_sha256 ?? "not recorded"}; arguments `, { code: JSON.stringify(sp.args ?? {}) }] });
    if (sp.recipe !== undefined) rows.push({ label: "Recipe", s: [{ code: sp.recipe }, ` on ${sp.target?.ref ?? sp.target?.name ?? "unknown"}${j.tool_sha256 ? `, sha256 ${j.tool_sha256}` : ""}`] });
    if (sp.targets?.length) rows.push({ label: "Targets", s: [sp.targets.map((t) => t.ref ?? t.name ?? "?").join(", ")] });
    if (sp.source !== undefined) rows.push({ label: "Imported", s: [{ code: sp.source }, " — the file an agent made; how it was made is not recorded"] });
    rows.push({ label: "Declared scope", s: [Array.isArray(sp.inputs) ? sp.inputs.map(String).join(", ") || "none" : "not recorded (the legacy default: every input)"] });
    // Code recovered from the evidence, run or evaluated by the command (extensions/evidence-code.ts): read from the command's own words, a flag that says "may have".
    const code = codes.get(j.id) ?? null;
    if (code) rows.push({ label: "Evidence code", s: [`may have been executed: the command ${code.how === "runs" ? `runs ${code.paths.join(", ")} with ${code.what}` : `evaluates code (${code.what}) it read from ${code.paths.join(", ")}`}. ${code.own?.paths.length ? `${ownWords(code)} ` : ""}What comes out of the evidence is read, never run; an interpreter reading it is not stopped by a no-exec mount.`] });
    rows.push({ label: "Network", s: [sp.network ?? "not recorded"] });
    if (sp.timeout_seconds) rows.push({ label: "Time limit", s: [`${sp.timeout_seconds} s`] });
    if (sp.note) rows.push({ label: "Note", s: [sp.note] });
    if (sp.parent) rows.push({ label: "Parent", s: [sp.parent] });
    if (j.outputs === null) rows.push({ label: "Output", s: ["no manifest: its sealed output is not listed"] });
    else if (!j.outputs.length) rows.push({ label: "Output", s: ["nothing sealed"] });
    else for (const [i, f] of j.outputs.entries()) rows.push({ label: i ? "" : "Output", s: [{ code: f.path }, ` ${bytesHuman(f.bytes)}, sha256 `, { code: f.sha256 }] });
    const by = citedBy.get(j.id) ?? [];
    rows.push({ label: "Cited by", s: by.length ? by.flatMap((n, i): Span[] => [...(i ? [", "] : []), { e: n }]) : ["no entry"] });
    const box: Block = { k: "box", cls: "exhibit job", id: `job-${j.id}`, level: 4, title: [{ plain: `Job ${j.id}` }], chips: [{ text: j.status ?? "unknown", tone: j.status === "ok" ? "moss" : "brick" }, ...(code ? [onlyOwnOutputs(code) ? { text: "own job's code may have run", tone: "saffron" as const } : { text: "evidence code may have run", tone: "brick" as const }] : [])], body: [{ k: "rows", rows }] };
    (by.length ? blocks : uncited).push(box);
  }
  if (uncited.length) blocks.push({ k: "details", summary: `${plural(uncited.length, "job")} no entry cites`, body: uncited });
  return { id: "sB", n: "B", title: "Jobs and their method records", desc: "every job: what ran, where, what it declared, what it sealed", count: `${plural(run.jobs.size, "job")}, ${cited} cited`, blocks };
}

function workingSection(run: Run): BodySection {
  const blocks: Block[] = [];
  const w = run.working;
  if (run.era === "predates") blocks.push({ k: "note", s: ["This run predates structured answers (ledger version 4): the answers it gives exist only in this working report, which the ledger does not check."] });
  else if (!run.hasAnswers && w) blocks.push({ k: "note", s: ["The swarm recorded no answers in the ledger: what this working report says is its prose alone, which the ledger does not check."] });
  if (!w) blocks.push({ k: "p", s: ["The swarm left no working report (work/report.md)."] });
  else if ("error" in w) blocks.push({ k: "note", s: [`The working report (${w.path}) could not be read: ${w.error}.`] });
  else {
    blocks.push({
      k: "note",
      s: [
        { b: "The agents' working document. " },
        "Reproduced verbatim from ",
        { code: w.path },
        `. ${w.seal ?? `Its sha256 as reproduced here: ${w.sha256}.`} Its headings are demoted so this document keeps one outline (the Markdown fences it instead); nothing else is changed. It carries no evidentiary authority: the answers in §5 and the exhibits in Appendix A are the record, and where this document says something they do not, it is the agents' prose, unchecked by the ledger.`,
      ],
    });
    blocks.push({ k: "verbatim", text: w.text });
  }
  return { id: "sC", n: "C", title: "The swarm's working report", desc: "the agents' own document, verbatim, without authority", blocks };
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

function buildSections(run: Run, memo = new Map<number, EntryState>()): { preamble: Block[]; sections: BodySection[] } {
  return {
    preamble: legendBlocks(run),
    sections: [
      summarySection(run, memo),
      requestSection(run, memo),
      evidenceSection(run),
      methodSection(run),
      answerSectionOf(run, memo),
      narrativeSection(run, memo),
      conclusionsSection(run, memo),
      limitsSection(run, memo),
      recommendationsSection(run, memo),
      reviewSection(run, memo),
      exhibitsSection(run, memo),
      jobsSection(run),
      workingSection(run),
      registerSection(run),
    ],
  };
}

// ---------------------------------------------------------------------------
// HTML
// ---------------------------------------------------------------------------

type Ctx = { known: Set<number> };

/** Words from the run: escaped, newlines kept, code spans as code, each E-<seq> of an entry that exists linked to its exhibit. */
function textHtml(text: string, ctx: Ctx): string {
  return text
    .split(/(`[^`]+`)/)
    .map((part, i) =>
      i % 2
        ? `<code>${escapeHtml(part.slice(1, -1))}</code>`
        : escapeHtml(part)
            .replace(/\bE-(\d{1,6})\b/g, (m, n: string) => (ctx.known.has(Number(n)) ? `<a href="#e-${Number(n)}">${m}</a>` : m))
            .replace(/\n/g, "<br>"),
    )
    .join("");
}

function chipHtml(c: Chip): string {
  return `<span class="chip chip-${c.tone}">${escapeHtml(c.text)}</span>`;
}

function spansHtml(spans: Span[], ctx: Ctx): string {
  return spans
    .map((s) => {
      if (typeof s === "string") return textHtml(s, ctx);
      if ("code" in s) return `<code>${escapeHtml(s.code)}</code>`;
      if ("b" in s) return `<strong>${textHtml(s.b, ctx)}</strong>`;
      if ("e" in s) return ctx.known.has(s.e) ? `<a href="#e-${s.e}">E-${s.e}</a>` : `E-${s.e}`;
      if ("a" in s) return `<a href="${escapeHtml(s.a)}">${escapeHtml(s.text)}</a>`;
      if ("plain" in s) return escapeHtml(s.plain);
      return chipHtml(s.chip);
    })
    .join("");
}

const chipsHtml = (chips: Chip[] | undefined) => (chips?.length ? `<span class="chips">${chips.map(chipHtml).join(" ")}</span>` : "");

function rowsHtml(rows: Row[], ctx: Ctx): string {
  return `<dl>${rows.map((r) => `<dt>${escapeHtml(r.label)}</dt><dd${r.voice ? ` class="v-${r.voice}"` : ""}>${spansHtml(r.s, ctx)}</dd>`).join("")}</dl>`;
}

function blockHtml(b: Block, ctx: Ctx): string {
  switch (b.k) {
    case "p":
      return `<p${b.lede ? ' class="lede"' : ""}>${spansHtml(b.s, ctx)}</p>`;
    case "note":
      return `<div class="note${b.draft ? " draft-banner" : ""}">${spansHtml(b.s, ctx)}</div>`;
    case "h":
      return `<h${b.level}${b.id ? ` id="${escapeHtml(b.id)}"` : ""}>${escapeHtml(b.text)}${b.chips?.length ? ` ${chipsHtml(b.chips)}` : ""}</h${b.level}>`;
    case "list": {
      const tag = b.ordered ? "ol" : "ul";
      return `<${tag}>${b.items.map((it) => `<li>${spansHtml(it, ctx)}</li>`).join("")}</${tag}>`;
    }
    case "rows":
      return rowsHtml(b.rows, ctx);
    case "table":
      return `<table${b.cls ? ` class="${escapeHtml(b.cls)}"` : ""}><thead><tr>${b.head.map((h) => `<th>${escapeHtml(h)}</th>`).join("")}</tr></thead><tbody>${b.rows.map((r) => `<tr>${r.map((c) => `<td>${spansHtml(c, ctx)}</td>`).join("")}</tr>`).join("")}</tbody></table>`;
    case "voice":
      return `<div class="voice v-${b.voice}"><span class="vl">${escapeHtml(b.label)}</span>${b.chips?.length ? `<div class="chips">${b.chips.map(chipHtml).join(" ")}</div>` : ""}<div class="vt">${spansHtml(b.s, ctx)}</div></div>`;
    case "cite":
      return `<div class="cite"><div class="ch">${spansHtml(b.head, ctx)}</div>${b.chips.length ? `<div class="chips">${b.chips.map(chipHtml).join(" ")}</div>` : ""}${b.rows.length ? rowsHtml(b.rows, ctx) : ""}</div>`;
    case "timeline":
      return `<ol class="tl">${b.rows.map((r) => `<li><div class="stamp"><span class="date">${escapeHtml(r.when)}</span><span class="no">${spansHtml([{ e: r.seq }], ctx)}</span></div><div class="what">${spansHtml(r.what, ctx)}</div><div class="meta">${escapeHtml(r.meta)}</div></li>`).join("")}</ol>`;
    case "html":
      return b.html;
    case "details":
      return `<details class="uncited"><summary>${escapeHtml(b.summary)}</summary>${b.body.map((x) => blockHtml(x, ctx)).join("\n")}</details>`;
    case "md":
      return `<div class="embedded goal">${markdownToHtml(b.text, 2)}</div>`;
    case "verbatim":
      return `<div class="embedded working">${markdownToHtml(b.text, 2)}</div>`;
    case "box":
      return `<div class="${escapeHtml(b.cls)}"${b.id ? ` id="${escapeHtml(b.id)}"` : ""}><div class="head"><h${b.level} class="bt">${spansHtml(b.title, ctx)}</h${b.level}>${chipsHtml(b.chips)}</div>${b.body.map((x) => blockHtml(x, ctx)).join("\n")}</div>`;
  }
}

/**
 * The body's own rules, on top of report.ts's stylesheet (its tokens,
 * chips, notes, tables and exhibits): the three voices, the answer blocks,
 * the citations under them, the DRAFT mark.
 */
export const REPORT_BODY_STYLE = `
.rb code { white-space: pre-wrap; }
.rb .note { margin: .8rem 0; }
.rb .note.draft-banner { border-color: var(--brick); background: var(--brick-soft); color: var(--brick-ink); }
.rb dl { display: grid; grid-template-columns: minmax(7rem, 12rem) minmax(0, 1fr); gap: .2rem .9rem; margin: .6rem 0; }
.rb dt { color: var(--ink-3); font-size: .9em; }
.rb dd { margin: 0; overflow-wrap: anywhere; }
.draft-mark { position: fixed; inset: 0; display: flex; align-items: center; justify-content: center; pointer-events: none; z-index: 5; font-family: var(--serif); font-size: clamp(5rem, 20vw, 13rem); letter-spacing: .08em; color: rgba(178, 58, 72, .08); transform: rotate(-28deg); user-select: none; }
.rb .chips { display: inline-flex; flex-wrap: wrap; gap: .3rem; vertical-align: baseline; }
.rb .chip { white-space: normal; }
.voice { margin: .7rem 0; padding: .2rem 0 .2rem .9rem; border-left: 3px solid var(--line-2); }
.voice .vl { display: block; font-family: var(--sans); font-style: normal; font-size: .62rem; letter-spacing: .12em; text-transform: uppercase; color: var(--ink-3); margin-bottom: .15rem; }
.voice .chips { display: flex; margin: .1rem 0 .3rem; }
.v-fact { border-left-color: var(--slate); }
.v-interpretation { border-left: 3px dotted var(--kelp); font-family: var(--serif); font-style: italic; font-size: 1.05em; color: var(--ink); }
.v-opinion { border: 1px solid var(--saffron); border-left-width: 4px; background: var(--saffron-soft); border-radius: 6px; padding: .5rem .85rem; }
.v-opinion .vt { font-size: 1.04rem; line-height: 1.45; }
.v-computed { border-left: 3px double var(--line-2); color: var(--ink-2); font-size: .94em; }
dd.v-fact, dd.v-interpretation, dd.v-opinion, dd.v-computed { margin: 0 0 .15rem; padding-left: .6rem; }
dd.v-opinion { padding: .2rem .5rem; }
.answer { border: 1px solid var(--line); border-radius: 10px; background: var(--card); padding: .8rem 1.1rem 1rem; margin: 1.5rem 0; }
.answer > .head { display: flex; flex-wrap: wrap; align-items: baseline; gap: .6rem; border-bottom: 1px solid var(--line); padding-bottom: .5rem; }
.answer > .head .bt { margin: 0; font-size: 1.12rem; flex: 1 1 20rem; }
.answer h4 { margin: 1.3em 0 .35em; font-size: .78rem; letter-spacing: .09em; text-transform: uppercase; color: var(--ink-2); }
.answer.unanswered { border-style: dashed; }
.cite { border-left: 2px solid var(--line); padding: .25rem 0 .25rem .8rem; margin: .5rem 0; }
.cite .ch { line-height: 1.45; }
.cite .chips { margin: .25rem 0; }
.cite dl, .rb .exhibit dl { display: grid; grid-template-columns: 7.2rem minmax(0, 1fr); gap: .15rem .8rem; margin: .2rem 0 0; font-size: .84em; }
.cite dt, .rb .exhibit dt { color: var(--ink-3); }
.cite dd, .rb .exhibit dd { margin: 0; overflow-wrap: anywhere; color: var(--ink-2); }
.rb .exhibit .head { display: flex; flex-wrap: wrap; align-items: baseline; gap: .5rem; }
.rb .exhibit .bt { margin: 0; font-family: var(--mono); font-size: .8rem; color: var(--ink-3); font-weight: 650; }
.rb .exhibit .head .chips { margin-left: auto; justify-content: flex-end; }
.rb .exhibit-answer { border-left-color: var(--saffron); }
.rb .job { border-left-color: var(--line-2); }
.rb table.status th:nth-child(1) { width: 18%; }
.rb table.status th:nth-child(2) { width: 34%; }
.rb table.timeline th:nth-child(1) { width: 20%; }
.rb table.timeline th:nth-child(4) { width: 10%; }
.rb .embedded.working { border-style: dashed; }
.rb details.uncited { margin: 1rem 0; border: 1px dashed var(--line-2); border-radius: 8px; padding: .5rem .9rem; }
.rb details.uncited > summary { cursor: pointer; font-weight: 650; color: var(--ink-2); }
.rb .tl { margin: 1.2rem 0 0; border-left: 1px solid var(--line-2); padding-left: 0; list-style: none; }
.rb .tl li { position: relative; padding: 0 0 1.1rem 1.4rem; margin: 0; }
.rb .tl li::before { content: ""; position: absolute; left: -4.5px; top: .55rem; width: 8px; height: 8px; border-radius: 50%; background: var(--slate); box-shadow: 0 0 0 3px var(--paper); }
.rb .tl .stamp { display: flex; flex-wrap: wrap; align-items: baseline; gap: .5rem; font-variant-numeric: tabular-nums; font-size: .78rem; color: var(--ink-3); }
.rb .tl .stamp .date { font-weight: 650; color: var(--ink-2); }
.rb .tl .stamp .no { font-family: var(--mono); }
.rb .tl .what { margin: .15rem 0 .2rem; line-height: 1.45; }
.rb .tl .meta { font-size: .8rem; color: var(--ink-3); overflow-wrap: anywhere; }
@media (max-width: 34rem) {
  .rb dl, .cite dl, .rb .exhibit dl { grid-template-columns: minmax(0, 1fr); }
  .rb dt, .cite dt, .rb .exhibit dt { font-size: .68rem; letter-spacing: .06em; text-transform: uppercase; margin-top: .3rem; }
}
@media print {
  .answer { break-inside: auto; }
  .answer h4 { break-after: avoid-page; }
  .cite, .voice, .rb .tl li { break-inside: avoid-page; }
  .draft-mark, .draft-banner, .voice, .v-opinion, .answer { -webkit-print-color-adjust: exact; print-color-adjust: exact; }
}
`;

/**
 * The page a preview renders on its own: the subset of report.ts's
 * stylesheet the body uses (its tokens, type, chips, tables, notes,
 * exhibits and sections), so a preview looks as the body will in the report.
 * In the report, report.ts's own stylesheet takes this place.
 */
const PREVIEW_BASE_STYLE = `
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
body { margin: 0; background: var(--paper-2); color: var(--ink); font: 10.5pt/1.6 var(--sans); }
main { max-width: 54rem; margin: 0 auto; padding: 0 0 4rem; background: var(--paper); box-shadow: 0 0 0 1px var(--line); }
section, .toc, .preamble { padding-left: clamp(1.25rem, 5vw, 3.25rem); padding-right: clamp(1.25rem, 5vw, 3.25rem); }
h1, h2, h3, h4 { font-family: var(--serif); font-weight: 400; line-height: 1.12; margin: 0 0 .5em; }
h2 { font-size: 1.6rem; margin: 0 0 1rem; }
h3 { font-size: 1.12rem; margin: 2em 0 .6em; }
h4 { font-size: .95rem; font-family: var(--sans); font-weight: 650; margin: 1.6em 0 .4em; }
p, li { margin: .55em 0; }
a { color: var(--kelp-ink); }
code { font-family: var(--mono); font-size: .86em; background: var(--paper-2); padding: .1em .32em; border-radius: 3px; overflow-wrap: anywhere; }
pre { background: var(--paper-2); border: 1px solid var(--line); border-radius: 8px; padding: .75rem .95rem; overflow-x: auto; }
.lede { font-size: 1.02rem; color: var(--ink-2); max-width: 42em; }
table { border-collapse: collapse; width: 100%; table-layout: fixed; margin: 1.1em 0; font-size: .92em; }
th, td { text-align: left; padding: .45rem .6rem; border-bottom: 1px solid var(--line); vertical-align: top; overflow-wrap: anywhere; }
th { font-size: .68rem; letter-spacing: .07em; text-transform: uppercase; color: var(--ink-3); font-weight: 650; }
.chip { display: inline-block; border-radius: 999px; padding: .1em .6em; font-size: .7rem; font-weight: 650; letter-spacing: .02em; line-height: 1.6; vertical-align: .08em; }
.chip-kelp { background: var(--kelp-soft); color: var(--kelp-ink); }
.chip-saffron { background: var(--saffron-soft); color: var(--saffron-ink); }
.chip-brick { background: var(--brick-soft); color: var(--brick-ink); }
.chip-slate { background: var(--slate-soft); color: var(--slate-ink); }
.chip-moss { background: var(--moss-soft); color: var(--moss-ink); }
.chip-none { background: var(--paper-3); color: var(--ink-2); }
.toc { padding-top: 2rem; padding-bottom: 1.5rem; border-bottom: 1px solid var(--line); }
.toc ol { list-style: none; padding: 0; margin: 0; display: grid; grid-template-columns: repeat(auto-fit, minmax(15rem, 1fr)); gap: 0 2rem; }
.toc li { border-bottom: 1px solid var(--line); padding: .45em 0; }
section { padding-top: 2.5rem; }
.sec-head { display: flex; align-items: baseline; gap: .8rem; border-bottom: 1px solid var(--rule); padding-bottom: .55rem; margin-bottom: 1.2rem; }
.sec-head .n { font-family: var(--mono); font-size: .8rem; color: var(--ink-3); }
.sec-head h2 { margin: 0; }
.sec-head .count { margin-left: auto; font-size: .72rem; letter-spacing: .06em; text-transform: uppercase; color: var(--ink-3); white-space: nowrap; }
.exhibit { border: 1px solid var(--line); border-left: 3px solid var(--slate); border-radius: 8px; background: var(--card); padding: .75rem .95rem; margin: .6rem 0; }
.exhibit-finding { border-left-color: var(--kelp); }
.exhibit-ioc { border-left-color: var(--saffron); }
.exhibit-absence { border-left-style: dashed; }
.exhibit-hypothesis { border-left-style: dotted; }
.exhibit-limitation { border-left-color: var(--brick); border-left-style: dashed; }
.note { background: var(--paper-2); border: 1px solid var(--line); border-radius: 8px; padding: .7rem .95rem; font-size: .9em; color: var(--ink-2); }
.note strong { color: var(--ink); }
.embedded { border: 1px solid var(--line); border-radius: 8px; padding: .3rem 1.1rem 1.1rem; background: var(--card); margin-top: 1rem; }
@media print {
  @page { size: A4; margin: 15mm 16mm; }
  html, body { background: #fff; }
  body { font-size: 9.3pt; line-height: 1.5; }
  main { max-width: none; margin: 0; padding: 0; box-shadow: none; }
  section, .toc, .preamble { padding-left: 0; padding-right: 0; }
  h1, h2, h3, h4, .sec-head { break-after: avoid-page; }
  .exhibit, tr, pre, .note { break-inside: avoid-page; }
  thead { display: table-header-group; }
  .chip, .exhibit, .note { -webkit-print-color-adjust: exact; print-color-adjust: exact; }
}
`;

export type ReportBody = {
  /** The body alone: the DRAFT mark and banner, the reading note, every section, with the sections' own wrappers. */
  html: string;
  /** Each section's inner HTML, for a caller that wraps sections itself (report.ts). */
  sections: Array<{ id: string; n: string; title: string; desc: string; count?: string; html: string }>;
  /** The DRAFT mark and banner and the reading note, for a caller that places them itself. */
  preamble: string;
  /** REPORT_BODY_STYLE: to add to the caller's stylesheet. */
  style: string;
  draft: boolean;
  /** A title for the case: the case id and the run id, as far as the run says them. */
  title: string;
  facts: BodyFacts;
};

/**
 * What a cover or a run summary says of the answers, computed once from the
 * run as the body reads it, so the report and the summary never disagree:
 * how many questions, how many have a standing answer, how many of those the
 * examiner adopted, whether the sign-off covers the run, whether it is a
 * draft, and each question's standing.
 */
export type BodyFacts = {
  questions: number;
  answered: number;
  hasAnswers: boolean;
  entries: number;
  /** What the ledger can hold: answers, none yet (version 4), none (it predates them), nothing at all. */
  era: "answers" | "no answers" | "predates" | "empty";
  draft: boolean;
  /** Standing answers to questions the examiner accepted, reviewed against the answer's own hash. */
  adopted: number;
  signoff: "current" | "not current" | "none" | "unreadable";
  questionStatus: Array<{ id: string; label: string; status: string; answer: number | null; confidence: string | null; adopted: boolean; value: string | null }>;
  /** The standing summary answer, and whether it still stands on its support. */
  summary: { seq: number; value: string; stands: boolean } | null;
};

/** An answer the examiner adopted (accept, adopt, or qualify), against its own hash (a review of another version of it adopts nothing). */
function adoptedBy(s: EntryState): boolean {
  return ["accept", "adopt", "qualify"].includes(s.review?.action ?? "") && (!s.review?.entry_hash || s.review.entry_hash === s.hash);
}

function factsOf(run: Run, memo: Map<number, EntryState>): BodyFacts {
  const questionStatus = run.questions.map((q) => {
    const st = questionStatus_(q, run, memo);
    const a = st.answer;
    return { id: q.id, label: questionName(q), status: st.status.text, answer: a?.seq ?? null, confidence: a ? stateOf(a, run, memo).confidence.recorded : null, adopted: a ? adoptedBy(stateOf(a, run, memo)) : false, value: a?.value ?? null };
  });
  const summary = standingAnswer(run, "summary");
  const r = run.review;
  return {
    questions: run.questions.length,
    answered: questionStatus.filter((q) => q.answer !== null).length,
    hasAnswers: run.hasAnswers,
    entries: run.entries.length,
    era: run.era,
    draft: run.draft,
    adopted: questionStatus.filter((q) => q.adopted).length,
    signoff: r?.unreadable ? "unreadable" : !r?.signed ? "none" : r.signed.current === false ? "not current" : "current",
    questionStatus,
    summary: summary ? { seq: summary.seq, value: summary.value, stands: !stateOf(summary, run, memo).problems.length } : null,
  };
}

/** The facts alone, for a caller that prints no body (the run summary): the same numbers the report's cover shows. */
export async function reportBodyFacts(sandbox: string, opts: ReportBodyOptions = {}): Promise<BodyFacts> {
  return factsOf(await loadRun(sandbox, opts), new Map());
}

function titleOf(run: Run): string {
  return `${run.caseId ? `${run.caseId} — ` : ""}Forensic report, run ${run.runId}`;
}

/** The body of the report for a run: HTML, per section, with its stylesheet. */
export async function renderReportBody(sandbox: string, opts: ReportBodyOptions = {}): Promise<ReportBody> {
  const run = await loadRun(sandbox, opts);
  const memo = new Map<number, EntryState>();
  const { preamble, sections } = buildSections(run, memo);
  const ctx: Ctx = { known: new Set(run.entries.map((e) => e.seq)) };
  const mark = run.draft ? `<div class="draft-mark" aria-hidden="true">DRAFT</div>\n` : "";
  const pre = `${mark}<div class="preamble rb">${preamble.map((b) => blockHtml(b, ctx)).join("\n")}</div>`;
  const rendered = sections.map((s) => ({ id: s.id, n: s.n, title: s.title, desc: s.desc, ...(s.count ? { count: s.count } : {}), html: `<div class="rb">${s.blocks.map((b) => blockHtml(b, ctx)).join("\n")}</div>` }));
  const html = [
    pre,
    ...rendered.map(
      (s) => `<section id="${s.id}"${/^[A-Z]$/.test(s.n) ? ' class="appendix"' : ""}>
  <div class="sec-head">${/^[A-Z]$/.test(s.n) ? "" : `<span class="n">${escapeHtml(s.n)}</span>`}<h2>${escapeHtml(/^[A-Z]$/.test(s.n) ? `Appendix ${s.n}: ${s.title}` : s.title)}</h2>${s.count ? `<span class="count">${escapeHtml(s.count)}</span>` : ""}</div>
${s.html}
</section>`,
    ),
  ].join("\n\n");
  return { html, sections: rendered, preamble: pre, style: REPORT_BODY_STYLE, draft: run.draft, title: titleOf(run), facts: factsOf(run, memo) };
}

/** A standalone page around a body: what the CLI prints for a preview. */
export function reportBodyDocument(body: ReportBody): string {
  const toc = body.sections.map((s) => `<li><a href="#${s.id}">${escapeHtml(/^[A-Z]$/.test(s.n) ? `Appendix ${s.n}` : s.n)}. ${escapeHtml(s.title)}</a></li>`).join("");
  return `<!doctype html>
<html lang="en">
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>${escapeHtml(`${body.draft ? "DRAFT — " : ""}${body.title}`)}</title>
<style>${PREVIEW_BASE_STYLE}${body.style}</style>
<body>
<main>
<nav class="toc" aria-label="Contents"><h2>${escapeHtml(body.title)}</h2><ol>${toc}</ol></nav>
${body.html}
</main>
</body>
</html>
`;
}

// ---------------------------------------------------------------------------
// Markdown
// ---------------------------------------------------------------------------

/**
 * A line of the run's words as Markdown: HTML cannot open (a `<` is an
 * entity), and a line that would open a block (a heading, a quote, a list,
 * a fence, a rule, a table row) is escaped to stay text. Nothing is dropped.
 */
function mdLine(line: string): string {
  let out = line.replace(/&(?=#?\w+;)/g, "&amp;").replace(/</g, "&lt;");
  const ordered = /^(\s*)(\d+)([.)])(\s|$)/.exec(out);
  if (ordered) return `${ordered[1]}${ordered[2]}\\${ordered[3]}${out.slice(ordered[0].length - ordered[4].length)}`;
  if (/^\s*(?:#|>|[-+*](?:\s|$)|`{3,}|~{3,}|\||=+\s*$|_{3,}\s*$)/.test(out)) out = out.replace(/^(\s*)/, "$1\\");
  return out;
}

function mdText(text: string, indent: string): string {
  return text
    .split("\n")
    .map((l, i) => (i ? indent : "") + mdLine(l))
    .join("\n");
}

function mdCode(text: string): string {
  const longest = Math.max(0, ...[...text.matchAll(/`+/g)].map((m) => m[0].length));
  const f = "`".repeat(longest + 1);
  const pad = /^`|`$/.test(text) || (/^ /.test(text) && / $/.test(text)) ? " " : "";
  return `${f}${pad}${text}${pad}${f}`;
}

function mdFence(text: string, indent: string): string {
  const longest = Math.max(2, ...[...text.matchAll(/`+/g)].map((m) => m[0].length));
  const f = "`".repeat(longest + 1);
  return [f, ...text.split("\n"), f].map((l) => indent + l).join("\n");
}

function spansMd(spans: Span[], indent: string): string {
  let out = "";
  for (const s of spans) {
    if (typeof s === "string") out += mdText(s, indent);
    else if ("code" in s) out += s.code.includes("\n") ? `\n${mdFence(s.code, indent)}\n${indent}` : mdCode(s.code);
    else if ("b" in s) {
      // Emphasis cannot close after a space: the spaces go outside it.
      const m = /^(\s*)([\s\S]*?)(\s*)$/.exec(s.b) as RegExpExecArray;
      out += m[2] ? `${m[1]}**${mdText(m[2], indent)}**${m[3]}` : s.b;
    }
    else if ("e" in s) out += `E-${s.e}`;
    else if ("a" in s) out += mdText(s.text, indent);
    else if ("plain" in s) out += mdText(s.plain, indent);
    else out += mdCode(s.chip.text);
  }
  return out;
}

/** A voice named beside its label in Markdown, where type cannot set it apart; once, when the label does not say it already. */
function voiceTag(label: string, voice: Voice | undefined): string {
  if (!voice || voice === "fact") return "";
  const word = VOICE_LABEL[voice].toLowerCase();
  return label.toLowerCase().includes(word.split(" ")[0]) ? "" : ` (${word})`;
}

const chipsMd = (chips: Chip[] | undefined) => (chips?.length ? chips.map((c) => mdCode(c.text)).join(" ") : "");

function cellMd(spans: Span[]): string {
  return spansMd(spans.map((s) => (typeof s === "object" && "code" in s ? { code: s.code.replace(/\n/g, " ") } : s)), "")
    .replace(/\n/g, " ")
    .replace(/\|/g, "\\|");
}

function blockMd(b: Block): string {
  switch (b.k) {
    case "p":
      return spansMd(b.s, "");
    case "note":
      return `> ${spansMd(b.s, "> ")}`;
    case "h":
      return `${"#".repeat(b.level)} ${mdText(b.text, "")}${b.chips?.length ? ` ${chipsMd(b.chips)}` : ""}`;
    case "list":
      return b.items.map((it, i) => (b.ordered ? `${i + 1}. ${spansMd(it, "   ")}` : `- ${spansMd(it, "  ")}`)).join("\n");
    case "rows":
      return b.rows.map((r) => (r.label ? `- **${mdText(r.label, "")}${voiceTag(r.label, r.voice)}:** ${spansMd(r.s, "  ")}` : `  - ${spansMd(r.s, "    ")}`)).join("\n");
    case "table":
      return [`| ${b.head.map((h) => mdText(h, "")).join(" | ")} |`, `| ${b.head.map(() => "---").join(" | ")} |`, ...b.rows.map((r) => `| ${r.map(cellMd).join(" | ")} |`)].join("\n");
    case "voice":
      return `**${mdText(b.label, "")}**${voiceTag(b.label, b.voice)}${b.chips?.length ? ` ${chipsMd(b.chips)}` : ""}\n\n> ${spansMd(b.s, "> ")}`;
    case "cite":
      return [`- ${spansMd(b.head, "  ")}${b.chips.length ? `  \n  ${chipsMd(b.chips)}` : ""}`, ...b.rows.map((r) => (r.label ? `  - ${mdText(r.label, "")}${voiceTag(r.label, r.voice)}: ${spansMd(r.s, "    ")}` : `    - ${spansMd(r.s, "      ")}`))].join("\n");
    case "timeline":
      return b.rows.map((r) => `- ${mdText(r.when, "")} — ${spansMd(r.what, "  ")} — ${mdText(r.meta, "")} — E-${r.seq}`).join("\n");
    case "html":
      return "";
    case "details":
      return [`### ${mdText(b.summary, "")}`, ...b.body.map(blockMd)].join("\n\n");
    case "md":
      return b.text
        .split("\n")
        .map((l) => `> ${l.replace(/</g, "&lt;")}`)
        .join("\n");
    case "verbatim":
      return mdFence(b.text, "");
    case "box":
      return [`${"#".repeat(b.level)} ${spansMd(b.title, "")}${b.chips.length ? ` ${chipsMd(b.chips)}` : ""}`, ...b.body.map(blockMd)].join("\n\n");
  }
}

/**
 * The same body as Markdown, for a reader without a browser, or a model:
 * every section, answer block, chip (as a code span) and exhibit, whole. The
 * working report is fenced, verbatim, so its headings stay its own.
 */
export async function renderReportBodyMarkdown(sandbox: string, opts: ReportBodyOptions = {}): Promise<string> {
  const run = await loadRun(sandbox, opts);
  const { preamble, sections } = buildSections(run);
  const parts: string[] = [`# ${mdText(`${run.draft ? "DRAFT — " : ""}${titleOf(run)}`, "")}`];
  parts.push(...preamble.map(blockMd));
  for (const s of sections) {
    parts.push(`## ${/^[A-Z]$/.test(s.n) ? `Appendix ${s.n}: ${mdText(s.title, "")}` : `${s.n}. ${mdText(s.title, "")}`}${s.count ? ` (${mdText(s.count, "")})` : ""}`);
    parts.push(...s.blocks.map(blockMd).filter(Boolean));
  }
  return `${parts.join("\n\n")}\n`;
}

// ---------------------------------------------------------------------------

if (process.argv[1] && resolve(process.argv[1]) === resolve(fileURLToPath(import.meta.url))) {
  const args = process.argv.slice(2);
  const sandbox = args.find((a) => !a.startsWith("--"));
  if (!sandbox) {
    console.error("Usage: report-body.ts <sandbox> [--md]");
    process.exit(2);
  }
  await stat(sandbox).catch(() => {
    console.error(`No such sandbox: ${sandbox}`);
    process.exit(1);
  });
  process.stdout.write(args.includes("--md") ? await renderReportBodyMarkdown(sandbox) : reportBodyDocument(await renderReportBody(sandbox)));
}
