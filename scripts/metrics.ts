#!/usr/bin/env node
/**
 * Process metrics of a run, read from its own registers: no truth, no case,
 * no tool's output (docs/adr/0017, the definitions in docs/usage.md).
 *
 *   node --experimental-strip-types scripts/metrics.ts <run-dir> [--json]
 *   node --experimental-strip-types scripts/metrics.ts --compare <run-dir-A> <run-dir-B> [--json]
 *   swarm.sh metrics <id> [--json]
 *   swarm.sh metrics --compare <id-A> <id-B> [--json]
 *
 * What is read, and nothing else: the lead register (leads/leads.jsonl, and
 * the finish register leads/finish.jsonl where the run has one), the question
 * register, the ledger with its attestations and disputes, the operator
 * requests, the store's journal (jobs, reuse hints, evidence added), the
 * network's grants and fetches, the trace (done calls, the hub's refusals),
 * the run's end (done/SWARM_DONE, done/STOPPED) and the seats' token records
 * (the model gateway's log, else the Pi sessions). A register a run does not
 * have is said to be absent, never read as zero: a run from before offers
 * has no offer events, one from before the reuse hints no job_similar lines.
 *
 * Each figure is a count of named records, and the JSON lists them (ids,
 * sections, seats, times, reason codes), so a figure can be checked against
 * the register it came from. No free text a record carries is copied, in
 * the table or the JSON: no answer value, no finding, no command, no
 * dispute's or done's why. A metric says what the process did, never what
 * the case holds. The questions a run is measured against are the ones in
 * its scope at its end (Q.liveInScope); an answer to a question since
 * withdrawn or excluded is listed apart, as history.
 *
 * `--compare` sets two runs of the same goal side by side, question by
 * question: each one's standing result, whether it was reviewed, its
 * coverage and acceptance, and where they agree or disagree. A negative in
 * one run that the other established is flagged; so is agreement on a
 * negative resting on partial coverage in both, which may be a shared blind
 * spot rather than a confirmation. A partial answer whose every asked part
 * is established (the under-claiming metric, `claims`) is marked and counted
 * on each side. Neither run's conclusions are shown to the other: this is
 * read after both ended.
 */
import { skillMetrics, skillMetricsWords, type SkillMetrics } from "./skill-metrics.ts";
import { frictionMetrics, frictionWords, type FrictionMetrics } from "./friction-metrics.ts";
import { existsSync, statSync } from "node:fs";
import { readdir, readFile } from "node:fs/promises";
import { basename, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import * as P from "../extensions/protocol.ts";
import * as L from "../extensions/leads.ts";
import * as Q from "../extensions/questions.ts";
import * as R from "../extensions/requests.ts";
import * as NB from "../extensions/negative-bar.ts";
import * as SW from "../extensions/store-sweep.ts";
import { readNetState, grantStatus } from "./net-grants.ts";
import { storePaths } from "./evidence-store.ts";
import { questionCost, roundParts, runCalls } from "./question-cost.ts";

type Rec = Record<string, unknown>;

export const METRICS_FORMAT = "dfirswarm-metrics/1";
export const COMPARE_FORMAT = "dfirswarm-metrics-compare/1";

const str = (v: unknown): string => (typeof v === "string" ? v : v === undefined || v === null ? "" : String(v));
const num = (v: unknown): number => (typeof v === "number" && Number.isFinite(v) ? v : 0);
const ms = (iso: unknown): number | null => {
  const t = Date.parse(str(iso));
  return Number.isFinite(t) ? t : null;
};
const minutes = (from: number | null, to: number | null): number | null => (from === null || to === null ? null : Math.round(((to - from) / 60000) * 10) / 10);
const iso = (t: number | null): string | null => (t === null ? null : new Date(t).toISOString());

async function jsonl(path: string): Promise<Rec[]> {
  const text = await readFile(path, "utf8").catch(() => "");
  const out: Rec[] = [];
  for (const line of text.split("\n")) {
    if (!line.trim()) continue;
    try {
      const v = JSON.parse(line) as unknown;
      if (v && typeof v === "object" && !Array.isArray(v)) out.push(v as Rec);
    } catch {
      // a torn line is skipped; the register's own chain check names it
    }
  }
  return out;
}

/** A question's section key, however it is written: question:3, Q-3 (through the register), 3, or a goal's own id. */
function sectionOf(raw: string, qs: Q.QuestionsSnapshot | null): string {
  const t = raw.trim();
  if (qs && /^Q-\d+$/i.test(t)) {
    const q = Q.findQuestion(qs, t);
    if (q) return q.section;
  }
  return P.sectionKey(t.replace(/^question:/i, ""));
}

// --- the shape ------------------------------------------------------------------------------------

export type QuestionRef = { section: string; id: string | null };

export type RunMetrics = {
  format: typeof METRICS_FORMAT;
  run: string;
  run_dir: string;
  measured_at: string;
  /** How the run ended, without the free text a done or a stop carries. */
  outcome: { outcome: string | null; by: string | null; at: string | null };
  registers: Record<string, boolean>;
  questions: { in_scope: QuestionRef[]; source: "register" | "goal" | "ledger" };
  negatives: {
    /** Whether the ledger is there to count answers from. */
    recorded: boolean;
    quick: { recorded: boolean; closes: number; count: number; items: Array<{ lead: string; seq: number; questions: string[]; held_seconds: number; jobs: number; objects: number }> };
    answers: number;
    reviewed: number;
    unreviewed_material: NegativeRow[];
    unreviewed_background: NegativeRow[];
    /** Negative answers still standing for questions no longer in scope (withdrawn, excluded, or a follow-up after done): history, not counted above. */
    out_of_scope: NegativeRow[];
  };
  coverage: {
    recorded: boolean;
    records: number;
    /**
     * Standing records whose results stand that the finish gate counts
     * reviewed: an attest with its review on the record itself, or on a
     * negative answer resting on it that the gate holds reviewed (the review
     * of the negative is the review of its search; the c10 pilot's
     * reviewers attested the answers, and the records read "0 reviewed").
     */
    reviewed: number;
    reviewed_on_record: number;
    reviewed_through_answer: number;
    /** Standing records whose results still stand, by the hub's field; a stale record is counted apart, never as complete. */
    complete: number;
    partial: number;
    not_computed: number;
    stale: Array<{ record: string; field: string | null; results: StaleResult[] }>;
    negatives_on_partial: Array<{ section: string; id: string | null; answer: string; coverage: string[] }>;
    negatives_without_coverage: Array<{ section: string; id: string | null; answer: string }>;
    /** Across standing coverage records that name their areas, how many say each area not_applicable: a sign to watch where a cap rests on the areas (docs/adr/0013, "A locator is not coverage"). */
    areas_not_applicable?: Record<string, number>;
  };
  /**
   * The established attests the review rule capped because a located value's
   * input no coverage record covered where a rival could live
   * (rival_area_uncovered, docs/adr/0013), counted from the attests'
   * recorded caps.
   */
  review_caps?: { rival_area_uncovered: number };
  /**
   * The confidence of each standing answer in scope, as its author stated
   * it and as the run records it (P.recordedConfidence: high stands only on
   * an established answer another seat attested established, naming the
   * alternatives it weighed), and each answer the run records lower, with
   * why. Words the harness writes, never the answer's own.
   */
  /**
   * The store sweeps (extensions/store-sweep.ts): the coverage records that
   * named what a hit would contain, how their sweeps ended (pending: none
   * recorded yet), the hit objects outside their records, the standing
   * negatives in scope a sweep holds now (by code), and the records with
   * hits that a revision naming what the sweep found released (its own
   * sweep clean).
   */
  sweeps: {
    recorded: boolean;
    records: number;
    pending: number;
    clean: number;
    with_hits: number;
    partial: number;
    hit_objects: number;
    /** Hits recorded as echoes (the run's own words, or a search's own; store-sweep.ts HitOrigin): named on their sweeps, holding nothing. */
    echoes: number;
    held: Array<{ section: string; id: string | null; answer: string; code: string; coverage: string }>;
    released: number;
  };
  confidence: {
    recorded: boolean;
    answers: number;
    stated: Record<"high" | "medium" | "low" | "none", number>;
    recorded_levels: Record<"high" | "medium" | "low" | "none", number>;
    lowered: Array<{ section: string; id: string | null; answer: string; why: string }>;
    /** Highs kept as declared: answers recorded before the run recorded confidence (no confidence_rule). */
    legacy: number;
  };
  /**
   * Under-claiming (docs/adr/0013, "What the report shows of an answer's
   * parts"): the standing partial answers in scope, those that carry parts,
   * and each whose asked parts are all established (asked: not marked
   * not_asked by a review; a part a review names missing is asked, and not
   * established), with its counts. A partial answer without parts is listed
   * apart and never counted either way. And the parts standing answers in
   * scope hold at the limit of the evidence (docs/adr/0013, "A part at the
   * limit of the evidence"), each with whether its bound is reviewed by
   * another seat. Counts and ids only.
   */
  claims: {
    recorded: boolean;
    partial: number;
    with_parts: number;
    without_parts: Array<{ section: string; id: string | null; answer: string }>;
    asked_all_established: Array<{ section: string; id: string | null; answer: string; asked: number; established: number; open: number; open_not_asked: number }>;
    limited?: Array<{ section: string; id: string | null; answer: string; part: string; bound: string; reviewed: boolean }>;
  };
  offers: {
    /** Whether the registers hold offer events at all (a run from before offers has none). */
    recorded: boolean;
    leads: OfferCounts & { by_reason: Record<string, OfferCounts> };
    questions: { made: number; accepted: number; declined: number; not_taken_up: number };
    /**
     * Reviews offered to one seat (a limiting route's review, a material
     * negative's review): taken up (the review its seat recorded), declined,
     * withdrawn (reviewed by another route, or superseded), lapsed, or still
     * open; and how many its seat took first (offer accept), whatever became
     * of them.
     */
    reviews: { made: number; accepted: number; declined: number; withdrawn: number; lapsed: number; open: number; taken: number; by_reason: Record<string, number> };
    wakes_before_offers: { recorded: boolean; made: number; taken_by_woken: number; taken_by_another: number; not_taken: number };
  };
  done: {
    /** Whether the trace is there to count them from. */
    recorded: boolean;
    calls: number;
    accepted: number;
    created_sentinel: number;
    refused: number;
    refused_by: Record<string, number>;
    hub_refused: number;
    not_yours: number;
    items: Array<{ at: string; agent: string; how: string }>;
  };
  /**
   * The finish's own acts (docs/adr/0015, "Preparing the finish"), from the
   * trace and the finish register: the coordinator's first done and whether
   * it was refused on late items (the refusal prepare exists to
   * remove), every done refused on late items, the finish tool's calls by
   * act (so a refusal renamed into more calls cannot pass for a gain), the
   * resolutions and checks the register holds, and the finish tail from
   * ready to the end with every seat's tokens in it.
   */
  finish: {
    /** Whether the trace is there to count them from. */
    recorded: boolean;
    /** The first done that was a finish (not another seat's, not a seat leaving on its cap, not an abandon vote): when, whose, and how it was answered. */
    first_done: { at: string; agent: string; how: string } | null;
    /**
     * Whether that first done was refused on what was late against the
     * report (null when there was none): the refusal a prepare exists to
     * remove. The goal's checks run only after it, so whether they would
     * have passed is not in the trace (replay reads it on the registers).
     */
    first_done_late: boolean | null;
    /** Every done refused on what was late against the report. */
    late_refusals: number;
    /** The finish tool's calls by act, whatever each answered. */
    calls: { prepare: number; resolve: number; resolve_batches: number; status: number; ack: number };
    /** The register's typed resolutions, the batches they came in, and its checks. */
    resolutions: number;
    batches: number;
    checks: number;
    /** From ready (tail.ready_at) to the end: minutes, every seat's tokens (null when no per-call record), and the finish's calls in it. */
    tail: { from: string | null; to: string | null; minutes: number | null; tokens: number | null; calls: { prepare: number; resolve: number; done: number; status: number; ack: number } };
  };
  /**
   * What the warnings and the review packets cost in deliveries (the Fable
   * review of the limits branch, P3-10): from the trace, each reply to a
   * record, an attest or a lead's close or confirmation that carried a
   * warning, and the warning codes they carried; from the lead register,
   * each review of an answer offered and delivered to its seat, each of
   * which leads with its source-first packet (leads.ts reviewPacketWords).
   * Every finish status also carries the warnings (finish.calls.status).
   */
  deliveries: {
    /** Whether the trace is there to count the warnings from. */
    recorded: boolean;
    warnings: { record: number; attest: number; lead_close: number };
    codes: Record<string, number>;
    /** Null when the lead register holds no offer events (a run from before offers). */
    review_packets: number | null;
  };
  tail: {
    /** Whether the ledger holds answers to measure the answer tails from. */
    recorded: boolean;
    end_at: string | null;
    end: "sentinel" | "stopped" | "paused" | null;
    ready_at: string | null;
    /** Where the ready time came from: readiness turning ready, the done that recorded it (readiness had not turned ready before the done passed), or the first answers (a run from before readiness). */
    ready_source: "readiness" | "done" | "first answers" | null;
    all_first_answered_at: string | null;
    all_final_answered_at: string | null;
    minutes_from_ready: number | null;
    minutes_from_first_answers: number | null;
    minutes_from_final_answers: number | null;
    unanswered: string[];
  };
  acquisition: {
    /** Whether the requests register is there; evidence_recorded, whether the store's journal is. */
    recorded: boolean;
    evidence_recorded: boolean;
    requests: number;
    by_stage: Record<string, number>;
    declined_by_policy: number;
    gaps: Array<{ rid: string; stage: string | null; state: string; questions: string[]; cause: string | null }>;
    questions_with_gap: string[];
    evidence_added: number;
    evidence_added_for_request: number;
  };
  interpretations: {
    recorded: boolean;
    total: number;
    valid: number;
    superseded: number;
    disputed: number;
    missing: number;
    jobs_under_leads: number;
    jobs_uninterpreted: string[];
    jobs_without_valid: string[];
  };
  reversals: {
    /** Whether the ledger is there (answer changes); leads_recorded, whether the lead register is (reopens). */
    recorded: boolean;
    leads_recorded: boolean;
    answer_supersessions: number;
    corrections: number;
    result_changes: Array<{ section: string; from: string; to: string; from_result: string | null; to_result: string | null; cause: "new_evidence" | "discoverable" }>;
    /**
     * An answer that claimed established recorded again partial after an
     * attest of it was capped (recorded best_candidate with its reasons in
     * `capped`, docs/adr/0015): what the review rule's caps cost, measured
     * rather than assumed (the Fable review of the limits branch, P2-3).
     * Each with the seats whose capped attests came before the revision.
     */
    partial_after_cap: Array<{ section: string; from: string; to: string; capped_by: string[] }>;
    negative_reopens: Array<{ lead: string; closed_seq: number; reopened_at: string; reopen_cause: string; cause: "new_evidence" | "discoverable" }>;
    new_evidence: number;
    discoverable: number;
  };
  cost: {
    /** Where the calls were read (question-cost.ts): the gateway's log, the seats' Pi sessions, or each seat's total spread over its trace rows (an estimate). */
    source: "model-gateway" | "pi-sessions" | "trace-estimate" | null;
    tokens: number;
    usd: number;
    per_question: Array<{ section: string; id: string | null; tokens: number; usd: number; leads: string[] }>;
    /** Calls made holding no lead and naming nothing, and the same by what they were (waiting, compaction, coordination, reading, other). */
    unheld: { tokens: number; usd: number; by_kind: Record<string, number> };
    /** Calls made holding no lead given to what they named (a review, a record, an act on a lead): in per_question, and counted here too. */
    named: { tokens: number };
    /** The finish's and the report's work made holding no lead (a finish call, a write of the report). */
    finish_and_report: { tokens: number; usd: number };
    leads_without_question: { tokens: number; usd: number; leads: string[] };
    /** A seat's budget the trace could not place (a host run's seat with no trace row): counted in the total, never dropped. */
    no_trace: { tokens: number; seats: string[] };
  };
  duplicates: {
    recorded: boolean;
    jobs_with_similar: string[];
    exact_repeats: string[];
    independent: string[];
    independent_with_similar: string[];
    same_as: { jobs: string[]; files: number; bytes: number; whole: string[] };
    recipe_merged: number;
    shadow_would_merge: number;
  };
  network: {
    recorded: boolean;
    requests: number;
    granted: number;
    denied: number;
    denied_by_code: Record<string, number>;
    operator_items: number;
    operator_items_open: number;
    grants: number;
    grants_by_status: Record<string, number>;
    fetches: number;
    captures: number;
    captures_complete: number;
    fetch_refusals: number;
    contamination: number;
  };
  /** What the run made of its packs' skills (skill-metrics.ts): loads, cards, tool jobs a seat ran holding the note on that tool, reloads after a compaction. */
  skills?: SkillMetrics;
  /** What the harness cost the seats: refusals, waits, compactions, the hub's health (friction-metrics.ts). */
  harness?: FrictionMetrics;
  notes: string[];
};

type OfferCounts = { made: number; accepted: number; declined: number; taken_by_another: number; lapsed: number; open: number };
export type NegativeRow = { section: string; id: string | null; answer: string; result: string };
/** A result of a coverage record that no longer stands, by code, with the entry that replaced it or the seats that dispute it: never their words. */
export type StaleResult = { result: string; code: "missing" | "rebound" | "superseded" | "disputed"; superseded_by?: string; disputed_by?: string[] };

// --- reading ---------------------------------------------------------------------------------------

type Context = {
  S: string;
  entries: P.LedgerEntry[];
  attestations: P.LedgerAttestation[];
  disputes: P.LedgerDispute[];
  sweeps: SW.SweepRecord[];
  replaced: Map<number, number>;
  leadEvents: L.LeadEvent[];
  leads: L.LeadsState;
  qs: Q.QuestionsSnapshot | null;
  journal: Rec[];
  evidenceTimes: number[];
  have: { ledger: boolean; leads: boolean; journal: boolean; requests: boolean; trace: boolean; finish: boolean; questions: boolean; network: boolean };
  notes: string[];
};

async function readContext(S: string): Promise<Context> {
  const notes: string[] = [];
  const entries = await P.readLedger(S).catch(() => [] as P.LedgerEntry[]);
  const attestations = await P.readAttestations(S).catch(() => [] as P.LedgerAttestation[]);
  const disputes = await P.readDisputes(S).catch(() => [] as P.LedgerDispute[]);
  const sweeps = await SW.readSweeps(S).catch(() => [] as SW.SweepRecord[]);
  const { events: leadEvents, text: leadText } = await L.readLeadEvents(S);
  const chain = L.verifyLeadChain(leadText);
  if (!chain.ok) notes.push(`the lead register's chain does not verify (${chain.reason} at line ${chain.broken_at}): read as written`);
  const leads = L.foldLeads(leadEvents, chain);
  let qs: Q.QuestionsSnapshot | null = null;
  try {
    qs = await Q.questionsSnapshot(S);
    if (!qs.state.questions.size) qs = null;
  } catch (err) {
    notes.push(`the question register could not be read (${(err as Error).message})`);
  }
  const journal = await jsonl(storePaths(S).journal);
  const evidenceTimes = journal.filter((l) => l.type === "evidence_added").map((l) => ms(l.at)).filter((t): t is number => t !== null).sort((a, b) => a - b);
  const have = {
    ledger: existsSync(join(S, "ledger", "entries.jsonl")),
    leads: existsSync(join(S, L.LEADS_LOG)),
    journal: existsSync(storePaths(S).journal),
    requests: existsSync(join(S, R.REQUESTS_LOG)),
    trace: existsSync(join(S, P.EVENTS_REL)),
    finish: existsSync(join(S, "leads", "finish.jsonl")),
    questions: existsSync(join(S, Q.QUESTIONS_LOG)),
    network: existsSync(join(S, "network", "grants.jsonl")) || existsSync(join(S, "network", "fetches.jsonl")),
  };
  return { S, entries, attestations, disputes, sweeps, replaced: P.supersededBy(entries), leadEvents, leads, qs, journal, evidenceTimes, have, notes };
}

/**
 * The questions in scope at the end of the run: the register's live ones (in
 * scope, not withdrawn, not a follow-up admitted after its done: a resume's
 * work, not this run's), else the goal's, else those the ledger answers.
 */
function inScope(c: Context): RunMetrics["questions"] {
  if (c.qs) {
    const list = [...c.qs.state.questions.values()].filter((q) => Q.liveInScope(q)).sort((a, b) => a.n - b.n);
    return { in_scope: list.map((q) => ({ section: q.section, id: q.id })), source: c.qs.seeded ? "register" : "goal" };
  }
  const sections = [...new Set(c.entries.filter((e) => e.kind === "answer" && str(e.section).startsWith("question:")).map((e) => sectionOf(str(e.section), null)))].sort();
  return { in_scope: sections.map((section) => ({ section, id: null })), source: "ledger" };
}

function isMaterial(section: string, c: Context): boolean {
  const q = c.qs?.bySection.get(section);
  return !q || q.materiality === "material";
}

/** The standing entries an answer cites for its own question (the gate's citedForQuestion). */
function citedOf(c: Context, e: P.LedgerEntry, section: string): P.LedgerEntry[] {
  return P.citedForQuestion(e, new Map(c.entries.map((x) => [x.seq, x])), c.replaced, section);
}

/** Whether a standing answer is a negative the bar holds: the finish gate's own test (a premise rejected on a search alone included). */
function isNegative(c: Context, e: P.LedgerEntry, section: string): boolean {
  return P.negativeByResult(NB.answerResult(e), citedOf(c, e, section));
}

/** A coverage record's results that no longer stand, as codes and ids. */
function staleResults(c: Context, rec: P.LedgerEntry): StaleResult[] {
  return P.coverageStaleness(rec, c.entries, c.disputes).map((x) => ({
    result: `E-${x.result}`,
    code: x.code,
    ...(x.by_seq !== undefined ? { superseded_by: `E-${x.by_seq}` } : {}),
    ...(x.disputes ? { disputed_by: [...new Set(x.disputes.map((d) => d.by))].sort() } : {}),
  }));
}

/** A coverage record as a comparison or a negative shows it: its field while its results stand, else stale. */
function coverageState(c: Context, rec: P.LedgerEntry): "complete" | "partial" | "not computed" | "stale" {
  if (staleResults(c, rec).length) return "stale";
  return rec.coverage === "complete" ? "complete" : rec.coverage === "partial" ? "partial" : "not computed";
}

/** The standing answer of each question section at the end of the run. */
function standingAnswers(c: Context): Map<string, P.LedgerEntry> {
  const out = new Map<string, P.LedgerEntry>();
  for (const e of c.entries) {
    if (e.kind !== "answer" || !str(e.section).startsWith("question:") || c.replaced.has(e.seq)) continue;
    const k = sectionOf(str(e.section), c.qs);
    const had = out.get(k);
    if (!had || e.seq > had.seq) out.set(k, e);
  }
  return out;
}

// --- the metrics ---------------------------------------------------------------------------------

function sweepsOf(c: Context, scope: RunMetrics["questions"]): RunMetrics["sweeps"] {
  const live = new Set(scope.in_scope.map((q) => q.section));
  const records = c.entries.filter((e) => e.kind === "coverage" && e.looked_for?.length);
  const of = (e: P.LedgerEntry) => SW.sweepOf({ hash: e.hash ?? P.ledgerHash(e, "genesis") }, c.sweeps);
  const states = records.map((e) => of(e));
  const held: RunMetrics["sweeps"]["held"] = [];
  for (const [section, e] of standingAnswers(c)) {
    if (!live.has(section)) continue;
    for (const h of P.sweepHolds(e, c.entries, c.sweeps, c.disputes, isMaterial(section, c), c.attestations)) held.push({ section, id: c.qs?.bySection.get(section)?.id ?? null, answer: `E-${e.seq}`, code: h.code, coverage: `E-${h.coverage.seq}` });
  }
  let released = 0;
  for (const e of records) {
    if (!of(e)?.hits.length) continue;
    const next = c.replaced.get(e.seq);
    const n = next !== undefined ? c.entries.find((x) => x.seq === next) : undefined;
    const sw = n ? of(n) : null;
    if (sw && !sw.hits.length && !sw.unsearched.length) released += 1;
  }
  return {
    recorded: c.have.ledger,
    records: records.length,
    pending: states.filter((x) => !x).length,
    clean: states.filter((x) => x?.state === "clean").length,
    with_hits: states.filter((x) => x?.hits.length).length,
    partial: states.filter((x) => x?.unsearched.length).length,
    hit_objects: states.reduce((n, x) => n + (x?.hits.length ?? 0), 0),
    echoes: states.reduce((n, x) => n + (x?.echoes?.length ?? 0), 0),
    held,
    released,
  };
}

function confidenceOf(c: Context, scope: RunMetrics["questions"]): RunMetrics["confidence"] {
  const live = new Set(scope.in_scope.map((q) => q.section));
  const blank = () => ({ high: 0, medium: 0, low: 0, none: 0 });
  const stated = blank();
  const recorded = blank();
  const lowered: RunMetrics["confidence"]["lowered"] = [];
  let answers = 0;
  let legacy = 0;
  for (const [section, e] of standingAnswers(c)) {
    if (!live.has(section)) continue;
    answers += 1;
    const r = P.recordedConfidence(e, c.attestations);
    if (r.legacy) legacy += 1;
    stated[r.stated ?? "none"] += 1;
    recorded[r.recorded ?? "none"] += 1;
    if (r.stated !== r.recorded) lowered.push({ section, id: c.qs?.bySection.get(section)?.id ?? null, answer: `E-${e.seq}`, why: r.why ?? "" });
  }
  return { recorded: c.have.ledger, answers, stated, recorded_levels: recorded, lowered, legacy };
}

/**
 * The standing partial answers in scope whose asked parts are all
 * established (protocol.ts answerPartsStanding, the reading the report and
 * the console show): the under-claiming count.
 */
function claimsOf(c: Context, scope: RunMetrics["questions"]): RunMetrics["claims"] {
  const live = new Set(scope.in_scope.map((q) => q.section));
  let partial = 0;
  const without: RunMetrics["claims"]["without_parts"] = [];
  const all: RunMetrics["claims"]["asked_all_established"] = [];
  const limited: NonNullable<RunMetrics["claims"]["limited"]> = [];
  for (const [section, e] of standingAnswers(c)) {
    if (live.has(section) && e.parts?.some((p) => p.status === "limited")) {
      const bounds = P.limitedBounds(e, c.entries, c.attestations, c.disputes);
      for (const p of e.parts.filter((x) => x.status === "limited")) limited.push({ section, id: c.qs?.bySection.get(section)?.id ?? null, answer: `E-${e.seq}`, part: p.id, bound: p.limited_by ?? "", reviewed: bounds.get(p.limited_by ?? "")?.reviewed === true });
    }
    if (!live.has(section) || NB.answerResult(e) !== "partial") continue;
    partial += 1;
    const id = c.qs?.bySection.get(section)?.id ?? null;
    const s = P.answerPartsStanding(e, c.attestations);
    if (!s) {
      without.push({ section, id, answer: `E-${e.seq}` });
      continue;
    }
    if (s.all_asked_established) all.push({ section, id, answer: `E-${e.seq}`, asked: s.asked, established: s.established, open: s.open, open_not_asked: s.open_not_asked });
  }
  return { recorded: c.have.ledger, partial, with_parts: partial - without.length, without_parts: without, asked_all_established: all, ...(limited.length ? { limited } : {}) };
}

function negativesAndCoverage(c: Context, scope: RunMetrics["questions"]): Pick<RunMetrics, "negatives" | "coverage"> {
  const closes = c.leadEvents.filter((e) => e.ev === "close" && e.disposition === "negative");
  const quick = closes.filter((e) => e.quick_negative).map((e) => ({
    lead: str(e.lead),
    seq: e.seq,
    questions: [...(c.leads.leads.get(str(e.lead))?.answers ?? [])],
    held_seconds: Math.round(num(e.quick_negative?.held_ms) / 1000),
    jobs: num(e.quick_negative?.jobs),
    objects: num(e.quick_negative?.objects),
  }));
  const bySeq = new Map(c.entries.map((e) => [e.seq, e]));
  const live = new Set(scope.in_scope.map((q) => q.section));
  const negatives = [...standingAnswers(c).entries()].filter(([section, e]) => isNegative(c, e, section));
  let reviewed = 0;
  let counted = 0;
  const unreviewedMaterial: NegativeRow[] = [];
  const unreviewedBackground: NegativeRow[] = [];
  const history: NegativeRow[] = [];
  const onPartial: RunMetrics["coverage"]["negatives_on_partial"] = [];
  const without: RunMetrics["coverage"]["negatives_without_coverage"] = [];
  for (const [section, e] of negatives) {
    const id = c.qs?.bySection.get(section)?.id ?? null;
    const row = { section, id, answer: `E-${e.seq}`, result: NB.answerResult(e) ?? "" };
    if (!live.has(section)) {
      history.push(row);
      continue;
    }
    counted += 1;
    const r = P.negativeReview(e, c.entries, c.attestations, c.disputes);
    if (r.reviewed) reviewed += 1;
    else if (isMaterial(section, c)) unreviewedMaterial.push(row);
    else unreviewedBackground.push(row);
    const cov = (e.support ?? []).map((x) => bySeq.get(x.seq)).filter((x): x is P.LedgerEntry => x?.kind === "coverage" && !c.replaced.has(x.seq));
    const states = cov.map((x) => coverageState(c, x));
    if (!cov.length) without.push({ section, id, answer: `E-${e.seq}` });
    else if (!states.includes("complete")) onPartial.push({ section, id, answer: `E-${e.seq}`, coverage: cov.map((x, i) => `E-${x.seq} ${states[i]}`) });
  }
  const records = c.entries.filter((e) => e.kind === "coverage" && !c.replaced.has(e.seq));
  const stale = records.map((x) => ({ record: `E-${x.seq}`, field: typeof x.coverage === "string" ? x.coverage : null, results: staleResults(c, x) })).filter((x) => x.results.length);
  const current = records.filter((x) => !stale.some((st) => st.record === `E-${x.seq}`));
  // Reviewed as the gate counts it: on the record while its results stand, or through a negative answer resting on it that the gate holds reviewed.
  const onRecord = new Set(current.filter((x) => P.negativeReview(x, c.entries, c.attestations, c.disputes).reviewed).map((x) => x.seq));
  const throughAnswer = new Set<number>();
  for (const x of current) {
    if (onRecord.has(x.seq)) continue;
    if (P.negativesResting(x, c.entries).some((a) => P.negativeReview(a, c.entries, c.attestations, c.disputes).reviewed)) throughAnswer.add(x.seq);
  }
  return {
    negatives: {
      recorded: c.have.ledger,
      quick: { recorded: c.have.leads, closes: closes.length, count: quick.length, items: quick },
      answers: counted,
      reviewed,
      unreviewed_material: unreviewedMaterial,
      unreviewed_background: unreviewedBackground,
      out_of_scope: history,
    },
    coverage: {
      recorded: c.have.ledger,
      records: records.length,
      reviewed: onRecord.size + throughAnswer.size,
      reviewed_on_record: onRecord.size,
      reviewed_through_answer: throughAnswer.size,
      complete: current.filter((x) => x.coverage === "complete").length,
      partial: current.filter((x) => x.coverage === "partial").length,
      not_computed: current.filter((x) => x.coverage !== "complete" && x.coverage !== "partial").length,
      stale,
      negatives_on_partial: onPartial,
      negatives_without_coverage: without,
      ...(records.some((x) => x.areas) ? { areas_not_applicable: Object.fromEntries(NB.COVERAGE_AREAS.map((a) => [a, current.filter((x) => x.areas?.[a] === "not_applicable").length])) } : {}),
    },
  };
}

/** The established attests capped for rival_area_uncovered, by their recorded reasons (protocol.ts reviewEvidenceCaps words them). */
function reviewCapsOf(c: Context): NonNullable<RunMetrics["review_caps"]> {
  const capped = c.attestations.filter((x) => P.attestationAct(x) === "attest" && (x.capped?.length ?? 0) > 0);
  return {
    rival_area_uncovered: capped.filter((x) => x.capped!.some((w) => w.startsWith("a locator is not coverage: "))).length,
  };
}

/**
 * Offers, from the registers' events: a lead offer is accepted by the claim
 * or confirm that names it, declined or lapsed by its own event, taken by
 * another seat when another seat claimed the lead after it was made and
 * before it was answered; one outcome each, in that order. Wakes from
 * before offers are counted apart.
 */
function offers(c: Context): RunMetrics["offers"] {
  const blank = (): OfferCounts => ({ made: 0, accepted: 0, declined: 0, taken_by_another: 0, lapsed: 0, open: 0 });
  const leads = { ...blank(), by_reason: {} as Record<string, OfferCounts> };
  const wakes = { made: 0, taken_by_woken: 0, taken_by_another: 0, not_taken: 0 };
  // Read by name: a register from before offers has none of these kinds, and one from after has more.
  const ev = c.leadEvents as unknown as Array<Rec & { seq: number; ev: string; lead?: string; to?: string; holder?: string; by: string }>;
  const recorded = ev.some((e) => e.ev.startsWith("offer"));
  const reviews = { made: 0, accepted: 0, declined: 0, withdrawn: 0, lapsed: 0, open: 0, taken: 0, by_reason: {} as Record<string, number> };
  for (let i = 0; i < ev.length; i += 1) {
    const e = ev[i];
    if (e.ev !== "offer" && e.ev !== "wake") continue;
    // A review's offer is answered by what names it (the review that took it up, a decline, a lapse), never by a claim.
    if (e.ev === "offer" && (e.reason === "route_review" || e.reason === "negative_review")) {
      const after = ev.slice(i + 1).filter((x) => x.offer === e.seq);
      const how = after.some((x) => x.ev === "offer_accept" || x.ev === "route_review") ? "accepted" : after.some((x) => x.ev === "offer_decline") ? "declined" : after.some((x) => x.ev === "offer_withdraw") ? "withdrawn" : after.some((x) => x.ev === "offer_lapse") ? "lapsed" : "open";
      reviews.made += 1;
      reviews[how] += 1;
      if (after.some((x) => x.ev === "offer_take")) reviews.taken += 1;
      reviews.by_reason[str(e.reason)] = (reviews.by_reason[str(e.reason)] ?? 0) + 1;
      continue;
    }
    const lead = str(e.lead);
    const to = str(e.to);
    // What happened to it while it stood: until the lead's next claim (or a confirm), release, close or reopen.
    const seen = new Set<string>();
    for (let k = i + 1; k < ev.length; k += 1) {
      const x = ev[k];
      if (x.lead !== lead) continue;
      if (x.ev === "claim" || x.ev === "confirm") {
        if (x.offer === e.seq) seen.add("accepted");
        else if (x.ev === "claim") seen.add(str(x.holder ?? x.by) === to ? "woken" : "another");
        break;
      }
      if (x.ev === "offer_decline" && x.offer === e.seq) seen.add("declined");
      if (x.ev === "offer_lapse" && x.offer === e.seq) seen.add("lapsed");
      if (x.ev === "release" || x.ev === "reopen" || x.ev === "close") break;
    }
    const outcome = e.ev === "wake" ? (seen.has("woken") || seen.has("accepted") ? "woken" : seen.has("another") ? "another" : "none") : seen.has("accepted") ? "accepted" : seen.has("declined") ? "declined" : seen.has("another") ? "taken_by_another" : seen.has("lapsed") ? "lapsed" : "open";
    if (e.ev === "wake") {
      wakes.made += 1;
      if (outcome === "woken") wakes.taken_by_woken += 1;
      else if (outcome === "another") wakes.taken_by_another += 1;
      else wakes.not_taken += 1;
      continue;
    }
    const reason = str(e.reason) || "wake";
    const r = (leads.by_reason[reason] ??= blank());
    const key = outcome as keyof OfferCounts;
    for (const t of [leads, r]) {
      t.made += 1;
      t[key] += 1;
    }
  }
  const qev = c.qs?.state.events ?? [];
  const qOffers = qev.filter((e) => e.ev === "offer");
  const answeredQ = (seq: number, what: string) => qev.some((x) => x.ev === what && (x as Rec).offer === seq);
  const questions = { made: qOffers.length, accepted: qOffers.filter((o) => answeredQ(o.seq, "offer_accept")).length, declined: qOffers.filter((o) => answeredQ(o.seq, "offer_decline")).length, not_taken_up: 0 };
  questions.not_taken_up = questions.made - questions.accepted - questions.declined;
  return { recorded: recorded || qOffers.length > 0, leads, questions, reviews, wakes_before_offers: { recorded: c.have.leads, ...wakes } };
}

/** Why a done was refused, by the trace's own record of it. */
function doneRefusal(reason: string, r: Rec): string {
  if (r.late !== undefined || /landed (?:after|against)/i.test(reason) || /^late against the report: /.test(reason)) return "late posts";
  if (r.abandon !== undefined) return "abandon vote";
  if (/changed while the finish line ran/i.test(reason)) return "finish line unsettled";
  if (/finish line is not met/i.test(reason)) return "finish line not met";
  return "other";
}

/** done calls, from the trace: each seat's own line, the hub's refusals of markDone, and a finish that was not the seat's (done_deferred). */
function doneCalls(events: readonly P.SwarmEvent[], recorded: boolean): RunMetrics["done"] {
  const out: RunMetrics["done"] = { recorded, calls: 0, accepted: 0, created_sentinel: 0, refused: 0, refused_by: {}, hub_refused: 0, not_yours: 0, items: [] };
  const why = doneRefusal;
  for (const e of events) {
    const r = (e.result && typeof e.result === "object" ? e.result : {}) as Rec;
    const at = P.hostTime(e);
    if (e.tool === "done") {
      out.calls += 1;
      if (r.ok === false) {
        const reason = str(r.reason);
        const k = why(reason, r);
        out.refused += 1;
        out.refused_by[k] = (out.refused_by[k] ?? 0) + 1;
        out.items.push({ at, agent: e.agent, how: `refused: ${k}` });
      } else {
        out.accepted += 1;
        if (r.created_sentinel === true) out.created_sentinel += 1;
        out.items.push({ at, agent: e.agent, how: r.created_sentinel === true ? "accepted: wrote the sentinel" : "accepted" });
      }
    } else if (e.tool === "done_deferred") {
      out.calls += 1;
      out.not_yours += 1;
      out.items.push({ at, agent: e.agent, how: "not yours" });
    } else if (e.tool === "hub_call" && str((e.args as Rec)?.fn) === "markDone" && r.ok === false) {
      // A refusal the hub counted and wrote once (repeated_before, or the flush's repeated) is that many calls.
      const n = r.repeated !== undefined ? num(r.repeated) : 1 + num(r.repeated_before);
      if (!n) continue;
      out.calls += n;
      out.hub_refused += n;
      out.items.push({ at, agent: str((e.args as Rec)?.agent), how: `refused by the hub${n > 1 ? ` (${n})` : ""}` });
    }
  }
  // A refusal on the hub reached its seat as a thrown error, never as a done line of its own: its hub_call line is the call.
  return out;
}

/**
 * The finish's own acts (RunMetrics.finish): from the trace (the done
 * lines, the finish tool's calls) and the finish register (resolutions,
 * batches, checks); the tail's tokens from the run's per-call record
 * (question-cost.ts runCalls), every seat's, between ready and the end.
 */
async function finishActs(c: Context, events: readonly P.SwarmEvent[], recorded: boolean, t: RunMetrics["tail"]): Promise<RunMetrics["finish"]> {
  const out: RunMetrics["finish"] = { recorded, first_done: null, first_done_late: null, late_refusals: 0, calls: { prepare: 0, resolve: 0, resolve_batches: 0, status: 0, ack: 0 }, resolutions: 0, batches: 0, checks: 0, tail: { from: t.ready_at, to: t.end_at, minutes: t.minutes_from_ready, tokens: null, calls: { prepare: 0, resolve: 0, done: 0, status: 0, ack: 0 } } };
  const from = ms(t.ready_at);
  const to = ms(t.end_at);
  // The tail runs from ready to the end: through the done that wrote the sentinel (its own row comes after the sentinel's stamp), else to the stop.
  const last = events.findIndex((e) => e.tool === "done" && ((e.result ?? {}) as Rec).created_sentinel === true);
  const inTail = (i: number, at: number | null) => at !== null && from !== null && to !== null && at >= from && (last >= 0 ? i <= last : at <= to);
  for (const [i, e] of events.entries()) {
    const r = (e.result && typeof e.result === "object" ? e.result : {}) as Rec;
    const a = (e.args && typeof e.args === "object" ? e.args : {}) as Rec;
    const at = P.hostTime(e);
    const tailed = inTail(i, ms(at));
    if (e.tool === "done") {
      if (tailed) out.tail.calls.done += 1;
      // A seat leaving on its own cap, an abandon vote, and a done after the sentinel (it succeeds, and ends nothing) are not the finish.
      if (a.abandon === true || str(a.reason) === "agent_cap") continue;
      const refused = r.ok === false;
      const kind = refused ? doneRefusal(str(r.reason), r) : null;
      if (kind === "late posts") out.late_refusals += 1;
      if (!out.first_done) {
        out.first_done = { at, agent: e.agent, how: refused ? `refused: ${kind}` : r.created_sentinel === true ? "accepted: wrote the sentinel" : "accepted" };
        out.first_done_late = kind === "late posts";
      }
    } else if (e.tool === "finish") {
      const act = str(a.action) || "status";
      if (act === "prepare" || act === "resolve" || act === "status" || act === "ack") {
        out.calls[act] += 1;
        if (tailed) out.tail.calls[act] += 1;
      }
      if (act === "resolve" && Array.isArray(a.items)) out.calls.resolve_batches += 1;
    }
  }
  const finish = await jsonl(join(c.S, "leads", "finish.jsonl"));
  const batches = new Set<string>();
  for (const f of finish) {
    if (f.ev === "resolve") {
      out.resolutions += 1;
      if (str(f.batch)) batches.add(str(f.batch));
    } else if (f.ev === "check") out.checks += 1;
  }
  out.batches = batches.size;
  if (from !== null && to !== null) {
    const { source, calls } = await runCalls(c.S).catch(() => ({ source: "none" as const, calls: [] as Array<{ at: number; tokens: number }> }));
    if (source !== "none") out.tail.tokens = Math.round(calls.filter((x) => Number.isFinite(x.at) && x.at >= from && x.at <= to).reduce((n, x) => n + x.tokens, 0));
  }
  return out;
}

/** The replies that carried a warning, by act, and the codes; the review packets delivered (RunMetrics["deliveries"]). */
function deliveries(c: Context, events: readonly P.SwarmEvent[], recorded: boolean): RunMetrics["deliveries"] {
  const out: RunMetrics["deliveries"] = { recorded, warnings: { record: 0, attest: 0, lead_close: 0 }, codes: {}, review_packets: null };
  for (const e of events) {
    const r = (e.result && typeof e.result === "object" ? e.result : {}) as Rec;
    if (!Array.isArray(r.warned) || !r.warned.length) continue;
    const act = e.tool === "record" ? "record" : e.tool === "attest" ? "attest" : e.tool.startsWith("lead") ? "lead_close" : null;
    if (!act) continue;
    out.warnings[act] += 1;
    for (const code of r.warned) out.codes[str(code)] = (out.codes[str(code)] ?? 0) + 1;
  }
  const ev = c.leadEvents as unknown as Array<Rec & { seq: number; ev: string; entry?: unknown; offer?: unknown }>;
  if (ev.some((e) => e.ev.startsWith("offer"))) {
    const bySeq = new Map(c.entries.map((e) => [e.seq, e]));
    const offers = new Map(ev.filter((e) => e.ev === "offer" && typeof e.entry === "number").map((e) => [e.seq, e.entry as number]));
    out.review_packets = ev.filter((e) => e.ev === "offer_seen" && typeof e.offer === "number" && offers.has(e.offer) && bySeq.get(offers.get(e.offer)!)?.kind === "answer" && str(bySeq.get(offers.get(e.offer)!)?.section).startsWith("question:")).length;
  }
  return out;
}

async function tail(c: Context, scope: RunMetrics["questions"], outcome: RunMetrics["outcome"]): Promise<RunMetrics["tail"]> {
  const endAt = ms(outcome.at);
  const end: RunMetrics["tail"]["end"] = outcome.outcome === "stopped" && existsSync(join(c.S, P.STOPPED_REL)) ? "stopped" : outcome.outcome === "paused" ? "paused" : existsSync(join(c.S, P.SENTINEL_REL)) ? "sentinel" : null;
  // Readiness where the finish register records it (docs/adr/0015): the last turn to ready before the end, not undone before it.
  // The done that wrote the sentinel records ready itself when readiness had not turned ready before it (finish.ts finishTransaction): at the end, a moment after the sentinel's stamp.
  let readyAt: number | null = null;
  let readyAtDone = false;
  const finish = await jsonl(join(c.S, "leads", "finish.jsonl"));
  for (const f of finish) {
    if (f.ev !== "readiness") continue;
    let t = ms(f.at);
    if (t === null) continue;
    if (endAt !== null && t > endAt) {
      if (!(f.at_done === true && f.ready === true)) continue;
      t = endAt;
    }
    if (f.ready === true && readyAt === null) {
      readyAt = t;
      readyAtDone = f.at_done === true;
    }
    if (f.ready === false) readyAt = null;
  }
  const first = new Map<string, number>();
  for (const e of c.entries) {
    if (e.kind !== "answer" || !str(e.section).startsWith("question:")) continue;
    const t = ms(e.at);
    if (t === null) continue;
    const k = sectionOf(str(e.section), c.qs);
    if (!first.has(k) || t < first.get(k)!) first.set(k, t);
  }
  const standing = standingAnswers(c);
  const unanswered = scope.in_scope.filter((q) => !standing.has(q.section)).map((q) => q.id ?? `question:${q.section}`);
  const allFirst = scope.in_scope.length && !unanswered.length ? Math.max(...scope.in_scope.map((q) => first.get(q.section) ?? 0)) : null;
  const allFinal = scope.in_scope.length && !unanswered.length ? Math.max(...scope.in_scope.map((q) => ms(standing.get(q.section)!.at) ?? 0)) : null;
  const hasReadiness = finish.some((f) => f.ev === "readiness");
  const ready = hasReadiness ? readyAt : allFirst;
  return {
    recorded: c.have.ledger,
    end_at: iso(endAt),
    end,
    ready_at: iso(ready),
    ready_source: hasReadiness ? (readyAt !== null ? (readyAtDone ? "done" : "readiness") : null) : allFirst !== null ? "first answers" : null,
    all_first_answered_at: iso(allFirst),
    all_final_answered_at: iso(allFinal),
    minutes_from_ready: minutes(ready, endAt),
    minutes_from_first_answers: minutes(allFirst, endAt),
    minutes_from_final_answers: minutes(allFinal, endAt),
    unanswered,
  };
}

async function acquisition(c: Context): Promise<RunMetrics["acquisition"]> {
  const snap = await R.requestsSnapshot(c.S).catch(() => null);
  const list = snap ? [...snap.requests.values()].filter((r) => r.kind === "acquisition") : [];
  const byStage: Record<string, number> = {};
  const gaps: RunMetrics["acquisition"]["gaps"] = [];
  let byPolicy = 0;
  for (const r of list) {
    const stage = r.stage ?? "requested";
    byStage[stage] = (byStage[stage] ?? 0) + 1;
    if (r.closed?.cause === "case_policy" || r.stages.some((s) => s.by === "case policy" && s.stage === "declined")) byPolicy += 1;
    if (stage !== "validated") gaps.push({ rid: r.rid, stage: r.stage, state: r.state, questions: [...r.questions], cause: r.closed?.cause ?? null });
  }
  const added = c.journal.filter((l) => l.type === "evidence_added");
  return {
    recorded: c.have.requests,
    evidence_recorded: c.have.journal,
    requests: list.length,
    by_stage: byStage,
    declined_by_policy: byPolicy,
    gaps,
    questions_with_gap: [...new Set(gaps.flatMap((g) => g.questions))].sort(),
    evidence_added: added.length,
    evidence_added_for_request: added.filter((l) => str(l.request)).length,
  };
}

function interpretations(c: Context): RunMetrics["interpretations"] {
  const view = L.ledgerView(c.entries, c.disputes);
  let total = 0;
  let valid = 0;
  let superseded = 0;
  let disputed = 0;
  let missing = 0;
  const withoutValid: string[] = [];
  for (const [job, list] of c.leads.interpretations) {
    let any = false;
    for (const it of list) {
      total += 1;
      const s = L.entryStands(view, it.entry);
      if (s.ok) {
        valid += 1;
        any = true;
      } else if (!view.bySeq.has(it.entry)) missing += 1;
      else if (view.replaced.has(it.entry)) superseded += 1;
      else disputed += 1;
    }
    if (!any) withoutValid.push(job);
  }
  const underLeads = [...c.leads.jobLead.keys()];
  return {
    recorded: c.have.leads,
    total,
    valid,
    superseded,
    disputed,
    missing,
    jobs_under_leads: underLeads.length,
    jobs_uninterpreted: underLeads.filter((j) => !c.leads.interpretations.has(j)).sort(),
    jobs_without_valid: withoutValid.sort(),
  };
}

/** New evidence arrived between two instants (an evidence_added line of the store's journal). */
function evidenceBetween(c: Context, from: number | null, to: number | null): boolean {
  if (from === null || to === null) return false;
  return c.evidenceTimes.some((t) => t > from && t <= to);
}

function reversals(c: Context): RunMetrics["reversals"] {
  const bySeq = new Map(c.entries.map((e) => [e.seq, e]));
  let supersessions = 0;
  let corrections = 0;
  const changes: RunMetrics["reversals"]["result_changes"] = [];
  const partialAfterCap: RunMetrics["reversals"]["partial_after_cap"] = [];
  for (const e of c.entries) {
    if (e.kind !== "answer" || e.supersedes === undefined) continue;
    const old = bySeq.get(e.supersedes);
    if (!old || old.kind !== "answer") continue;
    supersessions += 1;
    const a = NB.answerResult(old);
    const b = NB.answerResult(e);
    if (a === b) {
      corrections += 1;
      continue;
    }
    changes.push({ section: sectionOf(str(e.section), c.qs), from: `E-${old.seq}`, to: `E-${e.seq}`, from_result: a, to_result: b, cause: evidenceBetween(c, ms(old.at), ms(e.at)) ? "new_evidence" : "discoverable" });
    if (b === "partial" && P.claimsEstablished(old)) {
      const target = old.hash ?? P.ledgerHash(old, "genesis");
      const at = ms(e.at);
      const capped = c.attestations.filter((x) => P.attestationAct(x) === "attest" && x.target === target && !old.authors.includes(x.by) && (x.capped?.length ?? 0) > 0 && (at === null || (ms(x.at) ?? 0) <= at));
      if (capped.length) partialAfterCap.push({ section: sectionOf(str(e.section), c.qs), from: `E-${old.seq}`, to: `E-${e.seq}`, capped_by: [...new Set(capped.map((x) => x.by))] });
    }
  }
  const reopens: RunMetrics["reversals"]["negative_reopens"] = [];
  const lastNegative = new Map<string, { seq: number; at: number | null }>();
  for (const e of c.leadEvents) {
    const lead = str(e.lead);
    if (e.ev === "close") {
      if (e.disposition === "negative") lastNegative.set(lead, { seq: e.seq, at: ms(e.at) });
      else lastNegative.delete(lead);
    } else if (e.ev === "reopen" && lastNegative.has(lead)) {
      const closed = lastNegative.get(lead)!;
      const cause = e.cause === "evidence_added" || evidenceBetween(c, closed.at, ms(e.at)) ? "new_evidence" : "discoverable";
      reopens.push({ lead, closed_seq: closed.seq, reopened_at: e.at, reopen_cause: str(e.cause) || "agent", cause });
      lastNegative.delete(lead);
    }
  }
  const all = [...changes.map((x) => x.cause), ...reopens.map((x) => x.cause)];
  return {
    recorded: c.have.ledger,
    leads_recorded: c.have.leads,
    answer_supersessions: supersessions,
    corrections,
    result_changes: changes,
    partial_after_cap: partialAfterCap,
    negative_reopens: reopens,
    new_evidence: all.filter((x) => x === "new_evidence").length,
    discoverable: all.filter((x) => x === "discoverable").length,
  };
}

/**
 * Whole units shared among buckets in proportion to their exact shares, so
 * that the parts add up to the whole (the largest remainder method): each
 * bucket gets its share rounded down, and what is left goes one unit at a
 * time to the largest remainders, ties by the buckets' order. The rounding
 * of scripts/question-cost.ts (roundParts), which the report uses too.
 */
export function apportion(total: number, shares: Array<[string, number]>): Map<string, number> {
  return roundParts(shares, 1, total);
}

/**
 * Tokens apportioned by lead (scripts/question-cost.ts, the report's own
 * method): each call's tokens go to the leads its seat held when it was
 * made, in equal parts, and a lead's part to the questions it answers, in
 * equal parts. A call made while the seat held no lead is counted as
 * unheld; a lead that answers no question is counted apart. The parts are
 * exact until the end, then rounded to whole tokens and millionths of a
 * dollar so that they add up to the run's totals.
 */
async function cost(c: Context): Promise<RunMetrics["cost"]> {
  // What a call made holding no lead named is keyed as the leads' questions are: by section, when the run knows it.
  const known = (sec: string) => (c.qs ? c.qs.bySection.has(sec) : /^[A-Za-z0-9._-]{1,32}$/.test(sec));
  const qc = await questionCost(c.S, c.leadEvents, (lead) => [...new Set((c.leads.leads.get(lead)?.answers ?? []).map((a) => sectionOf(a, c.qs)))], { questionKey: (raw) => (known(sectionOf(raw, c.qs)) ? sectionOf(raw, c.qs) : null) });
  const source: RunMetrics["cost"]["source"] = qc.source === "gateway" ? "model-gateway" : qc.source === "sessions" ? "pi-sessions" : qc.source === "trace" ? "trace-estimate" : null;
  // The tokens exactly as the report shows them (qc.shown); the dollars in millionths, rounded the same way, so both add up.
  const MICRO = 0.000001;
  const usd = roundParts<string>([...[...qc.byQuestionUsd].map(([k, v]) => [`q\u0000${k}`, v] as const), ["u", qc.unheldUsd] as const, ["n", qc.noQuestionUsd] as const, ["r", qc.runUsd] as const], MICRO, Math.round(qc.totalUsd / MICRO));
  const dollars = (x: number) => Number(x.toFixed(6));
  return {
    source,
    tokens: qc.shown.total,
    usd: dollars([...usd.values()].reduce((a, b) => a + b, 0)),
    per_question: [...qc.byQuestion.keys()].map((section) => ({ section, id: c.qs?.bySection.get(section)?.id ?? null, tokens: qc.shown.byQuestion.get(section) ?? 0, usd: usd.get(`q\u0000${section}`) ?? 0, leads: [...(qc.byQuestionLeads.get(section) ?? [])].sort() })).sort((a, b) => b.tokens - a.tokens || a.section.localeCompare(b.section)),
    unheld: { tokens: [...qc.shown.unheld.values()].reduce((a, b) => a + b, 0), usd: usd.get("u") ?? 0, by_kind: Object.fromEntries(qc.shown.unheldByKind) },
    named: { tokens: qc.shown.named },
    finish_and_report: { tokens: qc.shown.run, usd: usd.get("r") ?? 0 },
    leads_without_question: { tokens: qc.shown.noQuestion, usd: usd.get("n") ?? 0, leads: [...qc.noQuestionLeads].sort() },
    no_trace: { tokens: [...qc.shown.noTrace.values()].reduce((a, b) => a + b, 0), seats: [...qc.shown.noTrace.keys()].sort() },
  };
}

async function duplicates(c: Context): Promise<RunMetrics["duplicates"]> {
  const accepted = c.journal.filter((l) => l.type === "job_accepted");
  const recorded = accepted.some((l) => l.reuse !== undefined) || c.journal.some((l) => l.type === "job_similar" || l.type === "job_same_as");
  const independent = accepted.filter((l) => (l.spec as Rec | undefined)?.independent === true).map((l) => str(l.job));
  const similar = c.journal.filter((l) => l.type === "job_similar");
  const exact = similar.filter((l) => ((l.similar as Rec[] | undefined) ?? []).some((s) => (s.match === "same command" || s.match === "same tool and arguments") && s.objects === "same")).map((l) => str(l.job));
  const same = c.journal.filter((l) => l.type === "job_same_as");
  let files = 0;
  let bytes = 0;
  const whole: string[] = [];
  for (const l of same) {
    const list = (l.same_as as Rec[] | undefined) ?? [];
    files += list.length;
    bytes += list.reduce((a, s) => a + num(s.bytes), 0);
    const m = await readFile(join(storePaths(c.S).jobs, str(l.job), "manifest.json"), "utf8").then((t) => JSON.parse(t) as { files?: Array<{ bytes?: number }> }).catch(() => null);
    const nonEmpty = (m?.files ?? []).filter((f) => num(f.bytes) > 0).length;
    if (m && nonEmpty > 0 && list.length >= nonEmpty) whole.push(str(l.job));
  }
  const withSimilar = similar.map((l) => str(l.job));
  return {
    recorded,
    jobs_with_similar: withSimilar.filter((j) => !independent.includes(j)),
    exact_repeats: exact.filter((j) => !independent.includes(j)),
    independent,
    independent_with_similar: withSimilar.filter((j) => independent.includes(j)),
    same_as: { jobs: same.map((l) => str(l.job)), files, bytes, whole },
    recipe_merged: c.journal.filter((l) => l.type === "job_deduplicated").length,
    shadow_would_merge: c.journal.filter((l) => l.type === "job_would_merge").length,
  };
}

/** The network's records; a grant's status is read at `now`: the run's end when it ended, so a finished run measures the same whenever it is read. */
async function network(S: string, now: number): Promise<RunMetrics["network"]> {
  const st = await readNetState(S).catch(() => null);
  const recorded = Boolean(st && (st.events.length || st.fetchEvents.length));
  const out: RunMetrics["network"] = { recorded, requests: 0, granted: 0, denied: 0, denied_by_code: {}, operator_items: 0, operator_items_open: 0, grants: 0, grants_by_status: {}, fetches: 0, captures: 0, captures_complete: 0, fetch_refusals: 0, contamination: 0 };
  if (!st || !recorded) return out;
  const reqs = [...st.requests.values()];
  out.requests = reqs.length;
  out.granted = reqs.filter((r) => r.decision?.decision === "granted").length;
  out.denied = reqs.filter((r) => r.decision?.decision === "denied").length;
  for (const r of reqs) if (r.decision?.decision === "denied") for (const reason of r.decision.reasons.length ? r.decision.reasons : [{ code: "unstated" }]) out.denied_by_code[reason.code] = (out.denied_by_code[reason.code] ?? 0) + 1;
  out.operator_items = st.items.size;
  out.operator_items_open = [...st.items.values()].filter((i) => !i.closed).length;
  out.grants = st.grants.size;
  for (const g of st.grants.values()) {
    const s = grantStatus(g, st, now).status;
    out.grants_by_status[s] = (out.grants_by_status[s] ?? 0) + 1;
  }
  const fetches = [...st.fetches.values()].flat();
  out.fetches = fetches.length;
  out.captures = fetches.filter((f) => f.result?.delivered).length;
  out.captures_complete = fetches.filter((f) => f.result?.delivered && f.result.complete).length;
  out.fetch_refusals = st.refusals.length + fetches.filter((f) => f.result?.refused).length;
  out.contamination = st.contamination.length;
  return out;
}

// --- one run --------------------------------------------------------------------------------------

/** `now`: when a grant's status is read for a run still going (tests fix it); a run that ended is read at its end. */
export async function measureRun(runDirArg: string, o: { now?: number } = {}): Promise<RunMetrics> {
  const S = resolve(runDirArg);
  const c = await readContext(S);
  const ended = await P.runOutcome(S).catch(() => ({ outcome: null, by: null, at: null, why: null }));
  const outcome = { outcome: ended.outcome, by: ended.by, at: ended.at };
  const { events, unreadable } = await P.readEventLogChecked(S);
  if (unreadable) c.notes.push(`the trace is ${unreadable}: done calls are not counted`);
  const scope = inScope(c);
  const registers: Record<string, boolean> = { ...c.have };
  const nc = negativesAndCoverage(c, scope);
  const off = offers(c);
  if (c.have.leads && !off.recorded) c.notes.push("no offer events in the registers (a run from before offers): offers are not counted; its wakes are");
  const dup = await duplicates(c);
  if (!dup.recorded && c.journal.some((l) => l.type === "job_accepted")) c.notes.push("no reuse hints on the journal (a run from before them): duplicates are not counted");
  const t = await tail(c, scope, outcome);
  if (!c.have.finish) c.notes.push("no finish register (a run from before readiness was recorded): the tail is measured from the first answers");
  const endAt = ms(outcome.at);
  const m: RunMetrics = {
    format: METRICS_FORMAT,
    run: basename(S),
    run_dir: S,
    measured_at: new Date().toISOString(),
    outcome,
    registers,
    questions: scope,
    ...nc,
    sweeps: sweepsOf(c, scope),
    confidence: confidenceOf(c, scope),
    claims: claimsOf(c, scope),
    review_caps: reviewCapsOf(c),
    offers: off,
    done: doneCalls(events, c.have.trace && !unreadable),
    finish: await finishActs(c, events, c.have.trace && !unreadable, t),
    deliveries: deliveries(c, events, c.have.trace && !unreadable),
    tail: t,
    acquisition: await acquisition(c),
    interpretations: interpretations(c),
    reversals: reversals(c),
    cost: await cost(c),
    duplicates: dup,
    network: await network(S, endAt ?? o.now ?? Date.now()),
    ...(c.have.trace && !unreadable ? { skills: skillMetrics(events) } : {}),
    ...(c.have.trace && !unreadable ? { harness: frictionMetrics(events, c.journal) } : {}),
    notes: c.notes,
  };
  if (!m.cost.source) m.notes.push("no per-call token record (no model gateway log, no Pi sessions, and no seat total with calls on the trace): cost per question is not measured");
  return m;
}

// --- two runs --------------------------------------------------------------------------------------

/**
 * A result's kind: it asserts (established, partial), it is a negative the
 * bar holds (bounded_negative, not_determinable, a premise rejected on a
 * search alone), a premise a finding shows false, out of scope, or unknown
 * (an answer recorded before results, which is not guessed at).
 */
export type ResultKind = "asserts" | "negative" | "premise_rejected" | "out_of_scope" | "unknown";

export type QuestionSide = {
  /** Whether the question is in this run's scope at its end. */
  in_scope: boolean;
  answer: string | null;
  result: string | null;
  kind: ResultKind | null;
  reviewed: boolean | null;
  coverage: string[];
  /** The operator's acceptance while it stands (Q.acceptanceStands); one that no longer does is acceptance_lapsed. */
  accepted: string | null;
  acceptance_lapsed: string | null;
  /** The answer still standing for a question that is no longer in scope: history, not compared. */
  history: { answer: string; result: string | null } | null;
  /** A partial answer with parts: whether every asked part is established (claims.asked_all_established); null for any other answer, or one without parts. */
  asked_all_established: boolean | null;
};
export type Verdict = "agree" | "class_differs" | "disagree" | "unknown" | "only_a" | "only_b" | "neither";
export type Comparison = {
  format: typeof COMPARE_FORMAT;
  a: { run: string; run_dir: string };
  b: { run: string; run_dir: string };
  compared_at: string;
  same_questions: boolean;
  questions: Array<{ section: string; id: string | null; a: QuestionSide; b: QuestionSide; verdict: Verdict; flags: string[] }>;
  summary: { questions: number; agree: number; class_differs: number; disagree: number; unknown: number; one_sided: number; neither: number; negative_disagreements: number; shared_partial_negatives: number; under_claimed: { a: number; b: number } };
  notes: string[];
};

function sideOf(c: Context, section: string, live: Set<string>, standing: Map<string, P.LedgerEntry>): QuestionSide {
  const e = standing.get(section);
  const q = c.qs?.bySection.get(section);
  const stands = q?.accepted ? Q.acceptanceStands(q, L.ledgerView(c.entries, c.disputes)) : false;
  const accepted = q?.accepted && stands ? q.accepted.as : null;
  const lapsed = q?.accepted && !stands ? q.accepted.as : null;
  const blank: QuestionSide = { in_scope: live.has(section), answer: null, result: null, kind: null, reviewed: null, coverage: [], accepted, acceptance_lapsed: lapsed, history: null, asked_all_established: null };
  if (!e) return blank;
  const result = NB.answerResult(e);
  if (!live.has(section)) return { ...blank, history: { answer: `E-${e.seq}`, result } };
  const negative = isNegative(c, e, section);
  const kind: ResultKind = result === null ? "unknown" : negative ? "negative" : result === "established" || result === "partial" ? "asserts" : result === "premise_not_supported" ? "premise_rejected" : result === "out_of_scope" ? "out_of_scope" : "unknown";
  const bySeq = new Map(c.entries.map((x) => [x.seq, x]));
  const cov = (e.support ?? []).map((x) => bySeq.get(x.seq)).filter((x): x is P.LedgerEntry => x?.kind === "coverage" && !c.replaced.has(x.seq)).map((x) => coverageState(c, x));
  const parts = result === "partial" ? P.answerPartsStanding(e, c.attestations) : null;
  return { ...blank, answer: `E-${e.seq}`, result, kind, reviewed: negative ? P.negativeReview(e, c.entries, c.attestations, c.disputes).reviewed : null, coverage: cov, asked_all_established: parts ? parts.all_asked_established : null };
}

export async function compareRuns(aDir: string, bDir: string): Promise<Comparison> {
  const A = await readContext(resolve(aDir));
  const B = await readContext(resolve(bDir));
  const notes = [...A.notes.map((n) => `A: ${n}`), ...B.notes.map((n) => `B: ${n}`)];
  const sa = inScope(A);
  const sb = inScope(B);
  const liveA = new Set(sa.in_scope.map((q) => q.section));
  const liveB = new Set(sb.in_scope.map((q) => q.section));
  const text = (c: Context, s: string) => c.qs?.bySection.get(s)?.text ?? null;
  const sections = [...new Set([...liveA, ...liveB])].sort((x, y) => (/^\d+$/.test(x) && /^\d+$/.test(y) ? Number(x) - Number(y) : x.localeCompare(y)));
  const sameQuestions = liveA.size === liveB.size && [...liveA].every((s) => liveB.has(s) && text(A, s) === text(B, s));
  if (!sameQuestions) notes.push("the two runs' questions in scope differ (in number, or in their text): compared by section, and a question in one run's scope alone is one-sided");
  const standA = standingAnswers(A);
  const standB = standingAnswers(B);
  const rows: Comparison["questions"] = [];
  for (const section of sections) {
    const a = sideOf(A, section, liveA, standA);
    const b = sideOf(B, section, liveB, standB);
    const flags: string[] = [];
    let verdict: Verdict;
    if (!a.answer && !b.answer) verdict = "neither";
    else if (!b.answer) verdict = "only_a";
    else if (!a.answer) verdict = "only_b";
    else if (a.kind === "unknown" || b.kind === "unknown") verdict = "unknown";
    else verdict = a.result === b.result ? "agree" : a.kind === b.kind ? "class_differs" : "disagree";
    if (verdict === "unknown") flags.push(`${[a.kind === "unknown" ? "A" : "", b.kind === "unknown" ? "B" : ""].filter(Boolean).join(" and ")} recorded no result class: not compared`);
    for (const [neg, other, n, o] of [[a, b, "A", "B"], [b, a, "B", "A"]] as const) {
      if (neg.kind === "negative" && other.kind === "asserts") flags.push(`a negative in ${n} (${neg.result}) is asserted in ${o} (${other.result}): re-examine the negative's coverage and detection assumptions`);
    }
    if (a.kind === "negative" && b.kind === "negative") {
      const partial = (s: QuestionSide) => !s.coverage.includes("complete");
      if (partial(a) && partial(b)) flags.push("both runs are negative and neither rests on complete coverage that still stands: agreement may be a shared blind spot");
      if (a.reviewed === false || b.reviewed === false) flags.push(`a negative not reviewed by another seat in ${[a.reviewed === false ? "A" : "", b.reviewed === false ? "B" : ""].filter(Boolean).join(" and ")}`);
    }
    for (const [s, n] of [[a, "A"], [b, "B"]] as const) if (s.acceptance_lapsed) flags.push(`${n}'s acceptance (${s.acceptance_lapsed}) no longer stands`);
    if (verdict === "agree" && (a.accepted || b.accepted)) flags.push("agreement where a run's question was accepted by the operator as limited");
    // Under-claiming: a partial answer whose every asked part is established, in one run or both.
    const under = [a.asked_all_established ? "A" : "", b.asked_all_established ? "B" : ""].filter(Boolean);
    if (under.length) flags.push(`partial in ${under.join(" and ")} with every asked part established (under-claimed: what is open, a review marks not asked)`);
    rows.push({ section, id: A.qs?.bySection.get(section)?.id ?? B.qs?.bySection.get(section)?.id ?? null, a, b, verdict, flags });
  }
  const count = (v: Verdict) => rows.filter((r) => r.verdict === v).length;
  return {
    format: COMPARE_FORMAT,
    a: { run: basename(resolve(aDir)), run_dir: resolve(aDir) },
    b: { run: basename(resolve(bDir)), run_dir: resolve(bDir) },
    compared_at: new Date().toISOString(),
    same_questions: sameQuestions,
    questions: rows,
    summary: {
      questions: rows.length,
      agree: count("agree"),
      class_differs: count("class_differs"),
      disagree: count("disagree"),
      unknown: count("unknown"),
      one_sided: count("only_a") + count("only_b"),
      neither: count("neither"),
      negative_disagreements: rows.filter((r) => r.flags.some((f) => f.startsWith("a negative in"))).length,
      shared_partial_negatives: rows.filter((r) => r.flags.some((f) => f.includes("shared blind spot"))).length,
      under_claimed: { a: rows.filter((r) => r.a.asked_all_established).length, b: rows.filter((r) => r.b.asked_all_established).length },
    },
    notes,
  };
}

// --- the tables -------------------------------------------------------------------------------------

function table(rows: string[][]): string[] {
  const widths = rows[0].map((_, i) => Math.max(...rows.map((r) => r[i].length)));
  return rows.map((r) => r.map((c, i) => (i === r.length - 1 ? c : c.padEnd(widths[i]))).join("  ").trimEnd());
}

const list = (xs: string[]): string => (xs.length ? xs.join(", ") : "none");
const counts = (o: Record<string, number>): string => (Object.keys(o).length ? Object.entries(o).sort().map(([k, v]) => `${k} ${v}`).join(", ") : "none");
const mins = (m: number | null): string => (m === null ? "-" : `${m} min`);
const qname = (x: { section: string; id: string | null }): string => x.id ?? `question:${x.section}`;
/** A metric whose register the run does not have: said, never a zero. */
const absent = (what: string) => `not recorded (no ${what})`;

export function metricsText(m: RunMetrics): string {
  const lines: string[] = [`Metrics: run ${m.run}${m.outcome.outcome ? ` (${m.outcome.outcome})` : ""}`, `Questions in scope: ${m.questions.in_scope.length} (from the ${m.questions.source})`, ""];
  const o = m.offers;
  const d = m.done;
  const a = m.acquisition;
  const i = m.interpretations;
  const r = m.reversals;
  const n = m.network;
  const t = m.tail;
  const neg = m.negatives;
  const cov = m.coverage;
  const LEDGER = "ledger/entries.jsonl";
  const LEADS = "leads/leads.jsonl";
  const rows: string[][] = [
    ["Metric", "Value"],
    ["Quick negatives", neg.quick.recorded ? `${neg.quick.count} of ${neg.quick.closes} negative closes${neg.quick.count ? `: ${neg.quick.items.map((x) => `${x.lead} (${x.held_seconds} s, ${x.jobs} job, ${x.objects} object)`).join(", ")}` : ""}` : absent(LEADS)],
    ["Negative answers", neg.recorded ? `${neg.answers} standing in scope; ${neg.reviewed} reviewed${neg.out_of_scope.length ? `; ${neg.out_of_scope.length} more on questions no longer in scope (${list(neg.out_of_scope.map((x) => `${qname(x)} ${x.answer}`))}), not counted` : ""}` : absent(LEDGER)],
    ["Unreviewed negatives", neg.recorded ? `${neg.unreviewed_material.length} material (${list(neg.unreviewed_material.map((x) => `${qname(x)} ${x.answer}`))}), ${neg.unreviewed_background.length} background` : absent(LEDGER)],
    ["Coverage records", cov.recorded ? `${cov.records} standing: ${cov.complete} complete, ${cov.partial} partial, ${cov.not_computed} not computed, ${cov.stale.length} stale (a result no longer stands: ${list(cov.stale.map((x) => `${x.record} ${x.results.map((y) => `${y.result} ${y.code}`).join(" ")}`))}); ${cov.reviewed} reviewed by another seat as the gate counts it (${cov.reviewed_on_record} on the record, ${cov.reviewed_through_answer} through the negative answer resting on it)` : absent(LEDGER)],
    ["Negatives on partial coverage", cov.recorded ? `${cov.negatives_on_partial.length} (${list(cov.negatives_on_partial.map((x) => `${qname(x)} ${x.answer}`))}); ${cov.negatives_without_coverage.length} cite no coverage record` : absent(LEDGER)],
    ["Store sweeps", m.sweeps.recorded ? `${m.sweeps.records} coverage record(s) named what a hit would contain: ${m.sweeps.clean} clean, ${m.sweeps.with_hits} with hits outside the record (${m.sweeps.hit_objects} hit(s)), ${m.sweeps.echoes} echo(es) named and holding nothing, ${m.sweeps.partial} partial, ${m.sweeps.pending} pending; ${m.sweeps.held.length} negative hold(s) now (${list(m.sweeps.held.map((x) => `${qname(x)} ${x.answer} ${x.code} on ${x.coverage}`))}); ${m.sweeps.released} record(s) with hits released by a revision whose sweep is clean` : absent(LEDGER)],
    ["Confidence", m.confidence.recorded ? `${m.confidence.answers} standing answer(s) in scope, recorded: high ${m.confidence.recorded_levels.high}, medium ${m.confidence.recorded_levels.medium}, low ${m.confidence.recorded_levels.low}, none ${m.confidence.recorded_levels.none}; stated high ${m.confidence.stated.high}; ${m.confidence.lowered.length} recorded lower than stated${m.confidence.lowered.length ? ` (${list(m.confidence.lowered.map((x) => `${qname(x)} ${x.answer}: ${x.why}`))})` : ""}${m.confidence.legacy ? `; ${m.confidence.legacy} high(s) kept as declared (recorded before the run recorded confidence)` : ""}` : absent(LEDGER)],
    ["Under-claiming", m.claims.recorded ? `${m.claims.asked_all_established.length} of ${m.claims.with_parts} partial answer(s) with parts have every asked part established (asked: not marked not_asked by a review)${m.claims.asked_all_established.length ? ` (${list(m.claims.asked_all_established.map((x) => `${qname(x)} ${x.answer}: ${x.established} of ${x.asked} asked established, ${x.open} open, ${x.open_not_asked} not asked`))})` : ""}; ${m.claims.partial} partial in scope${m.claims.without_parts.length ? `, ${m.claims.without_parts.length} without parts, not counted (${list(m.claims.without_parts.map((x) => `${qname(x)} ${x.answer}`))})` : ""}` : absent(LEDGER)],
    ["Limited parts", m.claims.recorded ? (m.claims.limited?.length ? `${m.claims.limited.length} part(s) held at the limit of the evidence, ${m.claims.limited.filter((x) => x.reviewed).length} on a bound another seat reviewed (${list(m.claims.limited.map((x) => `${qname(x)} ${x.answer} "${x.part}" by ${x.bound}${x.reviewed ? "" : ", not reviewed"}`))})` : "none") : absent(LEDGER)],
    ["Rival areas", m.claims.recorded ? `${m.review_caps?.rival_area_uncovered ?? 0} established attest(s) capped because a located value's input was not covered where a rival could live; not_applicable per area across standing coverage records: ${m.coverage.areas_not_applicable ? Object.entries(m.coverage.areas_not_applicable).map(([k, v]) => `${k} ${v}`).join(", ") : "no record names its areas"}` : absent(LEDGER)],
    ["Offers (leads)", o.recorded ? `${o.leads.made} made: ${o.leads.accepted} accepted, ${o.leads.declined} declined, ${o.leads.taken_by_another} taken by another seat, ${o.leads.lapsed} lapsed, ${o.leads.open} with no outcome` : o.wakes_before_offers.recorded ? "not recorded (no offer events: a run from before offers)" : absent(LEADS)],
    ["Offers (questions)", o.recorded ? `${o.questions.made} made: ${o.questions.accepted} accepted, ${o.questions.declined} declined, ${o.questions.not_taken_up} not taken up` : o.wakes_before_offers.recorded ? "not recorded (no offer events: a run from before offers)" : absent(LEADS)],
    ["Offers (reviews)", o.recorded ? `${o.reviews.made} made (${Object.entries(o.reviews.by_reason).map(([k, n]) => `${k} ${n}`).join(", ") || "none"}): ${o.reviews.accepted} taken up, ${o.reviews.declined} declined, ${o.reviews.withdrawn} withdrawn (reviewed by another route, or superseded), ${o.reviews.lapsed} lapsed, ${o.reviews.open} with no outcome; ${o.reviews.taken} taken by their seat first (offer accept)` : o.wakes_before_offers.recorded ? "not recorded (no offer events: a run from before offers)" : absent(LEADS)],
    ["Wakes (before offers)", o.wakes_before_offers.recorded ? `${o.wakes_before_offers.made}: ${o.wakes_before_offers.taken_by_woken} taken by the woken seat, ${o.wakes_before_offers.taken_by_another} by another, ${o.wakes_before_offers.not_taken} not taken` : absent(LEADS)],
    ["done calls", d.recorded ? `${d.calls}: ${d.accepted} accepted (${d.created_sentinel} wrote the sentinel), ${d.refused} refused by the seat's checks (${counts(d.refused_by)}), ${d.hub_refused} refused by the hub, ${d.not_yours} not the seat's finish` : absent("readable traces/events.jsonl")],
    ["Finish", m.finish.recorded ? `the first done ${m.finish.first_done ? `${m.finish.first_done.how} (${m.finish.first_done.agent})${m.finish.first_done_late ? ", on late items" : ""}` : "never came"}; ${m.finish.late_refusals} done(s) refused on late items; finish calls: ${m.finish.calls.prepare} prepare, ${m.finish.calls.resolve} resolve (${m.finish.calls.resolve_batches} with items), ${m.finish.calls.status} status, ${m.finish.calls.ack} ack; ${m.finish.resolutions} resolution(s) in the register (${m.finish.batches} batch(es)), ${m.finish.checks} check(s); from ready to the end: ${m.finish.tail.minutes === null ? "not measured" : `${mins(m.finish.tail.minutes)}, ${m.finish.tail.tokens === null ? "tokens not measured" : `${m.finish.tail.tokens} tokens`}, ${m.finish.tail.calls.prepare} prepare, ${m.finish.tail.calls.resolve} resolve, ${m.finish.tail.calls.done} done`}` : absent("readable traces/events.jsonl")],
    ["Warnings delivered", m.deliveries.recorded ? `${m.deliveries.warnings.record + m.deliveries.warnings.attest + m.deliveries.warnings.lead_close} repl(ies) carried a warning: ${m.deliveries.warnings.record} to a record, ${m.deliveries.warnings.attest} to an attest, ${m.deliveries.warnings.lead_close} to a lead's close or confirmation (${counts(m.deliveries.codes)}); ${m.deliveries.review_packets === null ? "review packets not recorded (no offer events)" : `${m.deliveries.review_packets} review packet(s) delivered with an answer's review offer`}` : absent("readable traces/events.jsonl")],
    ["Tail to the end", !t.end_at ? "not measured (the run has not ended)" : `${mins(t.minutes_from_ready)} from ready (${t.ready_source === "done" ? "recorded by the done: readiness had not turned ready before it passed" : (t.ready_source ?? "never ready")}); ${t.recorded ? `${mins(t.minutes_from_first_answers)} from the first answers, ${mins(t.minutes_from_final_answers)} from the final ones${t.unanswered.length ? `; unanswered: ${list(t.unanswered)}` : ""}` : `the answer tails ${absent(LEDGER)}`}`],
    ["Acquisition", a.recorded ? `${a.requests} request(s) (${counts(a.by_stage)}; ${a.declined_by_policy} declined by the case policy); ${a.gaps.length} gap(s)${a.questions_with_gap.length ? ` on ${list(a.questions_with_gap)}` : ""}` : absent("requests/requests.jsonl")],
    ["Evidence added", a.evidence_recorded ? `${a.evidence_added} time(s), ${a.evidence_added_for_request} for a request` : absent("store/journal.jsonl")],
    ["Interpretations", i.recorded ? `${i.total}: ${i.valid} valid, ${i.superseded} on a superseded entry, ${i.disputed} on a disputed one${i.missing ? `, ${i.missing} on no entry` : ""}; ${i.jobs_uninterpreted.length} of ${i.jobs_under_leads} lead jobs uninterpreted, ${i.jobs_without_valid.length} with no valid interpretation` : absent(LEADS)],
    ["Reversals", r.recorded ? `${r.result_changes.length + r.negative_reopens.length}: ${r.new_evidence} after new evidence, ${r.discoverable} discoverable in the original evidence (${r.result_changes.length} answer result changes, ${r.leads_recorded ? `${r.negative_reopens.length} negative leads reopened` : `negative reopens ${absent(LEADS)}`}); ${r.corrections} corrections kept the result; ${r.partial_after_cap.length} established answer(s) recorded partial after a capped attest${r.partial_after_cap.length ? ` (${list(r.partial_after_cap.map((x) => `question:${x.section} ${x.from} to ${x.to}, capped by ${x.capped_by.join(" ")}`))})` : ""}` : absent(LEDGER)],
    ["Cost", m.cost.source ? `${m.cost.tokens} tokens, $${m.cost.usd} (from ${m.cost.source === "model-gateway" ? "the model gateway's log" : m.cost.source === "pi-sessions" ? "the seats' Pi sessions" : "each seat's total spread over its calls on the trace, an estimate"}); ${m.cost.named.tokens} given to the questions and leads a call made holding no lead named (reviews, records, lead acts), ${m.cost.finish_and_report.tokens} on the finish and the report, ${m.cost.unheld.tokens} spent holding no lead and naming nothing (${Object.entries(m.cost.unheld.by_kind).map(([k, n]) => `${k} ${n}`).join(", ") || "none"}), ${m.cost.leads_without_question.tokens} on leads that answer no question${m.cost.no_trace.tokens ? `, ${m.cost.no_trace.tokens} a seat spent that the trace could not place (${m.cost.no_trace.seats.join(", ")})` : ""}` : "not measured (no per-call token record)"],
    ["Duplicates", m.duplicates.recorded ? `${m.duplicates.jobs_with_similar.length} jobs with similar work by another seat (${m.duplicates.exact_repeats.length} exact repeats); ${m.duplicates.independent.length} independent reproductions; same_as ${m.duplicates.same_as.files} file(s), ${m.duplicates.same_as.bytes} bytes in ${m.duplicates.same_as.jobs.length} job(s), ${m.duplicates.same_as.whole.length} wholly; recipes merged ${m.duplicates.recipe_merged}` : `not recorded${m.duplicates.shadow_would_merge ? ` (the retired shadow merge said ${m.duplicates.shadow_would_merge})` : " (no reuse hints on the store's journal)"}`],
    ["Skills", m.skills ? skillMetricsWords(m.skills) : absent("readable traces/events.jsonl")],
    ["Harness", m.harness ? frictionWords(m.harness) : absent("readable traces/events.jsonl")],
    ["Network", n.recorded ? `${n.requests} request(s): ${n.granted} granted, ${n.denied} denied (${counts(n.denied_by_code)}); ${n.operator_items} operator item(s), ${n.operator_items_open} open; ${n.grants} grant(s) (${counts(n.grants_by_status)}); ${n.fetches} fetch(es), ${n.captures} capture(s), ${n.fetch_refusals} refused by the fetch service${n.contamination ? `; contamination ${n.contamination}` : ""}` : "not used (no network/ records)"],
  ];
  lines.push(...table(rows));
  if (m.cost.per_question.length) {
    lines.push("", "Cost per question (tokens apportioned by lead):");
    lines.push(...table([["Question", "Tokens", "USD", "Leads"], ...m.cost.per_question.map((q) => [qname(q), String(q.tokens), String(q.usd), q.leads.join(" ")])]));
  }
  if (m.notes.length) lines.push("", ...m.notes.map((x) => `Note: ${x}`));
  return `${lines.join("\n")}\n`;
}

export function compareText(c: Comparison): string {
  const side = (s: QuestionSide) =>
    s.answer
      ? `${s.result ?? "no result class"}${s.asked_all_established ? " (every asked part established)" : ""}${s.reviewed === false ? " (unreviewed)" : ""}${s.coverage.length ? ` [${s.coverage.join(", ")}]` : ""}${s.accepted ? ` accepted ${s.accepted}` : ""}`
      : !s.in_scope
        ? `not in scope${s.history ? ` (${s.history.answer} ${s.history.result ?? "no result class"}, history)` : ""}`
        : "no answer";
  const lines = [`Compare: A ${c.a.run}, B ${c.b.run}${c.same_questions ? "" : " (their questions differ)"}`, ""];
  lines.push(...table([["Question", "A", "B", "Verdict"], ...c.questions.map((q) => [q.id ?? `question:${q.section}`, side(q.a), side(q.b), q.verdict])]));
  const flagged = c.questions.filter((q) => q.flags.length);
  if (flagged.length) {
    lines.push("");
    for (const q of flagged) for (const f of q.flags) lines.push(`Flag ${q.id ?? `question:${q.section}`}: ${f}`);
  }
  const s = c.summary;
  lines.push("", `${s.questions} question(s): ${s.agree} agree, ${s.class_differs} of the same kind in another class, ${s.disagree} disagree, ${s.unknown} with no result class to compare, ${s.one_sided} answered in one run only, ${s.neither} in neither; ${s.negative_disagreements} negative(s) the other run asserted, ${s.shared_partial_negatives} shared negative(s) without complete coverage.`);
  lines.push(`Under-claiming: ${s.under_claimed.a} partial answer(s) in A and ${s.under_claimed.b} in B with every asked part established (asked: not marked not_asked by a review).`);
  lines.push("Agreement is not confirmation: two runs of one harness can share a blind spot.");
  if (c.notes.length) lines.push("", ...c.notes.map((x) => `Note: ${x}`));
  return `${lines.join("\n")}\n`;
}

// --- the command --------------------------------------------------------------------------------------

function isRunDir(p: string): boolean {
  try {
    return statSync(p).isDirectory();
  } catch {
    return false;
  }
}

async function main(argv: string[]): Promise<number> {
  const json = argv.includes("--json");
  const args = argv.filter((a) => a !== "--json");
  const usage = "usage: metrics.ts <run-dir> [--json] | metrics.ts --compare <run-dir-A> <run-dir-B> [--json]\n";
  if (args[0] === "--compare") {
    const [a, b] = args.slice(1);
    if (!a || !b || args.length !== 3) {
      process.stderr.write(usage);
      return 2;
    }
    for (const d of [a, b]) {
      if (!isRunDir(d)) {
        process.stderr.write(`metrics.ts: ${d} is not a run directory\n`);
        return 2;
      }
    }
    const c = await compareRuns(a, b);
    process.stdout.write(json ? `${JSON.stringify(c, null, 2)}\n` : compareText(c));
    return 0;
  }
  if (args.length !== 1 || args[0].startsWith("--")) {
    process.stderr.write(usage);
    return 2;
  }
  if (!isRunDir(args[0])) {
    process.stderr.write(`metrics.ts: ${args[0]} is not a run directory\n`);
    return 2;
  }
  const m = await measureRun(args[0]);
  process.stdout.write(json ? `${JSON.stringify(m, null, 2)}\n` : metricsText(m));
  return 0;
}

if (process.argv[1] && resolve(process.argv[1]) === resolve(fileURLToPath(import.meta.url))) {
  process.exit(await main(process.argv.slice(2)));
}
