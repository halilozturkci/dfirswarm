#!/usr/bin/env node
/**
 * A goal's check (ADR 0002): the questions rest on the ledger.
 *
 * Ledger mode (no --report; ledger version 4): each named section has its
 * `answer` entry — `question:<id>` for each of the goal's questions, and
 * `summary` and `narrative` when the goal names them — and the ledger gate
 * (extensions/protocol.ts, ledgerGate) finds nothing left open: every answer
 * still stands on what it cites (nothing it rests on superseded without its
 * correction cited, disputed or resting on a failed job without the answer
 * saying why, no answer it rests on fallen), a critic other than its author
 * attested or disputed it, it is not disputed itself, and no contradiction
 * stands that no answer weighs and no limitation names. A question's answer
 * rests on a standing finding whose refs resolve now, bytes checked where the
 * run sealed them (one of them an object of the run), a complete search where
 * the question asks whether something exists, or a limitation
 * (examination-limited). Each defect is printed with what fixes
 * it; a defect a standing limitation names lets the run end and stays a
 * defect (the release counts it). So the finish line refuses a done once,
 * naming the fix, and the next done passes when each defect left is named.
 * Tokens an answer asserts that no cited entry holds are counted, never
 * failed: that is the release's to weigh.
 *
 * Report mode (--report, the check goals used before version 4): every
 * named section of the report rests on the ledger. A section's entries are
 * those it cites (#<seq> or E-<seq>, a range such as #72–#74 too) and those
 * that name it in `answers`. It passes when one of them, standing, is:
 * - a finding with refs that all resolve, at least one of them an object of
 *   the run (unresolved:<why> alone names none): answered;
 * - a search that found nothing (absence), complete, with refs that resolve
 *   when it has any: answered, as not found, when the question asks whether
 *   something exists (the goal names those with --existence); for any other
 *   question it documents the search and no more, and the section is
 *   examination-limited. On the Belka run s306463 scoped negative searches
 *   counted as answers and the check said 18 answered, 0 examination-limited,
 *   while the critic's sign-off said several exact answers were unavailable;
 * - a limitation: the examination could not establish it, and says why:
 *   examination-limited, which a reader is told apart from answered.
 * A hypothesis never answers. A finding resting on the kept output of a job
 * that failed passes and is named. How sure the swarm said it was is not
 * asked: a check on confidence would teach a swarm to declare it. A ledger
 * whose chain is broken answers nothing.
 *
 * Nothing here knows a case: the goal names the sections, as its questions
 * are numbered, or points at the brief that numbers them. Run from the
 * sandbox, as every check is:
 *
 *   node --experimental-strip-types --no-warnings "$SWARM_HARNESS/scripts/check-answers.ts" \
 *     --sections 1,2,3,summary,narrative
 *   node … check-answers.ts --sections-in inputs/CASE.md --sections summary,narrative
 *   node … check-answers.ts --report work/report.md --sections 1,2,3        (report mode)
 *   node … check-answers.ts --sections 1,2,3,summary,narrative --existence 2
 *     (question 2 asks whether something exists: a complete search that found
 *     nothing answers it; for 1 and 3 it documents the search and no more)
 *
 * Exit 0 when every section does; 1 when one does not (each named, with what
 * it rests on, why none of it counts and what fixes it); 2 on a usage error.
 */
import { readFile } from "node:fs/promises";
import { externalLineage } from "./net-broker.ts";
import { join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import {
  acceptanceExcuses,
  answerSection,
  answerReviews,
  briefQuestions,
  carriedCoverage,
  heldAsBestCandidate,
  ledgerGate,
  negativeReview,
  partialOutputCites,
  coverageProblems,
  forbiddenMaterialClasses,
  readAttestations,
  readDisputes,
  readLedger,
  sectionAnswersId,
  sectionKey,
  supersededBy,
  verifyAttestationChain,
  verifyDisputeChain,
  verifyLedgerChain,
  LEDGER_ATTESTATIONS,
  LEDGER_DISPUTES,
  type LedgerDefect,
  type LedgerEntry,
} from "../extensions/protocol.ts";
import { answerResult, resultWords, NEGATIVE_RESULTS } from "../extensions/negative-bar.ts";
import { committedLogHashes, resolveRef } from "./evidence-store.ts";
import { producerIndex } from "./output-hygiene.ts";
import { LEDGER_SWEEPS, readImportSweeps, readSweeps, reconcileSweeps, verifySweepChain } from "../extensions/store-sweep.ts";

type Entry = { seq: number; kind: string; refs?: string[]; supersedes?: number; answers?: string[]; completion?: string; reason?: string; status?: string };

/** A section id as the goal numbers it: "3", "Q3", "q3" and the question register's "Q-3" are section 3. */
export function sectionId(id: string): string {
  return id.trim().replace(/^q-?(?=\d)/i, "");
}

/** The seqs a text cites: #12, E-12, and every seq of a range #12–#15 (at most 50 a range). */
export function citedSeqs(text: string): number[] {
  const out = new Set<number>();
  for (const m of text.matchAll(/(?:#|\bE-)(\d{1,5})(?:\s*[–-]\s*(?:#|E-)?(\d{1,5}))?/g)) {
    const a = Number(m[1]);
    const b = m[2] ? Number(m[2]) : a;
    if (b >= a && b - a <= 50) for (let n = a; n <= b; n += 1) out.add(n);
    else out.add(a);
  }
  return [...out];
}

/** The report's sections by number: the text under `## <n>.` up to the next `## `. */
export function sections(report: string): Map<string, string> {
  const out = new Map<string, string>();
  let current: string | null = null;
  for (const line of report.split("\n")) {
    const h = /^##\s+(\d+)\./.exec(line);
    if (h) {
      current = h[1];
      out.set(current, "");
      continue;
    }
    if (/^##\s/.test(line)) {
      current = null;
      continue;
    }
    if (current) out.set(current, `${out.get(current)}${line}\n`);
  }
  return out;
}

export type SectionOutcome = "answered" | "limited" | "unanswered";

/** The prefix of the check's last line: its outcomes as JSON, for the finish line (scripts/finish-gate.ts). */
export const ANSWERS_MARK = "CHECK_ANSWERS_JSON";

/**
 * Whether a section's question asks whether something exists: only then does
 * a complete search that found nothing answer it. The goal says which, with
 * --existence; nothing here reads a question's words to guess.
 */
export function asksExistence(existence: readonly string[], section: string): boolean {
  const id = sectionId(section.startsWith("question:") ? section.slice("question:".length) : section);
  return existence.some((x) => sectionId(x) === id);
}

export async function checkAnswers(sandbox: string, reportPath: string, wanted: string[], existence: readonly string[] = []): Promise<{ ok: boolean; lines: string[]; outcomes: Record<string, SectionOutcome> }> {
  const S = resolve(sandbox);
  const outcomes: Record<string, SectionOutcome> = {};
  const report = await readFile(join(S, reportPath), "utf8").catch(() => null);
  if (report === null) return { ok: false, lines: [`no ${reportPath}`], outcomes };
  const text = await readFile(join(S, "ledger", "entries.jsonl"), "utf8").catch(() => "");
  const chain = verifyLedgerChain(text);
  if (!chain.ok) return { ok: false, lines: [`the ledger's chain is broken at line ${chain.broken_at} (${chain.reason}): no section can rest on it`], outcomes };
  const entries = text
    .split("\n")
    .filter((l) => l.trim())
    .map((l) => JSON.parse(l) as Entry);
  const bySeq = new Map(entries.map((e) => [e.seq, e]));
  const replaced = new Set(entries.map((e) => e.supersedes).filter((n): n is number => typeof n === "number"));
  const logs = await committedLogHashes(S);
  const parts = sections(report);
  const lines: string[] = [];
  let ok = true;
  for (const n of wanted) {
    const body = parts.get(n);
    if (body === undefined) {
      ok = false;
      outcomes[n] = "unanswered";
      lines.push(`section ${n}: no "## ${n}." heading in ${reportPath}`);
      continue;
    }
    const cited = citedSeqs(body);
    // Entries that name the section themselves come first: the agent said so, the prose need not.
    const tagged = entries.filter((e) => !replaced.has(e.seq) && (e.answers ?? []).some((a) => sectionId(a) === sectionId(n))).map((e) => e.seq);
    const candidates = [...new Set([...tagged, ...cited])];
    const why: string[] = [];
    let answered: string | null = null;
    let limited: string | null = null;
    for (const seq of candidates) {
      const e = bySeq.get(seq);
      if (!e) continue;
      const via = tagged.includes(seq) ? ", tagged for this section" : "";
      if (replaced.has(seq)) {
        why.push(`#${seq} is superseded`);
        continue;
      }
      if (e.kind === "hypothesis") {
        why.push(`#${seq} is a hypothesis (${e.status ?? "open"}), not an answer`);
        continue;
      }
      if (e.kind === "limitation") {
        limited ??= `#${seq} (a limitation: ${e.reason ?? "no reason"}${via})`;
        continue;
      }
      if (e.kind !== "finding" && e.kind !== "absence") continue;
      if (e.kind === "absence" && e.completion && e.completion !== "complete") {
        why.push(`#${seq} is a search that was ${e.completion}: it holds only for what was searched`);
        continue;
      }
      if (e.kind === "finding" && !e.refs?.length) {
        why.push(`#${seq} names no refs`);
        continue;
      }
      const bad: string[] = [];
      const failed: string[] = [];
      let objects = 0;
      for (const r of e.refs ?? []) {
        const got = await resolveRef(S, r, { verify: true, committedLogs: logs });
        if (!got.ok) bad.push(r);
        else {
          if (got.kind !== "unresolved") objects += 1;
          if (got.status && got.status !== "ok") failed.push(`${r} (job ${got.status})`);
        }
      }
      if (bad.length) {
        why.push(`#${seq}'s refs ${bad.join(", ")} do not resolve`);
        continue;
      }
      if (e.kind === "finding" && !objects) {
        why.push(`#${seq} rests on unresolved: refs only, which name no object of the run`);
        continue;
      }
      const onFailed = failed.length ? `; on the kept output of a job that did not succeed: ${failed.join(", ")}` : "";
      if (e.kind === "absence" && !asksExistence(existence, n)) {
        // A search documents what was searched; it answers only a question
        // that asks whether the thing exists at all.
        limited ??= `#${seq} (a search that found nothing${via}${onFailed}: it documents the search, and the question asks for more than whether something exists)`;
        continue;
      }
      answered = e.kind === "absence" ? `#${seq} (a search that found nothing${via}${onFailed})` : `#${seq} (a finding with refs${via}${onFailed})`;
      break;
    }
    if (answered) {
      outcomes[n] = "answered";
      lines.push(`section ${n}: rests on ${answered}`);
    } else if (limited) {
      outcomes[n] = "limited";
      lines.push(`section ${n}: examination-limited, rests on ${limited}`);
    } else {
      ok = false;
      outcomes[n] = "unanswered";
      lines.push(`section ${n}: rests on no standing finding with refs, no complete search that found nothing and no limitation${candidates.length ? ` (cites ${candidates.map((s) => `#${s}`).join(", ")}${why.length ? `: ${why.join("; ")}` : ""})` : " (cites no ledger entry)"}`);
    }
  }
  const count = (o: SectionOutcome) => Object.values(outcomes).filter((x) => x === o).length;
  lines.push(`sections: ${count("answered")} answered, ${count("limited")} examination-limited, ${count("unanswered")} unanswered`);
  return { ok, lines, outcomes };
}

// The questions a brief numbers (protocol.ts): the lead register reads them too.
export { briefQuestions };

export type LedgerOutcome = "answered" | "limited" | "inconclusive" | "unanswered";

/** Each job's status from its job.json, read once. */
/** Each job a ref of the ledger names, with its status as its record says (null when it has none). */
async function jobStatusMap(S: string, entries: LedgerEntry[]): Promise<Map<string, string | null>> {
  const status = new Map<string, string | null>();
  for (const e of entries) {
    for (const ref of e.refs ?? []) {
      const m = /^job:([a-z0-9-]{1,64})(?:\/|$)/.exec(ref);
      if (!m || status.has(m[1])) continue;
      const job = await readFile(join(S, "store", "jobs", m[1], "job.json"), "utf8").then((t) => JSON.parse(t) as { status?: string }).catch(() => null);
      status.set(m[1], job?.status ?? null);
    }
  }
  return status;
}

function jobStatuses(status: Map<string, string | null>, entries: LedgerEntry[]): Map<number, string[]> {
  const out = new Map<number, string[]>();
  for (const e of entries) {
    for (const ref of e.refs ?? []) {
      const m = /^job:([a-z0-9-]{1,64})(?:\/|$)/.exec(ref);
      if (!m) continue;
      const st = status.get(m[1]);
      if (st && st !== "ok" && !(e.qualifies ?? []).some((q) => q.ref === ref)) out.set(e.seq, [...(out.get(e.seq) ?? []), `${ref} (${st})`]);
    }
  }
  return out;
}

/** The entries the lead register recorded under each question's leads (leads.ts questionLeadEntries), or null when its chain is broken or it cannot be read. */
async function leadState(S: string): Promise<import("../extensions/leads.ts").LeadsState | null> {
  try {
    const L = await import("../extensions/leads.ts");
    const { events, text } = await L.readLeadEvents(S);
    const chain = L.verifyLeadChain(text);
    return chain.ok ? L.foldLeads(events, chain) : null;
  } catch {
    return null;
  }
}

/**
 * What the negative bar needs of each question section, read from the
 * registers: the goal's questions are material, a register question says;
 * a question asks whether something exists when the goal's --existence
 * names it or the register's expects says so.
 */
export async function sectionBars(S: string, existence: readonly string[] = []): Promise<(id: string) => { material: boolean; existence: boolean; completeness: boolean; must_establish: boolean }> {
  const Q = await import("../extensions/questions.ts").catch(() => null);
  const snap = Q ? await Q.questionsSnapshot(S).catch(() => null) : null;
  const goalIds = new Set((snap?.goal.questions ?? []).map((x) => sectionKey(x)));
  const goalExistence = snap?.goal.existence ?? [];
  return (id: string) => {
    const key = sectionKey(id);
    const q = snap?.bySection.get(key);
    return {
      material: goalIds.has(key) || !q ? true : q.materiality === "material",
      existence: asksExistence(existence, key) || asksExistence(goalExistence, key) || q?.expects === "existence",
      completeness: q?.completeness === true,
      // The goal, the operator or an examiner requires it to be established (docs/adr/0013): only an answer that answers it is its disposition.
      must_establish: Q ? Q.mustEstablish(q) : false,
    };
  };
}

/**
 * Ledger mode: each wanted section's answer, and the ledger gate over them.
 * `wanted` takes goal question ids ("3", "Q3", "question:3") and summary and
 * narrative.
 *
 * An answer that states its result (the negative bar, extensions/negative-
 * bar.ts) is held to it: established and premise_not_supported answer the
 * question when they rest on what stands; partial and out_of_scope limit
 * the run; not_determinable is inconclusive; bounded_negative answers a
 * question that asks whether something exists when its coverage record is
 * complete and another seat reviewed it, and limits the run otherwise. A
 * material negative with no coverage record, or nobody's review, and an
 * answer worded "it did not happen" without the bar for it, are defects no
 * limitation excuses. An answer recorded before results reads as it always
 * did (a limitation limits, a search answers only an existence question).
 */
/** An answer that rests on external material (docs/adr/0012, 0014): the entry, what it rests on, and the source classes. */
export type ExternalFlag = { seq: number; via: string[]; classes: string[] };

/**
 * A question's disposition under the bar (docs/adr/0013): what a run may end
 * on, under every stop policy. Established (a finding settles it); partial
 * (on a finding); a bounded negative or not determinable, each resting on a
 * standing coverage record another seat reviewed; a premise shown not to
 * hold (on a finding); out of scope. A best candidate (an answer that
 * claims established, every review of which holds it a best candidate only)
 * is none (B2), and so is anything a defect holds. A partial answer is a
 * disposition whatever its reviews' strength: its review attests the parts
 * it claims, and "best candidate" concerns only an established claim. A
 * question that must be established takes only an answer that answers it
 * (docs/adr/0013, "A question that must be established").
 */
export const DISPOSITIONS = ["established", "partial", "bounded_negative", "not_determinable", "premise_not_supported", "out_of_scope"] as const;
export type Disposition = (typeof DISPOSITIONS)[number];

export async function checkLedgerAnswers(sandbox: string, wanted: string[], existence: readonly string[] = []): Promise<{ ok: boolean; lines: string[]; outcomes: Record<string, LedgerOutcome>; results: Record<string, string>; defects: LedgerDefect[]; withdrawn: Record<string, string>; external: Record<string, ExternalFlag>; best_candidate: string[]; dispositions: Record<string, Disposition>; warnings: string[] }> {
  const S = resolve(sandbox);
  const outcomes: Record<string, LedgerOutcome> = {};
  const results: Record<string, string> = {};
  // Each section whose answer is a disposition under the bar, before the defects are counted (dropped below for any section a defect holds).
  const dispositions: Record<string, Disposition> = {};
  // The sections whose answer claims established and every review holds a best candidate only (B2): limited, never answered.
  const bestCandidate: string[] = [];
  // A goal question the question register holds as withdrawn is no longer
  // one the run must answer: the goal keeps it, the register says who took
  // it off and why, and this check names it instead of requiring it.
  const withdrawn: Record<string, string> = {};
  const text = await readFile(join(S, "ledger", "entries.jsonl"), "utf8").catch(() => "");
  const chain = verifyLedgerChain(text);
  if (!chain.ok) return { ok: false, lines: [`the ledger's chain is broken at line ${chain.broken_at} (${chain.reason}): no answer can rest on it`], outcomes, results, defects: [], withdrawn, external: {}, best_candidate: bestCandidate, dispositions, warnings: [] };
  // The acts are chains of their own: a broken one cannot say who checked what.
  for (const [rel, verify] of [[LEDGER_ATTESTATIONS, verifyAttestationChain], [LEDGER_DISPUTES, verifyDisputeChain], [LEDGER_SWEEPS, verifySweepChain]] as const) {
    const t = await readFile(join(S, rel), "utf8").catch(() => "");
    const v = verify(t);
    if (!v.ok) return { ok: false, lines: [`${rel}'s chain is broken at line ${v.broken_at} (${v.reason}): ${rel === LEDGER_SWEEPS ? "what the store sweeps found" : "the acts on the answers"} cannot be read`], outcomes, results, defects: [], withdrawn, external: {}, best_candidate: bestCandidate, dispositions, warnings: [] };
  }
  const entries = await readLedger(S);
  const attestations = await readAttestations(S);
  const disputes = await readDisputes(S);
  const sweeps = await readSweeps(S);
  // The additions' reverse sweeps (docs/adr/0013): said with a stale answer, warned of otherwise, never holding.
  const imports = await readImportSweeps(S);
  const sections: string[] = [];
  for (const w of wanted) {
    const sec = answerSection(w);
    if (!sec.ok) return { ok: false, lines: [`--sections: ${sec.reason}`], outcomes, results, defects: [], withdrawn, external: {}, best_candidate: bestCandidate, dispositions, warnings: [] };
    if (!sections.includes(sec.section)) sections.push(sec.section);
  }
  const lines: string[] = [];
  const Q = await import("../extensions/questions.ts").catch(() => null);
  const register = Q ? await Q.questionsSnapshot(S).catch(() => null) : null;
  for (const section of [...sections]) {
    if (!section.startsWith("question:")) continue;
    const q = register?.bySection.get(sectionAnswersId(section));
    if (!q?.withdrawn) continue;
    withdrawn[section] = `${q.id} was withdrawn by ${Q!.originWords(q.withdrawn.origin)} at ${q.withdrawn.at}: ${q.withdrawn.why}`;
    sections.splice(sections.indexOf(section), 1);
    lines.push(`${section}: not required: ${withdrawn[section]}`);
  }
  const bar = await sectionBars(S, existence);
  const statuses = await jobStatusMap(S, entries);
  // The kept output of a cancelled or stopped job, cited with no word on how
  // it is treated (docs/adr/0016), by whatever ref names those bytes.
  const { producerOf } = await producerIndex(S);
  // Under the case policy's more_evidence: no, the no_acquisition_ask warning names the policy, never an ask.
  const moreEvidence = await import("../extensions/requests.ts").then((R) => R.casePolicyMoreEvidence(S)).catch(() => "ask" as const);
  // What the lead register recorded under each question's leads: a finding two seats hold there that the answer leaves out is a warning. A register whose chain is broken says nothing here (the finish gate names it).
  const leads = await leadState(S);
  const underLeads = leads ? await import("../extensions/leads.ts").then((L) => L.questionLeadEntries(leads)) : null;
  // The sources' broad extractions, as the store journal's receipts say them (extensions/preparation.ts): a negative that claims absence over one still under way holds; any other on one not produced is warned.
  const preparation = await import("../extensions/preparation.ts").then((PR) => PR.preparationFacts(S, entries, leads?.leads.values())).catch(() => undefined);
  // What each question takes as happened (docs/adr/0011, "What a question presumes"): a partial answer to one whose premise nothing tests is a warning.
  const presumes = Q ? Q.presumptionsOf(register, leads) : new Map();
  const gate = ledgerGate({ entries, attestations, disputes, sections, failed: jobStatuses(statuses, entries), bar, partial: partialOutputCites(entries, producerOf), sweeps, ...(imports.length ? { imports } : {}), moreEvidence, ...(underLeads ? { underLeads } : {}), ...(preparation ? { preparation } : {}), ...(register?.state.premises.size ? { premises: register.state.premises } : {}), ...(presumes.size ? { presumes } : {}) });
  const bySeq = new Map(entries.map((e) => [e.seq, e]));
  const replaced = supersededBy(entries);
  const limits = entries.filter((e) => e.kind === "limitation" && !replaced.has(e.seq));
  const logs = await committedLogHashes(S);
  // What the operator's standing acceptance of a question excuses on it
  // (acceptanceExcuses), the one rule readiness (finish.ts) and the accept
  // act's still_held (questions.ts) read: every defect but the negative
  // bar's and material the case policy forbids (ACCEPTANCE_NEVER_EXCUSES),
  // a partial store sweep, and evidence added before the acceptance.
  const acceptedAt = new Map<string, number | null>();
  if (register && Q) {
    const L = await import("../extensions/leads.ts");
    const view = L.ledgerView(entries, disputes);
    for (const q of register.state.questions.values()) if (q.accepted && Q.acceptanceStands(q, view)) acceptedAt.set(`question:${q.section}`, q.accepted.ledger_seq ?? null);
  }
  const excused = (d: LedgerDefect): boolean => Boolean(d.section && acceptedAt.has(d.section) && acceptanceExcuses(d, acceptedAt.get(d.section)));
  const defects = gate.defects.filter((d) => !excused(d));
  for (const section of sections) {
    const a = gate.answers[section];
    const id = sectionAnswersId(section);
    if (!a) {
      const named = limits.filter((l) => (l.answers ?? []).some((x) => sectionKey(x) === id));
      outcomes[section] = named.length ? "limited" : "unanswered";
      lines.push(`${section}: no answer${named.length ? `; examination-limited by ${named.map((l) => `#${l.seq} (${l.reason ?? "no reason"})`).join(", ")}` : ""}`);
      continue;
    }
    const reviews = answerReviews(a, attestations);
    const acts = [
      ...reviews.map((x) => `attested by ${x.by}${x.strength === "best_candidate" ? " (best candidate)" : x.strength === "established" ? " (established)" : ""}`),
      ...disputes.filter((d) => d.act === "dispute" && d.target === a.hash).map((d) => `disputed by ${d.by}`),
    ];
    const actsText = acts.length ? `; ${[...new Set(acts)].join(", ")}` : "";
    if (!section.startsWith("question:")) {
      outcomes[section] = "answered";
      lines.push(`${section}: answered by #${a.seq}${actsText}`);
      continue;
    }
    // What the question's answer stands on: an entry naming it whose refs resolve now.
    // A coverage record revised for the same questions and coverage stands in for the one cited (carriedCoverage).
    const naming = [...new Set([...(a.support ?? []), ...(a.limitations ?? [])]
      .map((x) => bySeq.get(x.seq))
      .map((e) => (e && replaced.has(e.seq) ? (carriedCoverage(e, bySeq, replaced) ?? undefined) : e)))]
      .filter((e): e is LedgerEntry => Boolean(e) && !replaced.has((e as LedgerEntry).seq) && ((e as LedgerEntry).answers ?? []).some((x) => sectionKey(x) === id));
    const why: string[] = [];
    let rests: string | null = null;
    let restsOnFinding = false;
    let limited: string | null = null;
    let coverage: LedgerEntry | null = null;
    for (const e of naming) {
      if (e.kind === "limitation") {
        limited ??= `#${e.seq} (a limitation: ${e.reason ?? "no reason"})`;
        continue;
      }
      if (e.kind === "coverage") {
        // The coverage the hub found, while its results still stand; a complete one is preferred over a partial one.
        const stale = coverageProblems(e, entries, disputes);
        if (stale.length) {
          why.push(`coverage record #${e.seq} no longer says what its search found (${stale.join("; ")})`);
          continue;
        }
        if (!coverage || (coverage.coverage !== "complete" && e.coverage === "complete")) coverage = e;
        continue;
      }
      if (e.kind !== "finding" && e.kind !== "absence") continue;
      if (e.kind === "absence" && e.completion && e.completion !== "complete") {
        why.push(`#${e.seq} is a search that was ${e.completion}`);
        continue;
      }
      if (e.kind === "finding" && !e.refs?.length) {
        why.push(`#${e.seq} names no refs`);
        continue;
      }
      const bad: string[] = [];
      let objects = 0;
      for (const r of e.refs ?? []) {
        const got = await resolveRef(S, r, { verify: true, committedLogs: logs });
        if (!got.ok) bad.push(r);
        else if (got.kind !== "unresolved") objects += 1;
      }
      if (bad.length) {
        why.push(`#${e.seq}'s refs ${bad.join(", ")} do not resolve`);
        continue;
      }
      if (e.kind === "finding" && !objects) {
        why.push(`#${e.seq} rests on unresolved: refs only`);
        continue;
      }
      if (e.kind === "absence" && !asksExistence(existence, section) && !bar(id).existence) {
        limited ??= `#${e.seq} (a search that found nothing: it documents the search, and the question asks for more than whether something exists)`;
        continue;
      }
      if (rests && restsOnFinding) continue;
      rests = `#${e.seq} (${e.kind === "absence" ? "a search that found nothing" : "a finding with refs"})`;
      restsOnFinding = e.kind === "finding";
    }
    const result = answerResult(a);
    const covText = coverage ? `#${coverage.seq} (a coverage record, coverage ${coverage.coverage ?? "not computed"}${coverage.not_examined?.length ? `, ${coverage.not_examined.length} planned route(s) not examined` : ""})` : null;
    let outcome: LedgerOutcome = "unanswered";
    let said = "";
    if (result) {
      results[section] = result;
      // A premise rejected on a search alone is a negative, held as one.
      const premiseOnSearch = result === "premise_not_supported" && !restsOnFinding;
      const review = NEGATIVE_RESULTS.has(result) || premiseOnSearch ? negativeReview(a, entries, attestations, disputes) : null;
      const reviewText = review ? (review.reviewed ? `, reviewed by ${review.by.join(", ")}` : ", negative (unreviewed)") : "";
      if (premiseOnSearch && (rests || covText)) [outcome, said] = ["limited", `examination-limited (a premise rejected on a search alone: no finding shows it false), #${a.seq} resting on ${covText ?? rests}${reviewText}`];
      else if ((result === "established" || result === "premise_not_supported") && rests) [outcome, said] = ["answered", `answered by #${a.seq}, resting on ${rests}${result === "premise_not_supported" ? " (its premise is not supported)" : ""}`];
      else if (result === "bounded_negative" && (rests || covText)) {
        // It settles the question only under the stronger bar, saying so: an
        // existence question, a coverage record the hub found complete that
        // says the event would have left a trace, reviewed by another seat,
        // and the answer saying the event did not happen (asserts_absence).
        // Any other bounded negative is a disposition that limits the run.
        const settled = bar(id).existence && coverage?.coverage === "complete" && coverage.detection_opportunity?.trace_expected === "yes" && review?.reviewed === true && a.asserts_absence === true;
        [outcome, said] = settled
          ? ["answered", `answered (a bounded negative that says the event did not happen, under the stronger bar: an existence question, its coverage complete with the trace expected, reviewed) by #${a.seq}, resting on ${covText ?? rests}${reviewText}`]
          : [
              "limited",
              `examination-limited (a bounded negative: no evidence found in its scope${!bar(id).existence ? "; the question asks for more than whether something exists" : coverage?.coverage !== "complete" ? "; its coverage is partial" : coverage.detection_opportunity?.trace_expected !== "yes" ? "; its coverage does not say the event would have left a trace" : a.asserts_absence !== true ? "; the answer does not say the event did not happen" : ""}), #${a.seq} resting on ${covText ?? rests}${reviewText}`,
            ];
      } else if (result === "not_determinable" && (rests || limited || covText)) [outcome, said] = ["inconclusive", `inconclusive (not determinable), #${a.seq} resting on ${covText ?? limited ?? rests}${reviewText}`];
      else if ((result === "partial" || result === "out_of_scope") && (rests || limited || covText)) [outcome, said] = ["limited", `examination-limited (${resultWords(result)}), #${a.seq} resting on ${rests ?? limited ?? covText}`];
      else if ((result === "established" || result === "premise_not_supported") && limited) [outcome, said] = ["limited", `examination-limited, #${a.seq} (${resultWords(result)}) resting only on ${limited}`];
    } else if (rests && !a.inconclusive) [outcome, said] = ["answered", `answered by #${a.seq}, resting on ${rests}`];
    else if (rests || limited) [outcome, said] = [a.inconclusive ? "inconclusive" : "limited", `${a.inconclusive ? "inconclusive" : "examination-limited"}, #${a.seq} resting on ${rests ?? limited}`];
    // A review that holds the answer a best candidate only does not make it
    // answered (B2): with no review that holds it established, it has no
    // disposition, and the run waits for the route or for the operator's
    // acceptance. Only an answer that claims established is held so
    // (heldAsBestCandidate, the test readiness reads too): a partial answer,
    // a negative, out of scope and a premise shown not to hold are held to
    // their own bars, never to a strength.
    let best = false;
    if (outcome === "answered" && heldAsBestCandidate(a, reviews)) {
      best = true;
      bestCandidate.push(section);
      outcome = "limited";
      said = `examination-limited: a best candidate, not established (every review holds #${a.seq} a best candidate: ${[...new Set(reviews.map((x) => x.by))].join(", ")}${reviews.some((x) => x.capped?.length) ? `; ${[...new Set(reviews.flatMap((x) => x.capped ?? []))].join("; ")}` : ""}); ${said}`;
    }
    // Its disposition under the bar: what the answer is, on what it rests.
    // A negative rests on a standing coverage record another seat reviewed;
    // a best candidate is none (B2), a partial answer on a finding is one
    // whatever its reviews' strength; a section a defect holds loses it below.
    if (outcome !== "unanswered" && !best) {
      const negativeReviewed = Boolean(coverage) && Boolean(result && NEGATIVE_RESULTS.has(result) && negativeReview(a, entries, attestations, disputes).reviewed);
      const d: Disposition | null = !result
        ? outcome === "answered" && !a.inconclusive
          ? "established"
          : null
        : result === "established"
          ? outcome === "answered"
            ? "established"
            : null
          : result === "premise_not_supported"
            ? outcome === "answered" && restsOnFinding
              ? "premise_not_supported"
              : null
            : result === "partial"
              ? restsOnFinding
                ? "partial"
                : null
              : result === "out_of_scope"
                ? "out_of_scope"
                : NEGATIVE_RESULTS.has(result) && negativeReviewed
                  ? (result as Disposition)
                  : null;
      // A question that must be established (docs/adr/0013, "A question that
      // must be established") is disposed only by an answer that answers it:
      // established, a premise shown not to hold, or a bounded negative under
      // the stronger bar. Partial, not determinable, a bounded negative short
      // of that and out of scope limit the run as they always do, and are no
      // disposition for it: the finish line holds it until it is established,
      // or the operator accepts its limits or releases the requirement.
      if (d && bar(id).must_establish && outcome !== "answered") said += "; it must be established, and this is no disposition for it";
      else if (d) dispositions[section] = d;
    }
    if (outcome !== "unanswered") {
      outcomes[section] = outcome;
      lines.push(`${section}: ${said}${actsText}`);
    } else {
      outcomes[section] = "unanswered";
      defects.push({
        code: "answer_support",
        section,
        seqs: [a.seq],
        what: `answer #${a.seq} (${section}) rests on no standing finding whose refs resolve, no complete search, no coverage record and no limitation that names ${section}${why.length ? ` (${why.join("; ")})` : ""}`,
        fix: `record the finding again with refs that resolve (a correction, supersedes=<seq>) and the answer with supersedes=${a.seq} citing it, or record a limitation citing E-${a.seq}`,
        named_by: limits.filter((l) => (l.rel ?? []).some((r) => r.to === a.seq) || new RegExp(`\\bE-${a.seq}\\b`).test(`${l.value}\n${l.source ?? ""}\n${l.evidence ?? ""}`)).map((l) => l.seq),
      });
      lines.push(`${section}: #${a.seq} stands on nothing a reader can check now${actsText}`);
    }
  }
  // What rests on external material (a capture the fetch service sealed,
  // evidence added after the kickoff, material the operator supplied, and
  // whatever was derived from them: docs/adr/0012, 0014): named with its
  // source classes, never failed. A capture's hash proves its bytes, not
  // their truth or their fit to the time of the events; supplied material
  // proves nothing by itself; an examiner weighs each. The one exception is
  // a class the case policy says no record may rest on (material_use none):
  // an answer whose resolved lineage reaches one is a defect, whatever path
  // (a digest, a job's output, a coverage record) carried it there.
  const lineage = await externalLineage(S).catch(() => null);
  const forbidden = (await forbiddenMaterialClasses(S).catch(() => null))?.classes ?? new Set<string>();
  if (lineage && forbidden.size) {
    for (const section of sections) {
      const a = gate.answers[section];
      if (!a) continue;
      const hit = (lineage.classes.get(a.seq) ?? []).filter((c) => forbidden.has(c));
      if (!hit.length) continue;
      defects.push({
        code: "material_use",
        section,
        seqs: [a.seq],
        what: `answer #${a.seq} (${section}) rests on ${hit.join(", ")} material (through ${(lineage.entries.get(a.seq) ?? []).join(", ") || "its lineage"}), which the case policy lets no record rest on (material_use ${hit.map((c) => `${c}=none`).join(", ")})`,
        fix: `record the answer again (supersedes=${a.seq}) on findings that do not rest on that material, or record a limitation that says the question cannot be answered without it`,
        named_by: [],
      });
    }
  }
  // What an acceptance excuses among the defects this check finds itself (an answer that rests on nothing checkable now), as among the gate's.
  for (let i = defects.length - 1; i >= 0; i -= 1) if (excused(defects[i]!)) defects.splice(i, 1);
  // A section a defect holds, named by a limitation or not, has no disposition under the bar.
  for (const d of defects) if (d.section) delete dispositions[d.section];
  // A partial_output defect names the entry that cites a cancelled or stopped
  // job's output (its producer resolved by producerIndex), not a section: every
  // section that entry names, and every section whose standing answer rests on
  // it (support, contrary, limitations), is held by it and loses its disposition.
  const heldByPartial = new Set<string>();
  for (const d of defects) {
    if (d.code !== "partial_output") continue;
    for (const seq of d.seqs) {
      for (const x of bySeq.get(seq)?.answers ?? []) {
        const k = x === "summary" || x === "narrative" ? x : `question:${sectionKey(x)}`;
        heldByPartial.add(k);
      }
      for (const a of entries) {
        if (a.kind !== "answer" || replaced.has(a.seq) || !a.section) continue;
        if ([...(a.support ?? []), ...(a.contrary ?? []), ...(a.limitations ?? [])].some((x) => x.seq === seq)) heldByPartial.add(a.section);
      }
    }
  }
  for (const k of heldByPartial) delete dispositions[k];
  const open = defects.filter((d) => !d.named_by.length);
  for (const d of defects) lines.push(`${d.named_by.length ? `defect, named by ${d.named_by.map((n) => `#${n}`).join(", ")}` : "DEFECT"}: ${d.what}${d.named_by.length ? "" : `. Fix: ${d.fix}`}`);
  // What the gate warns of and does not hold on: said, counted in the machine line, never failed.
  const warnings = gate.warnings.map((w) => `${w.what}. ${w.fix}`);
  for (const w of warnings) lines.push(`WARN: ${w}`);
  const unsupported = Object.entries(gate.unsupported);
  if (unsupported.length) lines.push(`tokens in no cited entry (counted, not failed; the release weighs them): ${unsupported.map(([seq, t]) => `#${seq}: ${t.join(", ")}`).join("; ")}`);
  const externalFlags: Record<string, ExternalFlag> = {};
  if (lineage?.entries.size) {
    const external = entries.filter((e) => e.kind === "answer" && !replaced.has(e.seq) && e.section && sections.includes(e.section) && lineage.entries.has(e.seq));
    for (const e of external) externalFlags[e.section as string] = { seq: e.seq, via: lineage.entries.get(e.seq) ?? [], classes: lineage.classes.get(e.seq) ?? [] };
    if (external.length) lines.push(`rests on external material (named, not failed; a capture proves its bytes and supplied material proves nothing by itself: an examiner weighs each): ${external.map((e) => `${e.section} #${e.seq} (${(lineage.classes.get(e.seq) ?? []).join(", ") || "external"}) through ${(lineage.entries.get(e.seq) ?? []).join(", ")}`).join("; ")}`);
  }
  const count = (o: LedgerOutcome) => Object.values(outcomes).filter((x) => x === o).length;
  lines.push(`sections: ${count("answered")} answered, ${count("limited")} examination-limited, ${count("inconclusive")} inconclusive, ${count("unanswered")} unanswered; ${defects.length} defect${defects.length === 1 ? "" : "s"}, ${defects.length - open.length} named by a limitation, ${open.length} open`);
  if (open.length) lines.push("This check passes once each open defect is fixed, or named by a standing limitation (citing E-<seq> of the answer, or with answers=[<section>] for a missing one); a named defect is still a defect: the finish line holds done on it under every stop policy (a question ends on a disposition under the bar, never on a limitation that names it), and the release counts it. The negative bar's defects (coverage_missing, coverage_stale, negative_unreviewed, wording, evidence_stale, completeness_uncovered, and the store sweep's sweep_pending, sweep_hits and sweep_partial), an answer resting on material the case policy forbids (material_use), an entry citing a cancelled or stopped job's output with no word on it (partial_output), and two answers that assume and contradict one premise revision over scopes that overlap (premise_inconsistent: revise one, name the rebutting finding, narrow a scope, or answer conditionally) are fixed, never named. A negative held on a source's broad extraction (preparation_pending) is released when that extraction is produced, partial, failed or declined, or when the operator accepts the question's limits.");
  return { ok: open.length === 0, lines, outcomes, results, defects, withdrawn, external: externalFlags, best_candidate: bestCandidate, dispositions, warnings };
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  const args = process.argv.slice(2);
  const opt = (name: string) => {
    const i = args.indexOf(name);
    return i >= 0 ? args[i + 1] : undefined;
  };
  const report = opt("--report");
  const sandbox = opt("--sandbox") ?? process.cwd();
  const wanted = (opt("--sections") ?? "").split(",").map((s) => s.trim()).filter(Boolean);
  const existence = (opt("--existence") ?? "").split(",").map((s) => s.trim()).filter(Boolean);
  const briefPath = opt("--sections-in");
  if (briefPath) {
    const brief = await readFile(join(resolve(sandbox), briefPath), "utf8").catch(() => null);
    if (brief === null) {
      process.stdout.write(`no ${briefPath}: the questions are counted there\n`);
      process.exit(1);
    }
    const questions = briefQuestions(brief);
    if (!questions.length) {
      process.stdout.write(`${briefPath} numbers no question at the start of a line\n`);
      process.exit(1);
    }
    wanted.unshift(...questions);
  }
  if (!wanted.length) {
    process.stderr.write("usage: check-answers.ts [--report <path>] --sections 1,2,3[,summary,narrative] [--existence 2,…] [--sections-in inputs/CASE.md] [--sandbox DIR]\n");
    process.exit(2);
  }
  // A store sweep lost with the process that began it is run here before the gate is read.
  if (!report) await reconcileSweeps(resolve(sandbox)).catch(() => 0);
  const r = report ? await checkAnswers(sandbox, report, wanted, existence) : await checkLedgerAnswers(sandbox, wanted, existence);
  process.stdout.write(`${r.lines.join("\n")}\n`);
  // One machine line last, for the harness's finish line: each section's
  // outcome and each defect a limitation names, so a run whose checks pass
  // can still be told apart as examination-limited (await-done.sh hands it
  // back with the check's row, passing or not).
  const named = "defects" in r ? r.defects.filter((d) => d.named_by.length).map((d) => `${d.what} (named by ${d.named_by.map((n) => `#${n}`).join(", ")})`) : [];
  process.stdout.write(`${ANSWERS_MARK} ${JSON.stringify({ outcomes: r.outcomes, ...("results" in r ? { results: r.results } : {}), ...("withdrawn" in r && Object.keys(r.withdrawn).length ? { withdrawn: r.withdrawn } : {}), ...("external" in r && Object.keys(r.external).length ? { external: r.external } : {}), ...("best_candidate" in r && r.best_candidate.length ? { best_candidate: r.best_candidate } : {}), ...("dispositions" in r ? { dispositions: r.dispositions } : {}), ...("warnings" in r && r.warnings.length ? { warnings: r.warnings } : {}), named, existence, mode: report ? "report" : "ledger" })}\n`);
  process.exit(r.ok ? 0 : 1);
}
