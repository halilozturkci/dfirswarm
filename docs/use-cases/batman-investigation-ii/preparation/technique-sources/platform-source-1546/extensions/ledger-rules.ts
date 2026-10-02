/**
 * The rules over the ledger (split from extensions/protocol.ts, which re-exports it): what an entry
 * says and how it is recorded, the review evidence and the attestations, the rendered ledger,
 * disputes, answers, the question bar, downgrades and the gate at done. One cluster: its parts call
 * each other both ways, so it is not split further. It imports the core statically.
 */

import { execFile, execFileSync, spawn } from "node:child_process";
import { createHash, randomBytes, randomUUID } from "node:crypto";
import {
  closeSync,
  createReadStream,
  mkdirSync,
  openSync,
  readFileSync,
  readlinkSync,
  realpathSync,
  writeSync,
} from "node:fs";
import { connect, type Socket } from "node:net";
import {
  appendFile,
  chmod,
  copyFile,
  lstat,
  mkdir,
  open,
  readFile,
  readdir,
  readlink,
  realpath,
  rename,
  rm,
  stat,
  writeFile,
} from "node:fs/promises";
import { constants as fsConstants } from "node:fs";
import { basename, dirname, join, posix, relative, resolve, sep } from "node:path";
import { createInterface } from "node:readline";
import { fileURLToPath } from "node:url";
import * as NB from "./negative-bar.ts";
import * as PM from "./premises.ts";
import * as PR from "./preparation.ts";
import { importHitExamined, importHitsFor, importHitWords, unexaminedHits, type ImportSweepRecord, type SweepRecord, type UnexaminedHit } from "./store-sweep.ts";
import type { LedgerAlternative, LedgerEdge, LedgerEntry, LedgerKind, LedgerLocator, LedgerMethod, LedgerQualify, LedgerRel, SwarmContext } from "./protocol-core.ts";
import { ANSWER_ONLY_REL_KINDS, DELTA_REL_KINDS, LEDGER_ACT_MAX_CHARS, LEDGER_ALTERNATIVE_STATUS, LEDGER_ANSWER_ID, LEDGER_ANSWER_RESULTS, LEDGER_ATTESTATIONS, LEDGER_BASIS, LEDGER_BECAUSE_MAX_CHARS, LEDGER_CLOCK_MAX_CHARS, LEDGER_COMPLETION, LEDGER_CONFIDENCE, LEDGER_DIR, LEDGER_DISPUTES, LEDGER_ENTRIES, LEDGER_EVIDENCE_MAX_CHARS, LEDGER_HYPOTHESIS_STATUS, LEDGER_INDICATES_MAX_CHARS, LEDGER_KINDS, LEDGER_LIMITATION_REASONS, LEDGER_LOCATOR_MAX_CHARS, LEDGER_MAX_ALTERNATIVES, LEDGER_MAX_ANSWERS, LEDGER_MAX_CITATIONS, LEDGER_MAX_ENTRIES, LEDGER_MAX_LOCATORS, LEDGER_MAX_QUALIFIES, LEDGER_MAX_REFS, LEDGER_MAX_REL, LEDGER_MD, LEDGER_PRECISION, LEDGER_REASONING_MAX_CHARS, LEDGER_REF_MAX_CHARS, LEDGER_REL_KINDS, LEDGER_SECTION_SPECIAL, LEDGER_SOURCE_CLASSES, LEDGER_SOURCE_MAX_CHARS, LEDGER_SUBJECT_MAX_CHARS, LEDGER_SUBJECT_TYPES, LEDGER_VALUE_MAX_CHARS, LEDGER_VERSION, LEDGER_WHY_MAX_CHARS, REGISTER_LOCK, canonicalValue, ledgerContent, ledgerHash, sha256Hex, traceHarnessEntry, withNamedLock, withTableLock } from "./protocol-core.ts";

export type LedgerInput = {
  kind: string;
  ts?: string;
  value: string;
  source?: string;
  evidence?: string;
  confidence?: string;
  /** The seq of an entry this one corrects. */
  supersedes?: number | string;
  /** The run's objects it rests on (LedgerEntry.refs); a list, or one string of them separated by commas or spaces. */
  refs?: string[] | string;
  answers?: string[] | string;
  rel?: Array<{ to: number | string; kind: string }>;
  sensitive?: boolean;
  clock?: string;
  precision?: string;
  basis?: string;
  status?: string;
  reason?: string;
  completion?: string;
  attribution?: { subject?: string; subject_type?: string; basis_refs?: string[] | string };
  locators?: Array<{ ref?: string; at?: string }>;
  because?: string;
  /** An answer revised while the finish is assembled (extensions/finish.ts finishPhase): why it changes a conclusion. */
  material?: string;
  indicates?: string;
  confidence_why?: string;
  alternatives?: Array<{ explanation?: string; status?: string; why?: string; test_refs?: string[] | string }>;
  alternatives_none_why?: string;
  significance?: string;
  qualifies?: Array<{ ref?: string; why?: string }>;
  /** An answer's: question:<id> (or the id alone), summary or narrative. */
  section?: string;
  reasoning?: string;
  /** An answer's: the entries that say otherwise, by seq (12, "#12", "E-12"). */
  contrary?: Array<number | string> | string;
  /** An answer's: the limitation entries that bound it, by seq. */
  limitations?: Array<number | string> | string;
  alternatives_open?: string;
  would_change?: string;
  inconclusive?: boolean;
  /** An answer's result (LEDGER_ANSWER_RESULTS; premise_not_supported: the premise the question asks about does not hold). */
  result?: string;
  /** An answer to a person's question: why no entry says otherwise. */
  contrary_none_why?: string;
  /** An answer to a register question: the revision it answers (required once the question is amended past revision 1). */
  question_rev?: number | string;
  /** An answer: it says the event did not happen (only on an existence question whose coverage is complete and would have shown it). */
  asserts_absence?: boolean;
  /** A coverage record's own fields (kind coverage); its value is the proposition searched, its refs the objects. */
  proposition?: string;
  inventory_rev?: string;
  time_range?: string;
  search_method?: string;
  settings?: string;
  coverage_actual?: string;
  skipped?: string;
  failures?: string;
  result_refs?: string[] | string;
  detection_opportunity?: { trace_expected?: string; why?: string };
  /** A coverage record: {allocated, deleted, unallocated, slack, secondary}, each searched, skipped or not_applicable. */
  areas?: unknown;
  /** A coverage record behind a not-determinable answer: the acquisition ask opened for the missing source (R-<n>). */
  acquisition_ask?: string;
  /** A coverage record behind a not-determinable answer: why no acquisition ask was opened. */
  acquisition_none_why?: string;
  /** A coverage record: the literal strings a hit would contain (names, identifiers, addresses, keywords), at least one. */
  looked_for?: string[] | string;
  /** A coverage record, in place of looked_for: why no literal form exists. */
  looked_for_none_why?: string;
  /** An answer from a positive result to a negative one: {evidence: [E-<seq> or refs], why}. */
  downgrade?: unknown;
  /** An answer to a question: its claim and open-part rows, [{id, part, status: established | open, refs, open_by?}] (premises.ts). */
  parts?: unknown;
  /** An answer to a question: the premises it cites, [{id: P-<n>, rev, stance, refs?, conditional?, scope?}] (premises.ts). */
  premises?: unknown;
  /** An answer to a question that presumes an event: the test of that premise, {outcome, refs} (premises.ts PremiseTest; docs/adr/0011, "What a question presumes"). */
  premise_tested?: unknown;
};

function listOf(v: string[] | string | undefined): string[] {
  return [...new Set((Array.isArray(v) ? v.map(String) : String(v ?? "").split(/[\s,]+/)).map((x) => x.trim()).filter(Boolean))];
}

function oneOf<T extends readonly string[]>(name: string, v: unknown, allowed: T): { ok: true; value?: T[number] } | { ok: false; reason: string } {
  const text = String(v ?? "").trim().toLowerCase();
  if (!text) return { ok: true };
  if (!(allowed as readonly string[]).includes(text)) return { ok: false, reason: `${name} must be one of ${allowed.join(", ")}` };
  return { ok: true, value: text as T[number] };
}

/**
 * The version 3 fields an input carries, checked. `rel` is checked against
 * the ledger inside the lock (recordEntry); the rest needs nothing but the
 * input and, for attribution's refs, the run.
 */
async function ledgerV3Input(
  sandboxRoot: string,
  input: LedgerInput,
  kind: string,
  refs: string[],
  hasTs: boolean,
  tsRaw: string | undefined,
  superseding: boolean,
): Promise<{ ok: true; fields: Partial<LedgerEntry>; rel: Array<{ to: number; kind: (typeof LEDGER_REL_KINDS)[number] }> } | { ok: false; reason: string }> {
  const fields: Partial<LedgerEntry> = {};
  const answers = listOf(input.answers);
  if (answers.length > LEDGER_MAX_ANSWERS) return { ok: false, reason: `answers names ${answers.length} sections, more than ${LEDGER_MAX_ANSWERS}` };
  const badAnswer = answers.find((a) => !LEDGER_ANSWER_ID.test(a));
  if (badAnswer) return { ok: false, reason: `answers takes the goal's section ids, 1-16 letters, digits, dot, dash or underscore ("3", "Q3", "allegation-2"; got ${JSON.stringify(badAnswer)})` };
  if (answers.length) fields.answers = answers;
  const rel: Array<{ to: number; kind: (typeof LEDGER_REL_KINDS)[number] }> = [];
  for (const r of Array.isArray(input.rel) ? input.rel : []) {
    const to = Number(String(r?.to ?? "").trim().replace(/^#/, ""));
    if (!Number.isInteger(to) || to < 1) return { ok: false, reason: `rel.to names an entry by its seq, a whole number (got ${JSON.stringify(r?.to)})` };
    const k = oneOf("rel.kind", r?.kind, LEDGER_REL_KINDS);
    if (!k.ok) return k;
    if (!k.value) return { ok: false, reason: `rel.kind is required: ${LEDGER_REL_KINDS.join(", ")}` };
    if (!rel.some((x) => x.to === to && x.kind === k.value)) rel.push({ to, kind: k.value });
  }
  if (rel.length > LEDGER_MAX_REL) return { ok: false, reason: `rel links ${rel.length} entries, more than ${LEDGER_MAX_REL}` };
  if (input.sensitive !== undefined && input.sensitive !== null && typeof input.sensitive !== "boolean") return { ok: false, reason: "sensitive is true or false" };
  if (input.sensitive === true) fields.sensitive = true;
  const clock = String(input.clock ?? "").trim();
  if (clock) {
    if (!hasTs) return { ok: false, reason: "clock names the clock an entry's ts came from: give ts too" };
    if (clock.length > LEDGER_CLOCK_MAX_CHARS) return { ok: false, reason: `clock is over ${LEDGER_CLOCK_MAX_CHARS} characters: name the clock ("NTFS $SI created", "device local, offset unknown")` };
    fields.clock = clock;
  }
  const precision = oneOf("precision", input.precision, LEDGER_PRECISION);
  if (!precision.ok) return precision;
  if (precision.value && !hasTs) return { ok: false, reason: "precision says how precise an entry's ts is: give ts too" };
  // A date alone is a day, not midnight UTC: said, unless the agent said otherwise.
  const dateOnly = tsRaw !== undefined && /^\d{4}-\d{2}-\d{2}$/.test(tsRaw.trim());
  if (precision.value) fields.precision = precision.value;
  else if (dateOnly) fields.precision = "date";
  const basis = oneOf("basis", input.basis, LEDGER_BASIS);
  if (!basis.ok) return basis;
  if (basis.value) fields.basis = basis.value;
  const status = oneOf("status", input.status, LEDGER_HYPOTHESIS_STATUS);
  if (!status.ok) return status;
  if (status.value && kind !== "hypothesis") return { ok: false, reason: "status is a hypothesis's: open, supported or refuted" };
  if (kind === "hypothesis") fields.status = status.value ?? "open";
  const reason = oneOf("reason", input.reason, LEDGER_LIMITATION_REASONS);
  if (!reason.ok) return reason;
  if (reason.value && kind !== "limitation") return { ok: false, reason: "reason is a limitation's: why the examination could not establish it" };
  if (kind === "limitation") {
    if (!reason.value) return { ok: false, reason: `a limitation needs a reason: ${LEDGER_LIMITATION_REASONS.join(", ")}` };
    fields.reason = reason.value;
  }
  const completion = oneOf("completion", input.completion, LEDGER_COMPLETION);
  if (!completion.ok) return completion;
  if (completion.value && kind !== "absence") return { ok: false, reason: "completion is an absence's: how far the search got (complete, partial, failed)" };
  if (completion.value) fields.completion = completion.value;
  if (input.attribution !== undefined && input.attribution !== null) {
    const a = input.attribution;
    const subject = String(a.subject ?? "").trim();
    if (!subject) return { ok: false, reason: "attribution.subject is required: the account, device or person" };
    if (subject.length > LEDGER_SUBJECT_MAX_CHARS) return { ok: false, reason: `attribution.subject is over ${LEDGER_SUBJECT_MAX_CHARS} characters` };
    const type = oneOf("attribution.subject_type", a.subject_type ?? "unknown", LEDGER_SUBJECT_TYPES);
    if (!type.ok) return type;
    const basisRefs = listOf(a.basis_refs);
    if (basisRefs.length > LEDGER_MAX_REFS) return { ok: false, reason: `attribution.basis_refs names more than ${LEDGER_MAX_REFS} objects` };
    if (basisRefs.length) {
      const checked = await checkRefs(sandboxRoot, basisRefs);
      if (!checked.ok) return { ok: false, reason: `attribution.basis_refs: ${checked.reason}` };
    }
    fields.attribution = { subject, subject_type: type.value ?? "unknown", ...(basisRefs.length ? { basis_refs: basisRefs } : {}) };
  }
  const locators: LedgerLocator[] = [];
  for (const l of Array.isArray(input.locators) ? input.locators : []) {
    const ref = String(l?.ref ?? "").trim();
    const at = String(l?.at ?? "").trim();
    if (!ref || !at) return { ok: false, reason: "a locator is {ref, at}: one of the entry's refs, and where in it (a row, an offset, a record id)" };
    if (!refs.includes(ref)) return { ok: false, reason: `locator ref ${JSON.stringify(ref)} is not one of the entry's refs` };
    if (at.length > LEDGER_LOCATOR_MAX_CHARS) return { ok: false, reason: `a locator's at is over ${LEDGER_LOCATOR_MAX_CHARS} characters` };
    locators.push({ ref, at });
  }
  if (locators.length > LEDGER_MAX_LOCATORS) return { ok: false, reason: `locators names more than ${LEDGER_MAX_LOCATORS} places` };
  if (locators.length) fields.locators = locators;
  const because = String(input.because ?? "").trim();
  if (because) {
    if (!superseding) return { ok: false, reason: "because says why a correction corrects: give supersedes too" };
    if (because.length > LEDGER_BECAUSE_MAX_CHARS) return { ok: false, reason: `because is over ${LEDGER_BECAUSE_MAX_CHARS} characters` };
    fields.because = because;
  }
  return { ok: true, fields, rel };
}

/** The fields only an answer takes, and only a finding takes: named in a refusal when they come with another kind. */
const ANSWER_ONLY_FIELDS = ["section", "reasoning", "contrary", "limitations", "alternatives_open", "would_change", "inconclusive", "result", "contrary_none_why", "asserts_absence", "question_rev", "material", "downgrade", "parts", "premises", "premise_tested"] as const;
const FINDING_ONLY_FIELDS = ["indicates", "alternatives", "alternatives_none_why", "significance"] as const;
/** The fields only a coverage record takes. */
const COVERAGE_ONLY_FIELDS = ["proposition", "inventory_rev", "time_range", "search_method", "settings", "coverage_actual", "skipped", "failures", "result_refs", "result_bound", "detection_opportunity", "areas", "acquisition_ask", "acquisition_none_why", "looked_for", "looked_for_none_why"] as const;

function given(v: unknown): boolean {
  if (v === undefined || v === null) return false;
  if (typeof v === "string") return v.trim() !== "";
  if (Array.isArray(v)) return v.length > 0;
  return true;
}

function boundedText(name: string, v: unknown, max: number): { ok: true; value: string } | { ok: false; reason: string } {
  const text = String(v ?? "").trim();
  if (text.length > max) return { ok: false, reason: `${name} is over ${max} characters: say it in fewer, and put the material itself in a work/ file cited by a job` };
  return { ok: true, value: text };
}

/**
 * The version 4 fields a non-answer input carries, checked. A finding is an
 * observation and what the finder makes of it, written while the artefact is
 * open: `basis`, `confidence`, `indicates` and `confidence_why` are required
 * on it, and when it is inferred, what else could explain it (or why nothing
 * else was considered: an invented alternative is worse than none). A ref
 * whose job did not succeed needs `qualifies` on a finding (why those bytes
 * are still usable), and can never show that something is absent. Nothing
 * here weighs the confidence: it is the quality of the evidence, which the
 * finder states and a reader judges.
 */
async function ledgerV4Input(
  sandboxRoot: string,
  input: LedgerInput,
  kind: string,
  refs: string[],
  failed: Array<{ ref: string; status: string }>,
  basis: string | undefined,
  confidence: string,
): Promise<{ ok: true; fields: Partial<LedgerEntry> } | { ok: false; reason: string }> {
  const raw = input as Record<string, unknown>;
  const answerOnly = ANSWER_ONLY_FIELDS.find((f) => given(raw[f]));
  if (answerOnly) return { ok: false, reason: `${answerOnly} is an answer's: record kind=answer with its section to answer a question` };
  const coverageOnly = COVERAGE_ONLY_FIELDS.find((f) => given(raw[f]));
  if (coverageOnly) return { ok: false, reason: `${coverageOnly} is a coverage record's: record kind=coverage for what a negative was searched over` };
  if (kind !== "finding") {
    const findingOnly = FINDING_ONLY_FIELDS.find((f) => given(raw[f]));
    if (findingOnly) return { ok: false, reason: `${findingOnly} is a finding's: what an observation indicates and what else could explain it are recorded on kind=finding` };
  }
  const fields: Partial<LedgerEntry> = {};
  const why = boundedText("confidence_why", input.confidence_why, LEDGER_WHY_MAX_CHARS);
  if (!why.ok) return why;
  if (why.value && !confidence) return { ok: false, reason: "confidence_why says why that confidence: give confidence too" };
  if (why.value) fields.confidence_why = why.value;
  // What a failed job's kept bytes are still good for, ref by ref.
  const qualifies: LedgerQualify[] = [];
  for (const q of Array.isArray(input.qualifies) ? input.qualifies : []) {
    const ref = String(q?.ref ?? "").trim();
    const text = boundedText("a qualifies why", q?.why, LEDGER_WHY_MAX_CHARS);
    if (!text.ok) return text;
    if (!ref || !text.value) return { ok: false, reason: "qualifies is [{ref, why}]: one of the entry's refs whose job did not succeed, and why its kept bytes still support this entry" };
    if (!refs.includes(ref)) return { ok: false, reason: `qualifies names ${JSON.stringify(ref)}, which is not one of the entry's refs` };
    if (!failed.some((f) => f.ref === ref)) return { ok: false, reason: `qualifies names ${ref}, whose job succeeded: it qualifies only the output of a job that did not` };
    if (!qualifies.some((x) => x.ref === ref)) qualifies.push({ ref, why: text.value });
  }
  if (qualifies.length > LEDGER_MAX_QUALIFIES) return { ok: false, reason: `qualifies names more than ${LEDGER_MAX_QUALIFIES} refs` };
  if (qualifies.length && (kind === "limitation" || kind === "absence")) {
    return { ok: false, reason: `qualifies says why a failed job's bytes still support a claim; a ${kind} rests on what could not be done, and says so in its own fields` };
  }
  if (failed.length && kind === "absence" && (input.completion === undefined || String(input.completion).trim().toLowerCase() === "complete" || String(input.completion).trim() === "")) {
    return { ok: false, reason: `the output of a job that did not succeed cannot show that something is absent (${failed.map((f) => `${f.ref}: ${f.status}`).join(", ")}): record the search with completion partial or failed, and what was not reached as kind=limitation` };
  }
  if (kind === "finding") {
    const missing = failed.filter((f) => !qualifies.some((q) => q.ref === f.ref));
    if (missing.length) {
      return { ok: false, reason: `this finding rests on the kept output of a job that did not succeed (${missing.map((f) => `${f.ref}: ${f.status}`).join(", ")}): say in qualifies [{ref, why}] why those bytes are still usable, or cite the output of a job that worked` };
    }
  }
  if (qualifies.length) fields.qualifies = qualifies;
  if (kind !== "finding") return { ok: true, fields };
  if (!basis) return { ok: false, reason: "a finding says whether it was seen in the evidence or reasoned from it: basis observed or inferred" };
  if (!confidence) return { ok: false, reason: "a finding says how sure: confidence high, medium or low, with confidence_why" };
  const indicates = boundedText("indicates", input.indicates, LEDGER_INDICATES_MAX_CHARS);
  if (!indicates.ok) return indicates;
  if (!indicates.value) return { ok: false, reason: "indicates is required on a finding: what the observation means, and the step from one to the other, in one to three sentences" };
  fields.indicates = indicates.value;
  if (!fields.confidence_why) {
    return { ok: false, reason: "confidence_why is required on a finding: where the data came from, whether the method is reliable for it, how specific the observation is, and whether your sources depend on each other" };
  }
  const alternatives: LedgerAlternative[] = [];
  for (const a of Array.isArray(input.alternatives) ? input.alternatives : []) {
    const explanation = boundedText("an alternative's explanation", a?.explanation, LEDGER_WHY_MAX_CHARS);
    if (!explanation.ok) return explanation;
    const aWhy = boundedText("an alternative's why", a?.why, LEDGER_WHY_MAX_CHARS);
    if (!aWhy.ok) return aWhy;
    const status = oneOf("an alternative's status", a?.status, LEDGER_ALTERNATIVE_STATUS);
    if (!status.ok) return status;
    if (!explanation.value || !status.value || !aWhy.value) return { ok: false, reason: "an alternative is {explanation, status: rejected | open, why, test_refs?}: what else could explain it, whether it was rejected or is still open, and why" };
    const testRefs = listOf(a?.test_refs);
    if (testRefs.length > LEDGER_MAX_REFS) return { ok: false, reason: `an alternative's test_refs names more than ${LEDGER_MAX_REFS} objects` };
    if (testRefs.length) {
      const checked = await checkRefs(sandboxRoot, testRefs);
      if (!checked.ok) return { ok: false, reason: `an alternative's test_refs: ${checked.reason}` };
    }
    alternatives.push({ explanation: explanation.value, status: status.value, why: aWhy.value, ...(testRefs.length ? { test_refs: testRefs } : {}) });
  }
  if (alternatives.length > LEDGER_MAX_ALTERNATIVES) return { ok: false, reason: `alternatives lists more than ${LEDGER_MAX_ALTERNATIVES}: keep the ones a reader must weigh` };
  const noneWhy = boundedText("alternatives_none_why", input.alternatives_none_why, LEDGER_WHY_MAX_CHARS);
  if (!noneWhy.ok) return noneWhy;
  if (noneWhy.value && alternatives.length) return { ok: false, reason: "alternatives_none_why says no alternative was considered: give it or the alternatives, not both" };
  if (basis === "inferred" && !alternatives.length && !noneWhy.value) {
    return { ok: false, reason: "an inferred finding lists what else could explain it in alternatives [{explanation, status: rejected | open, why}], or says in alternatives_none_why why none was considered; never invent one" };
  }
  if (alternatives.length) fields.alternatives = alternatives;
  if (noneWhy.value) fields.alternatives_none_why = noneWhy.value;
  const significance = boundedText("significance", input.significance, LEDGER_WHY_MAX_CHARS);
  if (!significance.ok) return significance;
  if (significance.value) fields.significance = significance.value;
  return { ok: true, fields };
}

/**
 * How each object an entry cites was made, as the run recorded it: one
 * canonical record per job (its kind, the command or the tool with its sha256
 * and arguments, the recipe, the image and its digest, the scope it declared,
 * its network, how it ended), or per import. It describes recorded
 * execution, not the reads a tool made, and what the run did not record
 * stays "unknown". No times: the same job gives the same record. A ref kind
 * whose making is recorded elsewhere joins METHOD_DERIVERS; `tool:` and
 * `trace:` refs join once their grammar is fixed with the job service.
 */
export async function ledgerMethods(sandboxRoot: string, refs: string[]): Promise<LedgerMethod[]> {
  const out = new Map<string, LedgerMethod>();
  for (const ref of refs) {
    const m = /^([a-z0-9]+):(.*)$/s.exec(ref);
    const derive = m ? METHOD_DERIVERS[m[1]] : undefined;
    if (!derive || !m) continue;
    const got = await derive(sandboxRoot, m[2]).catch(() => null);
    if (got && !out.has(got.key)) out.set(got.key, canonicalValue(got.method) as LedgerMethod);
  }
  return [...out.entries()].sort((a, b) => a[0].localeCompare(b[0])).map(([, v]) => v);
}

type JobJson = {
  id?: string;
  spec?: { kind?: string; tool?: string; args?: unknown; command?: string; recipe?: string; target?: { ref?: string; name?: string }; targets?: Array<{ ref?: string; name?: string }>; inputs?: string[]; source?: string; network?: string; profile?: string };
  requester?: { agent?: string };
  status?: string;
  exit?: number | null;
  image?: string;
  image_digest?: string;
  tool_sha256?: string;
};

/** A job's method record, from its job.json beside its sealed output. */
async function jobMethod(sandboxRoot: string, id: string): Promise<{ key: string; method: LedgerMethod } | null> {
  if (!/^[a-z0-9-]{1,64}$/.test(id)) return null;
  const job = await readFile(join(sandboxRoot, "store", "jobs", id, "job.json"), "utf8")
    .then((t) => JSON.parse(t) as JobJson)
    .catch(() => null);
  if (!job) return { key: `job:${id}`, method: { kind: "job", job: id, record: "no job.json: how it was made is unknown" } };
  const s = job.spec ?? {};
  const method: LedgerMethod = {
    kind: s.kind === "import" ? "import" : "job",
    job: id,
    job_kind: s.kind ?? "unknown",
    status: job.status ?? "unknown",
    ...(job.exit !== undefined ? { exit: job.exit } : {}),
    image: job.image ?? "unknown",
    image_digest: job.image_digest ?? "unknown",
    declared_scope: Array.isArray(s.inputs) ? s.inputs : "unknown",
    network: s.network ?? "unknown",
    ...(s.profile ? { profile: s.profile } : {}),
  };
  if (s.kind === "tool") Object.assign(method, { tool: s.tool ?? "unknown", tool_sha256: job.tool_sha256 ?? "unknown", tool_version: "unknown", args: s.args ?? {} });
  else if (s.kind === "command") Object.assign(method, { command: s.command ?? "" });
  else if (s.kind === "recipe") Object.assign(method, { recipe: s.recipe ?? "unknown", recipe_sha256: job.tool_sha256 ?? "unknown", target: s.target?.ref ?? s.target?.name ?? "unknown" });
  else if (s.kind === "detect") Object.assign(method, { targets: (s.targets ?? []).map((t) => t.ref ?? t.name ?? "unknown") });
  else if (s.kind === "import") {
    // The job copied the file; who made it, and how, the run did not record.
    Object.assign(method, { source: s.source ?? "unknown", produced_by: `${job.requester?.agent ?? "unknown"}, in its own VM; how the file was made is not recorded`, copied_live: true });
  }
  return { key: `job:${id}`, method };
}

const METHOD_DERIVERS: Record<string, (sandboxRoot: string, value: string) => Promise<{ key: string; method: LedgerMethod } | null>> = {
  job: (S, value) => jobMethod(S, value.split("/")[0]),
  // A brain's own file brought into store/imports: its making is not recorded.
  import: async (_S, value) => {
    const id = value.split("/")[0];
    return /^[a-z0-9-]{1,64}$/.test(id) ? { key: `import:${id}`, method: { kind: "import", import: id, produced_by: "unknown: a file brought into the store; how it was made is not recorded" } } : null;
  },
  // An archive member of the catalogue: the recipe job that listed it.
  member: async (S, value) => {
    const gen = /^([a-z0-9-]+)#\d+$/.exec(value)?.[1];
    if (!gen) return null;
    const g = await readFile(join(S, "catalog", "gen", gen, "generation.json"), "utf8")
      .then((t) => JSON.parse(t) as { job?: string })
      .catch(() => null);
    return g?.job ? jobMethod(S, g.job) : null;
  },
};

/**
 * The seq each corrected entry is superseded by. A correction of a correction
 * names the one it replaces, so following the map from any entry reaches the
 * one that stands.
 */
export function supersededBy(entries: LedgerEntry[]): Map<number, number> {
  const out = new Map<number, number>();
  for (const e of entries) if (typeof e.supersedes === "number") out.set(e.supersedes, e.seq);
  return out;
}

export type LedgerResult =
  | ({ ok: true; entry: LedgerEntry; merged: boolean; total: number; note?: string } & WarningsDelivered)
  | { ok: false; reason: string; quiet?: true; deferred?: { coordinator: string; generation: number } };

/**
 * The answers check's warnings a reply delivers where the decision is made
 * (finish.ts warningsAt): `warnings` in the words finish status says them
 * with, `warned` their codes (for the trace). Absent when there are none;
 * never a refusal.
 */
export type WarningsDelivered = { warnings?: string[]; warned?: string[] };

/** The names closest to `want`: the same base name first, then by edit distance. */
function nearestNames(want: string, names: string[], n = 5): string[] {
  const base = (x: string) => x.slice(x.lastIndexOf("/") + 1).toLowerCase();
  const dist = (a: string, b: string) => {
    a = a.slice(-200);
    b = b.slice(-200);
    let row = Array.from({ length: b.length + 1 }, (_, i) => i);
    for (let i = 1; i <= a.length; i += 1) {
      const next = [i];
      for (let j = 1; j <= b.length; j += 1) next.push(Math.min(row[j] + 1, next[j - 1] + 1, row[j - 1] + (a[i - 1] === b[j - 1] ? 0 : 1)));
      row = next;
    }
    return row[b.length];
  };
  return names
    .map((x) => ({ x, d: (base(x) === base(want) ? 0 : 1000) + dist(x.toLowerCase(), want.toLowerCase()) }))
    .sort((a, b) => a.d - b.d)
    .slice(0, n)
    .map((r) => r.x);
}

/**
 * Every ref resolved against the run as it is now, or the first that is not,
 * with the names nearest to it: a typo costs one turn, where a wrong ref on
 * the chain would stand for good.
 */
export async function checkRefs(sandboxRoot: string, refs: string[]): Promise<{ ok: true; resolved: Array<{ ref: string; kind: string; status?: string }> } | { ok: false; reason: string }> {
  // Loaded when a ref is checked, not with the extension: a VM that mounts
  // only extensions/ still loads it, and in a VM the hub checks refs anyway.
  const { readManifest, resolveRef, storePaths } = await import("../scripts/evidence-store.ts");
  const resolved: Array<{ ref: string; kind: string; status?: string }> = [];
  for (const ref of refs) {
    const r = await resolveRef(sandboxRoot, ref);
    if (r.ok) {
      resolved.push({ ref, kind: r.kind, ...(r.status ? { status: r.status } : {}) });
      continue;
    }
    let near: string[] = [];
    const m = /^(job|import|input):(.*)$/s.exec(ref);
    try {
      if (m && m[1] === "input") {
        const inputs = JSON.parse(await readFile(join(sandboxRoot, "inputs.json"), "utf8")) as { files?: Array<{ path: string }> };
        near = nearestNames(m[2].startsWith("inputs/") ? m[2] : `inputs/${m[2]}`, (inputs.files ?? []).map((f) => f.path)).map((p) => `input:${p.replace(/^inputs\//, "")}`);
      } else if (m) {
        const slash = m[2].indexOf("/");
        const id = slash < 0 ? m[2] : m[2].slice(0, slash);
        const P = storePaths(sandboxRoot);
        const found = await readManifest(join(m[1] === "job" ? P.jobs : P.imports, id, "manifest.json"));
        if (found && slash >= 0) near = nearestNames(m[2].slice(slash + 1), found.manifest.files.map((f) => f.path)).map((p) => `${m[1]}:${id}/${p}`);
        else if (!found) near = nearestNames(id, await readdir(m[1] === "job" ? P.jobs : P.imports).catch(() => [])).map((x) => `${m[1]}:${x}`);
      }
    } catch {
      near = [];
    }
    return { ok: false, reason: `ref ${JSON.stringify(ref)} does not resolve: ${r.reason}${near.length ? `; nearest: ${near.join(", ")}` : ""}. A ref names an object of this run (input:<path>, job:<id>/<path>, import:<id>/<path>, member:<gen>#<n>, sha256:<hex>, or a brain's own output: tool:<seat>/<file> under tool-output/, trace:<sha256> of one trace line, which the hub seals first and cites as the import it became), or says why none can be named (unresolved:<why>).` };
  }
  return { ok: true, resolved };
}

const TS_DATE = /^(\d{4})-(\d{2})-(\d{2})$/;
const TS_DATE_TIME = /^(\d{4}-\d{2}-\d{2})[Tt ](\d{2}:\d{2}(?::\d{2}(?:\.\d{1,9})?)?)(Z|z|[+-]\d{2}:?\d{2})?$/;

/**
 * An event's time, in UTC, from what the agent wrote. A date and a time
 * must say their zone: `Z`, or the offset the source records. ECMAScript
 * reads a date-time without one as the host's local time, so the same
 * entry was 12:44Z on the droplet, 09:44Z on a Mac in Istanbul and 17:44Z
 * in New York, and the text it came from was gone. A date alone is a date.
 * Nothing else (01/02/2024 is two different days) is taken. What the agent
 * wrote is kept beside the UTC value when the two differ.
 */
export function normalizeTs(raw: string | undefined): { ok: true; ts?: string; raw?: string } | { ok: false; reason: string } {
  const text = (raw ?? "").trim();
  if (!text) return { ok: true };
  let iso: string;
  if (TS_DATE.test(text)) {
    iso = `${text}T00:00:00Z`;
  } else {
    const m = TS_DATE_TIME.exec(text);
    if (!m) {
      return { ok: false, reason: `ts must be ISO 8601 with its zone, e.g. 2024-01-15T12:44:22Z or 2024-01-15T15:44:22+03:00 (got ${JSON.stringify(text)})` };
    }
    if (!m[3]) {
      return {
        ok: false,
        reason: `ts ${JSON.stringify(text)} has no zone: add Z if the source's time is UTC, or the offset the source records (+03:00). The time zone is part of the evidence; the harness does not guess it.`,
      };
    }
    const zone = /^[Zz]$/.test(m[3]) ? "Z" : m[3].length === 5 ? `${m[3].slice(0, 3)}:${m[3].slice(3)}` : m[3];
    iso = `${m[1]}T${m[2]}${zone}`;
  }
  const ms = Date.parse(iso);
  if (!Number.isFinite(ms)) return { ok: false, reason: `ts is not a real time (got ${JSON.stringify(text)})` };
  const ts = new Date(ms).toISOString();
  return { ok: true, ts, ...(ts !== text ? { raw: text } : {}) };
}

/**
 * The ledger's entries, each with its attestations' authors folded into
 * `authors` (in memory: entries.jsonl is never rewritten). `raw` gives the
 * lines as written.
 */
export async function readLedger(sandboxRoot: string, opts: { raw?: boolean } = {}): Promise<LedgerEntry[]> {
  const text = await readFile(join(sandboxRoot, LEDGER_ENTRIES), "utf8").catch(() => "");
  const out: LedgerEntry[] = [];
  for (const line of text.split("\n")) {
    if (!line.trim()) continue;
    try {
      out.push(JSON.parse(line) as LedgerEntry);
    } catch {
      // a torn line is skipped, not fatal
    }
  }
  return opts.raw ? out : withAttestations(sandboxRoot, out);
}

/** Append one entry, merging with an equal one, and re-render ledger.md. */
/**
 * A reply with the warnings its point delivers (finish.ts warningsAt), read
 * after the act, outside every lock. What cannot be read adds nothing: a
 * warning never makes an act fail, and never holds.
 */
async function withWarnings<R extends { ok: boolean }>(sandboxRoot: string, r: R, point: (ok: Extract<R, { ok: true }>) => import("./finish.ts").WarningPoint | null): Promise<R> {
  if (!r.ok) return r;
  const at = point(r as Extract<R, { ok: true }>);
  if (!at) return r;
  try {
    const F = await import("./finish.ts");
    const ws = await F.warningsAt(sandboxRoot, at);
    return ws.length ? { ...r, warnings: ws.map(warningWords), warned: [...new Set(ws.map((w) => w.code))] } : r;
  } catch {
    return r;
  }
}

export async function recordEntry(ctx: SwarmContext, input: LedgerInput): Promise<LedgerResult> {
  // Q-<n> names a question of the register: its section, which is n unless
  // the goal gave it its own id.
  if (typeof input.section === "string" && /^(question:)?Q-\d/i.test(input.section.trim())) input = { ...input, section: await registerSection(ctx.sandboxRoot, input.section) };
  if (input.answers !== undefined && (Array.isArray(input.answers) ? input.answers : String(input.answers).split(/[\s,]+/)).some((a) => /^Q-\d/i.test(String(a).trim()))) {
    const list = Array.isArray(input.answers) ? input.answers.map(String) : String(input.answers).split(/[\s,]+/);
    input = { ...input, answers: await Promise.all(list.map((a) => registerSection(ctx.sandboxRoot, a.trim()))) };
  }
  const kind = String(input.kind ?? "").trim().toLowerCase();
  if (!(LEDGER_KINDS as readonly string[]).includes(kind)) {
    return { ok: false, reason: `kind must be one of ${LEDGER_KINDS.join(", ")}` };
  }
  if (kind === "external") return { ok: false, reason: "external material is recorded by the harness when it enters the run (a capture the fetch service sealed, material the operator supplied), with its provenance: cite it (net:<k>/<n>, E-<seq>) and record what it establishes as a finding of yours" };
  if (kind === "answer") return withWarnings(ctx.sandboxRoot, await recordAnswer(ctx, input), (r) => (r.entry.section?.startsWith("question:") ? { point: "record", section: r.entry.section } : null));
  if (kind === "coverage") return recordCoverage(ctx, input);
  const absence = kind === "absence";
  const limitation = kind === "limitation";
  const value = String(input.value ?? "").trim();
  if (!value) {
    return {
      ok: false,
      reason: absence
        ? "value is required: what was looked for and not found, in one sentence"
        : limitation
          ? "value is required: what the examination could not establish, in one sentence"
          : kind === "hypothesis"
            ? "value is required: the proposition under test, in one sentence"
            : "value is required: the event, the indicator or the finding, in one sentence",
    };
  }
  if (value.length > LEDGER_VALUE_MAX_CHARS) return { ok: false, reason: `value is over ${LEDGER_VALUE_MAX_CHARS} characters` };
  const ts = normalizeTs(input.ts);
  if (!ts.ok) return ts;
  if (kind === "event" && !ts.ts) return { ok: false, reason: "an event needs a ts (ISO 8601 with its zone: Z for UTC, or the source's offset)" };
  const confidence = String(input.confidence ?? "").trim().toLowerCase();
  if (confidence && !(LEDGER_CONFIDENCE as readonly string[]).includes(confidence)) {
    return { ok: false, reason: `confidence must be one of ${LEDGER_CONFIDENCE.join(", ")}` };
  }
  // Provenance is not optional. Across fifteen cases every one of 1501
  // ledger entries already carried both, so this costs a working run
  // nothing; what it stops is the entry that reads like a conclusion and
  // cannot be checked, which is the one a reader has no way to spot.
  const source = String(input.source ?? "").trim();
  if (!source) {
    return {
      ok: false,
      reason: absence
        ? "source is required: what was searched — the path, image, log or artefact the search ran over. 'Not found' is only ever 'not found there'."
        : limitation
          ? "source is required: what could not be examined — the object, volume, artefact or scope"
          : "source is required: where it was seen — a path, a log, a plugin, a registry key",
    };
  }
  if (source.length > LEDGER_SOURCE_MAX_CHARS) {
    return { ok: false, reason: `source is over ${LEDGER_SOURCE_MAX_CHARS} characters: name where it was seen, and put the material itself in a work/ file` };
  }
  const evidence = String(input.evidence ?? "").trim();
  if (!evidence) {
    return {
      ok: false,
      reason: absence
        ? "evidence is required: the query, the tool and its version, and the scope searched — allocated files only, or unallocated space and slack too, and the time range. An empty result holds only for that query and that scope."
        : limitation
          ? "evidence is required: what was tried and why it could not be done — the command, the error, the missing key or tool"
          : "evidence is required: how to check it — the command, the inode, the record id, the hash",
    };
  }
  if (evidence.length > LEDGER_EVIDENCE_MAX_CHARS) {
    return { ok: false, reason: `evidence is over ${LEDGER_EVIDENCE_MAX_CHARS} characters: say how to check it, and put the material itself in a work/ file` };
  }
  const refs = [...new Set((Array.isArray(input.refs) ? input.refs.map(String) : String(input.refs ?? "").split(/[\s,]+/)).map((r) => r.trim()).filter(Boolean))];
  if (refs.length > LEDGER_MAX_REFS) return { ok: false, reason: `refs names ${refs.length} objects, more than ${LEDGER_MAX_REFS}: name the ones the entry rests on, and the rest in evidence` };
  const long = refs.find((r) => r.length > LEDGER_REF_MAX_CHARS);
  if (long) return { ok: false, reason: `a ref is over ${LEDGER_REF_MAX_CHARS} characters: ${JSON.stringify(long.slice(0, 80))}…` };
  // The refs whose job did not succeed, as resolveRef reads the job's own status.
  const failed: Array<{ ref: string; status: string }> = [];
  if (refs.length) {
    const checked = await checkRefs(ctx.sandboxRoot, refs);
    if (!checked.ok) return checked;
    for (const r of checked.resolved) if (r.kind === "job" && r.status && r.status !== "ok") failed.push({ ref: r.ref, status: r.status });
  }
  // A finding with no ref is taken, and told what would let a reader check
  // it: the ask rides in the answer, never as an error.
  // A file in an agent's own work/ is what the #10 reports cited in prose:
  // said by name, with the way to make it an object of the run.
  const workFile = /(?:^|[\s`'"(])(?:\.\/)?(work\/[^\s`'",;)]+)/.exec(`${source} ${evidence}`)?.[1];
  const note =
    kind === "finding" && !refs.length
      ? workFile
        ? `no object of the run cited: ${workFile} is a file in an agent's own work/, which a reader cannot check against the run's record; seal it with job_run import=${workFile} (or run the work that made it as a job) and cite it as job:<id>/<path> in refs, then record this again with its refs`
        : "no object of the run cited: add refs (job:<id>/<path>, input:<path>, member:<gen>#<n>, sha256:<hex>, or unresolved:<why>) so a reader can check it; to add them to this entry, record it again with its refs"
      : undefined;
  let supersedes: number | undefined;
  if (input.supersedes !== undefined && input.supersedes !== null && String(input.supersedes).trim() !== "") {
    const n = Number(String(input.supersedes).trim().replace(/^#/, ""));
    if (!Number.isInteger(n) || n < 1) return { ok: false, reason: `supersedes names an entry by its seq, a whole number (got ${JSON.stringify(input.supersedes)})` };
    supersedes = n;
  }
  const v3 = await ledgerV3Input(ctx.sandboxRoot, input, kind, refs, Boolean(ts.ts), typeof input.ts === "string" ? input.ts : undefined, supersedes !== undefined);
  if (!v3.ok) return v3;
  const v4 = await ledgerV4Input(ctx.sandboxRoot, input, kind, refs, failed, v3.fields.basis, confidence);
  if (!v4.ok) return v4;
  // How each cited object was made, as the run recorded it: written by the
  // hub into the entry and its core, so the line alone says it.
  const method = refs.length ? await ledgerMethods(ctx.sandboxRoot, refs) : [];
  // An object a failed or cancelled job left is kept and citable (ADR 0010),
  // and said: an answer resting on it should not read as resting on a job that
  // worked. A finding says why in qualifies (ledgerV4Input); another kind is told.
  const notes: string[] = [];
  if (note) notes.push(note);
  const unqualified = failed.filter((f) => !(v4.fields.qualifies ?? []).some((q) => q.ref === f.ref));
  if (unqualified.length) {
    notes.push(`rests on the kept output of a job that did not succeed: ${unqualified.map((f) => `${f.ref} (job ${f.ref.slice(4).split("/")[0]}: ${f.status})`).join(", ")}; say why those bytes are still usable in qualifies [{ref, why}], or cite the output of a job that worked`);
  }
  if (v3.fields.completion && v3.fields.completion !== "complete") {
    notes.push(`the search was ${v3.fields.completion}: this absence holds only for what was searched; record what was not reached as kind=limitation (reason ${v3.fields.completion === "failed" ? "failed" : "partial"})`);
  }
  return withTableLock(ctx.sandboxRoot, async (held) => {
    const entries = await readLedger(ctx.sandboxRoot);
    const replaced = supersededBy(entries);
    const bySeq = new Map(entries.map((e) => [e.seq, e]));
    for (const r of v3.rel) {
      const target = bySeq.get(r.to);
      if (!target) return { ok: false, reason: `rel names #${r.to}: there is no entry #${r.to} in the ledger (list them with ledger)` };
      const standing = replaced.get(r.to);
      if (r.kind === "duplicates" && standing !== undefined) return { ok: false, reason: `#${r.to} is superseded by #${standing}: a duplicate names the entry that stands, #${standing}` };
      if (ANSWER_ONLY_REL_KINDS.has(r.kind) && !(target.kind === "answer" && target.section?.startsWith("question:"))) return { ok: false, reason: `rel ${r.kind} weighs evidence added late against a question's conclusion: its to names that question's answer (E-<seq> of an answer, section question:<n>); #${r.to} is ${target.kind === "answer" ? `the ${target.section}` : `a ${target.kind}`}. Link another entry with supports, contradicts, duplicates or derived_from` };
    }
    const candidate: LedgerEntry = {
      v: LEDGER_VERSION,
      seq: (entries.at(-1)?.seq ?? 0) + 1,
      kind: kind as LedgerKind,
      ...(ts.ts ? { ts: ts.ts } : {}),
      ...(ts.raw ? { ts_raw: ts.raw } : {}),
      value,
      source,
      evidence,
      ...(confidence ? { confidence: confidence as LedgerEntry["confidence"] } : {}),
      ...(refs.length ? { refs } : {}),
      ...v3.fields,
      ...(v3.rel.length ? { rel: v3.rel } : {}),
      ...v4.fields,
      ...(method.length ? { method } : {}),
      by: ctx.agentId,
      authors: [ctx.agentId],
      at: new Date().toISOString(),
    };
    const content = ledgerContent(candidate);
    if (supersedes !== undefined) {
      const target = bySeq.get(supersedes);
      if (!target) return { ok: false, reason: `supersedes #${supersedes}: there is no entry #${supersedes} in the ledger (list them with ledger)` };
      const already = replaced.get(supersedes);
      if (already !== undefined) return { ok: false, reason: `#${supersedes} is already superseded by #${already}: correct #${already} instead, so the corrections stay one line` };
      if (target.kind === "answer") return { ok: false, reason: `#${supersedes} is an answer: an answer is corrected by an answer to the same section (kind=answer, supersedes=${supersedes})` };
      // The whole of what it says, not the sentence alone: the same sentence
      // with another confidence, other refs or another status is a correction.
      if (ledgerContent(target) === content) {
        return { ok: false, reason: `the correction repeats #${supersedes} word for word, with the same confidence, refs and fields: a correction says what is right now` };
      }
    }
    // A correction is always its own entry. The same content again, from
    // anyone, is the entry that stands: a second author is an attestation,
    // appended, and the entry is never rewritten.
    const sameContent = supersedes === undefined ? entries.filter((e) => !replaced.has(e.seq) && ledgerContent(e) === content) : [];
    if (sameContent.length) return mergeSameContent(ctx, held, sameContent[0]);
    // The same sentence, from anyone: with refs where the standing one has
    // none, it is recorded anew and corrects it; otherwise it is its own
    // entry and is told of the other.
    const sameWords = supersedes === undefined ? entries.filter((e) => !replaced.has(e.seq) && e.kind === kind && e.value === value && (e.ts ?? "") === (ts.ts ?? "")) : [];
    const words = sameWords[0];
    if (words && refs.length && !words.refs?.length) {
      supersedes = words.seq;
    } else if (words) {
      notes.push(`#${words.seq} says the same sentence with other provenance or fields; if this one corrects it, record it with supersedes=${words.seq}; if it restates it, link it with rel {to: ${words.seq}, kind: "duplicates"}`);
    }
    return appendLedgerEntry(ctx, held, entries, { ...candidate, ...(supersedes !== undefined ? { supersedes } : {}) }, notes);
  });
}

/**
 * The same content again, from anyone, is the entry that stands: a second
 * author is an attestation of the kind "same content", appended, and the
 * entry is never rewritten.
 */
async function mergeSameContent(ctx: SwarmContext, held: { assertOwned(): Promise<void> }, same: LedgerEntry): Promise<LedgerResult> {
  const attested = await readAttestations(ctx.sandboxRoot);
  const already = same.by === ctx.agentId || same.authors.includes(ctx.agentId) || attested.some((a) => a.seq === same.seq && a.by === ctx.agentId && attestationAct(a) === "same_content");
  if (!already) {
    await held.assertOwned();
    await appendAttestation(ctx.sandboxRoot, attested, { v: 2, act: "same_content", seq: same.seq, target: same.hash ?? ledgerHash(same, "genesis"), by: ctx.agentId, at: new Date().toISOString() });
  }
  const all = await withAttestations(ctx.sandboxRoot, await readLedger(ctx.sandboxRoot, { raw: true }));
  await renderLedger(ctx.sandboxRoot, all);
  const stood = all.find((e) => e.seq === same.seq) ?? same;
  return { ok: true, entry: stood, merged: true, total: all.length, note: already ? `#${same.seq} already says this, recorded by you` : `#${same.seq} already says this word for word: recorded as your attestation of it (ledger/attestations.jsonl), not as a new entry` };
}

/** Chain and append one entry, and render ledger.md again. */
async function appendLedgerEntry(ctx: SwarmContext, held: { assertOwned(): Promise<void> }, entries: LedgerEntry[], entry: LedgerEntry, notes: string[]): Promise<LedgerResult> {
  if (entries.length >= LEDGER_MAX_ENTRIES) return { ok: false, reason: `the ledger holds ${LEDGER_MAX_ENTRIES} entries already` };
  // Every record an agent makes, of every kind, held to the case policy's
  // material use on what it rests on, transitively: the one place every
  // entry passes through. The harness's own external entries record the
  // material; they do not rest on it.
  if (entry.kind !== "external") {
    const use = await materialUseRefusal(ctx.sandboxRoot, entry as unknown as Record<string, unknown>);
    if (use) return { ok: false, reason: use };
  }
  // An entry whose refs reach a sensitive output (a job run with
  // secret_output, or one made from such an output) is recorded sensitive
  // (docs/adr/0016): its words are held to the run's sensitivity from now on.
  if (entry.refs?.length && !entry.sensitive) {
    const { sensitiveRefs } = await import("../scripts/output-hygiene.ts");
    const hits = await sensitiveRefs(ctx.sandboxRoot, entry.refs).catch(() => []);
    if (hits.length) {
      entry.sensitive = true;
      notes.push(`recorded sensitive: it cites sensitive output (${hits.map((h) => `${h.ref}, job ${h.job}${h.why === "secret_output" ? " ran with secret_output" : ", made from a sensitive output"}`).join("; ")}); no name, doing label or question may carry what it says, and a redacted package takes its words out`);
    }
  }
  // Keys in a stable order: the core is computed from the fields, not the line.
  // Chained like the trace: each entry names the one before it.
  const previous = entries.at(-1);
  entry.prev = previous?.hash ?? (previous ? ledgerHash(previous, "genesis") : "genesis");
  entry.hash = ledgerHash(entry, entry.prev);
  await mkdir(join(ctx.sandboxRoot, LEDGER_DIR), { recursive: true });
  await held.assertOwned();
  await appendFile(join(ctx.sandboxRoot, LEDGER_ENTRIES), `${JSON.stringify(entry)}\n`, "utf8");
  entries.push(entry);
  await renderLedger(ctx.sandboxRoot, await withAttestations(ctx.sandboxRoot, entries));
  return { ok: true, entry, merged: false, total: entries.length, ...(notes.length ? { note: notes.join("; ") } : {}) };
}

/** The classes of material the case policy says may not be used (material_use none), and the preset; null when none is forbidden. */
export async function forbiddenMaterialClasses(sandboxRoot: string): Promise<{ classes: Set<string>; preset: string } | null> {
  try {
    const p = JSON.parse(await readFile(join(sandboxRoot, "network", "policy.json"), "utf8")) as { policy?: string; material_use?: unknown };
    if (!p.material_use || typeof p.material_use !== "object") return null;
    const none = Object.entries(p.material_use as Record<string, unknown>).filter(([, v]) => String(v) === "none").map(([k]) => k);
    return none.length ? { classes: new Set(none), preset: String(p.policy ?? "standard") } : null;
  } catch {
    return null;
  }
}

/**
 * The case policy's material use, held at the record (docs/adr/0014): a
 * record that rests on material whose class the policy says may not be used
 * (`none`) is refused, whatever it cites: the material's own ref, the same
 * bytes by their digest (`sha256:`), a job's output made from it, a
 * catalogue member of such a job, or an entry that rests on it (support,
 * limitations, derived_from, a coverage record's results). The lineage is
 * the external lineage's (scripts/net-broker.ts), read over what each ref
 * resolves to, transitively; `reference` and `evidence` are taken, and what
 * rests on them is flagged where the answers are weighed. A run whose policy
 * forbids no class refuses nothing, and reads nothing.
 */
export async function materialUseRefusal(sandboxRoot: string, cand: string[] | (Partial<LedgerEntry> & Record<string, unknown>)): Promise<string | null> {
  const forbidden = await forbiddenMaterialClasses(sandboxRoot);
  if (!forbidden) return null;
  const record = Array.isArray(cand) ? { refs: cand } : cand;
  const { externalLineage } = await import("../scripts/net-broker.ts");
  const lineage = await externalLineage(sandboxRoot);
  for (const hit of await lineage.probe(record)) {
    const cls = hit.classes.find((c) => forbidden.classes.has(c));
    if (!cls) continue;
    return `${hit.cite} rests on ${cls.replace(/_/g, " ")} (${hit.via.join(", ")}), which case policy ${forbidden.preset} does not let a record cite or rest on (material_use ${cls}=none): it is kept on the record, and the examination does not rest on it`;
  }
  return null;
}

/**
 * External material, recorded by the harness as it enters the run: a
 * capture the fetch service sealed (source_class external_capture), material
 * the operator supplied. Its refs resolve now; its provenance is part of the
 * chained core. It is never an agent's: an agent cites it and records what
 * it establishes. The same material again (the same refs and class) is the
 * entry that stands.
 */
export async function recordExternal(sandboxRoot: string, input: { value: string; source: string; evidence: string; refs: string[]; source_class: (typeof LEDGER_SOURCE_CLASSES)[number]; provenance: NonNullable<LedgerEntry["provenance"]>; sensitive?: boolean }): Promise<LedgerResult> {
  const value = String(input.value ?? "").trim();
  if (!value || value.length > LEDGER_VALUE_MAX_CHARS) return { ok: false, reason: `an external entry says what the material is in 1 to ${LEDGER_VALUE_MAX_CHARS} characters` };
  if (!(LEDGER_SOURCE_CLASSES as readonly string[]).includes(input.source_class)) return { ok: false, reason: `source_class is one of ${LEDGER_SOURCE_CLASSES.join(", ")}` };
  if (!input.refs.length || input.refs.length > LEDGER_MAX_REFS) return { ok: false, reason: "an external entry cites the material it records" };
  const checked = await checkRefs(sandboxRoot, input.refs);
  if (!checked.ok) return checked;
  const r = await withTableLock(sandboxRoot, async (held): Promise<LedgerResult> => {
    const entries = await readLedger(sandboxRoot);
    const same = entries.find((e) => e.kind === "external" && e.source_class === input.source_class && JSON.stringify(e.refs ?? []) === JSON.stringify(input.refs));
    if (same) return { ok: true, entry: same, merged: true, total: entries.length, note: `#${same.seq} records it already` };
    const entry: LedgerEntry = {
      v: LEDGER_VERSION,
      seq: (entries.at(-1)?.seq ?? 0) + 1,
      kind: "external",
      value,
      source: input.source,
      evidence: input.evidence,
      refs: input.refs,
      ...(input.sensitive ? { sensitive: true } : {}),
      source_class: input.source_class,
      provenance: input.provenance,
      by: "system",
      authors: ["system"],
      at: new Date().toISOString(),
    };
    return appendLedgerEntry({ sandboxRoot, agentId: "system" }, held, entries, entry, []);
  });
  // No seat's record and no hub recordEntry wrote it: its own line carries its hash.
  if (r.ok && !r.merged) await traceHarnessEntry(sandboxRoot, r.entry, { fn: "recordExternal" });
  return r;
}

/**
 * A line of ledger/attestations.jsonl. Version 1 (no `v`) is a second author
 * recording an entry word for word, hashed over {seq, by, at}. Version 2
 * binds the entry's hash and says which act it is: `same_content`, the same
 * second author, or `attest`, an agent other than the entry's authors saying
 * what it re-derived, from which sealed objects, and what it only read, all
 * inside the hashed record. A duplicate is co-authorship, never a check.
 */
export type LedgerAttestation = {
  v?: 2;
  act?: "same_content" | "attest";
  seq: number;
  /** The attested entry's hash. */
  target?: string;
  by: string;
  at: string;
  /** An attest's: what was re-derived from which sealed object, and what was only read. */
  how?: string;
  /** An attest's: the sealed objects it re-derived from, each resolved. */
  refs?: string[];
  /**
   * An attest of a negative (a coverage record, or an answer bounded_negative
   * or not_determinable): whether the reviewer challenged the detection
   * assumptions, reproduced a decisive check, tried a materially different
   * route, each with what was done or why not. Inside the hashed record.
   */
  review?: NB.NegativeReview;
  /**
   * An attest of an answer to a question: whether the reviewer holds it
   * established, or a best candidate (what the evidence best supports, not
   * shown to be the answer). A best candidate does not satisfy the finish
   * line. Absent on a line from before strengths (read as it always was).
   */
  strength?: AttestStrength;
  /** An attest of an answer to a question: what the review of the answer found, part by part. */
  answer_review?: AnswerReview;
  /** Written by the hub: why only a best candidate could be attested (a medium or low confidence, a part not established, a route not taken). */
  capped?: string[];
  /** A second, independent review of a negative already reviewed or offered to another seat: why it adds something. */
  second_review_why?: string;
  prev?: string;
  hash?: string;
};

/** How strongly a review holds an answer: established, or a best candidate. */
export const ATTEST_STRENGTHS = ["established", "best_candidate"] as const;
export type AttestStrength = (typeof ATTEST_STRENGTHS)[number];

/**
 * A review of an answer to a question (B2): what the reviewer reproduced
 * and what it only read, whether each part the question asks is
 * established, the inference that connects the observations to the answer,
 * the alternatives it weighed, and whether another source family was
 * checked (or why not: never a compulsory box, but its absence is said).
 * `alternatives` is each alternative explanation considered and why the
 * evidence rules it out ([{explanation, why}]); a text is what an older
 * review said, and what a best candidate may still say. A review that holds
 * an answer established names at least one (the calibration run sabfd76: a
 * decoy adopted and attested established, "none the evidence allows").
 * A part of a partial answer that the answer itself declares open names
 * the entry that declares it (`declared_open`: E-<seq>, a limitation or a
 * coverage record the answer cites): the review attests that it is open, as
 * the answer says, and it does not cap the review (strengthCaps).
 */
/** An alternative weighed: what else could explain the answer, why the evidence rules it out, and the entries that show it (E-<seq>). */
export type AnswerReviewAlternative = { explanation: string; why: string; evidence?: string[] };
/**
 * A part the review weighed: whether it is established, why, and for a
 * partial answer the entry by which the answer declares it open. Against an
 * answer that carries parts (premises.ts AnswerPart), `id` names the answer's
 * part it weighs, and `missing` names a part the question asks that the
 * answer leaves out (never established by it). `not_asked` says a part the
 * answer holds (most often open) is outside what the question asks: detail
 * beyond it, an example category the evidence does not show, an
 * exhaustiveness the question does not demand, a hedge on direction (the c10
 * run s704e4b held three complete answers partial on such parts). It is a
 * limitation, not an open part: it caps no review, and a partial answer
 * whose every other part is established is warned
 * (partial_all_parts_established). Never a promotion: the answer stands as
 * recorded. `at_limit` agrees that a part the answer holds limited (by its
 * id) is at the limit of the evidence in scope: it caps no review; a review
 * that holds such a part not established without it says a route could
 * still settle it, and caps an established review (strengthCaps). Each only
 * when given: a review from before them hashes as it did.
 */
export type AnswerReviewPart = { id?: string; part: string; established: boolean; why: string; declared_open?: string; missing?: true; not_asked?: true; at_limit?: true };
/**
 * The strongest rival and the test that separates it from the answer
 * (source-first review, docs/adr/0015): the rival (another time, entity,
 * mechanism or activity the evidence could mean, or the premise not
 * holding), the test, the result that would favour each, what it showed,
 * and the observation or job it rests on (E-<seq>, or an object ref). The
 * hub checks the refs, never whether the test is good.
 */
export type AnswerReviewDiscriminator = { rival: string; test: string; favours_if: string; outcome: string; refs: string[] };
/**
 * Where the reviewer read a literal value it vouches for: a sealed object,
 * the byte offset where the value begins, and the value (or how many bytes
 * hold it, read back from the object and found in the answer's words). The
 * hub reads those bytes, in UTF-8 and in UTF-16LE: presence, never
 * attribution.
 */
export type AnswerReviewLocator = { ref: string; offset: number; length?: number; value?: string };
/** How a derived value was derived: the job that derived it, and the objects it read. */
export type AnswerReviewDerivation = { job: string; inputs: string[] };
export type AnswerReview = {
  reproduced: string;
  read: string;
  parts: AnswerReviewPart[];
  inference: string;
  alternatives: string | AnswerReviewAlternative[];
  other_family: { checked: boolean; text: string };
  /** Present only when given (a review from before them hashes as it did). */
  discriminator?: AnswerReviewDiscriminator;
  reproduced_at?: AnswerReviewLocator[];
  derivation?: AnswerReviewDerivation;
  /**
   * The test of what the question presumes (docs/adr/0011, "What a question
   * presumes"): the rival is fixed, "the question's premise is not
   * supported"; what the test showed, and the observation or job it rests
   * on. Present only when given.
   */
  premise_tested?: PM.PremiseTest;
};
export const ANSWER_REVIEW_MAX_PARTS = 20;
export const ANSWER_REVIEW_MAX_ALTERNATIVES = 10;
/** A review's locators: at most this many; a value at most this many bytes in either encoding; a length at most this many bytes. */
export const ANSWER_REVIEW_MAX_LOCATORS = 10;
export const LOCATOR_MAX_BYTES = 4096;
/** The fewest characters a value read back by length may be: a shorter one is in every answer. */
export const LOCATOR_MIN_CHARS = 3;
/** How far either side of a locator's offset the hub looks for its value when it is not there (to say where it is): a bounded read, never a scan. */
export const LOCATOR_NEAR_BYTES = 256;

/** Words that say nothing was weighed: an alternative written so is none. */
const PLACEHOLDER_WORDS: ReadonlySet<string> = new Set(["none", "na", "n a", "no alternative", "no alternatives", "nothing", "not applicable", "no other", "nothing else", "unknown", "tbd", "null", "nil", "no", "same", "see above", "none found", "no other explanation"]);

/** Whether a text is a placeholder: empty once its punctuation goes, a stock "none", or shorter than a real explanation (under 8 letters or digits). */
export function placeholderText(t: string | undefined | null): boolean {
  const norm = String(t ?? "").normalize("NFKC").toLowerCase().replace(/[^\p{L}\p{N}]+/gu, " ").trim();
  return !norm || PLACEHOLDER_WORDS.has(norm) || norm.replace(/\s+/g, "").length < 8;
}

/**
 * Whether an alternative counts as one weighed (structural, not a word list
 * alone): it names the evidence that rules it out (at least one E-<seq>,
 * which the attest checks against the ledger), its explanation and its why
 * are neither empty nor a placeholder, and they are not the same words (the
 * Fable review of batches 1-3: [{explanation: "none", why: "n/a"}] passed).
 */
export function alternativeCounts(a: AnswerReviewAlternative): boolean {
  const same = (x: string, y: string) => x.normalize("NFKC").toLowerCase().replace(/\s+/g, " ").trim() === y.normalize("NFKC").toLowerCase().replace(/\s+/g, " ").trim();
  return (a.evidence ?? []).some((r) => /^E-\d+$/.test(r)) && !placeholderText(a.explanation) && !placeholderText(a.why) && !same(a.explanation, a.why);
}

/** Whether a review names an alternative explanation it weighed, why the evidence rules it out, and the entries that show it (alternativeCounts). */
export function reviewNamesAlternative(r: AnswerReview | undefined | null): boolean {
  return Boolean(r && Array.isArray(r.alternatives) && r.alternatives.some(alternativeCounts));
}

/** Why an established attest is recorded a best candidate when its review names no alternative that counts. */
export const NO_ALTERNATIVE_CAP = "the review names no alternative explanation it weighed with the evidence that rules it out (answer_review.alternatives [{explanation, why, evidence: [E-<seq>]}], each a real explanation, not a placeholder)";

/** An answer review as given: every field said, each bounded (refused past it, never cut). */
export function checkAnswerReview(raw: unknown): { ok: true; review: AnswerReview } | { ok: false; reason: string } {
  const r = (raw && typeof raw === "object" ? raw : {}) as Record<string, unknown>;
  const shape = "answer_review is {reproduced, read, parts: [{part, established, why}], inference, alternatives: [{explanation, why}], other_family: {checked, text}}";
  const text = (name: string, v: unknown): { ok: true; value: string } | { ok: false; reason: string } => {
    const t = String(v ?? "").trim();
    if (!t) return { ok: false, reason: `answer_review.${name} is required (${shape}): say it, or "none" and why` };
    if (t.length > LEDGER_ACT_MAX_CHARS) return { ok: false, reason: `answer_review.${name} is over ${LEDGER_ACT_MAX_CHARS} characters: say it in fewer; nothing is cut, so a longer text is refused` };
    return { ok: true, value: t };
  };
  const reproduced = text("reproduced", r.reproduced);
  if (!reproduced.ok) return reproduced;
  const read = text("read", r.read);
  if (!read.ok) return read;
  const inference = text("inference", r.inference);
  if (!inference.ok) return inference;
  // Each alternative weighed, and why the evidence rules it out; a text is still read (an older review, a best candidate's "what else it allows").
  let alternatives: AnswerReview["alternatives"];
  if (Array.isArray(r.alternatives)) {
    if (!r.alternatives.length) return { ok: false, reason: `answer_review.alternatives lists each alternative explanation you considered and why the evidence rules it out, [{explanation, why}], at least one; if you weighed none, say so in a text and attest best_candidate (${shape})` };
    if (r.alternatives.length > ANSWER_REVIEW_MAX_ALTERNATIVES) return { ok: false, reason: `answer_review.alternatives lists at most ${ANSWER_REVIEW_MAX_ALTERNATIVES}: keep the ones a reader must weigh` };
    const list: AnswerReviewAlternative[] = [];
    for (const x of r.alternatives) {
      const o = (x && typeof x === "object" ? x : {}) as Record<string, unknown>;
      const explanation = text("alternatives[].explanation", o.explanation);
      if (!explanation.ok) return explanation;
      const why = text("alternatives[].why", o.why);
      if (!why.ok) return why;
      // The entries that rule it out, by seq (the attest checks each is in the ledger).
      const ev = (Array.isArray(o.evidence) ? o.evidence : o.evidence === undefined || o.evidence === null ? [] : String(o.evidence).split(/[\s,]+/)).map((v) => String(v).trim()).filter(Boolean).map((v) => (/^#\d+$/.test(v) ? `E-${v.slice(1)}` : /^e-\d+$/i.test(v) ? v.toUpperCase() : v));
      const bad = ev.find((v) => !/^E-[1-9]\d{0,6}$/.test(v));
      if (bad) return { ok: false, reason: `answer_review.alternatives[].evidence names entries as E-<seq> (got ${JSON.stringify(bad)}): the entries that rule the alternative out` };
      if (ev.length > LEDGER_MAX_CITATIONS) return { ok: false, reason: `answer_review.alternatives[].evidence names more than ${LEDGER_MAX_CITATIONS} entries` };
      list.push({ explanation: explanation.value, why: why.value, ...(ev.length ? { evidence: [...new Set(ev)] } : {}) });
    }
    alternatives = list;
  } else {
    const t = text("alternatives", r.alternatives);
    if (!t.ok) return t;
    alternatives = t.value;
  }
  if (!Array.isArray(r.parts) || !r.parts.length) return { ok: false, reason: `answer_review.parts names each part the question asks, [{part, established: true|false, why}], at least one (${shape})` };
  if (r.parts.length > ANSWER_REVIEW_MAX_PARTS) return { ok: false, reason: `answer_review.parts names at most ${ANSWER_REVIEW_MAX_PARTS} parts` };
  const parts: AnswerReview["parts"] = [];
  for (const p of r.parts) {
    const o = (p && typeof p === "object" ? p : {}) as Record<string, unknown>;
    const part = text("parts[].part", o.part);
    if (!part.ok) return part;
    if (typeof o.established !== "boolean") return { ok: false, reason: `answer_review.parts[].established is true or false: whether "${part.value}" is established` };
    const why = text("parts[].why", o.why);
    if (!why.ok) return why;
    // The entry by which a partial answer declares this part open, by seq.
    let declaredOpen: string | undefined;
    if (o.declared_open !== undefined && o.declared_open !== null && String(o.declared_open).trim() !== "") {
      const v = String(o.declared_open).trim();
      const m = /^(?:#|E-)?([1-9]\d{0,6})$/i.exec(v);
      if (!m) return { ok: false, reason: `answer_review.parts[].declared_open names the entry by which the answer declares "${part.value}" open, as E-<seq> (a limitation or a coverage record the answer cites; got ${JSON.stringify(o.declared_open)})` };
      declaredOpen = `E-${Number(m[1])}`;
    }
    // Against an answer's parts: the id of the part it weighs, or a part the answer leaves out (missing).
    const pid = o.id === undefined || o.id === null || String(o.id).trim() === "" ? undefined : String(o.id).trim();
    if (pid !== undefined && !PM.PART_ID.test(pid)) return { ok: false, reason: `answer_review.parts[].id names the answer's part by its id (a, b, who; got ${JSON.stringify(o.id)})` };
    if (o.missing !== undefined && o.missing !== null && typeof o.missing !== "boolean") return { ok: false, reason: "answer_review.parts[].missing is true or false: whether the answer leaves this part of the question out" };
    const missing = o.missing === true;
    if (missing && o.established) return { ok: false, reason: `answer_review.parts[]: "${part.value}" is missing from the answer, so the answer does not establish it: established false, and say in why what the evidence shows of it` };
    if (missing && pid !== undefined) return { ok: false, reason: `answer_review.parts[]: "${part.value}" is missing from the answer: it has no id of the answer's (leave id out)` };
    if (missing && declaredOpen) return { ok: false, reason: `answer_review.parts[]: "${part.value}" is missing from the answer: the answer declares nothing of it open` };
    // A part the answer holds that the question does not ask (a limitation, not an open part).
    if (o.not_asked !== undefined && o.not_asked !== null && typeof o.not_asked !== "boolean") return { ok: false, reason: "answer_review.parts[].not_asked is true or false: whether this part of the answer is outside what the question asks" };
    const notAsked = o.not_asked === true;
    if (notAsked && missing) return { ok: false, reason: `answer_review.parts[]: "${part.value}" is either missing (the question asks it and the answer leaves it out) or not_asked (the answer holds it and the question does not ask it), not both` };
    if (notAsked && o.established) return { ok: false, reason: `answer_review.parts[]: "${part.value}" is not asked by the question, so the review does not weigh it: established false, and say in why why the question does not ask it (detail beyond it, an example category, an exhaustiveness it does not demand)` };
    // A part the answer holds limited, which the review agrees the evidence in scope cannot settle.
    if (o.at_limit !== undefined && o.at_limit !== null && typeof o.at_limit !== "boolean") return { ok: false, reason: "answer_review.parts[].at_limit is true or false: whether you agree that the evidence in scope cannot settle this part the answer holds limited" };
    const atLimit = o.at_limit === true;
    if (atLimit && (o.established || missing || notAsked || pid === undefined)) return { ok: false, reason: `answer_review.parts[]: "${part.value}" at_limit agrees with a part the answer holds limited, by its id: established false, with id, and neither missing nor not_asked; say in why what shows the evidence cannot settle it` };
    parts.push({ ...(pid !== undefined ? { id: pid } : {}), part: part.value, established: o.established, why: why.value, ...(declaredOpen ? { declared_open: declaredOpen } : {}), ...(missing ? { missing: true as const } : {}), ...(notAsked ? { not_asked: true as const } : {}), ...(atLimit ? { at_limit: true as const } : {}) });
  }
  const f = (r.other_family && typeof r.other_family === "object" ? r.other_family : null) as Record<string, unknown> | null;
  if (!f || typeof f.checked !== "boolean") return { ok: false, reason: "answer_review.other_family is {checked: true|false, text}: whether a materially different source family was checked, and which, or why not" };
  const ft = text("other_family.text", f.text);
  if (!ft.ok) return ft;
  const extra = checkReviewEvidence(r);
  if (!extra.ok) return extra;
  return { ok: true, review: { reproduced: reproduced.value, read: read.value, parts, inference: inference.value, alternatives, other_family: { checked: f.checked, text: ft.value }, ...extra.fields } };
}

/** A ref an answer review names as its observation: an entry (E-<seq>, #<seq>), or an object, as given. */
function reviewRef(v: unknown): string {
  const s = String(v ?? "").trim();
  return /^#\d+$/.test(s) ? `E-${s.slice(1)}` : /^e-\d+$/i.test(s) ? s.toUpperCase() : s;
}

/**
 * The review's discriminator, locators and derivation as given, each only
 * when present, each bounded (refused past it, never cut): the shape only.
 * Whether a discriminator counts, a locator verifies and a derivation
 * resolves is the attest's (reviewEvidenceCaps).
 */
function checkReviewEvidence(r: Record<string, unknown>): { ok: true; fields: Pick<AnswerReview, "discriminator" | "reproduced_at" | "derivation" | "premise_tested"> } | { ok: false; reason: string } {
  const fields: Pick<AnswerReview, "discriminator" | "reproduced_at" | "derivation" | "premise_tested"> = {};
  const given = (v: unknown) => v !== undefined && v !== null && !(typeof v === "string" && !v.trim());
  if (given(r.premise_tested)) {
    const t = checkPremiseTest(r.premise_tested, "answer_review.premise_tested");
    if (!t.ok) return t;
    fields.premise_tested = t.test;
  }
  if (given(r.discriminator)) {
    const shape = "answer_review.discriminator is {rival, test, favours_if, outcome, refs}: the strongest rival reading, the test that separates it from the answer, the result that would favour each, what the test showed, and the observation or job it rests on (E-<seq>, job:<id>/<path>)";
    const d = (typeof r.discriminator === "object" ? r.discriminator : null) as Record<string, unknown> | null;
    if (!d || Array.isArray(d)) return { ok: false, reason: shape };
    const out: Record<string, string> = {};
    for (const k of ["rival", "test", "favours_if", "outcome"] as const) {
      const t = String(d[k] ?? "").trim();
      if (!t) return { ok: false, reason: `answer_review.discriminator.${k} is required (${shape})` };
      if (t.length > LEDGER_ACT_MAX_CHARS) return { ok: false, reason: `answer_review.discriminator.${k} is over ${LEDGER_ACT_MAX_CHARS} characters: say it in fewer; nothing is cut, so a longer text is refused` };
      out[k] = t;
    }
    const refs = (Array.isArray(d.refs) ? d.refs : given(d.refs) ? String(d.refs).split(/[\s,]+/) : []).map(reviewRef).filter(Boolean);
    if (!refs.length) return { ok: false, reason: `answer_review.discriminator.refs names the observation or the job the outcome rests on, at least one: E-<seq> of an entry, or an object (job:<id>/<path>, input:<path>, import:<id>/<path>) (${shape})` };
    if (refs.length > LEDGER_MAX_REFS) return { ok: false, reason: `answer_review.discriminator.refs names more than ${LEDGER_MAX_REFS}` };
    const long = refs.find((x) => x.length > LEDGER_REF_MAX_CHARS);
    if (long) return { ok: false, reason: `answer_review.discriminator.refs names one of ${long.length} characters, over ${LEDGER_REF_MAX_CHARS}: name the entry or the object` };
    const badE = refs.find((x) => /^E-/i.test(x) && !/^E-[1-9]\d{0,6}$/.test(x));
    if (badE) return { ok: false, reason: `answer_review.discriminator.refs names an entry as E-<seq> (got ${JSON.stringify(badE)})` };
    fields.discriminator = { rival: out.rival!, test: out.test!, favours_if: out.favours_if!, outcome: out.outcome!, refs: [...new Set(refs)] };
  }
  if (given(r.reproduced_at)) {
    const shape = "answer_review.reproduced_at is [{ref, offset, value}] (or {ref, offset, length}): the sealed object, the byte offset where the value begins, and the value you read there";
    if (!Array.isArray(r.reproduced_at)) return { ok: false, reason: shape };
    if (!r.reproduced_at.length) return { ok: false, reason: `${shape}; at least one, or leave it out` };
    if (r.reproduced_at.length > ANSWER_REVIEW_MAX_LOCATORS) return { ok: false, reason: `answer_review.reproduced_at names at most ${ANSWER_REVIEW_MAX_LOCATORS} locators: keep the ones for the values you vouch for` };
    const list: AnswerReviewLocator[] = [];
    for (const [i, x] of r.reproduced_at.entries()) {
      const o = (x && typeof x === "object" ? x : {}) as Record<string, unknown>;
      const at = `answer_review.reproduced_at[${i}]`;
      const ref = String(o.ref ?? "").trim();
      if (!ref) return { ok: false, reason: `${at}.ref names the sealed object you read the value in (job:<id>/<path>, import:<id>/<path>, input:<path>) (${shape})` };
      if (ref.length > LEDGER_REF_MAX_CHARS) return { ok: false, reason: `${at}.ref is over ${LEDGER_REF_MAX_CHARS} characters` };
      const offset = typeof o.offset === "string" && /^\d+$/.test(o.offset.trim()) ? Number(o.offset) : o.offset;
      if (typeof offset !== "number" || !Number.isSafeInteger(offset) || offset < 0) return { ok: false, reason: `${at}.offset is the byte offset in ${ref} where the value begins, a whole number from 0 (got ${JSON.stringify(o.offset)}): a job over the object gives it (grep -boa, a hex dump)` };
      const length = o.length === undefined || o.length === null || o.length === "" ? undefined : typeof o.length === "string" && /^\d+$/.test(o.length.trim()) ? Number(o.length) : o.length;
      if (length !== undefined && (typeof length !== "number" || !Number.isSafeInteger(length) || length < 1 || length > LOCATOR_MAX_BYTES)) return { ok: false, reason: `${at}.length is how many bytes hold the value, 1 to ${LOCATOR_MAX_BYTES} (got ${JSON.stringify(o.length)})` };
      const value = o.value === undefined || o.value === null ? undefined : String(o.value);
      if (value !== undefined && !value.trim()) return { ok: false, reason: `${at}.value is the value you read at the offset, as it is in the object; leave it out and give length to have it read back` };
      if (value !== undefined && Buffer.byteLength(value, "utf16le") > 2 * LOCATOR_MAX_BYTES) return { ok: false, reason: `${at}.value is over ${LOCATOR_MAX_BYTES} bytes: a locator names a value, not a passage` };
      if (value === undefined && length === undefined) return { ok: false, reason: `${at} names the value it vouches for (value, as it is in the object) or how many bytes hold it (length, read back and found in the answer's words) (${shape})` };
      list.push({ ref, offset, ...(length !== undefined ? { length: length as number } : {}), ...(value !== undefined ? { value } : {}) });
    }
    fields.reproduced_at = list;
  }
  if (given(r.derivation)) {
    const shape = "answer_review.derivation is {job, inputs}: the job that derived the value (j<id> or job:<id>) and the objects it read (input:<path>, job:<id>/<path>, import:<id>/<path>)";
    const d = (typeof r.derivation === "object" && !Array.isArray(r.derivation) ? r.derivation : null) as Record<string, unknown> | null;
    if (!d) return { ok: false, reason: shape };
    const job = /^(?:job:)?(j\d{6,})(?:\/.*)?$/.exec(String(d.job ?? "").trim())?.[1];
    if (!job) return { ok: false, reason: `answer_review.derivation.job names a job, j<id> or job:<id> (got ${JSON.stringify(d.job)}) (${shape})` };
    const inputs = (Array.isArray(d.inputs) ? d.inputs : given(d.inputs) ? String(d.inputs).split(/[\s,]+/) : []).map((x) => String(x).trim()).filter(Boolean);
    if (!inputs.length) return { ok: false, reason: `answer_review.derivation.inputs names the objects the job read, at least one (${shape})` };
    if (inputs.length > LEDGER_MAX_REFS) return { ok: false, reason: `answer_review.derivation.inputs names more than ${LEDGER_MAX_REFS}` };
    const long = inputs.find((x) => x.length > LEDGER_REF_MAX_CHARS);
    if (long) return { ok: false, reason: `answer_review.derivation.inputs names one of ${long.length} characters, over ${LEDGER_REF_MAX_CHARS}: name the object` };
    fields.derivation = { job, inputs: [...new Set(inputs)] };
  }
  return { ok: true, fields };
}

/**
 * A premise test as given (premises.ts PremiseTest), on a review or on an
 * answer: {outcome, refs}, bounded (refused past it, never cut), the shape
 * only. Whether its entries are in the ledger, and not the answer itself, is
 * checked where it is recorded; whether it counts, by premiseTestCounts.
 */
export function checkPremiseTest(raw: unknown, name: string): { ok: true; test: PM.PremiseTest } | { ok: false; reason: string } {
  const shape = `${name} is {outcome, refs}: what the test showed of whether what the question presumes happened at all (the rival: the question's premise is not supported), and the observation or job it rests on (E-<seq>, job:<id>/<path>, input:<path>, import:<id>/<path>)`;
  const d = (raw && typeof raw === "object" && !Array.isArray(raw) ? raw : null) as Record<string, unknown> | null;
  if (!d) return { ok: false, reason: shape };
  const outcome = String(d.outcome ?? "").trim();
  if (!outcome) return { ok: false, reason: `${name}.outcome is required (${shape})` };
  if (outcome.length > LEDGER_ACT_MAX_CHARS) return { ok: false, reason: `${name}.outcome is over ${LEDGER_ACT_MAX_CHARS} characters: say it in fewer; nothing is cut, so a longer text is refused` };
  const given = (v: unknown) => v !== undefined && v !== null && !(typeof v === "string" && !v.trim());
  const refs = [...new Set((Array.isArray(d.refs) ? d.refs : given(d.refs) ? String(d.refs).split(/[\s,]+/) : []).map(reviewRef).filter(Boolean))];
  if (!refs.length) return { ok: false, reason: `${name}.refs names the observation or the job the outcome rests on, at least one (${shape})` };
  if (refs.length > LEDGER_MAX_REFS) return { ok: false, reason: `${name}.refs names more than ${LEDGER_MAX_REFS}` };
  const long = refs.find((x) => x.length > LEDGER_REF_MAX_CHARS);
  if (long) return { ok: false, reason: `${name}.refs names one of ${long.length} characters, over ${LEDGER_REF_MAX_CHARS}: name the entry or the object` };
  const badE = refs.find((x) => /^E-/i.test(x) && !/^E-[1-9]\d{0,6}$/.test(x));
  if (badE) return { ok: false, reason: `${name}.refs names an entry as E-<seq> (got ${JSON.stringify(badE)})` };
  return { ok: true, test: { outcome, refs } };
}

/** Whether a premise test counts: an outcome that says something (not a placeholder) and at least one ref. */
export function premiseTestCounts(t: PM.PremiseTest | undefined | null): boolean {
  return Boolean(t && t.refs.length > 0 && !placeholderText(t.outcome));
}

/** A premise test in words: what it tested, what it showed, and on what. */
export function premiseTestWords(t: PM.PremiseTest): string {
  return `the premise tested against "the question's premise is not supported": ${t.outcome} (${t.refs.join(", ")})`;
}

/** Whether a discriminator counts: each of its words a real one (not a placeholder), the rival not the test's words again, and at least one ref. */
export function discriminatorCounts(d: AnswerReviewDiscriminator | undefined | null): boolean {
  if (!d) return false;
  const norm = (x: string) => x.normalize("NFKC").toLowerCase().replace(/\s+/g, " ").trim();
  return d.refs.length > 0 && ![d.rival, d.test, d.favours_if, d.outcome].some((t) => placeholderText(t)) && norm(d.rival) !== norm(d.test);
}

/** A locator's verdict: its value is at its offset in the sealed object (in which encoding), or why not. */
export type LocatorVerdict = { ok: true; ref: string; offset: number; encoding: "utf-8" | "utf-16le" } | { ok: false; ref: string; offset: number; why: string };

/** ASCII letters folded to lower case, in a copy (as the store sweep folds them). */
function foldAscii(b: Buffer): Buffer {
  const out = Buffer.from(b);
  for (let i = 0; i < out.length; i++) if (out[i]! >= 0x41 && out[i]! <= 0x5a) out[i] = out[i]! + 0x20;
  return out;
}

/** A value's byte forms, folded: as given, lower- and upper-cased, in UTF-8 and UTF-16LE. */
function valueForms(v: string): Array<{ enc: "utf-8" | "utf-16le"; bytes: Buffer }> {
  const out: Array<{ enc: "utf-8" | "utf-16le"; bytes: Buffer }> = [];
  for (const s of new Set([v, v.toLowerCase(), v.toUpperCase()])) {
    for (const enc of ["utf-8", "utf-16le"] as const) {
      const bytes = foldAscii(Buffer.from(s, enc === "utf-8" ? "utf8" : "utf16le"));
      if (!out.some((x) => x.enc === enc && x.bytes.equals(bytes))) out.push({ enc, bytes });
    }
  }
  return out;
}

/** Text as an answer's words are compared: NFKC, lower case, runs of space as one. */
function looseText(s: string): string {
  return s.normalize("NFKC").toLowerCase().replace(/\s+/g, " ").trim();
}

/**
 * A locator held to the sealed bytes and to what the answer rests on: its
 * ref resolves to a sealed object of this run (an input, a job's output or
 * log, an import, a capture, a sealed brain output), and its value is at
 * its offset there, in UTF-8 or UTF-16LE, ASCII letters in either case, and
 * is among the words of the answer (`answerText`, its value and reasoning)
 * or of an entry the answer reaches (`chainText`: its support, and what
 * those cite, answerReach), at least LOCATOR_MIN_CHARS: a locator vouches
 * for what the answer or its chain states, often a supporting observation,
 * never for an occurrence of something nothing in the chain states (the
 * Fable review of the limits branch, P2-2). With a length and no value, the
 * bytes there are read back and held to the same words. Bounded reads at
 * the offset (and LOCATOR_NEAR_BYTES either side, to say where the value is
 * when it is not at the offset): never a scan, never the object's whole
 * hash (resolving it against its manifest is the seal).
 */
export async function checkLocator(sandboxRoot: string, loc: AnswerReviewLocator, answerText: string, chainText = ""): Promise<LocatorVerdict> {
  const no = (why: string): LocatorVerdict => ({ ok: false, ref: loc.ref, offset: loc.offset, why });
  const { resolveRef } = await import("../scripts/evidence-store.ts");
  const r = await resolveRef(sandboxRoot, loc.ref).catch((err: Error) => ({ ok: false as const, ref: loc.ref, reason: err.message }));
  if (!r.ok) return no(`${loc.ref} does not resolve to a sealed object of this run: ${r.reason}`);
  if (r.kind === "unresolved" || r.kind === "member" || !r.path) return no(`${loc.ref} is not an object's bytes (${r.kind === "member" ? "a catalogue member is a row of a list: name the file it is in" : r.kind}): a locator names a sealed file`);
  const abs = join(sandboxRoot, r.path);
  const st = await stat(abs).catch(() => null);
  if (!st?.isFile()) return no(`${loc.ref} ${st ? "is a directory: a locator names one file in it" : `cannot be read here (${r.path})`}`);
  // What it vouches for is a value the answer or its chain states: an occurrence of anything else vouches for nothing the answer rests on.
  const stated = [looseText(answerText), looseText(chainText)];
  if (loc.value !== undefined) {
    const v = looseText(loc.value);
    if (v.length < LOCATOR_MIN_CHARS) return no(`the value "${loc.value}" is under ${LOCATOR_MIN_CHARS} characters: too short to vouch for what the answer rests on; locate a value the answer or an entry it rests on states`);
    if (!stated.some((t) => t.includes(v))) return no(`the value "${loc.value}" is not among the words of the answer (its value and reasoning) nor of any entry it rests on (its support, and what those cite): a locator vouches for a value the answer or its chain states. A value given there in another form (a converted time, a decoded field) is vouched for by derivation {job, inputs}`);
  }
  const forms = loc.value !== undefined ? valueForms(loc.value) : [];
  const need = loc.value !== undefined ? Math.max(...forms.map((f) => f.bytes.length)) : (loc.length as number);
  if (loc.offset >= st.size) return no(`offset ${loc.offset} is past the end of ${loc.ref} (${st.size} bytes)`);
  const from = Math.max(0, loc.offset - LOCATOR_NEAR_BYTES);
  const to = Math.min(st.size, loc.offset + need + LOCATOR_NEAR_BYTES);
  const fh = await open(abs, "r");
  let window: Buffer;
  try {
    window = Buffer.alloc(to - from);
    const { bytesRead } = await fh.read(window, 0, to - from, from);
    window = foldAscii(window.subarray(0, bytesRead));
  } finally {
    await fh.close();
  }
  const at = loc.offset - from;
  if (loc.value !== undefined) {
    for (const f of forms) {
      if (window.subarray(at, at + f.bytes.length).equals(f.bytes)) {
        if (loc.length !== undefined && loc.length !== f.bytes.length) return no(`the value is at offset ${loc.offset} in ${f.enc}, in ${f.bytes.length} bytes, not the length ${loc.length} given: leave length out, or give ${f.bytes.length}`);
        return { ok: true, ref: loc.ref, offset: loc.offset, encoding: f.enc };
      }
    }
    // Where it is nearby, when it is: the fix is then one number.
    let near: { offset: number; enc: string } | null = null;
    for (const f of forms) {
      for (let i = window.indexOf(f.bytes); i >= 0; i = window.indexOf(f.bytes, i + 1)) {
        const o = from + i;
        if (!near || Math.abs(o - loc.offset) < Math.abs(near.offset - loc.offset)) near = { offset: o, enc: f.enc };
      }
    }
    return no(`the value is not at offset ${loc.offset} of ${loc.ref} in UTF-8 or UTF-16LE${near ? `: it begins at offset ${near.offset} (${near.enc}), ${Math.abs(near.offset - loc.offset)} bytes ${near.offset < loc.offset ? "before" : "after"}` : `, nor within ${LOCATOR_NEAR_BYTES} bytes of it`}`);
  }
  // A length and no value: the bytes read back, and found in the answer's words.
  const raw = window.subarray(at, at + need);
  if (raw.length < need) return no(`${loc.ref} holds ${raw.length} bytes from offset ${loc.offset}, fewer than the length ${need} given`);
  const readings: Array<{ enc: "utf-8" | "utf-16le"; text: string }> = [];
  // A reading is text: no control character but tab and line ends, no replacement character (UTF-16LE's zero bytes are not UTF-8 text).
  const control = /[\u0000-\u0008\u000e-\u001f]/;
  const unreadable = (t: string) => control.test(t) || t.includes(String.fromCodePoint(0xfffd));
  try {
    const t = new TextDecoder("utf-8", { fatal: true }).decode(raw);
    if (!unreadable(t)) readings.push({ enc: "utf-8", text: t });
  } catch {
    // not UTF-8
  }
  if (need % 2 === 0) {
    const t = raw.toString("utf16le");
    if (Buffer.from(t, "utf16le").equals(raw) && !unreadable(t)) readings.push({ enc: "utf-16le", text: t });
  }
  for (const x of readings) {
    const t = looseText(x.text);
    if (t.length >= LOCATOR_MIN_CHARS && stated.some((w) => w.includes(t))) return { ok: true, ref: loc.ref, offset: loc.offset, encoding: x.enc };
  }
  return no(`the ${need} bytes at offset ${loc.offset} of ${loc.ref} ${readings.length ? `read as ${readings.map((x) => x.enc).join(" or ")} text neither the answer nor an entry it rests on states` : "are not UTF-8 or UTF-16LE text"}: give value, the value as it is in the object`);
}

/** A derivation held to the run: its job is sealed and ran to its end, each input resolves, and each is among what the job declared it would read. */
export async function checkDerivation(sandboxRoot: string, d: AnswerReviewDerivation): Promise<{ ok: true } | { ok: false; why: string }> {
  const { resolveRef } = await import("../scripts/evidence-store.ts");
  const j = await resolveRef(sandboxRoot, `job:${d.job}`).catch((err: Error) => ({ ok: false as const, ref: `job:${d.job}`, reason: err.message }));
  if (!j.ok) return { ok: false, why: `job ${d.job} is not a sealed job of this run: ${j.reason}` };
  if (j.status && j.status !== "ok") return { ok: false, why: `job ${d.job} ended ${j.status}: a derivation is a job that ran to its end` };
  const declared = await NB.jobDeclared(sandboxRoot, d.job).catch(() => null);
  const scope = declared?.scope === "declared" && declared.inputs.length ? await Promise.all(declared.inputs.map((x) => NB.objectOf(sandboxRoot, x).catch(() => null))) : null;
  for (const input of d.inputs) {
    const r = await resolveRef(sandboxRoot, input).catch((err: Error) => ({ ok: false as const, ref: input, reason: err.message }));
    if (!r.ok) return { ok: false, why: `derivation input ${input} does not resolve: ${r.reason}` };
    if (!scope) continue;
    const o = await NB.objectOf(sandboxRoot, input).catch(() => null);
    const inside = o && !("reason" in o) && scope.some((s) => s && !("reason" in s) && NB.contains(s, o));
    if (!inside) return { ok: false, why: `job ${d.job} did not declare ${input} among what it reads (it declared ${declared!.inputs.join(", ")}): name the objects the job read` };
  }
  return { ok: true };
}

/**
 * How a question's premise is tested (docs/adr/0011, "What a question
 * presumes"): the words the attest's reply, the warning and the tools give.
 */
export const PREMISE_TEST_FIX =
  "test the premise before the answer: does the evidence show that what the question presumes happened at all? Weigh it against the rival \"the question's premise is not supported\" and say what the test showed: premise_tested {outcome (what the test showed of whether it happened), refs (the E-<seq> of the observation, or the job:<id>/<path> it rests on)}, which a review gives as answer_review.premise_tested (never resting on the answer under review). If the evidence does not support it, the answer is premise_not_supported: its recorder records it so, and a reviewer disputes an answer that says otherwise. A clue that fits the question's frame is a candidate to test against that rival, not an answer";

/** Why an established attest is recorded a best candidate for want of source-first evidence: a code, and the words `capped` keeps. */
export type ReviewEvidenceCap = { code: "no_discriminator" | "locator_unverified" | "derivation_unverified" | "premise_untested" | "rival_area_uncovered"; why: string };
/**
 * What a source-first review is warned of and not capped for: it vouches
 * for no value by bytes or by derivation (no_locator_or_derivation). The
 * approved rule capped only a missing discriminator and a locator that does
 * not verify; requiring one of the two capped a correct established answer
 * that no single literal in the bytes and no job states (an inference over
 * several entries), and the way to end the run was then to record it
 * partial (the Fable review of the limits branch, P2-3). It is a warning
 * until the paired runs show the cap catches more than it costs; the
 * metrics count the established answers recorded partial after a capped
 * attest.
 */
export type ReviewEvidenceWarning = { code: "no_locator_or_derivation"; why: string };

/**
 * How a located value's source comes to be covered where a rival value
 * could live (docs/adr/0013, "A locator is not coverage").
 */
export const RIVAL_AREA_FIX =
  "a located value proves the value is there, not that it is the answer: record kind=coverage for the question over the source the value was read from (refs naming it), with areas {allocated, deleted, unallocated, slack, secondary} each searched or not_applicable (none skipped), result_refs naming the job that searched the source's other areas, and looked_for the strings a rival record would carry (another name, time or version of the same field); then attest again. Ask of the bytes: could they be there if the claim were wrong, and where would a rival value live?";

/** How each cap is fixed, in the words the attest's reply gives. */
export const REVIEW_CAP_FIX: Readonly<Record<ReviewEvidenceCap["code"], string>> = {
  no_discriminator: "name the strongest rival and the test that separates it from the answer: answer_review.discriminator {rival (another reading the evidence allows: another time, entity, mechanism or activity, or the premise not holding), test (what you checked), favours_if (the result that would favour the answer, and the one that would favour the rival), outcome (what the check showed), refs (the E-<seq> of the observation, or the job:<id>/<path> it rests on: not the answer, nor only entries it cites)}",
  locator_unverified: "give each locator's byte offset where the value begins in the sealed object and the value as it is there and as the answer or an entry it rests on states it (a job over the object gives the offset: grep -boa, a hex dump; UTF-16LE text counts), or drop the locator; a value you derived (a converted time, a decoded field) takes derivation {job, inputs} instead",
  derivation_unverified: "name a sealed job that ran to its end and the objects it declared it would read: answer_review.derivation {job: j<id>, inputs: [input:<path>, job:<id>/<path>, …]}",
  premise_untested: PREMISE_TEST_FIX,
  rival_area_uncovered: RIVAL_AREA_FIX,
};

/** How the warning no_locator_or_derivation is answered, where a value can be located. */
export const REVIEW_UNLOCATED_FIX =
  "where a value the answer or an entry it rests on states is in the bytes, say where you read it: answer_review.reproduced_at [{ref, offset, value}] (the sealed object, the byte offset where the value begins, the value as it is there and as the answer or that entry states it, in UTF-8 or UTF-16LE); for a derived value, answer_review.derivation {job (the job that derived it), inputs (the objects it read)}. An answer that is an inference over several entries, with no single value in the bytes, stands on its discriminator: a warning, never a hold";

/**
 * The source-first evidence an established review carries (docs/adr/0015,
 * "A source-first review"), on an answer that claims established to a
 * material question: a discriminator that counts, and every locator
 * verifying against the sealed bytes and the answer's words, every
 * derivation resolving; and, on a question that presumes an event
 * (docs/adr/0011, "What a question presumes"; `presumption`, read from the
 * register when the caller does not give it), a premise test that counts
 * (premise_untested). Each missing or failing one is a cap: the attest is
 * recorded best_candidate with the reason in `capped`, and the reply says
 * how to fix it. A review with neither a locator nor a derivation is warned
 * (`unlocated`, no_locator_or_derivation), not capped. Nothing else is
 * judged: byte presence proves presence, not attribution. `locators` is
 * every locator's verdict, for the reply of any review that gave them (a
 * partial answer's too, which none of this caps).
 */
export async function reviewEvidenceCaps(sandboxRoot: string, answer: LedgerEntry, review: AnswerReview | null, o: { material: boolean; entries?: readonly LedgerEntry[]; presumption?: PM.Presumption | null; attestations?: readonly LedgerAttestation[]; disputes?: readonly LedgerDispute[] }): Promise<{ caps: ReviewEvidenceCap[]; unlocated: ReviewEvidenceWarning | null; locators: LocatorVerdict[]; derivation: { ok: true } | { ok: false; why: string } | null }> {
  const text = `${answer.value ?? ""}\n${answer.reasoning ?? ""}`;
  const locators: LocatorVerdict[] = [];
  const chain = review?.reproduced_at?.length ? chainWords(answer, o.entries ?? (await readLedger(sandboxRoot).catch(() => [] as LedgerEntry[]))) : "";
  for (const l of review?.reproduced_at ?? []) locators.push(await checkLocator(sandboxRoot, l, text, chain).catch((err: Error) => ({ ok: false as const, ref: l.ref, offset: l.offset, why: `it could not be read (${err.message})` })));
  const derivation = review?.derivation ? await checkDerivation(sandboxRoot, review.derivation).catch((err: Error) => ({ ok: false as const, why: `it could not be checked (${err.message})` })) : null;
  const caps: ReviewEvidenceCap[] = [];
  if (!claimsEstablished(answer) || !o.material || !review) return { caps, unlocated: null, locators, derivation };
  if (!review.discriminator) caps.push({ code: "no_discriminator", why: "the review names no discriminator: the strongest rival and a test that separates it from the answer (answer_review.discriminator {rival, test, favours_if, outcome, refs})" });
  else if (!discriminatorCounts(review.discriminator)) caps.push({ code: "no_discriminator", why: "the review's discriminator says nothing a reader can weigh (a placeholder, or the rival in the test's words): a real rival and the test that separates it" });
  for (const [i, v] of locators.entries()) if (!v.ok) caps.push({ code: "locator_unverified", why: `reproduced_at[${i}] (${v.ref} at ${v.offset}) does not verify: ${v.why}` });
  if (derivation && !derivation.ok) caps.push({ code: "derivation_unverified", why: `the derivation does not resolve: ${derivation.why}` });
  // A question that presumes an event (docs/adr/0011, "What a question
  // presumes"): the review tests the premise itself against the rival "the
  // question's premise is not supported". Read from the register when the
  // caller did not say (a replay of an older caller).
  const presumption = o.presumption !== undefined ? o.presumption : answer.section?.startsWith("question:") ? ((await questionBar(sandboxRoot, sectionAnswersId(answer.section)).catch(() => null))?.presumption ?? null) : null;
  if (presumption && !premiseTestCounts(review.premise_tested)) {
    caps.push({ code: "premise_untested", why: review.premise_tested ? `the review's premise test says nothing a reader can weigh (a placeholder outcome): ${answer.section} presumes ${PM.presumptionWords(presumption)}` : `${answer.section} presumes ${PM.presumptionWords(presumption)}, and the review does not test that premise (answer_review.premise_tested {outcome, refs})` });
  }
  // A locator is not coverage (docs/adr/0013): each input a located value
  // was read from is covered, for the question, where a rival value could
  // live: a standing coverage record naming it, every area searched or not
  // applicable, and a job over it among its results. A located object that
  // traces to no input is not held.
  if (review.reproduced_at?.length) {
    const entries = [...(o.entries ?? (await readLedger(sandboxRoot).catch(() => [] as LedgerEntry[])))];
    const disputes = [...(o.disputes ?? (await readDisputes(sandboxRoot).catch(() => [] as LedgerDispute[])))];
    const uncovered = await rivalAreasUncovered(sandboxRoot, answer, review.reproduced_at.map((l) => l.ref), entries, disputes);
    if (uncovered.length) caps.push({ code: "rival_area_uncovered", why: `a locator is not coverage: ${uncovered.map((u) => `the value was read from ${u.source}, and ${u.why}`).join("; ")}` });
  }
  // Neither given: warned, never capped. One given and failing is capped by its own code above.
  const unlocated: ReviewEvidenceWarning | null = !review.reproduced_at?.length && !review.derivation ? { code: "no_locator_or_derivation", why: UNLOCATED_WHY } : null;
  return { caps, unlocated, locators, derivation };
}

/**
 * The inputs located values were read from that no coverage record for the
 * answer's question covers where a rival value could live (docs/adr/0013,
 * "A locator is not coverage"): for each input the refs reach, a standing
 * coverage record whose results still stand, recorded for the question,
 * that names the input (or a directory holding it), says every area
 * searched or not_applicable, and cites among its result_refs a job whose
 * declared inputs reach it. Each uncovered input with what is missing.
 */
export async function rivalAreasUncovered(sandboxRoot: string, answer: LedgerEntry, refs: readonly string[], entries: LedgerEntry[], disputes: LedgerDispute[] = []): Promise<Array<{ source: string; why: string }>> {
  if (!answer.section?.startsWith("question:")) return [];
  const qid = sectionKey(sectionAnswersId(answer.section));
  const replaced = supersededBy(entries);
  const covs = entries.filter((e) => e.kind === "coverage" && !replaced.has(e.seq) && (e.answers ?? []).some((x) => sectionKey(x) === qid) && !coverageProblems(e, entries, disputes).length);
  const { reach, names } = await PR.inputReach(sandboxRoot, [refs, ...covs.map((c) => c.refs ?? []), ...covs.map((c) => c.result_refs ?? [])]);
  const located = [...new Set(reach[0].map((r) => r.sha256))];
  const out: Array<{ source: string; why: string }> = [];
  for (const sha of located) {
    const name = names.get(sha) ?? `sha256:${sha}`;
    const naming = covs.filter((_, i) => reach[1 + i].some((r) => r.sha256 === sha && (r.how === "named" || r.how === "member")));
    if (!naming.length) {
      out.push({ source: name, why: `no standing coverage record for ${answer.section} names it` });
      continue;
    }
    const withAreas = naming.filter((c) => c.areas && NB.COVERAGE_AREAS.every((a) => c.areas?.[a] === "searched" || c.areas?.[a] === "not_applicable"));
    if (!withAreas.length) {
      out.push({ source: name, why: `its coverage record${naming.length === 1 ? "" : "s"} ${naming.map((c) => `E-${c.seq}`).join(", ")} ${naming.length === 1 ? "does" : "do"} not say every area {${NB.COVERAGE_AREAS.join(", ")}} searched or not applicable (${naming.map((c) => (c.areas ? NB.COVERAGE_AREAS.filter((a) => c.areas?.[a] !== "searched" && c.areas?.[a] !== "not_applicable").map((a) => `${a} ${c.areas?.[a] ?? "not said"}`).join(", ") : "no areas")).join("; ")})` });
      continue;
    }
    const byJob = withAreas.filter((c) => reach[1 + covs.length + covs.indexOf(c)].some((r) => r.sha256 === sha && r.how === "derived"));
    if (!byJob.length) out.push({ source: name, why: `its coverage record${withAreas.length === 1 ? "" : "s"} ${withAreas.map((c) => `E-${c.seq}`).join(", ")} ${withAreas.length === 1 ? "cites" : "cite"} no job over it among ${withAreas.length === 1 ? "its" : "their"} result_refs` });
  }
  return out;
}

/**
 * The words of every entry an answer reaches (answerReach: its support,
 * contrary and limitations, and what those cite in turn), for a locator to
 * be held to: what each says, where it was read, and what it indicates.
 */
export function chainWords(answer: LedgerEntry, entries: readonly LedgerEntry[]): string {
  const bySeq = new Map(entries.map((e) => [e.seq, e]));
  const reach = answerReach(answer, bySeq, supersededBy(entries as LedgerEntry[]));
  const out: string[] = [];
  for (const n of reach) {
    const e = bySeq.get(n);
    if (!e || n === answer.seq) continue;
    for (const w of [e.value, e.reasoning, e.evidence, e.source, e.indicates, e.significance]) if (typeof w === "string" && w) out.push(w);
  }
  return out.join("\n");
}

/** What a review that locates no value is warned of, in its words. */
const UNLOCATED_WHY = "the review vouches for no value by bytes or by derivation: no locator (answer_review.reproduced_at) and no derivation (answer_review.derivation)";

/** An answer review in words, for the ledger's rendering and the report. */
export function answerReviewWords(r: AnswerReview): string {
  const alternatives = Array.isArray(r.alternatives) ? `alternatives weighed: ${r.alternatives.map((a) => `${a.explanation} (ruled out: ${a.why}${a.evidence?.length ? `; ${a.evidence.join(", ")}` : "; no entry named"})`).join("; ")}` : `alternatives still open: ${r.alternatives}`;
  const d = r.discriminator;
  const discriminator = d ? `; the strongest rival: ${d.rival}; the test: ${d.test}; it would favour: ${d.favours_if}; it showed: ${d.outcome} (${d.refs.join(", ")})` : "";
  const located = r.reproduced_at?.length ? `; read at: ${r.reproduced_at.map((l) => `${l.ref} byte ${l.offset}${l.value !== undefined ? ` ("${l.value}")` : ` (${l.length} bytes)`}`).join("; ")}` : "";
  const derived = r.derivation ? `; derived by job ${r.derivation.job} from ${r.derivation.inputs.join(", ")}` : "";
  const premise = r.premise_tested ? `; ${premiseTestWords(r.premise_tested)}` : "";
  return `reproduced: ${r.reproduced}; only read: ${r.read}; parts: ${r.parts.map((p) => `${p.id ? `${p.id} ` : ""}${p.part} ${p.missing ? "MISSING from the answer" : p.not_asked ? "NOT ASKED by the question (a limitation, not an open part)" : p.at_limit ? "at the limit of the evidence, as the answer holds it" : p.established ? "established" : p.declared_open ? `open, as the answer declares it (${p.declared_open})` : "NOT established"} (${p.why})`).join("; ")}; inference: ${r.inference}; ${alternatives}; another source family ${r.other_family.checked ? "checked" : "not checked"}: ${r.other_family.text}${discriminator}${located}${derived}${premise}`;
}

/** Whether an attestation holds its answer established: a best candidate does not; a line from before strengths reads as it always did. */
export function attestEstablishes(a: LedgerAttestation): boolean {
  return a.strength !== "best_candidate";
}

/**
 * Whether an answer to a question claims established: its result is
 * established, or it was recorded before results and is not inconclusive
 * (it read as established). "A best candidate" concerns only such an
 * answer (B2). A disposition that only limits the run (partial, not
 * determinable, a bounded negative, out of scope) and a premise shown not
 * to hold are each held to their own bar, never to a strength: the run
 * s9722fa held six partial answers as best candidates, and its seats
 * walked every one of them down to not determinable.
 */
export function claimsEstablished(a: Pick<LedgerEntry, "kind" | "section" | "result" | "inconclusive">): boolean {
  if (a.kind !== "answer" || !a.section?.startsWith("question:")) return false;
  const r = NB.answerResult(a);
  return r === "established" || r === null;
}

/** The reviews of an answer: attests on it by seats other than its authors. */
export function answerReviews(a: LedgerEntry, attestations: readonly LedgerAttestation[]): LedgerAttestation[] {
  const h = a.hash ?? ledgerHash(a, "genesis");
  return attestations.filter((x) => attestationAct(x) === "attest" && x.target === h && !a.authors.includes(x.by));
}

/**
 * An answer's parts as its reviews weigh them (premises.ts partsStanding):
 * each review's not_asked and missing marks, with its reviewer; given the
 * ledger, each limited part's bound and whether another seat reviewed it
 * (limitedBounds). Null for an answer without rows, which reads as it
 * always did. The one reading the report, the console's view, questions.md
 * and the metrics share.
 */
export function answerPartsStanding(a: LedgerEntry, attestations: readonly LedgerAttestation[], ledger?: { entries: LedgerEntry[]; disputes?: LedgerDispute[] }): PM.PartsStanding | null {
  if (!a.parts?.length) return null;
  const marks: PM.PartMark[] = answerReviews(a, attestations).flatMap((x) =>
    (x.answer_review?.parts ?? []).filter((p) => p.not_asked || p.missing).map((p) => ({ by: x.by, ...(p.id ? { id: p.id } : {}), part: p.part, why: p.why, ...(p.not_asked ? { not_asked: true as const } : {}), ...(p.missing ? { missing: true as const } : {}) })),
  );
  const bounds = ledger && a.parts.some((p) => p.status === "limited") ? limitedBounds(a, ledger.entries, [...attestations], ledger.disputes ?? []) : undefined;
  return PM.partsStanding(a.parts, marks, bounds);
}

/**
 * Whether an answer is held as a best candidate (B2): it claims
 * established (claimsEstablished), another seat reviewed it, and every
 * review holds it a best candidate only. The one test readiness
 * (extensions/finish.ts), the answers check (scripts/check-answers.ts), and
 * through it the finish gate, and the report read, so they cannot drift.
 */
export function heldAsBestCandidate(a: LedgerEntry, reviews: readonly LedgerAttestation[]): boolean {
  return claimsEstablished(a) && reviews.length > 0 && !reviews.some(attestEstablishes);
}

/**
 * The entries by which an answer declares a part of it open: the
 * limitations it cites, and the coverage records it rests on. A partial
 * answer's review names one of them for each part it holds open as the
 * answer says (AnswerReviewPart.declared_open).
 */
export function declaredOpenBy(a: LedgerEntry, bySeq: ReadonlyMap<number, LedgerEntry>): Set<string> {
  const out = new Set<string>();
  for (const x of a.limitations ?? []) out.add(`E-${x.seq}`);
  for (const x of a.support ?? []) if (bySeq.get(x.seq)?.kind === "coverage") out.add(`E-${x.seq}`);
  return out;
}

/**
 * The confidence the run records for an answer to a question, beside the
 * one its author stated. High stands only on an established answer that
 * another seat attested established, naming the alternatives it weighed
 * and why the evidence rules each out (reviewNamesAlternative); any other
 * high is recorded medium, and `why` says what it lacks. Medium and low
 * stand as stated; nothing is refused. Derived where it is read (the report,
 * the metrics, the calibration score), because the attest that keeps a high
 * comes after the answer (the calibration run sabfd76: every answer high,
 * four of them wrong).
 */
export type RecordedConfidence = {
  stated: (typeof LEDGER_CONFIDENCE)[number] | null;
  recorded: (typeof LEDGER_CONFIDENCE)[number] | null;
  why: string | null;
  /** A high recorded before the rule (the answer carries no confidence_rule): kept as declared, and said so where it is shown. */
  legacy?: boolean;
};
export function recordedConfidence(answer: Pick<LedgerEntry, "kind" | "section" | "confidence" | "result" | "inconclusive" | "hash" | "by" | "authors" | "confidence_rule">, attestations: LedgerAttestation[]): RecordedConfidence {
  const stated = answer.confidence && (LEDGER_CONFIDENCE as readonly string[]).includes(answer.confidence) ? answer.confidence : null;
  if (stated !== "high" || answer.kind !== "answer" || !answer.section?.startsWith("question:")) return { stated, recorded: stated, why: null };
  // An answer recorded before the rule keeps what its author declared (a finished run reads as it did).
  if (answer.confidence_rule !== 1) return { stated, recorded: stated, why: null, legacy: true };
  const result = NB.answerResult(answer);
  if (result !== "established") return { stated, recorded: "medium", why: `high is kept only by an established answer, and this one ${result ? `is ${NB.resultWords(result)}` : "states no result"}` };
  const target = answer.hash ?? ledgerHash(answer as LedgerEntry, "genesis");
  const authors = new Set([answer.by, ...(answer.authors ?? [])]);
  const held = attestations.some((a) => attestationAct(a) === "attest" && a.target === target && !authors.has(a.by) && a.strength === "established" && reviewNamesAlternative(a.answer_review));
  return held ? { stated, recorded: "high", why: null } : { stated, recorded: "medium", why: "high is kept only once another seat attests it established, naming the alternatives it weighed and why the evidence rules each out; none has" };
}

/** The words that say a high was kept as declared because its answer predates the rule. */
export const LEGACY_CONFIDENCE_WORDS = "as declared: recorded before the run recorded confidence";

/** A recorded confidence in words: the recorded one, and the stated one when it differs, with why; a high from before the rule, as declared. */
export function confidenceWords(c: RecordedConfidence): string {
  if (!c.recorded) return "no confidence stated";
  if (c.legacy) return `${c.recorded} (${LEGACY_CONFIDENCE_WORDS})`;
  return c.recorded === c.stated ? c.recorded : `${c.recorded} (stated ${c.stated}; ${c.why})`;
}

/** The act of an attestation line: a version 1 line is a second author. */
export function attestationAct(a: LedgerAttestation): "same_content" | "attest" {
  return a.v === 2 && a.act === "attest" ? "attest" : "same_content";
}

export function attestationHash(a: LedgerAttestation, prev: string): string {
  const core =
    a.v === 2
      ? JSON.stringify({ v: 2, act: a.act, seq: a.seq, target: a.target, by: a.by, at: a.at, ...(a.how ? { how: a.how } : {}), ...(a.refs?.length ? { refs: a.refs } : {}), ...(a.review ? { review: canonicalValue(a.review) } : {}), ...(a.strength ? { strength: a.strength } : {}), ...(a.answer_review ? { answer_review: canonicalValue(a.answer_review) } : {}), ...(a.capped?.length ? { capped: a.capped } : {}), ...(a.second_review_why ? { second_review_why: a.second_review_why } : {}) })
      : JSON.stringify({ seq: a.seq, by: a.by, at: a.at });
  return createHash("sha256").update(`${prev}\n${core}`).digest("hex");
}

export async function readAttestations(sandboxRoot: string): Promise<LedgerAttestation[]> {
  const text = await readFile(join(sandboxRoot, LEDGER_ATTESTATIONS), "utf8").catch(() => "");
  const out: LedgerAttestation[] = [];
  for (const line of text.split("\n")) {
    if (!line.trim()) continue;
    try {
      out.push(JSON.parse(line) as LedgerAttestation);
    } catch {
      // a torn line is left for custody to name
    }
  }
  return out;
}

async function appendAttestation(sandboxRoot: string, existing: LedgerAttestation[], a: LedgerAttestation): Promise<LedgerAttestation> {
  const prev = existing.at(-1)?.hash ?? "genesis";
  const line: LedgerAttestation = { ...a, prev, hash: attestationHash(a, prev) };
  await mkdir(join(sandboxRoot, LEDGER_DIR), { recursive: true });
  await appendFile(join(sandboxRoot, LEDGER_ATTESTATIONS), `${JSON.stringify(line)}\n`, "utf8");
  return line;
}

/**
 * The attestations' own chain: each line names the one before it, and its
 * hash is over its version's record. A version 1 line after a version 2 one
 * is refused (the harness writes none again), and so is a version it does
 * not know, or a version 2 line that is neither act.
 */
export function verifyAttestationChain(text: string): { ok: boolean; total: number; broken_at: number | null; reason: string | null; head: string | null } {
  let last = "genesis";
  let total = 0;
  let sawV2 = false;
  for (const line of text.split("\n")) {
    if (!line.trim()) continue;
    total += 1;
    let a: LedgerAttestation;
    try {
      a = JSON.parse(line) as LedgerAttestation;
    } catch {
      return { ok: false, total, broken_at: total, reason: "not json", head: null };
    }
    if (a.v !== undefined && a.v !== 2) return { ok: false, total, broken_at: total, reason: `an attestation of version ${JSON.stringify(a.v)}, which this harness does not know`, head: null };
    if (a.v === 2 && a.act !== "same_content" && a.act !== "attest") return { ok: false, total, broken_at: total, reason: `an attestation whose act is ${JSON.stringify(a.act)}`, head: null };
    if (a.v === undefined && sawV2) return { ok: false, total, broken_at: total, reason: "a version 1 attestation after version 2 ones", head: null };
    if (a.v === 2) sawV2 = true;
    if (a.prev !== last) return { ok: false, total, broken_at: total, reason: "prev does not name the line before it", head: null };
    if (a.hash !== attestationHash(a, last)) return { ok: false, total, broken_at: total, reason: "the line was rewritten", head: null };
    last = a.hash;
  }
  return { ok: true, total, broken_at: null, reason: null, head: total ? last : null };
}

/**
 * Entries with every second author added to `authors`, in memory only. An
 * attest is not authorship: the agent that re-derived an entry is its
 * checker, and is never folded in.
 */
export async function withAttestations(sandboxRoot: string, entries: LedgerEntry[]): Promise<LedgerEntry[]> {
  const attested = (await readAttestations(sandboxRoot)).filter((a) => attestationAct(a) === "same_content");
  if (!attested.length) return entries;
  const extra = new Map<number, string[]>();
  for (const a of attested) extra.set(a.seq, [...(extra.get(a.seq) ?? []), a.by]);
  return entries.map((e) => {
    const more = (extra.get(e.seq) ?? []).filter((b) => !e.authors.includes(b));
    return more.length ? { ...e, authors: [...e.authors, ...more] } : e;
  });
}

/** Each job: ref whose job did not end ok, with the job's status. */
export async function refsOnFailedJobs(sandboxRoot: string, refs: string[]): Promise<Array<{ ref: string; job: string; status: string }>> {
  const out: Array<{ ref: string; job: string; status: string }> = [];
  const seen = new Map<string, string | null>();
  for (const ref of refs) {
    const m = /^job:(j\d{6})\//.exec(ref);
    if (!m) continue;
    if (!seen.has(m[1])) {
      const job = await readFile(join(sandboxRoot, "store", "jobs", m[1], "job.json"), "utf8").then((t) => JSON.parse(t) as { status?: string }).catch(() => null);
      seen.set(m[1], job?.status ?? null);
    }
    const status = seen.get(m[1]);
    if (status && status !== "ok") out.push({ ref, job: m[1], status });
  }
  return out;
}

function mdCell(text: string | undefined): string {
  return (text ?? "").replace(/\|/g, "\\|").replace(/\r?\n/g, " ");
}

/** ledger/ledger.md: the timeline in time order, the indicators, the findings. */
export async function renderLedger(sandboxRoot: string, entries?: LedgerEntry[]): Promise<string> {
  const all = await withAttestations(sandboxRoot, entries ?? (await readLedger(sandboxRoot)));
  const events = all.filter((e) => e.kind === "event").sort((a, b) => (a.ts ?? "").localeCompare(b.ts ?? "") || a.seq - b.seq);
  const iocs = all.filter((e) => e.kind === "ioc");
  const findings = all.filter((e) => e.kind === "finding");
  const absences = all.filter((e) => e.kind === "absence");
  const hypotheses = all.filter((e) => e.kind === "hypothesis");
  const limitations = all.filter((e) => e.kind === "limitation");
  const answers = all.filter((e) => e.kind === "answer");
  const coverages = all.filter((e) => e.kind === "coverage");
  const replaced = supersededBy(all);
  const contradictions = standingContradictions(all);
  // Who re-derived an entry, and who disputes it: read beside the ledger, never written into it.
  const allAttestations = await readAttestations(sandboxRoot);
  const attests = allAttestations.filter((a) => attestationAct(a) === "attest");
  const disputes = disputesInForce(all, await readDisputes(sandboxRoot));
  const problems = answers.length ? answerProblems(all, await readDisputes(sandboxRoot)) : new Map<number, string[]>();
  const lines: string[] = [
    "# Ledger",
    "",
    `${all.length} entries: ${events.length} events, ${iocs.length} indicators, ${findings.length} findings, ${absences.length} searches that found nothing${hypotheses.length ? `, ${hypotheses.length} hypotheses` : ""}${limitations.length ? `, ${limitations.length} limitations` : ""}${coverages.length ? `, ${coverages.length} coverage records` : ""}${answers.length ? `, ${answers.length} answers` : ""}${replaced.size ? `; ${replaced.size} corrected by a later entry, which stands` : ""}${contradictions.length ? `; ${contradictions.length} standing contradiction${contradictions.length === 1 ? "" : "s"}` : ""}. Written by the harness from \`record\`, \`attest\` and \`dispute\`; cite it as \`ledger/ledger.md\`.`,
    "",
  ];
  const acts = (e: LedgerEntry) => {
    const h = e.hash ?? ledgerHash(e, "genesis");
    const by = attests.filter((a) => a.target === h).map((a) => `${a.by}${a.strength === "best_candidate" ? " (best candidate)" : ""}`);
    const against = disputes.filter((d) => d.target === h);
    return `${by.length ? ` [attested by ${[...new Set(by)].join(", ")}]` : ""}${against.length ? ` **[disputed by ${against.map((d) => `${d.by}: ${mdCell(d.why)}${d.inherited_from !== undefined ? ` (raised on #${d.inherited_from}, which it corrects; open until answered)` : ""}`).join("; ")}]**` : ""}`;
  };
  // A corrected entry stays where it was, marked; its correction says what it corrects.
  const mark = (e: LedgerEntry) =>
    `${replaced.has(e.seq) ? ` **(superseded by #${replaced.get(e.seq)})**` : ""}${e.supersedes !== undefined ? ` (corrects #${e.supersedes}${e.because ? `: ${mdCell(e.because)}` : ""})` : ""}${ledgerFieldsText(e)}${acts(e)}`;
  lines.push("## Timeline", "", "| # | Time (UTC) | Event | Source | Evidence | By |", "| --- | --- | --- | --- | --- | --- |");
  // A time the source gave with an offset (or as a date) is shown as written too.
  const asWritten = (e: LedgerEntry) => (e.ts_raw && !/[Zz]$/.test(e.ts_raw) && !(e.precision === "date" && e.ts_raw === (e.ts ?? "").slice(0, 10)) ? ` (as written: ${mdCell(e.ts_raw)})` : "");
  // A date alone is shown as a date; the clock the time came from beside it.
  const when = (e: LedgerEntry) => `${e.precision === "date" ? (e.ts ?? "").slice(0, 10) : e.ts}${asWritten(e)}${e.clock ? ` · clock: ${mdCell(e.clock)}` : ""}${e.precision && e.precision !== "date" ? ` · precision: ${e.precision}` : ""}`;
  // The objects an entry rests on, with its evidence.
  const ev = (e: LedgerEntry) => `${mdCell(e.evidence)}${e.refs?.length ? ` · refs: ${mdCell(e.refs.join(", "))}` : ""}${e.locators?.length ? ` · at: ${mdCell(e.locators.map((l) => `${l.ref} ${l.at}`).join("; "))}` : ""}`;
  for (const e of events) lines.push(`| ${e.seq} | ${when(e)} | ${mdCell(e.value)}${mark(e)} | ${mdCell(e.source)} | ${ev(e)} | ${e.authors.join(", ")} |`);
  lines.push("", "## Indicators", "", "| # | Indicator | Source | Evidence | Confidence | By |", "| --- | --- | --- | --- | --- | --- |");
  for (const e of iocs) lines.push(`| ${e.seq} | ${mdCell(e.value)}${mark(e)} | ${mdCell(e.source)} | ${ev(e)} | ${e.confidence ?? ""} | ${e.authors.join(", ")} |`);
  lines.push("", "## Findings", "");
  for (const e of findings) {
    lines.push(`- **#${e.seq}** ${e.value}${mark(e)}${e.confidence ? ` _(${e.confidence})_` : ""}${e.source ? ` — source: ${e.source}` : ""}${e.evidence ? ` — evidence: ${e.evidence}` : ""}${e.refs?.length ? ` — refs: ${e.refs.map((r) => `\`${r}\``).join(", ")}` : ""}${interpretationText(e)} — by ${e.authors.join(", ")}`);
  }
  if (answers.length) {
    // The swarm's answers, each with what it rests on; one stands per section.
    lines.push("", "## Answers", "");
    for (const e of answers) {
      const cites = (label: string, edges?: LedgerEdge[]) => (edges?.length ? ` — ${label}: ${edges.map((x) => `E-${x.seq}`).join(", ")}` : "");
      const p = problems.get(e.seq);
      const r = NB.answerResult(e);
      const neg = r && NB.NEGATIVE_RESULTS.has(r) && e.section?.startsWith("question:") ? negativeReview(e, all, allAttestations) : null;
      const negText = neg ? (neg.reviewed ? ` (negative, reviewed by ${neg.by.join(", ")})` : " **(negative, unreviewed)**") : "";
      lines.push(
        `- **#${e.seq}** ${e.section}${e.question_rev ? ` (revision ${e.question_rev})` : ""}${e.inconclusive ? " (inconclusive)" : ""}${e.result ? ` (${e.result})` : ""}${e.asserts_absence ? " (asserts absence)" : ""}${negText}: ${e.value}${mark(e)}${e.confidence ? ` _(${e.confidence}${e.confidence_why ? `: ${e.confidence_why}` : ""})_` : ""}${cites("rests on", e.support)}${cites("contrary", e.contrary)}${e.contrary_none_why ? ` — nothing says otherwise: ${e.contrary_none_why}` : ""}${cites("limitations", e.limitations)}${e.qualifies?.length ? ` — qualifies: ${e.qualifies.map((q) => `${q.ref} (${q.why})`).join("; ")}` : ""}${e.alternatives_open ? ` — still open: ${e.alternatives_open}` : ""}${e.would_change ? ` — would change it: ${e.would_change}` : ""}${e.unsupported_tokens?.length ? ` — in none of the cited entries: ${e.unsupported_tokens.join(", ")}` : ""}${p?.length ? ` — **no longer stands on its support: ${p.join("; ")}**` : ""}${e.parts?.length ? ` — parts: ${PM.partsWords(e.parts)}` : ""}${e.premises?.length ? ` — premises: ${PM.citationsWords(e.premises)}` : ""}${e.premise_tested ? ` — ${premiseTestWords(e.premise_tested)}` : ""} — reasoning: ${e.reasoning ?? ""} — by ${e.authors.join(", ")}`,
      );
    }
  }
  if (hypotheses.length) {
    lines.push("", "## Hypotheses", "", "| # | Hypothesis | Status | Source | Evidence | By |", "| --- | --- | --- | --- | --- | --- |");
    for (const e of hypotheses) lines.push(`| ${e.seq} | ${mdCell(e.value)}${mark(e)} | ${e.status ?? "open"} | ${mdCell(e.source)} | ${ev(e)} | ${e.authors.join(", ")} |`);
  }
  // Searched and not found: what, where, and how far. Each holds for that
  // query and that scope only.
  lines.push("", "## Searched, not found", "", "| # | Looked for | Searched | Query, tool, scope | By |", "| --- | --- | --- | --- | --- |");
  for (const e of absences) lines.push(`| ${e.seq} | ${mdCell(e.value)}${mark(e)} | ${mdCell(e.source)} | ${ev(e)} | ${e.authors.join(", ")} |`);
  const externals = all.filter((e) => e.kind === "external");
  if (externals.length) {
    // What entered from outside the evidence, with where from: a capture's hash proves its bytes, not their truth.
    lines.push("", "## External material", "", "| # | What | Class | From | Provenance | By |", "| --- | --- | --- | --- | --- | --- |");
    for (const e of externals) lines.push(`| ${e.seq} | ${mdCell(e.value)}${mark(e)} | ${e.source_class ?? ""} | ${mdCell(e.provenance?.from ?? e.source)} | ${ev(e)}${e.provenance?.sha256 ? ` · sha256 ${e.provenance.sha256}` : ""} | ${e.authors.join(", ")} |`);
  }
  if (limitations.length) {
    lines.push("", "## Limitations", "", "| # | Not established | Reason | Scope | What was tried | By |", "| --- | --- | --- | --- | --- | --- |");
    for (const e of limitations) lines.push(`| ${e.seq} | ${mdCell(e.value)}${mark(e)} | ${e.reason ?? ""} | ${mdCell(e.source)} | ${ev(e)} | ${e.authors.join(", ")} |`);
  }
  if (coverages.length) {
    // What each negative was searched over, what the hub found the jobs were given, and who reviewed it.
    lines.push("", "## Coverage records", "");
    const SW = await import("./store-sweep.ts");
    const sweeps = await SW.readSweeps(sandboxRoot).catch(() => [] as SweepRecord[]);
    for (const e of coverages) {
      const neg = negativeReview(e, all, allAttestations);
      const looked = e.looked_for?.length ? ` — looked for: ${e.looked_for.map((t) => `"${mdCell(t)}"`).join(", ")}; ${mdCell(SW.sweepWords(SW.sweepOf({ hash: e.hash ?? ledgerHash(e, "genesis") }, sweeps), e))}` : e.looked_for_none_why ? ` — no literal form to look for: ${e.looked_for_none_why}` : "";
      lines.push(
        `- **#${e.seq}** for ${(e.answers ?? []).map((a) => `question:${a}`).join(", ")}: proposition: ${e.value}${mark(e)} — objects: ${(e.refs ?? []).map((r) => `\`${r}\``).join(", ")} — time range: ${e.time_range ?? ""} — method: ${e.search_method ?? ""} (settings: ${e.settings ?? ""}) — covered: ${e.coverage_actual ?? ""} — skipped: ${e.skipped ?? ""} — failures: ${e.failures ?? ""} — results: ${(e.result_refs ?? []).join(", ")} — alternatives: ${e.alternatives_open ?? ""} — detection opportunity: trace expected ${e.detection_opportunity?.trace_expected ?? "?"}, ${e.detection_opportunity?.why ?? ""} — inventory ${e.inventory_rev ?? "?"} — **coverage ${e.coverage ?? "not computed"}**${e.coverage_detail?.why.length ? ` (${e.coverage_detail.why.join("; ")})` : ""}${e.not_examined?.length ? ` — planned routes not examined: ${e.not_examined.map((r) => `${r.source} (${r.method}): ${r.why}`).join("; ")}` : ""}${looked} — ${neg.reviewed ? `reviewed by ${neg.by.join(", ")}: ${neg.reviews.map((x) => NB.reviewWords(x.review)).join(" / ")}` : "**unreviewed**"} — by ${e.authors.join(", ")}`,
      );
    }
  }
  if (contradictions.length) {
    // Weighed: an answer holds both, one as contrary evidence, or a limitation names both.
    const open = new Set(openContradictions(all).map((c) => `${c.from}:${c.to}`));
    lines.push("", "## Standing contradictions", "");
    for (const c of contradictions) lines.push(`- #${c.from} contradicts #${c.to}; both stand${open.has(`${c.from}:${c.to}`) ? "" : " (weighed in an answer or named by a limitation)"}`);
  }
  const text = lines.join("\n") + "\n";
  await mkdir(join(sandboxRoot, LEDGER_DIR), { recursive: true });
  await writeFile(join(sandboxRoot, LEDGER_MD), text, "utf8");
  return text;
}

/**
 * A finding's version 4 fields as a tail for a rendered line: what it
 * indicates, why that confidence, what else could explain it, why a failed
 * job's bytes still hold, and how its objects were made. A finding written
 * before version 4 says its interpretation was not recorded.
 */
export function interpretationText(e: LedgerEntry): string {
  if (e.kind !== "finding") return "";
  if (!e.indicates && (e.v ?? 1) < 4) return " — interpretation not recorded";
  const parts: string[] = [];
  if (e.indicates) parts.push(`indicates: ${e.indicates}`);
  if (e.confidence_why) parts.push(`why that confidence: ${e.confidence_why}`);
  if (e.alternatives?.length) parts.push(`alternatives: ${e.alternatives.map((a) => `${a.explanation} (${a.status}: ${a.why}${a.test_refs?.length ? `; tested with ${a.test_refs.join(", ")}` : ""})`).join("; ")}`);
  if (e.alternatives_none_why) parts.push(`no alternative considered: ${e.alternatives_none_why}`);
  if (e.significance) parts.push(`significance: ${e.significance}`);
  if (e.qualifies?.length) parts.push(`from a job that did not succeed: ${e.qualifies.map((q) => `${q.ref} (${q.why})`).join("; ")}`);
  if (e.method?.length) parts.push(`made by: ${e.method.map(methodText).join("; ")}`);
  return parts.map((p) => ` — ${p}`).join("");
}

/** One method record in a line: the job, what it ran, where, and how it ended. */
export function methodText(m: LedgerMethod): string {
  const what = m.tool ? `tool ${String(m.tool)}` : m.recipe ? `recipe ${String(m.recipe)}` : m.command !== undefined ? `command \`${String(m.command)}\`` : m.source ? `import of ${String(m.source)} (${String(m.produced_by ?? "producer unknown")})` : m.job_kind ? String(m.job_kind) : String(m.kind ?? "object");
  return `${m.job ? `job ${String(m.job)}: ` : m.import ? `import ${String(m.import)}: ` : ""}${what}${m.image ? ` in ${String(m.image)} (${String(m.image_digest ?? "digest unknown")})` : ""}${m.status ? `, ${String(m.status)}` : ""}`;
}

/** The typed fields of an entry, as a short tail for a rendered line. */
export function ledgerFieldsText(e: LedgerEntry): string {
  const parts: string[] = [];
  if (e.answers?.length) parts.push(`answers ${e.answers.join(", ")}`);
  if (e.rel?.length) parts.push(e.rel.map((r) => `${r.kind.replace("_", " ")} #${r.to}`).join(", "));
  if (e.basis) parts.push(e.basis);
  if (e.completion && e.completion !== "complete") parts.push(`search ${e.completion}`);
  if (e.attribution) parts.push(`attributed to ${e.attribution.subject} (${e.attribution.subject_type})`);
  if (e.sensitive) parts.push("sensitive");
  return parts.length ? ` [${mdCell(parts.join("; "))}]` : "";
}

/** Pairs where one standing entry says it contradicts another standing entry. */
export function standingContradictions(entries: LedgerEntry[]): Array<{ from: number; to: number }> {
  const replaced = supersededBy(entries);
  const out: Array<{ from: number; to: number }> = [];
  for (const e of entries) {
    if (replaced.has(e.seq)) continue;
    for (const r of e.rel ?? []) if (r.kind === "contradicts" && !replaced.has(r.to) && entries.some((x) => x.seq === r.to)) out.push({ from: e.seq, to: r.to });
  }
  return out;
}

export async function listLedger(sandboxRoot: string, filter: { kind?: string; limit?: number } = {}): Promise<LedgerEntry[]> {
  const all = await withAttestations(sandboxRoot, await readLedger(sandboxRoot));
  const kind = (filter.kind ?? "").trim().toLowerCase();
  const picked = kind ? all.filter((e) => e.kind === kind) : all;
  const limit = Math.max(1, Math.min(500, Number(filter.limit) || 200));
  // A corrected entry is listed with the entry that corrects it; every entry
  // with who re-derived it and who disputes it; an answer with what keeps it
  // from standing on its support, when anything does.
  const replaced = supersededBy(all);
  const attests = (await readAttestations(sandboxRoot)).filter((a) => attestationAct(a) === "attest");
  const allDisputes = await readDisputes(sandboxRoot);
  const disputes = disputesInForce(all, allDisputes);
  const problems = all.some((e) => e.kind === "answer") ? answerProblems(all, allDisputes) : new Map<number, string[]>();
  return picked.slice(-limit).map((e) => {
    const h = e.hash ?? ledgerHash(e, "genesis");
    const by = [...new Set(attests.filter((a) => a.target === h).map((a) => a.by))];
    const against = disputes.filter((d) => d.target === h).map((d) => ({ by: d.by, why: d.why, ...(d.inherited_from !== undefined ? { inherited_from: d.inherited_from } : {}) }));
    return {
      ...e,
      ...(replaced.has(e.seq) ? { superseded_by: replaced.get(e.seq) } : {}),
      ...(by.length ? { attested_by: by } : {}),
      ...(against.length ? { disputed_by: against } : {}),
      ...(problems.has(e.seq) ? { problems: problems.get(e.seq) } : {}),
    };
  });
}

// ---------------------------------------------------------------------------
// Interpretation, answers and the acts on them (ledger version 4).
//
// A finding says what it indicates; an `answer` is the swarm's answer to one
// question of the goal (or its summary, or its narrative), resting on the
// entries it cites by hash. A critic other than the author re-derives what an
// answer rests on and says so with `attest`, or says why not with `dispute`;
// both are hub-written, each in its own chain beside the ledger. Whether a
// run may end is the goal's to say: its check reads the answers (the ledger
// gate below, run by scripts/check-answers.ts), refuses a done that leaves a
// mechanical defect, names the fix, and lets the next done through once a
// limitation names each defect that is left. Nothing here judges whether an
// answer is right: that is the critic's and the examiner's.
// ---------------------------------------------------------------------------

/** A goal section id as an answer names it: "3", "Q3" and "question:3" are question:3; summary and narrative are themselves. */
export function answerSection(raw: string): { ok: true; section: string; id: string } | { ok: false; reason: string } {
  const text = String(raw ?? "").trim();
  const lower = text.toLowerCase();
  if ((LEDGER_SECTION_SPECIAL as readonly string[]).includes(lower)) return { ok: true, section: lower, id: lower };
  const id = sectionKey(lower.startsWith("question:") ? text.slice("question:".length) : text);
  if (!id || !LEDGER_ANSWER_ID.test(id) || (LEDGER_SECTION_SPECIAL as readonly string[]).includes(id.toLowerCase())) {
    return { ok: false, reason: `section is question:<id> (the goal's question, "question:3"), summary or narrative (got ${JSON.stringify(text)})` };
  }
  return { ok: true, section: `question:${id}`, id };
}

/**
 * The questions a brief numbers: the distinct numbers that open a line
 * (`1.`, `1)`, `1:`, `Q1`, `Question 1`, `**1.**`, `### 1.`), in the order
 * they first appear; the same count the goals' awk takes of inputs/CASE.md.
 */
export function briefQuestions(text: string): string[] {
  const out: string[] = [];
  for (const line of text.split("\n")) {
    const m = /^(#+ *)?(\*\* *)?([Qq](uestion)? *[0-9]+|[0-9]+[.):]([ *]|$))/.exec(line);
    if (!m) continue;
    const n = String(Number(m[0].replace(/[^0-9]/g, "")));
    if (!out.includes(n)) out.push(n);
  }
  return out;
}

/** A section id as the goal numbers it: "3", "Q3" and "q3" are section 3. */
export function sectionKey(id: string): string {
  // Q-19, the question register's id, is question:19 too.
  return String(id ?? "").trim().replace(/^q-?(?=\d)/i, "");
}

/** The goal id a section's entries name in `answers`: 3 for question:3, summary, narrative. */
export function sectionAnswersId(section: string): string {
  return section.startsWith("question:") ? section.slice("question:".length) : section;
}

/** The entries a text cites as E-<seq>, and every seq of a range E-12–E-15 (at most 50 a range). */
export function answerCitations(text: string): number[] {
  const out = new Set<number>();
  for (const m of String(text ?? "").matchAll(/\bE-(\d{1,5})(?:\s*[–-]\s*E-?(\d{1,5}))?\b/g)) {
    const a = Number(m[1]);
    const b = m[2] ? Number(m[2]) : a;
    if (b >= a && b - a <= 50) for (let n = a; n <= b; n += 1) out.add(n);
    else out.add(a);
  }
  return [...out].filter((n) => n > 0);
}

/** A list of seqs as an agent writes them: 12, "12", "#12", "E-12", or one string of them. */
function seqList(name: string, v: Array<number | string> | string | undefined): { ok: true; seqs: number[] } | { ok: false; reason: string } {
  const items = Array.isArray(v) ? v.map(String) : String(v ?? "").split(/[\s,]+/);
  const out: number[] = [];
  for (const raw of items.map((x) => x.trim()).filter(Boolean)) {
    const n = Number(raw.replace(/^(?:#|E-)/i, ""));
    if (!Number.isInteger(n) || n < 1) return { ok: false, reason: `${name} names entries by seq (12, "#12" or "E-12"; got ${JSON.stringify(raw)})` };
    if (!out.includes(n)) out.push(n);
  }
  return { ok: true, seqs: out };
}

/** Where a chain of corrections from `seq` ends: the entry that stands. */
export function standingSeq(seq: number, replaced: Map<number, number>): number {
  let at = seq;
  for (let i = 0; i < 10_000 && replaced.has(at); i += 1) at = replaced.get(at) as number;
  return at;
}

/** The seqs a limitation names: its links, and each E-<seq> in what it says. */
export function limitationCites(e: LedgerEntry): Set<number> {
  const out = new Set<number>((e.rel ?? []).map((r) => r.to));
  for (const n of answerCitations(`${e.value}\n${e.source ?? ""}\n${e.evidence ?? ""}`)) out.add(n);
  return out;
}

// --- the token check ------------------------------------------------------------------------

/**
 * The specifics an answer's text asserts that a reader could look up: hashes,
 * paths (and registry keys), times, inodes, addresses and accounts. Each is
 * kept as written and normalised for matching: hex lower-case; a path's
 * separators as "/", its case folded and a drive letter dropped; a time to
 * the second, in UTC when it says its zone (a date alone, or a time to the
 * minute, matches any time within it); an NTFS `inode-type-id` by its first
 * number. Token matching finds omissions, never entailment: a token in no
 * cited entry is marked, never refused, and a legitimate transformation
 * (a conversion, a sum) needs its derivation recorded as an entry.
 */
export type AnswerToken = { kind: "hash" | "path" | "time" | "inode" | "ip" | "account"; text: string; norm: string };

const TOKEN_TIME = /\b(\d{4})-(\d{2})-(\d{2})(?:[T ](\d{2}):(\d{2})(?::(\d{2})(?:\.\d+)?)?\s?(Z|z|UTC|[+-]\d{2}:?\d{2})?)?(?![\d:])/g;

function normalizeTokenTime(m: RegExpMatchArray): string | null {
  const [, y, mo, d, h, mi, sec, zone] = m;
  if (Number(mo) < 1 || Number(mo) > 12 || Number(d) < 1 || Number(d) > 31) return null;
  if (h === undefined) return `${y}-${mo}-${d}`;
  const naive = `${y}-${mo}-${d}T${h}:${mi}${sec !== undefined ? `:${sec}` : ""}`;
  if (!zone) return naive;
  const z = /^(z|utc)$/i.test(zone) ? "Z" : zone.length === 5 ? `${zone.slice(0, 3)}:${zone.slice(3)}` : zone;
  const ms = Date.parse(`${y}-${mo}-${d}T${h}:${mi}:${sec ?? "00"}${z}`);
  if (!Number.isFinite(ms)) return naive;
  const iso = new Date(ms).toISOString();
  return sec !== undefined ? iso.slice(0, 19) : iso.slice(0, 16);
}

function normalizePathText(text: string): string {
  return text.toLowerCase().replace(/\\+/g, "/").replace(/\/{2,}/g, "/").replace(/(^|[\s"'`(=])[a-z]:(?=\/)/g, "$1").replace(/\/$/, "");
}

/** The tokens of a text, each once by its normalised form, in the order they first appear. */
export function answerTokens(text: string): AnswerToken[] {
  const found: Array<{ at: number; t: AnswerToken }> = [];
  const add = (at: number, t: AnswerToken) => found.push({ at, t });
  const src = String(text ?? "");
  for (const m of src.matchAll(TOKEN_TIME)) {
    const norm = normalizeTokenTime(m);
    if (norm) add(m.index ?? 0, { kind: "time", text: m[0].trim(), norm });
  }
  for (const m of src.matchAll(/(?<![0-9A-Za-z])(?:[0-9a-fA-F]{128}|[0-9a-fA-F]{64}|[0-9a-fA-F]{40}|[0-9a-fA-F]{32})(?![0-9A-Za-z])/g)) add(m.index ?? 0, { kind: "hash", text: m[0], norm: m[0].toLowerCase() });
  for (const m of src.matchAll(/(?<![\d.])(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(?:\.(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}(?![\d.]*\d)/g)) add(m.index ?? 0, { kind: "ip", text: m[0], norm: m[0] });
  // An IPv6 address: eight groups, or fewer with one "::"; a time of day is not one.
  for (const m of src.matchAll(/(?<![\w:.])[0-9a-fA-F]{0,4}(?::[0-9a-fA-F]{0,4}){2,7}(?![\w:])/g)) {
    const v = m[0];
    const gaps = (v.match(/::/g) ?? []).length;
    const groups = v.split(":");
    if (gaps > 1 || (gaps === 0 && groups.length !== 8) || v.includes(":::") || v === "::") continue;
    if (gaps === 0 && groups.some((g) => !g)) continue;
    if (/^\d{1,2}(:\d{2}){1,2}$/.test(v)) continue;
    add(m.index ?? 0, { kind: "ip", text: v, norm: v.toLowerCase() });
  }
  // A SID's numbers are not an inode's: masked before inodes are read.
  const unSid = src.replace(/\bS-1-\d{1,3}(?:-\d{1,12}){1,14}\b/gi, (x) => " ".repeat(x.length));
  for (const m of unSid.matchAll(/\b(\d{1,12})-(\d{1,5})-(\d{1,5})\b/g)) {
    if (/^\d{4}$/.test(m[1]) && /^\d{2}$/.test(m[2]) && /^\d{2}$/.test(m[3])) continue;
    add(m.index ?? 0, { kind: "inode", text: m[0], norm: String(Number(m[1])) });
  }
  for (const m of src.matchAll(/\binode\s*[#:=]?\s*(\d{1,12})\b/gi)) add(m.index ?? 0, { kind: "inode", text: m[0], norm: String(Number(m[1])) });
  for (const m of src.matchAll(/\b[\w.+-]+@[\w-]+(?:\.[\w-]+)+\b/g)) add(m.index ?? 0, { kind: "account", text: m[0], norm: m[0].toLowerCase() });
  for (const m of src.matchAll(/\bS-1-\d{1,3}(?:-\d{1,12}){1,14}\b/gi)) add(m.index ?? 0, { kind: "account", text: m[0], norm: m[0].toUpperCase() });
  // Paths (and registry keys): a word with a separator that is rooted (a
  // drive, a UNC share, /, ~), has two separators or ends in an extension;
  // one backslash between two names is an account (DOMAIN\user). A URL,
  // an E-<seq> pair and a number like 03/20/2024 are none of them.
  for (const m of src.matchAll(/[^\s"'`<>|,;()[\]{}]+/g)) {
    const v = m[0].replace(/^[*_]+/, "").replace(/[*_]+$/, "").replace(/[.:!?]+$/, "");
    if (!/[\\/]/.test(v) || v.includes("://") || /^E-\d/i.test(v)) continue;
    const segs = v.split(/[\\/]+/).filter(Boolean);
    if (!segs.length || segs.every((x) => /^\d+$/.test(x))) continue;
    const seps = (v.match(/[\\/]/g) ?? []).length;
    const rooted = /^(?:[A-Za-z]:[\\/]|\\\\|\/|~\/)/.test(v);
    const ext = /\.[A-Za-z0-9]{1,8}$/.test(segs.at(-1) ?? "");
    if (!rooted && seps < 2 && !ext) {
      if (seps === 1 && /^[A-Za-z][\w.-]*\\[A-Za-z][\w.$-]*$/.test(v)) add(m.index ?? 0, { kind: "account", text: v, norm: v.toLowerCase().replace(/\\/g, "/") });
      continue;
    }
    add(m.index ?? 0, { kind: "path", text: v, norm: normalizePathText(v) });
  }
  const seen = new Set<string>();
  const out: AnswerToken[] = [];
  for (const { t } of found.sort((a, b) => a.at - b.at)) {
    const key = `${t.kind}\u0000${t.norm}`;
    if (seen.has(key)) continue;
    seen.add(key);
    out.push(t);
  }
  return out;
}

/** Every string an entry holds, but who wrote it, when, and the chain's own hashes. */
function entryText(e: LedgerEntry): string {
  const skip = new Set(["by", "authors", "at", "prev", "hash", "support", "contrary", "limitations", "unsupported_tokens", "v", "seq", "kind"]);
  const parts: string[] = [];
  const walk = (v: unknown) => {
    if (typeof v === "string") parts.push(v);
    else if (typeof v === "number") parts.push(String(v));
    else if (Array.isArray(v)) v.forEach(walk);
    else if (v && typeof v === "object") for (const [k, x] of Object.entries(v)) walk(x);
  };
  for (const [k, v] of Object.entries(e)) if (!skip.has(k)) walk(v);
  return parts.join("\n");
}

/**
 * The tokens of an answer's text that none of the entries it rests on holds.
 * An answer cited by another lends its own cited entries, never its text: a
 * token an answer asserted without support does not become supported by
 * being repeated in a summary.
 */
export function unsupportedTokens(text: string, cited: LedgerEntry[], bySeq: Map<number, LedgerEntry>): string[] {
  const pool: LedgerEntry[] = [];
  const seen = new Set<number>();
  const visit = (e: LedgerEntry | undefined) => {
    if (!e || seen.has(e.seq)) return;
    seen.add(e.seq);
    if (e.kind === "answer") for (const x of [...(e.support ?? []), ...(e.contrary ?? []), ...(e.limitations ?? [])]) visit(bySeq.get(x.seq));
    else pool.push(e);
  };
  for (const e of cited) visit(e);
  const raw = pool.map(entryText).join("\n");
  const flat = normalizePathText(raw);
  const lower = raw.toLowerCase();
  const poolTokens = answerTokens(raw);
  const times = poolTokens.filter((t) => t.kind === "time").map((t) => t.norm);
  for (const e of pool) if (e.ts) times.push(e.ts.slice(0, 19));
  const word = (hay: string, needle: string) => new RegExp(`(?<![\\w.])${needle.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")}(?![\\w])`).test(hay);
  const out: string[] = [];
  for (const t of answerTokens(text)) {
    let ok = false;
    if (t.kind === "time") ok = times.some((x) => x.startsWith(t.norm));
    else if (t.kind === "hash") ok = lower.includes(t.norm);
    else if (t.kind === "path") ok = flat.includes(t.norm);
    else if (t.kind === "inode") ok = word(raw, t.norm);
    else if (t.kind === "ip") ok = word(lower, t.norm);
    else ok = flat.includes(t.norm) || lower.includes(t.norm) || raw.toUpperCase().includes(t.norm);
    if (!ok) out.push(t.text);
  }
  return out;
}

// --- disputes -------------------------------------------------------------------------------

/**
 * A line of ledger/disputes.jsonl: an agent other than an entry's authors
 * says why the entry does not hold (`dispute`), or takes that back
 * (`withdraw`, its own dispute only). The why is inside the hashed record;
 * the chain is the file's own.
 */
export type LedgerDispute = { v: 1; act: "dispute" | "withdraw"; seq: number; target: string; by: string; at: string; why: string; refs?: string[]; prev?: string; hash?: string };

export function disputeHash(d: LedgerDispute, prev: string): string {
  const core = JSON.stringify({ v: d.v, act: d.act, seq: d.seq, target: d.target, by: d.by, at: d.at, why: d.why, ...(d.refs?.length ? { refs: d.refs } : {}) });
  return createHash("sha256").update(`${prev}\n${core}`).digest("hex");
}

export async function readDisputes(sandboxRoot: string): Promise<LedgerDispute[]> {
  const text = await readFile(join(sandboxRoot, LEDGER_DISPUTES), "utf8").catch(() => "");
  const out: LedgerDispute[] = [];
  for (const line of text.split("\n")) {
    if (!line.trim()) continue;
    try {
      out.push(JSON.parse(line) as LedgerDispute);
    } catch {
      // a torn line is left for the chain check to name
    }
  }
  return out;
}

/** The disputes' own chain: each line names the one before it; an unknown version or act is refused. */
export function verifyDisputeChain(text: string): { ok: boolean; total: number; broken_at: number | null; reason: string | null; head: string | null } {
  let last = "genesis";
  let total = 0;
  for (const line of text.split("\n")) {
    if (!line.trim()) continue;
    total += 1;
    let d: LedgerDispute;
    try {
      d = JSON.parse(line) as LedgerDispute;
    } catch {
      return { ok: false, total, broken_at: total, reason: "not json", head: null };
    }
    if (d.v !== 1) return { ok: false, total, broken_at: total, reason: `a dispute of version ${JSON.stringify(d.v)}, which this harness does not know`, head: null };
    if (d.act !== "dispute" && d.act !== "withdraw") return { ok: false, total, broken_at: total, reason: `a dispute line whose act is ${JSON.stringify(d.act)}`, head: null };
    if (d.prev !== last) return { ok: false, total, broken_at: total, reason: "prev does not name the line before it", head: null };
    if (d.hash !== disputeHash(d, last)) return { ok: false, total, broken_at: total, reason: "the line was rewritten", head: null };
    last = d.hash;
  }
  return { ok: true, total, broken_at: null, reason: null, head: total ? last : null };
}

/** The disputes that stand: each not withdrawn since by the agent that raised it. */
export function standingDisputes(disputes: LedgerDispute[]): LedgerDispute[] {
  const open = new Map<string, LedgerDispute>();
  for (const d of disputes) {
    const key = `${d.target}\u0000${d.by}`;
    if (d.act === "dispute") open.set(key, d);
    else open.delete(key);
  }
  return [...open.values()];
}

/** A dispute in force: one that stands, on the entry it names or, when that entry was corrected, on the correction that stands in its place (inherited_from names the entry it was raised on). */
export type DisputeInForce = LedgerDispute & { inherited_from?: number };

/**
 * The disputes in force. A correction may fix a disputed entry, but the
 * dispute stays open until it is answered: the disputer withdraws it once
 * the correction answers what it said. Until then it stands on the
 * correction that stands in the entry's place (on Belka two limitations
 * were superseded over a standing objection, and the answer and summary
 * that rested on them fell with nobody told why). Each standing dispute on
 * the entry it names, and each whose entry was superseded again on the
 * head of its chain of corrections, marked inherited_from.
 */
export function disputesInForce(entries: LedgerEntry[], disputes: LedgerDispute[]): DisputeInForce[] {
  const standing = standingDisputes(disputes);
  if (!standing.length) return [];
  const replaced = supersededBy(entries);
  if (!replaced.size) return standing;
  const bySeq = new Map(entries.map((e) => [e.seq, e]));
  const byHash = new Map(entries.map((e) => [e.hash ?? ledgerHash(e, "genesis"), e]));
  const out: DisputeInForce[] = [...standing];
  for (const d of standing) {
    const e = byHash.get(d.target);
    if (!e || !replaced.has(e.seq)) continue;
    const head = bySeq.get(standingSeq(e.seq, replaced));
    if (!head || head.seq === e.seq) continue;
    out.push({ ...d, target: head.hash ?? ledgerHash(head, "genesis"), inherited_from: e.seq });
  }
  return out;
}

/** A dispute in force, in words: who, why, and the entry it was raised on when it is inherited. */
export function disputeWords(d: DisputeInForce): string {
  return `${d.by} (${d.why})${d.inherited_from !== undefined ? ` raised on E-${d.inherited_from}, which it corrects, and not yet answered` : ""}`;
}

// --- attest and dispute ---------------------------------------------------------------------

export type LedgerActInput = { seq?: number | string; how?: string; why?: string; refs?: string[] | string; withdraw?: boolean; review?: unknown; strength?: unknown; answer_review?: unknown; second_review_why?: string };

/** The standing entries an answer cites that were recorded for its own question (`id`, its section key). */
export function citedForQuestion(a: LedgerEntry, bySeq: Map<number, LedgerEntry>, replaced: Map<number, number>, id: string): LedgerEntry[] {
  return (a.support ?? []).map((x) => bySeq.get(x.seq)).filter((e): e is LedgerEntry => Boolean(e) && !replaced.has((e as LedgerEntry).seq) && ((e as LedgerEntry).answers ?? []).some((x) => sectionKey(x) === id));
}

/**
 * Whether an answer's result makes it a negative the bar holds (the finish
 * gate's own test): a bounded negative, not determinable, or a premise
 * rejected on a search alone, where none of the standing entries it cites
 * for its question (`cited`, citedForQuestion) is a finding that shows the
 * premise false.
 */
export function negativeByResult(result: string | null, cited: LedgerEntry[]): boolean {
  return Boolean(result && (NB.NEGATIVE_RESULTS.has(result) || (result === "premise_not_supported" && !cited.some((e) => e.kind === "finding"))));
}

/** Whether an entry is a negative the review bar holds: a coverage record, or an answer bounded_negative or not_determinable. */
/** Whether an entry can show that a part is at the limit of the evidence: a coverage record, or a limitation whose reason is unavailable or excluded. */
export function limitBoundKind(e: LedgerEntry): boolean {
  return e.kind === "coverage" || (e.kind === "limitation" && (e.reason === "unavailable" || e.reason === "excluded"));
}

export function isNegativeEntry(e: LedgerEntry): boolean {
  if (e.kind === "coverage") return true;
  const r = NB.answerResult(e);
  return r !== null && NB.NEGATIVE_RESULTS.has(r) && Boolean(e.section?.startsWith("question:"));
}
export type LedgerActResult<T> = ({ ok: true; line: T; appended: boolean; note?: string } & WarningsDelivered) | { ok: false; reason: string };

/** The entry an act names, standing, and not the actor's own. */
function actTarget(entries: LedgerEntry[], raw: number | string | undefined, agentId: string, act: string): { ok: true; entry: LedgerEntry } | { ok: false; reason: string } {
  const n = Number(String(raw ?? "").trim().replace(/^(?:#|E-)/i, ""));
  if (!Number.isInteger(n) || n < 1) return { ok: false, reason: `${act} names an entry by its seq (12, "#12" or "E-12"; got ${JSON.stringify(raw)})` };
  const entry = entries.find((e) => e.seq === n);
  if (!entry) return { ok: false, reason: `there is no entry #${n} in the ledger (list them with ledger)` };
  const replaced = supersededBy(entries);
  if (replaced.has(n)) return { ok: false, reason: `#${n} is superseded by #${standingSeq(n, replaced)}: ${act} the entry that stands` };
  if (entry.by === agentId || entry.authors.includes(agentId)) {
    return { ok: false, reason: act === "attest" ? `#${n} is yours (you recorded it, or the same words): an attestation is somebody else re-deriving it` : `#${n} is yours: correct it with record(supersedes=${n}) instead of disputing it` };
  }
  return { ok: true, entry };
}

/**
 * Why a review can hold an answer to a question only as a best candidate
 * (B2), each in words: its confidence is medium or low; the review says a
 * part the question asks is not established; or its would_change names a
 * route nothing took: a planned route of the question (lead_open routes)
 * that no job under it examined, named by its source, or a lead (L-<n>)
 * that is not closed resolved, negative or duplicate. Read from the
 * registers and the refs; the answer's words are only searched for the
 * route sources and lead ids themselves. Empty when nothing caps it.
 *
 * A partial answer claims part of the question established and declares
 * the rest open, so its review attests those claims: a part the review
 * holds not established caps it only when the answer does not declare that
 * part open (the part names, in declared_open, a limitation or a coverage
 * record the answer cites: declaredOpenBy). Its confidence does not cap it,
 * nor do the routes its would_change names, which are how its open parts
 * would be settled: the answer already says they are open. The cap stays
 * whole for an answer that claims established (claimsEstablished), and for
 * any other that is not a negative.
 */
export async function strengthCaps(sandboxRoot: string, answer: LedgerEntry, review: AnswerReview | null, entries?: LedgerEntry[]): Promise<string[]> {
  const out: string[] = [];
  if (NB.answerResult(answer) === "partial") {
    const all = entries ?? (await readLedger(sandboxRoot));
    const open = declaredOpenBy(answer, new Map(all.map((e) => [e.seq, e])));
    // A part the answer's own rows hold open (premises.ts AnswerPart, status open), weighed by its id, is declared open too.
    const openRows = new Set((answer.parts ?? []).filter((p) => p.status === "open").map((p) => p.id));
    const limitedRows = new Set((answer.parts ?? []).filter((p) => p.status === "limited").map((p) => p.id));
    for (const p of review?.parts ?? []) {
      if (p.established || p.not_asked || (p.declared_open && open.has(p.declared_open)) || (p.id && openRows.has(p.id)) || (p.at_limit && p.id && limitedRows.has(p.id))) continue;
      out.push(p.missing ? `the review names "${p.part}", a part of the question the answer leaves out (${p.why})` : `the review holds "${p.part}" not established (${p.why}), and the answer does not declare it open${p.declared_open ? ` (${p.declared_open} is not a limitation or a coverage record it cites)` : ""}`);
    }
    return out;
  }
  if (answer.confidence === "medium" || answer.confidence === "low") out.push(`its confidence is ${answer.confidence}`);
  for (const p of review?.parts ?? []) if (!p.established && !p.not_asked) out.push(p.missing ? `the review names "${p.part}", a part of the question the answer leaves out (${p.why})` : `the review holds "${p.part}" not established (${p.why})`);
  const change = String(answer.would_change ?? "");
  if (!change || !answer.section?.startsWith("question:")) return out;
  const id = sectionAnswersId(answer.section);
  const bar = await questionBar(sandboxRoot, id).catch(() => null);
  const lower = change.toLowerCase();
  for (const r of bar?.routes ?? []) {
    const src = r.source.trim();
    if (src.length < 3 || !lower.includes(src.toLowerCase())) continue;
    const ex = await NB.routeExamined(sandboxRoot, r, { jobs: bar?.jobs ?? [], objects: [] }).catch(() => ({ examined: false, how: "it could not be checked" }));
    if (!ex.examined) out.push(`would_change names ${src} (${r.method}), a planned route nothing examined (${ex.how})`);
  }
  const named = [...new Set([...change.matchAll(/\bL-([1-9]\d{0,5})\b/g)].map((m) => `L-${Number(m[1])}`))];
  if (named.length) {
    const L = await import("./leads.ts");
    const snap = await L.leadsSnapshot(sandboxRoot).catch(() => null);
    for (const lid of named) {
      const l = snap?.state.leads.get(lid);
      if (!l) continue;
      if (l.closed && ["resolved", "negative", "duplicate"].includes(l.closed.disposition)) continue;
      out.push(`would_change names ${lid}, a route not taken (${l.closed ? `closed ${l.closed.disposition}` : l.holder ? `held by ${l.holder}, open` : "open, unheld"})`);
    }
  }
  return out;
}

/**
 * Attest an entry: an agent other than its authors re-derived it and says
 * how — what it re-derived from which sealed objects, and what it only read.
 * Hub-written into ledger/attestations.jsonl (version 2, the how inside the
 * hashed record). The same agent attesting the same entry again is told so.
 */
/**
 * An attest's result: a line recorded (or found), or a negative's review
 * answered quietly because another seat reviewed it already or has it
 * offered (`deferred`, nothing recorded, no refusal).
 */
export type AttestResult = LedgerActResult<LedgerAttestation> | { ok: true; line: null; appended: false; note: string; deferred: import("./leads.ts").ReviewDeferral };

export async function attestEntry(ctx: SwarmContext, input: LedgerActInput): Promise<AttestResult> {
  const how = boundedText("how", input.how, LEDGER_ACT_MAX_CHARS);
  if (!how.ok) return how;
  if (!how.value) return { ok: false, reason: "how is required: what you re-derived, from which sealed object (job:<id>/<path>, input:<path>, …), and what you only read" };
  const refs = listOf(input.refs);
  if (refs.length > LEDGER_MAX_REFS) return { ok: false, reason: `refs names more than ${LEDGER_MAX_REFS} objects` };
  if (refs.length) {
    const checked = await checkRefs(ctx.sandboxRoot, refs);
    if (!checked.ok) return checked;
    const use = await materialUseRefusal(ctx.sandboxRoot, refs);
    if (use) return { ok: false, reason: use };
  }
  const secondWhy = boundedText("second_review_why", input.second_review_why, LEDGER_ACT_MAX_CHARS);
  if (!secondWhy.ok) return secondWhy;
  let review: NB.NegativeReview | null = null;
  if (input.review !== undefined && input.review !== null) {
    const r = NB.checkReview(input.review);
    if (!r.ok) return r;
    review = r.review;
  }
  const strengthText = String(input.strength ?? "").trim().toLowerCase().replace(/-/g, "_");
  if (strengthText && !(ATTEST_STRENGTHS as readonly string[]).includes(strengthText)) return { ok: false, reason: `strength is established or best_candidate (got ${JSON.stringify(input.strength)})` };
  const strength = (strengthText || undefined) as AttestStrength | undefined;
  let answerReview: AnswerReview | null = null;
  if (input.answer_review !== undefined && input.answer_review !== null) {
    const r = checkAnswerReview(input.answer_review);
    if (!r.ok) return r;
    answerReview = r.review;
  }
  // What caps a review at best_candidate is read before the lock: the route
  // plan and the jobs under the question (the lead register), never the
  // answer's words beyond the refs and lead ids its would_change names.
  const pre = await readLedger(ctx.sandboxRoot);
  const preTarget = actTarget(pre, input.seq, ctx.agentId, "attest");
  const preAnswer = preTarget.ok && preTarget.entry.kind === "answer" && preTarget.entry.section?.startsWith("question:") && !isNegativeEntry(preTarget.entry) ? preTarget.entry : null;
  const caps = preAnswer ? await strengthCaps(ctx.sandboxRoot, preAnswer, answerReview, pre) : [];
  // The objects a discriminator and a premise test rest on resolve (their entries are checked under the lock, with the alternatives').
  for (const [name, refs] of [["answer_review.discriminator.refs", answerReview?.discriminator?.refs ?? []], ["answer_review.premise_tested.refs", answerReview?.premise_tested?.refs ?? []]] as const) {
    const objects = refs.filter((r) => !/^E-\d+$/.test(r));
    if (!objects.length) continue;
    const checked = await checkRefs(ctx.sandboxRoot, objects);
    if (!checked.ok) return { ok: false, reason: `${name}: ${checked.reason}` };
  }
  // The source-first evidence of an established review (docs/adr/0015): read before the lock, bounded reads at the locators' offsets.
  // What the question presumes is read here too (docs/adr/0011, "What a question presumes"): its premise is one of the rivals the review tests.
  const preBar = preAnswer && answerReview ? await questionBar(ctx.sandboxRoot, sectionAnswersId(preAnswer.section!)).catch(() => null) : null;
  const evidence = preAnswer && answerReview && (strength === "established" || answerReview.reproduced_at?.length || answerReview.derivation) ? await reviewEvidenceCaps(ctx.sandboxRoot, preAnswer, answerReview, { material: preBar?.material ?? true, entries: pre, presumption: preBar?.presumption ?? null }) : null;
  // The negatives a review recorded here answers (the answer itself, or those resting on the coverage record): their offers are taken up after the lock.
  const reviewed: string[] = [];
  const result = await withTableLock(ctx.sandboxRoot, async (held): Promise<AttestResult> => {
    const entries = await readLedger(ctx.sandboxRoot);
    const t = actTarget(entries, input.seq, ctx.agentId, "attest");
    if (!t.ok) return t;
    const target = t.entry.hash ?? ledgerHash(t.entry, "genesis");
    // An answer to a question is attested with how strongly the review holds
    // it, and the review part by part (B2): a best candidate you cannot break
    // is still a best candidate. A medium or low confidence, a part not
    // established, or a route its would_change names that nothing took
    // allows only best_candidate, which does not satisfy the finish line on
    // an answer that claims established. A partial answer's review attests
    // its own claims: a part it declares open does not cap it (strengthCaps).
    const questionAnswer = t.entry.kind === "answer" && Boolean(t.entry.section?.startsWith("question:")) && !isNegativeEntry(t.entry);
    // The entries an alternative is ruled out by are in the ledger.
    if (answerReview && Array.isArray(answerReview.alternatives)) {
      const seqs = new Set(entries.map((e) => e.seq));
      for (const a of answerReview.alternatives) {
        const missing = (a.evidence ?? []).find((r) => !seqs.has(Number(r.slice(2))));
        if (missing) return { ok: false, reason: `answer_review.alternatives[].evidence names ${missing}: there is no entry #${missing.slice(2)} in the ledger` };
      }
    }
    if (answerReview?.discriminator) {
      const seqs = new Set(entries.map((e) => e.seq));
      const refs = answerReview.discriminator.refs;
      const missing = refs.find((r) => /^E-\d+$/.test(r) && !seqs.has(Number(r.slice(2))));
      if (missing) return { ok: false, reason: `answer_review.discriminator.refs names ${missing}: there is no entry #${missing.slice(2)} in the ledger` };
      // The test that separates the rival rests on its own observation: never the answer under review, nor only what the answer already cites (the Fable review of the limits branch, P3-7).
      const self = refs.find((r) => /^E-\d+$/.test(r) && Number(r.slice(2)) === t.entry.seq);
      if (self) return { ok: false, reason: `answer_review.discriminator.refs names ${self}, the answer under review: a discriminator rests on an observation or a job, not the answer. Name the E-<seq> of what the test showed, or the job:<id>/<path> it read` };
      const cited = answerCites(t.entry, supersededBy(entries));
      if (refs.every((r) => /^E-\d+$/.test(r) && cited.has(Number(r.slice(2))))) return { ok: false, reason: `answer_review.discriminator.refs names only ${refs.join(", ")}, which #${t.entry.seq} cites already: the test that separates the rival from the answer rests on what it read or showed. Name the job:<id>/<path> the test read, or the E-<seq> of an observation the answer does not cite (record what the test showed first, if it is not on the ledger)` };
    }
    // A premise test rests on an observation or a job the ledger holds, never on the answer under review.
    if (answerReview?.premise_tested) {
      const seqs = new Set(entries.map((e) => e.seq));
      const refs = answerReview.premise_tested.refs;
      const missing = refs.find((r) => /^E-\d+$/.test(r) && !seqs.has(Number(r.slice(2))));
      if (missing) return { ok: false, reason: `answer_review.premise_tested.refs names ${missing}: there is no entry #${missing.slice(2)} in the ledger` };
      const self = refs.find((r) => /^E-\d+$/.test(r) && Number(r.slice(2)) === t.entry.seq);
      if (self) return { ok: false, reason: `answer_review.premise_tested.refs names ${self}, the answer under review: a premise test rests on what the test read or showed. Name the E-<seq> of that observation, or the job:<id>/<path> it read` };
    }
    // An established review names the alternatives it weighed and why the
    // evidence rules each out; one that names none is recorded a best
    // candidate, and the reply says so (nothing is refused).
    let recorded = strength;
    const downgraded: string[] = [];
    // Each source-first cap with how to fix it, for the reply.
    const downgradeFixes: string[] = [];
    // "A best candidate" concerns only an answer that claims established
    // (claimsEstablished); on a disposition that only limits the run it
    // holds nothing, and the replies say so.
    const claim = claimsEstablished(t.entry);
    const resultNow = NB.answerResult(t.entry);
    const holdsNothing = `#${t.entry.seq} is ${NB.resultWords(resultNow)}, a disposition held to its own bar, so a best candidate holds nothing on it ("best candidate" concerns only an answer that claims established)`;
    if (questionAnswer) {
      if (!strength) return { ok: false, reason: `#${t.entry.seq} answers ${t.entry.section}: its attest says how strongly you hold it, strength established or best_candidate, with answer_review {reproduced, read, parts: [{part, established, why}], inference, alternatives, other_family: {checked, text}}` };
      if (!answerReview) return { ok: false, reason: `#${t.entry.seq} answers ${t.entry.section}: give answer_review {reproduced (what you re-derived yourself), read (what you only read), parts (each part the question asks, established or not, and why), inference (what connects the observations to the answer), alternatives (what the evidence still allows), other_family {checked, text} (whether another source family was checked, or why not)}` };
      // A part a partial answer declares open names the entry that declares it: a limitation it cites, or a coverage record it rests on.
      const declared = answerReview.parts.filter((p) => p.declared_open);
      if (declared.length && resultNow !== "partial") {
        return { ok: false, reason: `answer_review.parts[].declared_open is for a partial answer's part the answer itself declares open; #${t.entry.seq} is ${NB.resultWords(resultNow)}${claim ? ": it claims every part established, and a part you do not hold established caps the review" : ""}` };
      }
      // Against an answer that carries parts (docs/adr/0013, "Claim and open-part rows"): a review part names the row it weighs by its id, and may add a part the answer leaves out (missing). A review part without an id is read as it always was.
      const rows = t.entry.parts ?? [];
      const byId = answerReview.parts.filter((p) => p.id);
      if (byId.length && !rows.length) return { ok: false, reason: `#${t.entry.seq} carries no parts: answer_review.parts[].id names an answer's part (${byId[0]!.id}), and this answer lists none. Weigh each part the question asks without an id, and a part the answer leaves out with missing: true` };
      const stray = byId.find((p) => !rows.some((r) => r.id === p.id));
      if (stray) return { ok: false, reason: `#${t.entry.seq} carries parts ${rows.map((r) => r.id).join(", ")}: answer_review.parts[].id names one of them (got ${stray.id} for "${stray.part}"); a part the answer leaves out is a row of its own, with missing: true and no id` };
      const twice = rows.map((r) => r.id).find((id) => byId.filter((p) => p.id === id).length > 1);
      if (twice) return { ok: false, reason: `answer_review.parts weighs ${twice} twice: one row per part` };
      if (declared.length) {
        const open = declaredOpenBy(t.entry, new Map(entries.map((e) => [e.seq, e])));
        const bad = declared.find((p) => !open.has(p.declared_open as string));
        if (bad) return { ok: false, reason: `answer_review.parts[].declared_open names ${bad.declared_open} for "${bad.part}": #${t.entry.seq} declares a part open by a limitation it cites or a coverage record it rests on, and it cites ${open.size ? [...open].join(", ") : "none"}. Name the one that declares that part open, or hold the part not established without it (a part the answer claims established that you do not hold so caps the review)` };
      }
      if (strength === "established" && caps.length) {
        return {
          ok: false,
          reason:
            resultNow === "partial"
              ? `#${t.entry.seq} is partial: its review attests the answer's own claims, the parts it holds established and the parts it declares open, and ${caps.join("; ")}. A part the answer declares open names, in declared_open, the limitation or coverage record by which it does; a part it claims established that you do not hold so is a dispute (dispute #${t.entry.seq}, why, refs) or a best_candidate attest. ${holdsNothing}`
              : `#${t.entry.seq} can be attested best_candidate only: ${caps.join("; ")}. Attest it best_candidate (${claim ? "it does not satisfy the finish line" : `on it that holds nothing: ${holdsNothing}`}), or take the route and record what it shows`,
        };
      }
      if (strength === "established" && !reviewNamesAlternative(answerReview)) {
        recorded = "best_candidate";
        downgraded.push(NO_ALTERNATIVE_CAP);
      }
      // Source-first (docs/adr/0015): an established review of an answer
      // that claims established, on a material question, names the
      // strongest rival and the test that separates it, and says where it
      // read the values it vouches for (a locator the hub verifies against
      // the sealed bytes) or how they were derived. What it lacks is
      // recorded, the attest is a best candidate, and the reply says how.
      if (strength === "established" && evidence?.caps.length) {
        recorded = "best_candidate";
        for (const c of evidence.caps) {
          downgraded.push(c.why);
          downgradeFixes.push(`${c.why}: ${REVIEW_CAP_FIX[c.code]}`);
        }
      }
    } else if (answerReview) {
      return { ok: false, reason: `answer_review is for an answer to a question; #${t.entry.seq} is ${isNegativeEntry(t.entry) ? "a negative: its attest is a review {detection, reproduced, other_route}" : t.entry.kind === "answer" ? `the ${t.entry.section} (say in how what you re-derived)` : `a ${t.entry.kind}: say in how what you re-derived`}` };
    } else if (strength && !(t.entry.kind === "answer" && t.entry.section?.startsWith("question:"))) {
      return { ok: false, reason: `strength is for an answer to a question; #${t.entry.seq} is ${t.entry.kind === "answer" ? `the ${t.entry.section}` : `a ${t.entry.kind}`}` };
    }
    // A negative is attested with its review: what was challenged, reproduced or tried, or why not.
    const negative = isNegativeEntry(t.entry);
    if (negative && !review) {
      return {
        ok: false,
        reason: `#${t.entry.seq} is a ${t.entry.kind === "coverage" ? "coverage record" : `negative answer (${NB.resultWords(NB.answerResult(t.entry))})`}: its attest is a review. Give review {detection: {done, text}, reproduced: {done, text}, other_route: {done, text}}: whether you challenged the detection assumptions, reproduced a decisive check, tried a materially different route, each with what you did or why not`,
      };
    }
    // A limitation that says the evidence is gone or left out may carry one too: it is what a limited part rests on (docs/adr/0013, "A part at the limit of the evidence").
    if (!negative && review && !limitBoundKind(t.entry)) return { ok: false, reason: `review is for a negative (a coverage record, or an answer bounded_negative or not_determinable) or for a limitation whose reason is unavailable or excluded (what a limited part rests on); #${t.entry.seq} is a ${t.entry.kind}${t.entry.kind === "limitation" ? ` whose reason is ${t.entry.reason ?? "not given"}` : ""}: say in how what you re-derived` };
    if (negative && t.entry.kind === "answer") {
      // Whoever recorded a coverage record the answer rests on is not its reviewer either.
      const bySeq = new Map(entries.map((e) => [e.seq, e]));
      const covAuthors = (t.entry.support ?? []).map((x) => bySeq.get(x.seq)).filter((e): e is LedgerEntry => e?.kind === "coverage").flatMap((e) => e.authors);
      if (covAuthors.includes(ctx.agentId)) return { ok: false, reason: `you recorded the coverage record #${t.entry.seq} rests on: a review of a negative is another seat's` };
    }
    const mineAgainst = disputesInForce(entries, await readDisputes(ctx.sandboxRoot)).find((d) => d.target === target && d.by === ctx.agentId);
    if (mineAgainst) {
      return { ok: false, reason: mineAgainst.inherited_from !== undefined ? `you disputed #${mineAgainst.inherited_from}, which #${t.entry.seq} corrects, and the dispute stands on the correction until you answer it: withdraw it (dispute withdraw=true on #${t.entry.seq}, with why the correction answers it) before attesting` : `you dispute #${t.entry.seq}: withdraw the dispute (dispute withdraw=true, with why) before attesting it` };
    }
    const attested = await readAttestations(ctx.sandboxRoot);
    // One review of a negative (the c10 pilot's stampede): offered to one
    // seat; another seat's review of a negative reviewed already, or
    // offered to another now, is answered quietly with who has it and
    // records nothing. A second, independent review says why it adds
    // something (second_review_why).
    if (negative && review && !secondWhy.value) {
      const answers = t.entry.kind === "answer" ? [t.entry] : negativesResting(t.entry, entries);
      const L = await import("./leads.ts");
      const disputes = await readDisputes(ctx.sandboxRoot);
      let deferral: import("./leads.ts").ReviewDeferral | null = null;
      for (const a of answers) {
        const nr = negativeReview(a, entries, attested, disputes);
        const d = await L.negativeReviewDeferral(ctx.sandboxRoot, `E-${a.seq}`, ctx.agentId, nr.reviewed ? nr.by : []);
        if (!d) {
          deferral = null;
          break;
        }
        deferral ??= d;
      }
      if (deferral) return { ok: true as const, line: null, appended: false as const, note: deferral.why, deferred: deferral };
    }
    // Once per seat, except a review that now holds established what this
    // seat's earlier one held a best candidate only (a route taken since,
    // the alternatives weighed): the later line is its review now.
    const mine = attested.filter((a) => attestationAct(a) === "attest" && a.target === target && a.by === ctx.agentId);
    const upgrade = questionAnswer && recorded === "established" && mine.length > 0 && !mine.some(attestEstablishes);
    if (mine.length && !upgrade) return { ok: true, line: mine.at(-1)!, appended: false, note: `you attested #${t.entry.seq} already` };
    await held.assertOwned();
    const line = await appendAttestation(ctx.sandboxRoot, attested, { v: 2, act: "attest", seq: t.entry.seq, target, by: ctx.agentId, at: new Date().toISOString(), how: how.value, ...(refs.length ? { refs } : {}), ...(review ? { review } : {}), ...(recorded ? { strength: recorded } : {}), ...(answerReview ? { answer_review: answerReview } : {}), ...(questionAnswer && (caps.length || downgraded.length) ? { capped: [...caps, ...downgraded] } : {}), ...(secondWhy.value ? { second_review_why: secondWhy.value } : {}) });
    await renderLedger(ctx.sandboxRoot);
    const noAlternative = downgraded.includes(NO_ALTERNATIVE_CAP);
    // A partial answer's locators are checked too, and what does not verify is said (partial is a disposition: nothing is capped on it).
    const unverified = !downgradeFixes.length ? (evidence?.locators ?? []).filter((v): v is Extract<LocatorVerdict, { ok: false }> => !v.ok) : [];
    const locatorNote = unverified.length || (evidence?.derivation && !evidence.derivation.ok && !downgradeFixes.length) ? ` Not verified (said: it caps only an established review of an answer that claims established): ${[...unverified.map((v) => `${v.ref} at ${v.offset}: ${v.why}`), ...(evidence?.derivation && !evidence.derivation.ok ? [`the derivation: ${evidence.derivation.why}`] : [])].join("; ")}.` : "";
    const note = review
      ? `recorded as the review of a negative: ${NB.reviewWords(review)}`
      : downgraded.length
        ? `you attested it established, and it is recorded as a best candidate: ${downgraded.join("; ")}. ${[...(noAlternative ? ["An established review names at least one alternative explanation you considered and why the evidence rules it out; attest again with answer_review.alternatives [{explanation, why}] once you have weighed one"] : []), ...(downgradeFixes.length ? [`A source-first review ${noAlternative ? "also " : ""}says what separates the answer from its strongest rival and where each value it vouches for is: ${downgradeFixes.join("; ")}. Attest again with them: your later attest is then your review`] : []), ...(evidence?.unlocated ? [`Warned, not capped: ${evidence.unlocated.why}; ${REVIEW_UNLOCATED_FIX}`] : [])].join(". ")}. ${claim ? `Until then ${t.entry.section} is not established by it, and the finish line says so` : holdsNothing}`
        : recorded === "best_candidate"
          ? claim
            ? `recorded as a best candidate${caps.length ? ` (${caps.join("; ")})` : ""}: ${t.entry.section} is not established by it, and the finish line says so; the way out is the route that would settle it, or the operator's acceptance of its limits`
            : `recorded as a best candidate${caps.length ? ` (${caps.join("; ")})` : ""}: ${holdsNothing}`
          : undefined;
    if (review) for (const a of t.entry.kind === "answer" ? [t.entry] : negativesResting(t.entry, entries)) reviewed.push(`E-${a.seq}`);
    const said = note || locatorNote ? `${note ?? ""}${locatorNote}`.trim() : undefined;
    return { ok: true, line, appended: true, ...(said ? { note: said } : {}) };
  });
  // Outside the ledger's lock (the registers' is taken after it, never inside): the review's offer, when it was this seat's, is taken up.
  if (result.ok && result.appended && reviewed.length) {
    const L = await import("./leads.ts");
    for (const key of reviewed) await L.reviewOfferTaken(ctx.sandboxRoot, key, ctx.agentId).catch(() => undefined);
  }
  // The warnings on what the attest bears on, delivered to the reviewer: an answer, the negatives resting on a coverage record, an entry an answer leaves out.
  return withWarnings(ctx.sandboxRoot, result, (r) => (r.line ? { point: "attest", entry: r.line.seq } : null));
}

/**
 * Why a coverage record no longer says what its search found: an entry
 * among its results that is not in the ledger, is not the entry it bound
 * (another hash), was superseded, or is disputed. A record from before
 * results were bound is held to its results as they stand. Empty when it
 * stands.
 */
export function coverageProblems(c: LedgerEntry, entries: LedgerEntry[], disputes: LedgerDispute[] = []): string[] {
  return coverageStaleness(c, entries, disputes).map((x) =>
    x.code === "missing"
      ? `its result E-${x.result} is not in the ledger`
      : x.code === "rebound"
        ? `its result E-${x.result} is not the entry it bound (the hash differs)`
        : x.code === "superseded"
          ? `its result E-${x.result} is superseded by #${x.by_seq}`
          : `its result E-${x.result} is disputed by ${x.disputes!.map(disputeWords).join("; ")}`,
  );
}

/**
 * coverageProblems as data: each result of the record that no longer stands,
 * by code (missing, rebound: another entry than the one bound, superseded,
 * disputed), with the entry that superseded it or the disputes against it.
 */
export function coverageStaleness(c: LedgerEntry, entries: LedgerEntry[], disputes: LedgerDispute[] = []): Array<{ result: number; code: "missing" | "rebound" | "superseded" | "disputed"; by_seq?: number; disputes?: DisputeInForce[] }> {
  if (c.kind !== "coverage") return [];
  const bySeq = new Map(entries.map((e) => [e.seq, e]));
  const replaced = supersededBy(entries);
  // A dispute stays in force on the correction of the entry it named (B18, disputesInForce).
  const against = disputesInForce(entries, disputes);
  const out: Array<{ result: number; code: "missing" | "rebound" | "superseded" | "disputed"; by_seq?: number; disputes?: DisputeInForce[] }> = [];
  for (const r of c.result_refs ?? []) {
    const m = /^E-(\d+)$/.exec(r);
    if (!m) continue;
    const seq = Number(m[1]);
    const e = bySeq.get(seq);
    if (!e) {
      out.push({ result: seq, code: "missing" });
      continue;
    }
    const hash = e.hash ?? ledgerHash(e, "genesis");
    const bound = c.result_bound?.find((x) => x.seq === seq);
    if (bound && bound.hash !== hash) out.push({ result: seq, code: "rebound" });
    if (replaced.has(seq)) out.push({ result: seq, code: "superseded", by_seq: standingSeq(seq, replaced) });
    const d = against.filter((x) => x.target === hash);
    if (d.length) out.push({ result: seq, code: "disputed", disputes: d });
  }
  return out;
}

/**
 * Whether a negative stands reviewed: an attest with its review, by a seat
 * that recorded neither the answer nor a coverage record it rests on, on the
 * answer or on one of those records. Who reviewed, and what they said. A
 * review is of what stood when it was made: one on a coverage record whose
 * results no longer stand counts for nothing, and neither does one on the
 * answer while any coverage record it rests on is so.
 */
export function negativeReview(
  answer: LedgerEntry,
  entries: LedgerEntry[],
  attestations: LedgerAttestation[],
  disputes: LedgerDispute[] = [],
): { reviewed: boolean; by: string[]; reviews: Array<{ by: string; seq: number; review: NB.NegativeReview }>; stale: Array<{ seq: number; problems: string[] }> } {
  const t = negativeReviewTargets(answer, entries, disputes);
  const targets = new Map<string, number>(t.targets.map((e): [string, number] => [e.hash ?? ledgerHash(e, "genesis"), e.seq]));
  // A review made before evidence was added counts for nothing on an answer
  // recorded after that evidence: it reviewed an examination that had not
  // seen it (the Fable review of batches 1-3).
  const added = evidenceAdditions(entries).filter((x) => x.seq < answer.seq).map((x) => Date.parse(x.at)).filter((n) => Number.isFinite(n));
  const since = added.length ? Math.max(...added) : null;
  const reviews = attestations.filter((a) => attestationAct(a) === "attest" && a.review && a.target && targets.has(a.target) && !t.authors.has(a.by) && (since === null || Date.parse(a.at) >= since)).map((a) => ({ by: a.by, seq: targets.get(a.target!)!, review: a.review! }));
  return { reviewed: reviews.length > 0, by: [...new Set(reviews.map((r) => r.by))], reviews, stale: t.stale };
}

/**
 * Where a negative's review counts, as the finish gate reads it
 * (negativeReview): the answer, unless a coverage record it rests on no
 * longer stands, and each standing coverage record it rests on whose
 * results still stand; who may not review it (whoever recorded the answer
 * or one of those records); and the records that no longer stand. A
 * review's offer names these, so the review it asks for is the one the
 * gate counts (the c10 pilot's reviewers went to a coverage record, or to
 * an answer already corrected). An answer resting only on records that no
 * longer stand has no target: its coverage is recorded again first.
 */
export function negativeReviewTargets(answer: LedgerEntry, entries: LedgerEntry[], disputes: LedgerDispute[] = []): { targets: LedgerEntry[]; authors: Set<string>; stale: Array<{ seq: number; problems: string[] }> } {
  const bySeq = new Map(entries.map((e) => [e.seq, e]));
  const replaced = supersededBy(entries);
  const cov = answer.kind === "coverage" ? [answer] : (answer.support ?? []).map((x) => bySeq.get(x.seq)).filter((e): e is LedgerEntry => e?.kind === "coverage" && !replaced.has(e.seq));
  const stale = cov.map((c) => ({ seq: c.seq, problems: coverageProblems(c, entries, disputes) })).filter((x) => x.problems.length);
  const standingCov = cov.filter((c) => !stale.some((x) => x.seq === c.seq));
  const authors = new Set([answer.by, ...answer.authors, ...cov.flatMap((c) => [c.by, ...c.authors])]);
  const targets = [...(stale.length && answer.kind !== "coverage" ? [] : [answer]), ...standingCov.filter((c) => c.seq !== answer.seq)];
  return { targets, authors, stale };
}

/**
 * Whether what a limited part is limited by stands reviewed (docs/adr/0013,
 * "A part at the limit of the evidence"): the bound (E-<seq>, a coverage
 * record or a limitation) stands, and a seat that recorded neither it nor
 * the answer attests it with a negative's review, as negativeReview reads
 * one (a review made before evidence was added does not count; a coverage
 * record whose results no longer stand counts for nothing). Claiming that
 * the evidence cannot settle a part costs what a negative costs.
 */
export function limitedBoundReview(answer: LedgerEntry, bound: string, entries: LedgerEntry[], attestations: LedgerAttestation[], disputes: LedgerDispute[] = []): PM.BoundReview {
  const n = /^E-(\d+)$/.exec(bound)?.[1];
  const e = n ? entries.find((x) => x.seq === Number(n)) : undefined;
  if (!e) return { reviewed: false, by: [], why: `${bound} is not in the ledger` };
  const replaced = supersededBy(entries);
  if (replaced.has(e.seq)) return { reviewed: false, by: [], why: `${bound} is superseded by #${standingSeq(e.seq, replaced)}` };
  const r = negativeReview(e, entries, attestations, disputes);
  if (r.stale.length) return { reviewed: false, by: [], why: `${bound}'s results no longer stand (${r.stale.flatMap((s) => s.problems).join("; ")})` };
  const authors = new Set([answer.by, ...answer.authors]);
  const by = r.by.filter((x) => !authors.has(x));
  return by.length ? { reviewed: true, by } : { reviewed: false, by: [], why: `no seat other than ${[...new Set([...authors, e.by, ...e.authors])].join(", ")} has reviewed ${bound} as a negative is reviewed` };
}

/** Each limited part's bound of an answer, as limitedBoundReview reads it, keyed by the bound. */
export function limitedBounds(answer: LedgerEntry, entries: LedgerEntry[], attestations: LedgerAttestation[], disputes: LedgerDispute[] = []): Map<string, PM.BoundReview> {
  const out = new Map<string, PM.BoundReview>();
  for (const p of answer.parts ?? []) if (p.status === "limited" && p.limited_by && !out.has(p.limited_by)) out.set(p.limited_by, limitedBoundReview(answer, p.limited_by, entries, attestations, disputes));
  return out;
}

/**
 * The standing answers a coverage record's review is the review of: each
 * that rests on it and is a negative by the finish gate's own test
 * (negativeByResult: a bounded negative, not determinable, or a premise
 * rejected on a search alone).
 */
export function negativesResting(cov: LedgerEntry, entries: LedgerEntry[]): LedgerEntry[] {
  const bySeq = new Map(entries.map((e) => [e.seq, e]));
  const replaced = supersededBy(entries);
  return entries.filter((e) => {
    if (e.kind !== "answer" || replaced.has(e.seq) || !e.section?.startsWith("question:") || !(e.support ?? []).some((x) => x.seq === cov.seq)) return false;
    return negativeByResult(NB.answerResult(e), citedForQuestion(e, bySeq, replaced, sectionKey(e.section.slice("question:".length))));
  });
}

/**
 * Dispute an entry: why it does not hold, with the objects that show it.
 * Or, with `withdraw`, take one's own dispute back and say why. Hub-written
 * into ledger/disputes.jsonl. An answer resting on a disputed entry is marked
 * until it is recorded again with the dispute answered.
 */
export async function disputeEntry(ctx: SwarmContext, input: LedgerActInput): Promise<LedgerActResult<LedgerDispute>> {
  const why = boundedText("why", input.why, LEDGER_ACT_MAX_CHARS);
  if (!why.ok) return why;
  if (!why.value) return { ok: false, reason: input.withdraw ? "why is required: why the dispute no longer stands" : "why is required: what does not hold, and what shows it" };
  const refs = listOf(input.refs);
  if (refs.length > LEDGER_MAX_REFS) return { ok: false, reason: `refs names more than ${LEDGER_MAX_REFS} objects` };
  if (refs.length) {
    const checked = await checkRefs(ctx.sandboxRoot, refs);
    if (!checked.ok) return checked;
    if (!input.withdraw) {
      const use = await materialUseRefusal(ctx.sandboxRoot, refs);
      if (use) return { ok: false, reason: use };
    }
  }
  return withTableLock(ctx.sandboxRoot, async (held) => {
    const entries = await readLedger(ctx.sandboxRoot);
    const t = actTarget(entries, input.seq, ctx.agentId, "dispute");
    if (!t.ok) return t;
    const target = t.entry.hash ?? ledgerHash(t.entry, "genesis");
    const all = await readDisputes(ctx.sandboxRoot);
    // A dispute stands on the correction of the entry it named until the
    // disputer answers it (B18): withdrawn by naming either entry.
    const standing = disputesInForce(entries, all).find((d) => d.target === target && d.by === ctx.agentId);
    if (input.withdraw && !standing) return { ok: false, reason: `you have no standing dispute of #${t.entry.seq} to withdraw` };
    if (!input.withdraw && standing) return { ok: true, line: standing, appended: false, note: standing.inherited_from !== undefined ? `you disputed #${standing.inherited_from}, which #${t.entry.seq} corrects, and that dispute stands on it until you withdraw it: ${standing.why}` : `you dispute #${t.entry.seq} already: ${standing.why}` };
    // A withdrawal names the dispute it ends: the entry that dispute was raised on.
    const named = standing?.inherited_from !== undefined ? entries.find((e) => e.seq === standing.inherited_from) : undefined;
    const d: LedgerDispute = { v: 1, act: input.withdraw ? "withdraw" : "dispute", seq: named ? named.seq : t.entry.seq, target: named ? (named.hash ?? ledgerHash(named, "genesis")) : target, by: ctx.agentId, at: new Date().toISOString(), why: why.value, ...(refs.length ? { refs } : {}) };
    const prev = all.at(-1)?.hash ?? "genesis";
    const line: LedgerDispute = { ...d, prev, hash: disputeHash(d, prev) };
    await held.assertOwned();
    await mkdir(join(ctx.sandboxRoot, LEDGER_DIR), { recursive: true });
    await appendFile(join(ctx.sandboxRoot, LEDGER_DISPUTES), `${JSON.stringify(line)}\n`, "utf8");
    await renderLedger(ctx.sandboxRoot);
    return { ok: true, line, appended: true };
  });
}

// --- answers --------------------------------------------------------------------------------

/** The fields an answer never takes: it rests on entries, not objects, and states no event. */
const NOT_ANSWER_FIELDS = ["ts", "refs", "answers", "rel", "clock", "precision", "basis", "status", "reason", "completion", "attribution", "locators", "indicates", "alternatives", "alternatives_none_why", "significance", ...COVERAGE_ONLY_FIELDS] as const;

/** Each ref of an entry whose job did not succeed and that the entry does not qualify itself. */
async function unqualifiedFailedRefs(sandboxRoot: string, e: LedgerEntry): Promise<string[]> {
  if (!e.refs?.length) return [];
  const { resolveRef } = await import("../scripts/evidence-store.ts");
  const out: string[] = [];
  for (const ref of e.refs) {
    if (!ref.startsWith("job:")) continue;
    const r = await resolveRef(sandboxRoot, ref).catch(() => null);
    if (r?.ok && r.status && r.status !== "ok" && !(e.qualifies ?? []).some((q) => q.ref === ref)) out.push(`${ref} (${r.status})`);
  }
  return out;
}

/**
 * What an answer concludes and rests on, as a summary's symbolic citation
 * binds it (A4): its result, the question revision it answers, and the
 * hashes of its support, its contrary evidence and its limitations. Its
 * words are not in it: a correction that only rewords keeps it.
 */
export function answerFingerprint(a: LedgerEntry): string {
  const hashes = (edges: LedgerEdge[] | undefined) => (edges ?? []).map((x) => x.hash).sort();
  const c = conclusionFields(a);
  // The keys in this order, always: a fingerprint recorded by an earlier harness is compared with this one.
  // What the answer stands on of the premises and which of its parts are open come last, and only when it has them (premises.ts): an answer without them keeps its fingerprint.
  return sha256Hex(JSON.stringify({ result: c.result, question_rev: c.question_rev, support: hashes(a.support), contrary: hashes(a.contrary), limitations: hashes(a.limitations), inconclusive: c.inconclusive, asserts_absence: c.asserts_absence, ...(c.premises ? { premises: c.premises } : {}), ...(c.parts ? { parts: c.parts } : {}) }));
}

/**
 * The conclusion fields of an entry that a rewording or a citation refresh
 * leaves alone: its result, the question revision it answers, whether it
 * is inconclusive and whether it asserts an absence (answerFingerprint
 * holds a summary's symbolic citation to these and to what the answer rests
 * on). Its words are not among them.
 */
export function conclusionFields(e: LedgerEntry): { result: string | null; question_rev: number; inconclusive: boolean; asserts_absence: boolean; premises?: Array<[string, number, string, boolean]>; parts?: Array<[string, string]> } {
  return {
    result: NB.answerResult(e) ?? null,
    question_rev: e.question_rev ?? 1,
    inconclusive: e.inconclusive === true,
    asserts_absence: e.asserts_absence === true,
    // Present only on an answer that has them: how it stands on each premise, and which of its parts are established or open.
    ...(e.premises?.length ? { premises: e.premises.map((c): [string, number, string, boolean] => [c.id, c.rev, c.stance, c.conditional === true]).sort() } : {}),
    ...(e.parts?.length ? { parts: e.parts.map((p): [string, string] => [p.id, p.status]).sort() } : {}),
  };
}

/**
 * The fields a correction of an entry other than an answer may change and
 * still conclude what it concluded: what it cites and how a reader checks
 * it (refs, evidence, source, locators, qualifies, the hub's method), why
 * it was corrected, and the record's own bookkeeping. Anything else (the
 * value, exactly; the time and its clock and precision; what a finding
 * indicates and how sure it is; an attribution; a hypothesis's status; a
 * search's completion; whether it is sensitive) is its conclusion.
 */
export const REFRESH_FIELDS: ReadonlySet<string> = new Set(["refs", "evidence", "source", "reasoning", "because", "locators", "method", "qualifies", "seq", "at", "by", "authors", "supersedes", "prev", "hash", "ts_raw", "v"]);

/**
 * Whether a correction leaves what an entry concludes as it was, so a
 * closure resting on it still holds (leads.ts reopenOnLedger re-points it
 * and says so). An answer: the same conclusion fields (conclusionFields)
 * and the same value up to case, spacing and closing punctuation. Any other
 * kind: every field outside REFRESH_FIELDS as it was, the value exactly (a
 * case can be the conclusion: an account name). A change of the kind is a
 * change of conclusion. Everything else is for the closer to confirm or
 * reopen (the Fable review of batches 1-3: a finding's indicates, an
 * event's time, a hypothesis's status re-pointed unasked).
 */
export function sameConclusion(a: LedgerEntry, b: LedgerEntry): boolean {
  if (a.kind !== b.kind) return false;
  if (a.kind === "answer") {
    const words = (v: unknown) => String(v ?? "").normalize("NFKC").toLowerCase().replace(/\s+/g, " ").trim().replace(/[.;:!]+$/, "").trim();
    return JSON.stringify(conclusionFields(a)) === JSON.stringify(conclusionFields(b)) && words(a.value) === words(b.value);
  }
  const ra = a as unknown as Record<string, unknown>;
  const rb = b as unknown as Record<string, unknown>;
  // Absent, empty and false say the same thing.
  const norm = (v: unknown) => JSON.stringify(v === undefined || v === null || v === "" || v === false || (Array.isArray(v) && !v.length) ? null : canonicalValue(v));
  for (const k of new Set([...Object.keys(ra), ...Object.keys(rb)])) {
    if (REFRESH_FIELDS.has(k)) continue;
    if (norm(ra[k]) !== norm(rb[k])) return false;
  }
  return true;
}

/** The questions a summary or a narrative names symbolically: Q-<n>, and question:<id>. */
export function symbolicQuestions(text: string): string[] {
  const out: string[] = [];
  for (const m of text.matchAll(/\bQ-([1-9]\d{0,5})\b/g)) if (!out.includes(`Q-${Number(m[1])}`)) out.push(`Q-${Number(m[1])}`);
  for (const m of text.matchAll(/\bquestion:([A-Za-z0-9._-]{1,16})\b/g)) if (!out.includes(`question:${m[1]}`)) out.push(`question:${m[1]}`);
  return out;
}

/**
 * Why each standing answer no longer stands on its own support, transitively:
 * an entry it cites was superseded and its correction is not cited with it,
 * or was disputed (or rests on a failed job) and the answer does not qualify
 * it, or is an answer that itself no longer stands; or the cited hash is not
 * the entry's. Its contrary evidence is held to the same: corrected or
 * disputed since it was weighed, the answer is weighed again. `failed` names, by seq, the entries resting on a failed job's
 * output that they do not qualify themselves.
 */
export function answerProblems(entries: LedgerEntry[], disputes: LedgerDispute[], failed: Map<number, string[]> = new Map()): Map<number, string[]> {
  const bySeq = new Map(entries.map((e) => [e.seq, e]));
  const replaced = supersededBy(entries);
  const disputed = new Map<string, DisputeInForce[]>();
  for (const d of disputesInForce(entries, disputes)) disputed.set(d.target, [...(disputed.get(d.target) ?? []), d]);
  const memo = new Map<number, string[]>();
  const visiting = new Set<number>();
  const problemsOf = (a: LedgerEntry): string[] => {
    const hit = memo.get(a.seq);
    if (hit) return hit;
    if (visiting.has(a.seq)) return [];
    visiting.add(a.seq);
    const out: string[] = [];
    const qualified = (seq: number) => (a.qualifies ?? []).some((q) => q.ref === `E-${seq}`);
    const cited = new Set([...(a.support ?? []), ...(a.contrary ?? []), ...(a.limitations ?? [])].map((x) => x.seq));
    // A summary's symbolic citations (A4): each question's standing answer,
    // held to the fingerprint it had when cited, never to its seq alone.
    for (const r of a.question_refs ?? []) {
      const now = entries.find((e) => e.kind === "answer" && e.section === r.section && !replaced.has(e.seq));
      if (!now) {
        out.push(`it cites ${r.q} (${r.section}), which has no standing answer now`);
        continue;
      }
      if (answerFingerprint(now) !== r.fp) {
        out.push(`it cites ${r.q} (${r.section}), whose answer changed its support, scope or contrary evidence since it was cited (E-${r.answer}${now.seq !== r.answer ? ` → E-${now.seq}` : ""})`);
        continue;
      }
      const sub = problemsOf(now);
      if (sub.length) out.push(`it cites ${r.q} (${r.section}), whose answer E-${now.seq} no longer stands on its own support`);
    }
    for (const [edges, role] of [[a.support ?? [], "rests on"], [a.limitations ?? [], "is bounded by"]] as const) {
      for (const edge of edges) {
        const t = bySeq.get(edge.seq);
        if (!t) {
          out.push(`it ${role} E-${edge.seq}, which is not in the ledger`);
          continue;
        }
        if ((t.hash ?? ledgerHash(t, "genesis")) !== edge.hash) {
          out.push(`it ${role} E-${edge.seq} by a hash that is not that entry's`);
          continue;
        }
        if (replaced.has(t.seq)) {
          const now = standingSeq(t.seq, replaced);
          if (!cited.has(now)) out.push(`it ${role} E-${t.seq}, superseded by #${now}, and does not cite the correction`);
          continue;
        }
        const against = disputed.get(edge.hash);
        if (against?.length && !qualified(t.seq)) out.push(`it ${role} E-${t.seq}, disputed by ${against.map(disputeWords).join("; ")}`);
        const bad = failed.get(t.seq);
        if (bad?.length && !qualified(t.seq)) out.push(`it ${role} E-${t.seq}, which rests on the kept output of a job that did not succeed (${bad.join(", ")}) and says nothing of it`);
        if (t.kind === "answer") {
          const sub = problemsOf(t);
          if (sub.length) out.push(`it ${role} E-${t.seq}, an answer that no longer stands on its own support`);
        }
      }
    }
    // The contrary evidence it weighed (A4): the weighing was of the entry
    // as it stood. Corrected since (and the correction not weighed with it)
    // or disputed (and not qualified), what the answer concludes against it
    // is to be weighed again; its fingerprint holds the hashes it cited, so
    // only its current standing shows the change.
    for (const edge of a.contrary ?? []) {
      const t = bySeq.get(edge.seq);
      if (!t) {
        out.push(`it weighs E-${edge.seq} as contrary evidence, which is not in the ledger`);
        continue;
      }
      if ((t.hash ?? ledgerHash(t, "genesis")) !== edge.hash) {
        out.push(`it weighs E-${edge.seq} as contrary evidence by a hash that is not that entry's`);
        continue;
      }
      if (replaced.has(t.seq)) {
        const now = standingSeq(t.seq, replaced);
        if (!cited.has(now)) out.push(`it weighs E-${t.seq} as contrary evidence, superseded by #${now}, and does not weigh the correction`);
        continue;
      }
      const against = disputed.get(edge.hash);
      if (against?.length && !qualified(t.seq)) out.push(`it weighs E-${t.seq} as contrary evidence, disputed by ${against.map(disputeWords).join("; ")}`);
    }
    visiting.delete(a.seq);
    memo.set(a.seq, out);
    return out;
  };
  const result = new Map<number, string[]>();
  for (const e of entries) {
    if (e.kind !== "answer" || replaced.has(e.seq)) continue;
    const p = problemsOf(e);
    if (p.length) result.set(e.seq, p);
  }
  return result;
}

/** Who asked a question section, when a person did (the question register): their words for the refusal, or null. */
async function personsQuestion(sandboxRoot: string, sectionId: string): Promise<string | null> {
  const Q = await import("./questions.ts");
  const snap = await Q.questionsSnapshot(sandboxRoot);
  const q = snap.bySection.get(sectionId);
  if (!q || !Q.HUMAN_ORIGINS.has(q.origin.kind)) return null;
  return `${q.id}, asked by ${Q.originWords(q.origin)}`;
}

/** A question section's register id and current revision, or null when the register has no question for it. */
async function registerRevision(sandboxRoot: string, sectionId: string): Promise<{ id: string; rev: number } | null> {
  const Q = await import("./questions.ts");
  const q = (await Q.questionsSnapshot(sandboxRoot)).bySection.get(sectionId);
  return q ? { id: q.id, rev: q.rev } : null;
}

/**
 * A register id (Q-9) as the section it answers: its number, or the goal's
 * own id when the goal numbers it otherwise ("bonus"). Other ids pass.
 */
async function registerSection(sandboxRoot: string, raw: string): Promise<string> {
  const m = /^(question:)?Q-([1-9]\d{0,5})$/i.exec(String(raw ?? "").trim());
  if (!m) return raw;
  const Q = await import("./questions.ts");
  const q = (await Q.questionsSnapshot(sandboxRoot)).state.questions.get(`Q-${Number(m[2])}`);
  return q ? `${m[1] ?? ""}${q.section}` : raw;
}

/**
 * What the negative bar needs to know of a question section: whether it is
 * material (the goal's always are; a register question says), whether it
 * asks whether something exists (the goal's --existence, or the register's
 * expects), whether it asks for a complete set (the register's completeness:
 * the asker's, or its words, "every", "all", "each", "complete list"), its
 * route plan (every route the leads under it planned), and the jobs run under
 * those leads. Read from the registers.
 */
export async function questionBar(sandboxRoot: string, sectionId: string): Promise<{ material: boolean; existence: boolean; completeness: boolean; routes: NB.Route[]; jobs: string[]; question: string | null; presumption: PM.Presumption | null }> {
  const L = await import("./leads.ts");
  const snap = await L.leadsSnapshot(sandboxRoot);
  const id = sectionKey(sectionId);
  const q = snap.questions?.bySection.get(id) ?? null;
  const goal = snap.goal.questions.map(sectionKey).includes(id);
  const material = goal || !q ? true : q.materiality === "material";
  const existence = snap.goal.existence.map(sectionKey).includes(id) || q?.expects === "existence";
  const routes: NB.Route[] = [];
  const jobs: string[] = [];
  for (const l of snap.state.leads.values()) {
    if (!l.answers.some((a) => sectionKey(a) === id)) continue;
    for (const r of l.routes ?? []) if (!routes.some((x) => x.source === r.source && x.method === r.method)) routes.push(r);
    for (const j of l.jobs) if (!jobs.includes(j)) jobs.push(j);
  }
  // What the question presumes (docs/adr/0011, "What a question presumes"): its presumes, or a person's question's framing.
  const Q = await import("./questions.ts");
  const presumption = q ? Q.questionPresumption(q, snap.state) : null;
  return { material, existence, completeness: q?.completeness === true, routes, jobs, question: q?.id ?? null, presumption };
}

/**
 * Record a coverage record (recordEntry with kind=coverage): what a negative,
 * or a "not determinable", was searched over. Every field is required, each
 * may say "none" with why; the hub adds the inventory revision, whether the
 * jobs behind it were given every object it names (coverage complete or
 * partial, with each unit and how), and the planned routes of its questions
 * that nothing examined. A record is about questions: it names them in
 * answers, and an answer cites it.
 */
async function recordCoverage(ctx: SwarmContext, input: LedgerInput): Promise<LedgerResult> {
  const raw = input as Record<string, unknown>;
  const notHere = [...ANSWER_ONLY_FIELDS.filter((f) => f !== "alternatives_open"), "indicates", "alternatives_none_why", "significance", "status", "reason", "completion", "ts", "clock", "precision", "basis", "attribution", "locators"].find((f) => given(raw[f]) && !(f === "alternatives" && typeof raw[f] === "string"));
  if (notHere) return { ok: false, reason: `${notHere} is not a coverage record's: it says what a search covered, and the entries it rests on say what was found` };
  const proposition = String(input.proposition ?? "").trim();
  const said = String(input.value ?? "").trim();
  if (proposition && said && proposition !== said) return { ok: false, reason: "value and proposition are the same field on a coverage record (the proposition searched): give one" };
  const value = proposition || said;
  if (!value) return { ok: false, reason: "proposition (or value) is required: the proposition the search tested, in one sentence (\"the account signed in from outside the office network\")" };
  if (value.length > LEDGER_VALUE_MAX_CHARS) return { ok: false, reason: `the proposition is over ${LEDGER_VALUE_MAX_CHARS} characters` };
  const text = (name: string, v: unknown, required = true): { ok: true; value: string } | { ok: false; reason: string } => {
    const t = boundedText(name, v, NB.COVERAGE_TEXT_MAX);
    if (!t.ok) return t;
    if (required && !t.value) return { ok: false, reason: `${name} is required on a coverage record${name === "skipped" || name === "failures" ? ' ("none" when nothing was, with how that is known)' : ""}` };
    return t;
  };
  const timeRange = text("time_range", input.time_range);
  if (!timeRange.ok) return timeRange;
  const method = text("search_method", input.search_method);
  if (!method.ok) return method;
  const settings = text("settings", input.settings);
  if (!settings.ok) return settings;
  const actual = text("coverage_actual", input.coverage_actual);
  if (!actual.ok) return actual;
  const skipped = text("skipped", input.skipped);
  if (!skipped.ok) return skipped;
  const failures = text("failures", input.failures);
  if (!failures.ok) return failures;
  const alternatives = text("alternatives", typeof raw.alternatives === "string" ? raw.alternatives : input.alternatives_open);
  if (!alternatives.ok) return { ok: false, reason: alternatives.reason.replace("alternatives is required", "alternatives is required: the explanations or routes still open, or none and why") };
  const d = (input.detection_opportunity ?? {}) as { trace_expected?: unknown; why?: unknown };
  const expected = String(d.trace_expected ?? "").trim().toLowerCase();
  if (!(NB.TRACE_EXPECTED as readonly string[]).includes(expected)) return { ok: false, reason: "detection_opportunity is {trace_expected: yes | no | unknown, why}: would the event have left a trace in these sources, given what was collected and what they keep, and why" };
  const dWhy = text("detection_opportunity.why", d.why);
  if (!dWhy.ok) return dWhy;
  // The areas the search reached, when it names them: a completeness claim
  // ("every file", "all connections") rests on a record that does.
  let areas: NB.CoverageAreas | undefined;
  if (given(raw.areas)) {
    const a = NB.checkAreas(raw.areas);
    if (!a.ok) return a;
    areas = a.areas;
    if (Object.values(areas).includes("skipped") && /^none\b/i.test(skipped.value)) return { ok: false, reason: `areas says ${NB.COVERAGE_AREAS.filter((k) => areas![k] === "skipped").join(", ")} skipped, and skipped says none: say in skipped what was not searched and why` };
  }
  // The ask for a source the evidence does not hold, or why none was opened.
  const askRaw = String(input.acquisition_ask ?? "").trim();
  const noAsk = text("acquisition_none_why", input.acquisition_none_why, false);
  if (!noAsk.ok) return noAsk;
  if (askRaw && noAsk.value) return { ok: false, reason: "acquisition_ask names the ask opened, acquisition_none_why says why none was: give one" };
  let acquisitionAsk: string | undefined;
  if (askRaw) {
    const m = /^R-?([1-9]\d{0,6})$/i.exec(askRaw);
    if (!m) return { ok: false, reason: `acquisition_ask names an acquisition request, R-<n> (got ${JSON.stringify(askRaw)}): open one with lead_close needs_operator and ask {kind: acquisition, …}` };
    acquisitionAsk = `R-${Number(m[1])}`;
    const R = await import("./requests.ts");
    const req = (await R.requestsSnapshot(ctx.sandboxRoot).catch(() => null))?.requests.get(acquisitionAsk) ?? null;
    if (!req) return { ok: false, reason: `acquisition_ask ${acquisitionAsk} is not a request of this run: open it with lead_close needs_operator and ask {kind: acquisition, source, where, expected_value, urgency}` };
    if (req.kind !== "acquisition") return { ok: false, reason: `acquisition_ask ${acquisitionAsk} is a ${req.kind} request, not an acquisition` };
  }
  // What a hit would contain, were the answer in the evidence: the hub
  // sweeps every output the run holds for it (store-sweep.ts). Or why no
  // literal form exists.
  const SW = await import("./store-sweep.ts");
  const lookedRaw = raw.looked_for;
  const lookedList = (Array.isArray(lookedRaw) ? lookedRaw : given(lookedRaw) ? [lookedRaw] : []).map((t) => String(t ?? "").trim());
  const lookedNone = text("looked_for_none_why", input.looked_for_none_why, false);
  if (!lookedNone.ok) return lookedNone;
  if (lookedList.length && lookedNone.value) return { ok: false, reason: "looked_for names the strings a hit would contain, looked_for_none_why says why there are none: give one" };
  if (!lookedList.length && !lookedNone.value) {
    return { ok: false, reason: `looked_for is required on a coverage record: the literal strings a hit would contain if the answer were in the evidence (names, identifiers, addresses, keywords), at least one, each ${SW.SWEEP_TERM_MIN} to ${SW.SWEEP_TERM_MAX} characters; the hub searches every output the run already holds for them (job outputs, imports, tool-output/), not only the objects named here. When no literal form exists, say why in looked_for_none_why` };
  }
  const lookedFor: string[] = [];
  for (const t of lookedList) {
    if (t.length < SW.SWEEP_TERM_MIN) return { ok: false, reason: `looked_for ${JSON.stringify(t)} is shorter than ${SW.SWEEP_TERM_MIN} characters: a string that short matches everything; name what a hit would contain` };
    if (t.length > SW.SWEEP_TERM_MAX) return { ok: false, reason: `a looked_for string is over ${SW.SWEEP_TERM_MAX} characters: name the distinctive part a hit would contain; nothing is cut, so a longer one is refused` };
    if (!lookedFor.some((x) => x.toLowerCase() === t.toLowerCase())) lookedFor.push(t);
  }
  if (lookedFor.length > SW.SWEEP_MAX_TERMS) return { ok: false, reason: `looked_for names more than ${SW.SWEEP_MAX_TERMS} strings: keep the ones a hit would contain` };
  const source = boundedText("source", input.source, LEDGER_SOURCE_MAX_CHARS);
  if (!source.ok) return source;
  const evidence = boundedText("evidence", input.evidence, LEDGER_EVIDENCE_MAX_CHARS);
  if (!evidence.ok) return evidence;
  const answers = listOf(input.answers);
  if (!answers.length) return { ok: false, reason: 'answers is required on a coverage record: the questions its search was for ("3", "Q-19")' };
  if (answers.length > LEDGER_MAX_ANSWERS) return { ok: false, reason: `answers names more than ${LEDGER_MAX_ANSWERS} sections` };
  const badAnswer = answers.find((a) => !LEDGER_ANSWER_ID.test(a));
  if (badAnswer) return { ok: false, reason: `answers takes the questions' section ids (got ${JSON.stringify(badAnswer)})` };
  const objects = [...new Set((Array.isArray(input.refs) ? input.refs.map(String) : String(input.refs ?? "").split(/[\s,]+/)).map((r) => r.trim()).filter(Boolean))];
  if (!objects.length) return { ok: false, reason: "refs is required on a coverage record: the objects the search was over (input:<path>, member:<gen>#<n>, job:<id>/<path>, …); the hub holds the jobs behind it to them" };
  if (objects.length > LEDGER_MAX_REFS) return { ok: false, reason: `refs names more than ${LEDGER_MAX_REFS} objects: name the directory or the container that holds them` };
  // Each object resolves, or is a directory of the run's objects (the evidence
  // directory, a job's whole output, a generation) as the job scopes take it.
  for (const obj of objects) {
    const checked = await checkRefs(ctx.sandboxRoot, [obj]);
    if (checked.ok) continue;
    const dir = await NB.coverageDirectory(ctx.sandboxRoot, obj);
    if (!dir.ok) return checked;
  }
  const results = [...new Set((Array.isArray(input.result_refs) ? input.result_refs.map(String) : String(input.result_refs ?? "").split(/[\s,]+/)).map((r) => r.trim()).filter(Boolean))].map((r) => (/^#\d+$/.test(r) ? `E-${r.slice(1)}` : /^e-\d+$/i.test(r) ? r.toUpperCase() : r));
  if (!results.length) return { ok: false, reason: "result_refs is required: what the search produced, the entries (E-<seq>: an absence, a limitation, a finding) and the job outputs (job:<id>[/<path>])" };
  if (results.length > LEDGER_MAX_CITATIONS) return { ok: false, reason: `result_refs names more than ${LEDGER_MAX_CITATIONS}` };
  const jobRefs = results.filter((r) => !/^E-\d+$/.test(r));
  const badResult = jobRefs.find((r) => !/^(job|import|member|sha256|input):/.test(r));
  if (badResult) return { ok: false, reason: `result_refs names entries as E-<seq> and objects as job:<id>[/<path>] (got ${JSON.stringify(badResult)})` };
  if (jobRefs.length) {
    const c = await checkRefs(ctx.sandboxRoot, jobRefs);
    if (!c.ok) return { ok: false, reason: `result_refs: ${c.reason}` };
  }
  const inventory = await NB.inventoryRevision(ctx.sandboxRoot);
  const givenRev = String(input.inventory_rev ?? "").trim();
  if (givenRev && givenRev !== inventory) return { ok: false, reason: `inventory_rev ${givenRev} is not the run's inventory now (${inventory}): the evidence changed since the search; leave it out, and the hub writes the one the record is made against` };
  let supersedes: number | undefined;
  if (input.supersedes !== undefined && input.supersedes !== null && String(input.supersedes).trim() !== "") {
    const n = Number(String(input.supersedes).trim().replace(/^#/, ""));
    if (!Number.isInteger(n) || n < 1) return { ok: false, reason: `supersedes names an entry by its seq, a whole number (got ${JSON.stringify(input.supersedes)})` };
    supersedes = n;
  }
  const because = boundedText("because", input.because, LEDGER_BECAUSE_MAX_CHARS);
  if (!because.ok) return because;
  if (because.value && supersedes === undefined) return { ok: false, reason: "because says why a correction corrects: give supersedes too" };
  if (input.sensitive !== undefined && input.sensitive !== null && typeof input.sensitive !== "boolean") return { ok: false, reason: "sensitive is true or false" };
  // The planned routes of the questions it is for, and the jobs under them.
  const bars = await Promise.all(answers.map((a) => questionBar(ctx.sandboxRoot, a)));
  const L = await import("./leads.ts");
  const leads = await L.leadsSnapshot(ctx.sandboxRoot);
  const method2 = await ledgerMethods(ctx.sandboxRoot, objects);
  const recorded = await withTableLock(ctx.sandboxRoot, async (held): Promise<LedgerResult> => {
    const entries = await readLedger(ctx.sandboxRoot);
    const bySeq = new Map(entries.map((e) => [e.seq, e]));
    const replaced = supersededBy(entries);
    for (const r of results.filter((x) => /^E-\d+$/.test(x))) {
      const n = Number(r.slice(2));
      const e = bySeq.get(n);
      if (!e) return { ok: false, reason: `result_refs names ${r}: there is no entry #${n} in the ledger` };
      if (replaced.has(n)) return { ok: false, reason: `result_refs names ${r}, superseded by #${standingSeq(n, replaced)}: name the entry that stands` };
      if (e.kind === "answer" || e.kind === "coverage") return { ok: false, reason: `result_refs names ${r}, a ${e.kind}: a search's results are what it found or failed to (absences, limitations, findings, events)` };
    }
    if (supersedes !== undefined) {
      const target = bySeq.get(supersedes);
      if (!target) return { ok: false, reason: `supersedes #${supersedes}: there is no entry #${supersedes} in the ledger` };
      if (target.kind !== "coverage") return { ok: false, reason: `#${supersedes} is a ${target.kind}: a coverage record corrects a coverage record` };
      const already = replaced.get(supersedes);
      if (already !== undefined) return { ok: false, reason: `#${supersedes} is already superseded by #${already}: correct #${already} instead` };
    }
    const cov = await NB.computeObjectCoverage(ctx.sandboxRoot, { objects, resultRefs: results, entries, interpretations: leads.state.interpretations });
    // The planned routes nothing examined: said on the record, whatever the search found.
    const notExamined: Array<{ source: string; method: string; why: string }> = [];
    for (const b of bars) {
      for (const r of b.routes) {
        if (notExamined.some((x) => x.source === r.source && x.method === r.method)) continue;
        const ex = await NB.routeExamined(ctx.sandboxRoot, r, { jobs: [...new Set([...b.jobs, ...cov.jobs])], objects });
        if (!ex.examined) notExamined.push({ source: r.source, method: r.method, why: ex.how });
      }
    }
    const candidate: LedgerEntry = {
      v: LEDGER_VERSION,
      seq: (entries.at(-1)?.seq ?? 0) + 1,
      kind: "coverage",
      value,
      ...(source.value ? { source: source.value } : {}),
      ...(evidence.value ? { evidence: evidence.value } : {}),
      refs: objects,
      answers,
      ...(input.sensitive === true ? { sensitive: true } : {}),
      ...(because.value ? { because: because.value } : {}),
      ...(method2.length ? { method: method2 } : {}),
      alternatives_open: alternatives.value,
      inventory_rev: inventory,
      time_range: timeRange.value,
      search_method: method.value,
      settings: settings.value,
      coverage_actual: actual.value,
      skipped: skipped.value,
      failures: failures.value,
      result_refs: results,
      // Its entries among its results, bound by the hash each has now.
      ...(results.some((x) => /^E-\d+$/.test(x)) ? { result_bound: results.filter((x) => /^E-\d+$/.test(x)).map((x) => { const e = bySeq.get(Number(x.slice(2))) as LedgerEntry; return { seq: e.seq, hash: e.hash ?? ledgerHash(e, "genesis") }; }) } : {}),
      detection_opportunity: { trace_expected: expected as NB.TraceExpected, why: dWhy.value },
      ...(areas ? { areas } : {}),
      ...(acquisitionAsk ? { acquisition_ask: acquisitionAsk } : {}),
      ...(noAsk.value ? { acquisition_none_why: noAsk.value } : {}),
      ...(lookedFor.length ? { looked_for: lookedFor } : {}),
      ...(lookedNone.value ? { looked_for_none_why: lookedNone.value } : {}),
      coverage: cov.coverage,
      coverage_detail: { units: cov.units, jobs: cov.jobs, why: cov.why },
      ...(notExamined.length ? { not_examined: notExamined } : {}),
      by: ctx.agentId,
      authors: [ctx.agentId],
      at: new Date().toISOString(),
    };
    const notes: string[] = [];
    notes.push(cov.coverage === "complete" ? "the hub finds the jobs behind it were given every object it names: coverage complete" : `the hub marks it coverage partial: ${cov.why.join("; ")}`);
    if (notExamined.length) notes.push(`planned routes not examined: ${notExamined.map((r) => `${r.source} (${r.method}): ${r.why}`).join("; ")}`);
    if (bars.some((b) => b.material && !b.routes.length)) notes.push("a question it is for has no route plan: a negative on a material question closes against one (lead_link routes)");
    const complete = bars.filter((b) => b.completeness).map((b) => b.question ?? "a question");
    if (complete.length && !areas) notes.push(`${complete.join(", ")} ask${complete.length === 1 ? "s" : ""} for a complete set: an established or partial answer rests on a coverage record that names its areas {${NB.COVERAGE_AREAS.join(", ")}} (each searched, skipped or not_applicable, a skipped one said in skipped); this one names none, so it does not carry a completeness claim`);
    if (areas) notes.push(`areas: ${NB.areasWords(areas)}`);
    notes.push("a material negative resting on it needs another seat's review: attest this record, or the answer, with review {detection, reproduced, other_route}");
    if (supersedes === undefined) {
      const same = entries.find((e) => !replaced.has(e.seq) && e.kind === "coverage" && ledgerContent(e) === ledgerContent(candidate));
      if (same) return mergeSameContent(ctx, held, same);
    }
    return appendLedgerEntry(ctx, held, entries, { ...candidate, ...(supersedes !== undefined ? { supersedes } : {}) }, notes);
  });
  // The store sweep, begun now and recorded when it ends (ledger/sweeps.jsonl):
  // the record stands at once, and a negative resting on it waits for the
  // sweep as it waits for a review.
  if (!recorded.ok || recorded.merged) return recorded;
  const notes: string[] = [];
  // An object an earlier sweep found a hit in, named here with nothing among the results saying what it showed: said now, held by the gate.
  const now = await readLedger(ctx.sandboxRoot);
  const unexamined = SW.unexaminedHits(recorded.entry, now, await SW.readSweeps(ctx.sandboxRoot), supersededBy(now));
  if (unexamined.length) {
    notes.push(`it names ${unexamined.length === 1 ? "an object" : `${unexamined.length} objects`} an earlier sweep found hits in, and no entry among its result_refs says what ${unexamined.length === 1 ? "it" : "each"} showed: ${unexamined.map((u) => u.ref).join(", ")}. Naming a hit is not examining it: a negative resting on this record is held (sweep_hits) until you record what each showed (a finding, an event or a limitation whose refs name the object, or one absence whose refs list several, written after the sweep) and record the coverage again citing them in result_refs`);
  }
  if (recorded.entry.looked_for?.length) {
    void SW.startSweep(ctx.sandboxRoot, recorded.entry);
    notes.push(`the hub now searches every output the run holds (job outputs and logs, imports, captures, tool-output/) for ${recorded.entry.looked_for.map((t) => `"${t}"`).join(", ")}, in UTF-8 and UTF-16LE: a negative resting on this record waits for the sweep, and a hit in an object it does not name holds it until you examine that object, record what it showed, and record the coverage again naming it with that entry in result_refs, or the answer is revised`);
  }
  return notes.length ? { ...recorded, note: [recorded.note, ...notes].filter(Boolean).join("; ") } : recorded;
}

/**
 * What a downgrade's evidence says against the earlier answer's chain
 * (docs/adr/0013, "After the run s9722fa"): the earlier answer and the
 * entries it rests on (its support). An entry of the evidence bears against
 * it when it is a finding or an event that contradicts the answer or an
 * entry it rests on (rel contradicts), a hypothesis refuted that names one
 * of them (rel) or corrects one, an entry it rests on that a dispute in
 * force or a standing finding or event contradicts, or a correction
 * (supersedes, at any depth) of an entry it rests on. A limitation says a
 * route could not be examined and a coverage record what a search covered:
 * neither undermines a finding that stands (the run s9722fa walked six
 * partial answers down to not determinable on its limitations and its own
 * coverage records).
 *
 * `standing` is each positive finding the earlier answer rested on (a
 * finding or an event it cites, recorded for its question) that still
 * stands: not corrected, under no dispute in force, and contradicted by no
 * standing finding or event. While one does, a revision to not determinable
 * or a bounded negative would discard it; the answer is partial. Refs and
 * links only: nothing here reads what an entry says.
 */
export function downgradeCheck(earlier: LedgerEntry, evidence: readonly string[], entries: LedgerEntry[], disputes: LedgerDispute[]): { bearing: Array<{ seq: number; how: string }>; not_bearing: Array<{ seq: number; why: string }>; standing: LedgerEntry[] } {
  const bySeq = new Map(entries.map((e) => [e.seq, e]));
  const replaced = supersededBy(entries);
  const hashOf = (e: LedgerEntry) => e.hash ?? ledgerHash(e, "genesis");
  const support = (earlier.support ?? []).map((x) => x.seq);
  const chain = new Set([earlier.seq, ...support]);
  const inForce = disputesInForce(entries, disputes);
  const disputed = (e: LedgerEntry) => inForce.some((d) => d.target === hashOf(e));
  const positive = (e: LedgerEntry | undefined): boolean => e?.kind === "finding" || e?.kind === "event";
  const contradictedBy = (seq: number) => entries.filter((c) => !replaced.has(c.seq) && positive(c) && (c.rel ?? []).some((x) => x.kind === "contradicts" && Number(x.to) === seq));
  // The entry of the chain an entry corrects, walking its supersedes back.
  const corrects = (e: LedgerEntry): number | null => {
    const seen = new Set<number>();
    let cur: LedgerEntry | undefined = e;
    while (cur && typeof cur.supersedes === "number" && !seen.has(cur.seq)) {
      seen.add(cur.seq);
      if (support.includes(cur.supersedes)) return cur.supersedes;
      cur = bySeq.get(cur.supersedes);
    }
    return null;
  };
  const bearing: Array<{ seq: number; how: string }> = [];
  const notBearing: Array<{ seq: number; why: string }> = [];
  const list = (xs: number[]) => xs.map((n) => `E-${n}`).join(", ");
  for (const r of evidence) {
    if (!/^E-\d+$/.test(r)) continue;
    const n = Number(r.slice(2));
    const e = bySeq.get(n);
    if (!e) continue;
    const against = (e.rel ?? []).filter((x) => x.kind === "contradicts" && chain.has(Number(x.to))).map((x) => Number(x.to));
    const fixed = corrects(e);
    if (positive(e) && against.length) bearing.push({ seq: n, how: `a ${e.kind} that contradicts ${list(against)}` });
    else if (e.kind === "hypothesis" && e.status === "refuted" && ((e.rel ?? []).some((x) => chain.has(Number(x.to))) || fixed !== null)) bearing.push({ seq: n, how: `a hypothesis refuted, tied to ${fixed !== null ? `E-${fixed}` : list((e.rel ?? []).filter((x) => chain.has(Number(x.to))).map((x) => Number(x.to)))}` });
    else if (fixed !== null) bearing.push({ seq: n, how: `a correction of E-${fixed}, which the earlier answer rests on` });
    else if (support.includes(n) && (disputed(e) || contradictedBy(n).length)) bearing.push({ seq: n, how: disputed(e) ? "an entry the earlier answer rests on, under a dispute in force" : `an entry the earlier answer rests on, contradicted by ${list(contradictedBy(n).map((c) => c.seq))}` });
    else
      notBearing.push({
        seq: n,
        why: support.includes(n)
          ? "an entry the earlier answer rests on, under no dispute and contradicted by nothing"
          : e.kind === "limitation"
            ? "a limitation: it says a route could not be examined, not that a finding is wrong"
            : e.kind === "coverage"
              ? "a coverage record: it says what a search covered, not that a finding is wrong"
              : e.kind === "absence"
                ? "a search that found nothing: it does not undermine a finding that stands"
                : positive(e)
                  ? `a ${e.kind} that contradicts nothing the earlier answer rests on (no rel contradicts to ${list([...chain])})`
                  : e.kind === "hypothesis"
                    ? "a hypothesis not refuted, or tied to nothing the earlier answer rests on"
                    : `a ${e.kind}: it does not bear against the earlier answer's chain`,
      });
  }
  const id = sectionKey(sectionAnswersId(earlier.section ?? ""));
  const standing = support
    .map((s) => bySeq.get(s))
    .filter((e): e is LedgerEntry => positive(e))
    .filter((e) => (e.answers ?? []).some((a) => sectionKey(a) === id) && !replaced.has(e.seq) && !disputed(e) && !contradictedBy(e.seq).length);
  return { bearing, not_bearing: notBearing, standing };
}

/** Record an answer (recordEntry with kind=answer): its checks need the ledger, so they run under the lock. */
async function recordAnswer(ctx: SwarmContext, input: LedgerInput): Promise<LedgerResult> {
  const raw = input as Record<string, unknown>;
  const wrong = NOT_ANSWER_FIELDS.find((f) => given(raw[f]));
  if (wrong) return { ok: false, reason: `${wrong} is not an answer's: an answer rests on ledger entries it cites as E-<seq>; record the fact itself as a finding, an event or an indicator first` };
  const sec = answerSection(String(input.section ?? ""));
  if (!sec.ok) return sec;
  const question = sec.section.startsWith("question:");
  const value = String(input.value ?? "").trim();
  if (!value) return { ok: false, reason: question ? "value is required: the answer itself, as the reader is to be told it" : sec.section === "summary" ? "value is required: the summary a decision maker reads first" : "value is required: what happened, in a paragraph; the whole narrative goes in reasoning" };
  if (value.length > LEDGER_VALUE_MAX_CHARS) return { ok: false, reason: `value is over ${LEDGER_VALUE_MAX_CHARS} characters: put the rest in reasoning` };
  const reasoning = boundedText("reasoning", input.reasoning, LEDGER_REASONING_MAX_CHARS);
  if (!reasoning.ok) return reasoning;
  if (!reasoning.value) return { ok: false, reason: "reasoning is required: how the cited entries lead to the answer, citing E-<seq> for every claim" };
  const confidence = String(input.confidence ?? "").trim().toLowerCase();
  if (confidence && !(LEDGER_CONFIDENCE as readonly string[]).includes(confidence)) return { ok: false, reason: `confidence must be one of ${LEDGER_CONFIDENCE.join(", ")}` };
  const why = boundedText("confidence_why", input.confidence_why, LEDGER_WHY_MAX_CHARS);
  if (!why.ok) return why;
  const openAlt = boundedText("alternatives_open", input.alternatives_open, LEDGER_WHY_MAX_CHARS);
  if (!openAlt.ok) return openAlt;
  const change = boundedText("would_change", input.would_change, LEDGER_WHY_MAX_CHARS);
  if (!change.ok) return change;
  if (question) {
    if (!confidence) return { ok: false, reason: "an answer to a question says how sure: confidence high, medium or low, with confidence_why" };
    if (!why.value) return { ok: false, reason: "confidence_why is required: the quality of the evidence the answer rests on, not a count of it" };
    if (!openAlt.value) return { ok: false, reason: "alternatives_open is required: what else could still explain it, or that nothing remains open and why" };
    if (!change.value) return { ok: false, reason: "would_change is required: what evidence would change this answer" };
  } else if (why.value && !confidence) return { ok: false, reason: "confidence_why says why that confidence: give confidence too" };
  if (input.inconclusive !== undefined && input.inconclusive !== null && typeof input.inconclusive !== "boolean") return { ok: false, reason: "inconclusive is true or false" };
  if (input.sensitive !== undefined && input.sensitive !== null && typeof input.sensitive !== "boolean") return { ok: false, reason: "sensitive is true or false" };
  const contrary = seqList("contrary", input.contrary);
  if (!contrary.ok) return contrary;
  const limits = seqList("limitations", input.limitations);
  if (!limits.ok) return limits;
  let resultText = String(input.result ?? "").trim().toLowerCase().replace(/-/g, "_");
  if (resultText && !(LEDGER_ANSWER_RESULTS as readonly string[]).includes(resultText)) return { ok: false, reason: `result is one of ${LEDGER_ANSWER_RESULTS.join(", ")} (got ${JSON.stringify(input.result)})` };
  // The old way of saying it: inconclusive is not_determinable, and is recorded as both.
  if (input.inconclusive === true) {
    if (resultText && resultText !== "not_determinable") return { ok: false, reason: `inconclusive is the old word for result not_determinable: it cannot come with result ${resultText}` };
    if (question) resultText = "not_determinable";
  }
  if (question && !resultText) {
    return {
      ok: false,
      reason:
        "an answer to a question states its result: established (answered on findings), partial (part of it), bounded_negative (no evidence of it found in a named scope: rests on a coverage record), not_determinable (the evidence cannot settle it: rests on a coverage record too), out_of_scope (the case's evidence cannot bear on it) or premise_not_supported (what it takes for granted does not hold)",
    };
  }
  if (input.asserts_absence !== undefined && input.asserts_absence !== null && typeof input.asserts_absence !== "boolean") return { ok: false, reason: "asserts_absence is true or false" };
  if (input.asserts_absence === true && resultText !== "bounded_negative") return { ok: false, reason: "asserts_absence says the event did not happen: it comes with result bounded_negative, on an existence question whose coverage record is complete and says the event would have left a trace" };
  const noneWhy = boundedText("contrary_none_why", input.contrary_none_why, LEDGER_WHY_MAX_CHARS);
  if (!noneWhy.ok) return noneWhy;
  if (!question && (resultText || noneWhy.value || input.asserts_absence === true)) return { ok: false, reason: "result, asserts_absence and contrary_none_why are a question's answer's" };
  let questionRev: number | undefined;
  if (input.question_rev !== undefined && input.question_rev !== null && String(input.question_rev).trim() !== "") {
    const n = Number(input.question_rev);
    if (!Number.isInteger(n) || n < 1) return { ok: false, reason: `question_rev is the revision of the question this answers, a whole number (got ${JSON.stringify(input.question_rev)})` };
    if (!question) return { ok: false, reason: "question_rev is a question's answer's" };
    questionRev = n;
  }
  if (noneWhy.value && contrary.seqs.length) return { ok: false, reason: "contrary_none_why says no entry says otherwise: give contrary or contrary_none_why, not both" };
  // The claim and open-part rows and the premises it cites (premises.ts):
  // their shape here, what they name in the registers under the locks.
  const partsIn = PM.parseParts(input.parts);
  if (!partsIn.ok) return partsIn;
  const citesIn = PM.parseCitations(input.premises);
  if (!citesIn.ok) return citesIn;
  const parts = partsIn.parts;
  const citations = citesIn.citations;
  if (!question && (parts.length || citations.length)) return { ok: false, reason: "parts and premises are a question's answer's; a summary or a narrative cites the questions it sums up (Q-<n>)" };
  // The test of what the question presumes (docs/adr/0011, "What a question presumes"): its shape here, its objects now, its entries under the lock.
  let premiseTest: PM.PremiseTest | undefined;
  if (input.premise_tested !== undefined && input.premise_tested !== null && input.premise_tested !== "") {
    if (!question) return { ok: false, reason: "premise_tested is a question's answer's: the test of what the question presumes" };
    const t = checkPremiseTest(input.premise_tested, "premise_tested");
    if (!t.ok) return t;
    const objects = t.test.refs.filter((r) => !/^E-\d+$/.test(r));
    if (objects.length) {
      const c = await checkRefs(ctx.sandboxRoot, objects);
      if (!c.ok) return { ok: false, reason: `premise_tested.refs: ${c.reason}` };
    }
    premiseTest = t.test;
  }
  if (question && resultText === "partial" && !parts.some((p) => p.status === "open" || p.status === "limited")) return { ok: false, reason: PARTIAL_NEEDS_OPEN_PART };
  const openParts = parts.filter((p) => p.status === "open");
  if (question && resultText === "established" && openParts.length) {
    return { ok: false, reason: `result established claims every part the question asks, and ${openParts.map((p) => `"${p.id}"`).join(", ")} ${openParts.length === 1 ? "is" : "are"} open: record it partial (its open parts named, each with what bounds it), or establish ${openParts.length === 1 ? "it" : "them"} on the entries that show ${openParts.length === 1 ? "it" : "them"} (status established, refs)` };
  }
  // A part at the limit of the evidence is still a part the answer does not
  // establish: it keeps the answer partial, and the report says it is beyond
  // the evidence rather than open to more work (docs/adr/0013, "A part at the
  // limit of the evidence"). It never lifts the label.
  const limitedParts = parts.filter((p) => p.status === "limited");
  if (question && resultText === "established" && limitedParts.length) {
    return { ok: false, reason: `result established claims every part the question asks, and ${limitedParts.map((p) => `"${p.id}"`).join(", ")} ${limitedParts.length === 1 ? "is" : "are"} at the limit of the evidence: a part the answer does not establish keeps it partial. Record it partial, with ${limitedParts.length === 1 ? "that part" : "those parts"} limited (the report says ${limitedParts.length === 1 ? "it is" : "they are"} beyond the evidence, not open to more work), or establish ${limitedParts.length === 1 ? "it" : "them"} on the entries that show ${limitedParts.length === 1 ? "it" : "them"}` };
  }
  // What bounds an open part outside the ledger: an acquisition ask the requests hold, or a route the lead register holds.
  for (const p of openParts) {
    if (p.open_by?.startsWith("R-")) {
      const R = await import("./requests.ts");
      const req = (await R.requestsSnapshot(ctx.sandboxRoot).catch(() => null))?.requests.get(p.open_by);
      if (!req) return { ok: false, reason: `parts: "${p.id}" is open by ${p.open_by}, which is not a request of this run (swarm.sh requests <run> list; an agent's ask is lead_close needs_operator with ask {kind: acquisition, …})` };
      if (req.kind !== "acquisition") return { ok: false, reason: `parts: "${p.id}" is open by ${p.open_by}, a ${req.kind} request: an open part is bounded by an acquisition ask (the source that would settle it), a route (L-<n>), or a limitation or a coverage record (E-<seq>)` };
    }
    if (p.open_by?.startsWith("L-")) {
      const L = await import("./leads.ts");
      const l = (await L.leadsSnapshot(ctx.sandboxRoot).catch(() => null))?.state.leads.get(p.open_by);
      if (!l) return { ok: false, reason: `parts: "${p.id}" is open by ${p.open_by}, which is not in the lead register (leads lists them): name the lead whose route would examine it` };
    }
  }
  // A person's question is a hypothesis to test: its answer names what says
  // otherwise, or says why nothing does (extensions/questions.ts).
  if (question && !contrary.seqs.length && !noneWhy.value) {
    const asker = await personsQuestion(ctx.sandboxRoot, sec.id).catch(() => null);
    if (asker) return { ok: false, reason: `${sec.section} is ${asker}: a person's question is a proposition to test, never a conclusion to confirm. Name the entries that say otherwise (contrary), or say why none does (contrary_none_why); result premise_not_supported is an answer` };
  }
  const quals: Array<{ seq: number; why: string }> = [];
  for (const q of Array.isArray(input.qualifies) ? input.qualifies : []) {
    const n = Number(String(q?.ref ?? "").trim().replace(/^(?:#|E-)/i, ""));
    const text = boundedText("a qualifies why", q?.why, LEDGER_WHY_MAX_CHARS);
    if (!text.ok) return text;
    if (!Number.isInteger(n) || n < 1 || !text.value) return { ok: false, reason: "an answer's qualifies is [{ref: \"E-<seq>\", why}]: a cited entry that is disputed or rests on a failed job, and why it still supports the answer" };
    if (!quals.some((x) => x.seq === n)) quals.push({ seq: n, why: text.value });
  }
  let supersedes: number | undefined;
  if (input.supersedes !== undefined && input.supersedes !== null && String(input.supersedes).trim() !== "") {
    const n = Number(String(input.supersedes).trim().replace(/^#/, ""));
    if (!Number.isInteger(n) || n < 1) return { ok: false, reason: `supersedes names an entry by its seq, a whole number (got ${JSON.stringify(input.supersedes)})` };
    supersedes = n;
  }
  const because = boundedText("because", input.because, LEDGER_BECAUSE_MAX_CHARS);
  if (!because.ok) return because;
  if (because.value && supersedes === undefined) return { ok: false, reason: "because says why a correction corrects: give supersedes too" };
  // A downgrade names its counter-evidence (docs/adr/0013, round 13: a
  // correct established answer was walked down to not determinable by a
  // dispute that cited nothing against it).
  let downgrade: { evidence: string[]; why: string } | undefined;
  if (input.downgrade !== undefined && input.downgrade !== null) {
    const shape = "downgrade is {evidence: [E-<seq> or objects], why}: what undermines the earlier answer's chain, and why";
    if (typeof input.downgrade !== "object" || Array.isArray(input.downgrade)) return { ok: false, reason: shape };
    const d = input.downgrade as Record<string, unknown>;
    const dWhy = boundedText("downgrade.why", d.why, LEDGER_WHY_MAX_CHARS);
    if (!dWhy.ok) return dWhy;
    const ev = listOf(d.evidence as string[] | string | undefined).map((r) => (/^#\d+$/.test(r) ? `E-${r.slice(1)}` : /^e-\d+$/i.test(r) ? r.toUpperCase() : r));
    if (!ev.length || !dWhy.value) return { ok: false, reason: shape };
    if (ev.length > LEDGER_MAX_CITATIONS) return { ok: false, reason: `downgrade.evidence names more than ${LEDGER_MAX_CITATIONS}` };
    const objects = ev.filter((r) => !/^E-\d+$/.test(r));
    if (objects.length) {
      const c = await checkRefs(ctx.sandboxRoot, objects);
      if (!c.ok) return { ok: false, reason: `downgrade.evidence: ${c.reason}` };
    }
    downgrade = { evidence: ev, why: dWhy.value };
  }
  // The finish phase (extensions/finish.ts): while the coordinator
  // assembles the finish (it holds the lease and the registers are met but
  // for what is late, a confirmation or a resolution), another seat's
  // revision of an answer is recorded only when it says why it changes a
  // conclusion (material). A rewording or a restatement is refused
  // quietly: on the c10 pilot's tail, answers revised again and again kept
  // re-offering confirmations and making late results, and the finish never
  // closed. The coordinator's own folding is free.
  const materialWhy = boundedText("material", input.material, LEDGER_WHY_MAX_CHARS);
  if (!materialWhy.ok) return materialWhy;
  if (supersedes !== undefined && !materialWhy.value) {
    const F = await import("./finish.ts");
    const lease = (await F.readFinish(ctx.sandboxRoot).catch(() => null))?.lease ?? null;
    if (lease && lease.holder !== ctx.agentId && (await F.finishPhase(ctx.sandboxRoot).catch(() => null))?.assembling) {
      return { ok: false, quiet: true, deferred: { coordinator: lease.holder, generation: lease.generation }, reason: `the finish is being assembled by ${lease.holder}; revise only with material: why (what conclusion this revision changes: its result, its value, what it rests on). A rewording or a restatement is not recorded now, and nothing is lost: ${lease.holder} folds what stands into the report` };
    }
  }
  const source = boundedText("source", input.source, LEDGER_SOURCE_MAX_CHARS);
  if (!source.ok) return source;
  const evidence = boundedText("evidence", input.evidence, LEDGER_EVIDENCE_MAX_CHARS);
  if (!evidence.ok) return evidence;
  // The entries its rows name are citations as the text's are: a part's refs and the entry that bounds an open part, a premise citation's refs.
  const rowRefs = [...parts.flatMap((p) => [...(p.refs ?? []), ...(p.open_by?.startsWith("E-") ? [p.open_by] : []), ...(p.limited_by ? [p.limited_by] : [])]), ...citations.flatMap((c) => c.refs ?? []), ...(premiseTest?.refs ?? []).filter((r) => /^E-\d+$/.test(r))].map((r) => Number(r.slice(2)));
  const cited = [...new Set([...answerCitations(`${value}\n${reasoning.value}`), ...rowRefs])];
  const support = cited.filter((n) => !contrary.seqs.includes(n) && !limits.seqs.includes(n));
  // A summary or a narrative cites the questions it sums up symbolically
  // (Q-<n>): bound to each answer's conclusion, not to its seq (A4).
  const symbolic: Array<{ q: string; section: string }> = [];
  if (!question) {
    for (const name of symbolicQuestions(`${value}\n${reasoning.value}`)) {
      const id = name.startsWith("question:") ? sectionKey(name.slice("question:".length)) : sectionKey(await registerSection(ctx.sandboxRoot, name));
      if (!LEDGER_ANSWER_ID.test(id)) return { ok: false, reason: `${name} is not a question this run has (questions list names them)` };
      if (!symbolic.some((x) => x.section === `question:${id}`)) symbolic.push({ q: name, section: `question:${id}` });
    }
  }
  if (support.length + contrary.seqs.length + limits.seqs.length > LEDGER_MAX_CITATIONS) return { ok: false, reason: `the answer cites more than ${LEDGER_MAX_CITATIONS} entries: cite the ones it rests on` };
  // The negative bar (extensions/negative-bar.ts): what the question is, as the registers say.
  const bar = question ? await questionBar(ctx.sandboxRoot, sec.id) : null;
  // What the case policy says of more evidence: under no, an acquisition ask is declined at once, and acquisition_none_why names the policy instead.
  const moreEvidence = question && resultText === "not_determinable" ? await import("./requests.ts").then((R) => R.casePolicyMoreEvidence(ctx.sandboxRoot)).catch(() => "ask" as const) : "ask";
  const negative = NB.NEGATIVE_RESULTS.has(resultText);
  const absolute = question ? NB.absoluteAbsenceForms(`${value}\n${reasoning.value}`) : [];
  if (absolute.length && !input.asserts_absence) {
    return { ok: false, reason: `it is worded as the event's absence (${absolute.map((f) => `"${f}"`).join(", ")}): a negative says "No evidence of <what> was found in <scope>". "It did not happen" is for an existence question whose coverage record is complete and says the event would have left a trace there, recorded with asserts_absence: true` };
  }
  if (negative && bar?.material && !bar.routes.length) {
    return { ok: false, reason: `${sec.section} is a material question with no route plan: a ${NB.resultWords(resultText)} closes against the sources and methods planned before the search. Give the lead under it its routes (lead_link with routes [{source, method}]), then record this again` };
  }
  // Which revision of the question it answers, held still while the answer
  // is written: the register's lock (the questions' amendments take it too),
  // then the ledger's. A question amended since the agent read it refuses
  // the answer; one amended past revision 1 needs its revision said.
  const recorded = await withNamedLock(ctx.sandboxRoot, REGISTER_LOCK, async (): Promise<LedgerResult> => {
    let premiseReg: ReadonlyMap<string, PM.Premise> | undefined;
    if (question) {
      const reg = await registerRevision(ctx.sandboxRoot, sec.id).catch(() => null);
      if (reg) {
        if (questionRev !== undefined && questionRev !== reg.rev) return { ok: false as const, reason: `${reg.id} (${sec.section}) is at revision ${reg.rev}, amended since the revision ${questionRev} this answers: read it again (questions show ${reg.id}) and answer revision ${reg.rev}, with question_rev: ${reg.rev}` };
        if (questionRev === undefined && reg.rev > 1) return { ok: false as const, reason: `${reg.id} (${sec.section}) was amended to revision ${reg.rev}: say which revision this answers (question_rev: ${reg.rev}, after reading it with questions show ${reg.id}); an answer to an earlier revision is stale` };
      }
      // The premises it cites, held still under the same lock (a revision, an admission or a withdrawal takes it too).
      if (citations.length) {
        const Q = await import("./questions.ts");
        premiseReg = (await Q.questionsSnapshot(ctx.sandboxRoot)).state.premises;
        const bad = citationRefusal(citations, premiseReg, reg?.id ?? `question:${sec.id}`);
        if (bad) return { ok: false as const, reason: bad };
      }
    }
    return withTableLock(ctx.sandboxRoot, async (held) => {
      const entries = await readLedger(ctx.sandboxRoot);
      const disputes = await readDisputes(ctx.sandboxRoot);
      const bySeq = new Map(entries.map((e) => [e.seq, e]));
      const replaced = supersededBy(entries);
      const hashOf = (e: LedgerEntry) => e.hash ?? ledgerHash(e, "genesis");
      const standing = entries.find((e) => e.kind === "answer" && e.section === sec.section && !replaced.has(e.seq));
      if (supersedes !== undefined) {
        const target = bySeq.get(supersedes);
        if (!target) return { ok: false, reason: `supersedes #${supersedes}: there is no entry #${supersedes} in the ledger (list them with ledger)` };
        if (target.kind !== "answer") return { ok: false, reason: `#${supersedes} is a ${target.kind}: an answer corrects an answer; correct the ${target.kind} with a ${target.kind}` };
        if (target.section !== sec.section) return { ok: false, reason: `#${supersedes} answers ${target.section}: an answer corrects the answer to its own section` };
        const already = replaced.get(supersedes);
        if (already !== undefined) return { ok: false, reason: `#${supersedes} is already superseded by #${already}: correct #${already} instead, so the corrections stay one line` };
      }
      // From a positive result to a negative one: a downgrade, which names what undermines the earlier chain.
      const earlier = supersedes !== undefined ? (bySeq.get(supersedes) as LedgerEntry) : undefined;
      const earlierResult = earlier ? NB.answerResult(earlier) : null;
      const downgrading = Boolean(earlier) && (earlierResult === "established" || earlierResult === "partial") && (resultText === "not_determinable" || resultText === "bounded_negative");
      if (downgrading && !downgrade) {
        return {
          ok: false,
          reason: `#${supersedes} answered ${sec.section} ${NB.resultWords(earlierResult)}; recording it ${NB.resultWords(resultText)} is a downgrade, and a downgrade names what undermines the earlier chain: downgrade {evidence: [E-<seq> of an entry that bears against it: a finding that contradicts it, a correction of what it rests on, …], why}. A doubt with no counter-evidence is not one: dispute #${supersedes} (why, refs), and if the doubt stands attest it best_candidate or record it again with confidence medium; the answer stays. A part the evidence cannot settle makes an answer partial, never not determinable while the findings it rests on stand`,
        };
      }
      if (downgrade && !downgrading) return { ok: false, reason: `downgrade is for a revision that moves an answer from established or partial to not_determinable or bounded_negative${earlier ? `; #${supersedes} is ${NB.resultWords(earlierResult)} and this is ${NB.resultWords(resultText)}` : "; give supersedes"}` };
      for (const r of downgrade?.evidence ?? []) {
        if (!/^E-\d+$/.test(r)) continue;
        const n = Number(r.slice(2));
        if (!bySeq.has(n)) return { ok: false, reason: `downgrade.evidence names ${r}: there is no entry #${n} in the ledger` };
        if (n === supersedes) return { ok: false, reason: `downgrade.evidence names ${r}, the answer being downgraded: name what undermines it` };
        if (replaced.has(n)) return { ok: false, reason: `downgrade.evidence names ${r}, superseded by #${standingSeq(n, replaced)}: name the entry that stands` };
      }
      // The evidence bears against the earlier chain, and no positive finding
      // it rested on still stands (downgradeCheck): a limitation, or the
      // downgrader's own coverage, undermines nothing, and a standing finding
      // is never discarded to make an answer not determinable.
      if (downgrading && downgrade && earlier) {
        const chk = downgradeCheck(earlier, downgrade.evidence, entries, disputes);
        const rests = [earlier.seq, ...(earlier.support ?? []).map((x) => x.seq)].map((n) => `E-${n}`).join(", ");
        const why: string[] = [];
        if (!chk.bearing.length) {
          why.push(
            `downgrade.evidence names nothing that bears against #${supersedes}'s chain (${rests}): ${[...chk.not_bearing.map((x) => `E-${x.seq} is ${x.why}`), ...(downgrade.evidence.some((r) => !/^E-\d+$/.test(r)) ? ["an object says nothing until an entry says what it shows"] : [])].join("; ")}. A downgrade names at least one entry that does: a finding or an event that contradicts #${supersedes} or an entry it rests on (recorded with rel [{to: <seq>, kind: "contradicts"}]), a hypothesis refuted that names one, an entry it rests on under a dispute in force, or a correction (supersedes) of one`,
          );
        }
        if (chk.standing.length) {
          const s = chk.standing.map((e) => `E-${e.seq}`).join(", ");
          const one = chk.standing.length === 1;
          why.push(
            `#${supersedes} rests on ${s}, recorded for ${sec.section}, which ${one ? "still stands" : "still stand"}: not corrected, under no dispute, contradicted by nothing. Recording ${sec.section} ${NB.resultWords(resultText)} would discard ${one ? "it" : "them"}. Answer partial instead (record it with supersedes=${supersedes}, result partial): state what ${s} establish${one ? "es" : ""}, and name the parts still open, each with what bounds it (parts [{id, part, status: "open", open_by: E-<seq> of its limitation or coverage record, R-<n> or L-<n>}], beside the parts ${s} establish${one ? "es" : ""}, status "established"). If ${one ? "it does" : "one of them does"} not hold, say so first: dispute it (why, refs), correct it (supersedes), or record the finding that contradicts it (rel contradicts), and name that in downgrade.evidence`,
          );
        }
        if (why.length) return { ok: false, reason: why.join(". ") };
      }
      // A summary or a narrative that cites a question's answer by its seq
      // (E-n) is bound to that question instead (question:N): the pilot's
      // summary and narrative cited three answers by seq and fell with every
      // revision of each. Its binding is then to the answer's conclusion (the
      // fingerprint below), whichever answer stands for the question now,
      // and the reply says so.
      const bound: Array<{ seq: number; section: string; standing: number | null }> = [];
      if (!question) {
        for (let i = support.length - 1; i >= 0; i--) {
          const e = bySeq.get(support[i]!);
          if (e?.kind !== "answer" || !e.section?.startsWith("question:")) continue;
          const standingNow = entries.find((x) => x.kind === "answer" && x.section === e.section && !replaced.has(x.seq));
          bound.unshift({ seq: e.seq, section: e.section, standing: standingNow?.seq ?? null });
          if (!symbolic.some((x) => x.section === e.section)) symbolic.push({ q: e.section, section: e.section });
          support.splice(i, 1);
        }
      }
      // A question's answer cited symbolically is not cited by seq as well:
      // its correction would take the summary down with it.
      for (let i = support.length - 1; i >= 0; i--) {
        const e = bySeq.get(support[i]!);
        if (e?.kind === "answer" && symbolic.some((x) => x.section === e.section)) support.splice(i, 1);
      }
      const questionRefs: NonNullable<LedgerEntry["question_refs"]> = [];
      if (symbolic.length) {
        const fallen = answerProblems(entries, disputes);
        for (const x of symbolic) {
          const a = entries.find((e) => e.kind === "answer" && e.section === x.section && !replaced.has(e.seq));
          if (!a) return { ok: false, reason: `${x.q} (${x.section}) has no standing answer yet: a ${sec.section} cites an answer that stands` };
          if (fallen.has(a.seq)) return { ok: false, reason: `${x.q}'s answer E-${a.seq} no longer stands on its own support (${(fallen.get(a.seq) as string[]).join("; ")}): it is to be recorded again first` };
          questionRefs.push({ q: x.q, section: x.section, answer: a.seq, fp: answerFingerprint(a) });
        }
      }
      for (const n of [...support, ...contrary.seqs, ...limits.seqs]) {
        if (!bySeq.has(n)) return { ok: false, reason: `E-${n}: there is no entry #${n} in the ledger (list them with ledger)` };
        if (n === supersedes) return { ok: false, reason: `E-${n} is the answer this one replaces: an answer does not rest on the answer it corrects` };
      }
      // An open part is bounded by a limitation (it joins the answer's limitations) or a coverage record, each standing.
      for (const p of parts) {
        if (!p.open_by?.startsWith("E-")) continue;
        const n = Number(p.open_by.slice(2));
        const b = bySeq.get(n) as LedgerEntry;
        if (b.kind !== "limitation" && b.kind !== "coverage") return { ok: false, reason: `parts: "${p.id}" is open by ${p.open_by}, a ${b.kind}: an open part is bounded by a limitation (why it could not be established) or a coverage record (what was searched for it) E-<seq>, an acquisition ask R-<n>, or a route L-<n>; a ${b.kind} that bears on it goes in its refs` };
        if (replaced.has(n)) return { ok: false, reason: `parts: "${p.id}" is open by ${p.open_by}, superseded by #${standingSeq(n, replaced)}: name the one that stands` };
        if (b.kind === "limitation" && !limits.seqs.includes(n)) {
          limits.seqs.push(n);
          const i = support.indexOf(n);
          if (i >= 0) support.splice(i, 1);
        }
      }
      // A limited part is shown by the coverage record for the question, or by
      // a limitation that says the evidence is unavailable or excluded, each
      // standing (docs/adr/0013, "A part at the limit of the evidence").
      for (const p of parts) {
        if (!p.limited_by) continue;
        const n = Number(p.limited_by.slice(2));
        const b = bySeq.get(n) as LedgerEntry;
        const qid = question ? sec.id : null;
        const forQuestion = (b.answers ?? []).some((x) => qid !== null && sectionKey(x) === qid);
        if (replaced.has(n)) return { ok: false, reason: `parts: "${p.id}" is limited by ${p.limited_by}, superseded by #${standingSeq(n, replaced)}: name the one that stands` };
        if (b.kind === "coverage" && !forQuestion) return { ok: false, reason: `parts: "${p.id}" is limited by ${p.limited_by}, a coverage record not recorded for ${sec.section}: a limited part rests on the coverage record for its question (answers=["${qid}"]: what was searched for it, over which objects, what was covered and skipped)` };
        if (b.kind === "limitation" && b.reason !== "unavailable" && b.reason !== "excluded") return { ok: false, reason: `parts: "${p.id}" is limited by ${p.limited_by}, a limitation whose reason is ${b.reason ?? "not given"}: a part the evidence in scope cannot settle rests on a limitation whose reason is unavailable (the evidence that would settle it was not collected, or no longer exists) or excluded (the case leaves it out). One that was not examined, failed or is partial could still be settled: hold the part open (open_by ${p.limited_by})` };
        if (b.kind !== "coverage" && b.kind !== "limitation") return { ok: false, reason: `parts: "${p.id}" is limited by ${p.limited_by}, a ${b.kind}: a limited part rests on the coverage record for the question (what was searched for it) or a limitation whose reason is unavailable or excluded; a ${b.kind} that bears on it goes in its refs` };
        if (b.kind === "limitation" && !limits.seqs.includes(n)) {
          limits.seqs.push(n);
          const i = support.indexOf(n);
          if (i >= 0) support.splice(i, 1);
        }
      }
      // A premise the answer says the evidence supports rests on a finding or an event that stands, undisputed.
      const inForce = new Set(disputesInForce(entries, disputes).map((d) => d.target));
      for (const c of citations) {
        if (c.stance !== "supported" || rebuttingRefs(c.refs ?? [], bySeq, replaced, inForce).length) continue;
        return { ok: false, reason: `premises: ${c.id} is supported: name in its refs the standing finding or event that shows it (E-<seq>, not disputed, not superseded)${c.refs?.length ? `; ${c.refs.join(", ")} ${c.refs.length === 1 ? "is not one" : "are not"}` : ""}. Without one, cite it assumed (a given is not proved again), or unresolved` };
      }
      for (const n of limits.seqs) {
        const l = bySeq.get(n) as LedgerEntry;
        if (l.kind !== "limitation") return { ok: false, reason: `limitations names #${n}, a ${l.kind}: it takes limitation entries` };
        if (replaced.has(n)) return { ok: false, reason: `limitations names #${n}, superseded by #${standingSeq(n, replaced)}: name the limitation that stands` };
      }
      // Every claimed support is checked, not one matching citation.
      const disputedBy = new Map<string, DisputeInForce[]>();
      for (const d of disputesInForce(entries, disputes)) disputedBy.set(d.target, [...(disputedBy.get(d.target) ?? []), d]);
      const problems = answerProblems(entries, disputes);
      const needs = new Set<number>();
      for (const n of support) {
        const e = bySeq.get(n) as LedgerEntry;
        if (replaced.has(n)) {
          const now = standingSeq(n, replaced);
          if (!cited.includes(now)) return { ok: false, reason: `E-${n} is superseded by #${now}: cite E-${now}, the correction, with it or instead (a superseded entry explains history; it supports nothing)` };
          continue;
        }
        if (e.kind === "answer" && problems.has(n)) return { ok: false, reason: `E-${n} is an answer that no longer stands on its own support (${(problems.get(n) as string[]).join("; ")}): it is to be recorded again first` };
        const against = disputedBy.get(hashOf(e));
        const failed = await unqualifiedFailedRefs(ctx.sandboxRoot, e);
        if (against?.length || failed.length) {
          if (!quals.some((q) => q.seq === n)) {
            return {
              ok: false,
              reason: against?.length
                ? `E-${n} is disputed by ${against.map((d) => `${d.by}: ${d.why}${d.inherited_from !== undefined ? ` (raised on E-${d.inherited_from}, which it corrects: the dispute is open until ${d.by} withdraws it)` : ""}`).join("; ")}; cite its correction, drop it, or say in qualifies [{ref: "E-${n}", why}] why it still supports this answer`
                : `E-${n} rests on the kept output of a job that did not succeed (${failed.join(", ")}) and does not say why it still holds: say so in qualifies [{ref: "E-${n}", why}], or cite an entry resting on a job that worked`,
            };
          }
          needs.add(n);
        }
      }
      const extra = quals.find((q) => !needs.has(q.seq));
      if (extra) return { ok: false, reason: `qualifies names E-${extra.seq}, which ${support.includes(extra.seq) ? "is neither disputed nor resting on a failed job" : "the answer does not cite as support"}: it qualifies only a cited entry that needs it` };
      // What the answer stands on: an entry that names its question, or for a
      // summary or a narrative any entry that stands.
      const standingCites = [...support, ...limits.seqs].filter((n) => !replaced.has(n)).map((n) => bySeq.get(n) as LedgerEntry);
      if (question) {
        const id = sectionAnswersId(sec.section);
        const naming = (kinds: string[]) => standingCites.filter((e) => kinds.includes(e.kind) && (e.answers ?? []).some((a) => sectionKey(a) === id));
        if (!naming(["finding", "absence", "limitation", "coverage"]).length) {
          return { ok: false, reason: `an answer to ${sec.section} rests on at least one standing finding, search, limitation or coverage record recorded with answers=["${id}"] and cited as E-<seq>${standingCites.length ? ` (none of ${standingCites.map((e) => `E-${e.seq}`).join(", ")} names it)` : " (the answer cites no standing entry)"}` };
        }
        // The result says what the answer rests on: findings for what is established, a coverage record for a material negative.
        if ((resultText === "established" || resultText === "partial") && !naming(["finding"]).length) {
          return { ok: false, reason: `a result ${resultText} rests on a standing finding recorded with answers=["${id}"] and cited as E-<seq>; if nothing was found, the result is bounded_negative or not_determinable, resting on a coverage record` };
        }
        // A premise is shown not to hold by what was found, never by a search that found nothing.
        if (resultText === "premise_not_supported" && !naming(["finding"]).length) {
          return { ok: false, reason: `premise_not_supported rests on a standing finding recorded with answers=["${id}"] that shows the premise does not hold, cited as E-<seq>; a search that found nothing is a bounded_negative (or not_determinable), resting on a coverage record and reviewed by another seat` };
        }
        const coverage = naming(["coverage"]);
        if (negative && bar?.material && !coverage.length) {
          return {
            ok: false,
            reason: `a ${NB.resultWords(resultText)} on a material question rests on a coverage record: record kind=coverage with answers=["${id}"] (the proposition searched, the objects in refs, time_range, search_method, settings, coverage_actual, skipped, failures, result_refs, alternatives and detection_opportunity), and cite it as E-<seq>`,
          };
        }
        if (input.asserts_absence === true) {
          const complete = coverage.filter((c) => c.coverage === "complete" && c.detection_opportunity?.trace_expected === "yes" && !coverageProblems(c, entries, disputes).length);
          if (!bar?.existence) return { ok: false, reason: `asserts_absence says the event did not happen: only an answer to a question that asks whether something exists may say that (the goal's --existence, or the register's expects existence); ${sec.section} does not. Say "No evidence of … was found in …"` };
          if (!complete.length) return { ok: false, reason: `asserts_absence says the event did not happen: it rests on a coverage record the hub found complete and that says the event would have left a trace (detection_opportunity.trace_expected yes); ${coverage.length ? coverage.map((c) => `E-${c.seq} is coverage ${c.coverage ?? "unknown"}, trace expected ${c.detection_opportunity?.trace_expected ?? "?"}`).join("; ") : "it cites no coverage record"}. Say "No evidence of … was found in …" instead` };
        }
      } else if (!standingCites.length && !questionRefs.length) {
        return { ok: false, reason: `a ${sec.section} cites at least one standing entry as E-<seq>, or the questions it sums up as Q-<n>` };
      }
      const edge = (n: number): LedgerEdge => ({ seq: n, hash: hashOf(bySeq.get(n) as LedgerEntry) });
      const citedEntries = [...support, ...contrary.seqs, ...limits.seqs, ...questionRefs.map((r) => r.answer)].map((n) => bySeq.get(n) as LedgerEntry);
      const tokens = unsupportedTokens(`${value}\n${reasoning.value}`, citedEntries, bySeq);
      const candidate: LedgerEntry = {
        v: LEDGER_VERSION,
        seq: (entries.at(-1)?.seq ?? 0) + 1,
        kind: "answer",
        value,
        ...(source.value ? { source: source.value } : {}),
        ...(evidence.value ? { evidence: evidence.value } : {}),
        ...(confidence ? { confidence: confidence as LedgerEntry["confidence"] } : {}),
        ...(input.sensitive === true ? { sensitive: true } : {}),
        ...(because.value ? { because: because.value } : {}),
        ...(why.value ? { confidence_why: why.value } : {}),
        ...(quals.length ? { qualifies: quals.map((q) => ({ ref: `E-${q.seq}`, why: q.why })) } : {}),
        section: sec.section,
        reasoning: reasoning.value,
        ...(support.length ? { support: support.map(edge) } : {}),
        ...(contrary.seqs.length ? { contrary: contrary.seqs.map(edge) } : {}),
        ...(limits.seqs.length ? { limitations: limits.seqs.map(edge) } : {}),
        ...(openAlt.value ? { alternatives_open: openAlt.value } : {}),
        ...(change.value ? { would_change: change.value } : {}),
        ...(input.inconclusive === true ? { inconclusive: true } : {}),
        ...(resultText ? { result: resultText as LedgerEntry["result"] } : {}),
        ...(noneWhy.value ? { contrary_none_why: noneWhy.value } : {}),
        ...(questionRev !== undefined ? { question_rev: questionRev } : {}),
        ...(questionRefs.length ? { question_refs: questionRefs } : {}),
        ...(materialWhy.value ? { finish_material: materialWhy.value } : {}),
        ...(input.asserts_absence === true ? { asserts_absence: true } : {}),
        ...(parts.length ? { parts } : {}),
        ...(citations.length ? { premises: citations } : {}),
        ...(premiseTest ? { premise_tested: premiseTest } : {}),
        ...(tokens.length ? { unsupported_tokens: tokens } : {}),
        ...(downgrade ? { downgrade } : {}),
        // Recorded under the recorded-confidence rule: its high is kept only as recordedConfidence says.
        ...(question && confidence ? { confidence_rule: 1 } : {}),
        by: ctx.agentId,
        authors: [ctx.agentId],
        at: new Date().toISOString(),
      };
      const content = ledgerContent(candidate);
      if (supersedes !== undefined && ledgerContent(bySeq.get(supersedes) as LedgerEntry) === content) {
        return { ok: false, reason: `the correction repeats #${supersedes} word for word: a correction says what is right now` };
      }
      if (supersedes === undefined && standing && ledgerContent(standing) === content) return mergeSameContent(ctx, held, standing);
      if (standing && supersedes !== standing.seq) {
        return { ok: false, reason: `${sec.section} is answered by #${standing.seq} already: one answer stands for a section; to revise it, record this with supersedes=${standing.seq}` };
      }
      const notes: string[] = [];
      if (bound.length) notes.push(`${bound.map((b) => `E-${b.seq} (the answer to ${b.section}${b.standing !== null && b.standing !== b.seq ? `, now E-${b.standing}` : ""})`).join(", ")} ${bound.length === 1 ? "is" : "are"} cited as ${[...new Set(bound.map((b) => b.section))].join(", ")}: a ${sec.section} is bound to the questions it sums up, to each answer's conclusion (its result, the revision it answers, its support and contrary evidence), not to its seq, so a reworded correction of an answer keeps it standing. Cite Q-<n> or question:<n> for an answer in a ${sec.section}`);
      if (tokens.length) notes.push(`in none of the cited entries: ${tokens.join(", ")}; cite the entry that holds each, or record how it was derived as its own entry and cite that (marked on the answer; the release counts them)`);
      if (question && resultText !== "not_determinable" && standingCites.every((e) => e.kind === "limitation")) notes.push("it rests on limitations only: if the ledger cannot answer it, say so with result not_determinable, resting on a coverage record");
      if (question && negative && bar?.material) {
        const cov = standingCites.filter((e) => e.kind === "coverage");
        if (cov.some((c) => c.coverage === "partial")) notes.push(`its coverage record${cov.length > 1 ? "s are" : " is"} partial (${cov.filter((c) => c.coverage === "partial").map((c) => `E-${c.seq}`).join(", ")}): the report says what was not covered`);
        notes.push(`a material negative is reviewed by another seat before the run may end: an attest on this answer or on ${cov.map((c) => `E-${c.seq}`).join(", ")} with review {detection, reproduced, other_route}; until then it shows as negative (unreviewed)`);
      }
      if (question) {
        const qid = sectionAnswersId(sec.section);
        const covFor = standingCites.filter((e) => e.kind === "coverage" && (e.answers ?? []).some((x) => sectionKey(x) === qid));
        // A completeness claim rests on a coverage record that names what was searched, area by area.
        if (bar?.completeness && (resultText === "established" || resultText === "partial") && !covFor.some((c) => c.areas)) {
          notes.push(`${bar.question ?? sec.section} asks for a complete set ("every", "all", "each", a complete list): a ${NB.resultWords(resultText)} answer to it rests on a coverage record for it that says what was searched, over which objects, and its areas {${NB.COVERAGE_AREAS.join(", ")}} (each searched, skipped or not_applicable, what was skipped said in skipped). It cites none, so the finish line holds it (completeness_uncovered) until it does: record the coverage, then this answer again with supersedes=<this seq> citing it`);
        }
        // A question the evidence cannot settle for want of a source: the ask comes first.
        if (resultText === "not_determinable" && !covFor.some((c) => c.acquisition_ask || c.acquisition_none_why)) {
          notes.push(
            moreEvidence === "no"
              ? `this case admits no further evidence (more_evidence: no), so open no acquisition ask: the coverage record behind this answer says so in acquisition_none_why ("${NO_MORE_EVIDENCE_NONE_WHY}"); the finish line warns until it does`
              : "not determinable for want of a source the evidence does not hold? Ask for it first: lead_close needs_operator with ask {kind: acquisition, source, where, expected_value, urgency} opens R-<n>. The coverage record behind this answer names the ask (acquisition_ask: R-<n>) or says why none would settle it (acquisition_none_why); the finish line warns until it does",
          );
        }
      }
      // The confidence the run records: high only on an established answer another seat attested established, naming the alternatives it weighed.
      if (question && confidence === "high") {
        notes.push(resultText === "established" ? "confidence high is recorded as medium until another seat attests this answer established, naming the alternatives it weighed and why the evidence rules each out; the report and the metrics show the recorded confidence" : `confidence high is recorded as medium: high is kept only by an established answer, and this one is ${NB.resultWords(resultText)}; the report and the metrics show the recorded confidence`);
      }
      // The premises: what this answer's citations meet among the answers that stand (premise_inconsistent), said now.
      if (question && citations.length) {
        const others: PM.CitingAnswer[] = entries.filter((e) => e.kind === "answer" && e.section?.startsWith("question:") && e.section !== sec.section && !replaced.has(e.seq) && e.premises?.length).map((e) => ({ seq: e.seq, section: e.section as string, citations: e.premises! }));
        const me: PM.CitingAnswer = { seq: candidate.seq, section: sec.section, citations };
        for (const c of PM.premiseConflicts([...others, me], premiseReg, (refs) => rebuttingRefs(refs, bySeq, replaced, inForce)).filter((x) => x.assumed.seq === me.seq || x.contradicted.seq === me.seq)) {
          const mine = c.assumed.seq === me.seq;
          const other = mine ? c.contradicted : c.assumed;
          if (c.contradicted.rebuttal.length) {
            notes.push(mine ? `this answer assumes ${c.premise} (revision ${c.rev}), which E-${other.seq} (${other.section}) contradicts on ${c.contradicted.rebuttal.join(", ")}: the premise is disputed before the operator, and nothing waits on the ruling. If this answer holds only if the premise does, cite it conditionally (premises [{id: "${c.premise}", rev: ${c.rev}, stance: "assumed", conditional: true}]: "assuming ${c.premise}")` : `${c.premise} (revision ${c.rev}), which E-${other.seq} (${other.section}) assumes, is contradicted here on ${c.contradicted.rebuttal.join(", ")}: the premise is disputed before the operator (a request of kind premise), and the answers that assume it are warned (premise_disputed); nothing is forced on either`);
          } else {
            notes.push(`${mine ? `this answer assumes ${c.premise} (revision ${c.rev}), which E-${other.seq} (${other.section}) contradicts` : `this answer contradicts ${c.premise} (revision ${c.rev}), which E-${other.seq} (${other.section}) assumes`}, over scopes that overlap: the finish line holds both questions (premise_inconsistent) until they are reconciled, and neither side is forced: ${PREMISE_WAYS_OUT(c.premise, c.rev)}`);
          }
        }
        for (const c of citations) {
          const p = premiseReg?.get(c.id);
          if (p?.class === "supplied_assertion" && c.stance === "assumed" && !c.conditional) notes.push(`${c.id} is a supplied assertion: the report says the answer rests on it as asserted (${p.locator}), not as established`);
        }
      }
      return appendLedgerEntry(ctx, held, entries, { ...candidate, ...(supersedes !== undefined ? { supersedes } : {}) }, notes);
    });
  });
  // A contradiction that names its rebutting finding opens a premise dispute for the operator (a request of kind premise): written now, its id said.
  if (recorded.ok && !recorded.merged && recorded.entry.premises?.some((c) => c.stance === "contradicted" && c.refs?.length)) {
    const R = await import("./requests.ts");
    await R.reconcileRequests(ctx.sandboxRoot).catch(() => undefined);
    const byKey = (await R.requestsSnapshot(ctx.sandboxRoot).catch(() => null))?.byKey;
    const ids = recorded.entry.premises.filter((c) => c.stance === "contradicted" && c.refs?.length).map((c) => ({ c, rid: byKey?.get(PM.premiseDisputeKey(c.id, c.rev)) })).filter((x) => x.rid);
    if (ids.length) recorded.note = [recorded.note, `the premise dispute${ids.length === 1 ? "" : "s"} ${ids.map((x) => `${x.rid} (${x.c.id} revision ${x.c.rev})`).join(", ")} ${ids.length === 1 ? "is" : "are"} with the operator: they revise or withdraw the premise, or answer the request; nothing waits on it`].filter(Boolean).join("; ");
  }
  return recorded;
}

/** What a partial answer with no open part is told: the refusal's words (docs/adr/0013, "Claim and open-part rows"). */
export const PARTIAL_NEEDS_OPEN_PART =
  'record it established or name what is open: a partial answer carries parts [{id, part, status, refs, open_by?}], each part the question asks as you read its revision, the parts it establishes (status "established", refs: the entries that establish each) and at least one open part (status "open", open_by: what bounds it: an acquisition ask R-<n>, a route L-<n>, or a limitation or a coverage record E-<seq>). An open part is a part the question asks: detail beyond the question, an example category the evidence does not show, and an exhaustiveness the question does not demand go in limitations, not in open parts (a question that asks for a complete set is held to its completeness coverage). A premise is never an open part: what the case takes as given is cited in premises (stance assumed), not held open. A part the question asks that the evidence in scope cannot settle may be held limited instead of open (status "limited", limited_by: the coverage record for the question, or a limitation whose reason is unavailable or excluded): the answer stays partial, and the report says that part is beyond the evidence rather than open to more work';

/** The ways out of premise_inconsistent, each on the record and none forcing either side (docs/adr/0011, "Premises"). */
export function PREMISE_WAYS_OUT(premise: string, rev: number): string {
  return `revise one answer (supersedes; a different stance, or without the premise); cite the finding that rebuts ${premise} in the contradiction's refs (premises [{id: "${premise}", rev: ${rev}, stance: "contradicted", refs: ["E-<seq>"]}]), which takes the premise to the operator as a dispute; narrow either citation's scope (scope {entities, times}) so the two no longer overlap; or answer conditionally (premises [{id: "${premise}", rev: ${rev}, stance: "assumed", conditional: true}]: "assuming ${premise}", said so in the report)`;
}

/** Which of `refs` name a standing finding or event, not superseded and under no dispute in force: what rebuts or supports a premise. */
export function rebuttingRefs(refs: readonly string[], bySeq: ReadonlyMap<number, LedgerEntry>, replaced: ReadonlyMap<number, number>, inForce: ReadonlySet<string>): string[] {
  return refs.filter((r) => {
    const e = bySeq.get(Number(r.replace(/^E-/, "")));
    return Boolean(e) && (e!.kind === "finding" || e!.kind === "event") && !replaced.has(e!.seq) && !inForce.has(e!.hash ?? ledgerHash(e!, "genesis"));
  });
}

/**
 * Why an answer's premise citations cannot stand against the register
 * (checked under the registers' lock), or null: each premise is in it, not
 * withdrawn, at the revision cited; a proposition under test is assumed only
 * conditionally; a premise scoped to named questions is assumed without a
 * condition only by an answer to one of them; and a citation's scope lies
 * inside its premise's.
 */
export function citationRefusal(citations: readonly PM.PremiseCitation[], reg: ReadonlyMap<string, PM.Premise>, question: string): string | null {
  for (const c of citations) {
    const p = reg.get(c.id);
    if (!p) return `premises cites ${c.id}, which is not in the premise register (questions view premises lists them)`;
    if (p.withdrawn) return `premises cites ${c.id}, withdrawn at ${p.withdrawn.at}: ${p.withdrawn.why}. An answer no longer rests on it: drop it, or cite what stands`;
    if (c.rev !== p.rev) return `premises cites ${c.id} at revision ${c.rev}, and it is at revision ${p.rev}: read it again (questions show ${c.id}) and cite rev ${p.rev}`;
    if (c.stance === "assumed" && !c.conditional && p.class === "proposition_under_test") return `${c.id} is a proposition under test (${p.authority === "agent" ? "proposed by an agent, not admitted by the operator" : "the operator put it under test"}): it is examined like any claim, never taken as given. Cite it supported or contradicted with the finding that shows it (refs), unresolved, or assumed conditionally (conditional: true: "assuming ${c.id}", and the report says the answer holds only if it does)`;
    if (c.stance === "assumed" && !c.conditional && p.scope.questions?.length && !p.scope.questions.includes(question)) return `${c.id} applies to ${p.scope.questions.join(", ")} (its scope), and this answers ${question}: assume it here only conditionally (conditional: true), or ask the operator to widen its scope (premise revise)`;
    if (c.scope) {
      const out = PM.scopeOutside(c.scope, PM.scopeAt(p, c.rev));
      if (out) return `premises: ${c.id}'s scope is narrower than the premise's or it is none: ${out}`;
    }
  }
  return null;
}


// --- the gate at done -----------------------------------------------------------------------

/**
 * A mechanical defect the finish line names before the run may end, with
 * what fixes it. `named_by` lists the standing limitations that name it: the
 * answers check passes once each defect is fixed or named, and a named
 * defect stays one. The finish line holds done on it under every stop
 * policy (finish-gate.ts holding): a question ends on a disposition under
 * the bar, never on a limitation that names it; the release counts it.
 */
export type LedgerDefect = {
  code: "no_answer" | "answer_support" | "answer_disputed" | "no_critic_act" | "open_contradiction" | "coverage_missing" | "negative_unreviewed" | "wording" | "coverage_stale" | "material_use" | "partial_output" | "evidence_stale" | "completeness_uncovered" | "sweep_pending" | "sweep_hits" | "sweep_partial" | "preparation_pending" | "premise_inconsistent";
  section?: string;
  seqs: number[];
  what: string;
  fix: string;
  named_by: number[];
  /** evidence_stale: the ledger seqs of the additions that stale the answer (acceptanceExcuses reads them). */
  additions?: number[];
};

export type LedgerGate = {
  /** Each wanted section's standing answer, or null. */
  answers: Record<string, LedgerEntry | null>;
  defects: LedgerDefect[];
  /** The defects no limitation names: what keeps the run from ending. */
  open: LedgerDefect[];
  /** Every standing answer's unsupported tokens, by seq (the release counts them). */
  unsupported: Record<number, string[]>;
  /** What the gate says and does not hold on (LedgerWarning). */
  warnings: LedgerWarning[];
};

/** The job statuses whose kept output is partial by an act, not by its own failure: cancelled by an agent or the harness, or stopped (docs/adr/0016). */
export const PARTIAL_STATUSES: ReadonlySet<string> = new Set(["cancelled", "stopped"]);

/**
 * The standing entries that cite the kept output of a cancelled or stopped
 * job without saying how they treat it (qualifies {ref, why}): by seq, each
 * such ref with the producing job and its status. A limitation says what
 * could not be done and is its own disposition; so is a search recorded
 * partial or failed, and a coverage record, whose coverage_actual, skipped
 * and failures say it. Pure: `producerOf(ref)` resolves a citation to the
 * job whose output it names and that job's status, following a digest or a
 * copy to the job that wrote those bytes (scripts/output-hygiene.ts builds
 * it from the store); a citation that names no job's output is null.
 */
export function partialOutputCites(entries: LedgerEntry[], producerOf: (ref: string) => { job: string; status: string } | null | undefined): Map<number, Array<{ ref: string; job: string; status: string }>> {
  const replaced = supersededBy(entries);
  const out = new Map<number, Array<{ ref: string; job: string; status: string }>>();
  for (const e of entries) {
    if (replaced.has(e.seq) || e.kind === "limitation" || e.kind === "coverage" || e.kind === "answer") continue;
    if (e.kind === "absence" && e.completion && e.completion !== "complete") continue;
    for (const ref of e.refs ?? []) {
      const p = producerOf(ref);
      if (!p || !PARTIAL_STATUSES.has(p.status)) continue;
      if ((e.qualifies ?? []).some((q) => q.ref === ref)) continue;
      out.set(e.seq, [...(out.get(e.seq) ?? []), { ref, job: p.job, status: p.status }]);
    }
  }
  return out;
}

/** Contradictions that stand and that nothing has weighed: no answer holds both with one as contrary evidence, no limitation names both. */
export function openContradictions(entries: LedgerEntry[]): Array<{ from: number; to: number }> {
  const replaced = supersededBy(entries);
  const answers = entries.filter((e) => e.kind === "answer" && !replaced.has(e.seq));
  const limits = entries.filter((e) => e.kind === "limitation" && !replaced.has(e.seq));
  return standingContradictions(entries).filter(({ from, to }) => {
    const weighed = answers.some((a) => {
      const contra = new Set((a.contrary ?? []).map((x) => x.seq));
      const all = new Set([...contra, ...(a.support ?? []).map((x) => x.seq)]);
      return all.has(from) && all.has(to) && (contra.has(from) || contra.has(to));
    });
    const named = limits.some((l) => {
      const c = limitationCites(l);
      return c.has(from) && c.has(to);
    });
    return !weighed && !named;
  });
}

/** Evidence added after the kickoff, as the ledger holds it (scripts/material.ts applyAddition): its external entry, its import, its inventory revision. */
export type EvidenceAddition = { seq: number; import: string; inventory_rev: number | null; at: string };

/** Each standing external entry of class acquired_evidence, in ledger order. */
export function evidenceAdditions(entries: LedgerEntry[]): EvidenceAddition[] {
  const replaced = supersededBy(entries);
  const out: EvidenceAddition[] = [];
  for (const e of entries) {
    if (e.kind !== "external" || e.source_class !== "acquired_evidence" || replaced.has(e.seq)) continue;
    const imp = typeof e.provenance?.import === "string" ? e.provenance.import : (/^import:([^/]+)/.exec((e.refs ?? [])[0] ?? "")?.[1] ?? "");
    if (!imp) continue;
    out.push({ seq: e.seq, import: imp, inventory_rev: typeof e.provenance?.inventory_rev === "number" ? e.provenance.inventory_rev : null, at: e.at });
  }
  return out;
}

/** The results evidence added later leaves stale until they are examined against it: a negative, a not determinable, a partial answer. An established answer is not. */
export const EVIDENCE_STALE_RESULTS: ReadonlySet<string> = new Set(["bounded_negative", "not_determinable", "partial"]);

/** Whether an entry rests on an import: its refs, its results or the declared scope of the jobs behind them name import:<id>. */
function namesImport(e: LedgerEntry, id: string): boolean {
  const re = new RegExp(`import:${id.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")}(?![A-Za-z0-9_-])`);
  return re.test(JSON.stringify([e.refs ?? [], e.result_refs ?? [], e.method ?? []]));
}

/** Whether an entry's refs name an import's objects: the import itself, or a file of it. */
export function namesImportObjects(e: Pick<LedgerEntry, "refs">, id: string): boolean {
  return (e.refs ?? []).some((r) => r === `import:${id}` || r.startsWith(`import:${id}/`));
}

/**
 * An entry's deltas on a question (DELTA_REL_KINDS): each rel of a delta's
 * kind whose `to` is an answer in that section, the answer standing or one
 * it corrects. How evidence the entry interprets bears on the question's
 * earlier conclusion.
 */
export function deltasFor(e: Pick<LedgerEntry, "rel">, section: string, bySeq: ReadonlyMap<number, LedgerEntry>): LedgerRel[] {
  return (e.rel ?? []).filter((r) => DELTA_REL_KINDS.has(r.kind) && bySeq.get(r.to)?.kind === "answer" && bySeq.get(r.to)?.section === section);
}

/**
 * Whether evidence added after an answer's coverage leaves the answer
 * stale (the calibration run sabfd76: the evidence that settled a question
 * came late, and its not-determinable answer stood). A standing answer to
 * a question whose result is bounded_negative, not_determinable or partial
 * (or a premise rejected on a search alone) is stale for each addition in
 * the ledger, whether or not the addition named the question, until the new
 * evidence was examined for it, another seat reviewed that examination, and
 * the examination says how the new evidence bears on the answer:
 * - examined and reviewed: the answer cites a coverage record for the
 *   question recorded after the addition that names the import among its
 *   objects and that another seat attested (its review), or cites an entry
 *   other than a coverage record that rests on the import (its refs,
 *   results or jobs name it) and that another seat attested. A one-line
 *   finding nobody else looked at clears nothing (the Fable review of
 *   batches 1-3).
 * - the delta (docs/adr/0013, "Late evidence: the reverse sweep and the
 *   delta"; the calibration run sb1b3c8 missed the late fact with the
 *   import cited 28 times): an entry that interprets the import (a
 *   standing entry recorded after the addition whose refs name the
 *   import's objects) carries a delta, a rel to the question's answer whose
 *   kind is supports, contradicts, adds_part, irrelevant or inconclusive
 *   (deltasFor), and it is the entry that examined the import, under the
 *   review the rule asks for: among the results of a coverage record the
 *   answer cites that names the import and another seat reviewed (its
 *   reviewer saw it), or an entry the answer cites (or cites as contrary)
 *   that rests on the import and another seat attested. A delta on an
 *   entry nobody else looked at, beside a coverage record somebody did,
 *   clears nothing: an "irrelevant" costs the same review as any other
 *   delta (the Fable review of the limits branch, P3-1).
 * The operator's acceptance of the question's limits after the addition
 * still excuses it (acceptanceExcuses). `coverage` lists the records it
 * cites recorded before the addition's entry; `unnamed` those recorded
 * after it that do not name the import; `unreviewed` those that name it
 * and entries resting on it that nobody else has attested yet;
 * `undelta` the entries so cited that interpret the import and carry no
 * delta; `unexamined` those that carry a delta outside the reviewed
 * examination; `nodelta` the additions examined and reviewed whose delta
 * is missing there. Null when nothing stales it.
 */
export function evidenceStale(answer: LedgerEntry, entries: LedgerEntry[], attestations: LedgerAttestation[]): { additions: EvidenceAddition[]; coverage: number[]; unnamed: number[]; unreviewed: number[]; undelta: number[]; unexamined: number[]; nodelta: number[] } | null {
  if (answer.kind !== "answer" || !answer.section?.startsWith("question:")) return null;
  const additions = evidenceAdditions(entries);
  if (!additions.length) return null;
  const bySeq = new Map(entries.map((e) => [e.seq, e]));
  const replaced = supersededBy(entries);
  if (replaced.has(answer.seq)) return null;
  const id = sectionAnswersId(answer.section);
  const result = NB.answerResult(answer);
  const cited = citedForQuestion(answer, bySeq, replaced, id);
  if (!result || !(EVIDENCE_STALE_RESULTS.has(result) || negativeByResult(result, cited))) return null;
  const cov = cited.filter((c) => c.kind === "coverage");
  const citedAll = [...(answer.support ?? []), ...(answer.limitations ?? [])].map((x) => bySeq.get(x.seq)).filter((e): e is LedgerEntry => Boolean(e) && !replaced.has((e as LedgerEntry).seq));
  // What may carry the delta: the entries the answer cites (its contrary too: new evidence that contradicts it), and the results of its coverage.
  const citedWithContrary = [...citedAll, ...(answer.contrary ?? []).map((x) => bySeq.get(x.seq)).filter((e): e is LedgerEntry => Boolean(e) && !replaced.has((e as LedgerEntry).seq))];
  const resultsOf = (c: LedgerEntry): LedgerEntry[] => (c.result_refs ?? []).filter((r) => /^E-\d+$/.test(r)).map((r) => bySeq.get(Number(r.slice(2)))).filter((e): e is LedgerEntry => Boolean(e) && !replaced.has((e as LedgerEntry).seq));
  // Attested by a seat that recorded neither it nor the answer.
  const reviewed = (e: LedgerEntry): boolean => {
    const authors = new Set([e.by, ...e.authors, answer.by, ...answer.authors]);
    const h = e.hash ?? ledgerHash(e, "genesis");
    return attestations.some((x) => attestationAct(x) === "attest" && x.target === h && !authors.has(x.by));
  };
  const namesAmongObjects = (c: LedgerEntry, imp: string) => (c.refs ?? []).some((r) => r === `import:${imp}` || r.startsWith(`import:${imp}/`));
  const stale: EvidenceAddition[] = [];
  const older = new Set<number>();
  const unnamed = new Set<number>();
  const unreviewed = new Set<number>();
  const undelta = new Set<number>();
  const unexamined = new Set<number>();
  const nodelta: number[] = [];
  for (const x of additions) {
    const covAfter = cov.filter((c) => c.seq > x.seq);
    const resting = answer.seq > x.seq ? citedAll.filter((e) => e.kind !== "coverage" && e.seq !== x.seq && namesImport(e, x.import)) : [];
    // The reviewed examinations of the import: a coverage record naming it that another seat attested, and an entry the answer cites that rests on it, attested.
    const examiners = covAfter.filter((c) => namesAmongObjects(c, x.import) && reviewed(c));
    const examined = examiners.length > 0 || resting.some(reviewed);
    // The entries that interpret the import, cited by the answer or by its coverage recorded since.
    const interpreting = [...new Map([...citedWithContrary, ...covAfter.flatMap(resultsOf)].map((e) => [e.seq, e])).values()].filter((e) => e.seq > x.seq && e.kind !== "coverage" && e.kind !== "answer" && namesImportObjects(e, x.import));
    // A delta clears it only on the entry that examined the import: a result of a reviewed coverage record naming it, or an entry the answer cites that another seat attested.
    const carriers = new Set(examiners.flatMap(resultsOf).map((e) => e.seq));
    const carried = (e: LedgerEntry) => carriers.has(e.seq) || (answer.seq > x.seq && citedWithContrary.some((c) => c.seq === e.seq) && reviewed(e));
    const withDelta = interpreting.filter((e) => deltasFor(e, answer.section!, bySeq).length);
    if (withDelta.some(carried)) continue;
    stale.push(x);
    if (examined) nodelta.push(x.seq);
    for (const e of interpreting) if (!deltasFor(e, answer.section!, bySeq).length) undelta.add(e.seq);
    for (const e of withDelta) unexamined.add(e.seq);
    for (const c of cov) {
      if (c.seq < x.seq) older.add(c.seq);
      else if (!namesAmongObjects(c, x.import)) unnamed.add(c.seq);
      else if (!reviewed(c)) unreviewed.add(c.seq);
    }
    for (const e of resting) if (!reviewed(e)) unreviewed.add(e.seq);
  }
  const sorted = (xs: Set<number>) => [...xs].sort((a, b) => a - b);
  return stale.length ? { additions: stale, coverage: sorted(older), unnamed: sorted(unnamed), unreviewed: sorted(unreviewed), undelta: sorted(undelta), unexamined: sorted(unexamined), nodelta } : null;
}

/**
 * The defects an operator's acceptance of a question excuses on it: a
 * partial store sweep, and evidence_stale for evidence added at or before
 * the ledger's head when the acceptance was made (`acceptedAt`, the
 * acceptance's ledger_seq): the operator took the question's limits
 * knowing that evidence. Evidence added after it, and every other defect of
 * the negative bar (ACCEPTANCE_NEVER_EXCUSES), is not excused.
 */
export function acceptanceExcuses(d: Pick<LedgerDefect, "code" | "additions">, acceptedAt: number | null | undefined): boolean {
  if (d.code === "sweep_partial") return true;
  if (d.code === "evidence_stale") return typeof acceptedAt === "number" && (d.additions ?? []).length > 0 && (d.additions ?? []).every((n) => n <= acceptedAt);
  return !ACCEPTANCE_NEVER_EXCUSES.has(d.code);
}

/** The defects an acceptance never excuses (but evidence_stale, as acceptanceExcuses says): the negative bar's, and material the case policy forbids. */
export const ACCEPTANCE_NEVER_EXCUSES: ReadonlySet<string> = new Set(["coverage_missing", "coverage_stale", "negative_unreviewed", "wording", "material_use", "evidence_stale", "completeness_uncovered", "sweep_pending", "sweep_hits"]);

/** Whether a coverage record says what a completeness claim needs: the areas it reached, each named. */
export function coverageNamesAreas(c: LedgerEntry): boolean {
  return Boolean(c.areas && NB.COVERAGE_AREAS.every((a) => c.areas?.[a]));
}

/**
 * What a negative's store sweeps hold (store-sweep.ts): each standing
 * coverage record it cites for its question that names looked_for, whose
 * sweep is pending (no line yet), found its strings in objects the record
 * does not name (hits), or was left partial by its budget (unsearched).
 * For a negative the bar holds, a partial answer on a material question,
 * and an answer that says the event did not happen; empty for any other.
 */
export type SweepHold = { code: "sweep_pending" | "sweep_hits" | "sweep_partial"; coverage: LedgerEntry; sweep: SweepRecord | null; unexamined?: UnexaminedHit[] };
export function sweepHolds(answer: LedgerEntry, entries: LedgerEntry[], sweeps: readonly SweepRecord[], disputes: LedgerDispute[] = [], material = true): SweepHold[] {
  if (answer.kind !== "answer" || !answer.section?.startsWith("question:")) return [];
  const bySeq = new Map(entries.map((e) => [e.seq, e]));
  const replaced = supersededBy(entries);
  const id = sectionAnswersId(answer.section);
  const result = NB.answerResult(answer);
  const cited = citedForQuestion(answer, bySeq, replaced, id);
  if (!result || !(negativeByResult(result, cited) || (result === "partial" && material) || answer.asserts_absence === true)) return [];
  const out: SweepHold[] = [];
  for (const c of cited) {
    if (c.kind !== "coverage" || coverageProblems(c, entries, disputes).length) continue;
    // An object an earlier sweep for its question found a hit in, named
    // here with no entry among its results saying what it showed, holds as
    // a hit does (store-sweep.ts unexaminedHits): naming is not examining.
    const unexamined = unexaminedHits(c, entries, sweeps, replaced);
    const h = c.hash ?? ledgerHash(c, "genesis");
    const sw = c.looked_for?.length ? (sweeps.filter((x) => x.target === h).at(-1) ?? null) : null;
    if (c.looked_for?.length && !sw) out.push({ code: "sweep_pending", coverage: c, sweep: null });
    if (sw?.hits.length || unexamined.length) out.push({ code: "sweep_hits", coverage: c, sweep: sw, ...(unexamined.length ? { unexamined } : {}) });
    if (sw?.unsearched.length) out.push({ code: "sweep_partial", coverage: c, sweep: sw });
  }
  return out;
}

/**
 * The acquisition_none_why a case under more_evidence: no gives (the ctf
 * preset): the case admits no further evidence, so an ask would be declined
 * at once, and naming the policy says why none was opened. Seats opened
 * asks in the finish tail only to satisfy the rule, each declined at once.
 */
export const NO_MORE_EVIDENCE_NONE_WHY = "the case policy admits no further evidence (more_evidence: no): an acquisition ask would be declined at once, so none was opened";
/** The fix the no_acquisition_ask warning gives under more_evidence: no: the policy as the reason, never an ask. */
export function noMoreEvidenceAskFix(coverage: number[], answer: number): string {
  return `this case admits no further evidence (more_evidence: no), so open no acquisition ask: record the coverage again${coverage.length ? ` with supersedes=${coverage[0]}` : ""} with acquisition_none_why: "${NO_MORE_EVIDENCE_NONE_WHY}", and the answer again with supersedes=${answer} citing it`;
}

/**
 * A warning the gate says and does not hold on: shown with the answers
 * check, counted in the finish line's note, and delivered where the
 * decision is made (finish.ts warningsAt): in the reply to the record that
 * writes the answer, in its review offer and the reply to an attest on it,
 * and in finish status. no_acquisition_ask: a not-determinable answer names
 * no ask, nor why none. partial_all_parts_established: a partial answer
 * every review of which holds every part it weighed established.
 * lead_findings_uncited: findings and events tied to the question that
 * its answer does not reach: held by two seats under its leads, naming it,
 * or linked by rel to an entry its answer cites; or one seat's naming it
 * that another question's answer relies on. preparation_missing: a
 * material negative resting on a source whose broad extraction has not
 * produced (extensions/preparation.ts), where it is not held for it.
 * late_evidence_hits: what the reverse sweep of evidence added late found
 * of a question's looked_for strings (store-sweep.ts), in objects no entry
 * the answer reaches names, where the addition does not stale the answer.
 * premise_disputed, premise_revised, premise_withdrawn: an answer that
 * assumes a premise disputed on a rebutting finding, or cites a revision
 * revised since, or a premise withdrawn. premise_inconsistent: the premise
 * conflict that holds a material question, on a question the operator
 * marked not material. part_omitted: a part of the question a review says
 * the answer leaves out. no_locator_or_derivation: an answer held
 * established on source-first reviews none of which vouches for a value by
 * bytes or by derivation. premise_untested: a partial answer to a question
 * that presumes an event, neither it nor a review of it testing that premise
 * (docs/adr/0011, "What a question presumes").
 * `seqs` opens with the answer's.
 */
export type LedgerWarning = { code: "no_acquisition_ask" | "partial_all_parts_established" | "lead_findings_uncited" | "preparation_missing" | "late_evidence_hits" | "premise_disputed" | "premise_revised" | "premise_withdrawn" | "premise_inconsistent" | "part_omitted" | "no_locator_or_derivation" | "premise_untested"; section: string; seqs: number[]; what: string; fix: string };

/** A warning in the words every point says it with: what, then the fix. */
export function warningWords(w: Pick<LedgerWarning, "what" | "fix">): string {
  return `${w.what}. ${w.fix}`;
}

/** A question's section as the register names it: Q-<n> for a numbered one, the section otherwise. */
function questionName(id: string, section: string): string {
  return /^\d+$/.test(id) ? `Q-${Number(id)}` : section;
}

/**
 * Every entry an answer reaches: those it cites (support, contrary,
 * limitations, a downgrade's evidence), and through them each entry they
 * name in turn (rel, a coverage record's result_refs and result_bound, a
 * cited answer's own citations), with the correction that stands in the
 * place of each. Refs only: nothing is read of what an entry says.
 */
export function answerReach(a: LedgerEntry, bySeq: ReadonlyMap<number, LedgerEntry>, replaced: Map<number, number>): Set<number> {
  const eseq = (r: string): number | null => {
    const m = /^E-(\d+)$/i.exec(String(r).trim());
    return m ? Number(m[1]) : null;
  };
  const stack: number[] = [...(a.support ?? []), ...(a.contrary ?? []), ...(a.limitations ?? [])].map((x) => x.seq);
  for (const r of a.downgrade?.evidence ?? []) {
    const n = eseq(r);
    if (n !== null) stack.push(n);
  }
  const seen = new Set<number>();
  while (stack.length) {
    const seq = stack.pop() as number;
    if (seen.has(seq)) continue;
    seen.add(seq);
    const head = standingSeq(seq, replaced);
    if (head !== seq) stack.push(head);
    const e = bySeq.get(seq);
    if (!e) continue;
    for (const r of e.rel ?? []) stack.push(r.to);
    for (const r of e.result_refs ?? []) {
      const n = eseq(r);
      if (n !== null) stack.push(n);
    }
    for (const x of [...(e.result_bound ?? []), ...(e.support ?? []), ...(e.contrary ?? []), ...(e.limitations ?? [])]) stack.push(x.seq);
  }
  return seen;
}

/** Whether two seats hold an entry: two recorded it (a second author), or a seat other than its authors attested it. */
export function heldByTwoSeats(e: LedgerEntry, attestations: readonly LedgerAttestation[]): boolean {
  const authors = new Set([e.by, ...(e.authors ?? [])]);
  if (authors.size >= 2) return true;
  const h = e.hash ?? ledgerHash(e, "genesis");
  // A line from before version 2 names its entry by seq; either act by another seat counts (a same_content one is a second author).
  return attestations.some((x) => (x.target ? x.target === h : x.seq === e.seq) && !authors.has(x.by));
}

/** The entries an answer cites itself (support, contrary, limitations, a downgrade's evidence), each with the correction that stands in its place. */
export function answerCites(a: LedgerEntry, replaced: Map<number, number>): Set<number> {
  const out = new Set<number>();
  const add = (n: number) => {
    out.add(n);
    out.add(standingSeq(n, replaced));
  };
  for (const x of [...(a.support ?? []), ...(a.contrary ?? []), ...(a.limitations ?? [])]) add(x.seq);
  for (const r of a.downgrade?.evidence ?? []) {
    const m = /^E-(\d+)$/i.exec(String(r).trim());
    if (m) add(Number(m[1]));
  }
  return out;
}

/** An entry a question's answer leaves out (lead_findings_uncited), with what ties it to the question (the leads it was recorded under, its own `answers`, its `rel` to an entry the answer cites), how many seats hold it, and the other questions whose standing answers rely on it. */
export type UncitedEntry = { seq: number; kind: "finding" | "event"; leads: readonly string[]; names: boolean; rel: LedgerRel[]; seats: 1 | 2; relied: string[] };

/**
 * What the registers tie to question `id` that its answer `a` does not
 * reach (answerReach): each standing finding or event, under no dispute in
 * force, that either
 * - two seats hold (heldByTwoSeats) and the lead register recorded under a
 *   lead of the question (`under`, leads.ts questionLeadEntries), or that
 *   names the question in its own `answers`, or whose `rel` supports or
 *   contradicts an entry the answer cites (answerCites), or weighs late
 *   evidence against it (DELTA_REL_KINDS); a `duplicates` or `derived_from`
 *   rel says what an entry repeats or comes from, and ties it to nothing
 *   (the Fable review of the limits branch, P3-6); or
 * - one seat holds, names the question in its own `answers`, and another
 *   question's standing answer reaches (`others`, each standing answer's
 *   reach by its section): its author tied it to this question, and the
 *   record already relies on it for a conclusion.
 * One seat's entry that no other answer relies on does not count. In
 * ledger order, every one. Registers and refs only.
 */
export function questionUncited(
  a: LedgerEntry,
  id: string,
  o: { bySeq: ReadonlyMap<number, LedgerEntry>; replaced: Map<number, number>; entries: readonly LedgerEntry[]; disputes: readonly DisputeInForce[]; attestations: readonly LedgerAttestation[]; under?: ReadonlyMap<number, readonly string[]>; others?: ReadonlyMap<string, ReadonlySet<number>> },
): UncitedEntry[] {
  const reach = answerReach(a, o.bySeq, o.replaced);
  const cites = answerCites(a, o.replaced);
  const disputed = new Set(o.disputes.map((d) => d.target));
  const out: UncitedEntry[] = [];
  const seqs = new Set<number>(o.under?.keys() ?? []);
  const ties = (r: LedgerRel) => DELTA_REL_KINDS.has(r.kind) && cites.has(r.to);
  for (const e of o.entries) if ((e.kind === "finding" || e.kind === "event") && ((e.answers ?? []).some((x) => sectionKey(x) === id) || (e.rel ?? []).some(ties))) seqs.add(e.seq);
  for (const seq of [...seqs].sort((x, y) => x - y)) {
    if (seq === a.seq || reach.has(seq) || o.replaced.has(seq)) continue;
    const e = o.bySeq.get(seq);
    if (!e || (e.kind !== "finding" && e.kind !== "event")) continue;
    if (disputed.has(e.hash ?? ledgerHash(e, "genesis"))) continue;
    const names = (e.answers ?? []).some((x) => sectionKey(x) === id);
    const two = heldByTwoSeats(e, o.attestations);
    const relied = [...(o.others ?? [])].filter(([section, reach]) => section !== a.section && reach.has(seq)).map(([section]) => section);
    if (!two && !(names && relied.length)) continue;
    out.push({ seq, kind: e.kind, leads: o.under?.get(seq) ?? [], names, rel: (e.rel ?? []).filter(ties), seats: two ? 2 : 1, relied });
  }
  return out;
}

/**
 * What a partial answer's warning says of a case premise: what the case
 * brief or the goal states as given is a premise, named, never a part held
 * open (the run s993d40: two complete answers stood partial on whether the
 * person the brief names did it).
 */
export const CASE_PREMISE_WORDS = 'what the case brief or the goal states as given (who the subject is, whose device it is, the scenario\'s facts) is a premise of the examination, not a part to prove again: name it ("rests on the case premise that …") and answer on the evidence for the rest';

/**
 * The ledger gate: each wanted section's answer (question:<id>, summary,
 * narrative), what keeps it from standing, whether a critic acted on it, and
 * the contradictions left open. Pure over what was read: the caller reads
 * the files (and which entries rest on a failed job) and verifies the chains.
 * `underLeads` is what the lead register recorded under each question's
 * leads (leads.ts questionLeadEntries): by question id, each entry with the
 * leads it was recorded under; without it (a lead register whose chain is
 * broken) the lead_findings_uncited warning looks only at what the ledger
 * itself ties to the question: an entry's `answers`, its `rel`.
 * `preparation` is the sources' broad extractions as the store journal's
 * receipts say them, and each coverage record's reach into those sources
 * (extensions/preparation.ts preparationFacts); without it nothing is held
 * or warned on a preparation. `imports` is the additions' reverse sweeps
 * (store-sweep.ts readImportSweeps): their hits are said where a question's
 * answer is stale by the addition, and warned of where its answer does not
 * reach them; they hold nothing by themselves.
 * `premises` is the premise register (premises.ts, folded from the question
 * chain): the pairs of standing answers that assume and contradict one
 * premise revision over overlapping scopes hold both questions
 * (premise_inconsistent) until reconciled on the record; without it a
 * citation's scope is its own, or unbounded.
 * `presumes` is what each question takes as happened, by its section id
 * (questions.ts presumptionsOf): a partial answer to one that neither it
 * nor a review tests the premise of is warned (premise_untested); without
 * it nothing is.
 */
export function ledgerGate(o: { entries: LedgerEntry[]; attestations: LedgerAttestation[]; disputes: LedgerDispute[]; sections: string[]; failed?: Map<number, string[]>; bar?: (sectionId: string) => { material: boolean; existence: boolean; completeness?: boolean }; partial?: Map<number, Array<{ ref: string; job: string; status: string }>>; sweeps?: readonly SweepRecord[]; imports?: readonly ImportSweepRecord[]; moreEvidence?: "no" | "ask" | "yes"; underLeads?: ReadonlyMap<string, ReadonlyMap<number, readonly string[]>>; preparation?: PR.PreparationFacts; premises?: ReadonlyMap<string, PM.Premise>; presumes?: ReadonlyMap<string, PM.Presumption> }): LedgerGate {
  const { entries } = o;
  const bySeq = new Map(entries.map((e) => [e.seq, e]));
  const replaced = supersededBy(entries);
  const limits = entries.filter((e) => e.kind === "limitation" && !replaced.has(e.seq));
  const problems = answerProblems(entries, o.disputes, o.failed);
  const standingD = disputesInForce(entries, o.disputes);
  // What each question's standing answer reaches, by its section, read once when asked for (lead_findings_uncited: one seat's entry counts where another answer relies on it).
  let othersMemo: Map<string, Set<number>> | null = null;
  const othersReach = (): Map<string, Set<number>> => {
    othersMemo ??= new Map(entries.filter((e) => e.kind === "answer" && e.section?.startsWith("question:") && !replaced.has(e.seq)).map((e) => [e.section as string, answerReach(e, bySeq, replaced)]));
    return othersMemo;
  };
  const defects: LedgerDefect[] = [];
  const answers: Record<string, LedgerEntry | null> = {};
  const unsupported: Record<number, string[]> = {};
  const warnings: LedgerWarning[] = [];
  const namedFor = (seq: number) => limits.filter((l) => limitationCites(l).has(seq)).map((l) => l.seq);
  // The premises (premises.ts): every standing answer's citations, and the
  // pairs that assume and contradict one premise revision over overlapping
  // scopes, each with the standing finding its contradiction names, if any.
  const inForceTargets = new Set(standingD.map((d) => d.target));
  const citing: PM.CitingAnswer[] = entries.filter((e) => e.kind === "answer" && e.section?.startsWith("question:") && !replaced.has(e.seq) && e.premises?.length).map((e) => ({ seq: e.seq, section: e.section as string, citations: e.premises! }));
  const conflicts = citing.length ? PM.premiseConflicts(citing, o.premises, (refs) => rebuttingRefs(refs, bySeq, replaced, inForceTargets)) : [];
  for (const raw of o.sections) {
    const sec = answerSection(raw);
    if (!sec.ok) continue;
    const a = entries.find((e) => e.kind === "answer" && e.section === sec.section && !replaced.has(e.seq)) ?? null;
    answers[sec.section] = a;
    const id = sectionAnswersId(sec.section);
    if (!a) {
      defects.push({
        code: "no_answer",
        section: sec.section,
        seqs: [],
        what: `${sec.section} has no answer`,
        fix: `record kind=answer section=${sec.section} citing E-<seq> of the entries it rests on${sec.section.startsWith("question:") ? ` (at least one recorded with answers=["${id}"])` : ""}; if the ledger cannot answer it, record kind=limitation with answers=["${id}"] saying why`,
        named_by: limits.filter((l) => (l.answers ?? []).some((x) => sectionKey(x) === id)).map((l) => l.seq),
      });
      continue;
    }
    if (a.unsupported_tokens?.length) unsupported[a.seq] = a.unsupported_tokens;
    const p = problems.get(a.seq);
    if (p?.length) {
      defects.push({ code: "answer_support", section: sec.section, seqs: [a.seq], what: `answer #${a.seq} (${sec.section}) no longer stands on its support: ${p.join("; ")}`, fix: `record the answer again with supersedes=${a.seq}, citing what stands now (a correction, or qualifies [{ref: "E-<seq>", why}] for a disputed or failed-job entry), or record a limitation citing E-${a.seq} that says why it stands as it is`, named_by: namedFor(a.seq) });
    }
    const target = a.hash ?? ledgerHash(a, "genesis");
    const against = standingD.filter((d) => d.target === target);
    if (against.length) {
      const inherited = against.filter((d) => d.inherited_from !== undefined);
      defects.push({
        code: "answer_disputed",
        section: sec.section,
        seqs: [a.seq],
        what: `answer #${a.seq} (${sec.section}) is disputed by ${against.map((d) => `${d.by}: ${d.why}${d.inherited_from !== undefined ? ` (raised on #${d.inherited_from}, which it corrects: a correction does not answer a dispute)` : ""}`).join("; ")}`,
        fix: inherited.length
          ? `the disputer reads the correction and withdraws the dispute when it answers it (dispute withdraw=true on #${a.seq}, with why), or disputes it again; or record a limitation citing E-${a.seq}`
          : `answer the dispute: correct the answer (record it again with supersedes=${a.seq}) and have the disputer withdraw it (dispute withdraw=true, with why) once the correction answers it, or record a limitation citing E-${a.seq}`,
        named_by: namedFor(a.seq),
      });
    }
    // The negative bar, on an answer that states its result (one recorded
    // before results reads as it always did): a material negative rests on
    // a standing coverage record whose results still stand and is reviewed
    // by another seat, and an answer is worded as what was not found where,
    // whatever its result, unless the bar for "it did not happen" is met.
    // A premise rejected on a search alone is a negative too. None of these
    // is excused by a limitation.
    const result = NB.answerResult(a);
    const bar = sec.section.startsWith("question:") ? (o.bar?.(id) ?? { material: true, existence: false }) : null;
    const cited = citedForQuestion(a, bySeq, replaced, id);
    const negativeLike = negativeByResult(result, cited);
    const review = negativeLike ? negativeReview(a, entries, o.attestations, o.disputes) : null;
    const cov = cited.filter((c) => c.kind === "coverage" && !review?.stale.some((x) => x.seq === c.seq));
    if (bar && result && negativeLike) {
      for (const st of review?.stale ?? []) {
        defects.push({ code: "coverage_stale", section: sec.section, seqs: [a.seq, st.seq], what: `answer #${a.seq} (${sec.section}) rests on coverage record E-${st.seq}, which no longer says what its search found: ${st.problems.join("; ")}`, fix: `record the coverage again with supersedes=${st.seq} over the results that stand now, and the answer again with supersedes=${a.seq} citing it; another seat reviews it again`, named_by: [] });
      }
      const what = result === "premise_not_supported" ? "a premise rejected on a search alone (no finding shows it false)" : NB.resultWords(result);
      if (bar.material && !cov.length) {
        defects.push({ code: "coverage_missing", section: sec.section, seqs: [a.seq], what: `answer #${a.seq} (${sec.section}) is ${what} on a material question and rests on no standing coverage record`, fix: `record kind=coverage with answers=["${id}"] (what was searched, over which objects, how, what was covered, skipped and failed, the results, the alternatives, the detection opportunity) and record the answer again with supersedes=${a.seq} citing it`, named_by: [] });
      }
      if (bar.material && !review?.reviewed) {
        defects.push({ code: "negative_unreviewed", section: sec.section, seqs: [a.seq, ...cov.map((c) => c.seq)], what: `answer #${a.seq} (${sec.section}) is a negative (unreviewed): ${what} on a material question, and no other seat has reviewed it`, fix: `a seat that recorded neither it nor its coverage record attests #${a.seq}${cov.length ? ` or ${cov.map((c) => `#${c.seq}`).join(", ")}` : ""} with review {detection, reproduced, other_route}: whether it challenged the detection assumptions, reproduced a decisive check, tried a materially different route, each with what it did or why not`, named_by: [] });
      }
    }
    // Evidence added since the answer's coverage (whether or not the
    // addition named the question): a negative, a not determinable or a
    // partial answer is examined against it before it stands again. Fixed,
    // never named.
    // The reverse sweeps' hits on this question (store-sweep.ts): said
    // with the stale answer they bear on, warned of otherwise; they hold
    // nothing by themselves.
    const importHits = bar && o.imports?.length ? importHitsFor(id, o.imports) : [];
    const stale = bar && result ? evidenceStale(a, entries, o.attestations) : null;
    if (bar && result) {
      const st = stale;
      if (st) {
        const imports = [...new Set(st.additions.map((x) => x.import))];
        const first = st.additions[0]!;
        const list = (xs: number[]) => xs.map((n) => `E-${n}`).join(", ");
        const hitsHere = importHits.filter((x) => st.additions.some((y) => y.seq === x.sweep.seq));
        const importWords = imports.map((i) => `import:${i}`).join(", ");
        defects.push({
          code: "evidence_stale",
          section: sec.section,
          seqs: [a.seq, ...st.coverage, ...st.unnamed, ...st.unreviewed, ...st.undelta, ...st.unexamined],
          additions: st.additions.map((x) => x.seq),
          what: `answer #${a.seq} (${sec.section}) is ${NB.resultWords(result)}: new evidence since its coverage (${st.additions.map((x) => `${x.import}, E-${x.seq}${x.inventory_rev !== null ? `, inventory revision ${x.inventory_rev}` : ""}`).join("; ")}); re-examine against it${st.coverage.length ? `. Its coverage record${st.coverage.length === 1 ? "" : "s"} ${list(st.coverage)} ${st.coverage.length === 1 ? "was" : "were"} recorded before the addition's entry E-${first.seq}` : ""}${st.unnamed.length ? `; ${list(st.unnamed)}, recorded after it, ${st.unnamed.length === 1 ? "does" : "do"} not name ${importWords} among its objects` : ""}${st.unreviewed.length ? `; ${list(st.unreviewed)} ${st.unreviewed.length === 1 ? "examines" : "examine"} it and no other seat has reviewed ${st.unreviewed.length === 1 ? "it" : "them"} yet` : ""}${st.nodelta.length ? `; it was examined and reviewed, and nothing it cites says how the new evidence bears on the answer (a delta)` : ""}${st.undelta.length ? `; ${list(st.undelta)} ${st.undelta.length === 1 ? "interprets" : "interpret"} it with no delta` : ""}${st.unexamined.length ? `; ${list(st.unexamined)} ${st.unexamined.length === 1 ? "carries a delta" : "carry deltas"} that no other seat reviewed: ${st.unexamined.length === 1 ? "it is" : "they are"} not among the results of a reviewed coverage record naming the import, nor attested` : ""}${hitsHere.length ? `. The reverse sweep found what this question's coverage looked for in it: ${hitsHere.map(importHitWords).join("; ")}` : ""}`,
          fix: `examine ${importWords} for ${sec.section}${hitsHere.length ? ` (each object the reverse sweep names first)` : ""}: record what it shows as an entry whose refs name the import's files, with a delta, rel [{to: ${a.seq}, kind: supports | contradicts | adds_part | irrelevant | inconclusive}] (how the new evidence bears on this answer: it supports it, contradicts it, adds a part it left open, is irrelevant to it within its scope, or cannot say); record kind=coverage with answers=["${id}"] naming the import (or its files) among its objects and that entry among its results; have another seat review it (attest it with review); and record the answer again with supersedes=${a.seq} citing it. An entry resting on the new evidence with its delta, cited by the answer, clears it too once another seat has attested it. Or the operator accepts the question's limits after the evidence came (question accept)`,
          named_by: [],
        });
      }
    }
    // A reverse sweep's hit this answer does not reach, where the addition
    // does not stale it (an established answer, or one examined since): a
    // warning, never a hold (docs/adr/0013, "Late evidence: the reverse
    // sweep and the delta").
    if (importHits.length) {
      const reach = answerReach(a, bySeq, replaced);
      const staledBy = new Set((stale?.additions ?? []).map((x) => x.seq));
      const left = importHits.filter((x) => !staledBy.has(x.sweep.seq) && !importHitExamined(x, reach, bySeq, replaced));
      if (left.length) {
        const q = questionName(id, sec.section);
        warnings.push({
          code: "late_evidence_hits",
          section: sec.section,
          seqs: [a.seq, ...[...new Set(left.flatMap((x) => x.records))].sort((x, y) => x - y)],
          what: `answer #${a.seq} (${sec.section}) does not reach what the reverse sweep of evidence added late found for ${q}: ${left.map((x) => `import:${x.sweep.import} (E-${x.sweep.seq}): ${importHitWords(x)}`).join("; ")}`,
          fix: `examine each object named and record what it shows for ${q}: an entry whose refs name the object, with a delta rel [{to: ${a.seq}, kind: supports | contradicts | adds_part | irrelevant | inconclusive}], and record the answer again with supersedes=${a.seq} citing it (or a coverage record citing it among its results). A hit is a string found, not a fact: weigh it, and say so if it does not bear on the question`,
        });
      }
    }
    // A completeness claim ("every file", "all connections"): an established
    // or partial answer rests on a coverage record for the question that
    // says what was searched, area by area. Without one it holds the gate as
    // an uncovered negative does. Fixed, never named.
    if (bar && result && (result === "established" || result === "partial") && bar.completeness) {
      const standingCov = cited.filter((c) => c.kind === "coverage" && !coverageProblems(c, entries, o.disputes).length);
      if (!standingCov.some(coverageNamesAreas)) {
        defects.push({
          code: "completeness_uncovered",
          section: sec.section,
          seqs: [a.seq, ...standingCov.map((c) => c.seq)],
          what: `answer #${a.seq} (${sec.section}) is ${NB.resultWords(result)} on a question that asks for a complete set, and ${standingCov.length ? `its coverage record${standingCov.length === 1 ? "" : "s"} ${standingCov.map((c) => `E-${c.seq}`).join(", ")} ${standingCov.length === 1 ? "does" : "do"} not say which areas the search reached` : "it rests on no standing coverage record that says what was searched"}`,
          fix: `record kind=coverage with answers=["${id}"]: the objects searched, how, and areas {${NB.COVERAGE_AREAS.join(", ")}} (each searched, skipped or not_applicable; what was skipped, and why, in skipped), then record the answer again with supersedes=${a.seq} citing it`,
          named_by: [],
        });
      }
    }
    // The store sweep (store-sweep.ts): a negative is checked against every
    // output the run holds, not only its coverage's sources. Read only where
    // the caller read the sweeps. Pending holds as an unreviewed negative
    // does; a hit in an object the record does not name holds until the
    // record is revised to name it, or the answer is; a partial sweep holds
    // until the operator accepts the question's limits.
    if (bar && result && o.sweeps) {
      for (const hold of sweepHolds(a, entries, o.sweeps, o.disputes, bar.material)) {
        const c = hold.coverage;
        const sw = hold.sweep;
        if (hold.code === "sweep_pending") {
          defects.push({ code: "sweep_pending", section: sec.section, seqs: [a.seq, c.seq], what: `answer #${a.seq} (${sec.section}) rests on coverage record E-${c.seq}, whose store sweep for ${c.looked_for!.map((t) => `"${t}"`).join(", ")} has not finished (pending)`, fix: "wait for the sweep: the hub runs it when the record is written and records it in ledger/sweeps.jsonl (the finish line runs one lost with its process); then examine what it found", named_by: [] });
        } else if (hold.code === "sweep_hits") {
          const words = (sw?.hits ?? []).map((h) => `"${h.term}" in ${h.ref}${h.also?.length ? ` (also ${h.also.join(", ")})` : ""} (${h.count} time${h.count === 1 ? "" : "s"}, first at byte ${h.first_offset}${h.encodings.includes("utf-16le") ? `, ${h.encodings.join(" and ")}` : ""})`);
          const unexamined = hold.unexamined ?? [];
          const named = unexamined.map((u) => `${u.ref}${u.also.length ? ` (also ${u.also.join(", ")})` : ""} (${u.terms.map((t) => `"${t}"`).join(", ")}, found by the sweep of E-${u.found_by})`);
          const said = [
            ...(words.length ? [`the store sweep for coverage record E-${c.seq} found what it looked for in objects the record does not name: ${words.join("; ")}`] : []),
            ...(named.length ? [`coverage record E-${c.seq} names ${unexamined.length === 1 ? "an object" : `${unexamined.length} objects`} an earlier sweep found hits in with no entry among its results that says what ${unexamined.length === 1 ? "it" : "each"} showed: ${named.join("; ")}. Naming a hit is not examining it`] : []),
          ];
          defects.push({
            code: "sweep_hits",
            section: sec.section,
            seqs: [a.seq, c.seq],
            what: `answer #${a.seq} (${sec.section}) is ${NB.resultWords(result)}, and ${said.join("; and ")}`,
            fix: `examine each object the sweep names and record what it showed: one entry per object (a finding, an event or a limitation whose refs name the object itself), or one absence whose refs list several (a search that found nothing that bears on the question in them), written after the sweep; then record the coverage again with supersedes=${c.seq} naming each in refs, with what it showed: those entries in result_refs (and coverage_actual), and the answer again with supersedes=${a.seq} citing it; or record the answer again on what those objects show`,
            named_by: [],
          });
        } else {
          defects.push({
            code: "sweep_partial",
            section: sec.section,
            seqs: [a.seq, c.seq],
            what: `answer #${a.seq} (${sec.section}) rests on coverage record E-${c.seq}, whose store sweep is partial: ${sw!.searched.objects} object(s) searched, not searched: ${sw!.unsearched.map((u) => `${u.ref} (${u.why})`).join("; ")}`,
            fix: `a partial sweep is not a clean one: record the coverage again with supersedes=${c.seq} (its sweep runs again; SWARM_SWEEP_MAX_BYTES and SWARM_SWEEP_MAX_SEC set its budget), or the operator accepts the question's limits`,
            named_by: [],
          });
        }
      }
    }
    // A source's broad extraction (extensions/preparation.ts): a material
    // negative that says the event did not happen, or whose coverage is
    // complete over a source, holds while that source's broad extraction is
    // planned or attempted (a wait on work already queued or offered, never
    // a demand to find something); produced, partial, failed or declined
    // releases it, and so does the operator's acceptance. Every other
    // material negative on a source whose extraction has not produced is
    // warned. Receipts and refs only.
    if (bar?.material && result && (negativeLike || a.asserts_absence === true) && o.preparation?.sources.size) {
      const covs = cited.filter((c) => c.kind === "coverage");
      const found = PR.preparationFindings(a, covs, o.preparation);
      const what = NB.resultWords(result);
      if (found.hold.length) {
        defects.push({
          code: "preparation_pending",
          section: sec.section,
          seqs: [a.seq, ...[...new Set(found.hold.flatMap((h) => h.coverage))].sort((x, y) => x - y)],
          what: `answer #${a.seq} (${sec.section}) is ${what} and ${found.hold.map((h) => `${h.claim === "absence" ? "says the event did not happen" : `rests on coverage record${h.coverage.length === 1 ? "" : "s"} ${h.coverage.map((n) => `E-${n}`).join(", ")}, complete`} over ${h.source.source.name}, whose broad extraction is not in yet: ${PR.sourceWords(h.source)}`).join("; and ")}`,
          fix: `${found.hold.map((h) => PR.holdFix(h.source, o.preparation?.closed)).join("; ")}. Produced, partial, failed or declined releases the hold (record the answer again with supersedes=${a.seq} if what the extraction holds bears on it); or the operator accepts the question's limits (question accept)`,
          named_by: [],
        });
      }
      if (found.warn.length) {
        const how = (w: PR.PreparationWarn) => (w.how === "named" ? "names" : w.how === "member" ? "names members of the catalogue of" : "rests on outputs made from");
        warnings.push({
          code: "preparation_missing",
          section: sec.section,
          seqs: [a.seq, ...[...new Set(found.warn.flatMap((w) => w.coverage))].sort((x, y) => x - y)],
          what: `answer #${a.seq} (${sec.section}) is ${what}, weighed without a produced broad extraction of what it rests on: ${found.warn.map((w) => `coverage record${w.coverage.length === 1 ? "" : "s"} ${w.coverage.map((n) => `E-${n}`).join(", ")} ${how(w)} ${PR.sourceWords(w.source)}`).join("; ")}`,
          fix: `weigh the answer against the extraction when it is in (catalog/gen/<generation>/, catalog_search), or say in its coverage record why it does not bear on the question; a failed or declined extraction is a limit on the search, said in the coverage record's skipped or failures`,
        });
      }
    }
    // A question not determinable for want of a source: its coverage names
    // the acquisition ask opened for it, or says why none was. A warning.
    if (bar && result === "not_determinable") {
      const covNow = cited.filter((c) => c.kind === "coverage");
      if (!covNow.some((c) => c.acquisition_ask || c.acquisition_none_why)) {
        warnings.push({
          code: "no_acquisition_ask",
          section: sec.section,
          seqs: [a.seq, ...covNow.map((c) => c.seq)],
          what: `answer #${a.seq} (${sec.section}) is not determinable, and ${covNow.length ? `its coverage record${covNow.length === 1 ? "" : "s"} ${covNow.map((c) => `E-${c.seq}`).join(", ")} name${covNow.length === 1 ? "s" : ""}` : "it rests on no coverage record that names"} no acquisition ask and no reason for none`,
          fix: o.moreEvidence === "no" ? noMoreEvidenceAskFix(covNow.map((c) => c.seq), a.seq) : `when the question needs a source the evidence does not hold, open an acquisition ask (lead_close needs_operator with ask {kind: acquisition, source, where, expected_value, urgency}) and record the coverage again with acquisition_ask: "R-<n>"; otherwise say why none would settle it in acquisition_none_why`,
        });
      }
    }
    // A partial answer whose every review holds every part it weighed
    // established, at least one of them attesting it established: the
    // partial label is then most often a hedge (on s993d40, whether the
    // person the case brief names did it). A part a review marks not asked
    // by the question (not_asked: detail beyond it, an example category, an
    // exhaustiveness it does not demand; on s704e4b three complete answers
    // stood partial on such parts) is left out of "every part", whichever
    // review marks it. A warning: partial is for a part the question asks
    // that the evidence could not establish, and the recorder says which.
    // Never a promotion: the answer stands as recorded.
    if (bar && result === "partial") {
      const reviews = answerReviews(a, o.attestations);
      const weighed = reviews.filter((x) => x.answer_review?.parts?.length);
      const established = reviews.filter((x) => x.strength === "established");
      const marks = weighed.flatMap((x) => x.answer_review!.parts.filter((p) => p.not_asked).map((p) => ({ by: x.by, p })));
      const unasked = (p: AnswerReviewPart) => marks.some((m) => (p.id && m.p.id ? p.id === m.p.id : looseText(p.part) === looseText(m.p.part)));
      const asked = weighed.map((x) => x.answer_review!.parts.filter((p) => !unasked(p)));
      if (weighed.length && established.length && asked.some((ps) => ps.length) && asked.every((ps) => ps.every((p) => p.established === true))) {
        const outside = [...new Map(marks.map((m) => [m.p.id ?? looseText(m.p.part), m])).values()];
        warnings.push({
          code: "partial_all_parts_established",
          section: sec.section,
          seqs: [a.seq],
          what: outside.length
            ? `answer #${a.seq} (${sec.section}) is partial, and every part of the question its reviews weighed is established (${[...new Set(weighed.map((x) => x.by))].join(", ")}; attested established by ${[...new Set(established.map((x) => x.by))].join(", ")}); what it holds open the question does not ask, as its reviews mark it: ${outside.map((m) => `${m.p.id ? `${m.p.id} ` : ""}"${m.p.part}" (${m.by}: ${m.p.why})`).join("; ")}`
            : `answer #${a.seq} (${sec.section}) is partial, and every review holds every part it weighed established (${[...new Set(weighed.map((x) => x.by))].join(", ")}; attested established by ${[...new Set(established.map((x) => x.by))].join(", ")})`,
          fix: outside.length
            ? `an open part is a part the question asks: record the answer again with supersedes=${a.seq} and result established, with what the question does not ask (${outside.map((m) => `"${m.p.part}"`).join(", ")}) among its limitations, not its parts; unasked detail, an example category the evidence does not show and an exhaustiveness the question does not demand are limitations (a question that asks for a complete set is held to its completeness coverage instead). If a part the question does ask is open, name it and what bounds it. Nothing is changed for you: the answer stands as recorded until you record it again`
            : `an answer is partial only for a part of the question the evidence could not establish: say which part is open (in its reasoning or limitations, citing what bounds it), or record the answer again with supersedes=${a.seq} and result established; ${CASE_PREMISE_WORDS}`,
        });
      }
    }
    // A partial answer to a question that presumes an event (docs/adr/0011,
    // "What a question presumes"): the premise is tested before the answer,
    // against the rival "the question's premise is not supported", by the
    // answer itself (premise_tested) or by a review of it. On the
    // calibration runs a premise-false question was answered partial on a
    // planted clue that fitted its frame, round after round. A warning,
    // never a hold: partial stays a disposition.
    const presumed = bar && result === "partial" ? o.presumes?.get(id) : undefined;
    if (presumed && !premiseTestCounts(a.premise_tested) && !answerReviews(a, o.attestations).some((x) => premiseTestCounts(x.answer_review?.premise_tested))) {
      warnings.push({
        code: "premise_untested",
        section: sec.section,
        seqs: [a.seq],
        what: `answer #${a.seq} (${sec.section}) is partial on a question that presumes ${PM.presumptionWords(presumed)}, and neither it nor a review of it tests that premise`,
        fix: `${PREMISE_TEST_FIX}. The answer may carry the test itself: record it again with supersedes=${a.seq} and premise_tested {outcome, refs}`,
      });
    }
    // What the registers tie to the question and its answer leaves out (on
    // s993d40 an answer left out two methods the ledger held as findings
    // under that question's leads, and one of them, established under that
    // other question's leads, named a second question whose answer never
    // reached it either): a standing finding or event, not disputed, that
    // the answer does not reach, directly or through the entries it cites
    // (answerReach), and that another seat attested or two seats recorded
    // and that the lead register recorded under a lead linked to the
    // question (it interprets a lead's job, or a lead's close or
    // confirmation names it), or that names the question in its own
    // `answers`, or whose `rel` links to an entry the answer cites; or one
    // seat's that names the question and that another question's standing
    // answer relies on (questionUncited). One seat's that no answer relies
    // on is not warned of: every finding a seat tags counted, and on
    // s993d40 and sa2f2f2 every question was warned, up to 18 entries each.
    // Registers and refs only: nothing is read of what an entry says. A
    // warning: every such entry is listed, with what ties it to the
    // question.
    const left = bar ? questionUncited(a, id, { bySeq, replaced, entries, disputes: standingD, attestations: o.attestations, under: o.underLeads?.get(id), others: othersReach() }) : [];
    if (left.length) {
      const q = questionName(id, sec.section);
      const one = left.length === 1;
      // One seat's entry counts by the question it names and the answers that rely on it; the tie said is that, with its leads when it has them.
      const reliedWords = (x: UncitedEntry) => `relied on by the answer${x.relied.length === 1 ? "" : "s"} to ${x.relied.map((s) => questionName(sectionAnswersId(s), s)).join(", ")}`;
      const tie = (x: UncitedEntry) => (x.seats === 1 ? `${x.leads.length ? `under ${x.leads.join(", ")} ` : ""}that names ${q}, held by one seat, ${reliedWords(x)}` : x.leads.length ? `under ${x.leads.join(", ")}` : x.names ? `that names ${q}` : `whose rel ${x.rel.map((r) => `${r.kind} E-${r.to}`).join(" and ")}, which the answer cites`);
      warnings.push({
        code: "lead_findings_uncited",
        section: sec.section,
        seqs: [a.seq, ...left.map((x) => x.seq)],
        what: `answer #${a.seq} (${sec.section}) leaves out what the record ties to ${q}: ${left.map((x) => `E-${x.seq} (${x.kind === "event" ? "an event" : "a finding"} ${tie(x)})`).join(", ")}: ${one ? "cite it or say why it does not bear on it" : "cite them or say why they do not bear on it"}`,
        fix: `record the answer again with supersedes=${a.seq}, citing ${one ? "it" : "each"} as E-<seq> in its reasoning (or among its contrary or limitations), or saying there why ${one ? "it does" : "each does"} not bear on ${q}; an entry the answer cites that names ${one ? "it" : "one"} (rel, a coverage record's result_refs) counts`,
      });
    }
    if (bar && result) {
      const forms = NB.absoluteAbsenceForms(`${a.value}\n${a.reasoning ?? ""}`);
      const earned = a.asserts_absence === true && result === "bounded_negative" && bar.existence && cov.some((c) => c.coverage === "complete" && c.detection_opportunity?.trace_expected === "yes");
      if ((forms.length || a.asserts_absence) && !earned) {
        defects.push({ code: "wording", section: sec.section, seqs: [a.seq], what: `answer #${a.seq} (${sec.section}) says the event did not happen${forms.length ? ` (${forms.map((f) => `"${f}"`).join(", ")})` : ""}, and the bar for saying so is not met: ${result !== "bounded_negative" ? `its result is ${NB.resultWords(result)}, and only a bounded negative may say it` : !bar.existence ? "the question does not ask whether something exists" : !cov.some((c) => c.coverage === "complete") ? "no coverage record it rests on is complete" : "no coverage record it rests on says the event would have left a trace"}`, fix: `record the answer again with supersedes=${a.seq}, worded "No evidence of … was found in …" (the coverage record's scope)`, named_by: [] });
      }
    }
    // Premises (docs/adr/0011, "Premises"): a standing answer that assumes a
    // premise revision another standing answer contradicts, over scopes that
    // overlap, holds both questions while the contradiction names no
    // standing finding that rebuts it. The ways out are all on the record and
    // none forces either side: revise an answer, name the rebutting finding
    // (the premise goes to the operator as a dispute, and the answer that
    // assumes it is warned), narrow a citation's scope, or answer
    // conditionally. Uncertainty (unresolved) holds nothing. Fixed, never named.
    // A withdrawn premise, or a revision revised since, holds nothing
    // (premiseConflicts): its warnings (premise_withdrawn, premise_revised)
    // carry it. On a question the operator marked not material it is a
    // warning, as every other defect of the bar is held on material
    // questions only (the Fable review of the limits branch, P2-1 and P3-5).
    const mine = conflicts.filter((c) => c.assumed.seq === a.seq || c.contradicted.seq === a.seq);
    const unreconciled = mine.filter((c) => !c.contradicted.rebuttal.length);
    if (unreconciled.length) {
      const says = (c: PM.PremiseConflict) => (c.assumed.seq === a.seq ? `assumes ${c.premise} (revision ${c.rev}), which #${c.contradicted.seq} (${c.contradicted.section}) contradicts` : `contradicts ${c.premise} (revision ${c.rev}), which #${c.assumed.seq} (${c.assumed.section}) assumes`);
      const revs = [...new Map(unreconciled.map((c) => [`${c.premise}@${c.rev}`, c])).values()];
      const held = {
        section: sec.section,
        seqs: [a.seq, ...[...new Set(unreconciled.map((c) => (c.assumed.seq === a.seq ? c.contradicted.seq : c.assumed.seq)))]],
        what: `answer #${a.seq} (${sec.section}) ${unreconciled.map(says).join("; and ")}, over scopes that overlap`,
        fix: `reconcile them on the record; neither side is forced: ${revs.map((c) => PREMISE_WAYS_OUT(c.premise, c.rev)).join("; and for the next premise, ")}`,
      };
      if (bar && !bar.material) warnings.push({ code: "premise_inconsistent", ...held, what: `${held.what} (a question not material: warned, never held)` });
      else defects.push({ code: "premise_inconsistent", ...held, named_by: [] });
    }
    const rebutted = mine.filter((c) => c.assumed.seq === a.seq && c.contradicted.rebuttal.length);
    if (rebutted.length) {
      warnings.push({
        code: "premise_disputed",
        section: sec.section,
        seqs: [a.seq, ...[...new Set(rebutted.map((c) => c.contradicted.seq))]],
        what: `answer #${a.seq} (${sec.section}) assumes ${rebutted.map((c) => `${c.premise} (revision ${c.rev}), which #${c.contradicted.seq} (${c.contradicted.section}) contradicts on ${c.contradicted.rebuttal.join(", ")}`).join("; and ")}: the premise is disputed before the operator`,
        fix: `weigh the rebutting finding: if the answer holds only if the premise does, record it again with supersedes=${a.seq} citing it conditionally (stance assumed, conditional: true: "assuming ${rebutted[0]!.premise}"); if the finding bears on it, revise it; otherwise it stands as it is, and the ruling on the premise (revise, withdraw, or answer the request) is the operator's`,
      });
    }
    if (o.premises && a.premises?.length) {
      const moved = a.premises.filter((c) => {
        const p = o.premises!.get(c.id);
        return p && !p.withdrawn && c.rev < p.rev;
      });
      if (moved.length) {
        warnings.push({
          code: "premise_revised",
          section: sec.section,
          seqs: [a.seq],
          what: `answer #${a.seq} (${sec.section}) cites ${moved.map((c) => `${c.id} at revision ${c.rev}, revised to ${o.premises!.get(c.id)!.rev} since`).join(", ")}`,
          fix: `read ${moved.length === 1 ? "it" : "them"} again (questions show ${moved[0]!.id}) and record the answer again with supersedes=${a.seq} citing the revision that stands (the same stance if it still holds)`,
        });
      }
      const gone = a.premises.filter((c) => o.premises!.get(c.id)?.withdrawn);
      if (gone.length) {
        warnings.push({
          code: "premise_withdrawn",
          section: sec.section,
          seqs: [a.seq],
          what: `answer #${a.seq} (${sec.section}) cites ${gone.map((c) => {
            const w = o.premises!.get(c.id)!.withdrawn!;
            return `${c.id}, withdrawn at ${w.at} (${w.why})`;
          }).join("; ")}`,
          fix: `record the answer again with supersedes=${a.seq} without ${gone.length === 1 ? "it" : "them"}, saying what it rests on instead`,
        });
      }
    }
    // A source-first review that holds the answer established and vouches
    // for no value by bytes or by derivation (docs/adr/0015, "A source-first
    // review"): warned, never held (no_locator_or_derivation, the Fable
    // review of the limits branch, P2-3). Only reviews made under the
    // source-first rule (a discriminator) are read: an established review
    // from before it names neither and is not this rule's to warn.
    if (bar?.material && claimsEstablished(a)) {
      const establishing = answerReviews(a, o.attestations).filter((x) => attestEstablishes(x) && x.answer_review);
      const sourceFirst = establishing.filter((x) => x.answer_review!.discriminator);
      if (sourceFirst.length && !establishing.some((x) => x.answer_review!.reproduced_at?.length || x.answer_review!.derivation)) {
        warnings.push({
          code: "no_locator_or_derivation",
          section: sec.section,
          seqs: [a.seq],
          what: `answer #${a.seq} (${sec.section}) is held established by ${[...new Set(sourceFirst.map((x) => x.by))].join(", ")} on a review that vouches for no value by bytes or by derivation (no locator, no derivation)`,
          fix: `the reviewer attests it again ${REVIEW_UNLOCATED_FIX}`,
        });
      }
    }
    // A requested part a review says the answer omits (docs/adr/0013, "Claim and open-part rows"): it stays visible until the answer is recorded again with it, or says why the question does not ask it.
    const omitted = answerReviews(a, o.attestations).flatMap((x) => (x.answer_review?.parts ?? []).filter((p) => p.missing).map((p) => ({ by: x.by, part: p.part, why: p.why })));
    if (omitted.length) {
      const reviewers = new Set(omitted.map((x) => x.by)).size;
      warnings.push({
        code: "part_omitted",
        section: sec.section,
        seqs: [a.seq],
        what: `answer #${a.seq} (${sec.section}) leaves out ${omitted.length === 1 ? "a part" : "parts"} of the question its review${reviewers === 1 ? "" : "s"} name${reviewers === 1 ? "s" : ""}: ${omitted.map((x) => `"${x.part}" (${x.by}: ${x.why})`).join("; ")}`,
        fix: `record the answer again with supersedes=${a.seq}, with ${omitted.length === 1 ? "the part" : "each part"} among its parts: established on the entries that show it, or open with what bounds it (R-<n>, L-<n>, E-<seq>); or say in its reasoning why the question does not ask it`,
      });
    }
    const acted = o.attestations.some((x) => attestationAct(x) === "attest" && x.target === target && !a.authors.includes(x.by) && x.by !== a.by) || against.some((d) => !a.authors.includes(d.by)) || Boolean(review?.reviewed);
    if (!acted) {
      defects.push({ code: "no_critic_act", section: sec.section, seqs: [a.seq], what: `answer #${a.seq} (${sec.section}) has no critic act`, fix: `an agent other than its author re-derives what it rests on from the sealed refs${sec.section.startsWith("question:") ? ", reading the question against its sources before the answer's conclusion," : ""} and records attest (how) or dispute (why) on #${a.seq}${claimsEstablished(a) ? `; an established attest names the strongest rival and the test that separates it (answer_review.discriminator) and, where a value the answer states is in the bytes, where it read it (answer_review.reproduced_at, checked against the bytes) or how it was derived (answer_review.derivation)` : ""}`, named_by: namedFor(a.seq) });
    }
  }
  for (const c of openContradictions(entries)) {
    defects.push({ code: "open_contradiction", seqs: [c.from, c.to], what: `#${c.from} contradicts #${c.to} and both stand`, fix: `supersede the one that is wrong, weigh both in an answer (one as support, the other in contrary), or record a limitation citing E-${c.from} and E-${c.to}`, named_by: [] });
  }
  // The kept output of a job that was cancelled or stopped, cited later: the
  // entry says how it treats what the job wrote before it was stopped, or it
  // stands as a defect (docs/adr/0016). Fixed by the entry, never named.
  for (const [seq, refs] of o.partial ?? []) {
    const e = bySeq.get(seq);
    if (!e || replaced.has(seq)) continue;
    defects.push({
      code: "partial_output",
      seqs: [seq],
      what: `#${seq} cites the kept output of ${refs.map((r) => `job ${r.job} (${r.status})`).filter((x, i, a) => a.indexOf(x) === i).join(", ")} (${refs.map((r) => r.ref).join(", ")}) and does not say how it treats a partial output`,
      fix: `record it again with supersedes=${seq} and qualifies [{ref, why}] for each such ref (what the job wrote before it was stopped, and why that part still holds), or cite the output of a job that ran to its end`,
      named_by: [],
    });
  }
  return { answers, defects, open: defects.filter((d) => !d.named_by.length), unsupported, warnings };
}
