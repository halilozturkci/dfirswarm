/**
 * The rules over the ledger (split from extensions/protocol.ts, which re-exports it): what an entry
 * says and how it is recorded, the review evidence and the attestations, the rendered ledger,
 * disputes, answers, the question bar, downgrades and the gate at done. One cluster: its parts call
 * each other both ways, so it is not split further. It imports the core statically.
 */

import { firstLine, formatMiss, formatNote, questionFormat } from "./answer-format.ts";
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
import { fileURLToPath } from "node:url";
import * as NB from "./negative-bar.ts";
import * as PM from "./premises.ts";
import * as PR from "./preparation.ts";
import * as SWS from "./store-sweep.ts";
import { importHitExamined, importHitsFor, importHitWords, INTERPRETING_KINDS, unexaminedHits, type ImportSweepRecord, type SweepHit, type SweepRecord, type UnexaminedHit } from "./store-sweep.ts";

/** How many of a sweep's hits a gate item names; the rest are counted (ledger/sweeps.jsonl holds each). */
const SWEEP_GATE_HITS = 20;
/** The first SWEEP_GATE_HITS of `items` said, the rest counted and pointed at the file that holds each. */
function boundedHits<T>(items: readonly T[], words: (x: T) => string, holder: string, max = SWEEP_GATE_HITS): string {
  const said = items.slice(0, max).map(words);
  if (items.length > max) said.push(`and ${items.length - max} more (${holder} holds each)`);
  return said.join("; ");
}
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
  /** An answer to a question: what qualifies the asked string in value (a candidate, the part still open, the words around it). The format check reads value only. */
  qualifier?: string;
  /** An answer's revision that changes the asked string: why, naming the entry (E-<seq>) that shows the earlier value wrong (reviewValueRule). */
  value_changed_because?: string;
  /** A negative from the seat's own scanner: the run in which the same scanner found a planted or known value, {ref, found} or a list (negativeBasis). */
  control?: unknown;
  /** A negative about pictures: the images read (job:<id>/<file>); the hub fills it from the trace when it is left out. */
  images_read?: string[] | string;
  /** A finding's carrier table: [{carrier, state: decoded | undecodable | not_examined, why}] (carriersOpen). */
  carriers?: unknown;
  /** An answer's or a finding's candidate values beside its value: [{value, state: open | ruled_out | decoy, why, by?}] (candidateRows). */
  candidates?: unknown;
  /** An answer's: the carriers its value could be in, by name (carriersOpen). */
  carrier_names?: string[] | string;
  /** A finding's: what in the artefact declares it fake, a test or a vendor's sample (decoyRule). */
  decoy?: string;
  /** An answer's that rests on a decoy: {by: the machine check, why} (decoyRule). */
  decoy_check?: unknown;
};

function listOf(v: string[] | string | undefined): string[] {
  return [...new Set((Array.isArray(v) ? v.map(String) : String(v ?? "").split(/[\s,]+/)).map((x) => x.trim()).filter(Boolean))];
}

/**
 * Everything wrong with one entry, collected, and what was taken as it was
 * plainly meant. The checks used to stop at the first defect: on the run
 * sf4406b `record` refused 353 of 776 calls, one rule a refusal, and one
 * coverage record took eight refusals in 190 s, each try resending 4K
 * characters (seat 05, session lines 784-800: kind, time_range, failures,
 * alternatives, result_refs three times). A check adds its defect and goes
 * on with an empty value, so the answer names every one; `need` also keeps
 * the name of a required field that is missing, for the line that lists
 * them. `took` is the other half: what the hub understood without asking
 * (a ref written as the shell shows it, "question:9" for "9", the kind the
 * fields allow), said in the reply and never a refusal.
 */
export class Defects {
  readonly list: string[] = [];
  readonly missing: string[] = [];
  readonly taken: string[] = [];
  add(reason: string): void {
    if (!this.list.includes(reason)) this.list.push(reason);
  }
  need(field: string, reason: string): void {
    if (!this.missing.includes(field)) this.missing.push(field);
    this.add(reason);
  }
  took(note: string): void {
    if (!this.taken.includes(note)) this.taken.push(note);
  }
  text(r: { ok: true; value: string } | { ok: false; reason: string }): { ok: true; value: string } {
    if (r.ok) return r;
    this.add(r.reason);
    return { ok: true, value: "" };
  }
  one<V>(r: { ok: true; value?: V } | { ok: false; reason: string }): { ok: true; value?: V } {
    if (r.ok) return r;
    this.add(r.reason);
    return { ok: true };
  }
  seqs(r: { ok: true; seqs: number[] } | { ok: false; reason: string }): { ok: true; seqs: number[] } {
    if (r.ok) return r;
    this.add(r.reason);
    return { ok: true, seqs: [] };
  }
  get any(): boolean {
    return this.list.length > 0;
  }
  /** The refusal that names them all (refusalWords), or null when there is none. */
  refusal(kind: string): { ok: false; reason: string; defects: string[] } | null {
    return this.any ? { ok: false, reason: refusalWords(kind, this), defects: [...this.list] } : null;
  }
  /** `reason` with what was taken as meant after it: a refusal from further down still says it. */
  withTaken<R extends { ok: boolean; reason?: string; note?: string }>(r: R): R {
    if (!this.taken.length) return r;
    const said = `Taken as meant, nothing to change there: ${this.taken.join("; ")}`;
    return r.ok ? { ...r, note: [said, r.note].filter(Boolean).join("; ") } : { ...r, reason: `${r.reason}. ${said}` };
  }
}

/**
 * One refusal for every defect of an entry. One defect is said as it always
 * was. Several are numbered, after the line that says how many and that one
 * more call is enough, and the required fields that are missing are listed
 * together first: the seats fixed what the refusal named and nothing else.
 */
export function refusalWords(kind: string, d: { list: readonly string[]; missing: readonly string[] }): string {
  if (d.list.length === 1) return d.list[0]!;
  const lead = d.missing.length > 1 ? ` ${/^[aeiou]/.test(kind) ? "An" : "A"} ${kind === "coverage" ? "coverage record" : kind} also needs ${d.missing.join(", ")}.` : "";
  return `${d.list.length} things to fix, every one named here, so one more call is enough (fix them all, then record once).${lead} ${d.list.map((x, i) => `(${i + 1}) ${x.replace(/[.;]\s*$/, "")}`).join("; ")}`;
}

/** A JSON Schema as a tool declares its parameters (TypeBox writes these): only what argsForValidator reads. */
type ArgSchema = { type?: string; properties?: Record<string, ArgSchema>; required?: string[]; items?: ArgSchema; anyOf?: ArgSchema[]; const?: unknown; enum?: unknown[] };

/** Whether a value is what a schema asks, read strictly: what does not fit is set aside for the tool's own check, never dropped. */
function fitsSchema(schema: ArgSchema | undefined, v: unknown): boolean {
  if (!schema || (schema.type === undefined && !schema.anyOf && schema.const === undefined && !schema.enum)) return true;
  if (schema.anyOf) return schema.anyOf.some((x) => fitsSchema(x, v));
  if (schema.const !== undefined) return v === schema.const;
  if (schema.enum) return schema.enum.includes(v);
  switch (schema.type) {
    case "string":
      return typeof v === "string";
    case "number":
    case "integer":
      return typeof v === "number" && Number.isFinite(v);
    case "boolean":
      return typeof v === "boolean";
    case "array":
      return Array.isArray(v) && v.every((x) => fitsSchema(schema.items, x));
    case "object":
      return Boolean(v) && typeof v === "object" && !Array.isArray(v) && (schema.required ?? []).every((k) => k in (v as object)) && Object.entries(schema.properties ?? {}).every(([k, s]) => !(k in (v as object)) || (v as Record<string, unknown>)[k] === undefined || fitsSchema(s, (v as Record<string, unknown>)[k]));
    default:
      return true;
  }
}

/** A value a schema takes, for a required place that was sent empty or wrong: read by nothing (argsAsSent takes it out again). */
function schemaPlaceholder(schema: ArgSchema | undefined): unknown {
  if (!schema) return "";
  if (schema.const !== undefined) return schema.const;
  if (schema.enum?.length) return schema.enum[0];
  if (schema.anyOf?.length) return schemaPlaceholder(schema.anyOf[0]);
  switch (schema.type) {
    case "number":
    case "integer":
      return 0;
    case "boolean":
      return false;
    case "array":
      return [];
    case "object":
      return Object.fromEntries((schema.required ?? []).map((k) => [k, schemaPlaceholder(schema.properties?.[k])]));
    default:
      return "";
  }
}

/** Where argsForValidator keeps what was sent: the names of required fields left out, and each value its schema would not take. */
export const ARGS_AS_SENT = "__as_sent";

/**
 * A tool call's arguments, made to pass the tool's own schema, with what was
 * sent kept beside them (`__as_sent`): a required field left out gets a
 * placeholder, and a value the schema would not take is set aside. Pi checks
 * a call against the schema before the tool runs, and what fails there is
 * answered by Pi, with every argument echoed back: on the run sf4406b
 * `kind` was left out 31 times and one enum was misspelt a handful, and the
 * echoes came to 255K characters. A tool gives this as its
 * `prepareArguments` (Pi calls it before it validates), and reads its
 * arguments through argsAsSent: the defect is then named by the tool's own
 * check, with the rest of the entry's, in one line each. The schema still
 * says what is required and which values a field takes, which is what a
 * model reads before it calls.
 */
export function argsForValidator(schema: unknown, args: unknown): unknown {
  const s = (schema ?? {}) as ArgSchema;
  if (!args || typeof args !== "object" || Array.isArray(args)) args = {};
  const sent = args as Record<string, unknown>;
  const out: Record<string, unknown> = { ...sent };
  const missing: string[] = [];
  const unfit: Record<string, unknown> = {};
  for (const [k, ps] of Object.entries(s.properties ?? {})) {
    const required = (s.required ?? []).includes(k);
    const v = sent[k];
    if (v === undefined || v === null) {
      if (v === null) delete out[k];
      if (required) {
        missing.push(k);
        out[k] = schemaPlaceholder(ps);
      }
      continue;
    }
    if (fitsSchema(ps, v)) continue;
    unfit[k] = v;
    if (required) out[k] = schemaPlaceholder(ps);
    else delete out[k];
  }
  if (!missing.length && !Object.keys(unfit).length) return args;
  out[ARGS_AS_SENT] = { missing, unfit };
  return out;
}

/** The arguments as the model sent them: argsForValidator undone (placeholders out, set-aside values back). */
export function argsAsSent<T extends Record<string, unknown>>(params: T): T {
  const mark = params?.[ARGS_AS_SENT] as { missing?: string[]; unfit?: Record<string, unknown> } | undefined;
  if (!mark || typeof mark !== "object") return params;
  const out: Record<string, unknown> = { ...params };
  delete out[ARGS_AS_SENT];
  for (const k of mark.missing ?? []) delete out[k];
  for (const [k, v] of Object.entries(mark.unfit ?? {})) out[k] = v;
  return out as T;
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
  D: Defects,
): Promise<{ fields: Partial<LedgerEntry>; rel: Array<{ to: number; kind: (typeof LEDGER_REL_KINDS)[number] }> }> {
  const fields: Partial<LedgerEntry> = {};
  const answers = listOf(input.answers);
  if (answers.length > LEDGER_MAX_ANSWERS) D.add(`answers names ${answers.length} sections, more than ${LEDGER_MAX_ANSWERS}`);
  const badAnswer = answers.find((a) => !LEDGER_ANSWER_ID.test(a));
  if (badAnswer) D.add(`answers takes the goal's section ids, 1-16 letters, digits, dot, dash or underscore ("3", "Q3", "allegation-2"; got ${JSON.stringify(badAnswer)})`);
  if (answers.length) fields.answers = answers;
  const rel: Array<{ to: number; kind: (typeof LEDGER_REL_KINDS)[number] }> = [];
  for (const r of Array.isArray(input.rel) ? input.rel : []) {
    const to = Number(String(r?.to ?? "").trim().replace(/^(?:#|E-)/i, ""));
    const k = D.one(oneOf("rel.kind", r?.kind, LEDGER_REL_KINDS));
    if (!Number.isInteger(to) || to < 1) D.add(`rel.to names an entry by its seq, a whole number (got ${JSON.stringify(r?.to)})`);
    else if (!k.value) D.add(`rel.kind is required: ${LEDGER_REL_KINDS.join(", ")}`);
    else if (!rel.some((x) => x.to === to && x.kind === k.value)) rel.push({ to, kind: k.value });
  }
  if (rel.length > LEDGER_MAX_REL) D.add(`rel links ${rel.length} entries, more than ${LEDGER_MAX_REL}`);
  if (input.sensitive !== undefined && input.sensitive !== null && typeof input.sensitive !== "boolean") D.add("sensitive is true or false");
  if (input.sensitive === true) fields.sensitive = true;
  const clock = String(input.clock ?? "").trim();
  if (clock) {
    if (!hasTs) D.add("clock names the clock an entry's ts came from: give ts too");
    if (clock.length > LEDGER_CLOCK_MAX_CHARS) D.add(`clock is over ${LEDGER_CLOCK_MAX_CHARS} characters: name the clock ("NTFS $SI created", "device local, offset unknown")`);
    fields.clock = clock;
  }
  const precision = D.one(oneOf("precision", input.precision, LEDGER_PRECISION));
  if (precision.value && !hasTs) D.add("precision says how precise an entry's ts is: give ts too");
  // A date alone is a day, not midnight UTC: said, unless the agent said otherwise.
  const dateOnly = tsRaw !== undefined && /^\d{4}-\d{2}-\d{2}$/.test(tsRaw.trim());
  if (precision.value) fields.precision = precision.value;
  else if (dateOnly) fields.precision = "date";
  const basis = D.one(oneOf("basis", input.basis, LEDGER_BASIS));
  if (basis.value) fields.basis = basis.value;
  const status = D.one(oneOf("status", input.status, LEDGER_HYPOTHESIS_STATUS));
  if (status.value && kind !== "hypothesis") D.add("status is a hypothesis's: open, supported or refuted");
  if (kind === "hypothesis") fields.status = status.value ?? "open";
  const reason = D.one(oneOf("reason", input.reason, LEDGER_LIMITATION_REASONS));
  if (reason.value && kind !== "limitation") D.add("reason is a limitation's: why the examination could not establish it");
  if (kind === "limitation") {
    if (!reason.value) D.need("reason", `a limitation needs a reason: ${LEDGER_LIMITATION_REASONS.join(", ")}`);
    else fields.reason = reason.value;
  }
  const completion = D.one(oneOf("completion", input.completion, LEDGER_COMPLETION));
  if (completion.value && kind !== "absence") D.add("completion is an absence's: how far the search got (complete, partial, failed)");
  if (completion.value) fields.completion = completion.value;
  if (input.attribution !== undefined && input.attribution !== null) {
    const a = input.attribution;
    const subject = String(a.subject ?? "").trim();
    if (!subject) D.add("attribution.subject is required: the account, device or person");
    if (subject.length > LEDGER_SUBJECT_MAX_CHARS) D.add(`attribution.subject is over ${LEDGER_SUBJECT_MAX_CHARS} characters`);
    const type = D.one(oneOf("attribution.subject_type", a.subject_type ?? "unknown", LEDGER_SUBJECT_TYPES));
    const basisRefs = listOf(a.basis_refs);
    if (basisRefs.length > LEDGER_MAX_REFS) D.add(`attribution.basis_refs names more than ${LEDGER_MAX_REFS} objects`);
    if (basisRefs.length) {
      const checked = await checkRefs(sandboxRoot, basisRefs);
      if (!checked.ok) D.add(`attribution.basis_refs: ${checked.reason}`);
    }
    if (subject) fields.attribution = { subject, subject_type: type.value ?? "unknown", ...(basisRefs.length ? { basis_refs: basisRefs } : {}) };
  }
  const locators: LedgerLocator[] = [];
  for (const l of Array.isArray(input.locators) ? input.locators : []) {
    const ref = String(l?.ref ?? "").trim();
    const at = String(l?.at ?? "").trim();
    if (!ref || !at) D.add("a locator is {ref, at}: one of the entry's refs, and where in it (a row, an offset, a record id)");
    else if (!refs.includes(ref)) D.add(`locator ref ${JSON.stringify(ref)} is not one of the entry's refs${refs.length ? ` (refs has ${refs.slice(0, 6).join(", ")}${refs.length > 6 ? ", …" : ""})` : ""}`);
    else if (at.length > LEDGER_LOCATOR_MAX_CHARS) D.add(`a locator's at is over ${LEDGER_LOCATOR_MAX_CHARS} characters`);
    else locators.push({ ref, at });
  }
  if (locators.length > LEDGER_MAX_LOCATORS) D.add(`locators names more than ${LEDGER_MAX_LOCATORS} places`);
  if (locators.length) fields.locators = locators;
  const because = String(input.because ?? "").trim();
  if (because) {
    if (!superseding) D.add("because says why a correction corrects: give supersedes too");
    if (because.length > LEDGER_BECAUSE_MAX_CHARS) D.add(`because is over ${LEDGER_BECAUSE_MAX_CHARS} characters`);
    fields.because = because;
  }
  return { fields, rel };
}

/** The fields only an answer takes, and only a finding takes: named in a refusal when they come with another kind. */
const ANSWER_ONLY_FIELDS = ["section", "reasoning", "contrary", "limitations", "alternatives_open", "would_change", "inconclusive", "result", "contrary_none_why", "asserts_absence", "question_rev", "material", "downgrade", "parts", "premises", "premise_tested", "qualifier", "value_changed_because", "carrier_names", "decoy_check"] as const;
const FINDING_ONLY_FIELDS = ["indicates", "alternatives", "alternatives_none_why", "significance", "carriers", "decoy"] as const;
/** The fields a finding and an answer both take, and no other kind: the candidate values beside its value (candidateRows). */
const CANDIDATE_FIELDS = ["candidates"] as const;
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
  D: Defects,
): Promise<{ fields: Partial<LedgerEntry> }> {
  const raw = input as Record<string, unknown>;
  // Every field of another kind, in one defect a kind: the refusal used to name the first and the next call met the second.
  const foreign = (names: readonly string[], whose: string, then: string) => {
    const got = names.filter((f) => given(raw[f]));
    if (got.length) D.add(`${got.join(", ")} ${got.length === 1 ? "is" : "are"} ${whose}: ${then}`);
  };
  foreign(ANSWER_ONLY_FIELDS, "an answer's", "record kind=answer with its section to answer a question");
  foreign(COVERAGE_ONLY_FIELDS, "a coverage record's", "record kind=coverage for what a negative was searched over");
  if (kind !== "finding") foreign(FINDING_ONLY_FIELDS, "a finding's", `what an observation indicates and what else could explain it are recorded on kind=finding${kind ? `; on ${/^[aeiou]/.test(kind) ? "an" : "a"} ${kind}, leave ${FINDING_ONLY_FIELDS.filter((f) => given(raw[f])).length === 1 ? "it" : "them"} out and say it in value or evidence` : ""}`);
  const fields: Partial<LedgerEntry> = {};
  const why = D.text(boundedText("confidence_why", input.confidence_why, LEDGER_WHY_MAX_CHARS));
  if (why.value && !confidence && !given(input.confidence)) D.add("confidence_why says why that confidence: give confidence too");
  if (why.value) fields.confidence_why = why.value;
  // What a failed job's kept bytes are still good for, ref by ref. A why
  // given for the job (job:j000020, or j000020) is the why of every ref of
  // the entry from that job: 21 refusals on the run sf4406b were "qualifies
  // names job:j000081, which is not one of the entry's refs", each answered
  // with the same words on the file's ref.
  const qualifies: LedgerQualify[] = [];
  const jobOf = (ref: string) => /^job:([a-z0-9-]+)/.exec(ref)?.[1] ?? "";
  const unusable = kind === "limitation" || kind === "absence";
  for (const q of Array.isArray(input.qualifies) ? input.qualifies : []) {
    const ref = String(q?.ref ?? "").trim();
    const text = D.text(boundedText("a qualifies why", q?.why, LEDGER_WHY_MAX_CHARS));
    if (!ref || !text.value) {
      D.add("qualifies is [{ref, why}]: one of the entry's refs whose job did not succeed, and why its kept bytes still support this entry");
      continue;
    }
    if (unusable) {
      D.took(`qualifies is left out of this ${kind}: it says why a failed job's bytes still support a claim, and ${/^[aeiou]/.test(kind) ? "an" : "a"} ${kind} rests on what could not be done, which its own fields say`);
      continue;
    }
    let targets = [ref];
    if (!refs.includes(ref)) {
      const job = /^(?:job:)?([a-z0-9-]+)(?:\/.*)?$/.exec(ref)?.[1] ?? "";
      const under = failed.filter((f) => jobOf(f.ref) === job).map((f) => f.ref);
      if (under.length) {
        // The job itself, or another file of it: the why is the job's, and it is the why of the entry's refs from that job.
        targets = under;
        D.took(`qualifies ${ref} ${/^(?:job:)?[a-z0-9-]+$/.test(ref) ? "names the job" : "is not one of the entry's refs, and is of the same job"}: taken as the why of the entry's ${under.length === 1 ? "ref" : "refs"} from it (${under.join(", ")})`);
      } else if (/^(?:job:)?j\d{6,}(?:\/|$)/.test(ref) && refs.some((r) => jobOf(r) !== "")) {
        // A job none of the entry's failed refs is from: it qualifies nothing here, and nothing is lost by leaving it out (the refs that do need a why are named below).
        D.took(`qualifies on ${ref} is left out: no ref of the entry from a job that failed is from that job`);
        continue;
      } else {
        const use = failed.map((f) => f.ref);
        D.add(`qualifies names ${JSON.stringify(ref)}, which is not one of the entry's refs${use.length ? `: use exactly ${use.join(" or ")}, as refs has ${use.length === 1 ? "it" : "them"}` : refs.length ? `, and no ref of the entry is from a job that failed: leave qualifies out` : ""}`);
        continue;
      }
    }
    for (const t of targets) {
      if (!failed.some((f) => f.ref === t)) {
        D.took(`qualifies on ${t} is left out: its job succeeded, and qualifies is only for the output of a job that did not`);
        continue;
      }
      if (!qualifies.some((x) => x.ref === t)) qualifies.push({ ref: t, why: text.value });
    }
  }
  if (qualifies.length > LEDGER_MAX_QUALIFIES) D.add(`qualifies names more than ${LEDGER_MAX_QUALIFIES} refs`);
  if (failed.length && kind === "absence" && (input.completion === undefined || String(input.completion).trim().toLowerCase() === "complete" || String(input.completion).trim() === "")) {
    D.add(`the output of a job that did not succeed cannot show that something is absent (${failed.map((f) => `${f.ref}: ${f.status}`).join(", ")}): record the search with completion partial or failed, and what was not reached as kind=limitation`);
  }
  if (kind === "finding") {
    const missing = failed.filter((f) => !qualifies.some((q) => q.ref === f.ref));
    if (missing.length) {
      // The call to make is written out: one row a job covers every ref from it.
      const jobs = [...new Set(missing.map((f) => jobOf(f.ref)))];
      const rows = jobs.map((j) => {
        const of = missing.filter((f) => jobOf(f.ref) === j);
        return `{ref: "${of.length === 1 ? of[0]!.ref : `job:${j}`}", why: "<why its bytes are still usable>"}`;
      });
      D.add(`this finding rests on the kept output of a job that did not succeed (${missing.map((f) => `${f.ref}: ${f.status}`).join(", ")}): say in qualifies [{ref, why}] why those bytes are still usable, or cite the output of a job that worked. To keep ${missing.length === 1 ? "it" : "them"}, add qualifies: [${rows.join(", ")}] (a row that names a job, job:<id>, covers every ref of the entry from it)`);
    }
  }
  if (qualifies.length) fields.qualifies = qualifies;
  if (kind !== "finding") {
    if (given(raw.candidates)) D.add(`candidates is an answer's or a finding's: the values still weighed beside its value${kind ? `; on ${/^[aeiou]/.test(kind) ? "an" : "a"} ${kind}, say them in value or evidence` : ""}`);
    return { fields };
  }
  if (!basis) D.need("basis", "a finding says whether it was seen in the evidence or reasoned from it: basis observed or inferred");
  if (!confidence && !given(input.confidence)) D.need("confidence", "a finding says how sure: confidence high, medium or low, with confidence_why");
  const indicates = D.text(boundedText("indicates", input.indicates, LEDGER_INDICATES_MAX_CHARS));
  if (!indicates.value) D.need("indicates", "indicates is required on a finding: what the observation means, and the step from one to the other, in one to three sentences");
  fields.indicates = indicates.value;
  if (!fields.confidence_why) {
    D.need("confidence_why", "confidence_why is required on a finding: where the data came from, whether the method is reliable for it, how specific the observation is, and whether your sources depend on each other");
  }
  const alternatives: LedgerAlternative[] = [];
  for (const a of Array.isArray(input.alternatives) ? input.alternatives : []) {
    const explanation = D.text(boundedText("an alternative's explanation", a?.explanation, LEDGER_WHY_MAX_CHARS));
    const aWhy = D.text(boundedText("an alternative's why", a?.why, LEDGER_WHY_MAX_CHARS));
    const status = D.one(oneOf("an alternative's status", a?.status, LEDGER_ALTERNATIVE_STATUS));
    if (!explanation.value || !status.value || !aWhy.value) {
      D.add("an alternative is {explanation, status: rejected | open, why, test_refs?}: what else could explain it, whether it was rejected or is still open, and why");
      continue;
    }
    const testRefs = listOf(a?.test_refs);
    if (testRefs.length > LEDGER_MAX_REFS) D.add(`an alternative's test_refs names more than ${LEDGER_MAX_REFS} objects`);
    if (testRefs.length) {
      const checked = await checkRefs(sandboxRoot, testRefs);
      if (!checked.ok) D.add(`an alternative's test_refs: ${checked.reason}`);
    }
    alternatives.push({ explanation: explanation.value, status: status.value, why: aWhy.value, ...(testRefs.length ? { test_refs: testRefs } : {}) });
  }
  if (alternatives.length > LEDGER_MAX_ALTERNATIVES) D.add(`alternatives lists more than ${LEDGER_MAX_ALTERNATIVES}: keep the ones a reader must weigh`);
  const noneWhy = D.text(boundedText("alternatives_none_why", input.alternatives_none_why, LEDGER_WHY_MAX_CHARS));
  if (noneWhy.value && alternatives.length) D.add("alternatives_none_why says no alternative was considered: give it or the alternatives, not both");
  if (basis === "inferred" && !alternatives.length && !noneWhy.value && !(Array.isArray(input.alternatives) && input.alternatives.length)) {
    D.need("alternatives", "an inferred finding lists what else could explain it in alternatives [{explanation, status: rejected | open, why}], or says in alternatives_none_why why none was considered; never invent one");
  }
  if (alternatives.length) fields.alternatives = alternatives;
  if (noneWhy.value) fields.alternatives_none_why = noneWhy.value;
  const significance = D.text(boundedText("significance", input.significance, LEDGER_WHY_MAX_CHARS));
  if (significance.value) fields.significance = significance.value;
  // The carrier table (carriersOpen): one row for each place the answer could be carried in.
  if (given(raw.carriers)) {
    const rows: CarrierRow[] = [];
    const shape = `carriers is [{carrier, state: ${CARRIER_STATES.join(" | ")}, why}]: one row for each place the answer could be carried in (a file, a stream, a field), whether it was decoded, and why (what it decoded to, or why it cannot be)`;
    for (const c of Array.isArray(raw.carriers) ? raw.carriers : [raw.carriers]) {
      const o = (c && typeof c === "object" ? c : {}) as Record<string, unknown>;
      const carrier = D.text(boundedText("a carrier", o.carrier, LEDGER_REF_MAX_CHARS)).value;
      const state = D.one(oneOf("a carrier's state", o.state, CARRIER_STATES)).value;
      const cWhy = D.text(boundedText("a carrier's why", o.why, LEDGER_WHY_MAX_CHARS)).value;
      if (!carrier || !state || !cWhy) D.add(shape);
      else if (!rows.some((r) => r.carrier === carrier)) rows.push({ carrier, state, why: cWhy });
    }
    if (rows.length > LEDGER_MAX_CARRIERS) D.add(`carriers lists more than ${LEDGER_MAX_CARRIERS} rows: group the ones that share a state and a why`);
    else if (rows.length) (fields as { carriers?: CarrierRow[] }).carriers = rows;
  }
  // A finding's candidate values (candidateRows; a check a row names is weighed against the ledger in recordChecked) and its decoy mark (decoyRule).
  if (given(raw.candidates)) {
    const rows = candidateRows(raw.candidates, D);
    if (rows.length) fields.candidates = rows;
  }
  if (given(raw.decoy)) {
    const d = D.text(boundedText("decoy", raw.decoy, LEDGER_WHY_MAX_CHARS));
    if (d.value) fields.decoy = d.value;
  }
  return { fields };
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
  | { ok: false; reason: string; defects?: string[]; quiet?: true; deferred?: { coordinator: string; generation: number } };

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

/** What every "does not resolve" ends with: said once in a refusal, however many refs it names. */
const REF_FORMS = "A ref names an object of this run (input:<path>, job:<id>/<path>, import:<id>/<path>, member:<gen>#<n>, sha256:<hex>, or a brain's own output: tool:<seat>/<file> under tool-output/, trace:<sha256> of one trace line, which the hub seals first and cites as the import it became), or says why none can be named (unresolved:<why>).";

/**
 * Every ref resolved against the run as it is now, and each that is not,
 * with the names nearest to it: a typo costs one turn, where a wrong ref on
 * the chain would stand for good. An entry in place of an object (E-12 in
 * refs) is told which form the field takes.
 */
export async function checkRefsAll(sandboxRoot: string, refs: string[]): Promise<{ resolved: Array<{ ref: string; kind: string; status?: string }>; bad: Array<{ ref: string; why: string }> }> {
  // Loaded when a ref is checked, not with the extension: a VM that mounts
  // only extensions/ still loads it, and in a VM the hub checks refs anyway.
  const { manifestNearNames, manifestOf, resolveRef, storePaths } = await import("../scripts/evidence-store.ts");
  const resolved: Array<{ ref: string; kind: string; status?: string }> = [];
  const bad: Array<{ ref: string; why: string }> = [];
  for (const ref of refs) {
    const entry = /^(?:#|E-)(\d+)$/i.exec(ref);
    if (entry) {
      bad.push({ ref, why: `ref ${JSON.stringify(ref)} names a ledger entry, and refs takes the run's objects (job:<id>/<path>, input:<path>, …): cite what E-${entry[1]} itself rests on, and link the entry with rel [{to: ${entry[1]}, kind: "supports" | "derived_from" | "contradicts" | "duplicates"}]` });
      continue;
    }
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
        // From the manifest's index as a stream, never the manifest parsed whole: one of 200,000 files is 50 MB of JSON, read here once for every ref that did not resolve.
        const manifestPath = join(m[1] === "job" ? P.jobs : P.imports, id, "manifest.json");
        const found = await manifestOf(manifestPath);
        if (found && slash >= 0) {
          const want = m[2].slice(slash + 1).replace(/^out\//, "");
          // A directory of the job's output is not an object: the files under it are, and the job as a whole.
          const prefix = `${want.replace(/\/+$/, "")}/`;
          const under: string[] = [];
          let underTotal = 0;
          for await (const rows of found.files()) for (const f of rows) if (f.path.startsWith(prefix)) {
            underTotal += 1;
            if (under.length < 5) under.push(f.path);
          }
          near = (underTotal ? under : await manifestNearNames(manifestPath, want)).map((p) => `${m[1]}:${id}/${p}`);
          if (underTotal) {
            bad.push({ ref, why: `ref ${JSON.stringify(ref)} is a directory of ${m[1]} ${id}'s output (${underTotal} ${underTotal === 1 ? "file" : "files"} under it), and a ref names a file: cite the files the entry rests on (${near.join(", ")}${underTotal > 5 ? ", …" : ""}), or the whole output as ${m[1]}:${id}` });
            continue;
          }
        } else if (!found) near = nearestNames(id, await readdir(m[1] === "job" ? P.jobs : P.imports).catch(() => [])).map((x) => `${m[1]}:${x}`);
      }
    } catch {
      near = [];
    }
    bad.push({ ref, why: `ref ${JSON.stringify(ref)} does not resolve: ${r.reason}${near.length ? `; nearest: ${near.join(", ")}` : ""}` });
  }
  return { resolved, bad };
}

/** Every ref resolved (checkRefsAll), or the first that is not: for the fields that hold one or two. */
export async function checkRefs(sandboxRoot: string, refs: string[]): Promise<{ ok: true; resolved: Array<{ ref: string; kind: string; status?: string }> } | { ok: false; reason: string }> {
  const all = await checkRefsAll(sandboxRoot, refs);
  return all.bad.length ? { ok: false, reason: `${all.bad[0]!.why}. ${REF_FORMS}` } : { ok: true, resolved: all.resolved };
}

/**
 * A ref as it was plainly meant, when it is not one as written and the
 * other form resolves: the path as the shell shows it
 * (store/jobs/j000149/out/x, job:j000149/out/x) for job:j000149/x, a job id
 * alone (j000149) for job:j000149, inputs/x for input:x. Null when the ref
 * is already in form, or the other form does not resolve either. On the run
 * sf4406b a seat's files were at store/jobs/<id>/out/<path> and its refs at
 * job:<id>/<path>: 99 refusals in the eight runs were that difference.
 */
export async function meantRef(sandboxRoot: string, ref: string): Promise<string | null> {
  const t = ref.trim().replace(/^\.\//, "");
  const path = /^(?:store\/jobs\/|job:|jobs\/)?(j\d{6,})(?:\/(.*))?$/.exec(t);
  let want: string | null = null;
  if (path) {
    // The job's logs by their short names (stdout, stderr) are stdout.log and stderr.log beside its output.
    const log = /^(?:out\/)?(stdout|stderr)(?:\.txt)?$/.exec(path[2] ?? "");
    const rest = log ? `${log[1]}.log` : (path[2] ?? "").replace(/^out(?:\/|$)/, "").replace(/\/+$/, "");
    want = `job:${path[1]}${rest ? `/${rest}` : ""}`;
  } else if (/^inputs\//.test(t)) want = `input:${t.slice("inputs/".length)}`;
  else if (/^import:[a-z0-9-]+\/out\//.test(t)) want = t.replace(/^(import:[a-z0-9-]+)\/out\//, "$1/");
  const { readManifest, resolveRef, storePaths } = await import("../scripts/evidence-store.ts");
  if (want && (await resolveRef(sandboxRoot, want).catch(() => null))?.ok) return want === ref ? null : want;
  // The job's own records beside its output (manifest.json, job.json, a scope file), or a directory of its output: the job, whole. A ref names a file or a whole output, and this is the one of the two that was meant.
  const job = /^job:(j\d{6,})\/(.+?)\/*$/.exec(want ?? "");
  if (!job) return null;
  const whole = `job:${job[1]}`;
  if (!(await resolveRef(sandboxRoot, whole).catch(() => null))?.ok) return null;
  if (/^(?:manifest\.json|job\.json|scope(?:\.\d+)?\.json)$/.test(job[2]!)) return whole;
  const found = await readManifest(join(storePaths(sandboxRoot).jobs, job[1]!, "manifest.json")).catch(() => null);
  return found?.manifest.files.some((f) => f.path.startsWith(`${job[2]}/`)) ? whole : null;
}

/** The fields each kind takes beside the ones every kind does: what `kindFitting` reads. */
const KIND_COMMON = ["kind", "value", "source", "evidence", "confidence", "confidence_why", "supersedes", "because", "sensitive", "qualifies"] as const;
const KIND_OBJECT = ["ts", "refs", "answers", "rel", "clock", "precision", "basis", "attribution", "locators", "control", "images_read"] as const;

/**
 * The kinds an input's fields allow, when it names none: each kind that
 * takes every field given. A finding's indicates, a limitation's reason, a
 * coverage record's time_range and an answer's section each allow one kind
 * only, and that one is taken and said; anything less is asked. The open
 * models send their arguments in alphabetical order and `kind` fell off 90
 * times in eight runs, the answer each time the whole argument object back.
 */
export function kindsFitting(raw: Record<string, unknown>): string[] {
  const takes: Record<string, readonly string[]> = {
    event: [...KIND_COMMON, ...KIND_OBJECT],
    ioc: [...KIND_COMMON, ...KIND_OBJECT],
    finding: [...KIND_COMMON, ...KIND_OBJECT, ...FINDING_ONLY_FIELDS, ...CANDIDATE_FIELDS],
    absence: [...KIND_COMMON, ...KIND_OBJECT, "completion"],
    hypothesis: [...KIND_COMMON, ...KIND_OBJECT, "status"],
    limitation: [...KIND_COMMON, ...KIND_OBJECT, "reason"],
    answer: [...KIND_COMMON, ...ANSWER_ONLY_FIELDS, ...CANDIDATE_FIELDS],
    coverage: [...KIND_COMMON, ...COVERAGE_ONLY_FIELDS, "refs", "answers", "alternatives", "alternatives_open"],
  };
  // A key no kind takes (a note to self, a misspelt name) says nothing of the kind: the check does not read it either.
  const known = new Set(Object.values(takes).flat());
  const has = Object.keys(raw).filter((k) => given(raw[k]) && known.has(k));
  return Object.keys(takes).filter((k) => has.every((f) => takes[k]!.includes(f)) && (k !== "event" || given(raw.ts)) && (k !== "answer" || given(raw.section)) && (k !== "coverage" || COVERAGE_ONLY_FIELDS.some((f) => given(raw[f]))));
}

/** The fields that are one kind's and no other's: a section is an answer's, a reason a limitation's. */
const KIND_MARKS: Record<string, readonly string[]> = { coverage: COVERAGE_ONLY_FIELDS, answer: ["section", "reasoning", "result", "would_change", "contrary", "contrary_none_why", "parts", "premises", "premise_tested", "question_rev", "qualifier", "carrier_names", "decoy_check"], finding: ["indicates", "significance", "alternatives_none_why", "carriers", "decoy"], absence: ["completion"], limitation: ["reason"], hypothesis: ["status"] };

/** The kinds whose own fields an input carries (KIND_MARKS). One alone names the kind even beside a field it does not take: that field is then named as not its own. */
export function kindsMarked(raw: Record<string, unknown>): string[] {
  return Object.keys(KIND_MARKS).filter((k) => KIND_MARKS[k]!.some((f) => given(raw[f])));
}

/** The kind an input with no kind comes closest to: of the kinds that fit when several do (a finding first), else the one that takes the most of its fields. */
function kindClosest(raw: Record<string, unknown>, fit: readonly string[]): string {
  const order = ["finding", "absence", "limitation", "hypothesis", "event", "ioc", "coverage", "answer"];
  if (fit.length) return order.find((k) => fit.includes(k)) ?? fit[0]!;
  if (given(raw.section)) return "answer";
  const score = (k: string) => (KIND_MARKS[k] ?? []).filter((f) => given(raw[f])).length;
  return [...order].sort((a, b) => score(b) - score(a))[0]!;
}

/**
 * An input as it was plainly meant, before it is checked: the kind its
 * fields allow when it names none (kindsFitting, one kind only), section
 * ids in the spellings the seats used ("question:9", "Question 9", "#9" for
 * "9"), and refs in the form the shell shows them (meantRef), wherever a
 * field holds refs. Each is said in the reply (`took`); nothing that could
 * be read two ways is taken.
 */
async function inputAsMeant(sandboxRoot: string, input: LedgerInput, D: Defects): Promise<LedgerInput> {
  const raw = { ...(input as Record<string, unknown>) };
  if (!String(raw.kind ?? "").trim()) {
    // The kind written as a key ({finding: "the sentence"}): the kind, and the value when none was given (four calls on the runs sf4406b and s082123).
    const named = (LEDGER_KINDS as readonly string[]).filter((k) => k !== "external" && typeof raw[k] === "string" && (raw[k] as string).trim());
    if (named.length === 1) {
      const k = named[0]!;
      raw.kind = k;
      const text = String(raw[k]).trim();
      const asValue = !given(raw.value) && k !== "answer";
      if (asValue) raw.value = text;
      delete raw[k];
      D.took(`the field "${k}" taken as kind=${k}${asValue ? ", and what it held as value" : ""}`);
    }
  }
  if (!String(raw.kind ?? "").trim()) {
    const fit = kindsFitting(raw);
    const marked = kindsMarked(raw);
    if (fit.length === 1) {
      raw.kind = fit[0];
      D.took(`kind was left out: taken as ${fit[0]}, the one kind these fields allow`);
    } else if (!fit.length && marked.length === 1) {
      raw.kind = marked[0];
      D.took(`kind was left out: taken as ${marked[0]}, the one kind whose own fields it carries (${KIND_MARKS[marked[0]!]!.filter((f) => given(raw[f])).slice(0, 4).join(", ")})`);
    }
  }
  const sectionId = (a: string) => a.trim().replace(/^["'\[\s]+|["'\]>\s]+$/g, "").replace(/^(?:question|q)\s*[:#_ ]\s*(?=[\w.-]+$)/i, "").replace(/^#(?=\d)/, "");
  if (given(raw.answers)) {
    const list = Array.isArray(raw.answers) ? raw.answers.map(String) : String(raw.answers).split(/[\s,]+/).filter(Boolean);
    const out = list.map(sectionId);
    const changed = list.filter((a, i) => a.trim() !== out[i]);
    if (changed.length) {
      raw.answers = out;
      D.took(`answers ${changed.map((a) => JSON.stringify(a)).join(", ")} taken as ${changed.map((a) => JSON.stringify(sectionId(a))).join(", ")}: answers takes the id alone`);
    }
  }
  // Each ref taken in another form, said one by one up to four and counted beyond (one coverage record of the run sf4406b carried six, twice over).
  const moved: string[] = [];
  const fix = async (r: unknown, where: string): Promise<unknown> => {
    if (typeof r !== "string" || !r.trim()) return r;
    const m = await meantRef(sandboxRoot, r);
    if (!m) return r;
    const said = `${where} ${JSON.stringify(r.trim())} taken as ${m}: ${/^job:j\d+$/.test(m) && !/^(?:job:|store\/jobs\/|jobs\/)?j\d+\/?(?:out\/?)?$/.test(r.trim().replace(/^\.\//, "")) ? "a ref names a file or a job's whole output, and this names a directory or the job's own record" : "a ref has no out/ and no store path"}`;
    if (!moved.includes(said)) moved.push(said);
    return m;
  };
  const list = async (v: unknown, where: string): Promise<unknown> => (Array.isArray(v) ? Promise.all(v.map((x) => fix(x, where))) : typeof v === "string" && /[\s,]/.test(v.trim()) ? Promise.all(v.split(/[\s,]+/).filter(Boolean).map((x) => fix(x, where))) : typeof v === "string" && v.trim() ? [await fix(v, where)] : v);
  if (given(raw.refs)) raw.refs = await list(raw.refs, "ref");
  // result_refs names entries too: a bare seq is the entry.
  if (given(raw.result_refs)) raw.result_refs = ((await list(raw.result_refs, "result_refs")) as unknown[]).map((x) => (typeof x === "string" && /^\d+$/.test(x.trim()) ? `E-${Number(x)}` : typeof x === "number" ? `E-${x}` : x));
  if (Array.isArray(raw.qualifies) && raw.kind !== "answer") raw.qualifies = await Promise.all(raw.qualifies.map(async (q) => (q && typeof q === "object" ? { ...(q as object), ref: await fix((q as { ref?: unknown }).ref, "qualifies") } : q)));
  if (Array.isArray(raw.locators)) raw.locators = await Promise.all(raw.locators.map(async (q) => (q && typeof q === "object" ? { ...(q as object), ref: await fix((q as { ref?: unknown }).ref, "locator ref") } : q)));
  if (Array.isArray(raw.alternatives)) raw.alternatives = await Promise.all(raw.alternatives.map(async (a) => (a && typeof a === "object" && given((a as { test_refs?: unknown }).test_refs) ? { ...(a as object), test_refs: await list((a as { test_refs?: unknown }).test_refs, "test_refs") } : a)));
  if (raw.attribution && typeof raw.attribution === "object" && given((raw.attribution as { basis_refs?: unknown }).basis_refs)) raw.attribution = { ...(raw.attribution as object), basis_refs: await list((raw.attribution as { basis_refs?: unknown }).basis_refs, "attribution.basis_refs") };
  if (given(raw.control)) {
    const one = async (c: unknown) => (c && typeof c === "object" && !Array.isArray(c) ? { ...(c as object), ref: await fix((c as { ref?: unknown }).ref, "control.ref") } : fix(c, "control.ref"));
    raw.control = Array.isArray(raw.control) ? await Promise.all(raw.control.map(one)) : await one(raw.control);
  }
  if (given(raw.images_read)) raw.images_read = await list(raw.images_read, "images_read");
  if (moved.length <= 4) for (const x of moved) D.took(x);
  else D.took(`${moved.length} refs written as the shell shows them (out/, a store path) taken in the form a ref has, job:<id>/<path>: ${moved.slice(0, 2).map((x) => x.replace(/: a ref .*$/, "")).join("; ")}, and ${moved.length - 2} more`);
  return raw as unknown as LedgerInput;
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
  // The whole entry is checked and every defect named in one refusal (Defects); what was plainly meant is taken first and said, whatever the answer.
  const D = new Defects();
  return D.withTaken(await recordChecked(ctx, input, D));
}

async function recordChecked(ctx: SwarmContext, input: LedgerInput, D: Defects): Promise<LedgerResult> {
  input = await inputAsMeant(ctx.sandboxRoot, input, D);
  // Q-<n> names a question of the register: its section, which is n unless
  // the goal gave it its own id.
  if (typeof input.section === "string" && /^(question:)?Q-\d/i.test(input.section.trim())) input = { ...input, section: await registerSection(ctx.sandboxRoot, input.section) };
  if (input.answers !== undefined && (Array.isArray(input.answers) ? input.answers : String(input.answers).split(/[\s,]+/)).some((a) => /^Q-\d/i.test(String(a).trim()))) {
    const list = Array.isArray(input.answers) ? input.answers.map(String) : String(input.answers).split(/[\s,]+/);
    input = { ...input, answers: await Promise.all(list.map((a) => registerSection(ctx.sandboxRoot, a.trim()))) };
  }
  let kind = String(input.kind ?? "").trim().toLowerCase();
  if (!kind) {
    // Asked only when the fields allow several kinds, or none. The rest of the entry is still checked, as the kind the fields come closest to, so that the one refusal names everything: said so, since a defect of that kind is none of another's.
    const fit = kindsFitting(input as Record<string, unknown>);
    const guess = kindClosest(input as Record<string, unknown>, fit);
    D.need("kind", `kind is required: one of ${LEDGER_KINDS.filter((k) => k !== "external").join(", ")}. ${fit.length ? `The fields sent fit ${fit.join(", ")}: say which` : "The fields sent fit no one kind (a finding takes indicates, a limitation reason, an absence completion, a hypothesis status, a coverage record time_range and its other fields, an answer section)"}. The rest was checked as ${/^[aeio]/.test(guess) ? "an" : "a"} ${guess}, the kind they come closest to: what follows holds for that kind`);
    kind = guess;
    input = { ...input, kind };
  }
  if (!(LEDGER_KINDS as readonly string[]).includes(kind)) {
    return { ok: false, reason: `kind must be one of ${LEDGER_KINDS.join(", ")}` };
  }
  if (kind === "external") return { ok: false, reason: "external material is recorded by the harness when it enters the run (a capture the fetch service sealed, material the operator supplied), with its provenance: cite it (net:<k>/<n>, E-<seq>) and record what it establishes as a finding of yours" };
  if (kind === "answer") return withWarnings(ctx.sandboxRoot, await recordAnswer(ctx, input, D), (r) => (r.entry.section?.startsWith("question:") ? { point: "record", section: r.entry.section } : null));
  if (kind === "coverage") return recordCoverage(ctx, input, D);
  const absence = kind === "absence";
  const limitation = kind === "limitation";
  const value = String(input.value ?? "").trim();
  if (!value) {
    D.need(
      "value",
      absence
        ? "value is required: what was looked for and not found, in one sentence"
        : limitation
          ? "value is required: what the examination could not establish, in one sentence"
          : kind === "hypothesis"
            ? "value is required: the proposition under test, in one sentence"
            : "value is required: the event, the indicator or the finding, in one sentence",
    );
  }
  if (value.length > LEDGER_VALUE_MAX_CHARS) D.add(`value is over ${LEDGER_VALUE_MAX_CHARS} characters`);
  const tsChecked = normalizeTs(input.ts);
  const ts: { ts?: string; raw?: string } = tsChecked.ok ? tsChecked : {};
  if (!tsChecked.ok) D.add(tsChecked.reason);
  else if (kind === "event" && !ts.ts) D.need("ts", "an event needs a ts (ISO 8601 with its zone: Z for UTC, or the source's offset)");
  let confidence = String(input.confidence ?? "").trim().toLowerCase();
  if (confidence && !(LEDGER_CONFIDENCE as readonly string[]).includes(confidence)) {
    D.add(`confidence must be one of ${LEDGER_CONFIDENCE.join(", ")}`);
    confidence = "";
  }
  // Provenance is not optional. Across fifteen cases every one of 1501
  // ledger entries already carried both, so this costs a working run
  // nothing; what it stops is the entry that reads like a conclusion and
  // cannot be checked, which is the one a reader has no way to spot.
  const source = String(input.source ?? "").trim();
  if (!source) {
    D.need(
      "source",
      absence
        ? "source is required: what was searched — the path, image, log or artefact the search ran over. 'Not found' is only ever 'not found there'."
        : limitation
          ? "source is required: what could not be examined — the object, volume, artefact or scope"
          : "source is required: where it was seen — a path, a log, a plugin, a registry key",
    );
  }
  if (source.length > LEDGER_SOURCE_MAX_CHARS) {
    D.add(`source is over ${LEDGER_SOURCE_MAX_CHARS} characters: name where it was seen, and put the material itself in a work/ file`);
  }
  const evidence = String(input.evidence ?? "").trim();
  if (!evidence) {
    D.need(
      "evidence",
      absence
        ? "evidence is required: the query, the tool and its version, and the scope searched — allocated files only, or unallocated space and slack too, and the time range. An empty result holds only for that query and that scope."
        : limitation
          ? "evidence is required: what was tried and why it could not be done — the command, the error, the missing key or tool"
          : "evidence is required: how to check it — the command, the inode, the record id, the hash",
    );
  }
  if (evidence.length > LEDGER_EVIDENCE_MAX_CHARS) {
    D.add(`evidence is over ${LEDGER_EVIDENCE_MAX_CHARS} characters: say how to check it, and put the material itself in a work/ file`);
  }
  let refs = [...new Set((Array.isArray(input.refs) ? input.refs.map(String) : String(input.refs ?? "").split(/[\s,]+/)).map((r) => r.trim()).filter(Boolean))];
  if (refs.length > LEDGER_MAX_REFS) D.add(`refs names ${refs.length} objects, more than ${LEDGER_MAX_REFS}: name the ones the entry rests on, and the rest in evidence`);
  const long = refs.find((r) => r.length > LEDGER_REF_MAX_CHARS);
  if (long) {
    D.add(`a ref is over ${LEDGER_REF_MAX_CHARS} characters: ${JSON.stringify(long.slice(0, 80))}…`);
    refs = refs.filter((r) => r.length <= LEDGER_REF_MAX_CHARS);
  }
  // The refs whose job did not succeed, as resolveRef reads the job's own status.
  const failed: Array<{ ref: string; status: string }> = [];
  if (refs.length) {
    // Every ref that does not resolve, each with its nearest names, and what a ref is said once.
    const checked = await checkRefsAll(ctx.sandboxRoot, refs.slice(0, LEDGER_MAX_REFS));
    for (const [i, x] of checked.bad.entries()) D.add(i === checked.bad.length - 1 ? `${x.why}. ${REF_FORMS}` : x.why);
    for (const r of checked.resolved) if (r.kind === "job" && r.status && r.status !== "ok") failed.push({ ref: r.ref, status: r.status });
    // A ref that does not resolve hides what its job's status asks next: said now, so that the corrected call carries it (on the run sf4406b a finding met the bad ref, then the failed job, then qualifies, one call each).
    if (kind === "finding" && checked.bad.length) {
      const { resolveRef } = await import("../scripts/evidence-store.ts");
      const said = new Set((Array.isArray(input.qualifies) ? input.qualifies : []).map((q) => /^(?:job:)?([a-z0-9-]+)/.exec(String(q?.ref ?? "").trim())?.[1]));
      for (const j of new Set(checked.bad.map((x) => /^job:([a-z0-9-]+)\//.exec(x.ref)?.[1]).filter((x): x is string => Boolean(x)))) {
        if (said.has(j) || failed.some((f) => f.ref.startsWith(`job:${j}/`))) continue;
        const st = await resolveRef(ctx.sandboxRoot, `job:${j}`).catch(() => null);
        if (st?.ok && st.status && st.status !== "ok") D.add(`job ${j} did not succeed (${st.status}): once its ref is right, the finding also says why those bytes are still usable, qualifies: [{ref: "job:${j}", why: "<why its bytes are still usable>"}]`);
      }
    }
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
    const n = Number(String(input.supersedes).trim().replace(/^(?:#|E-)/i, ""));
    if (!Number.isInteger(n) || n < 1) D.add(`supersedes names an entry by its seq, a whole number (got ${JSON.stringify(input.supersedes)})`);
    else supersedes = n;
  }
  // An entry already corrected is corrected at the end of its chain: the one move the ledger takes, so it is taken and said (when the entry that stands is of this kind).
  if (supersedes !== undefined) {
    const now = await readLedger(ctx.sandboxRoot, { raw: true });
    const replacedNow = supersededBy(now);
    const end = replacedNow.has(supersedes) ? now.find((e) => e.seq === standingSeq(supersedes as number, replacedNow)) : undefined;
    if (end && end.kind === kind) {
      D.took(`#${supersedes} is already superseded: taken as the correction of #${end.seq}, the entry that stands at the end of its corrections (supersedes=${end.seq})`);
      supersedes = end.seq;
    }
  }
  const v3 = await ledgerV3Input(ctx.sandboxRoot, input, kind, refs, Boolean(ts.ts), typeof input.ts === "string" ? input.ts : undefined, supersedes !== undefined, D);
  const v4 = await ledgerV4Input(ctx.sandboxRoot, input, kind, refs, failed, v3.fields.basis, confidence, D);
  // A negative that rests on the seat's own scanner, or on pictures (negativeBasis): its control run and the images read.
  const neg = await negativeBasis(ctx.sandboxRoot, ctx.agentId, input, kind, refs, value, D);
  // The candidates a correction carries from the finding it corrects (said in the reply).
  const carried: CandidateRow[] = [];
  // What the ledger itself says of the entries it names (rel, supersedes), read here so that it is named with the rest; the lock checks it again.
  {
    const now = await readLedger(ctx.sandboxRoot, { raw: true });
    const bySeq = new Map(now.map((e) => [e.seq, e]));
    const replaced = supersededBy(now);
    for (const r of v3.rel) for (const why of relDefects(r, bySeq, replaced)) D.add(why);
    if (supersedes !== undefined) for (const why of supersedeDefects(supersedes, bySeq, replaced)) D.add(why);
    // A finding's candidates: each check a row names, held to the ledger; a correction carries the rows of the finding it corrects and the readings disputes of it give (carryCandidates).
    if (kind === "finding") {
      for (const why of await candidateCheckDefects(ctx.sandboxRoot, v4.fields.candidates ?? [], bySeq, replaced)) D.add(why);
      const earlier = supersedes !== undefined ? bySeq.get(supersedes) : undefined;
      if (earlier?.kind === "finding") {
        const c = carryCandidates(earlier, v4.fields.candidates ?? [], { value, readings: readingsOn(earlier, disputesInForce(now, await readDisputes(ctx.sandboxRoot))), kept: false });
        if (c.rows.length) v4.fields.candidates = c.rows;
        carried.push(...c.carried);
      }
    }
  }
  const refused = D.refusal(kind);
  if (refused) return refused;
  // How each cited object was made, as the run recorded it: written by the
  // hub into the entry and its core, so the line alone says it.
  const method = refs.length ? await ledgerMethods(ctx.sandboxRoot, refs) : [];
  // An object a failed or cancelled job left is kept and citable (ADR 0010),
  // and said: an answer resting on it should not read as resting on a job that
  // worked. A finding says why in qualifies (ledgerV4Input); another kind is told.
  const notes: string[] = [];
  if (note) notes.push(note);
  notes.push(...neg.notes);
  const unqualified = failed.filter((f) => !(v4.fields.qualifies ?? []).some((q) => q.ref === f.ref));
  if (unqualified.length) {
    notes.push(`rests on the kept output of a job that did not succeed: ${unqualified.map((f) => `${f.ref} (job ${f.ref.slice(4).split("/")[0]}: ${f.status})`).join(", ")}${kind === "finding" ? "; say why those bytes are still usable in qualifies [{ref, why}], or cite the output of a job that worked" : ""}`);
  }
  if (carried.length) notes.push(`candidates carried from #${supersedes}: ${candidatesWords(carried)}. A correction keeps every candidate the finding it corrects held, and every reading a dispute of it gives; only a check removes one (candidates [{value, state: "ruled_out", by: job:<id>/<path> or E-<seq>, why}])`);
  if (kind === "finding" && decoyUnmarked({ value, indicates: v4.fields.indicates, decoy: v4.fields.decoy })) notes.push("its words say the payload declares itself fake, a test or a sample: if it does, record it again with decoy: what in it says so, so that it stays a decoy candidate and no answer rests on it alone");
  if (v3.fields.completion && v3.fields.completion !== "complete") {
    notes.push(`the search was ${v3.fields.completion}: this absence holds only for what was searched; record what was not reached as kind=limitation (reason ${v3.fields.completion === "failed" ? "failed" : "partial"})`);
  }
  return withTableLockRendered(ctx.sandboxRoot, async (held) => {
    const entries = await readLedger(ctx.sandboxRoot);
    const replaced = supersededBy(entries);
    const bySeq = new Map(entries.map((e) => [e.seq, e]));
    // Under the lock, what the read before it found may have changed: checked again, all of it.
    const late = [...v3.rel.flatMap((r) => relDefects(r, bySeq, replaced)), ...(supersedes !== undefined ? supersedeDefects(supersedes, bySeq, replaced) : [])];
    if (late.length) return { ok: false, reason: late.join("; "), defects: late };
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
      ...neg.fields,
      ...(method.length ? { method } : {}),
      by: ctx.agentId,
      authors: [ctx.agentId],
      at: new Date().toISOString(),
    };
    // The whole of what it says: the hashed content, and beside it the fields protocol-core's content does not hold yet (a carrier table, a control, the images read).
    const contentOf = (e: LedgerEntry) => `${ledgerContent(e)}\n${JSON.stringify({ ...negativeFieldsOf(e), carriers: (e as { carriers?: unknown }).carriers ?? null, ...(e.candidates?.length ? { candidates: e.candidates } : {}), ...(e.decoy ? { decoy: e.decoy } : {}) })}`;
    const content = contentOf(candidate);
    if (supersedes !== undefined) {
      const target = bySeq.get(supersedes) as LedgerEntry;
      // The whole of what it says, not the sentence alone: the same sentence
      // with another confidence, other refs or another status is a correction.
      if (contentOf(target) === content) return sameAsStanding(ctx, held, target, entries.length);
    }
    // A correction is always its own entry. The same content again, from
    // anyone, is the entry that stands: a second author is an attestation,
    // appended, and the entry is never rewritten.
    const sameContent = supersedes === undefined ? entries.filter((e) => !replaced.has(e.seq) && contentOf(e) === content) : [];
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

/** A negative said as a finding: its value opens with what was not found, or counts no hit. Read from the first 240 characters only. */
const NEGATIVE_WORDS = /^(?:no|none|nothing|neither|never)\b(?![-.])|\b(?:not (?:found|present|seen)|no (?:evidence|trace|sign|hits?|match(?:es)?|occurrences?|text|overlay)|(?:0|zero) (?:hits?|match(?:es)?|occurrences?|results?))\b/i;

/** Whether an entry is a negative: an absence, or a finding whose value says what was not found. */
export function negativeWorded(kind: string, value: string): boolean {
  return kind === "absence" || (kind === "finding" && NEGATIVE_WORDS.test(String(value ?? "").slice(0, 240)));
}

/** A finding that reports a search's empty result: it counts no hit, says not found, or opens with "No … found". Narrower than NEGATIVE_WORDS: "Nothing of note in the output" is a reading, not a scan. */
const SEARCH_NEGATIVE = /\b(?:0|zero|no) (?:hits?|match(?:es)?|occurrences?|results?|candidates?)\b|\bnot (?:found|present)\b|\bno (?:evidence|trace|sign|instance|occurrence|cop(?:y|ies))s? of\b|\b(?:found|returned|yielded|produced) (?:nothing|none|no \w+)\b|^(?:no|none)\b[^.]{0,120}\b(?:found|present|exists?|remains?|survives?)\b/i;

/** Whether an entry reports a search that found nothing: an absence, or a finding worded as one (SEARCH_NEGATIVE). What a control run is asked of. */
export function searchNegative(kind: string, value: string): boolean {
  return kind === "absence" || (kind === "finding" && SEARCH_NEGATIVE.test(String(value ?? "").slice(0, 300)));
}

const IMAGE_FILE = /\.(?:png|jpe?g|gif|bmp|webp|tiff?)$/i;

type ImageReads = { offset: number; read: Map<string, Set<string>> };
const imageReadsCache = new Map<string, ImageReads>();

/**
 * Which image files of the store each seat was handed by `read`, from the
 * trace (a `read` row whose path is store/jobs/<id>/out/<file> and whose
 * result is ok), read incrementally as leads.ts stdoutReads reads the
 * journal for a job's stdout: the key is job:<id>/<file>, the value the
 * seats. A picture reaches a model only through `read`, so this is the
 * record of which sheets a seat saw.
 */
export async function imageReads(sandboxRoot: string): Promise<Map<string, Set<string>>> {
  const path = join(sandboxRoot, "traces", "events.jsonl");
  const key = resolve(sandboxRoot);
  let c = imageReadsCache.get(key);
  const size = await stat(path).then((st) => st.size).catch(() => 0);
  if (!c || size < c.offset) {
    c = { offset: 0, read: new Map() };
    imageReadsCache.set(key, c);
  }
  if (size > c.offset) {
    const fh = await open(path, "r").catch(() => null);
    if (fh) {
      try {
        const buf = Buffer.alloc(size - c.offset);
        await fh.read(buf, 0, buf.length, c.offset);
        const text = buf.toString("utf8");
        const end = text.lastIndexOf("\n");
        if (end >= 0) {
          for (const line of text.slice(0, end).split("\n")) {
            if (!line.includes('"tool":"read"') || !line.includes("store/jobs/")) continue;
            try {
              const l = JSON.parse(line) as { agent?: string; tool?: string; args?: { path?: unknown }; result?: { ok?: boolean } };
              const m = /(?:^|\/)store\/jobs\/([a-z0-9-]+)\/out\/(.+)$/.exec(String(l.args?.path ?? ""));
              if (l.tool !== "read" || !l.agent || l.result?.ok === false || !m || !IMAGE_FILE.test(m[2]!)) continue;
              const k = `job:${m[1]}/${m[2]}`;
              c.read.set(k, (c.read.get(k) ?? new Set()).add(l.agent));
            } catch {
              // A torn line: the trace's own check names it.
            }
          }
          c.offset += Buffer.byteLength(text.slice(0, end + 1));
        }
      } finally {
        await fh.close();
      }
    }
  }
  return c.read;
}

/** The fields a negative carries for what it rests on: its control runs, the images read, and the sheets of the cited jobs nobody on the entry read. */
export type NegativeFields = { control?: Array<{ ref: string; found: string }>; images_read?: string[]; images_unread?: Array<{ job: string; dir: string; total: number; unread: string[] }> };

/**
 * What a negative rests on, beyond its refs (docs: the review of the one case
 * III runs, I-22 and I-07).
 *
 * A negative from the seat's own scanner needs a control: a search that
 * could not have matched reads the same as one that found nothing. On the
 * run sf4406b E-87 said "no live ChaCha20 state, 0 hits over 111.7 M key
 * offsets" where a state was there (the sweep used another file's cribs),
 * and it gave a wrong answer two seats attested; the same run's planted
 * self-tests voided nine of its own negatives. So an absence, or a finding
 * that says what was not found, whose refs name the output of a command job
 * (the seat's own script or shell line; a pack tool or a recipe that ended
 * ok reports its own completeness) names in `control` a job in which the
 * same scanner found a planted or known value: [{ref, found}].
 *
 * A negative about pictures lists the images read, and the sheets of a
 * cited job that the recorder was never handed are named on it
 * (`images_unread`): on the run s01a4f4 E-252 said no frame showed text at
 * high confidence after 3 of 11 sheets of job j000342 were read, and the
 * text was legible on m06.png. The entry is taken; an answer that cites it
 * is held by the gate until the sheets are read and it is recorded again.
 */
async function negativeBasis(sandboxRoot: string, agentId: string, input: LedgerInput, kind: string, refs: string[], value: string, D: Defects): Promise<{ fields: NegativeFields; notes: string[] }> {
  const raw = input as Record<string, unknown>;
  const fields: NegativeFields = {};
  const notes: string[] = [];
  const negative = negativeWorded(kind, value);
  // The control runs as given: {ref, found}, or a list of them.
  const controls: Array<{ ref: string; found: string }> = [];
  if (given(raw.control)) {
    for (const c of Array.isArray(raw.control) ? raw.control : [raw.control]) {
      const o = (c && typeof c === "object" ? c : { ref: c }) as { ref?: unknown; found?: unknown };
      const ref = String(o.ref ?? "").trim();
      const found = D.text(boundedText("control.found", o.found, LEDGER_WHY_MAX_CHARS)).value;
      if (!ref || !found) {
        D.add('control is {ref, found}: the job in which the same scanner found a planted or known value (job:<id>/stdout.log, job:<id>/<path>), and what it found there ("found the planted key at offset 4096")');
        continue;
      }
      if (!/^job:/.test(ref)) D.add(`control.ref names a job's output (job:<id>/stdout.log, job:<id>/<path>): a control is a run of the scanner, and ${JSON.stringify(ref)} is not one`);
      else {
        const checked = await checkRefs(sandboxRoot, [ref]);
        if (!checked.ok) D.add(`control.ref: ${checked.reason}`);
        else if (checked.resolved[0]?.status && checked.resolved[0].status !== "ok") D.add(`control.ref names ${ref}, whose job ${checked.resolved[0].status === "failed" ? "failed" : `ended ${checked.resolved[0].status}`}: a control is a run that worked and found the planted value`);
        else if (!controls.some((x) => x.ref === ref)) controls.push({ ref, found });
      }
    }
    if (controls.length) fields.control = controls;
  }
  if (!negative) {
    if (given(raw.images_read)) D.add(`images_read is a negative's: the images read for a claim that pictures do not show something (an absence, or a finding that says what was not found)`);
    return { fields, notes };
  }
  // How each cited job was run: a command job is the seat's own scanner.
  const jobs = [...new Set(refs.map((r) => /^job:([a-z0-9-]+)/.exec(r)?.[1]).filter((j): j is string => Boolean(j)))];
  const kinds = new Map<string, { kind: string; status: string }>();
  for (const j of jobs) {
    const job = await readFile(join(sandboxRoot, "store", "jobs", j, "job.json"), "utf8").then((t) => JSON.parse(t) as JobJson).catch(() => null);
    if (job) kinds.set(j, { kind: String(job.spec?.kind ?? "unknown"), status: String(job.status ?? "unknown") });
  }
  const images = refs.filter((r) => /^job:/.test(r) && IMAGE_FILE.test(r));
  const own = refs.filter((r) => {
    const j = /^job:([a-z0-9-]+)/.exec(r)?.[1];
    return Boolean(j) && kinds.get(j as string)?.kind === "command" && !IMAGE_FILE.test(r);
  });
  const reported = jobs.some((j) => (kinds.get(j)?.kind === "tool" || kinds.get(j)?.kind === "recipe") && kinds.get(j)?.status === "ok");
  if (own.length && !reported && !controls.length && searchNegative(kind, value) && String(raw.completion ?? "").trim().toLowerCase() !== "failed") {
    D.need(
      "control",
      `this ${kind === "absence" ? "absence" : "negative finding"} rests on your own scanner (${own.slice(0, 4).join(", ")}${own.length > 4 ? ", …" : ""}: the output of a command job, not of a pack tool that reports what it covered), and a search that could not have matched reads the same as one that found nothing: name its control in control: {ref: "job:<id>/stdout.log", found: "<what it found>"}, a job in which the same scanner, with the same pattern and layout, found a planted or known value (plant one in a copy and run it, or run it over a file known to hold one). Without a control, record what the scan did as a finding that says only what was run, or as a limitation`,
    );
  }
  // The pictures: the sheets beside each cited image, and which of them the recorder was handed.
  if (images.length || given(raw.images_read)) {
    const reads = await imageReads(sandboxRoot);
    const { readManifest, storePaths } = await import("../scripts/evidence-store.ts");
    const P = storePaths(sandboxRoot);
    const said = listOf(raw.images_read as string[] | string | undefined).filter((r) => /^job:/.test(r));
    const sawIt = (r: string) => reads.get(r)?.has(agentId) === true;
    const unread: NonNullable<NegativeFields["images_unread"]> = [];
    const seen = new Set<string>([...images, ...said].filter(sawIt));
    const dirs = new Set(images.map((r) => r.slice(0, r.lastIndexOf("/"))));
    for (const d of dirs) {
      const m = /^job:([a-z0-9-]+)(?:\/(.*))?$/.exec(d);
      if (!m) continue;
      const found = await readManifest(join(P.jobs, m[1]!, "manifest.json")).catch(() => null);
      const under = (found?.manifest.files ?? []).map((f) => f.path).filter((f) => IMAGE_FILE.test(f) && f.slice(0, Math.max(0, f.lastIndexOf("/"))) === (m[2] ?? ""));
      for (const f of under) if (sawIt(`job:${m[1]}/${f}`)) seen.add(`job:${m[1]}/${f}`);
      const left = under.filter((f) => !sawIt(`job:${m[1]}/${f}`));
      if (left.length && under.length > 1) unread.push({ job: m[1]!, dir: m[2] ?? "", total: under.length, unread: left.slice(0, 40) });
    }
    if (seen.size) fields.images_read = [...seen].sort().slice(0, 200);
    const claimed = said.filter((r) => !sawIt(r));
    if (claimed.length) notes.push(`images_read names ${claimed.join(", ")}, which the trace does not show you were handed by read: left out of images_read (it lists what you read, as the trace has it)`);
    if (unread.length) {
      fields.images_unread = unread;
      notes.push(`a negative about pictures holds for the pictures read, and the trace shows you were not handed ${unread.map((u) => `${u.unread.length} of the ${u.total} images of job:${u.job}${u.dir ? `/${u.dir}` : ""} (${u.unread.slice(0, 12).map((f) => f.slice(f.lastIndexOf("/") + 1)).join(", ")}${u.unread.length > 12 ? ", …" : ""})`).join("; ")}: recorded with them named (images_unread), and an answer that cites this entry is held (negative_images_unread) until you read them and record it again with supersedes`);
    }
  }
  return { fields, notes };
}

/**
 * What is wrong with the entries a coverage record names, as the ledger
 * stands: each of its result_refs that is not there, was corrected, or is
 * not what a search produces, and the record it corrects. A result that is
 * an answer is told what the answer itself rests on: a seat that names the
 * answer means the findings under it.
 */
function coverageLedgerDefects(results: readonly string[], supersedes: number | undefined, bySeq: ReadonlyMap<number, LedgerEntry>, replaced: Map<number, number>): string[] {
  const out: string[] = [];
  const product = (e: LedgerEntry | undefined) => Boolean(e) && e!.kind !== "answer" && e!.kind !== "coverage";
  for (const r of results.filter((x) => /^E-\d+$/.test(x))) {
    const n = Number(r.slice(2));
    const e = bySeq.get(n);
    if (!e) out.push(`result_refs names ${r}: there is no entry #${n} in the ledger`);
    else if (replaced.has(n)) {
      const now = standingSeq(n, replaced);
      out.push(`result_refs names ${r}, superseded by #${now}: name the entry that stands${product(bySeq.get(now)) ? ` (E-${now})` : `; E-${now} is ${bySeq.get(now)?.kind === "answer" ? "an answer" : "a coverage record"}, which is not a search's result, so leave ${r} out`}`);
    } else if (!product(e)) {
      const under = (e.support ?? []).map((x) => x.seq).filter((x) => product(bySeq.get(x)) && !replaced.has(x));
      out.push(`result_refs names ${r}, a ${e.kind}: a search's results are what it found or failed to (absences, limitations, findings, events); leave ${r} out${under.length ? `, and name what it rests on if this search produced it (${under.map((x) => `E-${x}`).join(", ")})` : ""}`);
    }
  }
  if (supersedes !== undefined) {
    const target = bySeq.get(supersedes);
    const already = replaced.get(supersedes);
    if (!target) out.push(`supersedes #${supersedes}: there is no entry #${supersedes} in the ledger`);
    else if (target.kind !== "coverage") out.push(`#${supersedes} is a ${target.kind}: a coverage record corrects a coverage record`);
    else if (already !== undefined) out.push(`#${supersedes} is already superseded by #${already}: correct #${standingSeq(already, replaced)} instead`);
  }
  return out;
}

/** What is wrong with a link to another entry, as the ledger stands: every reason, for the refusal that names them all. */
function relDefects(r: { to: number; kind: string }, bySeq: ReadonlyMap<number, LedgerEntry>, replaced: ReadonlyMap<number, number>): string[] {
  const target = bySeq.get(r.to);
  if (!target) return [`rel names #${r.to}: there is no entry #${r.to} in the ledger (list them with ledger)`];
  const out: string[] = [];
  const standing = replaced.get(r.to);
  if (r.kind === "duplicates" && standing !== undefined) out.push(`#${r.to} is superseded by #${standing}: a duplicate names the entry that stands, #${standing}`);
  if (ANSWER_ONLY_REL_KINDS.has(r.kind as (typeof LEDGER_REL_KINDS)[number]) && !(target.kind === "answer" && target.section?.startsWith("question:"))) out.push(`rel ${r.kind} weighs evidence added late against a question's conclusion: its to names that question's answer (E-<seq> of an answer, section question:<n>); #${r.to} is ${target.kind === "answer" ? `the ${target.section}` : `a ${target.kind}`}. Link another entry with supports, contradicts, duplicates or derived_from`);
  return out;
}

/** What is wrong with the entry a correction of a fact names, as the ledger stands. */
function supersedeDefects(supersedes: number, bySeq: ReadonlyMap<number, LedgerEntry>, replaced: ReadonlyMap<number, number>): string[] {
  const target = bySeq.get(supersedes);
  if (!target) return [`supersedes #${supersedes}: there is no entry #${supersedes} in the ledger (list them with ledger)`];
  const already = replaced.get(supersedes);
  if (already !== undefined) return [`#${supersedes} is already superseded by #${already}: correct #${already} instead, so the corrections stay one line (supersedes=${standingSeq(already, replaced as Map<number, number>)})`];
  if (target.kind === "answer") return [`#${supersedes} is an answer: an answer is corrected by an answer to the same section (kind=answer, supersedes=${supersedes})`];
  return [];
}

/** The fields of a negative an entry carries (negativeBasis), as a correction is compared with what it corrects. */
function negativeFieldsOf(e: LedgerEntry): NegativeFields {
  const x = e as LedgerEntry & NegativeFields;
  return { ...(x.control ? { control: x.control } : {}), ...(x.images_read ? { images_read: x.images_read } : {}), ...(x.images_unread ? { images_unread: x.images_unread } : {}) };
}

/**
 * A correction that says what the entry it corrects says, word for word,
 * with the same confidence, refs and fields: nothing is recorded, the entry
 * stands as it was, and the reply says so. It was a refusal ("a correction
 * says what is right now"), and the seat that met it had nothing to fix:
 * eight calls on the run sf4406b went on it.
 */
async function sameAsStanding(ctx: SwarmContext, held: object, target: LedgerEntry, total: number): Promise<LedgerResult> {
  renderOnceLetGo(held);
  return { ok: true, entry: target, merged: true, total, note: `#${target.seq} already says this word for word, with the same confidence, refs and fields: nothing was recorded, and #${target.seq} stands as it was (a correction says what is different now)` };
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
  renderOnceLetGo(held);
  const stood = all.find((e) => e.seq === same.seq) ?? same;
  return { ok: true, entry: stood, merged: true, total: all.length, note: already ? `#${same.seq} already says this, recorded by you` : `#${same.seq} already says this word for word: recorded as your attestation of it (ledger/attestations.jsonl), not as a new entry` };
}

/** Chain and append one entry; ledger.md is rendered again once the lock is let go (withTableLockRendered). */
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
  renderOnceLetGo(held);
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
  const r = await withTableLockRendered(sandboxRoot, async (held): Promise<LedgerResult> => {
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
  /** What ties the artefact the answer cites to what the question asks, apart from the value re-deriving (required from the run s01a4f4's review on; absent on a review recorded before). */
  link?: string;
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
export function checkAnswerReview(raw: unknown): { ok: true; review: AnswerReview } | { ok: false; reason: string; defects?: string[] } {
  const r = (raw && typeof raw === "object" ? raw : {}) as Record<string, unknown>;
  // Every defect of the review in one refusal (Defects): on the run sf4406b attest refused 80 of 206 calls, 30 of them for the three fields the form's schema named first.
  const D = new Defects();
  const shape = "answer_review is {reproduced, read, link, parts: [{part, established, why}], inference, alternatives: [{explanation, why}], other_family: {checked, text}}";
  const text = (name: string, v: unknown): { ok: true; value: string } => {
    const t = String(v ?? "").trim();
    if (!t) D.need(name, `answer_review.${name} is required (${shape}): say it, or "none" and why`);
    else if (t.length > LEDGER_ACT_MAX_CHARS) D.add(`answer_review.${name} is over ${LEDGER_ACT_MAX_CHARS} characters: say it in fewer; nothing is cut, so a longer text is refused`);
    return { ok: true, value: t };
  };
  const reproduced = text("reproduced", r.reproduced);
  const read = text("read", r.read);
  // What ties the artefact to the question, apart from the value re-deriving: the open-weight runs recorded 110, 56 and 24 attestations and no dispute while they took decoys (a browser autofill value as "the password noted down", recomputed five times and never asked whose it was).
  const linkText = String(r.link ?? "").trim();
  if (!linkText) D.need("link", `answer_review.link is required: what ties the artefact the answer cites to what the question asks, apart from the value re-deriving from it (whose it is, where it sits, when it was written, why this one and not another carrier of the same kind); a value that re-derives from the wrong artefact re-derives all the same`);
  else if (linkText.length > LEDGER_ACT_MAX_CHARS) D.add(`answer_review.link is over ${LEDGER_ACT_MAX_CHARS} characters: say it in fewer; nothing is cut, so a longer text is refused`);
  else if (placeholderText(linkText) || /^(?:the )?value (?:re-?derives|matches|was recomputed|reproduces)\b[^,;:]*\.?$/i.test(linkText)) D.add(`answer_review.link says what ties the cited artefact to the question, and ${JSON.stringify(linkText.slice(0, 80))} says only that the value re-derives (or nothing): say whose artefact it is and why it is the one the question asks about`);
  const inference = text("inference", r.inference);
  // Each alternative weighed, and why the evidence rules it out; a text is still read (an older review, a best candidate's "what else it allows").
  let alternatives: AnswerReview["alternatives"];
  if (Array.isArray(r.alternatives)) {
    if (!r.alternatives.length) D.add(`answer_review.alternatives lists each alternative explanation you considered and why the evidence rules it out, [{explanation, why}], at least one; if you weighed none, say so in a text and attest best_candidate (${shape})`);
    if (r.alternatives.length > ANSWER_REVIEW_MAX_ALTERNATIVES) D.add(`answer_review.alternatives lists at most ${ANSWER_REVIEW_MAX_ALTERNATIVES}: keep the ones a reader must weigh`);
    const list: AnswerReviewAlternative[] = [];
    for (const x of r.alternatives) {
      const o = (x && typeof x === "object" ? x : {}) as Record<string, unknown>;
      const explanation = text("alternatives[].explanation", o.explanation);
      const why = text("alternatives[].why", o.why);
      // The entries that rule it out, by seq (the attest checks each is in the ledger).
      const ev = (Array.isArray(o.evidence) ? o.evidence : o.evidence === undefined || o.evidence === null ? [] : String(o.evidence).split(/[\s,]+/)).map((v) => String(v).trim()).filter(Boolean).map((v) => (/^#\d+$/.test(v) ? `E-${v.slice(1)}` : /^e-\d+$/i.test(v) ? v.toUpperCase() : v));
      const bad = ev.find((v) => !/^E-[1-9]\d{0,6}$/.test(v));
      if (bad) D.add(`answer_review.alternatives[].evidence names entries as E-<seq> (got ${JSON.stringify(bad)}): the entries that rule the alternative out${/^(?:job|input|import|member|sha256):|^j\d{6}/.test(bad) ? `. ${JSON.stringify(bad)} is an object: it goes in the attest's refs (or in discriminator.refs), and here goes the E-<seq> of the entry that says what it shows` : ""}`);
      if (ev.length > LEDGER_MAX_CITATIONS) D.add(`answer_review.alternatives[].evidence names more than ${LEDGER_MAX_CITATIONS} entries`);
      const good = ev.filter((v) => /^E-[1-9]\d{0,6}$/.test(v)).slice(0, LEDGER_MAX_CITATIONS);
      list.push({ explanation: explanation.value, why: why.value, ...(good.length ? { evidence: [...new Set(good)] } : {}) });
    }
    alternatives = list;
  } else {
    const t = text("alternatives", r.alternatives);
    alternatives = t.value;
  }
  const partRows = Array.isArray(r.parts) ? r.parts : [];
  if (!partRows.length) D.need("parts", `answer_review.parts names each part the question asks, [{part, established: true|false, why}], at least one (${shape})`);
  if (partRows.length > ANSWER_REVIEW_MAX_PARTS) D.add(`answer_review.parts names at most ${ANSWER_REVIEW_MAX_PARTS} parts`);
  const parts: AnswerReview["parts"] = [];
  for (const p of partRows.slice(0, ANSWER_REVIEW_MAX_PARTS)) {
    const o = (p && typeof p === "object" ? p : {}) as Record<string, unknown>;
    const part = text("parts[].part", o.part);
    // "true" and "false" as words are the booleans they spell.
    if (o.established === "true" || o.established === "false") o.established = o.established === "true";
    if (typeof o.established !== "boolean") D.add(`answer_review.parts[].established is true or false: whether "${part.value}" is established`);
    const why = text("parts[].why", o.why);
    // The entry by which a partial answer declares this part open, by seq.
    let declaredOpen: string | undefined;
    if (o.declared_open !== undefined && o.declared_open !== null && String(o.declared_open).trim() !== "") {
      const v = String(o.declared_open).trim();
      const m = /^(?:#|E-)?([1-9]\d{0,6})$/i.exec(v);
      if (!m) D.add(`answer_review.parts[].declared_open names the entry by which the answer declares "${part.value}" open, as E-<seq> (a limitation or a coverage record the answer cites; got ${JSON.stringify(o.declared_open)})`);
      else declaredOpen = `E-${Number(m[1])}`;
    }
    // Against an answer's parts: the id of the part it weighs, or a part the answer leaves out (missing).
    const pid = o.id === undefined || o.id === null || String(o.id).trim() === "" ? undefined : String(o.id).trim();
    if (pid !== undefined && !PM.PART_ID.test(pid)) D.add(`answer_review.parts[].id names the answer's part by its id (a, b, who; got ${JSON.stringify(o.id)})`);
    if (o.missing !== undefined && o.missing !== null && typeof o.missing !== "boolean") D.add("answer_review.parts[].missing is true or false: whether the answer leaves this part of the question out");
    const missing = o.missing === true;
    if (missing && o.established) D.add(`answer_review.parts[]: "${part.value}" is missing from the answer, so the answer does not establish it: established false, and say in why what the evidence shows of it`);
    if (missing && pid !== undefined) D.add(`answer_review.parts[]: "${part.value}" is missing from the answer: it has no id of the answer's (leave id out)`);
    if (missing && declaredOpen) D.add(`answer_review.parts[]: "${part.value}" is missing from the answer: the answer declares nothing of it open`);
    // A part the answer holds that the question does not ask (a limitation, not an open part).
    if (o.not_asked !== undefined && o.not_asked !== null && typeof o.not_asked !== "boolean") D.add("answer_review.parts[].not_asked is true or false: whether this part of the answer is outside what the question asks");
    const notAsked = o.not_asked === true;
    if (notAsked && missing) D.add(`answer_review.parts[]: "${part.value}" is either missing (the question asks it and the answer leaves it out) or not_asked (the answer holds it and the question does not ask it), not both`);
    if (notAsked && o.established) D.add(`answer_review.parts[]: "${part.value}" is not asked by the question, so the review does not weigh it: established false, and say in why why the question does not ask it (detail beyond it, an example category, an exhaustiveness it does not demand)`);
    // A part the answer holds limited, which the review agrees the evidence in scope cannot settle.
    if (o.at_limit !== undefined && o.at_limit !== null && typeof o.at_limit !== "boolean") D.add("answer_review.parts[].at_limit is true or false: whether you agree that the evidence in scope cannot settle this part the answer holds limited");
    const atLimit = o.at_limit === true;
    if (atLimit && (o.established || missing || notAsked || pid === undefined)) D.add(`answer_review.parts[]: "${part.value}" at_limit agrees with a part the answer holds limited, by its id: established false, with id, and neither missing nor not_asked; say in why what shows the evidence cannot settle it`);
    parts.push({ ...(pid !== undefined ? { id: pid } : {}), part: part.value, established: o.established === true, why: why.value, ...(declaredOpen ? { declared_open: declaredOpen } : {}), ...(missing ? { missing: true as const } : {}), ...(notAsked ? { not_asked: true as const } : {}), ...(atLimit ? { at_limit: true as const } : {}) });
  }
  const f = (r.other_family && typeof r.other_family === "object" ? r.other_family : null) as Record<string, unknown> | null;
  if (f && (f.checked === "true" || f.checked === "false")) f.checked = f.checked === "true";
  if (!f || typeof f.checked !== "boolean") D.need("other_family", "answer_review.other_family is {checked: true|false, text}: whether a materially different source family was checked, and which, or why not");
  const ft = f && typeof f.checked === "boolean" ? text("other_family.text", f.text) : { ok: true as const, value: "" };
  const extra = checkReviewEvidence(r);
  if (!extra.ok) D.add(extra.reason);
  if (D.any) return { ok: false, reason: refusalWords("review", { list: D.list, missing: D.missing.map((m) => `answer_review.${m}`) }).replace("A review also needs", "The review also needs"), defects: [...D.list] };
  return { ok: true, review: { reproduced: reproduced.value, read: read.value, link: linkText, parts, inference: inference.value, alternatives, other_family: { checked: f!.checked as boolean, text: ft.value }, ...(extra.ok ? extra.fields : {}) } };
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
 * how to fix it. The rival-area check (rival_area_uncovered) runs for every review, with or without locators. A review with neither a locator nor a derivation is also warned
 * (`unlocated`, no_locator_or_derivation). Nothing else is
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
  // The rival-area check runs for every review (docs/adr/0013, "A locator is
  // not coverage"): each input the review's evidence was read from is covered,
  // for the question, where a rival value could live: a standing coverage
  // record naming it, every area searched or not applicable, and a job over it
  // among its results. The inputs are the located objects' when the review
  // gives locators; otherwise those the answer's support reaches (the answer's
  // refs and its cited entries' refs) and the derivation's inputs when it gives
  // one. Whatever metadata a review gives or leaves out, the same answer gets
  // the same verdict. An object that traces to no input is not held.
  {
    const entries = [...(o.entries ?? (await readLedger(sandboxRoot).catch(() => [] as LedgerEntry[])))];
    const disputes = [...(o.disputes ?? (await readDisputes(sandboxRoot).catch(() => [] as LedgerDispute[])))];
    const refs = review.reproduced_at?.length ? review.reproduced_at.map((l) => l.ref) : supportRefs(answer, entries, review);
    const uncovered = await rivalAreasUncovered(sandboxRoot, answer, refs, entries, disputes);
    if (uncovered.length) caps.push({ code: "rival_area_uncovered", why: `a locator is not coverage: ${uncovered.map((u) => `the value was read from ${u.source}, and ${u.why}`).join("; ")}` });
  }
  // Neither a locator nor a derivation given: warned as well. One given and failing is capped by its own code above.
  const unlocated: ReviewEvidenceWarning | null = !review.reproduced_at?.length && !review.derivation ? { code: "no_locator_or_derivation", why: UNLOCATED_WHY } : null;
  return { caps, unlocated, locators, derivation };
}

/**
 * The refs an answer's support reaches, for a review that locates no value:
 * the answer's own refs, the refs of every entry it reaches (answerReach: its
 * support, contrary and limitations, and what those cite in turn), and the
 * inputs of the review's derivation when it gives one.
 */
export function supportRefs(answer: LedgerEntry, entries: readonly LedgerEntry[], review: AnswerReview | null): string[] {
  const bySeq = new Map(entries.map((e) => [e.seq, e]));
  const out = new Set<string>(answer.refs ?? []);
  for (const n of answerReach(answer, bySeq, supersededBy(entries as LedgerEntry[]))) for (const r of bySeq.get(n)?.refs ?? []) out.add(r);
  for (const r of review?.derivation?.inputs ?? []) out.add(r);
  return [...out];
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
  return `reproduced: ${r.reproduced}; only read: ${r.read}${r.link ? `; what ties it to the question: ${r.link}` : ""}; parts: ${r.parts.map((p) => `${p.id ? `${p.id} ` : ""}${p.part} ${p.missing ? "MISSING from the answer" : p.not_asked ? "NOT ASKED by the question (a limitation, not an open part)" : p.at_limit ? "at the limit of the evidence, as the answer holds it" : p.established ? "established" : p.declared_open ? `open, as the answer declares it (${p.declared_open})` : "NOT established"} (${p.why})`).join("; ")}; inference: ${r.inference}; ${alternatives}; another source family ${r.other_family.checked ? "checked" : "not checked"}: ${r.other_family.text}${discriminator}${located}${derived}${premise}`;
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

/** The renders waiting or running, one chain per ledger path in this process. */
const renderChains = new Map<string, Promise<unknown>>();
/** The render asked for and not begun, by ledger path: whoever asks meanwhile is given it. */
const renderWaiting = new Map<string, Promise<string>>();

/**
 * ledger/ledger.md: the timeline in time order, the indicators, the findings.
 *
 * Renders of one ledger run one at a time, in the order they were asked for,
 * and each reads the run's records when its turn comes, not when it was asked
 * for: a render that started before a store sweep line was written can no
 * longer finish after the sweep's own render and put back a document that
 * says the sweep is pending. The chain orders the renders of this process; a
 * lock beside the registers orders them against another process. A render
 * given `entries` renders those entries (the caller holds the register), the
 * rest it reads when it runs.
 *
 * Renders asked for while one waits its turn are that one: it has read
 * nothing yet, so it will read what each of them wrote. A burst of records
 * is then one render after the one that is running, not one each (the run
 * s17fdfe rendered the document whole for each of 113 records, under the
 * table lock).
 */
export async function renderLedger(sandboxRoot: string, entries?: LedgerEntry[]): Promise<string> {
  const key = resolve(sandboxRoot);
  if (!entries) {
    const waiting = renderWaiting.get(key);
    if (waiting) return waiting;
  }
  const turn: Promise<string> = (renderChains.get(key) ?? Promise.resolve()).catch(() => undefined).then(() => {
    // Begun: what is written from now on is the next render's to read.
    if (renderWaiting.get(key) === turn) renderWaiting.delete(key);
    return withNamedLock(sandboxRoot, RENDER_LOCK, () => renderLedgerNow(sandboxRoot, entries));
  });
  if (!entries) renderWaiting.set(key, turn);
  renderChains.set(key, turn);
  try {
    return await turn;
  } finally {
    if (renderChains.get(key) === turn) renderChains.delete(key);
    if (renderWaiting.get(key) === turn) renderWaiting.delete(key);
  }
}

/** The table locks whose holder changed what ledger.md says: rendered once the lock is let go. */
const renderDue = new WeakSet<object>();
/** Said under the table lock by whoever appended to the ledger, its attestations or its disputes: the document is rendered when the lock is let go, never while it is held. */
function renderOnceLetGo(held: object): void {
  renderDue.add(held);
}

/**
 * The table lock, and ledger.md rendered after it is let go when the
 * holder changed what the document says (renderOnceLetGo): the render reads
 * the registers itself, outside the lock, and several records in a burst
 * share one (renderLedger). The run s17fdfe's records held the lock for 7
 * to 97 s each while the document was rendered whole inside it. The call
 * still returns after a render that read what it wrote.
 */
async function withTableLockRendered<T>(sandboxRoot: string, fn: (held: Parameters<Parameters<typeof withTableLock>[1]>[0]) => Promise<T>): Promise<T> {
  let mine: object | null = null;
  const result = await withTableLock(sandboxRoot, (held) => {
    // This call's own handle on the lock: what it marks is its own.
    const own = { ...held };
    mine = own;
    return fn(own);
  });
  if (mine && renderDue.has(mine)) await renderLedger(sandboxRoot);
  return result;
}

const RENDER_LOCK = "ledger-render";

async function renderLedgerNow(sandboxRoot: string, entries?: LedgerEntry[]): Promise<string> {
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
    return `${by.length ? ` [attested by ${[...new Set(by)].join(", ")}]` : ""}${against.length ? ` **[disputed by ${against.map((d) => `${d.by}: ${mdCell(d.why)}${d.reading ? ` (reads it as: ${mdCell(d.reading)})` : ""}${d.inherited_from !== undefined ? ` (raised on #${d.inherited_from}, which it corrects; open until answered)` : ""}`).join("; ")}]**` : ""}`;
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
        `- **#${e.seq}** ${e.section}${e.question_rev ? ` (revision ${e.question_rev})` : ""}${e.inconclusive ? " (inconclusive)" : ""}${e.result ? ` (${e.result})` : ""}${e.asserts_absence ? " (asserts absence)" : ""}${negText}: ${e.value || "(no value yet)"}${(e as AnswerExtras).qualifier ? ` — qualifier: ${(e as AnswerExtras).qualifier}` : ""}${candidatesOf(e, disputes).length ? ` — candidates: ${candidatesWords(candidatesOf(e, disputes))}` : ""}${e.carrier_names?.length ? ` — carriers named: ${e.carrier_names.join(", ")}` : ""}${e.decoy_check ? ` — decoy check: ${e.decoy_check.by} (${e.decoy_check.why})` : ""}${mark(e)}${e.confidence ? ` _(${e.confidence}${e.confidence_why ? `: ${e.confidence_why}` : ""})_` : ""}${cites("rests on", e.support)}${cites("contrary", e.contrary)}${e.contrary_none_why ? ` — nothing says otherwise: ${e.contrary_none_why}` : ""}${cites("limitations", e.limitations)}${e.qualifies?.length ? ` — qualifies: ${e.qualifies.map((q) => `${q.ref} (${q.why})`).join("; ")}` : ""}${e.alternatives_open ? ` — still open: ${e.alternatives_open}` : ""}${e.would_change ? ` — would change it: ${e.would_change}` : ""}${e.unsupported_tokens?.length ? ` — in none of the cited entries: ${e.unsupported_tokens.join(", ")}` : ""}${p?.length ? ` — **no longer stands on its support: ${p.join("; ")}**` : ""}${e.parts?.length ? ` — parts: ${PM.partsWords(e.parts)}` : ""}${e.premises?.length ? ` — premises: ${PM.citationsWords(e.premises)}` : ""}${e.premise_tested ? ` — ${premiseTestWords(e.premise_tested)}` : ""} — reasoning: ${e.reasoning ?? ""} — by ${e.authors.join(", ")}`,
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
  const x = e as LedgerEntry & NegativeFields & { carriers?: CarrierRow[] };
  if (x.carriers?.length) parts.push(`carriers: ${x.carriers.map((r) => `${r.carrier} (${r.state.replace("_", " ")}: ${r.why})`).join("; ")}`);
  if (e.decoy) parts.push(`DECOY (declares itself so: ${e.decoy})`);
  if (e.candidates?.length) parts.push(`candidates: ${candidatesWords(e.candidates)}`);
  if (x.control?.length) parts.push(`control: ${x.control.map((c) => `${c.ref} (${c.found})`).join("; ")}`);
  if (x.images_unread?.length) parts.push(`IMAGES NOT READ: ${x.images_unread.map((u) => `${u.unread.length} of ${u.total} of job:${u.job}${u.dir ? `/${u.dir}` : ""}`).join("; ")}`);
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

export async function listLedger(sandboxRoot: string, filter: { kind?: string; limit?: number; from?: number; ids?: number[] } = {}): Promise<LedgerEntry[]> {
  const all = await withAttestations(sandboxRoot, await readLedger(sandboxRoot));
  const kind = (filter.kind ?? "").trim().toLowerCase();
  const byKind = kind ? all.filter((e) => e.kind === kind) : all;
  const limit = Math.max(1, Math.min(500, Number(filter.limit) || 200));
  // `ids` reads exact entries, whatever their age or kind; `from` continues a listing from a seq a previous page named (entries appended
  // since come after it, none shifts or repeats); otherwise the newest `limit`.
  const wanted = filter.ids ? new Set(filter.ids) : null;
  const picked = wanted ? all.filter((e) => wanted.has(e.seq)) : filter.from !== undefined ? byKind.filter((e) => e.seq >= filter.from!) : byKind.slice(-limit);
  // A corrected entry is listed with the entry that corrects it; every entry
  // with who re-derived it and who disputes it; an answer with what keeps it
  // from standing on its support, when anything does.
  const replaced = supersededBy(all);
  const attests = (await readAttestations(sandboxRoot)).filter((a) => attestationAct(a) === "attest");
  const allDisputes = await readDisputes(sandboxRoot);
  const disputes = disputesInForce(all, allDisputes);
  const problems = all.some((e) => e.kind === "answer") ? answerProblems(all, allDisputes) : new Map<number, string[]>();
  return picked.map((e) => {
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
/** A dispute, or its withdrawal. `reading`: a dispute about a reading (a transcription, a glyph, a look-alike character) says the value as its disputer reads it, and that reading becomes a candidate of the entry (candidatesOf), never its value. */
export type LedgerDispute = { v: 1; act: "dispute" | "withdraw"; seq: number; target: string; by: string; at: string; why: string; refs?: string[]; reading?: string; prev?: string; hash?: string };

export function disputeHash(d: LedgerDispute, prev: string): string {
  // reading only when present: every dispute written before it keeps the hash it was chained with.
  const core = JSON.stringify({ v: d.v, act: d.act, seq: d.seq, target: d.target, by: d.by, at: d.at, why: d.why, ...(d.refs?.length ? { refs: d.refs } : {}), ...(d.reading ? { reading: d.reading } : {}) });
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

export type LedgerActInput = { seq?: number | string; how?: string; why?: string; refs?: string[] | string; withdraw?: boolean; review?: unknown; strength?: unknown; answer_review?: unknown; second_review_why?: string; reading?: string };

/**
 * The coverage record that carries a superseded one an answer cites, or null:
 * the standing correction of a coverage record, itself a coverage record, for
 * the same questions and at the same coverage (complete, partial, …). A
 * coverage record is revised to name what a sweep found, and on the run
 * sf4406b each revision made the answer resting on it be written again with
 * the same value (18 versions of one answer in an hour, each cutting the
 * report's acknowledgements). Such a revision does not change what the answer
 * rests on: the answer rests on the record as it now stands, which is still
 * reviewed (an unreviewed correction holds the negative), still swept, and
 * still read by the gates in place of the one cited. A correction that
 * changes the questions or the coverage is not carried: the answer is weighed
 * again.
 */
export function carriedCoverage(t: LedgerEntry, bySeq: Map<number, LedgerEntry>, replaced: Map<number, number>): LedgerEntry | null {
  if (t.kind !== "coverage" || !replaced.has(t.seq)) return null;
  const c = bySeq.get(standingSeq(t.seq, replaced));
  if (!c || c.kind !== "coverage" || c.seq === t.seq) return null;
  const qs = (e: LedgerEntry) => [...new Set((e.answers ?? []).map((x) => sectionKey(x)))].sort().join("\u0000");
  if (qs(c) !== qs(t)) return null;
  if (String((c as { coverage?: unknown }).coverage ?? "") !== String((t as { coverage?: unknown }).coverage ?? "")) return null;
  return c;
}

/** The standing entries an answer cites that were recorded for its own question (`id`, its section key); a coverage record carried by its correction (carriedCoverage) is that correction. */
export function citedForQuestion(a: LedgerEntry, bySeq: Map<number, LedgerEntry>, replaced: Map<number, number>, id: string): LedgerEntry[] {
  const out: LedgerEntry[] = [];
  for (const x of a.support ?? []) {
    const e = bySeq.get(x.seq);
    if (!e) continue;
    const now = replaced.has(e.seq) ? carriedCoverage(e, bySeq, replaced) : e;
    if (!now || out.includes(now)) continue;
    if ((now.answers ?? []).some((q) => sectionKey(q) === id)) out.push(now);
  }
  return out;
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
 * The entry an attest names (actTarget), or the entry that stands in its
 * place when the one named was corrected and every correction kept its
 * conclusion (sameConclusion: refs, evidence or wording refreshed, nothing
 * it concludes changed). The reviewer re-derived what the entry says, and
 * the correction says the same: "attest the entry that stands" cost 25
 * calls on the run sf4406b, where a coverage record was re-recorded to
 * name what a sweep found. A correction that changes the conclusion is
 * still refused, with the entry that stands: what it says now is not what
 * was reviewed.
 */
function attestStanding(entries: LedgerEntry[], raw: number | string | undefined, agentId: string, taken: string[]): { ok: true; entry: LedgerEntry } | { ok: false; reason: string } {
  const t = actTarget(entries, raw, agentId, "attest");
  if (t.ok) return t;
  const n = Number(String(raw ?? "").trim().replace(/^(?:#|E-)/i, ""));
  const named = entries.find((e) => e.seq === n);
  const replaced = supersededBy(entries);
  if (!named || !replaced.has(n)) return t;
  const bySeq = new Map(entries.map((e) => [e.seq, e]));
  let at = named;
  for (let i = 0; i < 1000 && replaced.has(at.seq); i += 1) {
    const next = bySeq.get(replaced.get(at.seq) as number);
    if (!next || !sameConclusion(at, next)) return { ok: false, reason: `${t.reason}; #${standingSeq(n, replaced)} concludes something else than #${n} did (its value, result, confidence or what it rests on changed), so read it and attest it as it is now` };
    at = next;
  }
  const now = actTarget(entries, at.seq, agentId, "attest");
  if (now.ok) taken.push(`#${n} was corrected by #${at.seq}, which concludes the same: your attest is recorded on #${at.seq}, the entry that stands`);
  return now;
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
  // Everything the call's own fields show is named in one refusal (Defects); what the ledger says of the entry is checked under the lock.
  const D = new Defects();
  const how = D.text(boundedText("how", input.how, LEDGER_ACT_MAX_CHARS));
  if (!how.value) D.need("how", "how is required: what you re-derived, from which sealed object (job:<id>/<path>, input:<path>, …), and what you only read");
  // The refs as they were plainly meant (meantRef: no out/, no store path), then each that does not resolve.
  const refs: string[] = [];
  for (const r of listOf(input.refs)) {
    const m = await meantRef(ctx.sandboxRoot, r);
    if (m) D.took(`ref ${JSON.stringify(r)} taken as ${m}: a ref has no out/ and no store path`);
    if (!refs.includes(m ?? r)) refs.push(m ?? r);
  }
  if (refs.length > LEDGER_MAX_REFS) D.add(`refs names more than ${LEDGER_MAX_REFS} objects`);
  else if (refs.length) {
    const checked = await checkRefsAll(ctx.sandboxRoot, refs);
    for (const [i, x] of checked.bad.entries()) D.add(i === checked.bad.length - 1 ? `${x.why}. ${REF_FORMS}` : x.why);
    const use = checked.bad.length ? null : await materialUseRefusal(ctx.sandboxRoot, refs);
    if (use) D.add(use);
  }
  const secondWhy = D.text(boundedText("second_review_why", input.second_review_why, LEDGER_ACT_MAX_CHARS));
  let review: NB.NegativeReview | null = null;
  if (input.review !== undefined && input.review !== null) {
    const r = NB.checkReview(input.review);
    if (!r.ok) D.add(r.reason);
    else review = r.review;
  }
  const strengthText = String(input.strength ?? "").trim().toLowerCase().replace(/[-\s]/g, "_");
  if (strengthText && !(ATTEST_STRENGTHS as readonly string[]).includes(strengthText)) D.add(`strength is established or best_candidate (got ${JSON.stringify(input.strength)})`);
  const strength = ((ATTEST_STRENGTHS as readonly string[]).includes(strengthText) ? strengthText : undefined) as AttestStrength | undefined;
  let answerReview: AnswerReview | null = null;
  if (input.answer_review !== undefined && input.answer_review !== null) {
    const r = checkAnswerReview(input.answer_review);
    if (!r.ok) for (const d of r.defects ?? [r.reason]) D.add(d);
    else answerReview = r.review;
  }
  if (D.any) return D.withTaken({ ok: false as const, reason: refusalWords("attest", { list: D.list, missing: [] }) });
  // What caps a review at best_candidate is read before the lock: the route
  // plan and the jobs under the question (the lead register), never the
  // answer's words beyond the refs and lead ids its would_change names.
  const pre = await readLedger(ctx.sandboxRoot);
  // What was taken as meant (a ref's form, attestStanding, part ids on an answer with no parts): said in the reply.
  const taken: string[] = [...D.taken];
  const takenRefs = taken.length;
  const preTarget = attestStanding(pre, input.seq, ctx.agentId, taken);
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
  const result = await withTableLockRendered(ctx.sandboxRoot, async (held): Promise<AttestResult> => {
    const entries = await readLedger(ctx.sandboxRoot);
    taken.length = takenRefs;
    const t = attestStanding(entries, input.seq, ctx.agentId, taken);
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
      // An id names one of the answer's part rows; on an answer that lists none it names nothing, and the part is weighed as written (25 refusals on the run sf4406b said only "leave the id out").
      if (byId.length && !rows.length) {
        taken.push(`#${t.entry.seq} carries no parts, so the ids in answer_review.parts (${byId.map((p) => p.id).join(", ")}) name nothing: each part is weighed as you wrote it, without an id`);
        for (const p of answerReview.parts) {
          delete p.id;
          // at_limit agrees with a row by its id: without rows there is none to agree with.
          delete p.at_limit;
        }
        byId.length = 0;
      }
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
    renderOnceLetGo(held);
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
    const said = note || locatorNote || taken.length ? [`${note ?? ""}${locatorNote}`.trim(), ...(taken.length ? [`Taken as meant, nothing to change there: ${taken.join("; ")}`] : [])].filter(Boolean).join(". ") : undefined;
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
  const reading = boundedText("reading", input.reading, LEDGER_VALUE_MAX_CHARS);
  if (!reading.ok) return reading;
  if (reading.value && input.withdraw) return { ok: false, reason: "reading is a dispute's: the value as you read it, added beside the entry's as a candidate; a withdrawal takes no reading" };
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
  return withTableLockRendered(ctx.sandboxRoot, async (held) => {
    const entries = await readLedger(ctx.sandboxRoot);
    const t = actTarget(entries, input.seq, ctx.agentId, "dispute");
    if (!t.ok) return t;
    if (reading.value && t.entry.kind !== "answer" && t.entry.kind !== "finding") return { ok: false, reason: `reading is the value as you read it, a candidate beside an answer's or a finding's value; #${t.entry.seq} is a ${t.entry.kind}: say what does not hold in why` };
    const target = t.entry.hash ?? ledgerHash(t.entry, "genesis");
    const all = await readDisputes(ctx.sandboxRoot);
    // A dispute stands on the correction of the entry it named until the
    // disputer answers it (B18): withdrawn by naming either entry.
    const standing = disputesInForce(entries, all).find((d) => d.target === target && d.by === ctx.agentId);
    if (input.withdraw && !standing) return { ok: false, reason: `you have no standing dispute of #${t.entry.seq} to withdraw` };
    if (!input.withdraw && standing) return { ok: true, line: standing, appended: false, note: standing.inherited_from !== undefined ? `you disputed #${standing.inherited_from}, which #${t.entry.seq} corrects, and that dispute stands on it until you withdraw it: ${standing.why}` : `you dispute #${t.entry.seq} already: ${standing.why}` };
    // A withdrawal names the dispute it ends: the entry that dispute was raised on.
    const named = standing?.inherited_from !== undefined ? entries.find((e) => e.seq === standing.inherited_from) : undefined;
    const d: LedgerDispute = { v: 1, act: input.withdraw ? "withdraw" : "dispute", seq: named ? named.seq : t.entry.seq, target: named ? (named.hash ?? ledgerHash(named, "genesis")) : target, by: ctx.agentId, at: new Date().toISOString(), why: why.value, ...(refs.length ? { refs } : {}), ...(reading.value ? { reading: reading.value } : {}) };
    const prev = all.at(-1)?.hash ?? "genesis";
    const line: LedgerDispute = { ...d, prev, hash: disputeHash(d, prev) };
    await held.assertOwned();
    await mkdir(join(ctx.sandboxRoot, LEDGER_DIR), { recursive: true });
    await appendFile(join(ctx.sandboxRoot, LEDGER_DISPUTES), `${JSON.stringify(line)}\n`, "utf8");
    renderOnceLetGo(held);
    return { ok: true, line, appended: true };
  });
}

// --- answers --------------------------------------------------------------------------------

/** The fields an answer never takes: it rests on entries, not objects, and states no event. */
const NOT_ANSWER_FIELDS = ["ts", "refs", "answers", "rel", "clock", "precision", "basis", "status", "reason", "completion", "attribution", "locators", "indicates", "alternatives", "alternatives_none_why", "significance", "carriers", "decoy", "control", "images_read", ...COVERAGE_ONLY_FIELDS] as const;

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

/** The roles an entry is cited in by an answer. */
export type CitedRole = "support" | "limitation";

/**
 * The one role-aware rule for an entry that rests on the kept output of a job
 * that did not succeed (docs/adr/0013): an answer that cites it as support
 * stands on those bytes, so the entry must say why they still hold (the
 * answer's qualifies), at the append and at the finish alike; an answer that
 * cites it as a limitation names what could not be done, and the failed job is
 * the limitation's subject, not a defect of the answer. The append check,
 * answerProblems (the answers check, the finish gate, the report and the
 * adoption count through it) and the failed-job note all ask here.
 */
export function failedJobIsDefect(role: CitedRole): boolean {
  return role === "support";
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
    for (const [edges, role, citedAs] of [[a.support ?? [], "rests on", "support"], [a.limitations ?? [], "is bounded by", "limitation"]] as const) {
      for (const edge of edges) {
        let t = bySeq.get(edge.seq);
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
          if (cited.has(now)) continue;
          // A coverage record revised for the same questions and coverage carries the answer (carriedCoverage): what follows is read on the
          // correction, which the answer now rests on.
          const carried = carriedCoverage(t, bySeq, replaced);
          if (!carried) {
            out.push(`it ${role} E-${t.seq}, superseded by #${now}, and does not cite the correction`);
            continue;
          }
          t = carried;
        }
        const against = disputed.get(t.hash ?? edge.hash);
        if (against?.length && !qualified(t.seq)) out.push(`it ${role} E-${t.seq}, disputed by ${against.map(disputeWords).join("; ")}`);
        const bad = failed.get(t.seq);
        if (bad?.length && !qualified(t.seq) && failedJobIsDefect(citedAs)) out.push(`it ${role} E-${t.seq}, which rests on the kept output of a job that did not succeed (${bad.join(", ")}) and says nothing of it`);
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
async function registerRevision(sandboxRoot: string, sectionId: string): Promise<{ id: string; rev: number; text: string } | null> {
  const Q = await import("./questions.ts");
  const q = (await Q.questionsSnapshot(sandboxRoot)).bySection.get(sectionId);
  return q ? { id: q.id, rev: q.rev, text: q.text } : null;
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
async function recordCoverage(ctx: SwarmContext, input: LedgerInput, D: Defects): Promise<LedgerResult> {
  const raw = input as Record<string, unknown>;
  const notHere = [...ANSWER_ONLY_FIELDS.filter((f) => f !== "alternatives_open"), "indicates", "alternatives_none_why", "significance", "status", "reason", "completion", "ts", "clock", "precision", "basis", "attribution", "locators", "carriers", "decoy", "candidates", "control", "images_read"].filter((f) => given(raw[f]) && !(f === "alternatives" && typeof raw[f] === "string"));
  if (notHere.length) D.add(`${notHere.join(", ")} ${notHere.length === 1 ? "is" : "are"} not a coverage record's: it says what a search covered, and the entries it rests on say what was found${notHere.length > 1 ? " (leave them out)" : ""}`);
  const proposition = String(input.proposition ?? "").trim();
  const said = String(input.value ?? "").trim();
  if (proposition && said && proposition !== said) D.add("value and proposition are the same field on a coverage record (the proposition searched): give one");
  const value = proposition || said;
  if (!value) D.need("value", "proposition (or value) is required: the proposition the search tested, in one sentence (\"the account signed in from outside the office network\")");
  if (value.length > LEDGER_VALUE_MAX_CHARS) D.add(`the proposition is over ${LEDGER_VALUE_MAX_CHARS} characters`);
  const text = (name: string, v: unknown, required = true): { ok: true; value: string } => {
    const t = D.text(boundedText(name, v, NB.COVERAGE_TEXT_MAX));
    if (required && !t.value) D.need(name, `${name} is required on a coverage record${name === "skipped" || name === "failures" ? ' ("none" when nothing was, with how that is known)' : ""}`);
    return t;
  };
  const timeRange = D.text(text("time_range", input.time_range));
  const method = D.text(text("search_method", input.search_method));
  const settings = D.text(text("settings", input.settings));
  const actual = D.text(text("coverage_actual", input.coverage_actual));
  const skipped = D.text(text("skipped", input.skipped));
  const failures = D.text(text("failures", input.failures));
  const alternatives = D.text(boundedText("alternatives", typeof raw.alternatives === "string" ? raw.alternatives : input.alternatives_open, NB.COVERAGE_TEXT_MAX));
  if (!alternatives.value) D.need("alternatives", "alternatives is required: the explanations or routes still open, or none and why on a coverage record");
  const d = (input.detection_opportunity ?? {}) as { trace_expected?: unknown; why?: unknown };
  const expected = String(d.trace_expected ?? "").trim().toLowerCase();
  const expectedOk = (NB.TRACE_EXPECTED as readonly string[]).includes(expected);
  if (!expectedOk) D.need("detection_opportunity", "detection_opportunity is {trace_expected: yes | no | unknown, why}: would the event have left a trace in these sources, given what was collected and what they keep, and why");
  const dWhy = expectedOk ? text("detection_opportunity.why", d.why) : { ok: true as const, value: "" };
  // The areas the search reached, when it names them: a completeness claim
  // ("every file", "all connections") rests on a record that does.
  let areas: NB.CoverageAreas | undefined;
  if (given(raw.areas)) {
    const a = NB.checkAreas(raw.areas);
    if (!a.ok) D.add(a.reason);
    else areas = a.areas;
    if (areas && Object.values(areas).includes("skipped") && /^none\b/i.test(skipped.value)) D.add(`areas says ${NB.COVERAGE_AREAS.filter((k) => areas![k] === "skipped").join(", ")} skipped, and skipped says none: say in skipped what was not searched and why`);
  }
  // The ask for a source the evidence does not hold, or why none was opened.
  const askRaw = String(input.acquisition_ask ?? "").trim();
  const noAsk = D.text(text("acquisition_none_why", input.acquisition_none_why, false));
  if (askRaw && noAsk.value) D.add("acquisition_ask names the ask opened, acquisition_none_why says why none was: give one");
  let acquisitionAsk: string | undefined;
  if (askRaw) {
    const m = /^R-?([1-9]\d{0,6})$/i.exec(askRaw);
    if (!m) D.add(`acquisition_ask names an acquisition request, R-<n> (got ${JSON.stringify(askRaw)}): open one with lead_close needs_operator and ask {kind: acquisition, …}`);
    else acquisitionAsk = `R-${Number(m[1])}`;
    const R = await import("./requests.ts");
    const req = acquisitionAsk ? ((await R.requestsSnapshot(ctx.sandboxRoot).catch(() => null))?.requests.get(acquisitionAsk) ?? null) : null;
    if (acquisitionAsk && !req) D.add(`acquisition_ask ${acquisitionAsk} is not a request of this run: open it with lead_close needs_operator and ask {kind: acquisition, source, where, expected_value, urgency}`);
    else if (req && req.kind !== "acquisition") D.add(`acquisition_ask ${acquisitionAsk} is a ${req.kind} request, not an acquisition`);
  }
  // What a hit would contain, were the answer in the evidence: the hub
  // sweeps every output the run holds for it (store-sweep.ts). Or why no
  // literal form exists.
  const SW = await import("./store-sweep.ts");
  const lookedRaw = raw.looked_for;
  const lookedList = (Array.isArray(lookedRaw) ? lookedRaw : given(lookedRaw) ? [lookedRaw] : []).map((t) => String(t ?? "").trim());
  const lookedNone = D.text(text("looked_for_none_why", input.looked_for_none_why, false));
  if (lookedList.length && lookedNone.value) D.add("looked_for names the strings a hit would contain, looked_for_none_why says why there are none: give one");
  if (!lookedList.length && !lookedNone.value) {
    D.need("looked_for", `looked_for is required on a coverage record: the literal strings a hit would contain if the answer were in the evidence (names, identifiers, addresses, keywords), at least one, each ${SW.SWEEP_TERM_MIN} to ${SW.SWEEP_TERM_MAX} characters; the hub searches every output the run already holds for them (job outputs, imports, tool-output/), not only the objects named here. When no literal form exists, say why in looked_for_none_why`);
  }
  const lookedFor: string[] = [];
  for (const t of lookedList) {
    if (t.length < SW.SWEEP_TERM_MIN) D.add(`looked_for ${JSON.stringify(t)} is shorter than ${SW.SWEEP_TERM_MIN} characters: a string that short matches everything; name what a hit would contain`);
    else if (t.length > SW.SWEEP_TERM_MAX) D.add(`a looked_for string is over ${SW.SWEEP_TERM_MAX} characters: name the distinctive part a hit would contain; nothing is cut, so a longer one is refused`);
    else if (!lookedFor.some((x) => x.toLowerCase() === t.toLowerCase())) lookedFor.push(t);
  }
  if (lookedFor.length > SW.SWEEP_MAX_TERMS) D.add(`looked_for names more than ${SW.SWEEP_MAX_TERMS} strings: keep the ones a hit would contain`);
  const source = D.text(boundedText("source", input.source, LEDGER_SOURCE_MAX_CHARS));
  const evidence = D.text(boundedText("evidence", input.evidence, LEDGER_EVIDENCE_MAX_CHARS));
  const answers = listOf(input.answers);
  if (!answers.length) D.need("answers", 'answers is required on a coverage record: the questions its search was for ("3", "Q-19")');
  if (answers.length > LEDGER_MAX_ANSWERS) D.add(`answers names more than ${LEDGER_MAX_ANSWERS} sections`);
  const badAnswer = answers.find((a) => !LEDGER_ANSWER_ID.test(a));
  if (badAnswer) D.add(`answers takes the questions' section ids (got ${JSON.stringify(badAnswer)})`);
  const objects = [...new Set((Array.isArray(input.refs) ? input.refs.map(String) : String(input.refs ?? "").split(/[\s,]+/)).map((r) => r.trim()).filter(Boolean))];
  if (!objects.length) D.need("refs", "refs is required on a coverage record: the objects the search was over (input:<path>, member:<gen>#<n>, job:<id>/<path>, …); the hub holds the jobs behind it to them");
  if (objects.length > LEDGER_MAX_REFS) D.add(`refs names more than ${LEDGER_MAX_REFS} objects: name the directory or the container that holds them`);
  // Each object resolves, or is a directory of the run's objects (the evidence
  // directory, a job's whole output, a generation) as the job scopes take it.
  const badObjects: string[] = [];
  for (const obj of objects.slice(0, LEDGER_MAX_REFS)) {
    const checked = await checkRefsAll(ctx.sandboxRoot, [obj]);
    if (!checked.bad.length) continue;
    const dir = await NB.coverageDirectory(ctx.sandboxRoot, obj);
    if (!dir.ok) badObjects.push(checked.bad[0]!.why);
  }
  for (const [i, why] of badObjects.entries()) D.add(i === badObjects.length - 1 ? `${why}. ${REF_FORMS}` : why);
  let results = [...new Set((Array.isArray(input.result_refs) ? input.result_refs.map(String) : String(input.result_refs ?? "").split(/[\s,]+/)).map((r) => r.trim()).filter(Boolean))].map((r) => (/^#\d+$/.test(r) ? `E-${r.slice(1)}` : /^e-\d+$/i.test(r) ? r.toUpperCase() : r));
  // The results as they were plainly meant: an entry that was corrected is the entry that stands (the only one a record can bind), and an answer or a coverage record among them, which no search produces, is left out when what the search did produce is named beside it. Each is said.
  {
    const now = await readLedger(ctx.sandboxRoot, { raw: true });
    const bySeq = new Map(now.map((e) => [e.seq, e]));
    const replaced = supersededBy(now);
    const product = (e: LedgerEntry | undefined) => Boolean(e) && e!.kind !== "answer" && e!.kind !== "coverage";
    const meant: string[] = [];
    const notes: string[] = [];
    for (const r of results) {
      const n = /^E-(\d+)$/.exec(r) ? Number(r.slice(2)) : null;
      if (n === null || !bySeq.has(n)) {
        meant.push(r);
        continue;
      }
      const at = replaced.has(n) ? standingSeq(n, replaced) : n;
      if (!product(bySeq.get(at))) {
        notes.push(`result_refs ${r}${at !== n ? `, now E-${at},` : ""} is ${bySeq.get(at)?.kind === "answer" ? "an answer" : "a coverage record"}, which no search produces: left out`);
        continue;
      }
      if (at !== n) notes.push(`result_refs ${r} was corrected by #${at}: taken as E-${at}, the entry that stands (a record binds the results that stand; read E-${at} if you have not)`);
      if (!meant.includes(`E-${at}`)) meant.push(`E-${at}`);
    }
    // Only when something the search produced is left: a record whose every result was an answer is told what a result is.
    if (meant.length && notes.length) {
      results = meant;
      for (const x of notes) D.took(x);
    }
  }
  if (!results.length) D.need("result_refs", "result_refs is required: what the search produced, the entries (E-<seq>: an absence, a limitation, a finding) and the job outputs (job:<id>[/<path>])");
  if (results.length > LEDGER_MAX_CITATIONS) D.add(`result_refs names more than ${LEDGER_MAX_CITATIONS}`);
  const jobRefs = results.filter((r) => !/^E-\d+$/.test(r));
  const badResults = jobRefs.filter((r) => !/^(job|import|member|sha256|input):/.test(r));
  if (badResults.length) D.add(`result_refs names entries as E-<seq> and objects as job:<id>[/<path>] (got ${badResults.map((r) => JSON.stringify(r)).join(", ")})`);
  for (const x of (await checkRefsAll(ctx.sandboxRoot, jobRefs.filter((r) => !badResults.includes(r)))).bad) D.add(`result_refs: ${x.why}`);
  const inventory = await NB.inventoryRevision(ctx.sandboxRoot);
  const givenRev = String(input.inventory_rev ?? "").trim();
  if (givenRev && givenRev !== inventory) D.add(`inventory_rev ${givenRev} is not the run's inventory now (${inventory}): the evidence changed since the search; leave it out, and the hub writes the one the record is made against`);
  let supersedes: number | undefined;
  if (input.supersedes !== undefined && input.supersedes !== null && String(input.supersedes).trim() !== "") {
    const n = Number(String(input.supersedes).trim().replace(/^#/, ""));
    if (!Number.isInteger(n) || n < 1) D.add(`supersedes names an entry by its seq, a whole number (got ${JSON.stringify(input.supersedes)})`);
    else supersedes = n;
  }
  const because = D.text(boundedText("because", input.because, LEDGER_BECAUSE_MAX_CHARS));
  if (because.value && supersedes === undefined && !given(input.supersedes)) D.add("because says why a correction corrects: give supersedes too");
  if (input.sensitive !== undefined && input.sensitive !== null && typeof input.sensitive !== "boolean") D.add("sensitive is true or false");
  // What the ledger says of the entries it names, read here so that it is named with the rest (the lock checks it again): on the run sf4406b one coverage record met "result_refs names E-255, a answer", "E-254, superseded by #255" and "E-255, a answer" in three calls.
  {
    const now = await readLedger(ctx.sandboxRoot, { raw: true });
    for (const why of coverageLedgerDefects(results, supersedes, new Map(now.map((e) => [e.seq, e])), supersededBy(now))) D.add(why);
  }
  const refused = D.refusal("coverage");
  if (refused) return refused;
  // The planned routes of the questions it is for, and the jobs under them.
  const bars = await Promise.all(answers.map((a) => questionBar(ctx.sandboxRoot, a)));
  const L = await import("./leads.ts");
  const leads = await L.leadsSnapshot(ctx.sandboxRoot);
  const method2 = await ledgerMethods(ctx.sandboxRoot, objects);
  const recorded = await withTableLockRendered(ctx.sandboxRoot, async (held): Promise<LedgerResult> => {
    const entries = await readLedger(ctx.sandboxRoot);
    const bySeq = new Map(entries.map((e) => [e.seq, e]));
    const replaced = supersededBy(entries);
    const late = coverageLedgerDefects(results, supersedes, bySeq, replaced);
    if (late.length) return { ok: false, reason: late.join("; "), defects: late };
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
    notes.push(`it names ${unexamined.length === 1 ? "an object" : `${unexamined.length} objects`} an earlier sweep found hits in, and no entry among its result_refs says what ${unexamined.length === 1 ? "it" : "each"} showed: ${unexamined.slice(0, SWEEP_GATE_HITS).map((u) => u.ref).join(", ")}${unexamined.length > SWEEP_GATE_HITS ? ` and ${unexamined.length - SWEEP_GATE_HITS} more` : ""}. Naming a hit is not examining it: a negative resting on this record is held (sweep_hits) until you record what each showed (a finding, an event or a limitation whose refs name the object, or one absence whose refs list several, written after the sweep) and record the coverage again citing them in result_refs`);
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

/** How many standing entries must cite a finding before it is a premise the run stands on (premisesUnreviewed). */
export const PREMISE_CITERS_MIN = 5;

/**
 * The findings a run stands on that nobody checked: a standing finding at
 * high confidence, recorded by one seat, attested by no other and under no
 * dispute, that at least PREMISE_CITERS_MIN later standing entries cite (five:
 * on the five one case ledgers read for it most findings are high and
 * unreviewed, two citers named 26 to 51 of them a run, five names 1 to 13): by
 * a link (rel supports or derived_from), as support of an answer, among a
 * coverage record's results, or as E-<seq> in what they say. On the run
 * s01a4f4 E-81 ("key and nonce are runtime-only values", high, unreviewed)
 * was cited by eleven entries and fixed the team's search for 115 minutes;
 * it was wrong in what it ruled out. Refs and links only: nothing here
 * judges the finding. Read by the gate as a warning (premise_unreviewed),
 * and exported for the header's review offers.
 */
export function premisesUnreviewed(entries: LedgerEntry[], attestations: readonly LedgerAttestation[], disputes: LedgerDispute[] = []): Array<{ entry: LedgerEntry; citers: number[] }> {
  const replaced = supersededBy(entries);
  const disputed = new Set(disputesInForce(entries, disputes).map((d) => d.target));
  const out: Array<{ entry: LedgerEntry; citers: number[] }> = [];
  const standing = entries.filter((e) => !replaced.has(e.seq));
  // What each standing entry cites, read once.
  const cites = new Map<number, Set<number>>();
  for (const e of standing) {
    const set = new Set<number>([...(e.rel ?? []).filter((r) => r.kind === "supports" || r.kind === "derived_from").map((r) => r.to), ...(e.support ?? []).map((x) => x.seq), ...(e.result_refs ?? []).filter((r) => /^E-\d+$/.test(r)).map((r) => Number(r.slice(2))), ...answerCitations(`${e.value}\n${e.evidence ?? ""}\n${e.indicates ?? ""}\n${e.source ?? ""}`)]);
    set.delete(e.seq);
    cites.set(e.seq, set);
  }
  for (const f of standing) {
    if (f.kind !== "finding" || f.confidence !== "high") continue;
    const hash = f.hash ?? ledgerHash(f, "genesis");
    if (disputed.has(hash) || f.authors.some((a) => a !== f.by)) continue;
    if (attestations.some((a) => a.target === hash && a.by !== f.by)) continue;
    const citers = standing.filter((e) => e.seq > f.seq && cites.get(e.seq)?.has(f.seq)).map((e) => e.seq);
    if (citers.length >= PREMISE_CITERS_MIN) out.push({ entry: f, citers });
  }
  return out;
}

/** Whether every correction from `seq` to the entry that stands kept its conclusion (sameConclusion at each step). */
function sameConclusionChain(seq: number, bySeq: ReadonlyMap<number, LedgerEntry>, replaced: ReadonlyMap<number, number>): boolean {
  let at = bySeq.get(seq);
  for (let i = 0; at && i < 1000 && replaced.has(at.seq); i += 1) {
    const next = bySeq.get(replaced.get(at.seq) as number);
    if (!next || !sameConclusion(at, next)) return false;
    at = next;
  }
  return Boolean(at);
}

/** What an answer carries beside the fields protocol-core names: the words that qualify its value, and why a revision changed the value. */
export type AnswerExtras = { qualifier?: string; value_changed_because?: string };

const CONFIDENCE_RANK: Record<string, number> = { low: 1, medium: 2, high: 3 };

/** The digests a text holds (32 hex digits or more), lower-cased: the candidates a transcription question carries. */
function digestsOf(text: string): string[] {
  return [...new Set([...String(text ?? "").matchAll(/(?<![0-9a-f])[0-9a-f]{32,128}(?![0-9a-f])/gi)].map((m) => m[0].toLowerCase()))];
}

/**
 * A review changes how sure an answer is, never what it says. On three runs
 * a right answer in the asked form was replaced by a sentence after its
 * critic doubted it: on the run s68ce47 E-253, a bare digest, became E-262
 * "A 22-character overlay is visible. The best-supported no-newline MD5
 * candidate is …" (established to partial, high to medium), and on the run
 * s530aa4 E-260, a name and a digest in the asked form, became E-267
 * "Strongest current candidate: …"; the graded string was gone from the
 * ledger's value. So, on a question that asks a
 * format: a revision that lowers the confidence or moves the result off
 * established, and whose earlier value's first line was in the format, keeps
 * that first line; the doubt goes in confidence, result, parts and
 * qualifier. It may change the value only by saying why in
 * value_changed_because, naming the entry (E-<seq>) that shows the earlier
 * value wrong. And a candidate is not removed by argument: a digest the
 * earlier answer held (in value or qualifier) stays in the revision's value
 * or qualifier unless value_changed_because names the entry that rules it
 * out (a transcription dispute adds a candidate; a machine check removes
 * one). Each defect in words; empty when the revision keeps to it.
 */
export function reviewValueRule(earlier: LedgerEntry & AnswerExtras, now: { value: string; qualifier: string; confidence: string; result: string; changed: string }, questionWords: string | null, bySeq: ReadonlyMap<number, LedgerEntry>, supersedes: number): string[] {
  const f = questionWords ? questionFormat(questionWords) : null;
  if (!f) return [];
  const was = firstLine(earlier.value);
  const lowered = (CONFIDENCE_RANK[now.confidence] ?? 0) < (CONFIDENCE_RANK[earlier.confidence ?? ""] ?? 0) || (NB.answerResult(earlier) === "established" && now.result !== "established");
  const cited = answerCitations(now.changed).filter((n) => n !== supersedes && bySeq.has(n));
  const out: string[] = [];
  if (now.changed && !cited.length) out.push(`value_changed_because names the entry that shows the earlier value wrong, as E-<seq> (${answerCitations(now.changed).length ? "the one it names is not in the ledger, or is the answer being revised" : "it names none"}): a doubt alone changes confidence or result, not the value`);
  if (cited.length) return out;
  if (lowered && was && f.pattern.test(was) && firstLine(now.value) !== was) {
    out.push(`this revision lowers ${NB.answerResult(earlier) === "established" && now.result !== "established" ? `the result of #${supersedes} (established to ${now.result || "none"})` : `the confidence of #${supersedes} (${earlier.confidence} to ${now.confidence || "none"})`} and also changes its value, which was in the asked format (${JSON.stringify(was)}): a drop in confidence or a dispute changes confidence, result and parts, never the value. Record it again with value ${JSON.stringify(was)} unchanged and the doubt in qualifier ("best candidate: …; open: …"); if the value itself is wrong, say why in value_changed_because, naming the entry that shows it (E-<seq>)`);
  }
  const dropped = digestsOf(`${earlier.value}\n${earlier.qualifier ?? ""}`).filter((d) => !digestsOf(`${now.value}\n${now.qualifier}`).includes(d));
  if (dropped.length && !out.length) {
    out.push(`this revision drops ${dropped.length === 1 ? "a candidate" : "candidates"} #${supersedes} held (${dropped.join(", ")}): a dispute about a reading adds a candidate and only a check that rules one out removes it. Keep ${dropped.length === 1 ? "it" : "them"} in qualifier ("candidates: …"), or say in value_changed_because which entry rules ${dropped.length === 1 ? "it" : "them"} out (E-<seq>)`);
  }
  return out;
}

/** "Nothing remains open", as an answer's alternatives_open says it. */
const NONE_OPEN = /^\s*(?:none\b|nothing\b|no (?:material |other |further |plausible |credible )*(?:candidates?|alternatives?|carriers?|explanations?|rivals?)\b[^.;]*\b(?:remains?|is|are|left)\b|all (?:other )?(?:candidates|alternatives|carriers)\b[^.;]*\b(?:eliminated|excluded|ruled out|decoded|rejected))/i;

/** One row of a finding's carrier table: a place the answer could be carried in, and whether it was decoded. */
export type CarrierRow = { carrier: string; state: "decoded" | "undecodable" | "not_examined"; why: string };
export const CARRIER_STATES = ["decoded", "undecodable", "not_examined"] as const;
export const LEDGER_MAX_CARRIERS = 60;

/**
 * "No candidate remains open" is held to the carriers the record names.
 * On the run s530aa4 E-187 chose its answer at high confidence with "No
 * material candidate remains open" while one carrier of 21 had no decode,
 * and the open-weight runs took decoys through 110, 56 and 24 attestations
 * with no dispute. What the registers can tell, and no more: an established
 * answer that says nothing remains open is refused when a finding it cites
 * carries a table of carriers with a row not examined, and when it cites
 * such a table beside a coverage record that names more objects than the
 * table has rows (a carrier with no row). An answer that cites no table is
 * not held by those two: nothing on the record says that it chose among
 * carriers (a first version held every such answer that cited a partial
 * coverage record, and refused 21 answers the three replayed runs had
 * recorded, none of them a choice among carriers). An answer that says it
 * chose among carriers (carrier_names, N of them) is held whatever it cites:
 * it may say nothing remains open, or be recorded established, only once the
 * tables it cites have a row for each of the N.
 */
export function carriersOpen(alternativesOpen: string, cited: ReadonlyArray<LedgerEntry & { carriers?: CarrierRow[] }>, o: { names?: readonly string[]; result?: string } = { result: "established" }): string[] {
  const none = NONE_OPEN.test(alternativesOpen);
  const out: string[] = [];
  const tables = cited.filter((e) => e.kind === "finding" && e.carriers?.length);
  const names = o.names ?? [];
  if (names.length && (none || o.result === "established")) {
    const missing = carriersWithoutRow(names, tables);
    if (missing.length) {
      const where = tables.length ? `the carrier table${tables.length > 1 ? "s" : ""} it cites (${tables.map((t) => `E-${t.seq}`).join(", ")}) ${tables.length > 1 ? "have" : "has"} no row for ${missing.length} of them` : `it cites no carrier table, so none of them has a row`;
      out.push(`this answer names ${names.length} carrier${names.length === 1 ? "" : "s"} (carrier_names) and ${where} (${missing.slice(0, 8).join(", ")}${missing.length > 8 ? ", …" : ""}): ${none ? "nothing can be said to remain open" : "it cannot be recorded established"} until each carrier has a row. Record the carrier table, a finding with carriers [{carrier, state: decoded | undecodable | not_examined, why}] and a row for each of the ${names.length}, and cite it; or record this answer partial, saying in alternatives_open which carriers are open`);
    }
  }
  if (!none || o.result !== "established") return out;
  for (const t of tables) {
    const open = (t.carriers ?? []).filter((r) => r.state === "not_examined");
    if (open.length) out.push(`alternatives_open says nothing remains open, and E-${t.seq}'s carrier table has ${open.length} not examined (${open.slice(0, 6).map((r) => r.carrier).join(", ")}${open.length > 6 ? ", …" : ""}): examine ${open.length === 1 ? "it" : "them"} and record the table again, or say in alternatives_open which ${open.length === 1 ? "carrier is" : "carriers are"} open`);
  }
  if (!tables.length) return out;
  const rows = Math.max(0, ...tables.map((t) => (t.carriers ?? []).length));
  for (const c of cited.filter((e) => e.kind === "coverage" && (e.refs?.length ?? 0) > rows)) {
    out.push(`alternatives_open says nothing remains open, and the coverage record E-${c.seq} names ${c.refs!.length} objects where the carrier table cited has ${rows} ${rows === 1 ? "row" : "rows"}: record the table again with a row for each carrier (carriers [{carrier, state: decoded | undecodable | not_examined, why}]), or say in alternatives_open what is still open`);
  }
  return out;
}

/**
 * The candidates a record holds beside its value (docs/protocol.md, "Ledger"): each still open, ruled out by
 * a machine check it names, or a decoy. The review of the Batman III runs found right answers replaced on a
 * critic's doubt (s68ce47 E-253 to E-262) and a reading dropped by argument; the digests a qualifier held were
 * the only candidates the hub tracked (reviewValueRule). Here a candidate is a row of the record itself: a
 * revision carries every row of the entry it corrects, and a reading a dispute in force says (its reading),
 * and the earlier value when the revision lowers the confidence or answers an objection; a row leaves only
 * as ruled_out, naming the job, or the entry resting on one, whose result excludes it.
 */
export type CandidateRow = { value: string; state: "open" | "ruled_out" | "decoy"; why: string; by?: string };
export const CANDIDATE_STATES = ["open", "ruled_out", "decoy"] as const;
export const LEDGER_MAX_CANDIDATES = 20;

/** A candidate's value as rows are matched: its words, spacing and letter case aside. */
export function candidateKey(v: string): string {
  return String(v ?? "").trim().replace(/\s+/g, " ").toLowerCase();
}

const CANDIDATES_SHAPE =
  "candidates is [{value, state: open | ruled_out | decoy, why, by?}]: each value still weighed beside value (open, why: what reads it so), one a check excludes (ruled_out, by: the job job:<id>/<path>, or the entry E-<seq> resting on one, whose result excludes it), or a payload that declares itself fake, a test or a vendor's sample (decoy, why: what in it says so)";

/** The candidate rows a record sends, their shape checked (each defect named once in D); a `by` is weighed against the ledger by candidateCheckDefects. */
export function candidateRows(raw: unknown, D: Defects): CandidateRow[] {
  if (!given(raw)) return [];
  const rows: CandidateRow[] = [];
  for (const c of Array.isArray(raw) ? raw : [raw]) {
    const o = (c && typeof c === "object" ? c : typeof c === "string" ? { value: c } : {}) as Record<string, unknown>;
    const value = D.text(boundedText("a candidate's value", o.value, LEDGER_VALUE_MAX_CHARS)).value;
    const state = D.one(oneOf("a candidate's state", o.state ?? "open", CANDIDATE_STATES)).value;
    const why = D.text(boundedText("a candidate's why", o.why, LEDGER_WHY_MAX_CHARS)).value;
    const by = D.text(boundedText("a candidate's by", o.by, LEDGER_REF_MAX_CHARS)).value;
    if (!value || !state || !why) {
      D.add(CANDIDATES_SHAPE);
      continue;
    }
    if (state === "ruled_out" && !by) {
      D.add(`candidate ${JSON.stringify(value.slice(0, 80))} is ruled_out with no check: by names the job (job:<id>/<path>) or the entry (E-<seq>) whose result excludes it. An argument, a doubt or another reading rules nothing out: the candidate stays open`);
      continue;
    }
    const row: CandidateRow = { value, state, why, ...(state === "ruled_out" ? { by } : {}) };
    const at = rows.findIndex((r) => candidateKey(r.value) === candidateKey(value));
    if (at >= 0) rows[at] = row;
    else rows.push(row);
  }
  if (rows.length > LEDGER_MAX_CANDIDATES) D.add(`candidates lists more than ${LEDGER_MAX_CANDIDATES}: keep the ones a reader must weigh, and group the rest in qualifier`);
  return rows.slice(0, LEDGER_MAX_CANDIDATES);
}

/**
 * Why the entry E-<n> is not a machine check that can rule a candidate out, or null when it is one: a
 * standing finding, event, absence or coverage record, not marked decoy, that rests on a job's result
 * (a job:<id>/<path> in its refs or its results, or a control run).
 */
export function entryCheckWhy(n: number, bySeq: ReadonlyMap<number, LedgerEntry>, replaced: ReadonlyMap<number, number>): string | null {
  const x = bySeq.get(n);
  if (!x) return `E-${n}: there is no entry #${n} in the ledger`;
  if (replaced.has(n)) return `E-${n} is superseded by #${standingSeq(n, replaced as Map<number, number>)}: name the entry that stands`;
  if (!["finding", "event", "absence", "coverage", "ioc"].includes(x.kind)) return `E-${n} is ${/^[aeiou]/.test(x.kind) ? "an" : "a"} ${x.kind}: a check that rules a candidate out is a job's result, or a finding, an event, an absence or a coverage record that rests on one`;
  if (x.decoy) return `E-${n} is marked decoy: what declares itself fake checks nothing`;
  const jobs = [...(x.refs ?? []), ...(x.result_refs ?? [])].some((r) => r.startsWith("job:")) || (x.control?.length ?? 0) > 0;
  if (!jobs) return `E-${n} rests on no job's result (no job:<id>/<path> in its refs, no control run): it is a reading or an argument, which adds a candidate and removes none`;
  return null;
}

/** Why `by` is not a machine check, or null when it is: a job that ended well (job:<id>[/<path>], or j<id>), or an entry entryCheckWhy holds. */
export async function machineCheckWhy(sandboxRoot: string, by: string, bySeq: ReadonlyMap<number, LedgerEntry>, replaced: ReadonlyMap<number, number>): Promise<string | null> {
  const t = by.trim();
  const e = /^(?:E-|#)(\d+)$/i.exec(t);
  if (e) return entryCheckWhy(Number(e[1]), bySeq, replaced);
  const ref = /^j\d{6}\b/.test(t) ? `job:${t}` : t;
  if (!ref.startsWith("job:")) return `${JSON.stringify(t)} is not a check: name the job (job:<id>/<path>) or the entry resting on one (E-<seq>)`;
  const c = await checkRefsAll(sandboxRoot, [ref]);
  if (c.bad.length) return `${ref}: ${c.bad[0]!.why}`;
  const failed = c.resolved.find((r) => r.kind === "job" && r.status && r.status !== "ok");
  if (failed) return `${ref} is the output of a job that did not succeed (${failed.status}): its result excludes nothing`;
  return null;
}

/** Each row's check that does not hold, in words (one defect each). */
export async function candidateCheckDefects(sandboxRoot: string, rows: readonly CandidateRow[], bySeq: ReadonlyMap<number, LedgerEntry>, replaced: ReadonlyMap<number, number>): Promise<string[]> {
  const out: string[] = [];
  for (const r of rows) {
    if (r.state !== "ruled_out" || !r.by) continue;
    const why = await machineCheckWhy(sandboxRoot, r.by, bySeq, replaced);
    if (why) out.push(`candidate ${JSON.stringify(r.value.slice(0, 80))} is ruled out by ${r.by}, which is not a machine check: ${why}. Keep it open (state open), or name the job whose result excludes it`);
  }
  return out;
}

/** The readings disputes in force say of an entry: each a candidate beside its value. */
export function readingsOn(e: LedgerEntry, inForce: readonly DisputeInForce[]): Array<{ by: string; reading: string; seq: number }> {
  const h = e.hash ?? ledgerHash(e, "genesis");
  return inForce.filter((d) => d.act === "dispute" && d.target === h && d.reading).map((d) => ({ by: d.by, reading: d.reading as string, seq: d.inherited_from ?? d.seq }));
}

/**
 * The candidates of a revision: the rows it sends, and every row of the entry it corrects that it does not
 * send again (a row leaves only as ruled_out, with its check), each reading a dispute in force on that entry
 * says, and the earlier value's first line when the revision lowers the confidence or the result, answers a
 * dispute or says why the value changed (`kept`) and its value no longer holds it: ruled out when
 * value_changed_because names a machine check (`check`), open otherwise.
 * What the hub added is said in `carried`.
 */
export function carryCandidates(
  earlier: LedgerEntry,
  sent: readonly CandidateRow[],
  o: { value: string; readings: ReadonlyArray<{ by: string; reading: string; seq: number }>; kept: boolean; check?: string },
): { rows: CandidateRow[]; carried: CandidateRow[] } {
  const rows: CandidateRow[] = [...sent];
  const carried: CandidateRow[] = [];
  const now = candidateKey(firstLine(o.value));
  const has = (v: string) => candidateKey(v) === now || rows.some((r) => candidateKey(r.value) === candidateKey(v));
  const add = (r: CandidateRow) => {
    if (has(r.value) || rows.length >= LEDGER_MAX_CANDIDATES) return;
    rows.push(r);
    carried.push(r);
  };
  for (const r of earlier.candidates ?? []) add({ value: r.value, state: r.state, why: r.why, ...(r.by ? { by: r.by } : {}) });
  // The earlier value is carried only when the new one no longer holds it ("Bob" revised to "Bob, at the console" keeps it).
  const was = firstLine(earlier.value ?? "");
  if (was && o.kept && candidateKey(was) !== now && !candidateKey(o.value).includes(candidateKey(was))) {
    add(o.check ? { value: was, state: "ruled_out", why: `the value #${earlier.seq} held, which value_changed_because shows wrong`, by: o.check } : { value: was, state: "open", why: `the value #${earlier.seq} held: a lower confidence or an objection keeps it a candidate until a check rules it out` });
  }
  for (const x of o.readings) add({ value: x.reading, state: "open", why: `the reading ${x.by}'s dispute of #${x.seq} gives` });
  return { rows, carried };
}

/** A record's candidates as a reader is shown them: its rows, then the readings of the disputes in force on it that no row holds. */
export function candidatesOf(e: LedgerEntry, inForce: readonly DisputeInForce[]): CandidateRow[] {
  const rows: CandidateRow[] = [...(e.candidates ?? [])];
  for (const x of readingsOn(e, inForce)) if (!rows.some((r) => candidateKey(r.value) === candidateKey(x.reading))) rows.push({ value: x.reading, state: "open", why: `the reading ${x.by}'s dispute gives` });
  return rows;
}

/** Candidate rows in words, for a rendered line or a reply. */
export function candidatesWords(rows: readonly CandidateRow[]): string {
  return rows.map((r) => `${r.value} (${r.state === "ruled_out" ? `ruled out by ${r.by}` : r.state}: ${r.why})`).join("; ");
}

/** Words a payload uses of itself when it is not the real thing: said to its recorder, never refused (the mark is the recorder's). */
const SELF_DECLARED_DECOY = /\b(?:fake|decoy|dummy|placeholder|not (?:the )?real|test (?:flag|key|value|data|string|payload)|sample (?:data|file|payload)|vendor(?:'s)? sample|example (?:key|value|password))\b/i;

/** Whether a finding's words say its payload declares itself a decoy, while the finding carries no decoy mark. */
export function decoyUnmarked(e: Pick<LedgerEntry, "value" | "indicates" | "decoy">): boolean {
  return !e.decoy && SELF_DECLARED_DECOY.test(`${e.value ?? ""}\n${e.indicates ?? ""}`);
}

/**
 * A decoy is a candidate, never on its own the answer (the open-weight runs took decoys through 110, 56 and
 * 24 attestations with no dispute). An answer whose value's first line is a candidate marked decoy (its own
 * row, or a row of a finding it cites), or whose findings for its question are all marked decoy, is refused
 * unless it names, in decoy_check, the machine check that shows the decoy is the answer all the same.
 */
export function decoyRule(o: { value: string; result: string; rows: readonly CandidateRow[]; findings: readonly LedgerEntry[]; cited: readonly LedgerEntry[]; checked: boolean }): string[] {
  if (o.checked || !o.value || !(o.result === "established" || o.result === "partial")) return [];
  const now = candidateKey(firstLine(o.value));
  const out: string[] = [];
  const own = o.rows.find((r) => r.state === "decoy" && candidateKey(r.value) === now);
  const theirs = o.cited.find((e) => (e.candidates ?? []).some((r) => r.state === "decoy" && candidateKey(r.value) === now));
  if (own || theirs) out.push(`value is a candidate marked decoy (${own ? `in this answer's candidates: ${own.why}` : `in E-${theirs!.seq}'s candidates`}): a payload that declares itself fake, a test or a vendor's sample is not the answer on its own. Answer on what the case's own data shows, or name the machine check that shows the decoy is the answer all the same: decoy_check {by: job:<id>/<path> or E-<seq>, why}`);
  const decoys = o.findings.filter((e) => e.decoy);
  if (!out.length && o.findings.length && decoys.length === o.findings.length) out.push(`every finding this answer cites for its question is marked decoy (${decoys.map((e) => `E-${e.seq}: ${e.decoy}`).join("; ")}): a payload that declares itself fake, a test or a vendor's sample cannot be the sole support of value. Cite a finding on the case's own data, or name the machine check that shows the decoy is the answer all the same: decoy_check {by: job:<id>/<path> or E-<seq>, why}`);
  return out;
}

/** Whether a carrier-table row names the carrier `name`: the same words, or the same file name when one of them is a bare name. */
function rowNames(row: string, name: string): boolean {
  const a = candidateKey(row);
  const b = candidateKey(name);
  if (a === b) return true;
  const base = (s: string) => s.slice(s.lastIndexOf("/") + 1);
  return (!a.includes("/") || !b.includes("/")) && base(a) === base(b);
}

/** The carriers an answer names that no row of the tables it cites holds. */
export function carriersWithoutRow(names: readonly string[], tables: ReadonlyArray<LedgerEntry>): string[] {
  const rows = tables.flatMap((t) => (t.carriers ?? []).map((r) => r.carrier));
  return names.filter((n) => !rows.some((r) => rowNames(r, n)));
}

/** Record an answer (recordEntry with kind=answer): its checks need the ledger, so they run under the lock. */
async function recordAnswer(ctx: SwarmContext, input: LedgerInput, D: Defects): Promise<LedgerResult> {
  const raw = input as Record<string, unknown>;
  const secIn = answerSection(String(input.section ?? ""));
  if (!secIn.ok) D.need("section", secIn.reason);
  // Checked on as a question's answer when the section is not readable: the rest of the entry is still named in the one refusal.
  const sec = secIn.ok ? secIn : { ok: true as const, section: "question:?", id: "?" };
  const question = sec.section.startsWith("question:");
  // answers on an answer that names its own question says nothing the section does not: left out, and said (20 refusals on the run sf4406b were this field).
  if (given(raw.answers) && secIn.ok && question && listOf(raw.answers as string[] | string).every((a) => sectionKey(a) === sec.id)) {
    delete raw.answers;
    D.took(`answers is left out: on an answer the section names the question (${sec.section})`);
  }
  // The fields of a fact on an answer: all of them, and the two calls that record what was meant.
  const wrong = NOT_ANSWER_FIELDS.filter((f) => given(raw[f]));
  if (wrong.length) {
    const fact = wrong.some((f) => (COVERAGE_ONLY_FIELDS as readonly string[]).includes(f)) ? "coverage" : wrong.includes("ts") ? "event" : "finding";
    D.add(
      `${wrong.join(", ")} ${wrong.length === 1 ? "is" : "are"} not an answer's: an answer rests on ledger entries it cites as E-<seq>; record the fact itself as a finding, an event or an indicator first. Two calls, in this order: (1) record_${fact} (record with kind=${fact}) with the fact and ${wrong.length === 1 ? "that field" : "those fields"}${fact === "finding" ? `, and answers: ["${question && secIn.ok ? sec.id : "<question id>"}"]` : ""}; its reply gives the entry's seq, E-<n>. (2) this answer again without ${wrong.join(", ")}, citing E-<n> in reasoning. If the fact is on the ledger already, send only the second call, citing its E-<seq>`,
    );
  }
  let value = String(input.value ?? "").trim();
  // The answer in two fields (the run s082123: five right answers out of eleven were sentences in the ledger while the report held the exact strings): value is the asked string, alone, or empty while it is not known; qualifier holds whatever qualifies it (a candidate, what is open, the words around it). The format check reads value only.
  const qualifier = D.text(boundedText("qualifier", raw.qualifier, LEDGER_VALUE_MAX_CHARS));
  let resultPeek = String(input.result ?? "").trim().toLowerCase().replace(/-/g, "_");
  if (input.inconclusive === true && !resultPeek) resultPeek = "not_determinable";
  if (!value && !(question && qualifier.value && resultPeek && resultPeek !== "established")) {
    D.need("value", question ? `value is required: the answer itself, as the reader is to be told it${qualifier.value ? " (it may be empty only on an answer that is not established, whose qualifier says what is known and what is open)" : ""}` : sec.section === "summary" ? "value is required: the summary a decision maker reads first" : "value is required: what happened, in a paragraph; the whole narrative goes in reasoning");
  }
  if (qualifier.value && !question) D.add("qualifier is a question's answer's: what qualifies the asked string in value (a candidate, the part still open)");
  if (value.length > LEDGER_VALUE_MAX_CHARS) {
    D.add(`value is over ${LEDGER_VALUE_MAX_CHARS} characters: put the rest in reasoning`);
    value = value.slice(0, LEDGER_VALUE_MAX_CHARS);
  }
  const reasoning = D.text(boundedText("reasoning", input.reasoning, LEDGER_REASONING_MAX_CHARS));
  if (!reasoning.value) D.need("reasoning", "reasoning is required: how the cited entries lead to the answer, citing E-<seq> for every claim");
  let confidence = String(input.confidence ?? "").trim().toLowerCase();
  if (confidence && !(LEDGER_CONFIDENCE as readonly string[]).includes(confidence)) {
    D.add(`confidence must be one of ${LEDGER_CONFIDENCE.join(", ")}`);
    confidence = "";
  }
  const why = D.text(boundedText("confidence_why", input.confidence_why, LEDGER_WHY_MAX_CHARS));
  const openAlt = D.text(boundedText("alternatives_open", input.alternatives_open, LEDGER_WHY_MAX_CHARS));
  const change = D.text(boundedText("would_change", input.would_change, LEDGER_WHY_MAX_CHARS));
  if (question) {
    if (!confidence && !given(input.confidence)) D.need("confidence", "an answer to a question says how sure: confidence high, medium or low, with confidence_why");
    if (!why.value) D.need("confidence_why", "confidence_why is required: the quality of the evidence the answer rests on, not a count of it");
    if (!openAlt.value) D.need("alternatives_open", "alternatives_open is required: what else could still explain it, or that nothing remains open and why");
    if (!change.value) D.need("would_change", "would_change is required: what evidence would change this answer");
  } else if (why.value && !confidence) D.add("confidence_why says why that confidence: give confidence too");
  if (input.inconclusive !== undefined && input.inconclusive !== null && typeof input.inconclusive !== "boolean") D.add("inconclusive is true or false");
  if (input.sensitive !== undefined && input.sensitive !== null && typeof input.sensitive !== "boolean") D.add("sensitive is true or false");
  const contrary = D.seqs(seqList("contrary", input.contrary));
  const limits = D.seqs(seqList("limitations", input.limitations));
  let resultText = String(input.result ?? "").trim().toLowerCase().replace(/-/g, "_");
  const resultGiven = Boolean(resultText);
  if (resultText && !(LEDGER_ANSWER_RESULTS as readonly string[]).includes(resultText)) {
    D.add(`result is one of ${LEDGER_ANSWER_RESULTS.join(", ")} (got ${JSON.stringify(input.result)})`);
    resultText = "";
  }
  // The old way of saying it: inconclusive is not_determinable, and is recorded as both.
  if (input.inconclusive === true) {
    if (resultText && resultText !== "not_determinable") D.add(`inconclusive is the old word for result not_determinable: it cannot come with result ${resultText}`);
    if (question) resultText = "not_determinable";
  }
  if (question && !resultText && !resultGiven) {
    D.need(
      "result",
      "an answer to a question states its result: established (answered on findings), partial (part of it), bounded_negative (no evidence of it found in a named scope: rests on a coverage record), not_determinable (the evidence cannot settle it: rests on a coverage record too), out_of_scope (the case's evidence cannot bear on it) or premise_not_supported (what it takes for granted does not hold)",
    );
  }
  if (input.asserts_absence !== undefined && input.asserts_absence !== null && typeof input.asserts_absence !== "boolean") D.add("asserts_absence is true or false");
  if (input.asserts_absence === true && resultText !== "bounded_negative") D.add("asserts_absence says the event did not happen: it comes with result bounded_negative, on an existence question whose coverage record is complete and says the event would have left a trace");
  const noneWhy = D.text(boundedText("contrary_none_why", input.contrary_none_why, LEDGER_WHY_MAX_CHARS));
  // result on a summary or a narrative says nothing (only a question's answer has one): left out, and said.
  if (!question && resultText && !noneWhy.value && input.asserts_absence !== true) {
    D.took(`result is left out: it is a question's answer's, and this is the ${sec.section}`);
    resultText = "";
  }
  if (!question && (resultText || noneWhy.value || input.asserts_absence === true)) D.add("result, asserts_absence and contrary_none_why are a question's answer's");
  let questionRev: number | undefined;
  if (input.question_rev !== undefined && input.question_rev !== null && String(input.question_rev).trim() !== "") {
    const n = Number(input.question_rev);
    if (!Number.isInteger(n) || n < 1) D.add(`question_rev is the revision of the question this answers, a whole number (got ${JSON.stringify(input.question_rev)})`);
    else if (!question) D.add("question_rev is a question's answer's");
    else questionRev = n;
  }
  if (noneWhy.value && contrary.seqs.length) D.add("contrary_none_why says no entry says otherwise: give contrary or contrary_none_why, not both");
  // The claim and open-part rows and the premises it cites (premises.ts):
  // their shape here, what they name in the registers under the locks.
  const partsIn = PM.parseParts(input.parts);
  if (!partsIn.ok) D.add(partsIn.reason);
  const citesIn = PM.parseCitations(input.premises);
  if (!citesIn.ok) D.add(citesIn.reason);
  const parts = partsIn.ok ? partsIn.parts : [];
  const citations = citesIn.ok ? citesIn.citations : [];
  if (!question && (parts.length || citations.length)) D.add("parts and premises are a question's answer's; a summary or a narrative cites the questions it sums up (Q-<n>)");
  // The test of what the question presumes (docs/adr/0011, "What a question presumes"): its shape here, its objects now, its entries under the lock.
  let premiseTest: PM.PremiseTest | undefined;
  if (input.premise_tested !== undefined && input.premise_tested !== null && input.premise_tested !== "") {
    if (!question) D.add("premise_tested is a question's answer's: the test of what the question presumes");
    const t = checkPremiseTest(input.premise_tested, "premise_tested");
    if (!t.ok) D.add(t.reason);
    else {
      const objects = t.test.refs.filter((r) => !/^E-\d+$/.test(r));
      if (objects.length) {
        const c = await checkRefs(ctx.sandboxRoot, objects);
        if (!c.ok) D.add(`premise_tested.refs: ${c.reason}`);
      }
      premiseTest = t.test;
    }
  }
  if (question && resultText === "partial" && partsIn.ok && !parts.some((p) => p.status === "open" || p.status === "limited")) D.add(PARTIAL_NEEDS_OPEN_PART);
  const openParts = parts.filter((p) => p.status === "open");
  if (question && resultText === "established" && openParts.length) {
    D.add(`result established claims every part the question asks, and ${openParts.map((p) => `"${p.id}"`).join(", ")} ${openParts.length === 1 ? "is" : "are"} open: record it partial (its open parts named, each with what bounds it), or establish ${openParts.length === 1 ? "it" : "them"} on the entries that show ${openParts.length === 1 ? "it" : "them"} (status established, refs)`);
  }
  // A part at the limit of the evidence is still a part the answer does not
  // establish: it keeps the answer partial, and the report says it is beyond
  // the evidence rather than open to more work (docs/adr/0013, "A part at the
  // limit of the evidence"). It never lifts the label.
  const limitedParts = parts.filter((p) => p.status === "limited");
  if (question && resultText === "established" && limitedParts.length) {
    D.add(`result established claims every part the question asks, and ${limitedParts.map((p) => `"${p.id}"`).join(", ")} ${limitedParts.length === 1 ? "is" : "are"} at the limit of the evidence: a part the answer does not establish keeps it partial. Record it partial, with ${limitedParts.length === 1 ? "that part" : "those parts"} limited (the report says ${limitedParts.length === 1 ? "it is" : "they are"} beyond the evidence, not open to more work), or establish ${limitedParts.length === 1 ? "it" : "them"} on the entries that show ${limitedParts.length === 1 ? "it" : "them"}`);
  }
  // What bounds an open part outside the ledger: an acquisition ask the requests hold, or a route the lead register holds.
  for (const p of openParts) {
    if (p.open_by?.startsWith("R-")) {
      const R = await import("./requests.ts");
      const req = (await R.requestsSnapshot(ctx.sandboxRoot).catch(() => null))?.requests.get(p.open_by);
      if (!req) D.add(`parts: "${p.id}" is open by ${p.open_by}, which is not a request of this run (swarm.sh requests <run> list; an agent's ask is lead_close needs_operator with ask {kind: acquisition, …})`);
      else if (req.kind !== "acquisition") D.add(`parts: "${p.id}" is open by ${p.open_by}, a ${req.kind} request: an open part is bounded by an acquisition ask (the source that would settle it), a route (L-<n>), or a limitation or a coverage record (E-<seq>)`);
    }
    if (p.open_by?.startsWith("L-")) {
      const L = await import("./leads.ts");
      const l = (await L.leadsSnapshot(ctx.sandboxRoot).catch(() => null))?.state.leads.get(p.open_by);
      if (!l) D.add(`parts: "${p.id}" is open by ${p.open_by}, which is not in the lead register (leads lists them): name the lead whose route would examine it`);
    }
  }
  // A person's question is a hypothesis to test: its answer names what says
  // otherwise, or says why nothing does (extensions/questions.ts).
  if (question && secIn.ok && !contrary.seqs.length && !noneWhy.value) {
    const asker = await personsQuestion(ctx.sandboxRoot, sec.id).catch(() => null);
    if (asker) D.add(`${sec.section} is ${asker}: a person's question is a proposition to test, never a conclusion to confirm. Name the entries that say otherwise (contrary), or say why none does (contrary_none_why); result premise_not_supported is an answer`);
  }
  const quals: Array<{ seq: number; why: string }> = [];
  for (const q of Array.isArray(input.qualifies) ? input.qualifies : []) {
    const n = Number(String(q?.ref ?? "").trim().replace(/^(?:#|E-)/i, ""));
    const text = D.text(boundedText("a qualifies why", q?.why, LEDGER_WHY_MAX_CHARS));
    if (!Number.isInteger(n) || n < 1 || !text.value) D.add(`an answer's qualifies is [{ref: "E-<seq>", why}]: a cited entry that is disputed or rests on a failed job, and why it still supports the answer${/^job:|^j\d{6}/.test(String(q?.ref ?? "").trim()) ? ` (got ${JSON.stringify(q?.ref)}, an object: name the entry that cites it)` : ""}`);
    else if (!quals.some((x) => x.seq === n)) quals.push({ seq: n, why: text.value });
  }
  let supersedes: number | undefined;
  if (input.supersedes !== undefined && input.supersedes !== null && String(input.supersedes).trim() !== "") {
    const n = Number(String(input.supersedes).trim().replace(/^(?:#|E-)/i, ""));
    if (!Number.isInteger(n) || n < 1) D.add(`supersedes names an entry by its seq, a whole number (got ${JSON.stringify(input.supersedes)})`);
    else supersedes = n;
  }
  const because = D.text(boundedText("because", input.because, LEDGER_BECAUSE_MAX_CHARS));
  // Set when the section is answered already and this names no supersedes: the hub then takes it as the revision of the standing answer (below), so because is in place.
  if (because.value && supersedes === undefined && !given(input.supersedes) && !question) D.add("because says why a correction corrects: give supersedes too");
  // Why a revision changes the asked string itself (reviewValueRule): the entry that shows the earlier value wrong.
  const valueChanged = D.text(boundedText("value_changed_because", raw.value_changed_because, LEDGER_WHY_MAX_CHARS));
  // The candidates beside value (candidateRows), the carriers the answer chose among (carriersOpen), and the
  // machine check that holds a decoy as the answer all the same (decoyRule): their shape here, the ledger under the lock.
  const candidatesIn = candidateRows(raw.candidates, D);
  if (candidatesIn.length && !question) D.add("candidates is a question's answer's: the values still weighed beside the asked string; a summary or a narrative says them in words");
  const carrierNames: string[] = [];
  if (given(raw.carrier_names)) {
    const list = Array.isArray(raw.carrier_names) ? raw.carrier_names.map(String) : String(raw.carrier_names).split(/[\n,]+/);
    for (const n of list) {
      const t = D.text(boundedText("a carrier name", n, LEDGER_REF_MAX_CHARS)).value;
      if (t && !carrierNames.some((x) => candidateKey(x) === candidateKey(t))) carrierNames.push(t);
    }
    if (!question) D.add("carrier_names is a question's answer's: the carriers its value could be in, each with a row in the carrier table it cites");
    else if (carrierNames.length > LEDGER_MAX_CARRIERS) D.add(`carrier_names names more than ${LEDGER_MAX_CARRIERS} carriers: group the ones that share a state in the carrier table, and name the groups`);
  }
  let decoyCheck: { by: string; why: string } | undefined;
  if (given(raw.decoy_check)) {
    const d = (raw.decoy_check && typeof raw.decoy_check === "object" && !Array.isArray(raw.decoy_check) ? raw.decoy_check : {}) as Record<string, unknown>;
    const by = D.text(boundedText("decoy_check.by", d.by, LEDGER_REF_MAX_CHARS)).value;
    const dWhy = D.text(boundedText("decoy_check.why", d.why, LEDGER_WHY_MAX_CHARS)).value;
    if (!by || !dWhy) D.add("decoy_check is {by, why}: the machine check (job:<id>/<path>, or E-<seq> of an entry resting on one) that shows the payload marked decoy is the answer all the same, and why");
    else if (!question) D.add("decoy_check is a question's answer's");
    else decoyCheck = { by, why: dWhy };
  }
  // A downgrade names its counter-evidence (docs/adr/0013, round 13: a
  // correct established answer was walked down to not determinable by a
  // dispute that cited nothing against it).
  let downgrade: { evidence: string[]; why: string } | undefined;
  if (input.downgrade !== undefined && input.downgrade !== null) {
    const shape = "downgrade is {evidence: [E-<seq> or objects], why}: what undermines the earlier answer's chain, and why";
    const d = (typeof input.downgrade === "object" && !Array.isArray(input.downgrade) ? input.downgrade : {}) as Record<string, unknown>;
    const dWhy = D.text(boundedText("downgrade.why", d.why, LEDGER_WHY_MAX_CHARS));
    const ev = listOf(d.evidence as string[] | string | undefined).map((r) => (/^#\d+$/.test(r) ? `E-${r.slice(1)}` : /^e-\d+$/i.test(r) ? r.toUpperCase() : r));
    if (!ev.length || !dWhy.value) D.add(shape);
    else if (ev.length > LEDGER_MAX_CITATIONS) D.add(`downgrade.evidence names more than ${LEDGER_MAX_CITATIONS}`);
    else {
      const objects = ev.filter((r) => !/^E-\d+$/.test(r));
      if (objects.length) {
        const c = await checkRefs(ctx.sandboxRoot, objects);
        if (!c.ok) D.add(`downgrade.evidence: ${c.reason}`);
      }
      downgrade = { evidence: ev, why: dWhy.value };
    }
  }
  // The finish phase (extensions/finish.ts): while the coordinator
  // assembles the finish (it holds the lease and the registers are met but
  // for what is late, a confirmation or a resolution), another seat's
  // revision of an answer is recorded only when it says why it changes a
  // conclusion (material). A rewording or a restatement is refused
  // quietly: on the c10 pilot's tail, answers revised again and again kept
  // re-offering confirmations and making late results, and the finish never
  // closed. The coordinator's own folding is free.
  const materialWhy = D.text(boundedText("material", input.material, LEDGER_WHY_MAX_CHARS));
  if (supersedes !== undefined && !materialWhy.value) {
    const F = await import("./finish.ts");
    const lease = (await F.readFinish(ctx.sandboxRoot).catch(() => null))?.lease ?? null;
    if (lease && lease.holder !== ctx.agentId && (await F.finishPhase(ctx.sandboxRoot).catch(() => null))?.assembling) {
      return { ok: false, quiet: true, deferred: { coordinator: lease.holder, generation: lease.generation }, reason: `the finish is being assembled by ${lease.holder}; revise only with material: why (what conclusion this revision changes: its result, its value, what it rests on). A rewording or a restatement is not recorded now, and nothing is lost: ${lease.holder} folds what stands into the report` };
    }
  }
  const source = D.text(boundedText("source", input.source, LEDGER_SOURCE_MAX_CHARS));
  const evidence = D.text(boundedText("evidence", input.evidence, LEDGER_EVIDENCE_MAX_CHARS));
  // The entries its rows name are citations as the text's are: a part's refs and the entry that bounds an open part, a premise citation's refs.
  const rowRefs = [...parts.flatMap((p) => [...(p.refs ?? []), ...(p.open_by?.startsWith("E-") ? [p.open_by] : []), ...(p.limited_by ? [p.limited_by] : [])]), ...citations.flatMap((c) => c.refs ?? []), ...(premiseTest?.refs ?? []).filter((r) => /^E-\d+$/.test(r))].map((r) => Number(r.slice(2)));
  const cited = [...new Set([...answerCitations(`${value}\n${qualifier.value}\n${reasoning.value}`), ...rowRefs])].filter((n) => Number.isInteger(n) && n > 0);
  const support = cited.filter((n) => !contrary.seqs.includes(n) && !limits.seqs.includes(n));
  // A summary or a narrative cites the questions it sums up symbolically
  // (Q-<n>): bound to each answer's conclusion, not to its seq (A4).
  const symbolic: Array<{ q: string; section: string }> = [];
  if (!question) {
    for (const name of symbolicQuestions(`${value}\n${reasoning.value}`)) {
      const id = name.startsWith("question:") ? sectionKey(name.slice("question:".length)) : sectionKey(await registerSection(ctx.sandboxRoot, name));
      if (!LEDGER_ANSWER_ID.test(id)) D.add(`${name} is not a question this run has (questions list names them)`);
      else if (!symbolic.some((x) => x.section === `question:${id}`)) symbolic.push({ q: name, section: `question:${id}` });
    }
  }
  if (support.length + contrary.seqs.length + limits.seqs.length > LEDGER_MAX_CITATIONS) D.add(`the answer cites more than ${LEDGER_MAX_CITATIONS} entries: cite the ones it rests on`);
  // The negative bar (extensions/negative-bar.ts): what the question is, as the registers say.
  const bar = question && secIn.ok ? await questionBar(ctx.sandboxRoot, sec.id) : null;
  // What the case policy says of more evidence: under no, an acquisition ask is declined at once, and acquisition_none_why names the policy instead.
  const moreEvidence = question && resultText === "not_determinable" ? await import("./requests.ts").then((R) => R.casePolicyMoreEvidence(ctx.sandboxRoot)).catch(() => "ask" as const) : "ask";
  const negative = NB.NEGATIVE_RESULTS.has(resultText);
  const absolute = question ? NB.absoluteAbsenceForms(`${value}\n${qualifier.value}\n${reasoning.value}`) : [];
  if (absolute.length && !input.asserts_absence) {
    D.add(`it is worded as the event's absence (${absolute.map((f) => `"${f}"`).join(", ")}): a negative says "No evidence of <what> was found in <scope>". "It did not happen" is for an existence question whose coverage record is complete and says the event would have left a trace there, recorded with asserts_absence: true`);
  }
  if (negative && bar?.material && !bar.routes.length) {
    D.add(`${sec.section} is a material question with no route plan: a ${NB.resultWords(resultText)} closes against the sources and methods planned before the search. Give the lead under it its routes (lead_link with routes [{source, method}]), then record this again`);
  }
  // What the registers and the ledger say of it is checked under their locks and collected with the rest. Without a section there is no question to hold it to: what its own fields show is named now.
  if (!secIn.ok) return D.refusal("answer") as LedgerResult;
  // Which revision of the question it answers, held still while the answer
  // is written: the register's lock (the questions' amendments take it too),
  // then the ledger's. A question amended since the agent read it refuses
  // the answer; one amended past revision 1 needs its revision said.
  const recorded = await withNamedLock(ctx.sandboxRoot, REGISTER_LOCK, async (): Promise<LedgerResult> => {
    let premiseReg: ReadonlyMap<string, PM.Premise> | undefined;
    // The question's words as the register holds them now: the answer format it asks for is read from them (answer-format.ts).
    let questionWords: string | null = null;
    if (question) {
      const reg = await registerRevision(ctx.sandboxRoot, sec.id).catch(() => null);
      questionWords = reg?.text ?? null;
      if (reg) {
        if (questionRev !== undefined && questionRev !== reg.rev) D.add(`${reg.id} (${sec.section}) is at revision ${reg.rev}, amended since the revision ${questionRev} this answers: read it again (questions show ${reg.id}) and answer revision ${reg.rev}, with question_rev: ${reg.rev}`);
        if (questionRev === undefined && reg.rev > 1) D.add(`${reg.id} (${sec.section}) was amended to revision ${reg.rev}: say which revision this answers (question_rev: ${reg.rev}, after reading it with questions show ${reg.id}); an answer to an earlier revision is stale`);
      }
      // The premises it cites, held still under the same lock (a revision, an admission or a withdrawal takes it too).
      if (citations.length) {
        const Q = await import("./questions.ts");
        premiseReg = (await Q.questionsSnapshot(ctx.sandboxRoot)).state.premises;
        const bad = citationRefusal(citations, premiseReg, reg?.id ?? `question:${sec.id}`);
        if (bad) D.add(bad);
      }
    }
    return withTableLockRendered(ctx.sandboxRoot, async (held) => {
      const entries = await readLedger(ctx.sandboxRoot);
      const disputes = await readDisputes(ctx.sandboxRoot);
      const bySeq = new Map(entries.map((e) => [e.seq, e]));
      const replaced = supersededBy(entries);
      const hashOf = (e: LedgerEntry) => e.hash ?? ledgerHash(e, "genesis");
      const standing = entries.find((e) => e.kind === "answer" && e.section === sec.section && !replaced.has(e.seq));
      // The section is answered and this names no entry to correct: when the standing answer is this seat's own, it is the revision of it (57 refusals in eight runs said only "record this with supersedes=<n>").
      if (supersedes === undefined && standing && !given(input.supersedes) && (standing.by === ctx.agentId || standing.authors.includes(ctx.agentId))) {
        supersedes = standing.seq;
        D.took(`${sec.section} is answered by your #${standing.seq} already: taken as its revision (supersedes=${standing.seq})`);
      }
      // An answer of this section that was corrected already: the revision is of the one that stands, the only one a revision can name.
      if (supersedes !== undefined && standing && replaced.has(supersedes) && bySeq.get(supersedes)?.kind === "answer" && bySeq.get(supersedes)?.section === sec.section) {
        D.took(`#${supersedes} is already superseded: taken as the revision of #${standing.seq}, the answer that stands for ${sec.section} (supersedes=${standing.seq})`);
        supersedes = standing.seq;
      }
      if (supersedes !== undefined) {
        const target = bySeq.get(supersedes);
        const already = replaced.get(supersedes);
        const now = standing ? ` (the answer that stands for ${sec.section} is #${standing.seq}: supersedes=${standing.seq})` : "";
        if (!target) D.add(`supersedes #${supersedes}: there is no entry #${supersedes} in the ledger (list them with ledger)${now}`);
        else if (target.kind !== "answer") D.add(`#${supersedes} is a ${target.kind}: an answer corrects an answer; correct the ${target.kind} with a ${target.kind}${now}`);
        else if (target.section !== sec.section) D.add(`#${supersedes} answers ${target.section}: an answer corrects the answer to its own section${now}`);
        else if (already !== undefined) D.add(`#${supersedes} is already superseded by #${already}: correct #${already} instead, so the corrections stay one line${now}`);
        if (!target || target.kind !== "answer" || target.section !== sec.section || already !== undefined) supersedes = undefined;
      }
      // From a positive result to a negative one: a downgrade, which names what undermines the earlier chain.
      const earlier = supersedes !== undefined ? (bySeq.get(supersedes) as LedgerEntry) : undefined;
      const earlierResult = earlier ? NB.answerResult(earlier) : null;
      const downgrading = Boolean(earlier) && (earlierResult === "established" || earlierResult === "partial") && (resultText === "not_determinable" || resultText === "bounded_negative");
      if (downgrading && !downgrade && !given(input.downgrade)) {
        D.add(`#${supersedes} answered ${sec.section} ${NB.resultWords(earlierResult)}; recording it ${NB.resultWords(resultText)} is a downgrade, and a downgrade names what undermines the earlier chain: downgrade {evidence: [E-<seq> of an entry that bears against it: a finding that contradicts it, a correction of what it rests on, …], why}. A doubt with no counter-evidence is not one: dispute #${supersedes} (why, refs), and if the doubt stands attest it best_candidate or record it again with confidence medium; the answer stays. A part the evidence cannot settle makes an answer partial, never not determinable while the findings it rests on stand`);
      }
      if (downgrade && !downgrading) D.add(`downgrade is for a revision that moves an answer from established or partial to not_determinable or bounded_negative${earlier ? `; #${supersedes} is ${NB.resultWords(earlierResult)} and this is ${NB.resultWords(resultText)}` : "; give supersedes"}`);
      for (const r of downgrade?.evidence ?? []) {
        if (!/^E-\d+$/.test(r)) continue;
        const n = Number(r.slice(2));
        if (!bySeq.has(n)) D.add(`downgrade.evidence names ${r}: there is no entry #${n} in the ledger`);
        else if (n === supersedes) D.add(`downgrade.evidence names ${r}, the answer being downgraded: name what undermines it`);
        else if (replaced.has(n)) D.add(`downgrade.evidence names ${r}, superseded by #${standingSeq(n, replaced)}: name the entry that stands`);
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
        if (why.length) D.add(why.join(". "));
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
          if (!a) {
            D.add(`${x.q} (${x.section}) has no standing answer yet: a ${sec.section} cites an answer that stands`);
            continue;
          }
          if (fallen.has(a.seq)) D.add(`${x.q}'s answer E-${a.seq} no longer stands on its own support (${(fallen.get(a.seq) as string[]).join("; ")}): it is to be recorded again first`);
          questionRefs.push({ q: x.q, section: x.section, answer: a.seq, fp: answerFingerprint(a) });
        }
      }
      for (const n of new Set([...support, ...contrary.seqs, ...limits.seqs])) {
        if (!bySeq.has(n)) D.add(`E-${n}: there is no entry #${n} in the ledger (list them with ledger)`);
        else if (n === supersedes) D.add(`E-${n} is the answer this one replaces: an answer does not rest on the answer it corrects`);
      }
      // What is not in the ledger is named above and weighed no further: the checks below read the entries that are.
      for (const list of [support, contrary.seqs, limits.seqs]) for (let i = list.length - 1; i >= 0; i--) if (!bySeq.has(list[i]!)) list.splice(i, 1);
      // An open part is bounded by a limitation (it joins the answer's limitations) or a coverage record, each standing.
      for (const p of parts) {
        if (!p.open_by?.startsWith("E-")) continue;
        const n = Number(p.open_by.slice(2));
        const b = bySeq.get(n);
        if (!b) continue;
        if (b.kind !== "limitation" && b.kind !== "coverage") D.add(`parts: "${p.id}" is open by ${p.open_by}, a ${b.kind}: an open part is bounded by a limitation (why it could not be established) or a coverage record (what was searched for it) E-<seq>, an acquisition ask R-<n>, or a route L-<n>; a ${b.kind} that bears on it goes in its refs`);
        if (replaced.has(n)) D.add(`parts: "${p.id}" is open by ${p.open_by}, superseded by #${standingSeq(n, replaced)}: name the one that stands`);
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
        const b = bySeq.get(n);
        if (!b) continue;
        const qid = question ? sec.id : null;
        const forQuestion = (b.answers ?? []).some((x) => qid !== null && sectionKey(x) === qid);
        if (replaced.has(n)) D.add(`parts: "${p.id}" is limited by ${p.limited_by}, superseded by #${standingSeq(n, replaced)}: name the one that stands`);
        if (b.kind === "coverage" && !forQuestion) D.add(`parts: "${p.id}" is limited by ${p.limited_by}, a coverage record not recorded for ${sec.section}: a limited part rests on the coverage record for its question (answers=["${qid}"]: what was searched for it, over which objects, what was covered and skipped)`);
        if (b.kind === "limitation" && b.reason !== "unavailable" && b.reason !== "excluded") D.add(`parts: "${p.id}" is limited by ${p.limited_by}, a limitation whose reason is ${b.reason ?? "not given"}: a part the evidence in scope cannot settle rests on a limitation whose reason is unavailable (the evidence that would settle it was not collected, or no longer exists) or excluded (the case leaves it out). One that was not examined, failed or is partial could still be settled: hold the part open (open_by ${p.limited_by})`);
        if (b.kind !== "coverage" && b.kind !== "limitation") D.add(`parts: "${p.id}" is limited by ${p.limited_by}, a ${b.kind}: a limited part rests on the coverage record for the question (what was searched for it) or a limitation whose reason is unavailable or excluded; a ${b.kind} that bears on it goes in its refs`);
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
        D.add(`premises: ${c.id} is supported: name in its refs the standing finding or event that shows it (E-<seq>, not disputed, not superseded)${c.refs?.length ? `; ${c.refs.join(", ")} ${c.refs.length === 1 ? "is not one" : "are not"}` : ""}. Without one, cite it assumed (a given is not proved again), or unresolved`);
      }
      for (const n of limits.seqs) {
        const l = bySeq.get(n) as LedgerEntry;
        if (l.kind !== "limitation") D.add(`limitations names #${n}, a ${l.kind}: it takes limitation entries (leave #${n} out of limitations: an entry cited as E-${n} in reasoning supports the answer as the ${l.kind} it is)`);
        else if (replaced.has(n)) D.add(`limitations names #${n}, superseded by #${standingSeq(n, replaced)}: name the limitation that stands`);
      }
      // Every claimed support is checked, not one matching citation.
      const disputedBy = new Map<string, DisputeInForce[]>();
      for (const d of disputesInForce(entries, disputes)) disputedBy.set(d.target, [...(disputedBy.get(d.target) ?? []), d]);
      const problems = answerProblems(entries, disputes);
      const needs = new Set<number>();
      // Superseded cites carried to the entry that stands (below), applied once the loop is over.
      const carried: Array<[number, number]> = [];
      // Each cited entry that needs a why and has none: named together, with the qualifies to send.
      const unqualified: Array<{ n: number; why: string; limitation: boolean }> = [];
      for (const n of support) {
        const e = bySeq.get(n) as LedgerEntry;
        if (replaced.has(n)) {
          const now = standingSeq(n, replaced);
          if (cited.includes(now)) continue;
          // Corrected without a change of conclusion (its refs or evidence refreshed, sameConclusion all the way): the answer rests on the entry that stands, and is told. A correction that concludes otherwise is for the author to read.
          if (sameConclusionChain(n, bySeq, replaced)) {
            carried.push([n, now]);
            D.took(`E-${n} was corrected by #${now}, which concludes the same: the answer rests on E-${now}, the entry that stands`);
          } else D.add(`E-${n} is superseded by #${now}: cite E-${now}, the correction, with it or instead (a superseded entry explains history; it supports nothing); E-${now} concludes something else than E-${n} did, so read it first`);
          continue;
        }
        if (e.kind === "answer" && problems.has(n)) D.add(`E-${n} is an answer that no longer stands on its own support (${(problems.get(n) as string[]).join("; ")}): it is to be recorded again first`);
        const against = disputedBy.get(hashOf(e));
        const failed = failedJobIsDefect("support") ? await unqualifiedFailedRefs(ctx.sandboxRoot, e) : [];
        if (against?.length || failed.length) {
          if (!quals.some((q) => q.seq === n)) {
            unqualified.push({
              n,
              limitation: e.kind === "limitation",
              why: against?.length
                ? `E-${n} is disputed by ${against.map((d) => `${d.by}: ${d.why}${d.inherited_from !== undefined ? ` (raised on E-${d.inherited_from}, which it corrects: the dispute is open until ${d.by} withdraws it)` : ""}`).join("; ")}; cite its correction, drop it, or say in qualifies [{ref: "E-${n}", why}] why it still supports this answer`
                : `E-${n} rests on the kept output of a job that did not succeed (${failed.join(", ")}) and does not say why it still holds: say so in qualifies [{ref: "E-${n}", why}], or cite an entry resting on a job that worked`,
            });
          }
          needs.add(n);
        }
      }
      for (const [from, to] of carried) {
        const i = support.indexOf(from);
        if (i >= 0) support.splice(i, 1, ...(support.includes(to) ? [] : [to]));
      }
      if (unqualified.length === 1) D.add(`${unqualified[0]!.why}${unqualified[0]!.limitation ? `; or, since E-${unqualified[0]!.n} is a limitation, name it in limitations: [${unqualified[0]!.n}] (what bounds the answer, not what it stands on)` : ""}`);
      else if (unqualified.length) {
        const lims = unqualified.filter((u) => u.limitation).map((u) => u.n);
        D.add(`${unqualified.map((u) => u.why.replace(/; cite its correction, drop it, or say in qualifies .*$|: say so in qualifies .*$/, "")).join("; ")}. Each needs its why: add qualifies: [${unqualified.map((u) => `{ref: "E-${u.n}", why: "<why it still supports this answer>"}`).join(", ")}], or cite its correction or an entry resting on a job that worked${lims.length ? `; a limitation among them (${lims.map((n) => `E-${n}`).join(", ")}) may be named in limitations instead` : ""}`);
      }
      // A qualifies on a cited entry that needs none says nothing false: left out and said. One on an entry the answer does not cite is named, with the entries that do need one.
      for (let i = quals.length - 1; i >= 0; i--) {
        const q = quals[i]!;
        if (needs.has(q.seq)) continue;
        if (support.includes(q.seq)) D.took(`qualifies on E-${q.seq} is left out: it is neither disputed nor resting on a failed job`);
        else D.add(`qualifies names E-${q.seq}, which the answer does not cite as support: it qualifies only a cited entry that needs it${needs.size ? ` (${[...needs].map((n) => `E-${n}`).join(", ")})` : " (none of the entries it cites does: leave qualifies out)"}`);
        quals.splice(i, 1);
      }
      // What the answer stands on: an entry that names its question, or for a
      // summary or a narrative any entry that stands.
      const standingCites = [...support, ...limits.seqs].filter((n) => !replaced.has(n)).map((n) => bySeq.get(n) as LedgerEntry);
      if (question) {
        const id = sectionAnswersId(sec.section);
        const naming = (kinds: string[]) => standingCites.filter((e) => kinds.includes(e.kind) && (e.answers ?? []).some((a) => sectionKey(a) === id));
        // The entries on the ledger that do name the question, standing and uncited: what the refusal can point at.
        const forIt = (kinds: string[]) => entries.filter((e) => kinds.includes(e.kind) && !replaced.has(e.seq) && (e.answers ?? []).some((a) => sectionKey(a) === id) && !standingCites.includes(e)).map((e) => `E-${e.seq}`);
        const hint = (kinds: string[]) => {
          const there = forIt(kinds);
          return there.length ? `; the ledger holds ${there.slice(0, 8).join(", ")}${there.length > 8 ? ", …" : ""} recorded for it: cite ${there.length === 1 ? "it" : "the ones this answer rests on"} in reasoning` : `; none is on the ledger yet: record it first (record_finding with answers: ["${id}"]), then this answer citing it`;
        };
        if (!naming(["finding", "absence", "limitation", "coverage"]).length) {
          D.add(`an answer to ${sec.section} rests on at least one standing finding, search, limitation or coverage record recorded with answers=["${id}"] and cited as E-<seq>${standingCites.length ? ` (none of ${standingCites.map((e) => `E-${e.seq}`).join(", ")} names it)` : " (the answer cites no standing entry)"}${hint(["finding", "absence", "limitation", "coverage"])}`);
        } else if ((resultText === "established" || resultText === "partial") && !naming(["finding"]).length) {
          // The result says what the answer rests on: findings for what is established, a coverage record for a material negative.
          D.add(`a result ${resultText} rests on a standing finding recorded with answers=["${id}"] and cited as E-<seq>; if nothing was found, the result is bounded_negative or not_determinable, resting on a coverage record${hint(["finding"])}`);
        } else if (resultText === "premise_not_supported" && !naming(["finding"]).length) {
          // A premise is shown not to hold by what was found, never by a search that found nothing.
          D.add(`premise_not_supported rests on a standing finding recorded with answers=["${id}"] that shows the premise does not hold, cited as E-<seq>; a search that found nothing is a bounded_negative (or not_determinable), resting on a coverage record and reviewed by another seat`);
        }
        const coverage = naming(["coverage"]);
        if (negative && bar?.material && !coverage.length) {
          D.add(`a ${NB.resultWords(resultText)} on a material question rests on a coverage record: record kind=coverage with answers=["${id}"] (the proposition searched, the objects in refs, time_range, search_method, settings, coverage_actual, skipped, failures, result_refs, alternatives and detection_opportunity), and cite it as E-<seq>${forIt(["coverage"]).length ? `; the ledger holds ${forIt(["coverage"]).join(", ")} for it` : ""}`);
        }
        if (input.asserts_absence === true) {
          const complete = coverage.filter((c) => c.coverage === "complete" && c.detection_opportunity?.trace_expected === "yes" && !coverageProblems(c, entries, disputes).length);
          if (!bar?.existence) D.add(`asserts_absence says the event did not happen: only an answer to a question that asks whether something exists may say that (the goal's --existence, or the register's expects existence); ${sec.section} does not. Say "No evidence of … was found in …"`);
          else if (!complete.length) D.add(`asserts_absence says the event did not happen: it rests on a coverage record the hub found complete and that says the event would have left a trace (detection_opportunity.trace_expected yes); ${coverage.length ? coverage.map((c) => `E-${c.seq} is coverage ${c.coverage ?? "unknown"}, trace expected ${c.detection_opportunity?.trace_expected ?? "?"}`).join("; ") : "it cites no coverage record"}. Say "No evidence of … was found in …" instead`);
        }
      } else if (!standingCites.length && !questionRefs.length) {
        D.add(`a ${sec.section} cites at least one standing entry as E-<seq>, or the questions it sums up as Q-<n>`);
      }
      // The candidates (carryCandidates): each check a row names, held to the ledger; then what a revision
      // carries from the answer it corrects, so that only a check removes one.
      for (const why of await candidateCheckDefects(ctx.sandboxRoot, candidatesIn, bySeq, replaced)) D.add(why);
      if (decoyCheck) {
        const w = await machineCheckWhy(ctx.sandboxRoot, decoyCheck.by, bySeq, replaced);
        if (w) D.add(`decoy_check.by is not a machine check: ${w}`);
      }
      let candidates: CandidateRow[] = candidatesIn;
      let carriedRows: CandidateRow[] = [];
      if (question && earlier) {
        const onEarlier = disputesInForce(entries, disputes).filter((d) => d.target === hashOf(earlier));
        const lowered = (CONFIDENCE_RANK[confidence] ?? 0) < (CONFIDENCE_RANK[earlier.confidence ?? ""] ?? 0) || (earlierResult === "established" && resultText !== "established");
        const changedBy = answerCitations(valueChanged.value).filter((n) => n !== supersedes && bySeq.has(n));
        const check = changedBy.find((n) => !entryCheckWhy(n, bySeq, replaced));
        const c = carryCandidates(earlier, candidatesIn, { value, readings: readingsOn(earlier, onEarlier), kept: lowered || onEarlier.length > 0 || changedBy.length > 0, ...(check !== undefined ? { check: `E-${check}` } : {}) });
        candidates = c.rows;
        carriedRows = c.carried;
      }
      // A review changes how sure an answer is, never what it says (reviewValueRule), and "nothing remains open" is held to the carriers the record names (carriersOpen) and to its own candidates.
      const questionFormatWords = question ? questionWords : null;
      if (question && earlier) for (const why of reviewValueRule(earlier, { value, qualifier: [qualifier.value, ...candidates.map((r) => r.value)].join("\n"), confidence, result: resultText, changed: valueChanged.value }, questionFormatWords, bySeq, supersedes as number)) D.add(why);
      if (question && valueChanged.value && !earlier) D.add("value_changed_because says why a revision changes the asked string: it comes with supersedes");
      if (question) for (const why of carriersOpen(openAlt.value, standingCites, { names: carrierNames, result: resultText })) D.add(why);
      const openRows = candidates.filter((r) => r.state === "open" && candidateKey(r.value) !== candidateKey(firstLine(value)));
      // Where value is the asked string (established, partial): a negative's value is not one, and its candidates are said in the report.
      if (question && openRows.length && (resultText === "established" || resultText === "partial") && NONE_OPEN.test(openAlt.value)) {
        D.add(`alternatives_open says nothing remains open, and this answer holds ${openRows.length === 1 ? "a candidate" : `${openRows.length} candidates`} no check has ruled out (${openRows.slice(0, 6).map((r) => JSON.stringify(r.value.slice(0, 80))).join(", ")}${openRows.length > 6 ? ", …" : ""}): rule ${openRows.length === 1 ? "it" : "each"} out with the check that excludes it (candidates [{value, state: "ruled_out", by: job:<id>/<path> or E-<seq>, why}]), or say in alternatives_open that ${openRows.length === 1 ? "it is" : "they are"} open`);
      }
      // A decoy is a candidate, never on its own the answer (decoyRule).
      if (question) {
        const qid = sectionAnswersId(sec.section);
        const forIt = standingCites.filter((e) => e.kind === "finding" && (e.answers ?? []).some((a) => sectionKey(a) === qid));
        for (const why of decoyRule({ value, result: resultText, rows: candidates, findings: forIt, cited: standingCites, checked: Boolean(decoyCheck) })) D.add(why);
      }
      // Every defect of the entry, the ones its fields show and the ones the registers and the ledger show, in the one refusal.
      {
        const refused = D.refusal("answer");
        if (refused) return refused;
      }
      const edge = (n: number): LedgerEdge => ({ seq: n, hash: hashOf(bySeq.get(n) as LedgerEntry) });
      const citedEntries = [...support, ...contrary.seqs, ...limits.seqs, ...questionRefs.map((r) => r.answer)].map((n) => bySeq.get(n) as LedgerEntry);
      const tokens = unsupportedTokens(`${value}\n${qualifier.value}\n${reasoning.value}`, citedEntries, bySeq);
      const candidate: LedgerEntry & AnswerExtras = {
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
        ...(qualifier.value ? { qualifier: qualifier.value } : {}),
        ...(valueChanged.value && supersedes !== undefined ? { value_changed_because: valueChanged.value } : {}),
        ...(candidates.length ? { candidates } : {}),
        ...(carrierNames.length ? { carrier_names: carrierNames } : {}),
        ...(decoyCheck ? { decoy_check: decoyCheck } : {}),
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
      // The whole of what it says: the hashed content, and the qualifier beside the value (protocol-core's content does not hold it yet).
      const contentOf = (e: LedgerEntry & AnswerExtras) => `${ledgerContent(e)}\n${e.qualifier ?? ""}`;
      const content = contentOf(candidate);
      if (supersedes !== undefined && contentOf(bySeq.get(supersedes) as LedgerEntry) === content) {
        // The same words again from the seat whose answer stands, with no entry named: the answer that stands, as it always was.
        if (!given(input.supersedes) && standing?.seq === supersedes) {
          D.taken.splice(0, D.taken.length, ...D.taken.filter((t) => !t.includes("taken as its revision")));
          return mergeSameContent(ctx, held, standing);
        }
        return sameAsStanding(ctx, held, bySeq.get(supersedes) as LedgerEntry, entries.length);
      }
      if (supersedes === undefined && standing && contentOf(standing) === content) return mergeSameContent(ctx, held, standing);
      if (standing && supersedes !== standing.seq) {
        return { ok: false, reason: `${sec.section} is answered by #${standing.seq} already: one answer stands for a section; to revise it, record this with supersedes=${standing.seq}` };
      }
      const notes: string[] = [];
      if (carriedRows.length) notes.push(`candidates carried from #${supersedes}: ${candidatesWords(carriedRows)}. A revision keeps every candidate the answer it corrects held, and every reading a dispute of it gives; only a check removes one (candidates [{value, state: "ruled_out", by: job:<id>/<path> or E-<seq>, why}])`);
      if (bound.length) notes.push(`${bound.map((b) => `E-${b.seq} (the answer to ${b.section}${b.standing !== null && b.standing !== b.seq ? `, now E-${b.standing}` : ""})`).join(", ")} ${bound.length === 1 ? "is" : "are"} cited as ${[...new Set(bound.map((b) => b.section))].join(", ")}: a ${sec.section} is bound to the questions it sums up, to each answer's conclusion (its result, the revision it answers, its support and contrary evidence), not to its seq, so a reworded correction of an answer keeps it standing. Cite Q-<n> or question:<n> for an answer in a ${sec.section}`);
      // The format the question asks for (a "Format:" line), read against value's first line: said, never refused.
      // No asked string exists on an answer that found nothing or cannot say (a negative, not determinable, out of
      // scope, a premise that does not hold), so none is asked for; an answer with a part open is asked only for the
      // pieces it has; and a first line an earlier answer to the question already had is not told again (12 notes in
      // three runs, 8 of them on an answer that could not satisfy them: the open half of question 7, a negative question 11).
      if (question && questionWords && (resultText === "established" || resultText === "partial")) {
        const open = resultText === "partial" && parts.some((p) => p.status === "open" || p.status === "limited");
        const miss = formatMiss(questionWords, value, { open });
        const first = firstLine(value);
        if (miss && !entries.some((e) => e.kind === "answer" && e.section === sec.section && firstLine(e.value) === first)) notes.push(formatNote(sec.section, miss));
      }
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
  code: "no_answer" | "answer_support" | "answer_disputed" | "no_critic_act" | "open_contradiction" | "coverage_missing" | "negative_unreviewed" | "wording" | "coverage_stale" | "material_use" | "partial_output" | "evidence_stale" | "completeness_uncovered" | "sweep_pending" | "sweep_hits" | "sweep_partial" | "preparation_pending" | "premise_inconsistent" | "negative_images_unread" | "carriers_incomplete";
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
export type SweepHold = {
  code: "sweep_pending" | "sweep_hits" | "sweep_partial";
  coverage: LedgerEntry;
  sweep: SweepRecord | null;
  unexamined?: UnexaminedHit[];
  /** The sweep's hits that hold: those not examined in place (examinedInPlace). Absent when every hit holds as the sweep found it. */
  hits?: SweepHit[];
  /** The sweep's hits examined in place, each with the entry that examined it. */
  examined?: Array<{ ref: string; term: string; by: number }>;
};

/**
 * A sweep hit examined in place, without the coverage record being written
 * again (the run sf4406b's finish loop: each revision of a record to name
 * what its sweep found was swept anew, and the revision's own outputs were
 * found in turn): a standing finding, event, absence or limitation for one of
 * the record's questions, written at or after the sweep, whose refs name the
 * hit object (any name of its bytes), and which a seat other than its authors
 * attested, says what the object showed. The entry that examined it, or null.
 * With no attestations given, none is: the hit holds until the record names
 * it with what it showed, as before.
 */
export function examinedInPlace(hit: SweepHit, cov: LedgerEntry, sw: SweepRecord, entries: readonly LedgerEntry[], replaced: ReadonlyMap<number, number>, attests: readonly LedgerAttestation[] | undefined, disputes: readonly LedgerDispute[]): LedgerEntry | null {
  if (!attests?.length) return null;
  const questions = new Set((cov.answers ?? []).map((x) => sectionKey(x)));
  const names = new Set([hit.ref, ...(hit.also ?? [])].map((n) => n.replace(/^(job:[^/]+)\/out\//, "$1/").replace(/\/+$/, "")));
  const inForce = disputesInForce(entries as LedgerEntry[], disputes as LedgerDispute[]);
  for (const e of entries) {
    if (!INTERPRETING_KINDS.has(e.kind) || replaced.has(e.seq) || Date.parse(e.at) < Date.parse(sw.at)) continue;
    if (!(e.answers ?? []).some((x) => questions.has(sectionKey(x)))) continue;
    if (!(e.refs ?? []).some((r) => names.has(r.replace(/^(job:[^/]+)\/out\//, "$1/").replace(/\/+$/, "")))) continue;
    const h = e.hash ?? ledgerHash(e, "genesis");
    if (inForce.some((d) => d.target === h)) continue;
    if (attests.some((x) => attestationAct(x) === "attest" && x.target === h && !e.authors.includes(x.by))) return e;
  }
  return null;
}

export function sweepHolds(answer: LedgerEntry, entries: LedgerEntry[], sweeps: readonly SweepRecord[], disputes: LedgerDispute[] = [], material = true, attests?: readonly LedgerAttestation[]): SweepHold[] {
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
    // A hit another seat attested an entry examining in place no longer holds (examinedInPlace); the rest do.
    const examined: NonNullable<SweepHold["examined"]> = [];
    const holding = (sw?.hits ?? []).filter((h) => {
      const by = sw ? examinedInPlace(h, c, sw, entries, replaced, attests, disputes) : null;
      if (by) examined.push({ ref: h.ref, term: h.term, by: by.seq });
      return !by;
    });
    if (holding.length || unexamined.length) out.push({ code: "sweep_hits", coverage: c, sweep: sw, ...(unexamined.length ? { unexamined } : {}), ...(examined.length ? { hits: holding, examined } : {}) });
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
export type LedgerWarning = { code: "no_acquisition_ask" | "partial_all_parts_established" | "lead_findings_uncited" | "preparation_missing" | "late_evidence_hits" | "premise_disputed" | "premise_revised" | "premise_withdrawn" | "premise_inconsistent" | "part_omitted" | "no_locator_or_derivation" | "premise_untested" | "premise_unreviewed"; section: string; seqs: number[]; what: string; fix: string };

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
    // An answer that chose among carriers (carrier_names) is settled only on a carrier table with a row for each of them,
    // read where the tables it cites stand now (carriersOpen; the record held it so when it was written).
    if (a.carrier_names?.length && (NB.answerResult(a) === "established" || NONE_OPEN.test(a.alternatives_open ?? ""))) {
      const tables = (a.support ?? []).map((x) => bySeq.get(standingSeq(x.seq, replaced))).filter((e): e is LedgerEntry => e?.kind === "finding" && Boolean(e.carriers?.length));
      const missing = carriersWithoutRow(a.carrier_names, tables);
      if (missing.length) {
        defects.push({
          code: "carriers_incomplete",
          section: sec.section,
          seqs: [a.seq, ...tables.map((t) => t.seq)],
          what: `answer #${a.seq} (${sec.section}) names ${a.carrier_names.length} carriers and is ${NB.answerResult(a) === "established" ? "established" : "said to leave nothing open"}, while ${tables.length ? `the carrier tables it rests on (${tables.map((t) => `E-${t.seq}`).join(", ")}) have` : "it rests on no carrier table, so it has"} no row for ${missing.length} of them (${missing.slice(0, 8).join(", ")}${missing.length > 8 ? ", …" : ""})`,
          fix: `record the carrier table again with a row for each of the ${a.carrier_names.length} carriers (a finding with carriers [{carrier, state, why}]), then the answer with supersedes=${a.seq} citing it; or record the answer partial, saying in alternatives_open which carriers are open`,
          named_by: namedFor(a.seq),
        });
      }
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
          what: `answer #${a.seq} (${sec.section}) is ${NB.resultWords(result)}: new evidence since its coverage (${st.additions.map((x) => `${x.import}, E-${x.seq}${x.inventory_rev !== null ? `, inventory revision ${x.inventory_rev}` : ""}`).join("; ")}); re-examine against it${st.coverage.length ? `. Its coverage record${st.coverage.length === 1 ? "" : "s"} ${list(st.coverage)} ${st.coverage.length === 1 ? "was" : "were"} recorded before the addition's entry E-${first.seq}` : ""}${st.unnamed.length ? `; ${list(st.unnamed)}, recorded after it, ${st.unnamed.length === 1 ? "does" : "do"} not name ${importWords} among its objects` : ""}${st.unreviewed.length ? `; ${list(st.unreviewed)} ${st.unreviewed.length === 1 ? "examines" : "examine"} it and no other seat has reviewed ${st.unreviewed.length === 1 ? "it" : "them"} yet` : ""}${st.nodelta.length ? `; it was examined and reviewed, and nothing it cites says how the new evidence bears on the answer (a delta)` : ""}${st.undelta.length ? `; ${list(st.undelta)} ${st.undelta.length === 1 ? "interprets" : "interpret"} it with no delta` : ""}${st.unexamined.length ? `; ${list(st.unexamined)} ${st.unexamined.length === 1 ? "carries a delta" : "carry deltas"} that no other seat reviewed: ${st.unexamined.length === 1 ? "it is" : "they are"} not among the results of a reviewed coverage record naming the import, nor attested` : ""}${hitsHere.length ? `. The reverse sweep found what this question's coverage looked for in it: ${boundedHits(hitsHere, importHitWords, (hitsHere[0] as { sweep?: { hits_all?: { file?: { path?: string } } } }).sweep?.hits_all?.file?.path ?? "ledger/sweeps.jsonl")}` : ""}`,
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
          what: `answer #${a.seq} (${sec.section}) does not reach what the reverse sweep of evidence added late found for ${q}: ${boundedHits(left, (x) => `import:${x.sweep.import} (E-${x.sweep.seq}): ${importHitWords(x)}`, (left[0] as { sweep?: { hits_all?: { file?: { path?: string } } } } | undefined)?.sweep?.hits_all?.file?.path ?? "ledger/sweeps.jsonl")}`,
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
      for (const hold of sweepHolds(a, entries, o.sweeps, o.disputes, bar.material, o.attestations)) {
        const c = hold.coverage;
        const sw = hold.sweep;
        if (hold.code === "sweep_pending") {
          defects.push({ code: "sweep_pending", section: sec.section, seqs: [a.seq, c.seq], what: `answer #${a.seq} (${sec.section}) rests on coverage record E-${c.seq}, whose store sweep for ${c.looked_for!.map((t) => `"${t}"`).join(", ")} has not finished (pending)`, fix: "wait for the sweep: the hub runs it when the record is written and records it in ledger/sweeps.jsonl (the finish line runs one lost with its process); then examine what it found", named_by: [] });
        } else if (hold.code === "sweep_hits") {
          // The first of them named, the rest counted: a gate item is read by a seat, and ledger/sweeps.jsonl holds each.
          const holding = hold.hits ?? sw?.hits ?? [];
          const words = holding.slice(0, SWEEP_GATE_HITS).map((h) => `"${h.term}" in ${h.ref}${h.also?.length ? ` (also ${h.also.slice(0, 8).join(", ")}${h.also.length > 8 ? ` and ${h.also.length - 8} more` : ""})` : ""} (${h.count} time${h.count === 1 ? "" : "s"}, first at byte ${h.first_offset}${h.encodings.includes("utf-16le") ? `, ${h.encodings.join(" and ")}` : ""})`);
          if (holding.length > SWEEP_GATE_HITS) words.push(`and ${holding.length - SWEEP_GATE_HITS} more (${(sw as { hits_all?: { file?: { path?: string } } } | undefined)?.hits_all?.file?.path ?? "ledger/sweeps.jsonl"} holds each)`);
          const unexamined = hold.unexamined ?? [];
          const named = unexamined.slice(0, SWEEP_GATE_HITS).map((u) => `${u.ref}${u.also.length ? ` (also ${u.also.slice(0, 8).join(", ")}${u.also.length > 8 ? ` and ${u.also.length - 8} more` : ""})` : ""} (${u.terms.slice(0, 8).map((t) => `"${t}"`).join(", ")}${u.terms.length > 8 ? ` and ${u.terms.length - 8} more` : ""}, found by the sweep of E-${u.found_by})`);
          if (unexamined.length > SWEEP_GATE_HITS) named.push(`and ${unexamined.length - SWEEP_GATE_HITS} more`);
          const said = [
            ...(words.length ? [`the store sweep for coverage record E-${c.seq} found what it looked for in objects the record does not name: ${words.join("; ")}`] : []),
            ...(named.length ? [`coverage record E-${c.seq} names ${unexamined.length === 1 ? "an object" : `${unexamined.length} objects`} an earlier sweep found hits in with no entry among its results that says what ${unexamined.length === 1 ? "it" : "each"} showed: ${named.join("; ")}. Naming a hit is not examining it`] : []),
          ];
          defects.push({
            code: "sweep_hits",
            section: sec.section,
            seqs: [a.seq, c.seq],
            what: `answer #${a.seq} (${sec.section}) is ${NB.resultWords(result)}, and ${said.join("; and ")}`,
            fix: `examine each object the sweep names and record what it showed: one entry per object (a finding, an event or a limitation whose refs name the object itself), or one absence whose refs list several (a search that found nothing that bears on the question in them), written after the sweep and naming the question in answers. Another seat's attest on that entry clears the hit where it stands, and the coverage record is not written again; without one, record the coverage again with supersedes=${c.seq} naming each object (in refs, which hold 20, or in result_refs, which hold 200 and where an object named counts the same: put them there rather than drop one named before), with what it showed: those entries in result_refs (and coverage_actual), and leave the answer as it is when its value and the coverage stay the same (it stands on the revised record); record it again with supersedes=${a.seq} only when what those objects show changes it`,
            named_by: [],
          });
        } else {
          defects.push({
            code: "sweep_partial",
            section: sec.section,
            seqs: [a.seq, c.seq],
            what: `answer #${a.seq} (${sec.section}) rests on coverage record E-${c.seq}, whose store sweep is partial: ${sw!.searched.objects} object(s) searched, not searched: ${SWS.unsearchedWords(sw!)}`,
            fix: SWS.unsearchedLeft(sw!)
              ? `wait: the hub goes on with what a pass's budget left in the next pass, by itself, until the sweep is clean or names hits (ledger/sweeps.jsonl); what no pass can search stays named, and then the coverage is recorded again with supersedes=${c.seq} under a larger budget (SWARM_SWEEP_MAX_BYTES, SWARM_SWEEP_MAX_SEC), or the operator accepts the question's limits`
              : `a partial sweep is not a clean one: record the coverage again with supersedes=${c.seq} (its sweep runs again; SWARM_SWEEP_MAX_BYTES and SWARM_SWEEP_MAX_SEC set its budget), or the operator accepts the question's limits`,
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
  // A negative about pictures with sheets of its job unread (negativeBasis): an answer that reaches it is held until they are read and it is recorded again.
  for (const [section, a] of Object.entries(answers)) {
    if (!a) continue;
    for (const n of answerReach(a, bySeq, replaced)) {
      const e = bySeq.get(n) as (LedgerEntry & NegativeFields) | undefined;
      if (!e?.images_unread?.length || replaced.has(n)) continue;
      const names = e.images_unread.map((u) => `${u.unread.length} of the ${u.total} images of job:${u.job}${u.dir ? `/${u.dir}` : ""} (${u.unread.slice(0, 8).map((f) => f.slice(f.lastIndexOf("/") + 1)).join(", ")}${u.unread.length > 8 ? ", …" : ""})`).join("; ");
      defects.push({
        code: "negative_images_unread",
        section,
        seqs: [a.seq, n],
        what: `answer #${a.seq} (${section}) rests on E-${n}, a negative about pictures recorded with ${names} never handed to its recorder: it holds for the pictures read, not for the job's`,
        fix: `${e.by} (or another seat) reads the unread images and records E-${n} again with supersedes=${n} (the hub then finds none unread), and the answer is recorded again citing it; or the answer is revised to what the pictures read show`,
        named_by: namedFor(n),
      });
    }
  }
  // A finding at high confidence that later entries stand on and nobody reviewed (premisesUnreviewed): said, never held.
  // Only for the sections this gate was asked about: the premise names one of them, or its answer reaches it (a reply to one question's record does not carry every other question's).
  for (const p of premisesUnreviewed(entries, o.attestations, o.disputes)) {
    const section = Object.entries(answers).find(([, a]) => a && answerReach(a, bySeq, replaced).has(p.entry.seq))?.[0] ?? (p.entry.answers ?? []).map((x) => `question:${sectionKey(x)}`).find((x) => x in answers);
    if (!section) continue;
    warnings.push({
      code: "premise_unreviewed",
      section,
      seqs: [p.entry.seq, ...p.citers],
      what: `E-${p.entry.seq} (a finding at high confidence, recorded by ${p.entry.by}, reviewed by nobody) is what ${p.citers.map((n) => `E-${n}`).join(", ")} rest on`,
      fix: `a seat other than ${p.entry.by} re-derives E-${p.entry.seq} from its refs and attests it, or disputes it with what it found: a premise several entries stand on is checked before more is built on it`,
    });
  }
  return { answers, defects, open: defects.filter((d) => !d.named_by.length), unsupported, warnings };
}
