/**
 * The lead register: the swarm's open investigative work, kept by the harness.
 *
 * A lead is a piece of material work somebody found: a container to open, a
 * key to find, a note to read to its end. Before this register a lead lived
 * only in prose: a post addressed to the peer the writer guessed owned the
 * next step, a `name(doing)` nobody checked, a job whose output nobody
 * interpreted. On the Belka run s94e373 a recovery key sat in a job's unread
 * page for 51 minutes while three agents searched for it; on c10 s6895a8 a
 * late recovery avenue was being interpreted when the run ended and no record
 * said it was open; on c09 the pointer to the third part's key was found in
 * every run and followed in none, and the finish line took "a limitation is
 * recorded" for an answer. The register makes that work durable, owned,
 * visible and part of the finish line, and nothing more: agents open, claim,
 * link and close leads themselves; the harness assigns nothing and never
 * judges what a lead is worth (the creator says whether it is material).
 *
 * Hub-owned state. `leads/leads.jsonl` is an append-only chain of events (each
 * line hashed over the one before, as the ledger's are); `leads/leads.md` is
 * derived from it after every write. On the host every pane writes it under
 * one named lock; in a microVM run the hub is its only writer (board.ts), and
 * the operator's CLI writes it on the host under the same lock. It sits
 * beside the ledger, not in it: a lead is work, not a finding, and custody
 * seals it and the package carries it, unsigned.
 *
 * What is derived, never stored: whether a lead is blocked (a need not met),
 * its priority (how many leads and unanswered questions wait on it, then its
 * age), whether its holder is stale, which questions nobody covers, which jobs
 * wait for an interpretation, and what each agent has not yet been told.
 * Everything derived is computed from the files on every read, so a hub that
 * restarts between a transition and its notice loses neither.
 *
 * Nothing here knows a tool or a case: a need names a lead's disposition or a
 * ledger entry, never a program, and a job's exit status never satisfies one.
 */

import { existsSync, readFileSync } from "node:fs";
import { appendFile, mkdir, open, readdir, readFile, realpath, rename, stat, writeFile } from "node:fs/promises";
import { dirname, join, resolve } from "node:path";
import * as NB from "./negative-bar.ts";
import * as O from "./offers.ts";
import * as PR from "./preparation.ts";
import * as P from "./protocol.ts";
import * as SW from "./store-sweep.ts";

// --- the files --------------------------------------------------------------------------------

export const LEADS_DIR = "leads";
export const LEADS_LOG = "leads/leads.jsonl";
export const LEADS_MD = "leads/leads.md";
/**
 * Every request made of the operator (a lead closed needs_operator, an
 * acquisition, a clarification, a network item, a stop proposed), one JSON
 * line each as it stands: rendered from requests/requests.jsonl, the outbox's
 * chain (extensions/requests.ts).
 */
export const OPERATOR_REQUESTS = "operator-requests.jsonl";
/** Hosts the operator allowed while the run went on, for jobs run with network=allowlist. */
export const OPERATOR_HOSTS = "operator-hosts.jsonl";
/**
 * The one lock both registers are written under: the leads and the questions
 * (extensions/questions.ts). A withdrawn question closes its leads in the
 * same act, and a done's sentinel is written under it too (protocol.ts
 * markDone), so an admission and a terminal done are never interleaved.
 */
export const REGISTER_LOCK = P.REGISTER_LOCK;
const LOCK = REGISTER_LOCK;

// --- the vocabulary ---------------------------------------------------------------------------

/**
 * How a lead ends, and what each must cite. resolved: the standing entry that
 * settles it (E-<seq>). negative: the search that found nothing (an absence,
 * E-<seq>). duplicate: the lead it repeats (L-<n>). deferred: the limitation
 * that says why it waits (E-<seq>). infeasible: the limitation naming the
 * methods tried and why none worked (E-<seq>). needs_operator: what only the
 * operator can do (allow a host, add a file, answer a question), in words.
 * withdrawn: the harness's alone, when every question the lead served was
 * withdrawn (extensions/questions.ts), or when the broad extraction a
 * preparation lead offered reached an outcome by any route
 * (closePreparationLead); it cites the question, or the receipt.
 */
export const LEAD_DISPOSITIONS = ["resolved", "negative", "duplicate", "deferred", "infeasible", "needs_operator", "withdrawn"] as const;
export type LeadDisposition = (typeof LEAD_DISPOSITIONS)[number];
/** The dispositions that leave the question behind them open: an examination-limited outcome, never an answered one. */
export const LIMITING_DISPOSITIONS: ReadonlySet<LeadDisposition> = new Set(["deferred", "infeasible", "needs_operator"]);
export const LEAD_ID = /^L-([1-9]\d{0,5})$/;
export const LEAD_TITLE_MAX = 200;
export const LEAD_WHY_MAX = 2000;
export const LEAD_REF_MAX = 2000;
export const LEAD_NOTE_MAX = 4000;
export const LEAD_MAX_NEEDS = 20;
export const LEAD_MAX_ANSWERS = 8;
export const LEAD_MAX_OPENS = 10;
/** Whole seconds from the environment, in milliseconds, or the default when unset or not a number. */
function envMs(name: string, dfltSec: number): number {
  const raw = process.env[name]?.trim();
  const n = raw && /^\d+$/.test(raw) ? Number(raw) : dfltSec;
  return n * 1000;
}
/** A holder silent this long, with no job running and no compaction under way, shows as stale (SWARM_LEAD_STALE_SEC, 600). */
export function leadStaleMs(): number {
  return envMs("SWARM_LEAD_STALE_SEC", 600);
}
/** How long a stale mark stands before the lead may be reclaimed: the holder is told first (SWARM_LEAD_RECLAIM_GRACE_SEC, 60). */
export function reclaimGraceMs(): number {
  return envMs("SWARM_LEAD_RECLAIM_GRACE_SEC", 60);
}
/** A compaction this long keeps its seat's leases; past it, the seat may have lost its turn for good. */
export const LEAD_COMPACTION_BOUND_MS = 20 * 60_000;
/** An idle seat is one that has waited at least this long, holding no active lead and no job. */
export const IDLE_SEAT_MS = 60_000;

export type LeadEventKind =
  | "open"
  | "claim"
  | "release"
  | "close"
  | "link"
  | "reopen"
  | "stale"
  | "job"
  | "interpret"
  | "wake"
  | "note"
  | "route"
  | "route_review"
  // Offers (extensions/offers.ts): made, delivered, declined, lapsed; accepted by the claim or confirm that names it.
  | "offer"
  | "offer_seen"
  | "offer_decline"
  | "offer_lapse"
  // A review's offer taken up by the review it offered (an attest of a negative is on the ledger, not here).
  | "offer_accept"
  // A review's offer its seat took (offer accept): held for the review until `until`.
  | "offer_take"
  // A review's offer the register withdrew: what it offered needs no review any more (reviewed by another route, superseded).
  | "offer_withdraw"
  // The holder keeps a parked lead; a hand-off to another seat; a closure confirmed on the entry that stands now.
  | "keep"
  | "handoff"
  | "confirm";

export type LeadEvent = {
  v: 1;
  seq: number;
  at: string;
  /** An agent's id, "system" for the harness, "operator" for the examiner. */
  by: string;
  ev: LeadEventKind;
  lead?: string;
  title?: string;
  why?: string;
  origin?: string;
  needs?: string[];
  answers?: string[];
  material?: boolean;
  holder?: string;
  generation?: number;
  /** A claim that took the lead from a stale holder: whom from. */
  from?: string;
  disposition?: LeadDisposition;
  ref?: string;
  /**
   * A close needs_operator that asks for evidence the run does not have: the
   * acquisition (extensions/requests.ts), committed on the close itself, so
   * the operator request it makes is derived from this line and written once
   * (the transactional outbox, docs/adr/0014).
   */
  ask?: import("./requests.ts").AcquisitionAsk;
  add?: string[];
  remove?: string[];
  /** A reopen's cause: superseded, disputed, operator, agent, evidence_added. */
  cause?: string;
  /** A reopen for evidence added after the kickoff: the import it came as, so the reopen is made once. */
  import?: string;
  job?: string;
  /** An interpretation: the ledger entry that is it, that entry's kind, and its hash (the interpretation is bound to that entry, never to its seq alone). */
  entry?: number;
  kind?: string;
  entry_hash?: string;
  /** An interpretation: how the rest of a job's output was read, or why it was not. */
  rest?: string;
  /** A wake: the seat woken, and which open spell of the lead it was for. */
  to?: string;
  cycle?: number;
  text?: string;
  allow_host?: string;
  last_activity?: string | null;
  idle_seconds?: number;
  /**
   * An open under an analyst's question (extensions/questions.ts): the
   * proposition the lead tests and its negation, so the question is worked as
   * a hypothesis, never as a conclusion to confirm.
   */
  proposition?: string;
  negation?: string;
  /** A directive (the operator's lead under a question): what it is to produce, and what makes that product acceptable. */
  product?: string;
  acceptance?: string;
  /**
   * An open or a route event: the route plan, the sources to examine and how,
   * listed before the search so that a source nobody examined stays visible
   * (the negative bar, extensions/negative-bar.ts).
   */
  routes?: NB.Route[];
  /** A close negative: the planned routes of its questions nothing examined, each with why (hub-computed). */
  not_examined?: Array<{ source: string; method: string; why: string }>;
  /** A close negative: held this long or less, one job, one object (a review cue, hub-computed). */
  quick_negative?: { held_ms: number; jobs: number; objects: number };
  /**
   * A route review (B3): another seat's word on a lead closed deferred,
   * infeasible or needs_operator, whether the route's limitation is still
   * material now that its questions are disposed; bound to the close it
   * reviews (its open spell and its ref).
   */
  material_now?: boolean;
  /** A reopen by an agent: the lead's revision the reopener read (lead_reopen's expected_revision). */
  expected_revision?: number;
  /** An offer: why it was made, the lead's revision it binds, its age bound; the offer an act answers (a claim, a confirm, a decline, a lapse). */
  reason?: string;
  rev?: number;
  max_until?: string;
  offer?: number;
  /** A confirm offer: the standing head of the superseded closing entry. */
  head?: string;
  /** A review's offer taken (offer_take): the seat holds it for the review until then. */
  until?: string;
  /**
   * An open or a claim that overlaps a held lead's questions and is held all
   * the same: why (a second route, an independent verification), in
   * `why`-like words. Otherwise the open is unheld and names the holder.
   */
  overlap?: string;
  overlap_why?: string;
  /** An open that overlapped held leads' questions and was left unheld: the leads it overlapped. */
  covered_by?: string[];
  /** Coverage hints: the objects the work is over (overlap is not identity; these are never load-bearing). */
  objects?: string[];
  /** The product contract (A2): the immutable refs it starts from, the first act once its product is accepted. */
  inputs?: string[];
  next_action?: string;
  /** A close: the delivered product, by ref (E-<seq> or an object of the run). */
  result_refs?: string[];
  /** An open made as a prerequisite of another lead, linked to it in the same act. */
  consumer?: string;
  /** A route review and its offer: the answers of its questions it was made against (routeBasis). */
  basis?: string;
  /** A second, independent route review: why it adds something to the one that stands. */
  second_review_why?: string;
  /** A confirmation offer: the batch it belongs to (the correction chain's head, E-<seq>): one offer per seat and batch, confirmed at once. */
  batch?: string;
  /**
   * An open by the harness of a source's broad extraction (extensions/preparation.ts):
   * the source by digest and ref, the capability and the recipe a pack
   * declares for it. One lead per source digest and capability.
   */
  preparation?: LeadPreparation;
  prev: string;
  hash: string;
};

/** What a preparation lead offers: a pack's broad extraction (its recipe and capability) over one source, by digest. */
export type LeadPreparation = { sha256: string; ref: string; capability: string; recipe: string };

/** A need dropped from a lead: withdrawn with a reason, never read as met. */
export type DroppedNeed = { need: string; why: string; at: string; by: string };

export type Lead = {
  id: string;
  n: number;
  title: string;
  why: string;
  origin: string;
  needs: string[];
  answers: string[];
  material: boolean;
  opened_by: string;
  opened_at: string;
  holder: string | null;
  generation: number;
  /** When the current holder took it. */
  held_since: string | null;
  closed: { disposition: LeadDisposition; ref: string; by: string; at: string; why?: string; seq?: number } | null;
  reopened: Array<{ at: string; by: string; why: string; cause: string; import?: string }>;
  /** The newest stale mark on the current holder, until the holder acts on the lead or loses it. */
  stale: { at: string; holder: string; generation: number; idle_seconds: number; last_activity: string | null } | null;
  jobs: string[];
  notes: Array<{ at: string; by: string; text: string; allow_host?: string }>;
  /** How many times it went back to open (released or reopened): one wake per open spell. */
  cycle: number;
  last_seq: number;
  proposition?: string;
  negation?: string;
  product?: string;
  acceptance?: string;
  /** The route plan: every route named at open and added since. */
  routes: NB.Route[];
  /** When it closed negative: the planned routes nothing examined, and whether it was a quick negative. */
  not_examined?: Array<{ source: string; method: string; why: string }>;
  quick_negative?: { held_ms: number; jobs: number; objects: number };
  /** Its revision: how many acts changed it (lead_reopen and lead_confirm name the one they read). */
  rev: number;
  /** Route reviews of its limiting closes, in order (B3). */
  route_reviews: Array<{ at: string; by: string; material: boolean; why: string; cycle: number; ref: string; basis?: string; second?: string }>;
  /** Every offer of it, in order (extensions/offers.ts). */
  offers: O.Offer[];
  /** A closure whose entry was superseded, waiting for its closer to confirm it or reopen it (lead_confirm): never re-pointed by itself. */
  confirm: { at: string; offer: number; ref_was: string; head: string | null } | null;
  /** Needs dropped with a reason (withdrawn, never read as met). */
  dropped: DroppedNeed[];
  /** The product contract (A2). */
  inputs?: string[];
  next_action?: string;
  result_refs?: string[];
  objects?: string[];
  overlap?: { kind: string; why: string; by: string };
  covered_by?: string[];
  /** A closure confirmed on the entry that stands after its first was superseded. */
  confirmed?: Array<{ at: string; by: string; from: string; to: string; why: string }>;
  /** A preparation lead (openPreparationLead): the broad extraction it offers. */
  preparation?: LeadPreparation;
};

export type LeadsState = {
  events: LeadEvent[];
  leads: Map<string, Lead>;
  /** The lead each job was run under. */
  jobLead: Map<string, string>;
  /** Each job's interpretations, in order, each bound to its entry's hash when the register recorded one. */
  interpretations: Map<string, Array<{ by: string; at: string; entry: number; kind: string; rest?: string; hash?: string }>>;
  /** Wakes, by lead and open spell. */
  wakes: Map<string, string>;
  /**
   * The reviews' offers, by item: a limiting lead's route review (its id,
   * L-<n>), a material negative's review (E-<seq> of the answer). One seat
   * at a time, as any offer.
   */
  reviewOffers: Map<string, O.Offer[]>;
  chain: { ok: boolean; broken_at: number | null; reason: string | null; head: string | null };
};

/** The reasons of a review's offer. */
export const REVIEW_REASONS: ReadonlySet<string> = new Set(["route_review", "negative_review"]);

// --- the chain ----------------------------------------------------------------------------------

function core(e: Omit<LeadEvent, "prev" | "hash"> | LeadEvent): string {
  const { prev: _p, hash: _h, ...rest } = e as LeadEvent;
  return JSON.stringify(P.canonicalValue(rest));
}

export function leadEventHash(e: Omit<LeadEvent, "hash"> | LeadEvent, prev: string): string {
  return P.sha256Hex(`${prev}\n${core(e)}`);
}

/** Whether leads.jsonl chains from its first line to its last: a rewritten or removed line breaks it. */
export function verifyLeadChain(text: string): { ok: boolean; total: number; broken_at: number | null; reason: string | null; head: string | null } {
  let prev = "genesis";
  let total = 0;
  for (const line of text.split("\n")) {
    if (!line.trim()) continue;
    total += 1;
    let e: LeadEvent;
    try {
      e = JSON.parse(line) as LeadEvent;
    } catch {
      return { ok: false, total, broken_at: total, reason: "the line is not JSON", head: null };
    }
    if (e.seq !== total) return { ok: false, total, broken_at: total, reason: `the line has seq ${e.seq}, not ${total}`, head: null };
    if (e.prev !== prev) return { ok: false, total, broken_at: total, reason: "the line does not chain to the one before", head: null };
    if (e.hash !== leadEventHash(e, prev)) return { ok: false, total, broken_at: total, reason: "the line was rewritten", head: null };
    prev = e.hash;
  }
  return { ok: true, total, broken_at: null, reason: null, head: total ? prev : null };
}

// --- reading ------------------------------------------------------------------------------------

export async function readLeadEvents(sandboxRoot: string): Promise<{ events: LeadEvent[]; text: string }> {
  const text = await readFile(join(sandboxRoot, LEADS_LOG), "utf8").catch(() => "");
  const events: LeadEvent[] = [];
  for (const line of text.split("\n")) {
    if (!line.trim()) continue;
    try {
      events.push(JSON.parse(line) as LeadEvent);
    } catch {
      // The chain check names it.
    }
  }
  return { events, text };
}

/** The events that change a lead (its revision): not a wake, a stale mark, an interpretation or an offer's delivery. */
const REVISING: ReadonlySet<string> = new Set(["open", "claim", "release", "close", "link", "reopen", "route", "job", "note", "route_review", "keep", "confirm", "handoff"]);

/** The register's state, folded from its events in order. */
export function foldLeads(events: LeadEvent[], chain: LeadsState["chain"] = { ok: true, broken_at: null, reason: null, head: events.at(-1)?.hash ?? null }): LeadsState {
  const leads = new Map<string, Lead>();
  const jobLead = new Map<string, string>();
  const interpretations: LeadsState["interpretations"] = new Map();
  const wakes = new Map<string, string>();
  const reviewOffers = new Map<string, O.Offer[]>();
  // Every offer by its seq, whichever register item it offers: its delivery, decline, lapse and acceptance name it so.
  const offerBySeq = new Map<number, O.Offer>();
  for (const e of events) {
    const l = e.lead ? leads.get(e.lead) : undefined;
    switch (e.ev) {
      case "open": {
        if (!e.lead) break;
        leads.set(e.lead, {
          id: e.lead,
          n: Number(LEAD_ID.exec(e.lead)?.[1] ?? 0),
          title: e.title ?? "",
          why: e.why ?? "",
          origin: e.origin ?? "",
          needs: [...(e.needs ?? [])],
          answers: [...(e.answers ?? [])],
          material: e.material !== false,
          opened_by: e.by,
          opened_at: e.at,
          holder: e.holder ?? null,
          generation: e.generation ?? 0,
          held_since: e.holder ? e.at : null,
          closed: null,
          reopened: [],
          stale: null,
          jobs: [],
          notes: [],
          cycle: 0,
          last_seq: e.seq,
          ...(e.proposition ? { proposition: e.proposition } : {}),
          ...(e.negation ? { negation: e.negation } : {}),
          ...(e.product ? { product: e.product } : {}),
          ...(e.acceptance ? { acceptance: e.acceptance } : {}),
          routes: [...(e.routes ?? [])],
          rev: 1,
          route_reviews: [],
          offers: [],
          confirm: null,
          dropped: [],
          ...(e.inputs?.length ? { inputs: [...e.inputs] } : {}),
          ...(e.next_action ? { next_action: e.next_action } : {}),
          ...(e.objects?.length ? { objects: [...e.objects] } : {}),
          ...(e.overlap ? { overlap: { kind: e.overlap, why: e.overlap_why ?? "", by: e.by } } : {}),
          ...(e.covered_by?.length ? { covered_by: [...e.covered_by] } : {}),
          ...(e.preparation ? { preparation: { ...e.preparation } } : {}),
        });
        break;
      }
      case "claim":
        if (!l) break;
        l.holder = e.holder ?? e.by;
        l.generation = e.generation ?? l.generation + 1;
        l.held_since = e.at;
        l.stale = null;
        if (typeof e.offer === "number") {
          const o = l.offers.find((x) => x.seq === e.offer);
          if (o && !o.accepted) o.accepted = { at: e.at };
        }
        if (e.overlap) l.overlap = { kind: e.overlap, why: e.overlap_why ?? "", by: e.by };
        // A directive framed by its first claim: the proposition it tests, from then on.
        if (e.proposition && !l.proposition) {
          l.proposition = e.proposition;
          l.negation = e.negation;
        }
        for (const r of e.routes ?? []) if (!l.routes.some((x) => x.source === r.source && x.method === r.method)) l.routes.push(r);
        l.last_seq = e.seq;
        break;
      case "release":
      case "handoff":
        if (!l) break;
        l.holder = null;
        l.held_since = null;
        l.stale = null;
        l.cycle += 1;
        l.last_seq = e.seq;
        break;
      case "close":
        if (!l || !e.disposition) break;
        l.closed = { disposition: e.disposition, ref: e.ref ?? "", by: e.by, at: e.at, ...(e.why ? { why: e.why } : {}), seq: e.seq };
        l.stale = null;
        l.confirm = null;
        if (e.result_refs?.length) l.result_refs = [...e.result_refs];
        else delete l.result_refs;
        if (e.not_examined?.length) l.not_examined = e.not_examined;
        else delete l.not_examined;
        if (e.quick_negative) l.quick_negative = e.quick_negative;
        else delete l.quick_negative;
        l.last_seq = e.seq;
        break;
      case "route":
        if (!l) break;
        for (const r of e.routes ?? []) if (!l.routes.some((x) => x.source === r.source && x.method === r.method)) l.routes.push(r);
        l.last_seq = e.seq;
        break;
      case "reopen":
        if (!l) break;
        l.closed = null;
        l.confirm = null;
        l.holder = null;
        l.held_since = null;
        l.stale = null;
        l.cycle += 1;
        l.reopened.push({ at: e.at, by: e.by, why: e.why ?? "", cause: e.cause ?? "agent", ...(e.import ? { import: e.import } : {}) });
        delete l.not_examined;
        delete l.quick_negative;
        l.last_seq = e.seq;
        break;
      case "link":
        if (!l) break;
        for (const n of e.remove ?? []) if (l.needs.includes(n)) l.dropped.push({ need: n, why: e.why ?? "", at: e.at, by: e.by });
        l.needs = [...l.needs.filter((n) => !(e.remove ?? []).includes(n)), ...(e.add ?? []).filter((n) => !l.needs.includes(n))];
        l.last_seq = e.seq;
        break;
      case "stale":
        if (!l) break;
        l.stale = { at: e.at, holder: e.holder ?? "", generation: e.generation ?? l.generation, idle_seconds: e.idle_seconds ?? 0, last_activity: e.last_activity ?? null };
        l.last_seq = e.seq;
        break;
      case "job":
        if (!l || !e.job) break;
        if (!l.jobs.includes(e.job)) l.jobs.push(e.job);
        jobLead.set(e.job, l.id);
        l.last_seq = e.seq;
        break;
      case "interpret":
        if (!e.job || typeof e.entry !== "number") break;
        interpretations.set(e.job, [...(interpretations.get(e.job) ?? []), { by: e.by, at: e.at, entry: e.entry, kind: e.kind ?? "", ...(e.rest ? { rest: e.rest } : {}), ...(e.entry_hash ? { hash: e.entry_hash } : {}) }]);
        break;
      case "wake":
        // A wake from before offers: read as an offer of the lead as it stood.
        if (!e.lead || !e.to) break;
        wakes.set(`${e.lead}#${e.cycle ?? 0}`, e.to);
        if (l) {
          const o: O.Offer = { seq: e.seq, at: e.at, to: e.to, rev: l.rev, reason: "wake", seen_at: null, declined: null, accepted: null, lapsed_at: null };
          l.offers.push(o);
          offerBySeq.set(e.seq, o);
        }
        break;
      case "offer": {
        if (!e.to) break;
        const reason = ((O.OFFER_REASONS as readonly string[]).includes(e.reason ?? "") ? e.reason : "wake") as O.OfferReason;
        // A review's offer: of a limiting lead's route review, or of a negative's review (by its answer's seq).
        if (REVIEW_REASONS.has(reason)) {
          const key = reason === "route_review" ? e.lead : typeof e.entry === "number" ? `E-${e.entry}` : undefined;
          if (!key) break;
          const o: O.Offer = { seq: e.seq, at: e.at, to: e.to, rev: e.rev ?? 1, reason, seen_at: null, declined: null, accepted: null, lapsed_at: null, ...(e.basis ? { basis: e.basis } : {}) };
          reviewOffers.set(key, [...(reviewOffers.get(key) ?? []), o]);
          offerBySeq.set(e.seq, o);
          break;
        }
        if (!l) break;
        const lo: O.Offer = { seq: e.seq, at: e.at, to: e.to, rev: e.rev ?? l.rev, reason, seen_at: null, declined: null, accepted: null, lapsed_at: null, ...(e.from ? { from: e.from } : {}), ...(e.batch ? { batch: e.batch } : {}) };
        l.offers.push(lo);
        offerBySeq.set(e.seq, lo);
        wakes.set(`${l.id}#${e.cycle ?? l.cycle}`, e.to);
        if (reason === "confirm" && l.closed) l.confirm = { at: e.at, offer: e.seq, ref_was: e.ref ?? l.closed.ref, head: e.head ?? null };
        break;
      }
      case "offer_seen":
      case "offer_decline":
      case "offer_lapse":
      case "offer_accept":
      case "offer_take":
      case "offer_withdraw": {
        const o = typeof e.offer === "number" ? offerBySeq.get(e.offer) : undefined;
        if (!o) break;
        if ((e.ev === "offer_seen" || e.ev === "offer_take") && !o.seen_at) o.seen_at = e.at;
        if (e.ev === "offer_take" && e.until && !o.held_until) o.held_until = e.until;
        if (e.ev === "offer_withdraw" && !o.withdrawn) o.withdrawn = { at: e.at, why: e.why ?? "" };
        if (e.ev === "offer_decline" && !o.declined) o.declined = { at: e.at, why: e.why ?? "" };
        if (e.ev === "offer_lapse" && !o.lapsed_at) o.lapsed_at = e.at;
        if (e.ev === "offer_accept" && !o.accepted) o.accepted = { at: e.at };
        break;
      }
      case "keep":
        if (!l) break;
        l.stale = null;
        l.last_seq = e.seq;
        break;
      case "confirm": {
        if (!l || !l.closed || !e.ref) break;
        const from = l.closed.ref;
        l.closed = { ...l.closed, ref: e.ref };
        l.confirmed = [...(l.confirmed ?? []), { at: e.at, by: e.by, from, to: e.ref, why: e.why ?? "" }];
        const o = l.offers.find((x) => x.seq === e.offer);
        if (o && !o.accepted) o.accepted = { at: e.at };
        l.confirm = null;
        l.last_seq = e.seq;
        break;
      }
      case "note":
        if (!l) break;
        l.notes.push({ at: e.at, by: e.by, text: e.text ?? "", ...(e.allow_host ? { allow_host: e.allow_host } : {}) });
        l.last_seq = e.seq;
        break;
      case "route_review":
        if (!l || typeof e.material_now !== "boolean") break;
        l.route_reviews.push({ at: e.at, by: e.by, material: e.material_now, why: e.why ?? "", cycle: e.cycle ?? l.cycle, ref: e.ref ?? "", ...(e.basis ? { basis: e.basis } : {}), ...(e.second_review_why ? { second: e.second_review_why } : {}) });
        if (typeof e.offer === "number") {
          const o = offerBySeq.get(e.offer);
          if (o && !o.accepted) o.accepted = { at: e.at };
        }
        l.last_seq = e.seq;
        break;
    }
    // Its revision: every act that changes what the lead is or who has it.
    if (l && e.ev !== "open" && REVISING.has(e.ev)) l.rev += 1;
  }
  return { events, leads, jobLead, interpretations, wakes, reviewOffers, chain };
}

/**
 * The ledger entries the register recorded under each question's leads, by
 * question id (its section key), each with the leads it was recorded under:
 * an entry that interprets a job run under a lead, and one a lead's close or
 * confirmation names (its ref and its result_refs, as E-<seq>), every close
 * in the lead's history included. The register's own acts only: nothing is
 * read of what an entry says. The answers check warns when a question's
 * answer leaves out one that two seats hold (protocol.ts ledgerGate,
 * lead_findings_uncited).
 */
export function questionLeadEntries(s: LeadsState): Map<string, Map<number, string[]>> {
  const byLead = new Map<string, Set<number>>();
  const add = (lead: string, seq: number) => {
    const set = byLead.get(lead) ?? new Set<number>();
    set.add(seq);
    byLead.set(lead, set);
  };
  for (const e of s.events) {
    if ((e.ev !== "close" && e.ev !== "confirm") || !e.lead) continue;
    for (const r of [e.ref ?? "", ...(e.result_refs ?? [])]) {
      const m = /^E-(\d+)$/i.exec(r.trim());
      if (m) add(e.lead, Number(m[1]));
    }
  }
  for (const [job, list] of s.interpretations) {
    const lead = s.jobLead.get(job);
    if (lead) for (const i of list) add(lead, i.entry);
  }
  const out = new Map<string, Map<number, string[]>>();
  for (const l of [...s.leads.values()].sort((x, y) => x.n - y.n)) {
    const seqs = byLead.get(l.id);
    if (!seqs) continue;
    for (const q of new Set(l.answers.map((x) => P.sectionKey(x)))) {
      const m = out.get(q) ?? new Map<number, string[]>();
      for (const seq of seqs) m.set(seq, [...(m.get(seq) ?? []), l.id]);
      out.set(q, m);
    }
  }
  return out;
}

// --- needs --------------------------------------------------------------------------------------

/** A need, as agents write it: L-3 (resolved), L-3:negative, or E-12 (a standing ledger entry). */
export function parseNeed(raw: string): { ok: true; need: string; lead?: string; disposition?: LeadDisposition; entry?: number } | { ok: false; reason: string } {
  const text = String(raw ?? "").trim();
  const e = /^E-([1-9]\d{0,5})$/i.exec(text);
  if (e) return { ok: true, need: `E-${Number(e[1])}`, entry: Number(e[1]) };
  const m = /^(L-[1-9]\d{0,5})(?::([a-z_]+))?$/i.exec(text);
  if (m) {
    const disposition = (m[2] ?? "resolved").toLowerCase() as LeadDisposition;
    if (!(LEAD_DISPOSITIONS as readonly string[]).includes(disposition)) return { ok: false, reason: `a need's disposition is one of ${LEAD_DISPOSITIONS.join(", ")} (got ${JSON.stringify(m[2])})` };
    if (disposition === "duplicate" || disposition === "needs_operator" || disposition === "withdrawn") return { ok: false, reason: `${text}: a lead closed ${disposition} produced nothing a lead can use; need the lead it duplicates, or the answer the operator gives, instead` };
    const lead = `L-${Number(m[1].slice(2))}`;
    return { ok: true, need: `${lead}:${disposition}`, lead, disposition };
  }
  return { ok: false, reason: `a need is a lead with the outcome it must reach (L-3, L-3:negative) or a standing ledger entry (E-12); a job's exit is never one (got ${JSON.stringify(text)})` };
}

/** What the ledger says, as a need reads it. */
export type LedgerView = {
  entries: P.LedgerEntry[];
  bySeq: Map<number, P.LedgerEntry>;
  replaced: Map<number, number>;
  disputed: Set<string>;
  /** The disputes read with it: a negative's review targets are read against them, as the gate reads them. */
  disputes?: P.LedgerDispute[];
  /** The store sweeps read with it (store-sweep.ts): a negative's review offer says what they found. */
  sweeps?: SW.SweepRecord[];
};

export function ledgerView(entries: P.LedgerEntry[], disputes: P.LedgerDispute[]): LedgerView {
  return {
    entries,
    bySeq: new Map(entries.map((e) => [e.seq, e])),
    replaced: P.supersededBy(entries),
    // A correction of a disputed entry is disputed too until the dispute is answered (B18).
    disputed: new Set(P.disputesInForce(entries, disputes).map((d) => d.target)),
    disputes,
  };
}

/** Whether a ledger entry stands: recorded, not corrected since, not disputed. */
export function entryStands(v: LedgerView, seq: number): { ok: true; kind: string } | { ok: false; why: string } {
  const e = v.bySeq.get(seq);
  if (!e) return { ok: false, why: `E-${seq} is not in the ledger` };
  const by = v.replaced.get(seq);
  if (by !== undefined) return { ok: false, why: `E-${seq} was superseded by E-${P.standingSeq(seq, v.replaced)}` };
  if (v.disputed.has(e.hash ?? P.ledgerHash(e, "genesis"))) return { ok: false, why: `E-${seq} is disputed` };
  return { ok: true, kind: e.kind };
}

/** Whether one need is met now, and when it is not, why and whether it still can be. */
export function needState(need: string, s: LeadsState, v: LedgerView): { met: boolean; why?: string; dead?: boolean } {
  const p = parseNeed(need);
  if (!p.ok) return { met: false, why: p.reason, dead: true };
  if (p.entry !== undefined) {
    const st = entryStands(v, p.entry);
    // A superseded entry never stands again; a disputed one does once the dispute is withdrawn.
    return st.ok ? { met: true } : { met: false, why: st.why, dead: v.bySeq.has(p.entry) && v.replaced.has(p.entry) };
  }
  const l = s.leads.get(p.lead!);
  if (!l) return { met: false, why: `${p.lead} does not exist`, dead: true };
  if (!l.closed) return { met: false, why: `${l.id} is ${l.holder ? `held by ${l.holder}` : "open, unheld"}` };
  // A closure whose entry was superseded stands only once its closer confirms it on what stands now.
  if (l.confirm) return { met: false, why: `${l.id} was closed ${l.closed.disposition} on ${l.confirm.ref_was}, since superseded: its closer confirms the closure or reopens it` };
  if (l.closed.disposition === p.disposition) return { met: true };
  return { met: false, why: `${l.id} was closed ${l.closed.disposition}${l.closed.ref ? ` (${l.closed.ref})` : ""}, not ${p.disposition}: revise the need (lead_link)`, dead: true };
}

export type LeadStatus = "open" | "active" | "blocked" | "closed";

/**
 * What a need came to (A2), never read from a removal: satisfied (met now),
 * pending (not yet), failed (the producer ended otherwise, or cannot meet
 * it), invalidated (it was met, and what met it no longer stands: the
 * producer reopened, or its closure waits for confirmation). A need dropped
 * with lead_link is withdrawn, with its reason, in the lead's `dropped`.
 */
export type NeedOutcome = "satisfied" | "pending" | "failed" | "invalidated";

export function needOutcome(need: string, s: LeadsState, v: LedgerView): NeedOutcome {
  const st = needState(need, s, v);
  if (st.met) return "satisfied";
  if (st.dead) return "failed";
  const p = parseNeed(need);
  if (p.ok && p.lead) {
    const l = s.leads.get(p.lead);
    const metOnce = s.events.some((e) => e.lead === p.lead && e.ev === "close" && e.disposition === p.disposition);
    if (l && metOnce && (!l.closed || l.confirm)) return "invalidated";
  }
  return "pending";
}

export function leadStatus(l: Lead, s: LeadsState, v: LedgerView): LeadStatus {
  if (l.closed) return "closed";
  if (l.needs.some((n) => !needState(n, s, v).met)) return "blocked";
  return l.holder ? "active" : "open";
}

/** The leads that need `id`, directly or through one another, still open or held. */
export function dependentsOf(id: string, s: LeadsState): string[] {
  const out = new Set<string>();
  const queue = [id];
  while (queue.length) {
    const cur = queue.shift()!;
    for (const l of s.leads.values()) {
      if (l.closed || out.has(l.id) || l.id === id) continue;
      if (l.needs.some((n) => n.split(":")[0] === cur)) {
        out.add(l.id);
        queue.push(l.id);
      }
    }
  }
  return [...out];
}

/** Whether adding `need` to lead `id` would close a loop of needs. */
export function wouldCycle(id: string, need: string, s: LeadsState): boolean {
  const target = need.split(":")[0];
  if (!LEAD_ID.test(target)) return false;
  if (target === id) return true;
  // The target needs id, directly or through others: a loop.
  const seen = new Set<string>();
  const queue = [target];
  while (queue.length) {
    const cur = queue.shift()!;
    if (cur === id) return true;
    if (seen.has(cur)) continue;
    seen.add(cur);
    for (const n of s.leads.get(cur)?.needs ?? []) {
      const t = n.split(":")[0];
      if (LEAD_ID.test(t)) queue.push(t);
    }
  }
  return false;
}

// --- the goal's questions ----------------------------------------------------------------------

export type GoalQuestions = { questions: string[]; existence: string[]; source: string | null };

/** Split a shell line into words: enough for a goal's check line (quotes, no expansion). */
export function shellWords(line: string): string[] {
  const out: string[] = [];
  let cur = "";
  let quote: string | null = null;
  let any = false;
  for (const ch of line) {
    if (quote) {
      if (ch === quote) quote = null;
      else cur += ch;
      continue;
    }
    if (ch === "'" || ch === '"') {
      quote = ch;
      any = true;
      continue;
    }
    if (/\s/.test(ch)) {
      if (cur || any) out.push(cur);
      cur = "";
      any = false;
      continue;
    }
    cur += ch;
  }
  if (cur || any) out.push(cur);
  return out;
}

/** The goal document the operator gave, from the registry; the contract when the registry has none. */
export async function goalDocument(sandboxRoot: string, runsDir = process.env.SWARM_RUNS_DIR || dirname(resolve(sandboxRoot))): Promise<{ text: string; source: "registry" | "sandbox contract" } | null> {
  try {
    const reg = JSON.parse(await readFile(join(runsDir, "registry.json"), "utf8")) as { runs?: Array<{ sandbox?: string; goal?: string }> };
    const real = await realpath(sandboxRoot).catch(() => resolve(sandboxRoot));
    for (const run of [...(reg.runs ?? [])].reverse()) {
      if (!run.sandbox) continue;
      const rec = await realpath(run.sandbox).catch(() => resolve(run.sandbox!));
      if (rec === real && run.goal) return { text: run.goal, source: "registry" };
    }
  } catch {
    // No registry: the contract below.
  }
  const text = await readFile(join(sandboxRoot, "SWARM.md"), "utf8").catch(() => null);
  return text ? { text, source: "sandbox contract" } : null;
}

/** The goal's checks: code spans on bullet lines under every `## Checks` heading (await-done.sh's rule). */
export function goalChecks(text: string): string[] {
  const out: string[] = [];
  const sections = [...text.matchAll(/^##[ \t]*Checks[ \t]*$([\s\S]*?)(?=^#{1,6}[ \t]|(?![\s\S]))/gm)].map((m) => m[1]);
  for (const body of sections) {
    for (const line of body.split("\n")) {
      if (!/^\s*[-*]/.test(line)) continue;
      for (const m of line.matchAll(/`+([^`]+)`+/g)) if (m[1].trim()) out.push(m[1].trim());
    }
  }
  return out;
}

/**
 * The goal's questions, as its answers check names them (--sections, and a
 * brief's numbered questions with --sections-in), and those it says ask
 * whether something exists (--existence). The check line is the goal's own:
 * nothing here reads a question's words.
 */
export async function goalQuestions(sandboxRoot: string): Promise<GoalQuestions> {
  const doc = await goalDocument(sandboxRoot);
  if (!doc) return { questions: [], existence: [], source: null };
  // The briefs the checks number questions in, read first (the run's own files).
  const briefs = new Map<string, string>();
  for (const path of goalBriefPaths(doc.text)) briefs.set(path, await readFile(join(sandboxRoot, path), "utf8").catch(() => ""));
  const { questions, existence } = goalQuestionsIn(doc.text, (path) => briefs.get(path) ?? "");
  return { questions, existence, source: doc.source };
}

/** The briefs a goal's answers check numbers its questions in (--sections-in), as the check names them. */
export function goalBriefPaths(text: string): string[] {
  const out: string[] = [];
  for (const check of goalChecks(text)) {
    if (!check.includes("check-answers.ts")) continue;
    const words = shellWords(check);
    const i = words.indexOf("--sections-in");
    if (i >= 0 && words[i + 1] && !out.includes(words[i + 1])) out.push(words[i + 1]);
  }
  return out;
}

/**
 * The goal's questions from its text (goalQuestions' reading, with no run):
 * a brief is read through `readBrief`, and one it cannot read (null) is
 * named in `unread`, its questions unknown.
 */
export function goalQuestionsIn(text: string, readBrief: (path: string) => string | null): { questions: string[]; existence: string[]; unread: string[] } {
  const questions: string[] = [];
  const existence: string[] = [];
  const unread: string[] = [];
  for (const check of goalChecks(text)) {
    if (!check.includes("check-answers.ts")) continue;
    const words = shellWords(check);
    const opt = (name: string) => {
      const i = words.indexOf(name);
      return i >= 0 ? words[i + 1] : undefined;
    };
    const briefPath = opt("--sections-in");
    if (briefPath) {
      const brief = readBrief(briefPath);
      if (brief === null) unread.push(briefPath);
      for (const q of P.briefQuestions(brief ?? "")) if (!questions.includes(q)) questions.push(q);
    }
    for (const raw of (opt("--sections") ?? "").split(",")) {
      const sec = P.answerSection(raw.trim());
      if (!sec.ok || !sec.section.startsWith("question:")) continue;
      if (!questions.includes(sec.id)) questions.push(sec.id);
    }
    for (const raw of (opt("--existence") ?? "").split(",")) {
      const id = P.sectionKey(raw.trim());
      if (id && !existence.includes(id)) existence.push(id);
    }
  }
  return { questions, existence, unread };
}

// --- jobs ---------------------------------------------------------------------------------------

export type JobFacts = { id: string; agent: string; kind: string; state: string; status?: string; command?: string; tool?: string; finished_at?: string };

const terminalJobs = new Map<string, JobFacts>();

/** The run's jobs, from their projected records in store/jobs/ (a terminal one is read once). */
export async function readJobs(sandboxRoot: string): Promise<JobFacts[]> {
  const dir = join(sandboxRoot, "store", "jobs");
  const names = await readdir(dir).catch(() => [] as string[]);
  const out: JobFacts[] = [];
  for (const id of names.sort()) {
    if (!/^j\d{6,}$/.test(id)) continue;
    const key = `${resolve(sandboxRoot)}\u0000${id}`;
    const known = terminalJobs.get(key);
    if (known) {
      out.push(known);
      continue;
    }
    const raw = await readFile(join(dir, id, "job.json"), "utf8").catch(() => null);
    if (!raw) continue;
    try {
      const j = JSON.parse(raw) as { id?: string; state?: string; status?: string; requester?: { agent?: string }; spec?: { kind?: string; command?: string; tool?: string }; finished_at?: string };
      const facts: JobFacts = {
        id,
        agent: j.requester?.agent ?? "",
        kind: j.spec?.kind ?? "",
        state: j.state ?? "",
        ...(j.status ? { status: j.status } : {}),
        ...(j.spec?.command ? { command: j.spec.command } : {}),
        ...(j.spec?.tool ? { tool: j.spec.tool } : {}),
        ...(j.finished_at ? { finished_at: j.finished_at } : {}),
      };
      if (facts.state === "committed" || facts.state === "failed" || facts.state === "cancelled") terminalJobs.set(key, facts);
      out.push(facts);
    } catch {
      // Not a record: skipped.
    }
  }
  return out;
}

/** Whether a job's output is the agent's to interpret: a command or a tool it asked for, that ran and was committed. */
export function needsInterpretation(j: JobFacts): boolean {
  return (j.kind === "command" || j.kind === "tool") && j.state === "committed" && j.status !== "cancelled";
}

/** Whether a job is still to finish: queued, running, or between its end and its commit. */
export function jobOpen(j: JobFacts): boolean {
  return ["accepted", "running", "finished", "fenced"].includes(j.state);
}

type Reads = { offset: number; returned: Map<string, Map<string, Array<[number, number]>>> };
const readsCache = new Map<string, Reads>();

/**
 * Which bytes of each job's stdout each agent was handed (the store journal's
 * job_returned lines), read incrementally.
 */
export async function stdoutReads(sandboxRoot: string): Promise<Map<string, Map<string, Array<[number, number]>>>> {
  const path = join(sandboxRoot, "store", "journal.jsonl");
  const key = resolve(sandboxRoot);
  let c = readsCache.get(key);
  const size = await stat(path).then((s) => s.size).catch(() => 0);
  if (!c || size < c.offset) {
    c = { offset: 0, returned: new Map() };
    readsCache.set(key, c);
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
            if (!line.includes('"job_returned"')) continue;
            try {
              const l = JSON.parse(line) as { type?: string; job?: string; to?: string; stdout_offset?: number; stdout_bytes?: number };
              if (l.type !== "job_returned" || !l.job || !l.to) continue;
              const byAgent = c.returned.get(l.job) ?? new Map<string, Array<[number, number]>>();
              const spans = byAgent.get(l.to) ?? [];
              spans.push([Number(l.stdout_offset ?? 0), Number(l.stdout_offset ?? 0) + Number(l.stdout_bytes ?? 0)]);
              byAgent.set(l.to, spans);
              c.returned.set(l.job, byAgent);
            } catch {
              // A torn line: the journal's own check names it.
            }
          }
          c.offset += Buffer.byteLength(text.slice(0, end + 1));
        }
      } finally {
        await fh.close();
      }
    }
  }
  return c.returned;
}

/** How many bytes of a job's stdout an agent was not handed, of `total`. */
export function unreadBytes(spans: Array<[number, number]> | undefined, total: number): number {
  if (!spans?.length) return total;
  const sorted = [...spans].sort((a, b) => a[0] - b[0]);
  let covered = 0;
  let at = 0;
  for (const [a, b] of sorted) {
    const lo = Math.max(a, at);
    const hi = Math.min(b, total);
    if (hi > lo) covered += hi - lo;
    at = Math.max(at, b);
  }
  return Math.max(0, total - covered);
}

export type AwaitingJob = { job: string; agent: string; lead: string | null; why: string; unread_bytes?: number; total_bytes?: number; next_offset?: number; reinterpret?: true };

/**
 * The jobs whose output waits for an interpretation: a command or tool job,
 * committed, that no interpretation names; or one whose stdout its requester
 * was handed only in part, until the rest is read or the interpretation says
 * how it was read or why not. A bare ledger citation does not count: an
 * interpretation is an entry recorded with `interprets` naming the job.
 */
export async function awaitingInterpretation(sandboxRoot: string, s: LeadsState, jobs?: JobFacts[], ledger?: LedgerView): Promise<AwaitingJob[]> {
  const all = jobs ?? (await readJobs(sandboxRoot));
  const reads = await stdoutReads(sandboxRoot);
  const out: AwaitingJob[] = [];
  for (const j of all) {
    if (!needsInterpretation(j) || !j.agent || j.agent === "system" || j.agent === "derived") continue;
    const lead = s.jobLead.get(j.id) ?? null;
    const recorded = s.interpretations.get(j.id) ?? [];
    // An interpretation is bound to its entry (B13): it holds while that
    // entry stands, as the entry it was recorded on. A correction carries it
    // only when the correction interprets the job again; a superseded or
    // disputed interpretation needs re-interpretation.
    const valid = ledger ? recorded.filter((i) => interpretationStands(i, ledger).ok) : recorded;
    if (recorded.length && !valid.length && ledger) {
      const why = recorded.map((i) => { const st = interpretationStands(i, ledger); return `E-${i.entry}: ${st.ok ? "stands" : st.why}`; }).join("; ");
      out.push({ job: j.id, agent: j.agent, lead, why: `its interpretation no longer stands (${why}): record what its output shows again, with interprets naming it (a correction that still holds says so by interpreting it too)`, reinterpret: true });
      continue;
    }
    const interps = valid;
    const spans = reads.get(j.id)?.get(j.agent);
    let unread: { unread: number; total: number; next: number } | null = null;
    if (spans?.length) {
      const total = await stat(join(sandboxRoot, "store", "jobs", j.id, "stdout.log")).then((st) => st.size).catch(() => 0);
      const left = unreadBytes(spans, total);
      if (left > 0) {
        const next = Math.max(...spans.map(([, b]) => b));
        unread = { unread: left, total, next: Math.min(next, total) };
      }
    }
    const restSaid = interps.some((i) => i.rest);
    if (!interps.length) {
      out.push({ job: j.id, agent: j.agent, lead, why: unread ? `no interpretation yet, and ${unread.unread} of ${unread.total} stdout bytes unread` : "no interpretation yet", ...(unread ? { unread_bytes: unread.unread, total_bytes: unread.total, next_offset: unread.next } : {}) });
    } else if (unread && !restSaid) {
      out.push({ job: j.id, agent: j.agent, lead, why: `interpreted, but ${unread.unread} of ${unread.total} stdout bytes unread: read them, or record why not (interprets with rest)`, unread_bytes: unread.unread, total_bytes: unread.total, next_offset: unread.next });
    }
  }
  return out;
}

/** Whether one interpretation of a job stands: its entry stands (not superseded, not disputed) and is the entry it was recorded on. */
export function interpretationStands(i: { entry: number; hash?: string }, v: LedgerView): { ok: true } | { ok: false; why: string } {
  const e = v.bySeq.get(i.entry);
  if (!e) return { ok: false, why: `E-${i.entry} is not in the ledger` };
  if (i.hash && (e.hash ?? P.ledgerHash(e, "genesis")) !== i.hash) return { ok: false, why: `E-${i.entry} is not the entry it was recorded on (another hash)` };
  const st = entryStands(v, i.entry);
  if (!st.ok) return { ok: false, why: `${st.why}, which does not interpret it` };
  return { ok: true };
}

// --- liveness -----------------------------------------------------------------------------------

/** Rows a seat's harness writes without the seat doing anything, and its waiting: none of it works a lead. */
const NOT_WORK = new Set([
  "hub_prompt", "context", "thinking", "tool_loaded", "agent_start", "inputs_guard", "budget_precall_stop", "pause_hold",
  "self_compact", "compact_config", "compact_notice", "compact_warning", "compact_forced", "compact_hold",
  "compact_note", "compact_start", "compact_done", "compact_failed", "compact_stalled", "wait", "inbox", "agent_error",
]);

/**
 * Each agent's last working row on the trace within `windowMs`, and whether a
 * compaction is under way (started, not ended). Read from the end of the
 * trace backwards, a chunk at a time, only as far as the window reaches.
 */
export async function recentActivity(sandboxRoot: string, windowMs: number, now = Date.now()): Promise<Map<string, { last: number; compacting: number | null }>> {
  const out = new Map<string, { last: number; compacting: number | null }>();
  const path = join(sandboxRoot, P.EVENTS_REL);
  const size = await stat(path).then((s) => s.size).catch(() => 0);
  if (!size) return out;
  const fh = await open(path, "r").catch(() => null);
  if (!fh) return out;
  const cutoff = now - windowMs;
  const compactEnded = new Set<string>();
  try {
    let pos = size;
    let carry = "";
    const CHUNK = 256 * 1024;
    let done = false;
    while (pos > 0 && !done) {
      const len = Math.min(CHUNK, pos);
      pos -= len;
      const buf = Buffer.alloc(len);
      await fh.read(buf, 0, len, pos);
      const text = buf.toString("utf8") + carry;
      const lines = text.split("\n");
      carry = pos > 0 ? (lines.shift() ?? "") : "";
      for (let i = lines.length - 1; i >= 0; i--) {
        const line = lines[i];
        if (!line.trim()) continue;
        let e: { agent?: string; tool?: string; ts?: string; recv_ts?: string; args?: { stage?: string } };
        try {
          e = JSON.parse(line);
        } catch {
          continue;
        }
        const at = Date.parse(e.recv_ts || e.ts || "");
        if (!Number.isFinite(at)) continue;
        if (at < cutoff) {
          done = true;
          break;
        }
        const agent = e.agent ?? "";
        if (!agent || agent === "system") continue;
        const row = out.get(agent) ?? { last: 0, compacting: null };
        if (e.tool === "compact_done" || (e.tool === "compact_failed" && (e.args?.stage === "compaction" || e.args?.stage === "pi"))) compactEnded.add(agent);
        if (e.tool === "compact_start" && !compactEnded.has(agent) && row.compacting === null) row.compacting = at;
        if (e.tool && !NOT_WORK.has(e.tool)) row.last = Math.max(row.last, at);
        out.set(agent, row);
      }
    }
  } finally {
    await fh.close();
  }
  return out;
}

export type HolderLiveness = { stale: boolean; why: string; last_activity: string | null; idle_seconds: number };

/**
 * Whether a lead's holder has gone quiet: marked done or dead, or silent past
 * LEAD_STALE_MS with no job of its own still to finish and no compaction
 * under way within its bound. A turn that ended in an error is not quiet by
 * itself: the holder keeps the lead until it is also silent that long.
 */
export async function holderLiveness(sandboxRoot: string, holder: string, jobs: JobFacts[], activity?: Map<string, { last: number; compacting: number | null }>, now = Date.now(), floor = 0): Promise<HolderLiveness> {
  for (const m of ["done", "dead"] as const) {
    if (existsSync(join(sandboxRoot, "done", "agents", `${holder}.${m}`))) return { stale: true, why: `${holder} is ${m === "done" ? "done" : "marked dead"}`, last_activity: null, idle_seconds: 0 };
  }
  const act = activity ?? (await recentActivity(sandboxRoot, Math.max(leadStaleMs(), LEAD_COMPACTION_BOUND_MS), now));
  const row = act.get(holder);
  // The holder's own last act on the register counts too: a claim a moment
  // ago is work, whether or not its trace line has reached the host yet.
  const last = Math.max(row?.last ?? 0, floor);
  const idle = last ? Math.round((now - last) / 1000) : Math.round(leadStaleMs() / 1000);
  const lastIso = last ? new Date(last).toISOString() : null;
  if (jobs.some((j) => j.agent === holder && jobOpen(j))) return { stale: false, why: `${holder} has a job still running`, last_activity: lastIso, idle_seconds: idle };
  if (row?.compacting && now - row.compacting < LEAD_COMPACTION_BOUND_MS) return { stale: false, why: `${holder} is compacting its context`, last_activity: lastIso, idle_seconds: idle };
  if (last && now - last < leadStaleMs()) return { stale: false, why: `${holder} worked ${idle} s ago`, last_activity: lastIso, idle_seconds: idle };
  return { stale: true, why: last ? `${holder} has done nothing for ${Math.round(idle / 60)} min, with no job running and no compaction under way` : `${holder} has done nothing in the last ${Math.round(leadStaleMs() / 60_000)} min`, last_activity: lastIso, idle_seconds: idle };
}

// --- idle seats ---------------------------------------------------------------------------------

/**
 * The seats something is offered to now, in either register (A3: one offer
 * mechanism, one offer at a time per seat): a lead's offer that still
 * reserves it, or a question's. `questions` is the question register's
 * snapshot the caller read with `s` (under the registers' lock when it
 * offers); left out, it is read here.
 */
export async function offeredSeats(sandboxRoot: string, s: LeadsState, now = Date.now(), questions?: import("./questions.ts").QuestionsSnapshot | null): Promise<Set<string>> {
  const out = new Set<string>();
  for (const l of s.leads.values()) for (const o of l.offers) if (O.reserving(o, now, l.rev)) out.add(o.to);
  for (const [key, list] of s.reviewOffers) for (const o of list) if (O.reserving(o, now, reviewRev(key, s))) out.add(o.to);
  const Q = await import("./questions.ts");
  const qs = questions !== undefined ? questions : await Q.questionsSnapshot(sandboxRoot).catch(() => null);
  for (const q of qs?.state.questions.values() ?? []) {
    const o = Q.reservingQuestionOffer(q, now);
    if (o) out.add(o.to);
  }
  return out;
}

/** When each seat began waiting, if it is waiting now (protocol.ts marks it); a seat with an offer standing in either register is not idle for another. */
export async function idleSeats(sandboxRoot: string, s: LeadsState, v: LedgerView, jobs: JobFacts[], now = Date.now(), questions?: import("./questions.ts").QuestionsSnapshot | null): Promise<Array<{ agent: string; since: number }>> {
  const ids = await P.teamIds(sandboxRoot).catch(() => [] as string[]);
  const offered = await offeredSeats(sandboxRoot, s, now, questions);
  const out: Array<{ agent: string; since: number }> = [];
  for (const agent of ids) {
    if (existsSync(join(sandboxRoot, "done", "agents", `${agent}.done`)) || existsSync(join(sandboxRoot, "done", "agents", `${agent}.dead`))) continue;
    const mark = await P.readWaiting(sandboxRoot, agent);
    const since = P.waitingSince(mark, now);
    if (since === null || now - since < IDLE_SEAT_MS) continue;
    // A seat whose held leads all wait on a need is idle for offers (A2):
    // it keeps them, and takes other work meanwhile.
    const holds = [...s.leads.values()].some((l) => l.holder === agent && !l.closed && leadStatus(l, s, v) !== "blocked");
    if (holds) continue;
    if (jobs.some((j) => j.agent === agent && jobOpen(j))) continue;
    // One offer at a time, across both registers: a seat something is offered to now is not offered more.
    if (offered.has(agent)) continue;
    out.push({ agent, since });
  }
  return out.sort((a, b) => a.since - b.since || a.agent.localeCompare(b.agent));
}

// --- coordination: availability, parked leads, coverage, first choices ------------------------

/**
 * Whether a seat can take work now: on the team, neither done nor marked
 * dead, and not compacting its context (a compacting seat takes no prompt
 * until it is through; offers, a confirmation and the finish coordinator
 * skip it). `activity` is recentActivity's, read by the caller when it has
 * it.
 */
export async function seatAvailable(sandboxRoot: string, agent: string, activity?: Map<string, { last: number; compacting: number | null }>, now = Date.now()): Promise<{ available: boolean; why: string }> {
  if (!agent || agent === "system" || agent === "operator") return { available: false, why: `${agent || "nobody"} is not a seat` };
  const ids = await P.teamIds(sandboxRoot).catch(() => [] as string[]);
  if (!ids.includes(agent)) return { available: false, why: `${agent} is not on the team` };
  for (const m of ["done", "dead"] as const) if (existsSync(join(sandboxRoot, "done", "agents", `${agent}.${m}`))) return { available: false, why: `${agent} is ${m === "done" ? "done" : "marked dead"}` };
  const act = activity ?? (await recentActivity(sandboxRoot, LEAD_COMPACTION_BOUND_MS, now));
  const row = act.get(agent);
  if (row?.compacting && now - row.compacting < LEAD_COMPACTION_BOUND_MS) return { available: false, why: `${agent} is compacting its context` };
  return { available: true, why: `${agent} can take it` };
}

/** How long a held lead may go with no job and no act on it while its holder works elsewhere before it shows as parked (SWARM_LEAD_PARK_SEC, 600). */
export function parkMs(): number {
  return envMs("SWARM_LEAD_PARK_SEC", 600);
}

/** When a lead was last worked: the newest act on it (a claim, a job, a link, a note, a keep), or an interpretation of one of its jobs. */
export function lastLeadAct(l: Lead, s: LeadsState): number {
  let last = 0;
  for (const e of s.events) {
    if ((e.lead === l.id && REVISING.has(e.ev)) || (e.ev === "interpret" && e.job && l.jobs.includes(e.job))) last = Math.max(last, Date.parse(e.at) || 0);
  }
  return last;
}

export type ParkedLead = { lead: string; holder: string; idle_ms: number; since: string; elsewhere: string };

/**
 * The positive evidence that a lead's holder works on something else since
 * its last act on this lead: an act of its on another lead (an open, a
 * claim, a job run under it, a link, a close, a keep, a hand-off), an
 * interpretation of another lead's job, or a job of its running under
 * another lead. Foreground work (reading, a shell) is no such evidence: a
 * seat analysing its only lead's output for ten minutes is working it.
 */
function workElsewhere(l: Lead, holder: string, since: number, snap: LeadsSnapshot): string | null {
  for (let i = snap.state.events.length - 1; i >= 0; i--) {
    const e = snap.state.events[i]!;
    const at = Date.parse(e.at);
    if (!(at > since)) break;
    const actor = e.ev === "claim" || e.ev === "open" ? (e.holder ?? e.by) : e.by;
    if (actor !== holder) continue;
    if (e.lead && e.lead !== l.id && REVISING.has(e.ev)) return `${holder} ${e.ev === "job" ? `ran ${e.job} under` : `acted on (${e.ev})`} ${e.lead} at ${e.at}`;
    if (e.ev === "interpret" && e.job && !l.jobs.includes(e.job)) return `${holder} interpreted ${e.job} at ${e.at}`;
  }
  for (const j of snap.jobs) {
    const under = snap.state.jobLead.get(j.id);
    if (j.agent === holder && jobOpen(j) && under && under !== l.id) return `${holder}'s job ${j.id} runs under ${under}`;
  }
  return null;
}

/**
 * The parked leads (A2): held and ready, no job of theirs running and no
 * act on them for parkMs(), while their holder works elsewhere: it acted
 * within the stale limit (so the stale rule does not reach them), and
 * something positive shows the work is on another lead (workElsewhere).
 * Shown in the header and offered to an idle seat unless the holder acts on
 * them first (lead_claim of one's own lead keeps it). Replaces a count cap:
 * on ctf12 two or more idle holds at an open were rare (4 of 105 in Belka),
 * and the idle holds that mattered ran 40 to 74 minutes in the hands of
 * seats busy elsewhere.
 */
export async function parkedLeads(sandboxRoot: string, snap: LeadsSnapshot, now = Date.now(), activity?: Map<string, { last: number; compacting: number | null }>): Promise<ParkedLead[]> {
  const candidates = [...snap.state.leads.values()].filter((l) => l.holder && !l.closed && leadStatus(l, snap.state, snap.ledger) === "active" && now - lastLeadAct(l, snap.state) >= parkMs() && !snap.jobs.some((j) => snap.state.jobLead.get(j.id) === l.id && jobOpen(j)));
  if (!candidates.length) return [];
  const act = activity ?? (await recentActivity(sandboxRoot, Math.max(leadStaleMs(), LEAD_COMPACTION_BOUND_MS), now));
  const out: ParkedLead[] = [];
  for (const l of candidates) {
    const row = act.get(l.holder!);
    if (!row?.last || now - row.last >= leadStaleMs() || row.compacting) continue;
    const last = lastLeadAct(l, snap.state);
    const elsewhere = workElsewhere(l, l.holder!, last, snap);
    if (!elsewhere) continue;
    out.push({ lead: l.id, holder: l.holder!, idle_ms: now - last, since: new Date(last).toISOString(), elsewhere });
  }
  return out;
}

/** The leads a seat holds, open, for its label. */
export function heldLeads(snap: LeadsSnapshot, agent: string): Array<{ id: string; title: string; status: string }> {
  return [...snap.state.leads.values()].filter((l) => l.holder === agent && !l.closed).map((l) => ({ id: l.id, title: l.title, status: leadStatus(l, snap.state, snap.ledger) }));
}

/** A seat's visible label (A1): its stable name (or its id), and what it holds. */
export function seatLabel(agent: string, name: string | null, holds: Array<{ id: string; title: string }>): string {
  return `${name ? `${name} (${agent})` : agent}${holds.length ? ` on ${holds.map((h) => `${h.id} "${h.title}"`).join(", ")}` : ", holding no lead"}`;
}

/** What the register covers now, for a seat choosing: every held open lead with its holder and questions, and the questions no held lead covers. */
export type CoverageView = { held: Array<{ lead: string; holder: string; title: string; answers: string[]; objects?: string[]; since: string | null }>; uncovered: string[] };

export function coverageView(snap: LeadsSnapshot): CoverageView {
  const held = [...snap.state.leads.values()]
    .filter((l) => l.holder && !l.closed)
    .map((l) => ({ lead: l.id, holder: l.holder!, title: l.title, answers: l.answers, ...(l.objects?.length ? { objects: l.objects } : {}), since: l.held_since }));
  return { held, uncovered: questionCoverage(snap).uncovered };
}

/**
 * The held open leads of other seats whose questions this work's questions
 * meet (A1): the load-bearing coverage check, on `answers` only. Overlap is
 * not identity: two routes to one question are legitimate when said so
 * (overlap second_route or verification, with why).
 */
export function overlappingLeads(snap: LeadsSnapshot, answers: string[], agent: string, except?: string): Array<{ lead: string; holder: string; answers: string[]; since: string | null }> {
  if (!answers.length) return [];
  const keys = new Set(answers.map((a) => P.sectionKey(a)));
  return [...snap.state.leads.values()]
    .filter((l) => l.id !== except && l.holder && l.holder !== agent && !l.closed && l.answers.some((a) => keys.has(P.sectionKey(a))))
    .map((l) => ({ lead: l.id, holder: l.holder!, answers: l.answers.filter((a) => keys.has(P.sectionKey(a))), since: l.held_since }));
}

/** Objects the work names that a held lead of another seat names too, or a running job of another seat declared: a hint, never a refusal. */
export function objectHints(snap: LeadsSnapshot, objects: string[], agent: string, except?: string): string[] {
  if (!objects.length) return [];
  const want = new Set(objects);
  const out: string[] = [];
  for (const l of snap.state.leads.values()) {
    if (l.id === except || !l.holder || l.holder === agent || l.closed) continue;
    const both = (l.objects ?? []).filter((o) => want.has(o));
    if (both.length) out.push(`${l.id} (${l.holder}) names ${both.join(", ")} too`);
  }
  return out;
}

/**
 * The coverage hint at a heavy job's admission (A1): the held leads of
 * other seats on the questions of the lead the job runs under, and those
 * naming the objects it declared, and the other seats' open jobs over the
 * same declared objects. A hint, never a refusal: a collision found after a
 * large extraction starts is already late, so it is said before.
 */
export async function jobAdmissionHint(sandboxRoot: string, agent: string, lead: unknown, inputs: string[]): Promise<{ overlaps: Array<{ lead: string; holder: string; answers: string[]; since: string | null }>; objects: string[]; jobs: string[] } | null> {
  const snap = await leadsSnapshot(sandboxRoot);
  const ref = lead !== undefined && lead !== null && String(lead).trim() ? leadRef(lead) : null;
  const l = ref?.ok ? snap.state.leads.get(ref.id) : [...snap.state.leads.values()].filter((x) => x.holder === agent && !x.closed).length === 1 ? [...snap.state.leads.values()].find((x) => x.holder === agent && !x.closed) : undefined;
  const overlaps = l ? overlappingLeads(snap, l.answers, agent, l.id) : [];
  const declared = inputs.filter((x) => x && x !== "all");
  const objects = objectHints(snap, declared, agent, l?.id);
  const jobs: string[] = [];
  if (declared.length) {
    for (const j of snap.jobs) {
      if (j.agent === agent || !jobOpen(j)) continue;
      const d = await NB.jobDeclared(sandboxRoot, j.id).catch(() => null);
      const both = (d?.inputs ?? []).filter((x) => declared.includes(x));
      if (both.length) jobs.push(`${j.id} (${j.agent}, ${j.state}) declared ${both.join(", ")} too`);
    }
  }
  return overlaps.length || objects.length || jobs.length ? { overlaps, objects, jobs } : null;
}

/**
 * A person's question this work serves that is offered to another seat now
 * (A3): its first claim holds against every way of taking the work (an
 * open with take, a claim, a reopen with take), not only the first.
 */
async function questionReservation(snap: LeadsSnapshot, answers: string[], agent: string, now: number): Promise<{ q: import("./questions.ts").Question; o: O.Offer } | null> {
  if (!snap.questions || !answers.length || agent === "operator") return null;
  const Q = await import("./questions.ts");
  for (const sec of answers) {
    const q = snap.questions.bySection.get(P.sectionKey(sec)) ?? snap.questions.bySection.get(sec);
    if (!q) continue;
    const o = Q.reservingQuestionOffer(q, now);
    if (o && o.to !== agent) return { q, o };
  }
  return null;
}

export const OVERLAP_KINDS = ["second_route", "verification"] as const;

/** The overlap an open or a claim says, when it says one: second_route or verification, with why. */
function checkOverlap(kind: unknown, why: unknown): { ok: true; overlap: { kind: string; why: string } | null } | { ok: false; reason: string } {
  const k = String(kind ?? "").trim();
  if (!k) return { ok: true, overlap: null };
  if (!(OVERLAP_KINDS as readonly string[]).includes(k)) return { ok: false, reason: `overlap is second_route or verification (got ${JSON.stringify(kind)})` };
  const w = bounded("overlap_why", why, LEAD_WHY_MAX, true);
  if (!w.ok) return { ok: false, reason: `${w.reason}: say how your route differs from the held lead's, or what you verify independently` };
  return { ok: true, overlap: { kind: k, why: w.value } };
}

/** When each seat made its first choice: its first lead opened or claimed, or its first name. */
async function firstChoices(sandboxRoot: string, s?: LeadsState): Promise<Map<string, number>> {
  const out = new Map<string, number>();
  const put = (agent: string, at: number) => {
    if (!agent || !Number.isFinite(at)) return;
    if (!out.has(agent) || at < out.get(agent)!) out.set(agent, at);
  };
  const state = s ?? foldLeads((await readLeadEvents(sandboxRoot)).events);
  for (const e of state.events) {
    if (e.ev === "open") put(e.by, Date.parse(e.at));
    else if (e.ev === "claim") put(e.holder ?? e.by, Date.parse(e.at));
  }
  for (const n of await P.readNames(sandboxRoot).catch(() => [] as P.NameRecord[])) put(n.id, Date.parse(n.first_at ?? n.at));
  return out;
}

export type FirstChoiceAdmission = { order: number; waited_ms: number; turn_at: string; coverage: CoverageView };

/**
 * Staggered first choices (A1). On ctf12 ten seats named themselves within
 * eight seconds against an empty board and an empty register, and six took
 * the same four questions. When the kickoff asks for it (budget.json
 * coordination.first_choice_stagger_sec), a seat's first choice (its first
 * lead opened or claimed, or its first name) waits for its turn in team
 * order: until the seat before it has chosen, or first_choice_stagger_sec
 * (20) after that seat's own turn, whichever is first; a seat marked done
 * or dead is skipped, and no seat waits past first_choice_bound_sec (90)
 * from the run's start. The admission carries the register's coverage as it
 * stands then, so the choice is made against what the seats before it took.
 * Null when there is nothing to wait for (no stagger, not a first choice,
 * past the bound).
 */
export async function admitFirstChoice(sandboxRoot: string, agent: string, o: { now?: () => number; sleep?: (ms: number) => Promise<void> } = {}): Promise<FirstChoiceAdmission | null> {
  const now = o.now ?? Date.now;
  const sleep = o.sleep ?? ((ms: number) => new Promise<void>((r) => setTimeout(r, ms)));
  const budget = await P.readBudget(sandboxRoot).catch(() => null);
  const step = Number(budget?.coordination?.first_choice_stagger_sec ?? 0) * 1000;
  if (!budget || !(step > 0)) return null;
  const bound = Number(budget.coordination?.first_choice_bound_sec ?? 90) * 1000;
  const start = Date.parse(budget.started_at);
  if (!Number.isFinite(start)) return null;
  const ids = await P.teamIds(sandboxRoot).catch(() => [] as string[]);
  const k = ids.indexOf(agent);
  if (k < 0) return null;
  if ((await firstChoices(sandboxRoot)).has(agent)) return null;
  const began = now();
  if (began >= start + bound) return null;
  let turn = start;
  for (;;) {
    const firsts = await firstChoices(sandboxRoot);
    turn = start;
    for (let j = 0; j < k; j++) {
      const peer = ids[j]!;
      if (existsSync(join(sandboxRoot, "done", "agents", `${peer}.done`)) || existsSync(join(sandboxRoot, "done", "agents", `${peer}.dead`))) continue;
      const chose = firsts.get(peer);
      turn = chose !== undefined ? Math.min(Math.max(chose, turn), turn + step) : turn + step;
    }
    turn = Math.min(turn, start + bound);
    const t = now();
    if (t >= turn) break;
    await sleep(Math.min(1000, turn - t));
  }
  return { order: k, waited_ms: Math.max(0, now() - began), turn_at: new Date(turn).toISOString(), coverage: coverageView(await leadsSnapshot(sandboxRoot)) };
}

// --- the snapshot -------------------------------------------------------------------------------

export type LeadsSnapshot = {
  state: LeadsState;
  ledger: LedgerView;
  goal: GoalQuestions;
  /** Question ids with a standing answer entry. */
  answered: Set<string>;
  jobs: JobFacts[];
  at: number;
  /** The question register (extensions/questions.ts), read beside the leads; null when it could not be read. */
  questions: import("./questions.ts").QuestionsSnapshot | null;
};

export async function leadsSnapshot(sandboxRoot: string): Promise<LeadsSnapshot> {
  const { events, text } = await readLeadEvents(sandboxRoot);
  const chain = verifyLeadChain(text);
  const state = foldLeads(events, chain);
  const entries = await P.readLedger(sandboxRoot).catch(() => [] as P.LedgerEntry[]);
  const disputes = await P.readDisputes(sandboxRoot).catch(() => [] as P.LedgerDispute[]);
  const ledger = ledgerView(entries, disputes);
  ledger.sweeps = await SW.readSweeps(sandboxRoot).catch(() => [] as SW.SweepRecord[]);
  const goal = await goalQuestions(sandboxRoot);
  const answered = new Set<string>();
  for (const e of entries) {
    if (e.kind !== "answer" || !e.section?.startsWith("question:") || ledger.replaced.has(e.seq)) continue;
    answered.add(P.sectionKey(e.section.slice("question:".length)));
  }
  const jobs = await readJobs(sandboxRoot);
  const questions = await import("./questions.ts").then((Q) => Q.questionsSnapshot(sandboxRoot, { goal })).catch(() => null);
  return { state, ledger, goal, answered, jobs, at: Date.now(), questions };
}

/** A lead as a reader is shown it: its record, with everything derived beside it. */
export type LeadView = {
  id: string;
  title: string;
  why: string;
  origin: string;
  status: LeadStatus;
  material: boolean;
  holder: string | null;
  generation: number;
  needs: Array<{ need: string; met: boolean; why?: string; outcome: NeedOutcome }>;
  /** Needs dropped with a reason: withdrawn, never met. */
  dropped?: DroppedNeed[];
  answers: string[];
  disposition?: LeadDisposition;
  ref?: string;
  closed_by?: string;
  closed_at?: string;
  close_why?: string;
  opened_by: string;
  opened_at: string;
  held_since: string | null;
  priority: number;
  waiting_on_it: { leads: string[]; questions: string[] };
  stale: Lead["stale"];
  jobs: string[];
  notes: Lead["notes"];
  reopened: Lead["reopened"];
  proposition?: string;
  negation?: string;
  product?: string;
  acceptance?: string;
  routes: NB.Route[];
  not_examined?: Array<{ source: string; method: string; why: string }>;
  quick_negative?: { held_ms: number; jobs: number; objects: number };
  /** Its revision: lead_reopen and lead_confirm name the one they read. */
  rev: number;
  route_reviews?: Lead["route_reviews"];
  /** The offer that holds it for one seat now, and until when (extensions/offers.ts). */
  offered?: { to: string; reason: O.OfferReason; until: string; state: O.OfferState; from?: string };
  /** A closure waiting for its closer's confirmation: the entry it was closed on, superseded, and the one that stands now. */
  confirm?: { ref_was: string; head: string | null; since: string; to: string | null };
  confirmed?: Lead["confirmed"];
  inputs?: string[];
  next_action?: string;
  result_refs?: string[];
  objects?: string[];
  overlap?: Lead["overlap"];
  covered_by?: string[];
};

export function viewLead(l: Lead, snap: LeadsSnapshot): LeadView {
  const { state: s, ledger: v } = snap;
  const status = leadStatus(l, s, v);
  const deps = dependentsOf(l.id, s);
  const qs = new Set<string>();
  for (const id of [l.id, ...deps]) for (const a of s.leads.get(id)?.answers ?? []) if (!snap.answered.has(P.sectionKey(a))) qs.add(P.sectionKey(a));
  return {
    id: l.id,
    title: l.title,
    why: l.why,
    origin: l.origin,
    status,
    material: l.material,
    holder: l.holder,
    generation: l.generation,
    needs: l.needs.map((n) => ({ need: n, ...needState(n, s, v), outcome: needOutcome(n, s, v) })).map(({ dead: _d, ...x }) => x),
    ...(l.dropped.length ? { dropped: l.dropped } : {}),
    answers: l.answers,
    ...(l.closed ? { disposition: l.closed.disposition, ref: l.closed.ref, closed_by: l.closed.by, closed_at: l.closed.at, ...(l.closed.why ? { close_why: l.closed.why } : {}) } : {}),
    opened_by: l.opened_by,
    opened_at: l.opened_at,
    held_since: l.held_since,
    priority: l.closed ? 0 : deps.length + qs.size,
    waiting_on_it: { leads: deps, questions: [...qs].sort() },
    stale: l.stale,
    jobs: l.jobs,
    notes: l.notes,
    reopened: l.reopened,
    ...(l.proposition ? { proposition: l.proposition } : {}),
    ...(l.negation ? { negation: l.negation } : {}),
    ...(l.product ? { product: l.product } : {}),
    ...(l.acceptance ? { acceptance: l.acceptance } : {}),
    routes: l.routes,
    ...(l.not_examined?.length ? { not_examined: l.not_examined } : {}),
    ...(l.quick_negative ? { quick_negative: l.quick_negative } : {}),
    rev: l.rev,
    ...(l.route_reviews.length ? { route_reviews: l.route_reviews } : {}),
    ...(() => {
      const o = O.reservingOffer(l.offers, snap.at, l.rev);
      if (!o) return {};
      const st = O.offerStatus(o, snap.at, l.rev);
      return { offered: { to: o.to, reason: o.reason, until: new Date(st.until).toISOString(), state: st.state, ...(o.from ? { from: o.from } : {}) } };
    })(),
    ...(l.confirm ? { confirm: { ref_was: l.confirm.ref_was, head: l.confirm.head, since: l.confirm.at, to: l.offers.find((o) => o.seq === l.confirm!.offer)?.to ?? null } } : {}),
    ...(l.confirmed?.length ? { confirmed: l.confirmed } : {}),
    ...(l.inputs?.length ? { inputs: l.inputs } : {}),
    ...(l.next_action ? { next_action: l.next_action } : {}),
    ...(l.result_refs?.length ? { result_refs: l.result_refs } : {}),
    ...(l.objects?.length ? { objects: l.objects } : {}),
    ...(l.overlap ? { overlap: l.overlap } : {}),
    ...(l.covered_by?.length ? { covered_by: l.covered_by } : {}),
  };
}

/** Every lead's view, the live ones by priority then age, the closed ones after them by when they closed. */
export function rankedLeads(snap: LeadsSnapshot): LeadView[] {
  const views = [...snap.state.leads.values()].map((l) => viewLead(l, snap));
  const live = views.filter((x) => x.status !== "closed").sort((a, b) => b.priority - a.priority || a.opened_at.localeCompare(b.opened_at) || a.id.localeCompare(b.id));
  const closed = views.filter((x) => x.status === "closed").sort((a, b) => (a.closed_at ?? "").localeCompare(b.closed_at ?? "") || a.id.localeCompare(b.id));
  return [...live, ...closed];
}

/** Whether the register holds a section's question as withdrawn: the goal's own included, whose withdrawal takes it off what the run must answer. */
export function withdrawnSection(snap: LeadsSnapshot, section: string): boolean {
  return Boolean(snap.questions?.bySection.get(P.sectionKey(section))?.withdrawn);
}

/**
 * The questions the run is to answer: the goal's that were not withdrawn,
 * then every other question the register holds in scope (a person's, an
 * agent's), by their sections. The goal keeps its questions, and the
 * register its withdrawals; this is what they leave required.
 */
export function caseQuestions(snap: LeadsSnapshot): string[] {
  const out = snap.goal.questions.filter((q) => !withdrawnSection(snap, q));
  for (const q of snap.questions?.state.questions.values() ?? []) {
    if (q.origin.kind === "goal" || q.scope !== "in_scope" || q.withdrawn || q.after_done) continue;
    if (!out.includes(q.section)) out.push(q.section);
  }
  return out;
}

/** The case's questions with no standing answer, and of those, the ones no held lead covers. */
export function questionCoverage(snap: LeadsSnapshot): { unanswered: string[]; uncovered: string[]; open_leads_for: Record<string, string[]> } {
  const unanswered = caseQuestions(snap).filter((q) => !snap.answered.has(P.sectionKey(q)));
  const uncovered: string[] = [];
  const openFor: Record<string, string[]> = {};
  for (const q of unanswered) {
    const naming = [...snap.state.leads.values()].filter((l) => !l.closed && l.answers.some((a) => P.sectionKey(a) === P.sectionKey(q)));
    if (!naming.some((l) => l.holder)) uncovered.push(q);
    const unheld = naming.filter((l) => !l.holder).map((l) => l.id);
    if (unheld.length) openFor[q] = unheld;
  }
  return { unanswered, uncovered, open_leads_for: openFor };
}

// --- writing ------------------------------------------------------------------------------------

async function appendLeadEvents(sandboxRoot: string, events: Array<Omit<LeadEvent, "v" | "seq" | "at" | "prev" | "hash"> & { at?: string }>, held: P.HeldLock): Promise<LeadEvent[]> {
  const { events: existing, text } = await readLeadEvents(sandboxRoot);
  const chain = verifyLeadChain(text);
  if (!chain.ok) throw new Error(`leads/leads.jsonl's chain is broken at line ${chain.broken_at} (${chain.reason}); the register takes no new event until the operator looks`);
  let prev = chain.head ?? "genesis";
  let seq = existing.length;
  const out: LeadEvent[] = [];
  for (const raw of events) {
    seq += 1;
    const draft = { v: 1 as const, seq, at: raw.at ?? new Date().toISOString(), ...Object.fromEntries(Object.entries(raw).filter(([k, x]) => k !== "at" && x !== undefined)) } as Omit<LeadEvent, "prev" | "hash">;
    const withPrev = { ...draft, prev } as Omit<LeadEvent, "hash">;
    const e = { ...withPrev, hash: leadEventHash(withPrev, prev) } as LeadEvent;
    out.push(e);
    prev = e.hash;
  }
  await mkdir(join(sandboxRoot, LEADS_DIR), { recursive: true });
  await held.assertOwned();
  await appendFile(join(sandboxRoot, LEADS_LOG), out.map((e) => `${JSON.stringify(e)}\n`).join(""), "utf8");
  return out;
}

/** A lead event as a writer drafts it: the chain fields are the append's. */
export type LeadDraft = Omit<LeadEvent, "v" | "seq" | "at" | "prev" | "hash">;

/** Run `fn` under the lock both registers share (the question register's writes take it through here). */
export async function withRegisters<T>(sandboxRoot: string, fn: (held: P.HeldLock) => Promise<T>): Promise<T> {
  return P.withNamedLock(sandboxRoot, LOCK, fn);
}

/** Append lead events under a lock the caller holds (withRegisters), and render leads.md. */
export async function appendLeadEventsHeld(sandboxRoot: string, events: LeadDraft[], held: P.HeldLock): Promise<LeadEvent[]> {
  const out = events.length ? await appendLeadEvents(sandboxRoot, events, held) : [];
  if (out.length) await writeLeadsMd(sandboxRoot).catch(() => undefined);
  return out;
}

/** Run `fn` under the register's lock, with its state read inside the lock; what it returns to append is appended, and leads.md rendered. */
async function transact<T>(sandboxRoot: string, fn: (snap: LeadsSnapshot) => Promise<{ append: Array<Omit<LeadEvent, "v" | "seq" | "at" | "prev" | "hash">>; result: T }>): Promise<T & { events: LeadEvent[] }> {
  return P.withNamedLock(sandboxRoot, LOCK, async (held) => {
    const snap = await leadsSnapshot(sandboxRoot);
    const { append, result } = await fn(snap);
    const events = append.length ? await appendLeadEvents(sandboxRoot, append, held) : [];
    if (events.length) await writeLeadsMd(sandboxRoot).catch(() => undefined);
    return { ...result, events };
  });
}

function bounded(name: string, raw: unknown, max: number, required: boolean): { ok: true; value: string } | { ok: false; reason: string } {
  const text = String(raw ?? "").trim();
  if (required && !text) return { ok: false, reason: `${name} is required` };
  if (text.length > max) return { ok: false, reason: `${name} is over ${max} characters: say it in fewer; nothing is cut, so a longer text is refused, not shortened` };
  return { ok: true, value: text };
}

function listOf(v: unknown): string[] {
  const raw = Array.isArray(v) ? v.map(String) : typeof v === "string" ? v.split(/[\s,]+/) : [];
  return [...new Set(raw.map((x) => x.trim()).filter(Boolean))];
}

export type LeadResult<T = Record<string, unknown>> = ({ ok: true } & T) | { ok: false; reason: string };
type Fail = { ok: false; reason: string };

export type LeadOpenInput = {
  title?: string;
  why?: string;
  needs?: string[] | string;
  answers?: string[] | string;
  material?: boolean;
  take?: boolean;
  origin?: string;
  /** Under an analyst's question: the proposition this lead tests, and its negation (required on the first agent lead under one). */
  proposition?: string;
  negation?: string;
  /** A directive's product and acceptance (the operator's lead under a question). */
  product?: string;
  acceptance?: string;
  /** The route plan: [{source, method}], the sources to examine and how, before the search (the negative bar). */
  routes?: unknown;
  /** A held open that overlaps a held lead's questions on purpose: second_route or verification, with why (A1). */
  overlap?: string;
  overlap_why?: string;
  /** Coverage hints: the objects the work is over (never load-bearing). */
  objects?: string[] | string;
  /** The product contract (A2): immutable refs it starts from, and the first act once its product is accepted. */
  inputs?: string[] | string;
  next_action?: string;
  /** Open this as a prerequisite of another lead and link it there in the same act: the consumer's id (L-<n>). */
  consumer?: string;
  /** With consumer: the outcome the consumer needs of this lead (resolved, negative, …), resolved when left out. */
  consumer_needs?: string;
};

/** A list of refs as given, each resolving to an object of the run or an entry (E-<seq>), at most LEAD_MAX_NEEDS. */
async function checkRefList(sandboxRoot: string, name: string, raw: unknown): Promise<{ ok: true; refs: string[] } | { ok: false; reason: string }> {
  const refs = listOf(raw);
  if (refs.length > LEAD_MAX_NEEDS) return { ok: false, reason: `${name} names at most ${LEAD_MAX_NEEDS} refs` };
  const objects = refs.filter((r) => !/^E-\d+$/i.test(r));
  if (objects.length) {
    const checked = await P.checkRefs(sandboxRoot, objects);
    if (!checked.ok) return { ok: false, reason: `${name}: ${checked.reason}` };
  }
  return { ok: true, refs: refs.map((r) => (/^e-\d+$/i.test(r) ? r.toUpperCase() : r)) };
}

/** A route plan as given: [{source, method}], each said, at most NB.MAX_ROUTES. */
export function checkRoutes(raw: unknown): { ok: true; routes: NB.Route[] } | { ok: false; reason: string } {
  if (raw === undefined || raw === null) return { ok: true, routes: [] };
  if (!Array.isArray(raw)) return { ok: false, reason: 'routes is a list of {source, method}: each source to examine (input:<path>, member:<gen>#<n>, job:<id>/<path>, a path of the run, or words when it is not an object yet) and how' };
  const out: NB.Route[] = [];
  for (const r of raw) {
    const o = (r && typeof r === "object" ? r : {}) as { source?: unknown; method?: unknown };
    const source = bounded("a route's source", o.source, LEAD_WHY_MAX, true);
    if (!source.ok) return { ok: false, reason: `${source.reason}: a route is {source, method}` };
    const method = bounded("a route's method", o.method, LEAD_WHY_MAX, true);
    if (!method.ok) return { ok: false, reason: `${method.reason}: a route is {source, method}` };
    if (!out.some((x) => x.source === source.value && x.method === method.value)) out.push({ source: source.value, method: method.value });
  }
  if (out.length > NB.MAX_ROUTES) return { ok: false, reason: `a lead plans at most ${NB.MAX_ROUTES} routes` };
  return { ok: true, routes: out };
}

/** Every route the leads under a question planned. */
export function questionRoutes(s: LeadsState, section: string): NB.Route[] {
  const out: NB.Route[] = [];
  for (const l of s.leads.values()) {
    if (!l.answers.includes(section)) continue;
    for (const r of l.routes) if (!out.some((x) => x.source === r.source && x.method === r.method)) out.push(r);
  }
  return out;
}

function checkNeeds(raw: unknown, s: LeadsState, v: LedgerView, self?: string): { ok: true; needs: string[] } | { ok: false; reason: string } {
  const needs: string[] = [];
  for (const n of listOf(raw)) {
    const p = parseNeed(n);
    if (!p.ok) return p;
    if (p.lead && !s.leads.has(p.lead)) return { ok: false, reason: `${p.lead} does not exist: open it first, or need an entry (E-<seq>)` };
    if (p.entry !== undefined && !v.bySeq.has(p.entry)) return { ok: false, reason: `E-${p.entry} is not in the ledger` };
    // A need is what has not come yet (A2): an entry that stands is where
    // the lead comes from, not what it waits for.
    if (p.entry !== undefined && entryStands(v, p.entry).ok) return { ok: false, reason: `E-${p.entry} stands: it is not a need. Put it in why or origin (where this lead comes from); a need is what has not come yet: another lead's outcome (L-<n>, L-<n>:negative)` };
    if (self && wouldCycle(self, p.need, s)) return { ok: false, reason: `${self} needing ${p.need} closes a loop: ${p.lead} already needs ${self}, directly or through other leads` };
    if (!needs.includes(p.need)) needs.push(p.need);
  }
  if (needs.length > LEAD_MAX_NEEDS) return { ok: false, reason: `a lead names at most ${LEAD_MAX_NEEDS} needs` };
  return { ok: true, needs };
}

function checkAnswers(raw: unknown): { ok: true; answers: string[]; registered: string[] } | { ok: false; reason: string } {
  const answers: string[] = [];
  // A register id (Q-19) is resolved against the question register inside the
  // lock (resolveAnswers); the goal's own forms (3, Q3, question:3) are the
  // section they always were.
  const registered: string[] = [];
  for (const a of listOf(raw)) {
    const reg = /^Q-([1-9]\d{0,5})$/i.exec(a);
    if (reg) {
      const id = `Q-${Number(reg[1])}`;
      if (!registered.includes(id)) registered.push(id);
      continue;
    }
    const key = P.sectionKey(a.replace(/^question:/i, ""));
    if (!answers.includes(key)) answers.push(key);
  }
  if (answers.length + registered.length > LEAD_MAX_ANSWERS) return { ok: false, reason: `a lead names at most ${LEAD_MAX_ANSWERS} questions` };
  const bad = answers.find((a) => !P.LEDGER_ANSWER_ID.test(a));
  if (bad) return { ok: false, reason: `answers takes question ids: Q-19 from the question register, or the goal's own ("3", "Q3", "question:3"; got ${JSON.stringify(bad)})` };
  return { ok: true, answers, registered };
}

/**
 * The questions a lead names, as the ledger's sections: a register id (Q-19)
 * must name a question in scope, and becomes its section (19, or a goal's own
 * id such as "bonus"); the goal's forms pass as they are. Also says which of
 * them an analyst, a reviewer or an observer asked (a human's question is a
 * hypothesis to test: its first agent lead states the proposition and its
 * negation). Read inside the register's lock.
 */
async function resolveAnswers(sandboxRoot: string, checked: { answers: string[]; registered: string[] }): Promise<{ ok: true; answers: string[]; human: Array<{ id: string; section: string }> } | { ok: false; reason: string }> {
  const Q = await import("./questions.ts");
  const qs = await Q.questionsSnapshot(sandboxRoot);
  const out: string[] = [];
  const human: Array<{ id: string; section: string }> = [];
  // Every form a question is named by (Q-4, question:4, 4, Q4) is the same
  // question, held to the same standing: canonical first, then checked.
  const standing = (q: import("./questions.ts").Question, named: string): string | null => {
    const as = named === q.id ? q.id : `${named} (${q.id})`;
    if (q.withdrawn) return `${as} was withdrawn by ${Q.originWords(q.withdrawn.origin)}: ${q.withdrawn.why}`;
    if (q.scope === "excluded") return `${as} is excluded from the case (${q.scope_why}); it is no lead's work`;
    if (q.scope === "proposed") return `${as} is proposed and waits for the operator's triage: it is not the case's work until it is admitted`;
    return null;
  };
  for (const section of checked.answers) {
    const q = qs.bySection.get(section);
    if (q) {
      const why = standing(q, `question:${section}`);
      if (why) return { ok: false, reason: why };
    }
    if (!out.includes(section)) out.push(section);
  }
  for (const id of checked.registered) {
    const q = qs.state.questions.get(id);
    if (!q) return { ok: false, reason: `${id} is not in the question register (questions view=list names every question)` };
    const why = standing(q, id);
    if (why) return { ok: false, reason: why };
    if (!out.includes(q.section)) out.push(q.section);
  }
  for (const section of out) {
    const q = qs.bySection.get(section);
    if (q && Q.HUMAN_ORIGINS.has(q.origin.kind)) human.push({ id: q.id, section });
  }
  return { ok: true, answers: out, human };
}

/**
 * Open a lead. With take, the opener holds it at once (create and claim in
 * one step: the discoverer's first refusal, so nobody takes the natural next
 * step of its own work from under it). Without, it is open to everyone, and
 * when it is ready (no unmet need) the seat idle longest is woken for it.
 */
/** An offer as the register writes it: to whom, why, the lead's revision and open spell it binds, and its age bound. */
function offerDraft(lead: string, to: string, reason: O.OfferReason, rev: number, cycle: number, now: number, extra: Partial<LeadDraft> = {}): LeadDraft {
  return { by: "system", ev: "offer", lead, to, reason, rev, cycle, max_until: new Date(now + O.offerMaxAgeMs()).toISOString(), ...extra };
}

export type OpenCoverage = { held: boolean; overlaps: Array<{ lead: string; holder: string; answers: string[]; since: string | null }>; objects: string[]; reserved?: string; why: string };

export async function openLead(ctx: P.SwarmContext, input: LeadOpenInput): Promise<LeadResult<{ lead: LeadView; woke?: string; offered_to?: string; warning?: string; coverage?: OpenCoverage; admission?: FirstChoiceAdmission; consumer?: string }>> {
  const title = bounded("title", input.title, LEAD_TITLE_MAX, true);
  if (!title.ok) return title;
  const why = bounded("why", input.why, LEAD_WHY_MAX, true);
  if (!why.ok) return why;
  const origin = bounded("origin", input.origin, 200, false);
  if (!origin.ok) return origin;
  if (input.material !== undefined && typeof input.material !== "boolean") return { ok: false, reason: "material is true or false" };
  if (input.take !== undefined && typeof input.take !== "boolean") return { ok: false, reason: "take is true or false" };
  const checked = checkAnswers(input.answers);
  if (!checked.ok) return checked;
  const proposition = bounded("proposition", input.proposition, LEAD_WHY_MAX, false);
  if (!proposition.ok) return proposition;
  const negation = bounded("negation", input.negation, LEAD_WHY_MAX, false);
  if (!negation.ok) return negation;
  if (Boolean(proposition.value) !== Boolean(negation.value)) return { ok: false, reason: "proposition and negation come together: the proposition this lead tests, and what would hold if it is false" };
  const product = bounded("product", input.product, LEAD_WHY_MAX, false);
  if (!product.ok) return product;
  const acceptance = bounded("acceptance", input.acceptance, LEAD_WHY_MAX, false);
  if (!acceptance.ok) return acceptance;
  const routes = checkRoutes(input.routes);
  if (!routes.ok) return routes;
  const overlapSaid = checkOverlap(input.overlap, input.overlap_why);
  if (!overlapSaid.ok) return overlapSaid;
  const nextAction = bounded("next_action", input.next_action, LEAD_WHY_MAX, false);
  if (!nextAction.ok) return nextAction;
  const inputs = await checkRefList(ctx.sandboxRoot, "inputs", input.inputs);
  if (!inputs.ok) return inputs;
  const objects = listOf(input.objects);
  if (objects.length > LEAD_MAX_NEEDS) return { ok: false, reason: `objects names at most ${LEAD_MAX_NEEDS} refs` };
  let consumer: { id: string; need: string } | null = null;
  if (input.consumer !== undefined && input.consumer !== null && String(input.consumer).trim()) {
    const c = leadRef(input.consumer);
    if (!c.ok) return c;
    const disp = String(input.consumer_needs ?? "resolved").trim().toLowerCase() || "resolved";
    consumer = { id: c.id, need: disp };
  }
  // A seat's first choice waits for its turn when the kickoff staggers them (A1).
  const admission = ctx.agentId !== "operator" ? await admitFirstChoice(ctx.sandboxRoot, ctx.agentId).catch(() => null) : null;
  try {
    const r = await transact<Fail | { ok: true; id: string; woke: string | undefined; warning?: string; coverage?: OpenCoverage }>(ctx.sandboxRoot, async (snap) => {
      const needs = checkNeeds(input.needs, snap.state, snap.ledger);
      if (!needs.ok) return { append: [], result: { ok: false as const, reason: needs.reason } };
      const answers = checked.registered.length || checked.answers.length ? await resolveAnswers(ctx.sandboxRoot, checked) : { ok: true as const, answers: [] as string[], human: [] as Array<{ id: string; section: string }> };
      if (!answers.ok) return { append: [], result: { ok: false as const, reason: answers.reason } };
      // The first agent lead under a human's question tests it: the
      // proposition and its negation, stated before the search (a directive
      // is the operator's own, and carries its product instead).
      if (ctx.agentId !== "operator" && !proposition.value) {
        for (const h of answers.human) {
          const earlier = [...snap.state.leads.values()].some((l) => l.opened_by !== "operator" && l.answers.includes(h.section));
          if (!earlier) {
            return {
              append: [],
              result: {
                ok: false as const,
                reason: `${h.id} is a person's question and this is the first lead under it: it is a proposition to test, never a conclusion to confirm. Give proposition (what this lead tests) and negation (what would hold if it is false), and plan a route that could disconfirm it`,
              },
            };
          }
        }
      }
      // The route plan (the negative bar): the first lead under a question
      // lists the sources it will examine and how, before the search. A
      // person's question's first lead gives it (with a route that could
      // disconfirm it); another question's is warned, and a negative on a
      // material question closes against a plan and is refused without one.
      let warning: string | undefined;
      if (ctx.agentId !== "operator" && !routes.routes.length) {
        const planless = answers.answers.filter((sec) => !questionRoutes(snap.state, sec).length);
        const human = answers.human.find((h) => planless.includes(h.section) && ![...snap.state.leads.values()].some((l) => l.opened_by !== "operator" && l.answers.includes(h.section)));
        if (human) {
          return {
            append: [],
            result: {
              ok: false as const,
              reason: `${human.id} is a person's question and this is the first lead under it: give its route plan too, routes [{source, method}] (the sources you will examine and how, one of them able to disconfirm the proposition), so that a source nobody examined stays visible`,
            },
          };
        }
        if (planless.length) warning = `no route plan under ${planless.map((q) => `question:${q}`).join(", ")}: list the sources you will examine and how, before the search (routes [{source, method}], here or with lead_link). A negative on a material question closes against the plan, and is refused without one`;
      }
      const id = `L-${snap.state.leads.size + 1}`;
      // The consumer this opens a prerequisite for: linked in the same act (A2).
      const cons = consumer ? snap.state.leads.get(consumer.id) : undefined;
      let consumerNeed: string | null = null;
      if (consumer) {
        if (!cons) return { append: [], result: { ok: false as const, reason: `${consumer.id} does not exist: the consumer is a lead that will wait for this one` } };
        if (cons.closed) return { append: [], result: { ok: false as const, reason: `${cons.id} is closed: a prerequisite is for work still to do` } };
        if (cons.holder && cons.holder !== ctx.agentId) return { append: [], result: { ok: false as const, reason: `${cons.id} is held by ${cons.holder}; its needs are its holder's to revise` } };
        const p = parseNeed(`${id}:${consumer.need}`);
        if (!p.ok) return { append: [], result: { ok: false as const, reason: `consumer_needs: ${p.reason}` } };
        if (cons.needs.length + 1 > LEAD_MAX_NEEDS) return { append: [], result: { ok: false as const, reason: `${cons.id} names ${LEAD_MAX_NEEDS} needs already` } };
        // The whole graph as it would stand after this act, checked before
        // either event is appended: the new lead with its needs, and the
        // consumer needing it. A loop would leave both blocked for good.
        const probe: LeadsState = { ...snap.state, leads: new Map(snap.state.leads) };
        probe.leads.set(id, { id, needs: needs.needs } as Lead);
        if (wouldCycle(cons.id, p.need, probe)) {
          return { append: [], result: { ok: false as const, reason: `${cons.id} needing ${id} closes a loop: ${id} would need ${needs.needs.join(", ")}, which needs ${cons.id}, directly or through other leads. Open the prerequisite without that need, or without the consumer` } };
        }
        consumerNeed = p.need;
      }
      // The coverage check (A1): a take that meets a held lead's questions is
      // opened unheld and names the holder, unless it says it is a second
      // route or a verification; a person's question offered to another seat
      // is theirs to take first. Objects are hints only.
      const overlaps = overlappingLeads(snap, answers.answers, ctx.agentId);
      const hints = objectHints(snap, objects, ctx.agentId);
      const reservedFor = await questionReservation(snap, answers.answers, ctx.agentId, snap.at);
      let take = input.take === true;
      let coverage: OpenCoverage | undefined;
      if (take && reservedFor?.o) {
        take = false;
        coverage = { held: false, overlaps, objects: hints, reserved: `${reservedFor.q.id} is offered to ${reservedFor.o.to} (${O.untilWords(reservedFor.o, snap.at, reservedFor.q.rev)})`, why: `${reservedFor.q.id} is offered to ${reservedFor.o.to} first: ${id} is open, unheld; post to ${reservedFor.o.to}, or claim it once the offer ends` };
      } else if (take && overlaps.length && !overlapSaid.overlap && ctx.agentId !== "operator") {
        take = false;
        coverage = { held: false, overlaps, objects: hints, why: `${overlaps.map((o) => `question:${o.answers.join(", question:")} is covered by ${o.lead} (${o.holder}${o.since ? `, since ${o.since}` : ""})`).join("; ")}: ${id} is open, unheld, as a second route. Claim it only if your route differs, with overlap: second_route (or verification) and overlap_why saying how; or post to the holder` };
      } else if (overlaps.length || hints.length) {
        coverage = { held: take, overlaps, objects: hints, why: overlapSaid.overlap ? `held as ${overlapSaid.overlap.kind}: ${overlapSaid.overlap.why}` : "a hint: the objects meet a held lead's; overlap is not identity" };
      }
      const open = {
        by: ctx.agentId,
        ev: "open" as const,
        lead: id,
        title: title.value,
        why: why.value,
        origin: origin.value || (cons ? `prerequisite of ${cons.id}` : `lead_open by ${ctx.agentId}`),
        needs: needs.needs,
        answers: answers.answers,
        material: input.material !== false,
        ...(take ? { holder: ctx.agentId, generation: 1 } : { generation: 0 }),
        ...(proposition.value ? { proposition: proposition.value, negation: negation.value } : {}),
        ...(product.value ? { product: product.value } : {}),
        ...(acceptance.value ? { acceptance: acceptance.value } : {}),
        ...(routes.routes.length ? { routes: routes.routes } : {}),
        ...(take && overlaps.length && overlapSaid.overlap ? { overlap: overlapSaid.overlap.kind, overlap_why: overlapSaid.overlap.why } : {}),
        ...(!take && input.take === true && overlaps.length ? { covered_by: overlaps.map((o) => o.lead) } : {}),
        ...(objects.length ? { objects } : {}),
        ...(inputs.refs.length ? { inputs: inputs.refs } : {}),
        ...(nextAction.value ? { next_action: nextAction.value } : {}),
        ...(cons ? { consumer: cons.id } : {}),
      };
      const append: LeadDraft[] = [open];
      if (cons && consumerNeed) append.push({ by: ctx.agentId, ev: "link", lead: cons.id, add: [consumerNeed], why: `prerequisite ${id} opened for it` });
      // Ready, unheld, and not a second route left for its opener: offered
      // to the seat idle longest, which has first claim for a while (A3).
      let woke: string | undefined;
      if (!take && input.take !== true && !needs.needs.some((n) => !needState(n, snap.state, snap.ledger).met)) {
        const idle = await idleSeats(ctx.sandboxRoot, snap.state, snap.ledger, snap.jobs, snap.at, snap.questions);
        const pick = idle.find((x) => x.agent !== ctx.agentId);
        if (pick) {
          woke = pick.agent;
          append.push(offerDraft(id, pick.agent, "wake", 1, 0, snap.at));
        }
      }
      return { append, result: { ok: true as const, id, woke, ...(warning ? { warning } : {}), ...(coverage ? { coverage } : {}) } };
    });
    if (!r.ok) return r;
    const snap = await leadsSnapshot(ctx.sandboxRoot);
    return {
      ok: true,
      lead: viewLead(snap.state.leads.get(r.id)!, snap),
      ...(r.woke ? { woke: r.woke, offered_to: r.woke } : {}),
      ...(r.warning ? { warning: r.warning } : {}),
      ...(r.coverage ? { coverage: r.coverage } : {}),
      ...(admission ? { admission } : {}),
      ...(consumer ? { consumer: consumer.id } : {}),
    };
  } catch (err) {
    return { ok: false, reason: (err as Error).message };
  }
}

/** What the harness offers when it offers a source's broad extraction (extensions/preparation.ts, scripts/preparation.ts). */
export type PreparationOffer = LeadPreparation & { name: string; version: string; description: string; exclusions: string[] };

/** A preparation lead's title: the recipe and the source, within the title's bound (the source is named whole in why, routes and objects). */
function preparationTitle(p: PreparationOffer): string {
  const t = `Broad extraction: ${p.recipe} over ${p.name}`;
  return t.length <= LEAD_TITLE_MAX ? t : `Broad extraction: ${p.recipe} over one source (named in why)`;
}

/**
 * The harness offers a source's broad extraction as a lead (docs/adr/0013,
 * "A source's broad extraction before a negative on it"): opened by
 * `system`, unheld, serving no question and not material (it holds the
 * finish line only through the negatives that rest on its source), with the
 * route {source, recipe} and the source among its objects, and offered to
 * the seat idle longest, as a lead nobody holds is (A3). One per source
 * digest and capability: an open lead of the same preparation, or a closed
 * one, is answered with, never a second. A seat takes it and runs the
 * recipe (catalog_request), or closes it deferred or infeasible citing a
 * limitation that says why it is not run, which is the preparation's
 * decline.
 */
export async function openPreparationLead(sandboxRoot: string, p: PreparationOffer, now = Date.now()): Promise<LeadResult<{ id: string; already?: true; offered_to?: string }>> {
  try {
    const r = await transact<{ ok: true; id: string; already?: true; offered_to?: string }>(sandboxRoot, async (snap) => {
      const same = [...snap.state.leads.values()].find((l) => l.preparation?.sha256 === p.sha256 && l.preparation.capability === p.capability);
      if (same) return { append: [], result: { ok: true as const, id: same.id, already: true as const } };
      const id = `L-${snap.state.leads.size + 1}`;
      const target = p.ref || `sha256:${p.sha256}`;
      const append: LeadDraft[] = [
        {
          by: "system",
          ev: "open",
          lead: id,
          title: preparationTitle(p),
          why: `${p.description} A broad extraction of ${p.name} (sha256 ${p.sha256}), declared by its pack as ${p.recipe} ${p.version} (capability ${p.capability}); it does not hold: ${p.exclusions.join("; ") || "nothing said"}. A negative that says an event did not happen on this source, or whose coverage is complete over it, is held (preparation_pending) until this extraction is produced, partial, failed or declined.`,
          origin: "a broad extraction offered by the harness",
          needs: [],
          answers: [],
          material: false,
          generation: 0,
          routes: [{ source: target, method: `recipe ${p.recipe}` }],
          objects: [target],
          next_action: `catalog_request target=${target} recipe=${p.recipe}; or, if it should not be run, close ${id} deferred or infeasible citing a limitation that says why`,
          preparation: { sha256: p.sha256, ref: p.ref, capability: p.capability, recipe: p.recipe },
        },
      ];
      // Offered to the seat idle longest now, if one waits; otherwise to the first that does (electOffer).
      const idle = await idleSeats(sandboxRoot, snap.state, snap.ledger, snap.jobs, now, snap.questions).catch(() => [] as Array<{ agent: string; since: number }>);
      const pick = idle[0]?.agent;
      if (pick) append.push(offerDraft(id, pick, "wake", 1, 0, now));
      return { append, result: { ok: true as const, id, ...(pick ? { offered_to: pick } : {}) } };
    });
    return r;
  } catch (err) {
    return { ok: false, reason: (err as Error).message };
  }
}

/**
 * A preparation lead whose extraction reached an outcome by any route (the
 * lane ran it, a seat ran it under the lead or without it, it was declined)
 * is closed by the harness, withdrawn: what it offered needs nothing more.
 * The close cites the receipt in words (`ref`) and says why; a lead already
 * closed is left as it is, and so is one a seat holds: the harness closes
 * its own preparation leads only, never one under a seat's hand (the Fable
 * review of the limits branch, P3-3).
 */
export async function closePreparationLead(sandboxRoot: string, lead: string, ref: string, why: string): Promise<LeadResult<{ closed: boolean }>> {
  try {
    return await transact<{ ok: true; closed: boolean }>(sandboxRoot, async (snap) => {
      const l = snap.state.leads.get(lead);
      if (!l?.preparation || l.closed || l.holder) return { append: [], result: { ok: true as const, closed: false } };
      return { append: [{ by: "system", ev: "close", lead: l.id, generation: l.generation, disposition: "withdrawn", ref, why }], result: { ok: true as const, closed: true } };
    });
  } catch (err) {
    return { ok: false, reason: (err as Error).message };
  }
}

function leadRef(raw: unknown): { ok: true; id: string } | { ok: false; reason: string } {
  const text = String(raw ?? "").trim().toUpperCase();
  const m = LEAD_ID.exec(text);
  if (!m) return { ok: false, reason: `a lead is named L-<n> (got ${JSON.stringify(raw)})` };
  return { ok: true, id: `L-${Number(m[1])}` };
}

/** A claim's framing: what an unframed directive under a person's question is taken to test (the first agent to work it says). */
export type LeadClaimInput = { proposition?: string; negation?: string; routes?: unknown; overlap?: string; overlap_why?: string };

/**
 * Claim a lead: atomically, with a new generation. A lead someone else holds
 * is theirs until they release it or show as stale; a stale holder is marked
 * first (and told, through their header and wait), and the lead may be taken
 * only once that mark has stood reclaimGraceMs(). A turn error frees
 * nothing by itself.
 *
 * A directive (the operator's lead, which carries a product, not a
 * hypothesis) under a person's question that no lead has framed yet is the
 * first agent work on that question: its first claim states the
 * proposition and its negation, kept on the claim, as the first agent lead
 * under the question would have.
 */
export async function claimLead(ctx: P.SwarmContext, rawId: unknown, input: LeadClaimInput = {}, now = Date.now()): Promise<LeadResult<{ lead: LeadView; reclaimed_from?: string; already?: true; kept?: true; coverage?: OpenCoverage; admission?: FirstChoiceAdmission }>> {
  const ref = leadRef(rawId);
  if (!ref.ok) return ref;
  const overlapSaid = checkOverlap(input?.overlap, input?.overlap_why);
  if (!overlapSaid.ok) return overlapSaid;
  const admission = ctx.agentId !== "operator" ? await admitFirstChoice(ctx.sandboxRoot, ctx.agentId).catch(() => null) : null;
  if (admission) now = Math.max(now, Date.now());
  const proposition = bounded("proposition", input?.proposition, LEAD_WHY_MAX, false);
  if (!proposition.ok) return proposition;
  const negation = bounded("negation", input?.negation, LEAD_WHY_MAX, false);
  if (!negation.ok) return negation;
  if (Boolean(proposition.value) !== Boolean(negation.value)) return { ok: false, reason: "proposition and negation come together: the proposition the lead tests, and what would hold if it is false" };
  const routes = checkRoutes(input?.routes);
  if (!routes.ok) return routes;
  try {
    const r = await transact<Fail | { ok: true; already?: true; kept?: true; from?: string; coverage?: OpenCoverage }>(ctx.sandboxRoot, async (snap) => {
      const l = snap.state.leads.get(ref.id);
      if (!l) return { append: [], result: { ok: false as const, reason: `${ref.id} does not exist` } };
      if (l.closed) return { append: [], result: { ok: false as const, reason: `${l.id} is closed (${l.closed.disposition}${l.closed.ref ? `, ${l.closed.ref}` : ""}, by ${l.closed.by}); open a new lead for new work, or reopen it with lead_reopen (the revision you read, and why)` } };
      const offer = O.reservingOffer(l.offers, now, l.rev);
      if (l.holder === ctx.agentId) {
        // The holder acts on a parked lead, or one offered away from it: it keeps it (A2), and the offer ends.
        const parkedAway = offer?.reason === "parked" && offer.to !== ctx.agentId;
        const parked = parkedAway || now - lastLeadAct(l, snap.state) >= parkMs();
        if (parked) return { append: [{ by: ctx.agentId, ev: "keep", lead: l.id, generation: l.generation, why: parkedAway ? `kept by its holder before the offer to ${offer!.to} was taken` : "kept by its holder" }], result: { ok: true as const, kept: true as const } };
        return { append: [], result: { ok: true as const, already: true as const } };
      }
      // An offer holds it for its seat (A3): nobody else claims it meanwhile.
      if (offer && offer.to !== ctx.agentId) {
        return { append: [], result: { ok: false as const, reason: `${l.id} is offered to ${offer.to} (${offer.reason === "parked" ? `parked in ${offer.from ?? l.holder}'s hands` : offer.reason === "handoff" ? `handed over by ${offer.from ?? "its holder"}` : offer.reason === "reopen" ? "reopened after the operator's note, to its previous holder first" : offer.reason === "confirm" ? "its closure to confirm" : "woken for it"}), who has first claim ${O.untilWords(offer, now, l.rev)}: claim it after that, or post to ${offer.to}` } };
      }
      const byOffer = offer && offer.to === ctx.agentId ? { offer: offer.seq } : {};
      // A person's question this lead serves, offered to another seat: its first claim holds here too (A3).
      if (!("offer" in byOffer)) {
        const qres = await questionReservation(snap, l.answers, ctx.agentId, now);
        if (qres) return { append: [], result: { ok: false as const, reason: `${l.id} serves ${qres.q.id}, which is offered to ${qres.o.to}, who has first claim on its work ${O.untilWords(qres.o, now, qres.q.rev)}: claim ${l.id} after that, or post to ${qres.o.to}` } };
      }
      // The coverage check (A1), at a claim too: another seat's held lead on
      // the same questions leaves this one unheld unless the claim says it is
      // a second route or a verification.
      const overlaps = !l.holder ? overlappingLeads(snap, l.answers, ctx.agentId, l.id) : [];
      if (overlaps.length && !overlapSaid.overlap) {
        return {
          append: [],
          result: {
            ok: false as const,
            reason: `${overlaps.map((o) => `question:${o.answers.join(", question:")} is covered by ${o.lead} (${o.holder}${o.since ? `, since ${o.since}` : ""})`).join("; ")}: claim ${l.id} only as a second route or a verification, saying so (overlap: second_route or verification, overlap_why: how your route differs), or post to the holder`,
          },
        };
      }
      const overlapFields = overlaps.length && overlapSaid.overlap ? { overlap: overlapSaid.overlap.kind, overlap_why: overlapSaid.overlap.why } : {};
      const coverage: OpenCoverage | undefined = overlaps.length ? { held: true, overlaps, objects: [], why: `held as ${overlapSaid.overlap!.kind}: ${overlapSaid.overlap!.why}` } : undefined;
      // An unframed directive under a person's question: framed by its first claim.
      const framing = await directiveFraming(ctx.sandboxRoot, l, snap);
      if (framing && !proposition.value) {
        return { append: [], result: { ok: false as const, reason: `${l.id} is a directive under ${framing.id}, a person's question no lead has framed yet: the first agent to work it tests it, never confirms it. Claim it with proposition (what the work tests) and negation (what would hold if it is false)${framing.planless ? ", and routes [{source, method}] (a route that could disconfirm it)" : ""}` } };
      }
      if (framing?.planless && !routes.routes.length) return { append: [], result: { ok: false as const, reason: `${framing.id} has no route plan yet: give routes [{source, method}] with the claim, one of them able to disconfirm the proposition` } };
      if (!framing && (proposition.value || routes.routes.length) && l.proposition) return { append: [], result: { ok: false as const, reason: `${l.id} is framed already (tests: ${l.proposition}); claim it without proposition, and add routes with lead_link` } };
      const frame = { ...(proposition.value ? { proposition: proposition.value, negation: negation.value } : {}), ...(routes.routes.length ? { routes: routes.routes } : {}) };
      if (!l.holder) return { append: [{ by: ctx.agentId, ev: "claim", lead: l.id, holder: ctx.agentId, generation: l.generation + 1, ...frame, ...byOffer, ...overlapFields }], result: { ok: true as const, ...(coverage ? { coverage } : {}) } };
      // A parked lead offered to this seat: taken over without the stale grace, the holder having had its chance to act.
      if (offer && offer.to === ctx.agentId && offer.reason === "parked") {
        return { append: [{ by: ctx.agentId, ev: "claim", lead: l.id, holder: ctx.agentId, generation: l.generation + 1, from: l.holder, cause: "parked", ...frame, ...byOffer }], result: { ok: true as const, from: l.holder } };
      }
      // Held by a peer: only a stale holder gives it up, and only after being marked.
      const lastAct = Math.max(0, ...snap.state.events.filter((e) => e.by === l.holder && e.ev !== "stale").map((e) => Date.parse(e.at)).filter(Number.isFinite));
      const live = await holderLiveness(ctx.sandboxRoot, l.holder, snap.jobs, undefined, now, lastAct);
      if (!live.stale) {
        return { append: [], result: { ok: false as const, reason: `${l.id} is held by ${l.holder} (generation ${l.generation}, since ${l.held_since}): ${live.why}. Post to ${l.holder}, or open a lead for your own part of it` } };
      }
      if (!l.stale || l.stale.holder !== l.holder || l.stale.generation !== l.generation) {
        const mark = { by: ctx.agentId, ev: "stale" as const, lead: l.id, holder: l.holder, generation: l.generation, idle_seconds: live.idle_seconds, last_activity: live.last_activity };
        return { append: [mark], result: { ok: false as const, reason: `${l.id}'s holder ${l.holder} shows as stale (${live.why}). It is marked stale now and ${l.holder} is told; claim it again in ${Math.round(reclaimGraceMs() / 1000)} s to take it over if ${l.holder} has not answered` } };
      }
      const since = now - Date.parse(l.stale.at);
      if (since < reclaimGraceMs()) {
        return { append: [], result: { ok: false as const, reason: `${l.id} was marked stale ${Math.round(since / 1000)} s ago; ${l.holder} has ${Math.round((reclaimGraceMs() - since) / 1000)} s more to answer before it can be taken over` } };
      }
      return { append: [{ by: ctx.agentId, ev: "claim", lead: l.id, holder: ctx.agentId, generation: l.generation + 1, from: l.holder, ...frame }], result: { ok: true as const, from: l.holder } };
    });
    if (!r.ok) return r;
    const snap = await leadsSnapshot(ctx.sandboxRoot);
    return {
      ok: true,
      lead: viewLead(snap.state.leads.get(ref.id)!, snap),
      ...("from" in r && r.from ? { reclaimed_from: r.from } : {}),
      ...("already" in r && r.already ? { already: true as const } : {}),
      ...("kept" in r && r.kept ? { kept: true as const } : {}),
      ...("coverage" in r && r.coverage ? { coverage: r.coverage } : {}),
      ...(admission ? { admission } : {}),
    };
  } catch (err) {
    return { ok: false, reason: (err as Error).message };
  }
}

/**
 * Whether claiming this lead is the first agent work on a person's question
 * nobody has framed: a directive (opened by the operator, with no
 * proposition) under such a question, when no lead under it states one.
 * Which question, and whether it has no route plan yet either.
 */
async function directiveFraming(sandboxRoot: string, l: Lead, snap: LeadsSnapshot): Promise<{ id: string; planless: boolean } | null> {
  if (l.opened_by !== "operator" || l.proposition) return null;
  const Q = await import("./questions.ts");
  const qs = snap.questions ?? (await Q.questionsSnapshot(sandboxRoot));
  for (const section of l.answers) {
    const q = qs.bySection.get(section);
    if (!q || !Q.HUMAN_ORIGINS.has(q.origin.kind)) continue;
    const framed = [...snap.state.leads.values()].some((x) => x.proposition && x.answers.includes(section));
    if (!framed) return { id: q.id, planless: !questionRoutes(snap.state, section).length };
  }
  return null;
}

function holderOnly(l: Lead, ctx: P.SwarmContext, generation: unknown, verb: string): string | null {
  if (l.holder !== ctx.agentId) return l.holder ? `${l.id} is held by ${l.holder} (generation ${l.generation}); only its holder can ${verb} it` : `${l.id} is not held by you (nobody holds it); claim it first`;
  if (generation !== undefined && generation !== null && Number(generation) !== l.generation) return `${l.id} is at generation ${l.generation}, not ${generation}: it changed hands since you last held it`;
  return null;
}

export async function releaseLead(ctx: P.SwarmContext, rawId: unknown, input: { why?: string; generation?: number } = {}): Promise<LeadResult<{ lead: LeadView }>> {
  const ref = leadRef(rawId);
  if (!ref.ok) return ref;
  const why = bounded("why", input.why, LEAD_WHY_MAX, false);
  if (!why.ok) return why;
  try {
    const r = await transact<Fail | { ok: true }>(ctx.sandboxRoot, async (snap) => {
      const l = snap.state.leads.get(ref.id);
      if (!l) return { append: [], result: { ok: false as const, reason: `${ref.id} does not exist` } };
      if (l.closed) return { append: [], result: { ok: false as const, reason: `${l.id} is closed; there is nothing to release` } };
      const refused = holderOnly(l, ctx, input.generation, "release");
      if (refused) return { append: [], result: { ok: false as const, reason: refused } };
      return { append: [{ by: ctx.agentId, ev: "release", lead: l.id, generation: l.generation, ...(why.value ? { why: why.value } : {}) }], result: { ok: true as const } };
    });
    if (!r.ok) return r;
    const snap = await leadsSnapshot(ctx.sandboxRoot);
    return { ok: true, lead: viewLead(snap.state.leads.get(ref.id)!, snap) };
  } catch (err) {
    return { ok: false, reason: (err as Error).message };
  }
}

/**
 * The answers check's warnings a close or a confirmation changed, for its
 * reply (finish.ts warningsAt, lead_close): what it recorded under the lead
 * (its ref, its results) can leave a question's answer short of an entry
 * the lead now holds. Nothing when it changed none, or when they cannot be
 * read: a warning never fails the act.
 */
async function closeWarnings(sandboxRoot: string, events: readonly LeadEvent[]): Promise<P.WarningsDelivered> {
  const seqs = events.filter((e) => e.ev === "close" || e.ev === "confirm").map((e) => e.seq);
  if (!seqs.length) return {};
  try {
    const F = await import("./finish.ts");
    const ws = await F.warningsAt(sandboxRoot, { point: "lead_close", events: seqs });
    return ws.length ? { warnings: ws.map(P.warningWords), warned: [...new Set(ws.map((w) => w.code))] } : {};
  } catch {
    return {};
  }
}

/** What a disposition's ref must be, checked against the ledger and the register. */
function checkRef(disposition: LeadDisposition, raw: string, l: Lead, snap: LeadsSnapshot): { ok: true; ref: string } | { ok: false; reason: string } {
  const text = raw.trim();
  if (disposition === "needs_operator") {
    if (text.length < 10) return { ok: false, reason: "needs_operator says in ref what only the operator can do: the host to allow, the file to add, or the question to answer, and why" };
    return { ok: true, ref: text };
  }
  if (disposition === "duplicate") {
    const d = leadRef(text);
    if (!d.ok) return { ok: false, reason: "duplicate cites the lead it repeats: ref L-<n>" };
    if (d.id === l.id) return { ok: false, reason: "a lead is not a duplicate of itself" };
    const other = snap.state.leads.get(d.id);
    if (!other) return { ok: false, reason: `${d.id} does not exist` };
    if (other.closed?.disposition === "duplicate" && other.closed.ref === l.id) return { ok: false, reason: `${d.id} is already closed as a duplicate of ${l.id}: one of the two carries the work` };
    return { ok: true, ref: d.id };
  }
  const m = /^E-([1-9]\d{0,5})$/i.exec(text);
  if (!m) return { ok: false, reason: `${disposition} cites a ledger entry: ref E-<seq> (${disposition === "resolved" ? "the entry that settles it" : disposition === "negative" ? "the absence: the search that found nothing" : disposition === "deferred" ? "the limitation that says why it waits" : "the limitation naming the methods tried and why none worked"})` };
  const seq = Number(m[1]);
  const st = entryStands(snap.ledger, seq);
  if (!st.ok) return { ok: false, reason: `${st.why}: cite an entry that stands` };
  const want: Record<string, string[]> = { negative: ["absence"], deferred: ["limitation"], infeasible: ["limitation"] };
  if (want[disposition] && !want[disposition].includes(st.kind)) return { ok: false, reason: `${disposition} cites ${want[disposition].join(" or ")} (E-${seq} is ${st.kind})` };
  if (disposition === "resolved" && st.kind === "limitation") return { ok: false, reason: `a limitation does not resolve a lead: close it deferred or infeasible citing E-${seq}` };
  if (disposition === "resolved" && st.kind === "hypothesis") return { ok: false, reason: `a hypothesis does not resolve a lead: record what settled it, and cite that` };
  return { ok: true, ref: `E-${seq}` };
}

/**
 * Close a lead with its disposition and what it cites. The holder closes its
 * own; an unheld lead can be closed by anyone (a duplicate found, a search
 * already recorded), and the record says who. A lead closed needs_operator
 * is a request of the operator: committed on the close (with its `ask` when
 * it asks for evidence), then written to the outbox (extensions/requests.ts)
 * with a durable id. A write that fails is not swallowed: the answer says the
 * request is pending, and the next reconciliation writes it.
 */
export async function closeLead(ctx: P.SwarmContext, rawId: unknown, input: { disposition?: string; ref?: string; why?: string; generation?: number; ask?: unknown; result_refs?: string[] | string }): Promise<LeadResult<{ lead: LeadView; operator_request?: string; request?: { id: string; kind: string; state: string; stage: string | null; answer: string | null }; request_pending?: string; hint?: string; guidance?: string } & P.WarningsDelivered>> {
  const ref = leadRef(rawId);
  if (!ref.ok) return ref;
  const disposition = String(input.disposition ?? "").trim().toLowerCase() as LeadDisposition;
  if (!(LEAD_DISPOSITIONS as readonly string[]).includes(disposition)) return { ok: false, reason: `disposition is one of ${LEAD_DISPOSITIONS.filter((d) => d !== "withdrawn").join(", ")}` };
  if (disposition === "withdrawn") return { ok: false, reason: "withdrawn is the harness's: a lead closes withdrawn when every question it serves is withdrawn by whoever asked it" };
  const refText = bounded("ref", input.ref, LEAD_REF_MAX, true);
  if (!refText.ok) return refText;
  const why = bounded("why", input.why, LEAD_WHY_MAX, false);
  if (!why.ok) return why;
  if (input.ask !== undefined && input.ask !== null && disposition !== "needs_operator") return { ok: false, reason: "ask goes with needs_operator: an acquisition is a request of the operator" };
  const R = await import("./requests.ts");
  // The delivered product (A2): what a consumer reads, each ref checked.
  const results = await checkRefList(ctx.sandboxRoot, "result_refs", input.result_refs);
  if (!results.ok) return results;
  try {
    const r = await transact<Fail | { ok: true }>(ctx.sandboxRoot, async (snap) => {
      const l = snap.state.leads.get(ref.id);
      if (!l) return { append: [], result: { ok: false as const, reason: `${ref.id} does not exist` } };
      if (l.closed) return { append: [], result: { ok: false as const, reason: `${l.id} is already closed (${l.closed.disposition}, by ${l.closed.by})` } };
      const asked = R.checkAsk(input.ask, l.answers.map((a) => (/^\d+$/.test(a) ? `Q-${a}` : a)));
      if (!asked.ok) return { append: [], result: { ok: false as const, reason: asked.reason } };
      for (const e of results.refs.filter((x) => /^E-\d+$/.test(x))) {
        const st = entryStands(snap.ledger, Number(e.slice(2)));
        if (!st.ok) return { append: [], result: { ok: false as const, reason: `result_refs: ${st.why}: name what stands` } };
      }
      if (l.holder) {
        const refused = holderOnly(l, ctx, input.generation, "close");
        if (refused) return { append: [], result: { ok: false as const, reason: refused } };
      }
      const checked = checkRef(disposition, refText.value, l, snap);
      if (!checked.ok) return { append: [], result: { ok: false as const, reason: checked.reason } };
      // A negative closes against the plan: the planned routes of its
      // questions nothing examined are named on the close, and a material
      // lead under a material question with no plan is refused.
      const negative = disposition === "negative" ? await negativeClose(ctx.sandboxRoot, l, snap) : null;
      if (negative && !negative.ok) return { append: [], result: { ok: false as const, reason: negative.reason } };
      const extra = negative?.ok ? { ...(negative.not_examined.length ? { not_examined: negative.not_examined } : {}), ...(negative.quick ? { quick_negative: negative.quick } : {}) } : {};
      return { append: [{ by: ctx.agentId, ev: "close", lead: l.id, generation: l.generation, disposition, ref: checked.ref, ...(why.value ? { why: why.value } : {}), ...(asked.ask ? { ask: asked.ask } : {}), ...(results.refs.length ? { result_refs: results.refs } : {}), ...extra }], result: { ok: true as const } };
    });
    if (!r.ok) return r;
    const snap = await leadsSnapshot(ctx.sandboxRoot);
    const view = viewLead(snap.state.leads.get(ref.id)!, snap);
    // The warnings the close changed, on the questions the lead serves (never a refusal).
    const warned = await closeWarnings(ctx.sandboxRoot, r.events);
    if (disposition !== "needs_operator") return { ok: true, lead: view, ...warned };
    const hinted = await dispositionAskHint(ctx.sandboxRoot, `${refText.value}\n${why.value ?? ""}`).catch(() => null);
    const guided = input.ask === undefined || input.ask === null ? operatorQuestionGuidance(snap.state.leads.get(ref.id)!.answers) : null;
    const hint = { ...(hinted ? { hint: hinted } : {}), ...(guided ? { guidance: guided } : {}), ...warned };
    // The close is the commit; the request is written from it, once, by its key.
    const closeSeq = r.events.find((e) => e.ev === "close")?.seq;
    try {
      await R.reconcileRequests(ctx.sandboxRoot);
      const rs = await R.requestsSnapshot(ctx.sandboxRoot);
      const rid = closeSeq ? rs.byKey.get(`lead:${ref.id}:${closeSeq}`) : undefined;
      const req = rid ? rs.requests.get(rid) : undefined;
      if (!req) return { ok: true, lead: view, request_pending: `the request is committed on ${ref.id}'s close and is written to the operator's requests at the next reconciliation`, ...hint };
      return {
        ok: true,
        lead: view,
        operator_request: String(req.line.answer ?? ""),
        request: { id: req.rid, kind: req.kind, state: req.state, stage: req.stage, answer: req.closed ? req.closed.text : null },
        ...hint,
      };
    } catch (err) {
      // Not swallowed: said to the agent, on the trace with its answer, and made good at the next reconciliation.
      return { ok: true, lead: view, request_pending: `the request is committed on ${ref.id}'s close and could not be written to the operator's requests yet (${(err as Error).message}); the next reconciliation writes it`, ...hint };
    }
  } catch (err) {
    return { ok: false, reason: (err as Error).message };
  }
}

/**
 * What a question put to the operator says, in the reply to every
 * needs_operator close that is not an acquisition (request guidance): the
 * observation that would settle the lead's questions, and what each
 * possible answer changes, so the answer can be acted on when it comes.
 * Guidance, never a refusal: whether the ref is a question is in its words,
 * which the harness does not read. Null for a lead that serves no question.
 */
export function operatorQuestionGuidance(answers: readonly string[]): string | null {
  const qs = [...new Set(answers.map((a) => (/^\d+$/.test(a) ? `Q-${a}` : a)))];
  if (!qs.length) return null;
  return `a question put to the operator says what observation would settle ${qs.join(", ")}, and what each possible answer changes (which answer, and to which result), so the answer can be acted on when it comes; a host to allow or a file to add says what it would establish`;
}

/**
 * A needs_operator close that asks the operator to accept or reject
 * dispositions, made before any done was refused on something only the
 * operator can release: said in the reply, never refused. In a real run
 * seats asked twice for the operator to rule on examination-limited
 * dispositions before any done, and a note answer settled nothing. Whether
 * they suffice is what done asks the finish line; the operator's acceptance
 * is for a question the finish line holds.
 */
async function dispositionAskHint(sandboxRoot: string, text: string): Promise<string | null> {
  if (!/\b(accept|reject|approv|ratif|rule on|sign[\s-]?off)/i.test(text) || !/\bdispositions?\b|examination[\s-]limited/i.test(text)) return null;
  const F = await import("./finish.ts");
  const st = await F.readFinish(sandboxRoot);
  // A done refused on a question with no disposition names what the operator may accept: then the ask may be the operator's.
  if (st.checks.some((c) => !c.proceed && /accepted by the operator|the operator accepts/i.test(c.reason ?? ""))) return null;
  return "no done has been refused on anything only the operator can release: whether examination-limited dispositions suffice is what done asks the finish line, and a question disposed under the bar needs nobody's acceptance. The coordinator calls done first; ask the operator only for what a refused done names as the operator's (a question it holds, which the operator accepts with swarm.sh question <run> accept Q-n). The close stands, and so does its request";
}

/**
 * What a negative close says of itself, computed by the hub: the planned
 * routes of the questions the lead serves that no job under them declared
 * and no coverage record names (each with why), and whether it was a quick
 * negative (held NB.QUICK_NEGATIVE_HELD_MS or less, one job at most, one
 * object at most): a review cue, never a refusal. A material lead under a
 * material question with no route plan is refused: the negative would close
 * against nothing.
 */
async function negativeClose(sandboxRoot: string, l: Lead, snap: LeadsSnapshot): Promise<{ ok: true; not_examined: Array<{ source: string; method: string; why: string }>; quick: { held_ms: number; jobs: number; objects: number } | null } | Fail> {
  const routes: NB.Route[] = [];
  const jobs = new Set<string>();
  for (const section of l.answers) {
    for (const r of questionRoutes(snap.state, section)) if (!routes.some((x) => x.source === r.source && x.method === r.method)) routes.push(r);
    for (const o of snap.state.leads.values()) if (o.answers.includes(section)) for (const j of o.jobs) jobs.add(j);
    if (!questionRoutes(snap.state, section).length && l.material) {
      const q = snap.questions?.bySection.get(section);
      const material = snap.goal.questions.includes(section) || !q || q.materiality === "material";
      if (material) return { ok: false, reason: `${l.id} serves question:${section}, a material question with no route plan: a negative closes against the sources and methods planned before the search. Give the lead its routes (lead_link ${l.id} routes [{source, method}]), then close it` };
    }
  }
  for (const j of l.jobs) jobs.add(j);
  const coverageObjects = snap.ledger.entries.filter((e) => e.kind === "coverage" && !snap.ledger.replaced.has(e.seq) && (e.answers ?? []).some((a) => l.answers.includes(P.sectionKey(a)))).flatMap((e) => e.refs ?? []);
  const notExamined: Array<{ source: string; method: string; why: string }> = [];
  for (const r of routes) {
    const ex = await NB.routeExamined(sandboxRoot, r, { jobs: [...jobs], objects: coverageObjects });
    if (!ex.examined) notExamined.push({ source: r.source, method: r.method, why: ex.how });
  }
  // Held from its first holder to now; its jobs and the objects they declared.
  const first = snap.state.events.find((e) => e.lead === l.id && ((e.ev === "open" && e.holder) || e.ev === "claim"));
  const heldMs = first ? Math.max(0, Date.now() - Date.parse(first.at)) : 0;
  const objects = new Set<string>();
  // A job that read everything (scope all, or none said) is not a search over one object.
  let everything = false;
  for (const j of l.jobs) {
    const d = await NB.jobDeclared(sandboxRoot, j);
    if (!d) continue;
    if (d.scope !== "declared") everything = true;
    for (const x of d.inputs) objects.add(x);
  }
  const quick = heldMs <= NB.QUICK_NEGATIVE_HELD_MS && l.jobs.length <= 1 && objects.size <= 1 && !everything ? { held_ms: heldMs, jobs: l.jobs.length, objects: objects.size } : null;
  return { ok: true, not_examined: notExamined, quick };
}

/**
 * Revise a lead's needs: add a route, or drop one that will not come, so an
 * alternative stays open. The holder revises its own lead; an unheld one,
 * anyone. A loop is refused.
 */
export async function linkLead(ctx: P.SwarmContext, rawId: unknown, input: { add?: string[] | string; remove?: string[] | string; routes?: unknown; why?: string }): Promise<LeadResult<{ lead: LeadView }>> {
  const ref = leadRef(rawId);
  if (!ref.ok) return ref;
  const routes = checkRoutes(input.routes);
  if (!routes.ok) return routes;
  const why = bounded("why", input.why, LEAD_WHY_MAX, false);
  if (!why.ok) return why;
  // A need dropped is withdrawn, never met (A2): it says why.
  if (listOf(input.remove).length && !why.value) return { ok: false, reason: "why is required with remove: a dropped need is recorded as withdrawn, with its reason, never as met (what will not come, and what the lead goes on without)" };
  try {
    const r = await transact<Fail | { ok: true }>(ctx.sandboxRoot, async (snap) => {
      const l = snap.state.leads.get(ref.id);
      if (!l) return { append: [], result: { ok: false as const, reason: `${ref.id} does not exist` } };
      if (l.closed) return { append: [], result: { ok: false as const, reason: `${l.id} is closed` } };
      if (l.holder && l.holder !== ctx.agentId) return { append: [], result: { ok: false as const, reason: `${l.id} is held by ${l.holder}; its needs are its holder's to revise` } };
      const add = checkNeeds(input.add, snap.state, snap.ledger, l.id);
      if (!add.ok) return { append: [], result: { ok: false as const, reason: add.reason } };
      const remove: string[] = [];
      for (const n of listOf(input.remove)) {
        const p = parseNeed(n);
        if (!p.ok) return { append: [], result: { ok: false as const, reason: p.reason } };
        if (!l.needs.includes(p.need)) return { append: [], result: { ok: false as const, reason: `${l.id} does not need ${p.need} (its needs: ${l.needs.join(", ") || "none"})` } };
        remove.push(p.need);
      }
      const fresh = add.needs.filter((n) => !l.needs.includes(n));
      const newRoutes = routes.routes.filter((r) => !l.routes.some((x) => x.source === r.source && x.method === r.method));
      if (!fresh.length && !remove.length && !newRoutes.length) return { append: [], result: { ok: false as const, reason: "give add, remove, routes, or more than one: a need to add that it does not have, one it has to drop, or a route it does not plan yet" } };
      if (l.needs.length - remove.length + fresh.length > LEAD_MAX_NEEDS) return { append: [], result: { ok: false as const, reason: `a lead names at most ${LEAD_MAX_NEEDS} needs` } };
      if (l.routes.length + newRoutes.length > NB.MAX_ROUTES) return { append: [], result: { ok: false as const, reason: `a lead plans at most ${NB.MAX_ROUTES} routes` } };
      const append: Array<Omit<LeadEvent, "v" | "seq" | "at" | "prev" | "hash">> = [];
      if (fresh.length || remove.length) append.push({ by: ctx.agentId, ev: "link", lead: l.id, ...(fresh.length ? { add: fresh } : {}), ...(remove.length ? { remove, why: why.value } : {}) });
      if (newRoutes.length) append.push({ by: ctx.agentId, ev: "route", lead: l.id, routes: newRoutes });
      return { append, result: { ok: true as const } };
    });
    if (!r.ok) return r;
    const snap = await leadsSnapshot(ctx.sandboxRoot);
    return { ok: true, lead: viewLead(snap.state.leads.get(ref.id)!, snap) };
  } catch (err) {
    return { ok: false, reason: (err as Error).message };
  }
}

/**
 * Reopen a closed lead. The operator does it after answering a request; the
 * harness does it when the entry a lead was closed on is superseded or
 * disputed (reopenOnLedger), since the closure no longer stands.
 */
export async function reopenLead(sandboxRoot: string, rawId: unknown, by: string, why: string, cause: string, o: { import?: string; closedBy?: number } = {}): Promise<LeadResult<{ lead: LeadView; already?: boolean }>> {
  const ref = leadRef(rawId);
  if (!ref.ok) return ref;
  const text = bounded("why", why, LEAD_WHY_MAX, true);
  if (!text.ok) return text;
  try {
    const r = await transact<Fail | { ok: true; already?: boolean }>(sandboxRoot, async (snap) => {
      const l = snap.state.leads.get(ref.id);
      if (!l) return { append: [], result: { ok: false as const, reason: `${ref.id} does not exist` } };
      // Once per import: a lead reopened for it already (and perhaps closed again since, knowing it) is not reopened again.
      if (o.import && l.reopened.some((x) => x.import === o.import)) return { append: [], result: { ok: true as const, already: true } };
      if (!l.closed) return { append: [], result: { ok: false as const, reason: `${l.id} is not closed` } };
      // Only a close made before the addition: one made after it was made knowing it.
      if (o.closedBy !== undefined && (l.closed.seq ?? 0) > o.closedBy) return { append: [], result: { ok: false as const, reason: `${l.id} was closed after the addition` } };
      return { append: [{ by, ev: "reopen", lead: l.id, why: text.value, cause, ...(o.import ? { import: o.import } : {}) }], result: { ok: true as const } };
    });
    if (!r.ok) return r;
    const snap = await leadsSnapshot(sandboxRoot);
    return { ok: true, lead: viewLead(snap.state.leads.get(ref.id)!, snap), ...(r.already ? { already: true } : {}) };
  } catch (err) {
    return { ok: false, reason: (err as Error).message };
  }
}

/** Who worked a lead last: its holder, or the seat that held it when it was closed or released. */
export function previousHolder(l: Lead, s: LeadsState): string | null {
  if (l.holder) return l.holder;
  for (let i = s.events.length - 1; i >= 0; i--) {
    const e = s.events[i]!;
    if (e.lead !== l.id) continue;
    if (e.ev === "claim") return e.holder ?? e.by;
    if (e.ev === "open" && e.holder) return e.holder;
  }
  return l.closed && l.closed.by !== "operator" && l.closed.by !== "system" ? l.closed.by : null;
}

/**
 * What keeps an agent from reopening a closed lead: the operator's
 * restrictions (a lead the operator closed, one closed withdrawn with its
 * question, one under a question withdrawn, excluded or waiting for triage,
 * one in the operator's triage, one closed needs_operator the operator has
 * not answered yet) and a duplicate of a lead that still carries the work.
 * Null when it may be reopened.
 */
async function reopenRefusal(sandboxRoot: string, l: Lead, snap: LeadsSnapshot): Promise<string | null> {
  if (!l.closed) return `${l.id} is not closed: claim it (lead_claim) to work it`;
  if (l.closed.by === "operator") return `${l.id} was closed by the operator: only the operator reopens it (swarm.sh lead <run> reopen)`;
  if (l.closed.disposition === "withdrawn" && l.preparation) return `${l.id} was closed by the harness once the broad extraction it offered reached an outcome (${l.closed.ref}): that outcome is on the store journal; to run ${l.preparation.recipe} again, catalog_request target=${l.preparation.ref || `sha256:${l.preparation.sha256}`} recipe=${l.preparation.recipe}`;
  if (l.closed.disposition === "withdrawn") return `${l.id} was closed withdrawn with the question it served: a withdrawn question is the asker's, and only the operator brings it back`;
  if (l.closed.disposition === "needs_operator") {
    const answered = l.notes.some((n) => Date.parse(n.at) >= Date.parse(l.closed!.at));
    if (!answered) return `${l.id} waits for the operator (${l.closed.ref}): the operator answers it and reopens it (swarm.sh lead <run> note); a reopen would not give what it asked for`;
  }
  if (l.closed.disposition === "duplicate") {
    const other = snap.state.leads.get(l.closed.ref);
    if (other && !other.closed) return `${l.id} is a duplicate of ${other.id}, which is still open${other.holder ? ` (held by ${other.holder})` : ""}: the work goes on there; claim ${other.id}, or post to its holder`;
  }
  const qs = snap.questions ?? (await import("./questions.ts").then((Q) => Q.questionsSnapshot(sandboxRoot)).catch(() => null));
  for (const section of l.answers) {
    const q = qs?.bySection.get(section);
    if (!q) continue;
    if (q.withdrawn) return `${l.id} serves ${q.id}, withdrawn by its asker: it is no lead's work`;
    if (q.scope === "excluded") return `${l.id} serves ${q.id}, excluded from the case by the operator (${q.scope_why})`;
    if (q.scope === "proposed") return `${l.id} serves ${q.id}, which waits for the operator's triage`;
  }
  if (qs?.state.triage.some((t) => t.lead === l.id && !t.resolved)) return `${l.id} is in the operator's triage: the operator decides whether it is the case's work`;
  return null;
}

/**
 * An agent reopens a closed lead (B4): with the revision it read, a reason,
 * and optionally taking it in the same step. History is kept (a reopen
 * event, cause agent); the previous holder and the leads that need it are
 * told as on any reopen. It never overrides an operator's restriction
 * (reopenRefusal) and never answers a dispute: a dispute in force stays in
 * force, and the reopen says so.
 */
export async function agentReopenLead(ctx: P.SwarmContext, rawId: unknown, input: { expected_revision?: unknown; why?: string; take?: boolean }): Promise<LeadResult<{ lead: LeadView; disputes?: string[] }>> {
  const ref = leadRef(rawId);
  if (!ref.ok) return ref;
  const why = bounded("why", input.why, LEAD_WHY_MAX, true);
  if (!why.ok) return why;
  if (input.take !== undefined && typeof input.take !== "boolean") return { ok: false, reason: "take is true or false" };
  const expected = Number(input.expected_revision);
  if (input.expected_revision === undefined || input.expected_revision === null || !Number.isInteger(expected) || expected < 1) return { ok: false, reason: "expected_revision is the lead's revision as you read it (leads L-<n> shows rev): a reopen names the state it saw" };
  try {
    const r = await transact<Fail | { ok: true; disputes: string[] }>(ctx.sandboxRoot, async (snap) => {
      const l = snap.state.leads.get(ref.id);
      if (!l) return { append: [], result: { ok: false as const, reason: `${ref.id} does not exist` } };
      if (l.rev !== expected) return { append: [], result: { ok: false as const, reason: `${l.id} is at revision ${l.rev}, not ${expected}: it changed since you read it (${l.closed ? `closed ${l.closed.disposition} by ${l.closed.by}` : l.holder ? `held by ${l.holder}` : "open"}); read it again (leads ${l.id})` } };
      const refused = await reopenRefusal(ctx.sandboxRoot, l, snap);
      if (refused) return { append: [], result: { ok: false as const, reason: refused } };
      // Taken in the same act: a person's question it serves, offered to another seat, is that seat's first (A3).
      if (input.take === true) {
        const qres = await questionReservation(snap, l.answers, ctx.agentId, Date.now());
        if (qres) return { append: [], result: { ok: false as const, reason: `${l.id} serves ${qres.q.id}, which is offered to ${qres.o.to}, who has first claim on its work ${O.untilWords(qres.o, Date.now(), qres.q.rev)}: reopen it without take, or post to ${qres.o.to}` } };
      }
      // A reopen answers no dispute: the ones in force on what the lead cites, or on its questions' answers, stay.
      const disputes = P.disputesInForce(snap.ledger.entries, await P.readDisputes(ctx.sandboxRoot).catch(() => [] as P.LedgerDispute[]));
      const cited = new Set<string>();
      const m = /^E-(\d+)$/.exec(l.closed!.ref);
      if (m) {
        const e = snap.ledger.bySeq.get(Number(m[1]));
        if (e) cited.add(e.hash ?? P.ledgerHash(e, "genesis"));
      }
      for (const a of snap.ledger.entries) if (a.kind === "answer" && !snap.ledger.replaced.has(a.seq) && l.answers.some((x) => a.section === `question:${x}`)) cited.add(a.hash ?? P.ledgerHash(a, "genesis"));
      const open = disputes.filter((d) => cited.has(d.target)).map((d) => `E-${snap.ledger.entries.find((e) => (e.hash ?? P.ledgerHash(e, "genesis")) === d.target)?.seq ?? "?"} disputed by ${P.disputeWords(d)}`);
      const append: LeadDraft[] = [{ by: ctx.agentId, ev: "reopen", lead: l.id, why: why.value, cause: "agent", expected_revision: expected }];
      if (input.take === true) append.push({ by: ctx.agentId, ev: "claim", lead: l.id, holder: ctx.agentId, generation: l.generation + 1 });
      return { append, result: { ok: true as const, disputes: open } };
    });
    if (!r.ok) return r;
    const snap = await leadsSnapshot(ctx.sandboxRoot);
    return { ok: true, lead: viewLead(snap.state.leads.get(ref.id)!, snap), ...(r.disputes.length ? { disputes: r.disputes.map((d) => `${d}: a reopen does not answer it; it stays in force until the disputer withdraws it`) } : {}) };
  } catch (err) {
    return { ok: false, reason: (err as Error).message };
  }
}

/**
 * Another seat's review of a limiting route (B3): a lead closed deferred,
 * infeasible or needs_operator, and whether its limitation is still
 * material now. A route lead stops holding the finish line only when its
 * questions are disposed under the bar and such a review says its
 * limitation is no longer material (or the operator accepted the
 * questions): never by itself, and never vacuously for a lead that names
 * no question. Bound to the close it reviews; a reopen or a new close
 * needs a new review. The seat that closed it, or held it, does not review
 * it.
 */
export async function routeReview(ctx: P.SwarmContext, rawId: unknown, input: { material?: unknown; why?: string; second_review_why?: string }): Promise<LeadResult<{ lead: LeadView; deferred?: ReviewDeferral }>> {
  const ref = leadRef(rawId);
  if (!ref.ok) return ref;
  if (typeof input.material !== "boolean") return { ok: false, reason: "material is true or false: whether the route's limitation still matters to what the case concludes" };
  const why = bounded("why", input.why, LEAD_WHY_MAX, true);
  if (!why.ok) return why;
  const second = bounded("second_review_why", input.second_review_why, LEAD_WHY_MAX, false);
  if (!second.ok) return second;
  const now = Date.now();
  try {
    const r = await transact<Fail | { ok: true; deferred?: ReviewDeferral }>(ctx.sandboxRoot, async (snap) => {
      const l = snap.state.leads.get(ref.id);
      if (!l) return { append: [], result: { ok: false as const, reason: `${ref.id} does not exist` } };
      if (!l.closed || !LIMITING_DISPOSITIONS.has(l.closed.disposition)) return { append: [], result: { ok: false as const, reason: `${l.id} is ${l.closed ? `closed ${l.closed.disposition}` : "not closed"}: a route review is of a lead closed deferred, infeasible or needs_operator` } };
      if (l.closed.by === ctx.agentId || leadHolders(l, snap.state).has(ctx.agentId)) return { append: [], result: { ok: false as const, reason: `you ${l.closed.by === ctx.agentId ? "closed" : "held"} ${l.id}: its route is reviewed by another seat` } };
      // One review of a close and the answers it saw (the c10 pilot: six
      // seats reviewed L-27 within minutes): a review that stands, or an
      // offer of it to another seat, answers this one quietly; a second,
      // independent review says why it adds something.
      const basis = routeBasis(l, snap).basis;
      const offer = O.reservingOffer(snap.state.reviewOffers.get(l.id) ?? [], now, l.rev);
      if (!second.value) {
        const settled = settledRouteReviews(l, basis);
        if (settled.length) return { append: [], result: { ok: true as const, deferred: { item: l.id, by: [...new Set(settled.map((x) => x.by))], why: `${l.id}'s close (${l.closed.ref}) was reviewed already for its questions' answers as they stand (${settled.map((x) => `${x.by} at ${x.at}: ${x.material ? "still material" : "no longer material"}`).join("; ")}); nothing recorded. A second, independent review says why it adds something (second_review_why)` } } };
        // A seat that was offered this review (at any state but declined or withdrawn: its offer may have run out while it reviewed) was asked: its review is recorded, never deferred.
        if (offer && offer.to !== ctx.agentId && !wasAsked(snap.state.reviewOffers.get(l.id) ?? [], ctx.agentId, l.rev)) return { append: [], result: { ok: true as const, deferred: { item: l.id, to: offer.to, until: new Date(O.offerStatus(offer, now, l.rev).until).toISOString(), why: `${l.id}'s route review is ${reviewHolderWords(offer, now, l.rev)}; nothing recorded. A second, independent review says why it adds something (second_review_why)` } } };
      }
      // The review takes up this seat's own offer of it, even one that ran out while it reviewed; another seat's standing offer is withdrawn.
      const offers = snap.state.reviewOffers.get(l.id) ?? [];
      const mine = [...offers].reverse().find((o) => o.to === ctx.agentId && !o.accepted && !o.declined && !o.withdrawn && o.rev === l.rev);
      const byOffer = mine ? { offer: mine.seq } : {};
      const withdrawn: LeadDraft[] = offers.filter((o) => o !== mine && O.reserving(o, now, l.rev)).map((o) => ({ by: "system", ev: "offer_withdraw", lead: l.id, offer: o.seq, to: o.to, why: `${l.id}'s route review was recorded by ${ctx.agentId}` }));
      return { append: [{ by: ctx.agentId, ev: "route_review", lead: l.id, material_now: input.material as boolean, why: why.value, cycle: l.cycle, ref: l.closed.ref, basis, ...byOffer, ...(second.value ? { second_review_why: second.value } : {}) }, ...withdrawn], result: { ok: true as const } };
    });
    if (!r.ok) return r;
    const snap = await leadsSnapshot(ctx.sandboxRoot);
    return { ok: true, lead: viewLead(snap.state.leads.get(ref.id)!, snap), ...(r.deferred ? { deferred: r.deferred } : {}) };
  } catch (err) {
    return { ok: false, reason: (err as Error).message };
  }
}

/** Whether a seat was offered a review at this revision and neither declined it nor had it withdrawn: pending, live, taken or run out, it was asked. */
function wasAsked(offers: readonly O.Offer[], agent: string, rev: number): boolean {
  return offers.some((o) => o.to === agent && o.rev === rev && !o.declined && !o.withdrawn);
}

/** A review another seat has or is offered, answered quietly (nothing recorded, no refusal): the item, who reviewed it or who has it, and until when. */
export type ReviewDeferral = { item: string; by?: string[]; to?: string; until?: string; why: string };

/** The seats that held a lead (at its open or by a claim). */
function leadHolders(l: Lead, s: LeadsState): Set<string> {
  return new Set(s.events.filter((e) => e.lead === l.id && (e.ev === "claim" || (e.ev === "open" && e.holder))).map((e) => e.holder ?? e.by));
}

/** A review offer's revision: a route review's is its lead's (a reopen or a new close ends it); a negative's is its answer's own (1). */
function reviewRev(key: string, s: LeadsState): number {
  return key.startsWith("L-") ? (s.leads.get(key)?.rev ?? 0) : 1;
}

/**
 * What a limiting lead's route review is made against: each question it
 * names with the answer standing for it, or its acceptance, or nothing yet.
 * A review stands for the answers it saw; an answer recorded again (or an
 * acceptance) since asks for a new one. `disposed` when every question has
 * an answer or an acceptance (or the lead names none).
 */
export function routeBasis(l: Lead, snap: LeadsSnapshot): { basis: string; disposed: boolean } {
  const parts: string[] = [];
  let disposed = true;
  for (const a of [...new Set(l.answers.map((x) => P.sectionKey(x)))].sort()) {
    const standing = snap.ledger.entries.find((e) => e.kind === "answer" && e.section === `question:${a}` && !snap.ledger.replaced.has(e.seq));
    const q = snap.questions?.bySection.get(a);
    if (standing) parts.push(`${a}:E-${standing.seq}`);
    else if (q?.accepted) parts.push(`${a}:accepted:r${q.accepted.rev}`);
    else {
      parts.push(`${a}:open`);
      disposed = false;
    }
  }
  return { basis: P.sha256Hex(parts.join("\n")).slice(0, 16), disposed };
}

/** The route reviews of a lead's current close, by another seat, made for these answers (a review from before bases counts for any). */
function settledRouteReviews(l: Lead, basis: string): Lead["route_reviews"] {
  if (!l.closed) return [];
  return l.route_reviews.filter((r) => r.cycle === l.cycle && r.ref === l.closed!.ref && r.by !== l.closed!.by && (r.basis === undefined || r.basis === basis));
}

/** A review item due now: a limiting lead's route review, or a material negative's review. */
type ReviewItem = { key: string; reason: "route_review" | "negative_review"; questions: string[]; exclude: Set<string>; offered: Set<string>; draft: (to: string, now: number) => LeadDraft; words: string };

/**
 * A material negative the finish gate holds unreviewed, as the gate reads
 * it: a standing answer to a material question that is a negative by the
 * gate's own test (P.negativeByResult: a bounded negative, not
 * determinable, or a premise rejected on a search alone), that no review
 * the gate counts has reviewed (P.negativeReview, against the disputes),
 * with where a review of it counts (P.negativeReviewTargets: the answer,
 * or a coverage record it rests on, whichever takes an attest with a
 * review). One with no such target (its coverage no longer stands) is not
 * reviewable yet: its coverage is recorded again first.
 */
export type NegativeDue = { answer: P.LedgerEntry; id: string; result: string; targets: P.LedgerEntry[]; exclude: Set<string> };

export function negativesDue(snap: LeadsSnapshot, attestations: P.LedgerAttestation[]): NegativeDue[] {
  const out: NegativeDue[] = [];
  const { entries, bySeq, replaced } = snap.ledger;
  const disputes = snap.ledger.disputes ?? [];
  for (const a of entries) {
    if (a.kind !== "answer" || replaced.has(a.seq) || !a.section?.startsWith("question:")) continue;
    const res = NB.answerResult(a);
    const id = P.sectionKey(a.section.slice("question:".length));
    if (!res || !P.negativeByResult(res, P.citedForQuestion(a, bySeq, replaced, id))) continue;
    const q = snap.questions?.bySection.get(id);
    if (!(snap.goal.questions.includes(id) || !q || q.materiality === "material")) continue;
    if (P.negativeReview(a, entries, attestations, disputes).reviewed) continue;
    const t = P.negativeReviewTargets(a, entries, disputes);
    const targets = t.targets.filter((e) => P.isNegativeEntry(e));
    if (!targets.length) continue;
    out.push({ answer: a, id, result: res, targets, exclude: t.authors });
  }
  return out;
}

/** Where a negative's review is recorded, in words: "attest E-220 or its coverage record E-218". */
export function reviewTargetWords(targets: P.LedgerEntry[]): string {
  const answer = targets.filter((e) => e.kind !== "coverage").map((e) => `E-${e.seq}`);
  const cov = targets.filter((e) => e.kind === "coverage").map((e) => `E-${e.seq}`);
  const records = cov.length ? `${answer.length ? "its " : ""}coverage record${cov.length === 1 ? "" : "s"} ${cov.join(", ")}` : "";
  return `attest ${[answer.join(", "), records].filter(Boolean).join(" or ")}`;
}

/**
 * The review items the registers hold due in a snapshot, offered or not:
 * a limiting material lead whose questions are disposed and no review saw
 * these answers, and a material negative the gate holds unreviewed
 * (negativesDue).
 */
function reviewItems(snap: LeadsSnapshot, attestations: P.LedgerAttestation[]): ReviewItem[] {
  const out: ReviewItem[] = [];
  for (const l of snap.state.leads.values()) {
    if (!l.material || !l.closed || !LIMITING_DISPOSITIONS.has(l.closed.disposition)) continue;
    const { basis, disposed } = routeBasis(l, snap);
    if (!disposed || settledRouteReviews(l, basis).length) continue;
    const offers = snap.state.reviewOffers.get(l.id) ?? [];
    const exclude = new Set([l.closed.by, ...leadHolders(l, snap.state)]);
    const closed = l.closed;
    out.push({
      key: l.id,
      reason: "route_review",
      questions: l.answers.map((a) => P.sectionKey(a)),
      exclude,
      offered: new Set(offers.filter((o) => o.basis === basis && o.rev === l.rev).map((o) => o.to)),
      draft: (to, at) => offerDraft(l.id, to, "route_review", l.rev, l.cycle, at, { basis, why: `${l.id} was closed ${closed.disposition} (${closed.ref}) and its questions are answered: whether its limitation still matters` }),
      words: `${l.id} "${l.title}", closed ${closed.disposition} (${closed.ref})`,
    });
  }
  for (const n of negativesDue(snap, attestations)) {
    const a = n.answer;
    const key = `E-${a.seq}`;
    const offers = snap.state.reviewOffers.get(key) ?? [];
    out.push({
      key,
      reason: "negative_review",
      questions: [n.id],
      exclude: n.exclude,
      offered: new Set(offers.map((o) => o.to)),
      draft: (to, at) => ({ by: "system", ev: "offer", entry: a.seq, to, reason: "negative_review", rev: 1, max_until: new Date(at + O.offerMaxAgeMs()).toISOString(), why: `E-${a.seq} (${a.section}, ${NB.resultWords(n.result)}) is a material negative no seat has reviewed: ${reviewTargetWords(n.targets)} with review {detection, reproduced, other_route}` }),
      words: `E-${a.seq} (${a.section}, ${NB.resultWords(n.result)})`,
    });
  }
  return out;
}

/** Why a review item needs no review any more: what the register says when it withdraws its offer. */
function reviewSettledWhy(key: string, snap: LeadsSnapshot, attestations: P.LedgerAttestation[]): string {
  if (key.startsWith("L-")) {
    const l = snap.state.leads.get(key);
    const r = l ? standingRouteReview(l) : null;
    return r ? `${key}'s route review was recorded by ${r.by}` : `${key} no longer waits for a route review`;
  }
  const seq = Number(key.slice(2));
  const by = snap.ledger.replaced.get(seq);
  if (by !== undefined) return `${key} was superseded by E-${P.standingSeq(seq, snap.ledger.replaced)}: a review of it would count for nothing`;
  const e = snap.ledger.bySeq.get(seq);
  const r = e ? P.negativeReview(e, snap.ledger.entries, attestations, snap.ledger.disputes ?? []) : null;
  if (r?.reviewed) return `${key} was reviewed by ${r.by.join(", ")}`;
  return `${key} no longer waits for a review (not a material negative the gate holds now, or its coverage is to be recorded again)`;
}

/**
 * The review offers the register settles before it offers anything: one
 * whose item needs no review any more (reviewed by any route the gate
 * counts, the answer superseded, the route reviewed) is withdrawn, so no
 * seat is left holding a review nobody needs (the c10 pilot's offer of
 * E-219, made seconds before E-220 corrected it, was declined as stale);
 * one whose first claim or hold ran out is recorded lapsed, so the
 * register says what became of it.
 */
function settleReviewOffers(snap: LeadsSnapshot, attestations: P.LedgerAttestation[], items: ReviewItem[], now: number, gone: ReadonlyMap<string, string> = new Map()): LeadDraft[] {
  const due = new Set(items.map((i) => i.key));
  const out: LeadDraft[] = [];
  for (const [key, list] of snap.state.reviewOffers) {
    const rev = reviewRev(key, snap.state);
    const where = key.startsWith("L-") ? { lead: key } : { entry: Number(key.slice(2)) };
    for (const o of list) {
      if (o.accepted || o.declined || o.withdrawn || o.lapsed_at) continue;
      const st = O.offerStatus(o, now, rev).state;
      if ((st === "pending" || st === "live") && !due.has(key)) {
        // Reviewed by the seat it was offered to (between the ledger's lock and the registers'): taken up, not withdrawn "reviewed by" itself.
        if (reviewersOf(key, snap, attestations).includes(o.to)) out.push({ by: o.to, ev: "offer_accept", ...where, offer: o.seq });
        else out.push({ by: "system", ev: "offer_withdraw", ...where, offer: o.seq, to: o.to, why: reviewSettledWhy(key, snap, attestations) });
      } else if (st === "lapsed") out.push({ by: "system", ev: "offer_lapse", ...where, offer: o.seq, to: o.to, why: o.held_until ? "taken, and the review was not recorded before its hold ran out" : "its first claim ran out" });
      // Its seat done or dead: it can no longer review, and the item passes on now, not at the end of its hold. A compacting seat is away, not gone, and keeps it.
      else if ((st === "pending" || st === "live") && gone.has(o.to)) out.push({ by: "system", ev: "offer_lapse", ...where, offer: o.seq, to: o.to, why: `its seat can no longer review it: ${gone.get(o.to)}` });
    }
  }
  return out;
}

/** Who reviewed an item as the gate counts it: a negative's reviewers, or the route review's seat. */
function reviewersOf(key: string, snap: LeadsSnapshot, attestations: P.LedgerAttestation[]): string[] {
  if (key.startsWith("L-")) {
    const l = snap.state.leads.get(key);
    const r = l ? standingRouteReview(l) : null;
    return r ? [r.by] : [];
  }
  const e = snap.ledger.bySeq.get(Number(key.slice(2)));
  return e ? P.negativeReview(e, snap.ledger.entries, attestations, snap.ledger.disputes ?? []).by : [];
}

/** Whether the register has review offers to settle or items to offer: read outside the lock, so an idle round writes nothing. */
function reviewWorkDue(snap: LeadsSnapshot, attestations: P.LedgerAttestation[], now: number): boolean {
  const items = reviewItems(snap, attestations);
  if (settleReviewOffers(snap, attestations, items, now).length) return true;
  return items.some((item) => !O.reservingOffer(snap.state.reviewOffers.get(item.key) ?? [], now, reviewRev(item.key, snap.state)));
}

/**
 * Offer each review item due to one eligible seat (A3's offers, the c10
 * pilot's stampede): never the closer, a holder or an author, never a seat
 * done, dead or compacting, never one with an offer standing or offered
 * this item already; a seat of another model family than those that did
 * the work first (a preference, never a requirement), then the relevant
 * (it held a lead under the item's questions, then it recorded an entry
 * answering them), then a waiting seat, idle longest (rankReviewers).
 * Made under the registers' lock, one seat per item,
 * each seat counted busy once offered. Offers whose item needs no review
 * any more are withdrawn first, and those that ran out recorded lapsed
 * (settleReviewOffers). Returns how many offers were made.
 */
export async function offerReviews(sandboxRoot: string, now = Date.now()): Promise<number> {
  const outer = await leadsSnapshot(sandboxRoot);
  const attestations = await P.readAttestations(sandboxRoot).catch(() => [] as P.LedgerAttestation[]);
  const activity = await recentActivity(sandboxRoot, LEAD_COMPACTION_BOUND_MS, now).catch(() => new Map<string, { last: number; compacting: number | null }>());
  // The seats holding a standing review offer that are done or dead: their offers lapse now. A compacting seat is away, not gone.
  const gone = new Map<string, string>();
  for (const list of outer.state.reviewOffers.values()) {
    for (const o of list) {
      if (gone.has(o.to) || o.accepted || o.declined || o.withdrawn || o.lapsed_at) continue;
      for (const m of ["done", "dead"] as const) if (existsSync(join(sandboxRoot, "done", "agents", `${o.to}.${m}`))) gone.set(o.to, `${o.to} is ${m === "done" ? "done" : "marked dead"}`);
    }
  }
  if (!gone.size && !reviewWorkDue(outer, attestations, now)) return 0;
  const ids = await P.teamIds(sandboxRoot).catch(() => [] as string[]);
  const r = await transact<{ ok: true; offered: number }>(sandboxRoot, async (snap) => {
    const atts = await P.readAttestations(sandboxRoot).catch(() => [] as P.LedgerAttestation[]);
    const items = reviewItems(snap, atts);
    const append: LeadDraft[] = settleReviewOffers(snap, atts, items, now, gone);
    // An offer settled just now (lapsed with its seat gone, withdrawn) no longer holds its item.
    const settled = new Set(append.filter((d) => d.ev === "offer_lapse" || d.ev === "offer_withdraw").map((d) => d.offer));
    const due = items.filter((item) => {
      const r = O.reservingOffer(snap.state.reviewOffers.get(item.key) ?? [], now, reviewRev(item.key, snap.state));
      return !r || settled.has(r.seq);
    });
    const busy = await offeredSeats(sandboxRoot, snap.state, now, snap.questions);
    let offered = 0;
    for (const item of due) {
      const candidates: string[] = [];
      for (const a of ids) {
        if (item.exclude.has(a) || busy.has(a) || item.offered.has(a)) continue;
        if (!(await seatAvailable(sandboxRoot, a, activity, now)).available) continue;
        candidates.push(a);
      }
      const pick = await rankReviewers(sandboxRoot, snap, candidates, item.questions, now, item.exclude);
      if (!pick) continue;
      busy.add(pick);
      append.push(item.draft(pick, now));
      offered += 1;
    }
    return { append, result: { ok: true as const, offered } };
  }).catch(() => null);
  return r?.offered ?? 0;
}

/**
 * A seat's model family, from team.json: its model's name without the
 * provider's route and without a release tag (-latest, -preview, a date),
 * lower-cased; null when its model is not known. The harness knows no
 * finer family than a model's name.
 */
export function modelFamily(model: string | null | undefined): string | null {
  const m = String(model ?? "").trim();
  if (!m) return null;
  const name = m.slice(m.indexOf("/") + 1).toLowerCase();
  return name.replace(/[-_.@:](?:latest|preview|\d{4}-?\d{2}-?\d{2}|\d{8})$/, "") || null;
}

/**
 * The most relevant of the candidates for a review of work under these
 * questions: first one of another model family than every seat that did
 * the work (`authors`, as team.json names their models; docs/adr/0015: a
 * routing preference, never a requirement: a team of one family is
 * offered as before, and another model is not an independent source),
 * then one that held a lead under them, then recorded an entry answering
 * them, then waiting, idle longest.
 */
async function rankReviewers(sandboxRoot: string, snap: LeadsSnapshot, candidates: string[], questions: string[], now: number, authors: ReadonlySet<string> = new Set()): Promise<string | null> {
  if (!candidates.length) return null;
  const qs = new Set(questions);
  const team = await P.readTeam(sandboxRoot).catch(() => null);
  const family = (id: string) => modelFamily(team?.agents.find((a) => a.id === id)?.model);
  const theirs = new Set([...authors].map(family).filter((f): f is string => f !== null));
  const scored: Array<{ agent: string; other: number; score: number; since: number }> = [];
  for (const agent of candidates) {
    let score = 0;
    if ([...snap.state.leads.values()].some((l) => l.answers.some((a) => qs.has(P.sectionKey(a))) && leadHolders(l, snap.state).has(agent))) score = 2;
    else if (snap.ledger.entries.some((e) => (e.by === agent || e.authors.includes(agent)) && ((e.answers ?? []).some((a) => qs.has(P.sectionKey(a))) || (e.section?.startsWith("question:") && qs.has(P.sectionKey(e.section.slice("question:".length))))))) score = 1;
    const since = P.waitingSince(await P.readWaiting(sandboxRoot, agent), now);
    const f = family(agent);
    scored.push({ agent, other: f !== null && theirs.size > 0 && !theirs.has(f) ? 1 : 0, score, since: since ?? Number.POSITIVE_INFINITY });
  }
  scored.sort((a, b) => b.other - a.other || b.score - a.score || a.since - b.since || a.agent.localeCompare(b.agent));
  return scored[0]!.agent;
}

/** Where a negative's review is recorded now, in words, from a snapshot: its answer, or a coverage record it rests on (negativesDue's targets). */
function negativeTargetWords(e: P.LedgerEntry | undefined, snap: LeadsSnapshot): string {
  if (!e) return "attest it";
  const targets = P.negativeReviewTargets(e, snap.ledger.entries, snap.ledger.disputes ?? []).targets.filter((x) => P.isNegativeEntry(x));
  return targets.length ? reviewTargetWords(targets) : `attest E-${e.seq}`;
}

/** Who has a review now, for another seat: taken by its seat (and until when), or offered to it and for how long. */
function reviewHolderWords(o: O.Offer, now: number, rev: number): string {
  const until = new Date(O.offerStatus(o, now, rev).until).toISOString();
  return o.held_until ? `taken by ${o.to}, who reviews it until ${until}` : `offered to ${o.to} ${O.untilWords(o, now, rev)}`;
}

/**
 * What a review's offer asks, for the seat it is made to; `packet`, the
 * question, its scope and its original sources, with the answer linked, not
 * quoted (reviewPacketWords), said first; `preparation`, the state of the
 * broad extraction of each source the negative rests on
 * (negativePreparationWords), said with the sources: what the reviewer
 * weighs the negative against; `warnings`, the answers check's warnings on
 * the answer offered (reviewOfferWarnings), said last.
 */
export function reviewOfferText(key: string, o: O.Offer, snap: LeadsSnapshot, warnings: readonly string[] = [], preparation: string | null = null, packet: string | null = null): string {
  const until = O.untilWords(o, snap.at, reviewRev(key, snap.state));
  const hold = `it is then yours for ${Math.round(O.reviewHoldMs() / 60_000)} min`;
  if (o.reason === "route_review") {
    const l = snap.state.leads.get(key);
    return `${key}${l ? ` ("${l.title}", closed ${l.closed?.disposition ?? "?"} on ${l.closed?.ref ?? "?"})` : ""} is offered to you for its route review, first claim ${until}: its questions are answered now. Take it with offer accept ${key} (${hold}), then say whether the route's limitation still matters with route_review(${key}, material, why); or offer decline ${key} with why. Other seats' reviews of it wait for yours.`;
  }
  const e = snap.ledger.bySeq.get(Number(key.slice(2)));
  return `${packet ? `${packet} ` : ""}${preparation ? `${preparation} ` : ""}${key}${e ? ` (${e.section}, ${NB.resultWords(NB.answerResult(e) ?? "")})` : ""} is offered to you for its review, first claim ${until}. Take it with offer accept ${key} (${hold}), then ${negativeTargetWords(e, snap)} with review {detection, reproduced, other_route} (a negative's review, not answer_review); or offer decline ${key} with why. Other seats' reviews of it wait for yours.${sweepReviewWords(e, snap)}${warnings.length ? ` The finish line warns of this answer, holding nothing on it; weigh each in your review: ${warnings.join("; ")}` : ""}`;
}

/**
 * What a negative's review is asked of the whole store (store-sweep.ts):
 * the sweeps of the coverage records it rests on, with their hits, and the
 * ask to check the answer against everything the run holds, not only the
 * coverage's sources; the review's other_route says what was done with it.
 */
function sweepReviewWords(e: P.LedgerEntry | undefined, snap: LeadsSnapshot): string {
  if (!e) return "";
  const cov = (e.support ?? []).map((x) => snap.ledger.bySeq.get(x.seq)).filter((c): c is P.LedgerEntry => c?.kind === "coverage" && !snap.ledger.replaced.has(c.seq));
  const said = cov.map((c) => `E-${c.seq}: ${SW.sweepWords(SW.sweepOf(c, snap.ledger.sweeps ?? []), c)}`);
  return ` Check the answer against everything the run holds, not only its coverage's sources${said.length ? `: ${said.join(" / ")}` : ""}; say in other_route what you did with the store sweep (each hit examined, or why it does not bear on the question).`;
}

/**
 * Answer a review's offer: decline passes it on at once (with why); accept
 * takes it, and it stays this seat's for the review itself
 * (O.reviewHoldMs), not the first claim's minute: the c10 pilot's review
 * offers went to the next seat sixty seconds after delivery while the seat
 * that took them was still reviewing. The review itself records the rest.
 */
export async function answerReviewOffer(ctx: P.SwarmContext, key: string, input: { action?: string; why?: string }, now = Date.now()): Promise<Record<string, unknown>> {
  const action = String(input.action ?? "").trim();
  if (action !== "accept" && action !== "decline") return { ok: false, reason: "action is accept or decline" };
  const why = bounded("why", input.why, LEAD_WHY_MAX, action === "decline");
  if (!why.ok) return { ok: false, reason: `${why.reason}: why you do not take it (the next seat reads it)` };
  try {
    return await transact<Record<string, unknown>>(ctx.sandboxRoot, async (snap) => {
      const o = O.reservingOffer(snap.state.reviewOffers.get(key) ?? [], now, reviewRev(key, snap.state));
      if (!o || o.to !== ctx.agentId) return { append: [], result: { ok: false, reason: `no review offer of ${key} stands for you${o ? ` (it is ${reviewHolderWords(o, now, reviewRev(key, snap.state))})` : ""}` } };
      const where = key.startsWith("L-") ? { lead: key } : { entry: Number(key.slice(2)) };
      if (action === "accept") {
        const until = o.held_until ?? new Date(now + O.reviewHoldMs()).toISOString();
        const how = o.reason === "route_review" ? `route_review(${key}, material, why)` : `${negativeTargetWords(snap.ledger.bySeq.get(Number(key.slice(2))), snap)} with review {detection, reproduced, other_route} (a negative's review, not answer_review)`;
        const note = `${key}'s review is yours until ${until}: ${how}. If you cannot, offer decline ${key} with why, and it passes on`;
        return { append: o.held_until ? [] : [{ by: ctx.agentId, ev: "offer_take", ...where, offer: o.seq, until }], result: { ok: true, id: key, action, held_until: until, note } };
      }
      return { append: [{ by: ctx.agentId, ev: "offer_decline", ...where, offer: o.seq, why: why.value }], result: { ok: true, id: key, action } };
    });
  } catch (err) {
    return { ok: false, reason: (err as Error).message };
  }
}

/**
 * A negative's review recorded (called by the ledger after the attest,
 * outside its lock): the recording seat's own offer of it is taken up, even
 * one whose first claim ran out while the seat reviewed (the c10 pilot's
 * s05 recorded E-266's review after its offer had passed on: "no outcome"),
 * and another seat's offer of it standing now is withdrawn, the item
 * reviewed.
 */
export async function reviewOfferTaken(sandboxRoot: string, key: string, agent: string, now = Date.now()): Promise<void> {
  await transact<{ ok: true }>(sandboxRoot, async (snap) => {
    const offers = snap.state.reviewOffers.get(key) ?? [];
    const rev = reviewRev(key, snap.state);
    const where = key.startsWith("L-") ? { lead: key } : { entry: Number(key.slice(2)) };
    const mine = [...offers].reverse().find((o) => o.to === agent && !o.accepted && !o.declined && !o.withdrawn && o.rev === rev);
    const append: LeadDraft[] = mine ? [{ by: agent, ev: "offer_accept", ...where, offer: mine.seq }] : [];
    for (const o of offers) if (o !== mine && O.reserving(o, now, rev)) append.push({ by: "system", ev: "offer_withdraw", ...where, offer: o.seq, to: o.to, why: `${key} was reviewed by ${agent}` });
    return { append, result: { ok: true as const } };
  }).catch(() => undefined);
}

/** Whether a negative's review is answered quietly for this seat: reviewed already by another, or offered to another now (the attest's check, read-only). */
export async function negativeReviewDeferral(sandboxRoot: string, key: string, agent: string, reviewedBy: string[], now = Date.now()): Promise<ReviewDeferral | null> {
  if (reviewedBy.length) return { item: key, by: reviewedBy, why: `${key} was reviewed already by ${reviewedBy.join(", ")}; nothing recorded. A second, independent review says why it adds something (second_review_why)` };
  const { events } = await readLeadEvents(sandboxRoot);
  const s = foldLeads(events);
  const o = O.reservingOffer(s.reviewOffers.get(key) ?? [], now, 1);
  // A seat that was offered this review was asked, even if its offer ran out while it reviewed and moved on (the Fable review: E-266's s05 again).
  if (o && o.to !== agent && !wasAsked(s.reviewOffers.get(key) ?? [], agent, 1)) return { item: key, to: o.to, until: new Date(O.offerStatus(o, now, 1).until).toISOString(), why: `${key}'s review is ${reviewHolderWords(o, now, 1)}; nothing recorded. A second, independent review says why it adds something (second_review_why)` };
  return null;
}

/** The standing route review of a lead's current close: the latest by another seat, for this open spell and this ref. */
export function standingRouteReview(l: Lead): Lead["route_reviews"][number] | null {
  if (!l.closed) return null;
  const mine = l.route_reviews.filter((r) => r.cycle === l.cycle && r.ref === l.closed!.ref && r.by !== l.closed!.by);
  return mine.at(-1) ?? null;
}

/**
 * Whether a material lead closed deferred, infeasible or needs_operator
 * still limits the run (A4, B3). It stops once every question it names is
 * disposed under the bar (`disposed` says answered, or accepted by the
 * operator) and either another seat's review holds its limitation no
 * longer material, or the operator accepted every question it names (the
 * acceptance is then the limit the run carries). A lead that names no
 * question needs the review.
 */
export function routeLimitation(l: Lead, disposed: (section: string) => "answered" | "accepted" | null): { limiting: boolean; why: string } {
  const review = standingRouteReview(l);
  const states = l.answers.map((q) => ({ q, d: disposed(q) }));
  const open = states.filter((x) => !x.d);
  if (open.length) return { limiting: true, why: `its question${open.length === 1 ? "" : "s"} ${open.map((x) => `question:${x.q}`).join(", ")} ${open.length === 1 ? "is" : "are"} not disposed under the bar` };
  if (states.length && states.every((x) => x.d === "accepted")) return { limiting: false, why: "the operator accepted the limits of every question it names" };
  if (!review) return { limiting: true, why: states.length ? "its questions are disposed, and no other seat has reviewed whether its limitation is still material (route_review)" : "it names no question, and no other seat has reviewed whether its limitation is material (route_review)" };
  if (review.material) return { limiting: true, why: `${review.by} holds its limitation still material: ${review.why}` };
  return { limiting: false, why: `${review.by} holds its limitation no longer material: ${review.why}` };
}

/**
 * The operator's answer to a lead: recorded on it, and the lead reopened when
 * it was closed, so the work goes on with what the operator gave. A host the
 * operator allows goes into operator-hosts.jsonl, which the job service reads
 * for each job run with network=allowlist from then on.
 */
export async function noteLead(sandboxRoot: string, rawId: unknown, text: string, o: { allowHost?: string; reopen?: boolean } = {}): Promise<LeadResult<{ lead: LeadView; reopened: boolean }>> {
  const ref = leadRef(rawId);
  if (!ref.ok) return ref;
  const note = bounded("the note", text, LEAD_NOTE_MAX, true);
  if (!note.ok) return note;
  const host = String(o.allowHost ?? "").trim();
  if (host && !/^(\*\.)?[A-Za-z0-9.-]{1,253}(:\d{1,5})?$/.test(host)) return { ok: false, reason: `--allow-host takes a host name (example.org, *.example.org, example.org:8443), got ${JSON.stringify(host)}` };
  try {
    const r = await transact<Fail | { ok: true; reopened: boolean }>(sandboxRoot, async (snap) => {
      const l = snap.state.leads.get(ref.id);
      if (!l) return { append: [], result: { ok: false as const, reason: `${ref.id} does not exist` } };
      const append: Array<Omit<LeadEvent, "v" | "seq" | "at" | "prev" | "hash">> = [{ by: "operator", ev: "note", lead: l.id, text: note.value, ...(host ? { allow_host: host } : {}) }];
      const reopen = Boolean(l.closed) && o.reopen !== false;
      if (reopen) {
        append.push({ by: "operator", ev: "reopen", lead: l.id, why: `the operator answered: ${note.value}`, cause: "operator" });
        // Offered to its previous holder first (A3): the seat with its context
        // reclaimed it in seconds on ctf12 while an idle seat was woken for it.
        const prev = previousHolder(l, snap.state);
        if (prev && (await seatAvailable(sandboxRoot, prev)).available) append.push(offerDraft(l.id, prev, "reopen", l.rev + 2, l.cycle + 1, snap.at, { from: prev }));
      }
      return { append, result: { ok: true as const, reopened: reopen } };
    });
    if (!r.ok) return r;
    if (host) await appendFile(join(sandboxRoot, OPERATOR_HOSTS), `${JSON.stringify({ at: new Date().toISOString(), host, lead: ref.id, by: "operator" })}\n`, "utf8");
    const snap = await leadsSnapshot(sandboxRoot);
    return { ok: true, lead: viewLead(snap.state.leads.get(ref.id)!, snap), reopened: r.reopened };
  } catch (err) {
    return { ok: false, reason: (err as Error).message };
  }
}

/** The hosts the operator allowed while the run went on. */
export async function operatorHosts(sandboxRoot: string): Promise<string[]> {
  return operatorHostsSync(sandboxRoot);
}

/** The same, read at once: the job service reads it as it places each job that asks for the network. */
export function operatorHostsSync(sandboxRoot: string): string[] {
  let text = "";
  try {
    text = readFileSync(join(sandboxRoot, OPERATOR_HOSTS), "utf8");
  } catch {
    return [];
  }
  const out: string[] = [];
  for (const line of text.split("\n")) {
    if (!line.trim()) continue;
    try {
      const h = String((JSON.parse(line) as { host?: string }).host ?? "");
      if (h && !out.includes(h)) out.push(h);
    } catch {
      // skipped
    }
  }
  return out;
}

/**
 * A job an agent ran, under the lead it named or, when it named none, the one
 * active lead it holds. A lead's jobs wait for an interpretation before the
 * run may end (the gate); an agent's other jobs are shown, never gated.
 */
export async function attachJob(sandboxRoot: string, agent: string, job: string, named?: unknown): Promise<LeadResult<{ lead: string | null }>> {
  try {
    const r = await transact<Fail | { ok: true; lead: string | null }>(sandboxRoot, async (snap) => {
      let lead: Lead | undefined;
      if (named !== undefined && named !== null && String(named).trim()) {
        const ref = leadRef(named);
        if (!ref.ok) return { append: [], result: { ok: false as const, reason: ref.reason } };
        lead = snap.state.leads.get(ref.id);
        if (!lead) return { append: [], result: { ok: false as const, reason: `${ref.id} does not exist` } };
        if (lead.closed) return { append: [], result: { ok: false as const, reason: `${lead.id} is closed` } };
        if (lead.holder !== agent) return { append: [], result: { ok: false as const, reason: `${lead.id} is ${lead.holder ? `held by ${lead.holder}` : "not held"}: claim it before running its jobs` } };
      } else {
        const mine = [...snap.state.leads.values()].filter((l) => l.holder === agent && !l.closed);
        if (mine.length !== 1) return { append: [], result: { ok: true as const, lead: null } };
        lead = mine[0];
      }
      if (snap.state.jobLead.has(job)) return { append: [], result: { ok: true as const, lead: snap.state.jobLead.get(job)! } };
      return { append: [{ by: agent, ev: "job", lead: lead.id, job }], result: { ok: true as const, lead: lead.id } };
    });
    return r.ok ? { ok: true, lead: r.lead } : r;
  } catch (err) {
    return { ok: false, reason: (err as Error).message };
  }
}

/** Whether a lead the agent names may run a job now (checked before the job is accepted). */
export async function jobLeadAllowed(sandboxRoot: string, agent: string, named: unknown): Promise<string | null> {
  if (named === undefined || named === null || !String(named).trim()) return null;
  const ref = leadRef(named);
  if (!ref.ok) return ref.reason;
  const snap = await leadsSnapshot(sandboxRoot);
  const l = snap.state.leads.get(ref.id);
  if (!l) return `${ref.id} does not exist`;
  if (l.closed) return `${l.id} is closed`;
  if (l.holder !== agent) return `${l.id} is ${l.holder ? `held by ${l.holder}` : "not held"}: claim it before running its jobs`;
  return null;
}

export type InterpretInput = { job?: string; rest?: string } | string;

/**
 * Record that a ledger entry is the interpretation of jobs' output: what the
 * output shows, as the entry says it, and its kind as the disposition (a
 * finding: it shows something; an absence: it shows nothing; a limitation:
 * it could not be used). `rest`, per job, says how the rest of an output
 * handed over only in part was read, or why it was not.
 */
export async function recordInterpretations(sandboxRoot: string, agent: string, entrySeq: number, items: InterpretInput[]): Promise<LeadResult<{ interprets: string[] }>> {
  const list: Array<{ job: string; rest?: string }> = [];
  for (const it of items) {
    const job = String(typeof it === "string" ? it : (it?.job ?? "")).trim();
    if (!/^j\d{6,}$/.test(job)) return { ok: false, reason: `interprets names jobs as j000123 (got ${JSON.stringify(job)})` };
    const rest = bounded("rest", typeof it === "string" ? "" : it?.rest, LEAD_WHY_MAX, false);
    if (!rest.ok) return rest;
    if (!list.some((x) => x.job === job)) list.push({ job, ...(rest.value ? { rest: rest.value } : {}) });
  }
  if (!list.length) return { ok: true, interprets: [] };
  try {
    const r = await transact<Fail | { ok: true }>(sandboxRoot, async (snap) => {
      const e = snap.ledger.bySeq.get(entrySeq);
      if (!e) return { append: [], result: { ok: false as const, reason: `E-${entrySeq} is not in the ledger` } };
      if (e.kind === "answer") return { append: [], result: { ok: false as const, reason: "an answer cites entries, not jobs: interpret a job in the finding, absence or limitation it rests on" } };
      const known = new Map(snap.jobs.map((j) => [j.id, j]));
      for (const x of list) {
        const j = known.get(x.job);
        if (!j) return { append: [], result: { ok: false as const, reason: `${x.job} is not a job of this run` } };
        if (j.state !== "committed") return { append: [], result: { ok: false as const, reason: `${x.job} is ${j.state}: interpret it once it is committed` } };
      }
      return { append: list.map((x) => ({ by: agent, ev: "interpret" as const, job: x.job, entry: entrySeq, kind: e.kind, entry_hash: e.hash ?? P.ledgerHash(e, "genesis"), ...(x.rest ? { rest: x.rest } : {}) })), result: { ok: true as const } };
    });
    return r.ok ? { ok: true, interprets: list.map((x) => x.job) } : r;
  } catch (err) {
    return { ok: false, reason: (err as Error).message };
  }
}

/**
 * A lead closed on an entry that no longer stands (superseded, or disputed)
 * goes back to open: its closure rested on it. Called after every change to
 * the ledger, and before the gate and every header, so a crash between the
 * ledger's change and this cannot leave a closure standing on nothing.
 */
export async function reopenOnLedger(sandboxRoot: string, now = Date.now()): Promise<string[]> {
  const snap = await leadsSnapshot(sandboxRoot);
  const due = [...snap.state.leads.values()].filter((l) => {
    const m = l.closed ? /^E-(\d+)$/.exec(l.closed.ref) : null;
    return m ? !entryStands(snap.ledger, Number(m[1])).ok : false;
  });
  if (!due.length) return [];
  // Who could confirm a superseded closure: its closer, available, or
  // compacting (away for a while, not gone: the c10 pilot's L-17 was
  // reopened three times because its closer began compacting as the offer
  // arrived); a closer done or dead is gone.
  const activity = await recentActivity(sandboxRoot, LEAD_COMPACTION_BOUND_MS, now).catch(() => new Map<string, { last: number; compacting: number | null }>());
  const closers = new Map<string, CloserState>();
  for (const l of due) {
    if (!l.closed || closers.has(l.closed.by)) continue;
    const seat = await seatAvailable(sandboxRoot, l.closed.by, activity, now);
    const since = activity.get(l.closed.by)?.compacting ?? null;
    closers.set(l.closed.by, seat.available ? { state: "available", why: seat.why } : since !== null && now - since < LEAD_COMPACTION_BOUND_MS ? { state: "compacting", why: seat.why, since } : { state: "gone", why: seat.why });
  }
  // A compacting closer's confirmation waits for it, up to this long past the compaction's start.
  const holdMs = confirmCompactionHoldMs();
  const heldFor = (c: CloserState | undefined) => c?.state === "compacting" && now - c.since! <= holdMs;
  const r = await transact<{ ok: true }>(sandboxRoot, async (inner) => {
    const append: LeadDraft[] = [];
    for (const l of inner.state.leads.values()) {
      const m = l.closed ? /^E-(\d+)$/.exec(l.closed.ref) : null;
      if (!m) continue;
      const st = entryStands(inner.ledger, Number(m[1]));
      if (st.ok) continue;
      const superseded = /superseded/.test(st.why);
      // A closure waiting for its closer's confirmation: while the offer
      // holds, it waits; declined, lapsed or overtaken by a change to the
      // lead, it reopens.
      if (l.confirm) {
        const o = l.offers.find((x) => x.seq === l.confirm!.offer);
        const closer = closers.get(l.closed!.by);
        // A closer compacting after the offer: the confirmation waits for it,
        // bounded; an offer whose window ran out meanwhile is made again (it is
        // delivered when the closer is back). Done, dead, or compacting past
        // the bound: reopened now, not after the window.
        if (superseded && heldFor(closer) && !o?.declined) {
          if (o && !O.reserving(o, now, l.rev)) {
            if (!o.lapsed_at && !o.accepted) append.push({ by: "system", ev: "offer_lapse", lead: l.id, offer: o.seq, to: o.to, why: `its window ran out while its closer compacted: made again, held for it` });
            // Made again in the batch it was in: the closer confirms its siblings and it in one act still.
            append.push(offerDraft(l.id, l.closed!.by, "confirm", l.rev, l.cycle, now, { ref: l.confirm.ref_was, ...(l.confirm.head ? { head: l.confirm.head, batch: o?.batch ?? l.confirm.head } : {}), why: `${l.confirm.ref_was} was superseded${l.confirm.head ? ` by ${l.confirm.head}` : ""}: confirm the closure on what stands, or reopen it (held while ${closer!.why})` }));
          }
          continue;
        }
        const gone = closer?.state === "gone" ? closer.why : closer?.state === "compacting" ? `${closer.why} for more than ${Math.round(holdMs / 60_000)} min` : null;
        if (o && O.reserving(o, now, l.rev) && superseded && !gone) continue;
        const lapsedNow = o && !o.lapsed_at && !o.declined && !o.accepted && (O.offerStatus(o, now, l.rev).state === "lapsed" || (gone && O.reserving(o, now, l.rev)));
        if (o && lapsedNow) append.push({ by: "system", ev: "offer_lapse", lead: l.id, offer: o.seq, to: o.to, why: gone ? `its closer can no longer take it: ${gone}` : "not confirmed within its window" });
        append.push({ by: "system", ev: "reopen", lead: l.id, why: `${l.id} was closed ${l.closed!.disposition} on ${l.confirm.ref_was}, ${st.why}, and ${o?.declined ? `${o.to} declined to confirm it (${o.declined.why})` : gone ? `its closer can no longer confirm it (${gone})` : `its closer did not confirm it within its window`}`, cause: "superseded" });
        continue;
      }
      // Superseded by a correction that changes no conclusion (its refs,
      // its evidence or its words only: a citation or qualification
      // refresh): the closure holds on the entry that stands, re-pointed and
      // said so (the c10 pilot re-offered four to six confirmations for each
      // such refresh near its finish). A change of value, result or kind
      // can reverse what the closure rested on (Astra's objection to any
      // re-point): that goes to confirm or reopen.
      const headSeq = inner.ledger.replaced.has(Number(m[1])) ? P.standingSeq(Number(m[1]), inner.ledger.replaced) : null;
      const was = inner.ledger.bySeq.get(Number(m[1]));
      const now_ = headSeq !== null ? inner.ledger.bySeq.get(headSeq) : undefined;
      if (superseded && was && now_ && entryStands(inner.ledger, headSeq!).ok && P.sameConclusion(was, now_)) {
        append.push({ by: "system", ev: "confirm", lead: l.id, ref: `E-${headSeq}`, why: `repoint (conclusion unchanged): ${l.closed!.ref} was superseded by E-${headSeq}, which changes neither its value nor its result, only what it cites or how it says it; the closure rests on the entry that stands` });
        continue;
      }
      // Superseded: the closure may still hold on the correction, or not (a
      // correction by the same author can reverse the basis). Its closer is
      // offered to confirm it on what stands now or reopen it (lead_confirm,
      // lead_reopen), one offer per seat and correction chain (its head,
      // the batch); nothing re-points it by itself (A3). Disputed, or with
      // nobody to confirm it: reopened.
      if (superseded && (closers.get(l.closed!.by)?.state === "available" || heldFor(closers.get(l.closed!.by)))) {
        const head = headSeq !== null ? `E-${headSeq}` : null;
        append.push(offerDraft(l.id, l.closed!.by, "confirm", l.rev, l.cycle, now, { ref: l.closed!.ref, ...(head ? { head, batch: head } : {}), why: `${l.closed!.ref} was superseded${head ? ` by ${head}` : ""}: confirm the closure on what stands, or reopen it` }));
        continue;
      }
      append.push({ by: "system", ev: "reopen", lead: l.id, why: `${l.id} was closed ${l.closed!.disposition} on ${l.closed!.ref}, and ${st.why}`, cause: superseded ? "superseded" : "disputed" });
    }
    return { append, result: { ok: true as const } };
  });
  return r.events.filter((e) => e.ev === "reopen").map((e) => e.lead!).filter(Boolean);
}

/** A correction chain's head as it stands now: E-<seq> of the entry that stands at the end of the chain (a later correction moved it), or the head as given. */
function standingHead(head: string | null | undefined, snap: LeadsSnapshot): string | null {
  const m = head ? /^E-(\d+)$/.exec(head) : null;
  if (!m) return head ?? null;
  const n = Number(m[1]);
  return snap.ledger.replaced.has(n) ? `E-${P.standingSeq(n, snap.ledger.replaced)}` : head!;
}

/** A closure's closer, for its confirmation: able to take it, compacting (since when), or gone (done, dead). */
type CloserState = { state: "available" | "compacting" | "gone"; why: string; since?: number };

/**
 * How long a confirmation waits for a closer that is compacting, from the
 * compaction's start (SWARM_CONFIRM_COMPACTION_HOLD_SEC, 300): compaction
 * is temporary unavailability; a closer done or dead is gone at once.
 */
export function confirmCompactionHoldMs(): number {
  return envMs("SWARM_CONFIRM_COMPACTION_HOLD_SEC", 300);
}

/**
 * Confirm a closure whose entry was superseded (A3): the closer, offered it,
 * says the closure still holds on what stands now (ref: the correction, by
 * default, or another standing entry of the kind the disposition cites),
 * with the lead's revision it read and why. Unconfirmed within the offer, it
 * reopens (reopenOnLedger). Never automatic: a correction by the same author
 * can reverse the basis.
 */
export async function confirmLead(ctx: P.SwarmContext, rawId: unknown, input: { expected_revision?: unknown; ref?: string; why?: string }, now = Date.now()): Promise<LeadResult<{ lead: LeadView } & P.WarningsDelivered>> {
  const ref = leadRef(rawId);
  if (!ref.ok) return ref;
  const why = bounded("why", input.why, LEAD_WHY_MAX, true);
  if (!why.ok) return { ok: false, reason: `${why.reason}: why the closure still holds on the correction` };
  const expected = Number(input.expected_revision);
  if (!Number.isInteger(expected) || expected < 1) return { ok: false, reason: "expected_revision is the lead's revision as you read it (leads L-<n> shows rev)" };
  try {
    const r = await transact<Fail | { ok: true }>(ctx.sandboxRoot, async (snap) => {
      const l = snap.state.leads.get(ref.id);
      if (!l) return { append: [], result: { ok: false as const, reason: `${ref.id} does not exist` } };
      if (!l.closed || !l.confirm) return { append: [], result: { ok: false as const, reason: `${l.id} has no closure waiting for confirmation${l.closed ? "" : ": it is open"}` } };
      if (l.rev !== expected) return { append: [], result: { ok: false as const, reason: `${l.id} is at revision ${l.rev}, not ${expected}: read it again` } };
      const o = l.offers.find((x) => x.seq === l.confirm!.offer);
      if (!o || !O.reserving(o, now, l.rev)) return { append: [], result: { ok: false as const, reason: `the confirmation of ${l.id} is no longer offered (${o ? O.offerStatus(o, now, l.rev).state : "none"}): it reopens; reopen or claim it` } };
      if (o.to !== ctx.agentId) return { append: [], result: { ok: false as const, reason: `${l.id}'s closure is ${o.to}'s to confirm (its closer)` } };
      const target = String(input.ref ?? standingHead(l.confirm.head, snap) ?? "").trim();
      if (!target) return { append: [], result: { ok: false as const, reason: "ref is the standing entry the closure rests on now" } };
      const checked = checkRef(l.closed.disposition, target, l, snap);
      if (!checked.ok) return { append: [], result: { ok: false as const, reason: checked.reason } };
      return { append: [{ by: ctx.agentId, ev: "confirm", lead: l.id, ref: checked.ref, why: why.value, offer: o.seq }], result: { ok: true as const } };
    });
    if (!r.ok) return r;
    const snap = await leadsSnapshot(ctx.sandboxRoot);
    return { ok: true, lead: viewLead(snap.state.leads.get(ref.id)!, snap), ...(await closeWarnings(ctx.sandboxRoot, r.events)) };
  } catch (err) {
    return { ok: false, reason: (err as Error).message };
  }
}

/**
 * Confirm every closure of this seat waiting in one batch (the correction
 * chain's head, E-<seq>): each on the entry that stands (its head, or
 * `ref`), with one why. The c10 pilot re-offered four to six confirmations
 * for one revision near its finish, several to one seat: one act answers
 * them. A closure whose offer ended or whose ref does not fit is skipped,
 * with why.
 */
export async function confirmBatch(ctx: P.SwarmContext, rawBatch: unknown, input: { ref?: string; why?: string }, now = Date.now()): Promise<LeadResult<{ confirmed: string[]; skipped: Array<{ lead: string; why: string }> } & P.WarningsDelivered>> {
  const batch = String(rawBatch ?? "").trim().replace(/^e-/i, "E-");
  if (!/^E-\d+$/.test(batch)) return { ok: false, reason: `a batch is named by the correction it follows, E-<seq> (got ${JSON.stringify(rawBatch)})` };
  const why = bounded("why", input.why, LEAD_WHY_MAX, true);
  if (!why.ok) return { ok: false, reason: `${why.reason}: why the closures still hold on the correction` };
  try {
    const r = await transact<Fail | { ok: true; confirmed: string[]; skipped: Array<{ lead: string; why: string }> }>(ctx.sandboxRoot, async (snap) => {
      const append: LeadDraft[] = [];
      const confirmed: string[] = [];
      const skipped: Array<{ lead: string; why: string }> = [];
      for (const l of snap.state.leads.values()) {
        if (!l.closed || !l.confirm) continue;
        const o = l.offers.find((x) => x.seq === l.confirm!.offer);
        if (!o || o.batch !== batch || o.to !== ctx.agentId) continue;
        if (!O.reserving(o, now, l.rev)) {
          skipped.push({ lead: l.id, why: `its confirmation is no longer offered (${O.offerStatus(o, now, l.rev).state})` });
          continue;
        }
        // The chain may have moved since the offer (a second correction): the closer confirms what stands now.
        const target = String(input.ref ?? standingHead(l.confirm.head ?? batch, snap) ?? batch).trim();
        const checked = checkRef(l.closed.disposition, target, l, snap);
        if (!checked.ok) {
          skipped.push({ lead: l.id, why: checked.reason });
          continue;
        }
        append.push({ by: ctx.agentId, ev: "confirm", lead: l.id, ref: checked.ref, why: why.value, offer: o.seq, batch });
        confirmed.push(l.id);
      }
      if (!confirmed.length && !skipped.length) return { append: [], result: { ok: false as const, reason: `no closure of yours waits for confirmation in batch ${batch}` } };
      return { append, result: { ok: true as const, confirmed, skipped } };
    });
    if (!r.ok) return r;
    return { ok: true, confirmed: r.confirmed, skipped: r.skipped, ...(await closeWarnings(ctx.sandboxRoot, r.events)) };
  } catch (err) {
    return { ok: false, reason: (err as Error).message };
  }
}

/**
 * Hand a held lead to another seat (A2): the holder lets it go with why,
 * and it is offered to the seat it names (available: not done, dead or
 * compacting) or, when it names none, to the seat idle longest; with no
 * seat to offer it to, it is open to everyone. Recorded as a hand-off, so
 * hand-over is a native measure.
 */
export async function handoffLead(ctx: P.SwarmContext, rawId: unknown, input: { why?: string; to?: string; generation?: number }): Promise<LeadResult<{ lead: LeadView; offered_to?: string }>> {
  const ref = leadRef(rawId);
  if (!ref.ok) return ref;
  const why = bounded("why", input.why, LEAD_WHY_MAX, true);
  if (!why.ok) return { ok: false, reason: `${why.reason}: what you did on it, and what the next seat takes up` };
  const to = String(input.to ?? "").trim();
  if (to && to === ctx.agentId) return { ok: false, reason: "a hand-off is to another seat" };
  const avail = to ? await seatAvailable(ctx.sandboxRoot, to) : null;
  if (avail && !avail.available) return { ok: false, reason: `${avail.why}: hand it to another seat, or leave to out and the seat idle longest is offered it` };
  try {
    const r = await transact<Fail | { ok: true; offered: string | null }>(ctx.sandboxRoot, async (snap) => {
      const l = snap.state.leads.get(ref.id);
      if (!l) return { append: [], result: { ok: false as const, reason: `${ref.id} does not exist` } };
      if (l.closed) return { append: [], result: { ok: false as const, reason: `${l.id} is closed; there is nothing to hand over` } };
      const refused = holderOnly(l, ctx, input.generation, "hand over");
      if (refused) return { append: [], result: { ok: false as const, reason: refused } };
      let target: string | null = to || null;
      if (!target) target = (await idleSeats(ctx.sandboxRoot, snap.state, snap.ledger, snap.jobs, snap.at, snap.questions)).find((x) => x.agent !== ctx.agentId)?.agent ?? null;
      const append: LeadDraft[] = [{ by: ctx.agentId, ev: "handoff", lead: l.id, why: why.value, generation: l.generation, ...(target ? { to: target } : {}) }];
      if (target) append.push(offerDraft(l.id, target, "handoff", l.rev + 1, l.cycle + 1, snap.at, { from: ctx.agentId }));
      return { append, result: { ok: true as const, offered: target } };
    });
    if (!r.ok) return r;
    const snap = await leadsSnapshot(ctx.sandboxRoot);
    return { ok: true, lead: viewLead(snap.state.leads.get(ref.id)!, snap), ...(r.offered ? { offered_to: r.offered } : {}) };
  } catch (err) {
    return { ok: false, reason: (err as Error).message };
  }
}

/**
 * Answer an offer of a lead (A3): accept takes it (the claim the offer
 * reserves; a closure to confirm is confirmed with lead_confirm), decline
 * passes it on at once, with why.
 */
export async function answerLeadOffer(ctx: P.SwarmContext, rawId: unknown, input: { action?: string; why?: string }, now = Date.now()): Promise<LeadResult<{ lead: LeadView; declined?: true; claimed?: true }>> {
  const ref = leadRef(rawId);
  if (!ref.ok) return ref;
  const action = String(input.action ?? "").trim();
  if (action !== "accept" && action !== "decline") return { ok: false, reason: "action is accept or decline" };
  if (action === "accept") {
    const snap = await leadsSnapshot(ctx.sandboxRoot);
    const l = snap.state.leads.get(ref.id);
    const o = l ? O.reservingOffer(l.offers, now, l.rev) : null;
    if (!l || !o || o.to !== ctx.agentId) return { ok: false, reason: `no offer of ${ref.id} stands for you${o ? ` (it is offered to ${o.to})` : ""}` };
    if (o.reason === "confirm") return { ok: false, reason: `${l.id}'s offer is its closure to confirm: lead_confirm ${l.id} (expected_revision ${l.rev}, ref, why), or lead_reopen it` };
    const c = await claimLead(ctx, ref.id, {}, now);
    return c.ok ? { ok: true, lead: c.lead, claimed: true } : c;
  }
  const why = bounded("why", input.why, LEAD_WHY_MAX, true);
  if (!why.ok) return { ok: false, reason: `${why.reason}: why you do not take it (the next seat reads it)` };
  try {
    const r = await transact<Fail | { ok: true }>(ctx.sandboxRoot, async (snap) => {
      const l = snap.state.leads.get(ref.id);
      if (!l) return { append: [], result: { ok: false as const, reason: `${ref.id} does not exist` } };
      const o = O.reservingOffer(l.offers, now, l.rev);
      if (!o || o.to !== ctx.agentId) return { append: [], result: { ok: false as const, reason: `no offer of ${l.id} stands for you` } };
      return { append: [{ by: ctx.agentId, ev: "offer_decline", lead: l.id, offer: o.seq, why: why.value }], result: { ok: true as const } };
    });
    if (!r.ok) return r;
    const snap = await leadsSnapshot(ctx.sandboxRoot);
    return { ok: true, lead: viewLead(snap.state.leads.get(ref.id)!, snap), declined: true };
  } catch (err) {
    return { ok: false, reason: (err as Error).message };
  }
}

/** An offer answered: a lead's (L-<n>) or a question's (Q-<n>), one mechanism (extensions/offers.ts). */
export async function answerOffer(ctx: P.SwarmContext, subject: unknown, input: { action?: string; why?: string }): Promise<Record<string, unknown>> {
  const id = String(subject ?? "").trim();
  if (/^Q-\d+$/i.test(id)) return (await import("./questions.ts")).answerQuestionOffer(ctx, id, input ?? {});
  // A review's offer: a negative's by its answer (E-<seq>); a route review's by its lead, when that is what is offered to this seat.
  if (/^E-\d+$/i.test(id)) return answerReviewOffer(ctx, `E-${Number(id.slice(2))}`, input ?? {});
  if (/^L-\d+$/i.test(id)) {
    const key = `L-${Number(id.slice(2))}`;
    const s = foldLeads((await readLeadEvents(ctx.sandboxRoot)).events);
    const review = O.reservingOffer(s.reviewOffers.get(key) ?? [], Date.now(), reviewRev(key, s));
    const lead = s.leads.get(key);
    const leadOffer = lead ? O.reservingOffer(lead.offers, Date.now(), lead.rev) : null;
    if (review?.to === ctx.agentId && leadOffer?.to !== ctx.agentId) return answerReviewOffer(ctx, key, input ?? {});
    return answerLeadOffer(ctx, id, input ?? {});
  }
  return { ok: false, reason: `an offer is of a lead (L-<n>), a question (Q-<n>) or a negative's review (E-<seq>); got ${JSON.stringify(subject)}` };
}

/** Record that offers reached their seat (its wait or its header delivered them): an offer's first claim is counted from here. */
export async function markOffersSeen(sandboxRoot: string, agent: string, seqs: Array<{ lead: string; offer: number }>): Promise<void> {
  if (!seqs.length) return;
  await transact<{ ok: true }>(sandboxRoot, async (snap) => {
    const append: LeadDraft[] = [];
    for (const x of seqs) {
      const o = snap.state.leads.get(x.lead)?.offers.find((y) => y.seq === x.offer) ?? snap.state.reviewOffers.get(x.lead)?.find((y) => y.seq === x.offer);
      const where = x.lead.startsWith("E-") ? { entry: Number(x.lead.slice(2)) } : { lead: x.lead };
      if (o && o.to === agent && !o.seen_at) append.push({ by: agent, ev: "offer_seen", ...where, offer: x.offer });
    }
    return { append, result: { ok: true as const } };
  }).catch(() => undefined);
}

// --- what each agent is told ---------------------------------------------------------------------

/** What an agent was last shown of the leads it holds and the ones they need (inbox/<id>/leads.json). */
type Told = { seq: number; held: Record<string, { status: LeadStatus; unmet: string[]; dead: string[]; stale: boolean; closed?: string; notes: number }>; deps: Record<string, { status: LeadStatus; holder: string | null; disposition?: string }>; wakes: string[]; offers?: number[] };

function toldPath(sandboxRoot: string, agent: string): string {
  return join(sandboxRoot, "inbox", agent, "leads.json");
}

async function readTold(sandboxRoot: string, agent: string): Promise<Told> {
  try {
    const t = JSON.parse(await readFile(toldPath(sandboxRoot, agent), "utf8")) as Told;
    return { seq: t.seq ?? 0, held: t.held ?? {}, deps: t.deps ?? {}, wakes: t.wakes ?? [], offers: t.offers ?? [] };
  } catch {
    return { seq: 0, held: {}, deps: {}, wakes: [], offers: [] };
  }
}

function toldNow(agent: string, snap: LeadsSnapshot, previouslyHeld: string[]): Told {
  const { state: s, ledger: v } = snap;
  const held: Told["held"] = {};
  const deps: Told["deps"] = {};
  for (const l of s.leads.values()) {
    // The leads it holds, and the ones it held when last told that nobody
    // holds now (released, reopened): what happens to those is still its news.
    if (l.holder !== agent && !(previouslyHeld.includes(l.id) && l.holder === null)) continue;
    const unmet = l.needs.filter((n) => !needState(n, s, v).met);
    held[l.id] = { status: leadStatus(l, s, v), unmet, dead: unmet.filter((n) => needState(n, s, v).dead), stale: Boolean(l.stale && l.stale.holder === agent), ...(l.closed ? { closed: l.closed.disposition } : {}), notes: l.notes.length };
    for (const n of l.needs) {
      const id = n.split(":")[0];
      const d = s.leads.get(id);
      if (d) deps[id] = { status: leadStatus(d, s, v), holder: d.holder, ...(d.closed ? { disposition: d.closed.disposition } : {}) };
    }
  }
  const wakes = [...s.wakes.entries()].filter(([, to]) => to === agent).map(([k]) => k);
  return { seq: s.events.length, held, deps, wakes, offers: [...offersFor(agent, snap).map((x) => x.offer.seq), ...reviewOffersFor(agent, snap).map((x) => x.offer.seq)] };
}

/** The offers that concern a seat now: made to it, or of a lead parked in its hands; each still holding its lead. */
export function offersFor(agent: string, snap: LeadsSnapshot): Array<{ lead: Lead; offer: O.Offer }> {
  const out: Array<{ lead: Lead; offer: O.Offer }> = [];
  for (const l of snap.state.leads.values()) {
    for (const o of l.offers) {
      if (o.to !== agent && !(o.reason === "parked" && o.from === agent)) continue;
      if (O.reserving(o, snap.at, l.rev)) out.push({ lead: l, offer: o });
    }
  }
  return out;
}

/** What an offer says to the seat it concerns. */
export function offerText(l: Lead, o: O.Offer, agent: string, snap: LeadsSnapshot): string {
  const until = O.untilWords(o, snap.at, l.rev);
  if (o.reason === "parked" && o.from === agent && o.to !== agent) return `${l.id} ("${l.title}") is parked in your hands (no job and no act on it for ${Math.round(parkMs() / 60_000)}+ min while you work elsewhere) and is offered to ${o.to}, who has first claim ${until}: act on it (lead_claim ${l.id} keeps it, or run its job), lead_handoff it, or let it go`;
  const decline = `offer decline ${l.id} with why if you cannot take it`;
  switch (o.reason) {
    case "parked":
      return `${l.id} ("${l.title}") is parked in ${o.from ?? l.holder}'s hands (no job and no act on it while they work elsewhere) and is offered to you, first claim ${until}: lead_claim ${l.id} takes it over unless ${o.from ?? l.holder} acts on it first; ${decline}`;
    case "handoff":
      return `${o.from ?? "its holder"} hands ${l.id} ("${l.title}") to you, first claim ${until}: ${l.why}${l.next_action ? ` Next action: ${l.next_action}.` : ""} lead_claim ${l.id} (or offer accept ${l.id}) to take it; ${decline}`;
    case "reopen":
      return `${l.id} ("${l.title}") was reopened after the operator's note and is offered to you first, its previous holder, ${until}: ${l.notes.at(-1)?.text ?? ""} lead_claim ${l.id} to go on; ${decline}`;
    case "confirm":
      return `${l.id} ("${l.title}") was closed ${l.closed?.disposition ?? "?"} on ${l.confirm?.ref_was ?? "?"}, since superseded${l.confirm?.head ? ` by ${l.confirm.head}` : ""}: confirm the closure on what stands now (lead_confirm ${l.id}, expected_revision ${l.rev}, ref, why) or reopen it (lead_reopen), ${until}. Unconfirmed, it reopens by itself; nothing re-points it`;
    default:
      return `${l.id} ("${l.title}") is open, ready and nobody holds it, and it is offered to you (idle), first claim ${until}: lead_claim ${l.id} to take it; ${decline}`;
  }
}

export type LeadNotice = {
  kind: "lead_ready" | "lead_blocked" | "need_dead" | "dependency_changed" | "stale_marked" | "reclaimed" | "reopened" | "operator_note" | "wake" | "offer" | "confirm" | "parked" | "review_offer" | `question_${import("./questions.ts").QuestionNotice["kind"]}`;
  /** The lead the notice is about, or the question (Q-<n>) for the register's. */
  lead: string;
  /** An offer notice: the offer it delivers (its first claim counts from this delivery). */
  offer?: number;
  /** A batch of confirmations delivered in one notice: every offer in it. */
  batch?: Array<{ lead: string; offer: number }>;
  text: string;
  wakes: boolean;
};

/**
 * What changed for this agent since it was last told: derived from the
 * state, never stored, so none is lost to a restart. `reviewWarnings`, the
 * answers check's warnings on each answer offered to it for review
 * (reviewOfferWarnings), said in the offer.
 */
export function noticesFor(agent: string, before: Told, snap: LeadsSnapshot, reviewWarnings: ReadonlyMap<string, readonly string[]> = new Map(), reviewPreparation: ReadonlyMap<string, string> = new Map(), reviewPackets: ReadonlyMap<string, string> = new Map()): LeadNotice[] {
  const { state: s, ledger: v } = snap;
  const out: LeadNotice[] = [];
  const now = toldNow(agent, snap, Object.keys(before.held));
  for (const [id, was] of Object.entries(before.held)) {
    const l = s.leads.get(id);
    if (!l) continue;
    const cur = now.held[id];
    if (l.holder && l.holder !== agent && !l.closed) {
      const took = [...s.events].reverse().find((e) => e.ev === "claim" && e.lead === id && e.seq > before.seq);
      if (took) out.push({ kind: "reclaimed", lead: id, text: `${id} was taken over by ${l.holder} (generation ${l.generation}) after it showed as stale in your hands: post to ${l.holder} with what you have`, wakes: true });
      continue;
    }
    if (!cur) continue;
    if (was.status === "blocked" && (cur.status === "active" || cur.status === "open")) out.push({ kind: "lead_ready", lead: id, text: `lead_ready: every need of ${id} (${l.title}) is met now; go on with it`, wakes: true });
    if (was.status !== "blocked" && cur.status === "blocked") out.push({ kind: "lead_blocked", lead: id, text: `${id} is blocked again: ${cur.unmet.map((n) => `${n} (${needState(n, s, v).why ?? "unmet"})`).join("; ")}`, wakes: false });
    for (const n of cur.dead) {
      if ((was.dead ?? []).includes(n)) continue;
      out.push({ kind: "need_dead", lead: id, text: `${id}'s need ${n} will not be met as it stands: ${needState(n, s, v).why}. Revise it with lead_link, or find another route`, wakes: true });
    }
    if (cur.stale && !was.stale) out.push({ kind: "stale_marked", lead: id, text: `${id} is marked stale in your hands: a peer found you silent with no job running. Act on it (a post, a job, lead_release) or it will be taken over`, wakes: true });
    if (was.closed && !cur.closed) {
      const r = l.reopened.at(-1);
      // Offered to it first, the offer says so (below).
      const offered = l.offers.some((o) => o.to === agent && O.reserving(o, snap.at, l.rev));
      if (!offered) out.push({ kind: "reopened", lead: id, text: `${id} was reopened (${r?.cause ?? "?"}): ${r?.why ?? ""}. It is open again; claim it to go on`, wakes: true });
    }
    if (cur.notes > was.notes) {
      for (const n of l.notes.slice(was.notes)) out.push({ kind: "operator_note", lead: id, text: `The operator on ${id}: ${n.text}${n.allow_host ? ` (allowed host for jobs with network=allowlist: ${n.allow_host})` : ""}`, wakes: true });
    }
  }
  for (const [id, cur] of Object.entries(now.deps)) {
    const was = before.deps[id];
    if (!was) continue;
    if (was.status !== cur.status || was.holder !== cur.holder || was.disposition !== cur.disposition) {
      out.push({ kind: "dependency_changed", lead: id, text: `${id}, which your lead needs, is now ${cur.status}${cur.holder ? ` (held by ${cur.holder})` : ""}${cur.disposition ? `, closed ${cur.disposition}` : ""}`, wakes: false });
    }
  }
  // Offers (A3): each once, while it still holds its lead; the confirmations of one batch in one notice.
  const told = new Set(before.offers ?? []);
  const batches = new Map<string, Array<{ lead: Lead; offer: O.Offer }>>();
  for (const { lead: l, offer: o } of offersFor(agent, snap)) {
    if (o.reason === "confirm" && o.batch && o.to === agent) {
      batches.set(o.batch, [...(batches.get(o.batch) ?? []), { lead: l, offer: o }]);
      continue;
    }
    if (told.has(o.seq)) continue;
    out.push({ kind: o.reason === "confirm" ? "confirm" : o.reason === "parked" && o.from === agent ? "parked" : "offer", lead: l.id, offer: o.seq, text: offerText(l, o, agent, snap), wakes: true });
  }
  for (const [batch, list] of batches) {
    if (list.every((x) => told.has(x.offer.seq))) continue;
    const until = O.untilWords(list[0]!.offer, snap.at, list[0]!.lead.rev);
    const text = `The correction ${batch} supersedes what ${list.length === 1 ? "a closure" : `${list.length} closures`} of yours rested on: ${list.map((x) => `${x.lead.id} ("${x.lead.title}", closed ${x.lead.closed?.disposition ?? "?"} on ${x.lead.confirm?.ref_was ?? "?"})`).join("; ")}. Confirm ${list.length === 1 ? "it" : "them"} on what stands now in one act, lead_confirm(batch: "${batch}", why), or reopen the one that no longer holds (lead_reopen), ${until}. Unconfirmed, ${list.length === 1 ? "it reopens" : "they reopen"} by ${list.length === 1 ? "itself" : "themselves"}; nothing re-points a closure whose conclusion changed`;
    out.push({ kind: "confirm", lead: list[0]!.lead.id, offer: list[0]!.offer.seq, batch: list.map((x) => ({ lead: x.lead.id, offer: x.offer.seq })), text, wakes: true });
  }
  // A review offered to this seat (a route review, a negative's review).
  for (const { key, offer: o } of reviewOffersFor(agent, snap)) {
    if (told.has(o.seq)) continue;
    out.push({ kind: "review_offer", lead: key, offer: o.seq, text: reviewOfferText(key, o, snap, reviewWarnings.get(key) ?? [], reviewPreparation.get(key) ?? null, reviewPackets.get(key) ?? null), wakes: true });
  }
  return out;
}

/**
 * The answers check's warnings on each answer offered to `agent` for
 * review and not yet told it (finish.ts warningsAt, review_offer): read as
 * the offer is delivered, so it says what the gate warns of then. A route
 * review is of a lead, not of an answer, and carries none. Nothing when no
 * such offer waits, so a delivery with none reads nothing more.
 */
export async function reviewOfferWarnings(sandboxRoot: string, agent: string, snap: LeadsSnapshot, before: Told): Promise<Map<string, string[]>> {
  const out = new Map<string, string[]>();
  const told = new Set(before.offers ?? []);
  const keys = reviewOffersFor(agent, snap).filter((x) => x.key.startsWith("E-") && !told.has(x.offer.seq)).map((x) => x.key);
  if (!keys.length) return out;
  const F = await import("./finish.ts");
  for (const key of keys) {
    const ws = await F.warningsAt(sandboxRoot, { point: "review_offer", entry: Number(key.slice(2)) }).catch(() => [] as P.LedgerWarning[]);
    if (ws.length) out.set(key, ws.map(P.warningWords));
  }
  return out;
}

/**
 * The state of the broad extraction of each source a negative rests on
 * (extensions/preparation.ts), in words, for its review offer to lead with:
 * the sources it is held on, those it was weighed without, then those whose
 * extraction produced, each with what the extraction does not hold. Null
 * when no receipt bears on the answer's coverage.
 */
export async function negativePreparationWords(sandboxRoot: string, snap: LeadsSnapshot, seq: number): Promise<string | null> {
  const a = snap.ledger.bySeq.get(seq);
  if (!a || a.kind !== "answer" || !a.section?.startsWith("question:")) return null;
  const facts = await PR.preparationFacts(sandboxRoot, snap.ledger.entries);
  if (!facts.sources.size) return null;
  const id = P.sectionKey(a.section.slice("question:".length));
  const covs = P.citedForQuestion(a, snap.ledger.bySeq, snap.ledger.replaced, id).filter((c) => c.kind === "coverage");
  const found = PR.preparationFindings(a, covs, facts);
  const shown = new Set([...found.hold, ...found.warn].map((x) => x.source.source.sha256));
  const others = [...new Set(covs.flatMap((c) => (facts.reach.get(c.seq) ?? []).map((r) => r.sha256)))]
    .filter((sha) => !shown.has(sha))
    .map((sha) => facts.sources.get(sha))
    .filter((x): x is PR.SourcePreparation => Boolean(x));
  return PR.reviewPreparationWords(found, others);
}

/** The preparation words of each negative offered to `agent` for review and not yet told it (negativePreparationWords): read as the offer is delivered. */
export async function reviewOfferPreparation(sandboxRoot: string, agent: string, snap: LeadsSnapshot, before: Told): Promise<Map<string, string>> {
  const out = new Map<string, string>();
  const told = new Set(before.offers ?? []);
  for (const { key, offer } of reviewOffersFor(agent, snap)) {
    if (!key.startsWith("E-") || told.has(offer.seq)) continue;
    const words = await negativePreparationWords(sandboxRoot, snap, Number(key.slice(2))).catch(() => null);
    if (words) out.set(key, words);
  }
  return out;
}

/** How many jobs back a job's output is followed to the sources it was made from. */
const SOURCE_DEPTH = 8;

/**
 * The original sources refs lead back to: an input, an import, a capture
 * or a digest as named; a job's output by the job's declared inputs,
 * followed back through the jobs that made them (a job over everything is
 * its own source); a catalogue member by its generation's target. Refs and
 * the jobs' own records only, each once, in the order met. A brain's own
 * output (tool:, trace:) is its own source.
 */
export async function originalSources(sandboxRoot: string, refs: readonly string[]): Promise<string[]> {
  const out: string[] = [];
  const seen = new Set<string>();
  const put = (r: string) => {
    if (!out.includes(r)) out.push(r);
  };
  const walk = async (ref: string, depth: number): Promise<void> => {
    const r = ref.trim();
    if (!r || seen.has(r) || depth > SOURCE_DEPTH || /^unresolved:/.test(r)) return;
    seen.add(r);
    const job = NB.jobOfRef(r);
    if (job) {
      // Only a job that declared what it reads leads back to it; one over everything is its own source.
      const d = await NB.jobDeclared(sandboxRoot, job).catch(() => null);
      if (!d || d.scope !== "declared" || !d.inputs.length) {
        put(`job:${job}`);
        return;
      }
      for (const i of d.inputs) await walk(i, depth + 1);
      return;
    }
    const mem = /^member:([a-z0-9-]+)#\d+$/.exec(r);
    if (mem) {
      const g = (await NB.generations(sandboxRoot).catch(() => [] as NB.GenRecord[])).find((x) => x.id === mem[1]);
      if (g?.target?.ref) await walk(g.target.ref, depth + 1);
      else put(r);
      return;
    }
    put(r.replace(/^input:inputs\//, "input:"));
  };
  for (const r of refs) await walk(r, 0);
  return out;
}

/**
 * A review's packet, source-first (docs/adr/0015, "A source-first
 * review"): the question as it is asked now (its register id and revision,
 * its words whole), its scope, and the original sources the answer's
 * coverage records and cited entries lead back to (originalSources); then
 * the answer under review, linked by its seq, the entries it corrects and
 * the coverage it rests on, never quoted: the reviewer reads the question
 * against the sources before it reads the conclusion. Reduced priming, not
 * blindness: a seat may have seen the board. Null when the entry is not an
 * answer to a question.
 */
export async function reviewPacketWords(sandboxRoot: string, snap: LeadsSnapshot, seq: number): Promise<string | null> {
  const a = snap.ledger.bySeq.get(seq);
  if (!a || a.kind !== "answer" || !a.section?.startsWith("question:")) return null;
  const id = P.sectionKey(a.section.slice("question:".length));
  const q = snap.questions?.bySection.get(id) ?? null;
  let words: string | null = q?.text ?? null;
  if (!words) {
    const doc = await goalDocument(sandboxRoot).catch(() => null);
    if (doc) words = (await import("./questions.ts")).goalQuestionText(doc.text, id, snap.goal.questions);
  }
  const name = q ? `${q.id}, revision ${q.rev}` : /^\d+$/.test(id) ? `Q-${id}` : a.section;
  const material = snap.goal.questions.map(P.sectionKey).includes(id) || !q || q.materiality === "material";
  const scope = [material ? "a material question" : "a question the operator marked not material", ...(snap.goal.existence.map(P.sectionKey).includes(id) || q?.expects === "existence" ? ["it asks whether something exists"] : []), ...(q?.completeness ? ["it asks for a complete set"] : [])];
  const cited = [...(a.support ?? []), ...(a.contrary ?? []), ...(a.limitations ?? [])].map((x) => snap.ledger.bySeq.get(x.seq)).filter((e): e is P.LedgerEntry => Boolean(e));
  const coverage = cited.filter((e) => e.kind === "coverage");
  const sources = await originalSources(sandboxRoot, cited.flatMap((e) => e.refs ?? []));
  const history: number[] = [];
  for (let e: P.LedgerEntry | undefined = a; typeof e?.supersedes === "number" && history.length < 50; e = snap.ledger.bySeq.get(e.supersedes)) history.push(e.supersedes);
  return [
    `Review it source-first. The question: ${name}: ${words ? `"${words}"` : `its words are in the goal (${a.section})`}.`,
    `Its scope: ${scope.join("; ")}.`,
    `The original sources its answer's coverage and cited entries lead back to: ${sources.length ? sources.join(", ") : "none named (read the question's leads and routes)"}.`,
    "Read the question against those sources before the answer under review, and weigh the strongest rival reading of them (another time, entity, mechanism, or the premise not holding).",
    `The answer under review is linked, not quoted: E-${a.seq} in ledger/ledger.md${history.length ? `, correcting ${history.map((n) => `E-${n}`).join(" ← ")}` : ""}${coverage.length ? `; its coverage ${coverage.map((c) => `E-${c.seq}`).join(", ")}` : ""}.`,
  ].join(" ");
}

/** The source-first packet of each answer offered to `agent` for review and not yet told it (reviewPacketWords): read as the offer is delivered. */
export async function reviewOfferPackets(sandboxRoot: string, agent: string, snap: LeadsSnapshot, before: Told): Promise<Map<string, string>> {
  const out = new Map<string, string>();
  const told = new Set(before.offers ?? []);
  for (const { key, offer } of reviewOffersFor(agent, snap)) {
    if (!key.startsWith("E-") || told.has(offer.seq)) continue;
    const words = await reviewPacketWords(sandboxRoot, snap, Number(key.slice(2))).catch(() => null);
    if (words) out.set(key, words);
  }
  return out;
}

/** The reviews offered to a seat now, each still held for it. */
export function reviewOffersFor(agent: string, snap: LeadsSnapshot): Array<{ key: string; offer: O.Offer }> {
  const out: Array<{ key: string; offer: O.Offer }> = [];
  for (const [key, list] of snap.state.reviewOffers) {
    const o = O.reservingOffer(list, snap.at, reviewRev(key, snap.state));
    if (o && o.to === agent) out.push({ key, offer: o });
  }
  return out;
}

export type LeadsDigest = {
  text: string;
  notices: LeadNotice[];
  counts: { open: number; active: number; blocked: number; closed: number; mine: number; awaiting: number; uncovered: number; questions?: { analyst: number; proposed: number; clarifications: number; triage: number } };
};

function lineOf(x: LeadView): string {
  return `${x.id} "${x.title}"${x.priority ? ` (priority ${x.priority})` : ""}${x.offered ? ` (offered to ${x.offered.to} until ${x.offered.until})` : ""}${x.covered_by?.length ? ` (a second route beside ${x.covered_by.join(", ")})` : ""}`;
}

/**
 * The header on every inbox and wait delivery, and the notices since the last
 * one. Whole: every lead it lists is named; a list is never cut to fit.
 */
export async function leadsDigest(ctx: P.SwarmContext, o: { mark?: boolean } = {}): Promise<LeadsDigest> {
  await reopenOnLedger(ctx.sandboxRoot).catch(() => undefined);
  // A review due goes to one seat (a route review, a negative's review): offered before the header is made, so it is delivered in it.
  await offerReviews(ctx.sandboxRoot).catch(() => 0);
  // What the question register committed and has not yet made good goes
  // first: what an act implies on the lead register (a withdrawal's leads
  // closed or sent to triage), then what it publishes (a crash between an
  // act and its effects, or its post, is made good here).
  const Q = await import("./questions.ts");
  await Q.reconcile(ctx.sandboxRoot).catch(() => undefined);
  await Q.deliverPending(ctx.sandboxRoot).catch(() => undefined);
  // An operator request committed on a lead's close, a clarification or a network item, and not yet written (docs/adr/0014).
  const R = await import("./requests.ts");
  await R.reconcileRequests(ctx.sandboxRoot).catch(() => undefined);
  // How each question stands, on the register's chain when it changed (an answer, a review, an acceptance).
  await Q.syncDispositions(ctx.sandboxRoot).catch(() => undefined);
  const snap = await leadsSnapshot(ctx.sandboxRoot);
  const me = ctx.agentId;
  const ranked = rankedLeads(snap);
  const open = ranked.filter((x) => x.status === "open");
  const mine = ranked.filter((x) => x.holder === me && x.status !== "closed");
  const blockedOnMe = ranked.filter((x) => x.status === "blocked" && x.holder !== me && x.needs.some((n) => !n.met && mine.some((m) => m.id === n.need.split(":")[0])));
  const awaiting = (await awaitingInterpretation(ctx.sandboxRoot, snap.state, snap.jobs, snap.ledger)).filter((a) => a.agent === me);
  const cov = questionCoverage(snap);
  const before = await readTold(ctx.sandboxRoot, me);
  const notices = noticesFor(me, before, snap, await reviewOfferWarnings(ctx.sandboxRoot, me, snap, before).catch(() => new Map<string, string[]>()), await reviewOfferPreparation(ctx.sandboxRoot, me, snap, before).catch(() => new Map<string, string>()), await reviewOfferPackets(ctx.sandboxRoot, me, snap, before).catch(() => new Map<string, string>()));
  // The register's part comes first: a person's question outranks the rest.
  const qTold = await Q.readTold(ctx.sandboxRoot, me);
  const qd = snap.questions ? Q.questionsDigest(me, { questions: snap.questions, leads: snap.state, ledger: snap.ledger }, qTold) : null;
  const lines: string[] = [...(qd?.lines ?? [])];
  const counts = {
    open: open.length,
    active: ranked.filter((x) => x.status === "active").length,
    blocked: ranked.filter((x) => x.status === "blocked").length,
    closed: ranked.filter((x) => x.status === "closed").length,
    mine: mine.length,
    awaiting: awaiting.length,
    uncovered: cov.uncovered.length,
  };
  lines.push(...(await negativeLines(ctx.sandboxRoot, snap)));
  lines.push(`Leads: ${counts.open} open, ${counts.active} active, ${counts.blocked} blocked, ${counts.closed} closed (leads for the whole register).`);
  for (const n of qd?.notices ?? []) lines.push(`NOTICE ${n.text}`);
  for (const n of notices) lines.push(`NOTICE ${n.text}`);
  lines.push(`Open, unheld, by priority: ${open.length ? open.map(lineOf).join("; ") : "none"}.`);
  // Holding nothing (the c10 pilot spent half its tokens so, a quarter of them waiting): sustained work is held.
  lines.push(`Yours: ${mine.length ? mine.map((x) => `${x.id} ${x.status}${x.status === "blocked" ? ` on ${x.needs.filter((n) => !n.met).map((n) => n.need).join(", ")}` : ""}${x.stale ? " (MARKED STALE: act on it)" : ""}`).join("; ") : "none. Sustained work (a review pass, a synthesis, a timeline, the report) is held: open or claim a lead for it, or take what is offered to you; each wake of a wait re-reads your whole context, so wait only when there is nothing to take"}.`);
  lines.push(`Blocked on you: ${blockedOnMe.length ? blockedOnMe.map((x) => `${x.id} (${x.holder ?? "unheld"}) needs ${x.needs.filter((n) => !n.met).map((n) => n.need).join(", ")}`).join("; ") : "none"}.`);
  lines.push(`Awaiting your interpretation: ${awaiting.length ? awaiting.map((a) => `${a.job}${a.lead ? ` (${a.lead})` : ""}${a.reinterpret ? `: its interpretation no longer stands, interpret it again (${a.why})` : ""}${a.unread_bytes ? `: ${a.unread_bytes} of ${a.total_bytes} stdout bytes unread, job_status offset ${a.next_offset}` : ""}`).join("; ") : "none"}.`);
  lines.push(`Questions nobody holds a lead for, with no answer yet: ${cov.uncovered.length ? cov.uncovered.map((q) => `question:${q}${cov.open_leads_for[q] ? ` (open: ${cov.open_leads_for[q].join(", ")})` : ""}`).join(", ") : "none"}.`);
  // This seat's running jobs that look stuck (B11): all three signals still, not near their timeout. A hint, never a cancel.
  const T = await import("../scripts/job-telemetry.ts");
  const stuck: string[] = [];
  for (const j of snap.jobs) {
    if (j.agent !== me || j.state !== "running") continue;
    const p = await T.jobProgressOnDisk(ctx.sandboxRoot, j.id).catch(() => null);
    if (p?.state === "suspected_stall") stuck.push(T.progressWords(j.id, p));
  }
  if (stuck.length) lines.push(`Your running jobs that look stuck: ${stuck.join("; ")}.`);
  // Parked leads (A2) and closures waiting for confirmation (A3): everyone sees them.
  const parked = await parkedLeads(ctx.sandboxRoot, snap).catch(() => [] as ParkedLead[]);
  if (parked.length) lines.push(`Parked (held, no job and no act on it for ${Math.round(parkMs() / 60_000)}+ min while the holder works elsewhere; offered to an idle seat unless the holder acts): ${parked.map((p) => `${p.lead} (${p.holder}, ${Math.round(p.idle_ms / 60_000)} min; ${p.elsewhere})`).join("; ")}.`);
  const confirming = ranked.filter((x) => x.confirm);
  if (confirming.length) lines.push(`Closures to confirm or reopen (their entry was superseded; nothing re-points them): ${confirming.map((x) => `${x.id} closed ${x.disposition} on ${x.confirm!.ref_was}${x.confirm!.head ? `, now ${x.confirm!.head}` : ""} (${x.confirm!.to ?? "nobody"} confirms)`).join("; ")}.`);
  // The finish (A4): whether the registers say it is ready, who coordinates it, and what this seat does about it.
  const F = await import("./finish.ts");
  const finish = await F.finishHeader(ctx.sandboxRoot, me).catch(() => null);
  if (finish) lines.push(finish);
  if (o.mark) {
    await writeTold(ctx.sandboxRoot, me, toldNow(me, snap, Object.keys(before.held)));
    if (snap.questions) await Q.markTold(ctx.sandboxRoot, me, snap.questions);
    // What was delivered now: each offer's first claim counts from here.
    await markOffersSeen(ctx.sandboxRoot, me, notices.filter((n) => n.offer !== undefined && n.kind !== "parked").flatMap((n) => n.batch ?? [{ lead: n.lead, offer: n.offer! }]));
    if (qd) await Q.markQuestionOffersSeen(ctx.sandboxRoot, me, qd.notices.filter((n) => n.kind === "offer" && n.offer !== undefined).map((n) => ({ q: n.q, offer: n.offer! }))).catch(() => undefined);
  }
  return { text: lines.join("\n"), notices: [...notices, ...(qd?.notices ?? []).map((n) => ({ kind: `question_${n.kind}` as LeadNotice["kind"], lead: n.q, text: n.text, wakes: n.wakes }))], counts: { ...counts, ...(qd ? { questions: qd.counts } : {}) } };
}

/**
 * The negative bar in the header: the material negatives nobody has
 * reviewed yet (the finish line waits for each), and the quick negatives
 * whose search nobody else has attested (a cue for review, never a
 * refusal). Nothing when there are none.
 */
export async function negativeLines(sandboxRoot: string, snap: LeadsSnapshot): Promise<string[]> {
  const out: string[] = [];
  const attestations = await P.readAttestations(sandboxRoot).catch(() => [] as P.LedgerAttestation[]);
  const unreviewed: string[] = [];
  const disputes = snap.ledger.disputes ?? [];
  for (const a of snap.ledger.entries) {
    if (a.kind !== "answer" || snap.ledger.replaced.has(a.seq) || !a.section?.startsWith("question:")) continue;
    const r = NB.answerResult(a);
    const id = P.sectionKey(a.section.slice("question:".length));
    // A negative by the gate's own test: a premise rejected on a search alone is one.
    if (!r || !P.negativeByResult(r, P.citedForQuestion(a, snap.ledger.bySeq, snap.ledger.replaced, id))) continue;
    const q = snap.questions?.bySection.get(id);
    const material = snap.goal.questions.includes(id) || !q || q.materiality === "material";
    if (!material) continue;
    const rev = P.negativeReview(a, snap.ledger.entries, attestations, disputes);
    if (rev.reviewed) continue;
    const cov = (a.support ?? []).map((x) => snap.ledger.bySeq.get(x.seq)).filter((e): e is P.LedgerEntry => e?.kind === "coverage");
    // Where its review counts, said when it is not simply the answer or any record it rests on.
    const targets = P.negativeReviewTargets(a, snap.ledger.entries, disputes).targets.filter((e) => P.isNegativeEntry(e));
    const plain = targets.length === 1 + cov.filter((c) => !snap.ledger.replaced.has(c.seq)).length && targets.some((e) => e.seq === a.seq);
    const where = !targets.length ? "; no coverage record it rests on stands: it is recorded again before a review counts" : plain ? "" : `; its review counts only as: ${reviewTargetWords(targets)}`;
    const offered = O.reservingOffer(snap.state.reviewOffers.get(`E-${a.seq}`) ?? [], snap.at, 1);
    unreviewed.push(`${a.section} (E-${a.seq} ${NB.resultWords(r)}, by ${a.authors.join(", ")}${cov.length ? `; coverage ${cov.map((c) => `E-${c.seq} ${c.coverage ?? "?"}`).join(", ")}` : "; no coverage record"}${where}${offered ? `; its review is ${offered.held_until ? `taken by ${offered.to}` : `offered to ${offered.to}`}` : ""})`);
  }
  if (unreviewed.length) out.push(`Negatives awaiting review by another seat (the finish line waits for each; attest the answer or its coverage record with review {detection, reproduced, other_route}): ${unreviewed.join("; ")}.`);
  const quick: string[] = [];
  for (const l of snap.state.leads.values()) {
    if (!l.quick_negative || l.closed?.disposition !== "negative") continue;
    const m = /^E-(\d+)$/.exec(l.closed.ref);
    const e = m ? snap.ledger.bySeq.get(Number(m[1])) : undefined;
    const attested = e ? attestations.some((x) => P.attestationAct(x) === "attest" && x.target === (e.hash ?? P.ledgerHash(e, "genesis")) && !e.authors.includes(x.by)) : false;
    if (attested) continue;
    quick.push(`${l.id} "${l.title}" (held ${Math.round(l.quick_negative.held_ms / 1000)} s, ${l.quick_negative.jobs} job(s), ${l.quick_negative.objects} object(s); ${l.closed.ref})`);
  }
  if (quick.length) out.push(`Quick negatives, each a cue for review (a search held under ${Math.round(NB.QUICK_NEGATIVE_HELD_MS / 60_000)} minutes, one job, one object, that nobody else has attested): ${quick.join("; ")}.`);
  return out;
}

async function writeTold(sandboxRoot: string, agent: string, told: Told): Promise<void> {
  const path = toldPath(sandboxRoot, agent);
  await mkdir(dirname(path), { recursive: true });
  const tmp = `${path}.${process.pid}.tmp`;
  await writeFile(tmp, `${JSON.stringify(told)}\n`, "utf8");
  await rename(tmp, path);
}

/** Cheap signature of the files the register's derived views read, so a waiting poll recomputes only when one changed. */
async function filesSignature(sandboxRoot: string): Promise<string> {
  const parts: string[] = [];
  for (const rel of [LEADS_LOG, P.LEDGER_ENTRIES, P.LEDGER_DISPUTES, "store/journal.jsonl", "questions/questions.jsonl"]) {
    const st = await stat(join(sandboxRoot, rel)).catch(() => null);
    parts.push(st ? `${st.size}:${st.mtimeMs}` : "-");
  }
  return parts.join("|");
}

/**
 * The check a waiting agent's wait makes each poll: a notice that wakes it
 * (its lead ready, a need that will not come, its lead marked stale or taken
 * over or reopened, the operator's note, a wake for an open lead), and, when
 * it is the seat idle longest, the wake for a ready lead nobody holds and no
 * seat was woken for (so a wake a crashed hub never wrote is still made).
 * Returns the words that wake it, or null.
 */
export function leadsWaitCheck(ctx: P.SwarmContext): () => Promise<string | null> {
  let sig = "";
  let lastElection = 0;
  return async () => {
    const now = Date.now();
    const next = await filesSignature(ctx.sandboxRoot);
    const due = now - lastElection > 5_000;
    if (next === sig && !due) return null;
    sig = next;
    // A confirmation window that lapsed reopens its lead here too, so a waiting seat sees it.
    if (due) await reopenOnLedger(ctx.sandboxRoot, now).catch(() => undefined);
    if (due) await offerReviews(ctx.sandboxRoot, now).catch(() => 0);
    const snap = await leadsSnapshot(ctx.sandboxRoot);
    const before = await readTold(ctx.sandboxRoot, ctx.agentId);
    const waking = noticesFor(ctx.agentId, before, snap, await reviewOfferWarnings(ctx.sandboxRoot, ctx.agentId, snap, before).catch(() => new Map<string, string[]>()), await reviewOfferPreparation(ctx.sandboxRoot, ctx.agentId, snap, before).catch(() => new Map<string, string>()), await reviewOfferPackets(ctx.sandboxRoot, ctx.agentId, snap, before).catch(() => new Map<string, string>())).filter((n) => n.wakes);
    // The question register's news for this seat: an offer, a clarification answered, its question amended or withdrawn.
    const Q = await import("./questions.ts");
    const qWaking = snap.questions ? Q.questionNotices(ctx.agentId, await Q.readTold(ctx.sandboxRoot, ctx.agentId), { questions: snap.questions, leads: snap.state, ledger: snap.ledger }).filter((n) => n.wakes) : [];
    if (waking.length || qWaking.length) {
      // Delivered now: each offer's first claim counts from here (A3).
      await markOffersSeen(ctx.sandboxRoot, ctx.agentId, waking.filter((n) => n.offer !== undefined && n.kind !== "parked").flatMap((n) => n.batch ?? [{ lead: n.lead, offer: n.offer! }]));
      await Q.markQuestionOffersSeen(ctx.sandboxRoot, ctx.agentId, qWaking.filter((n) => n.kind === "offer" && n.offer !== undefined).map((n) => ({ q: n.q, offer: n.offer! }))).catch(() => undefined);
      return [...qWaking, ...waking].map((n) => n.text).join(" ");
    }
    if (!due) return null;
    lastElection = now;
    // A person's question nobody has taken, past its suggested seat's offer, goes to the most suited idle seat.
    await Q.deliverPending(ctx.sandboxRoot).catch(() => undefined);
    const offered = await Q.electQuestionOffer(ctx, now, snap.questions ? { questions: snap.questions, leads: snap.state, ledger: snap.ledger } : undefined).catch(() => null);
    if (offered) return `${offered.q.id} is offered to you (you are idle and the most suited), first claim ${O.untilWords(offered.offer, Date.now(), offered.q.rev)}: "${offered.q.text}" (${Q.originWords(offered.q.origin)}). Take it with lead_open(answers: ["${offered.q.id}"], take: true, proposition, negation), or offer decline ${offered.q.id} with why; nobody owns it.`;
    const won = await electOffer(ctx, snap, now);
    return won ? won.text : null;
  };
}

/**
 * The offers a waiting seat makes to itself (A3): a ready lead nobody holds
 * and nothing is offered, or a parked lead (A2), goes to the idle seat that
 * waited longest among those not yet offered it at this revision; that seat
 * elects it for itself, under the lock, so two waits never both take it. A
 * lead whose questions another held lead covers is left for its opener's
 * second route, not offered. The offer is delivered as it is made.
 */
async function electOffer(ctx: P.SwarmContext, outer: LeadsSnapshot, now = Date.now()): Promise<{ lead: string; text: string } | null> {
  const offeredHere = (l: Lead, agent: string) => l.offers.some((o) => o.to === agent && o.rev === l.rev);
  const eligible = (snap: LeadsSnapshot, parked: Set<string>) =>
    [...snap.state.leads.values()]
      .filter((l) => !l.closed && !O.reservingOffer(l.offers, now, l.rev))
      .filter((l) => (!l.holder && leadStatus(l, snap.state, snap.ledger) === "open" && !(l.covered_by?.length && overlappingLeads(snap, l.answers, "", l.id).length)) || parked.has(l.id));
  const parkedOuter = new Set((await parkedLeads(ctx.sandboxRoot, outer, now).catch(() => [] as ParkedLead[])).map((p) => p.lead));
  const candidates = eligible(outer, parkedOuter);
  if (!candidates.length) return null;
  const idle = await idleSeats(ctx.sandboxRoot, outer.state, outer.ledger, outer.jobs, now, outer.questions);
  // Is this seat the one each candidate goes to? The first idle seat, in order, not yet offered it.
  const mine = candidates.filter((l) => idle.find((x) => x.agent !== l.holder && !offeredHere(l, x.agent))?.agent === ctx.agentId);
  if (!mine.length) return null;
  const r = await transact<{ ok: true; lead: string | null }>(ctx.sandboxRoot, async (snap) => {
    // One offer at a time, across both registers, read again under the lock.
    if ((await offeredSeats(ctx.sandboxRoot, snap.state, now, snap.questions)).has(ctx.agentId)) return { append: [], result: { ok: true as const, lead: null as string | null } };
    const parked = new Set((await parkedLeads(ctx.sandboxRoot, snap, now).catch(() => [] as ParkedLead[])).map((p) => p.lead));
    const still = eligible(snap, parked)
      .filter((l) => mine.some((m) => m.id === l.id) && !offeredHere(l, ctx.agentId) && l.holder !== ctx.agentId)
      .map((l) => ({ l, v: viewLead(l, snap) }))
      // Work nobody holds first, by priority then age; parked leads after.
      .sort((a, b) => Number(Boolean(a.l.holder)) - Number(Boolean(b.l.holder)) || b.v.priority - a.v.priority || a.v.opened_at.localeCompare(b.v.opened_at));
    const pick = still[0]?.l;
    if (!pick) return { append: [], result: { ok: true as const, lead: null as string | null } };
    const append: LeadDraft[] = [];
    // A lapsed offer before it is written down, for the record.
    for (const o of pick.offers) if (!o.lapsed_at && !o.accepted && !o.declined && o.rev === pick.rev && O.offerStatus(o, now, pick.rev).state === "lapsed") append.push({ by: "system", ev: "offer_lapse", lead: pick.id, offer: o.seq, to: o.to, why: "its first claim ran out" });
    const reason: O.OfferReason = pick.holder ? "parked" : "wake";
    append.push(offerDraft(pick.id, ctx.agentId, reason, pick.rev, pick.cycle, now, pick.holder ? { from: pick.holder } : {}));
    return { append, result: { ok: true as const, lead: pick.id } };
  }).catch(() => null);
  if (!r?.lead) return null;
  // Delivered as it is made: the seat's wait returns it now.
  const made = r.events.find((e) => e.ev === "offer");
  if (made) await markOffersSeen(ctx.sandboxRoot, ctx.agentId, [{ lead: r.lead, offer: made.seq }]);
  const snap = await leadsSnapshot(ctx.sandboxRoot);
  const l = snap.state.leads.get(r.lead)!;
  const o = l.offers.find((x) => x.seq === made?.seq);
  return { lead: r.lead, text: o ? offerText(l, o, ctx.agentId, snap) : `${r.lead} is offered to you: lead_claim ${r.lead} to take it` };
}

// --- the views an agent asks for ----------------------------------------------------------------

export const LEADS_VIEWS = ["summary", "open", "mine", "blocked", "active", "closed", "all", "jobs", "questions"] as const;

/**
 * The register as an agent reads it: a view (or one lead by id), whole leads
 * a page at a time. `next` names where the next page starts; nothing is cut.
 */
export async function leadsView(ctx: P.SwarmContext, o: { view?: string; from?: string; pageChars?: number } = {}): Promise<Record<string, unknown>> {
  await reopenOnLedger(ctx.sandboxRoot).catch(() => undefined);
  const snap = await leadsSnapshot(ctx.sandboxRoot);
  const view = String(o.view ?? "summary").trim();
  const one = leadRef(view);
  if (one.ok) {
    const l = snap.state.leads.get(one.id);
    if (!l) return { ok: false, reason: `${one.id} does not exist` };
    const history = snap.state.events.filter((e) => e.lead === one.id || (e.job && l.jobs.includes(e.job) && e.ev === "interpret")).map(({ prev: _p, hash: _h, v: _v, ...e }) => e);
    const awaiting = (await awaitingInterpretation(ctx.sandboxRoot, snap.state, snap.jobs, snap.ledger)).filter((a) => a.lead === one.id);
    return { ok: true, lead: viewLead(l, snap), history, awaiting_interpretation: awaiting };
  }
  if (!(LEADS_VIEWS as readonly string[]).includes(view)) return { ok: false, reason: `view is one of ${LEADS_VIEWS.join(", ")}, or a lead's id (L-3)` };
  if (view === "summary") {
    const digest = await leadsDigest(ctx, { mark: false });
    return { ok: true, view, summary: digest.text, counts: digest.counts, chain: snap.state.chain.ok ? "intact" : `BROKEN at line ${snap.state.chain.broken_at} (${snap.state.chain.reason})` };
  }
  if (view === "jobs") {
    const awaiting = await awaitingInterpretation(ctx.sandboxRoot, snap.state, snap.jobs, snap.ledger);
    return { ok: true, view, awaiting_interpretation: awaiting, note: "A job waits for an interpretation until an entry is recorded with interprets naming it (and, when its stdout was handed over in part, rest saying how the rest was read or why not). A lead's jobs hold the finish line; an agent's others are only shown." };
  }
  if (view === "questions") {
    const cov = questionCoverage(snap);
    // The register beside the goal's list: every question with its origin (a person's first), scope and state.
    const Q = await import("./questions.ts");
    const register = snap.questions
      ? Q.questionViews({ questions: snap.questions, leads: snap.state, ledger: snap.ledger }).map((v) => ({
          id: v.id,
          section: `question:${v.section}`,
          origin: v.origin.kind,
          author: v.author,
          text: v.text,
          rev: v.rev,
          scope: v.scope,
          work: v.work,
          answered: v.answer ? `E-${v.answer.seq}${v.answer.stale ? " (stale)" : ""}` : null,
          leads: v.leads.map((l) => l.id),
          ...(v.withdrawn ? { withdrawn: true } : {}),
        }))
      : [];
    return { ok: true, view, questions: caseQuestions(snap), existence: snap.goal.existence, answered: [...snap.answered].sort(), unanswered: cov.unanswered, uncovered: cov.uncovered, open_leads_for: cov.open_leads_for, source: snap.goal.source, register };
  }
  const ranked = rankedLeads(snap);
  const pick = ranked.filter((x) =>
    view === "all" ? true : view === "mine" ? x.holder === ctx.agentId && x.status !== "closed" : x.status === view,
  );
  const start = o.from ? Math.max(0, pick.findIndex((x) => x.id === o.from)) : 0;
  const pageChars = o.pageChars && o.pageChars > 0 ? o.pageChars : P.inboxPageChars();
  const page: LeadView[] = [];
  let chars = 0;
  for (const x of pick.slice(start)) {
    const size = JSON.stringify(x).length;
    if (page.length && chars + size > pageChars) break;
    page.push(x);
    chars += size;
  }
  const rest = pick.length - start - page.length;
  return { ok: true, view, n: pick.length, leads: page, remaining: rest, ...(rest > 0 ? { next: pick[start + page.length].id, note: `${rest} more lead(s) in this view, held back to keep this page under ${pageChars} characters; nothing was cut. Call leads again with from: "${pick[start + page.length].id}".` } : {}) };
}

// --- the finish line ---------------------------------------------------------------------------

export type LeadDefect = { code: "open_lead" | "uninterpreted_job"; lead?: string; job?: string; what: string; fix: string };

/**
 * What the register holds against a done: a material lead with no
 * disposition (open_lead), and a material lead's job with no interpretation
 * or with output unread and unexplained (uninterpreted_job). An agent's own
 * jobs outside a lead are never a defect.
 */
export async function leadDefects(sandboxRoot: string, snap?: LeadsSnapshot): Promise<{ defects: LeadDefect[]; limiting: Array<{ lead: string; disposition: LeadDisposition; ref: string }>; chain: LeadsState["chain"] }> {
  const s = snap ?? (await leadsSnapshot(sandboxRoot));
  const defects: LeadDefect[] = [];
  for (const l of s.state.leads.values()) {
    // A closure whose entry was superseded stands only once its closer confirms it (A3).
    if (l.material && l.closed && l.confirm) {
      defects.push({
        code: "open_lead",
        lead: l.id,
        what: `${l.id} "${l.title}" was closed ${l.closed.disposition} on ${l.confirm.ref_was}, since superseded${l.confirm.head ? ` by ${l.confirm.head}` : ""}: its closure waits for its closer's confirmation`,
        fix: `its closer confirms it on what stands (lead_confirm ${l.id} with ref and why) or reopens it (lead_reopen); unconfirmed, it reopens by itself`,
      });
      continue;
    }
    if (!l.material || l.closed) continue;
    const st = leadStatus(l, s.state, s.ledger);
    defects.push({
      code: "open_lead",
      lead: l.id,
      what: `${l.id} "${l.title}" is ${st}${l.holder ? ` (held by ${l.holder})` : ""} with no disposition`,
      fix: `close it with lead_close ${l.id}: resolved citing the entry that settles it (E-<seq>), negative citing the absence, duplicate citing the lead it repeats, deferred or infeasible citing the limitation, or needs_operator saying what the operator must do`,
    });
  }
  const awaiting = await awaitingInterpretation(sandboxRoot, s.state, s.jobs, s.ledger);
  for (const a of awaiting) {
    if (!a.lead) continue;
    const l = s.state.leads.get(a.lead);
    if (!l?.material) continue;
    defects.push({
      code: "uninterpreted_job",
      lead: a.lead,
      job: a.job,
      what: `${a.job}, run under ${a.lead}, ${a.why}`,
      fix: a.unread_bytes
        ? `read the rest (job_status ${a.job} offset ${a.next_offset}) and record what it shows with interprets: ["${a.job}"], or record with interprets: [{job: "${a.job}", rest: "how the rest was read, or why not"}]`
        : `record what its output shows (a finding, an absence or a limitation) with interprets: ["${a.job}"]`,
    });
  }
  const limiting = [...s.state.leads.values()]
    .filter((l) => l.material && l.closed && LIMITING_DISPOSITIONS.has(l.closed.disposition))
    .map((l) => ({ lead: l.id, disposition: l.closed!.disposition, ref: l.closed!.ref }));
  return { defects, limiting, chain: s.state.chain };
}

// --- the rendered register ----------------------------------------------------------------------

export function renderLeadsMd(snap: LeadsSnapshot): string {
  const ranked = rankedLeads(snap);
  const lines: string[] = ["# Leads", "", "The swarm's investigative work: what was found to follow, who holds it, what it needs, and how it ended. Rendered by the harness from `leads/leads.jsonl` after every change; do not edit.", ""];
  lines.push(`Chain: ${snap.state.chain.ok ? `intact, ${snap.state.events.length} events` : `BROKEN at line ${snap.state.chain.broken_at} (${snap.state.chain.reason})`}.`, "");
  const groups: Array<[string, LeadView[]]> = [
    ["Active", ranked.filter((x) => x.status === "active")],
    ["Blocked", ranked.filter((x) => x.status === "blocked")],
    ["Open", ranked.filter((x) => x.status === "open")],
    ["Closed", ranked.filter((x) => x.status === "closed")],
  ];
  for (const [name, list] of groups) {
    lines.push(`## ${name} (${list.length})`, "");
    if (!list.length) lines.push("None.", "");
    for (const x of list) {
      lines.push(`### ${x.id}: ${x.title}`, "");
      lines.push(`- Why: ${x.why}`);
      lines.push(`- Origin: ${x.origin}; opened by ${x.opened_by} at ${x.opened_at}${x.material ? "" : "; not material"}`);
      if (x.holder) lines.push(`- Held by ${x.holder}, generation ${x.generation}, since ${x.held_since}${x.stale ? `; MARKED STALE at ${x.stale.at}` : ""}`);
      if (x.overlap) lines.push(`- Held as ${x.overlap.kind === "verification" ? "a verification" : "a second route"} by ${x.overlap.by}: ${x.overlap.why}`);
      if (x.covered_by?.length) lines.push(`- Opened unheld: its questions were covered by ${x.covered_by.join(", ")}`);
      if (x.offered) lines.push(`- Offered to ${x.offered.to} (${x.offered.reason}${x.offered.from ? `, from ${x.offered.from}` : ""}), first claim until ${x.offered.until} (at revision ${x.rev})`);
      if (x.needs.length) lines.push(`- Needs: ${x.needs.map((n) => `${n.need} (${n.met ? "met" : `unmet: ${n.why}`}; ${n.outcome})`).join("; ")}`);
      for (const d of x.dropped ?? []) lines.push(`- Need dropped at ${d.at} by ${d.by}: ${d.need} (withdrawn, never met: ${d.why})`);
      if (x.answers.length) lines.push(`- Answers: ${x.answers.map((a) => `question:${a}`).join(", ")}`);
      if (x.proposition) lines.push(`- Tests: ${x.proposition}; against: ${x.negation ?? ""}`);
      if (x.product) lines.push(`- ${x.opened_by === "operator" ? "Directive's product" : "Product"}: ${x.product}; accepted when: ${x.acceptance ?? ""}`);
      if (x.inputs?.length) lines.push(`- Starts from: ${x.inputs.join(", ")}`);
      if (x.next_action) lines.push(`- Next action once accepted: ${x.next_action}`);
      if (x.routes.length) lines.push(`- Route plan: ${x.routes.map(NB.routeWords).join("; ")}`);
      if (x.priority) lines.push(`- Waiting on it: ${x.waiting_on_it.leads.length} lead(s)${x.waiting_on_it.leads.length ? ` (${x.waiting_on_it.leads.join(", ")})` : ""}, ${x.waiting_on_it.questions.length} unanswered question(s)${x.waiting_on_it.questions.length ? ` (${x.waiting_on_it.questions.map((q) => `question:${q}`).join(", ")})` : ""}`);
      if (x.jobs.length) lines.push(`- Jobs: ${x.jobs.join(", ")}`);
      if (x.disposition) lines.push(`- Closed ${x.disposition} by ${x.closed_by} at ${x.closed_at}: ${x.ref}${x.close_why ? ` (${x.close_why})` : ""}`);
      if (x.result_refs?.length) lines.push(`- Delivered: ${x.result_refs.join(", ")}`);
      if (x.confirm) lines.push(`- CLOSURE TO CONFIRM: closed on ${x.confirm.ref_was}, superseded since ${x.confirm.since}${x.confirm.head ? ` (now ${x.confirm.head})` : ""}; ${x.confirm.to ? `offered to ${x.confirm.to} to confirm or reopen` : "its closer cannot take it"}`);
      for (const c of x.confirmed ?? []) lines.push(`- Closure confirmed at ${c.at} by ${c.by}: ${c.from} -> ${c.to} (${c.why})`);
      if (x.quick_negative) lines.push(`- Quick negative (a review cue): held ${Math.round(x.quick_negative.held_ms / 1000)} s, ${x.quick_negative.jobs} job(s), ${x.quick_negative.objects} object(s)`);
      if (x.not_examined?.length) lines.push(`- Planned routes not examined: ${x.not_examined.map((r) => `${r.source} (${r.method}): ${r.why}`).join("; ")}`);
      for (const r of x.reopened) lines.push(`- Reopened at ${r.at} by ${r.by} (${r.cause}): ${r.why}`);
      for (const r of x.route_reviews ?? []) lines.push(`- Route reviewed at ${r.at} by ${r.by}: limitation ${r.material ? "still material" : "no longer material"} (${r.why})`);
      for (const n of x.notes) lines.push(`- Operator note at ${n.at}: ${n.text}${n.allow_host ? ` (allowed host: ${n.allow_host})` : ""}`);
      lines.push("");
    }
  }
  return `${lines.join("\n").trimEnd()}\n`;
}

export async function writeLeadsMd(sandboxRoot: string): Promise<void> {
  const snap = await leadsSnapshot(sandboxRoot);
  await mkdir(join(sandboxRoot, LEADS_DIR), { recursive: true });
  await P.writeFileAtomic(join(sandboxRoot, LEADS_MD), renderLeadsMd(snap));
}

// --- until solved: the regroup ------------------------------------------------------------------

/** The last moment the run moved: a standing entry recorded, a lead closed, a job committed. */
export async function lastProgress(sandboxRoot: string, snap: LeadsSnapshot, startedAt: string): Promise<{ at: number; what: string }> {
  let best = { at: Date.parse(startedAt) || 0, what: "the run's start" };
  const take = (iso: string | undefined, what: string) => {
    const t = iso ? Date.parse(iso) : NaN;
    if (Number.isFinite(t) && t > best.at) best = { at: t, what };
  };
  for (const e of snap.ledger.entries) if (!snap.ledger.replaced.has(e.seq)) take(e.at, `E-${e.seq} (${e.kind})`);
  for (const e of snap.state.events) if (e.ev === "close") take(e.at, `${e.lead} closed ${e.disposition}`);
  for (const j of snap.jobs) if (j.state === "committed") take(j.finished_at, `${j.id} committed`);
  return best;
}

/**
 * The evidence the catalogue knows that no standing entry cites: an input
 * file no ref names (directly, or through a catalogued member of it), and a
 * catalogued object (an archive's members, a disk's volumes) no ref reaches.
 * Generic: the catalogue says what it holds; nothing here reads a format.
 */
export async function uncitedEvidence(sandboxRoot: string, snap: LeadsSnapshot): Promise<string[]> {
  const refs = new Set<string>();
  for (const e of snap.ledger.entries) if (!snap.ledger.replaced.has(e.seq)) for (const r of e.refs ?? []) refs.add(r);
  const gens: Array<{ id: string; ref: string; name: string; what: string }> = [];
  for (const g of await readdir(join(sandboxRoot, "catalog", "gen")).catch(() => [] as string[])) {
    const raw = await readFile(join(sandboxRoot, "catalog", "gen", g, "generation.json"), "utf8").catch(() => null);
    if (!raw) continue;
    try {
      const j = JSON.parse(raw) as { id?: string; target?: { ref?: string; name?: string }; coverage?: { covered?: string; members?: number }; recipe?: string };
      gens.push({ id: j.id ?? g, ref: j.target?.ref ?? "", name: j.target?.name ?? j.target?.ref ?? g, what: [j.coverage?.covered, j.coverage?.members !== undefined ? `${j.coverage.members} listed` : ""].filter(Boolean).join(", ") || (j.recipe ?? "") });
    } catch {
      // skipped
    }
  }
  const cited = (ref: string) => [...refs].some((r) => r === ref || r.startsWith(`${ref}/`));
  const genCited = (g: { id: string; ref: string }) => [...refs].some((r) => r.startsWith(`member:${g.id}#`)) || (g.ref ? cited(g.ref) : false);
  const out: string[] = [];
  const manifest = await P.readInputsManifest(sandboxRoot).catch(() => null);
  for (const f of manifest?.files ?? []) {
    const ref = `input:${f.path.replace(/^inputs\//, "")}`;
    const viaGen = gens.some((g) => g.ref === ref && genCited(g));
    if (!cited(ref) && !viaGen) out.push(`${f.path} (${f.bytes} bytes)`);
  }
  // A catalogued object made from a job's output (an extracted archive, a
  // decrypted volume) that no ref reaches; one made from an input is said
  // with its input above.
  for (const g of gens) if (!genCited(g) && !g.ref.startsWith("input:")) out.push(`catalogue ${g.id}: ${g.name}${g.what ? ` (${g.what})` : ""}`);
  return out;
}

/** How each goal question stands for the regroup: no answer, or an answer that does not settle it. */
export function questionStanding(snap: LeadsSnapshot): Array<{ id: string; why: string; blocks: string[] }> {
  const out: Array<{ id: string; why: string; blocks: string[] }> = [];
  for (const q of snap.goal.questions) {
    if (withdrawnSection(snap, q)) continue;
    const a = snap.ledger.entries.find((e) => e.kind === "answer" && e.section === `question:${q}` && !snap.ledger.replaced.has(e.seq));
    let why = "";
    if (!a) why = "no answer";
    else if (a.inconclusive) why = `answer E-${a.seq} is inconclusive`;
    else if (!(a.support ?? []).length && (a.limitations ?? []).length) why = `answer E-${a.seq} rests on limitations only`;
    else if (snap.goal.existence.length && !snap.goal.existence.includes(q)) {
      const kinds = (a.support ?? []).map((x) => snap.ledger.bySeq.get(x.seq)?.kind);
      if (kinds.length && kinds.every((k) => k === "absence")) why = `answer E-${a.seq} rests on a search that found nothing, and the question asks for more than whether it exists`;
    }
    if (!why) continue;
    const blocks: string[] = [];
    for (const l of snap.state.leads.values()) {
      if (!l.answers.includes(q)) continue;
      const st = leadStatus(l, snap.state, snap.ledger);
      if (st === "closed") {
        if (LIMITING_DISPOSITIONS.has(l.closed!.disposition)) blocks.push(`${l.id} closed ${l.closed!.disposition}: ${l.closed!.ref}`);
        continue;
      }
      blocks.push(`${l.id} ${st}${l.holder ? ` (${l.holder})` : " (nobody holds it)"}${st === "blocked" ? ` on ${l.needs.filter((n) => !needState(n, snap.state, snap.ledger).met).join(", ")}` : ""}`);
    }
    out.push({ id: q, why, blocks });
  }
  return out;
}

/** The regroup post: what is open, what is blocked, what waits on the operator, and what nobody has cited. */
export async function regroupMessage(sandboxRoot: string, snap: LeadsSnapshot, o: { minutes: number; since: { at: number; what: string }; count: number; nextMinutes: number; running?: string[] }): Promise<string> {
  const ranked = rankedLeads(snap);
  const qs = questionStanding(snap);
  const open = ranked.filter((v) => v.status === "open");
  const blocked = ranked.filter((v) => v.status === "blocked");
  const operator = ranked.filter((v) => v.disposition === "needs_operator");
  const uncited = await uncitedEvidence(sandboxRoot, snap);
  const lines: string[] = [];
  lines.push(`REGROUP ${o.count}: nothing has moved for ${o.minutes} minutes: no new standing entry, no lead closed and no job committed since ${new Date(o.since.at).toISOString()} (${o.since.what}). This run is until solved, so it goes on until every question has a disposition under the bar; find another route, or, where the evidence cannot answer a question, dispose of it under the bar (a coverage record over the routes searched, another seat's review, then not_determinable).`);
  lines.push("", `Questions not answered (${qs.length}):`);
  for (const q of qs) lines.push(`- question:${q.id}: ${q.why}${q.blocks.length ? `; ${q.blocks.join("; ")}` : "; no lead names it"}`);
  if (!qs.length) lines.push("- none by the ledger: the finish line says what still holds done (call done, and read its refusal).");
  lines.push("", `Leads open, held by nobody (${open.length}):`);
  for (const v of open) lines.push(`- ${v.id} "${v.title}"${v.priority ? ` (${v.priority} waiting on it)` : ""}`);
  if (!open.length) lines.push("- none");
  lines.push("", `Leads blocked (${blocked.length}):`);
  for (const v of blocked) lines.push(`- ${v.id} "${v.title}"${v.holder ? ` (${v.holder})` : ""} waiting on ${v.needs.filter((n) => !n.met).map((n) => `${n.need}: ${n.why}`).join("; ")}`);
  if (!blocked.length) lines.push("- none");
  lines.push("", `Waiting on the operator (${operator.length}):`);
  for (const v of operator) lines.push(`- ${v.id} "${v.title}": ${v.ref}`);
  if (!operator.length) lines.push("- none");
  if (o.running?.length) {
    lines.push("", `Jobs running under leads (${o.running.length}): each was nudged to its holder a window ago; a running job does not hold this off for ever:`);
    for (const r of o.running) lines.push(`- ${r}`);
  }
  lines.push("", `Evidence no standing entry cites (${uncited.length}):`);
  for (const u of uncited) lines.push(`- ${u}`);
  if (!uncited.length) lines.push("- none");
  lines.push(
    "",
    "Each of you: say on the board which route you take next. An artefact above that no entry cites, a lead nobody holds (lead_claim), a need that can be met another way (lead_link), a question with no lead (lead_open), a job whose output nobody read to its end, a question whose routes are searched and which is to be disposed of under the bar (coverage record, review, not_determinable), or what only the operator can give (lead_close needs_operator, saying what). " +
      `If nothing moves, the next regroup comes in ${o.nextMinutes} minutes.`,
  );
  return lines.join("\n");
}
