/**
 * The finish: one coordinator, one check result per revision, readiness
 * shown to everyone, and typed acts around the report (docs/adr/0015).
 *
 * On ctf12 every seat called `done` when the last attest landed: Belka had
 * nine calls by six seats in 58 s and three sentinels in one second, c09 all
 * eight seats in 61 s, and the tail from every question answered to the
 * sentinel ran 33 to 64 minutes. Three things fed it, each verified in the
 * code: the late-posts rule fired once per seat and asked each to explain
 * itself on the board, which made the next seat's late post; historical
 * limiting closes blocked after their questions were answered; and the
 * prompt told every seat to call done. Here:
 *
 * - One coordinator holds the finish, by a lease with a generation in
 *   `leads/finish.jsonl` (a chain, the lead register's helpers). It is the
 *   seat that published the report last when the lease is first needed, or
 *   the first seat to call done; a seat that is done, dead, compacting or
 *   silent past the stale limit is unavailable, and the next seat's done
 *   takes the lease over (generation + 1). Any other seat's `done` is
 *   answered "not yours", quietly: no board post, no finish line run, not a
 *   refusal.
 * - Readiness is computed from the registers for every revision (the open
 *   leads, the questions' answers and the ledger gate over them, the
 *   negatives, best candidates and route limitations), shown in every
 *   header, and posted once each time it turns ready or back.
 * - A check (the operator's finish line run for a done) is recorded with
 *   the revision it ran against, and a done at the same revision takes that
 *   result instead of running it again.
 * - The report is reviewed with typed acts: an ack of its digest ("no
 *   objection") is not a late post; an objection, or a result or veto
 *   posted after the report was written, needs the coordinator's typed
 *   resolution (folded into the report, or not material, with why) before
 *   the done goes on. Reading them is not enough.
 * - The final check is atomic over the report's digest and the state
 *   revision (protocol.ts stateRevision: the board's verdict posts, the
 *   ledger and its review, the leads, the questions, the jobs, the policy
 *   and the operator's decisions): the sentinel is written only while that
 *   revision still holds.
 * - The coordinator prepares the finish before its done (`finish prepare`,
 *   docs/adr/0015 "Preparing the finish"): the lease and the report's
 *   boundary are taken as a done takes them, with no goal check and no
 *   sentinel, and what is late against the report is listed whole, so it is
 *   resolved before the done rather than by a refused one (s993d40,
 *   sa2f2f2 and s5764c4: every first done was refused on late items, since
 *   only a done made the lease the late list needs). Late items are resolved
 *   in one typed batch, each item its own resolution event, against the
 *   generation and the report's digest the coordinator read, with an
 *   idempotency key. A resume opens a new segment of the finish and keeps
 *   what was still late by name.
 *
 * Nothing here judges an answer or reads a case: the registers say what is
 * open, and the operator's checks say whether the goal is met.
 */

import { createHash } from "node:crypto";
import { existsSync } from "node:fs";
import type { Dirent } from "node:fs";
import { appendFile, mkdir, readdir, readFile, stat } from "node:fs/promises";
import { join } from "node:path";
import * as L from "./leads.ts";
import * as NB from "./negative-bar.ts";
import * as P from "./protocol.ts";
import { boundItems } from "./reply-bound.ts";
import { firstLine } from "./answer-format.ts";

export const FINISH_LOG = "leads/finish.jsonl";
/** How a done that is not the coordinator's is answered: quietly, never as a refusal. */
export const NOT_YOURS = "not yours: ";
/** The finish register's own lock: a lease is taken and a check recorded under it, never under the registers' (a done's sentinel is). */
const FINISH_LOCK = ".finish.lock";

export type FinishEventKind = "lease" | "ack" | "resolve" | "readiness" | "check" | "phase" | "prepare" | "carry";

/** A late post kept by name across a resume (FinishEvent.carried): its id, who posted it, and its tag. */
export type CarriedPost = { id: number; by: string; tag: string };

/**
 * A seat's review as a carry event records it for a version of the report
 * (docs/adr/0015, "A review carries over"): the acks it rests on, and the
 * sections it still covers unchanged (kept), or those to review again
 * (reasked: changed since, added to a review of the whole report, or
 * removed from one).
 */
export type ReviewCarry = { by: string; acks: number[]; sections?: string[]; changed?: string[]; removed?: string[] };

export type FinishEvent = {
  v: 1;
  seq: number;
  at: string;
  by: string;
  ev: FinishEventKind;
  /** lease: who holds it now, at which generation, whom it was taken from, and why; resolve (a batch's item) and prepare: the generation the coordinator acted at. */
  holder?: string;
  generation?: number;
  from?: string;
  why?: string;
  /** lease and prepare: the report the finish stands on (the path a done or a prepare names). */
  report?: string;
  /**
   * lease: when the report was written as the finish began (ms since the
   * epoch): a result or veto posted after it is late against the report, and
   * stays so through every later version of it until a resolution answers it.
   * prepare: the boundary in force when the coordinator prepared.
   */
  since?: number;
  /**
   * lease: the resume segment it belongs to (budget.json `resumes`: 1 after
   * the first resume); absent in the run's first segment. A lease of a later
   * segment than the lease before it opens that segment (a resume): its
   * `since` is the new segment's boundary, and `carried` names each post
   * still late when the run was resumed.
   */
  segment?: number;
  /** lease opening a segment: each post of the segments before that was late against the report and that no resolution answered, kept as an obligation by name. */
  carried?: CarriedPost[];
  /** ack: the report it reviewed (named by the reviewer before a coordinator's done named one), the report's digest the review is of, and its verdict; prepare: the report's digest the coordinator prepared on; carry: the version the reviews are weighed for. */
  digest?: string;
  verdict?: "no_objection" | "objection";
  /**
   * ack (versioned: present on acks recorded since 2026-09-29): each section
   * of the report the review covered, by its key, with the section's digest
   * in the version reviewed (reportSections); `whole` when the reviewer
   * named none, so it covered every section there was. An ack without them
   * is of the whole report at its digest, as before.
   */
  sections?: Record<string, string>;
  whole?: boolean;
  /** carry: the reviews of earlier versions that still stand for this one, their sections unchanged, and those asked again on what changed. */
  kept?: ReviewCarry[];
  reasked?: ReviewCarry[];
  /** resolve: the late post (its id) or the objection (its ack's seq) it resolves, and how; ack and resolve: the report's digest (a folded resolution names the version it was folded into). */
  post?: number;
  ack?: number;
  how?: "folded" | "not_material";
  /** resolve: the batch it was one item of, by its idempotency key (finish resolve with items). */
  batch?: string;
  /** prepare: what was late against the report when the coordinator prepared, by kind and id (the list it was given, whole). */
  late?: Array<{ kind: "post" | "objection"; id: number }>;
  /** readiness: whether the registers say the finish line is met, at which revision, and what holds it; prepare: readiness when the coordinator prepared. */
  ready?: boolean;
  /** readiness: recorded by the done that wrote the sentinel, readiness not having turned ready before it (finishTransaction). */
  at_done?: boolean;
  revision?: string;
  items?: string[];
  /** phase: the finish being assembled by its coordinator (another seat's answer revision needs material), or open again. */
  phase?: "assembling" | "open";
  /** check: what the finish line said at that revision. */
  proceed?: boolean;
  outcome?: string;
  reason?: string;
  run?: unknown;
  prev: string;
  hash: string;
};

export type FinishState = {
  events: FinishEvent[];
  /** The lease: its holder and generation, the report, the boundary (`since`), the resume segment it belongs to (0: the first) and the posts it carries from the segments before. */
  lease: { holder: string; generation: number; at: string; why: string; report: string | null; since: number | null; segment: number; carried: CarriedPost[]; from?: string } | null;
  acks: FinishAck[];
  resolutions: Array<{ seq: number; at: string; by: string; post?: number; ack?: number; how: "folded" | "not_material"; why: string; digest: string | null; batch?: string; generation?: number }>;
  /** Each time the coordinator prepared the finish (finish prepare): at which generation, on which report and digest, the boundary, readiness, and what it was given as late. */
  prepares: Array<{ seq: number; at: string; by: string; generation: number; report: string | null; digest: string | null; since: number | null; segment: number; ready: boolean; revision: string; late: Array<{ kind: "post" | "objection"; id: number }> }>;
  readiness: { ready: boolean; revision: string; items: string[]; at: string; at_done?: boolean } | null;
  /** The finish phase as last recorded: assembling (by whom, since when) or open. */
  phase: { phase: "assembling" | "open"; at: string; holder: string | null } | null;
  checks: Array<{ seq: number; at: string; by: string; revision: string; proceed: boolean; outcome?: string; reason?: string; run?: unknown }>;
  /** Each time the reviews of earlier versions were weighed for a new version of the report: which stand, carried over, and which were asked again. */
  carries: Array<{ seq: number; at: string; report: string; digest: string; kept: ReviewCarry[]; reasked: ReviewCarry[] }>;
  chain: { ok: boolean; broken_at: number | null; reason: string | null; head: string | null };
};

/** A review of the report (finish ack): the digest it read, its verdict, the sections it covered (by key, each with its digest then) and whether it covered the whole report. */
export type FinishAck = { seq: number; at: string; by: string; digest: string; verdict: "no_objection" | "objection"; why: string; report?: string; sections?: Record<string, string>; whole?: boolean };

export async function readFinish(sandboxRoot: string): Promise<FinishState> {
  const text = await readFile(join(sandboxRoot, FINISH_LOG), "utf8").catch(() => "");
  const chain = L.verifyLeadChain(text);
  const events: FinishEvent[] = [];
  for (const line of text.split("\n")) {
    if (!line.trim()) continue;
    try {
      events.push(JSON.parse(line) as FinishEvent);
    } catch {
      // The chain check names it.
    }
  }
  const st: FinishState = { events, lease: null, acks: [], resolutions: [], prepares: [], readiness: null, phase: null, checks: [], carries: [], chain };
  for (const e of events) {
    switch (e.ev) {
      case "lease":
        if (e.holder) {
          const was = st.lease;
          // A lease never goes back a segment; one of a later segment than the lease before it opens that segment (a resume).
          const segment = Math.max(typeof e.segment === "number" ? e.segment : 0, was?.segment ?? 0);
          const opens = segment > (was?.segment ?? 0);
          // Within a segment the earliest anchor a lease ever named stays: what was late against the report stays late.
          // A segment opened starts from its own anchor, and what was still late is carried by name, never forgiven.
          const since = opens ? (typeof e.since === "number" ? e.since : null) : typeof e.since === "number" ? (typeof was?.since === "number" ? Math.min(was.since, e.since) : e.since) : (was?.since ?? null);
          const carried = opens ? [...(e.carried ?? [])] : [...(was?.carried ?? [])];
          st.lease = { holder: e.holder, generation: e.generation ?? (was?.generation ?? 0) + 1, at: e.at, why: e.why ?? "", report: e.report ?? was?.report ?? null, since, segment, carried, ...(e.from ? { from: e.from } : {}) };
        }
        break;
      case "ack":
        if (e.digest && e.verdict) st.acks.push({ seq: e.seq, at: e.at, by: e.by, digest: e.digest, verdict: e.verdict, why: e.why ?? "", ...(e.report ? { report: e.report } : {}), ...(e.sections && typeof e.sections === "object" ? { sections: e.sections } : {}), ...(e.whole ? { whole: true } : {}) });
        break;
      case "carry":
        if (e.report && e.digest) st.carries.push({ seq: e.seq, at: e.at, report: e.report, digest: e.digest, kept: e.kept ?? [], reasked: e.reasked ?? [] });
        break;
      case "resolve":
        if (e.how) st.resolutions.push({ seq: e.seq, at: e.at, by: e.by, ...(e.post !== undefined ? { post: e.post } : {}), ...(e.ack !== undefined ? { ack: e.ack } : {}), how: e.how, why: e.why ?? "", digest: e.digest ?? null, ...(e.batch ? { batch: e.batch } : {}), ...(typeof e.generation === "number" ? { generation: e.generation } : {}) });
        break;
      case "prepare":
        st.prepares.push({ seq: e.seq, at: e.at, by: e.by, generation: e.generation ?? 0, report: e.report ?? null, digest: e.digest ?? null, since: typeof e.since === "number" ? e.since : null, segment: typeof e.segment === "number" ? e.segment : 0, ready: e.ready === true, revision: e.revision ?? "", late: e.late ?? [] });
        break;
      case "readiness":
        st.readiness = { ready: e.ready === true, revision: e.revision ?? "", items: e.items ?? [], at: e.at, ...(e.at_done ? { at_done: true } : {}) };
        break;
      case "phase":
        if (e.phase === "assembling" || e.phase === "open") st.phase = { phase: e.phase, at: e.at, holder: e.holder ?? null };
        break;
      case "check":
        if (e.revision) st.checks.push({ seq: e.seq, at: e.at, by: e.by, revision: e.revision, proceed: e.proceed === true, ...(e.outcome ? { outcome: e.outcome } : {}), ...(e.reason ? { reason: e.reason } : {}), ...(e.run !== undefined ? { run: e.run } : {}) });
        break;
    }
  }
  return st;
}

/** Append finish events under the finish lock the caller holds. */
async function appendFinish(sandboxRoot: string, drafts: Array<Omit<FinishEvent, "v" | "seq" | "at" | "prev" | "hash">>, held: P.HeldLock): Promise<FinishEvent[]> {
  const st = await readFinish(sandboxRoot);
  if (!st.chain.ok) throw new Error(`${FINISH_LOG}'s chain is broken at line ${st.chain.broken_at} (${st.chain.reason}): the finish takes no new act until the operator looks`);
  let prev = st.chain.head ?? "genesis";
  let seq = st.events.length;
  const out: FinishEvent[] = [];
  for (const d of drafts) {
    seq += 1;
    const draft = { v: 1 as const, seq, at: new Date().toISOString(), ...Object.fromEntries(Object.entries(d).filter(([, x]) => x !== undefined)) } as Omit<FinishEvent, "prev" | "hash">;
    const withPrev = { ...draft, prev } as Omit<FinishEvent, "hash">;
    const e = { ...withPrev, hash: L.leadEventHash(withPrev as unknown as L.LeadEvent, prev) } as FinishEvent;
    out.push(e);
    prev = e.hash;
  }
  await mkdir(join(sandboxRoot, L.LEADS_DIR), { recursive: true });
  await held.assertOwned();
  await appendFile(join(sandboxRoot, FINISH_LOG), out.map((e) => `${JSON.stringify(e)}\n`).join(""), "utf8");
  return out;
}

function withFinish<T>(sandboxRoot: string, fn: (held: P.HeldLock) => Promise<T>): Promise<T> {
  return P.withNamedLock(sandboxRoot, FINISH_LOCK, fn);
}

/** The report's sha256, or null while it does not exist. */
export async function reportDigest(sandboxRoot: string, report: string | null | undefined): Promise<string | null> {
  if (!report) return null;
  const bytes = await P.readSandboxFile(sandboxRoot, report).catch(() => null);
  return bytes ? createHash("sha256").update(bytes.bytes).digest("hex") : null;
}

/** Who published the report last: the seat that wrote its newest revision (history/). */
export async function reportPublisher(sandboxRoot: string, report: string): Promise<string | null> {
  const versions = await P.listFileHistory(sandboxRoot, report).catch(() => [] as P.FileVersion[]);
  return versions.at(-1)?.agent ?? null;
}

/**
 * Whether a seat can hold the finish now: a seat (not done, dead or
 * compacting: leads.ts seatAvailable) that has acted within the stale limit
 * or has a job running. A compacting coordinator is unavailable for the
 * whole compaction, so the last done does not wait on it.
 */
export async function coordinatorAvailable(sandboxRoot: string, agent: string, now = Date.now()): Promise<{ available: boolean; why: string }> {
  const activity = await L.recentActivity(sandboxRoot, Math.max(L.leadStaleMs(), L.LEAD_COMPACTION_BOUND_MS), now);
  const seat = await L.seatAvailable(sandboxRoot, agent, activity, now);
  if (!seat.available) return seat;
  const jobs = await L.readJobs(sandboxRoot).catch(() => [] as L.JobFacts[]);
  const live = await L.holderLiveness(sandboxRoot, agent, jobs, activity, now);
  return live.stale ? { available: false, why: live.why } : { available: true, why: live.why };
}

export type FinishTurn = {
  /** This seat coordinates the finish: its done goes on. */
  mine: boolean;
  holder: string;
  generation: number;
  why: string;
  /** Taken over now, from whom (unavailable). */
  took_over?: string;
  report: string | null;
};

/**
 * A seat's done asks for the finish (A4). With no lease yet, the report's
 * last publisher holds it when it can, else the seat asking; a holder that
 * is unavailable (done, dead, compacting, silent) is taken over by the seat
 * asking, at the next generation. Otherwise the finish is the holder's, and
 * this seat's done is "not yours". A prepare asks the same way (takeLease).
 */
export async function finishTurn(ctx: P.SwarmContext, input: { output_file?: string } = {}, now = Date.now()): Promise<FinishTurn> {
  const report = String(input.output_file ?? "").trim() || null;
  return withFinish(ctx.sandboxRoot, async (held) => {
    const turn = await takeLease(ctx, report, now, held);
    // What the reviews of earlier versions still cover, on the chain before the done goes on.
    if (turn.mine) await appendCarry(ctx.sandboxRoot, held);
    return turn;
  });
}

/** The resume segment the run is in (budget.json `resumes`: 0 before any resume) and when it began (ms; null before any resume). */
export async function currentSegment(sandboxRoot: string): Promise<{ k: number; at: number | null }> {
  const resumes = (await P.readBudget(sandboxRoot).catch(() => null))?.resumes ?? [];
  const at = resumes.length ? Date.parse(resumes.at(-1)!.at) : Number.NaN;
  return { k: resumes.length, at: Number.isFinite(at) ? at : null };
}

/**
 * The lease as a done or a prepare asks for it (A4; docs/adr/0015,
 * "Preparing the finish"), under the finish lock the caller holds. With no
 * lease yet, the report's last publisher holds it when it can, else the seat
 * asking; a holder that is unavailable (done, dead, compacting, silent) is
 * taken over by the seat asking, at the next generation; otherwise the
 * finish is the holder's. The report's boundary (`since`) is the time it was
 * written as the finish began, and a later call never moves it on.
 *
 * After a resume (budget.json `resumes`), the first lease asked for opens
 * the new segment: designated as a first lease is, at the next generation,
 * its boundary the report's time now, and every post that was late against
 * the report when the run was resumed and that no resolution answers is
 * carried on it by name (`carried`), so the new boundary forgives nothing.
 * What was posted after the resume and before the report the continuation
 * finishes on is the continuation's own work, which that report answers.
 */
async function takeLease(ctx: P.SwarmContext, report: string | null, now: number, held: P.HeldLock): Promise<FinishTurn> {
  const S = ctx.sandboxRoot;
  const st = await readFinish(S);
  const lease = st.lease;
  // Once the sentinel is written the finish is over: a done marker makes its
  // coordinator unavailable, and nobody takes over what has ended.
  if (await P.swarmDoneExists(S)) return { mine: false, holder: lease?.holder ?? "", generation: lease?.generation ?? 0, why: "the run is finished (done/SWARM_DONE)", report: lease?.report ?? report };
  // When the report was written as the finish began: what is posted after it is late, whatever version follows.
  const writtenAt = async (path: string | null) => (path ? (await P.outputWrittenAt(S, path)) || null : null);
  const seg = await currentSegment(S);
  const segment = seg.k ? { segment: seg.k } : {};
  // A first lease (or a segment's first): the report's last publisher when it can hold it, else the seat asking.
  const designate = async (path: string | null) => {
    const publisher = path ? await reportPublisher(S, path) : null;
    const pub = publisher && publisher !== ctx.agentId ? await coordinatorAvailable(S, publisher, now) : null;
    const holder = pub?.available ? publisher! : ctx.agentId;
    const why = holder === publisher ? `${holder} published ${path} last` : publisher ? `${publisher}, who published ${path} last, is unavailable (${pub?.why}): the first seat to ask for the finish holds it` : "the first seat to ask for the finish holds it";
    return { holder, why };
  };
  if (!lease) {
    const { holder, why } = await designate(report);
    const since = await writtenAt(report);
    await appendFinish(S, [{ by: ctx.agentId, ev: "lease", holder, generation: 1, why, ...(report ? { report } : {}), ...(since ? { since } : {}), ...segment }], held);
    return { mine: holder === ctx.agentId, holder, generation: 1, why, report };
  }
  if (seg.k > lease.segment) {
    const path = report ?? lease.report;
    const carried = await stillLate(S, st, seg.at);
    const d = await designate(path);
    const generation = lease.generation + 1;
    const why = `the run was resumed (segment ${seg.k}): ${d.why}${carried.length ? `; ${carried.length} post(s) still late from before the resume are kept` : ""}`;
    const since = await writtenAt(path);
    await appendFinish(S, [{ by: ctx.agentId, ev: "lease", holder: d.holder, generation, why, ...(d.holder !== lease.holder ? { from: lease.holder } : {}), ...(path ? { report: path } : {}), ...(since ? { since } : {}), segment: seg.k, ...(carried.length ? { carried } : {}) }], held);
    return { mine: d.holder === ctx.agentId, holder: d.holder, generation, why, report: path };
  }
  if (lease.holder === ctx.agentId) {
    // The coordinator's own done or prepare names the report: kept current on the lease, with its anchor once it exists.
    const since = lease.since === null ? await writtenAt(report ?? lease.report) : null;
    if ((report && report !== lease.report) || since) await appendFinish(S, [{ by: ctx.agentId, ev: "lease", holder: lease.holder, generation: lease.generation, why: report && report !== lease.report ? `the report is ${report}` : lease.why, ...(report ? { report } : {}), ...(since ? { since } : {}), ...segment }], held);
    return { mine: true, holder: lease.holder, generation: lease.generation, why: lease.why, report: report ?? lease.report };
  }
  const avail = await coordinatorAvailable(S, lease.holder, now);
  if (avail.available) return { mine: false, holder: lease.holder, generation: lease.generation, why: lease.why, report: lease.report };
  const generation = lease.generation + 1;
  const why = `${lease.holder} is unavailable (${avail.why}): taken over by ${ctx.agentId}`;
  const since = lease.since ?? (await writtenAt(report ?? lease.report));
  await appendFinish(S, [{ by: ctx.agentId, ev: "lease", holder: ctx.agentId, generation, from: lease.holder, why, ...(report ?? lease.report ? { report: report ?? lease.report! } : {}), ...(since ? { since } : {}), ...segment }], held);
  return { mine: true, holder: ctx.agentId, generation, why, took_over: lease.holder, report: report ?? lease.report };
}

/**
 * What a resume carries into the new segment (takeLease): each post that is
 * late against the report under the lease as it stands (its boundary, and
 * what it carries already) and was posted by the time the run was resumed.
 * An objection needs no carrying: it holds until it is resolved, whatever
 * the boundary.
 */
async function stillLate(sandboxRoot: string, st: FinishState, resumedAt: number | null): Promise<CarriedPost[]> {
  const lease = st.lease;
  if (!lease?.report) return [];
  const late = (await lateItems(sandboxRoot, lease.holder, lease.report)).filter((x) => x.kind === "post");
  if (!late.length) return [];
  const carried = new Set(lease.carried.map((c) => c.id));
  const times = await postTimes(sandboxRoot);
  return late.filter((x) => carried.has(x.id) || resumedAt === null || (times.get(x.id) ?? Number.POSITIVE_INFINITY) <= resumedAt).map((x) => ({ id: x.id, by: x.by, tag: x.tag ?? "result" }));
}

/** When each post of the main thread was written (its file's time, as correctionsAfter reads it), by id. */
async function postTimes(sandboxRoot: string): Promise<Map<number, number>> {
  const dir = join(sandboxRoot, "threads", P.PRIMARY_THREAD);
  const out = new Map<number, number>();
  for (const name of await readdir(dir).catch(() => [] as string[])) {
    const id = /^(\d{6})-.+\.md$/.exec(name)?.[1];
    if (!id) continue;
    const t = await stat(join(dir, name)).then((s) => s.mtimeMs).catch(() => null);
    if (t !== null) out.set(Number(id), t);
  }
  return out;
}

/** A seat's done, as the finish answers it: whose it is, what is late against the report (with the report's digest, for one batch of resolutions), and whether the registers say it is ready. */
export async function finishTurnFor(ctx: P.SwarmContext, input: { output_file?: string } = {}): Promise<FinishTurn & { late: LateItem[]; digest: string | null; readiness: { ready: boolean; items: string[]; limited: string[]; revision: string } }> {
  const turn = await finishTurn(ctx, input);
  const r = await readiness(ctx.sandboxRoot);
  return { ...turn, late: turn.mine ? await lateItems(ctx.sandboxRoot, ctx.agentId, turn.report) : [], digest: turn.mine ? await reportDigest(ctx.sandboxRoot, turn.report) : null, readiness: { ready: r.ready, items: r.items, limited: r.limited, revision: r.revision } };
}

/** The finish tool's acts: status for anyone, prepare for the seat that drafted the report, ack for a reviewer, resolve for the coordinator. */
export async function finishAct(ctx: P.SwarmContext, input: { action?: string; digest?: string; verdict?: string; why?: string; where?: string; post?: unknown; ack?: unknown; how?: string; report?: string; items?: unknown; generation?: unknown; key?: string; sections?: unknown }): Promise<Record<string, unknown>> {
  const action = String(input.action ?? "status").trim();
  if (action === "status") return finishStatus(ctx);
  if (action === "prepare") return prepareFinish(ctx, input);
  if (action === "ack") return ackReport(ctx, input);
  if (action === "resolve") return resolveLate(ctx, input);
  return { ok: false, reason: "action is status, prepare, ack or resolve" };
}

/** Whether a seat may write the sentinel: it holds the finish, or nobody does, or the holder is unavailable. */
export async function mayFinish(sandboxRoot: string, agent: string, now = Date.now()): Promise<{ ok: true } | { ok: false; holder: string; reason: string }> {
  const lease = (await readFinish(sandboxRoot)).lease;
  if (!lease || lease.holder === agent) return { ok: true };
  if (!(await coordinatorAvailable(sandboxRoot, lease.holder, now)).available) return { ok: true };
  return { ok: false, holder: lease.holder, reason: `${NOT_YOURS}${lease.holder} coordinates the finish (generation ${lease.generation}); its done ends the run` };
}

/**
 * Whether a post only restates an answer's revision by its own author: the
 * objects it cites are an answer that seat recorded (or is an author of)
 * and entries that answer corrects, directly or through its chain, and
 * nothing else (no job output, no input, no other entry). The revision is
 * in the ledger, where the gate and the coordinator read it: the post adds
 * nothing to answer.
 */
export function restatesRevision(body: string, by: string, entries: P.LedgerEntry[]): boolean {
  const refs = [...new Set(String(body ?? "").match(/\b(?:E-\d+|(?:job|input|import|member|sha256|net|tool|trace):[^\s,;)]+)/g) ?? [])];
  if (!refs.length || refs.some((r) => !/^E-\d+$/.test(r))) return false;
  const bySeq = new Map(entries.map((e) => [e.seq, e]));
  const cited = refs.map((r) => Number(r.slice(2)));
  const own = cited.map((n) => bySeq.get(n)).filter((e): e is P.LedgerEntry => Boolean(e) && e!.kind === "answer" && (e!.by === by || e!.authors.includes(by)) && e!.supersedes !== undefined);
  return own.some((a) => {
    const chain = new Set<number>([a.seq]);
    for (let n = a.supersedes; n !== undefined && !chain.has(n); n = bySeq.get(n)?.supersedes) chain.add(n);
    return cited.every((n) => chain.has(n));
  });
}

/**
 * How the coordinator's done is refused while something is late against the
 * report (the done tool, before the goal's checks run): each item, and how
 * to answer them all in one call; null when nothing is late. The metrics
 * read such a refusal by its words ("landed against") and its `late` count.
 */
export function lateRefusal(turn: { late: LateItem[]; generation: number; digest: string | null }, outputFile: string): string | null {
  if (!turn.late.length) return null;
  const each = turn.late.map((x) => (x.kind === "post" ? `- post #${x.id} (${x.tag}) by ${x.by}` : `- objection ${x.id} by ${x.by}: ${x.why}`)).join("\n");
  return `${turn.late.length} item(s) landed against \`${outputFile}\` since it was written, each for your typed resolution before the finish:\n${each}\nFold into the report what changes it and publish it again (then finish prepare gives its new digest), and resolve them all in one call: finish resolve with items [{post: <id> or ack: <seq>, how: "folded", where: "<where the report says it now>"} or {…, how: "not_material", why: "<why it changes nothing the report concludes>"}], generation ${turn.generation} and digest ${turn.digest ?? "(finish status gives it)"}. Typed acks of no objection are not among them. Next time, finish prepare before done lists them.`;
}

/** How a sentinel held by what is late against the report is refused (finishTransaction). */
export const LATE_PENDING = "late against the report: ";

/** A late item in words. */
export function lateWords(x: LateItem): string {
  return x.kind === "post" ? `post #${x.id} (${x.tag}) by ${x.by}` : `objection ${x.id} by ${x.by}: ${x.why}`;
}

/**
 * The finish's part of the one transaction that writes the sentinel (A4):
 * `write` runs under the finish register's lock, so no lease is taken over
 * and no objection is acked between the check and the sentinel, and only
 * while (1) the seat holds the lease at the holder and generation its done
 * began with (`expected`, carried through done; without it, any other
 * holder that can still take the finish refuses it) and (2) nothing late
 * against the report waits for a resolution. What the checks were run
 * against is the caller's to hold (the state revision, under the
 * registers' lock inside `write`). A seat's done marker is written inside
 * `write` too: it makes the seat unavailable, and a takeover waits for the
 * lock until the sentinel is written or the marker gone.
 */
export async function finishTransaction<T>(sandboxRoot: string, agent: string, expected: { holder: string; generation: number } | undefined, write: () => Promise<T>, now = Date.now(), at?: { revision?: string; outcome?: string }): Promise<T> {
  return withFinish(sandboxRoot, async (held) => {
    const lease = (await readFinish(sandboxRoot)).lease;
    if (expected) {
      if (!lease || expected.holder !== agent || lease.holder !== expected.holder || lease.generation !== expected.generation) {
        throw new Error(`${NOT_YOURS}${lease ? `${lease.holder} holds it at generation ${lease.generation}` : "nobody holds it"}, not ${expected.holder} at generation ${expected.generation}, which this done began with: ${lease && lease.holder !== agent ? `${lease.holder}'s done ends the run` : "call done again"}`);
      }
    } else if (lease && lease.holder !== agent && (await coordinatorAvailable(sandboxRoot, lease.holder, now)).available) {
      throw new Error(`${NOT_YOURS}${lease.holder} coordinates the finish (generation ${lease.generation}); its done ends the run`);
    }
    if (lease) {
      const late = await lateItems(sandboxRoot, lease.holder, lease.report);
      if (late.length) throw new Error(`${LATE_PENDING}${late.map(lateWords).join("; ")}. Each needs the coordinator's typed resolution (finish resolve, all in one call with items: folded, saying where the report says it now, or not_material, with why; generation ${lease.generation}, digest ${(await reportDigest(sandboxRoot, lease.report)) ?? "(finish status gives it)"}) before the sentinel is written`);
    }
    const written = await write();
    // The sentinel written: the finish line passed at this revision, so the
    // registers were met by the done's own rule. When readiness had not
    // turned ready before it (the c10 pilot's register held only "not
    // ready" to the end), the ready state is recorded here, marked as the
    // done's, so the tail from readiness is measured and the disagreement
    // is on the record.
    if (written === true && (await readFinish(sandboxRoot)).readiness?.ready !== true) {
      await appendFinish(sandboxRoot, [{ by: "system", ev: "readiness", ready: true, revision: at?.revision ?? "", items: [], at_done: true, why: `${agent}'s done passed the finish line${at?.outcome ? ` (${at.outcome})` : ""} while readiness had not turned ready` }], held).catch(() => undefined);
    }
    return written;
  });
}

/** A request's delivery bookkeeping (extensions/requests.ts): who was told, never what the finish rests on. */
const REQUEST_DELIVERY = new Set(["notified", "claimed", "delivery_failed"]);
/** The store journal's lines that commit an addition (scripts/material.ts), or say all that follows from one is recorded. */
const ADDITION_LINES = new Set(["evidence_added", "material_added", "addition_applied"]);

/**
 * The parts of the state revision the finish adds (protocol.ts
 * stateRevision): the report's digest (the path the lease names), each
 * job's state, the policy (the stop policy, the caps, a pause, the
 * contract and the run's case policy, docs/adr/0014), the operator's
 * decisions (the requests' chain less its delivery bookkeeping, and the
 * hosts allowed), what was added to the run after its kickoff (each
 * addition committed, and whether it was applied) and the sources' broad
 * extractions (each preparation receipt, only where the run has one, so a
 * run from before them keeps its revision). The review's acks are not in
 * it: a typed ack is not a change of state.
 */
export async function finishParts(sandboxRoot: string): Promise<Record<string, string>> {
  const out: Record<string, string> = {};
  const lease = (await readFinish(sandboxRoot).catch(() => null))?.lease ?? null;
  if (lease?.report) out.report = `${lease.report}:${(await reportDigest(sandboxRoot, lease.report)) ?? "missing"}`;
  // The shared deliverables a goal's checks read (the report among them, at
  // the top of work/): each by name, size and time, so a check result is
  // never taken for a revision whose deliverables changed since.
  const top: string[] = [];
  for (const d of await readdir(join(sandboxRoot, "work"), { withFileTypes: true }).catch(() => [] as Dirent[])) {
    if (!d.isFile() || d.name.startsWith(".")) continue;
    const st = await stat(join(sandboxRoot, "work", d.name)).catch(() => null);
    if (st) top.push(`${d.name}:${st.size}:${Math.round(st.mtimeMs)}`);
  }
  out.deliverables = P.sha256Hex(top.sort().join("\n"));
  const jobs = await L.readJobs(sandboxRoot).catch(() => [] as L.JobFacts[]);
  out.jobs = P.sha256Hex(jobs.map((j) => `${j.id}:${j.state}:${j.status ?? ""}`).join("\n"));
  // What of each job's stdout its requester was handed (the journal's
  // job_returned): the gate holds a job whose output was read only in part,
  // so a page read after a check (a new unread-output defect), or the rest
  // read after a refusal (its fix), moves the revision. Counted as the bytes
  // still unread of the whole: the same page handed over again moves nothing.
  const reads = await L.stdoutReads(sandboxRoot).catch(() => new Map<string, Map<string, Array<[number, number]>>>());
  const delivered: string[] = [];
  for (const j of jobs) {
    const spans = reads.get(j.id)?.get(j.agent);
    if (!spans?.length) continue;
    const total = await stat(join(sandboxRoot, "store", "jobs", j.id, "stdout.log")).then((x) => x.size).catch(() => 0);
    delivered.push(`${j.id}:${j.agent}:${L.unreadBytes(spans, total)}/${total}`);
  }
  out.delivery = P.sha256Hex(delivered.join("\n"));
  const b = await P.readBudget(sandboxRoot).catch(() => null);
  const policy: Record<string, unknown> = b ? { stop_policy: P.stopPolicyOf(b), until_solved: b.until_solved === true, paused: b.paused ?? null, cap_usd: b.cap_usd, cap_tokens: b.cap_tokens ?? null, wall_clock_minutes: b.wall_clock_minutes } : {};
  // The case policy (network/policy.json) says what material a record may rest on (material_use): the gate reads it.
  for (const rel of ["SWARM.md", "run.json", "policy.json", "network/policy.json"]) {
    const bytes = await readFile(join(sandboxRoot, rel)).catch(() => null);
    if (bytes) policy[rel] = P.sha256Hex(bytes);
  }
  out.policy = P.sha256Hex(JSON.stringify(P.canonicalValue(policy)));
  const decisions: string[] = [];
  // The requests' chain, less its delivery bookkeeping: a request opened,
  // acknowledged, answered, declined, withdrawn, or an acquisition's stage
  // moves the revision; a delivery claimed, a notification sent or failed
  // does not (a notifier's round must not make the coordinator's check run
  // again, as an offer's does not). A run from before the chain has only
  // the rendered view, read whole.
  const chain = await readFile(join(sandboxRoot, "requests", "requests.jsonl"), "utf8").catch(() => null);
  if (chain !== null) {
    const kept = chain.split("\n").filter((line) => {
      if (!line.trim()) return false;
      try {
        return !REQUEST_DELIVERY.has(String((JSON.parse(line) as { ev?: unknown }).ev));
      } catch {
        return true;
      }
    });
    decisions.push(`requests/requests.jsonl:${kept.length}:${P.sha256Hex(kept.join("\n"))}`);
  }
  for (const rel of chain !== null ? [L.OPERATOR_HOSTS] : [L.OPERATOR_REQUESTS, L.OPERATOR_HOSTS]) {
    const bytes = await readFile(join(sandboxRoot, rel)).catch(() => null);
    decisions.push(bytes ? `${rel}:${bytes.length}:${P.sha256Hex(bytes)}` : `${rel}:none`);
  }
  out.operator = P.sha256Hex(decisions.join("\n"));
  // What was added after the kickoff (evidence add, material add): each
  // addition committed on the store journal, and each applied. The gate
  // holds a done on one committed and not yet applied (addition_incomplete),
  // and what an addition reopens (answers made stale, acceptances lifted,
  // leads reopened) reaches the registers only when it is applied.
  const journal = await readFile(join(sandboxRoot, "store", "journal.jsonl"), "utf8").catch(() => "");
  const additions: string[] = [];
  for (const line of journal.split("\n")) {
    if (!line.includes("_added") && !line.includes("addition_applied")) continue;
    try {
      const j = JSON.parse(line) as { type?: unknown; import?: unknown };
      if (ADDITION_LINES.has(String(j.type))) additions.push(`${String(j.type)}:${String(j.import)}`);
    } catch {
      // a torn last line: the journal's own check names it
    }
  }
  out.additions = P.sha256Hex(additions.join("\n"));
  // The sources' broad extractions (extensions/preparation.ts): each receipt
  // on the journal. The gate holds a negative on a source whose extraction is
  // still planned or attempted, and a receipt written without a job changing
  // state (a seat's or the operator's decline) must move the revision too.
  const receipts: string[] = [];
  for (const line of journal.split("\n")) {
    if (!line.includes('"type":"preparation"')) continue;
    try {
      const j = JSON.parse(line) as { seq?: unknown; state?: unknown; capability?: unknown; source?: { sha256?: unknown } };
      receipts.push(`${String(j.seq)}:${String(j.state)}:${String(j.capability)}:${String(j.source?.sha256)}`);
    } catch {
      // a torn last line: the journal's own check names it
    }
  }
  if (receipts.length) out.preparation = P.sha256Hex(receipts.join("\n"));
  return out;
}

// --- the report's review ----------------------------------------------------------------------

export type LateItem = { kind: "post" | "objection"; id: number; by: string; tag?: string; why?: string };

/**
 * What the coordinator must answer before its done goes on: each result or
 * veto another seat posted after the report was written as the finish began
 * (the lease's `since`; the report's last write for a lease from before it),
 * and each objection acked against any version of the report, that no typed
 * resolution answers. They are obligations, kept through every later
 * version of the report until a resolution names them (publishing the
 * report again answers nothing by itself); an objector's own later ack
 * answers its objection. A typed ack of no objection is none of these.
 * After a resume, the posts the lease carries from before it (takeLease)
 * come first, each until a resolution names it.
 */
export async function lateItems(sandboxRoot: string, coordinator: string, report: string | null): Promise<LateItem[]> {
  if (!report) return [];
  const st = await readFinish(sandboxRoot);
  const since = st.lease?.report === report && typeof st.lease.since === "number" ? st.lease.since : undefined;
  const posts = await P.correctionsAfter(sandboxRoot, report, coordinator, since).catch(() => [] as Array<{ id: number; from: string; tag: P.PostTag; body: string }>);
  const out: LateItem[] = [];
  const resolved = (id: number) => st.resolutions.some((r) => r.post === id);
  for (const c of st.lease?.carried ?? []) if (!resolved(c.id) && !out.some((x) => x.kind === "post" && x.id === c.id)) out.push({ kind: "post", id: c.id, by: c.by, tag: c.tag });
  const entries = posts.length ? await P.readLedger(sandboxRoot).catch(() => [] as P.LedgerEntry[]) : [];
  for (const p of posts) {
    if (resolved(p.id) || out.some((x) => x.kind === "post" && x.id === p.id)) continue;
    // A result that only restates its author's own answer revision is covered by that revision (the c10 pilot: each revision came with such a post, and each asked the coordinator for a resolution).
    if (p.tag === "result" && restatesRevision(p.body, p.from, entries)) continue;
    out.push({ kind: "post", id: p.id, by: p.from, tag: p.tag });
  }
  for (const a of st.acks) {
    if (a.verdict !== "objection") continue;
    if (st.resolutions.some((r) => r.ack === a.seq)) continue;
    // A later ack by the same seat, of any version, answers its own objection
    // when it reviews what the objection was about: the whole report, or
    // every section the objection named. An objection to section 3 stands
    // through its objector's review of section 2 alone (the review a changed
    // section 2 asks it for).
    if (st.acks.some((b) => b.by === a.by && b.seq > a.seq && answersObjection(b, a))) continue;
    // An objection to another file than the finish's report (made before any
    // done named it) is late too, and says so: it was lost quietly (the
    // Fable review of batches 1-3). The coordinator resolves it, or says it
    // is of another file.
    if (a.report && a.report !== report) {
      out.push({ kind: "objection", id: a.seq, by: a.by, why: `objection to ${a.report}, not the finish's report (${report}): resolve it, or say it is another file. ${a.why ?? ""}`.trim() });
      continue;
    }
    out.push({ kind: "objection", id: a.seq, by: a.by, why: a.why });
  }
  return out;
}

// --- the report's sections, and the reviews that stand ------------------------------------------

/** The key of the text before the report's first `## ` heading. */
export const PREAMBLE = "preamble";

/** One section of the report: its key, its heading's words (none for the preamble), and the sha256 of its lines, the heading's among them. */
export type ReportSection = { key: string; title: string; digest: string };

/**
 * The report's sections, as the report body reads a Markdown document's
 * (scripts/report-body.ts, h2Sections: `## ` headings, fenced blocks
 * skipped) and the answers check numbers them (scripts/check-answers.ts,
 * sections: `## <n>.`): the text before the first heading (`preamble`),
 * then each `## ` heading with every line under it up to the next. A
 * numbered heading is keyed by its number ("3" for `## 3. …`), any other by
 * its words, and a key met again is numbered (`Notes (2)`): no line is
 * outside a section, so a change anywhere changes some section's digest.
 * The digest covers the heading line too, so a renamed section is a changed
 * one, and leaves out only the blank lines that end a section (layout before
 * the next heading, or the file's last newline). Nothing here reads what a
 * section says.
 */
export function reportSections(text: string): ReportSection[] {
  const out: Array<{ key: string; title: string; lines: string[] }> = [{ key: PREAMBLE, title: "", lines: [] }];
  let fenced = false;
  for (const line of text.split("\n")) {
    const h = fenced ? null : /^##\s+(.+?)\s*$/.exec(line);
    if (/^\s*(```|~~~)/.test(line)) fenced = !fenced;
    if (h) {
      const base = /^(\d+)\./.exec(h[1])?.[1] ?? h[1];
      let key = base;
      for (let n = 2; out.some((x) => x.key === key); n++) key = `${base} (${n})`;
      out.push({ key, title: h[1], lines: [line] });
      continue;
    }
    out[out.length - 1].lines.push(line);
  }
  // The blank lines that end a section are layout between it and the next (the report's last one ends with its newline): a section is its lines up to its last that says something.
  const trimmed = (lines: string[]) => {
    let n = lines.length;
    while (n > 0 && !lines[n - 1].trim()) n -= 1;
    return lines.slice(0, n);
  };
  return out.map((x) => ({ key: x.key, title: x.title, digest: P.sha256Hex(trimmed(x.lines).join("\n")) }));
}

/**
 * The sections a reviewer names (finish ack `sections`): each by its key, its
 * number (3, §3, Q-3, section 3) or its heading's words, as a list or one
 * comma-separated text. None named is the whole report (an empty list).
 * A name that is no section of the report is refused with the report's
 * sections, so the reviewer can name them again.
 */
export function namedSections(sections: readonly ReportSection[], raw: unknown, report = "the report"): { ok: true; keys: string[] } | { ok: false; reason: string } {
  const list = raw === undefined || raw === null || raw === "" ? [] : Array.isArray(raw) ? raw.map(String) : String(raw).split(",");
  const keys: string[] = [];
  const all = sections.map((x) => x.key);
  for (const name of list) {
    const t = name.trim();
    if (!t) continue;
    const bare = t.replace(/^(?:§\s*|section\s+|q-?(?=\d))/i, "").replace(/\.$/, "");
    const hit = sections.find((x) => x.key === t) ?? sections.find((x) => x.key === bare) ?? sections.find((x) => x.title.toLowerCase() === t.toLowerCase() || x.key.toLowerCase() === t.toLowerCase());
    if (!hit) return { ok: false, reason: `sections: "${t}" is not a section of ${report}; its sections are ${all.join(", ")} (name them by key or number, or name none for the whole report)` };
    if (!keys.includes(hit.key)) keys.push(hit.key);
  }
  return { ok: true, keys };
}

/**
 * Whether a seat's later ack answers its own earlier objection: it reviewed
 * what the objection was about, the whole report or every section the
 * objection named. An ack or an objection from before per-section reviews
 * (no sections) is of the whole report, as it always was.
 */
export function answersObjection(later: Pick<FinishAck, "sections" | "whole">, objection: Pick<FinishAck, "sections">): boolean {
  if (!objection.sections || !later.sections || later.whole) return true;
  return Object.keys(objection.sections).every((k) => k in later.sections!);
}

/** A seat's review of the report as it stands now (reviewStanding). */
export type SeatReview = {
  by: string;
  /** direct: every section it covers rests on a review of this very version; carried: some rest on an earlier version's, their sections unchanged; reasked: something it covered changed since. */
  standing: "direct" | "carried" | "reasked";
  /** The acks its covered sections rest on. */
  acks: number[];
  /** The sections its review still covers, unchanged since it reviewed them. */
  covered: string[];
  /** The sections to review again: changed since, or (a review of the whole report) added since. */
  changed: string[];
  /** Sections a review of the whole report covered that the report no longer has. */
  removed: string[];
  /** Whether its review is of the whole report. */
  whole: boolean;
};

/** The reviews of the report as it stands: its sections (keys, in order), each seat's review, and the sections no standing review covers. */
export type ReviewStanding = { report: string; digest: string; sections: string[]; seats: SeatReview[]; uncovered: string[] };

/**
 * Which reviews of the report still stand for its current version
 * (docs/adr/0015, "A review carries over"). Each seat's acks are read in
 * order, section by section: a no objection vouches for each section it
 * covered at the digest that section had then (a review of the whole
 * report vouches for every section there was, and for nothing it had
 * vouched before); an objection withdraws the vouching of the sections it
 * names. A section it vouches for whose digest is unchanged is covered, and
 * the review carries over; one that changed is asked again; a review of the
 * whole report is asked about a section added since, and about one removed
 * (answered by a review of the whole report as it is). An ack from before
 * per-section reviews (no sections) is of the whole report at its digest:
 * it stands for that digest and is asked again on any other, as before.
 * A seat whose acks vouch for nothing (an objection only) is left out: its
 * objection is a late item until it is resolved.
 */
export function reviewStanding(acks: readonly FinishAck[], report: string, current: { digest: string; sections: readonly ReportSection[] }): ReviewStanding {
  const order = current.sections.map((x) => x.key);
  const now = new Map(current.sections.map((x) => [x.key, x.digest]));
  const bySeat = new Map<string, FinishAck[]>();
  for (const a of [...acks].sort((x, y) => x.seq - y.seq)) {
    if (a.report && a.report !== report) continue;
    bySeat.set(a.by, [...(bySeat.get(a.by) ?? []), a]);
  }
  const seats: SeatReview[] = [];
  for (const [by, list] of bySeat) {
    let vouched = new Map<string, { digest: string; ack: number }>();
    let whole = false;
    let legacy: { digest: string; ack: number } | null = null;
    for (const a of list) {
      if (!a.sections) {
        vouched = new Map();
        whole = a.verdict === "no_objection";
        legacy = whole ? { digest: a.digest, ack: a.seq } : null;
        continue;
      }
      legacy = null;
      if (a.verdict === "objection") {
        if (a.whole) {
          vouched = new Map();
          whole = false;
        } else for (const k of Object.keys(a.sections)) vouched.delete(k);
        continue;
      }
      if (a.whole) {
        vouched = new Map();
        whole = true;
      }
      for (const [k, d] of Object.entries(a.sections)) vouched.set(k, { digest: d, ack: a.seq });
    }
    if (legacy) {
      const same = legacy.digest === current.digest;
      seats.push({ by, standing: same ? "direct" : "reasked", acks: [legacy.ack], covered: same ? [...order] : [], changed: same ? [] : [...order], removed: [], whole: true });
      continue;
    }
    if (!vouched.size) continue;
    const covered: string[] = [];
    const changed: string[] = [];
    const removed: string[] = [];
    const rests = new Set<number>();
    for (const [k, v] of vouched) {
      if (now.get(k) === v.digest) {
        covered.push(k);
        rests.add(v.ack);
      } else if (now.has(k)) changed.push(k);
      else if (whole) removed.push(k);
    }
    if (whole) for (const k of order) if (!vouched.has(k)) changed.push(k);
    // A review of sections the report no longer has, and of nothing else, covers nothing now.
    if (!covered.length && !changed.length && !removed.length) continue;
    const inOrder = (xs: string[]) => [...xs].sort((a, b) => order.indexOf(a) - order.indexOf(b));
    const onThis = [...rests].every((seq) => list.find((a) => a.seq === seq)?.digest === current.digest);
    const standing = changed.length || removed.length ? "reasked" : onThis ? "direct" : "carried";
    seats.push({ by, standing, acks: [...rests].sort((a, b) => a - b), covered: inOrder(covered), changed: inOrder(changed), removed: removed.sort(), whole });
  }
  const covering = new Set(seats.flatMap((x) => x.covered));
  return { report, digest: current.digest, sections: order, seats, uncovered: order.filter((k) => !covering.has(k)) };
}

/** The reviews of the finish's report as it stands now, or null while no lease names a report that exists. */
export async function reportReview(sandboxRoot: string, st?: FinishState): Promise<ReviewStanding | null> {
  const fin = st ?? (await readFinish(sandboxRoot));
  const report = fin.lease?.report ?? null;
  if (!report) return null;
  const read = await P.readSandboxFile(sandboxRoot, report).catch(() => null);
  if (!read) return null;
  return reviewStanding(fin.acks, report, { digest: P.sha256Hex(read.bytes), sections: reportSections(read.bytes.toString("utf8")) });
}

/**
 * The carry event a new version of the report needs, or null: when an ack
 * made on another version since this version was last weighed (a no
 * objection) has not been weighed for it, the reviews that still stand,
 * carried over, and those asked again, by seat, with the acks each rests on.
 * One per version and what was weighed: the chain shows why an ack of an
 * earlier version still counts.
 */
async function carryDraft(sandboxRoot: string, st: FinishState): Promise<Omit<FinishEvent, "v" | "seq" | "at" | "prev" | "hash"> | null> {
  const review = await reportReview(sandboxRoot, st);
  if (!review) return null;
  const last = st.carries.filter((c) => c.report === review.report && c.digest === review.digest).at(-1)?.seq ?? 0;
  if (!st.acks.some((a) => a.seq > last && a.verdict === "no_objection" && a.digest !== review.digest && (!a.report || a.report === review.report))) return null;
  const kept = review.seats.filter((x) => x.standing === "carried").map((x): ReviewCarry => ({ by: x.by, acks: x.acks, sections: x.covered }));
  const reasked = review.seats.filter((x) => x.standing === "reasked").map((x): ReviewCarry => ({ by: x.by, acks: x.acks, ...(x.changed.length ? { changed: x.changed } : {}), ...(x.removed.length ? { removed: x.removed } : {}) }));
  if (!kept.length && !reasked.length) return null;
  return { by: "system", ev: "carry", report: review.report, digest: review.digest, ...(kept.length ? { kept } : {}), ...(reasked.length ? { reasked } : {}) };
}

/** Record the carry event the report's current version needs, under the finish lock the caller holds. */
async function appendCarry(sandboxRoot: string, held: P.HeldLock): Promise<void> {
  const d = await carryDraft(sandboxRoot, await readFinish(sandboxRoot));
  if (d) await appendFinish(sandboxRoot, [d], held);
}

/** Record the carry event the report's current version needs, if any (from the header: a report published again is weighed at the next turn). */
export async function syncCarry(sandboxRoot: string): Promise<boolean> {
  if (!(await carryDraft(sandboxRoot, await readFinish(sandboxRoot)))) return false;
  return withFinish(sandboxRoot, async (held) => {
    const d = await carryDraft(sandboxRoot, await readFinish(sandboxRoot));
    if (!d) return false;
    await appendFinish(sandboxRoot, [d], held);
    return true;
  }).catch(() => false);
}

/** A seat's review in words: which sections it is asked again, and why. */
function reaskedWords(x: Pick<SeatReview, "changed" | "removed">): string {
  return [...(x.changed.length ? [x.changed.join(", ")] : []), ...(x.removed.length ? [`removed: ${x.removed.join(", ")}`] : [])].join("; ");
}

/** What the coordinator does about the report's review now: who stands (carried over or not), and whom to ask again, on what. */
export function reviewInvite(r: ReviewStanding | null): string {
  if (!r || !r.seats.length) return "invite the report's review (finish ack)";
  const again = r.seats.filter((x) => x.standing === "reasked");
  const carried = r.seats.filter((x) => x.standing === "carried");
  const stand = r.seats.filter((x) => x.standing !== "reasked");
  const parts: string[] = [];
  if (stand.length) parts.push(`the reviews of ${stand.map((x) => x.by).join(", ")} stand${carried.length ? ` (${carried.map((x) => x.by).join(", ")} carried over: the sections they reviewed are unchanged)` : ""}`);
  parts.push(again.length ? `ask again only on what changed: ${again.map((x) => `${x.by} (${reaskedWords(x)})`).join("; ")}` : "ask nobody to review it again");
  if (r.uncovered.length) parts.push(`no standing review covers ${r.uncovered.join(", ")}`);
  return parts.join("; ");
}

/** What a seat's own review of the report is now, for its header, or null when it has none. */
function ownReviewWords(r: ReviewStanding | null, me: string): string | null {
  const mine = r?.seats.find((x) => x.by === me);
  if (!mine) return null;
  if (mine.standing !== "reasked") return ` Your review of the report stands${mine.standing === "carried" ? " (carried over: the sections you reviewed are unchanged)" : ""}: do not ack it again, and do not post it on the board.`;
  const fix = mine.removed.length && !mine.changed.length ? "finish ack with no sections, the whole report as it is" : `finish ack with sections [${mine.changed.map((k) => JSON.stringify(k)).join(", ")}]${mine.removed.length ? ", or with none for the whole report as it is" : ""}`;
  return ` The report changed since your review in ${reaskedWords(mine)}: review only that (${fix}); the rest of your review carries over.`;
}

/**
 * A seat's review of the report (A4): the digest it read (the report's
 * current one when left out), its verdict, and the sections it covered
 * (`sections`, by key or number; none named is the whole report). No
 * objection is a typed ack, never a late post; an objection says why and
 * holds the coordinator's done until the coordinator resolves it. The ack
 * binds each section it covered by that section's digest, so a later
 * version that leaves them unchanged keeps it standing (reviewStanding),
 * and what an earlier version's reviews still cover is recorded first
 * (a carry event) when this is a new version.
 */
export async function ackReport(ctx: P.SwarmContext, input: { digest?: string; verdict?: string; why?: string; report?: string; sections?: unknown }): Promise<{ ok: true; seq: number; digest: string; report: string; sections: string[]; whole: boolean } | { ok: false; reason: string }> {
  const verdict = String(input.verdict ?? "").trim();
  if (verdict !== "no_objection" && verdict !== "objection") return { ok: false, reason: "verdict is no_objection or objection" };
  const why = String(input.why ?? "").trim();
  if (verdict === "objection" && !why) return { ok: false, reason: "an objection says why: what in the report does not hold, and what shows it" };
  if (why.length > L.LEAD_WHY_MAX) return { ok: false, reason: `why is over ${L.LEAD_WHY_MAX} characters: nothing is cut, so a longer text is refused` };
  const named = String(input.report ?? "").trim().replace(/^\.\//, "") || null;
  return withFinish(ctx.sandboxRoot, async (held) => {
    const st = await readFinish(ctx.sandboxRoot);
    // The report reviewed: the finish's, once a coordinator's done named it;
    // before that, the one the reviewer names (the c10 pilot's objection
    // was refused for want of a done, and lost).
    const leased = st.lease?.report ?? null;
    if (leased && named && named !== leased) return { ok: false as const, reason: `the finish's report is ${leased}: ack that one (a review of another file is a post)` };
    const report = leased ?? named;
    if (!report) return { ok: false as const, reason: "no coordinator's done has named the report yet: name the report you reviewed (report, e.g. work/report.md)" };
    const read = await P.readSandboxFile(ctx.sandboxRoot, report).catch(() => null);
    if (!read) return { ok: false as const, reason: `${report} does not exist yet` };
    const current = P.sha256Hex(read.bytes);
    const digest = String(input.digest ?? "").trim() || current;
    if (digest !== current) return { ok: false as const, reason: `${report} is at digest ${current} now, not ${digest}: read it again, then ack what you read` };
    if (st.lease?.holder === ctx.agentId) return { ok: false as const, reason: "you coordinate the finish: an ack is another seat's review of your report" };
    const secs = reportSections(read.bytes.toString("utf8"));
    const chosen = namedSections(secs, input.sections, report);
    if (!chosen.ok) return { ok: false as const, reason: chosen.reason };
    const keys = chosen.keys.length ? chosen.keys : secs.map((x) => x.key);
    const sections = Object.fromEntries(keys.map((k) => [k, secs.find((x) => x.key === k)!.digest]));
    // A new version: what the reviews of earlier ones still cover goes on the chain before this review does.
    await appendCarry(ctx.sandboxRoot, held);
    const [e] = await appendFinish(ctx.sandboxRoot, [{ by: ctx.agentId, ev: "ack", digest, verdict, ...(why ? { why } : {}), ...(leased ? {} : { report }), sections, ...(chosen.keys.length ? {} : { whole: true }) }], held);
    return { ok: true as const, seq: e.seq, digest, report, sections: keys, whole: !chosen.keys.length };
  });
}

/**
 * The coordinator answers a late post or an objection with a typed
 * resolution: folded into the report, or not material, with why. With
 * `items`, several in one act (resolveBatch).
 */
export async function resolveLate(ctx: P.SwarmContext, input: { post?: unknown; ack?: unknown; how?: string; why?: string; where?: string; items?: unknown; generation?: unknown; digest?: string; key?: string }): Promise<Record<string, unknown> & ({ ok: true } | { ok: false; reason: string })> {
  if (input.items !== undefined && input.items !== null) return resolveBatch(ctx, input);
  return resolveOne(ctx, input);
}

async function resolveOne(ctx: P.SwarmContext, input: { post?: unknown; ack?: unknown; how?: string; why?: string }): Promise<{ ok: true; seq: number } | { ok: false; reason: string }> {
  const how = String(input.how ?? "").trim();
  if (how !== "folded" && how !== "not_material") return { ok: false, reason: "how is folded (the report now says it) or not_material (it changes nothing the report concludes)" };
  const why = String(input.why ?? "").trim();
  if (!why) return { ok: false, reason: `why is required: ${how === "folded" ? "where the report says it now" : "why it changes nothing the report concludes"}` };
  const post = input.post !== undefined && input.post !== null && String(input.post).trim() ? Number(String(input.post).replace(/^#/, "")) : undefined;
  const ack = input.ack !== undefined && input.ack !== null && String(input.ack).trim() ? Number(input.ack) : undefined;
  if ((post === undefined) === (ack === undefined)) return { ok: false, reason: "name one: post (the late post's id, #123) or ack (the objection's seq)" };
  return withFinish(ctx.sandboxRoot, async (held) => {
    const st = await readFinish(ctx.sandboxRoot);
    if (st.lease?.holder !== ctx.agentId) return { ok: false as const, reason: `resolutions are the coordinator's${st.lease ? ` (${st.lease.holder})` : ""}` };
    const open = await lateItems(ctx.sandboxRoot, ctx.agentId, st.lease.report);
    const hit = open.find((x) => (post !== undefined && x.kind === "post" && x.id === post) || (ack !== undefined && x.kind === "objection" && x.id === ack));
    if (!hit) return { ok: false as const, reason: `${post !== undefined ? `post #${post}` : `objection ${ack}`} is not open against the report (open: ${open.map((x) => (x.kind === "post" ? `post #${x.id}` : `objection ${x.id}`)).join(", ") || "none"})` };
    // Bound to the version of the report it was made against: a folded item is in that one.
    const digest = await reportDigest(ctx.sandboxRoot, st.lease.report);
    const [e] = await appendFinish(ctx.sandboxRoot, [{ by: ctx.agentId, ev: "resolve", ...(post !== undefined ? { post } : {}), ...(ack !== undefined ? { ack } : {}), how: how as "folded" | "not_material", why, ...(digest ? { digest } : {}) }], held);
    return { ok: true as const, seq: e.seq };
  });
}

/** The longest idempotency key a batch takes: a longer one is refused, never cut. */
export const BATCH_KEY_MAX = 200;

/** One item of a batch, read: what it resolves, how, and its words (where it was folded, or why it is not material). */
type BatchItem = { index: number; kind: "post" | "objection"; id: number; how: "folded" | "not_material"; words: string };

const itemWords = (x: { kind: "post" | "objection"; id: number }) => (x.kind === "post" ? `post #${x.id}` : `objection ${x.id}`);

/** A batch's own key when none is given: the same batch sent again (the same seat, generation, digest and items, in any order) has the same key. */
export function batchKey(by: string, generation: number, digest: string, items: ReadonlyArray<Pick<BatchItem, "kind" | "id" | "how" | "words">>): string {
  const canon = items.map((x) => [x.kind, x.id, x.how, x.words] as const).sort((a, b) => a[0].localeCompare(b[0]) || a[1] - b[1]);
  return `auto-${P.sha256Hex(JSON.stringify({ by, generation, digest, items: canon })).slice(0, 24)}`;
}

/** A whole number above zero from a number or its text (a post's id may be written #123), else undefined when absent and NaN when not one. */
function wholeNumber(v: unknown, hash = false): number | undefined {
  if (v === undefined || v === null || (typeof v === "string" && !v.trim())) return undefined;
  const n = Number(hash ? String(v).trim().replace(/^#/, "") : v);
  return Number.isInteger(n) && n > 0 ? n : Number.NaN;
}

/**
 * Several late items resolved in one act (docs/adr/0015, "Preparing the
 * finish"): `items` [{post | ack, how: folded, where} or {post | ack, how:
 * not_material, why}], against the coordinator's `generation` and the
 * report's `digest` the coordinator read (finish prepare or finish status
 * gives both; the digest's first 12 characters or more), with an idempotency
 * `key` (the batch's own content names it when none is given).
 *
 * Validated whole under the finish lock, then one ordinary resolution event
 * per item (each carrying the key, the generation and the digest), or none:
 * a stale generation or digest, or any item that is not late against the
 * report (resolved already, never late, named twice), refuses the batch with
 * the exact stale fields, each item's problem and every id still unresolved,
 * and records nothing. A batch recorded already under the same key by the
 * same seat (a retry after an interruption) is answered with what was
 * recorded and what is still late, and nothing is recorded twice; a
 * different batch under a key used already is refused.
 */
async function resolveBatch(ctx: P.SwarmContext, input: { items?: unknown; generation?: unknown; digest?: string; key?: string }): Promise<Record<string, unknown> & ({ ok: true } | { ok: false; reason: string })> {
  const raw = input.items;
  if (!Array.isArray(raw) || !raw.length) return { ok: false, reason: "items is a list of what you resolve, at least one: {post: <id>} or {ack: <the objection's seq>}, each with how: folded (and where: where the report says it now) or not_material (and why: why it changes nothing the report concludes). Nothing was recorded." };
  const problems: Array<{ index: number; item: string; problem: string }> = [];
  const items: BatchItem[] = [];
  for (const [i, r] of raw.entries()) {
    const index = i + 1;
    if (!r || typeof r !== "object" || Array.isArray(r)) {
      problems.push({ index, item: `item ${index}`, problem: "is not an object: {post or ack, how, where or why}" });
      continue;
    }
    const o = r as Record<string, unknown>;
    const post = wholeNumber(o.post, true);
    const ack = wholeNumber(o.ack);
    const name = post !== undefined ? `post #${String(o.post).replace(/^#/, "")}` : ack !== undefined ? `objection ${String(o.ack)}` : `item ${index}`;
    if ((post === undefined) === (ack === undefined)) {
      problems.push({ index, item: name, problem: "names one: post (the late post's id, #123) or ack (the objection's seq)" });
      continue;
    }
    if (Number.isNaN(post ?? ack)) {
      problems.push({ index, item: name, problem: post !== undefined ? "post is the late post's id, a whole number" : "ack is the objection's seq, a whole number" });
      continue;
    }
    const how = String(o.how ?? "").trim();
    if (how !== "folded" && how !== "not_material") {
      problems.push({ index, item: name, problem: "how is folded (the report now says it: give where) or not_material (it changes nothing the report concludes: give why)" });
      continue;
    }
    const words = String((how === "folded" ? (o.where ?? o.why) : o.why) ?? "").trim();
    if (!words) {
      problems.push({ index, item: name, problem: how === "folded" ? "folded needs where: where the report says it now" : "not_material needs why: why it changes nothing the report concludes" });
      continue;
    }
    if (words.length > L.LEAD_WHY_MAX) {
      problems.push({ index, item: name, problem: `its ${how === "folded" ? "where" : "why"} is over ${L.LEAD_WHY_MAX} characters: nothing is cut, so a longer text is refused` });
      continue;
    }
    const kind = post !== undefined ? ("post" as const) : ("objection" as const);
    const id = (post ?? ack)!;
    const twice = items.find((x) => x.kind === kind && x.id === id);
    if (twice) {
      problems.push({ index, item: name, problem: `is named twice in this batch (items ${twice.index} and ${index}): one resolution each` });
      continue;
    }
    items.push({ index, kind, id, how, words });
  }
  const generation = wholeNumber(input.generation);
  const digestIn = String(input.digest ?? "").trim().toLowerCase();
  const needs: string[] = [];
  if (generation === undefined || Number.isNaN(generation)) needs.push("generation (the coordinator's generation: finish prepare or finish status gives it)");
  if (!/^[0-9a-f]{12,64}$/.test(digestIn)) needs.push("digest (the report's digest you read: finish prepare or finish status gives it; its first 12 characters or more)");
  const keyIn = input.key === undefined || input.key === null ? "" : String(input.key).trim();
  if (input.key !== undefined && input.key !== null && (!keyIn || keyIn.length > BATCH_KEY_MAX || /[\u0000-\u001f\u007f]/.test(keyIn))) needs.push(`key: 1 to ${BATCH_KEY_MAX} characters and no control character (or leave it out, and the batch's own content names it)`);
  return withFinish(ctx.sandboxRoot, async (held) => {
    const st = await readFinish(ctx.sandboxRoot);
    const lease = st.lease;
    // What is late against the report, as finish status shows it to any seat: said with every answer, so nothing is hidden.
    const open = lease ? await lateItems(ctx.sandboxRoot, lease.holder, lease.report) : [];
    const unresolved = open.map((x) => ({ kind: x.kind, id: x.id }));
    const stillLateWords = open.length ? ` Still late: ${open.map(itemWords).join(", ")}.` : "";
    if (needs.length || problems.length) {
      const parts = [...(needs.length ? [`a batch carries ${needs.join(", and ")}`] : []), ...problems.map((p) => `${p.item} (item ${p.index}) ${p.problem}`)];
      return { ok: false as const, reason: `${parts.join("; ")}. Nothing was recorded.${stillLateWords}`, ...(problems.length ? { problems } : {}), unresolved };
    }
    const key = keyIn || batchKey(ctx.agentId, generation!, digestIn, items);
    // A batch recorded already under this key by this seat: a retry after an interruption, answered with what was recorded.
    const prior = st.resolutions.filter((x) => x.batch === key && x.by === ctx.agentId);
    if (prior.length) {
      const same = prior.length === items.length && prior.every((p) => items.some((x) => (x.kind === "post" ? p.post === x.id : p.ack === x.id) && p.how === x.how && p.why === x.words));
      if (!same) return { ok: false as const, reason: `key ${key} was recorded already for another batch (seqs ${prior.map((p) => p.seq).join(", ")}): a new batch takes a new key. Nothing was recorded.${stillLateWords}`, key, unresolved };
      return { ok: true as const, replayed: true, key, seqs: prior.map((p) => p.seq), resolved: prior.length, late: open, note: `this batch was recorded already under key ${key} (seqs ${prior.map((p) => p.seq).join(", ")}): nothing was recorded twice.${open.length ? ` Still late: ${open.map(itemWords).join(", ")}.` : " Nothing is late against the report now."}` };
    }
    if (!lease || lease.holder !== ctx.agentId) return { ok: false as const, reason: `resolutions are the coordinator's${lease ? ` (${lease.holder})` : ""}` };
    const current = await reportDigest(ctx.sandboxRoot, lease.report);
    const stale: { generation?: { expected: number; current: number; holder: string }; digest?: { expected: string; current: string | null; report: string | null } } = {};
    if (generation !== lease.generation) stale.generation = { expected: generation!, current: lease.generation, holder: lease.holder };
    if (!current || !current.startsWith(digestIn)) stale.digest = { expected: digestIn, current, report: lease.report };
    const resolvedAlready: Array<{ item: string; seq: number }> = [];
    for (const x of items) {
      if (open.some((o) => o.kind === x.kind && o.id === x.id)) continue;
      const done = st.resolutions.find((r) => (x.kind === "post" ? r.post === x.id : r.ack === x.id));
      if (done) resolvedAlready.push({ item: itemWords(x), seq: done.seq });
      problems.push({ index: x.index, item: itemWords(x), problem: done ? `was resolved already (seq ${done.seq}, ${done.how}${done.batch ? `, batch ${done.batch}` : ""})` : "is not late against the report" });
    }
    // Every item of the batch resolved already (a retry under another key, a longer digest prefix): nothing to record, and nothing to send again (the Fable review of the limits branch, P3-8).
    if (items.length && resolvedAlready.length === items.length) {
      return { ok: true as const, key, seqs: [], resolved: 0, generation: lease.generation, digest: current, late: open, note: `every item of this batch was resolved already (${resolvedAlready.map((x) => `${x.item}, seq ${x.seq}`).join("; ")}): nothing was recorded.${open.length ? ` Still late: ${open.map(itemWords).join(", ")}: resolve those, then call done.` : " Nothing is late against the report: call done."}` };
    }
    if (stale.generation || stale.digest || problems.length) {
      const words = [
        ...(stale.generation ? [`the lease is at generation ${stale.generation.current} (held by ${lease.holder}), not ${stale.generation.expected}`] : []),
        ...(stale.digest ? [`${lease.report} is at digest ${current ?? "none (it does not exist)"}, not ${digestIn}`] : []),
        ...problems.map((p) => `${p.item} (item ${p.index}) ${p.problem}`),
      ];
      const fix = stale.generation || stale.digest ? " Read the report again (finish prepare or finish status gives its generation and digest), then send the batch with them." : " Leave those items out and send the batch again.";
      return { ok: false as const, reason: `${words.join("; ")}.${fix} Nothing was recorded.${stillLateWords}`, ...(stale.generation || stale.digest ? { stale } : {}), ...(problems.length ? { problems } : {}), unresolved };
    }
    const written = await appendFinish(ctx.sandboxRoot, items.map((x) => ({ by: ctx.agentId, ev: "resolve" as const, ...(x.kind === "post" ? { post: x.id } : { ack: x.id }), how: x.how, why: x.words, ...(current ? { digest: current } : {}), generation: lease.generation, batch: key })), held);
    const after = await lateItems(ctx.sandboxRoot, ctx.agentId, lease.report);
    return { ok: true as const, key, seqs: written.map((e) => e.seq), resolved: written.length, generation: lease.generation, digest: current, late: after, ...(after.length ? { note: `still late against the report: ${after.map(itemWords).join(", ")}` } : {}) };
  });
}

/**
 * The coordinator prepares the finish (docs/adr/0015, "Preparing the
 * finish"): after drafting the report, before inviting its review and
 * calling done. The lease and the report's boundary are taken exactly as a
 * done takes them (takeLease): a first lease, a takeover of an unavailable
 * holder, a report named anew, a resume's new segment. No goal check is run
 * and no sentinel written. The reply is readiness by the registers (and the
 * answers check's warnings) and every item late against the report, whole,
 * with the generation and the report's digest a batch of resolutions
 * carries; a `prepare` event records it. Any other seat's prepare is
 * answered "not yours", quietly, as its done is.
 *
 * Preparing again, or after a takeover, keeps the earliest boundary: a
 * later prepare never moves it on, so nothing late is forgiven by it.
 */
export async function prepareFinish(ctx: P.SwarmContext, input: { report?: string } = {}, now = Date.now()): Promise<Record<string, unknown> & ({ ok: true } | { ok: false; reason: string })> {
  const S = ctx.sandboxRoot;
  if (await P.swarmDoneExists(S)) return { ok: false, reason: "the run is finished (done/SWARM_DONE): call done and stop" };
  const named = String(input.report ?? "").trim().replace(/^\.\//, "") || null;
  const report = named ?? (await readFinish(S)).lease?.report ?? null;
  if (!report) return { ok: false, reason: "name the report you drafted (report, e.g. work/report.md): prepare binds the finish to it" };
  if (!(await reportDigest(S, report))) return { ok: false, reason: `${report} does not exist yet: write the report and publish it, then prepare the finish on it` };
  const r = await readiness(S);
  const readinessOut = { ready: r.ready, revision: r.revision, items: r.items, limited: r.limited, ...heldOut(r), ...(r.warnings.length ? { warnings: r.warnings } : {}) };
  const got = await withFinish(S, async (held) => {
    const turn = await takeLease(ctx, report, now, held);
    if (!turn.mine) return { turn, mine: false as const };
    // A report published again: which reviews of the earlier version still stand, and which are asked again, before the prepare.
    await appendCarry(S, held);
    const lease = (await readFinish(S)).lease!;
    const late = await lateItems(S, ctx.agentId, turn.report);
    const digest = await reportDigest(S, turn.report);
    const [e] = await appendFinish(S, [{ by: ctx.agentId, ev: "prepare", generation: turn.generation, ...(turn.report ? { report: turn.report } : {}), ...(digest ? { digest } : {}), ...(typeof lease.since === "number" ? { since: lease.since } : {}), ...(lease.segment ? { segment: lease.segment } : {}), ready: r.ready, revision: r.revision, late: late.map((x) => ({ kind: x.kind, id: x.id })) }], held);
    return { turn, mine: true as const, lease, late, digest, seq: e.seq };
  });
  const turn = got.turn;
  if (!got.mine) {
    const note = turn.holder ? `Not yours: ${turn.holder} coordinates the finish (generation ${turn.generation}: ${turn.why}). Review the report (finish ack), say on the board what is still open, or wait.` : `Not yours: ${turn.why}.`;
    return { ok: true, action: "prepare", mine: false, not_yours: true, coordinator: turn.holder, generation: turn.generation, why: turn.why, readiness: readinessOut, note };
  }
  if (turn.took_over) await P.systemPost(S, { tag: "hold", via: ctx.agentId, body: `${ctx.agentId} coordinates the finish now (generation ${turn.generation}): ${turn.why}.` }).catch(() => undefined);
  const { lease, late, digest } = got;
  const d = digest ?? "";
  const review = await reportReview(S);
  const invite = reviewInvite(review);
  const next = late.length
    ? `Resolve these ${late.length} in one call: finish resolve with items [{post: <id> or ack: <seq>, how: "folded", where: "<where the report says it now>"} or {…, how: "not_material", why: "<why it changes nothing the report concludes>"}], generation ${turn.generation} and digest ${d}. Fold first what changes the report: publish it again, then prepare again for its new digest. Then the review: ${invite}. Call done when the header says ready.`
    : r.ready
      ? `Nothing is late against the report. The review: ${invite}. Then call done.`
      : `Nothing is late against the report. The registers still hold the finish (${r.items.length}): call done once the header says ready. The review: ${invite}.`;
  return {
    ok: true,
    action: "prepare",
    mine: true,
    coordinator: turn.holder,
    generation: turn.generation,
    why: turn.why,
    ...(turn.took_over ? { took_over: turn.took_over } : {}),
    report: turn.report,
    digest,
    boundary: { since: typeof lease.since === "number" ? new Date(lease.since).toISOString() : null, ...(lease.segment ? { segment: lease.segment } : {}), ...(lease.carried.length ? { carried: lease.carried.map((c) => c.id) } : {}) },
    readiness: readinessOut,
    late,
    ...(review ? { reviews: reviewSummary(review) } : {}),
    seq: got.seq,
    next,
  };
}

/** The report's reviews in a reply (finish prepare and status): its sections, each seat's standing, and what no standing review covers. */
function reviewSummary(r: ReviewStanding): Record<string, unknown> {
  return {
    sections: r.sections,
    seats: r.seats.map((x) => ({ by: x.by, standing: x.standing, acks: x.acks, ...(x.standing === "reasked" ? { changed: x.changed, ...(x.removed.length ? { removed: x.removed } : {}) } : {}), ...(x.whole ? {} : { covered: x.covered }) })),
    ...(r.uncovered.length ? { uncovered: r.uncovered } : {}),
  };
}

// --- readiness ----------------------------------------------------------------------------------

/** The answer sections a goal's check names beside its questions: summary and narrative, when it names them. */
async function goalExtraSections(sandboxRoot: string): Promise<string[]> {
  const doc = await L.goalDocument(sandboxRoot);
  if (!doc) return [];
  const out: string[] = [];
  for (const check of L.goalChecks(doc.text)) {
    if (!check.includes("check-answers.ts")) continue;
    const words = L.shellWords(check);
    const i = words.indexOf("--sections");
    for (const raw of (i >= 0 ? words[i + 1] ?? "" : "").split(",")) {
      const s = raw.trim().toLowerCase();
      if ((s === "summary" || s === "narrative") && !out.includes(s)) out.push(s);
    }
  }
  return out;
}

/**
 * Readiness at a revision; `confirming`, the items among `items` that are
 * closures waiting for their closer's confirmation; `warnings`, what the
 * ledger gate warns of on the answers (protocol.ts LedgerWarning), in the
 * words every point says them with, and `warned`, the same warnings whole:
 * said in finish status, never held on.
 */
/**
 * What holds one question, as readiness reads it: its section, the code of
 * what holds it and the words (the regroup post lists these, so the post and
 * the finish line say the same thing about a question).
 */
export type ReadinessHold = { section: string; code: string; why: string };

export type Readiness = { ready: boolean; revision: string; items: string[]; limited: string[]; confirming: string[]; warnings: string[]; warned: P.LedgerWarning[]; held?: ReadinessHold[] };

/**
 * What holds each section, by the ledger gate's code (sweep_hits,
 * no_critic_act, answer_support, …): the codes of the items, for the seat
 * and for the trace, which keeps codes and counts and never the items' words.
 */
export function heldOut(r: Pick<Readiness, "held">): { held?: Array<{ section: string; code: string }> } {
  return r.held?.length ? { held: r.held.map((h) => ({ section: h.section, code: h.code })) } : {};
}

/** The codes that hold the finish, with how many sections each holds: what the trace records of a readiness. */
export function heldCodes(held: unknown): Record<string, number> {
  const out: Record<string, number> = {};
  if (!Array.isArray(held)) return out;
  for (const h of held) {
    const code = h && typeof h === "object" ? String((h as { code?: unknown }).code ?? "") : "";
    if (code) out[code] = (out[code] ?? 0) + 1;
  }
  return out;
}

/** What the trace keeps of a readiness a finish act gave: ready, how many items, and the codes holding sections; never the items' words. */
export function readinessCounts(r: Record<string, unknown>): { ready: boolean; items?: number; held?: Record<string, number> } {
  const held = heldCodes(r.held);
  return { ready: r.ready === true, ...(Array.isArray(r.items) ? { items: r.items.length } : {}), ...(Object.keys(held).length ? { held } : {}) };
}

const readinessCache = new Map<string, Readiness>();

/** How many times readiness reads the registers again when the state moved while it read them, before it answers uncached. */
const READINESS_ATTEMPTS = 3;

/**
 * Whether the registers say the finish line is met, at the revision it is
 * computed for: no material lead open (or waiting for a closure's
 * confirmation), no lead's job waiting for an interpretation, every
 * question in scope answered with nothing the ledger gate holds against it
 * (a negative unreviewed, a dispute, a stale answer) and no answer that
 * claims established held a best candidate only, no question that must be
 * established resting on an answer that only limits the run, and under the
 * operator's stop policy no route limitation left.
 * What would still limit the run is listed apart. Cheap and generic: the
 * goal's own checks run only at the coordinator's done. One result per
 * revision, shared by every reader in this process, and only for the
 * revision its own snapshot was read at: the snapshot is read here, between
 * two readings of the revision that agree (a caller's snapshot may be older
 * than the revision, and a lead admitted between them would be cached as
 * never there). A state that never holds still is answered, never cached.
 */
export async function readiness(sandboxRoot: string): Promise<Readiness> {
  let last: Readiness | null = null;
  for (let i = 0; i < READINESS_ATTEMPTS; i++) {
    const { revision } = await P.stateRevision(sandboxRoot);
    const hit = readinessCache.get(`${sandboxRoot}\u0000${revision}`);
    if (hit) return hit;
    const out = await computeReadiness(sandboxRoot, await L.leadsSnapshot(sandboxRoot), revision);
    if ((await P.stateRevision(sandboxRoot)).revision !== revision) {
      last = out;
      continue;
    }
    readinessCache.set(`${sandboxRoot}\u0000${revision}`, out);
    if (readinessCache.size > 256) readinessCache.delete(readinessCache.keys().next().value!);
    return out;
  }
  return last!;
}

/** The answer sections readiness reads: the case's questions, and the summary and narrative a goal's check names. */
async function readinessSections(sandboxRoot: string, s: L.LeadsSnapshot): Promise<string[]> {
  return [...L.caseQuestions(s).map((q) => `question:${q}`), ...(await goalExtraSections(sandboxRoot))];
}

/**
 * The ledger gate's inputs as readiness reads them from a snapshot: the
 * acts on the ledger, each question's bar, the store sweeps and the
 * additions' reverse sweeps, the case
 * policy (so a warning's fix reads as the answers check words it), what
 * the lead register recorded under each question's leads (none from a lead
 * register whose chain is broken) and the sources' broad extractions (the
 * store journal's preparation receipts, extensions/preparation.ts). One
 * reading for readiness and for every point a warning is delivered at
 * (warningsAt), so no two say different things.
 */
async function gateInputs(sandboxRoot: string, s: L.LeadsSnapshot): Promise<Omit<Parameters<typeof P.ledgerGate>[0], "sections">> {
  const attestations = await P.readAttestations(sandboxRoot).catch(() => [] as P.LedgerAttestation[]);
  const disputes = await P.readDisputes(sandboxRoot).catch(() => [] as P.LedgerDispute[]);
  const bar = (id: string) => {
    const q = s.questions?.bySection.get(P.sectionKey(id));
    return { material: s.goal.questions.map(P.sectionKey).includes(P.sectionKey(id)) || !q || q.materiality === "material", existence: s.goal.existence.map(P.sectionKey).includes(P.sectionKey(id)) || q?.expects === "existence", completeness: q?.completeness === true };
  };
  const sweeps = await import("./store-sweep.ts").then((SW) => SW.readSweeps(sandboxRoot)).catch(() => []);
  // The additions' reverse sweeps: their hits said with the stale answers they bear on, warned of otherwise.
  const imports = await import("./store-sweep.ts").then((SW) => SW.readImportSweeps(sandboxRoot)).catch(() => []);
  const moreEvidence = await import("./requests.ts").then((R) => R.casePolicyMoreEvidence(sandboxRoot)).catch(() => "ask" as const);
  // What the lead register recorded under each question's leads: a finding two seats hold there that an answer leaves out is warned of.
  const underLeads = s.state.chain.ok ? L.questionLeadEntries(s.state) : undefined;
  const preparation = await import("./preparation.ts").then((PR) => PR.preparationFacts(sandboxRoot, s.ledger.entries, s.state.leads.values())).catch(() => undefined);
  // The premise register, from the question chain (premises.ts): what the premise gate reads each citation's scope from.
  const premises = s.questions?.state.premises;
  // What each question takes as happened (docs/adr/0011, "What a question presumes"): a partial answer to one whose premise nothing tests is warned.
  const presumes = await import("./questions.ts").then((Q) => Q.presumptionsOf(s.questions, s.state)).catch(() => new Map());
  return { entries: s.ledger.entries, attestations, disputes, bar, sweeps, ...(imports.length ? { imports } : {}), moreEvidence, ...(underLeads ? { underLeads } : {}), ...(preparation ? { preparation } : {}), ...(premises?.size ? { premises } : {}), ...(presumes.size ? { presumes } : {}) };
}

/**
 * Where the answers check's warnings are delivered, as well as in the
 * check itself (docs/adr/0013, "Warnings where the decision is made"):
 * - `record`: the reply to the record that writes a question's answer:
 *   every warning on that question;
 * - `review_offer`: a review offered for an answer (a material negative's,
 *   the only answers reviews are offered for): the warnings on it;
 * - `attest`: the reply to an attest: the warnings on each answer the
 *   attested entry bears on (the answer itself, or the negatives resting on
 *   a coverage record), and each warning that names it (an entry an answer
 *   leaves out, now held by two seats);
 * - `lead_close`: the reply to a lead's close or a confirmation of it (the
 *   lead register's events, `events`): the warnings of each question the
 *   lead serves whose warnings that act changed, by what it recorded under
 *   the lead (its ref and results), as they stand after it;
 * - `finish_status`: every warning readiness carries.
 * Never a refusal, never an item: nothing holds on a warning.
 */
export type WarningPoint = { point: "record"; section: string } | { point: "review_offer"; entry: number } | { point: "attest"; entry: number } | { point: "lead_close"; events: number[] } | { point: "finish_status" };

/**
 * The warnings a point delivers now, as readiness reads the registers:
 * the same gate over the same inputs (gateInputs), for the questions
 * readiness reads, so a reply never says what finish status would not.
 */
export async function warningsAt(sandboxRoot: string, at: WarningPoint): Promise<P.LedgerWarning[]> {
  if (at.point === "finish_status") return (await readiness(sandboxRoot)).warned;
  const s = await L.leadsSnapshot(sandboxRoot);
  const all = await readinessSections(sandboxRoot, s);
  if (at.point === "lead_close") return closeChanged(sandboxRoot, s, all, at.events);
  const e = at.point === "record" ? null : s.ledger.bySeq.get(at.entry);
  if (at.point !== "record" && !e) return [];
  const sections = at.point === "record" ? all.filter((x) => x === at.section) : at.point === "review_offer" ? all.filter((x) => e!.kind === "answer" && x === e!.section) : all;
  if (!sections.length) return [];
  const gate = P.ledgerGate({ ...(await gateInputs(sandboxRoot, s)), sections });
  if (at.point === "record") return gate.warnings;
  if (at.point === "review_offer") return gate.warnings.filter((w) => w.seqs[0] === at.entry);
  const resting = new Set(e!.kind === "coverage" ? P.negativesResting(e!, s.ledger.entries).map((x) => x.seq) : []);
  return gate.warnings.filter((w) => w.seqs.includes(at.entry) || resting.has(w.seqs[0]!));
}

/**
 * What a lead's close or confirmation changed (warningsAt, lead_close): the
 * gate over each question the act's leads serve, once as the register
 * stands and once as it would without the act's events, on the same
 * snapshot, so nothing else that moved meanwhile is laid at its door. The
 * warnings, as they stand, of each question whose warnings differ.
 */
async function closeChanged(sandboxRoot: string, s: L.LeadsSnapshot, all: string[], events: readonly number[]): Promise<P.LedgerWarning[]> {
  const acts = s.state.events.filter((e) => events.includes(e.seq) && (e.ev === "close" || e.ev === "confirm") && e.lead);
  if (!acts.length || !s.state.chain.ok) return [];
  const served = new Set(acts.flatMap((e) => s.state.leads.get(e.lead!)?.answers ?? []).map((x) => `question:${P.sectionKey(x)}`));
  const sections = all.filter((x) => served.has(x));
  if (!sections.length) return [];
  const inputs = await gateInputs(sandboxRoot, s);
  const without = new Set(acts.map((e) => e.seq));
  const before = P.ledgerGate({ ...inputs, sections, underLeads: L.questionLeadEntries(L.foldLeads(s.state.events.filter((e) => !without.has(e.seq)), s.state.chain)) }).warnings;
  const after = P.ledgerGate({ ...inputs, sections }).warnings;
  const words = (ws: P.LedgerWarning[], section: string) => JSON.stringify(ws.filter((w) => w.section === section).map((w) => [w.code, w.seqs, w.what]));
  const changed = new Set(sections.filter((x) => words(before, x) !== words(after, x)));
  return after.filter((w) => changed.has(w.section));
}

async function computeReadiness(sandboxRoot: string, s: L.LeadsSnapshot, revision: string): Promise<Readiness> {
  const items: string[] = [];
  const limited: string[] = [];
  const held: ReadinessHold[] = [];
  const lead = await L.leadDefects(sandboxRoot, s);
  const confirming: string[] = [];
  for (const d of lead.defects) {
    items.push(d.what);
    if (d.lead && s.state.leads.get(d.lead)?.confirm) confirming.push(d.what);
  }
  // An addition committed and not yet applied (docs/adr/0014): what it reopens may still look settled; the gate holds it too.
  const M = await import("../scripts/material.ts").catch(() => null);
  for (const a of (await M?.unappliedAdditions(sandboxRoot).catch(() => [])) ?? []) items.push(`import:${a.import} (${a.type === "evidence_added" ? "evidence" : "material"} added at ${a.at}) is committed and not all it implies is recorded yet (the hub records it at its next round)`);
  const sections = await readinessSections(sandboxRoot, s);
  const inputs = await gateInputs(sandboxRoot, s);
  const { attestations } = inputs;
  // The kept output of a cancelled or stopped job, cited with no word on how it is treated (docs/adr/0016): the answers check holds it, and so does readiness.
  // The producer of each citation (scripts/output-hygiene.ts producerIndex): a copy or a digest of a cancelled job's bytes keeps its partial status.
  const hygiene = await import("../scripts/output-hygiene.ts").catch(() => null);
  const { producerOf } = hygiene ? await hygiene.producerIndex(sandboxRoot).catch(() => ({ producerOf: (_ref: string) => null })) : { producerOf: (_ref: string) => null };
  const partial = P.partialOutputCites(s.ledger.entries, producerOf);
  const gate = P.ledgerGate({ ...inputs, sections, partial });
  // What the gate warns of: shown to every seat that reads finish status, and never an item.
  const warnings = gate.warnings.map(P.warningWords);
  const accepted = new Set<string>();
  const acceptedAt = new Map<string, number | null>();
  for (const q of s.questions?.state.questions.values() ?? []) {
    if (!q.accepted || !(await import("./questions.ts")).acceptanceStands(q, s.ledger)) continue;
    accepted.add(`question:${q.section}`);
    acceptedAt.set(`question:${q.section}`, q.accepted.ledger_seq ?? null);
  }
  for (const d of gate.open) {
    // What an acceptance excuses (P.acceptanceExcuses): all but the negative bar's defects, a partial sweep, and evidence added before it.
    if (d.section && accepted.has(d.section) && P.acceptanceExcuses(d, acceptedAt.get(d.section))) continue;
    items.push(d.what);
    if (d.section?.startsWith("question:")) held.push({ section: d.section, code: d.code, why: d.code === "no_answer" ? "no answer" : d.what });
  }
  // Best candidates, stale answers, and what else would limit the run.
  // A best candidate (an answer that claims established, every review of
  // which holds it a best candidate only: P.heldAsBestCandidate, the test
  // the answers check and the finish gate read too) has no disposition, so
  // it holds readiness under every stop policy, as it holds the done. Under
  // the operator's stop policy a route limitation holds readiness too (ADR
  // 0015, 8). A disposition that only limits the run (partial, not
  // determinable, a bounded negative, out of scope, a premise shown not to
  // hold, an acceptance) never holds it, whatever its reviews' strength:
  // the done ends the run examination-limited on it, and readiness held on
  // it would never turn ready before a done that passes (the c10 pilot:
  // "never ready"; the run s9722fa: six partial answers read as "a best
  // candidate, not established", and all six walked down to not
  // determinable).
  const holdsUnderOperator: string[] = [];
  const disposed = new Map<string, "answered" | "accepted">();
  for (const sec of sections) {
    if (!sec.startsWith("question:")) continue;
    if (accepted.has(sec)) {
      disposed.set(sec.slice("question:".length), "accepted");
      limited.push(`${sec} was accepted by the operator`);
      continue;
    }
    const a = gate.answers[sec];
    if (!a) continue;
    const result = NB.answerResult(a);
    if (P.heldAsBestCandidate(a, P.answerReviews(a, attestations))) {
      items.push(`${sec} is a best candidate, not established (E-${a.seq} claims established, and every review holds it a best candidate only)`);
      held.push({ section: sec, code: "best_candidate", why: `answer E-${a.seq} claims established and every review holds it a best candidate only` });
      continue;
    }
    const q = s.questions?.bySection.get(sec.slice("question:".length));
    if (q && (a.question_rev ?? 1) !== q.rev) {
      items.push(`${sec}'s answer E-${a.seq} predates revision ${q.rev} of ${q.id}`);
      held.push({ section: sec, code: "predates_revision", why: `answer E-${a.seq} predates revision ${q.rev} of ${q.id}` });
      continue;
    }
    // Stale by evidence too (docs/adr/0014): evidence for the question arrived after the answer was recorded, as the gate holds it.
    const arrived = q?.evidence.find((x) => a.seq <= x.ledger_seq);
    if (q && arrived) {
      items.push(`${sec}'s answer E-${a.seq} predates new evidence for ${q.id} (${arrived.import})`);
      held.push({ section: sec, code: "predates_evidence", why: `answer E-${a.seq} predates new evidence for ${q.id} (${arrived.import})` });
      continue;
    }
    // A question that must be established (docs/adr/0013): an answer that
    // only limits the run is no disposition for it, so it holds readiness
    // as it holds the done, under every stop policy, until it is
    // established, or the operator accepts its limits (above) or releases it.
    const QM = await import("./questions.ts");
    if (q && QM.mustEstablish(q) && !QM.establishesBy(a)) {
      items.push(`${sec} must be established (required by ${QM.requiredByWords(q)}): its answer E-${a.seq} is ${NB.resultWords(result ?? "not_determinable")}, which ends no run on it: ${QM.MUST_ESTABLISH_WAYS}`);
      held.push({ section: sec, code: "must_establish", why: `must be established (required by ${QM.requiredByWords(q)}): answer E-${a.seq} is ${NB.resultWords(result ?? "not_determinable")}, which ends no run on it` });
      continue;
    }
    if (result && result !== "established" && result !== "premise_not_supported") limited.push(`${sec} is ${NB.resultWords(result)}`);
    if (!gate.defects.some((d) => d.section === sec)) disposed.set(sec.slice("question:".length), "answered");
  }
  for (const l of lead.limiting) {
    const lv = s.state.leads.get(l.lead);
    const v = lv ? L.routeLimitation(lv, (q) => disposed.get(q) ?? null) : { limiting: true, why: "" };
    if (v.limiting) {
      const line = `${l.lead} was closed ${l.disposition} (${l.ref})${v.why ? `: ${v.why}` : ""}`;
      limited.push(line);
      holdsUnderOperator.push(line);
    }
  }
  const budget = await P.readBudget(sandboxRoot).catch(() => null);
  const operatorStop = P.stopPolicyOf(budget) === "operator";
  const blocking = operatorStop ? [...items, ...holdsUnderOperator] : items;
  return { ready: !blocking.length, revision, items: blocking, limited, confirming: confirming.filter((c) => blocking.includes(c)), warnings, warned: gate.warnings, held };
}


/**
 * Readiness posted once each time it turns (A4): ready, the coordinator is
 * told to call done and everyone else to wait; not ready again, what came
 * up. Recorded in the finish register, so a restart posts nothing twice.
 */
export async function syncReadiness(sandboxRoot: string, r: Omit<Readiness, "warnings" | "warned">): Promise<boolean> {
  const st = await readFinish(sandboxRoot);
  const last = st.readiness;
  if (last && last.ready === r.ready) return false;
  if (await P.swarmDoneExists(sandboxRoot)) return false;
  return withFinish(sandboxRoot, async (held) => {
    const again = (await readFinish(sandboxRoot)).readiness;
    if (again && again.ready === r.ready) return false;
    await appendFinish(sandboxRoot, [{ by: "system", ev: "readiness", ready: r.ready, revision: r.revision, items: r.items }], held);
    // The first state is recorded (the register then exists from the first
    // header, and the metrics read readiness from it); not ready from the
    // start is nothing to post.
    if (!again && !r.ready) return false;
    const lease = st.lease;
    const who = lease ? `${lease.holder} coordinates the finish (generation ${lease.generation})` : "The seat that publishes the report coordinates the finish (the first prepare or done takes it)";
    const body = r.ready
      ? `FINISH READY by the registers at revision ${r.revision.slice(0, 12)}: every material lead has a disposition, every question in scope an answer the ledger gate holds nothing against${r.limited.length ? ` (limited: ${r.limited.join("; ")})` : ""}. ${who}: it prepares the finish (finish prepare), resolves what is late against the report in one call, and its done runs the goal's checks. Everyone else: do not call done; review the report (finish ack), say what is still open, or wait.`
      : `FINISH NOT READY again at revision ${r.revision.slice(0, 12)}: ${r.items.join("; ")}.`;
    await P.systemPost(sandboxRoot, { tag: "hold", body }).catch(() => undefined);
    return true;
  }).catch(() => false);
}

/**
 * The finish phase: whether the coordinator is assembling the finish. It
 * is, while a coordinator holds the lease and the registers are met but for
 * what is late against the report, a closure waiting for its confirmation
 * or a resolution (the c10 pilot's tail ran over 90 minutes as answers kept
 * being revised in it). Then another seat's answer revision is recorded
 * only with `material` (protocol.ts recordAnswer); a material one reopens
 * readiness as ever, and the phase ends until the registers are met again.
 */
export type FinishPhase = { assembling: boolean; coordinator: string | null; generation: number; why: string; pending: string[] };

export async function finishPhase(sandboxRoot: string): Promise<FinishPhase> {
  if (await P.swarmDoneExists(sandboxRoot)) return { assembling: false, coordinator: null, generation: 0, why: "the run is finished", pending: [] };
  const lease = (await readFinish(sandboxRoot)).lease;
  if (!lease) return { assembling: false, coordinator: null, generation: 0, why: "no coordinator holds the finish yet", pending: [] };
  const r = await readiness(sandboxRoot);
  const open = r.items.filter((i) => !r.confirming.includes(i));
  if (open.length) return { assembling: false, coordinator: lease.holder, generation: lease.generation, why: `the registers are not met: ${open.join("; ")}`, pending: [] };
  const late = await lateItems(sandboxRoot, lease.holder, lease.report);
  return { assembling: true, coordinator: lease.holder, generation: lease.generation, why: `${lease.holder} holds the finish and the registers are met${r.confirming.length || late.length ? ` but for ${[...r.confirming, ...late.map(lateWords)].join("; ")}` : ""}`, pending: [...r.confirming, ...late.map(lateWords)] };
}

/** The phase recorded in the finish register each time it turns (assembling, or open again). */
export async function syncPhase(sandboxRoot: string, p: FinishPhase): Promise<boolean> {
  const want = p.assembling ? "assembling" : "open";
  const last = (await readFinish(sandboxRoot)).phase;
  if ((last?.phase ?? "open") === want) return false;
  return withFinish(sandboxRoot, async (held) => {
    const again = (await readFinish(sandboxRoot)).phase;
    if ((again?.phase ?? "open") === want) return false;
    await appendFinish(sandboxRoot, [{ by: "system", ev: "phase", phase: want, ...(p.coordinator ? { holder: p.coordinator } : {}), why: p.why }], held);
    return true;
  }).catch(() => false);
}

/**
 * Readiness for the header, shared: eight seats that wake on one post ask at once, and each call walked every
 * register. One computation serves the calls of the next READINESS_SHARE_MS; a gate decision (prepare, done, status)
 * never reads it.
 */
const READINESS_SHARE_MS = 2000;
const readinessHeld = new Map<string, { at: number; value: Promise<Awaited<ReturnType<typeof readiness>>> }>();
function readinessShared(sandboxRoot: string): Promise<Awaited<ReturnType<typeof readiness>>> {
  const had = readinessHeld.get(sandboxRoot);
  if (had && Date.now() - had.at < READINESS_SHARE_MS) return had.value;
  const value = readiness(sandboxRoot);
  readinessHeld.set(sandboxRoot, { at: Date.now(), value });
  value.catch(() => readinessHeld.delete(sandboxRoot));
  return value;
}

/** The finish in the header (A4): readiness, the coordinator, and what this seat does about it. */
export async function finishHeader(sandboxRoot: string, me: string): Promise<string | null> {
  if (await P.swarmDoneExists(sandboxRoot)) return null;
  const r = await readinessShared(sandboxRoot);
  await syncReadiness(sandboxRoot, r).catch(() => false);
  const st = await readFinish(sandboxRoot);
  const lease = st.lease;
  const mine = lease?.holder === me;
  const who = lease ? `${lease.holder}${mine ? " (you)" : ""} coordinates it (generation ${lease.generation})` : "nobody coordinates it yet: the first prepare or done takes it (normally the report's publisher, who prepares it with finish prepare once the report is drafted)";
  // The header rides on every wait, inbox and leads answer and on every hand-off: it names the caller's own items and
  // a few of the rest, each cut to a bound, and counts the others. The whole list is finish status's. Joined whole it
  // was 40-59% of all wait output in four runs, and 38 MB a call once an item listed 137,703 unsearched objects.
  const shown = boundItems(r.items, (item) => item.includes(me));
  const state = r.ready
    ? `READY by the registers${r.limited.length ? `, limited: ${boundItems(r.limited, () => false).text}` : ""}`
    : `not ready (${r.items.length}${shown.own ? `, ${shown.own} of them yours` : ""}): ${shown.text}`;
  let act = "";
  // The finish phase: recorded when it turns, and said to every seat.
  const phase = await finishPhase(sandboxRoot).catch(() => null);
  if (phase) await syncPhase(sandboxRoot, phase).catch(() => false);
  if (phase?.assembling) act += mine ? " ASSEMBLING: you assemble the finish; another seat's answer revision is admitted only with material (why it changes a conclusion); yours are free." : ` ASSEMBLING by ${phase.coordinator}: an answer revision from another seat is admitted only with material (why it changes a conclusion); a rewording or a restatement is not recorded now.`;
  if (mine) {
    const differs = await reportCheck(sandboxRoot, lease.report).catch(() => [] as string[]);
    if (differs.length) act += ` The report and the ledger differ in ${differs.length} place(s) (finish status lists them under report_against_ledger): bring them together before done.`;
    const late = await lateItems(sandboxRoot, me, lease.report);
    const digest = await reportDigest(sandboxRoot, lease.report);
    act += late.length ? ` Late against the report, each for your typed resolution, all in one call (finish resolve with items, generation ${lease.generation}, digest ${(digest ?? "").slice(0, 12)}): ${late.map((x) => (x.kind === "post" ? `post #${x.id} (${x.tag}) by ${x.by}` : `objection ${x.id} by ${x.by}: ${x.why}`)).join("; ")}.` : r.ready ? " Call done." : "";
    // The report's review: who stands (carried over where the sections they reviewed are unchanged), and whom to ask again, on what.
    await syncCarry(sandboxRoot).catch(() => false);
    const review = await reportReview(sandboxRoot).catch(() => null);
    if (review?.seats.length) act += ` Review: ${reviewInvite(review)}.`;
  } else if (lease) {
    await syncCarry(sandboxRoot).catch(() => false);
    const own = ownReviewWords(await reportReview(sandboxRoot).catch(() => null), me);
    act += own ?? " Your done is not the finish: when your slice ends, review the report (finish ack) or say on the board what is open, and wait.";
  }
  return `Finish: ${state}; ${who}.${act}`;
}

// --- checks, one per revision ------------------------------------------------------------------

/** The check recorded for a revision, if any: a done at the same revision takes it instead of running the finish line again. */
export async function checkAt(sandboxRoot: string, revision: string): Promise<FinishState["checks"][number] | null> {
  if (!revision) return null;
  return (await readFinish(sandboxRoot)).checks.filter((c) => c.revision === revision).at(-1) ?? null;
}

/** Record what the finish line said at a revision (whole: the run the verdict was made from). */
export async function recordCheck(sandboxRoot: string, by: string, revision: string, verdict: { proceed: boolean; outcome?: string; reason?: string }, run: unknown): Promise<void> {
  if (!revision) return;
  await withFinish(sandboxRoot, async (held) => {
    if ((await readFinish(sandboxRoot)).checks.some((c) => c.revision === revision)) return;
    await appendFinish(sandboxRoot, [{ by, ev: "check", revision, proceed: verdict.proceed, ...(verdict.outcome ? { outcome: verdict.outcome } : {}), ...(verdict.reason ? { reason: verdict.reason } : {}), run }], held);
  });
}

/**
 * Where the finish stands, for any seat (finish status): readiness, the
 * coordinator, the last check, the report's review, and what is late
 * against the report. What is late needs the lease's boundary: before a
 * coordinator's prepare (or done) there is none, and nothing is listed.
 */
/**
 * A report held against the ledger: each question's standing answer whose value's first line the report does not hold,
 * and each E-<n> the report cites that the ledger does not have. A run's report held six exact strings its ledger had
 * as sentences (s082123), another cited E-97 in a ledger that ended at E-95, a third said "pending" twelve minutes
 * after the answer was recorded. Pure: `answers` are the standing answers, `maxSeq` the ledger's last entry.
 */
export function reportAgainstLedger(report: string, answers: ReadonlyArray<{ section: string; seq: number; value: string }>, maxSeq: number): string[] {
  const out: string[] = [];
  const flat = report.replace(/[*_`]/g, "").replace(/\s+/g, " ").toLowerCase();
  for (const a of answers) {
    const first = firstLine(a.value);
    if (!first) continue;
    const want = first.replace(/[*_`]/g, "").replace(/\s+/g, " ").toLowerCase();
    if (!flat.includes(want)) out.push(`the report does not hold ${a.section}'s standing answer (E-${a.seq}): its value's first line, ${first.length > 120 ? `${first.slice(0, 117)}...` : first}, is not in it; the report and the ledger must say the same, so bring one to the other`);
  }
  const cited = new Set([...report.matchAll(/\bE-(\d{1,6})\b/g)].map((m) => Number(m[1])));
  const missing = [...cited].filter((n) => n > maxSeq || n < 1).sort((x, y) => x - y);
  if (missing.length) out.push(`the report cites ${missing.slice(0, 10).map((n) => `E-${n}`).join(", ")}${missing.length > 10 ? ` and ${missing.length - 10} more` : ""}, which the ledger does not have (its last entry is E-${maxSeq})`);
  return out;
}

/** The standing report held against the standing answers, or [] with no report to read. */
export async function reportCheck(sandboxRoot: string, report: string | null | undefined): Promise<string[]> {
  if (!report) return [];
  const bytes = await P.readSandboxFile(sandboxRoot, report).catch(() => null);
  if (!bytes) return [];
  const entries = await P.readLedger(sandboxRoot).catch(() => [] as P.LedgerEntry[]);
  const replaced = P.supersededBy(entries);
  const answers = entries.filter((e) => e.kind === "answer" && !replaced.has(e.seq) && String(e.section ?? "").startsWith("question:")).map((e) => ({ section: String(e.section), seq: e.seq, value: String(e.value ?? "") }));
  return reportAgainstLedger(Buffer.from(bytes.bytes).toString("utf8"), answers, entries.reduce((m, e) => Math.max(m, e.seq), 0));
}

export async function finishStatus(ctx: P.SwarmContext): Promise<Record<string, unknown>> {
  const r = await readiness(ctx.sandboxRoot);
  const st = await readFinish(ctx.sandboxRoot);
  const reportItems = await reportCheck(ctx.sandboxRoot, st.lease?.report).catch(() => [] as string[]);
  const digest = await reportDigest(ctx.sandboxRoot, st.lease?.report);
  const review = await reportReview(ctx.sandboxRoot, st).catch(() => null);
  const last = st.checks.at(-1);
  const prepared = st.prepares.at(-1);
  return {
    ok: true,
    ready: r.ready,
    revision: r.revision,
    items: r.items,
    limited: r.limited,
    ...heldOut(r),
    // What the answers check warns of and the finish never holds on: the coordinator weighs each before its done.
    ...(r.warnings.length ? { warnings: r.warnings } : {}),
    // The boundary late items are read against (the lease's since), its resume segment and what it carries from before a resume.
    coordinator: st.lease ? { holder: st.lease.holder, generation: st.lease.generation, why: st.lease.why, report: st.lease.report, digest, boundary: typeof st.lease.since === "number" ? new Date(st.lease.since).toISOString() : null, ...(st.lease.segment ? { segment: st.lease.segment } : {}), ...(st.lease.carried.length ? { carried: st.lease.carried.map((c) => c.id) } : {}) } : null,
    // The coordinator's last prepare: when, at which generation and digest, and how many items it was given as late.
    ...(prepared ? { prepared: { by: prepared.by, at: prepared.at, generation: prepared.generation, digest: prepared.digest, late: prepared.late.length, current: prepared.generation === st.lease?.generation && prepared.digest === digest } } : {}),
    ...(last ? { last_check: { revision: last.revision, current: last.revision === r.revision, proceed: last.proceed, outcome: last.outcome ?? null, reason: last.reason ?? null, by: last.by, at: last.at } } : {}),
    acks: st.acks.filter((a) => a.digest === digest).map((a) => ({ seq: a.seq, by: a.by, verdict: a.verdict, why: a.why, ...(a.sections && !a.whole ? { sections: Object.keys(a.sections) } : {}) })),
    // Every review that stands for this version (on it, or carried over from an earlier one whose sections it covered are unchanged), and those asked again on what changed.
    ...(review ? { reviews: { ...reviewSummary(review), invite: reviewInvite(review), ...(st.carries.some((c) => c.digest === review.digest && c.report === review.report) ? { carry: st.carries.filter((c) => c.digest === review.digest && c.report === review.report).at(-1)!.seq } : {}) } } : {}),
    late: st.lease ? await lateItems(ctx.sandboxRoot, st.lease.holder, st.lease.report) : [],
    // The report held against the ledger: where they say different things, for the coordinator to bring them together before done.
    ...(reportItems.length ? { report_against_ledger: reportItems } : {}),
    chain: st.chain.ok ? "intact" : `BROKEN at line ${st.chain.broken_at} (${st.chain.reason})`,
    ...(existsSync(join(ctx.sandboxRoot, FINISH_LOG)) ? {} : { note: "no finish act yet" }),
  };
}
