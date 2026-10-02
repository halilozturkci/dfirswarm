#!/usr/bin/env node
/**
 * The stop policy from the operator's side and the watchdog's (docs/adr/0013):
 * extending a paused run, the operator's own pause and its lift, recording
 * the operator's stop, reading how a run stands, and the diminishing-returns
 * proposal. The provider's limit is scripts/provider-limit.ts.
 *
 *   stop-policy.ts extend <sandbox> [--minutes N] [--tokens N] [--usd N] [--by WHO]
 *       add to the caps; a paused run whose caps then leave room goes on (the
 *       watchdog wakes its seats), one still over a cap is refused
 *   stop-policy.ts pause <sandbox> [--by WHO] [--why TEXT]
 *       the operator's hold on a going run, under any stop policy: seats idle,
 *       no model call goes out, the wall clock stands, until unpause
 *   stop-policy.ts unpause <sandbox> [--by WHO]
 *       lift a pause whose cause is gone: the provider's limit or the
 *       operator's hold always, a cap's only when the caps leave room (else
 *       refused, pointing to extend); the watchdog wakes the seats
 *   stop-policy.ts stopped <sandbox> [--by WHO] [--why TEXT]
 *       the operator's stop of a run with no sentinel: done/STOPPED, outcome stopped
 *   stop-policy.ts outcome <sandbox>
 *       how the run stands: completed, examination_limited, paused, stopped,
 *       abandoned, verification_unavailable, or null while it runs
 *   stop-policy.ts yield <sandbox> [--now ISO] [--jobs K] [--minutes M]
 *       the diminishing-returns check: when no new finding, question
 *       disposition or coverage record has appeared for M minutes (or, when
 *       a job count is set, across K committed jobs), an operator request of
 *       kind decision proposes a stop. Never an agent's vote, never a stop by
 *       itself: silence is not approval.
 *
 * Each prints one JSON line.
 */
import { readFile, writeFile } from "node:fs/promises";
import { join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import * as P from "../extensions/protocol.ts";
import * as L from "../extensions/leads.ts";

/**
 * How long without a yield before a stop is proposed (SWARM_YIELD_MINUTES,
 * 30), and how many committed jobs, when the operator sets a count
 * (SWARM_YIELD_JOBS; 0, the default, is off). The count proposed by itself
 * until 2026-10-01 (20 jobs or 30 minutes). On the 45 recorded runs with ten
 * jobs or more it proposed 27 times in 10 runs, 26 of them on a burst of 20
 * jobs in one to eight minutes, and every one of those was followed by a
 * yield, 25 within ten minutes; the one stretch that never yielded again
 * had no job at all, and the minutes caught it. So the minutes decide, and
 * the count is the operator's to add (docs/adr/0013, "The stop proposal's
 * window").
 */
export function yieldWindow(env: Record<string, string | undefined> = process.env): { jobs: number; minutes: number } {
  const n = (v: string | undefined, d: number) => (v && /^[1-9]\d*$/.test(v.trim()) ? Number(v) : d);
  return { jobs: n(env.SWARM_YIELD_JOBS, 0), minutes: n(env.SWARM_YIELD_MINUTES, 30) };
}

export const YIELD_STATE_REL = "traces/stop-policy.yield.json";

type YieldState = { proposals: Array<{ id: string; at: string; since: string }> };

/**
 * The last time the run yielded something a case can use: a standing
 * finding, an answer to a question, a coverage record, or a question's
 * disposition or acceptance on the register; the current stretch's start
 * when nothing has since. Generic: kinds and times, never words.
 */
export async function lastYield(sandbox: string): Promise<{ at: number; what: string }> {
  const budget = await P.readBudget(sandbox).catch(() => null);
  const start = Date.parse(budget?.wall_base_at ?? budget?.started_at ?? "") || 0;
  let best = { at: start, what: budget?.wall_base_at ? "the run's resume" : "the run's start" };
  const take = (iso: string | undefined, what: string) => {
    const t = iso ? Date.parse(iso) : NaN;
    if (Number.isFinite(t) && t > best.at) best = { at: t, what };
  };
  const entries = await P.readLedger(sandbox).catch(() => [] as P.LedgerEntry[]);
  const replaced = P.supersededBy(entries);
  for (const e of entries) {
    if (replaced.has(e.seq)) continue;
    if (e.kind === "finding") take(e.at, `E-${e.seq} (a finding)`);
    else if (e.kind === "coverage") take(e.at, `E-${e.seq} (a coverage record)`);
    else if (e.kind === "answer" && e.section?.startsWith("question:")) take(e.at, `E-${e.seq} (an answer to ${e.section})`);
  }
  const Q = await import("../extensions/questions.ts");
  const qs = await Q.questionsSnapshot(sandbox).catch(() => null);
  for (const ev of qs?.state.events ?? []) if (ev.ev === "dispose" || ev.ev === "accept") take(ev.at, `${ev.q} (${ev.ev === "accept" ? "accepted" : "disposed"})`);
  return best;
}

/**
 * The diminishing-returns proposal. When nothing has yielded for M minutes,
 * or across K committed jobs when a count is set (the current stretch of the
 * run, so a resume starts afresh), one operator request of kind decision proposes a stop,
 * with what is still open; another only after a further window with nothing
 * yielded since. A paused or finished run proposes nothing, and nothing is
 * ever stopped here: the operator decides, and silence changes nothing.
 */
export async function yieldCheck(sandbox: string, o: { now?: number; jobs?: number; minutes?: number } = {}): Promise<Record<string, unknown>> {
  const now = o.now ?? Date.now();
  const w = { ...yieldWindow(), ...(o.jobs ? { jobs: o.jobs } : {}), ...(o.minutes ? { minutes: o.minutes } : {}) };
  if (await P.swarmDoneExists(sandbox)) return { proposed: false, why: "the run is finished" };
  const budget = await P.readBudget(sandbox).catch(() => null);
  if (budget?.paused) return { proposed: false, why: "the run is paused: the operator is asked already" };
  const y = await lastYield(sandbox);
  const state: YieldState = await readFile(join(sandbox, YIELD_STATE_REL), "utf8").then((t) => JSON.parse(t) as YieldState).catch(() => ({ proposals: [] }));
  const lastProposal = state.proposals.at(-1);
  // The window runs from the later of the last yield and the last proposal made on it.
  const from = lastProposal && Date.parse(lastProposal.since) >= y.at ? Math.max(y.at, Date.parse(lastProposal.at)) : y.at;
  const jobs = (await L.readJobs(sandbox).catch(() => [] as L.JobFacts[])).filter((j) => j.state === "committed" && j.agent !== "system" && j.agent !== "derived" && j.finished_at && Date.parse(j.finished_at) > from).length;
  const minutes = Math.floor((now - from) / 60_000);
  // The minutes decide; a job count proposes too only when one is set.
  if (minutes < w.minutes && !(w.jobs > 0 && jobs >= w.jobs)) return { proposed: false, since: new Date(y.at).toISOString(), what: y.what, jobs, minutes, window: w };
  const snap = await L.leadsSnapshot(sandbox).catch(() => null);
  const open = snap ? [...snap.state.leads.values()].filter((l) => !l.closed).map((l) => `${l.id} ${l.holder ? `(${l.holder})` : "(unheld)"}`) : [];
  const unanswered = snap ? L.questionCoverage(snap).unanswered.map((q) => `question:${q}`) : [];
  // A request of the operator's, with a durable id, through the outbox (extensions/requests.ts).
  const R = await import("../extensions/requests.ts");
  const n = (await R.countKind(sandbox, "decision")) + 1;
  const id = `D-${n}`;
  const run = (await P.readTeam(sandbox).catch(() => null))?.swarm_id ?? "";
  const sinceIso = new Date(y.at).toISOString();
  const line = {
    at: new Date(now).toISOString(),
    run,
    kind: "decision",
    id,
    by: "harness",
    title: "A stop is proposed: nothing has yielded for a while",
    request:
      `No new finding, question disposition or coverage record since ${sinceIso} (${y.what}): ${jobs} job(s) committed and ${minutes} minute(s) since, the window being ${w.minutes} minutes${w.jobs > 0 ? ` or ${w.jobs} committed jobs` : ""}. ` +
      `Still open: ${open.length ? open.join(", ") : "no lead"}; unanswered: ${unanswered.length ? unanswered.join(", ") : "none"}. The harness proposes that you stop the run. It is never the agents' vote, and nothing happens unless you act.`,
    answer: `swarm.sh stop ${run || "<run>"} ends it as stopped. To let it go on, do nothing: silence is not approval of the stop, and the run goes on under its stop policy.`,
    since: sinceIso,
    jobs,
    minutes,
    open: { leads: open, unanswered },
  };
  const opened = await R.openHarnessRequest(sandbox, { kind: "decision", key: `decision:${id}`, by: "harness", line });
  state.proposals.push({ id, at: line.at, since: sinceIso });
  await writeFile(join(sandbox, YIELD_STATE_REL), `${JSON.stringify(state)}\n`, "utf8");
  return { proposed: true, id, request: opened.rid, since: sinceIso, what: y.what, jobs, minutes, window: w };
}

function opt(args: string[], name: string): string | undefined {
  const i = args.indexOf(name);
  return i >= 0 ? args[i + 1] : undefined;
}

async function main(argv: string[]): Promise<number> {
  const [cmd, sandboxArg, ...rest] = argv;
  if (!cmd || !sandboxArg) {
    process.stderr.write("usage: stop-policy.ts extend|pause|unpause|stopped|outcome|yield <sandbox> [options]\n");
    return 2;
  }
  const sandbox = resolve(sandboxArg);
  const emit = (o: unknown) => process.stdout.write(`${JSON.stringify(o)}\n`);
  const num = (name: string): number | undefined => {
    const v = opt(rest, name);
    if (v === undefined) return undefined;
    const n = Number(v);
    if (!Number.isFinite(n)) throw new Error(`${name} takes a number (got ${JSON.stringify(v)})`);
    return n;
  };
  try {
    switch (cmd) {
      case "extend": {
        const r = await P.extendRun(sandbox, { minutes: num("--minutes"), tokens: num("--tokens"), usd: num("--usd") }, opt(rest, "--by") ?? "operator");
        emit({ ok: true, set: r.set, resumed: r.resumed, paused: Boolean(r.budget.paused), caps: { wall_clock_minutes: r.budget.wall_clock_minutes, cap_tokens: r.budget.cap_tokens ?? null, cap_usd: r.budget.cap_usd } });
        return 0;
      }
      case "pause": {
        const by = opt(rest, "--by") ?? "operator";
        const why = opt(rest, "--why") ?? "";
        const r = await P.pauseRun(sandbox, "operator", why || `${by} paused the run`, Date.now(), { by });
        if (!r.paused) {
          const b = await P.readBudget(sandbox).catch(() => null);
          const reason = r.already && b?.paused ? `the run is paused already, since ${b.paused.at}, for ${P.pauseReasonWords(b.paused)}` : "the run has ended or was stopped: there is nothing to pause";
          emit({ ok: false, reason });
          return 1;
        }
        emit({ ok: true, paused: (await P.readBudget(sandbox)).paused });
        return 0;
      }
      case "unpause": {
        const r = await P.unpauseRun(sandbox, opt(rest, "--by") ?? "operator");
        emit({ ok: true, resumed: r.resumed });
        return 0;
      }
      case "stopped": {
        const r = await P.markStopped(sandbox, opt(rest, "--by") ?? "operator", opt(rest, "--why") ?? "the operator stopped the run");
        emit({ ok: true, ...r });
        return 0;
      }
      case "outcome":
        emit(await P.runOutcome(sandbox));
        return 0;
      case "yield": {
        const at = opt(rest, "--now");
        emit(await yieldCheck(sandbox, { ...(at ? { now: Date.parse(at) } : {}), ...(num("--jobs") ? { jobs: num("--jobs") } : {}), ...(num("--minutes") ? { minutes: num("--minutes") } : {}) }));
        return 0;
      }
      default:
        process.stderr.write(`stop-policy.ts: unknown command ${cmd}\n`);
        return 2;
    }
  } catch (err) {
    emit({ ok: false, reason: (err as Error).message });
    return 1;
  }
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  process.exit(await main(process.argv.slice(2)));
}
