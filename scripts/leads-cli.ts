#!/usr/bin/env node
/**
 * The lead register from outside the panes: the operator's side of it and
 * the watchdog's (extensions/leads.ts).
 *
 *   leads-cli.ts list <sandbox> [--json]            every lead, the operator's requests first, then
 *                                                   the parked leads and the finish (read only)
 *   leads-cli.ts note <sandbox> <L-n> <text> [--allow-host HOST]
 *                                                   the operator's answer: recorded on the lead,
 *                                                   the lead reopened, a host allowed for jobs
 *   leads-cli.ts reopen <sandbox> <L-n> [why]       the operator reopens a closed lead
 *   leads-cli.ts nudge-line <sandbox> <agent>       one line for the idle watchdog's nudge
 *   leads-cli.ts regroup <sandbox> [--now ISO]      an until-solved run's regroup, when one is due:
 *                                                   posted to everyone, printed as one JSON line
 *
 * swarm.sh lead <run> list|note|reopen calls this with the run's sandbox,
 * puts the operator's act on the trace and the operator's record, and posts
 * the note to the board as the examiner.
 */
import { mkdir, readFile, rename, writeFile } from "node:fs/promises";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import * as L from "../extensions/leads.ts";
import * as P from "../extensions/protocol.ts";
import { readCasePolicy } from "./case-policy.ts";
import { operatorSocket } from "./net-broker.ts";

function words(v: L.LeadView): string {
  const needs = v.needs.length ? ` needs ${v.needs.map((n) => `${n.need}${n.met ? " (met)" : ` (unmet: ${n.why})`}`).join(", ")}` : "";
  const held = v.holder ? ` held by ${v.holder} (generation ${v.generation})` : "";
  const ended = v.disposition ? ` closed ${v.disposition} by ${v.closed_by}: ${v.ref}` : "";
  const notes = v.notes.length ? ` operator notes: ${v.notes.map((n) => n.text).join(" | ")}` : "";
  // What coordination adds (docs/adr/0015): the offer that holds it, a closure to confirm, a second route, the product contract.
  const extra: string[] = [];
  if (v.offered) extra.push(`offered to ${v.offered.to} (${v.offered.reason}${v.offered.from ? `, from ${v.offered.from}` : ""}), first claim until ${v.offered.until}`);
  if (v.confirm) extra.push(`CLOSURE TO CONFIRM: closed on ${v.confirm.ref_was}, superseded${v.confirm.head ? ` by ${v.confirm.head}` : ""}; ${v.confirm.to ? `${v.confirm.to} confirms or reopens it` : "its closer cannot take it"}`);
  if (v.overlap) extra.push(`held as ${v.overlap.kind === "verification" ? "a verification" : "a second route"}: ${v.overlap.why}`);
  if (v.covered_by?.length) extra.push(`opened unheld, its questions covered by ${v.covered_by.join(", ")}`);
  for (const d of v.dropped ?? []) extra.push(`need ${d.need} dropped by ${d.by}: ${d.why}`);
  if (v.product) extra.push(`product: ${v.product}; accepted when: ${v.acceptance ?? ""}${v.next_action ? `; then: ${v.next_action}` : ""}`);
  if (v.result_refs?.length) extra.push(`delivered: ${v.result_refs.join(", ")}`);
  return `${v.id} [${v.status}${v.material ? "" : ", not material"}] ${v.title}${held}${needs}${ended}${v.stale ? ` STALE since ${v.stale.at}` : ""}${notes}\n    why: ${v.why}${extra.map((x) => `\n    ${x}`).join("")}`;
}

/** The finish as the operator reads it (extensions/finish.ts): readiness by the registers, the coordinator, the last check and what is late. Read only: nothing is posted from here. */
export async function finishText(sandbox: string): Promise<string> {
  if (await P.swarmDoneExists(sandbox)) return "Finish: the run is finished (done/SWARM_DONE).";
  const F = await import("../extensions/finish.ts");
  const r = await F.readiness(sandbox);
  const st = await F.readFinish(sandbox);
  const lines = [`Finish: ${r.ready ? "READY by the registers" : `not ready (${r.items.length})`}${st.lease ? `; ${st.lease.holder} coordinates it (generation ${st.lease.generation}: ${st.lease.why})` : "; nobody coordinates it yet: the first prepare or done takes it"}.`];
  // The boundary what is late is read against, and the coordinator's last prepare (docs/adr/0015, "Preparing the finish").
  if (st.lease) lines.push(`  boundary: ${typeof st.lease.since === "number" ? `the report as written at ${new Date(st.lease.since).toISOString()}` : "none yet (the report did not exist when the finish was taken)"}${st.lease.segment ? `, segment ${st.lease.segment} (resumed)` : ""}${st.lease.carried.length ? `, ${st.lease.carried.length} post(s) carried from before the resume` : ""}`);
  const prepared = st.prepares.at(-1);
  if (prepared) lines.push(`  prepared: by ${prepared.by} at ${prepared.at}, generation ${prepared.generation}, ${prepared.late.length} item(s) late then`);
  const phase = await F.finishPhase(sandbox).catch(() => null);
  if (phase?.assembling) lines.push(`  phase: assembling by ${phase.coordinator} (${phase.why}): another seat's answer revision is admitted only with material`);
  for (const i of r.items) lines.push(`  holds it: ${i}`);
  for (const i of r.limited) lines.push(`  limits it: ${i}`);
  const last = st.checks.at(-1);
  if (last) lines.push(`  last check: ${last.proceed ? `passed (${last.outcome ?? "?"})` : `refused (${last.reason ?? "?"})`} at ${last.at} by ${last.by}, ${last.revision === r.revision ? "at the current revision" : "at an earlier revision"}`);
  if (st.lease) for (const x of await F.lateItems(sandbox, st.lease.holder, st.lease.report)) lines.push(`  late against the report: ${x.kind === "post" ? `post #${x.id} (${x.tag}) by ${x.by}` : `objection ${x.id} by ${x.by}: ${x.why}`}`);
  return lines.join("\n");
}

/** Every lead, the ones waiting on the operator first, as a reader in a terminal takes them. */
export async function listText(sandbox: string): Promise<string> {
  const snap = await L.leadsSnapshot(sandbox);
  const ranked = L.rankedLeads(snap);
  const lines: string[] = [];
  lines.push(`${ranked.length} lead(s); chain ${snap.state.chain.ok ? `intact, ${snap.state.events.length} events` : `BROKEN at line ${snap.state.chain.broken_at} (${snap.state.chain.reason})`}.`);
  const waiting = ranked.filter((v) => v.disposition === "needs_operator");
  if (waiting.length) {
    lines.push("", "WAITING ON THE OPERATOR:");
    for (const v of waiting) {
      lines.push(`  ${v.id} ${v.title} (closed by ${v.closed_by} at ${v.closed_at})`, `    asks: ${v.ref}`);
      lines.push(`    answer: swarm.sh lead <run> note ${v.id} "<your answer>" [--allow-host HOST]`);
    }
  }
  for (const [name, st] of [["ACTIVE", "active"], ["BLOCKED", "blocked"], ["OPEN", "open"], ["CLOSED", "closed"]] as const) {
    const list = ranked.filter((v) => v.status === st && v.disposition !== "needs_operator");
    if (!list.length) continue;
    lines.push("", `${name}:`);
    for (const v of list) lines.push(`  ${words(v)}`);
  }
  const cov = L.questionCoverage(snap);
  if (snap.goal.questions.length) lines.push("", `Questions: ${snap.goal.questions.length}; without an answer: ${cov.unanswered.map((q) => `question:${q}`).join(", ") || "none"}; of those, held by no lead: ${cov.uncovered.map((q) => `question:${q}`).join(", ") || "none"}.`);
  const parked = await L.parkedLeads(sandbox, snap).catch(() => [] as L.ParkedLead[]);
  if (parked.length) lines.push("", `Parked (held, no job and no act on it while the holder works elsewhere; offered to an idle seat): ${parked.map((p) => `${p.lead} (${p.holder}, ${Math.round(p.idle_ms / 60_000)} min; ${p.elsewhere})`).join("; ")}.`);
  const finish = await finishText(sandbox).catch((err: Error) => `Finish: could not be read (${err.message}).`);
  lines.push("", finish);
  return `${lines.join("\n")}\n`;
}

/**
 * The idle watchdog's line for an agent it nudges: the top question nobody
 * covers, or the ready lead the register ranks first, and the jobs awaiting
 * the agent's interpretation. Empty when there is nothing to name.
 */
export async function nudgeLine(sandbox: string, agent: string): Promise<string> {
  const snap = await L.leadsSnapshot(sandbox);
  const ranked = L.rankedLeads(snap);
  const cov = L.questionCoverage(snap);
  const parts: string[] = [];
  const mine = ranked.filter((v) => v.holder === agent && v.status !== "closed");
  if (mine.length) parts.push(`You hold ${mine.map((v) => `${v.id} (${v.status})`).join(", ")}: go on with it, or lead_release it with why.`);
  const ready = ranked.find((v) => v.status === "open");
  if (ready) parts.push(`The ready lead the register ranks first is ${ready.id} "${ready.title}"${ready.priority ? ` (${ready.priority} waiting on it)` : ""}: lead_claim ${ready.id}.`);
  if (cov.uncovered.length) parts.push(`Question${cov.uncovered.length === 1 ? "" : "s"} nobody holds a lead for: ${cov.uncovered.map((q) => `question:${q}${cov.open_leads_for[q] ? ` (open: ${cov.open_leads_for[q].join(", ")})` : ""}`).join(", ")}.`);
  const awaiting = (await L.awaitingInterpretation(sandbox, snap.state, snap.jobs, snap.ledger)).filter((a) => a.agent === agent);
  if (awaiting.length) parts.push(`Jobs of yours awaiting interpretation: ${awaiting.map((a) => `${a.job}${a.unread_bytes ? ` (${a.unread_bytes} bytes unread)` : ""}`).join(", ")}: record what each shows with interprets.`);
  return parts.join(" ");
}

/** Where the watchdog keeps what it last regrouped on: the harness's own, under traces/. */
export const REGROUP_STATE = "traces/regroup.json";
/** The longest wait between two regroups while nothing moves. */
export const REGROUP_MAX_MINUTES = 240;

type RegroupState = { progress_at: number; count: number; last_at: number; nudged_at?: number; nudged?: string[] };

/**
 * An until-solved run's regroup, when one is due: nothing has moved (no new
 * standing entry, no lead closed, no job committed) for the run's
 * stall_minutes, and, after the first, for twice as long as the wait before
 * the last one, up to REGROUP_MAX_MINUTES. It never stops. The post goes to
 * everyone; the answer is null when none is due.
 */
/** Whether what holds a run still is the store: jobs that have finished (or are fenced) and wait to be sealed. */
export function platformStall(jobs: ReadonlyArray<{ id: string; state: string }>): { jobs: string[]; queued: number } | null {
  const sealing = jobs.filter((j) => j.state === "finished" || j.state === "fenced").map((j) => j.id);
  return sealing.length ? { jobs: sealing, queued: jobs.filter((j) => j.state === "accepted").length } : null;
}

export function platformStallWords(w: { jobs: string[]; queued: number }, minutes: number): string {
  const named = w.jobs.slice(0, 8).join(", ") + (w.jobs.length > 8 ? ` and ${w.jobs.length - 8} more` : "");
  return `PLATFORM STALL: nothing has been sealed for ${minutes} minutes, and the cause is the harness's store, not your work: ${w.jobs.length} job(s) have finished and wait to be sealed (${named})${w.queued ? `, and ${w.queued} more wait for a worker behind them` : ""}. Nothing is asked of you over this: do not cancel or run these jobs again (their output is not lost; job_status says where each stands), and take work that does not wait for them. The operator is told.`;
}

export async function regroup(sandbox: string, now = Date.now()): Promise<{ posted: false; why: string } | { posted: true; kind: "nudge" | "all_hands" | "platform"; count: number; post: number; since: string; next_minutes: number; to?: string[] }> {
  const budget = await P.readBudget(sandbox).catch(() => null);
  if (!budget?.until_solved) return { posted: false, why: "not an until-solved run" };
  if (await P.swarmDoneExists(sandbox)) return { posted: false, why: "the run is over" };
  const stall = (budget.stall_minutes ?? 15) * 60_000;
  const snap = await L.leadsSnapshot(sandbox);
  const since = await L.lastProgress(sandbox, snap, budget.started_at);
  const path = join(sandbox, REGROUP_STATE);
  let state: RegroupState = { progress_at: since.at, count: 0, last_at: 0 };
  try {
    const was = JSON.parse(await readFile(path, "utf8")) as RegroupState;
    if (was.progress_at === since.at) state = was;
  } catch {
    // none yet: the first
  }
  if (now - since.at < stall) return { posted: false, why: `the run moved ${Math.round((now - since.at) / 60_000)} min ago` };
  // The store is the stall: jobs have finished and wait to be sealed. That is the harness's own, and no seat is asked to
  // regroup over it or to cancel a job (on the run s17fdfe a seat was asked whether to cancel a job that had finished 43
  // minutes before and was waiting for its seal). Said once per stall to everyone, and to the operator on the trace.
  const waiting = platformStall(snap.jobs.map((j) => ({ id: j.id, state: j.state })));
  if (waiting) {
    if ((state as RegroupState & { platform_at?: number }).platform_at) return { posted: false, why: `the store is the stall (${waiting.jobs.length} finished job(s) wait to be sealed); said ${Math.round((now - (state as RegroupState & { platform_at?: number }).platform_at!) / 60_000)} min ago` };
    const body = platformStallWords(waiting, Math.round((now - since.at) / 60_000));
    const post = await P.systemPost(sandbox, { tag: "hold", to: "all", body });
    await mkdir(dirname(path), { recursive: true });
    await writeFile(`${path}.tmp`, `${JSON.stringify({ ...state, progress_at: since.at, platform_at: now })}\n`, "utf8");
    await rename(`${path}.tmp`, path);
    return { posted: true, kind: "platform", count: state.count, post: post.id, since: new Date(since.at).toISOString(), next_minutes: Math.round(stall / 60_000) };
  }
  // A job running under a lead is movement for one window (B12): the first
  // regroup nudges that lead's holder, with what the job is doing; if
  // nothing changes in the next window everyone is asked, job or not, so a
  // running job never holds the regroup off for ever.
  const T = await import("./job-telemetry.ts");
  const running: Array<{ job: string; lead: string; holder: string; words: string }> = [];
  for (const j of snap.jobs) {
    if (!L.jobOpen(j)) continue;
    const lead = snap.state.jobLead.get(j.id);
    const holder = lead ? snap.state.leads.get(lead)?.holder : null;
    if (!lead || !holder) continue;
    const p = await T.jobProgressOnDisk(sandbox, j.id, now).catch(() => null);
    running.push({ job: j.id, lead, holder, words: p ? T.progressWords(j.id, p) : `${j.id} ${j.state} (no sample of it yet)` });
  }
  if (running.length && state.count === 0 && !state.nudged_at) {
    const holders = [...new Set(running.map((r) => r.holder))];
    let first = 0;
    for (const h of holders) {
      const mine = running.filter((r) => r.holder === h);
      const body = `REGROUP NUDGE for ${h}: nothing has moved for ${Math.round((now - since.at) / 60_000)} minutes (no new standing entry, no lead closed, no job committed since ${new Date(since.at).toISOString()}), and your job${mine.length === 1 ? " runs" : "s run"} under ${[...new Set(mine.map((r) => r.lead))].join(", ")}: ${mine.map((r) => r.words).join("; ")}. Is it the route? Say so on the board; if it is not, cancel it (cancel keeps what it wrote) and take another. If nothing moves in ${Math.round(stall / 60_000)} minutes, everyone is asked to regroup.`;
      const post = await P.systemPost(sandbox, { tag: "ask", to: h, body });
      if (!first) first = post.id;
    }
    await mkdir(dirname(path), { recursive: true });
    await writeFile(`${path}.tmp`, `${JSON.stringify({ ...state, progress_at: since.at, nudged_at: now, nudged: holders })}\n`, "utf8");
    await rename(`${path}.tmp`, path);
    return { posted: true, kind: "nudge", count: 0, post: first, since: new Date(since.at).toISOString(), next_minutes: Math.round(stall / 60_000), to: holders };
  }
  if (state.nudged_at && state.count === 0 && now - state.nudged_at < stall) return { posted: false, why: `the holders of the running jobs were nudged ${Math.round((now - state.nudged_at) / 60_000)} min ago` };
  const wait = state.count === 0 ? 0 : Math.min(stall * 2 ** state.count, REGROUP_MAX_MINUTES * 60_000);
  if (state.count > 0 && now - state.last_at < wait) return { posted: false, why: `regroup ${state.count} was ${Math.round((now - state.last_at) / 60_000)} min ago` };
  const count = state.count + 1;
  const nextMinutes = Math.round(Math.min(stall * 2 ** count, REGROUP_MAX_MINUTES * 60_000) / 60_000);
  const body = await L.regroupMessage(sandbox, snap, { minutes: Math.round((now - since.at) / 60_000), since, count, nextMinutes, running: running.map((r) => `${r.words} (under ${r.lead}, ${r.holder})`) });
  const post = await P.systemPost(sandbox, { tag: "ask", body });
  await mkdir(dirname(path), { recursive: true });
  await writeFile(`${path}.tmp`, `${JSON.stringify({ progress_at: since.at, count, last_at: now, ...(state.nudged_at ? { nudged_at: state.nudged_at, nudged: state.nudged } : {}) })}\n`, "utf8");
  await rename(`${path}.tmp`, path);
  return { posted: true, kind: "all_hands", count, post: post.id, since: new Date(since.at).toISOString(), next_minutes: nextMinutes };
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  const [cmd, sandboxArg, ...rest] = process.argv.slice(2);
  const usage = () => {
    process.stderr.write("usage: leads-cli.ts list|note|reopen|nudge-line|regroup|seed <sandbox> ...\n");
    process.exit(2);
  };
  if (!cmd || !sandboxArg) usage();
  const sandbox = resolve(sandboxArg);
  const opt = (name: string) => {
    const i = rest.indexOf(name);
    if (i < 0) return undefined;
    const v = rest[i + 1];
    rest.splice(i, 2);
    return v;
  };
  switch (cmd) {
    case "list": {
      if (rest.includes("--json")) {
        const snap = await L.leadsSnapshot(sandbox);
        const F = await import("../extensions/finish.ts");
        const r = await F.readiness(sandbox).catch(() => null);
        const lease = (await F.readFinish(sandbox).catch(() => null))?.lease ?? null;
        const parked = await L.parkedLeads(sandbox, snap).catch(() => [] as L.ParkedLead[]);
        process.stdout.write(`${JSON.stringify({ leads: L.rankedLeads(snap), chain: snap.state.chain, coverage: L.questionCoverage(snap), parked, finish: r ? { ready: r.ready, items: r.items, limited: r.limited, revision: r.revision, coordinator: lease } : null }, null, 2)}\n`);
      } else process.stdout.write(await listText(sandbox));
      break;
    }
    case "note": {
      const host = opt("--allow-host");
      const [lead, ...text] = rest;
      if (!lead || !text.length) usage();
      // Who had the lead last, for the board post: the holder, or the agent that closed it.
      const before = (await L.leadsSnapshot(sandbox)).state.leads.get(String(lead).toUpperCase());
      const to = before?.holder ?? before?.closed?.by ?? "all";
      // A host allowed while the run goes on is a socket grant (tier 2,
      // docs/adr/0012): refused before anything is written where the case
      // policy permits none, and recorded as one, with what it is.
      if (host && readCasePolicy(sandbox).sockets === "none") {
        const policy = readCasePolicy(sandbox).policy;
        process.stdout.write(`${JSON.stringify({ ok: false, reason: `--allow-host would make a socket grant (host and port, no method or path control, no content capture), which policy ${policy} does not permit; answer without it${policy === "ctf" || policy === "live_adversary" ? ", and grant the agent's network request instead (swarm.sh net <run> list)" : ""}` })}\n`);
        process.exit(1);
      }
      const r = await L.noteLead(sandbox, lead, text.join(" "), { ...(host ? { allowHost: host } : {}) });
      const socket = r.ok && host ? await operatorSocket(sandbox, { host, lead: r.lead.id, why: text.join(" ") }, { jobs: true }) : null;
      process.stdout.write(`${JSON.stringify({ ...r, to, ...(socket?.ok ? { grant: socket.grant, socket: socket.text } : socket ? { socket_error: socket.reason } : {}) })}\n`);
      process.exit(r.ok ? 0 : 1);
      break;
    }
    case "reopen": {
      const [lead, ...why] = rest;
      if (!lead) usage();
      const r = await L.reopenLead(sandbox, lead, "operator", why.join(" ") || "the operator reopened it", "operator");
      process.stdout.write(`${JSON.stringify(r)}\n`);
      process.exit(r.ok ? 0 : 1);
      break;
    }
    case "seed": {
      // One open, unheld lead per question no lead answers (swarm.sh --seed-leads).
      process.stdout.write(`${JSON.stringify(await L.seedQuestionLeads(sandbox))}\n`);
      break;
    }
    case "regroup": {
      const at = opt("--now");
      const r = await regroup(sandbox, at ? Date.parse(at) : Date.now());
      process.stdout.write(`${JSON.stringify(r)}\n`);
      break;
    }
    case "nudge-line": {
      const [agent] = rest;
      if (!agent) usage();
      process.stdout.write(`${await nudgeLine(sandbox, agent).catch(() => "")}\n`);
      break;
    }
    default:
      usage();
  }
}
