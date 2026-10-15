#!/usr/bin/env node
/**
 * Run summary: one Markdown page built from a sandbox's own files. No Herdr,
 * no model, no keys — it reads what the harness wrote and says what the run
 * was, how it ended, what it cost, what the agents did, what they recorded,
 * what they left in work/, and what the chain of custody looks like.
 *
 *   node --experimental-strip-types scripts/summary.ts <sandbox>
 *   swarm.sh summary <id>            (same thing, by run id)
 *
 * The registry is `${SWARM_RUNS_DIR:-dirname(sandbox)}/registry.json`; the
 * run whose recorded sandbox resolves to this one supplies the id, label,
 * state, model, caps, case id, examiner and kickoff flags. A sandbox with no
 * registry entry still gets a summary from its files.
 */
import { readdir, readFile, stat } from "node:fs/promises";
import { join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import {
  SENTINEL_REL,
  hostTime,
  agentDeadPath,
  agentDonePath,
  isSharedScratch,
  leadingCommand,
  readNames,
  supersededBy,
  type AgentBudget,
  type LedgerEntry,
  type SwarmEvent,
  type TeamRecord,
} from "../extensions/protocol.ts";
import * as P from "../extensions/protocol.ts";
import { loadRunContext, readJsonFile } from "./run-record.ts";
import { manifestMeta, verdictAnchorLine, verdictAnchorState } from "./custody.ts";
import { bodyReview, gatewayRecordOf, heldRows, readReviewState, reviewLine, sourceCheckedLine, vmSpendNote, type GatewayTotals } from "./report.ts";
import { reportBodyFacts, type BodyFacts } from "./report-body.ts";
import { bodyRelease } from "./release-record.ts";
import { coverageLine, coverageOf } from "./coverage.ts";
import { readRegularText } from "./regular-file.ts";
import { leadsSnapshot, rankedLeads } from "../extensions/leads.ts";
import { questionViews, viewContext } from "../extensions/questions.ts";

type Marker = { id: string; marker: "done" | "dead" | "none"; reason: string; at: string };

type Toolbox = {
  preset?: string;
  present?: Array<{ name: string; version?: string }>;
  missing?: Array<{ name: string; install?: string }>;
};

export { leadingCommand };

function parseFrontMatter(text: string): Record<string, string> {
  const attrs: Record<string, string> = {};
  const match = /^---\r?\n([\s\S]*?)\r?\n---/.exec(text);
  if (!match) return attrs;
  for (const line of match[1].split(/\r?\n/)) {
    const colon = line.indexOf(":");
    if (colon <= 0) continue;
    attrs[line.slice(0, colon).trim()] = line.slice(colon + 1).trim();
  }
  return attrs;
}

function usd(n: number): string {
  return `$${(Number(n) || 0).toFixed(2)}`;
}

function bytesHuman(n: number): string {
  const b = Number(n) || 0;
  if (b >= 1024 ** 3) return `${(b / 1024 ** 3).toFixed(1)} GB`;
  if (b >= 1024 ** 2) return `${(b / 1024 ** 2).toFixed(1)} MB`;
  if (b >= 1024) return `${(b / 1024).toFixed(1)} KB`;
  return `${b} B`;
}

function durationHuman(ms: number): string {
  if (!Number.isFinite(ms) || ms < 0) return "unknown";
  const s = Math.round(ms / 1000);
  const h = Math.floor(s / 3600);
  const m = Math.floor((s % 3600) / 60);
  const rest = s % 60;
  if (h) return `${h}h ${m}m`;
  if (m) return `${m}m ${rest}s`;
  return `${rest}s`;
}

/** The answers in one line, in the words the report's cover and §1 use. */
function answersLine(f: BodyFacts): string {
  const release = f.draft ? "a draft: no release v1" : "released";
  if (f.era === "predates") return `none in the ledger: the run predates structured answers (ledger version 4), so its answers are its working report's prose; ${release}`;
  if (f.era === "empty") return `none: nothing was recorded in the ledger; ${release}`;
  if (f.era === "no answers") return `none recorded${f.questions ? ` for ${f.questions} question${f.questions === 1 ? "" : "s"}` : ""}; ${release}`;
  const signoff = f.signoff === "current" ? "signed off over this run" : f.signoff === "not current" ? "signed off, NOT over this run as it stands" : f.signoff === "unreadable" ? "the examiner's review could not be read" : "not signed off";
  return `${f.answered} of ${f.questions} question${f.questions === 1 ? "" : "s"} answered, ${f.adopted} adopted by the examiner; ${signoff}; ${release}`;
}

function cell(text: unknown): string {
  return String(text ?? "")
    .replace(/\|/g, "\\|")
    .replace(/\r?\n/g, " ")
    .trim();
}

function pct(part: number, whole: number): string {
  if (!whole) return "—";
  return `${Math.round((part / whole) * 100)}%`;
}

async function readMarkers(sandbox: string, team: TeamRecord): Promise<Marker[]> {
  const out: Marker[] = [];
  for (const agent of team.agents) {
    const done = await readFile(agentDonePath(sandbox, agent.id), "utf8").catch(() => null);
    const dead = done === null ? await readFile(agentDeadPath(sandbox, agent.id), "utf8").catch(() => null) : null;
    const text = done ?? dead;
    if (text === null) {
      out.push({ id: agent.id, marker: "none", reason: "", at: "" });
      continue;
    }
    const attrs = parseFrontMatter(text);
    out.push({ id: agent.id, marker: done !== null ? "done" : "dead", reason: attrs.reason ?? "", at: attrs.at ?? "" });
  }
  return out;
}

type WorkEntry = { path: string; bytes: number };

async function walkWork(dir: string, rel: string, out: WorkEntry[], limit: number): Promise<void> {
  if (out.length >= limit) return;
  const entries = (await readdir(dir, { withFileTypes: true }).catch(() => [])).sort((a, b) => (a.name < b.name ? -1 : a.name > b.name ? 1 : 0));
  for (const entry of entries) {
    if (out.length >= limit) return;
    const abs = join(dir, entry.name);
    const key = rel ? `${rel}/${entry.name}` : entry.name;
    if (entry.isDirectory()) {
      await walkWork(abs, key, out, limit);
    } else if (entry.isFile()) {
      const info = await stat(abs).catch(() => null);
      out.push({ path: key, bytes: info?.size ?? 0 });
    }
  }
}

function count<T>(items: T[], key: (item: T) => string | null | undefined): Map<string, number> {
  const out = new Map<string, number>();
  for (const item of items) {
    const k = key(item);
    if (!k) continue;
    out.set(k, (out.get(k) ?? 0) + 1);
  }
  return out;
}

function top(map: Map<string, number>, n: number): Array<[string, number]> {
  return [...map.entries()].sort((a, b) => b[1] - a[1] || a[0].localeCompare(b[0])).slice(0, n);
}

function resultOf(event: SwarmEvent): Record<string, unknown> {
  return event.result && typeof event.result === "object" ? (event.result as Record<string, unknown>) : {};
}

export async function summarize(sandboxArg: string, options: { runsDir?: string } = {}): Promise<string> {
  const { sandbox, runsDir, run, team, budgetRaw, budget, events, trace_unreadable, sentinel, allDead, ledger, inputs } = await loadRunContext(sandboxArg, {
    runsDir: options.runsDir,
    parseSentinel: parseFrontMatter,
  });
  const capPerAgent = Number(budgetRaw?.cap_per_agent_usd ?? run?.cap_per_agent_usd) || 0;
  const capPerModel = Object.entries(budget?.cap_per_model_usd ?? run?.cap_per_model_usd ?? {})
    .filter(([, cap]) => Number(cap) > 0)
    .sort((x, y) => x[0].localeCompare(y[0]));
  const markers = await readMarkers(sandbox, team);
  const toolbox = await readJsonFile<Toolbox>(join(sandbox, "toolbox.json"));
  const catalogReadme = await readFile(join(sandbox, "catalog", "README.md"), "utf8").catch(() => "");
  const catalogSummary = /^Summary:\s*(.+)$/m.exec(catalogReadme)?.[1]?.trim() ?? "";

  const id = run?.id ?? team.swarm_id ?? "";
  const label = run?.label ?? "";
  // What the trace shows the swarm naming, and the ledger's grounding in it.
  const coverage = await coverageOf(sandbox, { events, ledger, traceUnreadable: trace_unreadable });
  const startedAt = budget?.started_at ?? events[0]?.ts ?? "";
  const endedAt = sentinel?.at ?? (events.length ? hostTime(events.at(-1)!) : "");
  const durationMs = startedAt && endedAt ? Date.parse(endedAt) - Date.parse(startedAt) : Number.NaN;
  const lines: string[] = [];

  // --- header -------------------------------------------------------------
  lines.push(`# Run summary: ${id || "(no id)"}${label ? ` — ${label}` : ""}`, "");
  const outcome = await P.runOutcome(sandbox).catch(() => null);
  lines.push(`- State: ${run?.state ?? "unknown (no registry entry)"} · sentinel ${sentinel ? "present" : "absent"}${outcome?.outcome ? ` · outcome ${outcome.outcome}` : sentinel?.outcome ? ` · outcome ${sentinel.outcome}` : ""}`);
  // Every pause, whatever paused it: a cap, the provider's limit, the operator.
  const pauses = budget
    ? `${budget.pauses?.length ? `; paused ${budget.pauses.length} time(s) and went on (${budget.pauses.map((x) => `${x.reason} at ${x.at}, lifted by ${x.resumed_by ?? "?"} at ${x.resumed_at ?? "?"}`).join("; ")})` : ""}${budget.paused ? (outcome?.outcome === "paused" ? `; PAUSED since ${budget.paused.at} (${budget.paused.reason}${budget.paused.until ? `, until ${budget.paused.until}` : ""}): ${P.pauseWayOn(budget.paused)}` : `; it ended while paused since ${budget.paused.at} (${budget.paused.reason})`) : ""}`
    : "";
  if (budget?.until_solved) lines.push(`- Mode: until solved (--stop operator): no wall clock, every cap advisory (spend recorded, nothing stopped for it), no abandon, a regroup after ${budget.stall_minutes ?? 15} minutes without progress${pauses}`);
  else if (budget) lines.push(`- Stop policy: ${P.stopPolicyOf(budget)}${P.stopPolicyOf(budget) === "cap-pause" ? " (a cap pauses the run for the operator)" : " (a cap stops the run)"}${pauses}`);
  if (budget?.resumes?.length) lines.push(`- Resumed: ${budget.resumes.map((r) => `${r.at} by ${r.by} (after it was ${r.from})`).join("; ")}`);
  lines.push(`- Started: ${startedAt || "unknown"} · Duration: ${durationHuman(durationMs)}${endedAt ? ` (to ${sentinel ? "the sentinel" : "the last trace event"} at ${endedAt})` : ""}`);
  // What the kickoff was told about who ran the run: never the examiner who adopts a report (swarm.sh releases says who did).
  if (run?.case_id || run?.examiner) lines.push(`- Case: ${run?.case_id || "—"} · Run by: ${run?.examiner ? `${run.examiner} (as the kickoff recorded it; not an enrolled examiner)` : "—"}`);
  // How the agents were held, and what the host could say once they were gone.
  const iso = (run as { isolation?: { mode?: string; image?: string; image_digest?: string } } | null)?.isolation;
  const gateway = gatewayRecordOf(run as Record<string, unknown> | null);
  const gatewayTotalsRead = gateway ? await readRegularText(join(sandbox, "traces", "model-gateway.json"), 64 * 1024 * 1024) : null;
  let gatewayTotals: GatewayTotals | null = null;
  try {
    gatewayTotals = gatewayTotalsRead && "text" in gatewayTotalsRead ? (JSON.parse(gatewayTotalsRead.text) as GatewayTotals) : null;
  } catch {
    gatewayTotals = null;
  }
  lines.push(`- Isolation: ${iso?.mode === "microvm" ? `one microVM per agent${iso.image ? ` (${iso.image}${iso.image_digest ? ` ${iso.image_digest}` : ""})` : ""}; spend ${gateway ? vmSpendNote(run as Record<string, unknown> | null, gatewayTotals).replace(/^ \(|\)$/g, "") : "is what each VM reported"}` : "host, unisolated (every agent a process on this machine)"}`);
  if (gateway) {
    lines.push(`- Model gateway: on for ${gateway.providers.join(", ") || "no provider"}; ${gatewayTotals ? `$${(Number(gatewayTotals.spent_usd) || 0).toFixed(2)} metered on the host` : "its totals were not found (traces/model-gateway.json)"}${gateway.declined.length ? `; ${gateway.declined.map((d) => d.provider).join(", ")} as reported by the seats` : ""}`);
  }
  // A removed VM whose finish could not clear msb's database of it: its
  // secret values may still be there, on the host.
  if (iso?.mode === "microvm") {
    const unscrubbed: string[] = [];
    for (const name of (await readdir(join(sandbox, "vm")).catch(() => [])).filter((n) => n.endsWith(".json")).sort()) {
      const rec = await readRegularText(join(sandbox, "vm", name), 16 * 1024 * 1024);
      if (!("text" in rec)) continue;
      try {
        const v = JSON.parse(rec.text) as { agent?: unknown; msb_db?: unknown };
        if (typeof v.msb_db === "string" && v.msb_db !== "scrubbed" && v.msb_db !== "no database") unscrubbed.push(`${String(v.agent ?? name.replace(/\.json$/, ""))} (${v.msb_db})`);
      } catch {
        // a torn record is custody's to name
      }
    }
    if (unscrubbed.length) lines.push(`- msb's database: NOT cleared after removing ${unscrubbed.join(", ")}; a secret's value may remain in msb's database on the host`);
  }
  // custody.json is read as a regular file, never through a link a host
  // run's shell planted, and checked against the verdict anchored outside
  // the run: a verdict edited after the stop is said to be one.
  const custodyRead = await readRegularText(join(sandbox, "custody.json"), 256 * 1024 * 1024);
  let custodySummary: string | null = null;
  try {
    custodySummary = "text" in custodyRead ? ((JSON.parse(custodyRead.text) as { summary?: string }).summary ?? null) : null;
  } catch {
    custodySummary = null;
  }
  const custodyAnchor = custodySummary ? verdictAnchorLine(await verdictAnchorState(sandbox)) : "";
  if (custodySummary) lines.push(`- Custody: ${custodySummary}${custodyAnchor ? ` (custody.json ${custodyAnchor})` : ""}`);
  else if ("why" in custodyRead && custodyRead.why !== "missing") lines.push(`- Custody: custody.json is ${custodyRead.why}; not read`);
  else lines.push("- Custody: not taken (swarm.sh stop takes it)");
  // Whether an examiner has reviewed the agents' conclusions, from the
  // review file beside the registry.
  const review = await readReviewState(runsDir, id, sandbox, ledger);
  lines.push(`- Examiner review: ${reviewLine(review, ledger)}`);
  // The answers as the report's cover counts them, from the same facts
  // (scripts/report-body.ts) with the same review: the two never disagree.
  // The release state, and the adopting examiner, read as the report reads them (release-record.ts bodyRelease): never the kickoff's examiner string.
  const rel = bodyRelease(sandbox);
  const facts = await reportBodyFacts(sandbox, { review: bodyReview(review, rel.examiner), release: rel.release, ...(run?.model ? { defaultModel: run.model } : {}) });
  lines.push(`- Answers: ${answersLine(facts)}`);
  for (const [k, v] of heldRows(run as Record<string, unknown> | null)) lines.push(`- ${k}: ${v}`);
  const flags: string[] = [];
  if (run?.model) flags.push(`model ${run.model}`);
  if (run?.catalog) flags.push("catalog");
  if (run?.toolbox && run.toolbox !== "off") flags.push(`toolbox ${run.toolbox}`);
  if (run?.quarantine) flags.push("quarantine");
  if (run?.allow_hosts) flags.push(`allow-host ${run.allow_hosts}`);
  if (flags.length) lines.push(`- Kickoff: ${flags.join(" · ")}`);
  lines.push(`- Sandbox: \`${sandbox}\``, "");

  // --- outcome ------------------------------------------------------------
  lines.push("## Outcome", "");
  if (sentinel) {
    lines.push(`Sentinel \`${SENTINEL_REL}\` by **${sentinel.by ?? "?"}** at ${sentinel.at ?? "?"}: ${sentinel.reason ?? ""}${sentinel.output ? ` (output: \`${sentinel.output}\`)` : ""}${sentinel.outcome ? `. Outcome: **${sentinel.outcome}**` : ""}`, "");
  } else if (outcome?.outcome === "stopped") {
    lines.push(`No sentinel: the operator stopped the run (\`done/STOPPED\`, ${outcome.by ?? "?"} at ${outcome.at ?? "?"}). Outcome: **stopped**, never completed.`, "");
  } else if (outcome?.outcome === "paused") {
    const pause = budget?.paused;
    lines.push(`No sentinel: the run is **paused** since ${outcome.at ?? "?"} (${outcome.why ?? ""}): no model call goes out until ${pause ? P.pauseWayOn(pause) : "the operator extends it (swarm.sh extend) or stops it (swarm.sh stop)"}.`, "");
  } else if (allDead) {
    lines.push(`No sentinel: every agent died (\`done/ALL_AGENTS_DEAD\`, ${allDead.reason ?? "all_agents_dead"}, at ${allDead.at ?? "?"}). The swarm stopped without meeting its definition of done.`, "");
  } else {
    lines.push("No sentinel: the swarm has not finished (or was stopped from outside without one).", "");
  }
  if (markers.length) {
    lines.push("| Agent | Marker | At | Reason |", "| --- | --- | --- | --- |");
    for (const m of markers) lines.push(`| ${m.id} | ${m.marker === "none" ? "—" : m.marker} | ${m.at} | ${cell(m.reason)} |`);
    const unmarked = markers.filter((m) => m.marker === "none").map((m) => m.id);
    const dead = markers.filter((m) => m.marker === "dead").map((m) => m.id);
    lines.push("");
    lines.push(`${markers.length - unmarked.length} of ${markers.length} agents marked${dead.length ? ` (${dead.length} reaped: ${dead.join(", ")})` : ""}${unmarked.length ? `; without a marker: ${unmarked.join(", ")}` : ""}.`, "");
  } else {
    lines.push("No team.json: no agents to report on.", "");
  }

  // --- team ---------------------------------------------------------------
  lines.push("## Team", "");
  const agentBudget = (agentId: string) => budget?.agents[agentId];
  // What each agent decided to call itself. Nothing here was assigned, so an
  // empty cell means that agent never said, not that it had no work.
  const chosen = new Map<string, string>();
  for (const n of await readNames(sandbox).catch(() => [])) {
    if (n.doing) chosen.set(n.id, `${n.name} — ${n.doing}`);
    else chosen.set(n.id, n.name);
  }
  // A team of local models is not charged. Its page speaks in tokens, and
  // never says "$0.00 spent", which reads as "nothing happened".
  const unmetered = budget?.metered === false;
  const spentCell = (n: number) => (unmetered ? "free" : usd(n));
  if (team.agents.length) {
    // The context column reads against the self-compaction ceiling when the
    // run had one, else against Pi's declared window; the compaction column
    // is the hand-offs, with every compaction Pi recorded in brackets when
    // the two differ (its own overflow recovery counts as one, a hand-off does not).
    const contextCell = (b: AgentBudget | undefined) => {
      const ctx = b?.context_tokens ?? 0;
      const against = b?.context_ceiling || b?.context_window || 0;
      if (!ctx || !against) return "";
      return `${ctx.toLocaleString("en-US")} (${Math.round((ctx / against) * 100)}%${b?.context_ceiling ? " of ceiling" : ""})`;
    };
    const compactCell = (b: AgentBudget | undefined) => {
      const handoffs = b?.handoffs ?? 0;
      const all = b?.compactions ?? 0;
      if (!handoffs && !all) return "";
      const cost = b?.compaction_usd ? ` ${usd(b.compaction_usd)}` : "";
      return `${handoffs}${all !== handoffs ? ` (${all})` : ""}${cost}`;
    };
    lines.push("| Agent | Calls itself | Role | Model | Spent | Calls | Tokens | Context | Compactions |", "| --- | --- | --- | --- | --- | --- | --- | --- | --- |");
    for (const a of team.agents) {
      const b = agentBudget(a.id);
      lines.push(`| ${a.id} | ${cell(chosen.get(a.id) ?? "")} | ${cell(a.role)} | ${cell(a.model ?? "")} | ${spentCell(b?.spent_usd ?? 0)} | ${b?.calls ?? 0} | ${(b?.tokens ?? 0).toLocaleString("en-US")} | ${contextCell(b)} | ${compactCell(b)} |`);
    }
    lines.push("");
  }
  const spentTotal = budget?.spent_usd ?? 0;
  const tokensTotal = budget?.tokens ?? 0;
  const byModel = new Map<string, { spent: number; tokens: number; calls: number; agents: string[] }>();
  for (const a of team.agents) {
    const model = a.model || run?.model || "unknown";
    const slot = byModel.get(model) ?? { spent: 0, tokens: 0, calls: 0, agents: [] };
    const b = agentBudget(a.id);
    slot.spent += b?.spent_usd ?? 0;
    slot.tokens += b?.tokens ?? 0;
    slot.calls += b?.calls ?? 0;
    slot.agents.push(a.id);
    byModel.set(model, slot);
  }
  if (byModel.size) {
    lines.push("By model:", "", "| Model | Spent | Share | Calls | Agents |", "| --- | --- | --- | --- | --- |");
    const weight = (s: { spent: number; tokens: number }) => (unmetered ? s.tokens : s.spent);
    for (const [model, slot] of [...byModel.entries()].sort((x, y) => weight(y[1]) - weight(x[1]))) {
      const share = unmetered ? pct(slot.tokens, tokensTotal) : pct(slot.spent, spentTotal);
      lines.push(`| ${cell(model)} | ${spentCell(slot.spent)} | ${share} | ${slot.calls} | ${slot.agents.length} (${slot.agents.join(", ")}) |`);
    }
    lines.push("");
  }
  const tail = `${budget?.calls ?? 0} provider calls, ${tokensTotal.toLocaleString("en-US")} tokens${budget?.cap_steer_sent ? "; the cap steer was sent" : ""}${budget?.stop_reason ? `; stop reason ${budget.stop_reason}` : ""}.`;
  const capTokens = Number(budget?.cap_tokens) || 0;
  lines.push(
    unmetered
      ? `No metered cost: every model on this team is local. ${tokensTotal.toLocaleString("en-US")} tokens${capTokens ? ` of a ${capTokens.toLocaleString("en-US")}-token cap` : " (no token cap recorded)"}; ${tail}`
      : `Spent ${usd(spentTotal)} of a ${usd(budget?.cap_usd ?? run?.cap_usd ?? 0)} cap${capPerAgent ? `, ${usd(capPerAgent)} per agent` : ""}${capTokens ? `, ${capTokens.toLocaleString("en-US")} tokens` : ""}; ${tail}`,
    "",
  );
  // A model's cap is measured against what its agents spent together, which
  // is the same sum the By-model table shows.
  if (capPerModel.length && !unmetered) {
    const against = capPerModel.map(([model, cap]) => {
      const spent = byModel.get(model)?.spent ?? 0;
      return `${model} spent ${usd(spent)} of its ${usd(Number(cap))} cap${spent >= Number(cap) ? " and is over it" : ""}`;
    });
    lines.push(`Per-model caps: ${against.join("; ")}.`, "");
  }

  // --- activity -----------------------------------------------------------
  lines.push("## Activity", "");
  // A trace that is there and could not be read is not a run with no events.
  if (trace_unreadable) lines.push(`The trace is there and could not be read (${trace_unreadable}): the counts below are not the run's. The host's custody check says what it found.`, "");
  lines.push(`${events.length} trace events${events.length ? ` from ${hostTime(events[0])} to ${hostTime(events.at(-1)!)} (the host's clock where the collector stamped it)` : ""}.`, "");
  // Operator actions run from a shell outside the run reach the collector
  // with no pane's token: the operator's, not lines nobody can account for.
  const operatorActions = events.filter((e) => e.tool === "operator_action");
  if (operatorActions.length) {
    lines.push(
      `${operatorActions.length} operator action${operatorActions.length === 1 ? "" : "s"} on the trace (${[...new Set(operatorActions.map((e) => String((e.args as { command?: unknown } | undefined)?.command ?? "?")))].join(", ")}); each is also on runs/operator-audit.jsonl, with the OS user and host.`,
      "",
    );
  }
  if (events.length) {
    const byAgent = new Map<string, SwarmEvent[]>();
    for (const e of events) {
      const list = byAgent.get(e.agent) ?? [];
      list.push(e);
      byAgent.set(e.agent, list);
    }
    lines.push("| Agent | Events | Top tools |", "| --- | --- | --- |");
    for (const [agentId, list] of [...byAgent.entries()].sort((x, y) => y[1].length - x[1].length || x[0].localeCompare(y[0]))) {
      const tools = top(count(list, (e) => e.tool), 5)
        .map(([tool, n]) => `${tool} ${n}`)
        .join(", ");
      lines.push(`| ${agentId} | ${list.length} | ${cell(tools)} |`);
    }
    lines.push("");
    const isTool = (name: string) => (e: SwarmEvent) => e.tool === name;
    // One pass: every tool's event count, plus the implicit claims.
    const toolCounts = new Map<unknown, number>();
    let implicitClaims = 0;
    for (const e of events) {
      toolCounts.set(e.tool, (toolCounts.get(e.tool) ?? 0) + 1);
      if (e.tool === "claim_file" && (e.args?.implicit === true || resultOf(e).implicit === true)) implicitClaims++;
    }
    const toolCount = (name: string) => toolCounts.get(name) ?? 0;
    const counters: Array<[string, number]> = [
      ["claim violations", toolCount("claim_violation")],
      ["implicit claims (shell writes turned into claims)", implicitClaims],
      ["inputs violations", toolCount("inputs_violation")],
      ["inputs checks", toolCount("inputs_check")],
      ["forge hints", toolCount("forge_hint")],
      ["sentinel nudges", toolCount("sentinel_nudge")],
      ["idle nudges", toolCount("idle_nudge")],
      ["per-agent cap steers", toolCount("agent_cap_steer")],
      ["per-agent cap stops", toolCount("agent_cap_stop")],
      ["posts", toolCount("post")],
      ["bash calls", toolCount("bash")],
    ];
    lines.push("| Signal | Count |", "| --- | --- |");
    for (const [name, n] of counters) lines.push(`| ${name} | ${n} |`);
    lines.push("");
    const forged = events.filter((e) => e.tool === "make_tool" && resultOf(e).ok === true);
    if (forged.length) {
      lines.push("Forged tools (written by the agents during the run; not independently validated):", "");
      for (const e of forged) {
        const name = String(e.args?.name ?? "?");
        const calls = toolCount(name);
        lines.push(`- \`${name}\` by ${e.agent} at ${hostTime(e)} (${String(e.args?.runtime ?? "?")}; called ${calls} time${calls === 1 ? "" : "s"})`);
      }
      lines.push("");
    }
    const commands = count(events.filter(isTool("bash")), (e) => (typeof e.args?.command === "string" ? leadingCommand(e.args.command) : null));
    const topCommands = top(commands, 10);
    if (topCommands.length) {
      lines.push("Bash leading commands (top 10):", "", "| Command | Runs |", "| --- | --- |");
      for (const [command, n] of topCommands) lines.push(`| \`${cell(command)}\` | ${n} |`);
      lines.push("");
    }
  }

  // --- answers ------------------------------------------------------------
  if (facts.questions) {
    lines.push("## Answers", "", `${answersLine(facts)}. The report's §5 has each answer with what it rests on.`, "", "| Question | Status | Answer | Adopted |", "| --- | --- | --- | --- |");
    for (const q of facts.questionStatus) {
      lines.push(`| ${cell(q.label)} | ${cell(`${q.status}${q.confidence ? `, ${q.confidence} confidence` : ""}`)} | ${q.answer !== null ? `E-${q.answer}: ${cell(q.value)}` : "—"} | ${q.answer === null ? "—" : q.adopted ? "yes, by the examiner" : "no"} |`);
    }
    lines.push("");
    if (facts.summary) lines.push(`Summary (E-${facts.summary.seq}${facts.summary.stands ? "" : ", no longer standing on its support"}): ${cell(facts.summary.value)}`, "");
  }

  // --- ledger -------------------------------------------------------------
  lines.push("## Ledger", "");
  if (!ledger.length) {
    lines.push("No ledger: nothing was recorded with `record`.", "");
  } else {
    const kinds = count(ledger, (e) => e.kind);
    const corrected = supersededBy(ledger);
    lines.push(
      `${ledger.length} entries: ${["event", "ioc", "finding"].map((k) => `${kinds.get(k) ?? 0} ${k === "ioc" ? "indicators" : `${k}s`}`).join(", ")}${kinds.get("absence") ? `, ${kinds.get("absence")} searched and not found (valid only for the scope each states)` : ""} (\`ledger/ledger.md\`).${corrected.size ? ` ${corrected.size} corrected by a later entry, kept as recorded: ${[...corrected].map(([old, by]) => `E-${old} by E-${by}`).join(", ")}.` : ""}`,
      "",
    );
    const ungrounded = Object.entries(coverage.grounding).filter(([, g]) => g === "not in the trace").map(([seq]) => `E-${seq}`);
    if (!coverage.unavailable || Object.keys(coverage.grounding).length) {
      lines.push(`Grounding: ${ungrounded.length ? `${ungrounded.length} entr${ungrounded.length === 1 ? "y's" : "ies'"} source named by no call before the entry was recorded, nor by a job the entry cites that was given an evidence input (${ungrounded.join(", ")})` : "every entry that names a path had it named by an earlier call or by a job it cites that was given an evidence input"}.`, "");
    }
    const timeline: LedgerEntry[] = ledger
      .filter((e) => e.kind === "event")
      .sort((a, b) => (a.ts ?? "").localeCompare(b.ts ?? "") || a.seq - b.seq)
      .slice(-10);
    if (timeline.length) {
      lines.push(`Last ${timeline.length} events in time order:`, "", "| Time (UTC) | Event | Source | By |", "| --- | --- | --- | --- |");
      for (const e of timeline) lines.push(`| ${e.ts ?? ""} | ${cell(e.value)} | ${cell(e.source ?? "")} | ${(e.authors ?? [e.by]).join(", ")} |`);
      lines.push("");
    }
  }

  // --- leads --------------------------------------------------------------
  // The lead register: the work the swarm found to follow, who held it and
  // how each piece ended. Every lead is listed; none is cut.
  const leadsSnap = await leadsSnapshot(sandbox).catch(() => null);
  if (leadsSnap && leadsSnap.state.events.length) {
    const ranked = rankedLeads(leadsSnap);
    const by = (st: string) => ranked.filter((x) => x.status === st).length;
    lines.push("## Leads", "");
    lines.push(`${ranked.length} lead${ranked.length === 1 ? "" : "s"} (\`leads/leads.md\`): ${by("open")} open, ${by("active")} active, ${by("blocked")} blocked, ${by("closed")} closed; chain ${leadsSnap.state.chain.ok ? `intact, ${leadsSnap.state.events.length} events` : `BROKEN at line ${leadsSnap.state.chain.broken_at} (${leadsSnap.state.chain.reason})`}.`, "");
    lines.push("| Lead | Title | Status | Holder | Disposition | Rests on |", "| --- | --- | --- | --- | --- | --- |");
    for (const x of ranked) lines.push(`| ${x.id} | ${cell(x.title)} | ${x.status}${x.material ? "" : " (not material)"} | ${x.holder ?? ""} | ${x.disposition ?? ""} | ${cell(x.ref ?? "")} |`);
    lines.push("");
  }

  // --- questions ----------------------------------------------------------
  // The question register: what the run was asked, by whom, and how each
  // question stands. Listed when the chain holds more than the goal's seed.
  const qctx = await viewContext(sandbox).catch(() => null);
  if (qctx && qctx.questions.state.events.some((e) => e.ev !== "seed" && e.ev !== "objective" && !(e.ev === "open" && e.origin?.kind === "goal"))) {
    const views = questionViews(qctx);
    lines.push("## Questions", "");
    lines.push(`${views.length} question${views.length === 1 ? "" : "s"} (\`questions/questions.md\`); chain ${qctx.questions.state.chain.ok ? `intact, ${qctx.questions.state.events.length} events` : `BROKEN at line ${qctx.questions.state.chain.broken_at} (${qctx.questions.state.chain.reason})`}.`, "");
    lines.push("| Question | Asked by | Scope | Revision | Answer | Leads |", "| --- | --- | --- | --- | --- | --- |");
    for (const v of views) lines.push(`| ${v.id}: ${cell(v.text)} | ${cell(v.author)} | ${v.withdrawn ? "withdrawn" : v.scope}${v.after_done ? " (after done)" : ""} | ${v.rev} | ${v.answer ? `E-${v.answer.seq}${v.answer.stale ? " (stale)" : ""}` : ""} | ${v.leads.map((l) => l.id).join(", ")} |`);
    lines.push("");
  }

  // --- work ---------------------------------------------------------------
  lines.push("## Work", "");
  const agentIds = new Set(team.agents.map((a) => a.id));
  const workDir = join(sandbox, "work");
  const topEntries = (await readdir(workDir, { withFileTypes: true }).catch(() => [])).sort((a, b) => (a.name < b.name ? -1 : a.name > b.name ? 1 : 0));
  if (!topEntries.length) {
    lines.push("work/ is empty.", "");
  } else {
    const files: WorkEntry[] = [];
    const scratch: Array<{ id: string; files: number; bytes: number }> = [];
    const shared: Array<{ name: string; files: number; bytes: number }> = [];
    const LIMIT = 200;
    for (const entry of topEntries) {
      const abs = join(workDir, entry.name);
      if (entry.isDirectory() && agentIds.has(entry.name)) {
        const own: WorkEntry[] = [];
        await walkWork(abs, entry.name, own, 100_000);
        scratch.push({ id: entry.name, files: own.length, bytes: own.reduce((a, f) => a + f.bytes, 0) });
      } else if (entry.isDirectory() && isSharedScratch(`work/${entry.name}/`)) {
        // pip's site-packages and Pi's own logs: one line each, not 200 rows
        // of .pyc files ahead of the report (run s57e9's summary).
        const own: WorkEntry[] = [];
        await walkWork(abs, entry.name, own, 100_000);
        shared.push({ name: entry.name, files: own.length, bytes: own.reduce((a, f) => a + f.bytes, 0) });
      } else if (entry.isDirectory()) {
        await walkWork(abs, entry.name, files, LIMIT + 1);
      } else if (entry.isFile()) {
        const info = await stat(abs).catch(() => null);
        files.push({ path: entry.name, bytes: info?.size ?? 0 });
      }
    }
    const isTopMd = (f: WorkEntry) => !f.path.includes("/") && f.path.endsWith(".md");
    const ordered = [...files.filter(isTopMd), ...files.filter((f) => !isTopMd(f))];
    lines.push("| File | Size |", "| --- | --- |");
    for (const f of ordered.slice(0, LIMIT)) lines.push(`| \`work/${cell(f.path)}\` | ${bytesHuman(f.bytes)} |`);
    if (ordered.length > LIMIT) lines.push(`| … and ${ordered.length - LIMIT} more | |`);
    for (const s of scratch) lines.push(`| \`work/${s.id}/\` (scratch of ${s.id}) | ${s.files} files, ${bytesHuman(s.bytes)} |`);
    for (const s of shared) lines.push(`| \`work/${s.name}/\` (${s.name === ".toolchain" ? "the install area" : "the harness's scratch"}, not work product) | ${s.files} files, ${bytesHuman(s.bytes)} |`);
    lines.push("");
  }

  // --- custody ------------------------------------------------------------
  lines.push("## Custody", "");
  // The host's own verdict first: what custody.json says was re-hashed,
  // sealed and checked after the run, which no agent could write.
  const hostCustody = await readJsonFile<{ summary?: string; at?: string; incomplete?: string | null; trace?: { spilled?: Array<{ path: string; lines: number; bad?: number }> } }>(join(sandbox, "custody.json"));
  if (hostCustody?.summary && custodySummary) {
    lines.push(`Host custody (taken ${hostCustody.at ?? "at an unknown time"}, \`custody.json\`${custodyAnchor ? `, which ${custodyAnchor}` : ""}): ${hostCustody.summary}`, "");
  } else {
    lines.push("No host custody was taken yet: what follows is what the agents said about the evidence, and `swarm.sh stop` takes the host's own verdict.", "");
  }
  if (!inputs) {
    lines.push("No read-only inputs were given to this swarm.", "");
  } else {
    // Several sets: each named at inputs/<name>/ with its source.
    const from = inputs.sets?.length
      ? `${inputs.sets.length} sets (${inputs.sets.map((set) => `\`${set.path}/\` from \`${set.source}\``).join(", ")})`
      : `\`${inputs.source}\``;
    const arrived = (inputs as { held?: string }).held === "bind"
      ? `used in place from ${from} (no copy; ${inputs.guard === "microvm" ? "mounted read-only into every VM" : "kernel guard " + inputs.guard})`
      : (inputs as { held?: string }).held === "image"
        ? `attached as a read-only image from ${from}`
        : `copied from ${from} ${inputs.copied_at || "at an unknown time"}`;
    lines.push(
      `Inputs ${arrived}: ${inputs.files.length} file${inputs.files.length === 1 ? "" : "s"}, ${bytesHuman(inputs.bytes)}; enforcement asked ${inputs.enforce}, kickoff guard ${inputs.guard}.`,
      "",
    );
    // sha1 and md5 beside sha256 when the kickoff took them: the digests an
    // imager's log carries.
    const dig = (f: unknown) => f as { sha1?: string; md5?: string };
    const withSha1 = inputs.files.some((f) => typeof dig(f).sha1 === "string");
    const withMd5 = inputs.files.some((f) => typeof dig(f).md5 === "string");
    lines.push(
      `| Input | Bytes | SHA-256 |${withSha1 ? " SHA-1 |" : ""}${withMd5 ? " MD5 |" : ""}`,
      `| --- | --- | --- |${withSha1 ? " --- |" : ""}${withMd5 ? " --- |" : ""}`,
    );
    for (const f of inputs.files) {
      lines.push(`| \`${cell(f.path)}\` | ${f.bytes.toLocaleString("en-US")} | \`${f.sha256}\` |${withSha1 ? ` \`${dig(f).sha1 ?? "—"}\` |` : ""}${withMd5 ? ` \`${dig(f).md5 ?? "—"}\` |` : ""}`);
    }
    lines.push("");
    const sourceCheck = sourceCheckedLine((await manifestMeta(sandbox))?.source_checked);
    if (sourceCheck) lines.push(`${sourceCheck.charAt(0).toUpperCase()}${sourceCheck.slice(1)}.`, "");
    const checks = events.filter((e) => e.tool === "inputs_check");
    if (checks.length) {
      lines.push("| Inputs check | By | Result |", "| --- | --- | --- |");
      for (const e of checks) {
        const r = resultOf(e);
        const modified = Array.isArray(r.modified) ? r.modified.length : 0;
        const missing = Array.isArray(r.missing) ? r.missing.length : 0;
        const added = Array.isArray(r.added) ? r.added.length : 0;
        const metadata = Array.isArray(r.metadata) ? r.metadata.length : 0;
        // "CHANGED: 0 modified, 0 missing, 0 added" is what this printed for a
        // returning write bit, which is the confusion the content/metadata
        // split exists to remove. An older event has no `content_ok`, and then
        // `ok` is the only answer there is.
        const contentOk = r.content_ok === undefined ? r.ok === true : r.content_ok === true;
        const verdict = r.ok === true ? "intact" : contentOk ? `bytes intact, ${metadata} held differently` : "CHANGED";
        lines.push(`| ${hostTime(e)} | ${e.agent} | ${verdict}: ${String(r.checked ?? 0)} checked, ${modified} modified, ${missing} missing, ${added} added |`);
      }
      lines.push("");
    } else {
      lines.push("No inputs check is on the trace: nothing verified the inputs at the end of the run.", "");
    }
  }
  if (toolbox) {
    const present = (toolbox.present ?? []).map((t) => (t.version ? `${t.name} (${cell(t.version)})` : t.name));
    const missing = (toolbox.missing ?? []).map((t) => t.name);
    lines.push(`Toolbox (${toolbox.preset ?? "?"}): ${present.length} present${present.length ? ` — ${present.join(", ")}` : ""}; ${missing.length} missing${missing.length ? ` — ${missing.join(", ")}` : ""}.`, "");
  }
  if (catalogSummary) lines.push(`Evidence catalog: ${catalogSummary}.`, "");
  if (inputs) lines.push(`Coverage: ${coverageLine(coverage)}`, "");

  return lines.join("\n").replace(/\n{3,}/g, "\n\n").trimEnd() + "\n";
}

const invokedDirectly = (() => {
  try {
    return Boolean(process.argv[1]) && resolve(process.argv[1]) === fileURLToPath(import.meta.url);
  } catch {
    return false;
  }
})();

if (invokedDirectly) {
  const sandbox = process.argv[2];
  if (!sandbox) {
    console.error("usage: summary.ts <sandbox>");
    process.exit(2);
  }
  const info = await stat(sandbox).catch(() => null);
  if (!info?.isDirectory()) {
    console.error(`summary: no such sandbox: ${sandbox}`);
    process.exit(1);
  }
  process.stdout.write(await summarize(sandbox));
}
