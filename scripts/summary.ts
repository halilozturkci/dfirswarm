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
  agentDeadPath,
  agentDonePath,
  isSharedScratch,
  leadingCommand,
  readNames,
  type AgentBudget,
  type LedgerEntry,
  type SwarmEvent,
  type TeamRecord,
} from "../extensions/protocol.ts";
import { loadRunContext, readJsonFile } from "./run-record.ts";

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
  const { sandbox, run, team, budgetRaw, budget, events, sentinel, ledger, inputs } = await loadRunContext(sandboxArg, {
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
  const startedAt = budget?.started_at ?? events[0]?.ts ?? "";
  const endedAt = sentinel?.at ?? events.at(-1)?.ts ?? "";
  const durationMs = startedAt && endedAt ? Date.parse(endedAt) - Date.parse(startedAt) : Number.NaN;
  const lines: string[] = [];

  // --- header -------------------------------------------------------------
  lines.push(`# Run summary: ${id || "(no id)"}${label ? ` — ${label}` : ""}`, "");
  lines.push(`- State: ${run?.state ?? "unknown (no registry entry)"} · sentinel ${sentinel ? "present" : "absent"}`);
  lines.push(`- Started: ${startedAt || "unknown"} · Duration: ${durationHuman(durationMs)}${endedAt ? ` (to ${sentinel ? "the sentinel" : "the last trace event"} at ${endedAt})` : ""}`);
  if (run?.case_id || run?.examiner) lines.push(`- Case: ${run?.case_id || "—"} · Examiner: ${run?.examiner || "—"}`);
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
    lines.push(`Sentinel \`${SENTINEL_REL}\` by **${sentinel.by ?? "?"}** at ${sentinel.at ?? "?"}: ${sentinel.reason ?? ""}${sentinel.output ? ` (output: \`${sentinel.output}\`)` : ""}`, "");
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
  lines.push(`${events.length} trace events${events.length ? ` from ${events[0].ts} to ${events.at(-1)?.ts}` : ""}.`, "");
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
      lines.push("Forged tools:", "");
      for (const e of forged) {
        const name = String(e.args?.name ?? "?");
        const calls = toolCount(name);
        lines.push(`- \`${name}\` by ${e.agent} at ${e.ts} (${String(e.args?.runtime ?? "?")}; called ${calls} time${calls === 1 ? "" : "s"})`);
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

  // --- ledger -------------------------------------------------------------
  lines.push("## Ledger", "");
  if (!ledger.length) {
    lines.push("No ledger: nothing was recorded with `record`.", "");
  } else {
    const kinds = count(ledger, (e) => e.kind);
    lines.push(
      `${ledger.length} entries: ${["event", "ioc", "finding"].map((k) => `${kinds.get(k) ?? 0} ${k === "ioc" ? "indicators" : `${k}s`}`).join(", ")} (\`ledger/ledger.md\`).`,
      "",
    );
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
  if (!inputs) {
    lines.push("No read-only inputs were given to this swarm.", "");
  } else {
    lines.push(
      `Inputs from \`${inputs.source}\`, copied ${inputs.copied_at || "at an unknown time"}: ${inputs.files.length} file${inputs.files.length === 1 ? "" : "s"}, ${bytesHuman(inputs.bytes)}; enforcement asked ${inputs.enforce}, kickoff guard ${inputs.guard}.`,
      "",
      "| Input | Bytes | SHA-256 |",
      "| --- | --- | --- |",
    );
    for (const f of inputs.files) lines.push(`| \`${cell(f.path)}\` | ${f.bytes.toLocaleString("en-US")} | \`${f.sha256}\` |`);
    lines.push("");
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
        lines.push(`| ${e.ts} | ${e.agent} | ${verdict}: ${String(r.checked ?? 0)} checked, ${modified} modified, ${missing} missing, ${added} added |`);
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
