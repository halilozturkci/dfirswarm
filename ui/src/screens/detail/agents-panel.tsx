/**
 * The agents page: the last few trace
 * lines on top, an ORDER bar, then one full-width row per agent with its
 * activity span (first to last call, failures ticked along it), its call /
 * token / cost / failure line, the token split, and the context window
 * against the ceiling its self-compaction lines are fractions of.
 * Opening one shows its threads, its stats, its context over the run with
 * every compaction, and its own trace with the
 * ALL / MESSAGES / TOOLS / THINKING / CONTEXT / FAILURES / SESSION ENDS tabs.
 */
import { useCallback, useMemo, useState } from "react";
import { ArrowLeft, Lock, Users } from "lucide-react";
import { Badge } from "@/components/ui/badge";
import { Input } from "@/components/ui/input";
import { EmptyState, ErrorState, LoadingState } from "@/components/states";
import { AgentMark, markerText } from "@/components/swarm-bits";
import { useAgentColours } from "@/lib/agent-colour";
import { api } from "@/lib/api";
import { clock, compact, money, relTime } from "@/lib/format";
import { compactionHistory, contextSeries, defaultThresholds, isContextEvent, type CompactionMoment, type ContextPoint, type ContextSeries, type ContextThresholds } from "@/lib/context-series";
import { isFailureEvent } from "@/lib/event-taxonomy";
import { isNoise, toolLabel, toolTone, useAgentNames } from "@/lib/hooks";
import { useResource } from "@/lib/live";
import { thinkingText } from "@/lib/thinking";
import type { AgentBudget, AgentRow, SwarmEvent, SwarmView } from "@/lib/types";
import { cn } from "@/lib/utils";
import { TraceList } from "./traces-panel";
import { ThinkingStream } from "./thinking";

type Order = "active" | "messages" | "threads" | "calls" | "cost" | "name";
type Lens = "all" | "messages" | "tools" | "thinking" | "context" | "failures" | "ends";

const LIFECYCLE = new Set(["agent_start", "agent_stop", "harness_stop", "cap_steer", "wall_steer", "claim_violation", "reap", "reaped"]);

/** ◇ worker · △ critic · ○ anything else — a glyph per role. */
function roleGlyph(role: string): string {
  return role === "critic" ? "△" : role === "worker" ? "◇" : "○";
}

/**
 * What this agent decided to call itself, and what it said it was taking on.
 * Nothing here was assigned: an empty answer means it has not said yet.
 */
/**
 * Every time this agent said who it was.
 *
 * A name is not permanent. `name()` can be called again whenever the work
 * changes, and on a real run it is: one agent opened as "Laptop Triage" and
 * four minutes later was "Dependency & Timeline"; another moved from "iPhone
 * identity" to "Laptop identity" when a peer got there first; a third kept
 * its name and rewrote what it was doing an hour in. `names.json` keeps only
 * the last of those, so the console showed a single title for a decision the
 * agent had made three times. The trace has all of them, refusals included —
 * a name already taken is refused with the peer who holds it, and that
 * refusal is part of how the team divided the work.
 */
type NameMoment = { ts: string; name: string; doing: string; ok: boolean; reason: string };

function nameHistory(traces: SwarmEvent[], id: string): NameMoment[] {
  const out: NameMoment[] = [];
  for (const e of traces) {
    if (e.tool !== "name" || e.agent !== id) continue;
    const args = (e.args ?? {}) as { name?: unknown; doing?: unknown };
    const result = (e.result ?? {}) as { ok?: unknown; reason?: unknown };
    const moment: NameMoment = {
      ts: e.ts,
      name: typeof args.name === "string" ? args.name : "",
      doing: typeof args.doing === "string" ? args.doing : "",
      ok: result.ok !== false,
      reason: typeof result.reason === "string" ? result.reason : "",
    };
    // The harness writes the call twice, and the two copies can land on
    // different milliseconds. Same name, same sentence, same answer as the
    // one before it is the same decision however its timestamp reads — but a
    // refusal followed by an accepted call is two, which is why `ok` counts.
    const last = out[out.length - 1];
    if (last && last.name === moment.name && last.doing === moment.doing && last.ok === moment.ok) continue;
    out.push(moment);
  }
  return out;
}

/** What changed at this moment, in the words a reader would use. */
function nameChange(moment: NameMoment, previous: NameMoment | undefined): string {
  if (!moment.ok) return "refused";
  if (!previous) return "named itself";
  if (previous.name !== moment.name) return `renamed · was ${previous.name}`;
  return "same name, new job";
}

function NameHistory({ swarmId, id, version }: { swarmId: string; id: string; version: number }) {
  // Not from `view.traces`: that is the tail of the trace, and an agent names
  // itself in its first minute — on a fifty-minute run the decision has long
  // scrolled out of the window. The trace route answers the whole history for
  // one agent and one tool.
  const loader = useCallback(() => api.traces(swarmId, { agent: id, tool: "name", order: "asc", limit: 200 }), [swarmId, id]);
  const page = useResource(loader, version, [swarmId, id]);
  const moments = nameHistory(page.data?.events ?? [], id);
  if (moments.length < 2) return null;
  let previousAccepted: NameMoment | undefined;
  return (
    <div className="mt-2.5">
      <div className="label-caps mb-1.5 text-ink-3">What it called itself · {moments.length} decisions</div>
      <ol className="m-0 flex list-none flex-col gap-1.5 border-l border-line p-0 pl-3">
        {moments.map((moment, i) => {
          const change = nameChange(moment, previousAccepted);
          if (moment.ok) previousAccepted = moment;
          return (
            <li key={`${moment.ts}-${i}`} className="relative">
              <span
                className={cn(
                  "absolute -left-[15px] top-[6px] size-1.5 rounded-full ring-2 ring-card",
                  moment.ok ? "bg-kelp" : "bg-brick",
                )}
              />
              <div className="flex flex-wrap items-baseline gap-x-2 gap-y-0.5">
                <span className="font-mono text-[11px] tabular text-ink-3">{clock(moment.ts)}</span>
                <span className={cn("text-[12.5px] font-semibold", moment.ok ? "text-ink" : "text-brick-ink line-through")}>
                  {moment.name || "—"}
                </span>
                <span className="text-[11px] text-ink-3">{change}</span>
              </div>
              {moment.ok && moment.doing ? (
                <p className="m-0 text-[11.5px] leading-[1.45] text-ink-2">{moment.doing}</p>
              ) : null}
              {!moment.ok && moment.reason ? (
                <p className="m-0 text-[11.5px] leading-[1.45] text-brick-ink">{moment.reason}</p>
              ) : null}
            </li>
          );
        })}
      </ol>
    </div>
  );
}

/**
 * What an agent decided to call itself, and what it said it was taking on.
 * Nobody assigned either: the agent read the goal, looked at the board and
 * said so with `name()`. "seat" was the old word for this, from when the
 * kickoff handed out slices; it stopped being true with A23 and the console
 * kept printing it.
 */
function chosenName(view: SwarmView, id: string): string {
  return (view.names ?? []).find((n) => n.id === id)?.name ?? "";
}

function chosenDoing(view: SwarmView, id: string): string {
  return (view.names ?? []).find((n) => n.id === id)?.doing ?? "";
}

function lastActivity(agent: AgentRow, traces: SwarmEvent[], prepared = false): string {
  if (prepared && agent.marker === "stalled") return "waiting for kickoff";
  if (agent.marker === "done") return agent.marker_info?.reason ? `done · ${agent.marker_info.reason}` : "done · session end";
  if (agent.marker === "dead") return `reaped · ${agent.marker_info?.reason ?? "stall"}${agent.marker_info?.idle_seconds ? ` after ${agent.marker_info.idle_seconds}s idle` : ""}`;
  const last = [...traces].reverse().find((e) => e.agent === agent.id);
  if (!last) return agent.marker === "stalled" ? "stalled · no trace yet" : "working";
  const what = last.tool === "post" ? "posting" : last.tool === "inbox" ? "reading inbox" : last.tool === "claim_file" ? `claiming ${String(last.args.path ?? "")}` : last.tool === "write" || last.tool === "edit" ? `writing ${String(last.args.path ?? "")}` : toolLabel(last.tool);
  return `${agent.marker === "stalled" ? "stalled · last " : ""}${what}`;
}

/** From the run's start to its end: when this agent was alive, with a brick tick per failed call and a moss one per compaction. */
function ActivitySpan({ agent, view, colour }: { agent: AgentRow; view: SwarmView; colour: string }) {
  const start = Date.parse(view.summary.started_at);
  const end = view.summary.finished_at ? Date.parse(view.summary.finished_at) : Date.now();
  const span = Math.max(1, end - start);
  const x = (iso: string | null) => {
    const t = iso ? Date.parse(iso) : NaN;
    return Number.isFinite(t) && Number.isFinite(start) ? Math.min(100, Math.max(0, ((t - start) / span) * 100)) : null;
  };
  const from = x(agent.first_event_at);
  const to = x(agent.last_event_at);
  return (
    <div className="relative h-2.5 w-full overflow-hidden rounded-[2px] bg-paper-3" aria-label={agent.first_event_at ? `active ${clock(agent.first_event_at)} – ${clock(agent.last_event_at)}` : "no activity yet"}>
      {from !== null && to !== null ? (
        <>
          <span className="absolute top-0 h-full opacity-45" style={{ left: `${from}%`, width: `${Math.max(0.5, to - from)}%`, background: colour }} />
          <span className="absolute top-0 h-full" style={{ left: `${from}%`, width: `${Math.min(2, Math.max(0.5, to - from))}%`, background: colour }} />
        </>
      ) : null}
      {agent.failure_at.map((iso, i) => {
        const fx = x(iso);
        return fx === null ? null : <span key={i} className="absolute top-0 h-full w-[2px] bg-brick" style={{ left: `${fx}%` }} title={`failure ${clock(iso)}`} />;
      })}
      {agent.compaction_at.map((iso, i) => {
        const cx = x(iso);
        return cx === null ? null : <span key={`c${i}`} className="absolute top-0 h-full w-[2px] bg-moss" style={{ left: `${cx}%` }} title={`compaction ${clock(iso)}`} />;
      })}
    </div>
  );
}

function TokenChips({ slice, tokens }: { slice: AgentBudget | undefined; tokens: number }) {
  const cells: Array<[string, number]> = [
    ["read", slice?.input ?? 0],
    ["write", slice?.output ?? 0],
    ["cache r", slice?.cache_read ?? 0],
    ["cache w", slice?.cache_write ?? 0],
    ["total", tokens],
  ];
  return (
    <div className="flex flex-wrap gap-1.5">
      {cells.map(([label, n]) => (
        <span key={label} className={cn("inline-flex h-6 items-center gap-1 rounded-[3px] border border-line px-1.5 font-mono text-[11px] tabular", label === "total" && "bg-saffron-soft/60")}>
          <span className="font-semibold text-ink">{compact(n)}</span>
          <span className="text-ink-3">{label}</span>
        </span>
      ))}
    </div>
  );
}

/**
 * How full the agent's context is, against the ceiling the self-compaction
 * lines are fractions of when the run had one, else against the model's own
 * window. The three ticks are the notice, warning and compact lines: on the
 * card the defaults, in the detail whatever `compact_config` resolved. The
 * fill follows the level the harness reports; an old run has none, and the
 * bar then colours by how full it is, as it always did.
 */
function ContextBar({ agent, compactLabel, thresholds }: { agent: AgentRow; compactLabel?: boolean; thresholds?: ContextThresholds | null }) {
  const ceiling = agent.context_ceiling > 0 ? agent.context_ceiling : agent.context_window;
  if (!(ceiling > 0 && agent.context_tokens >= 0)) return null;
  const ratio = agent.context_tokens / ceiling;
  const pct = Math.round(ratio * 100);
  const lines = agent.context_ceiling > 0 ? (thresholds ?? defaultThresholds(agent.context_ceiling)) : null;
  const level = agent.context_level;
  const fill =
    level === "forced" ? "bg-brick" : level === "notice" || level === "warning" ? "bg-saffron" : level ? "bg-kelp" : ratio >= 0.9 ? "bg-brick" : ratio >= 0.7 ? "bg-saffron" : "bg-kelp";
  return (
    <div className="min-w-0">
      <div className="flex flex-wrap items-center justify-between gap-x-2 gap-y-0.5 text-[11px]">
        <span className="flex items-center gap-1.5">
          <span className="label-caps">context</span>
          {agent.context_locked ? (
            <Badge variant="brick">COMPACTING</Badge>
          ) : level === "forced" || level === "warning" || level === "notice" ? (
            <Badge variant={level === "forced" ? "brick" : "saffron"}>{level}</Badge>
          ) : null}
          {agent.handoffs > 0 ? <Badge variant="moss">{agent.handoffs} hand-off{agent.handoffs === 1 ? "" : "s"}</Badge> : null}
        </span>
        <span className="font-mono tabular text-ink-2">{compactLabel ? `${pct}%` : `${compact(agent.context_tokens)} of ${compact(ceiling)} | ${pct}%`}</span>
      </div>
      <div className="relative mt-1 h-1.5 overflow-hidden rounded-full bg-paper-3" role="progressbar" aria-valuenow={pct} aria-valuemin={0} aria-valuemax={100} aria-label="context">
        <div className={cn("h-full rounded-full", fill)} style={{ width: `${Math.max(0, Math.min(100, ratio * 100))}%` }} />
        {lines
          ? (["notice", "warning", "compact"] as const).map((name) => (
              <span key={name} className="absolute top-0 h-full w-px bg-ink/45" style={{ left: `${Math.min(100, (lines[name] / ceiling) * 100)}%` }} title={`${name} ${compact(lines[name])}`} />
            ))
          : null}
      </div>
    </div>
  );
}

function StatsLine({ agent }: { agent: AgentRow }) {
  return (
    <span className="font-mono text-[12px] tabular text-saffron-ink">
      {agent.calls} calls | {agent.tokens.toLocaleString()} tokens | {money(agent.spent_usd)} | {agent.failures} failure{agent.failures === 1 ? "" : "s"}
    </span>
  );
}

function AgentLine({ agent, view, colour, onOpen }: { agent: AgentRow; view: SwarmView; colour: string; onOpen: () => void }) {
  const prepared = view.summary.phase === "prepared";
  const marker = prepared && agent.marker === "stalled" ? "active" : agent.marker;
  const threads = Object.keys(agent.thread_posts).length;
  return (
    <button type="button" onClick={onOpen} className={cn("card flex w-full flex-col gap-2 rounded-[10px] p-3 text-left transition-colors hover:bg-paper-2/70", agent.dead && "bg-paper-2/70")}>
      <div className="flex flex-wrap items-center gap-2.5">
        <AgentMark marker={marker} size="sm" />
        <span className="text-[13px] font-semibold" style={{ color: colour }}>
          {roleGlyph(agent.role)} {chosenName(view, agent.id) || agent.callsign || agent.id}
        </span>
        <code className="text-[11px] text-ink-3">{agent.id}</code>
        {agent.role !== "worker" ? <Badge variant="slate">{agent.role}</Badge> : null}
        <span className="truncate text-[12px] text-ink-2">{lastActivity(agent, view.traces, prepared)}</span>
        <span className="ml-auto font-mono text-[11.5px] tabular text-ink-3">
          {threads} thread{threads === 1 ? "" : "s"} / {agent.posts} message{agent.posts === 1 ? "" : "s"} / {agent.calls} call{agent.calls === 1 ? "" : "s"}
        </span>
      </div>
      {chosenDoing(view, agent.id) ? (
        <span className="truncate text-[11.5px] text-ink-3" title={chosenDoing(view, agent.id)}>
          {chosenDoing(view, agent.id)}
        </span>
      ) : null}
      <ActivitySpan agent={agent} view={view} colour={colour} />
      <div className="flex flex-wrap items-center justify-between gap-2">
        <StatsLine agent={agent} />
        <span className="text-[11px] text-ink-3">{agent.last_event_at ? relTime(agent.last_event_at) : "—"}</span>
      </div>
      <TokenChips slice={view.budget.agents[agent.id]} tokens={agent.tokens} />
      <ContextBar agent={agent} />
      {agent.claims.length ? (
        <div className="flex flex-wrap gap-1.5">
          {agent.claims.map((c) => (
            <Badge key={c} variant="slate">
              <Lock /> {c}
            </Badge>
          ))}
        </div>
      ) : null}
    </button>
  );
}

function lensKeeps(lens: Lens, e: SwarmEvent): boolean {
  switch (lens) {
    case "all":
      return true;
    case "messages":
      return e.tool === "post" || e.tool === "inbox";
    case "tools":
      return e.tool !== "thinking" && e.tool !== "post" && e.tool !== "inbox" && !LIFECYCLE.has(e.tool) && !isContextEvent(e);
    case "thinking":
      return e.tool === "thinking";
    case "context":
      return isContextEvent(e);
    case "failures":
      return isFailureEvent(e);
    case "ends":
      return e.tool === "agent_stop" || e.tool === "done" || e.tool === "harness_stop" || e.tool === "reap";
  }
}

/**
 * What an empty tab means, which is never "the file is empty".
 *
 * An agent with 700 trace lines and no failures is a good run, not a missing
 * recording, and the panel should say which of the two it is looking at.
 */
function lensEmpty(lens: Lens, total: number): { title: string; hint: string } {
  if (total === 0) return { title: "This agent left no trace", hint: "It recorded no calls at all — it may have died before its first turn." };
  switch (lens) {
    case "messages":
      return { title: "It never posted or read the board", hint: `It worked alone: ${total.toLocaleString()} lines, none of them a message.` };
    case "tools":
      return { title: "No tool calls", hint: "Everything it did was messages and lifecycle — nothing that touched a file or a shell." };
    case "context":
      return { title: "No context rows", hint: "Self compaction writes one line per turn end and one per crossing; this agent has none, so the run either predates the feature or had it off." };
    case "failures":
      return { title: "Nothing failed", hint: "No refusal, no claim violation, no error result in its whole trace." };
    case "ends":
      return { title: "No session end recorded", hint: "It never called done, and the harness never stopped or reaped it." };
    default:
      return { title: "No trace lines", hint: "traces/events.jsonl holds nothing for this selection." };
  }
}

/**
 * The agent's context over its run: tokens against the ceiling, the three
 * lines dashed across, a moss mark where each compaction landed, and the
 * line itself in the colour of the level it was at. Plain SVG in percent
 * coordinates, so it needs no library and no measuring; the strokes are
 * pinned to pixel width so a wide card does not fatten them, and the labels
 * are HTML beside the drawing because text inside a stretched SVG stretches
 * with it.
 */
function ContextChart({ agent, series }: { agent: AgentRow; series: ContextSeries }) {
  const { points, compactions } = series;
  const ceiling = series.ceiling > 0 ? series.ceiling : Math.max(agent.context_ceiling, agent.context_window, ...points.map((p) => p.tokens));
  if (!points.length || !(ceiling > 0)) return null;
  const lines = series.thresholds ?? defaultThresholds(ceiling);
  const first = agent.first_event_at ? Date.parse(agent.first_event_at) : NaN;
  const last = agent.last_event_at ? Date.parse(agent.last_event_at) : NaN;
  const from = Math.min(Number.isFinite(first) ? first : Infinity, points[0].t, compactions[0]?.t ?? Infinity);
  const to = Math.max(Number.isFinite(last) ? last : -Infinity, points[points.length - 1].t, compactions[compactions.length - 1]?.t ?? -Infinity);
  const span = Math.max(1, to - from);
  const x = (t: number) => Math.max(0, Math.min(100, ((t - from) / span) * 100));
  const y = (tokens: number) => 100 - Math.max(0, Math.min(100, (tokens / ceiling) * 100));
  const iso = (t: number) => new Date(t).toISOString();
  // One polyline per stretch at the same level, each starting from the point
  // before it so the line stays joined where the colour changes.
  const runs: Array<{ level: string; pts: ContextPoint[] }> = [];
  for (const p of points) {
    const run = runs[runs.length - 1];
    if (run && run.level === p.level) run.pts.push(p);
    else runs.push({ level: p.level, pts: run ? [run.pts[run.pts.length - 1], p] : [p] });
  }
  const stroke = (level: string) => (level === "forced" ? "var(--color-brick)" : level === "notice" || level === "warning" ? "var(--color-saffron)" : "var(--color-kelp)");
  const lineStroke = { notice: "var(--color-ink-3)", warning: "var(--color-saffron)", compact: "var(--color-brick)" } as const;
  const tail = points[points.length - 1];
  const tailPct = Math.round((tail.tokens / ceiling) * 100);
  const tailTitle = `${clock(iso(tail.t))} · ${tail.tokens.toLocaleString()} of ${ceiling.toLocaleString()} tokens · ${tailPct}%${tail.level ? ` · ${tail.level}` : ""} · cycle ${tail.cycle}`;
  return (
    <div className="mt-2">
      <div className="relative h-[120px] w-full overflow-hidden rounded-md border border-line bg-paper-2/40">
        <svg className="absolute inset-0 h-full w-full" viewBox="0 0 100 100" preserveAspectRatio="none" role="img" aria-label={`context over the run, last ${tailTitle}`}>
          {(["notice", "warning", "compact"] as const).map((name) => (
            <line key={name} x1={0} x2={100} y1={y(lines[name])} y2={y(lines[name])} stroke={lineStroke[name]} strokeWidth={1} strokeDasharray="4 3" vectorEffect="non-scaling-stroke" opacity={0.7} />
          ))}
          {compactions.map((c, i) => (
            <line key={i} x1={x(c.t)} x2={x(c.t)} y1={0} y2={100} stroke="var(--color-moss)" strokeWidth={2} vectorEffect="non-scaling-stroke">
              <title>{`compaction ${clock(iso(c.t))} · via ${c.via} · ${c.reason} · ${c.tokensBefore === null ? "?" : compact(c.tokensBefore)} to ${c.tokensAfter === null ? "?" : compact(c.tokensAfter)} tokens · cycle ${c.cycle}`}</title>
            </line>
          ))}
          {runs.map((run, i) => (
            <polyline key={i} points={run.pts.map((p) => `${x(p.t)},${y(p.tokens)}`).join(" ")} fill="none" stroke={stroke(run.level)} strokeWidth={1.5} strokeLinejoin="round" strokeLinecap="round" vectorEffect="non-scaling-stroke">
              <title>{`${run.level || "no level"} · ${run.pts.length} turn${run.pts.length === 1 ? "" : "s"}`}</title>
            </polyline>
          ))}
        </svg>
        {(["notice", "warning", "compact"] as const).map((name) => (
          <span key={name} className="pointer-events-none absolute left-1.5 font-mono text-[10px] leading-none text-ink-3" style={{ top: `calc(${y(lines[name])}% + 2px)` }}>
            {name} {compact(lines[name])}
          </span>
        ))}
        <span className="pointer-events-none absolute right-1.5 top-1 font-mono text-[10px] leading-none text-ink-3">ceiling {compact(ceiling)}</span>
        <span
          className={cn("absolute size-2 -translate-x-1/2 -translate-y-1/2 rounded-full ring-2 ring-card", tail.level === "forced" ? "bg-brick" : tail.level === "notice" || tail.level === "warning" ? "bg-saffron" : "bg-kelp")}
          style={{ left: `${x(tail.t)}%`, top: `${y(tail.tokens)}%` }}
          title={tailTitle}
        />
      </div>
      <div className="mt-1 flex flex-wrap items-baseline justify-between gap-x-3 font-mono text-[10.5px] tabular text-ink-3">
        <span>{clock(iso(from))}</span>
        <span title={tailTitle}>
          last {compact(tail.tokens)} · {tailPct}%{tail.level ? ` · ${tail.level}` : ""} · cycle {tail.cycle}
        </span>
        <span>{clock(iso(to))}</span>
      </div>
    </div>
  );
}

/** The words for one moment on the compaction timeline: what it was, the numbers, whether it went wrong. */
function momentRow(m: CompactionMoment): { dot: string; tone: string; title: string; meta: string; detail: string; bad: boolean } {
  const pctText = (p: number | null) => (p === null ? "" : ` (${Math.round(p)}%)`);
  switch (m.kind) {
    case "crossing":
      return {
        dot: m.level === "forced" ? "bg-brick" : "bg-saffron",
        tone: m.level === "forced" ? "text-brick-ink" : "text-saffron-ink",
        title: m.level === "forced" ? "compact line" : `${m.level} line`,
        meta: `${m.tokens === null ? "?" : m.tokens.toLocaleString()} tokens${pctText(m.percent)}${m.cycle === null ? "" : ` · cycle ${m.cycle}`}`,
        detail: m.level === "forced" ? "every tool but self_compact, budget and done is refused until the hand-off" : "",
        bad: false,
      };
    case "note":
      return m.ok
        ? {
            dot: "bg-moss",
            tone: "text-moss-ink",
            title: m.retry ? "note to self · retried" : "note to self",
            meta: `${m.chars.toLocaleString()} chars${m.tokens === null ? "" : ` at ${m.tokens.toLocaleString()} tokens${pctText(m.percent)}`}`,
            detail: "",
            bad: false,
          }
        : { dot: "bg-brick", tone: "text-brick-ink line-through", title: "note to self", meta: "refused", detail: m.reason, bad: true };
    case "compaction":
      return {
        dot: "bg-moss",
        tone: "text-moss-ink",
        title: m.via === "self" ? "hand-off" : "Pi compaction",
        meta: `${m.reason}${m.cycle === null ? "" : ` · cycle ${m.cycle}`}`,
        detail: `${m.tokensBefore === null ? "?" : compact(m.tokensBefore)} → ${m.tokensAfter === null ? "?" : compact(m.tokensAfter)} tokens${m.summaryUsd === null ? "" : ` · summary ${money(m.summaryUsd)}`}${m.summaryTokens === null ? "" : ` · ${compact(m.summaryTokens)} summary tokens`}${m.via === "pi" ? " · no note came back" : ""}`,
        bad: false,
      };
    case "failure":
      return {
        dot: "bg-brick",
        tone: "text-brick-ink",
        title: "compaction failed",
        meta: `${m.stage || "unknown"} stage${m.retrying ? " · retrying" : m.lockReleased ? " · lock released" : m.fallback ? ` · fell back to ${m.fallback}` : ""}${m.aborted ? " · aborted" : ""}`,
        detail: m.reason,
        bad: true,
      };
  }
}

/**
 * What happened to this agent's context, one entry per crossing, note,
 * compaction and failure, in the style of the name history. Holds are one
 * count under the list: a dozen refused calls in a row are one fact. A run
 * with nothing here is either older than the feature, or had it off, or has
 * not reached the first line yet, and the sentence says which.
 */
function CompactionHistory({ view, series, moments }: { view: SwarmView; series: ContextSeries; moments: CompactionMoment[] }) {
  if (!moments.length) {
    const options = view.registry?.self_compact;
    const off = !options || options.enabled === false;
    return <p className="m-0 mt-1.5 text-[12px] text-ink-3">{off ? "Self compaction was not on for this run." : "No crossings yet."}</p>;
  }
  return (
    <div className="mt-2.5">
      <div className="label-caps mb-1.5 text-ink-3">
        Compaction history · {moments.length} moment{moments.length === 1 ? "" : "s"}
      </div>
      <ol className="m-0 flex list-none flex-col gap-1.5 border-l border-line p-0 pl-3">
        {moments.map((m, i) => {
          const row = momentRow(m);
          return (
            <li key={`${m.ts}-${i}`} className="relative">
              <span className={cn("absolute -left-[15px] top-[6px] size-1.5 rounded-full ring-2 ring-card", row.dot)} />
              <div className="flex flex-wrap items-baseline gap-x-2 gap-y-0.5">
                <span className="font-mono text-[11px] tabular text-ink-3">{clock(m.ts)}</span>
                <span className={cn("text-[12.5px] font-semibold", row.tone)}>{row.title}</span>
                {row.meta ? <span className="text-[11px] text-ink-3">{row.meta}</span> : null}
              </div>
              {row.detail ? <p className={cn("m-0 text-[11.5px] leading-[1.45]", row.bad ? "text-brick-ink" : "text-ink-2")}>{row.detail}</p> : null}
            </li>
          );
        })}
      </ol>
      {series.holds > 0 ? (
        <p className="m-0 mt-1.5 text-[11.5px] text-ink-3">
          {series.holds} tool call{series.holds === 1 ? "" : "s"} held at the line.
        </p>
      ) : null}
    </div>
  );
}

function AgentDetail({ view, agent, version, onBack, colour }: { view: SwarmView; agent: AgentRow; version: number; onBack: () => void; colour: string }) {
  const loader = useCallback(() => api.traces(view.summary.id, { agent: agent.id, limit: 2000 }), [view.summary.id, agent.id]);
  const traces = useResource(loader, version, [view.summary.id, agent.id]);
  const [lens, setLens] = useState<Lens>("all");
  const events = useMemo(() => (traces.data?.events ?? []).filter((e) => lensKeeps(lens, e)), [traces.data, lens]);
  const counts = useMemo(() => {
    const all = traces.data?.events ?? [];
    const c = (l: Lens) => all.filter((e) => lensKeeps(l, e)).length;
    return { all: all.length, messages: c("messages"), tools: c("tools"), thinking: c("thinking"), context: c("context"), failures: c("failures"), ends: c("ends") };
  }, [traces.data]);
  // The whole trace of this one agent, so the chart and the history are not
  // limited to the tail `view.traces` carries.
  const series = useMemo(() => contextSeries(traces.data?.events ?? [], agent.id), [traces.data, agent.id]);
  const moments = useMemo(() => compactionHistory(traces.data?.events ?? [], agent.id), [traces.data, agent.id]);
  const threads = Object.entries(agent.thread_posts).sort((a, b) => b[1] - a[1]);
  return (
    <div className="space-y-3">
      <button type="button" onClick={onBack} className="inline-flex items-center gap-1 text-[12px] text-ink-2 hover:text-ink">
        <ArrowLeft className="size-3.5" /> All agents
      </button>
      <div className="card rounded-[10px] p-4" style={{ borderTop: `4px solid ${colour}` }}>
        <div className="flex flex-wrap items-baseline gap-3">
          <h3 className="serif m-0 text-[28px] leading-none" style={{ color: colour }}>
            {chosenName(view, agent.id) || agent.callsign || agent.id}
          </h3>
          <Badge variant={agent.marker === "done" ? "moss" : agent.marker === "dead" ? "brick" : agent.marker === "stalled" ? "saffron" : "kelp"}>{markerText(agent.marker)}</Badge>
        </div>
        <p className="m-0 mt-1.5 font-mono text-[12px] text-ink-3">
          {roleGlyph(agent.role)} {agent.id} | {agent.role} | {agent.first_event_at ? `active ${clock(agent.first_event_at)} — ${clock(agent.last_event_at)}` : "no activity yet"}
          {view.team.agents.find((a) => a.id === agent.id)?.model ? ` | ${view.team.agents.find((a) => a.id === agent.id)!.model}` : ""}
        </p>
        <p className="m-0 mt-1 text-[13px] text-ink-2">{lastActivity(agent, view.traces)}</p>
        {chosenDoing(view, agent.id) ? (
          <div className="mt-2.5 rounded-lg border border-line bg-paper-2/60 px-3 py-2">
            <div className="label-caps mb-0.5 text-ink-3">In its own words · what it took on</div>
            <p className="m-0 text-[12.5px] leading-[1.5] text-ink-2">{chosenDoing(view, agent.id)}</p>
          </div>
        ) : null}
        <NameHistory swarmId={view.summary.id} id={agent.id} version={version} />
        <div className="mt-3">
          <ActivitySpan agent={agent} view={view} colour={colour} />
        </div>
        <div className="mt-3 grid gap-3 sm:grid-cols-[200px_minmax(0,1fr)]">
          <div>
            <div className="label-caps mb-1">Threads</div>
            {threads.length ? (
              <ul className="m-0 flex list-none flex-col gap-0.5 p-0 font-mono text-[12px]">
                {threads.map(([name, n]) => (
                  <li key={name} className="flex items-center justify-between gap-2">
                    <span className="font-semibold text-ink"># {name}</span>
                    <span className="tabular text-ink-3">{n}</span>
                  </li>
                ))}
              </ul>
            ) : (
              <span className="text-[12px] text-ink-3">no posts yet</span>
            )}
          </div>
          <div className="flex flex-col gap-2">
            <div className="label-caps">Agent stats</div>
            <StatsLine agent={agent} />
            <TokenChips slice={view.budget.agents[agent.id]} tokens={agent.tokens} />
            <ContextBar agent={agent} thresholds={series.thresholds} />
          </div>
        </div>
        <div className="mt-3 border-t border-line pt-2">
          <div className="flex flex-wrap items-baseline justify-between gap-2">
            <div className="label-caps">Context</div>
            {series.points.length ? (
              <span className="text-[11px] text-ink-3">
                {series.points.length} turn{series.points.length === 1 ? "" : "s"} · {series.compactions.length} compaction{series.compactions.length === 1 ? "" : "s"}
                {series.thresholds ? " · lines from compact_config" : " · default lines"}
              </span>
            ) : null}
          </div>
          {traces.data ? (
            <>
              <ContextChart agent={agent} series={series} />
              <CompactionHistory view={view} series={series} moments={moments} />
            </>
          ) : (
            <span className="text-[12px] text-ink-3">reading the trace</span>
          )}
        </div>
        {agent.marker_info ? (
          <dl className="mt-3 grid grid-cols-2 gap-x-4 gap-y-1 border-t border-line pt-2 text-[12px] sm:grid-cols-4">
            {Object.entries(agent.marker_info).map(([k, v]) => (
              <div key={k}>
                <dt className="label-caps">{k.replace(/_/g, " ")}</dt>
                <dd className="truncate text-ink">{String(v)}</dd>
              </div>
            ))}
          </dl>
        ) : null}
        <div className="mt-3 flex flex-wrap gap-1.5">
          {agent.claims.length ? (
            agent.claims.map((c) => (
              <Badge key={c} variant="slate">
                <Lock /> holds {c}
              </Badge>
            ))
          ) : (
            <span className="text-[12px] text-ink-3">No live claims.</span>
          )}
        </div>
      </div>

      <div className="flex flex-wrap items-center gap-1.5" role="tablist" aria-label="Trace lens">
        {(
          [
            ["all", "All"],
            ["messages", "Messages"],
            ["tools", "Tools"],
            ["thinking", "Thinking"],
            ["context", "Context"],
            ["failures", "Failures"],
            ["ends", "Session ends"],
          ] as Array<[Lens, string]>
        ).map(([key, label]) => (
          <button
            key={key}
            type="button"
            role="tab"
            aria-selected={lens === key}
            onClick={() => setLens(key)}
            className={cn("h-7 rounded-md border px-2.5 font-mono text-[11px] font-semibold uppercase tracking-[0.03em] tabular", lens === key ? "border-ink bg-ink text-paper" : "border-line bg-card text-ink-2 hover:text-ink", key === "failures" && counts.failures && lens !== key && "text-brick-ink")}
          >
            {label} <span className={cn("font-normal", lens === key ? "text-paper/70" : "text-ink-3")}>{counts[key]}</span>
          </button>
        ))}
      </div>
      {traces.error && !traces.data ? <ErrorState error={traces.error} onRetry={traces.reload} /> : null}
      {traces.loading && !traces.data ? <LoadingState label="Reading trace" rows={4} /> : null}
      {traces.data ? (
        lens === "thinking" ? (
          <ThinkingStream view={view} agent={agent} events={events} version={version} colour={colour} />
        ) : (
          <TraceList
            events={events}
            agents={view.agents}
            showAgent={false}
            swarmId={view.summary.id}
            empty={lensEmpty(lens, counts.all)}
            pageKey={`${agent.id}|${lens}`}
          />
        )
      ) : null}
    </div>
  );
}

export function AgentsPanel({
  view,
  selected,
  onSelect,
  version,
}: {
  view: SwarmView;
  selected: string | null;
  onSelect: (agent: string | null) => void;
  version: number;
}) {
  const [query, setQuery] = useState("");
  const [order, setOrder] = useState<Order>("active");
  const colour = useAgentColours(view.agents);
  const names = useAgentNames(view.agents);

  const filtered = useMemo(() => {
    const q = query.trim().toLowerCase();
    const list = view.agents.filter((a) => !q || `${a.id} ${a.callsign ?? ""} ${a.role}`.toLowerCase().includes(q));
    const by: Record<Order, (a: AgentRow, b: AgentRow) => number> = {
      active: (a, b) => (b.last_event_at ?? "").localeCompare(a.last_event_at ?? ""),
      messages: (a, b) => b.posts - a.posts,
      threads: (a, b) => Object.keys(b.thread_posts).length - Object.keys(a.thread_posts).length,
      calls: (a, b) => b.calls - a.calls,
      cost: (a, b) => b.spent_usd - a.spent_usd,
      name: (a, b) => (a.callsign ?? a.id).localeCompare(b.callsign ?? b.id),
    };
    return list.sort((a, b) => by[order](a, b) || a.id.localeCompare(b.id));
  }, [view.agents, query, order]);

  // The five newest lines that are not chatter: what the team is doing right
  // now. On a run that has finished, "right now" is the shutdown sequence —
  // five rows of `session end`, `done` and `inputs check` with no heading,
  // sitting above the agents and belonging to nothing a reader had asked
  // about. A live run gets them; a finished one gets its agents.
  const finished = view.summary.phase === "done";
  const recent = useMemo(
    () => (finished ? [] : view.traces.filter((e) => !isNoise(e) || e.tool === "thinking").slice(-5).reverse()),
    [view.traces, finished],
  );

  const current = selected ? view.agents.find((a) => a.id === selected || a.callsign?.toLowerCase() === selected.toLowerCase()) : null;
  if (selected && current) return <AgentDetail view={view} agent={current} version={version} onBack={() => onSelect(null)} colour={colour(current.id)} />;

  if (!view.agents.length) return <EmptyState icon={<Users />} title="No agents in team.json" hint="The spawner writes team.json at kickoff; an empty team means the sandbox was never prepared." />;

  return (
    <div className="space-y-3">
      {recent.length ? (
        <div className="card rounded-[10px] p-3">
        <div className="mb-1.5 flex items-baseline justify-between gap-2">
          <span className="label-caps text-ink-3">Right now · the last five lines</span>
          <span className="text-[11px] text-ink-3">every call is in the raw trace</span>
        </div>
        <ol className="m-0 flex list-none flex-col gap-0.5 p-0 font-mono text-[11.5px]" aria-label="Latest trace lines">
          {recent.map((e, i) => (
            <li key={`${e.ts}${i}`} className="grid grid-cols-[86px_110px_100px_minmax(0,1fr)] items-baseline gap-2">
              <span className="tabular text-ink-3">{clock(e.ts)}</span>
              <span className="truncate font-semibold" style={{ color: colour(e.agent) }}>
                {names(e.agent)}
              </span>
              <Badge variant={toolTone(e.tool)} className="justify-self-start font-mono">
                {toolLabel(e.tool)}
              </Badge>
              <span className={cn("truncate text-ink-3", e.tool === "thinking" && "italic")}>{e.tool === "thinking" ? thinkingText(e) : JSON.stringify(e.args)}</span>
            </li>
          ))}
        </ol>
        </div>
      ) : null}

      <div className="flex flex-wrap items-center justify-between gap-3">
        <div className="flex items-center gap-3 font-mono text-[11.5px] uppercase tracking-[0.04em]" role="group" aria-label="Order">
          <span className="font-semibold text-ink">Order</span>
          {(
            [
              ["active", "Active"],
              ["messages", "Messages"],
              ["threads", "Threads"],
              ["calls", "Calls"],
              ["cost", "Cost"],
              ["name", "Name"],
            ] as Array<[Order, string]>
          ).map(([key, label]) => (
            <button key={key} type="button" aria-pressed={order === key} onClick={() => setOrder(key)} className={cn("border-b-2 pb-px", order === key ? "border-brick text-brick-ink" : "border-transparent text-ink-3 hover:text-ink")}>
              {label}
            </button>
          ))}
        </div>
        <div className="flex items-center gap-2">
          <span className="font-mono text-[11.5px] tabular text-ink-3">
            {filtered.length} of {view.agents.length}
          </span>
          <Input value={query} onChange={(e) => setQuery(e.target.value)} placeholder="find an agent…  ( / )" className="h-8 w-[220px] rounded-lg font-mono text-[12.5px]" aria-label="Search agents" data-find />
        </div>
      </div>
      {selected && !current ? <EmptyState title={`No agent “${selected}”`} hint="Not in team.json for this swarm." /> : null}
      {filtered.length === 0 ? <EmptyState title="No agent matches" hint="Search by callsign (Scout), id (s7a1c00) or role (critic)." /> : null}
      <div className="flex flex-col gap-2">
        {filtered.map((a) => (
          <AgentLine key={a.id} agent={a} view={view} colour={colour(a.id)} onOpen={() => onSelect(a.id)} />
        ))}
      </div>
      <div className="flex items-center gap-1.5 text-[11px] text-ink-3">
        <AgentMark marker="active" size="sm" /> working <AgentMark marker="done" size="sm" /> done <AgentMark marker="stalled" size="sm" /> stalled <AgentMark marker="dead" size="sm" /> reaped · a brick tick on the span is a failed call, a moss tick a compaction
      </div>
    </div>
  );
}
