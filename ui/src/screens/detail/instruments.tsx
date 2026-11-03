/**
 * The instruments beside the story: leases with their time left, the team
 * with spend per agent, and what the harness is doing — including the grace
 * clock once a cap or wall-clock steer has gone out.
 */
import { seatStates } from "@/lib/seat-state";
import { describeEvent } from "@/lib/event-taxonomy";
import { Fragment } from "react";
import { Link } from "react-router-dom";
import { Chip, Meter, SerifH } from "@/components/console";
import { useAgentColours } from "@/lib/agent-colour";
import { compact, mmss, money, shortDuration } from "@/lib/format";
import type { SwarmEvent, SwarmView } from "@/lib/types";
import { cn } from "@/lib/utils";
import { meteringWords } from "@/lib/metering";

/** Matches STOP_GRACE_MS in extensions/protocol.ts. */
export const GRACE_MS = 2 * 60 * 1000;

export function LeasesPanel({ view, now }: { view: SwarmView; now: number }) {
  const claims = view.claims;
  return (
    <section className="card flex flex-col gap-3 rounded-xl p-[18px_20px]">
      <div className="flex items-baseline justify-between">
        <SerifH as="h3" size={22}>
          Leases
        </SerifH>
        <span className="text-[12px] text-ink-3">{claims.length ? `${claims.length} held` : "none held"}</span>
      </div>
      {claims.length === 0 ? (
        <p className="m-0 text-[12.5px] text-ink-2">Nobody holds a path. A write without a lease is blocked; a shell write without one is announced.</p>
      ) : (
        claims.map((c) => {
          const expires = Date.parse(c.expires_at);
          const left = Number.isFinite(expires) ? Math.max(0, expires - now) : c.expires_in_seconds * 1000;
          const total = Math.max(1, c.seconds * 1000);
          return (
            <div key={`${c.path}:${c.owner}`} className="flex flex-col gap-1.5">
              <div className="flex items-baseline justify-between gap-2.5">
                <span className="truncate font-mono text-[12.5px] text-ink">{c.path}</span>
                <span className="shrink-0 font-mono text-[12px] text-kelp-ink">
                  {c.owner} · {mmss(left)} left
                </span>
              </div>
              <Meter pct={(left / total) * 100} tone={left < 15_000 ? "saffron" : "kelp"} label={`${c.owner} holds ${c.path}`} />
              {c.reason ? <span className="text-[12px] text-ink-2">"{c.reason}"</span> : null}
            </div>
          );
        })
      )}
    </section>
  );
}

export function TeamPanel({ view, onSelect }: { view: SwarmView; onSelect?: (id: string) => void }) {
  // Nothing was charged on a team of local models; what varies between
  // agents there is how many tokens each one used.
  const unmetered = view.budget.metered === false;
  const measure = (a: { spent_usd: number; tokens: number }) => (unmetered ? a.tokens : a.spent_usd);
  const max = Math.max(unmetered ? 1 : 0.0001, ...view.agents.map(measure));
  const lastTool = new Map<string, string>();
  for (const e of view.traces) lastTool.set(e.agent, e.tool);
  // One source for a seat's state: the hub's word while it hears from the
  // VM, the host's markers otherwise (the same rule as the band and the VM panel).
  const states = seatStates(view.agents, view.vms, lastTool);
  const byHub = [...states.values()].some((st) => st.by === "hub");
  const models = new Map(view.team.agents.map((a) => [a.id, a.model]));
  const mixed = (view.team.models?.length ?? 0) > 1;
  const colour = useAgentColours(view.agents);
  return (
    <section className="card flex flex-col gap-2.5 rounded-xl p-[18px_20px]">
      <div className="flex items-baseline justify-between">
        <SerifH as="h3" size={22}>
          Team
        </SerifH>
        <span className="text-[12px] text-ink-3">{mixed ? "mixed models · " : ""}{unmetered ? `tokens per agent · ${meteringWords(view.budget).label}` : "spend per agent"}{byHub ? " · state by the hub" : ""}</span>
      </div>
      <div className="grid grid-cols-[minmax(64px,auto)_minmax(0,1fr)_60px_56px] items-center gap-x-3 gap-y-2 text-[12.5px]">
        {view.agents.map((a) => {
          const st = states.get(a.id)!;
          const tone = { done: "text-moss", dead: "text-brick-ink", quiet: "text-saffron-ink", idle: "text-ink-3", working: "text-kelp-ink" }[st.tone];
          return (
            <Fragment key={a.id}>
              <button type="button" onClick={() => onSelect?.(a.id)} className="flex flex-col items-start gap-0.5 text-left font-mono text-[12.5px] hover:underline" style={{ color: colour(a.id) }}>
                <span className="inline-flex items-center gap-1.5">
                  <span className="size-2 rounded-full" style={{ background: colour(a.id) }} />
                  {a.id}
                </span>
                {mixed && models.get(a.id) ? <span className="max-w-[140px] truncate text-[10.5px] text-ink-3">{models.get(a.id)}</span> : null}
              </button>
              <Meter pct={(measure(a) / max) * 100} tone="slate" label={`${a.id} ${unmetered ? "tokens" : "spend"}`} />
              <span className="text-right font-mono">
                {unmetered ? compact(a.tokens) : money(a.spent_usd, 2)}
              </span>
              <span className={cn("truncate", tone)} title={`${st.by === "hub" ? "the hub's word" : "the host's markers"}${st.host_note ? ` · ${st.host_note}` : ""}`}>
                {st.label}
              </span>
            </Fragment>
          );
        })}
      </div>
    </section>
  );
}

function describe(e: SwarmEvent): string {
  const r = (e.result ?? {}) as Record<string, unknown>;
  const path = typeof e.args.path === "string" ? e.args.path : "";
  if (e.tool === "claim_violation") {
    if (r.blocked) return `blocked ${e.agent}: ${r.protected ? `${path} is harness-owned` : `${path} without a lease`}`;
    return `detected a shell write by ${e.agent} to ${path}${r.rev ? ` (snapshot rev ${r.rev})` : ""}`;
  }
  if (e.tool === "cap_steer") return `steered ${e.agent}: the spend cap is hit`;
  if (e.tool === "wall_steer") return `steered ${e.agent}: the wall clock is hit`;
  if (e.tool === "harness_stop") return `wrote done/SWARM_DONE itself (${String(e.args.reason ?? "")})`;
  if (e.tool === "reap") return `reaped ${e.agent}`;
  // The VM run's own: the hub, the keeper, the collector, the finish, custody.
  const words = describeEvent(e);
  if (words) return words;
  return `${e.tool} · ${e.agent}`;
}

/**
 * What the harness did to the run rather than what an agent did: a blocked
 * or detected write, a steer, a stop, a reap, and in a VM run the hub's own
 * interventions: a seat stopped at its cap, the keeper bringing back a dead
 * hub or collector, a finish or a custody that failed, an idle nudge.
 */
export function isIntervention(e: SwarmEvent): boolean {
  if (["claim_violation", "cap_steer", "wall_steer", "harness_stop", "reap", "agent_cap_steer", "agent_cap_stop", "hub_restarted", "collector_restarted", "idle_nudge", "budget_precall_stop"].includes(e.tool)) return true;
  const failed = (e.result as { ok?: unknown } | null)?.ok === false;
  return failed && (e.tool === "vm_finish" || e.tool === "custody");
}

export function HarnessPanel({ view, now, onShowTraces }: { view: SwarmView; now: number; onShowTraces?: () => void }) {
  const b = view.budget;
  const s = view.summary;
  const interventions = view.traces.filter(isIntervention);
  const steeredAt = b.stop_steer_at ? Date.parse(b.stop_steer_at) : NaN;
  const steering = Number.isFinite(steeredAt) && !view.sentinel && s.phase === "running";
  const graceLeft = steering ? Math.max(0, steeredAt + GRACE_MS - now) : 0;
  const unmetered = b.metered === false;
  const capTokens = typeof b.cap_tokens === "number" && b.cap_tokens > 0 ? b.cap_tokens : 0;
  const capPct = unmetered ? (capTokens > 0 ? Math.round((b.tokens / capTokens) * 100) : 0) : b.cap_usd > 0 ? Math.round((b.spent_usd / b.cap_usd) * 100) : 0;
  const capWord = unmetered ? "token cap" : "spend cap";
  const quiet = interventions.length === 0 && !steering;

  return (
    <section className={cn("card flex flex-col gap-2.5 rounded-xl p-[16px_20px]", quiet ? "border-paper-3 bg-paper-2" : steering ? "border-brick bg-brick-soft/40" : "bg-card")}>
      <div className="flex items-baseline justify-between">
        <SerifH as="h3" size={20}>
          Harness
        </SerifH>
        {steering ? <Chip tone="brick">grace {mmss(graceLeft)}</Chip> : quiet ? <Chip tone="moss">quiet</Chip> : <Chip tone="saffron">{interventions.length} intervention{interventions.length === 1 ? "" : "s"}</Chip>}
      </div>

      {steering ? (
        <div className="flex flex-col gap-2">
          <div className="flex items-baseline gap-2.5">
            <span className="serif text-[40px] leading-none text-brick-ink tabular">{mmss(graceLeft)}</span>
            <span className="text-[13px] leading-[1.35] text-ink">
              until the harness writes <span className="font-mono">done/SWARM_DONE</span> itself
            </span>
          </div>
          <Meter pct={((GRACE_MS - graceLeft) / GRACE_MS) * 100} tone="brick" label="grace period" />
          <p className="m-0 text-[12.5px] leading-[1.5] text-ink-2 [text-wrap:pretty]">
            {b.stop_reason === "wall_clock" ? "The wall clock is hit" : `The ${capWord} is hit (${capPct}%)`}: every agent was steered to call{" "}
            <span className="font-mono">done(cannot_complete)</span> from one shared clock. Raising the cap clears it.
          </p>
        </div>
      ) : quiet ? (
        <p className="m-0 text-[12.5px] leading-[1.5] text-ink-2 [text-wrap:pretty]">
          {view.violations.length === 0 ? "0 violations — every write so far went through a lease." : ""} {unmetered ? (capTokens > 0 ? `Token cap at ${capPct}%` : "No metered cost, no token cap recorded") : `Cap at ${capPct}%`}, no steer sent. A shell write without a lease would be announced here and on the board.
        </p>
      ) : (
        <ul className="m-0 flex list-none flex-col gap-1.5 p-0 text-[12.5px] leading-[1.45]">
          {interventions.slice(-5).map((e, i) => (
            <li key={`${e.ts}-${i}`} className="grid grid-cols-[10px_minmax(0,1fr)] items-start gap-2">
              <span className={cn("mt-[6px] size-2 rounded-full", e.tool === "harness_stop" ? "bg-brick" : e.tool === "claim_violation" ? "bg-saffron" : "bg-slate")} />
              <span className="text-ink">{describe(e)}</span>
            </li>
          ))}
          {interventions.length > 5 && onShowTraces ? (
            <li>
              <button type="button" onClick={onShowTraces} className="text-[12px] font-medium text-kelp-ink hover:underline">
                all {interventions.length} in the raw trace
              </button>
            </li>
          ) : null}
        </ul>
      )}

      {view.sentinel && view.sentinel_info ? (
        <p className="m-0 border-t border-paper-3 pt-2 text-[12px] leading-[1.45] text-ink-2">
          <span className="font-mono">done/SWARM_DONE</span> by <span className="font-mono">{view.sentinel_info.by}</span>
          {view.sentinel_info.reason ? ` — ${view.sentinel_info.reason}` : ""}
          {view.sentinel_info.output ? (
            <>
              {" · "}
              <Link to={`/swarms/${s.id}/artifacts/${encodeURIComponent(view.sentinel_info.output)}`} className="font-mono">
                {view.sentinel_info.output}
              </Link>
            </>
          ) : null}
        </p>
      ) : null}
      {s.phase === "running" && !steering ? <span className="text-[11.5px] text-ink-3">{view.until_solved ? "until solved: no wall clock" : s.wall_clock_minutes > 0 ? `wall clock ${shortDuration(s.wall_clock_minutes * 60_000)}` : "no wall clock"} · hard-kill {b.hard_kill ? "on" : "off"}</span> : null}
    </section>
  );
}
