import { spendSourceNote } from "@/lib/run-facts";
import { Badge } from "@/components/ui/badge";
import { InlineNote } from "@/components/states";
import { BudgetBar } from "@/components/swarm-bits";
import { compact, money, pct, shortDuration } from "@/lib/format";
import { useAgentNames } from "@/lib/hooks";
import type { SwarmView } from "@/lib/types";
import { meteringWords } from "@/lib/metering";
import { cn } from "@/lib/utils";

/** Spend folded by the model each agent runs on, from team.json. */
type ModelSlice = { model: string; spent_usd: number; calls: number; tokens: number; agents: string[] };

/**
 * The model an agent runs on: its own entry in team.json, else the swarm's
 * single model when the kickoff had one, else "unknown". An agent that is in
 * the budget but not in the team (a stray id) falls back the same way.
 */
function modelOf(view: SwarmView, id: string): string {
  const own = view.team.agents.find((a) => a.id === id)?.model;
  if (own) return own;
  const single = view.summary.model && !view.summary.model.includes(",") ? view.summary.model : "";
  return single || "unknown";
}

function byModel(view: SwarmView, names: (id: string) => string): ModelSlice[] {
  const groups = new Map<string, ModelSlice>();
  for (const [id, slice] of Object.entries(view.budget.agents)) {
    const model = modelOf(view, id);
    const g = groups.get(model) ?? { model, spent_usd: 0, calls: 0, tokens: 0, agents: [] };
    g.spent_usd += slice.spent_usd;
    g.calls += slice.calls;
    g.tokens += slice.tokens;
    g.agents.push(names(id));
    groups.set(model, g);
  }
  // A team member with no usage yet still counts as an agent on its model.
  for (const a of view.team.agents) {
    if (view.budget.agents[a.id]) continue;
    const model = modelOf(view, a.id);
    const g = groups.get(model) ?? { model, spent_usd: 0, calls: 0, tokens: 0, agents: [] };
    g.agents.push(names(a.id));
    groups.set(model, g);
  }
  return [...groups.values()].sort((x, y) => y.spent_usd - x.spent_usd || y.tokens - x.tokens || x.model.localeCompare(y.model));
}

export function BudgetPanel({ view, elapsedMs }: { view: SwarmView; elapsedMs: number }) {
  const b = view.budget;
  const names = useAgentNames(view.agents);
  const remaining = Math.max(0, b.cap_usd - b.spent_usd);
  const wallMs = b.wall_clock_minutes * 60_000;
  const wallPct = pct(elapsedMs, wallMs);
  const perAgentCap = typeof b.cap_per_agent_usd === "number" && b.cap_per_agent_usd > 0 ? b.cap_per_agent_usd : 0;
  // A ceiling per model on what every seat running it spends together, as the kickoff wrote it.
  const modelCaps = Object.entries(b.cap_per_model_usd ?? {}).filter((e): e is [string, number] => typeof e[1] === "number" && e[1] > 0);
  const spentOn = (model: string) => Object.values(b.agents).reduce((sum, a) => (a.model === model ? sum + (a.spent_usd ?? 0) : sum), 0);
  const overOwnCap = (id: string) => perAgentCap > 0 && (b.agents[id]?.spent_usd ?? 0) >= perAgentCap;
  const rows = view.agents.map((a) => ({ id: a.id, name: names(a.id), slice: b.agents[a.id], marker: a.marker, overOwn: overOwnCap(a.id) }));
  const extra = Object.keys(b.agents).filter((id) => !view.agents.some((a) => a.id === id));
  // A team of local models is not charged. Its numbers are tokens, its brake
  // is cap_tokens, and "$0.0000" would read as "nothing happened".
  const unmetered = b.metered === false;
  const metering = meteringWords(b);
  const capTokens = typeof b.cap_tokens === "number" && b.cap_tokens > 0 ? b.cap_tokens : 0;
  const remainingTokens = capTokens > 0 ? Math.max(0, capTokens - b.tokens) : 0;
  const maxSpend = Math.max(0.0001, ...Object.values(b.agents).map((s) => s.spent_usd));
  const maxTokens = Math.max(1, ...Object.values(b.agents).map((s) => s.tokens));
  // An until-solved run's caps are advisory: spend is shown against them, and nothing is stopped for it.
  const advisory = view.until_solved === true || b.until_solved === true;
  const overUsd = !advisory && !unmetered && b.cap_usd > 0 && b.spent_usd >= b.cap_usd;
  const overTokens = !advisory && capTokens > 0 && b.tokens >= capTokens;
  const over = overUsd || overTokens;
  const models = byModel(view, names);
  const overOwnCount = rows.filter((r) => r.overOwn).length;
  const shareOf = (spent: number, tokens: number) =>
    unmetered ? (b.tokens > 0 ? `${Math.round((tokens / b.tokens) * 100)}%` : "—") : b.spent_usd > 0 ? `${Math.round((spent / b.spent_usd) * 100)}%` : "—";

  const vmRun = view.summary.isolation === "microvm" || (view.vms ?? []).length > 0;
  const capStopped = (view.vms ?? []).filter((v) => v.cap_stopped_at);

  return (
    <div className="space-y-4">
      {advisory ? (
        <InlineNote tone="warn">
          This run is until solved: there is no wall clock, and every cap below is advisory. Spend is recorded and shown, and nothing is stopped for it; only the operator's stop ends the run.
        </InlineNote>
      ) : null}
      {vmRun ? (
        <InlineNote>
          {spendSourceNote(true)}
          {capStopped.length ? ` Stopped at their own cap by the hub: ${capStopped.map((v) => v.agent).join(", ")}.` : ""}
        </InlineNote>
      ) : null}
      <div className="grid gap-3 md:grid-cols-3">
        <section className="card p-4 md:col-span-2">
          <div className="flex items-baseline justify-between">
            <h3 className="label-caps">{unmetered ? "Tokens against cap" : "Spend against cap"}</h3>
            <span className="text-[12px] text-ink-3">source: {b.source}</span>
          </div>
          <div className="mt-2 flex flex-wrap items-end gap-6">
            {unmetered ? (
              <>
                <div>
                  <div className={cn("text-[30px] font-semibold leading-none tabular", over ? "text-brick-ink" : "text-ink")}>{compact(b.tokens)}</div>
                  <div className="mt-1 text-[12px] text-ink-3">tokens · {b.calls} provider calls</div>
                </div>
                <div>
                  <div className="text-[20px] font-semibold leading-none tabular text-ink">{capTokens > 0 ? compact(remainingTokens) : "—"}</div>
                  <div className="mt-1 text-[12px] text-ink-3">{capTokens > 0 ? `remaining of ${compact(capTokens)} tokens` : "no token cap recorded"}</div>
                </div>
                <div>
                  <div className="text-[20px] font-semibold leading-none tabular text-kelp-ink">{metering.label}</div>
                  <div className="mt-1 text-[12px] text-ink-3">{metering.note}{metering.dollars_estimate ? " · Pi's dollars are an estimate" : ""}</div>
                </div>
              </>
            ) : (
              <>
                <div>
                  <div className={cn("text-[30px] font-semibold leading-none tabular", over ? "text-brick-ink" : "text-ink")}>{money(b.spent_usd, 4)}</div>
                  <div className="mt-1 text-[12px] text-ink-3">spent · {b.calls} provider calls</div>
                </div>
                <div>
                  <div className="text-[20px] font-semibold leading-none tabular text-ink">{money(remaining, 4)}</div>
                  <div className="mt-1 text-[12px] text-ink-3">remaining of {money(b.cap_usd, 2)}</div>
                </div>
                <div>
                  <div className="text-[20px] font-semibold leading-none tabular text-ink">{compact(b.tokens)}</div>
                  <div className="mt-1 text-[12px] text-ink-3">tokens (in + out + cache){capTokens > 0 ? ` · cap ${compact(capTokens)}` : ""}</div>
                </div>
              </>
            )}
            {perAgentCap > 0 ? (
              <div>
                <div className={cn("text-[20px] font-semibold leading-none tabular", overOwnCount ? "text-brick-ink" : "text-ink")}>{money(perAgentCap, 2)}</div>
                <div className="mt-1 text-[12px] text-ink-3">per-agent cap{overOwnCount ? ` · ${overOwnCount} over it` : ""}</div>
              </div>
            ) : null}
          </div>
          {unmetered ? <BudgetBar spent={b.tokens} cap={Math.max(1, capTokens)} className="mt-4" compactLabel unit="tokens" /> : <BudgetBar spent={b.spent_usd} cap={b.cap_usd} className="mt-4" />}
          <div className="mt-3 flex flex-wrap gap-1.5 text-[12px]">
            <Badge variant={b.cap_steer_sent ? "saffron" : "outline"}>cap steer {b.cap_steer_sent ? "sent" : "not sent"}</Badge>
            <Badge variant={b.hard_kill ? "brick" : "outline"}>hard kill {b.hard_kill ? "on" : "off"}</Badge>
            {perAgentCap > 0 ? <Badge variant="outline">per-agent cap {money(perAgentCap, 2)}</Badge> : null}
            {modelCaps.length ? <Badge variant={modelCaps.some(([m, cap]) => (spentOn(m) ?? 0) >= cap) ? "saffron" : "outline"}>per-model caps {modelCaps.length}</Badge> : null}
            {unmetered ? <Badge variant="kelp">not metered</Badge> : null}
            {capTokens > 0 && !unmetered ? <Badge variant="outline">token cap {compact(capTokens)}</Badge> : null}
            {over ? <Badge variant="brick">{overTokens && !overUsd ? "token cap hit" : "cap hit"} — agents are told to call done cannot_complete</Badge> : null}
            {advisory && b.cap_usd > 0 && b.spent_usd >= b.cap_usd ? <Badge variant="outline">past the advisory cap: nothing is stopped for it</Badge> : null}
            {(b.token_alerts ?? []).map((mark) => (
              <Badge key={mark} variant={b.tokens >= mark ? "saffron" : "outline"} title="--token-alert: you are told once as the run crosses it (the board, the trace, your notify hook); nothing pauses or stops for it">
                token alert {compact(mark)}{b.tokens >= mark ? ": crossed" : ""}
              </Badge>
            ))}
          </div>
        </section>
        <section className="card p-4">
          <h3 className="label-caps">Wall clock</h3>
          <div className="mt-2 text-[30px] font-semibold leading-none tabular text-ink">{shortDuration(elapsedMs)}</div>
          <div className="mt-1 text-[12px] text-ink-3">{advisory || wallMs <= 0 ? "no wall clock (until solved)" : `of ${b.wall_clock_minutes} min`} · started {new Date(b.started_at).toLocaleTimeString()}</div>
          <div className="mt-4 h-1.5 w-full overflow-hidden rounded-full bg-paper-3">
            <div className={cn("h-full rounded-full", wallPct >= 100 ? "bg-saffron" : "bg-slate")} style={{ width: `${wallPct}%` }} />
          </div>
          <div className="mt-1 text-[11px] tabular text-ink-3">{Math.round(wallPct)}% of the window</div>
        </section>
      </div>

      <section className="card p-4" aria-label="Spend by model">
        <div className="flex items-baseline justify-between">
          <h3 className="label-caps">By model</h3>
          <span className="text-[12px] text-ink-3">
            {models.length} model{models.length === 1 ? "" : "s"} · from team.json
          </span>
        </div>
        {models.length ? (
          <div className="mt-3 grid gap-3 sm:grid-cols-2 lg:grid-cols-3">
            {models.map((m) => {
              return (
                <div key={m.model} className="rounded-[8px] border border-line bg-paper-2/40 p-3">
                  <div className="flex items-baseline justify-between gap-2">
                    <code className="truncate text-[12px] font-semibold text-ink" title={m.model}>
                      {m.model}
                    </code>
                    <span className="shrink-0 font-mono text-[11px] tabular text-ink-3">{shareOf(m.spent_usd, m.tokens)}</span>
                  </div>
                  {(() => {
                    const cap = b.cap_per_model_usd?.[m.model];
                    const capped = typeof cap === "number" && cap > 0 && !unmetered;
                    const overCap = capped && m.spent_usd >= cap;
                    return (
                      <>
                        <div className={cn("mt-1.5 text-[22px] font-semibold leading-none tabular", unmetered ? "text-kelp-ink" : overCap ? "text-brick-ink" : "text-ink")}>{unmetered ? metering.label : money(m.spent_usd, 4)}</div>
                        {unmetered ? (
                          <BudgetBar spent={m.tokens} cap={Math.max(1, b.tokens)} className="mt-2" compactLabel unit="tokens" />
                        ) : capped ? (
                          <>
                            <BudgetBar spent={m.spent_usd} cap={cap} className="mt-2" compactLabel />
                            <div className={cn("mt-1 text-[11.5px]", overCap ? "text-brick-ink" : "text-ink-3")}>
                              {overCap ? `over its cap of ${money(cap, 2)}: its agents are steered, then stopped` : `of its cap of ${money(cap, 2)} · ${Math.round((m.spent_usd / cap) * 100)}%`}
                            </div>
                          </>
                        ) : (
                          <BudgetBar spent={m.spent_usd} cap={Math.max(0.0001, b.spent_usd)} className="mt-2" compactLabel />
                        )}
                      </>
                    );
                  })()}
                  <div className="mt-2 font-mono text-[11.5px] tabular text-ink-2">
                    {m.calls} call{m.calls === 1 ? "" : "s"} · {compact(m.tokens)} tokens
                  </div>
                  <div className="mt-1 truncate text-[11.5px] text-ink-3" title={m.agents.join(", ")}>
                    {m.agents.length} agent{m.agents.length === 1 ? "" : "s"}: {m.agents.join(", ")}
                  </div>
                </div>
              );
            })}
          </div>
        ) : (
          <p className="m-0 mt-2 text-[12px] text-ink-3">No agent has reported a turn yet.</p>
        )}
      </section>

      <section className="card overflow-x-auto">
        <table className="w-full min-w-[720px] text-[12.5px]">
          <thead>
            <tr className="border-b border-line text-left">
              <th className="label-caps px-3 py-2">Agent</th>
              <th className="label-caps px-3 py-2 w-[220px]">Spend</th>
              <th className="label-caps px-3 py-2 text-right">Calls</th>
              <th className="label-caps px-3 py-2 text-right">Tokens</th>
              <th className="label-caps px-3 py-2 text-right">Input</th>
              <th className="label-caps px-3 py-2 text-right">Output</th>
              <th className="label-caps px-3 py-2 text-right">Cache r/w</th>
              <th className="label-caps px-3 py-2 text-right">Context</th>
              <th className="label-caps px-3 py-2 text-right">Compactions</th>
              <th className="label-caps px-3 py-2 text-right">Share</th>
            </tr>
          </thead>
          <tbody>
            {rows.map((r) => (
              <tr key={r.id} className={cn("border-b border-line last:border-0", r.marker === "dead" && "text-ink-3")}>
                <td className="px-3 py-2">
                  <span className="font-medium text-ink">{r.name}</span>
                  {r.name !== r.id ? <code className="ml-1 text-[11px] text-ink-3">{r.id}</code> : null}
                  {r.overOwn ? (
                    <Badge variant="brick" className="ml-1.5">
                      over own cap
                    </Badge>
                  ) : null}
                </td>
                <td className="px-3 py-2">
                  {unmetered ? <BudgetBar spent={r.slice?.tokens ?? 0} cap={maxTokens} compactLabel unit="tokens" /> : <BudgetBar spent={r.slice?.spent_usd ?? 0} cap={maxSpend} compactLabel />}
                </td>
                <td className="px-3 py-2 text-right tabular">{r.slice?.calls ?? 0}</td>
                <td className="px-3 py-2 text-right tabular">{compact(r.slice?.tokens ?? 0)}</td>
                <td className="px-3 py-2 text-right tabular">{compact(r.slice?.input ?? 0)}</td>
                <td className="px-3 py-2 text-right tabular">{compact(r.slice?.output ?? 0)}</td>
                <td className="px-3 py-2 text-right tabular">
                  {compact(r.slice?.cache_read ?? 0)} / {compact(r.slice?.cache_write ?? 0)}
                </td>
                <td className="px-3 py-2 text-right tabular text-ink-2">
                  {(() => {
                    // Against the ceiling the self-compaction lines are fractions of when the run had one, else the model's own window.
                    const ceiling = r.slice?.context_ceiling || r.slice?.context_window || 0;
                    return r.slice?.context_tokens && ceiling > 0 ? `${Math.round((r.slice.context_tokens / ceiling) * 100)}%` : "—";
                  })()}
                </td>
                <td className="px-3 py-2 text-right tabular text-ink-2">
                  {(() => {
                    // Hand-offs first; the total in brackets when Pi compacted on its own as well.
                    const handoffs = r.slice?.handoffs ?? 0;
                    const all = r.slice?.compactions ?? 0;
                    const usd = r.slice?.compaction_usd ?? 0;
                    if (!handoffs && !all) return "—";
                    return (
                      <>
                        {handoffs}
                        {all !== handoffs ? ` (${all})` : ""}
                        {usd > 0 ? <span className="ml-1 text-[11px] text-ink-3">{money(usd)}</span> : null}
                      </>
                    );
                  })()}
                </td>
                <td className="px-3 py-2 text-right tabular">{shareOf(r.slice?.spent_usd ?? 0, r.slice?.tokens ?? 0)}</td>
              </tr>
            ))}
            {extra.map((id) => (
              <tr key={id} className="border-b border-line last:border-0 text-ink-3">
                <td className="px-3 py-2">
                  <code>{id}</code> <Badge variant="outline">not in team</Badge>
                  {overOwnCap(id) ? (
                    <Badge variant="brick" className="ml-1.5">
                      over own cap
                    </Badge>
                  ) : null}
                </td>
                <td className="px-3 py-2" colSpan={9}>
                  {unmetered ? metering.label : money(b.agents[id].spent_usd)} · {b.agents[id].calls} calls · {compact(b.agents[id].tokens)} tokens
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </section>
      <InlineNote>
        Numbers come from each Pi session's <code>sessionManager.getEntries()</code> Usage, folded into <code>budget.json</code> on every turn end — the same fields as Pi's footer.{" "}
        {unmetered
          ? `${metering.sentence} The brake is ${capTokens > 0 ? `${compact(capTokens)} tokens` : "the wall clock alone"}${capTokens > 0 ? " and the wall clock" : ""}.`
          : "Zero means the agent has not reported a turn yet."}
        {perAgentCap > 0 ? " An agent at its own cap is steered to post and stop; the swarm goes on." : ""}
      </InlineNote>
    </div>
  );
}
