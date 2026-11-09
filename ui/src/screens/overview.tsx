import { useCallback, useMemo, useState } from "react";
import { Link } from "react-router-dom";
import { ChevronRight, Layers, Plus } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Chip, FinishMeter, Meter, StatusDot, VitalsBand } from "@/components/console";
import { isolationChip } from "@/components/swarm-bits";
import { EmptyState, ErrorState, LoadingState } from "@/components/states";
import { api } from "@/lib/api";
import { compact, dateTime, liveElapsed, money, providerGlyph, shortDuration } from "@/lib/format";
import { useNow } from "@/lib/hooks";
import { useLive, useResource } from "@/lib/live";
import type { SwarmRow } from "@/lib/types";
import { meteringWords } from "@/lib/metering";
import { cn } from "@/lib/utils";
import { harnessStopLabel, isCertifiedDone, isHarnessStop, phaseGroup, reachedDone } from "@/lib/overview-status";

type Filter = "all" | "running" | "done" | "stopped";

/** The four numbers that say whether anything is wrong right now. */
function FleetBand({ rows }: { rows: SwarmRow[] }) {
  const running = rows.filter((r) => r.phase === "running");
  const working = running.reduce((a, r) => a + Math.max(0, r.agents_total - r.agents_done - r.agents_dead), 0);
  const done = rows.reduce((a, r) => a + r.agents_done, 0);
  const dead = rows.reduce((a, r) => a + r.agents_dead, 0);
  // A run on local models is not charged; it neither spends nor has a USD
  // cap to count, and saying "$0.00 of $0.00" about it would be a lie twice.
  const metered = rows.filter((r) => r.metered !== false);
  const free = rows.length - metered.length;
  const subscribed = rows.filter((r) => r.metered === false && r.unmetered_why === "subscription").length;
  const spent = metered.reduce((a, r) => a + r.spent_usd, 0);
  const cap = metered.reduce((a, r) => a + r.cap_usd, 0);
  const violations = rows.reduce((a, r) => a + r.violations, 0);
  const capStops = rows.filter((r) => isHarnessStop(r)).length;
  // A VM run's own vitals: how many agents are in VMs right now, and whose
  // hub is down with nothing to bring it back (its agents fail closed).
  const vmRunning = running.filter((r) => r.isolation === "microvm");
  const vmsUp = vmRunning.reduce((a, r) => a + Math.max(0, r.agents_total - r.agents_done - r.agents_dead), 0);
  const hubsDown = vmRunning.filter((r) => r.hub_down === true).length;
  const cell = (label: string, big: string, tail: string, last = false) => (
    <div className={cn("flex min-w-0 flex-col gap-1 py-1 pr-7", !last && "border-r border-band-line", label !== "Running now" && "pl-7")}>
      <span className="label-caps text-band-ink-2">{label}</span>
      <span className="serif text-[44px] leading-none tabular">
        {big} <span className="text-[20px] text-band-ink-2">{tail}</span>
      </span>
    </div>
  );
  return (
    <VitalsBand>
      <div className="mx-auto grid w-full max-w-[1680px] grid-cols-2 gap-y-5 px-4 py-[26px] sm:px-10 lg:grid-cols-4" aria-label="Fleet vitals">
        {cell("Running now", String(running.length), `of ${rows.length} swarm${rows.length === 1 ? "" : "s"}`)}
        {cell("Agents working", String(working), `· ${done} done · ${dead} dead${vmRunning.length ? ` · ${vmsUp} in VMs${hubsDown ? ` · ${hubsDown} hub${hubsDown === 1 ? "" : "s"} DOWN` : ""}` : ""}`)}
        {cell("Spend across the fleet", money(spent, 2), `of ${money(cap, 2)} in caps${free ? ` · ${free - subscribed ? `${free - subscribed} unmetered` : ""}${free - subscribed && subscribed ? ", " : ""}${subscribed ? `${subscribed} on a subscription` : ""}` : ""}`)}
        {cell("Harness interventions", String(violations + capStops), `· ${violations} blocked · ${capStops} cap stop${capStops === 1 ? "" : "s"}`, true)}
      </div>
    </VitalsBand>
  );
}

/** Over whichever cap applies: dollars on a metered run, tokens on a free one (or as a second brake). */
function overCapOf(row: SwarmRow): boolean {
  const usd = row.metered !== false && row.cap_usd > 0 && row.spent_usd >= row.cap_usd;
  const tokens = row.cap_tokens > 0 && row.tokens >= row.cap_tokens;
  return usd || tokens;
}

function statusChip(row: SwarmRow, now: number) {
  if (row.phase === "running") return <Chip tone="kelp">running · {shortDuration(liveElapsed(row, now))}</Chip>;
  // Before the harness-stop chip: whoever wrote the sentinel, what is
  // happening now is the hub putting the VMs away, or having failed to.
  if (row.finishing) return <Chip tone="moss">finishing · the hub is putting the VMs away</Chip>;
  if (row.phase === "finish_failed") return <Chip tone="brick">finish failed · the hub could not put the VMs away</Chip>;
  if (row.phase === "stop_incomplete") return <Chip tone="brick">stop incomplete · a VM is still up after the stop</Chip>;
  if (isHarnessStop(row)) return <Chip tone="brick">{harnessStopLabel(row)}</Chip>;
  if (row.phase === "done") return <Chip tone="moss">done</Chip>;
  if (row.phase === "stopped") return <Chip tone="neutral">stopped</Chip>;
  if (row.phase === "prepared") return <Chip tone="slate">prepared · not launched</Chip>;
  if (row.phase === "failed") return <Chip tone="brick">failed · the kickoff did not get its agents running</Chip>;
  return <Chip tone="neutral">{row.phase}</Chip>;
}

function SwarmLine({ row, now }: { row: SwarmRow; now: number }) {
  const overCap = overCapOf(row);
  const free = row.metered === false;
  const metering = meteringWords(row);
  const pct = free ? (row.cap_tokens > 0 ? (row.tokens / row.cap_tokens) * 100 : 0) : row.cap_usd > 0 ? (row.spent_usd / row.cap_usd) * 100 : 0;
  const certified = isCertifiedDone(row);
  const last = row.last_post;
  return (
    <Link
      to={`/swarms/${row.id}`}
      className={cn("console-row", row.phase === "running" && "border-kelp shadow-[0_0_0_3px_var(--color-kelp-soft)]")}
    >
      <StatusDot phase={row.finishing ? "finishing" : row.phase === "finish_failed" || row.phase === "stop_incomplete" ? row.phase : isHarnessStop(row) ? "stopped" : row.phase} />
      <div className="flex min-w-0 flex-col gap-1.5">
        <div className="flex flex-wrap items-center gap-2.5">
          <span className="serif text-[22px] leading-[1.1]">{row.label}</span>
          <span className="font-mono text-[12px] text-ink-3">{row.id}</span>
          {statusChip(row, now)}
          {isolationChip(row)}
          {row.hub_down ? <Chip tone="brick">hub down · the agents fail closed</Chip> : null}
          {row.custody ? <Chip tone={row.custody === "clean" ? "moss" : "brick"}>custody {row.custody === "clean" ? "clean" : "needs attention"}</Chip> : null}
          {row.hold ? (
            <span title={row.hold.reason ?? undefined}>
              <Chip tone="slate">on hold{row.hold.reason ? ` · ${row.hold.reason}` : ""}</Chip>
            </span>
          ) : null}
          <Chip tone="neutral">{row.agents_total} agent{row.agents_total === 1 ? "" : "s"}</Chip>
          {row.model ? (
            <span
              className={cn(
                "inline-flex h-6 max-w-[420px] items-center rounded-full px-2.5 font-mono text-[11.5px] font-medium",
                row.model.includes("+") ? "bg-slate-soft text-slate-ink" : "bg-paper-2 text-ink-2",
              )}
              title={row.model}
            >
              <span className="mr-1.5 shrink-0" aria-hidden>
                {providerGlyph(row.model)}
              </span>
              <span className="truncate">{row.model}</span>
            </span>
          ) : null}
          {row.violations ? <Chip tone="saffron">{row.violations} harness post{row.violations === 1 ? "" : "s"}</Chip> : null}
        </div>
        {/* the second line: the counts that say how much has happened */}
        <div className="flex flex-wrap items-center gap-x-3 gap-y-0.5 font-mono text-[11.5px] tabular text-ink-3">
          {row.started_at ? <span title={row.started_at}>{dateTime(row.started_at)}</span> : null}
          <span>
            {row.threads_total} thread{row.threads_total === 1 ? "" : "s"}
          </span>
          <span>{row.posts_total} msgs</span>
          <span>{compact(row.calls)} calls</span>
          <span>{compact(row.tokens)} tok</span>
        </div>
        <div className="truncate text-[13px] text-ink-2" title={last ? `${last.from} · ${last.tag} · ${last.body}` : undefined}>
          {last ? (
            <>
              <span className={cn("font-mono", last.from === "system" ? "text-brick-ink" : "text-kelp-ink")}>{last.from}</span>
              <span className="text-ink-3"> · {last.tag} · </span>
              {last.body}
            </>
          ) : row.goal ? (
            <span className="text-ink-3">nothing on the board yet · {row.goal.split("\n").find((l) => l.trim() && !l.startsWith("#")) ?? ""}</span>
          ) : (
            <span className="italic text-ink-3">no goal recorded</span>
          )}
        </div>
      </div>
      <div className="console-cell flex flex-col gap-1.5">
        <FinishMeter passed={certified ? row.checks_total : 0} total={row.checks_total} pendingTone={row.phase === "running" ? "saffron" : "neutral"} />
        <span className="text-[12.5px] text-ink-2">
          {row.checks_total === 0 ? "no checks · sentinel only" : certified ? `${row.checks_total} of ${row.checks_total} checks · certified` : `${row.checks_total} check${row.checks_total === 1 ? "" : "s"} · ${row.phase === "running" ? "in progress" : "not certified"}`}
        </span>
      </div>
      <div className="console-cell flex flex-col gap-1.5">
        <Meter pct={pct} tone={overCap ? "brick" : reachedDone(row.phase) ? "moss" : "kelp"} />
        <span className={cn("text-[12.5px]", overCap ? "text-brick-ink" : "text-ink-2")}>
          {free ? (
            <>
              {metering.label} · <span className="font-mono">{compact(row.tokens)}</span> of {row.cap_tokens > 0 ? `${compact(row.cap_tokens)} tokens` : "no token cap"} · {overCap ? "over cap" : row.cap_tokens > 0 ? `${Math.round(pct)}%` : "local"}
            </>
          ) : (
            <>
              <span className="font-mono">{money(row.spent_usd, 2)}</span> of {money(row.cap_usd, 2)} · {overCap ? "over cap" : `${Math.round(pct)}%`}
            </>
          )}
        </span>
      </div>
      <span className="console-cell font-mono text-[13px] text-ink-2">{shortDuration(liveElapsed(row, now))}</span>
      <ChevronRight className="console-cell size-[18px] text-ink-3" />
    </Link>
  );
}

export function OverviewScreen() {
  const live = useLive();
  const loader = useCallback(() => api.swarms(), []);
  const swarms = useResource(loader, live.globalVersion);
  // The elapsed column ticks on the client; the list itself refetches only
  // when something on disk changed.
  const now = useNow(15_000);
  const [filter, setFilter] = useState<Filter>("all");
  const [query, setQuery] = useState("");

  const rows = useMemo(() => {
    const all = swarms.data ?? [];
    const q = query.trim().toLowerCase();
    return all
      .filter((r) => {
        if (filter !== "all" && phaseGroup(r.phase) !== filter) return false;
        if (q && !`${r.id} ${r.label} ${r.model} ${r.goal} ${r.last_post?.body ?? ""} ${r.last_post?.from ?? ""}`.toLowerCase().includes(q)) return false;
        return true;
      })
      // Running first; within a group, the newest start on top. The old
      // comparison returned early whenever `a` was running, so two live
      // swarms were never ordered against each other.
      .sort((a, b) => Number(b.phase === "running") - Number(a.phase === "running") || (a.started_at < b.started_at ? 1 : a.started_at > b.started_at ? -1 : 0));
  }, [swarms.data, filter, query]);

  const counts = useMemo(() => {
    const all = swarms.data ?? [];
    return {
      all: all.length,
      running: all.filter((r) => phaseGroup(r.phase) === "running").length,
      done: all.filter((r) => phaseGroup(r.phase) === "done").length,
      stopped: all.filter((r) => phaseGroup(r.phase) === "stopped").length,
    };
  }, [swarms.data]);

  if (swarms.error && !swarms.data) {
    return (
      <div className="mx-auto w-full max-w-[1680px] px-4 py-6 sm:px-10">
        <ErrorState error={swarms.error} onRetry={swarms.reload} title="Could not load the swarm list" />
      </div>
    );
  }
  if (!swarms.data) {
    return (
      <div className="mx-auto w-full max-w-[1680px] px-4 py-6 sm:px-10">
        <LoadingState label="Reading registry" rows={4} />
      </div>
    );
  }

  return (
    <div className="flex flex-col">
      <FleetBand rows={swarms.data} />
      <div className="mx-auto flex w-full max-w-[1680px] flex-col gap-3.5 px-4 py-[26px] sm:px-10">
        <div className="flex flex-wrap items-center justify-between gap-3">
          <div className="flex flex-wrap gap-1.5" role="tablist" aria-label="Status filter">
            {(
              [
                ["all", "All"],
                ["running", "Running"],
                ["done", "Done"],
                ["stopped", "Stopped"],
              ] as Array<[Filter, string]>
            ).map(([key, label]) => (
              <button
                key={key}
                type="button"
                role="tab"
                aria-selected={filter === key}
                onClick={() => setFilter(key)}
                className={cn(
                  "h-8 rounded-full border px-3 text-[13px] font-medium transition-colors",
                  filter === key ? "border-ink bg-ink text-paper" : "border-line bg-transparent text-ink-2 hover:text-ink",
                )}
              >
                {label} · {counts[key]}
              </button>
            ))}
            {swarms.error ? <span className="ml-2 self-center text-[12px] text-brick-ink">Refresh failed: {swarms.error.message}</span> : null}
          </div>
          <div className="flex items-center gap-3">
            <span className="font-mono text-[12px] tabular text-ink-3">
              {counts.all} swarm{counts.all === 1 ? "" : "s"} | {counts.running} live
            </span>
            <Input
              value={query}
              onChange={(e) => setQuery(e.target.value)}
              placeholder="find a signal…  ( / )"
              className="h-8 w-[260px] rounded-lg font-mono text-[12.5px]"
              aria-label="Find a swarm by id, label, model or goal"
              data-find
            />
          </div>
        </div>

        <div className="console-row !bg-transparent !border-0 !py-0 hidden md:grid">
          <span />
          <span className="label-caps">Swarm · what it is doing</span>
          <span className="label-caps console-cell">Finish line</span>
          <span className="label-caps console-cell">Spend / cap</span>
          <span className="label-caps console-cell">Took</span>
          <span />
        </div>

        {swarms.data.length === 0 ? (
          <EmptyState
            icon={<Layers />}
            title="Quiet field"
            hint={
              <>
                No signal yet — nothing in <code>runs/registry.json</code>. Kick a swarm off here or run <code>scripts/swarm.sh start</code>.
              </>
            }
            action={
              <Button asChild>
                <Link to="/new">
                  <Plus /> Kick off a swarm
                </Link>
              </Button>
            }
          />
        ) : rows.length === 0 ? (
          <EmptyState title="No swarms match" hint="Try another status filter or clear the search." />
        ) : (
          rows.map((row) => <SwarmLine key={row.id} row={row} now={now} />)
        )}
      </div>
    </div>
  );
}
