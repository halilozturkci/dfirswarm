import { hubStateCounts } from "@/lib/seat-state";
import { useCallback, useMemo, useState } from "react";
import { Link, useNavigate, useParams } from "react-router-dom";
import { ArrowLeft, Archive, Skull, Square } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Dialog, DialogContent, DialogDescription, DialogTitle } from "@/components/ui/dialog";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Switch } from "@/components/ui/switch";
import { Chip, Meter, Vital, VitalsBand } from "@/components/console";
import { EmptyState, ErrorState, InlineNote, LoadingState } from "@/components/states";
import { JobCard } from "@/components/jobs-drawer";
import { ActivityStrip } from "@/components/activity-strip";
import { TeamStrip } from "@/components/team-strip";
import { api, ApiError } from "@/lib/api";
import { compact, liveElapsed, mmss, money } from "@/lib/format";
import { useNow } from "@/lib/hooks";
import { useLive, useResource, useSwarmVersion } from "@/lib/live";
import { CHECKS_CHANGE_KINDS } from "@/lib/live-version";
import { reachedDone, stopHasWork } from "@/lib/overview-status";
import type { SwarmView } from "@/lib/types";
import { cn } from "@/lib/utils";
import { StoryPanel } from "./detail/story-panel";
import { FinishLinePanel } from "./detail/finish-line";
import { GRACE_MS, HarnessPanel, LeasesPanel, TeamPanel } from "./detail/instruments";
import { ThreadsPanel } from "./detail/threads-panel";
import { AgentsPanel } from "./detail/agents-panel";
import { TracesPanel } from "./detail/traces-panel";
import { ClaimsPanel } from "./detail/claims-panel";
import { BudgetPanel } from "./detail/budget-panel";
import { FilesPanel } from "./detail/files-panel";
import { InputsPanel } from "./detail/inputs-panel";
import { CustodyPanel } from "./detail/custody-panel";
import { VmPanel } from "./detail/vm-panel";
import { ReportPanel } from "./detail/report-panel";
import { ArtifactsPanel } from "./detail/artifacts-panel";
import { GoalPanel } from "./detail/goal-panel";
import { PacksPanel } from "./detail/packs-panel";
import { ToolsPanel } from "./detail/tools-panel";
import { LedgerPanel } from "./detail/ledger-panel";
import { JobsPanel } from "./detail/jobs-panel";
import { RecordActions } from "./detail/record-actions";
import { isolationChip } from "@/components/swarm-bits";

/**
 * Four groups, not eleven peers. The strip had grown to eleven tabs with no
 * order to it, and the evidence hashes were hidden inside `files` where
 * nobody looks for them. Grouping says what each tab is for: the run, the
 * evidence it read and produced, the frame it ran under, and the output.
 */
const TAB_GROUPS = [
  { label: "The run", tabs: ["story", "threads", "traces", "agents"] },
  { label: "Evidence", tabs: ["files", "artifacts", "jobs", "ledger"] },
  { label: "The frame", tabs: ["goal", "packs", "tools", "claims", "budget"] },
  { label: "Output", tabs: ["report", "custody"] },
] as const;
const TABS = TAB_GROUPS.flatMap((g) => g.tabs);
type Tab = (typeof TAB_GROUPS)[number]["tabs"][number];
const TAB_LABEL: Record<Tab, string> = {
  story: "Story",
  threads: "Every post",
  traces: "Raw trace",
  agents: "Agents",
  tools: "Tools",
  ledger: "Ledger",
  claims: "Claims",
  budget: "Budget",
  files: "Files",
  artifacts: "Artifacts",
  jobs: "Jobs",
  goal: "Goal",
  packs: "Packs",
  report: "Report",
  custody: "Custody",
};

function ActionBar({ view }: { view: SwarmView }) {
  const live = useLive();
  const [stopOpen, setStopOpen] = useState(false);
  const [reapOpen, setReapOpen] = useState(false);
  const [recordOpen, setRecordOpen] = useState(false);
  const [stall, setStall] = useState("90");
  const [closePanes, setClosePanes] = useState(false);
  const [jobId, setJobId] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [stopAnyway, setStopAnyway] = useState(false);
  // swarm.sh stop's own custody options: skip the host's custody check, or bound it.
  const [noCustody, setNoCustody] = useState(false);
  const [custodyTimeout, setCustodyTimeout] = useState("");
  const job = jobId ? live.jobs[jobId] ?? null : null;
  const id = view.summary.id;
  const state = view.summary.state;
  const canStop = stopHasWork(state);
  const vmRun = (view.vms ?? []).length > 0 || (view.registry?.isolation as { mode?: string } | undefined)?.mode === "microvm";
  const vm0 = view.vms?.[0];
  const hubAlive = vm0?.hub_alive ?? null;
  // The hub itself says it is putting the VMs away and taking custody. A
  // stop now waits for it before it touches anything, and custody taken
  // twice at once writes one verdict over the other: asked for on purpose,
  // never by accident. Before the hub starts, or with no hub running, Stop
  // is how the VMs get put away, and needs no guard.
  const finishingGuard = vm0?.hub_finishing === true && hubAlive === true;
  const stopBegun = vm0?.hub_stop_begun === true;
  const afterFinish = state === "finished" || state === "finish_failed";
  const stopLabel = afterFinish ? "Clean up" : state === "stop_incomplete" ? "Stop again" : "Stop swarm";
  const stopTitle = !canStop
    ? "Already stopped"
    : afterFinish
      ? "swarm.sh stop: the hub already ran it after finishing; safe to run again for anything left"
      : state === "stop_incomplete"
        ? "swarm.sh stop again: a VM of this run was still up after the last stop"
        : finishingGuard
          ? "The hub is putting the VMs away; a stop now waits for it"
          : "swarm.sh stop";

  async function run(fn: () => Promise<{ id: string }>) {
    setError(null);
    try {
      const j = await fn();
      setJobId(j.id);
    } catch (err) {
      setError(err instanceof ApiError ? err.message : (err as Error).message);
    }
  }

  return (
    <div className="flex flex-col items-end gap-2">
      <div className="flex gap-2">
        {view.summary.phase === "running" && !reachedDone(view.summary.phase) ? (
          <Button variant="secondary" size="sm" className="h-9 border-band-line bg-transparent text-band-ink hover:bg-band-2" onClick={() => setReapOpen(true)}>
            <Skull /> Reap stalled
          </Button>
        ) : null}
        <Button variant="secondary" size="sm" className="h-9 border-band-line bg-transparent text-band-ink hover:bg-band-2" onClick={() => setRecordOpen(true)} title="Hold, export, package, verify or purge this run">
          <Archive /> Record
        </Button>
        <Button
          variant="danger"
          size="sm"
          className="h-9"
          onClick={() => {
            setStopAnyway(false);
            setStopOpen(true);
          }}
          disabled={!canStop}
          title={stopTitle}
        >
          <Square className="fill-current" /> {stopLabel}
        </Button>
      </div>
      {error ? <InlineNote tone="danger">{error}</InlineNote> : null}
      {job ? (
        <div className="w-full max-w-[520px] text-left">
          <JobCard job={job} compact />
        </div>
      ) : null}

      <Dialog open={stopOpen} onOpenChange={setStopOpen}>
        <DialogContent>
          <DialogTitle>{afterFinish ? `Clean up ${view.summary.label}?` : `Stop ${view.summary.label}?`}</DialogTitle>
          <DialogDescription>
            {vmRun ? (
              <>
                Runs <code>scripts/swarm.sh stop {id}</code>: closes the Herdr workspace(s), puts each VM away ({(view.registry?.isolation as { snapshot?: boolean } | undefined)?.snapshot === false ? "removed without keeping its disk" : "its disk kept as a snapshot beside the run, then removed"}; a few minutes a VM), stops the hub and the collector, marks the registry <code>stopped</code> (<code>done</code> when the sentinel is there), then takes custody: the evidence re-hashed and the run sealed into <code>custody.json</code>. Files in the sandbox stay. This does not write <code>SWARM_DONE</code>.
              </>
            ) : (
              <>
                Runs <code>scripts/swarm.sh stop {id}</code>: closes the Herdr workspace(s), stops the collector and the netguard sidecar, marks the registry <code>stopped</code> (<code>done</code> when the sentinel is there), then takes custody: the evidence re-hashed and the run sealed into <code>custody.json</code>. Files in the sandbox stay. This does not write <code>SWARM_DONE</code>.
              </>
            )}
          </DialogDescription>
          {state === "finish_failed" ? (
            <InlineNote tone="danger">
              The hub tried to put the VMs away and failed; some may still be running. Stop puts away what is left and takes custody again; the previous <code>custody.json</code> is kept beside it, dated.
            </InlineNote>
          ) : state === "finished" ? (
            <InlineNote tone="neutral">
              The hub put the VMs away, took custody, then ran the stop itself (<code>swarm.sh stop --after-hub</code>) for the panes and the daemons. Usually nothing is left; running it again is safe, and takes custody again (the previous <code>custody.json</code> is kept beside it, dated).
            </InlineNote>
          ) : state === "stop_incomplete" ? (
            <InlineNote tone="danger">
              The last stop left a VM of this run up, and the record says <code>stop_incomplete</code>. Stop again puts away what is left; a VM that still will not go is for <code>swarm.sh reap {id}</code>, or msb itself.
            </InlineNote>
          ) : null}
          {stopBegun && !afterFinish ? <InlineNote tone="warn">A stop of this run has already begun. Another one is safe: it finds what the first has done and goes on from there.</InlineNote> : null}
          {view.summary.finishing ? (
            finishingGuard ? (
              <div className="mt-2 flex flex-col gap-2">
                <InlineNote tone="danger">
                  The hub is putting the VMs away right now: a snapshot of each disk, then removal, then custody. A stop now waits for it to finish, up to half an hour, before it closes anything, and custody taken twice at once writes one verdict over the other. Leave it to the hub unless it is stuck.
                </InlineNote>
                <label className="flex items-center justify-between gap-3 text-[13px]">
                  <span>Stop anyway, while the hub is finishing</span>
                  <Switch checked={stopAnyway} onCheckedChange={setStopAnyway} aria-label="Stop while the hub is finishing" />
                </label>
              </div>
            ) : hubAlive === false ? (
              <InlineNote tone="warn">The sentinel is written and some VMs are not put away yet, but the hub is not running, so nothing is putting them away. Stop does it.</InlineNote>
            ) : (
              <InlineNote tone="neutral">The sentinel is written; the hub puts the VMs away once every agent is out. Stopping now puts them away instead.</InlineNote>
            )
          ) : null}
          <div className="mt-3 flex flex-col gap-2 border-t border-paper-3 pt-3 text-[13px]">
            <span className="label-caps">Custody at stop</span>
            <label className="flex items-center justify-between gap-3">
              <span>
                Skip it (<code>--no-custody</code>): the run is not re-hashed or sealed now; <code>scripts/custody.ts</code> can take it later
              </span>
              <Switch checked={noCustody} onCheckedChange={setNoCustody} aria-label="Skip custody at stop" />
            </label>
            {noCustody ? (
              <InlineNote tone="warn">Without custody the record does not say whether the evidence changed during the run until someone takes it.</InlineNote>
            ) : (
              <label className="flex flex-wrap items-center justify-between gap-2">
                <span>
                  Its deadline in seconds (<code>--custody-timeout</code>); blank is the run's own
                  {(view.registry as { custody_timeout_sec?: number | string } | null)?.custody_timeout_sec !== undefined ? ` (${String((view.registry as { custody_timeout_sec?: number | string }).custody_timeout_sec)} s)` : ""}
                </span>
                <Input value={custodyTimeout} onChange={(e) => setCustodyTimeout(e.target.value.replace(/[^0-9]/g, ""))} inputMode="numeric" placeholder="the run's own" aria-label="Custody deadline in seconds" className="h-8 w-32 font-mono" />
              </label>
            )}
            {vmRun ? (
              <span className="text-[12px] text-ink-3">
                Whether each VM's disk is kept was set at kickoff ({(view.registry?.isolation as { snapshot?: boolean } | undefined)?.snapshot === false ? "--no-vm-snapshot: not kept" : "kept"}); stop has no option for it.
              </span>
            ) : null}
          </div>
          <div className="mt-4 flex justify-end gap-2">
            <Button variant="secondary" onClick={() => setStopOpen(false)}>
              Cancel
            </Button>
            <Button
              variant="danger"
              disabled={finishingGuard && !stopAnyway}
              onClick={() => {
                setStopOpen(false);
                const timeout = custodyTimeout ? Number(custodyTimeout) : undefined;
                void run(() => api.stop(id, { no_custody: noCustody, custody_timeout: noCustody ? undefined : timeout }));
              }}
            >
              <Square className="fill-current" /> {stopLabel}
            </Button>
          </div>
        </DialogContent>
      </Dialog>

      <RecordActions view={view} open={recordOpen} onOpenChange={setRecordOpen} onJob={setJobId} />

      <Dialog open={reapOpen} onOpenChange={setReapOpen}>
        <DialogContent>
          <DialogTitle>Reap stalled agents in {view.summary.label}</DialogTitle>
          <DialogDescription>
            Runs <code>scripts/swarm.sh reap {id} --stall-sec N</code>: any agent silent longer than N seconds gets <code>done/agents/&lt;id&gt;.dead</code>, its leases dropped and a <code>reap</code> trace line. Idempotent.
            {vmRun ? (
              <>
                {" "}In a VM run the hub's word on a seat comes first: a seat the hub hears from is not silent, whatever the host saw. With <code>--stop</code>, a reaped seat's VM is stopped and its disk kept, as stop would keep it.
              </>
            ) : null}
          </DialogDescription>
          <div className="mt-4 grid gap-3">
            <div className="space-y-1.5">
              <Label htmlFor="stall">Stall threshold (seconds)</Label>
              <Input id="stall" inputMode="numeric" value={stall} onChange={(e) => setStall(e.target.value)} className="w-32 tabular" />
            </div>
            <label className="flex items-center justify-between gap-3 text-[13px]">
              <span>
                {vmRun ? (
                  <>
                    Also close the agent's Herdr pane and put its VM away (<code>--stop</code>)
                  </>
                ) : (
                  <>
                    Also close the agent's Herdr pane (<code>--stop</code>)
                  </>
                )}
              </span>
              <Switch checked={closePanes} onCheckedChange={setClosePanes} />
            </label>
          </div>
          <div className="mt-4 flex justify-end gap-2">
            <Button variant="secondary" onClick={() => setReapOpen(false)}>
              Cancel
            </Button>
            <Button
              variant="warn"
              disabled={!/^\d+$/.test(stall) || Number(stall) < 1}
              onClick={() => {
                setReapOpen(false);
                void run(() => api.reap(id, { stall_sec: Number(stall), stop: closePanes }));
              }}
            >
              <Skull /> Reap now
            </Button>
          </div>
        </DialogContent>
      </Dialog>
    </div>
  );
}

export function SwarmDetailScreen() {
  const { id = "", tab: rawTab, sub } = useParams();
  const navigate = useNavigate();
  // The view reads nearly everything, so it keys on every kind. Each panel
  // keys on what its own request reads, and nothing else: a claim landing
  // while you read the trace refetches the leases in the view, not the trace
  // page. The finish line runs the goal's own shell checks, so it keys on
  // everything a check could read — which is everything but a lease and a
  // spend fold.
  const version = useSwarmVersion(id);
  const threadsVersion = useSwarmVersion(id, ["threads"]);
  const eventsVersion = useSwarmVersion(id, ["events"]);
  const historyVersion = useSwarmVersion(id, ["history"]);
  const toolsVersion = useSwarmVersion(id, ["tools"]);
  const contractVersion = useSwarmVersion(id, ["contract"]);
  const storeVersion = useSwarmVersion(id, ["store"]);
  const checksVersion = useSwarmVersion(id, CHECKS_CHANGE_KINDS);
  const loader = useCallback(() => api.swarm(id), [id]);
  const view = useResource(loader, version, [id]);
  const now = useNow(1000);
  const tab: Tab = (TABS as readonly string[]).includes(rawTab ?? "") ? (rawTab as Tab) : "story";

  const setTab = useCallback((next: string) => navigate(`/swarms/${id}/${next}`), [navigate, id]);
  const setSub = useCallback((t: Tab, s: string | null) => navigate(s ? `/swarms/${id}/${t}/${encodeURIComponent(s)}` : `/swarms/${id}/${t}`), [navigate, id]);

  const elapsedLive = useMemo(() => (view.data ? liveElapsed(view.data.summary, now) : 0), [view.data, now]);

  if (view.error && !view.data) {
    const notFound = view.error instanceof ApiError && view.error.status === 404;
    return (
      <div className="mx-auto w-full max-w-[1680px] space-y-3 px-4 py-6 sm:px-10">
        <Link to="/" className="inline-flex items-center gap-1 text-[12px] text-ink-2 hover:text-ink">
          <ArrowLeft className="size-3.5" /> Swarms
        </Link>
        {notFound ? (
          <EmptyState title={`No swarm “${id}”`} hint="It is not in runs/registry.json. It may have been started with another SWARM_RUNS_DIR, or the id is mistyped." />
        ) : (
          <ErrorState error={view.error} onRetry={view.reload} title="Could not load this swarm" />
        )}
      </div>
    );
  }
  if (!view.data) {
    return (
      <div className="mx-auto w-full max-w-[1680px] space-y-3 px-4 py-6 sm:px-10">
        <LoadingState label={`Reading ${id}`} rows={5} />
      </div>
    );
  }

  const d = view.data;
  const s = d.summary;
  const b = d.budget;
  // A team of local models is not charged: its cap is in tokens, and the
  // header measures it that way rather than showing "$0.00 of $0.00".
  const unmetered = b.metered === false;
  const capTokens = typeof b.cap_tokens === "number" && b.cap_tokens > 0 ? b.cap_tokens : 0;
  const capPct = unmetered ? (capTokens > 0 ? (b.tokens / capTokens) * 100 : 0) : s.cap_usd > 0 ? (s.spent_usd / s.cap_usd) * 100 : 0;
  const overCap = unmetered ? capTokens > 0 && b.tokens >= capTokens : s.cap_usd > 0 && s.spent_usd >= s.cap_usd;
  const wallMs = s.wall_clock_minutes * 60_000;
  const wallPct = wallMs > 0 ? (elapsedLive / wallMs) * 100 : 0;
  const overWall = wallMs > 0 && elapsedLive > wallMs;
  // In a VM run the hub's word on each seat is the live signal (a seat the
  // hub hears from is not quiet, whatever the host saw); the host's stall is
  // secondary. Without a live hub the markers decide, as in a host run.
  const hubStates = hubStateCounts(d.vms);
  const working = hubStates ? (hubStates.working ?? 0) + (hubStates.idle ?? 0) : d.agents.filter((a) => !a.done && !a.dead).length;
  const doneN = d.agents.filter((a) => a.done).length;
  const deadN = d.agents.filter((a) => a.dead).length;
  // Silent for the stall window but not reaped: in a long tool call, or idle.
  // Not dead, and the header used to say so.
  const stalledN = d.agents.filter((a) => a.stalled && !a.dead && !a.done).length;
  /** Started, never reached a marker: a provider error, a killed turn, a pane that went away. */
  const unmarkedN = d.agents.filter((a) => !a.done && !a.dead).length;
  const steeredAt = b.stop_steer_at ? Date.parse(b.stop_steer_at) : NaN;
  const steering = Number.isFinite(steeredAt) && !d.sentinel && s.phase === "running";
  const graceLeft = steering ? Math.max(0, steeredAt + GRACE_MS - now) : 0;
  const harnessStopped = reachedDone(s.phase) && d.sentinel_info?.by === "harness";

  const stateChip = steering ? (
    <Chip tone="brick" className="bg-brick text-white">
      over {b.stop_reason === "wall_clock" ? "wall clock" : "cap"} · steered
    </Chip>
  ) : s.finishing ? (
    // The sentinel is there and the hub is still putting the VMs away; the
    // list says the same, from the same predicate on the server.
    <span title="done/SWARM_DONE exists; the VMs are being snapshotted and removed, then custody runs">
      <Chip tone="moss">finishing</Chip>
    </span>
  ) : s.phase === "finish_failed" ? (
    <span title="The hub reached the end of the run and could not put every VM away. The work is done; Clean up puts away what is left.">
      <Chip tone="brick" className="bg-brick text-white">
        finish failed
      </Chip>
    </span>
  ) : s.phase === "stop_incomplete" ? (
    <span title="swarm.sh stop ran and a VM of this run was still up after it. Stop again, or reap.">
      <Chip tone="brick" className="bg-brick text-white">
        stop incomplete · a VM is still up
      </Chip>
    </span>
  ) : harnessStopped ? (
    <Chip tone="brick" className="bg-brick text-white">
      stopped by harness
    </Chip>
  ) : s.phase === "running" ? (
    <Chip tone="kelp" className="bg-kelp text-white">
      running
    </Chip>
  ) : s.phase === "done" ? (
    <Chip tone="moss" className="bg-moss text-white">
      done
    </Chip>
  ) : (
    <Chip tone="band">{s.phase}</Chip>
  );

  return (
    <div className="flex flex-col">
      <VitalsBand>
        <div className="mx-auto flex w-full max-w-[1680px] flex-col gap-5 px-4 py-[22px] sm:px-10">
          <div className="flex flex-wrap items-start justify-between gap-4">
            <div className="flex min-w-0 flex-col gap-2">
              <nav className="flex items-center gap-2 text-[12.5px] text-band-ink-2" aria-label="Breadcrumb">
                <Link to="/" className="text-band-ink-2 hover:text-band-ink">
                  Swarms
                </Link>
                <span>/</span>
                <span className="text-band-ink">{s.label}</span>
              </nav>
              <div className="flex flex-wrap items-baseline gap-3.5">
                <h1 className="serif m-0 text-[40px] leading-none">{s.label}</h1>
                <span className="font-mono text-[13px] text-band-ink-2">{s.id}</span>
                {stateChip}
                {isolationChip(s)}
                {s.hold ? (
                  <span title={s.hold.reason ?? undefined}>
                    <Chip tone="slate">on hold{s.hold.reason ? ` · ${s.hold.reason}` : ""}</Chip>
                  </span>
                ) : null}
                {view.refreshing ? <span className="text-[11px] text-band-ink-2">syncing…</span> : null}
              </div>
              {/*
                The settings this run was started with used to sit here as four
                chips — Herdr panes, hard-kill, tool forging, the inputs guard
                — in the most valuable strip on the page, and every one of them
                was already stated where it is used: the Tools tab says forging
                is on, the Harness panel says hard-kill is off, the Inputs
                panel names the guard per pane. They are now in one place that
                answers the whole question, "How this run was started" on the
                Goal tab, and the band keeps only what an operator could not
                find elsewhere: something that went wrong.
              */}
              {typeof d.layout?.split_failures === "number" && d.layout.split_failures > 0 ? (
                <div className="flex flex-wrap items-center gap-2">
                  <Chip tone="saffron">{d.layout.split_failures} pane split{d.layout.split_failures === 1 ? "" : "s"} fell back to a new tab</Chip>
                </div>
              ) : null}
              {d.custody?.verdict === "attention" ? (
                <div className="flex flex-wrap items-center gap-2">
                  <button type="button" onClick={() => setTab("custody")} title={d.custody.problems.join("\n")}>
                    <Chip tone="brick" className="bg-brick text-white">
                      custody: {d.custody.problems.length} to look at
                    </Chip>
                  </button>
                </div>
              ) : null}
            </div>
            <ActionBar view={d} />
          </div>
          {/* The numbers and the team, side by side. The strip spent a week
              under the title, which left the right half of the band empty at
              every width and made a box of names look like the subject of the
              page. The three vitals are what an operator watches; the team is
              what they look up. Both fit the band, neither dominates it. */}
          <div className="grid items-start gap-x-8 gap-y-5 lg:grid-cols-[minmax(0,560px)_minmax(0,1fr)]">
          <div className="grid gap-x-8 gap-y-4 sm:grid-cols-3">
          <Vital
            label={unmetered ? "Tokens / cap" : "Spend / cap"}
            value={unmetered ? compact(b.tokens) : money(s.spent_usd, 2)}
            tail={
              unmetered
                ? capTokens > 0
                  ? `of ${compact(capTokens)}${overCap ? ` · ${(capPct / 100).toFixed(1)}×` : ""}`
                  : "no token cap"
                : overCap
                  ? `of ${money(s.cap_usd, 2)} · ${(capPct / 100).toFixed(1)}×`
                  : `of ${money(s.cap_usd, 2)}`
            }
            tone={overCap ? "brick" : capPct >= 80 ? "saffron" : undefined}
            meter={<Meter pct={capPct} tone={overCap ? "brick" : capPct >= 80 ? "saffron" : "kelp"} onDark label={unmetered ? "tokens against cap" : "spend against cap"} />}
            sub={
              unmetered
                ? overCap
                  ? `${compact(b.tokens - capTokens)} tokens over the cap`
                  : `free · no metered cost${capTokens > 0 ? ` · ${compact(capTokens - b.tokens)} left` : ""}`
                : overCap
                  ? `${money(s.spent_usd - s.cap_usd)} over the cap`
                  : `${money(Math.max(0, s.cap_usd - s.spent_usd), 2)} left of ${money(s.cap_usd, 2)}`
            }
          />
          <Vital
            label={reachedDone(s.phase) ? "Took" : "Wall clock"}
            value={mmss(elapsedLive)}
            tail={wallMs ? `of ${mmss(wallMs)}` : undefined}
            tone={overWall ? "saffron" : undefined}
            meter={<Meter pct={wallPct} tone={overWall ? "saffron" : "band"} onDark label="elapsed against wall clock" />}
          />
          <Vital
            label="Agents"
            // The denominator is the point. A finished run used to read
            // "6 done" when ten agents had started: four of them had ended a
            // provider error or a terminated turn away from a marker, and the
            // header counted only the ones that made it. A reader cannot tell
            // 6 of 6 from 6 of 10, and on the BelkaCTF run the difference was
            // two dead providers.
            value={`${reachedDone(s.phase) ? doneN : working} of ${d.agents.length}`}
            tail={
              reachedDone(s.phase)
                ? `done${unmarkedN ? ` · ${unmarkedN} unfinished` : ""}${deadN ? ` · ${deadN} dead` : ""}`
                : hubStates
                  ? `live, by the hub: ${Object.entries(hubStates).map(([k, n]) => `${n} ${k}`).join(" · ")}${deadN ? ` · ${deadN} dead` : ""}`
                  : `working · ${doneN} done${deadN ? ` · ${deadN} dead` : ""}${stalledN ? ` · ${stalledN} quiet` : ""}`
            }
            sub={`${compact(s.tokens)} tokens · ${compact(s.calls)} calls${hubStates && stalledN ? ` · host saw ${stalledN} quiet` : ""}`}
          />
          </div>
          {/* Who is doing this, not which identifiers were passed to Pi. */}
          <TeamStrip view={d} />
          </div>

          {/*
            The sections, in the band rather than on the paper. Navigation is
            chrome: it belonged with the run's own identity, not at the top of
            the reader's page, where it took four rows of the most-read area
            and pushed the work itself below the fold. Here it is one row, the
            groups separated by a rule instead of by four labels that looked
            like tabs nobody could click.
          */}
          <div className="-mb-[6px] flex flex-wrap items-center gap-x-1 gap-y-2 pt-1" role="tablist" aria-label="Swarm sections">
            {TAB_GROUPS.map((group, gi) => (
              <div key={group.label} className="flex flex-wrap items-center gap-1" role="group" aria-label={group.label}>
                {gi > 0 ? <span aria-hidden className="mx-2 h-4 w-px bg-band-line" /> : null}
                {group.tabs.map((t) => (
                  <button
                    key={t}
                    type="button"
                    role="tab"
                    aria-selected={tab === t}
                    title={group.label}
                    onClick={() => setTab(t)}
                    className={cn(
                      "h-[30px] rounded-full px-3 text-[12.5px] font-medium transition-colors",
                      tab === t ? "bg-band-ink text-band" : "text-band-ink-2 hover:bg-band-2 hover:text-band-ink",
                    )}
                  >
                    {TAB_LABEL[t]}
                    <span className="ml-1 font-mono text-[11px] opacity-60">
                      {t === "threads" && d.threads.length ? d.threads.reduce((a, th) => a + th.posts, 0) : ""}
                      {t === "traces" ? s.calls : ""}
                      {t === "claims" && d.violations.length ? d.violations.length : ""}
                      {t === "artifacts" && d.work.length ? d.work.length : ""}
                      {t === "tools" && d.tools.length ? d.tools.length : ""}
                      {t === "ledger" && d.ledger?.entries.length ? d.ledger.entries.length : ""}
                    </span>
                  </button>
                ))}
              </div>
            ))}
          </div>
        </div>
      </VitalsBand>

      {steering ? (
        <section className="border-b border-line bg-card">
          <div className="mx-auto grid w-full max-w-[1680px] items-center gap-6 px-4 py-6 sm:px-10 lg:grid-cols-[minmax(0,1fr)_220px]">
            <div className="flex flex-col gap-3.5">
              <div className="flex flex-wrap items-baseline gap-4">
                <span className="serif text-[56px] leading-none text-brick-ink tabular">{mmss(graceLeft)}</span>
                <span className="serif text-[26px] leading-[1.1] text-ink">
                  until the harness writes <span className="font-mono text-[20px]">done/SWARM_DONE</span> itself
                </span>
              </div>
              <div className="grid grid-cols-[auto_minmax(0,1fr)_auto] items-center gap-3.5">
                <div className="flex flex-col gap-0.5">
                  <span className="label-caps">steered</span>
                  <span className="font-mono text-[13px]">{new Date(steeredAt).toLocaleTimeString()}</span>
                </div>
                <Meter pct={((GRACE_MS - graceLeft) / GRACE_MS) * 100} tone="brick" className="h-2.5" label="grace period" />
                <div className="flex flex-col gap-0.5 text-right">
                  <span className="label-caps">sentinel</span>
                  <span className="font-mono text-[13px]">{new Date(steeredAt + GRACE_MS).toLocaleTimeString()}</span>
                </div>
              </div>
              <p className="m-0 max-w-[720px] text-[13.5px] leading-[1.5] text-ink-2 [text-wrap:pretty]">
                Every agent was told to call <span className="font-mono">done(cannot_complete)</span> and has not. One clock for the whole swarm: the grace period is measured from the same instant by every agent, and only one of them will create the sentinel.
              </p>
            </div>
            <div className="text-[11.5px] text-ink-3">
              Stop now with the button above, or raise the cap from the shell — <span className="font-mono">budget.json</span> is re-read every 15 s and a raised cap clears the clock.
            </div>
          </div>
        </section>
      ) : null}

      <div className="mx-auto grid w-full max-w-[1680px] gap-7 px-4 py-[26px] sm:px-10 lg:grid-cols-[minmax(0,1fr)_440px]">
        <section className="flex min-w-0 flex-col gap-3.5">
          {tab === "story" ? <StoryPanel view={d} version={threadsVersion} /> : null}
          {tab === "threads" ? <ThreadsPanel view={d} selected={sub ? decodeURIComponent(sub) : null} onSelect={(t) => setSub("threads", t)} version={threadsVersion} /> : null}
          {tab === "traces" ? <TracesPanel view={d} version={eventsVersion} initialAgent={sub ? decodeURIComponent(sub) : undefined} /> : null}
          {tab === "agents" ? (
            <div className="space-y-4">
              <VmPanel view={d} />
              <AgentsPanel view={d} selected={sub ? decodeURIComponent(sub) : null} onSelect={(a) => setSub("agents", a)} version={eventsVersion} />
            </div>
          ) : null}
          {tab === "claims" ? <ClaimsPanel view={d} now={now} /> : null}
          {tab === "budget" ? <BudgetPanel view={d} elapsedMs={elapsedLive} /> : null}
          {tab === "custody" ? <CustodyPanel view={d} /> : null}
          {tab === "files" ? (
            <div className="space-y-4">
              <InputsPanel view={d} />
              <FilesPanel view={d} selected={sub ? decodeURIComponent(sub) : null} onSelect={(p) => setSub("files", p)} version={historyVersion} />
            </div>
          ) : null}
          {tab === "artifacts" ? <ArtifactsPanel view={d} selected={sub ? decodeURIComponent(sub) : null} onSelect={(p) => setSub("artifacts", p)} /> : null}
          {tab === "goal" ? <GoalPanel view={d} version={contractVersion} /> : null}
          {tab === "tools" ? <ToolsPanel view={d} selected={sub ? decodeURIComponent(sub) : null} onSelect={(t) => setSub("tools", t)} version={toolsVersion} /> : null}
          {tab === "packs" ? <PacksPanel view={d} /> : null}
          {tab === "jobs" ? <JobsPanel view={d} selected={sub ? decodeURIComponent(sub) : null} onSelect={(j) => setSub("jobs", j)} version={storeVersion} /> : null}
          {tab === "ledger" ? <LedgerPanel view={d} /> : null}
          {tab === "report" ? <ReportPanel view={d} /> : null}
        </section>

        <aside className="flex flex-col gap-4">
          <FinishLinePanel view={d} version={checksVersion} />
          <LeasesPanel view={d} now={now} />
          <TeamPanel view={d} onSelect={(a) => setSub("agents", a)} />
          <HarnessPanel view={d} now={now} onShowTraces={() => setTab("traces")} />
        </aside>
      </div>

      {/* the rhythm of the whole run, always in view */}
      <div className="sticky bottom-0 z-30 border-t border-line bg-card/95 backdrop-blur supports-[backdrop-filter]:bg-card/85">
        <div className="mx-auto w-full max-w-[1680px] px-4 py-2 sm:px-10">
          <ActivityStrip series={d.activity} />
        </div>
      </div>
    </div>
  );
}
