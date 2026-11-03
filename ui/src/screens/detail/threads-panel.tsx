/**
 * Every post, thread by thread.
 *
 * The list: an ORDER / SHOW bar, then one row per thread with the primary
 * thread marked and badged, a pulse line (a lane per agent while the team is
 * small, ticks when it is not) with the message count at its end, the
 * agents who posted with their call counts, and the latest post as a two-line
 * preview. Opening a thread lifts it into an overlay: the compute budget,
 * the members, SHOW ALL / PREVIEW / RAW, and every post with its size.
 */
import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { ArrowDownToLine, Hash, MessageSquareOff, ShieldAlert } from "lucide-react";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Dialog, DialogContent, DialogDescription, DialogTitle } from "@/components/ui/dialog";
import { Input } from "@/components/ui/input";
import { ThreadPulse } from "@/components/activity-strip";
import { Meter, tagTone, type Tone } from "@/components/console";
import { EmptyState, ErrorState, LoadingState } from "@/components/states";
import { DarkThreadMark } from "@/components/swarm-bits";
import { BoardAnalytics } from "./board-analytics";
import { useAgentColours } from "@/lib/agent-colour";
import { api } from "@/lib/api";
import { chars, clock, eventTime, money, relTime, shortDuration } from "@/lib/format";
import { useAgentNames } from "@/lib/hooks";
import { useResource } from "@/lib/live";
import { reachedDone } from "@/lib/overview-status";
import type { AgentRow, SwarmEvent, SwarmView, ThreadRow, TimedPost } from "@/lib/types";
import { meteringWords } from "@/lib/metering";
import { cn } from "@/lib/utils";

/** One colour per tag everywhere: the same table the story and the chips use. */
function tagVariant(tag: string): Exclude<Tone, "band"> {
  const tone = tagTone(tag);
  return tone === "band" ? "neutral" : tone;
}

type Order = "activity" | "created" | "volume" | "members";
type Show = "all" | "active" | "dormant";
type Mode = "preview" | "all" | "raw";
type Row = { kind: "post"; post: TimedPost; at: number; badge?: string } | { kind: "violation"; event: SwarmEvent; at: number };

function markOf(agent: AgentRow | undefined): string {
  if (!agent) return "·";
  return agent.done ? "✓" : agent.dead || agent.stalled ? "?" : "●";
}

/** The first two lines of a post, for the list's preview. */
/** A post on one line: its whitespace folded, nothing cut (the row clamps it on screen and carries the whole in its title). */
function preview(body: string): string {
  return body.replace(/\s+/g, " ").trim();
}

function SegBar<T extends string>({ label, value, options, onChange }: { label: string; value: T; options: Array<[T, string]>; onChange: (v: T) => void }) {
  return (
    <div className="flex items-center gap-3 font-mono text-[11.5px] uppercase tracking-[0.04em]" role="group" aria-label={label}>
      <span className="font-semibold text-ink">{label}</span>
      {options.map(([key, text]) => (
        <button
          key={key}
          type="button"
          aria-pressed={value === key}
          onClick={() => onChange(key)}
          className={cn("border-b-2 pb-px", value === key ? "border-brick text-brick-ink" : "border-transparent text-ink-3 hover:text-ink")}
        >
          {text}
        </button>
      ))}
    </div>
  );
}

function PostBody({ body, mode, forced }: { body: string; mode: Mode; forced: boolean | null }) {
  const [open, setOpen] = useState(false);
  const expanded = forced ?? open;
  const long = body.length > 240 || body.split("\n").length > 2;
  const folded = !expanded && long;
  return (
    <div>
      <pre className={cn("m-0 whitespace-pre-wrap break-words text-[13px] leading-[1.5] text-ink", mode === "raw" ? "font-mono text-[12px]" : "font-sans", folded && "max-h-[2.95rem] overflow-hidden")}>{body}</pre>
      {long ? (
        <button type="button" className="mt-1 font-mono text-[11px] text-ink-3 hover:text-ink" onClick={() => setOpen((o) => !o)}>
          {expanded ? "▾ collapse" : `▸ ${chars(body)}`}
        </button>
      ) : null}
    </div>
  );
}

function ThreadLine({ t, view, colour, names, onOpen }: { t: ThreadRow; view: SwarmView; colour: (id: string) => string; names: (id: string) => string; onOpen: () => void }) {
  const primary = t.name === "main";
  const s = view.summary;
  // Who is on this thread: the members it declares, plus anyone who posted;
  // the primary thread is the whole team. Ordered by who moved last.
  const roster = useMemo(() => {
    const ids = new Set<string>(primary ? view.agents.map((a) => a.id) : t.members ?? []);
    for (const d of t.activity) if (d.from !== "system") ids.add(d.from);
    return [...ids]
      .map((id) => ({ id, agent: view.agents.find((a) => a.id === id) }))
      .sort((a, b) => (b.agent?.last_event_at ?? "").localeCompare(a.agent?.last_event_at ?? ""));
  }, [primary, view.agents, t.members, t.activity]);
  const last = t.activity[t.activity.length - 1];
  return (
    <button
      type="button"
      onClick={onOpen}
      className={cn("card flex w-full flex-col gap-2 rounded-[10px] p-3 text-left transition-colors hover:bg-paper-2/70", t.dim && "thread-dark")}
    >
      <div className="grid grid-cols-[minmax(0,1fr)] items-center gap-3 sm:grid-cols-[240px_minmax(0,1fr)_40px]">
        <span className="flex min-w-0 items-center gap-2">
          <span className={cn("thread-title inline-flex items-center gap-1.5 truncate font-mono text-[13px] font-semibold uppercase tracking-[0.03em]", primary ? "text-brick-ink" : "text-ink-2")}>
            {primary ? <span aria-hidden>◆</span> : <Hash className="size-3.5 text-ink-3" />}
            {primary ? "Primary thread" : t.name}
          </span>
          {primary ? (
            reachedDone(s.phase) ? (
              <span className="rounded-[3px] bg-moss px-1.5 font-mono text-[10px] font-semibold uppercase text-white">done</span>
            ) : s.phase === "running" ? (
              <span className="rounded-[3px] border border-moss px-1.5 font-mono text-[10px] font-semibold uppercase text-moss-ink">running</span>
            ) : null
          ) : null}
          {t.dim ? <DarkThreadMark /> : null}
        </span>
        <ThreadPulse dots={t.activity} from={s.started_at || null} to={s.finished_at} colour={colour} names={names} lanes={roster.map((r) => r.id)} />
        <span className="text-right font-mono text-[12px] tabular text-ink-3">{t.posts}</span>
      </div>
      {roster.length ? (
        <div className="flex flex-wrap items-center gap-1.5">
          <span className="label-caps mr-1">Agents:</span>
          {roster.map((m) => (
            <span
              key={m.id}
              className={cn("inline-flex h-6 items-center gap-1.5 rounded-md border px-2 font-mono text-[11.5px] tabular", m.agent?.dead || m.agent?.stalled ? "border-dashed border-line-2 opacity-60" : "border-line")}
              title={`${m.id} · ${m.agent?.calls ?? 0} tool calls · ${money(m.agent?.spent_usd ?? 0)}`}
            >
              <span style={{ color: colour(m.id) }}>{markOf(m.agent)}</span>
              <span className="font-medium" style={{ color: colour(m.id) }}>
                {names(m.id)}
              </span>
              <span className="text-ink-3">{m.agent?.calls ?? 0}</span>
            </span>
          ))}
        </div>
      ) : null}
      {last ? (
        <div
          className="line-clamp-2 border-l-2 pl-2.5 font-mono text-[12px] leading-[1.45] text-ink-2"
          style={{ borderColor: colour(last.from) }}
          title={t.last_from === last.from && view.summary.last_post && t.name === "main" ? `${names(last.from)}: ${view.summary.last_post.body}` : undefined}
        >
          <span className="font-semibold" style={{ color: colour(last.from) }}>
            {names(last.from)}:
          </span>{" "}
          {t.last_from === last.from && view.summary.last_post && t.name === "main" ? preview(view.summary.last_post.body) : `${last.tag} · ${relTime(last.at)}`}
        </div>
      ) : (
        <span className="text-[12px] text-ink-3">empty — nobody has posted here</span>
      )}
      <div className="flex flex-wrap items-center gap-x-3 text-[11px] text-ink-3">
        {t.opened_by ?? t.created_by ? <span>by {names(t.opened_by ?? t.created_by ?? "")}</span> : null}
        {t.created_at ? <span>created {clock(t.created_at)}</span> : null}
        {t.last_at ? <span>last {relTime(t.last_at)}</span> : null}
        {t.purpose ? <span className="truncate">{t.purpose}</span> : null}
      </div>
    </button>
  );
}

function ThreadOverlay({ view, thread, version, onClose }: { view: SwarmView; thread: ThreadRow; version: number; onClose: () => void }) {
  const id = view.summary.id;
  const loader = useCallback(() => api.thread(id, thread.name), [id, thread.name]);
  const posts = useResource(loader, version, [id, thread.name]);
  const names = useAgentNames(view.agents);
  const colour = useAgentColours(view.agents);
  const [mode, setMode] = useState<Mode>("preview");
  const [newestFirst, setNewestFirst] = useState(false);
  const [showSystem, setShowSystem] = useState(true);
  const [follow, setFollow] = useState(true);
  const [q, setQ] = useState("");
  const scroller = useRef<HTMLDivElement | null>(null);
  const prevCount = useRef(0);
  // Posts that were already on the board when the overlay opened do not flash.
  const seenAtOpen = useRef<number | null>(null);
  if (seenAtOpen.current === null && posts.data) seenAtOpen.current = Math.max(0, ...posts.data.map((p) => p.id));
  const primary = thread.name === "main";
  const b = view.budget;

  const rows = useMemo<Row[]>(() => {
    const needle = q.trim().toLowerCase();
    const out: Row[] = (posts.data ?? [])
      .filter((p) => !needle || `${p.from} ${p.to} ${p.tag} ${p.body}`.toLowerCase().includes(needle))
      .map((p) => ({ kind: "post", post: p, at: p.at ? Date.parse(p.at) : 0 }));
    if (primary && !needle && view.goal_document) {
      // The starting prompt is the oldest post on the primary thread.
      const at = Date.parse(view.summary.started_at);
      out.push({ kind: "post", badge: "goal / starting prompt", at: Number.isFinite(at) ? at : 0, post: { id: 0, thread: "main", from: "system", to: "all", tag: "intro", body: `MISSION — the starting prompt for this swarm.\n\n${view.goal_document}`, path: "", at: view.summary.started_at || null } });
    }
    if (showSystem && primary && !needle) {
      for (const e of view.violations) out.push({ kind: "violation", event: e, at: Date.parse(eventTime(e)) });
    }
    out.sort((a, b2) => a.at - b2.at || (a.kind === "post" && b2.kind === "post" ? a.post.id - b2.post.id : 0));
    return newestFirst ? out.reverse() : out;
  }, [posts.data, view.violations, view.goal_document, view.summary.started_at, showSystem, primary, q, newestFirst]);

  const jumpLatest = useCallback(() => {
    const el = scroller.current;
    if (!el) return;
    el.scrollTo({ top: newestFirst ? 0 : el.scrollHeight, behavior: "smooth" });
  }, [newestFirst]);

  useEffect(() => {
    if (follow && prevCount.current > 0 && rows.length > prevCount.current) jumpLatest();
    prevCount.current = rows.length;
  }, [rows.length, follow, jumpLatest]);

  const roster = useMemo(() => {
    const ids = new Set<string>(thread.members ?? []);
    for (const p of posts.data ?? []) ids.add(p.from);
    if (primary) ids.add("system");
    return [...ids].sort();
  }, [thread.members, posts.data, primary]);

  return (
    <Dialog open onOpenChange={(open) => (open ? undefined : onClose())}>
      <DialogContent className="flex max-h-[88vh] max-w-[1100px] flex-col gap-0 overflow-hidden border-t-4 border-t-brick p-0">
        <div className="flex flex-col gap-3 px-5 pb-3 pt-4">
          <div>
            <DialogTitle className={cn("serif text-[30px] font-normal leading-none", primary ? "text-brick-ink" : "text-ink")}>{primary ? "Primary thread" : `#${thread.name}`}</DialogTitle>
            <DialogDescription className="mt-1.5 font-mono text-[12px] text-ink-3">
              {primary ? "public" : `${thread.members?.length ?? 0} member${thread.members?.length === 1 ? "" : "s"}`} · created by {names(thread.opened_by ?? thread.created_by ?? "system")} | {clock(thread.created_at ?? view.summary.started_at)} | {posts.data ? `${posts.data.length} message${posts.data.length === 1 ? "" : "s"}` : "…"}
              {thread.purpose ? ` — ${thread.purpose}` : ""}
            </DialogDescription>
          </div>
          <div className="grid grid-cols-[auto_120px_minmax(0,1fr)] items-center gap-3 rounded-md border border-saffron/40 bg-saffron-soft/40 px-3 py-2 font-mono text-[12px] tabular">
            <span className="label-caps">Compute budget</span>
            <Meter
              pct={b.metered === false ? ((b.cap_tokens ?? 0) > 0 ? (b.tokens / (b.cap_tokens ?? 1)) * 100 : 0) : b.cap_usd > 0 ? (b.spent_usd / b.cap_usd) * 100 : 0}
              tone={(b.metered === false ? (b.cap_tokens ?? 0) > 0 && b.tokens >= (b.cap_tokens ?? 0) : b.spent_usd >= b.cap_usd && b.cap_usd > 0) ? "brick" : "saffron"}
              label="compute budget"
            />
            <span className="truncate text-saffron-ink">
              {b.metered === false
                ? `${meteringWords(b).label} · ${b.tokens.toLocaleString()} tokens${(b.cap_tokens ?? 0) > 0 ? ` of ${(b.cap_tokens ?? 0).toLocaleString()}` : ""} | ${meteringWords(b).note}`
                : `${money(Math.max(0, b.cap_usd - b.spent_usd), 2)} left of ${money(b.cap_usd, 2)} | ${money(b.spent_usd)} spent | ${b.tokens.toLocaleString()} tokens`}
            </span>
          </div>
          <div className="flex flex-wrap items-center gap-x-2.5 gap-y-1">
            <span className="label-caps mr-1">Members</span>
            {roster.map((m) => (
              <span key={m} className="font-mono text-[12px] font-medium" style={{ color: colour(m) }}>
                +{names(m)}
              </span>
            ))}
          </div>
          <div className="flex flex-wrap items-center justify-between gap-2 border-t border-line pt-2.5">
            <span className="label-caps">Thread</span>
            <div className="flex flex-wrap items-center gap-2 text-[12px]">
              <div className="inline-flex rounded-md border border-line p-0.5" role="group" aria-label="View mode">
                <button type="button" aria-pressed={mode === "all"} onClick={() => setMode((m) => (m === "all" ? "preview" : "all"))} className={cn("h-6 rounded px-2.5 font-mono text-[11px] font-medium uppercase tracking-[0.03em]", mode === "all" ? "bg-brick text-white" : "text-ink-2 hover:text-ink")}>
                  {mode === "all" ? "Collapse all" : "Show all"}
                </button>
                <button type="button" aria-pressed={mode === "preview"} onClick={() => setMode("preview")} className={cn("h-6 rounded px-2.5 font-mono text-[11px] font-medium uppercase tracking-[0.03em]", mode === "preview" ? "bg-ink text-paper" : "text-ink-2 hover:text-ink")}>
                  Preview
                </button>
                <button type="button" aria-pressed={mode === "raw"} onClick={() => setMode("raw")} className={cn("h-6 rounded px-2.5 font-mono text-[11px] font-medium uppercase tracking-[0.03em]", mode === "raw" ? "bg-ink text-paper" : "text-ink-2 hover:text-ink")}>
                  Raw
                </button>
              </div>
              <button type="button" onClick={() => setNewestFirst((n) => !n)} className="font-mono text-[11px] uppercase tracking-[0.03em] text-ink-2 hover:text-ink">
                {newestFirst ? "newest first" : "oldest first"}
              </button>
              {primary && view.violations.length ? (
                <label className="inline-flex items-center gap-1.5 text-ink-2">
                  <input type="checkbox" checked={showSystem} onChange={(e) => setShowSystem(e.target.checked)} className="accent-kelp" />
                  guard rows
                </label>
              ) : null}
              <Button size="sm" variant={follow ? "secondary" : "ghost"} onClick={() => setFollow((f) => !f)} title="Keep the newest message in view">
                <ArrowDownToLine /> {follow ? "Following" : "Follow"}
              </Button>
              <Input value={q} onChange={(e) => setQ(e.target.value)} placeholder="find in thread…  ( / )" className="h-7 w-[200px] rounded-md font-mono text-[12px]" aria-label="Find in this thread" data-find />
            </div>
          </div>
        </div>

        <div ref={scroller} className="relative min-h-0 flex-1 overflow-y-auto border-t border-line bg-paper px-5 py-3">
          {posts.error && !posts.data ? <ErrorState error={posts.error} onRetry={posts.reload} /> : null}
          {posts.loading && !posts.data ? <LoadingState label="Reading posts" rows={4} /> : null}
          {posts.data && rows.length === 0 ? (
            q ? <EmptyState title="Nothing matches" hint="Try another word; the search reads sender, tag and body." /> : <EmptyState icon={<MessageSquareOff />} title="Thread is empty" hint="Nobody has posted here yet." />
          ) : null}
          {rows.length ? (
            <ol className="flex flex-col" aria-label="Messages">
              {rows.map((row) =>
                row.kind === "post" ? (
                  <li key={`p${row.post.id}-${row.badge ?? ""}`} className={cn("grid grid-cols-[86px_minmax(0,1fr)] gap-3 border-b border-line/70 py-2.5 last:border-b-0", seenAtOpen.current !== null && row.post.id > seenAtOpen.current && "post-fresh")}>
                    <span className="pt-0.5 font-mono text-[11px] tabular text-ink-3" title={row.post.at ?? ""}>
                      {clock(row.post.at)}
                    </span>
                    <div className="min-w-0 border-l-[3px] pl-3" style={{ borderColor: colour(row.post.via ?? row.post.from) }}>
                      <div className="flex flex-wrap items-center gap-x-2 gap-y-1 text-[12px]">
                        {row.badge ? (
                          <span className="rounded-[3px] bg-brick px-1.5 font-mono text-[10px] font-semibold uppercase text-white">{row.badge}</span>
                        ) : row.post.from === "system" && row.post.via ? (
                          // A seat's harness code in its VM: the seat's word, never the harness's.
                          <span className="rounded-[3px] border border-line px-1.5 font-mono text-[10px] font-semibold uppercase text-ink-2" title={`Harness code in ${row.post.via}'s VM posted this with that seat's authority, not the harness's`}>
                            via {row.post.via}
                          </span>
                        ) : row.post.from === "system" ? (
                          <span className="rounded-[3px] bg-brick px-1.5 font-mono text-[10px] font-semibold uppercase text-white">harness</span>
                        ) : null}
                        <span className="font-mono font-semibold" style={{ color: colour(row.post.via ?? row.post.from) }}>
                          {row.post.from === "system" && row.post.via ? `system via ${names(row.post.via)}` : names(row.post.from)}
                        </span>
                        {row.badge ? null : <Badge variant={tagVariant(row.post.tag)}>{row.post.tag}</Badge>}
                        {row.badge ? null : <span className="text-ink-3">→ {row.post.to}</span>}
                        <span className="ml-auto font-mono text-[11px] text-ink-3">{row.badge ? "" : `#${row.post.id}`}</span>
                      </div>
                      {mode === "raw" ? <pre className="mt-1 font-mono text-[11px] leading-[1.5] text-ink-3">{`---\nid: ${row.post.id}\nthread: ${row.post.thread}\nfrom: ${row.post.from}\nto: ${row.post.to}\ntag: ${row.post.tag}\n---`}</pre> : null}
                      <div className="mt-1">
                        <PostBody body={row.post.body} mode={mode} forced={mode === "all" ? true : null} />
                      </div>
                    </div>
                  </li>
                ) : (
                  <li key={`v${row.event.ts}${row.event.agent}`} className="grid grid-cols-[86px_minmax(0,1fr)] gap-3 border-b border-line/70 py-2.5">
                    <span className="pt-0.5 font-mono text-[11px] tabular text-ink-3">{clock(row.event.ts)}</span>
                    <div className="min-w-0 border-l-[3px] border-brick pl-3 text-[12.5px]">
                      <div className="flex flex-wrap items-center gap-x-2 text-[12px]">
                        <span className="rounded-[3px] bg-brick px-1.5 font-mono text-[10px] font-semibold uppercase text-white">harness</span>
                        <span className="font-mono font-semibold text-brick-ink">system</span>
                        <ShieldAlert className="size-3.5 text-brick" />
                      </div>
                      <p className="m-0 mt-1 text-ink">
                        ⚠ CLAIM VIOLATION: {names(row.event.agent)} tried <code>{String(row.event.args.tool ?? "write")}</code> on <code>{String(row.event.args.path ?? "?")}</code> without holding the lease
                        {typeof (row.event.result as { owner?: string })?.owner === "string" ? <> (held by {names((row.event.result as { owner: string }).owner)})</> : null}.{" "}
                        {(row.event.result as { via?: string } | null)?.via === "bash" ? "A shell write cannot be intercepted; the change was snapshotted and is undoable via file_history / file_restore." : "The write guard blocked it."}
                      </p>
                    </div>
                  </li>
                ),
              )}
            </ol>
          ) : null}
          {rows.length ? <p className="m-0 py-3 text-center font-mono text-[11px] text-ink-3">— member telemetry is per agent (open an agent); a post carries no link to the tool calls around it —</p> : null}
          {rows.length > 3 ? (
            <div className="pointer-events-none sticky bottom-1 flex justify-end">
              <button type="button" className="pointer-events-auto rounded-md bg-brick px-3 py-1.5 font-mono text-[11.5px] font-semibold uppercase tracking-[0.04em] text-white shadow-md hover:bg-brick-ink" onClick={() => { setFollow(true); jumpLatest(); }}>
                ▲ Latest
              </button>
            </div>
          ) : null}
        </div>
      </DialogContent>
    </Dialog>
  );
}

export function ThreadsPanel({
  view,
  selected,
  onSelect,
  version,
}: {
  view: SwarmView;
  selected: string | null;
  onSelect: (thread: string) => void;
  version: number;
}) {
  const [order, setOrder] = useState<Order>("activity");
  const [show, setShow] = useState<Show>("all");
  const names = useAgentNames(view.agents);
  const colour = useAgentColours(view.agents);

  const threads = useMemo(() => {
    const list = view.threads.filter((t) => (show === "all" ? true : show === "active" ? !t.dim : t.dim));
    const by: Record<Order, (a: ThreadRow, b: ThreadRow) => number> = {
      activity: (a, b) => (b.last_at ?? "").localeCompare(a.last_at ?? ""),
      created: (a, b) => (a.created_at ?? "").localeCompare(b.created_at ?? ""),
      volume: (a, b) => b.posts - a.posts,
      members: (a, b) => (b.members?.length ?? 0) - (a.members?.length ?? 0),
    };
    // The primary thread stays on top whatever the order; it is the board.
    return list.sort((a, b) => (a.name === "main" ? -1 : b.name === "main" ? 1 : by[order](a, b) || a.name.localeCompare(b.name)));
  }, [view.threads, order, show]);

  const open = selected ? view.threads.find((t) => t.name === selected) ?? null : null;

  if (!view.threads.length) {
    return <EmptyState icon={<MessageSquareOff />} title="No threads yet" hint="threads/main appears with the first post. Agents can open more threads by name; empty ones go dark." />;
  }

  return (
    <div className="flex flex-col gap-3">
      <div className="flex flex-wrap items-center justify-between gap-3">
        <SegBar
          label="Order"
          value={order}
          onChange={setOrder}
          options={[
            ["activity", "Activity"],
            ["created", "Created"],
            ["volume", "Volume"],
            ["members", "Members"],
          ]}
        />
        <SegBar
          label="Show"
          value={show}
          onChange={setShow}
          options={[
            ["all", "All"],
            ["active", "Active"],
            ["dormant", "Dormant"],
          ]}
        />
      </div>
      {threads.length === 0 ? <EmptyState title={`No ${show} threads`} hint="Change the filter to see the rest." /> : null}
      <div className="flex flex-col gap-2">
        {threads.map((t) => (
          <ThreadLine key={t.name} t={t} view={view} colour={colour} names={names} onOpen={() => onSelect(t.name)} />
        ))}
      </div>
      <p className="m-0 text-[11px] leading-[1.45] text-ink-3">
        A thread goes dark after {shortDuration(2 * 60_000)} idle or on a hold / veto / stop tag. Chip numbers are each agent's tool calls over the whole run; open a thread for its posts.
      </p>
      <BoardAnalytics view={view} version={version} onOpenThread={onSelect} />
      {open ? <ThreadOverlay view={view} thread={open} version={version} onClose={() => onSelect("")} /> : null}
    </div>
  );
}
