/**
 * The run's tool jobs: what the agents asked the job service to run in
 * throwaway worker VMs, read from the store's journal (store/journal.jsonl),
 * which is the record of how every object in the store came to be.
 *
 * Two things are kept apart on every row, because on a job they are not the
 * same: the outcome is what the job did (its status and exit), the record is
 * where its output stands (committed: sealed and hashed into the store). A
 * failed job's output is committed too, so "committed" never reads as a
 * success and is never drawn green.
 *
 * Nothing is cut: the list and a job's files are paged by the server, a log
 * is paged by bytes and opens whole in a tab, and every journal line about a
 * job is shown as it was written.
 */
import { useCallback, useEffect, useState } from "react";
import { ArrowLeft, Download, ExternalLink, Workflow } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Chip, PhaseHead, SerifH, type Tone } from "@/components/console";
import { HashChip } from "@/components/evidence";
import { Pager } from "@/components/pager";
import { EmptyState, ErrorState, InlineNote, LoadingState } from "@/components/states";
import { useAgentColours } from "@/lib/agent-colour";
import { api } from "@/lib/api";
import { bytes, dateTime, duration } from "@/lib/format";
import { useAgentNames } from "@/lib/hooks";
import { useResource } from "@/lib/live";
import { paginate } from "@/lib/pager";
import type { StoreJobDetail, StoreJobRow, StoreJobsView, SwarmView } from "@/lib/types";
import { cn } from "@/lib/utils";

const OUTCOME: Record<string, { label: string; tone: Tone }> = {
  ok: { label: "ok", tone: "moss" },
  failed: { label: "failed", tone: "brick" },
  timed_out: { label: "timed out", tone: "brick" },
  stopped: { label: "stopped", tone: "brick" },
  interrupted: { label: "interrupted", tone: "saffron" },
  cancelled: { label: "cancelled", tone: "neutral" },
  not_run: { label: "not run", tone: "saffron" },
  queued: { label: "queued", tone: "slate" },
  running: { label: "running", tone: "kelp" },
  pending: { label: "pending", tone: "slate" },
};

/** Where the job's output stands in the store, in words; never a verdict on the job. */
function recordLabel(row: StoreJobRow): { label: string; tone: Tone } {
  if (row.fenced === false) return { label: "worker not confirmed gone", tone: "brick" };
  switch (row.state) {
    case "accepted":
      return { label: row.attempts > 1 ? `queued, attempt ${row.attempts}` : "queued", tone: "neutral" };
    case "running":
      return { label: "in a worker", tone: "neutral" };
    case "finished":
      return { label: "finished, fencing", tone: "neutral" };
    case "fenced":
      return { label: "fenced, sealing", tone: "neutral" };
    case "committed":
      return { label: "committed (sealed)", tone: "slate" };
    case "failed":
    case "cancelled":
      return { label: "closed, nothing sealed", tone: "neutral" };
    default:
      return { label: row.state, tone: "neutral" };
  }
}

function OutcomeChip({ row }: { row: StoreJobRow }) {
  const o = OUTCOME[row.outcome] ?? { label: row.outcome, tone: "neutral" as Tone };
  // The exit beside anything but a clean one: "failed · exit 2", "timed out · exit 124".
  const exit = row.finished_at && row.outcome !== "ok" ? (row.exit === null ? " · no exit status" : ` · exit ${row.exit}`) : "";
  return (
    <Chip tone={o.tone} mono>
      {o.label}
      {exit}
    </Chip>
  );
}

function RecordChip({ row }: { row: StoreJobRow }) {
  const r = recordLabel(row);
  return (
    <Chip tone={r.tone} mono>
      {r.label}
    </Chip>
  );
}

function Fact({ label, bad, children }: { label: string; bad?: boolean; children: React.ReactNode }) {
  return (
    <div className="grid grid-cols-1 gap-1 border-t border-line py-2 sm:grid-cols-[140px_minmax(0,1fr)]">
      <span className="label-caps pt-0.5">{label}</span>
      <div className={cn("flex min-w-0 flex-col gap-1 text-[12.5px] [overflow-wrap:anywhere]", bad ? "text-brick-ink" : "text-ink-2")}>{children}</div>
    </div>
  );
}

function plural(n: number, one: string, many = `${one}s`): string {
  return `${n} ${n === 1 ? one : many}`;
}

/** A run-level journal line in words: the service's notices, a dedup answer, a repair. */
function eventLine(e: StoreJobsView["events"][number]): string {
  const who = (b: unknown) => (b && typeof b === "object" ? String((b as { name?: string; agent?: string }).name ?? (b as { agent?: string }).agent ?? "?") : String(b ?? "?"));
  switch (e.type) {
    case "job_deduplicated":
      return `${who(e.by)} asked for the same recipe over the same object and was answered with ${e.job}${e.notify ? ", to be told when it is done" : ""}`;
    case "journal_repaired":
      return `the journal was repaired on opening: ${String(e.why ?? "")}; ${String(e.dropped_bytes ?? "?")} bytes kept in ${String(e.saved_as ?? "?")}`;
    case "anchor_behind":
      return `the anchor was one step behind the journal on opening (a crash between two writes, recovered)`;
    case "anchor_mismatch":
      return `THE ANCHOR DID NOT MATCH THE JOURNAL on opening: anchor seq ${String(e.anchor_seq)}, journal seq ${String(e.journal_seq)}`;
    case "detect_bounded":
      return `${e.job}: ${String(e.offered ?? "?")} of its files were offered to the recipes; ${String(e.not_offered ?? "?")} were not`;
    default:
      return JSON.stringify(e);
  }
}

function JobsHeader({ data }: { data: StoreJobsView }) {
  const t = data.totals;
  const j = data.journal;
  const c = data.custody;
  const grew = j && c?.journal_lines !== null && c?.journal_lines !== undefined && j.lines > c.journal_lines ? j.lines - c.journal_lines : 0;
  const notices = data.events.filter((e) => e.type === "jobs_degraded" || e.type === "jobs_recovered");
  const notes = data.events.filter((e) => e.type === "note");
  const other = data.events.filter((e) => e.type !== "note" && e.type !== "jobs_degraded" && e.type !== "jobs_recovered");
  const outcomes = Object.entries(t.by_outcome).sort((a, b) => b[1] - a[1]);
  return (
    <section className="card space-y-2 p-4" aria-label="Tool jobs">
      <div className="flex flex-wrap items-center gap-2">
        <Workflow className="size-4 text-ink-3" />
        <span className="text-[14px] font-medium text-ink">Tool jobs</span>
        <Chip tone="neutral" mono>
          {plural(t.jobs, "job")}
        </Chip>
        <Chip tone="slate" mono>
          {t.committed} committed
        </Chip>
        {outcomes.map(([k, n]) => (
          <Chip key={k} tone={(OUTCOME[k] ?? { tone: "neutral" as Tone }).tone} mono>
            {n} {(OUTCOME[k] ?? { label: k }).label}
          </Chip>
        ))}
        <span className="font-mono text-[11.5px] text-ink-3">
          {plural(t.files, "file")} · {bytes(t.bytes)} sealed{t.rejected ? ` · ${t.rejected} left out (links, special files)` : ""}
          {t.generations ? ` · ${plural(t.generations, "catalogue generation")}` : ""}
        </span>
      </div>
      <p className="m-0 text-[12px] leading-[1.5] text-ink-3">
        <span className="text-ink-2">Outcome</span> is what the job did: its status and exit. <span className="text-ink-2">Record</span> is where its output stands in the store: <em>committed</em> means sealed and hashed, whatever the outcome, so a failed job's output is committed too.
      </p>
      {j ? (
        <p className={cn("m-0 font-mono text-[11.5px] [overflow-wrap:anywhere]", !j.intact || j.anchor === "off the chain" || j.anchor === "missing" ? "text-brick-ink" : "text-ink-3")}>
          {j.path} · {plural(j.lines, "line")} · {j.intact ? "chain intact" : `CHAIN BROKEN: ${j.detail}`} · {j.anchor === "matches" ? "its anchor matches" : j.anchor === "behind" ? "its anchor a step behind (the hub writing)" : j.anchor === "missing" ? "NO ANCHOR beside the run" : "ANCHOR OFF THE CHAIN"}
        </p>
      ) : null}
      {data.note ? <InlineNote tone={data.service && !j ? "danger" : "neutral"}>{data.note}</InlineNote> : null}
      {notices.map((e, i) => (
        <InlineNote key={`n${i}`} tone={e.type === "jobs_degraded" ? "warn" : "ok"}>
          {e.type === "jobs_degraded"
            ? `${dateTime(e.at)}: the job service told every agent tool jobs were not running — the last ${String(e.in_a_row ?? "?")} could not run in a worker (${e.error ?? "no error given"}), ${e.job} the last of them.`
            : `${dateTime(e.at)}: tool jobs ran again (${e.job} ran in a worker), and the agents were told.`}
        </InlineNote>
      ))}
      {notes.length ? (
        <div className="flex flex-col">
          {notes.map((e, i) => (
            <Fact key={`note${i}`} label="Examiner note">
              <span className="text-ink">{e.text}</span>
              <span className="text-ink-3">
                {String(e.by ?? "?")} · {dateTime(e.at)}
                {e.jobs?.length ? ` · on ${e.jobs.join(", ")}` : ""} · added to the journal after the run, never an edit of a line
              </span>
            </Fact>
          ))}
        </div>
      ) : null}
      <Fact label="Custody">
        {c?.line ? (
          <>
            <span className="font-mono text-[11.5px] leading-[1.55]">{c.line}</span>
            <span className="text-ink-3">
              verified {dateTime(c.at)}
              {grew ? ` · the journal has ${plural(grew, "line")} more than custody read: written after it, as an examiner's note is` : ""}
            </span>
          </>
        ) : c ? (
          `custody.json (${dateTime(c.at)}) has no store line: custody did not check a store for this run`
        ) : (
          "Custody is taken when the run stops: it re-reads the journal's chain and anchor and re-hashes every sealed file against its manifest."
        )}
      </Fact>
      {other.length ? (
        <details className="text-[12px]">
          <summary className="cursor-pointer text-ink-2">{plural(other.length, "other journal line")} about the run</summary>
          <ul className="m-0 mt-1 flex list-none flex-col gap-0.5 p-0 font-mono text-[11.5px] text-ink-2">
            {other.map((e, i) => (
              <li key={i} className="[overflow-wrap:anywhere]">
                {e.at ? `${dateTime(e.at)} · ` : ""}
                {eventLine(e)}
              </li>
            ))}
          </ul>
        </details>
      ) : null}
    </section>
  );
}

function JobsTable({ rows, colour, onOpen }: { rows: StoreJobRow[]; colour: (id: string) => string; onOpen: (id: string) => void }) {
  return (
    <div className="card overflow-x-auto">
      <table className="w-full min-w-[760px] border-collapse text-left text-[12.5px]">
        <thead>
          <tr className="border-b border-line text-ink-3">
            <th className="label-caps px-3 py-2 font-normal">Job</th>
            <th className="label-caps px-3 py-2 font-normal">What</th>
            <th className="label-caps px-3 py-2 font-normal">Asked by</th>
            <th className="label-caps px-3 py-2 font-normal" title="What the job did: its status and exit">
              Outcome
            </th>
            <th className="label-caps px-3 py-2 font-normal" title="Where its output stands in the store; committed is sealed, whatever the outcome">
              Record
            </th>
            <th className="label-caps px-3 py-2 font-normal">Took</th>
            <th className="label-caps px-3 py-2 font-normal">Output</th>
          </tr>
        </thead>
        <tbody>
          {rows.map((r) => (
            <tr key={r.id} className="cursor-pointer border-b border-line align-top last:border-b-0 hover:bg-paper-2/70" onClick={() => onOpen(r.id)}>
              <td className="px-3 py-2">
                <button type="button" className="font-mono font-semibold text-ink hover:underline" onClick={() => onOpen(r.id)}>
                  {r.id}
                </button>
                {r.attempts > 1 ? <div className="text-[11px] text-ink-3">{r.attempts} attempts</div> : null}
              </td>
              <td className="px-3 py-2">
                <span className="mr-1.5 text-[11px] uppercase tracking-[0.03em] text-ink-3">{r.kind}</span>
                <span className="font-mono text-[12px] text-ink [overflow-wrap:anywhere]">{r.what}</span>
                {r.target ? <span className="text-ink-3"> over {r.target}</span> : null}
                {r.more_lines ? <span className="text-[11px] text-ink-3"> · {plural(r.more_lines, "more line")}</span> : null}
              </td>
              <td className="px-3 py-2">
                <span className="font-medium" style={{ color: colour(r.requester.agent) }}>
                  {r.requester.name ?? r.requester.agent}
                </span>
                {r.requester.name ? <div className="font-mono text-[11px] text-ink-3">{r.requester.agent}</div> : null}
              </td>
              <td className="px-3 py-2">
                <OutcomeChip row={r} />
              </td>
              <td className="px-3 py-2">
                <RecordChip row={r} />
              </td>
              <td className="px-3 py-2 font-mono tabular text-ink-2">{r.duration_ms !== null ? duration(r.duration_ms) : "—"}</td>
              <td className="px-3 py-2 font-mono text-[11.5px] text-ink-2">
                {r.outputs ? `${plural(r.outputs.files, "file")} · ${bytes(r.outputs.bytes)}` : "—"}
                {r.outputs?.rejected ? <div className="text-ink-3">{r.outputs.rejected} left out</div> : null}
                {r.generation ? <div className="text-ink-3">catalogued {r.generation}</div> : null}
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

/** What the agent asked to run, whole, from its job_accepted line. */
function WhatItRan({ spec }: { spec: Record<string, unknown> | null }) {
  if (!spec) return <span>not in the journal</span>;
  const pre = "m-0 max-h-[40vh] overflow-auto rounded-md border border-line bg-paper-2 px-3 py-2 font-mono text-[12px] leading-[1.5] text-ink whitespace-pre-wrap [overflow-wrap:anywhere]";
  if (spec.kind === "command") return <pre className={pre}>{String(spec.command ?? "")}</pre>;
  if (spec.kind === "tool")
    return (
      <>
        <span>
          tool <span className="font-mono text-ink">{String(spec.tool)}</span> with
        </span>
        <pre className={pre}>{JSON.stringify(spec.args ?? {}, null, 2)}</pre>
      </>
    );
  if (spec.kind === "import") return <span>an import of <span className="font-mono text-ink">{String(spec.source)}</span>, copied as it was then</span>;
  if (spec.kind === "recipe")
    return (
      <>
        <span>
          recipe <span className="font-mono text-ink">{String(spec.recipe)}</span> over
        </span>
        <pre className={pre}>{JSON.stringify(spec.target ?? null, null, 2)}</pre>
      </>
    );
  return (
    <>
      <span>a detect pass ({String(spec.trigger ?? "request")}) over</span>
      <pre className={pre}>{JSON.stringify(spec.targets ?? [], null, 2)}</pre>
    </>
  );
}

const LOG_PAGE = 64 * 1024;

/** One of a job's logs, a page at a time by bytes; whole in a tab. */
function LogView({ run, job, log, version }: { run: string; job: string; log: StoreJobDetail["logs"][number]; version: number }) {
  const [offset, setOffset] = useState(0);
  const [back, setBack] = useState<number[]>([]);
  const loader = useCallback(() => api.storeJobLog(run, job, log.name, { offset, limit: LOG_PAGE }), [run, job, log.name, offset]);
  const page = useResource(log.present ? loader : null, version, [run, job, log.name, offset]);
  if (!log.present) return <InlineNote tone="warn">{log.path} is {log.why}; it is not shown.</InlineNote>;
  const p = page.data;
  return (
    <div className="space-y-2">
      <div className="flex flex-wrap items-center gap-2">
        <span className="font-mono text-[11.5px] text-ink-3">
          {log.path}
          {p ? ` · bytes ${p.total ? p.offset + 1 : 0}–${p.offset + p.bytes} of ${p.total}` : ""}
        </span>
        {log.sha256 ? <HashChip sha={log.sha256} label="sha256 in the journal" /> : null}
        <div className="ml-auto flex flex-wrap items-center gap-1">
          <Button variant="ghost" size="sm" disabled={!p || p.offset === 0} onClick={() => { setOffset(0); setBack([]); }}>
            Start
          </Button>
          <Button variant="ghost" size="sm" disabled={!back.length} onClick={() => { setOffset(back[back.length - 1] ?? 0); setBack(back.slice(0, -1)); }}>
            Earlier
          </Button>
          <Button variant="ghost" size="sm" disabled={!p || p.next === null} onClick={() => { if (p?.next !== null && p?.next !== undefined) { setBack([...back, offset]); setOffset(p.next); } }}>
            Later
          </Button>
          <Button variant="ghost" size="sm" disabled={!p || p.next === null} title="The last page; it may start inside a character" onClick={() => { if (p) { setBack([...back, offset]); setOffset(Math.max(0, p.total - LOG_PAGE)); } }}>
            End
          </Button>
          <Button asChild variant="secondary" size="sm" title="The whole log, as plain text">
            <a href={api.storeJobLogUrl(run, job, log.name)} target="_blank" rel="noopener noreferrer">
              <ExternalLink /> Whole
            </a>
          </Button>
          <Button asChild variant="ghost" size="sm">
            <a href={api.storeJobLogUrl(run, job, log.name, true)} download>
              <Download /> Download
            </a>
          </Button>
        </div>
      </div>
      {page.error && !p ? <ErrorState error={page.error} onRetry={page.reload} /> : null}
      {!p && !page.error ? <LoadingState label={`Reading ${log.name}`} rows={3} /> : null}
      {p ? (
        <pre className="card m-0 max-h-[60vh] overflow-auto px-3 py-2 font-mono text-[12px] leading-[1.5] text-ink whitespace-pre-wrap [overflow-wrap:anywhere]">
          {p.total ? p.text : <span className="italic text-ink-3">(empty)</span>}
        </pre>
      ) : null}
    </div>
  );
}

function JobDetail({ view, jobId, version, onBack }: { view: SwarmView; jobId: string; version: number; onBack: () => void }) {
  const id = view.summary.id;
  const colour = useAgentColours(view.agents);
  const names = useAgentNames(view.agents);
  const [tree, setTree] = useState<string | undefined>(undefined);
  const [size, setSize] = useState(50);
  const [wanted, setWanted] = useState(1);
  const [logName, setLogName] = useState<string | null>(null);
  useEffect(() => setWanted(1), [tree, size]);
  const loader = useCallback(() => api.storeJob(id, jobId, { tree, offset: (wanted - 1) * size, limit: size }), [id, jobId, tree, wanted, size]);
  const detail = useResource(loader, version, [id, jobId, tree, wanted, size]);
  const back = (
    <button type="button" onClick={onBack} className="inline-flex items-center gap-1 text-[12px] text-ink-2 hover:text-ink">
      <ArrowLeft className="size-3.5" /> All jobs
    </button>
  );
  if (detail.error && !detail.data) {
    return (
      <div className="space-y-3">
        {back}
        <ErrorState error={detail.error} onRetry={detail.reload} title={`Could not read ${jobId}`} />
      </div>
    );
  }
  if (!detail.data) {
    return (
      <div className="space-y-3">
        {back}
        <LoadingState label={`Reading ${jobId}`} rows={5} />
      </div>
    );
  }
  const d = detail.data;
  const r = d.row;
  const spec = (d.lines.find((l) => l.type === "job_accepted")?.spec ?? null) as Record<string, unknown> | null;
  const m = d.manifest;
  // A job that did not end well opens on what it said about it.
  const stderr = r.outcome !== "ok" ? d.logs.find((l) => l.name === "stderr.log" && l.bytes) : undefined;
  const shownLog = d.logs.find((l) => l.name === logName) ?? stderr ?? d.logs[0] ?? null;
  // The reason the service writes for a plain non-zero exit is the exit itself; said once.
  const reason = r.reason && r.reason !== `exit ${r.exit}` ? ` · ${r.reason}` : "";
  const filePage = m ? paginate(m.page.total, size, wanted) : null;
  const outcomeText = !r.ran && r.state === "failed" ? `not run: ${r.reason ?? "no reason given"}` : r.status ? `${(OUTCOME[r.status] ?? { label: r.status }).label}${r.exit !== null ? ` · exit ${r.exit}` : r.finished_at ? " · no exit status" : ""}${reason}` : `${(OUTCOME[r.outcome] ?? { label: r.outcome }).label}: not finished yet`;
  return (
    <div className="space-y-3">
      {back}
      <div className="card rounded-[10px] p-4" style={{ borderTop: `4px solid ${colour(r.requester.agent)}` }}>
        <div className="flex flex-wrap items-center gap-2.5">
          <SerifH as="h3" size={26} className="font-mono">
            {r.id}
          </SerifH>
          <Chip tone="neutral" mono>
            {r.kind}
          </Chip>
          <OutcomeChip row={r} />
          <RecordChip row={r} />
        </div>
        <p className="m-0 mt-1.5 text-[12.5px] text-ink-2 [overflow-wrap:anywhere]">
          asked by{" "}
          <span className="font-medium" style={{ color: colour(r.requester.agent) }}>
            {r.requester.name ?? names(r.requester.agent)}
          </span>{" "}
          <span className="font-mono text-ink-3">({r.requester.agent})</span>
          {r.requester.doing ? <span className="text-ink-3"> · doing {r.requester.doing}</span> : null} · {dateTime(r.accepted_at)}
          <span className="text-ink-3"> · the name and doing it had given itself then: context, not authority</span>
        </p>
        <div className="mt-2 flex flex-col">
          <Fact label="What it ran">
            <WhatItRan spec={spec} />
            {r.note ? <span className="text-ink-3">note: {r.note}</span> : null}
            {r.parent ? <span className="text-ink-3">follows job {r.parent}</span> : null}
          </Fact>
          <Fact label="Outcome" bad={r.outcome !== "ok" && r.outcome !== "queued" && r.outcome !== "running" && r.outcome !== "cancelled"}>
            {outcomeText}
          </Fact>
          <Fact label="Record" bad={r.fenced === false}>
            <span>
              {recordLabel(r).label}
              {r.committed_at ? ` at ${dateTime(r.committed_at)}` : ""}
              {r.outputs ? ` · ${r.outputs.path}/` : ""}
            </span>
            {r.fenced === true ? <span className="text-ink-3">msb said the worker was gone before a byte of its output was read</span> : null}
            {r.fenced === false ? <span>WORKER NOT CONFIRMED GONE{r.fence_error ? `: ${r.fence_error}` : ""}; its output is not sealed while it may still write</span> : null}
            {r.cancel_requested ? <span className="text-ink-3">cancel asked by {r.cancel_requested}</span> : null}
          </Fact>
          <Fact label="Times">
            {/* As the journal has them, whole: the order of steps is the record. */}
            <span className="font-mono text-[12px]">
              {[["queued", r.accepted_at], ["started", r.started_at], ["finished", r.finished_at], ["committed", r.committed_at]]
                .filter(([, t]) => t)
                .map(([k, t]) => `${k} ${t}`)
                .join(" · ")}
            </span>
            {r.duration_ms !== null || r.create_ms !== null ? (
              <span className="text-ink-3">
                {r.duration_ms !== null ? `took ${duration(r.duration_ms)} (${r.duration_ms} ms)` : ""}
                {r.create_ms !== null ? `${r.duration_ms !== null ? " · " : ""}its VM up ${r.create_ms} ms after it was asked for` : ""}
                {r.boot_retry ? ` · boot retried: ${r.boot_retry}` : ""}
              </span>
            ) : null}
          </Fact>
          {r.worker ? (
            <Fact label="Worker">
              <span className="font-mono text-[12px]">{r.worker}</span>
              <span className="text-ink-3">
                {r.worker_size ?? "size not recorded"} · image {r.image ?? "?"} · network {r.network ?? "?"}
                {r.attempts > 1 ? ` · attempt ${r.attempts}` : ""}
              </span>
            </Fact>
          ) : null}
          <Fact label="Told">
            {r.notified.length ? r.notified.map((n, i) => <span key={i}>{`${n.to} by ${n.how === "status" ? "its own job_status or job_run" : "a post"} · ${dateTime(n.at)}`}</span>) : <span>{r.state === "committed" || r.state === "failed" || r.state === "cancelled" ? "no one told yet" : "not done yet"}</span>}
            {r.deduplicated ? <span className="text-ink-3">{plural(r.deduplicated, "later request")} answered with this job</span> : null}
          </Fact>
          {r.generation ? (
            <Fact label="Catalogue">
              {r.generation} · {r.generation_status ?? "status not said"} · catalog/gen/{r.generation}/
            </Fact>
          ) : null}
          {r.kept_attempts.length ? (
            <Fact label="Kept attempts">
              {r.kept_attempts.map((a) => (
                <span key={a.path}>
                  attempt {a.attempt}: {a.status ?? "?"} · {plural(a.files, "file")} · {bytes(a.bytes)} · {a.path}/
                </span>
              ))}
            </Fact>
          ) : null}
        </div>
      </div>

      <div>
        <PhaseHead
          title="Files it wrote"
          summary={
            m?.present && m.totals
              ? `${plural(m.totals.files, "file")} · ${bytes(m.totals.bytes)}${m.sealed_at ? ` · sealed ${dateTime(m.sealed_at)}` : ""} · ${m.path}`
              : r.state === "committed"
                ? m?.path
                : "nothing sealed"
          }
        />
        {d.trees.length > 1 ? (
          <div className="mt-2 flex flex-wrap gap-1" role="group" aria-label="Sealed trees">
            {d.trees.map((t) => (
              <Button key={t} variant={(m?.tree ?? d.trees[0]) === t ? "secondary" : "ghost"} size="sm" onClick={() => setTree(t)}>
                {t === "out" ? "the result" : t}
              </Button>
            ))}
          </div>
        ) : null}
        {m ? (
          <div className="mt-2 space-y-2">
            {m.error ? <InlineNote tone="danger">{m.error}</InlineNote> : null}
            {m.sha256 ? (
              <div className="flex flex-wrap items-center gap-2 text-[12px]">
                <HashChip sha={m.sha256} label="manifest sha256" />
                {m.matches_journal === true ? <span className="text-ink-3">the sha256 its job_committed line recorded</span> : null}
                {m.matches_journal === false ? <span className="text-brick-ink">NOT THE SHA256 ITS job_committed LINE RECORDED: the manifest changed after it was sealed</span> : null}
              </div>
            ) : null}
            {m.files.length ? (
              <div className="card overflow-x-auto">
                <table className="w-full min-w-[520px] border-collapse text-left text-[12.5px]">
                  <thead>
                    <tr className="border-b border-line text-ink-3">
                      <th className="label-caps px-3 py-2 font-normal">Path</th>
                      <th className="label-caps px-3 py-2 font-normal">Bytes</th>
                      <th className="label-caps px-3 py-2 font-normal">sha256</th>
                    </tr>
                  </thead>
                  <tbody>
                    {m.files.map((f) => (
                      <tr key={f.path} className="border-b border-line align-top last:border-b-0">
                        <td className="px-3 py-1.5 font-mono text-[12px] text-ink [overflow-wrap:anywhere]">{f.path}</td>
                        <td className="px-3 py-1.5 font-mono tabular text-ink-2">{f.bytes}</td>
                        <td className="px-3 py-1.5">
                          <HashChip sha={f.sha256} />
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            ) : m.present && !m.error ? (
              <p className="m-0 text-[12.5px] text-ink-3">It wrote no file.</p>
            ) : null}
            {filePage && m.page.total ? <Pager page={filePage} onPage={setWanted} onSize={setSize} unit="files" /> : null}
            {m.rejected.length ? (
              <details className="text-[12px]" open={m.rejected.length <= 5}>
                <summary className="cursor-pointer text-ink-2">{plural(m.rejected.length, "entry", "entries")} left out, never followed</summary>
                <ul className="m-0 mt-1 flex list-none flex-col gap-0.5 p-0 font-mono text-[11.5px] text-ink-2">
                  {m.rejected.map((x) => (
                    <li key={x.path} className="[overflow-wrap:anywhere]">
                      {x.path} · {x.kind}
                      {x.link ? ` → ${x.link}` : ""}
                    </li>
                  ))}
                </ul>
              </details>
            ) : null}
          </div>
        ) : null}
      </div>

      <div>
        <PhaseHead title="What it printed" summary="stdout and stderr, whole in the store beside its output" />
        {d.logs.length ? (
          <div className="mt-2 space-y-2">
            <div className="flex flex-wrap gap-1" role="group" aria-label="Logs">
              {d.logs.map((l) => (
                <Button key={l.name} variant={shownLog?.name === l.name ? "secondary" : "ghost"} size="sm" onClick={() => setLogName(l.name)}>
                  {l.name}
                  <span className="font-mono text-[11px] opacity-60">{l.bytes !== null ? bytes(l.bytes) : l.why}</span>
                </Button>
              ))}
            </div>
            {shownLog ? <LogView key={shownLog.name} run={id} job={r.id} log={shownLog} version={version} /> : null}
          </div>
        ) : (
          <p className="m-0 mt-2 text-[12.5px] text-ink-3">{r.ran ? "No log was kept for it yet." : "It never ran, so it printed nothing."}</p>
        )}
      </div>

      <details className="card p-3 text-[12px]">
        <summary className="cursor-pointer text-ink-2">{plural(d.lines.length, "journal line")} about {r.id}, as written</summary>
        <ol className="m-0 mt-2 flex list-none flex-col gap-1 p-0">
          {d.lines.map((l, i) => (
            <li key={i} className="whitespace-pre-wrap rounded-md border border-line bg-paper-2 px-2.5 py-1.5 font-mono text-[11.5px] text-ink-2 [overflow-wrap:anywhere]">
              {JSON.stringify(l)}
            </li>
          ))}
        </ol>
      </details>
      <details className="card p-3 text-[12px]">
        <summary className="cursor-pointer text-ink-2">job.json, the service's projection of it (the journal is the record)</summary>
        {d.record_error ? <InlineNote tone="warn" className="mt-2">{d.record_error}</InlineNote> : null}
        {d.record ? <pre className="m-0 mt-2 whitespace-pre-wrap font-mono text-[11.5px] text-ink-2 [overflow-wrap:anywhere]">{JSON.stringify(d.record, null, 2)}</pre> : null}
      </details>
    </div>
  );
}

export function JobsPanel({ view, selected, onSelect, version }: { view: SwarmView; selected: string | null; onSelect: (job: string | null) => void; version: number }) {
  const id = view.summary.id;
  const colour = useAgentColours(view.agents);
  const [size, setSize] = useState(50);
  const [wanted, setWanted] = useState(1);
  useEffect(() => setWanted(1), [size]);
  const loader = useCallback(() => api.storeJobs(id, { offset: (wanted - 1) * size, limit: size }), [id, wanted, size]);
  // Not asked for while one job is open: the detail reads what it shows itself.
  const jobs = useResource(selected ? null : loader, version, [id, wanted, size, Boolean(selected)]);
  if (selected) return <JobDetail view={view} jobId={selected} version={version} onBack={() => onSelect(null)} />;
  if (jobs.error && !jobs.data) return <ErrorState error={jobs.error} onRetry={jobs.reload} title="Could not read the run's jobs" />;
  if (!jobs.data) return <LoadingState label="Reading the job journal" rows={4} />;
  const d = jobs.data;
  if (!d.service) {
    return <EmptyState icon={<Workflow />} title="No job service in this run" hint={d.note ?? undefined} />;
  }
  const page = paginate(d.page.total, size, wanted);
  return (
    <div className="space-y-3">
      <JobsHeader data={d} />
      {d.jobs.length ? (
        <>
          <JobsTable rows={d.jobs} colour={colour} onOpen={(j) => onSelect(j)} />
          <Pager page={page} onPage={setWanted} onSize={setSize} unit="jobs" />
        </>
      ) : d.journal ? (
        <EmptyState icon={<Workflow />} title="No job yet" hint="The job service is running and no agent has asked it for one." />
      ) : null}
    </div>
  );
}
