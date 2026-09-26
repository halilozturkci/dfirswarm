/**
 * The ledger: what the agents put on record with `record`, straight from
 * ledger/entries.jsonl. The timeline is the events in time order; the
 * indicators, the findings and the searches that found nothing follow.
 *
 * The rendering is the report vocabulary rather than markup local to this
 * screen, so a claim looks the same here as it does on the handover and in
 * `report.html`. That matters for one reason in particular: an entry missing
 * its source or its evidence is marked in both places, because the harness's
 * rule is that an entry nobody can check is not a record, and a panel that
 * quietly dropped the empty column would hide exactly the thing worth seeing.
 *
 * Around the entries, three things only a person or the trace can add:
 * - the examiner's review, per entry (accept, reject, amend with a note) and a
 *   signature over the ledger as it stands, kept outside the run and chained;
 * - whether the trace grounds an entry: a call before it named its source;
 * - a correction (`supersedes`): the older entry stays, marked, and links to
 *   the one that corrects it. Nothing is ever hidden.
 *
 * Version 3 of the ledger adds two kinds — a hypothesis with its status, a
 * limitation with its reason — and typed fields the agents used to write in
 * prose: the goal section an entry answers (filterable here), its links to
 * other entries (a standing contradiction is said at the top), a sensitive
 * mark, the clock and precision of a time, observed or inferred, how far a
 * search got, an attribution, locators and a correction's reason.
 */
import { useCallback, useEffect, useMemo, useState, type ReactNode } from "react";
import { BookOpenText } from "lucide-react";
import { Chip } from "@/components/console";
import { Pager, usePager } from "@/components/pager";
import { EmptyState, InlineNote } from "@/components/states";
import { Button } from "@/components/ui/button";
import {
  FindingCard,
  IndicatorTable,
  NotRecorded,
  ReportCounts,
  TimelineTable,
  isCited,
  type Author,
  type ClaimRecord,
} from "@/components/report";
import { api } from "@/lib/api";
import { useAgentColours } from "@/lib/agent-colour";
import { useAgentNames } from "@/lib/hooks";
import { useResource, useSwarmVersion } from "@/lib/live";
import type { Coverage, LedgerEntry, ReviewAction, ReviewState, SwarmView } from "@/lib/types";
import { cn } from "@/lib/utils";

type Kind = "all" | LedgerEntry["kind"];
const KINDS: Array<{ key: Kind; label: string }> = [
  { key: "all", label: "All" },
  { key: "event", label: "Events" },
  { key: "ioc", label: "Indicators" },
  { key: "finding", label: "Findings" },
  { key: "absence", label: "Searched, not found" },
  { key: "hypothesis", label: "Hypotheses" },
  { key: "limitation", label: "Limitations" },
];

const REL_WORD = { supports: "supports", contradicts: "contradicts", duplicates: "duplicates", derived_from: "derived from" } as const;
const STATUS_TONE = { open: "neutral", supported: "moss", refuted: "brick" } as const;
/** "Q3" and "3" are the same section. */
const sectionId = (a: string) => a.trim().replace(/^q(?=\d)/i, "");

const REVIEW_TONE = { accept: "moss", reject: "brick", amend: "saffron" } as const;
const EXAMINER_KEY = "dfirswarm.examiner";

function savedExaminer(): string {
  try {
    return window.localStorage.getItem(EXAMINER_KEY) ?? "";
  } catch {
    return "";
  }
}

export function LedgerPanel({ view }: { view: SwarmView }) {
  const id = view.summary.id;
  const entries = useMemo(() => view.ledger?.entries ?? [], [view.ledger]);
  const names = useAgentNames(view.agents);
  const colour = useAgentColours(view.agents);
  const chosenOf = useMemo(() => {
    const map = new Map<string, string>();
    for (const n of view.names ?? []) map.set(n.id, n.name);
    return (who: string) => map.get(who);
  }, [view.names]);
  const [kind, setKind] = useState<Kind>("all");
  const [query, setQuery] = useState("");
  const [question, setQuestion] = useState("");
  const version = useSwarmVersion(id, ["ledger", "events"]);
  const [reviewNonce, setReviewNonce] = useState(0);
  const reviewLoader = useCallback(() => api.review(id), [id]);
  const review = useResource<ReviewState>(reviewLoader, version + reviewNonce, [id, "review"]);
  const coverageLoader = useCallback(() => api.coverage(id), [id]);
  const coverage = useResource<Coverage>(coverageLoader, version, [id, "coverage"]);

  const supersededBy = useMemo(() => {
    const map = new Map<number, number>();
    for (const e of entries) if (typeof e.supersedes === "number") map.set(e.supersedes, e.seq);
    return map;
  }, [entries]);

  const authorsFor = useCallback(
    (c: ClaimRecord): Author[] => (c.authors ?? []).map((who) => ({ id: who, name: names(who), chosen: chosenOf(who), colour: colour(who) })),
    [names, chosenOf, colour],
  );

  const [examiner, setExaminer] = useState(savedExaminer);
  useEffect(() => {
    try {
      if (examiner) window.localStorage.setItem(EXAMINER_KEY, examiner);
    } catch {
      // private window: the name is typed again next time
    }
  }, [examiner]);
  const [pending, setPending] = useState<string | null>(null);
  const [actionError, setActionError] = useState<string | null>(null);
  const [noteFor, setNoteFor] = useState<{ seq: number; action: "reject" | "amend" } | null>(null);
  const [note, setNote] = useState("");

  const send = useCallback(
    async (action: ReviewAction, seq?: number, text?: string) => {
      setActionError(null);
      if (!examiner.trim()) {
        setActionError("Name the examiner first: the review is signed with it.");
        return;
      }
      setPending(action === "sign" ? "sign" : `${action}:${seq}`);
      try {
        let job = await api.sendReview(id, { action, entry_seq: seq, note: text, examiner: examiner.trim() });
        // The write is a swarm.sh job; wait for it, then read the review again.
        for (let i = 0; i < 60 && job.status === "running"; i++) {
          await new Promise((r) => setTimeout(r, 500));
          job = await api.job(job.id);
        }
        if (job.status !== "ok") setActionError((job.stderr || job.stdout || `the review job ended ${job.status}`).trim());
        setNoteFor(null);
        setNote("");
        setReviewNonce((n) => n + 1);
      } catch (err) {
        setActionError(err instanceof Error ? err.message : String(err));
      } finally {
        setPending(null);
      }
    },
    [id, examiner],
  );

  const grounding = coverage.data?.grounding ?? {};
  const bySeq = useMemo(() => new Map(entries.map((e) => [e.seq, e])), [entries]);
  const marks = useCallback(
    (c: ClaimRecord): ReactNode => {
      const out: ReactNode[] = [];
      const e = bySeq.get(c.seq);
      if (typeof c.supersedes === "number") out.push(<Chip key="corrects" tone="slate">corrects #{c.supersedes}{e?.because ? `: ${e.because}` : ""}</Chip>);
      // The typed fields of version 3, each a chip a reader can scan.
      if (e?.status) out.push(<Chip key="status" tone={STATUS_TONE[e.status]}>{e.status}</Chip>);
      if (e?.reason) out.push(<Chip key="reason" tone="brick">{e.reason.replace("_", " ")}</Chip>);
      if (e?.sensitive) out.push(<span key="sens" title="It, or what it cites, holds a credential, a key or personal data: a package made with --redact replaces it."><Chip tone="brick">sensitive</Chip></span>);
      for (const a of e?.answers ?? [])
        out.push(
          <button key={`q${a}`} type="button" className="contents" onClick={() => setQuestion(sectionId(a))} title="Show the entries for this section">
            <Chip tone="kelp">answers {a}</Chip>
          </button>,
        );
      for (const r of e?.rel ?? [])
        out.push(
          <a key={`rel${r.kind}${r.to}`} href={`#ledger-${r.to}`} className="no-underline">
            <Chip tone={r.kind === "contradicts" ? "saffron" : "slate"}>{REL_WORD[r.kind]} #{r.to}</Chip>
          </a>,
        );
      if (e?.basis) out.push(<Chip key="basis" tone="neutral">{e.basis}</Chip>);
      if (e?.completion && e.completion !== "complete") out.push(<Chip key="completion" tone="saffron">search {e.completion}</Chip>);
      if (e?.clock) out.push(<span key="clock" className="text-[11.5px] text-ink-2 [overflow-wrap:anywhere]">clock: {e.clock}</span>);
      if (e?.precision) out.push(<span key="precision" className="text-[11.5px] text-ink-3">precision: {e.precision === "date" ? "a date only" : e.precision}</span>);
      if (e?.attribution)
        out.push(
          <span key="attr" className="text-[11.5px] text-ink-2 [overflow-wrap:anywhere]">
            attributed to {e.attribution.subject} ({e.attribution.subject_type}){e.attribution.basis_refs?.length ? `, on ${e.attribution.basis_refs.join(", ")}` : ""}
          </span>,
        );
      if (e?.locators?.length) out.push(<span key="loc" className="font-mono text-[11px] text-ink-3 [overflow-wrap:anywhere]">at {e.locators.map((l) => `${l.ref} ${l.at}`).join("; ")}</span>);
      const by = supersededBy.get(c.seq);
      if (by !== undefined)
        out.push(
          <a key="superseded" href={`#ledger-${by}`} className="no-underline">
            <Chip tone="saffron">superseded by #{by}</Chip>
          </a>,
        );
      const g = grounding[String(c.seq)];
      if (g === "not in the trace") out.push(<span key="g" title="No call before this entry named its source: the trace does not show where the agent read it."><Chip tone="saffron">not grounded in the trace</Chip></span>);
      const r = review.data?.by_entry[String(c.seq)];
      if (r) {
        out.push(
          <span key="r" title={r.note ?? undefined}>
            <Chip tone={REVIEW_TONE[r.action]}>
              {r.action === "accept" ? "accepted" : r.action === "reject" ? "rejected" : "amended"} by {r.examiner}
            </Chip>
          </span>,
        );
        if (r.note) out.push(<span key="rn" className="text-[11.5px] text-ink-2 [overflow-wrap:anywhere]">“{r.note}”</span>);
      }
      out.push(
        <span key="actions" className="inline-flex flex-wrap gap-1">
          <button type="button" className="rounded border border-line px-1.5 text-[11px] text-ink-2 hover:text-ink disabled:opacity-50" disabled={pending !== null} onClick={() => void send("accept", c.seq)}>
            accept
          </button>
          <button type="button" className="rounded border border-line px-1.5 text-[11px] text-ink-2 hover:text-ink disabled:opacity-50" disabled={pending !== null} onClick={() => setNoteFor({ seq: c.seq, action: "reject" })}>
            reject…
          </button>
          <button type="button" className="rounded border border-line px-1.5 text-[11px] text-ink-2 hover:text-ink disabled:opacity-50" disabled={pending !== null} onClick={() => setNoteFor({ seq: c.seq, action: "amend" })}>
            amend…
          </button>
        </span>,
      );
      if (noteFor?.seq === c.seq) {
        out.push(
          <span key="note" className="flex w-full flex-wrap items-center gap-1">
            <input
              value={note}
              onChange={(e) => setNote(e.target.value)}
              placeholder={noteFor.action === "reject" ? "why it is rejected" : "what the examiner corrects"}
              aria-label={`${noteFor.action} note for exhibit ${c.seq}`}
              className="h-[24px] min-w-[180px] flex-1 rounded-[6px] border border-line bg-paper px-2 text-[12px]"
            />
            <button type="button" className="rounded border border-ink bg-ink px-1.5 text-[11px] text-paper disabled:opacity-50" disabled={!note.trim() || pending !== null} onClick={() => void send(noteFor.action, c.seq, note.trim())}>
              {noteFor.action}
            </button>
            <button type="button" className="text-[11px] text-ink-3" onClick={() => setNoteFor(null)}>
              cancel
            </button>
          </span>,
        );
      }
      return <span id={`ledger-${c.seq}`} className="contents">{out}</span>;
    },
    [supersededBy, grounding, review.data, pending, noteFor, note, send, bySeq],
  );

  const filtered = useMemo(() => {
    const q = query.trim().toLowerCase();
    return entries.filter(
      (e) =>
        (kind === "all" || e.kind === kind) &&
        (!question || (e.answers ?? []).some((a) => sectionId(a) === question)) &&
        (!q || [e.value, e.source, e.evidence, e.clock, e.because, ...(e.answers ?? []), ...e.authors].some((t) => (t ?? "").toLowerCase().includes(q))),
    );
  }, [entries, kind, query, question]);
  // The goal sections the entries name, and the contradictions that stand.
  const questions = useMemo(() => [...new Set(entries.flatMap((e) => (e.answers ?? []).map(sectionId)))].sort((a, b) => Number(a) - Number(b) || a.localeCompare(b)), [entries]);
  const contradictions = useMemo(
    () => entries.flatMap((e) => (supersededBy.has(e.seq) ? [] : (e.rel ?? []).filter((r) => r.kind === "contradicts" && !supersededBy.has(r.to)).map((r) => ({ from: e.seq, to: r.to })))),
    [entries, supersededBy],
  );
  const events = filtered.filter((e) => e.kind === "event");
  const iocs = filtered.filter((e) => e.kind === "ioc");
  const findings = filtered.filter((e) => e.kind === "finding");
  const absences = filtered.filter((e) => e.kind === "absence");
  const hypotheses = filtered.filter((e) => e.kind === "hypothesis");
  const limitations = filtered.filter((e) => e.kind === "limitation");
  const timelinePage = usePager(events, `${kind}|${query}`, 50);
  const iocPage = usePager(iocs, `${kind}|${query}`, 50);
  const findingPage = usePager(findings, `${kind}|${query}`, 25);
  const counts: Record<LedgerEntry["kind"], number> = {
    event: entries.filter((e) => e.kind === "event").length,
    ioc: entries.filter((e) => e.kind === "ioc").length,
    finding: entries.filter((e) => e.kind === "finding").length,
    absence: entries.filter((e) => e.kind === "absence").length,
    hypothesis: entries.filter((e) => e.kind === "hypothesis").length,
    limitation: entries.filter((e) => e.kind === "limitation").length,
  };
  const uncited = entries.filter((e) => !isCited(e)).length;
  // What a signature is over: the last chained entry's hash (scripts/review.ts ledgerHead).
  const headHash = [...entries].reverse().find((e) => typeof e.hash === "string")?.hash ?? null;
  const reviewed = Object.keys(review.data?.by_entry ?? {}).length;

  if (!entries.length) {
    return (
      <div className="space-y-4">
        <EmptyState
          icon={<BookOpenText className="size-5" />}
          title="Nothing recorded yet"
          hint={
            <>
              Agents put dated events, indicators, findings and searches that found nothing here with <code>record</code>; the harness renders them into <code>ledger/ledger.md</code> after every call.
            </>
          }
        />
        <CoverageSection coverage={coverage.data} error={coverage.error} />
      </div>
    );
  }

  return (
    <div className="space-y-4">
      <ReportCounts events={counts.event} indicators={counts.ioc} findings={counts.finding} uncited={uncited} />
      {contradictions.length ? (
        <InlineNote tone="warn">
          {contradictions.length} standing contradiction{contradictions.length === 1 ? "" : "s"}:{" "}
          {contradictions.map((c, i) => (
            <span key={`${c.from}-${c.to}`}>
              {i ? "; " : ""}
              <a href={`#ledger-${c.from}`}>#{c.from}</a> contradicts <a href={`#ledger-${c.to}`}>#{c.to}</a>
            </span>
          ))}
          . Both entries stand; neither was corrected.
        </InlineNote>
      ) : null}

      <section className="card space-y-2 p-3" aria-label="Examiner review">
        <div className="flex flex-wrap items-center gap-2">
          <h3 className="label-caps m-0">Examiner review</h3>
          {review.data?.signed ? (
            <Chip tone={review.data.signed.ledger_head && headHash && review.data.signed.ledger_head !== headHash ? "saffron" : "moss"} wrap>
              signed by {review.data.signed.examiner} at {review.data.signed.at}
              {review.data.signed.ledger_head && headHash && review.data.signed.ledger_head !== headHash ? " · the ledger has grown since" : ""}
            </Chip>
          ) : (
            <Chip tone="neutral">not signed</Chip>
          )}
          <span className="text-[12px] text-ink-2">
            {reviewed} of {entries.length} entr{entries.length === 1 ? "y" : "ies"} reviewed
          </span>
          {review.data?.error ? <Chip tone="brick">review file NOT READ</Chip> : review.data?.present ? <Chip tone={review.data.chain.intact ? "moss" : "brick"}>{review.data.chain.intact ? "review chain intact" : "review chain BROKEN"}</Chip> : null}
        </div>
        {review.data && !review.data.present ? <p className="m-0 text-[12px] text-ink-2">Not reviewed by an examiner: the report says so until someone does.</p> : null}
        {review.data?.error ? (
          <InlineNote tone="danger">{review.data.error}. Whatever is in the review file's place is not a review, and the run is not taken for unreviewed either; look at it on the host.</InlineNote>
        ) : review.data?.present && !review.data.chain.intact ? (
          <InlineNote tone="danger">{review.data.chain.detail}</InlineNote>
        ) : null}
        <div className="flex flex-wrap items-center gap-2">
          <input
            value={examiner}
            onChange={(e) => setExaminer(e.target.value)}
            placeholder="examiner's name"
            aria-label="Examiner's name"
            className="h-[26px] min-w-[180px] rounded-[6px] border border-line bg-paper px-2 text-[12.5px]"
          />
          <Button size="sm" variant="secondary" disabled={pending !== null} onClick={() => void send("sign")}>
            {pending === "sign" ? "Signing…" : `Sign the ledger as it stands (${entries.length} entries)`}
          </Button>
        </div>
        <p className="m-0 text-[11.5px] text-ink-3">
          Each decision is one line in the run's review file, outside the run where no agent reaches it, written by <code>swarm.sh review</code> and chained to the line before. Accept, reject or amend each entry below; a signature records the ledger's head hash.
        </p>
        {actionError ? <InlineNote tone="danger">{actionError}</InlineNote> : null}
      </section>

      <div className="flex flex-wrap items-center gap-2">
        <div className="flex flex-wrap gap-1.5" role="tablist" aria-label="Ledger kinds">
          {KINDS.map((k) => (
            <button
              key={k.key}
              type="button"
              role="tab"
              aria-selected={kind === k.key}
              onClick={() => setKind(k.key)}
              className={cn(
                "h-[26px] rounded-full border px-2.5 text-[12px] font-medium transition-colors",
                kind === k.key ? "border-ink bg-ink text-paper" : "border-line bg-transparent text-ink-2 hover:text-ink",
              )}
            >
              {k.label}
              {k.key === "all" ? ` · ${entries.length}` : ` · ${counts[k.key]}`}
            </button>
          ))}
        </div>
        {questions.length ? (
          <select
            value={question}
            onChange={(e) => setQuestion(e.target.value)}
            aria-label="Filter by the goal section an entry answers"
            className="h-[26px] rounded-[6px] border border-line bg-paper px-2 text-[12.5px] text-ink"
          >
            <option value="">every section</option>
            {questions.map((q) => (
              <option key={q} value={q}>
                answers {q}
              </option>
            ))}
          </select>
        ) : null}
        <input
          value={query}
          onChange={(e) => setQuery(e.target.value)}
          placeholder="filter by text, source, evidence or agent"
          aria-label="Filter ledger entries"
          className="h-[26px] min-w-[220px] flex-1 rounded-[6px] border border-line bg-paper px-2 text-[12.5px] text-ink outline-none placeholder:text-ink-3"
        />
        <span className="text-[12px] text-ink-3">
          {view.ledger?.rendered ? (
            <>
              rendered as <code>ledger/ledger.md</code>
            </>
          ) : (
            "not rendered yet"
          )}
        </span>
      </div>

      {kind === "all" || kind === "event" ? (
        <section className="space-y-1.5">
          <div className="flex items-baseline justify-between">
            <h3 className="label-caps">Timeline</h3>
            <span className="text-[12px] text-ink-3">
              {events.length} event{events.length === 1 ? "" : "s"}, in time order (UTC)
            </span>
          </div>
          <TimelineTable entries={timelinePage.rows} authorsFor={authorsFor} marks={marks} />
          <Pager page={timelinePage.page} onPage={timelinePage.set} onSize={timelinePage.setSize} unit="events" />
        </section>
      ) : null}

      {kind === "all" || kind === "ioc" ? (
        <section className="space-y-1.5">
          <div className="flex items-baseline justify-between">
            <h3 className="label-caps">Indicators</h3>
            <span className="text-[12px] text-ink-3">
              {iocs.length} indicator{iocs.length === 1 ? "" : "s"}
            </span>
          </div>
          <IndicatorTable entries={iocPage.rows} authorsFor={authorsFor} marks={marks} />
          <Pager page={iocPage.page} onPage={iocPage.set} onSize={iocPage.setSize} unit="indicators" />
        </section>
      ) : null}

      {kind === "all" || kind === "finding" ? (
        <section className="space-y-1.5">
          <div className="flex items-baseline justify-between">
            <h3 className="label-caps">Findings</h3>
            <span className="text-[12px] text-ink-3">
              {findings.length} finding{findings.length === 1 ? "" : "s"}
            </span>
          </div>
          {findings.length ? (
            <ol className="m-0 list-none space-y-2 p-0">
              {findingPage.rows.map((e) => (
                <li key={e.seq}>
                  <FindingCard claim={e} authors={authorsFor(e)} below={marks(e)} />
                </li>
              ))}
            </ol>
          ) : null}
          {findings.length ? (
            <Pager page={findingPage.page} onPage={findingPage.set} onSize={findingPage.setSize} unit="findings" />
          ) : (
            <NotRecorded what="No finding matches" why="Clear the filter, or nothing was recorded with kind `finding`." />
          )}
        </section>
      ) : null}

      {(kind === "all" && absences.length) || kind === "absence" ? (
        <section className="space-y-1.5" aria-label="Searched and not found">
          <div className="flex items-baseline justify-between">
            <h3 className="label-caps">Searched and not found</h3>
            <span className="text-[12px] text-ink-3">as the agents recorded it, valid only for the scope each names</span>
          </div>
          {absences.length ? (
            <ol className="m-0 list-none space-y-2 p-0">
              {absences.map((e) => (
                <li key={e.seq} className="card space-y-1 p-2.5 text-[12.5px]">
                  <div className="flex flex-wrap items-center gap-2">
                    <span className="font-mono text-[11px] text-ink-3">#{e.seq}</span>
                    <span className="text-ink">looked for: {e.value}</span>
                  </div>
                  <p className="m-0 text-ink-2 [overflow-wrap:anywhere]">
                    where: <span className="font-mono">{e.source || "not said"}</span>
                  </p>
                  <p className="m-0 text-ink-2 [overflow-wrap:anywhere]">
                    query, tool and scope: <span className="font-mono">{e.evidence || "not said"}</span>
                  </p>
                  <div className="flex flex-wrap gap-1">{marks(e)}</div>
                </li>
              ))}
            </ol>
          ) : (
            <NotRecorded what="No search recorded as finding nothing" why="Agents record one with kind `absence` when it matters to the case; an empty search is not evidence of absence unless it says what, where and how." />
          )}
        </section>
      ) : null}

      {(kind === "all" && hypotheses.length) || kind === "hypothesis" ? (
        <section className="space-y-1.5" aria-label="Hypotheses">
          <div className="flex items-baseline justify-between">
            <h3 className="label-caps">Hypotheses</h3>
            <span className="text-[12px] text-ink-3">propositions under test, with the status last given; a supported one is an assessment, not a finding</span>
          </div>
          {hypotheses.length ? (
            <ol className="m-0 list-none space-y-2 p-0">
              {hypotheses.map((e) => (
                <li key={e.seq} className="card space-y-1 p-2.5 text-[12.5px]">
                  <div className="flex flex-wrap items-center gap-2">
                    <span className="font-mono text-[11px] text-ink-3">#{e.seq}</span>
                    <span className="text-ink">{e.value}</span>
                  </div>
                  <p className="m-0 text-ink-2 [overflow-wrap:anywhere]">
                    source: <span className="font-mono">{e.source || "not said"}</span> · evidence: <span className="font-mono">{e.evidence || "not said"}</span>
                  </p>
                  <div className="flex flex-wrap gap-1">{marks(e)}</div>
                </li>
              ))}
            </ol>
          ) : (
            <NotRecorded what="No hypothesis recorded" why="Agents record a proposition they are still testing with kind `hypothesis`." />
          )}
        </section>
      ) : null}

      {(kind === "all" && limitations.length) || kind === "limitation" ? (
        <section className="space-y-1.5" aria-label="Limitations">
          <div className="flex items-baseline justify-between">
            <h3 className="label-caps">Limitations</h3>
            <span className="text-[12px] text-ink-3">what the examination could not establish, and why: weigh every conclusion against these</span>
          </div>
          {limitations.length ? (
            <ol className="m-0 list-none space-y-2 p-0">
              {limitations.map((e) => (
                <li key={e.seq} className="card space-y-1 border-l-2 border-brick p-2.5 text-[12.5px]">
                  <div className="flex flex-wrap items-center gap-2">
                    <span className="font-mono text-[11px] text-ink-3">#{e.seq}</span>
                    <span className="text-ink">{e.value}</span>
                  </div>
                  <p className="m-0 text-ink-2 [overflow-wrap:anywhere]">
                    scope: <span className="font-mono">{e.source || "not said"}</span> · what was tried: <span className="font-mono">{e.evidence || "not said"}</span>
                  </p>
                  <div className="flex flex-wrap gap-1">{marks(e)}</div>
                </li>
              ))}
            </ol>
          ) : (
            <NotRecorded what="No limitation recorded" why="Agents record what they could not examine, or only partly, with kind `limitation` and its reason." />
          )}
        </section>
      ) : null}

      <CoverageSection coverage={coverage.data} error={coverage.error} />

      <InlineNote>
        Rows come from <code>ledger/entries.jsonl</code>, one line per <code>record</code> call, never rewritten. A second agent recording an entry word for word is an attestation, appended beside it in <code>ledger/attestations.jsonl</code>, and both authors are named; the same sentence with other provenance is its own entry. A correction is a new entry with <code>supersedes</code> (and its reason): the older one stays and is marked. The same content is rendered into <code>ledger/ledger.md</code> for the report to cite.
      </InlineNote>
    </div>
  );
}

/**
 * Which inputs no command named, from the trace: generic path matching over
 * every call's arguments. It says only that no command named an input; a
 * named input is not an examined one, and the panel never calls it covered.
 */
function CoverageSection({ coverage, error }: { coverage: Coverage | null; error: Error | null }) {
  const [open, setOpen] = useState(false);
  if (error) return <InlineNote tone="warn">Coverage could not be read: {error.message}</InlineNote>;
  if (!coverage) return null;
  if (coverage.unavailable) {
    return (
      <section className="card p-3 text-[12.5px]" aria-label="Coverage">
        <h3 className="label-caps m-0">Inputs no command named</h3>
        <p className="m-0 mt-1 text-ink-2">{coverage.unavailable}</p>
      </section>
    );
  }
  const named = Object.keys(coverage.touched).length;
  const shown = open ? coverage.untouched : coverage.untouched.slice(0, 20);
  return (
    <section className="card space-y-1.5 p-3 text-[12.5px]" aria-label="Coverage">
      <div className="flex flex-wrap items-center gap-2">
        <h3 className="label-caps m-0">Inputs no command named</h3>
        <Chip tone={coverage.untouched.length ? "saffron" : "moss"}>
          {coverage.untouched.length} of {coverage.inputs}
        </Chip>
        <span className="text-ink-3">
          {named} named by at least one command · {coverage.calls_scanned} calls read
          {coverage.clipped_calls ? ` · ${coverage.clipped_calls} calls the trace kept cut short, where a name past the cut is not seen` : ""}
        </span>
      </div>
      <p className="m-0 text-ink-2">
        No command in the trace named these inputs by path. That is all it says: a command that named an input did not necessarily examine it, and a walk over a directory above one may have read it{Object.keys(coverage.under_named_dir).length ? " (marked below)" : ""}.
      </p>
      {coverage.untouched.length ? (
        <ul className="m-0 flex list-none flex-col gap-0.5 p-0 font-mono text-[11.5px]">
          {shown.map((p) => (
            <li key={p} className="[overflow-wrap:anywhere] text-ink-2">
              {p}
              {coverage.under_named_dir[p] ? <span className="font-sans text-ink-3"> · a directory above it was named {coverage.under_named_dir[p]}×</span> : null}
            </li>
          ))}
        </ul>
      ) : null}
      {coverage.untouched.length > 20 ? (
        <button type="button" className="text-[12px] text-kelp-ink" onClick={() => setOpen((o) => !o)}>
          {open ? "show the first 20" : `show all ${coverage.untouched.length}`}
        </button>
      ) : null}
    </section>
  );
}

