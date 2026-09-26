/**
 * The report vocabulary: what a claim looks like when somebody can check it.
 *
 * The evidence components put a sha256 next to every file. These put a source
 * and a way to verify next to every assertion, which is the same rule one
 * level up. `record` already requires both, and the harness says why in its
 * own words: an entry nobody can check is not a record. So nothing here
 * renders an assertion as though it were fine when its provenance is missing.
 * An uncited claim carries a brick mark, because in this system that absence
 * is the violation.
 *
 * Confidence is deliberately not a colour. The palette spends its accents on
 * state — kelp is running, saffron is budget and stall, brick is violation,
 * slate is locks and files, moss is done — and painting a low-confidence
 * finding brick would shout "danger" about a sentence that is merely hedged.
 * Confidence is three pips and a word, in ink. The accents keep their
 * meanings and the reader keeps one code to learn.
 *
 * Every ledger entry carries a stable `seq`, so an exhibit number is
 * `E-<seq>`: the console, `ledger/ledger.md` and `report.html` cite the same
 * thing. Sections are numbered and anchored because `scripts/report.ts` asks
 * to be cited by section — page numbers belong to the browser, not to the
 * document.
 *
 * Everything renders from its props. Author colours and chosen names arrive
 * as props rather than from `useAgentColours`, so these work outside this
 * application.
 */
import type { ReactNode } from "react";
import { cn } from "@/lib/utils";
import { bytes as formatBytes } from "@/lib/format";
import { HashChip } from "@/components/evidence";

/** What `record` puts in the ledger. Structurally the app's `LedgerEntry`. */
/** absence: a search that found nothing, valid only for the scope it names; hypothesis: a proposition under test; limitation: what could not be established. */
export type ClaimKind = "event" | "ioc" | "finding" | "absence" | "hypothesis" | "limitation";
export type Confidence = "high" | "medium" | "low";

export type ClaimRecord = {
  seq: number;
  kind: ClaimKind;
  value: string;
  /** ISO 8601 UTC. Required for an event, absent for the other kinds. */
  ts?: string;
  /** Where it was seen: a path, a log, a registry key. */
  source?: string;
  /** How to check it: the command, the inode, the record id, the hash. */
  evidence?: string;
  confidence?: Confidence;
  authors?: string[];
  /** The seq of the entry this one corrects; nothing is deleted. */
  supersedes?: number;
  /** What the agent wrote for `ts`, when it was not already the UTC value. */
  ts_raw?: string;
  /** The entry's own hash in the ledger's chain. */
  hash?: string;
};

/** One author of a record, with whatever it decided to call itself. */
export type Author = { id: string; name?: string; chosen?: string; colour?: string };

/** `2026-09-20 14:31:07Z` — the stamp a forensic timeline is read in. */
export function utcStamp(ts: string | undefined | null): string {
  if (!ts) return "";
  const ms = Date.parse(ts);
  if (!Number.isFinite(ms)) return ts;
  return new Date(ms).toISOString().replace("T", " ").replace(/\.\d{3}Z$/, "Z");
}

/** A record is citable when it says both where it was seen and how to check it. */
export function isCited(claim: Pick<ClaimRecord, "source" | "evidence">): boolean {
  return Boolean(claim.source?.trim()) && Boolean(claim.evidence?.trim());
}

/* -------------------------------------------------------------------------
 * The citation atoms
 * ---------------------------------------------------------------------- */

/**
 * `E-12`. The one number the console, the ledger and the report agree on, so
 * a reader who finds a claim in one can find it in the other two.
 */
export function ExhibitNo({ seq, className }: { seq: number; className?: string }) {
  return (
    <span className={cn("font-mono text-[11px] text-ink-3 tabular whitespace-nowrap", className)} title={`Exhibit ${seq}`}>
      E-{seq}
    </span>
  );
}

const PIPS: Record<Confidence, number> = { high: 3, medium: 2, low: 1 };

/**
 * Three pips and a word. Not a colour: see the file header. Filled pips count
 * up with confidence, so the mark is readable at a glance and still survives
 * a greyscale print, which is how most of these documents are actually read.
 */
export function ConfidenceMark({
  level,
  label = true,
  className,
}: {
  level?: Confidence;
  /** Hide the word when the column header already says "confidence". */
  label?: boolean;
  className?: string;
}) {
  if (!level) {
    return <span className={cn("text-[11.5px] text-ink-3", className)}>not stated</span>;
  }
  const filled = PIPS[level];
  return (
    <span className={cn("inline-flex items-center gap-1.5 whitespace-nowrap", className)} title={`Confidence: ${level}`}>
      <span aria-hidden className="inline-flex items-center gap-[3px]">
        {[0, 1, 2].map((i) => (
          <span
            key={i}
            className={cn("block size-[6px] rounded-[1px] border border-ink-3", i < filled ? "bg-ink-2" : "bg-transparent")}
          />
        ))}
      </span>
      {label ? <span className="text-[11.5px] text-ink-2">{level}</span> : <span className="sr-only">{level} confidence</span>}
    </span>
  );
}

/**
 * `source … · evidence …`. The line that makes a sentence a record.
 *
 * When either half is missing the component does not quietly drop it: it says
 * which half is absent, in brick, because a claim that cannot be checked is
 * the one thing this format is built to make visible.
 */
export function Provenance({
  source,
  evidence,
  className,
}: {
  source?: string;
  evidence?: string;
  className?: string;
}) {
  const hasSource = Boolean(source?.trim());
  const hasEvidence = Boolean(evidence?.trim());
  if (hasSource && hasEvidence) {
    return (
      <span className={cn("text-[11.5px] leading-[1.5] text-ink-3", className)}>
        source <span className="font-mono text-ink-2">{source}</span>
        <span className="px-1">·</span>
        evidence <span className="font-mono text-ink-2">{evidence}</span>
      </span>
    );
  }
  return (
    <span className={cn("inline-flex flex-wrap items-baseline gap-x-1 text-[11.5px] leading-[1.5]", className)}>
      {hasSource ? (
        <span className="text-ink-3">
          source <span className="font-mono text-ink-2">{source}</span>
        </span>
      ) : null}
      {hasEvidence ? (
        <span className="text-ink-3">
          evidence <span className="font-mono text-ink-2">{evidence}</span>
        </span>
      ) : null}
      <span className="font-medium text-brick-ink">
        {!hasSource && !hasEvidence ? "uncited" : !hasSource ? "no source" : "no way to check it"}
      </span>
    </span>
  );
}

/* -------------------------------------------------------------------------
 * Attribution
 * ---------------------------------------------------------------------- */

/** One agent, in the ink it uses everywhere else, with the name it chose. */
export function AuthorMark({ author, className }: { author: Author; className?: string }) {
  const { id, name, chosen, colour } = author;
  return (
    <span
      className={cn("font-mono text-[11.5px] whitespace-nowrap", className)}
      style={colour ? { color: colour } : undefined}
      title={chosen ? `${id} — ${chosen}` : id}
    >
      {name ?? id}
      {chosen ? <span className="text-ink-3"> · {chosen}</span> : null}
    </span>
  );
}

/** Who put it on record. Merged entries name every author, never just the first. */
export function AuthorList({ authors, className }: { authors: Author[]; className?: string }) {
  if (!authors.length) return <span className={cn("text-[11.5px] text-ink-3", className)}>—</span>;
  return (
    <span className={cn("inline-flex flex-wrap gap-x-1.5 gap-y-0.5", className)}>
      {authors.map((a) => (
        <AuthorMark key={a.id} author={a} />
      ))}
    </span>
  );
}

/* -------------------------------------------------------------------------
 * The claim
 * ---------------------------------------------------------------------- */

/**
 * One record, laid out the way the report reads it: the number that cites it,
 * what it says, and underneath, in smaller type, everything a reader needs to
 * go and disagree.
 *
 * `emphasis` is the difference between a finding, which is a conclusion and
 * gets room, and a line in a table, which does not.
 */
export function Claim({
  claim,
  authors = [],
  emphasis = "normal",
  showTime = false,
  tail,
  below,
  className,
}: {
  claim: ClaimRecord;
  authors?: Author[];
  emphasis?: "normal" | "lead";
  /** Put the UTC stamp above the statement. Events want this; findings do not. */
  showTime?: boolean;
  tail?: ReactNode;
  /** Marks under the provenance: a correction, a review, whether the trace grounds it. */
  below?: ReactNode;
  className?: string;
}) {
  const cited = isCited(claim);
  return (
    <div
      className={cn(
        "break-inside-avoid rounded-[8px] border bg-card p-2.5",
        cited ? "border-line" : "border-brick/40 bg-brick-soft/30",
        className,
      )}
    >
      <div className="flex flex-wrap items-center gap-2">
        <ExhibitNo seq={claim.seq} />
        {showTime && claim.ts ? <span className="font-mono text-[11px] tabular text-ink-2">{utcStamp(claim.ts)}</span> : null}
        <ConfidenceMark level={claim.confidence} />
        {authors.length ? <AuthorList authors={authors} /> : null}
        {tail ? <span className="ml-auto">{tail}</span> : null}
      </div>
      <p className={cn("m-0 mt-1.5 text-ink", emphasis === "lead" ? "text-[14px] leading-[1.5]" : "text-[13px] leading-[1.45]")}>
        {claim.value}
      </p>
      <div className="mt-1.5">
        <Provenance source={claim.source} evidence={claim.evidence} />
      </div>
      {below ? <div className="mt-1.5 flex flex-wrap items-center gap-1.5">{below}</div> : null}
    </div>
  );
}

/** A finding is a conclusion, so it gets the room a conclusion needs. */
export function FindingCard({
  claim,
  authors = [],
  below,
  className,
}: {
  claim: ClaimRecord;
  authors?: Author[];
  below?: ReactNode;
  className?: string;
}) {
  return <Claim claim={claim} authors={authors} emphasis="lead" below={below} className={className} />;
}

/* -------------------------------------------------------------------------
 * The tables
 * ---------------------------------------------------------------------- */

function Th({ children, w }: { children: ReactNode; w?: string }) {
  return (
    <th className="label-caps px-3 py-2 text-left align-bottom" style={w ? { width: w } : undefined}>
      {children}
    </th>
  );
}

function Cell({ text, mono }: { text?: string; mono?: boolean }) {
  if (!text?.trim()) return <span className="text-brick-ink">missing</span>;
  // `break-words` only breaks a word that would overflow the *line*; a
  // 64-character hash or a Windows path with no spaces still paints past its
  // column and grows the table. `break-all` is the rule that always fits, and
  // these cells are machine strings, not prose.
  return <span className={cn("break-all", mono && "font-mono text-[11.5px]")}>{text}</span>;
}

/**
 * The timeline, in time order, UTC. A forensic timeline is read across
 * machines and time zones, so the stamp is never localised and the column
 * says so in its own header.
 */
export function TimelineTable({
  entries,
  authorsFor,
  marks,
  className,
}: {
  entries: ClaimRecord[];
  /** Resolve an entry's authors. Omit it and the column is left out. */
  authorsFor?: (claim: ClaimRecord) => Author[];
  /** Marks under an entry's statement: a correction, a review, whether the trace grounds it. */
  marks?: (claim: ClaimRecord) => ReactNode;
  className?: string;
}) {
  const rows = [...entries].sort((a, b) => (a.ts ?? "").localeCompare(b.ts ?? "") || a.seq - b.seq);
  if (!rows.length) return <NotRecorded what="No events on the timeline" why="Nothing was recorded with kind `event`." />;
  return (
    // Fixed layout and shares of the width, not five fixed pixel columns: the
    // old table asked for 1,645px on a real run, so every operator read it
    // through a horizontal scrollbar with the last column cut off, on a screen
    // that had room to spare. It now fits whatever it is given and spends any
    // extra width on the two columns that carry forensic strings.
    <div className={cn("card overflow-x-auto", className)}>
      <table className="w-full min-w-[600px] table-fixed text-[12.5px]">
        <thead>
          <tr className="border-b border-line">
            <Th w="58px">Exhibit</Th>
            <Th w="96px">Time (UTC)</Th>
            <Th w="27%">Event</Th>
            <Th w="22%">Source</Th>
            <Th w="26%">How to check it</Th>
            {authorsFor ? <Th w="10%">Recorded by</Th> : null}
          </tr>
        </thead>
        <tbody>
          {rows.map((e) => (
            <tr key={e.seq} className={cn("border-b border-line align-top last:border-0", isCited(e) ? null : "bg-brick-soft/25")}>
              <td className="px-3 py-2">
                <ExhibitNo seq={e.seq} />
              </td>
              <td className="px-3 py-2 font-mono text-[11.5px] tabular text-ink-2">
                {utcStamp(e.ts) || <span className="text-brick-ink">no time</span>}
                {/* The ledger's own rule (protocol.ts renderLedger): the time as the
                    agent wrote it is worth showing only when it was not already UTC. */}
                {e.ts_raw && !/[Zz]$/.test(e.ts_raw) ? <span className="mt-0.5 block font-sans text-[10.5px] text-ink-3 [overflow-wrap:anywhere]">written as {e.ts_raw}</span> : null}
              </td>
              <td className="px-3 py-2 break-words text-ink">
                {e.value}
                {marks ? <div className="mt-1 flex flex-wrap gap-1">{marks(e)}</div> : null}
              </td>
              <td className="px-3 py-2">
                <Cell text={e.source} mono />
              </td>
              <td className="px-3 py-2">
                <Cell text={e.evidence} mono />
              </td>
              {authorsFor ? (
                <td className="px-3 py-2">
                  <AuthorList authors={authorsFor(e)} />
                </td>
              ) : null}
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

/**
 * Indicators, which is the part of a report somebody else will paste into a
 * tool. The value is mono and carries its own hash chip when it is one, so a
 * reader can copy it without copying the prose around it.
 */
export function IndicatorTable({
  entries,
  authorsFor,
  marks,
  className,
}: {
  entries: ClaimRecord[];
  authorsFor?: (claim: ClaimRecord) => Author[];
  marks?: (claim: ClaimRecord) => ReactNode;
  className?: string;
}) {
  if (!entries.length) return <NotRecorded what="No indicators" why="Nothing was recorded with kind `ioc`." />;
  return (
    // A sha256 is 64 characters and an indicator column that squeezes it into
    // a six-character ribbon is unreadable, so the value column is given a
    // share of the width rather than whatever is left after the fixed ones.
    <div className={cn("card overflow-x-auto", className)}>
      <table className="w-full min-w-[640px] table-fixed text-[12.5px]">
        <thead>
          <tr className="border-b border-line">
            <Th w="58px">Exhibit</Th>
            <Th w="29%">Indicator</Th>
            <Th w="22%">Source</Th>
            <Th w="24%">How to check it</Th>
            <Th w="92px">Confidence</Th>
            {authorsFor ? <Th w="10%">Recorded by</Th> : null}
          </tr>
        </thead>
        <tbody>
          {entries.map((e) => (
            <tr key={e.seq} className={cn("border-b border-line align-top last:border-0", isCited(e) ? null : "bg-brick-soft/25")}>
              <td className="px-3 py-2">
                <ExhibitNo seq={e.seq} />
              </td>
              <td className="px-3 py-2 font-mono text-[12px] break-all text-ink">
                {e.value}
                {marks ? <div className="mt-1 flex flex-wrap gap-1 font-sans">{marks(e)}</div> : null}
              </td>
              <td className="px-3 py-2">
                <Cell text={e.source} mono />
              </td>
              <td className="px-3 py-2">
                <Cell text={e.evidence} mono />
              </td>
              <td className="px-3 py-2">
                <ConfidenceMark level={e.confidence} />
              </td>
              {authorsFor ? (
                <td className="px-3 py-2">
                  <AuthorList authors={authorsFor(e)} />
                </td>
              ) : null}
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

/**
 * The timeline as a reader follows it rather than as a table: one dated rule
 * per entry, the statement under it. For the narrow column of a report page,
 * where six columns do not fit and a table becomes a horizontal scroll nobody
 * scrolls.
 */
export function Timeline({
  entries,
  authorsFor,
  className,
}: {
  entries: ClaimRecord[];
  authorsFor?: (claim: ClaimRecord) => Author[];
  className?: string;
}) {
  const rows = [...entries].sort((a, b) => (a.ts ?? "").localeCompare(b.ts ?? "") || a.seq - b.seq);
  if (!rows.length) return <NotRecorded what="No events on the timeline" why="Nothing was recorded with kind `event`." />;
  return (
    <ol className={cn("m-0 list-none space-y-0 p-0", className)}>
      {rows.map((e) => (
        <li key={e.seq} className="break-inside-avoid border-l border-line pl-3 pb-3 last:pb-0">
          <div className="flex flex-wrap items-baseline gap-2">
            <span className="-ml-[17px] mr-0.5 block size-[7px] shrink-0 translate-y-[3px] rounded-full border border-line-2 bg-paper-3" aria-hidden />
            <span className="font-mono text-[11.5px] tabular text-ink-2">{utcStamp(e.ts) || <span className="text-brick-ink">no time</span>}</span>
            <ExhibitNo seq={e.seq} />
            {authorsFor ? <AuthorList authors={authorsFor(e)} /> : null}
          </div>
          <p className="m-0 mt-0.5 text-[13px] leading-[1.45] text-ink">{e.value}</p>
          <div className="mt-0.5">
            <Provenance source={e.source} evidence={e.evidence} />
          </div>
        </li>
      ))}
    </ol>
  );
}

/* -------------------------------------------------------------------------
 * Exhibits
 * ---------------------------------------------------------------------- */

/**
 * A numbered exhibit: the thing itself, framed, with the line that says where
 * it came from. `break-inside: avoid` because an exhibit split across a page
 * boundary is an exhibit a reader stops trusting.
 */
export function Exhibit({
  seq,
  caption,
  source,
  evidence,
  children,
  className,
}: {
  seq: number;
  caption: ReactNode;
  source?: string;
  evidence?: string;
  children: ReactNode;
  className?: string;
}) {
  return (
    <figure className={cn("m-0 break-inside-avoid rounded-[10px] border border-line bg-card p-3", className)}>
      <figcaption className="mb-2">
        <div className="flex flex-wrap items-baseline gap-2">
          <ExhibitNo seq={seq} className="text-ink-2" />
          <span className="text-[12.5px] font-medium text-ink">{caption}</span>
        </div>
        {source || evidence ? (
          <div className="mt-0.5">
            <Provenance source={source} evidence={evidence} />
          </div>
        ) : null}
      </figcaption>
      {children}
    </figure>
  );
}

/**
 * A quoted piece of evidence, with line numbers so a reader can cite a line
 * rather than the whole excerpt. Long lines wrap instead of scrolling: a
 * report is printed, and a horizontal scrollbar prints as a truncation.
 */
export function Excerpt({
  text,
  startLine = 1,
  highlight = [],
  className,
}: {
  text: string;
  /** The line number the first line really has in the source file. */
  startLine?: number;
  /** Absolute line numbers to mark. */
  highlight?: number[];
  className?: string;
}) {
  const lines = text.replace(/\n$/, "").split("\n");
  const marked = new Set(highlight);
  return (
    <pre className={cn("m-0 overflow-hidden rounded-[6px] border border-line bg-paper-2 p-0 font-mono text-[11.5px] leading-[1.6]", className)}>
      <code className="block">
        {lines.map((line, i) => {
          const n = startLine + i;
          return (
            <span key={n} className={cn("flex gap-3 px-2.5", marked.has(n) && "bg-saffron-soft")}>
              <span className="select-none tabular text-ink-3" aria-hidden>
                {String(n).padStart(String(startLine + lines.length - 1).length, " ")}
              </span>
              <span className="min-w-0 whitespace-pre-wrap break-all text-ink">{line || " "}</span>
            </span>
          );
        })}
      </code>
    </pre>
  );
}

/* -------------------------------------------------------------------------
 * Method, custody, limits
 * ---------------------------------------------------------------------- */

/**
 * One step of the method: what was run, with which version, against what.
 * A result nobody can reproduce is the same problem as a claim nobody can
 * check, one level further back.
 */
export function MethodStep({
  tool,
  version,
  args,
  at,
  note,
  className,
}: {
  tool: string;
  version?: string;
  args?: string;
  /** ISO 8601 UTC. */
  at?: string;
  note?: ReactNode;
  className?: string;
}) {
  return (
    <li className={cn("break-inside-avoid border-b border-line py-2 last:border-0", className)}>
      <div className="flex flex-wrap items-baseline gap-2">
        <span className="font-mono text-[12.5px] font-medium text-ink">{tool}</span>
        {version ? <span className="font-mono text-[11.5px] text-ink-3">{version}</span> : <span className="text-[11.5px] text-brick-ink">version not recorded</span>}
        {at ? <span className="ml-auto font-mono text-[11px] tabular text-ink-3">{utcStamp(at)}</span> : null}
      </div>
      {args ? <p className="m-0 mt-1 font-mono text-[11.5px] break-all text-ink-2">{args}</p> : null}
      {note ? <p className="m-0 mt-1 text-[12px] leading-[1.45] text-ink-2">{note}</p> : null}
    </li>
  );
}

/** The method section: an ordered list of steps, each reproducible or marked. */
export function MethodList({ children, className }: { children: ReactNode; className?: string }) {
  return <ol className={cn("card m-0 list-none px-3 py-0", className)}>{children}</ol>;
}

/**
 * Artifacts produced: every file, its size, its hash, and whether it travelled
 * with the package. A file the package does not carry is not a gap as long as
 * its hash is here, because that is what lets a reader check a copy obtained
 * another way — so the row says which it is rather than hiding it.
 *
 * This is the file list. The custody record, which is a different thing, is
 * `CustodyRecord` below.
 */
export function ArtifactTable({
  files,
  className,
}: {
  files: Array<{ path: string; bytes: number; sha256?: string | null; packaged?: boolean; note?: string }>;
  className?: string;
}) {
  if (!files.length) return <NotRecorded what="No artifacts" why="This run wrote nothing under `work/`, so there is nothing to hash." />;
  return (
    <div className={cn("card overflow-x-auto", className)}>
      <table className="w-full min-w-[640px] text-[12.5px]">
        <thead>
          <tr className="border-b border-line">
            <Th>Path</Th>
            <Th w="90px">Size</Th>
            <Th w="150px">sha256</Th>
            <Th w="130px">In the package</Th>
          </tr>
        </thead>
        <tbody>
          {files.map((f) => (
            <tr key={f.path} className="border-b border-line align-top last:border-0">
              <td className="px-3 py-2 font-mono text-[11.5px] break-all text-ink">{f.path}</td>
              <td className="px-3 py-2 tabular text-ink-2">{formatBytes(f.bytes)}</td>
              <td className="px-3 py-2">
                {f.sha256 ? <HashChip sha={f.sha256} chars={8} /> : <span className="text-[11.5px] text-brick-ink">not hashed</span>}
              </td>
              <td className="px-3 py-2 text-[11.5px] text-ink-2">
                {f.packaged === false ? <span className="text-saffron-ink">held in the sandbox</span> : "yes"}
                {f.note ? <span className="block text-ink-3">{f.note}</span> : null}
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

/**
 * The custody record: not a list of files but the fixed set of facts a reader
 * needs to know who held what, when, and whether it was still intact at the
 * end. The printed report carries the same rows — case, examiner, tool, run,
 * period, sandbox, evidence, whether the evidence was still intact, network,
 * ledger, trace — so the two documents answer the custody question the same
 * way.
 *
 * A row whose value is absent says so. "Not checked" and "intact" are
 * different answers and a blank cell reads as the second.
 */
export function CustodyRecord({
  rows,
  className,
}: {
  rows: Array<{ label: string; value?: ReactNode; tone?: "ok" | "warn" | "danger"; mono?: boolean }>;
  className?: string;
}) {
  return (
    <dl className={cn("card m-0 grid grid-cols-[minmax(120px,auto)_1fr] gap-px overflow-hidden bg-line", className)}>
      {rows.map((r) => (
        <div key={r.label} className="contents">
          <dt className="label-caps bg-paper-2 px-3 py-2">{r.label}</dt>
          <dd
            className={cn(
              "m-0 bg-card px-3 py-2 text-[12.5px] break-words",
              r.mono && "font-mono text-[11.5px]",
              r.tone === "ok" && "text-moss",
              r.tone === "warn" && "text-saffron-ink",
              r.tone === "danger" && "font-medium text-brick-ink",
              !r.tone && "text-ink",
            )}
          >
            {r.value ?? <span className="text-brick-ink">not recorded</span>}
          </dd>
        </div>
      ))}
    </dl>
  );
}

/**
 * What the run could not establish. A report without a limitations section is
 * not a shorter report, it is a report that overclaims, so this renders as a
 * first-class item rather than a footnote.
 */
export function Limitation({ children, className }: { children: ReactNode; className?: string }) {
  return (
    <li className={cn("break-inside-avoid border-l-2 border-saffron/50 pl-3 text-[13px] leading-[1.5] text-ink-2", className)}>
      {children}
    </li>
  );
}

/**
 * Absence, stated. The report's version of an empty state: it names what is
 * missing and why, because a silent gap reads as "nothing happened" and that
 * is a different claim.
 */
export function NotRecorded({ what, why, className }: { what: string; why?: ReactNode; className?: string }) {
  return (
    <div className={cn("rounded-[8px] border border-dashed border-line-2 bg-paper-2/60 px-3 py-2.5", className)}>
      <p className="m-0 text-[12.5px] font-medium text-ink-2">{what}</p>
      {why ? <p className="m-0 mt-0.5 text-[12px] leading-[1.45] text-ink-3">{why}</p> : null}
    </div>
  );
}

/* -------------------------------------------------------------------------
 * The document frame
 * ---------------------------------------------------------------------- */

/**
 * The cover: who is handing what to whom, and the one sentence that says the
 * numbers in this document are checkable. Serif, because it is the only place
 * besides the wordmark and the band figures where this console uses it, and
 * because a cover is the one page that is allowed to look like a document.
 */
const STATE_TONE: Record<string, string> = {
  finished: "border-moss/30 bg-moss-soft text-moss",
  stopped: "border-brick/30 bg-brick-soft text-brick-ink",
  "did not finish": "border-saffron/40 bg-saffron-soft text-saffron-ink",
};

export function ReportCover({
  title,
  organisation,
  caseId,
  runId,
  tool,
  startedAt,
  endedAt,
  generatedAt,
  examiner,
  state,
  integrity,
  className,
}: {
  /** Defaults to "<organisation> — forensic report", as the printed report titles it. */
  title?: string;
  organisation?: string;
  caseId?: string;
  runId: string;
  /** What produced it, with its version: the other half of reproducibility. */
  tool?: string;
  /** ISO 8601 UTC. */
  startedAt?: string;
  endedAt?: string;
  generatedAt?: string;
  examiner?: string;
  /** `finished` | `stopped` | `did not finish`, or any label your run uses. */
  state?: string;
  /** Overrides the default integrity sentence. */
  integrity?: ReactNode;
  className?: string;
}) {
  const heading = title ?? (organisation ? `${organisation} — forensic report` : "Forensic report");
  return (
    <header className={cn("break-inside-avoid border-b border-line pb-4", className)}>
      <div className="flex flex-wrap items-baseline gap-3">
        <h1 className="serif m-0 text-[34px] leading-[1.1] text-ink">{heading}</h1>
        {state ? (
          <span
            className={cn(
              "rounded-sm border px-1.5 py-[1px] text-[11px] font-medium whitespace-nowrap",
              STATE_TONE[state] ?? "border-line bg-paper-2 text-ink-2",
            )}
          >
            {state}
          </span>
        ) : null}
      </div>
      <dl className="m-0 mt-3 grid grid-cols-[auto_1fr] gap-x-4 gap-y-1 text-[12.5px]">
        {caseId ? (
          <>
            <dt className="label-caps">Case</dt>
            <dd className="m-0 font-mono text-ink">{caseId}</dd>
          </>
        ) : null}
        {examiner ? (
          <>
            <dt className="label-caps">Examiner</dt>
            <dd className="m-0 text-ink">{examiner}</dd>
          </>
        ) : null}
        {tool ? (
          <>
            <dt className="label-caps">Tool</dt>
            <dd className="m-0 font-mono text-ink">{tool}</dd>
          </>
        ) : null}
        <dt className="label-caps">Run</dt>
        <dd className="m-0 font-mono text-ink">{runId}</dd>
        {startedAt || endedAt ? (
          <>
            <dt className="label-caps">Period</dt>
            <dd className="m-0 font-mono tabular text-ink">
              {utcStamp(startedAt) || "—"} → {utcStamp(endedAt) || "still running"}
            </dd>
          </>
        ) : null}
        {generatedAt ? (
          <>
            <dt className="label-caps">Generated</dt>
            <dd className="m-0 font-mono tabular text-ink">{utcStamp(generatedAt)}</dd>
          </>
        ) : null}
      </dl>
      <p className="m-0 mt-3 max-w-[62ch] text-[12.5px] leading-[1.55] text-ink-2">
        {integrity ?? (
          <>
            Every file named here is named with its sha256, and every claim with where it was seen and how to check it. An entry
            that carries neither is marked rather than omitted.
          </>
        )}
      </p>
    </header>
  );
}

/**
 * A numbered, anchored section. The anchor is what makes "cited by section"
 * true rather than aspirational: `#s-3` is a link a reader can be sent.
 */
export function ReportSection({
  n,
  title,
  children,
  id,
  className,
}: {
  n: number;
  title: string;
  children: ReactNode;
  /** Defaults to `s-<n>`. */
  id?: string;
  className?: string;
}) {
  return (
    <section id={id ?? `s-${n}`} className={cn("scroll-mt-4 space-y-2.5", className)}>
      <h2 className="m-0 flex items-baseline gap-2">
        <span className="font-mono text-[13px] tabular text-ink-3">{n}.</span>
        <span className="serif text-[22px] leading-[1.2] text-ink">{title}</span>
      </h2>
      {children}
    </section>
  );
}

/** The contents, numbered to match the sections a reader will cite. */
export function ReportContents({
  sections,
  className,
}: {
  sections: Array<{ n: number; title: string; id?: string }>;
  className?: string;
}) {
  return (
    <nav className={cn("card break-inside-avoid p-3", className)} aria-label="Contents">
      <h2 className="label-caps m-0">Contents</h2>
      <ol className="m-0 mt-1.5 list-none space-y-0.5 p-0 text-[12.5px]">
        {sections.map((s) => (
          <li key={s.n} className="flex gap-2">
            <span className="font-mono tabular text-ink-3">{s.n}.</span>
            <a href={`#${s.id ?? `s-${s.n}`}`} className="text-ink hover:text-kelp-ink">
              {s.title}
            </a>
          </li>
        ))}
      </ol>
    </nav>
  );
}

/**
 * The answer, before the evidence for it. A reader who stops after the first
 * paragraph should still leave with the finding and how sure it is.
 */
export function Verdict({
  statement,
  confidence,
  children,
  className,
}: {
  statement: ReactNode;
  confidence?: Confidence;
  children?: ReactNode;
  className?: string;
}) {
  return (
    <div className={cn("break-inside-avoid rounded-[10px] border border-line bg-card p-4", className)}>
      <p className="serif m-0 text-[20px] leading-[1.3] text-ink">{statement}</p>
      <div className="mt-2 flex flex-wrap items-center gap-3">
        <ConfidenceMark level={confidence} />
      </div>
      {children ? <div className="mt-2 text-[13px] leading-[1.5] text-ink-2">{children}</div> : null}
    </div>
  );
}

/**
 * What the ledger holds, counted — including the count that matters most,
 * which is how many records cannot be checked. A zero there is the claim the
 * rest of the document rests on, so it is stated rather than implied.
 */
export function ReportCounts({
  events,
  indicators,
  findings,
  uncited = 0,
  className,
}: {
  events: number;
  indicators: number;
  findings: number;
  uncited?: number;
  className?: string;
}) {
  const cells: Array<{ label: string; value: number; tone?: "brick" }> = [
    { label: "Events", value: events },
    { label: "Indicators", value: indicators },
    { label: "Findings", value: findings },
    { label: "Uncited", value: uncited, tone: uncited > 0 ? "brick" : undefined },
  ];
  return (
    <div className={cn("card grid grid-cols-2 gap-px overflow-hidden bg-line sm:grid-cols-4", className)}>
      {cells.map((c) => (
        <div key={c.label} className="bg-card px-3 py-2.5">
          <div className="label-caps">{c.label}</div>
          <div className={cn("mt-0.5 font-mono text-[20px] tabular leading-none", c.tone === "brick" ? "text-brick-ink" : "text-ink")}>
            {c.value}
          </div>
        </div>
      ))}
    </div>
  );
}
