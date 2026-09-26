/**
 * The ledger out of the run, for the tools an examiner already uses.
 *
 *   node --experimental-strip-types scripts/export.ts <sandbox> --format csv|timesketch [--out FILE]
 *
 * `csv`: every ledger entry with every field it carries, its hash, the entry
 * that corrects it (superseded by), the examiner's review of it and whether
 * the trace grounds its source. `timesketch`: Timesketch's CSV import, one row
 * per entry: `message`, `datetime` (the entry's own time, ISO 8601 in UTC)
 * and `timestamp_desc`, with the ledger's columns beside them; an entry with
 * no time of its own is placed at the time it was recorded and says so.
 *
 * Nothing is left out and nothing is shortened. The file is written where
 * `--out` says (to stdout without it) and nowhere else; the run is only
 * read.
 */
import { readFile, writeFile } from "node:fs/promises";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { readEventLogChecked, readLedger, supersededBy, type LedgerEntry } from "../extensions/protocol.ts";
import { groundingOf, type Grounding } from "./coverage.ts";
import { readReviewState, reviewStatusOf } from "./report.ts";
import { findRunBySandbox } from "./run-record.ts";

export type ExportFormat = "csv" | "timesketch";

/**
 * One cell, RFC 4180: quoted when it holds a comma, a quote or a line break,
 * quotes doubled. A text cell that a spreadsheet would read as a formula (it
 * starts with =, +, -, @, a tab or a carriage return) gets a leading
 * apostrophe, so opening the export cannot run what an agent, or the
 * evidence it quoted, wrote there. The one change made to any value, and
 * only to text cells.
 */
export function csvCell(value: unknown): string {
  if (value === undefined || value === null) return "";
  if (typeof value === "number" || typeof value === "boolean") return String(value);
  let s = Array.isArray(value) ? value.map((v) => (typeof v === "string" ? v : JSON.stringify(v))).join(";") : typeof value === "object" ? JSON.stringify(value) : String(value);
  if (/^[=+\-@\t\r]/.test(s)) s = `'${s}`;
  return /[",\r\n]/.test(s) ? `"${s.replace(/"/g, '""')}"` : s;
}

function csvRows(header: string[], rows: unknown[][]): string {
  return [header.map(csvCell), ...rows.map((r) => r.map(csvCell))].map((r) => r.join(",")).join("\r\n") + "\r\n";
}

/** The fields every entry is shown with first, in this order; any other field an entry carries follows, by name. */
const LEDGER_FIELDS = ["seq", "kind", "ts", "ts_raw", "precision", "clock", "value", "source", "evidence", "confidence", "status", "reason", "completion", "basis", "answers", "rel", "attribution", "locators", "sensitive", "by", "authors", "at", "v", "supersedes", "because", "prev", "hash"];

export type ExportContext = {
  /** seq → the examiner's standing on it (accepted, rejected, amended, not reviewed). */
  review?: Map<number, string>;
  /** seq → whether the trace grounds its source. */
  grounding?: Record<string, Grounding>;
  /** Replace what a sensitive entry says (value, source, evidence, locators) with a note: the export is for handing over. */
  redact?: boolean;
};

/** An entry as an export may carry it: a sensitive one's words replaced, its hash and refs kept, so it can still be matched to the ledger. */
export function redactEntry(e: LedgerEntry): LedgerEntry {
  if (!e.sensitive) return e;
  const note = "[redacted: marked sensitive]";
  return { ...e, value: note, source: note, evidence: note, ...(e.locators ? { locators: e.locators.map((l) => ({ ref: l.ref, at: note })) } : {}), ...(e.attribution ? { attribution: { ...e.attribution, subject: note } } : {}) };
}

export function ledgerCsv(given: readonly LedgerEntry[], ctx: ExportContext = {}): string {
  const ledger = ctx.redact ? given.map(redactEntry) : given;
  const extra = [...new Set(ledger.flatMap((e) => Object.keys(e)))].filter((k) => !LEDGER_FIELDS.includes(k)).sort();
  const header = [...LEDGER_FIELDS, ...extra, "superseded_by", "review", "grounding"];
  const by = supersededBy([...ledger]);
  const rows = ledger.map((e) => {
    const rec = e as unknown as Record<string, unknown>;
    return [
      ...LEDGER_FIELDS.map((k) => rec[k]),
      ...extra.map((k) => rec[k]),
      by.get(e.seq) ?? "",
      ctx.review ? (ctx.review.get(e.seq) ?? "not reviewed") : "",
      ctx.grounding?.[String(e.seq)] ?? "",
    ];
  });
  return csvRows(header, rows);
}

/** What an entry's datetime is, in Timesketch's words. */
function timestampDesc(e: LedgerEntry): string {
  if (!e.ts) return "Recorded in the ledger";
  // The clock the time came from is exactly what this column is for.
  if (e.clock) return `${e.clock}${e.precision === "date" ? " (date only)" : ""}`;
  return e.kind === "event" ? `Event time, as recorded in the ledger${e.precision === "date" ? " (date only)" : ""}` : `Time given with the ${e.kind}, as recorded in the ledger`;
}

export function ledgerTimesketch(given: readonly LedgerEntry[], ctx: ExportContext = {}): string {
  const ledger = ctx.redact ? given.map(redactEntry) : given;
  const header = ["message", "datetime", "timestamp_desc", "kind", "source", "evidence", "confidence", "by", "seq", "hash", "superseded_by", "review"];
  const by = supersededBy([...ledger]);
  const rows = ledger.map((e) => {
    const when = e.ts || e.at || "";
    const iso = Number.isFinite(Date.parse(when)) ? new Date(Date.parse(when)).toISOString() : when;
    return [
      e.value,
      iso,
      timestampDesc(e),
      e.kind,
      e.source ?? "",
      e.evidence ?? "",
      e.confidence ?? "",
      e.by,
      e.seq,
      e.hash ?? "",
      by.get(e.seq) ?? "",
      ctx.review ? (ctx.review.get(e.seq) ?? "not reviewed") : "",
    ];
  });
  return csvRows(header, rows);
}

export async function exportLedger(sandboxArg: string, format: ExportFormat, ctx: ExportContext & { runsDir?: string } = {}): Promise<string> {
  const sandbox = resolve(sandboxArg);
  const ledger = await readLedger(sandbox);
  let grounding = ctx.grounding;
  if (!grounding) {
    const trace = await readEventLogChecked(sandbox);
    grounding = trace.unreadable ? {} : groundingOf(ledger, trace.events);
  }
  // The examiner's review, from beside the registry; every entry "not
  // reviewed" when there is none.
  let review = ctx.review;
  if (!review) {
    const runsDir = ctx.runsDir ?? process.env.SWARM_RUNS_DIR ?? dirname(sandbox);
    const run = await findRunBySandbox(sandbox, runsDir);
    const teamId = await readFile(join(sandbox, "team.json"), "utf8").then((t) => (JSON.parse(t) as { swarm_id?: string }).swarm_id ?? "").catch(() => "");
    const state = await readReviewState(runsDir, run?.id ?? teamId, sandbox, ledger);
    review = new Map(ledger.map((e) => [e.seq, reviewStatusOf(state, e)]));
  }
  return format === "timesketch" ? ledgerTimesketch(ledger, { ...ctx, grounding, review }) : ledgerCsv(ledger, { ...ctx, grounding, review });
}


if (process.argv[1] && resolve(process.argv[1]) === resolve(fileURLToPath(import.meta.url))) {
  const args = process.argv.slice(2);
  const opt = (name: string) => {
    const i = args.indexOf(name);
    return i >= 0 ? args[i + 1] : undefined;
  };
  const sandbox = args.find((a, i) => !a.startsWith("--") && !["--format", "--out", "--runs-dir"].includes(args[i - 1] ?? ""));
  const format = opt("--format");
  if (!sandbox || (format !== "csv" && format !== "timesketch")) {
    console.error("Usage: export.ts <sandbox> --format csv|timesketch [--out FILE] [--runs-dir DIR] [--redact]");
    process.exit(2);
  }
  const text = await exportLedger(sandbox, format, { runsDir: opt("--runs-dir"), redact: args.includes("--redact") });
  const out = opt("--out");
  if (out) {
    await writeFile(out, text);
    console.error(`Wrote ${out}`);
  } else {
    process.stdout.write(text);
  }
}
