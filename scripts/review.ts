/**
 * The examiner's review of a run's ledger: the one writer of it.
 *
 * An entry the swarm recorded is the swarm's word. What the examiner makes
 * of it — accepted, rejected, amended with a note — and the sign-off over
 * the whole ledger are the examiner's, and they are kept apart from
 * anything an agent can reach: `$SWARM_RUNS_DIR/reviews/<run>.jsonl`,
 * beside the registry, 0600. One JSON line per act, chained: each line's
 * `prev` is the SHA-256 of the previous line's text, as the operator's
 * audit is, so a line taken out or changed breaks the chain. Written under
 * a lock, appended, never rewritten.
 *
 *   {v: 1, seq, at, examiner, os_user, host, action: accept|reject|amend|sign,
 *    entry_seq?, entry_hash?, note?, ledger_head?, ledger_entries?,
 *    report_path?, report_sha256?, attestations_head?, open_rejections?, prev}
 *
 * `entry_hash` is the entry's own hash from the ledger's chain (its
 * immutable core); `sign` records the head of the chain it signs, the
 * report's own hash and the head of the attestations, and the entries the
 * examiner had rejected and not since accepted, so a sign-off over a ledger
 * or a report that changed afterwards is seen to be over another, and a
 * sign-off with objections standing says so.
 *
 * Usage:
 *   node scripts/review.ts add --runs DIR --run ID --sandbox DIR --examiner NAME
 *        --action accept|reject|amend|sign [--entry SEQ] [--note TEXT]
 *   node scripts/review.ts show --runs DIR --run ID [--sandbox DIR] [--json]
 *   node scripts/review.ts verify --runs DIR --run ID
 *   node scripts/review.ts prior --runs DIR --run ID --sandbox DIR --out FILE
 */
import { createHash } from "node:crypto";
import { constants as fsConstants } from "node:fs";
import { chmod, mkdir, open, rm, stat, writeFile } from "node:fs/promises";
import { hostname, userInfo } from "node:os";
import { dirname, join } from "node:path";
import { pathToFileURL } from "node:url";
import { readRegularText } from "./regular-file.ts";

export type ReviewAction = "accept" | "reject" | "amend" | "sign";
export const REVIEW_ACTIONS: readonly ReviewAction[] = ["accept", "reject", "amend", "sign"];

export type ReviewLine = {
  v: 1;
  seq: number;
  at: string;
  examiner: string;
  os_user: string;
  host: string;
  action: ReviewAction;
  entry_seq?: number;
  entry_hash?: string;
  note?: string;
  ledger_head?: string;
  ledger_entries?: number;
  /** The report the sign-off is over, as a path under the sandbox and its sha256 (null: there was none). */
  report_path?: string;
  report_sha256?: string | null;
  /** The last line of ledger/attestations.jsonl, or null when there are none. */
  attestations_head?: string | null;
  /** Entries whose latest review was a rejection when the examiner signed. */
  open_rejections?: number[];
  prev: string | null;
};

/** A line as it was read: the parsed object and the exact text the next line's `prev` hashes. */
export type ReadReviewLine = ReviewLine & { text: string };

type LedgerLine = { seq?: number; kind?: string; ts?: string; value?: string; source?: string; evidence?: string; confidence?: string; by?: string; at?: string; hash?: string; supersedes?: number };

const sha256 = (text: string | Buffer) => createHash("sha256").update(text).digest("hex");

/**
 * A review or a ledger that is there and is not a regular file: a link, a
 * FIFO, a directory planted in its place. Never read through, and never
 * taken for "no review": the caller says what it found.
 */
export class ReviewFileError extends Error {
  readonly why: string;
  readonly path: string;
  constructor(path: string, why: string) {
    super(`${path} is ${why}; it is not read`);
    this.name = "ReviewFileError";
    this.path = path;
    this.why = why;
  }
}

/** Reviews and ledgers are small; a file past this is refused, never cut. */
const READ_MAX_BYTES = 512 * 1024 * 1024;

/** A file's text through the no-follow reader: "" when missing, a ReviewFileError for anything but a regular file. */
async function readText(path: string): Promise<string> {
  const r = await readRegularText(path, READ_MAX_BYTES);
  if ("text" in r) return r.text;
  if (r.why === "missing") return "";
  throw new ReviewFileError(path, r.why);
}

export function reviewsPath(runsDir: string, runId: string): string {
  if (!/^[A-Za-z0-9_-]+$/.test(runId)) throw new Error(`not a run id: ${JSON.stringify(runId)}`);
  return join(runsDir, "reviews", `${runId}.jsonl`);
}

/**
 * Every review line of a run in file order, each with its own text; [] when
 * there is none. A torn or foreign line is kept as text with no fields, so
 * the chain check sees it. A link, a FIFO or anything but a regular file in
 * the review's place throws a ReviewFileError: it is not a review, and it
 * is not "no review" either.
 */
export async function readReviews(runsDir: string, runId: string): Promise<ReadReviewLine[]> {
  const text = await readText(reviewsPath(runsDir, runId));
  const out: ReadReviewLine[] = [];
  for (const line of text.split("\n")) {
    if (!line) continue;
    try {
      out.push({ ...(JSON.parse(line) as ReviewLine), text: line });
    } catch {
      out.push({ text: line } as ReadReviewLine);
    }
  }
  return out;
}

/**
 * Whether the lines are the chain they claim: seq from 1 up by one, each
 * `prev` the SHA-256 of the line before (null on the first), every action
 * one of the four. Takes what readReviews returned, or the file's text.
 */
export function verifyReviewChain(lines: ReadReviewLine[] | Array<{ text: string }> | string): { ok: boolean; total: number; broken_at: number | null; reason: string | null } {
  const texts = typeof lines === "string" ? lines.split("\n").filter(Boolean) : lines.map((l) => l.text);
  let prev: string | null = null;
  for (let i = 0; i < texts.length; i++) {
    let line: ReviewLine;
    try {
      line = JSON.parse(texts[i]) as ReviewLine;
    } catch {
      return { ok: false, total: texts.length, broken_at: i + 1, reason: `line ${i + 1} is not JSON` };
    }
    if (line.seq !== i + 1) return { ok: false, total: texts.length, broken_at: i + 1, reason: `line ${i + 1} says seq ${line.seq}` };
    if ((line.prev ?? null) !== prev) return { ok: false, total: texts.length, broken_at: i + 1, reason: `line ${i + 1} does not follow the line before it (a line was changed, removed or put in)` };
    if (!REVIEW_ACTIONS.includes(line.action)) return { ok: false, total: texts.length, broken_at: i + 1, reason: `line ${i + 1} has no known action` };
    prev = sha256(texts[i]);
  }
  return { ok: true, total: texts.length, broken_at: null, reason: null };
}

/** Each reviewed entry's latest act, and the latest sign-off. */
export function reviewState(lines: ReviewLine[]): { entries: Map<number, ReviewLine>; signed: ReviewLine | null } {
  const entries = new Map<number, ReviewLine>();
  let signed: ReviewLine | null = null;
  for (const l of lines) {
    if (l.action === "sign") signed = l;
    else if (typeof l.entry_seq === "number") entries.set(l.entry_seq, l);
  }
  return { entries, signed };
}

async function readLedger(sandbox: string): Promise<{ entries: Array<LedgerLine & { text: string }>; sha256: string }> {
  const file = join(sandbox, "ledger", "entries.jsonl");
  // In a host run the ledger sits where a pane can write: a link or a FIFO
  // there is refused by name, never read through or waited on.
  const raw = Buffer.from(await readText(file), "utf8");
  const entries: Array<LedgerLine & { text: string }> = [];
  for (const line of raw.toString("utf8").split("\n")) {
    if (!line.trim()) continue;
    try {
      entries.push({ ...(JSON.parse(line) as LedgerLine), text: line });
    } catch {
      // a torn line is no entry
    }
  }
  return { entries, sha256: sha256(raw) };
}

/** The entry's own hash from the ledger's chain, or the line's when it is unchained. */
const entryHash = (e: LedgerLine & { text: string }) => e.hash ?? sha256(e.text);

/** The head of the ledger a sign-off is over: the last entry's chain hash, or the file's when nothing is chained. */
export function ledgerHead(entries: Array<LedgerLine & { text: string }>, fileSha: string): string {
  const last = [...entries].reverse().find((e) => typeof e.hash === "string");
  return last?.hash ?? `file:${fileSha}`;
}

async function withLock<T>(file: string, fn: () => Promise<T>): Promise<T> {
  const lock = `${file}.lock`;
  const deadline = Date.now() + 10_000;
  for (;;) {
    try {
      await mkdir(lock);
      break;
    } catch {
      // A lock a writer left when it died goes stale after a minute.
      const st = await stat(lock).catch(() => null);
      if (st && Date.now() - st.mtimeMs > 60_000) {
        await rm(lock, { recursive: true, force: true });
        continue;
      }
      if (Date.now() > deadline) throw new Error(`${lock} is held; another review is being written`);
      await new Promise((r) => setTimeout(r, 50));
    }
  }
  try {
    return await fn();
  } finally {
    await rm(lock, { recursive: true, force: true });
  }
}

export type ReviewInput = { action: ReviewAction; examiner: string; entry_seq?: number; note?: string; report?: string };

/** The sha256 of a regular file under the sandbox, or null when there is none. */
async function sandboxFileSha(sandbox: string, rel: string): Promise<string | null> {
  const r = await readRegularText(join(sandbox, rel), READ_MAX_BYTES).catch(() => null);
  return r && "text" in r ? sha256(r.text) : null;
}

/** The attestations' head: the last line's hash, or null. */
async function attestationsHead(sandbox: string): Promise<string | null> {
  const r = await readRegularText(join(sandbox, "ledger", "attestations.jsonl"), READ_MAX_BYTES).catch(() => null);
  const text = r && "text" in r ? r.text : "";
  const last = text.trim().split("\n").filter(Boolean).at(-1);
  if (!last) return null;
  try {
    return (JSON.parse(last) as { hash?: string }).hash ?? null;
  } catch {
    return null;
  }
}

/** Append one act to a run's review, checked against its ledger. Returns the line written. */
export async function appendReview(runsDir: string, runId: string, sandbox: string, input: ReviewInput): Promise<ReviewLine> {
  if (!REVIEW_ACTIONS.includes(input.action)) throw new Error(`action must be one of ${REVIEW_ACTIONS.join(", ")}`);
  const examiner = (input.examiner ?? "").trim();
  if (!examiner) throw new Error("an examiner's name is required (--examiner)");
  const note = input.note?.trim() || undefined;
  if ((input.action === "reject" || input.action === "amend") && !note) throw new Error(`${input.action} needs a note saying why (--note)`);
  const ledger = await readLedger(sandbox);
  const file = reviewsPath(runsDir, runId);
  await mkdir(dirname(file), { recursive: true, mode: 0o700 });
  await chmod(dirname(file), 0o700).catch(() => undefined);
  return withLock(file, async () => {
    const before = await readReviews(runsDir, runId);
    const chain = verifyReviewChain(before);
    if (!chain.ok) throw new Error(`the review of ${runId} is broken (${chain.reason}); nothing is added to a broken chain`);
    const line: ReviewLine = {
      v: 1,
      seq: before.length + 1,
      at: new Date().toISOString(),
      examiner,
      os_user: userInfo().username,
      host: hostname(),
      action: input.action,
      prev: before.length ? sha256(before[before.length - 1].text) : null,
    };
    if (input.action === "sign") {
      if (!ledger.entries.length) throw new Error(`run ${runId} has no ledger entries to sign`);
      line.ledger_head = ledgerHead(ledger.entries, ledger.sha256);
      line.ledger_entries = ledger.entries.length;
      // The report the examiner read, and what still stood against it.
      line.report_path = input.report ?? "work/report.md";
      line.report_sha256 = await sandboxFileSha(sandbox, line.report_path);
      line.attestations_head = await attestationsHead(sandbox);
      line.open_rejections = [...reviewState(before).entries.values()].filter((l) => l.action === "reject").map((l) => l.entry_seq as number).sort((a, b) => a - b);
    } else {
      if (!Number.isInteger(input.entry_seq)) throw new Error(`${input.action} needs the entry's seq (--entry N)`);
      const entry = ledger.entries.find((e) => e.seq === input.entry_seq);
      if (!entry) throw new Error(`run ${runId} has no ledger entry ${input.entry_seq}`);
      line.entry_seq = input.entry_seq;
      line.entry_hash = entryHash(entry);
    }
    if (note) line.note = note;
    const text = JSON.stringify(line);
    // Appended through a handle that follows no link and waits on no FIFO,
    // and only to a regular file.
    const handle = await open(file, fsConstants.O_WRONLY | fsConstants.O_APPEND | fsConstants.O_CREAT | fsConstants.O_NOFOLLOW | fsConstants.O_NONBLOCK, 0o600).catch((err: NodeJS.ErrnoException) => {
      throw new ReviewFileError(file, err.code === "ELOOP" ? "a link" : `not writable (${err.code ?? "error"})`);
    });
    try {
      if (!(await handle.stat()).isFile()) throw new ReviewFileError(file, "not a regular file");
      await handle.write(`${text}\n`);
    } finally {
      await handle.close();
    }
    await chmod(file, 0o600).catch(() => undefined);
    return line;
  });
}

/**
 * An earlier run's claims as hypotheses for a new run (`--ledger-from`):
 * with its examiner's reviews, only the entries accepted or amended (with
 * the note); without, every entry, marked unreviewed. Markdown, one section
 * per entry, whole; each with the run, its seq and its hash.
 */
export async function priorLedger(runsDir: string, runId: string, sandbox: string): Promise<{ markdown: string; entries: number; reviewed: boolean; ledger_sha256: string }> {
  const ledger = await readLedger(sandbox);
  const lines = (await readReviews(runsDir, runId)).filter((l) => l.action);
  const chain = verifyReviewChain(await readReviews(runsDir, runId));
  const reviewed = lines.length > 0 && chain.ok;
  const state = reviewState(lines);
  const picked = ledger.entries.filter((e) => {
    if (!reviewed) return true;
    const act = typeof e.seq === "number" ? state.entries.get(e.seq) : undefined;
    return !!act && (act.action === "accept" || act.action === "amend") && act.entry_hash === entryHash(e);
  });
  const out: string[] = [
    `# Prior claims: run ${runId}`,
    "",
    "These are an earlier run's ledger entries, brought in with --ledger-from as hypotheses to",
    "re-derive or refute from the evidence. They are not findings and are not in this run's ledger.",
    "A claim that rests on one must cite what was read in the evidence, never this file.",
    "",
    reviewed
      ? `Reviewed: yes. Only the entries run ${runId}'s examiner accepted or amended are here (${picked.length} of ${ledger.entries.length}).`
      : lines.length && !chain.ok
        ? `Reviewed: the examiner's review of run ${runId} does not verify (${chain.reason}), so no acceptance is taken from it: every entry is here, unreviewed (${ledger.entries.length}).`
        : `Reviewed: no. No examiner has reviewed run ${runId}: every entry is here, unreviewed (${ledger.entries.length}).`,
    `Ledger of run ${runId}: sha256 ${ledger.sha256}.`,
    "",
  ];
  for (const e of picked) {
    const act = reviewed && typeof e.seq === "number" ? state.entries.get(e.seq) : undefined;
    out.push(`## ${runId}#${e.seq ?? "?"} · ${e.kind ?? "entry"} · ${act ? (act.action === "amend" ? "amended by the examiner" : "accepted by the examiner") : "unreviewed"}`, "");
    const field = (name: string, value: unknown) => {
      if (value === undefined || value === null || value === "") return;
      const text = String(value);
      out.push(text.includes("\n") ? `- ${name}:\n\n${text.split("\n").map((l) => `      ${l}`).join("\n")}\n` : `- ${name}: ${text}`);
    };
    field("Claim", e.value);
    field("Time", e.ts);
    field("Source", e.source);
    field("Evidence", e.evidence);
    field("Confidence", e.confidence);
    field("Supersedes", e.supersedes);
    field("Recorded by", e.by);
    field("Examiner's note", act?.note);
    out.push(`- Entry hash: \`${entryHash(e)}\``, "");
  }
  return { markdown: `${out.join("\n")}\n`, entries: picked.length, reviewed, ledger_sha256: ledger.sha256 };
}

function opt(args: string[], name: string): string | undefined {
  const i = args.indexOf(name);
  return i >= 0 ? args[i + 1] : undefined;
}

async function main(argv: string[]): Promise<number> {
  const [cmd, ...args] = argv;
  const runsDir = opt(args, "--runs") ?? process.env.SWARM_RUNS_DIR;
  const run = opt(args, "--run");
  if (!runsDir || !run) {
    console.error("review: --runs DIR and --run ID are required");
    return 2;
  }
  switch (cmd) {
    case "add": {
      const sandbox = opt(args, "--sandbox");
      if (!sandbox) {
        console.error("review add: --sandbox DIR is required");
        return 2;
      }
      const entry = opt(args, "--entry");
      const line = await appendReview(runsDir, run, sandbox, {
        action: (opt(args, "--action") ?? "") as ReviewAction,
        examiner: opt(args, "--examiner") ?? "",
        entry_seq: entry === undefined ? undefined : Number(entry),
        note: opt(args, "--note"),
        report: opt(args, "--report"),
      });
      console.log(JSON.stringify(line));
      return 0;
    }
    case "verify": {
      const v = verifyReviewChain(await readReviews(runsDir, run));
      console.log(JSON.stringify(v));
      return v.ok ? 0 : 1;
    }
    case "show": {
      const lines = await readReviews(runsDir, run);
      const v = verifyReviewChain(lines);
      const state = reviewState(lines);
      let head: string | null = null;
      let reportNow: string | null | undefined;
      const sandbox = opt(args, "--sandbox");
      if (sandbox) {
        const ledger = await readLedger(sandbox).catch(() => null);
        if (ledger) head = ledgerHead(ledger.entries, ledger.sha256);
        if (state.signed?.report_path) reportNow = await sandboxFileSha(sandbox, state.signed.report_path);
      }
      const s0 = state.signed;
      const summary = {
        run,
        lines: lines.length,
        chain: v,
        entries: [...state.entries.values()].map((l) => ({ seq: l.entry_seq, action: l.action, examiner: l.examiner, at: l.at, note: l.note ?? null })),
        signed: s0
          ? {
              examiner: s0.examiner,
              at: s0.at,
              ledger_head: s0.ledger_head,
              current: head === null ? null : head === s0.ledger_head,
              report_path: s0.report_path ?? null,
              report_sha256: s0.report_sha256 ?? null,
              report_current: reportNow === undefined || s0.report_sha256 === undefined ? null : reportNow === s0.report_sha256,
              open_rejections: s0.open_rejections ?? [],
            }
          : null,
      };
      if (args.includes("--json")) {
        console.log(JSON.stringify(summary));
      } else {
        console.log(`Review of ${run}: ${lines.length} act(s); the chain ${v.ok ? "verifies" : `is BROKEN (${v.reason})`}.`);
        for (const e of summary.entries) console.log(`  #${e.seq}: ${e.action} by ${e.examiner} at ${e.at}${e.note ? ` (${e.note})` : ""}`);
        if (summary.signed) {
          console.log(`  Signed by ${summary.signed.examiner} at ${summary.signed.at}, over ledger head ${summary.signed.ledger_head}${summary.signed.current === false ? " (the ledger has changed since: the sign-off is over an earlier one)" : ""}.`);
          if (summary.signed.report_path) console.log(`  Over ${summary.signed.report_path} ${summary.signed.report_sha256 ?? "(absent when signed)"}${summary.signed.report_current === false ? " (the report has changed since)" : ""}.`);
          if (summary.signed.open_rejections.length) console.log(`  Signed with rejections standing: ${summary.signed.open_rejections.map((n) => `#${n}`).join(", ")}.`);
        } else {
          console.log("  Not signed.");
        }
      }
      return v.ok ? 0 : 1;
    }
    case "prior": {
      const sandbox = opt(args, "--sandbox");
      const out = opt(args, "--out");
      if (!sandbox || !out) {
        console.error("review prior: --sandbox DIR and --out FILE are required");
        return 2;
      }
      const p = await priorLedger(runsDir, run, sandbox);
      await writeFile(out, p.markdown, { mode: 0o644 });
      console.log(JSON.stringify({ entries: p.entries, reviewed: p.reviewed, ledger_sha256: p.ledger_sha256 }));
      return 0;
    }
    default:
      console.error("review: add | show | verify | prior");
      return 2;
  }
}

if (process.argv[1] && pathToFileURL(process.argv[1]).href === import.meta.url) {
  main(process.argv.slice(2)).then(
    (code) => process.exit(code),
    (err) => {
      console.error(`review: ${err instanceof Error ? err.message : err}`);
      process.exit(1);
    },
  );
}
