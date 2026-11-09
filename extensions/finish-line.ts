/**
 * The finish line (split from extensions/protocol.ts, which re-exports it): the done, the abandon
 * gate, the state revision, the finish-line checks and their verdict, run outcomes, and the turn and
 * provider errors the finish reads.
 */

import { execFile, execFileSync, spawn } from "node:child_process";
import { createHash, randomBytes, randomUUID } from "node:crypto";
import {
  closeSync,
  createReadStream,
  mkdirSync,
  openSync,
  readFileSync,
  readlinkSync,
  realpathSync,
  writeSync,
} from "node:fs";
import { connect, type Socket } from "node:net";
import {
  appendFile,
  chmod,
  copyFile,
  lstat,
  mkdir,
  open,
  readFile,
  readdir,
  readlink,
  realpath,
  rename,
  rm,
  stat,
  writeFile,
} from "node:fs/promises";
import { constants as fsConstants } from "node:fs";
import { basename, dirname, join, posix, relative, resolve, sep } from "node:path";
import { fileURLToPath } from "node:url";
import * as NB from "./negative-bar.ts";
import * as PM from "./premises.ts";
import * as PR from "./preparation.ts";
import { importHitExamined, importHitsFor, importHitWords, unexaminedHits, type ImportSweepRecord, type SweepRecord, type UnexaminedHit } from "./store-sweep.ts";
import type { AbandonGate, DoneRefused, DoneResult, SwarmContext } from "./protocol-core.ts";
import { ABANDON_PREFIX, ALL_DEAD_REL, LEDGER_ENTRIES, REGISTER_LOCK, SHARED_WORK_DIRS, STOPPED_REL, SYSTEM_AGENT, abandonVotePath, agentDeadPath, agentDonePath, claimKey, createSentinel, harnessStop, listPostFiles, listThreadNames, readBudget, readPost, readTeam, releaseAllOwned, sentinelPath, sha256Hex, swarmDoneExists, withNamedLock, withTableLock, yamlOneLine } from "./protocol-core.ts";

export async function markDone(
  ctx: SwarmContext,
  args: { reason: string; outputFile: string; createSentinel?: boolean; outcome?: FinishOutcome; revision?: string; finish?: { holder: string; generation: number } },
): Promise<DoneResult | DoneRefused> {
  const reason = yamlOneLine(args.reason);
  const outputFile = yamlOneLine(args.outputFile);
  if (!reason) throw new Error("done requires a reason");
  if (!outputFile) throw new Error("done requires output_file");
  // The report reads the output file back: it names a file in the run.
  claimKey(ctx.sandboxRoot, outputFile);

  // A per-agent cap stop is one seat leaving. The swarm's clock is
  // done/SWARM_DONE; writing it here would shut every other pane.
  const seatOnly = args.createSentinel === false || reason === "agent_cap";
  // An until-solved run takes no abandon, a vote or not: only the operator
  // ends it (swarm.sh stop), or every question disposed under the bar.
  if (!seatOnly && reason.startsWith(ABANDON_PREFIX) && (await readBudget(ctx.sandboxRoot).catch(() => null))?.until_solved === true) {
    throw new Error(UNTIL_SOLVED_NO_ABANDON);
  }
  if (!seatOnly && reason.startsWith(ABANDON_PREFIX) && !(await swarmDoneExists(ctx.sandboxRoot))) {
    const gate = await abandonGate(ctx.sandboxRoot, ctx.agentId, reason);
    if (!gate.proceed) {
      const others = gate.working.length;
      return {
        terminate: false,
        refused:
          `An abandon ends the run for everyone, so one agent's word is not enough while ${others} other agent${others === 1 ? " is" : "s are"} still working (${gate.working.join(", ")}). ` +
          `Your abandon is recorded (done/abandon/${ctx.agentId}.md) and the board is asked: the run ends when a second agent also calls done with abandon: true, or when no other agent is still working. ` +
          `If only your own slice failed, post what you tried and what blocked it to the board, then take another open question or wait.`,
        abandon: gate,
        created_sentinel: false,
        reason,
        output_file: outputFile,
      };
    }
  }

  // The finish is one seat's (A4, extensions/finish.ts): a done that would
  // end the swarm is checked against the coordinator's lease (the holder and
  // generation its done began with, `finish`) and what is late against the
  // report, in the same transaction that writes this seat's marker and the
  // sentinel (finishTransaction), never only before.
  const ending = !seatOnly && !reason.startsWith(ABANDON_PREFIX) && !(await swarmDoneExists(ctx.sandboxRoot));

  const by = ctx.agentId;
  const stamp = new Date().toISOString();
  const agentFile = agentDonePath(ctx.sandboxRoot, ctx.agentId);
  const sentinel = sentinelPath(ctx.sandboxRoot);

  // How the run ended, when the finish line said (FinishOutcome): an
  // abandon is abandoned whatever the caller passed.
  const outcome: FinishOutcome | undefined = reason.startsWith(ABANDON_PREFIX) ? "abandoned" : args.outcome && (FINISH_OUTCOMES as readonly string[]).includes(args.outcome) ? args.outcome : undefined;
  const outcomeLine = outcome && !seatOnly ? `outcome: ${outcome}\n` : "";
  const agentBody = `---
by: ${by}
output: ${outputFile}
reason: ${reason}
${outcomeLine}at: ${stamp}
---

Worker ${by} is exiting.
`;
  const sentinelText = `---
by: ${by}
output: ${outputFile}
reason: ${reason}
${outcomeLine}at: ${stamp}
---

Collective finished. Presence of this file is the clock. Call done and stop.
`;
  // The sentinel is written under the registers' lock, against the state the
  // finish line was judged on (`revision`, when the caller ran it): a question
  // admitted or a lead opened after that line either moved the state, and the
  // done is refused to be run again, or finds the sentinel and is recorded as
  // a follow-up. Admission and a terminal done are never interleaved.
  const writeDone = async (): Promise<boolean> => {
    await mkdir(dirname(agentFile), { recursive: true });
    await writeFile(agentFile, agentBody, "utf8");
    if (seatOnly) return false;
    if (!args.revision) return createSentinel(ctx.sandboxRoot, sentinelText);
    return withNamedLock(ctx.sandboxRoot, REGISTER_LOCK, async () => {
      if (!(await swarmDoneExists(ctx.sandboxRoot)) && (await stateRevision(ctx.sandboxRoot).catch(() => ({ revision: "" }))).revision !== args.revision) {
        await rm(agentFile, { force: true }).catch(() => undefined);
        throw new Error(FINISH_LINE_UNSETTLED);
      }
      return createSentinel(ctx.sandboxRoot, sentinelText);
    });
  };
  const created = ending ? await (await import("./finish.ts")).finishTransaction(ctx.sandboxRoot, ctx.agentId, args.finish, writeDone, Date.now(), { ...(args.revision ? { revision: args.revision } : {}), ...(outcome ? { outcome } : {}) }) : await writeDone();

  await releaseAllOwned(ctx);

  return {
    terminate: true,
    agent_done: agentFile,
    sentinel,
    created_sentinel: created,
    reason,
    output_file: outputFile,
    ...(outcome && !seatOnly ? { outcome } : {}),
  };
}

/**
 * An abandon ends the run for everyone and skips the finish line, so one
 * agent's word is not enough while others are still working: run sfeeebb
 * lost a ten-agent case after six minutes to one seat whose own slice had
 * not come together. The caller's vote is recorded under done/abandon/; the
 * run may end when a second agent has voted too, or when no other agent is
 * still working (every peer has a .done or a .dead marker, as reap and
 * await-done read them). No team file, no peers.
 */
export async function abandonGate(sandboxRoot: string, agentId: string, reason: string): Promise<AbandonGate> {
  const mine = abandonVotePath(sandboxRoot, agentId);
  await mkdir(dirname(mine), { recursive: true });
  const first = !(await stat(mine).then(() => true).catch(() => false));
  await writeFile(mine, `---\nby: ${agentId}\nreason: ${yamlOneLine(reason)}\nat: ${new Date().toISOString()}\n---\n`, "utf8");
  const votes = (await readdir(dirname(mine)).catch(() => [] as string[]))
    .filter((n) => n.endsWith(".md"))
    .map((n) => n.slice(0, -3))
    .sort();
  const team = await readTeam(sandboxRoot).catch(() => null);
  const working: string[] = [];
  for (const member of team?.agents ?? []) {
    if (member.id === agentId || votes.includes(member.id)) continue;
    const marked = await Promise.all(
      [agentDonePath(sandboxRoot, member.id), agentDeadPath(sandboxRoot, member.id)].map((p) => stat(p).then(() => true).catch(() => false)),
    );
    if (!marked.some(Boolean)) working.push(member.id);
  }
  return { proceed: votes.length >= 2 || working.length === 0, votes, working, first_vote: first };
}

/**
 * Whether a turn that ended in an error was the provider's doing, or the
 * harness's own. When the harness stops an agent (the sentinel landed, a cap
 * bound, a hard kill) it aborts the turn in flight, and Pi records that as an
 * error whose message is the abort's: "This operation was aborted". That is
 * not the provider answering, and the board must not say it was. A stop the
 * harness itself began names its reason; an abort after the sentinel is the
 * same thing seen from a process that did not set the flag.
 *
 * A connection that died is the same once the run is over: the last agent
 * out turns the proxy off, and every turn still streaming through it ends
 * with "Connection error." or "terminated". On run s57e9 that put four
 * PROVIDER ERROR vetoes on the board of a finished run, six seconds after the
 * sentinel. A provider's own answer — a status, a balance, a rate limit — is
 * the provider's whether or not the run is over, and stays reported.
 */
export function classifyTurnError(
  reason: string,
  harnessStop: string | null,
  swarmDone: boolean,
): "provider" | "harness" {
  const aborted = /\baborted\b/i.test(reason);
  const tornDown = /connection error|\bterminated\b|ECONNRESET|ECONNREFUSED|EPIPE|socket hang up|fetch failed/i.test(reason);
  if ((harnessStop || swarmDone) && (aborted || tornDown)) return "harness";
  return "provider";
}

/** A page of a job's stdout as the job service hands it back (job_run, job_status). */
export type JobStdoutPage = { offset: number; bytes: number; total: number; text?: string; next: number | null; path: string };

/**
 * What a page of a job's stdout leaves unread, said plainly. On the Belka run
 * s94e373 a job returned the first 8,192 of 18,206 bytes of a notes
 * database; the note the three blocked agents needed began at byte 10,709,
 * and nothing in the result said that most of the output was still unread.
 * The key sat on the agent's screen, in the half it never read, for the
 * rest of the run. Null when the page reaches the end.
 */
export function jobPageNote(job: string, page: JobStdoutPage): string | null {
  const end = page.offset + page.bytes;
  const unread = Math.max(0, page.total - end);
  if (!unread) return null;
  const before = page.offset > 0 ? ` (bytes 0-${page.offset} came on earlier pages)` : "";
  return (
    `This is bytes ${page.offset}-${end} of ${page.total} of ${job}'s stdout${before}: ${unread} bytes are unread. ` +
    `Read the next page with job_status(job_id: "${job}", offset: ${end}), or read ${page.path} whole, before you draw a conclusion from this page. ` +
    `Until the rest is read, or an entry you record with interprets: [{job: "${job}", rest: "how you read the rest, or why not"}] says why not, ${job} stays on your list of jobs awaiting interpretation.`
  );
}

/**
 * A provider's error text with its numbers and times masked, so the same
 * error said with a countdown ("Try again in ~6904 min.", then "~6874
 * min.") reads as one. For telling the board once; the trace keeps every
 * text whole.
 */
export function normalizeProviderError(reason: string): string {
  return reason
    .replace(/\d{4}-\d{2}-\d{2}(?:[T ]\d{1,2}:\d{2}(?::\d{2}(?:\.\d+)?)?)?\s*(?:Z|UTC|GMT|[+-]\d{2}:?\d{2})?/gi, "<time>")
    .replace(/\d+(?:[.,:]\d+)*/g, "#")
    .replace(/\s+/g, " ")
    .trim();
}

/**
 * What the board is told when a seat's turn ends in the provider's error.
 * It used to say the seat's work was "free", and on the Belka run s306463
 * a peer began taking over an agent that had only lost one turn: the agent
 * came back, the two collided, and the board spent four posts sorting it
 * out. A failed turn transfers nothing. The work stands as the seat's until
 * the seat itself, or the hub (a lead reclaimed from a stale holder), says
 * otherwise.
 */
export function providerErrorPost(agentId: string, model: string, reason: string): string {
  return (
    `PROVIDER ERROR: ${agentId}'s turn on ${model} ended with: ${reason}. ` +
    `Nothing this agent or a peer does will change that: it is the provider answering, not the harness. ` +
    `Only this turn failed. ${agentId}'s work, its leads and its claims stand as its own until ${agentId} or the hub says otherwise; ` +
    `do not take them over on the strength of this post. If ${agentId} stays silent, its leads show as stale in \`leads\` and can be reclaimed from there.`
  );
}

/**
 * The shared install area and the scratch dir are nobody's work product. pip
 * writes hundreds of files under work/.toolchain/, a tool keeps its cache
 * there, and two agents installing at once are not in conflict over the case:
 * on run sb36f that read as 442 claim violations over pytz's zoneinfo. What
 * was installed is still inventoried from toolchain.json.
 */
export function isSharedScratch(path: string): boolean {
  // One list for the two readers: the shell-write watch leaves these
  // directories out of its snapshot (`SHARED_WORK_DIRS`, above), and a
  // report that still names one of them is dropped here.
  return (SHARED_WORK_DIRS as readonly string[]).some((dir) => path === `work/${dir}` || path.startsWith(`work/${dir}/`));
}

/** Where await-done.sh may read a finish line that certifies a run: the operator's copy. */
export const FINISH_LINE_TRUSTED_SOURCES = new Set(["registry"]);

/**
 * The operator's finish line, run once, right now, by await-done.sh from the
 * registry: what an agent's `done` runs before the sentinel, and what the VM
 * hub runs again on the host before it lets a sentinel be written.
 */
export async function runFinishLine(sandbox: string): Promise<FinishLineRun | null> {
  const script = resolve(dirname(fileURLToPath(import.meta.url)), "..", "scripts", "await-done.sh");
  const run = await new Promise<FinishLineRun | null>((done) => {
    execFile(
      "bash",
      [script, "--sandbox", sandbox, "--checks-json", "--check-timeout", "120"],
      { cwd: sandbox, timeout: 15 * 60_000, maxBuffer: 4 * 1024 * 1024, env: { ...process.env, CHECKS_SOURCE: "done" } },
      (err, stdout) => {
        try {
          const parsed = JSON.parse(String(stdout || "").trim().split("\n").pop() || "") as FinishLineRun;
          if (typeof parsed.total === "number" && Array.isArray(parsed.checks)) return done(parsed);
        } catch {
          /* fall through */
        }
        done(err ? { total: 0, passed: 0, checks: [], error: String(err.message || err) } : null);
      },
    );
  });
  // The harness's own part (scripts/finish-gate.ts): the lead register's
  // open work, and whether the run would end completed or examination-
  // limited. Read after the goal's checks, from the same files; the caller
  // binds both to one revision (runFinishLineBound, the hub's markDone).
  if (!run) return run;
  try {
    const { finishGate } = (await import(resolve(dirname(fileURLToPath(import.meta.url)), "..", "scripts", "finish-gate.ts"))) as typeof import("../scripts/finish-gate.ts");
    run.gate = await finishGate(sandbox, run);
  } catch (err) {
    run.gate = { defects: [], limited: [], questions: [], until_solved: false, error: `the harness's gate could not be run: ${(err as Error).message}` };
  }
  return run;
}

/** The record a finish line reads that is not the goal's own files: where each lives. */
export const REVISION_FILES = { ledger: LEDGER_ENTRIES, attestations: "ledger/attestations.jsonl", disputes: "ledger/disputes.jsonl", leads: "leads/leads.jsonl", questions: "questions/questions.jsonl" } as const;

/**
 * Whether a line of the lead or the question register is an offer's
 * bookkeeping (docs/adr/0015): an offer made, delivered, declined, accepted
 * or lapsed, or a wake from before offers. Those say who may take a piece of
 * work first, never what the finish rests on, and idle seats write them all
 * the time: were they in the revision, a waiting seat's delivered offer would
 * make the coordinator's finish line run again, and one check result per
 * revision would not hold. A closure offered to its closer to confirm is not
 * bookkeeping: until it is confirmed it holds the finish. The lines are the
 * registers' own compact JSON, where `"ev":"…"` can only be the event's key
 * (a quote inside a value is escaped).
 */
export function offerBookkeeping(line: string): boolean {
  if (line.includes('"ev":"wake"')) return true;
  if (!line.includes('"ev":"offer')) return false;
  return !(line.includes('"ev":"offer"') && line.includes('"reason":"confirm"'));
}

/** A register's part of the revision: its bytes, less its offers' bookkeeping for the lead and question registers. */
function revisionPart(name: string, bytes: Buffer): string {
  if (name !== "leads" && name !== "questions") return `${bytes.length}:${sha256Hex(bytes)}`;
  const kept = Buffer.from(
    bytes
      .toString("utf8")
      .split("\n")
      .filter((line) => !offerBookkeeping(line))
      .join("\n"),
    "utf8",
  );
  return `${kept.length}:${sha256Hex(kept)}`;
}

/** Tags of a post that can change a verdict: a result, a veto, a hold, a stop. */
const VERDICT_TAGS = new Set<string>(["result", "veto", "hold", "stop"]);
/** A post never changes once written, so its tag and sender are read once per process. */
const postTagCache = new Map<string, { tag: string; from: string }>();

/**
 * The state a finish line is judged against, as one revision: the board (per
 * thread, the newest agent post that can change a verdict: a result, a veto,
 * a hold or a stop; an intro or a claim cannot), the ledger (every byte: a
 * merge rewrites an entry's authors, and an author may not attest), the
 * review (the attestations and the disputes), the leads and the questions
 * (less their offers' bookkeeping: offerBookkeeping). A finish line run
 * against one revision holds only while the revision does: on the VM hub a
 * passing run was reused for 30 s whatever had changed in between, and a
 * dispute recorded in that window did not stop the sentinel.
 */
export async function stateRevision(sandboxRoot: string): Promise<{ revision: string; parts: Record<string, string> }> {
  const parts = await stateParts(sandboxRoot);
  // What the finish rests on beyond the registers (A4): the report the
  // coordinator's done names (by its digest), every job's state, the run's
  // policy (the case policy too), the operator's decisions (the requests'
  // chain, less its delivery bookkeeping) and what was added after the
  // kickoff (docs/adr/0014). A job committed, a report rewritten, a pause, a
  // host allowed, a request answered or evidence added between the finish
  // line and the sentinel moves the revision, and the done is run again.
  const { finishParts } = await import("./finish.ts");
  Object.assign(parts, await finishParts(sandboxRoot));
  return { revision: sha256Hex(JSON.stringify(parts)), parts };
}

async function stateParts(sandboxRoot: string): Promise<Record<string, string>> {
  const parts: Record<string, string> = {};
  const board: Record<string, number> = {};
  for (const thread of await listThreadNames(sandboxRoot)) {
    let newest = 0;
    for (const file of await listPostFiles(sandboxRoot, thread)) {
      let seen = postTagCache.get(file);
      if (!seen) {
        const post = await readPost(file).catch(() => null);
        if (!post) continue;
        seen = { tag: post.tag, from: post.from };
        postTagCache.set(file, seen);
      }
      if (seen.from === SYSTEM_AGENT || !VERDICT_TAGS.has(seen.tag)) continue;
      newest = Math.max(newest, Number.parseInt(basename(file).slice(0, 6), 10) || 0);
    }
    if (newest) board[thread] = newest;
  }
  parts.board = JSON.stringify(board);
  for (const [name, rel] of Object.entries(REVISION_FILES)) {
    const bytes = await readFile(join(sandboxRoot, rel)).catch(() => null);
    parts[name] = bytes ? revisionPart(name, bytes) : "none";
  }
  return parts;
}

/** How many times a finish line is run again when the state moved under it, before done is refused. */
export const FINISH_LINE_ATTEMPTS = 3;

/**
 * The finish line bound to a revision: the revision taken before the run, the
 * run, and the revision again after it. A run the state moved under is run
 * again, up to FINISH_LINE_ATTEMPTS times; `settled` false says it never held
 * still, and the caller refuses rather than write a sentinel on a verdict the
 * state no longer matches.
 */
export async function runFinishLineBound(
  sandboxRoot: string,
  runner: (sandbox: string) => Promise<FinishLineRun | null> = runFinishLine,
  attempts = FINISH_LINE_ATTEMPTS,
): Promise<{ run: FinishLineRun | null; revision: string; settled: boolean; runs: number }> {
  let last: { run: FinishLineRun | null; revision: string } = { run: null, revision: "" };
  for (let i = 1; i <= attempts; i++) {
    const before = (await stateRevision(sandboxRoot).catch(() => ({ revision: "" }))).revision;
    const run = await runner(sandboxRoot).catch(() => null);
    const after = (await stateRevision(sandboxRoot).catch(() => ({ revision: "" }))).revision;
    last = { run, revision: before };
    if (before === after) return { ...last, settled: true, runs: i };
  }
  return { ...last, settled: false, runs: attempts };
}

/** The refusal of a done whose finish line never held still. */
export const FINISH_LINE_UNSETTLED =
  `The board, the ledger, the review or the leads changed while the finish line ran, ${FINISH_LINE_ATTEMPTS} times in a row, ` +
  "so no verdict matches the state a sentinel would close. Read what landed (inbox, ledger, leads), then call done again.";

/**
 * What await-done.sh --checks-json prints: the finish line, run once, right
 * now. What a failing check said (`out`, and `fix` or `output` when a runner
 * gives them) the refusal carries to the agent verbatim.
 */
export type FinishLineRun = {
  total: number;
  passed: number;
  /**
   * A failing check's output, whole when it is at most 64 KiB (out), and its
   * size (out_bytes): the runner's own words for the check. `fix` or
   * `output`, when a runner gives them, are the check's words too.
   */
  checks: Array<{ cmd: string; ok: boolean; ms?: number; timed_out?: boolean; out?: string; out_bytes?: number; fix?: string; output?: string; answers?: { outcomes?: Record<string, string>; named?: string[]; existence?: string[]; mode?: string } }>;
  source?: string | null;
  error?: string;
  /** The harness's part, beside the goal's checks (scripts/finish-gate.ts). */
  gate?: FinishGateView;
};

/** What the harness's gate says (scripts/finish-gate.ts's FinishGate, as the verdict reads it). */
export type FinishGateView = {
  defects: Array<{ code: string; lead?: string; job?: string; question?: string; what: string; fix: string }>;
  limited: string[];
  /** Each question, how it stands, what blocks it, and its disposition under the bar when it has one (established, partial, bounded_negative, not_determinable, premise_not_supported, out_of_scope); `must_establish` when it takes only an answer that answers it (docs/adr/0013). */
  questions?: Array<{ id: string; outcome: string; blocks: string[]; disposition?: string; must_establish?: boolean }>;
  until_solved?: boolean;
  /** The lines of `limited` that are the operator's acceptances. */
  accepted?: string[];
  /** What holds a run under the operator's stop policy beside its questions: a defect a limitation only names. */
  holding?: string[];
  /** What the answers check warns of and does not hold on (LedgerWarning: a not-determinable answer that names no acquisition ask, a partial answer every review holds whole, findings under a question's leads its answer leaves out): said in the verdict's note. */
  warnings?: string[];
  error?: string;
};

/**
 * How a run ended, as the sentinel and the record say it. `completed`: the
 * finish line was run and met. `examination_limited`: it was met, and the
 * run says what it could not establish (a limitation never reads as an
 * answer). `abandoned`: given up without its checks. `verification_unavailable`:
 * the harness could not run the finish line at all, so nothing was
 * established either way; it never reads as completed.
 */
export const FINISH_OUTCOMES = ["completed", "examination_limited", "abandoned", "verification_unavailable"] as const;
export type FinishOutcome = (typeof FINISH_OUTCOMES)[number];
/**
 * How a run stands or ended, beyond what a done can say: `paused` (a cap,
 * the model provider's limit or the operator paused it; it goes on once the
 * cause is gone, or the operator stops it) and `stopped` (the operator
 * stopped it, or a cap did under cap-stop): never `completed`, whatever its
 * answers say.
 */
export const RUN_OUTCOMES = ["completed", "examination_limited", "paused", "stopped", "abandoned", "verification_unavailable"] as const;
export type RunOutcome = (typeof RUN_OUTCOMES)[number];
/**
 * How a run stands, from its own files: stopped (the operator's STOPPED, or
 * the harness's sentinel at a cap), the outcome a done wrote in the
 * sentinel, paused (a cap, the provider's limit or the operator's hold,
 * the run not finished), or null while it runs and when every seat died
 * with no sentinel (done/ALL_AGENTS_DEAD, paused or not).
 */
export async function runOutcome(sandboxRoot: string): Promise<{ outcome: RunOutcome | null; by: string | null; at: string | null; why: string | null }> {
  const front = (text: string) => Object.fromEntries([...text.matchAll(/^([a-z_]+):[ \t]*(.*)$/gm)].map((m) => [m[1], m[2].trim()])) as Record<string, string>;
  const stopped = await readFile(join(sandboxRoot, STOPPED_REL), "utf8").catch(() => null);
  if (stopped !== null) {
    try {
      const j = JSON.parse(stopped) as { by?: string; at?: string; why?: string };
      return { outcome: "stopped", by: j.by ?? null, at: j.at ?? null, why: j.why ?? null };
    } catch {
      return { outcome: "stopped", by: null, at: null, why: null };
    }
  }
  const sentinel = await readFile(sentinelPath(sandboxRoot), "utf8").catch(() => null);
  if (sentinel !== null) {
    const f = front(sentinel);
    const said = (RUN_OUTCOMES as readonly string[]).includes(f.outcome ?? "") ? (f.outcome as RunOutcome) : null;
    const byCap = f.by === "harness" && (f.reason === "cap" || f.reason === "wall_clock");
    return { outcome: byCap ? "stopped" : said, by: f.by ?? null, at: f.at ?? null, why: f.reason ?? null };
  }
  // Every seat dead and no sentinel (the reaper's done/ALL_AGENTS_DEAD): the
  // run has no outcome of its own, paused or not; nothing will lift a pause
  // it died in. Its readers name it from that file.
  if (await lstat(join(sandboxRoot, ALL_DEAD_REL)).then(() => true).catch(() => false)) return { outcome: null, by: null, at: null, why: null };
  const budget = await readBudget(sandboxRoot).catch(() => null);
  if (budget?.paused) return { outcome: "paused", by: budget.paused.by ?? "harness", at: budget.paused.at, why: budget.paused.detail };
  return { outcome: null, by: null, at: null, why: null };
}

/** Record the operator's stop of a run that has no sentinel: done/STOPPED, once. */
export async function markStopped(sandboxRoot: string, by: string, why: string): Promise<{ written: boolean }> {
  // Under the lock an extension takes, so the two are ordered: one that
  // came first is in the caps the stop leaves, one that comes after is refused.
  return withTableLock(sandboxRoot, async () => {
    if (await swarmDoneExists(sandboxRoot)) return { written: false };
    const file = join(sandboxRoot, STOPPED_REL);
    if (await lstat(file).then(() => true).catch(() => false)) return { written: false };
    await mkdir(dirname(file), { recursive: true });
    await writeFile(file, `${JSON.stringify({ outcome: "stopped", by, at: new Date().toISOString(), why })}\n`, { encoding: "utf8", flag: "wx" }).catch(() => undefined);
    return { written: true };
  });
}

/** The reason prefix of a done the harness could not check. */
export const VERIFICATION_UNAVAILABLE_PREFIX = "VERIFICATION UNAVAILABLE: ";

/**
 * What a question may end on under the bar, said to the agents of a run
 * under the operator's stop policy: every disposition, and the way to one
 * when the evidence cannot answer it (docs/adr/0013).
 */
export const DISPOSITION_WORDS =
  "every question in scope has a disposition under the bar: established; partial; a bounded negative or not determinable, each resting on a coverage record another seat has reviewed; a premise shown not to hold; out of scope; accepted by the operator; or withdrawn";
export const NEGATIVE_PATH_WORDS =
  "When the evidence cannot answer a question, that is an answer too: plan its routes (lead_open or lead_link with routes); when it needs a source the evidence does not hold, ask for it first (lead_close needs_operator with ask {kind: acquisition, source, where, expected_value, urgency}); record a coverage record (kind=coverage: what was searched, over which objects, how, what was covered, skipped and failed, the results, what is still open, whether the event would have left a trace, and the acquisition ask as acquisition_ask R-<n>, or why none in acquisition_none_why), have another seat review it (attest with review {detection, reproduced, other_route}), then answer not_determinable, or bounded_negative when nothing was found in that scope";

/**
 * The way to a disposition for a question that must be established (docs/adr/0013,
 * "A question that must be established"): never a negative, and never a vote.
 */
export const MUST_ESTABLISH_PATH_WORDS =
  "A question that must be established (the goal's Must establish section, or the operator's word) ends the run only established, on a standing finding another seat attests established, with its premise shown not to hold on a finding, or settled by a bounded negative under the stronger bar: partial, not determinable and the rest do not end the run on it, and only the operator accepts its limits (question accept) or releases the requirement (question amend --no-must-establish). " +
  "The stronger bar is for a question that asks whether something exists: plan its routes, record a coverage record (kind=coverage) over the objects the event would have touched, which the hub finds complete and which says the event would have left a trace there (trace_expected yes), have another seat review it (attest with review {detection, reproduced, other_route}), then answer bounded_negative with asserts_absence: true, saying the event did not happen. " +
  "Short of that, keep working it: another route, another source, another reading of what the run holds";

/** The refusal of an abandon in an until-solved run: only the operator ends it. */
export const UNTIL_SOLVED_NO_ABANDON =
  `This run was started until solved (--stop operator): no caps, no wall clock, and it ends when ${DISPOSITION_WORDS}, or when the operator stops it (swarm.sh stop). The agents cannot abandon it. ` +
  `${NEGATIVE_PATH_WORDS}. Post what blocks you, open a lead for another route, or close a lead needs_operator for what only the operator can give, and keep working.`;

export type FinishVerdict =
  | { proceed: true; outcome: FinishOutcome; note?: string; reasonPrefix?: string }
  | { proceed: false; reason: string; failing: string };

/**
 * Whether a `done` that would write the sentinel may go ahead. The checks are
 * the operator's, read from the registry by await-done.sh, so an agent cannot
 * rewrite them; but until now nothing ran them at the moment `done` was
 * called, and on run sb36f a nano agent ended a 25 GB case after four minutes
 * by calling done when its own slice was finished, with no report written. A
 * failing finish line is a refusal that names every check that fails and
 * what makes it pass (`failing` is the first, for the record's one field).
 * `abandon` is the way out the guidelines promise for a task that is
 * impossible or unsafe: the sentinel is written and says so. A run whose
 * checks cannot be run at all is not held hostage by the runner, but it is
 * not a clean done either: it proceeds as `verification_unavailable`, the
 * sentinel's reason says so, and the trace records why.
 */
export function finishLineVerdict(run: FinishLineRun | null, abandon: boolean, opts: { untilSolved?: boolean } = {}): FinishVerdict {
  // A run under the operator's stop policy (--stop operator, --until-solved)
  // has no caps and no wall clock, and one end the agents can reach: every
  // question in scope with a disposition under the bar, the same end any run
  // takes. Giving up is the operator's (swarm.sh stop), never a vote.
  const until = opts.untilSolved === true || run?.gate?.until_solved === true;
  if (!run || run.error) {
    const why = run?.error ? ` (${run.error})` : "";
    if (until) return { proceed: false, failing: "(finish line unavailable)", reason: `The finish line could not be run${why}, so nothing can show that every question has a disposition under the bar, and this run ends only then. Say so on the board and keep working; the operator sees the same.` };
    if (abandon) return { proceed: true, outcome: "abandoned", reasonPrefix: ABANDON_PREFIX, note: `the finish line could not be run${why}; abandoned on purpose` };
    return { proceed: true, outcome: "verification_unavailable", reasonPrefix: VERIFICATION_UNAVAILABLE_PREFIX, note: `the finish line could not be run${why}; done proceeds as verification_unavailable, never as completed` };
  }
  // A finish line that is met, or has nothing to meet, proves something only
  // if the checks are the operator's. Read from anywhere else they are checks
  // an agent could have rewritten — on the host SWARM.md is writable from a
  // shell — so passing them certifies nothing. The harness hands every pane
  // the registry (SWARM_RUNS_DIR), and a microVM a read-only view of it, so a
  // different source means something is wrong. A failing finish line is a
  // refusal either way, and the check that fails is the useful thing to say.
  const untrusted = Boolean(run.source) && !FINISH_LINE_TRUSTED_SOURCES.has(run.source as string);
  if (untrusted && run.passed >= run.total) {
    // Abandoning claims nothing, so it is still the way out.
    if (abandon && !until) return { proceed: true, outcome: "abandoned", reasonPrefix: ABANDON_PREFIX, note: `checks read from the ${run.source} were not trusted; abandoned on purpose` };
    return {
      proceed: false,
      failing: `(checks read from ${run.source})`,
      reason:
        `The finish line was read from the ${run.source}, which agents can edit, not from the operator's registry, so it cannot certify the run. ` +
        `This is the harness's problem, not yours: say so on the board and wait for the operator. If the goal cannot be met at all, call done again with abandon: true and say why.`,
    };
  }
  if (run.total === 0 || run.passed >= run.total) {
    // The goal's checks are met: what the harness's gate says decides, and an
    // abandon counts only while a question has no disposition under the bar.
    const noChecks = run.total === 0 ? "the goal has no checks" : undefined;
    const gate = run.gate;
    if (!gate) return { proceed: true, outcome: "completed", ...(noChecks ? { note: noChecks } : {}) };
    if (gate.error) {
      if (until) return { proceed: false, failing: "(gate unavailable)", reason: `The goal's checks pass, but ${gate.error}; this run ends only when every question is shown to have a disposition under the bar. Say so on the board; the operator sees the same.` };
      return { proceed: true, outcome: "verification_unavailable", reasonPrefix: VERIFICATION_UNAVAILABLE_PREFIX, note: gate.error };
    }
    if (gate.defects.length) {
      const each = gate.defects.map((d) => `- ${d.what}. Fix: ${d.fix}`).join("\n");
      return {
        proceed: false,
        failing: `${gate.defects[0].code}${gate.defects[0].lead ? ` ${gate.defects[0].lead}` : ""}${gate.defects[0].job ? ` ${gate.defects[0].job}` : ""}${gate.defects[0].question ? ` ${gate.defects[0].question}` : ""}`,
        reason:
          `The goal's checks pass, but material work is still open: ${gate.defects.length} item${gate.defects.length === 1 ? "" : "s"} the lead and question registers hold against done:\n${each}\n` +
          "A lead is disposed of with lead_close; a lead's job is interpreted by recording what its output shows with interprets naming it; a question in scope is answered in the ledger in its section. Then call done again.",
      };
    }
    // One rule under every stop policy (docs/adr/0013, joint-r3 Phase 1a):
    // done finishes a run only when every question in scope has a
    // disposition under the bar (answered; partial; a bounded negative or not
    // determinable on a coverage record another seat reviewed; a premise
    // shown not to hold; out of scope; accepted; withdrawn). What holds it: a
    // question with none (a best candidate, an unreviewed or stale negative,
    // an answer resting on a limitation, a quick negative nobody attested),
    // and a defect a limitation only names: "looked, not found" is no end.
    // The stop policy decides only who else ends the run: a cap pauses or
    // stops it, and the operator stops it, whatever the questions' state
    // (paused, stopped; never completed). Under --stop operator nothing else
    // does, and nobody abandons.
    {
      const acceptedIds = (gate.questions ?? []).filter((q) => q.outcome === "accepted").map((q) => q.id);
      const byOperator = (l: string) => (gate.accepted ?? []).includes(l) || acceptedIds.some((id) => l.startsWith(`question:${id} `));
      const open = (gate.questions ?? []).filter((q) => q.outcome !== "answered" && q.outcome !== "accepted" && q.outcome !== "withdrawn" && !q.disposition);
      // A gate from before dispositions says nothing of what holds beside its questions: every line an operator did not take holds.
      const holding = gate.holding ?? gate.limited.filter((l: string) => !byOperator(l) && !open.some((q) => l.startsWith(`question:${q.id} `)));
      if (open.length || holding.length) {
        // Giving up is still a way out where the operator is not the only one who ends the run.
        if (abandon && !until) return { proceed: true, outcome: "abandoned", reasonPrefix: ABANDON_PREFIX, note: `the goal's checks pass, and ${open.length ? `${open.length} question(s) have no disposition under the bar` : "a defect a limitation only names stands"}; abandoned on purpose` };
        const qs = open.map((q) => `- question:${q.id} is ${q.outcome}, with no disposition under the bar: ${q.blocks.join("; ")}`).join("\n");
        // A question that must be established is never ended by a negative: its way is said instead of the negative path, or beside it.
        const required = open.filter((q) => q.must_establish);
        const path = required.length && required.length === open.length && !holding.length ? MUST_ESTABLISH_PATH_WORDS : `${NEGATIVE_PATH_WORDS}${required.length ? `. ${MUST_ESTABLISH_PATH_WORDS} (${required.map((q) => `question:${q.id}`).join(", ")})` : ""}`;
        return {
          proceed: false,
          failing: open[0] ? `question:${open[0].id}` : "(a defect a limitation names)",
          reason:
            (until
              ? `This run's stop is the operator's (--stop operator): no caps, no wall clock, and it ends when ${DISPOSITION_WORDS}; with no material lead open and no defect. `
              : `done finishes a run, whatever its stop policy, only when ${DISPOSITION_WORDS}; with no material lead open and no defect. A cap pauses or stops the run whatever the questions' state, and the operator may stop it: that end is stopped, never completed. `) +
            `${open.length ? `No disposition yet:\n${qs}\n` : ""}${holding.length ? `A defect is fixed, never only named:\n${holding.map((l) => `- ${l}`).join("\n")}\n` : ""}` +
            `${path}. Otherwise take another route (lead_open), or close a lead needs_operator when only the operator can unblock it. ` +
            (until ? "Only the operator can stop this run." : "If the goal cannot be met at all, call done again with abandon: true and say why on the board."),
        };
      }
    }
    const warned = gate.warnings?.length ? `warnings (not held on): ${gate.warnings.join("; ")}` : "";
    if (gate.limited.length) return { proceed: true, outcome: "examination_limited", note: [`examination-limited: ${gate.limited.join("; ")}`, warned].filter(Boolean).join("; ") };
    const note = [noChecks, warned].filter(Boolean).join("; ");
    return { proceed: true, outcome: "completed", ...(note ? { note } : {}) };
  }
  if (until && abandon) return { proceed: false, failing: "(until solved)", reason: UNTIL_SOLVED_NO_ABANDON };
  if (abandon) return { proceed: true, outcome: "abandoned", reasonPrefix: ABANDON_PREFIX, note: `${run.passed} of ${run.total} checks pass; abandoned on purpose` };
  const failed = run.checks.filter((c) => !c.ok);
  const failing = failed[0]?.cmd ?? "(unknown check)";
  // Each failing check, and what makes it pass. What the check said, when it
  // said something, verbatim: a check such as check-answers.ts names each
  // defect and its fix there (`out`, whole up to what the finish line hands
  // back; past that, its size and the way to read it all). Otherwise the
  // command itself, which is the test.
  const each = failed.length
    ? failed
        .map((c) => {
          const head = `- \`${c.cmd}\` ${c.timed_out ? "timed out" : "fails"}.`;
          const said = [c.out, c.fix, c.output].filter((t): t is string => typeof t === "string" && t.trim().length > 0).map((t) => t.trimEnd());
          if (said.length) return `${head} It says:\n${said.join("\n")}`;
          if (c.out_bytes) return `${head} It printed ${c.out_bytes} bytes; run it from the run's directory to read them.`;
          return `${head} Fix: ${c.timed_out ? "it has to finish within the check's time limit and succeed" : "make this command succeed when run from the run's directory"}`;
        })
        .join("\n")
    : "- the runner reported fewer passing checks than it ran, and named none";
  return {
    proceed: false,
    failing,
    reason:
      `The finish line is not met: ${run.passed} of ${run.total} checks pass. The harness ran the goal's checks when you called done; each that fails:\n${each}\n` +
      `done ends the whole swarm, not your slice. If your slice is finished, post it to the board and take the next one, or wait. ` +
      `If the finish line cannot be met, call done again with abandon: true and say why on the board.`,
  };
}

/** The first command word of a shell line, past env assignments and `cd x &&`. */
export function leadingCommand(command: string): string {
  let text = command.trim();
  // drop a leading `cd … &&` or `cd … ;`
  text = text.replace(/^cd\s+[^&;|\n]+(&&|;|\n)\s*/, "");
  // drop VAR=value prefixes
  text = text.replace(/^(?:[A-Za-z_][A-Za-z0-9_]*=[^\s]*\s+)+/, "");
  const word = text.split(/\s+/)[0] ?? "";
  const base = word.split("/").pop() ?? word;
  return /^[A-Za-z0-9_.+-]{1,40}$/.test(base) ? base : "";
}
