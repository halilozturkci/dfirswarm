/**
 * The harness measures of swarm.sh metrics (docs/usage.md, "Harness measures"), over synthetic runs written by hand:
 * when an answer's value was first in front of a seat (a job's answer, through its sighting digest; a file read kept
 * whole; never), that no value is ever printed, and that one command prints every measure or says why it cannot.
 */
import test from "node:test";
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { mkdirSync, mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { answerKey, answerPieces, digestHolds, sightingDigest, SIGHTING_MAX } from "../extensions/sighting.ts";
import { firstSightings, frictionMetrics } from "../scripts/friction-metrics.ts";
import { measureRun, metricsText } from "../scripts/metrics.ts";

const ROOT = join(import.meta.dirname, "..");
const T = (hms: string) => `2026-10-02T${hms}.000Z`;
const lines = (rows: Array<Record<string, unknown>>) => rows.map((r) => `${JSON.stringify(r)}\n`).join("");

function write(S: string, rel: string, text: string): void {
  mkdirSync(join(S, rel, ".."), { recursive: true });
  writeFileSync(join(S, rel), text);
}

// Invented values: nothing here comes from a case.
const PATH_VALUE = "`C:\\Users\\bob\\AppData\\evil-dropper.exe`\nprefetch shows it ran";
const NEVER = "never-seen-host-77";
const SECRET = "S3cretPassw0rd!x";

const answer = (seq: number, at: string, by: string, section: string, value: string, extra: Record<string, unknown> = {}) => ({ v: 4, seq, kind: "answer", value, source: "s", evidence: "e", by, authors: [by], at: T(at), hash: `h${seq}`, section: `question:${section}`, result: "established", reasoning: "r", ...extra });

/** A run whose job answer held a value 12 minutes before it was recorded, another value never seen, and a secret seen in a file read. */
function fullRun(): string {
  const S = mkdtempSync(join(tmpdir(), "first-sighting-"));
  const jobAnswer = { ok: true, id: "j000004", state: "committed", stdout: { text: "pid\tpath\n4242\tC:\\Users\\bob\\AppData\\evil-dropper.exe\n", next: null } };
  write(S, "ledger/entries.jsonl", lines([
    answer(1, "10:10:00", "a1", "1", "C:\\Windows\\notepad.exe"),
    answer(2, "10:20:00", "a1", "1", PATH_VALUE, { supersedes: 1 }),
    answer(3, "10:30:00", "a3", "1", PATH_VALUE, { supersedes: 2, reasoning: "restated" }),
    answer(4, "10:25:00", "a2", "2", NEVER),
    answer(5, "10:03:00", "a1", "3", SECRET),
    answer(6, "10:04:00", "a2", "4", "yes"),
  ]));
  write(S, "traces/events.jsonl", lines([
    { ts: T("10:00:00"), agent: "a2", tool: "read", args: { path: "work/a2/notes.txt" }, result: { ok: true, output: `user: admin\npassword: ${SECRET}\n`, output_chars: 40 } },
    { ts: T("10:01:00"), agent: "a1", tool: "record", args: {}, result: { ok: false, reason: "x" } },
    { ts: T("10:01:10"), agent: "a1", tool: "record", args: {}, result: { ok: false, reason: "y" } },
    { ts: T("10:01:20"), agent: "a1", tool: "record", args: {}, result: { ok: true } },
    { ts: T("10:02:00"), agent: "a1", tool: "job_run", args: { tool: "pslist" }, result: { ok: true, job: "j000004", state: "running", answer_chars: 2000, hint_chars: 800, library_chars: 600, sighted: sightingDigest({ ok: true, job: "j000004", state: "running" }) } },
    { ts: T("10:02:05"), agent: "a1", tool: "tools", args: {}, result: { ok: true, n: 40, loaded: 0, answer_chars: 3000 } },
    { ts: T("10:03:00"), agent: "a2", tool: "wait", args: {}, result: { reason: "timeout", waited_ms: 60000, n: 0 } },
    { ts: T("10:04:00"), agent: "a2", tool: "wait", args: {}, result: { reason: "posts", waited_ms: 30000, n: 2 } },
    { ts: T("10:08:00"), agent: "a1", tool: "job_status", args: { job_id: "j000004" }, result: { ok: true, state: "committed", answer_chars: JSON.stringify(jobAnswer).length, sighted: sightingDigest(jobAnswer) } },
    { ts: T("10:09:00"), agent: "system", tool: "hub_health", args: {}, result: { ok: true, loop_p99_ms: 120, heap_used_mb: 1000, heap_limit_mb: 4000 } },
    { ts: T("10:12:00"), agent: "a1", tool: "compact_done", args: {}, result: { ok: true, summary_chars: 0 } },
    { ts: T("10:15:00"), agent: "system", tool: "seat_down", args: { agent: "a3" }, result: { ok: true } },
    { ts: T("10:40:00"), agent: "a1", tool: "bash", args: { command: "grep -r evil-dropper" }, result: { ok: true, output: "C:\\Users\\bob\\AppData\\evil-dropper.exe\n" } },
    { ts: T("11:00:00"), agent: "a2", tool: "bash", args: { command: "ls" }, result: { ok: true, output: "x\n" } },
  ]));
  write(S, "store/journal.jsonl", lines([
    { at: T("10:02:00"), type: "job_accepted", job: "j000004" },
    { at: T("10:02:01"), type: "job_started", job: "j000004" },
    { at: T("10:05:00"), type: "job_finished", job: "j000004" },
    { at: T("10:05:01"), type: "job_fenced", job: "j000004", fenced: true },
    { at: T("10:07:01"), type: "job_committed", job: "j000004", outputs: { files: 20000 } },
    { at: T("10:08:00"), type: "job_notified", job: "j000004", to: "a1", how: "status" },
  ]));
  // The gateway logs each call when it ends, with its duration: a1's request started 4 s after its record answered.
  write(S, "traces/model-gateway.jsonl", lines([
    { at: T("10:00:30"), seat: "a1", provider: "p", model: "p/m", status: 200, input: 10, output: 5, cost_usd: 0, ms: 20000 },
    { at: T("10:01:44"), seat: "a1", provider: "p", model: "p/m", status: 200, input: 10, output: 5, cost_usd: 0, ms: 20000 },
    { at: T("10:01:50"), seat: "a1", refused: "cap" },
  ]));
  return S;
}

test("a value first held by a job's answer 12 minutes before its record, a value never seen, and a secret seen in a file read", async () => {
  const S = fullRun();
  const m = await measureRun(S);
  const fs = m.first_sighting!;
  const by = (section: string) => fs.answers.find((x) => x.section === section)!;
  assert.deepEqual(by("1"), { section: "1", id: null, answer: "E-3", status: "seen", minutes: 12, kind: "job_status answer", same_seat: true }, "from the job's answer at 10:08 to the first record with that value (E-2 at 10:20), not the restatement");
  assert.equal(by("2").status, "not_seen");
  assert.equal(by("2").minutes, null);
  assert.deepEqual(by("3"), { section: "3", id: null, answer: "E-5", status: "seen", minutes: 3, kind: "file read", same_seat: false });
  assert.equal(by("4").status, "not_matchable", "a value under four characters says nothing by being seen");
  assert.deepEqual([fs.seen, fs.median_minutes, fs.max_minutes, fs.rows_without_text], [2, 12, 12, 0]);
  const text = metricsText(m);
  const json = JSON.stringify(m);
  for (const v of [SECRET, SECRET.toLowerCase(), NEVER, "evil-dropper", "notepad"]) {
    assert.ok(!text.includes(v), `the table never prints a value (${v})`);
    assert.ok(!json.includes(v), `nor does the JSON (${v})`);
  }
  assert.match(text, /Minutes from first sighting to answer\s+2 of 4 answer\(s\) seen in a tool result at or before their record: median 12 min, max 12 min; question:1 E-3 12 min \(job_status answer, its own seat\); question:2 E-4 not seen in a tool result the trace holds; question:3 E-5 3 min \(file read, another seat\); question:4 E-6 not matchable/);
});

test("one command prints every harness measure, with its figure", () => {
  const S = fullRun();
  const r = spawnSync(process.execPath, ["--experimental-strip-types", "--no-warnings", join(ROOT, "scripts", "metrics.ts"), S], { encoding: "utf8" });
  assert.equal(r.status, 0, r.stderr);
  const out = r.stdout;
  const row = (name: string) => out.split("\n").find((l) => l.startsWith(name)) ?? assert.fail(`no ${name} row in:\n${out}`);
  assert.match(out, /Harness measures/);
  assert.match(row("Job result delivery time"), /median 180 s, p90 180 s, max 180 s over 1 job\(s\); 0 finished job\(s\) never told/);
  assert.match(row("Sealing time for large extractions"), /1 job\(s\) of 10000 files or more, from the fence to the commit: median 120 s, max 120 s \(the largest 20000 files\)/);
  assert.match(row("Hub heap and loop delay"), /loop p99 at most 120 ms, heap at most 25% of its limit \(1 sample\(s\)\)/);
  assert.match(row("Seat-down events"), /1 down, 0 started again, 0 recorded dead/);
  assert.match(row("Refusals per accepted record"), /2 \(2 refused for 1 accepted\)/);
  assert.match(row("Records needing two or more refusals"), /1 record\(s\) accepted after two or more refusals in a row; the longest run of refusals 2/);
  assert.match(row("job_run result text and hint share"), /1 answer\(s\), 2000 characters; hints at admission 40% of them, the library hint 30%/);
  assert.match(row("Library share"), /the library hint \(600 characters\) and the tools listings \(3000\) are \d+% of the \d+ characters of tool answers/);
  assert.match(row("Gap before a model call"), /median 4 s, p90 4 s, max 4 s over 1 request\(s\)/);
  assert.match(row("Compactions per seat-hour"), /\(1 compaction\(s\), 0 failed\)/);
  assert.match(row("Minutes from first sighting to answer"), /2 of 4 answer\(s\) seen/);
  assert.match(row("Idle waits"), /1 of 2 wait\(s\) ended with nothing delivered: 60 s, \d+% of seat time; all waits 90 s/);
  assert.match(row("Empty summaries"), /1 of 1 compaction\(s\) that give their summary's size/);
  assert.match(row("Largest answer"), /characters \(/);
  assert.ok(!out.includes(SECRET) && !out.includes(NEVER));
  const j = spawnSync(process.execPath, ["--experimental-strip-types", "--no-warnings", join(ROOT, "scripts", "metrics.ts"), S, "--json"], { encoding: "utf8" });
  const measures = (JSON.parse(j.stdout) as { measures: Array<{ measure: string; measured: boolean }> }).measures;
  assert.equal(measures.length, 14);
  assert.ok(measures.every((x) => x.measured), JSON.stringify(measures.filter((x) => !x.measured)));
});

test("a run whose registers cannot give a measure says so, never a zero", async () => {
  const S = mkdtempSync(join(tmpdir(), "first-sighting-bare-"));
  write(S, "ledger/entries.jsonl", lines([answer(1, "10:20:00", "a1", "1", "value-from-an-old-run")]));
  // A run from before the digests: its job answers carry their size only.
  write(S, "traces/events.jsonl", lines([
    { ts: T("10:00:00"), agent: "a1", tool: "job_status", args: {}, result: { ok: true, state: "committed" } },
    { ts: T("10:01:00"), agent: "a1", tool: "job_run", args: {}, result: { ok: true, job: "j000001" } },
    { ts: T("10:02:00"), agent: "a1", tool: "compact_done", args: {}, result: { ok: true } },
  ]));
  const text = metricsText(await measureRun(S));
  const row = (name: string) => text.split("\n").find((l) => l.startsWith(name)) ?? assert.fail(`no ${name} row`);
  assert.match(row("Job result delivery time"), /not measured: no store\/journal\.jsonl/);
  assert.match(row("Hub heap and loop delay"), /not measured: no hub_health rows/);
  assert.match(row("Gap before a model call"), /not measured: no model gateway log/);
  assert.match(row("Library share"), /not measured: no job_run row gives library_chars/);
  assert.match(row("job_run result text and hint share"), /not measured: no job_run row gives its answer's size/);
  assert.match(row("Empty summaries"), /not measured: no compaction row gives its summary's size/);
  assert.match(row("Minutes from first sighting to answer"), /0 of 1 answer\(s\) seen.*not seen in a tool result the trace holds; 2 job answer row\(s\) carry neither text nor a sighting digest/);
  const none = mkdtempSync(join(tmpdir(), "first-sighting-none-"));
  write(none, "ledger/entries.jsonl", lines([answer(1, "10:20:00", "a1", "1", "x-value")]));
  const t2 = metricsText(await measureRun(none));
  assert.match(t2, /Minutes from first sighting to answer\s+not measured: no readable traces\/events\.jsonl/);
  assert.match(t2, /Seat-down events\s+not measured: no readable traces\/events\.jsonl/);
});

test("the sighting digest: a value is found by its key, the digest holds no text, and it is bounded", () => {
  const answerText = { ok: true, stdout: { text: "Name\tValue\nhostname: WS-ACCT-07\n\"user\",\"S-1-5-21-1111-2222-3333-1001\"\n" } };
  const d = sightingDigest(answerText)!;
  for (const v of ["WS-ACCT-07", "**ws-acct-07**", "S-1-5-21-1111-2222-3333-1001"]) assert.ok(digestHolds(d, answerKey(v)!), v);
  assert.ok(!digestHolds(d, answerKey("WS-ACCT-08")!));
  assert.ok(!JSON.stringify(d).toLowerCase().includes("acct"), "only digests");
  assert.match(d.d, /^[0-9a-f]+$/);
  const big = sightingDigest({ text: Array.from({ length: 5000 }, (_, i) => `token-${i}`).join("\n") })!;
  assert.equal(big.n, SIGHTING_MAX);
  assert.equal(big.d.length, SIGHTING_MAX * 8);
  assert.equal(big.cut, true);
  assert.equal(answerKey("ab"), null);
  assert.equal(answerKey("  \n"), null);
});

test("a value of two pieces is in front of a seat once both have been", () => {
  const q = "Which file dropped the payload? Format: *Name_md5(file)*";
  const value = "dropper.exe_0123456789abcdef0123456789abcdef";
  const pieces = answerPieces(value, q)!;
  assert.deepEqual(pieces, ["dropper.exe", "0123456789abcdef0123456789abcdef"]);
  const ev = (ts: string, agent: string, output: string) => ({ ts: T(ts), agent, tool: "bash", args: {}, result: { ok: true, output } }) as never;
  const s = firstSightings(
    [ev("10:00:00", "a1", "found dropper.exe in prefetch"), ev("10:05:00", "a2", "md5 0123456789abcdef0123456789abcdef  dropper.exe")],
    [{ section: "1", id: "Q-1", answer: "E-1", by: "a1", at: Date.parse(T("10:15:00")), key: answerKey(value), pieces }],
  );
  assert.deepEqual(s.answers[0], { section: "1", id: "Q-1", answer: "E-1", status: "seen_in_pieces", minutes: 10, kind: "shell output", same_seat: false });
  const after = firstSightings([ev("10:20:00", "a1", "dropper.exe_0123456789abcdef0123456789abcdef")], [{ section: "1", id: null, answer: "E-1", by: "a1", at: Date.parse(T("10:15:00")), key: answerKey(value), pieces: null }]);
  assert.equal(after.answers[0]!.status, "seen_after");
  assert.equal(after.answers[0]!.kind, "shell output");
});

test("a value inside a longer word or number is not a sighting", () => {
  const ev = (output: string) => ({ ts: T("10:00:00"), agent: "a1", tool: "read", args: {}, result: { ok: true, output } }) as never;
  const a = [{ section: "1", id: null, answer: "E-1", by: "a1", at: Date.parse(T("10:10:00")), key: answerKey("10.0.0.5"), pieces: null }];
  assert.equal(firstSightings([ev("peer 110.0.0.55 and 10.0.0.50")], a).answers[0]!.status, "not_seen");
  assert.equal(firstSightings([ev("peer=10.0.0.5:443")], a).answers[0]!.status, "seen");
});

test("friction: the gap before a model call counts only requests that follow a tool result after the previous call", () => {
  const ev = (ts: string, tool: string) => ({ ts: T(ts), agent: "a1", tool, args: {}, result: { ok: true } }) as never;
  const f = frictionMetrics([ev("10:00:10", "read"), ev("10:00:12", "bash"), ev("10:00:30", "thinking")], [], {
    calls: [
      { seat: "a1", start: Date.parse(T("10:00:00")), end: Date.parse(T("10:00:09")) },
      { seat: "a1", start: Date.parse(T("10:00:15")), end: Date.parse(T("10:00:29")) },
      { seat: "a1", start: Date.parse(T("10:00:31")), end: Date.parse(T("10:00:40")) },
    ],
  });
  assert.deepEqual(f.model_gap, { source: "model-gateway", calls: 1, median_s: 3, p90_s: 3, max_s: 3 }, "the third request followed only the model's own thinking row");
  assert.equal(frictionMetrics([], []).model_gap.source, null);
});
