/**
 * The console's Jobs tab, as the server answers it: the run's tool jobs read
 * from the job service's journal (store/journal.jsonl). The fixture's
 * microVM run carries a store written with the store's own Journal and
 * sealTree (a command that ran, a tool that failed, one cancelled, an
 * examiner's note after custody); the cases it has no room for are built
 * here the same way. No VM starts, no model, no MCP server.
 */
import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { mkdir, mkdtemp, readFile, rm, symlink, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { after, before, test } from "node:test";
import { createUiApp, type UiApp } from "../scripts/ui/app.ts";
import { readStoreJob, readStoreJobLog, readStoreJobs, storeJobLogFile, utf8Boundary, type StoreJobDetail, type StoreJobsView } from "../scripts/ui/store-jobs.ts";
import { Journal, verifyJournalText } from "../scripts/evidence-store.ts";
import { seedFixtureRuns } from "../scripts/seed-fixture.ts";

const ROOT = join(dirname(fileURLToPath(import.meta.url)), "..");

let runsDir: string;
let scratch: string;
let app: UiApp;
let base: string;

async function get<T = unknown>(path: string): Promise<{ status: number; body: T; headers: Headers; text: string }> {
  const res = await fetch(`${base}${path}`);
  const text = await res.text();
  let body: unknown = text;
  try {
    body = JSON.parse(text);
  } catch {
    // raw body
  }
  return { status: res.status, body: body as T, headers: res.headers, text };
}

before(async () => {
  runsDir = await mkdtemp(join(tmpdir(), "swarm-ui-jobs-"));
  scratch = await mkdtemp(join(tmpdir(), "swarm-ui-jobs-scratch-"));
  await seedFixtureRuns(runsDir);
  app = createUiApp({
    root: ROOT,
    runsDir,
    distDir: join(runsDir, "no-dist"),
    models: async () => ({ source: "static", models: ["openai-codex/gpt-6-astra"] }),
    readiness: async () => ({ checked_at: "2026-09-26T00:00:00.000Z", providers: {} }),
    liveHubDirs: async () => [],
    heartbeatMs: 200,
  });
  const { port } = await app.listen(0, "127.0.0.1");
  base = `http://127.0.0.1:${port}`;
});

after(async () => {
  await app.close();
  // The fixture's inputs and sealed outputs are read-only, as a real run's are.
  for (const dir of [runsDir, scratch]) {
    execFileSync("chmod", ["-R", "u+w", dir]);
    await rm(dir, { recursive: true, force: true });
  }
});

test("a run with a job service: each job's outcome apart from its record, totals over all of them, the note and custody's store line", async () => {
  const { status, body: v } = await get<StoreJobsView>("/api/swarms/svm1d/jobs");
  assert.equal(status, 200);
  assert.equal(v.service, true);
  assert.equal(v.note, null);
  assert.deepEqual([v.journal?.intact, v.journal?.anchor, v.journal?.unparsed, v.journal?.partial_tail_bytes], [true, "matches", [], 0]);
  const sandbox = join(runsDir, "svm1d");
  assert.equal(v.journal?.lines, verifyJournalText(await readFile(join(sandbox, "store", "journal.jsonl"), "utf8")).lines.length, "every line of the journal is read");
  assert.deepEqual(v.jobs.map((j) => j.id), ["j000001", "j000002", "j000003"]);
  const [ran, failed, cancelled] = v.jobs;

  assert.deepEqual([ran.kind, ran.outcome, ran.state, ran.exit, ran.ran], ["command", "ok", "committed", 0, true]);
  assert.equal(ran.what, `grep -n 'shell.php' inputs/web/access.log > "$OUT/hits.tsv"`, "a command is named by its first line");
  assert.equal(ran.more_lines, 3, "and says how many more it has; the whole is in the record");
  assert.deepEqual(ran.requester, { agent: "svm1d00", name: "Scout", doing: "the access log" });
  assert.deepEqual([ran.outputs?.files, ran.outputs?.rejected, ran.outputs?.path], [2, 1, "store/jobs/j000001/out"]);
  assert.deepEqual([ran.duration_ms, ran.create_ms, ran.fenced, ran.worker_size, ran.network], [58_200, 3_400, true, "1 vCPU, 1024 MiB", "none"]);
  assert.deepEqual(ran.notified.map((n) => [n.to, n.how]), [["svm1d00", "status"]]);
  for (const t of [ran.accepted_at, ran.started_at, ran.finished_at, ran.committed_at]) assert.match(t ?? "", /^\d{4}-\d\d-\d\dT/);

  // Committed is where the output stands, not what the job did.
  assert.deepEqual([failed.kind, failed.what, failed.state, failed.status, failed.outcome, failed.exit, failed.reason], ["tool", "log_timeline", "committed", "failed", "failed", 2, "exit 2"]);
  assert.equal(failed.outputs?.files, 1, "a failed job's output is sealed all the same");

  assert.deepEqual([cancelled.state, cancelled.outcome, cancelled.ran, cancelled.outputs, cancelled.cancel_requested], ["cancelled", "cancelled", false, null, "svm1d02"]);
  assert.match(cancelled.reason ?? "", /cancelled by svm1d02 before it started/);

  assert.deepEqual([v.totals.jobs, v.totals.committed, v.totals.files, v.totals.rejected, v.totals.notes, v.totals.revisions], [3, 2, 3, 1, 1, 1]);
  assert.deepEqual(v.totals.by_outcome, { ok: 1, failed: 1, cancelled: 1 });
  assert.deepEqual(v.totals.by_state, { committed: 2, cancelled: 1 });

  const note = v.events.find((e) => e.type === "note");
  assert.equal(note?.by, "H. Examiner");
  assert.deepEqual(note?.jobs, ["j000002"]);
  assert.match(String(note?.text), /^j000002 failed on the log's quoting, not on the evidence: .* Its partial timeline is not relied on\.$/, "the note whole");

  assert.match(v.custody?.line ?? "", /^store: 3 jobs, 2 committed, journal 17 lines chain intact, its anchor matches, 3 of 3 output files verified/);
  assert.ok(v.custody?.at);
  assert.equal(v.custody?.journal_lines, (v.journal?.lines ?? 0) - 1, "the note came after custody read the journal, and that is visible");
});

test("a run without a store answers that it had no job service, in the same shape", async () => {
  const { status, body: v } = await get<StoreJobsView>("/api/swarms/s7a1c/jobs");
  assert.equal(status, 200);
  assert.equal(v.service, false);
  assert.match(v.note ?? "", /no job service: there is no store\/journal\.jsonl/);
  assert.deepEqual([v.journal, v.jobs, v.events, v.page.total, v.page.next, v.totals.jobs, v.totals.committed], [null, [], [], 0, null, 0, 0]);
  assert.equal(v.page.whole, "store/journal.jsonl");
});

test("the list is paged with offset and limit, the totals stay over the whole, and the page says where the whole is", async () => {
  const { body: v } = await get<StoreJobsView>("/api/swarms/svm1d/jobs?offset=1&limit=1");
  assert.deepEqual(v.jobs.map((j) => j.id), ["j000002"]);
  assert.deepEqual(v.page, { offset: 1, limit: 1, total: 3, next: 2, whole: "store/journal.jsonl" });
  assert.equal(v.totals.jobs, 3);
  const last = await get<StoreJobsView>("/api/swarms/svm1d/jobs?offset=2&limit=1");
  assert.deepEqual([last.body.jobs.map((j) => j.id), last.body.page.next], [["j000003"], null]);
});

test("one job: its journal lines as written, its record, a page of its manifest held to the journal, its logs with their recorded sha256", async () => {
  const { status, body: d } = await get<StoreJobDetail>("/api/swarms/svm1d/jobs/j000001?limit=1");
  assert.equal(status, 200);
  assert.deepEqual(d.lines.map((l) => l.type), ["job_accepted", "job_started", "job_finished", "job_fenced", "job_committed", "job_notified"]);
  const accepted = d.lines[0] as { spec: { command: string } };
  assert.equal(accepted.spec.command.split("\n").length, 4, "the command whole, every line of it");
  assert.equal((d.record as { id?: string }).id, "j000001");
  assert.equal(d.record_error, null);
  assert.deepEqual(d.trees, ["out"]);
  const m = d.manifest!;
  assert.deepEqual([m.present, m.matches_journal, m.totals, m.path], [true, true, { files: 2, bytes: 91 }, "store/jobs/j000001/manifest.json"]);
  assert.deepEqual(m.files.map((f) => f.path), ["clients.txt"]);
  assert.deepEqual(m.page, { offset: 0, limit: 1, total: 2, next: 1 });
  assert.deepEqual(m.rejected, [{ path: "passwd", kind: "symlink", link: "/etc/passwd" }], "a link it left is named, never followed");
  const second = await get<StoreJobDetail>("/api/swarms/svm1d/jobs/j000001?offset=1&limit=1");
  assert.deepEqual([second.body.manifest?.files.map((f) => f.path), second.body.manifest?.page.next], [["hits.tsv"], null]);

  const committed = d.lines.find((l) => l.type === "job_committed") as { logs: Record<string, string> };
  assert.deepEqual(d.logs.map((l) => [l.name, l.present, l.sha256]), [["stdout.log", true, committed.logs["stdout.log"]], ["stderr.log", true, committed.logs["stderr.log"]]]);

  // A job cancelled before it ran: nothing sealed, and no manifest pretended.
  const never = await get<StoreJobDetail>("/api/swarms/svm1d/jobs/j000003");
  assert.deepEqual([never.body.manifest, never.body.logs, never.body.trees], [null, [], []]);
});

test("a log comes a page at a time as JSON and whole as plain text; nothing else is reached through the route", async () => {
  const page = await get<{ offset: number; bytes: number; total: number; text: string; next: number | null; path: string }>("/api/swarms/svm1d/jobs/j000002/log/stderr.log?limit=16");
  assert.equal(page.status, 200);
  assert.deepEqual([page.body.offset, page.body.bytes, page.body.text, page.body.next, page.body.path], [0, 16, "Traceback (most ", 16, "store/jobs/j000002/stderr.log"]);
  const file = await readFile(join(runsDir, "svm1d", "store", "jobs", "j000002", "stderr.log"), "utf8");
  assert.equal(page.body.total, Buffer.byteLength(file));
  const whole = await get("/api/swarms/svm1d/jobs/j000002/log/stderr.log?raw=1");
  assert.equal(whole.status, 200);
  assert.equal(whole.text, file, "the whole log, byte for byte");
  assert.match(whole.headers.get("content-type") ?? "", /^text\/plain/);
  assert.match(whole.headers.get("content-security-policy") ?? "", /sandbox/);
  assert.match(whole.headers.get("content-disposition") ?? "", /^inline/);
  assert.match((await get("/api/swarms/svm1d/jobs/j000002/log/stderr.log?raw=1&download=1")).headers.get("content-disposition") ?? "", /^attachment/);

  for (const [path, want] of [
    ["/api/swarms/svm1d/jobs/j12", 400],
    ["/api/swarms/svm1d/jobs/j000009", 404],
    ["/api/swarms/svm1d/jobs/j000001/log/job.json", 400],
    ["/api/swarms/svm1d/jobs/j000001/log/..%2F..%2F..%2Fcustody.json", 400],
    ["/api/swarms/svm1d/jobs/j000001/log/stderr.log/more", 404],
    ["/api/swarms/svm1d/jobs/j000001?tree=..%2Fj000002%2Fout", 400],
    ["/api/swarms/s7a1c/jobs/j000001", 404],
  ] as const) {
    assert.equal((await get(path)).status, want, path);
  }
  const write = await fetch(`${base}/api/swarms/svm1d/jobs`, { method: "POST" });
  assert.equal(write.status, 405, "the job record is read-only from the console");
});

/** A sandbox of this test's own, its journal written with the store's Journal. */
async function scratchRun(name: string): Promise<{ S: string; journal: Journal }> {
  const S = join(scratch, name);
  await mkdir(join(S, "store", "jobs"), { recursive: true });
  return { S, journal: await Journal.open(S) };
}

const spec = (command: string) => ({ kind: "command", command, inputs: ["all"], timeout_seconds: 60, network: "off" });

test("a page of a log ends on a character boundary, and the pages put together are the log", async () => {
  const { S, journal } = await scratchRun("utf8");
  await journal.append({ type: "job_accepted", job: "j000001", spec: spec("printf"), requester: { agent: "a1" } });
  const text = `ab${"é".repeat(5)}😀z\n${"ş".repeat(40)}`;
  await mkdir(join(S, "store", "jobs", "j000001"), { recursive: true });
  await writeFile(join(S, "store", "jobs", "j000001", "stdout.log"), text);
  for (const limit of [4, 5, 7]) {
    let offset: number | null = 0;
    let joined = "";
    let pages = 0;
    while (offset !== null) {
      const page = await readStoreJobLog(S, "j000001", "stdout.log", { offset, limit });
      assert.ok(!("error" in page));
      assert.ok(!page.text.includes("�"), `page at ${offset} (limit ${limit}) splits no character: ${JSON.stringify(page.text)}`);
      assert.ok(page.bytes <= limit);
      joined += page.text;
      offset = page.next;
      pages += 1;
    }
    assert.equal(joined, text, `limit ${limit}: nothing lost between pages`);
    assert.ok(pages > 1);
  }
  assert.equal(utf8Boundary(Buffer.from("aé").subarray(0, 2)), 1, "a two-byte character cut after its first byte is left for the next page");
  assert.equal(utf8Boundary(Buffer.from("a😀").subarray(0, 4)), 1);
  assert.equal(utf8Boundary(Buffer.from("a😀")), 5, "a whole character is kept");
});

test("a journal being written, a line that is not JSON and a broken chain are said, and no job is dropped for them", async () => {
  const { S, journal } = await scratchRun("live");
  await journal.append({ type: "job_accepted", job: "j000001", spec: spec("sleep 60\ntrue"), requester: { agent: "a1", name: "Quill" } });
  await journal.append({ type: "job_started", job: "j000001", attempt: 1, worker: "dfs-x-job-j000001-1", image: "img", network: "none", cpus: 1, memory_mib: 512 });
  // The hub half way through its next line.
  const path = join(S, "store", "journal.jsonl");
  await writeFile(path, `{"v":1,"seq":2,"type":"job_fin`, { flag: "a" });
  const live = await readStoreJobs(S);
  assert.deepEqual([live.journal?.intact, live.journal?.lines, (live.journal?.partial_tail_bytes ?? 0) > 0, live.journal?.anchor], [true, 2, true, "matches"]);
  assert.match(live.note ?? "", /a line still being written/);
  assert.deepEqual([live.jobs[0].state, live.jobs[0].outcome, live.jobs[0].status, live.jobs[0].worker_size, live.jobs[0].more_lines], ["running", "running", null, "1 vCPU, 512 MiB", 1]);

  // The torn write finished as garbage, and a later line was written after it.
  await writeFile(path, `\n{"v":1,"seq":3,"at":"2026-09-26T10:00:00.000Z","type":"job_accepted","job":"j000002","spec":{"kind":"tool","tool":"t"},"requester":{"agent":"a2"},"prev":null}\n`, { flag: "a" });
  const broken = await readStoreJobs(S);
  assert.equal(broken.journal?.intact, false);
  assert.deepEqual(broken.journal?.unparsed, [3]);
  assert.match(broken.journal?.detail ?? "", /every line after it that parses is still shown/);
  assert.match(broken.note ?? "", /not JSON \(line 3\)/);
  assert.deepEqual(broken.jobs.map((j) => j.id), ["j000001", "j000002"], "the line past the break is still read");
});

test("the service's notices, a dedup answer, an interrupted attempt kept beside its retry, and a job never run", async () => {
  const { S, journal } = await scratchRun("notices");
  await journal.append({ type: "job_accepted", job: "j000001", spec: { kind: "recipe", recipe: "cfb/disk-volumes", target: { paths: ["/x"], name: "inputs/disk.E01" }, inputs: ["all"], network: "off" }, requester: { agent: "system", name: "harness" } });
  await journal.append({ type: "job_started", job: "j000001", attempt: 1, worker: "w1", image: "img", network: "none" });
  await journal.append({ type: "job_deduplicated", job: "j000001", by: { agent: "a2", name: "Comet" }, dedup_key: "k", notify: true });
  // The hub died while it ran: the attempt's output is kept under its own name, and the job runs again.
  await journal.append({ type: "job_fenced", job: "j000001", attempt: 1, fenced: true });
  await journal.append({ type: "job_committed", job: "j000001", attempt: 1, status: "interrupted", exit: null, reason: "the hub stopped while it ran", outputs: { manifest_sha256: "m", files: 1, bytes: 10, rejected: 0, path: "store/jobs/j000001/attempt-1-interrupted" }, logs: { "stdout.log": "s" } });
  await journal.append({ type: "job_retried", job: "j000001", attempt: 2, why: "interrupted by the hub's restart" });
  const retried = await readStoreJobs(S);
  const r = retried.jobs[0];
  assert.deepEqual([r.what, r.target, r.state, r.outcome, r.status, r.attempts], ["cfb/disk-volumes", "inputs/disk.E01", "accepted", "queued", null, 2]);
  assert.deepEqual(r.kept_attempts.map((a) => [a.attempt, a.status, a.path, a.files]), [[1, "interrupted", "store/jobs/j000001/attempt-1-interrupted", 1]]);
  assert.equal(r.deduplicated, 1);
  assert.equal(retried.totals.deduplicated, 1);
  assert.deepEqual(retried.events.map((e) => e.type), ["job_deduplicated"]);
  assert.equal(retried.totals.committed, 0, "a kept attempt is not the job's result");

  await journal.append({ type: "job_started", job: "j000001", attempt: 2, worker: "w2", image: "img", network: "none" });
  await journal.append({ type: "job_finished", job: "j000001", attempt: 2, exit: 124, status: "timed_out", reason: "stopped at its limit of 900s", duration_ms: 900_000 });
  await journal.append({ type: "job_fenced", job: "j000001", attempt: 2, fenced: false, error: "msb rm failed" });
  await journal.append({ type: "jobs_degraded", job: "j000001", in_a_row: 3, error: "no free worker slot" });
  await journal.append({ type: "job_accepted", job: "j000002", spec: spec("true"), requester: { agent: "a1" } });
  await journal.append({ type: "job_failed", job: "j000002", reason: "tool t's script does not match its manifest's sha256" });
  await journal.append({ type: "jobs_recovered", job: "j000002" });
  await journal.append({ type: "generation_committed", generation: "g0001", job: "j000001", recipe: "cfb/disk-volumes", status: "partial" });
  const later = await readStoreJobs(S);
  const [timed, never] = later.jobs;
  assert.deepEqual([timed.state, timed.outcome, timed.exit, timed.fenced, timed.fence_error, timed.attempts, timed.generation, timed.generation_status], ["finished", "timed_out", 124, false, "msb rm failed", 2, "g0001", "partial"]);
  assert.deepEqual([never.state, never.outcome, never.status, never.ran], ["failed", "not_run", null, false], "a job refused at its script step never ran, and is not called failed");
  assert.deepEqual([later.totals.degraded, later.totals.recovered, later.totals.generations], [1, 1, 1]);
  assert.deepEqual(later.totals.by_outcome, { timed_out: 1, not_run: 1 });
  assert.deepEqual(later.events.map((e) => e.type), ["job_deduplicated", "jobs_degraded", "jobs_recovered"]);
  const detail = (await readStoreJob(S, "j000001")) as StoreJobDetail;
  assert.deepEqual([detail.trees, detail.manifest?.tree], [["attempt-1-interrupted"], "attempt-1-interrupted"], "the kept attempt's tree is the one there is to open");
});

test("a link in a job's directory is not read, whatever it points at", async () => {
  const { S, journal } = await scratchRun("links");
  await journal.append({ type: "job_accepted", job: "j000001", spec: spec("true"), requester: { agent: "a1" } });
  const dir = join(S, "store", "jobs", "j000001");
  await mkdir(dir, { recursive: true });
  await symlink("/etc/hosts", join(dir, "stderr.log"));
  await symlink(join(S, "nowhere"), join(dir, "stdout.log"));
  await symlink("/etc/hosts", join(dir, "job.json"));
  assert.deepEqual(await storeJobLogFile(S, "j000001", "stderr.log"), { error: 409, message: "stderr.log is a link" });
  assert.deepEqual(await readStoreJobLog(S, "j000001", "stdout.log"), { error: 409, message: "stdout.log is a link" }, "a link to nothing is a link, not a missing file");
  const d = (await readStoreJob(S, "j000001")) as StoreJobDetail;
  assert.equal(d.record, null);
  assert.equal(d.record_error, "job.json is a link");
  assert.deepEqual(d.logs.map((l) => [l.name, l.present, l.why]), [["stdout.log", false, "a link"], ["stderr.log", false, "a link"]]);
  // A job's whole directory swapped for a link.
  await journal.append({ type: "job_accepted", job: "j000002", spec: spec("true"), requester: { agent: "a1" } });
  await mkdir(join(scratch, "elsewhere"), { recursive: true });
  await writeFile(join(scratch, "elsewhere", "stdout.log"), "not the job's\n");
  await symlink(join(scratch, "elsewhere"), join(S, "store", "jobs", "j000002"));
  assert.deepEqual(await readStoreJobLog(S, "j000002", "stdout.log"), { error: 409, message: "stdout.log is a link" });
  // And the journal itself.
  const { S: S2 } = await scratchRun("journal-link");
  await rm(join(S2, "store", "journal.jsonl"), { force: true });
  await symlink(join(S, "store", "journal.jsonl"), join(S2, "store", "journal.jsonl"));
  const linked = await readStoreJobs(S2);
  assert.deepEqual([linked.service, linked.jobs, linked.journal], [true, [], null]);
  assert.match(linked.note ?? "", /store\/journal\.jsonl was not read: a link/);
});
