/**
 * Coverage and grounding over the worker-VM flow (scripts/coverage.ts): an
 * agent there reads the evidence only through jobs, so a job request counts
 * as naming a file when its arguments carry the path or its `inputs` list
 * declares it, and an entry whose source may lie inside an input is grounded
 * through a job it cites that was given the input. Both say "named" or "was
 * given", never "examined".
 */
import assert from "node:assert/strict";
import { mkdir, mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "node:test";
import { coverageLine, coverageOf, declaredInput, groundingDetail, isCommand, readJobDeclarations } from "../scripts/coverage.ts";

const T = (s: string) => `2026-01-01T00:${s}Z`;

async function jobsSandbox(): Promise<string> {
  const root = await mkdtemp(join(tmpdir(), "coverage-jobs-"));
  await mkdir(join(root, "traces"), { recursive: true });
  await mkdir(join(root, "ledger"), { recursive: true });
  const file = (path: string) => ({ path, bytes: 10, sha256: "a".repeat(64) });
  await writeFile(
    join(root, "inputs.json"),
    JSON.stringify({
      source: "/ev",
      copied_at: "t",
      held: "copy",
      // A split image (E01 to E03), a memory image, a file only a catalogue
      // request names, one nothing names, and a directory of mail.
      files: [file("inputs/disk.E01"), file("inputs/disk.E02"), file("inputs/disk.E03"), file("inputs/mem.raw"), file("inputs/notes.txt"), file("inputs/quiet.bin"), file("inputs/mail/a.eml")],
      bytes: 70,
      enforce: "auto",
      guard: "none",
    }),
  );
  const line = (ts: string, agent: string, tool: string, args: Record<string, unknown>) => JSON.stringify({ ts: T(ts), agent, tool, args, result: { ok: true } });
  await writeFile(
    join(root, "traces", "events.jsonl"),
    [
      // Names disk.E01 twice over: a tool argument and a declared input.
      line("00:01", "s100", "job_run", { tool: "ad1_extract", args: { image: "inputs/disk.E01" }, inputs: ["input:disk.E01"] }),
      // Names mem.raw by declaration alone.
      line("00:02", "s100", "job_run", { command: "vol windows.pslist", inputs: ["input:mem.raw"] }),
      // Names nothing: all, a job's output, and a command that only talks about an input.
      line("00:03", "s101", "job_run", { command: "ls /job", inputs: ["all"] }),
      line("00:04", "s101", "job_run", { command: "echo input:quiet.bin inputs-quiet.bin", inputs: ["job:j000001/out/members.tsv"] }),
      // A status call carries a job id and names no file.
      line("00:05", "s101", "job_status", { job_id: "j000001" }),
      // A catalogue request names its target; a directory declared names the directory.
      line("00:06", "s102", "catalog_request", { target: "input:notes.txt", recipe: "tool:x" }),
      line("00:07", "s102", "job_run", { command: "ls", inputs: ["input:mail/"] }),
      // The harness's own line, and a post, are not commands.
      line("00:08", "system", "job_run", { command: "x", inputs: ["input:quiet.bin"] }),
      line("00:09", "s101", "post", { body: "look at inputs/quiet.bin" }),
    ].join("\n") + "\n",
  );
  const job = (id: string, started: string, spec: Record<string, unknown>) =>
    mkdir(join(root, "store", "jobs", id), { recursive: true }).then(() =>
      writeFile(join(root, "store", "jobs", id, "job.json"), JSON.stringify({ id, state: "committed", accepted_at: T(started), started_at: T(started), spec: { kind: "tool", timeout_seconds: 60, network: "off", ...spec } })),
    );
  await job("j000001", "00:01", { scope: "declared", inputs: ["input:disk.E01"] });
  await job("j000002", "00:10", { scope: "declared", inputs: ["job:j000001/out/members.tsv"] });
  await job("j000003", "00:03", { scope: "all", inputs: ["all"] });
  await job("j000004", "00:04", { scope: "declared", inputs: ["work/s101/notes.md"] });
  await job("j000005", "00:20", { scope: "declared", inputs: ["inputs/mem.raw"] });
  const entry = (seq: number, source: string, at: string, refs?: string[]) =>
    JSON.stringify({ v: 4, seq, kind: "finding", value: `v${seq}`, source, evidence: "e", ...(refs ? { refs } : {}), by: "s100", authors: ["s100"], at: T(at) });
  const member = "private/var/mobile/Library/Safari/History.db";
  await writeFile(
    join(root, "ledger", "entries.jsonl"),
    [
      // A member path no call named; the entry cites a job given the image.
      entry(1, member, "00:30", ["job:j000001/out/members.tsv"]),
      // Through the output of that job, a later job's.
      entry(2, member, "00:30", ["job:j000002/out/hits.json"]),
      // The cited job was given everything, which names no input.
      entry(3, member, "00:30", ["job:j000003/out/x.json"]),
      // The cited job read a file of the agents' work, not the evidence.
      entry(4, member, "00:30", ["job:j000004/out/x.json"]),
      // Cites nothing.
      entry(5, member, "00:30"),
      // The job started after the entry was recorded.
      entry(6, member, "00:15", ["job:j000005/out/x.json"]),
      // A path of the run's own is not a path inside an input.
      entry(7, "store/jobs/j000001/stderr.log", "00:30", ["job:j000001/out/members.tsv"]),
      // A call named it: not counted as through a job.
      entry(8, "inputs/disk.E01", "00:30", ["job:j000001/out/members.tsv"]),
      // Prose is not a path.
      entry(9, "memory strings, TCP/IP stack", "00:30", ["job:j000001/out/members.tsv"]),
    ].join("\n") + "\n",
  );
  return root;
}

test("a job request names a file when its arguments carry the path or its inputs declare it, and a split image's other segments stay unnamed", async () => {
  const root = await jobsSandbox();
  try {
    const c = await coverageOf(root);
    assert.equal(c.unavailable, null);
    assert.deepEqual(c.untouched, ["inputs/disk.E02", "inputs/disk.E03", "inputs/quiet.bin", "inputs/mail/a.eml"]);
    assert.deepEqual(c.touched, { "inputs/disk.E01": 1, "inputs/mem.raw": 1, "inputs/notes.txt": 1 });
    // A declared directory names the directory, which a walk may have read, and no file in it.
    assert.deepEqual(c.under_named_dir, { "inputs/mail/a.eml": 1 });
    // job_run x5 counted (the system line and the post are not), the catalogue request too; job_status is not a command.
    assert.equal(c.calls_scanned, 6);
    assert.match(coverageLine(c), /^4 of 7 evidence files named by no command or job request on the trace \(6 calls matched\); 1 of those sits under a directory a command named, which a walk may have read\. A file a command named, or a job request listed as an input, was not necessarily examined\.$/);
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test("a job request that does not name a file leaves it untouched", async () => {
  const root = await jobsSandbox();
  try {
    const c = await coverageOf(root);
    assert.ok(c.untouched.includes("inputs/quiet.bin"), "inputs: [all], a job's output, prose and the harness's own line name nothing");
    assert.equal(isCommand({ ts: T("00:05"), agent: "s101", tool: "job_status", args: { job_id: "j000001" } } as never), false);
    assert.equal(isCommand({ ts: T("00:01"), agent: "s101", tool: "job_run", args: {} } as never), true);
    assert.equal(isCommand({ ts: T("00:01"), agent: "s101", tool: "catalog_request", args: {} } as never), true);
    assert.equal(isCommand({ ts: T("00:01"), agent: "system", tool: "job_run", args: {} } as never), false);
    assert.deepEqual(declaredInput("input:disk.E01"), ["disk.E01"]);
    assert.deepEqual(declaredInput("input:inputs/mail/"), ["mail/"]);
    assert.deepEqual(declaredInput("input:"), [""]);
    assert.deepEqual(declaredInput("echo input:disk.E01"), []);
    assert.deepEqual(declaredInput("all"), []);
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test("an entry whose source may lie inside an input is grounded through a job it cites that was given the input, and only so", async () => {
  const root = await jobsSandbox();
  try {
    const jobs = await readJobDeclarations(root);
    assert.deepEqual(jobs.get("j000001")?.inputs, ["disk.E01"]);
    assert.deepEqual(jobs.get("j000002")?.from, ["j000001"]);
    assert.deepEqual(jobs.get("j000003"), { at: Date.parse(T("00:03")), inputs: [], from: [] }, "a scope of all names nothing");
    assert.deepEqual(jobs.get("j000004")?.inputs, [], "a work path is not evidence");
    const c = await coverageOf(root);
    assert.deepEqual(c.grounding, {
      "1": "grounded",
      "2": "grounded",
      "3": "not in the trace",
      "4": "not in the trace",
      "5": "not in the trace",
      "6": "not in the trace",
      "7": "not in the trace",
      "8": "grounded",
      "9": "not a path",
    });
    assert.deepEqual(c.grounded_via_job, ["1", "2"], "entry 8 was named by a call, not grounded through a job");
    // Without the jobs the same entries are only what the calls name.
    const ledger = Array.from({ length: 1 }, () => ({ v: 4, seq: 1, kind: "finding", value: "v", source: "Users/x/y.db", evidence: "e", refs: ["job:j000001/out"], by: "s", authors: ["s"], at: T("00:30") })) as never[];
    assert.deepEqual(groundingDetail(ledger, [], undefined), { grounding: { "1": "not in the trace" }, via_job: [] });
    assert.deepEqual(groundingDetail(ledger, [], jobs), { grounding: { "1": "grounded" }, via_job: ["1"] });
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});
