/**
 * The clocks of the macos-forensics tools: knowledgec_query stops at its own deadline with a lossless partial and the way to go on,
 * fsevents_parse reads the gzip members of a file in linear time and stops at its own deadline, its `contains` runs only a restricted subset of
 * regular expressions, and unified_log takes staging and the census out of the reader's time.
 */
import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { mkdir, readFile, stat, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { test } from "node:test";
import { runPySnippet, withCwd } from "./tool-library-harness.ts";
import { CREATED, FS, KC, body, dbCopy, fsDir, fsPage, fsRecord, gz, kcDb, logarchive, measured, ok, tool, ul, ulStandin } from "./macos-pack-harness.ts";
import type { Json } from "./macos-pack-harness.ts";

const lines = async (file: string): Promise<Json[]> => (await readFile(file, "utf8")).trimEnd().split("\n").filter(Boolean).map((l) => JSON.parse(l) as Json);

// ---- knowledgec_query: a deadline, a lossless partial, the way to go on -----------------------------------------------------------------------

test("knowledgec_query stops at max_seconds, says partial with the way to go on, keeps the rows it read, and a second run from resume_since reads the rest", async () => {
  // It had no clock: a database of 2.3 million rows was still being read at the 125 s cap of the review, with no JSON and a 2.7 GB partial file.
  await withCwd(async (cwd) => {
    const rows = 40_000;
    const db = await kcDb(cwd, "k.db", rows, 25);
    let first: Json | null = null;
    for (let seconds = 0.3; seconds < 20; seconds *= 2) {
      const run = await tool(KC, cwd, { db, max_seconds: seconds, out_file: `work/first-${seconds}.jsonl` });
      assert.equal(run.code, 0, run.stderr + run.stdout);
      const answer = body(run);
      assert.ok(answer.limits.seconds_used < seconds + 8, `${answer.limits.seconds_used} s for max_seconds ${seconds}`);
      assert.equal(answer.status, "partial", "a deadline that passes is not a complete read");
      assert.ok(answer.entry_count < rows, `${answer.entry_count} of ${rows}`);
      if (answer.entry_count > 0) {
        first = { ...answer, file: `work/first-${seconds}.jsonl` };
        break;
      }
      assert.ok(answer.resume.to_go_on, "even with nothing read, the answer says what to do");
    }
    assert.ok(first, "some rows were read within a few seconds");
    assert.match(first.status_basis, /max_seconds/);
    const prefix = await lines(join(cwd, first.file));
    assert.equal(prefix.length, first.entry_count, "every row it counted is in the file, and the file holds no more");
    assert.deepEqual(prefix.map((r) => r.z_pk), Array.from({ length: prefix.length }, (_, i) => i + 1), "a prefix of the result in start order");
    assert.equal(first.resume.rows_read, prefix.length);
    assert.equal(first.resume.stopped_after_z_pk, prefix.length);
    assert.equal(typeof first.resume.resume_since, "string");
    assert.ok(first.problems.some((p: string) => /stopped on the clock/.test(p)));
    // The rest: since = resume_since (a microsecond before the last start read), with room to finish.
    const rest = ok(await tool(KC, cwd, { db, since: first.resume.resume_since, max_seconds: 90, out_file: "work/rest.jsonl" }));
    assert.equal(rest.status, "complete");
    const seen = new Set<number>([...prefix.map((r) => r.z_pk), ...(await lines(join(cwd, "work/rest.jsonl"))).map((r) => r.z_pk)]);
    assert.equal(seen.size, rows, "the two runs together hold every row: none is skipped between them");
  });
});

test("knowledgec_query clamps max_seconds below the manifest's timeout and refuses one that is not a number", async () => {
  await withCwd(async (cwd) => {
    const db = await kcDb(cwd, "k.db", 20);
    const answer = ok(await tool(KC, cwd, { db, max_seconds: 100000 }));
    assert.equal(answer.limits.max_seconds, 90);
    assert.equal(answer.limits.max_seconds_requested, 100000);
    const refused = await tool(KC, cwd, { db, max_seconds: "soon" });
    assert.equal(refused.code, 1);
    assert.match(body(refused).error, /max_seconds/);
  });
});

// ---- fsevents_parse: linear in the number of gzip members, a deadline ------------------------------------------------------------------------

/** A file of `n` gzip members, each one a page header with no record (12 bytes), written by Python's gzip module. */
const MEMBERS = `
import gzip, struct, sys
page = b"1SLD" + b"\\0" * 4 + struct.pack("<I", 12)
data = b"".join(gzip.compress(page, 1) for _ in range(int(sys.argv[2])))
open(sys.argv[1], "wb").write(data)
`;

async function memberFile(cwd: string, n: number): Promise<string> {
  const out = await runPySnippet(MEMBERS, [join(cwd, "work", `m${n}`), String(n)], null);
  assert.equal(out.code, 0, out.stderr);
  return `work/m${n}`;
}

test("fsevents_parse reads a file of many gzip members in linear time: 4 times the members is about 4 times the CPU, not 16", async () => {
  // member_at() rebuilt a list of every member's offset for every page: 100,000 members took 46 s.
  await withCwd(async (cwd) => {
    const small = await measured(FS, cwd, { path: await memberFile(cwd, 20_000), out_file: "work/o1.jsonl" });
    const large = await measured(FS, cwd, { path: await memberFile(cwd, 80_000), out_file: "work/o2.jsonl" });
    for (const run of [small, large]) assert.equal(JSON.parse(run.stdout).coverage.members.complete, run === small ? 20_000 : 80_000);
    assert.ok(large.cpu < Math.max(8, small.cpu * 9), `20,000 members ${small.cpu.toFixed(2)} s of CPU, 80,000 ${large.cpu.toFixed(2)} s: that is not linear`);
    assert.ok(large.cpu < 20, `${large.cpu.toFixed(2)} s of CPU for 80,000 members`);
  });
});

test("fsevents_parse stops at max_seconds: partial, the rest of the files counted as not attempted and named, the records read kept in the file", async () => {
  await withCwd(async (cwd) => {
    const records = Array.from({ length: 2000 }, (_, i) => fsRecord(`Users/alice/Library/Caches/app${i % 40}/file-${i}.tmp`, BigInt(i + 1), CREATED, BigInt(i + 1)));
    const page = fsPage("2SLD", records);
    const dir = join(cwd, "work", "fse");
    await mkdir(dir, { recursive: true });
    await writeFile(join(dir, "0000000000000001"), gz(Buffer.concat(Array.from({ length: 400 }, () => page))));
    await writeFile(join(dir, "0000000000000002"), gz(page));
    const answer = ok(await tool(FS, cwd, { path: "work/fse", out_file: "work/o.jsonl", max_seconds: 0.5 }));
    assert.equal(answer.status, "partial");
    assert.match(answer.status_basis, /max_seconds/);
    assert.equal(answer.files_by_state.not_attempted, 1);
    assert.equal(answer.time_limit.files_not_attempted, 1);
    assert.match(answer.time_limit.stopped_in_file, /0000000000000001$/);
    assert.ok(answer.limits.seconds_used < 6, `${answer.limits.seconds_used} s`);
    const kept = await lines(join(cwd, "work/o.jsonl"));
    assert.equal(kept.length, answer.record_count, "every record it counted is in the file");
    assert.ok(kept.length > 0 && kept.length < 800_000);
    assert.ok(answer.per_file.some((f: Json) => f.state === "not_attempted"));
  });
});

// ---- fsevents_parse: contains is a restricted regular expression, run on the text the answer prints, under a timer ----------------------------

async function runWithLimit(script: string, cwd: string, args: unknown, ms: number): Promise<{ code: number | null; stdout: string; ended: boolean }> {
  return new Promise((resolve) => {
    const child = spawn("python3", [script], { cwd, env: { ...process.env, AGENT_ID: "s1" } });
    const out: Buffer[] = [];
    child.stdout.on("data", (c: Buffer) => out.push(c));
    let ended = true;
    const timer = setTimeout(() => {
      ended = false;
      child.kill("SIGKILL");
    }, ms);
    child.on("close", (code) => {
      clearTimeout(timer);
      resolve({ code, stdout: Buffer.concat(out).toString("utf8"), ended });
    });
    child.stdin.end(JSON.stringify(args));
  });
}

test("fsevents_parse refuses a contains that can backtrack without end, at once and as JSON: (a|aa)+$ over a path of 40 characters took 37 s", async () => {
  await withCwd(async (cwd) => {
    const dir = await fsDir(cwd, "ev", { "0000000000000001": gz(fsPage("2SLD", [fsRecord("tmp/" + "a".repeat(40) + "b", 1n, CREATED, 1n)])) });
    for (const pattern of ["(a|aa)+$", "(a+)+b", "(?:a*)*b", "(a*)*$", "(.*a){12}", "(?=a+)+b", "(a)\\1", "^(a?){30}a{30}$", "(?<=a)b", "(x+x+)+y", "a*a*a*b", "a?".repeat(30) + "a".repeat(30), "(?i)" + "a?".repeat(9) + "b", "((((((a?){8}){8}){8}){8}){8}){8}b"]) {
      const started = Date.now();
      const run = await runWithLimit(FS, cwd, { path: dir, contains: pattern }, 20_000);
      assert.equal(run.ended, true, `${pattern}: the tool did not end in 20 s`);
      assert.ok(Date.now() - started < 15_000, pattern);
      const answer = JSON.parse(run.stdout) as Json;
      assert.equal(run.code, 1, pattern);
      assert.equal(answer.status, "failed", pattern);
      assert.match(answer.error, /contains is not run/, pattern);
    }
    const longPattern = await runWithLimit(FS, cwd, { path: dir, contains: "a".repeat(300) }, 20_000);
    assert.match((JSON.parse(longPattern.stdout) as Json).error, /longer than 256/);
  });
});

test("fsevents_parse runs an ordinary contains over the path as the answer prints it, and counts a search that ran out of time instead of waiting for it", async () => {
  await withCwd(async (cwd) => {
    const dir = await fsDir(cwd, "ev", {
      "0000000000000001": gz(fsPage("2SLD", [fsRecord("Users/alice/Documents/report.docx", 1n, CREATED, 1n), fsRecord("Users/bob/Downloads/setup.pkg", 2n, CREATED, 2n), fsRecord("tmp/x", 3n, CREATED, 3n)])),
    });
    for (const pattern of ["alice/.*\\.docx$", "^(users|tmp)/", "[a-z]+\\.pkg", "\\.(docx|pkg)$"]) {
      const answer = ok(await tool(FS, cwd, { path: dir, contains: pattern }));
      assert.ok(answer.record_count >= 1, pattern);
      assert.equal(answer.status, "complete", pattern);
    }
    // Two repeats over the same characters take quadratic time: accepted, and bounded by the timer. The shown path is 100,000 components of one letter.
    const long = "a/".repeat(100_000);
    const slow = await fsDir(cwd, "evslow", { "0000000000000001": gz(fsPage("2SLD", [fsRecord(long, 1n, CREATED, 1n), fsRecord("tmp/x", 2n, CREATED, 2n)])) });
    const started = Date.now();
    const answer = ok(await tool(FS, cwd, { path: slow, contains: "[a/]*[a/]*b" }));
    assert.ok(Date.now() - started < 20_000, `${Date.now() - started} ms`);
    assert.equal(answer.filters.contains_timeouts, 1);
    assert.equal(answer.status, "partial");
    assert.match(answer.status_basis, /contains_timeouts/);
  });
});

// ---- unified_log: staging and the census come out of the reader's time -----------------------------------------------------------------------

test("unified_log gives the reader what is left of timeout_seconds after staging and the census, and says how the budget was spent", async () => {
  // Staging, the census and the counting were not subtracted: 1100 seconds for the reader and then the rest.
  await withCwd(async (cwd) => {
    const bin = await ulStandin(cwd, `
with open(out, "w") as f:
    f.write(json.dumps({"timestamp": "2026-02-14T09:30:00.000000+0000", "eventMessage": "m", "process": "sudo", "subsystem": "s"}) + "\\n")
`);
    const path = await dbCopy(cwd, 400, 200_000);
    const answer = ok(await ul(cwd, bin, { path, out_dir: "work/u1", timeout_seconds: 600 }));
    assert.equal(answer.staging.staged, true);
    const spent = answer.budget.staging_seconds + answer.budget.census_seconds;
    assert.ok(answer.budget.staging_seconds >= 0 && answer.budget.census_seconds >= 0);
    assert.ok(answer.budget.seconds_for_reader <= 600 - Math.floor(spent) + 1, `the reader had ${answer.budget.seconds_for_reader} s; staging and census took ${spent} s`);
    assert.ok(answer.budget.seconds_for_reader >= 595 - spent);
    assert.equal(answer.timeout_seconds_used, 600);
  });
});

test("unified_log does not start a reader when staging has used the whole budget, and removes what it staged", async () => {
  await withCwd(async (cwd) => {
    const bin = await ulStandin(cwd, `open(out, "w").write("")`);
    const path = await dbCopy(cwd, 150, 2_000_000);
    const run = await ul(cwd, bin, { path, out_dir: "work/u2", timeout_seconds: 1 });
    const answer = body(run);
    // On a fast disk 300 MB can be staged in a second; the test only asserts the two outcomes that are allowed.
    if (answer.status === "failed" && answer.error) {
      assert.match(answer.error, /staging used the whole time budget|staging and the census used the whole time budget/);
      assert.equal(run.code, 1);
      await assert.rejects(stat(join(cwd, "work/u2/.logarchive-input")), "the staged copy was removed");
    } else {
      assert.ok(answer.budget.seconds_for_reader <= 1);
    }
  });
});

test("unified_log previews an entry under Mandiant's field names too: time, message, raw_message, pid, thread_id, event_type, log_type", async () => {
  // KEEP listed Apple's names only: the preview of a Linux read was a process, a subsystem and a category, with no time and no message.
  await withCwd(async (cwd) => {
    const bin = await ulStandin(cwd, `
with open(out, "w") as f:
    f.write(json.dumps({"subsystem": "com.apple.xpc.launchd", "thread_id": 1, "pid": 1, "time": 1650767813342574000.0, "category": "", "event_type": "Create", "log_type": "Default", "process": "/sbin/launchd", "message": "Reached target", "raw_message": "Reached %s", "euid": 0}) + "\\n")
    f.write(json.dumps({"message": None, "unrelated": 1}) + "\\n")
`);
    const answer = ok(await ul(cwd, bin, { path: await logarchive(cwd), out_dir: "work/u3" }));
    assert.equal(answer.entry_count, 2);
    const first = answer.entries[0];
    assert.equal(first.message, "Reached target");
    assert.equal(first.raw_message, "Reached %s");
    assert.equal(first.time, 1650767813342574000);
    assert.equal(first.pid, 1);
    assert.equal(first.thread_id, 1);
    assert.equal(first.event_type, "Create");
    assert.equal(first.log_type, "Default");
    // A record that is an entry by one key whose value is empty is previewed by its key names, never as the whole unfiltered row.
    assert.deepEqual(Object.keys(answer.entries[1]), ["keys"]);
  });
});
