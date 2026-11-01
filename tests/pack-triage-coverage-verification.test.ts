/**
 * triage-collection: collection_coverage reads the verification table (the checks table collection_manifest_verify wrote) under a bound on a
 * line (1 MiB; a longer line is skipped to its end and counted in rows_not_used) and a bound on the rows. A table cut at the cap, by the clock
 * or by the memory bound is not a table read whole: the answer is `partial`, names the cut in status_basis, and `verification` says how many
 * rows were not read. It used to stop at 5,000,000 rows without a word, and a question could be `complete` without the mismatches in the rows
 * it never read.
 *
 * The cap is lowered the way a suite lowers a constant of a tool: the tool's source is run with MAX_VERIFICATION_ROWS set before main (the
 * constant exists in the code this suite is shown to fail on), and COLLECTION_COVERAGE_MAX_VERIFICATION_ROWS lowers it too.
 */
import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { createHash } from "node:crypto";
import { writeFile } from "node:fs/promises";
import { join } from "node:path";
import { test } from "node:test";
import { KAPE_COPY_HEADER, TOOLS, kapeCopyRow, put, withCwd } from "./pack-triage-harness.ts";
import type { Json } from "./pack-triage-harness.ts";

const COVERAGE = join(TOOLS, "collection_coverage", "run.py");
const sha1 = (data: string) => createHash("sha1").update(data).digest("hex").toUpperCase();

// the tool's source run in a namespace of its own, a constant set before main, and the peak RSS of the process printed to stderr at the end
const WRAPPER = `
import sys, json, resource
path, cap = sys.argv[1], int(sys.argv[2])
g = {"__name__": "coverage_under_test", "__file__": path}
exec(compile(open(path).read(), path, "exec"), g)
if cap:
    g["MAX_VERIFICATION_ROWS"] = cap
try:
    g["main"]()
finally:
    sys.stderr.write("MAXRSS_KB=%d\\n" % resource.getrusage(resource.RUSAGE_SELF).ru_maxrss)
`;

type Result = { code: number | null; answer: Json; rssKb: number };

function run(cwd: string, args: unknown, cap = 0, env: Record<string, string> = {}): Promise<Result> {
  return new Promise((resolve, reject) => {
    const child = spawn("python3", ["-c", WRAPPER, COVERAGE, String(cap)], { cwd, env: { ...process.env, AGENT_ID: "s1", ...env } });
    const out: Buffer[] = [];
    const err: Buffer[] = [];
    child.stdout.on("data", (c: Buffer) => out.push(c));
    child.stderr.on("data", (c: Buffer) => err.push(c));
    child.on("error", reject);
    child.on("close", (code) => {
      const stderr = Buffer.concat(err).toString("utf8");
      assert.doesNotMatch(stderr, /Traceback/, stderr);
      resolve({ code, answer: JSON.parse(Buffer.concat(out).toString("utf8")), rssKb: Number(/MAXRSS_KB=(\d+)/.exec(stderr)?.[1] ?? 0) });
    });
    child.stdin.end(JSON.stringify(args));
  });
}

/** A delivery whose one file is named by its copy log, so that the question below is `complete` without a verification table. */
async function delivery(cwd: string): Promise<void> {
  const row = kapeCopyRow("C:\\Users\\a\\notes.txt", "D:\\o\\C\\Users\\a\\notes.txt", 5).replace("da39a3ee5e6b4b0d3255bfef95601890afd80709", sha1("hello"));
  await put(cwd, "ev/2026_run_CopyLog.csv", `${KAPE_COPY_HEADER}\n${row}\n`);
  await put(cwd, "ev/C/Users/a/notes.txt", "hello");
}

const QUESTION = { root: "ev", questions: [{ id: "q1", delivered_paths: ["C/Users/a/*"] }], verification: "checks.jsonl" };
const row = (delivered: string, status: string) => JSON.stringify({ delivered, status });

test("a verification table cut at the cap makes the answer partial, and the unread rows are counted", async () => {
  await withCwd(async (cwd) => {
    await delivery(cwd);
    // the cap is 2 rows: the two rows read say nothing of notes.txt; the row after the cap is the mismatch for it
    await writeFile(join(cwd, "checks.jsonl"), [row("other-1", "matched"), row("other-2", "matched"), row("C/Users/a/notes.txt", "mismatch")].join("\n") + "\n");
    const cut = await run(cwd, QUESTION, 2);
    assert.equal(cut.code, 0);
    assert.equal(cut.answer.status, "partial", "a table that was not read whole is not a complete answer");
    assert.match(cut.answer.status_basis, /verification table was cut \(the cap of 2 rows\)/);
    assert.equal(cut.answer.verification.truncated, true);
    assert.equal(cut.answer.verification.rows_not_read, 1);
    assert.equal(cut.answer.verification.rows_read, 2);
    assert.ok(cut.answer.questions[0].state.includes("verification_table_cut"));
    assert.match(cut.answer.questions[0].statement, /verification table was cut before its end/);
    // the table read whole: the mismatch is shown, and the cut is not claimed
    const whole = await run(cwd, QUESTION, 3);
    assert.equal(whole.answer.verification.truncated, false);
    assert.equal(whole.answer.verification.rows_not_read, 0);
    assert.equal(whole.answer.questions[0].integrity.mismatch, 1);
    assert.equal(whole.answer.status, "complete", whole.answer.status_basis);
    // a table that ends exactly at the cap is not a cut one
    await writeFile(join(cwd, "checks.jsonl"), [row("other-1", "matched"), row("other-2", "matched")].join("\n"));
    const ends = await run(cwd, QUESTION, 2);
    assert.equal(ends.answer.verification.truncated, false, "two rows, no final newline, cap of two");
    assert.equal(ends.answer.status, "complete", ends.answer.status_basis);
  });
});

test("the cap can be lowered by COLLECTION_COVERAGE_MAX_VERIFICATION_ROWS, and never raised by it", async () => {
  await withCwd(async (cwd) => {
    await delivery(cwd);
    await writeFile(join(cwd, "checks.jsonl"), [row("a", "matched"), row("b", "matched"), row("c", "matched")].join("\n") + "\n");
    const lowered = await run(cwd, QUESTION, 0, { COLLECTION_COVERAGE_MAX_VERIFICATION_ROWS: "1" });
    assert.equal(lowered.answer.verification.rows_not_read, 2);
    assert.equal(lowered.answer.status, "partial");
    for (const bad of ["0", "-1", "lots", "9".repeat(400)]) {
      const same = await run(cwd, QUESTION, 0, { COLLECTION_COVERAGE_MAX_VERIFICATION_ROWS: bad });
      assert.equal(same.answer.verification.truncated, false, `a cap of ${bad.slice(0, 10)} is no cap`);
    }
    const raised = await run(cwd, QUESTION, 2, { COLLECTION_COVERAGE_MAX_VERIFICATION_ROWS: "1000000000" });
    assert.equal(raised.answer.verification.rows_not_read, 1, "the environment lowers the cap and never raises it");
  });
});

test("a 10 MiB line of the table is counted in rows_not_used at a bounded memory, not read whole", async () => {
  await withCwd(async (cwd) => {
    await delivery(cwd);
    const good = [row("C/Users/a/notes.txt", "matched")];
    await writeFile(join(cwd, "checks.jsonl"), good.join("\n") + "\n");
    const small = await run(cwd, QUESTION);
    // a valid-looking row whose path is 10 MiB long, then another row
    const huge = JSON.stringify({ delivered: "x".repeat(10 << 20), status: "mismatch" });
    await writeFile(join(cwd, "checks.jsonl"), [...good, huge, row("after", "matched")].join("\n") + "\n");
    const big = await run(cwd, QUESTION);
    assert.equal(big.answer.verification.rows_read, 3);
    assert.equal(big.answer.verification.rows_not_used, 1, "the long line is not used");
    assert.equal(big.answer.verification.lines_over_the_bound, 1);
    assert.equal(big.answer.verification.files, 2, "the rows around it are read");
    assert.equal(big.answer.verification.truncated, false);
    assert.ok(big.rssKb - small.rssKb < 8 * 1024, `the peak memory grew by ${big.rssKb - small.rssKb} KiB over a 10 MiB line`);
  });
});

test("CRLF rows, a NUL byte, a row without a newline at the end and a line exactly at the bound are read as rows", async () => {
  await withCwd(async (cwd) => {
    await delivery(cwd);
    const nul = Buffer.from('{"delivered":"n\\u0000ul","status":"matched"}\n');
    const raw = Buffer.concat([
      Buffer.from(row("a", "matched") + "\r\n" + row("b", "mismatch") + "\r\n"),
      Buffer.from('{"delivered":"bad\0","status":"matched"}\n'),               // a raw NUL byte is not JSON: not used
      nul,                                                                      // an escaped NUL is
      Buffer.from(row("C/Users/a/notes.txt", "matched")),                       // no newline at the end
    ]);
    await writeFile(join(cwd, "checks.jsonl"), raw);
    const out = (await run(cwd, QUESTION)).answer;
    assert.equal(out.verification.rows_read, 5);
    assert.equal(out.verification.rows_not_used, 1);
    assert.equal(out.verification.files, 4);
    assert.equal(out.verification.truncated, false);
    assert.equal(out.status, "complete", out.status_basis);
    // a line of exactly the bound (1 MiB with its newline) is a row; one byte more is not
    const pad = (n: number) => '{"delivered":"' + "p".repeat(n - '{"delivered":"'.length - '","status":"matched"}'.length) + '","status":"matched"}';
    await writeFile(join(cwd, "checks.jsonl"), pad((1 << 20) - 1) + "\n" + pad(1 << 20) + "\n");
    const edge = (await run(cwd, QUESTION)).answer.verification;
    assert.equal(edge.rows_not_used, 1, JSON.stringify(edge));
    assert.equal(edge.lines_over_the_bound, 1);
    assert.equal(edge.files, 1);
  });
});
