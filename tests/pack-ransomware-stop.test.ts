/**
 * ransomware-response: how the two tools end. A stop signal gives one JSON answer and exit code 128 + the signal, and the files the tool
 * was still writing are gone; the tool's own clock ends the walk with a partial answer; a page or census file that is already there is
 * never replaced by a smaller one. The walk is made slow by a wrapper that sleeps in os.scandir, so that a signal arrives while the tool
 * is working, whatever the machine.
 */
import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { randomBytes } from "node:crypto";
import { mkdir, readFile, readdir, stat, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { test } from "node:test";
import { withCwd } from "./tool-library-harness.ts";
import { NOTES, SURVEY, body, exists, filesUnder, tool } from "./ransomware-pack-harness.ts";

const SLOW = String.raw`
import os, runpy, sys, time
_real = os.scandir
def slow(path="."):
    time.sleep(float(os.environ["SLOW_SCANDIR"]))
    return _real(path)
os.scandir = slow
script = sys.argv[1]
sys.argv = [script]
runpy.run_path(script, run_name="__main__")
`;

type Ended = { code: number | null; signal: NodeJS.Signals | null; stdout: string; stderr: string };

/** Run a tool with a slow walk; when `when()` says so (a file it writes exists), send `signal`. */
async function runSlow(script: string, cwd: string, args: unknown, env: Record<string, string>, signal: NodeJS.Signals | null, when: () => Promise<boolean>): Promise<Ended> {
  const child = spawn("python3", ["-c", SLOW, script], { cwd, env: { ...process.env, AGENT_ID: "s1", SLOW_SCANDIR: "0.15", ...env } });
  const out: Buffer[] = [];
  const err: Buffer[] = [];
  child.stdout.on("data", (c: Buffer) => out.push(c));
  child.stderr.on("data", (c: Buffer) => err.push(c));
  const ended = new Promise<Ended>((resolve) =>
    child.on("close", (code, sig) => resolve({ code, signal: sig, stdout: Buffer.concat(out).toString("utf8"), stderr: Buffer.concat(err).toString("utf8") })),
  );
  child.stdin.end(JSON.stringify(args));
  if (signal) {
    const deadline = Date.now() + 20000;
    while (!(await when()) && Date.now() < deadline) await new Promise((r) => setTimeout(r, 50));
    await new Promise((r) => setTimeout(r, 300)); // let the walk run on
    child.kill(signal);
  }
  return ended;
}

/** A tree of many small directories: the slow walk takes seconds. */
async function slowTree(cwd: string, dirs = 40): Promise<void> {
  for (let i = 0; i < dirs; i++) {
    const d = join(cwd, "work", "ev", `d${String(i).padStart(3, "0")}`);
    await mkdir(d, { recursive: true });
    await writeFile(join(d, "README.txt"), `Your files are encrypted. Decrypt them: pay in bitcoin.\nyour personal id: ${"Z9".repeat(8)}${i}\n`);
    await writeFile(join(d, "a.docx.locked"), randomBytes(5000));
  }
}

const hiddenTemps = async (cwd: string, extra: string[] = []): Promise<string[]> => {
  const found: string[] = [];
  for (const dir of [join(cwd, "work", "s1"), ...extra]) {
    for (const name of Object.keys(await filesUnder(dir))) if (name.split("/").pop()!.startsWith(".")) found.push(name);
  }
  return found;
};

const NUMBER: Record<string, number> = { SIGTERM: 15, SIGINT: 2, SIGHUP: 1 };
const SIGNALS: [NodeJS.Signals, number][] = [["SIGTERM", 143], ["SIGINT", 130], ["SIGHUP", 129]];

for (const [name, script, args] of [
  ["encrypted_survey", SURVEY, { root: "work/ev", limit: 1 }],
  ["ransom_note_scan", NOTES, { root: "work/ev", limit: 1 }],
] as const) {
  for (const [signal, code] of SIGNALS) {
    test(`${name} ends on ${signal} with one JSON answer, exit code ${code}, no traceback and none of its temporary files left`, async () => {
      await withCwd(async (cwd) => {
        await slowTree(cwd);
        const place = join(cwd, "work", "s1", "tool-output");
        const started = async () => (await exists(place)) && (await readdir(place)).length > 0;
        const ended = await runSlow(script, cwd, args, {}, signal, started);
        assert.equal(ended.code, code, `${ended.stdout}\n${ended.stderr}`);
        assert.doesNotMatch(ended.stderr, /Traceback|KeyboardInterrupt/);
        const answer = JSON.parse(ended.stdout) as { status: string; status_basis: string; interrupted: boolean; signal: number; coverage_so_far: Record<string, number> };
        assert.deepEqual([answer.status, answer.interrupted, answer.signal], ["failed", true, NUMBER[signal]]);
        assert.ok(answer.status_basis.length > 20);
        assert.deepEqual(await hiddenTemps(cwd), [], "a temporary file was left");
        assert.deepEqual(await filesUnder(place), {}, "a result file was left that does not end in a receipt");
      });
    });
  }
}

test("ransom_note_scan, stopped while it writes values, keeps a values file of whole rows and says how many it holds", async () => {
  await withCwd(async (cwd) => {
    await slowTree(cwd);
    const out = join(cwd, "out");
    await mkdir(out);
    const file = join(out, "ransom-note-values.jsonl");
    const rows = async () => ((await exists(file)) ? (await readFile(file, "utf8")).split("\n").length - 1 : 0);
    const ended = await runSlow(NOTES, cwd, { root: "work/ev", write_values: true }, { JOB_ID: "j000001", OUT: out, SECRET_OUTPUT: "1" }, "SIGTERM", async () => (await rows()) >= 6);
    assert.equal(ended.code, 143, ended.stderr);
    const answer = JSON.parse(ended.stdout) as { rows_in_values_file: number; values_file_is_partial: boolean; values_file: string; status: string };
    assert.equal(answer.status, "failed");
    assert.equal(answer.values_file_is_partial, true);
    assert.equal(answer.values_file, "store/jobs/j000001/out/ransom-note-values.jsonl");
    const text = await readFile(file, "utf8");
    assert.ok(text.endsWith("\n"), "the file ends in a whole row");
    const lines = text.trimEnd().split("\n");
    for (const line of lines) JSON.parse(line);
    assert.equal(answer.rows_in_values_file, lines.length);
    assert.ok(lines.length >= 6);
    assert.equal((await stat(file)).mode & 0o777, 0o600);
    assert.doesNotMatch(ended.stdout, /Z9Z9Z9/, "the answer carries no value");
  });
});

// --- the tool's own clock -----------------------------------------------------------

for (const [name, script] of [["encrypted_survey", SURVEY], ["ransom_note_scan", NOTES]] as const) {
  test(`${name} stops its walk at max_seconds, within two seconds, and says what it did not examine`, async () => {
    await withCwd(async (cwd) => {
      await slowTree(cwd);
      const started = Date.now();
      const ended = await runSlow(script, cwd, { root: "work/ev", max_seconds: 1 }, {}, null, async () => true);
      const seconds = (Date.now() - started) / 1000;
      assert.equal(ended.code, 0, ended.stderr);
      assert.ok(seconds < 1 + 2 + 1, `took ${seconds} s`);
      const answer = JSON.parse(ended.stdout) as { status: string; complete: string; status_basis: string; time_limit: { reached: boolean; max_seconds: number; directories_not_entered: number } };
      assert.deepEqual([answer.status, answer.complete], ["partial", "partial"]);
      assert.equal(answer.time_limit.reached, true);
      assert.equal(answer.time_limit.max_seconds, 1);
      assert.ok(answer.time_limit.directories_not_entered > 0);
      assert.match(answer.status_basis, /time limit \(max_seconds 1\) was reached/);
    });
  });

  test(`${name} refuses a max_seconds beyond the manifest's timeout`, async () => {
    await withCwd(async (cwd) => {
      await mkdir(join(cwd, "work", "ev"));
      const out = await tool(script, cwd, { root: "work/ev", max_seconds: 100000 });
      assert.notEqual(out.code, 0);
      const answer = JSON.parse(out.stdout) as { error: string; status: string };
      assert.match(answer.error, /max_seconds must be at most/);
      assert.equal(answer.status, "failed");
    });
  });
}

// --- a result that is there is never replaced ----------------------------------------

test("encrypted_survey keeps the census and the candidates of an earlier run when a later run writes smaller ones, and names the new files", async () => {
  await withCwd(async (cwd) => {
    const ev = join(cwd, "work", "ev");
    await mkdir(ev, { recursive: true });
    for (let i = 0; i < 60; i++) await writeFile(join(ev, `f${String(i).padStart(3, "0")}.doc.locked`), randomBytes(9000));
    const place = join(cwd, "work", "s1", "tool-output");
    const first = body<{ census: { file: string }; pages: { candidates: { all_results: string } } }>(await tool(SURVEY, cwd, { root: "work/ev", limit: 5 }));
    const before: Record<string, string> = {};
    for (const f of [first.census.file, first.pages.candidates.all_results]) before[f] = await readFile(join(cwd, f), "utf8");
    // a smaller run in the same place: no census rows for files that matched nothing, a read budget that stops early
    const second = body<{ census: { file: string }; pages: { candidates: { all_results: string } }; status: string }>(
      await tool(SURVEY, cwd, { root: "work/ev", limit: 5, census: false, read_budget_bytes: 200000 }),
    );
    for (const [f, text] of Object.entries(before)) assert.equal(await readFile(join(cwd, f), "utf8"), text, `${f} was replaced`);
    assert.notEqual(second.census.file, first.census.file);
    assert.notEqual(second.pages.candidates.all_results, first.pages.candidates.all_results);
    assert.match(second.census.file, /-2\.jsonl$/);
    assert.ok(await exists(join(cwd, second.census.file)));
    assert.ok(await exists(join(cwd, second.pages.candidates.all_results)));
    // the same run again writes the same bytes and names the file that holds them
    const third = body<{ census: { file: string } }>(await tool(SURVEY, cwd, { root: "work/ev", limit: 5 }));
    assert.equal(third.census.file, first.census.file);
    assert.deepEqual((await readdir(place)).filter((n) => n.startsWith(".")), []);
  });
});

test("ransom_note_scan keeps the notes page of an earlier run when a later run writes a smaller one", async () => {
  await withCwd(async (cwd) => {
    const ev = join(cwd, "work", "ev");
    await mkdir(ev, { recursive: true });
    for (let i = 0; i < 6; i++) await writeFile(join(ev, `README_${i}.txt`), `Your files are encrypted. Decrypt them and pay in bitcoin. ${"x".repeat(100 * (i + 1))}\n`);
    const first = body<{ pages: { notes: { all_results: string; matched: number } } }>(await tool(NOTES, cwd, { root: "work/ev", limit: 1 }));
    assert.equal(first.pages.notes.matched, 6);
    const kept = await readFile(join(cwd, first.pages.notes.all_results), "utf8");
    const second = body<{ pages: { notes: { all_results: string; matched: number } } }>(await tool(NOTES, cwd, { root: "work/ev", limit: 1, max_size: 330 }));
    assert.ok(second.pages.notes.matched < 6);
    assert.equal(await readFile(join(cwd, first.pages.notes.all_results), "utf8"), kept, "the earlier page was replaced");
    assert.notEqual(second.pages.notes.all_results, first.pages.notes.all_results);
    assert.match(second.pages.notes.all_results, /-2\.jsonl$/);
  });
});
