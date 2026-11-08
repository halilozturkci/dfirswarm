/**
 * SIGTERM, SIGINT and SIGHUP end each of the four macos-forensics tools the way a time limit does: one JSON answer with status partial and the
 * signal's name, the exit code 128 plus the signal, what was staged removed, the rows already written kept whole, and the reader process the tool
 * started ended with it. The harness ends a tool by signalling it; before this the answer was empty, the exit code was minus the signal, a staged
 * copy of the evidence (up to 2 GiB for knowledgec_query, 16 GiB for unified_log) stayed in a sealed output, and unified_log's reader kept running.
 */
import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { mkdir, readFile, readdir, stat, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { test } from "node:test";
import { runPySnippet, withCwd } from "./tool-library-harness.ts";
import { CREATED, FS, KC, PLIST, UL, dbCopy, fsPage, fsRecord, gz, kcDb, logarchive, runAndSignal, ulStandin } from "./macos-pack-harness.ts";
import type { Json } from "./macos-pack-harness.ts";

const SIGNALS = [["SIGTERM", 15], ["SIGINT", 2], ["SIGHUP", 1]] as const;

const exists = (path: string): Promise<boolean> => stat(path).then(() => true, () => false);
const size = (path: string): Promise<number> => stat(path).then((s) => s.size, () => 0);

function oneAnswer(stdout: string, name: string, number: number): Json {
  const answer = JSON.parse(stdout) as Json;                 // one JSON document and nothing else
  assert.equal(answer.interrupted, name);
  return answer;
}

async function validRows(file: string): Promise<number> {
  const text = await readFile(file, "utf8");
  assert.ok(text === "" || text.endsWith("\n"), "the file ends on a whole row");
  return text.split("\n").filter(Boolean).map((l) => JSON.parse(l)).length;
}

for (const [name, number] of SIGNALS) {
  test(`plist_read, ${name}: one JSON answer, partial, exit ${128 + number}, the rows already written are whole`, async () => {
    await withCwd(async (cwd) => {
      const dir = join(cwd, "work", "pl");
      await mkdir(dir, { recursive: true });
      const out = await runPySnippet(`
import plistlib, os, sys
for i in range(400):
    plistlib.dump({"n": i, "items": list(range(8000))}, open(os.path.join(sys.argv[1], "p%04d.plist" % i), "wb"), fmt=plistlib.FMT_BINARY)
`, [dir], null);
      assert.equal(out.code, 0, out.stderr);
      const file = join(cwd, "work", "o.jsonl");
      const run = await runAndSignal(PLIST, cwd, { path: "work/pl", out_file: "work/o.jsonl", max_nodes: 100000 }, name, async () => (await size(file)) > 200_000);
      assert.equal(run.signalled, true);
      assert.equal(run.code, 128 + number, `${run.stderr}${run.stdout.slice(0, 200)}`);
      const answer = oneAnswer(run.stdout, name, number);
      assert.equal(answer.status, "partial");
      assert.match(answer.status_basis, new RegExp(name));
      assert.equal(await validRows(file), answer.counts.parsed + answer.counts.failed + answer.counts.skipped_over_a_bound, "every row it counted is in the file, and no row is half written");
    });
  });

  test(`fsevents_parse, ${name}: one JSON answer, partial, exit ${128 + number}, the records already written are whole`, async () => {
    await withCwd(async (cwd) => {
      const page = fsPage("2SLD", Array.from({ length: 2000 }, (_, i) => fsRecord(`Users/alice/Library/Caches/app${i % 40}/file-${i}.tmp`, BigInt(i + 1), CREATED, BigInt(i + 1))));
      const dir = join(cwd, "work", "fse");
      await mkdir(dir, { recursive: true });
      await writeFile(join(dir, "0000000000000001"), gz(Buffer.concat(Array.from({ length: 300 }, () => page))));
      await writeFile(join(dir, "0000000000000002"), gz(page));
      const file = join(cwd, "work", "o.jsonl");
      const run = await runAndSignal(FS, cwd, { path: "work/fse", out_file: "work/o.jsonl" }, name, async () => (await size(file)) > 300_000);
      assert.equal(run.signalled, true);
      assert.equal(run.code, 128 + number, `${run.stderr}${run.stdout.slice(0, 200)}`);
      const answer = oneAnswer(run.stdout, name, number);
      assert.equal(answer.status, "partial");
      assert.equal(await validRows(file), answer.record_count, "every record it counted is in the file, and no row is half written");
      assert.equal(answer.files_by_state.not_attempted, 1, "the second file was not reached, and the answer says so");
    });
  });

  test(`knowledgec_query, ${name}: one JSON answer, partial, exit ${128 + number}, the staged copy of the evidence removed`, async () => {
    await withCwd(async (cwd) => {
      const db = await kcDb(cwd, "k.db", 30_000, 10, {}, "wal");
      const stage = join(cwd, "out", "knowledgec-stage");
      const file = join(cwd, "work", "o.jsonl");
      await mkdir(join(cwd, "out"), { recursive: true });
      const run = await runAndSignal(KC, cwd, { db, out_file: "work/o.jsonl" }, name, async () => (await size(file)) > 100_000 && (await exists(stage)),
        { JOB_ID: "j-1", OUT: join(cwd, "out"), SECRET_OUTPUT: "1" });
      assert.equal(run.signalled, true, "the staged copy existed while the rows were read");
      assert.equal(run.code, 128 + number, `${run.stderr}${run.stdout.slice(0, 200)}`);
      const answer = oneAnswer(run.stdout, name, number);
      assert.equal(answer.status, "partial");
      assert.equal(answer.source_used.staged_copy, "removed");
      assert.deepEqual(await readdir(join(cwd, "out")), [], "nothing of the staged evidence is left in the sealed output");
      assert.equal(await validRows(file), answer.entry_count);
    });
  });

  test(`unified_log, ${name}: one JSON answer, partial, exit ${128 + number}, the reader it started ended, the staged copy removed`, async () => {
    await withCwd(async (cwd) => {
      const bin = await ulStandin(cwd, `
with open(out, "w") as f:
    f.write(json.dumps({"timestamp": "2026-02-14T09:30:00.000000+0000", "eventMessage": "m", "process": "sudo", "subsystem": "s"}) + "\\n")
open(os.path.join(os.path.dirname(out), "reader.pid"), "w").write(str(os.getpid()))
time.sleep(120)
`);
      const path = await dbCopy(cwd, 20, 1000);
      const pidFile = join(cwd, "out", "u", "reader.pid");
      await mkdir(join(cwd, "out"), { recursive: true });
      const run = await runAndSignal(UL, cwd, { path, out_dir: "out/u" }, name, async () => (await exists(pidFile)) && (await size(pidFile)) > 0,
        { JOB_ID: "j-1", OUT: join(cwd, "out"), SECRET_OUTPUT: "1" }, bin);
      assert.equal(run.signalled, true);
      assert.equal(run.code, 128 + number, `${run.stderr}${run.stdout.slice(0, 300)}`);
      const answer = oneAnswer(run.stdout, name, number);
      assert.equal(answer.status, "partial");
      assert.equal(answer.entry_count, 1, "what the reader had written is counted");
      const pid = Number(await readFile(pidFile, "utf8"));
      let alive = true;
      for (let i = 0; i < 40 && alive; i++) {
        try {
          process.kill(pid, 0);
          await new Promise((r) => setTimeout(r, 50));
        } catch {
          alive = false;
        }
      }
      assert.equal(alive, false, "the reader is gone: the tool ended it with itself");
      assert.equal(await exists(join(cwd, "out", "u", ".logarchive-input")), false, "the staged copy of /private/var/db is removed");
    });
  });
}

// ---- a stop signal that lands while the tool's own sweep is still working ends the orphans it had not yet reached ------------------------------------

test("unified_log, SIGTERM during the sweep of a storm of setsid orphans: every orphan is gone when the answer is printed", async () => {
  // The iterator exits 0 at once and leaves a setsid parent that forks 400 setsid sleepers. The tool's sweep ends them one by one (seconds); a stop that
  // lands in it used to leave the ones it had not yet reached running, writing into the output after the answer. end_leftovers_on_stop() was never called.
  await withCwd(async (cwd) => {
    const pidFile = join(cwd, "out", "u", "storm.pids");
    const bin = await ulStandin(cwd, `
with open(out, "w") as f:
    f.write(json.dumps({"timestamp": "2026-02-14T09:30:00.000000+0000", "eventMessage": "m", "process": "sudo", "subsystem": "s"}) + "\\n")
pids = os.path.join(os.path.dirname(out), "storm.pids")
open(pids, "a").close()                    # the file exists before the first sleeper has written to it: the wait below must not race the forks
if os.fork() == 0:
    os.setsid()
    for _ in range(400):
        if os.fork() == 0:
            os.setsid()
            with open(pids, "a") as p:
                p.write("%d\\n" % os.getpid())
            time.sleep(6)
            with open(out + ".late", "a") as late:
                late.write("late\\n")
            os._exit(0)
    os._exit(0)
deadline = time.time() + 20
while time.time() < deadline and len(open(pids).read().split()) < 400:
    time.sleep(0.01)
os._exit(0)
`);
    const path = await dbCopy(cwd, 20, 1000);
    await mkdir(join(cwd, "out"), { recursive: true });
    const pidsNow = async (): Promise<number[]> => (await readFile(pidFile, "utf8").catch(() => "")).split("\n").filter(Boolean).map(Number);
    let storm: number[] = [];
    let seen: number | undefined;
    try {
      const run = await runAndSignal(UL, cwd, { path, out_dir: "out/u" }, "SIGTERM", async () => {
          if ((await pidsNow()).length < 400) return false;
          seen ??= Date.now();                     // the storm is all there: the iterator ends and the sweep begins; the signal lands half a second into it
          return Date.now() - seen > 500;
        },
        { JOB_ID: "j-1", OUT: join(cwd, "out"), SECRET_OUTPUT: "1" }, bin);
      assert.equal(run.signalled, true, `${run.stderr}${run.stdout.slice(0, 600)} pids=${(await pidsNow()).length}`);
      assert.equal(run.code, 128 + 15, `${run.stderr}${run.stdout.slice(0, 300)}`);
      assert.equal(oneAnswer(run.stdout, "SIGTERM", 15).interrupted, "SIGTERM");
      storm = await pidsNow();
      const alive = storm.filter((pid) => {
        try {
          process.kill(pid, 0);
          return true;
        } catch {
          return false;
        }
      });
      assert.equal(alive.length, 0, `${alive.length} of ${storm.length} orphans are still running after the answer`);
    } finally {
      for (const pid of storm.length ? storm : await pidsNow()) {
        try {
          process.kill(pid, "SIGKILL");
        } catch { /* gone */ }
      }
    }
  });
});

// ---- a stop signal in the few bytecodes after the sweep is a stop of the run, not of start-up ---------------------------------------------------

/**
 * Runs a tool as `python3 run.py` does, but fires one real SIGTERM at the first hold_signals() call: the signal then lands in the bytecodes that
 * follow the sweep, before the hold takes effect. Before this the first hold came after the sweep's own `except Interrupted`, so the signal went to
 * main's wrapper, and the answer said the tool was stopped "before it had read anything" although the sweep had finished.
 */
async function stopAfterTheSweep(script: string, cwd: string, args: unknown, env: Record<string, string> = {}): Promise<{ code: number | null; stdout: string; stderr: string }> {
  const code = `
import os, signal, sys
src = open(sys.argv[1], encoding="utf-8").read()
head, tail = src.split(chr(10) + 'if __name__ == "__main__":', 1)
g = {"__name__": "__main__", "__file__": sys.argv[1]}
exec(compile(head, sys.argv[1], "exec"), g)
real = g["hold_signals"]
fired = []
def hold():
    if not fired:
        fired.append(1)
        os.kill(os.getpid(), signal.SIGTERM)
    return real()
g["hold_signals"] = hold
exec(compile('if __name__ == "__main__":' + tail, sys.argv[1], "exec"), g)
`;
  return new Promise((resolve, reject) => {
    const child = spawn("python3", ["-c", code, script], { cwd, env: { ...process.env, AGENT_ID: "s1", ...env } });
    const so: Buffer[] = [];
    const se: Buffer[] = [];
    child.stdout.on("data", (c: Buffer) => so.push(c));
    child.stderr.on("data", (c: Buffer) => se.push(c));
    child.on("error", reject);
    child.on("close", (c) => resolve({ code: c, stdout: Buffer.concat(so).toString("utf8"), stderr: Buffer.concat(se).toString("utf8") }));
    child.stdin.end(JSON.stringify(args));
  });
}

function finishedThenStopped(run: { code: number | null; stdout: string; stderr: string }): Json {
  assert.equal(run.code, 143, run.stderr + run.stdout.slice(0, 300));
  const answer = JSON.parse(run.stdout) as Json;
  assert.doesNotMatch(run.stdout, /before it had read anything|before its sweep|before staging|before the read began|before the reader had run/);
  assert.equal(answer.interrupted, "SIGTERM");
  assert.equal(answer.status, "partial");
  return answer;
}

test("plist_read: a SIGTERM in the bytecodes after the sweep gives the normal answer with interrupted set, not 'before it had read anything'", async () => {
  await withCwd(async (cwd) => {
    await mkdir(join(cwd, "work", "pl"), { recursive: true });
    await writeFile(join(cwd, "work", "pl", "a.plist"), '<?xml version="1.0" encoding="UTF-8"?><plist version="1.0"><dict><key>a</key><string>b</string></dict></plist>');
    const answer = finishedThenStopped(await stopAfterTheSweep(PLIST, cwd, { path: "work/pl" }));
    assert.equal(answer.counts.parsed, 1, "the file read before the signal is in the answer");
    assert.match(answer.status_basis, /after the last file was read/);
  });
});

test("fsevents_parse: a SIGTERM in the bytecodes after the sweep gives the normal answer with interrupted set, not 'before it had read anything'", async () => {
  await withCwd(async (cwd) => {
    const page = fsPage("2SLD", [fsRecord("Users/alice/a.txt", 1n, CREATED, 1n), fsRecord("Users/alice/b.txt", 2n, CREATED, 2n)]);
    await mkdir(join(cwd, "work", "fse"), { recursive: true });
    await writeFile(join(cwd, "work", "fse", "0000000000000001"), gz(page));
    const answer = finishedThenStopped(await stopAfterTheSweep(FS, cwd, { path: "work/fse" }));
    assert.equal(answer.record_count, 2, "the records read before the signal are in the answer");
  });
});

test("knowledgec_query: a SIGTERM in the bytecodes after the read gives the normal answer with interrupted set, and no claim that the table was cut", async () => {
  await withCwd(async (cwd) => {
    const db = await kcDb(cwd, "k.db", 30);
    const answer = finishedThenStopped(await stopAfterTheSweep(KC, cwd, { db }));
    assert.equal(answer.entry_count, 30, "every row was read before the signal");
    assert.doesNotMatch(JSON.stringify(answer.problems), /the rest of the table was not read/, "the read had finished: no prefix is claimed");
  });
});

test("unified_log: a SIGTERM in the bytecodes after the reader gives the normal answer with interrupted set, and the reader's output is counted", async () => {
  await withCwd(async (cwd) => {
    const bin = await ulStandin(cwd, `
open(out, "w").write(chr(10).join(json.dumps({"timestamp": "2026-01-01T00:00:0%d" % i, "eventMessage": "m%d" % i, "processImagePath": "/usr/bin/p"}) for i in range(5)) + chr(10))
`);
    const answer = finishedThenStopped(await stopAfterTheSweep(UL, cwd, { path: await logarchive(cwd), out_dir: "work/out" }, { PATH: bin }));
    assert.equal(answer.entry_count, 5);
    assert.match(answer.status_basis + JSON.stringify(answer.problems), /after the reader had already finished/);
  });
});
