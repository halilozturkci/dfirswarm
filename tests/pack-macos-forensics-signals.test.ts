/**
 * SIGTERM, SIGINT and SIGHUP end each of the four macos-forensics tools the way a time limit does: one JSON answer with status partial and the
 * signal's name, the exit code 128 plus the signal, what was staged removed, the rows already written kept whole, and the reader process the tool
 * started ended with it. The harness ends a tool by signalling it; before this the answer was empty, the exit code was minus the signal, a staged
 * copy of the evidence (up to 2 GiB for knowledgec_query, 16 GiB for unified_log) stayed in a sealed output, and unified_log's reader kept running.
 */
import assert from "node:assert/strict";
import { mkdir, readFile, readdir, stat, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { test } from "node:test";
import { runPySnippet, withCwd } from "./tool-library-harness.ts";
import { CREATED, FS, KC, PLIST, UL, dbCopy, fsPage, fsRecord, gz, kcDb, runAndSignal, ulStandin } from "./macos-pack-harness.ts";
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
