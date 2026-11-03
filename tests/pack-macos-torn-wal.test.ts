/**
 * A write-ahead log with a damaged frame in the middle is applied by SQLite only up to the damage; the frames after it are committed rows that are NOT in
 * the result. macos_tcc, safari_history and knowledgec_query copy the database and its WAL and let SQLite apply the log, then compare what SQLite applied
 * (the checkpoint's `log`) with the committed frames of the current generation they counted in the copy; a shortfall is a problem that names both numbers
 * and makes the answer partial. A clean WAL stays complete. The databases are built by SQLite (30 or more commits, no automatic checkpoint) and the damage
 * is 8 bytes overwritten inside a frame of the copy, so that nothing of the tool is used to build or to tear them.
 */
import assert from "node:assert/strict";
import { readFile, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { test } from "node:test";
import { withCwd, runPySnippet } from "./tool-library-harness.ts";
import { KC } from "./macos-pack-harness.ts";
import { SAFARI, TCC, ok, tool } from "./macos-late-harness.ts";

const BUILD = `
import os, shutil, sqlite3, sys
path, kind, commits = sys.argv[1], sys.argv[2], int(sys.argv[3])
tmp = path + ".build"
os.makedirs(tmp, exist_ok=True)
c = sqlite3.connect(tmp + "/x.db")
c.execute("PRAGMA journal_mode=WAL")
c.execute("PRAGMA wal_autocheckpoint=0")
if kind == "tcc":
    c.execute("CREATE TABLE access (service TEXT NOT NULL, client TEXT NOT NULL, client_type INTEGER NOT NULL, auth_value INTEGER NOT NULL, auth_reason INTEGER NOT NULL, auth_version INTEGER NOT NULL, csreq BLOB, policy_id INTEGER, last_modified INTEGER NOT NULL)")
elif kind == "safari":
    c.execute("CREATE TABLE history_items (id INTEGER PRIMARY KEY AUTOINCREMENT, url TEXT NOT NULL UNIQUE, domain_expansion TEXT, visit_count INTEGER NOT NULL, daily_visit_counts BLOB NOT NULL, should_recompute_derived_visit_counts INTEGER NOT NULL, visit_count_score INTEGER NOT NULL)")
    c.execute("CREATE TABLE history_visits (id INTEGER PRIMARY KEY AUTOINCREMENT, history_item INTEGER NOT NULL, visit_time REAL NOT NULL, title TEXT)")
    c.execute("INSERT INTO history_items (url, visit_count, daily_visit_counts, should_recompute_derived_visit_counts, visit_count_score) VALUES ('https://example.org/', 1, x'00', 0, 1)")
else:
    c.execute("CREATE TABLE ZOBJECT (Z_PK INTEGER PRIMARY KEY, ZSTREAMNAME TEXT, ZSTARTDATE REAL, ZENDDATE REAL, ZVALUESTRING TEXT)")
c.commit()
c.execute("PRAGMA wal_checkpoint(TRUNCATE)")
for i in range(commits):
    if kind == "tcc":
        c.execute("INSERT INTO access VALUES ('kTCCServiceCamera', ?, 0, 2, 3, 1, NULL, NULL, ?)", ("com.example.app%d" % i, 1700000000 + i))
    elif kind == "safari":
        c.execute("INSERT INTO history_visits (history_item, visit_time, title) VALUES (1, ?, ?)", (700000000.0 + i, "visit %d" % i))
    else:
        c.execute("INSERT INTO ZOBJECT (ZSTREAMNAME, ZSTARTDATE, ZENDDATE, ZVALUESTRING) VALUES ('/app/inFocus', ?, ?, ?)", (700000000.0 + i, 700000001.0 + i, "app%d" % i))
    c.commit()
shutil.copy(tmp + "/x.db", path)
shutil.copy(tmp + "/x.db-wal", path + "-wal")
c.close()
shutil.rmtree(tmp)
`;

async function torn(cwd: string, kind: string, tear: boolean): Promise<{ db: string; commits: number; frames: number }> {
  const commits = 30;
  const db = join(cwd, "work", `${kind}.db`);
  const built = await runPySnippet(BUILD, [db, kind, String(commits)], {});
  assert.equal(built.code, 0, built.stderr);
  const wal = Buffer.from(await readFile(db + "-wal"));
  const page = wal.readUInt32BE(8);
  const frames = Math.floor((wal.length - 32) / (24 + page));
  assert.ok(frames >= 30, `the log holds ${frames} frames`);
  if (tear) {
    const at = 32 + Math.floor(frames * 0.6) * (24 + page) + 24 + 100;
    for (let i = 0; i < 8; i++) wal[at + i] ^= 0xff;
    await writeFile(db + "-wal", wal);
  }
  return { db: `work/${kind}.db`, commits, frames };
}

const CASES: Array<[string, string, string, (a: any) => number]> = [ // eslint-disable-line @typescript-eslint/no-explicit-any
  ["macos_tcc", TCC, "tcc", (a) => a.entry_count],
  ["safari_history", SAFARI, "safari", (a) => a.entry_count],
  ["knowledgec_query", KC, "kc", (a) => a.entry_count],
];

for (const [name, script, kind, count] of CASES) {
  test(`${name}: a clean WAL of 30 commits is read whole and complete`, async () => {
    await withCwd(async (cwd) => {
      const { db, commits } = await torn(cwd, kind, false);
      const a = ok(await tool(script, cwd, name === "knowledgec_query" ? { db } : { path: db }));
      assert.equal(count(a), commits, JSON.stringify(a.problems));
      assert.equal(a.status, "complete", a.status_basis + JSON.stringify(a.problems));
    });
  });

  test(`${name}: a torn WAL is partial, with the committed frames and the frames SQLite applied named`, async () => {
    await withCwd(async (cwd) => {
      const { db, commits } = await torn(cwd, kind, true);
      const a = ok(await tool(script, cwd, name === "knowledgec_query" ? { db } : { path: db }));
      assert.ok(count(a) < commits, `${count(a)} of ${commits} rows read`);
      assert.equal(a.status, "partial", "a torn WAL is never complete");
      const problem = (a.problems as string[]).find((p) => /committed frame/.test(p));
      assert.ok(problem, JSON.stringify(a.problems));
      const wal = a.source_used.wal ?? a.source_used.wal;
      assert.match(problem, new RegExp(`holds ${wal.frames_committed} committed frame`));
      assert.match(problem, new RegExp(`applied only ${a.source_used.wal_checkpoint.log} `));
      assert.ok(a.source_used.wal_checkpoint.log < wal.frames_committed);
    });
  });
}
