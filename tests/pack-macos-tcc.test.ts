/**
 * macos_tcc reads one TCC.db through a private copy. Held here, each with a fixture built from the documented column list of the schema (the macOS
 * version is in the fixture's name; 26 and 27 are not built, their schema is not verified here) and never from the tool's output:
 *   - the columns of each version are shown raw, auth_value and client_type are decoded only where written down, with the raw number beside;
 *   - last_modified and last_reminder are the row's last write: given as UTC beside the raw Unix seconds, never called a grant time;
 *   - rows that are only in the -wal are read, the evidence files are not touched, nothing is written outside the run's own directories;
 *   - a sidecar that is a link or a FIFO is named, never followed, never waited for, and the answer is partial;
 *   - the code-signing requirement is given by length only; a token-shaped client id is withheld;
 *   - a file that is not a TCC database fails as JSON; the paging file and out_file hold as many rows as entry_count says;
 *   - SIGTERM mid-read ends with one JSON answer, exit 143, the staged copy removed.
 */
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { mkdir, readFile, readdir, stat, symlink, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { test } from "node:test";
import { spawnSync } from "node:child_process";
import { withCwd } from "./tool-library-harness.ts";
import { TCC, body, everything, filesUnder, ok, secretJob, signalled, tccDb, tool } from "./macos-late-harness.ts";

const MIC = { service: "kTCCServiceMicrophone", client: "com.apple.Terminal", client_type: 0, auth_value: 2, auth_reason: 3, auth_version: 1, last_modified: 1700000000 };
const FILES = { service: "kTCCServiceSystemPolicyAllFiles", client: "/usr/local/bin/tool", client_type: 1, auth_value: 0, auth_reason: 6, auth_version: 1, policy_id: 7, last_modified: 1700000100, csreq: "hex:fade0c0000000010" };

for (const version of ["11", "12", "13", "14", "15"]) {
  test(`macOS ${version} schema: raw columns, documented decodings only, times as the row's last write`, async () => {
    await withCwd(async (cwd) => {
      const extra = version === "11" ? {} : { last_reminder: 1700000500 };
      const db = await tccDb(cwd, `tcc-macos${version}.db`, version, [{ ...MIC, ...extra }, { ...FILES, ...extra }], "plain", { policy: true });
      const a = ok(await tool(TCC, cwd, { path: db }));
      assert.equal(a.status, "complete", a.status_basis);
      assert.equal(a.entry_count, 2);
      const [mic, files] = a.entries;
      assert.equal(mic.columns.client, "com.apple.Terminal");
      assert.equal(mic.columns.auth_value, 2);
      assert.equal(mic.auth_value_meaning, "allowed");
      assert.equal(mic.client_type_meaning, "bundle identifier");
      assert.equal(mic.managed, false);
      assert.equal(mic.columns.auth_reason, 3);
      assert.equal(mic.auth_reason_meaning, undefined, "auth_reason is not decoded");
      assert.equal(files.auth_value_meaning, "denied");
      assert.equal(files.client_type_meaning, "absolute path");
      assert.equal(files.managed, true);
      assert.equal(mic.columns.last_modified, 1700000000);
      assert.equal(mic.last_modified_utc, "2023-11-14T22:13:20Z");
      if (version !== "11") assert.equal(mic.last_reminder_utc, "2023-11-14T22:21:40Z");
      assert.deepEqual(files.length_only.csreq, { present: true, type: "blob", bytes: 8 });
      assert.deepEqual(Object.keys(a.schema.access_columns).includes("pid"), version !== "11");
      assert.equal(a.schema.admin.version, 15);
      assert.equal(a.schema.policies_rows, 1);
      assert.match(a.note, /not the time of a grant/);
      assert.doesNotMatch(JSON.stringify(a.entries), /grant_time|granted_at/);
    });
  });
}

test("macOS 10.15 (allowed, prompt_count): no auth_value is invented, the columns are raw", async () => {
  await withCwd(async (cwd) => {
    const db = await tccDb(cwd, "tcc-macos10.15.db", "10.15", [{ service: "kTCCServiceCamera", client: "com.example.app", client_type: 0, allowed: 1, prompt_count: 2, last_modified: 1600000000 }]);
    const a = ok(await tool(TCC, cwd, { path: db }));
    assert.equal(a.status, "complete");
    assert.equal(a.entries[0].auth_value_meaning, undefined);
    assert.equal(a.entries[0].columns.allowed, 1);
    assert.equal(a.entries[0].managed, false);
  });
});

test("rows only in the -wal are read, the evidence is byte-identical afterwards, and nothing is written beside it", async () => {
  await withCwd(async (cwd) => {
    const db = await tccDb(cwd, "ev/TCC.db", "14", [MIC, { ...MIC, client: "com.example.walonly", service: "kTCCServiceCamera", last_reminder: 1 }], "wal");
    const before = await Promise.all(["", "-wal", "-shm"].map((s) => readFile(join(cwd, db + s))));
    assert.ok(before[1].length > 0, "the fixture has a -wal");
    const a = ok(await tool(TCC, cwd, { path: db }));
    assert.equal(a.status, "complete", a.status_basis + JSON.stringify(a.problems));
    assert.equal(a.entry_count, 2);
    assert.ok(a.source_used.wal.frames_valid > 0);
    const after = await Promise.all(["", "-wal", "-shm"].map((s) => readFile(join(cwd, db + s))));
    for (let i = 0; i < 3; i++) assert.ok(before[i].equals(after[i]), `evidence file ${i} unchanged`);
    assert.deepEqual((await readdir(join(cwd, "work", "ev"))).sort(), ["TCC.db", "TCC.db-shm", "TCC.db-wal"]);
    assert.equal(a.source_used.staged_copy, "removed");
    const stage = join(cwd, "work", "s1", ".tcc-stage");
    assert.deepEqual((await readdir(stage)).filter((n) => n.startsWith("tcc-")), [], "no private copy is left");
  });
});

test("a -wal that is a symbolic link or a FIFO is named and not followed, the answer is partial, and the tool does not wait", async () => {
  await withCwd(async (cwd) => {
    const db = await tccDb(cwd, "evidence/TCC.db", "14", [MIC]);
    await mkdir(join(cwd, "work", "evidence"), { recursive: true });
    await writeFile(join(cwd, "work", "evidence", "secret-target"), "CANARY-TARGET-CONTENT");
    await symlink(join(cwd, "work", "evidence", "secret-target"), join(cwd, db + "-wal"));
    const link = ok(await tool(TCC, cwd, { path: db }));
    assert.equal(link.status, "partial");
    assert.match(link.source_used.sidecars_not_used["-wal"], /symbolic link/);
    assert.doesNotMatch(await everything(cwd, JSON.stringify(link)), /CANARY-TARGET-CONTENT/);
    const fifo = join(cwd, db + "-journal");
    assert.equal(spawnSync("mkfifo", [fifo]).status, 0);
    const t0 = Date.now();
    const f = ok(await tool(TCC, cwd, { path: db }));
    assert.ok(Date.now() - t0 < 20000, "no wait on a FIFO with no writer");
    assert.match(f.source_used.sidecars_not_used["-journal"], /FIFO/);
    assert.equal(f.status, "partial");
  });
});

test("the requirement blob is given by length only, a token-shaped client is withheld, and a canary is in nothing the run left", async () => {
  await withCwd(async (cwd) => {
    const canary = "CSREQCANARY0123456789abcdef";
    const token = "ghp_" + "A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r8";
    const db = await tccDb(cwd, "evidence/tcc.db", "15", [{ ...FILES, csreq: "hex:" + Buffer.from(canary).toString("hex"), client: token, indirect_object_code_identity: "hex:" + Buffer.from(canary).toString("hex") }]);
    const run = await tool(TCC, cwd, { path: db, out_file: "work/out.jsonl" });
    const a = ok(run);
    const text = await everything(cwd, run.stdout);
    assert.doesNotMatch(text, new RegExp(canary));
    assert.doesNotMatch(text, new RegExp(Buffer.from(canary).toString("hex")));
    assert.doesNotMatch(text, new RegExp(token));
    assert.equal(a.entries[0].length_only.csreq.bytes, canary.length);
    assert.match(JSON.stringify(a.entries[0].client), /withheld/);
    // out_file: the rows in the file are the rows counted
    const lines = (await readFile(join(cwd, "work", "out.jsonl"), "utf8")).split("\n").filter(Boolean);
    assert.equal(lines.length, a.entry_count);
    assert.equal(((await stat(join(cwd, "work", "out.jsonl"))).mode & 0o777).toString(8), "600");
  });
});

test("a paging file holds as many rows as entry_count says, and an existing out_file is refused", async () => {
  await withCwd(async (cwd) => {
    const rows = Array.from({ length: 30 }, (_, i) => ({ ...MIC, client: `com.example.app${i}`, last_modified: 1700000000 + i }));
    const db = await tccDb(cwd, "tcc.db", "14", rows);
    const a = ok(await tool(TCC, cwd, { path: db, limit: 5 }));
    assert.equal(a.entry_count, 30);
    assert.equal(a.entries_inline, 5);
    assert.equal(a.inline_limited, true);
    const lines = (await readFile(join(cwd, a.complete_entries), "utf8")).split("\n").filter(Boolean);
    assert.equal(lines.length, 30);
    await writeFile(join(cwd, "work", "taken.jsonl"), "x");
    const refused = await tool(TCC, cwd, { path: db, out_file: "work/taken.jsonl" });
    assert.equal(refused.code, 1);
    assert.equal(body(refused).status, "failed");
  });
});

test("a database with no access table, and a file that is not SQLite, fail as JSON and are never an empty result", async () => {
  await withCwd(async (cwd) => {
    await writeFile(join(cwd, "work", "junk.db"), Buffer.alloc(4096, 0x41));
    const junk = await tool(TCC, cwd, { path: "work/junk.db" });
    assert.equal(junk.code, 1);
    assert.equal(body(junk).status, "failed");
    const db = await tccDb(cwd, "ok.db", "14", [MIC]);
    const sql = spawnSync("python3", ["-c", "import sqlite3,sys; c=sqlite3.connect(sys.argv[1]); c.execute('DROP TABLE access'); c.commit()", join(cwd, db)]);
    assert.equal(sql.status, 0);
    const none = await tool(TCC, cwd, { path: db });
    assert.equal(none.code, 1);
    assert.match(body(none).error, /no access table/);
  });
});

test("a table without a rowid (WITHOUT ROWID) is read, its text cells are not lost, and resume is not offered", async () => {
  await withCwd(async (cwd) => {
    const path = join(cwd, "work", "wr.db");
    const py = "import sqlite3,sys; c=sqlite3.connect(sys.argv[1]); c.execute('CREATE TABLE access (service TEXT NOT NULL, client TEXT NOT NULL, auth_value INTEGER, last_modified INTEGER, PRIMARY KEY(service, client)) WITHOUT ROWID'); c.execute(\"INSERT INTO access VALUES ('kTCCServiceCamera','com.example.a',2,1700000000)\"); c.commit()";
    assert.equal(spawnSync("python3", ["-c", py, path]).status, 0);
    const a = ok(await tool(TCC, cwd, { path: "work/wr.db" }));
    assert.equal(a.schema.rowid_available, false);
    assert.equal(a.entries[0].columns.client, "com.example.a");
    assert.equal(a.entries[0].source.rowid, null);
    assert.equal(a.status, "partial");
  });
});

test("SIGTERM in the middle of a large table: one JSON answer, exit 143, the rows written are whole, the private copy is gone", async () => {
  await withCwd(async (cwd) => {
    const rows = Array.from({ length: 60000 }, (_, i) => ({ ...MIC, client: `com.example.app${i}`, indirect_object_identifier: `id${i}`, last_modified: 1700000000 + i }));
    const db = await tccDb(cwd, "big.db", "14", rows);
    const run = await signalled(TCC, cwd, { path: db, out_file: "work/big.jsonl" }, "SIGTERM", 1500);
    assert.equal(run.code, 143, run.stderr + run.stdout.slice(0, 300));
    const a = JSON.parse(run.stdout);
    assert.equal(a.interrupted, "SIGTERM");
    assert.equal(a.status, "partial");
    const lines = (await readFile(join(cwd, "work", "big.jsonl"), "utf8")).split("\n").filter(Boolean);
    assert.equal(lines.length, a.entry_count);
    for (const l of lines.slice(-3)) JSON.parse(l);
    const stage = join(cwd, "work", "s1", ".tcc-stage");
    assert.deepEqual((await readdir(stage)).filter((n) => n.startsWith("tcc-")), []);
    assert.ok(a.resume.after_rowid >= 1);
  });
});

test("write_values is not a parameter of macos_tcc, the manifest declares no values mode, and the tool writes only under its own directories", async () => {
  await withCwd(async (cwd) => {
    const m = JSON.parse(await readFile(join(TCC, "..", "manifest.json"), "utf8")) as { params: Record<string, unknown>; secret_output?: unknown };
    assert.equal(m.params.write_values, undefined);
    assert.equal(m.secret_output, undefined);
    const db = await tccDb(cwd, "tcc.db", "14", [MIC]);
    const before = new Set(await filesUnder(cwd));
    ok(await secretJob(TCC, cwd, { path: db }));
    const created = (await filesUnder(cwd)).filter((f) => !before.has(f));
    for (const f of created) assert.match(f.slice(cwd.length), /^\/(out|work\/s1)\//, f);
    await mkdir(join(cwd, "x"), { recursive: true });
  });
});

test("the evidence's digest is the same before and after a run with a -wal", async () => {
  await withCwd(async (cwd) => {
    const db = await tccDb(cwd, "ev/TCC.db", "13", [MIC], "wal");
    const digest = async (): Promise<string> => createHash("sha256").update(await readFile(join(cwd, db))).update(await readFile(join(cwd, db + "-wal"))).digest("hex");
    const d0 = await digest();
    ok(await tool(TCC, cwd, { path: db }));
    assert.equal(await digest(), d0);
  });
});
