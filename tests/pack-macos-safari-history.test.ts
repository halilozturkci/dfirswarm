/**
 * safari_history reads Safari's History.db through a private copy. Held here with databases built by SQLite from the documented tables
 * (history_items, history_visits), never from the tool's output:
 *   - visits only in the -wal are read; the evidence is byte-identical afterwards; a link or a FIFO as a sidecar is named and not followed;
 *   - the time is Apple absolute: the raw REAL beside the UTC reading with the fraction (a Unix reading would land in 1970);
 *   - query values are withheld by shape (a token-shaped and a long random value), plain numbers are shown; the whole URL is written only with
 *     write_values in a secret job and is in nothing else the run leaves; write_values is refused as JSON elsewhere with nothing written;
 *   - a visit whose page row is missing is an entry with item null and the answer is partial;
 *   - the paging file and out_file hold as many rows as entry_count says; SIGTERM ends with one answer.
 */
import assert from "node:assert/strict";
import { mkdir, readFile, readdir, symlink, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { test } from "node:test";
import { spawnSync } from "node:child_process";
import { withCwd } from "./tool-library-harness.ts";
import { SAFARI, body, everything, filesUnder, ok, plainJob, safariDb, secretJob, signalled, tool } from "./macos-late-harness.ts";

const APPLE_2023 = 700000000.5; // 2023-03-08T20:26:40.5Z

test("visits only in the -wal are read, with the raw Apple time beside the UTC reading, and the evidence is not touched", async () => {
  await withCwd(async (cwd) => {
    const db = await safariDb(cwd, "evidence/History.db", ["https://example.org/a?page=2", "https://example.org/b"], [[1, APPLE_2023, "A"], [2, APPLE_2023 + 100.25, "B"]], "wal");
    const before = await Promise.all(["", "-wal", "-shm"].map((s) => readFile(join(cwd, db + s))));
    assert.ok(before[1].length > 0);
    const a = ok(await tool(SAFARI, cwd, { path: db }));
    assert.equal(a.status, "complete", a.status_basis + JSON.stringify(a.problems));
    assert.equal(a.entry_count, 2);
    assert.ok(a.source_used.wal.frames_valid > 0);
    const [first, second] = a.entries;
    assert.equal(first.visit_time_raw, APPLE_2023);
    assert.equal(first.visit_time, "2023-03-08T20:26:40.500000Z");
    assert.equal(second.visit_time, "2023-03-08T20:28:20.750000Z");
    assert.equal(first.visit.title, "A");
    assert.equal(first.item.domain_expansion, "example");
    assert.match(a.note, /2001-01-01/);
    const after = await Promise.all(["", "-wal", "-shm"].map((s) => readFile(join(cwd, db + s))));
    for (let i = 0; i < 3; i++) assert.ok(before[i].equals(after[i]));
    assert.deepEqual((await readdir(join(cwd, "work", "evidence"))).sort(), ["History.db", "History.db-shm", "History.db-wal"]);
  });
});

test("query values are withheld by shape and the answer carries no token, in nothing the run leaves; plain numbers stay", async () => {
  await withCwd(async (cwd) => {
    const token = "ghp_" + "A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r8";
    const random = "Zk3Qw9Xv2Lm8Pr4Tn7Yb5Hd1Gs6Fj0Cx";
    const url = `https://example.org/search?q=${random}&token=${token}&page=2#frag${random}`;
    const db = await safariDb(cwd, "evidence/History.db", [url], [[1, APPLE_2023, `title ${token}`]]);
    const run = await tool(SAFARI, cwd, { path: db, out_file: "work/rows.jsonl" });
    const a = ok(run);
    const text = await everything(cwd, run.stdout);
    for (const secret of [token, random]) assert.doesNotMatch(text, new RegExp(secret));
    assert.match(a.entries[0].url, /page=2/);
    assert.match(a.entries[0].url, /withheld/);
    assert.match(a.entries[0].title, /withheld/);
  });
});

test("write_values: refused as JSON outside a job and in a job that is not secret output; in a secret job the whole URL is in the sealed file and nowhere else", async () => {
  await withCwd(async (cwd) => {
    const token = "ghp_" + "A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r8";
    const url = `https://example.org/a?session=${token}`;
    const db = await safariDb(cwd, "evidence/History.db", [url], [[1, APPLE_2023, "t"]]);
    for (const run of [await tool(SAFARI, cwd, { path: db, write_values: true }), await plainJob(SAFARI, cwd, { path: db, write_values: true })]) {
      assert.equal(run.code, 1, run.stderr);
      const answer = body(run);
      assert.equal(answer.status, "failed");
      assert.match(answer.error, /secret output/);
    }
    assert.deepEqual((await filesUnder(join(cwd, "out"))).filter((f) => !f.endsWith(".gitkeep")), []);
    const run = await secretJob(SAFARI, cwd, { path: db, write_values: true });
    const a = ok(run);
    assert.equal(a.boundary.values.requested, true);
    assert.doesNotMatch(run.stdout, new RegExp(token));
    const file = join(cwd, "out", "safari_history-values.jsonl");
    const rows = (await readFile(file, "utf8")).split("\n").filter(Boolean).map((l) => JSON.parse(l) as { value: string; visit_id: number; field: string });
    assert.ok(rows.some((r) => r.field === "url" && r.value === url && r.visit_id === 1));
    for (const f of await filesUnder(join(cwd, "out"))) if (f !== file && !f.includes("/evidence/")) assert.doesNotMatch(await readFile(f, "utf8"), new RegExp(token), f);
    const second = await secretJob(SAFARI, cwd, { path: db, write_values: true });
    assert.equal(second.code, 1, "an existing values file is refused");
  });
});

test("a visit whose page row is missing is an entry with item null, counted, and the answer is partial", async () => {
  await withCwd(async (cwd) => {
    const db = await safariDb(cwd, "History.db", ["https://example.org/"], [[1, APPLE_2023, "ok"], [99, APPLE_2023, "orphan"]]);
    const a = ok(await tool(SAFARI, cwd, { path: db }));
    assert.equal(a.entry_count, 2);
    assert.equal(a.entries[1].item, null);
    assert.equal(a.status, "partial");
    assert.match(a.problems.join(" "), /page row that does not exist/);
  });
});

test("a sidecar that is a link or a FIFO is named and not followed or waited for; the answer is partial", async () => {
  await withCwd(async (cwd) => {
    const db = await safariDb(cwd, "evidence/History.db", ["https://example.org/"], [[1, APPLE_2023, "t"]]);
    await writeFile(join(cwd, "work", "evidence", "target"), "CANARY-TARGET-CONTENT");
    await symlink(join(cwd, "work", "evidence", "target"), join(cwd, db + "-wal"));
    assert.equal(spawnSync("mkfifo", [join(cwd, db + "-journal")]).status, 0);
    const t0 = Date.now();
    const run = await tool(SAFARI, cwd, { path: db });
    const a = ok(run);
    assert.ok(Date.now() - t0 < 20000);
    assert.equal(a.status, "partial");
    assert.match(a.source_used.sidecars_not_used["-wal"], /symbolic link/);
    assert.match(a.source_used.sidecars_not_used["-journal"], /FIFO/);
    assert.doesNotMatch(run.stdout, /CANARY-TARGET-CONTENT/);
  });
});

test("since and until select by the Apple time; a file with no history_visits table fails as JSON", async () => {
  await withCwd(async (cwd) => {
    const db = await safariDb(cwd, "History.db", ["https://example.org/"], [[1, APPLE_2023, "early"], [1, APPLE_2023 + 86400, "late"]]);
    const a = ok(await tool(SAFARI, cwd, { path: db, since: "2023-03-09T00:00:00Z" }));
    assert.equal(a.entry_count, 1);
    assert.equal(a.entries[0].title, "late");
    await writeFile(join(cwd, "work", "junk.db"), Buffer.alloc(2048, 0x42));
    const junk = await tool(SAFARI, cwd, { path: "work/junk.db" });
    assert.equal(junk.code, 1);
    assert.equal(body(junk).status, "failed");
  });
});

test("the paging file and out_file hold as many rows as entry_count says", async () => {
  await withCwd(async (cwd) => {
    const visits: Array<[number, number, string]> = Array.from({ length: 40 }, (_, i) => [1, APPLE_2023 + i, `v${i}`]);
    const db = await safariDb(cwd, "History.db", ["https://example.org/"], visits);
    const a = ok(await tool(SAFARI, cwd, { path: db, limit: 7 }));
    assert.equal(a.entry_count, 40);
    assert.equal((await readFile(join(cwd, a.complete_entries), "utf8")).split("\n").filter(Boolean).length, 40);
    const b = ok(await tool(SAFARI, cwd, { path: db, out_file: "work/o.jsonl" }));
    assert.equal((await readFile(join(cwd, "work", "o.jsonl"), "utf8")).split("\n").filter(Boolean).length, b.entry_count);
  });
});

test("SIGTERM in the middle of a large history: one JSON answer, exit 143, whole rows, no private copy left", async () => {
  await withCwd(async (cwd) => {
    const visits: Array<[number, number, string]> = Array.from({ length: 80000 }, (_, i) => [1, APPLE_2023 + i, `visit ${i}`]);
    const db = await safariDb(cwd, "History.db", ["https://example.org/"], visits);
    const run = await signalled(SAFARI, cwd, { path: db, out_file: "work/big.jsonl" }, "SIGTERM", 1500);
    assert.equal(run.code, 143, run.stderr + run.stdout.slice(0, 200));
    const a = JSON.parse(run.stdout);
    assert.equal(a.interrupted, "SIGTERM");
    const lines = (await readFile(join(cwd, "work", "big.jsonl"), "utf8")).split("\n").filter(Boolean);
    assert.equal(lines.length, a.entry_count);
    for (const l of lines.slice(-3)) JSON.parse(l);
    assert.deepEqual((await readdir(join(cwd, "work", "s1", ".safari-stage"))).filter((n) => n.startsWith("safari-")), []);
    await mkdir(join(cwd, "x"), { recursive: true });
  });
});

test("the manifest declares secret_output for write_values only, in a form the harness accepts", async () => {
  const m = JSON.parse(await readFile(join(SAFARI, "..", "manifest.json"), "utf8")) as { secret_output: unknown; params: Record<string, { type: string }>; description: string };
  assert.deepEqual(m.secret_output, { when_args: ["write_values"] });
  assert.equal(m.params.write_values.type, "boolean");
  assert.match(m.description, /SENSITIVE/);
});
