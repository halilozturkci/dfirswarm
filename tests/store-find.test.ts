/**
 * Which job holds a file, by name or by content hash, from the manifests;
 * and the run's jobs with why each waits.
 */
import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import { sealTree, storePaths } from "../scripts/evidence-store.ts";
import { jobsListing, storeFind } from "../scripts/store-find.ts";
import { initSandbox } from "../extensions/protocol.ts";

test("a file is found by a part of its name and by its sha256, across jobs and imports, without a grep", async () => {
  const S = mkdtempSync(join(tmpdir(), "store-find-"));
  try {
    await initSandbox(S, { reset: true, agentIds: ["a0"] });
    const stage = (job: string, files: Record<string, string>) => {
      const d = join(S, `staging-${job}`);
      for (const [p, text] of Object.entries(files)) { mkdirSync(join(d, p, ".."), { recursive: true }); writeFileSync(join(d, p), text); }
      return d;
    };
    await sealTree(S, stage("j000008", { "tree/Users/x/AppData/Local/Temp/mssetup.exe.dmp": "dump bytes", "tree/Windows/a.dll": "dll" }), join(storePaths(S).jobs, "j000008", "out"), "j000008", 1);
    await sealTree(S, stage("j000032", { "small/notes.txt": "n", "small/copy.dmp": "dump bytes" }), join(storePaths(S).jobs, "j000032", "out"), "j000032", 1);
    await sealTree(S, stage("mat-0001", { "bin/zbarimg": "elf" }), join(storePaths(S).imports, "mat-0001", "out"), "mat-0001", 1);
    const byName = await storeFind(S, { name: "MSSETUP.exe.dmp" });
    assert.ok(byName.ok);
    if (!byName.ok) return;
    assert.deepEqual(byName.hits.map((h) => h.ref), ["job:j000008/tree/Users/x/AppData/Local/Temp/mssetup.exe.dmp"], "the dump a seat was refused in one job is in another");
    assert.deepEqual(byName.searched, { jobs: 2, imports: 1, files: 5 });
    const star = await storeFind(S, { name: "*.dmp" });
    assert.ok(star.ok && star.matched === 2);
    const bySha = await storeFind(S, { sha256: byName.hits[0]!.sha256 });
    assert.ok(bySha.ok && bySha.hits.length === 2, "the same bytes under two names, in two jobs");
    const one = await storeFind(S, { name: "dmp", limit: 1 });
    assert.ok(one.ok && one.returned === 1 && one.matched === 2 && /1 more match/.test(one.note ?? ""));
    const imp = await storeFind(S, { name: "zbarimg" });
    assert.ok(imp.ok && imp.hits[0]!.ref === "import:mat-0001/bin/zbarimg");
    assert.match((byName.note ?? ""), /To search inside the files for text, run a job/);
    assert.equal((await storeFind(S, {})).ok, false);
    assert.equal((await storeFind(S, { sha256: "abc" })).ok, false);
    const none = await storeFind(S, { name: "nothing-like-this" });
    assert.ok(none.ok && none.matched === 0 && none.complete);
  } finally {
    // Sealed trees are read-only: make them writable again before the temporary run is removed.
    execFileSync("chmod", ["-R", "u+w", S]);
    rmSync(S, { recursive: true, force: true });
  }
});

test("the jobs listing: mine by default, the open ones first with why they wait, counted and bounded", () => {
  const job = (id: string, state: string, agent: string, extra: Record<string, unknown> = {}) => ({ id, state, spec: { kind: "command", command: "python3 x.py   --all" }, requester: { agent }, accepted_at: `2026-01-01T00:00:${id.slice(-2)}Z`, ...extra }) as never;
  const all = [job("j000001", "committed", "a0", { status: "ok", outputs: { files: 3, bytes: 90 } }), job("j000002", "finished", "a0"), job("j000003", "accepted", "a1"), job("j000004", "running", "a0", { spec: { kind: "tool", tool: "ad1_extract" } })];
  const mine = jobsListing(all, { who: "a0", waitWords: (j) => (j.state === "finished" ? "finished, waiting to be sealed: 0 job(s) ahead of it" : undefined), leadOf: (id) => (id === "j000004" ? "L-2" : undefined) });
  assert.deepEqual(mine.jobs.map((r) => r.job), ["j000004", "j000002", "j000001"], "open first, the newest first");
  assert.deepEqual(mine.counts, { committed: 1, finished: 1, running: 1 });
  assert.equal(mine.jobs[1]!.waiting, "finished, waiting to be sealed: 0 job(s) ahead of it");
  assert.equal(mine.jobs[0]!.what, "tool ad1_extract");
  assert.equal(mine.jobs[0]!.lead, "L-2");
  assert.equal(mine.jobs[2]!.what, "command: python3 x.py --all");
  assert.equal(jobsListing(all, { who: "a0", scope: "all" }).total, 4);
  assert.deepEqual(jobsListing(all, { who: "a9", scope: "lead", lead: "L-2", leadOf: (id) => (id === "j000004" ? "L-2" : undefined) }).jobs.map((r) => r.job), ["j000004"]);
  const cut = jobsListing(all, { who: "a0", scope: "all", limit: 2 });
  assert.ok(cut.returned === 2 && /2 more, older/.test(cut.note ?? ""));
});
