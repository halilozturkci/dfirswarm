/**
 * The hub's memory (Batman III, the run s082123: the hub ran out of a 4 GiB
 * heap after 90 minutes and nothing was said before it died). Measured on a
 * clone of that run: one store sweep's object list held 330 MB, 260 MB of it
 * the objects' whole paths, and three sweeps at once peaked at 1.6 GB. Now a
 * sweep's objects hold their directory (shared) and their name, sweeps that
 * start while a listing is made share it, the hub writes its memory to
 * status.json, and a crossing of three quarters of the heap's limit is said on
 * the trace once.
 */
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { mkdir, mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { createServer } from "node:net";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { after, test } from "node:test";
import { initSandbox } from "../extensions/protocol.ts";
import * as SW from "../extensions/store-sweep.ts";
import { sealTree, storePaths } from "../scripts/evidence-store.ts";
import { Hub, hubMemory } from "../scripts/vm-hub.ts";

const dirs: string[] = [];
after(async () => {
  for (const d of dirs) {
    // The store seals what a job wrote read-only.
    spawnSync("chmod", ["-R", "u+w", d]);
    await rm(d, { recursive: true, force: true });
  }
});

test("sweeps that start while a listing is made share it; one that starts after gets a fresh one with what was sealed since", async () => {
  const base = await mkdtemp(join(tmpdir(), "sweep-share-"));
  dirs.push(base);
  const S = join(base, "run");
  await initSandbox(S, { swarmId: "t1", agentIds: ["a0"], capUsd: 1, wallClockMinutes: 30 });
  const seal = async (id: string, files: Record<string, string>) => {
    const staging = join(base, `staging-${id}`);
    await mkdir(staging, { recursive: true });
    for (const [n, b] of Object.entries(files)) await writeFile(join(staging, n), b);
    await sealTree(S, staging, join(storePaths(S).jobs, id, "out"), id, 1);
  };
  await seal("j000001", { "a.txt": "alpha", "b.txt": "beta" });
  const [x, y] = await Promise.all([SW.sweepObjects(S), SW.sweepObjects(S)]);
  assert.equal(x, y, "one list for both");
  assert.deepEqual(x.map((o) => o.ref), ["job:j000001/a.txt", "job:j000001/b.txt"]);
  await seal("j000002", { "c.txt": "gamma" });
  const z = await SW.sweepObjects(S);
  assert.notEqual(z, x);
  assert.deepEqual(z.map((o) => o.ref), ["job:j000001/a.txt", "job:j000001/b.txt", "job:j000002/c.txt"]);
  // The files of a job share their directory string.
  const [a, b] = z;
  assert.equal((a as unknown as { dir: string }).dir, (b as unknown as { dir: string }).dir);
  // And a sweep still finds the string in the file whose path is put together when it is read.
  const sw = await SW.computeSweep(S, { seq: 1, hash: "h", refs: [], result_refs: [], looked_for: ["gamma"] });
  assert.deepEqual(sw.hits.map((h) => h.ref), ["job:j000002/c.txt"]);
});

test("the hub's memory is in status.json, and three quarters of the heap's limit is said on the trace once until it falls back under two thirds", async () => {
  const m = hubMemory();
  assert.ok(m.heap_limit_mb > m.heap_used_mb && m.heap_used_mb > 0 && m.rss_mb > 0, JSON.stringify(m));
  const base = await mkdtemp(join(tmpdir(), "hub-mem-"));
  dirs.push(base);
  const S = join(base, "runs", "t1");
  await mkdir(S, { recursive: true });
  await initSandbox(S, { swarmId: "t1", agentIds: ["a0"], capUsd: 1, wallClockMinutes: 30 });
  const dir = await mkdtemp(join(tmpdir(), "hubm-"));
  dirs.push(dir);
  const col = createServer((s) => {
    s.on("data", () => s.write('{"ok":true}\n'));
    s.on("error", () => undefined);
  });
  await new Promise<void>((r) => col.listen(join(dir, "col.sock"), () => r()));
  const hub = new Hub({ sandbox: S, dir, agents: ["a0"], tokens: { a0: "t", system: "s" }, collector: join(dir, "col.sock"), backstop: false, quiet: true, settleMs: 0, herdrBin: "/usr/bin/false" });
  await hub.start();
  try {
    const said: Array<[string, Record<string, unknown>]> = [];
    (hub as unknown as { event: (t: string, a: unknown, r: Record<string, unknown>) => Promise<void> }).event = async (t, _a, r) => void said.push([t, r]);
    await hub.checkMemory({ rss_mb: 4000, heap_used_mb: 3300, heap_limit_mb: 4288 });
    await hub.checkMemory({ rss_mb: 4000, heap_used_mb: 3400, heap_limit_mb: 4288 });
    assert.deepEqual(said, [["hub_memory_high", { ok: true, rss_mb: 4000, heap_used_mb: 3300, heap_limit_mb: 4288 }]], "said once");
    await hub.checkMemory({ rss_mb: 1000, heap_used_mb: 1000, heap_limit_mb: 4288 });
    await hub.checkMemory({ rss_mb: 4000, heap_used_mb: 3300, heap_limit_mb: 4288 });
    assert.equal(said.length, 2, "again after it fell back");
    const status = JSON.parse(await readFile(join(dir, "status.json"), "utf8")) as { memory: Record<string, number> };
    assert.deepEqual(Object.keys(status.memory).sort(), ["heap_limit_mb", "heap_used_mb", "rss_mb"]);
  } finally {
    await hub.stop().catch(() => undefined);
    col.close();
  }
});

test("the launchers start the hub with a heap snapshot near its limit, into its own directory, and the stop keeps it out of the run", async () => {
  const sh = await readFile(join(import.meta.dirname, "..", "scripts", "swarm.sh"), "utf8");
  assert.match(sh, /--heapsnapshot-near-heap-limit=1 --diagnostic-dir="\$dir" "\$script"/);
  assert.match(sh, /mv "\$snap" "\$HOME\/\.dfirswarm\/diagnostics\/\$run\/"/);
  for (const f of ["hub-supervise.sh", "idle-nudge.sh"]) assert.match(await readFile(join(import.meta.dirname, "..", "scripts", f), "utf8"), /--heapsnapshot-near-heap-limit=1 --diagnostic-dir="\$HUB_DIR"/, f);
});
