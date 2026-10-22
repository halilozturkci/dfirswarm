/**
 * ledger.md is written by one render at a time. A render that started before
 * a store sweep line was written must not finish after the sweep's own render
 * and put back a document that says the sweep is pending. The test holds the
 * first render at its read of the sweeps file (a named pipe stands in for
 * the file), writes the sweep line, asks for a second render, and only then
 * lets the first go. Synthetic run only.
 */
import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { constants } from "node:fs";
import { open, readFile, rename, rm, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { test } from "node:test";
import * as P from "../extensions/protocol.ts";
import * as SW from "../extensions/store-sweep.ts";
import { coverage, ok, planned, rec, run } from "./negative-bar-fixture.ts";

const sleep = (ms: number) => new Promise<void>((r) => setTimeout(r, ms));

test("a render that began before the store sweep line was written cannot overwrite the render that saw it", { skip: process.platform === "win32" }, async () => {
  const { S, a0 } = await run();
  await planned(a0, "2");
  const abs = ok(await rec(a0, { kind: "absence", value: "a remote tool", source: "the disk", evidence: "a search", refs: ["job:j000001/hits.txt"], answers: ["2"] })).entry;
  ok(await rec(a0, coverage("2", ["input:disk.E01"], [`E-${abs.seq}`, "job:j000001/hits.txt"], { looked_for: ["alice"] })));
  await SW.awaitSweeps(S);
  const sweepsFile = join(S, SW.LEDGER_SWEEPS);
  const sweepLine = await readFile(sweepsFile, "utf8");
  assert.ok(sweepLine.trim(), "the sweep wrote its line");
  const done = await P.renderLedger(S);
  assert.doesNotMatch(done, /store sweep pending/);

  // The state the first render sees: no sweep line yet. Its read of the sweeps file waits on a pipe.
  const held = join(S, "ledger", "sweeps.held");
  await rm(sweepsFile);
  execFileSync("mkfifo", [sweepsFile]);
  const first = P.renderLedger(S);
  await sleep(200);

  // The sweep line is written, and the sweep's own render is asked for.
  await rename(sweepsFile, held);
  await writeFile(sweepsFile, sweepLine);
  const second = P.renderLedger(S);

  // Whoever runs second has had its chance: give it time to finish if nothing holds it back, then let the first go.
  await Promise.race([second, sleep(400)]);
  const release = await open(held, constants.O_RDWR);
  await release.close();
  await Promise.all([first, second]);

  const text = await readFile(join(S, P.LEDGER_MD), "utf8");
  assert.doesNotMatch(text, /store sweep pending/, "the document the last render wrote holds the sweep line");
  assert.equal(text, done, "and is the document a render of the final state gives");
});

test("renders asked for together each run in turn and none fails", async () => {
  const { S } = await run();
  const texts = await Promise.all(Array.from({ length: 12 }, () => P.renderLedger(S)));
  assert.equal(new Set(texts).size, 1);
  assert.equal(await readFile(join(S, P.LEDGER_MD), "utf8"), texts[0]);
});
