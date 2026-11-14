/** Custody holds a sweep line's side list to the sha256 the line names (scripts/custody.ts sweepSideLists). */
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { after, test } from "node:test";
import { sweepSideLists } from "../scripts/custody.ts";

const S = mkdtempSync(join(tmpdir(), "sweep-side-"));
after(() => rmSync(S, { recursive: true, force: true }));
mkdirSync(join(S, "ledger", "sweeps"), { recursive: true });
const put = (body: string) => {
  const sha = createHash("sha256").update(body).digest("hex");
  const path = `ledger/sweeps/unsearched-${sha}.jsonl`;
  writeFileSync(join(S, path), body);
  return { path, sha256: sha, rows: body.split("\n").length - 1 };
};
const line = (file: unknown) => JSON.stringify({ v: 4, unsearched: [], unsearched_all: { total: 9, left: 9, by_reason: [], by_prefix: [], file } });

test("a side list as its line names it passes; a changed, a missing and an oddly placed one are named", async () => {
  const good = put('{"ref":"job:j000001/a","why":"budget"}\n');
  const changed = put('{"ref":"job:j000001/b","why":"budget"}\n');
  writeFileSync(join(S, changed.path), "something else\n");
  const missing = { path: `ledger/sweeps/unsearched-${"0".repeat(64)}.jsonl`, sha256: "0".repeat(64), rows: 1 };
  const odd = { path: "../outside.jsonl", sha256: "1".repeat(64), rows: 1 };
  assert.deepEqual(await sweepSideLists(S, [line(good), JSON.stringify({ v: 4, unsearched: [] })].join("\n")), { named: 1, bad: [] });
  const r = await sweepSideLists(S, [line(good), line(changed), line(missing), line(odd), "not json unsearched_all"].join("\n"));
  assert.equal(r.named, 4);
  assert.equal(r.bad.length, 3);
  assert.match(r.bad.join("\n"), /its bytes are not the/);
  assert.match(r.bad.join("\n"), /: missing/);
  assert.match(r.bad.join("\n"), /not a side list's path/);
});

test("a line's file of hits is held the same way, beside its list of what was not searched; a file not named by its own sha256, or named for the other list, is named", async () => {
  const hits = (body: string) => {
    const sha = createHash("sha256").update(body).digest("hex");
    const path = `ledger/sweeps/hits-${sha}.jsonl`;
    writeFileSync(join(S, path), body);
    return { path, sha256: sha, rows: body.split("\n").length - 1 };
  };
  const both = (u: unknown, h: unknown) => JSON.stringify({ v: 1, unsearched: [], unsearched_all: { total: 60, left: 0, by_reason: [], by_prefix: [], file: u }, hits: [], hits_all: { total: 60, counts: { hits: 60, named_hits: 0, echoes: 0 }, by_term: [], by_prefix: [], file: h } });
  const u = put('{"ref":"job:j000002/a","why":"too_large"}\n');
  const h = hits('{"list":"hits","ref":"job:j000002/b","term":"mallory","count":1,"first_offset":0,"encodings":["utf-8"]}\n');
  assert.deepEqual(await sweepSideLists(S, both(u, h)), { named: 2, bad: [] });
  // Its bytes changed: named.
  const changed = hits('{"list":"hits","ref":"job:j000002/c","term":"mallory","count":1,"first_offset":0,"encodings":["utf-8"]}\n');
  writeFileSync(join(S, changed.path), "something else\n");
  // A name that is not the sha256 the line gives it; a list of hits named as one of what was not searched (no such file).
  const renamed = { ...h, sha256: "2".repeat(64) };
  const swapped = { ...h, path: `ledger/sweeps/unsearched-${h.sha256}.jsonl` };
  const r = await sweepSideLists(S, [both(u, changed), both(u, renamed), JSON.stringify({ v: 2, unsearched: [], unsearched_all: { total: 60, left: 0, by_reason: [], by_prefix: [], file: swapped } })].join("\n"));
  assert.equal(r.named, 4);
  assert.deepEqual(r.bad.map((b) => b.replace(/[0-9a-f]{64}/g, "<sha>")).sort(), [
    "ledger/sweeps/hits-<sha>.jsonl: not a side list's path",
    "ledger/sweeps/hits-<sha>.jsonl: its bytes are not the " + changed.sha256.slice(0, 12) + "… its line names",
    "ledger/sweeps/unsearched-<sha>.jsonl: missing",
  ].sort().map((b) => b.replace(/[0-9a-f]{64}/g, "<sha>")));
});
