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
