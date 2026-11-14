/**
 * macos-forensics, the GUARD block's print_order_until (every GUARD carrier holds the same text; fsevents_parse is driven here). It judged a list's
 * names inside _quietly with no clock of the boundary block and read its caller's `until` once every 16 items; a list it did not finish came back with
 * `whole` false, which several callers drop, so the answer stayed complete. It now judges under the block's clock and cap (_timed, the characters
 * counted), reads `until` before every item, and counts what it did not judge so that the answer is partial whatever the caller does with `whole`.
 */
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { join } from "node:path";
import { test } from "node:test";
import { MAC } from "./macos-pack-harness.ts";

type Answer = Record<string, any>; // eslint-disable-line @typescript-eslint/no-explicit-any

const PROBE = String.raw`
import json, runpy, sys, time
g = runpy.run_path(sys.argv[1], run_name="probe")
box = g["print_order_until"].__globals__
mode = sys.argv[2]
items = ["%05d-" % i + "".join(chr(97 + (i * 7 + j * 13) % 26) + "Zq7" for j in range(16000)) for i in range(400)]   # 64 KiB of text each
until = None
if mode == "until":
    items = ["name%03d" % i for i in range(40)]
    until = time.monotonic() - 1.0                 # the caller's clock has already run out
elif mode == "clock":
    box["SEAL_BUDGET"] = 1.0
else:
    box["_STOP"]["cap"] = 200000
t = time.monotonic()
order, whole = g["print_order_until"](items, "path", until=until)
took = time.monotonic() - t
out = g["answer_object"]({"status": "complete", "status_basis": "probe"})
print(json.dumps({"took": took, "whole": whole, "same": sorted(order) == sorted(items), "stop": box["_STOP"], "status": out["status"],
                  "basis": out["status_basis"], "boundary": out["boundary"]}))
`;

for (const mode of ["until", "clock", "cap"] as const) {
  test(`print_order_until stops at ${mode === "until" ? "the caller's clock" : mode === "clock" ? "the boundary's clock" : "the cap of characters"}, counts what it did not judge, and the answer is partial`, async () => {
    const run = spawnSync("python3", ["-c", PROBE, join(MAC, "fsevents_parse", "run.py"), mode], { encoding: "utf8", timeout: 120_000 });
    assert.equal(run.status, 0, run.stderr);
    const r = JSON.parse(run.stdout) as Answer;
    assert.ok(r.took < (mode === "clock" ? 5 : 2), `ordering took ${r.took} s`);
    assert.equal(r.whole, false);
    assert.equal(r.same, true, "every item is returned, judged or not");
    assert.ok(r.stop.quiet > 0, JSON.stringify(r.stop));
    assert.notEqual(r.stop.by, null);
    assert.equal(r.status, "partial", "the answer is partial even when the caller drops `whole`");
    assert.ok(r.boundary.strings_not_judged_for_order_or_filter > 0, JSON.stringify(r.boundary));
    assert.match(r.basis, /put in order or filtered without being judged/);
  });
}
